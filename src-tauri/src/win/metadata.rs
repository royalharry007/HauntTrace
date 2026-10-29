//! Read-only executable metadata: version resource strings, size and file
//! times, and a coarse location category. The file is never executed.

use serde::Serialize;
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesExW, GetFileExInfoStandard, GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, WIN32_FILE_ATTRIBUTE_DATA,
};

use crate::types::filetime_to_unix_ms;

#[derive(Debug, Clone, Serialize, Default)]
pub struct ExecutableMetadata {
    pub exists: bool,
    pub size_bytes: Option<u64>,
    pub created_ms: Option<u64>,
    pub modified_ms: Option<u64>,
    pub company_name: Option<String>,
    pub file_description: Option<String>,
    pub product_name: Option<String>,
    pub file_version: Option<String>,
    pub original_filename: Option<String>,
    pub location: String,
}

/// Coarse, explainable classification of where an executable lives.
pub fn classify_location(path: &str) -> String {
    let p = path.to_lowercase();
    let env = |k: &str| std::env::var(k).ok().map(|v| v.to_lowercase().trim_end_matches('\\').to_string());
    let under = |base: Option<String>| base.map(|b| !b.is_empty() && p.starts_with(&(b + "\\"))).unwrap_or(false);
    if under(env("SystemRoot")) {
        "windows_directory".into()
    } else if under(env("ProgramFiles")) || under(env("ProgramFiles(x86)")) {
        "program_files".into()
    } else if under(env("TEMP")) || p.contains("\\appdata\\local\\temp\\") {
        "user_temp".into()
    } else if p.contains("\\downloads\\") {
        "user_downloads".into()
    } else if under(env("LOCALAPPDATA")) || under(env("APPDATA")) {
        "user_appdata".into()
    } else if under(env("ProgramData")) {
        "program_data".into()
    } else if under(env("USERPROFILE")) {
        "user_profile".into()
    } else {
        "other".into()
    }
}

fn query_string(block: &[u8], lang: &str, name: &str) -> Option<String> {
    let sub = HSTRING::from(format!("\\StringFileInfo\\{lang}\\{name}"));
    let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len: u32 = 0;
    let ok = unsafe { VerQueryValueW(block.as_ptr() as *const _, PCWSTR(sub.as_ptr()), &mut ptr, &mut len) };
    if !ok.as_bool() || ptr.is_null() || len == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize) };
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    let s = String::from_utf16_lossy(&slice[..end]).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s.chars().take(200).collect())
    }
}

/// Blocking; run off the async runtime with a timeout.
pub fn read_metadata(path: &str) -> ExecutableMetadata {
    let mut m = ExecutableMetadata { location: classify_location(path), ..Default::default() };
    let hpath = HSTRING::from(path);
    let mut attrs = WIN32_FILE_ATTRIBUTE_DATA::default();
    if unsafe { GetFileAttributesExW(PCWSTR(hpath.as_ptr()), GetFileExInfoStandard, &mut attrs as *mut _ as *mut _) }.is_ok() {
        m.exists = true;
        m.size_bytes = Some(((attrs.nFileSizeHigh as u64) << 32) | attrs.nFileSizeLow as u64);
        let ft = |f: windows::Win32::Foundation::FILETIME| filetime_to_unix_ms(((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64);
        m.created_ms = Some(ft(attrs.ftCreationTime));
        m.modified_ms = Some(ft(attrs.ftLastWriteTime));
    } else {
        return m;
    }

    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(hpath.as_ptr()), None) };
    if size == 0 || size > 8 * 1024 * 1024 {
        return m;
    }
    let mut block = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(PCWSTR(hpath.as_ptr()), None, size, block.as_mut_ptr() as *mut _) }.is_err() {
        return m;
    }
    // Find the first language/codepage pair.
    let mut langs: Vec<String> = Vec::new();
    let sub = HSTRING::from("\\VarFileInfo\\Translation");
    let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len: u32 = 0;
    if unsafe { VerQueryValueW(block.as_ptr() as *const _, PCWSTR(sub.as_ptr()), &mut ptr, &mut len) }.as_bool() && len >= 4 && !ptr.is_null() {
        let pairs = unsafe { std::slice::from_raw_parts(ptr as *const u16, (len / 2) as usize) };
        for c in pairs.chunks(2) {
            if c.len() == 2 {
                langs.push(format!("{:04x}{:04x}", c[0], c[1]));
            }
        }
    }
    langs.extend(["040904b0".to_string(), "040904e4".to_string(), "000004b0".to_string()]);
    for lang in &langs {
        let company = query_string(&block, lang, "CompanyName");
        let desc = query_string(&block, lang, "FileDescription");
        if company.is_some() || desc.is_some() {
            m.company_name = company;
            m.file_description = desc;
            m.product_name = query_string(&block, lang, "ProductName");
            m.file_version = query_string(&block, lang, "FileVersion");
            m.original_filename = query_string(&block, lang, "OriginalFilename");
            break;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_notepad_version_info() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let m = read_metadata(&format!("{windir}\\System32\\notepad.exe"));
        assert!(m.exists);
        assert_eq!(m.location, "windows_directory");
        assert!(m.company_name.unwrap_or_default().contains("Microsoft"));
    }

    #[test]
    fn missing_file_reports_not_exists() {
        let m = read_metadata("C:\\nope\\missing.exe");
        assert!(!m.exists);
        assert!(m.company_name.is_none());
    }
}

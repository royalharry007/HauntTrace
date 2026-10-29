//! Small, focused Win32 helpers used by the app layer.

pub mod metadata;
pub mod signature;
pub mod sound;
pub mod tts;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Security::Credentials::{CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC};
use windows::Win32::System::SystemInformation::{GetLocalTime, GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE};

use crate::collector::windows::{process_times, OwnedHandle};

/// Minutes after local midnight.
pub fn local_minute_of_day() -> u32 {
    let t = unsafe { GetLocalTime() };
    t.wHour as u32 * 60 + t.wMinute as u32
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemoryStatus {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

pub fn memory_status() -> Option<MemoryStatus> {
    let mut m = MEMORYSTATUSEX { dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
    unsafe { GlobalMemoryStatusEx(&mut m).ok()? };
    Some(MemoryStatus { total_bytes: m.ullTotalPhys, available_bytes: m.ullAvailPhys })
}

/// Terminate exactly the given process instance. Refuses if the PID now
/// belongs to a different process (creation time mismatch). Only called
/// after explicit user confirmation in the UI.
pub fn terminate_instance(pid: u32, created: u64) -> Result<(), String> {
    if pid == 0 || pid == 4 || pid == std::process::id() {
        return Err("This process cannot be ended from HauntTrace.".into());
    }
    let h = unsafe { OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .map_err(|e| format!("Windows denied access to end this process ({}). It may belong to the system or another user.", e.code()))?;
    let h = OwnedHandle(h);
    let (c, _) = process_times(&h).ok_or("Could not confirm the process identity, so it was not ended.")?;
    if c != created {
        return Err("That process already exited and its ID now belongs to a different process. Nothing was ended.".into());
    }
    unsafe { TerminateProcess(h.0, 1) }.map_err(|e| format!("Windows refused to end the process ({}).", e.code()))
}

const CRED_TARGET: &str = "HauntTrace/ElevenLabs";

/// Store a secret in Windows Credential Manager (per-user, encrypted by the OS).
pub fn credential_write(secret: &str) -> Result<(), String> {
    let target = HSTRING::from(CRED_TARGET);
    let user = HSTRING::from("api-key");
    let mut blob = secret.as_bytes().to_vec();
    let cred = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(target.as_ptr() as *mut _),
        UserName: PWSTR(user.as_ptr() as *mut _),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    let r = unsafe { CredWriteW(&cred, 0) }.map_err(|e| format!("Could not save to Windows Credential Manager ({}).", e.code()));
    blob.iter_mut().for_each(|b| *b = 0);
    r
}

pub fn credential_read() -> Option<String> {
    let target = HSTRING::from(CRED_TARGET);
    let mut p: *mut CREDENTIALW = std::ptr::null_mut();
    unsafe {
        CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None, &mut p).ok()?;
        let c = &*p;
        let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
        let s = String::from_utf8(bytes.to_vec()).ok();
        CredFree(p as *const _);
        s.filter(|s| !s.is_empty())
    }
}

pub fn credential_delete() -> Result<(), String> {
    let target = HSTRING::from(CRED_TARGET);
    match unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) } {
        Ok(()) => Ok(()),
        Err(e) if e.code().0 as u32 == 0x80070490 => Ok(()), // ERROR_NOT_FOUND
        Err(e) => Err(format!("Could not remove the credential ({}).", e.code())),
    }
}

/// Replace the user profile prefix with %USERPROFILE% so logs and model
/// prompts do not carry the Windows account name.
pub fn redact_user_path(s: &str) -> String {
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.is_empty() {
            let lower = s.to_lowercase();
            let pl = profile.to_lowercase();
            let mut out = String::with_capacity(s.len());
            let mut i = 0;
            while let Some(pos) = lower[i..].find(&pl) {
                out.push_str(&s[i..i + pos]);
                out.push_str("%USERPROFILE%");
                i += pos + pl.len();
            }
            out.push_str(&s[i..]);
            return out;
        }
    }
    s.to_string()
}

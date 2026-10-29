//! "Who is this spirit?": a quick, deterministic identity for the process
//! behind a haunting, from its signature, version resource and location.
//! It answers *who made it and where it lives*, never *whether it is bad*.

use serde::Serialize;

use crate::win::metadata::ExecutableMetadata;
use crate::win::signature::SignatureInfo;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Identity {
    /// Friendly program name ("Google Chrome"), else the process name.
    pub title: String,
    /// Verified signer, else the company named in the file (unverified).
    pub maker: Option<String>,
    pub maker_verified: bool,
    /// Plain-language folder ("Program Files", "your Downloads folder").
    pub place: String,
    /// True only for a valid signature.
    pub known: bool,
    pub note: String,
}

pub fn place_label(location: &str) -> &'static str {
    match location {
        "windows_directory" => "the Windows folder",
        "program_files" => "Program Files",
        "program_data" => "ProgramData",
        "user_appdata" => "your app data folder",
        "user_temp" => "your Temp folder",
        "user_downloads" => "your Downloads folder",
        "user_profile" => "your user folder",
        _ => "an unusual folder",
    }
}

pub fn identify(process_name: &str, path: Option<&str>, meta: Option<&ExecutableMetadata>, sig: Option<&SignatureInfo>) -> Identity {
    let Some(_) = path else {
        return Identity {
            title: process_name.to_string(),
            maker: None,
            maker_verified: false,
            place: "hidden".into(),
            known: false,
            note: "Windows wouldn't show me its file. That's normal for protected system processes.".into(),
        };
    };
    let title = meta
        .and_then(|m| m.file_description.clone().or_else(|| m.product_name.clone()))
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| process_name.to_string());
    let place = place_label(meta.map(|m| m.location.as_str()).unwrap_or("other")).to_string();
    let known = sig.map(|s| s.status == "valid").unwrap_or(false);
    let signer = sig.filter(|_| known).and_then(|s| s.publisher.clone());
    let company = meta.and_then(|m| m.company_name.clone());
    let (maker, maker_verified) = match (signer, company) {
        (Some(s), _) => (Some(s), true),
        (None, c) => (c, false),
    };
    let risky_place = matches!(meta.map(|m| m.location.as_str()), Some("user_temp" | "user_downloads"));
    let note = if known {
        format!("Signed by {}. That proves who made it, not what it's doing right now.", maker.as_deref().unwrap_or("its publisher"))
    } else if sig.map(|s| s.status == "unavailable").unwrap_or(true) {
        "I couldn't check its signature. Unknown doesn't mean bad.".into()
    } else if risky_place {
        format!("No valid signature, and it runs from {place}. Unknown doesn't mean bad, but this one is worth a closer look.")
    } else {
        "No valid signature, so I can't confirm who made it. Many small tools are unsigned; unknown doesn't mean bad.".into()
    };
    Identity { title, maker, maker_verified, place, known, note }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(loc: &str, company: Option<&str>, desc: Option<&str>) -> ExecutableMetadata {
        ExecutableMetadata {
            exists: true,
            size_bytes: None,
            created_ms: None,
            modified_ms: None,
            company_name: company.map(String::from),
            file_description: desc.map(String::from),
            product_name: None,
            file_version: None,
            original_filename: None,
            location: loc.into(),
        }
    }
    fn sig(status: &str, publisher: Option<&str>) -> SignatureInfo {
        SignatureInfo { status: status.into(), kind: None, publisher: publisher.map(String::from), detail: String::new(), code: String::new() }
    }

    #[test]
    fn signed_program_is_known_with_verified_maker() {
        let m = meta("program_files", Some("Google LLC"), Some("Google Chrome"));
        let id = identify("chrome.exe", Some("C:\\Program Files\\x.exe"), Some(&m), Some(&sig("valid", Some("Google LLC"))));
        assert!(id.known && id.maker_verified);
        assert_eq!(id.title, "Google Chrome");
        assert_eq!(id.place, "Program Files");
    }

    #[test]
    fn unsigned_is_unknown_never_bad() {
        let m = meta("user_downloads", Some("Acme"), None);
        let id = identify("tool.exe", Some("C:\\Users\\a\\Downloads\\tool.exe"), Some(&m), Some(&sig("unsigned", None)));
        assert!(!id.known && !id.maker_verified);
        assert_eq!(id.maker.as_deref(), Some("Acme"));
        assert!(id.note.contains("doesn't mean bad"));
        assert!(!id.note.to_lowercase().contains("malware"));
    }

    #[test]
    fn missing_path_is_explained() {
        let id = identify("System", None, None, None);
        assert_eq!(id.place, "hidden");
        assert!(!id.known);
    }
}

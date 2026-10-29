//! Authenticode signature verification through WinVerifyTrust.
//!
//! Checks the embedded signature first, then the system catalog (most
//! Windows binaries are catalog-signed). Revocation checks are disabled and
//! URL retrieval is cache-only, so verification never touches the network.
//! The file is only read, never executed.

use serde::Serialize;
use windows::core::{w, GUID, PCWSTR};
use windows::Win32::Foundation::{
    CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_UNTRUSTEDROOT, CRYPT_E_FILE_ERROR, GENERIC_READ, HANDLE, HWND, TRUST_E_BAD_DIGEST,
    TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
};
use windows::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO,
    WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING};

use crate::collector::windows::OwnedHandle;

#[derive(Debug, Clone, Serialize)]
pub struct SignatureInfo {
    /// valid | unsigned | untrusted | invalid | expired | unavailable
    pub status: String,
    /// embedded | catalog
    pub kind: Option<String>,
    pub publisher: Option<String>,
    pub detail: String,
    pub code: String,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct VerifyOutcome {
    code: i32,
    publisher: Option<String>,
}

/// Run WinVerifyTrust with the given union choice, capture the signer name
/// while the state is open, then close the state.
unsafe fn verify(choice: windows::Win32::Security::WinTrust::WINTRUST_DATA_UNION_CHOICE, union: WINTRUST_DATA_0) -> VerifyOutcome {
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        Anonymous: union,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let code = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);

    let mut publisher = None;
    if !data.hWVTStateData.is_invalid() && !data.hWVTStateData.0.is_null() {
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if !prov.is_null() {
            let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
            if !sgnr.is_null() && (*sgnr).csCertChain > 0 && !(*sgnr).pasCertChain.is_null() {
                let cert = (*(*sgnr).pasCertChain).pCert;
                if !cert.is_null() {
                    let mut buf = [0u16; 256];
                    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
                    if n > 1 {
                        publisher = Some(String::from_utf16_lossy(&buf[..(n - 1) as usize]));
                    }
                }
            }
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
    VerifyOutcome { code, publisher }
}

unsafe fn verify_embedded(path: &[u16]) -> VerifyOutcome {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    verify(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &mut file })
}

/// Look the file's hash up in the system catalogs. Returns None when no
/// catalog contains it.
unsafe fn verify_catalog(path: &[u16]) -> Option<VerifyOutcome> {
    let file = CreateFileW(PCWSTR(path.as_ptr()), GENERIC_READ.0, FILE_SHARE_READ, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None).ok()?;
    let file = OwnedHandle(file);
    for algo in [w!("SHA256"), PCWSTR::null()] {
        let mut admin: isize = 0;
        if CryptCATAdminAcquireContext2(&mut admin, None, algo, None, None).is_err() {
            continue;
        }
        let mut len: u32 = 0;
        let _ = CryptCATAdminCalcHashFromFileHandle2(admin, file.0, &mut len, None, None);
        let mut hash = vec![0u8; len.max(1) as usize];
        let ok = len > 0 && CryptCATAdminCalcHashFromFileHandle2(admin, file.0, &mut len, Some(hash.as_mut_ptr()), None).is_ok();
        if !ok {
            let _ = CryptCATAdminReleaseContext(admin, 0);
            continue;
        }
        hash.truncate(len as usize);
        let cat = CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None);
        if cat == 0 {
            let _ = CryptCATAdminReleaseContext(admin, 0);
            continue;
        }
        let mut info = CATALOG_INFO { cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32, ..Default::default() };
        let result = if CryptCATCatalogInfoFromContext(cat, &mut info, 0).is_ok() {
            let tag: String = hash.iter().map(|b| format!("{b:02X}")).collect();
            let tag_w = wide(&tag);
            let mut ci = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                pcwszCatalogFilePath: PCWSTR(info.wszCatalogFile.as_ptr()),
                pcwszMemberTag: PCWSTR(tag_w.as_ptr()),
                pcwszMemberFilePath: PCWSTR(path.as_ptr()),
                hMemberFile: file.0,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash.len() as u32,
                hCatAdmin: admin,
                ..Default::default()
            };
            Some(verify(WTD_CHOICE_CATALOG, WINTRUST_DATA_0 { pCatalog: &mut ci }))
        } else {
            None
        };
        let _ = CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        let _ = CryptCATAdminReleaseContext(admin, 0);
        if result.is_some() {
            return result;
        }
    }
    None
}

fn describe(code: i32) -> (&'static str, &'static str) {
    if code == 0 {
        return ("valid", "The signature is valid and chains to a trusted root (revocation not checked, to stay offline).");
    }
    let h = windows::core::HRESULT(code);
    if h == TRUST_E_NOSIGNATURE || h == TRUST_E_SUBJECT_FORM_UNKNOWN || h == TRUST_E_PROVIDER_UNKNOWN {
        ("unsigned", "No Authenticode signature was found in the file or the system catalogs. Many legitimate tools are unsigned.")
    } else if h == CERT_E_EXPIRED {
        ("expired", "The file is signed, but the signing certificate has expired or the timestamp is outside its validity period.")
    } else if h == CERT_E_UNTRUSTEDROOT || h == CERT_E_CHAINING || h == TRUST_E_SUBJECT_NOT_TRUSTED || h == TRUST_E_EXPLICIT_DISTRUST {
        ("untrusted", "The file is signed, but the certificate chain is not trusted on this computer.")
    } else if h == TRUST_E_BAD_DIGEST {
        ("invalid", "The file's signature does not match its contents (the file changed after signing or the signature is corrupt).")
    } else if h == CRYPT_E_FILE_ERROR {
        ("unavailable", "The file could not be read for verification.")
    } else {
        ("unavailable", "The signature could not be evaluated.")
    }
}

/// Verify the Authenticode signature of an executable. Blocking; callers
/// must run this off the async runtime with a timeout.
pub fn check_signature(path: &str) -> SignatureInfo {
    let wpath = wide(path);
    unsafe {
        let embedded = verify_embedded(&wpath);
        let h = windows::core::HRESULT(embedded.code);
        let (outcome, kind) = if h == TRUST_E_NOSIGNATURE || h == TRUST_E_SUBJECT_FORM_UNKNOWN || h == TRUST_E_PROVIDER_UNKNOWN {
            match verify_catalog(&wpath) {
                Some(c) => (c, Some("catalog")),
                None => (embedded, None),
            }
        } else {
            (embedded, Some("embedded"))
        };
        let (status, detail) = describe(outcome.code);
        SignatureInfo {
            status: status.into(),
            kind: if status == "unsigned" { None } else { kind.map(String::from) },
            publisher: outcome.publisher,
            detail: detail.into(),
            code: format!("0x{:08X}", outcome.code as u32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notepad_is_signed_by_microsoft() {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let info = check_signature(&format!("{windir}\\System32\\notepad.exe"));
        assert_eq!(info.status, "valid", "{info:?}");
        assert!(info.publisher.unwrap_or_default().contains("Microsoft"));
    }

    #[test]
    fn missing_file_is_unavailable_not_malicious() {
        let info = check_signature("C:\\definitely\\not\\here.exe");
        assert_ne!(info.status, "valid");
        assert_ne!(info.status, "invalid");
    }
}

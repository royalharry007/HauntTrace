//! Native Windows toast notifications with Investigate / Snooze buttons.
//! Independent of the model and the network.
//!
//! Installed builds register the `haunttrace://` protocol (done by the
//! installer, never by the app), so the buttons use protocol activation and
//! keep working from Notification Center, under Do Not Disturb, and even if
//! HauntTrace was closed. Unregistered builds (portable, dev) fall back to
//! in-process activation, which works while the app is running.

use std::collections::VecDeque;
use std::sync::Mutex;

use windows::core::{Interface, HSTRING};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastActivatedEventArgs, ToastNotification, ToastNotificationManager};
use windows::Win32::System::Registry::{RegCloseKey, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

pub const SCHEME: &str = "haunttrace";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToastAction {
    Open(String),
    Investigate(String),
    Snooze(String),
}

/// PowerShell's registered AppUserModelID, used by unpackaged dev builds.
const POWERSHELL_APP_ID: &str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe";

/// Keep recent toasts alive so in-process activation handlers stay attached.
static LIVE: Mutex<VecDeque<ToastNotification>> = Mutex::new(VecDeque::new());

fn app_id(identifier: &str) -> String {
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().to_lowercase()).unwrap_or_default();
    if exe.contains("\\target\\debug\\") || exe.contains("\\target\\release\\") {
        POWERSHELL_APP_ID.to_string()
    } else {
        identifier.to_string()
    }
}

/// Read-only check: did the installer register the haunttrace:// protocol?
pub fn protocol_registered() -> bool {
    let sub = HSTRING::from(format!("Software\\Classes\\{SCHEME}"));
    for root in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        let mut key = HKEY::default();
        if unsafe { RegOpenKeyExW(root, &sub, None, KEY_READ, &mut key) }.is_ok() {
            unsafe {
                let _ = RegCloseKey(key);
            }
            return true;
        }
    }
    false
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// Parse an action from either a protocol URL (`haunttrace://investigate/ID`)
/// or an in-process argument (`investigate/ID`). Untrusted input: the ID is
/// only checked for shape here; callers must look it up.
pub fn parse_action(s: &str) -> Option<ToastAction> {
    let rest = s.trim().trim_matches('"');
    let rest = rest.strip_prefix(&format!("{SCHEME}://")).unwrap_or(rest);
    let rest = rest.trim_end_matches('/');
    let (verb, id) = rest.split_once('/')?;
    if id.is_empty() || id.len() > 80 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    let id = id.to_string();
    match verb {
        "investigate" => Some(ToastAction::Investigate(id)),
        "snooze" => Some(ToastAction::Snooze(id)),
        "open" => Some(ToastAction::Open(id)),
        _ => None,
    }
}

pub fn show_alert(identifier: &str, alert_id: &str, title: &str, line1: &str, line2: &str, on_action: impl Fn(ToastAction) + Send + Sync + 'static) -> Result<(), String> {
    let protocol = protocol_registered();
    let (kind, prefix) = if protocol { ("protocol", format!("{SCHEME}://")) } else { ("foreground", String::new()) };
    let arg = |verb: &str| esc(&format!("{prefix}{verb}/{alert_id}"));
    let xml = format!(
        "<toast launch=\"{open}\" activationType=\"{kind}\">\
           <visual><binding template=\"ToastGeneric\"><text>{t}</text><text>{l1}</text><text>{l2}</text></binding></visual>\
           <audio silent=\"true\"/>\
           <actions>\
             <action content=\"Investigate\" activationType=\"{kind}\" arguments=\"{inv}\"/>\
             <action content=\"Snooze 1 hour\" activationType=\"{kind}\" arguments=\"{snz}\"/>\
           </actions>\
         </toast>",
        open = arg("open"),
        inv = arg("investigate"),
        snz = arg("snooze"),
        t = esc(title),
        l1 = esc(line1),
        l2 = esc(line2),
    );
    let doc = XmlDocument::new().map_err(|e| e.to_string())?;
    doc.LoadXml(&HSTRING::from(xml)).map_err(|e| format!("toast XML: {e}"))?;
    let toast = ToastNotification::CreateToastNotification(&doc).map_err(|e| e.to_string())?;
    if !protocol {
        toast
            .Activated(&TypedEventHandler::new(move |_, args: windows::core::Ref<windows::core::IInspectable>| {
                if let Some(a) = args.as_ref().and_then(|i| i.cast::<ToastActivatedEventArgs>().ok()) {
                    if let Some(action) = a.Arguments().ok().and_then(|s| parse_action(&s.to_string())) {
                        on_action(action);
                    }
                }
                Ok(())
            }))
            .map_err(|e| e.to_string())?;
    }
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(app_id(identifier)))
        .and_then(|n| n.Show(&toast))
        .map_err(|e| format!("Windows notification failed: {e}"))?;
    let mut live = LIVE.lock().unwrap_or_else(|e| e.into_inner());
    live.push_back(toast);
    while live.len() > 20 {
        live.pop_front();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_well_formed_actions() {
        assert_eq!(parse_action("haunttrace://investigate/alert-1a2b-3c-0"), Some(ToastAction::Investigate("alert-1a2b-3c-0".into())));
        assert_eq!(parse_action("\"haunttrace://snooze/alert-1/\""), Some(ToastAction::Snooze("alert-1".into())));
        assert_eq!(parse_action("open/alert-9"), Some(ToastAction::Open("alert-9".into())));
        assert_eq!(parse_action("haunttrace://terminate/alert-1"), None);
        assert_eq!(parse_action("haunttrace://investigate/../../etc"), None);
        assert_eq!(parse_action("haunttrace://investigate/"), None);
        assert_eq!(parse_action("haunttrace://investigate/a b"), None);
    }

    #[test]
    fn xml_text_is_escaped() {
        assert_eq!(esc("<a & 'b'>"), "&lt;a &amp; &apos;b&apos;&gt;");
    }
}

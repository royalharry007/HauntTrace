//! HauntTrace: a lightweight local AI ghost detective for Windows.
//!
//! Components (each independently testable):
//! - `collector`      native Win32 process collection + identity tracking
//! - `detection`      deterministic rules with hysteresis/cooldowns
//! - `alerts`         delivery policy (quiet hours, snooze, rate limits)
//! - `investigation`  bounded evidence loop, tool registry, report validation
//! - `llm`            local Gemma adapter (Ollama, loopback only)
//! - `narration`      optional ElevenLabs voice adapter
//! - `win`            signature/metadata/credentials/sound/termination helpers
//! - `store`          SQLite evidence store
//! - `app` / `commands`  wiring and the UI command surface

pub mod alerts;
pub mod chat;
pub mod spirit;
pub mod sweep;
pub mod collector;
pub mod detection;
pub mod investigation;
pub mod llm;
pub mod logging;
pub mod narration;
pub mod settings;
pub mod store;
pub mod types;

#[cfg(windows)]
pub mod app;
#[cfg(windows)]
mod commands;
#[cfg(windows)]
pub mod notify;
#[cfg(windows)]
pub mod win;

#[cfg(windows)]
use std::sync::atomic::Ordering;

#[cfg(windows)]
use tauri::menu::{CheckMenuItem, Menu, MenuItem};
#[cfg(windows)]
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
#[cfg(windows)]
use tauri::{AppHandle, Emitter, Manager, RunEvent, Wry};

#[cfg(windows)]
struct TrayItems {
    monitor: CheckMenuItem<Wry>,
    mute: CheckMenuItem<Wry>,
}

/// Sync tray checkmarks and tooltip with the current state.
#[cfg(windows)]
pub fn refresh_tray(app: &AppHandle) {
    let (Some(items), Some(st)) = (app.try_state::<TrayItems>(), app.try_state::<app::AppState>()) else { return };
    let _ = items.monitor.set_checked(st.settings().monitoring.enabled);
    let _ = items.mute.set_checked(st.muted.load(Ordering::Relaxed));
    if let Some(tray) = app.tray_by_id("main") {
        let label = match st.ghost_state() {
            "investigating" => "HauntTrace: investigating",
            "watching" => "HauntTrace: watching",
            _ => "HauntTrace: quiet (monitoring paused)",
        };
        let _ = tray.set_tooltip(Some(label));
    }
}

#[cfg(windows)]
pub fn apply_mute(app: &AppHandle, st: &app::AppState, muted: bool) {
    st.muted.store(muted, Ordering::Relaxed);
    let _ = app::lock(&st.store).set_kv("muted", if muted { "true" } else { "false" });
    if muted {
        win::sound::stop();
    }
    let _ = app.emit("audio://mute", serde_json::json!({"muted": muted}));
    logging::info("mute_toggled", serde_json::json!({"muted": muted}));
    refresh_tray(app);
}

#[cfg(windows)]
fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let st = app.state::<app::AppState>();
    let open = MenuItem::with_id(app, "open", "Open HauntTrace", true, None::<&str>)?;
    let monitor = CheckMenuItem::with_id(app, "monitor", "Monitoring", true, st.settings().monitoring.enabled, None::<&str>)?;
    let mute = CheckMenuItem::with_id(app, "mute", "Mute all sounds", true, st.muted.load(Ordering::Relaxed), None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit HauntTrace", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &monitor, &mute, &quit])?;
    app.manage(TrayItems { monitor, mute });
    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().cloned().expect("bundled icon"))
        .tooltip("HauntTrace")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| {
            let st = app.state::<app::AppState>();
            match ev.id().as_ref() {
                "open" => app::show_main(app),
                "monitor" => {
                    let enabled = !st.settings().monitoring.enabled;
                    let mut s = st.settings();
                    s.monitoring.enabled = enabled;
                    let _ = app::lock(&st.store).save_settings(&s);
                    *st.settings.write().unwrap_or_else(|e| e.into_inner()) = s;
                    let _ = app.emit("settings://changed", ());
                    app::emit_status(app);
                    refresh_tray(app);
                }
                "mute" => {
                    let m = !st.muted.load(Ordering::Relaxed);
                    apply_mute(app, &st, m);
                }
                "quit" => {
                    for r in app::lock(&st.running).values() {
                        r.cancel.cancel();
                    }
                    win::sound::stop();
                    app.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                app::show_main(tray.app_handle());
            }
        })
        .build(app)?;
    refresh_tray(app);
    Ok(())
}

#[cfg(windows)]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    use tauri_plugin_deep_link::DeepLinkExt;
    tauri::Builder::default()
        // A second launch (e.g. from a notification link) is forwarded to
        // the running instance instead of starting another monitor.
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if !argv.iter().any(|a| a.contains("://snooze/")) {
                app::show_main(app);
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            let handle = app.handle().clone();
            let state = app::build_state(&handle).map_err(|e| Box::<dyn std::error::Error>::from(e))?;
            app.manage(state);
            let h2 = handle.clone();
            handle.deep_link().on_open_url(move |event| {
                for url in event.urls() {
                    if let Some(action) = notify::parse_action(url.as_str()) {
                        app::handle_toast_action(&h2, action);
                    }
                }
            });
            if let Ok(Some(urls)) = handle.deep_link().get_current() {
                for url in urls {
                    if let Some(action) = notify::parse_action(url.as_str()) {
                        app::handle_toast_action(&handle, action);
                    }
                }
            }
            logging::info("startup", serde_json::json!({"version": handle.package_info().version.to_string()}));
            setup_tray(&handle)?;
            app::start_monitor(handle.clone());
            if std::env::args().any(|a| a == "--background") {
                if let Some(w) = handle.get_webview_window("main") {
                    let _ = w.destroy();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_settings,
            commands::save_settings,
            commands::set_monitoring,
            commands::set_muted,
            commands::list_alerts,
            commands::get_alert,
            commands::dismiss_alert,
            commands::delete_alert,
            commands::start_investigation,
            commands::cancel_investigation,
            commands::get_investigation,
            commands::list_investigations,
            commands::snooze_process,
            commands::list_snoozes,
            commands::clear_snooze,
            commands::exclude_process,
            commands::open_file_location,
            commands::terminate_process,
            commands::test_sound,
            commands::model_diagnostics,
            commands::suggested_models,
            commands::pull_model,
            commands::cancel_pull,
            commands::voice_status,
            commands::save_voice_key,
            commands::clear_voice_key,
            commands::test_voice,
            commands::narration_audio,
            commands::diagnostics,
            commands::delete_all_history,
            commands::launch_test_process,
            commands::take_pending_navigation,
            commands::windows_voices,
            commands::elevenlabs_voices,
            commands::setup_completed,
            commands::set_setup_completed,
            commands::ask_ghost,
            commands::speak_text,
            commands::spirit_identity,
            commands::sweep_house,
            commands::summon_spirit,
        ])
        .build(tauri::generate_context!())
        .expect("error while building HauntTrace")
        .run(|_app, event| {
            // Closing the window destroys the WebView (freeing its memory) but
            // keeps the native monitor running in the tray. Only "Quit" exits.
            if let RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}

#[cfg(not(windows))]
pub fn run() {
    eprintln!("HauntTrace is a Windows application.");
}

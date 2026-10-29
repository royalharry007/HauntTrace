//! Tauri commands: the only interface the UI has to the system. Every
//! consequential action requires an explicit, specific user request.

use std::sync::atomic::Ordering;

use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, State};
use tokio_util::sync::CancellationToken;

use crate::app::{emit_status, lock, start_investigation as start_inv, AppState, MonitorStats};
use crate::investigation::provider::TEST_PROCESS_NAME;
use crate::llm::{self, ModelDiagnostics};
use crate::logging::{self, LogEntry};
use crate::settings::Settings;
use crate::store::{ActionRecord, AlertRecord, InvestigationDetail, InvestigationRecord, StoreStats};
use crate::types::{filetime_to_unix_ms, now_ms, ProcessKey};
use crate::{alerts, win};

type R<T> = Result<T, String>;

#[derive(Serialize)]
pub struct StatusPayload {
    pub ghost: &'static str,
    pub monitoring: bool,
    pub muted: bool,
    pub active_investigations: Vec<Value>,
    pub process_count: usize,
    pub last_sample_ms: u64,
    pub interval_secs: u32,
    pub voice_enabled: bool,
    /// Total CPU in use (% of the machine) and physical memory in use (%).
    pub cpu_total: f32,
    pub memory_used_pct: Option<f32>,
    /// 0 calm · 1 uneasy · 2 haunted
    pub haunt_level: u8,
}

#[tauri::command]
pub fn get_status(st: State<'_, AppState>) -> StatusPayload {
    let s = st.settings();
    let stats = lock(&st.stats).clone();
    let cpu_total = crate::sweep::cpu_total(&lock(&st.tracker));
    let memory_used_pct = win::memory_status().filter(|m| m.total_bytes > 0).map(|m| (100.0 * (1.0 - m.available_bytes as f64 / m.total_bytes as f64)) as f32);
    StatusPayload {
        ghost: st.ghost_state(),
        monitoring: s.monitoring.enabled,
        muted: st.muted.load(Ordering::Relaxed),
        active_investigations: lock(&st.running).iter().map(|(id, r)| json!({"investigation_id": id, "alert_id": r.alert_id})).collect(),
        process_count: stats.process_count,
        last_sample_ms: stats.last_sample_ms,
        interval_secs: s.monitoring.interval_secs,
        voice_enabled: s.voice.enabled(),
        cpu_total,
        memory_used_pct,
        haunt_level: crate::sweep::haunt_level(cpu_total, memory_used_pct),
    }
}

#[tauri::command]
pub fn get_settings(st: State<'_, AppState>) -> Settings {
    st.settings()
}

#[tauri::command]
pub fn save_settings(app: AppHandle, st: State<'_, AppState>, settings: Settings) -> R<Settings> {
    let s = settings.sanitized()?;
    lock(&st.store).save_settings(&s)?;
    *st.settings.write().unwrap_or_else(|e| e.into_inner()) = s.clone();
    logging::info("settings_saved", json!({"interval": s.monitoring.interval_secs, "model": s.model.model, "voice": s.voice.mode}));
    emit_status(&app);
    crate::refresh_tray(&app);
    Ok(s)
}

#[tauri::command]
pub fn set_monitoring(app: AppHandle, st: State<'_, AppState>, enabled: bool) -> R<()> {
    let mut s = st.settings();
    s.monitoring.enabled = enabled;
    lock(&st.store).save_settings(&s)?;
    *st.settings.write().unwrap_or_else(|e| e.into_inner()) = s;
    if !enabled {
        lock(&st.detector).reset();
    }
    logging::info("monitoring_toggled", json!({"enabled": enabled}));
    emit_status(&app);
    crate::refresh_tray(&app);
    Ok(())
}

#[tauri::command]
pub fn set_muted(app: AppHandle, st: State<'_, AppState>, muted: bool) -> R<()> {
    crate::apply_mute(&app, &st, muted);
    Ok(())
}

#[tauri::command]
pub fn list_alerts(st: State<'_, AppState>, limit: Option<u32>) -> R<Vec<AlertRecord>> {
    lock(&st.store).list_alerts(limit.unwrap_or(100).min(1000))
}

#[derive(Serialize)]
pub struct LiveProcess {
    pub alive: bool,
    pub exited_ms: Option<u64>,
    pub runtime_ms: Option<u64>,
    pub cpu_latest: Option<f32>,
    pub cpu_avg_5min: Option<f32>,
    pub private_bytes: Option<u64>,
    pub working_set: Option<u64>,
    pub logical_cpus: u32,
    /// [unix ms, cpu %, private bytes] for the last 10 minutes.
    pub history: Vec<(u64, Option<f32>, u64)>,
}

#[derive(Serialize)]
pub struct AlertView {
    pub alert: AlertRecord,
    pub live: Option<LiveProcess>,
    pub actions: Vec<ActionRecord>,
    pub is_test_process: bool,
    pub excluded: bool,
}

#[tauri::command]
pub fn get_alert(st: State<'_, AppState>, id: String) -> R<AlertView> {
    let alert = lock(&st.store).get_alert(&id)?.ok_or("Alert not found")?;
    let created: u64 = alert.process_created.parse().unwrap_or(0);
    let key = ProcessKey { pid: alert.pid, created };
    let now = now_ms();
    let live = {
        let t = lock(&st.tracker);
        t.get(&key).map(|p| {
            let since5 = now.saturating_sub(300_000);
            let cpus: Vec<f32> = p.history.iter().filter(|s| s.t >= since5 && !s.cpu.is_nan()).map(|s| s.cpu).collect();
            LiveProcess {
                alive: p.alive(),
                exited_ms: p.exited_at,
                runtime_ms: if created != 0 { Some(now.saturating_sub(filetime_to_unix_ms(created))) } else { None },
                cpu_latest: p.latest().map(|s| s.cpu).filter(|c| !c.is_nan()),
                cpu_avg_5min: if cpus.is_empty() { None } else { Some(cpus.iter().sum::<f32>() / cpus.len() as f32) },
                private_bytes: p.latest().map(|s| s.private_bytes),
                working_set: p.latest().map(|s| s.working_set),
                logical_cpus: t.logical_cpus,
                history: p
                    .history
                    .iter()
                    .filter(|s| s.t >= now.saturating_sub(600_000))
                    .map(|s| (s.t, if s.cpu.is_nan() { None } else { Some(s.cpu) }, s.private_bytes))
                    .collect(),
            }
        })
    };
    let actions = lock(&st.store).actions_for(&id)?;
    let excluded = st.settings().is_excluded(&alert.process_name, alert.exe_path.as_deref());
    Ok(AlertView { is_test_process: alert.process_name.eq_ignore_ascii_case(TEST_PROCESS_NAME), alert, live, actions, excluded })
}

#[tauri::command]
pub fn dismiss_alert(st: State<'_, AppState>, id: String) -> R<()> {
    lock(&st.store).set_alert_status(&id, "dismissed", None)?;
    st.record_action(Some(&id), None, "dismiss", "Alert dismissed", "done");
    Ok(())
}

#[tauri::command]
pub fn delete_alert(st: State<'_, AppState>, id: String) -> R<()> {
    if lock(&st.running).values().any(|r| r.alert_id == id) {
        return Err("Cancel the running investigation before deleting this alert.".into());
    }
    lock(&st.store).delete_alert(&id)
}

#[tauri::command]
pub fn start_investigation(app: AppHandle, alert_id: String) -> R<String> {
    start_inv(&app, &alert_id)
}

#[tauri::command]
pub fn cancel_investigation(st: State<'_, AppState>, id: String) -> R<()> {
    let running = lock(&st.running);
    let r = running.get(&id).ok_or("That investigation is not running.")?;
    r.cancel.cancel();
    logging::info("investigation_cancel_requested", json!({"id": id}));
    Ok(())
}

#[tauri::command]
pub fn get_investigation(st: State<'_, AppState>, id: String) -> R<InvestigationDetail> {
    lock(&st.store).get_investigation(&id)?.ok_or_else(|| "Investigation not found".into())
}

#[tauri::command]
pub fn list_investigations(st: State<'_, AppState>, limit: Option<u32>) -> R<Vec<InvestigationRecord>> {
    lock(&st.store).list_investigations(limit.unwrap_or(200).min(2000))
}

#[tauri::command]
pub fn snooze_process(st: State<'_, AppState>, alert_id: String, minutes: u32) -> R<()> {
    let minutes = minutes.clamp(5, 7 * 24 * 60);
    let a = lock(&st.store).get_alert(&alert_id)?.ok_or("Alert not found")?;
    lock(&st.policy).snooze(alerts::snooze_key(&a.process_name, a.exe_path.as_deref()), now_ms() + minutes as u64 * 60_000);
    st.record_action(Some(&alert_id), a.investigation_id.as_deref(), "snooze", &format!("Snoozed alerts for {} for {} min", a.process_name, minutes), "done");
    Ok(())
}

#[tauri::command]
pub fn list_snoozes(st: State<'_, AppState>) -> Vec<(String, u64)> {
    lock(&st.policy).snoozes(now_ms())
}

#[tauri::command]
pub fn clear_snooze(st: State<'_, AppState>, key: String) {
    lock(&st.policy).unsnooze(&key);
}

/// Mark a program as trusted (exclusion), by process name or exact path.
#[tauri::command]
pub fn exclude_process(app: AppHandle, st: State<'_, AppState>, alert_id: String, by_path: bool) -> R<Settings> {
    let a = lock(&st.store).get_alert(&alert_id)?.ok_or("Alert not found")?;
    let entry = if by_path { a.exe_path.clone().ok_or("The executable path is unknown; exclude by name instead.")? } else { a.process_name.clone() };
    let mut s = st.settings();
    if !s.exclusions.iter().any(|e| e.eq_ignore_ascii_case(&entry)) {
        s.exclusions.push(entry.clone());
    }
    let s = save_settings(app, st.clone(), s)?;
    st.record_action(Some(&alert_id), a.investigation_id.as_deref(), "exclude", &format!("Added \"{}\" to trusted exclusions", win::redact_user_path(&entry)), "done");
    Ok(s)
}

/// Open Explorer with the executable selected. Read-only for the system.
#[tauri::command]
pub fn open_file_location(st: State<'_, AppState>, alert_id: String) -> R<()> {
    let a = lock(&st.store).get_alert(&alert_id)?.ok_or("Alert not found")?;
    let path = a.exe_path.clone().ok_or("The executable path is not known for this process.")?;
    if !std::path::Path::new(&path).is_file() {
        return Err("The executable no longer exists at the recorded path.".into());
    }
    std::process::Command::new("explorer.exe").arg(format!("/select,{path}")).spawn().map_err(|e| e.to_string())?;
    st.record_action(Some(&alert_id), a.investigation_id.as_deref(), "open_location", "Opened the file location in Explorer", "done");
    Ok(())
}

/// End exactly the alerted process instance. The UI must pass the process
/// name the user typed/confirmed; PID reuse is guarded by creation time.
#[tauri::command]
pub fn terminate_process(st: State<'_, AppState>, alert_id: String, confirm_name: String) -> R<String> {
    let a = lock(&st.store).get_alert(&alert_id)?.ok_or("Alert not found")?;
    if !confirm_name.eq_ignore_ascii_case(&a.process_name) {
        return Err("Confirmation did not match the process name. Nothing was ended.".into());
    }
    let created: u64 = a.process_created.parse().map_err(|_| "Unknown process identity")?;
    if created == 0 {
        return Err("This process's identity could not be verified, so HauntTrace will not end it.".into());
    }
    let result = win::terminate_instance(a.pid, created);
    let outcome = match &result {
        Ok(()) => "done".to_string(),
        Err(e) => format!("failed: {e}"),
    };
    st.record_action(Some(&alert_id), a.investigation_id.as_deref(), "terminate", &format!("Ended {} (PID {}) at your request", a.process_name, a.pid), &outcome);
    result.map(|_| format!("{} (PID {}) was ended.", a.process_name, a.pid))
}

#[tauri::command]
pub fn test_sound(st: State<'_, AppState>, warning: bool) {
    let v = st.settings().alerts.volume;
    win::sound::play(if warning { win::sound::Tone::Warning } else { win::sound::Tone::Soft }, v);
}

#[tauri::command]
pub async fn model_diagnostics(st: State<'_, AppState>, run_test: bool) -> R<ModelDiagnostics> {
    let cfg = st.settings().model;
    let d = llm::diagnose(&cfg, run_test).await;
    logging::info("model_diagnostics", json!({"reachable": d.runtime_reachable, "available": d.selected_model_available, "test_ok": d.test_ok, "latency_ms": d.test_latency_ms}));
    Ok(d)
}

#[tauri::command]
pub fn suggested_models() -> Vec<Value> {
    llm::suggested_models()
}

/// Explicit user-initiated model download. Progress arrives as events.
#[tauri::command]
pub async fn pull_model(app: AppHandle, st: State<'_, AppState>, model: String) -> R<()> {
    let model = model.trim().to_string();
    if model.is_empty() || model.len() > 100 || !model.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:/".contains(c)) {
        return Err("Invalid model name".into());
    }
    let cancel = CancellationToken::new();
    *lock(&st.pull_cancel) = Some(cancel.clone());
    let cfg = st.settings().model;
    logging::info("model_pull_started", json!({"model": model}));
    let app2 = app.clone();
    let m2 = model.clone();
    let mut last_emit = std::time::Instant::now() - std::time::Duration::from_secs(1);
    let r = llm::pull_model(&cfg, &model, cancel, move |status, done, total| {
        if last_emit.elapsed().as_millis() > 250 || total == 0 {
            last_emit = std::time::Instant::now();
            let _ = app2.emit("model://pull", json!({"model": m2, "status": status, "completed": done, "total": total}));
        }
    })
    .await;
    *lock(&st.pull_cancel) = None;
    let _ = app.emit("model://pull", json!({"model": model, "status": if r.is_ok() { "success" } else { "error" }, "error": r.as_ref().err(), "done": true}));
    logging::info("model_pull_finished", json!({"model": model, "ok": r.is_ok()}));
    r
}

#[tauri::command]
pub fn cancel_pull(st: State<'_, AppState>) {
    if let Some(c) = lock(&st.pull_cancel).take() {
        c.cancel();
    }
}

#[derive(Serialize)]
pub struct VoiceStatus {
    pub mode: String,
    pub key_saved: bool,
    pub voice_id_set: bool,
}

#[tauri::command]
pub fn voice_status(st: State<'_, AppState>) -> VoiceStatus {
    let v = st.settings().voice;
    VoiceStatus { mode: v.mode.clone(), key_saved: win::credential_read().is_some(), voice_id_set: !v.voice_id.is_empty() }
}

/// Save the ElevenLabs key into Windows Credential Manager. The key is
/// never returned to the UI.
#[tauri::command]
pub fn save_voice_key(key: String) -> R<()> {
    let key = key.trim().to_string();
    if key.len() < 10 || key.len() > 200 || key.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("That does not look like an ElevenLabs API key.".into());
    }
    win::credential_write(&key)?;
    logging::info("voice_key_saved", json!({}));
    Ok(())
}

#[tauri::command]
pub fn clear_voice_key(st: State<'_, AppState>) -> R<()> {
    win::credential_delete()?;
    st.narrator.clear_cache();
    logging::info("voice_key_cleared", json!({}));
    Ok(())
}

#[tauri::command]
pub async fn test_voice(st: State<'_, AppState>) -> R<tauri::ipc::Response> {
    let bytes = crate::app::synthesize(&st, "Hello. I am the ghost in your machine. I will whisper when something lingers.").await?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// Narration audio for a finished investigation (from cache when possible).
#[tauri::command]
pub async fn narration_audio(st: State<'_, AppState>, investigation_id: String) -> R<tauri::ipc::Response> {
    if !st.settings().voice.enabled() {
        return Err("Voice narration is turned off.".into());
    }
    let detail = lock(&st.store).get_investigation(&investigation_id)?.ok_or("Investigation not found")?;
    let text = detail.investigation.report.as_ref().and_then(|r| r["narration"].as_str()).map(String::from).ok_or("This investigation has no narration line.")?;
    let bytes = crate::app::synthesize(&st, &text).await?;
    Ok(tauri::ipc::Response::new(bytes))
}

#[derive(Serialize)]
pub struct Diagnostics {
    pub version: String,
    pub monitor: MonitorStats,
    pub store: StoreStats,
    pub data_dir: String,
    pub log_path: Option<String>,
    pub logs: Vec<LogEntry>,
    pub logical_cpus: u32,
    pub memory: Option<win::MemoryStatus>,
    pub is_elevated_hint: String,
}

#[tauri::command]
pub fn diagnostics(app: AppHandle, st: State<'_, AppState>) -> Diagnostics {
    Diagnostics {
        version: app.package_info().version.to_string(),
        monitor: lock(&st.stats).clone(),
        store: lock(&st.store).stats(),
        data_dir: win::redact_user_path(&st.data_dir.to_string_lossy()),
        log_path: logging::path().map(|p| win::redact_user_path(&p.to_string_lossy())),
        logs: logging::recent(120),
        logical_cpus: crate::collector::windows::logical_cpu_count(),
        memory: win::memory_status(),
        is_elevated_hint: "HauntTrace runs without administrator rights. Some system and protected processes cannot be inspected; they are reported as 'access denied', never as suspicious.".into(),
    }
}

#[tauri::command]
pub fn delete_all_history(st: State<'_, AppState>) -> R<()> {
    if !lock(&st.running).is_empty() {
        return Err("Cancel running investigations first.".into());
    }
    lock(&st.store).delete_all_history()?;
    st.narrator.clear_cache();
    logging::info("history_deleted", json!({}));
    Ok(())
}

/// Launch HauntTrace's controlled test process: a bounded, self-terminating
/// load generator used to demonstrate detection on real measurements.
#[tauri::command]
pub fn launch_test_process(mode: String, seconds: u32) -> R<String> {
    if !matches!(mode.as_str(), "cpu" | "spikes" | "memory" | "restart") {
        return Err("Unknown test mode".into());
    }
    let seconds = seconds.clamp(30, 900);
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let burner = exe.with_file_name(TEST_PROCESS_NAME);
    if !burner.is_file() {
        return Err(format!("{TEST_PROCESS_NAME} was not found next to HauntTrace. Build it with `npm run build:burner`."));
    }
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let child = std::process::Command::new(burner)
        .args(["--mode", &mode, "--seconds", &seconds.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| e.to_string())?;
    logging::info("test_process_launched", json!({"mode": mode, "seconds": seconds, "pid": child.id()}));
    Ok(format!("Started {TEST_PROCESS_NAME} (PID {}) in '{mode}' mode for up to {seconds} s.", child.id()))
}

/// Navigation requested (e.g. from a toast) before the window finished loading.
#[tauri::command]
pub fn take_pending_navigation(st: State<'_, AppState>) -> Option<Value> {
    lock(&st.pending_nav).take()
}

/// Voices built into Windows (offline narration mode).
#[tauri::command]
pub async fn windows_voices() -> R<Vec<String>> {
    tokio::task::spawn_blocking(win::tts::voices).await.map_err(|e| e.to_string())?
}

/// Voices available to the saved ElevenLabs key.
#[tauri::command]
pub async fn elevenlabs_voices(st: State<'_, AppState>) -> R<Vec<Value>> {
    st.narrator.list_voices(win::credential_read()).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn setup_completed(st: State<'_, AppState>) -> bool {
    lock(&st.store).get_kv("setup_completed").map(|v| v == "true").unwrap_or(false)
}

#[tauri::command]
pub fn set_setup_completed(st: State<'_, AppState>, done: bool) -> R<()> {
    lock(&st.store).set_kv("setup_completed", if done { "true" } else { "false" })?;
    logging::info("setup_completed", json!({"done": done}));
    Ok(())
}

/// Ask the ghost a question about one haunting (or in general). Answered by
/// the local model only, from stored case notes; no tools, no actions.
#[tauri::command]
pub async fn ask_ghost(st: State<'_, AppState>, question: String, alert_id: Option<String>, history: Vec<crate::chat::ChatTurn>) -> R<String> {
    let question = crate::chat::validate_question(&question)?;
    let settings = st.settings();
    let notes = {
        let store = lock(&st.store);
        let alert = match alert_id.as_deref() {
            Some(id) => Some(store.get_alert(id)?.ok_or("That haunting no longer exists.")?),
            None => None,
        };
        let inv = match alert.as_ref().and_then(|a| a.investigation_id.clone()) {
            Some(i) => store.get_investigation(&i)?,
            None => None,
        };
        crate::chat::case_notes(alert.as_ref(), inv.as_ref(), lock(&st.stats).process_count, settings.monitoring.enabled)
    };
    let model = llm::OllamaClient::new(&settings.model)?;
    let reply = crate::chat::ask(&model, &notes, &history, &question).await.map_err(|e| e.to_string())?;
    logging::info("ghost_chat", json!({"alert_id": alert_id, "question_chars": question.len(), "reply_chars": reply.len()}));
    Ok(reply)
}

/// Speak a line in the ghost's voice (Windows voice or ElevenLabs). The text
/// is sanitized and clipped before synthesis; only that text leaves the PC
/// in ElevenLabs mode.
#[tauri::command]
pub async fn speak_text(st: State<'_, AppState>, text: String) -> R<tauri::ipc::Response> {
    if !st.settings().voice.enabled() {
        return Err("The ghost's voice is off.".into());
    }
    if text.chars().count() > 1000 {
        return Err("That is too much to say at once.".into());
    }
    let bytes = crate::app::synthesize(&st, &text).await?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// Who made the process behind a haunting and where it lives (signature,
/// version resource, folder). Read-only; never a malware verdict.
#[tauri::command]
pub async fn spirit_identity(st: State<'_, AppState>, alert_id: String) -> R<crate::spirit::Identity> {
    let alert = lock(&st.store).get_alert(&alert_id)?.ok_or("That haunting no longer exists.")?;
    let Some(path) = alert.exe_path.clone() else {
        return Ok(crate::spirit::identify(&alert.process_name, None, None, None));
    };
    let p = path.clone();
    let work = tokio::task::spawn_blocking(move || (win::metadata::read_metadata(&p), win::signature::check_signature(&p)));
    let (meta, sig) = tokio::time::timeout(std::time::Duration::from_secs(15), work).await.map_err(|_| "Checking the file took too long.")?.map_err(|e| e.to_string())?;
    Ok(crate::spirit::identify(&alert.process_name, Some(&path), Some(&meta), Some(&sig)))
}

/// Who is using this PC right now, without waiting for a rule to fire.
#[tauri::command]
pub fn sweep_house(st: State<'_, AppState>) -> Vec<crate::sweep::SweepEntry> {
    crate::sweep::sweep(&lock(&st.tracker), now_ms(), std::process::id(), 4, 2)
}

/// Turn a process from a sweep into a spirit the user can inspect,
/// investigate, befriend, shoo or banish. Reuses an open one if it exists.
#[tauri::command]
pub fn summon_spirit(app: AppHandle, st: State<'_, AppState>, pid: u32, created: String) -> R<String> {
    let created: u64 = created.parse().map_err(|_| "Bad process identity.")?;
    let key = ProcessKey { pid, created };
    let now = now_ms();
    let (p, ncpu) = {
        let tracker = lock(&st.tracker);
        let p = tracker.get(&key).filter(|p| p.alive()).cloned().ok_or("That program has already left the house.")?;
        (p, tracker.logical_cpus)
    };
    let store = lock(&st.store);
    if let Some(open) = store.list_alerts(200)?.into_iter().find(|a| {
        a.rule == "summoned" && a.pid == pid && a.process_created == created.to_string() && matches!(a.status.as_str(), "new" | "investigating" | "investigated")
    }) {
        return Ok(open.id);
    }
    let m = crate::detection::metrics_for(&p, now, 60_000, ncpu);
    let reason = format!(
        "You swept the house and picked it: {:.1}% CPU right now ({:.1}% average over the last minute), {:.0} MB of private memory. No rule had flagged it.",
        m.cpu_latest.unwrap_or(0.0),
        m.cpu_avg.unwrap_or(0.0),
        m.private_bytes.unwrap_or(0) as f64 / 1_048_576.0
    );
    let alert = AlertRecord {
        id: crate::app::new_id("alert"),
        created_ms: now,
        rule: "summoned".into(),
        rule_label: crate::detection::RuleKind::Summoned.label().into(),
        priority: "info".into(),
        pid,
        process_created: created.to_string(),
        process_name: p.name.clone(),
        exe_path: p.exe_path.clone(),
        reason,
        metrics: serde_json::to_value(&m).unwrap_or(Value::Null),
        details: json!({"source": "sweep"}),
        delivery: json!({"kind": "silent", "reason": "summoned from a sweep"}),
        status: "new".into(),
        investigation_id: None,
        synthetic: false,
    };
    store.insert_alert(&alert)?;
    drop(store);
    logging::info("spirit_summoned", json!({"process": alert.process_name, "pid": pid}));
    let _ = app.emit("status://changed", json!({}));
    Ok(alert.id)
}

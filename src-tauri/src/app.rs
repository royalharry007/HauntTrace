//! Application wiring: shared state, the background monitor loop, alert
//! delivery, and the investigation runner. Each concern delegates to its own
//! module; this file only connects them to the store and the UI.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use tokio_util::sync::CancellationToken;

use crate::alerts::{snooze_key, AlertPolicy, Delivery};
use crate::collector::tracker::{Tracker, TrackerConfig};
use crate::collector::windows::WinProcessSource;
use crate::collector::ProcessSource;
use crate::detection::{Detection, Detector, Priority, RuleKind};
use crate::investigation::provider::LiveProvider;
use crate::investigation::{self, Limits, Sink, Subject};
use crate::llm::{ModelClient, OllamaClient};
use crate::narration::Narrator;
use crate::settings::Settings;
use crate::store::{ActionRecord, AlertRecord, EvidenceRecord, InvestigationRecord, StepRecord, Store};
use crate::types::{now_ms, ProcessKey};
use crate::{logging, notify, win};

#[derive(Debug, Clone, Serialize, Default)]
pub struct MonitorStats {
    pub started_ms: u64,
    pub samples: u64,
    pub last_sample_ms: u64,
    pub last_sample_duration_ms: f64,
    pub avg_sample_duration_ms: f64,
    pub process_count: usize,
    pub last_error: Option<String>,
    pub alerts_raised: u64,
    pub alerts_suppressed: u64,
    pub self_cpu_percent: Option<f32>,
    pub self_private_mb: Option<f64>,
    pub self_working_set_mb: Option<f64>,
}

pub struct RunningInvestigation {
    pub alert_id: String,
    pub cancel: CancellationToken,
}

pub struct AppState {
    pub identifier: String,
    pub settings: RwLock<Settings>,
    pub tracker: Arc<Mutex<Tracker>>,
    pub detector: Mutex<Detector>,
    pub policy: Mutex<AlertPolicy>,
    pub store: Mutex<Store>,
    pub running: Mutex<HashMap<String, RunningInvestigation>>,
    pub narrator: Narrator,
    pub muted: AtomicBool,
    pub stats: Mutex<MonitorStats>,
    pub narrated: Mutex<HashSet<String>>,
    pub pull_cancel: Mutex<Option<CancellationToken>>,
    /// Navigation requested from a toast while the window may be loading.
    pub pending_nav: Mutex<Option<Value>>,
    pub data_dir: std::path::PathBuf,
}

pub fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl AppState {
    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn ghost_state(&self) -> &'static str {
        if !lock(&self.running).is_empty() {
            "investigating"
        } else if self.settings().monitoring.enabled {
            "watching"
        } else {
            "quiet"
        }
    }

    pub fn record_action(&self, alert_id: Option<&str>, investigation_id: Option<&str>, action: &str, detail: &str, outcome: &str) {
        let rec = ActionRecord {
            created_ms: now_ms(),
            alert_id: alert_id.map(String::from),
            investigation_id: investigation_id.map(String::from),
            action: action.into(),
            detail: detail.into(),
            outcome: outcome.into(),
        };
        if let Err(e) = lock(&self.store).record_action(&rec) {
            logging::error("action_record_failed", json!({"error": e}));
        }
        logging::info("user_action", json!({"action": action, "outcome": outcome}));
    }
}

static ID_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

pub fn new_id(prefix: &str) -> String {
    let n = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{:x}-{:x}-{:x}", now_ms(), std::process::id() & 0xffff, n)
}

pub fn emit_status(app: &AppHandle) {
    if let Some(st) = app.try_state::<AppState>() {
        let _ = app.emit("status://changed", json!({"ghost": st.ghost_state(), "active_investigations": lock(&st.running).len()}));
    }
}

// ---------------- Monitor loop ----------------

pub fn start_monitor(app: AppHandle) {
    std::thread::Builder::new()
        .name("haunttrace-monitor".into())
        .spawn(move || monitor_loop(app))
        .expect("spawn monitor thread");
}

fn monitor_loop(app: AppHandle) {
    let mut source = WinProcessSource::new();
    let mut last_prune = Instant::now();
    let own_pid = std::process::id();
    loop {
        let st = app.state::<AppState>();
        let settings = st.settings();
        let interval = Duration::from_secs(settings.monitoring.interval_secs as u64);
        if settings.monitoring.enabled {
            let t0 = Instant::now();
            match source.snapshot() {
                Ok(snap) => {
                    let detections = {
                        let mut tracker = lock(&st.tracker);
                        // 30 minutes of history at the current interval.
                        tracker.set_history_capacity((1800 / settings.monitoring.interval_secs.max(1)) as usize);
                        tracker.ingest(&snap, &mut |raw| source.image_path(raw.pid, raw.created));
                        let now = snap.wall_ms;
                        let excluded = |p: &crate::collector::tracker::TrackedProcess| p.key.pid == own_pid || settings.is_excluded(&p.name, p.exe_path.as_deref());
                        let dets = lock(&st.detector).evaluate(&tracker, &settings.rules, now, &excluded);
                        // Self-measurement for the diagnostics screen.
                        let mut stats = lock(&st.stats);
                        if let Some(me) = tracker.live_by_pid(own_pid) {
                            let since = now.saturating_sub(60_000);
                            let cpus: Vec<f32> = me.history.iter().filter(|s| s.t >= since && !s.cpu.is_nan()).map(|s| s.cpu).collect();
                            stats.self_cpu_percent = if cpus.is_empty() { None } else { Some(cpus.iter().sum::<f32>() / cpus.len() as f32) };
                            stats.self_private_mb = me.latest().map(|s| s.private_bytes as f64 / 1_048_576.0);
                            stats.self_working_set_mb = me.latest().map(|s| s.working_set as f64 / 1_048_576.0);
                        }
                        stats.process_count = tracker.process_count();
                        dets
                    };
                    let dur = t0.elapsed().as_secs_f64() * 1000.0;
                    {
                        let mut stats = lock(&st.stats);
                        stats.samples += 1;
                        stats.last_sample_ms = snap.wall_ms;
                        stats.last_sample_duration_ms = dur;
                        stats.avg_sample_duration_ms = if stats.samples == 1 { dur } else { stats.avg_sample_duration_ms * 0.95 + dur * 0.05 };
                        stats.last_error = None;
                    }
                    for d in detections {
                        deliver(&app, &st, d, &settings);
                    }
                    let _ = app.emit("monitor://tick", json!({"t": snap.wall_ms}));
                }
                Err(e) => {
                    lock(&st.stats).last_error = Some(e.clone());
                    logging::error("snapshot_failed", json!({"error": e}));
                }
            }
        }
        if last_prune.elapsed() > Duration::from_secs(3600) {
            last_prune = Instant::now();
            let _ = lock(&st.store).prune(now_ms(), settings.history.retention_days, settings.history.max_alerts);
        }
        // Sleep in short slices so pause/resume and interval changes apply quickly.
        let start = Instant::now();
        while start.elapsed() < interval {
            std::thread::sleep(Duration::from_millis(250));
            let s = app.state::<AppState>().settings();
            if s.monitoring.enabled != settings.monitoring.enabled || s.monitoring.interval_secs != settings.monitoring.interval_secs {
                break;
            }
        }
    }
}

pub fn alert_from_detection(d: &Detection, delivery: &Delivery) -> AlertRecord {
    AlertRecord {
        id: new_id("alert"),
        created_ms: d.at,
        rule: d.rule.as_str().into(),
        rule_label: d.rule.label().into(),
        priority: if d.priority == Priority::Warning { "warning".into() } else { "info".into() },
        pid: d.key.pid,
        process_created: d.key.created.to_string(),
        process_name: d.name.clone(),
        exe_path: d.exe_path.clone(),
        reason: d.reason.clone(),
        metrics: serde_json::to_value(&d.metrics).unwrap_or(Value::Null),
        details: d.details.clone(),
        delivery: serde_json::to_value(delivery).unwrap_or(Value::Null),
        status: "new".into(),
        investigation_id: None,
        synthetic: d.synthetic,
    }
}

fn deliver(app: &AppHandle, st: &AppState, d: Detection, settings: &Settings) {
    let decision = lock(&st.policy).decide(&d, &settings.alerts, d.at, win::local_minute_of_day());
    let Some(delivery) = decision else {
        lock(&st.stats).alerts_suppressed += 1;
        logging::info("alert_snoozed", json!({"rule": d.rule.as_str(), "process": d.name}));
        return;
    };
    let alert = alert_from_detection(&d, &delivery);
    if let Err(e) = lock(&st.store).insert_alert(&alert) {
        logging::error("alert_store_failed", json!({"error": e}));
    }
    lock(&st.stats).alerts_raised += 1;
    logging::info("alert", json!({"rule": alert.rule, "process": alert.process_name, "pid": alert.pid, "delivery": alert.delivery}));
    let _ = app.emit("alert://new", &alert);

    if let Delivery::Notify { sound } = delivery {
        if sound && !st.muted.load(Ordering::Relaxed) {
            let tone = if d.priority == Priority::Warning { win::sound::Tone::Warning } else { win::sound::Tone::Soft };
            win::sound::play(tone, settings.alerts.volume);
        }
        let app2 = app.clone();
        let title = format!("{} {}", if d.priority == Priority::Warning { "👻" } else { "🌫" }, d.rule.label());
        let line1 = format!("{} (PID {})", d.name, d.key.pid);
        let line2 = alert.reason.chars().take(150).collect::<String>();
        if let Err(e) = notify::show_alert(&st.identifier, &alert.id, &title, &line1, &line2, move |action| handle_toast_action(&app2, action)) {
            logging::warn("toast_failed", json!({"error": e}));
        }
    }
}

/// Act on a notification button, from in-process activation or a
/// haunttrace:// link. Links are untrusted: only existing alerts are acted
/// on, and the only effects are read-only investigation, a 1-hour snooze of
/// a recent alert, or opening the window.
pub fn handle_toast_action(app: &AppHandle, action: notify::ToastAction) {
    let st = app.state::<AppState>();
    let id = match &action {
        notify::ToastAction::Investigate(id) | notify::ToastAction::Snooze(id) | notify::ToastAction::Open(id) => id.clone(),
    };
    let alert = match lock(&st.store).get_alert(&id) {
        Ok(Some(a)) => a,
        _ => {
            logging::warn("toast_action_unknown_alert", json!({}));
            show_main(app);
            return;
        }
    };
    logging::info("toast_action", json!({"action": format!("{action:?}").split('(').next().unwrap_or("")}));
    match action {
        notify::ToastAction::Investigate(_) => {
            show_main(app);
            match start_investigation(app, &alert.id) {
                Ok(inv) => navigate_ui(app, json!({"view": "investigation", "id": inv})),
                Err(e) => logging::error("toast_investigate_failed", json!({"error": e})),
            }
        }
        notify::ToastAction::Snooze(_) => {
            if now_ms().saturating_sub(alert.created_ms) > 2 * 3_600_000 {
                return; // Stale links cannot silence future alerts.
            }
            lock(&st.policy).snooze(snooze_key(&alert.process_name, alert.exe_path.as_deref()), now_ms() + 3_600_000);
            st.record_action(Some(&alert.id), None, "snooze", "Snoozed for 1 hour from the notification", "done");
        }
        notify::ToastAction::Open(_) => {
            show_main(app);
            navigate_ui(app, json!({"view": "haunting", "id": alert.id}));
        }
    }
}

/// Ask the UI to navigate. Kept as pending too, so a freshly created window
/// picks it up on load.
fn navigate_ui(app: &AppHandle, target: Value) {
    *lock(&app.state::<AppState>().pending_nav) = Some(target.clone());
    let _ = app.emit("ui://navigate", target);
}

/// Show the main window, recreating it if it was closed to the tray.
pub fn show_main(app: &AppHandle) {
    if app.get_webview_window("main").is_none() {
        if let Some(cfg) = app.config().app.windows.first() {
            if let Err(e) = tauri::WebviewWindowBuilder::from_config(app, cfg).and_then(|b| b.build()) {
                logging::error("window_create_failed", json!({"error": e.to_string()}));
            }
        }
    }
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

// ---------------- Investigations ----------------

struct AppSink {
    app: AppHandle,
    inv_id: String,
}

impl Sink for AppSink {
    fn step(&self, step: &StepRecord) {
        let st = self.app.state::<AppState>();
        if let Err(e) = lock(&st.store).append_step(&self.inv_id, step) {
            logging::error("step_store_failed", json!({"error": e}));
        }
        let _ = self.app.emit("investigation://step", json!({"investigation_id": self.inv_id, "step": step}));
    }
    fn evidence(&self, ev: &EvidenceRecord) {
        let st = self.app.state::<AppState>();
        if let Err(e) = lock(&st.store).insert_evidence(&self.inv_id, ev) {
            logging::error("evidence_store_failed", json!({"error": e}));
        }
        let _ = self.app.emit("investigation://evidence", json!({"investigation_id": self.inv_id, "evidence": ev}));
    }
}

pub fn subject_from_alert(a: &AlertRecord) -> Result<Subject, String> {
    let created: u64 = a.process_created.parse().map_err(|_| "Corrupt alert: bad process identity")?;
    Ok(Subject {
        key: ProcessKey { pid: a.pid, created },
        name: a.process_name.clone(),
        rule: RuleKind::parse(&a.rule).ok_or("Corrupt alert: unknown rule")?,
        rule_label: a.rule_label.clone(),
        reason: a.reason.clone(),
        alert_metrics: a.metrics.clone(),
        alert_details: a.details.clone(),
        synthetic: a.synthetic,
    })
}

pub fn start_investigation(app: &AppHandle, alert_id: &str) -> Result<String, String> {
    let st = app.state::<AppState>();
    if let Some((id, _)) = lock(&st.running).iter().find(|(_, r)| r.alert_id == alert_id) {
        return Ok(id.clone());
    }
    let alert = lock(&st.store).get_alert(alert_id)?.ok_or("Alert not found")?;
    let subject = subject_from_alert(&alert)?;
    let settings = st.settings();
    let inv_id = new_id("inv");
    let rec = InvestigationRecord {
        id: inv_id.clone(),
        alert_id: alert_id.into(),
        started_ms: now_ms(),
        finished_ms: None,
        status: "running".into(),
        model: settings.model.model.clone(),
        deterministic: false,
        report: None,
        error: None,
    };
    {
        let store = lock(&st.store);
        store.insert_investigation(&rec)?;
        store.set_alert_status(alert_id, "investigating", Some(&inv_id))?;
    }
    let cancel = CancellationToken::new();
    lock(&st.running).insert(inv_id.clone(), RunningInvestigation { alert_id: alert_id.into(), cancel: cancel.clone() });
    logging::info("investigation_started", json!({"id": inv_id, "rule": alert.rule, "model": settings.model.model}));
    let _ = app.emit("investigation://started", json!({"investigation_id": inv_id, "alert_id": alert_id}));
    emit_status(app);

    let app2 = app.clone();
    let id2 = inv_id.clone();
    tauri::async_runtime::spawn(async move {
        let st = app2.state::<AppState>();
        let provider = LiveProvider { tracker: st.tracker.clone() };
        let sink = AppSink { app: app2.clone(), inv_id: id2.clone() };
        let limits = Limits {
            max_steps: settings.model.max_steps,
            time_budget: Duration::from_secs(settings.model.time_budget_secs as u64),
            call_timeout: Duration::from_secs(settings.model.call_timeout_secs as u64),
            ..Default::default()
        };
        let model = OllamaClient::new(&settings.model).ok();
        let outcome = investigation::investigate(&subject, model.as_ref().map(|m| m as &dyn ModelClient), &provider, &sink, &limits, &cancel).await;
        let report = serde_json::to_value(&outcome.report).unwrap_or(Value::Null);
        {
            let store = lock(&st.store);
            let _ = store.finish_investigation(&id2, &outcome.status, now_ms(), outcome.deterministic, Some(&report), outcome.error.as_deref());
            let _ = store.set_alert_status(&alert.id, if outcome.status == "cancelled" { "cancelled" } else { "investigated" }, None);
        }
        lock(&st.running).remove(&id2);
        logging::info("investigation_finished", json!({"id": id2, "status": outcome.status, "deterministic": outcome.deterministic, "error": outcome.error}));
        let _ = app2.emit("investigation://done", json!({"investigation_id": id2, "status": outcome.status}));
        emit_status(&app2);

        if outcome.status == "completed" {
            narrate_if_enabled(&app2, &id2, &outcome.report.narration, &alert.priority).await;
        }
    });
    Ok(inv_id)
}

/// Speak a narration line with the configured voice mode. Returns audio
/// bytes (WAV for the Windows voice, MP3 for ElevenLabs).
pub async fn synthesize(st: &AppState, text: &str) -> Result<Vec<u8>, String> {
    let v = st.settings().voice;
    match v.mode.as_str() {
        "windows" => {
            let text = crate::investigation::schema::sanitize_narration(text).ok_or("The narration text was empty or unsafe to speak.")?;
            let voice = v.windows_voice.clone();
            tokio::task::spawn_blocking(move || win::tts::speak_to_wav(&text, Some(&voice))).await.map_err(|e| e.to_string())?
        }
        "elevenlabs" => st.narrator.speak(text, &v.voice_id, &v.model_id, win::credential_read(), v.cache_enabled).await.map_err(|e| e.to_string()),
        _ => Err("Voice narration is turned off.".into()),
    }
}

async fn narrate_if_enabled(app: &AppHandle, inv_id: &str, text: &str, priority: &str) {
    let st = app.state::<AppState>();
    let v = st.settings().voice;
    if !v.enabled() || st.muted.load(Ordering::Relaxed) || (v.only_significant && priority != "warning") {
        return;
    }
    // Deduplicate: each investigation is narrated automatically at most once.
    if !lock(&st.narrated).insert(inv_id.to_string()) {
        return;
    }
    match synthesize(&st, text).await {
        Ok(_) => {
            let _ = app.emit("narration://ready", json!({"investigation_id": inv_id}));
        }
        Err(e) => {
            logging::warn("narration_failed", json!({"error": e.to_string()}));
            let _ = app.emit("narration://error", json!({"investigation_id": inv_id, "message": e.to_string()}));
        }
    }
}

pub fn build_state(app: &AppHandle) -> Result<AppState, String> {
    let data_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;
    logging::init(data_dir.join("logs"));
    let store = Store::open(&data_dir.join("haunttrace.db"))?;
    store.recover_interrupted(now_ms())?;
    let settings = store.load_settings().and_then(|s| s.sanitized().ok()).unwrap_or_default();
    let _ = store.prune(now_ms(), settings.history.retention_days, settings.history.max_alerts);
    let muted = store.get_kv("muted").map(|v| v == "true").unwrap_or(false);
    let identifier = app.config().identifier.clone();
    Ok(AppState {
        identifier,
        settings: RwLock::new(settings),
        tracker: Arc::new(Mutex::new(Tracker::new(TrackerConfig::default()))),
        detector: Mutex::new(Detector::new()),
        policy: Mutex::new(AlertPolicy::new()),
        store: Mutex::new(store),
        running: Mutex::new(HashMap::new()),
        narrator: Narrator::new(data_dir.join("narration-cache")),
        muted: AtomicBool::new(muted),
        stats: Mutex::new(MonitorStats { started_ms: now_ms(), ..Default::default() }),
        narrated: Mutex::new(HashSet::new()),
        pull_cancel: Mutex::new(None),
        pending_nav: Mutex::new(None),
        data_dir,
    })
}

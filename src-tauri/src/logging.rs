//! Structured, privacy-conscious logging: JSON lines in a size-capped file
//! plus a small in-memory ring for the diagnostics screen. User profile
//! paths are redacted, and secrets are never passed to the logger.

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Serialize;
use serde_json::Value;

use crate::types::now_ms;

const MAX_FILE_BYTES: u64 = 1_000_000;
const RING: usize = 300;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub t: u64,
    pub level: &'static str,
    pub event: String,
    pub data: Value,
}

struct Inner {
    path: Option<PathBuf>,
    ring: VecDeque<LogEntry>,
}

static LOG: Mutex<Inner> = Mutex::new(Inner { path: None, ring: VecDeque::new() });

pub fn init(dir: PathBuf) {
    let _ = std::fs::create_dir_all(&dir);
    LOG.lock().unwrap_or_else(|e| e.into_inner()).path = Some(dir.join("haunttrace.log"));
}

fn redact(s: &str) -> String {
    #[cfg(windows)]
    {
        crate::win::redact_user_path(s)
    }
    #[cfg(not(windows))]
    {
        s.to_string()
    }
}

pub fn log(level: &'static str, event: &str, data: Value) {
    let data: Value = serde_json::from_str(&redact(&data.to_string())).unwrap_or(Value::Null);
    let entry = LogEntry { t: now_ms(), level, event: event.to_string(), data };
    let mut g = LOG.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(path) = g.path.clone() {
        if std::fs::metadata(&path).map(|m| m.len() > MAX_FILE_BYTES).unwrap_or(false) {
            let _ = std::fs::rename(&path, path.with_extension("log.1"));
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{}", serde_json::to_string(&entry).unwrap_or_default());
        }
    }
    g.ring.push_back(entry);
    while g.ring.len() > RING {
        g.ring.pop_front();
    }
}

pub fn info(event: &str, data: Value) {
    log("info", event, data)
}
pub fn warn(event: &str, data: Value) {
    log("warn", event, data)
}
pub fn error(event: &str, data: Value) {
    log("error", event, data)
}

pub fn recent(n: usize) -> Vec<LogEntry> {
    let g = LOG.lock().unwrap_or_else(|e| e.into_inner());
    g.ring.iter().rev().take(n).cloned().collect()
}

pub fn path() -> Option<PathBuf> {
    LOG.lock().unwrap_or_else(|e| e.into_inner()).path.clone()
}

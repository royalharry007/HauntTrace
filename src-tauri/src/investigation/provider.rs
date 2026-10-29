//! Live evidence provider: answers registered tools from the in-memory
//! process tracker and read-only Win32 file checks. Every tool operates on an
//! exact process instance (PID + creation time) that the engine authorized.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};

use super::tools::{EvidenceProvider, ToolName, ToolOutput};
use crate::collector::tracker::{TrackedProcess, Tracker};
use crate::types::{filetime_to_unix_ms, now_ms, ProcessEventKind, ProcessKey};

pub const TEST_PROCESS_NAME: &str = "haunt-burner.exe";

pub struct LiveProvider {
    pub tracker: Arc<Mutex<Tracker>>,
}

fn mb(b: u64) -> f64 {
    (b as f64 / 1_048_576.0 * 10.0).round() / 10.0
}

fn r1(v: f32) -> f64 {
    (v as f64 * 10.0).round() / 10.0
}

#[cfg(windows)]
fn redact(p: &str) -> String {
    crate::win::redact_user_path(p)
}
#[cfg(not(windows))]
fn redact(p: &str) -> String {
    p.to_string()
}

fn mins_ago(now: u64, t: u64) -> f64 {
    ((now.saturating_sub(t)) as f64 / 60_000.0 * 10.0).round() / 10.0
}

fn avg_cpu(p: &TrackedProcess, since: u64) -> Option<f64> {
    let v: Vec<f32> = p.history.iter().filter(|s| s.t >= since && !s.cpu.is_nan()).map(|s| s.cpu).collect();
    if v.is_empty() {
        None
    } else {
        Some(r1(v.iter().sum::<f32>() / v.len() as f32))
    }
}

fn describe(p: &TrackedProcess, now: u64, ncpu: u32) -> Value {
    let latest = p.history.back();
    let runtime_min = if p.key.created != 0 { Some(mins_ago(now, filetime_to_unix_ms(p.key.created))) } else { None };
    json!({
        "pid": p.key.pid,
        "name": p.name,
        "image_path": p.exe_path.as_deref().map(redact),
        "alive": p.alive(),
        "exited_minutes_ago": p.exited_at.map(|t| mins_ago(now, t)),
        "runtime_minutes": runtime_min,
        "session_id": p.session_id,
        "runs_in_service_session": p.session_id == Some(0),
        "parent_pid": p.ppid,
        "parent_verified": p.parent_key.is_some(),
        "access": p.access,
        "latest_cpu_percent_of_total": latest.and_then(|s| if s.cpu.is_nan() { None } else { Some(r1(s.cpu)) }),
        "logical_cpus": ncpu,
        "private_memory_mb": latest.map(|s| mb(s.private_bytes)),
        "working_set_mb": latest.map(|s| mb(s.working_set)),
        "controlled_test_process": p.name.eq_ignore_ascii_case(TEST_PROCESS_NAME),
    })
}

fn summary_line(p: &TrackedProcess, now: u64) -> String {
    let mut s = format!("{} (PID {})", p.name, p.key.pid);
    if let Some(t) = p.exited_at {
        s.push_str(&format!(" exited {:.0} min ago", mins_ago(now, t)));
    } else {
        s.push_str(" is running");
    }
    if p.key.created != 0 {
        let m = mins_ago(now, filetime_to_unix_ms(p.key.created));
        if m >= 120.0 {
            s.push_str(&format!(", started {:.1} h ago", m / 60.0));
        } else {
            s.push_str(&format!(", started {:.0} min ago", m));
        }
    }
    match &p.exe_path {
        Some(path) => s.push_str(&format!(", from {}", redact(path))),
        None => s.push_str(", image path not accessible"),
    }
    if p.session_id == Some(0) {
        s.push_str(", in the background service session");
    }
    if let Some(l) = p.history.back() {
        if !l.cpu.is_nan() {
            s.push_str(&format!(", latest CPU {:.1}%", l.cpu));
        }
        s.push_str(&format!(", private memory {:.0} MB", mb(l.private_bytes)));
    }
    if p.name.eq_ignore_ascii_case(TEST_PROCESS_NAME) {
        s.push_str(". This is HauntTrace's own controlled test process (real measurements of a deliberate CPU load)");
    }
    s.push('.');
    s
}

impl LiveProvider {
    fn with<T>(&self, f: impl FnOnce(&Tracker) -> T) -> T {
        let t = self.tracker.lock().unwrap_or_else(|e| e.into_inner());
        f(&t)
    }

    fn lookup(&self, key: ProcessKey) -> Result<(TrackedProcess, u32), String> {
        self.with(|t| t.get(&key).cloned().map(|p| (p, t.logical_cpus))).ok_or_else(|| {
            "This process instance is no longer in HauntTrace's recent memory (it exited more than 15 minutes ago).".to_string()
        })
    }

    fn details(&self, key: ProcessKey) -> Result<ToolOutput, String> {
        let now = now_ms();
        let (p, ncpu) = self.lookup(key)?;
        let parent = p.parent_key.and_then(|pk| self.with(|t| t.get(&pk).map(|pp| (pk, pp.name.clone()))));
        let mut data = describe(&p, now, ncpu);
        let mut summary = summary_line(&p, now);
        if let Some((_, pname)) = &parent {
            summary.push_str(&format!(" Launched by {} (PID {}).", pname, p.ppid));
            data["parent_name"] = json!(pname);
        }
        if p.history.back().map(|s| s.cpu.is_nan()).unwrap_or(true) && p.access != crate::types::Access::Full {
            summary.push_str(" Windows denied access to this process's resource counters.");
        }
        Ok(ToolOutput {
            title: format!("Process details: {}", p.name),
            summary,
            data,
            discovered: parent.map(|(k, n)| vec![(k, format!("parent of {}: {}", p.name, n))]).unwrap_or_default(),
        })
    }

    fn parent(&self, key: ProcessKey) -> Result<ToolOutput, String> {
        let now = now_ms();
        let (p, ncpu) = self.lookup(key)?;
        let Some(pk) = p.parent_key else {
            return Ok(ToolOutput {
                title: format!("Parent of {}: unknown", p.name),
                summary: format!(
                    "Parent PID {} was not running when {} was first observed (or the PID was reused by a newer process), so the launching program cannot be verified. This is common for processes started at boot or by short-lived launchers.",
                    p.ppid, p.name
                ),
                data: json!({"parent_pid": p.ppid, "verified": false}),
                discovered: vec![],
            });
        };
        let pp = self.with(|t| t.get(&pk).cloned());
        match pp {
            Some(pp) => Ok(ToolOutput {
                title: format!("Parent of {}: {}", p.name, pp.name),
                summary: format!("{} was launched by {}", p.name, summary_line(&pp, now)),
                data: json!({"verified": true, "parent": describe(&pp, now, ncpu)}),
                discovered: vec![(pk, format!("parent of {}: {}", p.name, pp.name))],
            }),
            None => Ok(ToolOutput {
                title: format!("Parent of {}: exited", p.name),
                summary: format!("The parent (PID {}) has exited and is no longer in recent memory.", pk.pid),
                data: json!({"parent_pid": pk.pid, "verified": true, "parent_exited": true}),
                discovered: vec![],
            }),
        }
    }

    fn history(&self, key: ProcessKey, minutes: u32) -> Result<ToolOutput, String> {
        let now = now_ms();
        let (p, _) = self.lookup(key)?;
        let since = now.saturating_sub(minutes as u64 * 60_000);
        let samples: Vec<_> = p.history.iter().filter(|s| s.t >= since).copied().collect();
        if samples.is_empty() {
            return Err("No resource samples are available for this window (access denied or just started).".into());
        }
        let buckets = 12usize.min(samples.len());
        let per = samples.len().div_ceil(buckets);
        let series: Vec<Value> = samples
            .chunks(per)
            .map(|c| {
                let cpus: Vec<f32> = c.iter().map(|s| s.cpu).filter(|v| !v.is_nan()).collect();
                json!({
                    "minutes_ago": mins_ago(now, c[0].t),
                    "cpu_avg": if cpus.is_empty() { None } else { Some(r1(cpus.iter().sum::<f32>() / cpus.len() as f32)) },
                    "cpu_max": cpus.iter().cloned().fold(None, |m: Option<f32>, v| Some(m.map_or(v, |m| m.max(v)))).map(r1),
                    "private_mb": mb(c.iter().map(|s| s.private_bytes).max().unwrap_or(0)),
                })
            })
            .collect();
        let cpus: Vec<f32> = samples.iter().map(|s| s.cpu).filter(|v| !v.is_nan()).collect();
        let (cmin, cmax) = cpus.iter().fold((f32::MAX, 0.0f32), |(a, b), v| (a.min(*v), b.max(*v)));
        let cavg = if cpus.is_empty() { 0.0 } else { cpus.iter().sum::<f32>() / cpus.len() as f32 };
        let m0 = samples.first().unwrap().private_bytes;
        let m1 = samples.last().unwrap().private_bytes;
        let covered = mins_ago(now, samples[0].t);
        let above_half = cpus.iter().filter(|c| **c >= cavg * 0.5).count();
        let pattern = if cpus.is_empty() {
            "unknown"
        } else if cmax - cmin < 5.0 || above_half as f32 >= cpus.len() as f32 * 0.9 {
            "steady"
        } else {
            "variable"
        };
        Ok(ToolOutput {
            title: format!("Resource history ({} min requested, {:.1} min observed)", minutes, covered),
            summary: format!(
                "Over the last {:.1} min ({} samples): CPU averaged {:.1}% (min {:.1}%, max {:.1}%), {} pattern. Private memory went from {:.0} MB to {:.0} MB.",
                covered,
                samples.len(),
                cavg,
                if cpus.is_empty() { 0.0 } else { cmin },
                cmax,
                pattern,
                mb(m0),
                mb(m1)
            ),
            data: json!({"observed_minutes": covered, "samples": samples.len(), "cpu_avg": r1(cavg), "cpu_max": r1(cmax), "cpu_pattern": pattern,
                         "private_mb_start": mb(m0), "private_mb_end": mb(m1), "series": series}),
            discovered: vec![],
        })
    }

    fn related(&self, key: ProcessKey) -> Result<ToolOutput, String> {
        let now = now_ms();
        let (p, _) = self.lookup(key)?;
        let since = now.saturating_sub(5 * 60_000);
        let group = p.group();
        let (children, siblings) = self.with(|t| {
            let ch: Vec<TrackedProcess> = t.children(&key).into_iter().take(10).cloned().collect();
            let sib: Vec<TrackedProcess> = t.alive().filter(|o| o.key != key && o.group() == group).take(10).cloned().collect();
            (ch, sib)
        });
        let item = |o: &TrackedProcess| json!({"pid": o.key.pid, "name": o.name, "alive": o.alive(), "cpu_avg_5min": avg_cpu(o, since), "private_mb": o.history.back().map(|s| mb(s.private_bytes))});
        let mut discovered = Vec::new();
        for c in &children {
            discovered.push((c.key, format!("child of {}: {}", p.name, c.name)));
        }
        for s in &siblings {
            discovered.push((s.key, format!("another instance of {}", s.name)));
        }
        let child_names: Vec<String> = children.iter().map(|c| c.name.clone()).collect();
        Ok(ToolOutput {
            title: format!("Related processes of {}", p.name),
            summary: format!(
                "{} child process(es){}; {} other running instance(s) of the same executable.",
                children.len(),
                if child_names.is_empty() { String::new() } else { format!(" ({})", child_names.join(", ")) },
                siblings.len()
            ),
            data: json!({"children": children.iter().map(item).collect::<Vec<_>>(), "same_executable_instances": siblings.iter().map(item).collect::<Vec<_>>()}),
            discovered,
        })
    }

    fn events(&self, key: ProcessKey, minutes: u32) -> Result<ToolOutput, String> {
        let now = now_ms();
        let (p, _) = self.lookup(key)?;
        let since = now.saturating_sub(minutes as u64 * 60_000);
        let group = p.group();
        let evs: Vec<Value> = self.with(|t| {
            let mut v: Vec<Value> = t
                .events()
                .filter(|e| e.t >= since)
                .filter(|e| {
                    e.exe_path.as_deref().unwrap_or(&e.name).to_lowercase() == group
                        || t.get(&e.key).and_then(|x| x.parent_key).map(|pk| pk == key).unwrap_or(false)
                })
                .map(|e| json!({"minutes_ago": mins_ago(now, e.t), "event": e.kind, "pid": e.key.pid, "name": e.name, "is_child": e.exe_path.as_deref().unwrap_or(&e.name).to_lowercase() != group}))
                .collect();
            v.reverse();
            v.truncate(25);
            v
        });
        let starts = evs.iter().filter(|e| e["event"] == json!(ProcessEventKind::Started) && e["is_child"] == false).count();
        let exits = evs.iter().filter(|e| e["event"] == json!(ProcessEventKind::Exited) && e["is_child"] == false).count();
        let child_events = evs.iter().filter(|e| e["is_child"] == true).count();
        Ok(ToolOutput {
            title: format!("Process events in the last {} min", minutes),
            summary: format!(
                "Observed {} start(s) and {} exit(s) of {} and {} start/exit event(s) of its child processes in the last {} min (very short-lived processes between samples may be missed).",
                starts, exits, p.name, child_events, minutes
            ),
            data: json!({"events": evs, "window_minutes": minutes}),
            discovered: vec![],
        })
    }

    fn exe_path(&self, key: ProcessKey) -> Result<(String, String), String> {
        let (p, _) = self.lookup(key)?;
        let path = p.exe_path.ok_or("The executable path is not accessible (protected process or access denied). This is a limitation, not a sign of a problem.")?;
        Ok((p.name, path))
    }
}

#[async_trait]
impl EvidenceProvider for LiveProvider {
    async fn initial(&self, subject: ProcessKey) -> Vec<ToolOutput> {
        let mut out = Vec::new();
        match self.details(subject) {
            Ok(d) => out.push(d),
            Err(e) => out.push(ToolOutput { title: "Process details unavailable".into(), summary: e.clone(), data: json!({"error": e}), discovered: vec![] }),
        }
        if let Ok(h) = self.history(subject, 5) {
            out.push(h);
        }
        out
    }

    async fn run(&self, tool: ToolName, target: ProcessKey, minutes: Option<u32>) -> Result<ToolOutput, String> {
        match tool {
            ToolName::GetProcessDetails => self.details(target),
            ToolName::GetParentProcess => self.parent(target),
            ToolName::GetResourceHistory => self.history(target, minutes.unwrap_or(10)),
            ToolName::GetRelatedProcesses => self.related(target),
            ToolName::GetRecentProcessEvents => self.events(target, minutes.unwrap_or(15)),
            ToolName::GetExecutableMetadata => {
                let (name, path) = self.exe_path(target)?;
                #[cfg(windows)]
                {
                    let p2 = path.clone();
                    let m = tokio::task::spawn_blocking(move || crate::win::metadata::read_metadata(&p2)).await.map_err(|e| e.to_string())?;
                    if !m.exists {
                        return Err("The executable file could not be read (it may have been moved, deleted or is protected).".into());
                    }
                    let mut s = format!("{}'s executable", name);
                    match (&m.company_name, &m.file_description) {
                        (Some(c), Some(d)) => s.push_str(&format!(" describes itself as \"{d}\" from \"{c}\"")),
                        (Some(c), None) => s.push_str(&format!(" names its company as \"{c}\"")),
                        (None, Some(d)) => s.push_str(&format!(" describes itself as \"{d}\" (no company name)")),
                        (None, None) => s.push_str(" has no company or description in its version information"),
                    }
                    if let Some(v) = &m.file_version {
                        s.push_str(&format!(", version {v}"));
                    }
                    s.push_str(&format!(". It is {:.1} MB, located in {}. (Version text is self-reported by the file and is not proof of origin; see the signature check.)",
                        mb(m.size_bytes.unwrap_or(0)), m.location.replace('_', " ")));
                    let mut data = serde_json::to_value(&m).unwrap_or(Value::Null);
                    data["image_path"] = json!(redact(&path));
                    Ok(ToolOutput { title: format!("Executable metadata: {}", name), summary: s, data, discovered: vec![] })
                }
                #[cfg(not(windows))]
                {
                    let _ = (name, path);
                    Err("Not supported on this platform".into())
                }
            }
            ToolName::GetDigitalSignatureStatus => {
                let (name, path) = self.exe_path(target)?;
                #[cfg(windows)]
                {
                    let p2 = path.clone();
                    let sig = tokio::task::spawn_blocking(move || crate::win::signature::check_signature(&p2)).await.map_err(|e| e.to_string())?;
                    let summary = match (&sig.status[..], &sig.publisher) {
                        ("valid", Some(p)) => format!("{}'s executable has a valid {} signature from \"{}\". {}", name, sig.kind.clone().unwrap_or_default(), p, sig.detail),
                        (_, Some(p)) => format!("{}'s executable signature status: {} (signer \"{}\"). {}", name, sig.status, p, sig.detail),
                        _ => format!("{}'s executable signature status: {}. {}", name, sig.status, sig.detail),
                    };
                    Ok(ToolOutput { title: format!("Digital signature: {}", name), summary, data: serde_json::to_value(&sig).unwrap_or(Value::Null), discovered: vec![] })
                }
                #[cfg(not(windows))]
                {
                    let _ = (name, path);
                    Err("Not supported on this platform".into())
                }
            }
        }
    }
}

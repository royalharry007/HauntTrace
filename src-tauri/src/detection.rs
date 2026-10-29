//! Deterministic, rule-based detection. No AI is involved here: these rules
//! decide when something deserves the user's attention, using only measured
//! samples, with consecutive-sample requirements, hysteresis and cooldowns.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::collector::tracker::{TrackedProcess, Tracker};
use crate::settings::RuleSettings;
use crate::types::{filetime_to_unix_ms, ProcessEventKind, ProcessKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Lingering,
    SustainedCpu,
    RepeatedSpikes,
    MemoryGrowth,
    RepeatedRestarts,
    /// Picked by the user from a sweep; never raised automatically.
    Summoned,
}

impl RuleKind {
    pub fn label(&self) -> &'static str {
        match self {
            RuleKind::Lingering => "Lingering activity",
            RuleKind::SustainedCpu => "Sustained CPU activity",
            RuleKind::RepeatedSpikes => "Repeated CPU spikes",
            RuleKind::MemoryGrowth => "Memory growth",
            RuleKind::RepeatedRestarts => "Repeated restarts",
            RuleKind::Summoned => "Summoned from a sweep",
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleKind::Lingering => "lingering",
            RuleKind::SustainedCpu => "sustained_cpu",
            RuleKind::RepeatedSpikes => "repeated_spikes",
            RuleKind::MemoryGrowth => "memory_growth",
            RuleKind::RepeatedRestarts => "repeated_restarts",
            RuleKind::Summoned => "summoned",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "lingering" => RuleKind::Lingering,
            "sustained_cpu" => RuleKind::SustainedCpu,
            "repeated_spikes" => RuleKind::RepeatedSpikes,
            "memory_growth" => RuleKind::MemoryGrowth,
            "repeated_restarts" => RuleKind::RepeatedRestarts,
            "summoned" => RuleKind::Summoned,
            _ => return None,
        })
    }
    pub fn priority(&self) -> Priority {
        match self {
            // Restart loops are often benign (build tools, updaters launching
            // workers), so they are informational; sustained load and memory
            // growth have a direct cost and are higher priority.
            RuleKind::Lingering | RuleKind::RepeatedSpikes | RuleKind::RepeatedRestarts | RuleKind::Summoned => Priority::Info,
            RuleKind::SustainedCpu | RuleKind::MemoryGrowth => Priority::Warning,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Info,
    Warning,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectionMetrics {
    pub cpu_latest: Option<f32>,
    pub cpu_avg: Option<f32>,
    pub cpu_peak: Option<f32>,
    pub private_bytes: Option<u64>,
    pub working_set: Option<u64>,
    pub runtime_ms: Option<u64>,
    pub samples: usize,
    pub logical_cpus: u32,
}

/// A structured event produced when a rule triggers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub rule: RuleKind,
    pub priority: Priority,
    pub key: ProcessKey,
    pub name: String,
    pub exe_path: Option<String>,
    pub at: u64,
    /// Deterministic, human-readable explanation of exactly what was measured.
    pub reason: String,
    pub metrics: DetectionMetrics,
    pub details: serde_json::Value,
    /// True when the underlying data came from a synthetic fixture.
    pub synthetic: bool,
}

#[derive(Debug, Default, Clone)]
struct RuleState {
    active: bool,
    last_fired: Option<u64>,
}

#[derive(Default)]
pub struct Detector {
    state: HashMap<(RuleKind, String), RuleState>,
}

/// A new instance counts as a restart only if it appears this soon after the
/// previous one exited.
const RESPAWN_MS: u64 = 30_000;

/// Shells and console hosts are started by people and other programs on
/// demand; their comings and goings are someone else's activity, not a loop.
const LAUNCHED_ON_DEMAND: &[&str] = &["conhost.exe", "openconsole.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe", "wsl.exe", "wslhost.exe"];

fn is_launched_on_demand(name: &str) -> bool {
    LAUNCHED_ON_DEMAND.iter().any(|n| name.eq_ignore_ascii_case(n))
}

fn valid_cpu(p: &TrackedProcess) -> impl Iterator<Item = (u64, f32)> + '_ {
    p.history.iter().filter(|s| !s.cpu.is_nan()).map(|s| (s.t, s.cpu))
}

pub fn metrics_for(p: &TrackedProcess, now: u64, window_ms: u64, logical_cpus: u32) -> DetectionMetrics {
    let since = now.saturating_sub(window_ms);
    let cpus: Vec<f32> = valid_cpu(p).filter(|(t, _)| *t >= since).map(|(_, c)| c).collect();
    let latest = p.history.back();
    DetectionMetrics {
        cpu_latest: latest.map(|s| s.cpu).filter(|c| !c.is_nan()),
        cpu_avg: if cpus.is_empty() { None } else { Some(cpus.iter().sum::<f32>() / cpus.len() as f32) },
        cpu_peak: cpus.iter().cloned().fold(None, |m: Option<f32>, c| Some(m.map_or(c, |m| m.max(c)))),
        private_bytes: latest.map(|s| s.private_bytes),
        working_set: latest.map(|s| s.working_set),
        runtime_ms: if p.key.created != 0 { Some(now.saturating_sub(filetime_to_unix_ms(p.key.created))) } else { None },
        samples: cpus.len(),
        logical_cpus,
    }
}

fn fmt_dur(ms: u64) -> String {
    let mins = ms / 60_000;
    if mins >= 120 {
        format!("{:.1} hours", mins as f64 / 60.0)
    } else if mins >= 1 {
        format!("{mins} min")
    } else {
        format!("{} s", ms / 1000)
    }
}

fn mb(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.state.clear();
    }

    /// Decide whether a rule may fire for a subject. Implements hysteresis
    /// (`active` latches until the release condition) and cooldown.
    fn gate(&mut self, rule: RuleKind, subject: &str, condition: bool, released: bool, now: u64, cooldown_ms: u64) -> bool {
        let st = self.state.entry((rule, subject.to_string())).or_default();
        if released {
            st.active = false;
            return false;
        }
        if !condition {
            return false;
        }
        if st.active {
            return false;
        }
        st.active = true;
        if let Some(last) = st.last_fired {
            if now.saturating_sub(last) < cooldown_ms {
                return false;
            }
        }
        st.last_fired = Some(now);
        true
    }

    pub fn evaluate(&mut self, tracker: &Tracker, rules: &RuleSettings, now: u64, is_excluded: &dyn Fn(&TrackedProcess) -> bool) -> Vec<Detection> {
        let mut out = Vec::new();
        let cooldown = rules.cooldown_minutes as u64 * 60_000;
        let ncpu = tracker.logical_cpus;
        let mut alive_subjects: HashSet<String> = HashSet::new();

        for p in tracker.alive() {
            if is_excluded(p) {
                continue;
            }
            let subject = format!("{}:{}", p.key.pid, p.key.created);
            alive_subjects.insert(subject.clone());

            // 1. Sustained CPU.
            let r = &rules.sustained_cpu;
            if r.enabled {
                let n = r.consecutive_samples as usize;
                let recent: Vec<f32> = p.history.iter().rev().take(n).map(|s| s.cpu).collect();
                let condition = recent.len() == n && recent.iter().all(|c| !c.is_nan() && *c >= r.cpu_percent);
                let released = p.latest().map(|s| !s.cpu.is_nan() && s.cpu < r.cpu_percent * r.release_ratio).unwrap_or(false);
                if self.gate(RuleKind::SustainedCpu, &subject, condition, released, now, cooldown) {
                    let span = p.history.iter().rev().take(n).last().map(|s| now.saturating_sub(s.t)).unwrap_or(0);
                    let m = metrics_for(p, now, span.max(1), ncpu);
                    out.push(self.make(p, RuleKind::SustainedCpu, now, m.clone(), format!(
                        "CPU usage stayed at or above {:.0}% of total capacity for {} consecutive samples (about {}). Average {:.1}%, peak {:.1}%.",
                        r.cpu_percent, n, fmt_dur(span), m.cpu_avg.unwrap_or(0.0), m.cpu_peak.unwrap_or(0.0)
                    ), serde_json::json!({"threshold_percent": r.cpu_percent, "consecutive_samples": n, "span_ms": span})));
                }
            }

            // 2. Repeated spikes: rising edges above the spike threshold,
            // separated by a dip below half of it (hysteresis).
            let r = &rules.spikes;
            if r.enabled {
                let window = r.window_minutes as u64 * 60_000;
                let since = now.saturating_sub(window);
                let mut spikes = 0u32;
                let mut armed = true;
                for (_, c) in valid_cpu(p).filter(|(t, _)| *t >= since) {
                    if armed && c >= r.spike_cpu_percent {
                        spikes += 1;
                        armed = false;
                    } else if c < r.spike_cpu_percent * 0.5 {
                        armed = true;
                    }
                }
                let condition = spikes >= r.min_spikes;
                if self.gate(RuleKind::RepeatedSpikes, &subject, condition, !condition, now, cooldown) {
                    let m = metrics_for(p, now, window, ncpu);
                    out.push(self.make(p, RuleKind::RepeatedSpikes, now, m.clone(), format!(
                        "{} separate bursts above {:.0}% CPU within the last {} min, dropping back in between. Peak {:.1}%.",
                        spikes, r.spike_cpu_percent, r.window_minutes, m.cpu_peak.unwrap_or(0.0)
                    ), serde_json::json!({"spikes": spikes, "threshold_percent": r.spike_cpu_percent, "window_minutes": r.window_minutes})));
                }
            }

            // 3. Memory growth over a window with enough coverage.
            let r = &rules.memory_growth;
            if r.enabled {
                let window = r.window_minutes as u64 * 60_000;
                let since = now.saturating_sub(window);
                let samples: Vec<u64> = p.history.iter().filter(|s| s.t >= since).map(|s| s.private_bytes).collect();
                let covered = p.history.iter().find(|s| s.t >= since).map(|s| now.saturating_sub(s.t) >= window * 8 / 10).unwrap_or(false);
                let mut condition = false;
                let (mut base, mut cur) = (0u64, 0u64);
                if covered && samples.len() >= 8 {
                    let q = (samples.len() / 4).max(1);
                    base = *samples[..q].iter().min().unwrap();
                    cur = *samples[samples.len() - q..].iter().min().unwrap();
                    let growth = cur.saturating_sub(base);
                    let pct = if base > 0 { growth as f64 / base as f64 * 100.0 } else { 0.0 };
                    condition = pct >= r.min_growth_percent as f64 && mb(growth) >= r.min_growth_mb as f64;
                }
                if self.gate(RuleKind::MemoryGrowth, &subject, condition, !condition && covered, now, cooldown) {
                    let m = metrics_for(p, now, window, ncpu);
                    out.push(self.make(p, RuleKind::MemoryGrowth, now, m, format!(
                        "Private memory grew from {:.0} MB to {:.0} MB (+{:.0}%) over about {} min and has not dropped back.",
                        mb(base), mb(cur), (cur as f64 - base as f64) / base.max(1) as f64 * 100.0, r.window_minutes
                    ), serde_json::json!({"baseline_bytes": base, "current_bytes": cur, "window_minutes": r.window_minutes})));
                }
            }

            // 4. Lingering activity: long runtime AND ongoing activity.
            let r = &rules.lingering;
            if r.enabled && p.key.created != 0 {
                let runtime = now.saturating_sub(filetime_to_unix_ms(p.key.created));
                let window = r.window_minutes as u64 * 60_000;
                let m = metrics_for(p, now, window, ncpu);
                let covered = p.history.iter().find(|s| s.t >= now.saturating_sub(window)).map(|s| now.saturating_sub(s.t) >= window * 8 / 10).unwrap_or(false);
                let avg = m.cpu_avg.unwrap_or(0.0);
                let condition = covered && runtime >= r.runtime_minutes as u64 * 60_000 && avg >= r.min_avg_cpu;
                let released = covered && avg < r.min_avg_cpu * 0.5;
                if self.gate(RuleKind::Lingering, &subject, condition, released, now, cooldown) {
                    out.push(self.make(p, RuleKind::Lingering, now, m, format!(
                        "Running for {} (threshold {}) and still active: averaged {:.1}% CPU over the last {} min. Long runtime by itself is normal for many apps.",
                        fmt_dur(runtime), fmt_dur(r.runtime_minutes as u64 * 60_000), avg, r.window_minutes
                    ), serde_json::json!({"runtime_ms": runtime, "threshold_minutes": r.runtime_minutes, "avg_cpu": avg})));
                }
            }
        }

        // 5. Repeated restarts, from observed exit/start events.
        let r = &rules.restarts;
        if r.enabled {
            let window = r.window_minutes as u64 * 60_000;
            let since = now.saturating_sub(window);
            // group -> (restart count, latest started key)
            let mut groups: HashMap<String, (u32, Option<ProcessKey>, Vec<u64>)> = HashMap::new();
            let mut last_exit: HashMap<String, u64> = HashMap::new();
            for ev in tracker.events().filter(|e| e.t >= since) {
                let group = ev.exe_path.as_deref().unwrap_or(&ev.name).to_lowercase();
                match ev.kind {
                    ProcessEventKind::Exited => {
                        // Ignore very short-lived instances (one-shot helper tools).
                        let lived = if ev.key.created != 0 { ev.t.saturating_sub(filetime_to_unix_ms(ev.key.created)) } else { 0 };
                        if lived >= 10_000 {
                            last_exit.insert(group, ev.t);
                        }
                    }
                    ProcessEventKind::Started => {
                        if let Some(exit_t) = last_exit.remove(&group) {
                            // A crash loop respawns quickly; reopening something
                            // minutes later is just normal use.
                            if ev.t >= exit_t && ev.t - exit_t <= RESPAWN_MS {
                                let g = groups.entry(group).or_insert((0, None, Vec::new()));
                                g.0 += 1;
                                g.1 = Some(ev.key);
                                g.2.push(ev.t);
                            }
                        }
                    }
                }
            }
            for (group, (count, key, times)) in groups {
                let Some(key) = key else { continue };
                let Some(p) = tracker.get(&key) else { continue };
                if is_excluded(p) || is_launched_on_demand(&p.name) {
                    continue;
                }
                // Multi-process apps (browsers, service hosts) open and close
                // instances all the time. Only a program that runs as a single
                // copy and keeps dying is a restart loop.
                if tracker.alive().any(|q| q.key != key && q.group() == group) {
                    continue;
                }
                let condition = count >= r.min_restarts;
                if self.gate(RuleKind::RepeatedRestarts, &format!("group:{group}"), condition, !condition, now, cooldown) {
                    let m = metrics_for(p, now, window, ncpu);
                    out.push(self.make(p, RuleKind::RepeatedRestarts, now, m, format!(
                        "Exited and started again {} times within {} min (only instances that ran at least 10 s are counted).",
                        count, r.window_minutes
                    ), serde_json::json!({"restarts": count, "window_minutes": r.window_minutes, "restart_times": times})));
                }
            }
        }

        // Forget state for instances that are gone (bounded memory).
        self.state.retain(|(_, s), st| s.starts_with("group:") || alive_subjects.contains(s) || st.last_fired.map(|t| now.saturating_sub(t) < cooldown).unwrap_or(false));
        out
    }

    fn make(&self, p: &TrackedProcess, rule: RuleKind, now: u64, metrics: DetectionMetrics, reason: String, details: serde_json::Value) -> Detection {
        Detection {
            rule,
            priority: rule.priority(),
            key: p.key,
            name: p.name.clone(),
            exe_path: p.exe_path.clone(),
            at: now,
            reason,
            metrics,
            details,
            synthetic: p.synthetic,
        }
    }
}

/// Synthetic telemetry fixtures. Used by tests; they never reach the real UI
/// as real measurements (every snapshot is marked `synthetic`).
#[cfg(test)]
pub mod fixtures {
    use crate::collector::tracker::{Tracker, TrackerConfig};
    use crate::types::{unix_ms_to_filetime, Access, RawProcess, RawSnapshot};

    pub const T0: u64 = 1_750_000_000_000;
    pub const STEP: u64 = 5_000;

    pub struct Fixture {
        pub tracker: Tracker,
        pub i: u64,
        cpu_time: std::collections::HashMap<u32, u64>,
    }

    pub struct FakeProc {
        pub pid: u32,
        pub name: &'static str,
        pub started_ms_ago: u64,
        pub cpu: f64,
        pub mem: u64,
    }

    impl Fixture {
        pub fn new() -> Self {
            Self { tracker: Tracker::new(TrackerConfig::default()), i: 0, cpu_time: Default::default() }
        }
        pub fn now(&self) -> u64 {
            T0 + self.i * STEP
        }
        /// Advance one sample interval with the given processes at the given CPU %.
        pub fn tick(&mut self, procs: &[FakeProc]) {
            self.i += 1;
            let now = self.now();
            let ncpu = 4u64;
            let mut raws = Vec::new();
            for p in procs {
                let ticks = (p.cpu / 100.0 * (STEP * 10_000 * ncpu) as f64) as u64;
                let total = self.cpu_time.entry(p.pid).or_insert(0);
                *total += ticks;
                raws.push(RawProcess {
                    pid: p.pid,
                    ppid: 0,
                    name: p.name.into(),
                    created: unix_ms_to_filetime(T0.saturating_sub(p.started_ms_ago)),
                    cpu_time: Some(*total),
                    private_bytes: Some(p.mem),
                    working_set: Some(p.mem),
                    session_id: Some(1),
                    access: Access::Full,
                });
            }
            let snap = RawSnapshot { mono_ms: self.i * STEP, wall_ms: now, logical_cpus: ncpu as u32, processes: raws, synthetic: true };
            self.tracker.ingest(&snap, &mut |r| Some(format!("C:\\fixture\\{}", r.name)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::settings::Settings;

    fn rules() -> RuleSettings {
        Settings::default().rules
    }

    fn run(fx: &mut Fixture, det: &mut Detector, rules: &RuleSettings, procs: &[FakeProc]) -> Vec<Detection> {
        fx.tick(procs);
        det.evaluate(&fx.tracker, rules, fx.now(), &|_| false)
    }

    fn p(pid: u32, cpu: f64, mem: u64) -> FakeProc {
        FakeProc { pid, name: "fixture.exe", started_ms_ago: 60_000, cpu, mem }
    }

    #[test]
    fn sustained_cpu_requires_consecutive_samples() {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        // First sample has no CPU delta; then 11 high samples: not enough.
        for _ in 0..12 {
            fired.extend(run(&mut fx, &mut det, &r, &[p(1, 40.0, 1 << 20)]));
        }
        assert!(fired.is_empty(), "fired too early");
        fired.extend(run(&mut fx, &mut det, &r, &[p(1, 40.0, 1 << 20)]));
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, RuleKind::SustainedCpu);
        assert!(fired[0].synthetic);
    }

    #[test]
    fn sustained_cpu_dip_resets_the_count() {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        for i in 0..40 {
            let cpu = if i % 10 == 9 { 5.0 } else { 40.0 };
            fired.extend(run(&mut fx, &mut det, &r, &[p(1, cpu, 1 << 20)]));
        }
        assert!(fired.iter().all(|d| d.rule != RuleKind::SustainedCpu));
    }

    #[test]
    fn sustained_cpu_hysteresis_and_cooldown_prevent_spam() {
        let mut r = rules();
        r.spikes.enabled = false;
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut count = 0;
        // Hover around the threshold: above, then slightly below (but above
        // the release level), repeatedly for a long time.
        for i in 0..400 {
            let cpu = if (i / 13) % 2 == 0 { 40.0 } else { 20.0 };
            count += run(&mut fx, &mut det, &r, &[p(1, cpu, 1 << 20)]).len();
        }
        assert_eq!(count, 1, "hysteresis should latch while CPU stays above the release level");

        // Full release then re-trigger inside the cooldown: no second alert.
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut count = 0;
        for i in 0..200 {
            let cpu = if (i / 20) % 2 == 0 { 40.0 } else { 1.0 };
            count += run(&mut fx, &mut det, &r, &[p(1, cpu, 1 << 20)]).len();
        }
        assert_eq!(count, 1, "cooldown should suppress re-alerting within 30 minutes");
    }

    #[test]
    fn repeated_spikes_rule() {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        for i in 0..40 {
            let cpu = if i % 6 == 3 { 70.0 } else { 2.0 };
            fired.extend(run(&mut fx, &mut det, &r, &[p(1, cpu, 1 << 20)]));
        }
        assert!(fired.iter().any(|d| d.rule == RuleKind::RepeatedSpikes));
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn memory_growth_rule() {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        let base: u64 = 400 << 20;
        for i in 0..200u64 {
            let mem = base + i * (5 << 20); // +5 MB per sample
            fired.extend(run(&mut fx, &mut det, &r, &[p(1, 1.0, mem)]));
        }
        assert_eq!(fired.iter().filter(|d| d.rule == RuleKind::MemoryGrowth).count(), 1);
    }

    #[test]
    fn stable_memory_does_not_trigger_growth() {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        for i in 0..250u64 {
            let mem = (2048u64 << 20) + (i % 7) * (20 << 20);
            fired.extend(run(&mut fx, &mut det, &r, &[p(1, 1.0, mem)]));
        }
        assert!(fired.is_empty());
    }

    #[test]
    fn lingering_requires_runtime_and_activity() {
        let r = rules();
        // Long-running but idle: no alert.
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let idle = |cpu| FakeProc { pid: 7, name: "player.exe", started_ms_ago: 5 * 3_600_000, cpu, mem: 1 << 20 };
        let mut fired = Vec::new();
        for _ in 0..200 {
            fired.extend(run(&mut fx, &mut det, &r, &[idle(0.5)]));
        }
        assert!(fired.is_empty(), "runtime alone must not alert");
        // Long-running and active (below the sustained CPU threshold): alert.
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        for _ in 0..200 {
            fired.extend(run(&mut fx, &mut det, &r, &[idle(8.0)]));
        }
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].rule, RuleKind::Lingering);
        assert_eq!(fired[0].priority, Priority::Info);
        // Young and active: no lingering alert.
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let young = || FakeProc { pid: 8, name: "young.exe", started_ms_ago: 60_000, cpu: 8.0, mem: 1 << 20 };
        let mut fired = Vec::new();
        for _ in 0..200 {
            fired.extend(run(&mut fx, &mut det, &r, &[young()]));
        }
        assert!(fired.is_empty());
    }

    #[test]
    fn repeated_restarts_rule() {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        // An instance lives ~20 s, exits, and a new instance (new PID) appears.
        for gen in 0..5u32 {
            for _ in 0..4 {
                fx.tick(&[FakeProc { pid: 100 + gen, name: "flappy.exe", started_ms_ago: 0, cpu: 1.0, mem: 1 << 20 }]);
                fired.extend(det.evaluate(&fx.tracker, &r, fx.now(), &|_| false));
            }
            // One empty tick: the instance exited.
            fx.tick(&[]);
            fired.extend(det.evaluate(&fx.tracker, &r, fx.now(), &|_| false));
        }
        // Instances in this fixture are created at T0, so every exit has
        // lived >= 10 s; each new PID following an exit counts as a restart.
        let restarts: Vec<_> = fired.iter().filter(|d| d.rule == RuleKind::RepeatedRestarts).collect();
        assert_eq!(restarts.len(), 1);
    }

    /// Five generations of `name`, each living four ticks, with `gap` empty
    /// ticks between them and optional companion instances kept alive.
    fn flap(name: &'static str, gap: usize, companion: bool) -> usize {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        let other = || FakeProc { pid: 999, name, started_ms_ago: 0, cpu: 1.0, mem: 1 << 20 };
        for gen in 0..5u32 {
            for _ in 0..4 {
                let mut procs = vec![FakeProc { pid: 100 + gen, name, started_ms_ago: 0, cpu: 1.0, mem: 1 << 20 }];
                if companion {
                    procs.push(other());
                }
                fx.tick(&procs);
                fired.extend(det.evaluate(&fx.tracker, &r, fx.now(), &|_| false));
            }
            for _ in 0..gap {
                let procs: Vec<FakeProc> = if companion { vec![other()] } else { vec![] };
                fx.tick(&procs);
                fired.extend(det.evaluate(&fx.tracker, &r, fx.now(), &|_| false));
            }
        }
        fired.iter().filter(|d| d.rule == RuleKind::RepeatedRestarts).count()
    }

    #[test]
    fn restarts_ignore_normal_churn() {
        assert_eq!(flap("flappy.exe", 1, false), 1, "a single copy that keeps respawning is a loop");
        assert_eq!(flap("chrome.exe", 1, true), 0, "multi-process apps open and close instances all the time");
        assert_eq!(flap("conhost.exe", 1, false), 0, "console hosts are launched on demand");
        assert_eq!(flap("flappy.exe", (RESPAWN_MS / STEP) as usize + 2, false), 0, "reopening it later is normal use");
    }

    #[test]
    fn exclusions_suppress_detection() {
        let r = rules();
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        for _ in 0..30 {
            fx.tick(&[p(1, 50.0, 1 << 20)]);
            fired.extend(det.evaluate(&fx.tracker, &r, fx.now(), &|p| p.name == "fixture.exe"));
        }
        assert!(fired.is_empty());
    }

    #[test]
    fn pid_reuse_does_not_carry_rule_state_to_new_process() {
        let mut r = rules();
        r.spikes.enabled = false;
        let mut fx = Fixture::new();
        let mut det = Detector::new();
        let mut fired = Vec::new();
        for _ in 0..20 {
            fired.extend(run(&mut fx, &mut det, &r, &[p(1, 40.0, 1 << 20)]));
        }
        assert_eq!(fired.len(), 1);
        let first_key = fired[0].key;
        // PID 1 is reused by a new process (different creation time) that is also busy.
        let mut fired2 = Vec::new();
        for _ in 0..20 {
            fired2.extend(run(&mut fx, &mut det, &r, &[FakeProc { pid: 1, name: "other.exe", started_ms_ago: 1_000, cpu: 40.0, mem: 1 << 20 }]));
        }
        assert_eq!(fired2.len(), 1, "a new instance is a new subject");
        assert_ne!(fired2[0].key, first_key);
        assert_eq!(fired2[0].name, "other.exe");
    }
}

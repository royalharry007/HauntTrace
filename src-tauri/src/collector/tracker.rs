//! Turns raw snapshots into per-instance resource histories and process
//! start/exit events. Pure logic: no OS calls, so it is fully testable with
//! synthetic snapshots.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;

use crate::types::{Access, ProcessEvent, ProcessEventKind, ProcessKey, RawProcess, RawSnapshot, Sample};

#[derive(Debug, Clone, Serialize)]
pub struct TrackedProcess {
    pub key: ProcessKey,
    pub name: String,
    pub exe_path: Option<String>,
    pub ppid: u32,
    /// Parent instance, only when the parent PID was alive and created before
    /// this process (so a reused parent PID is never mistaken for the parent).
    pub parent_key: Option<ProcessKey>,
    pub session_id: Option<u32>,
    pub access: Access,
    pub first_seen: u64,
    pub last_seen: u64,
    pub exited_at: Option<u64>,
    #[serde(skip)]
    pub history: VecDeque<Sample>,
    #[serde(skip)]
    last_cpu_time: Option<u64>,
    #[serde(skip)]
    last_mono: u64,
    pub synthetic: bool,
}

impl TrackedProcess {
    pub fn alive(&self) -> bool {
        self.exited_at.is_none()
    }
    pub fn latest(&self) -> Option<&Sample> {
        self.history.back()
    }
    /// Group key used for restart detection: the lowercase image path when
    /// known, otherwise the lowercase name.
    pub fn group(&self) -> String {
        self.exe_path.as_deref().unwrap_or(&self.name).to_lowercase()
    }
}

#[derive(Debug, Clone)]
pub struct TrackerConfig {
    pub history_capacity: usize,
    pub exited_retention_ms: u64,
    pub event_retention_ms: u64,
    pub max_events: usize,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            // 30 minutes at the default 5 s interval.
            history_capacity: 360,
            exited_retention_ms: 15 * 60_000,
            event_retention_ms: 60 * 60_000,
            max_events: 5000,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct IngestResult {
    pub started: Vec<ProcessKey>,
    pub exited: Vec<ProcessKey>,
}

pub struct Tracker {
    cfg: TrackerConfig,
    procs: HashMap<ProcessKey, TrackedProcess>,
    by_pid: HashMap<u32, ProcessKey>,
    events: VecDeque<ProcessEvent>,
    initialized: bool,
    pub logical_cpus: u32,
    pub last_wall: u64,
    pub snapshots_ingested: u64,
}

impl Tracker {
    pub fn new(cfg: TrackerConfig) -> Self {
        Self {
            cfg,
            procs: HashMap::new(),
            by_pid: HashMap::new(),
            events: VecDeque::new(),
            initialized: false,
            logical_cpus: 1,
            last_wall: 0,
            snapshots_ingested: 0,
        }
    }

    pub fn set_history_capacity(&mut self, cap: usize) {
        self.cfg.history_capacity = cap.max(12);
    }

    /// Ingest one snapshot. `resolve_path` is called once per newly seen
    /// instance to obtain its executable path.
    pub fn ingest(&mut self, snap: &RawSnapshot, resolve_path: &mut dyn FnMut(&RawProcess) -> Option<String>) -> IngestResult {
        let mut result = IngestResult::default();
        let first = !self.initialized;
        self.logical_cpus = snap.logical_cpus.max(1);
        let ncpu = self.logical_cpus as f64;

        let mut seen: HashSet<ProcessKey> = HashSet::with_capacity(snap.processes.len());
        let mut new_by_pid: HashMap<u32, ProcessKey> = HashMap::with_capacity(snap.processes.len());
        let mut newly_seen: Vec<ProcessKey> = Vec::new();

        for raw in &snap.processes {
            let key = ProcessKey { pid: raw.pid, created: raw.created };
            // Weak identity (creation time unreadable): a different name on the
            // same PID means a different process.
            let replaced_weak = !key.has_reliable_identity()
                && self.procs.get(&key).map(|p| p.alive() && !p.name.eq_ignore_ascii_case(&raw.name)).unwrap_or(false);
            if replaced_weak {
                if let Some(old) = self.procs.remove(&key) {
                    self.push_event(snap.wall_ms, ProcessEventKind::Exited, &old);
                    result.exited.push(key);
                }
            }
            seen.insert(key);
            new_by_pid.insert(raw.pid, key);

            let existed = self.procs.get(&key).map(|p| p.alive()).unwrap_or(false);
            if !existed {
                let exe_path = if raw.access == Access::Full { resolve_path(raw) } else { None };
                self.procs.insert(
                    key,
                    TrackedProcess {
                        key,
                        name: raw.name.clone(),
                        exe_path,
                        ppid: raw.ppid,
                        parent_key: None,
                        session_id: raw.session_id,
                        access: raw.access,
                        first_seen: snap.wall_ms,
                        last_seen: snap.wall_ms,
                        exited_at: None,
                        history: VecDeque::new(),
                        last_cpu_time: raw.cpu_time,
                        last_mono: snap.mono_ms,
                        synthetic: snap.synthetic,
                    },
                );
                newly_seen.push(key);
                if !first {
                    result.started.push(key);
                }
                // First observation: no CPU delta yet, but record memory.
                if let (Some(pb), Some(ws)) = (raw.private_bytes, raw.working_set) {
                    let cap = self.cfg.history_capacity;
                    let p = self.procs.get_mut(&key).unwrap();
                    p.history.push_back(Sample { t: snap.wall_ms, cpu: f32::NAN, private_bytes: pb, working_set: ws });
                    while p.history.len() > cap {
                        p.history.pop_front();
                    }
                }
                continue;
            }

            let cap = self.cfg.history_capacity;
            let p = self.procs.get_mut(&key).unwrap();
            p.last_seen = snap.wall_ms;
            p.access = raw.access;
            let cpu = match (raw.cpu_time, p.last_cpu_time) {
                (Some(now), Some(prev)) if snap.mono_ms > p.last_mono && now >= prev => {
                    let wall_ticks = (snap.mono_ms - p.last_mono) as f64 * 10_000.0;
                    (((now - prev) as f64 / (wall_ticks * ncpu)) * 100.0).clamp(0.0, 100.0) as f32
                }
                _ => f32::NAN,
            };
            p.last_cpu_time = raw.cpu_time;
            p.last_mono = snap.mono_ms;
            if let (Some(pb), Some(ws)) = (raw.private_bytes, raw.working_set) {
                p.history.push_back(Sample { t: snap.wall_ms, cpu, private_bytes: pb, working_set: ws });
                while p.history.len() > cap {
                    p.history.pop_front();
                }
            }
        }

        // Resolve parents for new instances against the current table.
        for key in &newly_seen {
            let (ppid, created) = {
                let p = &self.procs[key];
                (p.ppid, p.key.created)
            };
            if ppid == 0 || ppid == key.pid {
                continue;
            }
            if let Some(pk) = new_by_pid.get(&ppid) {
                let parent_ok = pk.created == 0 || created == 0 || pk.created <= created;
                if parent_ok {
                    self.procs.get_mut(key).unwrap().parent_key = Some(*pk);
                }
            }
        }

        // Emit start events after paths are known.
        for key in &result.started {
            let p = self.procs[key].clone();
            self.push_event(snap.wall_ms, ProcessEventKind::Started, &p);
        }

        // Exits: alive instances not in this snapshot.
        let gone: Vec<ProcessKey> = self.procs.iter().filter(|(k, p)| p.alive() && !seen.contains(k)).map(|(k, _)| *k).collect();
        for key in gone {
            let p = self.procs.get_mut(&key).unwrap();
            p.exited_at = Some(snap.wall_ms);
            let p = p.clone();
            self.push_event(snap.wall_ms, ProcessEventKind::Exited, &p);
            result.exited.push(key);
        }

        // Retention.
        let cutoff = snap.wall_ms.saturating_sub(self.cfg.exited_retention_ms);
        self.procs.retain(|_, p| p.exited_at.map(|t| t >= cutoff).unwrap_or(true));
        let ev_cutoff = snap.wall_ms.saturating_sub(self.cfg.event_retention_ms);
        while self.events.front().map(|e| e.t < ev_cutoff).unwrap_or(false) || self.events.len() > self.cfg.max_events {
            self.events.pop_front();
        }

        self.by_pid = new_by_pid;
        self.initialized = true;
        self.last_wall = snap.wall_ms;
        self.snapshots_ingested += 1;
        result
    }

    fn push_event(&mut self, t: u64, kind: ProcessEventKind, p: &TrackedProcess) {
        self.events.push_back(ProcessEvent { t, kind, key: p.key, name: p.name.clone(), exe_path: p.exe_path.clone() });
    }

    pub fn get(&self, key: &ProcessKey) -> Option<&TrackedProcess> {
        self.procs.get(key)
    }

    /// The live instance currently holding `pid`, if any.
    pub fn live_by_pid(&self, pid: u32) -> Option<&TrackedProcess> {
        self.by_pid.get(&pid).and_then(|k| self.procs.get(k)).filter(|p| p.alive())
    }

    pub fn iter(&self) -> impl Iterator<Item = &TrackedProcess> {
        self.procs.values()
    }

    pub fn alive(&self) -> impl Iterator<Item = &TrackedProcess> {
        self.procs.values().filter(|p| p.alive())
    }

    pub fn children(&self, key: &ProcessKey) -> Vec<&TrackedProcess> {
        self.procs.values().filter(|p| p.parent_key.as_ref() == Some(key)).collect()
    }

    pub fn events(&self) -> impl Iterator<Item = &ProcessEvent> {
        self.events.iter()
    }

    pub fn process_count(&self) -> usize {
        self.by_pid.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(pid: u32, created: u64, name: &str, cpu_time: u64, mem: u64) -> RawProcess {
        RawProcess {
            pid,
            ppid: 0,
            name: name.into(),
            created,
            cpu_time: Some(cpu_time),
            private_bytes: Some(mem),
            working_set: Some(mem),
            session_id: Some(1),
            access: Access::Full,
        }
    }

    fn snap(mono: u64, procs: Vec<RawProcess>) -> RawSnapshot {
        RawSnapshot { mono_ms: mono, wall_ms: 1_700_000_000_000 + mono, logical_cpus: 4, processes: procs, synthetic: true }
    }

    fn no_path(_: &RawProcess) -> Option<String> {
        None
    }

    #[test]
    fn cpu_percent_is_relative_to_all_logical_cpus() {
        let mut t = Tracker::new(TrackerConfig::default());
        t.ingest(&snap(0, vec![raw(10, 5, "a.exe", 0, 100)]), &mut no_path);
        // 5 s wall on 4 CPUs = 200_000_000 ticks of capacity; one full core = 50_000_000.
        t.ingest(&snap(5000, vec![raw(10, 5, "a.exe", 50_000_000, 100)]), &mut no_path);
        let p = t.get(&ProcessKey { pid: 10, created: 5 }).unwrap();
        assert!((p.latest().unwrap().cpu - 25.0).abs() < 0.01);
    }

    #[test]
    fn pid_reuse_creates_a_distinct_instance() {
        let mut t = Tracker::new(TrackerConfig::default());
        t.ingest(&snap(0, vec![raw(10, 5, "old.exe", 0, 100)]), &mut no_path);
        t.ingest(&snap(5000, vec![raw(10, 5, "old.exe", 1000, 100)]), &mut no_path);
        // Same PID, new creation time: the old process exited, a new one started.
        let r = t.ingest(&snap(10000, vec![raw(10, 99, "new.exe", 0, 100)]), &mut no_path);
        assert_eq!(r.exited, vec![ProcessKey { pid: 10, created: 5 }]);
        assert_eq!(r.started, vec![ProcessKey { pid: 10, created: 99 }]);
        let old = t.get(&ProcessKey { pid: 10, created: 5 }).unwrap();
        assert!(!old.alive());
        assert_eq!(old.name, "old.exe");
        let new = t.live_by_pid(10).unwrap();
        assert_eq!(new.key.created, 99);
        // The new instance must not inherit the old instance's CPU baseline.
        assert!(new.latest().unwrap().cpu.is_nan());
    }

    #[test]
    fn parent_is_not_assigned_from_a_reused_pid() {
        let mut t = Tracker::new(TrackerConfig::default());
        let mut parent = raw(20, 500, "newer-holder.exe", 0, 1);
        parent.ppid = 0;
        let mut child = raw(21, 100, "child.exe", 0, 1);
        child.ppid = 20; // Created before the current holder of PID 20.
        t.ingest(&snap(0, vec![parent, child]), &mut no_path);
        assert!(t.get(&ProcessKey { pid: 21, created: 100 }).unwrap().parent_key.is_none());
    }

    #[test]
    fn first_snapshot_does_not_emit_start_events() {
        let mut t = Tracker::new(TrackerConfig::default());
        let r = t.ingest(&snap(0, vec![raw(1, 1, "a", 0, 1), raw(2, 2, "b", 0, 1)]), &mut no_path);
        assert!(r.started.is_empty());
        let r = t.ingest(&snap(5000, vec![raw(1, 1, "a", 0, 1), raw(3, 3, "c", 0, 1)]), &mut no_path);
        assert_eq!(r.started.len(), 1);
        assert_eq!(r.exited.len(), 1);
        assert_eq!(t.events().count(), 2);
    }

    #[test]
    fn history_is_bounded() {
        let mut t = Tracker::new(TrackerConfig { history_capacity: 12, ..Default::default() });
        for i in 0..50u64 {
            t.ingest(&snap(i * 5000, vec![raw(1, 1, "a", i * 1000, 1)]), &mut no_path);
        }
        assert_eq!(t.get(&ProcessKey { pid: 1, created: 1 }).unwrap().history.len(), 12);
    }
}

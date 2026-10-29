//! "Sweep the house": who is using this PC right now, on demand, without
//! waiting for a rule to fire. Also the overall haunt level of the house.

use serde::Serialize;

use crate::collector::tracker::{TrackedProcess, Tracker};
use crate::detection::metrics_for;

/// Not real programs: the idle counter would always top the CPU list.
const NOT_SPIRITS: &[&str] = &["idle", "system idle process"];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SweepEntry {
    pub pid: u32,
    /// Creation FILETIME as a string (exceeds JS number precision).
    pub created: String,
    pub name: String,
    pub exe_path: Option<String>,
    /// Average over the last 30 s, % of the whole machine.
    pub cpu: f32,
    pub private_bytes: u64,
    /// "cpu" or "memory": why it made the list.
    pub why: &'static str,
}

fn counts(p: &TrackedProcess, own_pid: u32) -> bool {
    p.key.pid != 0 && p.key.pid != own_pid && !NOT_SPIRITS.iter().any(|n| p.name.eq_ignore_ascii_case(n))
}

/// The busiest processes right now: up to `by_cpu` by recent CPU (only if
/// actually busy) and up to `by_mem` more by private memory.
pub fn sweep(tracker: &Tracker, now: u64, own_pid: u32, by_cpu: usize, by_mem: usize) -> Vec<SweepEntry> {
    let rows: Vec<(f32, u64, &TrackedProcess)> = tracker
        .alive()
        .filter(|p| counts(p, own_pid))
        .map(|p| {
            let m = metrics_for(p, now, 30_000, tracker.logical_cpus);
            (m.cpu_avg.unwrap_or(0.0), m.private_bytes.unwrap_or(0), p)
        })
        .collect();
    let entry = |(cpu, mem, p): &(f32, u64, &TrackedProcess), why| SweepEntry {
        pid: p.key.pid,
        created: p.key.created.to_string(),
        name: p.name.clone(),
        exe_path: p.exe_path.clone(),
        cpu: *cpu,
        private_bytes: *mem,
        why,
    };
    let mut by_c = rows.clone();
    by_c.sort_by(|a, b| b.0.total_cmp(&a.0));
    let mut out: Vec<SweepEntry> = by_c.iter().filter(|r| r.0 >= 1.0).take(by_cpu).map(|r| entry(r, "cpu")).collect();
    let mut by_m = rows;
    by_m.sort_by(|a, b| b.1.cmp(&a.1));
    let extra: Vec<SweepEntry> = by_m.iter().filter(|r| !out.iter().any(|e| e.pid == r.2.key.pid)).take(by_mem).map(|r| entry(r, "memory")).collect();
    out.extend(extra);
    out
}

/// Total CPU in use by all processes (% of the machine), from the latest sample.
pub fn cpu_total(tracker: &Tracker) -> f32 {
    tracker
        .alive()
        .filter(|p| counts(p, 0))
        .filter_map(|p| p.history.back().map(|s| s.cpu).filter(|c| !c.is_nan()))
        .sum::<f32>()
        .clamp(0.0, 100.0)
}

/// 0 calm · 1 uneasy · 2 haunted, from CPU and memory pressure.
pub fn haunt_level(cpu_total: f32, memory_used_pct: Option<f32>) -> u8 {
    let mem = memory_used_pct.unwrap_or(0.0);
    if cpu_total >= 85.0 || mem >= 92.0 {
        2
    } else if cpu_total >= 50.0 || mem >= 80.0 {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::fixtures::{FakeProc, Fixture};

    #[test]
    fn sweep_lists_busy_then_big_without_idle_or_self() {
        let mut fx = Fixture::new();
        let procs = [
            FakeProc { pid: 0, name: "System Idle Process", started_ms_ago: 0, cpu: 90.0, mem: 0 },
            FakeProc { pid: 10, name: "busy.exe", started_ms_ago: 0, cpu: 30.0, mem: 50 << 20 },
            FakeProc { pid: 11, name: "quiet.exe", started_ms_ago: 0, cpu: 0.1, mem: 900 << 20 },
            FakeProc { pid: 12, name: "me.exe", started_ms_ago: 0, cpu: 40.0, mem: 10 << 20 },
            FakeProc { pid: 13, name: "warm.exe", started_ms_ago: 0, cpu: 5.0, mem: 20 << 20 },
        ];
        for _ in 0..8 {
            fx.tick(&procs);
        }
        let out = sweep(&fx.tracker, fx.now(), 12, 3, 1);
        let names: Vec<_> = out.iter().map(|e| (e.name.as_str(), e.why)).collect();
        assert_eq!(names, vec![("busy.exe", "cpu"), ("warm.exe", "cpu"), ("quiet.exe", "memory")]);
        assert!((out[0].cpu - 30.0).abs() < 1.0);
    }

    #[test]
    fn haunt_levels() {
        assert_eq!(haunt_level(10.0, Some(40.0)), 0);
        assert_eq!(haunt_level(60.0, Some(40.0)), 1);
        assert_eq!(haunt_level(10.0, Some(85.0)), 1);
        assert_eq!(haunt_level(90.0, None), 2);
        assert_eq!(haunt_level(5.0, Some(95.0)), 2);
    }
}

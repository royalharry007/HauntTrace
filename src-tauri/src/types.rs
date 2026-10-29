//! Data types shared between the collector, detector, investigation engine and UI.

use serde::{Deserialize, Serialize};

/// Stable identity of one process instance.
///
/// A PID alone is not an identity: Windows reuses PIDs. The pair of PID and
/// creation time (FILETIME, 100 ns ticks since 1601) uniquely identifies an
/// instance. When the creation time cannot be read (access denied), it is 0
/// and `weak` identity matching falls back to the process name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ProcessKey {
    pub pid: u32,
    pub created: u64,
}

impl ProcessKey {
    pub fn has_reliable_identity(&self) -> bool {
        self.created != 0
    }
}

/// How much the collector was able to read for a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Times, memory and image path were readable.
    Full,
    /// The process exists but could not be opened (protected or access denied).
    Denied,
}

/// One process as seen in a single raw snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// Creation FILETIME in 100 ns ticks, 0 if unavailable.
    pub created: u64,
    /// Total kernel + user CPU time in 100 ns ticks, if readable.
    pub cpu_time: Option<u64>,
    /// Private committed bytes, if readable.
    pub private_bytes: Option<u64>,
    /// Working set bytes, if readable.
    pub working_set: Option<u64>,
    pub session_id: Option<u32>,
    pub access: Access,
}

/// A complete snapshot of the process table at one moment.
#[derive(Debug, Clone)]
pub struct RawSnapshot {
    /// Monotonic timestamp in ms; used for rate computations.
    pub mono_ms: u64,
    /// Wall clock time (unix ms); used for display and history.
    pub wall_ms: u64,
    pub logical_cpus: u32,
    pub processes: Vec<RawProcess>,
    /// Is this snapshot synthetic test data rather than a real measurement?
    pub synthetic: bool,
}

/// One resource sample for one process instance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Sample {
    pub t: u64,
    /// CPU usage as % of the whole machine (all logical CPUs = 100%).
    pub cpu: f32,
    pub private_bytes: u64,
    pub working_set: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessEventKind {
    Started,
    Exited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub t: u64,
    pub kind: ProcessEventKind,
    pub key: ProcessKey,
    pub name: String,
    pub exe_path: Option<String>,
}

/// Convert a Windows FILETIME tick count to unix milliseconds.
pub fn filetime_to_unix_ms(ft: u64) -> u64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    if ft <= EPOCH_DIFF {
        0
    } else {
        (ft - EPOCH_DIFF) / 10_000
    }
}

pub fn unix_ms_to_filetime(ms: u64) -> u64 {
    ms * 10_000 + 116_444_736_000_000_000
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

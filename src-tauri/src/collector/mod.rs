//! Process collection: a raw source of snapshots plus the tracker that turns
//! snapshots into per-instance histories and start/exit events.

pub mod tracker;
#[cfg(windows)]
pub mod windows;

use crate::types::RawSnapshot;

/// Anything that can produce process-table snapshots. The real implementation
/// uses Win32; tests use synthetic fixtures.
pub trait ProcessSource: Send {
    fn snapshot(&mut self) -> Result<RawSnapshot, String>;
    /// Resolve the full executable path for a live process instance.
    fn image_path(&mut self, pid: u32, created: u64) -> Option<String>;
}

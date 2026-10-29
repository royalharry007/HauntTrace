//! Real process collection through native Win32 APIs (no WMI, no PowerShell).
//!
//! Uses a Toolhelp32 snapshot for the process table and opens each process
//! with `PROCESS_QUERY_LIMITED_INFORMATION` only, which works without
//! administrator rights for most processes. Protected processes are reported
//! with `Access::Denied` rather than guessed.

use std::time::Instant;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    GetActiveProcessorCount, GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::ProcessSource;
use crate::types::{now_ms, Access, RawProcess, RawSnapshot};

pub struct WinProcessSource {
    start: Instant,
}

impl WinProcessSource {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Default for WinProcessSource {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII wrapper so every opened handle is closed.
pub(crate) struct OwnedHandle(pub HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub(crate) fn open_limited(pid: u32) -> Option<OwnedHandle> {
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok().map(OwnedHandle) }
}

fn ft_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// Creation time and total CPU time (100 ns ticks) of an open process.
pub(crate) fn process_times(h: &OwnedHandle) -> Option<(u64, u64)> {
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u).ok()? };
    Some((ft_to_u64(c), ft_to_u64(k) + ft_to_u64(u)))
}

pub(crate) fn query_image_path(h: &OwnedHandle) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).ok()? };
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

fn memory(h: &OwnedHandle) -> Option<(u64, u64)> {
    let mut pmc = PROCESS_MEMORY_COUNTERS_EX::default();
    let cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    let ok = unsafe { K32GetProcessMemoryInfo(h.0, &mut pmc as *mut _ as *mut PROCESS_MEMORY_COUNTERS, cb) };
    if !ok.as_bool() {
        return None;
    }
    Some((pmc.PrivateUsage as u64, pmc.WorkingSetSize as u64))
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

pub fn logical_cpu_count() -> u32 {
    // ALL_PROCESSOR_GROUPS = 0xffff
    let n = unsafe { GetActiveProcessorCount(0xffff) };
    n.max(1)
}

impl ProcessSource for WinProcessSource {
    fn snapshot(&mut self) -> Result<RawSnapshot, String> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| format!("Toolhelp snapshot failed: {e}"))?;
        let snap = OwnedHandle(snap);
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut processes = Vec::with_capacity(400);

        let mut ok = unsafe { Process32FirstW(snap.0, &mut entry) }.is_ok();
        while ok {
            let pid = entry.th32ProcessID;
            let name = wide_to_string(&entry.szExeFile);
            let mut p = RawProcess {
                pid,
                ppid: entry.th32ParentProcessID,
                name,
                created: 0,
                cpu_time: None,
                private_bytes: None,
                working_set: None,
                session_id: None,
                access: Access::Denied,
            };
            let mut sid = 0u32;
            if unsafe { ProcessIdToSessionId(pid, &mut sid) }.is_ok() {
                p.session_id = Some(sid);
            }
            if pid != 0 {
                if let Some(h) = open_limited(pid) {
                    if let Some((created, cpu)) = process_times(&h) {
                        p.created = created;
                        p.cpu_time = Some(cpu);
                        p.access = Access::Full;
                    }
                    if let Some((private, ws)) = memory(&h) {
                        p.private_bytes = Some(private);
                        p.working_set = Some(ws);
                    }
                }
            }
            processes.push(p);
            ok = unsafe { Process32NextW(snap.0, &mut entry) }.is_ok();
        }

        Ok(RawSnapshot {
            mono_ms: self.start.elapsed().as_millis() as u64,
            wall_ms: now_ms(),
            logical_cpus: logical_cpu_count(),
            processes,
            synthetic: false,
        })
    }

    fn image_path(&mut self, pid: u32, created: u64) -> Option<String> {
        let h = open_limited(pid)?;
        // Guard against PID reuse: only answer for the exact instance.
        if created != 0 {
            let (c, _) = process_times(&h)?;
            if c != created {
                return None;
            }
        }
        query_image_path(&h)
    }
}

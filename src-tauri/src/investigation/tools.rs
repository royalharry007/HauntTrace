//! The validated tool registry. The model can only *request* these tools by
//! name; every request is parsed, checked against a strict schema, limited
//! to process instances already authorized for this investigation, and
//! deduplicated before the engine runs it. All tools are read-only.
//!
//! There is deliberately no tool that takes a file path, URL, command line
//! or script: paths are resolved by the app from the authorized process
//! instance, never supplied by the model.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;

use crate::types::ProcessKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolName {
    GetProcessDetails,
    GetParentProcess,
    GetResourceHistory,
    GetExecutableMetadata,
    GetDigitalSignatureStatus,
    GetRelatedProcesses,
    GetRecentProcessEvents,
}

pub struct ToolSpec {
    pub name: ToolName,
    pub id: &'static str,
    pub description: &'static str,
    /// (min, max, default) for the optional `minutes` argument, if accepted.
    pub minutes: Option<(u32, u32, u32)>,
}

pub const REGISTRY: &[ToolSpec] = &[
    ToolSpec { name: ToolName::GetProcessDetails, id: "get_process_details", description: "Current state of the process: alive/exited, runtime, session, image path, parent PID, latest CPU and memory.", minutes: None },
    ToolSpec { name: ToolName::GetParentProcess, id: "get_parent_process", description: "The verified parent process instance (which program launched it), if still known.", minutes: None },
    ToolSpec { name: ToolName::GetResourceHistory, id: "get_resource_history", description: "Downsampled CPU and memory history over the last N minutes (minutes 1-30, default 10).", minutes: Some((1, 30, 10)) },
    ToolSpec { name: ToolName::GetExecutableMetadata, id: "get_executable_metadata", description: "Version-resource metadata of the process's own executable: company, description, product, version, file size and dates, folder category.", minutes: None },
    ToolSpec { name: ToolName::GetDigitalSignatureStatus, id: "get_digital_signature_status", description: "Authenticode signature status and signer of the process's own executable (offline check).", minutes: None },
    ToolSpec { name: ToolName::GetRelatedProcesses, id: "get_related_processes", description: "Child processes and other running instances of the same executable, with their CPU and memory.", minutes: None },
    ToolSpec { name: ToolName::GetRecentProcessEvents, id: "get_recent_process_events", description: "Observed start/exit events for the same executable and its children over the last N minutes (minutes 1-60, default 15).", minutes: Some((1, 60, 15)) },
];

pub fn spec_by_id(id: &str) -> Option<&'static ToolSpec> {
    REGISTRY.iter().find(|s| s.id == id)
}

pub fn spec(name: ToolName) -> &'static ToolSpec {
    REGISTRY.iter().find(|s| s.name == name).expect("every tool is registered")
}

pub fn tool_ids() -> Vec<&'static str> {
    REGISTRY.iter().map(|s| s.id).collect()
}

/// A request that passed validation and authorization.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ValidRequest {
    pub tool: ToolName,
    pub tool_id: &'static str,
    pub pid: u32,
    #[serde(skip)]
    pub target: ProcessKey,
    pub minutes: Option<u32>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rejection {
    pub request: Value,
    pub reason: String,
}

/// What the engine has authorized for this investigation.
#[derive(Debug, Default, Clone)]
pub struct AuthContext {
    /// PID -> exact instance. Only the subject and processes revealed by
    /// evidence (parent, related) are ever added.
    pub authorized: HashMap<u32, ProcessKey>,
    pub executed: HashSet<(ToolName, ProcessKey, Option<u32>)>,
}

impl AuthContext {
    pub fn new(subject: ProcessKey) -> Self {
        let mut a = Self::default();
        a.authorized.insert(subject.pid, subject);
        a
    }

    pub fn authorize(&mut self, key: ProcessKey) {
        // Never let a later discovery silently re-point an authorized PID.
        self.authorized.entry(key.pid).or_insert(key);
    }
}

pub const MAX_REQUESTS_PER_STEP: usize = 2;

fn reject(req: &Value, reason: impl Into<String>) -> Rejection {
    Rejection { request: req.clone(), reason: reason.into() }
}

/// Validate one raw request object from the model.
pub fn validate_request(req: &Value, ctx: &AuthContext, pending: &[ValidRequest]) -> Result<ValidRequest, Rejection> {
    let obj = req.as_object().ok_or_else(|| reject(req, "Request is not an object"))?;
    for k in obj.keys() {
        if !matches!(k.as_str(), "tool" | "pid" | "minutes" | "reason") {
            return Err(reject(req, format!("Unexpected argument '{k}'")));
        }
    }
    let tool_id = obj.get("tool").and_then(|t| t.as_str()).ok_or_else(|| reject(req, "Missing tool name"))?;
    let spec = spec_by_id(tool_id).ok_or_else(|| reject(req, format!("'{tool_id}' is not a registered investigation tool")))?;
    let pid_v = obj.get("pid").ok_or_else(|| reject(req, "Missing pid"))?;
    let pid = pid_v.as_u64().filter(|p| *p <= u32::MAX as u64).ok_or_else(|| reject(req, "pid must be a non-negative integer"))? as u32;
    let target = *ctx
        .authorized
        .get(&pid)
        .ok_or_else(|| reject(req, format!("PID {pid} is not part of this investigation (only the subject and processes revealed by evidence may be inspected)")))?;
    let minutes = match (spec.minutes, obj.get("minutes")) {
        (None, Some(m)) if !m.is_null() => return Err(reject(req, format!("{tool_id} does not accept 'minutes'"))),
        (None, _) => None,
        (Some((_, _, def)), None) => Some(def),
        (Some((_, _, def)), Some(m)) if m.is_null() => Some(def),
        (Some((lo, hi, _)), Some(m)) => {
            let v = m.as_u64().ok_or_else(|| reject(req, "minutes must be an integer"))?;
            if v < lo as u64 || v > hi as u64 {
                return Err(reject(req, format!("minutes must be between {lo} and {hi}")));
            }
            Some(v as u32)
        }
    };
    let reason = obj.get("reason").and_then(|r| r.as_str()).map(|s| s.trim()).unwrap_or("");
    if reason.is_empty() {
        return Err(reject(req, "Each request must state why the check is relevant"));
    }
    let dedupe = (spec.name, target, minutes);
    if ctx.executed.contains(&dedupe) || pending.iter().any(|p| (p.tool, p.target, p.minutes) == dedupe) {
        return Err(reject(req, "Duplicate: this exact check was already run"));
    }
    // Same tool on same target with a different window is also redundant for
    // tools whose answer does not depend on the window.
    Ok(ValidRequest { tool: spec.name, tool_id: spec.id, pid, target, minutes, reason: reason.chars().take(300).collect() })
}

/// Validate a batch of requests from one planning step.
pub fn validate_batch(reqs: &[Value], ctx: &AuthContext) -> (Vec<ValidRequest>, Vec<Rejection>) {
    let mut ok = Vec::new();
    let mut rejected = Vec::new();
    for r in reqs {
        if ok.len() >= MAX_REQUESTS_PER_STEP {
            rejected.push(reject(r, format!("At most {MAX_REQUESTS_PER_STEP} checks may run per step")));
            continue;
        }
        match validate_request(r, ctx, &ok) {
            Ok(v) => ok.push(v),
            Err(e) => rejected.push(e),
        }
    }
    (ok, rejected)
}

/// Result of running a tool: a short summary for people, structured data
/// for the evidence record, and any process instances it revealed.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub title: String,
    pub summary: String,
    pub data: Value,
    /// Process instances revealed by this evidence, with a short label
    /// (e.g. "parent: explorer.exe"). They become inspectable.
    pub discovered: Vec<(ProcessKey, String)>,
}

/// Evidence gathering backend. The production implementation reads the
/// live tracker and Win32 metadata; tests supply a fake.
#[async_trait]
pub trait EvidenceProvider: Send + Sync {
    /// Initial evidence about the subject (before the model is consulted).
    async fn initial(&self, subject: ProcessKey) -> Vec<ToolOutput>;
    async fn run(&self, tool: ToolName, target: ProcessKey, minutes: Option<u32>) -> Result<ToolOutput, String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> AuthContext {
        AuthContext::new(ProcessKey { pid: 100, created: 5 })
    }

    #[test]
    fn accepts_a_valid_request() {
        let r = validate_request(&json!({"tool":"get_digital_signature_status","pid":100,"reason":"check signer"}), &ctx(), &[]).unwrap();
        assert_eq!(r.tool, ToolName::GetDigitalSignatureStatus);
        assert_eq!(r.target, ProcessKey { pid: 100, created: 5 });
    }

    #[test]
    fn rejects_unknown_tools_and_shell_like_requests() {
        for bad in [
            json!({"tool":"run_powershell","pid":100,"reason":"x"}),
            json!({"tool":"read_file","pid":100,"reason":"x"}),
            json!({"tool":"get_executable_metadata","pid":100,"path":"C:\\Windows\\System32\\config\\SAM","reason":"x"}),
            json!({"tool":"get_process_details","pid":100,"command":"del /f","reason":"x"}),
        ] {
            assert!(validate_request(&bad, &ctx(), &[]).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_unauthorized_pids_and_bad_arguments() {
        assert!(validate_request(&json!({"tool":"get_process_details","pid":4,"reason":"x"}), &ctx(), &[]).is_err());
        assert!(validate_request(&json!({"tool":"get_process_details","pid":-1,"reason":"x"}), &ctx(), &[]).is_err());
        assert!(validate_request(&json!({"tool":"get_process_details","pid":"100","reason":"x"}), &ctx(), &[]).is_err());
        assert!(validate_request(&json!({"tool":"get_process_details","pid":100}), &ctx(), &[]).is_err(), "reason required");
        assert!(validate_request(&json!({"tool":"get_resource_history","pid":100,"minutes":999,"reason":"x"}), &ctx(), &[]).is_err());
        assert!(validate_request(&json!({"tool":"get_process_details","pid":100,"minutes":5,"reason":"x"}), &ctx(), &[]).is_err());
        assert!(validate_request(&json!("get_process_details"), &ctx(), &[]).is_err());
    }

    #[test]
    fn defaults_minutes_and_dedupes() {
        let mut c = ctx();
        let r = validate_request(&json!({"tool":"get_resource_history","pid":100,"reason":"trend"}), &c, &[]).unwrap();
        assert_eq!(r.minutes, Some(10));
        c.executed.insert((r.tool, r.target, r.minutes));
        assert!(validate_request(&json!({"tool":"get_resource_history","pid":100,"minutes":10,"reason":"again"}), &c, &[]).is_err());
        assert!(validate_request(&json!({"tool":"get_resource_history","pid":100,"minutes":20,"reason":"longer"}), &c, &[]).is_ok());
    }

    #[test]
    fn batch_limits_and_in_batch_duplicates() {
        let reqs = vec![
            json!({"tool":"get_process_details","pid":100,"reason":"a"}),
            json!({"tool":"get_process_details","pid":100,"reason":"dup"}),
            json!({"tool":"get_parent_process","pid":100,"reason":"b"}),
            json!({"tool":"get_related_processes","pid":100,"reason":"c"}),
        ];
        let (ok, rej) = validate_batch(&reqs, &ctx());
        assert_eq!(ok.len(), 2);
        assert_eq!(rej.len(), 2);
    }

    #[test]
    fn authorization_cannot_be_repointed() {
        let mut c = ctx();
        c.authorize(ProcessKey { pid: 100, created: 999 });
        assert_eq!(c.authorized[&100].created, 5);
    }
}

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use super::tools::{EvidenceProvider, ToolName, ToolOutput};
use super::*;
use crate::llm::{ModelClient, ModelError};
use crate::store::{EvidenceRecord, StepRecord};

const SUBJECT: ProcessKey = ProcessKey { pid: 4242, created: 77 };

/// A model that returns scripted responses in order and records prompts.
struct ScriptedModel {
    responses: Mutex<Vec<Result<String, ModelError>>>,
    prompts: Mutex<Vec<String>>,
    delay: Duration,
}

impl ScriptedModel {
    fn new(r: Vec<Result<String, ModelError>>) -> Self {
        Self { responses: Mutex::new(r.into_iter().rev().collect()), prompts: Mutex::new(vec![]), delay: Duration::ZERO }
    }
}

#[async_trait]
impl ModelClient for ScriptedModel {
    fn model_name(&self) -> String {
        "scripted".into()
    }
    async fn generate_json(&self, _s: &str, user: &str, _schema: &Value, _t: Duration) -> Result<String, ModelError> {
        self.prompts.lock().unwrap().push(user.to_string());
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.responses.lock().unwrap().pop().unwrap_or(Err(ModelError::Other("script exhausted".into())))
    }
}

/// Provider with fixed, clearly synthetic outputs. Records executed tools.
#[derive(Default)]
struct FakeProvider {
    calls: Mutex<Vec<(ToolName, ProcessKey)>>,
}

#[async_trait]
impl EvidenceProvider for FakeProvider {
    async fn initial(&self, _s: ProcessKey) -> Vec<ToolOutput> {
        vec![ToolOutput { title: "Process snapshot".into(), summary: "busy.exe, running 2 h, parent PID 10".into(), data: json!({"name": "busy.exe"}), discovered: vec![] }]
    }
    async fn run(&self, tool: ToolName, target: ProcessKey, _m: Option<u32>) -> Result<ToolOutput, String> {
        self.calls.lock().unwrap().push((tool, target));
        match tool {
            ToolName::GetParentProcess => Ok(ToolOutput {
                title: "Parent".into(),
                summary: "Parent is builder.exe (PID 10)".into(),
                data: json!({"name": "builder.exe"}),
                discovered: vec![(ProcessKey { pid: 10, created: 5 }, "parent: builder.exe".into())],
            }),
            ToolName::GetDigitalSignatureStatus => Ok(ToolOutput { title: "Signature".into(), summary: "Signed by Contoso Ltd (valid)".into(), data: json!({"status": "valid"}), discovered: vec![] }),
            _ => Err("Access denied".into()),
        }
    }
}

#[derive(Default)]
struct VecSink {
    steps: Mutex<Vec<StepRecord>>,
    evidence: Mutex<Vec<EvidenceRecord>>,
}

impl Sink for VecSink {
    fn step(&self, s: &StepRecord) {
        self.steps.lock().unwrap().push(s.clone());
    }
    fn evidence(&self, e: &EvidenceRecord) {
        self.evidence.lock().unwrap().push(e.clone());
    }
}

fn subject() -> Subject {
    Subject {
        key: SUBJECT,
        name: "busy.exe".into(),
        rule: RuleKind::SustainedCpu,
        rule_label: "Sustained CPU activity".into(),
        reason: "CPU >= 25% for 12 samples".into(),
        alert_metrics: json!({"cpu_avg": 31.0}),
        alert_details: json!({}),
        synthetic: true,
    }
}

fn plan(reqs: Value, more: bool) -> Result<String, ModelError> {
    Ok(json!({
        "assessment": "High CPU from busy.exe; cause unknown.",
        "hypotheses": [{"explanation": "A build or compile job", "likelihood": "medium", "evidence_ids": ["E1"]}],
        "evidence_gaps": ["Who launched it"],
        "tool_requests": reqs,
        "needs_more_investigation": more
    })
    .to_string())
}

fn report() -> Result<String, ModelError> {
    Ok(json!({
        "finding": "busy.exe was launched by builder.exe and is likely doing build work.",
        "observed_facts": [
            {"statement": "CPU stayed above 25%", "evidence_ids": ["E1"]},
            {"statement": "Launched by builder.exe", "evidence_ids": ["E3"]},
            {"statement": "It is a crypto miner", "evidence_ids": ["E99"]}
        ],
        "explanations": [{"explanation": "Build job", "likelihood": "medium", "supporting": [{"statement": "parent is builder.exe", "evidence_ids": ["E3"]}], "contradicting": []}],
        "unknowns": ["What is being built"],
        "confidence": "moderate",
        "confidence_reason": "Parent fits, purpose unconfirmed",
        "next_steps": ["Check builder.exe's job list"],
        "narration": "Something has been busy in the dark, summoned by a builder. Likely work, not mischief."
    })
    .to_string())
}

fn run(model: Option<&dyn ModelClient>, provider: &FakeProvider, sink: &VecSink, limits: Limits, cancel: &CancellationToken) -> Outcome {
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    rt.block_on(investigate(&subject(), model, provider, sink, &limits, cancel))
}

#[test]
fn model_requests_a_check_receives_the_result_and_reassesses() {
    let model = ScriptedModel::new(vec![
        plan(json!([{"tool": "get_parent_process", "pid": 4242, "reason": "Find who launched it"}]), true),
        plan(json!([]), false),
        report(),
    ]);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let out = run(Some(&model), &provider, &sink, Limits::default(), &CancellationToken::new());

    assert_eq!(out.status, "completed");
    assert!(!out.deterministic);
    assert_eq!(provider.calls.lock().unwrap().as_slice(), &[(ToolName::GetParentProcess, SUBJECT)]);
    // The second planning prompt contains the new evidence (E3) from the tool.
    let prompts = model.prompts.lock().unwrap();
    assert!(prompts[1].contains("[E3]") && prompts[1].contains("builder.exe"));
    assert!(prompts[1].contains("YOUR PREVIOUS ASSESSMENT"));
    // Facts are traceable; the unsupported claim is demoted.
    assert_eq!(out.report.observed_facts.len(), 2);
    assert_eq!(out.report.unlinked_claims.len(), 1);
    assert_eq!(out.report.actions_performed, no_actions());
    let kinds: Vec<String> = sink.steps.lock().unwrap().iter().map(|s| s.kind.clone()).collect();
    assert_eq!(kinds, ["packet", "thinking", "plan", "tool", "thinking", "plan", "note", "thinking", "report"]);
}

#[test]
fn requested_checks_run_and_are_reassessed_even_if_model_says_sufficient() {
    // Small models often request checks while also claiming sufficiency.
    let model = ScriptedModel::new(vec![
        plan(json!([{"tool": "get_digital_signature_status", "pid": 4242, "reason": "is it signed"}]), false),
        plan(json!([]), false),
        report(),
    ]);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let out = run(Some(&model), &provider, &sink, Limits::default(), &CancellationToken::new());
    assert_eq!(provider.calls.lock().unwrap().as_slice(), &[(ToolName::GetDigitalSignatureStatus, SUBJECT)]);
    assert_eq!(sink.steps.lock().unwrap().iter().filter(|s| s.kind == "plan").count(), 2, "new evidence is reassessed");
    assert!(!out.deterministic);
}

#[test]
fn newly_discovered_parent_becomes_inspectable_but_others_do_not() {
    let model = ScriptedModel::new(vec![
        plan(json!([{"tool": "get_parent_process", "pid": 4242, "reason": "who"}]), true),
        plan(json!([
            {"tool": "get_digital_signature_status", "pid": 10, "reason": "is the parent signed"},
            {"tool": "get_process_details", "pid": 4, "reason": "look at System"}
        ]), true),
        plan(json!([]), false),
        report(),
    ]);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    run(Some(&model), &provider, &sink, Limits::default(), &CancellationToken::new());
    let calls = provider.calls.lock().unwrap();
    assert!(calls.contains(&(ToolName::GetDigitalSignatureStatus, ProcessKey { pid: 10, created: 5 })));
    assert!(!calls.iter().any(|(_, k)| k.pid == 4));
    assert!(sink.steps.lock().unwrap().iter().any(|s| s.kind == "tool_rejected"));
}

#[test]
fn invalid_requests_are_rejected_and_never_executed() {
    let model = ScriptedModel::new(vec![
        plan(json!([
            {"tool": "run_shell", "pid": 4242, "reason": "x"},
            {"tool": "get_executable_metadata", "pid": 4242, "path": "C:\\secret.txt", "reason": "x"}
        ]), true),
        report(),
    ]);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let out = run(Some(&model), &provider, &sink, Limits::default(), &CancellationToken::new());
    assert!(provider.calls.lock().unwrap().is_empty());
    assert_eq!(sink.steps.lock().unwrap().iter().filter(|s| s.kind == "tool_rejected").count(), 2);
    assert_eq!(out.status, "completed");
}

#[test]
fn malformed_output_is_retried_then_falls_back_without_executing_anything() {
    let model = ScriptedModel::new(vec![Ok("I think you should run `del C:\\`".into()), Ok("{not json".into())]);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let out = run(Some(&model), &provider, &sink, Limits::default(), &CancellationToken::new());
    assert_eq!(out.status, "completed");
    assert!(out.deterministic);
    assert!(provider.calls.lock().unwrap().is_empty());
    assert!(out.report.observed_facts.iter().all(|f| f.linked));
}

#[test]
fn unavailable_model_runs_standard_checks_and_deterministic_report() {
    let model = ScriptedModel::new(vec![Err(ModelError::Unavailable("connection refused".into()))]);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let out = run(Some(&model), &provider, &sink, Limits::default(), &CancellationToken::new());
    assert!(out.deterministic);
    assert_eq!(provider.calls.lock().unwrap().len(), 4);
    assert_eq!(out.report.confidence, "low");
    // Failed checks (access denied) are recorded as limitations.
    assert!(sink.evidence.lock().unwrap().iter().any(|e| e.summary.contains("limitation")));
}

#[test]
fn no_model_configured_still_produces_evidence_report() {
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let out = run(None, &provider, &sink, Limits::default(), &CancellationToken::new());
    assert!(out.deterministic);
    assert!(!out.report.observed_facts.is_empty());
}

#[test]
fn step_limit_is_enforced() {
    // Each step asks for a fresh (non-duplicate) window, forever.
    let mut script = vec![];
    for m in [5, 6] {
        script.push(plan(json!([{"tool": "get_resource_history", "pid": 4242, "minutes": m, "reason": "x"}]), true));
    }
    script.push(report());
    let model = ScriptedModel::new(script);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let limits = Limits { max_steps: 2, ..Default::default() };
    run(Some(&model), &provider, &sink, limits, &CancellationToken::new());
    assert_eq!(provider.calls.lock().unwrap().len(), 2);
    assert!(sink.steps.lock().unwrap().iter().any(|s| s.title.contains("Step limit")));
}

#[test]
fn cancellation_stops_the_investigation() {
    let mut model = ScriptedModel::new(vec![plan(json!([]), false), report()]);
    model.delay = Duration::from_secs(30);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    let out = rt.block_on(async {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            c2.cancel();
        });
        investigate(&subject(), Some(&model), &provider, &sink, &Limits::default(), &cancel).await
    });
    assert_eq!(out.status, "cancelled");
    assert!(provider.calls.lock().unwrap().is_empty());
}

#[test]
fn time_budget_is_enforced() {
    let mut model = ScriptedModel::new(vec![plan(json!([]), false), report()]);
    model.delay = Duration::from_secs(30);
    let provider = FakeProvider::default();
    let sink = VecSink::default();
    let limits = Limits { time_budget: Duration::from_millis(100), ..Default::default() };
    let out = run(Some(&model), &provider, &sink, limits, &CancellationToken::new());
    assert!(out.deterministic);
    assert!(out.report.notes.iter().any(|n| n.contains("time budget")));
}

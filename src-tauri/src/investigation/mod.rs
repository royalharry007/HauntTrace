//! The investigation orchestrator: a bounded, multi-step evidence loop.
//!
//! detection -> evidence packet -> model plans -> registry validates ->
//! read-only tool runs -> evidence appended -> model reassesses -> ... ->
//! validated report. Stops on sufficiency, no useful checks, step limit,
//! time budget, or cancellation. Without a model, standard checks run and a
//! deterministic evidence report is produced.

pub mod prompt;
pub mod provider;
pub mod schema;
pub mod tools;

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::detection::RuleKind;
use crate::llm::{ModelClient, ModelError};
use crate::store::{EvidenceRecord, StepRecord};
use crate::types::{now_ms, ProcessKey};

use self::prompt::{plan_prompt, report_prompt, PromptState, SYSTEM};
use self::schema::{parse_plan, parse_report, plan_schema, report_schema, sanitize_narration, Plan, Report};
use self::tools::{validate_batch, AuthContext, EvidenceProvider, ToolName, ToolOutput};

/// What is being investigated, built from the stored alert.
#[derive(Debug, Clone)]
pub struct Subject {
    pub key: ProcessKey,
    pub name: String,
    pub rule: RuleKind,
    pub rule_label: String,
    pub reason: String,
    pub alert_metrics: Value,
    pub alert_details: Value,
    pub synthetic: bool,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_steps: u32,
    pub time_budget: Duration,
    pub call_timeout: Duration,
    pub tool_timeout: Duration,
    pub max_evidence_chars: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_steps: 4,
            time_budget: Duration::from_secs(300),
            call_timeout: Duration::from_secs(150),
            tool_timeout: Duration::from_secs(15),
            max_evidence_chars: 9000,
        }
    }
}

/// Receives progress as it happens (persisted + shown in the UI).
pub trait Sink: Send + Sync {
    fn step(&self, step: &StepRecord);
    fn evidence(&self, ev: &EvidenceRecord);
}

#[derive(Debug, Clone)]
pub struct Outcome {
    /// completed | cancelled | failed
    pub status: String,
    pub report: Report,
    pub deterministic: bool,
    pub error: Option<String>,
}

enum Interrupt {
    Cancelled,
    OutOfTime,
}

struct Run<'a> {
    subject: &'a Subject,
    provider: &'a dyn EvidenceProvider,
    sink: &'a dyn Sink,
    limits: &'a Limits,
    cancel: &'a CancellationToken,
    deadline: Instant,
    seq: u32,
    evidence: Vec<EvidenceRecord>,
    auth: AuthContext,
    labels: HashMap<u32, String>,
    executed: Vec<String>,
    rejected: Vec<String>,
    notes: Vec<String>,
}

impl<'a> Run<'a> {
    fn step(&mut self, kind: &str, title: impl Into<String>, payload: Value) {
        let s = StepRecord { seq: self.seq, created_ms: now_ms(), kind: kind.into(), title: title.into(), payload };
        self.seq += 1;
        self.sink.step(&s);
    }

    fn add_evidence(&mut self, source: &str, out: ToolOutput) -> String {
        let id = format!("E{}", self.evidence.len() + 1);
        for (k, label) in &out.discovered {
            if !self.auth.authorized.contains_key(&k.pid) {
                self.labels.insert(k.pid, label.clone());
            }
            self.auth.authorize(*k);
        }
        let rec = EvidenceRecord {
            evidence_id: id.clone(),
            created_ms: now_ms(),
            source: source.into(),
            title: out.title,
            summary: out.summary,
            data: out.data,
            synthetic: self.subject.synthetic,
        };
        self.sink.evidence(&rec);
        self.evidence.push(rec);
        id
    }

    fn remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }

    /// Await a future, honoring cancellation and the overall time budget.
    async fn guard<T>(&self, fut: impl Future<Output = T>) -> Result<T, Interrupt> {
        let remaining = self.remaining();
        if self.cancel.is_cancelled() {
            return Err(Interrupt::Cancelled);
        }
        if remaining.is_zero() {
            return Err(Interrupt::OutOfTime);
        }
        tokio::select! {
            _ = self.cancel.cancelled() => Err(Interrupt::Cancelled),
            _ = tokio::time::sleep(remaining) => Err(Interrupt::OutOfTime),
            r = fut => Ok(r),
        }
    }

    async fn run_tool(&mut self, tool: ToolName, target: ProcessKey, minutes: Option<u32>, reason: &str, by_model: bool) -> Result<(), Interrupt> {
        let spec = tools::spec(tool);
        let timeout = self.limits.tool_timeout;
        let res = self.guard(tokio::time::timeout(timeout, self.provider.run(tool, target, minutes))).await?;
        self.auth.executed.insert((tool, target, minutes));
        let label = match minutes {
            Some(m) => format!("{}(pid {}, {} min)", spec.id, target.pid, m),
            None => format!("{}(pid {})", spec.id, target.pid),
        };
        match res {
            Ok(Ok(out)) => {
                let summary = out.summary.clone();
                let id = self.add_evidence(spec.id, out);
                self.executed.push(format!("{label} -> {id}"));
                self.step(
                    "tool",
                    format!("Checked: {}", spec.id.replace('_', " ")),
                    json!({"tool": spec.id, "pid": target.pid, "minutes": minutes, "reason": reason, "requested_by": if by_model {"model"} else {"standard checks"}, "evidence_id": id, "summary": summary}),
                );
            }
            Ok(Err(e)) => {
                // A failed check is itself evidence (e.g. access denied).
                let out = ToolOutput {
                    title: format!("{} could not complete", spec.id),
                    summary: format!("The check did not return data: {e}. This is a limitation, not evidence of a problem."),
                    data: json!({"error": e}),
                    discovered: vec![],
                };
                let id = self.add_evidence(spec.id, out);
                self.executed.push(format!("{label} -> {id} (failed)"));
                self.step("tool", format!("Check failed: {}", spec.id.replace('_', " ")), json!({"tool": spec.id, "pid": target.pid, "reason": reason, "evidence_id": id, "error": e}));
            }
            Err(_) => {
                let id = self.add_evidence(
                    spec.id,
                    ToolOutput {
                        title: format!("{} timed out", spec.id),
                        summary: format!("The check exceeded its {} s time limit and was abandoned.", timeout.as_secs()),
                        data: json!({"error": "timeout"}),
                        discovered: vec![],
                    },
                );
                self.executed.push(format!("{label} -> {id} (timed out)"));
                self.step("tool", format!("Check timed out: {}", spec.id.replace('_', " ")), json!({"tool": spec.id, "pid": target.pid, "evidence_id": id, "error": "timeout"}));
            }
        }
        Ok(())
    }

    fn prompt_state<'b>(&'b self, last_plan: Option<&'b Plan>, step: u32) -> PromptState<'b> {
        PromptState {
            subject: self.subject,
            evidence: &self.evidence,
            executed: &self.executed,
            rejected: &self.rejected,
            last_plan,
            labels: &self.labels,
            step,
            max_steps: self.limits.max_steps,
            max_chars: self.limits.max_evidence_chars,
        }
    }

    /// Call the model, retrying once with feedback if the output is invalid.
    async fn call_model<T>(
        &mut self,
        model: &dyn ModelClient,
        user: String,
        schema: &Value,
        parse: impl Fn(&str) -> Result<T, String>,
    ) -> Result<Result<T, ModelError>, Interrupt> {
        let mut prompt = user;
        for attempt in 0..2 {
            let t = self.limits.call_timeout.min(self.remaining());
            let res = self.guard(model.generate_json(SYSTEM, &prompt, schema, t)).await?;
            match res {
                Ok(text) => match parse(&text) {
                    Ok(v) => return Ok(Ok(v)),
                    Err(e) => {
                        self.step("note", "The model's answer was malformed and was not used", json!({"error": e, "attempt": attempt + 1}));
                        prompt.push_str(&format!("\n\nYour previous answer was invalid ({e}). Answer again with JSON that matches the schema exactly."));
                    }
                },
                Err(e) => return Ok(Err(e)),
            }
        }
        Ok(Err(ModelError::Other("The model returned malformed output twice".into())))
    }
}

fn initial_detector_evidence(s: &Subject) -> ToolOutput {
    ToolOutput {
        title: format!("Detection rule fired: {}", s.rule_label),
        summary: s.reason.clone(),
        data: json!({"rule": s.rule.as_str(), "metrics_at_alert": s.alert_metrics, "rule_details": s.alert_details}),
        discovered: vec![],
    }
}

/// Run a full investigation.
pub async fn investigate(
    subject: &Subject,
    model: Option<&dyn ModelClient>,
    provider: &dyn EvidenceProvider,
    sink: &dyn Sink,
    limits: &Limits,
    cancel: &CancellationToken,
) -> Outcome {
    let mut run = Run {
        subject,
        provider,
        sink,
        limits,
        cancel,
        deadline: Instant::now() + limits.time_budget,
        seq: 0,
        evidence: Vec::new(),
        auth: AuthContext::new(subject.key),
        labels: HashMap::from([(subject.key.pid, format!("subject: {}", subject.name))]),
        executed: Vec::new(),
        rejected: Vec::new(),
        notes: Vec::new(),
    };

    // 1. Initial evidence packet.
    run.add_evidence("detector", initial_detector_evidence(subject));
    let initial = match run.guard(provider.initial(subject.key)).await {
        Ok(v) => v,
        Err(i) => return finish_interrupted(&mut run, i),
    };
    for out in initial {
        run.add_evidence("collector", out);
    }
    let packet_ids: Vec<&str> = run.evidence.iter().map(|e| e.evidence_id.as_str()).collect();
    run.step("packet", "Initial evidence packet assembled", json!({"evidence_ids": packet_ids, "synthetic": subject.synthetic}));

    let Some(model) = model else {
        run.notes.push("No local model is configured, so only standard checks ran.".into());
        return deterministic_path(&mut run, None).await;
    };

    // 2. Plan / gather / reassess loop.
    let mut last_plan: Option<Plan> = None;
    let mut model_failure: Option<String> = None;
    for step in 1..=limits.max_steps {
        let title = if step == 1 { "Gemma is forming a hypothesis" } else { "Gemma is reassessing with the new evidence" };
        run.step("thinking", title, json!({"step": step, "max_steps": limits.max_steps}));
        let user = plan_prompt(&run.prompt_state(last_plan.as_ref(), step));
        let plan = match run.call_model(model, user, &plan_schema(), parse_plan).await {
            Err(i) => return finish_interrupted(&mut run, i),
            Ok(Err(e)) if e.is_unavailable() && last_plan.is_none() => {
                run.step("error", "The local model is unavailable", json!({"error": e.to_string()}));
                run.notes.push(format!("{e}. Standard checks ran instead."));
                return deterministic_path(&mut run, Some(e.to_string())).await;
            }
            Ok(Err(e)) => {
                run.step("error", "The model could not continue planning", json!({"error": e.to_string()}));
                model_failure = Some(e.to_string());
                break;
            }
            Ok(Ok(p)) => p,
        };

        let (valid, rejected) = validate_batch(&plan.tool_requests, &run.auth);
        run.step(
            "plan",
            if step == 1 { "Initial assessment" } else { "Reassessment" },
            json!({
                "step": step,
                "assessment": plan.assessment,
                "hypotheses": plan.hypotheses,
                "evidence_gaps": plan.evidence_gaps,
                "requested": valid.iter().map(|v| json!({"tool": v.tool_id, "pid": v.pid, "minutes": v.minutes, "reason": v.reason})).collect::<Vec<_>>(),
                "needs_more_investigation": plan.needs_more_investigation,
            }),
        );
        for r in &rejected {
            run.rejected.push(format!("{} -> {}", r.request, r.reason));
            run.step("tool_rejected", "Request rejected by the tool registry", json!({"request": r.request, "reason": r.reason}));
        }
        // Validated requests always run (they are read-only and bounded), and
        // any new evidence is always followed by a reassessment. The loop
        // ends when the model asks for nothing new that is permitted.
        let wants_more = plan.needs_more_investigation;
        last_plan = Some(plan);
        if valid.is_empty() {
            let title = if wants_more { "No new permitted checks remain" } else { "Gemma judged the evidence sufficient" };
            run.step("note", title, json!({}));
            break;
        }
        for v in valid {
            if let Err(i) = run.run_tool(v.tool, v.target, v.minutes, &v.reason, true).await {
                return finish_interrupted(&mut run, i);
            }
        }
        if step == limits.max_steps {
            run.step("note", format!("Step limit reached ({})", limits.max_steps), json!({}));
            run.notes.push(format!("The investigation stopped at the {}-step limit.", limits.max_steps));
        }
    }

    // 3. Final report.
    if model_failure.is_none() {
        run.step("thinking", "Gemma is preparing the report", json!({}));
        let valid_ids: HashSet<String> = run.evidence.iter().map(|e| e.evidence_id.clone()).collect();
        let user = report_prompt(&run.prompt_state(last_plan.as_ref(), limits.max_steps));
        match run.call_model(model, user, &report_schema(), |t| parse_report(t, &valid_ids)).await {
            Err(i) => return finish_interrupted(&mut run, i),
            Ok(Ok(mut report)) => {
                report.generated_by = format!("Local model {} via Ollama", model.model_name());
                if report.narration.is_empty() {
                    report.narration = deterministic_narration(subject.rule, &report.confidence);
                }
                report.notes.splice(0..0, run.notes.drain(..));
                report.actions_performed = no_actions();
                run.step("report", "Report ready", json!({"finding": report.finding, "confidence": report.confidence}));
                return Outcome { status: "completed".into(), report, deterministic: false, error: None };
            }
            Ok(Err(e)) => {
                run.step("error", "The model could not write the report", json!({"error": e.to_string()}));
                model_failure = Some(e.to_string());
            }
        }
    }
    let err = model_failure.unwrap_or_default();
    run.notes.push(format!("The model failed before finishing ({err}); this report lists the collected evidence only."));
    let mut report = deterministic_report(&run, last_plan.as_ref());
    report.generated_by = "HauntTrace deterministic summary (model output unavailable)".into();
    run.step("report", "Evidence report ready (without AI conclusions)", json!({"finding": report.finding}));
    Outcome { status: "completed".into(), report, deterministic: true, error: Some(err) }
}

/// Without a usable model: run the standard read-only checks and build an
/// evidence-only report.
async fn deterministic_path(run: &mut Run<'_>, error: Option<String>) -> Outcome {
    let key = run.subject.key;
    let standard = [
        (ToolName::GetParentProcess, None),
        (ToolName::GetExecutableMetadata, None),
        (ToolName::GetDigitalSignatureStatus, None),
        (ToolName::GetResourceHistory, Some(10)),
    ];
    for (tool, minutes) in standard {
        if let Err(i) = run.run_tool(tool, key, minutes, "Standard check (no AI)", false).await {
            return finish_interrupted(run, i);
        }
    }
    let mut report = deterministic_report(run, None);
    report.generated_by = "HauntTrace standard checks (no AI model used)".into();
    run.step("report", "Evidence report ready (without AI conclusions)", json!({"finding": report.finding}));
    Outcome { status: "completed".into(), report, deterministic: true, error }
}

fn finish_interrupted(run: &mut Run<'_>, i: Interrupt) -> Outcome {
    let (status, note) = match i {
        Interrupt::Cancelled => ("cancelled", "You cancelled the investigation. Evidence gathered so far is kept."),
        Interrupt::OutOfTime => ("completed", "The investigation reached its time budget; this report lists the evidence gathered so far."),
    };
    run.notes.push(note.into());
    run.step(if status == "cancelled" { "note" } else { "error" }, note, json!({}));
    let mut report = deterministic_report(run, None);
    report.generated_by = "HauntTrace deterministic summary".into();
    Outcome { status: status.into(), report, deterministic: true, error: None }
}

pub fn no_actions() -> Vec<String> {
    vec!["No actions were performed. Every check was read-only.".into()]
}

fn confidence_phrase(c: &str) -> &'static str {
    match c {
        "high" => "and the clues point to a clear explanation.",
        "moderate" => "and I have a likely explanation, though not a certain one.",
        _ => "but we haven't established why it's happening yet.",
    }
}

pub fn deterministic_narration(rule: RuleKind, confidence: &str) -> String {
    let opening = match rule {
        RuleKind::SustainedCpu => "Something has been lingering. Its CPU activity stayed unusually high.",
        RuleKind::RepeatedSpikes => "Something keeps stirring. Its CPU activity rose and fell, again and again.",
        RuleKind::MemoryGrowth => "Something keeps growing in the dark. Its memory use has climbed steadily.",
        RuleKind::RepeatedRestarts => "Something keeps returning. A program exited and came back several times.",
        RuleKind::Lingering => "Something has lingered for hours, and it is still busy.",
        RuleKind::Summoned => "You asked me to look at something busy in the house.",
    };
    sanitize_narration(&format!("{opening} I found a few clues, {}", confidence_phrase(confidence))).unwrap_or_else(|| opening.to_string())
}

fn safe_steps(rule: RuleKind) -> Vec<String> {
    let mut v = vec!["Open the process details and confirm you recognize the program and where it is installed.".to_string()];
    match rule {
        RuleKind::SustainedCpu | RuleKind::RepeatedSpikes | RuleKind::Lingering | RuleKind::Summoned => {
            v.push("If it is an app you use, check whether it is doing expected work (a download, build, sync, scan or render).".into());
            v.push("If it is unexpected and keeps running, close it normally from its own window, or end it from HauntTrace after confirming.".into());
        }
        RuleKind::MemoryGrowth => {
            v.push("Restarting the app normally usually releases leaked memory; check for an update if it keeps growing.".into());
        }
        RuleKind::RepeatedRestarts => {
            v.push("A program that keeps restarting is often crashing; check for an update or the app's own logs.".into());
        }
    }
    v.push("If you remain unsure about the program, scan it with your antivirus software.".into());
    v.push("If this behavior is normal for you, exclude the program so HauntTrace stops alerting on it.".into());
    v
}

/// Evidence-only report: every fact is a direct restatement of an evidence
/// summary, with no explanations asserted.
fn deterministic_report(run: &Run<'_>, last_plan: Option<&Plan>) -> Report {
    let s = run.subject;
    let observed_facts = run
        .evidence
        .iter()
        .map(|e| schema::LinkedStatement { statement: e.summary.clone(), evidence_ids: vec![e.evidence_id.clone()], linked: true })
        .collect();
    let explanations = last_plan
        .map(|p| {
            p.hypotheses
                .iter()
                .map(|h| schema::Explanation {
                    explanation: format!("(unconfirmed model hypothesis) {}", h.explanation),
                    likelihood: h.likelihood.clone(),
                    supporting: vec![],
                    contradicting: vec![],
                })
                .collect()
        })
        .unwrap_or_default();
    Report {
        finding: format!("{} triggered \"{}\". The measured evidence is listed below; no AI conclusion was reached, so the cause has not been established.", s.name, s.rule_label),
        observed_facts,
        unlinked_claims: vec![],
        explanations,
        unknowns: vec!["Why the process behaves this way has not been assessed.".into()],
        confidence: "low".into(),
        confidence_reason: "Only raw measurements are available.".into(),
        next_steps: safe_steps(s.rule),
        narration: deterministic_narration(s.rule, "low"),
        actions_performed: no_actions(),
        generated_by: String::new(),
        notes: run.notes.clone(),
    }
}

#[cfg(test)]
mod tests;

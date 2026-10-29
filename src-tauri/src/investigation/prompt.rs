//! Prompt construction. Each model call is stateless and receives a compact,
//! size-bounded evidence packet, so context never grows without limit.

use std::collections::HashMap;
use std::fmt::Write;

use crate::store::EvidenceRecord;

use super::schema::Plan;
use super::tools::REGISTRY;
use super::Subject;

pub const SYSTEM: &str = "You are the investigator inside HauntTrace, a Windows app that notices unusual process activity. \
You explain, calmly and honestly, why a process triggered an activity alert.

Rules you must follow:
1. Use ONLY the evidence given to you. Never invent measurements, file paths, publishers, signatures, versions, timestamps or process names.
2. Cite evidence IDs (E1, E2, ...) for every factual claim.
3. High CPU, long runtime, an unfamiliar name, an unsigned file or an unusual folder are NOT by themselves signs of malware. Browsers, games, compilers, backup tools, indexers, updaters and encoders often behave this way. Never call something malware, a virus or an attack.
4. Missing data or 'access denied' means unknown, not suspicious.
5. You cannot run anything. You may only REQUEST checks from the provided list, for the provided PIDs. The app validates and decides.
6. Request only checks that could change your assessment, and never repeat a check that already ran.
7. Never recommend disabling security software, and never claim that any action was taken.
Answer with JSON only.";

fn evidence_block(evidence: &[EvidenceRecord], max_chars: usize) -> String {
    // Newest evidence is kept in full; if the packet is too large, older
    // evidence data is truncated (summaries are always kept).
    let per_item = (max_chars / evidence.len().max(1)).clamp(300, 1600);
    let mut out = String::new();
    for e in evidence {
        let mut data = e.data.to_string();
        if data.len() > per_item {
            let cut = (0..=per_item).rev().find(|i| data.is_char_boundary(*i)).unwrap_or(0);
            data.truncate(cut);
            data.push_str("…(truncated)");
        }
        let _ = writeln!(out, "[{}] {} (source: {})\nsummary: {}\ndata: {}\n", e.evidence_id, e.title, e.source, e.summary, data);
    }
    out
}

fn tools_block(labels: &HashMap<u32, String>) -> String {
    let mut out = String::from("AVAILABLE READ-ONLY CHECKS:\n");
    for t in REGISTRY {
        let _ = writeln!(out, "- {}: {}", t.id, t.description);
    }
    out.push_str("\nPIDs you may inspect (any other PID will be rejected):\n");
    let mut pids: Vec<_> = labels.iter().collect();
    pids.sort();
    for (pid, label) in pids {
        let _ = writeln!(out, "- {pid}: {label}");
    }
    out
}

pub struct PromptState<'a> {
    pub subject: &'a Subject,
    pub evidence: &'a [EvidenceRecord],
    pub executed: &'a [String],
    pub rejected: &'a [String],
    pub last_plan: Option<&'a Plan>,
    pub labels: &'a HashMap<u32, String>,
    pub step: u32,
    pub max_steps: u32,
    pub max_chars: usize,
}

fn header(s: &PromptState) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "ALERT: {} for {} (PID {}).", s.subject.rule_label, s.subject.name, s.subject.key.pid);
    let _ = writeln!(out, "Why the rule fired: {}\n", s.subject.reason);
    out.push_str("EVIDENCE COLLECTED BY HAUNTTRACE (these are the only facts):\n");
    out.push_str(&evidence_block(s.evidence, s.max_chars));
    if !s.executed.is_empty() {
        let _ = writeln!(out, "CHECKS ALREADY RUN: {}", s.executed.join("; "));
    }
    if !s.rejected.is_empty() {
        let _ = writeln!(out, "REQUESTS THE APP REJECTED: {}", s.rejected.join("; "));
    }
    if let Some(p) = s.last_plan {
        let _ = writeln!(out, "YOUR PREVIOUS ASSESSMENT: {}", p.assessment);
        for h in &p.hypotheses {
            let _ = writeln!(out, "- previous hypothesis ({}): {}", h.likelihood, h.explanation);
        }
    }
    out
}

pub fn plan_prompt(s: &PromptState) -> String {
    let mut out = header(s);
    out.push('\n');
    out.push_str(&tools_block(s.labels));
    let _ = write!(
        out,
        "\nSTEP {} OF {}. {}\nTask: assess the evidence. Give 1-3 hypotheses with likelihood and the evidence IDs behind them, list the evidence gaps, \
and request at most 2 checks (tool + pid, plus minutes where the tool accepts it, plus a one-sentence reason) that would best confirm or rule out a hypothesis. \
{}Set needs_more_investigation to false when the evidence is sufficient or no listed check would help.",
        s.step,
        s.max_steps,
        if s.step == 1 { "Form your first hypotheses." } else { "Reassess your previous hypotheses in light of the new evidence: say what changed." },
        if s.step == 1 { "At this first step you should normally request at least one check. " } else { "" }
    );
    out
}

pub fn report_prompt(s: &PromptState) -> String {
    let mut out = header(s);
    out.push_str(
        "\nTask: write the final investigation report.\n\
- finding: one or two plain-language sentences on what was observed and the most plausible explanation, with honest uncertainty.\n\
- observed_facts: statements that restate ONLY what the evidence shows, each with the evidence IDs it comes from.\n\
- explanations: 1-3 plausible explanations, each with supporting and contradicting evidence (statements with evidence IDs). Contradicting may be empty.\n\
- unknowns: what could not be determined, including access limits.\n\
- confidence: low, moderate or high, with a short reason. Use high only if several independent facts agree.\n\
- next_steps: safe, practical things the user could do (e.g. check the app's own settings, wait for it to finish, update it, scan with their antivirus if still worried). No destructive or security-weakening steps.\n\
- narration: at most 30 words, spoken by a calm, slightly eerie ghost companion, summarizing the actual finding. No file paths, no numbers longer than 3 digits, no accusations.",
    );
    out
}

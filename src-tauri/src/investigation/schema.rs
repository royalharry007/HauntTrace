//! Structured model output: JSON schemas sent to the model (constrained
//! decoding) and strict parsing/validation of what comes back. Model output
//! is data, never instructions or authorization.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::tools::tool_ids;

/// String with a length cap. Ollama compiles `maxLength`/`maxItems` into the
/// decoding grammar, so a small model cannot loop inside a string forever.
fn text(max: u32) -> Value {
    json!({"type": "string", "maxLength": max})
}

fn list(items: Value, max: u32) -> Value {
    json!({"type": "array", "items": items, "maxItems": max})
}

fn evidence_ids() -> Value {
    list(json!({"type": "string", "maxLength": 4}), 6)
}

pub fn plan_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "assessment": text(500),
            "hypotheses": list(json!({"type": "object", "properties": {
                "explanation": text(300),
                "likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
                "evidence_ids": evidence_ids()
            }, "required": ["explanation", "likelihood", "evidence_ids"]}), 3),
            "evidence_gaps": list(text(200), 4),
            "tool_requests": list(json!({"type": "object", "properties": {
                "tool": {"type": "string", "enum": tool_ids()},
                "pid": {"type": "integer"},
                "minutes": {"type": "integer"},
                "reason": text(250)
            }, "required": ["tool", "pid", "reason"]}), 3),
            "needs_more_investigation": {"type": "boolean"}
        },
        "required": ["assessment", "hypotheses", "evidence_gaps", "tool_requests", "needs_more_investigation"]
    })
}

pub fn report_schema() -> Value {
    let linked = json!({"type": "object", "properties": {
        "statement": text(350),
        "evidence_ids": evidence_ids()
    }, "required": ["statement", "evidence_ids"]});
    json!({
        "type": "object",
        "properties": {
            "finding": text(500),
            "observed_facts": list(linked.clone(), 8),
            "explanations": list(json!({"type": "object", "properties": {
                "explanation": text(350),
                "likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
                "supporting": list(linked.clone(), 4),
                "contradicting": list(linked, 4)
            }, "required": ["explanation", "likelihood", "supporting", "contradicting"]}), 3),
            "unknowns": list(text(250), 5),
            "confidence": {"type": "string", "enum": ["low", "moderate", "high"]},
            "confidence_reason": text(300),
            "next_steps": list(text(250), 5),
            "narration": text(220)
        },
        "required": ["finding", "observed_facts", "explanations", "unknowns", "confidence", "confidence_reason", "next_steps", "narration"]
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Hypothesis {
    pub explanation: String,
    pub likelihood: String,
    #[serde(default)]
    pub evidence_ids: Vec<String>,
}

/// A parsed plan. `tool_requests` stay raw JSON so each one can be validated
/// (and rejected) individually by the tool registry.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Plan {
    pub assessment: String,
    pub hypotheses: Vec<Hypothesis>,
    pub evidence_gaps: Vec<String>,
    pub tool_requests: Vec<Value>,
    pub needs_more_investigation: bool,
}

fn clip(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= n {
        t.to_string()
    } else {
        let mut out: String = t.chars().take(n).collect();
        out.push('…');
        out
    }
}

fn str_list(v: &Value, max: usize, len: usize) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| clip(s, len)).filter(|s| !s.is_empty()).take(max).collect())
        .unwrap_or_default()
}

fn likelihood(v: &Value) -> String {
    match v.as_str() {
        Some(s @ ("low" | "medium" | "high")) => s.to_string(),
        _ => "low".to_string(),
    }
}

/// Strip a markdown code fence if a model wrapped its JSON in one.
fn extract_json(text: &str) -> &str {
    let t = text.trim();
    if let (Some(s), Some(e)) = (t.find('{'), t.rfind('}')) {
        if s < e {
            return &t[s..=e];
        }
    }
    t
}

pub fn parse_plan(text: &str) -> Result<Plan, String> {
    let v: Value = serde_json::from_str(extract_json(text)).map_err(|e| format!("not valid JSON ({e})"))?;
    let o = v.as_object().ok_or("plan is not a JSON object")?;
    let assessment = o.get("assessment").and_then(|x| x.as_str()).ok_or("missing 'assessment'")?;
    let needs = o.get("needs_more_investigation").and_then(|x| x.as_bool()).ok_or("missing 'needs_more_investigation'")?;
    let reqs = match o.get("tool_requests") {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Null) | None => vec![],
        Some(_) => return Err("'tool_requests' must be an array".into()),
    };
    let hypotheses = o
        .get("hypotheses")
        .and_then(|h| h.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|h| {
                    let e = h.get("explanation")?.as_str()?;
                    Some(Hypothesis { explanation: clip(e, 300), likelihood: likelihood(&h["likelihood"]), evidence_ids: str_list(&h["evidence_ids"], 10, 12) })
                })
                .take(5)
                .collect()
        })
        .unwrap_or_default();
    Ok(Plan {
        assessment: clip(assessment, 500),
        hypotheses,
        evidence_gaps: str_list(o.get("evidence_gaps").unwrap_or(&Value::Null), 6, 200),
        tool_requests: reqs.into_iter().take(6).collect(),
        needs_more_investigation: needs,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LinkedStatement {
    pub statement: String,
    pub evidence_ids: Vec<String>,
    /// True when at least one cited evidence ID exists in this investigation.
    pub linked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Explanation {
    pub explanation: String,
    pub likelihood: String,
    pub supporting: Vec<LinkedStatement>,
    pub contradicting: Vec<LinkedStatement>,
}

/// The validated report shown to the user and stored in history.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub finding: String,
    /// Facts whose evidence references were verified.
    pub observed_facts: Vec<LinkedStatement>,
    /// Statements the model presented as facts without valid evidence links.
    /// Shown as unverified claims, never as facts.
    pub unlinked_claims: Vec<LinkedStatement>,
    pub explanations: Vec<Explanation>,
    pub unknowns: Vec<String>,
    pub confidence: String,
    pub confidence_reason: String,
    pub next_steps: Vec<String>,
    pub narration: String,
    /// Set by the application, never by the model.
    pub actions_performed: Vec<String>,
    /// Set by the application: notes about how the report was produced.
    pub generated_by: String,
    pub notes: Vec<String>,
}

fn linked_list(v: &Value, valid: &HashSet<String>, max: usize) -> Vec<LinkedStatement> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    let st = x.get("statement")?.as_str()?;
                    if st.trim().is_empty() {
                        return None;
                    }
                    let ids: Vec<String> = str_list(&x["evidence_ids"], 10, 12).into_iter().map(|s| s.trim().to_uppercase()).collect();
                    let good: Vec<String> = ids.iter().filter(|i| valid.contains(*i)).cloned().collect();
                    Some(LinkedStatement { statement: clip(st, 400), linked: !good.is_empty(), evidence_ids: good })
                })
                .take(max)
                .collect()
        })
        .unwrap_or_default()
}

const ALARMIST: &[&str] = &["malware", "virus", "trojan", "ransomware", "spyware", "infected", "hacker", "hacked", "miner", "backdoor", "keylogger"];

pub fn contains_alarmist(s: &str) -> bool {
    let l = s.to_lowercase();
    ALARMIST.iter().any(|w| l.contains(w))
}

/// Next steps that would weaken the user's security or take consequential
/// action automatically are dropped.
fn unsafe_step(s: &str) -> bool {
    let l = s.to_lowercase();
    let disable_security = (l.contains("disable") || l.contains("turn off") || l.contains("uninstall"))
        && (l.contains("antivirus") || l.contains("defender") || l.contains("firewall") || l.contains("security"));
    disable_security || l.contains("regedit") || l.contains("format your") || l.contains("delete system")
}

/// Sanitize narration text: short, one line, no paths or long numbers, and
/// no alarmist claims. Returns None if unusable.
pub fn sanitize_narration(s: &str) -> Option<String> {
    let one_line: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.is_empty() || contains_alarmist(&one_line) {
        return None;
    }
    let cleaned: Vec<&str> = one_line.split(' ').filter(|w| !(w.contains('\\') || w.contains(":/") || w.contains(".exe") || w.chars().filter(|c| c.is_ascii_digit()).count() > 5)).collect();
    let text = cleaned.join(" ");
    let text = clip(&text, 240);
    if text.len() < 12 {
        None
    } else {
        Some(text)
    }
}

/// Parse and validate the final report against the known evidence IDs.
pub fn parse_report(text: &str, valid_ids: &HashSet<String>) -> Result<Report, String> {
    let v: Value = serde_json::from_str(extract_json(text)).map_err(|e| format!("not valid JSON ({e})"))?;
    let o = v.as_object().ok_or("report is not a JSON object")?;
    let finding = o.get("finding").and_then(|x| x.as_str()).filter(|s| !s.trim().is_empty()).ok_or("missing 'finding'")?;
    let all_facts = linked_list(o.get("observed_facts").unwrap_or(&Value::Null), valid_ids, 10);
    let (observed_facts, unlinked_claims): (Vec<_>, Vec<_>) = all_facts.into_iter().partition(|f| f.linked);
    let explanations: Vec<Explanation> = o
        .get("explanations")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| {
                    Some(Explanation {
                        explanation: clip(e.get("explanation")?.as_str()?, 400),
                        likelihood: likelihood(&e["likelihood"]),
                        supporting: linked_list(&e["supporting"], valid_ids, 6),
                        contradicting: linked_list(&e["contradicting"], valid_ids, 6),
                    })
                })
                .take(5)
                .collect()
        })
        .unwrap_or_default();
    let mut confidence = match o.get("confidence").and_then(|x| x.as_str()) {
        Some(c @ ("low" | "moderate" | "high")) => c.to_string(),
        _ => "low".to_string(),
    };
    let mut notes = Vec::new();
    // Calibration guard: "high" confidence needs several evidence-linked facts.
    if confidence == "high" && observed_facts.len() < 3 {
        confidence = "moderate".into();
        notes.push("Confidence lowered from high: fewer than three facts were linked to evidence.".into());
    }
    if !unlinked_claims.is_empty() {
        notes.push(format!("{} statement(s) were not linked to collected evidence and are shown as unverified claims.", unlinked_claims.len()));
    }
    let raw_steps = str_list(o.get("next_steps").unwrap_or(&Value::Null), 8, 300);
    let next_steps: Vec<String> = raw_steps.iter().filter(|s| !unsafe_step(s)).cloned().collect();
    if next_steps.len() < raw_steps.len() {
        notes.push("A suggested step that could weaken system security was removed.".into());
    }
    let narration = o.get("narration").and_then(|x| x.as_str()).and_then(sanitize_narration).unwrap_or_default();
    Ok(Report {
        finding: clip(finding, 500),
        observed_facts,
        unlinked_claims,
        explanations,
        unknowns: str_list(o.get("unknowns").unwrap_or(&Value::Null), 8, 300),
        confidence,
        confidence_reason: clip(o.get("confidence_reason").and_then(|x| x.as_str()).unwrap_or(""), 400),
        next_steps,
        narration,
        actions_performed: vec![],
        generated_by: String::new(),
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> HashSet<String> {
        ["E1", "E2", "E3"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn malformed_output_is_an_error_not_a_panic() {
        for bad in ["", "not json", "{", "[]", "{\"assessment\": 3}", "null", "{\"tool_requests\": \"rm -rf\"}"] {
            assert!(parse_plan(bad).is_err(), "{bad}");
        }
        assert!(parse_report("{\"finding\": \"\"}", &ids()).is_err());
        assert!(parse_report("garbage", &ids()).is_err());
    }

    #[test]
    fn plan_parses_and_tolerates_code_fences() {
        let p = parse_plan("```json\n{\"assessment\":\"busy\",\"hypotheses\":[{\"explanation\":\"build\",\"likelihood\":\"certain\",\"evidence_ids\":[\"E1\"]}],\"evidence_gaps\":[],\"tool_requests\":[{\"tool\":\"get_parent_process\",\"pid\":5,\"reason\":\"who\"}],\"needs_more_investigation\":true}\n```").unwrap();
        assert_eq!(p.tool_requests.len(), 1);
        assert_eq!(p.hypotheses[0].likelihood, "low", "unknown likelihood values are not trusted");
    }

    #[test]
    fn facts_without_valid_evidence_become_unlinked_claims() {
        let r = parse_report(
            r#"{"finding":"f","observed_facts":[
                {"statement":"CPU was 30%","evidence_ids":["E1"]},
                {"statement":"Signed by Contoso","evidence_ids":["E9"]},
                {"statement":"It is a game","evidence_ids":[]}],
              "explanations":[{"explanation":"x","likelihood":"medium","supporting":[{"statement":"s","evidence_ids":["e2"]}],"contradicting":[]}],
              "unknowns":[],"confidence":"high","confidence_reason":"r","next_steps":["Disable Windows Defender","Check the app's settings"],"narration":"Something lingers at C:\\x\\y.exe in the dark."}"#,
            &ids(),
        )
        .unwrap();
        assert_eq!(r.observed_facts.len(), 1);
        assert_eq!(r.unlinked_claims.len(), 2);
        assert!(r.explanations[0].supporting[0].linked, "ids are normalized to upper case");
        assert_eq!(r.confidence, "moderate", "high confidence needs more linked facts");
        assert_eq!(r.next_steps, vec!["Check the app's settings".to_string()]);
        assert!(!r.narration.contains('\\'));
        assert!(r.actions_performed.is_empty(), "the model cannot claim actions");
    }

    #[test]
    fn alarmist_narration_is_rejected() {
        assert!(sanitize_narration("This is definitely malware stealing your files!").is_none());
        assert!(sanitize_narration("Something has been lingering, but I found no cause yet.").is_some());
    }
}

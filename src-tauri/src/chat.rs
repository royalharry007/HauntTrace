//! "Talk to the ghost": short, grounded conversation with the local model.
//! The ghost answers only from what HauntTrace recorded about one haunting
//! (alert, report, evidence summaries). It has no tools and cannot act; the
//! reply is plain text shown in the UI and, if a voice is set, spoken.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::llm::{ModelClient, ModelError};
use crate::store::{AlertRecord, InvestigationDetail};

pub const MAX_QUESTION: usize = 500;
const MAX_TURNS: usize = 8;
const MAX_TURN_CHARS: usize = 600;
const MAX_REPLY: usize = 700;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatTurn {
    /// "you" or "ghost"
    pub role: String,
    pub text: String,
}

const SYSTEM: &str = "You are the friendly ghost inside HauntTrace, a local Windows app that watches process activity. \
Speak in first person, warm and a little spooky, but stay factual and plain. Keep answers short: one to four sentences. \
Use ONLY the case notes provided. If the notes do not answer the question, say you don't know and suggest pressing Investigate or opening the case file. \
Never call a program malware or a virus because it is unfamiliar or busy; high CPU or memory alone proves nothing. \
You cannot end, delete, block or change anything, and you never ask the user to disable security software. \
If asked to take an action, explain which button in the app the user can press (Snooze, Trust, Open file location, End process). \
Never invent file paths, publishers, network activity or numbers that are not in the notes. \
Reply as JSON: {\"reply\": \"...\"}.";

fn clip(s: &str, n: usize) -> String {
    let t: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() <= n {
        t
    } else {
        let mut out: String = t.chars().take(n).collect();
        out.push('…');
        out
    }
}

/// Plain-text case notes for one haunting. Only data HauntTrace already
/// stored is included.
pub fn case_notes(alert: Option<&AlertRecord>, inv: Option<&InvestigationDetail>, process_count: usize, monitoring: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!("Monitoring is {}. Processes currently tracked: {process_count}.\n", if monitoring { "on" } else { "paused" }));
    let Some(a) = alert else {
        out.push_str("No specific haunting is selected. Talk generally about what HauntTrace does if asked.\n");
        return out;
    };
    out.push_str(&format!(
        "\nHAUNTING\nProcess: {} (PID {})\nRule: {} ({} priority)\nWhy it was noticed: {}\nMeasurements at alert: {}\nStatus: {}\n",
        a.process_name,
        a.pid,
        a.rule_label,
        a.priority,
        a.reason,
        clip(&a.metrics.to_string(), 400),
        a.status
    ));
    if let Some(d) = inv {
        if let Some(r) = d.investigation.report.as_ref() {
            out.push_str("\nINVESTIGATION REPORT\n");
            if let Some(f) = r["finding"].as_str() {
                out.push_str(&format!("Finding: {}\n", clip(f, 500)));
            }
            if let Some(c) = r["confidence"].as_str() {
                out.push_str(&format!("Confidence: {c}\n"));
            }
            for f in r["observed_facts"].as_array().into_iter().flatten().take(10) {
                if let Some(s) = f["statement"].as_str() {
                    out.push_str(&format!("- Fact: {}\n", clip(s, 240)));
                }
            }
            for e in r["explanations"].as_array().into_iter().flatten().take(4) {
                if let Some(s) = e["explanation"].as_str() {
                    out.push_str(&format!("- Possible explanation ({}): {}\n", e["likelihood"].as_str().unwrap_or("?"), clip(s, 240)));
                }
            }
            for u in r["unknowns"].as_array().into_iter().flatten().take(5) {
                if let Some(s) = u.as_str() {
                    out.push_str(&format!("- Unknown: {}\n", clip(s, 200)));
                }
            }
            for n in r["next_steps"].as_array().into_iter().flatten().take(5) {
                if let Some(s) = n.as_str() {
                    out.push_str(&format!("- Suggested next step: {}\n", clip(s, 200)));
                }
            }
        } else {
            out.push_str(&format!("\nAn investigation is {}.\n", d.investigation.status));
        }
        if !d.evidence.is_empty() {
            out.push_str("\nEVIDENCE\n");
            for e in d.evidence.iter().take(12) {
                out.push_str(&format!("{}: {} — {}\n", e.evidence_id, e.title, clip(&e.summary, 240)));
            }
        }
    } else {
        out.push_str("\nNot investigated yet.\n");
    }
    out
}

pub fn build_user_message(notes: &str, history: &[ChatTurn], question: &str) -> String {
    let mut msg = format!("CASE NOTES\n{notes}\n");
    let recent: Vec<&ChatTurn> = history.iter().rev().take(MAX_TURNS).collect::<Vec<_>>().into_iter().rev().collect();
    if !recent.is_empty() {
        msg.push_str("\nCONVERSATION SO FAR\n");
        for t in recent {
            let who = if t.role == "ghost" { "Ghost" } else { "User" };
            msg.push_str(&format!("{who}: {}\n", clip(&t.text, MAX_TURN_CHARS)));
        }
    }
    msg.push_str(&format!("\nUser asks: {}\n", clip(question, MAX_QUESTION)));
    msg
}

pub fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {"reply": {"type": "string", "maxLength": MAX_REPLY}},
        "required": ["reply"]
    })
}

pub fn parse_reply(raw: &str) -> Result<String, String> {
    let start = raw.find('{').ok_or("The ghost mumbled something unreadable.")?;
    let end = raw.rfind('}').ok_or("The ghost mumbled something unreadable.")?;
    let v: Value = serde_json::from_str(&raw[start..=end]).map_err(|_| "The ghost mumbled something unreadable.")?;
    let r = v["reply"].as_str().map(|s| clip(s, MAX_REPLY)).unwrap_or_default();
    if r.is_empty() {
        return Err("The ghost had nothing to say.".into());
    }
    Ok(r)
}

pub fn validate_question(q: &str) -> Result<String, String> {
    let q = q.trim();
    if q.is_empty() {
        return Err("Ask the ghost something first.".into());
    }
    if q.chars().count() > MAX_QUESTION {
        return Err(format!("Please keep questions under {MAX_QUESTION} characters."));
    }
    Ok(q.to_string())
}

pub async fn ask(model: &dyn ModelClient, notes: &str, history: &[ChatTurn], question: &str) -> Result<String, ModelError> {
    let user = build_user_message(notes, history, question);
    let raw = model.generate_json(SYSTEM, &user, &schema(), Duration::from_secs(90)).await?;
    parse_reply(&raw).map_err(ModelError::Other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct Echo(Mutex<String>);
    #[async_trait]
    impl ModelClient for Echo {
        fn model_name(&self) -> String {
            "echo".into()
        }
        async fn generate_json(&self, _s: &str, user: &str, _schema: &Value, _t: Duration) -> Result<String, ModelError> {
            *self.0.lock().unwrap() = user.to_string();
            Ok("```json\n{\"reply\": \"  I saw   it too.  \"}\n```".into())
        }
    }

    #[test]
    fn parses_and_normalizes_replies() {
        assert_eq!(parse_reply("{\"reply\":\"Boo.\"}").unwrap(), "Boo.");
        assert!(parse_reply("{\"reply\":\"   \"}").is_err());
        assert!(parse_reply("no json").is_err());
        let long = format!("{{\"reply\":\"{}\"}}", "a".repeat(2000));
        assert!(parse_reply(&long).unwrap().chars().count() <= MAX_REPLY + 1);
    }

    #[test]
    fn validates_questions() {
        assert!(validate_question("   ").is_err());
        assert!(validate_question(&"x".repeat(MAX_QUESTION + 1)).is_err());
        assert_eq!(validate_question("  why? ").unwrap(), "why?");
    }

    #[test]
    fn history_is_bounded_and_notes_included() {
        let history: Vec<ChatTurn> = (0..20).map(|i| ChatTurn { role: if i % 2 == 0 { "you".into() } else { "ghost".into() }, text: format!("turn {i}") }).collect();
        let msg = build_user_message("NOTES-HERE", &history, "what now?");
        assert!(msg.contains("NOTES-HERE"));
        assert!(msg.contains("turn 19") && msg.contains("turn 12"));
        assert!(!msg.contains("turn 11"));
        assert!(msg.ends_with("User asks: what now?\n"));
    }

    #[test]
    fn notes_without_alert_are_general() {
        let n = case_notes(None, None, 212, true);
        assert!(n.contains("212") && n.contains("No specific haunting"));
    }

    #[tokio::test]
    async fn ask_round_trip() {
        let m = Echo(Mutex::new(String::new()));
        let r = ask(&m, "notes", &[], "hello").await.unwrap();
        assert_eq!(r, "I saw it too.");
        assert!(m.0.lock().unwrap().contains("User asks: hello"));
    }
}

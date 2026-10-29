//! End-to-end check on REAL data, without the UI:
//!   real controlled test process -> real Win32 collector -> deterministic
//!   rule -> evidence packet -> local Gemma plans -> registry validates ->
//!   real read-only tools -> Gemma reassesses -> validated report.
//!
//!   cargo run --example live_demo -- [model]      (default gemma4:e2b-it-qat)
//!
//! Requires Ollama running locally and the burner built (npm run build:burner).
//! Exits non-zero if any stage of the loop did not happen.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use haunttrace_lib::collector::tracker::{Tracker, TrackerConfig};
use haunttrace_lib::collector::windows::WinProcessSource;
use haunttrace_lib::collector::ProcessSource;
use haunttrace_lib::detection::{Detector, RuleKind};
use haunttrace_lib::investigation::provider::LiveProvider;
use haunttrace_lib::investigation::{investigate, Limits, Sink, Subject};
use haunttrace_lib::llm::{ModelClient, OllamaClient};
use haunttrace_lib::settings::Settings;
use haunttrace_lib::store::{EvidenceRecord, StepRecord};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct PrintSink {
    steps: Mutex<Vec<StepRecord>>,
}

impl Sink for PrintSink {
    fn step(&self, s: &StepRecord) {
        println!("  [step {:>2}] {:<14} {}", s.seq, s.kind, s.title);
        match s.kind.as_str() {
            "plan" => {
                println!("             assessment: {}", s.payload["assessment"].as_str().unwrap_or(""));
                for h in s.payload["hypotheses"].as_array().cloned().unwrap_or_default() {
                    println!("             hypothesis ({}): {} {:?}", h["likelihood"].as_str().unwrap_or(""), h["explanation"].as_str().unwrap_or(""), h["evidence_ids"]);
                }
                for r in s.payload["requested"].as_array().cloned().unwrap_or_default() {
                    println!("             -> requests {}(pid {}) because: {}", r["tool"].as_str().unwrap_or(""), r["pid"], r["reason"].as_str().unwrap_or(""));
                }
            }
            "tool" | "tool_rejected" | "error" | "note" => println!("             {}", s.payload),
            _ => {}
        }
        self.steps.lock().unwrap().push(s.clone());
    }
    fn evidence(&self, e: &EvidenceRecord) {
        println!("  [{}] {} -- {}", e.evidence_id, e.title, e.summary);
    }
}

#[tokio::main]
async fn main() {
    let model_name = std::env::args().nth(1).unwrap_or_else(|| "gemma4:e2b-it-qat".into());
    let burner = std::env::current_exe().unwrap().parent().unwrap().parent().unwrap().join("haunt-burner.exe");
    assert!(burner.is_file(), "build the burner first: npm run build:burner ({})", burner.display());

    println!("== 1. Launching the controlled test process (real CPU load)");
    let mut child = std::process::Command::new(&burner).args(["--mode", "cpu", "--seconds", "300"]).spawn().expect("spawn burner");
    println!("   haunt-burner.exe PID {}", child.id());

    let mut settings = Settings::default();
    settings.rules.sustained_cpu.consecutive_samples = 5; // 2 s interval -> ~10 s
    settings.model.model = model_name.clone();
    let tracker = Arc::new(Mutex::new(Tracker::new(TrackerConfig::default())));
    let mut source = WinProcessSource::new();
    let mut detector = Detector::new();
    let own = std::process::id();

    println!("== 2. Monitoring with the real Win32 collector (2 s interval)");
    let started = Instant::now();
    let detection = loop {
        let snap = source.snapshot().expect("snapshot");
        let mut t = tracker.lock().unwrap();
        t.ingest(&snap, &mut |r| source.image_path(r.pid, r.created));
        let dets = detector.evaluate(&t, &settings.rules, snap.wall_ms, &|p| p.key.pid == own || settings.is_excluded(&p.name, p.exe_path.as_deref()));
        drop(t);
        if let Some(d) = dets.into_iter().find(|d| d.key.pid == child.id() && d.rule == RuleKind::SustainedCpu) {
            break d;
        }
        assert!(started.elapsed() < Duration::from_secs(90), "the rule did not fire for the burner");
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    println!("   RULE FIRED after {:.0} s: {} -- {}", started.elapsed().as_secs_f32(), detection.rule.label(), detection.reason);
    assert!(!detection.synthetic, "real collector data must not be marked synthetic");

    // Keep sampling in the background so history tools have fresh data.
    let t2 = tracker.clone();
    let sampler = tokio::spawn(async move {
        let mut src = WinProcessSource::new();
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok(s) = src.snapshot() {
                t2.lock().unwrap().ingest(&s, &mut |r| src.image_path(r.pid, r.created));
            }
        }
    });

    println!("== 3. Investigating with local model {model_name}");
    let subject = Subject {
        key: detection.key,
        name: detection.name.clone(),
        rule: detection.rule,
        rule_label: detection.rule.label().into(),
        reason: detection.reason.clone(),
        alert_metrics: serde_json::to_value(&detection.metrics).unwrap(),
        alert_details: detection.details.clone(),
        synthetic: detection.synthetic,
    };
    let model = OllamaClient::new(&settings.model).unwrap();
    let provider = LiveProvider { tracker: tracker.clone() };
    let sink = PrintSink::default();
    let t0 = Instant::now();
    let out = investigate(&subject, Some(&model as &dyn ModelClient), &provider, &sink, &Limits::default(), &CancellationToken::new()).await;
    sampler.abort();
    let _ = child.kill();

    println!("== 4. Report ({:.0} s, status {}, deterministic {})", t0.elapsed().as_secs_f32(), out.status, out.deterministic);
    println!("{}", serde_json::to_string_pretty(&out.report).unwrap());

    let steps = sink.steps.lock().unwrap();
    let model_tools = steps.iter().filter(|s| s.kind == "tool" && s.payload["requested_by"] == "model").count();
    let plans = steps.iter().filter(|s| s.kind == "plan").count();
    println!("== Summary: {} plan step(s), {} model-requested check(s) executed, {} rejected", plans, model_tools, steps.iter().filter(|s| s.kind == "tool_rejected").count());
    let ok = !out.deterministic && model_tools >= 1 && plans >= 2;
    if !ok {
        eprintln!("FAILED: expected a model-requested check followed by a reassessment and an AI report");
        std::process::exit(1);
    }
    println!("PASSED: Gemma requested a permitted check, received the real result, reassessed, and reported.");
}

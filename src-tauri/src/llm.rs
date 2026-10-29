//! Local model adapter. The investigation engine talks to a `ModelClient`;
//! the production implementation is Ollama on a loopback address. Nothing in
//! here executes tools: the model only returns JSON that the engine parses,
//! validates and independently authorizes.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use serde_json::{json, Value};

use crate::settings::{is_loopback_endpoint, ModelSettings};

#[derive(Debug, Clone, PartialEq)]
pub enum ModelError {
    /// The runtime is not reachable (not installed / not running).
    Unavailable(String),
    /// The runtime is up but the configured model is not downloaded.
    ModelMissing(String),
    Timeout,
    Cancelled,
    Other(String),
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::Unavailable(s) => write!(f, "Local model runtime unavailable: {s}"),
            ModelError::ModelMissing(m) => write!(f, "Model '{m}' is not downloaded in Ollama"),
            ModelError::Timeout => write!(f, "The model did not answer within the time limit"),
            ModelError::Cancelled => write!(f, "Cancelled"),
            ModelError::Other(s) => write!(f, "{s}"),
        }
    }
}

impl ModelError {
    /// Errors that mean "no model at all", which triggers the deterministic
    /// fallback instead of retrying.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, ModelError::Unavailable(_) | ModelError::ModelMissing(_))
    }
}

#[async_trait]
pub trait ModelClient: Send + Sync {
    fn model_name(&self) -> String;
    /// Generate a JSON document constrained by `schema`. Returns raw text;
    /// the caller parses and validates it.
    async fn generate_json(&self, system: &str, user: &str, schema: &Value, timeout: Duration) -> Result<String, ModelError>;
}

pub struct OllamaClient {
    http: reqwest::Client,
    endpoint: String,
    model: String,
    keep_alive_minutes: u32,
}

impl OllamaClient {
    pub fn new(cfg: &ModelSettings) -> Result<Self, String> {
        if !is_loopback_endpoint(&cfg.endpoint) {
            return Err("Refusing a non-local model endpoint.".into());
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            // Never route local model traffic through a system proxy.
            .no_proxy()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { http, endpoint: cfg.endpoint.clone(), model: cfg.model.clone(), keep_alive_minutes: cfg.keep_alive_minutes })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.endpoint, path)
    }
}

fn map_send_err(e: reqwest::Error) -> ModelError {
    if e.is_timeout() {
        ModelError::Timeout
    } else if e.is_connect() {
        ModelError::Unavailable("Ollama is not reachable. Is it installed and running?".into())
    } else {
        ModelError::Other(format!("request failed: {e}"))
    }
}

#[async_trait]
impl ModelClient for OllamaClient {
    fn model_name(&self) -> String {
        self.model.clone()
    }

    async fn generate_json(&self, system: &str, user: &str, schema: &Value, timeout: Duration) -> Result<String, ModelError> {
        let body = json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "stream": false,
            "format": schema,
            "options": {"temperature": 0.2, "num_ctx": 8192, "num_predict": 2048},
            "keep_alive": format!("{}m", self.keep_alive_minutes),
        });
        let resp = self.http.post(self.url("/api/chat")).timeout(timeout).json(&body).send().await.map_err(map_send_err)?;
        let status = resp.status();
        let v: Value = resp.json().await.map_err(map_send_err)?;
        if !status.is_success() {
            let msg = v.get("error").and_then(|e| e.as_str()).unwrap_or("unknown error").to_string();
            if status.as_u16() == 404 || msg.contains("not found") {
                return Err(ModelError::ModelMissing(self.model.clone()));
            }
            return Err(ModelError::Other(format!("Ollama returned {status}: {msg}")));
        }
        v.pointer("/message/content")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| ModelError::Other("Ollama response had no message content".into()))
    }
}

// ---------------- Diagnostics & setup ----------------

#[derive(Debug, Clone, Serialize, Default)]
pub struct InstalledModel {
    pub name: String,
    pub size_bytes: u64,
    pub parameter_size: Option<String>,
    pub quantization: Option<String>,
    pub family: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ModelDiagnostics {
    pub endpoint: String,
    pub runtime_reachable: bool,
    pub runtime_version: Option<String>,
    pub runtime_error: Option<String>,
    pub models: Vec<InstalledModel>,
    pub selected_model: String,
    pub selected_model_available: bool,
    pub selected_model_loaded: bool,
    pub test_ran: bool,
    pub test_ok: bool,
    pub test_latency_ms: Option<u64>,
    pub test_error: Option<String>,
    pub total_ram_bytes: Option<u64>,
    pub available_ram_bytes: Option<u64>,
    pub resource_note: Option<String>,
}

pub fn suggested_models() -> Vec<Value> {
    vec![
        json!({"name": "gemma4:e2b-it-qat", "approx_download": "about 4.3 GB", "note": "Recommended default. Instruction-tuned, quantization-aware trained; good structured output on most laptops with 8 GB+ RAM. Runs on GPU if available."}),
        json!({"name": "gemma3:1b", "approx_download": "about 0.8 GB", "note": "For constrained laptops. Much faster and lighter, but noticeably weaker reasoning and more frequent invalid tool requests (which HauntTrace rejects)."}),
        json!({"name": "gemma3:4b", "approx_download": "about 3.3 GB", "note": "Middle ground if Gemma 4 is unavailable for your Ollama version."}),
    ]
}

pub async fn diagnose(cfg: &ModelSettings, run_test: bool) -> ModelDiagnostics {
    let mut d = ModelDiagnostics { endpoint: cfg.endpoint.clone(), selected_model: cfg.model.clone(), ..Default::default() };
    #[cfg(windows)]
    if let Some(m) = crate::win::memory_status() {
        d.total_ram_bytes = Some(m.total_bytes);
        d.available_ram_bytes = Some(m.available_bytes);
    }
    let client = match OllamaClient::new(cfg) {
        Ok(c) => c,
        Err(e) => {
            d.runtime_error = Some(e);
            return d;
        }
    };
    let http = &client.http;
    match http.get(client.url("/api/version")).timeout(Duration::from_secs(4)).send().await {
        Ok(r) => {
            d.runtime_reachable = true;
            d.runtime_version = r.json::<Value>().await.ok().and_then(|v| v["version"].as_str().map(String::from));
        }
        Err(e) => {
            d.runtime_error = Some(if e.is_connect() || e.is_timeout() {
                "Ollama is not running or not installed. Install it from https://ollama.com, start it, then re-check.".into()
            } else {
                format!("Could not query Ollama: {e}")
            });
            return d;
        }
    }
    if let Ok(r) = http.get(client.url("/api/tags")).timeout(Duration::from_secs(6)).send().await {
        if let Ok(v) = r.json::<Value>().await {
            for m in v["models"].as_array().cloned().unwrap_or_default() {
                d.models.push(InstalledModel {
                    name: m["name"].as_str().unwrap_or_default().to_string(),
                    size_bytes: m["size"].as_u64().unwrap_or(0),
                    parameter_size: m.pointer("/details/parameter_size").and_then(|x| x.as_str()).map(String::from),
                    quantization: m.pointer("/details/quantization_level").and_then(|x| x.as_str()).map(String::from),
                    family: m.pointer("/details/family").and_then(|x| x.as_str()).map(String::from),
                });
            }
        }
    }
    let sel = cfg.model.as_str();
    let matches = |n: &str| n == sel || n == format!("{sel}:latest");
    d.selected_model_available = d.models.iter().any(|m| matches(&m.name));
    if let Ok(r) = http.get(client.url("/api/ps")).timeout(Duration::from_secs(4)).send().await {
        if let Ok(v) = r.json::<Value>().await {
            d.selected_model_loaded = v["models"].as_array().map(|a| a.iter().any(|m| matches(m["name"].as_str().unwrap_or("")))).unwrap_or(false);
        }
    }
    if let (Some(size), Some(avail), Some(total)) = (
        d.models.iter().find(|m| matches(&m.name)).map(|m| m.size_bytes),
        d.available_ram_bytes,
        d.total_ram_bytes,
    ) {
        if size > total * 7 / 10 {
            d.resource_note = Some("This model is large relative to your installed RAM. Consider a smaller variant such as gemma3:1b.".into());
        } else if !d.selected_model_loaded && size > avail {
            d.resource_note = Some("Free memory is currently below the model size; loading may be slow or fail unless a GPU holds the model.".into());
        }
    }
    if run_test && d.selected_model_available {
        d.test_ran = true;
        let schema = json!({"type":"object","properties":{"status":{"type":"string","enum":["ready"]},"spooky_word":{"type":"string"}},"required":["status","spooky_word"]});
        let start = Instant::now();
        match client
            .generate_json(
                "You are a test harness. Reply only with JSON matching the schema.",
                "Return status \"ready\" and one spooky word.",
                &schema,
                Duration::from_secs(cfg.call_timeout_secs as u64),
            )
            .await
        {
            Ok(text) => {
                d.test_latency_ms = Some(start.elapsed().as_millis() as u64);
                match serde_json::from_str::<Value>(&text) {
                    Ok(v) if v["status"] == "ready" => d.test_ok = true,
                    _ => d.test_error = Some("The model answered, but not with valid structured output.".into()),
                }
            }
            Err(e) => d.test_error = Some(e.to_string()),
        }
    }
    d
}

/// Explicit, user-initiated model download through Ollama's pull API.
/// `progress` receives (status, completed, total). Cancellable.
pub async fn pull_model(
    cfg: &ModelSettings,
    model: &str,
    cancel: tokio_util::sync::CancellationToken,
    mut progress: impl FnMut(String, u64, u64) + Send,
) -> Result<(), String> {
    let client = OllamaClient::new(cfg)?;
    let mut resp = client
        .http
        .post(client.url("/api/pull"))
        .json(&json!({"model": model, "stream": true}))
        .send()
        .await
        .map_err(|e| map_send_err(e).to_string())?;
    if !resp.status().is_success() {
        return Err(format!("Ollama refused the download: {}", resp.status()));
    }
    let mut buf = String::new();
    loop {
        let chunk = tokio::select! {
            _ = cancel.cancelled() => return Err("Download cancelled".into()),
            c = resp.chunk() => c.map_err(|e| e.to_string())?,
        };
        let Some(chunk) = chunk else { break };
        buf.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(pos) = buf.find('\n') {
            let line: String = buf.drain(..=pos).collect();
            if let Ok(v) = serde_json::from_str::<Value>(line.trim()) {
                if let Some(err) = v["error"].as_str() {
                    return Err(err.to_string());
                }
                progress(v["status"].as_str().unwrap_or("").to_string(), v["completed"].as_u64().unwrap_or(0), v["total"].as_u64().unwrap_or(0));
            }
        }
    }
    Ok(())
}

//! Optional ElevenLabs narration. Only the short, sanitized narration line is
//! ever sent (never process lists, paths or evidence). The API key lives in
//! Windows Credential Manager and never reaches the frontend.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::json;

use crate::investigation::schema::sanitize_narration;

const API: &str = "https://api.elevenlabs.io/v1/text-to-speech";
const MAX_CACHE_FILES: usize = 60;

#[derive(Debug, Clone, PartialEq)]
pub enum NarrationError {
    NotConfigured(String),
    InvalidText,
    Auth,
    RateLimited,
    BadVoice,
    Offline,
    Timeout,
    Other(String),
}

impl std::fmt::Display for NarrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NarrationError::NotConfigured(s) => write!(f, "Voice narration is not configured: {s}"),
            NarrationError::InvalidText => write!(f, "The narration text was empty or unsafe to send"),
            NarrationError::Auth => write!(f, "ElevenLabs rejected the API key (401). Check the key in Settings."),
            NarrationError::RateLimited => write!(f, "ElevenLabs rate limit or quota reached (429). Text alerts continue to work."),
            NarrationError::BadVoice => write!(f, "ElevenLabs did not accept the voice ID or model."),
            NarrationError::Offline => write!(f, "No connection to ElevenLabs. Narration skipped; local sound and text still work."),
            NarrationError::Timeout => write!(f, "ElevenLabs did not respond in time."),
            NarrationError::Other(s) => write!(f, "{s}"),
        }
    }
}

/// FNV-1a: stable cache key across runs and versions.
fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub struct Narrator {
    http: reqwest::Client,
    cache_dir: PathBuf,
}

impl Narrator {
    pub fn new(cache_dir: PathBuf) -> Self {
        let http = reqwest::Client::builder().connect_timeout(Duration::from_secs(5)).timeout(Duration::from_secs(25)).build().unwrap_or_default();
        Self { http, cache_dir }
    }

    fn cache_path(&self, voice: &str, model: &str, text: &str) -> PathBuf {
        self.cache_dir.join(format!("{:016x}.mp3", fnv64(&format!("{voice}|{model}|{text}"))))
    }

    pub fn cached(&self, voice: &str, model: &str, text: &str) -> Option<Vec<u8>> {
        std::fs::read(self.cache_path(voice, model, text)).ok()
    }

    fn store(&self, path: &PathBuf, bytes: &[u8]) {
        let _ = std::fs::create_dir_all(&self.cache_dir);
        let _ = std::fs::write(path, bytes);
        // Bound the cache.
        if let Ok(rd) = std::fs::read_dir(&self.cache_dir) {
            let mut files: Vec<_> = rd.filter_map(|e| e.ok()).filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path()))).collect();
            if files.len() > MAX_CACHE_FILES {
                files.sort();
                for (_, p) in files.iter().take(files.len() - MAX_CACHE_FILES) {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
    }

    pub fn clear_cache(&self) {
        let _ = std::fs::remove_dir_all(&self.cache_dir);
    }

    /// Voices available to this API key: (voice_id, name, category). Only
    /// the key is sent.
    pub async fn list_voices(&self, api_key: Option<String>) -> Result<Vec<serde_json::Value>, NarrationError> {
        let key = api_key.ok_or_else(|| NarrationError::NotConfigured("no API key saved".into()))?;
        let resp = self
            .http
            .get("https://api.elevenlabs.io/v1/voices")
            .header("xi-api-key", key)
            .send()
            .await
            .map_err(|e| if e.is_timeout() { NarrationError::Timeout } else if e.is_connect() { NarrationError::Offline } else { NarrationError::Other(format!("Request failed: {e}")) })?;
        match resp.status().as_u16() {
            200 => {}
            401 | 403 => return Err(NarrationError::Auth),
            429 => return Err(NarrationError::RateLimited),
            s => return Err(NarrationError::Other(format!("ElevenLabs returned HTTP {s}"))),
        }
        let v: serde_json::Value = resp.json().await.map_err(|e| NarrationError::Other(e.to_string()))?;
        Ok(v["voices"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| json!({"voice_id": x["voice_id"], "name": x["name"], "category": x["category"]}))
                    .take(200)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Synthesize speech (MP3 bytes). Uses the cache when allowed.
    pub async fn speak(&self, text: &str, voice_id: &str, model_id: &str, api_key: Option<String>, use_cache: bool) -> Result<Vec<u8>, NarrationError> {
        let text = sanitize_narration(text).ok_or(NarrationError::InvalidText)?;
        if voice_id.is_empty() {
            return Err(NarrationError::NotConfigured("no voice ID set".into()));
        }
        let path = self.cache_path(voice_id, model_id, &text);
        if use_cache {
            if let Some(b) = self.cached(voice_id, model_id, &text) {
                return Ok(b);
            }
        }
        let key = api_key.ok_or_else(|| NarrationError::NotConfigured("no API key saved".into()))?;
        let resp = self
            .http
            .post(format!("{API}/{voice_id}?output_format=mp3_44100_64"))
            .header("xi-api-key", key)
            .header("accept", "audio/mpeg")
            .json(&json!({"text": text, "model_id": model_id, "voice_settings": {"stability": 0.45, "similarity_boost": 0.75}}))
            .send()
            .await
            .map_err(|e| if e.is_timeout() { NarrationError::Timeout } else if e.is_connect() { NarrationError::Offline } else { NarrationError::Other(format!("Request failed: {e}")) })?;
        match resp.status().as_u16() {
            200 => {}
            401 | 403 => return Err(NarrationError::Auth),
            429 => return Err(NarrationError::RateLimited),
            400 | 404 | 422 => return Err(NarrationError::BadVoice),
            s => return Err(NarrationError::Other(format!("ElevenLabs returned HTTP {s}"))),
        }
        let bytes = resp.bytes().await.map_err(|_| NarrationError::Offline)?.to_vec();
        if bytes.len() < 100 {
            return Err(NarrationError::Other("ElevenLabs returned an empty audio response".into()));
        }
        if use_cache {
            self.store(&path, &bytes);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn missing_credentials_fail_gracefully_without_network() {
        let n = Narrator::new(std::env::temp_dir().join("haunttrace-test-cache-none"));
        let r = rt().block_on(n.speak("Something has been lingering in the dark.", "voice123", "eleven_flash_v2_5", None, false));
        assert!(matches!(r, Err(NarrationError::NotConfigured(_))));
        let r = rt().block_on(n.speak("Something has been lingering in the dark.", "", "m", Some("k".into()), false));
        assert!(matches!(r, Err(NarrationError::NotConfigured(_))));
    }

    #[test]
    fn unsafe_text_is_never_sent() {
        let n = Narrator::new(std::env::temp_dir().join("haunttrace-test-cache-none"));
        let r = rt().block_on(n.speak("This is malware!", "v", "m", Some("k".into()), false));
        assert_eq!(r, Err(NarrationError::InvalidText));
    }

    #[test]
    fn cache_is_used_before_network() {
        let dir = std::env::temp_dir().join(format!("haunttrace-test-cache-{}", std::process::id()));
        let n = Narrator::new(dir.clone());
        let text = "Something has been lingering in the dark.";
        let p = n.cache_path("v1", "m1", text);
        n.store(&p, &[7u8; 200]);
        // No API key: would fail if it hit the network.
        let r = rt().block_on(n.speak(text, "v1", "m1", None, true)).unwrap();
        assert_eq!(r.len(), 200);
        n.clear_cache();
        let _ = dir;
    }
}

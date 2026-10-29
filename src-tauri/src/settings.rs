//! User-configurable settings with conservative defaults and clamping.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub monitoring: MonitoringSettings,
    pub rules: RuleSettings,
    pub alerts: AlertSettings,
    /// Process names (e.g. "chrome.exe") or full executable paths that are
    /// trusted and never alerted on. Case-insensitive.
    pub exclusions: Vec<String>,
    pub model: ModelSettings,
    pub voice: VoiceSettings,
    pub history: HistorySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MonitoringSettings {
    pub enabled: bool,
    pub interval_secs: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RuleSettings {
    pub lingering: LingeringRule,
    pub sustained_cpu: SustainedCpuRule,
    pub spikes: SpikesRule,
    pub memory_growth: MemoryGrowthRule,
    pub restarts: RestartsRule,
    /// After a rule fires for a process, it will not fire again for that
    /// process for this long.
    pub cooldown_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct LingeringRule {
    pub enabled: bool,
    pub runtime_minutes: u32,
    /// Runtime alone is not interesting: the process must also have averaged
    /// at least this CPU % over the recent window.
    pub min_avg_cpu: f32,
    pub window_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SustainedCpuRule {
    pub enabled: bool,
    /// % of the whole machine (all logical CPUs = 100 %).
    pub cpu_percent: f32,
    pub consecutive_samples: u32,
    /// Hysteresis: the condition is only considered over once CPU falls below
    /// `cpu_percent * release_ratio`.
    pub release_ratio: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SpikesRule {
    pub enabled: bool,
    pub spike_cpu_percent: f32,
    pub min_spikes: u32,
    pub window_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MemoryGrowthRule {
    pub enabled: bool,
    pub window_minutes: u32,
    pub min_growth_percent: f32,
    pub min_growth_mb: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct RestartsRule {
    pub enabled: bool,
    pub min_restarts: u32,
    pub window_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AlertSettings {
    pub notifications_enabled: bool,
    pub sound_enabled: bool,
    /// 0..=100
    pub volume: u8,
    pub quiet_hours_enabled: bool,
    /// Minutes after local midnight.
    pub quiet_start_min: u32,
    pub quiet_end_min: u32,
    pub min_interval_secs: u32,
    pub max_per_hour: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ModelSettings {
    /// Must be a loopback URL. Process evidence is never sent off-machine.
    pub endpoint: String,
    pub model: String,
    pub max_steps: u32,
    pub time_budget_secs: u32,
    pub call_timeout_secs: u32,
    pub keep_alive_minutes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct VoiceSettings {
    /// "off" (local alert sound + text), "windows" (offline Windows voice,
    /// no API key) or "elevenlabs" (cloud voice, needs an API key).
    pub mode: String,
    /// Display name of the Windows voice; empty = system default.
    pub windows_voice: String,
    /// ElevenLabs voice ID.
    pub voice_id: String,
    pub model_id: String,
    /// Only narrate investigations whose alert was a warning (true) or all (false).
    pub only_significant: bool,
    pub cache_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct HistorySettings {
    pub retention_days: u32,
    pub max_alerts: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            monitoring: MonitoringSettings::default(),
            rules: RuleSettings::default(),
            alerts: AlertSettings::default(),
            exclusions: default_exclusions(),
            model: ModelSettings::default(),
            voice: VoiceSettings::default(),
            history: HistorySettings::default(),
        }
    }
}

pub fn default_exclusions() -> Vec<String> {
    ["System Idle Process", "System", "Registry", "Memory Compression", "Secure System", "haunttrace.exe"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

impl Default for MonitoringSettings {
    fn default() -> Self {
        Self { enabled: true, interval_secs: 5 }
    }
}
impl Default for RuleSettings {
    fn default() -> Self {
        Self {
            lingering: LingeringRule::default(),
            sustained_cpu: SustainedCpuRule::default(),
            spikes: SpikesRule::default(),
            memory_growth: MemoryGrowthRule::default(),
            restarts: RestartsRule::default(),
            cooldown_minutes: 30,
        }
    }
}
impl Default for LingeringRule {
    fn default() -> Self {
        Self { enabled: true, runtime_minutes: 180, min_avg_cpu: 5.0, window_minutes: 10 }
    }
}
impl Default for SustainedCpuRule {
    fn default() -> Self {
        Self { enabled: true, cpu_percent: 25.0, consecutive_samples: 12, release_ratio: 0.6 }
    }
}
impl Default for SpikesRule {
    fn default() -> Self {
        Self { enabled: true, spike_cpu_percent: 40.0, min_spikes: 4, window_minutes: 5 }
    }
}
impl Default for MemoryGrowthRule {
    fn default() -> Self {
        Self { enabled: true, window_minutes: 15, min_growth_percent: 50.0, min_growth_mb: 300 }
    }
}
impl Default for RestartsRule {
    fn default() -> Self {
        Self { enabled: true, min_restarts: 3, window_minutes: 10 }
    }
}
impl Default for AlertSettings {
    fn default() -> Self {
        Self {
            notifications_enabled: true,
            sound_enabled: true,
            volume: 45,
            quiet_hours_enabled: false,
            quiet_start_min: 22 * 60,
            quiet_end_min: 7 * 60,
            min_interval_secs: 60,
            max_per_hour: 6,
        }
    }
}
impl Default for ModelSettings {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:11434".into(),
            model: "gemma4:e2b-it-qat".into(),
            max_steps: 4,
            time_budget_secs: 300,
            call_timeout_secs: 150,
            keep_alive_minutes: 5,
        }
    }
}
impl Default for VoiceSettings {
    fn default() -> Self {
        Self {
            mode: "off".into(),
            windows_voice: String::new(),
            voice_id: String::new(),
            model_id: "eleven_flash_v2_5".into(),
            only_significant: false,
            cache_enabled: true,
        }
    }
}
impl Default for HistorySettings {
    fn default() -> Self {
        Self { retention_days: 30, max_alerts: 500 }
    }
}

/// Only loopback endpoints are accepted, so process evidence can never be
/// routed to a remote model by configuration mistake.
pub fn is_loopback_endpoint(url: &str) -> bool {
    let rest = match url.strip_prefix("http://") {
        Some(r) => r,
        None => return false,
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn valid_model_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 100 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:/".contains(c))
}

impl VoiceSettings {
    pub fn enabled(&self) -> bool {
        self.mode != "off"
    }
}

impl Settings {
    /// Clamp every value into a safe range. Returns an error for values that
    /// cannot be repaired (e.g. a non-loopback model endpoint).
    pub fn sanitized(mut self) -> Result<Self, String> {
        let m = &mut self.monitoring;
        m.interval_secs = m.interval_secs.clamp(2, 60);
        let r = &mut self.rules;
        r.cooldown_minutes = r.cooldown_minutes.clamp(1, 24 * 60);
        r.lingering.runtime_minutes = r.lingering.runtime_minutes.clamp(5, 7 * 24 * 60);
        r.lingering.min_avg_cpu = r.lingering.min_avg_cpu.clamp(0.0, 100.0);
        r.lingering.window_minutes = r.lingering.window_minutes.clamp(1, 30);
        r.sustained_cpu.cpu_percent = r.sustained_cpu.cpu_percent.clamp(1.0, 100.0);
        r.sustained_cpu.consecutive_samples = r.sustained_cpu.consecutive_samples.clamp(2, 300);
        r.sustained_cpu.release_ratio = r.sustained_cpu.release_ratio.clamp(0.1, 1.0);
        r.spikes.spike_cpu_percent = r.spikes.spike_cpu_percent.clamp(1.0, 100.0);
        r.spikes.min_spikes = r.spikes.min_spikes.clamp(2, 100);
        r.spikes.window_minutes = r.spikes.window_minutes.clamp(1, 30);
        r.memory_growth.window_minutes = r.memory_growth.window_minutes.clamp(2, 30);
        r.memory_growth.min_growth_percent = r.memory_growth.min_growth_percent.clamp(5.0, 1000.0);
        r.memory_growth.min_growth_mb = r.memory_growth.min_growth_mb.clamp(10, 64_000);
        r.restarts.min_restarts = r.restarts.min_restarts.clamp(2, 100);
        r.restarts.window_minutes = r.restarts.window_minutes.clamp(1, 60);
        let a = &mut self.alerts;
        a.volume = a.volume.min(100);
        a.quiet_start_min %= 24 * 60;
        a.quiet_end_min %= 24 * 60;
        a.min_interval_secs = a.min_interval_secs.clamp(0, 3600);
        a.max_per_hour = a.max_per_hour.clamp(1, 120);
        self.exclusions = self
            .exclusions
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.len() <= 400)
            .take(500)
            .collect();
        let md = &mut self.model;
        md.endpoint = md.endpoint.trim().trim_end_matches('/').to_string();
        if !is_loopback_endpoint(&md.endpoint) {
            return Err("The model endpoint must be a local http://127.0.0.1, localhost or [::1] address. HauntTrace never sends process evidence to a remote model.".into());
        }
        md.model = md.model.trim().to_string();
        if !valid_model_name(&md.model) {
            return Err("Model name contains unsupported characters.".into());
        }
        md.max_steps = md.max_steps.clamp(1, 8);
        md.time_budget_secs = md.time_budget_secs.clamp(30, 1800);
        md.call_timeout_secs = md.call_timeout_secs.clamp(10, 600);
        md.keep_alive_minutes = md.keep_alive_minutes.clamp(0, 60);
        let v = &mut self.voice;
        if !matches!(v.mode.as_str(), "off" | "windows" | "elevenlabs") {
            v.mode = "off".into();
        }
        v.windows_voice = v.windows_voice.trim().chars().take(120).collect();
        v.voice_id = v.voice_id.trim().to_string();
        if !v.voice_id.chars().all(|c| c.is_ascii_alphanumeric()) || v.voice_id.len() > 64 {
            return Err("Voice ID must be alphanumeric (as shown in the ElevenLabs voice library).".into());
        }
        v.model_id = v.model_id.trim().to_string();
        if !valid_model_name(&v.model_id) {
            v.model_id = VoiceSettings::default().model_id;
        }
        let h = &mut self.history;
        h.retention_days = h.retention_days.clamp(1, 3650);
        h.max_alerts = h.max_alerts.clamp(10, 10_000);
        Ok(self)
    }

    pub fn is_excluded(&self, name: &str, exe_path: Option<&str>) -> bool {
        self.exclusions.iter().any(|e| e.eq_ignore_ascii_case(name) || exe_path.map(|p| e.eq_ignore_ascii_case(p)).unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_remote_model_endpoints() {
        assert!(is_loopback_endpoint("http://127.0.0.1:11434"));
        assert!(is_loopback_endpoint("http://localhost:11434"));
        assert!(is_loopback_endpoint("http://[::1]:11434"));
        assert!(!is_loopback_endpoint("http://192.168.1.4:11434"));
        assert!(!is_loopback_endpoint("https://api.example.com"));
        assert!(!is_loopback_endpoint("http://localhost.evil.com:11434"));
        let mut s = Settings::default();
        s.model.endpoint = "http://10.0.0.2:11434".into();
        assert!(s.sanitized().is_err());
    }

    #[test]
    fn clamps_out_of_range_values() {
        let mut s = Settings::default();
        s.monitoring.interval_secs = 0;
        s.model.max_steps = 99;
        s.alerts.volume = 255;
        let s = s.sanitized().unwrap();
        assert_eq!(s.monitoring.interval_secs, 2);
        assert_eq!(s.model.max_steps, 8);
        assert_eq!(s.alerts.volume, 100);
    }

    #[test]
    fn documented_example_matches_defaults() {
        let doc: Settings = serde_json::from_str(include_str!("../../docs/settings.example.json")).unwrap();
        assert_eq!(doc, Settings::default());
    }

    #[test]
    fn exclusions_match_name_or_path_case_insensitively() {
        let mut s = Settings::default();
        s.exclusions.push("C:\\Tools\\Backup.exe".into());
        assert!(s.is_excluded("SYSTEM", None));
        assert!(s.is_excluded("x.exe", Some("c:\\tools\\backup.exe")));
        assert!(!s.is_excluded("x.exe", Some("c:\\tools\\other.exe")));
    }
}

//! Alert delivery policy: snoozes, quiet hours, minimum interval and hourly
//! cap. Pure logic, independent of how notifications or sounds are produced.

use std::collections::{HashMap, VecDeque};

use serde::Serialize;

use crate::detection::Detection;
use crate::settings::AlertSettings;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Delivery {
    /// Show a desktop notification (and a sound if `sound`).
    Notify { sound: bool },
    /// Record the alert in the app, but stay quiet.
    Silent { reason: String },
}

#[derive(Default)]
pub struct AlertPolicy {
    notified: VecDeque<u64>,
    snoozes: HashMap<String, u64>,
}

pub fn snooze_key(name: &str, exe_path: Option<&str>) -> String {
    exe_path.unwrap_or(name).to_lowercase()
}

pub fn in_quiet_hours(start: u32, end: u32, minute_of_day: u32) -> bool {
    if start == end {
        return false;
    }
    if start < end {
        minute_of_day >= start && minute_of_day < end
    } else {
        // Wraps past midnight, e.g. 22:00 - 07:00.
        minute_of_day >= start || minute_of_day < end
    }
}

impl AlertPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snooze(&mut self, key: String, until: u64) {
        self.snoozes.insert(key, until);
    }

    pub fn unsnooze(&mut self, key: &str) {
        self.snoozes.remove(key);
    }

    pub fn snoozes(&self, now: u64) -> Vec<(String, u64)> {
        self.snoozes.iter().filter(|(_, u)| **u > now).map(|(k, u)| (k.clone(), *u)).collect()
    }

    /// Decide how to deliver a detection. `None` means drop it (snoozed).
    pub fn decide(&mut self, d: &Detection, s: &AlertSettings, now: u64, minute_of_day: u32) -> Option<Delivery> {
        let key = snooze_key(&d.name, d.exe_path.as_deref());
        if let Some(until) = self.snoozes.get(&key) {
            if *until > now {
                return None;
            }
            self.snoozes.remove(&key);
        }
        while self.notified.front().map(|t| now.saturating_sub(*t) >= 3_600_000).unwrap_or(false) {
            self.notified.pop_front();
        }
        if !s.notifications_enabled {
            return Some(Delivery::Silent { reason: "Desktop notifications are turned off".into() });
        }
        if s.quiet_hours_enabled && in_quiet_hours(s.quiet_start_min, s.quiet_end_min, minute_of_day) {
            return Some(Delivery::Silent { reason: "Quiet hours".into() });
        }
        if let Some(last) = self.notified.back() {
            if now.saturating_sub(*last) < s.min_interval_secs as u64 * 1000 {
                return Some(Delivery::Silent { reason: "Minimum interval between alerts".into() });
            }
        }
        if self.notified.len() as u32 >= s.max_per_hour {
            return Some(Delivery::Silent { reason: "Hourly alert limit reached".into() });
        }
        self.notified.push_back(now);
        Some(Delivery::Notify { sound: s.sound_enabled })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{DetectionMetrics, Priority, RuleKind};
    use crate::types::ProcessKey;

    fn det(name: &str) -> Detection {
        Detection {
            rule: RuleKind::SustainedCpu,
            priority: Priority::Warning,
            key: ProcessKey { pid: 1, created: 1 },
            name: name.into(),
            exe_path: Some(format!("C:\\x\\{name}")),
            at: 0,
            reason: String::new(),
            metrics: DetectionMetrics::default(),
            details: serde_json::Value::Null,
            synthetic: true,
        }
    }

    #[test]
    fn min_interval_and_hourly_cap() {
        let mut p = AlertPolicy::new();
        let s = AlertSettings { min_interval_secs: 60, max_per_hour: 3, ..Default::default() };
        let t0 = 10_000_000;
        assert_eq!(p.decide(&det("a"), &s, t0, 600), Some(Delivery::Notify { sound: true }));
        assert!(matches!(p.decide(&det("b"), &s, t0 + 30_000, 600), Some(Delivery::Silent { .. })));
        assert!(matches!(p.decide(&det("b"), &s, t0 + 61_000, 600), Some(Delivery::Notify { .. })));
        assert!(matches!(p.decide(&det("c"), &s, t0 + 122_000, 600), Some(Delivery::Notify { .. })));
        assert_eq!(p.decide(&det("d"), &s, t0 + 183_000, 600), Some(Delivery::Silent { reason: "Hourly alert limit reached".into() }));
        // An hour later the cap resets.
        assert!(matches!(p.decide(&det("d"), &s, t0 + 3_700_000, 600), Some(Delivery::Notify { .. })));
    }

    #[test]
    fn snooze_drops_alerts_until_expiry() {
        let mut p = AlertPolicy::new();
        let s = AlertSettings::default();
        p.snooze(snooze_key("a", Some("C:\\x\\a")), 5_000);
        assert_eq!(p.decide(&det("a"), &s, 1_000, 600), None);
        assert!(p.decide(&det("a"), &s, 6_000, 600).is_some());
    }

    #[test]
    fn quiet_hours_wrap_midnight() {
        assert!(in_quiet_hours(22 * 60, 7 * 60, 23 * 60));
        assert!(in_quiet_hours(22 * 60, 7 * 60, 3 * 60));
        assert!(!in_quiet_hours(22 * 60, 7 * 60, 12 * 60));
        assert!(in_quiet_hours(9 * 60, 17 * 60, 12 * 60));
        let mut p = AlertPolicy::new();
        let s = AlertSettings { quiet_hours_enabled: true, ..Default::default() };
        assert_eq!(p.decide(&det("a"), &s, 1_000, 23 * 60), Some(Delivery::Silent { reason: "Quiet hours".into() }));
    }

    #[test]
    fn sound_follows_setting() {
        let mut p = AlertPolicy::new();
        let s = AlertSettings { sound_enabled: false, ..Default::default() };
        assert_eq!(p.decide(&det("a"), &s, 1_000, 600), Some(Delivery::Notify { sound: false }));
    }
}

//! Dead-man trigger — automated key destruction when conditions are met.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadManConfig {
    pub inactivity_timeout_hours: u64,
    pub trigger_on_forensic_tool: bool,
    pub trigger_on_tamper: bool,
    pub accept_remote_kill: bool,
    pub remote_kill_key_hash: Option<[u8; 32]>,
}

impl Default for DeadManConfig {
    fn default() -> Self {
        Self { inactivity_timeout_hours: 336, trigger_on_forensic_tool: true, trigger_on_tamper: true, accept_remote_kill: false, remote_kill_key_hash: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TriggerReason { InactivityTimeout { hours: u64 }, ForensicTool { name: String }, Tamper { desc: String }, RemoteKill, Manual }

pub struct DeadManTrigger {
    config: DeadManConfig,
    last_checkin: DateTime<Utc>,
    triggered: bool,
    triggered_at: Option<DateTime<Utc>>,
    reason: Option<TriggerReason>,
}

impl DeadManTrigger {
    pub fn new(config: DeadManConfig) -> Self {
        Self { config, last_checkin: Utc::now(), triggered: false, triggered_at: None, reason: None }
    }

    pub fn checkin(&mut self) { if !self.triggered { self.last_checkin = Utc::now(); } }

    pub fn should_trigger(&self) -> Option<TriggerReason> {
        if self.triggered { return None; }
        let elapsed = Utc::now() - self.last_checkin;
        if elapsed > Duration::hours(self.config.inactivity_timeout_hours as i64) {
            Some(TriggerReason::InactivityTimeout { hours: elapsed.num_hours() as u64 })
        } else { None }
    }

    pub fn fire(&mut self, reason: TriggerReason) -> bool {
        if self.triggered { return false; }
        self.triggered = true;
        self.triggered_at = Some(Utc::now());
        self.reason = Some(reason);
        true
    }

    pub fn report_forensic_tool(&mut self, name: &str) -> bool {
        if self.config.trigger_on_forensic_tool { self.fire(TriggerReason::ForensicTool { name: name.into() }) } else { false }
    }

    pub fn report_tamper(&mut self, desc: &str) -> bool {
        if self.config.trigger_on_tamper { self.fire(TriggerReason::Tamper { desc: desc.into() }) } else { false }
    }

    pub fn remote_kill(&mut self, key: &[u8]) -> bool {
        if !self.config.accept_remote_kill { return false; }
        if let Some(expected) = &self.config.remote_kill_key_hash {
            if blake3::hash(key).as_bytes() == expected { return self.fire(TriggerReason::RemoteKill); }
        }
        false
    }

    pub fn is_triggered(&self) -> bool { self.triggered }
    pub fn hours_remaining(&self) -> i64 { (Duration::hours(self.config.inactivity_timeout_hours as i64) - (Utc::now() - self.last_checkin)).num_hours().max(0) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkin_resets() { let mut t = DeadManTrigger::new(DeadManConfig::default()); t.checkin(); assert!(!t.is_triggered()); assert!(t.hours_remaining() > 300); }

    #[test]
    fn test_inactivity() {
        let mut t = DeadManTrigger::new(DeadManConfig { inactivity_timeout_hours: 1, ..Default::default() });
        t.last_checkin = Utc::now() - Duration::hours(2);
        assert!(t.should_trigger().is_some());
    }

    #[test]
    fn test_forensic_fires() { let mut t = DeadManTrigger::new(DeadManConfig::default()); assert!(t.report_forensic_tool("Cellebrite")); assert!(t.is_triggered()); }

    #[test]
    fn test_tamper_fires() { let mut t = DeadManTrigger::new(DeadManConfig::default()); assert!(t.report_tamper("SIM removed")); assert!(t.is_triggered()); }

    #[test]
    fn test_remote_kill_valid() {
        let key = b"secret-key";
        let hash = *blake3::hash(key).as_bytes();
        let mut t = DeadManTrigger::new(DeadManConfig { accept_remote_kill: true, remote_kill_key_hash: Some(hash), ..Default::default() });
        assert!(t.remote_kill(key)); assert!(t.is_triggered());
    }

    #[test]
    fn test_remote_kill_wrong_key() {
        let hash = *blake3::hash(b"correct").as_bytes();
        let mut t = DeadManTrigger::new(DeadManConfig { accept_remote_kill: true, remote_kill_key_hash: Some(hash), ..Default::default() });
        assert!(!t.remote_kill(b"wrong")); assert!(!t.is_triggered());
    }

    #[test]
    fn test_no_double_fire() { let mut t = DeadManTrigger::new(DeadManConfig::default()); assert!(t.fire(TriggerReason::Manual)); assert!(!t.fire(TriggerReason::Manual)); }

    #[test]
    fn test_checkin_after_trigger_ignored() {
        let mut t = DeadManTrigger::new(DeadManConfig::default());
        t.fire(TriggerReason::Manual);
        let before = t.last_checkin;
        t.checkin();
        assert_eq!(t.last_checkin, before);
    }

    #[test]
    fn test_disabled_forensic() {
        let mut t = DeadManTrigger::new(DeadManConfig { trigger_on_forensic_tool: false, ..Default::default() });
        assert!(!t.report_forensic_tool("Cellebrite")); assert!(!t.is_triggered());
    }
}

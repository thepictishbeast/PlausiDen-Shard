//! Key rotation lifecycle — automatic key renewal and re-encryption.
//!
//! Keys should be rotated periodically to limit the damage from key compromise.
//! When a key is rotated, all fragments encrypted under the old key must be
//! re-encrypted with the new key.

use crate::encryption::SecureKey;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Key rotation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Maximum key age before rotation is required (days).
    pub max_age_days: u32,
    /// Warning threshold before expiry (days).
    pub warn_before_days: u32,
    /// Whether to auto-rotate or just alert.
    pub auto_rotate: bool,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_age_days: 90,
            warn_before_days: 14,
            auto_rotate: false,
        }
    }
}

/// Tracks the lifecycle of an encryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyLifecycle {
    /// When the key was created.
    pub created_at: DateTime<Utc>,
    /// When the key was last used for encryption.
    pub last_used: DateTime<Utc>,
    /// Number of fragments encrypted with this key.
    pub fragments_encrypted: u64,
    /// Whether the key has been rotated (replaced).
    pub rotated: bool,
    /// When the key was rotated (if applicable).
    pub rotated_at: Option<DateTime<Utc>>,
    /// Rotation policy.
    pub policy: RotationPolicy,
}

/// Rotation status check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationStatus {
    /// Key is fresh — no action needed.
    Fresh,
    /// Key is approaching expiry — warn the user.
    WarningSoon { days_remaining: u32 },
    /// Key has expired — rotation required.
    Expired { days_overdue: u32 },
    /// Key has already been rotated.
    AlreadyRotated,
}

impl KeyLifecycle {
    /// Create a new key lifecycle tracker.
    pub fn new(policy: RotationPolicy) -> Self {
        let now = Utc::now();
        Self {
            created_at: now,
            last_used: now,
            fragments_encrypted: 0,
            rotated: false,
            rotated_at: None,
            policy,
        }
    }

    /// Record that the key was used to encrypt a fragment.
    pub fn record_use(&mut self) {
        self.last_used = Utc::now();
        self.fragments_encrypted += 1;
    }

    /// Check if the key needs rotation.
    pub fn check_rotation(&self) -> RotationStatus {
        if self.rotated {
            return RotationStatus::AlreadyRotated;
        }

        let age = Utc::now() - self.created_at;
        let max_age = Duration::days(self.policy.max_age_days as i64);
        let warn_threshold = max_age - Duration::days(self.policy.warn_before_days as i64);

        if age > max_age {
            RotationStatus::Expired {
                days_overdue: (age - max_age).num_days() as u32,
            }
        } else if age > warn_threshold {
            let remaining = (max_age - age).num_days() as u32;
            RotationStatus::WarningSoon { days_remaining: remaining }
        } else {
            RotationStatus::Fresh
        }
    }

    /// Mark the key as rotated.
    pub fn mark_rotated(&mut self) {
        self.rotated = true;
        self.rotated_at = Some(Utc::now());
    }

    /// Days since key creation.
    pub fn age_days(&self) -> u32 {
        (Utc::now() - self.created_at).num_days().max(0) as u32
    }

    /// Days until rotation required.
    pub fn days_until_rotation(&self) -> i64 {
        let max_age = Duration::days(self.policy.max_age_days as i64);
        let age = Utc::now() - self.created_at;
        (max_age - age).num_days()
    }
}

/// Key rotation manager — tracks multiple keys.
pub struct KeyRotationManager {
    keys: Vec<(String, KeyLifecycle)>,
}

impl KeyRotationManager {
    pub fn new() -> Self { Self { keys: Vec::new() } }

    /// Register a key for lifecycle tracking.
    pub fn register(&mut self, key_id: String, policy: RotationPolicy) {
        self.keys.push((key_id, KeyLifecycle::new(policy)));
    }

    /// Check all keys and return those needing attention.
    pub fn check_all(&self) -> Vec<(&str, RotationStatus)> {
        self.keys.iter()
            .map(|(id, lc)| (id.as_str(), lc.check_rotation()))
            .filter(|(_, status)| !matches!(status, RotationStatus::Fresh))
            .collect()
    }

    /// Get lifecycle for a specific key.
    pub fn get_lifecycle(&self, key_id: &str) -> Option<&KeyLifecycle> {
        self.keys.iter().find(|(id, _)| id == key_id).map(|(_, lc)| lc)
    }

    /// Get mutable lifecycle for a specific key.
    pub fn get_lifecycle_mut(&mut self, key_id: &str) -> Option<&mut KeyLifecycle> {
        self.keys.iter_mut().find(|(id, _)| id == key_id).map(|(_, lc)| lc)
    }

    /// Number of tracked keys.
    pub fn key_count(&self) -> usize { self.keys.len() }
}

impl Default for KeyRotationManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_key() {
        let lc = KeyLifecycle::new(RotationPolicy::default());
        assert_eq!(lc.check_rotation(), RotationStatus::Fresh);
        assert_eq!(lc.fragments_encrypted, 0);
    }

    #[test]
    fn test_expired_key() {
        let mut lc = KeyLifecycle::new(RotationPolicy { max_age_days: 1, warn_before_days: 0, auto_rotate: false });
        lc.created_at = Utc::now() - Duration::days(5);
        assert!(matches!(lc.check_rotation(), RotationStatus::Expired { .. }));
    }

    #[test]
    fn test_warning_key() {
        let mut lc = KeyLifecycle::new(RotationPolicy { max_age_days: 30, warn_before_days: 10, auto_rotate: false });
        lc.created_at = Utc::now() - Duration::days(25);
        assert!(matches!(lc.check_rotation(), RotationStatus::WarningSoon { .. }));
    }

    #[test]
    fn test_mark_rotated() {
        let mut lc = KeyLifecycle::new(RotationPolicy::default());
        lc.mark_rotated();
        assert_eq!(lc.check_rotation(), RotationStatus::AlreadyRotated);
        assert!(lc.rotated_at.is_some());
    }

    #[test]
    fn test_record_use() {
        let mut lc = KeyLifecycle::new(RotationPolicy::default());
        lc.record_use();
        lc.record_use();
        lc.record_use();
        assert_eq!(lc.fragments_encrypted, 3);
    }

    #[test]
    fn test_rotation_manager() {
        let mut mgr = KeyRotationManager::new();
        mgr.register("key1".into(), RotationPolicy::default());
        mgr.register("key2".into(), RotationPolicy { max_age_days: 1, warn_before_days: 0, auto_rotate: false });

        // Expire key2
        mgr.get_lifecycle_mut("key2").unwrap().created_at = Utc::now() - Duration::days(5);

        let alerts = mgr.check_all();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].0, "key2");
    }

    #[test]
    fn test_days_until_rotation() {
        let lc = KeyLifecycle::new(RotationPolicy { max_age_days: 90, warn_before_days: 14, auto_rotate: false });
        assert!(lc.days_until_rotation() > 85);
    }
}

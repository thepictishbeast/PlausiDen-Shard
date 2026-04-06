//! Cipher rotation — schedule key and cipher upgrades over time.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A supported cipher suite.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Cipher {
    ChaCha20Poly1305,
    AesGcm256,
    AesGcmSiv256,
    Xchacha20Poly1305,
    /// Post-quantum candidate.
    AsconAead,
    /// Placeholder for future upgrades.
    Future(String),
}

impl Cipher {
    /// Security strength in bits (approximate).
    pub fn strength_bits(&self) -> u32 {
        match self {
            Cipher::ChaCha20Poly1305 => 256,
            Cipher::AesGcm256 => 256,
            Cipher::AesGcmSiv256 => 256,
            Cipher::Xchacha20Poly1305 => 256,
            Cipher::AsconAead => 128,
            Cipher::Future(_) => 256,
        }
    }

    /// Is this cipher post-quantum resistant?
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Cipher::AsconAead)
    }
}

/// A fragment's current cipher assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherAssignment {
    pub fragment_id: String,
    pub cipher: Cipher,
    pub key_version: u32,
    pub assigned_at: DateTime<Utc>,
    pub rotate_by: DateTime<Utc>,
}

impl CipherAssignment {
    pub fn is_overdue(&self) -> bool {
        Utc::now() > self.rotate_by
    }

    pub fn days_until_rotation(&self) -> i64 {
        (self.rotate_by - Utc::now()).num_days()
    }
}

/// Rotation schedule policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub default_lifetime_days: i64,
    pub deprecated_ciphers: Vec<Cipher>,
    pub preferred_cipher: Cipher,
    pub require_pq_after: Option<DateTime<Utc>>,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            default_lifetime_days: 90,
            deprecated_ciphers: Vec::new(),
            preferred_cipher: Cipher::ChaCha20Poly1305,
            require_pq_after: None,
        }
    }
}

/// Cipher rotation manager.
pub struct CipherRotation {
    assignments: HashMap<String, CipherAssignment>,
    policy: RotationPolicy,
}

impl CipherRotation {
    pub fn new(policy: RotationPolicy) -> Self {
        Self {
            assignments: HashMap::new(),
            policy,
        }
    }

    /// Assign a cipher to a fragment.
    pub fn assign(&mut self, fragment_id: &str, cipher: Cipher, key_version: u32) {
        let now = Utc::now();
        self.assignments.insert(fragment_id.into(), CipherAssignment {
            fragment_id: fragment_id.into(),
            cipher,
            key_version,
            assigned_at: now,
            rotate_by: now + chrono::Duration::days(self.policy.default_lifetime_days),
        });
    }

    /// Get an assignment.
    pub fn get(&self, fragment_id: &str) -> Option<&CipherAssignment> {
        self.assignments.get(fragment_id)
    }

    /// Remove an assignment.
    pub fn remove(&mut self, fragment_id: &str) -> bool {
        self.assignments.remove(fragment_id).is_some()
    }

    /// Fragments overdue for rotation.
    pub fn overdue(&self) -> Vec<&CipherAssignment> {
        self.assignments.values().filter(|a| a.is_overdue()).collect()
    }

    /// Fragments using deprecated ciphers.
    pub fn using_deprecated(&self) -> Vec<&CipherAssignment> {
        self.assignments.values()
            .filter(|a| self.policy.deprecated_ciphers.contains(&a.cipher))
            .collect()
    }

    /// Fragments needing post-quantum upgrade.
    pub fn needs_pq_upgrade(&self) -> Vec<&CipherAssignment> {
        if let Some(cutoff) = self.policy.require_pq_after {
            if Utc::now() < cutoff { return Vec::new(); }
            return self.assignments.values()
                .filter(|a| !a.cipher.is_post_quantum())
                .collect();
        }
        Vec::new()
    }

    /// Fragments using a specific cipher.
    pub fn by_cipher(&self, cipher: &Cipher) -> Vec<&CipherAssignment> {
        self.assignments.values().filter(|a| &a.cipher == cipher).collect()
    }

    /// Cipher distribution.
    pub fn cipher_distribution(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for a in self.assignments.values() {
            *map.entry(format!("{:?}", a.cipher)).or_insert(0) += 1;
        }
        map
    }

    /// Update policy.
    pub fn set_policy(&mut self, policy: RotationPolicy) {
        self.policy = policy;
    }

    pub fn assignment_count(&self) -> usize {
        self.assignments.len()
    }

    /// Assignments due within N days.
    pub fn due_within_days(&self, days: i64) -> Vec<&CipherAssignment> {
        self.assignments.values()
            .filter(|a| a.days_until_rotation() <= days)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_strength() {
        assert_eq!(Cipher::ChaCha20Poly1305.strength_bits(), 256);
        assert_eq!(Cipher::AsconAead.strength_bits(), 128);
    }

    #[test]
    fn test_is_post_quantum() {
        assert!(Cipher::AsconAead.is_post_quantum());
        assert!(!Cipher::ChaCha20Poly1305.is_post_quantum());
    }

    #[test]
    fn test_assign_and_get() {
        let mut r = CipherRotation::new(RotationPolicy::default());
        r.assign("frag1", Cipher::ChaCha20Poly1305, 1);
        assert!(r.get("frag1").is_some());
    }

    #[test]
    fn test_overdue_detection() {
        let mut r = CipherRotation::new(RotationPolicy::default());
        r.assign("frag1", Cipher::ChaCha20Poly1305, 1);
        // Force overdue.
        if let Some(a) = r.assignments.get_mut("frag1") {
            a.rotate_by = Utc::now() - chrono::Duration::days(1);
        }
        assert_eq!(r.overdue().len(), 1);
    }

    #[test]
    fn test_deprecated_ciphers() {
        let policy = RotationPolicy {
            deprecated_ciphers: vec![Cipher::AesGcm256],
            ..Default::default()
        };
        let mut r = CipherRotation::new(policy);
        r.assign("frag1", Cipher::AesGcm256, 1);
        r.assign("frag2", Cipher::ChaCha20Poly1305, 1);
        assert_eq!(r.using_deprecated().len(), 1);
    }

    #[test]
    fn test_pq_upgrade_needed() {
        let policy = RotationPolicy {
            require_pq_after: Some(Utc::now() - chrono::Duration::days(1)),
            ..Default::default()
        };
        let mut r = CipherRotation::new(policy);
        r.assign("frag1", Cipher::ChaCha20Poly1305, 1);
        r.assign("frag2", Cipher::AsconAead, 1);
        assert_eq!(r.needs_pq_upgrade().len(), 1);
    }

    #[test]
    fn test_by_cipher() {
        let mut r = CipherRotation::new(RotationPolicy::default());
        r.assign("a", Cipher::ChaCha20Poly1305, 1);
        r.assign("b", Cipher::ChaCha20Poly1305, 1);
        r.assign("c", Cipher::AesGcm256, 1);
        assert_eq!(r.by_cipher(&Cipher::ChaCha20Poly1305).len(), 2);
    }

    #[test]
    fn test_cipher_distribution() {
        let mut r = CipherRotation::new(RotationPolicy::default());
        r.assign("a", Cipher::ChaCha20Poly1305, 1);
        r.assign("b", Cipher::AesGcm256, 1);
        let dist = r.cipher_distribution();
        assert_eq!(dist.len(), 2);
    }

    #[test]
    fn test_remove() {
        let mut r = CipherRotation::new(RotationPolicy::default());
        r.assign("a", Cipher::ChaCha20Poly1305, 1);
        assert!(r.remove("a"));
        assert_eq!(r.assignment_count(), 0);
    }

    #[test]
    fn test_due_within_days() {
        let mut r = CipherRotation::new(RotationPolicy::default());
        r.assign("frag1", Cipher::ChaCha20Poly1305, 1);
        if let Some(a) = r.assignments.get_mut("frag1") {
            a.rotate_by = Utc::now() + chrono::Duration::days(5);
        }
        assert_eq!(r.due_within_days(10).len(), 1);
    }
}

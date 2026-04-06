//! Shard integrity verification — continuous checking of stored fragments.

use crate::fragment::Fragment;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub total_checked: usize,
    pub passed: usize,
    pub failed: usize,
    pub expired: usize,
    pub corrupted_ids: Vec<String>,
}

pub struct IntegrityChecker {
    check_history: Vec<IntegrityReport>,
    max_history: usize,
}

impl IntegrityChecker {
    pub fn new(max_history: usize) -> Self { Self { check_history: Vec::new(), max_history } }

    pub fn check_fragments(&mut self, fragments: &[Fragment]) -> IntegrityReport {
        let mut report = IntegrityReport { total_checked: fragments.len(), passed: 0, failed: 0, expired: 0, corrupted_ids: Vec::new() };

        for frag in fragments {
            if frag.is_expired() { report.expired += 1; }
            if frag.verify_integrity() { report.passed += 1; }
            else {
                report.failed += 1;
                report.corrupted_ids.push(hex::encode(&frag.fragment_id[..8]));
            }
        }

        self.check_history.push(report.clone());
        if self.check_history.len() > self.max_history { self.check_history.remove(0); }
        report
    }

    pub fn history(&self) -> &[IntegrityReport] { &self.check_history }
    pub fn last_report(&self) -> Option<&IntegrityReport> { self.check_history.last() }
    pub fn total_checks(&self) -> usize { self.check_history.len() }
}

impl Default for IntegrityChecker { fn default() -> Self { Self::new(100) } }

mod hex {
    pub fn encode(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_frag() -> Fragment {
        let payload = vec![0xABu8; 64];
        let hash = blake3::hash(&payload);
        Fragment { fragment_id: [1u8; 32], index: 0, total: 1, threshold: 1, content_hash: *hash.as_bytes(), encrypted_payload: payload, padding_bytes: 0, expires_at: 0, shard_set_id: [0u8; 32] }
    }

    #[test]
    fn test_all_pass() {
        let mut checker = IntegrityChecker::new(10);
        let frags = vec![good_frag(), good_frag()];
        let report = checker.check_fragments(&frags);
        assert_eq!(report.passed, 2);
        assert_eq!(report.failed, 0);
    }

    #[test]
    fn test_corrupted_detected() {
        let mut checker = IntegrityChecker::new(10);
        let mut frag = good_frag();
        frag.encrypted_payload[0] = 0xFF;
        let report = checker.check_fragments(&[frag]);
        assert_eq!(report.failed, 1);
        assert!(!report.corrupted_ids.is_empty());
    }

    #[test]
    fn test_history() {
        let mut checker = IntegrityChecker::new(3);
        for _ in 0..5 { checker.check_fragments(&[good_frag()]); }
        assert_eq!(checker.total_checks(), 3); // Max history
    }
}

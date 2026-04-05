//! Shard audit — verify integrity and security of all fragments.

use crate::fragment::Fragment;
use crate::encryption;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub total_fragments: usize,
    pub integrity_passed: usize,
    pub integrity_failed: usize,
    pub expired_count: usize,
    pub total_bytes: u64,
    pub issues: Vec<AuditIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIssue {
    pub fragment_index: u32,
    pub issue_type: IssueType,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueType { IntegrityFailure, Expired, OversizedPayload, MissingSetId }

/// Audit a set of fragments.
pub fn audit_fragments(fragments: &[Fragment]) -> AuditResult {
    let mut result = AuditResult {
        total_fragments: fragments.len(), integrity_passed: 0, integrity_failed: 0,
        expired_count: 0, total_bytes: 0, issues: Vec::new(),
    };

    for frag in fragments {
        result.total_bytes += frag.encrypted_payload.len() as u64;

        if frag.verify_integrity() {
            result.integrity_passed += 1;
        } else {
            result.integrity_failed += 1;
            result.issues.push(AuditIssue { fragment_index: frag.index, issue_type: IssueType::IntegrityFailure, description: "BLAKE3 hash mismatch".into() });
        }

        if frag.is_expired() {
            result.expired_count += 1;
            result.issues.push(AuditIssue { fragment_index: frag.index, issue_type: IssueType::Expired, description: format!("expired at {}", frag.expires_at) });
        }

        if frag.encrypted_payload.len() > 16 * 1024 * 1024 {
            result.issues.push(AuditIssue { fragment_index: frag.index, issue_type: IssueType::OversizedPayload, description: format!("{}MB exceeds 16MB limit", frag.encrypted_payload.len() / 1_000_000) });
        }
    }

    result
}

impl AuditResult {
    pub fn is_clean(&self) -> bool { self.issues.is_empty() }
    pub fn integrity_rate(&self) -> f64 {
        if self.total_fragments == 0 { 1.0 } else { self.integrity_passed as f64 / self.total_fragments as f64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_fragment(idx: u32) -> Fragment {
        let payload = vec![0xABu8; 256];
        let hash = blake3::hash(&payload);
        Fragment { fragment_id: [idx as u8; 32], index: idx, total: 5, threshold: 3, content_hash: *hash.as_bytes(), encrypted_payload: payload, padding_bytes: 0, expires_at: 0, shard_set_id: [1u8; 32] }
    }

    #[test]
    fn test_clean_audit() {
        let frags: Vec<_> = (0..5).map(good_fragment).collect();
        let result = audit_fragments(&frags);
        assert!(result.is_clean());
        assert_eq!(result.integrity_passed, 5);
    }

    #[test]
    fn test_tampered_fragment() {
        let mut frags: Vec<_> = (0..3).map(good_fragment).collect();
        frags[1].encrypted_payload[0] = 0xFF; // Tamper
        let result = audit_fragments(&frags);
        assert!(!result.is_clean());
        assert_eq!(result.integrity_failed, 1);
    }

    #[test]
    fn test_expired_fragment() {
        let mut frag = good_fragment(0);
        frag.expires_at = 1000; // Long past
        let result = audit_fragments(&[frag]);
        assert_eq!(result.expired_count, 1);
    }
}

//! Share verifier — validate Shamir secret shares before reconstruction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single secret share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub share_id: String,
    pub secret_id: String,
    pub index: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub data: Vec<u8>,
    pub holder: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Share {
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }
}

/// Verification result for a set of shares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub secret_id: String,
    pub shares_present: usize,
    pub threshold: u8,
    pub has_quorum: bool,
    pub duplicates: Vec<u8>,
    pub expired_shares: Vec<String>,
    pub inconsistent_metadata: bool,
    pub ready_to_reconstruct: bool,
}

/// Share verifier.
pub struct ShareVerifier;

impl ShareVerifier {
    pub fn new() -> Self { Self }

    /// Verify a collection of shares for the same secret.
    pub fn verify(&self, shares: &[Share]) -> VerificationResult {
        if shares.is_empty() {
            return VerificationResult {
                secret_id: String::new(),
                shares_present: 0,
                threshold: 0,
                has_quorum: false,
                duplicates: Vec::new(),
                expired_shares: Vec::new(),
                inconsistent_metadata: false,
                ready_to_reconstruct: false,
            };
        }

        let secret_id = shares[0].secret_id.clone();
        let threshold = shares[0].threshold;
        let total = shares[0].total_shares;

        // Metadata consistency check.
        let inconsistent_metadata = shares.iter().any(|s|
            s.secret_id != secret_id
            || s.threshold != threshold
            || s.total_shares != total
        );

        // Duplicate index detection.
        let mut seen_indices = HashMap::new();
        let mut duplicates = Vec::new();
        for s in shares {
            if seen_indices.contains_key(&s.index) {
                duplicates.push(s.index);
            }
            seen_indices.insert(s.index, ());
        }

        // Expiry check.
        let expired: Vec<String> = shares.iter()
            .filter(|s| s.is_expired())
            .map(|s| s.share_id.clone())
            .collect();

        // Count unique usable shares.
        let usable: usize = shares.iter()
            .filter(|s| !s.is_expired())
            .map(|s| s.index)
            .collect::<std::collections::HashSet<_>>()
            .len();

        let has_quorum = usable >= threshold as usize;
        let ready = has_quorum && !inconsistent_metadata;

        VerificationResult {
            secret_id,
            shares_present: shares.len(),
            threshold,
            has_quorum,
            duplicates,
            expired_shares: expired,
            inconsistent_metadata,
            ready_to_reconstruct: ready,
        }
    }

    /// Group shares by secret_id and verify each group.
    pub fn verify_all(&self, shares: &[Share]) -> HashMap<String, VerificationResult> {
        let mut groups: HashMap<String, Vec<Share>> = HashMap::new();
        for s in shares {
            groups.entry(s.secret_id.clone()).or_default().push(s.clone());
        }
        groups.into_iter()
            .map(|(id, group)| (id, self.verify(&group)))
            .collect()
    }
}

impl Default for ShareVerifier {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(secret_id: &str, idx: u8, threshold: u8, total: u8) -> Share {
        Share {
            share_id: format!("{}-{}", secret_id, idx),
            secret_id: secret_id.into(),
            index: idx,
            threshold,
            total_shares: total,
            data: vec![0u8; 32],
            holder: "peer".into(),
            issued_at: Utc::now(),
            expires_at: None,
        }
    }

    #[test]
    fn test_empty_returns_empty() {
        let v = ShareVerifier::new();
        let result = v.verify(&[]);
        assert_eq!(result.shares_present, 0);
        assert!(!result.ready_to_reconstruct);
    }

    #[test]
    fn test_quorum_met() {
        let v = ShareVerifier::new();
        let shares = vec![
            share("s1", 1, 3, 5),
            share("s1", 2, 3, 5),
            share("s1", 3, 3, 5),
        ];
        let result = v.verify(&shares);
        assert!(result.has_quorum);
        assert!(result.ready_to_reconstruct);
    }

    #[test]
    fn test_quorum_not_met() {
        let v = ShareVerifier::new();
        let shares = vec![
            share("s1", 1, 3, 5),
            share("s1", 2, 3, 5),
        ];
        let result = v.verify(&shares);
        assert!(!result.has_quorum);
    }

    #[test]
    fn test_duplicate_indices() {
        let v = ShareVerifier::new();
        let shares = vec![
            share("s1", 1, 3, 5),
            share("s1", 1, 3, 5), // duplicate
            share("s1", 2, 3, 5),
        ];
        let result = v.verify(&shares);
        assert_eq!(result.duplicates, vec![1]);
    }

    #[test]
    fn test_expired_shares() {
        let v = ShareVerifier::new();
        let mut s1 = share("s1", 1, 2, 5);
        s1.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        let shares = vec![
            s1,
            share("s1", 2, 2, 5),
            share("s1", 3, 2, 5),
        ];
        let result = v.verify(&shares);
        assert_eq!(result.expired_shares.len(), 1);
        assert!(result.has_quorum); // 2 unexpired of 3 threshold=2
    }

    #[test]
    fn test_inconsistent_metadata() {
        let v = ShareVerifier::new();
        let mut bad = share("s1", 1, 3, 5);
        bad.threshold = 4;
        let shares = vec![
            bad,
            share("s1", 2, 3, 5),
            share("s1", 3, 3, 5),
        ];
        let result = v.verify(&shares);
        assert!(result.inconsistent_metadata);
        assert!(!result.ready_to_reconstruct);
    }

    #[test]
    fn test_verify_all_groups() {
        let v = ShareVerifier::new();
        let shares = vec![
            share("s1", 1, 2, 3),
            share("s1", 2, 2, 3),
            share("s2", 1, 2, 3),
        ];
        let results = v.verify_all(&shares);
        assert_eq!(results.len(), 2);
        assert!(results["s1"].has_quorum);
        assert!(!results["s2"].has_quorum);
    }

    #[test]
    fn test_expired_below_quorum() {
        let v = ShareVerifier::new();
        let mut s1 = share("s1", 1, 3, 5);
        s1.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        let mut s2 = share("s1", 2, 3, 5);
        s2.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        let shares = vec![
            s1,
            s2,
            share("s1", 3, 3, 5),
        ];
        let result = v.verify(&shares);
        assert!(!result.has_quorum);
    }
}

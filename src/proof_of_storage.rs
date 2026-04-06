//! Proof of storage — challenge/response to verify peers are actually storing data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A storage challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: String,
    pub fragment_id: String,
    pub peer_id: String,
    /// Byte offset to sample.
    pub offset: u64,
    /// Number of bytes to hash.
    pub length: u64,
    /// Nonce to prevent replay.
    pub nonce: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A challenge response from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_id: String,
    pub peer_id: String,
    pub proof_hash: String,
    pub responded_at: DateTime<Utc>,
}

/// Verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    Passed,
    Failed(FailReason),
    Expired,
    NotAnswered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailReason {
    HashMismatch,
    LateResponse,
    WrongPeer,
}

/// Challenge tracker.
pub struct ProofOfStorage {
    challenges: HashMap<String, Challenge>,
    /// Expected proof hashes, keyed by challenge_id.
    expected_hashes: HashMap<String, String>,
    verifications: Vec<Verification>,
    /// Per-peer stats.
    peer_stats: HashMap<String, PeerProofStats>,
}

/// Per-peer proof statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerProofStats {
    pub total_challenges: u64,
    pub passed: u64,
    pub failed: u64,
    pub expired: u64,
    pub last_checked: Option<DateTime<Utc>>,
}

impl PeerProofStats {
    pub fn pass_rate(&self) -> f64 {
        if self.total_challenges == 0 { return 0.0; }
        self.passed as f64 / self.total_challenges as f64
    }
}

/// A verification record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub challenge_id: String,
    pub peer_id: String,
    pub result: VerificationResult,
    pub verified_at: DateTime<Utc>,
}

impl ProofOfStorage {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
            expected_hashes: HashMap::new(),
            verifications: Vec::new(),
            peer_stats: HashMap::new(),
        }
    }

    /// Issue a challenge with the expected proof hash.
    pub fn issue(&mut self, challenge: Challenge, expected_hash: &str) {
        self.expected_hashes.insert(challenge.id.clone(), expected_hash.into());
        self.challenges.insert(challenge.id.clone(), challenge);
    }

    /// Verify a response.
    pub fn verify(&mut self, response: ChallengeResponse) -> VerificationResult {
        let now = Utc::now();
        let challenge = match self.challenges.get(&response.challenge_id) {
            Some(c) => c.clone(),
            None => return VerificationResult::Failed(FailReason::HashMismatch),
        };
        let expected = match self.expected_hashes.get(&response.challenge_id) {
            Some(h) => h.clone(),
            None => return VerificationResult::Failed(FailReason::HashMismatch),
        };

        let result = if response.peer_id != challenge.peer_id {
            VerificationResult::Failed(FailReason::WrongPeer)
        } else if response.responded_at > challenge.expires_at {
            VerificationResult::Expired
        } else if response.proof_hash != expected {
            VerificationResult::Failed(FailReason::HashMismatch)
        } else {
            VerificationResult::Passed
        };

        let stats = self.peer_stats.entry(response.peer_id.clone()).or_default();
        stats.total_challenges += 1;
        stats.last_checked = Some(now);
        match &result {
            VerificationResult::Passed => stats.passed += 1,
            VerificationResult::Expired => stats.expired += 1,
            VerificationResult::Failed(_) => stats.failed += 1,
            VerificationResult::NotAnswered => {}
        }

        self.verifications.push(Verification {
            challenge_id: response.challenge_id.clone(),
            peer_id: response.peer_id.clone(),
            result: result.clone(),
            verified_at: now,
        });

        result
    }

    /// Mark unanswered challenges whose deadline has passed.
    pub fn sweep_expired(&mut self) -> usize {
        let now = Utc::now();
        let mut marked = 0;
        let expired_ids: Vec<String> = self.challenges.iter()
            .filter(|(_, c)| c.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired_ids {
            let challenge = self.challenges.remove(&id).unwrap();
            self.expected_hashes.remove(&id);

            // Did we already have a verification for this challenge?
            let already_verified = self.verifications.iter()
                .any(|v| v.challenge_id == id);
            if !already_verified {
                let stats = self.peer_stats.entry(challenge.peer_id.clone()).or_default();
                stats.total_challenges += 1;
                stats.expired += 1;

                self.verifications.push(Verification {
                    challenge_id: id,
                    peer_id: challenge.peer_id,
                    result: VerificationResult::NotAnswered,
                    verified_at: now,
                });
                marked += 1;
            }
        }
        marked
    }

    /// Get peer stats.
    pub fn stats_for(&self, peer_id: &str) -> Option<&PeerProofStats> {
        self.peer_stats.get(peer_id)
    }

    /// Peers with low pass rate.
    pub fn untrustworthy_peers(&self, min_pass_rate: f64) -> Vec<&String> {
        self.peer_stats.iter()
            .filter(|(_, s)| s.total_challenges >= 5 && s.pass_rate() < min_pass_rate)
            .map(|(id, _)| id)
            .collect()
    }

    /// Verification history.
    pub fn verifications(&self) -> &[Verification] {
        &self.verifications
    }

    pub fn challenge_count(&self) -> usize { self.challenges.len() }
    pub fn verification_count(&self) -> usize { self.verifications.len() }
}

impl Default for ProofOfStorage {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(id: &str, peer: &str) -> Challenge {
        Challenge {
            id: id.into(),
            fragment_id: "frag1".into(),
            peer_id: peer.into(),
            offset: 100,
            length: 256,
            nonce: "abc".into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
        }
    }

    fn response(id: &str, peer: &str, hash: &str) -> ChallengeResponse {
        ChallengeResponse {
            challenge_id: id.into(),
            peer_id: peer.into(),
            proof_hash: hash.into(),
            responded_at: Utc::now(),
        }
    }

    #[test]
    fn test_passed_verification() {
        let mut p = ProofOfStorage::new();
        p.issue(challenge("c1", "peer1"), "correct_hash");
        let result = p.verify(response("c1", "peer1", "correct_hash"));
        assert_eq!(result, VerificationResult::Passed);
    }

    #[test]
    fn test_hash_mismatch() {
        let mut p = ProofOfStorage::new();
        p.issue(challenge("c1", "peer1"), "correct_hash");
        let result = p.verify(response("c1", "peer1", "wrong_hash"));
        assert!(matches!(result, VerificationResult::Failed(FailReason::HashMismatch)));
    }

    #[test]
    fn test_wrong_peer() {
        let mut p = ProofOfStorage::new();
        p.issue(challenge("c1", "peer1"), "correct_hash");
        let result = p.verify(response("c1", "peer2", "correct_hash"));
        assert!(matches!(result, VerificationResult::Failed(FailReason::WrongPeer)));
    }

    #[test]
    fn test_stats_tracking() {
        let mut p = ProofOfStorage::new();
        p.issue(challenge("c1", "peer1"), "h");
        p.issue(challenge("c2", "peer1"), "h");
        p.verify(response("c1", "peer1", "h"));
        p.verify(response("c2", "peer1", "wrong"));
        let stats = p.stats_for("peer1").unwrap();
        assert_eq!(stats.passed, 1);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn test_pass_rate() {
        let stats = PeerProofStats {
            total_challenges: 10,
            passed: 8,
            failed: 2,
            expired: 0,
            last_checked: None,
        };
        assert_eq!(stats.pass_rate(), 0.8);
    }

    #[test]
    fn test_untrustworthy() {
        let mut p = ProofOfStorage::new();
        for i in 0..10 {
            p.issue(challenge(&format!("c{}", i), "bad"), "h");
            p.verify(response(&format!("c{}", i), "bad", "wrong"));
        }
        let untrust = p.untrustworthy_peers(0.5);
        assert!(untrust.iter().any(|p| *p == "bad"));
    }

    #[test]
    fn test_sweep_expired() {
        let mut p = ProofOfStorage::new();
        let mut c = challenge("c1", "peer1");
        c.expires_at = Utc::now() - chrono::Duration::seconds(1);
        p.issue(c, "h");
        let marked = p.sweep_expired();
        assert_eq!(marked, 1);
    }

    #[test]
    fn test_unknown_challenge() {
        let mut p = ProofOfStorage::new();
        let result = p.verify(response("unknown", "peer", "h"));
        assert!(matches!(result, VerificationResult::Failed(_)));
    }
}

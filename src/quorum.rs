//! Quorum decisions for distributed operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A quorum vote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter: String,
    pub decision: VoteDecision,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteDecision {
    Approve,
    Reject,
    Abstain,
}

/// Quorum result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumResult {
    Approved { approve_count: usize, reject_count: usize },
    Rejected { approve_count: usize, reject_count: usize },
    Pending { needed: usize, received: usize },
    Failed { reason: String },
}

/// Quorum proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
    pub votes: Vec<Vote>,
    pub voters_needed: HashSet<String>,
    pub min_quorum: usize,
}

/// Quorum manager.
pub struct QuorumManager {
    proposals: HashMap<String, Proposal>,
}

impl QuorumManager {
    pub fn new() -> Self {
        Self { proposals: HashMap::new() }
    }

    /// Create a new proposal.
    pub fn create_proposal(
        &mut self,
        proposal_id: &str,
        description: &str,
        voters: HashSet<String>,
        min_quorum: usize,
    ) {
        self.proposals.insert(proposal_id.into(), Proposal {
            proposal_id: proposal_id.into(),
            description: description.into(),
            created_at: Utc::now(),
            votes: Vec::new(),
            voters_needed: voters,
            min_quorum,
        });
    }

    /// Cast a vote.
    pub fn vote(&mut self, proposal_id: &str, voter: &str, decision: VoteDecision) -> bool {
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            // Voter must be in the eligible set.
            if !proposal.voters_needed.contains(voter) {
                return false;
            }
            // Check if already voted.
            if proposal.votes.iter().any(|v| v.voter == voter) {
                return false;
            }
            proposal.votes.push(Vote {
                voter: voter.into(),
                decision,
                timestamp: Utc::now(),
            });
            true
        } else {
            false
        }
    }

    /// Compute the current result.
    pub fn result(&self, proposal_id: &str) -> QuorumResult {
        if let Some(proposal) = self.proposals.get(proposal_id) {
            let approve = proposal.votes.iter().filter(|v| v.decision == VoteDecision::Approve).count();
            let reject = proposal.votes.iter().filter(|v| v.decision == VoteDecision::Reject).count();
            let total = proposal.votes.len();

            if total < proposal.min_quorum {
                return QuorumResult::Pending {
                    needed: proposal.min_quorum,
                    received: total,
                };
            }

            if approve > reject {
                QuorumResult::Approved { approve_count: approve, reject_count: reject }
            } else {
                QuorumResult::Rejected { approve_count: approve, reject_count: reject }
            }
        } else {
            QuorumResult::Failed { reason: "proposal not found".into() }
        }
    }

    /// Get a proposal.
    pub fn get(&self, proposal_id: &str) -> Option<&Proposal> {
        self.proposals.get(proposal_id)
    }

    pub fn proposal_count(&self) -> usize { self.proposals.len() }
}

impl Default for QuorumManager {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn voters(n: usize) -> HashSet<String> {
        (0..n).map(|i| format!("voter{i}")).collect()
    }

    #[test]
    fn test_create_proposal() {
        let mut mgr = QuorumManager::new();
        mgr.create_proposal("p1", "test", voters(5), 3);
        assert_eq!(mgr.proposal_count(), 1);
    }

    #[test]
    fn test_vote() {
        let mut mgr = QuorumManager::new();
        mgr.create_proposal("p1", "test", voters(5), 3);
        assert!(mgr.vote("p1", "voter0", VoteDecision::Approve));
    }

    #[test]
    fn test_no_double_vote() {
        let mut mgr = QuorumManager::new();
        mgr.create_proposal("p1", "test", voters(5), 3);
        assert!(mgr.vote("p1", "voter0", VoteDecision::Approve));
        assert!(!mgr.vote("p1", "voter0", VoteDecision::Reject));
    }

    #[test]
    fn test_unauthorized_voter() {
        let mut mgr = QuorumManager::new();
        mgr.create_proposal("p1", "test", voters(3), 2);
        assert!(!mgr.vote("p1", "outsider", VoteDecision::Approve));
    }

    #[test]
    fn test_pending_result() {
        let mut mgr = QuorumManager::new();
        mgr.create_proposal("p1", "test", voters(5), 3);
        mgr.vote("p1", "voter0", VoteDecision::Approve);
        match mgr.result("p1") {
            QuorumResult::Pending { needed, received } => {
                assert_eq!(needed, 3);
                assert_eq!(received, 1);
            }
            _ => panic!("Expected pending"),
        }
    }

    #[test]
    fn test_approved() {
        let mut mgr = QuorumManager::new();
        mgr.create_proposal("p1", "test", voters(5), 3);
        mgr.vote("p1", "voter0", VoteDecision::Approve);
        mgr.vote("p1", "voter1", VoteDecision::Approve);
        mgr.vote("p1", "voter2", VoteDecision::Approve);
        match mgr.result("p1") {
            QuorumResult::Approved { .. } => {}
            other => panic!("Expected approved, got {:?}", other),
        }
    }

    #[test]
    fn test_rejected() {
        let mut mgr = QuorumManager::new();
        mgr.create_proposal("p1", "test", voters(5), 3);
        mgr.vote("p1", "voter0", VoteDecision::Reject);
        mgr.vote("p1", "voter1", VoteDecision::Reject);
        mgr.vote("p1", "voter2", VoteDecision::Approve);
        match mgr.result("p1") {
            QuorumResult::Rejected { .. } => {}
            other => panic!("Expected rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_unknown_proposal() {
        let mgr = QuorumManager::new();
        match mgr.result("nonexistent") {
            QuorumResult::Failed { .. } => {}
            _ => panic!("Expected failed"),
        }
    }
}

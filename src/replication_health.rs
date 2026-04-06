//! Replication health — measure fragment redundancy and identify at-risk data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A fragment's replication state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentReplication {
    pub fragment_id: String,
    pub replicas: Vec<Replica>,
    pub target_replicas: u8,
    pub last_verified: DateTime<Utc>,
}

/// A single replica placement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Replica {
    pub peer_id: String,
    pub placed_at: DateTime<Utc>,
    pub last_health_check: DateTime<Utc>,
    pub status: ReplicaStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicaStatus {
    Healthy,
    Degraded,
    Unreachable,
    Corrupted,
}

impl FragmentReplication {
    /// Number of currently-healthy replicas.
    pub fn healthy_count(&self) -> usize {
        self.replicas.iter().filter(|r| r.status == ReplicaStatus::Healthy).count()
    }

    /// Number of reachable (healthy or degraded) replicas.
    pub fn reachable_count(&self) -> usize {
        self.replicas.iter()
            .filter(|r| r.status == ReplicaStatus::Healthy || r.status == ReplicaStatus::Degraded)
            .count()
    }

    /// Health ratio compared to target.
    pub fn health_ratio(&self) -> f64 {
        if self.target_replicas == 0 {
            return 1.0;
        }
        self.healthy_count() as f64 / self.target_replicas as f64
    }

    /// Is the fragment fully replicated?
    pub fn is_fully_replicated(&self) -> bool {
        self.healthy_count() >= self.target_replicas as usize
    }

    /// Is the fragment critically under-replicated?
    pub fn is_critical(&self) -> bool {
        self.healthy_count() == 0 || self.health_ratio() < 0.5
    }

    /// Is the fragment at risk (below target but not critical)?
    pub fn is_at_risk(&self) -> bool {
        !self.is_fully_replicated() && !self.is_critical()
    }
}

/// Replication health overview.
pub struct ReplicationHealth {
    fragments: HashMap<String, FragmentReplication>,
}

impl ReplicationHealth {
    pub fn new() -> Self {
        Self { fragments: HashMap::new() }
    }

    pub fn record(&mut self, fragment: FragmentReplication) {
        self.fragments.insert(fragment.fragment_id.clone(), fragment);
    }

    pub fn remove(&mut self, fragment_id: &str) {
        self.fragments.remove(fragment_id);
    }

    pub fn get(&self, fragment_id: &str) -> Option<&FragmentReplication> {
        self.fragments.get(fragment_id)
    }

    /// Update a single replica's status.
    pub fn update_replica(&mut self, fragment_id: &str, peer_id: &str, status: ReplicaStatus) -> bool {
        if let Some(frag) = self.fragments.get_mut(fragment_id) {
            if let Some(r) = frag.replicas.iter_mut().find(|r| r.peer_id == peer_id) {
                r.status = status;
                r.last_health_check = Utc::now();
                return true;
            }
        }
        false
    }

    /// All critically under-replicated fragments.
    pub fn critical_fragments(&self) -> Vec<&FragmentReplication> {
        self.fragments.values().filter(|f| f.is_critical()).collect()
    }

    /// At-risk fragments (under target but not critical).
    pub fn at_risk_fragments(&self) -> Vec<&FragmentReplication> {
        self.fragments.values().filter(|f| f.is_at_risk()).collect()
    }

    /// Fully-replicated fragments.
    pub fn healthy_fragments(&self) -> Vec<&FragmentReplication> {
        self.fragments.values().filter(|f| f.is_fully_replicated()).collect()
    }

    /// Cluster-wide average health ratio.
    pub fn average_health(&self) -> f64 {
        if self.fragments.is_empty() {
            return 1.0;
        }
        let sum: f64 = self.fragments.values().map(|f| f.health_ratio()).sum();
        sum / self.fragments.len() as f64
    }

    /// Fragments dependent on a specific peer.
    pub fn fragments_on_peer(&self, peer_id: &str) -> Vec<&FragmentReplication> {
        self.fragments.values()
            .filter(|f| f.replicas.iter().any(|r| r.peer_id == peer_id))
            .collect()
    }

    /// Fragments that would become critical if a peer left.
    pub fn vulnerable_to_peer_loss(&self, peer_id: &str) -> Vec<&FragmentReplication> {
        self.fragments.values()
            .filter(|f| {
                let healthy_excluding = f.replicas.iter()
                    .filter(|r| r.peer_id != peer_id && r.status == ReplicaStatus::Healthy)
                    .count();
                let target = f.target_replicas as usize;
                healthy_excluding < target / 2
            })
            .collect()
    }

    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }
}

impl Default for ReplicationHealth {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(peer: &str, status: ReplicaStatus) -> Replica {
        Replica {
            peer_id: peer.into(),
            placed_at: Utc::now(),
            last_health_check: Utc::now(),
            status,
        }
    }

    fn fragment(id: &str, replicas: Vec<Replica>, target: u8) -> FragmentReplication {
        FragmentReplication {
            fragment_id: id.into(),
            replicas,
            target_replicas: target,
            last_verified: Utc::now(),
        }
    }

    #[test]
    fn test_fully_replicated() {
        let f = fragment("f1",
            vec![
                replica("p1", ReplicaStatus::Healthy),
                replica("p2", ReplicaStatus::Healthy),
                replica("p3", ReplicaStatus::Healthy),
            ], 3);
        assert!(f.is_fully_replicated());
        assert_eq!(f.healthy_count(), 3);
    }

    #[test]
    fn test_critical_no_healthy() {
        let f = fragment("f1",
            vec![
                replica("p1", ReplicaStatus::Unreachable),
                replica("p2", ReplicaStatus::Corrupted),
            ], 3);
        assert!(f.is_critical());
    }

    #[test]
    fn test_at_risk() {
        let f = fragment("f1",
            vec![
                replica("p1", ReplicaStatus::Healthy),
                replica("p2", ReplicaStatus::Healthy),
                replica("p3", ReplicaStatus::Unreachable),
            ], 3);
        assert!(f.is_at_risk());
    }

    #[test]
    fn test_record_and_get() {
        let mut h = ReplicationHealth::new();
        let f = fragment("f1", vec![replica("p1", ReplicaStatus::Healthy)], 1);
        h.record(f);
        assert!(h.get("f1").is_some());
    }

    #[test]
    fn test_update_replica() {
        let mut h = ReplicationHealth::new();
        h.record(fragment("f1", vec![replica("p1", ReplicaStatus::Healthy)], 1));
        assert!(h.update_replica("f1", "p1", ReplicaStatus::Unreachable));
        assert_eq!(h.get("f1").unwrap().replicas[0].status, ReplicaStatus::Unreachable);
    }

    #[test]
    fn test_critical_fragments() {
        let mut h = ReplicationHealth::new();
        h.record(fragment("good",
            vec![replica("p1", ReplicaStatus::Healthy), replica("p2", ReplicaStatus::Healthy)], 2));
        h.record(fragment("bad",
            vec![replica("p1", ReplicaStatus::Unreachable)], 3));
        assert_eq!(h.critical_fragments().len(), 1);
    }

    #[test]
    fn test_average_health() {
        let mut h = ReplicationHealth::new();
        h.record(fragment("f1",
            vec![replica("p1", ReplicaStatus::Healthy), replica("p2", ReplicaStatus::Healthy)], 2));
        assert!((h.average_health() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_fragments_on_peer() {
        let mut h = ReplicationHealth::new();
        h.record(fragment("f1",
            vec![replica("p1", ReplicaStatus::Healthy)], 1));
        h.record(fragment("f2",
            vec![replica("p2", ReplicaStatus::Healthy)], 1));
        assert_eq!(h.fragments_on_peer("p1").len(), 1);
    }

    #[test]
    fn test_vulnerable_to_peer_loss() {
        let mut h = ReplicationHealth::new();
        h.record(fragment("risky",
            vec![
                replica("p1", ReplicaStatus::Healthy),
                replica("p2", ReplicaStatus::Unreachable),
            ], 4));
        let vuln = h.vulnerable_to_peer_loss("p1");
        assert_eq!(vuln.len(), 1);
    }
}

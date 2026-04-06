//! Replication strategy — manages how fragments are duplicated across peers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Replication strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Strategy {
    /// Simple N replicas.
    SimpleReplication,
    /// Erasure coding (k of n).
    ErasureCoding,
    /// Hybrid: erasure coding + extra replicas of critical shards.
    Hybrid,
    /// No replication (single copy).
    None,
}

/// Replication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    pub strategy: Strategy,
    pub replication_factor: u8,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub min_replicas: u8,
    pub target_replicas: u8,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            strategy: Strategy::Hybrid,
            replication_factor: 3,
            data_shards: 4,
            parity_shards: 2,
            min_replicas: 2,
            target_replicas: 5,
        }
    }
}

/// Replication state for a fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentReplication {
    pub fragment_id: String,
    pub current_replicas: u8,
    pub healthy_replicas: u8,
    pub peers: Vec<String>,
    pub status: ReplicationStatus,
}

/// Status of replication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplicationStatus {
    Healthy,
    Underreplicated,
    AtRisk,
    Critical,
    Lost,
}

/// Replication manager.
pub struct ReplicationManager {
    config: ReplicationConfig,
    fragments: HashMap<String, FragmentReplication>,
}

impl ReplicationManager {
    pub fn new(config: ReplicationConfig) -> Self {
        Self {
            config,
            fragments: HashMap::new(),
        }
    }

    /// Register a fragment for replication tracking.
    pub fn register(&mut self, fragment_id: &str, peers: Vec<String>) {
        let count = peers.len() as u8;
        let status = self.compute_status(count);
        self.fragments.insert(fragment_id.into(), FragmentReplication {
            fragment_id: fragment_id.into(),
            current_replicas: count,
            healthy_replicas: count,
            peers,
            status,
        });
    }

    /// Mark a peer as having lost a fragment.
    pub fn mark_lost(&mut self, fragment_id: &str, peer: &str) {
        if let Some(frag) = self.fragments.get_mut(fragment_id) {
            frag.peers.retain(|p| p != peer);
            frag.current_replicas = frag.peers.len() as u8;
            frag.healthy_replicas = frag.current_replicas;
            frag.status = self.compute_status(frag.current_replicas);
        }
    }

    /// Add a new replica peer.
    pub fn add_replica(&mut self, fragment_id: &str, peer: String) {
        if let Some(frag) = self.fragments.get_mut(fragment_id) {
            if !frag.peers.contains(&peer) {
                frag.peers.push(peer);
                frag.current_replicas = frag.peers.len() as u8;
                frag.healthy_replicas = frag.current_replicas;
                frag.status = self.compute_status(frag.current_replicas);
            }
        }
    }

    fn compute_status(&self, replica_count: u8) -> ReplicationStatus {
        if replica_count == 0 { ReplicationStatus::Lost }
        else if replica_count < self.config.min_replicas { ReplicationStatus::Critical }
        else if replica_count < self.config.target_replicas / 2 { ReplicationStatus::AtRisk }
        else if replica_count < self.config.target_replicas { ReplicationStatus::Underreplicated }
        else { ReplicationStatus::Healthy }
    }

    /// Get fragments needing more replicas.
    pub fn underreplicated(&self) -> Vec<&FragmentReplication> {
        self.fragments.values()
            .filter(|f| f.status != ReplicationStatus::Healthy)
            .collect()
    }

    /// Get critical fragments (below min_replicas).
    pub fn critical(&self) -> Vec<&FragmentReplication> {
        self.fragments.values()
            .filter(|f| matches!(f.status, ReplicationStatus::Critical | ReplicationStatus::Lost))
            .collect()
    }

    pub fn total_fragments(&self) -> usize { self.fragments.len() }
    pub fn healthy_count(&self) -> usize {
        self.fragments.values().filter(|f| f.status == ReplicationStatus::Healthy).count()
    }
}

impl Default for ReplicationManager {
    fn default() -> Self { Self::new(ReplicationConfig::default()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peers(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("peer{i}")).collect()
    }

    #[test]
    fn test_healthy_replication() {
        let mut mgr = ReplicationManager::default();
        mgr.register("frag1", peers(5));
        let frag = mgr.fragments.get("frag1").unwrap();
        assert_eq!(frag.status, ReplicationStatus::Healthy);
    }

    #[test]
    fn test_underreplicated() {
        let mut mgr = ReplicationManager::default();
        mgr.register("frag1", peers(3));
        let frag = mgr.fragments.get("frag1").unwrap();
        assert_eq!(frag.status, ReplicationStatus::Underreplicated);
    }

    #[test]
    fn test_critical() {
        let mut mgr = ReplicationManager::default();
        mgr.register("frag1", peers(1));
        assert_eq!(mgr.critical().len(), 1);
    }

    #[test]
    fn test_lost() {
        let mut mgr = ReplicationManager::default();
        mgr.register("frag1", peers(0));
        let frag = mgr.fragments.get("frag1").unwrap();
        assert_eq!(frag.status, ReplicationStatus::Lost);
    }

    #[test]
    fn test_mark_lost() {
        let mut mgr = ReplicationManager::default();
        mgr.register("frag1", peers(5));
        mgr.mark_lost("frag1", "peer0");
        let frag = mgr.fragments.get("frag1").unwrap();
        assert_eq!(frag.current_replicas, 4);
    }

    #[test]
    fn test_add_replica() {
        let mut mgr = ReplicationManager::default();
        mgr.register("frag1", peers(3));
        mgr.add_replica("frag1", "peer3".into());
        mgr.add_replica("frag1", "peer4".into());
        let frag = mgr.fragments.get("frag1").unwrap();
        assert_eq!(frag.current_replicas, 5);
        assert_eq!(frag.status, ReplicationStatus::Healthy);
    }

    #[test]
    fn test_no_duplicate_replicas() {
        let mut mgr = ReplicationManager::default();
        mgr.register("frag1", peers(3));
        mgr.add_replica("frag1", "peer0".into()); // Already exists.
        assert_eq!(mgr.fragments.get("frag1").unwrap().current_replicas, 3);
    }

    #[test]
    fn test_underreplicated_list() {
        let mut mgr = ReplicationManager::default();
        mgr.register("healthy", peers(5));
        mgr.register("low", peers(2));
        assert_eq!(mgr.underreplicated().len(), 1);
    }

    #[test]
    fn test_healthy_count() {
        let mut mgr = ReplicationManager::default();
        mgr.register("a", peers(5));
        mgr.register("b", peers(5));
        mgr.register("c", peers(2));
        assert_eq!(mgr.healthy_count(), 2);
    }
}

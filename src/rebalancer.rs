//! Fragment rebalancer — redistribute fragments across peers for optimal load.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A peer's current fragment load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerLoad {
    pub peer_id: String,
    pub fragment_count: usize,
    pub bytes_stored: u64,
    pub capacity_bytes: u64,
    pub reliability: f64, // 0.0-1.0
}

impl PeerLoad {
    pub fn utilization(&self) -> f64 {
        if self.capacity_bytes == 0 {
            return 1.0;
        }
        self.bytes_stored as f64 / self.capacity_bytes as f64
    }

    pub fn free_bytes(&self) -> u64 {
        self.capacity_bytes.saturating_sub(self.bytes_stored)
    }

    pub fn has_room_for(&self, bytes: u64) -> bool {
        self.free_bytes() >= bytes
    }
}

/// A rebalancing action to take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebalanceMove {
    pub fragment_id: String,
    pub from_peer: String,
    pub to_peer: String,
    pub bytes: u64,
    pub reason: RebalanceReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RebalanceReason {
    SourceOverloaded,
    TargetUnderutilized,
    LowReliabilitySource,
    HighReliabilityTarget,
    CapacityPressure,
}

/// Fragment rebalancer.
pub struct Rebalancer {
    /// Target utilization range. Moves trigger when outside this.
    pub min_util: f64,
    pub max_util: f64,
    /// Minimum reliability to keep fragments on a peer.
    pub min_reliability: f64,
}

impl Rebalancer {
    pub fn new() -> Self {
        Self {
            min_util: 0.10,
            max_util: 0.85,
            min_reliability: 0.75,
        }
    }

    /// Plan rebalance moves to smooth load across peers.
    pub fn plan_moves(
        &self,
        peers: &[PeerLoad],
        fragments_per_peer: &HashMap<String, Vec<(String, u64)>>, // peer_id → [(fragment_id, bytes)]
    ) -> Vec<RebalanceMove> {
        let mut moves = Vec::new();

        let mean_util = peers.iter().map(|p| p.utilization()).sum::<f64>()
            / peers.len().max(1) as f64;

        // Work on a snapshot of peer state so we can account for in-plan moves.
        let mut state: HashMap<String, PeerLoad> = peers.iter()
            .map(|p| (p.peer_id.clone(), p.clone())).collect();

        for source in peers {
            let needs_offload = source.utilization() > self.max_util
                || source.utilization() > mean_util + 0.2
                || source.reliability < self.min_reliability;
            if !needs_offload { continue; }

            let Some(frags) = fragments_per_peer.get(&source.peer_id) else { continue };
            for (frag_id, bytes) in frags {
                // Find a target peer.
                let mut candidates: Vec<&PeerLoad> = state.values()
                    .filter(|p| p.peer_id != source.peer_id)
                    .filter(|p| p.reliability >= self.min_reliability)
                    .filter(|p| p.has_room_for(*bytes))
                    .filter(|p| p.utilization() < mean_util)
                    .collect();
                candidates.sort_by(|a, b|
                    a.utilization().partial_cmp(&b.utilization()).unwrap_or(std::cmp::Ordering::Equal)); // SAFETY: utilization is bytes_used/bytes_total in [0.0, 1.0]; never NaN but Equal fallback for total ordering

                if let Some(target) = candidates.first() {
                    let target_id = target.peer_id.clone();
                    let reason = if source.reliability < self.min_reliability {
                        RebalanceReason::LowReliabilitySource
                    } else if source.utilization() > self.max_util {
                        RebalanceReason::SourceOverloaded
                    } else {
                        RebalanceReason::CapacityPressure
                    };
                    moves.push(RebalanceMove {
                        fragment_id: frag_id.clone(),
                        from_peer: source.peer_id.clone(),
                        to_peer: target_id.clone(),
                        bytes: *bytes,
                        reason,
                    });
                    // Update snapshot.
                    if let Some(s) = state.get_mut(&source.peer_id) {
                        s.bytes_stored = s.bytes_stored.saturating_sub(*bytes);
                        s.fragment_count = s.fragment_count.saturating_sub(1);
                    }
                    if let Some(t) = state.get_mut(&target_id) {
                        t.bytes_stored += *bytes;
                        t.fragment_count += 1;
                    }
                }
            }
        }

        moves
    }

    /// Compute cluster-wide statistics.
    pub fn cluster_stats(&self, peers: &[PeerLoad]) -> ClusterStats {
        let total_capacity: u64 = peers.iter().map(|p| p.capacity_bytes).sum();
        let total_stored: u64 = peers.iter().map(|p| p.bytes_stored).sum();
        let utils: Vec<f64> = peers.iter().map(|p| p.utilization()).collect();
        let mean = if utils.is_empty() { 0.0 } else { utils.iter().sum::<f64>() / utils.len() as f64 };
        let variance = if utils.is_empty() { 0.0 }
            else { utils.iter().map(|u| (u - mean).powi(2)).sum::<f64>() / utils.len() as f64 };

        ClusterStats {
            peer_count: peers.len(),
            total_capacity,
            total_stored,
            mean_utilization: mean,
            utilization_variance: variance,
            overloaded_peers: peers.iter()
                .filter(|p| p.utilization() > self.max_util)
                .count(),
            low_reliability_peers: peers.iter()
                .filter(|p| p.reliability < self.min_reliability)
                .count(),
        }
    }
}

impl Default for Rebalancer {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStats {
    pub peer_count: usize,
    pub total_capacity: u64,
    pub total_stored: u64,
    pub mean_utilization: f64,
    pub utilization_variance: f64,
    pub overloaded_peers: usize,
    pub low_reliability_peers: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str, stored: u64, cap: u64, reliability: f64) -> PeerLoad {
        PeerLoad {
            peer_id: id.into(),
            fragment_count: 1,
            bytes_stored: stored,
            capacity_bytes: cap,
            reliability,
        }
    }

    #[test]
    fn test_utilization() {
        let p = peer("a", 50, 100, 1.0);
        assert_eq!(p.utilization(), 0.5);
        assert_eq!(p.free_bytes(), 50);
        assert!(p.has_room_for(40));
        assert!(!p.has_room_for(100));
    }

    #[test]
    fn test_plan_offload_from_overloaded() {
        let r = Rebalancer::new();
        let peers = vec![
            peer("hot", 90, 100, 1.0), // overloaded
            peer("cold", 10, 100, 1.0),
        ];
        let mut frags: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        frags.insert("hot".into(), vec![("f1".into(), 20)]);

        let moves = r.plan_moves(&peers, &frags);
        assert_eq!(moves.len(), 1);
        assert_eq!(moves[0].from_peer, "hot");
        assert_eq!(moves[0].to_peer, "cold");
    }

    #[test]
    fn test_low_reliability_source_drained() {
        let r = Rebalancer::new();
        let peers = vec![
            peer("flaky", 50, 100, 0.3), // below min_reliability
            peer("solid", 10, 100, 0.99),
        ];
        let mut frags: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        frags.insert("flaky".into(), vec![("f1".into(), 10), ("f2".into(), 10)]);

        let moves = r.plan_moves(&peers, &frags);
        assert_eq!(moves.len(), 2);
        assert!(moves.iter().all(|m| m.reason == RebalanceReason::LowReliabilitySource));
    }

    #[test]
    fn test_cluster_stats() {
        let r = Rebalancer::new();
        let peers = vec![
            peer("a", 50, 100, 0.9),
            peer("b", 50, 100, 0.9),
        ];
        let stats = r.cluster_stats(&peers);
        assert_eq!(stats.peer_count, 2);
        assert_eq!(stats.total_capacity, 200);
        assert_eq!(stats.total_stored, 100);
        assert!((stats.mean_utilization - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_no_suitable_target() {
        let r = Rebalancer::new();
        let peers = vec![
            peer("hot", 90, 100, 1.0),
            peer("full", 95, 100, 1.0), // no room
        ];
        let mut frags: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        frags.insert("hot".into(), vec![("f1".into(), 20)]);
        let moves = r.plan_moves(&peers, &frags);
        assert!(moves.is_empty());
    }

    #[test]
    fn test_balanced_cluster_no_moves() {
        let r = Rebalancer::new();
        let peers = vec![
            peer("a", 50, 100, 1.0),
            peer("b", 50, 100, 1.0),
            peer("c", 50, 100, 1.0),
        ];
        let frags: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        let moves = r.plan_moves(&peers, &frags);
        assert!(moves.is_empty());
    }

    #[test]
    fn test_overloaded_count() {
        let r = Rebalancer::new();
        let peers = vec![
            peer("a", 95, 100, 1.0),
            peer("b", 20, 100, 1.0),
        ];
        let stats = r.cluster_stats(&peers);
        assert_eq!(stats.overloaded_peers, 1);
    }
}

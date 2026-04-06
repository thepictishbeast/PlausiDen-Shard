//! Fragment routing — determines where shards are distributed.
//!
//! Implements geographic diversity, redundancy targets, and avoidance
//! constraints to ensure fragments survive even coordinated takedowns.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A storage peer that can hold fragments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePeer {
    pub peer_id: String,
    pub region: String,
    pub capacity_bytes: u64,
    pub used_bytes: u64,
    pub reliability_score: f64,
    pub latency_ms: u32,
    pub online: bool,
}

impl StoragePeer {
    /// Available capacity in bytes.
    pub fn available(&self) -> u64 {
        self.capacity_bytes.saturating_sub(self.used_bytes)
    }

    /// Utilization as a fraction [0.0, 1.0].
    pub fn utilization(&self) -> f64 {
        if self.capacity_bytes == 0 { return 1.0; }
        self.used_bytes as f64 / self.capacity_bytes as f64
    }
}

/// Constraints for fragment placement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementConstraints {
    /// Minimum number of distinct regions for redundancy.
    pub min_regions: usize,
    /// Maximum fraction of fragments on a single peer.
    pub max_per_peer_fraction: f64,
    /// Peers to avoid (e.g., compromised or untrusted).
    pub avoid_peers: HashSet<String>,
    /// Regions to avoid.
    pub avoid_regions: HashSet<String>,
    /// Prefer peers with reliability above this threshold.
    pub min_reliability: f64,
}

impl Default for PlacementConstraints {
    fn default() -> Self {
        Self {
            min_regions: 2,
            max_per_peer_fraction: 0.5,
            avoid_peers: HashSet::new(),
            avoid_regions: HashSet::new(),
            min_reliability: 0.7,
        }
    }
}

/// A placement decision for a set of fragments.
#[derive(Debug, Clone)]
pub struct PlacementPlan {
    /// Maps fragment index to list of peers that should store it.
    pub assignments: HashMap<usize, Vec<String>>,
    /// Number of distinct regions used.
    pub regions_used: usize,
    /// Whether all constraints were satisfied.
    pub fully_satisfied: bool,
    /// Warnings about partially met constraints.
    pub warnings: Vec<String>,
}

/// Fragment routing engine.
pub struct FragmentRouter {
    peers: Vec<StoragePeer>,
    constraints: PlacementConstraints,
}

impl FragmentRouter {
    pub fn new(constraints: PlacementConstraints) -> Self {
        Self {
            peers: Vec::new(),
            constraints,
        }
    }

    /// Register a storage peer.
    pub fn add_peer(&mut self, peer: StoragePeer) {
        self.peers.push(peer);
    }

    /// Get eligible peers (online, not avoided, sufficient reliability).
    fn eligible_peers(&self) -> Vec<&StoragePeer> {
        self.peers
            .iter()
            .filter(|p| {
                p.online
                    && !self.constraints.avoid_peers.contains(&p.peer_id)
                    && !self.constraints.avoid_regions.contains(&p.region)
                    && p.reliability_score >= self.constraints.min_reliability
                    && p.available() > 0
            })
            .collect()
    }

    /// Plan fragment placement for `n` fragments, each replicated `r` times.
    pub fn plan_placement(&self, fragment_count: usize, replication: usize) -> PlacementPlan {
        let eligible = self.eligible_peers();
        let mut assignments: HashMap<usize, Vec<String>> = HashMap::new();
        let mut warnings = Vec::new();
        let mut regions_used: HashSet<String> = HashSet::new();

        if eligible.is_empty() {
            warnings.push("No eligible peers available".into());
            return PlacementPlan {
                assignments,
                regions_used: 0,
                fully_satisfied: false,
                warnings,
            };
        }

        // Sort peers: prefer low utilization, high reliability.
        let mut sorted_peers: Vec<&StoragePeer> = eligible;
        sorted_peers.sort_by(|a, b| {
            let score_a = a.utilization() - a.reliability_score;
            let score_b = b.utilization() - b.reliability_score;
            score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
        });

        for frag_idx in 0..fragment_count {
            let mut assigned: Vec<String> = Vec::new();
            let mut used_regions: HashSet<String> = HashSet::new();

            for peer in &sorted_peers {
                if assigned.len() >= replication {
                    break;
                }

                // Check max-per-peer constraint.
                let peer_fragment_count = assignments
                    .values()
                    .filter(|v| v.contains(&peer.peer_id))
                    .count();
                let max_allowed = (fragment_count as f64 * self.constraints.max_per_peer_fraction).ceil() as usize;
                if peer_fragment_count >= max_allowed {
                    continue;
                }

                // Prefer geographic diversity.
                if used_regions.contains(&peer.region) && assigned.len() < replication - 1 {
                    // Try to find a peer in a different region first.
                    continue;
                }

                assigned.push(peer.peer_id.clone());
                used_regions.insert(peer.region.clone());
                regions_used.insert(peer.region.clone());
            }

            // If we couldn't get enough replicas with region diversity, relax the constraint.
            if assigned.len() < replication {
                for peer in &sorted_peers {
                    if assigned.len() >= replication {
                        break;
                    }
                    if !assigned.contains(&peer.peer_id) {
                        assigned.push(peer.peer_id.clone());
                        regions_used.insert(peer.region.clone());
                    }
                }
            }

            if assigned.len() < replication {
                warnings.push(format!(
                    "Fragment {frag_idx}: only {} replicas (wanted {replication})",
                    assigned.len()
                ));
            }

            assignments.insert(frag_idx, assigned);
        }

        if regions_used.len() < self.constraints.min_regions {
            warnings.push(format!(
                "Only {} regions used (minimum: {})",
                regions_used.len(), self.constraints.min_regions
            ));
        }

        PlacementPlan {
            assignments,
            regions_used: regions_used.len(),
            fully_satisfied: warnings.is_empty(),
            warnings,
        }
    }

    /// Get the number of registered peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the number of eligible peers.
    pub fn eligible_count(&self) -> usize {
        self.eligible_peers().len()
    }

    /// Total available capacity across all eligible peers.
    pub fn total_available(&self) -> u64 {
        self.eligible_peers().iter().map(|p| p.available()).sum()
    }
}

impl Default for FragmentRouter {
    fn default() -> Self {
        Self::new(PlacementConstraints::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(id: &str, region: &str, reliability: f64) -> StoragePeer {
        StoragePeer {
            peer_id: id.into(),
            region: region.into(),
            capacity_bytes: 1_000_000,
            used_bytes: 100_000,
            reliability_score: reliability,
            latency_ms: 50,
            online: true,
        }
    }

    #[test]
    fn test_basic_placement() {
        let mut router = FragmentRouter::default();
        router.add_peer(make_peer("p1", "us-east", 0.9));
        router.add_peer(make_peer("p2", "eu-west", 0.85));
        router.add_peer(make_peer("p3", "ap-south", 0.8));

        let plan = router.plan_placement(3, 2);
        assert_eq!(plan.assignments.len(), 3);
        for (_, peers) in &plan.assignments {
            assert!(peers.len() >= 2, "each fragment should have 2 replicas");
        }
    }

    #[test]
    fn test_geographic_diversity() {
        let mut router = FragmentRouter::default();
        router.add_peer(make_peer("p1", "us", 0.9));
        router.add_peer(make_peer("p2", "eu", 0.9));
        router.add_peer(make_peer("p3", "ap", 0.9));

        let plan = router.plan_placement(2, 2);
        assert!(plan.regions_used >= 2);
    }

    #[test]
    fn test_avoid_peer() {
        let mut router = FragmentRouter::new(PlacementConstraints {
            avoid_peers: HashSet::from(["bad".into()]),
            ..Default::default()
        });
        router.add_peer(make_peer("good", "us", 0.9));
        router.add_peer(make_peer("bad", "eu", 0.9));

        let plan = router.plan_placement(1, 1);
        let assigned = &plan.assignments[&0];
        assert!(!assigned.contains(&"bad".to_string()));
    }

    #[test]
    fn test_avoid_region() {
        let mut router = FragmentRouter::new(PlacementConstraints {
            avoid_regions: HashSet::from(["eu".into()]),
            ..Default::default()
        });
        router.add_peer(make_peer("p1", "us", 0.9));
        router.add_peer(make_peer("p2", "eu", 0.9));

        assert_eq!(router.eligible_count(), 1);
    }

    #[test]
    fn test_reliability_filter() {
        let mut router = FragmentRouter::new(PlacementConstraints {
            min_reliability: 0.8,
            ..Default::default()
        });
        router.add_peer(make_peer("reliable", "us", 0.9));
        router.add_peer(make_peer("unreliable", "eu", 0.5));

        assert_eq!(router.eligible_count(), 1);
    }

    #[test]
    fn test_no_peers_warning() {
        let router = FragmentRouter::default();
        let plan = router.plan_placement(3, 2);
        assert!(!plan.fully_satisfied);
        assert!(!plan.warnings.is_empty());
    }

    #[test]
    fn test_insufficient_replicas_warning() {
        let mut router = FragmentRouter::default();
        router.add_peer(make_peer("p1", "us", 0.9));
        // Only 1 peer but want 3 replicas.
        let plan = router.plan_placement(1, 3);
        assert!(!plan.warnings.is_empty());
    }

    #[test]
    fn test_total_available() {
        let mut router = FragmentRouter::default();
        router.add_peer(make_peer("p1", "us", 0.9)); // 900K available
        router.add_peer(make_peer("p2", "eu", 0.9)); // 900K available
        assert_eq!(router.total_available(), 1_800_000);
    }

    #[test]
    fn test_offline_peer_excluded() {
        let mut router = FragmentRouter::default();
        let mut p = make_peer("p1", "us", 0.9);
        p.online = false;
        router.add_peer(p);
        router.add_peer(make_peer("p2", "eu", 0.9));

        assert_eq!(router.eligible_count(), 1);
    }
}

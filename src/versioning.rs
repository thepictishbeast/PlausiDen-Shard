//! Fragment versioning — tracks shard versions for conflict resolution.
//!
//! When fragments are updated (re-encrypted during key rotation), multiple
//! versions may exist across the swarm. This module tracks version history
//! and resolves conflicts using vector clocks.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A version vector (simplified vector clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionVector {
    /// Peer ID → counter.
    pub counters: HashMap<String, u64>,
}

impl VersionVector {
    pub fn new() -> Self { Self { counters: HashMap::new() } }

    /// Increment the counter for a peer.
    pub fn increment(&mut self, peer_id: &str) {
        *self.counters.entry(peer_id.into()).or_default() += 1;
    }

    /// Merge another vector clock (take max of each counter).
    pub fn merge(&mut self, other: &VersionVector) {
        for (peer, counter) in &other.counters {
            let entry = self.counters.entry(peer.clone()).or_default();
            *entry = (*entry).max(*counter);
        }
    }

    /// Check if this version dominates another (happened-after).
    pub fn dominates(&self, other: &VersionVector) -> bool {
        let mut dominated = false;
        for (peer, counter) in &other.counters {
            let ours = self.counters.get(peer).copied().unwrap_or(0);
            if ours < *counter {
                return false; // Other has a higher counter somewhere.
            }
            if ours > *counter {
                dominated = true;
            }
        }
        // Also check if we have any counters the other doesn't.
        for (peer, counter) in &self.counters {
            if *counter > other.counters.get(peer).copied().unwrap_or(0) {
                dominated = true;
            }
        }
        dominated
    }

    /// Check if two versions are concurrent (neither dominates).
    pub fn is_concurrent(&self, other: &VersionVector) -> bool {
        !self.dominates(other) && !other.dominates(self) && self != other
    }
}

impl Default for VersionVector {
    fn default() -> Self { Self::new() }
}

/// A versioned fragment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentVersion {
    pub fragment_id: String,
    pub version: VersionVector,
    pub hash: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// Tracks fragment version history.
pub struct VersionTracker {
    /// Latest known versions per fragment.
    latest: HashMap<String, Vec<FragmentVersion>>,
    /// Resolved conflicts count.
    conflicts_resolved: u64,
}

impl VersionTracker {
    pub fn new() -> Self {
        Self {
            latest: HashMap::new(),
            conflicts_resolved: 0,
        }
    }

    /// Record a new version of a fragment.
    pub fn record(&mut self, version: FragmentVersion) {
        let entry = self.latest.entry(version.fragment_id.clone()).or_default();

        // Remove versions dominated by this one.
        entry.retain(|existing| !version.version.dominates(&existing.version));

        // Check if this version is dominated by any existing version.
        let dominated = entry.iter().any(|existing| existing.version.dominates(&version.version));
        if !dominated {
            entry.push(version);
        }
    }

    /// Get the latest version(s) of a fragment.
    /// Returns multiple versions if there's an unresolved conflict.
    pub fn get_latest(&self, fragment_id: &str) -> Option<&[FragmentVersion]> {
        self.latest.get(fragment_id).map(|v| v.as_slice())
    }

    /// Check if a fragment has conflicting versions.
    pub fn has_conflict(&self, fragment_id: &str) -> bool {
        self.latest.get(fragment_id).map(|v| v.len() > 1).unwrap_or(false)
    }

    /// Resolve a conflict by choosing a winner and merging version vectors.
    pub fn resolve_conflict(&mut self, fragment_id: &str, winner_hash: &str) -> bool {
        if let Some(versions) = self.latest.get_mut(fragment_id) {
            if versions.len() <= 1 {
                return false; // No conflict.
            }

            // Find the winner.
            let winner_idx = versions.iter().position(|v| v.hash == winner_hash);
            if let Some(idx) = winner_idx {
                // Merge all version vectors into the winner.
                let mut merged = versions[idx].version.clone();
                for v in versions.iter() {
                    merged.merge(&v.version);
                }
                merged.increment(&versions[idx].created_by);

                let mut winner = versions[idx].clone();
                winner.version = merged;
                *versions = vec![winner];
                self.conflicts_resolved += 1;
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Get all fragments with unresolved conflicts.
    pub fn conflicted_fragments(&self) -> Vec<&str> {
        self.latest.iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    pub fn fragment_count(&self) -> usize { self.latest.len() }
    pub fn conflicts_resolved(&self) -> u64 { self.conflicts_resolved }
}

impl Default for VersionTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_version(frag_id: &str, peer: &str, hash: &str) -> FragmentVersion {
        let mut vv = VersionVector::new();
        vv.increment(peer);
        FragmentVersion {
            fragment_id: frag_id.into(),
            version: vv,
            hash: hash.into(),
            size_bytes: 1024,
            created_at: Utc::now(),
            created_by: peer.into(),
        }
    }

    #[test]
    fn test_version_vector_increment() {
        let mut vv = VersionVector::new();
        vv.increment("peer1");
        vv.increment("peer1");
        assert_eq!(vv.counters.get("peer1"), Some(&2));
    }

    #[test]
    fn test_version_dominates() {
        let mut a = VersionVector::new();
        a.increment("p1");
        a.increment("p1");

        let mut b = VersionVector::new();
        b.increment("p1");

        assert!(a.dominates(&b));
        assert!(!b.dominates(&a));
    }

    #[test]
    fn test_concurrent_versions() {
        let mut a = VersionVector::new();
        a.increment("p1");

        let mut b = VersionVector::new();
        b.increment("p2");

        assert!(a.is_concurrent(&b));
    }

    #[test]
    fn test_merge() {
        let mut a = VersionVector::new();
        a.increment("p1");
        a.increment("p1");

        let mut b = VersionVector::new();
        b.increment("p2");
        b.increment("p2");
        b.increment("p2");

        a.merge(&b);
        assert_eq!(a.counters.get("p1"), Some(&2));
        assert_eq!(a.counters.get("p2"), Some(&3));
    }

    #[test]
    fn test_record_and_get() {
        let mut tracker = VersionTracker::new();
        tracker.record(make_version("frag1", "peer1", "hash_a"));
        assert_eq!(tracker.fragment_count(), 1);
        let versions = tracker.get_latest("frag1").unwrap();
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn test_conflict_detection() {
        let mut tracker = VersionTracker::new();
        tracker.record(make_version("frag1", "peer1", "hash_a"));
        tracker.record(make_version("frag1", "peer2", "hash_b")); // Concurrent!
        assert!(tracker.has_conflict("frag1"));
        assert_eq!(tracker.conflicted_fragments().len(), 1);
    }

    #[test]
    fn test_dominated_version_pruned() {
        let mut tracker = VersionTracker::new();
        let v1 = make_version("frag1", "peer1", "hash_a");

        let mut v2_vv = v1.version.clone();
        v2_vv.increment("peer1"); // v2 dominates v1.
        let v2 = FragmentVersion { version: v2_vv, hash: "hash_b".into(), ..v1.clone() };

        tracker.record(v1);
        tracker.record(v2);
        assert!(!tracker.has_conflict("frag1"));
        assert_eq!(tracker.get_latest("frag1").unwrap()[0].hash, "hash_b");
    }

    #[test]
    fn test_resolve_conflict() {
        let mut tracker = VersionTracker::new();
        tracker.record(make_version("frag1", "peer1", "hash_a"));
        tracker.record(make_version("frag1", "peer2", "hash_b"));
        assert!(tracker.has_conflict("frag1"));

        assert!(tracker.resolve_conflict("frag1", "hash_a"));
        assert!(!tracker.has_conflict("frag1"));
        assert_eq!(tracker.conflicts_resolved(), 1);
    }

    #[test]
    fn test_no_conflict_to_resolve() {
        let mut tracker = VersionTracker::new();
        tracker.record(make_version("frag1", "peer1", "hash_a"));
        assert!(!tracker.resolve_conflict("frag1", "hash_a")); // No conflict.
    }
}

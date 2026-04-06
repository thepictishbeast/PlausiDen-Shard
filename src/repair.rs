//! Fragment repair — recover lost or corrupted shards from peers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Repair task for a damaged fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairTask {
    pub fragment_id: String,
    pub damage_type: DamageType,
    pub priority: RepairPriority,
    pub created_at: DateTime<Utc>,
    pub status: RepairStatus,
    pub source_peers: Vec<String>,
    pub target_peers: Vec<String>,
    pub bytes_recovered: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DamageType {
    Corrupted,
    Missing,
    Truncated,
    InaccessiblePeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RepairPriority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepairStatus {
    Pending,
    Fetching,
    Reconstructing,
    Verifying,
    Distributing,
    Complete,
    Failed { reason: String },
}

/// Fragment repair coordinator.
pub struct RepairCoordinator {
    tasks: HashMap<String, RepairTask>,
    completed_count: u64,
    failed_count: u64,
}

impl RepairCoordinator {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            completed_count: 0,
            failed_count: 0,
        }
    }

    /// Schedule a repair task.
    pub fn schedule(&mut self, fragment_id: &str, damage: DamageType, priority: RepairPriority) {
        self.tasks.insert(fragment_id.into(), RepairTask {
            fragment_id: fragment_id.into(),
            damage_type: damage,
            priority,
            created_at: Utc::now(),
            status: RepairStatus::Pending,
            source_peers: Vec::new(),
            target_peers: Vec::new(),
            bytes_recovered: 0,
        });
    }

    /// Get all pending tasks ordered by priority.
    pub fn pending_tasks(&self) -> Vec<&RepairTask> {
        let mut tasks: Vec<_> = self.tasks.values()
            .filter(|t| t.status == RepairStatus::Pending)
            .collect();
        tasks.sort_by(|a, b| b.priority.cmp(&a.priority));
        tasks
    }

    /// Update task status.
    pub fn update_status(&mut self, fragment_id: &str, status: RepairStatus) {
        if let Some(task) = self.tasks.get_mut(fragment_id) {
            task.status = status.clone();
            if status == RepairStatus::Complete {
                self.completed_count += 1;
            } else if matches!(status, RepairStatus::Failed { .. }) {
                self.failed_count += 1;
            }
        }
    }

    /// Add a source peer that has a healthy copy.
    pub fn add_source(&mut self, fragment_id: &str, peer: &str) {
        if let Some(task) = self.tasks.get_mut(fragment_id) {
            if !task.source_peers.contains(&peer.to_string()) {
                task.source_peers.push(peer.into());
            }
        }
    }

    /// Add a target peer to receive the repaired fragment.
    pub fn add_target(&mut self, fragment_id: &str, peer: &str) {
        if let Some(task) = self.tasks.get_mut(fragment_id) {
            if !task.target_peers.contains(&peer.to_string()) {
                task.target_peers.push(peer.into());
            }
        }
    }

    /// Get a task by fragment ID.
    pub fn get(&self, fragment_id: &str) -> Option<&RepairTask> {
        self.tasks.get(fragment_id)
    }

    /// Get repair statistics.
    pub fn stats(&self) -> RepairStats {
        RepairStats {
            total_tasks: self.tasks.len(),
            pending: self.tasks.values().filter(|t| t.status == RepairStatus::Pending).count(),
            in_progress: self.tasks.values()
                .filter(|t| !matches!(t.status, RepairStatus::Pending | RepairStatus::Complete | RepairStatus::Failed { .. }))
                .count(),
            completed: self.completed_count,
            failed: self.failed_count,
        }
    }
}

impl Default for RepairCoordinator {
    fn default() -> Self { Self::new() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairStats {
    pub total_tasks: usize,
    pub pending: usize,
    pub in_progress: usize,
    pub completed: u64,
    pub failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule() {
        let mut coord = RepairCoordinator::new();
        coord.schedule("frag1", DamageType::Corrupted, RepairPriority::High);
        assert_eq!(coord.tasks.len(), 1);
    }

    #[test]
    fn test_pending_priority_order() {
        let mut coord = RepairCoordinator::new();
        coord.schedule("low", DamageType::Missing, RepairPriority::Low);
        coord.schedule("critical", DamageType::Missing, RepairPriority::Critical);
        coord.schedule("normal", DamageType::Missing, RepairPriority::Normal);

        let pending = coord.pending_tasks();
        assert_eq!(pending[0].fragment_id, "critical");
        assert_eq!(pending[1].fragment_id, "normal");
        assert_eq!(pending[2].fragment_id, "low");
    }

    #[test]
    fn test_update_status() {
        let mut coord = RepairCoordinator::new();
        coord.schedule("frag1", DamageType::Missing, RepairPriority::High);
        coord.update_status("frag1", RepairStatus::Complete);
        let stats = coord.stats();
        assert_eq!(stats.completed, 1);
    }

    #[test]
    fn test_add_source_peer() {
        let mut coord = RepairCoordinator::new();
        coord.schedule("frag1", DamageType::Missing, RepairPriority::Normal);
        coord.add_source("frag1", "peer1");
        coord.add_source("frag1", "peer2");
        let task = coord.get("frag1").unwrap();
        assert_eq!(task.source_peers.len(), 2);
    }

    #[test]
    fn test_no_duplicate_sources() {
        let mut coord = RepairCoordinator::new();
        coord.schedule("frag1", DamageType::Missing, RepairPriority::Normal);
        coord.add_source("frag1", "peer1");
        coord.add_source("frag1", "peer1");
        assert_eq!(coord.get("frag1").unwrap().source_peers.len(), 1);
    }

    #[test]
    fn test_failed_status() {
        let mut coord = RepairCoordinator::new();
        coord.schedule("frag1", DamageType::Missing, RepairPriority::High);
        coord.update_status("frag1", RepairStatus::Failed { reason: "no source peers".into() });
        assert_eq!(coord.stats().failed, 1);
    }

    #[test]
    fn test_stats() {
        let mut coord = RepairCoordinator::new();
        coord.schedule("a", DamageType::Missing, RepairPriority::High);
        coord.schedule("b", DamageType::Corrupted, RepairPriority::High);
        coord.update_status("a", RepairStatus::Fetching);
        let stats = coord.stats();
        assert_eq!(stats.total_tasks, 2);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.in_progress, 1);
    }
}

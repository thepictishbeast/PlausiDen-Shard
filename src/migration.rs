//! Fragment migration — move shards between peers for load balancing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A migration task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationTask {
    pub fragment_id: String,
    pub source_peer: String,
    pub destination_peer: String,
    pub created_at: DateTime<Utc>,
    pub status: MigrationStatus,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStatus {
    Queued,
    InProgress,
    Verifying,
    Complete,
    Failed { reason: String },
}

/// Migration coordinator.
pub struct MigrationCoordinator {
    tasks: HashMap<String, MigrationTask>,
    completed: u64,
    failed: u64,
    total_bytes_migrated: u64,
}

impl MigrationCoordinator {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
            completed: 0,
            failed: 0,
            total_bytes_migrated: 0,
        }
    }

    /// Create a migration task.
    pub fn create(&mut self, fragment_id: &str, source: &str, destination: &str, total_bytes: u64) {
        let task_id = format!("{fragment_id}:{source}->{destination}");
        self.tasks.insert(task_id, MigrationTask {
            fragment_id: fragment_id.into(),
            source_peer: source.into(),
            destination_peer: destination.into(),
            created_at: Utc::now(),
            status: MigrationStatus::Queued,
            bytes_transferred: 0,
            total_bytes,
        });
    }

    /// Update progress for a task.
    pub fn update_progress(&mut self, fragment_id: &str, source: &str, dest: &str, bytes: u64) {
        let key = format!("{fragment_id}:{source}->{dest}");
        if let Some(task) = self.tasks.get_mut(&key) {
            task.bytes_transferred = bytes;
            if task.status == MigrationStatus::Queued {
                task.status = MigrationStatus::InProgress;
            }
        }
    }

    /// Mark a task complete.
    pub fn complete(&mut self, fragment_id: &str, source: &str, dest: &str) {
        let key = format!("{fragment_id}:{source}->{dest}");
        if let Some(task) = self.tasks.get_mut(&key) {
            task.status = MigrationStatus::Complete;
            self.completed += 1;
            self.total_bytes_migrated += task.total_bytes;
        }
    }

    /// Mark a task failed.
    pub fn fail(&mut self, fragment_id: &str, source: &str, dest: &str, reason: &str) {
        let key = format!("{fragment_id}:{source}->{dest}");
        if let Some(task) = self.tasks.get_mut(&key) {
            task.status = MigrationStatus::Failed { reason: reason.into() };
            self.failed += 1;
        }
    }

    /// Get queued tasks.
    pub fn queued(&self) -> Vec<&MigrationTask> {
        self.tasks.values().filter(|t| t.status == MigrationStatus::Queued).collect()
    }

    /// Get in-progress tasks.
    pub fn in_progress(&self) -> Vec<&MigrationTask> {
        self.tasks.values().filter(|t| t.status == MigrationStatus::InProgress).collect()
    }

    /// Get migration progress percentage for a task.
    pub fn progress_percent(&self, fragment_id: &str, source: &str, dest: &str) -> Option<f64> {
        let key = format!("{fragment_id}:{source}->{dest}");
        self.tasks.get(&key).map(|t| {
            if t.total_bytes == 0 { 0.0 }
            else { (t.bytes_transferred as f64 / t.total_bytes as f64) * 100.0 }
        })
    }

    pub fn task_count(&self) -> usize { self.tasks.len() }
    pub fn completed_count(&self) -> u64 { self.completed }
    pub fn failed_count(&self) -> u64 { self.failed }
    pub fn total_migrated_bytes(&self) -> u64 { self.total_bytes_migrated }
}

impl Default for MigrationCoordinator {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_task() {
        let mut coord = MigrationCoordinator::new();
        coord.create("frag1", "peer1", "peer2", 1024);
        assert_eq!(coord.task_count(), 1);
    }

    #[test]
    fn test_update_progress() {
        let mut coord = MigrationCoordinator::new();
        coord.create("f", "s", "d", 1000);
        coord.update_progress("f", "s", "d", 500);
        let progress = coord.progress_percent("f", "s", "d").unwrap();
        assert!((progress - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_complete() {
        let mut coord = MigrationCoordinator::new();
        coord.create("f", "s", "d", 1024);
        coord.complete("f", "s", "d");
        assert_eq!(coord.completed_count(), 1);
        assert_eq!(coord.total_migrated_bytes(), 1024);
    }

    #[test]
    fn test_fail() {
        let mut coord = MigrationCoordinator::new();
        coord.create("f", "s", "d", 1024);
        coord.fail("f", "s", "d", "network error");
        assert_eq!(coord.failed_count(), 1);
    }

    #[test]
    fn test_queued() {
        let mut coord = MigrationCoordinator::new();
        coord.create("a", "s", "d", 100);
        coord.create("b", "s", "d", 100);
        coord.update_progress("a", "s", "d", 50);
        assert_eq!(coord.queued().len(), 1);
        assert_eq!(coord.in_progress().len(), 1);
    }

    #[test]
    fn test_progress_zero_bytes() {
        let mut coord = MigrationCoordinator::new();
        coord.create("f", "s", "d", 0);
        let progress = coord.progress_percent("f", "s", "d").unwrap();
        assert_eq!(progress, 0.0);
    }

    #[test]
    fn test_unknown_task() {
        let coord = MigrationCoordinator::new();
        assert!(coord.progress_percent("nonexistent", "s", "d").is_none());
    }
}

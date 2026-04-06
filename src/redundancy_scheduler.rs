//! Redundancy scheduler — schedule fragment re-replication to maintain target.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A scheduled redundancy task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedundancyTask {
    pub id: String,
    pub fragment_id: String,
    pub task_type: TaskType,
    pub priority: Priority,
    pub scheduled_for: DateTime<Utc>,
    pub state: TaskState,
    pub retries: u32,
    pub max_retries: u32,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskType {
    /// Replicate to additional peers.
    Replicate { target_count: u8 },
    /// Verify replica integrity.
    Verify,
    /// Repair corrupted replica.
    Repair,
    /// Migrate from one peer to another.
    Migrate { from: String, to: String },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Low,
    Normal,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Redundancy scheduler.
pub struct RedundancyScheduler {
    tasks: HashMap<String, RedundancyTask>,
    next_id: u64,
}

impl RedundancyScheduler {
    pub fn new() -> Self {
        Self { tasks: HashMap::new(), next_id: 0 }
    }

    /// Schedule a new task.
    pub fn schedule(
        &mut self,
        fragment_id: &str,
        task_type: TaskType,
        priority: Priority,
        when: DateTime<Utc>,
    ) -> String {
        let id = format!("task-{}", self.next_id);
        self.next_id += 1;
        self.tasks.insert(id.clone(), RedundancyTask {
            id: id.clone(),
            fragment_id: fragment_id.into(),
            task_type,
            priority,
            scheduled_for: when,
            state: TaskState::Pending,
            retries: 0,
            max_retries: 3,
            last_error: None,
        });
        id
    }

    /// Get tasks ready to run now, ordered by priority.
    pub fn ready_tasks(&self) -> Vec<&RedundancyTask> {
        let now = Utc::now();
        let mut ready: Vec<&RedundancyTask> = self.tasks.values()
            .filter(|t| t.state == TaskState::Pending && t.scheduled_for <= now)
            .collect();
        ready.sort_by(|a, b| b.priority.cmp(&a.priority));
        ready
    }

    /// Mark a task as running.
    pub fn start(&mut self, task_id: &str) -> bool {
        if let Some(t) = self.tasks.get_mut(task_id) {
            if t.state == TaskState::Pending {
                t.state = TaskState::Running;
                return true;
            }
        }
        false
    }

    /// Mark a task completed.
    pub fn complete(&mut self, task_id: &str) -> bool {
        if let Some(t) = self.tasks.get_mut(task_id) {
            t.state = TaskState::Completed;
            return true;
        }
        false
    }

    /// Mark a task failed, possibly scheduling a retry.
    pub fn fail(&mut self, task_id: &str, error: &str) -> bool {
        if let Some(t) = self.tasks.get_mut(task_id) {
            t.retries += 1;
            t.last_error = Some(error.into());
            if t.retries >= t.max_retries {
                t.state = TaskState::Failed;
            } else {
                t.state = TaskState::Pending;
                // Exponential backoff.
                let delay = 2_i64.pow(t.retries) * 60;
                t.scheduled_for = Utc::now() + chrono::Duration::seconds(delay);
            }
            return true;
        }
        false
    }

    /// Cancel a pending task.
    pub fn cancel(&mut self, task_id: &str) -> bool {
        if let Some(t) = self.tasks.get_mut(task_id) {
            if t.state != TaskState::Completed {
                t.state = TaskState::Cancelled;
                return true;
            }
        }
        false
    }

    /// Get a task by id.
    pub fn get(&self, task_id: &str) -> Option<&RedundancyTask> {
        self.tasks.get(task_id)
    }

    /// Tasks for a specific fragment.
    pub fn for_fragment(&self, fragment_id: &str) -> Vec<&RedundancyTask> {
        self.tasks.values()
            .filter(|t| t.fragment_id == fragment_id)
            .collect()
    }

    /// Tasks in a specific state.
    pub fn by_state(&self, state: &TaskState) -> Vec<&RedundancyTask> {
        self.tasks.values().filter(|t| &t.state == state).collect()
    }

    /// Count by state.
    pub fn state_counts(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for t in self.tasks.values() {
            *map.entry(format!("{:?}", t.state)).or_insert(0) += 1;
        }
        map
    }

    pub fn task_count(&self) -> usize { self.tasks.len() }
}

impl Default for RedundancyScheduler {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_pending() {
        let mut s = RedundancyScheduler::new();
        let id = s.schedule("frag1",
            TaskType::Replicate { target_count: 3 },
            Priority::Normal,
            Utc::now());
        assert_eq!(s.get(&id).unwrap().state, TaskState::Pending);
    }

    #[test]
    fn test_ready_tasks() {
        let mut s = RedundancyScheduler::new();
        s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        s.schedule("f2", TaskType::Verify, Priority::Normal,
            Utc::now() + chrono::Duration::days(1));
        let ready = s.ready_tasks();
        assert_eq!(ready.len(), 1);
    }

    #[test]
    fn test_priority_order() {
        let mut s = RedundancyScheduler::new();
        s.schedule("low", TaskType::Verify, Priority::Low, Utc::now());
        s.schedule("high", TaskType::Verify, Priority::Critical, Utc::now());
        let ready = s.ready_tasks();
        assert_eq!(ready[0].fragment_id, "high");
    }

    #[test]
    fn test_start_and_complete() {
        let mut s = RedundancyScheduler::new();
        let id = s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        assert!(s.start(&id));
        assert!(s.complete(&id));
        assert_eq!(s.get(&id).unwrap().state, TaskState::Completed);
    }

    #[test]
    fn test_fail_retries() {
        let mut s = RedundancyScheduler::new();
        let id = s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        s.fail(&id, "network error");
        assert_eq!(s.get(&id).unwrap().state, TaskState::Pending);
        assert_eq!(s.get(&id).unwrap().retries, 1);
    }

    #[test]
    fn test_fail_max_retries() {
        let mut s = RedundancyScheduler::new();
        let id = s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        for _ in 0..4 { s.fail(&id, "err"); }
        assert_eq!(s.get(&id).unwrap().state, TaskState::Failed);
    }

    #[test]
    fn test_cancel() {
        let mut s = RedundancyScheduler::new();
        let id = s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        assert!(s.cancel(&id));
        assert_eq!(s.get(&id).unwrap().state, TaskState::Cancelled);
    }

    #[test]
    fn test_for_fragment() {
        let mut s = RedundancyScheduler::new();
        s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        s.schedule("f1", TaskType::Repair, Priority::High, Utc::now());
        s.schedule("f2", TaskType::Verify, Priority::Normal, Utc::now());
        assert_eq!(s.for_fragment("f1").len(), 2);
    }

    #[test]
    fn test_state_counts() {
        let mut s = RedundancyScheduler::new();
        s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        s.schedule("f2", TaskType::Verify, Priority::Normal, Utc::now());
        let counts = s.state_counts();
        assert_eq!(*counts.get("Pending").unwrap(), 2);
    }

    #[test]
    fn test_by_state() {
        let mut s = RedundancyScheduler::new();
        let id = s.schedule("f1", TaskType::Verify, Priority::Normal, Utc::now());
        s.start(&id);
        assert_eq!(s.by_state(&TaskState::Running).len(), 1);
    }
}

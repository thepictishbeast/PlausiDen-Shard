//! Scrub scheduler — schedule periodic data scrubbing for fragments.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A scrub task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubTask {
    pub fragment_id: String,
    pub last_scrubbed: Option<DateTime<Utc>>,
    pub next_due: DateTime<Utc>,
    pub interval_secs: i64,
    pub priority: ScrubPriority,
    pub failure_count: u32,
    pub success_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScrubPriority {
    Low,
    Normal,
    High,
}

impl ScrubTask {
    pub fn is_due(&self) -> bool {
        Utc::now() >= self.next_due
    }

    pub fn overdue_secs(&self) -> i64 {
        let delta = Utc::now() - self.next_due;
        delta.num_seconds().max(0)
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.failure_count;
        if total == 0 { return 0.0; }
        self.success_count as f64 / total as f64
    }
}

/// Scrub result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScrubResult {
    Passed,
    BitRot,
    DataLoss,
    Unreachable,
}

/// Scrub scheduler.
pub struct ScrubScheduler {
    tasks: HashMap<String, ScrubTask>,
    default_interval_secs: i64,
}

impl ScrubScheduler {
    pub fn new(default_interval_secs: i64) -> Self {
        Self {
            tasks: HashMap::new(),
            default_interval_secs,
        }
    }

    /// Add a fragment to the scrub schedule.
    pub fn add(&mut self, fragment_id: &str, priority: ScrubPriority) {
        let interval = match priority {
            ScrubPriority::High => self.default_interval_secs / 2,
            ScrubPriority::Normal => self.default_interval_secs,
            ScrubPriority::Low => self.default_interval_secs * 2,
        };
        let now = Utc::now();
        self.tasks.insert(fragment_id.into(), ScrubTask {
            fragment_id: fragment_id.into(),
            last_scrubbed: None,
            next_due: now + chrono::Duration::seconds(interval),
            interval_secs: interval,
            priority,
            failure_count: 0,
            success_count: 0,
        });
    }

    /// Remove a fragment.
    pub fn remove(&mut self, fragment_id: &str) -> bool {
        self.tasks.remove(fragment_id).is_some()
    }

    /// Tasks ready to scrub now, ordered by overdue + priority.
    pub fn due_tasks(&self) -> Vec<&ScrubTask> {
        let mut due: Vec<&ScrubTask> = self.tasks.values().filter(|t| t.is_due()).collect();
        due.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| b.overdue_secs().cmp(&a.overdue_secs()))
        });
        due
    }

    /// Record a scrub result.
    pub fn record_result(&mut self, fragment_id: &str, result: ScrubResult) -> bool {
        let task = match self.tasks.get_mut(fragment_id) {
            Some(t) => t,
            None => return false,
        };
        let now = Utc::now();
        task.last_scrubbed = Some(now);
        match result {
            ScrubResult::Passed => {
                task.success_count += 1;
                // Reset interval on success.
                task.next_due = now + chrono::Duration::seconds(task.interval_secs);
            }
            _ => {
                task.failure_count += 1;
                // Re-check sooner on failure.
                let urgent = task.interval_secs / 4;
                task.next_due = now + chrono::Duration::seconds(urgent.max(60));
            }
        }
        true
    }

    /// Update priority for a fragment.
    pub fn set_priority(&mut self, fragment_id: &str, priority: ScrubPriority) -> bool {
        if let Some(task) = self.tasks.get_mut(fragment_id) {
            task.priority = priority;
            return true;
        }
        false
    }

    /// Tasks with high failure rate.
    pub fn problematic(&self, max_success_rate: f64) -> Vec<&ScrubTask> {
        self.tasks.values()
            .filter(|t| (t.success_count + t.failure_count) >= 5
                && t.success_rate() < max_success_rate)
            .collect()
    }

    /// Get a task.
    pub fn get(&self, fragment_id: &str) -> Option<&ScrubTask> {
        self.tasks.get(fragment_id)
    }

    pub fn task_count(&self) -> usize { self.tasks.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_task() {
        let mut s = ScrubScheduler::new(86400);
        s.add("frag1", ScrubPriority::Normal);
        assert_eq!(s.task_count(), 1);
    }

    #[test]
    fn test_priority_intervals() {
        let mut s = ScrubScheduler::new(1000);
        s.add("low", ScrubPriority::Low);
        s.add("normal", ScrubPriority::Normal);
        s.add("high", ScrubPriority::High);
        assert_eq!(s.get("high").unwrap().interval_secs, 500);
        assert_eq!(s.get("normal").unwrap().interval_secs, 1000);
        assert_eq!(s.get("low").unwrap().interval_secs, 2000);
    }

    #[test]
    fn test_due_tasks() {
        let mut s = ScrubScheduler::new(1000);
        s.add("frag1", ScrubPriority::Normal);
        if let Some(t) = s.tasks.get_mut("frag1") {
            t.next_due = Utc::now() - chrono::Duration::seconds(10);
        }
        assert_eq!(s.due_tasks().len(), 1);
    }

    #[test]
    fn test_record_passed() {
        let mut s = ScrubScheduler::new(1000);
        s.add("frag1", ScrubPriority::Normal);
        s.record_result("frag1", ScrubResult::Passed);
        let task = s.get("frag1").unwrap();
        assert_eq!(task.success_count, 1);
    }

    #[test]
    fn test_record_failure_shortens_interval() {
        let mut s = ScrubScheduler::new(1000);
        s.add("frag1", ScrubPriority::Normal);
        let original_next = s.get("frag1").unwrap().next_due;
        s.record_result("frag1", ScrubResult::BitRot);
        let new_next = s.get("frag1").unwrap().next_due;
        assert!(new_next < original_next);
    }

    #[test]
    fn test_problematic() {
        let mut s = ScrubScheduler::new(1000);
        s.add("flaky", ScrubPriority::Normal);
        for _ in 0..3 { s.record_result("flaky", ScrubResult::BitRot); }
        for _ in 0..2 { s.record_result("flaky", ScrubResult::Passed); }
        assert_eq!(s.problematic(0.5).len(), 1);
    }

    #[test]
    fn test_set_priority() {
        let mut s = ScrubScheduler::new(1000);
        s.add("frag1", ScrubPriority::Normal);
        s.set_priority("frag1", ScrubPriority::High);
        assert_eq!(s.get("frag1").unwrap().priority, ScrubPriority::High);
    }

    #[test]
    fn test_remove() {
        let mut s = ScrubScheduler::new(1000);
        s.add("frag1", ScrubPriority::Normal);
        assert!(s.remove("frag1"));
        assert_eq!(s.task_count(), 0);
    }

    #[test]
    fn test_due_tasks_priority_order() {
        let mut s = ScrubScheduler::new(1000);
        s.add("low", ScrubPriority::Low);
        s.add("high", ScrubPriority::High);
        if let Some(t) = s.tasks.get_mut("low") {
            t.next_due = Utc::now() - chrono::Duration::seconds(1);
        }
        if let Some(t) = s.tasks.get_mut("high") {
            t.next_due = Utc::now() - chrono::Duration::seconds(1);
        }
        let due = s.due_tasks();
        assert_eq!(due[0].fragment_id, "high");
    }
}

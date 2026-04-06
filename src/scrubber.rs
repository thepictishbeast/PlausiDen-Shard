//! Scrubber — periodic integrity verification of stored fragments.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A scrub result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubResult {
    pub fragment_id: String,
    pub timestamp: DateTime<Utc>,
    pub status: ScrubStatus,
    pub bytes_checked: u64,
}

/// Status of an integrity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScrubStatus {
    Ok,
    Corrupted,
    Missing,
    Unreadable,
}

/// Scrub configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubConfig {
    /// How often to scrub each fragment (seconds).
    pub interval_secs: i64,
    /// Maximum fragments to scrub per cycle.
    pub batch_size: usize,
    /// Hash verification.
    pub verify_hashes: bool,
}

impl Default for ScrubConfig {
    fn default() -> Self {
        Self {
            interval_secs: 86400 * 7, // Weekly
            batch_size: 100,
            verify_hashes: true,
        }
    }
}

/// Scrubber engine.
pub struct Scrubber {
    config: ScrubConfig,
    last_scrub: HashMap<String, DateTime<Utc>>,
    results: Vec<ScrubResult>,
    /// Statistics.
    total_scrubs: u64,
    corrupted_count: u64,
    missing_count: u64,
}

impl Scrubber {
    pub fn new(config: ScrubConfig) -> Self {
        Self {
            config,
            last_scrub: HashMap::new(),
            results: Vec::new(),
            total_scrubs: 0,
            corrupted_count: 0,
            missing_count: 0,
        }
    }

    /// Get fragments due for scrubbing.
    pub fn due_for_scrub(&self, all_fragments: &[String]) -> Vec<String> {
        let cutoff = Utc::now() - Duration::seconds(self.config.interval_secs);
        all_fragments.iter()
            .filter(|id| {
                self.last_scrub.get(*id)
                    .map(|t| *t < cutoff)
                    .unwrap_or(true)
            })
            .take(self.config.batch_size)
            .cloned()
            .collect()
    }

    /// Record the result of a scrub.
    pub fn record_result(&mut self, result: ScrubResult) {
        self.last_scrub.insert(result.fragment_id.clone(), result.timestamp);
        match result.status {
            ScrubStatus::Corrupted => self.corrupted_count += 1,
            ScrubStatus::Missing => self.missing_count += 1,
            _ => {}
        }
        self.total_scrubs += 1;
        self.results.push(result);
    }

    /// Get all results with a specific status.
    pub fn results_by_status(&self, status: ScrubStatus) -> Vec<&ScrubResult> {
        self.results.iter().filter(|r| r.status == status).collect()
    }

    /// Get fragments that need attention (corrupted or missing).
    pub fn problem_fragments(&self) -> Vec<&ScrubResult> {
        self.results.iter()
            .filter(|r| matches!(r.status, ScrubStatus::Corrupted | ScrubStatus::Missing | ScrubStatus::Unreadable))
            .collect()
    }

    /// Total bytes verified across all scrubs.
    pub fn total_bytes_checked(&self) -> u64 {
        self.results.iter().map(|r| r.bytes_checked).sum()
    }

    /// Health metrics.
    pub fn health_metrics(&self) -> ScrubMetrics {
        ScrubMetrics {
            total_scrubs: self.total_scrubs,
            corrupted_count: self.corrupted_count,
            missing_count: self.missing_count,
            error_rate: if self.total_scrubs > 0 {
                ((self.corrupted_count + self.missing_count) as f64 / self.total_scrubs as f64) * 100.0
            } else {
                0.0
            },
        }
    }
}

impl Default for Scrubber {
    fn default() -> Self { Self::new(ScrubConfig::default()) }
}

/// Scrub metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubMetrics {
    pub total_scrubs: u64,
    pub corrupted_count: u64,
    pub missing_count: u64,
    pub error_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(id: &str, status: ScrubStatus) -> ScrubResult {
        ScrubResult {
            fragment_id: id.into(),
            timestamp: Utc::now(),
            status,
            bytes_checked: 1024,
        }
    }

    #[test]
    fn test_due_for_scrub_initial() {
        let scrubber = Scrubber::default();
        let frags = vec!["f1".into(), "f2".into(), "f3".into()];
        let due = scrubber.due_for_scrub(&frags);
        assert_eq!(due.len(), 3);
    }

    #[test]
    fn test_record_result() {
        let mut scrubber = Scrubber::default();
        scrubber.record_result(make_result("f1", ScrubStatus::Ok));
        assert_eq!(scrubber.total_scrubs, 1);
    }

    #[test]
    fn test_corrupted_tracking() {
        let mut scrubber = Scrubber::default();
        scrubber.record_result(make_result("f1", ScrubStatus::Corrupted));
        scrubber.record_result(make_result("f2", ScrubStatus::Ok));
        assert_eq!(scrubber.corrupted_count, 1);
    }

    #[test]
    fn test_problem_fragments() {
        let mut scrubber = Scrubber::default();
        scrubber.record_result(make_result("f1", ScrubStatus::Ok));
        scrubber.record_result(make_result("f2", ScrubStatus::Corrupted));
        scrubber.record_result(make_result("f3", ScrubStatus::Missing));
        scrubber.record_result(make_result("f4", ScrubStatus::Ok));
        assert_eq!(scrubber.problem_fragments().len(), 2);
    }

    #[test]
    fn test_health_metrics() {
        let mut scrubber = Scrubber::default();
        for _ in 0..8 { scrubber.record_result(make_result("f", ScrubStatus::Ok)); }
        for _ in 0..2 { scrubber.record_result(make_result("f", ScrubStatus::Corrupted)); }
        let metrics = scrubber.health_metrics();
        assert_eq!(metrics.total_scrubs, 10);
        assert_eq!(metrics.corrupted_count, 2);
        assert!((metrics.error_rate - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_total_bytes() {
        let mut scrubber = Scrubber::default();
        scrubber.record_result(make_result("f1", ScrubStatus::Ok));
        scrubber.record_result(make_result("f2", ScrubStatus::Ok));
        assert_eq!(scrubber.total_bytes_checked(), 2048);
    }

    #[test]
    fn test_results_by_status() {
        let mut scrubber = Scrubber::default();
        scrubber.record_result(make_result("f1", ScrubStatus::Ok));
        scrubber.record_result(make_result("f2", ScrubStatus::Ok));
        scrubber.record_result(make_result("f3", ScrubStatus::Corrupted));
        assert_eq!(scrubber.results_by_status(ScrubStatus::Ok).len(), 2);
        assert_eq!(scrubber.results_by_status(ScrubStatus::Corrupted).len(), 1);
    }

    #[test]
    fn test_batch_size_limit() {
        let scrubber = Scrubber::new(ScrubConfig { batch_size: 2, ..Default::default() });
        let frags = vec!["a".into(), "b".into(), "c".into(), "d".into()];
        let due = scrubber.due_for_scrub(&frags);
        assert_eq!(due.len(), 2);
    }
}

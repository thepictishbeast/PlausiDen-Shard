//! Consistency checker — verify fragment state consistency across the swarm.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A fragment's view from a single peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FragmentView {
    pub fragment_id: String,
    pub version: u64,
    pub hash_hex: String,
    pub size_bytes: u64,
    pub holder_peer_id: String,
    pub observed_at: DateTime<Utc>,
}

/// Consistency check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyReport {
    pub fragment_id: String,
    pub view_count: usize,
    pub consistent: bool,
    pub inconsistencies: Vec<Inconsistency>,
    pub majority_hash: Option<String>,
    pub majority_version: Option<u64>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Inconsistency {
    HashDisagreement { peer: String, expected: String, found: String },
    VersionDrift { peer: String, expected: u64, found: u64 },
    SizeMismatch { peer: String, expected: u64, found: u64 },
}

impl ConsistencyReport {
    pub fn has_issues(&self) -> bool {
        !self.consistent || !self.inconsistencies.is_empty()
    }
}

/// Consistency checker.
pub struct ConsistencyChecker;

impl ConsistencyChecker {
    pub fn new() -> Self { Self }

    /// Check a set of views for the same fragment.
    pub fn check(&self, views: &[FragmentView]) -> ConsistencyReport {
        let now = Utc::now();
        if views.is_empty() {
            return ConsistencyReport {
                fragment_id: String::new(),
                view_count: 0,
                consistent: true,
                inconsistencies: Vec::new(),
                majority_hash: None,
                majority_version: None,
                checked_at: now,
            };
        }

        let fragment_id = views[0].fragment_id.clone();
        let mut inconsistencies = Vec::new();

        // Hash counts.
        let mut hash_counts: HashMap<String, usize> = HashMap::new();
        for v in views {
            *hash_counts.entry(v.hash_hex.clone()).or_insert(0) += 1;
        }
        let majority_hash = hash_counts.iter()
            .max_by_key(|(_, c)| *c)
            .map(|(h, _)| h.clone());

        // Version counts.
        let mut version_counts: HashMap<u64, usize> = HashMap::new();
        for v in views {
            *version_counts.entry(v.version).or_insert(0) += 1;
        }
        let majority_version = version_counts.iter()
            .max_by_key(|(_, c)| *c)
            .map(|(v, _)| *v);

        // Size counts.
        let mut size_counts: HashMap<u64, usize> = HashMap::new();
        for v in views {
            *size_counts.entry(v.size_bytes).or_insert(0) += 1;
        }
        let majority_size = size_counts.iter()
            .max_by_key(|(_, c)| *c)
            .map(|(s, _)| *s);

        // Gather inconsistencies.
        for v in views {
            if let Some(m) = &majority_hash {
                if &v.hash_hex != m {
                    inconsistencies.push(Inconsistency::HashDisagreement {
                        peer: v.holder_peer_id.clone(),
                        expected: m.clone(),
                        found: v.hash_hex.clone(),
                    });
                }
            }
            if let Some(m) = majority_version {
                if v.version != m {
                    inconsistencies.push(Inconsistency::VersionDrift {
                        peer: v.holder_peer_id.clone(),
                        expected: m,
                        found: v.version,
                    });
                }
            }
            if let Some(m) = majority_size {
                if v.size_bytes != m {
                    inconsistencies.push(Inconsistency::SizeMismatch {
                        peer: v.holder_peer_id.clone(),
                        expected: m,
                        found: v.size_bytes,
                    });
                }
            }
        }

        let consistent = inconsistencies.is_empty();

        ConsistencyReport {
            fragment_id,
            view_count: views.len(),
            consistent,
            inconsistencies,
            majority_hash,
            majority_version,
            checked_at: now,
        }
    }

    /// Check multiple fragments' views, grouping by fragment_id.
    pub fn check_many(&self, all_views: &[FragmentView]) -> HashMap<String, ConsistencyReport> {
        let mut groups: HashMap<String, Vec<FragmentView>> = HashMap::new();
        for v in all_views {
            groups.entry(v.fragment_id.clone()).or_default().push(v.clone());
        }
        groups.into_iter()
            .map(|(id, views)| (id, self.check(&views)))
            .collect()
    }
}

impl Default for ConsistencyChecker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(frag: &str, version: u64, hash: &str, size: u64, peer: &str) -> FragmentView {
        FragmentView {
            fragment_id: frag.into(),
            version,
            hash_hex: hash.into(),
            size_bytes: size,
            holder_peer_id: peer.into(),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn test_empty_views() {
        let c = ConsistencyChecker::new();
        let report = c.check(&[]);
        assert!(report.consistent);
        assert_eq!(report.view_count, 0);
    }

    #[test]
    fn test_consistent_views() {
        let c = ConsistencyChecker::new();
        let views = vec![
            view("f1", 1, "abc", 100, "p1"),
            view("f1", 1, "abc", 100, "p2"),
            view("f1", 1, "abc", 100, "p3"),
        ];
        let report = c.check(&views);
        assert!(report.consistent);
        assert_eq!(report.view_count, 3);
    }

    #[test]
    fn test_hash_disagreement() {
        let c = ConsistencyChecker::new();
        let views = vec![
            view("f1", 1, "abc", 100, "p1"),
            view("f1", 1, "abc", 100, "p2"),
            view("f1", 1, "xyz", 100, "p3"),
        ];
        let report = c.check(&views);
        assert!(!report.consistent);
        assert_eq!(report.majority_hash, Some("abc".into()));
    }

    #[test]
    fn test_version_drift() {
        let c = ConsistencyChecker::new();
        let views = vec![
            view("f1", 2, "abc", 100, "p1"),
            view("f1", 2, "abc", 100, "p2"),
            view("f1", 1, "old", 100, "p3"),
        ];
        let report = c.check(&views);
        assert!(!report.consistent);
        assert_eq!(report.majority_version, Some(2));
    }

    #[test]
    fn test_size_mismatch() {
        let c = ConsistencyChecker::new();
        let views = vec![
            view("f1", 1, "a", 100, "p1"),
            view("f1", 1, "a", 100, "p2"),
            view("f1", 1, "a", 200, "p3"),
        ];
        let report = c.check(&views);
        assert!(!report.consistent);
    }

    #[test]
    fn test_check_many() {
        let c = ConsistencyChecker::new();
        let views = vec![
            view("f1", 1, "a", 100, "p1"),
            view("f1", 1, "a", 100, "p2"),
            view("f2", 1, "b", 200, "p1"),
            view("f2", 1, "c", 200, "p2"),
        ];
        let reports = c.check_many(&views);
        assert_eq!(reports.len(), 2);
        assert!(reports["f1"].consistent);
        assert!(!reports["f2"].consistent);
    }

    #[test]
    fn test_has_issues() {
        let c = ConsistencyChecker::new();
        let views = vec![
            view("f1", 1, "a", 100, "p1"),
            view("f1", 1, "b", 100, "p2"),
        ];
        assert!(c.check(&views).has_issues());
    }

    #[test]
    fn test_single_view_consistent() {
        let c = ConsistencyChecker::new();
        let views = vec![view("f1", 1, "a", 100, "p1")];
        assert!(c.check(&views).consistent);
    }
}

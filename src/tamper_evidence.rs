//! Tamper evidence — detect unauthorized fragment modifications via hash witnesses.

use blake3::Hash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A hash witness for a fragment at a given point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    pub fragment_id: String,
    pub hash_hex: String,
    pub size_bytes: u64,
    pub witnessed_at: DateTime<Utc>,
    pub source: WitnessSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessSource {
    Local,
    Peer(String),
    Ledger,
    UserSubmitted,
}

/// A detected tamper event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperEvent {
    pub fragment_id: String,
    pub original_hash: String,
    pub observed_hash: String,
    pub detected_at: DateTime<Utc>,
    pub disagreeing_sources: Vec<WitnessSource>,
    pub severity: TamperSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TamperSeverity {
    Minor,   // single disagreement
    Serious, // majority disagree
    Critical, // all peers disagree
}

/// Tamper evidence tracker.
pub struct TamperEvidence {
    /// Fragment ID → witnesses from multiple sources.
    witnesses: HashMap<String, Vec<Witness>>,
    events: Vec<TamperEvent>,
}

impl TamperEvidence {
    pub fn new() -> Self {
        Self {
            witnesses: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Compute the BLAKE3 hash of data.
    pub fn hash_data(data: &[u8]) -> Hash {
        blake3::hash(data)
    }

    /// Record a witness observation.
    pub fn witness(&mut self, fragment_id: &str, data: &[u8], source: WitnessSource) {
        let hash = Self::hash_data(data);
        self.witnesses.entry(fragment_id.into())
            .or_default()
            .push(Witness {
                fragment_id: fragment_id.into(),
                hash_hex: hash.to_hex().to_string(),
                size_bytes: data.len() as u64,
                witnessed_at: Utc::now(),
                source,
            });
    }

    /// Record a witness directly (for pre-computed hashes).
    pub fn witness_hash(&mut self, witness: Witness) {
        self.witnesses.entry(witness.fragment_id.clone())
            .or_default()
            .push(witness);
    }

    /// Detect whether a fragment's witnesses agree.
    pub fn check_consistency(&mut self, fragment_id: &str) -> Option<TamperEvent> {
        let witnesses = self.witnesses.get(fragment_id)?;
        if witnesses.len() < 2 {
            return None;
        }

        let mut hash_counts: HashMap<String, Vec<WitnessSource>> = HashMap::new();
        for w in witnesses {
            hash_counts.entry(w.hash_hex.clone())
                .or_default()
                .push(w.source.clone());
        }

        if hash_counts.len() == 1 {
            return None; // all agree
        }

        // Find the majority hash.
        let majority = hash_counts.iter()
            .max_by_key(|(_, sources)| sources.len())
            .map(|(hash, _)| hash.clone())?;

        // Any hash that isn't the majority is a minority — report the first
        // disagreement.
        let disagreement = hash_counts.iter()
            .find(|(hash, _)| **hash != majority)?;
        let disagreeing_sources = disagreement.1.clone();
        let observed_hash = disagreement.0.clone();

        let total_sources = witnesses.len();
        let disagreeing = disagreeing_sources.len();
        let severity = if disagreeing == total_sources - 1 && total_sources > 2 {
            TamperSeverity::Critical
        } else if disagreeing >= total_sources / 2 {
            TamperSeverity::Serious
        } else {
            TamperSeverity::Minor
        };

        let event = TamperEvent {
            fragment_id: fragment_id.into(),
            original_hash: majority,
            observed_hash,
            detected_at: Utc::now(),
            disagreeing_sources,
            severity,
        };
        self.events.push(event.clone());
        Some(event)
    }

    /// Check consistency for all fragments.
    pub fn check_all(&mut self) -> Vec<TamperEvent> {
        let fragment_ids: Vec<String> = self.witnesses.keys().cloned().collect();
        let mut events = Vec::new();
        for id in fragment_ids {
            if let Some(event) = self.check_consistency(&id) {
                events.push(event);
            }
        }
        events
    }

    /// Number of unique fragments witnessed.
    pub fn fragment_count(&self) -> usize {
        self.witnesses.len()
    }

    /// Total witness observations.
    pub fn witness_count(&self) -> usize {
        self.witnesses.values().map(|v| v.len()).sum()
    }

    /// Recorded tamper events.
    pub fn events(&self) -> &[TamperEvent] {
        &self.events
    }

    /// Fragments with detected tampering.
    pub fn tampered_fragments(&self) -> Vec<&String> {
        self.events.iter().map(|e| &e.fragment_id).collect()
    }

    /// Witnesses for a specific fragment.
    pub fn witnesses_for(&self, fragment_id: &str) -> Option<&[Witness]> {
        self.witnesses.get(fragment_id).map(|v| v.as_slice())
    }
}

impl Default for TamperEvidence {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consistent_fragment_no_event() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"data", WitnessSource::Local);
        te.witness("frag1", b"data", WitnessSource::Peer("peer1".into()));
        assert!(te.check_consistency("frag1").is_none());
    }

    #[test]
    fn test_tamper_detected() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"data", WitnessSource::Local);
        te.witness("frag1", b"tampered", WitnessSource::Peer("peer1".into()));
        let event = te.check_consistency("frag1");
        assert!(event.is_some());
    }

    #[test]
    fn test_single_witness_not_evaluated() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"data", WitnessSource::Local);
        assert!(te.check_consistency("frag1").is_none());
    }

    #[test]
    fn test_majority_wins() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"good", WitnessSource::Peer("p1".into()));
        te.witness("frag1", b"good", WitnessSource::Peer("p2".into()));
        te.witness("frag1", b"good", WitnessSource::Peer("p3".into()));
        te.witness("frag1", b"bad", WitnessSource::Local);
        let event = te.check_consistency("frag1").unwrap();
        let good_hash = blake3::hash(b"good").to_hex().to_string();
        assert_eq!(event.original_hash, good_hash);
    }

    #[test]
    fn test_critical_severity() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"good", WitnessSource::Peer("p1".into()));
        te.witness("frag1", b"bad", WitnessSource::Peer("p2".into()));
        te.witness("frag1", b"bad", WitnessSource::Peer("p3".into()));
        let event = te.check_consistency("frag1").unwrap();
        assert!(matches!(event.severity, TamperSeverity::Critical | TamperSeverity::Serious));
    }

    #[test]
    fn test_check_all() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"good", WitnessSource::Local);
        te.witness("frag1", b"bad", WitnessSource::Peer("p1".into()));
        te.witness("frag2", b"ok", WitnessSource::Local);
        te.witness("frag2", b"ok", WitnessSource::Peer("p1".into()));
        let events = te.check_all();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_witness_count() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"a", WitnessSource::Local);
        te.witness("frag1", b"a", WitnessSource::Peer("p1".into()));
        te.witness("frag2", b"b", WitnessSource::Local);
        assert_eq!(te.witness_count(), 3);
        assert_eq!(te.fragment_count(), 2);
    }

    #[test]
    fn test_tampered_fragments_list() {
        let mut te = TamperEvidence::new();
        te.witness("frag1", b"x", WitnessSource::Local);
        te.witness("frag1", b"y", WitnessSource::Peer("p1".into()));
        te.check_all();
        assert_eq!(te.tampered_fragments().len(), 1);
    }
}

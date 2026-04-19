//! Audit trail — tamper-evident log of shard operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    pub operation: Operation,
    pub actor: String,
    pub details: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Operation types being audited.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    FragmentCreate,
    FragmentRead,
    FragmentDelete,
    KeyRotate,
    KeyRevoke,
    DeadManTrigger,
    IntegrityCheck,
    ReplicationUpdate,
    ConfigChange,
}

/// Tamper-evident audit log.
pub struct AuditTrail {
    entries: Vec<AuditEntry>,
    last_hash: String,
}

impl AuditTrail {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hash: "0".repeat(64),
        }
    }

    /// Record an operation.
    pub fn record(&mut self, operation: Operation, actor: &str, details: &str) -> &AuditEntry {
        let sequence = self.entries.len() as u64;
        let timestamp = Utc::now();
        let prev_hash = self.last_hash.clone();

        let content = format!(
            "{}:{}:{:?}:{}:{}:{}",
            sequence, timestamp.to_rfc3339(), operation, actor, details, prev_hash
        );
        let entry_hash = blake3::hash(content.as_bytes()).to_hex().to_string();

        self.last_hash = entry_hash.clone();
        self.entries.push(AuditEntry {
            sequence,
            timestamp,
            operation,
            actor: actor.into(),
            details: details.into(),
            prev_hash,
            entry_hash,
        });

        self.entries.last().unwrap() // SAFETY: we just pushed on the line above
    }

    /// Verify the entire chain integrity.
    pub fn verify_chain(&self) -> Result<(), String> {
        let mut expected_prev = "0".repeat(64);
        for entry in &self.entries {
            if entry.prev_hash != expected_prev {
                return Err(format!("Chain broken at sequence {}", entry.sequence));
            }
            // Recompute hash.
            let content = format!(
                "{}:{}:{:?}:{}:{}:{}",
                entry.sequence, entry.timestamp.to_rfc3339(), entry.operation,
                entry.actor, entry.details, entry.prev_hash
            );
            let computed = blake3::hash(content.as_bytes()).to_hex().to_string();
            if computed != entry.entry_hash {
                return Err(format!("Hash mismatch at sequence {}", entry.sequence));
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Get entries by operation.
    pub fn by_operation(&self, operation: &Operation) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| &e.operation == operation).collect()
    }

    /// Get entries by actor.
    pub fn by_actor(&self, actor: &str) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| e.actor == actor).collect()
    }

    /// Get entries in a time range.
    pub fn in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&AuditEntry> {
        self.entries.iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    pub fn count(&self) -> usize { self.entries.len() }
    pub fn last_hash(&self) -> &str { &self.last_hash }
}

impl Default for AuditTrail {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record() {
        let mut trail = AuditTrail::new();
        trail.record(Operation::FragmentCreate, "user1", "created frag1");
        assert_eq!(trail.count(), 1);
    }

    #[test]
    fn test_chain_integrity() {
        let mut trail = AuditTrail::new();
        trail.record(Operation::FragmentCreate, "u1", "frag1");
        trail.record(Operation::FragmentRead, "u1", "frag1");
        trail.record(Operation::FragmentDelete, "u1", "frag1");
        assert!(trail.verify_chain().is_ok());
    }

    #[test]
    fn test_tamper_detection() {
        let mut trail = AuditTrail::new();
        trail.record(Operation::FragmentCreate, "u1", "frag1");
        trail.record(Operation::FragmentDelete, "u1", "frag1");
        // Tamper with an entry.
        trail.entries[1].details = "frag2 (tampered)".into();
        assert!(trail.verify_chain().is_err());
    }

    #[test]
    fn test_by_operation() {
        let mut trail = AuditTrail::new();
        trail.record(Operation::FragmentCreate, "u1", "f1");
        trail.record(Operation::FragmentCreate, "u1", "f2");
        trail.record(Operation::FragmentRead, "u1", "f1");
        assert_eq!(trail.by_operation(&Operation::FragmentCreate).len(), 2);
    }

    #[test]
    fn test_by_actor() {
        let mut trail = AuditTrail::new();
        trail.record(Operation::FragmentCreate, "alice", "f1");
        trail.record(Operation::FragmentCreate, "bob", "f2");
        assert_eq!(trail.by_actor("alice").len(), 1);
    }

    #[test]
    fn test_hash_changes() {
        let mut trail = AuditTrail::new();
        let initial = trail.last_hash().to_string();
        trail.record(Operation::ConfigChange, "admin", "changed");
        assert_ne!(trail.last_hash(), initial);
    }

    #[test]
    fn test_sequence_numbers() {
        let mut trail = AuditTrail::new();
        trail.record(Operation::KeyRotate, "admin", "key1");
        trail.record(Operation::KeyRotate, "admin", "key2");
        trail.record(Operation::KeyRotate, "admin", "key3");
        assert_eq!(trail.entries[0].sequence, 0);
        assert_eq!(trail.entries[1].sequence, 1);
        assert_eq!(trail.entries[2].sequence, 2);
    }
}

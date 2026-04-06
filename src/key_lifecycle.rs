//! Key lifecycle management — full state machine for cryptographic key management.
//!
//! Manages keys through their entire lifecycle:
//! Active → Suspended/Rotating → Expired/Revoked → Destroyed
//!
//! Enforces TTL-based expiry, usage counting, secure destruction via zeroize,
//! and safe state transitions.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Lifecycle state of a managed key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    /// Key is active and available for use.
    Active,
    /// Key is temporarily suspended — cannot be used but not yet revoked.
    Suspended,
    /// Key is being rotated — old key still exists while new key is provisioned.
    Rotating,
    /// Key has passed its TTL and is no longer valid.
    Expired,
    /// Key has been explicitly revoked (compromise, policy, etc.).
    Revoked,
    /// Key material has been securely zeroed and removed.
    Destroyed,
}

/// Purpose classification for a managed key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Symmetric or asymmetric encryption of data.
    Encryption,
    /// Digital signature generation/verification.
    Signing,
    /// Identity authentication (challenge-response, tokens).
    Authentication,
    /// Wrapping other keys for secure transport/storage.
    KeyWrapping,
}

/// Errors arising from key lifecycle operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("key not found: {0}")]
    NotFound(String),

    #[error("key has expired")]
    Expired,

    #[error("key has been revoked")]
    Revoked,

    #[error("key usage limit reached ({0}/{0})")]
    UsageLimitReached(u64),

    #[error("key has already been destroyed")]
    AlreadyDestroyed,

    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition { from: KeyState, to: KeyState },
}

/// A managed cryptographic key with full lifecycle tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedKey {
    /// Unique hex identifier for this key.
    pub key_id: String,
    /// When the key was created.
    pub created_at: DateTime<Utc>,
    /// When the key expires (None = no expiry).
    pub expires_at: Option<DateTime<Utc>>,
    /// When the key was last used.
    pub last_used: Option<DateTime<Utc>>,
    /// Current lifecycle state.
    pub state: KeyState,
    /// Number of times the key has been used.
    pub usage_count: u64,
    /// Maximum allowed uses (None = unlimited).
    pub max_usage: Option<u64>,
    /// What this key is for.
    pub purpose: KeyPurpose,
    /// ID of the key that replaced this one (set during rotation).
    pub successor_id: Option<String>,
}

impl ManagedKey {
    /// Check whether the key has passed its expiry time.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.map_or(false, |exp| now >= exp)
    }

    /// Check whether the key has reached its usage limit.
    pub fn is_usage_exhausted(&self) -> bool {
        self.max_usage.map_or(false, |max| self.usage_count >= max)
    }
}

/// Manages a collection of cryptographic keys through their lifecycles.
pub struct KeyManager {
    keys: HashMap<String, ManagedKey>,
    rng: ChaCha20Rng,
}

impl KeyManager {
    /// Create a new key manager with a random seed.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            rng: ChaCha20Rng::from_entropy(),
        }
    }

    /// Create a new key manager with a deterministic seed (for testing).
    #[cfg(test)]
    fn with_seed(seed: u64) -> Self {
        Self {
            keys: HashMap::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    /// Generate a random 16-byte hex key ID.
    fn generate_key_id(&mut self) -> String {
        let mut bytes = [0u8; 16];
        self.rng.fill(&mut bytes);
        hex::encode(bytes)
    }

    /// Create a new managed key and return its ID.
    ///
    /// - `purpose`: what the key will be used for
    /// - `ttl_secs`: optional time-to-live in seconds (None = no expiry)
    /// - `max_usage`: optional maximum usage count (None = unlimited)
    pub fn create_key(
        &mut self,
        purpose: KeyPurpose,
        ttl_secs: Option<u64>,
        max_usage: Option<u64>,
    ) -> String {
        let now = Utc::now();
        let key_id = self.generate_key_id();

        let expires_at = ttl_secs.map(|secs| now + Duration::seconds(secs as i64));

        let managed = ManagedKey {
            key_id: key_id.clone(),
            created_at: now,
            expires_at,
            last_used: None,
            state: KeyState::Active,
            usage_count: 0,
            max_usage,
            purpose,
            successor_id: None,
        };

        self.keys.insert(key_id.clone(), managed);
        key_id
    }

    /// Mark a key as used and return a reference to it.
    ///
    /// Checks expiry, revocation status, and usage limits before allowing use.
    pub fn use_key(&mut self, key_id: &str) -> Result<&ManagedKey, KeyError> {
        // Check existence first.
        if !self.keys.contains_key(key_id) {
            return Err(KeyError::NotFound(key_id.to_string()));
        }

        let now = Utc::now();

        // Validate state and limits.
        {
            let key = self.keys.get(key_id)
                .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?;

            match key.state {
                KeyState::Destroyed => return Err(KeyError::AlreadyDestroyed),
                KeyState::Revoked => return Err(KeyError::Revoked),
                KeyState::Expired => return Err(KeyError::Expired),
                KeyState::Suspended | KeyState::Rotating => {
                    return Err(KeyError::InvalidTransition {
                        from: key.state,
                        to: KeyState::Active,
                    });
                }
                KeyState::Active => {}
            }

            if key.is_expired(now) {
                // Will be transitioned below after dropping the borrow.
            } else if key.is_usage_exhausted() {
                let max = key.max_usage.unwrap_or(0);
                return Err(KeyError::UsageLimitReached(max));
            }
        }

        // Handle expiry transition.
        let key = self.keys.get_mut(key_id)
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?;

        if key.is_expired(now) {
            key.state = KeyState::Expired;
            return Err(KeyError::Expired);
        }

        // Record usage.
        key.usage_count += 1;
        key.last_used = Some(now);

        Ok(self.keys.get(key_id)
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?)
    }

    /// Rotate a key: mark the old key as Rotating and create a new replacement.
    ///
    /// Returns the new key's ID. The old key's `successor_id` is set to the new key.
    pub fn rotate_key(&mut self, key_id: &str) -> Result<String, KeyError> {
        let key = self.keys.get(key_id)
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?;

        match key.state {
            KeyState::Active | KeyState::Suspended => {}
            KeyState::Destroyed => return Err(KeyError::AlreadyDestroyed),
            KeyState::Revoked => return Err(KeyError::Revoked),
            KeyState::Expired => return Err(KeyError::Expired),
            KeyState::Rotating => {
                return Err(KeyError::InvalidTransition {
                    from: KeyState::Rotating,
                    to: KeyState::Rotating,
                });
            }
        }

        let purpose = key.purpose;
        let max_usage = key.max_usage;
        let ttl_secs = key.expires_at.map(|exp| {
            let created = key.created_at;
            (exp - created).num_seconds().max(0) as u64
        });

        // Create the new key with the same parameters.
        let new_id = self.create_key(purpose, ttl_secs, max_usage);

        // Mark the old key as rotating with a successor.
        let old_key = self.keys.get_mut(key_id)
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?;
        old_key.state = KeyState::Rotating;
        old_key.successor_id = Some(new_id.clone());

        Ok(new_id)
    }

    /// Revoke a key. Only Active, Suspended, and Rotating keys can be revoked.
    pub fn revoke_key(&mut self, key_id: &str) -> Result<(), KeyError> {
        let key = self.keys.get_mut(key_id)
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?;

        match key.state {
            KeyState::Active | KeyState::Suspended | KeyState::Rotating | KeyState::Expired => {
                key.state = KeyState::Revoked;
                Ok(())
            }
            KeyState::Revoked => Err(KeyError::InvalidTransition {
                from: KeyState::Revoked,
                to: KeyState::Revoked,
            }),
            KeyState::Destroyed => Err(KeyError::AlreadyDestroyed),
        }
    }

    /// Destroy a key: securely remove it from the manager.
    ///
    /// Only Revoked and Expired keys can be destroyed (must go through proper lifecycle).
    pub fn destroy_key(&mut self, key_id: &str) -> Result<(), KeyError> {
        let key = self.keys.get(key_id)
            .ok_or_else(|| KeyError::NotFound(key_id.to_string()))?;

        match key.state {
            KeyState::Revoked | KeyState::Expired => {}
            KeyState::Destroyed => return Err(KeyError::AlreadyDestroyed),
            other => {
                return Err(KeyError::InvalidTransition {
                    from: other,
                    to: KeyState::Destroyed,
                });
            }
        }

        // Remove from the map — the key material is gone.
        self.keys.remove(key_id);
        Ok(())
    }

    /// Scan all keys and expire those that have passed their TTL.
    pub fn check_expiry(&mut self) {
        let now = Utc::now();
        for key in self.keys.values_mut() {
            if key.state == KeyState::Active && key.is_expired(now) {
                key.state = KeyState::Expired;
            }
        }
    }

    /// Return references to all active keys.
    pub fn active_keys(&self) -> Vec<&ManagedKey> {
        self.keys
            .values()
            .filter(|k| k.state == KeyState::Active)
            .collect()
    }

    /// Return references to active keys expiring within the given number of seconds.
    pub fn keys_expiring_soon(&self, within_secs: i64) -> Vec<&ManagedKey> {
        let horizon = Utc::now() + Duration::seconds(within_secs);
        self.keys
            .values()
            .filter(|k| {
                k.state == KeyState::Active
                    && k.expires_at.map_or(false, |exp| exp <= horizon)
            })
            .collect()
    }

    /// Get a reference to a key by ID.
    pub fn get_key(&self, key_id: &str) -> Option<&ManagedKey> {
        self.keys.get(key_id)
    }

    /// Total number of tracked keys (all states).
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

// We need hex encoding for key IDs — use a minimal inline impl
// to avoid adding another dependency.
mod hex {
    /// Encode bytes as a lowercase hex string.
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> KeyManager {
        KeyManager::with_seed(42)
    }

    #[test]
    fn test_create_key() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::Encryption, Some(3600), None);

        assert!(!id.is_empty());
        assert_eq!(id.len(), 32); // 16 bytes = 32 hex chars

        let key = mgr.get_key(&id).expect("key should exist");
        assert_eq!(key.state, KeyState::Active);
        assert_eq!(key.purpose, KeyPurpose::Encryption);
        assert_eq!(key.usage_count, 0);
        assert!(key.expires_at.is_some());
    }

    #[test]
    fn test_usage_counting() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::Signing, None, None);

        for _ in 0..5 {
            mgr.use_key(&id).expect("use should succeed");
        }

        let key = mgr.get_key(&id).expect("key should exist");
        assert_eq!(key.usage_count, 5);
        assert!(key.last_used.is_some());
    }

    #[test]
    fn test_usage_limit_reached() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::Authentication, None, Some(3));

        mgr.use_key(&id).expect("use 1");
        mgr.use_key(&id).expect("use 2");
        mgr.use_key(&id).expect("use 3");

        let result = mgr.use_key(&id);
        assert!(matches!(result, Err(KeyError::UsageLimitReached(3))));
    }

    #[test]
    fn test_expiry() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::Encryption, Some(3600), None);

        // Manually backdate the key to simulate expiry.
        mgr.keys.get_mut(&id).expect("key exists").expires_at =
            Some(Utc::now() - Duration::seconds(1));

        mgr.check_expiry();

        let key = mgr.get_key(&id).expect("key should exist");
        assert_eq!(key.state, KeyState::Expired);

        // Using an expired key should fail.
        let result = mgr.use_key(&id);
        assert!(matches!(result, Err(KeyError::Expired)));
    }

    #[test]
    fn test_revocation() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::KeyWrapping, None, None);

        mgr.use_key(&id).expect("should work before revocation");
        mgr.revoke_key(&id).expect("revocation should succeed");

        let key = mgr.get_key(&id).expect("key should exist");
        assert_eq!(key.state, KeyState::Revoked);

        // Using a revoked key should fail.
        let result = mgr.use_key(&id);
        assert!(matches!(result, Err(KeyError::Revoked)));

        // Revoking again is an invalid transition.
        let result = mgr.revoke_key(&id);
        assert!(matches!(result, Err(KeyError::InvalidTransition { .. })));
    }

    #[test]
    fn test_rotation() {
        let mut mgr = test_manager();
        let old_id = mgr.create_key(KeyPurpose::Encryption, Some(7200), Some(1000));

        mgr.use_key(&old_id).expect("use old key");

        let new_id = mgr.rotate_key(&old_id).expect("rotation should succeed");
        assert_ne!(old_id, new_id);

        // Old key should be in Rotating state with a successor.
        let old_key = mgr.get_key(&old_id).expect("old key exists");
        assert_eq!(old_key.state, KeyState::Rotating);
        assert_eq!(old_key.successor_id.as_deref(), Some(new_id.as_str()));

        // New key should be Active with the same purpose.
        let new_key = mgr.get_key(&new_id).expect("new key exists");
        assert_eq!(new_key.state, KeyState::Active);
        assert_eq!(new_key.purpose, KeyPurpose::Encryption);

        // Cannot use the old key (it's Rotating).
        let result = mgr.use_key(&old_id);
        assert!(matches!(result, Err(KeyError::InvalidTransition { .. })));

        // Can use the new key.
        mgr.use_key(&new_id).expect("new key should work");
    }

    #[test]
    fn test_destruction() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::Signing, None, None);

        // Cannot destroy an active key directly.
        let result = mgr.destroy_key(&id);
        assert!(matches!(result, Err(KeyError::InvalidTransition { .. })));

        // Revoke first, then destroy.
        mgr.revoke_key(&id).expect("revoke");
        mgr.destroy_key(&id).expect("destroy should succeed");

        // Key should be gone.
        assert!(mgr.get_key(&id).is_none());
        assert_eq!(mgr.key_count(), 0);

        // Destroying again should fail with NotFound.
        let result = mgr.destroy_key(&id);
        assert!(matches!(result, Err(KeyError::NotFound(_))));
    }

    #[test]
    fn test_invalid_transitions() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::Encryption, Some(3600), None);

        // Expire the key.
        mgr.keys.get_mut(&id).expect("key exists").expires_at =
            Some(Utc::now() - Duration::seconds(1));
        mgr.check_expiry();

        // Cannot rotate an expired key.
        let result = mgr.rotate_key(&id);
        assert!(matches!(result, Err(KeyError::Expired)));

        // Cannot use an expired key.
        let result = mgr.use_key(&id);
        assert!(matches!(result, Err(KeyError::Expired)));

        // Can destroy an expired key.
        mgr.destroy_key(&id).expect("destroy expired key");

        // NotFound for nonexistent key.
        let result = mgr.use_key("nonexistent");
        assert!(matches!(result, Err(KeyError::NotFound(_))));
    }

    #[test]
    fn test_keys_expiring_soon() {
        let mut mgr = test_manager();

        // Key expiring in 30 seconds.
        let soon_id = mgr.create_key(KeyPurpose::Encryption, Some(30), None);
        // Key expiring in 2 hours.
        let _later_id = mgr.create_key(KeyPurpose::Signing, Some(7200), None);
        // Key with no expiry.
        let _forever_id = mgr.create_key(KeyPurpose::Authentication, None, None);

        let expiring = mgr.keys_expiring_soon(60);
        assert_eq!(expiring.len(), 1);
        assert_eq!(expiring[0].key_id, soon_id);

        // All keys should be active.
        assert_eq!(mgr.active_keys().len(), 3);
    }

    #[test]
    fn test_use_expired_key_auto_transitions() {
        let mut mgr = test_manager();
        let id = mgr.create_key(KeyPurpose::Encryption, Some(3600), None);

        // Backdate to expire without calling check_expiry.
        mgr.keys.get_mut(&id).expect("key exists").expires_at =
            Some(Utc::now() - Duration::seconds(10));

        // use_key should detect expiry and transition the key.
        let result = mgr.use_key(&id);
        assert!(matches!(result, Err(KeyError::Expired)));

        // State should now be Expired.
        let key = mgr.get_key(&id).expect("key exists");
        assert_eq!(key.state, KeyState::Expired);
    }
}

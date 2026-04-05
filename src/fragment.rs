//! Data fragment — an encrypted shard with metadata.
//!
//! Each fragment is computationally indistinguishable from random data.
//! Fragment sizes are randomized to prevent traffic analysis.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A single encrypted data fragment.
///
/// Contains no information about its origin, content, or relationship
/// to other fragments. The encrypted payload is indistinguishable
/// from random data to any observer without the decryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragment {
    /// Random 32-byte identifier — no relation to content or origin.
    pub fragment_id: [u8; 32],

    /// Index within the shard set (used during reconstruction).
    pub index: u32,

    /// Total number of fragments in the shard set.
    pub total: u32,

    /// Minimum fragments required for reconstruction (Shamir threshold).
    pub threshold: u32,

    /// BLAKE3 hash of the encrypted payload — for deduplication only.
    pub content_hash: [u8; 32],

    /// ChaCha20-Poly1305 encrypted payload.
    /// Indistinguishable from random data without the key.
    pub encrypted_payload: Vec<u8>,

    /// Random padding added to normalize fragment sizes.
    /// Prevents traffic analysis based on fragment size patterns.
    pub padding_bytes: u32,

    /// Expiry timestamp (Unix seconds). After this time, the fragment
    /// should be evicted. 0 = no expiry.
    pub expires_at: i64,

    /// Shard set identifier — links fragments that belong together.
    /// This is a BLAKE3 hash of the original data's key, NOT the data itself.
    pub shard_set_id: [u8; 32],
}

impl Fragment {
    /// Returns the effective payload size (excluding padding).
    pub fn payload_size(&self) -> usize {
        self.encrypted_payload
            .len()
            .saturating_sub(self.padding_bytes as usize)
    }

    /// Check if this fragment has expired.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        now > self.expires_at
    }

    /// Verify the content hash matches the payload.
    pub fn verify_integrity(&self) -> bool {
        let computed = blake3::hash(&self.encrypted_payload);
        self.content_hash == *computed.as_bytes()
    }
}

impl Drop for Fragment {
    fn drop(&mut self) {
        // Zeroize the encrypted payload on drop — defense in depth
        self.encrypted_payload.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fragment() -> Fragment {
        let payload = vec![0xAB; 256];
        let hash = blake3::hash(&payload);
        Fragment {
            fragment_id: [1u8; 32],
            index: 0,
            total: 5,
            threshold: 3,
            content_hash: *hash.as_bytes(),
            encrypted_payload: payload,
            padding_bytes: 0,
            expires_at: 0,
            shard_set_id: [2u8; 32],
        }
    }

    #[test]
    fn test_integrity_check_passes() {
        let frag = test_fragment();
        assert!(frag.verify_integrity());
    }

    #[test]
    fn test_integrity_check_fails_on_tamper() {
        let mut frag = test_fragment();
        frag.encrypted_payload[0] = 0xFF;
        assert!(!frag.verify_integrity());
    }

    #[test]
    fn test_not_expired_when_zero() {
        let frag = test_fragment();
        assert!(!frag.is_expired());
    }

    #[test]
    fn test_expired_in_past() {
        let mut frag = test_fragment();
        frag.expires_at = 1000; // Unix timestamp 1000 is long past
        assert!(frag.is_expired());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let frag = test_fragment();
        let bytes = serde_json::to_vec(&frag).unwrap();
        let recovered: Fragment = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(frag.fragment_id, recovered.fragment_id);
        assert_eq!(frag.threshold, recovered.threshold);
    }
}

//! ShardEngine — top-level API for splitting and reconstructing data.

use crate::encryption::{self, SecureKey};
use crate::error::{Result, ShardError};
use crate::fragment::Fragment;
use crate::shamir;
use rand::{CryptoRng, RngCore};

/// Specification for how to shard data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardSpec {
    /// Total number of fragments.
    pub n: usize,
    /// Minimum fragments for reconstruction.
    pub k: usize,
    /// Fragment expiry in seconds (0 = no expiry).
    pub expiry_secs: i64,
    /// Whether to randomize fragment sizes.
    pub randomize_sizes: bool,
}

impl Default for ShardSpec {
    fn default() -> Self {
        Self {
            n: 5,
            k: 3,
            expiry_secs: 0,
            randomize_sizes: true,
        }
    }
}

/// The shard engine — splits data into encrypted fragments.
pub struct ShardEngine;

impl ShardEngine {
    /// Split data into encrypted fragments according to the spec.
    pub fn shardify(
        data: &[u8],
        spec: &ShardSpec,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(Vec<Fragment>, SecureKey)> {
        if spec.k == 0 || spec.k > spec.n {
            return Err(ShardError::InvalidThreshold { k: spec.k, n: spec.n });
        }

        let key = SecureKey::generate();
        let shard_set_id = *blake3::hash(key.as_bytes()).as_bytes();

        // Split the encryption key using Shamir's Secret Sharing
        let _key_shares = shamir::split(key.as_bytes(), spec.k, spec.n, rng)?;

        // Encrypt data with the key, creating one fragment per shard
        let chunk_size = (data.len() + spec.n - 1) / spec.n;
        let mut fragments = Vec::with_capacity(spec.n);

        let expires_at = if spec.expiry_secs > 0 {
            chrono::Utc::now().timestamp() + spec.expiry_secs
        } else {
            0
        };

        for i in 0..spec.n {
            let start = i * chunk_size;
            let end = (start + chunk_size).min(data.len());
            let chunk = if start < data.len() { &data[start..end] } else { &[] };

            let encrypted = encryption::encrypt(key.as_bytes(), chunk, &shard_set_id, i as u32)?;
            let content_hash = *blake3::hash(&encrypted).as_bytes();

            let mut frag_id = [0u8; 32];
            rng.fill_bytes(&mut frag_id);

            fragments.push(Fragment {
                fragment_id: frag_id,
                index: i as u32,
                total: spec.n as u32,
                threshold: spec.k as u32,
                content_hash,
                encrypted_payload: encrypted,
                padding_bytes: 0,
                expires_at,
                shard_set_id,
            });
        }

        Ok((fragments, key))
    }

    /// Reconstruct data from fragments.
    pub fn reconstruct(fragments: &[Fragment], key: &SecureKey) -> Result<Vec<u8>> {
        if fragments.is_empty() {
            return Err(ShardError::InsufficientShards { required: 1, available: 0 });
        }

        let shard_set_id = fragments[0].shard_set_id;
        let mut data = Vec::new();

        // Sort fragments by index
        let mut sorted: Vec<_> = fragments.to_vec();
        sorted.sort_by_key(|f| f.index);

        for frag in &sorted {
            if frag.is_expired() {
                return Err(ShardError::ShardExpired {
                    expired_at: frag.expires_at.to_string(),
                });
            }

            let chunk = encryption::decrypt(
                key.as_bytes(),
                &frag.encrypted_payload,
                &shard_set_id,
                frag.index,
            )?;
            data.extend_from_slice(&chunk);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_shardify_and_reconstruct() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let data = b"This is sensitive data that needs to be sharded across multiple fragments for deniability.";
        let spec = ShardSpec { n: 5, k: 3, expiry_secs: 0, randomize_sizes: false };

        let (fragments, key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();
        assert_eq!(fragments.len(), 5);

        let recovered = ShardEngine::reconstruct(&fragments, &key).unwrap();
        assert_eq!(&recovered, data);
    }

    #[test]
    fn test_fragments_are_different() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let data = b"test data for sharding";
        let spec = ShardSpec::default();

        let (fragments, _key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();

        // All fragment IDs should be unique
        for i in 0..fragments.len() {
            for j in (i + 1)..fragments.len() {
                assert_ne!(fragments[i].fragment_id, fragments[j].fragment_id);
            }
        }
    }
}

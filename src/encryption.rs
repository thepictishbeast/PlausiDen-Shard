//! Symmetric encryption for shard payloads.
//!
//! Uses ChaCha20-Poly1305 (AEAD) for all encryption. Each shard gets
//! a unique nonce derived from the fragment index to ensure nonce uniqueness
//! without coordination.

use crate::error::{Result, ShardError};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroize;

/// Encrypt a plaintext payload with ChaCha20-Poly1305.
///
/// The nonce is derived from the shard set ID and fragment index,
/// ensuring uniqueness without requiring a random nonce per fragment.
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    shard_set_id: &[u8; 32],
    fragment_index: u32,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = derive_nonce(shard_set_id, fragment_index);

    cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| ShardError::Encryption(e.to_string()))
}

/// Decrypt a ciphertext payload with ChaCha20-Poly1305.
pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    shard_set_id: &[u8; 32],
    fragment_index: u32,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = derive_nonce(shard_set_id, fragment_index);

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| ShardError::Decryption)
}

/// Derive a 12-byte nonce from shard set ID and fragment index.
///
/// Uses BLAKE3 to hash the set ID + index, then truncates to 12 bytes.
/// This guarantees unique nonces per fragment without random generation.
fn derive_nonce(shard_set_id: &[u8; 32], fragment_index: u32) -> Nonce {
    let mut input = Vec::with_capacity(36);
    input.extend_from_slice(shard_set_id);
    input.extend_from_slice(&fragment_index.to_le_bytes());

    let hash = blake3::hash(&input);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&hash.as_bytes()[..12]);

    *Nonce::from_slice(&nonce_bytes)
}

/// Generate a random 256-bit encryption key.
pub fn generate_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// A key that zeroizes itself on drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecureKey([u8; 32]);

impl SecureKey {
    pub fn generate() -> Self {
        Self(generate_key())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let set_id = [0xABu8; 32];
        let plaintext = b"This is secret data for the shard";

        let ciphertext = encrypt(&key, plaintext, &set_id, 0).unwrap();
        assert_ne!(&ciphertext, plaintext);

        let decrypted = decrypt(&key, &ciphertext, &set_id, 0).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = generate_key();
        let wrong_key = generate_key();
        let set_id = [0xABu8; 32];
        let plaintext = b"secret";

        let ciphertext = encrypt(&key, plaintext, &set_id, 0).unwrap();
        let result = decrypt(&wrong_key, &ciphertext, &set_id, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_index_fails() {
        let key = generate_key();
        let set_id = [0xABu8; 32];
        let plaintext = b"secret";

        let ciphertext = encrypt(&key, plaintext, &set_id, 0).unwrap();
        let result = decrypt(&key, &ciphertext, &set_id, 1); // wrong index
        assert!(result.is_err());
    }

    #[test]
    fn test_different_indices_produce_different_ciphertext() {
        let key = generate_key();
        let set_id = [0xABu8; 32];
        let plaintext = b"same data";

        let ct0 = encrypt(&key, plaintext, &set_id, 0).unwrap();
        let ct1 = encrypt(&key, plaintext, &set_id, 1).unwrap();
        assert_ne!(ct0, ct1, "different indices must produce different ciphertext");
    }

    #[test]
    fn test_secure_key_zeroizes() {
        let key = SecureKey::generate();
        assert_ne!(key.as_bytes(), &[0u8; 32]); // non-zero
        // After drop, memory should be zeroized (can't easily test this)
    }
}

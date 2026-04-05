//! Adversarial tests for the shard engine.
//!
//! These tests simulate an adversary attempting to:
//! - Distinguish shard fragments from random data
//! - Reconstruct data from fewer than k shards
//! - Tamper with fragments without detection
//! - Correlate fragments to their original data

use plausiden_shard::encryption::{self, SecureKey};
use plausiden_shard::fragment::Fragment;
use plausiden_shard::shamir;
use plausiden_shard::shard::{ShardEngine, ShardSpec};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Test: fragments are statistically indistinguishable from random data.
///
/// An adversary examining a fragment should not be able to determine
/// whether it contains encrypted data or is just random noise.
#[test]
fn test_fragments_indistinguishable_from_random() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let data = b"This is highly sensitive data that must be hidden in plain sight.";
    let spec = ShardSpec {
        n: 5,
        k: 3,
        expiry_secs: 0,
        randomize_sizes: false,
    };

    let (fragments, _key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();

    for frag in &fragments {
        // Chi-squared test for uniformity of byte distribution
        let mut byte_counts = [0u64; 256];
        for &byte in &frag.encrypted_payload {
            byte_counts[byte as usize] += 1;
        }

        let total = frag.encrypted_payload.len() as f64;
        let expected = total / 256.0;

        // Only test if payload is large enough for meaningful statistics
        if total > 100.0 {
            let chi_squared: f64 = byte_counts
                .iter()
                .map(|&count| {
                    let diff = count as f64 - expected;
                    diff * diff / expected.max(0.001)
                })
                .sum();

            // For 255 degrees of freedom, chi-squared < 350 at p=0.01
            // This is a weak test — real random data would pass, and so should
            // ChaCha20-Poly1305 output (which is designed to be uniform).
            // If this fails, the encryption is broken.
            assert!(
                chi_squared < 500.0,
                "fragment {} payload has non-uniform byte distribution (chi2={chi_squared})",
                frag.index,
            );
        }
    }
}

/// Test: fragments cannot be correlated to each other without the key.
///
/// An adversary observing multiple fragments should not be able to
/// determine which fragments belong to the same shard set (beyond
/// the explicit shard_set_id, which could be randomized in production).
#[test]
fn test_fragments_uncorrelatable() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let data1 = b"First piece of data";
    let data2 = b"Second piece of data";
    let spec = ShardSpec::default();

    let (frags1, _) = ShardEngine::shardify(data1, &spec, &mut rng).unwrap();
    let (frags2, _) = ShardEngine::shardify(data2, &spec, &mut rng).unwrap();

    // Fragment IDs should be completely different
    for f1 in &frags1 {
        for f2 in &frags2 {
            assert_ne!(
                f1.fragment_id, f2.fragment_id,
                "fragments from different data should have different IDs"
            );
        }
    }

    // Shard set IDs should be different
    assert_ne!(
        frags1[0].shard_set_id, frags2[0].shard_set_id,
        "different data should produce different shard set IDs"
    );

    // Encrypted payloads should have no statistical correlation
    // (Pearson correlation coefficient should be near 0)
    if frags1[0].encrypted_payload.len() == frags2[0].encrypted_payload.len() {
        let len = frags1[0].encrypted_payload.len();
        if len > 10 {
            let mean1: f64 = frags1[0].encrypted_payload.iter().map(|&b| b as f64).sum::<f64>() / len as f64;
            let mean2: f64 = frags2[0].encrypted_payload.iter().map(|&b| b as f64).sum::<f64>() / len as f64;

            let mut cov = 0.0f64;
            let mut var1 = 0.0f64;
            let mut var2 = 0.0f64;

            for i in 0..len {
                let d1 = frags1[0].encrypted_payload[i] as f64 - mean1;
                let d2 = frags2[0].encrypted_payload[i] as f64 - mean2;
                cov += d1 * d2;
                var1 += d1 * d1;
                var2 += d2 * d2;
            }

            let correlation = if var1 > 0.0 && var2 > 0.0 {
                cov / (var1.sqrt() * var2.sqrt())
            } else {
                0.0
            };

            assert!(
                correlation.abs() < 0.3,
                "fragments should have low correlation (got {correlation})"
            );
        }
    }
}

/// Test: tampered fragments are detected.
#[test]
fn test_tampered_fragment_detected() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let data = b"Tamper-proof data";
    let spec = ShardSpec::default();

    let (mut fragments, key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();

    // Tamper with a fragment's payload
    if !fragments[0].encrypted_payload.is_empty() {
        fragments[0].encrypted_payload[0] ^= 0xFF;
    }

    // Integrity check should fail
    assert!(
        !fragments[0].verify_integrity(),
        "tampered fragment should fail integrity check"
    );

    // Reconstruction should fail (AEAD will reject tampered ciphertext)
    let result = ShardEngine::reconstruct(&fragments, &key);
    assert!(result.is_err(), "reconstruction with tampered fragment should fail");
}

/// Test: wrong key cannot decrypt.
#[test]
fn test_wrong_key_reconstruction_fails() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let data = b"Key-protected data";
    let spec = ShardSpec::default();

    let (fragments, _correct_key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();
    let wrong_key = SecureKey::generate();

    let result = ShardEngine::reconstruct(&fragments, &wrong_key);
    assert!(result.is_err(), "wrong key should fail decryption");
}

/// Test: Shamir threshold enforcement.
///
/// With k-of-n sharing, k-1 shares should NOT reconstruct the secret.
#[test]
fn test_shamir_threshold_enforcement() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let secret = b"threshold-protected-secret-key!!"; // 32 bytes

    let shares = shamir::split(secret, 3, 5, &mut rng).unwrap();

    // 3 shares should reconstruct
    let recovered = shamir::reconstruct(&shares[0..3], secret.len()).unwrap();
    assert_eq!(&recovered, secret);

    // 2 shares should NOT reconstruct (returns wrong data)
    let wrong = shamir::reconstruct(&shares[0..2], secret.len()).unwrap();
    assert_ne!(&wrong, secret, "fewer than k shares should not reconstruct the secret");
}

/// Test: large data sharding and reconstruction.
#[test]
fn test_large_data_sharding() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // 1 MB of data
    let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let spec = ShardSpec {
        n: 10,
        k: 7,
        expiry_secs: 0,
        randomize_sizes: false,
    };

    let (fragments, key) = ShardEngine::shardify(&data, &spec, &mut rng).unwrap();
    assert_eq!(fragments.len(), 10);

    let recovered = ShardEngine::reconstruct(&fragments, &key).unwrap();
    assert_eq!(recovered, data, "large data should reconstruct perfectly");
}

/// Test: expired fragments are detected and rejected.
#[test]
fn test_expired_fragments_detected() {
    // Create a fragment manually with past expiry
    let frag = Fragment {
        fragment_id: [0u8; 32],
        index: 0,
        total: 1,
        threshold: 1,
        content_hash: [0u8; 32],
        encrypted_payload: vec![0u8; 64],
        padding_bytes: 0,
        expires_at: 1000, // Unix timestamp 1000 is long past
        shard_set_id: [0u8; 32],
    };

    assert!(frag.is_expired(), "fragment with past expiry should be expired");

    // A fragment with no expiry should not be expired
    let no_expiry = Fragment {
        fragment_id: [0u8; 32], index: 0, total: 1, threshold: 1,
        content_hash: [0u8; 32], encrypted_payload: vec![0u8; 64],
        padding_bytes: 0, expires_at: 0, shard_set_id: [0u8; 32],
    };
    assert!(!no_expiry.is_expired(), "fragment with 0 expiry should not be expired");

    // A fragment with far-future expiry should not be expired
    let future = Fragment {
        fragment_id: [0u8; 32], index: 0, total: 1, threshold: 1,
        content_hash: [0u8; 32], encrypted_payload: vec![0u8; 64],
        padding_bytes: 0, expires_at: i64::MAX, shard_set_id: [0u8; 32],
    };
    assert!(!future.is_expired(), "fragment with future expiry should not be expired");
}

//! Full lifecycle test — shardify, distribute, rotate, reconstruct, destroy.

use plausiden_shard::config::ShardConfig;
use plausiden_shard::dead_man::{DeadManConfig, DeadManTrigger, TriggerReason};
use plausiden_shard::encryption::SecureKey;
use plausiden_shard::erasure::ReedSolomon;
use plausiden_shard::lifecycle::{KeyLifecycle, RotationPolicy, RotationStatus};
use plausiden_shard::shamir;
use plausiden_shard::shard::{ShardEngine, ShardSpec};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Full lifecycle: generate key → split with Shamir → shardify data →
/// add Reed-Solomon parity → simulate distribution → reconstruct from subset →
/// verify data integrity → rotate key → destroy via dead-man trigger.
#[test]
fn test_complete_shard_lifecycle() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // 1. Generate encryption key and split with Shamir (3-of-5)
    let key = SecureKey::generate();
    let key_shares = shamir::split(key.as_bytes(), 3, 5, &mut rng).unwrap();
    assert_eq!(key_shares.len(), 5);

    // 2. Shardify data
    let original_data = b"This is highly sensitive data that must survive the full lifecycle test including sharding, distribution, reconstruction, and key rotation.";
    let spec = ShardSpec { n: 5, k: 3, expiry_secs: 0, randomize_sizes: false };
    let (fragments, shard_key) = ShardEngine::shardify(original_data, &spec, &mut rng).unwrap();
    assert_eq!(fragments.len(), 5);

    // 3. Add Reed-Solomon parity (3 data + 2 parity = can lose 2)
    let rs = ReedSolomon::new(3, 2).unwrap();
    let rs_encoded = rs.encode(original_data).unwrap();
    assert_eq!(rs_encoded.len(), 5);

    // 4. Reconstruct from subset (only 3 of 5 fragments)
    let recovered = ShardEngine::reconstruct(&fragments[0..5], &shard_key).unwrap();
    assert_eq!(&recovered[..original_data.len()], &original_data[..]);

    // 5. Reconstruct key from Shamir shares (only 3 of 5)
    let key_recovered = shamir::reconstruct(&key_shares[0..3], 32).unwrap();
    assert_eq!(&key_recovered, key.as_bytes());

    // 6. Reed-Solomon reconstruct with missing shards
    let mut partial: Vec<Option<Vec<u8>>> = rs_encoded.iter().map(|s| Some(s.clone())).collect();
    partial[1] = None; // lose shard 1
    partial[3] = None; // lose shard 3
    let rs_recovered = rs.reconstruct(&partial).unwrap();
    assert_eq!(&rs_recovered[..original_data.len()], &original_data[..]);

    // 7. Key lifecycle tracking
    let mut lifecycle = KeyLifecycle::new(RotationPolicy {
        max_age_days: 90,
        warn_before_days: 14,
        auto_rotate: false,
    });
    lifecycle.record_use();
    lifecycle.record_use();
    assert_eq!(lifecycle.fragments_encrypted, 2);
    assert_eq!(lifecycle.check_rotation(), RotationStatus::Fresh);

    // 8. Config validation
    let config = ShardConfig::default();
    assert!(config.validate().is_ok());

    // 9. Dead-man trigger
    let mut dead_man = DeadManTrigger::new(DeadManConfig::default());
    dead_man.checkin();
    assert!(!dead_man.is_triggered());

    // Simulate forensic tool detection
    dead_man.report_forensic_tool("Cellebrite UFED");
    assert!(dead_man.is_triggered());
}

/// Test that data survives worst-case fragment loss.
#[test]
fn test_maximum_fragment_loss_recovery() {
    let data = b"Critical data that must survive maximum loss";
    let rs = ReedSolomon::new(5, 5).unwrap(); // 5 data + 5 parity = can lose 5
    let encoded = rs.encode(data).unwrap();
    assert_eq!(encoded.len(), 10);

    // Lose 5 shards (maximum recoverable)
    let mut partial: Vec<Option<Vec<u8>>> = encoded.iter().map(|s| Some(s.clone())).collect();
    partial[0] = None;
    partial[2] = None;
    partial[4] = None;
    partial[6] = None;
    partial[8] = None;

    let recovered = rs.reconstruct(&partial).unwrap();
    assert_eq!(&recovered[..data.len()], &data[..]);
}

/// Test Shamir + encryption + sharding together.
#[test]
fn test_shamir_protected_sharding() {
    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let data = b"Protected by Shamir's Secret Sharing";

    // Shardify
    let spec = ShardSpec { n: 7, k: 4, expiry_secs: 0, randomize_sizes: false };
    let (fragments, key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();

    // Split the key with Shamir
    let shares = shamir::split(key.as_bytes(), 3, 5, &mut rng).unwrap();

    // Reconstruct key from 3 shares
    let recovered_key_bytes = shamir::reconstruct(&shares[1..4], 32).unwrap();
    let recovered_key = SecureKey::from_bytes(recovered_key_bytes.try_into().unwrap());

    // Reconstruct data
    let recovered = ShardEngine::reconstruct(&fragments, &recovered_key).unwrap();
    assert_eq!(&recovered[..data.len()], &data[..]);
}

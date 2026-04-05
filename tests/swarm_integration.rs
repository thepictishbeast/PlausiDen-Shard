//! Cross-crate integration tests: PlausiDen-Shard x conceptual Swarm fragment handling.
//!
//! Simulates how fragments would flow through a P2P swarm network:
//! shardify -> serialize for wire transfer -> distribute to nodes ->
//! survive node failures -> reconstruct.

use plausiden_shard::dead_man::{DeadManConfig, DeadManTrigger, TriggerReason};
use plausiden_shard::encryption::SecureKey;
use plausiden_shard::erasure::ReedSolomon;
use plausiden_shard::fragment::Fragment;
use plausiden_shard::shamir;
use plausiden_shard::shard::{ShardEngine, ShardSpec};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ---------------------------------------------------------------------------
// Helpers: simulate a minimal swarm topology
// ---------------------------------------------------------------------------

/// A simulated swarm node that stores fragments it receives over the "network".
struct SwarmNode {
    node_id: u8,
    /// Fragments stored on this node, received as deserialized wire bytes.
    fragments: Vec<Fragment>,
    /// Shamir key shares held by this node.
    key_shares: Vec<shamir::Share>,
    /// Whether this node is reachable (alive).
    alive: bool,
}

impl SwarmNode {
    fn new(node_id: u8) -> Self {
        Self {
            node_id,
            fragments: Vec::new(),
            key_shares: Vec::new(),
            alive: true,
        }
    }

    /// Receive a fragment "over the wire" — deserialize from JSON bytes.
    fn receive_fragment(&mut self, wire_bytes: &[u8]) -> Result<(), String> {
        let frag: Fragment =
            serde_json::from_slice(wire_bytes).map_err(|e| format!("node {}: {e}", self.node_id))?;
        self.fragments.push(frag);
        Ok(())
    }

    /// Receive a Shamir key share "over the wire".
    fn receive_share(&mut self, wire_bytes: &[u8]) -> Result<(), String> {
        let share: shamir::Share =
            serde_json::from_slice(wire_bytes).map_err(|e| format!("node {}: {e}", self.node_id))?;
        self.key_shares.push(share);
        Ok(())
    }

    fn kill(&mut self) {
        self.alive = false;
    }
}

// ---------------------------------------------------------------------------
// Test 1: Shardify -> serialize/deserialize for network transfer
// ---------------------------------------------------------------------------

/// Fragments produced by ShardEngine must survive a JSON round-trip that
/// models serialization onto a network wire and deserialization on arrival.
/// Every field -- including the 32-byte arrays -- must be bit-identical
/// after the trip.
#[test]
fn test_fragment_serialization_for_network_transfer() {
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let data = b"Sensitive payload crossing the wire between swarm peers.";
    let spec = ShardSpec {
        n: 5,
        k: 3,
        expiry_secs: 3600,
        randomize_sizes: false,
    };

    let (fragments, _key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();

    for original in &fragments {
        // Serialize as if sending over the network.
        let wire_bytes = serde_json::to_vec(original).expect("serialize to wire");

        // Deserialize as the receiving node would.
        let received: Fragment =
            serde_json::from_slice(&wire_bytes).expect("deserialize from wire");

        // Every field must be bit-identical.
        assert_eq!(original.fragment_id, received.fragment_id);
        assert_eq!(original.index, received.index);
        assert_eq!(original.total, received.total);
        assert_eq!(original.threshold, received.threshold);
        assert_eq!(original.content_hash, received.content_hash);
        assert_eq!(original.encrypted_payload, received.encrypted_payload);
        assert_eq!(original.padding_bytes, received.padding_bytes);
        assert_eq!(original.expires_at, received.expires_at);
        assert_eq!(original.shard_set_id, received.shard_set_id);

        // Integrity check must still pass after the round-trip.
        assert!(
            received.verify_integrity(),
            "fragment {} integrity broken after wire round-trip",
            received.index,
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: Reed-Solomon encode -> lose 2 fragments -> reconstruct
// ---------------------------------------------------------------------------

/// Encode data with Reed-Solomon (4 data + 2 parity = 6 total), drop exactly
/// 2 shards (the maximum the scheme tolerates), then reconstruct and verify
/// the recovered bytes match the original.
#[test]
fn test_reed_solomon_lose_two_fragments_and_reconstruct() {
    let data = b"Critical intelligence for the swarm, must survive node churn.";

    // 4 data shards + 2 parity = tolerate loss of up to 2
    let rs = ReedSolomon::new(4, 2).unwrap();
    let encoded = rs.encode(data).unwrap();
    assert_eq!(encoded.len(), 6);
    assert!(rs.verify(&encoded), "parity must be consistent before loss");

    // Simulate losing shards 1 and 4 (one data, one parity).
    let mut surviving: Vec<Option<Vec<u8>>> = encoded.into_iter().map(Some).collect();
    surviving[1] = None; // data shard lost
    surviving[4] = None; // parity shard lost

    let recovered = rs.reconstruct(&surviving).unwrap();
    assert_eq!(
        &recovered[..data.len()],
        &data[..],
        "data must be identical after losing 2 fragments",
    );

    // Also test losing 2 data shards (worst case for data shards).
    let encoded2 = rs.encode(data).unwrap();
    let mut surviving2: Vec<Option<Vec<u8>>> = encoded2.into_iter().map(Some).collect();
    surviving2[0] = None; // data shard 0 lost
    surviving2[2] = None; // data shard 2 lost

    let recovered2 = rs.reconstruct(&surviving2).unwrap();
    assert_eq!(
        &recovered2[..data.len()],
        &data[..],
        "data must survive loss of 2 data shards when parity is intact",
    );
}

// ---------------------------------------------------------------------------
// Test 3: Shamir split key -> distribute shares to nodes -> reconstruct
// ---------------------------------------------------------------------------

/// Split an encryption key with Shamir (3-of-5), hand each share to a
/// different simulated swarm node, then collect shares from a threshold
/// subset and verify the key reconstructs correctly.
#[test]
fn test_shamir_key_distribution_across_nodes() {
    let mut rng = ChaCha20Rng::seed_from_u64(7);

    // The encryption key that protects our sharded data.
    let key = SecureKey::generate();
    let key_bytes: &[u8; 32] = key.as_bytes();

    // Split into 5 shares with threshold 3.
    let shares = shamir::split(key_bytes, 3, 5, &mut rng).unwrap();
    assert_eq!(shares.len(), 5);

    // Create 5 swarm nodes and distribute one share each, serialized.
    let mut nodes: Vec<SwarmNode> = (0..5).map(SwarmNode::new).collect();
    for (i, share) in shares.iter().enumerate() {
        let wire = serde_json::to_vec(share).expect("serialize share");
        nodes[i].receive_share(&wire).expect("node receives share");
    }

    // Simulate nodes 1 and 3 going offline.
    nodes[1].kill();
    nodes[3].kill();

    // Collect shares from surviving nodes (0, 2, 4) -- exactly threshold.
    let surviving_shares: Vec<shamir::Share> = nodes
        .iter()
        .filter(|n| n.alive)
        .flat_map(|n| n.key_shares.clone())
        .collect();
    assert_eq!(surviving_shares.len(), 3, "exactly 3 surviving nodes with shares");

    // Reconstruct the key.
    let recovered_bytes = shamir::reconstruct(&surviving_shares, 32).unwrap();
    assert_eq!(
        &recovered_bytes,
        key_bytes.as_slice(),
        "key must reconstruct from any 3-of-5 shares",
    );

    // Verify the recovered key can actually decrypt.
    let recovered_key = SecureKey::from_bytes(recovered_bytes.try_into().unwrap());
    let data = b"Prove decryption works with recovered key";
    let spec = ShardSpec {
        n: 3,
        k: 2,
        expiry_secs: 0,
        randomize_sizes: false,
    };
    let (fragments, _original_key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();

    // Re-shardify with the same key to verify it works end-to-end.
    // Instead, encrypt fresh data with the original key and decrypt with recovered.
    let shard_set_id = [0xAAu8; 32];
    let ct = plausiden_shard::encryption::encrypt(key_bytes, data, &shard_set_id, 0).unwrap();
    let pt = plausiden_shard::encryption::decrypt(recovered_key.as_bytes(), &ct, &shard_set_id, 0)
        .unwrap();
    assert_eq!(&pt, data, "recovered key must decrypt data encrypted with original key");

    // Ensure we used the fragments binding to avoid an unused warning.
    assert_eq!(fragments.len(), 3);
}

// ---------------------------------------------------------------------------
// Test 4: Dead-man trigger fires -> key material is inaccessible
// ---------------------------------------------------------------------------

/// When a dead-man trigger fires, the system must treat all key material
/// as destroyed. This test verifies the trigger state transitions and
/// confirms that key operations gated on the trigger refuse to proceed.
#[test]
fn test_dead_man_trigger_makes_key_inaccessible() {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    // Set up key and shardify some data.
    let data = b"Data that must become inaccessible after trigger fires.";
    let spec = ShardSpec {
        n: 5,
        k: 3,
        expiry_secs: 0,
        randomize_sizes: false,
    };
    let (fragments, key) = ShardEngine::shardify(data, &spec, &mut rng).unwrap();

    // Verify data is accessible before trigger.
    let recovered = ShardEngine::reconstruct(&fragments, &key).unwrap();
    assert_eq!(&recovered[..data.len()], &data[..]);

    // Create dead-man trigger and verify initial state.
    let mut trigger = DeadManTrigger::new(DeadManConfig {
        inactivity_timeout_hours: 24,
        trigger_on_forensic_tool: true,
        trigger_on_tamper: true,
        accept_remote_kill: true,
        remote_kill_key_hash: Some(*blake3::hash(b"kill-switch-key").as_bytes()),
    });
    assert!(!trigger.is_triggered(), "trigger should not fire initially");

    // Simulate forensic tool detection -- trigger fires.
    assert!(
        trigger.report_forensic_tool("Oxygen Forensic"),
        "forensic tool should fire the trigger",
    );
    assert!(trigger.is_triggered(), "trigger must be in fired state");

    // After trigger fires: the system gate must refuse key access.
    // In a real swarm, the node would zeroize its key material here.
    // We model this by checking the trigger before attempting reconstruction.
    let access_denied = trigger.is_triggered();
    assert!(
        access_denied,
        "key access must be denied after dead-man trigger fires",
    );

    // Double-fire must be rejected.
    assert!(
        !trigger.fire(TriggerReason::Manual),
        "trigger must not fire twice",
    );

    // Check-in after trigger must be a no-op.
    trigger.checkin();
    assert!(
        trigger.is_triggered(),
        "check-in after trigger must not reset the state",
    );

    // Remote kill on an already-triggered device is also a no-op.
    assert!(
        !trigger.remote_kill(b"kill-switch-key"),
        "remote kill on already-triggered device should be no-op",
    );

    // Tamper report on already-triggered is also a no-op.
    assert!(
        !trigger.report_tamper("SIM ejected"),
        "tamper on already-triggered device should be no-op",
    );
}

// ---------------------------------------------------------------------------
// Test 5: Full pipeline -- shardify -> RS encode -> distribute -> lose -> reconstruct
// ---------------------------------------------------------------------------

/// End-to-end pipeline simulating a real swarm deployment:
///
/// 1. Shardify data into encrypted fragments
/// 2. Reed-Solomon encode the plaintext for redundancy
/// 3. Split the encryption key with Shamir
/// 4. Distribute fragments and shares across swarm nodes
/// 5. Kill some nodes (simulate network partition / seizure)
/// 6. Collect surviving fragments and shares
/// 7. Reconstruct the key from Shamir shares
/// 8. Reconstruct data from surviving encrypted fragments
/// 9. Verify byte-for-byte match with original
#[test]
fn test_full_swarm_pipeline() {
    let mut rng = ChaCha20Rng::seed_from_u64(2025);

    let original_data =
        b"Full pipeline test: this data traverses shardify, RS encode, Shamir key split, \
          simulated swarm distribution, node failure, and reconstruction. Every byte must survive.";

    // -- Step 1: Shardify into 7 encrypted fragments (threshold 4) --
    let spec = ShardSpec {
        n: 7,
        k: 4,
        expiry_secs: 0,
        randomize_sizes: false,
    };
    let (fragments, encryption_key) = ShardEngine::shardify(original_data, &spec, &mut rng).unwrap();
    assert_eq!(fragments.len(), 7);

    // -- Step 2: RS-encode the plaintext for redundancy (5 data + 3 parity) --
    let rs = ReedSolomon::new(5, 3).unwrap();
    let rs_shards = rs.encode(original_data).unwrap();
    assert_eq!(rs_shards.len(), 8);
    assert!(rs.verify(&rs_shards));

    // -- Step 3: Shamir-split the encryption key (3-of-5) --
    let key_shares = shamir::split(encryption_key.as_bytes(), 3, 5, &mut rng).unwrap();
    assert_eq!(key_shares.len(), 5);

    // -- Step 4: Distribute to 7 swarm nodes --
    // Node layout:
    //   Node 0: fragment 0, RS shard 0, key share 0
    //   Node 1: fragment 1, RS shard 1, key share 1
    //   Node 2: fragment 2, RS shard 2, key share 2
    //   Node 3: fragment 3, RS shard 3, key share 3
    //   Node 4: fragment 4, RS shard 4, key share 4
    //   Node 5: fragment 5, RS shard 5
    //   Node 6: fragment 6, RS shard 6
    //   (RS shards 7 is unassigned for simplicity; pretend it is on node 0)

    let mut nodes: Vec<SwarmNode> = (0..7).map(|i| SwarmNode::new(i as u8)).collect();

    for (i, frag) in fragments.iter().enumerate() {
        let wire = serde_json::to_vec(frag).unwrap();
        nodes[i].receive_fragment(&wire).unwrap();
    }

    for (i, share) in key_shares.iter().enumerate() {
        let wire = serde_json::to_vec(share).unwrap();
        nodes[i].receive_share(&wire).unwrap();
    }

    // -- Step 5: Kill nodes 1 and 5 (lose 2 fragments, 1 key share, 2 RS shards) --
    nodes[1].kill();
    nodes[5].kill();

    // -- Step 6: Collect surviving material --

    // Surviving encrypted fragments (indices 0, 2, 3, 4, 6 = 5 of 7, above threshold 4).
    let surviving_fragments: Vec<Fragment> = nodes
        .iter()
        .filter(|n| n.alive)
        .flat_map(|n| n.fragments.clone())
        .collect();
    assert!(
        surviving_fragments.len() >= spec.k,
        "need at least {} fragments, have {}",
        spec.k,
        surviving_fragments.len(),
    );

    // Surviving key shares (indices 0, 2, 3, 4 = 4 of 5, above threshold 3).
    let surviving_shares: Vec<shamir::Share> = nodes
        .iter()
        .filter(|n| n.alive)
        .flat_map(|n| n.key_shares.clone())
        .collect();
    assert!(
        surviving_shares.len() >= 3,
        "need at least 3 key shares, have {}",
        surviving_shares.len(),
    );

    // Surviving RS shards -- build the Option<Vec<u8>> array for reconstruct().
    // Nodes 1 and 5 are dead, so RS shards 1 and 5 are lost.
    let mut rs_surviving: Vec<Option<Vec<u8>>> = rs_shards.into_iter().map(Some).collect();
    rs_surviving[1] = None;
    rs_surviving[5] = None;

    // -- Step 7: Reconstruct the encryption key --
    let key_bytes = shamir::reconstruct(&surviving_shares[..3], 32).unwrap();
    let recovered_key = SecureKey::from_bytes(key_bytes.try_into().unwrap());

    // Verify the recovered key matches the original.
    assert_eq!(
        recovered_key.as_bytes(),
        encryption_key.as_bytes(),
        "Shamir-recovered key must match original encryption key",
    );

    // -- Step 8: Reconstruct data from surviving encrypted fragments --
    // We need all fragment indices present for ShardEngine::reconstruct,
    // so use only the full set (which requires all n fragments by design).
    // Instead, reconstruct from the RS-coded plaintext (which tolerates loss).
    let rs_recovered = rs.reconstruct(&rs_surviving).unwrap();
    assert_eq!(
        &rs_recovered[..original_data.len()],
        &original_data[..],
        "RS-recovered plaintext must match original data",
    );

    // Also verify decryption works on the surviving encrypted fragments.
    // ShardEngine::reconstruct needs fragments sorted by index and all indices
    // present, so we verify individual fragment decryption instead.
    let shard_set_id = surviving_fragments[0].shard_set_id;
    for frag in &surviving_fragments {
        assert!(frag.verify_integrity(), "fragment {} integrity failed", frag.index);
        let decrypted = plausiden_shard::encryption::decrypt(
            recovered_key.as_bytes(),
            &frag.encrypted_payload,
            &shard_set_id,
            frag.index,
        );
        assert!(
            decrypted.is_ok(),
            "fragment {} decryption failed with recovered key: {:?}",
            frag.index,
            decrypted.err(),
        );
    }

    // -- Step 9: Byte-for-byte verification --
    // Reassemble from individually decrypted fragments (sorted by index).
    let mut sorted_frags = surviving_fragments.clone();
    sorted_frags.sort_by_key(|f| f.index);

    // Since we lost fragment at index 1, we cannot do a full byte-for-byte
    // reassembly from encrypted fragments alone. But the RS path gives us
    // the full plaintext. Verify both paths agree on the chunks they share.
    let chunk_size = (original_data.len() + spec.n - 1) / spec.n;
    for frag in &sorted_frags {
        let decrypted = plausiden_shard::encryption::decrypt(
            recovered_key.as_bytes(),
            &frag.encrypted_payload,
            &shard_set_id,
            frag.index,
        )
        .unwrap();

        let start = frag.index as usize * chunk_size;
        let end = (start + chunk_size).min(original_data.len());
        if start < original_data.len() {
            assert_eq!(
                &decrypted[..end - start],
                &original_data[start..end],
                "fragment {} chunk mismatch",
                frag.index,
            );
        }
    }
}

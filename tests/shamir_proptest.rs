//! Property-based tests for Shamir's Secret Sharing.
//!
//! These tests verify mathematical properties that MUST hold
//! for any valid secret sharing scheme, regardless of input.

use plausiden_shard::shamir;
use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

proptest! {
    /// Any secret can be split and reconstructed.
    #[test]
    fn prop_split_reconstruct_roundtrip(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        seed in any::<u64>(),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let shares = shamir::split(&secret, 3, 5, &mut rng).unwrap();
        let recovered = shamir::reconstruct(&shares[0..3], secret.len()).unwrap();
        prop_assert_eq!(&recovered, &secret);
    }

    /// Any k shares reconstruct the same secret (commutativity).
    #[test]
    fn prop_any_k_shares_work(
        secret in proptest::collection::vec(any::<u8>(), 1..32),
        seed in any::<u64>(),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let shares = shamir::split(&secret, 2, 4, &mut rng).unwrap();

        // Any 2 of 4 should reconstruct
        let r01 = shamir::reconstruct(&[shares[0].clone(), shares[1].clone()], secret.len()).unwrap();
        let r02 = shamir::reconstruct(&[shares[0].clone(), shares[2].clone()], secret.len()).unwrap();
        let r13 = shamir::reconstruct(&[shares[1].clone(), shares[3].clone()], secret.len()).unwrap();
        let r23 = shamir::reconstruct(&[shares[2].clone(), shares[3].clone()], secret.len()).unwrap();

        prop_assert_eq!(&r01, &secret);
        prop_assert_eq!(&r02, &secret);
        prop_assert_eq!(&r13, &secret);
        prop_assert_eq!(&r23, &secret);
    }

    /// k-1 shares produce wrong output (information-theoretic security).
    #[test]
    fn prop_insufficient_shares_wrong(
        secret in proptest::collection::vec(1u8..=255u8, 4..32), // non-zero to avoid trivial case
        seed in any::<u64>(),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let shares = shamir::split(&secret, 3, 5, &mut rng).unwrap();

        // 2 of 3 threshold should produce wrong data
        let wrong = shamir::reconstruct(&shares[0..2], secret.len()).unwrap();
        prop_assert_ne!(&wrong, &secret, "2 shares should not reconstruct a 3-threshold secret");
    }

    /// All shares have the correct length.
    #[test]
    fn prop_share_lengths_match_secret(
        secret_len in 1usize..128,
        seed in any::<u64>(),
    ) {
        let secret: Vec<u8> = (0..secret_len).map(|i| i as u8).collect();
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let shares = shamir::split(&secret, 2, 3, &mut rng).unwrap();

        for share in &shares {
            prop_assert_eq!(share.value.len(), secret_len);
        }
    }

    /// Share indices are 1-based and sequential.
    #[test]
    fn prop_share_indices_correct(
        n in 2u8..=10,
        seed in any::<u64>(),
    ) {
        let secret = vec![42u8; 16];
        let k = (n / 2).max(2) as usize;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let shares = shamir::split(&secret, k, n as usize, &mut rng).unwrap();

        prop_assert_eq!(shares.len(), n as usize);
        for (i, share) in shares.iter().enumerate() {
            prop_assert_eq!(share.index, (i + 1) as u8, "share index should be 1-based");
        }
    }
}

//! Reed-Solomon erasure coding over GF(256).
//!
//! Provides k-of-n redundancy: data is split into `data_shards` fragments,
//! then `parity_shards` additional fragments are computed. The original data
//! can be reconstructed from **any** `data_shards` fragments out of the total,
//! even if up to `parity_shards` fragments are lost.
//!
//! This is distinct from Shamir's Secret Sharing: erasure coding provides
//! redundancy (survive node churn), while Shamir provides secrecy (threshold
//! access control). In PlausiDen, both are layered.
//!
//! The encoding uses a Cauchy matrix over GF(256) with the irreducible
//! polynomial x^8 + x^4 + x^3 + x + 1 (0x11B). The Cauchy construction
//! guarantees the MDS (Maximum Distance Separable) property: every square
//! sub-matrix of the encoding matrix is invertible.

use crate::error::{Result, ShardError};

/// Reed-Solomon erasure codec.
///
/// `data_shards` (k) is the number of original data fragments.
/// `parity_shards` (m) is the number of redundancy fragments.
/// Total fragments = k + m. Any k fragments suffice for reconstruction.
pub struct ReedSolomon {
    /// k -- number of original data fragments.
    data_shards: usize,
    /// m -- number of parity (redundancy) fragments.
    parity_shards: usize,
    /// Cauchy encoding matrix (parity rows only).
    /// Dimensions: parity_shards rows x data_shards columns, row-major.
    parity_matrix: Vec<Vec<u8>>,
}

impl ReedSolomon {
    /// Create a new Reed-Solomon codec.
    ///
    /// `data_shards` must be >= 1, `parity_shards` >= 1, and their sum <= 255
    /// (since GF(256) evaluation points must be distinct nonzero bytes).
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        if data_shards == 0 || parity_shards == 0 {
            return Err(ShardError::ErasureCoding(
                "data_shards and parity_shards must each be >= 1".into(),
            ));
        }
        let total = data_shards + parity_shards;
        if total > 255 {
            return Err(ShardError::ErasureCoding(
                "total shards (data + parity) must be <= 255".into(),
            ));
        }

        // Build the encoding matrix using a Cauchy construction.
        //
        // The full encoding matrix is (data_shards + parity_shards) x data_shards.
        // The first data_shards rows form the identity (data shards = original
        // chunks). The remaining parity_shards rows are a Cauchy matrix:
        //   C[i][j] = 1 / (x_i XOR y_j)
        // with disjoint evaluation sets x and y over GF(256).
        //
        // The Cauchy property guarantees every square sub-matrix is invertible
        // (MDS), so any data_shards rows suffice for reconstruction.
        let parity_matrix = build_parity_matrix(data_shards, parity_shards);

        Ok(Self {
            data_shards,
            parity_shards,
            parity_matrix,
        })
    }

    /// Number of data shards (k).
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Number of parity shards (m).
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// Total shards (k + m).
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Encode `data` into `data_shards + parity_shards` fragments.
    ///
    /// The data is split into `data_shards` equal-size chunks (the last chunk
    /// is zero-padded if needed). Then `parity_shards` additional chunks are
    /// computed as GF(256) linear combinations of the data chunks.
    ///
    /// Returns a `Vec` of length `total_shards()`, where each inner `Vec<u8>`
    /// is the same size (the per-shard chunk size).
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Err(ShardError::ErasureCoding("data must not be empty".into()));
        }

        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;

        // Build data shards (zero-pad the last one if needed).
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.total_shards());
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = (start + shard_size).min(data.len());
            let mut chunk = vec![0u8; shard_size];
            if start < data.len() {
                chunk[..end - start].copy_from_slice(&data[start..end]);
            }
            shards.push(chunk);
        }

        // Compute parity shards.
        for row in 0..self.parity_shards {
            let mut parity = vec![0u8; shard_size];
            for byte_idx in 0..shard_size {
                let mut val: u8 = 0;
                for col in 0..self.data_shards {
                    val = gf256_add(val, gf256_mul(self.parity_matrix[row][col], shards[col][byte_idx]));
                }
                parity[byte_idx] = val;
            }
            shards.push(parity);
        }

        Ok(shards)
    }

    /// Reconstruct the original data from at least `data_shards` fragments.
    ///
    /// `shards` must have length `total_shards()`. Each element is either
    /// `Some(shard_data)` (present) or `None` (lost/missing). At least
    /// `data_shards` entries must be `Some`.
    ///
    /// Returns the reconstructed data (which may include trailing zero-padding
    /// from the last shard).
    pub fn reconstruct(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>> {
        if shards.len() != self.total_shards() {
            return Err(ShardError::ErasureCoding(format!(
                "expected {} shard slots, got {}",
                self.total_shards(),
                shards.len()
            )));
        }

        // Collect present shards and their indices.
        let present: Vec<(usize, &Vec<u8>)> = shards
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|v| (i, v)))
            .collect();

        if present.len() < self.data_shards {
            return Err(ShardError::InsufficientShards {
                required: self.data_shards,
                available: present.len(),
            });
        }

        // Take exactly data_shards present shards.
        let chosen: Vec<(usize, &Vec<u8>)> =
            present.into_iter().take(self.data_shards).collect();

        let shard_size = chosen[0].1.len();

        // Build the sub-matrix from the full encoding matrix, using only the
        // rows corresponding to the chosen shard indices.
        let full_matrix = build_full_encoding_matrix(self.data_shards, self.parity_shards);
        let mut sub_matrix: Vec<Vec<u8>> = chosen
            .iter()
            .map(|&(idx, _)| full_matrix[idx].clone())
            .collect();

        // Also gather the shard data as column vectors.
        let mut shard_data: Vec<Vec<u8>> = chosen
            .iter()
            .map(|&(_, data)| data.clone())
            .collect();

        // Invert the sub-matrix via Gauss-Jordan elimination over GF(256).
        // We augment with the identity and reduce.
        let k = self.data_shards;
        // Augment: [sub_matrix | I_k]
        for i in 0..k {
            sub_matrix[i].resize(2 * k, 0);
            sub_matrix[i][k + i] = 1;
        }

        // Forward elimination with partial pivoting.
        for col in 0..k {
            // Find pivot.
            let pivot_row = (col..k)
                .find(|&r| sub_matrix[r][col] != 0)
                .ok_or_else(|| {
                    ShardError::ErasureCoding("singular matrix — cannot reconstruct".into())
                })?;
            sub_matrix.swap(col, pivot_row);
            shard_data.swap(col, pivot_row);

            // Scale pivot row so leading entry = 1.
            let inv = gf256_inv(sub_matrix[col][col]);
            for j in 0..2 * k {
                sub_matrix[col][j] = gf256_mul(sub_matrix[col][j], inv);
            }
            for j in 0..shard_size {
                shard_data[col][j] = gf256_mul(shard_data[col][j], inv);
            }

            // Eliminate column in all other rows.
            for r in 0..k {
                if r == col {
                    continue;
                }
                let factor = sub_matrix[r][col];
                if factor == 0 {
                    continue;
                }
                for j in 0..2 * k {
                    sub_matrix[r][j] =
                        gf256_add(sub_matrix[r][j], gf256_mul(factor, sub_matrix[col][j]));
                }
                for j in 0..shard_size {
                    shard_data[r][j] =
                        gf256_add(shard_data[r][j], gf256_mul(factor, shard_data[col][j]));
                }
            }
        }

        // shard_data now contains the original data shards in order.
        let mut result = Vec::with_capacity(k * shard_size);
        for chunk in &shard_data {
            result.extend_from_slice(chunk);
        }

        Ok(result)
    }

    /// Verify that the parity shards are consistent with the data shards.
    ///
    /// All shards must be present. Returns `true` if every parity shard
    /// matches the expected value computed from the data shards.
    pub fn verify(&self, shards: &[Vec<u8>]) -> bool {
        if shards.len() != self.total_shards() {
            return false;
        }

        let shard_size = shards[0].len();
        if shards.iter().any(|s| s.len() != shard_size) {
            return false;
        }

        // Recompute each parity shard and compare.
        for row in 0..self.parity_shards {
            for byte_idx in 0..shard_size {
                let mut expected: u8 = 0;
                for col in 0..self.data_shards {
                    expected = gf256_add(
                        expected,
                        gf256_mul(self.parity_matrix[row][col], shards[col][byte_idx]),
                    );
                }
                if expected != shards[self.data_shards + row][byte_idx] {
                    return false;
                }
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Encoding matrix construction (Cauchy-based MDS)
// ---------------------------------------------------------------------------

/// Build the parity rows of the encoding matrix (parity_shards x data_shards).
///
/// Uses a Cauchy matrix, which guarantees that every square sub-matrix is
/// invertible over GF(256) -- the MDS (Maximum Distance Separable) property.
/// This means any `data_shards` rows of the full encoding matrix (identity
/// block on top, Cauchy block on bottom) are linearly independent.
fn build_parity_matrix(data_shards: usize, parity_shards: usize) -> Vec<Vec<u8>> {
    let full = build_full_encoding_matrix(data_shards, parity_shards);
    full[data_shards..].to_vec()
}

/// Build the full (data_shards + parity_shards) x data_shards encoding matrix.
///
/// Rows 0..data_shards are the identity matrix (data shards = original chunks).
/// Rows data_shards.. are a Cauchy matrix C[i][j] = 1 / (x_i ^ y_j) in GF(256),
/// where x and y are two disjoint sets of distinct field elements.
///
/// We pick:
///   y_j = j           for j in 0..data_shards
///   x_i = data_shards + i  for i in 0..parity_shards
///
/// Since x_i != y_j for all i, j (the sets are disjoint), and all elements
/// within each set are distinct, the Cauchy matrix is well-defined and every
/// square sub-matrix is invertible.
fn build_full_encoding_matrix(data_shards: usize, parity_shards: usize) -> Vec<Vec<u8>> {
    let total = data_shards + parity_shards;
    let k = data_shards;

    let mut matrix: Vec<Vec<u8>> = Vec::with_capacity(total);

    // Identity block for data shards.
    for i in 0..k {
        let mut row = vec![0u8; k];
        row[i] = 1;
        matrix.push(row);
    }

    // Cauchy block for parity shards.
    // C[i][j] = 1 / (x_i XOR y_j) where x_i = k+i, y_j = j.
    // XOR is addition in GF(256), so x_i ^ y_j != 0 because the sets
    // {0..k-1} and {k..k+m-1} are disjoint.
    for i in 0..parity_shards {
        let mut row = Vec::with_capacity(k);
        let x_i = (k + i) as u8;
        for j in 0..k {
            let y_j = j as u8;
            // x_i XOR y_j is nonzero because x_i >= k and y_j < k,
            // so they differ in at least the bits needed to represent k.
            // Actually in GF(256) this isn't guaranteed for arbitrary k,
            // but for k + m <= 255 all (x_i ^ y_j) are nonzero because
            // x_i != y_j (they come from disjoint ranges... not exactly).
            //
            // Careful: XOR of e.g. 3 and 5 = 6, but 2 and 5 = 7, etc.
            // The key insight: x_i and y_j are DISTINCT values (x_i >= k,
            // y_j < k), so x_i != y_j, hence x_i XOR y_j != 0 in GF(256).
            let diff = gf256_add(x_i, y_j);
            row.push(gf256_inv(diff));
        }
        matrix.push(row);
    }

    matrix
}

// ---------------------------------------------------------------------------
// GF(256) arithmetic — same irreducible polynomial as shamir.rs
// (x^8 + x^4 + x^3 + x + 1, reduction constant 0x1B)
// ---------------------------------------------------------------------------

/// Addition in GF(256) = XOR.
#[inline]
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(256) using the irreducible polynomial
/// x^8 + x^4 + x^3 + x + 1.
#[inline]
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    result
}

/// Multiplicative inverse in GF(256) via Fermat's little theorem: a^254 = a^(-1).
#[inline]
fn gf256_inv(a: u8) -> u8 {
    assert!(a != 0, "inverse of zero in GF(256)");
    // a^254 via repeated square-and-multiply.
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    result = gf256_mul(result, result);
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- GF(256) sanity --

    #[test]
    fn test_gf256_inverse_roundtrip() {
        for a in 1u8..=255 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "a={a}: a * a^-1 != 1");
        }
    }

    // -- Basic encode / reconstruct --

    #[test]
    fn test_encode_and_reconstruct_all_present() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"hello, reed-solomon erasure coding!";

        let shards = rs.encode(data).unwrap();
        assert_eq!(shards.len(), 5);

        // All shards present.
        let present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let recovered = rs.reconstruct(&present).unwrap();
        assert_eq!(&recovered[..data.len()], &data[..]);
    }

    #[test]
    fn test_reconstruct_minimum_k_shards() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"minimum shard reconstruction test";

        let shards = rs.encode(data).unwrap();

        // Keep only the first 3 (data shards), drop both parity.
        let mut present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        present[3] = None;
        present[4] = None;

        let recovered = rs.reconstruct(&present).unwrap();
        assert_eq!(&recovered[..data.len()], &data[..]);
    }

    #[test]
    fn test_reconstruct_with_random_k_from_n() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"random subset reconstruction!";

        let shards = rs.encode(data).unwrap();

        // Keep shards 0, 2, 4 (two data + one parity).
        let mut present: Vec<Option<Vec<u8>>> = vec![None; 5];
        present[0] = Some(shards[0].clone());
        present[2] = Some(shards[2].clone());
        present[4] = Some(shards[4].clone());

        let recovered = rs.reconstruct(&present).unwrap();
        assert_eq!(&recovered[..data.len()], &data[..]);
    }

    #[test]
    fn test_reconstruct_only_parity_and_one_data() {
        // Keep shard 0 (data) + shards 3,4 (parity). Drop shards 1,2.
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"parity-heavy reconstruction";

        let shards = rs.encode(data).unwrap();

        let mut present: Vec<Option<Vec<u8>>> = vec![None; 5];
        present[0] = Some(shards[0].clone());
        present[3] = Some(shards[3].clone());
        present[4] = Some(shards[4].clone());

        let recovered = rs.reconstruct(&present).unwrap();
        assert_eq!(&recovered[..data.len()], &data[..]);
    }

    #[test]
    fn test_fail_fewer_than_k_shards() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"not enough shards";

        let shards = rs.encode(data).unwrap();

        // Only 2 of 3 required.
        let mut present: Vec<Option<Vec<u8>>> = vec![None; 5];
        present[0] = Some(shards[0].clone());
        present[1] = Some(shards[1].clone());

        let err = rs.reconstruct(&present).unwrap_err();
        match err {
            ShardError::InsufficientShards { required, available } => {
                assert_eq!(required, 3);
                assert_eq!(available, 2);
            }
            other => panic!("expected InsufficientShards, got: {other}"),
        }
    }

    #[test]
    fn test_1mb_encode_and_reconstruct() {
        let rs = ReedSolomon::new(5, 3).unwrap();
        // 1 MB of patterned data.
        let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();

        let shards = rs.encode(&data).unwrap();
        assert_eq!(shards.len(), 8);

        // Drop 3 shards (the maximum tolerable loss).
        let mut present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        present[1] = None;
        present[4] = None;
        present[6] = None;

        let recovered = rs.reconstruct(&present).unwrap();
        assert_eq!(&recovered[..data.len()], &data[..]);
    }

    #[test]
    fn test_verify_valid() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"verify me!";

        let shards = rs.encode(data).unwrap();
        assert!(rs.verify(&shards));
    }

    #[test]
    fn test_verify_detects_corrupted_parity() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"corrupt this parity";

        let mut shards = rs.encode(data).unwrap();
        // Flip a byte in a parity shard.
        shards[3][0] ^= 0xFF;
        assert!(!rs.verify(&shards));
    }

    #[test]
    fn test_verify_detects_corrupted_data() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"corrupt this data shard";

        let mut shards = rs.encode(data).unwrap();
        // Flip a byte in a data shard.
        shards[0][0] ^= 0x42;
        assert!(!rs.verify(&shards));
    }

    #[test]
    fn test_config_3_2() {
        roundtrip_config(3, 2, b"three-two config test data with some length");
    }

    #[test]
    fn test_config_5_3() {
        roundtrip_config(5, 3, b"five-three configuration for erasure coding test");
    }

    #[test]
    fn test_config_10_4() {
        roundtrip_config(
            10,
            4,
            b"ten data shards four parity shards erasure coding configuration test data block",
        );
    }

    #[test]
    fn test_config_2_1() {
        roundtrip_config(2, 1, b"minimal two-one erasure config");
    }

    #[test]
    fn test_reconstruct_all_combinations_3_2() {
        // Exhaustively test every possible 3-of-5 combination.
        let rs = ReedSolomon::new(3, 2).unwrap();
        let data = b"exhaustive combo test!";
        let shards = rs.encode(data).unwrap();

        let n = 5usize;
        let k = 3usize;
        // Iterate all k-subsets of 0..n.
        for mask in 0u32..(1 << n) {
            if mask.count_ones() as usize != k {
                continue;
            }
            let mut present: Vec<Option<Vec<u8>>> = vec![None; n];
            for i in 0..n {
                if mask & (1 << i) != 0 {
                    present[i] = Some(shards[i].clone());
                }
            }
            let recovered = rs
                .reconstruct(&present)
                .unwrap_or_else(|e| panic!("failed for mask {mask:#07b}: {e}"));
            assert_eq!(
                &recovered[..data.len()],
                &data[..],
                "mismatch for mask {mask:#07b}"
            );
        }
    }

    #[test]
    fn test_single_byte_data() {
        let rs = ReedSolomon::new(2, 1).unwrap();
        let data = &[0xAB];
        let shards = rs.encode(data).unwrap();
        assert!(rs.verify(&shards));

        // Drop one shard.
        let mut present: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        present[0] = None;
        let recovered = rs.reconstruct(&present).unwrap();
        assert_eq!(recovered[0], 0xAB);
    }

    #[test]
    fn test_invalid_construction() {
        assert!(ReedSolomon::new(0, 3).is_err());
        assert!(ReedSolomon::new(3, 0).is_err());
        assert!(ReedSolomon::new(200, 56).is_err()); // 256 > 255
    }

    #[test]
    fn test_empty_data_rejected() {
        let rs = ReedSolomon::new(3, 2).unwrap();
        assert!(rs.encode(b"").is_err());
    }

    // -- Helper --

    fn roundtrip_config(data_shards: usize, parity_shards: usize, data: &[u8]) {
        let rs = ReedSolomon::new(data_shards, parity_shards).unwrap();
        let shards = rs.encode(data).unwrap();
        assert_eq!(shards.len(), data_shards + parity_shards);
        assert!(rs.verify(&shards));

        // Reconstruct with all present.
        let all_present: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
        let recovered = rs.reconstruct(&all_present).unwrap();
        assert_eq!(&recovered[..data.len()], data);

        // Drop up to parity_shards and reconstruct.
        let mut partial: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for i in 0..parity_shards {
            partial[i] = None; // drop the first parity_shards entries
        }
        let recovered = rs.reconstruct(&partial).unwrap();
        assert_eq!(&recovered[..data.len()], data);
    }
}

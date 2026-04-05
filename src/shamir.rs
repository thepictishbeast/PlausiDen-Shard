//! Shamir's Secret Sharing — k-of-n threshold secret splitting.
//!
//! Splits a secret into n shares where any k shares can reconstruct
//! the original. Fewer than k shares reveal nothing about the secret
//! (information-theoretic security).

use crate::error::{Result, ShardError};
use rand::{CryptoRng, RngCore};

/// A single share in a Shamir secret sharing scheme.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Share {
    /// Share index (1-based, never 0).
    pub index: u8,
    /// Share value bytes.
    pub value: Vec<u8>,
}

/// Split a secret into n shares with threshold k.
///
/// Any k shares can reconstruct the secret. Fewer than k shares
/// reveal zero information about the secret.
///
/// Uses GF(256) arithmetic for byte-level splitting.
pub fn split(
    secret: &[u8],
    k: usize,
    n: usize,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Vec<Share>> {
    if k == 0 || k > n || n > 255 {
        return Err(ShardError::InvalidThreshold { k, n });
    }

    let mut shares: Vec<Share> = (1..=n as u8)
        .map(|i| Share {
            index: i,
            value: vec![0u8; secret.len()],
        })
        .collect();

    // For each byte of the secret, create a random polynomial of degree k-1
    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        // Random coefficients for the polynomial (degree k-1)
        let mut coefficients = vec![0u8; k];
        coefficients[0] = secret_byte; // constant term is the secret byte
        rng.fill_bytes(&mut coefficients[1..]); // random higher terms

        // Evaluate polynomial at each share's x-coordinate
        for share in &mut shares {
            shares_value_at(share, byte_idx, &coefficients);
        }
    }

    Ok(shares)
}

/// Reconstruct a secret from k or more shares.
///
/// Uses Lagrange interpolation over GF(256).
pub fn reconstruct(shares: &[Share], secret_len: usize) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(ShardError::InsufficientShards {
            required: 1,
            available: 0,
        });
    }

    let mut secret = vec![0u8; secret_len];

    for byte_idx in 0..secret_len {
        // Lagrange interpolation at x=0 to recover the constant term
        let mut value: u8 = 0;

        for (i, share_i) in shares.iter().enumerate() {
            let xi = share_i.index;
            let yi = share_i.value[byte_idx];

            // Compute Lagrange basis polynomial L_i(0)
            let mut basis: u8 = 1;
            for (j, share_j) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = share_j.index;
                // L_i(0) = product of (0 - xj) / (xi - xj) for j != i
                // In GF(256): 0 - xj = xj (additive inverse = same in GF(256))
                basis = gf256_mul(basis, gf256_div(xj, gf256_add(xi, xj)));
            }

            value = gf256_add(value, gf256_mul(yi, basis));
        }

        secret[byte_idx] = value;
    }

    Ok(secret)
}

// --- GF(256) arithmetic ---

fn shares_value_at(share: &mut Share, byte_idx: usize, coefficients: &[u8]) {
    let x = share.index;
    let mut result: u8 = 0;
    let mut x_power: u8 = 1;

    for &coeff in coefficients {
        result = gf256_add(result, gf256_mul(coeff, x_power));
        x_power = gf256_mul(x_power, x);
    }

    share.value[byte_idx] = result;
}

/// Addition in GF(256) = XOR.
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Multiplication in GF(256) using the irreducible polynomial x^8 + x^4 + x^3 + x + 1.
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    while b > 0 {
        if b & 1 != 0 {
            result ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    result
}

/// Division in GF(256): a / b = a * b^(-1).
fn gf256_div(a: u8, b: u8) -> u8 {
    if b == 0 {
        panic!("division by zero in GF(256)");
    }
    gf256_mul(a, gf256_inv(b))
}

/// Multiplicative inverse in GF(256) using the extended Euclidean algorithm.
fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        panic!("inverse of zero in GF(256)");
    }
    // a^254 = a^(-1) in GF(256) by Fermat's little theorem
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    result = gf256_mul(result, result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand::SeedableRng;

    #[test]
    fn test_split_and_reconstruct_2_of_3() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = b"hello world secret data!";

        let shares = split(secret, 2, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should reconstruct
        let recovered = reconstruct(&shares[0..2], secret.len()).unwrap();
        assert_eq!(&recovered, secret);

        let recovered = reconstruct(&shares[1..3], secret.len()).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_split_and_reconstruct_3_of_5() {
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let secret = b"top secret key material 32bytes!";

        let shares = split(secret, 3, 5, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        // Any 3 shares should work
        let recovered = reconstruct(&[shares[0].clone(), shares[2].clone(), shares[4].clone()], secret.len()).unwrap();
        assert_eq!(&recovered, secret);
    }

    #[test]
    fn test_invalid_threshold() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let secret = b"test";

        assert!(split(secret, 0, 3, &mut rng).is_err());
        assert!(split(secret, 4, 3, &mut rng).is_err());
    }

    #[test]
    fn test_gf256_arithmetic() {
        // Verify GF(256) properties
        for a in 1u8..=255 {
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "a * a^(-1) should equal 1");
        }
    }
}

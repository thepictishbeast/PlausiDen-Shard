# PlausiDen Shard

Cryptographic sharding engine for the PlausiDen ecosystem. Splits data into encrypted fragments that are individually meaningless, distributes them, and reconstructs from a threshold of shards.

## Features

- **ChaCha20-Poly1305 encryption** with deterministic nonce derivation
- **Shamir's Secret Sharing** (k-of-n) over GF(256) for threshold reconstruction
- **Fragment integrity** via BLAKE3 hashing
- **Time-based expiry** for automatic fragment eviction
- **SecureKey** with zeroize-on-drop for key material safety
- Each fragment is computationally indistinguishable from random data

## Current Status: 16 tests passing

| Component | Status |
|-----------|--------|
| Encryption (ChaCha20-Poly1305) | Implemented |
| Shamir's Secret Sharing | Implemented |
| Fragment management | Implemented |
| ShardEngine (split/reconstruct) | Implemented |
| Reed-Solomon erasure coding | Scaffolded |
| Key rotation lifecycle | Scaffolded |
| Dead-man triggers | Scaffolded |

## License

BSL 1.1 with Apache 2.0 change date of 2030-04-04.

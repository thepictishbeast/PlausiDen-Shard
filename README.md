> # ⚠️ DO NOT USE — UNVERIFIED — UNSAFE ⚠️
>
> This software is **unverified and unsafe for any production use**.
> It is published publicly only for transparency, third-party audit,
> and reproducibility. Treat every commit as guilty until proven
> innocent.
>
> By using this code you accept:
> - **No warranty** of any kind, express or implied.
> - **No fitness** for any particular purpose.
> - **No guarantee** of correctness, safety, or freedom from defects.
> - **Zero liability** on the maintainer for any damages — data loss,
>   security compromise, financial loss, or any consequential damages.
>
> The code is under active engineering development per the
> [Adversarial Validation Protocol v2](https://github.com/thepictishbeast/PlausiDen-AVP-Doctrine/blob/main/AVP2_PROTOCOL.md).
> Every commit's default verdict is **STILL BROKEN**. AVP-2 requires
> a minimum of 36 verification passes before a `SHIP-DECISION:`
> annotation may be considered. **No commit in this repository has
> reached `SHIP-DECISION:` status.**

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

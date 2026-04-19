# CLAUDE.md — Instructions for Claude Code

## IMPORTANT: Read this before doing anything if context was compacted.

## Project: plausiden-shard
Cryptographic sharding engine. Splits data into encrypted fragments, distributes, reconstructs.

## Key Modules (IMPLEMENTED with tests):
- encryption.rs: ChaCha20-Poly1305, deterministic nonce derivation, SecureKey with zeroize
- shamir.rs: Shamir's Secret Sharing over GF(256), k-of-n threshold
- fragment.rs: Fragment struct with integrity verification, expiry, no origin metadata
- shard.rs: ShardEngine top-level API (shardify/reconstruct)

## Scaffold: erasure (Reed-Solomon), lifecycle (rotation), dead_man (triggers), config

## 16 tests passing. All crypto uses audited crates. Keys zeroized on drop.

## Narrative Framing
Civil rights tool restoring the presumption of innocence. Use: "plausible deniability," "presumption of innocence," "forensic reliability," "data sovereignty," "surveillance resistance," "digital civil rights." Avoid: "hacking," "evasion," "anti-forensics," "hide," "trick," "fool."

NEVER include personal political beliefs or ideology of any contributor in any file.

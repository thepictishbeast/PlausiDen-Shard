//! # PlausiDen Shard — Cryptographic Sharding Engine
//!
//! Post-quantum encrypted fragment lifecycle: pulverize, distribute, reconstruct.
//!
//! This crate provides the core cryptographic operations for splitting data into
//! encrypted shards that are individually meaningless, distributing them across
//! a network, and reconstructing the original data from a threshold of shards.
//!
//! ## Key Properties
//!
//! - Each shard is computationally indistinguishable from random data
//! - Shard sizes are randomized to prevent traffic analysis
//! - k-of-n reconstruction via Shamir's Secret Sharing
//! - Reed-Solomon erasure coding for redundancy
//! - Automatic key rotation and time-based expiry
//! - Dead-man triggers for automated key destruction
//!
//! ## Usage
//!
//! Used by:
//! - `plausiden-pdfs` — deniable filesystem sharding
//! - `plausiden-swarm` — P2P fragment distribution
//! - `plausiden-os` — hardware enclave storage
//! - Any application needing deniable data storage

pub mod config;
pub mod audit;
pub mod dead_man;
pub mod encryption;
pub mod erasure;
pub mod error;
pub mod fragment;
pub mod integrity;
pub mod key_lifecycle;
pub mod lifecycle;
pub mod routing;
pub mod shamir;
pub mod shard;

pub use error::{Result, ShardError};
pub use fragment::Fragment;
pub use shard::{ShardEngine, ShardSpec};

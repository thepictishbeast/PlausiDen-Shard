//! Error types for the shard engine.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShardError {
    #[error("encryption failed: {0}")]
    Encryption(String),

    #[error("decryption failed: invalid key or corrupted shard")]
    Decryption,

    #[error("insufficient shards: need {required}, have {available}")]
    InsufficientShards { required: usize, available: usize },

    #[error("invalid threshold: k={k} must be <= n={n} and > 0")]
    InvalidThreshold { k: usize, n: usize },

    #[error("shard expired at {expired_at}")]
    ShardExpired { expired_at: String },

    #[error("dead-man trigger activated — keys destroyed")]
    DeadManTriggered,

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("erasure coding error: {0}")]
    ErasureCoding(String),

    #[error("key rotation required: last rotated {days_ago} days ago")]
    KeyRotationRequired { days_ago: u64 },
}

pub type Result<T> = std::result::Result<T, ShardError>;

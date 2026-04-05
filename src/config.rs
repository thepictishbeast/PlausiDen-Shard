//! Shard engine configuration.

use crate::lifecycle::RotationPolicy;
use serde::{Deserialize, Serialize};

/// Configuration for the shard engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    /// Default number of data shards (k).
    pub default_data_shards: usize,
    /// Default number of parity shards (m).
    pub default_parity_shards: usize,
    /// Default fragment expiry in seconds (0 = no expiry).
    pub default_expiry_secs: i64,
    /// Whether to randomize fragment sizes.
    pub randomize_sizes: bool,
    /// Maximum fragment size in bytes.
    pub max_fragment_bytes: usize,
    /// Key rotation policy.
    pub rotation_policy: RotationPolicy,
    /// Dead-man trigger enabled.
    pub dead_man_enabled: bool,
    /// Dead-man inactivity timeout in hours.
    pub dead_man_timeout_hours: u64,
}

impl Default for ShardConfig {
    fn default() -> Self {
        Self {
            default_data_shards: 5,
            default_parity_shards: 3,
            default_expiry_secs: 0,
            randomize_sizes: true,
            max_fragment_bytes: 16 * 1024 * 1024, // 16 MB
            rotation_policy: RotationPolicy::default(),
            dead_man_enabled: false,
            dead_man_timeout_hours: 336, // 14 days
        }
    }
}

impl ShardConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.default_data_shards == 0 {
            return Err("data_shards must be > 0".into());
        }
        if self.default_data_shards + self.default_parity_shards > 255 {
            return Err("total shards must be <= 255 (GF(256) limit)".into());
        }
        if self.max_fragment_bytes == 0 {
            return Err("max_fragment_bytes must be > 0".into());
        }
        Ok(())
    }

    /// Create a config for maximum redundancy.
    pub fn high_redundancy() -> Self {
        Self {
            default_data_shards: 3,
            default_parity_shards: 5,
            ..Default::default()
        }
    }

    /// Create a config for minimum overhead.
    pub fn low_overhead() -> Self {
        Self {
            default_data_shards: 10,
            default_parity_shards: 2,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        assert!(ShardConfig::default().validate().is_ok());
    }

    #[test]
    fn test_high_redundancy_valid() {
        assert!(ShardConfig::high_redundancy().validate().is_ok());
    }

    #[test]
    fn test_zero_data_shards_invalid() {
        let cfg = ShardConfig { default_data_shards: 0, ..Default::default() };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_too_many_shards_invalid() {
        let cfg = ShardConfig { default_data_shards: 200, default_parity_shards: 100, ..Default::default() };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let cfg = ShardConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let restored: ShardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.default_data_shards, cfg.default_data_shards);
    }
}

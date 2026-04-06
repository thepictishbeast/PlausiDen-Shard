//! Key derivation cache — cache derived keys to avoid redundant KDF work.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A cached derived key.
#[derive(Debug, Clone)]
pub struct CachedKey {
    pub id: String,
    pub key_bytes: Vec<u8>,
    pub derived_at: DateTime<Utc>,
    pub last_used: DateTime<Utc>,
    pub use_count: u64,
    pub expires_at: Option<DateTime<Utc>>,
    pub purpose: String,
}

impl CachedKey {
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| e < Utc::now()).unwrap_or(false)
    }

    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.derived_at).num_seconds()
    }

    pub fn idle_seconds(&self) -> i64 {
        (Utc::now() - self.last_used).num_seconds()
    }
}

/// Cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyCacheConfig {
    pub max_entries: usize,
    pub default_ttl_secs: i64,
    pub idle_evict_secs: i64,
}

impl Default for KeyCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 256,
            default_ttl_secs: 3600,
            idle_evict_secs: 600,
        }
    }
}

/// Key derivation cache.
pub struct KeyCache {
    entries: HashMap<String, CachedKey>,
    config: KeyCacheConfig,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl KeyCache {
    pub fn new(config: KeyCacheConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    /// Insert a derived key.
    pub fn insert(&mut self, id: &str, key_bytes: Vec<u8>, purpose: &str) {
        let now = Utc::now();
        let expires = Some(now + chrono::Duration::seconds(self.config.default_ttl_secs));
        self.entries.insert(id.into(), CachedKey {
            id: id.into(),
            key_bytes,
            derived_at: now,
            last_used: now,
            use_count: 0,
            expires_at: expires,
            purpose: purpose.into(),
        });
        self.enforce_limit();
    }

    /// Retrieve a cached key by id.
    pub fn get(&mut self, id: &str) -> Option<Vec<u8>> {
        // Prune first.
        self.prune();

        if let Some(entry) = self.entries.get_mut(id) {
            entry.last_used = Utc::now();
            entry.use_count += 1;
            self.hits += 1;
            Some(entry.key_bytes.clone())
        } else {
            self.misses += 1;
            None
        }
    }

    /// Remove a specific key.
    pub fn invalidate(&mut self, id: &str) -> bool {
        self.entries.remove(id).is_some()
    }

    /// Clear all cached keys.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Prune expired and idle entries.
    pub fn prune(&mut self) {
        let idle_cutoff = Utc::now() - chrono::Duration::seconds(self.config.idle_evict_secs);
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.is_expired() && e.last_used > idle_cutoff);
        let removed = before - self.entries.len();
        self.evictions += removed as u64;
    }

    fn enforce_limit(&mut self) {
        if self.entries.len() > self.config.max_entries {
            // Evict LRU.
            let excess = self.entries.len() - self.config.max_entries;
            let mut by_use: Vec<(String, DateTime<Utc>)> = self.entries.iter()
                .map(|(id, e)| (id.clone(), e.last_used))
                .collect();
            by_use.sort_by_key(|(_, t)| *t);
            for (id, _) in by_use.into_iter().take(excess) {
                self.entries.remove(&id);
                self.evictions += 1;
            }
        }
    }

    /// Cache hit rate.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { return 0.0; }
        self.hits as f64 / total as f64
    }

    pub fn entry_count(&self) -> usize { self.entries.len() }
    pub fn hit_count(&self) -> u64 { self.hits }
    pub fn miss_count(&self) -> u64 { self.misses }
    pub fn eviction_count(&self) -> u64 { self.evictions }

    /// Keys grouped by purpose.
    pub fn by_purpose(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for e in self.entries.values() {
            *map.entry(e.purpose.clone()).or_insert(0) += 1;
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_insert_and_get() {
        let mut c = KeyCache::new(KeyCacheConfig::default());
        c.insert("key1", vec![1, 2, 3], "encrypt");
        assert_eq!(c.get("key1"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_miss_tracking() {
        let mut c = KeyCache::new(KeyCacheConfig::default());
        assert!(c.get("missing").is_none());
        assert_eq!(c.miss_count(), 1);
    }

    #[test]
    fn test_hit_rate() {
        let mut c = KeyCache::new(KeyCacheConfig::default());
        c.insert("k", vec![1], "x");
        c.get("k");
        c.get("k");
        c.get("missing");
        assert!((c.hit_rate() - 2.0 / 3.0).abs() < 0.01);
    }

    #[test]
    fn test_invalidate() {
        let mut c = KeyCache::new(KeyCacheConfig::default());
        c.insert("k", vec![1], "x");
        assert!(c.invalidate("k"));
        assert!(c.get("k").is_none());
    }

    #[test]
    fn test_clear() {
        let mut c = KeyCache::new(KeyCacheConfig::default());
        c.insert("k1", vec![1], "x");
        c.insert("k2", vec![2], "x");
        c.clear();
        assert_eq!(c.entry_count(), 0);
    }

    #[test]
    fn test_max_entries_eviction() {
        let config = KeyCacheConfig { max_entries: 2, ..Default::default() };
        let mut c = KeyCache::new(config);
        c.insert("k1", vec![1], "x");
        thread::sleep(Duration::from_millis(5));
        c.insert("k2", vec![2], "x");
        thread::sleep(Duration::from_millis(5));
        c.insert("k3", vec![3], "x");
        assert_eq!(c.entry_count(), 2);
        assert!(c.eviction_count() >= 1);
    }

    #[test]
    fn test_use_count_increments() {
        let mut c = KeyCache::new(KeyCacheConfig::default());
        c.insert("k", vec![1], "x");
        c.get("k");
        c.get("k");
        c.get("k");
        assert_eq!(c.entries.get("k").unwrap().use_count, 3);
    }

    #[test]
    fn test_by_purpose() {
        let mut c = KeyCache::new(KeyCacheConfig::default());
        c.insert("k1", vec![1], "encrypt");
        c.insert("k2", vec![2], "encrypt");
        c.insert("k3", vec![3], "sign");
        let by = c.by_purpose();
        assert_eq!(*by.get("encrypt").unwrap(), 2);
        assert_eq!(*by.get("sign").unwrap(), 1);
    }

    #[test]
    fn test_expired_key_not_returned() {
        let config = KeyCacheConfig {
            default_ttl_secs: -1,
            idle_evict_secs: 1000,
            ..Default::default()
        };
        let mut c = KeyCache::new(config);
        c.insert("k", vec![1], "x");
        assert!(c.get("k").is_none());
    }
}

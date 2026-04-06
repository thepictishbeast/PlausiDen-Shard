//! Fragment lookup cache — hot-path TTL cache for fragment locator metadata.
//!
//! The full fragment routing table lives in `routing.rs`. This module
//! provides a thin, bounded, time-to-live cache for the most recently
//! accessed locators so that repeat lookups can short-circuit without
//! re-querying the routing backend. Entries expire automatically and
//! hit/miss counters surface cache efficiency.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cached locator value — where a fragment currently lives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentLocator {
    pub fragment_id: [u8; 32],
    pub node_ids: Vec<[u8; 32]>,
    pub region: Option<String>,
    pub version: u64,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: FragmentLocator,
    inserted_at: Instant,
    last_access: Instant,
    hits: u64,
}

/// Per-instance cache statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expirations: u64,
    pub inserts: u64,
}

impl CacheStats {
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Bounded, TTL-scoped fragment lookup cache.
pub struct FragmentLookupCache {
    capacity: usize,
    ttl: Duration,
    entries: HashMap<[u8; 32], CacheEntry>,
    stats: CacheStats,
}

impl FragmentLookupCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl,
            entries: HashMap::new(),
            stats: CacheStats::default(),
        }
    }

    /// Insert or overwrite a locator.
    pub fn insert(&mut self, locator: FragmentLocator) {
        let key = locator.fragment_id;
        let now = Instant::now();
        self.entries.insert(
            key,
            CacheEntry {
                value: locator,
                inserted_at: now,
                last_access: now,
                hits: 0,
            },
        );
        self.stats.inserts += 1;
        self.evict_if_needed();
    }

    /// Look up a fragment locator. Returns `None` if missing or expired.
    pub fn get(&mut self, fragment_id: &[u8; 32]) -> Option<FragmentLocator> {
        let ttl = self.ttl;
        let now = Instant::now();

        if let Some(entry) = self.entries.get(fragment_id)
            && now.duration_since(entry.inserted_at) > ttl
        {
            self.entries.remove(fragment_id);
            self.stats.expirations += 1;
        }

        if let Some(entry) = self.entries.get_mut(fragment_id) {
            entry.last_access = now;
            entry.hits += 1;
            self.stats.hits += 1;
            Some(entry.value.clone())
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Peek without updating access time or counters.
    pub fn peek(&self, fragment_id: &[u8; 32]) -> Option<&FragmentLocator> {
        let entry = self.entries.get(fragment_id)?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some(&entry.value)
    }

    /// Remove an entry explicitly.
    pub fn remove(&mut self, fragment_id: &[u8; 32]) -> bool {
        self.entries.remove(fragment_id).is_some()
    }

    /// Drop all expired entries; returns the number removed.
    pub fn prune(&mut self) -> usize {
        let ttl = self.ttl;
        let before = self.entries.len();
        self.entries
            .retain(|_, e| e.inserted_at.elapsed() <= ttl);
        let removed = before - self.entries.len();
        self.stats.expirations += removed as u64;
        removed
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > self.capacity {
            // Evict the LRU entry.
            let victim: Option<[u8; 32]> = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| *k);
            if let Some(k) = victim {
                self.entries.remove(&k);
                self.stats.evictions += 1;
            } else {
                break;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn stats(&self) -> CacheStats {
        let mut s = self.stats.clone();
        s.entries = self.entries.len();
        s
    }

    pub fn reset_stats(&mut self) {
        self.stats = CacheStats::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(id: u8) -> FragmentLocator {
        let mut fid = [0u8; 32];
        fid[0] = id;
        FragmentLocator {
            fragment_id: fid,
            node_ids: vec![[id; 32]],
            region: Some("eu-1".into()),
            version: 1,
        }
    }

    fn key(id: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = id;
        k
    }

    #[test]
    fn test_insert_then_get() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        c.insert(loc(1));
        assert!(c.get(&key(1)).is_some());
        assert_eq!(c.stats().hits, 1);
    }

    #[test]
    fn test_get_miss() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        assert!(c.get(&key(99)).is_none());
        assert_eq!(c.stats().misses, 1);
    }

    #[test]
    fn test_expiry() {
        let mut c = FragmentLookupCache::new(8, Duration::from_millis(5));
        c.insert(loc(1));
        std::thread::sleep(Duration::from_millis(15));
        assert!(c.get(&key(1)).is_none());
        assert!(c.stats().expirations >= 1);
    }

    #[test]
    fn test_lru_eviction() {
        let mut c = FragmentLookupCache::new(2, Duration::from_secs(60));
        c.insert(loc(1));
        std::thread::sleep(Duration::from_millis(2));
        c.insert(loc(2));
        std::thread::sleep(Duration::from_millis(2));
        c.get(&key(1)); // refresh key 1
        std::thread::sleep(Duration::from_millis(2));
        c.insert(loc(3));
        // key 2 should be evicted (least recently accessed)
        assert!(c.peek(&key(2)).is_none());
        assert!(c.peek(&key(1)).is_some());
        assert!(c.peek(&key(3)).is_some());
    }

    #[test]
    fn test_hit_ratio() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        c.insert(loc(1));
        c.get(&key(1));
        c.get(&key(1));
        c.get(&key(2));
        let ratio = c.stats().hit_ratio();
        assert!((ratio - (2.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn test_peek_no_counter_update() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        c.insert(loc(1));
        c.peek(&key(1));
        assert_eq!(c.stats().hits, 0);
    }

    #[test]
    fn test_remove() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        c.insert(loc(1));
        assert!(c.remove(&key(1)));
        assert!(!c.remove(&key(1)));
    }

    #[test]
    fn test_prune_drops_expired() {
        let mut c = FragmentLookupCache::new(8, Duration::from_millis(5));
        c.insert(loc(1));
        c.insert(loc(2));
        std::thread::sleep(Duration::from_millis(15));
        let removed = c.prune();
        assert_eq!(removed, 2);
        assert!(c.is_empty());
    }

    #[test]
    fn test_clear() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        c.insert(loc(1));
        c.insert(loc(2));
        c.clear();
        assert!(c.is_empty());
    }

    #[test]
    fn test_reset_stats() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        c.insert(loc(1));
        c.get(&key(1));
        c.reset_stats();
        assert_eq!(c.stats().hits, 0);
    }

    #[test]
    fn test_capacity_floor_of_one() {
        let c = FragmentLookupCache::new(0, Duration::from_secs(60));
        assert_eq!(c.capacity, 1);
    }

    #[test]
    fn test_stats_insertion_counter() {
        let mut c = FragmentLookupCache::new(8, Duration::from_secs(60));
        c.insert(loc(1));
        c.insert(loc(2));
        assert_eq!(c.stats().inserts, 2);
    }
}

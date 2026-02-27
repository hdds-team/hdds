// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! History cache for writer-side message retransmission
//!
//! Thread-safe ring buffer that stores recently written messages for retransmission.
//! Enforces QoS ResourceLimits (max_samples, max_quota_bytes) via FIFO eviction
//! for KEEP_LAST, or insert rejection for KEEP_ALL.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::core::rt::slabpool::{SlabHandle, SlabPool};
use crate::qos::{History, ResourceLimits};
use crate::telemetry::metrics::current_time_ns;
use crate::Error;

/// Special value meaning "no limit" for DurabilityService limits.
/// Corresponds to DDS LENGTH_UNLIMITED (-1 as i32).
pub const LENGTH_UNLIMITED: usize = usize::MAX;

/// Cache entry for a single written message.
#[derive(Debug, Clone, Copy)]
pub struct CacheEntry {
    pub seq: u64,
    pub slab: SlabHandle,
    pub len: usize,
    pub ts_ns: u64,
    /// Instance key hash (0 = unkeyed / default instance).
    pub instance_key: u64,
}

/// History cache for writer-side message retransmission.
pub struct HistoryCache {
    ring: Mutex<VecDeque<CacheEntry>>,
    slabs: Arc<SlabPool>,
    quota_bytes: AtomicUsize,
    max_quota_bytes: usize,
    max_samples: usize,
    history_kind: History,
    /// Maximum number of distinct instances (keyed topics).
    /// LENGTH_UNLIMITED means no limit.
    max_instances: usize,
    /// Maximum samples per instance for keyed topics.
    /// LENGTH_UNLIMITED means no limit.
    max_samples_per_instance: usize,
}

impl HistoryCache {
    /// Create new history cache from QoS `ResourceLimits`.
    pub fn new(slabs: Arc<SlabPool>, limits: &ResourceLimits) -> Self {
        let depth = u32::try_from(limits.max_samples).unwrap_or(u32::MAX);
        let history_kind = History::KeepLast(depth);
        Self::new_with_history(slabs, limits, history_kind)
    }

    /// Create new history cache from QoS `ResourceLimits` and history policy.
    pub fn new_with_history(
        slabs: Arc<SlabPool>,
        limits: &ResourceLimits,
        history_kind: History,
    ) -> Self {
        let max_samples = limits.max_samples;
        let max_quota_bytes = limits.max_quota_bytes;

        Self {
            ring: Mutex::new(VecDeque::with_capacity(max_samples)),
            slabs,
            quota_bytes: AtomicUsize::new(0),
            max_quota_bytes,
            max_samples,
            history_kind,
            max_instances: limits.max_instances,
            max_samples_per_instance: limits.max_samples_per_instance,
        }
    }

    /// Create new history cache with explicit limits (legacy API for tests).
    #[doc(hidden)]
    pub fn new_with_limits(
        slabs: Arc<SlabPool>,
        max_samples: usize,
        max_quota_bytes: usize,
        history_kind: History,
    ) -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(max_samples)),
            slabs,
            quota_bytes: AtomicUsize::new(0),
            max_quota_bytes,
            max_samples,
            history_kind,
            max_instances: LENGTH_UNLIMITED,
            max_samples_per_instance: LENGTH_UNLIMITED,
        }
    }

    /// Create new history cache with DurabilityService-style limits.
    ///
    /// Allows specifying max_instances and max_samples_per_instance in addition
    /// to basic max_samples and quota limits.
    pub fn new_with_durability_service_limits(
        slabs: Arc<SlabPool>,
        max_samples: usize,
        max_quota_bytes: usize,
        history_kind: History,
        max_instances: usize,
        max_samples_per_instance: usize,
    ) -> Self {
        Self {
            ring: Mutex::new(VecDeque::with_capacity(max_samples)),
            slabs,
            quota_bytes: AtomicUsize::new(0),
            max_quota_bytes,
            max_samples,
            history_kind,
            max_instances,
            max_samples_per_instance,
        }
    }

    /// Insert message into cache (unkeyed, instance_key = 0).
    pub fn insert(&self, seq: u64, payload: &[u8]) -> Result<(), Error> {
        self.insert_keyed(seq, payload, 0)
    }

    /// Insert message into cache with an explicit instance key.
    ///
    /// The instance_key is a hash that identifies the data instance for keyed topics.
    /// For unkeyed topics, use 0.
    pub fn insert_keyed(&self, seq: u64, payload: &[u8], instance_key: u64) -> Result<(), Error> {
        let len = payload.len();
        let (handle, buf) = self.slabs.reserve(len).ok_or(Error::WouldBlock)?;

        buf[..len].copy_from_slice(payload);
        self.slabs.commit(handle, len);

        let entry = CacheEntry {
            seq,
            slab: handle,
            len,
            ts_ns: current_time_ns(),
            instance_key,
        };

        let should_reject = {
            let mut ring = match self.ring.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    log::debug!("[HistoryCache::insert] Lock poisoned, recovering");
                    e.into_inner()
                }
            };

            if matches!(self.history_kind, History::KeepAll) {
                let next_samples = ring.len().saturating_add(1);
                let next_quota = self.quota_bytes.load(Ordering::Relaxed).saturating_add(len);
                if next_samples > self.max_samples || next_quota > self.max_quota_bytes {
                    true
                } else {
                    // Check instance limits for KEEP_ALL
                    if self.would_exceed_instance_limits(&ring, instance_key) {
                        true
                    } else {
                        ring.push_back(entry);
                        false
                    }
                }
            } else {
                ring.push_back(entry);
                false
            }
        };

        if should_reject {
            self.slabs.release(handle);
            return Err(Error::WouldBlock);
        }

        self.quota_bytes.fetch_add(len, Ordering::Relaxed);
        if matches!(self.history_kind, History::KeepLast(_)) {
            self.enforce_limits();
            self.enforce_instance_limits();
        }
        Ok(())
    }

    /// Get message by sequence number.
    pub fn get(&self, seq: u64) -> Option<Vec<u8>> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::get] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        let entry = ring.iter().find(|e| e.seq == seq)?;
        let buf = self.slabs.get_buffer(entry.slab);
        Some(buf[..entry.len].to_vec())
    }

    /// Get number of cached messages.
    pub fn len(&self) -> usize {
        match self.ring.lock() {
            Ok(lock) => lock.len(),
            Err(e) => {
                log::debug!("[HistoryCache::len] Lock poisoned, recovering");
                e.into_inner().len()
            }
        }
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        match self.ring.lock() {
            Ok(lock) => lock.is_empty(),
            Err(e) => {
                log::debug!("[HistoryCache::is_empty] Lock poisoned, recovering");
                e.into_inner().is_empty()
            }
        }
    }

    /// Get current quota usage in bytes.
    pub fn quota_bytes(&self) -> usize {
        self.quota_bytes.load(Ordering::Relaxed)
    }

    /// Expose configured sample capacity.
    #[must_use]
    pub fn max_samples(&self) -> usize {
        self.max_samples
    }

    /// Expose configured quota limit in bytes.
    #[must_use]
    pub fn max_quota_bytes(&self) -> usize {
        self.max_quota_bytes
    }

    /// Expose configured history policy.
    #[must_use]
    pub fn history_kind(&self) -> History {
        self.history_kind
    }

    /// Snapshot all cached samples for late-joiner delivery.
    pub fn get_all_samples(&self) -> Vec<(u64, SlabHandle, usize)> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::get_all_samples] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.iter().map(|e| (e.seq, e.slab, e.len)).collect()
    }

    /// Snapshot all cached payloads (seq + bytes) for late-joiner replay.
    pub fn snapshot_payloads(&self) -> Vec<(u64, Vec<u8>)> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::snapshot_payloads] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        ring.iter()
            .map(|entry| {
                let buf = self.slabs.get_buffer(entry.slab);
                (entry.seq, buf[..entry.len].to_vec())
            })
            .collect()
    }

    /// Snapshot cached payloads for late-joiner replay, limited by DurabilityService constraints.
    ///
    /// Returns only the most recent `max_replay_samples` samples.
    /// If `max_replay_samples` is LENGTH_UNLIMITED, returns all cached samples.
    pub fn snapshot_payloads_limited(&self, max_replay_samples: usize) -> Vec<(u64, Vec<u8>)> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::snapshot_payloads_limited] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        let total = ring.len();
        let skip = if max_replay_samples >= total || max_replay_samples == LENGTH_UNLIMITED {
            0
        } else {
            total - max_replay_samples
        };

        ring.iter()
            .skip(skip)
            .map(|entry| {
                let buf = self.slabs.get_buffer(entry.slab);
                (entry.seq, buf[..entry.len].to_vec())
            })
            .collect()
    }

    /// Expose configured max_instances limit.
    #[must_use]
    pub fn max_instances(&self) -> usize {
        self.max_instances
    }

    /// Expose configured max_samples_per_instance limit.
    #[must_use]
    pub fn max_samples_per_instance(&self) -> usize {
        self.max_samples_per_instance
    }

    /// Count distinct instance keys currently in the cache.
    pub fn instance_count(&self) -> usize {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::instance_count] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        Self::count_instances(&ring)
    }

    /// Count samples for a specific instance key.
    pub fn samples_for_instance(&self, instance_key: u64) -> usize {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::samples_for_instance] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.iter()
            .filter(|e| e.instance_key == instance_key)
            .count()
    }

    /// Remove all samples acknowledged by all readers (seqs <= acked_seq).
    ///
    /// Returns the number of samples removed.
    pub fn remove_acknowledged(&self, acked_seq: u64) -> usize {
        let mut removed = 0;
        let mut ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::remove_acknowledged] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        while let Some(front) = ring.front() {
            if front.seq <= acked_seq {
                let Some(entry) = ring.pop_front() else {
                    unreachable!("front() returned Some, pop_front must succeed")
                };
                self.slabs.release(entry.slab);
                self.quota_bytes.fetch_sub(entry.len, Ordering::Relaxed);
                removed += 1;
            } else {
                break;
            }
        }

        removed
    }

    /// Get oldest sequence number in cache.
    pub fn oldest_seq(&self) -> Option<u64> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::oldest_seq] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.front().map(|e| e.seq)
    }

    /// Get newest sequence number in cache.
    pub fn newest_seq(&self) -> Option<u64> {
        let ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::newest_seq] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        ring.back().map(|e| e.seq)
    }

    /// Evict oldest entry from cache.
    pub fn evict_oldest(&self) -> Option<u64> {
        let entry = {
            let mut ring = match self.ring.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    log::debug!("[HistoryCache::evict_oldest] Lock poisoned, recovering");
                    e.into_inner()
                }
            };
            ring.pop_front()?
        };
        self.slabs.release(entry.slab);
        self.quota_bytes.fetch_sub(entry.len, Ordering::Relaxed);
        Some(entry.seq)
    }

    fn enforce_limits(&self) {
        while self.len() > self.max_samples {
            self.evict_oldest();
        }

        while self.quota_bytes.load(Ordering::Relaxed) > self.max_quota_bytes && !self.is_empty() {
            self.evict_oldest();
        }
    }

    /// Enforce per-instance limits (max_instances and max_samples_per_instance).
    ///
    /// Evicts oldest samples from the most populated instances until limits are met.
    fn enforce_instance_limits(&self) {
        if self.max_instances == LENGTH_UNLIMITED
            && self.max_samples_per_instance == LENGTH_UNLIMITED
        {
            return;
        }

        let mut ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::enforce_instance_limits] Lock poisoned, recovering");
                e.into_inner()
            }
        };

        // Enforce max_samples_per_instance by evicting oldest entries for over-limit instances
        if self.max_samples_per_instance != LENGTH_UNLIMITED {
            let mut changed = true;
            while changed {
                changed = false;
                // Find the first instance that exceeds its per-instance limit
                // and evict the oldest sample from that instance.
                let mut instance_to_evict: Option<(usize, u64)> = None;

                // Count samples per instance and find the first over-limit one
                for (idx, entry) in ring.iter().enumerate() {
                    let count = ring
                        .iter()
                        .filter(|e| e.instance_key == entry.instance_key)
                        .count();
                    if count > self.max_samples_per_instance {
                        instance_to_evict = Some((idx, entry.instance_key));
                        break;
                    }
                }

                if let Some((_idx, key)) = instance_to_evict {
                    // Find and remove the oldest entry for this instance
                    if let Some(pos) = ring.iter().position(|e| e.instance_key == key) {
                        let Some(entry) = ring.remove(pos) else {
                            unreachable!("position() found idx {pos}, remove must succeed")
                        };
                        self.slabs.release(entry.slab);
                        self.quota_bytes.fetch_sub(entry.len, Ordering::Relaxed);
                        changed = true;
                    }
                }
            }
        }

        // Enforce max_instances by evicting oldest samples from the oldest instance
        if self.max_instances != LENGTH_UNLIMITED {
            while Self::count_instances(&ring) > self.max_instances {
                // Find the oldest instance (by earliest seq in ring)
                if let Some(oldest_entry) = ring.front() {
                    let oldest_key = oldest_entry.instance_key;
                    // Remove all samples from this instance
                    let mut removed_indices = Vec::new();
                    for (idx, entry) in ring.iter().enumerate() {
                        if entry.instance_key == oldest_key {
                            removed_indices.push(idx);
                        }
                    }
                    // Remove in reverse order to preserve indices --
                    // reverse guarantees earlier indices remain valid after each removal
                    for &idx in removed_indices.iter().rev() {
                        let Some(entry) = ring.remove(idx) else {
                            log::error!(
                                "[history_cache] BUG: remove({idx}) failed, ring len={}, \
                                 skipping -- indices may have been invalidated",
                                ring.len()
                            );
                            continue;
                        };
                        self.slabs.release(entry.slab);
                        self.quota_bytes.fetch_sub(entry.len, Ordering::Relaxed);
                    }
                } else {
                    break;
                }
            }
        }
    }

    /// Check if adding a new entry with the given instance_key would exceed instance limits.
    fn would_exceed_instance_limits(&self, ring: &VecDeque<CacheEntry>, instance_key: u64) -> bool {
        // Check max_instances
        if self.max_instances != LENGTH_UNLIMITED {
            let is_new_instance = !ring.iter().any(|e| e.instance_key == instance_key);
            if is_new_instance && Self::count_instances(ring) >= self.max_instances {
                return true;
            }
        }

        // Check max_samples_per_instance
        if self.max_samples_per_instance != LENGTH_UNLIMITED {
            let instance_count = ring
                .iter()
                .filter(|e| e.instance_key == instance_key)
                .count();
            if instance_count >= self.max_samples_per_instance {
                return true;
            }
        }

        false
    }

    /// Count the number of distinct instance keys in the ring.
    fn count_instances(ring: &VecDeque<CacheEntry>) -> usize {
        let mut keys: Vec<u64> = Vec::new();
        for entry in ring.iter() {
            if !keys.contains(&entry.instance_key) {
                keys.push(entry.instance_key);
            }
        }
        keys.len()
    }

    /// Clear all entries from cache.
    pub fn clear(&self) {
        let mut ring = match self.ring.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[HistoryCache::clear] Lock poisoned, recovering");
                e.into_inner()
            }
        };
        while let Some(entry) = ring.pop_front() {
            self.slabs.release(entry.slab);
        }
        self.quota_bytes.store(0, Ordering::Relaxed);
    }
}

impl Drop for HistoryCache {
    fn drop(&mut self) {
        self.clear();
    }
}

// Removed: now using telemetry::metrics::current_time_ns()

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rt::slabpool::SlabPool;
    use std::sync::Arc;

    fn make_cache() -> HistoryCache {
        let pool = Arc::new(SlabPool::new());
        HistoryCache::new_with_limits(pool, 100, 10_000_000, History::KeepLast(100))
    }

    #[test]
    fn test_cache_new() {
        let cache = make_cache();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.quota_bytes(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_insert_get() {
        let cache = make_cache();
        let data = b"Hello, world!";

        cache.insert(42, data).expect("Cache insert should succeed");

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(42), Some(data.to_vec()));
        assert_eq!(cache.get(99), None);
    }

    #[test]
    fn test_cache_insert_multiple() {
        let cache = make_cache();

        cache
            .insert(1, b"one")
            .expect("Cache insert should succeed");
        cache
            .insert(2, b"two")
            .expect("Cache insert should succeed");
        cache
            .insert(3, b"three")
            .expect("Cache insert should succeed");

        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(1), Some(b"one".to_vec()));
        assert_eq!(cache.get(2), Some(b"two".to_vec()));
        assert_eq!(cache.get(3), Some(b"three".to_vec()));
    }

    #[test]
    fn test_cache_evict_oldest() {
        let cache = make_cache();

        cache
            .insert(10, b"first")
            .expect("Cache insert should succeed");
        cache
            .insert(20, b"second")
            .expect("Cache insert should succeed");

        let evicted = cache.evict_oldest();
        assert_eq!(evicted, Some(10));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get(10), None);
        assert_eq!(cache.get(20), Some(b"second".to_vec()));
    }

    #[test]
    fn test_cache_capacity_limit() {
        let pool = Arc::new(SlabPool::new());
        let cache = HistoryCache::new_with_limits(pool, 10, 10_000_000, History::KeepLast(10));

        for i in 1..=15 {
            cache
                .insert(i, b"data")
                .expect("Cache insert should succeed");
        }

        assert_eq!(cache.len(), 10);
        assert_eq!(cache.oldest_seq(), Some(6));
        assert_eq!(cache.newest_seq(), Some(15));
    }

    #[test]
    fn test_cache_quota_limit() {
        let pool = Arc::new(SlabPool::new());
        let cache = HistoryCache::new_with_limits(pool, 1000, 50, History::KeepLast(1000));

        for i in 1..=10 {
            cache
                .insert(i, &[0u8; 10])
                .expect("Cache insert should succeed");
        }

        assert!(cache.quota_bytes() <= 50);
        assert!(cache.len() <= 5);
    }

    #[test]
    fn test_cache_oldest_newest_seq() {
        let cache = make_cache();

        cache
            .insert(100, b"a")
            .expect("Cache insert should succeed");
        cache
            .insert(200, b"b")
            .expect("Cache insert should succeed");
        cache
            .insert(300, b"c")
            .expect("Cache insert should succeed");

        assert_eq!(cache.oldest_seq(), Some(100));
        assert_eq!(cache.newest_seq(), Some(300));
    }

    #[test]
    fn test_cache_clear() {
        let cache = make_cache();

        cache
            .insert(1, b"test")
            .expect("Cache insert should succeed");
        cache
            .insert(2, b"data")
            .expect("Cache insert should succeed");

        cache.clear();

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.quota_bytes(), 0);
        assert_eq!(cache.oldest_seq(), None);
    }

    #[test]
    fn test_cache_get_not_found() {
        let cache = make_cache();
        assert_eq!(cache.get(999), None);
    }

    #[test]
    fn test_cache_quota_tracking() {
        let cache = make_cache();

        cache
            .insert(1, &[0u8; 100])
            .expect("Cache insert should succeed");
        assert_eq!(cache.quota_bytes(), 100);

        cache
            .insert(2, &[0u8; 50])
            .expect("Cache insert should succeed");
        assert_eq!(cache.quota_bytes(), 150);

        cache.evict_oldest();
        assert_eq!(cache.quota_bytes(), 50);
    }

    #[test]
    fn test_cache_fifo_order() {
        let pool = Arc::new(SlabPool::new());
        let cache = HistoryCache::new_with_limits(pool, 3, 10_000_000, History::KeepLast(3));

        cache.insert(10, b"a").expect("Cache insert should succeed");
        cache.insert(20, b"b").expect("Cache insert should succeed");
        cache.insert(30, b"c").expect("Cache insert should succeed");
        cache.insert(40, b"d").expect("Cache insert should succeed");

        assert_eq!(cache.len(), 3);
        assert_eq!(cache.get(10), None);
        assert_eq!(cache.get(20), Some(b"b".to_vec()));
        assert_eq!(cache.get(30), Some(b"c".to_vec()));
        assert_eq!(cache.get(40), Some(b"d".to_vec()));
    }

    #[test]
    fn test_cache_with_resource_limits() {
        use crate::qos::ResourceLimits;

        let pool = Arc::new(SlabPool::new());
        let limits = ResourceLimits {
            max_samples: 50,
            max_instances: 1,
            max_samples_per_instance: 50,
            max_quota_bytes: 1000,
        };

        let cache = HistoryCache::new_with_history(pool, &limits, History::KeepLast(50));

        for i in 1..=60 {
            cache
                .insert(i, &[0u8; 10])
                .expect("Cache insert should succeed");
        }

        assert_eq!(cache.len(), 50);
        assert_eq!(cache.oldest_seq(), Some(11));
        assert_eq!(cache.newest_seq(), Some(60));
        assert!(cache.quota_bytes() <= limits.max_quota_bytes);
    }

    #[test]
    fn test_cache_keep_all_rejects_when_full() {
        let pool = Arc::new(SlabPool::new());
        let cache = HistoryCache::new_with_limits(pool, 2, 100, History::KeepAll);

        cache.insert(1, b"a").expect("Cache insert should succeed");
        cache.insert(2, b"b").expect("Cache insert should succeed");
        let err = cache
            .insert(3, b"c")
            .expect_err("KeepAll should reject overflow");

        assert!(matches!(err, Error::WouldBlock));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.oldest_seq(), Some(1));
    }

    #[test]
    fn test_cache_resource_limits_default() {
        use crate::qos::ResourceLimits;

        let pool = Arc::new(SlabPool::new());
        let limits = ResourceLimits::default();

        let cache = HistoryCache::new_with_history(pool, &limits, History::KeepLast(100_000));

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.quota_bytes(), 0);
        assert_eq!(cache.max_samples(), 100_000);
        assert_eq!(cache.max_quota_bytes(), 100_000_000);
    }
}

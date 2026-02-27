// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Sample cache for DataReader with read/take semantics.
//!
//! This module provides a cache that supports both DDS `read()` (non-destructive)
//! and `take()` (destructive) operations on received samples.
//!
//! # Architecture
//!
//! ```text
//! Buffer: [S0][S1][S2][S3][S4][S5]
//!          ^              ^
//!          |              |
//!     take_cursor    write_cursor
//!
//! read()  -> peek from take_cursor, marks sample as READ
//! take()  -> removes sample, advances take_cursor
//! ```

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Sample state per DDS spec (NOT_READ vs READ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleState {
    /// Sample has not been read yet.
    NotRead,
    /// Sample has been accessed via `read()`.
    Read,
}

/// Instance handle for keyed topics (16-byte key hash).
///
/// This is the DDS-standard instance identifier computed from @key fields.
/// For keyless topics, this is all zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InstanceHandle(pub [u8; 16]);

impl InstanceHandle {
    /// Create a new instance handle from a key hash.
    pub const fn new(key_hash: [u8; 16]) -> Self {
        Self(key_hash)
    }

    /// Create a nil (all zeros) instance handle for keyless topics.
    pub const fn nil() -> Self {
        Self([0u8; 16])
    }

    /// Check if this is a nil handle.
    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Get the raw key hash bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Cached sample with metadata.
#[derive(Debug)]
pub struct CachedSample<T> {
    /// The actual data.
    pub data: T,
    /// Sequence number from writer.
    pub seq: u64,
    /// Reception timestamp (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Instance handle (key hash for keyed topics).
    pub instance_handle: InstanceHandle,
    /// Sample state (NOT_READ vs READ).
    state: AtomicBool, // false = NotRead, true = Read
}

impl<T: Clone> Clone for CachedSample<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            seq: self.seq,
            timestamp_ns: self.timestamp_ns,
            instance_handle: self.instance_handle,
            state: AtomicBool::new(self.state.load(Ordering::Relaxed)),
        }
    }
}

impl<T> CachedSample<T> {
    /// Create a new cached sample (keyless topic, nil instance handle).
    #[allow(dead_code)] // DDS API - available for DataReader extensions
    pub fn new(data: T, seq: u64, timestamp_ns: u64) -> Self {
        Self {
            data,
            seq,
            timestamp_ns,
            instance_handle: InstanceHandle::nil(),
            state: AtomicBool::new(false), // NotRead
        }
    }

    /// Create a new cached sample with an instance handle (keyed topic).
    pub fn with_instance(
        data: T,
        seq: u64,
        timestamp_ns: u64,
        instance_handle: InstanceHandle,
    ) -> Self {
        Self {
            data,
            seq,
            timestamp_ns,
            instance_handle,
            state: AtomicBool::new(false), // NotRead
        }
    }

    /// Get sample state.
    pub fn sample_state(&self) -> SampleState {
        if self.state.load(Ordering::Relaxed) {
            SampleState::Read
        } else {
            SampleState::NotRead
        }
    }

    /// Mark sample as read.
    pub fn mark_read(&self) {
        self.state.store(true, Ordering::Relaxed);
    }
}

/// Sample cache with read/take cursor semantics.
///
/// Supports DDS-compliant read (non-destructive) and take (destructive) operations.
pub struct SampleCache<T> {
    /// Ring buffer of cached samples.
    buffer: Mutex<VecDeque<CachedSample<T>>>,
    /// Read cursor position (for read operations).
    /// Samples before this cursor have been read at least once.
    read_cursor: AtomicUsize,
    /// Maximum number of samples to keep (history depth).
    max_samples: usize,
    /// Total samples received (for stats).
    total_received: AtomicUsize,
}

impl<T> SampleCache<T> {
    /// Create a new sample cache with given history depth.
    pub fn new(max_samples: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(max_samples)),
            read_cursor: AtomicUsize::new(0),
            max_samples,
            total_received: AtomicUsize::new(0),
        }
    }

    /// Push a new sample into the cache.
    ///
    /// If cache is full (at max_samples), removes oldest sample.
    pub fn push(&self, sample: CachedSample<T>) {
        let mut buffer = self.buffer.lock();

        // Dedup: reject if a sample with same seq already in buffer
        if buffer.iter().any(|s| s.seq == sample.seq) {
            log::warn!("[CACHE] dedup: dropping duplicate seq={}", sample.seq);
            return;
        }

        // Enforce history depth
        while buffer.len() >= self.max_samples {
            buffer.pop_front();
            // Adjust read cursor if it was pointing to removed sample
            let cursor = self.read_cursor.load(Ordering::Relaxed);
            if cursor > 0 {
                self.read_cursor.store(cursor - 1, Ordering::Relaxed);
            }
        }

        buffer.push_back(sample);
        self.total_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of samples currently in cache.
    #[allow(dead_code)] // DDS API - diagnostics
    pub fn len(&self) -> usize {
        self.buffer.lock().len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.lock().is_empty()
    }

    /// Total samples received since creation.
    #[allow(dead_code)] // DDS API - diagnostics
    pub fn total_received(&self) -> usize {
        self.total_received.load(Ordering::Relaxed)
    }
}

impl<T> SampleCache<T> {
    /// Take a single sample, removing it from cache (DDS take semantics).
    ///
    /// Returns and removes the oldest sample.
    /// Returns `None` if cache is empty.
    pub fn take(&self) -> Option<T> {
        let mut buffer = self.buffer.lock();

        if buffer.is_empty() {
            return None;
        }

        let sample = buffer.pop_front()?;

        // Adjust read cursor
        let cursor = self.read_cursor.load(Ordering::Relaxed);
        if cursor > 0 {
            self.read_cursor.store(cursor - 1, Ordering::Relaxed);
        }

        Some(sample.data)
    }

    /// Take up to `max` samples, removing them from cache.
    #[allow(dead_code)] // DDS API - batch operations
    pub fn take_batch(&self, max: usize) -> Vec<T> {
        let mut buffer = self.buffer.lock();
        let count = max.min(buffer.len());
        let mut result = Vec::with_capacity(count);

        for _ in 0..count {
            if let Some(sample) = buffer.pop_front() {
                result.push(sample.data);
            }
        }

        // Reset read cursor (samples removed from front)
        let cursor = self.read_cursor.load(Ordering::Relaxed);
        let new_cursor = cursor.saturating_sub(count);
        self.read_cursor.store(new_cursor, Ordering::Relaxed);

        result
    }

    /// Reset read cursor to beginning (re-read all samples).
    #[allow(dead_code)] // DDS API - cursor management
    pub fn reset_read_cursor(&self) {
        self.read_cursor.store(0, Ordering::Relaxed);
    }

    /// Clear all samples from cache.
    #[allow(dead_code)] // DDS API - cache management
    pub fn clear(&self) {
        let mut buffer = self.buffer.lock();
        buffer.clear();
        self.read_cursor.store(0, Ordering::Relaxed);
    }

    /// Take a single sample for a specific instance, removing it (DDS take_instance).
    ///
    /// Returns and removes the oldest sample matching the given instance handle.
    /// Uses linear scan O(n) - acceptable for v1.0.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    ///
    /// # Returns
    /// * `Some(data)` if a matching sample was found and removed
    /// * `None` if no matching sample exists
    pub fn take_instance(&self, handle: InstanceHandle) -> Option<T> {
        let mut buffer = self.buffer.lock();

        // Linear scan to find first matching instance
        let pos = buffer.iter().position(|s| s.instance_handle == handle)?;

        let sample = buffer.remove(pos)?;

        // Adjust read cursor if we removed a sample before it
        let cursor = self.read_cursor.load(Ordering::Relaxed);
        if pos < cursor {
            self.read_cursor.store(cursor - 1, Ordering::Relaxed);
        }

        Some(sample.data)
    }

    /// Take up to `max` samples for a specific instance, removing them.
    ///
    /// Returns and removes samples matching the given instance handle.
    /// Uses linear scan O(n*max) - acceptable for v1.0.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    /// * `max` - Maximum number of samples to take
    pub fn take_instance_batch(&self, handle: InstanceHandle, max: usize) -> Vec<T> {
        let mut buffer = self.buffer.lock();
        let mut result = Vec::with_capacity(max);
        let mut removed_before_cursor = 0;
        let cursor = self.read_cursor.load(Ordering::Relaxed);

        // Collect indices to remove (in reverse order to not invalidate indices)
        let indices: Vec<usize> = buffer
            .iter()
            .enumerate()
            .filter(|(_, s)| s.instance_handle == handle)
            .take(max)
            .map(|(i, _)| i)
            .collect();

        // Remove in reverse order to maintain valid indices
        for &idx in indices.iter().rev() {
            if let Some(sample) = buffer.remove(idx) {
                result.push(sample.data);
                if idx < cursor {
                    removed_before_cursor += 1;
                }
            }
        }

        // Adjust read cursor
        if removed_before_cursor > 0 {
            let new_cursor = cursor.saturating_sub(removed_before_cursor);
            self.read_cursor.store(new_cursor, Ordering::Relaxed);
        }

        // Results are in reverse order, fix that
        result.reverse();
        result
    }
}

// Read operations require T: Clone (samples are copied, not moved)
impl<T: Clone> SampleCache<T> {
    /// Read a single sample without removing it (DDS read semantics).
    ///
    /// Returns the next unread sample and marks it as READ.
    /// Returns `None` if no unread samples available.
    pub fn read(&self) -> Option<T> {
        let buffer = self.buffer.lock();
        let cursor = self.read_cursor.load(Ordering::Relaxed);

        if cursor >= buffer.len() {
            return None;
        }

        let sample = &buffer[cursor];
        sample.mark_read();

        // Advance read cursor
        self.read_cursor.store(cursor + 1, Ordering::Relaxed);

        Some(sample.data.clone())
    }

    /// Read up to `max` samples without removing them.
    ///
    /// Returns samples and marks them as READ.
    pub fn read_batch(&self, max: usize) -> Vec<T> {
        let buffer = self.buffer.lock();
        let mut cursor = self.read_cursor.load(Ordering::Relaxed);
        let mut result = Vec::with_capacity(max.min(buffer.len()));

        for _ in 0..max {
            if cursor >= buffer.len() {
                break;
            }

            let sample = &buffer[cursor];
            sample.mark_read();
            result.push(sample.data.clone());
            cursor += 1;
        }

        self.read_cursor.store(cursor, Ordering::Relaxed);
        result
    }

    /// Read a single sample for a specific instance (DDS read_instance).
    ///
    /// Returns the first unread sample matching the given instance handle.
    /// Uses linear scan O(n) - acceptable for v1.0.
    ///
    /// Note: This only reads samples that haven't been read yet. After reading,
    /// the sample is marked as READ and won't be returned again by `read_instance`.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    ///
    /// # Returns
    /// * `Some(data)` if a matching unread sample was found
    /// * `None` if no matching unread sample exists
    pub fn read_instance(&self, handle: InstanceHandle) -> Option<T> {
        let buffer = self.buffer.lock();

        // Linear scan to find first unread matching instance
        for sample in buffer.iter() {
            if sample.instance_handle == handle && sample.sample_state() == SampleState::NotRead {
                sample.mark_read();
                return Some(sample.data.clone());
            }
        }

        None
    }

    /// Read up to `max` samples for a specific instance without removing them.
    ///
    /// Returns clones of unread samples matching the given instance handle.
    /// Uses linear scan O(n) - acceptable for v1.0.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    /// * `max` - Maximum number of samples to read
    pub fn read_instance_batch(&self, handle: InstanceHandle, max: usize) -> Vec<T> {
        let buffer = self.buffer.lock();
        let mut result = Vec::with_capacity(max);

        // Linear scan for unread samples matching instance
        for sample in buffer.iter() {
            if result.len() >= max {
                break;
            }

            if sample.instance_handle == handle && sample.sample_state() == SampleState::NotRead {
                sample.mark_read();
                result.push(sample.data.clone());
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_take() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0));

        assert_eq!(cache.len(), 3);

        assert_eq!(cache.take(), Some(1));
        assert_eq!(cache.take(), Some(2));
        assert_eq!(cache.take(), Some(3));
        assert_eq!(cache.take(), None);
    }

    #[test]
    fn test_push_read() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0));

        // Read doesn't remove
        assert_eq!(cache.read(), Some(1));
        assert_eq!(cache.read(), Some(2));
        assert_eq!(cache.read(), Some(3));
        assert_eq!(cache.read(), None); // No more unread

        // Still 3 samples in cache
        assert_eq!(cache.len(), 3);

        // Reset and read again
        cache.reset_read_cursor();
        assert_eq!(cache.read(), Some(1));
    }

    #[test]
    fn test_read_then_take() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));

        // Read first sample
        assert_eq!(cache.read(), Some(1));

        // Take removes from front
        assert_eq!(cache.take(), Some(1));

        // Read cursor adjusted, next read is sample 2
        assert_eq!(cache.read(), Some(2));
    }

    #[test]
    fn test_take_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        for i in 1..=5 {
            cache.push(CachedSample::new(i, i as u64, 0));
        }

        let batch = cache.take_batch(3);
        assert_eq!(batch, vec![1, 2, 3]);
        assert_eq!(cache.len(), 2);

        let batch = cache.take_batch(10);
        assert_eq!(batch, vec![4, 5]);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_read_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        for i in 1..=5 {
            cache.push(CachedSample::new(i, i as u64, 0));
        }

        let batch = cache.read_batch(3);
        assert_eq!(batch, vec![1, 2, 3]);
        assert_eq!(cache.len(), 5); // Still all there

        let batch = cache.read_batch(10);
        assert_eq!(batch, vec![4, 5]); // Only unread ones

        // All read, no more
        let batch = cache.read_batch(10);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_history_depth() {
        let cache: SampleCache<i32> = SampleCache::new(3);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0));
        assert_eq!(cache.len(), 3);

        // Push 4th, should evict oldest
        cache.push(CachedSample::new(4, 4, 0));
        assert_eq!(cache.len(), 3);

        let all = cache.take_batch(10);
        assert_eq!(all, vec![2, 3, 4]); // 1 was evicted
    }

    #[test]
    fn test_sample_state() {
        let sample = CachedSample::new(42, 1, 0);
        assert_eq!(sample.sample_state(), SampleState::NotRead);

        sample.mark_read();
        assert_eq!(sample.sample_state(), SampleState::Read);
    }

    #[test]
    fn test_total_received() {
        let cache: SampleCache<i32> = SampleCache::new(2);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0)); // Evicts 1

        assert_eq!(cache.total_received(), 3);
        assert_eq!(cache.len(), 2);
    }

    // =========================================================================
    // Instance filtering tests (Phase 2)
    // =========================================================================

    fn make_handle(id: u8) -> InstanceHandle {
        let mut key = [0u8; 16];
        key[0] = id;
        InstanceHandle::new(key)
    }

    #[test]
    fn test_push_dedup_same_seq() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        // Push 3 samples with distinct seqs
        cache.push(CachedSample::new(10, 1, 0));
        cache.push(CachedSample::new(20, 2, 0));
        cache.push(CachedSample::new(30, 3, 0));
        assert_eq!(cache.len(), 3);

        // Push duplicates (same seqs, different data) — should all be rejected
        cache.push(CachedSample::new(11, 1, 0));
        cache.push(CachedSample::new(21, 2, 0));
        cache.push(CachedSample::new(31, 3, 0));
        assert_eq!(cache.len(), 3, "Duplicates should have been rejected");

        // take() returns original data in order, then None
        assert_eq!(cache.take(), Some(10));
        assert_eq!(cache.take(), Some(20));
        assert_eq!(cache.take(), Some(30));
        assert_eq!(cache.take(), None);
    }

    #[test]
    fn test_instance_handle() {
        let nil = InstanceHandle::nil();
        assert!(nil.is_nil());
        assert_eq!(nil.as_bytes(), &[0u8; 16]);

        let handle = make_handle(42);
        assert!(!handle.is_nil());
        assert_eq!(handle.as_bytes()[0], 42);
    }

    #[test]
    fn test_take_instance() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        // Push samples with different instance handles
        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));
        cache.push(CachedSample::with_instance(21, 4, 0, h2));

        // Take from instance 1
        assert_eq!(cache.take_instance(h1), Some(10));
        assert_eq!(cache.len(), 3);

        // Take from instance 2
        assert_eq!(cache.take_instance(h2), Some(20));
        assert_eq!(cache.len(), 2);

        // Take remaining from instance 1
        assert_eq!(cache.take_instance(h1), Some(11));
        assert_eq!(cache.len(), 1);

        // No more instance 1 samples
        assert_eq!(cache.take_instance(h1), None);

        // Still one instance 2 sample
        assert_eq!(cache.take_instance(h2), Some(21));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_take_instance_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        // Push interleaved samples
        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));
        cache.push(CachedSample::with_instance(21, 4, 0, h2));
        cache.push(CachedSample::with_instance(12, 5, 0, h1));

        // Take batch from instance 1 (limit 2)
        let batch = cache.take_instance_batch(h1, 2);
        assert_eq!(batch, vec![10, 11]);
        assert_eq!(cache.len(), 3);

        // Take all remaining from instance 1
        let batch = cache.take_instance_batch(h1, 10);
        assert_eq!(batch, vec![12]);
        assert_eq!(cache.len(), 2);

        // Only instance 2 samples remain
        let batch = cache.take_instance_batch(h2, 10);
        assert_eq!(batch, vec![20, 21]);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_read_instance() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));

        // Read from instance 1 (non-destructive)
        assert_eq!(cache.read_instance(h1), Some(10));
        assert_eq!(cache.len(), 3); // Still all there

        // Reading again from instance 1 gets next unread sample
        assert_eq!(cache.read_instance(h1), Some(11));

        // No more unread instance 1 samples
        assert_eq!(cache.read_instance(h1), None);

        // Instance 2 sample still unread
        assert_eq!(cache.read_instance(h2), Some(20));
        assert_eq!(cache.read_instance(h2), None);

        // All samples still in cache
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_read_instance_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));
        cache.push(CachedSample::with_instance(12, 4, 0, h1));

        // Read batch from instance 1 (limit 2)
        let batch = cache.read_instance_batch(h1, 2);
        assert_eq!(batch, vec![10, 11]);

        // Read remaining unread from instance 1
        let batch = cache.read_instance_batch(h1, 10);
        assert_eq!(batch, vec![12]);

        // No more unread instance 1 samples
        let batch = cache.read_instance_batch(h1, 10);
        assert!(batch.is_empty());

        // All samples still in cache
        assert_eq!(cache.len(), 4);
    }

    #[test]
    fn test_take_instance_adjusts_read_cursor() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(30, 3, 0, h1));

        // Read first two samples (advances cursor to 2)
        assert_eq!(cache.read(), Some(10));
        assert_eq!(cache.read(), Some(20));

        // Take instance 1 sample from front (should adjust cursor)
        assert_eq!(cache.take_instance(h1), Some(10));

        // Next read should be sample at new cursor position
        assert_eq!(cache.read(), Some(30));
    }

    #[test]
    fn test_instance_handle_nil() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let nil = InstanceHandle::nil();

        // Keyless samples use nil handle
        cache.push(CachedSample::new(1, 1, 0)); // Uses nil handle
        cache.push(CachedSample::new(2, 2, 0));

        // Can filter by nil handle (all keyless samples)
        assert_eq!(cache.take_instance(nil), Some(1));
        assert_eq!(cache.take_instance(nil), Some(2));
        assert_eq!(cache.take_instance(nil), None);
    }
}

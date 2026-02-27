// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Coalescing queue for P2 (background) traffic.
//!
//! Implements "last value wins" semantics by instance key, reducing
//! queue pressure for high-frequency telemetry where only the latest
//! value matters.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// FNV-1a 64-bit offset basis (standard constant).
const FNV1A_OFFSET_BASIS: u64 = 0xcbf29ce484222325;

/// FNV-1a 64-bit prime multiplier (standard constant).
const FNV1A_PRIME: u64 = 0x100000001b3;

/// Instance key for coalescing (topic + key hash).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InstanceKey {
    /// Topic name hash (or full name for small topics).
    topic_hash: u64,
    /// Instance key hash (from @key fields).
    key_hash: u64,
}

impl InstanceKey {
    /// Create a new instance key.
    pub fn new(topic_hash: u64, key_hash: u64) -> Self {
        Self {
            topic_hash,
            key_hash,
        }
    }

    /// Create from topic name and key bytes.
    pub fn from_topic_and_key(topic: &str, key: &[u8]) -> Self {
        Self {
            topic_hash: Self::hash_bytes(topic.as_bytes()),
            key_hash: Self::hash_bytes(key),
        }
    }

    /// Create for a keyless topic (single instance).
    pub fn keyless(topic: &str) -> Self {
        Self {
            topic_hash: Self::hash_bytes(topic.as_bytes()),
            key_hash: 0,
        }
    }

    fn hash_bytes(data: &[u8]) -> u64 {
        // FNV-1a hash
        let mut hash = FNV1A_OFFSET_BASIS;
        for byte in data {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(FNV1A_PRIME);
        }
        hash
    }
}

/// A pending sample in the coalescing queue.
#[derive(Clone, Debug)]
pub struct CoalescedSample {
    /// The sample data.
    pub data: Vec<u8>,
    /// Instance key for this sample.
    pub key: InstanceKey,
    /// When this sample was enqueued.
    pub enqueued_at: Instant,
    /// Sequence number (for ordering).
    pub sequence: u64,
}

impl CoalescedSample {
    /// Create a new coalesced sample.
    pub fn new(data: Vec<u8>, key: InstanceKey, sequence: u64) -> Self {
        Self {
            data,
            key,
            enqueued_at: Instant::now(),
            sequence,
        }
    }

    /// Get the size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Get the age of this sample.
    pub fn age(&self) -> std::time::Duration {
        self.enqueued_at.elapsed()
    }
}

/// Coalescing queue with "last value wins" semantics.
///
/// For each unique instance key, only the most recent sample is kept.
/// This is ideal for telemetry where only the latest reading matters.
#[derive(Debug)]
pub struct CoalescingQueue {
    /// Map instance_key -> latest sample.
    map: HashMap<InstanceKey, CoalescedSample>,

    /// Insertion order for FIFO drain.
    order: VecDeque<InstanceKey>,

    /// Maximum unique instances.
    max_instances: usize,

    /// Next sequence number.
    next_sequence: u64,

    /// Metrics: samples coalesced (replaced).
    coalesced_count: u64,

    /// Metrics: samples dropped due to capacity.
    dropped_count: u64,

    /// Total bytes currently queued.
    total_bytes: usize,
}

impl CoalescingQueue {
    /// Create a new coalescing queue.
    pub fn new(max_instances: usize) -> Self {
        Self {
            map: HashMap::with_capacity(max_instances),
            order: VecDeque::with_capacity(max_instances),
            max_instances,
            next_sequence: 0,
            coalesced_count: 0,
            dropped_count: 0,
            total_bytes: 0,
        }
    }

    /// Insert a sample, coalescing if key exists.
    ///
    /// Returns `true` if the sample was inserted (possibly replacing an older one).
    /// Returns `false` if the queue is full and no coalescing occurred.
    pub fn insert(&mut self, data: Vec<u8>, key: InstanceKey) -> bool {
        let size = data.len();
        let seq = self.next_sequence;
        self.next_sequence += 1;

        if let Some(existing) = self.map.get_mut(&key) {
            // Coalesce: replace existing
            self.total_bytes -= existing.data.len();
            self.total_bytes += size;
            *existing = CoalescedSample::new(data, key, seq);
            self.coalesced_count += 1;
            true
        } else if self.map.len() < self.max_instances {
            // New instance, have capacity
            self.total_bytes += size;
            self.map
                .insert(key.clone(), CoalescedSample::new(data, key.clone(), seq));
            self.order.push_back(key);
            true
        } else {
            // Full, drop oldest to make room
            if let Some(oldest_key) = self.order.pop_front() {
                if let Some(removed) = self.map.remove(&oldest_key) {
                    self.total_bytes -= removed.data.len();
                    self.dropped_count += 1;
                }
            }
            // Now insert new
            self.total_bytes += size;
            self.map
                .insert(key.clone(), CoalescedSample::new(data, key.clone(), seq));
            self.order.push_back(key);
            true
        }
    }

    /// Insert with size limit check.
    ///
    /// Returns `false` if total bytes would exceed limit.
    pub fn insert_with_limit(&mut self, data: Vec<u8>, key: InstanceKey, max_bytes: usize) -> bool {
        let size = data.len();

        // Check if this would exceed limit (accounting for coalescing)
        let existing_size = self.map.get(&key).map(|s| s.data.len()).unwrap_or(0);
        let new_total = self.total_bytes - existing_size + size;

        if new_total > max_bytes && !self.map.contains_key(&key) {
            // Would exceed and not coalescing
            self.dropped_count += 1;
            return false;
        }

        self.insert(data, key)
    }

    /// Pop the oldest sample (FIFO order by first insertion).
    pub fn pop_front(&mut self) -> Option<CoalescedSample> {
        while let Some(key) = self.order.pop_front() {
            if let Some(sample) = self.map.remove(&key) {
                self.total_bytes -= sample.data.len();
                return Some(sample);
            }
            // Key was in order but not in map (shouldn't happen, but handle gracefully)
        }
        None
    }

    /// Peek at the oldest sample without removing.
    pub fn peek_front(&self) -> Option<&CoalescedSample> {
        for key in &self.order {
            if let Some(sample) = self.map.get(key) {
                return Some(sample);
            }
        }
        None
    }

    /// Get the number of unique instances queued.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get total bytes queued.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Get the maximum instances capacity.
    pub fn capacity(&self) -> usize {
        self.max_instances
    }

    /// Get the number of samples coalesced (replaced).
    pub fn coalesced_count(&self) -> u64 {
        self.coalesced_count
    }

    /// Get the number of samples dropped.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    /// Clear the queue.
    pub fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
        self.total_bytes = 0;
    }

    /// Drain all samples in insertion order.
    pub fn drain(&mut self) -> impl Iterator<Item = CoalescedSample> + '_ {
        std::iter::from_fn(move || self.pop_front())
    }

    /// Get fill ratio (0.0 to 1.0).
    pub fn fill_ratio(&self) -> f32 {
        if self.max_instances == 0 {
            return 1.0;
        }
        self.map.len() as f32 / self.max_instances as f32
    }

    /// Reset metrics counters.
    pub fn reset_metrics(&mut self) {
        self.coalesced_count = 0;
        self.dropped_count = 0;
    }
}

/// Statistics snapshot for the coalescing queue.
#[derive(Clone, Debug, Default)]
pub struct CoalescingStats {
    /// Number of unique instances currently queued.
    pub instances: usize,
    /// Total bytes currently queued.
    pub bytes: usize,
    /// Samples coalesced (replaced).
    pub coalesced: u64,
    /// Samples dropped.
    pub dropped: u64,
    /// Fill ratio.
    pub fill_ratio: f32,
}

impl CoalescingQueue {
    /// Get a statistics snapshot.
    pub fn stats(&self) -> CoalescingStats {
        CoalescingStats {
            instances: self.map.len(),
            bytes: self.total_bytes,
            coalesced: self.coalesced_count,
            dropped: self.dropped_count,
            fill_ratio: self.fill_ratio(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_key_new() {
        let key = InstanceKey::new(123, 456);
        assert_eq!(key.topic_hash, 123);
        assert_eq!(key.key_hash, 456);
    }

    #[test]
    fn test_instance_key_from_topic() {
        let key1 = InstanceKey::from_topic_and_key("sensor/temp", b"sensor_1");
        let key2 = InstanceKey::from_topic_and_key("sensor/temp", b"sensor_1");
        let key3 = InstanceKey::from_topic_and_key("sensor/temp", b"sensor_2");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_instance_key_keyless() {
        let key = InstanceKey::keyless("my_topic");
        assert_eq!(key.key_hash, 0);
    }

    #[test]
    fn test_coalescing_queue_new() {
        let queue = CoalescingQueue::new(100);
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        assert_eq!(queue.capacity(), 100);
    }

    #[test]
    fn test_insert_new_key() {
        let mut queue = CoalescingQueue::new(10);
        let key = InstanceKey::new(1, 1);

        assert!(queue.insert(vec![1, 2, 3], key.clone()));
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.total_bytes(), 3);
    }

    #[test]
    fn test_insert_coalesce() {
        let mut queue = CoalescingQueue::new(10);
        let key = InstanceKey::new(1, 1);

        queue.insert(vec![1, 2, 3], key.clone());
        queue.insert(vec![4, 5, 6, 7], key.clone()); // Replace

        assert_eq!(queue.len(), 1); // Still 1 instance
        assert_eq!(queue.total_bytes(), 4); // New size
        assert_eq!(queue.coalesced_count(), 1);

        let sample = queue.pop_front().expect("should have sample");
        assert_eq!(sample.data, vec![4, 5, 6, 7]);
    }

    #[test]
    fn test_insert_multiple_keys() {
        let mut queue = CoalescingQueue::new(10);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        queue.insert(vec![2], InstanceKey::new(1, 2));
        queue.insert(vec![3], InstanceKey::new(2, 1));

        assert_eq!(queue.len(), 3);
        assert_eq!(queue.total_bytes(), 3);
    }

    #[test]
    fn test_fifo_order() {
        let mut queue = CoalescingQueue::new(10);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        queue.insert(vec![2], InstanceKey::new(2, 2));
        queue.insert(vec![3], InstanceKey::new(3, 3));

        assert_eq!(queue.pop_front().expect("s1").data, vec![1]);
        assert_eq!(queue.pop_front().expect("s2").data, vec![2]);
        assert_eq!(queue.pop_front().expect("s3").data, vec![3]);
        assert!(queue.pop_front().is_none());
    }

    #[test]
    fn test_coalesce_preserves_order() {
        let mut queue = CoalescingQueue::new(10);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        queue.insert(vec![2], InstanceKey::new(2, 2));
        queue.insert(vec![10], InstanceKey::new(1, 1)); // Coalesce first

        // Order should still be: key(1,1), key(2,2)
        let s1 = queue.pop_front().expect("s1");
        assert_eq!(s1.data, vec![10]); // Updated value
        assert_eq!(s1.key, InstanceKey::new(1, 1));

        let s2 = queue.pop_front().expect("s2");
        assert_eq!(s2.data, vec![2]);
    }

    #[test]
    fn test_capacity_drop_oldest() {
        let mut queue = CoalescingQueue::new(2);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        queue.insert(vec![2], InstanceKey::new(2, 2));
        queue.insert(vec![3], InstanceKey::new(3, 3)); // Should drop key(1,1)

        assert_eq!(queue.len(), 2);
        assert_eq!(queue.dropped_count(), 1);

        let s1 = queue.pop_front().expect("s1");
        assert_eq!(s1.key, InstanceKey::new(2, 2)); // First was dropped
    }

    #[test]
    fn test_insert_with_limit() {
        let mut queue = CoalescingQueue::new(100);

        // Insert 50 bytes
        assert!(queue.insert_with_limit(vec![0; 50], InstanceKey::new(1, 1), 100));
        assert_eq!(queue.total_bytes(), 50);

        // Insert 30 more (total 80, within limit)
        assert!(queue.insert_with_limit(vec![0; 30], InstanceKey::new(2, 2), 100));
        assert_eq!(queue.total_bytes(), 80);

        // Try to insert 30 more (would exceed 100)
        assert!(!queue.insert_with_limit(vec![0; 30], InstanceKey::new(3, 3), 100));
        assert_eq!(queue.dropped_count(), 1);

        // But coalescing should still work
        assert!(queue.insert_with_limit(vec![0; 60], InstanceKey::new(1, 1), 100));
        assert_eq!(queue.total_bytes(), 90); // 60 + 30
    }

    #[test]
    fn test_peek_front() {
        let mut queue = CoalescingQueue::new(10);

        assert!(queue.peek_front().is_none());

        queue.insert(vec![1, 2, 3], InstanceKey::new(1, 1));

        let peeked = queue.peek_front().expect("should peek");
        assert_eq!(peeked.data, vec![1, 2, 3]);

        // Should still be there
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_clear() {
        let mut queue = CoalescingQueue::new(10);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        queue.insert(vec![2], InstanceKey::new(2, 2));

        queue.clear();

        assert!(queue.is_empty());
        assert_eq!(queue.total_bytes(), 0);
    }

    #[test]
    fn test_drain() {
        let mut queue = CoalescingQueue::new(10);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        queue.insert(vec![2], InstanceKey::new(2, 2));
        queue.insert(vec![3], InstanceKey::new(3, 3));

        let samples: Vec<_> = queue.drain().collect();
        assert_eq!(samples.len(), 3);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_fill_ratio() {
        let mut queue = CoalescingQueue::new(4);

        assert!((queue.fill_ratio() - 0.0).abs() < 0.01);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        assert!((queue.fill_ratio() - 0.25).abs() < 0.01);

        queue.insert(vec![2], InstanceKey::new(2, 2));
        assert!((queue.fill_ratio() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_stats() {
        let mut queue = CoalescingQueue::new(10);

        queue.insert(vec![1, 2, 3], InstanceKey::new(1, 1));
        queue.insert(vec![4, 5], InstanceKey::new(2, 2));
        queue.insert(vec![6, 7, 8, 9], InstanceKey::new(1, 1)); // Coalesce

        let stats = queue.stats();
        assert_eq!(stats.instances, 2);
        assert_eq!(stats.bytes, 6); // 4 + 2
        assert_eq!(stats.coalesced, 1);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn test_reset_metrics() {
        let mut queue = CoalescingQueue::new(2);

        queue.insert(vec![1], InstanceKey::new(1, 1));
        queue.insert(vec![2], InstanceKey::new(1, 1)); // Coalesce
        queue.insert(vec![3], InstanceKey::new(2, 2));
        queue.insert(vec![4], InstanceKey::new(3, 3)); // Drop

        assert_eq!(queue.coalesced_count(), 1);
        assert_eq!(queue.dropped_count(), 1);

        queue.reset_metrics();

        assert_eq!(queue.coalesced_count(), 0);
        assert_eq!(queue.dropped_count(), 0);
    }

    #[test]
    fn test_coalesced_sample_age() {
        let sample = CoalescedSample::new(vec![1, 2, 3], InstanceKey::new(1, 1), 0);

        std::thread::sleep(std::time::Duration::from_millis(10));

        assert!(sample.age().as_millis() >= 10);
    }

    #[test]
    fn test_coalesced_sample_size() {
        let sample = CoalescedSample::new(vec![1, 2, 3, 4, 5], InstanceKey::new(1, 1), 0);
        assert_eq!(sample.size(), 5);
    }
}

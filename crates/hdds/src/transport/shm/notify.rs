// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Topic notification system using futex-based buckets.
//!
//! Multiple writers can notify readers about new data availability.
//! Uses a bucketed approach to reduce contention when many writers
//! are active simultaneously.
//!
//! # Design
//!
//! ```text
//! TopicNotify (16KB shared memory segment)
//! +----------------------------------------+
//! | NotifyBucket[0]   (64 bytes, aligned)  |
//! | NotifyBucket[1]   (64 bytes, aligned)  |
//! | ...                                    |
//! | NotifyBucket[255] (64 bytes, aligned)  |
//! +----------------------------------------+
//! ```
//!
//! Writers increment their assigned bucket and wake waiters.
//! Readers snapshot the bucket value before waiting to avoid lost wakes.

use super::futex::{futex_wait, futex_wake_all};
use super::segment::ShmSegment;
use super::{Result, NOTIFY_BUCKET_COUNT};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// Notification bucket (cache-line aligned to prevent false sharing).
///
/// Each writer is assigned a bucket based on hash of its GUID.
/// This distributes contention across multiple cache lines.
#[repr(C, align(64))]
pub struct NotifyBucket {
    /// Notification counter (incremented on each publish)
    pub val: AtomicU32,
    /// Padding to fill cache line
    _pad: [u8; 60],
}

impl NotifyBucket {
    /// Create a new zeroed bucket
    #[must_use]
    pub const fn new() -> Self {
        Self {
            val: AtomicU32::new(0),
            _pad: [0u8; 60],
        }
    }

    /// Increment the notification counter and wake waiters
    #[inline]
    pub fn notify(&self) {
        self.val.fetch_add(1, Ordering::Release);
        futex_wake_all(&self.val);
    }

    /// Get current counter value (for snapshot before wait)
    #[inline]
    pub fn snapshot(&self) -> u32 {
        self.val.load(Ordering::Acquire)
    }

    /// Wait until counter changes from snapshot value
    ///
    /// Uses double-check pattern to avoid lost wakes:
    /// 1. Poll data
    /// 2. Snapshot notify counter
    /// 3. Re-poll data (catches race)
    /// 4. If still no data, wait on futex
    #[inline]
    pub fn wait(&self, snapshot: u32, timeout: Option<Duration>) -> i32 {
        futex_wait(&self.val, snapshot, timeout)
    }
}

impl Default for NotifyBucket {
    fn default() -> Self {
        Self::new()
    }
}

/// Topic-level notification coordinator.
///
/// Manages a shared memory segment containing notification buckets.
/// Each topic has one TopicNotify that all writers/readers for that
/// topic share.
pub struct TopicNotify {
    /// Underlying shared memory segment
    segment: ShmSegment,
}

impl TopicNotify {
    /// Size of the notification segment (256 buckets x 64 bytes = 16KB)
    pub const SEGMENT_SIZE: usize = NOTIFY_BUCKET_COUNT * std::mem::size_of::<NotifyBucket>();

    /// Create or open a topic notification segment.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name (e.g., `/hdds_notify_d0_topic_foo`)
    /// * `create` - If true, create segment; if false, open existing
    pub fn new(name: &str, create: bool) -> Result<Self> {
        let segment = if create {
            ShmSegment::create(name, Self::SEGMENT_SIZE)?
        } else {
            ShmSegment::open(name, Self::SEGMENT_SIZE)?
        };

        Ok(Self { segment })
    }

    /// Get pointer to the bucket array
    fn buckets_ptr(&self) -> *const NotifyBucket {
        self.segment.as_ptr() as *const NotifyBucket
    }

    /// Get a reference to a specific bucket
    ///
    /// # Safety
    ///
    /// Bucket index must be < NOTIFY_BUCKET_COUNT
    #[inline]
    pub fn bucket(&self, index: usize) -> &NotifyBucket {
        debug_assert!(index < NOTIFY_BUCKET_COUNT);
        // SAFETY: We own the segment and index is bounds-checked
        unsafe { &*self.buckets_ptr().add(index) }
    }

    /// Compute bucket index for a writer GUID
    ///
    /// Uses FNV-1a hash of the GUID to distribute writers across buckets.
    #[must_use]
    pub fn bucket_for_guid(guid: &[u8; 16]) -> usize {
        let mut hash: u32 = 2_166_136_261;
        for byte in guid {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(16_777_619);
        }
        (hash as usize) % NOTIFY_BUCKET_COUNT
    }

    /// Notify on a specific bucket
    #[inline]
    pub fn notify(&self, bucket_index: usize) {
        self.bucket(bucket_index).notify();
    }

    /// Wait on a specific bucket
    #[inline]
    pub fn wait(&self, bucket_index: usize, snapshot: u32, timeout: Option<Duration>) -> i32 {
        self.bucket(bucket_index).wait(snapshot, timeout)
    }

    /// Get segment name for a topic
    #[must_use]
    pub fn segment_name(domain_id: u32, topic_name: &str) -> String {
        // Sanitize topic name for POSIX shm naming
        let safe_topic: String = topic_name
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        format!("/hdds_notify_d{domain_id}_{safe_topic}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_bucket_alignment() {
        assert_eq!(std::mem::align_of::<NotifyBucket>(), 64);
        assert_eq!(std::mem::size_of::<NotifyBucket>(), 64);
    }

    #[test]
    fn test_notify_bucket_increment() {
        let bucket = NotifyBucket::new();
        assert_eq!(bucket.snapshot(), 0);

        // Note: notify() calls futex_wake which is fine in tests
        bucket.val.fetch_add(1, Ordering::Release);
        assert_eq!(bucket.snapshot(), 1);
    }

    #[test]
    fn test_bucket_for_guid_distribution() {
        // Test that different GUIDs get distributed across buckets
        let mut buckets_used = std::collections::HashSet::new();

        for i in 0u8..100 {
            let mut guid = [0u8; 16];
            guid[0] = i;
            let bucket = TopicNotify::bucket_for_guid(&guid);
            assert!(bucket < NOTIFY_BUCKET_COUNT);
            buckets_used.insert(bucket);
        }

        // Should use at least 50 different buckets for 100 GUIDs
        assert!(buckets_used.len() > 50, "Poor bucket distribution");
    }

    #[test]
    fn test_segment_name_sanitization() {
        let name = TopicNotify::segment_name(0, "my/topic/name");
        assert_eq!(name, "/hdds_notify_d0_my_topic_name");

        let name2 = TopicNotify::segment_name(42, "Hello World!");
        assert_eq!(name2, "/hdds_notify_d42_Hello_World_");
    }

    #[test]
    fn test_segment_size() {
        assert_eq!(TopicNotify::SEGMENT_SIZE, 256 * 64);
        assert_eq!(TopicNotify::SEGMENT_SIZE, 16384); // 16KB
    }
}

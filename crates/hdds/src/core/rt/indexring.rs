// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Single-producer single-consumer (SPSC) ring buffer for index entries.
//!
//! Lock-free ring buffer using atomic head/tail pointers. Each entry contains
//! a sequence number, slab handle, length, and flags.
//!
//! # Performance
//!
//! - push: < 10 ns (p99)
//! - pop: < 5 ns (p99)

use super::slabpool::SlabHandle;
use std::sync::atomic::{AtomicUsize, Ordering};

/// COMMITTED flag (bit 0): entry is fully written and ready to pop
const COMMITTED_FLAG: u8 = 0x01;

/// Entry in a SPSC ring (sequence + slab handle + length + flags + timestamp)
#[derive(Debug, Clone, Copy)]
pub struct IndexEntry {
    pub seq: u32,           // sequence number
    pub handle: SlabHandle, // slab handle for payload
    pub len: u32,           // bytes written
    pub flags: u8,          // COMMITTED flag (bit 0)
    pub timestamp_ns: u64,  // write timestamp for latency measurement
}

impl IndexEntry {
    /// Create new entry with uncommitted state
    pub fn new(seq: u32, handle: SlabHandle, len: u32) -> Self {
        Self {
            seq,
            handle,
            len,
            flags: 0, // Not committed yet
            timestamp_ns: 0,
        }
    }

    /// Create entry with timestamp
    pub fn with_timestamp(seq: u32, handle: SlabHandle, len: u32, timestamp_ns: u64) -> Self {
        Self {
            seq,
            handle,
            len,
            flags: 0,
            timestamp_ns,
        }
    }

    /// Check if entry is committed (ready to pop)
    pub fn is_committed(self) -> bool {
        (self.flags & COMMITTED_FLAG) != 0
    }

    /// Mark entry as committed
    fn mark_committed(&mut self) {
        self.flags |= COMMITTED_FLAG;
    }
}

impl Default for IndexEntry {
    fn default() -> Self {
        Self {
            seq: 0,
            handle: SlabHandle(0),
            len: 0,
            flags: 0,
            timestamp_ns: 0,
        }
    }
}

use std::cell::UnsafeCell;

/// Single-producer, single-consumer atomic ring buffer
///
/// Protocol:
/// - Producer: push() advances head, marks entry COMMITTED
/// - Consumer: pop() checks COMMITTED flag, advances tail
/// - Full: (head + 1) % capacity == tail
/// - Empty: head == tail
///
/// SAFETY:
/// - SPSC constraint: only ONE thread calls push(), ONE calls pop()
/// - Acquire/Release ordering ensures proper sync between producer/consumer
/// - Capacity is power of 2 (mask-based wrapping, no modulo)
/// - Uses UnsafeCell for interior mutability with atomic protection
pub struct IndexRing {
    // Fixed-size ring buffer (power of 2 capacity)
    entries: UnsafeCell<Vec<IndexEntry>>,
    #[allow(dead_code)]
    capacity: usize,
    capacity_mask: usize,

    // Head pointer (producer advances)
    head: AtomicUsize,

    // Tail pointer (consumer advances)
    tail: AtomicUsize,
}

// SAFETY: IndexRing is Send + Sync because:
// - entries protected by atomic head/tail (SPSC protocol)
// - only one thread writes (producer), one thread reads (consumer)
// - atomics ensure proper synchronization
unsafe impl Send for IndexRing {}
unsafe impl Sync for IndexRing {}

impl IndexRing {
    /// Create new index ring with capacity (rounded up to next power of 2)
    ///
    /// # Panics
    /// Panics if capacity is 0.
    pub fn with_capacity(n: usize) -> Self {
        assert!(n > 0, "Capacity must be > 0");

        // Round up to next power of 2 for efficient masking
        let capacity = n.next_power_of_two();
        let capacity_mask = capacity - 1;

        let entries = vec![IndexEntry::default(); capacity];

        Self {
            entries: UnsafeCell::new(entries),
            capacity,
            capacity_mask,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
        }
    }

    /// Push entry (non-blocking, returns false if full)
    ///
    /// SAFETY:
    /// - Only ONE thread (producer) may call this function
    /// - Acquire ordering on tail ensures we see consumer's updates
    /// - Release ordering on head ensures consumer sees our writes
    /// - UnsafeCell: safe because SPSC protocol ensures no aliasing
    ///
    /// # Returns
    /// * `true` if entry pushed successfully.
    /// * `false` if ring is full (non-blocking).
    ///
    /// # Performance
    /// Target: < 50 ns (single atomic store + write)
    ///
    /// # Latency
    /// - **p50:** 7.20 ns
    /// - **p99:** 7.92 ns (`SLA target < 50 ns`)
    /// - **p999:** 8.29 ns
    ///
    /// Measured in `bench_indexring_push` (see `benches/runtime.rs`).
    /// Last measured on 2025-10-21 (Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz).
    pub fn push(&self, mut entry: IndexEntry) -> bool {
        // 1. Load current head (Relaxed: no sync needed, we're the only producer)
        let head = self.head.load(Ordering::Relaxed);
        let next_head = (head + 1) & self.capacity_mask;

        // 2. Check if ring full (Acquire: sync with consumer's tail advance)
        let tail = self.tail.load(Ordering::Acquire);
        if next_head == tail {
            return false; // Full, non-blocking
        }

        // 3. Write entry at head (no atomics needed: SPSC, no contention)
        entry.mark_committed(); // Mark as COMMITTED before advancing head

        // SAFETY: SPSC protocol ensures only producer writes to head position
        unsafe {
            let entries = &mut *self.entries.get();
            entries[head] = entry;
        }

        // 4. Advance head (Release: sync with consumer, entry now visible)
        self.head.store(next_head, Ordering::Release);

        true // Success
    }

    /// Pop entry (non-blocking, returns None if empty)
    ///
    /// SAFETY:
    /// - Only ONE thread (consumer) may call this function
    /// - Acquire ordering on head ensures we see producer's updates
    /// - Release ordering on tail ensures producer sees freed slot
    /// - UnsafeCell: safe because SPSC protocol ensures no aliasing
    ///
    /// # Returns
    /// * `Some(entry)` if entry available and committed.
    /// * `None` if ring empty or entry not yet committed.
    ///
    /// # Performance
    /// Target: < 50 ns (single atomic load + check)
    ///
    /// # Latency
    /// - **p50:** 2.83 ns
    /// - **p99:** 3.38 ns (`SLA target < 50 ns`)
    /// - **p999:** 3.68 ns
    ///
    /// Measured in `bench_indexring_pop` (see `benches/runtime.rs`).
    /// Last measured on 2025-10-21 (Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz).
    pub fn pop(&self) -> Option<IndexEntry> {
        // 1. Load current tail (Relaxed: no sync needed, we're the only consumer)
        let tail = self.tail.load(Ordering::Relaxed);

        // 2. Check if ring empty (Acquire: sync with producer's head advance)
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None; // Empty
        }

        // 3. Read entry and check if COMMITTED
        // SAFETY: SPSC protocol ensures only consumer reads from tail position
        let entry = unsafe {
            let entries = &*self.entries.get();
            entries[tail]
        };

        if !entry.is_committed() {
            return None; // Not yet committed (half-write detected, rare)
        }

        // 4. Advance tail (Release: sync with producer, slot now free)
        let next_tail = (tail + 1) & self.capacity_mask;
        self.tail.store(next_tail, Ordering::Release);

        Some(entry)
    }

    /// Get current number of entries in ring (approximate, for debugging)
    ///
    /// Note: This is racy in multi-threaded context but safe to call.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        (head.wrapping_sub(tail)) & self.capacity_mask
    }

    /// Check if ring is empty (approximate, for debugging)
    pub fn is_empty(&self) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head == tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn test_push_pop_basic() {
        let ring = IndexRing::with_capacity(16);

        let entry = IndexEntry::new(1, SlabHandle(42), 100);
        assert!(ring.push(entry));

        let popped = ring.pop().expect("Pop should succeed after push");
        assert_eq!(popped.seq, 1);
        assert_eq!(popped.handle, SlabHandle(42));
        assert_eq!(popped.len, 100);
        assert!(popped.is_committed());
    }

    #[test]
    fn test_empty_ring() {
        let ring = IndexRing::with_capacity(8);
        assert!(ring.is_empty());
        assert!(ring.pop().is_none());
    }

    #[test]
    fn test_full_ring() {
        let ring = IndexRing::with_capacity(4); // Capacity rounds to 4

        // Push 3 entries (capacity - 1, because one slot reserved)
        for i in 0..3 {
            let entry = IndexEntry::new(i, SlabHandle(i), 100);
            assert!(ring.push(entry), "Failed to push entry {}", i);
        }

        // Next push should fail (ring full)
        let entry = IndexEntry::new(99, SlabHandle(99), 100);
        assert!(!ring.push(entry), "Should fail when ring full");
    }

    #[test]
    fn test_push_pop_sequence() {
        let ring = IndexRing::with_capacity(8);

        // Push 5 entries
        for i in 0..5 {
            let entry = IndexEntry::new(i, SlabHandle(i), i * 10);
            assert!(ring.push(entry));
        }

        // Pop all 5 entries in order
        for i in 0..5 {
            let popped = ring.pop().expect("Pop should succeed for pushed entries");
            assert_eq!(popped.seq, i);
            assert_eq!(popped.handle, SlabHandle(i));
        }

        // Ring should be empty now
        assert!(ring.pop().is_none());
        assert!(ring.is_empty());
    }

    #[test]
    fn test_wraparound() {
        let ring = IndexRing::with_capacity(4); // Capacity = 4

        // Fill ring (3 entries, since 1 slot reserved)
        for i in 0..3 {
            assert!(ring.push(IndexEntry::new(i, SlabHandle(i), 100)));
        }

        // Pop all
        for _ in 0..3 {
            ring.pop().expect("Pop should succeed for pushed entries");
        }

        // Push again (should wrap around)
        for i in 10..13 {
            assert!(ring.push(IndexEntry::new(i, SlabHandle(i), 100)));
        }

        // Pop again
        for i in 10..13 {
            let popped = ring.pop().expect("Pop should succeed for pushed entries");
            assert_eq!(popped.seq, i);
        }
    }

    #[test]
    fn test_stress_push_pop() {
        let ring = IndexRing::with_capacity(256);

        // Push and pop 10,000 entries in sequence
        for i in 0..10000 {
            let seq = u32::try_from(i).expect("test sequence fits in u32");
            let handle = SlabHandle(seq);
            let len = u32::try_from(i * 10).expect("test payload length fits in u32");
            let entry = IndexEntry::new(seq, handle, len);

            // Push (may block if ring fills up, but we pop immediately)
            while !ring.push(entry) {
                // Spin until space available (shouldn't happen with immediate pop)
            }

            let popped = ring.pop().expect("Pop should succeed after push");
            assert_eq!(popped.seq, seq);
        }
    }

    #[test]
    fn test_committed_flag() {
        let mut entry = IndexEntry::new(1, SlabHandle(1), 100);
        assert!(!entry.is_committed());

        entry.mark_committed();
        assert!(entry.is_committed());
    }

    #[test]
    fn test_capacity_power_of_two() {
        let ring = IndexRing::with_capacity(10); // Should round up to 16
        assert_eq!(ring.capacity, 16);
        assert_eq!(ring.capacity_mask, 15);

        let ring2 = IndexRing::with_capacity(8); // Already power of 2
        assert_eq!(ring2.capacity, 8);
    }
}

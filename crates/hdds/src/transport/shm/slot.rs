// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared memory slot structures with cache-line alignment.
//!
//! All structures are aligned to 64 bytes to prevent false sharing between
//! CPU cores, which is critical for performance in multi-core scenarios.
//!
//! # Memory Ordering Strategy
//!
//! This module uses Acquire/Release ordering to establish happens-before relationships:
//!
//! - **Release** on writes (`commit`, `publish_head`): Ensures all payload writes
//!   are visible to other threads before the sequence number becomes visible.
//!   Acts as a "publish" barrier - everything written before Release is guaranteed
//!   to be visible to any thread that does an Acquire load of the same location.
//!
//! - **Acquire** on reads (`is_ready`, `get_head`, `get_seq`): Ensures we see all
//!   writes that happened before the Release store. Prevents the CPU from
//!   reordering subsequent reads before the atomic load.
//!
//! - **Relaxed** on `mark_writing`: Safe because the odd sequence value itself
//!   signals "don't trust the payload yet" - readers will spin until commit().
//!
//! # ABA Prevention
//!
//! The 64-bit sequence number prevents ABA problems:
//! - Each message gets a unique, monotonically increasing sequence number
//! - With 2^63 usable sequences (MSB reserved for in-progress flag), at 1 billion
//!   messages/second, wraparound takes ~292 years
//! - Readers compare exact sequence, not just "changed" - a slot with seq=5 won't
//!   be confused with a later seq=5 because head advancement prevents re-reading
//!
//! # Torn Read Detection
//!
//! The LSB flag protocol detects torn reads without locks:
//! 1. Writer sets `seq = (msg_seq << 1) | 1` (odd = writing)
//! 2. Writer copies payload
//! 3. Writer sets `seq = msg_seq << 1` (even = committed)
//!
//! Reader checks: `seq == expected << 1` - if odd or wrong sequence, payload is unsafe.
//!
//! # Sequence Wraparound
//!
//! The 64-bit sequence space is practically infinite for messaging:
//! - At 10M msgs/sec: ~58,000 years to wrap
//! - The ring buffer uses `seq % capacity` for slot indexing
//! - Readers track their own cursor and detect overruns via head comparison

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Default payload size per slot (4KB)
pub const SLOT_PAYLOAD_SIZE: usize = 4096;

/// Shared memory slot for a single message.
///
/// # Memory Layout (cache-aligned)
///
/// ```text
/// Offset  Size   Field
/// 0       8      seq (AtomicU64) - commit marker
/// 8       4      len (AtomicU32) - payload length
/// 12      4      _pad
/// 16      4080   payload (up to SLOT_PAYLOAD_SIZE)
/// ```
///
/// # Sequence Number Encoding
///
/// The `seq` field uses the LSB as a write-in-progress flag:
/// - `seq = msg_seq << 1` -> committed (even)
/// - `seq = (msg_seq << 1) | 1` -> writing in progress (odd)
///
/// This allows readers to detect torn reads without locks.
#[repr(C, align(64))]
pub struct ShmSlot {
    /// Commit marker: `msg_seq << 1`, LSB=1 means write in progress
    pub seq: AtomicU64,
    /// Payload length in bytes
    pub len: AtomicU32,
    /// Padding for alignment
    _pad: u32,
    /// Payload data (UnsafeCell for interior mutability)
    pub payload: UnsafeCell<[u8; SLOT_PAYLOAD_SIZE]>,
}

// SAFETY: ShmSlot is designed for concurrent access across processes.
// The seq field provides synchronization via atomic operations.
// Writers use seq|1 to mark in-progress, readers check for even seq.
unsafe impl Send for ShmSlot {}
unsafe impl Sync for ShmSlot {}

impl ShmSlot {
    /// Create a new zeroed slot
    #[must_use]
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            len: AtomicU32::new(0),
            _pad: 0,
            payload: UnsafeCell::new([0u8; SLOT_PAYLOAD_SIZE]),
        }
    }

    /// Check if this slot is ready to read for the given expected sequence
    ///
    /// Returns `true` if `seq == expected << 1` (committed, not in-progress)
    #[inline]
    pub fn is_ready(&self, expected_msg_seq: u64) -> bool {
        // Acquire ordering: synchronizes with the Release in commit().
        // This ensures we see all payload writes that happened before commit().
        // Without Acquire, CPU could speculatively read stale payload data.
        let seq = self.seq.load(Ordering::Acquire);
        // Exact match required: prevents ABA (wrong sequence) and torn reads (odd = writing)
        seq == expected_msg_seq << 1
    }

    /// Check if a write is currently in progress
    #[inline]
    pub fn is_writing(&self) -> bool {
        // Acquire ordering: ensures we don't read payload before checking the flag.
        // LSB=1 means writer is mid-copy - payload content is undefined.
        self.seq.load(Ordering::Acquire) & 1 == 1
    }

    /// Mark slot as write-in-progress for the given message sequence
    #[inline]
    pub fn mark_writing(&self, msg_seq: u64) {
        // Relaxed ordering is sufficient here because:
        // 1. The odd value (LSB=1) tells readers "don't trust payload" regardless of ordering
        // 2. Readers will spin/retry until they see the committed (even) value
        // 3. No happens-before relationship needed - we're just raising a "busy" flag
        // The actual synchronization happens in commit() with Release ordering.
        self.seq.store((msg_seq << 1) | 1, Ordering::Relaxed);
    }

    /// Commit the slot (mark as ready for reading)
    #[inline]
    pub fn commit(&self, msg_seq: u64) {
        // Release ordering: critical for correctness!
        // Ensures all payload writes are visible BEFORE seq becomes even.
        // Pairs with Acquire in is_ready()/get_seq() to form happens-before.
        // Without Release, readers could see committed seq but stale payload.
        self.seq.store(msg_seq << 1, Ordering::Release);
    }

    /// Get current sequence marker (for corruption detection)
    #[inline]
    pub fn get_seq(&self) -> u64 {
        // Acquire ordering: synchronizes with Release in commit().
        // Used for double-check pattern: read seq, copy payload, read seq again.
        // If seq changed, payload may be torn - discard and retry.
        self.seq.load(Ordering::Acquire)
    }
}

impl Default for ShmSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// Control block for the shared memory ring buffer.
///
/// Located at the beginning of the shared memory segment.
/// Contains the head pointer and ring metadata.
#[repr(C, align(64))]
pub struct ShmControl {
    /// Head pointer: next sequence number to be written
    /// Readers use this to detect overruns
    pub head: AtomicU64,
    /// Ring capacity (power of 2)
    pub capacity: u32,
    /// Slot payload size
    pub slot_size: u32,
    /// Magic number for validation
    pub magic: u32,
    /// Version number
    pub version: u32,
    /// Padding to fill cache line
    _pad: [u8; 40],
}

impl ShmControl {
    /// Magic number to identify valid SHM segments
    pub const MAGIC: u32 = 0x4844_4453; // "HDDS"

    /// Current version
    pub const VERSION: u32 = 1;

    /// Create a new control block
    #[must_use]
    pub const fn new(capacity: u32, slot_size: u32) -> Self {
        Self {
            head: AtomicU64::new(0),
            capacity,
            slot_size,
            magic: Self::MAGIC,
            version: Self::VERSION,
            _pad: [0u8; 40],
        }
    }

    /// Validate the control block
    pub fn validate(&self) -> bool {
        self.magic == Self::MAGIC && self.version == Self::VERSION
    }

    /// Get the current head (next write position)
    #[inline]
    pub fn get_head(&self) -> u64 {
        // Acquire ordering: synchronizes with Release in publish_head().
        // Readers use head to detect overruns: if reader_cursor < head - capacity,
        // the slot has been overwritten and data is lost (ring buffer wraparound).
        self.head.load(Ordering::Acquire)
    }

    /// Publish new head position
    #[inline]
    pub fn publish_head(&self, new_head: u64) {
        // Release ordering: ensures slot commit is visible before head advances.
        // Sequence of operations: commit(slot) -> publish_head(new_head)
        // Readers see: get_head() -> is_ready(slot) - ordering is preserved.
        self.head.store(new_head, Ordering::Release);
    }
}

impl Default for ShmControl {
    fn default() -> Self {
        Self::new(
            super::DEFAULT_RING_CAPACITY as u32,
            SLOT_PAYLOAD_SIZE as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_alignment() {
        assert_eq!(std::mem::align_of::<ShmSlot>(), 64);
    }

    #[test]
    fn test_control_alignment() {
        assert_eq!(std::mem::align_of::<ShmControl>(), 64);
    }

    #[test]
    fn test_control_size() {
        // Control block should be exactly one cache line
        assert_eq!(std::mem::size_of::<ShmControl>(), 64);
    }

    #[test]
    fn test_slot_sequence_encoding() {
        let slot = ShmSlot::new();

        // Mark writing for msg_seq=5
        slot.mark_writing(5);
        assert!(slot.is_writing());
        assert!(!slot.is_ready(5));

        // Commit
        slot.commit(5);
        assert!(!slot.is_writing());
        assert!(slot.is_ready(5));
        assert!(!slot.is_ready(4)); // Wrong sequence
        assert!(!slot.is_ready(6)); // Wrong sequence
    }

    #[test]
    fn test_control_validation() {
        let ctrl = ShmControl::new(256, 4096);
        assert!(ctrl.validate());
    }

    #[test]
    fn test_control_head_operations() {
        let ctrl = ShmControl::new(256, 4096);
        assert_eq!(ctrl.get_head(), 0);

        ctrl.publish_head(42);
        assert_eq!(ctrl.get_head(), 42);
    }
}

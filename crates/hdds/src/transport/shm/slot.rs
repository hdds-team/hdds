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
//! - **Acquire** on reads (`get_head`, and the first `seq` load in
//!   `ShmRingReader::try_pop`): Ensures we see all writes that happened before
//!   the Release store. Prevents the CPU from reordering subsequent reads
//!   before the atomic load.
//!
//! - **Relaxed store plus a Release fence** on `mark_writing`: the odd value
//!   signals "don't trust the payload yet", but only if it becomes visible
//!   BEFORE the payload writes it guards, which the Relaxed store alone does
//!   not give. The fence is the writer half of the seqlock barrier pair; the
//!   reader half is an Acquire fence before the re-check in
//!   `ShmRingReader::try_pop`. Note that an Acquire LOAD would not do there:
//!   it orders what follows it, not the payload copy that precedes it.
//!
//! # Who implements the protocol
//!
//! The WRITER half is here, in `mark_writing` and `commit`, and `ring.rs` calls
//! them. There is one copy on purpose: a seqlock barrier fix must be written
//! once, not by hand in two places.
//!
//! The READER half is NOT here. `ShmRingReader::try_pop` is the only production
//! reader, and it deliberately does not go through `is_ready`, `is_writing` or
//! `get_seq` -- see the note on those methods before reaching for one.
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

/// Bytes of framed RTPS packet one slot can hold.
///
/// # Why 12288 and not "4 KB fits most DDS samples"
///
/// The shared-memory data path pushes the COMPLETE framed RTPS packet, and
/// it must never silently hand a packet back to UDP because it did not fit:
/// a fallback nobody can see is the exact defect this transport exists to
/// close. So the slot is sized from the packet the writer can actually
/// produce, not from a round number.
///
/// RTPS emits a single DATA submessage up to
/// `protocol::builder::DEFAULT_MAX_UNFRAGMENTED_SIZE` (8192) bytes of user
/// payload, and only fragments past it -- into
/// `DEFAULT_FRAGMENT_SIZE` (1024) byte pieces, which fit trivially. So the
/// band a slot must cover is 0..=8192 of payload, PLUS framing: the 20 byte
/// RTPS header, the INFO_TS submessage, the DATA submessage header, and the
/// inline QoS. Inline QoS is NOT a constant -- it carries the topic name --
/// so the framing cost is measured, not assumed
/// (`transport::shm::policy::tests::slot_capacity_frontier_is_measured_not_guessed`
/// walks the real builder over the whole band and prints the frontier).
///
/// 12288 = 8192 + 4096: the maximum unfragmented payload plus a 4 KB
/// framing budget. Measured framing for an ordinary topic name is under 100
/// bytes, so the budget is spent almost entirely on topic-name length: a
/// topic name would have to run to roughly 4 KB before a single DATA could
/// overflow a slot. `slot_holds_every_unfragmented_data_packet` asserts the
/// whole band fits and fails if that ever stops being true.
///
/// Cost is a lazily created, sparsely paged tmpfs mapping: the segment is
/// `DEFAULT_RING_CAPACITY` slots, but only pages actually written are
/// resident, and no segment is created at all until a writer has a
/// co-located reader to serve.
pub const SLOT_PAYLOAD_SIZE: usize = SLOT_PAYLOAD_SIZE_U32 as usize;

/// `SLOT_PAYLOAD_SIZE` in the width the control block stores it
/// (`ShmControl::slot_size` is a u32 in the segment). Defined first, in the
/// segment's type, so the `usize` the rest of the code sizes buffers with is
/// the widening and nothing is ever narrowed to write the geometry.
pub(crate) const SLOT_PAYLOAD_SIZE_U32: u32 = 12288;

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
    ///
    /// # Not the ring reader's path
    ///
    /// `ShmRingReader::try_pop` does not call this, and reading it as "the
    /// reader's readiness check" is wrong. `try_pop` needs the sequence VALUE,
    /// not a verdict: when the slot does not hold the message it wants, it
    /// compares `seq >> 1` against that message to tell "the writer has not got
    /// here yet" from "the writer has already recycled this slot and the
    /// message is gone", and it reuses the same value for the torn-read
    /// re-check. A bool discards both. This accessor is for callers that only
    /// want the verdict.
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
        // The store itself is Relaxed, but ordering DOES matter here. The odd
        // marker only tells a reader "do not trust the payload" if it becomes visible
        // BEFORE the payload writes it is meant to guard. Relaxed alone lets
        // those writes be hoisted above it, which lands new bytes in a slot
        // whose `seq` still reads as the previous committed message; a reader
        // copying that previous message then sees no change on its re-check
        // and accepts torn data.
        //
        // The Release fence after the store is what actually orders this
        // store before the caller's payload writes. It is the writer half of
        // the seqlock barrier pair; the reader half is an Acquire fence
        // before the re-check (see `ShmRingReader::try_pop`).
        self.seq.store((msg_seq << 1) | 1, Ordering::Relaxed);
        std::sync::atomic::fence(Ordering::Release);
    }

    /// Commit the slot (mark as ready for reading)
    #[inline]
    pub fn commit(&self, msg_seq: u64) {
        // Release ordering: critical for correctness!
        // Ensures all payload writes are visible BEFORE seq becomes even.
        // Pairs with the Acquire load of `seq` that opens `ShmRingReader::
        // try_pop` to form happens-before.
        // Without Release, readers could see committed seq but stale payload.
        self.seq.store(msg_seq << 1, Ordering::Release);
    }

    /// Get current sequence marker (for corruption detection)
    ///
    /// # Do NOT use this for the second half of a double check
    ///
    /// This is an Acquire LOAD, and for the re-check that closes a seqlock
    /// read that is the wrong direction: an Acquire load stops LATER accesses
    /// from moving before it and says nothing about EARLIER ones, so the
    /// payload copy it is supposed to fence can be sunk past it. The check then
    /// compares a value sampled before the writer touched the slot and accepts
    /// the torn read it exists to catch.
    ///
    /// The correct shape is an Acquire FENCE after the copy and a Relaxed load
    /// for the re-check, which is what `ShmRingReader::try_pop` does, and why
    /// it does not call this.
    #[inline]
    pub fn get_seq(&self) -> u64 {
        // Acquire ordering: synchronizes with the Release store in commit(),
        // so a caller that only samples the marker sees the payload writes that
        // preceded it. Sound for a single read; see the warning above before
        // using it as the second read of a pair.
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
    /// GUID of the writer that created this segment.
    ///
    /// Not a secret -- it is broadcast in discovery -- but it catches the
    /// honest collision: an unrelated participant that created a segment
    /// under a name this reader computed. The `nonce` below is what catches
    /// a deliberate one.
    pub owner_guid: [u8; 16],
    /// The creating participant's nonce, which it also announced in its
    /// shared-memory capability over discovery. A reader attaches only when
    /// this matches what the peer announced, so a segment planted by any
    /// other local process is refused instead of having its bytes delivered
    /// to the Router under the legitimate peer's identity.
    pub nonce: AtomicU64,
    /// Padding to fill cache line
    _pad: [u8; 16],
}

impl ShmControl {
    /// Magic number to identify valid SHM segments
    pub const MAGIC: u32 = 0x4844_4453; // "HDDS"

    /// Current version
    /// Segment layout version.
    ///
    /// Version 2: the segment carries the presence table
    /// (`super::presence::ShmPresence`) between this control block and the
    /// slots, so a version-1 peer's slot offsets do not match a version-2
    /// peer's. `validate()` refuses the mismatch rather than reading at the
    /// wrong offset.
    pub const VERSION: u32 = 2;

    /// Create a new control block
    #[must_use]
    pub const fn new(capacity: u32, slot_size: u32) -> Self {
        Self {
            head: AtomicU64::new(0),
            capacity,
            slot_size,
            magic: Self::MAGIC,
            version: Self::VERSION,
            owner_guid: [0u8; 16],
            nonce: AtomicU64::new(0),
            _pad: [0u8; 16],
        }
    }

    /// Stamp the identity of the participant that created this segment.
    /// Called once, at creation, before the segment is reachable by name.
    pub fn set_owner(&mut self, guid: [u8; 16], nonce: u64) {
        self.owner_guid = guid;
        self.nonce.store(nonce, Ordering::Release);
    }

    /// Whether this segment was created by the writer and participant the
    /// reader expects. Both halves matter: the GUID catches an unrelated
    /// participant that happened to collide on the name, the nonce catches a
    /// local process that read the GUID off the wire and planted the segment
    /// on purpose.
    pub fn owner_matches(&self, guid: [u8; 16], nonce: u64) -> bool {
        nonce != 0 && self.nonce.load(Ordering::Acquire) == nonce && self.owner_guid == guid
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
        Self::new(super::DEFAULT_RING_CAPACITY_U32, SLOT_PAYLOAD_SIZE_U32)
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

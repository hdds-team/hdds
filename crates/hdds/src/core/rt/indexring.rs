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
use crate::dds::CdrVersion;
use std::sync::atomic::{AtomicUsize, Ordering};

/// COMMITTED flag (bit 0): entry is fully written and ready to pop
const COMMITTED_FLAG: u16 = 0x01;

/// EXCLUSIVE flag (bit 1): the pushing side transferred SOLE ownership
/// of the entry's slab handle with this entry -- no fan-out duplicate,
/// no HistoryCache retention, no replay ref exists or can ever exist.
/// The consumer may free the slot directly (`SlabPool::release_exclusive`,
/// one RMW) instead of walking the refcount side-table. Set by
/// `TopicMerger::push` on the single-registered-reader path BEFORE the
/// push (an already-published entry is never re-tagged). Intra-process
/// only: `flags` never crosses the wire.
const EXCLUSIVE_FLAG: u16 = 0x02;

/// SOURCE_TS flag (bit 2): `timestamp_ns` carries the WRITER's source
/// timestamp (write-side clock on the intra path, INFO_TS on the
/// network path), not local reception time. Without this bit the two
/// meanings are indistinguishable at pop time, which is exactly where
/// `SampleInfo.source_timestamp_ns` needs the distinction. Rides a
/// free bit so the 24-byte entry stride is untouched.
const SOURCE_TS_FLAG: u16 = 0x04;

/// GUID_PREFIX flag (bit 3): the slab payload begins with the 16-byte
/// GUID of the originating writer; the encoded sample starts at byte
/// 16 and `len` covers prefix + sample. Set only by the network
/// delivery path (`ReaderSubscriber::process_admitted`), which is the
/// one producer that knows the remote writer; intra-process pushes
/// never set it. In-band (per-entry self-describing) rather than a
/// seq-keyed side map because the shared network ring already collides
/// cross-writer sequence numbers in the cache dedup.
const GUID_PREFIX_FLAG: u16 = 0x08;

/// WRITER_SN_PREFIX flag (bit 6): after the 16-byte GUID prefix
/// ([`GUID_PREFIX_FLAG`], always set with this one) the slab payload
/// carries the originating writer's full 64-bit sequence number, little
/// endian, and the encoded sample starts at byte 24. `seq` is 32 bits
/// wide; this is the writer's own number in full, for source ordering
/// (DDS v1.4 Sec.2.2.3.17) and presentation. Network delivery sets it for
/// source-order readers and for sequence numbers beyond 32 bits under
/// either policy; `len` covers both prefixes and the sample.
/// Without GUID_PREFIX, bit 6 instead identifies local history replay:
/// timestamp_ns holds journaled source time beside the shared retained slab,
/// and the reception merge key is zero. No payload prefix is present.
const WRITER_SN_PREFIX_FLAG: u16 = 0x40;

/// RECEPTION_TS_PREFIX flag (bit 7): the slab payload begins with the
/// 8-byte write-time clock of an intra-process write (nanoseconds since
/// the Unix epoch, little endian), and the encoded sample starts at byte
/// 8. Set only when the write carried an application-supplied source
/// timestamp (`write_w_timestamp`): `timestamp_ns` then holds that
/// override, and this prefix keeps the moment the write happened, which
/// is what orders a reader's rings under BY_RECEPTION_TIMESTAMP.
/// Intra-process only; `len` covers the prefix and the sample.
const RECEPTION_TS_PREFIX_FLAG: u16 = 0x80;

/// LIFECYCLE bits (4 and 5): the entry is not a sample but an instance
/// lifecycle change from a writer in this process - its slab holds the
/// 16-byte key hash, bit 4 says disposed, bit 5 unregistered (the RTPS
/// StatusInfo bits, shifted into free flag bits). The network delivers these
/// changes as key-only DATA; the local path carries them through this flag
/// pair so an intra-process reader receives them too.
/// Intra-process only: `flags` never crosses the wire.
const LIFECYCLE_SHIFT: u8 = 4;
const LIFECYCLE_MASK: u16 = 0x30;

/// The slab slot carries a receipt-time generation snapshot in its fixed
/// metadata side table. The extra flag bit fits the entry's existing padding.
const GENERATION_COUNTS_FLAG: u16 = 0x100;

/// Entry in a SPSC ring (sequence + slab handle + length + flags + timestamp
/// + CDR version selected at the write side per DDS-XTypes v1.3 sec. 7.6.3.1).
///
/// Two entry shapes share this struct:
/// - **Data entries** populate `seq`, `handle`, `len`, `flags`,
///   `timestamp_ns`, `cdr_version`.
/// - **Event entries** (constructed via `new_event`) populate `seq` (event
///   tag) and the packed event payload (read back via
///   [`IndexEntry::event_data`]), and leave `handle` / `timestamp_ns`
///   zero. Consumers of event entries must go through `event_data()`
///   only -- `handle` and `len` carry no direct meaning for them.
///
/// The event payload is stored in the `len` field: event entries never
/// reference slab storage, so the byte count slot is free for them.
/// This overlay keeps the struct at 24 bytes (size pinned by
/// `test_index_entry_layout`), the hot stride of the intra-process
/// merger ring; a dedicated `event_data` field pushed it to 32 bytes.
#[derive(Debug, Clone, Copy)]
pub struct IndexEntry {
    pub seq: u32,                // sequence number (or event tag)
    pub handle: SlabHandle,      // slab handle for payload (packed u32)
    pub len: u32,                // bytes written (or packed event payload)
    pub flags: u16,              // COMMITTED flag (bit 0)
    pub timestamp_ns: u64,       // write timestamp for latency measurement
    pub cdr_version: CdrVersion, // encoding version used for the payload
}

impl IndexEntry {
    /// Create new entry with uncommitted state (default Xcdr2 encoding).
    pub fn new(seq: u32, handle: SlabHandle, len: u32) -> Self {
        Self {
            seq,
            handle,
            len,
            flags: 0, // Not committed yet
            timestamp_ns: 0,
            cdr_version: CdrVersion::Xcdr2,
        }
    }

    /// Create entry with timestamp (default Xcdr2 encoding).
    pub fn with_timestamp(seq: u32, handle: SlabHandle, len: u32, timestamp_ns: u64) -> Self {
        Self {
            seq,
            handle,
            len,
            flags: 0,
            timestamp_ns,
            cdr_version: CdrVersion::Xcdr2,
        }
    }

    /// Create entry with the explicit CDR version used to encode the
    /// payload carried in the slab handle.
    pub fn with_cdr_version(
        seq: u32,
        handle: SlabHandle,
        len: u32,
        timestamp_ns: u64,
        cdr_version: CdrVersion,
    ) -> Self {
        Self {
            seq,
            handle,
            len,
            flags: 0,
            timestamp_ns,
            cdr_version,
        }
    }

    /// Create a hub-event entry. `seq` carries the event tag (per
    /// `engine::hub::Event` encoding) and
    /// `event_data` carries the packed payload (stored in the `len`
    /// slot -- event entries do not reference slab storage, see the
    /// struct docs). The slab handle stays `EMPTY`.
    pub fn new_event(seq: u32, event_data: u32) -> Self {
        Self {
            seq,
            handle: SlabHandle::EMPTY,
            len: event_data,
            flags: 0,
            timestamp_ns: 0,
            cdr_version: CdrVersion::Xcdr2,
        }
    }

    /// Packed hub-event payload of an entry constructed via
    /// [`IndexEntry::new_event`]. Only meaningful for event entries;
    /// data entries return their byte count here (callers distinguish
    /// the two shapes by ring, never by field inspection).
    #[inline]
    pub fn event_data(self) -> u32 {
        self.len
    }

    /// Check if entry is committed (ready to pop)
    pub fn is_committed(self) -> bool {
        (self.flags & COMMITTED_FLAG) != 0
    }

    /// Tag this entry as the SOLE reference to its slab handle (see
    /// `EXCLUSIVE_FLAG`). Must be called BEFORE the entry is pushed.
    #[inline]
    pub fn set_exclusive(&mut self) {
        self.flags |= EXCLUSIVE_FLAG;
    }

    /// Whether the pushing side transferred sole ownership of the slab
    /// handle with this entry (direct-free eligible).
    #[inline]
    pub fn is_exclusive(self) -> bool {
        (self.flags & EXCLUSIVE_FLAG) != 0
    }

    /// Tag `timestamp_ns` as a true SOURCE timestamp (see
    /// [`SOURCE_TS_FLAG`]). Must be called BEFORE the entry is pushed.
    #[inline]
    pub fn mark_source_ts(&mut self) {
        self.flags |= SOURCE_TS_FLAG;
    }

    /// Whether `timestamp_ns` is the writer's source timestamp rather
    /// than local reception time.
    #[inline]
    pub fn has_source_ts(self) -> bool {
        (self.flags & SOURCE_TS_FLAG) != 0
    }

    /// Tag the slab payload as GUID-prefixed (see [`GUID_PREFIX_FLAG`]).
    /// Must be called BEFORE the entry is pushed.
    #[inline]
    pub fn mark_guid_prefix(&mut self) {
        self.flags |= GUID_PREFIX_FLAG;
    }

    /// Whether the slab payload starts with the 16-byte writer GUID
    /// (encoded sample at byte 16).
    #[inline]
    pub fn has_guid_prefix(self) -> bool {
        (self.flags & GUID_PREFIX_FLAG) != 0
    }

    /// Tag the slab payload as carrying the writer's full sequence
    /// number after its GUID prefix (see [`WRITER_SN_PREFIX_FLAG`]). Must
    /// be called BEFORE the entry is pushed, on an entry that also has
    /// the GUID prefix.
    #[inline]
    pub fn mark_writer_sn_prefix(&mut self) {
        self.flags |= WRITER_SN_PREFIX_FLAG;
    }

    /// Whether the slab payload carries the writer's full sequence number
    /// at bytes 16..24.
    #[inline]
    pub fn has_writer_sn_prefix(self) -> bool {
        (self.flags & (WRITER_SN_PREFIX_FLAG | GUID_PREFIX_FLAG))
            == (WRITER_SN_PREFIX_FLAG | GUID_PREFIX_FLAG)
    }

    /// Local replay shares the retained slab, with source time in this
    /// entry and a zero reception merge key.
    #[inline]
    pub(crate) fn mark_local_replay(&mut self) {
        debug_assert!(!self.has_guid_prefix());
        self.flags |= WRITER_SN_PREFIX_FLAG;
    }

    #[inline]
    pub(crate) fn is_local_replay(self) -> bool {
        (self.flags & (WRITER_SN_PREFIX_FLAG | GUID_PREFIX_FLAG)) == WRITER_SN_PREFIX_FLAG
    }

    /// Tag the slab payload as beginning with the write-time clock (see
    /// [`RECEPTION_TS_PREFIX_FLAG`]). Must be called BEFORE the entry is
    /// pushed.
    #[inline]
    pub fn mark_reception_ts_prefix(&mut self) {
        self.flags |= RECEPTION_TS_PREFIX_FLAG;
    }

    /// Whether the slab payload begins with the write-time clock.
    #[inline]
    pub fn has_reception_ts_prefix(self) -> bool {
        (self.flags & RECEPTION_TS_PREFIX_FLAG) != 0
    }

    /// The owning reader stamped both generation counters before publication.
    #[inline]
    pub(crate) fn mark_generation_counts(&mut self) {
        self.flags |= GENERATION_COUNTS_FLAG;
    }

    /// Whether this entry's slab metadata carries receipt-time counters.
    #[inline]
    pub(crate) fn has_generation_counts(self) -> bool {
        self.flags & GENERATION_COUNTS_FLAG != 0
    }

    /// Where the encoded sample starts in the slab payload: past the GUID
    /// prefix, the writer sequence number and the write-time clock, each
    /// when its flag says it is there. Branch-free.
    #[inline]
    #[must_use]
    pub fn payload_offset(self) -> usize {
        16 * usize::from(self.has_guid_prefix())
            + 8 * usize::from(self.has_writer_sn_prefix())
            + 8 * usize::from(self.has_reception_ts_prefix())
    }

    /// The writer's full sequence number from a payload carrying it
    /// ([`WRITER_SN_PREFIX_FLAG`]), `None` otherwise or when `payload` is
    /// too short to hold it.
    #[inline]
    #[must_use]
    pub fn writer_sn_in(self, payload: &[u8]) -> Option<u64> {
        if !self.has_writer_sn_prefix() {
            return None;
        }
        let bytes = payload.get(16..24)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// The write-time clock from a payload beginning with it
    /// ([`RECEPTION_TS_PREFIX_FLAG`]), `None` otherwise or when `payload`
    /// is too short to hold it.
    #[inline]
    #[must_use]
    pub fn reception_ts_in(self, payload: &[u8]) -> Option<u64> {
        if !self.has_reception_ts_prefix() {
            return None;
        }
        let at =
            16 * usize::from(self.has_guid_prefix()) + 8 * usize::from(self.has_writer_sn_prefix());
        let bytes = payload.get(at..at + 8)?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    }

    /// Mark this entry as an instance lifecycle change; `status_bits` are
    /// the RTPS StatusInfo bits (1 disposed, 2 unregistered). See
    /// `LIFECYCLE_SHIFT`.
    #[inline]
    pub fn mark_lifecycle(&mut self, status_bits: u8) {
        self.flags |= (u16::from(status_bits) << LIFECYCLE_SHIFT) & LIFECYCLE_MASK;
    }

    /// The StatusInfo bits of a lifecycle entry, 0 for a sample.
    #[inline]
    #[must_use]
    pub fn lifecycle_bits(self) -> u8 {
        // LIFECYCLE_MASK keeps two bits, so naming the four values keeps this
        // total without a truncating cast.
        match self.flags & LIFECYCLE_MASK {
            0 => 0,
            0x10 => 1,
            0x20 => 2,
            _ => 3,
        }
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
            handle: SlabHandle::EMPTY,
            len: 0,
            flags: 0,
            timestamp_ns: 0,
            cdr_version: CdrVersion::Xcdr2,
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
    pub fn pop(&self) -> Option<IndexEntry> {
        let mut was_full = false;
        self.pop_noting_full(&mut was_full)
    }

    /// [`pop`](Self::pop), also setting `was_full` when the ring was full
    /// before this pop (and leaving it as it was otherwise): a producer that
    /// found it full may be waiting for the slot this pop frees. Computed
    /// from the indices `pop` loads anyway; the entry is returned exactly
    /// as `pop` returns it.
    #[inline]
    pub(crate) fn pop_noting_full(&self, was_full: &mut bool) -> Option<IndexEntry> {
        // 1. Load current tail (Relaxed: no sync needed, we're the only consumer)
        let tail = self.tail.load(Ordering::Relaxed);

        // 2. Check if ring empty (Acquire: sync with producer's head advance)
        let head = self.head.load(Ordering::Acquire);
        if tail == head {
            return None; // Empty
        }
        *was_full |= (head + 1) & self.capacity_mask == tail;

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

    /// [`push`](Self::push) of `entry` tagged EXCLUSIVE (see
    /// [`IndexEntry::set_exclusive`]) when `exclusive`.
    ///
    /// The tag is set on the ring's slot, after the entry is copied into it,
    /// not on the caller's copy. Tagging the caller's copy compiled to a
    /// one-byte read-modify-write of its flags followed by an 8-byte reload
    /// of the same bytes to copy the entry (seen in the disassembly), and
    /// cost 3-4 ns p50 on the one-thread write-then-take path.
    /// The ring of an EXCLUSIVE reader is unchanged: the consumer reads the
    /// same flags.
    #[inline]
    pub(crate) fn push_tagged(&self, entry: IndexEntry, exclusive: bool) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let next_head = (head + 1) & self.capacity_mask;
        let tail = self.tail.load(Ordering::Acquire);
        if next_head == tail {
            return false;
        }
        let tag = COMMITTED_FLAG | if exclusive { EXCLUSIVE_FLAG } else { 0 };
        // SAFETY: SPSC protocol ensures only the producer writes the slot at
        // `head`, which the consumer reads only after the release below.
        unsafe {
            let entries = &mut *self.entries.get();
            let slot = &mut entries[head];
            *slot = entry;
            slot.flags |= tag;
        }
        self.head.store(next_head, Ordering::Release);
        true
    }

    /// Whether a push would find the ring full now. Exact for the producer,
    /// the only thread that fills the ring: a pop after this read only makes
    /// room, so a push that follows a `false` from the producer succeeds.
    #[must_use]
    pub(crate) fn is_full(&self) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        (head + 1) & self.capacity_mask == tail
    }

    /// Get current number of entries in ring (approximate, for debugging)
    ///
    /// Note: This is racy in multi-threaded context but safe to call.
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        (head.wrapping_sub(tail)) & self.capacity_mask
    }

    /// The number of entries the ring holds when full: one slot less than
    /// its power-of-two capacity, since one slot stays empty to tell a full
    /// ring from an empty one.
    #[must_use]
    pub fn usable_capacity(&self) -> usize {
        self.capacity - 1
    }

    /// The entries in the ring as of the head this call reads, never less:
    /// safe to call from a thread that is neither the producer nor the
    /// consumer.
    ///
    /// The tail is read first, with Acquire. It synchronizes with the
    /// consumer's store of that tail, which the consumer made only after
    /// reading a head at least that far, so the head read next is at least
    /// as far as the tail and the difference never wraps (`len` reads the
    /// head first and can wrap to a nonsense value). A pop after the tail was
    /// read makes the result larger than the truth, never smaller; an entry
    /// pushed after the head was read is not counted.
    #[must_use]
    pub fn len_at_most(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        head.wrapping_sub(tail) & self.capacity_mask
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

    /// Layout pin for the merger-ring hot stride.
    ///
    /// The intra-process fast path pushes/pops `IndexEntry` by value on
    /// every write/take, so its size is a hot-path cost (growing it from
    /// 24 to 32 bytes, e.g. with an 8-byte `SlabHandle` enum plus a dedicated
    /// `event_data` field, costs measurable ns). Any future field addition
    /// must justify breaking this pin.
    #[test]
    fn test_index_entry_layout() {
        assert_eq!(
            std::mem::size_of::<IndexEntry>(),
            24,
            "IndexEntry must stay at the 24-byte hot-ring stride"
        );
        assert_eq!(
            std::mem::size_of::<SlabHandle>(),
            4,
            "SlabHandle must stay a packed 4-byte handle"
        );
    }

    #[test]
    fn test_event_data_roundtrip() {
        // Event payload overlays the len slot; the accessor must return
        // exactly what new_event stored, and the handle stays EMPTY.
        let entry = IndexEntry::new_event(2, (77u32 << 16) | 42);
        assert_eq!(entry.event_data(), (77u32 << 16) | 42);
        assert_eq!(entry.seq, 2);
        assert!(entry.handle.is_empty());
        assert_eq!(entry.timestamp_ns, 0);
    }

    #[test]
    fn test_push_pop_basic() {
        let ring = IndexRing::with_capacity(16);

        let entry = IndexEntry::new(1, SlabHandle::legacy_handle_to_primary(42), 100);
        assert!(ring.push(entry));

        let popped = ring.pop().expect("Pop should succeed after push");
        assert_eq!(popped.seq, 1);
        assert_eq!(popped.handle, SlabHandle::legacy_handle_to_primary(42));
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
            let entry = IndexEntry::new(i, SlabHandle::legacy_handle_to_primary(i), 100);
            assert!(ring.push(entry), "Failed to push entry {}", i);
        }

        // Next push should fail (ring full)
        let entry = IndexEntry::new(99, SlabHandle::legacy_handle_to_primary(99), 100);
        assert!(!ring.push(entry), "Should fail when ring full");
    }

    #[test]
    fn test_push_pop_sequence() {
        let ring = IndexRing::with_capacity(8);

        // Push 5 entries
        for i in 0..5 {
            let entry = IndexEntry::new(i, SlabHandle::legacy_handle_to_primary(i), i * 10);
            assert!(ring.push(entry));
        }

        // Pop all 5 entries in order
        for i in 0..5 {
            let popped = ring.pop().expect("Pop should succeed for pushed entries");
            assert_eq!(popped.seq, i);
            assert_eq!(popped.handle, SlabHandle::legacy_handle_to_primary(i));
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
            assert!(ring.push(IndexEntry::new(
                i,
                SlabHandle::legacy_handle_to_primary(i),
                100
            )));
        }

        // Pop all
        for _ in 0..3 {
            ring.pop().expect("Pop should succeed for pushed entries");
        }

        // Push again (should wrap around)
        for i in 10..13 {
            assert!(ring.push(IndexEntry::new(
                i,
                SlabHandle::legacy_handle_to_primary(i),
                100
            )));
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
            let handle = SlabHandle::legacy_handle_to_primary(seq);
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
        let mut entry = IndexEntry::new(1, SlabHandle::legacy_handle_to_primary(1), 100);
        assert!(!entry.is_committed());

        entry.mark_committed();
        assert!(entry.is_committed());
    }

    #[test]
    fn test_metadata_flags_independent() {
        // The metadata bits must ride bits 2/3 without disturbing the
        // COMMITTED/EXCLUSIVE protocol bits, and each must be readable
        // independently of the others.
        let mut entry = IndexEntry::new(1, SlabHandle::legacy_handle_to_primary(1), 100);
        assert!(!entry.has_source_ts());
        assert!(!entry.has_guid_prefix());

        entry.mark_source_ts();
        assert!(entry.has_source_ts());
        assert!(!entry.has_guid_prefix());
        assert!(!entry.is_committed());
        assert!(!entry.is_exclusive());

        entry.mark_guid_prefix();
        entry.set_exclusive();
        entry.mark_committed();
        assert!(entry.has_source_ts());
        assert!(entry.has_guid_prefix());
        assert!(entry.is_exclusive());
        assert!(entry.is_committed());

        // Flags survive a ring roundtrip verbatim (push only ORs in
        // COMMITTED).
        let ring = IndexRing::with_capacity(4);
        let mut pushed = IndexEntry::new(7, SlabHandle::legacy_handle_to_primary(7), 32);
        pushed.mark_source_ts();
        pushed.mark_guid_prefix();
        assert!(ring.push(pushed));
        let popped = ring.pop().expect("pop after push");
        assert!(popped.has_source_ts());
        assert!(popped.has_guid_prefix());
        assert!(popped.is_committed());
        assert!(!popped.is_exclusive());
    }

    #[test]
    fn test_capacity_power_of_two() {
        let ring = IndexRing::with_capacity(10); // Should round up to 16
        assert_eq!(ring.capacity, 16);
        assert_eq!(ring.capacity_mask, 15);

        let ring2 = IndexRing::with_capacity(8); // Already power of 2
        assert_eq!(ring2.capacity, 8);
    }

    /// TWO producers on one ring must not lose accepted entries.
    ///
    /// This is not a supported use of `IndexRing` -- `push` is documented
    /// single-producer. The topology it models is a DataReader that is
    /// intra-process-bound to a local writer AND fed by the network: the
    /// writer's application thread (`TopicMerger::push`) and the router RX
    /// thread (`ReaderSubscriber::process_admitted`) would both push into
    /// the reader's PRIMARY ring (`ReaderBindings::bind` hands the primary
    /// to the first binding). The engine avoids it: the network pushes into
    /// a ring of its own, and its several delivering threads take the
    /// subscriber's push lock.
    ///
    /// The race: both producers `head.load(Relaxed)` the same value, both
    /// write `entries[head]`, both `head.store(head+1, Release)`. One
    /// accepted entry is overwritten and gone, head advanced once for two
    /// accepted pushes -- and in the engine the vanished entry's slab handle
    /// is never popped, so its refcount never releases (a leak on top of the
    /// loss).
    ///
    /// RED BY NATURE, hence `#[ignore]`: two producers on one SPSC ring is
    /// undefined behaviour at this level -- the remedy is for the ENGINE not
    /// to create the topology, not to make `push` multi-producer (that would
    /// tax the hot path for everyone). This test is the executed proof of
    /// what the topology does; run it manually:
    ///
    /// `cargo test --lib -- --ignored two_producers_on_one_ring`
    ///
    /// Accepted entries are silently lost. Some runs also WEDGE outright: a
    /// torn slot leaves the COMMITTED flag invisible at the tail, the
    /// consumer stops draining, and both producers spin on ring-full forever
    /// -- the race does not merely lose samples, it can freeze the delivery
    /// pipeline. The deadline below turns that wedge into a clean assertion
    /// failure.
    #[test]
    #[ignore = "executed proof of TODO 8.5, red by nature: two producers on an SPSC ring"]
    fn two_producers_on_one_ring_lose_accepted_entries() {
        use std::sync::atomic::{AtomicBool, AtomicU64};
        use std::sync::Arc;

        const PUSHES_PER_PRODUCER: u64 = 200_000;
        /// A wedged run (see the doc comment) must fail, not hang.
        const DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);

        let start = std::time::Instant::now();
        let ring = Arc::new(IndexRing::with_capacity(1024));
        let accepted = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));

        // Single consumer, draining concurrently (as the reader pump does).
        let popped = {
            let ring = Arc::clone(&ring);
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let mut popped = 0u64;
                loop {
                    if ring.pop().is_some() {
                        popped += 1;
                    } else if done.load(Ordering::Acquire) {
                        // Producers finished: drain what is left, then stop.
                        while ring.pop().is_some() {
                            popped += 1;
                        }
                        break;
                    } else if start.elapsed() > DEADLINE {
                        break;
                    } else {
                        std::hint::spin_loop();
                    }
                }
                popped
            })
        };

        let producers: Vec<_> = (0..2u32)
            .map(|producer_id| {
                let ring = Arc::clone(&ring);
                let accepted = Arc::clone(&accepted);
                std::thread::spawn(move || {
                    for i in 0..PUSHES_PER_PRODUCER {
                        let entry = IndexEntry::new(
                            u32::try_from(i & 0xFFFF_FFFF).expect("fits"),
                            SlabHandle::EMPTY,
                            producer_id + 1,
                        );
                        // Spin on full: a full ring is backpressure, not loss,
                        // and must not count against the SPSC contract.
                        loop {
                            if ring.push(entry) {
                                accepted.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                            if start.elapsed() > DEADLINE {
                                // Wedged (see doc comment): stop pushing so
                                // the joins below complete and the count
                                // mismatch fails the test cleanly.
                                return;
                            }
                            std::hint::spin_loop();
                        }
                    }
                })
            })
            .collect();

        for p in producers {
            p.join().expect("producer thread");
        }
        done.store(true, Ordering::Release);
        let popped = popped.join().expect("consumer thread");
        let accepted = accepted.load(Ordering::Relaxed);

        assert_eq!(
            popped,
            accepted,
            "the ring accepted {} pushes but the single consumer drained only {}: \
             {} entries were silently overwritten by the concurrent producer. In the \
             engine each vanished entry also leaks its slab handle's refcount",
            accepted,
            popped,
            accepted - popped
        );
    }
}

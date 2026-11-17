// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared memory ring buffer implementation for inter-process communication.
//!
//! # Memory Layout
//!
//! ```text
//! +-------------------------------------------------------------+
//! | ShmControl (64 bytes, cache-aligned)                        |
//! +-------------------------------------------------------------+
//! | ShmSlot[0] (64 bytes header + SLOT_PAYLOAD_SIZE payload)    |
//! | ShmSlot[1]                                                  |
//! | ...                                                         |
//! | ShmSlot[capacity-1]                                         |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Synchronization Protocol
//!
//! Writer push:
//! 1. Mark slot as writing: `slot.seq = (msg_seq << 1) | 1`
//! 2. Write payload length and data
//! 3. Commit: `slot.seq = msg_seq << 1` (Release)
//! 4. Publish head: `control.head = msg_seq + 1` (Release)
//! 5. Wake readers via futex
//!
//! Reader try_pop:
//! 1. Load head (Acquire), check for overrun
//! 2. Load slot.seq (Acquire), verify `seq == expected << 1`
//! 3. Copy payload
//! 4. Re-check slot.seq (detect torn read)
//! 5. Advance local sequence

use super::notify::TopicNotify;
use super::presence::ShmPresence;
use super::segment::ShmSegment;
use super::slot::{ShmControl, ShmSlot, SLOT_PAYLOAD_SIZE, SLOT_PAYLOAD_SIZE_U32};
use super::{Result, ShmError};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Calculate total segment size for a ring buffer
///
/// Layout, in order: the control block, the presence table, then the slots.
/// The presence table sits between them rather than at the end so that adding
/// slots never moves it.
#[must_use]
pub const fn ring_segment_size(capacity: usize) -> usize {
    slots_offset() + capacity * std::mem::size_of::<ShmSlot>()
}

/// Byte offset of slot 0 from the start of the segment.
#[must_use]
pub const fn slots_offset() -> usize {
    std::mem::size_of::<ShmControl>() + std::mem::size_of::<ShmPresence>()
}

/// Byte offset of the presence table from the start of the segment.
#[must_use]
pub const fn presence_offset() -> usize {
    std::mem::size_of::<ShmControl>()
}

/// Shared memory ring buffer writer.
///
/// Owns the shared memory segment and writes messages to it.
/// Readers can attach to the same segment via `ShmRingReader::attach()`.
pub struct ShmRingWriter {
    /// Shared memory segment (owned)
    segment: ShmSegment,
    /// Ring capacity (power of 2)
    capacity: usize,
    /// Capacity mask for index calculation
    mask: usize,
    /// Next sequence number to write
    next_seq: u64,
    /// Topic notification for waking readers
    topic_notify: Option<TopicNotify>,
    /// Notification bucket index (hash of writer GUID)
    notify_bucket: usize,
}

impl ShmRingWriter {
    /// Create a new shared memory ring buffer.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name (e.g., `/hdds_d0_w{guid}`)
    /// * `capacity` - Number of slots (must be power of 2)
    /// * `writer_guid` - Writer GUID for bucket assignment
    ///
    /// # Errors
    ///
    /// Returns error if capacity is not power of 2 or segment creation fails.
    pub fn create(name: &str, capacity: usize, writer_guid: &[u8; 16]) -> Result<Self> {
        if !capacity.is_power_of_two() {
            return Err(ShmError::InvalidCapacity(capacity));
        }
        // The control block stores the capacity as a u32; the conversion is
        // the check that it fits.
        let control_capacity =
            u32::try_from(capacity).map_err(|_| ShmError::InvalidCapacity(capacity))?;

        let size = ring_segment_size(capacity);
        let segment = ShmSegment::create(name, size)?;

        // Initialize control block
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from successful ShmSegment::create
        // - The segment was created with size = ring_segment_size(capacity), which includes
        //   sizeof(ShmControl) at the beginning
        // - ShmControl requires 8-byte alignment; mmap returns page-aligned memory (4096+ bytes)
        // - The segment was just created, so we have exclusive access (no data races)
        // - The memory was zero-initialized by ShmSegment::create
        let control = unsafe { &mut *(segment.as_ptr() as *mut ShmControl) };
        *control = ShmControl::new(control_capacity, SLOT_PAYLOAD_SIZE_U32);
        // Stamp who owns this segment, while we still hold it exclusively:
        // the segment was created with O_EXCL and nobody can reach it by name
        // until we return. A reader compares both halves before trusting a
        // byte of it.
        control.set_owner(*writer_guid, super::local_nonce());

        let notify_bucket = TopicNotify::bucket_for_guid(writer_guid);

        // Record this process as the segment's owner for crash reclamation
        // (`super::owner`): a side record, never mapped, so this carries no
        // layout or wire implications for a peer that only attaches.
        super::owner::record_owner(name);

        Ok(Self {
            segment,
            capacity,
            mask: capacity - 1,
            next_seq: 0,
            topic_notify: None,
            notify_bucket,
        })
    }

    /// Attach a topic notification for waking readers
    pub fn with_notify(mut self, notify: TopicNotify) -> Self {
        self.topic_notify = Some(notify);
        self
    }

    /// Set topic notification after construction
    pub fn set_notify(&mut self, notify: TopicNotify) {
        self.topic_notify = Some(notify);
    }

    /// Get pointer to control block
    #[inline]
    fn control(&self) -> &ShmControl {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::create
        // - The segment size includes ShmControl at offset 0
        // - ShmControl requires 8-byte alignment; mmap provides page alignment
        // - ShmControl uses atomic fields for thread-safe access across processes
        // - The reference is valid for the lifetime of &self
        unsafe { &*(self.segment.as_ptr() as *const ShmControl) }
    }

    /// The segment's presence table: which remote participants have proven
    /// they are attached to this ring.
    ///
    /// SAFETY: the table lives at `presence_offset()`, inside the mapping
    /// whose size is `ring_segment_size(capacity)`; every field is an atomic
    /// integer, so concurrent access from the peer process is defined, and
    /// the kernel hands out zero-filled pages, which is the table's own
    /// "every entry free" state.
    pub fn presence(&self) -> &ShmPresence {
        unsafe { &*(self.segment.as_ptr().add(presence_offset()) as *const ShmPresence) }
    }

    /// Get pointer to slots array
    #[inline]
    fn slots(&self) -> *mut ShmSlot {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::create
        // - Adding sizeof(ShmControl) bytes is within bounds because the segment was
        //   created with size = sizeof(ShmControl) + capacity * sizeof(ShmSlot)
        // - ShmSlot is cache-aligned (64 bytes); ShmControl is also 64 bytes, so
        //   the slots array starts at a 64-byte aligned offset
        // - The pointer arithmetic does not overflow (segment sizes are bounded)
        unsafe { self.segment.as_ptr().add(slots_offset()) as *mut ShmSlot }
    }

    /// Get a specific slot
    #[inline]
    fn slot(&self, index: usize) -> &ShmSlot {
        debug_assert!(index < self.capacity);
        // SAFETY:
        // - self.slots() returns a valid pointer to the start of the slots array
        // - index < self.capacity is asserted in debug mode and guaranteed by callers
        //   (index is computed as seq & mask where mask = capacity - 1)
        // - The slots array has exactly `capacity` elements, so index is in bounds
        // - ShmSlot uses atomic fields for thread-safe concurrent access
        // - The reference is valid for the lifetime of &self
        unsafe { &*self.slots().add(index) }
    }

    /// Push a message to the ring buffer.
    ///
    /// # Arguments
    ///
    /// * `data` - Message payload (must fit in SLOT_PAYLOAD_SIZE)
    ///
    /// # Errors
    ///
    /// Returns error if payload is too large.
    ///
    /// # Performance
    ///
    /// Target: < 200 ns per push
    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        // One statement carries both bounds: the slot's, and the u32 the
        // length is stored in. Neither can drift away from the other.
        let len = match u32::try_from(data.len()) {
            Ok(len) if len <= SLOT_PAYLOAD_SIZE_U32 => len,
            _ => {
                return Err(ShmError::PayloadTooLarge {
                    size: data.len(),
                    capacity: SLOT_PAYLOAD_SIZE,
                })
            }
        };

        let msg_seq = self.next_seq;
        let idx = (msg_seq as usize) & self.mask;
        let slot = self.slot(idx);

        // 1. Mark in-progress (odd), together with the store-store half of the
        //    seqlock barrier pair. Both live in `ShmSlot::mark_writing`, which
        //    documents why the barrier has to be a fence rather than an
        //    ordering on the store. Do NOT re-inline it: the protocol must
        //    live in one place so a barrier fix is written once.
        slot.mark_writing(msg_seq);

        // 2. Write payload length
        slot.len.store(len, Ordering::Relaxed);

        // 3. Write payload data
        // SAFETY:
        // - slot.payload is a valid UnsafeCell containing a byte array of SLOT_PAYLOAD_SIZE
        // - data.len() <= SLOT_PAYLOAD_SIZE was checked at function entry
        // - We have exclusive write access because:
        //   a) The slot's sequence number was set to an odd value (in-progress marker)
        //   b) Only one writer exists per ring buffer (single-producer design)
        //   c) Readers check the sequence number and skip in-progress slots
        // - ptr::copy_nonoverlapping is safe because src and dst don't overlap
        //   (data is caller's buffer, dst is in shared memory)
        // - The destination buffer is properly aligned for u8 (alignment of 1)
        unsafe {
            let dst = (*slot.payload.get()).as_mut_ptr();
            ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }

        // 4. Commit (even) with Release ordering
        slot.commit(msg_seq);

        // 5. Publish head
        self.control().publish_head(msg_seq + 1);

        // 6. Wake readers (if notify attached)
        if let Some(ref notify) = self.topic_notify {
            notify.notify(self.notify_bucket);
        }

        self.next_seq = msg_seq + 1;
        Ok(())
    }

    /// Get current sequence number (next to be written)
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.next_seq
    }

    /// Get the segment name
    #[must_use]
    pub fn segment_name(&self) -> &str {
        self.segment.name()
    }

    /// Get ring capacity
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Unlink the segment (cleanup).
    ///
    /// `ShmSegment::unlink` itself removes the crash-reclamation sidecar
    /// record alongside the segment (see `super::owner`), so every caller
    /// that unlinks a ring segment -- this method, a test's `UnlinkOnDrop`,
    /// `cleanup_domain_segments` -- gets that for free.
    pub fn unlink(&self) -> Result<()> {
        ShmSegment::unlink(self.segment.name())
    }
}

/// Metrics for reader operations
#[derive(Debug, Default)]
pub struct ReaderMetrics {
    /// Number of messages read successfully
    pub messages_read: AtomicU64,
    /// Number of overrun EVENTS (reader lapped by the writer). One event can
    /// cover many lost messages; `samples_skipped` is that number.
    pub overruns: AtomicU64,
    /// Messages the reader skipped past on overrun recovery. This is what an
    /// operator means by "how many samples did shared memory lose", and it can
    /// be far larger than the event count.
    pub samples_skipped: AtomicU64,
    /// Number of corrupted reads (torn read detected)
    pub corrupted: AtomicU64,
    /// Number of empty polls (no data available)
    pub empty_polls: AtomicU64,
    /// Messages consumed without a copy because they were longer than the
    /// caller's buffer (`discard_if_longer`): out of contract for the caller.
    pub oversize_skipped: AtomicU64,
}

impl ReaderMetrics {
    /// Create new metrics
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Shared memory ring buffer reader.
///
/// Attaches to an existing shared memory segment created by `ShmRingWriter`.
/// Multiple readers can attach to the same segment.
pub struct ShmRingReader {
    /// Shared memory segment (opened, not owned)
    segment: ShmSegment,
    /// Ring capacity
    capacity: usize,
    /// Capacity mask
    mask: usize,
    /// Next expected sequence number
    next_seq: u64,
    /// Topic notification for blocking wait
    topic_notify: Option<TopicNotify>,
    /// Notification bucket index to wait on
    notify_bucket: usize,
    /// Performance metrics
    pub metrics: ReaderMetrics,
}

impl ShmRingReader {
    /// Attach to an existing shared memory ring buffer.
    ///
    /// # Arguments
    ///
    /// * `name` - Segment name
    /// * `capacity` - Expected ring capacity
    /// * `notify_bucket` - Bucket index to wait on (usually from writer GUID)
    ///
    /// # Errors
    ///
    /// Returns error if segment doesn't exist or validation fails.
    pub fn attach(
        name: &str,
        capacity: usize,
        notify_bucket: usize,
        expected_owner: Option<([u8; 16], u64)>,
    ) -> Result<Self> {
        let size = ring_segment_size(capacity);
        let segment = ShmSegment::open(name, size)?;

        // Validate control block
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from successful ShmSegment::open
        // - The segment was opened with size = ring_segment_size(capacity), which includes
        //   sizeof(ShmControl) at the beginning
        // - ShmControl requires 8-byte alignment; mmap returns page-aligned memory
        // - ShmControl uses atomic fields, so reading from another process is safe
        // - The reference is valid for the duration of this validation check
        let control = unsafe { &*(segment.as_ptr() as *const ShmControl) };
        if !control.validate() {
            return Err(ShmError::Corruption);
        }

        // Compared in the control block's own width. A capacity that does
        // not fit a u32 cannot match any segment, and says so by name.
        let expected_capacity =
            u32::try_from(capacity).map_err(|_| ShmError::InvalidCapacity(capacity))?;
        if control.capacity != expected_capacity {
            return Err(ShmError::InvalidCapacity(control.capacity as usize));
        }

        // The control block has carried `slot_size` from the start and nothing
        // ever read it. It is the one field that says whether the writer's
        // idea of the geometry matches ours: a peer built with a different
        // `SLOT_PAYLOAD_SIZE` passes `validate()` (magic and version are the
        // same) and passes the capacity check, and then every slot offset we
        // compute lands in the middle of one of its slots. The segment size
        // check in `ShmSegment::open` catches the case where that makes the
        // mapping too short; this catches the case where it does not.
        if control.slot_size != SLOT_PAYLOAD_SIZE_U32 {
            log::error!(
                "[SHM-RX] segment '{}' was built with {} byte slots but this build uses {}: \
                 refusing to attach rather than reading every slot at the wrong offset.",
                name,
                control.slot_size,
                SLOT_PAYLOAD_SIZE
            );
            return Err(ShmError::Corruption);
        }

        // Authenticate the segment before trusting anything else in it.
        // `/dev/shm` is typically mode 1777 and this segment's name derives
        // from the domain id and the writer GUID, both broadcast in
        // discovery, so any local process can create the name first and push
        // whatever it likes. Those samples would reach the Router stamped
        // with the legitimate peer's real unicast locator -- the identity
        // every per-peer check upstream relies on.
        match expected_owner {
            Some((guid, nonce)) if control.owner_matches(guid, nonce) => {}
            Some(_) => {
                log::error!(
                    "[SHM-RX] segment '{name}' is not owned by the writer that announced it \
                     (owner guid/nonce mismatch): refusing to attach. Something else on this \
                     machine created this segment name."
                );
                return Err(ShmError::Corruption);
            }
            None => {
                log::warn!(
                    "[SHM-RX] segment '{name}': no owner nonce was announced for this peer, so \
                     the segment cannot be authenticated. Refusing to attach and keeping UDP."
                );
                return Err(ShmError::Corruption);
            }
        }

        // Start reading from current head (skip old data). Load-bearing: a reader claims its presence entry right after attaching,
        // and starting at the head is what guarantees it never reads a sample
        // the writer already sent it over UDP before the claim was observed.
        let start_seq = control.get_head();

        Ok(Self {
            segment,
            capacity,
            mask: capacity - 1,
            next_seq: start_seq,
            topic_notify: None,
            notify_bucket,
            metrics: ReaderMetrics::new(),
        })
    }

    /// Attach with specific starting sequence (for replay)
    pub fn attach_from(
        name: &str,
        capacity: usize,
        notify_bucket: usize,
        start_seq: u64,
        expected_owner: Option<([u8; 16], u64)>,
    ) -> Result<Self> {
        let mut reader = Self::attach(name, capacity, notify_bucket, expected_owner)?;
        reader.next_seq = start_seq;
        Ok(reader)
    }

    /// Attach a topic notification for blocking waits
    pub fn with_notify(mut self, notify: TopicNotify) -> Self {
        self.topic_notify = Some(notify);
        self
    }

    /// Set topic notification after construction
    pub fn set_notify(&mut self, notify: TopicNotify) {
        self.topic_notify = Some(notify);
    }

    /// Whether this reader holds a topic notify handle (and with it a row in
    /// the segment's user table).
    #[cfg(test)]
    pub(crate) fn has_notify(&self) -> bool {
        self.topic_notify.is_some()
    }

    /// Get pointer to control block
    #[inline]
    fn control(&self) -> &ShmControl {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::open
        // - The segment size includes ShmControl at offset 0 (validated in attach())
        // - ShmControl requires 8-byte alignment; mmap provides page alignment
        // - ShmControl uses atomic fields for thread-safe access across processes
        // - The reference is valid for the lifetime of &self
        unsafe { &*(self.segment.as_ptr() as *const ShmControl) }
    }

    /// The segment's presence table: which remote participants have proven
    /// they are attached to this ring.
    ///
    /// SAFETY: the table lives at `presence_offset()`, inside the mapping
    /// whose size is `ring_segment_size(capacity)`; every field is an atomic
    /// integer, so concurrent access from the peer process is defined, and
    /// the kernel hands out zero-filled pages, which is the table's own
    /// "every entry free" state.
    pub fn presence(&self) -> &ShmPresence {
        unsafe { &*(self.segment.as_ptr().add(presence_offset()) as *const ShmPresence) }
    }

    /// Get pointer to slots array
    #[inline]
    fn slots(&self) -> *const ShmSlot {
        // SAFETY:
        // - segment.as_ptr() returns a valid pointer from ShmSegment::open
        // - Adding sizeof(ShmControl) bytes is within bounds because the segment was
        //   opened with size = sizeof(ShmControl) + capacity * sizeof(ShmSlot)
        // - ShmSlot is cache-aligned (64 bytes); ShmControl is also 64 bytes, so
        //   the slots array starts at a 64-byte aligned offset
        // - The pointer arithmetic does not overflow (segment sizes are bounded)
        unsafe { self.segment.as_ptr().add(slots_offset()) as *const ShmSlot }
    }

    /// Get a specific slot
    #[inline]
    fn slot(&self, index: usize) -> &ShmSlot {
        debug_assert!(index < self.capacity);
        // SAFETY:
        // - self.slots() returns a valid pointer to the start of the slots array
        // - index < self.capacity is asserted in debug mode and guaranteed by callers
        //   (index is computed as seq & mask where mask = capacity - 1)
        // - The slots array has exactly `capacity` elements, so index is in bounds
        // - ShmSlot uses atomic fields for thread-safe concurrent access
        // - The reference is valid for the lifetime of &self
        unsafe { &*self.slots().add(index) }
    }

    /// Validate the head message without copying it: its expected position,
    /// its sequence marker and its length.
    ///
    /// `None` means nothing can be read now: nothing to read, an overrun
    /// (counted and resynced), a slot not holding the wanted message, or a
    /// torn read / impossible length (counted as corrupted). The length is
    /// only trusted when the slot's marker is still the committed one after
    /// the length was loaded (seqlock: load marker, load length, fence, load
    /// marker again) and when it fits the slot payload.
    fn committed_head(&mut self) -> Option<(u64, usize)> {
        let head = self.control().get_head();

        // Overrun check: the writer has lapped us, so the oldest messages we
        // still wanted are gone. Resume at the OLDEST message that is still
        // intact, not at the newest one.
        //
        // Jumping to `head - 1` was throwing away up to `capacity - 2` samples
        // that were sitting in the ring, committed and readable, to recover
        // from as little as ONE that had actually been overwritten - and
        // reporting all of it as a single overrun. On a BEST_EFFORT path with
        // nothing to repair it, that turned a brief scheduling hiccup into a
        // ring-sized hole.
        //
        // Message `m` occupies slot `m & mask`, so it survives until `m +
        // capacity` is written. With `head` published, messages `head -
        // capacity ..= head - 1` are resident, and the writer is about to
        // overwrite the oldest of them with message `head`. So `head -
        // capacity + 1` is the oldest position that cannot be pulled out from
        // under us mid-copy; the seqlock re-check in the copy below catches
        // the boundary case anyway.
        if head.saturating_sub(self.next_seq) > self.capacity as u64 {
            let resume = head.saturating_sub(self.capacity as u64 - 1);
            let skipped = resume.saturating_sub(self.next_seq);
            self.next_seq = resume;
            self.metrics.overruns.fetch_add(1, Ordering::Relaxed);
            self.metrics
                .samples_skipped
                .fetch_add(skipped, Ordering::Relaxed);
            return None;
        }

        // Nothing to read
        if self.next_seq >= head {
            self.metrics.empty_polls.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let expected = self.next_seq;
        let idx = (expected as usize) & self.mask;
        let slot = self.slot(idx);
        let want = expected << 1; // Expected committed marker

        // 1. Check seq (must be committed, not in-progress)
        let seq1 = slot.seq.load(Ordering::Acquire);
        if seq1 != want {
            // The slot does not hold the message we are waiting for. WHICH
            // message it holds decides whether we wait or give up on ours.
            //
            // `seq >> 1` is the message this slot belongs to, in progress or
            // committed. If that is NEWER than the one we want, the writer has
            // already recycled the slot and our message is gone - waiting for
            // it is waiting forever.
            //
            // The lag check above does not cover this. `head = M` means
            // messages up to M-1 are COMMITTED and says nothing about whether
            // M has been started; at rest, a reader exactly `capacity` behind
            // is legitimately waiting for a message that is still intact,
            // which is why that test is `>` and must stay `>`. But a writer
            // that has started M and died before publishing leaves the odd
            // marker for M in the very slot a reader at M-capacity wants, with
            // `head` frozen at M. The lag stays at exactly `capacity` for ever,
            // so unless the reader resumes here it would return None on every
            // call from then on - no metric, no log, no progress, while 255
            // committed samples sat in the ring behind it and its presence
            // claim kept a slot in the writer's table for a peer draining
            // nothing.
            if (seq1 >> 1) > expected {
                let resume = head.saturating_sub(self.capacity as u64 - 1);
                let skipped = resume.saturating_sub(self.next_seq);
                self.next_seq = resume.max(expected + 1);
                self.metrics.overruns.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .samples_skipped
                    .fetch_add(skipped.max(1), Ordering::Relaxed);
                return None;
            }
            // Older, or not written yet: the writer simply has not reached us.
            return None;
        }

        // 2. Load the length, then check that the slot was not rewritten while
        // we loaded it. The Acquire fence orders the length load before the
        // second marker load (the marker load alone would not, see below), so
        // a length read from a slot being rewritten is caught here and never
        // reported as a message size.
        let len = slot.len.load(Ordering::Relaxed) as usize;
        std::sync::atomic::fence(Ordering::Acquire);
        if slot.seq.load(Ordering::Relaxed) != seq1 {
            self.metrics.corrupted.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // 3. A length beyond the slot payload is no message of this ring:
        // corruption, and it must never reach a buffer size or a copy.
        if len > SLOT_PAYLOAD_SIZE {
            self.metrics.corrupted.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some((expected, len))
    }

    /// Try to read the next message without blocking, reporting a message
    /// that does not fit `buf`.
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to copy payload into
    ///
    /// # Returns
    ///
    /// * `Ok(Some(len))` - Payload was copied, len bytes written
    /// * `Ok(None)` - No data available, or an overrun or torn read (counted
    ///   in the metrics)
    /// * `Err(len)` - The next message is `len` bytes (validated against the
    ///   slot payload size) and `buf` is shorter. Nothing is consumed and no
    ///   metric moves: the message stays first in the ring, so a retry with a
    ///   buffer of `len` bytes pops it.
    ///
    /// # Performance
    ///
    /// Target: < 100 ns per successful pop
    pub fn try_pop_sized(&mut self, buf: &mut [u8]) -> std::result::Result<Option<usize>, usize> {
        let Some((expected, len)) = self.committed_head() else {
            return Ok(None);
        };
        if len > buf.len() {
            return Err(len);
        }
        let idx = (expected as usize) & self.mask;
        let slot = self.slot(idx);
        let seq1 = expected << 1;

        // 3. Copy payload data (`len` is bounded by the slot payload above)
        // SAFETY:
        // - slot.payload is a valid UnsafeCell containing a byte array of SLOT_PAYLOAD_SIZE
        // - len <= buf.len() and len <= SLOT_PAYLOAD_SIZE were checked above
        // - The slot's sequence number indicates the data is committed (not in-progress)
        // - ptr::copy_nonoverlapping is safe because src and dst don't overlap
        //   (src is in shared memory, dst is caller's buffer)
        // - Both buffers are properly aligned for u8 (alignment of 1)
        // - Note: A torn read is possible if writer overwrites during copy, but we
        //   detect this by re-checking the sequence number after the copy
        unsafe {
            let src = (*slot.payload.get()).as_ptr();
            ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), len);
        }

        // The load-load half of the seqlock barrier pair, and the reason the
        // re-check below is a Relaxed load rather than an Acquire one.
        //
        // `Acquire` on the re-check would be the WRONG DIRECTION: an acquire
        // load stops LATER accesses from moving before it, but says nothing
        // about EARLIER ones. The payload copy above is exactly such an
        // earlier access, so compiler and CPU are both free to sink it past
        // the re-check. Sunk, the copy runs after `seq2` was sampled, the
        // comparison passes on a value read before the writer touched the
        // slot, and the torn read this check exists to catch is accepted.
        //
        // An Acquire FENCE orders prior loads against subsequent loads, which
        // is the guarantee actually needed here. With the fence in place the
        // re-check itself needs no ordering of its own.
        std::sync::atomic::fence(Ordering::Acquire);

        // 4. Re-check seq (detect torn read - slot was overwritten during copy)
        let seq2 = slot.seq.load(Ordering::Relaxed);
        if seq2 != seq1 {
            self.metrics.corrupted.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        // Success!
        self.next_seq = expected + 1;
        self.metrics.messages_read.fetch_add(1, Ordering::Relaxed);
        Ok(Some(len))
    }

    /// Consume the next message without copying it, but only when it is
    /// longer than `max_len`: the out-of-contract skip of a caller whose
    /// buffer cannot hold it. Returns its length. A message that fits is left
    /// in the ring (`None`), and so is nothing else.
    pub fn discard_if_longer(&mut self, max_len: usize) -> Option<usize> {
        let (expected, len) = self.committed_head()?;
        if len <= max_len {
            return None;
        }
        self.next_seq = expected + 1;
        self.metrics
            .oversize_skipped
            .fetch_add(1, Ordering::Relaxed);
        Some(len)
    }

    /// Try to read the next message without blocking.
    ///
    /// Returns the payload length, or `None` when no message was popped. A
    /// message longer than `buf` is NOT consumed: it stays first in the ring,
    /// and every call with the same buffer counts it as corrupt and returns
    /// `None`, so this reader stalls on it until the writer laps it. Callers
    /// that can grow their buffer use
    /// [`try_pop_sized`](Self::try_pop_sized), which reports the length.
    pub fn try_pop(&mut self, buf: &mut [u8]) -> Option<usize> {
        match self.try_pop_sized(buf) {
            Ok(popped) => popped,
            Err(_) => {
                // Historical contract of this method: an over-long message is
                // counted as corruption. The sized form does not count it.
                self.metrics.corrupted.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Read next message, blocking until available.
    ///
    /// Uses double-check pattern to avoid lost wakes:
    /// 1. Poll for data
    /// 2. Snapshot notify counter
    /// 3. Re-poll (catches race)
    /// 4. If still no data, wait on futex
    ///
    /// # Arguments
    ///
    /// * `buf` - Buffer to copy payload into
    /// * `timeout` - Optional timeout duration
    ///
    /// # Returns
    ///
    /// * `Some(len)` - Payload was copied
    /// * `None` - Timeout expired
    pub fn take_blocking(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Option<usize> {
        // Check if we have notify - if not, fallback to spinning
        if self.topic_notify.is_none() {
            return self.take_spinning(buf, timeout);
        }

        let deadline = timeout.map(|t| std::time::Instant::now() + t);
        let bucket_idx = self.notify_bucket;

        loop {
            // 1. Poll for data
            if let Some(len) = self.try_pop(buf) {
                return Some(len);
            }

            // 2. Snapshot notify counter
            // SAFETY: We checked topic_notify.is_some() at the start of the function
            let snapshot = self
                .topic_notify
                .as_ref()
                .map(|tn| tn.bucket(bucket_idx).snapshot());

            let snapshot = snapshot?;

            // 3. Re-poll (anti lost-wake)
            if let Some(len) = self.try_pop(buf) {
                return Some(len);
            }

            // 4. Calculate remaining timeout
            let remaining = match deadline {
                Some(d) => {
                    let now = std::time::Instant::now();
                    if now >= d {
                        return None; // Timeout expired
                    }
                    Some(d - now)
                }
                None => None,
            };

            // 5. Wait on futex
            if let Some(ref topic_notify) = self.topic_notify {
                topic_notify.wait(bucket_idx, snapshot, remaining);
            }
        }
    }

    /// Fallback blocking read using spinning with sleep
    fn take_spinning(&mut self, buf: &mut [u8], timeout: Option<Duration>) -> Option<usize> {
        let deadline = timeout.map(|t| std::time::Instant::now() + t);
        let spin_count = 1000;

        loop {
            // Spin first
            for _ in 0..spin_count {
                if let Some(len) = self.try_pop(buf) {
                    return Some(len);
                }
                std::hint::spin_loop();
            }

            // Check timeout
            if let Some(d) = deadline {
                if std::time::Instant::now() >= d {
                    return None;
                }
            }

            // Sleep briefly
            std::thread::sleep(Duration::from_micros(10));
        }
    }

    /// Get current read position
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.next_seq
    }

    /// Get number of messages available to read
    #[must_use]
    pub fn available(&self) -> u64 {
        let head = self.control().get_head();
        head.saturating_sub(self.next_seq)
    }

    /// Check if any data is available
    #[must_use]
    pub fn has_data(&self) -> bool {
        self.available() > 0
    }
}

#[cfg(test)]
#[path = "ring_test.rs"]
mod tests;

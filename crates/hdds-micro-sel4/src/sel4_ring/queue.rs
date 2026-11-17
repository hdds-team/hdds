// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! sDDF queue handles - the unsafe surface of `Sel4Ring`.
//!
//! This module holds the raw-pointer and FFI code. The crate-level lint
//! is `#![deny(unsafe_code)]`; the only exceptions are the inner
//! `#![allow(unsafe_code)]` here and in the parent `sel4_ring` module,
//! whose `Sel4Ring::new` calls the `unsafe` handle constructors.
//!
//! Layout assertions (structs match `sddf/network/queue.h:16-32` byte
//! for byte) fire at compile time on every `cargo check` regardless of
//! whether the `microkit` feature is enabled, so an accidental ABI
//! drift is caught immediately and not only when cross-compiling for
//! seL4.
//!
//! The host tests here are single-threaded; cross-PD concurrency is
//! only exercised by running the PDs under QEMU. No `loom`-style
//! exhaustive interleaving check exists.
//!
//! The memory-ordering choices follow the sDDF producer/consumer
//! signalling protocol; see the per-method comments for the recipe.

#![allow(unsafe_code)]
#![allow(dead_code)]

use core::ptr::NonNull;
use core::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// sDDF network queue header - matches `net_queue_t` in
/// `sddf/network/queue.h:25-31`.
///
/// `#[repr(C, align(8))]` guarantees the same field offsets the C side
/// computes (the descriptors that follow need 8-byte alignment).
/// `buffers[]` is the C flexible array member; we access it via raw
/// pointer arithmetic right after the header.
#[repr(C, align(8))]
pub(super) struct NetQueueHeader {
    /// Producer's cursor. SeqCst-written by the producer end on
    /// publish; SeqCst- / Acquire-read by the consumer end on peek and
    /// the empty-recheck.
    pub tail: AtomicU16,
    /// Consumer's cursor. SeqCst-written by the consumer end on commit;
    /// Acquire-read by the producer end on full-check.
    pub head: AtomicU16,
    /// Notification flag - `0` = "consumer wants a notify", `1` = "no
    /// signal needed". The producer SeqCst-loads it before publish;
    /// when seen as `0` it SeqCst-stores `1` and calls
    /// `microkit_notify`. Encoded inverted vs. the obvious sense for
    /// historical sDDF reasons.
    pub consumer_signalled: AtomicU32,
    // `buffers[]` starts at offset 8 - accessed via pointer arithmetic.
}

/// sDDF descriptor - matches `net_buff_desc_t` in
/// `sddf/network/queue.h:16-20`.
///
/// The wire field is `io_or_offset`; on the client side (`Sel4Ring`)
/// it always carries the offset form.
/// The trailing 6 bytes of padding are emitted implicitly by `repr(C)`
/// so the struct is 16 bytes / 8-byte aligned.
#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct NetBuffDesc {
    /// Offset (in bytes) into the data region. The `len` field carries
    /// the payload length in active-queue slots; in free-queue slots
    /// it is `0`.
    pub offset: u64,
    /// Payload length. 0 for free-queue enqueues, >0 for active.
    pub len: u16,
    // 6 bytes implicit trailing pad (sizeof = 16, align = 8).
}

// Compile-time ABI lock: anything that drifts will refuse to build.
// The explicit `offset_of!` asserts below matter: a field reorder that
// preserves total size would otherwise pass the size/align checks
// silently and break the wire ABI.
const _: () = {
    assert!(core::mem::size_of::<NetQueueHeader>() == 8);
    assert!(core::mem::align_of::<NetQueueHeader>() == 8);
    assert!(core::mem::offset_of!(NetQueueHeader, tail) == 0);
    assert!(core::mem::offset_of!(NetQueueHeader, head) == 2);
    assert!(core::mem::offset_of!(NetQueueHeader, consumer_signalled) == 4);

    assert!(core::mem::size_of::<NetBuffDesc>() == 16);
    assert!(core::mem::align_of::<NetBuffDesc>() == 8);
    assert!(core::mem::offset_of!(NetBuffDesc, offset) == 0);
    assert!(core::mem::offset_of!(NetBuffDesc, len) == 8);
};

/// A slot peeked or claimed off either end of a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Slot {
    /// Offset (bytes) into the data region.
    pub offset: u64,
    /// Payload length. `0` for free-queue slots.
    pub len: u16,
}

/// Verdict returned by [`ConsumerHandle::request_signal_with_recheck`].
///
/// Modelled as an enum (not `Result`): a `?` propagation site at the
/// call point would silently bury the `Continue` case behind a generic
/// "empty" error and re-introduce a drain stall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DrainVerdict {
    /// The producer raced our request; `consumer_signalled` was
    /// restored to `1` and the caller MUST loop back to a fresh peek.
    Continue,
    /// Queue is truly empty; `consumer_signalled` is left at `0`. The
    /// caller may park; the next producer publish will notify us.
    Sleep,
}

// Issue a Microkit channel notification.
//
// Concrete FFI when built with `feature = "microkit"`; a no-op stub on
// host (the binding compiles cleanly so its state-transition logic
// stays host-testable, but the wakeup itself is a Microkit syscall
// that does not exist outside a PD).
//
// The Microkit SDK ships `microkit_notify` as `static inline` in
// `<microkit.h>` - so there is no linker symbol to bind to. The C
// wrapper at `crates/hdds-micro-sel4/microkit/client2_rust_wrapper.c` re-exports it
// as `hdds_microkit_notify`, which DOES emit a linker symbol; that is
// what we declare here.
#[cfg(feature = "microkit")]
unsafe extern "C" {
    fn hdds_microkit_notify(ch: u32);
}

#[cfg(feature = "microkit")]
fn do_notify(channel_id: u32) {
    // SAFETY: `hdds_microkit_notify` is a Microkit-provided thunk that
    // wraps the SDK's inline `microkit_notify`. `channel_id` is the
    // value handed to us by the C wrapper from the
    // `.net_client_config` blob - a runtime-validated u32.
    unsafe { hdds_microkit_notify(channel_id) }
}

// Host-test observation of issued notifications. Thread-local, because
// each `cargo test` case runs on its own thread.
#[cfg(all(not(feature = "microkit"), test, feature = "std"))]
thread_local! {
    pub(super) static HOST_NOTIFIES: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

#[cfg(not(feature = "microkit"))]
fn do_notify(_channel_id: u32) {
    // Host build - no syscall. Tests count the calls instead.
    #[cfg(all(test, feature = "std"))]
    HOST_NOTIFIES.with(|c| c.set(c.get() + 1));
}

/// Producer-side handle on an SPSC sDDF queue.
///
/// Owns the `local_tail` cursor (we are the sole writer of `tail` in
/// shared memory). `header` points into a region the caller mapped at
/// init via the sDDF resource blob.
pub(super) struct ProducerHandle {
    header: NonNull<NetQueueHeader>,
    capacity: u16,
    local_tail: u16,
    channel_id: u32,
}

impl ProducerHandle {
    /// Wrap a shared-memory queue header.
    ///
    /// # Safety
    /// - `header` MUST point to a writable `NetQueueHeader` mapped into
    ///   the current PD's address space.
    /// - `header` MUST be followed by `capacity` `NetBuffDesc` slots
    ///   (the C flexible array member).
    /// - `capacity` MUST be a power of two and <= 32768.
    /// - There MUST be exactly one `ProducerHandle` for this queue
    ///   instance in the PD at any given time.
    pub unsafe fn new(header: NonNull<NetQueueHeader>, capacity: u16, channel_id: u32) -> Self {
        // SAFETY: caller asserted `header` validity.
        let local_tail = unsafe { header.as_ref().tail.load(Ordering::Acquire) };
        Self {
            header,
            capacity,
            local_tail,
            channel_id,
        }
    }

    fn header(&self) -> &NetQueueHeader {
        // SAFETY: invariant from `new`.
        unsafe { self.header.as_ref() }
    }

    fn buffers_ptr_mut(&self) -> *mut NetBuffDesc {
        let base = self.header.as_ptr() as *mut u8;
        // SAFETY: pointer arithmetic stays inside the shared region the
        // caller guaranteed at `new` time (header + capacity * 16 bytes).
        unsafe { base.add(core::mem::size_of::<NetQueueHeader>()) as *mut NetBuffDesc }
    }

    /// True if the queue cannot accept another descriptor.
    pub fn is_full(&self) -> bool {
        let head = self.header().head.load(Ordering::Acquire);
        self.local_tail.wrapping_sub(head) >= self.capacity
    }

    /// Publish a descriptor at `buffers[local_tail % cap]`, then
    /// SeqCst-store `tail += 1`.
    ///
    /// Returns `false` if the queue is full (no descriptor written, no
    /// cursor bump). Caller (e.g. `Sel4Ring::enqueue_tx`) maps this
    /// to `RingError::Full`.
    ///
    /// Memory ordering: the descriptor bytes are written with a
    /// `write_volatile` (Relaxed) and ordered with respect to the
    /// other side by the subsequent SeqCst tail store. The sDDF
    /// producer recipe relies on this single SeqCst store to
    /// publish both the descriptor and the cursor.
    pub fn publish(&mut self, offset: u64, len: u16) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = (self.local_tail % self.capacity) as usize;
        let desc = NetBuffDesc { offset, len };
        // SAFETY: idx < capacity (modulo); `buffers_ptr_mut` is valid
        // per `new`'s invariant.
        unsafe {
            core::ptr::write_volatile(self.buffers_ptr_mut().add(idx), desc);
        }
        let new_tail = self.local_tail.wrapping_add(1);
        self.header().tail.store(new_tail, Ordering::SeqCst);
        self.local_tail = new_tail;
        true
    }

    /// Producer notify recipe.
    ///
    /// Steps:
    /// 1. SeqCst-load `consumer_signalled`.
    /// 2. If `0`: SeqCst-store `1` (mandatory cancel-before-notify),
    ///    then issue the Microkit notification.
    /// 3. If `1`: nothing to do - consumer is already draining or
    ///    has explicitly disabled notifications for this round.
    pub fn maybe_notify_seqcst(&self) {
        let sig = self.header().consumer_signalled.load(Ordering::SeqCst);
        if sig == 0 {
            self.header().consumer_signalled.store(1, Ordering::SeqCst);
            do_notify(self.channel_id);
        }
    }

    /// Current cached `local_tail`. Used by tests / observability.
    pub fn local_tail(&self) -> u16 {
        self.local_tail
    }
}

/// Consumer-side handle on an SPSC sDDF queue.
///
/// Owns the `local_head` cursor (we are the sole writer of `head` in
/// shared memory). `peek_acquire` synchronises with the producer's
/// SeqCst tail store via an Acquire load.
pub(super) struct ConsumerHandle {
    header: NonNull<NetQueueHeader>,
    capacity: u16,
    local_head: u16,
    channel_id: u32,
}

impl ConsumerHandle {
    /// Wrap a shared-memory queue header.
    ///
    /// # Safety
    /// Same invariants as [`ProducerHandle::new`]; in addition the
    /// caller MUST guarantee there is exactly one `ConsumerHandle` for
    /// this queue instance.
    pub unsafe fn new(header: NonNull<NetQueueHeader>, capacity: u16, channel_id: u32) -> Self {
        // SAFETY: caller asserted `header` validity.
        let local_head = unsafe { header.as_ref().head.load(Ordering::Acquire) };
        Self {
            header,
            capacity,
            local_head,
            channel_id,
        }
    }

    fn header(&self) -> &NetQueueHeader {
        // SAFETY: invariant from `new`.
        unsafe { self.header.as_ref() }
    }

    fn buffers_ptr(&self) -> *const NetBuffDesc {
        let base = self.header.as_ptr() as *const u8;
        // SAFETY: pointer arithmetic stays inside the shared region.
        unsafe { base.add(core::mem::size_of::<NetQueueHeader>()) as *const NetBuffDesc }
    }

    /// Peek the next slot without committing.
    ///
    /// Consumer recipe step 1: Acquire-load `tail`; if equal to
    /// `local_head`, the queue is empty. Otherwise the Acquire
    /// synchronises with the producer's SeqCst tail store, so the
    /// descriptor bytes that were written before that store are
    /// visible.
    pub fn peek_acquire(&self) -> Option<Slot> {
        let tail = self.header().tail.load(Ordering::Acquire);
        if tail == self.local_head {
            return None;
        }
        let idx = (self.local_head % self.capacity) as usize;
        // SAFETY: idx < capacity; the Acquire load synchronises with
        // the producer's SeqCst tail store, so the descriptor is fully
        // initialised by the time we read it.
        let desc = unsafe { core::ptr::read_volatile(self.buffers_ptr().add(idx)) };
        Some(Slot {
            offset: desc.offset,
            len: desc.len,
        })
    }

    /// Commit the previously peeked slot - SeqCst-store `head += 1`.
    pub fn commit_seqcst(&mut self) {
        let new_head = self.local_head.wrapping_add(1);
        self.header().head.store(new_head, Ordering::SeqCst);
        self.local_head = new_head;
    }

    /// Consumer on-empty recipe.
    ///
    /// 1. SeqCst-store `consumer_signalled = 0` (request a signal).
    /// 2. SeqCst-load `tail` (the double-check).
    /// 3. If `tail` moved past `local_head` while we were storing,
    ///    the producer raced us with a publish that did not see our
    ///    "wants notify" flag yet; cancel the request (SeqCst-store
    ///    `consumer_signalled = 1`) and return [`DrainVerdict::Continue`].
    /// 4. Else the queue is truly empty; return [`DrainVerdict::Sleep`].
    ///    We are guaranteed to be notified by the producer's recipe
    ///    when the next publish lands.
    ///
    /// The SeqCst on both atomics is mandatory - Release/Acquire alone
    /// leaves a StoreLoad gap on independent locations that lets both
    /// sides conclude "the other side already observed me", causing a
    /// deadlock.
    pub fn request_signal_with_recheck(&self) -> DrainVerdict {
        self.header()
            .consumer_signalled
            .store(0, Ordering::SeqCst);
        let tail_now = self.header().tail.load(Ordering::SeqCst);
        if tail_now != self.local_head {
            self.header()
                .consumer_signalled
                .store(1, Ordering::SeqCst);
            DrainVerdict::Continue
        } else {
            DrainVerdict::Sleep
        }
    }

    /// Current cached `local_head`. Used by tests / observability.
    pub fn local_head(&self) -> u16 {
        self.local_head
    }
}

/// Safe wrapper around an sDDF data region (the payload bytes pointed
/// at by descriptor offsets).
///
/// The unsafe pointer + size are captured at construction; every slice
/// accessor bounds-checks `offset + len` against `size`, so the public
/// API is fully safe.
pub(super) struct DataRegion {
    base: NonNull<u8>,
    size: usize,
}

impl DataRegion {
    /// Wrap a shared data region.
    ///
    /// # Safety
    /// - `base` MUST point to a writable region of at least `size`
    ///   bytes mapped into the current PD.
    /// - The region MUST stay mapped for the lifetime of this handle.
    /// - For TX data regions: the binding is the sole writer.
    ///   For RX data regions: the copy component is the sole writer;
    ///   the binding is read-only - `slice_mut` MUST NOT be called.
    pub unsafe fn new(base: NonNull<u8>, size: usize) -> Self {
        Self { base, size }
    }

    /// Borrow `[offset .. offset + len]` as a read-only slice.
    /// Returns `None` if the range is out of bounds.
    pub fn slice(&self, offset: u64, len: u16) -> Option<&[u8]> {
        let off = offset as usize;
        let n = len as usize;
        let end = off.checked_add(n)?;
        if end > self.size {
            return None;
        }
        // SAFETY: bounds checked just above; `base` validity from `new`.
        Some(unsafe { core::slice::from_raw_parts(self.base.as_ptr().add(off), n) })
    }

    /// Borrow `[offset .. offset + cap]` as a writable slice.
    ///
    /// Used when filling a TX buffer; `cap` is typically the full slot
    /// size (NET_BUFFER_SIZE) since we don't know the final frame
    /// length until after we've built it. Returns `None` if the range
    /// is out of bounds.
    pub fn slice_mut(&mut self, offset: u64, cap: usize) -> Option<&mut [u8]> {
        let off = offset as usize;
        let end = off.checked_add(cap)?;
        if end > self.size {
            return None;
        }
        // SAFETY: bounds checked; `base` validity from `new`; we are
        // the sole writer per `new`'s invariant.
        Some(unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr().add(off), cap) })
    }

    /// Region size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Allocate a queue header + descriptor table on the heap, with
    // an explicit 8-byte alignment guarantee (a plain
    // `Box<[u8]>` is only u8-aligned by language semantics; casting
    // its pointer to `*mut NetQueueHeader` is UB unless the allocator
    // happens to return >=8-aligned blocks, which is allocator-specific
    // luck on x86_64 glibc and not portable to strict-align targets).
    // Backing it with `Vec<u64>` makes the alignment a language-level
    // guarantee.
    struct QueueArena {
        _backing: Vec<u64>,
        ptr: NonNull<NetQueueHeader>,
    }

    fn make_arena(capacity: u16) -> QueueArena {
        let bytes = core::mem::size_of::<NetQueueHeader>()
            + (capacity as usize) * core::mem::size_of::<NetBuffDesc>();
        // Round up to whole u64 words; zero-init mirrors the Microkit
        // loader's pre-PD wipe.
        let words = bytes.div_ceil(core::mem::size_of::<u64>());
        let mut backing: Vec<u64> = vec![0u64; words];
        let raw = backing.as_mut_ptr() as *mut NetQueueHeader;
        // SAFETY: `backing` holds `words * 8 >= bytes` zero bytes
        // contiguously, 8-aligned by the language guarantee on
        // `Vec<u64>`. `raw` stays valid as long as `backing` lives.
        let ptr = NonNull::new(raw).expect("non-null Vec pointer");
        QueueArena { _backing: backing, ptr }
    }

    #[test]
    fn header_layout_matches_sddf_abi() {
        // These also fire as compile-time `const _: ()` asserts above,
        // but a runtime check keeps the failure message tidier if the
        // pointer cast/offset logic ever drifts.
        assert_eq!(core::mem::size_of::<NetQueueHeader>(), 8);
        assert_eq!(core::mem::align_of::<NetQueueHeader>(), 8);
        assert_eq!(core::mem::size_of::<NetBuffDesc>(), 16);
    }

    #[test]
    fn producer_consumer_single_threaded_roundtrip() {
        let arena = make_arena(4);
        // SAFETY: arena was just allocated with the right size +
        // alignment; capacity=4 is power-of-two and small.
        let mut p = unsafe { ProducerHandle::new(arena.ptr, 4, 99) };
        let mut c = unsafe { ConsumerHandle::new(arena.ptr, 4, 99) };

        assert!(c.peek_acquire().is_none(), "fresh queue must be empty");
        assert!(!p.is_full());

        assert!(p.publish(0x1000, 42));
        let slot = c.peek_acquire().expect("producer just published");
        assert_eq!(slot.offset, 0x1000);
        assert_eq!(slot.len, 42);
        c.commit_seqcst();
        assert!(c.peek_acquire().is_none());
    }

    #[test]
    fn producer_fills_then_blocks_on_full() {
        let arena = make_arena(4);
        let mut p = unsafe { ProducerHandle::new(arena.ptr, 4, 1) };

        for i in 0..4 {
            assert!(p.publish(i as u64, 0), "publish {i} should succeed");
        }
        assert!(p.is_full());
        assert!(
            !p.publish(99, 0),
            "publish into full queue must refuse"
        );
    }

    #[test]
    fn request_signal_returns_continue_when_producer_races() {
        let arena = make_arena(4);
        let mut p = unsafe { ProducerHandle::new(arena.ptr, 4, 1) };
        let c = unsafe { ConsumerHandle::new(arena.ptr, 4, 1) };

        // Producer publishes BEFORE the consumer requests a signal.
        // The race in the real protocol is between consumer's
        // store(consumer_signalled=0) and producer's store(tail). Here
        // we just simulate the post-state: tail has moved while
        // local_head has not.
        p.publish(0xdead_beef, 13);
        let verdict = c.request_signal_with_recheck();
        assert_eq!(verdict, DrainVerdict::Continue);
        // Cancel-restore: consumer_signalled MUST be back to 1.
        let sig = unsafe { arena.ptr.as_ref().consumer_signalled.load(Ordering::SeqCst) };
        assert_eq!(sig, 1);
    }

    #[test]
    fn request_signal_returns_sleep_when_truly_empty() {
        let arena = make_arena(4);
        let c = unsafe { ConsumerHandle::new(arena.ptr, 4, 1) };
        let verdict = c.request_signal_with_recheck();
        assert_eq!(verdict, DrainVerdict::Sleep);
        // Wants-notify flag left at 0.
        let sig = unsafe { arena.ptr.as_ref().consumer_signalled.load(Ordering::SeqCst) };
        assert_eq!(sig, 0);
    }

    #[test]
    fn maybe_notify_cancels_signal_when_consumer_wants_it() {
        let arena = make_arena(4);
        let p = unsafe { ProducerHandle::new(arena.ptr, 4, 7) };
        // Consumer requested a signal (= 0).
        unsafe {
            arena.ptr.as_ref().consumer_signalled.store(0, Ordering::SeqCst);
        }
        p.maybe_notify_seqcst();
        // consumer_signalled MUST be 1 after the producer recipe.
        let sig = unsafe { arena.ptr.as_ref().consumer_signalled.load(Ordering::SeqCst) };
        assert_eq!(sig, 1, "cancel-before-notify must store 1");
    }

    #[test]
    fn maybe_notify_skips_when_consumer_already_silenced() {
        let arena = make_arena(4);
        let p = unsafe { ProducerHandle::new(arena.ptr, 4, 7) };
        // Consumer already silenced - nothing to do.
        unsafe {
            arena.ptr.as_ref().consumer_signalled.store(1, Ordering::SeqCst);
        }
        p.maybe_notify_seqcst();
        // Still 1 - no spurious store.
        let sig = unsafe { arena.ptr.as_ref().consumer_signalled.load(Ordering::SeqCst) };
        assert_eq!(sig, 1);
    }

    #[test]
    fn multiple_publish_then_drain_preserves_order() {
        let arena = make_arena(4);
        let mut p = unsafe { ProducerHandle::new(arena.ptr, 4, 0) };
        let mut c = unsafe { ConsumerHandle::new(arena.ptr, 4, 0) };

        for i in 0..3 {
            assert!(p.publish((i as u64) * 0x100, 10 + i));
        }
        for i in 0..3 {
            let s = c.peek_acquire().expect("slot");
            assert_eq!(s.offset, (i as u64) * 0x100);
            assert_eq!(s.len, 10 + i);
            c.commit_seqcst();
        }
        assert!(c.peek_acquire().is_none());
    }

    #[test]
    fn data_region_slice_bounds_check() {
        let mut backing = vec![0xAAu8; 64].into_boxed_slice();
        let base = NonNull::new(backing.as_mut_ptr()).unwrap();
        let mut region = unsafe { DataRegion::new(base, 64) };
        // In bounds.
        let s = region.slice(0, 16).unwrap();
        assert_eq!(s.len(), 16);
        assert!(s.iter().all(|&b| b == 0xAA));
        // Right at the edge.
        assert!(region.slice(48, 16).is_some());
        // Crossing the boundary.
        assert!(region.slice(56, 16).is_none());
        // Past the end.
        assert!(region.slice(64, 1).is_none());
        // Zero-len at edge is OK.
        assert!(region.slice(64, 0).is_some());
        // slice_mut symmetric.
        assert!(region.slice_mut(0, 64).is_some());
        assert!(region.slice_mut(1, 64).is_none());
    }

    #[test]
    fn wraparound_with_capacity_power_of_two() {
        let arena = make_arena(2);
        let mut p = unsafe { ProducerHandle::new(arena.ptr, 2, 0) };
        let mut c = unsafe { ConsumerHandle::new(arena.ptr, 2, 0) };

        // Push 2 (full), drain 2, push 2 more - the cursors should
        // wrap modulo cap and the consumer should see the new slots.
        for i in 0..2 {
            assert!(p.publish(0xAA00 + i as u64, i));
        }
        for i in 0..2 {
            let s = c.peek_acquire().unwrap();
            assert_eq!(s.offset, 0xAA00 + i as u64);
            c.commit_seqcst();
        }
        for i in 0..2 {
            assert!(p.publish(0xBB00 + i as u64, 100 + i));
        }
        for i in 0..2 {
            let s = c.peek_acquire().unwrap();
            assert_eq!(s.offset, 0xBB00 + i as u64);
            assert_eq!(s.len, 100 + i);
            c.commit_seqcst();
        }
        assert!(c.peek_acquire().is_none());
    }
}

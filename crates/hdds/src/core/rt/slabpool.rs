// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Lock-free slab allocator for zero-copy message buffers.
//!
//! Provides O(1) allocation from size-class pools using atomic bitmaps.
//! Supports 14 size classes from 16B to 128KB.
//!
//! # Performance
//!
//! - reserve: < 30 ns (p99)
//! - release: < 30 ns (p99)

use crate::core::rt::slabpool_metrics::SlabPoolMetrics;
use crate::qos::MemoryPolicy;
use parking_lot::Mutex;
use std::borrow::Cow;
use std::cell::UnsafeCell;
use std::convert::TryFrom;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Allocation tier that produced a successful `reserve_and_write` call.
///
/// Used by the caller to bump the matching counter without forcing
/// the pool itself to depend on the metrics layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub(crate) enum SlabMetric {
    /// Reserved from the primary 14-class pool.
    Primary,
    /// Reserved from the secondary opt-in large pool.
    Large,
    /// Reserved from the heap fallback tier.
    HeapFallback,
}

/// Whose storage a reservation is, which decides what of the pool it may
/// take (see [`MemoryPolicy::reader_reserve_percent`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Claim {
    /// A writer's: its history (unacknowledged changes, retained ones), the
    /// intra-process leg it pushes into co-located readers' rings, a
    /// replay. It never takes the share of each tier kept for readers.
    Writer,
    /// A sample a reader received from the network, stored before it is
    /// acknowledged: it may take every tier whole, the reader's share
    /// included.
    Reader,
    /// The head of a reliable reader's stream: the next sample of a writer,
    /// in order, the one that releases the samples its reorder gate holds
    /// above it, and whose acknowledgement frees its writer's history. A
    /// reader's claim that, when every tier is full, takes the heap tier
    /// past `max_heap_bytes` by this one sample, provided the tier is not
    /// past it already. Refused, the held samples waited for it, and it for
    /// their storage (the room held storage keeps for it is an estimate),
    /// or for a co-located writer's history at its ceiling that only its
    /// acknowledgement frees (a readers' share smaller than one sample),
    /// for good. So the heap tier's gauge may exceed `max_heap_bytes` by
    /// at most one sample, a head, at any time.
    Head,
}

/// Handle to a reserved slab region.
///
/// Packed 4-byte handle covering the three allocation tiers. The top
/// two bits select the tier, the low 30 bits address storage within
/// that tier:
///
/// | tag (bits 31..30) | tier    | payload layout                             |
/// |-------------------|---------|--------------------------------------------|
/// | `0b00`            | Primary | `pool_id` (bits 29..16), `slot_id` (15..0) |
/// | `0b01`            | Large   | `pool_id` (bits 29..16), `slot_id` (15..0) |
/// | `0b10`            | Heap    | `heap_id` (bits 29..0)                     |
/// | `0b11`            | EMPTY   | sentinel (`0xFFFF_FFFF` only)              |
///
/// Keeping the handle at 4 bytes keeps `IndexEntry` at its 24-byte hot
/// stride on the intra-process merger ring (an 8-byte enum shape would
/// push the entry to 32 bytes). Decode via [`SlabHandle::unpack`],
/// which yields the [`SlabRef`] view for tier dispatch; the payload
/// bounds are generous (16 384 pools x 65 536 slots per tier; the
/// bitmap allocator itself caps `slot_id` at 63).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlabHandle(u32);

/// Decoded view of a [`SlabHandle`] (see the packing table there).
///
/// Produced by [`SlabHandle::unpack`]; never stored. Tier dispatch
/// sites match on this enum while the 4-byte packed handle travels
/// through rings and caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabRef {
    /// Slot in the primary 14-class pool (everyday traffic, <=128 KB).
    Primary { pool_id: u16, slot_id: u16 },
    /// Slot in the secondary opt-in large pool (configured per-participant).
    Large { pool_id: u16, slot_id: u16 },
    /// Heap-allocated buffer indexed by `heap_id` into the pool's
    /// `heap_buffers` vector.
    Heap { heap_id: u32 },
}

/// Tier tag shift (top two bits of the packed handle).
const TAG_SHIFT: u32 = 30;
/// Tier tags (see the packing table on [`SlabHandle`]).
const TAG_PRIMARY: u32 = 0b00;
const TAG_LARGE: u32 = 0b01;
const TAG_HEAP: u32 = 0b10;
/// Largest pool index representable in the packed handle (14 bits).
const MAX_POOL_ID: u32 = 0x3FFF;
/// Largest heap id representable in the packed handle (30 bits).
const MAX_HEAP_ID: u32 = 0x3FFF_FFFF;

impl SlabHandle {
    /// Sentinel value used by `IndexEntry::default()` and event entries
    /// to mark "no buffer associated". Uses the reserved `0b11` tag, so
    /// it can never collide with a real allocation in any tier.
    pub const EMPTY: SlabHandle = SlabHandle(u32::MAX);

    /// Returns true if this handle is the `EMPTY` sentinel.
    #[inline]
    pub fn is_empty(self) -> bool {
        self.0 == u32::MAX
    }

    /// Pack a `Primary` handle. `pool_id` is bounded by the size-class
    /// table (14 classes) and `slot_id` by the 64-bit bitmap (<= 63);
    /// both fit their fields with room to spare.
    #[inline]
    fn primary(pool_id: u16, slot_id: u16) -> Self {
        debug_assert!(
            u32::from(pool_id) <= MAX_POOL_ID,
            "pool_id overflows tag field"
        );
        SlabHandle((TAG_PRIMARY << TAG_SHIFT) | (u32::from(pool_id) << 16) | u32::from(slot_id))
    }

    /// Pack a `Large` handle (same field layout as `Primary`).
    #[inline]
    fn large(pool_id: u16, slot_id: u16) -> Self {
        debug_assert!(
            u32::from(pool_id) <= MAX_POOL_ID,
            "pool_id overflows tag field"
        );
        SlabHandle((TAG_LARGE << TAG_SHIFT) | (u32::from(pool_id) << 16) | u32::from(slot_id))
    }

    /// Pack a `Heap` handle. Callers enforce `heap_id <= MAX_HEAP_ID`
    /// before allocating the id (see `try_reserve_heap_and_copy`).
    #[inline]
    fn heap(heap_id: u32) -> Self {
        debug_assert!(heap_id <= MAX_HEAP_ID, "heap_id overflows tag field");
        SlabHandle((TAG_HEAP << TAG_SHIFT) | heap_id)
    }

    /// Decode the packed handle into its tier view. `#[inline]` so tier
    /// dispatch compiles down to a shift + masked extraction at every
    /// hot call site (get_buffer / release on the intra-process path).
    #[inline]
    pub fn unpack(self) -> SlabRef {
        let bits = self.0;
        match bits >> TAG_SHIFT {
            // Masked extraction: pool_id is 14 bits, slot_id the low 16.
            // Values are produced by the packing constructors above, so
            // the casts cannot truncate meaningful bits.
            TAG_PRIMARY => SlabRef::Primary {
                pool_id: ((bits >> 16) & MAX_POOL_ID) as u16,
                slot_id: (bits & 0xFFFF) as u16,
            },
            TAG_LARGE => SlabRef::Large {
                pool_id: ((bits >> 16) & MAX_POOL_ID) as u16,
                slot_id: (bits & 0xFFFF) as u16,
            },
            TAG_HEAP => SlabRef::Heap {
                heap_id: bits & MAX_HEAP_ID,
            },
            // Reserved tag (EMPTY sentinel). Surface as an out-of-range
            // Primary view so misuse trips the debug assertions /
            // bounds checks of any other out-of-range reference.
            _ => SlabRef::Primary {
                pool_id: u16::MAX,
                slot_id: u16::MAX,
            },
        }
    }

    /// Construct a `Primary` handle from a packed `(pool_id << 16) | slot_id`
    /// `u32` value. Test and benchmark fixture only -- production code
    /// constructs handles through `SlabPool::reserve` directly.
    #[doc(hidden)]
    pub fn legacy_handle_to_primary(packed: u32) -> Self {
        // Clamp into the 14-bit pool field; fixture values in-tree stay
        // far below the bound.
        let pool_id = ((packed >> 16) & MAX_POOL_ID) as u16;
        let slot_id = (packed & 0xFFFF) as u16;
        SlabHandle::primary(pool_id, slot_id)
    }
}

/// Size class configuration: (slot_size, slot_count)
///
/// Optimized for fast allocation with minimal memory footprint.
/// Larger slot counts for bigger sizes support pipelining of fragmented messages
/// and buffering when application read rate is slower than network receive rate.
const SIZE_CLASSES: &[(usize, usize)] = &[
    (16, 64),      // 16B x 64 slots = 1 KB
    (32, 64),      // 32B x 64 slots = 2 KB
    (64, 64),      // 64B x 64 slots = 4 KB
    (128, 64),     // 128B x 64 slots = 8 KB
    (256, 64),     // 256B x 64 slots = 16 KB
    (512, 64),     // 512B x 64 slots = 32 KB
    (1024, 64),    // 1KB x 64 slots = 64 KB
    (2048, 32),    // 2KB x 32 slots = 64 KB
    (4096, 32),    // 4KB x 32 slots = 128 KB
    (8192, 32),    // 8KB x 32 slots = 256 KB
    (16384, 32),   // 16KB x 32 slots = 512 KB
    (32768, 32),   // 32KB x 32 slots = 1 MB
    (65536, 32),   // 64KB x 32 slots = 2 MB
    (131_072, 16), // 128KB x 16 slots = 2 MB
];

/// Per-pool state with atomic bitmap for free slot tracking
struct Pool {
    data: UnsafeCell<Vec<u8>>,
    bitmap: AtomicU64,
    /// Per-slot reference counts (side-table, one entry per slot).
    ///
    /// A slot's payload can be referenced by several `IndexEntry` copies
    /// at once: the merger fans one entry out to N reader rings, the
    /// HistoryCache retains a handle for TRANSIENT_LOCAL replay, and a
    /// replay pushes yet more copies. The count tracks live handle
    /// copies; the slot bit is only cleared when it reaches zero, so no
    /// holder can ever observe a reclaimed-and-overwritten payload
    /// (two race classes this protocol rules out).
    ///
    /// Protocol (loom-verified, see the release/claim comments):
    /// - `try_reserve` initializes the count to 1 (the claimer's ref);
    /// - `add_ref` (fan-out) increments BEFORE the handle copy becomes
    ///   visible to its consumer, under a ref the caller already holds;
    /// - `release_ref` decrements; the 1 -> 0 transition frees the slot.
    refcounts: Box<[AtomicU32]>,
    /// Receipt-time reader metadata, valid while its tagged entry owns the slot.
    generations: Box<[AtomicU64]>,
    slot_size: usize,
    slot_count: usize,
    /// How many slots a [`Claim::Writer`] reservation may find taken and
    /// still claim one: `slot_count` less the readers' share.
    writer_limit: usize,
}

// SAFETY: Pool is Send + Sync because:
// - data is protected by atomic bitmap (mutual exclusion via CAS)
// - only one thread can access a given slot at a time
unsafe impl Send for Pool {}
unsafe impl Sync for Pool {}

impl Pool {
    /// A class of `slot_count` slots of `slot_size` bytes, `reserved` of
    /// which writers never take.
    fn new(slot_size: usize, slot_count: usize, reserved: usize) -> Self {
        let total_size = slot_size * slot_count;
        let data = UnsafeCell::new(vec![0u8; total_size]);

        // Initialize bitmap: all slots free (all bits set to 0)
        let bitmap = AtomicU64::new(0);
        let refcounts = (0..slot_count)
            .map(|_| AtomicU32::new(0))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Self {
            data,
            bitmap,
            refcounts,
            generations: (0..slot_count).map(|_| AtomicU64::new(0)).collect(),
            slot_size,
            slot_count,
            writer_limit: slot_count.saturating_sub(reserved),
        }
    }

    /// Try to reserve a slot from this pool, for a claim that may find at
    /// most `limit - 1` slots taken (`slot_count`: any free slot).
    ///
    /// Returns (slot_id, &mut [u8]) on success, None if pool full.
    ///
    /// SAFETY:
    /// - Atomic CAS ensures only one thread claims a given slot
    /// - Bounds checked: slot_id always < slot_count
    /// - Mutable slice returned is exclusive to this slot (enforced by bitmap)
    /// - UnsafeCell: interior mutability is safe because bitmap ensures no aliasing
    #[allow(clippy::mut_from_ref)]
    fn try_reserve(&self, limit: usize) -> Option<(u16, &mut [u8])> {
        loop {
            let bitmap = self.bitmap.load(Ordering::Acquire);

            // Find first free bit (bit=0 means free)
            let slot_idx_bits = (!bitmap).trailing_zeros();
            let slot_index = match usize::try_from(slot_idx_bits) {
                Ok(value) => value,
                Err(_) => return None,
            };
            if slot_index >= self.slot_count {
                return None; // Pool full
            }
            // The readers' share: a writer finds the class full once only
            // that share is left. Counted on the bitmap the claim below
            // CASes on, so a writer can never pass the bound however many
            // claim at once (each CAS succeeds only on the bitmap it counted).
            // Slots are claimed lowest first: with no slot taken above the
            // first free one, the taken ones are the run below it, and no
            // popcount is needed (one in flight, the common case).
            if limit < self.slot_count {
                let taken = if bitmap >> slot_index == 0 {
                    slot_index
                } else {
                    bitmap.count_ones() as usize
                };
                if taken >= limit {
                    return None;
                }
            }

            // Try to claim this slot (set bit to 1). AcqRel on success:
            // the load half must acquire the previous owner's releasing
            // fetch_and so its payload writes are ordered before ours
            // (a Release-only CAS leaves the load half relaxed).
            let new_bitmap = bitmap | (1u64 << slot_index);
            if self
                .bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // Initialize the claimer's reference. Relaxed store is
                // sufficient: the CAS above grants exclusive ownership,
                // and the handle only becomes visible to other threads
                // through a Release-publishing channel (ring push /
                // cache insert), which orders this store before any
                // consumer's fetch_sub. The previous generation's zero
                // is visible here via the AcqRel CAS pairing with the
                // releasing fetch_and in release_slot.
                self.refcounts[slot_index].store(1, Ordering::Relaxed);
                // Success: compute slice
                // SAFETY: bitmap CAS ensures exclusive access to this slot
                let offset = slot_index * self.slot_size;
                // SAFETY:
                // 1. `self.data` points to the Vec backing storage allocated in Pool::new.
                // 2. Bitmap CAS guarantees this slot_id is exclusively owned by this thread.
                // 3. Offset computation stays within allocation (slot_id < slot_count).
                // 4. &mut [u8] returned lives only for this scope, preventing aliasing.
                let data = unsafe { &mut *self.data.get() };
                let slice = &mut data[offset..offset + self.slot_size];
                let slot_id = match u16::try_from(slot_index) {
                    Ok(id) => id,
                    Err(_) => return None,
                };
                return Some((slot_id, slice));
            }
            // CAS failed, retry
        }
    }

    /// Release a slot back to the pool
    ///
    /// SAFETY:
    /// - slot_id must be valid (< slot_count)
    /// - slot must have been previously reserved
    /// - Single atomic fetch_and clears the bit; releasing an
    ///   already-free slot is a no-op (idempotent)
    fn release_slot(&self, slot_id: u16) {
        debug_assert!(usize::from(slot_id) < self.slot_count, "Invalid slot_id");

        let slot_mask = 1u64 << slot_id;
        // Clear the bit (mark free). Release ordering publishes the
        // slot's data writes before the bit becomes visible to the
        // Acquire load in try_reserve.
        self.bitmap.fetch_and(!slot_mask, Ordering::Release);
    }

    /// Take one additional reference on a slot (fan-out duplication).
    ///
    /// MUST be called while the caller already holds a reference (the
    /// writer's claim ref during merger fan-out, or the HistoryCache's
    /// persistent ref during replay snapshot): incrementing from an
    /// already-freed slot would resurrect it. Relaxed suffices (same
    /// argument as `Arc::clone`): the new handle copy only travels to
    /// its consumer through a Release-publishing channel, which orders
    /// this RMW before the consumer's `release_ref`.
    fn add_ref(&self, slot_id: u16) {
        debug_assert!(usize::from(slot_id) < self.slot_count, "Invalid slot_id");
        self.refcounts[usize::from(slot_id)].fetch_add(1, Ordering::Relaxed);
    }

    /// Drop one reference; the 1 -> 0 transition frees the slot.
    ///
    /// AcqRel on the fetch_sub (mirrors `Arc::drop`): the Release half
    /// orders this holder's payload reads before the decrement, the
    /// Acquire half makes every earlier holder's accesses visible to
    /// the freeing thread before `release_slot` publishes the slot.
    /// This RMW chain feeds the fetch_and(Release) -> claim-CAS(AcqRel)
    /// pairing, so all reads of generation N happen-before the writes
    /// of generation N+1 (loom-verified: loom-slab-refcount model).
    ///
    /// A decrement observing prev == 0 (double release / foreign
    /// handle) is left as-is: the count wraps but the next claim
    /// re-initializes it to 1, like the bitmap fetch_and, which is
    /// equally unprotected against a double release racing a reclaim.
    fn release_ref(&self, slot_id: u16) {
        debug_assert!(usize::from(slot_id) < self.slot_count, "Invalid slot_id");
        let prev = self.refcounts[usize::from(slot_id)].fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            self.release_slot(slot_id);
        } else if prev == 0 {
            log::debug!(
                "[slabpool] release of an unreferenced slot {} (double release?)",
                slot_id
            );
        }
    }
}

/// Heap-tier buffer plus its reference count.
///
/// The count lives under the `heap_store` mutex (the tier is mutex-
/// serialized anyway, and it is the exceptional path by design), which
/// makes the increment/decrement/free transitions trivially atomic.
/// The box is dropped only when the count reaches zero, so a holder's
/// `get_buffer` can never observe an empty slot while it still owns a
/// reference (releasing by taking the box would hand sibling
/// readers an empty Cow and decode would slice out of bounds).
struct HeapSlot {
    buf: Box<[u8]>,
    refs: u32,
    generations: u64,
    /// Coherent staging storage ([`SlabPool::reserve_staged`]): accounted
    /// on `staged_heap_bytes`, not on `heap_bytes_used`.
    staged: bool,
}

/// Combined storage for the heap fallback tier. Single mutex avoids
/// the deadlock-by-ordering class that two independent locks would
/// introduce; tier 3 contention is exceptional by design.
struct HeapStore {
    /// `heap_id` -> live buffer + refcount, or `None` when released.
    buffers: Vec<Option<HeapSlot>>,
    /// LIFO stack of `heap_id` values reusable by future allocations.
    free_list: Vec<u32>,
}

/// Memory pool for zero-copy message buffers.
///
/// Three allocation tiers are tried in order: the primary 14-class pool
/// (lock-free bitmap CAS), an opt-in secondary pool sized for large
/// payloads, and a heap fallback bounded by `max_heap_bytes`.
pub struct SlabPool {
    pools: Vec<Pool>,
    /// Secondary pool, configured at participant start via `MemoryPolicy`
    /// (`ParticipantBuilder::memory_policy` ->
    /// `rt::init_slab_pool_with_policy`, called from `build()`). Empty =
    /// disabled. The PROCESS-WIDE pool is built once, from whichever
    /// participant's policy gets there first; see
    /// `init_slab_pool_with_policy`'s doc comment.
    large_pools: Vec<Pool>,
    /// Heap fallback storage; mutated under a single mutex.
    heap_store: Mutex<HeapStore>,
    /// Allocation counters and the heap-bytes gauge. The
    /// `heap_bytes_used` field is the CAS-protected accountant for
    /// `SlabHandle::Heap` allocations.
    metrics: SlabPoolMetrics,
    /// Ceiling for the heap fallback tier (per `MemoryPolicy.max_heap_bytes`).
    max_heap_bytes: usize,
    /// Ceiling of the heap tier for a [`Claim::Writer`]: `max_heap_bytes`
    /// less the readers' share.
    writer_heap_ceiling: usize,
    /// Heap bytes [`hold`](Self::hold) may charge, plus the head they keep
    /// free (see there): the readers' share of the heap tier.
    held_ceiling: usize,
    /// What the coherent readers storing in this pool may stage together
    /// (`MemoryPolicy::max_staging_bytes`, `dds::reader::staging_budget`).
    staging_ceiling: std::sync::Arc<super::staging_ceiling::StagingCeiling>,
}

impl SlabPool {
    /// Build a slab pool with the default `MemoryPolicy` (no large tier,
    /// 16 MB heap fallback ceiling).
    pub fn new() -> Self {
        Self::with_policy(&MemoryPolicy::default())
    }

    /// Build a slab pool from an explicit allocation policy.
    pub fn with_policy(policy: &MemoryPolicy) -> Self {
        let percent = usize::from(policy.reader_reserve_percent.min(100));
        // Rounded up: a class of 16 slots keeps 4 at 25 %, one at 1 %.
        let reserved = |count: usize| (count * percent).div_ceil(100);
        let pools = SIZE_CLASSES
            .iter()
            .map(|&(size, count)| Pool::new(size, count, reserved(count)))
            .collect();
        let large_pools = policy
            .large_pool
            .classes
            .iter()
            .map(|&(size, count)| Pool::new(size, count, reserved(count)))
            .collect();
        let heap_reserved = policy
            .max_heap_bytes
            .checked_mul(percent)
            .map_or(policy.max_heap_bytes / 100 * percent, |n| n / 100);

        Self {
            pools,
            large_pools,
            heap_store: Mutex::new(HeapStore {
                buffers: Vec::new(),
                free_list: Vec::new(),
            }),
            metrics: SlabPoolMetrics::new(),
            max_heap_bytes: policy.max_heap_bytes,
            writer_heap_ceiling: policy.max_heap_bytes - heap_reserved,
            held_ceiling: heap_reserved,
            staging_ceiling: super::staging_ceiling::StagingCeiling::new(policy.max_staging_bytes),
        }
    }

    /// The ceiling on what the coherent readers storing in this pool stage
    /// together (`MemoryPolicy::max_staging_bytes`).
    pub(crate) fn staging_ceiling(
        &self,
    ) -> &std::sync::Arc<super::staging_ceiling::StagingCeiling> {
        &self.staging_ceiling
    }

    /// Snapshot accessor for the pool's allocation counters.
    #[must_use]
    pub fn metrics(&self) -> &SlabPoolMetrics {
        &self.metrics
    }

    /// Benchmark fixture that mirrors `reserve_and_write` under a
    /// stable public surface. Returns the handle only (the tier tag
    /// would force `SlabMetric` to be public). Use only from
    /// `crates/hdds/benches/` and test fixtures; production code calls
    /// `reserve_and_write` directly.
    ///
    /// A reader's claim (`Claim::Reader`): every tier whole, so a fixture
    /// that exhausts the pool exhausts it for readers too.
    #[doc(hidden)]
    pub fn bench_reserve_and_write(&self, payload: &[u8]) -> Option<SlabHandle> {
        self.reserve_and_write(payload, Claim::Reader)
            .map(|(handle, _)| handle)
    }

    /// Test fixture: [`bench_reserve_and_write`](Self::bench_reserve_and_write)
    /// as the head of a reliable reader's stream (`Claim::Head`), which may
    /// take the heap tier past `max_heap_bytes` by one sample. A fixture
    /// that exhausts the pool for readers takes that sample too.
    #[doc(hidden)]
    pub fn bench_reserve_and_write_head(&self, payload: &[u8]) -> Option<SlabHandle> {
        self.reserve_and_write(payload, Claim::Head)
            .map(|(handle, _)| handle)
    }

    /// Reserve buffer space; returns handle + mutable slice.
    ///
    /// Used by the intra-process write fast path that encodes the
    /// payload directly into the slab buffer (single copy, no
    /// intermediate `Vec`). Production code that already holds the
    /// payload as `&[u8]` should call `reserve_and_write` instead.
    ///
    /// A writer's reservation ([`Claim::Writer`]): it never takes the
    /// slots kept for readers.
    ///
    /// Finds the smallest size class >= len and attempts to allocate.
    /// Falls back to larger classes if smaller ones are full.
    ///
    /// # Returns
    /// - `Some((handle, slice))` on success
    /// - `None` if all primary pools exhausted (Large and Heap tiers
    ///   are not consulted by this entry point)
    ///
    /// # Panics
    /// Never panics on valid input (all bounds checked).
    ///
    /// # Performance
    /// Target: < 50 ns (single CAS in common case)
    ///
    /// # Latency
    /// - **p50:** 24.27 ns (256-byte request)
    /// - **p99:** 27.38 ns (**SLA target:** < 200 ns)
    /// - **p999:** 28.33 ns
    ///   [!] **Benchmark methodology:** Includes slot acquisition + release in isolation using Criterion
    ///   `slabpool_reserve_256b` (benches/runtime.rs) with pre-initialized pool.
    ///
    /// # Safety
    /// Uses interior mutability (UnsafeCell) with atomic bitmap protection.
    /// Safe because bitmap CAS ensures exclusive access to allocated slots.
    pub fn reserve(&self, len: usize) -> Option<(SlabHandle, &mut [u8])> {
        // Find first size class >= len
        let start_idx = SIZE_CLASSES.iter().position(|&(size, _)| size >= len)?;

        // Try pools starting from best-fit size class
        for pool_id in start_idx..self.pools.len() {
            let pool = &self.pools[pool_id];
            if let Some((slot_id, slice)) = pool.try_reserve(pool.writer_limit) {
                let pool_id = match u16::try_from(pool_id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                let handle = SlabHandle::primary(pool_id, slot_id);
                return Some((handle, slice));
            }
        }

        None // All pools full
    }

    /// Reserve a slot in the appropriate pool tier and copy the payload
    /// into it atomically. Returns the handle and which tier was used,
    /// or `None` if every tier was exhausted.
    ///
    /// Production write paths use this entry point. Stateful encoding
    /// directly into a reserved buffer (where the payload is not known
    /// upfront) uses the `reserve` pair.
    ///
    /// The slot returned by `get_buffer(handle)` may be larger than
    /// `payload.len()` for the `Primary` and `Large` tiers (size classes
    /// round up). Consumers must track the logical length independently
    /// (the runtime carries it on `IndexEntry::len`).
    ///
    /// `claim` decides what of each tier it may take: a writer never takes
    /// the readers' share ([`MemoryPolicy::reader_reserve_percent`]), so
    /// that a writer's unacknowledged history, however large, never takes
    /// the storage a reader needs to receive (and acknowledge) the samples
    /// that would free it.
    pub(crate) fn reserve_and_write(
        &self,
        payload: &[u8],
        claim: Claim,
    ) -> Option<(SlabHandle, SlabMetric)> {
        if let Some(handle) = self.try_reserve_primary_and_copy(payload, claim) {
            self.metrics
                .primary_hit_total
                .fetch_add(1, Ordering::Relaxed);
            return Some((handle, SlabMetric::Primary));
        }
        if let Some(handle) = self.try_reserve_large_and_copy(payload, claim) {
            self.metrics.large_hit_total.fetch_add(1, Ordering::Relaxed);
            return Some((handle, SlabMetric::Large));
        }
        if let Some(handle) = self.try_reserve_heap_and_copy(payload, claim) {
            self.metrics
                .heap_fallback_total
                .fetch_add(1, Ordering::Relaxed);
            return Some((handle, SlabMetric::HeapFallback));
        }
        self.metrics
            .insert_dropped_total
            .fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Keep the storage behind `handle` (`len` bytes) for a sample that is
    /// acknowledged but cannot be taken yet: one a reliable reader's reorder
    /// gate holds above a gap. (A coherent set's staged samples are stored
    /// apart, [`reserve_staged`](Self::reserve_staged).)
    ///
    /// Held storage of the heap tier, which every payload reaches once the
    /// size classes are full, is charged here
    /// ([`hold_charge`](Self::hold_charge)), and a hold is granted only while
    /// what is held there plus `head` stays within the readers' share of the
    /// heap tier ([`held_ceiling`](Self::held_ceiling),
    /// [`MemoryPolicy::reader_reserve_percent`]). Storage of a size class is
    /// charged nothing, but is granted on the same condition.
    ///
    /// `head` is the room a sample held above a gap keeps for the gap's
    /// head, the sample that releases it (estimated by the reader): held
    /// storage that took that room would wait for the head for good, and
    /// the writer with it; a head larger than the estimate still finds
    /// storage, past the ceiling by one sample ([`Claim::Head`]).
    ///
    /// `Some(bytes charged)` (0 outside the heap tier), to give back with
    /// [`unhold`](Self::unhold) once the sample is released or dropped;
    /// `None`: not held.
    pub(crate) fn hold(&self, handle: SlabHandle, len: usize, head: usize) -> Option<usize> {
        let charged = Self::hold_charge(handle, len);
        let held = &self.metrics.held_heap_bytes;
        let mut prev = held.load(Ordering::Acquire);
        loop {
            let next = prev.checked_add(charged)?;
            if next.checked_add(head)? > self.held_ceiling {
                return None;
            }
            match held.compare_exchange_weak(prev, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(charged),
                Err(now) => prev = now,
            }
        }
    }

    /// What [`hold`](Self::hold) charges the storage behind `handle` (`len`
    /// bytes): `len` in the heap tier, nothing in a size class.
    pub(crate) fn hold_charge(handle: SlabHandle, len: usize) -> usize {
        match handle.unpack() {
            SlabRef::Heap { .. } => len,
            SlabRef::Primary { .. } | SlabRef::Large { .. } => 0,
        }
    }

    /// Give back what [`hold`](Self::hold) charged.
    pub(crate) fn unhold(&self, charged: usize) {
        if charged != 0 {
            self.metrics
                .held_heap_bytes
                .fetch_sub(charged, Ordering::AcqRel);
        }
    }

    /// Walk the primary size classes from best-fit upward, reserve the
    /// first available slot, and `copy_from_slice` the payload into it.
    /// Returns `None` if every primary class is full.
    fn try_reserve_primary_and_copy(&self, payload: &[u8], claim: Claim) -> Option<SlabHandle> {
        let len = payload.len();
        let start_idx = SIZE_CLASSES.iter().position(|&(size, _)| size >= len)?;

        for pool_idx in start_idx..self.pools.len() {
            if let Some(handle) = self.try_claim_slot(&self.pools, pool_idx, payload, false, claim)
            {
                return Some(handle);
            }
        }
        None
    }

    /// Walk the secondary (`Large`) size classes and reserve+copy on hit.
    /// Returns `None` if the large pool is disabled or every class is full.
    fn try_reserve_large_and_copy(&self, payload: &[u8], claim: Claim) -> Option<SlabHandle> {
        if self.large_pools.is_empty() {
            return None;
        }
        let len = payload.len();
        let start_idx = self
            .large_pools
            .iter()
            .position(|pool| pool.slot_size >= len)?;

        for pool_idx in start_idx..self.large_pools.len() {
            if let Some(handle) =
                self.try_claim_slot(&self.large_pools, pool_idx, payload, true, claim)
            {
                return Some(handle);
            }
        }
        None
    }

    /// Try to reserve a slot in `pools[pool_idx]` and copy the payload
    /// into it. Returns `Some(handle)` on success with the matching
    /// variant tag, `None` if the pool was full at this class.
    fn try_claim_slot(
        &self,
        pools: &[Pool],
        pool_idx: usize,
        payload: &[u8],
        is_large: bool,
        claim: Claim,
    ) -> Option<SlabHandle> {
        let len = payload.len();
        let pool = &pools[pool_idx];
        let limit = match claim {
            Claim::Writer => pool.writer_limit,
            Claim::Reader | Claim::Head => pool.slot_count,
        };
        let (slot_id, slice) = pool.try_reserve(limit)?;
        slice[..len].copy_from_slice(payload);
        // Defensive: pools.len() is bounded by SIZE_CLASSES (14) for
        // the primary tier and by LargePoolConfig for the secondary
        // tier, both far below the 14-bit packed pool field. If a
        // future change crosses that bound the caller simply skips to
        // the next class.
        let pool_id = match u16::try_from(pool_idx) {
            Ok(id) if u32::from(id) <= MAX_POOL_ID => id,
            _ => {
                // Drop the claim ref taken by try_reserve (count is 1).
                pools[pool_idx].release_ref(slot_id);
                return None;
            }
        };
        Some(if is_large {
            SlabHandle::large(pool_id, slot_id)
        } else {
            SlabHandle::primary(pool_id, slot_id)
        })
    }

    /// Allocate a heap-tier buffer for `payload` within what `claim` may
    /// take of the tier. Returns `None` if that would be crossed:
    ///
    /// - a reader's claim: `max_heap_bytes`;
    /// - a head ([`Claim::Head`]): `max_heap_bytes` too, but crossed by
    ///   this buffer alone when the tier is not past it already;
    /// - a writer's: `max_heap_bytes` less the readers' share, counted
    ///   without what [`hold`](Self::hold) charges: held storage is the
    ///   readers' share's (at most all of it), and counted against writers
    ///   it would leave a writer no room to write what would release it
    ///   (as when coherent sets are held there, staged in the writer's own
    ///   process). Within the tier's ceiling all the same: writers' storage
    ///   and held storage together stay within `max_heap_bytes`.
    fn try_reserve_heap_and_copy(&self, payload: &[u8], claim: Claim) -> Option<SlabHandle> {
        let len = payload.len();
        let (ceiling, past) = match claim {
            Claim::Writer => (self.writer_heap_ceiling, false),
            Claim::Reader => (self.max_heap_bytes, false),
            Claim::Head => (self.max_heap_bytes, true),
        };

        // Atomic accounting (CAS-loop). On success, `metrics.heap_bytes_used`
        // has been incremented by `len` and the caller is responsible for
        // either publishing a Heap handle (matched by a future `release`
        // that decrements) or rolling back via `fetch_sub` on failure.
        loop {
            let prev = self.metrics.heap_bytes_used.load(Ordering::Acquire);
            let next = prev.checked_add(len)?;
            // A writer's, without the held storage. Read apart from the
            // gauge: a hold given back since only lowers it, and the
            // storage stays on the gauge; a hold granted since charges
            // storage already on it. Neither takes the tier past its
            // ceiling.
            let counted = match claim {
                Claim::Writer => {
                    next.saturating_sub(self.metrics.held_heap_bytes.load(Ordering::Acquire))
                }
                Claim::Reader | Claim::Head => next,
            };
            // Counted on the gauge the CAS below swaps: two heads at once
            // cannot both pass the ceiling.
            if counted > ceiling && (!past || prev > ceiling) {
                return None;
            }
            if self
                .metrics
                .heap_bytes_used
                .compare_exchange(prev, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
            // CAS lost the race; re-read and retry.
        }

        let handle = self.heap_insert(payload, false);
        if handle.is_none() {
            // Heap-id space exhausted; roll back the accounting and
            // surface as exhaustion to the caller.
            self.metrics
                .heap_bytes_used
                .fetch_sub(len, Ordering::AcqRel);
        }
        handle
    }

    /// Store `payload` for a coherent set a reader stages: in the heap
    /// tier, outside its ceiling and its gauge, on `staged_heap_bytes`
    /// instead. Staged storage is bounded by each staging reader's own
    /// budget (`dds::reader::staging_budget`), all of them together by the
    /// pool's staging ceiling (`MemoryPolicy::max_staging_bytes`,
    /// [`staging_ceiling`](Self::staging_ceiling)), which its reader charges
    /// once the sample is stored and before it is acknowledged (a member
    /// refused is released at once): it takes nothing of what writers and
    /// other readers store, and nothing of theirs keeps it from being
    /// stored. `None` only when the heap tier has no handle left to give.
    pub(crate) fn reserve_staged(&self, payload: &[u8]) -> Option<SlabHandle> {
        let len = payload.len();
        self.metrics
            .staged_heap_bytes
            .fetch_add(len, Ordering::AcqRel);
        let handle = self.heap_insert(payload, true);
        if handle.is_none() {
            self.metrics
                .staged_heap_bytes
                .fetch_sub(len, Ordering::AcqRel);
        }
        handle
    }

    /// Copy `payload` into a new heap-tier buffer of the class `staged`
    /// says, its accounting already taken by the caller. `None` when the
    /// packed handle has no heap id left.
    fn heap_insert(&self, payload: &[u8], staged: bool) -> Option<SlabHandle> {
        let len = payload.len();
        // SAFETY:
        // 1. `Box::new_uninit_slice(len)` allocates `len` `MaybeUninit<u8>`
        //    bytes; layout is identical to `[u8; len]`.
        // 2. `copy_nonoverlapping` writes every byte of `dst`, so the slice
        //    is fully initialised before we cast.
        // 3. `Box::from_raw(Box::into_raw(boxed) as *mut [u8])` reclaims
        //    ownership of the same allocation with the layout unchanged.
        let init_box: Box<[u8]> = unsafe {
            let mut boxed: Box<[MaybeUninit<u8>]> = Box::new_uninit_slice(len);
            let dst = boxed.as_mut_ptr().cast::<u8>();
            std::ptr::copy_nonoverlapping(payload.as_ptr(), dst, len);
            Box::from_raw(Box::into_raw(boxed) as *mut [u8])
        };

        let heap_id = {
            let mut store = self.heap_store.lock();
            if let Some(reused) = store.free_list.pop() {
                store.buffers[reused as usize] = Some(HeapSlot {
                    buf: init_box,
                    refs: 1,
                    generations: 0,
                    staged,
                });
                reused
            } else {
                let new_id = match u32::try_from(store.buffers.len()) {
                    // The packed handle carries 30 bits of heap id; ids
                    // beyond that are treated as exhaustion (same rollback
                    // as the u32 overflow arm below).
                    Ok(id) if id <= MAX_HEAP_ID => id,
                    _ => return None,
                };
                store.buffers.push(Some(HeapSlot {
                    buf: init_box,
                    refs: 1,
                    generations: 0,
                    staged,
                }));
                new_id
            }
        };

        Some(SlabHandle::heap(heap_id))
    }

    /// Get immutable buffer from handle (for reading)
    ///
    /// Returns a slice to the buffer data backing the handle. The slice
    /// length matches the size class slot, which may exceed the bytes
    /// actually written; the runtime carries the logical length on
    /// `IndexEntry::len` for callers that need to slice down.
    ///
    /// # Safety
    /// - Handle must be valid and currently allocated
    /// - Buffer must have been written by `reserve_and_write`, or by
    ///   the caller after a `reserve` call returned the slice
    /// - Caller must ensure no concurrent writes to this handle
    ///
    /// # Panics
    /// Panics if handle is invalid (debug builds only).
    ///
    /// # Performance
    /// Target: < 20 ns (pointer arithmetic only, no atomics)
    /// Borrow the payload bytes for `handle` without constructing a
    /// `Cow`. Returns `None` for the Heap tier, whose storage lives
    /// behind a mutex and must be copied out via [`Self::get_buffer`].
    ///
    /// Hot-path companion to `get_buffer`: the intra-process reader
    /// pump calls this first so the (overwhelmingly common) pool-tier
    /// samples decode straight from the slab slot with zero wrapper.
    #[inline]
    pub fn try_borrow(&self, handle: SlabHandle) -> Option<&[u8]> {
        match handle.unpack() {
            SlabRef::Primary { pool_id, slot_id } => {
                Some(slot_slice(&self.pools, pool_id, slot_id))
            }
            SlabRef::Large { pool_id, slot_id } => {
                Some(slot_slice(&self.large_pools, pool_id, slot_id))
            }
            SlabRef::Heap { .. } => None,
        }
    }

    /// Stamp an owned, unpublished reader slot. Its ring entry publishes the
    /// snapshot; slot reuse needs no cleanup because each tagged entry writes
    /// its own value before publication. Ordinary writer slots never access it.
    pub(crate) fn set_generation_counts(&self, handle: SlabHandle, counts: (u32, u32)) {
        let packed = (u64::from(counts.0) << 32) | u64::from(counts.1);
        match handle.unpack() {
            SlabRef::Primary { pool_id, slot_id } => {
                self.pools[pool_id as usize].generations[slot_id as usize]
                    .store(packed, Ordering::Relaxed);
            }
            SlabRef::Large { pool_id, slot_id } => {
                self.large_pools[pool_id as usize].generations[slot_id as usize]
                    .store(packed, Ordering::Relaxed);
            }
            SlabRef::Heap { heap_id } => {
                let mut store = self.heap_store.lock();
                let slot = store.buffers[heap_id as usize].as_mut();
                debug_assert!(
                    slot.is_some(),
                    "a generation snapshot targets a live heap slab"
                );
                match slot {
                    Some(slot) => slot.generations = packed,
                    // A snapshot for a slab that is no longer live has no slot to stamp.
                    None => {
                        log::error!("generation snapshot dropped: heap slab {heap_id} is not live")
                    }
                }
            }
        }
    }

    /// Read a tagged entry's snapshot while still owning its live slab ref.
    pub(crate) fn generation_counts(&self, handle: SlabHandle) -> (u32, u32) {
        let packed = match handle.unpack() {
            SlabRef::Primary { pool_id, slot_id } => {
                self.pools[pool_id as usize].generations[slot_id as usize].load(Ordering::Relaxed)
            }
            SlabRef::Large { pool_id, slot_id } => self.large_pools[pool_id as usize].generations
                [slot_id as usize]
                .load(Ordering::Relaxed),
            SlabRef::Heap { heap_id } => {
                let store = self.heap_store.lock();
                let slot = store.buffers[heap_id as usize].as_ref();
                debug_assert!(
                    slot.is_some(),
                    "a generation snapshot reads a live heap slab"
                );
                match slot {
                    Some(slot) => slot.generations,
                    // A slab that is no longer live has no generation to report.
                    None => {
                        log::error!(
                            "generation snapshot read as zero: heap slab {heap_id} is not live"
                        );
                        0
                    }
                }
            }
        };
        let [hi0, hi1, hi2, hi3, lo0, lo1, lo2, lo3] = packed.to_be_bytes();
        (
            u32::from_be_bytes([hi0, hi1, hi2, hi3]),
            u32::from_be_bytes([lo0, lo1, lo2, lo3]),
        )
    }

    /// Read fixed-size metadata without copying the payload. The caller
    /// holds a live reference; heap storage stays locked only for this read.
    #[inline]
    pub(crate) fn read_array<const N: usize>(
        &self,
        handle: SlabHandle,
        offset: usize,
    ) -> Option<[u8; N]> {
        let end = offset.checked_add(N)?;
        if let Some(bytes) = self.try_borrow(handle) {
            return bytes.get(offset..end)?.try_into().ok();
        }
        let SlabRef::Heap { heap_id } = handle.unpack() else {
            return None;
        };
        let store = self.heap_store.lock();
        let slot = store.buffers.get(heap_id as usize)?.as_ref()?;
        slot.buf.get(offset..end)?.try_into().ok()
    }

    #[inline]
    pub fn get_buffer(&self, handle: SlabHandle) -> Cow<'_, [u8]> {
        match handle.unpack() {
            // Primary first: the intra-process fast path is a pure
            // primary-tier workload, so this arm is the predicted one.
            SlabRef::Primary { pool_id, slot_id } => {
                Cow::Borrowed(slot_slice(&self.pools, pool_id, slot_id))
            }
            SlabRef::Large { pool_id, slot_id } => {
                Cow::Borrowed(slot_slice(&self.large_pools, pool_id, slot_id))
            }
            SlabRef::Heap { heap_id } => {
                let store = self.heap_store.lock();
                let buf = store
                    .buffers
                    .get(heap_id as usize)
                    .and_then(|slot| slot.as_ref())
                    .map(|slot| slot.buf.to_vec())
                    .unwrap_or_default();
                Cow::Owned(buf)
            }
        }
    }

    /// Free the slot behind a SOLE-ownership handle directly, without
    /// touching the refcount side-table.
    ///
    /// Only legal for handles received through an `IndexEntry` carrying
    /// the EXCLUSIVE flag: the pushing side guaranteed, BEFORE
    /// publication, that this is the only reference in existence (no
    /// `add_ref` was or can ever be issued for this generation). The
    /// side-table entry is left at a stale 1; the next claim of the
    /// slot overwrites it unconditionally.
    ///
    /// This is the hot-path release (1w1r intra): one fetch_and
    /// instead of fetch_sub + fetch_and on two cache lines -- the
    /// side-table line stays writer-local, avoiding the per-message
    /// line ping-pong of the refcounted release. The refcounted
    /// `release` remains CORRECT for exclusive handles (count is 1);
    /// cold paths (tombstone drains, ring trim, decode-error unwinds)
    /// keep using it for uniformity.
    #[inline]
    pub fn release_exclusive(&self, handle: SlabHandle) {
        match handle.unpack() {
            // Primary first: predicted arm on the intra-process path.
            SlabRef::Primary { pool_id, slot_id } => {
                let pool_idx = usize::from(pool_id);
                debug_assert!(pool_idx < self.pools.len(), "Invalid Primary pool_id");
                debug_assert_eq!(
                    self.pools[pool_idx].refcounts[usize::from(slot_id)].load(Ordering::Relaxed),
                    1,
                    "exclusive release with foreign references alive"
                );
                self.pools[pool_idx].release_slot(slot_id);
            }
            SlabRef::Large { pool_id, slot_id } => {
                let pool_idx = usize::from(pool_id);
                debug_assert!(pool_idx < self.large_pools.len(), "Invalid Large pool_id");
                debug_assert_eq!(
                    self.large_pools[pool_idx].refcounts[usize::from(slot_id)]
                        .load(Ordering::Relaxed),
                    1,
                    "exclusive release with foreign references alive"
                );
                self.large_pools[pool_idx].release_slot(slot_id);
            }
            SlabRef::Heap { heap_id } => {
                // Sole owner: take the box in one lock excursion.
                let taken = {
                    let mut store = self.heap_store.lock();
                    match store.buffers.get_mut(heap_id as usize) {
                        Some(slot_opt) => slot_opt.take().inspect(|slot| {
                            debug_assert_eq!(
                                slot.refs, 1,
                                "exclusive release with foreign references alive"
                            );
                            store.free_list.push(heap_id);
                        }),
                        None => None,
                    }
                };
                if let Some(slot) = taken {
                    self.heap_freed(slot);
                }
            }
        }
    }

    /// Take one additional reference on `handle` (fan-out duplication).
    ///
    /// MUST be called while the caller already holds a reference to the
    /// handle (see `Pool::add_ref`); the merger fan-out holds the
    /// writer's claim ref, the TRANSIENT_LOCAL replay snapshot holds
    /// the HistoryCache's persistent ref.
    #[inline]
    pub(crate) fn add_ref(&self, handle: SlabHandle) {
        match handle.unpack() {
            SlabRef::Primary { pool_id, slot_id } => {
                let pool_idx = usize::from(pool_id);
                debug_assert!(pool_idx < self.pools.len(), "Invalid Primary pool_id");
                self.pools[pool_idx].add_ref(slot_id);
            }
            SlabRef::Large { pool_id, slot_id } => {
                let pool_idx = usize::from(pool_id);
                debug_assert!(pool_idx < self.large_pools.len(), "Invalid Large pool_id");
                self.large_pools[pool_idx].add_ref(slot_id);
            }
            SlabRef::Heap { heap_id } => {
                let mut store = self.heap_store.lock();
                match store.buffers.get_mut(heap_id as usize) {
                    Some(Some(slot)) => slot.refs += 1,
                    _ => {
                        debug_assert!(false, "add_ref on a released heap slot {heap_id}");
                        log::debug!("[slabpool] add_ref on released heap slot {}", heap_id);
                    }
                }
            }
        }
    }

    /// Drop one reference on `handle`; frees the slot at zero.
    ///
    /// Every holder of a handle copy (reader pump after decode, ring
    /// trim, HistoryCache eviction, merger fan-out guard) releases
    /// through here; the last one returns the slot to the pool's free
    /// list. See `Pool::release_ref` for the ordering contract.
    ///
    /// # Panics
    /// Panics if handle is invalid (debug builds only).
    ///
    /// # Performance
    /// Target: < 50 ns (fetch_sub + conditional fetch_and on the
    /// single-reference fast path; measured +1-2 ns over a bare single
    /// fetch_and, accepted correctness rent for the two race classes above)
    #[inline]
    pub fn release(&self, handle: SlabHandle) {
        match handle.unpack() {
            // Primary first: predicted arm on the intra-process path.
            SlabRef::Primary { pool_id, slot_id } => {
                let pool_idx = usize::from(pool_id);
                debug_assert!(pool_idx < self.pools.len(), "Invalid Primary pool_id");
                self.pools[pool_idx].release_ref(slot_id);
            }
            SlabRef::Large { pool_id, slot_id } => {
                let pool_idx = usize::from(pool_id);
                debug_assert!(pool_idx < self.large_pools.len(), "Invalid Large pool_id");
                self.large_pools[pool_idx].release_ref(slot_id);
            }
            SlabRef::Heap { heap_id } => {
                // Decrement under the lock; take the box out only on the
                // last reference so the drop and the accounting update
                // happen outside the critical section.
                let taken = {
                    let mut store = self.heap_store.lock();
                    match store.buffers.get_mut(heap_id as usize) {
                        Some(slot_opt) => {
                            let last = match slot_opt.as_mut() {
                                Some(slot) => {
                                    slot.refs = slot.refs.saturating_sub(1);
                                    slot.refs == 0
                                }
                                // Released slot: tolerated as a no-op.
                                None => false,
                            };
                            if last {
                                slot_opt.take().inspect(|_| {
                                    store.free_list.push(heap_id);
                                })
                            } else {
                                None
                            }
                        }
                        None => None,
                    }
                };
                if let Some(slot) = taken {
                    self.heap_freed(slot);
                }
            }
        }
    }
}

impl SlabPool {
    /// A heap-tier buffer's last reference is gone: its bytes leave the
    /// gauge of its class.
    fn heap_freed(&self, slot: HeapSlot) {
        let len = slot.buf.len();
        let gauge = if slot.staged {
            &self.metrics.staged_heap_bytes
        } else {
            &self.metrics.heap_bytes_used
        };
        drop(slot);
        gauge.fetch_sub(len, Ordering::AcqRel);
    }
}

/// Borrow the size-class slot referenced by a slab handle. Used by both
/// `Primary` and `Large` paths in `get_buffer`.
fn slot_slice(pools: &[Pool], pool_id: u16, slot_id: u16) -> &[u8] {
    let pool_idx = usize::from(pool_id);
    let slot_idx = usize::from(slot_id);
    debug_assert!(pool_idx < pools.len(), "Invalid pool_id");
    let pool = &pools[pool_idx];
    debug_assert!(slot_idx < pool.slot_count, "Invalid slot_id");
    let offset = slot_idx * pool.slot_size;
    // SAFETY:
    // 1. pool.data was allocated once during Pool::new and never freed
    //    while Pool alive.
    // 2. Slot is allocated (bitmap bit set) so slice lies within
    //    initialized memory.
    // 3. We only create an immutable slice (&[u8]), so concurrent
    //    readers are allowed.
    // 4. Offset math is bounded by slot_count and slot_size.
    let data = unsafe { &*pool.data.get() };
    &data[offset..offset + pool.slot_size]
}

impl Default for SlabPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qos::LargePoolConfig;

    #[test]
    fn test_handle_encoding() {
        let h = SlabHandle::primary(42, 1337);
        assert!(matches!(
            h.unpack(),
            SlabRef::Primary {
                pool_id: 42,
                slot_id: 1337,
            }
        ));
        let l = SlabHandle::large(3, 9);
        assert!(matches!(
            l.unpack(),
            SlabRef::Large {
                pool_id: 3,
                slot_id: 9,
            }
        ));
        let hp = SlabHandle::heap(0x1234_5678);
        assert!(matches!(
            hp.unpack(),
            SlabRef::Heap {
                heap_id: 0x1234_5678,
            }
        ));
    }

    #[test]
    fn test_empty_sentinel() {
        let h = SlabHandle::EMPTY;
        assert!(h.is_empty());
        assert!(!SlabHandle::primary(0, 0).is_empty());
        // Unpacking the sentinel yields the out-of-range Primary view.
        assert!(matches!(
            h.unpack(),
            SlabRef::Primary {
                pool_id: u16::MAX,
                slot_id: u16::MAX,
            }
        ));
    }

    #[test]
    fn test_reserve_and_write_primary() {
        let pool = SlabPool::new();
        let payload = b"hello slab";
        let (handle, metric) = pool
            .reserve_and_write(payload, crate::core::rt::Claim::Reader)
            .expect("primary tier should have capacity");
        assert_eq!(metric, SlabMetric::Primary);
        let buf = pool.get_buffer(handle);
        assert_eq!(&buf[..payload.len()], payload);
        pool.release(handle);
    }

    #[test]
    fn test_reserve_and_write_primary_tier() {
        // Three-path integration test, per design sec. 6 #1 -- small payload
        // must land in the Primary tier without consulting Large or Heap.
        let pool = SlabPool::new();
        let payload = vec![0xABu8; 256];
        let (handle, metric) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("primary tier should accept a 256-byte payload");
        assert_eq!(metric, SlabMetric::Primary);
        let buf = pool.get_buffer(handle);
        assert_eq!(&buf[..payload.len()], payload.as_slice());
        pool.release(handle);
    }

    #[test]
    fn test_reserve_and_write_large_tier() {
        // Three-path integration test, per design sec. 6 #1 -- payload that
        // exceeds the primary 128 KB ceiling lands in the Large tier when
        // it is configured, not in Heap fallback.
        //
        // Custom Large config (single 256 KB class x 2 slots) keeps the
        // calibration robust against future SIZE_CLASSES changes; the
        // 200 KB payload picks this class regardless of primary layout.
        let policy = MemoryPolicy {
            large_pool: LargePoolConfig {
                classes: vec![(262_144, 2)],
            },
            max_heap_bytes: 16 * 1024 * 1024,
            ..MemoryPolicy::default()
        };
        let pool = SlabPool::with_policy(&policy);
        let payload = vec![0xCDu8; 200_000];
        let (handle, metric) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("large tier should accept a 200 KB payload");
        assert_eq!(metric, SlabMetric::Large);
        let buf = pool.get_buffer(handle);
        assert_eq!(&buf[..payload.len()], payload.as_slice());
        pool.release(handle);
    }

    #[test]
    fn test_reserve_and_write_heap_fallback_after_large_saturated() {
        // Three-path integration test, per design sec. 6 #1 -- payload that
        // outgrows both the Primary and the Large tiers must succeed via
        // Heap fallback, not silently drop.
        //
        // Custom Large config (single 256 KB class x 2 slots, total 512 KB)
        // saturates fast; the third 200 KB allocation must reach Heap.
        let policy = MemoryPolicy {
            large_pool: LargePoolConfig {
                classes: vec![(262_144, 2)],
            },
            max_heap_bytes: 4 * 1024 * 1024,
            ..MemoryPolicy::default()
        };
        let pool = SlabPool::with_policy(&policy);
        let payload = vec![0xEFu8; 200_000];

        let (h1, m1) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("first large slot");
        let (h2, m2) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("second large slot");
        assert_eq!(m1, SlabMetric::Large);
        assert_eq!(m2, SlabMetric::Large);

        let (h3, m3) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("heap fallback after Large saturation");
        assert_eq!(m3, SlabMetric::HeapFallback);
        let buf = pool.get_buffer(h3);
        assert_eq!(&buf[..payload.len()], payload.as_slice());

        pool.release(h1);
        pool.release(h2);
        pool.release(h3);
    }

    #[test]
    fn test_reserve_and_write_heap_fallback_when_primary_saturated() {
        // Saturate the largest primary class (128 KB x 16 slots) and prove
        // the 17th 100 KB allocation lands in the heap fallback tier with
        // its bytes intact. Mirrors a large-data stream (writer
        // sends N > 16 samples of 100 KB, primary class exhausts, heap
        // fallback must succeed instead of silently dropping).
        let pool = SlabPool::new();
        let mut primary_handles = Vec::new();
        for _ in 0..16 {
            let payload = vec![0u8; 100_000];
            let (h, m) = pool
                .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
                .expect("primary slot should be available");
            assert_eq!(m, SlabMetric::Primary);
            primary_handles.push(h);
        }

        let payload = vec![0xCDu8; 100_000];
        let (h_heap, m_heap) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("heap fallback should succeed once primary is full");
        assert_eq!(m_heap, SlabMetric::HeapFallback);

        let buf = pool.get_buffer(h_heap);
        assert_eq!(buf.len(), 100_000);
        assert!(buf.iter().all(|&b| b == 0xCD));

        pool.release(h_heap);
        for h in primary_handles {
            pool.release(h);
        }
    }

    #[test]
    fn test_heap_budget_exhaustion_increments_drop_counter() {
        // Test plan sec. 6 #3: when reserve_and_write fails at every tier
        // (heap budget exhausted in this case), the drop counter must
        // increment. The warn! emission is asserted by inspection of
        // the production code path, not by a captured log assertion
        // (no log-capture crate is currently authorised in workspace
        // dev-dependencies).
        let policy = MemoryPolicy {
            large_pool: LargePoolConfig::default(),
            max_heap_bytes: 1024 * 1024,
            ..MemoryPolicy::default()
        };
        let pool = SlabPool::with_policy(&policy);
        let mut primary_handles = Vec::new();
        for _ in 0..16 {
            let payload = vec![0u8; 100_000];
            let (h, _m) = pool
                .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
                .expect("primary slot should be available");
            primary_handles.push(h);
        }
        let payload = vec![0u8; 800_000];
        let (h_heap, _) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("first heap allocation under ceiling");

        let drops_before = pool.metrics().insert_dropped_total.load(Ordering::Relaxed);
        let overflow = vec![0u8; 800_000];
        assert!(
            pool.reserve_and_write(&overflow, crate::core::rt::Claim::Reader)
                .is_none(),
            "heap budget exhausted; reserve_and_write must return None"
        );
        let drops_after = pool.metrics().insert_dropped_total.load(Ordering::Relaxed);
        assert_eq!(
            drops_after,
            drops_before + 1,
            "insert_dropped_total must increment on full-tier exhaustion",
        );

        pool.release(h_heap);
        for h in primary_handles {
            pool.release(h);
        }
    }

    #[test]
    fn test_reserve_and_write_metrics_per_tier() {
        // Each tier hit should bump its own counter, not the others.
        let policy = MemoryPolicy {
            large_pool: LargePoolConfig {
                classes: vec![(262_144, 2)],
            },
            max_heap_bytes: 4 * 1024 * 1024,
            ..MemoryPolicy::default()
        };
        let pool = SlabPool::with_policy(&policy);
        let (primary_h, _) = pool
            .reserve_and_write(&[0u8; 256], crate::core::rt::Claim::Reader)
            .expect("primary");
        let (large_h, _) = pool
            .reserve_and_write(&[0u8; 200_000], crate::core::rt::Claim::Reader)
            .expect("large 1");
        let (large_h2, _) = pool
            .reserve_and_write(&[0u8; 200_000], crate::core::rt::Claim::Reader)
            .expect("large 2");
        let (heap_h, _) = pool
            .reserve_and_write(&[0u8; 200_000], crate::core::rt::Claim::Reader)
            .expect("heap fallback");

        let (primary, large, heap, dropped, _used) = pool.metrics().snapshot();
        assert_eq!(primary, 1);
        assert_eq!(large, 2);
        assert_eq!(heap, 1);
        assert_eq!(dropped, 0);

        pool.release(primary_h);
        pool.release(large_h);
        pool.release(large_h2);
        pool.release(heap_h);
    }

    #[test]
    fn test_reserve_and_write_heap_ceiling_enforced() {
        // 1 MB heap ceiling: two 400 KB heap allocations should succeed,
        // a third 400 KB allocation must fail without corrupting state.
        let pool = SlabPool::with_policy(&MemoryPolicy {
            large_pool: LargePoolConfig::default(),
            max_heap_bytes: 1024 * 1024,
            ..MemoryPolicy::default()
        });
        let mut primary_handles = Vec::new();
        for _ in 0..16 {
            let payload = vec![0u8; 100_000];
            let (h, _m) = pool
                .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
                .expect("primary slot should be available");
            primary_handles.push(h);
        }

        let payload = vec![0u8; 400_000];
        let (h1, m1) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("first heap allocation under ceiling");
        let (h2, m2) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("second heap allocation under ceiling");
        assert_eq!(m1, SlabMetric::HeapFallback);
        assert_eq!(m2, SlabMetric::HeapFallback);

        // Third 400 KB would push to 1.2 MB > 1 MB ceiling.
        let blocked = pool.reserve_and_write(&payload, crate::core::rt::Claim::Reader);
        assert!(blocked.is_none(), "ceiling must reject allocation");

        pool.release(h1);
        pool.release(h2);
        for h in primary_handles {
            pool.release(h);
        }
    }

    #[test]
    fn test_legacy_handle_to_primary() {
        let h = SlabHandle::legacy_handle_to_primary((3 << 16) | 7);
        assert!(matches!(
            h.unpack(),
            SlabRef::Primary {
                pool_id: 3,
                slot_id: 7,
            }
        ));
    }

    #[test]
    fn test_reserve_basic() {
        let pool = SlabPool::new();
        let (h1, buf1) = pool
            .reserve(64)
            .expect("SlabPool reservation should succeed");
        assert!(buf1.len() >= 64);

        let (h2, buf2) = pool
            .reserve(64)
            .expect("SlabPool reservation should succeed");
        assert_ne!(h1, h2); // Different slots
        assert!(buf2.len() >= 64);
    }

    #[test]
    fn test_reserve_release_cycle() {
        let pool = SlabPool::new();
        let (h, _) = pool
            .reserve(100)
            .expect("SlabPool reservation should succeed");
        pool.release(h);

        // Should be able to allocate same slot again
        let (h2, _) = pool
            .reserve(100)
            .expect("SlabPool reservation should succeed");
        assert_eq!(h, h2); // Same slot reused
    }

    #[test]
    fn test_reserve_size_classes() {
        let pool = SlabPool::new();

        // Request 10 bytes -> should get 16B pool
        let (h, buf) = pool
            .reserve(10)
            .expect("SlabPool reservation should succeed");
        assert_eq!(buf.len(), 16);
        match h.unpack() {
            SlabRef::Primary { pool_id, .. } => assert_eq!(pool_id, 0),
            other => panic!("expected Primary, got {:?}", other),
        }

        pool.release(h);

        // Request 100 bytes -> should get 128B pool
        let (h2, buf2) = pool
            .reserve(100)
            .expect("SlabPool reservation should succeed");
        assert_eq!(buf2.len(), 128);
        match h2.unpack() {
            SlabRef::Primary { pool_id, .. } => assert_eq!(pool_id, 3),
            other => panic!("expected Primary, got {:?}", other),
        }
    }

    #[test]
    fn test_pool_exhaustion() {
        let pool = SlabPool::new();

        // Allocate all 16B slots (64 of them)
        let mut handles = Vec::new();
        for _ in 0..64 {
            let (h, _) = pool
                .reserve(16)
                .expect("SlabPool reservation should succeed");
            handles.push(h);
        }

        // Next 16B allocation should fallback to 32B pool
        let (h_fallback, buf) = pool
            .reserve(16)
            .expect("SlabPool reservation should succeed");
        assert_eq!(buf.len(), 32); // Fallback to next size class
        match h_fallback.unpack() {
            SlabRef::Primary { pool_id, .. } => assert_eq!(pool_id, 1),
            other => panic!("expected Primary, got {:?}", other),
        }
    }

    #[test]
    fn test_no_double_free() {
        let pool = SlabPool::new();
        let (h, _) = pool
            .reserve(100)
            .expect("SlabPool reservation should succeed");
        pool.release(h);

        // Second release should be safe (idempotent bitmap clear)
        pool.release(h); // Should not panic or corrupt state
    }

    #[test]
    fn test_refcount_fanout_keeps_slot_alive() {
        // A slot with a live sibling reference must not be reclaimed by
        // the first release.
        let pool = SlabPool::new();
        let payload = b"fanout payload";
        let (h, _) = pool
            .reserve_and_write(payload, crate::core::rt::Claim::Reader)
            .expect("primary reservation");
        pool.add_ref(h); // second holder (fan-out duplicate)
        pool.release(h); // first holder done

        // Payload must still be intact and the slot still claimed.
        let buf = pool.get_buffer(h);
        assert_eq!(&buf[..payload.len()], payload);
        let (h2, _) = pool
            .reserve_and_write(payload, crate::core::rt::Claim::Reader)
            .expect("second reservation");
        assert_ne!(h, h2, "slot with a live reference must not be reused");
        pool.release(h2);

        pool.release(h); // last holder: frees
        let (h3, _) = pool
            .reserve_and_write(payload, crate::core::rt::Claim::Reader)
            .expect("reservation after final release");
        assert_eq!(h, h3, "slot must be reusable after the last release");
        pool.release(h3);
    }

    #[test]
    fn test_release_exclusive_frees_and_next_claim_reinits() {
        // Exclusive direct free leaves the side-table count at a stale
        // 1; the next claim must overwrite it and the refcount protocol
        // must work unchanged on the new generation.
        let pool = SlabPool::new();
        let (h, _) = pool
            .reserve_and_write(b"gen1", crate::core::rt::Claim::Reader)
            .expect("gen1");
        pool.release_exclusive(h);

        let (h2, _) = pool
            .reserve_and_write(b"gen2", crate::core::rt::Claim::Reader)
            .expect("gen2");
        assert_eq!(h, h2, "direct free must return the slot");
        pool.add_ref(h2); // refcounted generation on the same slot
        pool.release(h2);
        let buf = pool.get_buffer(h2);
        assert_eq!(&buf[..4], b"gen2");
        pool.release(h2); // last ref frees

        let (h3, _) = pool
            .reserve_and_write(b"gen3", crate::core::rt::Claim::Reader)
            .expect("gen3");
        assert_eq!(h, h3, "slot must cycle through both disciplines");
        pool.release(h3);
    }

    #[test]
    fn test_release_exclusive_heap_tier() {
        // Heap-tier exclusive free: box taken in one excursion,
        // accounting settles, id reusable.
        let pool = SlabPool::new();
        let mut primary_handles = Vec::new();
        for _ in 0..16 {
            let payload = vec![0u8; 100_000];
            let (h, _m) = pool
                .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
                .expect("primary slot should be available");
            primary_handles.push(h);
        }
        let payload = vec![0xEEu8; 100_000];
        let (h_heap, m) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("heap slot");
        assert_eq!(m, SlabMetric::HeapFallback);
        pool.release_exclusive(h_heap);
        let (_p, _l, _h, _d, used) = pool.metrics().snapshot();
        assert_eq!(used, 0, "heap accounting must return to zero");
        assert!(pool.get_buffer(h_heap).is_empty());
        for h in primary_handles {
            pool.release(h);
        }
    }

    #[test]
    fn test_refcount_heap_tier_survives_sibling_release() {
        // The heap tier's box must live until the last reference is
        // dropped: handing it to the first releaser would leave sibling
        // readers an empty Cow (decode would slice out of bounds).
        let pool = SlabPool::new();
        let mut primary_handles = Vec::new();
        for _ in 0..16 {
            let payload = vec![0u8; 100_000];
            let (h, _m) = pool
                .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
                .expect("primary slot should be available");
            primary_handles.push(h);
        }
        let payload = vec![0xCDu8; 100_000];
        let (h_heap, m_heap) = pool
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("heap fallback once primary is full");
        assert_eq!(m_heap, SlabMetric::HeapFallback);

        pool.add_ref(h_heap); // sibling reader's reference
        pool.release(h_heap); // first reader done

        // Sibling must still see the FULL buffer, never an empty Cow.
        let buf = pool.get_buffer(h_heap);
        assert_eq!(buf.len(), 100_000);
        assert!(buf.iter().all(|&b| b == 0xCD));

        pool.release(h_heap); // last reference: box dropped, accounting settles
        let (_p, _l, _h, _d, used) = pool.metrics().snapshot();
        assert_eq!(used, 0, "heap accounting must return to zero");
        let empty = pool.get_buffer(h_heap);
        assert!(empty.is_empty(), "released heap slot serves nothing");

        for h in primary_handles {
            pool.release(h);
        }
    }

    /// Storage held for samples that cannot be taken yet keeps the heap
    /// room their head needs: past it, the hold is refused, and what is
    /// given back is room again.
    #[test]
    fn held_heap_storage_keeps_room_for_the_head() {
        // The whole heap tier the readers' share: the held ceiling.
        let pool = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 1_000_000,
            reader_reserve_percent: 100,
            ..MemoryPolicy::default()
        });
        let big = vec![0u8; 200_000];
        let (a, m) = pool
            .reserve_and_write(&big, crate::core::rt::Claim::Reader)
            .expect("heap");
        assert_eq!(m, SlabMetric::HeapFallback);
        let (b, _) = pool
            .reserve_and_write(&big, crate::core::rt::Claim::Reader)
            .expect("heap");
        let (c, _) = pool
            .reserve_and_write(&big, crate::core::rt::Claim::Reader)
            .expect("heap");
        let held = &pool.metrics().held_heap_bytes;
        assert_eq!(pool.hold(a, big.len(), big.len()), Some(big.len()));
        assert_eq!(pool.hold(b, big.len(), big.len()), Some(big.len()));
        assert_eq!(held.load(Ordering::Acquire), 400_000);
        // 600 000 held, and the head's 200 000: 800 000, within the
        // ceiling; with a head of 500 000, not.
        assert_eq!(
            pool.hold(c, big.len(), 500_000),
            None,
            "no room for the head"
        );
        assert_eq!(
            held.load(Ordering::Acquire),
            400_000,
            "a refusal charges nothing"
        );
        assert_eq!(pool.hold(c, big.len(), big.len()), Some(big.len()));
        // 600 000 held: 150 000 more and a head of 250 000 is the ceiling
        // exactly, granted at the bound; a head of 250 001 is not.
        let (d, _) = pool
            .reserve_and_write(&[0u8; 150_000], crate::core::rt::Claim::Reader)
            .expect("heap");
        assert_eq!(pool.hold(d, 150_000, 250_001), None);
        assert_eq!(
            pool.hold(d, 150_000, 250_000),
            Some(150_000),
            "at the bound"
        );
        pool.unhold(150_000);
        // Given back: 200 000 less held, room for a head that was refused.
        assert_eq!(pool.hold(d, 150_000, 350_000), None);
        pool.unhold(big.len());
        assert_eq!(held.load(Ordering::Acquire), 400_000);
        assert_eq!(
            pool.hold(d, 150_000, 350_000),
            Some(150_000),
            "room given back"
        );
        for h in [a, b, c, d] {
            pool.release(h);
        }
    }

    /// Staged storage is the heap tier's, outside its ceiling and its
    /// gauge: stored with the tier full, on its own gauge, given back to it
    /// at the last release, whatever the references taken meanwhile.
    #[test]
    fn staged_storage_is_outside_the_heap_ceiling_and_gauge() {
        let pool = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 300_000,
            reader_reserve_percent: 25,
            ..MemoryPolicy::default()
        });
        let big = vec![7u8; 200_000];
        let (full, _) = pool
            .reserve_and_write(&big, crate::core::rt::Claim::Reader)
            .expect("heap");
        assert!(
            pool.reserve_and_write(&big, crate::core::rt::Claim::Reader)
                .is_none(),
            "the tier is full"
        );
        let staged = pool.reserve_staged(&big).expect("staged");
        let metrics = pool.metrics();
        assert_eq!(metrics.heap_bytes_used.load(Ordering::Acquire), 200_000);
        assert_eq!(metrics.staged_heap_bytes.load(Ordering::Acquire), 200_000);
        assert_eq!(&pool.get_buffer(staged)[..], &big[..]);
        pool.add_ref(staged);
        pool.release(staged);
        assert_eq!(metrics.staged_heap_bytes.load(Ordering::Acquire), 200_000);
        pool.release(staged);
        assert_eq!(metrics.staged_heap_bytes.load(Ordering::Acquire), 0);
        assert_eq!(metrics.heap_bytes_used.load(Ordering::Acquire), 200_000);
        let exclusive = pool.reserve_staged(&big).expect("staged");
        pool.release_exclusive(exclusive);
        assert_eq!(metrics.staged_heap_bytes.load(Ordering::Acquire), 0);
        pool.release(full);
        assert_eq!(metrics.heap_bytes_used.load(Ordering::Acquire), 0);
    }

    /// Storage of a size class is charged nothing, the head never needing
    /// it, but it is held only while the heap tier keeps the head's room.
    #[test]
    fn held_class_storage_is_charged_nothing_but_needs_the_head_room() {
        let pool = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 10_000,
            reader_reserve_percent: 100,
            ..MemoryPolicy::default()
        });
        let (h, m) = pool
            .reserve_and_write(&[1u8; 100], crate::core::rt::Claim::Reader)
            .expect("primary");
        assert_eq!(m, SlabMetric::Primary);
        assert_eq!(pool.hold(h, 100, 10_000), Some(0));
        assert_eq!(pool.metrics().held_heap_bytes.load(Ordering::Acquire), 0);
        assert_eq!(pool.hold(h, 100, 10_001), None, "no room kept for the head");
        let none = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 0,
            reader_reserve_percent: 100,
            ..MemoryPolicy::default()
        });
        let (h0, _) = none
            .reserve_and_write(&[1u8; 100], crate::core::rt::Claim::Reader)
            .expect("primary");
        assert_eq!(none.hold(h0, 100, 100), None, "no heap tier: nothing held");
        pool.release(h);
        none.release(h0);
    }

    /// A writer finds a size class full once only the readers' share of it
    /// is left (rounded up: 4 of the 16 slots of the 128 KiB class at the
    /// default 25 %), whoever holds the rest; a reader takes the class
    /// whole. Counted on the taken slots: room a reader gives back is room
    /// for a writer again only once fewer than the writer's limit are taken.
    #[test]
    fn a_writer_never_takes_the_readers_share_of_a_class() {
        // No heap tier: a 100 kB payload fits the 128 KiB class only.
        let pool = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 0,
            ..MemoryPolicy::default()
        });
        let payload = vec![7u8; 100_000];
        let mut writer = Vec::new();
        while let Some((h, _)) = pool.reserve_and_write(&payload, Claim::Writer) {
            writer.push(h);
        }
        assert_eq!(writer.len(), 12, "16 slots, 4 kept for readers");
        let mut reader = Vec::new();
        while let Some((h, _)) = pool.reserve_and_write(&payload, Claim::Reader) {
            reader.push(h);
        }
        assert_eq!(reader.len(), 4, "the readers' share, whole");
        assert!(pool.reserve(100_000).is_none(), "`reserve` is a writer's");
        // A writer gives its first slot back: 15 taken around a free first
        // slot, still past a writer's limit.
        pool.release(writer.remove(0));
        assert!(
            pool.reserve_and_write(&payload, Claim::Writer).is_none(),
            "15 taken, the free slot first"
        );
        // The readers give theirs back: 11 taken, room for a writer.
        for h in reader.drain(..) {
            pool.release(h);
        }
        let (h, _) = pool
            .reserve_and_write(&payload, Claim::Writer)
            .expect("11 taken: room for a writer");
        writer.push(h);
        assert!(
            pool.reserve_and_write(&payload, Claim::Writer).is_none(),
            "12 taken, a writer's limit"
        );
        for h in writer {
            pool.release(h);
        }
    }

    /// The heap tier likewise: a writer's ceiling is `max_heap_bytes` less
    /// the readers' share, a reader's the whole tier; held storage stays
    /// within the readers' share.
    #[test]
    fn a_writer_never_takes_the_readers_share_of_the_heap() {
        let pool = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 1_000_000,
            ..MemoryPolicy::default()
        });
        // Over the largest class: heap tier only.
        let big = vec![1u8; 200_000];
        let mut held = Vec::new();
        for _ in 0..3 {
            let (h, m) = pool
                .reserve_and_write(&big, Claim::Writer)
                .expect("within 750 000");
            assert_eq!(m, SlabMetric::HeapFallback);
            held.push(h);
        }
        assert!(
            pool.reserve_and_write(&big, Claim::Writer).is_none(),
            "800 000 is past a writer's 750 000"
        );
        for _ in 0..2 {
            let (h, _) = pool
                .reserve_and_write(&big, Claim::Reader)
                .expect("a reader's tier is the whole 1 000 000");
            held.push(h);
        }
        assert!(pool.reserve_and_write(&big, Claim::Reader).is_none());
        // Held storage: the readers' 250 000, a head of 50 000 kept.
        let r = held[3];
        assert_eq!(pool.hold(r, 200_000, 50_000), Some(200_000));
        assert_eq!(pool.hold(held[4], 200_000, 1), None, "past the share");
        for h in held {
            pool.release(h);
        }
        pool.unhold(200_000);
    }

    /// The head of a gap takes the heap tier past its ceiling by its own
    /// length, only while the tier is not past it already: the gauge is
    /// never past the ceiling by more than one sample. A reader's claim
    /// never passes it.
    #[test]
    fn a_head_passes_the_heap_ceiling_by_one_sample_at_most() {
        let pool = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 1_000_000,
            ..MemoryPolicy::default()
        });
        let big = vec![1u8; 300_000];
        let used = || pool.metrics().heap_bytes_used.load(Ordering::Acquire);
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(pool.reserve_and_write(&big, Claim::Reader).expect("heap").0);
        }
        assert!(pool.reserve_and_write(&big, Claim::Reader).is_none());
        let (head, m) = pool
            .reserve_and_write(&big, Claim::Head)
            .expect("900 000 used: the head passes the ceiling");
        assert_eq!(m, SlabMetric::HeapFallback);
        assert_eq!(used(), 1_200_000, "past the ceiling by the head alone");
        assert!(
            pool.reserve_and_write(&[1u8; 200_000], Claim::Head)
                .is_none(),
            "past the ceiling already: a second head waits"
        );
        assert!(pool
            .reserve_and_write(&[1u8; 1], Claim::Reader)
            .is_some_and(|(h, m)| {
                pool.release(h);
                m == SlabMetric::Primary
            }));
        // Back within the ceiling: a head may pass it again.
        pool.release(held.pop().expect("held"));
        pool.release(held.pop().expect("held"));
        assert_eq!(used(), 600_000);
        let (second, _) = pool
            .reserve_and_write(&vec![1u8; 500_000], Claim::Head)
            .expect("within the ceiling again");
        assert_eq!(used(), 1_100_000);
        for h in held.into_iter().chain([head, second]) {
            pool.release(h);
        }
        assert_eq!(used(), 0);
    }

    /// The accepted range's top is the highest share that leaves writers a
    /// slot of every primary size class, and the bottom keeps a slot of
    /// each for readers.
    #[test]
    fn the_accepted_readers_share_leaves_both_sides_a_slot() {
        let both = |percent: u8| {
            let pool = SlabPool::with_policy(&MemoryPolicy {
                reader_reserve_percent: percent,
                ..MemoryPolicy::default()
            });
            pool.pools
                .iter()
                .all(|p| p.writer_limit >= 1 && p.writer_limit < p.slot_count)
        };
        let accepted: Vec<u8> = (0..=100).filter(|&p| both(p)).collect();
        assert_eq!(
            (accepted.first().copied(), accepted.last().copied()),
            (
                Some(MemoryPolicy::READER_RESERVE_PERCENT_MIN),
                Some(MemoryPolicy::READER_RESERVE_PERCENT_MAX)
            )
        );
        assert_eq!(accepted.len(), 93, "contiguous");
        for percent in 0..=100u8 {
            let policy = MemoryPolicy {
                reader_reserve_percent: percent,
                ..MemoryPolicy::default()
            };
            assert_eq!(
                policy.check_reader_reserve_percent().is_ok(),
                both(percent),
                "{percent}"
            );
        }
    }

    /// Held storage is the readers' share's: a writer's part of the heap
    /// tier is counted without it, and the tier stays within its ceiling.
    #[test]
    fn held_storage_takes_nothing_of_the_writers_part() {
        let pool = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 1_000_000,
            ..MemoryPolicy::default()
        });
        let (r, _) = pool
            .reserve_and_write(&vec![1u8; 250_000], Claim::Reader)
            .expect("heap");
        assert_eq!(pool.hold(r, 250_000, 0), Some(250_000));
        let mut writer = Vec::new();
        while let Some((h, _)) = pool.reserve_and_write(&vec![1u8; 250_000], Claim::Writer) {
            writer.push(h);
        }
        assert_eq!(writer.len(), 3, "the writers' 750 000, whole");
        assert_eq!(
            pool.metrics().heap_bytes_used.load(Ordering::Acquire),
            1_000_000,
            "within the ceiling"
        );
        pool.unhold(250_000);
        assert!(
            pool.reserve_and_write(&[1u8; 200_000], Claim::Writer)
                .is_none(),
            "given back, it counts as a reader's storage"
        );
        for h in writer.into_iter().chain([r]) {
            pool.release(h);
        }
    }

    /// The share is a knob: 0 lets a writer take every tier whole, 100
    /// keeps every tier for readers.
    #[test]
    fn the_readers_share_is_set_by_the_policy() {
        let none = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 0,
            reader_reserve_percent: 0,
            ..MemoryPolicy::default()
        });
        let payload = vec![7u8; 100_000];
        let mut taken = Vec::new();
        while let Some((h, _)) = none.reserve_and_write(&payload, Claim::Writer) {
            taken.push(h);
        }
        assert_eq!(taken.len(), 16, "no share: the class whole");
        for h in taken {
            none.release(h);
        }
        let all = SlabPool::with_policy(&MemoryPolicy {
            max_heap_bytes: 1_000_000,
            reader_reserve_percent: 100,
            ..MemoryPolicy::default()
        });
        assert!(all.reserve_and_write(&[1u8; 16], Claim::Writer).is_none());
        assert!(all.reserve(16).is_none());
        let (h, _) = all
            .reserve_and_write(&[1u8; 16], Claim::Reader)
            .expect("a reader's");
        all.release(h);
    }
    /// Receipt snapshots follow ownership of a slab slot through references
    /// and reuse in every tier; no sequence-keyed history survives reuse.
    #[test]
    fn generation_snapshots_follow_live_slots_and_reuse_in_all_tiers() {
        let pool = SlabPool::with_policy(&MemoryPolicy {
            large_pool: LargePoolConfig {
                classes: vec![(262_144, 1)],
            },
            max_heap_bytes: 2_000_000,
            ..MemoryPolicy::default()
        });
        for (len, tier) in [
            (32, SlabMetric::Primary),
            (200_000, SlabMetric::Large),
            (400_000, SlabMetric::HeapFallback),
        ] {
            let payload = vec![0x57; len];
            let (handle, actual) = pool
                .reserve_and_write(&payload, Claim::Reader)
                .expect("slot");
            assert_eq!(actual, tier);
            pool.set_generation_counts(handle, (1, 2));
            pool.add_ref(handle);
            pool.release(handle);
            assert_eq!(pool.generation_counts(handle), (1, 2));
            pool.release(handle);
            let (reused, _) = pool
                .reserve_and_write(&payload, Claim::Reader)
                .expect("reused slot");
            assert_eq!(reused, handle, "the freed slot is reused");
            // An untagged entry never reads the previous owner's snapshot.
            let mut entry = crate::core::rt::IndexEntry::new(1, reused, len as u32);
            assert!(!entry.has_generation_counts());
            pool.set_generation_counts(reused, (3, 4));
            entry.mark_generation_counts();
            assert!(entry.has_generation_counts());
            assert_eq!(pool.generation_counts(reused), (3, 4));
            assert_eq!(pool.read_array::<1>(reused, 0), Some([0x57]));
            pool.release(reused);
        }
    }
}

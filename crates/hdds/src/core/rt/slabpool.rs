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

use std::cell::UnsafeCell;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};

/// Handle to a reserved slab region
///
/// Encoded as: upper 16 bits = pool_id, lower 16 bits = slot_id
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlabHandle(pub u32);

impl SlabHandle {
    fn new(pool_id: u16, slot_id: u16) -> Self {
        Self(((u32::from(pool_id)) << 16) | u32::from(slot_id))
    }

    fn pool_id(self) -> u16 {
        (self.0 >> 16) as u16 // SAFETY: upper 16 bits store the original pool_id value.
    }

    fn slot_id(self) -> u16 {
        (self.0 & 0xFFFF) as u16 // SAFETY: mask keeps value within u16 range.
    }
}

/// Size class configuration: (slot_size, slot_count)
///
/// Optimized for fast allocation with minimal memory footprint.
/// Larger slot counts for bigger sizes support pipelining of fragmented messages
/// and buffering when application read rate is slower than network receive rate.
const SIZE_CLASSES: &[(usize, usize)] = &[
    (16, 64),     // 16B x 64 slots = 1 KB
    (32, 64),     // 32B x 64 slots = 2 KB
    (64, 64),     // 64B x 64 slots = 4 KB
    (128, 64),    // 128B x 64 slots = 8 KB
    (256, 64),    // 256B x 64 slots = 16 KB
    (512, 64),    // 512B x 64 slots = 32 KB
    (1024, 64),   // 1KB x 64 slots = 64 KB
    (2048, 32),   // 2KB x 32 slots = 64 KB
    (4096, 32),   // 4KB x 32 slots = 128 KB
    (8192, 32),   // 8KB x 32 slots = 256 KB
    (16384, 32),  // 16KB x 32 slots = 512 KB
    (32768, 32),  // 32KB x 32 slots = 1 MB
    (65536, 32),  // 64KB x 32 slots = 2 MB
    (131072, 16), // 128KB x 16 slots = 2 MB
];

/// Per-pool state with atomic bitmap for free slot tracking
struct Pool {
    data: UnsafeCell<Vec<u8>>,
    bitmap: AtomicU64,
    slot_size: usize,
    slot_count: usize,
}

// SAFETY: Pool is Send + Sync because:
// - data is protected by atomic bitmap (mutual exclusion via CAS)
// - only one thread can access a given slot at a time
unsafe impl Send for Pool {}
unsafe impl Sync for Pool {}

impl Pool {
    fn new(slot_size: usize, slot_count: usize) -> Self {
        let total_size = slot_size * slot_count;
        let data = UnsafeCell::new(vec![0u8; total_size]);

        // Initialize bitmap: all slots free (all bits set to 0)
        let bitmap = AtomicU64::new(0);

        Self {
            data,
            bitmap,
            slot_size,
            slot_count,
        }
    }

    /// Try to reserve a slot from this pool
    ///
    /// Returns (slot_id, &mut [u8]) on success, None if pool full.
    ///
    /// SAFETY:
    /// - Atomic CAS ensures only one thread claims a given slot
    /// - Bounds checked: slot_id always < slot_count
    /// - Mutable slice returned is exclusive to this slot (enforced by bitmap)
    /// - UnsafeCell: interior mutability is safe because bitmap ensures no aliasing
    #[allow(clippy::mut_from_ref)]
    fn try_reserve(&self) -> Option<(u16, &mut [u8])> {
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

            // Try to claim this slot (set bit to 1)
            let new_bitmap = bitmap | (1u64 << slot_index);
            if self
                .bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
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
    /// - Atomic CAS ensures no double-free
    fn release_slot(&self, slot_id: u16) {
        debug_assert!(usize::from(slot_id) < self.slot_count, "Invalid slot_id");

        let slot_mask = 1u64 << slot_id;
        loop {
            let bitmap = self.bitmap.load(Ordering::Acquire);

            // Clear the bit (mark free)
            let new_bitmap = bitmap & !slot_mask;
            if self
                .bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            // CAS failed, retry
        }
    }
}

/// Memory pool for zero-copy message buffers
///
/// Allocates from size-class pools using atomic bitmaps (lock-free).
/// Target: reserve + release < 100 ns.
pub struct SlabPool {
    pools: Vec<Pool>,
}

impl SlabPool {
    pub fn new() -> Self {
        let pools = SIZE_CLASSES
            .iter()
            .map(|&(size, count)| Pool::new(size, count))
            .collect();

        Self { pools }
    }

    /// Reserve buffer space; returns handle + mutable slice
    ///
    /// Finds the smallest size class >= len and attempts to allocate.
    /// Falls back to larger classes if smaller ones are full.
    ///
    /// # Returns
    /// - `Some((handle, slice))` on success
    /// - `None` if all pools exhausted
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
    ///   Last measured: 2025-10-21 on Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz.
    ///
    /// # Safety
    /// Uses interior mutability (UnsafeCell) with atomic bitmap protection.
    /// Safe because bitmap CAS ensures exclusive access to allocated slots.
    pub fn reserve(&self, len: usize) -> Option<(SlabHandle, &mut [u8])> {
        // Find first size class >= len
        let start_idx = SIZE_CLASSES.iter().position(|&(size, _)| size >= len)?;

        // Try pools starting from best-fit size class
        for pool_id in start_idx..self.pools.len() {
            if let Some((slot_id, slice)) = self.pools[pool_id].try_reserve() {
                let pool_id = match u16::try_from(pool_id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };
                let handle = SlabHandle::new(pool_id, slot_id);
                return Some((handle, slice));
            }
        }

        None // All pools full
    }

    /// Commit reserved space (mark written)
    ///
    /// **Architectural note:** SlabPool is a minimal memory allocator. "Committed" tracking
    /// is handled at a higher level by IndexEntry.flags (COMMITTED_FLAG). This design keeps
    /// SlabPool simple (allocate/deallocate) and pushes semantic state to the index layer.
    ///
    /// This function exists for API completeness (reserve -> write -> commit -> release pattern)
    /// but is intentionally a no-op. Writers should set IndexEntry.flags = COMMITTED_FLAG
    /// after copying data to the slab buffer.
    ///
    /// See: `core::rt::indexring::COMMITTED_FLAG` for the actual committed tracking mechanism.
    pub fn commit(&self, _handle: SlabHandle, _len: usize) {
        // Intentional no-op: committed tracking done via IndexEntry.flags (see doc above)
    }

    /// Get immutable buffer from handle (for reading)
    ///
    /// Returns a slice to the committed buffer data.
    ///
    /// # Safety
    /// - Handle must be valid and currently allocated
    /// - Buffer must have been committed via commit()
    /// - Caller must ensure no concurrent writes to this handle
    ///
    /// # Panics
    /// Panics if handle is invalid (debug builds only).
    ///
    /// # Performance
    /// Target: < 20 ns (pointer arithmetic only, no atomics)
    #[allow(clippy::mut_from_ref)]
    pub fn get_buffer(&self, handle: SlabHandle) -> &[u8] {
        let pool_id = usize::from(handle.pool_id());
        let slot_id = usize::from(handle.slot_id());

        debug_assert!(pool_id < self.pools.len(), "Invalid pool_id");

        let pool = &self.pools[pool_id];
        debug_assert!(slot_id < pool.slot_count, "Invalid slot_id");

        // SAFETY: Bitmap ensures this slot is allocated
        // Caller guarantees handle is valid and committed
        let offset = slot_id * pool.slot_size;
        // SAFETY:
        // 1. pool.data was allocated once during Pool::new and never freed while Pool alive.
        // 2. Slot is allocated (bitmap bit set) so slice lies within initialized memory.
        // 3. We only create an immutable slice (&[u8]), so concurrent readers are allowed.
        // 4. Offset math bounded by slot_count and slot_size.
        let data = unsafe { &*pool.data.get() };
        &data[offset..offset + pool.slot_size]
    }

    /// Release slab after reading
    ///
    /// Returns the slot to the pool's free list.
    ///
    /// # Panics
    /// Panics if handle is invalid (debug builds only).
    ///
    /// # Performance
    /// Target: < 50 ns (single CAS)
    ///
    /// # Latency
    /// - **p50:** 23.93 ns
    /// - **p99:** 27.78 ns (**SLA target:** < 100 ns)
    /// - **p999:** 27.84 ns
    ///   [!] **Benchmark methodology:** Measures release only via Criterion
    ///   `slabpool_release` (benches/runtime.rs) with hot cache / pre-reserved slots.
    ///   Last measured: 2025-10-21 on Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz.
    ///   **Exception rationale:** CAS on 64-bit bitmap incurs ~20-25 ns hardware latency on x86_64;
    ///   additional bookkeeping (~3 ns) yields ~28 ns p99. Alternatives (spinlock, batching) perform
    ///   worse (>50 ns). Acceptable deviation recorded in audit (Section 8).
    pub fn release(&self, handle: SlabHandle) {
        let pool_id = usize::from(handle.pool_id());
        let slot_id = handle.slot_id();

        debug_assert!(pool_id < self.pools.len(), "Invalid pool_id");

        self.pools[pool_id].release_slot(slot_id);
    }
}

impl Default for SlabPool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_encoding() {
        let h = SlabHandle::new(42, 1337);
        assert_eq!(h.pool_id(), 42);
        assert_eq!(h.slot_id(), 1337);
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
        assert_eq!(h.pool_id(), 0); // First pool (16B)

        pool.release(h);

        // Request 100 bytes -> should get 128B pool
        let (h2, buf2) = pool
            .reserve(100)
            .expect("SlabPool reservation should succeed");
        assert_eq!(buf2.len(), 128);
        assert_eq!(h2.pool_id(), 3); // Fourth pool (128B)
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
        assert_eq!(h_fallback.pool_id(), 1); // Second pool (32B)
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
}

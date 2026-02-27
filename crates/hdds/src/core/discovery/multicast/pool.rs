// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Lock-free buffer pool for zero-allocation multicast receive.
//!
//! Pre-allocates N buffers of MTU size, managed via lock-free freelist.
//! Listener acquires buffers, FSM releases them after processing.
//!
//! # Performance
//!
//! - acquire/release: < 30 ns (p99)
//! - Memory: 16 buffers x 1500 bytes = 24 KB (default)

use crossbeam::queue::ArrayQueue;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Buffer pool for zero-allocation multicast receive
///
/// Pre-allocates N buffers of size MTU, managed via lock-free freelist.
/// Listener thread acquires buffers, FSM releases them after processing.
///
/// # Design
/// - **Lock-free:** Uses crossbeam ArrayQueue (MPSC-safe)
/// - **Zero-copy:** Buffers owned by pool, passed by BufferId (u8)
/// - **Metrics:** Tracks exhaustion events (when all buffers in use)
///
/// # Memory Budget
/// - 16 buffers x 1500 bytes = 24 KB (default config)
/// - 64 buffers x 9000 bytes = 576 KB (jumbo frames config)
pub struct RxPool {
    /// Pre-allocated packet buffers (MTU-sized)
    buffers: Vec<Vec<u8>>,
    /// Lock-free freelist of available buffer IDs
    freelist: Arc<ArrayQueue<u8>>,
    /// Count of pool exhaustion events (diagnostic)
    exhausted_count: AtomicU64,
}

impl RxPool {
    /// Create new RxPool with specified capacity and buffer size
    ///
    /// # Arguments
    /// - `capacity`: Number of buffers (1-255, typically 16)
    /// - `buffer_size`: Size per buffer in bytes (typically 1500 MTU or 9000 jumbo)
    ///
    /// # Panics
    /// Panics if capacity > 255 (BufferId is u8)
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::multicast::RxPool;
    ///
    /// // Standard Ethernet MTU config
    /// let pool = RxPool::new(16, 1500).expect("Pool creation should succeed");
    /// assert_eq!(pool.capacity(), 16);
    ///
    /// // Jumbo frames config
    /// let pool_jumbo = RxPool::new(64, 9000).expect("Pool creation should succeed");
    /// assert_eq!(pool_jumbo.capacity(), 64);
    /// ```
    pub fn new(capacity: usize, buffer_size: usize) -> Result<Self, &'static str> {
        assert!(
            capacity > 0 && capacity <= 255,
            "RxPool capacity must be 1-255 (BufferId is u8)"
        );

        // Pre-allocate buffers
        let buffers: Vec<Vec<u8>> = (0..capacity).map(|_| vec![0u8; buffer_size]).collect();

        // Initialize freelist with all buffer IDs
        // SAFETY: ArrayQueue capacity matches loop count, push cannot fail
        let freelist = Arc::new(ArrayQueue::new(capacity));
        for id in 0..capacity {
            let id_u8 = match u8::try_from(id) {
                Ok(value) => value,
                Err(_) => return Err("Freelist init failed: buffer id overflow"),
            };
            freelist
                .push(id_u8)
                .map_err(|_| "Freelist init failed: capacity mismatch")?;
        }

        Ok(Self {
            buffers,
            freelist,
            exhausted_count: AtomicU64::new(0),
        })
    }

    /// Get pool capacity (total number of buffers)
    pub fn capacity(&self) -> usize {
        self.buffers.len()
    }

    /// Get current number of available buffers
    pub fn available(&self) -> usize {
        self.freelist.len()
    }

    /// Acquire a buffer for listener thread
    ///
    /// Returns `Some(buffer_id)` if a buffer is available, `None` if pool exhausted.
    /// On exhaustion, increments `exhausted_count` metric.
    ///
    /// # Thread Safety
    /// Safe to call from listener thread (MPSC producer).
    ///
    /// # Latency
    /// - **p50:** 23.98 ns
    /// - **p99:** 25.38 ns (`SLA target < 100 ns`)
    /// - **p999:** 25.44 ns
    ///
    /// Measured in `rxpool_acquire_release` (see `benches/discovery_latency.rs`).
    /// Last measured on 2025-10-21 (Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz).
    pub fn acquire_for_listener(&self) -> Option<u8> {
        match self.freelist.pop() {
            Some(id) => Some(id),
            None => {
                self.exhausted_count.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Release a buffer back to the pool
    ///
    /// Must be called by FSM after processing packet to avoid buffer leak.
    ///
    /// # Arguments
    /// * `buffer_id` - The buffer ID acquired from `acquire_for_listener()`.
    ///
    /// # Errors
    /// Returns error if double-release detected (freelist full)
    ///
    /// # Panics
    /// Panics if buffer_id >= capacity (debug mode only)
    ///
    /// # Thread Safety
    /// Safe to call from FSM thread (MPSC consumer).
    pub fn release(&self, buffer_id: u8) -> Result<(), &'static str> {
        debug_assert!(
            (buffer_id as usize) < self.buffers.len(),
            "Invalid buffer_id: {} >= {}",
            buffer_id,
            self.buffers.len()
        );

        self.freelist
            .push(buffer_id)
            .map_err(|_| "Freelist full: double release detected")
    }

    /// Get mutable reference to buffer (for listener write)
    ///
    /// # Safety
    /// Caller must ensure buffer_id is currently acquired and not aliased.
    /// Typically called immediately after `acquire_for_listener()`.
    ///
    /// # Panics
    /// Panics if buffer_id >= capacity
    pub fn get_buffer_mut(&mut self, buffer_id: u8) -> &mut [u8] {
        &mut self.buffers[buffer_id as usize]
    }

    /// Get immutable reference to buffer (for FSM read)
    ///
    /// # Safety
    /// Caller must ensure buffer_id is currently acquired.
    ///
    /// # Panics
    /// Panics if buffer_id >= capacity
    pub fn get_buffer(&self, buffer_id: u8) -> &[u8] {
        &self.buffers[buffer_id as usize]
    }

    /// Get pool exhaustion count (diagnostic metric)
    pub fn exhausted_count(&self) -> u64 {
        self.exhausted_count.load(Ordering::Relaxed)
    }

    /// Get shareable reference to freelist (for MulticastListener)
    pub fn freelist(&self) -> Arc<ArrayQueue<u8>> {
        Arc::clone(&self.freelist)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creation() {
        let pool = RxPool::new(16, 1500).expect("Pool creation should succeed");
        assert_eq!(pool.capacity(), 16);
        assert_eq!(pool.available(), 16);
    }

    #[test]
    fn test_acquire_release_cycle() {
        let pool = RxPool::new(4, 512).expect("Pool creation should succeed");

        // Acquire all buffers
        let ids: Vec<u8> = (0..4).filter_map(|_| pool.acquire_for_listener()).collect();
        assert_eq!(ids.len(), 4);
        assert_eq!(pool.available(), 0);

        // Pool exhausted
        assert!(pool.acquire_for_listener().is_none());
        assert_eq!(pool.exhausted_count(), 1);

        // Release one buffer
        pool.release(ids[0]).expect("Buffer release should succeed");
        assert_eq!(pool.available(), 1);

        // Can acquire again
        assert!(pool.acquire_for_listener().is_some());
    }

    #[test]
    fn test_buffer_access() {
        let mut pool = RxPool::new(2, 128).expect("Pool creation should succeed");

        let id = pool
            .acquire_for_listener()
            .expect("Buffer acquisition should succeed");

        // Write to buffer
        {
            let buf = pool.get_buffer_mut(id);
            buf[0] = 0x42;
            buf[1] = 0xFF;
        }

        // Read from buffer
        let buf = pool.get_buffer(id);
        assert_eq!(buf[0], 0x42);
        assert_eq!(buf[1], 0xFF);

        pool.release(id).expect("Buffer release should succeed");
    }

    #[test]
    #[should_panic(expected = "RxPool capacity must be 1-255")]
    fn test_pool_capacity_overflow() {
        let _ = RxPool::new(256, 1500); // Should panic
    }

    #[test]
    #[should_panic(expected = "RxPool capacity must be 1-255")]
    fn test_pool_zero_capacity() {
        let _ = RxPool::new(0, 1500); // Should panic
    }

    /// Layer 1 Resilience Test: Verify pool exhaustion handling
    ///
    /// **Goal:** Prove that pool exhaustion is handled gracefully without panic
    ///
    /// **Scenario:**
    /// 1. Create small pool (4 buffers)
    /// 2. Acquire all buffers
    /// 3. Try to acquire 5th buffer (should fail gracefully with None)
    /// 4. Release one buffer
    /// 5. Retry acquisition (should succeed)
    /// 6. Verify no panic or undefined behavior
    ///
    /// **Success Criteria:**
    /// - acquire_for_listener() returns None when pool exhausted
    /// - Release + re-acquire works correctly
    /// - No panic or crash
    #[test]
    fn test_pool_exhaustion_graceful_failure() -> Result<(), String> {
        // Setup: Small pool with only 4 buffers
        let pool = RxPool::new(4, 1500).map_err(|e| e.to_string())?;

        // Acquire all 4 buffers
        let id0 = pool
            .acquire_for_listener()
            .ok_or("Buffer 0 should be available")?;
        let id1 = pool
            .acquire_for_listener()
            .ok_or("Buffer 1 should be available")?;
        let id2 = pool
            .acquire_for_listener()
            .ok_or("Buffer 2 should be available")?;
        let id3 = pool
            .acquire_for_listener()
            .ok_or("Buffer 3 should be available")?;

        log::debug!("[test] Acquired all 4 buffers: {:?}", [id0, id1, id2, id3]);

        // Try to acquire 5th buffer (pool exhausted)
        let id4_result = pool.acquire_for_listener();

        // Verify: Should fail gracefully with None
        if id4_result.is_some() {
            return Err("Pool exhaustion should return None".to_string());
        }
        log::debug!("[test] [OK] Pool exhaustion returned None gracefully");

        // Release buffer 0
        pool.release(id0).map_err(|e| e.to_string())?;
        log::debug!("[test] Released buffer {}", id0);

        // Retry acquisition (should succeed now)
        let id4_retry = pool
            .acquire_for_listener()
            .ok_or("After release, acquisition should succeed")?;
        log::debug!("[test] [OK] Re-acquisition succeeded after release");

        // Cleanup: Release all buffers
        pool.release(id1).map_err(|e| e.to_string())?;
        pool.release(id2).map_err(|e| e.to_string())?;
        pool.release(id3).map_err(|e| e.to_string())?;
        pool.release(id4_retry).map_err(|e| e.to_string())?;

        // Verify all buffers available again
        let id_final = pool
            .acquire_for_listener()
            .ok_or("All buffers should be available after release")?;
        pool.release(id_final).map_err(|e| e.to_string())?;

        log::debug!("[test] [OK] Pool exhaustion handled gracefully without panic");
        Ok(())
    }
}

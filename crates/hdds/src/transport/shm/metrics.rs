// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SHM Transport Metrics
//!
//! Provides atomic counters for tracking SHM transport performance and usage.
//! All metrics are thread-safe and can be read/reset from any thread.
//!
//! # Tracked Metrics
//!
//! - `shm_writes`: Total messages sent via SHM
//! - `shm_reads`: Total messages received via SHM
//! - `shm_fallback_udp`: Times SHM was unavailable, fell back to UDP
//! - `shm_overruns`: Reader overrun events (reader too slow)
//! - `shm_wake_calls`: Futex wake syscalls
//! - `shm_wait_calls`: Futex wait syscalls

use std::sync::atomic::{AtomicU64, Ordering};

/// SHM transport metrics with atomic counters.
///
/// All counters use `Relaxed` ordering for minimal overhead.
/// Metrics are eventually consistent across threads.
#[derive(Debug, Default)]
pub struct ShmMetrics {
    /// Total messages written via SHM
    pub shm_writes: AtomicU64,
    /// Total messages read via SHM
    pub shm_reads: AtomicU64,
    /// Fallback to UDP count (SHM unavailable)
    pub shm_fallback_udp: AtomicU64,
    /// Reader overrun events (data lost due to slow reader)
    pub shm_overruns: AtomicU64,
    /// Futex wake syscalls
    pub shm_wake_calls: AtomicU64,
    /// Futex wait syscalls
    pub shm_wait_calls: AtomicU64,
    /// Framed packets the SHM leg refused because they exceed
    /// `SLOT_PAYLOAD_SIZE`. The slot is sized so that no packet the UDP
    /// path emits unfragmented can reach this, so a NON-ZERO value here
    /// means the slot budget has been outgrown (an extreme topic name, or a
    /// change to `DEFAULT_MAX_UNFRAGMENTED_SIZE`), NOT normal operation.
    /// Each one is also logged at error level.
    pub shm_oversize_refused: AtomicU64,
    /// Writers whose shared-memory segment could not be created, so the
    /// writer gave up on SHM entirely and moved every reader back to UDP.
    /// Counted once per writer, not once per packet.
    pub shm_writer_segment_failures: AtomicU64,
    /// Remote writer rings a reader was told to drain and never managed to
    /// attach to within the attach budget. Each one means samples that
    /// writer sends over shared memory are being lost, so it is logged at
    /// error level and counted once per abandoned peer.
    pub shm_attach_abandoned: AtomicU64,
    /// Readers that attached to a writer's ring but found its presence table
    /// full, so the writer keeps serving them over UDP. Costs bandwidth, never
    /// samples: a participant that cannot claim an entry is exactly a
    /// participant the writer will not stop sending UDP to.
    pub shm_presence_table_full: AtomicU64,
    /// Packets for which a peer held a presence claim whose cursor had stopped
    /// moving and now sits more than a ring behind. The peer is served over UDP
    /// for those packets instead. NON-ZERO means a claim outlived the peer that
    /// made it - a killed reader whose entry was never released, a recycled pid
    /// rebuilding the same participant GUID, or an entry written by something
    /// that is not the peer at all.
    pub shm_peer_cursor_stale: AtomicU64,
}

impl ShmMetrics {
    /// Create new metrics instance with all counters at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            shm_writes: AtomicU64::new(0),
            shm_reads: AtomicU64::new(0),
            shm_fallback_udp: AtomicU64::new(0),
            shm_overruns: AtomicU64::new(0),
            shm_wake_calls: AtomicU64::new(0),
            shm_wait_calls: AtomicU64::new(0),
            shm_oversize_refused: AtomicU64::new(0),
            shm_writer_segment_failures: AtomicU64::new(0),
            shm_attach_abandoned: AtomicU64::new(0),
            shm_presence_table_full: AtomicU64::new(0),
            shm_peer_cursor_stale: AtomicU64::new(0),
        }
    }

    /// Increment the oversize-refusal counter.
    #[inline]
    pub fn inc_oversize_refused(&self) {
        self.shm_oversize_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the writer-segment-failure counter.
    #[inline]
    pub fn inc_writer_segment_failures(&self) {
        self.shm_writer_segment_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the stale-peer-cursor counter.
    #[inline]
    pub fn inc_peer_cursor_stale(&self) {
        self.shm_peer_cursor_stale.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the full-presence-table counter.
    #[inline]
    pub fn inc_presence_table_full(&self) {
        self.shm_presence_table_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the abandoned-attach counter.
    #[inline]
    pub fn inc_attach_abandoned(&self) {
        self.shm_attach_abandoned.fetch_add(1, Ordering::Relaxed);
    }

    /// Framed packets refused because they exceed one slot.
    #[must_use]
    pub fn oversize_refused(&self) -> u64 {
        self.shm_oversize_refused.load(Ordering::Relaxed)
    }

    /// Writers that gave up on shared memory because their segment could
    /// not be created.
    #[must_use]
    pub fn writer_segment_failures(&self) -> u64 {
        self.shm_writer_segment_failures.load(Ordering::Relaxed)
    }

    /// Remote writer rings abandoned after the attach budget expired.
    #[must_use]
    pub fn attach_abandoned(&self) -> u64 {
        self.shm_attach_abandoned.load(Ordering::Relaxed)
    }

    /// Increment write counter.
    #[inline]
    pub fn inc_writes(&self) {
        self.shm_writes.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment read counter.
    #[inline]
    pub fn inc_reads(&self) {
        self.shm_reads.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment UDP fallback counter.
    #[inline]
    pub fn inc_fallback_udp(&self) {
        self.shm_fallback_udp.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment overrun counter.
    #[inline]
    pub fn inc_overruns(&self) {
        self.shm_overruns.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment wake syscall counter.
    #[inline]
    pub fn inc_wake_calls(&self) {
        self.shm_wake_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment wait syscall counter.
    #[inline]
    pub fn inc_wait_calls(&self) {
        self.shm_wait_calls.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total writes.
    #[inline]
    #[must_use]
    pub fn writes(&self) -> u64 {
        self.shm_writes.load(Ordering::Relaxed)
    }

    /// Get total reads.
    #[inline]
    #[must_use]
    pub fn reads(&self) -> u64 {
        self.shm_reads.load(Ordering::Relaxed)
    }

    /// Get UDP fallback count.
    #[inline]
    #[must_use]
    pub fn fallback_udp(&self) -> u64 {
        self.shm_fallback_udp.load(Ordering::Relaxed)
    }

    /// Get overrun count.
    #[inline]
    #[must_use]
    pub fn overruns(&self) -> u64 {
        self.shm_overruns.load(Ordering::Relaxed)
    }

    /// Get wake syscall count.
    #[inline]
    #[must_use]
    pub fn wake_calls(&self) -> u64 {
        self.shm_wake_calls.load(Ordering::Relaxed)
    }

    /// Get wait syscall count.
    #[inline]
    #[must_use]
    pub fn wait_calls(&self) -> u64 {
        self.shm_wait_calls.load(Ordering::Relaxed)
    }

    /// Reset all counters to zero.
    pub fn reset(&self) {
        self.shm_writes.store(0, Ordering::Relaxed);
        self.shm_reads.store(0, Ordering::Relaxed);
        self.shm_fallback_udp.store(0, Ordering::Relaxed);
        self.shm_overruns.store(0, Ordering::Relaxed);
        self.shm_wake_calls.store(0, Ordering::Relaxed);
        self.shm_wait_calls.store(0, Ordering::Relaxed);
        self.shm_oversize_refused.store(0, Ordering::Relaxed);
        self.shm_writer_segment_failures.store(0, Ordering::Relaxed);
        self.shm_attach_abandoned.store(0, Ordering::Relaxed);
    }

    /// Get a snapshot of all metrics.
    #[must_use]
    pub fn snapshot(&self) -> ShmMetricsSnapshot {
        ShmMetricsSnapshot {
            writes: self.writes(),
            reads: self.reads(),
            fallback_udp: self.fallback_udp(),
            overruns: self.overruns(),
            wake_calls: self.wake_calls(),
            wait_calls: self.wait_calls(),
            oversize_refused: self.oversize_refused(),
            writer_segment_failures: self.writer_segment_failures(),
            attach_abandoned: self.attach_abandoned(),
        }
    }
}

/// Snapshot of SHM metrics (non-atomic, for reporting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmMetricsSnapshot {
    /// Total messages written via SHM
    pub writes: u64,
    /// Total messages read via SHM
    pub reads: u64,
    /// Fallback to UDP count
    pub fallback_udp: u64,
    /// Reader overrun events
    pub overruns: u64,
    /// Futex wake syscalls
    pub wake_calls: u64,
    /// Futex wait syscalls
    pub wait_calls: u64,
    /// Framed packets refused because they exceed one slot
    pub oversize_refused: u64,
    /// Writers that gave up on shared memory (segment creation failed)
    pub writer_segment_failures: u64,
    /// Remote writer rings abandoned after the attach budget expired
    pub attach_abandoned: u64,
}

impl ShmMetricsSnapshot {
    /// Calculate SHM usage ratio (writes via SHM / total writes).
    ///
    /// Returns 0.0 if no writes have occurred.
    #[must_use]
    pub fn shm_usage_ratio(&self) -> f64 {
        let total = self.writes + self.fallback_udp;
        if total == 0 {
            0.0
        } else {
            self.writes as f64 / total as f64
        }
    }

    /// Calculate average wake calls per write.
    ///
    /// Useful for measuring notification efficiency.
    #[must_use]
    pub fn wake_per_write(&self) -> f64 {
        if self.writes == 0 {
            0.0
        } else {
            self.wake_calls as f64 / self.writes as f64
        }
    }
}

impl std::fmt::Display for ShmMetricsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SHM[writes={}, reads={}, fallback={}, overruns={}, wake={}, wait={}]",
            self.writes,
            self.reads,
            self.fallback_udp,
            self.overruns,
            self.wake_calls,
            self.wait_calls
        )
    }
}

/// Global SHM metrics instance.
///
/// Thread-safe singleton for process-wide metrics collection.
static GLOBAL_METRICS: ShmMetrics = ShmMetrics::new();

/// Get reference to global SHM metrics.
#[must_use]
pub fn global_metrics() -> &'static ShmMetrics {
    &GLOBAL_METRICS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_metrics_new() {
        let m = ShmMetrics::new();
        assert_eq!(m.writes(), 0);
        assert_eq!(m.reads(), 0);
        assert_eq!(m.fallback_udp(), 0);
        assert_eq!(m.overruns(), 0);
        assert_eq!(m.wake_calls(), 0);
        assert_eq!(m.wait_calls(), 0);
    }

    #[test]
    fn test_metrics_increment() {
        let m = ShmMetrics::new();

        m.inc_writes();
        m.inc_writes();
        m.inc_reads();
        m.inc_fallback_udp();
        m.inc_overruns();
        m.inc_wake_calls();
        m.inc_wait_calls();

        assert_eq!(m.writes(), 2);
        assert_eq!(m.reads(), 1);
        assert_eq!(m.fallback_udp(), 1);
        assert_eq!(m.overruns(), 1);
        assert_eq!(m.wake_calls(), 1);
        assert_eq!(m.wait_calls(), 1);
    }

    #[test]
    fn test_metrics_reset() {
        let m = ShmMetrics::new();

        m.inc_writes();
        m.inc_reads();
        m.reset();

        assert_eq!(m.writes(), 0);
        assert_eq!(m.reads(), 0);
    }

    #[test]
    fn test_metrics_snapshot() {
        let m = ShmMetrics::new();

        m.inc_writes();
        m.inc_writes();
        m.inc_reads();

        let snap = m.snapshot();
        assert_eq!(snap.writes, 2);
        assert_eq!(snap.reads, 1);
    }

    #[test]
    fn test_snapshot_shm_usage_ratio() {
        let snap = ShmMetricsSnapshot {
            writes: 80,
            reads: 80,
            fallback_udp: 20,
            overruns: 0,
            wake_calls: 80,
            wait_calls: 80,
            oversize_refused: 0,
            writer_segment_failures: 0,
            attach_abandoned: 0,
        };

        let ratio = snap.shm_usage_ratio();
        assert!((ratio - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_snapshot_shm_usage_ratio_zero() {
        let snap = ShmMetricsSnapshot {
            writes: 0,
            reads: 0,
            fallback_udp: 0,
            overruns: 0,
            wake_calls: 0,
            wait_calls: 0,
            oversize_refused: 0,
            writer_segment_failures: 0,
            attach_abandoned: 0,
        };

        assert_eq!(snap.shm_usage_ratio(), 0.0);
    }

    #[test]
    fn test_snapshot_wake_per_write() {
        let snap = ShmMetricsSnapshot {
            writes: 100,
            reads: 100,
            fallback_udp: 0,
            overruns: 0,
            wake_calls: 100,
            wait_calls: 100,
            oversize_refused: 0,
            writer_segment_failures: 0,
            attach_abandoned: 0,
        };

        assert!((snap.wake_per_write() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_snapshot_display() {
        let snap = ShmMetricsSnapshot {
            writes: 100,
            reads: 99,
            fallback_udp: 5,
            overruns: 1,
            wake_calls: 100,
            wait_calls: 99,
            oversize_refused: 0,
            writer_segment_failures: 0,
            attach_abandoned: 0,
        };

        let s = snap.to_string();
        assert!(s.contains("writes=100"));
        assert!(s.contains("reads=99"));
        assert!(s.contains("fallback=5"));
        assert!(s.contains("overruns=1"));
    }

    #[test]
    fn test_metrics_thread_safety() {
        use std::sync::Arc;

        let m = Arc::new(ShmMetrics::new());

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let m_clone = Arc::clone(&m);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        m_clone.inc_writes();
                        m_clone.inc_reads();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(m.writes(), 4000);
        assert_eq!(m.reads(), 4000);
    }

    #[test]
    fn test_global_metrics() {
        let gm = global_metrics();

        // Reset to ensure clean state
        gm.reset();

        gm.inc_writes();
        assert!(gm.writes() >= 1); // May have concurrent tests

        // Get same reference
        let gm2 = global_metrics();
        assert!(std::ptr::eq(gm, gm2));
    }
}

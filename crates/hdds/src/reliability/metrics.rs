// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Metrics for Reliable QoS
//!
//! Tracks gap detection, out-of-order packets, and retransmission stats.
//! Integrates with HDDS telemetry system for web debugger observability.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::telemetry::metrics::{DType, Field, Frame};

// Metric tag constants for Reliable QoS
/// Tag for total gaps detected counter
pub const TAG_GAPS_DETECTED: u16 = 100;
/// Tag for maximum gap size observed
pub const TAG_MAX_GAP_SIZE: u16 = 101;
/// Tag for total out-of-order packets
pub const TAG_OUT_OF_ORDER: u16 = 102;
/// Tag for total retransmissions sent (writer-side)
pub const TAG_RETRANSMIT_SENT: u16 = 103;
/// Tag for total retransmissions received (reader-side)
pub const TAG_RETRANSMIT_RECEIVED: u16 = 104;
/// Tag for total NACKs sent
pub const TAG_NACKS_SENT: u16 = 105;
/// Tag for total heartbeats sent
pub const TAG_HEARTBEATS_SENT: u16 = 106;

/// Reliable QoS metrics collector
///
/// Thread-safe atomic counters for tracking Reliable QoS behavior:
/// - Gap detection (missing sequences)
/// - Out-of-order delivery
/// - Retransmissions (future: T2.7)
/// - NACK protocol (future: T2.5)
/// - Heartbeat protocol (future: T2.6)
///
/// # Thread Safety
///
/// All methods use atomic operations (Relaxed ordering) for lock-free updates.
///
/// # Performance
///
/// - Increment: < 5 ns (single atomic fetch_add)
/// - Update max: < 10 ns (atomic compare-exchange loop)
/// - Snapshot: < 500 ns (load all counters)
///
/// # Example
///
/// ```ignore
/// let metrics = ReliableMetrics::new();
///
/// // Reader detects gap [3..5) -> 2 missing sequences
/// metrics.record_gap(2);
///
/// // Reader receives out-of-order packet
/// metrics.increment_out_of_order(1);
///
/// // Export for web debugger
/// let frame = metrics.snapshot(1234567890);
/// ```
#[derive(Debug)]
pub struct ReliableMetrics {
    /// Total gaps detected (cumulative)
    ///
    /// Incremented when GapTracker detects missing sequences.
    gaps_detected: AtomicU64,

    /// Maximum gap size observed (high-water mark)
    ///
    /// Updated when gap size exceeds previous maximum.
    max_gap_size: AtomicU64,

    /// Total out-of-order packets received (cumulative)
    ///
    /// Incremented when packet arrives with seq < last_seen.
    total_out_of_order: AtomicU64,

    /// Total retransmissions sent (writer-side, future)
    retransmit_sent: AtomicU64,

    /// Total retransmissions received (reader-side, future)
    retransmit_received: AtomicU64,

    /// Total NACKs sent (reader-side, future)
    nacks_sent: AtomicU64,

    /// Total heartbeats sent (writer-side, future)
    heartbeats_sent: AtomicU64,
}

impl ReliableMetrics {
    /// Create new Reliable QoS metrics collector
    pub fn new() -> Self {
        Self {
            gaps_detected: AtomicU64::new(0),
            max_gap_size: AtomicU64::new(0),
            total_out_of_order: AtomicU64::new(0),
            retransmit_sent: AtomicU64::new(0),
            retransmit_received: AtomicU64::new(0),
            nacks_sent: AtomicU64::new(0),
            heartbeats_sent: AtomicU64::new(0),
        }
    }

    /// Record gap detection (increment gaps_detected, update max_gap_size)
    ///
    /// # Arguments
    ///
    /// - `gap_size`: Number of missing sequences in detected gap
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Gap [5..8) -> 3 missing sequences
    /// metrics.record_gap(3);
    /// assert_eq!(metrics.gaps_detected(), 1);
    /// assert_eq!(metrics.max_gap_size(), 3);
    /// ```
    pub fn record_gap(&self, gap_size: u64) {
        self.gaps_detected.fetch_add(1, Ordering::Relaxed);
        self.update_max_gap_size(gap_size);
    }

    /// Update maximum gap size (high-water mark)
    ///
    /// Uses compare-exchange loop to ensure we only update if new size is larger.
    fn update_max_gap_size(&self, new_size: u64) {
        let mut current = self.max_gap_size.load(Ordering::Relaxed);
        while new_size > current {
            match self.max_gap_size.compare_exchange_weak(
                current,
                new_size,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Increment out-of-order packet counter
    ///
    /// Called when packet arrives with seq <= last_seen (but not duplicate).
    pub fn increment_out_of_order(&self, count: u64) {
        self.total_out_of_order.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment retransmissions sent (writer-side, T2.7)
    pub fn increment_retransmit_sent(&self, count: u64) {
        self.retransmit_sent.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment retransmissions received (reader-side, T2.7)
    pub fn increment_retransmit_received(&self, count: u64) {
        self.retransmit_received.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment NACKs sent (T2.5)
    pub fn increment_nacks_sent(&self, count: u64) {
        self.nacks_sent.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment heartbeats sent (T2.6)
    pub fn increment_heartbeats_sent(&self, count: u64) {
        self.heartbeats_sent.fetch_add(count, Ordering::Relaxed);
    }

    /// Get gaps detected count (snapshot)
    pub fn gaps_detected(&self) -> u64 {
        self.gaps_detected.load(Ordering::Relaxed)
    }

    /// Get maximum gap size (snapshot)
    pub fn max_gap_size(&self) -> u64 {
        self.max_gap_size.load(Ordering::Relaxed)
    }

    /// Get out-of-order packet count (snapshot)
    pub fn out_of_order(&self) -> u64 {
        self.total_out_of_order.load(Ordering::Relaxed)
    }

    /// Get retransmissions sent count (snapshot)
    pub fn retransmit_sent(&self) -> u64 {
        self.retransmit_sent.load(Ordering::Relaxed)
    }

    /// Get retransmissions received count (snapshot)
    pub fn retransmit_received(&self) -> u64 {
        self.retransmit_received.load(Ordering::Relaxed)
    }

    /// Snapshot current metrics into a Frame
    ///
    /// # Arguments
    ///
    /// - `ts_ns`: Timestamp (nanoseconds since epoch)
    ///
    /// # Returns
    ///
    /// Frame with all Reliable QoS metric fields.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let frame = metrics.snapshot(current_time_ns());
    /// for field in &frame.fields {
    ///     println!("Tag {}: {}", field.tag, field.value_u64);
    /// }
    /// ```
    pub fn snapshot(&self, ts_ns: u64) -> Frame {
        let mut frame = Frame::new(ts_ns);

        frame.push_field(Field {
            tag: TAG_GAPS_DETECTED,
            dtype: DType::U64,
            value_u64: self.gaps_detected.load(Ordering::Relaxed),
        });

        frame.push_field(Field {
            tag: TAG_MAX_GAP_SIZE,
            dtype: DType::U64,
            value_u64: self.max_gap_size.load(Ordering::Relaxed),
        });

        frame.push_field(Field {
            tag: TAG_OUT_OF_ORDER,
            dtype: DType::U64,
            value_u64: self.total_out_of_order.load(Ordering::Relaxed),
        });

        frame.push_field(Field {
            tag: TAG_RETRANSMIT_SENT,
            dtype: DType::U64,
            value_u64: self.retransmit_sent.load(Ordering::Relaxed),
        });

        frame.push_field(Field {
            tag: TAG_RETRANSMIT_RECEIVED,
            dtype: DType::U64,
            value_u64: self.retransmit_received.load(Ordering::Relaxed),
        });

        frame.push_field(Field {
            tag: TAG_NACKS_SENT,
            dtype: DType::U64,
            value_u64: self.nacks_sent.load(Ordering::Relaxed),
        });

        frame.push_field(Field {
            tag: TAG_HEARTBEATS_SENT,
            dtype: DType::U64,
            value_u64: self.heartbeats_sent.load(Ordering::Relaxed),
        });

        frame
    }
}

impl Default for ReliableMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_metrics_new() {
        let m = ReliableMetrics::new();
        assert_eq!(m.gaps_detected(), 0);
        assert_eq!(m.max_gap_size(), 0);
        assert_eq!(m.out_of_order(), 0);
    }

    #[test]
    fn test_record_gap_single() {
        let m = ReliableMetrics::new();
        m.record_gap(5);

        assert_eq!(m.gaps_detected(), 1);
        assert_eq!(m.max_gap_size(), 5);
    }

    #[test]
    fn test_record_gap_multiple() {
        let m = ReliableMetrics::new();
        m.record_gap(3);
        m.record_gap(7);
        m.record_gap(2);

        assert_eq!(m.gaps_detected(), 3);
        assert_eq!(m.max_gap_size(), 7); // Max = 7
    }

    #[test]
    fn test_max_gap_size_updates() {
        let m = ReliableMetrics::new();
        m.record_gap(10);
        assert_eq!(m.max_gap_size(), 10);

        m.record_gap(5); // Smaller, should not update max
        assert_eq!(m.max_gap_size(), 10);

        m.record_gap(20); // Larger, should update max
        assert_eq!(m.max_gap_size(), 20);
    }

    #[test]
    fn test_increment_out_of_order() {
        let m = ReliableMetrics::new();
        m.increment_out_of_order(3);
        m.increment_out_of_order(5);

        assert_eq!(m.out_of_order(), 8);
    }

    #[test]
    fn test_snapshot_fields() {
        let m = ReliableMetrics::new();
        m.record_gap(5);
        m.increment_out_of_order(2);

        let frame = m.snapshot(1234567890);

        // Verify gaps_detected field
        let gaps = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_GAPS_DETECTED)
            .map(|f| f.value_u64)
            .expect("gaps_detected field should be present in snapshot");
        assert_eq!(gaps, 1);

        // Verify max_gap_size field
        let max_gap = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_MAX_GAP_SIZE)
            .map(|f| f.value_u64)
            .expect("max_gap_size field should be present in snapshot");
        assert_eq!(max_gap, 5);

        // Verify out_of_order field
        let ooo = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_OUT_OF_ORDER)
            .map(|f| f.value_u64)
            .expect("out_of_order field should be present in snapshot");
        assert_eq!(ooo, 2);
    }

    #[test]
    fn test_snapshot_timestamp() {
        let m = ReliableMetrics::new();
        let ts = 9876543210;
        let frame = m.snapshot(ts);

        assert_eq!(frame.ts_ns, ts);
    }

    #[test]
    fn test_concurrent_gap_recording() {
        let m = Arc::new(ReliableMetrics::new());
        let mut handles = vec![];

        // Spawn 10 threads, each recording 100 gaps
        for thread_id in 0..10 {
            let m_clone = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for i in 0..100 {
                    let gap_size = (thread_id * 100 + i) as u64;
                    m_clone.record_gap(gap_size);
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread should complete successfully");
        }

        // Should have 1000 gaps detected
        assert_eq!(m.gaps_detected(), 1000);

        // Max gap size should be 999 (thread 9, iteration 99)
        assert_eq!(m.max_gap_size(), 999);
    }

    #[test]
    fn test_concurrent_out_of_order() {
        let m = Arc::new(ReliableMetrics::new());
        let mut handles = vec![];

        // Spawn 4 threads, each incrementing by 250
        for _ in 0..4 {
            let m_clone = Arc::clone(&m);
            handles.push(thread::spawn(move || {
                for _ in 0..250 {
                    m_clone.increment_out_of_order(1);
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread should complete successfully");
        }

        // Total should be 1000
        assert_eq!(m.out_of_order(), 1000);
    }

    #[test]
    fn test_retransmit_counters() {
        let m = ReliableMetrics::new();
        m.increment_retransmit_sent(5);
        m.increment_retransmit_received(3);

        let frame = m.snapshot(0);

        let sent = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_RETRANSMIT_SENT)
            .map(|f| f.value_u64)
            .expect("retransmit_sent field should be present in snapshot");
        assert_eq!(sent, 5);

        let received = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_RETRANSMIT_RECEIVED)
            .map(|f| f.value_u64)
            .expect("retransmit_received field should be present in snapshot");
        assert_eq!(received, 3);
    }

    #[test]
    fn test_nack_heartbeat_counters() {
        let m = ReliableMetrics::new();
        m.increment_nacks_sent(7);
        m.increment_heartbeats_sent(12);

        let frame = m.snapshot(0);

        let nacks = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_NACKS_SENT)
            .map(|f| f.value_u64)
            .expect("nacks_sent field should be present in snapshot");
        assert_eq!(nacks, 7);

        let hb = frame
            .fields
            .iter()
            .find(|f| f.tag == TAG_HEARTBEATS_SENT)
            .map(|f| f.value_u64)
            .expect("heartbeats_sent field should be present in snapshot");
        assert_eq!(hb, 12);
    }

    #[test]
    fn test_default_impl() {
        let m = ReliableMetrics::default();
        assert_eq!(m.gaps_detected(), 0);
        assert_eq!(m.max_gap_size(), 0);
        assert_eq!(m.out_of_order(), 0);
    }
}

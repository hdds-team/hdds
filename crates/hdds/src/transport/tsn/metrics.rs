// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN metrics and counters.

use std::sync::atomic::{AtomicU64, Ordering};

/// TSN metrics counters.
#[derive(Debug, Default)]
pub struct TsnMetrics {
    /// Number of times SO_PRIORITY was set.
    pub priority_set: AtomicU64,

    /// Number of times SO_TXTIME was enabled.
    pub txtime_enabled: AtomicU64,

    /// Number of sends with txtime.
    pub txtime_sends: AtomicU64,

    /// Number of sends without txtime (fallback).
    pub regular_sends: AtomicU64,

    /// Number of packets dropped late (ETF deadline missed).
    pub dropped_late: AtomicU64,

    /// Number of packets dropped for other reasons.
    pub dropped_other: AtomicU64,

    /// Number of txtime enable failures (Opportunistic mode).
    pub txtime_fallbacks: AtomicU64,

    /// Number of txtime enable failures (Mandatory mode).
    pub txtime_failures: AtomicU64,

    /// Number of capability probes.
    pub probes: AtomicU64,

    /// Number of error queue drains.
    pub error_queue_drains: AtomicU64,
}

impl TsnMetrics {
    /// Create new metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record SO_PRIORITY set.
    pub fn record_priority_set(&self) {
        self.priority_set.fetch_add(1, Ordering::Relaxed);
    }

    /// Record SO_TXTIME enabled.
    pub fn record_txtime_enabled(&self) {
        self.txtime_enabled.fetch_add(1, Ordering::Relaxed);
    }

    /// Record send with txtime.
    pub fn record_txtime_send(&self) {
        self.txtime_sends.fetch_add(1, Ordering::Relaxed);
    }

    /// Record regular send (no txtime).
    pub fn record_regular_send(&self) {
        self.regular_sends.fetch_add(1, Ordering::Relaxed);
    }

    /// Record late packet drop.
    pub fn record_dropped_late(&self, count: u64) {
        self.dropped_late.fetch_add(count, Ordering::Relaxed);
    }

    /// Record other packet drop.
    pub fn record_dropped_other(&self, count: u64) {
        self.dropped_other.fetch_add(count, Ordering::Relaxed);
    }

    /// Record txtime fallback (Opportunistic mode).
    pub fn record_txtime_fallback(&self) {
        self.txtime_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    /// Record txtime failure (Mandatory mode).
    pub fn record_txtime_failure(&self) {
        self.txtime_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record capability probe.
    pub fn record_probe(&self) {
        self.probes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record error queue drain.
    pub fn record_error_queue_drain(&self) {
        self.error_queue_drains.fetch_add(1, Ordering::Relaxed);
    }

    /// Get snapshot of all metrics.
    pub fn snapshot(&self) -> TsnMetricsSnapshot {
        TsnMetricsSnapshot {
            priority_set: self.priority_set.load(Ordering::Relaxed),
            txtime_enabled: self.txtime_enabled.load(Ordering::Relaxed),
            txtime_sends: self.txtime_sends.load(Ordering::Relaxed),
            regular_sends: self.regular_sends.load(Ordering::Relaxed),
            dropped_late: self.dropped_late.load(Ordering::Relaxed),
            dropped_other: self.dropped_other.load(Ordering::Relaxed),
            txtime_fallbacks: self.txtime_fallbacks.load(Ordering::Relaxed),
            txtime_failures: self.txtime_failures.load(Ordering::Relaxed),
            probes: self.probes.load(Ordering::Relaxed),
            error_queue_drains: self.error_queue_drains.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.priority_set.store(0, Ordering::Relaxed);
        self.txtime_enabled.store(0, Ordering::Relaxed);
        self.txtime_sends.store(0, Ordering::Relaxed);
        self.regular_sends.store(0, Ordering::Relaxed);
        self.dropped_late.store(0, Ordering::Relaxed);
        self.dropped_other.store(0, Ordering::Relaxed);
        self.txtime_fallbacks.store(0, Ordering::Relaxed);
        self.txtime_failures.store(0, Ordering::Relaxed);
        self.probes.store(0, Ordering::Relaxed);
        self.error_queue_drains.store(0, Ordering::Relaxed);
    }
}

/// Immutable snapshot of TSN metrics.
#[derive(Clone, Debug, Default)]
pub struct TsnMetricsSnapshot {
    pub priority_set: u64,
    pub txtime_enabled: u64,
    pub txtime_sends: u64,
    pub regular_sends: u64,
    pub dropped_late: u64,
    pub dropped_other: u64,
    pub txtime_fallbacks: u64,
    pub txtime_failures: u64,
    pub probes: u64,
    pub error_queue_drains: u64,
}

impl TsnMetricsSnapshot {
    /// Total sends (txtime + regular).
    pub fn total_sends(&self) -> u64 {
        self.txtime_sends + self.regular_sends
    }

    /// Total drops.
    pub fn total_drops(&self) -> u64 {
        self.dropped_late + self.dropped_other
    }

    /// Txtime usage ratio (0.0 - 1.0).
    pub fn txtime_ratio(&self) -> f64 {
        let total = self.total_sends();
        if total == 0 {
            0.0
        } else {
            self.txtime_sends as f64 / total as f64
        }
    }

    /// Drop rate (0.0 - 1.0).
    pub fn drop_rate(&self) -> f64 {
        let total = self.total_sends();
        if total == 0 {
            0.0
        } else {
            self.total_drops() as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_default() {
        let metrics = TsnMetrics::new();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.priority_set, 0);
        assert_eq!(snapshot.txtime_sends, 0);
        assert_eq!(snapshot.total_sends(), 0);
    }

    #[test]
    fn test_metrics_record() {
        let metrics = TsnMetrics::new();

        metrics.record_priority_set();
        metrics.record_txtime_enabled();
        metrics.record_txtime_send();
        metrics.record_txtime_send();
        metrics.record_regular_send();
        metrics.record_dropped_late(3);
        metrics.record_dropped_other(1);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.priority_set, 1);
        assert_eq!(snapshot.txtime_enabled, 1);
        assert_eq!(snapshot.txtime_sends, 2);
        assert_eq!(snapshot.regular_sends, 1);
        assert_eq!(snapshot.dropped_late, 3);
        assert_eq!(snapshot.dropped_other, 1);
        assert_eq!(snapshot.total_sends(), 3);
        assert_eq!(snapshot.total_drops(), 4);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = TsnMetrics::new();

        metrics.record_priority_set();
        metrics.record_txtime_send();

        let snapshot1 = metrics.snapshot();
        assert_eq!(snapshot1.priority_set, 1);

        metrics.reset();

        let snapshot2 = metrics.snapshot();
        assert_eq!(snapshot2.priority_set, 0);
        assert_eq!(snapshot2.txtime_sends, 0);
    }

    #[test]
    fn test_metrics_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let metrics = Arc::new(TsnMetrics::new());
        let mut handles = vec![];

        for _ in 0..4 {
            let m = Arc::clone(&metrics);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    m.record_txtime_send();
                    m.record_regular_send();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread should complete");
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.txtime_sends, 4000);
        assert_eq!(snapshot.regular_sends, 4000);
    }

    #[test]
    fn test_snapshot_ratios() {
        let snapshot = TsnMetricsSnapshot {
            txtime_sends: 80,
            regular_sends: 20,
            dropped_late: 5,
            dropped_other: 5,
            ..Default::default()
        };

        assert_eq!(snapshot.total_sends(), 100);
        assert_eq!(snapshot.total_drops(), 10);
        assert!((snapshot.txtime_ratio() - 0.8).abs() < 0.001);
        assert!((snapshot.drop_rate() - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_snapshot_zero_sends() {
        let snapshot = TsnMetricsSnapshot::default();
        assert_eq!(snapshot.txtime_ratio(), 0.0);
        assert_eq!(snapshot.drop_rate(), 0.0);
    }

    #[test]
    fn test_metrics_fallbacks_failures() {
        let metrics = TsnMetrics::new();

        metrics.record_txtime_fallback();
        metrics.record_txtime_fallback();
        metrics.record_txtime_failure();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.txtime_fallbacks, 2);
        assert_eq!(snapshot.txtime_failures, 1);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PROBE Metrics - Telemetry for dialect detection
//!
//! Tracks detection performance and hot-reconfiguration overlap.

use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// PROBE phase metrics (atomic for lock-free access)
pub struct ProbeMetrics {
    /// Total samples processed during PROBE
    pub samples_seen: AtomicU32,

    /// Score for RTI dialect (0-100)
    pub score_rti: AtomicU16,

    /// Score for FastDDS dialect (0-100)
    pub score_fast: AtomicU16,

    /// Score for Cyclone dialect (0-100)
    pub score_cyclone: AtomicU16,

    /// Final decision (Dialect enum as u8)
    pub decision: AtomicU8,

    /// Confidence in decision (0-100)
    pub confidence: AtomicU8,

    /// Time to first decision (microseconds)
    pub ttfd_us: AtomicU64,

    /// Time since last dialect switch (milliseconds)
    pub last_switch_ms_ago: AtomicU32,

    // Hot-reconfiguration overlap window metrics
    /// Packets received from old sockets during overlap
    pub overlap_rx_old: AtomicU32,

    /// Packets received from new sockets during overlap
    pub overlap_rx_new: AtomicU32,

    /// Estimated packet loss during overlap
    pub overlap_loss: AtomicU32,
}

impl ProbeMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        crate::trace_fn!("ProbeMetrics::new");
        Self {
            samples_seen: AtomicU32::new(0),
            score_rti: AtomicU16::new(0),
            score_fast: AtomicU16::new(0),
            score_cyclone: AtomicU16::new(0),
            decision: AtomicU8::new(0),
            confidence: AtomicU8::new(0),
            ttfd_us: AtomicU64::new(0),
            last_switch_ms_ago: AtomicU32::new(0),
            overlap_rx_old: AtomicU32::new(0),
            overlap_rx_new: AtomicU32::new(0),
            overlap_loss: AtomicU32::new(0),
        }
    }

    /// Reset metrics for new PROBE phase
    pub fn reset(&self) {
        crate::trace_fn!("ProbeMetrics::reset");
        self.samples_seen.store(0, Ordering::Relaxed);
        self.score_rti.store(0, Ordering::Relaxed);
        self.score_fast.store(0, Ordering::Relaxed);
        self.score_cyclone.store(0, Ordering::Relaxed);
        self.decision.store(0, Ordering::Relaxed);
        self.confidence.store(0, Ordering::Relaxed);
        self.ttfd_us.store(0, Ordering::Relaxed);
    }

    /// Get snapshot of all metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        crate::trace_fn!("ProbeMetrics::snapshot");
        MetricsSnapshot {
            samples_seen: self.samples_seen.load(Ordering::Relaxed),
            score_rti: self.score_rti.load(Ordering::Relaxed),
            score_fast: self.score_fast.load(Ordering::Relaxed),
            score_cyclone: self.score_cyclone.load(Ordering::Relaxed),
            decision: self.decision.load(Ordering::Relaxed),
            confidence: self.confidence.load(Ordering::Relaxed),
            ttfd_us: self.ttfd_us.load(Ordering::Relaxed),
            last_switch_ms_ago: self.last_switch_ms_ago.load(Ordering::Relaxed),
            overlap_rx_old: self.overlap_rx_old.load(Ordering::Relaxed),
            overlap_rx_new: self.overlap_rx_new.load(Ordering::Relaxed),
            overlap_loss: self.overlap_loss.load(Ordering::Relaxed),
        }
    }
}

impl Default for ProbeMetrics {
    fn default() -> Self {
        crate::trace_fn!("ProbeMetrics::default");
        Self::new()
    }
}

/// Immutable metrics snapshot
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub samples_seen: u32,
    pub score_rti: u16,
    pub score_fast: u16,
    pub score_cyclone: u16,
    pub decision: u8,
    pub confidence: u8,
    pub ttfd_us: u64,
    pub last_switch_ms_ago: u32,
    pub overlap_rx_old: u32,
    pub overlap_rx_new: u32,
    pub overlap_loss: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = ProbeMetrics::new();
        assert_eq!(metrics.samples_seen.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.confidence.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = ProbeMetrics::new();
        metrics.samples_seen.store(10, Ordering::Relaxed);
        metrics.confidence.store(90, Ordering::Relaxed);

        metrics.reset();

        assert_eq!(metrics.samples_seen.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.confidence.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_metrics_snapshot() {
        let metrics = ProbeMetrics::new();
        metrics.samples_seen.store(5, Ordering::Relaxed);
        metrics.confidence.store(80, Ordering::Relaxed);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.samples_seen, 5);
        assert_eq!(snapshot.confidence, 80);
    }
}

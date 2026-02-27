// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Control channel metrics for monitoring RTPS protocol messages.

use std::sync::atomic::{AtomicU64, Ordering};

/// Control channel metrics
#[derive(Debug)]
pub struct ControlMetrics {
    /// Total control messages received
    pub messages_received: AtomicU64,
    /// Messages dropped (channel full)
    pub messages_dropped: AtomicU64,
    /// ACKNACKs sent
    pub acknacks_sent: AtomicU64,
    /// Batched HEARTBEATs processed
    pub heartbeats_batched: AtomicU64,
    /// Final HEARTBEATs (immediate response)
    pub heartbeats_final: AtomicU64,
}

impl ControlMetrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        Self {
            messages_received: AtomicU64::new(0),
            messages_dropped: AtomicU64::new(0),
            acknacks_sent: AtomicU64::new(0),
            heartbeats_batched: AtomicU64::new(0),
            heartbeats_final: AtomicU64::new(0),
        }
    }

    /// Get snapshot of metrics
    pub fn snapshot(&self) -> ControlMetricsSnapshot {
        ControlMetricsSnapshot {
            messages_received: self.messages_received.load(Ordering::Relaxed),
            messages_dropped: self.messages_dropped.load(Ordering::Relaxed),
            acknacks_sent: self.acknacks_sent.load(Ordering::Relaxed),
            heartbeats_batched: self.heartbeats_batched.load(Ordering::Relaxed),
            heartbeats_final: self.heartbeats_final.load(Ordering::Relaxed),
        }
    }
}

impl Default for ControlMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics snapshot (for logging/monitoring)
#[derive(Debug, Clone)]
pub struct ControlMetricsSnapshot {
    pub messages_received: u64,
    pub messages_dropped: u64,
    pub acknacks_sent: u64,
    pub heartbeats_batched: u64,
    pub heartbeats_final: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_snapshot() {
        let metrics = ControlMetrics::new();
        metrics.messages_received.fetch_add(10, Ordering::Relaxed);
        metrics.acknacks_sent.fetch_add(5, Ordering::Relaxed);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.messages_received, 10);
        assert_eq!(snapshot.acknacks_sent, 5);
        assert_eq!(snapshot.messages_dropped, 0);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Congestion control metrics.
//!
//!
//! Provides observable metrics for congestion control and an observer
//! trait for integration with external monitoring systems.

use super::config::Priority;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Congestion state for metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CongestionState {
    /// Normal operation, rate can increase.
    #[default]
    Stable,
    /// Congestion detected, rate is being reduced.
    Congested,
}

/// Global congestion metrics for a participant.
#[derive(Debug)]
pub struct CongestionMetrics {
    // === Rate Control ===
    /// Current rate in bytes per second.
    current_rate_bps: AtomicU64,

    /// Congestion score (0-100, stored as integer).
    congestion_score: AtomicU64,

    /// Number of decrease events.
    decrease_count: AtomicU64,

    /// Number of increase events.
    increase_count: AtomicU64,

    // === Signals ===
    /// Total EAGAIN/ENOBUFS events.
    eagain_total: AtomicU64,

    /// Total NACK events received.
    nack_total: AtomicU64,

    // === Per-Priority ===
    /// Samples enqueued to P0.
    enqueued_p0: AtomicU64,

    /// Samples enqueued to P1.
    enqueued_p1: AtomicU64,

    /// Samples enqueued to P2.
    enqueued_p2: AtomicU64,

    /// Samples sent from P0.
    sent_p0: AtomicU64,

    /// Samples sent from P1.
    sent_p1: AtomicU64,

    /// Samples sent from P2.
    sent_p2: AtomicU64,

    /// Samples dropped from P1.
    dropped_p1: AtomicU64,

    /// Samples coalesced in P2.
    coalesced_p2: AtomicU64,

    /// Samples dropped from P2.
    dropped_p2: AtomicU64,

    // === ECN (Phase 6) ===
    /// ECN CE (Congestion Experienced) marks received.
    ecn_ce_received: AtomicU64,

    // === Reliable ===
    /// Repair requests received.
    repair_requests: AtomicU64,

    /// Repair packets sent.
    repair_sent: AtomicU64,

    /// Times repair budget was exhausted.
    repair_budget_exhausted: AtomicU64,

    /// Retries exceeded max.
    retries_exceeded: AtomicU64,

    // === General ===
    /// Total bytes sent.
    bytes_sent: AtomicU64,

    /// Total rate limit hits.
    rate_limited: AtomicU64,

    /// P0 force sends (bypassed rate limit).
    force_sends_p0: AtomicU64,

    /// Creation time for uptime calculation.
    created_at: Instant,
}

impl Default for CongestionMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionMetrics {
    /// Create new metrics.
    pub fn new() -> Self {
        Self {
            current_rate_bps: AtomicU64::new(0),
            congestion_score: AtomicU64::new(0),
            decrease_count: AtomicU64::new(0),
            increase_count: AtomicU64::new(0),
            eagain_total: AtomicU64::new(0),
            nack_total: AtomicU64::new(0),
            enqueued_p0: AtomicU64::new(0),
            enqueued_p1: AtomicU64::new(0),
            enqueued_p2: AtomicU64::new(0),
            sent_p0: AtomicU64::new(0),
            sent_p1: AtomicU64::new(0),
            sent_p2: AtomicU64::new(0),
            dropped_p1: AtomicU64::new(0),
            coalesced_p2: AtomicU64::new(0),
            dropped_p2: AtomicU64::new(0),
            ecn_ce_received: AtomicU64::new(0),
            repair_requests: AtomicU64::new(0),
            repair_sent: AtomicU64::new(0),
            repair_budget_exhausted: AtomicU64::new(0),
            retries_exceeded: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            force_sends_p0: AtomicU64::new(0),
            created_at: Instant::now(),
        }
    }

    // === Recording methods ===

    /// Record a rate change.
    pub fn record_rate(&self, rate_bps: u32) {
        self.current_rate_bps
            .store(rate_bps as u64, Ordering::Relaxed);
    }

    /// Record a congestion score update.
    pub fn record_score(&self, score: f32) {
        self.congestion_score
            .store((score * 100.0) as u64, Ordering::Relaxed);
    }

    /// Record a decrease event.
    pub fn record_decrease(&self) {
        self.decrease_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an increase event.
    pub fn record_increase(&self) {
        self.increase_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an EAGAIN event.
    pub fn record_eagain(&self) {
        self.eagain_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a NACK event.
    pub fn record_nack(&self) {
        self.nack_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a sample enqueue.
    pub fn record_enqueue(&self, priority: Priority) {
        match priority {
            Priority::P0 => self.enqueued_p0.fetch_add(1, Ordering::Relaxed),
            Priority::P1 => self.enqueued_p1.fetch_add(1, Ordering::Relaxed),
            Priority::P2 => self.enqueued_p2.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Record a sample send.
    pub fn record_send(&self, priority: Priority, bytes: u64) {
        match priority {
            Priority::P0 => self.sent_p0.fetch_add(1, Ordering::Relaxed),
            Priority::P1 => self.sent_p1.fetch_add(1, Ordering::Relaxed),
            Priority::P2 => self.sent_p2.fetch_add(1, Ordering::Relaxed),
        };
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record a P1 drop.
    pub fn record_drop_p1(&self) {
        self.dropped_p1.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a P2 coalesce.
    pub fn record_coalesce_p2(&self) {
        self.coalesced_p2.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a P2 drop.
    pub fn record_drop_p2(&self) {
        self.dropped_p2.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an ECN CE (Congestion Experienced) mark.
    pub fn record_ecn_ce(&self) {
        self.ecn_ce_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a repair request.
    pub fn record_repair_request(&self) {
        self.repair_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a repair send.
    pub fn record_repair_sent(&self) {
        self.repair_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record repair budget exhaustion.
    pub fn record_repair_budget_exhausted(&self) {
        self.repair_budget_exhausted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record retry limit exceeded.
    pub fn record_retry_exceeded(&self) {
        self.retries_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rate limit hit.
    pub fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a P0 force send.
    pub fn record_force_send_p0(&self) {
        self.force_sends_p0.fetch_add(1, Ordering::Relaxed);
    }

    // === Snapshot ===

    /// Get a snapshot of current metrics.
    pub fn snapshot(&self) -> CongestionMetricsSnapshot {
        CongestionMetricsSnapshot {
            current_rate_bps: self.current_rate_bps.load(Ordering::Relaxed) as u32,
            congestion_score: self.congestion_score.load(Ordering::Relaxed) as f32 / 100.0,
            state: if self.congestion_score.load(Ordering::Relaxed) >= 60 {
                CongestionState::Congested
            } else {
                CongestionState::Stable
            },
            decrease_count: self.decrease_count.load(Ordering::Relaxed),
            increase_count: self.increase_count.load(Ordering::Relaxed),
            eagain_total: self.eagain_total.load(Ordering::Relaxed),
            nack_total: self.nack_total.load(Ordering::Relaxed),
            enqueued_p0: self.enqueued_p0.load(Ordering::Relaxed),
            enqueued_p1: self.enqueued_p1.load(Ordering::Relaxed),
            enqueued_p2: self.enqueued_p2.load(Ordering::Relaxed),
            sent_p0: self.sent_p0.load(Ordering::Relaxed),
            sent_p1: self.sent_p1.load(Ordering::Relaxed),
            sent_p2: self.sent_p2.load(Ordering::Relaxed),
            dropped_p1: self.dropped_p1.load(Ordering::Relaxed),
            coalesced_p2: self.coalesced_p2.load(Ordering::Relaxed),
            dropped_p2: self.dropped_p2.load(Ordering::Relaxed),
            ecn_ce_received: self.ecn_ce_received.load(Ordering::Relaxed),
            repair_requests: self.repair_requests.load(Ordering::Relaxed),
            repair_sent: self.repair_sent.load(Ordering::Relaxed),
            repair_budget_exhausted: self.repair_budget_exhausted.load(Ordering::Relaxed),
            retries_exceeded: self.retries_exceeded.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            force_sends_p0: self.force_sends_p0.load(Ordering::Relaxed),
            uptime_secs: self.created_at.elapsed().as_secs_f64(),
        }
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.decrease_count.store(0, Ordering::Relaxed);
        self.increase_count.store(0, Ordering::Relaxed);
        self.eagain_total.store(0, Ordering::Relaxed);
        self.nack_total.store(0, Ordering::Relaxed);
        self.enqueued_p0.store(0, Ordering::Relaxed);
        self.enqueued_p1.store(0, Ordering::Relaxed);
        self.enqueued_p2.store(0, Ordering::Relaxed);
        self.sent_p0.store(0, Ordering::Relaxed);
        self.sent_p1.store(0, Ordering::Relaxed);
        self.sent_p2.store(0, Ordering::Relaxed);
        self.dropped_p1.store(0, Ordering::Relaxed);
        self.coalesced_p2.store(0, Ordering::Relaxed);
        self.dropped_p2.store(0, Ordering::Relaxed);
        self.ecn_ce_received.store(0, Ordering::Relaxed);
        self.repair_requests.store(0, Ordering::Relaxed);
        self.repair_sent.store(0, Ordering::Relaxed);
        self.repair_budget_exhausted.store(0, Ordering::Relaxed);
        self.retries_exceeded.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.rate_limited.store(0, Ordering::Relaxed);
        self.force_sends_p0.store(0, Ordering::Relaxed);
    }
}

/// Snapshot of congestion metrics.
#[derive(Clone, Debug, Default)]
pub struct CongestionMetricsSnapshot {
    // === Rate Control ===
    /// Current rate in bytes per second.
    pub current_rate_bps: u32,
    /// Congestion score (0.0 - 1.0).
    pub congestion_score: f32,
    /// Current congestion state.
    pub state: CongestionState,
    /// Number of decrease events.
    pub decrease_count: u64,
    /// Number of increase events.
    pub increase_count: u64,

    // === Signals ===
    /// Total EAGAIN/ENOBUFS events.
    pub eagain_total: u64,
    /// Total NACK events.
    pub nack_total: u64,

    // === Per-Priority ===
    /// Samples enqueued to P0.
    pub enqueued_p0: u64,
    /// Samples enqueued to P1.
    pub enqueued_p1: u64,
    /// Samples enqueued to P2.
    pub enqueued_p2: u64,
    /// Samples sent from P0.
    pub sent_p0: u64,
    /// Samples sent from P1.
    pub sent_p1: u64,
    /// Samples sent from P2.
    pub sent_p2: u64,
    /// Samples dropped from P1.
    pub dropped_p1: u64,
    /// Samples coalesced in P2.
    pub coalesced_p2: u64,
    /// Samples dropped from P2.
    pub dropped_p2: u64,

    // === ECN (Phase 6) ===
    /// ECN CE (Congestion Experienced) marks received.
    pub ecn_ce_received: u64,

    // === Reliable ===
    /// Repair requests received.
    pub repair_requests: u64,
    /// Repair packets sent.
    pub repair_sent: u64,
    /// Times repair budget was exhausted.
    pub repair_budget_exhausted: u64,
    /// Retries exceeded max.
    pub retries_exceeded: u64,

    // === General ===
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total rate limit hits.
    pub rate_limited: u64,
    /// P0 force sends.
    pub force_sends_p0: u64,
    /// Uptime in seconds.
    pub uptime_secs: f64,
}

impl CongestionMetricsSnapshot {
    /// Get total samples enqueued.
    pub fn total_enqueued(&self) -> u64 {
        self.enqueued_p0 + self.enqueued_p1 + self.enqueued_p2
    }

    /// Get total samples sent.
    pub fn total_sent(&self) -> u64 {
        self.sent_p0 + self.sent_p1 + self.sent_p2
    }

    /// Get total samples dropped.
    pub fn total_dropped(&self) -> u64 {
        self.dropped_p1 + self.dropped_p2
    }

    /// Get throughput in bytes per second.
    pub fn throughput_bps(&self) -> f64 {
        if self.uptime_secs <= 0.0 {
            return 0.0;
        }
        self.bytes_sent as f64 / self.uptime_secs
    }

    /// Get success rate (0.0 to 1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.total_enqueued();
        if total == 0 {
            return 1.0;
        }
        self.total_sent() as f64 / total as f64
    }

    /// Get P2 coalesce ratio.
    pub fn coalesce_ratio(&self) -> f64 {
        if self.enqueued_p2 == 0 {
            return 0.0;
        }
        self.coalesced_p2 as f64 / self.enqueued_p2 as f64
    }
}

/// Observer trait for external monitoring integration.
///
/// Implement this trait to receive notifications about congestion events.
pub trait MetricsObserver: Send + Sync {
    /// Called when rate is decreased.
    fn on_decrease(&self, old_rate: u32, new_rate: u32, trigger: &str);

    /// Called when rate is increased.
    fn on_increase(&self, old_rate: u32, new_rate: u32);

    /// Called when a sample is dropped.
    fn on_drop(&self, priority: Priority, count: u64);

    /// Called when samples are coalesced.
    fn on_coalesce(&self, count: u64);

    /// Called when a repair is sent.
    fn on_repair(&self, sequence: u64, retry: u32);

    /// Called on EAGAIN.
    fn on_eagain(&self);
}

/// No-op observer for when monitoring is not needed.
///
/// Use this when you don't need to observe congestion control events.
/// For custom monitoring, implement [`MetricsObserver`] directly.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoOpObserver;

impl MetricsObserver for NoOpObserver {
    /// No-op: ignores rate decrease events.
    fn on_decrease(&self, _old: u32, _new: u32, _trigger: &str) {
        // Intentionally empty - NoOpObserver discards all events.
    }

    /// No-op: ignores rate increase events.
    fn on_increase(&self, _old: u32, _new: u32) {
        // Intentionally empty - NoOpObserver discards all events.
    }

    /// No-op: ignores drop events.
    fn on_drop(&self, _priority: Priority, _count: u64) {
        // Intentionally empty - NoOpObserver discards all events.
    }

    /// No-op: ignores coalesce events.
    fn on_coalesce(&self, _count: u64) {
        // Intentionally empty - NoOpObserver discards all events.
    }

    /// No-op: ignores repair events.
    fn on_repair(&self, _sequence: u64, _retry: u32) {
        // Intentionally empty - NoOpObserver discards all events.
    }

    /// No-op: ignores EAGAIN events.
    fn on_eagain(&self) {
        // Intentionally empty - NoOpObserver discards all events.
    }
}

/// Logging observer that logs events (uses println for simplicity).
#[derive(Clone, Copy, Debug, Default)]
pub struct LoggingObserver;

impl MetricsObserver for LoggingObserver {
    fn on_decrease(&self, old: u32, new: u32, trigger: &str) {
        // Use crate logging if available, otherwise silent
        #[cfg(feature = "logging")]
        crate::warn!(
            "congestion: rate decreased {} -> {} (trigger: {})",
            old,
            new,
            trigger
        );
        let _ = (old, new, trigger);
    }

    fn on_increase(&self, old: u32, new: u32) {
        #[cfg(feature = "logging")]
        crate::debug!("congestion: rate increased {} -> {}", old, new);
        let _ = (old, new);
    }

    fn on_drop(&self, priority: Priority, count: u64) {
        #[cfg(feature = "logging")]
        crate::warn!("congestion: {} samples dropped from {:?}", count, priority);
        let _ = (priority, count);
    }

    fn on_coalesce(&self, count: u64) {
        // trace! is only available when both logging and trace features are enabled
        // Just silence the variable for now
        let _ = count;
    }

    fn on_repair(&self, sequence: u64, retry: u32) {
        #[cfg(feature = "logging")]
        crate::debug!("congestion: repair sent seq={} retry={}", sequence, retry);
        let _ = (sequence, retry);
    }

    fn on_eagain(&self) {
        #[cfg(feature = "logging")]
        crate::debug!("congestion: EAGAIN received");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_state_default() {
        assert_eq!(CongestionState::default(), CongestionState::Stable);
    }

    #[test]
    fn test_metrics_new() {
        let metrics = CongestionMetrics::new();
        let snap = metrics.snapshot();
        assert_eq!(snap.current_rate_bps, 0);
        assert_eq!(snap.decrease_count, 0);
    }

    #[test]
    fn test_record_rate() {
        let metrics = CongestionMetrics::new();
        metrics.record_rate(100_000);
        assert_eq!(metrics.snapshot().current_rate_bps, 100_000);
    }

    #[test]
    fn test_record_score() {
        let metrics = CongestionMetrics::new();
        metrics.record_score(0.75);
        let snap = metrics.snapshot();
        assert!((snap.congestion_score - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_record_events() {
        let metrics = CongestionMetrics::new();

        metrics.record_decrease();
        metrics.record_decrease();
        metrics.record_increase();
        metrics.record_eagain();
        metrics.record_nack();
        metrics.record_nack();

        let snap = metrics.snapshot();
        assert_eq!(snap.decrease_count, 2);
        assert_eq!(snap.increase_count, 1);
        assert_eq!(snap.eagain_total, 1);
        assert_eq!(snap.nack_total, 2);
    }

    #[test]
    fn test_record_priority() {
        let metrics = CongestionMetrics::new();

        metrics.record_enqueue(Priority::P0);
        metrics.record_enqueue(Priority::P1);
        metrics.record_enqueue(Priority::P1);
        metrics.record_enqueue(Priority::P2);

        metrics.record_send(Priority::P0, 100);
        metrics.record_send(Priority::P1, 200);

        let snap = metrics.snapshot();
        assert_eq!(snap.enqueued_p0, 1);
        assert_eq!(snap.enqueued_p1, 2);
        assert_eq!(snap.enqueued_p2, 1);
        assert_eq!(snap.sent_p0, 1);
        assert_eq!(snap.sent_p1, 1);
        assert_eq!(snap.bytes_sent, 300);
    }

    #[test]
    fn test_record_drops() {
        let metrics = CongestionMetrics::new();

        metrics.record_drop_p1();
        metrics.record_drop_p1();
        metrics.record_coalesce_p2();
        metrics.record_drop_p2();

        let snap = metrics.snapshot();
        assert_eq!(snap.dropped_p1, 2);
        assert_eq!(snap.coalesced_p2, 1);
        assert_eq!(snap.dropped_p2, 1);
    }

    #[test]
    fn test_record_reliable() {
        let metrics = CongestionMetrics::new();

        metrics.record_repair_request();
        metrics.record_repair_request();
        metrics.record_repair_sent();
        metrics.record_repair_budget_exhausted();
        metrics.record_retry_exceeded();

        let snap = metrics.snapshot();
        assert_eq!(snap.repair_requests, 2);
        assert_eq!(snap.repair_sent, 1);
        assert_eq!(snap.repair_budget_exhausted, 1);
        assert_eq!(snap.retries_exceeded, 1);
    }

    #[test]
    fn test_reset() {
        let metrics = CongestionMetrics::new();

        metrics.record_decrease();
        metrics.record_eagain();
        metrics.record_send(Priority::P0, 100);

        metrics.reset();

        let snap = metrics.snapshot();
        assert_eq!(snap.decrease_count, 0);
        assert_eq!(snap.eagain_total, 0);
        assert_eq!(snap.bytes_sent, 0);
    }

    #[test]
    fn test_snapshot_totals() {
        let snap = CongestionMetricsSnapshot {
            enqueued_p0: 10,
            enqueued_p1: 20,
            enqueued_p2: 30,
            sent_p0: 10,
            sent_p1: 18,
            sent_p2: 25,
            dropped_p1: 2,
            dropped_p2: 5,
            ..Default::default()
        };

        assert_eq!(snap.total_enqueued(), 60);
        assert_eq!(snap.total_sent(), 53);
        assert_eq!(snap.total_dropped(), 7);
    }

    #[test]
    fn test_snapshot_throughput() {
        let snap = CongestionMetricsSnapshot {
            bytes_sent: 1000,
            uptime_secs: 2.0,
            ..Default::default()
        };

        assert!((snap.throughput_bps() - 500.0).abs() < 0.01);
    }

    #[test]
    fn test_snapshot_success_rate() {
        let snap = CongestionMetricsSnapshot {
            enqueued_p0: 10,
            enqueued_p1: 10,
            enqueued_p2: 10,
            sent_p0: 10,
            sent_p1: 8,
            sent_p2: 6,
            ..Default::default()
        };

        assert!((snap.success_rate() - 0.8).abs() < 0.01); // 24/30 = 0.8
    }

    #[test]
    fn test_snapshot_coalesce_ratio() {
        let snap = CongestionMetricsSnapshot {
            enqueued_p2: 100,
            coalesced_p2: 70,
            ..Default::default()
        };

        assert!((snap.coalesce_ratio() - 0.7).abs() < 0.01);
    }

    #[test]
    fn test_congestion_state_from_score() {
        let metrics = CongestionMetrics::new();

        metrics.record_score(0.50);
        assert_eq!(metrics.snapshot().state, CongestionState::Stable);

        metrics.record_score(0.70);
        assert_eq!(metrics.snapshot().state, CongestionState::Congested);
    }

    #[test]
    fn test_noop_observer() {
        let obs = NoOpObserver;
        obs.on_decrease(100, 50, "test");
        obs.on_increase(50, 100);
        obs.on_drop(Priority::P1, 1);
        obs.on_coalesce(1);
        obs.on_repair(1, 1);
        obs.on_eagain();
        // Should not panic
    }

    #[test]
    fn test_logging_observer() {
        let obs = LoggingObserver;
        obs.on_decrease(100, 50, "eagain");
        obs.on_increase(50, 100);
        obs.on_drop(Priority::P1, 5);
        obs.on_coalesce(10);
        obs.on_repair(42, 2);
        obs.on_eagain();
        // Should not panic (logging may or may not output depending on config)
    }
}

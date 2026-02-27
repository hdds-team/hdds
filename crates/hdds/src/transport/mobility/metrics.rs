// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Metrics for IP mobility tracking.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Metrics for IP mobility operations.
pub struct MobilityMetrics {
    /// Number of IP addresses added.
    addresses_added: AtomicU64,

    /// Number of IP addresses removed.
    addresses_removed: AtomicU64,

    /// Number of reannounce bursts triggered.
    reannounce_bursts: AtomicU64,

    /// Total reannounce packets sent.
    reannounce_packets: AtomicU64,

    /// Number of detection polls performed.
    polls_performed: AtomicU64,

    /// Number of locators expired (hold-down complete).
    locators_expired: AtomicU64,

    /// Number of locators currently in hold-down.
    locators_hold_down: AtomicU64,

    /// Number of active locators.
    locators_active: AtomicU64,

    /// Creation time for uptime calculation.
    created: Instant,
}

impl MobilityMetrics {
    /// Create new metrics.
    pub fn new() -> Self {
        Self {
            addresses_added: AtomicU64::new(0),
            addresses_removed: AtomicU64::new(0),
            reannounce_bursts: AtomicU64::new(0),
            reannounce_packets: AtomicU64::new(0),
            polls_performed: AtomicU64::new(0),
            locators_expired: AtomicU64::new(0),
            locators_hold_down: AtomicU64::new(0),
            locators_active: AtomicU64::new(0),
            created: Instant::now(),
        }
    }

    /// Record an address addition.
    pub fn record_address_added(&self) {
        self.addresses_added.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an address removal.
    pub fn record_address_removed(&self) {
        self.addresses_removed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a reannounce burst.
    pub fn record_reannounce_burst(&self, packet_count: u64) {
        self.reannounce_bursts.fetch_add(1, Ordering::Relaxed);
        self.reannounce_packets
            .fetch_add(packet_count, Ordering::Relaxed);
    }

    /// Record a poll operation.
    pub fn record_poll(&self) {
        self.polls_performed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record locators expired.
    pub fn record_locators_expired(&self, count: u64) {
        self.locators_expired.fetch_add(count, Ordering::Relaxed);
    }

    /// Update current locator counts.
    pub fn update_locator_counts(&self, active: u64, hold_down: u64) {
        self.locators_active.store(active, Ordering::Relaxed);
        self.locators_hold_down.store(hold_down, Ordering::Relaxed);
    }

    /// Get total addresses added.
    pub fn addresses_added(&self) -> u64 {
        self.addresses_added.load(Ordering::Relaxed)
    }

    /// Get total addresses removed.
    pub fn addresses_removed(&self) -> u64 {
        self.addresses_removed.load(Ordering::Relaxed)
    }

    /// Get total reannounce bursts.
    pub fn reannounce_bursts(&self) -> u64 {
        self.reannounce_bursts.load(Ordering::Relaxed)
    }

    /// Get total reannounce packets.
    pub fn reannounce_packets(&self) -> u64 {
        self.reannounce_packets.load(Ordering::Relaxed)
    }

    /// Get total polls performed.
    pub fn polls_performed(&self) -> u64 {
        self.polls_performed.load(Ordering::Relaxed)
    }

    /// Get total locators expired.
    pub fn locators_expired(&self) -> u64 {
        self.locators_expired.load(Ordering::Relaxed)
    }

    /// Get current active locator count.
    pub fn active_locators(&self) -> u64 {
        self.locators_active.load(Ordering::Relaxed)
    }

    /// Get current hold-down locator count.
    pub fn hold_down_locators(&self) -> u64 {
        self.locators_hold_down.load(Ordering::Relaxed)
    }

    /// Get uptime.
    pub fn uptime(&self) -> Duration {
        self.created.elapsed()
    }

    /// Get a snapshot of all metrics.
    pub fn snapshot(&self) -> MobilityMetricsSnapshot {
        MobilityMetricsSnapshot {
            addresses_added: self.addresses_added(),
            addresses_removed: self.addresses_removed(),
            reannounce_bursts: self.reannounce_bursts(),
            reannounce_packets: self.reannounce_packets(),
            polls_performed: self.polls_performed(),
            locators_expired: self.locators_expired(),
            locators_active: self.active_locators(),
            locators_hold_down: self.hold_down_locators(),
            uptime: self.uptime(),
        }
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.addresses_added.store(0, Ordering::Relaxed);
        self.addresses_removed.store(0, Ordering::Relaxed);
        self.reannounce_bursts.store(0, Ordering::Relaxed);
        self.reannounce_packets.store(0, Ordering::Relaxed);
        self.polls_performed.store(0, Ordering::Relaxed);
        self.locators_expired.store(0, Ordering::Relaxed);
        // Don't reset current counts - they reflect actual state
    }
}

impl Default for MobilityMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of mobility metrics.
#[derive(Clone, Debug)]
pub struct MobilityMetricsSnapshot {
    /// Total addresses added.
    pub addresses_added: u64,

    /// Total addresses removed.
    pub addresses_removed: u64,

    /// Total reannounce bursts.
    pub reannounce_bursts: u64,

    /// Total reannounce packets.
    pub reannounce_packets: u64,

    /// Total polls performed.
    pub polls_performed: u64,

    /// Total locators expired.
    pub locators_expired: u64,

    /// Current active locators.
    pub locators_active: u64,

    /// Current hold-down locators.
    pub locators_hold_down: u64,

    /// Metrics uptime.
    pub uptime: Duration,
}

impl MobilityMetricsSnapshot {
    /// Get total locator change events.
    pub fn total_changes(&self) -> u64 {
        self.addresses_added + self.addresses_removed
    }

    /// Get total current locators (active + hold-down).
    pub fn total_locators(&self) -> u64 {
        self.locators_active + self.locators_hold_down
    }

    /// Get average packets per burst.
    pub fn avg_packets_per_burst(&self) -> f64 {
        if self.reannounce_bursts == 0 {
            0.0
        } else {
            self.reannounce_packets as f64 / self.reannounce_bursts as f64
        }
    }

    /// Get poll rate (polls per second).
    pub fn poll_rate(&self) -> f64 {
        let secs = self.uptime.as_secs_f64();
        if secs < 0.001 {
            0.0
        } else {
            self.polls_performed as f64 / secs
        }
    }

    /// Get change rate (changes per minute).
    pub fn change_rate_per_minute(&self) -> f64 {
        let minutes = self.uptime.as_secs_f64() / 60.0;
        if minutes < 0.001 {
            0.0
        } else {
            self.total_changes() as f64 / minutes
        }
    }
}

impl Default for MobilityMetricsSnapshot {
    fn default() -> Self {
        Self {
            addresses_added: 0,
            addresses_removed: 0,
            reannounce_bursts: 0,
            reannounce_packets: 0,
            polls_performed: 0,
            locators_expired: 0,
            locators_active: 0,
            locators_hold_down: 0,
            uptime: Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let metrics = MobilityMetrics::new();
        assert_eq!(metrics.addresses_added(), 0);
        assert_eq!(metrics.addresses_removed(), 0);
        assert_eq!(metrics.reannounce_bursts(), 0);
        assert_eq!(metrics.polls_performed(), 0);
    }

    #[test]
    fn test_metrics_record_address_added() {
        let metrics = MobilityMetrics::new();
        metrics.record_address_added();
        metrics.record_address_added();
        assert_eq!(metrics.addresses_added(), 2);
    }

    #[test]
    fn test_metrics_record_address_removed() {
        let metrics = MobilityMetrics::new();
        metrics.record_address_removed();
        assert_eq!(metrics.addresses_removed(), 1);
    }

    #[test]
    fn test_metrics_record_reannounce_burst() {
        let metrics = MobilityMetrics::new();
        metrics.record_reannounce_burst(5);
        metrics.record_reannounce_burst(3);

        assert_eq!(metrics.reannounce_bursts(), 2);
        assert_eq!(metrics.reannounce_packets(), 8);
    }

    #[test]
    fn test_metrics_record_poll() {
        let metrics = MobilityMetrics::new();
        metrics.record_poll();
        metrics.record_poll();
        metrics.record_poll();
        assert_eq!(metrics.polls_performed(), 3);
    }

    #[test]
    fn test_metrics_record_locators_expired() {
        let metrics = MobilityMetrics::new();
        metrics.record_locators_expired(2);
        metrics.record_locators_expired(1);
        assert_eq!(metrics.locators_expired(), 3);
    }

    #[test]
    fn test_metrics_update_locator_counts() {
        let metrics = MobilityMetrics::new();
        metrics.update_locator_counts(5, 2);
        assert_eq!(metrics.active_locators(), 5);
        assert_eq!(metrics.hold_down_locators(), 2);
    }

    #[test]
    fn test_metrics_uptime() {
        let metrics = MobilityMetrics::new();
        std::thread::sleep(Duration::from_millis(10));
        assert!(metrics.uptime() >= Duration::from_millis(10));
    }

    #[test]
    fn test_metrics_snapshot() {
        let metrics = MobilityMetrics::new();
        metrics.record_address_added();
        metrics.record_address_removed();
        metrics.record_reannounce_burst(3);
        metrics.record_poll();
        metrics.update_locator_counts(2, 1);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.addresses_added, 1);
        assert_eq!(snapshot.addresses_removed, 1);
        assert_eq!(snapshot.reannounce_bursts, 1);
        assert_eq!(snapshot.reannounce_packets, 3);
        assert_eq!(snapshot.polls_performed, 1);
        assert_eq!(snapshot.locators_active, 2);
        assert_eq!(snapshot.locators_hold_down, 1);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = MobilityMetrics::new();
        metrics.record_address_added();
        metrics.record_address_removed();
        metrics.record_poll();
        metrics.update_locator_counts(5, 2);

        metrics.reset();
        assert_eq!(metrics.addresses_added(), 0);
        assert_eq!(metrics.addresses_removed(), 0);
        assert_eq!(metrics.polls_performed(), 0);
        // Locator counts not reset
        assert_eq!(metrics.active_locators(), 5);
    }

    #[test]
    fn test_snapshot_total_changes() {
        let snapshot = MobilityMetricsSnapshot {
            addresses_added: 10,
            addresses_removed: 5,
            ..Default::default()
        };
        assert_eq!(snapshot.total_changes(), 15);
    }

    #[test]
    fn test_snapshot_total_locators() {
        let snapshot = MobilityMetricsSnapshot {
            locators_active: 3,
            locators_hold_down: 2,
            ..Default::default()
        };
        assert_eq!(snapshot.total_locators(), 5);
    }

    #[test]
    fn test_snapshot_avg_packets_per_burst() {
        let snapshot = MobilityMetricsSnapshot {
            reannounce_bursts: 4,
            reannounce_packets: 12,
            ..Default::default()
        };
        assert!((snapshot.avg_packets_per_burst() - 3.0).abs() < 0.001);

        let empty = MobilityMetricsSnapshot::default();
        assert!((empty.avg_packets_per_burst() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_snapshot_poll_rate() {
        let snapshot = MobilityMetricsSnapshot {
            polls_performed: 60,
            uptime: Duration::from_secs(60),
            ..Default::default()
        };
        assert!((snapshot.poll_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_snapshot_change_rate_per_minute() {
        let snapshot = MobilityMetricsSnapshot {
            addresses_added: 30,
            addresses_removed: 30,
            uptime: Duration::from_secs(60),
            ..Default::default()
        };
        assert!((snapshot.change_rate_per_minute() - 60.0).abs() < 0.001);
    }

    #[test]
    fn test_snapshot_default() {
        let snapshot = MobilityMetricsSnapshot::default();
        assert_eq!(snapshot.addresses_added, 0);
        assert_eq!(snapshot.uptime, Duration::ZERO);
    }

    #[test]
    fn test_metrics_default() {
        let metrics = MobilityMetrics::default();
        assert_eq!(metrics.addresses_added(), 0);
    }
}

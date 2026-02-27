// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Retry tracker with exponential backoff for reliable QoS.
//!
//! Tracks retry attempts per sequence number and calculates
//! exponential backoff delays to avoid overwhelming the network.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::nack_coalescer::SequenceNumber;

/// Configuration for retry backoff.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// Base delay for first retry (ms).
    pub base_ms: u32,
    /// Maximum delay cap (ms).
    pub max_ms: u32,
    /// Maximum number of retries before giving up.
    pub max_retries: u32,
    /// Jitter factor (0.0 - 1.0) to add randomness.
    pub jitter_factor: f32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            base_ms: 100,
            max_ms: 5000,
            max_retries: 10,
            jitter_factor: 0.1,
        }
    }
}

impl RetryConfig {
    /// Create with custom base and max delays.
    pub fn new(base_ms: u32, max_ms: u32) -> Self {
        Self {
            base_ms,
            max_ms,
            ..Default::default()
        }
    }

    /// Set maximum retries.
    pub fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set jitter factor.
    pub fn with_jitter(mut self, factor: f32) -> Self {
        self.jitter_factor = factor.clamp(0.0, 1.0);
        self
    }
}

/// State of a single retry sequence.
#[derive(Debug, Clone, Copy)]
struct RetryState {
    /// Number of retries attempted.
    retry_count: u32,
    /// Time of last retry.
    last_retry: Instant,
    /// Time of first NACK for this sequence.
    first_nack: Instant,
}

/// Tracks retry state for sequence numbers.
///
/// Implements exponential backoff to avoid overwhelming the network
/// with retransmissions under congestion.
#[derive(Debug)]
pub struct RetryTracker {
    /// Configuration.
    config: RetryConfig,

    /// Retry state per sequence.
    retries: HashMap<SequenceNumber, RetryState>,

    /// Statistics.
    stats: RetryTrackerStats,
}

/// Statistics for retry tracking.
#[derive(Debug, Clone, Copy, Default)]
pub struct RetryTrackerStats {
    /// Total retry requests.
    pub retry_requests: u64,
    /// Retries that were scheduled.
    pub retries_scheduled: u64,
    /// Retries that exceeded max_retries.
    pub retries_exceeded: u64,
    /// Sequences acknowledged (removed from tracking).
    pub sequences_acked: u64,
    /// Sequences pruned due to age.
    pub sequences_pruned: u64,
}

impl RetryTracker {
    /// Create a new retry tracker with default configuration.
    pub fn new() -> Self {
        Self::with_config(RetryConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: RetryConfig) -> Self {
        Self {
            config,
            retries: HashMap::new(),
            stats: RetryTrackerStats::default(),
        }
    }

    /// Request a retry for a sequence number.
    ///
    /// Returns `Some(delay)` if the retry should be scheduled,
    /// `None` if max retries exceeded.
    pub fn next_retry(&mut self, seq: SequenceNumber) -> Option<Duration> {
        self.stats.retry_requests += 1;

        let now = Instant::now();

        let state = self.retries.entry(seq).or_insert(RetryState {
            retry_count: 0,
            last_retry: now,
            first_nack: now,
        });

        if state.retry_count >= self.config.max_retries {
            self.stats.retries_exceeded += 1;
            return None;
        }

        state.retry_count += 1;
        state.last_retry = now;

        let retry_count = state.retry_count;

        self.stats.retries_scheduled += 1;

        // Calculate delay with exponential backoff
        Some(self.calculate_delay(retry_count))
    }

    /// Calculate delay for the given retry count.
    fn calculate_delay(&self, retry_count: u32) -> Duration {
        // Exponential backoff: base * 2^(retry_count - 1)
        let exponent = retry_count.saturating_sub(1);
        let delay_ms = self
            .config
            .base_ms
            .saturating_mul(2u32.saturating_pow(exponent));
        let delay_ms = delay_ms.min(self.config.max_ms);

        // Add jitter
        let jitter_range = (delay_ms as f32 * self.config.jitter_factor) as u32;
        let jitter = if jitter_range > 0 {
            // Simple deterministic "jitter" based on delay
            // In production, would use proper RNG
            delay_ms % jitter_range
        } else {
            0
        };

        Duration::from_millis((delay_ms + jitter) as u64)
    }

    /// Acknowledge a sequence (stop tracking it).
    pub fn ack(&mut self, seq: SequenceNumber) {
        if self.retries.remove(&seq).is_some() {
            self.stats.sequences_acked += 1;
        }
    }

    /// Acknowledge multiple sequences.
    pub fn ack_range(&mut self, start: SequenceNumber, end: SequenceNumber) {
        for seq in start..=end {
            self.ack(seq);
        }
    }

    /// Get the retry count for a sequence.
    pub fn retry_count(&self, seq: SequenceNumber) -> u32 {
        self.retries.get(&seq).map(|s| s.retry_count).unwrap_or(0)
    }

    /// Check if a sequence has exceeded max retries.
    pub fn is_exceeded(&self, seq: SequenceNumber) -> bool {
        self.retries
            .get(&seq)
            .map(|s| s.retry_count >= self.config.max_retries)
            .unwrap_or(false)
    }

    /// Get time since first NACK for a sequence.
    pub fn time_since_first_nack(&self, seq: SequenceNumber) -> Option<Duration> {
        self.retries.get(&seq).map(|s| s.first_nack.elapsed())
    }

    /// Get the number of tracked sequences.
    pub fn tracked_count(&self) -> usize {
        self.retries.len()
    }

    /// Check if there are any tracked sequences.
    pub fn has_tracked(&self) -> bool {
        !self.retries.is_empty()
    }

    /// Prune old entries (sequences that have been tracked too long).
    pub fn prune_old(&mut self, max_age: Duration) {
        let before = self.retries.len();
        self.retries
            .retain(|_, state| state.first_nack.elapsed() < max_age);
        let removed = before - self.retries.len();
        self.stats.sequences_pruned += removed as u64;
    }

    /// Clear all tracked sequences.
    pub fn clear(&mut self) {
        self.retries.clear();
    }

    /// Get statistics.
    pub fn stats(&self) -> RetryTrackerStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = RetryTrackerStats::default();
    }

    /// Get the configuration.
    pub fn config(&self) -> &RetryConfig {
        &self.config
    }

    /// Update configuration.
    pub fn set_config(&mut self, config: RetryConfig) {
        self.config = config;
    }
}

impl Default for RetryTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduled repair request.
#[derive(Debug, Clone, Copy)]
pub struct RepairRequest {
    /// Sequence number to repair.
    pub sequence: SequenceNumber,
    /// When this repair should be sent.
    pub scheduled_at: Instant,
    /// Retry attempt number.
    pub retry_attempt: u32,
}

impl RepairRequest {
    /// Create a new repair request scheduled at now + delay.
    pub fn new(sequence: SequenceNumber, delay: Duration, retry_attempt: u32) -> Self {
        Self {
            sequence,
            scheduled_at: Instant::now() + delay,
            retry_attempt,
        }
    }

    /// Check if this repair is ready to send.
    pub fn is_ready(&self) -> bool {
        Instant::now() >= self.scheduled_at
    }

    /// Time until this repair is ready.
    pub fn time_until_ready(&self) -> Duration {
        let now = Instant::now();
        if now >= self.scheduled_at {
            Duration::ZERO
        } else {
            self.scheduled_at - now
        }
    }

    /// Estimated size of the repair packet.
    pub fn estimated_size(&self) -> usize {
        // RTPS header (20) + DATA submessage (~100 typical)
        // This is a rough estimate; actual size depends on payload
        120
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_retry_config_default() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.base_ms, 100);
        assert_eq!(cfg.max_ms, 5000);
        assert_eq!(cfg.max_retries, 10);
    }

    #[test]
    fn test_retry_config_builder() {
        let cfg = RetryConfig::new(50, 2000)
            .with_max_retries(5)
            .with_jitter(0.2);

        assert_eq!(cfg.base_ms, 50);
        assert_eq!(cfg.max_ms, 2000);
        assert_eq!(cfg.max_retries, 5);
        assert!((cfg.jitter_factor - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_new() {
        let tracker = RetryTracker::new();
        assert_eq!(tracker.tracked_count(), 0);
        assert!(!tracker.has_tracked());
    }

    #[test]
    fn test_next_retry_first() {
        let mut tracker = RetryTracker::new();

        let delay = tracker.next_retry(100);
        assert!(delay.is_some());

        // First retry should use base delay (~100ms)
        let delay = delay.unwrap();
        assert!(delay >= Duration::from_millis(100));
        assert!(delay < Duration::from_millis(200)); // With jitter

        assert_eq!(tracker.retry_count(100), 1);
    }

    #[test]
    fn test_exponential_backoff() {
        let cfg = RetryConfig::new(100, 10000).with_jitter(0.0);
        let mut tracker = RetryTracker::with_config(cfg);

        // First retry: 100ms
        let d1 = tracker.next_retry(1).unwrap();
        assert_eq!(d1, Duration::from_millis(100));

        // Second retry: 200ms
        let d2 = tracker.next_retry(1).unwrap();
        assert_eq!(d2, Duration::from_millis(200));

        // Third retry: 400ms
        let d3 = tracker.next_retry(1).unwrap();
        assert_eq!(d3, Duration::from_millis(400));

        // Fourth retry: 800ms
        let d4 = tracker.next_retry(1).unwrap();
        assert_eq!(d4, Duration::from_millis(800));
    }

    #[test]
    fn test_max_delay_cap() {
        let cfg = RetryConfig::new(100, 500)
            .with_jitter(0.0)
            .with_max_retries(20);
        let mut tracker = RetryTracker::with_config(cfg);

        // Keep retrying - should cap at 500ms
        for _ in 0..10 {
            let delay = tracker.next_retry(1).unwrap();
            assert!(delay <= Duration::from_millis(500));
        }
    }

    #[test]
    fn test_max_retries_exceeded() {
        let cfg = RetryConfig::new(10, 100).with_max_retries(3);
        let mut tracker = RetryTracker::with_config(cfg);

        // Three retries OK
        assert!(tracker.next_retry(1).is_some());
        assert!(tracker.next_retry(1).is_some());
        assert!(tracker.next_retry(1).is_some());

        // Fourth should fail
        assert!(tracker.next_retry(1).is_none());
        assert!(tracker.is_exceeded(1));

        assert_eq!(tracker.stats().retries_exceeded, 1);
    }

    #[test]
    fn test_ack() {
        let mut tracker = RetryTracker::new();

        tracker.next_retry(100);
        tracker.next_retry(101);
        tracker.next_retry(102);

        assert_eq!(tracker.tracked_count(), 3);

        tracker.ack(101);
        assert_eq!(tracker.tracked_count(), 2);
        assert_eq!(tracker.retry_count(101), 0); // Reset after ack

        assert_eq!(tracker.stats().sequences_acked, 1);
    }

    #[test]
    fn test_ack_range() {
        let mut tracker = RetryTracker::new();

        for seq in 100..110 {
            tracker.next_retry(seq);
        }
        assert_eq!(tracker.tracked_count(), 10);

        tracker.ack_range(103, 107);
        assert_eq!(tracker.tracked_count(), 5); // 100, 101, 102, 108, 109
        assert_eq!(tracker.stats().sequences_acked, 5);
    }

    #[test]
    fn test_ack_nonexistent() {
        let mut tracker = RetryTracker::new();

        tracker.ack(999); // Doesn't exist
        assert_eq!(tracker.stats().sequences_acked, 0);
    }

    #[test]
    fn test_time_since_first_nack() {
        let mut tracker = RetryTracker::new();

        assert!(tracker.time_since_first_nack(100).is_none());

        tracker.next_retry(100);
        thread::sleep(Duration::from_millis(10));

        let elapsed = tracker.time_since_first_nack(100);
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() >= Duration::from_millis(10));
    }

    #[test]
    fn test_prune_old() {
        let mut tracker = RetryTracker::new();

        tracker.next_retry(100);
        tracker.next_retry(101);

        thread::sleep(Duration::from_millis(20));

        tracker.next_retry(102); // Fresh one

        tracker.prune_old(Duration::from_millis(15));

        // 100 and 101 should be pruned, 102 should remain
        assert_eq!(tracker.tracked_count(), 1);
        assert_eq!(tracker.retry_count(100), 0);
        assert_eq!(tracker.retry_count(101), 0);
        assert_eq!(tracker.retry_count(102), 1);

        assert_eq!(tracker.stats().sequences_pruned, 2);
    }

    #[test]
    fn test_clear() {
        let mut tracker = RetryTracker::new();

        tracker.next_retry(100);
        tracker.next_retry(101);

        tracker.clear();

        assert_eq!(tracker.tracked_count(), 0);
        assert!(!tracker.has_tracked());
    }

    #[test]
    fn test_stats() {
        let cfg = RetryConfig::new(10, 100).with_max_retries(2);
        let mut tracker = RetryTracker::with_config(cfg);

        tracker.next_retry(1); // scheduled
        tracker.next_retry(1); // scheduled
        tracker.next_retry(1); // exceeded

        let stats = tracker.stats();
        assert_eq!(stats.retry_requests, 3);
        assert_eq!(stats.retries_scheduled, 2);
        assert_eq!(stats.retries_exceeded, 1);
    }

    #[test]
    fn test_repair_request() {
        let req = RepairRequest::new(100, Duration::from_millis(50), 1);

        assert_eq!(req.sequence, 100);
        assert_eq!(req.retry_attempt, 1);
        assert!(!req.is_ready()); // Not ready yet

        thread::sleep(Duration::from_millis(60));
        assert!(req.is_ready());
        assert_eq!(req.time_until_ready(), Duration::ZERO);
    }

    #[test]
    fn test_repair_request_time_until_ready() {
        let req = RepairRequest::new(100, Duration::from_millis(100), 1);

        let remaining = req.time_until_ready();
        assert!(remaining <= Duration::from_millis(100));
        assert!(remaining > Duration::from_millis(50));
    }

    #[test]
    fn test_repair_request_estimated_size() {
        let req = RepairRequest::new(100, Duration::ZERO, 1);
        assert!(req.estimated_size() > 0);
    }

    #[test]
    fn test_multiple_sequences() {
        let mut tracker = RetryTracker::new();

        tracker.next_retry(100);
        tracker.next_retry(101);
        tracker.next_retry(100); // Second retry for 100

        assert_eq!(tracker.retry_count(100), 2);
        assert_eq!(tracker.retry_count(101), 1);
        assert_eq!(tracker.tracked_count(), 2);
    }

    #[test]
    fn test_config_update() {
        let mut tracker = RetryTracker::new();

        let new_cfg = RetryConfig::new(50, 1000);
        tracker.set_config(new_cfg);

        assert_eq!(tracker.config().base_ms, 50);
        assert_eq!(tracker.config().max_ms, 1000);
    }

    #[test]
    fn test_jitter_clamping() {
        let cfg = RetryConfig::default().with_jitter(2.0); // Should clamp to 1.0
        assert!((cfg.jitter_factor - 1.0).abs() < 0.001);

        let cfg = RetryConfig::default().with_jitter(-0.5); // Should clamp to 0.0
        assert!(cfg.jitter_factor.abs() < 0.001);
    }
}

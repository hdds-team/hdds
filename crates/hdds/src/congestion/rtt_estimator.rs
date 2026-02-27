// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTT (Round-Trip Time) estimator.
//!
//! Estimates RTT from Heartbeat/AckNack exchanges using EWMA.
//! Used to detect RTT inflation as a soft congestion signal.

use std::time::{Duration, Instant};

/// RTT estimator using EWMA (Exponentially Weighted Moving Average).
#[derive(Debug)]
pub struct RttEstimator {
    /// Current RTT estimate (EWMA).
    rtt_ms: f32,

    /// Minimum RTT observed (baseline).
    rtt_min_ms: f32,

    /// RTT variance estimate.
    rtt_var_ms: f32,

    /// EWMA smoothing factor (0.0 - 1.0).
    alpha: f32,

    /// Variance smoothing factor.
    beta: f32,

    /// Default RTT for bootstrap.
    default_ms: f32,

    /// Number of samples received.
    samples: u64,

    /// Last sample time.
    last_sample: Option<Instant>,

    /// Inflation detection factor.
    inflate_factor: f32,
}

impl RttEstimator {
    /// Create a new RTT estimator.
    pub fn new(default_ms: f32) -> Self {
        Self {
            rtt_ms: default_ms,
            rtt_min_ms: default_ms,
            rtt_var_ms: 0.0,
            alpha: 0.125, // TCP-like smoothing
            beta: 0.25,   // Variance smoothing
            default_ms,
            samples: 0,
            last_sample: None,
            inflate_factor: 2.0,
        }
    }

    /// Create with custom smoothing factors.
    pub fn with_alpha(default_ms: f32, alpha: f32, beta: f32) -> Self {
        Self {
            rtt_ms: default_ms,
            rtt_min_ms: default_ms,
            rtt_var_ms: 0.0,
            alpha: alpha.clamp(0.0, 1.0),
            beta: beta.clamp(0.0, 1.0),
            default_ms,
            samples: 0,
            last_sample: None,
            inflate_factor: 2.0,
        }
    }

    /// Create with custom inflation factor.
    pub fn with_inflate_factor(default_ms: f32, factor: f32) -> Self {
        Self {
            inflate_factor: factor,
            ..Self::new(default_ms)
        }
    }

    /// Update the RTT estimate with a new sample.
    pub fn update(&mut self, sample_ms: f32) {
        self.samples += 1;
        self.last_sample = Some(Instant::now());

        // Update minimum (baseline)
        if sample_ms < self.rtt_min_ms || self.samples == 1 {
            self.rtt_min_ms = sample_ms;
        }

        if self.samples == 1 {
            // First sample - initialize directly
            self.rtt_ms = sample_ms;
            self.rtt_var_ms = sample_ms / 2.0;
        } else {
            // EWMA update (RFC 6298 style)
            let diff = sample_ms - self.rtt_ms;
            self.rtt_ms += self.alpha * diff;
            self.rtt_var_ms += self.beta * (diff.abs() - self.rtt_var_ms);
        }
    }

    /// Update from a Duration.
    pub fn update_duration(&mut self, sample: Duration) {
        self.update(sample.as_secs_f32() * 1000.0);
    }

    /// Check if RTT is inflated compared to baseline.
    pub fn is_inflated(&self) -> bool {
        self.rtt_ms > self.rtt_min_ms * self.inflate_factor
    }

    /// Check if RTT is inflated by a specific factor.
    pub fn is_inflated_by(&self, factor: f32) -> bool {
        self.rtt_ms > self.rtt_min_ms * factor
    }

    /// Get the current RTT estimate.
    pub fn rtt(&self) -> f32 {
        self.rtt_ms
    }

    /// Get the current RTT as Duration.
    pub fn rtt_duration(&self) -> Duration {
        Duration::from_secs_f32(self.rtt_ms / 1000.0)
    }

    /// Get the minimum (baseline) RTT.
    pub fn baseline(&self) -> f32 {
        self.rtt_min_ms
    }

    /// Get the baseline as Duration.
    pub fn baseline_duration(&self) -> Duration {
        Duration::from_secs_f32(self.rtt_min_ms / 1000.0)
    }

    /// Get the RTT variance.
    pub fn variance(&self) -> f32 {
        self.rtt_var_ms
    }

    /// Get the current inflation ratio.
    pub fn inflation_ratio(&self) -> f32 {
        if self.rtt_min_ms > 0.0 {
            self.rtt_ms / self.rtt_min_ms
        } else {
            1.0
        }
    }

    /// Get the number of samples.
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Check if we have enough samples for reliable estimation.
    pub fn is_reliable(&self) -> bool {
        self.samples >= 3
    }

    /// Get time since last sample.
    pub fn time_since_sample(&self) -> Option<Duration> {
        self.last_sample.map(|t| t.elapsed())
    }

    /// Check if the estimator is stale (no recent samples).
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.last_sample
            .map(|t| t.elapsed() > max_age)
            .unwrap_or(true)
    }

    /// Calculate RTO (Retransmission Timeout) using TCP-like formula.
    ///
    /// RTO = RTT + 4 * RTTVAR
    pub fn rto(&self) -> f32 {
        (self.rtt_ms + 4.0 * self.rtt_var_ms).max(1.0)
    }

    /// Get RTO as Duration.
    pub fn rto_duration(&self) -> Duration {
        Duration::from_secs_f32(self.rto() / 1000.0)
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.rtt_ms = self.default_ms;
        self.rtt_min_ms = self.default_ms;
        self.rtt_var_ms = 0.0;
        self.samples = 0;
        self.last_sample = None;
    }

    /// Reset the baseline (e.g., after network change).
    pub fn reset_baseline(&mut self) {
        self.rtt_min_ms = self.rtt_ms;
    }

    /// Get the smoothing factor.
    pub fn alpha(&self) -> f32 {
        self.alpha
    }

    /// Get the inflation factor.
    pub fn inflate_factor(&self) -> f32 {
        self.inflate_factor
    }

    /// Set the inflation factor.
    pub fn set_inflate_factor(&mut self, factor: f32) {
        self.inflate_factor = factor.max(1.0);
    }
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new(100.0) // 100ms default
    }
}

/// RTT sample for batch processing.
#[derive(Clone, Copy, Debug)]
pub struct RttSample {
    /// RTT value in milliseconds.
    pub rtt_ms: f32,
    /// When the sample was taken.
    pub timestamp: Instant,
    /// Optional peer identifier.
    pub peer_id: Option<u32>,
}

impl RttSample {
    /// Create a new RTT sample.
    pub fn new(rtt_ms: f32) -> Self {
        Self {
            rtt_ms,
            timestamp: Instant::now(),
            peer_id: None,
        }
    }

    /// Create from Duration.
    pub fn from_duration(rtt: Duration) -> Self {
        Self::new(rtt.as_secs_f32() * 1000.0)
    }

    /// Create with peer ID.
    pub fn with_peer(rtt_ms: f32, peer_id: u32) -> Self {
        Self {
            rtt_ms,
            timestamp: Instant::now(),
            peer_id: Some(peer_id),
        }
    }

    /// Get the age of this sample.
    pub fn age(&self) -> Duration {
        self.timestamp.elapsed()
    }
}

/// Per-peer RTT tracking.
#[derive(Debug, Default)]
pub struct PeerRttTracker {
    /// Estimators per peer.
    peers: std::collections::HashMap<u32, RttEstimator>,
    /// Default RTT for new peers.
    default_ms: f32,
    /// Inflation factor.
    inflate_factor: f32,
}

impl PeerRttTracker {
    /// Create a new peer RTT tracker.
    pub fn new(default_ms: f32) -> Self {
        Self {
            peers: std::collections::HashMap::new(),
            default_ms,
            inflate_factor: 2.0,
        }
    }

    /// Update RTT for a peer.
    pub fn update(&mut self, peer_id: u32, rtt_ms: f32) {
        let estimator = self.peers.entry(peer_id).or_insert_with(|| {
            RttEstimator::with_inflate_factor(self.default_ms, self.inflate_factor)
        });
        estimator.update(rtt_ms);
    }

    /// Check if any peer has inflated RTT.
    pub fn any_inflated(&self) -> bool {
        self.peers.values().any(|e| e.is_inflated())
    }

    /// Get the minimum RTT across all peers.
    pub fn min_rtt(&self) -> Option<f32> {
        self.peers.values().map(|e| e.rtt()).reduce(f32::min)
    }

    /// Get the maximum RTT across all peers.
    pub fn max_rtt(&self) -> Option<f32> {
        self.peers.values().map(|e| e.rtt()).reduce(f32::max)
    }

    /// Get the median RTT across all peers.
    pub fn median_rtt(&self) -> Option<f32> {
        if self.peers.is_empty() {
            return None;
        }

        let mut rtts: Vec<f32> = self.peers.values().map(|e| e.rtt()).collect();
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let mid = rtts.len() / 2;
        if rtts.len().is_multiple_of(2) {
            Some((rtts[mid - 1] + rtts[mid]) / 2.0)
        } else {
            Some(rtts[mid])
        }
    }

    /// Get the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Remove stale peers.
    pub fn prune_stale(&mut self, max_age: Duration) {
        self.peers.retain(|_, e| !e.is_stale(max_age));
    }

    /// Get estimator for a specific peer.
    pub fn get(&self, peer_id: u32) -> Option<&RttEstimator> {
        self.peers.get(&peer_id)
    }

    /// Clear all peer data.
    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new() {
        let est = RttEstimator::new(100.0);
        assert_eq!(est.rtt(), 100.0);
        assert_eq!(est.baseline(), 100.0);
        assert_eq!(est.samples(), 0);
    }

    #[test]
    fn test_default() {
        let est = RttEstimator::default();
        assert_eq!(est.rtt(), 100.0);
    }

    #[test]
    fn test_first_sample() {
        let mut est = RttEstimator::new(100.0);
        est.update(50.0);

        assert_eq!(est.rtt(), 50.0);
        assert_eq!(est.baseline(), 50.0);
        assert_eq!(est.samples(), 1);
    }

    #[test]
    fn test_ewma_smoothing() {
        let mut est = RttEstimator::new(100.0);

        est.update(100.0);
        est.update(200.0);

        // EWMA: 100 + 0.125 * (200 - 100) = 112.5
        assert!((est.rtt() - 112.5).abs() < 0.1);
    }

    #[test]
    fn test_baseline_tracking() {
        let mut est = RttEstimator::new(100.0);

        est.update(80.0);
        est.update(90.0);
        est.update(70.0);
        est.update(100.0);

        assert_eq!(est.baseline(), 70.0); // Minimum
    }

    #[test]
    fn test_is_inflated() {
        // Use high alpha for faster convergence in test
        let mut est = RttEstimator::with_alpha(100.0, 1.0, 0.25);
        est.set_inflate_factor(2.0);

        est.update(50.0); // Baseline = 50
        assert!(!est.is_inflated());

        // With alpha=1.0, update sets rtt directly to 110
        est.update(110.0);
        assert!(est.is_inflated()); // 110 > 50 * 2 = 100
    }

    #[test]
    fn test_is_inflated_by() {
        // Use high alpha for instant convergence
        let mut est = RttEstimator::with_alpha(100.0, 1.0, 0.25);

        est.update(50.0); // Baseline = 50, rtt = 50
        est.update(75.0); // rtt = 75 immediately with alpha=1.0

        assert!(!est.is_inflated_by(2.0)); // 75 < 50 * 2 = 100
        assert!(est.is_inflated_by(1.4)); // 75 > 50 * 1.4 = 70
    }

    #[test]
    fn test_inflation_ratio() {
        let mut est = RttEstimator::new(100.0);

        est.update(50.0);
        assert!((est.inflation_ratio() - 1.0).abs() < 0.01);

        est.update(100.0);
        // After EWMA, rtt = 50 + 0.125 * 50 = 56.25
        // ratio = 56.25 / 50 = 1.125
        assert!(est.inflation_ratio() > 1.0);
    }

    #[test]
    fn test_variance() {
        let mut est = RttEstimator::new(100.0);

        est.update(100.0);
        est.update(150.0);
        est.update(50.0);

        // Variance should be non-zero after varying samples
        assert!(est.variance() > 0.0);
    }

    #[test]
    fn test_rto() {
        let mut est = RttEstimator::new(100.0);

        est.update(100.0);
        est.update(120.0);

        // RTO = RTT + 4 * VAR
        let rto = est.rto();
        assert!(rto >= est.rtt());
    }

    #[test]
    fn test_duration_methods() {
        let mut est = RttEstimator::new(100.0);
        est.update(50.0);

        let rtt = est.rtt_duration();
        assert!((rtt.as_millis() as f32 - 50.0).abs() < 1.0);

        let baseline = est.baseline_duration();
        assert!((baseline.as_millis() as f32 - 50.0).abs() < 1.0);
    }

    #[test]
    fn test_update_duration() {
        let mut est = RttEstimator::new(100.0);
        est.update_duration(Duration::from_millis(50));

        assert_eq!(est.rtt(), 50.0);
    }

    #[test]
    fn test_is_reliable() {
        let mut est = RttEstimator::new(100.0);

        assert!(!est.is_reliable());

        est.update(100.0);
        est.update(100.0);
        assert!(!est.is_reliable());

        est.update(100.0);
        assert!(est.is_reliable());
    }

    #[test]
    fn test_is_stale() {
        let mut est = RttEstimator::new(100.0);

        assert!(est.is_stale(Duration::from_secs(1)));

        est.update(100.0);
        assert!(!est.is_stale(Duration::from_secs(1)));

        thread::sleep(Duration::from_millis(20));
        assert!(est.is_stale(Duration::from_millis(10)));
    }

    #[test]
    fn test_reset() {
        let mut est = RttEstimator::new(100.0);

        est.update(50.0);
        est.update(60.0);

        est.reset();

        assert_eq!(est.rtt(), 100.0);
        assert_eq!(est.baseline(), 100.0);
        assert_eq!(est.samples(), 0);
    }

    #[test]
    fn test_reset_baseline() {
        let mut est = RttEstimator::new(100.0);

        est.update(50.0);
        est.update(80.0);

        // Baseline is 50
        assert_eq!(est.baseline(), 50.0);

        est.reset_baseline();

        // Baseline now equals current RTT
        assert!((est.baseline() - est.rtt()).abs() < 0.01);
    }

    #[test]
    fn test_rtt_sample() {
        let sample = RttSample::new(50.0);
        assert_eq!(sample.rtt_ms, 50.0);
        assert!(sample.peer_id.is_none());

        let sample2 = RttSample::from_duration(Duration::from_millis(100));
        assert!((sample2.rtt_ms - 100.0).abs() < 0.1);

        let sample3 = RttSample::with_peer(75.0, 42);
        assert_eq!(sample3.peer_id, Some(42));
    }

    #[test]
    fn test_peer_rtt_tracker() {
        let mut tracker = PeerRttTracker::new(100.0);

        tracker.update(1, 50.0);
        tracker.update(2, 80.0);
        tracker.update(3, 60.0);

        assert_eq!(tracker.peer_count(), 3);
        assert!((tracker.min_rtt().unwrap() - 50.0).abs() < 0.1);
        assert!((tracker.max_rtt().unwrap() - 80.0).abs() < 0.1);
        assert!((tracker.median_rtt().unwrap() - 60.0).abs() < 0.1);
    }

    #[test]
    fn test_peer_rtt_tracker_any_inflated() {
        let mut tracker = PeerRttTracker::new(100.0);

        tracker.update(1, 50.0);
        tracker.update(2, 50.0);
        assert!(!tracker.any_inflated());

        // Inflate peer 1: need many samples to overcome EWMA smoothing
        // Default inflate_factor is 2.0, so need rtt > 50 * 2 = 100
        // With default alpha=0.125, we need many high samples
        for _ in 0..20 {
            tracker.update(1, 200.0);
        }
        assert!(tracker.any_inflated());
    }

    #[test]
    fn test_peer_rtt_tracker_prune() {
        let mut tracker = PeerRttTracker::new(100.0);

        tracker.update(1, 50.0);
        tracker.update(2, 60.0);

        thread::sleep(Duration::from_millis(20));

        tracker.prune_stale(Duration::from_millis(10));

        assert_eq!(tracker.peer_count(), 0);
    }

    #[test]
    fn test_peer_rtt_tracker_get() {
        let mut tracker = PeerRttTracker::new(100.0);

        tracker.update(42, 75.0);

        let est = tracker.get(42).expect("should exist");
        assert_eq!(est.rtt(), 75.0);

        assert!(tracker.get(99).is_none());
    }

    #[test]
    fn test_with_alpha() {
        let est = RttEstimator::with_alpha(100.0, 0.25, 0.5);
        assert_eq!(est.alpha(), 0.25);
    }
}

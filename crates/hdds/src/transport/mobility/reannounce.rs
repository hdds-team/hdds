// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reannounce controller for SPDP burst on IP change.
//!
//! Manages the burst schedule for reannouncing participant presence
//! after an IP address change.

use std::time::{Duration, Instant};

/// Configuration for reannounce burst.
#[derive(Clone, Debug)]
pub struct ReannounceBurst {
    /// Delays between announcements (from burst start).
    pub delays: Vec<Duration>,

    /// Jitter percentage (0-50).
    pub jitter_percent: u8,

    /// Minimum delay between bursts.
    pub min_burst_interval: Duration,
}

impl Default for ReannounceBurst {
    fn default() -> Self {
        Self {
            delays: vec![
                Duration::ZERO,
                Duration::from_millis(100),
                Duration::from_millis(300),
                Duration::from_secs(1),
                Duration::from_secs(3),
            ],
            jitter_percent: 20,
            min_burst_interval: Duration::from_secs(1),
        }
    }
}

impl ReannounceBurst {
    /// Create a fast burst for aggressive recovery.
    pub fn fast() -> Self {
        Self {
            delays: vec![
                Duration::ZERO,
                Duration::from_millis(50),
                Duration::from_millis(150),
                Duration::from_millis(500),
            ],
            jitter_percent: 15,
            min_burst_interval: Duration::from_millis(500),
        }
    }

    /// Create a slow burst for stable networks.
    pub fn slow() -> Self {
        Self {
            delays: vec![
                Duration::ZERO,
                Duration::from_millis(500),
                Duration::from_secs(2),
                Duration::from_secs(5),
            ],
            jitter_percent: 25,
            min_burst_interval: Duration::from_secs(5),
        }
    }

    /// Get the number of announcements in a burst.
    pub fn count(&self) -> usize {
        self.delays.len()
    }

    /// Get total burst duration.
    pub fn total_duration(&self) -> Duration {
        self.delays.last().copied().unwrap_or(Duration::ZERO)
    }

    /// Apply jitter to a duration.
    pub fn apply_jitter(&self, duration: Duration) -> Duration {
        if self.jitter_percent == 0 || duration.is_zero() {
            return duration;
        }

        let jitter_range = duration.as_millis() as u64 * self.jitter_percent as u64 / 100;
        if jitter_range == 0 {
            return duration;
        }

        // Simple pseudo-random jitter based on current time
        let now_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let jitter_ms = (now_nanos % (jitter_range * 2)) as i64 - jitter_range as i64;
        let adjusted_ms = duration.as_millis() as i64 + jitter_ms;

        Duration::from_millis(adjusted_ms.max(0) as u64)
    }
}

/// State of a reannounce burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BurstState {
    /// No burst in progress.
    Idle,

    /// Burst in progress.
    Active,

    /// Burst completed.
    Completed,
}

/// Controller for managing reannounce bursts.
pub struct ReannounceController {
    /// Burst configuration.
    config: ReannounceBurst,

    /// Current burst state.
    state: BurstState,

    /// When the current burst started.
    burst_start: Option<Instant>,

    /// Index of next announcement in burst.
    next_index: usize,

    /// When last burst completed.
    last_burst_end: Option<Instant>,

    /// Total bursts triggered.
    total_bursts: u64,

    /// Total announcements sent.
    total_announces: u64,
}

impl ReannounceController {
    /// Create a new reannounce controller.
    pub fn new(config: ReannounceBurst) -> Self {
        Self {
            config,
            state: BurstState::Idle,
            burst_start: None,
            next_index: 0,
            last_burst_end: None,
            total_bursts: 0,
            total_announces: 0,
        }
    }

    /// Start a new burst.
    ///
    /// Returns true if burst was started, false if rate-limited.
    pub fn start_burst(&mut self) -> bool {
        // Rate limit
        if let Some(last_end) = self.last_burst_end {
            if last_end.elapsed() < self.config.min_burst_interval {
                return false;
            }
        }

        self.state = BurstState::Active;
        self.burst_start = Some(Instant::now());
        self.next_index = 0;
        self.total_bursts += 1;

        true
    }

    /// Check if an announcement should be sent now.
    ///
    /// Returns true if it's time for the next announcement.
    pub fn should_announce(&self) -> bool {
        if self.state != BurstState::Active {
            return false;
        }

        let start = match self.burst_start {
            Some(s) => s,
            None => return false,
        };

        if self.next_index >= self.config.delays.len() {
            return false;
        }

        let target_delay = self.config.delays[self.next_index];
        let target_with_jitter = self.config.apply_jitter(target_delay);

        start.elapsed() >= target_with_jitter
    }

    /// Mark an announcement as sent and advance to next.
    ///
    /// Returns the announcement index that was sent.
    pub fn mark_announced(&mut self) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        self.total_announces += 1;

        // Check if burst is complete
        if self.next_index >= self.config.delays.len() {
            self.state = BurstState::Completed;
            self.last_burst_end = Some(Instant::now());
        }

        index
    }

    /// Poll for next announcement.
    ///
    /// Returns Some(index) if an announcement should be sent now.
    pub fn poll(&mut self) -> Option<usize> {
        if self.should_announce() {
            Some(self.mark_announced())
        } else {
            None
        }
    }

    /// Get time until next announcement.
    ///
    /// Returns None if burst is not active or complete.
    pub fn time_until_next(&self) -> Option<Duration> {
        if self.state != BurstState::Active {
            return None;
        }

        let start = self.burst_start?;

        if self.next_index >= self.config.delays.len() {
            return None;
        }

        let target_delay = self.config.delays[self.next_index];
        let elapsed = start.elapsed();

        Some(target_delay.saturating_sub(elapsed))
    }

    /// Cancel current burst.
    pub fn cancel(&mut self) {
        if self.state == BurstState::Active {
            self.state = BurstState::Idle;
            self.burst_start = None;
            self.next_index = 0;
        }
    }

    /// Reset to idle state after burst completion.
    pub fn reset(&mut self) {
        self.state = BurstState::Idle;
        self.burst_start = None;
        self.next_index = 0;
    }

    /// Get current state.
    pub fn state(&self) -> BurstState {
        self.state
    }

    /// Check if burst is active.
    pub fn is_active(&self) -> bool {
        self.state == BurstState::Active
    }

    /// Check if burst is complete.
    pub fn is_complete(&self) -> bool {
        self.state == BurstState::Completed
    }

    /// Get progress through current burst (0.0 - 1.0).
    pub fn progress(&self) -> f32 {
        if self.config.delays.is_empty() {
            return 1.0;
        }

        self.next_index as f32 / self.config.delays.len() as f32
    }

    /// Get remaining announcements in burst.
    pub fn remaining(&self) -> usize {
        if self.state != BurstState::Active {
            return 0;
        }

        self.config.delays.len().saturating_sub(self.next_index)
    }

    /// Get total bursts triggered.
    pub fn total_bursts(&self) -> u64 {
        self.total_bursts
    }

    /// Get total announcements sent.
    pub fn total_announces(&self) -> u64 {
        self.total_announces
    }

    /// Get statistics.
    pub fn stats(&self) -> ReannounceStats {
        ReannounceStats {
            state: self.state,
            total_bursts: self.total_bursts,
            total_announces: self.total_announces,
            current_progress: self.progress(),
            remaining_in_burst: self.remaining(),
        }
    }

    /// Get a reference to the config.
    pub fn config(&self) -> &ReannounceBurst {
        &self.config
    }

    /// Update config (takes effect on next burst).
    pub fn set_config(&mut self, config: ReannounceBurst) {
        self.config = config;
    }
}

impl Default for ReannounceController {
    fn default() -> Self {
        Self::new(ReannounceBurst::default())
    }
}

/// Statistics for reannounce controller.
#[derive(Clone, Copy, Debug)]
pub struct ReannounceStats {
    /// Current state.
    pub state: BurstState,

    /// Total bursts triggered.
    pub total_bursts: u64,

    /// Total announcements sent.
    pub total_announces: u64,

    /// Progress through current burst.
    pub current_progress: f32,

    /// Remaining announcements in current burst.
    pub remaining_in_burst: usize,
}

impl ReannounceStats {
    /// Average announcements per burst.
    pub fn avg_announces_per_burst(&self) -> f64 {
        if self.total_bursts == 0 {
            0.0
        } else {
            self.total_announces as f64 / self.total_bursts as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reannounce_burst_default() {
        let burst = ReannounceBurst::default();
        assert_eq!(burst.count(), 5);
        assert_eq!(burst.jitter_percent, 20);
        assert_eq!(burst.total_duration(), Duration::from_secs(3));
    }

    #[test]
    fn test_reannounce_burst_fast() {
        let burst = ReannounceBurst::fast();
        assert_eq!(burst.count(), 4);
        assert!(burst.total_duration() < Duration::from_secs(1));
    }

    #[test]
    fn test_reannounce_burst_slow() {
        let burst = ReannounceBurst::slow();
        assert_eq!(burst.count(), 4);
        assert!(burst.total_duration() >= Duration::from_secs(5));
    }

    #[test]
    fn test_reannounce_burst_apply_jitter_zero() {
        let burst = ReannounceBurst {
            jitter_percent: 0,
            ..Default::default()
        };

        let duration = Duration::from_millis(100);
        assert_eq!(burst.apply_jitter(duration), duration);
    }

    #[test]
    fn test_reannounce_burst_apply_jitter_zero_duration() {
        let burst = ReannounceBurst::default();
        assert_eq!(burst.apply_jitter(Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn test_reannounce_burst_apply_jitter() {
        let burst = ReannounceBurst {
            jitter_percent: 20,
            ..Default::default()
        };

        let duration = Duration::from_millis(1000);
        let jittered = burst.apply_jitter(duration);

        // Should be within +/- 20%
        assert!(jittered >= Duration::from_millis(800));
        assert!(jittered <= Duration::from_millis(1200));
    }

    #[test]
    fn test_reannounce_controller_new() {
        let ctrl = ReannounceController::default();
        assert_eq!(ctrl.state(), BurstState::Idle);
        assert!(!ctrl.is_active());
        assert_eq!(ctrl.total_bursts(), 0);
    }

    #[test]
    fn test_reannounce_controller_start_burst() {
        let mut ctrl = ReannounceController::default();

        assert!(ctrl.start_burst());
        assert_eq!(ctrl.state(), BurstState::Active);
        assert!(ctrl.is_active());
        assert_eq!(ctrl.total_bursts(), 1);
    }

    #[test]
    fn test_reannounce_controller_rate_limit() {
        let config = ReannounceBurst {
            min_burst_interval: Duration::from_secs(10),
            ..Default::default()
        };
        let mut ctrl = ReannounceController::new(config);

        // First burst starts
        assert!(ctrl.start_burst());

        // Complete the burst
        while ctrl.state() == BurstState::Active {
            ctrl.mark_announced();
        }

        // Second burst should be rate-limited
        assert!(!ctrl.start_burst());
    }

    #[test]
    fn test_reannounce_controller_should_announce_first() {
        let config = ReannounceBurst {
            delays: vec![Duration::ZERO, Duration::from_millis(100)],
            jitter_percent: 0,
            min_burst_interval: Duration::ZERO,
        };
        let mut ctrl = ReannounceController::new(config);

        // Not active yet
        assert!(!ctrl.should_announce());

        // Start burst
        ctrl.start_burst();

        // First announcement should be immediate (delay = 0)
        assert!(ctrl.should_announce());
    }

    #[test]
    fn test_reannounce_controller_mark_announced() {
        let config = ReannounceBurst {
            delays: vec![Duration::ZERO, Duration::from_millis(100)],
            jitter_percent: 0,
            min_burst_interval: Duration::ZERO,
        };
        let mut ctrl = ReannounceController::new(config);
        ctrl.start_burst();

        assert_eq!(ctrl.mark_announced(), 0);
        assert_eq!(ctrl.total_announces(), 1);
        assert_eq!(ctrl.remaining(), 1);

        assert_eq!(ctrl.mark_announced(), 1);
        assert_eq!(ctrl.total_announces(), 2);
        assert_eq!(ctrl.state(), BurstState::Completed);
    }

    #[test]
    fn test_reannounce_controller_poll() {
        let config = ReannounceBurst {
            delays: vec![Duration::ZERO],
            jitter_percent: 0,
            min_burst_interval: Duration::ZERO,
        };
        let mut ctrl = ReannounceController::new(config);
        ctrl.start_burst();

        // Should return the index
        assert_eq!(ctrl.poll(), Some(0));

        // No more announcements
        assert_eq!(ctrl.poll(), None);
        assert!(ctrl.is_complete());
    }

    #[test]
    fn test_reannounce_controller_cancel() {
        let mut ctrl = ReannounceController::default();
        ctrl.start_burst();
        assert!(ctrl.is_active());

        ctrl.cancel();
        assert!(!ctrl.is_active());
        assert_eq!(ctrl.state(), BurstState::Idle);
    }

    #[test]
    fn test_reannounce_controller_reset() {
        let config = ReannounceBurst {
            delays: vec![Duration::ZERO],
            jitter_percent: 0,
            min_burst_interval: Duration::ZERO,
        };
        let mut ctrl = ReannounceController::new(config);
        ctrl.start_burst();
        ctrl.mark_announced();
        assert!(ctrl.is_complete());

        ctrl.reset();
        assert_eq!(ctrl.state(), BurstState::Idle);
    }

    #[test]
    fn test_reannounce_controller_progress() {
        let config = ReannounceBurst {
            delays: vec![Duration::ZERO, Duration::from_millis(100)],
            jitter_percent: 0,
            min_burst_interval: Duration::ZERO,
        };
        let mut ctrl = ReannounceController::new(config);
        ctrl.start_burst();

        assert!((ctrl.progress() - 0.0).abs() < 0.001);

        ctrl.mark_announced();
        assert!((ctrl.progress() - 0.5).abs() < 0.001);

        ctrl.mark_announced();
        assert!((ctrl.progress() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_reannounce_controller_time_until_next() {
        let config = ReannounceBurst {
            delays: vec![Duration::ZERO, Duration::from_millis(100)],
            jitter_percent: 0,
            min_burst_interval: Duration::ZERO,
        };
        let mut ctrl = ReannounceController::new(config);

        // Not active
        assert!(ctrl.time_until_next().is_none());

        ctrl.start_burst();

        // First is immediate
        let time = ctrl.time_until_next();
        assert!(time.is_some());
        assert!(time.expect("should have time") <= Duration::from_millis(1));
    }

    #[test]
    fn test_reannounce_controller_stats() {
        let mut ctrl = ReannounceController::default();
        ctrl.start_burst();

        let stats = ctrl.stats();
        assert_eq!(stats.state, BurstState::Active);
        assert_eq!(stats.total_bursts, 1);
        assert_eq!(stats.total_announces, 0);
    }

    #[test]
    fn test_reannounce_stats_avg_announces() {
        let stats = ReannounceStats {
            state: BurstState::Idle,
            total_bursts: 2,
            total_announces: 10,
            current_progress: 0.0,
            remaining_in_burst: 0,
        };

        assert!((stats.avg_announces_per_burst() - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_reannounce_stats_avg_announces_zero() {
        let stats = ReannounceStats {
            state: BurstState::Idle,
            total_bursts: 0,
            total_announces: 0,
            current_progress: 0.0,
            remaining_in_burst: 0,
        };

        assert!((stats.avg_announces_per_burst() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_reannounce_controller_set_config() {
        let mut ctrl = ReannounceController::default();
        let new_config = ReannounceBurst::fast();

        ctrl.set_config(new_config.clone());
        assert_eq!(ctrl.config().count(), new_config.count());
    }

    #[test]
    fn test_burst_state_variants() {
        assert_eq!(BurstState::Idle, BurstState::Idle);
        assert_ne!(BurstState::Idle, BurstState::Active);
        assert_ne!(BurstState::Active, BurstState::Completed);
    }
}

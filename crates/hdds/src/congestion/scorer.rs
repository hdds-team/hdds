// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Congestion scorer with EWMA and state machine.
//!
//! The scorer aggregates congestion signals (EAGAIN, RTT inflation, NACK rate)
//! into a single score using EWMA, and manages state transitions with hysteresis.

use std::time::{Duration, Instant};

use super::config::CongestionConfig;

/// Congestion state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScorerState {
    /// Normal operation, rate can increase.
    #[default]
    Stable,
    /// Congestion detected, rate should decrease.
    Congested,
}

/// Action to take based on scoring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionAction {
    /// No action needed.
    None,
    /// Increase rate (additive).
    Increase,
    /// Decrease rate softly (RTT/NACK triggered).
    DecreaseSoft,
    /// Decrease rate hard (EAGAIN triggered).
    DecreaseHard,
}

/// Pending signals accumulated between ticks.
#[derive(Clone, Debug, Default)]
pub struct PendingSignals {
    /// Number of EAGAIN/ENOBUFS events.
    pub eagain_count: u32,
    /// Whether RTT inflation was detected.
    pub rtt_inflated: bool,
    /// Number of NACK events received.
    pub nack_count: u32,
    /// Number of packet losses detected.
    pub loss_count: u32,
}

impl PendingSignals {
    /// Create empty signals.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any signals are pending.
    pub fn has_any(&self) -> bool {
        self.eagain_count > 0 || self.rtt_inflated || self.nack_count > 0 || self.loss_count > 0
    }

    /// Reset all signals.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Congestion scorer using EWMA with hysteresis.
#[derive(Debug)]
pub struct CongestionScorer {
    /// Current score (0.0 - 100.0).
    score: f32,

    /// Current state.
    state: ScorerState,

    /// Last tick time.
    last_tick: Instant,

    /// Cooldown end time (no new decrease until then).
    cooldown_until: Option<Instant>,

    /// Stable period start (for increase eligibility).
    stable_since: Option<Instant>,

    /// Pending signals since last tick.
    pending: PendingSignals,

    /// Configuration.
    config: ScorerConfig,

    /// Metrics.
    metrics: ScorerMetrics,
}

/// Scorer configuration (subset of CongestionConfig).
#[derive(Clone, Debug)]
pub struct ScorerConfig {
    /// Tick interval.
    pub tick_interval: Duration,
    /// EWMA decay factor.
    pub decay: f32,
    /// Threshold to trigger decrease.
    pub decrease_threshold: f32,
    /// Threshold to allow increase.
    pub increase_threshold: f32,
    /// Hysteresis band.
    pub hysteresis: f32,
    /// Cooldown duration after decrease.
    pub cooldown: Duration,
    /// Stable window before increase allowed.
    pub stable_window: Duration,
    /// EAGAIN impulse value.
    pub eagain_impulse: f32,
    /// RTT inflation impulse.
    pub rtt_impulse: f32,
    /// NACK impulse.
    pub nack_impulse: f32,
    /// NACK rate threshold.
    pub nack_threshold: u32,
    /// Whether EAGAIN triggers hard decrease.
    pub eagain_is_hard: bool,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_millis(100),
            decay: 0.90,
            decrease_threshold: 60.0,
            increase_threshold: 20.0,
            hysteresis: 10.0,
            cooldown: Duration::from_millis(300),
            stable_window: Duration::from_millis(1000),
            eagain_impulse: 60.0,
            rtt_impulse: 20.0,
            nack_impulse: 20.0,
            nack_threshold: 10,
            eagain_is_hard: true,
        }
    }
}

impl From<&CongestionConfig> for ScorerConfig {
    fn from(cfg: &CongestionConfig) -> Self {
        Self {
            tick_interval: Duration::from_millis(cfg.score_tick_ms as u64),
            decay: cfg.score_decay,
            decrease_threshold: cfg.decrease_threshold as f32,
            increase_threshold: cfg.increase_threshold as f32,
            hysteresis: cfg.hysteresis_band as f32,
            cooldown: Duration::from_millis(cfg.cooldown_ms as u64),
            stable_window: Duration::from_millis(cfg.stable_window_ms as u64),
            eagain_impulse: cfg.eagain_impulse as f32,
            rtt_impulse: cfg.rtt_impulse as f32,
            nack_impulse: cfg.nack_impulse as f32,
            nack_threshold: cfg.nack_rate_threshold,
            eagain_is_hard: cfg.eagain_is_hard,
        }
    }
}

/// Scorer metrics.
#[derive(Clone, Debug, Default)]
pub struct ScorerMetrics {
    /// Total ticks processed.
    pub ticks: u64,
    /// Times entered congested state.
    pub congestion_events: u64,
    /// Times returned to stable state.
    pub recovery_events: u64,
    /// Total EAGAIN signals processed.
    pub eagain_signals: u64,
    /// Total RTT inflation signals.
    pub rtt_signals: u64,
    /// Total NACK signals.
    pub nack_signals: u64,
    /// Peak score observed.
    pub peak_score: f32,
    /// Time spent in congested state.
    pub congested_duration: Duration,
}

impl CongestionScorer {
    /// Create a new scorer with default config.
    pub fn new() -> Self {
        Self::with_config(ScorerConfig::default())
    }

    /// Create a scorer from CongestionConfig.
    pub fn from_config(config: &CongestionConfig) -> Self {
        Self::with_config(ScorerConfig::from(config))
    }

    /// Create a scorer with specific config.
    pub fn with_config(config: ScorerConfig) -> Self {
        Self {
            score: 0.0,
            state: ScorerState::Stable,
            last_tick: Instant::now(),
            cooldown_until: None,
            stable_since: Some(Instant::now()),
            pending: PendingSignals::new(),
            config,
            metrics: ScorerMetrics::default(),
        }
    }

    /// Record an EAGAIN/ENOBUFS event.
    pub fn on_eagain(&mut self) {
        self.pending.eagain_count += 1;
        self.metrics.eagain_signals += 1;
    }

    /// Record RTT inflation detection.
    pub fn on_rtt_inflated(&mut self) {
        self.pending.rtt_inflated = true;
        self.metrics.rtt_signals += 1;
    }

    /// Record a NACK event.
    pub fn on_nack(&mut self) {
        self.pending.nack_count += 1;
        self.metrics.nack_signals += 1;
    }

    /// Record packet loss.
    pub fn on_loss(&mut self) {
        self.pending.loss_count += 1;
    }

    /// Process a tick and return the action to take.
    ///
    /// Should be called at regular intervals (e.g., every 100ms).
    pub fn tick(&mut self) -> CongestionAction {
        let now = Instant::now();
        self.last_tick = now;
        self.metrics.ticks += 1;

        // Calculate impulse from pending signals
        let impulse = self.calculate_impulse();
        let had_eagain = self.pending.eagain_count > 0;

        // EWMA update
        self.score = (self.score * self.config.decay + impulse).clamp(0.0, 100.0);

        // Track peak
        if self.score > self.metrics.peak_score {
            self.metrics.peak_score = self.score;
        }

        // Reset pending signals
        self.pending.reset();

        // Evaluate state and action
        self.evaluate_state(now, had_eagain)
    }

    /// Force a tick if enough time has passed.
    ///
    /// Returns `Some(action)` if a tick was performed.
    pub fn maybe_tick(&mut self) -> Option<CongestionAction> {
        let elapsed = self.last_tick.elapsed();
        if elapsed >= self.config.tick_interval {
            Some(self.tick())
        } else {
            None
        }
    }

    /// Calculate impulse from pending signals.
    fn calculate_impulse(&self) -> f32 {
        let mut impulse = 0.0;

        if self.pending.eagain_count > 0 {
            impulse += self.config.eagain_impulse;
        }

        if self.pending.rtt_inflated {
            impulse += self.config.rtt_impulse;
        }

        if self.pending.nack_count > self.config.nack_threshold {
            impulse += self.config.nack_impulse;
        }

        // Loss contributes proportionally
        if self.pending.loss_count > 0 {
            impulse += (self.pending.loss_count as f32 * 5.0).min(30.0);
        }

        impulse
    }

    /// Evaluate state transitions and return action.
    fn evaluate_state(&mut self, now: Instant, had_eagain: bool) -> CongestionAction {
        let in_cooldown = self.cooldown_until.map(|t| now < t).unwrap_or(false);

        match self.state {
            ScorerState::Stable => {
                // Check for transition to congested
                if self.score >= self.config.decrease_threshold {
                    self.state = ScorerState::Congested;
                    self.stable_since = None;
                    self.cooldown_until = Some(now + self.config.cooldown);
                    self.metrics.congestion_events += 1;

                    if self.config.eagain_is_hard && had_eagain {
                        CongestionAction::DecreaseHard
                    } else {
                        CongestionAction::DecreaseSoft
                    }
                } else if !in_cooldown && self.can_increase(now) {
                    CongestionAction::Increase
                } else {
                    CongestionAction::None
                }
            }
            ScorerState::Congested => {
                // Track time in congested state
                self.metrics.congested_duration += self.config.tick_interval;

                // Check for recovery (with hysteresis)
                let recovery_threshold = self.config.increase_threshold + self.config.hysteresis;

                if !in_cooldown && self.score <= recovery_threshold {
                    self.state = ScorerState::Stable;
                    self.stable_since = Some(now);
                    self.metrics.recovery_events += 1;
                    CongestionAction::None
                } else {
                    CongestionAction::None
                }
            }
        }
    }

    /// Check if we've been stable long enough to increase.
    fn can_increase(&self, now: Instant) -> bool {
        if let Some(stable_start) = self.stable_since {
            now.duration_since(stable_start) >= self.config.stable_window
        } else {
            false
        }
    }

    /// Get the current score.
    pub fn score(&self) -> f32 {
        self.score
    }

    /// Get the current state.
    pub fn state(&self) -> ScorerState {
        self.state
    }

    /// Check if currently in cooldown.
    pub fn in_cooldown(&self) -> bool {
        self.cooldown_until
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }

    /// Get time remaining in cooldown.
    pub fn cooldown_remaining(&self) -> Duration {
        self.cooldown_until
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or(Duration::ZERO)
    }

    /// Get the metrics.
    pub fn metrics(&self) -> &ScorerMetrics {
        &self.metrics
    }

    /// Reset the scorer to initial state.
    pub fn reset(&mut self) {
        self.score = 0.0;
        self.state = ScorerState::Stable;
        self.cooldown_until = None;
        self.stable_since = Some(Instant::now());
        self.pending.reset();
    }

    /// Get the config.
    pub fn config(&self) -> &ScorerConfig {
        &self.config
    }
}

impl Default for CongestionScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn make_config() -> ScorerConfig {
        ScorerConfig {
            tick_interval: Duration::from_millis(10),
            decay: 0.5, // Fast decay for testing
            decrease_threshold: 50.0,
            increase_threshold: 10.0,
            hysteresis: 5.0,
            cooldown: Duration::from_millis(50),
            stable_window: Duration::from_millis(30),
            eagain_impulse: 60.0,
            rtt_impulse: 30.0,
            nack_impulse: 20.0,
            nack_threshold: 5,
            eagain_is_hard: true,
        }
    }

    #[test]
    fn test_new() {
        let scorer = CongestionScorer::new();
        assert_eq!(scorer.state(), ScorerState::Stable);
        assert_eq!(scorer.score(), 0.0);
    }

    #[test]
    fn test_pending_signals() {
        let mut signals = PendingSignals::new();
        assert!(!signals.has_any());

        signals.eagain_count = 1;
        assert!(signals.has_any());

        signals.reset();
        assert!(!signals.has_any());
    }

    #[test]
    fn test_on_eagain() {
        let mut scorer = CongestionScorer::with_config(make_config());
        scorer.on_eagain();
        assert_eq!(scorer.pending.eagain_count, 1);
        assert_eq!(scorer.metrics.eagain_signals, 1);
    }

    #[test]
    fn test_on_rtt_inflated() {
        let mut scorer = CongestionScorer::with_config(make_config());
        scorer.on_rtt_inflated();
        assert!(scorer.pending.rtt_inflated);
        assert_eq!(scorer.metrics.rtt_signals, 1);
    }

    #[test]
    fn test_on_nack() {
        let mut scorer = CongestionScorer::with_config(make_config());
        scorer.on_nack();
        assert_eq!(scorer.pending.nack_count, 1);
        assert_eq!(scorer.metrics.nack_signals, 1);
    }

    #[test]
    fn test_tick_no_signals() {
        let mut scorer = CongestionScorer::with_config(make_config());
        let action = scorer.tick();

        // No signals, should stay stable, no action (not stable long enough)
        assert_eq!(action, CongestionAction::None);
        assert_eq!(scorer.state(), ScorerState::Stable);
        assert_eq!(scorer.score(), 0.0);
    }

    #[test]
    fn test_tick_eagain_triggers_congestion() {
        let mut scorer = CongestionScorer::with_config(make_config());

        scorer.on_eagain();
        let action = scorer.tick();

        // EAGAIN impulse (60) > decrease_threshold (50)
        assert_eq!(action, CongestionAction::DecreaseHard);
        assert_eq!(scorer.state(), ScorerState::Congested);
        assert!(scorer.score() >= 30.0); // 60 * 0.5 decay = 30
    }

    #[test]
    fn test_tick_rtt_triggers_soft_congestion() {
        let mut config = make_config();
        config.decrease_threshold = 25.0;
        let mut scorer = CongestionScorer::with_config(config);

        scorer.on_rtt_inflated();
        let action = scorer.tick();

        // RTT impulse (30) > threshold (25), no EAGAIN
        assert_eq!(action, CongestionAction::DecreaseSoft);
        assert_eq!(scorer.state(), ScorerState::Congested);
    }

    #[test]
    fn test_ewma_decay() {
        let mut scorer = CongestionScorer::with_config(make_config());

        // First tick with EAGAIN
        scorer.on_eagain();
        scorer.tick();
        let score_after_first = scorer.score();

        // Second tick, no signals - should decay
        scorer.tick();
        let score_after_second = scorer.score();

        assert!(
            score_after_second < score_after_first,
            "score should decay: {} < {}",
            score_after_second,
            score_after_first
        );
    }

    #[test]
    fn test_cooldown() {
        let mut scorer = CongestionScorer::with_config(make_config());

        // Trigger congestion
        scorer.on_eagain();
        scorer.tick();

        assert!(scorer.in_cooldown());
        assert!(scorer.cooldown_remaining() > Duration::ZERO);

        // Wait for cooldown
        thread::sleep(Duration::from_millis(60));

        assert!(!scorer.in_cooldown());
    }

    #[test]
    fn test_recovery_with_hysteresis() {
        let mut config = make_config();
        config.cooldown = Duration::from_millis(10);
        let mut scorer = CongestionScorer::with_config(config);

        // Trigger congestion
        scorer.on_eagain();
        scorer.tick();
        assert_eq!(scorer.state(), ScorerState::Congested);

        // Wait for cooldown
        thread::sleep(Duration::from_millis(15));

        // Decay until below recovery threshold (increase_threshold + hysteresis = 15)
        for _ in 0..10 {
            scorer.tick();
        }

        // Should recover to stable
        assert_eq!(scorer.state(), ScorerState::Stable);
        assert_eq!(scorer.metrics.recovery_events, 1);
    }

    #[test]
    fn test_increase_after_stable_window() {
        let mut config = make_config();
        config.stable_window = Duration::from_millis(20);
        let mut scorer = CongestionScorer::with_config(config);

        // Initially stable but not long enough
        let action = scorer.tick();
        assert_eq!(action, CongestionAction::None);

        // Wait for stable window
        thread::sleep(Duration::from_millis(25));

        let action = scorer.tick();
        assert_eq!(action, CongestionAction::Increase);
    }

    #[test]
    fn test_nack_threshold() {
        let mut config = make_config();
        config.decrease_threshold = 15.0;
        config.nack_threshold = 3;
        let mut scorer = CongestionScorer::with_config(config);

        // Below threshold - no impulse
        scorer.on_nack();
        scorer.on_nack();
        scorer.tick();
        assert_eq!(scorer.state(), ScorerState::Stable);

        // Above threshold - triggers impulse
        scorer.on_nack();
        scorer.on_nack();
        scorer.on_nack();
        scorer.on_nack();
        let action = scorer.tick();

        assert_eq!(action, CongestionAction::DecreaseSoft);
    }

    #[test]
    fn test_loss_contributes_proportionally() {
        let mut config = make_config();
        config.decrease_threshold = 20.0;
        let mut scorer = CongestionScorer::with_config(config);

        scorer.on_loss();
        scorer.on_loss();
        scorer.on_loss();
        scorer.on_loss();
        scorer.on_loss(); // 5 losses * 5 = 25 impulse

        let action = scorer.tick();
        assert_eq!(action, CongestionAction::DecreaseSoft);
    }

    #[test]
    fn test_reset() {
        let mut scorer = CongestionScorer::with_config(make_config());

        scorer.on_eagain();
        scorer.tick();
        assert_eq!(scorer.state(), ScorerState::Congested);

        scorer.reset();

        assert_eq!(scorer.state(), ScorerState::Stable);
        assert_eq!(scorer.score(), 0.0);
        assert!(!scorer.in_cooldown());
    }

    #[test]
    fn test_maybe_tick() {
        let mut config = make_config();
        config.tick_interval = Duration::from_millis(20);
        let mut scorer = CongestionScorer::with_config(config);

        // Too soon
        assert!(scorer.maybe_tick().is_none());

        thread::sleep(Duration::from_millis(25));

        // Now should tick
        assert!(scorer.maybe_tick().is_some());
    }

    #[test]
    fn test_peak_score_tracking() {
        let mut scorer = CongestionScorer::with_config(make_config());

        scorer.on_eagain();
        scorer.tick();

        let peak = scorer.metrics().peak_score;
        assert!(peak > 0.0);

        // Decay
        for _ in 0..5 {
            scorer.tick();
        }

        // Peak should remain
        assert_eq!(scorer.metrics().peak_score, peak);
    }

    #[test]
    fn test_congested_duration_tracking() {
        let mut config = make_config();
        config.cooldown = Duration::from_millis(5);
        let mut scorer = CongestionScorer::with_config(config);

        scorer.on_eagain();
        scorer.tick();

        // In congested state, tick a few times
        scorer.tick();
        scorer.tick();

        let duration = scorer.metrics().congested_duration;
        assert!(duration >= Duration::from_millis(20)); // At least 2 ticks * 10ms
    }

    #[test]
    fn test_from_congestion_config() {
        let cfg = CongestionConfig::default();
        let scorer = CongestionScorer::from_config(&cfg);

        assert_eq!(
            scorer.config().decrease_threshold,
            cfg.decrease_threshold as f32
        );
        assert_eq!(scorer.config().decay, cfg.score_decay);
    }

    #[test]
    fn test_multiple_signals_combine() {
        let mut config = make_config();
        config.decrease_threshold = 80.0;
        let mut scorer = CongestionScorer::with_config(config);

        // All signals together
        scorer.on_eagain(); // 60
        scorer.on_rtt_inflated(); // 30
                                  // Total: 90 impulse

        let action = scorer.tick();
        assert_eq!(action, CongestionAction::DecreaseHard); // Because EAGAIN present
        assert!(scorer.score() >= 40.0); // (90 * 0.5) = 45
    }

    #[test]
    fn test_state_transitions_count() {
        let mut config = make_config();
        config.cooldown = Duration::from_millis(5);
        let mut scorer = CongestionScorer::with_config(config);

        // Go to congested
        scorer.on_eagain();
        scorer.tick();
        assert_eq!(scorer.metrics().congestion_events, 1);

        // Wait and recover
        thread::sleep(Duration::from_millis(10));
        for _ in 0..10 {
            scorer.tick();
        }
        assert_eq!(scorer.metrics().recovery_events, 1);

        // Go congested again
        scorer.on_eagain();
        scorer.tick();
        assert_eq!(scorer.metrics().congestion_events, 2);
    }
}

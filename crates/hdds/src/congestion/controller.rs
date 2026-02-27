// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Main congestion controller orchestrating all components.
//!
//! Integrates:
//! - Scorer (EWMA + state machine)
//! - Rate controller (AIMD)
//! - Budget allocator (priority-based distribution)
//! - RTT estimator (soft signals)
//! - Transport feedback (EAGAIN/ENOBUFS)
//! - ECN feedback (CE marks from routers) [Phase 6]

use std::time::{Duration, Instant};

use super::budget_allocator::{AllocationConfig, BudgetAllocator, WriterBudgetUpdate, WriterId};
use super::config::{CongestionConfig, EcnMode, Priority};
use super::ecn::{EcnCodepoint, EcnProcessor};
use super::metrics::{CongestionMetrics, MetricsObserver, NoOpObserver};
use super::rate_controller::RateController;
use super::rtt_estimator::PeerRttTracker;
use super::scorer::{CongestionAction, CongestionScorer, ScorerConfig};
use super::transport_feedback::{TransportFeedback, TransportSignal};

/// Main congestion controller for a participant.
///
/// Orchestrates all congestion control components and provides
/// a unified interface for rate management.
pub struct CongestionController<O: MetricsObserver = NoOpObserver> {
    /// Configuration.
    config: CongestionConfig,

    /// Congestion scorer.
    scorer: CongestionScorer,

    /// Rate controller (AIMD).
    rate_controller: RateController,

    /// Budget allocator.
    allocator: BudgetAllocator,

    /// RTT tracker (per-peer).
    rtt_tracker: PeerRttTracker,

    /// Transport feedback.
    transport_feedback: TransportFeedback,

    /// ECN processor (Phase 6).
    ecn_processor: Option<EcnProcessor>,

    /// ECN mode.
    ecn_mode: EcnMode,

    /// Metrics.
    metrics: CongestionMetrics,

    /// Metrics observer.
    observer: O,

    /// Last tick time.
    last_tick: Instant,

    /// Tick interval.
    tick_interval: Duration,

    /// NACK count this window.
    nack_count_window: u32,

    /// Window start for NACK rate.
    nack_window_start: Instant,

    /// Enabled flag.
    enabled: bool,
}

impl CongestionController<NoOpObserver> {
    /// Create a new congestion controller with default observer.
    pub fn new(config: CongestionConfig) -> Self {
        Self::with_observer(config, NoOpObserver)
    }
}

impl<O: MetricsObserver> CongestionController<O> {
    /// Create with custom metrics observer.
    pub fn with_observer(config: CongestionConfig, observer: O) -> Self {
        let tick_interval = Duration::from_millis(config.score_tick_ms as u64);

        let scorer_config = ScorerConfig {
            tick_interval,
            decay: config.score_decay,
            decrease_threshold: config.decrease_threshold as f32,
            increase_threshold: config.increase_threshold as f32,
            hysteresis: config.hysteresis_band as f32,
            eagain_impulse: config.eagain_impulse as f32,
            rtt_impulse: config.rtt_impulse as f32,
            nack_impulse: config.nack_impulse as f32,
            nack_threshold: config.nack_rate_threshold,
            cooldown: Duration::from_millis(config.cooldown_ms as u64),
            stable_window: Duration::from_millis(config.stable_window_ms as u64),
            eagain_is_hard: config.eagain_is_hard,
        };

        let rate_controller = RateController::with_params(
            config.max_rate_bps, // initial = max
            config.min_rate_bps,
            config.max_rate_bps,
            config.ai_step_bps,
            config.md_factor_hard,
            config.md_factor_soft,
        );

        let alloc_config = AllocationConfig {
            p0_min_share: config.p0_min_share,
            p0_min_bps: config.p0_min_bps,
            ..Default::default()
        };

        // Initialize ECN processor if enabled
        let ecn_mode = config.ecn_mode;
        let ecn_processor = match ecn_mode {
            EcnMode::Off => None,
            EcnMode::Opportunistic | EcnMode::Mandatory => {
                // 100 packet window, 1% CE threshold for congestion signal
                Some(EcnProcessor::new(100, 0.01))
            }
        };

        Self {
            enabled: config.enabled,
            scorer: CongestionScorer::with_config(scorer_config),
            rate_controller,
            allocator: BudgetAllocator::with_config(alloc_config),
            rtt_tracker: PeerRttTracker::new(100.0), // 100ms default RTT
            transport_feedback: TransportFeedback::new(),
            ecn_processor,
            ecn_mode,
            metrics: CongestionMetrics::new(),
            observer,
            last_tick: Instant::now(),
            tick_interval,
            nack_count_window: 0,
            nack_window_start: Instant::now(),
            config,
        }
    }

    /// Check if congestion control is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable/disable congestion control.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Register a writer with the allocator.
    pub fn register_writer(&mut self, writer_id: WriterId, priority: Priority) {
        self.allocator.register(writer_id, priority);
    }

    /// Unregister a writer.
    pub fn unregister_writer(&mut self, writer_id: WriterId) {
        self.allocator.unregister(writer_id);
    }

    /// Called periodically (e.g., every 100ms) to update state.
    ///
    /// Returns budget updates if rate changed.
    pub fn tick(&mut self) -> Option<Vec<WriterBudgetUpdate>> {
        if !self.enabled {
            return None;
        }

        self.last_tick = Instant::now();

        // Check RTT inflation
        if self.rtt_tracker.any_inflated() {
            self.scorer.on_rtt_inflated();
        }

        // Check NACK rate
        self.update_nack_rate();

        // Get action from scorer
        let action = self.scorer.tick();

        // Apply action to rate controller
        if let Some(new_rate) = self.rate_controller.apply_action(action) {
            // Record metrics
            self.record_action(&action, new_rate);

            // Reallocate budgets
            let updates = self.allocator.reallocate(new_rate);
            return Some(updates);
        }

        None
    }

    /// Called periodically if there's a possibility tick wasn't called.
    ///
    /// Only ticks if enough time has passed since last tick.
    pub fn maybe_tick(&mut self) -> Option<Vec<WriterBudgetUpdate>> {
        if self.last_tick.elapsed() >= self.tick_interval {
            self.tick()
        } else {
            None
        }
    }

    fn update_nack_rate(&mut self) {
        // Reset window if needed
        if self.nack_window_start.elapsed() >= Duration::from_secs(1) {
            // Check if NACK rate exceeded threshold
            if self.nack_count_window > self.config.nack_rate_threshold {
                self.scorer.on_nack();
            }
            self.nack_count_window = 0;
            self.nack_window_start = Instant::now();
        }
    }

    fn record_action(&mut self, action: &CongestionAction, new_rate: u32) {
        let old_rate = self.metrics.snapshot().current_rate_bps;

        match action {
            CongestionAction::Increase => {
                self.observer.on_increase(old_rate, new_rate);
            }
            CongestionAction::DecreaseSoft => {
                self.observer.on_decrease(old_rate, new_rate, "soft");
            }
            CongestionAction::DecreaseHard => {
                self.observer.on_decrease(old_rate, new_rate, "hard");
            }
            CongestionAction::None => {}
        }

        self.metrics.record_rate(new_rate);
    }

    /// Report a send result (for transport feedback).
    pub fn on_send_result<T>(&mut self, result: &std::io::Result<T>) {
        if !self.enabled {
            return;
        }

        let signal = self.transport_feedback.record_result(result);

        match signal {
            TransportSignal::WouldBlock | TransportSignal::NoBuffers => {
                self.scorer.on_eagain();
                self.metrics.record_eagain();
                self.observer.on_eagain();
            }
            _ => {}
        }
    }

    /// Report an EAGAIN/ENOBUFS directly.
    pub fn on_eagain(&mut self) {
        if !self.enabled {
            return;
        }

        self.scorer.on_eagain();
        self.metrics.record_eagain();
        self.observer.on_eagain();
    }

    /// Report an RTT sample.
    pub fn on_rtt_sample(&mut self, peer_id: u32, rtt_ms: f32) {
        if !self.enabled {
            return;
        }

        self.rtt_tracker.update(peer_id, rtt_ms);
    }

    /// Report a NACK received.
    pub fn on_nack(&mut self) {
        if !self.enabled {
            return;
        }

        self.nack_count_window = self.nack_count_window.saturating_add(1);
    }

    /// Report multiple NACKs (e.g., from a NACK message with multiple gaps).
    pub fn on_nacks(&mut self, count: u32) {
        if !self.enabled {
            return;
        }

        self.nack_count_window = self.nack_count_window.saturating_add(count);
    }

    /// Report an ECN TOS byte from a received packet.
    ///
    /// This should be called for every received packet when ECN is enabled.
    /// Returns `true` if the ECN processor signals congestion.
    pub fn on_ecn_tos(&mut self, tos: u8) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(ref mut processor) = self.ecn_processor {
            let should_signal = processor.process_tos(tos);
            if should_signal {
                // ECN congestion is treated as soft signal (like RTT inflation)
                self.scorer.on_rtt_inflated();
                self.metrics.record_ecn_ce();
            }
            should_signal
        } else {
            false
        }
    }

    /// Report an ECN codepoint directly.
    pub fn on_ecn_codepoint(&mut self, codepoint: EcnCodepoint) -> bool {
        self.on_ecn_tos(codepoint.to_tos())
    }

    /// Report a CE (Congestion Experienced) mark immediately.
    ///
    /// This bypasses the windowed processing and signals congestion immediately.
    /// Use this for latency-sensitive applications or when you want immediate response.
    pub fn on_ecn_ce(&mut self) {
        if !self.enabled {
            return;
        }

        if let Some(ref mut processor) = self.ecn_processor {
            processor.process_ce();
            self.scorer.on_rtt_inflated(); // ECN CE = soft congestion
            self.metrics.record_ecn_ce();
        }
    }

    /// Check if ECN is active.
    pub fn is_ecn_active(&self) -> bool {
        self.ecn_processor.is_some()
    }

    /// Get ECN mode.
    pub fn ecn_mode(&self) -> EcnMode {
        self.ecn_mode
    }

    /// Get ECN statistics (if ECN is enabled).
    pub fn ecn_stats(&self) -> Option<&super::ecn::EcnStats> {
        self.ecn_processor.as_ref().map(|p| p.stats())
    }

    /// Get the current rate (bytes/sec).
    pub fn current_rate(&self) -> u32 {
        self.rate_controller.rate()
    }

    /// Get the budget for a specific writer.
    pub fn get_writer_budget(&self, writer_id: WriterId) -> Option<u32> {
        self.allocator.get_budget(writer_id)
    }

    /// Force a rate change (e.g., for testing or manual override).
    pub fn set_rate(&mut self, rate_bps: u32) -> Vec<WriterBudgetUpdate> {
        self.rate_controller.set_rate(rate_bps);
        self.metrics.record_rate(rate_bps);
        self.allocator.reallocate(rate_bps)
    }

    /// Get the scorer state.
    pub fn scorer_state(&self) -> super::scorer::ScorerState {
        self.scorer.state()
    }

    /// Get the current congestion score.
    pub fn score(&self) -> f32 {
        self.scorer.score()
    }

    /// Check if currently congested.
    pub fn is_congested(&self) -> bool {
        self.scorer.state() == super::scorer::ScorerState::Congested
    }

    /// Get metrics snapshot.
    pub fn metrics(&self) -> super::metrics::CongestionMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get transport feedback snapshot.
    pub fn transport_feedback(&self) -> super::transport_feedback::TransportFeedbackSnapshot {
        self.transport_feedback.snapshot()
    }

    /// Get the configuration.
    pub fn config(&self) -> &CongestionConfig {
        &self.config
    }

    /// Get the number of registered writers.
    pub fn writer_count(&self) -> usize {
        self.allocator.writer_count()
    }

    /// Reset the controller state.
    pub fn reset(&mut self) {
        self.scorer.reset();
        self.rate_controller.set_rate(self.config.max_rate_bps);
        self.nack_count_window = 0;
        self.nack_window_start = Instant::now();
    }

    /// Prune stale RTT data.
    pub fn prune_stale_rtt(&mut self, max_age: Duration) {
        self.rtt_tracker.prune_stale(max_age);
    }
}

impl Default for CongestionController<NoOpObserver> {
    fn default() -> Self {
        Self::new(CongestionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_new() {
        let ctrl = CongestionController::new(CongestionConfig::default());
        assert!(ctrl.is_enabled());
        assert_eq!(ctrl.writer_count(), 0);
    }

    #[test]
    fn test_default() {
        let ctrl = CongestionController::default();
        assert!(ctrl.is_enabled());
    }

    #[test]
    fn test_enable_disable() {
        let mut ctrl = CongestionController::default();

        ctrl.set_enabled(false);
        assert!(!ctrl.is_enabled());

        ctrl.set_enabled(true);
        assert!(ctrl.is_enabled());
    }

    #[test]
    fn test_register_writer() {
        let mut ctrl = CongestionController::default();

        ctrl.register_writer(1, Priority::P0);
        ctrl.register_writer(2, Priority::P1);
        ctrl.register_writer(3, Priority::P2);

        assert_eq!(ctrl.writer_count(), 3);
    }

    #[test]
    fn test_unregister_writer() {
        let mut ctrl = CongestionController::default();

        ctrl.register_writer(1, Priority::P0);
        ctrl.unregister_writer(1);

        assert_eq!(ctrl.writer_count(), 0);
    }

    #[test]
    fn test_tick_no_writers() {
        let mut ctrl = CongestionController::default();

        let updates = ctrl.tick();
        assert!(updates.is_none() || updates.unwrap().is_empty());
    }

    #[test]
    fn test_tick_with_writers() {
        let mut ctrl = CongestionController::default();

        ctrl.register_writer(1, Priority::P1);

        // First tick may not produce updates (no action yet)
        ctrl.tick();
    }

    #[test]
    fn test_on_eagain() {
        let mut ctrl = CongestionController::default();

        ctrl.on_eagain();
        ctrl.tick(); // Process pending signals

        // Score should have increased after tick
        assert!(ctrl.score() > 0.0);
    }

    #[test]
    fn test_on_send_result_ok() {
        let mut ctrl = CongestionController::default();

        let result: io::Result<usize> = Ok(100);
        ctrl.on_send_result(&result);

        // Score should not change on success
        let feedback = ctrl.transport_feedback();
        assert_eq!(feedback.sends_ok, 1);
    }

    #[test]
    fn test_on_send_result_eagain() {
        let mut ctrl = CongestionController::default();

        let result: io::Result<usize> = Err(io::Error::from(io::ErrorKind::WouldBlock));
        ctrl.on_send_result(&result);
        ctrl.tick(); // Process pending signals

        assert!(ctrl.score() > 0.0);
        let feedback = ctrl.transport_feedback();
        assert_eq!(feedback.eagain_count, 1);
    }

    #[test]
    fn test_on_rtt_sample() {
        let mut ctrl = CongestionController::default();

        ctrl.on_rtt_sample(1, 50.0);
        ctrl.on_rtt_sample(1, 100.0);

        // RTT should be tracked
    }

    #[test]
    fn test_on_nack() {
        let mut ctrl = CongestionController::default();

        for _ in 0..20 {
            ctrl.on_nack();
        }

        // NACK count should accumulate
    }

    #[test]
    fn test_disabled_no_action() {
        let mut ctrl = CongestionController::default();
        ctrl.set_enabled(false);

        ctrl.on_eagain();

        // Score should not change when disabled
        assert!((ctrl.score() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_set_rate() {
        let mut ctrl = CongestionController::default();

        ctrl.register_writer(1, Priority::P1);

        let updates = ctrl.set_rate(50_000);

        assert_eq!(updates.len(), 1);
        assert_eq!(ctrl.current_rate(), 50_000);
    }

    #[test]
    fn test_get_writer_budget() {
        let mut ctrl = CongestionController::default();

        ctrl.register_writer(1, Priority::P1);
        ctrl.set_rate(100_000);

        let budget = ctrl.get_writer_budget(1);
        assert!(budget.is_some());
        assert!(budget.unwrap() > 0);
    }

    #[test]
    fn test_scorer_state() {
        let ctrl = CongestionController::default();

        // Initially stable
        assert_eq!(
            ctrl.scorer_state(),
            super::super::scorer::ScorerState::Stable
        );
        assert!(!ctrl.is_congested());
    }

    #[test]
    fn test_reset() {
        let mut ctrl = CongestionController::default();

        ctrl.on_eagain();
        ctrl.on_eagain();

        ctrl.reset();

        assert!((ctrl.score() - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_metrics() {
        let mut ctrl = CongestionController::default();

        ctrl.set_rate(75_000);

        let metrics = ctrl.metrics();
        assert_eq!(metrics.current_rate_bps, 75_000);
    }

    #[test]
    fn test_maybe_tick_not_ready() {
        let mut ctrl = CongestionController::default();

        ctrl.tick(); // First tick

        // Immediately call maybe_tick - should not tick again
        let updates = ctrl.maybe_tick();
        assert!(updates.is_none());
    }

    #[test]
    fn test_multiple_writers_budget() {
        let mut ctrl = CongestionController::default();

        ctrl.register_writer(1, Priority::P0);
        ctrl.register_writer(2, Priority::P1);
        ctrl.register_writer(3, Priority::P2);

        let updates = ctrl.set_rate(100_000);

        assert_eq!(updates.len(), 3);

        // P0 should have budget
        let p0_budget = updates
            .iter()
            .find(|u| u.writer_id == 1)
            .unwrap()
            .budget_bps;
        assert!(p0_budget > 0);
    }

    #[test]
    fn test_congestion_cycle() {
        let mut ctrl = CongestionController::default();

        ctrl.register_writer(1, Priority::P1);

        // Simulate congestion
        for _ in 0..10 {
            ctrl.on_eagain();
        }

        // Tick to process
        ctrl.tick();

        // Should be congested
        assert!(ctrl.score() > 0.0);
    }

    #[test]
    fn test_on_nacks_batch() {
        let mut ctrl = CongestionController::default();

        ctrl.on_nacks(5);

        // Should count as 5 NACKs
    }

    // === Phase 6: ECN Tests ===

    #[test]
    fn test_ecn_disabled_by_default() {
        let ctrl = CongestionController::default();

        // Default config has ECN off
        assert!(!ctrl.is_ecn_active());
        assert_eq!(ctrl.ecn_mode(), EcnMode::Off);
    }

    #[test]
    fn test_ecn_enabled_opportunistic() {
        let config = CongestionConfig {
            ecn_mode: EcnMode::Opportunistic,
            ..Default::default()
        };
        let ctrl = CongestionController::new(config);

        assert!(ctrl.is_ecn_active());
        assert_eq!(ctrl.ecn_mode(), EcnMode::Opportunistic);
    }

    #[test]
    fn test_ecn_enabled_mandatory() {
        let config = CongestionConfig {
            ecn_mode: EcnMode::Mandatory,
            ..Default::default()
        };
        let ctrl = CongestionController::new(config);

        assert!(ctrl.is_ecn_active());
        assert_eq!(ctrl.ecn_mode(), EcnMode::Mandatory);
    }

    #[test]
    fn test_ecn_tos_no_signal_on_ect() {
        let config = CongestionConfig {
            ecn_mode: EcnMode::Opportunistic,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        // ECT0 and ECT1 should not signal congestion
        let signal = ctrl.on_ecn_tos(0b10); // ECT0
        assert!(!signal);

        let signal = ctrl.on_ecn_tos(0b01); // ECT1
        assert!(!signal);
    }

    #[test]
    fn test_ecn_ce_immediate_signal() {
        let config = CongestionConfig {
            ecn_mode: EcnMode::Opportunistic,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        ctrl.on_ecn_ce();
        ctrl.tick();

        // CE should increase score
        assert!(ctrl.score() > 0.0);
    }

    #[test]
    fn test_ecn_stats() {
        let config = CongestionConfig {
            ecn_mode: EcnMode::Opportunistic,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        // Process some packets
        ctrl.on_ecn_tos(0b10); // ECT0
        ctrl.on_ecn_tos(0b10); // ECT0
        ctrl.on_ecn_ce(); // CE

        let stats = ctrl.ecn_stats();
        assert!(stats.is_some());
        let stats = stats.unwrap();
        assert_eq!(stats.ect0_received, 2);
        assert_eq!(stats.ce_received, 1);
    }

    #[test]
    fn test_ecn_disabled_no_processing() {
        let mut ctrl = CongestionController::default(); // ECN off

        // Should return false and not crash
        let signal = ctrl.on_ecn_tos(0b11); // CE
        assert!(!signal);

        // Should also not crash
        ctrl.on_ecn_ce();

        // Stats should be None
        assert!(ctrl.ecn_stats().is_none());
    }

    #[test]
    fn test_ecn_codepoint_method() {
        use super::super::ecn::EcnCodepoint;

        let config = CongestionConfig {
            ecn_mode: EcnMode::Opportunistic,
            ..Default::default()
        };
        let mut ctrl = CongestionController::new(config);

        let signal = ctrl.on_ecn_codepoint(EcnCodepoint::Ect0);
        assert!(!signal);
    }
}

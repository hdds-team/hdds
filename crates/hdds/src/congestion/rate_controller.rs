// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! AIMD rate controller.
//!
//! Implements Additive Increase / Multiplicative Decrease rate adaptation
//! based on congestion signals from the scorer.

use std::time::{Duration, Instant};

use super::config::CongestionConfig;
use super::scorer::CongestionAction;

/// AIMD rate controller.
#[derive(Debug)]
pub struct RateController {
    /// Current rate in bytes per second.
    current_rate: u32,

    /// Minimum rate (floor).
    min_rate: u32,

    /// Maximum rate (ceiling).
    max_rate: u32,

    /// Additive increase step.
    ai_step: u32,

    /// Multiplicative decrease factor for hard congestion.
    md_hard: f32,

    /// Multiplicative decrease factor for soft congestion.
    md_soft: f32,

    /// Last rate change time.
    last_change: Instant,

    /// Metrics.
    metrics: RateControllerMetrics,
}

/// Rate controller metrics.
#[derive(Clone, Debug, Default)]
pub struct RateControllerMetrics {
    /// Number of increases.
    pub increases: u64,
    /// Number of soft decreases.
    pub decreases_soft: u64,
    /// Number of hard decreases.
    pub decreases_hard: u64,
    /// Total bytes of capacity lost to decreases.
    pub capacity_lost: u64,
    /// Total bytes of capacity gained from increases.
    pub capacity_gained: u64,
    /// Peak rate achieved.
    pub peak_rate: u32,
    /// Lowest rate reached.
    pub min_rate_reached: u32,
}

impl RateController {
    /// Create a new rate controller with default settings.
    pub fn new(initial_rate: u32) -> Self {
        Self {
            current_rate: initial_rate,
            min_rate: 10_000,
            max_rate: 100_000_000,
            ai_step: 50_000,
            md_hard: 0.5,
            md_soft: 0.8,
            last_change: Instant::now(),
            metrics: RateControllerMetrics {
                peak_rate: initial_rate,
                min_rate_reached: initial_rate,
                ..Default::default()
            },
        }
    }

    /// Create from CongestionConfig.
    pub fn from_config(config: &CongestionConfig) -> Self {
        let initial = config.max_rate_bps / 2; // Start at 50% of max
        Self {
            current_rate: initial,
            min_rate: config.min_rate_bps,
            max_rate: config.max_rate_bps,
            ai_step: config.ai_step_bps,
            md_hard: config.md_factor_hard,
            md_soft: config.md_factor_soft,
            last_change: Instant::now(),
            metrics: RateControllerMetrics {
                peak_rate: initial,
                min_rate_reached: initial,
                ..Default::default()
            },
        }
    }

    /// Create with specific parameters.
    pub fn with_params(
        initial_rate: u32,
        min_rate: u32,
        max_rate: u32,
        ai_step: u32,
        md_hard: f32,
        md_soft: f32,
    ) -> Self {
        let clamped = initial_rate.clamp(min_rate, max_rate);
        Self {
            current_rate: clamped,
            min_rate,
            max_rate,
            ai_step,
            md_hard,
            md_soft,
            last_change: Instant::now(),
            metrics: RateControllerMetrics {
                peak_rate: clamped,
                min_rate_reached: clamped,
                ..Default::default()
            },
        }
    }

    /// Apply an action from the scorer.
    ///
    /// Returns the new rate if it changed.
    pub fn apply_action(&mut self, action: CongestionAction) -> Option<u32> {
        let old_rate = self.current_rate;

        match action {
            CongestionAction::None => return None,

            CongestionAction::Increase => {
                let new_rate = (self.current_rate + self.ai_step).min(self.max_rate);
                if new_rate != self.current_rate {
                    let gained = new_rate - self.current_rate;
                    self.current_rate = new_rate;
                    self.metrics.increases += 1;
                    self.metrics.capacity_gained += gained as u64;

                    if new_rate > self.metrics.peak_rate {
                        self.metrics.peak_rate = new_rate;
                    }
                }
            }

            CongestionAction::DecreaseSoft => {
                let new_rate = ((self.current_rate as f32) * self.md_soft) as u32;
                let new_rate = new_rate.max(self.min_rate);
                if new_rate != self.current_rate {
                    let lost = self.current_rate - new_rate;
                    self.current_rate = new_rate;
                    self.metrics.decreases_soft += 1;
                    self.metrics.capacity_lost += lost as u64;

                    if new_rate < self.metrics.min_rate_reached {
                        self.metrics.min_rate_reached = new_rate;
                    }
                }
            }

            CongestionAction::DecreaseHard => {
                let new_rate = ((self.current_rate as f32) * self.md_hard) as u32;
                let new_rate = new_rate.max(self.min_rate);
                if new_rate != self.current_rate {
                    let lost = self.current_rate - new_rate;
                    self.current_rate = new_rate;
                    self.metrics.decreases_hard += 1;
                    self.metrics.capacity_lost += lost as u64;

                    if new_rate < self.metrics.min_rate_reached {
                        self.metrics.min_rate_reached = new_rate;
                    }
                }
            }
        }

        if self.current_rate != old_rate {
            self.last_change = Instant::now();
            Some(self.current_rate)
        } else {
            None
        }
    }

    /// Get the current rate.
    pub fn rate(&self) -> u32 {
        self.current_rate
    }

    /// Set the rate directly (e.g., for initialization).
    pub fn set_rate(&mut self, rate: u32) {
        self.current_rate = rate.clamp(self.min_rate, self.max_rate);
        self.last_change = Instant::now();

        if self.current_rate > self.metrics.peak_rate {
            self.metrics.peak_rate = self.current_rate;
        }
        if self.current_rate < self.metrics.min_rate_reached {
            self.metrics.min_rate_reached = self.current_rate;
        }
    }

    /// Get the minimum rate.
    pub fn min_rate(&self) -> u32 {
        self.min_rate
    }

    /// Get the maximum rate.
    pub fn max_rate(&self) -> u32 {
        self.max_rate
    }

    /// Get the AI step.
    pub fn ai_step(&self) -> u32 {
        self.ai_step
    }

    /// Get time since last rate change.
    pub fn time_since_change(&self) -> Duration {
        self.last_change.elapsed()
    }

    /// Get the metrics.
    pub fn metrics(&self) -> &RateControllerMetrics {
        &self.metrics
    }

    /// Reset metrics.
    pub fn reset_metrics(&mut self) {
        self.metrics = RateControllerMetrics {
            peak_rate: self.current_rate,
            min_rate_reached: self.current_rate,
            ..Default::default()
        };
    }

    /// Calculate what the rate would be after an action (without applying).
    pub fn preview_action(&self, action: CongestionAction) -> u32 {
        match action {
            CongestionAction::None => self.current_rate,
            CongestionAction::Increase => (self.current_rate + self.ai_step).min(self.max_rate),
            CongestionAction::DecreaseSoft => {
                { ((self.current_rate as f32) * self.md_soft) as u32 }.max(self.min_rate)
            }
            CongestionAction::DecreaseHard => {
                { ((self.current_rate as f32) * self.md_hard) as u32 }.max(self.min_rate)
            }
        }
    }

    /// Get utilization ratio (current / max).
    pub fn utilization(&self) -> f32 {
        self.current_rate as f32 / self.max_rate as f32
    }

    /// Check if at minimum rate.
    pub fn at_floor(&self) -> bool {
        self.current_rate <= self.min_rate
    }

    /// Check if at maximum rate.
    pub fn at_ceiling(&self) -> bool {
        self.current_rate >= self.max_rate
    }
}

impl RateControllerMetrics {
    /// Get total decreases.
    pub fn total_decreases(&self) -> u64 {
        self.decreases_soft + self.decreases_hard
    }

    /// Get net capacity change.
    pub fn net_capacity_change(&self) -> i64 {
        self.capacity_gained as i64 - self.capacity_lost as i64
    }

    /// Get average decrease severity.
    pub fn avg_decrease_severity(&self) -> f32 {
        let total = self.total_decreases();
        if total == 0 {
            return 0.0;
        }
        self.capacity_lost as f32 / total as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let ctrl = RateController::new(100_000);
        assert_eq!(ctrl.rate(), 100_000);
        assert_eq!(ctrl.min_rate(), 10_000);
        assert_eq!(ctrl.max_rate(), 100_000_000);
    }

    #[test]
    fn test_from_config() {
        let config = CongestionConfig::default();
        let ctrl = RateController::from_config(&config);

        assert_eq!(ctrl.min_rate(), config.min_rate_bps);
        assert_eq!(ctrl.max_rate(), config.max_rate_bps);
        assert_eq!(ctrl.ai_step(), config.ai_step_bps);
    }

    #[test]
    fn test_with_params() {
        let ctrl = RateController::with_params(50_000, 10_000, 100_000, 5_000, 0.5, 0.8);

        assert_eq!(ctrl.rate(), 50_000);
        assert_eq!(ctrl.min_rate(), 10_000);
        assert_eq!(ctrl.max_rate(), 100_000);
        assert_eq!(ctrl.ai_step(), 5_000);
    }

    #[test]
    fn test_initial_rate_clamped() {
        let ctrl = RateController::with_params(5_000, 10_000, 100_000, 5_000, 0.5, 0.8);
        assert_eq!(ctrl.rate(), 10_000); // Clamped to min

        let ctrl2 = RateController::with_params(200_000, 10_000, 100_000, 5_000, 0.5, 0.8);
        assert_eq!(ctrl2.rate(), 100_000); // Clamped to max
    }

    #[test]
    fn test_apply_none() {
        let mut ctrl = RateController::new(100_000);
        let result = ctrl.apply_action(CongestionAction::None);
        assert!(result.is_none());
        assert_eq!(ctrl.rate(), 100_000);
    }

    #[test]
    fn test_apply_increase() {
        let mut ctrl = RateController::with_params(50_000, 10_000, 100_000, 10_000, 0.5, 0.8);

        let result = ctrl.apply_action(CongestionAction::Increase);

        assert_eq!(result, Some(60_000));
        assert_eq!(ctrl.rate(), 60_000);
        assert_eq!(ctrl.metrics().increases, 1);
        assert_eq!(ctrl.metrics().capacity_gained, 10_000);
    }

    #[test]
    fn test_apply_increase_capped() {
        let mut ctrl = RateController::with_params(95_000, 10_000, 100_000, 10_000, 0.5, 0.8);

        let result = ctrl.apply_action(CongestionAction::Increase);

        assert_eq!(result, Some(100_000)); // Capped at max
        assert_eq!(ctrl.rate(), 100_000);
    }

    #[test]
    fn test_apply_decrease_soft() {
        let mut ctrl = RateController::with_params(100_000, 10_000, 200_000, 10_000, 0.5, 0.8);

        let result = ctrl.apply_action(CongestionAction::DecreaseSoft);

        assert_eq!(result, Some(80_000)); // 100_000 * 0.8
        assert_eq!(ctrl.rate(), 80_000);
        assert_eq!(ctrl.metrics().decreases_soft, 1);
        assert_eq!(ctrl.metrics().capacity_lost, 20_000);
    }

    #[test]
    fn test_apply_decrease_hard() {
        let mut ctrl = RateController::with_params(100_000, 10_000, 200_000, 10_000, 0.5, 0.8);

        let result = ctrl.apply_action(CongestionAction::DecreaseHard);

        assert_eq!(result, Some(50_000)); // 100_000 * 0.5
        assert_eq!(ctrl.rate(), 50_000);
        assert_eq!(ctrl.metrics().decreases_hard, 1);
        assert_eq!(ctrl.metrics().capacity_lost, 50_000);
    }

    #[test]
    fn test_decrease_floored() {
        let mut ctrl = RateController::with_params(15_000, 10_000, 100_000, 5_000, 0.5, 0.8);

        let result = ctrl.apply_action(CongestionAction::DecreaseHard);

        assert_eq!(result, Some(10_000)); // Floored at min (15_000 * 0.5 = 7_500 < 10_000)
        assert_eq!(ctrl.rate(), 10_000);
    }

    #[test]
    fn test_set_rate() {
        let mut ctrl = RateController::new(100_000);

        ctrl.set_rate(50_000);
        assert_eq!(ctrl.rate(), 50_000);

        ctrl.set_rate(5_000); // Below min
        assert_eq!(ctrl.rate(), 10_000); // Clamped
    }

    #[test]
    fn test_preview_action() {
        let ctrl = RateController::with_params(100_000, 10_000, 200_000, 10_000, 0.5, 0.8);

        assert_eq!(ctrl.preview_action(CongestionAction::None), 100_000);
        assert_eq!(ctrl.preview_action(CongestionAction::Increase), 110_000);
        assert_eq!(ctrl.preview_action(CongestionAction::DecreaseSoft), 80_000);
        assert_eq!(ctrl.preview_action(CongestionAction::DecreaseHard), 50_000);
    }

    #[test]
    fn test_utilization() {
        let ctrl = RateController::with_params(50_000, 10_000, 100_000, 5_000, 0.5, 0.8);
        assert!((ctrl.utilization() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_at_floor_ceiling() {
        let mut ctrl = RateController::with_params(50_000, 10_000, 100_000, 5_000, 0.5, 0.8);

        assert!(!ctrl.at_floor());
        assert!(!ctrl.at_ceiling());

        ctrl.set_rate(10_000);
        assert!(ctrl.at_floor());

        ctrl.set_rate(100_000);
        assert!(ctrl.at_ceiling());
    }

    #[test]
    fn test_peak_tracking() {
        let mut ctrl = RateController::with_params(50_000, 10_000, 100_000, 10_000, 0.5, 0.8);

        ctrl.apply_action(CongestionAction::Increase);
        ctrl.apply_action(CongestionAction::Increase);
        assert_eq!(ctrl.metrics().peak_rate, 70_000);

        ctrl.apply_action(CongestionAction::DecreaseHard);
        // Peak should remain at 70_000
        assert_eq!(ctrl.metrics().peak_rate, 70_000);
    }

    #[test]
    fn test_min_rate_tracking() {
        let mut ctrl = RateController::with_params(50_000, 10_000, 100_000, 10_000, 0.5, 0.8);

        ctrl.apply_action(CongestionAction::DecreaseHard);
        assert_eq!(ctrl.metrics().min_rate_reached, 25_000);

        ctrl.apply_action(CongestionAction::Increase);
        // Min should remain at 25_000
        assert_eq!(ctrl.metrics().min_rate_reached, 25_000);
    }

    #[test]
    fn test_metrics_total_decreases() {
        let mut ctrl = RateController::with_params(100_000, 10_000, 200_000, 10_000, 0.5, 0.8);

        ctrl.apply_action(CongestionAction::DecreaseSoft);
        ctrl.apply_action(CongestionAction::DecreaseHard);
        ctrl.apply_action(CongestionAction::DecreaseSoft);

        assert_eq!(ctrl.metrics().total_decreases(), 3);
    }

    #[test]
    fn test_metrics_net_capacity() {
        let mut ctrl = RateController::with_params(50_000, 10_000, 100_000, 10_000, 0.5, 0.8);

        ctrl.apply_action(CongestionAction::Increase); // +10_000
        ctrl.apply_action(CongestionAction::Increase); // +10_000
        ctrl.apply_action(CongestionAction::DecreaseSoft); // -14_000 (70_000 * 0.2)

        let net = ctrl.metrics().net_capacity_change();
        assert_eq!(net, 20_000 - 14_000); // +6_000
    }

    #[test]
    fn test_time_since_change() {
        let mut ctrl = RateController::new(100_000);

        std::thread::sleep(std::time::Duration::from_millis(10));

        ctrl.apply_action(CongestionAction::Increase);

        let elapsed = ctrl.time_since_change();
        assert!(elapsed < std::time::Duration::from_millis(10));
    }

    #[test]
    fn test_reset_metrics() {
        let mut ctrl = RateController::with_params(50_000, 10_000, 100_000, 10_000, 0.5, 0.8);

        ctrl.apply_action(CongestionAction::Increase);
        ctrl.apply_action(CongestionAction::DecreaseHard);

        ctrl.reset_metrics();

        assert_eq!(ctrl.metrics().increases, 0);
        assert_eq!(ctrl.metrics().decreases_hard, 0);
        assert_eq!(ctrl.metrics().peak_rate, ctrl.rate());
        assert_eq!(ctrl.metrics().min_rate_reached, ctrl.rate());
    }

    #[test]
    fn test_aimd_cycle() {
        let mut ctrl = RateController::with_params(50_000, 10_000, 100_000, 10_000, 0.5, 0.8);

        // Additive increase phase
        for _ in 0..5 {
            ctrl.apply_action(CongestionAction::Increase);
        }
        assert_eq!(ctrl.rate(), 100_000);

        // Multiplicative decrease
        ctrl.apply_action(CongestionAction::DecreaseHard);
        assert_eq!(ctrl.rate(), 50_000);

        // Increase again
        for _ in 0..3 {
            ctrl.apply_action(CongestionAction::Increase);
        }
        assert_eq!(ctrl.rate(), 80_000);
    }
}

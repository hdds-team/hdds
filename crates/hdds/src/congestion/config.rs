// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Congestion control configuration.
//!
//! This module defines the configuration for HDDS congestion control,
//! including rate limiting, scoring thresholds, and queue policies.

use std::time::Duration;

/// Traffic priority levels.
///
/// P0 is highest priority (protected), P2 is lowest (sacrificed first).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Priority {
    /// Critical traffic - protected from drops, guaranteed minimum budget.
    P0,
    /// Normal traffic - best effort with drops under congestion.
    #[default]
    P1,
    /// Background traffic - coalesced and dropped first.
    P2,
}

impl Priority {
    /// Returns the numeric value (lower = higher priority).
    pub fn as_u8(&self) -> u8 {
        match self {
            Priority::P0 => 0,
            Priority::P1 => 1,
            Priority::P2 => 2,
        }
    }
}

/// Backpressure policy when queues or tokens are exhausted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BackpressurePolicy {
    /// write() returns Err(WouldBlock) immediately.
    #[default]
    ReturnError,
    /// write() blocks until timeout.
    BlockWithTimeout(Duration),
    /// Drop the oldest sample (dangerous for P0).
    DropOldest,
}

impl BackpressurePolicy {
    /// Derive policy from DDS max_blocking_time QoS.
    pub fn from_max_blocking_time(max_blocking: Duration) -> Self {
        if max_blocking.is_zero() {
            BackpressurePolicy::ReturnError
        } else {
            BackpressurePolicy::BlockWithTimeout(max_blocking)
        }
    }
}

/// ECN (Explicit Congestion Notification) mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EcnMode {
    /// ECN disabled.
    #[default]
    Off,
    /// ECN if supported by OS and peers (v1.1).
    Opportunistic,
    /// ECN required, error otherwise (v1.1).
    Mandatory,
}

/// Congestion control configuration.
#[derive(Clone, Debug)]
pub struct CongestionConfig {
    /// Enable congestion control.
    pub enabled: bool,

    // === Rate Control (AIMD) ===
    /// Minimum guaranteed rate (bytes/sec).
    pub min_rate_bps: u32,

    /// Maximum allowed rate (bytes/sec).
    pub max_rate_bps: u32,

    /// Additive Increase step (bytes/sec per stable_window).
    pub ai_step_bps: u32,

    /// Multiplicative Decrease factor for hard congestion (e.g., EAGAIN).
    pub md_factor_hard: f32,

    /// Multiplicative Decrease factor for soft congestion (e.g., RTT inflation).
    pub md_factor_soft: f32,

    /// Stability window before allowing increase (ms).
    pub stable_window_ms: u32,

    /// Cooldown after decrease before allowing new decrease (ms).
    pub cooldown_ms: u32,

    // === Scoring ===
    /// Score calculation tick interval (ms).
    pub score_tick_ms: u32,

    /// EWMA decay factor (0.0-1.0).
    pub score_decay: f32,

    /// Score threshold to trigger decrease.
    pub decrease_threshold: u8,

    /// Score threshold to allow increase.
    pub increase_threshold: u8,

    /// Hysteresis band to prevent oscillations.
    pub hysteresis_band: u8,

    // === Signals ===
    /// Treat EAGAIN/ENOBUFS as hard congestion.
    pub eagain_is_hard: bool,

    /// Score impulse for EAGAIN events.
    pub eagain_impulse: u8,

    /// RTT inflation factor to detect congestion.
    pub rtt_inflate_factor: f32,

    /// Score impulse for RTT inflation.
    pub rtt_impulse: u8,

    /// NACK rate threshold (per second) for congestion.
    pub nack_rate_threshold: u32,

    /// Score impulse for high NACK rate.
    pub nack_impulse: u8,

    // === Reliable ===
    /// Maximum ratio of budget for repair traffic (0.0-1.0).
    pub repair_budget_ratio: f32,

    /// NACK coalescing delay (ms).
    pub nack_coalesce_ms: u32,

    /// Base delay for exponential retry backoff (ms).
    pub retry_backoff_base_ms: u32,

    /// Maximum delay for exponential retry backoff (ms).
    pub retry_backoff_max_ms: u32,

    /// Maximum retry attempts before giving up.
    pub max_retries: u32,

    // === Queues ===
    /// Enable P2 coalescing (last value wins by instance key).
    pub p2_coalesce: bool,

    /// Maximum P0 queue size (samples).
    pub max_queue_p0: usize,

    /// Maximum P1 queue size (samples).
    pub max_queue_p1: usize,

    /// Maximum P2 queue size (unique instances).
    pub max_queue_p2: usize,

    // === Backpressure ===
    /// Backpressure policy (if None, derived from max_blocking_time).
    pub backpressure_policy: Option<BackpressurePolicy>,

    // === Priority Allocation ===
    /// Minimum share guaranteed for P0 (0.0-1.0).
    pub p0_min_share: f32,

    /// Absolute minimum for P0 (bytes/sec).
    pub p0_min_bps: u32,

    /// Share of remaining budget for P1 vs P2 (0.0-1.0).
    pub p1_share_of_remaining: f32,

    // === ECN (future) ===
    /// ECN mode.
    pub ecn_mode: EcnMode,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            enabled: true,

            // Rate control
            min_rate_bps: 10_000,      // 10 KB/s floor
            max_rate_bps: 100_000_000, // 100 MB/s ceiling
            ai_step_bps: 50_000,       // +50 KB/s per window
            md_factor_hard: 0.5,       // -50% on EAGAIN
            md_factor_soft: 0.8,       // -20% on RTT/NACK
            stable_window_ms: 1000,    // 1s stability
            cooldown_ms: 300,          // 300ms cooldown

            // Scoring
            score_tick_ms: 100,     // 100ms ticks
            score_decay: 0.90,      // ~1s memory
            decrease_threshold: 60, // Congested if score >= 60
            increase_threshold: 20, // Stable if score <= 20
            hysteresis_band: 10,    // 10-point band

            // Signals
            eagain_is_hard: true,
            eagain_impulse: 60,      // Immediate congestion
            rtt_inflate_factor: 2.0, // 2x baseline = inflated
            rtt_impulse: 20,
            nack_rate_threshold: 10, // 10 NACKs/sec
            nack_impulse: 20,

            // Reliable
            repair_budget_ratio: 0.3,   // 30% max for repairs
            nack_coalesce_ms: 15,       // 15ms coalescing
            retry_backoff_base_ms: 100, // 100ms base
            retry_backoff_max_ms: 5000, // 5s max
            max_retries: 10,

            // Queues
            p2_coalesce: true,
            max_queue_p0: 100,
            max_queue_p1: 500,
            max_queue_p2: 100, // Small (coalesced)

            // Backpressure
            backpressure_policy: None, // Derive from QoS

            // Priority
            p0_min_share: 0.2,          // 20% reserved
            p0_min_bps: 10_000,         // 10 KB/s minimum
            p1_share_of_remaining: 0.7, // 70% of remaining to P1

            // ECN
            ecn_mode: EcnMode::Off,
        }
    }
}

impl CongestionConfig {
    /// Create a new config with congestion control enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a disabled config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Builder: set minimum rate.
    pub fn with_min_rate(mut self, bps: u32) -> Self {
        self.min_rate_bps = bps;
        self
    }

    /// Builder: set maximum rate.
    pub fn with_max_rate(mut self, bps: u32) -> Self {
        self.max_rate_bps = bps;
        self
    }

    /// Builder: set AI step.
    pub fn with_ai_step(mut self, bps: u32) -> Self {
        self.ai_step_bps = bps;
        self
    }

    /// Builder: set MD factors.
    pub fn with_md_factors(mut self, hard: f32, soft: f32) -> Self {
        self.md_factor_hard = hard;
        self.md_factor_soft = soft;
        self
    }

    /// Builder: set queue sizes.
    pub fn with_queue_sizes(mut self, p0: usize, p1: usize, p2: usize) -> Self {
        self.max_queue_p0 = p0;
        self.max_queue_p1 = p1;
        self.max_queue_p2 = p2;
        self
    }

    /// Builder: set P0 protection.
    pub fn with_p0_protection(mut self, min_share: f32, min_bps: u32) -> Self {
        self.p0_min_share = min_share;
        self.p0_min_bps = min_bps;
        self
    }

    /// Builder: set backpressure policy.
    pub fn with_backpressure(mut self, policy: BackpressurePolicy) -> Self {
        self.backpressure_policy = Some(policy);
        self
    }

    /// Builder: set scoring thresholds.
    pub fn with_thresholds(mut self, decrease: u8, increase: u8) -> Self {
        self.decrease_threshold = decrease;
        self.increase_threshold = increase;
        self
    }

    /// Get the effective backpressure policy.
    pub fn effective_backpressure(&self, max_blocking_time: Duration) -> BackpressurePolicy {
        self.backpressure_policy
            .unwrap_or_else(|| BackpressurePolicy::from_max_blocking_time(max_blocking_time))
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.min_rate_bps > self.max_rate_bps {
            return Err(ConfigError::InvalidRange("min_rate > max_rate"));
        }
        if self.md_factor_hard <= 0.0 || self.md_factor_hard > 1.0 {
            return Err(ConfigError::InvalidRange(
                "md_factor_hard must be in (0, 1]",
            ));
        }
        if self.md_factor_soft <= 0.0 || self.md_factor_soft > 1.0 {
            return Err(ConfigError::InvalidRange(
                "md_factor_soft must be in (0, 1]",
            ));
        }
        if self.score_decay <= 0.0 || self.score_decay >= 1.0 {
            return Err(ConfigError::InvalidRange("score_decay must be in (0, 1)"));
        }
        if self.decrease_threshold <= self.increase_threshold {
            return Err(ConfigError::InvalidRange(
                "decrease_threshold must be > increase_threshold",
            ));
        }
        if self.p0_min_share < 0.0 || self.p0_min_share > 1.0 {
            return Err(ConfigError::InvalidRange("p0_min_share must be in [0, 1]"));
        }
        if self.repair_budget_ratio < 0.0 || self.repair_budget_ratio > 1.0 {
            return Err(ConfigError::InvalidRange(
                "repair_budget_ratio must be in [0, 1]",
            ));
        }
        Ok(())
    }
}

/// Configuration validation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Invalid range for a parameter.
    InvalidRange(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::InvalidRange(msg) => write!(f, "invalid config: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::P0.as_u8() < Priority::P1.as_u8());
        assert!(Priority::P1.as_u8() < Priority::P2.as_u8());
    }

    #[test]
    fn test_priority_default() {
        assert_eq!(Priority::default(), Priority::P1);
    }

    #[test]
    fn test_backpressure_from_max_blocking_time() {
        let zero = BackpressurePolicy::from_max_blocking_time(Duration::ZERO);
        assert_eq!(zero, BackpressurePolicy::ReturnError);

        let timeout = BackpressurePolicy::from_max_blocking_time(Duration::from_secs(1));
        assert_eq!(
            timeout,
            BackpressurePolicy::BlockWithTimeout(Duration::from_secs(1))
        );
    }

    #[test]
    fn test_config_default() {
        let cfg = CongestionConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.min_rate_bps, 10_000);
        assert_eq!(cfg.max_rate_bps, 100_000_000);
        assert_eq!(cfg.md_factor_hard, 0.5);
        assert!(cfg.p2_coalesce);
    }

    #[test]
    fn test_config_disabled() {
        let cfg = CongestionConfig::disabled();
        assert!(!cfg.enabled);
    }

    #[test]
    fn test_config_builder() {
        let cfg = CongestionConfig::new()
            .with_min_rate(20_000)
            .with_max_rate(50_000_000)
            .with_queue_sizes(50, 200, 50);

        assert_eq!(cfg.min_rate_bps, 20_000);
        assert_eq!(cfg.max_rate_bps, 50_000_000);
        assert_eq!(cfg.max_queue_p0, 50);
        assert_eq!(cfg.max_queue_p1, 200);
    }

    #[test]
    fn test_config_validation_ok() {
        let cfg = CongestionConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_config_validation_min_max_rate() {
        let cfg = CongestionConfig::new()
            .with_min_rate(100_000)
            .with_max_rate(10_000);
        assert!(matches!(cfg.validate(), Err(ConfigError::InvalidRange(_))));
    }

    #[test]
    fn test_config_validation_md_factor() {
        let cfg = CongestionConfig {
            md_factor_hard: 1.5,
            ..CongestionConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::InvalidRange(_))));

        let cfg = CongestionConfig {
            md_factor_hard: 0.0,
            ..CongestionConfig::default()
        };
        assert!(matches!(cfg.validate(), Err(ConfigError::InvalidRange(_))));
    }

    #[test]
    fn test_config_validation_thresholds() {
        let cfg = CongestionConfig::new().with_thresholds(20, 60); // decrease < increase
        assert!(matches!(cfg.validate(), Err(ConfigError::InvalidRange(_))));
    }

    #[test]
    fn test_effective_backpressure() {
        let cfg = CongestionConfig::default();

        // No explicit policy -> derive from max_blocking_time
        let policy = cfg.effective_backpressure(Duration::from_millis(500));
        assert_eq!(
            policy,
            BackpressurePolicy::BlockWithTimeout(Duration::from_millis(500))
        );

        // Explicit policy overrides
        let cfg2 = cfg.with_backpressure(BackpressurePolicy::DropOldest);
        let policy2 = cfg2.effective_backpressure(Duration::from_secs(1));
        assert_eq!(policy2, BackpressurePolicy::DropOldest);
    }

    #[test]
    fn test_ecn_mode_default() {
        assert_eq!(EcnMode::default(), EcnMode::Off);
    }
}

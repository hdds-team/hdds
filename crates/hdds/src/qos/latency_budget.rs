// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LATENCY_BUDGET QoS policy (DDS v1.4 Sec.2.2.3.15)
//!
//! Provides a hint to the DDS implementation about the desired maximum delay
//! from the time data is written to when it's received.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** LATENCY_BUDGET is a hint (no RxO check required)
//!
//! This policy does not affect compatibility between readers and writers.
//! It provides optimization hints to the transport layer but doesn't
//! enforce any guarantees.
//!
//! # Use Cases
//!
//! - **Low-latency critical data**:
//!   - Control commands (require fast response)
//!   - Emergency alerts (immediate delivery)
//!   - Real-time sensor data (minimize staleness)
//!
//! - **Non-critical data**:
//!   - Logs (no specific latency requirement)
//!   - Diagnostics (can tolerate delay)
//!   - Historical data (latency irrelevant)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::latency_budget::LatencyBudget;
//! use std::time::Duration;
//!
//! // Critical data: 10ms latency budget
//! let critical = LatencyBudget::new(Duration::from_millis(10));
//! assert_eq!(critical.duration, Duration::from_millis(10));
//!
//! // No specific latency requirement (default)
//! let default = LatencyBudget::zero();
//! assert_eq!(default.duration, Duration::ZERO);
//! ```

use std::time::Duration;

/// LATENCY_BUDGET QoS policy
///
/// Specifies the maximum acceptable delay from write to receive.
/// This is a hint to the DDS implementation for transport optimization.
///
/// Default: Zero (no specific latency requirement).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LatencyBudget {
    /// Maximum acceptable delay from write to receive
    pub duration: Duration,
}

impl Default for LatencyBudget {
    /// Default: Zero duration (no specific latency requirement)
    fn default() -> Self {
        Self::zero()
    }
}

impl LatencyBudget {
    /// Create new LATENCY_BUDGET policy with specified duration
    ///
    /// # Arguments
    ///
    /// * `duration` - Maximum acceptable delay
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::latency_budget::LatencyBudget;
    /// use std::time::Duration;
    ///
    /// // 10ms latency budget for critical control data
    /// let budget = LatencyBudget::new(Duration::from_millis(10));
    /// assert_eq!(budget.duration, Duration::from_millis(10));
    /// ```
    pub fn new(duration: Duration) -> Self {
        Self { duration }
    }

    /// Create LATENCY_BUDGET with zero duration (no specific requirement)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::latency_budget::LatencyBudget;
    /// use std::time::Duration;
    ///
    /// let budget = LatencyBudget::zero();
    /// assert_eq!(budget.duration, Duration::ZERO);
    /// assert!(budget.is_zero());
    /// ```
    pub fn zero() -> Self {
        Self {
            duration: Duration::ZERO,
        }
    }

    /// Check if latency budget is zero (no specific requirement)
    pub fn is_zero(&self) -> bool {
        self.duration == Duration::ZERO
    }

    /// Check if latency budget is set (non-zero)
    pub fn is_set(&self) -> bool {
        self.duration > Duration::ZERO
    }

    /// Create latency budget from milliseconds
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::latency_budget::LatencyBudget;
    ///
    /// let budget = LatencyBudget::from_millis(50);
    /// assert_eq!(budget.duration.as_millis(), 50);
    /// ```
    pub fn from_millis(ms: u64) -> Self {
        Self {
            duration: Duration::from_millis(ms),
        }
    }

    /// Create latency budget from seconds
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::latency_budget::LatencyBudget;
    ///
    /// let budget = LatencyBudget::from_secs(2);
    /// assert_eq!(budget.duration.as_secs(), 2);
    /// ```
    pub fn from_secs(secs: u64) -> Self {
        Self {
            duration: Duration::from_secs(secs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_budget_default() {
        let budget = LatencyBudget::default();
        assert_eq!(budget.duration, Duration::ZERO);
        assert!(budget.is_zero());
        assert!(!budget.is_set());
    }

    #[test]
    fn test_latency_budget_zero() {
        let budget = LatencyBudget::zero();
        assert_eq!(budget.duration, Duration::ZERO);
        assert!(budget.is_zero());
        assert!(!budget.is_set());
    }

    #[test]
    fn test_latency_budget_new() {
        let budget = LatencyBudget::new(Duration::from_millis(100));
        assert_eq!(budget.duration, Duration::from_millis(100));
        assert!(!budget.is_zero());
        assert!(budget.is_set());
    }

    #[test]
    fn test_latency_budget_is_zero() {
        let zero = LatencyBudget::zero();
        let non_zero = LatencyBudget::new(Duration::from_millis(10));

        assert!(zero.is_zero());
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_latency_budget_is_set() {
        let zero = LatencyBudget::zero();
        let set = LatencyBudget::new(Duration::from_millis(10));

        assert!(!zero.is_set());
        assert!(set.is_set());
    }

    #[test]
    fn test_latency_budget_clone() {
        let budget1 = LatencyBudget::new(Duration::from_millis(50));
        let budget2 = budget1;

        assert_eq!(budget1.duration, budget2.duration);
    }

    #[test]
    fn test_latency_budget_debug() {
        let budget = LatencyBudget::new(Duration::from_millis(10));
        let debug_str = format!("{:?}", budget);

        assert!(debug_str.contains("LatencyBudget"));
    }

    #[test]
    fn test_latency_budget_equality() {
        let budget1 = LatencyBudget::new(Duration::from_millis(10));
        let budget2 = LatencyBudget::new(Duration::from_millis(10));
        let budget3 = LatencyBudget::new(Duration::from_millis(20));

        assert_eq!(budget1, budget2);
        assert_ne!(budget1, budget3);
    }

    // Use case tests

    #[test]
    fn test_use_case_critical_control_data() {
        // Control commands: 10ms latency budget
        let budget = LatencyBudget::new(Duration::from_millis(10));

        assert_eq!(budget.duration, Duration::from_millis(10));
        assert!(budget.is_set());
    }

    #[test]
    fn test_use_case_emergency_alerts() {
        // Emergency alerts: 5ms latency budget
        let budget = LatencyBudget::new(Duration::from_millis(5));

        assert_eq!(budget.duration, Duration::from_millis(5));
        assert!(budget.is_set());
    }

    #[test]
    fn test_use_case_real_time_sensors() {
        // Real-time sensor data: 20ms latency budget
        let budget = LatencyBudget::new(Duration::from_millis(20));

        assert_eq!(budget.duration, Duration::from_millis(20));
        assert!(budget.is_set());
    }

    #[test]
    fn test_use_case_non_critical_logs() {
        // Logs: no specific latency requirement
        let budget = LatencyBudget::zero();

        assert!(budget.is_zero());
        assert!(!budget.is_set());
    }

    #[test]
    fn test_use_case_diagnostics() {
        // Diagnostics: can tolerate delay
        let budget = LatencyBudget::zero();

        assert!(budget.is_zero());
    }

    #[test]
    fn test_latency_budget_very_short() {
        // Edge case: 1 microsecond latency budget
        let budget = LatencyBudget::new(Duration::from_micros(1));

        assert_eq!(budget.duration, Duration::from_micros(1));
        assert!(budget.is_set());
    }

    #[test]
    fn test_latency_budget_very_long() {
        // Edge case: 1 second latency budget
        let budget = LatencyBudget::new(Duration::from_secs(1));

        assert_eq!(budget.duration, Duration::from_secs(1));
        assert!(budget.is_set());
    }

    #[test]
    fn test_latency_budget_copy() {
        let budget1 = LatencyBudget::new(Duration::from_millis(10));
        let budget2 = budget1; // Copy

        assert_eq!(budget1, budget2);
    }
}

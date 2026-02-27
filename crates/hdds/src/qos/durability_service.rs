// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DURABILITY_SERVICE QoS policy (DDS v1.4 Sec.2.2.3.5)
//!
//! Configures the history cache for TRANSIENT_LOCAL and PERSISTENT durability.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** DURABILITY_SERVICE is not part of RxO compatibility checking
//!
//! This policy controls writer-side history cache configuration and does not
//! affect compatibility between readers and writers.
//!
//! # Policy Semantics
//!
//! Only relevant when DURABILITY is TRANSIENT_LOCAL or PERSISTENT. For VOLATILE
//! durability, this policy is ignored.
//!
//! - **service_cleanup_delay_us**: Time to wait before purging samples from
//!   history cache when all readers have acknowledged them (microseconds).
//!   Default: 0 (immediate cleanup).
//! - **history_kind**: KEEP_LAST(n) or KEEP_ALL for history cache.
//! - **history_depth**: Number of samples to keep (for KEEP_LAST).
//! - **max_samples**: Maximum total samples in history cache.
//! - **max_instances**: Maximum instances in history cache.
//! - **max_samples_per_instance**: Maximum samples per instance.
//!
//! # Use Cases
//!
//! - **Late-joiner support**: Configure history depth for late-joining readers
//! - **Memory management**: Limit history cache size with max_samples
//! - **Reliability**: Combine with RELIABLE for guaranteed historical delivery
//! - **Instance management**: Control per-instance history with history_depth
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::durability_service::DurabilityService;
//!
//! // Default: KEEP_LAST(1) with minimal limits
//! let service = DurabilityService::default();
//! assert_eq!(service.history_depth, 1);
//!
//! // Late-joiner support: keep last 100 samples
//! let service = DurabilityService::keep_last(100, 1000, 10, 100);
//! assert_eq!(service.history_depth, 100);
//!
//! // Immediate cleanup after all readers acknowledge
//! let service = DurabilityService::default();
//! assert_eq!(service.service_cleanup_delay_us, 0);
//! ```

/// Constant for unlimited resource limit (DDS v1.4 convention)
///
/// Used for `max_samples`, `max_instances`, `max_samples_per_instance`
pub const LENGTH_UNLIMITED: i32 = -1;

/// DURABILITY_SERVICE QoS policy (DDS v1.4 Sec.2.2.3.5)
///
/// Configures the history cache for TRANSIENT_LOCAL/PERSISTENT durability.
///
/// Only relevant when DURABILITY is TRANSIENT_LOCAL or PERSISTENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurabilityService {
    /// Cleanup delay after all readers acknowledge (microseconds)
    ///
    /// 0 = immediate cleanup (default)
    pub service_cleanup_delay_us: u64,

    /// History depth (KEEP_LAST depth)
    ///
    /// Number of samples to keep in history cache per instance.
    /// Must be > 0 (unsigned, no "unlimited" concept for depth).
    pub history_depth: u32,

    /// Maximum total samples in history cache
    ///
    /// **Type: `i32`** (not `u32`) per DDS v1.4 convention:
    /// - `-1` = UNLIMITED (no maximum)
    /// - `0` = invalid (must be > 0 if limited)
    /// - `> 0` = specific limit
    pub max_samples: i32,

    /// Maximum instances in history cache
    ///
    /// **Type: `i32`** (not `u32`) per DDS v1.4 convention:
    /// - `-1` = UNLIMITED (no maximum)
    /// - `0` = invalid (must be > 0 if limited)
    /// - `> 0` = specific limit
    pub max_instances: i32,

    /// Maximum samples per instance in history cache
    ///
    /// **Type: `i32`** (not `u32`) per DDS v1.4 convention:
    /// - `-1` = UNLIMITED (no maximum)
    /// - `0` = invalid (must be > 0 if limited)
    /// - `> 0` = specific limit
    pub max_samples_per_instance: i32,
}

impl Default for DurabilityService {
    /// Default: KEEP_LAST(1) with minimal limits
    fn default() -> Self {
        Self {
            service_cleanup_delay_us: 0,
            history_depth: 1,
            max_samples: 1000,
            max_instances: 1,
            max_samples_per_instance: 1000,
        }
    }
}

impl DurabilityService {
    /// Create DURABILITY_SERVICE for late-joiner support
    ///
    /// # Arguments
    ///
    /// * `history_depth` - Number of samples to keep (KEEP_LAST depth)
    /// * `max_samples` - Maximum total samples in history cache
    /// * `max_instances` - Maximum instances in history cache
    /// * `max_samples_per_instance` - Maximum samples per instance
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::durability_service::DurabilityService;
    ///
    /// // Keep last 100 samples, up to 1000 total
    /// let service = DurabilityService::keep_last(100, 1000, 10, 100);
    /// assert_eq!(service.history_depth, 100);
    /// assert_eq!(service.max_samples, 1000);
    /// ```
    pub fn keep_last(
        history_depth: u32,
        max_samples: i32,
        max_instances: i32,
        max_samples_per_instance: i32,
    ) -> Self {
        Self {
            service_cleanup_delay_us: 0,
            history_depth,
            max_samples,
            max_instances,
            max_samples_per_instance,
        }
    }

    /// Create DURABILITY_SERVICE with cleanup delay
    ///
    /// Delays cleanup to allow late readers to catch up.
    ///
    /// # Arguments
    ///
    /// * `cleanup_delay_secs` - Cleanup delay in seconds
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::durability_service::DurabilityService;
    ///
    /// // Wait 60 seconds before cleanup
    /// let service = DurabilityService::with_cleanup_delay_secs(60);
    /// assert_eq!(service.service_cleanup_delay_us, 60_000_000);
    /// ```
    pub fn with_cleanup_delay_secs(cleanup_delay_secs: u32) -> Self {
        Self {
            service_cleanup_delay_us: (cleanup_delay_secs as u64) * 1_000_000,
            ..Default::default()
        }
    }

    /// Create DURABILITY_SERVICE with all parameters
    ///
    /// Full control over all history cache configuration.
    ///
    /// # Arguments
    ///
    /// * `cleanup_delay_us` - Cleanup delay (microseconds)
    /// * `history_depth` - Number of samples to keep (KEEP_LAST depth)
    /// * `max_samples` - Maximum total samples in history cache
    /// * `max_instances` - Maximum instances in history cache
    /// * `max_samples_per_instance` - Maximum samples per instance
    pub fn new(
        cleanup_delay_us: u64,
        history_depth: u32,
        max_samples: i32,
        max_instances: i32,
        max_samples_per_instance: i32,
    ) -> Self {
        Self {
            service_cleanup_delay_us: cleanup_delay_us,
            history_depth,
            max_samples,
            max_instances,
            max_samples_per_instance,
        }
    }

    /// Check if cleanup is immediate (delay = 0)
    pub fn is_immediate_cleanup(&self) -> bool {
        self.service_cleanup_delay_us == 0
    }

    /// Validate DURABILITY_SERVICE configuration
    ///
    /// Checks for invalid resource limit combinations.
    ///
    /// # Valid Values (DDS v1.4 convention)
    ///
    /// - `-1` (`LENGTH_UNLIMITED`): No limit (unlimited)
    /// - `> 0`: Specific limit
    /// - `0`: Invalid (rejected)
    ///
    /// # Returns
    ///
    /// - `Ok(())` if valid
    /// - `Err(String)` with validation error message
    pub fn validate(&self) -> Result<(), String> {
        // history_depth must be > 0 (no "unlimited" concept for depth)
        if self.history_depth == 0 {
            return Err("history_depth must be > 0".to_string());
        }

        // Resource limits: -1 (UNLIMITED) or > 0 are valid, 0 is invalid
        if self.max_samples == 0 {
            return Err("max_samples must be > 0 or LENGTH_UNLIMITED (-1)".to_string());
        }
        if self.max_instances == 0 {
            return Err("max_instances must be > 0 or LENGTH_UNLIMITED (-1)".to_string());
        }
        if self.max_samples_per_instance == 0 {
            return Err(
                "max_samples_per_instance must be > 0 or LENGTH_UNLIMITED (-1)".to_string(),
            );
        }

        // Skip relationship check if any limit is unlimited
        if self.max_samples == LENGTH_UNLIMITED
            || self.max_instances == LENGTH_UNLIMITED
            || self.max_samples_per_instance == LENGTH_UNLIMITED
        {
            return Ok(());
        }

        // Check relationship: max_samples >= max_samples_per_instance * max_instances
        if self.max_samples < self.max_samples_per_instance * self.max_instances {
            return Err(format!(
                "max_samples ({}) must be >= max_samples_per_instance ({}) * max_instances ({})",
                self.max_samples, self.max_samples_per_instance, self.max_instances
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic functionality tests
    // ========================================================================

    #[test]
    fn test_durability_service_default() {
        let service = DurabilityService::default();
        assert_eq!(service.service_cleanup_delay_us, 0);
        assert_eq!(service.history_depth, 1);
        assert_eq!(service.max_samples, 1000);
        assert_eq!(service.max_instances, 1);
        assert_eq!(service.max_samples_per_instance, 1000);
        assert!(service.is_immediate_cleanup());
    }

    #[test]
    fn test_durability_service_keep_last() {
        let service = DurabilityService::keep_last(100, 5000, 10, 500);
        assert_eq!(service.service_cleanup_delay_us, 0);
        assert_eq!(service.history_depth, 100);
        assert_eq!(service.max_samples, 5000);
        assert_eq!(service.max_instances, 10);
        assert_eq!(service.max_samples_per_instance, 500);
    }

    #[test]
    fn test_durability_service_with_cleanup_delay_secs() {
        let service = DurabilityService::with_cleanup_delay_secs(30);
        assert_eq!(service.service_cleanup_delay_us, 30_000_000);
        assert!(!service.is_immediate_cleanup());
    }

    #[test]
    fn test_durability_service_new() {
        let service = DurabilityService::new(5_000_000, 50, 2000, 5, 400);
        assert_eq!(service.service_cleanup_delay_us, 5_000_000);
        assert_eq!(service.history_depth, 50);
        assert_eq!(service.max_samples, 2000);
        assert_eq!(service.max_instances, 5);
        assert_eq!(service.max_samples_per_instance, 400);
    }

    #[test]
    fn test_durability_service_clone() {
        let service1 = DurabilityService::keep_last(100, 1000, 10, 100);
        let service2 = service1; // Copy, not clone
        assert_eq!(service1, service2);
    }

    #[test]
    fn test_durability_service_equality() {
        let service1 = DurabilityService::keep_last(100, 1000, 10, 100);
        let service2 = DurabilityService::keep_last(100, 1000, 10, 100);
        let service3 = DurabilityService::keep_last(200, 1000, 10, 100);

        assert_eq!(service1, service2);
        assert_ne!(service1, service3);
    }

    #[test]
    fn test_durability_service_debug() {
        let service = DurabilityService::default();
        let debug_str = format!("{:?}", service);
        assert!(debug_str.contains("DurabilityService"));
        assert!(debug_str.contains("service_cleanup_delay_us"));
    }

    // ========================================================================
    // Validation tests
    // ========================================================================

    #[test]
    fn test_validate_default_valid() {
        let service = DurabilityService::default();
        assert!(service.validate().is_ok());
    }

    #[test]
    fn test_validate_history_depth_zero() {
        let service = DurabilityService {
            history_depth: 0,
            ..Default::default()
        };
        assert!(service.validate().is_err());
        assert!(service
            .validate()
            .unwrap_err()
            .contains("history_depth must be > 0"));
    }

    #[test]
    fn test_validate_max_samples_too_small() {
        let service = DurabilityService {
            max_samples: 10,
            max_instances: 5,
            max_samples_per_instance: 10,
            ..Default::default()
        };
        assert!(service.validate().is_err());
        assert!(service.validate().unwrap_err().contains("max_samples"));
    }

    #[test]
    fn test_validate_max_samples_zero() {
        let service = DurabilityService {
            max_samples: 0,
            ..Default::default()
        };
        assert!(service.validate().is_err());
        assert!(service
            .validate()
            .unwrap_err()
            .contains("max_samples must be > 0"));
    }

    #[test]
    fn test_validate_max_instances_zero() {
        let service = DurabilityService {
            max_instances: 0,
            ..Default::default()
        };
        assert!(service.validate().is_err());
        assert!(service
            .validate()
            .unwrap_err()
            .contains("max_instances must be > 0"));
    }

    #[test]
    fn test_validate_max_samples_per_instance_zero() {
        let service = DurabilityService {
            max_samples_per_instance: 0,
            ..Default::default()
        };
        assert!(service.validate().is_err());
        assert!(service
            .validate()
            .unwrap_err()
            .contains("max_samples_per_instance must be > 0"));
    }

    #[test]
    fn test_validate_length_unlimited_max_samples() {
        let service = DurabilityService {
            max_samples: LENGTH_UNLIMITED,
            ..Default::default()
        };
        assert!(
            service.validate().is_ok(),
            "LENGTH_UNLIMITED should be valid for max_samples"
        );
    }

    #[test]
    fn test_validate_length_unlimited_max_instances() {
        let service = DurabilityService {
            max_instances: LENGTH_UNLIMITED,
            ..Default::default()
        };
        assert!(
            service.validate().is_ok(),
            "LENGTH_UNLIMITED should be valid for max_instances"
        );
    }

    #[test]
    fn test_validate_length_unlimited_max_samples_per_instance() {
        let service = DurabilityService {
            max_samples_per_instance: LENGTH_UNLIMITED,
            ..Default::default()
        };
        assert!(
            service.validate().is_ok(),
            "LENGTH_UNLIMITED should be valid for max_samples_per_instance"
        );
    }

    #[test]
    fn test_validate_all_unlimited() {
        let service = DurabilityService {
            max_samples: LENGTH_UNLIMITED,
            max_instances: LENGTH_UNLIMITED,
            max_samples_per_instance: LENGTH_UNLIMITED,
            ..Default::default()
        };
        assert!(
            service.validate().is_ok(),
            "All LENGTH_UNLIMITED should be valid"
        );
    }

    #[test]
    fn test_validate_valid_configuration() {
        let service = DurabilityService::keep_last(100, 5000, 10, 500);
        assert!(service.validate().is_ok());
    }

    // ========================================================================
    // Use case tests
    // ========================================================================

    #[test]
    fn test_use_case_late_joiner_support() {
        // Late-joiner support: keep last 100 samples for new readers
        let service = DurabilityService::keep_last(100, 1000, 10, 100);
        assert_eq!(service.history_depth, 100);
        assert!(service.validate().is_ok());

        // Application would:
        // 1. Create writer with TRANSIENT_LOCAL durability
        // 2. Configure DURABILITY_SERVICE to keep 100 samples
        // 3. Late-joining readers receive historical samples
    }

    #[test]
    fn test_use_case_memory_constrained() {
        // Memory-constrained: limit history cache size
        let service = DurabilityService::keep_last(10, 100, 5, 20);
        assert_eq!(service.max_samples, 100);
        assert!(service.validate().is_ok());

        // Balances late-joiner support with memory constraints
    }

    #[test]
    fn test_use_case_reliable_transient() {
        // Reliable + TransientLocal: guaranteed historical delivery
        let service = DurabilityService::keep_last(1000, 10000, 10, 1000);
        assert_eq!(service.history_depth, 1000);
        assert!(service.validate().is_ok());

        // Combine with RELIABLE QoS for guaranteed delivery
        // and TRANSIENT_LOCAL for late-joiner support
    }

    #[test]
    fn test_use_case_cleanup_delay() {
        // Cleanup delay: allow very late readers to catch up
        let service = DurabilityService::with_cleanup_delay_secs(300);
        assert_eq!(service.service_cleanup_delay_us, 300_000_000);
        assert!(!service.is_immediate_cleanup());

        // Keep samples in cache for 5 minutes after all readers ack
    }

    #[test]
    fn test_use_case_high_throughput() {
        // High-throughput: large history cache
        let service = DurabilityService::keep_last(10000, 100000, 100, 1000);
        assert_eq!(service.max_samples, 100000);
        assert!(service.validate().is_ok());

        // Support high-rate topics with many instances
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    #[test]
    fn test_durability_service_copy_semantics() {
        let service1 = DurabilityService::keep_last(100, 1000, 10, 100);
        let service2 = service1; // Copy, not move
        assert_eq!(service1, service2);
    }

    #[test]
    fn test_durability_service_field_access() {
        let service = DurabilityService::keep_last(42, 420, 4, 42);
        assert_eq!(service.history_depth, 42);
        assert_eq!(service.max_samples, 420);
        assert_eq!(service.max_instances, 4);
        assert_eq!(service.max_samples_per_instance, 42);
    }

    #[test]
    fn test_durability_service_immediate_cleanup() {
        let service = DurabilityService::default();
        assert!(service.is_immediate_cleanup());

        let service_delayed = DurabilityService::with_cleanup_delay_secs(1);
        assert!(!service_delayed.is_immediate_cleanup());
    }

    #[test]
    fn test_validate_boundary_exact() {
        // max_samples = max_instances * max_samples_per_instance (exact)
        let service = DurabilityService {
            max_samples: 100,
            max_instances: 10,
            max_samples_per_instance: 10,
            ..Default::default()
        };
        assert!(service.validate().is_ok());
    }

    #[test]
    fn test_validate_boundary_greater() {
        // max_samples > max_instances * max_samples_per_instance
        let service = DurabilityService {
            max_samples: 101,
            max_instances: 10,
            max_samples_per_instance: 10,
            ..Default::default()
        };
        assert!(service.validate().is_ok());
    }
}

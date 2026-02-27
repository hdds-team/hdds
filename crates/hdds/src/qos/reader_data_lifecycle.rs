// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! READER_DATA_LIFECYCLE QoS policy (DDS v1.4 Sec.2.2.3.8)
//!
//! Controls the behavior of the DataReader with regards to the lifecycle
//! of the data instances it manages.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** READER_DATA_LIFECYCLE is not part of RxO compatibility checking
//!
//! This policy controls reader-side instance management and does not affect
//! compatibility between readers and writers.
//!
//! # Policy Semantics
//!
//! - **autopurge_nowriter_samples_delay**: Duration to wait before purging
//!   instances that are in the NOT_ALIVE_NO_WRITERS state. INFINITE means
//!   instances are kept indefinitely.
//! - **autopurge_disposed_samples_delay**: Duration to wait before purging
//!   instances that are in the NOT_ALIVE_DISPOSED state. INFINITE means
//!   instances are kept indefinitely.
//!
//! # Use Cases
//!
//! - **Immediate cleanup**: Set both delays to 0 to purge instances immediately
//!   when they become not alive
//! - **Keep historical data**: Set to INFINITE to keep all instances for
//!   late-joining applications or historical analysis
//! - **Graceful cleanup**: Set moderate delays (e.g., 30s) to allow readers
//!   to process final instance states before purging
//! - **Memory management**: Use delays to control memory consumption by
//!   limiting how long inactive instances are retained
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::reader_data_lifecycle::ReaderDataLifecycle;
//!
//! // Default: keep instances indefinitely (INFINITE)
//! let lifecycle = ReaderDataLifecycle::default();
//! assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, i64::MAX);
//!
//! // Immediate cleanup: purge as soon as instances become not alive
//! let lifecycle = ReaderDataLifecycle::immediate_cleanup();
//! assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 0);
//! assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 0);
//!
//! // Custom delays: purge after 30 seconds
//! let lifecycle = ReaderDataLifecycle::new(30_000_000, 30_000_000);
//! ```

/// READER_DATA_LIFECYCLE QoS policy (DDS v1.4 Sec.2.2.3.8)
///
/// Controls automatic purging of reader instances.
///
/// Default: INFINITE (keep instances indefinitely).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderDataLifecycle {
    /// Delay before purging NOT_ALIVE_NO_WRITERS instances (microseconds)
    ///
    /// i64::MAX = INFINITE (never purge)
    pub autopurge_nowriter_samples_delay_us: i64,
    /// Delay before purging NOT_ALIVE_DISPOSED instances (microseconds)
    ///
    /// i64::MAX = INFINITE (never purge)
    pub autopurge_disposed_samples_delay_us: i64,
}

impl Default for ReaderDataLifecycle {
    /// Default: keep instances indefinitely (INFINITE)
    fn default() -> Self {
        Self::keep_all()
    }
}

impl ReaderDataLifecycle {
    /// Create READER_DATA_LIFECYCLE with custom delays
    ///
    /// # Arguments
    ///
    /// * `autopurge_nowriter_delay_us` - Delay before purging NOT_ALIVE_NO_WRITERS instances (us)
    /// * `autopurge_disposed_delay_us` - Delay before purging NOT_ALIVE_DISPOSED instances (us)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::reader_data_lifecycle::ReaderDataLifecycle;
    ///
    /// // Purge after 10 seconds
    /// let lifecycle = ReaderDataLifecycle::new(10_000_000, 10_000_000);
    /// assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 10_000_000);
    /// ```
    pub fn new(autopurge_nowriter_delay_us: i64, autopurge_disposed_delay_us: i64) -> Self {
        Self {
            autopurge_nowriter_samples_delay_us: autopurge_nowriter_delay_us,
            autopurge_disposed_samples_delay_us: autopurge_disposed_delay_us,
        }
    }

    /// Create READER_DATA_LIFECYCLE with INFINITE delays (never purge)
    ///
    /// Instances are kept indefinitely, even after all writers are gone
    /// or instances are disposed.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::reader_data_lifecycle::ReaderDataLifecycle;
    ///
    /// let lifecycle = ReaderDataLifecycle::keep_all();
    /// assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, i64::MAX);
    /// ```
    pub fn keep_all() -> Self {
        Self {
            autopurge_nowriter_samples_delay_us: i64::MAX,
            autopurge_disposed_samples_delay_us: i64::MAX,
        }
    }

    /// Create READER_DATA_LIFECYCLE with immediate cleanup
    ///
    /// Instances are purged as soon as they become NOT_ALIVE.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::reader_data_lifecycle::ReaderDataLifecycle;
    ///
    /// let lifecycle = ReaderDataLifecycle::immediate_cleanup();
    /// assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 0);
    /// ```
    pub fn immediate_cleanup() -> Self {
        Self {
            autopurge_nowriter_samples_delay_us: 0,
            autopurge_disposed_samples_delay_us: 0,
        }
    }

    /// Create READER_DATA_LIFECYCLE with delays in seconds
    ///
    /// # Arguments
    ///
    /// * `nowriter_delay_secs` - Delay before purging NOT_ALIVE_NO_WRITERS instances (seconds)
    /// * `disposed_delay_secs` - Delay before purging NOT_ALIVE_DISPOSED instances (seconds)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::reader_data_lifecycle::ReaderDataLifecycle;
    ///
    /// let lifecycle = ReaderDataLifecycle::from_secs(30, 30);
    /// assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 30_000_000);
    /// ```
    pub fn from_secs(nowriter_delay_secs: u32, disposed_delay_secs: u32) -> Self {
        Self {
            autopurge_nowriter_samples_delay_us: (nowriter_delay_secs as i64) * 1_000_000,
            autopurge_disposed_samples_delay_us: (disposed_delay_secs as i64) * 1_000_000,
        }
    }

    /// Check if autopurge is disabled (INFINITE delays)
    pub fn is_keep_all(&self) -> bool {
        self.autopurge_nowriter_samples_delay_us == i64::MAX
            && self.autopurge_disposed_samples_delay_us == i64::MAX
    }

    /// Check if immediate cleanup is enabled (both delays = 0)
    pub fn is_immediate_cleanup(&self) -> bool {
        self.autopurge_nowriter_samples_delay_us == 0
            && self.autopurge_disposed_samples_delay_us == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic functionality tests
    // ========================================================================

    #[test]
    fn test_reader_data_lifecycle_default() {
        let lifecycle = ReaderDataLifecycle::default();
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, i64::MAX);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, i64::MAX);
        assert!(lifecycle.is_keep_all());
        assert!(!lifecycle.is_immediate_cleanup());
    }

    #[test]
    fn test_reader_data_lifecycle_keep_all() {
        let lifecycle = ReaderDataLifecycle::keep_all();
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, i64::MAX);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, i64::MAX);
        assert!(lifecycle.is_keep_all());
    }

    #[test]
    fn test_reader_data_lifecycle_immediate_cleanup() {
        let lifecycle = ReaderDataLifecycle::immediate_cleanup();
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 0);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 0);
        assert!(!lifecycle.is_keep_all());
        assert!(lifecycle.is_immediate_cleanup());
    }

    #[test]
    fn test_reader_data_lifecycle_new() {
        let lifecycle = ReaderDataLifecycle::new(5_000_000, 10_000_000);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 5_000_000);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 10_000_000);
    }

    #[test]
    fn test_reader_data_lifecycle_from_secs() {
        let lifecycle = ReaderDataLifecycle::from_secs(30, 60);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 30_000_000);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 60_000_000);
    }

    #[test]
    fn test_reader_data_lifecycle_clone() {
        let lifecycle1 = ReaderDataLifecycle::immediate_cleanup();
        let lifecycle2 = lifecycle1; // Copy, not clone (ReaderDataLifecycle is Copy)
        assert_eq!(lifecycle1, lifecycle2);
    }

    #[test]
    fn test_reader_data_lifecycle_equality() {
        let lifecycle1 = ReaderDataLifecycle::keep_all();
        let lifecycle2 = ReaderDataLifecycle::keep_all();
        let lifecycle3 = ReaderDataLifecycle::immediate_cleanup();

        assert_eq!(lifecycle1, lifecycle2);
        assert_ne!(lifecycle1, lifecycle3);
    }

    #[test]
    fn test_reader_data_lifecycle_debug() {
        let lifecycle = ReaderDataLifecycle::keep_all();
        let debug_str = format!("{:?}", lifecycle);
        assert!(debug_str.contains("ReaderDataLifecycle"));
        assert!(debug_str.contains("autopurge_nowriter_samples_delay_us"));
    }

    // ========================================================================
    // Use case tests
    // ========================================================================

    #[test]
    fn test_use_case_historical_data() {
        // Keep historical data: INFINITE delays
        let lifecycle = ReaderDataLifecycle::keep_all();
        assert!(lifecycle.is_keep_all());

        // Application can analyze all historical instances,
        // even after writers are gone or instances are disposed
    }

    #[test]
    fn test_use_case_memory_management() {
        // Memory management: purge after 30 seconds
        let lifecycle = ReaderDataLifecycle::from_secs(30, 30);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 30_000_000);

        // Balances memory usage with data retention
    }

    #[test]
    fn test_use_case_real_time_cleanup() {
        // Real-time systems: immediate cleanup
        let lifecycle = ReaderDataLifecycle::immediate_cleanup();
        assert!(lifecycle.is_immediate_cleanup());

        // Minimizes memory footprint in resource-constrained environments
    }

    #[test]
    fn test_use_case_graceful_processing() {
        // Graceful processing: allow time to handle final states
        let lifecycle = ReaderDataLifecycle::from_secs(10, 5);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 10_000_000);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 5_000_000);

        // Application has time to process NOT_ALIVE states before purge
    }

    #[test]
    fn test_use_case_asymmetric_delays() {
        // Asymmetric delays: different cleanup policies for different states
        let lifecycle = ReaderDataLifecycle::new(60_000_000, 5_000_000);

        // Keep NO_WRITERS instances longer (60s) for late-joining apps
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 60_000_000);

        // Purge DISPOSED instances quickly (5s) to free memory
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 5_000_000);
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    #[test]
    fn test_reader_data_lifecycle_zero_delays() {
        let lifecycle = ReaderDataLifecycle::new(0, 0);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 0);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 0);
        assert!(lifecycle.is_immediate_cleanup());
    }

    #[test]
    fn test_reader_data_lifecycle_mixed_delays() {
        // One INFINITE, one immediate
        let lifecycle = ReaderDataLifecycle::new(i64::MAX, 0);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, i64::MAX);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 0);
        assert!(!lifecycle.is_keep_all());
        assert!(!lifecycle.is_immediate_cleanup());
    }

    #[test]
    fn test_reader_data_lifecycle_from_secs_zero() {
        let lifecycle = ReaderDataLifecycle::from_secs(0, 0);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 0);
        assert!(lifecycle.is_immediate_cleanup());
    }

    #[test]
    fn test_reader_data_lifecycle_copy_semantics() {
        let lifecycle1 = ReaderDataLifecycle::from_secs(10, 20);
        let lifecycle2 = lifecycle1; // Copy, not move
        assert_eq!(lifecycle1, lifecycle2);
    }

    #[test]
    fn test_reader_data_lifecycle_field_access() {
        let lifecycle = ReaderDataLifecycle::from_secs(42, 84);
        assert_eq!(lifecycle.autopurge_nowriter_samples_delay_us, 42_000_000);
        assert_eq!(lifecycle.autopurge_disposed_samples_delay_us, 84_000_000);
    }
}

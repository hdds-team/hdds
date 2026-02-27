// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! WRITER_DATA_LIFECYCLE QoS policy (DDS v1.4 Sec.2.2.3.7)
//!
//! Controls the behavior of the DataWriter with regards to the lifecycle
//! of the data instances it manages.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** WRITER_DATA_LIFECYCLE is not part of RxO compatibility checking
//!
//! This policy controls writer-side instance management and does not affect
//! compatibility between readers and writers.
//!
//! # Policy Semantics
//!
//! - **autodispose_unregistered_instances = true** (default): When a DataWriter
//!   unregisters an instance (or is deleted), the instance is automatically
//!   disposed. Readers will receive a NOT_ALIVE_DISPOSED notification.
//! - **autodispose_unregistered_instances = false**: Unregistered instances remain
//!   in the NOT_ALIVE_NO_WRITERS state. Applications must explicitly dispose
//!   instances via `writer.dispose()`.
//!
//! # Use Cases
//!
//! - **Auto-dispose (default)**: Simplifies lifecycle management - instances are
//!   automatically cleaned up when no longer needed
//! - **Manual dispose**: Provides fine-grained control over instance lifecycle,
//!   useful for:
//!   - Coordinating disposal across multiple writers
//!   - Delaying disposal until specific conditions are met
//!   - Custom cleanup logic
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::writer_data_lifecycle::WriterDataLifecycle;
//!
//! // Default: auto-dispose unregistered instances
//! let lifecycle = WriterDataLifecycle::auto_dispose();
//! assert!(lifecycle.autodispose_unregistered_instances);
//!
//! // Manual dispose: keep instances alive after unregister
//! let lifecycle = WriterDataLifecycle::manual_dispose();
//! assert!(!lifecycle.autodispose_unregistered_instances);
//! ```

/// WRITER_DATA_LIFECYCLE QoS policy (DDS v1.4 Sec.2.2.3.7)
///
/// Controls automatic disposal of unregistered instances.
///
/// Default: auto-dispose (true).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterDataLifecycle {
    /// Whether to automatically dispose unregistered instances
    pub autodispose_unregistered_instances: bool,
}

impl Default for WriterDataLifecycle {
    /// Default: auto-dispose unregistered instances
    fn default() -> Self {
        Self::auto_dispose()
    }
}

impl WriterDataLifecycle {
    /// Create WRITER_DATA_LIFECYCLE with custom auto-dispose setting
    ///
    /// # Arguments
    ///
    /// * `autodispose` - Whether to automatically dispose unregistered instances
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::writer_data_lifecycle::WriterDataLifecycle;
    ///
    /// let lifecycle = WriterDataLifecycle::new(true);
    /// assert!(lifecycle.autodispose_unregistered_instances);
    /// ```
    pub fn new(autodispose: bool) -> Self {
        Self {
            autodispose_unregistered_instances: autodispose,
        }
    }

    /// Create WRITER_DATA_LIFECYCLE with auto-dispose (default)
    ///
    /// Unregistered instances are automatically disposed.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::writer_data_lifecycle::WriterDataLifecycle;
    ///
    /// let lifecycle = WriterDataLifecycle::auto_dispose();
    /// assert!(lifecycle.autodispose_unregistered_instances);
    /// ```
    pub fn auto_dispose() -> Self {
        Self {
            autodispose_unregistered_instances: true,
        }
    }

    /// Create WRITER_DATA_LIFECYCLE with manual dispose
    ///
    /// Unregistered instances remain alive until explicitly disposed.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::writer_data_lifecycle::WriterDataLifecycle;
    ///
    /// let lifecycle = WriterDataLifecycle::manual_dispose();
    /// assert!(!lifecycle.autodispose_unregistered_instances);
    /// ```
    pub fn manual_dispose() -> Self {
        Self {
            autodispose_unregistered_instances: false,
        }
    }

    /// Check if auto-dispose is enabled
    pub fn is_auto_dispose(&self) -> bool {
        self.autodispose_unregistered_instances
    }

    /// Check if manual dispose is required
    pub fn is_manual_dispose(&self) -> bool {
        !self.autodispose_unregistered_instances
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic functionality tests
    // ========================================================================

    #[test]
    fn test_writer_data_lifecycle_default() {
        let lifecycle = WriterDataLifecycle::default();
        assert!(lifecycle.autodispose_unregistered_instances);
        assert!(lifecycle.is_auto_dispose());
        assert!(!lifecycle.is_manual_dispose());
    }

    #[test]
    fn test_writer_data_lifecycle_auto_dispose() {
        let lifecycle = WriterDataLifecycle::auto_dispose();
        assert!(lifecycle.autodispose_unregistered_instances);
        assert!(lifecycle.is_auto_dispose());
    }

    #[test]
    fn test_writer_data_lifecycle_manual_dispose() {
        let lifecycle = WriterDataLifecycle::manual_dispose();
        assert!(!lifecycle.autodispose_unregistered_instances);
        assert!(!lifecycle.is_auto_dispose());
        assert!(lifecycle.is_manual_dispose());
    }

    #[test]
    fn test_writer_data_lifecycle_new_true() {
        let lifecycle = WriterDataLifecycle::new(true);
        assert!(lifecycle.autodispose_unregistered_instances);
    }

    #[test]
    fn test_writer_data_lifecycle_new_false() {
        let lifecycle = WriterDataLifecycle::new(false);
        assert!(!lifecycle.autodispose_unregistered_instances);
    }

    #[test]
    fn test_writer_data_lifecycle_clone() {
        let lifecycle1 = WriterDataLifecycle::manual_dispose();
        let lifecycle2 = lifecycle1; // Copy, not clone (WriterDataLifecycle is Copy)
        assert_eq!(lifecycle1, lifecycle2);
    }

    #[test]
    fn test_writer_data_lifecycle_copy() {
        let lifecycle1 = WriterDataLifecycle::auto_dispose();
        let lifecycle2 = lifecycle1;
        assert_eq!(lifecycle1, lifecycle2);
    }

    #[test]
    fn test_writer_data_lifecycle_equality() {
        let lifecycle1 = WriterDataLifecycle::auto_dispose();
        let lifecycle2 = WriterDataLifecycle::auto_dispose();
        let lifecycle3 = WriterDataLifecycle::manual_dispose();

        assert_eq!(lifecycle1, lifecycle2);
        assert_ne!(lifecycle1, lifecycle3);
    }

    #[test]
    fn test_writer_data_lifecycle_debug() {
        let lifecycle = WriterDataLifecycle::auto_dispose();
        let debug_str = format!("{:?}", lifecycle);
        assert!(debug_str.contains("WriterDataLifecycle"));
        assert!(debug_str.contains("autodispose_unregistered_instances"));
    }

    // ========================================================================
    // Use case tests
    // ========================================================================

    #[test]
    fn test_use_case_default_simple_cleanup() {
        // Simple applications: auto-dispose for automatic cleanup
        let lifecycle = WriterDataLifecycle::default();
        assert!(lifecycle.is_auto_dispose());
    }

    #[test]
    fn test_use_case_coordinated_disposal() {
        // Coordinated disposal: manual dispose to synchronize across writers
        let lifecycle = WriterDataLifecycle::manual_dispose();
        assert!(lifecycle.is_manual_dispose());

        // Application would:
        // 1. Unregister instance from multiple writers
        // 2. Coordinate disposal logic
        // 3. Explicitly dispose when ready
    }

    #[test]
    fn test_use_case_conditional_cleanup() {
        // Conditional cleanup: manual dispose for custom logic
        let lifecycle = WriterDataLifecycle::manual_dispose();
        assert!(!lifecycle.autodispose_unregistered_instances);

        // Application would:
        // 1. Unregister instance
        // 2. Check custom conditions (e.g., database cleanup)
        // 3. Dispose only if conditions met
    }

    #[test]
    fn test_use_case_graceful_shutdown() {
        // Graceful shutdown: manual dispose for controlled cleanup
        let lifecycle = WriterDataLifecycle::manual_dispose();
        assert!(lifecycle.is_manual_dispose());

        // Application would:
        // 1. Unregister instances during shutdown
        // 2. Perform cleanup operations
        // 3. Dispose instances in specific order
    }

    #[test]
    fn test_use_case_instance_reuse() {
        // Instance reuse: manual dispose to keep instances alive
        let lifecycle = WriterDataLifecycle::manual_dispose();
        assert!(!lifecycle.autodispose_unregistered_instances);

        // Application would:
        // 1. Unregister instance temporarily
        // 2. Perform operations
        // 3. Re-register instance without disposal
    }

    // ========================================================================
    // Edge cases
    // ========================================================================

    #[test]
    fn test_writer_data_lifecycle_multiple_toggles() {
        let lifecycle1 = WriterDataLifecycle::auto_dispose();
        let lifecycle2 = WriterDataLifecycle::manual_dispose();
        let lifecycle3 = WriterDataLifecycle::auto_dispose();

        assert!(lifecycle1.is_auto_dispose());
        assert!(lifecycle2.is_manual_dispose());
        assert!(lifecycle3.is_auto_dispose());
    }

    #[test]
    fn test_writer_data_lifecycle_from_bool() {
        let lifecycle_true = WriterDataLifecycle::new(true);
        let lifecycle_false = WriterDataLifecycle::new(false);

        assert_eq!(lifecycle_true, WriterDataLifecycle::auto_dispose());
        assert_eq!(lifecycle_false, WriterDataLifecycle::manual_dispose());
    }

    #[test]
    fn test_writer_data_lifecycle_field_access() {
        let lifecycle = WriterDataLifecycle::manual_dispose();
        let autodispose = lifecycle.autodispose_unregistered_instances;
        assert!(!autodispose);
    }
}

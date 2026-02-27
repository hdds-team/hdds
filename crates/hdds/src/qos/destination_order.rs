// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DESTINATION_ORDER QoS policy (DDS v1.4 Sec.2.2.3.8)
//!
//! Controls the order in which samples are presented to the DataReader.
//! Determines whether samples should be ordered by reception time or source timestamp.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** Writer DestinationOrder must be >= Reader DestinationOrder (ordered compatibility)
//!
//! - Writer BY_SOURCE_TIMESTAMP -> Reader BY_SOURCE_TIMESTAMP \[OK\] (exact match)
//! - Writer BY_SOURCE_TIMESTAMP -> Reader BY_RECEPTION_TIMESTAMP \[OK\] (writer is stricter)
//! - Writer BY_RECEPTION_TIMESTAMP -> Reader BY_RECEPTION_TIMESTAMP \[OK\] (exact match)
//! - Writer BY_RECEPTION_TIMESTAMP -> Reader BY_SOURCE_TIMESTAMP \[X\] (incompatible)
//!
//! # Use Cases
//!
//! - **BY_RECEPTION_TIMESTAMP** (default):
//!   - Real-time sensor data (process in arrival order)
//!   - Live streaming (minimize latency)
//!   - Network monitoring (detect reordering)
//!
//! - **BY_SOURCE_TIMESTAMP**:
//!   - Log replay (preserve original temporal order)
//!   - Distributed system event correlation
//!   - Time-series data analysis
//!   - Causal consistency (event A happened before B)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::destination_order::{DestinationOrder, DestinationOrderKind};
//!
//! // Default: Order by reception (arrival order)
//! let reception_order = DestinationOrder::by_reception_timestamp();
//! assert_eq!(reception_order.kind, DestinationOrderKind::ByReceptionTimestamp);
//!
//! // Order by source timestamp (temporal order)
//! let source_order = DestinationOrder::by_source_timestamp();
//! assert_eq!(source_order.kind, DestinationOrderKind::BySourceTimestamp);
//!
//! // Check compatibility (Writer vs Reader)
//! assert!(source_order.is_compatible_with(&reception_order)); // Writer stricter -> OK
//! assert!(!reception_order.is_compatible_with(&source_order)); // Writer looser -> FAIL
//! ```

/// DESTINATION_ORDER kind
///
/// Determines the ordering criterion for samples at the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DestinationOrderKind {
    /// Order samples by reception timestamp (default)
    ///
    /// Samples are delivered in the order they arrive at the reader.
    /// Fastest delivery, no reordering overhead.
    ByReceptionTimestamp = 0,

    /// Order samples by source timestamp
    ///
    /// Samples are delivered in the order they were written at the source.
    /// Requires timestamp propagation and reordering buffer.
    /// Useful for log replay and temporal consistency.
    BySourceTimestamp = 1,
}

impl Default for DestinationOrderKind {
    /// Default: BY_RECEPTION_TIMESTAMP (fastest, no reordering)
    fn default() -> Self {
        Self::ByReceptionTimestamp
    }
}

/// DESTINATION_ORDER QoS policy
///
/// Specifies the order in which samples are presented to the reader.
/// Default: BY_RECEPTION_TIMESTAMP (arrival order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationOrder {
    /// Ordering criterion
    pub kind: DestinationOrderKind,
}

impl Default for DestinationOrder {
    /// Default: BY_RECEPTION_TIMESTAMP (arrival order)
    fn default() -> Self {
        Self::by_reception_timestamp()
    }
}

impl DestinationOrder {
    /// Create BY_RECEPTION_TIMESTAMP policy (default)
    ///
    /// Samples are delivered in arrival order (fastest, no reordering).
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::destination_order::{DestinationOrder, DestinationOrderKind};
    ///
    /// let policy = DestinationOrder::by_reception_timestamp();
    /// assert_eq!(policy.kind, DestinationOrderKind::ByReceptionTimestamp);
    /// ```
    pub fn by_reception_timestamp() -> Self {
        Self {
            kind: DestinationOrderKind::ByReceptionTimestamp,
        }
    }

    /// Create BY_SOURCE_TIMESTAMP policy
    ///
    /// Samples are delivered in source timestamp order (temporal consistency).
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::destination_order::{DestinationOrder, DestinationOrderKind};
    ///
    /// let policy = DestinationOrder::by_source_timestamp();
    /// assert_eq!(policy.kind, DestinationOrderKind::BySourceTimestamp);
    /// ```
    pub fn by_source_timestamp() -> Self {
        Self {
            kind: DestinationOrderKind::BySourceTimestamp,
        }
    }

    /// Check if this writer policy is compatible with a reader policy (RxO)
    ///
    /// # Compatibility Rules
    ///
    /// - Writer BY_SOURCE_TIMESTAMP -> Reader BY_SOURCE_TIMESTAMP \[OK\]
    /// - Writer BY_SOURCE_TIMESTAMP -> Reader BY_RECEPTION_TIMESTAMP \[OK\] (writer stricter)
    /// - Writer BY_RECEPTION_TIMESTAMP -> Reader BY_RECEPTION_TIMESTAMP \[OK\]
    /// - Writer BY_RECEPTION_TIMESTAMP -> Reader BY_SOURCE_TIMESTAMP \[X\] (incompatible)
    ///
    /// # Arguments
    ///
    /// * `requested` - Reader's requested DESTINATION_ORDER policy
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::destination_order::DestinationOrder;
    ///
    /// let writer_source = DestinationOrder::by_source_timestamp();
    /// let reader_reception = DestinationOrder::by_reception_timestamp();
    ///
    /// // Writer BY_SOURCE -> Reader BY_RECEPTION (OK, writer is stricter)
    /// assert!(writer_source.is_compatible_with(&reader_reception));
    ///
    /// // Writer BY_RECEPTION -> Reader BY_SOURCE (FAIL, writer cannot provide source order)
    /// assert!(!reader_reception.is_compatible_with(&writer_source));
    /// ```
    pub fn is_compatible_with(&self, requested: &DestinationOrder) -> bool {
        // Writer kind >= Reader kind (ordered compatibility)
        //
        // BY_SOURCE_TIMESTAMP (1) >= BY_RECEPTION_TIMESTAMP (0) -> OK (writer is stricter)
        // BY_SOURCE_TIMESTAMP (1) >= BY_SOURCE_TIMESTAMP (1) -> OK (exact match)
        // BY_RECEPTION_TIMESTAMP (0) >= BY_RECEPTION_TIMESTAMP (0) -> OK (exact match)
        // BY_RECEPTION_TIMESTAMP (0) >= BY_SOURCE_TIMESTAMP (1) -> FAIL (writer looser)
        self.kind >= requested.kind
    }

    /// Check if policy uses source timestamps (requires timestamp propagation)
    pub fn uses_source_timestamp(&self) -> bool {
        self.kind == DestinationOrderKind::BySourceTimestamp
    }

    /// Check if policy uses reception timestamps (default, fastest)
    pub fn uses_reception_timestamp(&self) -> bool {
        self.kind == DestinationOrderKind::ByReceptionTimestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destination_order_kind_default() {
        let kind = DestinationOrderKind::default();
        assert_eq!(kind, DestinationOrderKind::ByReceptionTimestamp);
    }

    #[test]
    fn test_destination_order_kind_ordering() {
        // BY_RECEPTION_TIMESTAMP (0) < BY_SOURCE_TIMESTAMP (1)
        assert!(
            DestinationOrderKind::ByReceptionTimestamp < DestinationOrderKind::BySourceTimestamp
        );
        assert!(
            DestinationOrderKind::BySourceTimestamp > DestinationOrderKind::ByReceptionTimestamp
        );
    }

    #[test]
    fn test_destination_order_default() {
        let policy = DestinationOrder::default();
        assert_eq!(policy.kind, DestinationOrderKind::ByReceptionTimestamp);
    }

    #[test]
    fn test_destination_order_by_reception_timestamp() {
        let policy = DestinationOrder::by_reception_timestamp();
        assert_eq!(policy.kind, DestinationOrderKind::ByReceptionTimestamp);
        assert!(policy.uses_reception_timestamp());
        assert!(!policy.uses_source_timestamp());
    }

    #[test]
    fn test_destination_order_by_source_timestamp() {
        let policy = DestinationOrder::by_source_timestamp();
        assert_eq!(policy.kind, DestinationOrderKind::BySourceTimestamp);
        assert!(policy.uses_source_timestamp());
        assert!(!policy.uses_reception_timestamp());
    }

    #[test]
    fn test_compatibility_exact_match_reception() {
        let writer = DestinationOrder::by_reception_timestamp();
        let reader = DestinationOrder::by_reception_timestamp();

        assert!(writer.is_compatible_with(&reader)); // Exact match -> OK
    }

    #[test]
    fn test_compatibility_exact_match_source() {
        let writer = DestinationOrder::by_source_timestamp();
        let reader = DestinationOrder::by_source_timestamp();

        assert!(writer.is_compatible_with(&reader)); // Exact match -> OK
    }

    #[test]
    fn test_compatibility_writer_stricter() {
        let writer = DestinationOrder::by_source_timestamp(); // Stricter (provides source order)
        let reader = DestinationOrder::by_reception_timestamp(); // Looser (accepts any order)

        assert!(writer.is_compatible_with(&reader)); // Writer BY_SOURCE -> Reader BY_RECEPTION (OK)
    }

    #[test]
    fn test_incompatibility_writer_looser() {
        let writer = DestinationOrder::by_reception_timestamp(); // Looser (no source order)
        let reader = DestinationOrder::by_source_timestamp(); // Stricter (requires source order)

        assert!(!writer.is_compatible_with(&reader)); // Writer BY_RECEPTION -> Reader BY_SOURCE (FAIL)
    }

    #[test]
    fn test_uses_source_timestamp() {
        let reception = DestinationOrder::by_reception_timestamp();
        let source = DestinationOrder::by_source_timestamp();

        assert!(!reception.uses_source_timestamp());
        assert!(source.uses_source_timestamp());
    }

    #[test]
    fn test_uses_reception_timestamp() {
        let reception = DestinationOrder::by_reception_timestamp();
        let source = DestinationOrder::by_source_timestamp();

        assert!(reception.uses_reception_timestamp());
        assert!(!source.uses_reception_timestamp());
    }

    #[test]
    fn test_destination_order_clone() {
        let policy1 = DestinationOrder::by_source_timestamp();
        let policy2 = policy1;

        assert_eq!(policy1.kind, policy2.kind);
    }

    #[test]
    fn test_destination_order_debug() {
        let policy = DestinationOrder::by_source_timestamp();
        let debug_str = format!("{:?}", policy);

        assert!(debug_str.contains("DestinationOrder"));
        assert!(debug_str.contains("BySourceTimestamp"));
    }

    #[test]
    fn test_destination_order_kind_debug() {
        let kind = DestinationOrderKind::BySourceTimestamp;
        let debug_str = format!("{:?}", kind);

        assert!(debug_str.contains("BySourceTimestamp"));
    }

    #[test]
    fn test_destination_order_equality() {
        let policy1 = DestinationOrder::by_source_timestamp();
        let policy2 = DestinationOrder::by_source_timestamp();
        let policy3 = DestinationOrder::by_reception_timestamp();

        assert_eq!(policy1, policy2);
        assert_ne!(policy1, policy3);
    }

    #[test]
    fn test_compatibility_matrix() {
        let reception = DestinationOrder::by_reception_timestamp();
        let source = DestinationOrder::by_source_timestamp();

        // Writer RECEPTION -> Reader RECEPTION (OK)
        assert!(reception.is_compatible_with(&reception));

        // Writer RECEPTION -> Reader SOURCE (FAIL)
        assert!(!reception.is_compatible_with(&source));

        // Writer SOURCE -> Reader RECEPTION (OK)
        assert!(source.is_compatible_with(&reception));

        // Writer SOURCE -> Reader SOURCE (OK)
        assert!(source.is_compatible_with(&source));
    }

    #[test]
    fn test_destination_order_kind_copy() {
        let kind1 = DestinationOrderKind::BySourceTimestamp;
        let kind2 = kind1; // Copy

        assert_eq!(kind1, kind2);
    }

    #[test]
    fn test_destination_order_copy() {
        let policy1 = DestinationOrder::by_source_timestamp();
        let policy2 = policy1; // Copy

        assert_eq!(policy1, policy2);
    }

    // Use case tests

    #[test]
    fn test_use_case_real_time_sensor() {
        // Real-time sensor data: process in arrival order (minimize latency)
        let policy = DestinationOrder::by_reception_timestamp();

        assert!(policy.uses_reception_timestamp());
        assert!(!policy.uses_source_timestamp());
    }

    #[test]
    fn test_use_case_log_replay() {
        // Log replay: preserve original temporal order
        let policy = DestinationOrder::by_source_timestamp();

        assert!(policy.uses_source_timestamp());
        assert!(!policy.uses_reception_timestamp());
    }

    #[test]
    fn test_use_case_distributed_events() {
        // Distributed system: correlate events by source timestamp
        let writer_policy = DestinationOrder::by_source_timestamp();
        let reader_policy = DestinationOrder::by_source_timestamp();

        assert!(writer_policy.is_compatible_with(&reader_policy));
        assert!(writer_policy.uses_source_timestamp());
    }

    #[test]
    fn test_use_case_network_monitoring() {
        // Network monitoring: detect packet reordering
        let policy = DestinationOrder::by_reception_timestamp();

        assert!(policy.uses_reception_timestamp());
    }
}

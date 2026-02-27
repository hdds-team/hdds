// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TRANSPORT_PRIORITY QoS policy (DDS v1.4 Sec.2.2.3.16)
//!
//! Provides a hint to the DDS implementation about the importance of data,
//! which can be used to control network stack priority (DSCP/ToS fields).
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** TRANSPORT_PRIORITY is a hint (no RxO check required)
//!
//! This policy does not affect compatibility between readers and writers.
//! It provides optimization hints to the transport layer but doesn't
//! enforce any guarantees.
//!
//! # Use Cases
//!
//! - **High-priority data**:
//!   - Emergency alerts (highest priority)
//!   - Control commands (high priority)
//!   - Real-time telemetry (medium-high priority)
//!
//! - **Normal-priority data**:
//!   - Sensor data (default priority)
//!   - Status updates (default priority)
//!
//! - **Low-priority data**:
//!   - Logs (low priority)
//!   - Diagnostics (low priority)
//!   - Bulk transfers (lowest priority)
//!
//! # Network Priority Mapping
//!
//! The `value` field is typically mapped to:
//! - **DSCP (Differentiated Services Code Point)**: 0-63 (6 bits)
//! - **ToS (Type of Service)**: 0-255 (8 bits, legacy)
//!
//! Common DSCP values:
//! - 0: Best Effort (default)
//! - 46: Expedited Forwarding (low-latency, low-loss)
//! - 34: Assured Forwarding 4 (high priority)
//! - 26: Assured Forwarding 3 (medium-high priority)
//! - 18: Assured Forwarding 2 (medium priority)
//! - 10: Assured Forwarding 1 (low priority)
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::transport_priority::TransportPriority;
//!
//! // Emergency alerts: highest priority
//! let emergency = TransportPriority::new(100);
//! assert_eq!(emergency.value, 100);
//!
//! // Normal data: default priority
//! let default = TransportPriority::default();
//! assert_eq!(default.value, 0);
//! ```

/// TRANSPORT_PRIORITY QoS policy
///
/// Specifies the importance of the data, used as a hint for
/// transport-layer prioritization (e.g., DSCP/ToS marking).
///
/// Default: 0 (normal priority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransportPriority {
    /// Priority value (higher = more important)
    ///
    /// Typically mapped to DSCP (0-63) or ToS (0-255) by the transport.
    /// Applications can use arbitrary values; the implementation
    /// scales them to the available network priority range.
    pub value: i32,
}

impl Default for TransportPriority {
    /// Default: Priority 0 (normal priority)
    fn default() -> Self {
        Self::normal()
    }
}

impl TransportPriority {
    /// Create new TRANSPORT_PRIORITY policy with specified value
    ///
    /// # Arguments
    ///
    /// * `value` - Priority value (higher = more important)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::transport_priority::TransportPriority;
    ///
    /// // High-priority control commands
    /// let priority = TransportPriority::new(50);
    /// assert_eq!(priority.value, 50);
    /// ```
    pub fn new(value: i32) -> Self {
        Self { value }
    }

    /// Create TRANSPORT_PRIORITY with normal priority (0)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::transport_priority::TransportPriority;
    ///
    /// let priority = TransportPriority::normal();
    /// assert_eq!(priority.value, 0);
    /// assert!(priority.is_normal());
    /// ```
    pub fn normal() -> Self {
        Self { value: 0 }
    }

    /// Create TRANSPORT_PRIORITY with high priority
    ///
    /// Convenience method for common high-priority data.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::transport_priority::TransportPriority;
    ///
    /// let priority = TransportPriority::high();
    /// assert_eq!(priority.value, 50);
    /// ```
    pub fn high() -> Self {
        Self { value: 50 }
    }

    /// Create TRANSPORT_PRIORITY with low priority
    ///
    /// Convenience method for background/bulk data.
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::transport_priority::TransportPriority;
    ///
    /// let priority = TransportPriority::low();
    /// assert_eq!(priority.value, -50);
    /// ```
    pub fn low() -> Self {
        Self { value: -50 }
    }

    /// Check if priority is normal (0)
    pub fn is_normal(&self) -> bool {
        self.value == 0
    }

    /// Check if priority is high (positive value)
    pub fn is_high(&self) -> bool {
        self.value > 0
    }

    /// Check if priority is low (negative value)
    pub fn is_low(&self) -> bool {
        self.value < 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_priority_default() {
        let priority = TransportPriority::default();
        assert_eq!(priority.value, 0);
        assert!(priority.is_normal());
        assert!(!priority.is_high());
        assert!(!priority.is_low());
    }

    #[test]
    fn test_transport_priority_normal() {
        let priority = TransportPriority::normal();
        assert_eq!(priority.value, 0);
        assert!(priority.is_normal());
    }

    #[test]
    fn test_transport_priority_new() {
        let priority = TransportPriority::new(100);
        assert_eq!(priority.value, 100);
        assert!(!priority.is_normal());
        assert!(priority.is_high());
    }

    #[test]
    fn test_transport_priority_high() {
        let priority = TransportPriority::high();
        assert_eq!(priority.value, 50);
        assert!(priority.is_high());
        assert!(!priority.is_low());
        assert!(!priority.is_normal());
    }

    #[test]
    fn test_transport_priority_low() {
        let priority = TransportPriority::low();
        assert_eq!(priority.value, -50);
        assert!(priority.is_low());
        assert!(!priority.is_high());
        assert!(!priority.is_normal());
    }

    #[test]
    fn test_transport_priority_is_normal() {
        assert!(TransportPriority::normal().is_normal());
        assert!(!TransportPriority::high().is_normal());
        assert!(!TransportPriority::low().is_normal());
        assert!(!TransportPriority::new(1).is_normal());
    }

    #[test]
    fn test_transport_priority_is_high() {
        assert!(TransportPriority::high().is_high());
        assert!(TransportPriority::new(1).is_high());
        assert!(TransportPriority::new(100).is_high());
        assert!(!TransportPriority::normal().is_high());
        assert!(!TransportPriority::low().is_high());
    }

    #[test]
    fn test_transport_priority_is_low() {
        assert!(TransportPriority::low().is_low());
        assert!(TransportPriority::new(-1).is_low());
        assert!(TransportPriority::new(-100).is_low());
        assert!(!TransportPriority::normal().is_low());
        assert!(!TransportPriority::high().is_low());
    }

    #[test]
    fn test_transport_priority_clone() {
        let priority1 = TransportPriority::new(50);
        let priority2 = priority1;

        assert_eq!(priority1.value, priority2.value);
    }

    #[test]
    fn test_transport_priority_debug() {
        let priority = TransportPriority::new(10);
        let debug_str = format!("{:?}", priority);

        assert!(debug_str.contains("TransportPriority"));
    }

    #[test]
    fn test_transport_priority_equality() {
        let priority1 = TransportPriority::new(10);
        let priority2 = TransportPriority::new(10);
        let priority3 = TransportPriority::new(20);

        assert_eq!(priority1, priority2);
        assert_ne!(priority1, priority3);
    }

    #[test]
    fn test_transport_priority_ordering() {
        let low = TransportPriority::low();
        let normal = TransportPriority::normal();
        let high = TransportPriority::high();

        assert!(low < normal);
        assert!(normal < high);
        assert!(low < high);
    }

    // Use case tests

    #[test]
    fn test_use_case_emergency_alerts() {
        // Emergency alerts: highest priority
        let priority = TransportPriority::new(100);

        assert_eq!(priority.value, 100);
        assert!(priority.is_high());
    }

    #[test]
    fn test_use_case_control_commands() {
        // Control commands: high priority
        let priority = TransportPriority::high();

        assert_eq!(priority.value, 50);
        assert!(priority.is_high());
    }

    #[test]
    fn test_use_case_real_time_telemetry() {
        // Real-time telemetry: medium-high priority
        let priority = TransportPriority::new(30);

        assert_eq!(priority.value, 30);
        assert!(priority.is_high());
    }

    #[test]
    fn test_use_case_sensor_data() {
        // Sensor data: normal priority
        let priority = TransportPriority::normal();

        assert_eq!(priority.value, 0);
        assert!(priority.is_normal());
    }

    #[test]
    fn test_use_case_logs() {
        // Logs: low priority
        let priority = TransportPriority::low();

        assert_eq!(priority.value, -50);
        assert!(priority.is_low());
    }

    #[test]
    fn test_use_case_bulk_transfers() {
        // Bulk transfers: lowest priority
        let priority = TransportPriority::new(-100);

        assert_eq!(priority.value, -100);
        assert!(priority.is_low());
    }

    #[test]
    fn test_transport_priority_negative() {
        // Test negative values (background traffic)
        let priority = TransportPriority::new(-25);

        assert_eq!(priority.value, -25);
        assert!(priority.is_low());
    }

    #[test]
    fn test_transport_priority_very_high() {
        // Test very high priority (critical systems)
        let priority = TransportPriority::new(1000);

        assert_eq!(priority.value, 1000);
        assert!(priority.is_high());
    }

    #[test]
    fn test_transport_priority_copy() {
        let priority1 = TransportPriority::new(10);
        let priority2 = priority1; // Copy

        assert_eq!(priority1, priority2);
    }

    #[test]
    fn test_transport_priority_partial_ord() {
        let p1 = TransportPriority::new(10);
        let p2 = TransportPriority::new(20);

        assert!(p1 < p2);
        assert!(p2 > p1);
        assert!(p1 <= p2);
        assert!(p2 >= p1);
    }

    #[test]
    fn test_dscp_range_values() {
        // Common DSCP values (0-63)
        let best_effort = TransportPriority::new(0); // DSCP 0
        let af1 = TransportPriority::new(10); // DSCP 10 (AF11)
        let af2 = TransportPriority::new(18); // DSCP 18 (AF21)
        let af3 = TransportPriority::new(26); // DSCP 26 (AF31)
        let af4 = TransportPriority::new(34); // DSCP 34 (AF41)
        let ef = TransportPriority::new(46); // DSCP 46 (EF - Expedited Forwarding)

        assert_eq!(best_effort.value, 0);
        assert_eq!(af1.value, 10);
        assert_eq!(af2.value, 18);
        assert_eq!(af3.value, 26);
        assert_eq!(af4.value, 34);
        assert_eq!(ef.value, 46);

        // Verify ordering
        assert!(best_effort < af1);
        assert!(af1 < af2);
        assert!(af2 < af3);
        assert!(af3 < af4);
        assert!(af4 < ef);
    }
}

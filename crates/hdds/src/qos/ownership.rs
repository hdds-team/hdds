// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OWNERSHIP QoS policy (DDS v1.4 Sec.2.2.3.11)
//!
//! Controls whether multiple DataWriters can update the same data instance.
//!
//! # QoS Compatibility (Request vs Offered)
//!
//! **Rule:** Writer kind must match Reader kind (exact match required)
//!
//! Example:
//! - Writer SHARED, Reader SHARED -> Compatible \[OK\]
//! - Writer EXCLUSIVE, Reader EXCLUSIVE -> Compatible \[OK\]
//! - Writer SHARED, Reader EXCLUSIVE -> Incompatible \[X\]
//! - Writer EXCLUSIVE, Reader SHARED -> Incompatible \[X\]
//!
//! # Use Cases
//!
//! - Redundant sensors (highest-priority writer wins in EXCLUSIVE mode)
//! - Fail-over systems (backup writer takes over when primary fails)
//! - Multi-robot coordination (exclusive control of shared resources)
//! - Distributed consensus (leader election via OWNERSHIP_STRENGTH)
//!
//! # Kinds
//!
//! - **SHARED** (default): Multiple writers can update the same instance
//! - **EXCLUSIVE**: Only the writer with highest OWNERSHIP_STRENGTH can publish
//!
//! # Examples
//!
//! ```no_run
//! use hdds::qos::ownership::{Ownership, OwnershipKind};
//!
//! // Shared ownership (default) - multiple writers allowed
//! let shared = Ownership::shared();
//!
//! // Exclusive ownership - highest-strength writer wins
//! let exclusive = Ownership::exclusive();
//!
//! // Check compatibility
//! assert!(shared.is_compatible_with(&shared)); // Same kind \[OK\]
//! assert!(!shared.is_compatible_with(&exclusive)); // Different kinds \[X\]
//! ```

use std::sync::atomic::{AtomicI32, Ordering};

/// OWNERSHIP QoS kinds
///
/// Determines whether multiple writers can update the same data instance.
///
/// **Note on Default implementation:**
/// Uses `#[derive(Default)]` + `#[default]` instead of manual `impl Default`.
/// This is the idiomatic Rust way (since 1.62) and satisfies `clippy::derivable_impls`.
/// Behavior is identical to: `impl Default { fn default() -> Self { Self::Shared } }`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OwnershipKind {
    /// Multiple writers can update the same instance (default)
    ///
    /// All samples from all writers are delivered to readers.
    /// No arbitration between writers.
    #[default]
    Shared,

    /// Only the highest-strength writer can publish
    ///
    /// Requires OWNERSHIP_STRENGTH policy to determine priority.
    /// Lower-strength writers are ignored for the same instance.
    Exclusive,
}

/// OWNERSHIP QoS policy
///
/// Specifies whether multiple writers can update the same data instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ownership {
    /// Ownership mode (SHARED or EXCLUSIVE)
    pub kind: OwnershipKind,
}

impl Default for Ownership {
    /// Default: SHARED (multiple writers allowed)
    fn default() -> Self {
        Self {
            kind: OwnershipKind::Shared,
        }
    }
}

impl Ownership {
    /// Create new ownership policy
    ///
    /// # Arguments
    ///
    /// * `kind` - Ownership mode (SHARED or EXCLUSIVE)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::ownership::{Ownership, OwnershipKind};
    ///
    /// let ownership = Ownership::new(OwnershipKind::Exclusive);
    /// ```
    pub fn new(kind: OwnershipKind) -> Self {
        Self { kind }
    }

    /// Create shared ownership (multiple writers allowed)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::ownership::Ownership;
    ///
    /// let ownership = Ownership::shared();
    /// assert_eq!(ownership.kind, hdds::qos::ownership::OwnershipKind::Shared);
    /// ```
    pub fn shared() -> Self {
        Self::new(OwnershipKind::Shared)
    }

    /// Create exclusive ownership (highest-strength writer wins)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::ownership::Ownership;
    ///
    /// let ownership = Ownership::exclusive();
    /// assert_eq!(ownership.kind, hdds::qos::ownership::OwnershipKind::Exclusive);
    /// ```
    pub fn exclusive() -> Self {
        Self::new(OwnershipKind::Exclusive)
    }

    /// Check QoS compatibility between offered (writer) and requested (reader)
    ///
    /// **Rule:** Kinds must match exactly
    ///
    /// # Arguments
    ///
    /// * `requested` - Reader's requested ownership
    ///
    /// # Returns
    ///
    /// `true` if compatible
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::ownership::Ownership;
    ///
    /// let writer_shared = Ownership::shared();
    /// let reader_shared = Ownership::shared();
    /// assert!(writer_shared.is_compatible_with(&reader_shared)); // Same kind \[OK\]
    ///
    /// let writer_exclusive = Ownership::exclusive();
    /// assert!(!writer_shared.is_compatible_with(&writer_exclusive)); // Different kinds \[X\]
    /// ```
    pub fn is_compatible_with(&self, requested: &Ownership) -> bool {
        // Kinds must match exactly
        self.kind == requested.kind
    }
}

/// OWNERSHIP_STRENGTH QoS policy (DDS v1.4 Sec.2.2.3.18)
///
/// Specifies the priority of a DataWriter when OWNERSHIP is EXCLUSIVE.
/// Higher strength wins. Default is 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct OwnershipStrength {
    /// Priority value (higher wins in EXCLUSIVE mode)
    pub value: i32,
}

impl OwnershipStrength {
    /// Create new ownership strength
    ///
    /// # Arguments
    ///
    /// * `value` - Priority value (higher wins)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::ownership::OwnershipStrength;
    ///
    /// let high_priority = OwnershipStrength::new(100);
    /// let low_priority = OwnershipStrength::new(10);
    /// ```
    pub fn new(value: i32) -> Self {
        Self { value }
    }

    /// Create ownership strength with high priority (100)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::ownership::OwnershipStrength;
    ///
    /// let high = OwnershipStrength::high();
    /// assert_eq!(high.value, 100);
    /// ```
    pub fn high() -> Self {
        Self { value: 100 }
    }

    /// Create ownership strength with low priority (-100)
    ///
    /// # Examples
    ///
    /// ```
    /// use hdds::qos::ownership::OwnershipStrength;
    ///
    /// let low = OwnershipStrength::low();
    /// assert_eq!(low.value, -100);
    /// ```
    pub fn low() -> Self {
        Self { value: -100 }
    }
}

/// Ownership arbiter for EXCLUSIVE mode
///
/// Tracks the current owner (highest-strength writer) for a data instance.
#[derive(Debug)]
pub struct OwnershipArbiter {
    /// Current owner's strength (i32::MIN = no owner)
    current_strength: AtomicI32,
}

impl OwnershipArbiter {
    const NO_OWNER: i32 = i32::MIN;

    /// Create new ownership arbiter
    pub fn new() -> Self {
        Self {
            current_strength: AtomicI32::new(Self::NO_OWNER),
        }
    }

    /// Check if a writer can publish (based on strength)
    ///
    /// # Arguments
    ///
    /// * `writer_strength` - Writer's OWNERSHIP_STRENGTH value
    ///
    /// # Returns
    ///
    /// `true` if writer is current owner or has higher strength
    pub fn can_publish(&self, writer_strength: i32) -> bool {
        let current = self.current_strength.load(Ordering::Acquire);

        // No owner yet, or writer has equal/higher strength
        if current == Self::NO_OWNER || writer_strength >= current {
            // Try to become owner
            self.current_strength
                .store(writer_strength, Ordering::Release);
            true
        } else {
            false // Lower strength, rejected
        }
    }

    /// Get current owner's strength
    ///
    /// # Returns
    ///
    /// - `Some(strength)` if there's an owner
    /// - `None` if no owner yet
    pub fn current_owner_strength(&self) -> Option<i32> {
        let strength = self.current_strength.load(Ordering::Acquire);
        if strength == Self::NO_OWNER {
            None
        } else {
            Some(strength)
        }
    }

    /// Reset arbiter (no owner)
    pub fn reset(&self) {
        self.current_strength
            .store(Self::NO_OWNER, Ordering::Release);
    }
}

impl Default for OwnershipArbiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ownership_default() {
        let ownership = Ownership::default();
        assert_eq!(ownership.kind, OwnershipKind::Shared);
    }

    #[test]
    fn test_ownership_shared() {
        let ownership = Ownership::shared();
        assert_eq!(ownership.kind, OwnershipKind::Shared);
    }

    #[test]
    fn test_ownership_exclusive() {
        let ownership = Ownership::exclusive();
        assert_eq!(ownership.kind, OwnershipKind::Exclusive);
    }

    #[test]
    fn test_ownership_kind_default() {
        assert_eq!(OwnershipKind::default(), OwnershipKind::Shared);
    }

    #[test]
    fn test_compatibility_shared_shared() {
        let writer = Ownership::shared();
        let reader = Ownership::shared();
        assert!(writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_compatibility_exclusive_exclusive() {
        let writer = Ownership::exclusive();
        let reader = Ownership::exclusive();
        assert!(writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_incompatibility_shared_exclusive() {
        let writer = Ownership::shared();
        let reader = Ownership::exclusive();
        assert!(!writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_incompatibility_exclusive_shared() {
        let writer = Ownership::exclusive();
        let reader = Ownership::shared();
        assert!(!writer.is_compatible_with(&reader));
    }

    #[test]
    fn test_ownership_clone() {
        let ownership1 = Ownership::exclusive();
        let ownership2 = ownership1;
        assert_eq!(ownership1, ownership2);
    }

    #[test]
    fn test_ownership_strength_default() {
        let strength = OwnershipStrength::default();
        assert_eq!(strength.value, 0);
    }

    #[test]
    fn test_ownership_strength_new() {
        let strength = OwnershipStrength::new(42);
        assert_eq!(strength.value, 42);
    }

    #[test]
    fn test_arbiter_new() {
        let arbiter = OwnershipArbiter::new();
        assert_eq!(arbiter.current_owner_strength(), None);
    }

    #[test]
    fn test_arbiter_first_writer_wins() {
        let arbiter = OwnershipArbiter::new();

        // First writer with strength 10
        assert!(arbiter.can_publish(10));
        assert_eq!(arbiter.current_owner_strength(), Some(10));
    }

    #[test]
    fn test_arbiter_higher_strength_takes_over() {
        let arbiter = OwnershipArbiter::new();

        // Writer 1: strength 10
        assert!(arbiter.can_publish(10));
        assert_eq!(arbiter.current_owner_strength(), Some(10));

        // Writer 2: strength 20 (higher) - takes over
        assert!(arbiter.can_publish(20));
        assert_eq!(arbiter.current_owner_strength(), Some(20));
    }

    #[test]
    fn test_arbiter_lower_strength_rejected() {
        let arbiter = OwnershipArbiter::new();

        // Writer 1: strength 20
        assert!(arbiter.can_publish(20));

        // Writer 2: strength 10 (lower) - rejected
        assert!(!arbiter.can_publish(10));
        assert_eq!(arbiter.current_owner_strength(), Some(20)); // Still writer 1
    }

    #[test]
    fn test_arbiter_equal_strength_accepted() {
        let arbiter = OwnershipArbiter::new();

        // Writer 1: strength 15
        assert!(arbiter.can_publish(15));

        // Writer 2: strength 15 (equal) - accepted
        assert!(arbiter.can_publish(15));
        assert_eq!(arbiter.current_owner_strength(), Some(15));
    }

    #[test]
    fn test_arbiter_reset() {
        let arbiter = OwnershipArbiter::new();

        // Set owner
        assert!(arbiter.can_publish(10));
        assert_eq!(arbiter.current_owner_strength(), Some(10));

        // Reset
        arbiter.reset();
        assert_eq!(arbiter.current_owner_strength(), None);

        // New writer can take over
        assert!(arbiter.can_publish(5));
        assert_eq!(arbiter.current_owner_strength(), Some(5));
    }

    #[test]
    fn test_arbiter_negative_strength() {
        let arbiter = OwnershipArbiter::new();

        // Negative strength is valid (lower priority)
        assert!(arbiter.can_publish(-10));
        assert_eq!(arbiter.current_owner_strength(), Some(-10));

        // Higher (less negative) takes over
        assert!(arbiter.can_publish(-5));
        assert_eq!(arbiter.current_owner_strength(), Some(-5));

        // Positive takes over
        assert!(arbiter.can_publish(0));
        assert_eq!(arbiter.current_owner_strength(), Some(0));
    }
}

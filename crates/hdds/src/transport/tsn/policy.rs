// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Traffic policy types shared between TSN and LowBW transports.

use std::time::Duration;

/// Politique de trafic transversale (TSN + LowBW).
///
/// This struct provides a unified way to specify traffic priorities
/// and deadlines that can be mapped to both TSN (SO_PRIORITY, txtime)
/// and LowBW (scheduler priorities, drop policies).
#[derive(Clone, Copy, Debug, Default)]
pub struct TrafficPolicy {
    /// Priorite applicative.
    pub priority: Priority,

    /// Deadline applicative (semantique).
    /// If set, the transport may drop messages that exceed this deadline.
    pub deadline: Option<Duration>,

    /// Comportement si deadline depassee.
    pub drop_policy: DropPolicy,
}

impl TrafficPolicy {
    /// Create a new traffic policy with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a critical priority policy (P0).
    pub fn critical() -> Self {
        Self {
            priority: Priority::P0,
            drop_policy: DropPolicy::BestEffort,
            deadline: None,
        }
    }

    /// Create a normal priority policy (P1).
    pub fn normal() -> Self {
        Self {
            priority: Priority::P1,
            drop_policy: DropPolicy::BestEffort,
            deadline: None,
        }
    }

    /// Create a best-effort/telemetry policy (P2).
    pub fn telemetry() -> Self {
        Self {
            priority: Priority::P2,
            drop_policy: DropPolicy::DropIfLate,
            deadline: None,
        }
    }

    /// Set priority.
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Set deadline.
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Set drop policy.
    pub fn with_drop_policy(mut self, policy: DropPolicy) -> Self {
        self.drop_policy = policy;
        self
    }

    /// Get the recommended PCP (VLAN Priority Code Point) for TSN.
    ///
    /// Mapping:
    /// - P0 (critical) -> PCP 6
    /// - P1 (normal) -> PCP 4
    /// - P2 (telemetry) -> PCP 2
    pub fn to_pcp(&self) -> u8 {
        self.priority.to_pcp()
    }

    /// Get the recommended traffic class for TSN mqprio.
    pub fn to_traffic_class(&self) -> u8 {
        self.priority.to_traffic_class()
    }
}

/// Priorite applicative.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// Critique (commands, safety-critical).
    /// Highest priority, guaranteed delivery.
    P0,

    /// Normal (sensor data, regular messages).
    #[default]
    P1,

    /// Best-effort (telemetry, bulk data).
    /// May be dropped under congestion.
    P2,
}

impl Priority {
    /// Convert to PCP (VLAN Priority Code Point, 0-7).
    pub fn to_pcp(&self) -> u8 {
        match self {
            Priority::P0 => 6, // High priority
            Priority::P1 => 4, // Normal
            Priority::P2 => 2, // Best-effort
        }
    }

    /// Convert to traffic class (for mqprio).
    pub fn to_traffic_class(&self) -> u8 {
        match self {
            Priority::P0 => 0, // TC0 = highest
            Priority::P1 => 1, // TC1
            Priority::P2 => 2, // TC2 = lowest
        }
    }

    /// Create from PCP value.
    pub fn from_pcp(pcp: u8) -> Self {
        match pcp {
            6..=7 => Priority::P0,
            4..=5 => Priority::P1,
            _ => Priority::P2,
        }
    }

    /// Check if this is critical priority.
    pub fn is_critical(&self) -> bool {
        *self == Priority::P0
    }

    /// Check if this is droppable priority.
    pub fn is_droppable(&self) -> bool {
        *self == Priority::P2
    }
}

/// Comportement si deadline depassee.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DropPolicy {
    /// Try to send anyway (may be late).
    #[default]
    BestEffort,

    /// Drop the message if it would be late.
    DropIfLate,
}

impl DropPolicy {
    /// Check if late messages should be dropped.
    pub fn should_drop_late(&self) -> bool {
        *self == DropPolicy::DropIfLate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_default() {
        let p = Priority::default();
        assert_eq!(p, Priority::P1);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::P0 < Priority::P1);
        assert!(Priority::P1 < Priority::P2);
        assert!(Priority::P0 < Priority::P2);
    }

    #[test]
    fn test_priority_to_pcp() {
        assert_eq!(Priority::P0.to_pcp(), 6);
        assert_eq!(Priority::P1.to_pcp(), 4);
        assert_eq!(Priority::P2.to_pcp(), 2);
    }

    #[test]
    fn test_priority_from_pcp() {
        assert_eq!(Priority::from_pcp(7), Priority::P0);
        assert_eq!(Priority::from_pcp(6), Priority::P0);
        assert_eq!(Priority::from_pcp(5), Priority::P1);
        assert_eq!(Priority::from_pcp(4), Priority::P1);
        assert_eq!(Priority::from_pcp(3), Priority::P2);
        assert_eq!(Priority::from_pcp(0), Priority::P2);
    }

    #[test]
    fn test_priority_to_traffic_class() {
        assert_eq!(Priority::P0.to_traffic_class(), 0);
        assert_eq!(Priority::P1.to_traffic_class(), 1);
        assert_eq!(Priority::P2.to_traffic_class(), 2);
    }

    #[test]
    fn test_priority_is_critical() {
        assert!(Priority::P0.is_critical());
        assert!(!Priority::P1.is_critical());
        assert!(!Priority::P2.is_critical());
    }

    #[test]
    fn test_priority_is_droppable() {
        assert!(!Priority::P0.is_droppable());
        assert!(!Priority::P1.is_droppable());
        assert!(Priority::P2.is_droppable());
    }

    #[test]
    fn test_drop_policy_default() {
        let dp = DropPolicy::default();
        assert_eq!(dp, DropPolicy::BestEffort);
        assert!(!dp.should_drop_late());
    }

    #[test]
    fn test_drop_policy_drop_if_late() {
        let dp = DropPolicy::DropIfLate;
        assert!(dp.should_drop_late());
    }

    #[test]
    fn test_traffic_policy_default() {
        let policy = TrafficPolicy::default();
        assert_eq!(policy.priority, Priority::P1);
        assert!(policy.deadline.is_none());
        assert_eq!(policy.drop_policy, DropPolicy::BestEffort);
    }

    #[test]
    fn test_traffic_policy_critical() {
        let policy = TrafficPolicy::critical();
        assert_eq!(policy.priority, Priority::P0);
        assert_eq!(policy.to_pcp(), 6);
    }

    #[test]
    fn test_traffic_policy_normal() {
        let policy = TrafficPolicy::normal();
        assert_eq!(policy.priority, Priority::P1);
        assert_eq!(policy.to_pcp(), 4);
    }

    #[test]
    fn test_traffic_policy_telemetry() {
        let policy = TrafficPolicy::telemetry();
        assert_eq!(policy.priority, Priority::P2);
        assert_eq!(policy.drop_policy, DropPolicy::DropIfLate);
        assert_eq!(policy.to_pcp(), 2);
    }

    #[test]
    fn test_traffic_policy_builder() {
        let policy = TrafficPolicy::new()
            .with_priority(Priority::P0)
            .with_deadline(Duration::from_millis(10))
            .with_drop_policy(DropPolicy::DropIfLate);

        assert_eq!(policy.priority, Priority::P0);
        assert_eq!(policy.deadline, Some(Duration::from_millis(10)));
        assert_eq!(policy.drop_policy, DropPolicy::DropIfLate);
    }

    #[test]
    fn test_traffic_policy_to_traffic_class() {
        let policy = TrafficPolicy::critical();
        assert_eq!(policy.to_traffic_class(), 0);

        let policy = TrafficPolicy::telemetry();
        assert_eq!(policy.to_traffic_class(), 2);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Quality of Service policies.
//!
//! This module re-exports QoS policies from the top-level [`crate::qos`] module
//! for convenience when using the DDS API.

mod entity;
mod lifecycle;
mod liveliness;
mod ordering;
mod ownership;
mod partition;
mod profile;
mod reliability;
mod transport;

#[cfg(feature = "qos-loaders")]
pub mod loaders;

#[cfg(feature = "qos-loaders")]
pub mod profiles;

#[cfg(feature = "qos-loaders")]
pub mod hot_reload;

// Metadata types re-exported from core (GroupData, TopicData, UserData)
pub use crate::qos::metadata::{GroupData, TopicData, UserData};
pub use entity::EntityFactory;
pub use lifecycle::{ReaderDataLifecycle, WriterDataLifecycle};
pub use liveliness::{Liveliness, LivelinessKind};
pub use ordering::{DestinationOrder, DestinationOrderKind, Presentation, PresentationAccessScope};
pub use ownership::{Ownership, OwnershipKind, OwnershipStrength};
pub use partition::Partition;
pub use profile::QoS;
pub use reliability::{Durability, DurabilityService, History, Reliability};
pub use transport::TransportPriority;

// Timing policies re-exported from core qos/ module (uses Duration-based types)
pub use crate::qos::deadline::Deadline;
pub use crate::qos::latency_budget::LatencyBudget;
pub use crate::qos::lifespan::Lifespan;
pub use crate::qos::time_based_filter::TimeBasedFilter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qos_transient_local_builder() {
        let qos = QoS::best_effort().transient_local();

        assert!(matches!(qos.durability, Durability::TransientLocal));
        assert!(matches!(qos.reliability, Reliability::BestEffort));
    }

    #[test]
    fn test_qos_reliable_transient_local() {
        let qos = QoS::reliable().transient_local().keep_last(50);

        assert!(matches!(qos.durability, Durability::TransientLocal));
        assert!(matches!(qos.reliability, Reliability::Reliable));
        assert!(matches!(qos.history, History::KeepLast(50)));
    }

    #[test]
    fn test_qos_keep_all_builder() {
        let qos = QoS::best_effort().keep_all();

        assert!(matches!(qos.history, History::KeepAll));
        assert!(matches!(qos.reliability, Reliability::BestEffort));
    }

    #[test]
    fn test_qos_volatile_builder() {
        let qos = QoS::reliable().volatile();

        assert!(matches!(qos.durability, Durability::Volatile));
        assert!(matches!(qos.reliability, Reliability::Reliable));
    }

    #[test]
    fn test_qos_persistent_builder() {
        let qos = QoS::best_effort().persistent();

        assert!(matches!(qos.durability, Durability::Persistent));
        assert!(matches!(qos.reliability, Reliability::BestEffort));
    }
}

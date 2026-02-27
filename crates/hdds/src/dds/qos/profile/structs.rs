// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS struct definition with all 22 DDS policies.
//!

use super::super::{
    Deadline, DestinationOrder, Durability, DurabilityService, EntityFactory, GroupData, History,
    LatencyBudget, Lifespan, Liveliness, Ownership, OwnershipStrength, Partition, Presentation,
    ReaderDataLifecycle, Reliability, TimeBasedFilter, TopicData, TransportPriority, UserData,
    WriterDataLifecycle,
};
use crate::qos::ResourceLimits;

/// Aggregated QoS profile used by the public API.
/// All 22 standard DDS QoS policies.
#[derive(Clone, Debug)]
pub struct QoS {
    pub reliability: Reliability,
    pub history: History,
    pub durability: Durability,
    pub deadline: Deadline,
    pub lifespan: Lifespan,
    pub time_based_filter: TimeBasedFilter,
    pub destination_order: DestinationOrder,
    pub presentation: Presentation,
    pub latency_budget: LatencyBudget,
    pub transport_priority: TransportPriority,
    pub liveliness: Liveliness,
    pub ownership: Ownership,
    pub ownership_strength: OwnershipStrength,
    pub partition: Partition,
    pub resource_limits: ResourceLimits,
    pub user_data: UserData,
    pub group_data: GroupData,
    pub topic_data: TopicData,
    pub entity_factory: EntityFactory,
    pub writer_data_lifecycle: WriterDataLifecycle,
    pub reader_data_lifecycle: ReaderDataLifecycle,
    pub durability_service: DurabilityService,
}

impl QoS {
    /// Create BestEffort QoS profile (default baseline).
    pub fn best_effort() -> Self {
        Self {
            reliability: Reliability::BestEffort,
            history: History::KeepLast(100),
            durability: Durability::Volatile,
            deadline: Deadline::infinite(),
            lifespan: Lifespan::infinite(),
            time_based_filter: TimeBasedFilter::zero(),
            destination_order: DestinationOrder::by_reception_timestamp(),
            presentation: Presentation::instance(),
            latency_budget: LatencyBudget::zero(),
            transport_priority: TransportPriority::normal(),
            liveliness: Liveliness::infinite(),
            ownership: Ownership::shared(),
            ownership_strength: OwnershipStrength::default(),
            partition: Partition::default(),
            resource_limits: ResourceLimits::default(),
            user_data: UserData::default(),
            group_data: GroupData::default(),
            topic_data: TopicData::default(),
            entity_factory: EntityFactory::default(),
            writer_data_lifecycle: WriterDataLifecycle::default(),
            reader_data_lifecycle: ReaderDataLifecycle::default(),
            durability_service: DurabilityService::default(),
        }
    }

    /// Create Reliable QoS profile (NACK-driven retransmission enabled).
    pub fn reliable() -> Self {
        Self {
            reliability: Reliability::Reliable,
            history: History::KeepLast(100),
            durability: Durability::Volatile,
            deadline: Deadline::infinite(),
            lifespan: Lifespan::infinite(),
            time_based_filter: TimeBasedFilter::zero(),
            destination_order: DestinationOrder::by_reception_timestamp(),
            presentation: Presentation::instance(),
            latency_budget: LatencyBudget::zero(),
            transport_priority: TransportPriority::normal(),
            liveliness: Liveliness::infinite(),
            ownership: Ownership::shared(),
            ownership_strength: OwnershipStrength::default(),
            partition: Partition::default(),
            resource_limits: ResourceLimits::default(),
            user_data: UserData::default(),
            group_data: GroupData::default(),
            topic_data: TopicData::default(),
            entity_factory: EntityFactory::default(),
            writer_data_lifecycle: WriterDataLifecycle::default(),
            reader_data_lifecycle: ReaderDataLifecycle::default(),
            durability_service: DurabilityService::default(),
        }
    }

    /// Create RTI Connext default QoS profile for interoperability.
    ///
    /// Based on RTI Connext DDS 6.x defaults:
    /// - Reliability: RELIABLE
    /// - Durability: VOLATILE (RTI default, not TransientLocal)
    /// - History: KEEP_LAST(10) (per USER_QOS_PROFILES.xml)
    ///
    /// Reference: `/tests/interop/rti/USER_QOS_PROFILES.xml`
    pub fn rti_defaults() -> Self {
        Self {
            reliability: Reliability::Reliable,
            history: History::KeepLast(10),   // RTI default depth
            durability: Durability::Volatile, // RTI uses VOLATILE by default
            deadline: Deadline::infinite(),
            lifespan: Lifespan::infinite(),
            time_based_filter: TimeBasedFilter::zero(),
            destination_order: DestinationOrder::by_reception_timestamp(),
            presentation: Presentation::instance(),
            latency_budget: LatencyBudget::zero(),
            transport_priority: TransportPriority::normal(),
            liveliness: Liveliness::infinite(),
            ownership: Ownership::shared(),
            ownership_strength: OwnershipStrength::default(),
            partition: Partition::default(),
            resource_limits: ResourceLimits::default(),
            user_data: UserData::default(),
            group_data: GroupData::default(),
            topic_data: TopicData::default(),
            entity_factory: EntityFactory::default(),
            writer_data_lifecycle: WriterDataLifecycle::default(),
            reader_data_lifecycle: ReaderDataLifecycle::default(),
            durability_service: DurabilityService::default(),
        }
    }

    /// Load QoS from FastDDS XML profile file.
    ///
    /// Parses a FastDDS XML profile and extracts QoS policies.
    /// Searches for the first `<data_writer>` or `<data_reader>` profile
    /// with `is_default_profile="true"`.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use hdds::api::QoS;
    ///
    /// let qos = QoS::load_fastdds("fastdds_profile.xml")?;
    /// ```
    #[cfg(feature = "qos-loaders")]
    pub fn load_fastdds<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        crate::trace_fn!("QoS::load_fastdds");
        use crate::dds::qos::loaders::FastDdsLoader;
        FastDdsLoader::load_from_file(path)
    }

    /// Load QoS from vendor XML file (auto-detect vendor).
    ///
    /// Automatically detects the vendor (FastDDS, RTI, etc.) from the XML
    /// structure and loads the appropriate QoS profile.
    ///
    /// Currently supported vendors:
    /// - FastDDS (eProsima)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use hdds::api::QoS;
    ///
    /// let qos = QoS::from_xml("qos_profile.xml")?;
    /// ```
    #[cfg(feature = "qos-loaders")]
    pub fn from_xml<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        crate::trace_fn!("QoS::from_xml");
        // For now, try FastDDS (can add auto-detection later)
        Self::load_fastdds(path)
    }
}

impl Default for QoS {
    fn default() -> Self {
        Self::best_effort()
    }
}

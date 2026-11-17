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
use crate::protocol::discovery::types::TypeConsistencyEnforcement;
use crate::qos::ResourceLimits;

/// The DDS default RELIABILITY `max_blocking_time` ("The default
/// max_blocking_time=100ms", DDS v1.4 Sec.2.2.3.14).
pub const DEFAULT_MAX_BLOCKING_TIME: std::time::Duration = std::time::Duration::from_millis(100);

/// Aggregated QoS profile used by the public API.
/// All 22 standard DDS QoS policies.
#[derive(Clone, Debug)]
pub struct QoS {
    pub reliability: Reliability,
    /// DDS RELIABILITY `max_blocking_time` (DDS v1.4 Sec.2.2.3.14): how long
    /// a RELIABLE writer's `write()` may block for room in its own history or
    /// in a reliable reader's before it returns TIMEOUT. Default 100 ms, the
    /// spec's default. Only meaningful for RELIABLE writers; announced in
    /// SEDP PID_RELIABILITY.
    pub reliability_max_blocking_time: std::time::Duration,
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
    /// Supported data representations (XCDR1=0, XCDR2=2).
    /// Empty means "accept any" (default / unspecified).
    pub data_representation: Vec<u16>,
    /// Type consistency enforcement policy (DDS-XTypes v1.3 sec. 7.6.3.3.3).
    /// `None` means "use the endpoint's default" (permissive: ALLOW_TYPE_COERCION,
    /// ignore_sequence_bounds=true, ignore_string_bounds=true).
    /// Set to `Some(policy)` to advertise an explicit coercion policy via SEDP
    /// `PID_TYPE_CONSISTENCY_ENFORCEMENT` (0x0074), e.g. from OMG harness CLI flags.
    pub type_consistency: Option<TypeConsistencyEnforcement>,
    /// DataTagQosPolicy (DDS-Security v1.1 Sec.7.2.5): the data tags a
    /// remote endpoint announced in PID_DATA_TAGS, which a permissions
    /// document's `<data_tags>` conditions are evaluated against. Empty by
    /// default; HDDS does not announce tags of its own endpoints in this
    /// release, and refuses to create one that has some.
    pub data_tags: crate::qos::data_tags::DataTags,
}

impl QoS {
    /// Create BestEffort QoS profile (default baseline).
    pub fn best_effort() -> Self {
        Self {
            reliability: Reliability::BestEffort,
            reliability_max_blocking_time: DEFAULT_MAX_BLOCKING_TIME,
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
            data_representation: Vec::new(),
            type_consistency: None,
            data_tags: crate::qos::data_tags::DataTags::default(),
        }
    }

    /// Create Reliable QoS profile (NACK-driven retransmission enabled).
    pub fn reliable() -> Self {
        Self {
            reliability: Reliability::Reliable,
            reliability_max_blocking_time: DEFAULT_MAX_BLOCKING_TIME,
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
            data_representation: Vec::new(),
            type_consistency: None,
            data_tags: crate::qos::data_tags::DataTags::default(),
        }
    }

    /// Create the interoperability QoS preset.
    ///
    /// Sets:
    /// - Reliability: RELIABLE
    /// - Durability: VOLATILE
    /// - History: KEEP_LAST(10)
    ///
    /// Every other policy is at its default (same as `reliable()` with a
    /// history depth of 10).
    ///
    /// Deprecated: the name suggests one vendor's defaults, and these values
    /// are not documented as anyone's; they are an HDDS preset. Write
    /// `QoS::reliable().keep_last(10)` for the same profile.
    #[deprecated(
        since = "1.5.0",
        note = "an HDDS preset, not a vendor's defaults: use QoS::reliable().keep_last(10)"
    )]
    pub fn rti_defaults() -> Self {
        Self {
            reliability: Reliability::Reliable,
            reliability_max_blocking_time: DEFAULT_MAX_BLOCKING_TIME,
            history: History::KeepLast(10),
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
            data_representation: Vec::new(),
            type_consistency: None,
            data_tags: crate::qos::data_tags::DataTags::default(),
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
    /// Automatically detects the vendor from the XML
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

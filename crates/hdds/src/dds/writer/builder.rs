// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Builder pattern for DataWriter configuration.
//!
//!
//! Provides fluent API for configuring QoS, transport, history cache,
//! and reliability options before constructing a DataWriter instance.

use super::frag_route::FragRouteProfile;
use super::heartbeat_scheduler::{
    spawn_heartbeat_scheduler, HeartbeatPeriodic, HeartbeatSchedulerState, WriterHeartbeatSink,
    DEFAULT_HEARTBEAT_PERIOD_MS,
};
use super::nack::{RetransmitCfg, WriterNackFragHandler, WriterNackHandler};
use super::runtime::DataWriter;
use super::runtime::WriterReplayState;
use crate::core::discovery::ReplayRegistry;
use crate::core::discovery::GUID;
use crate::core::rt;
use crate::dds::listener::{DataWriterListener, WriterListenerSlot};
use crate::dds::qos::check_history_and_limits;
use crate::dds::{DomainState, Error, MatchKey, QoS, Result, StatusMask, TypeId, DDS};
use crate::protocol::builder::RtpsEndpointContext;
use crate::reliability::{HeartbeatTx, HistoryCache, ReliableMetrics};
use crate::transport::shm::ShmPolicy;
use crate::transport::UdpTransport;
use crate::xtypes::CompleteTypeObject;
use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

/// A DURABILITY_SERVICE limit (`i32`, -1 = LENGTH_UNLIMITED) as a
/// RESOURCE_LIMITS value.
fn service_limit(value: i32) -> usize {
    usize::try_from(value).unwrap_or(crate::reliability::LENGTH_UNLIMITED)
}

/// The HISTORY and RESOURCE_LIMITS the writer's history cache enforces.
///
/// - VOLATILE and TRANSIENT_LOCAL: the writer's own HISTORY and
///   RESOURCE_LIMITS, nothing else. For TRANSIENT_LOCAL, which samples are
///   kept for late joiners "depends on other QoS such as HISTORY and
///   RESOURCE_LIMITS" (DDS 1.4 2.2.3.4), and DURABILITY_SERVICE does not
///   apply (it configures "the service that implements the DURABILITY kind
///   of TRANSIENT and PERSISTENT"; the built-in topics table says it in so
///   many words: "Does not apply as DURABILITY is TRANSIENT_LOCAL").
/// - TRANSIENT and PERSISTENT: HDDS keeps that data in the writer's own
///   cache, which then also plays the persistence service's fictitious
///   reader, whose HISTORY and RESOURCE_LIMITS DURABILITY_SERVICE
///   configures. The cache keeps what either of the two requires.
///
/// Depth and every limit stay PER INSTANCE (2.2.3.18); none of them is
/// turned into a total. Making a durable writer's depth its `max_samples`
/// and adopting DURABILITY_SERVICE `max_instances` (default 1) would make a
/// TRANSIENT_LOCAL KEEP_LAST(1) writer of three instances replay one sample
/// to a late joiner.
pub(super) fn derive_history_and_limits(
    qos: &QoS,
) -> Result<(crate::qos::History, crate::qos::ResourceLimits)> {
    let writer_history = qos.history;
    let writer_limits = qos.resource_limits;
    check_history_and_limits("DataWriter", writer_history, &writer_limits)?;

    match qos.durability {
        super::super::qos::Durability::Volatile | super::super::qos::Durability::TransientLocal => {
            Ok((writer_history, writer_limits))
        }
        super::super::qos::Durability::Transient | super::super::qos::Durability::Persistent => {
            let service = qos.durability_service;
            service
                .validate()
                .map_err(|err| Error::InvalidQos(format!("DurabilityService invalid: {}", err)))?;
            let service_limits = crate::qos::ResourceLimits {
                max_samples: service_limit(service.max_samples),
                max_instances: service_limit(service.max_instances),
                max_samples_per_instance: service_limit(service.max_samples_per_instance),
                max_quota_bytes: writer_limits.max_quota_bytes,
            };
            let history = match writer_history {
                crate::qos::History::KeepAll => crate::qos::History::KeepAll,
                crate::qos::History::KeepLast(depth) => {
                    crate::qos::History::KeepLast(depth.max(service.history_depth))
                }
            };
            // LENGTH_UNLIMITED is `usize::MAX`, so `max` keeps "no limit"
            // whenever either side has none.
            let limits = crate::qos::ResourceLimits {
                max_samples: writer_limits.max_samples.max(service_limits.max_samples),
                max_instances: writer_limits
                    .max_instances
                    .max(service_limits.max_instances),
                max_samples_per_instance: writer_limits
                    .max_samples_per_instance
                    .max(service_limits.max_samples_per_instance),
                max_quota_bytes: writer_limits.max_quota_bytes,
            };
            check_history_and_limits("DataWriter (durability service)", history, &limits)?;
            Ok((history, limits))
        }
    }
}

/// Derive the canonical (XCDR2) encapsulation representation identifier
/// for a writer's serialized payloads per DDS-XTypes v1.3 section
/// 7.6.3.1.2, from the resolved TypeObject extensibility flags:
///
/// - `@final`      -> PLAIN_CDR2_LE (0x0007)
/// - `@appendable` -> D_CDR2_LE     (0x0009) -- delimited CDR2 with DHEADER
/// - `@mutable`    -> PL_CDR2_LE    (0x000B) -- EMHEADER per member
///
/// Both struct and union extensibility flags are honored (mutable checked
/// before appendable; a TypeObject never carries both in practice, but the
/// stronger framing wins if it did). Any other or absent TypeObject falls
/// back to PLAIN_CDR2_LE.
///
/// `override_kind`, when present, takes precedence over the derivation:
/// raw-bytes writers that suppress the TypeObject from SEDP (so
/// `type_object` is `None`) but still frame their bodies as
/// appendable/mutable use it to keep the wire encap consistent with the
/// body bytes. The per-write wire encap still degrades this canonical
/// form to the matching XCDR1 code when XCDR1 is negotiated (see
/// `encap_kind_for_version`).
fn canonical_encapsulation_kind(
    type_object: Option<&CompleteTypeObject>,
    override_kind: Option<u16>,
) -> u16 {
    if let Some(kind) = override_kind {
        return kind;
    }
    match type_object {
        Some(CompleteTypeObject::Struct(s))
            if s.struct_flags
                .contains(crate::xtypes::StructTypeFlag::IS_MUTABLE) =>
        {
            0x000B // PL_CDR2_LE
        }
        Some(CompleteTypeObject::Struct(s))
            if s.struct_flags
                .contains(crate::xtypes::StructTypeFlag::IS_APPENDABLE) =>
        {
            0x0009 // D_CDR2_LE (delimited, with DHEADER)
        }
        Some(CompleteTypeObject::Union(u))
            if u.union_flags
                .contains(crate::xtypes::UnionTypeFlag::IS_MUTABLE) =>
        {
            0x000B // PL_CDR2_LE
        }
        Some(CompleteTypeObject::Union(u))
            if u.union_flags
                .contains(crate::xtypes::UnionTypeFlag::IS_APPENDABLE) =>
        {
            0x0009 // D_CDR2_LE (delimited, with DHEADER)
        }
        _ => 0x0007, // PLAIN_CDR2_LE (default for @final or unknown)
    }
}

pub struct WriterBuilder<T: DDS> {
    pub(super) topic: String,
    pub(super) qos: QoS,
    pub(super) transport: Option<Arc<UdpTransport>>,
    pub(super) registry: Option<Arc<crate::engine::TopicRegistry>>,
    pub(super) endpoint_registry: Option<crate::core::discovery::EndpointRegistry>,
    pub(super) discovery_fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    pub(super) participant: Option<Arc<crate::Participant>>,
    pub(super) domain_state: Option<Arc<DomainState>>,
    pub(super) serialized_keys: bool,
    pub(super) type_name_override: Option<String>,
    pub(super) type_object_override: Option<CompleteTypeObject>,
    /// The writer has no type of its own and adopts the name its topic's
    /// readers announce (`adopting_type_name`).
    pub(super) adopt_type_name: bool,
    /// `type_name_override` is announced alone: no TypeObject registered
    /// under that name is attached (set when the name was adopted).
    pub(super) type_name_only: bool,
    /// Explicit canonical (XCDR2) encapsulation kind for the writer's
    /// serialized payloads. When set, this takes precedence over the
    /// kind derived from the resolved TypeObject extensibility flags.
    /// Needed by raw-writer applications that suppress the TypeObject
    /// from SEDP (e.g. force_type_validation interop tests) but still
    /// publish appendable/mutable XCDR2 bodies: without a TypeObject
    /// the builder would otherwise fall back to PLAIN_CDR2 (0x0007)
    /// while the body carries a DHEADER, which strict peers reject.
    pub(super) encapsulation_kind_override: Option<u16>,
    pub(super) replay_registry: Option<ReplayRegistry>,
    /// Per-ENDPOINT shared-memory policy. `None` means "inherit the
    /// participant's", which is the default and what every existing caller
    /// gets; `Some` is an explicit override by this writer.
    ///
    /// It has to be an Option: `ShmPolicy::default()` is `Disable`, so a plain
    /// field cannot tell "never asked" from "asked for Disable", and inheriting
    /// would silently beat an explicit opt-out.
    ///
    /// Not `#[cfg(target_os = "linux")]`: shared memory is Linux-only, but
    /// `ShmPolicy` and `ShmPolicy::resolve` exist on every platform (a
    /// no-op stub elsewhere), and `effective_shm_policy()` below is called
    /// unconditionally, so gating this field alone would fail every
    /// non-Linux build.
    pub(super) shm_policy: Option<ShmPolicy>,
    /// Listener for writer callbacks
    pub(super) listener: Option<Arc<dyn DataWriterListener<T>>>,
    #[cfg(test)]
    pub(crate) deadline_clock: Option<Arc<dyn crate::dds::liveliness::LivelinessClock>>,
    /// Parent Publisher for coherent-set tracking (RTPS v2.5 sec. 8.7.5).
    /// Set via `.publisher(&pub)`; when present the writer registers
    /// itself with the publisher's coherent-set registry and tags
    /// samples written inside a `begin/end_coherent_changes` window
    /// with `PID_COHERENT_SET` (+ `PID_GROUP_COHERENT_SET` when the
    /// publisher access_scope is GROUP).
    pub(super) publisher: Option<Arc<crate::dds::publisher::PublisherCore>>,
    pub(super) _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> WriterBuilder<T> {
    pub(crate) fn new(topic: String) -> Self {
        Self {
            topic,
            qos: QoS::best_effort(),
            transport: None,
            registry: None,
            endpoint_registry: None,
            discovery_fsm: None,
            participant: None,
            domain_state: None,
            serialized_keys: false,
            type_name_override: None,
            type_object_override: None,
            adopt_type_name: false,
            type_name_only: false,
            encapsulation_kind_override: None,
            replay_registry: None,
            shm_policy: None,
            listener: None,
            #[cfg(test)]
            deadline_clock: None,
            publisher: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// The writer belongs to the Publisher of `core`, as `publisher` does,
    /// for a Publisher that is not shared (`Publisher::create_writer`).
    pub(crate) fn in_publisher(mut self, core: &Arc<crate::dds::publisher::PublisherCore>) -> Self {
        self.publisher = Some(Arc::clone(core));
        self
    }

    /// Attach a parent Publisher so this writer participates in
    /// `Publisher::begin/end_coherent_changes` and emits ECS DATA
    /// submessages per RTPS v2.5 sec. 8.7.5. Pass the Arc returned by
    /// `participant.create_publisher(...)`. Required for any test or
    /// application that exercises GROUP-scope coherent_access.
    pub fn publisher(mut self, publisher: &Arc<crate::dds::Publisher>) -> Self {
        self.publisher = Some(Arc::clone(&publisher.core));
        self
    }

    pub(crate) fn with_participant(mut self, participant: Arc<crate::Participant>) -> Self {
        self.participant = Some(participant);
        self
    }

    pub fn qos(mut self, q: QoS) -> Self {
        self.qos = q;
        self
    }

    /// Override the participant's shared-memory policy FOR THIS WRITER.
    ///
    /// - `Prefer`: use shared memory when the pairing qualifies (same realm,
    ///   both sides BEST_EFFORT), UDP otherwise. On a platform with no SHM
    ///   data path this always resolves to UDP.
    /// - `Require`: refuse to fall back to UDP behind your back. On a
    ///   platform with no SHM data path this is refused at
    ///   `ParticipantBuilder::build()`, never silently downgraded.
    /// - `Disable`: always UDP.
    ///
    /// Left unset, the writer follows the participant. An application that
    /// turns SHM off for one writer never gets it for that writer.
    pub fn shm_policy(mut self, policy: ShmPolicy) -> Self {
        self.shm_policy = Some(policy);
        self
    }

    /// The shared-memory policy this writer actually runs under: its own when
    /// it set one, the participant's otherwise, and `Disable` with no
    /// participant.
    ///
    /// Both consumers MUST go through here. The pairing verdict
    /// (`register_writer_full`) and the data leg must not read the policy
    /// separately: once an endpoint can override it, the two could disagree -
    /// pairing electing shared memory while the send path stays on UDP, or the
    /// reverse.
    fn effective_shm_policy(&self) -> crate::transport::shm::ShmPolicy {
        crate::transport::shm::ShmPolicy::resolve(
            self.shm_policy,
            self.participant.as_ref().map(|p| p.shm_policy()),
        )
    }

    pub fn with_transport(mut self, transport: Arc<UdpTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn with_registry(mut self, registry: Arc<crate::engine::TopicRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn with_endpoint_registry(
        mut self,
        endpoint_registry: crate::core::discovery::EndpointRegistry,
    ) -> Self {
        self.endpoint_registry = Some(endpoint_registry);
        self
    }

    pub fn with_discovery_fsm(
        mut self,
        fsm: Arc<crate::core::discovery::multicast::DiscoveryFsm>,
    ) -> Self {
        self.discovery_fsm = Some(fsm);
        self
    }

    pub fn with_domain_state(mut self, domain_state: Arc<DomainState>) -> Self {
        self.domain_state = Some(domain_state);
        self
    }

    pub fn with_replay_registry(mut self, replay_registry: ReplayRegistry) -> Self {
        self.replay_registry = Some(replay_registry);
        self
    }

    pub(crate) fn with_serialized_keys(mut self, enabled: bool) -> Self {
        self.serialized_keys = enabled;
        self
    }

    pub(crate) fn with_type_name_override(mut self, type_name: impl Into<String>) -> Self {
        self.type_name_override = Some(type_name.into());
        self
    }

    /// Announce `type_name` for this writer in discovery instead of the
    /// type's own name, so it matches a remote reader announcing that name
    /// (the same override `Participant::create_writer_with_type` applies).
    pub fn with_type_name(self, type_name: impl Into<String>) -> Self {
        self.with_type_name_override(type_name)
    }

    /// Mark this writer as having no type of its own (a byte-payload
    /// writer): with no type name given, it announces the type registered
    /// for its topic, else the name its topic's readers already announce
    /// (XTypes 1.3 Sec.7.6.3.4.2 Step 2), else the placeholder `RawBytes`.
    /// An endpoint created for a type must not call this: it announces its
    /// own type's name. Decided once, at `build()`. Blocks `build()` for up
    /// to `HDDS_TYPE_ADOPT_WAIT_MS` when set and nothing is announced yet.
    pub fn adopting_type_name(mut self) -> Self {
        self.adopt_type_name = true;
        self
    }

    pub(crate) fn with_type_object_override(mut self, type_object: CompleteTypeObject) -> Self {
        self.type_object_override = Some(type_object);
        self
    }

    /// Force the canonical (XCDR2) encapsulation kind for this writer's
    /// serialized payloads, bypassing the TypeObject-derived default.
    ///
    /// Valid values are the canonical XCDR2 representation identifiers
    /// (DDS-XTypes v1.3 section 7.6.3.1.2): `0x0007` PLAIN_CDR2_LE,
    /// `0x0009` D_CDR2_LE, `0x000B` PL_CDR2_LE. The per-write wire encap
    /// still degrades to the matching XCDR1 code when the negotiated CDR
    /// version is XCDR1 (see `encap_kind_for_version`).
    ///
    /// Intended for raw-bytes writers that suppress the TypeObject from
    /// SEDP but publish appendable/mutable bodies; when unset, behavior
    /// is unchanged (kind derived from the resolved TypeObject).
    pub(crate) fn with_encapsulation_kind_override(mut self, kind: u16) -> Self {
        self.encapsulation_kind_override = Some(kind);
        self
    }

    /// Set a listener for writer callbacks.
    ///
    /// The listener will be called when samples are written and for
    /// other writer events like publication matching.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, QoS, DataWriterListener};
    /// use std::sync::Arc;
    ///
    /// struct MyListener;
    ///
    /// impl<T: hdds::DDS> DataWriterListener<T> for MyListener {
    ///     fn on_sample_written(&self, sample: &T, seq: u64) {
    ///         println!("Written sample with seq {}", seq);
    ///     }
    /// }
    ///
    /// let writer = participant
    ///     .create_writer::<Temperature>("temp", QoS::default())
    ///     .with_listener(Arc::new(MyListener))
    ///     .build()?;
    /// ```
    pub fn with_listener(mut self, listener: Arc<dyn DataWriterListener<T>>) -> Self {
        self.listener = Some(listener);
        self
    }

    pub fn build(mut self) -> Result<DataWriter<T>> {
        // DATA_REPRESENTATION is resolved here, once, before anything reads
        // the QoS: the announcement, every verdict, `get_qos()` and every
        // encode see the one representation this writer offers
        // (DDS-XTypes v1.3 Sec.7.6.3.1.1).
        let set_no_representation = self.qos.data_representation.is_empty();
        let cdr_version = crate::dds::cdr_negotiation::resolve_writer_data_representation(
            &mut self.qos,
            crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
        )
        .map_err(|_| {
            crate::dds::Error::InvalidQos(format!(
                "DATA_REPRESENTATION {:?}: a writer offers its first element; HDDS \
                 serializes XCDR (0) and XCDR2 (2) only, and XCDR (0) only when the \
                 type's encode/decode actually produces the XCDR1 layout \
                 (DDS::encodes_xcdr1_natively)",
                self.qos.data_representation
            ))
        })?;
        if set_no_representation && cdr_version == crate::dds::CdrVersion::Xcdr2 {
            log::info!(
                "[writer] topic='{}' type='{}': no DATA_REPRESENTATION set and the type does \
                 not encode XCDR natively; this writer offers and encodes XCDR2",
                self.topic,
                T::type_descriptor().type_name
            );
        }

        // Extract configs from participant if not explicitly provided
        if let Some(ref participant) = self.participant {
            if self.transport.is_none() {
                if let Some(ref transport) = participant.transport {
                    self.transport = Some(transport.clone());
                }
            }
            if self.registry.is_none() {
                if let Some(ref registry) = participant.registry {
                    self.registry = Some(registry.clone());
                }
            }
            if self.endpoint_registry.is_none() {
                if let Some(ref fsm) = participant.discovery_fsm {
                    self.endpoint_registry = Some(fsm.endpoint_registry());
                }
            }
            if self.discovery_fsm.is_none() {
                if let Some(ref fsm) = participant.discovery_fsm {
                    self.discovery_fsm = Some(fsm.clone());
                }
            }
            if self.replay_registry.is_none() {
                if let Some(ref fsm) = participant.discovery_fsm {
                    self.replay_registry = Some(fsm.replay_registry());
                }
            }
            if self.domain_state.is_none() {
                self.domain_state = Some(participant.domain_state.clone());
            }
            // Make T's TypeObject servable to a peer that asks via
            // TypeLookup (OMG getTypes / HTLK), without touching the SEDP
            // announcement path -- see `Participant::register_served_type`.
            #[cfg(feature = "xtypes-structural-assignability")]
            participant.register_served_type::<T>();
            // The name announced in SEDP and the one the intra-process
            // match key is built from are settled here, once.
            let settled = participant.settle_type(
                &self.topic,
                crate::dds::DiscoveredEndpointKind::Writer,
                self.type_name_override.take(),
                self.type_object_override.take(),
                self.adopt_type_name,
            );
            self.type_name_override = settled.name;
            self.type_object_override = settled.object;
            self.type_name_only = settled.name_only;
        }

        // A zero period asks for an unbounded number of periodic events.
        // Refuse it explicitly instead of pinning the scheduler in place.
        if self.qos.deadline.period.is_zero() {
            return Err(Error::InvalidQos(
                "deadline period must be positive".to_string(),
            ));
        }

        // DataTagQosPolicy (DDS-Security v1.1 Sec.7.2.5): HDDS does not
        // announce an endpoint's data tags (PID_DATA_TAGS) in this release,
        // and a peer would judge the endpoint as untagged. Refused rather
        // than ignored.
        if !self.qos.data_tags.is_empty() {
            return Err(Error::InvalidQos(
                "data_tags on a local endpoint: this release does not announce data tags \
                 (PID_DATA_TAGS), so no peer could apply a permissions <data_tags> condition \
                 to them"
                    .to_string(),
            ));
        }

        // DDS Security: Check access control permissions for writer creation
        #[cfg(feature = "security")]
        if let Some(ref participant) = self.participant {
            // Every partition the endpoint names, and its data tags
            // (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4, 9.4.1.3.2.3.1.5).
            participant.check_create_writer(
                &self.topic,
                &self.qos,
                crate::dds::participant::EndpointKeyHooks {
                    has_key: T::has_key() || self.serialized_keys,
                    keys_round_trip: T::keys_round_trip() || self.serialized_keys,
                },
            )?;
        }

        let (history_policy, resource_limits) = derive_history_and_limits(&self.qos)?;

        let history_cache = match (self.qos.reliability, self.qos.durability) {
            (super::super::qos::Reliability::Reliable, _) => {
                let qos_profile = crate::qos::QosProfile {
                    reliability: crate::qos::Reliability::Reliable,
                    history: history_policy,
                    durability: match self.qos.durability {
                        super::super::qos::Durability::Volatile => crate::qos::Durability::Volatile,
                        super::super::qos::Durability::TransientLocal
                        | super::super::qos::Durability::Transient => {
                            crate::qos::Durability::TransientLocal
                        }
                        super::super::qos::Durability::Persistent => {
                            crate::qos::Durability::Persistent
                        }
                    },
                    resource_limits,
                };

                let slab_pool = rt::get_slab_pool();
                Some(Arc::new(HistoryCache::new_with_history(
                    slab_pool,
                    &qos_profile.resource_limits,
                    qos_profile.history,
                )))
            }
            (
                super::super::qos::Reliability::BestEffort,
                super::super::qos::Durability::TransientLocal
                | super::super::qos::Durability::Transient
                | super::super::qos::Durability::Persistent,
            ) => {
                let durability = match self.qos.durability {
                    super::super::qos::Durability::Persistent => crate::qos::Durability::Persistent,
                    _ => crate::qos::Durability::TransientLocal,
                };
                let qos_profile = crate::qos::QosProfile {
                    reliability: crate::qos::Reliability::BestEffort,
                    history: history_policy,
                    durability,
                    resource_limits,
                };

                let slab_pool = rt::get_slab_pool();
                Some(Arc::new(HistoryCache::new_with_history(
                    slab_pool,
                    &qos_profile.resource_limits,
                    qos_profile.history,
                )))
            }
            (
                super::super::qos::Reliability::BestEffort,
                super::super::qos::Durability::Volatile,
            ) => None,
        };

        // Propagate LIFESPAN QoS to the history cache so expired samples are
        // pruned automatically and cannot be retransmitted (DDS 2.2.2.4.2.20).
        if let Some(ref cache) = history_cache {
            if !self.qos.lifespan.is_infinite() {
                let nanos =
                    u64::try_from(self.qos.lifespan.duration.as_nanos()).unwrap_or(u64::MAX);
                cache.set_lifespan_nanos(nanos);
            }
            // How a full history gets room back (see HistoryCache): a
            // RELIABLE writer gives up only what every matched reader has
            // acknowledged, a durable one keeps acknowledged changes for late
            // joiners. No reliable reader is matched yet, so every change is
            // acknowledged by all of them; pairing lowers the floor.
            cache.set_release_policy(
                matches!(
                    self.qos.reliability,
                    super::super::qos::Reliability::Reliable
                ),
                !matches!(self.qos.durability, super::super::qos::Durability::Volatile),
            );
            cache.set_acked_floor(u64::MAX);
        }

        let heartbeat_tx = match self.qos.reliability {
            super::super::qos::Reliability::Reliable => Some(RefCell::new(HeartbeatTx::new())),
            super::super::qos::Reliability::BestEffort => None,
        };

        let reliable_metrics = match self.qos.reliability {
            super::super::qos::Reliability::Reliable => Some(Arc::new(ReliableMetrics::new())),
            super::super::qos::Reliability::BestEffort => None,
        };

        // Determine the type's canonical (XCDR2) encapsulation kind from
        // its extensibility flag. The wire encap is derived per-write
        // from this canonical form combined with the negotiated CDR
        // version (XCDR2 keeps it as-is; XCDR1 degrades to the matching
        // XCDR1 wire code) -- see `encap_kind_for_version`.
        //
        // @final      -> PLAIN_CDR2_LE (0x0007)
        // @appendable -> D_CDR2_LE     (0x0009) -- delimited CDR2 with DHEADER
        // @mutable    -> PL_CDR2_LE    (0x000B)
        //
        // Falls back to T::get_type_object() when no override is set so
        // the standard topic.writer().build() path picks up the correct
        // canonical kind from the type's DDS trait implementation.
        //
        // Computed outside the participant block so the NACK retransmit
        // fallback path can use the true canonical kind even without an
        // RTPS endpoint context.
        let resolved_type_object = self
            .type_object_override
            .clone()
            .or_else(|| T::get_type_object());
        let encapsulation_kind = canonical_encapsulation_kind(
            resolved_type_object.as_ref(),
            self.encapsulation_kind_override,
        );

        // An AUTOMATIC writer's liveliness is its participant's: asserted
        // from now on, before any peer learns of the writer below.
        let liveliness = self
            .participant
            .as_ref()
            .and_then(|p| p.liveliness.as_ref())
            .filter(|_| self.qos.liveliness.kind == crate::dds::qos::LivelinessKind::Automatic)
            .and_then(|l| l.shared().local_writer(self.qos.liveliness.lease_duration));

        // Build RTPS endpoint context (if participant is available) so DATA
        // packets use the same GUID prefix/entity IDs as SEDP announcements.
        //
        // The announcement's retirement goes to the writer, whose Drop runs it
        // (`SedpRetirement`); an error below drops it here, which retires the
        // endpoint that was announced but never built.
        let (rtps_endpoint, sedp_retirement) = if let Some(ref participant) = self.participant {
            // The writer's Publisher: the one it is created through, or the
            // participant's implicit one. Its SEDP announcement and its
            // GROUP-scope members and ends of set name it.
            let publisher_entity_id = self.publisher.as_ref().map_or_else(
                || participant.implicit_publisher_entity_id(),
                |core| core.entity_id,
            );
            let retirement = if let Some(ref type_name) = self.type_name_override {
                participant.announce_writer_endpoint_with_type::<T>(
                    &self.topic,
                    &self.qos,
                    type_name,
                    self.type_object_override.clone(),
                    self.type_name_only,
                    self.serialized_keys,
                    publisher_entity_id,
                )?
            } else {
                participant.announce_writer_endpoint_in::<T>(
                    &self.topic,
                    &self.qos,
                    publisher_entity_id,
                )?
            };
            let guid = participant.guid();
            // ENTITYID_UNKNOWN as default; send_packet_to_endpoints_classed()
            // patches in the real reader entity ID per-reader for cross-vendor
            // interop (RTPS v2.5 Sec.8.3.8.2).
            let reader_entity_id = [0, 0, 0, 0x00];

            (
                Some(RtpsEndpointContext {
                    guid_prefix: guid.prefix,
                    reader_entity_id,
                    writer_entity_id: retirement.entity_id(),
                    encapsulation_kind,
                    publisher_entity_id,
                }),
                Some(retirement),
            )
        } else {
            (None, None)
        };

        let next_seq = 1u64;
        // Created before discovery registration: the per-peer hook below
        // reads it the moment a reader matches, and the catch-up at
        // registration already matches readers discovered earlier.
        let next_seq_atomic = Arc::new(AtomicU64::new(next_seq));
        let wire_windows = history_cache
            .as_ref()
            .map_or_else(Arc::default, |cache| Arc::clone(&cache.wire_windows));
        let presentation = window_presentation(self.publisher.as_deref(), self.qos.presentation);
        let group_presentation = presentation.is_group_scope()
            && (presentation.coherent_access || presentation.ordered_access);
        wire_windows.configure(group_presentation);
        // Per-reader cumulative ack watermarks, fed by the nack handler and
        // read by DataWriter::fully_acked(). Created unconditionally so the
        // writer struct always has one (empty map = nothing to wait for).
        let ack_track: Arc<std::sync::Mutex<std::collections::HashMap<[u8; 16], u64>>> =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        // Shared large-payload route: ONE instance for the live write path
        // and both nack handlers so every DATA_FRAG emitter fragments with
        // the same size (see frag_route module docs).
        // DEFAULT_FRAGMENT_SIZE is a usize constant; the route holds the
        // u16 the DATA_FRAG.fragmentSize field carries, so the constant is
        // checked against that width once, here, when the writer is built.
        let default_fragment_size = u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
            .map_err(|_| {
                Error::InvalidState(format!(
                    "DEFAULT_FRAGMENT_SIZE {} does not fit the u16 DATA_FRAG fragmentSize field",
                    crate::protocol::builder::DEFAULT_FRAGMENT_SIZE
                ))
            })?;
        let frag_route = Arc::new(FragRouteProfile::new(default_fragment_size));
        let mut nack_handler_token = None;
        if let (Some(ref cache), Some(ref transport), Some(ref registry), Some(ref metrics)) = (
            &history_cache,
            &self.transport,
            &self.registry,
            &reliable_metrics,
        ) {
            // Register NACK handler for sequence-level retransmission.
            // Pass endpoint_registry so the handler can route retransmits
            // unicast to the specific NACKing reader instead of multicast.
            let handler = Arc::new(WriterNackHandler::new(
                self.topic.clone(),
                cache.clone(),
                transport.clone(),
                metrics.clone(),
                RetransmitCfg {
                    rtps_endpoint,
                    endpoint_registry: self.endpoint_registry.clone(),
                    canonical_encapsulation_kind: encapsulation_kind,
                    ack_track: Some(ack_track.clone()),
                    frag_route: frag_route.clone(),
                    // Vendor resolution for dialect-correct ECS close repair.
                    discovery_fsm: self.discovery_fsm.clone(),
                },
            ));
            let mut nack_ids = vec![registry.register_nack_handler(handler)];

            // Register NACK_FRAG handler for fragment-level retransmission.
            if let Some(ctx) = rtps_endpoint {
                let frag_handler = Arc::new(WriterNackFragHandler::new(
                    self.topic.clone(),
                    cache.clone(),
                    transport.clone(),
                    metrics.clone(),
                    ctx.writer_entity_id,
                    RetransmitCfg {
                        rtps_endpoint: Some(ctx),
                        endpoint_registry: self.endpoint_registry.clone(),
                        canonical_encapsulation_kind: encapsulation_kind,
                        // Fragment-level ACKNACKs do not carry the sample
                        // watermark; only the DATA-level handler feeds it.
                        // This one reads it, to refuse what is not owed.
                        ack_track: Some(ack_track.clone()),
                        frag_route: frag_route.clone(),
                        discovery_fsm: self.discovery_fsm.clone(),
                    },
                ));
                nack_ids.push(registry.register_nack_frag_handler(frag_handler));
            }
            nack_handler_token = Some(crate::engine::NackHandlerToken::new(registry, nack_ids));
        }

        // DurabilityService cleanup timer (DDS v1.4 Sec.2.2.3.5).
        //
        // `service_cleanup_delay` governs the TRANSIENT/PERSISTENT
        // "persistence service", not TRANSIENT_LOCAL: a delay of 0 is the
        // default and means "no timed cleanup", so no thread is spawned for
        // the overwhelming majority of writers either way.
        //
        // TRANSIENT_LOCAL is NOT in this match. Its history serves late
        // joiners directly from the writer, bounded by HISTORY /
        // RESOURCE_LIMITS alone (DDS v1.4 Sec.2.2.3.4), the same as
        // `derive_history_and_limits` already holds it to neither of
        // DurabilityService's own HISTORY/RESOURCE_LIMITS. Wiring it into
        // this timer would remove every acknowledged sample on a plain
        // delay, with none of Sec.2.2.3.5's three conditions (disposed, no
        // live writer, delay since both) checked: a late joiner that
        // matched after every current reader had acked would get an empty
        // history instead of the KEEP_LAST depth it is owed.
        //
        // A VOLATILE writer keeps no history for late joiners in the first
        // place, and DurabilityService does not apply to it either (see
        // `derive_history_and_limits`).
        //
        // The timer reads `ack_track`, the SAME map the ACKNACK path fills
        // in `nack.rs`, through the same minimum `DataWriter::acked_through`
        // computes. Not a second counter: two copies of one rule are rarely
        // symmetric.
        //
        // The timer is what implements the cleanup half of the public
        // DURABILITY_SERVICE QoS (see docs/qos-guide.md).
        let cleanup_timer = match (&history_cache, self.qos.durability) {
            (Some(cache), super::super::qos::Durability::Transient)
            | (Some(cache), super::super::qos::Durability::Persistent)
                if self.qos.durability_service.service_cleanup_delay_us > 0 =>
            {
                let delay = std::time::Duration::from_micros(
                    self.qos.durability_service.service_cleanup_delay_us,
                );
                // Poll at half the delay so a sample is removed within one
                // delay of becoming eligible, never later than two.
                let interval = (delay / 2).max(std::time::Duration::from_millis(1));
                let track = ack_track.clone();
                // Enable BEFORE the timer thread starts, which is also
                // before this writer is handed to its caller: no insert
                // can race the flag going true (`enable_durability_cleanup`).
                cache.enable_durability_cleanup();
                Some(super::cleanup_timer::spawn_cleanup_timer(
                    Arc::clone(cache),
                    Arc::new(move || {
                        let map = match track.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        map.values().copied().min().unwrap_or(0)
                    }),
                    interval,
                    self.qos
                        .durability_service
                        .service_cleanup_delay_us
                        .saturating_mul(1_000),
                )?)
            }
            _ => None,
        };

        let merger = if let Some(ref cache) = history_cache {
            let needs_late_joiner = matches!(
                self.qos.durability,
                super::super::qos::Durability::TransientLocal
                    | super::super::qos::Durability::Transient
                    | super::super::qos::Durability::Persistent
            );

            if needs_late_joiner {
                let slab_pool = rt::get_slab_pool();
                rt::TopicMerger::with_history(cache.clone(), slab_pool)
            } else {
                rt::TopicMerger::new()
            }
        } else {
            rt::TopicMerger::new()
        };
        let merger = Arc::new(merger.with_ordered_pairing(
            (self.qos.presentation.coherent_access
                || (self.qos.presentation.is_group_scope()
                    && self.qos.presentation.ordered_access))
                && self.publisher.is_some(),
        ));

        if matches!(
            self.qos.reliability,
            super::super::qos::Reliability::Reliable
        ) {
            if let Some(cache) = &history_cache {
                merger.set_acknowledgments(crate::reliability::local_ack::LocalAckWriter {
                    track: ack_track.clone(),
                    cache: cache.clone(),
                    volatile: self.qos.durability == super::super::qos::Durability::Volatile,
                });
            }
        }

        // Name the writer behind the merger for the EXCLUSIVE readers of this
        // process, which arbitrate it like a remote writer (DDS v1.4
        // Sec.2.2.3.9.2): its GUID, or, for a writer of no participant, an
        // identity of its own (`local_writer_identity`), and its strength.
        // The instances it holds are shared with every reader of this
        // process: an unregister or a departure leaves an instance without
        // writers only if no writer, local or remote, still holds it (DDS
        // v1.4 Sec.2.2.2.4.2.7).
        let written_instances: Arc<rt::WriterInstances> = Arc::default();
        merger.set_writer(rt::MergerWriter {
            guid: rtps_endpoint
                .as_ref()
                .map_or_else(local_writer_identity, |ctx| {
                    GUID::new(ctx.guid_prefix, ctx.writer_entity_id).as_bytes()
                }),
            strength: self.qos.ownership_strength.value,
            instances: Arc::downgrade(&written_instances),
        });

        // Registering this writer in domain state (intra-process
        // auto-binding) is deferred to just after the match/incompatible-QoS
        // callbacks are built below (`bind_token`): a participant with no
        // `match_registry` (IntraProcess) drives PUBLICATION_MATCHED /
        // OFFERED_INCOMPATIBLE_QOS from THAT registration instead of from
        // `match_registry`, and matching a reader already registered on this
        // key must report the match before any TRANSIENT_LOCAL history the
        // same call replays to it (DDS v1.4 Sec.2.2.4.1; see
        // `domain_registry::LocalMatchStatus`).

        // `replay_state` is kept alongside `replay_token` (not just captured
        // by the callback closure) so `DataWriter::stats()` has a handle to
        // read this writer's OWN ECS-replay outcome counters: per-writer
        // counters are preferred over process-wide statics, and
        // `WriterReplayState` can own them cheaply (five `AtomicU64`s, no
        // allocation).
        let (replay_token, replay_state) = if matches!(
            self.qos.durability,
            super::super::qos::Durability::TransientLocal
                | super::super::qos::Durability::Transient
                | super::super::qos::Durability::Persistent
        ) {
            if let (Some(ref cache), Some(ref transport), Some(ref registry)) =
                (&history_cache, &self.transport, &self.replay_registry)
            {
                let type_name = self
                    .type_name_override
                    .as_deref()
                    .unwrap_or(T::type_descriptor().type_name)
                    .to_string();
                let state = Arc::new(WriterReplayState::new(
                    self.topic.clone(),
                    rtps_endpoint,
                    transport.clone(),
                    cache.clone(),
                    self.discovery_fsm.clone(),
                ));
                let callback_state = Arc::clone(&state);
                let token = registry.register(
                    self.topic.clone(),
                    type_name,
                    Arc::new(move |endpoint, reader_guid| {
                        callback_state.replay_to(endpoint, reader_guid);
                    }),
                );
                (Some(token), Some(state))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Get security plugin from participant if available
        #[cfg(feature = "security")]
        let security = self.participant.as_ref().and_then(|p| p.security());

        // DDS-Security data plane: mint this writer's key and register it for
        // distribution. One random AES-256 key per WRITER (option B): the
        // writer produces one ciphertext for all destinations, and the
        // distribution sweep announces (GUID, key id, key) to each
        // authenticated peer under that peer's key-wrap envelope.
        //
        // Minted only when the participant asked for encryption AND the writer
        // has an RTPS endpoint: without an endpoint there is no wire to
        // encrypt for, and every write already fails closed.
        #[cfg(feature = "security")]
        if let (Some(suite), Some(ctx)) = (security.as_ref(), rtps_endpoint) {
            if suite.cryptographic().is_some() {
                // CryptoTransformKeyId is octet[4] on both the token and
                // protected payload (DDS-Security 1.1 Sec.9.5.2.1.1-2).
                let (key_id, mut material) = crate::security::crypto::data_keys::WriterKey::mint()
                    .map_err(|e| {
                        Error::Config(format!(
                            "{} -- refusing to build a writer that could only ever emit \
                             cleartext or nothing",
                            e
                        ))
                    })?;
                let attributes =
                    crate::security::crypto::user_data::endpoint_security_info(suite, &self.topic)
                        .map_err(|e| Error::Config(e.to_string()))?;
                if attributes.is_payload_protected() && !attributes.is_payload_encrypted() {
                    material = material.with_transformation(
                        crate::security::crypto::secure_submessage::Transformation::Aes256Gmac,
                    );
                }
                let key_id = u64::from(key_id);

                let writer_guid = GUID::new(ctx.guid_prefix, ctx.writer_entity_id);
                let installed = suite.data_keys.insert(writer_guid, key_id, material);
                // Fail closed: a key the store refused (degraded audit chain)
                // would never be distributed, and a writer that seals with a
                // key nobody can receive is a writer that can only emit noise.
                installed.map_err(|e| {
                    Error::Config(format!(
                        "cannot register the data-plane key for writer {:?}: {}",
                        writer_guid, e
                    ))
                })?;
                log::debug!(
                    "[writer] minted data-plane key for {:?} (key_id={:#x}) on topic '{}'",
                    writer_guid,
                    key_id,
                    self.topic
                );
            }
        }

        // Periodic HEARTBEAT for RELIABLE writers (RTPS 2.5 Section
        // 8.4.7.2): sent even when the writer is idle, enabling reliable
        // recovery after bursts. An entry on the participant's liveliness
        // scheduler (`crate::dds::liveliness`) when the writer has one --
        // instead of a dedicated per-writer thread -- or, for a writer built
        // with no participant (a standalone constructor, no scheduler to
        // join), its own thread.
        let heartbeat_scheduler: Option<HeartbeatPeriodic> = match (
            &self.transport,
            &history_cache,
            rtps_endpoint,
            self.qos.reliability,
        ) {
            (Some(transport), Some(cache), Some(ctx), super::super::qos::Reliability::Reliable) => {
                let participant_scheduler = self
                    .participant
                    .as_ref()
                    .and_then(|p| p.liveliness.as_ref())
                    .map(|l| Arc::clone(l.shared()));
                match participant_scheduler {
                    Some(shared) => {
                        log::debug!(
                            "[writer] periodic HEARTBEAT for topic '{}' on the participant's liveliness scheduler (period={}ms)",
                            self.topic,
                            DEFAULT_HEARTBEAT_PERIOD_MS
                        );
                        let sink = Arc::new(WriterHeartbeatSink::new(
                            transport.clone(),
                            cache.clone(),
                            ctx,
                            self.topic.clone(),
                            self.discovery_fsm.clone(),
                            self.endpoint_registry.clone(),
                            self.publisher.clone().filter(|core| core.group_scope),
                        ));
                        let watch_sink: Weak<dyn crate::dds::liveliness::HeartbeatSink> =
                            Arc::downgrade(&sink)
                                as Weak<dyn crate::dds::liveliness::HeartbeatSink>;
                        let watch = shared.watch_heartbeat(
                            watch_sink,
                            std::time::Duration::from_millis(DEFAULT_HEARTBEAT_PERIOD_MS),
                        );
                        Some(HeartbeatPeriodic::Participant { watch, sink })
                    }
                    None => {
                        log::debug!(
                            "[writer] Spawning periodic heartbeat thread for topic '{}' (period={}ms)",
                            self.topic,
                            DEFAULT_HEARTBEAT_PERIOD_MS
                        );
                        Some(HeartbeatPeriodic::Standalone(spawn_heartbeat_scheduler(
                            transport.clone(),
                            cache.clone(),
                            ctx,
                            DEFAULT_HEARTBEAT_PERIOD_MS,
                            self.topic.clone(),
                            self.discovery_fsm.clone(),
                            self.endpoint_registry.clone(),
                            self.publisher.clone().filter(|core| core.group_scope),
                        )))
                    }
                }
            }
            _ => None,
        };

        // Capture scheduler state for the VOLATILE firstSN floor. This
        // lets the match callback (below) snapshot `last_seq` at the moment
        // the first reader matches, so subsequent HEARTBEATs hide samples
        // produced before the subscriber existed. See heartbeat_scheduler.rs
        // `first_eligible_seq` doc-comment for the full rationale and the
        // known single-reader limitation.
        let scheduler_state_for_match: Option<Arc<HeartbeatSchedulerState>> =
            heartbeat_scheduler.as_ref().map(|h| Arc::clone(h.state()));
        let writer_is_volatile =
            matches!(self.qos.durability, super::super::qos::Durability::Volatile);

        // Shared-memory data path. `shm_selected` is handed to the match
        // registry, which latches it the first time a matched remote reader
        // resolves to SHM; until then the writer's send loop pays exactly
        // one relaxed atomic load per packet for the whole feature.
        let shm_selected = Arc::new(AtomicBool::new(false));

        // The ring itself is created lazily on the first SHM-selected send
        // (a segment is ~1 MB of /dev/shm and most BEST_EFFORT writers never
        // pair with a co-located reader), but the writer only gets a leg at
        // all when its configuration could ever produce one: SHM not
        // disabled, BEST_EFFORT (SHM carries no retransmission, so Reliable
        // stays on UDP), a real RTPS endpoint context to name the segment
        // from, and a domain id the reader can reconstruct that name with.
        #[cfg(target_os = "linux")]
        let shm_leg = {
            // This writer's own policy wins when it set one; otherwise it
            // inherits the participant's. No participant at all means no
            // shared memory.
            let policy = self.effective_shm_policy();
            let best_effort = matches!(
                self.qos.reliability,
                crate::dds::qos::Reliability::BestEffort
            );
            match (
                policy,
                best_effort,
                rtps_endpoint,
                self.domain_state.as_ref(),
            ) {
                (crate::transport::shm::ShmPolicy::Disable, _, _, _) => None,
                (_, false, _, _) => None,
                (_, true, Some(ctx), Some(domain_state)) => {
                    Some(super::runtime::ShmWriterLeg::new(
                        domain_state.domain_id,
                        GUID::new(ctx.guid_prefix, ctx.writer_entity_id),
                    ))
                }
                _ => None,
            }
        };

        // Register match notification (match / incompatible QoS / inconsistent
        // topic) when a participant is present. Counters are tracked even
        // without a listener so counter-only OMG tests see accurate values via
        // the MatchEntry status fields.
        // The writer's listener slot: every callback site holds it, so
        // `DataWriter::set_listener` reaches them all at runtime.
        let listener_slot = Arc::new(WriterListenerSlot::<T>::new(self.listener.take()));
        // This writer's StatusCondition (DDS v1.4 Sec.2.2.2.1.1.5
        // `get_statuscondition`), raised by the match callbacks below and
        // `DataWriter::check_offered_deadline`.
        let status_condition = Arc::new(crate::dds::StatusCondition::new());

        // This writer's own hand on its MANUAL_BY_PARTICIPANT or
        // MANUAL_BY_TOPIC liveliness (DDS v1.4 Sec.2.2.3.11), and the
        // LIVELINESS_LOST watch it feeds (Sec.2.2.4.1): both on the exact
        // same `Renewal`, the writer's own lease. `None` for AUTOMATIC or
        // an infinite lease -- the write() hot path then costs nothing
        // new (one `Option` check).
        let (liveliness_manual, liveliness_assert, liveliness_lost) = match (
            self.participant
                .as_ref()
                .and_then(|p| p.liveliness.as_ref()),
            self.qos.liveliness.is_infinite(),
        ) {
            (Some(l), false) => {
                let shared = l.shared();
                match self.qos.liveliness.kind {
                    crate::dds::qos::LivelinessKind::ManualByParticipant => {
                        let manual_lease =
                            shared.local_manual_writer(self.qos.liveliness.lease_duration);
                        let assert = shared.writer_assert_participant();
                        let slot = Arc::clone(&listener_slot);
                        let wl = crate::dds::liveliness::WriterLiveliness::new(
                            Arc::clone(shared),
                            assert.renewal(),
                            self.qos.liveliness.lease_duration,
                            Arc::clone(&status_condition),
                            Box::new(move |status| {
                                let l = slot.get(StatusMask::LIVELINESS_LOST)?;
                                Some(Box::new(move || l.on_liveliness_lost(status))
                                    as crate::dds::reader::notices::Notice)
                            }),
                        );
                        (manual_lease, Some(assert), Some(wl))
                    }
                    crate::dds::qos::LivelinessKind::ManualByTopic => {
                        let assert = shared.writer_assert_own();
                        let slot = Arc::clone(&listener_slot);
                        let wl = crate::dds::liveliness::WriterLiveliness::new(
                            Arc::clone(shared),
                            assert.renewal(),
                            self.qos.liveliness.lease_duration,
                            Arc::clone(&status_condition),
                            Box::new(move |status| {
                                let l = slot.get(StatusMask::LIVELINESS_LOST)?;
                                Some(Box::new(move || l.on_liveliness_lost(status))
                                    as crate::dds::reader::notices::Notice)
                            }),
                        );
                        (None, Some(assert), Some(wl))
                    }
                    crate::dds::qos::LivelinessKind::Automatic => (None, None, None),
                }
            }
            _ => (None, None, None),
        };

        // This writer's per-instance DEADLINE watches (DDS v1.4
        // Sec.2.2.3.7): `None` with an infinite deadline (the default).
        // See `ReaderBuilder::build`'s `deadlines` for why a writer with
        // no participant gets its own `Shared` (no scheduler thread,
        // lazy-only detection) instead of nothing at all.
        let deadlines = (!self.qos.deadline.is_infinite()).then(|| {
            let shared = self
                .participant
                .as_ref()
                .and_then(|p| p.liveliness.as_ref())
                .map(|l| Arc::clone(l.shared()));
            let lazy_only = shared.is_none();
            let shared = shared.unwrap_or_else(|| {
                #[cfg(test)]
                if let Some(clock) = self.deadline_clock.as_ref() {
                    return crate::dds::liveliness::Shared::new(Arc::clone(clock));
                }
                crate::dds::liveliness::Shared::new(Arc::new(
                    crate::dds::liveliness::MonotonicClock::new(),
                ))
            });
            let slot = Arc::clone(&listener_slot);
            crate::dds::liveliness::WriterDeadlines::new(
                shared,
                self.qos.deadline.period,
                Arc::clone(&status_condition),
                Box::new(move |status| {
                    let l = slot.get(crate::dds::StatusMask::OFFERED_DEADLINE_MISSED)?;
                    Some(Box::new(move || l.on_offered_deadline_missed(status))
                        as crate::dds::reader::notices::Notice)
                }),
                lazy_only,
            )
        });

        // Shared with the `DataWriter` below exactly like `status_condition`:
        // the match callback writes PUBLICATION_MATCHED /
        // OFFERED_INCOMPATIBLE_QOS state here, and the matching getter reads
        // and resets the same `Arc` -- same pattern as
        // `ReaderBuilder::build`'s `subscription_matched` /
        // `requested_incompatible_qos`.
        let publication_matched = Arc::new(std::sync::Mutex::new(
            crate::dds::listener::PublicationMatchedStatus::default(),
        ));
        let offered_incompatible_qos = Arc::new(std::sync::Mutex::new(
            crate::dds::listener::OfferedIncompatibleQosStatus::default(),
        ));
        // `match_cb` / `incompat_cb` are shared between whichever
        // registries end up driving them: `match_registry` (SEDP: remote
        // peers, and a local peer caught by the loopback self-announce)
        // when the participant has one, and `domain_registry::
        // LocalMatchStatus` (this writer's own `bind_token` below)
        // ALWAYS -- not only when there is no `match_registry`. A writer
        // with a real transport can still be matched, through
        // domain_registry.rs alone, with a reader that has none at all
        // (IntraProcess): such a reader is never announced over SEDP, so
        // `match_registry` can never report it, and PUBLICATION_MATCHED
        // for it stayed at 0 forever without this fallback (the
        // mixed-transport gap). domain_registry.rs fires this status only
        // for a pair where the peer has no wire path either
        // (`local_status_applies`): a same-participant pair where BOTH
        // sides are wire-capable is SEDP's loopback to report, never
        // double-counted here. Every side effect inside `match_cb` besides
        // the listener call (the durable-writer announce, the VOLATILE
        // floor bump) already reads through an `Option` that is `None`
        // with no transport, so sharing it costs IntraProcess nothing it
        // would not already skip.
        let (match_token, match_status) = if let Some(ref participant) = self.participant {
            let scheduler_state_for_closure = scheduler_state_for_match.clone();
            let listener_for_match = Arc::clone(&listener_slot);
            {
                // Durable-writer announce heartbeat (see inside the callback).
                let announce_transport = self.transport.clone();
                let announce_ctx = rtps_endpoint;
                let announce_sent = Arc::new(std::sync::atomic::AtomicBool::new(false));

                // A reader of this participant is matched like any other
                // (`MatchNotificationRegistry::on_endpoint_discovered`) but
                // is fed through the merger: nothing on the wire is for it.
                let own_prefix = rtps_endpoint.map(|ctx| ctx.guid_prefix);
                let publication_matched_for_match = Arc::clone(&publication_matched);
                let status_condition_for_match = Arc::clone(&status_condition);
                #[allow(clippy::type_complexity)]
                let match_cb: Arc<
                    dyn Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync,
                > = Arc::new(
                    move |total,
                          total_change,
                          current,
                          current_change,
                          last_handle: Option<GUID>| {
                        let local_reader =
                            last_handle.is_some_and(|guid| Some(guid.prefix) == own_prefix);
                        // Durable writers announce with a valid-count HEARTBEAT
                        // (firstSN=1, lastSN=0: empty history) the moment the
                        // first reader matches and BEFORE any sample exists.
                        // Classic readers arm the reliable writer proxy
                        // only on a HEARTBEAT they consider valid; the periodic
                        // scheduler skips while last_seq == 0 and the immediate
                        // write-path HB starts at count=0, so without this
                        // announce the first samples always race proxy arming
                        // and are silently discarded, forcing a repair of the
                        // first coherent window. Only
                        // fires when nothing was written yet, so durable
                        // writers with pre-match history (Durability tests)
                        // keep their existing wire behavior.
                        if !writer_is_volatile
                            && current > 0
                            && !local_reader
                            && !announce_sent.swap(true, Ordering::Relaxed)
                        {
                            if let (Some(ref transport), Some(ref ctx), Some(ref state)) = (
                                &announce_transport,
                                &announce_ctx,
                                &scheduler_state_for_closure,
                            ) {
                                if state.announced_last_seq() == 0 {
                                    // This runs on a discovery thread, never
                                    // the writer's own: `try_with_next_count`
                                    // (not the blocking `with_next_count`)
                                    // so a concurrent piggyback HEARTBEAT for
                                    // THIS writer, holding send_serial, can
                                    // never make a discovery thread wait --
                                    // a direct `next_count()` +
                                    // `transport.send` call would bypass
                                    // serialization entirely, risking the
                                    // out-of-order-wire defect that lock
                                    // closes for every other origin. On contention, the
                                    // announcement is not dropped: `fire_
                                    // heartbeat_tick` retries it on this
                                    // writer's own next due periodic tick
                                    // (`announce_pending`), as many times as
                                    // it takes.
                                    let fired = state.try_with_next_count(|count| {
                                        let packet =
                                    crate::protocol::builder::build_heartbeat_packet_with_context(
                                        ctx, 1, 0, count,
                                    );
                                        let _ = transport.send(&packet);
                                    });
                                    if fired.is_none() {
                                        state.mark_announce_pending();
                                    }
                                }
                            }
                        }
                        // Before the user listener fires, if the writer
                        // is VOLATILE and we are observing a real match
                        // (current_count > 0, i.e. at least one reader), take
                        // the current `last_seq` snapshot and install it as
                        // the HEARTBEAT floor. The CAS in bump_first_eligible
                        // ensures only the first match wins; later matches
                        // are no-ops (see known limitation in the field's
                        // doc-comment). A RELIABLE reader installed it earlier,
                        // at its discovery pairing (`peer_cb` below), with the
                        // watermark its ReaderProxy took then; this one only
                        // ever installs it for a writer whose first match is
                        // best-effort.
                        if writer_is_volatile && current > 0 && !local_reader {
                            if let Some(ref state) = scheduler_state_for_closure {
                                let last_seq = state.announced_last_seq();
                                let _ = state.bump_first_eligible(last_seq);
                            }
                        }
                        // PUBLICATION_MATCHED (DDS v1.4 Sec.2.2.4.1):
                        // accumulate here always, whether or not a
                        // listener is installed, so a later
                        // `get_publication_matched_status` sees every
                        // event -- same rule as `ReaderBuilder::build`'s
                        // SUBSCRIPTION_MATCHED.
                        let listener = listener_for_match.get(StatusMask::PUBLICATION_MATCHED);
                        let mut status = publication_matched_for_match
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        status.total_count = total;
                        status.total_count_change =
                            status.total_count_change.saturating_add(total_change);
                        status.current_count = current;
                        status.current_count_change =
                            status.current_count_change.saturating_add(current_change);
                        status.last_subscription_handle = last_handle;
                        if let Some(l) = listener {
                            let snap = status.clone();
                            status.total_count_change = 0;
                            status.current_count_change = 0;
                            drop(status);
                            status_condition_for_match
                                .clear_active_status(StatusMask::PUBLICATION_MATCHED);
                            // Out of the match registry's dispatch (`notices`).
                            crate::dds::reader::notices::notify(move || {
                                l.on_publication_matched(snap);
                            });
                        } else {
                            drop(status);
                            status_condition_for_match
                                .raise_active_statuses(StatusMask::PUBLICATION_MATCHED);
                            let sc = Arc::clone(&status_condition_for_match);
                            crate::dds::reader::notices::notify(move || {
                                sc.notify_waitsets_for(StatusMask::PUBLICATION_MATCHED);
                            });
                        }
                    },
                );

                #[allow(clippy::type_complexity)]
                // Always registered: a listener installed after the build
                // must be reached (the registry counts only while a
                // callback is registered).
                let incompat_cb: Arc<dyn Fn(u32, i32, u32) + Send + Sync> = {
                    let slot = Arc::clone(&listener_slot);
                    let offered_incompatible_qos_for_match = Arc::clone(&offered_incompatible_qos);
                    let status_condition_for_incompat = Arc::clone(&status_condition);
                    Arc::new(move |total: u32, total_change: i32, policy_id: u32| {
                        // OFFERED_INCOMPATIBLE_QOS (DDS v1.4
                        // Sec.2.2.4.1): same always-accumulate rule as
                        // PUBLICATION_MATCHED above.
                        let listener = slot.get(StatusMask::OFFERED_INCOMPATIBLE_QOS);
                        let mut status = offered_incompatible_qos_for_match
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        status.total_count = total;
                        status.total_count_change =
                            status.total_count_change.saturating_add(total_change);
                        status.last_policy_id = policy_id;
                        if let Some(l) = listener {
                            status.total_count_change = 0;
                            drop(status);
                            status_condition_for_incompat
                                .clear_active_status(StatusMask::OFFERED_INCOMPATIBLE_QOS);
                            let policy_name = crate::dds::qos::policy_id::name(policy_id);
                            crate::dds::reader::notices::notify(move || {
                                l.on_offered_incompatible_qos(policy_id, policy_name);
                            });
                        } else {
                            drop(status);
                            status_condition_for_incompat
                                .raise_active_statuses(StatusMask::OFFERED_INCOMPATIBLE_QOS);
                            let sc = Arc::clone(&status_condition_for_incompat);
                            crate::dds::reader::notices::notify(move || {
                                sc.notify_waitsets_for(StatusMask::OFFERED_INCOMPATIBLE_QOS);
                            });
                        }
                    })
                };

                // ALWAYS built: this writer's own `bind_token` registration
                // (below) is the ONLY source of PUBLICATION_MATCHED /
                // OFFERED_INCOMPATIBLE_QOS for a peer domain_registry.rs can
                // see but SEDP cannot (no wire path on either side at all),
                // whether or not this participant ALSO has a
                // `match_registry` for its wire-reachable peers.
                let identity = rtps_endpoint.map_or_else(GUID::zero, |ctx| {
                    GUID::new(ctx.guid_prefix, ctx.writer_entity_id)
                });
                let status_match_cb = Arc::clone(&match_cb);
                let status_incompat_cb = Arc::clone(&incompat_cb);
                let match_status = Some(crate::dds::domain_registry::LocalMatchStatus::new(
                    identity,
                    Box::new(move |a, b, c, d, e| status_match_cb(a, b, c, d, e)),
                    Some(Box::new(move |a, b, c| status_incompat_cb(a, b, c))),
                ));

                let match_token = if let Some(ref reg) = participant.match_registry {
                    let local_type_object = self
                        .type_object_override
                        .clone()
                        .or_else(|| T::get_type_object());

                    // One ReaderProxy per matched RELIABLE reader (RTPS 2.5
                    // 8.4.7.4 matched_reader_add / matched_reader_remove):
                    // its acknowledgement watermark starts where the
                    // writer's debt to it starts - nothing written yet for
                    // a VOLATILE writer, its whole history for a durable
                    // one. A best-effort reader acknowledges nothing and
                    // never holds the history back.
                    //
                    // The VOLATILE HEARTBEAT floor is installed by the same
                    // event, with the same value: the first RELIABLE
                    // reader's ReaderProxy, taken at its discovery pairing,
                    // is owed what comes after its watermark, so the floor
                    // (firstSN = watermark + 1) must be taken at that
                    // instant too. Taken at the surfaced match instead, a
                    // sample written in between and lost is owed to the
                    // reader yet below the advertised firstSN: the reader
                    // never asks for it, and it is never repaired.
                    let peer_cb: Option<crate::dds::match_notification::PeerCallback> = {
                        let cache = history_cache.clone();
                        let track = Arc::clone(&ack_track);
                        let volatile = writer_is_volatile;
                        let floor = scheduler_state_for_match.clone();
                        let windows = Arc::clone(&wire_windows);
                        let fsm = self.discovery_fsm.clone();
                        let registry = self.endpoint_registry.clone();
                        let group = group_presentation;
                        let coherent = presentation.coherent_access;
                        Some(Box::new(move |change| {
                            let created = cache.as_ref().and_then(|cache| {
                                super::nack::track_reader_proxy(&track, cache, volatile, change)
                            });
                            if let (true, Some(watermark), Some(state)) =
                                (volatile, created, floor.as_ref())
                            {
                                let _ = state.bump_first_eligible(watermark);
                            }
                            use crate::dds::match_notification::PeerChange;
                            match change {
                                PeerChange::Matched {
                                    guid,
                                    volatile: reader_volatile,
                                    ..
                                } if group => {
                                    let participant = GUID::new(
                                        guid.prefix,
                                        crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                                    );
                                    if fsm.as_ref().is_some_and(|fsm| {
                                        fsm.needs_classic_sequence_window(&guid.prefix)
                                    }) {
                                        let watermark = created.unwrap_or_else(|| {
                                            if volatile || reader_volatile {
                                                cache.as_ref().map_or_else(
                                                    || windows.highest_unretained(),
                                                    |cache| cache.highest_inserted(),
                                                )
                                            } else {
                                                0
                                            }
                                        });
                                        let endpoint = registry.as_ref().and_then(|reg| {
                                            reg.get_reader_locator(&guid)
                                                .or_else(|| reg.get(&participant))
                                        });
                                        windows.pair(guid, endpoint, watermark, coherent);
                                    } else {
                                        windows.note_native_match(guid);
                                    }
                                }
                                PeerChange::Unmatched { guid } => windows.unpair(guid),
                                _ => (),
                            }
                        })
                            as crate::dds::match_notification::PeerCallback)
                    };

                    let inconsistent_cb: Option<Box<dyn Fn(u32, i32) + Send + Sync>> = {
                        let slot = Arc::clone(&listener_slot);
                        Some(Box::new(move |total: u32, total_change: i32| {
                            if let Some(l) = slot.get(StatusMask::INCONSISTENT_TOPIC) {
                                l.on_inconsistent_topic(
                                    crate::dds::listener::InconsistentTopicStatus {
                                        total_count: total,
                                        total_count_change: total_change,
                                    },
                                );
                            }
                        })
                            as Box<dyn Fn(u32, i32) + Send + Sync>)
                    };

                    let reg_match_cb = Arc::clone(&match_cb);
                    let reg_incompat_cb = Arc::clone(&incompat_cb);
                    // The name announced in SEDP: Step 2 compares it.
                    let announced_type_name = self
                        .type_name_override
                        .clone()
                        .unwrap_or_else(|| T::type_descriptor().type_name.to_string());
                    let token = reg.register_writer_with_peers(
                        self.topic.clone(),
                        self.qos.clone(),
                        crate::dds::match_notification::LocalType::new(
                            crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
                            announced_type_name,
                        ),
                        local_type_object,
                        move |a, b, c, d, e| reg_match_cb(a, b, c, d, e),
                        peer_cb,
                        Some(Box::new(move |a, b, c| reg_incompat_cb(a, b, c))
                            as Box<dyn Fn(u32, i32, u32) + Send + Sync>),
                        inconsistent_cb,
                        self.effective_shm_policy(),
                        Some(Arc::clone(&shm_selected)),
                    );
                    // The writer's GUID, for the CryptoTokens addressed to
                    // it or by it (DDS Security v1.1 Sec.7.4.4.6.2-3).
                    if identity != GUID::zero() {
                        token.bind_local_guid(identity);
                    }
                    Some(token)
                } else {
                    None
                };

                (match_token, match_status)
            }
        } else {
            (None, None)
        };

        // Register writer in domain state for intra-process auto-binding.
        // `match_status` (built above, ALWAYS `Some` when this writer
        // has a participant) makes this call the source of
        // PUBLICATION_MATCHED / OFFERED_INCOMPATIBLE_QOS for any peer with
        // no wire path at all, whether or not this writer's OWN participant
        // also has a `match_registry` for its wire-reachable peers
        // (`local_status_applies` in domain_registry.rs is what keeps the
        // two sources from double-counting a same-participant pair).
        // Retained separately from the `match_status` moved into the
        // registration call below: `DataWriter::matched_reader_count` sums
        // it with `_match_token`'s count (disjoint peer sets: SEDP's and
        // this registry's).
        let match_status_for_writer = match_status.clone();
        let bind_token = if let Some(ref domain_state) = self.domain_state {
            let type_name = self
                .type_name_override
                .as_deref()
                .unwrap_or(T::type_descriptor().type_name);
            let type_id = TypeId::from_type_name(type_name);
            let key = MatchKey::new(self.topic.as_str(), type_id);

            // Generate a GUID for this writer endpoint
            let guid = if let Some(ref ctx) = rtps_endpoint {
                GUID::new(ctx.guid_prefix, ctx.writer_entity_id)
            } else {
                GUID::zero()
            };

            log::debug!(
                "[WriterBuilder] Registering writer in domain {} for topic='{}' type='{}'",
                domain_state.domain_id,
                self.topic,
                type_name
            );

            Some(domain_state.register_writer_with_match(
                key,
                guid,
                merger.clone(),
                crate::dds::domain_registry::EndpointQos::new(
                    &self.qos,
                    crate::dds::cdr_negotiation::Xcdr1Encoding::of::<T>(),
                ),
                crate::dds::domain_registry::EndpointContext::new(
                    self.participant.as_ref().map(|p| p.participant_token()),
                    self.transport.is_some(),
                ),
                match_status,
            ))
        } else {
            None
        };

        let last_sn_in_active_set = Arc::new(AtomicU64::new(0));
        let coherent_set_first_sn = Arc::new(AtomicU64::new(0));
        // This writer's coherent sets awaiting local delivery
        // (`intra_coherent`): shared with the `WriterCoherentBridge` below,
        // which closes and delivers them at `end_coherent_changes`.
        // A GROUP Publisher delivers a coherent set across its writers at
        // once (`local_group`): each writer reports its part there instead
        // of pushing it alone, and its merger wakes the coordinator when a
        // reader's access bracket has just closed.
        let local_group = self.publisher.as_ref().and_then(|core| core.local_group());
        if let Some(group) = local_group.as_ref() {
            merger.set_local_publisher(group.identity());
            group.register_merger(&merger);
            let weak = Arc::downgrade(group);
            merger.set_local_group_wake(Arc::new(move || {
                if let Some(group) = weak.upgrade() {
                    group.release_ready();
                }
            }));
        }
        let grouped = local_group.is_some();
        let intra_coherent_sets = Arc::new(super::intra_coherent::IntraCoherentSets::new(
            self.topic.clone(),
            Arc::clone(&merger),
            self.qos.reliability_max_blocking_time,
            matches!(
                self.qos.reliability,
                super::super::qos::Reliability::Reliable
            ),
            local_group,
        ));
        // A TOPIC-scope set held back by a reader's access bracket is delivered
        // when that bracket ends (a GROUP Publisher's coordinator does it).
        if !grouped && self.qos.presentation.coherent_access {
            intra_coherent_sets.follow_brackets();
        }
        if (self.qos.presentation.coherent_access
            || (self.qos.presentation.is_group_scope() && self.qos.presentation.ordered_access))
            && self.publisher.is_some()
        {
            let order: Arc<dyn rt::LocalDeliveryOrder> = intra_coherent_sets.clone();
            merger.set_local_order(Arc::downgrade(&order));
        }

        // Register a CoherentWriter bridge with the parent Publisher
        // so `Publisher::end_coherent_changes` can iterate its writers
        // and emit one ECS DATA submessage per (writer, gsn) tuple.
        // The bridge shares the writer's counters and destination windows.
        let publisher_core = self.publisher.clone();
        // A GROUP Publisher keeps a set's ends while any of its writers
        // retains a member of the set (RTPS v2.5 Sec.8.7.6).
        if let (Some(publisher), Some(cache)) = (
            self.publisher.as_ref().filter(|core| core.group_scope),
            history_cache.as_ref(),
        ) {
            cache.set_group_retention(
                Arc::clone(publisher) as Arc<dyn crate::reliability::GroupRetention>
            );
        }
        if let Some(ref publisher) = self.publisher {
            let scheduler_state_for_bridge =
                heartbeat_scheduler.as_ref().map(|h| Arc::clone(h.state()));
            let bridge: Arc<dyn crate::dds::publisher::CoherentWriter> = Arc::new(
                super::coherent::WriterCoherentBridge::new(
                    self.topic.clone(),
                    Arc::clone(&next_seq_atomic),
                    Arc::clone(&last_sn_in_active_set),
                    Arc::clone(&coherent_set_first_sn),
                    Arc::clone(&wire_windows),
                    self.transport.clone(),
                    rtps_endpoint,
                    history_cache.clone(),
                    self.endpoint_registry.clone(),
                    self.discovery_fsm.clone(),
                    scheduler_state_for_bridge,
                    Arc::clone(&intra_coherent_sets),
                )
                .with_participant_fallback(self.qos.partition.is_default())
                .with_acknowledgments(
                    matches!(
                        self.qos.reliability,
                        super::super::qos::Reliability::Reliable
                    ),
                    Arc::clone(&ack_track),
                ),
            );
            publisher.add_writer(
                Arc::downgrade(&bridge),
                rtps_endpoint.map_or([0; 4], |ctx| ctx.writer_entity_id),
            )?;
            // Leak a strong ref into the writer so the bridge outlives
            // the build() scope and the Publisher's Weak stays
            // upgradeable until the writer is dropped. Wrap inside a
            // Box that the DataWriter holds for the entire lifetime;
            // dropping the writer drops the bridge, after which the
            // publisher's Weak fails to upgrade and the entry is
            // pruned on the next `end_coherent_changes` sweep.
            let _bridge_keepalive: Arc<dyn crate::dds::publisher::CoherentWriter> = bridge;
            // Store inside the DataWriter via the optional field below.
            return Ok(DataWriter {
                serialized_keys: self.serialized_keys,
                topic: self.topic,
                qos: self.qos,
                rtps_endpoint,
                merger,
                transport: self.transport,
                next_seq: next_seq_atomic,
                history_cache,
                _cleanup_timer: cleanup_timer,
                reliable_metrics,
                heartbeat_tx,
                _heartbeat_scheduler: heartbeat_scheduler,
                nack_handlers: nack_handler_token,
                endpoint_registry: self.endpoint_registry,
                discovery_fsm: self.discovery_fsm,
                frag_route,
                _bind_token: bind_token,
                _replay_token: replay_token,
                _replay_state: replay_state,
                listener: listener_slot,
                _match_token: match_token,
                _match_status: match_status_for_writer,
                status_condition,
                publication_matched,
                offered_incompatible_qos,
                shm_selected,
                #[cfg(target_os = "linux")]
                shm_leg,
                ack_track: ack_track.clone(),
                deadlines: deadlines.clone(),
                #[cfg(feature = "security")]
                security,
                #[cfg(feature = "security")]
                protection: Default::default(),
                #[cfg(feature = "security")]
                protected_key_hashes: std::sync::Mutex::new(std::collections::HashMap::new()),
                written_instances: Arc::clone(&written_instances),
                disposed_instances: std::sync::Mutex::new(std::collections::HashSet::new()),
                last_lifecycle_sn: AtomicU64::new(0),
                publisher: publisher_core,
                last_sn_in_active_set,
                coherent_set_first_sn,
                coherent_set_gsn_seen: AtomicU64::new(u64::MAX),
                set_undo: std::sync::Mutex::new(super::runtime::SetUndo::default()),
                wire_windows,
                intra_coherent_sets,
                cdr_version,
                intra_scratch: std::sync::Mutex::new(Vec::new()),
                wire_scratch: std::sync::Mutex::new(Vec::new()),
                _coherent_bridge: Some(_bridge_keepalive),
                sedp_retirement,
                _liveliness: liveliness,
                _liveliness_manual: liveliness_manual,
                _liveliness_assert: liveliness_assert,
                liveliness_lost,
                pending_source_ts: core::cell::Cell::new(None),
                counts: Default::default(),
                _phantom: core::marker::PhantomData,
            });
        }

        Ok(DataWriter {
            serialized_keys: self.serialized_keys,
            topic: self.topic,
            qos: self.qos,
            rtps_endpoint,
            merger,
            transport: self.transport,
            next_seq: next_seq_atomic,
            history_cache,
            _cleanup_timer: cleanup_timer,
            reliable_metrics,
            heartbeat_tx,
            _heartbeat_scheduler: heartbeat_scheduler,
            nack_handlers: nack_handler_token,
            endpoint_registry: self.endpoint_registry,
            discovery_fsm: self.discovery_fsm,
            frag_route,
            _bind_token: bind_token,
            _replay_token: replay_token,
            _replay_state: replay_state,
            listener: listener_slot,
            _match_token: match_token,
            _match_status: match_status_for_writer,
            status_condition,
            publication_matched,
            offered_incompatible_qos,
            shm_selected,
            #[cfg(target_os = "linux")]
            shm_leg,
            ack_track,
            deadlines,
            #[cfg(feature = "security")]
            security,
            #[cfg(feature = "security")]
            protection: Default::default(),
            #[cfg(feature = "security")]
            protected_key_hashes: std::sync::Mutex::new(std::collections::HashMap::new()),
            written_instances: Arc::clone(&written_instances),
            disposed_instances: std::sync::Mutex::new(std::collections::HashSet::new()),
            last_lifecycle_sn: AtomicU64::new(0),
            publisher: None,
            last_sn_in_active_set,
            coherent_set_first_sn,
            coherent_set_gsn_seen: AtomicU64::new(u64::MAX),
            set_undo: std::sync::Mutex::new(super::runtime::SetUndo::default()),
            wire_windows,
            // No publisher: `coherent_context` short-circuits on it before
            // ever stamping, so these sets stay empty.
            intra_coherent_sets,
            cdr_version,
            intra_scratch: std::sync::Mutex::new(Vec::new()),
            wire_scratch: std::sync::Mutex::new(Vec::new()),
            _coherent_bridge: None,
            sedp_retirement,
            _liveliness: liveliness,
            _liveliness_manual: liveliness_manual,
            _liveliness_assert: liveliness_assert,
            liveliness_lost,
            pending_source_ts: core::cell::Cell::new(None),
            counts: Default::default(),
            _phantom: core::marker::PhantomData,
        })
    }
}

/// PRESENTATION belongs to the Publisher; a writer need not duplicate it.
fn window_presentation(
    publisher: Option<&crate::dds::publisher::PublisherCore>,
    writer: crate::dds::qos::Presentation,
) -> crate::dds::qos::Presentation {
    publisher.map_or(writer, |core| core.presentation)
}

/// An identity for a DataWriter of no participant, which no RTPS GUID
/// announced on any wire can be expected to take: a GUID prefix drawn at
/// random once per process, and a process-unique counter in the entity key
/// with the user-writer kind (RTPS v2.5 Sec.9.3.1.2, 0x02).
///
/// Ties. An EXCLUSIVE reader breaks a strength tie by the lower GUID
/// (`WriterRegistrations::arbitrate`). Such a writer reaches only the
/// readers of its own process, which all see the same identity, so they
/// pick the same owner as Sec.2.2.3.9.2 requires; against a remote writer
/// of equal strength its rank is arbitrary but fixed for the life of the
/// process. An all-zero prefix would be the lowest GUID there is, so such a
/// writer would win every strength tie against every remote writer; and it
/// is GUIDPREFIX_UNKNOWN (Sec.9.3.1.1), a value a peer may carry.
fn local_writer_identity() -> [u8; 16] {
    use std::hash::{BuildHasher, Hasher};
    static PREFIX: std::sync::OnceLock<[u8; 12]> = std::sync::OnceLock::new();
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let prefix = PREFIX.get_or_init(|| {
        // RandomState is seeded from the OS's randomness once per process.
        let state = std::collections::hash_map::RandomState::new();
        let draw = |salt: u64| {
            let mut hasher = state.build_hasher();
            hasher.write_u64(salt);
            hasher.write_u32(std::process::id());
            hasher.finish()
        };
        let mut prefix = [0u8; 12];
        prefix[..8].copy_from_slice(&draw(1).to_be_bytes());
        prefix[8..].copy_from_slice(&draw(2).to_be_bytes()[..4]);
        if prefix[8..] == [0u8; 4] {
            prefix[11] = 1;
        }
        prefix
    });
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut guid = [0u8; 16];
    guid[..12].copy_from_slice(prefix);
    guid[12..15].copy_from_slice(&n.to_be_bytes()[1..]);
    guid[15] = 0x02;
    guid
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DDS 1.4 Sec.2.2.3.6: ordered access does not imply coherent access.
    /// A matched ordered-only reader is owed every change above its match
    /// watermark, including a change it must recover before its first DATA.
    #[test]
    fn window_presentation_preserves_the_publishers_ordered_only_policy() {
        use crate::dds::qos::{Presentation, PresentationAccessScope};
        let policy = Presentation::new(PresentationAccessScope::Group, false, true);
        let publisher =
            crate::dds::Publisher::new(QoS::reliable().presentation(policy), None, None, None);
        let resolved = window_presentation(Some(&publisher.core), Presentation::instance());
        assert_eq!(resolved, policy);
        let domain = crate::test_support::domains::unique_domain();
        let transport = crate::transport::UdpTransport::new(
            domain.id(),
            0,
            crate::transport::PortMapping::calculate(domain.id(), 0).unwrap(),
        )
        .unwrap();
        let socket = crate::test_support::ports::bind_capture_socket();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let reader = GUID::new([9; 12], [0, 0, 2, 7]);
        let windows = crate::protocol::dialect::sequence_window::WriterWindows::default();
        windows.pair(reader, Some(addr), 20, resolved.coherent_access);
        let ctx = crate::protocol::builder::RtpsEndpointContext {
            guid_prefix: [7; 12],
            reader_entity_id: [0; 4],
            writer_entity_id: [0, 0, 1, 2],
            encapsulation_kind: 7,
            publisher_entity_id: [0, 0, 1, 8],
        };
        let heartbeat =
            crate::protocol::builder::build_heartbeat_packet_with_context(&ctx, 21, 24, 1);
        windows
            .send_classed(&transport, &heartbeat, &addr, reader, true)
            .unwrap();
        let mut bytes = [0u8; 256];
        let n = socket.recv(&mut bytes).unwrap();
        assert!(n >= 64);
        assert_eq!(bytes[36], 7, "HEARTBEAT after INFO_DST");
        assert_eq!(
            u32::from_le_bytes(bytes[60..64].try_into().unwrap()),
            4,
            "an ordered-only window advertises changes above the match watermark immediately"
        );
        let coherent = crate::dds::Publisher::new(
            QoS::reliable().presentation(Presentation::group_coherent()),
            None,
            None,
            None,
        );
        assert!(
            window_presentation(Some(&coherent.core), Presentation::instance()).coherent_access
        );
    }

    /// A writer of no participant has a GUID prefix of its own: not
    /// GUIDPREFIX_UNKNOWN (all zero, what a peer that announces no prefix
    /// carries, RTPS v2.5 Sec.9.3.1.1), which would also rank it below every
    /// remote writer on a strength tie; the same for every such writer of
    /// the process, each with its own entity id, a user writer's
    /// (Sec.9.3.1.2, kind 0x02).
    #[test]
    fn a_participant_less_writer_has_its_own_identity() {
        let first = local_writer_identity();
        let second = local_writer_identity();
        assert_ne!(first[..12], [0u8; 12], "not GUIDPREFIX_UNKNOWN");
        assert_ne!(first[8..12], [0u8; 4], "no zero run where a counter was");
        assert_eq!(first[..12], second[..12], "one prefix per process");
        assert_ne!(first[12..], second[12..], "one entity id per writer");
        assert_eq!(first[15], 0x02, "a user writer, no key");
    }
    use crate::dds::qos::{Durability, DurabilityService, History, Reliability};
    use crate::qos::ResourceLimits;

    fn base_limits() -> ResourceLimits {
        ResourceLimits {
            max_samples: 1000,
            max_instances: 1,
            max_samples_per_instance: 1000,
            max_quota_bytes: 100_000,
        }
    }

    #[test]
    fn test_derive_history_volatil_keep_last() {
        let mut qos = QoS::best_effort().keep_last(5);
        qos.resource_limits = base_limits();

        let (history, limits) = derive_history_and_limits(&qos).expect("history derivation");
        assert!(matches!(history, crate::qos::History::KeepLast(5)));
        // KEEP_LAST depth is PER INSTANCE and the history cache enforces it
        // as such; RESOURCE_LIMITS stay exactly what the user set. The depth
        // must not be copied over max_samples_per_instance, which would
        // silently replace a user value the spec requires to be checked.
        assert_eq!(limits, base_limits());
    }

    #[test]
    fn test_derive_history_transient_local_ignores_the_durability_service() {
        let mut qos = QoS::reliable()
            .transient_local()
            .keep_last(10)
            .durability_service(DurabilityService::keep_last(50, 200, 1, 200));
        qos.resource_limits = base_limits();

        let (history, limits) = derive_history_and_limits(&qos).expect("history derivation");
        assert!(matches!(history, crate::qos::History::KeepLast(10)));
        assert_eq!(limits, base_limits());
    }

    #[test]
    fn test_derive_history_transient_service_depth_wins() {
        let mut qos = QoS::reliable()
            .transient()
            .keep_last(10)
            .durability_service(DurabilityService::keep_last(50, 2000, 1, 2000));
        qos.resource_limits = base_limits();

        let (history, limits) = derive_history_and_limits(&qos).expect("history derivation");
        assert!(matches!(history, crate::qos::History::KeepLast(50)));
        assert_eq!(limits.max_samples, 2000);
        assert_eq!(limits.max_instances, 1);
        assert_eq!(limits.max_samples_per_instance, 2000);
    }

    #[test]
    fn test_derive_history_rejects_what_the_spec_calls_inconsistent() {
        // DDS v1.4 2.2.3.19: max_samples >= max_samples_per_instance.
        let mut qos = QoS::best_effort().keep_last(10);
        qos.resource_limits = ResourceLimits {
            max_samples: 50,
            max_instances: 1,
            max_samples_per_instance: 100,
            max_quota_bytes: 100_000,
        };
        let err = derive_history_and_limits(&qos).expect_err("inconsistent");
        assert!(
            err.to_string()
                .contains("max_samples (50) must be >= max_samples_per_instance (100)"),
            "{err}"
        );
        // DDS 1.4 2.2.1.1: INCONSISTENT_POLICY, not PRECONDITION_NOT_MET.
        assert!(matches!(err, Error::InvalidQos(_)), "{err:?}");

        // DDS v1.4 2.2.3.18: depth <= max_samples_per_instance.
        let mut qos = QoS::best_effort().keep_last(10);
        qos.resource_limits = ResourceLimits {
            max_samples: 100,
            max_instances: 1,
            max_samples_per_instance: 5,
            max_quota_bytes: 100_000,
        };
        let err = derive_history_and_limits(&qos).expect_err("inconsistent");
        assert!(
            err.to_string().contains(
                "HISTORY depth (10) must be <= RESOURCE_LIMITS.max_samples_per_instance (5)"
            ),
            "{err}"
        );
        assert!(matches!(err, Error::InvalidQos(_)), "{err:?}");
    }

    /// An invalid DURABILITY_SERVICE (TRANSIENT/PERSISTENT) is the same
    /// INCONSISTENT_POLICY as a bad HISTORY / RESOURCE_LIMITS pair, DDS 1.4
    /// 2.2.1.1: `Error::InvalidQos`, never `Error::InvalidState`.
    #[test]
    fn test_derive_history_rejects_an_inconsistent_durability_service() {
        let mut qos = QoS::reliable()
            .transient()
            .keep_last(10)
            .durability_service(DurabilityService::keep_last(50, 10, 1, 100));
        qos.resource_limits = base_limits();

        let err = derive_history_and_limits(&qos).expect_err("inconsistent durability service");
        assert!(
            err.to_string().contains("DurabilityService invalid"),
            "{err}"
        );
        assert!(matches!(err, Error::InvalidQos(_)), "{err:?}");
    }

    #[test]
    fn test_derive_history_accepts_what_the_spec_allows() {
        // max_samples below max_instances * max_samples_per_instance is
        // legal: DDS v1.4 2.2.2.4.2.11 describes write's behaviour in exactly
        // that situation, so it is accepted.
        let mut qos = QoS::reliable().keep_last(10);
        qos.resource_limits = ResourceLimits {
            max_samples: 100,
            max_instances: 50,
            max_samples_per_instance: 10,
            max_quota_bytes: 100_000,
        };
        assert!(derive_history_and_limits(&qos).is_ok());

        // A TRANSIENT_LOCAL writer is not held to DurabilityService limits
        // it does not use (this setting is accepted).
        let mut qos = QoS::best_effort()
            .transient_local()
            .keep_last(10)
            .durability_service(DurabilityService::keep_last(50, 2000, 1, 2000));
        qos.resource_limits = ResourceLimits {
            max_samples: 100,
            max_instances: 1,
            max_samples_per_instance: 100,
            max_quota_bytes: 100_000,
        };
        assert!(derive_history_and_limits(&qos).is_ok());
    }

    // -- canonical_encapsulation_kind (XTypes v1.3 section 7.6.3.1.2) -----

    fn union_type_object(flags: crate::xtypes::UnionTypeFlag) -> CompleteTypeObject {
        use crate::xtypes::{
            CompleteTypeDetail, CompleteUnionHeader, CompleteUnionType, MemberFlag, TypeIdentifier,
            TypeKind,
        };

        CompleteTypeObject::Union(CompleteUnionType {
            union_flags: flags,
            header: CompleteUnionHeader {
                discriminator: TypeIdentifier::Primitive(TypeKind::TK_INT32),
                discriminator_flags: MemberFlag::empty(),
                detail: CompleteTypeDetail {
                    type_name: "TestUnion".to_string(),
                    ann_builtin: None,
                    ann_custom: None,
                },
            },
            member_seq: Vec::new(),
        })
    }

    fn struct_type_object(flags: crate::xtypes::StructTypeFlag) -> CompleteTypeObject {
        use crate::xtypes::{CompleteStructHeader, CompleteStructType, CompleteTypeDetail};

        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: flags,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail {
                    type_name: "TestStruct".to_string(),
                    ann_builtin: None,
                    ann_custom: None,
                },
            },
            member_seq: Vec::new(),
        })
    }

    #[test]
    fn test_encap_kind_struct_extensibility() {
        use crate::xtypes::StructTypeFlag;
        let final_s = struct_type_object(StructTypeFlag::IS_FINAL);
        let app_s = struct_type_object(StructTypeFlag::IS_APPENDABLE);
        let mut_s = struct_type_object(StructTypeFlag::IS_MUTABLE);
        assert_eq!(canonical_encapsulation_kind(Some(&final_s), None), 0x0007);
        assert_eq!(canonical_encapsulation_kind(Some(&app_s), None), 0x0009);
        assert_eq!(canonical_encapsulation_kind(Some(&mut_s), None), 0x000B);
    }

    #[test]
    fn test_encap_kind_union_extensibility() {
        use crate::xtypes::UnionTypeFlag;
        // Appendable/mutable unions must NOT fall through to
        // PLAIN_CDR2 (0x0007) -- their bodies carry DHEADER/EMHEADER
        // framing, and a receiver that selects its decoder from the
        // encapsulation id would parse them with the wrong framing.
        let final_u = union_type_object(UnionTypeFlag::IS_FINAL);
        let app_u = union_type_object(UnionTypeFlag::IS_APPENDABLE);
        let mut_u = union_type_object(UnionTypeFlag::IS_MUTABLE);
        assert_eq!(canonical_encapsulation_kind(Some(&final_u), None), 0x0007);
        assert_eq!(canonical_encapsulation_kind(Some(&app_u), None), 0x0009);
        assert_eq!(canonical_encapsulation_kind(Some(&mut_u), None), 0x000B);
    }

    #[test]
    fn test_encap_kind_no_type_object_defaults_plain_cdr2() {
        assert_eq!(canonical_encapsulation_kind(None, None), 0x0007);
    }

    #[test]
    fn test_encap_kind_override_wins() {
        use crate::xtypes::StructTypeFlag;
        // Override beats both the None fallback (TypeObject suppressed via
        // --disable-type-info) and any TypeObject-derived kind.
        assert_eq!(canonical_encapsulation_kind(None, Some(0x0009)), 0x0009);
        assert_eq!(canonical_encapsulation_kind(None, Some(0x000B)), 0x000B);
        let final_s = struct_type_object(StructTypeFlag::IS_FINAL);
        assert_eq!(
            canonical_encapsulation_kind(Some(&final_s), Some(0x0009)),
            0x0009
        );
    }

    #[test]
    fn test_derive_history_rejects_zero_keep_last() {
        let mut qos = QoS {
            history: History::KeepLast(0),
            reliability: Reliability::BestEffort,
            durability: Durability::Volatile,
            ..QoS::best_effort()
        };
        qos.resource_limits = base_limits();

        let err = derive_history_and_limits(&qos).expect_err("should reject depth 0");
        let msg = format!("{}", err);
        assert!(msg.contains("History::KeepLast"));
    }
}

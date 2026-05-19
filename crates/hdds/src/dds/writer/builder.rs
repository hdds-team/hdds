// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Builder pattern for DataWriter configuration.
//!
//!
//! Provides fluent API for configuring QoS, transport, history cache,
//! and reliability options before constructing a DataWriter instance.

use super::heartbeat_scheduler::{
    spawn_heartbeat_scheduler, HeartbeatSchedulerHandle, HeartbeatSchedulerState,
    DEFAULT_HEARTBEAT_PERIOD_MS,
};
use super::nack::{WriterNackFragHandler, WriterNackHandler};
use super::runtime::DataWriter;
use super::runtime::WriterReplayState;
use crate::core::discovery::ReplayRegistry;
use crate::core::discovery::GUID;
use crate::core::rt;
use crate::dds::cdr_negotiation::stable_writer_version;
use crate::dds::listener::DataWriterListener;
use crate::dds::{DomainState, Error, MatchKey, QoS, Result, TypeId, DDS};
use crate::protocol::builder::RtpsEndpointContext;
use crate::reliability::{HeartbeatTx, HistoryCache, ReliableMetrics};
#[cfg(target_os = "linux")]
use crate::transport::shm::ShmPolicy;
use crate::transport::UdpTransport;
use crate::xtypes::CompleteTypeObject;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn validate_resource_limits(limits: &crate::qos::ResourceLimits) -> Result<()> {
    // Skip the `per_instance * max_instances <= max_samples` cross-check when
    // either factor is effectively LENGTH_UNLIMITED (`usize::MAX`). The DDS
    // spec treats these as "no limit" and the product overflows trivially.
    if limits.max_instances == usize::MAX || limits.max_samples_per_instance == usize::MAX {
        return Ok(());
    }
    let required = limits
        .max_samples_per_instance
        .checked_mul(limits.max_instances)
        .ok_or_else(|| {
            Error::InvalidState(format!(
                "ResourceLimits overflow: max_samples_per_instance ({}) * max_instances ({})",
                limits.max_samples_per_instance, limits.max_instances
            ))
        })?;
    if limits.max_samples < required {
        return Err(Error::InvalidState(format!(
            "ResourceLimits.max_samples ({}) must be >= max_samples_per_instance ({}) * max_instances ({})",
            limits.max_samples, limits.max_samples_per_instance, limits.max_instances
        )));
    }
    Ok(())
}

fn derive_history_and_limits(
    qos: &QoS,
) -> Result<(crate::qos::History, crate::qos::ResourceLimits)> {
    let mut resource_limits = qos.resource_limits;
    validate_resource_limits(&resource_limits)?;

    if matches!(qos.history, super::super::qos::History::KeepLast(0)) {
        return Err(Error::InvalidState(
            "History::KeepLast requires depth > 0".to_string(),
        ));
    }

    let durability_enabled = matches!(
        qos.durability,
        super::super::qos::Durability::TransientLocal
            | super::super::qos::Durability::Transient
            | super::super::qos::Durability::Persistent
    );

    let history_policy;

    if durability_enabled {
        let service = qos.durability_service;
        service
            .validate()
            .map_err(|err| Error::InvalidState(format!("DurabilityService invalid: {}", err)))?;

        let service_max_samples = usize::try_from(service.max_samples).map_err(|_| {
            Error::InvalidState(format!(
                "DurabilityService.max_samples must be > 0 (got {})",
                service.max_samples
            ))
        })?;
        let service_max_instances = usize::try_from(service.max_instances).map_err(|_| {
            Error::InvalidState(format!(
                "DurabilityService.max_instances must be > 0 (got {})",
                service.max_instances
            ))
        })?;
        let service_max_samples_per_instance = usize::try_from(service.max_samples_per_instance)
            .map_err(|_| {
                Error::InvalidState(format!(
                    "DurabilityService.max_samples_per_instance must be > 0 (got {})",
                    service.max_samples_per_instance
                ))
            })?;
        let service_depth = usize::try_from(service.history_depth).map_err(|_| {
            Error::InvalidState(format!(
                "DurabilityService.history_depth {} exceeds usize",
                service.history_depth
            ))
        })?;

        if service_max_samples < service_depth {
            return Err(Error::InvalidState(format!(
                "DurabilityService.max_samples ({}) must be >= history_depth ({})",
                service_max_samples, service_depth
            )));
        }
        if service_max_samples_per_instance < service_depth {
            return Err(Error::InvalidState(format!(
                "DurabilityService.max_samples_per_instance ({}) must be >= history_depth ({})",
                service_max_samples_per_instance, service_depth
            )));
        }
        if resource_limits.max_samples < service_max_samples {
            return Err(Error::InvalidState(format!(
                "ResourceLimits.max_samples ({}) must be >= DurabilityService.max_samples ({})",
                resource_limits.max_samples, service_max_samples
            )));
        }
        if resource_limits.max_instances < service_max_instances {
            return Err(Error::InvalidState(format!(
                "ResourceLimits.max_instances ({}) must be >= DurabilityService.max_instances ({})",
                resource_limits.max_instances, service_max_instances
            )));
        }
        if resource_limits.max_samples_per_instance < service_max_samples_per_instance {
            return Err(Error::InvalidState(format!(
                "ResourceLimits.max_samples_per_instance ({}) must be >= DurabilityService.max_samples_per_instance ({})",
                resource_limits.max_samples_per_instance, service_max_samples_per_instance
            )));
        }

        resource_limits.max_instances = service_max_instances;

        match qos.history {
            super::super::qos::History::KeepLast(depth) => {
                let depth = usize::try_from(depth).map_err(|_| {
                    Error::InvalidState(format!("History::KeepLast depth {} exceeds usize", depth))
                })?;
                let effective_depth = depth.max(service_depth);
                if service_max_samples < effective_depth {
                    return Err(Error::InvalidState(format!(
                        "DurabilityService.max_samples ({}) must be >= effective history depth ({})",
                        service_max_samples, effective_depth
                    )));
                }
                if service_max_samples_per_instance < effective_depth {
                    return Err(Error::InvalidState(format!(
                        "DurabilityService.max_samples_per_instance ({}) must be >= effective history depth ({})",
                        service_max_samples_per_instance, effective_depth
                    )));
                }
                resource_limits.max_samples = effective_depth;
                resource_limits.max_samples_per_instance = effective_depth;
                history_policy = crate::qos::History::KeepLast(effective_depth as u32);
            }
            super::super::qos::History::KeepAll => {
                resource_limits.max_samples = service_max_samples;
                resource_limits.max_samples_per_instance = service_max_samples_per_instance;
                if resource_limits.max_samples == 0 {
                    return Err(Error::InvalidState(
                        "History::KeepAll requires ResourceLimits.max_samples > 0".to_string(),
                    ));
                }
                history_policy = crate::qos::History::KeepAll;
            }
        }
    } else {
        match qos.history {
            super::super::qos::History::KeepLast(depth) => {
                if depth == 0 {
                    return Err(Error::InvalidState(
                        "History::KeepLast requires depth > 0".to_string(),
                    ));
                }
                // DDS spec 2.2.2.4.2.2: KEEP_LAST `depth` applies PER INSTANCE.
                // Only cap the per-instance limit; leave the global cap at its
                // default (or user value) so multi-instance topics aren't
                // starved by a global cap of `depth`.
                resource_limits.max_samples_per_instance = depth as usize;
                history_policy = crate::qos::History::KeepLast(depth);
            }
            super::super::qos::History::KeepAll => {
                if resource_limits.max_samples == 0 {
                    return Err(Error::InvalidState(
                        "History::KeepAll requires ResourceLimits.max_samples > 0".to_string(),
                    ));
                }
                history_policy = crate::qos::History::KeepAll;
            }
        }
    }

    validate_resource_limits(&resource_limits)?;
    Ok((history_policy, resource_limits))
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
    pub(super) type_name_override: Option<String>,
    pub(super) type_object_override: Option<CompleteTypeObject>,
    pub(super) replay_registry: Option<ReplayRegistry>,
    /// SHM transport policy (Linux only)
    #[cfg(target_os = "linux")]
    pub(super) shm_policy: ShmPolicy,
    /// Listener for writer callbacks
    pub(super) listener: Option<Arc<dyn DataWriterListener<T>>>,
    /// Parent Publisher for coherent-set tracking (RTPS v2.5 §8.7.5).
    /// Set via `.publisher(&pub)`; when present the writer registers
    /// itself with the publisher's coherent-set registry and tags
    /// samples written inside a `begin/end_coherent_changes` window
    /// with `PID_COHERENT_SET` (+ `PID_GROUP_COHERENT_SET` when the
    /// publisher access_scope is GROUP).
    pub(super) publisher: Option<Arc<crate::dds::Publisher>>,
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
            type_name_override: None,
            type_object_override: None,
            replay_registry: None,
            #[cfg(target_os = "linux")]
            shm_policy: ShmPolicy::default(),
            listener: None,
            publisher: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Attach a parent Publisher so this writer participates in
    /// `Publisher::begin/end_coherent_changes` and emits ECS DATA
    /// submessages per RTPS v2.5 §8.7.5. Pass the Arc returned by
    /// `participant.create_publisher(...)`. Required for any test or
    /// application that exercises GROUP-scope coherent_access.
    pub fn publisher(mut self, publisher: &Arc<crate::dds::Publisher>) -> Self {
        self.publisher = Some(Arc::clone(publisher));
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

    /// Set SHM transport policy (Linux only).
    ///
    /// - `Prefer` (default): Use SHM if same-host + BestEffort, fallback to UDP
    /// - `Require`: Force SHM, fail if conditions not met
    /// - `Disable`: Always use UDP even when SHM is available
    #[cfg(target_os = "linux")]
    pub fn shm_policy(mut self, policy: ShmPolicy) -> Self {
        self.shm_policy = policy;
        self
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

    pub(crate) fn with_type_name_override(mut self, type_name: impl Into<String>) -> Self {
        self.type_name_override = Some(type_name.into());
        self
    }

    pub(crate) fn with_type_object_override(mut self, type_object: CompleteTypeObject) -> Self {
        self.type_object_override = Some(type_object);
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
        }

        // DDS Security: Check access control permissions for writer creation
        #[cfg(feature = "security")]
        if let Some(ref participant) = self.participant {
            let partition = self.qos.partition.names.first().map(|s| s.as_str());
            participant.check_create_writer(&self.topic, partition)?;
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
        }

        let heartbeat_tx = match self.qos.reliability {
            super::super::qos::Reliability::Reliable => Some(RefCell::new(HeartbeatTx::new())),
            super::super::qos::Reliability::BestEffort => None,
        };

        let reliable_metrics = match self.qos.reliability {
            super::super::qos::Reliability::Reliable => Some(Arc::new(ReliableMetrics::new())),
            super::super::qos::Reliability::BestEffort => None,
        };

        // Build RTPS endpoint context (if participant is available) so DATA
        // packets use the same GUID prefix/entity IDs as SEDP announcements.
        let rtps_endpoint = if let Some(ref participant) = self.participant {
            let entity_id = if let Some(ref type_name) = self.type_name_override {
                participant.announce_writer_endpoint_with_type::<T>(
                    &self.topic,
                    &self.qos,
                    type_name,
                    self.type_object_override.clone(),
                )?
            } else {
                participant.announce_writer_endpoint::<T>(&self.topic, &self.qos)?
            };
            let guid = participant.guid();
            // v240: ENTITYID_UNKNOWN as default; send_packet_to_endpoints()
            // patches in the real reader entity ID per-reader for cross-vendor
            // interop (RTPS v2.3 Sec.8.3.7.2).
            let reader_entity_id = [0, 0, 0, 0x00];

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
            let resolved_type_object = self
                .type_object_override
                .clone()
                .or_else(|| T::get_type_object());
            let encapsulation_kind = match &resolved_type_object {
                Some(CompleteTypeObject::Struct(s))
                    if s.struct_flags
                        .contains(crate::xtypes::StructTypeFlag::IS_MUTABLE) =>
                {
                    0x000Bu16
                } // PL_CDR2_LE
                Some(CompleteTypeObject::Struct(s))
                    if s.struct_flags
                        .contains(crate::xtypes::StructTypeFlag::IS_APPENDABLE) =>
                {
                    0x0009u16
                } // D_CDR2_LE (delimited, with DHEADER)
                _ => 0x0007u16, // PLAIN_CDR2_LE (default for @final or unknown)
            };

            Some(RtpsEndpointContext {
                guid_prefix: guid.prefix,
                reader_entity_id,
                writer_entity_id: entity_id,
                encapsulation_kind,
            })
        } else {
            None
        };

        let next_seq = 1u64;
        if let (Some(ref cache), Some(ref transport), Some(ref registry), Some(ref metrics)) = (
            &history_cache,
            &self.transport,
            &self.registry,
            &reliable_metrics,
        ) {
            // Register NACK handler for sequence-level retransmission
            let handler = Arc::new(WriterNackHandler::new(
                self.topic.clone(),
                cache.clone(),
                transport.clone(),
                metrics.clone(),
                rtps_endpoint,
                stable_writer_version(&self.qos),
            ));
            registry.register_nack_handler(handler);

            // Register NACK_FRAG handler for fragment-level retransmission
            if let Some(ctx) = rtps_endpoint {
                let frag_handler = Arc::new(WriterNackFragHandler::new(
                    self.topic.clone(),
                    cache.clone(),
                    transport.clone(),
                    metrics.clone(),
                    Some(ctx),
                    ctx.writer_entity_id,
                    stable_writer_version(&self.qos),
                ));
                registry.register_nack_frag_handler(frag_handler);
            }
        }

        let merger = if let Some(ref cache) = history_cache {
            let needs_late_joiner = matches!(
                self.qos.durability,
                super::super::qos::Durability::TransientLocal
                    | super::super::qos::Durability::Transient
                    | super::super::qos::Durability::Persistent
            );

            if needs_late_joiner {
                let slab_pool = rt::get_slab_pool();
                Arc::new(rt::TopicMerger::with_history(cache.clone(), slab_pool))
            } else {
                Arc::new(rt::TopicMerger::new())
            }
        } else {
            Arc::new(rt::TopicMerger::new())
        };

        // Register writer in domain state for intra-process auto-binding
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

            Some(domain_state.register_writer(key, guid, merger.clone(), self.qos.reliability))
        } else {
            None
        };

        let replay_token = if matches!(
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
                    stable_writer_version(&self.qos),
                ));
                let callback_state = Arc::clone(&state);
                Some(registry.register(
                    self.topic.clone(),
                    type_name,
                    Arc::new(move |endpoint| {
                        callback_state.replay_to(endpoint);
                    }),
                ))
            } else {
                None
            }
        } else {
            None
        };

        // Get security plugin from participant if available
        #[cfg(feature = "security")]
        let security = self.participant.as_ref().and_then(|p| p.security());

        // Spawn periodic heartbeat scheduler thread for RELIABLE writers
        // This ensures HEARTBEAT messages are sent even when the writer is idle,
        // enabling reliable recovery after bursts (RTPS 2.5 Section 8.4.7.2).
        let heartbeat_scheduler: Option<HeartbeatSchedulerHandle> = match (
            &self.transport,
            &history_cache,
            rtps_endpoint,
            self.qos.reliability,
        ) {
            (Some(transport), Some(cache), Some(ctx), super::super::qos::Reliability::Reliable) => {
                log::debug!(
                    "[writer] Spawning periodic heartbeat thread for topic '{}' (period={}ms)",
                    self.topic,
                    DEFAULT_HEARTBEAT_PERIOD_MS
                );
                Some(spawn_heartbeat_scheduler(
                    transport.clone(),
                    cache.clone(),
                    ctx,
                    DEFAULT_HEARTBEAT_PERIOD_MS,
                ))
            }
            _ => None,
        };

        // Capture deadline period before moving self.qos into the struct
        let deadline_period = self.qos.deadline.period;

        // v252: Capture scheduler state for the VOLATILE firstSN floor. This
        // lets the match callback (below) snapshot `last_seq` at the moment
        // the first reader matches, so subsequent HEARTBEATs hide samples
        // produced before the subscriber existed. See heartbeat_scheduler.rs
        // `first_eligible_seq` doc-comment for the full rationale and the
        // known single-reader limitation.
        let scheduler_state_for_match: Option<Arc<HeartbeatSchedulerState>> =
            heartbeat_scheduler.as_ref().map(|h| Arc::clone(h.state()));
        let writer_is_volatile =
            matches!(self.qos.durability, super::super::qos::Durability::Volatile);

        // Register match notification (on_publication_matched) if listener is present.
        // Must happen before self.listener is moved into the DataWriter.
        let match_token = if let (Some(ref participant), Some(ref listener)) =
            (&self.participant, &self.listener)
        {
            if let Some(ref reg) = participant.match_registry {
                let l_match = Arc::clone(listener);
                let l_incompat = Arc::clone(listener);
                // v252: Clone the Arc into the match closure so the floor is
                // visible from the SEDP callback thread.
                let scheduler_state_for_closure = scheduler_state_for_match.clone();
                Some(reg.register_writer_with_incompatible(
                    self.topic.clone(),
                    self.qos.clone(),
                    T::type_descriptor(),
                    move |total, total_change, current, current_change, last_handle| {
                        // v252: Before the user listener fires, if the writer
                        // is VOLATILE and we are observing a real match
                        // (current_count > 0, i.e. at least one reader), take
                        // the current `last_seq` snapshot and install it as
                        // the HEARTBEAT floor. The CAS in bump_first_eligible
                        // ensures only the first match wins; later matches
                        // are no-ops (see known limitation in the field's
                        // doc-comment).
                        if writer_is_volatile && current > 0 {
                            if let Some(ref state) = scheduler_state_for_closure {
                                let last_seq = state.last_seq.load(Ordering::Acquire);
                                let _ = state.bump_first_eligible(last_seq);
                            }
                        }
                        l_match.on_publication_matched(
                            crate::dds::listener::PublicationMatchedStatus {
                                total_count: total,
                                total_count_change: total_change,
                                current_count: current,
                                current_count_change: current_change,
                                last_subscription_handle: last_handle,
                            },
                        );
                    },
                    Some(Box::new(move |_total, _total_change, policy_id| {
                        let policy_name = match policy_id {
                            2 => "PRESENTATION",
                            5 => "OWNERSHIP",
                            7 => "DURABILITY",
                            11 => "RELIABILITY",
                            13 => "DEADLINE",
                            14 => "DURABILITY_SERVICE",
                            21 => "LIVELINESS",
                            23 => "DATA_REPRESENTATION",
                            _ => "UNKNOWN",
                        };
                        l_incompat.on_offered_incompatible_qos(policy_id, policy_name);
                    })),
                ))
            } else {
                None
            }
        } else {
            None
        };

        let next_seq_atomic = Arc::new(AtomicU64::new(next_seq));
        let last_sn_in_active_set = Arc::new(AtomicU64::new(0));

        // Register a CoherentWriter bridge with the parent Publisher
        // so `Publisher::end_coherent_changes` can iterate its writers
        // and emit one ECS DATA submessage per (writer, gsn) tuple.
        // Bridge holds clones of the runtime state the writer also
        // holds; both stay in sync via shared `Arc`s on `next_seq` and
        // `last_sn_in_active_set` (RTPS v2.5 §8.7.5).
        let publisher_weak: Option<std::sync::Weak<crate::dds::Publisher>> =
            self.publisher.as_ref().map(Arc::downgrade);
        if let Some(ref publisher) = self.publisher {
            let scheduler_state_for_bridge =
                heartbeat_scheduler.as_ref().map(|h| Arc::clone(h.state()));
            let bridge: Arc<dyn crate::dds::publisher::CoherentWriter> =
                Arc::new(super::coherent::WriterCoherentBridge::new(
                    self.topic.clone(),
                    Arc::clone(&next_seq_atomic),
                    Arc::clone(&last_sn_in_active_set),
                    self.transport.clone(),
                    rtps_endpoint,
                    history_cache.clone(),
                    self.endpoint_registry.clone(),
                    self.discovery_fsm.clone(),
                    scheduler_state_for_bridge,
                ));
            publisher.register_writer(Arc::downgrade(&bridge));
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
                topic: self.topic,
                qos: self.qos,
                rtps_endpoint,
                merger,
                transport: self.transport,
                next_seq: next_seq_atomic,
                history_cache,
                reliable_metrics,
                heartbeat_tx,
                _heartbeat_scheduler: heartbeat_scheduler,
                endpoint_registry: self.endpoint_registry,
                discovery_fsm: self.discovery_fsm,
                _bind_token: bind_token,
                _replay_token: replay_token,
                listener: self.listener,
                _match_token: match_token,
                deadline_tracker: std::sync::Mutex::new(
                    crate::qos::deadline::DeadlineTracker::new(deadline_period),
                ),
                deadline_missed_total: std::sync::atomic::AtomicU32::new(0),
                #[cfg(feature = "security")]
                security,
                written_instances: std::sync::Mutex::new(std::collections::HashSet::new()),
                publisher: publisher_weak,
                last_sn_in_active_set,
                _coherent_bridge: Some(_bridge_keepalive),
                _phantom: core::marker::PhantomData,
            });
        }

        Ok(DataWriter {
            topic: self.topic,
            qos: self.qos,
            rtps_endpoint,
            merger,
            transport: self.transport,
            next_seq: next_seq_atomic,
            history_cache,
            reliable_metrics,
            heartbeat_tx,
            _heartbeat_scheduler: heartbeat_scheduler,
            endpoint_registry: self.endpoint_registry,
            discovery_fsm: self.discovery_fsm,
            _bind_token: bind_token,
            _replay_token: replay_token,
            listener: self.listener,
            _match_token: match_token,
            deadline_tracker: std::sync::Mutex::new(crate::qos::deadline::DeadlineTracker::new(
                deadline_period,
            )),
            deadline_missed_total: std::sync::atomic::AtomicU32::new(0),
            #[cfg(feature = "security")]
            security,
            written_instances: std::sync::Mutex::new(std::collections::HashSet::new()),
            publisher: None,
            last_sn_in_active_set,
            _coherent_bridge: None,
            _phantom: core::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        // DDS spec 2.2.2.4.2.2: KEEP_LAST depth applies PER INSTANCE; the
        // global cap is left at the user value so multi-instance topics are
        // not starved. See derive_history_and_limits, non-durable branch.
        // (Test assertion updated to match the spec-correct logic introduced
        // in f9615d7, which had left this assertion on the pre-fix value of 5.)
        assert_eq!(limits.max_samples, base_limits().max_samples);
        assert_eq!(limits.max_samples_per_instance, 5);
    }

    #[test]
    fn test_derive_history_durable_service_depth_wins() {
        let mut qos = QoS::reliable()
            .transient_local()
            .keep_last(10)
            .durability_service(DurabilityService::keep_last(50, 200, 1, 200));
        qos.resource_limits = base_limits();

        let (history, limits) = derive_history_and_limits(&qos).expect("history derivation");
        assert!(matches!(history, crate::qos::History::KeepLast(50)));
        assert_eq!(limits.max_samples, 50);
        assert_eq!(limits.max_instances, 1);
        assert_eq!(limits.max_samples_per_instance, 50);
    }

    #[test]
    fn test_derive_history_rejects_conflicting_limits() {
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

        let err = derive_history_and_limits(&qos).expect_err("should reject limits");
        let msg = format!("{}", err);
        assert!(msg.contains("ResourceLimits.max_samples"));
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

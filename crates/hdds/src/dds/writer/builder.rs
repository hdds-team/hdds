// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Builder pattern for DataWriter configuration.
//!
//!
//! Provides fluent API for configuring QoS, transport, history cache,
//! and reliability options before constructing a DataWriter instance.

use super::heartbeat_scheduler::{
    spawn_heartbeat_scheduler, HeartbeatSchedulerHandle, DEFAULT_HEARTBEAT_PERIOD_MS,
};
use super::nack::{WriterNackFragHandler, WriterNackHandler};
use super::runtime::DataWriter;
use super::runtime::WriterReplayState;
use crate::core::discovery::ReplayRegistry;
use crate::core::discovery::GUID;
use crate::core::rt;
use crate::dds::listener::DataWriterListener;
use crate::dds::{DomainState, Error, MatchKey, QoS, Result, TypeId, DDS};
use crate::protocol::builder::RtpsEndpointContext;
use crate::reliability::{HeartbeatTx, HistoryCache, ReliableMetrics};
#[cfg(target_os = "linux")]
use crate::transport::shm::ShmPolicy;
use crate::transport::UdpTransport;
use crate::xtypes::CompleteTypeObject;
use std::cell::RefCell;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn validate_resource_limits(limits: &crate::qos::ResourceLimits) -> Result<()> {
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
        super::super::qos::Durability::TransientLocal | super::super::qos::Durability::Persistent
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
                resource_limits.max_samples = depth as usize;
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
            participant: None,
            domain_state: None,
            type_name_override: None,
            type_object_override: None,
            replay_registry: None,
            #[cfg(target_os = "linux")]
            shm_policy: ShmPolicy::default(),
            listener: None,
            _phantom: core::marker::PhantomData,
        }
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
                        super::super::qos::Durability::TransientLocal => {
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
            // Default: use ENTITYID_UNKNOWN so that DATA is not tied to a
            // specific remote reader. Targeting concrete reader EntityIds is
            // only needed for specialised interop modes and is handled at a
            // higher level when required.
            let reader_entity_id = [0, 0, 0, 0x00];
            Some(RtpsEndpointContext {
                guid_prefix: guid.prefix,
                reader_entity_id,
                writer_entity_id: entity_id,
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
                ));
                registry.register_nack_frag_handler(frag_handler);
            }
        }

        let merger = if let Some(ref cache) = history_cache {
            let needs_late_joiner = matches!(
                self.qos.durability,
                super::super::qos::Durability::TransientLocal
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

        Ok(DataWriter {
            topic: self.topic,
            qos: self.qos,
            rtps_endpoint,
            merger,
            transport: self.transport,
            next_seq: AtomicU64::new(next_seq),
            history_cache,
            reliable_metrics,
            heartbeat_tx,
            _heartbeat_scheduler: heartbeat_scheduler,
            endpoint_registry: self.endpoint_registry,
            _bind_token: bind_token,
            _replay_token: replay_token,
            listener: self.listener,
            #[cfg(feature = "security")]
            security,
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
        assert_eq!(limits.max_samples, 5);
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

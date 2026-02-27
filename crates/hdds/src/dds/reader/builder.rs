// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Builder pattern for DataReader configuration.
//!
//!
//! Provides fluent API for configuring QoS, transport, and runtime options
//! before constructing a DataReader instance.

use super::heartbeat::ReaderHeartbeatHandler;
use super::runtime::DataReader;
use super::subscriber::ReaderSubscriber;
use crate::config::READER_HISTORY_RING_SIZE;
use crate::core::discovery::GUID;
use crate::core::rt;
use crate::dds::filter::FilterEvaluator;
use crate::dds::listener::DataReaderListener;
use crate::dds::qos::{History, Reliability};
use crate::dds::{
    DomainState, Error, GuardCondition, MatchKey, QoS, Result, StatusCondition, StatusMask, TypeId,
    DDS,
};
use crate::engine::TopicRegistry;
use crate::reliability::{NackScheduler, ReliableMetrics};
#[cfg(target_os = "linux")]
use crate::transport::shm::ShmPolicy;
use crate::transport::UdpTransport;
use crate::xtypes::CompleteTypeObject;
use std::sync::{Arc, Mutex};

pub struct ReaderBuilder<T: DDS> {
    pub(super) topic: String,
    pub(super) qos: QoS,
    pub(super) registry: Option<Arc<TopicRegistry>>,
    pub(super) transport: Option<Arc<UdpTransport>>,
    pub(super) participant_guard: Option<Arc<GuardCondition>>,
    pub(super) participant: Option<Arc<crate::Participant>>,
    pub(super) domain_state: Option<Arc<DomainState>>,
    pub(super) type_name_override: Option<String>,
    pub(super) type_object_override: Option<CompleteTypeObject>,
    /// SHM transport policy (Linux only)
    #[cfg(target_os = "linux")]
    pub(super) shm_policy: ShmPolicy,
    /// Content filter for ContentFilteredTopic
    pub(super) content_filter: Option<FilterEvaluator>,
    /// Listener for data callbacks
    pub(super) listener: Option<Arc<dyn DataReaderListener<T>>>,
    pub(super) _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> ReaderBuilder<T> {
    pub(crate) fn new(topic: String) -> Self {
        Self {
            topic,
            qos: QoS::best_effort(),
            registry: None,
            transport: None,
            participant_guard: None,
            participant: None,
            domain_state: None,
            type_name_override: None,
            type_object_override: None,
            #[cfg(target_os = "linux")]
            shm_policy: ShmPolicy::default(),
            content_filter: None,
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

    pub fn with_registry(mut self, registry: Arc<TopicRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn with_transport(mut self, transport: Arc<UdpTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn with_participant_guard(mut self, guard: Arc<GuardCondition>) -> Self {
        log::debug!(
            "[READER-BUILDER] attaching participant guard for topic='{}'",
            self.topic
        );
        self.participant_guard = Some(guard);
        self
    }

    pub fn with_domain_state(mut self, domain_state: Arc<DomainState>) -> Self {
        self.domain_state = Some(domain_state);
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

    /// Set content filter for ContentFilteredTopic.
    ///
    /// When set, the reader will only receive samples that match the filter.
    /// This is typically set automatically when creating a reader from a
    /// ContentFilteredTopic.
    pub fn with_content_filter(mut self, filter: FilterEvaluator) -> Self {
        self.content_filter = Some(filter);
        self
    }

    /// Set a listener for data callbacks.
    ///
    /// The listener will be called when data arrives, when subscriptions
    /// are matched, and for other reader events.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, QoS, DataReaderListener, ClosureListener};
    /// use std::sync::Arc;
    ///
    /// // Simple closure-based listener
    /// let listener = ClosureListener::new(|sample: &Temperature| {
    ///     println!("Received: {:?}", sample);
    /// });
    ///
    /// let reader = participant
    ///     .create_reader::<Temperature>("temp", QoS::default())
    ///     .with_listener(Arc::new(listener))
    ///     .build()?;
    /// ```
    pub fn with_listener(mut self, listener: Arc<dyn DataReaderListener<T>>) -> Self {
        self.listener = Some(listener);
        self
    }

    pub fn build(mut self) -> Result<DataReader<T>> {
        // Extract configs from participant if not explicitly provided
        // (mirrors WriterBuilder behavior for API consistency)
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
            if self.participant_guard.is_none() {
                self.participant_guard = Some(participant.graph_guard());
            }
            if self.domain_state.is_none() {
                self.domain_state = Some(participant.domain_state.clone());
            }
        }

        // DDS Security: Check access control permissions for reader creation
        #[cfg(feature = "security")]
        if let Some(ref participant) = self.participant {
            let partition = self.qos.partition.names.first().map(|s| s.as_str());
            participant.check_create_reader(&self.topic, partition)?;
        }

        let ReaderBuilder {
            topic,
            qos,
            registry,
            transport,
            participant_guard,
            participant,
            domain_state,
            type_name_override,
            type_object_override,
            content_filter,
            listener,
            ..
        } = self;

        if matches!(qos.history, History::KeepLast(0)) {
            return Err(Error::InvalidState(
                "History::KeepLast requires depth > 0".to_string(),
            ));
        }
        if matches!(qos.history, History::KeepAll) && qos.resource_limits.max_samples == 0 {
            return Err(Error::InvalidState(
                "History::KeepAll requires ResourceLimits.max_samples > 0".to_string(),
            ));
        }

        // Ring must be larger than history depth to buffer incoming samples
        // before enforce_history() trims at read time. Use READER_HISTORY_RING_SIZE
        // as minimum to handle writer bursts without dropping newest samples.
        let ring_capacity = match qos.history {
            History::KeepLast(depth) => std::cmp::max(depth as usize, READER_HISTORY_RING_SIZE),
            History::KeepAll => {
                std::cmp::max(qos.resource_limits.max_samples, READER_HISTORY_RING_SIZE)
            }
        };
        let ring = Arc::new(rt::IndexRing::with_capacity(ring_capacity));
        let status_condition = Arc::new(StatusCondition::new());
        status_condition.set_enabled_statuses(StatusMask::DATA_AVAILABLE);

        if let Some(ref registry) = registry {
            let subscriber: Arc<dyn crate::engine::Subscriber> =
                Arc::new(ReaderSubscriber::<T>::new(
                    topic.clone(),
                    Arc::clone(&ring),
                    Arc::clone(&status_condition),
                    participant_guard.as_ref().map(Arc::clone),
                    content_filter.clone(),
                    listener.clone(),
                ));

            if let Err(err) = registry.register_subscriber(subscriber) {
                log::debug!("Failed to register subscriber: {}", err);
            }
        }

        let is_reliable = matches!(qos.reliability, Reliability::Reliable);
        let reliable_metrics = is_reliable.then(|| Arc::new(ReliableMetrics::new()));

        let nack_scheduler = if is_reliable {
            let scheduler = Arc::new(Mutex::new(NackScheduler::new()));

            if let (Some(metrics), Ok(mut guard)) = (reliable_metrics.clone(), scheduler.lock()) {
                guard.set_metrics(metrics);
            }

            if let Some(ref registry) = registry {
                // Create heartbeat handler with ACKNACK context if we have transport and participant
                let handler: Arc<dyn crate::engine::HeartbeatHandler> =
                    match (&transport, &participant) {
                        (Some(ref xport), Some(ref part)) => {
                            // Get our GUID prefix from participant
                            let guid = part.guid();
                            let our_guid_prefix = guid.prefix;

                            // Generate reader entity ID (use hash of topic for uniqueness)
                            // Note: Uses topic hash for deterministic entity ID allocation.
                            // This ensures the same topic always gets the same entity ID.
                            let topic_hash = {
                                let mut h = 0u32;
                                for b in topic.bytes() {
                                    h = h.wrapping_mul(31).wrapping_add(u32::from(b));
                                }
                                h
                            };
                            let reader_entity_id = [
                                (topic_hash >> 24) as u8,
                                (topic_hash >> 16) as u8,
                                (topic_hash >> 8) as u8,
                                0x04, // ENTITYKIND_READER_NO_KEY (per RTPS spec)
                            ];

                            log::debug!(
                            "[reader] Creating ACKNACK-capable heartbeat handler for topic='{}'",
                            topic
                        );
                            Arc::new(ReaderHeartbeatHandler::with_acknack_context(
                                Arc::clone(&scheduler),
                                our_guid_prefix,
                                reader_entity_id,
                                xport.clone(),
                            ))
                        }
                        _ => {
                            // Fallback: no ACKNACK capability (intra-process mode)
                            Arc::new(ReaderHeartbeatHandler::new(Arc::clone(&scheduler)))
                        }
                    };
                registry.register_heartbeat_handler(handler);
            }

            Some(scheduler)
        } else {
            None
        };

        // v108: Announce Reader endpoint via SEDP (if participant available)
        if let Some(ref p) = participant {
            if let Some(ref type_name) = type_name_override {
                p.announce_reader_endpoint_with_type::<T>(
                    &topic,
                    &qos,
                    type_name,
                    type_object_override.clone(),
                )?;
            } else {
                p.announce_reader_endpoint::<T>(&topic, &qos)?;
            }
        }

        // Register reader in domain state for intra-process auto-binding
        let bind_token = if let Some(ref domain_state) = domain_state {
            let type_name = type_name_override
                .as_deref()
                .unwrap_or(T::type_descriptor().type_name);
            let type_id = TypeId::from_type_name(type_name);
            let key = MatchKey::new(topic.as_str(), type_id);

            // Generate a GUID for this reader endpoint (use zero if no participant)
            let guid = GUID::zero();

            log::debug!(
                "[ReaderBuilder] Registering reader in domain {} for topic='{}' type='{}'",
                domain_state.domain_id,
                topic,
                type_name
            );

            // Create bind callback that will be called for each matching writer
            let ring_clone = Arc::clone(&ring);
            let status_condition_clone = Arc::clone(&status_condition);

            Some(domain_state.register_reader(
                key,
                guid,
                ring.clone(),
                qos.reliability,
                move |writer_merger| {
                    // Create notification callback for status condition
                    let status_condition_for_notify = Arc::clone(&status_condition_clone);
                    let notify: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                        status_condition_for_notify.set_active_statuses(StatusMask::DATA_AVAILABLE);
                    });

                    // Register this reader with the writer's merger
                    let registration = rt::MergerReader::new(Arc::clone(&ring_clone), notify);
                    writer_merger.add_reader(registration);
                },
            ))
        } else {
            None
        };

        // Get security plugin from participant if available
        #[cfg(feature = "security")]
        let security = participant.as_ref().and_then(|p| p.security());

        Ok(DataReader::new(
            topic,
            qos,
            ring,
            registry,
            nack_scheduler,
            transport,
            reliable_metrics,
            status_condition,
            bind_token,
            #[cfg(feature = "security")]
            security,
        ))
    }
}

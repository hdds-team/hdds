// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::core::discovery::multicast::{ControlHandler, DiscoveryFsm};
use crate::core::discovery::GUID;
#[cfg(feature = "security")]
use crate::dds::Error;
use crate::dds::{
    ContentFilteredTopic, DataReader, DataWriter, DomainState, FilterError, GuardCondition,
    Publisher, Result, Subscriber, Topic,
};
#[cfg(feature = "cloud-discovery")]
use crate::discovery::cloud::{CloudDiscoveryPoller, CloudDiscoveryPollerHandle};
#[cfg(feature = "k8s")]
use crate::discovery::k8s::K8sDiscoveryHandle;
use crate::discovery_server::DiscoveryServerConfig;
use crate::engine::{Router as DemuxRouter, TopicRegistry};
use crate::transport::lowbw::LowBwConfig;
#[cfg(feature = "quic")]
use crate::transport::quic::{QuicConfig, QuicIoThread, QuicIoThreadHandle, QuicTransportHandle};
use crate::transport::shm::ShmPolicy;
use crate::transport::tcp::{TcpTransport, TransportPreference};
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

#[cfg(feature = "xtypes")]
use crate::core::types::{Distro, TypeCache, TypeObjectHandle};
#[cfg(feature = "xtypes")]
use crate::xtypes::CompleteTypeObject;
#[cfg(feature = "xtypes")]
use parking_lot::RwLock;
#[cfg(feature = "xtypes")]
use std::collections::HashMap;

/// RTPS ENTITYID_PARTICIPANT (spec 9.3.1)
pub(super) const RTPS_ENTITYID_PARTICIPANT: [u8; 4] = [0, 0, 1, 0xC1];

/// Transport mode for DDS communication.
///
/// Determines how data is exchanged between participants.
///
/// # Variants
///
/// | Mode | Latency | Use Case |
/// |------|---------|----------|
/// | `IntraProcess` | ~257ns | Same process, testing, single-node apps |
/// | `UdpMulticast` | ~10us+ | Network communication, distributed systems |
///
/// # Example
///
/// ```rust,no_run
/// use hdds::{Participant, TransportMode};
///
/// // Fast intra-process for testing
/// let test_participant = Participant::builder("test")
///     .with_transport(TransportMode::IntraProcess)
///     .build()?;
///
/// // Network communication for production
/// let prod_participant = Participant::builder("robot")
///     .with_transport(TransportMode::UdpMulticast)
///     .domain_id(42)
///     .build()?;
/// # Ok::<(), hdds::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportMode {
    /// In-process communication via shared memory (zero-copy).
    ///
    /// Best for: testing, single-process applications, maximum performance.
    /// Limitation: cannot communicate with other processes.
    IntraProcess,

    /// UDP multicast for network discovery and communication.
    ///
    /// Best for: distributed systems, multi-host deployments, ROS 2 interop.
    /// Requires: network access, multicast-enabled network (or static peers).
    UdpMulticast,
}

/// DDS Domain Participant - the entry point to the HDDS middleware.
///
/// A `Participant` represents a single node in a DDS domain. It is the factory
/// for all DDS entities (publishers, subscribers, topics, readers, writers) and
/// manages discovery with other participants.
///
/// # Creating a Participant
///
/// Use the builder pattern via [`Participant::builder`]:
///
/// ```rust,no_run
/// use hdds::{Participant, TransportMode};
///
/// let participant = Participant::builder("my_app")
///     .domain_id(0)
///     .with_transport(TransportMode::UdpMulticast)
///     .build()?;
/// # Ok::<(), hdds::Error>(())
/// ```
///
/// # Thread Safety
///
/// `Participant` is wrapped in `Arc<Participant>` after creation and is
/// `Send + Sync`. All methods that create entities take `&Arc<Self>`.
///
/// # Lifecycle
///
/// When dropped, the participant:
/// 1. Stops the lease tracker (cleanup of expired peers)
/// 2. Stops telemetry collection
/// 3. Closes all network sockets
///
/// All child entities (readers, writers) hold an `Arc` to the participant,
/// so the participant remains alive until all children are dropped.
///
/// # See Also
///
/// - `ParticipantBuilder` - Configuration options
/// - [DDS Spec Sec.2.2.1](https://www.omg.org/spec/DDS/1.4/) - DomainParticipant
#[allow(clippy::struct_field_names)]
pub struct Participant {
    pub(super) name: String,
    pub(super) transport_mode: TransportMode,
    pub(super) domain_id: u32,
    pub(super) participant_id: u8,
    pub(super) guid: GUID,
    pub(super) port_mapping: Option<crate::transport::PortMapping>,
    pub(crate) transport: Option<Arc<UdpTransport>>,
    /// TCP transport for WAN/Internet communication (HDDS-to-HDDS only)
    pub(crate) tcp_transport: Option<Arc<TcpTransport>>,
    /// Transport preference (UDP only, TCP only, hybrid)
    pub(crate) transport_preference: TransportPreference,
    /// QUIC configuration for async transport creation
    #[cfg(feature = "quic")]
    pub(crate) quic_config: Option<QuicConfig>,
    /// Low Bandwidth transport configuration (for constrained links)
    pub(crate) lowbw_config: Option<LowBwConfig>,
    /// Discovery Server configuration (for environments without multicast)
    pub(crate) discovery_server_config: Option<DiscoveryServerConfig>,
    /// Cloud discovery provider (consul, aws, azure)
    #[cfg(feature = "cloud-discovery")]
    pub(crate) cloud_discovery_provider: Option<String>,
    /// Cloud discovery endpoint/config
    #[cfg(feature = "cloud-discovery")]
    pub(crate) cloud_discovery_config: Option<String>,
    /// Shared Memory transport policy
    pub(crate) shm_policy: ShmPolicy,
    pub(crate) registry: Option<Arc<TopicRegistry>>,
    pub(super) router: Option<Arc<DemuxRouter>>,
    pub(crate) discovery_fsm: Option<Arc<DiscoveryFsm>>,
    #[cfg(feature = "xtypes")]
    pub(super) type_cache: Arc<TypeCache>,
    #[cfg(feature = "xtypes")]
    pub(super) distro: Distro,
    #[cfg(feature = "xtypes")]
    pub(super) registered_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    #[cfg(feature = "xtypes")]
    pub(super) topic_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    pub(super) telemetry_shutdown: Arc<AtomicBool>,
    pub(super) telemetry_handle: Option<JoinHandle<()>>,
    /// SPDP announcer thread (kept alive for automatic cleanup on Drop)
    pub(super) _spdp_announcer: Option<crate::core::discovery::SpdpAnnouncer>,
    /// Lease tracker thread (removes expired participants)
    pub(super) lease_tracker: Option<crate::core::discovery::multicast::LeaseTracker>,
    /// v230: ControlHandler for Two-Ring HEARTBEAT/ACKNACK processing.
    /// Must be stored in Participant to prevent immediate Drop (which stops the thread).
    pub(super) _control_handler: Option<ControlHandler>,
    /// v230: Multicast listeners must be stored to prevent immediate Drop.
    /// If dropped, listener threads exit (running flag set to false).
    pub(super) _listeners: Vec<crate::core::discovery::multicast::MulticastListener>,
    pub(super) graph_guard: Arc<GuardCondition>,
    /// Cache of local SEDP announcements (Reader/Writer) for unicast replay to newly discovered peers
    /// Used by discovery callback to re-announce endpoints via unicast (RTI interop)
    pub(super) sedp_announcements: Arc<
        std::sync::RwLock<
            Vec<(
                crate::protocol::discovery::SedpData,
                crate::core::discovery::multicast::SedpEndpointKind,
            )>,
        >,
    >,
    /// Dialect detector for vendor auto-detection (Phase 1: monitoring passif)
    /// Observes SPDP packets to detect FastDDS/RTI/Cyclone, logs decision
    /// Phase 2 will add hot-reconfig based on detection
    #[allow(dead_code)] // Used via Arc::clone in discovery callback
    pub(super) dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
    /// Incremental key allocator for user entity IDs (ensures unique GUIDs per endpoint)
    pub(super) next_entity_key: AtomicU32,
    /// Domain state for intra-process auto-binding
    pub(crate) domain_state: Arc<DomainState>,
    /// DDS Security plugin suite (authentication, access control, crypto, logging)
    ///
    /// When set, security checks are performed on writer/reader creation and data operations.
    #[cfg(feature = "security")]
    pub(crate) security: Option<Arc<crate::security::SecurityPluginSuite>>,
    /// Kubernetes DNS-based discovery handle (for cleanup on drop)
    ///
    /// When dropped, stops the background DNS polling thread.
    #[cfg(feature = "k8s")]
    #[allow(dead_code)] // Used for automatic cleanup on drop
    pub(super) k8s_discovery_handle: Option<K8sDiscoveryHandle>,
    /// v233: QUIC I/O thread for sync access to async QUIC transport
    ///
    /// When configured via `.with_quic()`, this thread is spawned automatically
    /// and provides sync access via `quic_handle()`.
    #[cfg(feature = "quic")]
    pub(super) quic_io_thread: Option<QuicIoThread>,
    /// v233: Cloud discovery poller thread for sync access to async discovery
    ///
    /// When configured via `.with_consul()` etc., this thread is spawned automatically
    /// and provides sync access via `cloud_discovery_handle()`.
    #[cfg(feature = "cloud-discovery")]
    pub(super) cloud_discovery_poller: Option<CloudDiscoveryPoller>,
    /// Sprint 7: Unicast routing thread (TCP/QUIC → TopicRegistry).
    /// Stored to prevent Drop until Participant drops.
    pub(super) _unicast_routing_thread:
        Option<super::builder::unicast_routing::UnicastRoutingThread>,
}

impl Participant {
    pub fn domain_id(&self) -> u32 {
        self.domain_id
    }

    pub fn participant_id(&self) -> u8 {
        self.participant_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn transport_mode(&self) -> TransportMode {
        self.transport_mode
    }

    pub fn port_mapping(&self) -> Option<&crate::transport::PortMapping> {
        self.port_mapping.as_ref()
    }

    pub fn transport(&self) -> Option<Arc<UdpTransport>> {
        self.transport.clone()
    }

    /// Get TCP transport (if configured).
    ///
    /// Returns `Some(Arc<TcpTransport>)` if TCP was enabled via
    /// `ParticipantBuilder::with_tcp` or `ParticipantBuilder::tcp_config`.
    pub fn tcp_transport(&self) -> Option<Arc<TcpTransport>> {
        self.tcp_transport.clone()
    }

    /// Get transport preference (UDP only, TCP only, hybrid).
    pub fn transport_preference(&self) -> TransportPreference {
        self.transport_preference
    }

    pub fn guid(&self) -> GUID {
        self.guid
    }

    pub fn discovery(&self) -> Option<Arc<DiscoveryFsm>> {
        self.discovery_fsm.clone()
    }

    /// Get security plugin suite (if security is enabled).
    ///
    /// Returns `Some(Arc<SecurityPluginSuite>)` if security was configured,
    /// `None` otherwise.
    #[cfg(feature = "security")]
    pub fn security(&self) -> Option<Arc<crate::security::SecurityPluginSuite>> {
        self.security.clone()
    }

    /// Check if access control allows creating a writer for the given topic.
    ///
    /// Returns `Ok(())` if allowed, `Err(PermissionsDenied)` if denied.
    #[cfg(feature = "security")]
    pub(crate) fn check_create_writer(&self, topic: &str, partition: Option<&str>) -> Result<()> {
        if let Some(ref security) = self.security {
            if let Some(access_control) = security.access_control() {
                let resource = format!("{}:{}", topic, partition.unwrap_or("*"));
                match access_control.check_create_writer(topic, partition) {
                    Ok(()) => {
                        self.log_access_control_event("create_writer", &resource, true);
                    }
                    Err(e) => {
                        self.log_access_control_event("create_writer", &resource, false);
                        return Err(Error::PermissionDenied(format!(
                            "Access control denied: cannot create writer for topic '{}': {}",
                            topic, e
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Check if access control allows creating a reader for the given topic.
    ///
    /// Returns `Ok(())` if allowed, `Err(PermissionsDenied)` if denied.
    #[cfg(feature = "security")]
    pub(crate) fn check_create_reader(&self, topic: &str, partition: Option<&str>) -> Result<()> {
        if let Some(ref security) = self.security {
            if let Some(access_control) = security.access_control() {
                let resource = format!("{}:{}", topic, partition.unwrap_or("*"));
                match access_control.check_create_reader(topic, partition) {
                    Ok(()) => {
                        self.log_access_control_event("create_reader", &resource, true);
                    }
                    Err(e) => {
                        self.log_access_control_event("create_reader", &resource, false);
                        return Err(Error::PermissionDenied(format!(
                            "Access control denied: cannot create reader for topic '{}': {}",
                            topic, e
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Encrypt a payload using the cryptographic plugin if encryption is enabled.
    ///
    /// Returns the encrypted payload, or the original payload if encryption is disabled.
    #[cfg(feature = "security")]
    #[allow(dead_code)] // Part of security API, used when encryption is enabled
    pub(crate) fn encrypt_payload(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if let Some(ref security) = self.security {
            if let Some(crypto) = security.cryptographic() {
                // Use session key ID 0 for now (local encryption)
                // Full ECDH key exchange is done during discovery handshake
                return crypto
                    .encrypt_data(plaintext, 0)
                    .map_err(|e| Error::InvalidState(format!("Encryption failed: {}", e)));
            }
        }
        // No encryption, return original data
        Ok(plaintext.to_vec())
    }

    /// Decrypt a payload using the cryptographic plugin if encryption is enabled.
    ///
    /// Returns the decrypted payload, or the original payload if encryption is disabled.
    #[cfg(feature = "security")]
    #[allow(dead_code)] // Part of security API, used when encryption is enabled
    pub(crate) fn decrypt_payload(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if let Some(ref security) = self.security {
            if let Some(crypto) = security.cryptographic() {
                // Use session key ID 0 for now (local encryption)
                return crypto
                    .decrypt_data(ciphertext, 0)
                    .map_err(|e| Error::InvalidState(format!("Decryption failed: {}", e)));
            }
        }
        // No encryption, return original data
        Ok(ciphertext.to_vec())
    }

    /// Check if encryption is enabled for this participant.
    #[cfg(feature = "security")]
    pub fn is_encryption_enabled(&self) -> bool {
        self.security
            .as_ref()
            .is_some_and(|s| s.is_encryption_enabled())
    }

    /// Log an access control event (create writer/reader allowed/denied).
    #[cfg(feature = "security")]
    pub(crate) fn log_access_control_event(&self, action: &str, resource: &str, allowed: bool) {
        use std::time::{SystemTime, UNIX_EPOCH};

        if let Some(ref security) = self.security {
            // Need interior mutability for logging - use Arc<Mutex<LoggingPlugin>>
            // For now, just log to standard log if audit logging is enabled
            if security.is_audit_log_enabled() {
                let outcome = if allowed { "ALLOWED" } else { "DENIED" };
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                log::info!(
                    "[SECURITY AUDIT] AccessControl: action={} resource={} outcome={} timestamp={} guid={:?}",
                    action, resource, outcome, timestamp, self.guid.prefix
                );
            }
        }
    }

    /// Log an authentication event (participant validated/rejected).
    #[cfg(feature = "security")]
    #[allow(dead_code)] // Part of security audit API, used during authentication
    pub(crate) fn log_authentication_event(&self, outcome: bool, participant_guid: [u8; 16]) {
        use std::time::{SystemTime, UNIX_EPOCH};

        if let Some(ref security) = self.security {
            if security.is_audit_log_enabled() {
                let outcome_str = if outcome { "SUCCESS" } else { "FAILED" };
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                log::info!(
                    "[SECURITY AUDIT] Authentication: outcome={} participant={:02x?} timestamp={}",
                    outcome_str,
                    participant_guid,
                    timestamp
                );
            }
        }
    }

    pub fn topic<T: crate::dds::DDS>(self: &Arc<Self>, name: &str) -> Result<Topic<T>> {
        Ok(Topic::new(name.to_string(), Arc::clone(self)))
    }

    /// Create a ContentFilteredTopic with SQL-like filtering.
    ///
    /// A ContentFilteredTopic is a specialized topic that filters incoming samples
    /// based on a SQL-like expression. Only samples matching the filter are delivered
    /// to DataReaders created from this topic.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for this filtered topic (for identification)
    /// * `related_topic_name` - Name of the underlying topic to subscribe to
    /// * `filter_expression` - SQL-like filter expression (e.g., "value > %0")
    /// * `expression_parameters` - Values for %0, %1, etc. in the expression
    ///
    /// # Filter Expression Syntax
    ///
    /// ```text
    /// expression ::= condition
    ///              | expression AND expression
    ///              | expression OR expression
    ///              | NOT expression
    ///              | '(' expression ')'
    ///
    /// condition  ::= field_name operator value
    /// operator   ::= '>' | '<' | '>=' | '<=' | '=' | '<>' | '!='
    /// value      ::= parameter (%0, %1, ...) | integer | float | 'string'
    /// ```
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, QoS};
    ///
    /// #[derive(hdds::DDS)]
    /// struct Temperature { sensor_id: u32, value: f64 }
    ///
    /// let participant = Participant::builder("app").build()?;
    ///
    /// // Only receive temperatures > 25.0
    /// let filtered = participant.create_content_filtered_topic::<Temperature>(
    ///     "high_temp",
    ///     "sensors/temperature",
    ///     "value > %0",
    ///     vec!["25.0".to_string()],
    /// )?;
    ///
    /// let reader = filtered.reader().build()?;
    /// ```
    ///
    /// # Note
    ///
    /// For full content filtering to work, DDS types must implement the `get_fields()`
    /// method to extract field values. Types that don't implement this will pass all
    /// samples through the filter.
    pub fn create_content_filtered_topic<T: crate::dds::DDS>(
        self: &Arc<Self>,
        name: &str,
        related_topic_name: &str,
        filter_expression: &str,
        expression_parameters: Vec<String>,
    ) -> std::result::Result<ContentFilteredTopic<T>, FilterError> {
        ContentFilteredTopic::new(
            name,
            related_topic_name,
            filter_expression,
            expression_parameters,
            Arc::clone(self),
        )
    }

    #[cfg(feature = "xtypes")]
    #[allow(clippy::missing_panics_doc)]
    pub fn type_cache(&self) -> Arc<TypeCache> {
        self.type_cache.clone()
    }

    #[cfg(feature = "xtypes")]
    pub fn default_distro(&self) -> Distro {
        self.distro
    }

    pub fn create_publisher(self: &Arc<Self>, qos: crate::dds::QoS) -> Result<Publisher> {
        Ok(Publisher::new(
            qos,
            self.transport.clone(),
            self.registry.clone(),
            Some(Arc::clone(self)),
        ))
    }

    pub fn router(&self) -> Option<Arc<DemuxRouter>> {
        self.router.clone()
    }

    pub fn create_subscriber(self: &Arc<Self>, qos: crate::dds::QoS) -> Result<Subscriber> {
        Ok(Subscriber::new(
            qos,
            self.transport.clone(),
            self.registry.clone(),
            Some(Arc::clone(self)),
        ))
    }

    /// Access the participant-level discovery guard condition.
    #[must_use]
    pub fn graph_guard(&self) -> Arc<GuardCondition> {
        Arc::clone(&self.graph_guard)
    }

    pub fn create_writer<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
    ) -> Result<DataWriter<T>> {
        // DDS Security v1.1: Check access control before creating writer
        #[cfg(feature = "security")]
        if let Some(ref security) = self.security {
            if let Some(access_control) = security.access_control() {
                // Extract partition from QoS (first partition or None)
                let partition = qos.partition.names.first().map(String::as_str);
                let check_result = access_control.check_create_writer(topic, partition);

                // Log access control event (DDS Security v1.1 Sec.8.6)
                let outcome = if check_result.is_ok() {
                    crate::security::audit::AccessOutcome::Allowed
                } else {
                    crate::security::audit::AccessOutcome::Denied
                };
                let event = crate::security::audit::SecurityEvent::AccessControl {
                    participant_guid: self.guid.as_bytes(),
                    action: "create_writer".to_string(),
                    resource: topic.to_string(),
                    outcome,
                    timestamp: crate::telemetry::metrics::current_time_ns(),
                };
                let _ = security.log_security_event(&event);

                check_result.map_err(|e| {
                    log::warn!(
                        "[security] Access denied for writer on topic '{}': {}",
                        topic,
                        e
                    );
                    crate::dds::Error::PermissionDenied(format!(
                        "Cannot create writer on '{}': {}",
                        topic, e
                    ))
                })?;
            }
        }

        let mut builder = self.topic(topic)?.writer().qos(qos.clone());

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        // v102: Pass endpoint_registry to writer for unicast DATA sends
        if let Some(ref discovery_fsm) = self.discovery_fsm {
            builder = builder.with_endpoint_registry(discovery_fsm.endpoint_registry());
            builder = builder.with_replay_registry(discovery_fsm.replay_registry());
        }

        // Pass domain state for intra-process auto-binding
        builder = builder.with_domain_state(self.domain_state.clone());

        builder.build()
    }

    pub fn create_reader<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
    ) -> Result<DataReader<T>> {
        // DDS Security v1.1: Check access control before creating reader
        #[cfg(feature = "security")]
        if let Some(ref security) = self.security {
            if let Some(access_control) = security.access_control() {
                // Extract partition from QoS (first partition or None)
                let partition = qos.partition.names.first().map(String::as_str);
                let check_result = access_control.check_create_reader(topic, partition);

                // Log access control event (DDS Security v1.1 Sec.8.6)
                let outcome = if check_result.is_ok() {
                    crate::security::audit::AccessOutcome::Allowed
                } else {
                    crate::security::audit::AccessOutcome::Denied
                };
                let event = crate::security::audit::SecurityEvent::AccessControl {
                    participant_guid: self.guid.as_bytes(),
                    action: "create_reader".to_string(),
                    resource: topic.to_string(),
                    outcome,
                    timestamp: crate::telemetry::metrics::current_time_ns(),
                };
                let _ = security.log_security_event(&event);

                check_result.map_err(|e| {
                    log::warn!(
                        "[security] Access denied for reader on topic '{}': {}",
                        topic,
                        e
                    );
                    crate::dds::Error::PermissionDenied(format!(
                        "Cannot create reader on '{}': {}",
                        topic, e
                    ))
                })?;
            }
        }

        let mut builder = self.topic(topic)?.reader().qos(qos.clone());

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        builder = builder.with_participant_guard(self.graph_guard());

        // Pass domain state for intra-process auto-binding
        builder = builder.with_domain_state(self.domain_state.clone());

        let reader = builder.build()?;
        Ok(reader)
    }

    /// Create a DataReader with explicit DDS type metadata overrides.
    ///
    /// # Arguments
    /// * `topic` - Topic name to bind the reader to.
    /// * `qos` - QoS profile to apply.
    /// * `type_name` - DDS type name to announce for discovery.
    /// * `type_object` - Optional XTypes CompleteTypeObject for discovery.
    ///
    /// # Returns
    /// Returns a fully configured `DataReader<T>` bound to the topic.
    ///
    /// # Errors
    /// Returns any reader construction errors (transport unavailable, discovery errors, etc.).
    ///
    /// # Panics
    /// Does not panic.
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, QoS, DDS};
    ///
    /// #[derive(DDS)]
    /// struct Pose {
    ///     x: f32,
    ///     y: f32,
    ///     z: f32,
    /// }
    ///
    /// # fn main() -> hdds::Result<()> {
    /// let participant = Participant::builder("reader").domain_id(0).build()?;
    /// let reader = participant.create_reader_with_type::<Pose>(
    ///     "/pose",
    ///     QoS::default(),
    ///     "example::msg::Pose",
    ///     None,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Latency Contract
    /// - Reader creation (control path): p99 < 5 ms
    #[cfg(feature = "xtypes")]
    pub fn create_reader_with_type<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
        type_name: &str,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<DataReader<T>> {
        // DDS Security v1.1: Check access control before creating reader
        #[cfg(feature = "security")]
        if let Some(ref security) = self.security {
            if let Some(access_control) = security.access_control() {
                let partition = qos.partition.names.first().map(String::as_str);
                access_control
                    .check_create_reader(topic, partition)
                    .map_err(|e| {
                        log::warn!(
                            "[security] Access denied for reader on topic '{}': {}",
                            topic,
                            e
                        );
                        crate::dds::Error::PermissionDenied(format!(
                            "Cannot create reader on '{}': {}",
                            topic, e
                        ))
                    })?;
            }
        }

        let mut builder = self
            .topic(topic)?
            .reader()
            .qos(qos.clone())
            .with_type_name_override(type_name);

        if let Some(type_object) = type_object {
            builder = builder.with_type_object_override(type_object);
        }

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        builder = builder.with_participant_guard(self.graph_guard());
        builder = builder.with_domain_state(self.domain_state.clone());

        builder.build()
    }

    /// Create a DataWriter with explicit DDS type metadata overrides.
    ///
    /// # Arguments
    /// * `topic` - Topic name to bind the writer to.
    /// * `qos` - QoS profile to apply.
    /// * `type_name` - DDS type name to announce for discovery.
    /// * `type_object` - Optional XTypes CompleteTypeObject for discovery.
    ///
    /// # Returns
    /// Returns a fully configured `DataWriter<T>` bound to the topic.
    ///
    /// # Errors
    /// Returns any writer construction errors (transport unavailable, discovery errors, etc.).
    ///
    /// # Panics
    /// Does not panic.
    ///
    /// # Example
    /// ```no_run
    /// use hdds::{Participant, QoS, DDS};
    ///
    /// #[derive(DDS)]
    /// struct Pose {
    ///     x: f32,
    ///     y: f32,
    ///     z: f32,
    /// }
    ///
    /// # fn main() -> hdds::Result<()> {
    /// let participant = Participant::builder("writer").domain_id(0).build()?;
    /// let writer = participant.create_writer_with_type::<Pose>(
    ///     "/pose",
    ///     QoS::default(),
    ///     "example::msg::Pose",
    ///     None,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Latency Contract
    /// - Writer creation (control path): p99 < 5 ms
    #[cfg(feature = "xtypes")]
    pub fn create_writer_with_type<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
        type_name: &str,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<DataWriter<T>> {
        // DDS Security v1.1: Check access control before creating writer
        #[cfg(feature = "security")]
        if let Some(ref security) = self.security {
            if let Some(access_control) = security.access_control() {
                let partition = qos.partition.names.first().map(String::as_str);
                access_control
                    .check_create_writer(topic, partition)
                    .map_err(|e| {
                        log::warn!(
                            "[security] Access denied for writer on topic '{}': {}",
                            topic,
                            e
                        );
                        crate::dds::Error::PermissionDenied(format!(
                            "Cannot create writer on '{}': {}",
                            topic, e
                        ))
                    })?;
            }
        }

        let mut builder = self
            .topic(topic)?
            .writer()
            .qos(qos.clone())
            .with_type_name_override(type_name);

        if let Some(type_object) = type_object {
            builder = builder.with_type_object_override(type_object);
        }

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        if let Some(ref discovery_fsm) = self.discovery_fsm {
            builder = builder.with_endpoint_registry(discovery_fsm.endpoint_registry());
        }

        builder = builder.with_domain_state(self.domain_state.clone());

        builder.build()
    }

    /// Allocate a unique EntityId for a user endpoint.
    ///
    /// EntityId layout (RTPS v2.3 Table 9.2):
    /// - bytes 0..3: 24-bit entity key (little-endian)
    /// - byte 3: entity kind (writer=0x03, reader=0x04)
    pub(super) fn next_user_entity_id(&self, entity_kind: u8) -> [u8; 4] {
        let key = (self.next_entity_key.fetch_add(1, Ordering::Relaxed) + 1) & 0x00FF_FFFF;
        let key_bytes = key.to_le_bytes();
        [key_bytes[0], key_bytes[1], key_bytes[2], entity_kind]
    }

    // =========================================================================
    // TCP Transport Methods (HDDS-to-HDDS WAN communication)
    // =========================================================================

    /// Connect to a remote HDDS participant over TCP.
    ///
    /// This establishes a TCP connection to another HDDS participant for
    /// WAN/Internet communication. Note that TCP transport is **not interoperable**
    /// with other DDS vendors - use UDP for cross-vendor communication.
    ///
    /// # Arguments
    /// * `remote_guid_prefix` - The 12-byte GUID prefix of the remote participant
    /// * `addr` - The TCP address of the remote participant (e.g., "192.168.1.100:7410")
    ///
    /// # Returns
    /// * `Ok(())` if connection was initiated (may still be connecting)
    /// * `Err` if TCP transport is not configured or connection failed
    ///
    /// # Example
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    ///
    /// let participant = Participant::builder("client")
    ///     .with_transport(TransportMode::UdpMulticast)
    ///     .with_tcp(0)  // Ephemeral port (client doesn't need fixed port)
    ///     .build()?;
    ///
    /// // Connect to remote server (GUID prefix obtained via discovery or config)
    /// let server_guid = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];
    /// participant.tcp_connect(server_guid, "server.example.com:7410".parse()?)?;
    /// ```
    pub fn tcp_connect(
        &self,
        remote_guid_prefix: [u8; 12],
        addr: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        if let Some(ref tcp) = self.tcp_transport {
            log::info!(
                "[TCP] Connecting to {:02x?} at {}",
                remote_guid_prefix,
                addr
            );
            tcp.connect(remote_guid_prefix, addr)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TCP transport not configured - use .with_tcp() in ParticipantBuilder",
            ))
        }
    }

    /// Check if TCP transport is configured and running.
    ///
    /// Returns `true` if this participant has TCP transport enabled.
    pub fn tcp_enabled(&self) -> bool {
        self.tcp_transport.is_some()
    }

    /// Get the local TCP listen address (if TCP is configured and listening).
    ///
    /// Returns `Some(SocketAddr)` if TCP is enabled and listening,
    /// `None` if TCP is not configured or using client-only mode.
    pub fn tcp_listen_addr(&self) -> Option<std::net::SocketAddr> {
        self.tcp_transport.as_ref().and_then(|tcp| tcp.local_addr())
    }

    /// Get the number of active TCP connections.
    pub fn tcp_connection_count(&self) -> usize {
        self.tcp_transport
            .as_ref()
            .map(|tcp| tcp.connection_count())
            .unwrap_or(0)
    }

    /// Check if we have a TCP connection to a remote participant.
    pub fn tcp_has_connection(&self, remote_guid_prefix: &[u8; 12]) -> bool {
        self.tcp_transport
            .as_ref()
            .map(|tcp| tcp.has_connection(remote_guid_prefix))
            .unwrap_or(false)
    }

    /// Send an RTPS message to a remote participant over TCP.
    ///
    /// Requires an existing TCP connection to the remote participant.
    /// Use [`tcp_connect`](Self::tcp_connect) first if needed.
    pub fn tcp_send(&self, remote_guid_prefix: &[u8; 12], payload: &[u8]) -> std::io::Result<()> {
        if let Some(ref tcp) = self.tcp_transport {
            tcp.send(remote_guid_prefix, payload)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TCP transport not configured",
            ))
        }
    }

    /// Disconnect from a remote TCP peer.
    pub fn tcp_disconnect(&self, remote_guid_prefix: &[u8; 12]) -> std::io::Result<()> {
        if let Some(ref tcp) = self.tcp_transport {
            tcp.disconnect(remote_guid_prefix)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TCP transport not configured",
            ))
        }
    }

    /// Poll for TCP transport events.
    ///
    /// Returns a list of events (connections, disconnections, messages).
    /// Call this regularly if you need to process TCP events manually.
    pub fn tcp_poll(&self) -> Vec<crate::transport::tcp::TcpTransportEvent> {
        self.tcp_transport
            .as_ref()
            .map(|tcp| tcp.poll())
            .unwrap_or_default()
    }

    // =========================================================================
    // QUIC Transport Methods (async, requires tokio runtime)
    // =========================================================================

    /// Returns `true` if QUIC transport is enabled.
    ///
    /// QUIC is enabled when configuration was provided via
    /// [`ParticipantBuilder::with_quic`].
    #[cfg(feature = "quic")]
    pub fn quic_enabled(&self) -> bool {
        self.quic_config.is_some()
    }

    /// Get the QUIC configuration (if configured).
    #[cfg(feature = "quic")]
    pub fn quic_config(&self) -> Option<&QuicConfig> {
        self.quic_config.as_ref()
    }

    /// Create a QUIC transport handle (async).
    ///
    /// QUIC transport requires an async runtime (tokio). This method creates
    /// the transport and returns a handle that can be used for connections.
    ///
    /// # Note
    /// Unlike TCP, QUIC transport is created lazily because it requires async.
    /// Call this method within a tokio runtime context.
    ///
    /// # Example
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::quic::QuicConfig;
    ///
    /// #[tokio::main]
    /// async fn main() -> hdds::Result<()> {
    ///     let quic_config = QuicConfig::default();
    ///
    ///     let participant = Participant::builder("node")
    ///         .with_transport(TransportMode::UdpMulticast)
    ///         .with_quic(quic_config)
    ///         .build()?;
    ///
    ///     // Create QUIC transport (requires async context)
    ///     let quic = participant.create_quic_transport().await?;
    ///
    ///     // Connect to remote peer
    ///     quic.connect("192.168.1.100:7400".parse().unwrap()).await?;
    ///
    ///     // Send data
    ///     quic.send(b"hello", &"192.168.1.100:7400".parse().unwrap()).await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    #[cfg(feature = "quic")]
    pub async fn create_quic_transport(
        &self,
    ) -> crate::transport::quic::QuicResult<QuicTransportHandle> {
        let config = self.quic_config.clone().ok_or_else(|| {
            crate::transport::quic::QuicError::InvalidConfig(
                "QUIC not configured - use .with_quic() in ParticipantBuilder".to_string(),
            )
        })?;

        // Create event channel for the transport (events are consumed by
        // the caller via QuicIoThreadHandle when using the io_thread path;
        // for standalone usage, the receiver is dropped here).
        let (event_tx, _event_rx) = std::sync::mpsc::channel();
        crate::transport::quic::QuicTransport::new(config, event_tx).await
    }

    /// Get the QUIC I/O thread handle (sync).
    ///
    /// v233: Returns a sync handle to the QUIC transport that was automatically
    /// started when QUIC was configured. No tokio runtime required.
    ///
    /// # Example
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::quic::QuicConfig;
    ///
    /// let participant = Participant::builder("node")
    ///     .with_quic(QuicConfig::default())
    ///     .build()?;
    ///
    /// // Get sync handle (no async required!)
    /// if let Some(quic) = participant.quic_handle() {
    ///     quic.connect("192.168.1.100:7400".parse().unwrap())?;
    ///     quic.send("192.168.1.100:7400".parse().unwrap(), b"hello".to_vec())?;
    /// }
    /// ```
    #[cfg(feature = "quic")]
    pub fn quic_handle(&self) -> Option<QuicIoThreadHandle> {
        self.quic_io_thread.as_ref().map(|t| t.handle())
    }

    // =========================================================================
    // Low Bandwidth Transport Methods (for constrained links)
    // =========================================================================

    /// Check if Low Bandwidth transport is configured.
    pub fn lowbw_configured(&self) -> bool {
        self.lowbw_config.is_some()
    }

    /// Get the Low Bandwidth configuration (if configured).
    pub fn lowbw_config(&self) -> Option<&LowBwConfig> {
        self.lowbw_config.as_ref()
    }

    /// Create a Low Bandwidth transport with the given link.
    ///
    /// LowBw transport requires a link implementation (UDP, Serial, etc.).
    /// Use [`LowBwLink`](crate::transport::lowbw::LowBwLink) trait to implement
    /// custom links for your hardware (HC-12, LoRa, satellite modem, etc.).
    ///
    /// # Built-in Links
    /// - `UdpLink` - UDP-based link for testing
    /// - `LoopbackLink` - In-memory loopback for unit tests
    /// - `SimLink` - Simulated link with configurable loss/latency
    ///
    /// # Example: Custom Serial Link
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::transport::lowbw::{LowBwConfig, LowBwLink, LowBwTransport};
    /// use std::sync::Arc;
    ///
    /// // Implement LowBwLink for your serial hardware
    /// struct HC12Link { /* serial port handle */ }
    /// impl LowBwLink for HC12Link {
    ///     fn send(&self, frame: &[u8]) -> std::io::Result<()> { /* ... */ }
    ///     fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> { /* ... */ }
    /// }
    ///
    /// let participant = Participant::builder("gateway")
    ///     .with_lowbw(LowBwConfig::slow_serial())
    ///     .build()?;
    ///
    /// let link = Arc::new(HC12Link::new("/dev/ttyUSB0", 9600)?);
    /// let transport = participant.create_lowbw_transport(link)?;
    /// ```
    pub fn create_lowbw_transport(
        &self,
        link: std::sync::Arc<dyn crate::transport::lowbw::LowBwLink>,
    ) -> std::result::Result<
        crate::transport::lowbw::LowBwTransport,
        crate::transport::lowbw::TransportError,
    > {
        let config = self
            .lowbw_config
            .clone()
            .ok_or(crate::transport::lowbw::TransportError::NotConnected)?;

        Ok(crate::transport::lowbw::LowBwTransport::new(config, link))
    }

    // ========================================================================
    // Discovery Server methods
    // ========================================================================

    /// Check if a Discovery Server is configured.
    pub fn discovery_server_configured(&self) -> bool {
        self.discovery_server_config.is_some()
    }

    /// Get the Discovery Server configuration (if configured).
    pub fn discovery_server_config(&self) -> Option<&DiscoveryServerConfig> {
        self.discovery_server_config.as_ref()
    }

    /// Create a Discovery Server client.
    ///
    /// Returns a client that can connect to a Discovery Server for environments
    /// where UDP multicast is not available (cloud, WAN, NAT traversal).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    /// use hdds::discovery_server::DiscoveryServerConfig;
    ///
    /// let participant = Participant::builder("cloud_app")
    ///     .with_discovery_server(DiscoveryServerConfig::default())
    ///     .build()?;
    ///
    /// let mut client = participant.create_discovery_server_client()?;
    /// client.connect()?;
    /// ```
    pub fn create_discovery_server_client(
        &self,
    ) -> std::result::Result<
        crate::discovery_server::DiscoveryServerClient,
        crate::discovery_server::ClientError,
    > {
        let config = self
            .discovery_server_config
            .clone()
            .ok_or(crate::discovery_server::ClientError::NotConnected)?;

        crate::discovery_server::DiscoveryServerClient::new(config, self.guid.prefix)
    }

    // ========================================================================
    // Cloud Discovery methods
    // ========================================================================

    /// Check if cloud discovery is configured.
    #[cfg(feature = "cloud-discovery")]
    pub fn cloud_discovery_configured(&self) -> bool {
        self.cloud_discovery_provider.is_some()
    }

    /// Get the cloud discovery provider name (consul, aws, azure).
    #[cfg(feature = "cloud-discovery")]
    pub fn cloud_discovery_provider(&self) -> Option<&str> {
        self.cloud_discovery_provider.as_deref()
    }

    /// Get the cloud discovery configuration string.
    #[cfg(feature = "cloud-discovery")]
    pub fn cloud_discovery_config(&self) -> Option<&str> {
        self.cloud_discovery_config.as_deref()
    }

    /// Create a Consul discovery backend.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    ///
    /// let participant = Participant::builder("microservice")
    ///     .with_consul("http://consul.service.consul:8500")
    ///     .build()?;
    ///
    /// let consul = participant.create_consul_discovery()?;
    /// consul.register_participant(&info).await?;
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn create_consul_discovery(
        &self,
    ) -> std::result::Result<crate::discovery::cloud::ConsulDiscovery, crate::dds::Error> {
        let addr = self
            .cloud_discovery_config
            .as_ref()
            .ok_or(crate::dds::Error::Config)?;

        if self.cloud_discovery_provider.as_deref() != Some("consul") {
            return Err(crate::dds::Error::Config);
        }

        crate::discovery::cloud::ConsulDiscovery::new(addr)
    }

    /// Create an AWS Cloud Map discovery backend.
    ///
    /// Requires AWS credentials (via environment or IAM role).
    #[cfg(feature = "cloud-discovery")]
    pub fn create_aws_cloud_map(
        &self,
    ) -> std::result::Result<crate::discovery::cloud::AwsCloudMap, crate::dds::Error> {
        let config = self
            .cloud_discovery_config
            .as_ref()
            .ok_or(crate::dds::Error::Config)?;

        if self.cloud_discovery_provider.as_deref() != Some("aws") {
            return Err(crate::dds::Error::Config);
        }

        // Parse JSON config: {"namespace":"...", "service":"...", "region":"..."}
        let parsed: serde_json::Value =
            serde_json::from_str(config).map_err(|_| crate::dds::Error::Config)?;

        let namespace = parsed
            .get("namespace")
            .and_then(|v| v.as_str())
            .ok_or(crate::dds::Error::Config)?;
        let service = parsed
            .get("service")
            .and_then(|v| v.as_str())
            .unwrap_or("hdds"); // Default service name
        let region = parsed
            .get("region")
            .and_then(|v| v.as_str())
            .ok_or(crate::dds::Error::Config)?;

        crate::discovery::cloud::AwsCloudMap::new(namespace, service, region)
    }

    /// Create an Azure discovery backend.
    #[cfg(feature = "cloud-discovery")]
    pub fn create_azure_discovery(
        &self,
    ) -> std::result::Result<crate::discovery::cloud::AzureDiscovery, crate::dds::Error> {
        let config = self
            .cloud_discovery_config
            .as_ref()
            .ok_or(crate::dds::Error::Config)?;

        if self.cloud_discovery_provider.as_deref() != Some("azure") {
            return Err(crate::dds::Error::Config);
        }

        crate::discovery::cloud::AzureDiscovery::new(config)
    }

    /// Get the cloud discovery poller handle (sync).
    ///
    /// v233: Returns a sync handle to the cloud discovery poller that was
    /// automatically started when cloud discovery was configured.
    /// No tokio runtime required.
    ///
    /// # Example
    /// ```ignore
    /// use hdds::Participant;
    ///
    /// let participant = Participant::builder("node")
    ///     .with_consul("http://localhost:8500")
    ///     .build()?;
    ///
    /// // Get sync handle (no async required!)
    /// if let Some(cloud) = participant.cloud_discovery_handle() {
    ///     // Poll for discovered participants
    ///     for event in cloud.poll() {
    ///         println!("Discovery event: {:?}", event);
    ///     }
    /// }
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn cloud_discovery_handle(&self) -> Option<CloudDiscoveryPollerHandle> {
        self.cloud_discovery_poller.as_ref().map(|p| p.handle())
    }

    // ========================================================================
    // SHM (Shared Memory) Transport methods
    // ========================================================================

    /// Get the configured SHM policy.
    ///
    /// Returns the policy that controls transport selection between SHM and UDP.
    pub fn shm_policy(&self) -> ShmPolicy {
        self.shm_policy
    }

    /// Check if SHM transport is enabled (not disabled).
    pub fn shm_enabled(&self) -> bool {
        self.shm_policy != ShmPolicy::Disable
    }

    /// Get the local host ID for SHM transport.
    ///
    /// This ID is used to determine if two endpoints are on the same host,
    /// which is required for SHM communication.
    pub fn shm_host_id(&self) -> u32 {
        crate::transport::shm::host_id()
    }

    /// Format SHM capability for user_data announcement.
    ///
    /// Returns a string like `"shm=1;host_id=12345678;v=1"` that should be
    /// included in SPDP/SEDP announcements to advertise SHM capability.
    pub fn shm_user_data(&self) -> String {
        crate::transport::shm::format_shm_user_data()
    }

    // ========================================================================
    // Feature Detection methods (compile-time checks, zero-cost)
    // ========================================================================

    /// Check if Type Lookup Service is enabled.
    ///
    /// Type Lookup is enabled at compile time via the `type-lookup` feature flag.
    /// When enabled, HDDS automatically requests TypeObjects from remote
    /// participants for unknown types discovered via SEDP.
    ///
    /// # Note
    ///
    /// Type Lookup is HDDS-only and not interoperable with other DDS vendors.
    /// It's automatically disabled when interop mode is detected.
    #[inline]
    pub fn type_lookup_enabled(&self) -> bool {
        cfg!(feature = "type-lookup")
    }

    /// Check if XTypes (Extended Type System) is enabled.
    ///
    /// XTypes provides runtime type discovery and compatibility checking.
    #[inline]
    pub fn xtypes_enabled(&self) -> bool {
        cfg!(feature = "xtypes")
    }

    /// Check if Cloud Discovery is enabled.
    ///
    /// Cloud Discovery provides AWS Cloud Map, Azure, and Consul backends
    /// for environments without UDP multicast.
    #[inline]
    pub fn cloud_discovery_enabled(&self) -> bool {
        cfg!(feature = "cloud-discovery")
    }

    /// Check if Kubernetes DNS discovery is enabled.
    #[inline]
    pub fn k8s_discovery_enabled(&self) -> bool {
        cfg!(feature = "k8s")
    }

    /// Check if DDS-RPC (Request/Reply) is enabled.
    #[inline]
    pub fn rpc_enabled(&self) -> bool {
        cfg!(feature = "rpc")
    }

    /// Get a summary of all enabled features (for diagnostics/logging).
    ///
    /// Returns a vector of feature names that are compiled in.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let participant = Participant::builder("app").build()?;
    /// println!("HDDS features: {:?}", participant.features_summary());
    /// // Output: ["xtypes", "security", "quic"]
    /// ```
    pub fn features_summary(&self) -> Vec<&'static str> {
        let mut features = Vec::new();
        if cfg!(feature = "xtypes") {
            features.push("xtypes");
        }
        if cfg!(feature = "type-lookup") {
            features.push("type-lookup");
        }
        if cfg!(feature = "security") {
            features.push("security");
        }
        if cfg!(feature = "quic") {
            features.push("quic");
        }
        if cfg!(feature = "cloud-discovery") {
            features.push("cloud-discovery");
        }
        if cfg!(feature = "k8s") {
            features.push("k8s");
        }
        if cfg!(feature = "rpc") {
            features.push("rpc");
        }
        features
    }
}

impl Drop for Participant {
    fn drop(&mut self) {
        // Stop lease tracker
        if let Some(tracker) = self.lease_tracker.take() {
            tracker.stop();
        }

        // Stop telemetry
        self.telemetry_shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.telemetry_handle.take() {
            let _ = handle.join();
        }
    }
}

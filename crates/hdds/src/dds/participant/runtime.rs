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
use crate::discovery::cloud::{
    CloudDiscoveryPoller, CloudDiscoveryPollerHandle, CloudDiscoveryStatus,
};
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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[cfg(feature = "xtypes")]
use crate::core::types::{Distro, TypeCache, TypeObjectHandle};
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

/// What the type of a new endpoint declares about its instance key, so that
/// [`Participant::check_create_endpoint`] can refuse a key-protected topic
/// whose type cannot name a protected dispose.
#[cfg(feature = "security")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EndpointKeyHooks {
    /// `DDS::has_key`: the type declares at least one key member.
    pub has_key: bool,
    /// `DDS::keys_round_trip`: the type writes a key-only payload and reads
    /// it back (`encode_key` and `key_hash_of_key_payload`).
    pub keys_round_trip: bool,
}

/// Which endpoint an access-control decision is about.
///
/// Carries the three spellings shared by the writer and the reader branch: the
/// audit action name, the human noun in the refusal message, and the overlay's
/// rule action.
#[cfg(feature = "security")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointKind {
    Writer,
    Reader,
}

#[cfg(feature = "security")]
impl EndpointKind {
    fn audit_action(self) -> &'static str {
        match self {
            Self::Writer => "create_writer",
            Self::Reader => "create_reader",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Writer => "writer",
            Self::Reader => "reader",
        }
    }

    fn rule_action(self) -> crate::security::permissions::dynamic::RuleAction {
        match self {
            Self::Writer => crate::security::permissions::dynamic::RuleAction::Publish,
            Self::Reader => crate::security::permissions::dynamic::RuleAction::Subscribe,
        }
    }
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
/// When the last `Arc` is dropped, the participant says its farewell
/// (SPDP dispose), then stops and joins every thread it started and closes
/// its sockets and shared memory before the drop returns, so the same
/// participant id can be taken again at once. Dropped from one of its own
/// threads (inside a listener callback), it hands that work to a thread of
/// its own and returns at once instead (see the `Drop` impl).
///
/// Readers and writers do not keep the participant alive, but they keep
/// what they share with it (its transport, hence its sockets) until they
/// are dropped too: drop them first.
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
    /// Process-local identity used by the intra delivery registry. Unlike
    /// `participant_id`, this remains unique in `IntraProcess` mode.
    pub(crate) participant_token: crate::dds::domain_registry::ParticipantToken,
    pub(super) guid: GUID,
    pub(super) port_mapping: Option<crate::transport::PortMapping>,
    pub(crate) transport: Option<Arc<UdpTransport>>,
    /// Manual HDDS-to-HDDS TCP endpoint.
    pub(crate) tcp_transport: Option<Arc<TcpTransport>>,
    /// Requested transport preference; not yet an outbound routing policy.
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
    /// Consul-specific options the builder was given (service prefix,
    /// datacenter, ACL token, health policy, KV mirror), kept so a
    /// backend built by hand through `create_consul_discovery` speaks to
    /// the same agent, with the same credential, as the poller does.
    #[cfg(feature = "cloud-discovery")]
    pub(crate) consul_options: Option<crate::discovery::cloud::ConsulOptions>,
    /// Shared Memory transport policy
    pub(crate) shm_policy: ShmPolicy,
    pub(crate) registry: Option<Arc<TopicRegistry>>,
    pub(super) router: Option<Arc<DemuxRouter>>,
    pub(crate) discovery_fsm: Option<Arc<DiscoveryFsm>>,
    #[allow(dead_code)] // retained even when dynamic resolution is disabled
    pub(super) type_lookup: super::builder::discovery_setup::TypeLookupHandle,
    #[cfg(feature = "xtypes")]
    pub(super) type_cache: Arc<TypeCache>,
    #[cfg(feature = "xtypes")]
    pub(super) distro: Distro,
    #[cfg(feature = "xtypes")]
    pub(super) registered_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    /// Types this participant can SERVE to a peer that asks, via either
    /// TypeLookup responder. Never consulted by the SEDP announcement path.
    /// See `Participant::register_served_type`.
    #[cfg(feature = "xtypes")]
    pub(super) served_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    #[cfg(feature = "xtypes")]
    pub(super) topic_types: Arc<RwLock<HashMap<String, Arc<TypeObjectHandle>>>>,
    /// The telemetry push thread (stopped and joined on drop).
    pub(super) telemetry: Option<super::builder::telemetry_setup::TelemetryThread>,
    /// SPDP announcer thread (kept alive for automatic cleanup on Drop)
    pub(super) _spdp_announcer: Option<crate::core::discovery::SpdpAnnouncer>,
    /// Automatic Discovery Server client lifecycle.
    pub(super) discovery_server_runtime:
        Option<super::builder::discovery_server_runtime::DiscoveryServerRuntime>,
    /// Lease tracker thread (removes expired participants)
    pub(super) lease_tracker: Option<crate::core::discovery::multicast::LeaseTracker>,
    /// The liveliness thread (`hdds-liveliness`): the leases of the remote
    /// writers its readers match, and this participant's own assertions.
    pub(crate) liveliness: Option<crate::dds::liveliness::Scheduler>,
    /// ControlHandler for Two-Ring HEARTBEAT/ACKNACK processing.
    /// Must be stored in Participant to prevent immediate Drop (which stops the thread).
    pub(super) _control_handler: Option<ControlHandler>,
    /// Multicast listeners must be stored to prevent immediate Drop.
    /// If dropped, listener threads exit (running flag set to false).
    pub(super) _listeners: Vec<crate::core::discovery::multicast::MulticastListener>,
    /// The Discovery Server relay's receive dispatch, kept to pin whose it is.
    #[cfg(test)]
    pub(crate) relay_ingress: Option<Arc<crate::core::discovery::multicast::PacketDispatch>>,
    /// DDS Security: handle for the BuiltinParticipantStatelessMessageWriter drain thread.
    /// Kept alive for the participant lifetime; dropping requests thread exit.
    #[cfg(feature = "security")]
    pub(super) _stateless_writer_handle:
        Option<crate::security::stateless_writer::inner::StatelessWriterHandle>,
    pub(super) graph_guard: Arc<GuardCondition>,
    /// The history of this participant's SEDP built-in writers: one change
    /// per local Reader/Writer announcement, and the retirement of each one
    /// deleted (`SedpHistory`). Replayed to newly discovered peers, read by
    /// the retransmission path.
    pub(super) sedp_announcements:
        Arc<std::sync::RwLock<crate::core::discovery::multicast::SedpHistory>>,
    /// Dialect detector for vendor auto-detection (Phase 1: monitoring passif)
    /// Observes SPDP packets to detect the peer's vendor, logs decision
    /// Phase 2 will add hot-reconfig based on detection
    #[allow(dead_code)] // Used via Arc::clone in discovery callback
    pub(super) dialect_detector:
        Arc<std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>>,
    /// Incremental key allocator for user entity IDs (ensures unique GUIDs per endpoint)
    pub(super) next_entity_key: AtomicU32,
    /// The EntityId of the Publisher a writer built without one belongs to
    /// (`implicit_publisher_entity_id`), allocated on first use.
    pub(super) implicit_publisher: std::sync::OnceLock<[u8; 4]>,
    /// Domain state for intra-process auto-binding
    pub(crate) domain_state: Arc<DomainState>,
    /// Match notification registry for on_publication/subscription_matched (DDS spec 2.2.2.4)
    pub(crate) match_registry:
        Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
    /// Participant-level shared-memory receive leg. Held only to keep the
    /// poller thread alive for the participant's lifetime: dropping it
    /// signals the thread to stop and joins it.
    #[cfg(target_os = "linux")]
    pub(crate) _shm_receiver: Option<Arc<crate::transport::shm::receiver::ShmReceiver>>,
    /// Shared per-writer reliable-reader proxy registry for USER DATA.
    /// Handed to each reader's subscriber so on_data advances the ACKNACK
    /// contiguous-prefix base; read by the ControlHandler to build ACKNACKs
    /// (RTPS v2.5 Sec.8.4.12.2). Cheap clone (`Arc<DashMap>` inside).
    pub(crate) user_data_registry: crate::core::reader::ReaderProxyRegistry,
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
    /// DNS-SD discovery thread (SRV + A/AAAA -> SPDP unicast destinations).
    ///
    /// When configured via `.with_dns_sd()`, resolves the service name in
    /// the background and feeds the `Cloud` origin of the SPDP peer set.
    /// Stopped explicitly in `Drop`, before the lease tracker.
    #[cfg(feature = "dns-sd")]
    pub(super) dns_sd_discovery: Option<crate::discovery::dnssd::DnsSdDiscovery>,
    /// QUIC I/O thread for sync access to async QUIC transport
    ///
    /// When configured via `.with_quic()`, this thread is spawned automatically
    /// and provides sync access via `quic_handle()`.
    #[cfg(feature = "quic")]
    pub(super) quic_io_thread: Option<QuicIoThread>,
    /// Cloud discovery poller thread for sync access to async discovery
    ///
    /// When configured via `.with_consul()` etc., this thread is spawned automatically,
    /// feeds the SPDP peer set and provides sync access via `cloud_discovery_handle()`.
    #[cfg(feature = "cloud-discovery")]
    pub(super) cloud_discovery_poller: Option<CloudDiscoveryPoller>,
    /// Unicast routing thread (TCP/QUIC -> TopicRegistry).
    /// Stored to prevent Drop until Participant drops.
    pub(super) _unicast_routing_thread:
        Option<super::builder::unicast_routing::UnicastRoutingThread>,
    /// Tests only: leave without the sealed departure, as a participant that
    /// crashes does (`leave_without_a_sealed_departure_for_test`).
    #[cfg(all(test, feature = "security"))]
    pub(super) leaves_without_a_sealed_departure: std::sync::atomic::AtomicBool,
}

impl Participant {
    pub fn domain_id(&self) -> u32 {
        self.domain_id
    }

    pub fn participant_id(&self) -> u8 {
        self.participant_id
    }

    pub(crate) fn participant_token(&self) -> crate::dds::domain_registry::ParticipantToken {
        self.participant_token
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

    /// Get the requested transport preference.
    ///
    /// This value does not currently control the DDS writer send path.
    pub fn transport_preference(&self) -> TransportPreference {
        self.transport_preference
    }

    pub fn guid(&self) -> GUID {
        self.guid
    }

    pub fn discovery(&self) -> Option<Arc<DiscoveryFsm>> {
        self.discovery_fsm.clone()
    }

    /// Manually assert this participant's liveliness (DDS v1.4
    /// Sec.2.2.3.11, Sec.2.2.2.2.4.19 `assert_liveliness`): renews the
    /// lease every MANUAL_BY_PARTICIPANT writer of this participant
    /// shares, and rate-limits a `ParticipantMessage` of kind MANUAL to
    /// peers (RTPS v2.5 Sec.8.4.13.5). A no-op on a participant with no
    /// liveliness thread (no transport: nothing to assert to) or no
    /// MANUAL_BY_PARTICIPANT writer yet -- the renewal is simply held for
    /// the first one that is built.
    pub fn assert_liveliness(&self) {
        if let Some(ref liveliness) = self.liveliness {
            let shared = liveliness.shared();
            let renewal = shared.local_manual_renewal();
            shared.renew(&renewal);
        }
    }

    /// Get security plugin suite (if security is enabled).
    ///
    /// Returns `Some(Arc<SecurityPluginSuite>)` if security was configured,
    /// `None` otherwise.
    #[cfg(feature = "security")]
    pub fn security(&self) -> Option<Arc<crate::security::SecurityPluginSuite>> {
        self.security.clone()
    }

    /// Name, for the audit chain, exactly what the decision was made on: the
    /// topic, and the partitions the endpoint names when it names any other
    /// than the default one.
    ///
    /// The signed permissions document is evaluated on every partition the
    /// endpoint names (DDS-Security v1.1 Sec.9.4.1.3.2.3.1.4), and so is
    /// the local restriction overlay, so the record names them all. An
    /// audit record that overstates its inputs is worse than one that omits
    /// them; this one states them.
    #[cfg(feature = "security")]
    fn audit_resource(topic: &str, partitions: &[String]) -> String {
        if partitions.iter().all(String::is_empty) {
            topic.to_string()
        } else {
            format!("{} (partitions {:?})", topic, partitions)
        }
    }

    /// Check if access control allows creating a writer for the given topic
    /// with `qos` (its PARTITION and its DataTagQosPolicy).
    ///
    /// Returns `Ok(())` if allowed, `Err(PermissionsDenied)` if denied.
    #[cfg(feature = "security")]
    pub(crate) fn check_create_writer(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        keys: EndpointKeyHooks,
    ) -> Result<()> {
        self.check_create_endpoint(EndpointKind::Writer, topic, qos, keys)
    }

    /// Check if access control allows creating a reader for the given topic
    /// with `qos`.
    ///
    /// Returns `Ok(())` if allowed, `Err(PermissionsDenied)` if denied.
    #[cfg(feature = "security")]
    pub(crate) fn check_create_reader(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        keys: EndpointKeyHooks,
    ) -> Result<()> {
        self.check_create_endpoint(EndpointKind::Reader, topic, qos, keys)
    }

    /// The ONE door every endpoint creation goes through, whichever public
    /// entry point was called: the builders, the deprecated
    /// `create_writer` / `create_reader` wrappers, and the `xtypes`
    /// `create_*_with_type` pair all end at the same builder.
    ///
    /// Two policies are consulted, in this order and never the other way
    /// round:
    ///
    /// 1. the signed permissions document, which is the only thing that
    ///    GRANTS anything (DDS-Security v1.1 section 9.4.1.3);
    /// 2. the local restriction overlay, which can only take away what was
    ///    granted, and needs no signature to do so.
    ///
    /// Both verdicts are taken BEFORE anything is written to the audit chain,
    /// so one decision produces exactly one record. Recording the allow and
    /// then the refusal would put two AccessControl lines in the chain for a
    /// single endpoint, which is the defect `create_writer` was cured of.
    ///
    /// The signed document is judged on every partition the endpoint names
    /// and its data tags (DDS-Security v1.1 Sec.8.4.2.9.4, 9.4.1.3.2.3), the
    /// overlay on every partition (a refusal in one refuses the endpoint),
    /// and the audit record names them all (`audit_resource`). Reading
    /// the first non-empty name only would let an endpoint in ["A", "B"]
    /// escape a rule refusing "B".
    #[cfg(feature = "security")]
    fn check_create_endpoint(
        &self,
        kind: EndpointKind,
        topic: &str,
        qos: &crate::dds::QoS,
        keys: EndpointKeyHooks,
    ) -> Result<()> {
        let Some(ref security) = self.security else {
            return Ok(());
        };
        // A key-protected topic whose type cannot round-trip a key-only
        // payload loses every dispose and unregister: K=1 carries the key
        // and only that payload can name the instance under encryption
        // (the cleartext PID_KEY_HASH is not authenticated), so the reader
        // would drop each one in silence. Refused at creation rather than
        // lost at run time. This is a property of the type and its
        // governance, not an access decision, so it is neither gated on
        // `evaluates_endpoint_access` nor written to the audit chain.
        if keys.has_key
            && !keys.keys_round_trip
            && crate::security::crypto::user_data::endpoint_security_info(security, topic)
                .is_ok_and(|attributes| attributes.is_key_protected())
        {
            return Err(Error::Config(format!(
                "topic '{}' is key-protected (data_protection_kind ENCRYPT) and its type \
                 declares a key but implements no key-payload round trip \
                 (DDS::keys_round_trip is false: both DDS::encode_key and \
                 DDS::key_hash_of_key_payload are required): every dispose and unregister \
                 of this topic would be dropped by the reader",
                topic
            )));
        }
        if !security.evaluates_endpoint_access() {
            // Neither the signed documents nor an overlay is configured:
            // nothing decides, so nothing is recorded.
            return Ok(());
        }

        let resource = Self::audit_resource(topic, &qos.partition.names);

        let mut verdict: std::result::Result<(), String> = Ok(());

        if let Some(access_control) = security.access_control() {
            // DDS-Security v1.1 9.4.1.2.7: an entity whose topic no topic
            // rule of the governance matches is refused - the specification
            // has no default protection for it, and announcing it would need
            // one. And a topic whose payload the governance protects
            // (9.4.1.2.6.7, `is_payload_protected`) is refused to a
            // participant built without the encryption that protects it: its
            // samples would otherwise go out, or be expected, in clear while
            // the governance says they are encrypted.
            let signed = access_control
                .endpoint_attributes(topic)
                .and_then(|attributes| {
                    if attributes.is_payload_protected && security.cryptographic().is_none() {
                        Err(crate::security::SecurityError::ConfigError(format!(
                            "governance <data_protection_kind> protects the payload of topic \
                             '{}', and this participant was built without encryption \
                             (SecurityConfig::enable_encryption): its samples would cross in \
                             clear",
                            topic
                        )))
                    } else {
                        Ok(())
                    }
                })
                .and_then(|_| match kind {
                    EndpointKind::Writer => access_control.check_create_datawriter(
                        topic,
                        &qos.partition.names,
                        &qos.data_tags.tags,
                    ),
                    EndpointKind::Reader => access_control.check_create_datareader(
                        topic,
                        &qos.partition.names,
                        &qos.data_tags.tags,
                    ),
                });
            if let Err(e) = signed {
                verdict = Err(format!("Access control denied: {}", e));
            }
        }

        if verdict.is_ok() {
            let local =
                security.check_local_restriction(kind.rule_action(), topic, &qos.partition.names);
            if let Err(e) = local {
                verdict = Err(format!("Local permission overlay denied: {}", e));
            }
        }

        match verdict {
            Ok(()) => {
                self.log_access_control_event(kind.audit_action(), &resource, true)?;
                Ok(())
            }
            Err(reason) => {
                // Denied either way; the record is attempted so the refusal is
                // in the chain, its own failure only degrades the chain.
                let _ = self.log_access_control_event(kind.audit_action(), &resource, false);
                Err(Error::PermissionDenied(format!(
                    "{}: cannot create {} for topic '{}'",
                    reason,
                    kind.noun(),
                    topic
                )))
            }
        }
    }

    // There is deliberately no participant-level `encrypt_payload` or
    // `decrypt_payload`: a method named "encrypt" that falls back to cleartext
    // when the plugin is absent would be a fail-open waiting to be wired up
    // once a key store exists. The wire path is `DataWriter::write` ->
    // `encrypt_payload_for_network`, which refuses.

    /// Check if encryption is enabled for this participant.
    #[cfg(feature = "security")]
    pub fn is_encryption_enabled(&self) -> bool {
        self.security
            .as_ref()
            .is_some_and(|s| s.is_encryption_enabled())
    }

    /// Record an access control decision (create writer/reader allowed/denied)
    /// in the suite's audit chain.
    ///
    /// This is the path every `writer().build()` / `reader().build()` takes;
    /// it must reach the audit file, not only the log. Fail closed:
    /// a record that cannot be written degrades the chain and the endpoint
    /// is refused, because a decision the audit trail did not capture is a
    /// decision the operator cannot account for.
    #[cfg(feature = "security")]
    pub(crate) fn log_access_control_event(
        &self,
        action: &str,
        resource: &str,
        allowed: bool,
    ) -> Result<()> {
        let Some(ref security) = self.security else {
            return Ok(());
        };
        if !security.is_audit_log_enabled() {
            return Ok(());
        }
        // Fail closed, same rule as the handshake machine and the key store:
        // once a record has been lost, no NEW trust is established, and an
        // endpoint is new trust.
        if security.is_audit_degraded() {
            return Err(Error::Config(format!(
                "audit chain degraded (a record was lost): refusing {} on '{}' until this \
                 participant is rebuilt",
                action, resource
            )));
        }

        let outcome = if allowed {
            crate::security::audit::AccessOutcome::Allowed
        } else {
            crate::security::audit::AccessOutcome::Denied
        };
        let event = crate::security::audit::SecurityEvent::AccessControl {
            participant_guid: self.guid.as_bytes(),
            action: action.to_string(),
            resource: resource.to_string(),
            outcome,
            timestamp: crate::security::audit::timestamp_ns(),
        };
        security.log_security_event(&event).map_err(|e| {
            Error::Config(format!(
                "audit chain degraded while recording {} on '{}': refusing the endpoint ({})",
                action, resource, e
            ))
        })
    }

    // Authentication records are emitted by `security::handshake`, on the
    // terminal transitions, through the suite's audit chain (stamped in
    // nanoseconds), not by a participant-level logging helper.

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

    #[deprecated(
        since = "1.0.10",
        note = "Use participant.topic::<T>(name).writer().build() instead"
    )]
    pub fn create_writer<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
    ) -> Result<DataWriter<T>> {
        // Access control and its audit record are owned by ONE place, the
        // builder path below (`Participant::check_create_writer`): this wrapper used
        // to check and record here as well, so a single decision produced two
        // AccessControl lines with two different `resource` spellings.

        let mut builder = self.topic(topic)?.writer().qos(qos.clone());

        if let Some(ref registry) = self.registry {
            builder = builder.with_registry(registry.clone());
        }

        if let Some(ref transport) = self.transport {
            builder = builder.with_transport(transport.clone());
        }

        // Pass endpoint_registry to writer for unicast DATA sends
        // Pass discovery_fsm for partition-aware data routing
        if let Some(ref discovery_fsm) = self.discovery_fsm {
            builder = builder.with_endpoint_registry(discovery_fsm.endpoint_registry());
            builder = builder.with_replay_registry(discovery_fsm.replay_registry());
            builder = builder.with_discovery_fsm(discovery_fsm.clone());
        }

        // Pass domain state for intra-process auto-binding
        builder = builder.with_domain_state(self.domain_state.clone());

        builder.build()
    }

    #[deprecated(
        since = "1.0.10",
        note = "Use participant.topic::<T>(name).reader().build() instead"
    )]
    pub fn create_reader<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
    ) -> Result<DataReader<T>> {
        // Access control and its audit record are owned by ONE place, the
        // builder path below (`Participant::check_create_reader`): this wrapper used
        // to check and record here as well, so a single decision produced two
        // AccessControl lines with two different `resource` spellings.

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
        // Access control and its audit record are owned by ONE place, the
        // builder path below (`Participant::check_create_reader`). This entry
        // point must not evaluate the signed document a second time, inline and
        // without writing to the audit chain: a refusal taken here would never
        // appear in the record the operator reads.

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
        // Same as `create_reader_with_type`: the builder path below
        // (`Participant::check_create_writer`) owns the decision and its audit
        // record; an inline copy would leave no trace in the chain.

        self.create_writer_with_type_and_extensibility(topic, qos, type_name, type_object, None)
    }

    /// [`create_writer_with_type`](Self::create_writer_with_type), and the
    /// extensibility of the type whose bodies `T` writes.
    ///
    /// The encapsulation identifier of every sample names the extensibility
    /// of its type (DDS-XTypes v1.3 Sec.7.6.3.1.2, Table 60): under XCDR2,
    /// `CDR2_LE` (0x0007) for a FINAL type, `D_CDR2_LE` (0x0009) for an
    /// APPENDABLE one (its body starts with a DHEADER), `PL_CDR2_LE`
    /// (0x000b) for a MUTABLE one; under XCDR1, `CDR_LE` (0x0001) for FINAL
    /// and APPENDABLE, `PL_CDR_LE` (0x0003) for MUTABLE. A writer reads it
    /// from `type_object` when there is one; `extensibility` is for a writer
    /// that has none and is handed bodies it did not encode (the C ABI
    /// writer, whose bytes come from `hdds_gen` encoders), which would
    /// otherwise label every body FINAL. `Some` overrides the TypeObject;
    /// `None` keeps the derivation.
    ///
    /// # Errors
    /// As [`create_writer_with_type`](Self::create_writer_with_type).
    #[cfg(feature = "xtypes")]
    pub fn create_writer_with_type_and_extensibility<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
        type_name: &str,
        type_object: Option<CompleteTypeObject>,
        extensibility: Option<crate::dynamic::Extensibility>,
    ) -> Result<DataWriter<T>> {
        self.create_writer_with_metadata(
            topic,
            qos,
            Some(type_name),
            type_object,
            extensibility,
            false,
        )
    }

    /// Create an opaque serialized writer whose codec supplies instance keys.
    /// The adapter must implement `DDS::instance_key`, `DDS::protected_key`
    /// and `DDS::encode_key` consistently for every keyed operation.
    pub fn create_serialized_key_writer<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
        type_name: &str,
        extensibility: crate::dynamic::Extensibility,
    ) -> Result<DataWriter<T>> {
        self.create_writer_with_metadata(
            topic,
            qos,
            Some(type_name),
            None,
            Some(extensibility),
            true,
        )
    }

    /// Create a writer for bodies of a type the caller does not name (the C
    /// ABI writer fed by `hdds_gen` encoders, called without a type name).
    ///
    /// With no type of its own it announces the type registered for the
    /// topic, else the name its topic's readers already announce (XTypes 1.3
    /// Sec.7.6.3.4.2 Step 2), else the placeholder `RawBytes`
    /// ([`WriterBuilder::adopting_type_name`](crate::dds::WriterBuilder::adopting_type_name)).
    /// `extensibility` is that of the bodies; `serialized_keys` makes it a
    /// keyed serialized writer. A writer created for a type must use
    /// [`Self::create_writer_with_type_and_extensibility`] with its name.
    ///
    /// # Errors
    /// As [`create_writer_with_type`](Self::create_writer_with_type).
    pub fn create_adopting_writer<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
        extensibility: Option<crate::dynamic::Extensibility>,
        serialized_keys: bool,
    ) -> Result<DataWriter<T>> {
        self.create_writer_with_metadata(topic, qos, None, None, extensibility, serialized_keys)
    }

    #[allow(clippy::too_many_arguments)]
    fn create_writer_with_metadata<T: crate::dds::DDS>(
        self: &Arc<Self>,
        topic: &str,
        qos: crate::dds::QoS,
        type_name: Option<&str>,
        type_object: Option<CompleteTypeObject>,
        extensibility: Option<crate::dynamic::Extensibility>,
        serialized_keys: bool,
    ) -> Result<DataWriter<T>> {
        let builder = self.topic(topic)?.writer().qos(qos.clone());
        let mut builder = match type_name {
            Some(type_name) => builder.with_type_name_override(type_name),
            None => builder.adopting_type_name(),
        };

        builder = builder.with_serialized_keys(serialized_keys);

        if let Some(type_object) = type_object {
            builder = builder.with_type_object_override(type_object);
        }

        if let Some(extensibility) = extensibility {
            builder = builder.with_encapsulation_kind_override(match extensibility {
                crate::dynamic::Extensibility::Final => 0x0007,
                crate::dynamic::Extensibility::Appendable => 0x0009,
                crate::dynamic::Extensibility::Mutable => 0x000B,
            });
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
    /// - bytes 0..2: 24-bit entity key (big-endian / network order)
    /// - byte 3: entity kind (writer=0x02/0x03, reader=0x04/0x07)
    pub(crate) fn next_user_entity_id(&self, entity_kind: u8) -> [u8; 4] {
        let key = (self.next_entity_key.fetch_add(1, Ordering::Relaxed) + 1) & 0x00FF_FFFF;
        let key_bytes = key.to_be_bytes(); // Network byte order per RTPS spec
        [key_bytes[1], key_bytes[2], key_bytes[3], entity_kind]
    }

    /// The EntityId of the Publisher every writer built without an explicit
    /// one belongs to: allocated once per participant from the same key space
    /// as every user entity (RTPS v2.5 Sec.9.3.1.2, kind 0x08
    /// USER_DEFINED_WRITER_GROUP), so it never names another Publisher.
    pub(crate) fn implicit_publisher_entity_id(&self) -> [u8; 4] {
        *self
            .implicit_publisher
            .get_or_init(|| self.next_user_entity_id(crate::dds::publisher::ENTITY_KIND_PUBLISHER))
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
    /// [`ParticipantBuilder::with_quic`](crate::dds::ParticipantBuilder::with_quic).
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
    /// Returns a sync handle to the QUIC transport that was automatically
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

    /// Create an additional raw Discovery Server client.
    ///
    /// A participant configured with a Discovery Server already owns and drives
    /// its client automatically. Connecting the returned client concurrently
    /// uses the same GUID and will normally be rejected as a duplicate. This
    /// method remains available for low-level diagnostics and API compatibility.
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
    /// assert!(participant.discovery_server_configured());
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

    /// Create a Consul discovery backend you drive yourself.
    ///
    /// It carries the options the builder was given (service prefix,
    /// datacenter, ACL token, KV mirror) and this participant's own
    /// domain, but its health policy is forced to
    /// [`ConsulHealthPolicy::Disabled`](crate::discovery::cloud::ConsulHealthPolicy::Disabled):
    /// NOTHING refreshes a check on a backend the caller owns. Left on,
    /// the service registered here would go critical one TTL after
    /// registration and Consul would then drop it -- a registration that
    /// deletes itself while the participant is perfectly alive. A caller
    /// who does run a refresh loop opts back in explicitly:
    ///
    /// ```ignore
    /// let consul = participant
    ///     .create_consul_discovery()?
    ///     .with_health(ConsulHealthPolicy::Ttl)
    ///     .with_heartbeat_interval(Duration::from_secs(5));
    /// // ... and then call consul.heartbeat(guid) every 5 s.
    /// ```
    ///
    /// The participant's OWN registration does not go through here: the
    /// builder's `with_consul` / `with_consul_options` start the poller,
    /// which registers, refreshes and deregisters on its own.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::{Participant, TransportMode};
    ///
    /// let participant = Participant::builder("microservice")
    ///     .with_consul("https://consul.service.consul:8500")
    ///     .build()?;
    ///
    /// let consul = participant.create_consul_discovery()?;
    /// consul.register_participant(&info).await?;
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn create_consul_discovery(
        &self,
    ) -> std::result::Result<crate::discovery::cloud::ConsulDiscovery, crate::dds::Error> {
        let addr = self.cloud_discovery_config.as_ref().ok_or_else(|| {
            crate::dds::Error::Config("cloud_discovery_config is not set".to_string())
        })?;

        if self.cloud_discovery_provider.as_deref() != Some("consul") {
            return Err(crate::dds::Error::Config(format!(
                "cloud_discovery_provider is {:?}, expected \"consul\"",
                self.cloud_discovery_provider.as_deref()
            )));
        }

        // The options the builder was given, not the defaults: without
        // them this backend goes out with no ACL token (403 on an
        // ACL-enabled agent) and queries the default service name, which
        // answers an empty list -- not an error -- for a fleet registered
        // under another prefix.
        let options = self
            .consul_options
            .clone()
            .unwrap_or_default()
            // Nothing drives `heartbeat()` on a backend the caller owns,
            // so no TTL check is registered here: see the doc above.
            .with_health(crate::discovery::cloud::ConsulHealthPolicy::Disabled);

        // The participant's own domain, not domain 0: a backend built
        // without it queries the `domain-0` tag and finds nobody.
        crate::discovery::cloud::ConsulDiscovery::new(addr)
            .map(|consul| consul.with_options(options).with_domain_id(self.domain_id))
    }

    /// Create a STANDALONE AWS Cloud Map discovery backend.
    ///
    /// This is a helper for code that wants to talk to Cloud Map itself;
    /// the participant's own registration and peer feed are handled by the
    /// poller started at `build()`, not by this object.
    ///
    /// It is rebuilt from the PUBLIC configuration string, which never
    /// carries credential material, so the backend it returns always uses
    /// the default credential chain even when the participant was built
    /// with `with_aws_cloud_map_config` and an explicit credential source.
    #[cfg(feature = "cloud-discovery")]
    pub fn create_aws_cloud_map(
        &self,
    ) -> std::result::Result<crate::discovery::cloud::AwsCloudMap, crate::dds::Error> {
        let config = self.cloud_discovery_config.as_ref().ok_or_else(|| {
            crate::dds::Error::Config("cloud_discovery_config is not set".to_string())
        })?;

        if self.cloud_discovery_provider.as_deref() != Some("aws") {
            return Err(crate::dds::Error::Config(format!(
                "cloud_discovery_provider is {:?}, expected \"aws\"",
                self.cloud_discovery_provider.as_deref()
            )));
        }

        crate::discovery::cloud::AwsCloudMap::with_config(
            crate::discovery::cloud::AwsCloudMapConfig::from_json(config)?,
        )
    }

    /// Create an Azure discovery backend.
    #[cfg(feature = "cloud-discovery")]
    pub fn create_azure_discovery(
        &self,
    ) -> std::result::Result<crate::discovery::cloud::AzureDiscovery, crate::dds::Error> {
        let config = self.cloud_discovery_config.as_ref().ok_or_else(|| {
            crate::dds::Error::Config("cloud_discovery_config is not set".to_string())
        })?;

        if self.cloud_discovery_provider.as_deref() != Some("azure") {
            return Err(crate::dds::Error::Config(format!(
                "cloud_discovery_provider is {:?}, expected \"azure\"",
                self.cloud_discovery_provider.as_deref()
            )));
        }

        // The config string is an AzureDiscoveryConfig, not a DNS zone:
        // it is parsed here exactly as the poller parses it, so a direct
        // user of this constructor gets the participant's own backend.
        let parsed = crate::discovery::cloud::AzureDiscoveryConfig::from_json(config)?;
        crate::discovery::cloud::AzureDiscovery::from_config(parsed)
            .map(|azure| azure.with_domain_id(self.domain_id))
    }

    /// Get the cloud discovery poller handle (sync).
    ///
    /// Returns a sync handle to the cloud discovery poller that was
    /// automatically started when cloud discovery was configured.
    /// No tokio runtime required.
    ///
    /// The handle receives a COPY of every poller event: the participant's
    /// own SPDP feed consumes the events on the poller thread, so polling
    /// this handle (or never polling it) cannot affect discovery. The copy
    /// is bounded; overflow is counted in
    /// [`CloudDiscoveryStatus::dropped_events`].
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
    ///     // Observe discovered participants
    ///     for event in cloud.poll() {
    ///         println!("Discovery event: {:?}", event);
    ///     }
    /// }
    /// ```
    #[cfg(feature = "cloud-discovery")]
    pub fn cloud_discovery_handle(&self) -> Option<CloudDiscoveryPollerHandle> {
        self.cloud_discovery_poller.as_ref().map(|p| p.handle())
    }

    /// Current state of DNS-SD resolution: answered lookups, consecutive
    /// failures, peers the last answered lookup produced, last error.
    /// `None` when no DNS-SD discovery is configured.
    #[cfg(feature = "dns-sd")]
    pub fn dns_sd_status(&self) -> Option<crate::discovery::dnssd::DnsSdStatus> {
        self.dns_sd_discovery.as_ref().map(|d| d.status())
    }

    /// Current state of the cloud registry poller: registration outcome,
    /// consecutive poll failures, peers seen in the last successful poll.
    /// `None` when no cloud discovery is configured.
    #[cfg(feature = "cloud-discovery")]
    pub fn cloud_discovery_status(&self) -> Option<CloudDiscoveryStatus> {
        self.cloud_discovery_poller
            .as_ref()
            .map(|p| p.handle().status())
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
        if cfg!(feature = "dns-sd") {
            features.push("dns-sd");
        }
        if cfg!(feature = "rpc") {
            features.push("rpc");
        }
        features
    }
}

impl Participant {
    /// Tests only: when dropped, leave without the sealed departure that
    /// tells authenticated peers this participant is gone, as one that
    /// crashes does. Its peers then hold it for its whole lease.
    #[cfg(all(test, feature = "security"))]
    pub(crate) fn leave_without_a_sealed_departure_for_test(&self) {
        self.leaves_without_a_sealed_departure
            .store(true, Ordering::Relaxed);
    }
}

impl Drop for Participant {
    /// Synchronous: when the drop returns, every thread the participant
    /// started has been stopped and joined, and its sockets and shared
    /// memory are closed (DDS 1.4 2.2.2.2.2.2 `delete_participant`; RTPS 2.5
    /// 9.6.1.1 unicast ports are its alone, so the next participant may take
    /// the same participant id at once).
    ///
    /// Except on one of its own threads, typically from inside one of its
    /// listener callbacks: a thread cannot wait for its own end, and the
    /// callback may hold locks the teardown takes. There the teardown runs
    /// on a thread of its own and the drop returns at once; the resources
    /// are released once the callback has returned.
    ///
    /// What an entity that outlives its participant (a reader, a writer, a
    /// handle from `transport()` or `router()`) shares with it, it keeps until
    /// it drops too: delete the contained entities first.
    fn drop(&mut self) {
        let teardown = self.take_teardown();
        if crate::core::rt::shutdown::current_owner() != Some(self.participant_token.raw()) {
            teardown.run();
            return;
        }
        log::debug!(
            "[participant] dropped on one of its own threads: teardown handed to a thread of its own"
        );
        let spawned = std::thread::Builder::new()
            .name("hdds-teardown".to_string())
            .spawn(move || teardown.run());
        if let Err(e) = spawned {
            // The teardown is dropped unrun: each part still stops and joins
            // its thread on drop (never the calling one), without the farewell.
            log::error!("[participant] teardown thread not started ({e}); parts dropped in place");
        }
    }
}

impl Participant {
    /// Everything the teardown stops, taken out of the participant so that
    /// it can run on another thread (`Drop`).
    fn take_teardown(&mut self) -> Teardown {
        #[cfg(all(test, feature = "security"))]
        let says_goodbye = !self
            .leaves_without_a_sealed_departure
            .load(Ordering::Relaxed);
        #[cfg(all(not(test), feature = "security"))]
        let says_goodbye = true;
        Teardown {
            guid: self.guid,
            discovery_fsm: self.discovery_fsm.take(),
            sedp_announcements: Arc::clone(&self.sedp_announcements),
            spdp_announcer: self._spdp_announcer.take(),
            #[cfg(feature = "security")]
            says_goodbye,
            transport: self.transport.take(),
            tcp_transport: self.tcp_transport.take(),
            discovery_server_runtime: self.discovery_server_runtime.take(),
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_poller: self.cloud_discovery_poller.take(),
            #[cfg(feature = "dns-sd")]
            dns_sd_discovery: self.dns_sd_discovery.take(),
            lease_tracker: self.lease_tracker.take(),
            liveliness: self.liveliness.take(),
            type_lookup: self.type_lookup.take(),
            telemetry: self.telemetry.take(),
            registry: self.registry.take(),
            router: self.router.take(),
            control_handler: self._control_handler.take(),
            listeners: std::mem::take(&mut self._listeners),
            #[cfg(test)]
            relay_ingress: self.relay_ingress.take(),
            #[cfg(feature = "security")]
            stateless_writer_handle: self._stateless_writer_handle.take(),
            match_registry: self.match_registry.take(),
            #[cfg(target_os = "linux")]
            shm_receiver: self._shm_receiver.take(),
            #[cfg(feature = "security")]
            security: self.security.take(),
            #[cfg(feature = "k8s")]
            k8s_discovery_handle: self.k8s_discovery_handle.take(),
            #[cfg(feature = "quic")]
            quic_io_thread: self.quic_io_thread.take(),
            unicast_routing_thread: self._unicast_routing_thread.take(),
        }
    }
}

/// The parts of a participant its drop stops, in the order it stops them
/// (`run`).
struct Teardown {
    guid: GUID,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    sedp_announcements: Arc<std::sync::RwLock<crate::core::discovery::multicast::SedpHistory>>,
    spdp_announcer: Option<crate::core::discovery::SpdpAnnouncer>,
    #[cfg(feature = "security")]
    says_goodbye: bool,
    transport: Option<Arc<UdpTransport>>,
    tcp_transport: Option<Arc<TcpTransport>>,
    discovery_server_runtime:
        Option<super::builder::discovery_server_runtime::DiscoveryServerRuntime>,
    #[cfg(feature = "cloud-discovery")]
    cloud_discovery_poller: Option<CloudDiscoveryPoller>,
    #[cfg(feature = "dns-sd")]
    dns_sd_discovery: Option<crate::discovery::dnssd::DnsSdDiscovery>,
    lease_tracker: Option<crate::core::discovery::multicast::LeaseTracker>,
    liveliness: Option<crate::dds::liveliness::Scheduler>,
    type_lookup: super::builder::discovery_setup::TypeLookupHandle,
    telemetry: Option<super::builder::telemetry_setup::TelemetryThread>,
    registry: Option<Arc<TopicRegistry>>,
    router: Option<Arc<DemuxRouter>>,
    control_handler: Option<ControlHandler>,
    listeners: Vec<crate::core::discovery::multicast::MulticastListener>,
    #[cfg(test)]
    relay_ingress: Option<Arc<crate::core::discovery::multicast::PacketDispatch>>,
    #[cfg(feature = "security")]
    stateless_writer_handle:
        Option<crate::security::stateless_writer::inner::StatelessWriterHandle>,
    match_registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
    #[cfg(target_os = "linux")]
    shm_receiver: Option<Arc<crate::transport::shm::receiver::ShmReceiver>>,
    #[cfg(feature = "security")]
    security: Option<Arc<crate::security::SecurityPluginSuite>>,
    #[cfg(feature = "k8s")]
    k8s_discovery_handle: Option<K8sDiscoveryHandle>,
    #[cfg(feature = "quic")]
    quic_io_thread: Option<QuicIoThread>,
    unicast_routing_thread: Option<super::builder::unicast_routing::UnicastRoutingThread>,
}

impl Teardown {
    fn run(mut self) {
        // Nothing announces us after the farewell. The receive side (the
        // listeners, the Discovery Server relay's ingress) lives until the
        // end of this teardown; an SPDP it hands the handler in the meantime
        // would be answered with an immediate SPDP reply and SEDP
        // re-announcements, and the receiver would take us back for a lease.
        // `depart` waits for any SPDP handler in flight; from then on they
        // answer nobody. The relay is not stopped instead: the farewell goes
        // out through it to relayed peers.
        if let Some(ref fsm) = self.discovery_fsm {
            fsm.depart();
        }

        // No liveliness assertion follows the farewell, and no lease of a
        // remote writer is judged any more: the thread is stopped and
        // joined (bounded).
        drop(self.liveliness.take());

        // The SPDP dispose below retires every endpoint of this participant at
        // once: close the SEDP history first, so that an endpoint dropped from
        // from here on (one that outlives its participant) sends no SEDP dispose
        // after the farewell, and neither does a per-peer retry round nor a
        // retransmission (a closed history has nothing to send). Taken under
        // the history's lock, which an endpoint's retirement, a retry round
        // and a retransmission hold across their own sends, so one already
        // under way is on the wire before the farewell (`SedpRetirement`).
        // The discovery worker stops at `depart` above.
        let retry_rounds = {
            let mut history = self
                .sedp_announcements
                .write()
                .unwrap_or_else(|e| e.into_inner());
            history.close();
            history.retry_rounds()
        };
        // The per-peer SEDP retry threads end on the close (woken at once,
        // nothing more to send) and are joined here, with no lock of the
        // history held: none outlives its participant, and none re-enters
        // the dedup maps after `forget_local_participant` below.
        retry_rounds.join_all();

        // Dispose through the authoritative SPDP path before leaving the
        // rendezvous registry.
        if let Some(announcer) = self.spdp_announcer.take() {
            announcer.shutdown();
        }
        // An authenticated peer ignores the plain dispose (DDS Security v1.1
        // Sec.7.4.1.6) and would hold us for our whole lease: tell each
        // authenticated HDDS peer sealed, before the keys are drained below.
        #[cfg(feature = "security")]
        if let (true, Some(fsm), Some(transport)) = (
            self.says_goodbye,
            self.discovery_fsm.as_ref(),
            self.transport.as_ref(),
        ) {
            let departing = GUID::new(
                self.guid.prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            );
            for (sealed, endpoints) in fsm.sealed_departures(departing) {
                for endpoint in &endpoints {
                    if let Err(err) = transport.send_to_endpoint(&sealed, endpoint) {
                        log::debug!("[SPDP] sealed departure to {} failed: {}", endpoint, err);
                    }
                }
            }
        }
        if let Some(mut runtime) = self.discovery_server_runtime.take() {
            runtime.stop();
        }
        // Then leave the cloud registry (deregister, bounded), still after
        // the SPDP dispose so cloud peers received it.
        #[cfg(feature = "cloud-discovery")]
        if let Some(mut poller) = self.cloud_discovery_poller.take() {
            poller.stop();
        }
        // Same order for the DNS peer source: stop resolving only after the
        // SPDP dispose has gone out to the peers DNS gave us.
        #[cfg(feature = "dns-sd")]
        if let Some(mut discovery) = self.dns_sd_discovery.take() {
            discovery.stop();
        }

        // Stop lease tracker
        if let Some(tracker) = self.lease_tracker.take() {
            tracker.stop();
        }

        // The TypeLookup tick sends on our transport: stopped and joined
        // here, it does not outlive us.
        #[cfg(feature = "xtypes-structural-assignability")]
        if let Some(service) = self.type_lookup.as_ref() {
            service.stop_tick();
        }

        // Stop telemetry
        if let Some(mut telemetry) = self.telemetry.take() {
            telemetry.stop();
        }

        // DDS Security v1.1: drain all per-peer handshake state so that ECDH
        // key material is cleared from memory when the participant shuts down.
        #[cfg(feature = "security")]
        if let Some(ref suite) = self.security {
            suite.handshakes.drain();
        }

        // The threads that remain, in the order of the participant's fields:
        // each part stops and joins its thread(s) as it drops (bounded, never
        // the calling thread). The router first, then the receive side, then
        // the rest.
        drop(self.router.take());
        drop(self.control_handler.take());
        drop(std::mem::take(&mut self.listeners));
        #[cfg(test)]
        drop(self.relay_ingress.take());
        #[cfg(feature = "security")]
        drop(self.stateless_writer_handle.take());
        drop(self.match_registry.take());
        #[cfg(target_os = "linux")]
        drop(self.shm_receiver.take());
        #[cfg(feature = "security")]
        drop(self.security.take());
        #[cfg(feature = "k8s")]
        drop(self.k8s_discovery_handle.take());
        #[cfg(feature = "quic")]
        drop(self.quic_io_thread.take());
        drop(self.unicast_routing_thread.take());
        drop(self.tcp_transport.take());
        drop(self.registry.take());
        drop(self.type_lookup.take());
        drop(self.discovery_fsm.take());
        drop(self.transport.take());

        // Last, once every thread above has been stopped: drop this
        // participant's entries from the process-global SEDP dedup maps. Our
        // participant id and its RTPS ports are free again, so the next
        // participant built in this process can be handed exactly the same
        // ones, and would otherwise inherit our "already announced" state and
        // never retry SEDP. Ordering matters: a retry guard still in flight
        // re-inserts its key when it drops, so this has to run after the
        // shutdowns, not before them.
        super::builder::forget_local_participant(self.guid.prefix);
    }
}

#[cfg(test)]
mod departure_tests {
    use super::Participant;
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::SpdpData;
    use crate::test_support::domains::unique_domain;
    use crate::TransportMode;

    /// An SPDP announcement of the participant `prefix`, as the wire carries it.
    fn announcement(prefix: [u8; 12], domain_id: u32) -> Vec<u8> {
        crate::core::discovery::multicast::build_spdp_rtps_packet(
            &SpdpData {
                participant_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id,
                metatraffic_unicast_locators: vec!["192.0.2.7:7410".parse().expect("addr")],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: None,
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            },
            1,
            None,
        )
        .expect("an announcement")
    }

    /// A participant's drop joins its SEDP retry threads: they are woken by
    /// the close of its history and none outlives it.
    #[test]
    fn a_dropped_participant_joins_its_sedp_retry_threads() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let domain = unique_domain();
        let participant = Participant::builder("joins_its_sedp_retries")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant");
        let rounds = participant
            .sedp_announcements
            .read()
            .expect("history")
            .retry_rounds();
        let ended = Arc::new(AtomicBool::new(false));
        let (in_thread, flag) = (Arc::clone(&rounds), Arc::clone(&ended));
        // A retry thread between two rounds.
        rounds.track(std::thread::spawn(move || {
            let _ = in_thread.wait_while_running(std::time::Duration::from_secs(10));
            // A round still finishing after the wake, longer than the rest
            // of the drop takes (about a second): only a join waits for it.
            std::thread::sleep(std::time::Duration::from_millis(3000));
            flag.store(true, Ordering::SeqCst);
        }));
        drop(participant);
        assert!(
            rounds.is_stopped(),
            "the drop did not stop the retry rounds"
        );
        assert!(
            ended.load(Ordering::SeqCst),
            "the participant returned from its drop with a retry thread still running"
        );
    }

    /// A participant whose farewell has gone answers no SPDP: its receive
    /// legs outlive the body of its drop (the relay's ingress here, which a
    /// Discovery Server keeps delivering into until it is stopped), and an
    /// announcement they hand the handler after the farewell would be
    /// answered, so the receiver would take the participant back for a lease.
    #[test]
    fn a_participant_whose_farewell_has_gone_answers_no_spdp() {
        let domain = unique_domain();
        let participant = Participant::builder("farewell_answers_nobody")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant");
        let fsm = participant
            .discovery_fsm
            .clone()
            .expect("a UDP participant has a discovery FSM");
        let ingress = participant
            .relay_ingress
            .clone()
            .expect("a UDP participant builds the relay's receive leg");
        let from = "198.51.100.9:7410".parse().expect("addr");

        let before = [0x0B; 12];
        ingress.dispatch(&announcement(before, domain.id()), from);
        assert!(
            fsm.is_participant_known(&before),
            "fixture: an announcement through this leg is handled while we live"
        );

        drop(participant);

        let after = [0x0A; 12];
        ingress.dispatch(&announcement(after, domain.id()), from);
        assert!(
            !fsm.is_participant_known(&after),
            "after the farewell, the announcement is not answered"
        );
    }
}

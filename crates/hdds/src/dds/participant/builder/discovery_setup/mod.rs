// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery subsystem setup and listener spawning.
//!
//! This module handles:
//! - Discovery FSM initialization
//! - Discovery callback closure (dispatches to handler modules)
//! - Multicast listener spawning
//! - Unicast listener spawning
//! - User data listener spawning
//! - DemuxRouter setup and rx_ring consumer thread
//!
//! # Architecture
//! The routing decision itself lives in `dispatch`, as a value rather than a
//! closure, so a test can drive it without standing up a participant.
//! The handlers it routes to are composable modules:
//! - `spdp_handler`: SPDP parsing, dialect ACKNACKs, SEDP re-announcements
//! - `sedp_handler`: SEDP parsing, endpoint discovery, TopicRegistry updates
//! - `fragment_handler`: DATA_FRAG reassembly and recursive parsing

mod dispatch;
mod fragment_handler;
mod heartbeat_handler;
#[cfg(test)]
mod install_tests;
mod secure_builtins;
mod sedp_handler;
mod spdp_handler;
mod type_lookup_handler;
#[cfg(all(test, feature = "security"))]
mod volatile_tests;
#[cfg(test)]
mod wire_fixtures;

use dispatch::DiscoveryDispatch;
pub(in crate::dds::participant) use spdp_handler::forget_local_participant;

pub(super) use type_lookup_handler::TypeLookupConfig;
pub(in crate::dds::participant) use type_lookup_handler::TypeLookupHandle;
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
use type_lookup_handler::TypeLookupService;

use super::entity_registry::SedpAnnouncementsCache;
use super::sockets::{create_data_multicast_socket, create_unicast_socket};
use crate::config::{
    FRAGMENT_BUFFER_MAX_BYTES, FRAGMENT_BUFFER_SIZE, FRAGMENT_TIMEOUT_MS, MAX_PACKET_SIZE,
    RX_POOL_SIZE, RX_RING_SIZE,
};
use crate::core::discovery::{
    multicast::{
        ControlHandler, DiscoveryCallback, DiscoveryFsm, ListenerMetrics, PacketDispatch, RxMeta,
        RxPool,
    },
    DiscoveredParticipants, FragmentBuffer, KnownSources, GUID,
};
use crate::core::reader::ReaderProxyRegistry;
use crate::engine::{Router as DemuxRouter, TopicRegistry, WakeNotifier};
use crate::transport::UdpTransport;
use crossbeam::queue::ArrayQueue;
use parking_lot::Mutex;
use std::sync::Arc;

#[cfg(feature = "security")]
use crate::security::{SecurityPluginSuite, SecurityValidatorAdapter};

/// Prebuilt DDS Security payloads attached to this participant's SPDP samples,
/// and the SN counter of its SPDP writer.
///
/// The discovery callback owns this value so multiple participants in one
/// process cannot overwrite each other's advertised identity. The counter is
/// the one its periodic announcer numbers with too
/// (`spdp_announcer::spdp_sequence`): an immediate reply numbered from a
/// process-wide count could go back below the participant's announcements.
#[derive(Clone)]
pub(super) struct SpdpSecurityTokens {
    identity_token: Option<Vec<u8>>,
    permissions_token: Option<Vec<u8>>,
    participant_security_info: Option<[u8; 8]>,
    sequence: Arc<std::sync::atomic::AtomicU64>,
}

impl Default for SpdpSecurityTokens {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

impl SpdpSecurityTokens {
    pub(super) fn new(
        identity_token: Option<Vec<u8>>,
        permissions_token: Option<Vec<u8>>,
        participant_security_info: Option<[u8; 8]>,
    ) -> Self {
        Self {
            identity_token,
            permissions_token,
            participant_security_info,
            sequence: crate::core::discovery::spdp_announcer::spdp_sequence(),
        }
    }

    /// The participant's SPDP writer SN counter, for its announcer.
    pub(super) fn sequence(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.sequence)
    }
}

/// Feature flag for Two-Ring architecture
/// When enabled, HEARTBEATs are processed in a dedicated ControlHandler thread
/// instead of synchronously in the listener callback. This prevents pool exhaustion
/// under high HEARTBEAT load (RELIABLE QoS).
const ENABLE_TWO_RING_CONTROL: bool = true;

/// Discovery components after initialization.
pub(super) struct DiscoveryComponents {
    pub discovery_fsm: Option<Arc<DiscoveryFsm>>,
    /// The match notification registry, installed on the FSM before any
    /// discovery thread starts. `None` without discovery.
    pub match_registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
    pub type_lookup: TypeLookupHandle,
    pub registry: Option<Arc<TopicRegistry>>,
    pub router: Option<Arc<DemuxRouter>>,
    /// ControlHandler must be stored to prevent immediate Drop.
    /// If dropped, the control thread exits (running flag set to false).
    pub control_handler: Option<ControlHandler>,
    /// Listeners must be stored to prevent immediate Drop.
    /// If dropped, listener threads exit (running flag set to false).
    pub listeners: Vec<crate::core::discovery::multicast::MulticastListener>,
    /// Where a datagram relayed by a Discovery Server is handed in.
    ///
    /// `None` when this participant has no receive plumbing at all
    /// (intra-process), which is also the only mode that has no Discovery
    /// Server session to call it.
    pub relay_ingress: Option<Arc<PacketDispatch>>,
    /// Shared per-writer reliable-reader proxy registry for USER DATA. The
    /// ControlHandler reads it (HEARTBEAT -> ACKNACK base/bitmap); reader
    /// subscribers write it (on_data advances the contiguous prefix). Stored
    /// here so the participant can hand a clone to each reader's subscriber.
    /// RTPS v2.5 Sec.8.4.12.2 -- without the subscriber writing reception state,
    /// the ACKNACK base stays frozen and strict reliable writers never release
    /// late-joiner history.
    pub user_data_registry: ReaderProxyRegistry,
    /// Participant-level shared-memory receive leg (one poller thread).
    ///
    /// Built here because this is where the receive plumbing it needs lives:
    /// it pushes onto the SAME `rx_ring` the multicast listeners feed, using
    /// the SAME `RxPool` and wake notifier, so the Router consumes a
    /// shared-memory packet without knowing it came from one. `None` when
    /// the platform has no shared memory. Must be stored on the participant:
    /// dropping it stops and joins the poller thread.
    #[cfg(target_os = "linux")]
    pub shm_receiver: Option<Arc<crate::transport::shm::receiver::ShmReceiver>>,
    /// DDS Security: handle for the BuiltinParticipantStatelessMessageWriter thread.
    /// Must be stored to keep the writer alive for the participant lifetime.
    /// Dropping this signals the thread to exit on the next drain cycle.
    #[cfg(feature = "security")]
    pub stateless_writer_handle:
        Option<crate::security::stateless_writer::inner::StatelessWriterHandle>,
    /// The participants every reassembly buffer of this participant ranks
    /// (`fragment_buffer::KnownSources`): those discovery knows, those
    /// authenticated above them. `None` without discovery.
    pub known_sources: Option<Arc<dyn KnownSources>>,
}

/// Setup discovery FSM, listeners, and demux router.
///
/// # Arguments
/// - `guid`: Participant GUID
/// - `transport`: UDP transport
/// - `sedp_cache`: SEDP announcements cache
/// - `domain_id`: DDS domain, used to name this participant's shared-memory
///   segments so a co-located peer can reconstruct them from discovery alone
/// - `mapping`: Port mapping for multicast/unicast ports
/// - `dialect_detector`: Dialect detector for SPDP packet monitoring (Phase 1.6)
/// - `transport_options`: Resolved transport options (TTL/DSCP/interface allowlist)
///   applied to the listener sockets created here
/// - `security_suite`: Optional security plugin suite for participant authentication (DDS Security v1.1)
///
/// # Returns
/// DiscoveryComponents with FSM, registry, and router
#[allow(unused_variables)] // security_suite unused when feature disabled
#[allow(clippy::too_many_arguments)] // orchestration entry point: one param per subsystem
pub(super) fn setup_discovery(
    guid: GUID,
    transport: Arc<UdpTransport>,
    sedp_cache: SedpAnnouncementsCache,
    domain_id: u32,
    mapping: crate::transport::PortMapping,
    dialect_detector: Arc<
        std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>,
    >,
    type_lookup_config: TypeLookupConfig,
    transport_options: &crate::transport::options::ResolvedTransportOptions,
    socket_buffer_options: &crate::transport::socket_buffer::ResolvedSocketBufferOptions,
    participant_lease_duration_ms: u64,
    spdp_security_tokens: SpdpSecurityTokens,
    discovered_peers: Option<Arc<crate::core::discovery::SpdpPeerSet>>,
    // The user-data unicast socket the participant-id auto-assignment already
    // bound, or `None` to bind `mapping.user_unicast` here.
    reserved_user_unicast: Option<socket2::Socket>,
    // The participant's liveliness: every received message renews its
    // sender's writers, a ParticipantMessage its manual ones.
    liveliness: Arc<crate::dds::liveliness::Shared>,
    #[cfg(feature = "security")] security_suite: Option<Arc<SecurityPluginSuite>>,
) -> std::io::Result<DiscoveryComponents> {
    log::debug!("[hdds] Setting up discovery subsystem");

    let registry = Arc::new(TopicRegistry::new());
    let rx_ring = Arc::new(ArrayQueue::<(RxMeta, u8)>::new(RX_RING_SIZE));
    let rx_pool = Arc::new(
        RxPool::new(RX_POOL_SIZE, MAX_PACKET_SIZE)
            .map_err(|_| std::io::Error::other("Failed to create RxPool"))?,
    );

    #[allow(unused_mut)] // mut needed when security feature is enabled
    let mut discovery_fsm = DiscoveryFsm::new(guid, participant_lease_duration_ms);

    // Extract GUID prefix early so it can be reused by both the security block
    // and the stateless writer spawn. The later `our_guid_prefix` variable
    // (defined at callback-build time) carries the same value; the early binding
    // avoids a lifetime issue when the security block needs it before that
    // binding is in scope. Unused when `security` feature is disabled.
    #[cfg(feature = "security")]
    let guid_prefix_early: [u8; 12] = {
        let bytes = guid.as_bytes();
        let mut p = [0u8; 12];
        p.copy_from_slice(&bytes[..12]);
        p
    };

    // Option populated inside the security block below; cloned into the
    // discovery callback for PacketKind::Stateless dispatch (gap #3 C3-sec).
    #[cfg(feature = "security")]
    #[allow(unused_mut)]
    let mut secure_builtins_opt: Option<secure_builtins::SecureBuiltins> = None;

    // Handle for the BuiltinParticipantStatelessMessageWriter thread.
    // Populated below after `discovery_fsm` and `endpoint_registry` are available.
    #[cfg(feature = "security")]
    let mut stateless_writer_handle: Option<
        crate::security::stateless_writer::inner::StatelessWriterHandle,
    > = None;

    // DDS Security v1.1: Connect AuthenticationPlugin to DiscoveryFsm
    // When security is enabled, participants with invalid identity_tokens are rejected.
    #[cfg(feature = "security")]
    if let Some(ref suite) = security_suite {
        let validator = Arc::new(SecurityValidatorAdapter::new(suite.clone()));
        let require_auth = suite.config().require_authentication;
        discovery_fsm.set_security_validator(validator, require_auth);
        log::info!(
            "[hdds] Security: AuthenticationPlugin connected to DiscoveryFsm (require_auth={})",
            require_auth
        );

        // DDS Security v1.1 sec. 7.4.1.3 -- bootstrap the 12 secure builtin
        // endpoints (gap #2). The returned `SecureBuiltins` carries the 6
        // tunnel GUID pairs plus the empty StatelessChannel that gap #3
        // (handshake driver) will consume. Failure here is fatal: the
        // participant must not start without its secure-builtin surface.
        let secure_builtins = secure_builtins::setup_secure_builtins(guid_prefix_early, suite)
            .map_err(|err| {
                std::io::Error::other(format!("setup_secure_builtins failed: {:?}", err))
            })?;
        log::info!(
            "[hdds] Security: 12 secure builtin endpoints registered ({} tunnels)",
            secure_builtins.tunnels.len()
        );
        // Gap #3 (C3-sec): promote the handle into the Option so the
        // discovery callback can route PacketKind::Stateless payloads.
        secure_builtins_opt = Some(secure_builtins);

        // C2/C3 (gap #3 wire-up): register the PKI-DH handshake machine on
        // the DiscoveryFsm so `handle_spdp` can initiate toward each newly
        // admitted remote participant and `notify_endpoint_discovered` can
        // gate on `is_authenticated`.
        //
        // Load cert + key bytes. A failure here is FATAL.
        //
        // Degrading to an empty Vec with a warning is not an option: the
        // inbound handshake leg is live, so empty material produces an
        // AuthRequest carrying a zero-length certificate, which the peer
        // rejects -- a participant
        // that looks configured, announces security in SPDP, and can never
        // authenticate. SecurityConfigBuilder::build() already proved these
        // three files exist, so reaching this branch means a race, a
        // permission error or a truncated file: all reasons to refuse to start.
        let local_cert_der =
            std::fs::read(suite.config().identity_certificate.as_path()).map_err(|err| {
                std::io::Error::other(format!(
                    "cannot read identity_certificate {}: {}",
                    suite.config().identity_certificate.display(),
                    err
                ))
            })?;
        let local_key_pem = std::fs::read(suite.config().private_key.as_path()).map_err(|err| {
            std::io::Error::other(format!(
                "cannot read private_key {}: {}",
                suite.config().private_key.display(),
                err
            ))
        })?;
        if local_cert_der.is_empty() || local_key_pem.is_empty() {
            return Err(std::io::Error::other(
                "identity_certificate or private_key is empty -- refusing to start a participant \
                 that would announce security it cannot perform",
            ));
        }
        discovery_fsm.set_handshake_machine(
            suite.handshakes.clone(),
            local_cert_der,
            local_key_pem,
        );
        // What the governance document says about discovery: the protection
        // of the secure discovery writers and, per topic, whether an endpoint
        // is announced on them (DDS Security v1.1 9.4.1.2.5.4, 9.4.1.2.6.2).
        discovery_fsm.set_discovery_governance(
            suite
                .access_control()
                .and_then(crate::security::access::AccessControlPlugin::discovery_governance),
        );
        // The key material of our secure builtin writers, announced to every
        // authenticated participant as DatawriterCryptoTokens (DDS Security
        // v1.1 Sec.8.8.8.3, Sec.8.8.9.2), after the governance that names its
        // transformation.
        discovery_fsm
            .register_builtin_writer_keys(Arc::clone(&suite.data_keys))
            .map_err(|err| {
                std::io::Error::other(format!(
                    "cannot create the key material of the secure builtin writers: {}",
                    err
                ))
            })?;
        // The key material of our secure builtin READERS, announced to every
        // authenticated participant as DatareaderCryptoTokens (DDS Security
        // v1.1 Sec.8.8.9.3): the mirror image of the writer keys just above,
        // in the SAME store (`register_builtin_reader_keys`'s own docs).
        discovery_fsm
            .register_builtin_reader_keys(Arc::clone(&suite.data_keys))
            .map_err(|err| {
                std::io::Error::other(format!(
                    "cannot create the key material of the secure builtin readers: {}",
                    err
                ))
            })?;
        log::info!("[hdds] Security: PKI-DH handshake machine registered on DiscoveryFsm");

        // The access-control half of the same wiring (DDS Security v1.1
        // 9.4.3). `remote_access_control` returns `None` when this participant
        // was built without governance and permissions, and the gate is then
        // never installed: a participant with no access control configured
        // must be completely unaffected by it.
        discovery_fsm.set_volatile_suite(suite);
        let remote_access = suite.remote_access_control(domain_id);
        let remote_access_configured = remote_access.is_some();
        discovery_fsm.set_remote_access_control(remote_access);
        if remote_access_configured {
            log::info!(
                "[hdds] Security: remote access control registered on DiscoveryFsm for domain {}",
                domain_id
            );
        }

        // Our own local restriction overlay (DDS Security v1.1 9.4.1.3's
        // signed documents remain the only thing that GRANTS anything; this
        // can only narrow). Only registered when one is actually configured:
        // `admission_gate_active` reads `local_restriction.is_some()` to
        // decide whether the gate runs at all, and a participant with a
        // suite but no overlay (no governance, no handshake either) must
        // stay exactly as ungated as before this existed. Registering the
        // whole `Arc<SecurityPluginSuite>` rather than copying anything out
        // of it means a reload after bootstrap -- the overlay's whole
        // purpose -- is seen through `local_restriction_generation()`
        // without re-registering.
        if suite.permissions_overlay.is_some() {
            discovery_fsm.set_local_restriction(Some(Arc::clone(suite)));
        }

        // Wire the outbound stateless_channel so handle_spdp can enqueue
        // HandshakeAction::SendRequest tokens onto the writer entity 0x000201C3.
        if let Some(ref sbu) = secure_builtins_opt {
            discovery_fsm.set_stateless_channel(sbu.stateless_channel.clone());
            log::info!(
                "[hdds] Security: stateless_channel wired to DiscoveryFsm for initiator path"
            );
        }
    }

    let discovery_fsm = Arc::new(discovery_fsm);
    // Endpoints a peer announced before its handshake completed are refused
    // until then; they are offered again when it completes.
    #[cfg(feature = "security")]
    discovery_fsm.arm_surfacing_on_authentication();
    // The handshake answers an AuthRequest only from a participant discovery
    // has seen, and frees the failed session of one it no longer knows.
    #[cfg(feature = "security")]
    if let Some(ref sbu) = secure_builtins_opt {
        let fsm = Arc::downgrade(&discovery_fsm);
        sbu.handshake_machine
            .set_participant_known(Box::new(move |prefix| {
                fsm.upgrade()
                    .is_some_and(|fsm| fsm.knows_participant_prefix(prefix))
            }));
    }
    // A remote participant that leaves takes its writers with it.
    discovery_fsm.register_listener(Arc::new(sedp_handler::WriterDepartures::new(&registry)));
    // A remote participant removed from discovery leaves no record behind
    // that would keep us from announcing ourselves to it if it comes back.
    discovery_fsm.register_listener(Arc::new(spdp_handler::ForgottenPeerRecords::new(
        guid.prefix,
    )));

    // The match notification registry, and the receive legs that feed the
    // topic registry, are installed before any thread that consults them is
    // spawned: the ControlHandler, the listeners and the router are spawned
    // below, the shared-memory poller right here. An announcement handled
    // before the registry exists is judged by no one, and a peer does not
    // repeat an announcement it saw accepted.
    let wake_notifier = Arc::new(WakeNotifier::new());
    log::debug!("[hdds] WakeNotifier created for low-latency routing");
    // A remote writer's departure reaches the readers behind its data still
    // queued, in the receive ring and in its shared-memory ring
    // (`engine::departures`).
    let departure_route = Arc::new(crate::engine::departures::DepartureRoute::new(
        Arc::clone(&rx_ring),
        Some(Arc::clone(&wake_notifier)),
    ));
    registry.set_departure_route(Arc::clone(&departure_route));
    // Shared-memory receive leg. Shares the participant's rx_ring, RxPool
    // and wake notifier with every UDP listener below, so a sample that
    // crossed over shared memory reaches the Router through exactly the
    // same door as one that arrived on a socket -- dedup, reassembly,
    // ownership filters and listener dispatch all run unchanged.
    #[cfg(target_os = "linux")]
    let shm_receiver = Some(Arc::new(crate::transport::shm::receiver::ShmReceiver::new(
        domain_id,
        guid,
        Arc::clone(&rx_ring),
        Arc::clone(&rx_pool),
        Some(Arc::clone(&wake_notifier)),
    )));
    #[cfg(target_os = "linux")]
    if let Some(receiver) = shm_receiver.as_ref() {
        receiver.route_departures(Arc::clone(&departure_route));
    }
    let match_registry = Arc::new(
        crate::dds::match_notification::MatchNotificationRegistry::new(&discovery_fsm, guid.prefix),
    );
    discovery_fsm.register_listener(match_registry.clone());
    // Wired back into the FSM for inconsistent-type notifications
    // (DDS-XTypes v1.3 section 7.6.3.4.3). The FSM calls
    // notify_inconsistent_type_for_topic when a remote endpoint's type fails
    // is_assignable_to against local endpoints on the same topic.
    install_match_registry(&discovery_fsm, &registry, match_registry.clone());
    // The registry is where a pairing is resolved exactly once, so it is
    // also where "this remote writer's ring must be drained" is decided.
    #[cfg(target_os = "linux")]
    if let Some(receiver) = shm_receiver.as_ref() {
        match_registry.set_shm_receiver(Arc::clone(receiver));
    }

    // DDS Security (gap #3): spawn the BuiltinParticipantStatelessMessageWriter
    // (entity 0x000201C3). Must happen after `discovery_fsm` is wrapped in Arc
    // so that `endpoint_registry()` is available for remote address lookup.
    #[cfg(feature = "security")]
    {
        if let Some(ref sbu) = secure_builtins_opt {
            // The local endpoints and their matches, which the CryptoTokens
            // of USER endpoints are addressed by and checked against
            // (DDS Security v1.1 Sec.7.4.4.6.2-3).
            sbu.suite
                .volatile
                .set_local_endpoints(Box::new(Arc::downgrade(&discovery_fsm)));
            let endpoint_reg = discovery_fsm.endpoint_registry();
            let handle =
                sbu.spawn_stateless_writer(guid_prefix_early, transport.clone(), endpoint_reg);
            stateless_writer_handle = Some(handle);
            log::info!("[hdds] Security: BuiltinParticipantStatelessMessageWriter spawned");
        }
    }

    // Who every reassembly buffer of this participant ranks: the
    // participants discovery knows are told apart from forged prefixes
    // (those share a pool of their own, `fragment_buffer::
    // UNKNOWN_POOL_DIVISOR`), and with DDS Security the authenticated ones
    // rank above those an SPDP alone made known, when the governance
    // protects whole RTPS messages: only then is the header prefix a
    // buffer ranks by authenticated (`DiscoveredParticipants::
    // with_handshakes`).
    let known_participants =
        DiscoveredParticipants::new(guid.prefix, discovery_fsm.endpoint_registry());
    #[cfg(feature = "security")]
    let known_participants = match security_suite.as_ref() {
        Some(suite) => {
            let rtps_protected = suite
                .access_control
                .as_ref()
                .and_then(|access| access.participant_attributes().ok())
                .is_some_and(|attributes| attributes.is_rtps_protected);
            known_participants.with_handshakes(suite.handshakes.clone(), rtps_protected)
        }
        None => known_participants,
    };
    let known_sources: Arc<dyn KnownSources> = Arc::new(known_participants);

    // Fragment buffer for discovery reassembly.
    let fragment_buffer = Arc::new(Mutex::new(
        FragmentBuffer::new(FRAGMENT_BUFFER_SIZE, FRAGMENT_TIMEOUT_MS)
            .with_max_bytes(FRAGMENT_BUFFER_MAX_BYTES)
            .with_known_sources(Arc::clone(&known_sources)),
    ));

    let our_guid_prefix = {
        let bytes = guid.as_bytes();
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&bytes[..12]);
        prefix
    };

    let type_lookup: TypeLookupHandle = {
        #[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
        {
            let service = Arc::new(TypeLookupService::new(
                discovery_fsm.clone(),
                transport.clone(),
                our_guid_prefix,
                type_lookup_config,
            ));
            // Retries, the bound on held roots, HEARTBEATs and departures
            // must not wait for a datagram that may never come.
            #[cfg(feature = "xtypes-structural-assignability")]
            service.start_tick();
            Some(service)
        }
        #[cfg(not(any(feature = "type-lookup", feature = "xtypes-structural-assignability")))]
        {
            let _ = type_lookup_config;
            None
        }
    };

    // Create SEDP Reader proxy registry BEFORE callback and ControlHandler.
    // This registry must be shared between:
    // - Discovery callback: calls on_data() when SEDP DATA is received
    // - ControlHandler: calls on_heartbeat() to decide ACKNACK response
    //
    // The registry is created here, cloned for the callback, then passed to ControlHandler.
    let sedp_reader_registry = ReaderProxyRegistry::new();

    // User-data reliable-reader proxy registry. Shared (Arc<DashMap> inside)
    // between the ControlHandler and the reader subscribers so the ACKNACK
    // bitmapBase advances with actual DATA reception (RTPS v2.5 Sec.8.4.12.2).
    let user_data_registry = ReaderProxyRegistry::new();

    // Where a received discovery datagram goes. One value rather than the
    // a long list of captured variables standing for few distinct things,
    // and - the reason for it - something a test can build and drive without
    // standing up a participant. See `dispatch.rs`.
    let dispatch = Arc::new(DiscoveryDispatch {
        our_guid_prefix,
        transport: transport.clone(),
        fsm: discovery_fsm.clone(),
        registry: registry.clone(),
        sedp_cache: sedp_cache.clone(),
        sedp_reader_registry: sedp_reader_registry.clone(),
        dialect_detector: dialect_detector.clone(),
        port_mapping: mapping,
        spdp_security_tokens,
        discovered_peers,
        fragment_buffer,
        type_lookup: type_lookup.clone(),
        liveliness: Some(Arc::clone(&liveliness)),
        // Gap #3 (C3-sec): SecureBuiltins for Stateless/SecureSEDP/volatile dispatch.
        #[cfg(feature = "security")]
        secure_builtins: secure_builtins_opt.clone(),
        // Set once `control_tx` exists below (`DiscoveryDispatch::set_control_tx`):
        // the channel is built AFTER this dispatch.
        #[cfg(feature = "security")]
        control_tx: Mutex::new(None),
    });

    #[cfg(feature = "security")]
    dispatch.arm_secure_sedp();
    // A second handle, outliving the closure below's move of `dispatch`:
    // `set_control_tx` runs once the channel exists, after this point.
    #[cfg(feature = "security")]
    let dispatch_for_control_tx = dispatch.clone();

    let discovery_callback: DiscoveryCallback =
        Arc::new(move |packet_kind, payload, cdr_offset, frag_meta, origin| {
            dispatch.dispatch(packet_kind, payload, cdr_offset, frag_meta, origin);
        });

    // Two-Ring Architecture for RELIABLE QoS
    // IMPORTANT: Create ControlHandler AFTER registry but BEFORE listeners so all listeners can use control_tx
    // This prevents pool exhaustion under high HEARTBEAT/ACKNACK load.
    //
    // ControlHandler uses the shared sedp_reader_registry created above.
    // Both the discovery callback and ControlHandler use the same registry.
    //
    // ControlHandler also receives the TopicRegistry, for dispatching user data
    // ACKNACKs to WriterNackHandler (without it a RELIABLE publisher would not
    // retransmit despite receiving ACKNACKs).
    //
    // ControlHandler must be stored, not only its sender: dropping it would run
    // its Drop and kill the thread.
    let (control_tx, control_handler) = if ENABLE_TWO_RING_CONTROL {
        log::debug!("[hdds] Two-Ring Architecture enabled - spawning ControlHandler");
        #[cfg(test)]
        order_probe::record("control");

        let handler = ControlHandler::spawn_with_type_lookup_writers(
            transport.clone(),
            our_guid_prefix,
            mapping.metatraffic_unicast, // fallback port (overridden by FSM lookup)
            sedp_reader_registry.clone(),
            user_data_registry.clone(), // shared with reader subscribers (ACKNACK base)
            registry.clone(),           // TopicRegistry for user data NACK dispatch
            discovery_fsm.clone(),      // for peer metatraffic port resolution
            sedp_cache.clone(),         // for SEDP DATA retransmission on NACK
            type_lookup_writers(&type_lookup), // ACKNACKs to the TypeLookup writers
        );

        log::debug!("[hdds] ControlHandler spawned with SEDP registry + TopicRegistry");

        let sender = handler.sender();
        #[cfg(feature = "security")]
        dispatch_for_control_tx.set_control_tx(sender.clone());
        (Some(sender), Some(handler))
    } else {
        (None, None)
    };

    // All listeners share the WakeNotifier, created above, to wake the
    // router immediately when data arrives.

    // Collect all listeners to store in DiscoveryComponents (prevent Drop)
    // Capacity 4, for the data multicast listener
    let mut listeners = Vec::with_capacity(4);

    // Unified SPDP/SEDP listener (port 7400)
    // Single socket joined to both 239.255.0.1 (SPDP) and 239.255.0.2 (SEDP)
    // This avoids port conflicts and ensures we receive all metatraffic
    // Uses Two-Ring to bypass HEARTBEAT/ACKNACK pool allocation
    // Uses WakeNotifier for low-latency router wake
    if transport.multicast_receive_enabled() {
        #[cfg(test)]
        order_probe::record("multicast");
        let metatraffic_listener =
            crate::core::discovery::multicast::MulticastListener::spawn_for_participant(
                transport.socket(),
                rx_pool.clone(),
                rx_ring.clone(),
                Some(discovery_callback.clone()),
                control_tx.clone(),          // All listeners use Two-Ring
                Some(wake_notifier.clone()), // WakeNotifier for low-latency
                Some(our_guid_prefix),       // INFO_DST: what is destined here
                Some(Arc::clone(&liveliness)),
            )?;
        listeners.push(metatraffic_listener);
    } else {
        log::debug!("[hdds] Multicast metatraffic listener disabled");
    }

    // Phase 1.6: UNICAST listener (port 7410 for domain 0)
    // Remote peers send SEDP and user data to this unicast address
    // IMPORTANT: Uses same rx_ring as multicast so data goes to DemuxRouter!
    //
    // The transport's metatraffic_unicast_socket is bound to primary_ip:7410.
    // If we create a SECOND listener socket on 0.0.0.0:7410, the kernel delivers
    // incoming packets to the MORE SPECIFIC socket (primary_ip:7410), so the
    // wildcard listener never receives anything.
    //
    // Solution: Use the transport's socket for BOTH sending AND receiving.
    // The listener thread calls recv_from while main thread calls send_to.
    // UDP sockets support concurrent send/recv from different threads.
    log::debug!(
        "[hdds] Reusing transport metatraffic_unicast_socket for SEDP reception (port {})",
        mapping.metatraffic_unicast
    );
    let unicast_socket = transport.metatraffic_unicast_socket();

    // Uses Two-Ring to bypass HEARTBEAT/ACKNACK pool allocation
    // Uses WakeNotifier for low-latency router wake
    #[cfg(test)]
    order_probe::record("unicast");
    let unicast_listener =
        crate::core::discovery::multicast::MulticastListener::spawn_for_participant(
            unicast_socket,  // Use transport's socket directly for both send AND recv
            rx_pool.clone(), // Reuse same pool
            rx_ring.clone(), // Reuse same ring -> goes to DemuxRouter!
            Some(discovery_callback.clone()),
            control_tx.clone(),          // All listeners use Two-Ring
            Some(wake_notifier.clone()), // WakeNotifier for low-latency
            Some(our_guid_prefix),       // INFO_DST: what is destined here
            Some(Arc::clone(&liveliness)),
        )?;
    listeners.push(unicast_listener);

    log::debug!("[hdds] [OK] Unicast listener ready - RTI/HDDS can now send us SEDP/data!");

    // USER DATA listener (port 7411 for domain 0)
    // Remote writers send user data to this port per RTPS v2.5
    // CRITICAL for interop: must listen where SEDP announced
    log::debug!(
        "[hdds] Creating user data listener on port {} for RTI interop",
        mapping.user_unicast
    );
    let user_socket = create_unicast_socket(
        mapping.user_unicast,
        transport_options,
        socket_buffer_options,
        reserved_user_unicast,
    )?;

    // Pass discovery callback AND control channel to user data listener
    // With Two-Ring: HEARTBEATs/ACKNACKs bypass pool, DATA goes to ring
    // Without Two-Ring: Legacy synchronous callback handles HEARTBEATs
    // WakeNotifier for low-latency router wake
    #[cfg(test)]
    order_probe::record("user-data");
    let user_data_listener =
        crate::core::discovery::multicast::MulticastListener::spawn_for_participant(
            Arc::new(user_socket),
            rx_pool.clone(),                  // Reuse same pool
            rx_ring.clone(),                  // Reuse same ring -> goes to DemuxRouter!
            Some(discovery_callback.clone()), // For SPDP/SEDP on this port (rare but possible)
            control_tx.clone(),               // Control channel for HEARTBEATs/ACKNACKs
            Some(wake_notifier.clone()),      // WakeNotifier for low-latency
            Some(our_guid_prefix),            // INFO_DST: what is destined here
            Some(Arc::clone(&liveliness)),
        )?;
    listeners.push(user_data_listener);

    log::debug!(
        "[hdds] [OK] User data listener ready on port {}{}!",
        mapping.user_unicast,
        if ENABLE_TWO_RING_CONTROL {
            " (Two-Ring enabled on ALL listeners)"
        } else {
            ""
        }
    );

    // Kept before the last listener takes `control_tx` by move - and takes
    // it only when multicast reception is on, which would leave the relay
    // holding a moved-from value on exactly the deployments it serves.
    let relay_control_tx = control_tx.clone();

    // DATA MULTICAST listener (port 7401 for domain 0)
    // Peers may send user data to the default user-data multicast locator
    // 239.255.0.1:7401 (DDSI-RTPS 2.5 9.6.2.2: port PB + DG*domainId + d2),
    // e.g. before unicast readers are discovered. Without this listener, HDDS
    // cannot receive such user data until both sides have exchanged SEDP
    // endpoint info.
    if transport.multicast_receive_enabled() {
        let data_multicast_port =
            mapping.metatraffic_multicast + crate::config::DATA_MULTICAST_OFFSET;
        log::debug!(
            "[hdds] Creating data multicast listener on port {} for CycloneDDS/FastDDS interop",
            data_multicast_port
        );
        let data_multicast_socket = create_data_multicast_socket(
            domain_id,
            mapping.metatraffic_multicast,
            transport_options,
            socket_buffer_options,
        )?;

        #[cfg(test)]
        order_probe::record("data-multicast");
        let data_multicast_listener =
            crate::core::discovery::multicast::MulticastListener::spawn_for_participant(
                Arc::new(data_multicast_socket),
                rx_pool.clone(),                  // Reuse same pool
                rx_ring.clone(),                  // Reuse same ring -> goes to DemuxRouter!
                Some(discovery_callback.clone()), // For any discovery packets on this port
                control_tx, // Control channel for RELIABLE HEARTBEATs/ACKNACKs on multicast
                Some(wake_notifier.clone()), // WakeNotifier for low-latency
                Some(our_guid_prefix), // INFO_DST: what is destined here
                Some(Arc::clone(&liveliness)),
            )?;
        listeners.push(data_multicast_listener);

        log::debug!(
            "[hdds] [OK] Data multicast listener ready on port {} (CycloneDDS interop)!",
            data_multicast_port
        );
    } else {
        log::debug!("[hdds] Data multicast listener disabled");
    }

    // The relay's receive leg: the third way a datagram reaches this
    // participant, after a socket and shared memory. Not a thread and not a
    // socket - a routing target the Discovery Server session thread calls on
    // the thread that read the frame. It shares the ring, the pool, the
    // discovery callback, the control channel and the wake notifier with
    // every listener above, so a datagram the server carried is classified,
    // deduplicated and routed exactly like one off the wire. That matters
    // more here than for the other two legs: a relayed peer's SPDP and SEDP
    // arrive through this door and through no other.
    //
    // Its counters are its own. Folding relayed traffic into a listener's
    // metrics would have that socket report packets it never received.
    let relay_ingress = Arc::new(PacketDispatch::new(
        Arc::clone(&rx_pool),
        Arc::clone(&rx_ring),
        ListenerMetrics::new(),
        Some(discovery_callback.clone()),
        relay_control_tx,
        Some(Arc::clone(&wake_notifier)),
        Some(our_guid_prefix),
        Some(Arc::clone(&liveliness)),
    ));

    // Start router with transport for NACK_FRAG support
    // Use WakeNotifier for low-latency packet routing
    #[cfg(test)]
    order_probe::record("router");
    let router = DemuxRouter::start_with_reader_proxies(
        rx_ring,
        rx_pool,
        registry.clone(),
        Some(transport.clone()),
        guid.prefix,
        Some(wake_notifier), // WakeNotifier for low-latency
        // Peer participant locators so NACK_FRAG repair requests go to the
        // advertised default unicast locator, not the datagram source.
        Some(discovery_fsm.endpoint_registry()),
        // The readers' writer proxies: a NACK_FRAG is sent in their names.
        user_data_registry.clone(),
        Some(Arc::clone(&known_sources)),
    )?;

    log::debug!("[hdds] Discovery subsystem setup complete");

    Ok(DiscoveryComponents {
        discovery_fsm: Some(discovery_fsm),
        match_registry: Some(match_registry),
        type_lookup,
        registry: Some(registry),
        router: Some(Arc::new(router)),
        control_handler, // Store to prevent immediate Drop
        listeners,       // Store to prevent immediate Drop
        relay_ingress: Some(relay_ingress),
        // Shared with reader subscribers so on_data advances the ACKNACK base
        // (RTPS v2.5 Sec.8.4.12.2). Cheap clone (Arc<DashMap> inside).
        user_data_registry,
        #[cfg(target_os = "linux")]
        shm_receiver,
        #[cfg(feature = "security")]
        stateless_writer_handle,
        known_sources: Some(known_sources),
    })
}

/// The TypeLookup service's two writers, for the ControlHandler; `None` when
/// the service is compiled out.
#[cfg(any(feature = "type-lookup", feature = "xtypes-structural-assignability"))]
fn type_lookup_writers(
    handle: &TypeLookupHandle,
) -> Option<Arc<crate::core::discovery::multicast::directed_writer::TypeLookupWriters>> {
    handle.as_ref().map(|service| service.writers())
}

#[cfg(not(any(feature = "type-lookup", feature = "xtypes-structural-assignability")))]
fn type_lookup_writers(
    _handle: &TypeLookupHandle,
) -> Option<Arc<crate::core::discovery::multicast::directed_writer::TypeLookupWriters>> {
    None
}

/// Install the match registry on the FSM, then wake the samples the writers
/// judged by the install were deferred for: the install judges the writers
/// discovery holds whose verdict is not on record (`set_match_registry`), and
/// their deferred samples are otherwise held until the writer's next sample.
/// Called before any discovery thread that consults the registry is spawned.
fn install_match_registry(
    fsm: &DiscoveryFsm,
    topics: &TopicRegistry,
    match_registry: Arc<crate::dds::match_notification::MatchNotificationRegistry>,
) {
    #[cfg(test)]
    order_probe::record("install");
    for writer in fsm.set_match_registry(match_registry) {
        let _ = topics.notify_writer_qos_resolved(writer);
    }
}

/// The discovery steps `setup_discovery` ran that consult the match registry,
/// and the install, in the order they ran on the thread that set them up
/// (test builds only).
#[cfg(test)]
pub(super) mod order_probe {
    use std::cell::RefCell;

    thread_local! {
        static STEPS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(step: &'static str) {
        STEPS.with(|steps| steps.borrow_mut().push(step));
    }

    /// The steps recorded on this thread so far, cleared.
    pub(super) fn take() -> Vec<&'static str> {
        STEPS.with(|steps| std::mem::take(&mut *steps.borrow_mut()))
    }
}

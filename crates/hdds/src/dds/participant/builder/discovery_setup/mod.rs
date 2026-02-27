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
//! The discovery callback has been refactored into composable handler modules:
//! - `spdp_handler`: SPDP parsing, RTI ACKNACKs, SEDP re-announcements
//! - `sedp_handler`: SEDP parsing, endpoint discovery, TopicRegistry updates
//! - `fragment_handler`: DATA_FRAG reassembly and recursive parsing
//! - `data_handler`: DATA packet fallback parsing

mod data_handler;
mod fragment_handler;
mod heartbeat_handler;
mod sedp_handler;
mod spdp_handler;
mod type_lookup_handler;

use data_handler::handle_data_packet;
use fragment_handler::handle_fragment;
use heartbeat_handler::handle_heartbeat_packet;
use sedp_handler::handle_sedp_packet;
use spdp_handler::handle_spdp_packet;
pub(super) use type_lookup_handler::TypeLookupConfig;
#[cfg(feature = "type-lookup")]
use type_lookup_handler::TypeLookupService;
use type_lookup_handler::{handle_type_lookup_packet, TypeLookupHandle};

use super::entity_registry::SedpAnnouncementsCache;
use super::sockets::{create_data_multicast_socket, create_unicast_socket};
use crate::config::{
    FRAGMENT_BUFFER_SIZE, FRAGMENT_TIMEOUT_MS, MAX_PACKET_SIZE, PARTICIPANT_LEASE_DURATION_MS,
    RX_POOL_SIZE, RX_RING_SIZE,
};
use crate::core::discovery::{
    multicast::{ControlHandler, DiscoveryCallback, DiscoveryFsm, PacketKind, RxMeta, RxPool},
    FragmentBuffer, GUID,
};
use crate::core::reader::ReaderProxyRegistry;
use crate::engine::{Router as DemuxRouter, TopicRegistry, WakeNotifier};
use crate::transport::UdpTransport;
use crossbeam::queue::ArrayQueue;
use parking_lot::Mutex;
use std::sync::Arc;

#[cfg(feature = "security")]
use crate::security::{SecurityPluginSuite, SecurityValidatorAdapter};

/// Feature flag for Two-Ring architecture (v202)
/// When enabled, HEARTBEATs are processed in a dedicated ControlHandler thread
/// instead of synchronously in the listener callback. This prevents pool exhaustion
/// under high HEARTBEAT load (RELIABLE QoS).
const ENABLE_TWO_RING_CONTROL: bool = true;

/// Discovery components after initialization.
pub(super) struct DiscoveryComponents {
    pub discovery_fsm: Option<Arc<DiscoveryFsm>>,
    pub registry: Option<Arc<TopicRegistry>>,
    pub router: Option<Arc<DemuxRouter>>,
    /// v230: ControlHandler must be stored to prevent immediate Drop.
    /// If dropped, the control thread exits (running flag set to false).
    pub control_handler: Option<ControlHandler>,
    /// v230: Listeners must be stored to prevent immediate Drop.
    /// If dropped, listener threads exit (running flag set to false).
    pub listeners: Vec<crate::core::discovery::multicast::MulticastListener>,
}

/// Setup discovery FSM, listeners, and demux router.
///
/// # Arguments
/// - `guid`: Participant GUID
/// - `transport`: UDP transport
/// - `sedp_cache`: SEDP announcements cache
/// - `mapping`: Port mapping for multicast/unicast ports
/// - `dialect_detector`: Dialect detector for SPDP packet monitoring (Phase 1.6)
/// - `security_suite`: Optional security plugin suite for participant authentication (DDS Security v1.1)
///
/// # Returns
/// DiscoveryComponents with FSM, registry, and router
#[allow(unused_variables)] // security_suite unused when feature disabled
pub(super) fn setup_discovery(
    guid: GUID,
    transport: Arc<UdpTransport>,
    sedp_cache: SedpAnnouncementsCache,
    mapping: crate::transport::PortMapping,
    dialect_detector: Arc<
        std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>,
    >,
    type_lookup_config: TypeLookupConfig,
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
    let mut discovery_fsm = DiscoveryFsm::new(guid, PARTICIPANT_LEASE_DURATION_MS);

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
    }

    let discovery_fsm = Arc::new(discovery_fsm);
    let fsm_clone = discovery_fsm.clone();
    let fsm_clone2 = discovery_fsm.clone();
    let fsm_clone3 = discovery_fsm.clone();
    let fsm_for_hb = discovery_fsm.clone(); // v207: for heartbeat handler peer locator lookup

    // Clone SEDP announcements cache for use in discovery callback
    let sedp_announcements_clone = sedp_cache.clone();

    // Fragment buffer for reassembly (Phase 1.6)
    let fragment_buffer = Arc::new(Mutex::new(FragmentBuffer::new(
        FRAGMENT_BUFFER_SIZE,
        FRAGMENT_TIMEOUT_MS,
    )));
    let buffer_clone = fragment_buffer.clone();

    // Clone demux registry for GUID->topic mapping (RTI interop)
    let registry_clone = registry.clone();
    let registry_clone2 = registry.clone();

    // Clone transport for service-request ACKNACK responses
    let transport_clone = transport.clone();
    let our_guid_prefix = {
        let bytes = guid.as_bytes();
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&bytes[..12]);
        prefix
    };

    let type_lookup: TypeLookupHandle = {
        #[cfg(feature = "type-lookup")]
        {
            Some(Arc::new(TypeLookupService::new(
                discovery_fsm.clone(),
                transport.clone(),
                our_guid_prefix,
                type_lookup_config,
            )))
        }
        #[cfg(not(feature = "type-lookup"))]
        {
            let _ = type_lookup_config;
            None
        }
    };

    let type_lookup_for_callback = type_lookup.clone();
    let type_lookup_for_sedp = type_lookup.clone();

    // Phase 1.6: Clone dialect detector for SPDP packet monitoring
    let detector_clone = dialect_detector.clone();
    let detector_clone2 = dialect_detector.clone();

    // Clone port mapping for RTI locator inference in SPDP handler
    let mapping_clone = mapping;

    // v150: Create SEDP Reader proxy registry BEFORE callback and ControlHandler.
    // This registry must be shared between:
    // - Discovery callback: calls on_data() when SEDP DATA is received
    // - ControlHandler: calls on_heartbeat() to decide ACKNACK response
    //
    // The registry is created here, cloned for the callback, then passed to ControlHandler.
    let sedp_reader_registry = ReaderProxyRegistry::new();
    let sedp_registry_for_callback = sedp_reader_registry.clone();

    let discovery_callback: DiscoveryCallback = Arc::new(
        move |packet_kind, payload, cdr_offset, frag_meta, src_addr| {
            // v124: Dispatch to appropriate handler with CDR offset
            match packet_kind {
                PacketKind::SPDP => {
                    handle_spdp_packet(
                        payload,
                        cdr_offset,
                        src_addr,
                        our_guid_prefix,
                        transport_clone.clone(),
                        fsm_clone2.clone(),
                        sedp_announcements_clone.clone(),
                        detector_clone.clone(),
                        mapping_clone,
                    );
                }
                PacketKind::SEDP => {
                    // v150: Pass SEDP reader registry for DATA notification
                    // v184: Pass transport, sedp_cache, our_guid_prefix, src_addr for OpenDDS re-announcements
                    handle_sedp_packet(
                        payload,
                        cdr_offset,
                        fsm_clone3.clone(),
                        registry_clone2.clone(),
                        sedp_registry_for_callback.clone(),
                        transport_clone.clone(),
                        sedp_announcements_clone.clone(),
                        our_guid_prefix,
                        type_lookup_for_sedp.clone(),
                        src_addr,
                    );
                }
                PacketKind::DataFrag => {
                    if let Some(meta) = frag_meta {
                        handle_fragment(
                            meta,
                            payload,
                            src_addr,
                            our_guid_prefix,
                            buffer_clone.clone(),
                            transport_clone.clone(),
                            fsm_clone.clone(),
                            registry_clone.clone(),
                            sedp_announcements_clone.clone(),
                            detector_clone2.clone(),
                            mapping_clone,
                        );
                    } else {
                        log::debug!(
                            "[callback-builder] WARNING: DATA_FRAG without fragment metadata!"
                        );
                    }
                }
                PacketKind::Data => {
                    // User data (port user_unicast) should be routed via DemuxRouter,
                    // not parsed as SPDP/SEDP fallback. Skip the handler on that port.
                    if src_addr.port() == mapping_clone.user_unicast {
                        return;
                    }
                    handle_data_packet(
                        payload,
                        cdr_offset,
                        fsm_clone.clone(),
                        registry_clone.clone(),
                    );
                }
                PacketKind::TypeLookup => {
                    handle_type_lookup_packet(
                        &type_lookup_for_callback,
                        payload,
                        cdr_offset,
                        src_addr,
                    );
                }
                // v104: Handle HEARTBEAT for SEDP endpoints - respond with ACKNACK
                // v207: Pass discovery FSM for peer metatraffic locator lookup
                PacketKind::Heartbeat => {
                    handle_heartbeat_packet(
                        payload,
                        src_addr,
                        our_guid_prefix,
                        transport_clone.clone(),
                        mapping_clone.metatraffic_unicast, // v106 fallback
                        fsm_for_hb.clone(), // v207: lookup peer's actual metatraffic port
                    );
                }
                // Other packet kinds (AckNack, Gap, InfoTs, InfoSrc, InfoDst, InfoReply, Pad)
                // are automatically routed by MulticastListener to rx_ring -> DemuxRouter
                _ => {
                    // No action needed - MulticastListener handles routing
                }
            }
        },
    );

    // v203: Two-Ring Architecture for RELIABLE QoS
    // IMPORTANT: Create ControlHandler AFTER registry but BEFORE listeners so all listeners can use control_tx
    // This prevents pool exhaustion under high HEARTBEAT/ACKNACK load.
    //
    // v150: ControlHandler uses the shared sedp_reader_registry created above.
    // Both the discovery callback and ControlHandler use the same registry.
    //
    // v201: ControlHandler now also receives the TopicRegistry for dispatching user data
    // ACKNACKs to WriterNackHandler. This fixes BUG #3 where publisher didn't retransmit
    // despite receiving ACKNACKs (82% packet loss in RELIABLE HDDS-to-HDDS tests).
    //
    // v230: CRITICAL FIX - ControlHandler must be stored to prevent Drop from killing the thread!
    // Previously, only the sender was extracted, causing control_handler to be dropped immediately.
    let (control_tx, control_handler) = if ENABLE_TWO_RING_CONTROL {
        log::debug!("[hdds] v203: Two-Ring Architecture enabled - spawning ControlHandler");

        let handler = ControlHandler::spawn_with_topic_registry(
            transport.clone(),
            our_guid_prefix,
            mapping.metatraffic_unicast, // v207: fallback port (overridden by FSM lookup)
            sedp_reader_registry.clone(),
            registry.clone(),      // v201: TopicRegistry for user data NACK dispatch
            discovery_fsm.clone(), // v207: for peer metatraffic port resolution
            sedp_cache.clone(),    // v207: for SEDP DATA retransmission on NACK
        );

        log::debug!("[hdds] v201: ControlHandler spawned with SEDP registry + TopicRegistry");

        let sender = handler.sender();
        (Some(sender), Some(handler))
    } else {
        (None, None)
    };

    // v210: Create shared WakeNotifier for low-latency router wake
    // All listeners share this notifier to immediately wake the router when data arrives
    let wake_notifier = Arc::new(WakeNotifier::new());
    log::debug!("[hdds] v210: WakeNotifier created for low-latency routing");

    // v230: Collect all listeners to store in DiscoveryComponents (prevent Drop)
    // v240: Increased capacity to 4 for data multicast listener (CycloneDDS interop)
    let mut listeners = Vec::with_capacity(4);

    // Unified SPDP/SEDP listener (port 7400)
    // Single socket joined to both 239.255.0.1 (SPDP) and 239.255.0.2 (SEDP)
    // This avoids port conflicts and ensures we receive all metatraffic
    // v203: Now uses Two-Ring to bypass HEARTBEAT/ACKNACK pool allocation
    // v210: Now uses WakeNotifier for low-latency router wake
    let metatraffic_listener =
        crate::core::discovery::multicast::MulticastListener::spawn_with_notifier(
            transport.socket(),
            rx_pool.clone(),
            rx_ring.clone(),
            Some(discovery_callback.clone()),
            control_tx.clone(),          // v203: All listeners use Two-Ring
            Some(wake_notifier.clone()), // v210: WakeNotifier for low-latency
        )?;
    listeners.push(metatraffic_listener);

    // Phase 1.6: UNICAST listener (port 7410 for domain 0)
    // RTI/HDDS sends SEDP and Temperature data to this unicast address
    // IMPORTANT: Uses same rx_ring as multicast so data goes to DemuxRouter!
    //
    // v133: The transport's metatraffic_unicast_socket is bound to primary_ip:7410.
    // If we create a SECOND listener socket on 0.0.0.0:7410, the kernel delivers
    // incoming packets to the MORE SPECIFIC socket (primary_ip:7410), so the
    // wildcard listener never receives anything.
    //
    // Solution: Use the transport's socket for BOTH sending AND receiving.
    // The listener thread calls recv_from while main thread calls send_to.
    // UDP sockets support concurrent send/recv from different threads.
    log::debug!(
        "[hdds] v133: Reusing transport metatraffic_unicast_socket for SEDP reception (port {})",
        mapping.metatraffic_unicast
    );
    let unicast_socket = transport.metatraffic_unicast_socket();

    // v203: Now uses Two-Ring to bypass HEARTBEAT/ACKNACK pool allocation
    // v210: Now uses WakeNotifier for low-latency router wake
    let unicast_listener =
        crate::core::discovery::multicast::MulticastListener::spawn_with_notifier(
            unicast_socket,  // v133: Use transport's socket directly for both send AND recv
            rx_pool.clone(), // Reuse same pool
            rx_ring.clone(), // Reuse same ring -> goes to DemuxRouter!
            Some(discovery_callback.clone()),
            control_tx.clone(),          // v203: All listeners use Two-Ring
            Some(wake_notifier.clone()), // v210: WakeNotifier for low-latency
        )?;
    listeners.push(unicast_listener);

    log::debug!("[hdds] [OK] Unicast listener ready - RTI/HDDS can now send us SEDP/data!");

    // Phase v58: USER DATA listener (port 7411 for domain 0)
    // RTI sends user data (Temperature, etc.) to this port per RTPS v2.5
    // CRITICAL for RTI interop: must listen where SEDP announced
    log::debug!(
        "[hdds] Creating user data listener on port {} for RTI interop",
        mapping.user_unicast
    );
    let user_socket = create_unicast_socket(mapping.user_unicast)?;

    // v201/v202/v203: Pass discovery callback AND control channel to user data listener
    // With Two-Ring: HEARTBEATs/ACKNACKs bypass pool, DATA goes to ring
    // Without Two-Ring: Legacy synchronous callback handles HEARTBEATs
    // v210: WakeNotifier for low-latency router wake
    let user_data_listener =
        crate::core::discovery::multicast::MulticastListener::spawn_with_notifier(
            Arc::new(user_socket),
            rx_pool.clone(),                  // Reuse same pool
            rx_ring.clone(),                  // Reuse same ring -> goes to DemuxRouter!
            Some(discovery_callback.clone()), // For SPDP/SEDP on this port (rare but possible)
            control_tx,                       // v203: Control channel for HEARTBEATs/ACKNACKs
            Some(wake_notifier.clone()),      // v210: WakeNotifier for low-latency
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

    // v240: DATA MULTICAST listener (port 7401 for domain 0)
    // CycloneDDS and FastDDS send user data to 239.255.0.1:7401 when unicast readers
    // are not yet discovered. This is a non-standard but widely-used extension.
    // Without this listener, HDDS cannot receive user data from CycloneDDS until
    // both sides have exchanged SEDP endpoint info.
    let data_multicast_port = mapping.metatraffic_multicast + crate::config::DATA_MULTICAST_OFFSET;
    log::debug!(
        "[hdds] v240: Creating data multicast listener on port {} for CycloneDDS/FastDDS interop",
        data_multicast_port
    );
    let data_multicast_socket = create_data_multicast_socket(mapping.metatraffic_multicast)?;

    let data_multicast_listener =
        crate::core::discovery::multicast::MulticastListener::spawn_with_notifier(
            Arc::new(data_multicast_socket),
            rx_pool.clone(),                  // Reuse same pool
            rx_ring.clone(),                  // Reuse same ring -> goes to DemuxRouter!
            Some(discovery_callback.clone()), // For any discovery packets on this port
            None,                             // v240: No control channel needed for data multicast
            Some(wake_notifier.clone()),      // v210: WakeNotifier for low-latency
        )?;
    listeners.push(data_multicast_listener);

    log::debug!(
        "[hdds] [OK] Data multicast listener ready on port {} (CycloneDDS interop)!",
        data_multicast_port
    );

    // Start router with transport for NACK_FRAG support
    // v210: Use WakeNotifier for low-latency packet routing
    let router = DemuxRouter::start_with_notifier(
        rx_ring,
        rx_pool,
        registry.clone(),
        Some(transport.clone()),
        guid.prefix,
        Some(wake_notifier), // v210: WakeNotifier for low-latency
    )?;

    log::debug!("[hdds] Discovery subsystem setup complete");

    Ok(DiscoveryComponents {
        discovery_fsm: Some(discovery_fsm),
        registry: Some(registry),
        router: Some(Arc::new(router)),
        control_handler, // v230: Store to prevent immediate Drop
        listeners,       // v230: Store to prevent immediate Drop
    })
}

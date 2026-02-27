// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant build() orchestration.
//!
//! This module coordinates participant initialization by calling focused setup modules:
//! - entity_registry: SEDP cache and GUID generation
//! - telemetry_setup: Metrics and telemetry exporter
//! - discovery_setup: Discovery FSM, listeners, and demux router
//! - threads: Background thread spawning (SPDP announcer, lease tracker)

use super::{discovery_setup, entity_registry, telemetry_setup, threads, ParticipantBuilder};
use crate::config::RuntimeConfig;
use crate::dds::participant::runtime::{Participant, TransportMode, RTPS_ENTITYID_PARTICIPANT};
use crate::dds::{DomainRegistry, GuardCondition, Result};
use crate::transport::tcp::{TcpTransport, TransportPreference};
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;

#[cfg(feature = "xtypes")]
use crate::core::types::TypeCache;

#[cfg(feature = "security")]
use crate::security::SecurityPluginSuite;

#[cfg(feature = "k8s")]
use crate::discovery::k8s::K8sDiscovery;

impl ParticipantBuilder {
    /// Build and initialize a DDS participant.
    ///
    /// # Initialization Sequence
    /// 1. Initialize slab pool and telemetry
    /// 2. Calculate port mapping and generate GUID
    /// 3. Create SEDP announcements cache
    /// 4. Setup transport (if UdpMulticast mode)
    /// 5. Setup discovery subsystem (FSM, listeners, demux router)
    /// 6. Spawn background threads (telemetry, SPDP announcer, lease tracker)
    /// 7. Create type cache (if xtypes feature enabled)
    /// 8. Construct and return Participant
    ///
    /// # Returns
    /// `Result<Arc<Participant>>` or Error if initialization fails
    pub fn build(self) -> Result<Arc<Participant>> {
        log::debug!("[hdds] ParticipantBuilder::build name={}", self.name);

        // Step 1: Initialize slab pool and telemetry
        let _slab_pool = crate::core::rt::init_slab_pool();
        let metrics = telemetry_setup::init_telemetry();
        let telemetry_thread = telemetry_setup::spawn_telemetry_thread(metrics.clone());

        // Step 2: Calculate port mapping and generate GUID
        //
        // Port assignment priority (v1.0.6):
        //   1. Custom ports via with_discovery_ports() - for explicit control
        //   2. Code via .participant_id(Some(X)) - programmatic assignment
        //   3. Env via HDDS_PARTICIPANT_ID=X - deployment-time assignment (v1.0.6)
        //   4. Auto-assign - probe ports until free pair found
        //
        // For multi-process on same machine:
        //   - Set HDDS_REUSEPORT=1 (required for multicast port sharing)
        //   - Set unique HDDS_PARTICIPANT_ID per process (0, 1, 2, ...)
        //   - Ports: metatraffic=7410+pid*2, userdata=7411+pid*2
        //
        // FIX: For auto-assigned participant IDs, we keep reservation sockets alive
        // until transport creation to prevent race conditions where two processes on
        // the same machine both get the same participant_id.
        let mut _port_reservation: Vec<std::net::UdpSocket> = Vec::new();

        let (port_mapping, actual_participant_id) = match self.transport_mode {
            TransportMode::IntraProcess => (None, 0),
            TransportMode::UdpMulticast => {
                // Priority 1: Custom ports (if specified via with_discovery_ports())
                let (mapping, pid) = if let Some(custom) = self.custom_ports {
                    let mapping = crate::transport::PortMapping::from_custom(custom);
                    let pid = self.participant_id.unwrap_or(0);
                    log::debug!(
                        "[hdds] Using CUSTOM ports -> spdp_multicast={}, sedp_unicast={}, user_unicast={}",
                        custom.spdp_multicast, custom.sedp_unicast, custom.user_unicast
                    );
                    (mapping, pid)
                // Priority 2: User-specified participant ID (RTPS formula)
                } else if let Some(pid) = self.participant_id {
                    // User-specified participant ID (RTPS formula)
                    let mapping = crate::transport::PortMapping::calculate(self.domain_id, pid)?;
                    log::debug!(
                        "[hdds] Using RTPS formula with participant_id={} -> multicast={}, unicast={}, userdata={}",
                        pid, mapping.metatraffic_multicast, mapping.metatraffic_unicast, mapping.user_unicast
                    );
                    (mapping, pid)
                // Priority 2.5: Environment variable HDDS_PARTICIPANT_ID
                } else if let Ok(pid_str) = std::env::var("HDDS_PARTICIPANT_ID") {
                    let pid: u8 = pid_str.parse().map_err(|_| {
                        log::error!(
                            "[hdds] Invalid HDDS_PARTICIPANT_ID='{}' (must be 0-119)",
                            pid_str
                        );
                        crate::dds::Error::Config
                    })?;
                    let mapping = crate::transport::PortMapping::calculate(self.domain_id, pid)?;
                    log::info!(
                        "[hdds] Using HDDS_PARTICIPANT_ID={} -> unicast={}, userdata={}",
                        pid,
                        mapping.metatraffic_unicast,
                        mapping.user_unicast
                    );
                    (mapping, pid)
                } else {
                    // Priority 3: Auto-assign participant ID (try 0-255, RTPS formula)
                    //
                    // We reserve BOTH metatraffic_unicast (7410) AND user_unicast (7411) ports
                    // to prevent conflicts on same-machine deployments. The reservation sockets
                    // are kept alive in _port_reservation until after transport creation.
                    let mut last_mapping = None;
                    let mut found_pid = 0;

                    for pid_guess in 0..=255u8 {
                        let mapping = match crate::transport::PortMapping::calculate(
                            self.domain_id,
                            pid_guess,
                        ) {
                            Ok(m) => m,
                            Err(_) => continue, // Skip invalid participant IDs
                        };
                        last_mapping = Some(mapping);

                        // Try to bind to BOTH unicast ports to check availability
                        // This prevents race conditions on same-machine deployments
                        let meta_bind_addr = format!("0.0.0.0:{}", mapping.metatraffic_unicast);
                        let user_bind_addr = format!("0.0.0.0:{}", mapping.user_unicast);

                        match (
                            std::net::UdpSocket::bind(&meta_bind_addr),
                            std::net::UdpSocket::bind(&user_bind_addr),
                        ) {
                            (Ok(meta_sock), Ok(user_sock)) => {
                                // Keep sockets alive in outer scope to prevent race conditions
                                // These will be dropped after transport creation (with SO_REUSEADDR)
                                _port_reservation.push(meta_sock);
                                _port_reservation.push(user_sock);
                                log::debug!(
                                    "[hdds] Auto-assigned participant_id={} (RTPS formula) -> multicast={}, unicast={}, userdata={}",
                                    pid_guess, mapping.metatraffic_multicast, mapping.metatraffic_unicast, mapping.user_unicast
                                );
                                found_pid = pid_guess;
                                break;
                            }
                            _ => {
                                // One or both ports unavailable, try next participant_id
                                continue;
                            }
                        }
                    }

                    // All ports busy, use last mapping and let OS handle bind failure
                    let mapping = last_mapping.ok_or_else(|| {
                        log::debug!(
                            "[hdds] ERROR: All participant IDs (0-255) failed to calculate valid PortMapping"
                        );
                        crate::dds::Error::Config
                    })?;

                    (mapping, found_pid)
                };
                (Some(mapping), pid)
            }
        };

        // Generate RTPS v2.5 compliant GUID
        let guid = entity_registry::generate_guid(actual_participant_id, RTPS_ENTITYID_PARTICIPANT);

        // Step 2.5: Create runtime configuration and store port mapping
        let config = Arc::new(RuntimeConfig::new());
        if let Some(mapping) = port_mapping {
            config.set_port_mapping(mapping);
        }

        // Step 3: Create SEDP announcements cache for unicast replay (RTI interop)
        let sedp_cache = entity_registry::create_sedp_cache();

        // Step 3.5: Initialize dialect detector (Phase 1.6 - monitoring passif)
        // Created before setup_discovery so it can be passed to SPDP callback
        let dialect_detector = Arc::new(std::sync::Mutex::new(
            crate::core::discovery::multicast::dialect_detector::DialectDetector::with_domain(
                self.domain_id,
            ),
        ));

        // Step 3.6: Create security suite BEFORE discovery setup (DDS Security v1.1)
        // Must be created early so AuthenticationPlugin can be connected to DiscoveryFsm
        #[cfg(feature = "security")]
        let security_suite: Option<Arc<SecurityPluginSuite>> = match self.security_config {
            Some(ref config) => Some(Arc::new(SecurityPluginSuite::new(config.clone())?)),
            None => None,
        };

        // Step 4-5: Setup transport and discovery (if UdpMulticast mode)
        let (transport, discovery_components) = match self.transport_mode {
            TransportMode::IntraProcess => {
                // No transport or discovery for intra-process mode
                (
                    None,
                    discovery_setup::DiscoveryComponents {
                        discovery_fsm: None,
                        registry: None,
                        router: None,
                        control_handler: None,
                        listeners: Vec::new(),
                    },
                )
            }
            TransportMode::UdpMulticast => {
                let mapping = port_mapping.ok_or(crate::dds::Error::Config)?;

                log::debug!(
                    "[hdds] Creating UDP transport domain={} pid={}",
                    self.domain_id,
                    actual_participant_id
                );

                // Release port reservation BEFORE creating transport.
                // The transport will bind with SO_REUSEADDR, but the reservation sockets
                // (without SO_REUSEADDR) would block the bind if still alive.
                // Race window is minimal since we're in single-threaded init.
                drop(_port_reservation);

                let transport = Arc::new(
                    UdpTransport::new(self.domain_id, actual_participant_id, mapping)
                        .map_err(crate::dds::Error::IoError)?,
                );

                log::debug!("[hdds] UDP transport ready");

                #[cfg(feature = "type-lookup")]
                let type_lookup_config = discovery_setup::TypeLookupConfig {
                    registered_types: self.registered_types.clone(),
                    dialect_detector: dialect_detector.clone(),
                };
                #[cfg(not(feature = "type-lookup"))]
                let type_lookup_config = discovery_setup::TypeLookupConfig;

                // Setup discovery subsystem (FSM, listeners, demux router)
                // Phase 1.6: Pass dialect_detector for SPDP packet monitoring
                // DDS Security v1.1: Pass security_suite for AuthenticationPlugin -> DiscoveryFsm
                let components = discovery_setup::setup_discovery(
                    guid,
                    transport.clone(),
                    sedp_cache.clone(),
                    mapping,
                    dialect_detector.clone(),
                    type_lookup_config,
                    #[cfg(feature = "security")]
                    security_suite.clone(),
                )
                .map_err(crate::dds::Error::IoError)?;

                (Some(transport), components)
            }
        };

        // Step 5.5: Register static peers (for unicast without discovery)
        // Note: add_static_peer() is for UDP SPDP discovery. For TCP-only mode,
        // use TcpConfig::initial_peers instead.
        if !self.static_peers.is_empty() {
            if let Some(ref fsm) = discovery_components.discovery_fsm {
                for peer_addr in &self.static_peers {
                    println!("[hdds] Registering static peer: {}", peer_addr);
                    fsm.register_static_peer(*peer_addr);
                }
            } else {
                // Provide helpful guidance based on configuration
                let has_tcp = self.tcp_config.as_ref().is_some_and(|c| c.enabled);
                if has_tcp {
                    eprintln!(
                        "[hdds] Warning: add_static_peer() requires UdpMulticast transport mode.\n\
                         For TCP-only mode, use TcpConfig::initial_peers instead:\n\
                         \n\
                             .with_tcp(TcpConfig::tcp_only(vec![\"addr:port\".parse().unwrap()]))\n\
                         \n\
                         Current transport mode: {:?}",
                        self.transport_mode
                    );
                } else {
                    eprintln!(
                        "[hdds] Warning: static_peers configured but no discovery FSM available.\n\
                         add_static_peer() requires TransportMode::UdpMulticast.\n\
                         Current transport mode: {:?}",
                        self.transport_mode
                    );
                }
            }
        }

        // Step 5.6: Create TCP transport (if configured)
        // Note: TCP transport is HDDS-to-HDDS only, NOT interoperable with other DDS vendors
        let tcp_transport = if let Some(tcp_config) = self.tcp_config {
            if tcp_config.enabled {
                log::info!(
                    "[hdds] Creating TCP transport (port={}, role={:?})",
                    tcp_config.listen_port,
                    tcp_config.role
                );

                match TcpTransport::new(guid.prefix, tcp_config) {
                    Ok(tcp) => {
                        log::info!("[hdds] TCP transport ready");
                        Some(Arc::new(tcp))
                    }
                    Err(e) => {
                        log::error!("[hdds] Failed to create TCP transport: {}", e);
                        // TCP is optional - continue without it
                        // For tcp_only mode, this would be an error, but we handle that gracefully
                        if self.transport_preference == TransportPreference::TcpOnly {
                            return Err(crate::dds::Error::IoError(e));
                        }
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // Store transport preference
        let transport_preference = self.transport_preference;

        // Step 5.7: Start Kubernetes DNS discovery (if configured)
        #[cfg(feature = "k8s")]
        let k8s_discovery_handle = if let Some(k8s_config) = self.k8s_discovery_config {
            if let Some(ref fsm) = discovery_components.discovery_fsm {
                let dns_name = k8s_config.dns_name();
                let fsm_clone = Arc::clone(fsm);
                let k8s_discovery = K8sDiscovery::new(k8s_config).on_peer_discovered(move |peer| {
                    log::info!("[K8s-Discovery] Registering peer: {}", peer);
                    fsm_clone.register_static_peer(peer);
                });
                log::info!("[hdds] Starting K8s DNS discovery for service {}", dns_name);
                Some(k8s_discovery.start())
            } else {
                log::warn!(
                    "[hdds] K8s discovery configured but no discovery FSM (transport mode: {:?})",
                    self.transport_mode
                );
                None
            }
        } else {
            None
        };

        // Step 6: Spawn background threads (SPDP announcer, lease tracker)
        let participant_threads = threads::spawn_participant_threads(
            guid,
            metrics.clone(),
            transport.clone(),
            discovery_components.discovery_fsm.clone(),
            telemetry_thread,
            config.clone(),
        );

        // Step 7: Create type cache (if xtypes feature enabled)
        #[cfg(feature = "xtypes")]
        let type_cache = Arc::new(TypeCache::new(self.type_cache_capacity));

        // Step 8: Get or create domain state for intra-process auto-binding
        let domain_state = DomainRegistry::global().get_or_create(self.domain_id);

        // Step 9: v233 - Spawn QUIC I/O thread if configured
        #[cfg(feature = "quic")]
        let quic_io_thread = if let Some(ref quic_config) = self.quic_config {
            log::info!("[QUIC] Starting QUIC I/O thread...");
            Some(crate::transport::quic::QuicIoThread::spawn(
                quic_config.clone(),
            ))
        } else {
            None
        };

        // Step 9.5: Sprint 7 - Spawn unicast routing thread if TCP or QUIC configured
        let unicast_routing_thread = {
            let has_tcp = tcp_transport.is_some();
            #[cfg(feature = "quic")]
            let has_quic = quic_io_thread.is_some();
            #[cfg(not(feature = "quic"))]
            let has_quic = false;

            if has_tcp || has_quic {
                #[cfg(feature = "quic")]
                let quic_h = quic_io_thread.as_ref().map(|q| q.handle());

                if let (Some(reg), Some(rtr)) =
                    (&discovery_components.registry, &discovery_components.router)
                {
                    Some(super::unicast_routing::spawn(
                        tcp_transport.clone(),
                        #[cfg(feature = "quic")]
                        quic_h,
                        Arc::clone(reg),
                        Arc::clone(&rtr.metrics),
                        Arc::new(AtomicBool::new(false)),
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Step 10: v233 - Spawn cloud discovery poller if configured
        #[cfg(feature = "cloud-discovery")]
        let cloud_discovery_poller = if let Some(ref provider) = self.cloud_discovery_provider {
            let poller_config = match provider.as_str() {
                "consul" => {
                    if let Some(ref addr) = self.consul_addr {
                        Some(crate::discovery::cloud::CloudPollerConfig {
                            provider: crate::discovery::cloud::CloudProvider::Consul {
                                addr: addr.clone(),
                            },
                            poll_interval: std::time::Duration::from_secs(5),
                            domain_id: self.domain_id,
                        })
                    } else {
                        None
                    }
                }
                _ => None, // AWS and Azure not yet implemented in sync poller
            };

            if let Some(config) = poller_config {
                log::info!("[CLOUD-DISCOVERY] Starting {} poller thread...", provider);
                Some(crate::discovery::cloud::CloudDiscoveryPoller::spawn(config))
            } else {
                None
            }
        } else {
            None
        };

        // Step 11: Construct and return Participant (wrapped in Arc)
        let graph_guard = Arc::new(GuardCondition::new());

        Ok(Arc::new(Participant {
            name: self.name,
            transport_mode: self.transport_mode,
            domain_id: self.domain_id,
            participant_id: actual_participant_id,
            guid,
            port_mapping,
            transport,
            tcp_transport,
            transport_preference,
            #[cfg(feature = "quic")]
            quic_config: self.quic_config,
            lowbw_config: self.lowbw_config,
            discovery_server_config: self.discovery_server_config,
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_provider: self.cloud_discovery_provider,
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_config: self.consul_addr,
            shm_policy: self.shm_policy,
            registry: discovery_components.registry,
            router: discovery_components.router,
            discovery_fsm: discovery_components.discovery_fsm,
            _spdp_announcer: participant_threads.spdp_announcer,
            lease_tracker: participant_threads.lease_tracker,
            _control_handler: discovery_components.control_handler, // v230: prevent Drop
            _listeners: discovery_components.listeners,             // v230: prevent Drop
            sedp_announcements: sedp_cache,
            telemetry_shutdown: participant_threads.telemetry_shutdown,
            telemetry_handle: participant_threads.telemetry_handle,
            graph_guard,
            dialect_detector,
            next_entity_key: AtomicU32::new(0),
            domain_state,
            #[cfg(feature = "xtypes")]
            type_cache,
            #[cfg(feature = "xtypes")]
            registered_types: self.registered_types,
            #[cfg(feature = "xtypes")]
            topic_types: self.topic_types,
            #[cfg(feature = "xtypes")]
            distro: self.distro,
            #[cfg(feature = "security")]
            security: security_suite,
            #[cfg(feature = "k8s")]
            k8s_discovery_handle,
            #[cfg(feature = "quic")]
            quic_io_thread,
            #[cfg(feature = "cloud-discovery")]
            cloud_discovery_poller,
            _unicast_routing_thread: unicast_routing_thread,
        }))
    }
}

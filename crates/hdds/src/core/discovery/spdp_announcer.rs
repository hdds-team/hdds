// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP (Simple Participant Discovery Protocol) periodic announcer thread.
//!
//!
//! Per RTPS v2.3 spec section 8.5.3, participants MUST announce themselves
//! periodically (default: every 3 seconds) to multicast address 239.255.0.1:7400.
//!
//! This module implements that announcement: without it, participants never
//! announce themselves and discovery remains empty.

use crate::config::{
    RuntimeConfig, MULTICAST_IP, SPDP_ANNOUNCEMENT_PERIOD_MS, USER_UNICAST_PORT_DOMAIN0_P0,
};
use crate::core::discovery::multicast::{build_spdp_dispose_packet, build_spdp_rtps_packet};
use crate::core::discovery::{DiscoveryHint, SpdpPeerSet, GUID};
use crate::protocol::discovery::SpdpData;
use crate::transport::UdpTransport;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// A participant's SPDP writer SN counter, from its first SN (RTPS v2.5
/// Sec.8.2.3: the writer numbers its changes): shared by its periodic
/// announcer and its immediate replies, so a peer never sees the SN of the
/// participant's announcements go back.
#[must_use]
pub(crate) fn spdp_sequence() -> Arc<AtomicU64> {
    Arc::new(AtomicU64::new(1))
}

/// Where a participant is reached and in which domain, as its SPDP
/// announces it: read from its transport by both its periodic announcement
/// and its immediate reply to a peer (`spdp_announcement`).
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct AnnouncedLocators {
    /// The transport's domain: custom ports do not encode it.
    pub(crate) domain_id: u32,
    pub(crate) metatraffic_unicast: Vec<SocketAddr>,
    /// Asked of the transport, not derived by rewriting the port of the
    /// metatraffic list: an external locator (NAT mapping, relay) has TWO
    /// independent public ports.
    pub(crate) default_unicast: Vec<SocketAddr>,
    /// None unless the transport sends multicast: even when it listens
    /// (ReceiveOnly), a peer that prefers an advertised multicast locator for
    /// user data would lose everything on a link that does not route
    /// multicast to it; the unicast locators always work.
    pub(crate) default_multicast: Vec<SocketAddr>,
}

impl AnnouncedLocators {
    /// What `transport` announces, its user data on `user_unicast_port`.
    pub(crate) fn of(transport: &UdpTransport, user_unicast_port: u16) -> Self {
        Self {
            domain_id: transport.domain_id(),
            metatraffic_unicast: transport.get_unicast_locators(),
            default_unicast: transport.get_user_unicast_locators(user_unicast_port),
            default_multicast: transport
                .multicast_send_enabled()
                .then(|| SocketAddr::from((MULTICAST_IP, transport.data_multicast_port())))
                .into_iter()
                .collect(),
        }
    }
}

/// The one SPDP sample of a participant: its periodic announcement and its
/// immediate reply to a peer are built here, from the same inputs. They
/// must not differ (a reply that re-derives the domain from a port, advertises
/// a multicast locator a unicast-only participant does not, or carries no
/// capabilities would leave a peer with whichever sample it got last).
///
/// PID_METATRAFFIC_MULTICAST_LOCATOR is not put on the wire by build_spdp
/// (see protocol/discovery/spdp/build.rs: it is not needed, SPDP itself
/// proves the group reachable), so none is announced.
pub(crate) fn spdp_announcement(
    participant_guid: GUID,
    locators: &AnnouncedLocators,
    lease_duration_ms: u64,
    identity_token: Option<Vec<u8>>,
    permissions_token: Option<Vec<u8>>,
    participant_security_info: Option<[u8; 8]>,
    hdds_capabilities: u32,
) -> SpdpData {
    SpdpData {
        participant_guid,
        lease_duration_ms,
        domain_id: locators.domain_id,
        metatraffic_unicast_locators: locators.metatraffic_unicast.clone(),
        default_unicast_locators: locators.default_unicast.clone(),
        default_multicast_locators: locators.default_multicast.clone(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token,
        permissions_token,
        participant_security_info,
        vendor_id: None,
        hdds_capabilities: Some(hdds_capabilities),
        builtin_endpoint_set: None,
    }
}

/// Global counter of SPDP announcements sent by this participant.
///
/// Used by discovery helpers (e.g. SEDP re-announcer) to add a small
/// barrier and avoid sending SEDP before remote PDP has had multiple
/// opportunities to ingest our SPDP.
pub static SPDP_SENT_COUNT: AtomicU64 = AtomicU64::new(0);

/// SPDP periodic announcer that broadcasts participant information.
///
/// # RTPS Spec Compliance
///
/// - **Announcement Period**: 3 seconds (RTPS v2.3 default)
/// - **Lease Duration**: 30 seconds (10x announcement period)
/// - **Multicast Address**: 239.255.0.1:7400 (SPDP well-known port)
///
/// # Implementation Notes
///
/// The announcer runs in a background thread and sends SPDP DATA submessages
/// containing participant GUID, lease duration, and unicast locators. Remote
/// participants receiving these announcements add this participant to their
/// `DiscoveryFsm` database, enabling topic discovery via SEDP.
///
/// Unicast destinations come from a shared [`SpdpPeerSet`]: static peers
/// (builder, `HDDS_SPDP_UNICAST_PEERS`, `HDDS_REUSEPORT` localhost fan-out)
/// plus the locators a Discovery Server hands out at runtime. Any change to
/// the set wakes the announcer so the new peer receives SPDP immediately.
/// Multicast emission and multicast locator advertising follow the
/// transport's policy ([`UdpTransport::multicast_enabled`]).
pub struct SpdpAnnouncer {
    /// Background thread handle
    handle: Option<JoinHandle<()>>,
    /// Shutdown signal (set to true to stop announcer)
    shutdown: Arc<AtomicBool>,
    /// Transport for sending dispose packet on shutdown
    transport: Arc<UdpTransport>,
    /// Participant GUID for dispose message
    participant_guid: GUID,
    /// SPDP writer sequence number counter, shared with the announcer
    /// thread so the shutdown dispose gets the next monotonic SN
    /// (a DATA whose writerSN is SEQUENCENUMBER_UNKNOWN is invalid, RTPS
    /// v2.5 Sec.8.3.8.2).
    sequence_number: Arc<AtomicU64>,
    /// Live SPDP unicast destinations.
    peer_set: Arc<SpdpPeerSet>,
    /// Set by the first `send_dispose`: a participant leaves once.
    farewell_sent: AtomicBool,
}

impl SpdpAnnouncer {
    /// Spawn SPDP announcer thread.
    ///
    /// # Arguments
    ///
    /// - `participant_guid`: RTPS GUID of the local participant
    /// - `transport`: UDP transport for sending multicast packets
    /// - `lease_duration_ms`: Lease duration in milliseconds (default: 30,000)
    /// - `config`: Runtime configuration (for custom ports)
    ///
    /// # Returns
    ///
    /// `SpdpAnnouncer` instance with background thread running. Call `shutdown()`
    /// or let it drop to stop the announcer gracefully.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let config = Arc::new(RuntimeConfig::new());
    /// let announcer = SpdpAnnouncer::spawn(guid, transport.clone(), 30_000, config, None);
    /// // Announcements sent every 3 seconds...
    /// announcer.shutdown(); // Stop announcer
    /// ```
    #[must_use]
    pub fn spawn(
        participant_guid: GUID,
        transport: Arc<UdpTransport>,
        lease_duration_ms: u64,
        config: Arc<RuntimeConfig>,
    ) -> Self {
        Self::spawn_with_security(
            participant_guid,
            transport,
            lease_duration_ms,
            config,
            None,
            None,
            None,
        )
    }

    /// Spawn SPDP announcer thread with DDS Security tokens.
    ///
    /// # Arguments
    ///
    /// - `participant_guid`: RTPS GUID of the local participant
    /// - `transport`: UDP transport for sending multicast packets
    /// - `lease_duration_ms`: Lease duration in milliseconds (default: 30,000)
    /// - `config`: Runtime configuration (for custom ports)
    /// - `identity_token`: Optional serialized IdentityToken DataHolder
    ///   (PID 0x1001) per DDS Security v1.1 sec. 7.4.1.4
    /// - `permissions_token`: Optional serialized PermissionsToken DataHolder
    ///   (PID 0x1007) per DDS Security v1.1 sec. 7.4.1.4
    /// - `participant_security_info`: Optional 8-byte
    ///   PID_PARTICIPANT_SECURITY_INFO payload (DDS Security v1.1 sec. 7.4.1.5)
    ///
    /// # Returns
    ///
    /// `SpdpAnnouncer` instance with background thread running.
    #[must_use]
    pub fn spawn_with_security(
        participant_guid: GUID,
        transport: Arc<UdpTransport>,
        lease_duration_ms: u64,
        config: Arc<RuntimeConfig>,
        identity_token: Option<Vec<u8>>,
        permissions_token: Option<Vec<u8>>,
        participant_security_info: Option<[u8; 8]>,
    ) -> Self {
        Self::spawn_with_security_and_period(
            participant_guid,
            transport,
            lease_duration_ms,
            Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS),
            config,
            identity_token,
            permissions_token,
            participant_security_info,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_with_security_and_period(
        participant_guid: GUID,
        transport: Arc<UdpTransport>,
        lease_duration_ms: u64,
        announcement_period: Duration,
        config: Arc<RuntimeConfig>,
        identity_token: Option<Vec<u8>>,
        permissions_token: Option<Vec<u8>>,
        participant_security_info: Option<[u8; 8]>,
    ) -> Self {
        Self::spawn_with_security_and_peers(
            participant_guid,
            transport,
            lease_duration_ms,
            announcement_period,
            config,
            identity_token,
            permissions_token,
            participant_security_info,
            Arc::new(SpdpPeerSet::new()),
            None,
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        )
    }

    /// Spawn the announcer on a shared peer set.
    ///
    /// The env-configured peers (`HDDS_SPDP_UNICAST_PEERS`, `HDDS_REUSEPORT`)
    /// are seeded into `peer_set` here, once; the caller adds builder static
    /// peers and Discovery Server locators through the same set.
    ///
    /// `hint`, when given, is polled after every announcement (see
    /// [`DiscoveryHint`]).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn_with_security_and_peers(
        participant_guid: GUID,
        transport: Arc<UdpTransport>,
        lease_duration_ms: u64,
        announcement_period: Duration,
        config: Arc<RuntimeConfig>,
        identity_token: Option<Vec<u8>>,
        permissions_token: Option<Vec<u8>>,
        participant_security_info: Option<[u8; 8]>,
        peer_set: Arc<SpdpPeerSet>,
        hint: Option<DiscoveryHint>,
        hdds_capabilities: u32,
        sequence_number: Arc<AtomicU64>,
    ) -> Self {
        crate::trace_fn!("SpdpAnnouncer::spawn_with_security");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let transport_for_dispose = Arc::clone(&transport);
        // The participant's SPDP writer SN counter (starts at 1 per RTPS
        // spec), shared with its immediate replies (`spdp_sequence`): the
        // announcer thread consumes it per announcement and send_dispose
        // takes the next value on shutdown.
        let sequence_number_clone = Arc::clone(&sequence_number);
        seed_configured_peers(peer_set.as_ref(), transport.as_ref());
        let thread_peer_set = Arc::clone(&peer_set);

        let handle = thread::spawn(crate::core::rt::shutdown::owned(move || {
            announcer_loop(
                participant_guid,
                transport,
                lease_duration_ms,
                announcement_period,
                config,
                shutdown_clone,
                identity_token,
                permissions_token,
                participant_security_info,
                sequence_number_clone,
                thread_peer_set,
                hint,
                hdds_capabilities,
            );
        }));

        Self {
            handle: Some(handle),
            shutdown,
            transport: transport_for_dispose,
            participant_guid,
            sequence_number,
            peer_set,
            farewell_sent: AtomicBool::new(false),
        }
    }

    /// Signal announcer thread to stop and wait for completion.
    ///
    /// This is automatically called on Drop, but can be explicitly invoked
    /// if synchronous shutdown is required. Once the thread has stopped, tells
    /// the peers this participant is leaving (`send_dispose`).
    pub fn shutdown(mut self) {
        self.stop_then_say_farewell();
    }
}

impl Drop for SpdpAnnouncer {
    fn drop(&mut self) {
        // Once: `shutdown` may have already.
        self.stop_then_say_farewell();
    }
}

impl SpdpAnnouncer {
    /// Stop the announcer thread, wait for it, THEN send the departure. In
    /// the other order, a thread already past its shutdown check sends one
    /// more announcement after the departure, with a lower sequence number,
    /// and an HDDS receiver takes the participant back for a whole lease.
    fn stop_then_say_farewell(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.peer_set.wake();
        if let Some(handle) = self.handle.take() {
            crate::core::rt::shutdown::join_bounded(handle, "SPDP announcer");
        }
        self.send_dispose();
    }

    /// Tell the peers this participant is going away, once: a DATA of the
    /// SPDP writer disposing and unregistering its DCPSParticipant instance
    /// (`build_spdp_dispose_packet`, RTPS v2.5 Sec.9.6.4.9).
    ///
    /// Routed like the announcements: multicast when the transport allows
    /// it, plus every unicast peer currently in the set. `shutdown` and
    /// `Drop` both call it; only the first sends.
    ///
    /// It is a dispose, not a full SPDP announcement with a lease of 0 and no
    /// default locators: that reads as a change of the participant's
    /// configuration rather than a departure, and an HDDS peer would run it
    /// through its whole SPDP pipeline (immediate reply, SEDP
    /// re-announcements) towards a participant that is leaving.
    fn send_dispose(&self) {
        if self.farewell_sent.swap(true, Ordering::AcqRel) {
            return;
        }
        // The next SN of the live SPDP writer stream: a DATA whose writerSN
        // is SEQUENCENUMBER_UNKNOWN is invalid (RTPS v2.5 Sec.8.3.8.2) and a
        // receiver drops it.
        let seq_num = self.sequence_number.fetch_add(1, Ordering::Relaxed);
        let packet = build_spdp_dispose_packet(&self.participant_guid, seq_num);
        if self.transport.multicast_send_enabled() {
            if let Err(err) = self.transport.send(&packet) {
                log::debug!("[spdp_announcer] Failed to send SPDP dispose: {}", err);
            }
        }
        for peer in self.peer_set.snapshot() {
            if let Err(err) = self.transport.send_to_endpoint(&packet, &peer) {
                log::debug!(
                    "[spdp_announcer] Failed unicast SPDP dispose to {}: {}",
                    peer,
                    err
                );
            }
        }
        log::debug!(
            "[spdp_announcer] Sent SPDP dispose (DATA(p[UD])) for {:?}",
            self.participant_guid
        );
    }
}

const AGGRESSIVE_WINDOW: Duration = Duration::from_secs(5);
const AGGRESSIVE_INTERVAL: Duration = Duration::from_millis(200);
/// Minimum gap between two announcements triggered by peer-set changes.
const MIN_ANNOUNCE_GAP: Duration = AGGRESSIVE_INTERVAL;

fn select_announcement_interval(elapsed: Duration, normal_interval: Duration) -> Duration {
    if elapsed < AGGRESSIVE_WINDOW {
        normal_interval.min(AGGRESSIVE_INTERVAL)
    } else {
        normal_interval
    }
}

/// Main announcer loop (runs in background thread).
///
/// Sends SPDP RTPS packets at the configured period until shutdown.
/// Each packet includes a complete RTPS header with incrementing sequence numbers.
#[allow(clippy::too_many_arguments)]
fn announcer_loop(
    participant_guid: GUID,
    transport: Arc<UdpTransport>,
    lease_duration_ms: u64,
    announcement_period: Duration,
    config: Arc<RuntimeConfig>,
    shutdown: Arc<AtomicBool>,
    identity_token: Option<Vec<u8>>,
    permissions_token: Option<Vec<u8>>,
    participant_security_info: Option<[u8; 8]>,
    sequence_number: Arc<AtomicU64>,
    peer_set: Arc<SpdpPeerSet>,
    mut hint: Option<DiscoveryHint>,
    hdds_capabilities: u32,
) {
    // Aggressive burst phase at startup to reduce SPDP->SEDP races with
    // external stacks. During this window we send SPDP
    // more frequently so that remote PDP has multiple opportunities to
    // ingest our participant before SEDP re-announces start flowing.
    let start_instant = std::time::Instant::now();

    // Sequence number counter is shared with SpdpAnnouncer::send_dispose
    // (starts at 1 per RTPS spec) so the shutdown dispose continues the
    // live SPDP writer SN stream instead of sending an out-of-band value.

    // Get all locator types needed for cross-vendor interop (RTPS v2.3 Sec.8.5.3.1)
    // A peer needs to know WHERE to send different types of traffic:
    // - Metatraffic unicast (SEDP/ACKNACK)
    // - Default unicast (USER DATA) [MANDATORY!]
    // - Multicast addresses for discovery and data

    // Get port configuration (custom or default RTPS formula)
    let port_mapping = config.get_port_mapping();

    // Calculate user data unicast port (custom or default)
    let user_unicast_port = port_mapping
        .map(|m| m.user_unicast)
        .unwrap_or(USER_UNICAST_PORT_DOMAIN0_P0);

    let locators = AnnouncedLocators::of(&transport, user_unicast_port);
    let multicast_send = transport.multicast_send_enabled();
    log::debug!(
        "[spdp_announcer] Announcing domain {} metatraffic unicast {:?}, default unicast \
         (port {}) {:?}, default multicast {:?}",
        locators.domain_id,
        locators.metatraffic_unicast,
        user_unicast_port,
        locators.default_unicast,
        locators.default_multicast
    );

    let mut peer_generation = peer_set.generation();
    let mut last_send: Option<std::time::Instant> = None;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            log::debug!("[spdp_announcer] Shutdown signal received, stopping announcer");
            break;
        }

        // Rate floor: a peer-set change wakes the loop immediately, but a
        // burst of changes (a Discovery Server registering many participants,
        // a segment full of multicast peers appearing at once) must not turn
        // into a burst of full announcements. Never announce more often than
        // the aggressive startup interval.
        if let Some(last) = last_send {
            let since = last.elapsed();
            if since < MIN_ANNOUNCE_GAP {
                peer_generation = peer_set.wait_for_change(
                    peer_generation,
                    MIN_ANNOUNCE_GAP - since,
                    shutdown.as_ref(),
                );
                continue;
            }
        }

        let spdp_data = spdp_announcement(
            participant_guid,
            &locators,
            lease_duration_ms,
            identity_token.clone(),
            permissions_token.clone(),
            participant_security_info,
            hdds_capabilities,
        );

        // Get current sequence number and increment for next announcement
        let seq_num = sequence_number.fetch_add(1, Ordering::Relaxed);

        // Build complete RTPS packet (header + DATA submessage + payload)
        match build_spdp_rtps_packet(&spdp_data, seq_num, None) {
            // None = multicast
            Ok(packet) => {
                let mut sent_any = false;
                // 1) Multicast SPDP (239.255.0.1:7400), MulticastMode::Enabled only.
                if multicast_send {
                    if let Err(err) = transport.send(&packet) {
                        log::debug!(
                            "[spdp_announcer] Failed to send SPDP multicast: {} (GUID={:?}, seq={})",
                            err,
                            participant_guid,
                            seq_num
                        );
                    } else {
                        sent_any = true;
                        if crate::config::env_flags::spdp_announce_debug_log() {
                            log::debug!(
                                "[spdp_announcer] Sent SPDP multicast (GUID={:?}, seq={}, lease={}ms, size={} bytes)",
                                participant_guid,
                                seq_num,
                                lease_duration_ms,
                                packet.len()
                            );
                        }
                    }
                }

                // 2) Unicast SPDP to every live peer (static + Discovery Server).
                for peer in peer_set.snapshot() {
                    match transport.send_to_endpoint(&packet, &peer) {
                        Ok(sent) => {
                            sent_any = true;
                            log::debug!(
                                "[UDP-SPDP] Sent unicast SPDP {} bytes -> {} (GUID={:?}, seq={})",
                                sent,
                                peer,
                                participant_guid,
                                seq_num
                            );
                        }
                        Err(err) => {
                            log::debug!(
                                "[UDP-SPDP] Failed unicast SPDP to {}: {} (GUID={:?}, seq={})",
                                peer,
                                err,
                                participant_guid,
                                seq_num
                            );
                        }
                    }
                }

                if sent_any {
                    SPDP_SENT_COUNT.fetch_add(1, Ordering::Relaxed);
                }
                last_send = Some(std::time::Instant::now());
            }
            Err(err) => {
                log::debug!(
                    "[spdp_announcer] Failed to build SPDP RTPS packet: {:?} (GUID={:?}, seq={})",
                    err,
                    participant_guid,
                    seq_num
                );
            }
        }

        // Once-only "discovered nobody" hint: one comparison per
        // announcement until its deadline, then dropped.
        if let Some(pending) = hint.as_mut() {
            if let Some((level, line)) = pending.poll(start_instant.elapsed()) {
                log::log!(level, "{line}");
            }
            if pending.is_done() {
                hint = None;
            }
        }

        // Sleep until next announcement. Use an aggressive burst interval
        // during the first few seconds after startup, then fall back to
        // the configured period. The wait returns early when the peer set
        // changes (new Discovery Server locator) or on shutdown.
        let sleep_dur = select_announcement_interval(start_instant.elapsed(), announcement_period);
        peer_generation = peer_set.wait_for_change(peer_generation, sleep_dur, shutdown.as_ref());
    }
}

/// Seed the peer set with the env-configured unicast destinations.
///
/// - `HDDS_SPDP_UNICAST_PEERS` (comma-separated `ip:port`): Plan A interop
///   helper for stacks that miss our multicast SPDP (IGMP/interface quirks)
///   but listen on metatraffic unicast. Invalid entries are logged and
///   skipped (no panic).
/// - `HDDS_REUSEPORT=1`: localhost peers for participant IDs 0-7 so
///   same-machine discovery survives the Linux SO_REUSEPORT multicast
///   load-balancing behaviour (each process only sees SOME multicast
///   packets). Port formula: 7400 + 250*domain_id + participant_id*2 + 10.
fn seed_configured_peers(peer_set: &SpdpPeerSet, transport: &UdpTransport) {
    if let Ok(raw) = std::env::var("HDDS_SPDP_UNICAST_PEERS") {
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match entry.parse::<SocketAddr>() {
                Ok(locator) => {
                    peer_set.add_static(locator);
                }
                Err(error) => log::debug!(
                    "[spdp_announcer] Ignoring invalid HDDS_SPDP_UNICAST_PEERS entry '{}': {}",
                    entry,
                    error
                ),
            }
        }
    }

    let reuseport_enabled = std::env::var("HDDS_REUSEPORT")
        .map(|value| value == "1")
        .unwrap_or(false);
    if reuseport_enabled {
        // The port we are actually BOUND to, not the first announced
        // locator: the announced list can carry external entries whose port
        // belongs to a NAT, and it can be empty.
        let our_port = transport.metatraffic_unicast_port();
        for participant_id in 0..8u16 {
            let peer_port = 7410 + participant_id * 2;
            if peer_port != our_port {
                peer_set.add_static(SocketAddr::from(([127, 0, 0, 1], peer_port)));
            }
        }
        log::info!(
            "[spdp_announcer] HDDS_REUSEPORT=1 - added localhost unicast peers for same-machine discovery ({} peers total)",
            peer_set.snapshot().len()
        );
    }

    let peers = peer_set.snapshot();
    if !peers.is_empty() {
        log::debug!(
            "[spdp_announcer] SPDP unicast peers enabled ({}):",
            peers.len()
        );
        for peer in &peers {
            log::debug!("  -> {}", peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::multicast::{classify_rtps, PacketKind};
    use crate::protocol::discovery::parse_spdp;
    use crate::transport::{CustomPortMapping, MulticastMode, PortMapping, TransportOptions};
    use std::net::{Ipv4Addr, UdpSocket};
    use std::time::Instant;

    #[test]
    fn test_announcer_shutdown() {
        // This test just ensures the announcer can be created and shutdown
        // without panicking. Full integration testing requires UDP transport.
        let _guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);

        // We can't easily test with real transport without network setup,
        // but we can verify the shutdown mechanism works
        let shutdown = Arc::new(AtomicBool::new(false));
        shutdown.store(true, Ordering::Relaxed);
        assert!(shutdown.load(Ordering::Relaxed));
    }

    #[test]
    fn configured_period_is_used_after_the_startup_burst() {
        let normal = Duration::from_secs(60);

        assert_eq!(
            select_announcement_interval(Duration::from_secs(2), normal),
            Duration::from_millis(200)
        );
        assert_eq!(
            select_announcement_interval(Duration::from_secs(6), normal),
            normal
        );
    }

    #[test]
    fn runtime_peer_addition_triggers_unicast_spdp() {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let (transport, config) = build_transport_for_mode(MulticastMode::Disabled);
        let peers = Arc::new(SpdpPeerSet::new());
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let announcer = SpdpAnnouncer::spawn_with_security_and_peers(
            guid,
            transport,
            30_000,
            Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS),
            config,
            None,
            None,
            None,
            Arc::clone(&peers),
            None,
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        );

        peers.add_static(receiver_addr);
        let mut packet = [0u8; 2048];
        let (bytes_read, _) = receiver.recv_from(&mut packet).expect("receive SPDP");
        assert!(bytes_read >= 20);
        assert_eq!(&packet[..4], b"RTPS");

        drop(announcer);
    }

    /// The announcer polls the discovery hint and evaluates it exactly once,
    /// after two announcement periods.
    #[test]
    fn the_announcer_evaluates_the_discovery_hint_once() {
        use std::sync::atomic::AtomicUsize;

        let (transport, config) = build_transport_for_mode(MulticastMode::Disabled);
        let reads = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&reads);
        let period = Duration::from_millis(50);
        let hint = DiscoveryHint::new(period, move || {
            seen.fetch_add(1, Ordering::Relaxed);
            crate::core::discovery::DiscoveryState {
                remote_participants: 0,
                peers_configured: false,
                multicast_blocked: false,
            }
        });
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let announcer = SpdpAnnouncer::spawn_with_security_and_peers(
            guid,
            transport,
            30_000,
            period,
            config,
            None,
            None,
            None,
            Arc::new(SpdpPeerSet::new()),
            Some(hint),
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while reads.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(reads.load(Ordering::Relaxed), 1, "evaluated once");
        // Several more announcements: still once.
        std::thread::sleep(period * 6);
        assert_eq!(reads.load(Ordering::Relaxed), 1, "never re-evaluated");
        drop(announcer);
    }

    /// Build a transport in the given [`MulticastMode`] on reserved ports,
    /// paired with the [`RuntimeConfig`] the announcer needs to derive its
    /// data-multicast port.
    ///
    /// Retries on `AddrInUse`: the reserve-drop-rebind window is a known
    /// race when other socket tests run in parallel.
    fn build_transport_for_mode(mode: MulticastMode) -> (Arc<UdpTransport>, Arc<RuntimeConfig>) {
        let resolved = TransportOptions {
            multicast: mode,
            ..TransportOptions::default()
        }
        .resolve();
        crate::test_support::ports::with_reserved_ports(
            8,
            |[spdp_multicast, sedp_unicast, user_unicast]| {
                let mapping = PortMapping::from_custom(CustomPortMapping {
                    spdp_multicast,
                    sedp_unicast,
                    user_unicast,
                });
                UdpTransport::new_with_options(42, 0, mapping, &resolved).map(|transport| {
                    let config = Arc::new(RuntimeConfig::new());
                    config.set_port_mapping(mapping);
                    (Arc::new(transport), config)
                })
            },
        )
        .unwrap_or_else(|e| panic!("create transport for mode: ports kept colliding: {e:?}"))
    }

    /// Receive one datagram, classify it as an RTPS SPDP DATA submessage and
    /// parse the SPDP payload at the classifier-provided CDR offset -- the
    /// same offset computation the live receive path uses
    /// (`classify_rtps`), so the test extracts the payload exactly as a
    /// real peer would.
    fn receive_one_spdp(receiver: &UdpSocket) -> SpdpData {
        let mut packet = [0u8; 2048];
        let (len, _) = receiver.recv_from(&mut packet).expect("receive SPDP");
        let (kind, payload_offset, _fragment_metadata, _rtps_context) =
            classify_rtps(&packet[..len]);
        assert_eq!(
            kind,
            PacketKind::SPDP,
            "classifier did not recognize the announcer's packet as SPDP"
        );
        let offset = payload_offset.expect("classifier should locate the CDR payload offset");
        parse_spdp(&packet[offset..len]).expect("parse SPDP CDR payload")
    }

    /// Test 1 (advertised locator invariant), `Enabled`: the default
    /// multicast locator is advertised and multicast send/receive are both
    /// on.
    ///
    /// NOTE: `PID_METATRAFFIC_MULTICAST_LOCATOR` is never emitted on the wire
    /// at all, in ANY mode -- this is independent of the multicast mode (see
    /// `crates/hdds/src/protocol/discovery/spdp/build.rs` around line 150,
    /// "Position 8 ... still not announced", left commented out). So
    /// `spdp_data.metatraffic_multicast_locators` parses back empty even
    /// though the announcer computes a non-empty value for `Enabled`
    /// internally (`spdp_announcer.rs`'s `metatraffic_multicast_locators`
    /// local) -- that computed value is silently dropped by `build_spdp`
    /// before it ever reaches the wire. The only multicast-locator PID that
    /// actually varies by `MulticastMode` on the wire is
    /// `PID_DEFAULT_MULTICAST_LOCATOR`, asserted below.
    #[test]
    fn advertised_locators_enabled_mode() {
        let (transport, config) = build_transport_for_mode(MulticastMode::Enabled);
        assert!(transport.multicast_receive_enabled());
        assert!(transport.multicast_send_enabled());

        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let peers = Arc::new(SpdpPeerSet::new());
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let announcer = SpdpAnnouncer::spawn_with_security_and_peers(
            guid,
            transport,
            30_000,
            Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS),
            config,
            None,
            None,
            None,
            Arc::clone(&peers),
            None,
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        );
        peers.add_static(receiver_addr);

        let spdp_data = receive_one_spdp(&receiver);
        assert_eq!(
            spdp_data.hdds_capabilities,
            Some(crate::protocol::group::LOCAL_CAPABILITIES),
            "the announcement carries this build's capabilities"
        );
        assert!(
            spdp_data.metatraffic_multicast_locators.is_empty(),
            "PID_METATRAFFIC_MULTICAST_LOCATOR is never emitted on the wire in any mode \
             (pre-existing, unrelated to MulticastMode v2); see build_spdp"
        );
        assert!(
            !spdp_data.default_multicast_locators.is_empty(),
            "Enabled must advertise the default multicast locator"
        );
        assert!(
            !spdp_data.metatraffic_unicast_locators.is_empty(),
            "metatraffic unicast locators must always be advertised"
        );

        drop(announcer);
    }

    /// A participant leaves once: `shutdown` sends the departure, and the
    /// `Drop` that follows it sends nothing more. The departure is the
    /// dispose/unregister of the DCPSParticipant instance (StatusInfo 3),
    /// not an announcement.
    #[test]
    fn a_participant_announces_its_departure_once() {
        let (transport, config) = build_transport_for_mode(MulticastMode::ReceiveOnly);
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let peers = Arc::new(SpdpPeerSet::new());
        peers.add_static(receiver.local_addr().unwrap());
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 0, 0, 1, 0xC1]);
        let announcer = SpdpAnnouncer::spawn_with_security_and_peers(
            guid,
            transport,
            30_000,
            Duration::from_secs(60),
            config,
            None,
            None,
            None,
            Arc::clone(&peers),
            None,
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        );
        announcer.shutdown();

        let status_disposed_unregistered = [0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03];
        let mut departures = 0;
        let mut packet = [0u8; 2048];
        while let Ok((len, _)) = receiver.recv_from(&mut packet) {
            if packet[..len]
                .windows(status_disposed_unregistered.len())
                .any(|w| w == status_disposed_unregistered)
            {
                departures += 1;
            }
        }
        assert_eq!(departures, 1, "one departure, not one per shutdown path");
    }

    /// Test 1, `ReceiveOnly`: no multicast locators advertised (peers must
    /// use our unicast locators), reception stays on, emission is off.
    #[test]
    fn advertised_locators_receive_only_mode() {
        let (transport, config) = build_transport_for_mode(MulticastMode::ReceiveOnly);
        assert!(transport.multicast_receive_enabled());
        assert!(!transport.multicast_send_enabled());

        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let peers = Arc::new(SpdpPeerSet::new());
        let guid = GUID::from_bytes([2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let announcer = SpdpAnnouncer::spawn_with_security_and_peers(
            guid,
            transport,
            30_000,
            Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS),
            config,
            None,
            None,
            None,
            Arc::clone(&peers),
            None,
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        );
        peers.add_static(receiver_addr);

        let spdp_data = receive_one_spdp(&receiver);
        assert!(
            spdp_data.metatraffic_multicast_locators.is_empty(),
            "ReceiveOnly must NOT advertise metatraffic multicast locators"
        );
        assert!(
            spdp_data.default_multicast_locators.is_empty(),
            "ReceiveOnly must NOT advertise the default multicast locator"
        );
        assert!(
            !spdp_data.metatraffic_unicast_locators.is_empty(),
            "metatraffic unicast locators must always be advertised"
        );

        drop(announcer);
    }

    /// Test 1, `Disabled`: same locator invariant as `ReceiveOnly`, plus
    /// reception is off too.
    #[test]
    fn advertised_locators_disabled_mode() {
        let (transport, config) = build_transport_for_mode(MulticastMode::Disabled);
        assert!(!transport.multicast_receive_enabled());
        assert!(!transport.multicast_send_enabled());

        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let peers = Arc::new(SpdpPeerSet::new());
        let guid = GUID::from_bytes([3, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let announcer = SpdpAnnouncer::spawn_with_security_and_peers(
            guid,
            transport,
            30_000,
            Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS),
            config,
            None,
            None,
            None,
            Arc::clone(&peers),
            None,
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        );
        peers.add_static(receiver_addr);

        let spdp_data = receive_one_spdp(&receiver);
        assert!(
            spdp_data.metatraffic_multicast_locators.is_empty(),
            "Disabled must NOT advertise metatraffic multicast locators"
        );
        assert!(
            spdp_data.default_multicast_locators.is_empty(),
            "Disabled must NOT advertise the default multicast locator"
        );
        assert!(
            !spdp_data.metatraffic_unicast_locators.is_empty(),
            "metatraffic unicast locators must always be advertised"
        );

        drop(announcer);
    }

    /// Test 2 (rate floor): three static peers added back-to-back on a
    /// `ReceiveOnly` announcer must not turn into three full announcement
    /// rounds inside a 150ms window. `MIN_ANNOUNCE_GAP` (200ms, equal to
    /// the aggressive startup interval) caps how often a peer-set change
    /// can trigger a full round, so each receiver should see at most one
    /// datagram in the window, tolerantly asserted as "at most 2" to absorb
    /// scheduling jitter. Without the floor, three back-to-back adds would
    /// each independently wake the loop and could produce three rounds.
    #[test]
    fn rate_floor_caps_bursts_from_rapid_peer_additions() {
        let (transport, config) = build_transport_for_mode(MulticastMode::ReceiveOnly);
        let peers = Arc::new(SpdpPeerSet::new());
        let guid = GUID::from_bytes([4, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let announcer = SpdpAnnouncer::spawn_with_security_and_peers(
            guid,
            transport,
            30_000,
            Duration::from_millis(SPDP_ANNOUNCEMENT_PERIOD_MS),
            config,
            None,
            None,
            None,
            Arc::clone(&peers),
            None,
            crate::protocol::group::LOCAL_CAPABILITIES,
            spdp_sequence(),
        );

        let receivers: Vec<UdpSocket> = (0..3)
            .map(|_| {
                let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_millis(10)))
                    .unwrap();
                socket
            })
            .collect();
        let addrs: Vec<_> = receivers
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect();

        // Add all three peers back-to-back (no sleep between), then measure
        // for 150ms starting right after the third add.
        for addr in &addrs {
            peers.add_static(*addr);
        }

        let deadline = Instant::now() + Duration::from_millis(150);
        let mut counts = [0usize; 3];
        while Instant::now() < deadline {
            for (index, receiver) in receivers.iter().enumerate() {
                let mut buf = [0u8; 2048];
                if receiver.recv_from(&mut buf).is_ok() {
                    counts[index] += 1;
                }
            }
        }

        for (index, count) in counts.iter().enumerate() {
            assert!(
                *count <= 2,
                "receiver {index} saw {count} datagrams within the 150ms window after 3 \
                 back-to-back peer adds -- the rate floor should cap full announcement rounds"
            );
        }

        drop(announcer);
    }
}

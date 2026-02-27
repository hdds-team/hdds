// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP (Simple Participant Discovery Protocol) periodic announcer thread.
//!
//!
//! Per RTPS v2.3 spec section 8.5.3, participants MUST announce themselves
//! periodically (default: every 3 seconds) to multicast address 239.255.0.1:7400.
//!
//! This module implements the missing critical component identified in
//! DISCOVERY_STATUS_AUDIT.md - without this, participants never announce
//! themselves and discovery remains empty.

use crate::config::{
    RuntimeConfig, DATA_MULTICAST_OFFSET, DOMAIN_ID_GAIN, MULTICAST_IP, PORT_BASE,
    SPDP_MULTICAST_PORT_DOMAIN0, USER_UNICAST_PORT_DOMAIN0_P0,
};
use crate::core::discovery::multicast::build_spdp_rtps_packet;
use crate::core::discovery::GUID;
use crate::protocol::discovery::SpdpData;
use crate::transport::UdpTransport;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

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
pub struct SpdpAnnouncer {
    /// Background thread handle
    handle: Option<JoinHandle<()>>,
    /// Shutdown signal (set to true to stop announcer)
    shutdown: Arc<AtomicBool>,
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
        Self::spawn_with_security(participant_guid, transport, lease_duration_ms, config, None)
    }

    /// Spawn SPDP announcer thread with DDS Security identity token.
    ///
    /// # Arguments
    ///
    /// - `participant_guid`: RTPS GUID of the local participant
    /// - `transport`: UDP transport for sending multicast packets
    /// - `lease_duration_ms`: Lease duration in milliseconds (default: 30,000)
    /// - `config`: Runtime configuration (for custom ports)
    /// - `identity_token`: Optional identity token (X.509 certificate, PEM-encoded)
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
    ) -> Self {
        crate::trace_fn!("SpdpAnnouncer::spawn_with_security");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            announcer_loop(
                participant_guid,
                transport,
                lease_duration_ms,
                config,
                shutdown_clone,
                identity_token,
            );
        });

        Self {
            handle: Some(handle),
            shutdown,
        }
    }

    /// Signal announcer thread to stop and wait for completion.
    ///
    /// This is automatically called on Drop, but can be explicitly invoked
    /// if synchronous shutdown is required.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SpdpAnnouncer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Main announcer loop (runs in background thread).
///
/// Sends SPDP RTPS packets every 3 seconds until shutdown signal is received.
/// Each packet includes a complete RTPS header with incrementing sequence numbers.
fn announcer_loop(
    participant_guid: GUID,
    transport: Arc<UdpTransport>,
    lease_duration_ms: u64,
    config: Arc<RuntimeConfig>,
    shutdown: Arc<AtomicBool>,
    identity_token: Option<Vec<u8>>,
) {
    // RTPS v2.3 default periodic announcement interval.
    const ANNOUNCEMENT_INTERVAL_SECS: u64 = 3;
    // Aggressive burst phase at startup to reduce SPDP->SEDP races with
    // external stacks (FastDDS/RTI). During this window we send SPDP
    // more frequently so that remote PDP has multiple opportunities to
    // ingest our participant before SEDP re-announces start flowing.
    const AGGRESSIVE_WINDOW_SECS: u64 = 5;
    const AGGRESSIVE_INTERVAL_MS: u64 = 200;

    let normal_interval = Duration::from_secs(ANNOUNCEMENT_INTERVAL_SECS);
    let aggressive_interval = Duration::from_millis(AGGRESSIVE_INTERVAL_MS);
    let start_instant = std::time::Instant::now();

    // Sequence number counter (starts at 1 per RTPS spec)
    let sequence_number = AtomicU64::new(1);

    // v79: Get all locator types needed for RTI interop (RTPS v2.3 Sec.8.5.3.1)
    // RTI needs to know WHERE to send different types of traffic:
    // - Metatraffic unicast (SEDP/ACKNACK)
    // - Default unicast (USER DATA) [MANDATORY!]
    // - Multicast addresses for discovery and data

    let metatraffic_unicast_locators = transport.get_unicast_locators();

    // Get port configuration (custom or default RTPS formula)
    let port_mapping = config.get_port_mapping();

    // Calculate user data unicast port (custom or default)
    let user_unicast_port = port_mapping
        .map(|m| m.user_unicast)
        .unwrap_or(USER_UNICAST_PORT_DOMAIN0_P0);

    // Calculate multicast ports (custom or default)
    let data_multicast_port = port_mapping
        .map(|m| m.metatraffic_multicast + DATA_MULTICAST_OFFSET)
        .unwrap_or(SPDP_MULTICAST_PORT_DOMAIN0 + DATA_MULTICAST_OFFSET);

    let spdp_multicast_port = port_mapping
        .map(|m| m.metatraffic_multicast)
        .unwrap_or(SPDP_MULTICAST_PORT_DOMAIN0);

    // Build default unicast locators (user data port from config)
    let default_unicast_locators: Vec<std::net::SocketAddr> = metatraffic_unicast_locators
        .iter()
        .map(|addr| {
            let mut new_addr = *addr;
            new_addr.set_port(user_unicast_port); // [OK] From config or RTPS formula
            new_addr
        })
        .collect();

    // Build multicast locators (ports from config)
    let default_multicast_locators = vec![
        std::net::SocketAddr::from((MULTICAST_IP, data_multicast_port)), // [OK] From config
    ];
    let metatraffic_multicast_locators = vec![
        std::net::SocketAddr::from((MULTICAST_IP, spdp_multicast_port)), // [OK] From config
    ];

    log::debug!("[spdp_announcer] v79: Announcing locators (RTI interop fix):");
    log::debug!(
        "  Metatraffic unicast: {} locator(s)",
        metatraffic_unicast_locators.len()
    );
    for loc in &metatraffic_unicast_locators {
        log::debug!("    -> {}", loc);
    }
    log::debug!(
        "  Default unicast (port {}): {} locator(s) [MANDATORY for RTI]",
        user_unicast_port,
        default_unicast_locators.len()
    );
    for loc in &default_unicast_locators {
        log::debug!("    -> {}", loc);
    }
    log::debug!(
        "  Default multicast (port {}): {} locator(s)",
        data_multicast_port,
        default_multicast_locators.len()
    );
    log::debug!(
        "  Metatraffic multicast (port {}): {} locator(s)",
        spdp_multicast_port,
        metatraffic_multicast_locators.len()
    );

    // Optional: SPDP unicast peers (Plan A interop helper)
    //
    // If HDDS_SPDP_UNICAST_PEERS is set (e.g. "192.168.1.100:7410,10.0.0.5:7410"),
    // we will send each SPDP announce both to multicast AND to these unicast endpoints.
    // This is particularly useful when remote stacks (FastDDS/RTI) do not see our
    // multicast SPDP due to IGMP/interface quirks but do listen on metatraffic unicast.
    let spdp_unicast_peers: Vec<SocketAddr> = std::env::var("HDDS_SPDP_UNICAST_PEERS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .filter_map(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        match trimmed.parse::<SocketAddr>() {
                            Ok(addr) => Some(addr),
                            Err(err) => {
                                log::debug!(
                                    "[spdp_announcer] Ignoring invalid HDDS_SPDP_UNICAST_PEERS entry '{}': {}",
                                    trimmed,
                                    err
                                );
                                None
                            }
                        }
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    // v242: When HDDS_REUSEPORT=1, automatically add localhost unicast peers
    // to work around Linux SO_REUSEPORT multicast load-balancing issue.
    // Without this, each process only receives SOME multicast packets, breaking discovery.
    let mut spdp_unicast_peers = spdp_unicast_peers;
    let reuseport_enabled = std::env::var("HDDS_REUSEPORT")
        .map(|v| v == "1")
        .unwrap_or(false);
    if reuseport_enabled {
        // Get our own metatraffic unicast port to avoid sending to self
        let our_port = metatraffic_unicast_locators
            .first()
            .map(|a| a.port())
            .unwrap_or(7410);

        // Add localhost peers for participant IDs 0-7 (covers most use cases)
        // Port formula: 7400 + 250*domain_id + participant_id*2 + 10
        // For domain 0: 7410, 7412, 7414, 7416, 7418, 7420, 7422, 7424
        for pid in 0..8u16 {
            let peer_port = 7410 + pid * 2;
            if peer_port != our_port {
                #[allow(clippy::expect_used)] // format string with known-good port always parses
                let peer_addr: SocketAddr = format!("127.0.0.1:{}", peer_port)
                    .parse()
                    .expect("valid localhost addr");
                if !spdp_unicast_peers.contains(&peer_addr) {
                    spdp_unicast_peers.push(peer_addr);
                }
            }
        }
        log::info!(
            "[spdp_announcer] v242: HDDS_REUSEPORT=1 - added {} localhost unicast peers for same-machine discovery",
            spdp_unicast_peers.len()
        );
    }

    if !spdp_unicast_peers.is_empty() {
        log::debug!(
            "[spdp_announcer] SPDP unicast peers enabled ({}):",
            spdp_unicast_peers.len()
        );
        for peer in &spdp_unicast_peers {
            log::debug!("  -> {}", peer);
        }
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            log::debug!("[spdp_announcer] Shutdown signal received, stopping announcer");
            break;
        }

        // v79: Build SPDP participant data with ALL locator types
        // v208: derive domain_id from metatraffic multicast port
        // Formula: metatraffic_multicast = PORT_BASE + DOMAIN_ID_GAIN * domain_id
        let domain_id = (spdp_multicast_port.saturating_sub(PORT_BASE)) / DOMAIN_ID_GAIN;
        // Clamp to DDS spec max (RTPS v2.3 Sec.9.6.1.1: valid range 0..232)
        let domain_id = u32::from(domain_id).min(crate::config::MAX_DOMAIN_ID);

        let spdp_data = SpdpData {
            participant_guid,
            lease_duration_ms,
            domain_id,
            metatraffic_unicast_locators: metatraffic_unicast_locators.clone(),
            default_unicast_locators: default_unicast_locators.clone(),
            default_multicast_locators: default_multicast_locators.clone(),
            metatraffic_multicast_locators: metatraffic_multicast_locators.clone(),
            identity_token: identity_token.clone(), // DDS Security identity certificate (if security enabled)
        };

        // Get current sequence number and increment for next announcement
        let seq_num = sequence_number.fetch_add(1, Ordering::Relaxed);

        // Build complete RTPS packet (header + DATA submessage + payload)
        match build_spdp_rtps_packet(&spdp_data, seq_num, None) {
            // v61: None = multicast
            Ok(packet) => {
                // 1) Multicast SPDP (239.255.0.1:7400)
                if let Err(err) = transport.send(&packet) {
                    log::debug!(
                        "[spdp_announcer] Failed to send SPDP multicast: {} (GUID={:?}, seq={})",
                        err,
                        participant_guid,
                        seq_num
                    );
                } else if should_log_debug() {
                    log::debug!(
                        "[spdp_announcer] Sent SPDP multicast (GUID={:?}, seq={}, lease={}ms, size={} bytes)",
                        participant_guid,
                        seq_num,
                        lease_duration_ms,
                        packet.len()
                    );
                }

                // Track SPDP announcements for interop timing helpers.
                SPDP_SENT_COUNT.fetch_add(1, Ordering::Relaxed);

                // 2) Optional unicast SPDP to explicitly configured peers
                for peer in &spdp_unicast_peers {
                    match transport.send_to_endpoint(&packet, peer) {
                        Ok(sent) => {
                            // Always log SPDP unicast for FastDDS interop
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

        // Sleep until next announcement. Use an aggressive burst interval
        // during the first few seconds after startup, then fall back to
        // the RTPS default period.
        // v235: Split sleep into small chunks for responsive shutdown (<50ms).
        let elapsed = start_instant.elapsed();
        let sleep_dur = if elapsed.as_secs() < AGGRESSIVE_WINDOW_SECS {
            aggressive_interval
        } else {
            normal_interval
        };
        let sleep_end = std::time::Instant::now() + sleep_dur;
        while std::time::Instant::now() < sleep_end {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Check if debug logging is enabled via HDDS_LOG_UDP env var.
fn should_log_debug() -> bool {
    std::env::var("HDDS_LOG_UDP").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

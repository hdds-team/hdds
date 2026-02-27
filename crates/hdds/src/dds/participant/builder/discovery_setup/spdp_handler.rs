// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP packet handler.
//!
//! Handles SPDP (Simple Participant Discovery Protocol) packets including:
//! - SPDP parsing (full and partial)
//! - Metatraffic locator inference
//! - Dialect-specific discovery handshake (via DialectEncoder trait)
//! - SEDP re-announcements to unicast locators
//!
//! # Architecture
//!
//! This handler is vendor-neutral. Vendor-specific discovery handshake
//! behavior (e.g., RTI's service-request ACKNACKs) is encapsulated in
//! the `DialectEncoder::build_discovery_handshake()` trait method.

use crate::core::discovery::{
    multicast::{
        build_heartbeat_submessage, build_heartbeat_submessage_final, build_sedp_rtps_packet,
        build_spdp_rtps_packet, rtps_packet::SEDP_HEARTBEAT_COUNT, DiscoveryFsm, SedpEndpointKind,
    },
    spdp_announcer::SPDP_SENT_COUNT,
};
use crate::protocol::dialect::{get_encoder, Dialect};
use crate::protocol::discovery::constants::{CDR2_LE, CDR_LE, PID_METATRAFFIC_UNICAST_LOCATOR};
use crate::protocol::discovery::{parse_spdp, parse_spdp_partial, ParseError, SedpData, SpdpData};
use crate::transport::UdpTransport;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};

use super::super::entity_registry::SedpAnnouncementsCache;

// =============================================================================
// SEDP Retry Flood Prevention (v125, v210)
// =============================================================================
// Problem: Each SPDP received spawns a NEW retry thread without deduplication,
// causing 10 SPDP x 120 retries = 1200+ SEDP sends. RTI rejects this flood with
// "subscriptionReaderListenerOnSampleLost" errors.
//
// Solution: RetryGuard RAII pattern ensures only ONE retry thread per peer.
// Fix: SEDP retry flood deduplication (v232)
//
// v210: After a retry cycle completes, the peer is moved to COMPLETED_PEERS.
// Subsequent SPDPs from the same peer will NOT trigger re-announce.
// This prevents continuous SEDP DATA + non-Final HEARTBEAT floods that block
// FastDDS from starting its own SEDP writer (observed in log14).

/// Tracks active retry threads by peer GUID prefix.
/// Prevents multiple threads from retrying SEDP to the same peer.
fn active_retries() -> &'static Mutex<HashSet<[u8; 12]>> {
    static ACTIVE_RETRIES: OnceLock<Mutex<HashSet<[u8; 12]>>> = OnceLock::new();
    ACTIVE_RETRIES.get_or_init(|| Mutex::new(HashSet::new()))
}

/// v210: Tracks peers that completed at least one SEDP reannounce cycle.
/// Peers in this set will NOT be re-announced on subsequent SPDPs.
fn completed_peers() -> &'static Mutex<HashSet<[u8; 12]>> {
    static COMPLETED_PEERS: OnceLock<Mutex<HashSet<[u8; 12]>>> = OnceLock::new();
    COMPLETED_PEERS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// RAII guard for SEDP retry thread deduplication.
///
/// Ensures only one retry thread runs per peer. When dropped, removes the peer
/// from ACTIVE_RETRIES and adds it to COMPLETED_PEERS to suppress future re-announce.
struct RetryGuard {
    peer_prefix: [u8; 12],
}

impl RetryGuard {
    /// Try to acquire exclusive retry rights for a peer.
    ///
    /// Returns `Some(RetryGuard)` if no other thread is retrying to this peer,
    /// `None` if a retry is already in progress OR already completed.
    fn try_acquire(peer_prefix: [u8; 12]) -> Option<Self> {
        // v210: Check completed peers first — skip if already announced
        if let Ok(completed) = completed_peers().lock() {
            if completed.contains(&peer_prefix) {
                return None;
            }
        }
        let mut set = active_retries().lock().ok()?;
        if set.contains(&peer_prefix) {
            return None;
        }
        set.insert(peer_prefix);
        Some(Self { peer_prefix })
    }
}

impl Drop for RetryGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = active_retries().lock() {
            set.remove(&self.peer_prefix);
        }
        // v210: Mark peer as completed to suppress future re-announce
        if let Ok(mut completed) = completed_peers().lock() {
            completed.insert(self.peer_prefix);
        }
    }
}

/// Handle SPDP packet.
///
/// # Arguments
/// - `payload`: Full RTPS packet (including headers)
/// - `cdr_offset`: CDR payload offset within the packet (computed by classifier)
/// - `src_addr`: Source socket address (for metatraffic locator inference)
/// - `our_guid_prefix`: Our participant GUID prefix (for loopback filtering)
/// - `transport`: UDP transport for sending ACKNACKs and SEDP re-announcements
/// - `fsm`: Discovery FSM for state updates
/// - `sedp_cache`: SEDP announcements cache for re-announcements
/// - `dialect_detector`: Dialect detector for SPDP packet monitoring (Phase 1.6)
/// - `port_mapping`: Port mapping for RTI metatraffic locator inference
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_spdp_packet(
    payload: &[u8],
    cdr_offset: usize,
    src_addr: SocketAddr,
    our_guid_prefix: [u8; 12],
    transport: Arc<UdpTransport>,
    fsm: Arc<DiscoveryFsm>,
    sedp_cache: SedpAnnouncementsCache,
    dialect_detector: Arc<
        std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>,
    >,
    port_mapping: crate::transport::PortMapping,
) {
    log::debug!(
        "[callback-builder] v124: Received SPDP packet, len={}, cdr_offset={}",
        payload.len(),
        cdr_offset
    );

    // v231: Extract GUID prefix from RTPS header to detect self-loopback BEFORE dialect detection.
    // RTPS header: bytes 8-19 contain the GUID prefix (after magic + version + vendor).
    // Without this check, dialect detector locks to Hdds on self-SPDP before seeing FastDDS.
    let packet_guid_prefix: Option<[u8; 12]> = if payload.len() >= 20 {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&payload[8..20]);
        Some(prefix)
    } else {
        None
    };

    let is_self_packet = packet_guid_prefix == Some(our_guid_prefix);

    // Phase 1.6: Feed full RTPS packet to dialect detector (monitoring passif)
    // and remember detected dialect for SEDP encoding.
    //
    // HDDS-first strategy:
    // - Default = Dialect::Hdds (native mode, fast discovery)
    // - If interop_mode enabled (non-HDDS vendor detected) -> use detected dialect
    let mut encoding_dialect = Dialect::Hdds; // Default: HDDS native mode
    let mut is_interop_mode = false;

    if let Ok(mut detector) = dialect_detector.lock() {
        // v231: Skip dialect detection for self-loopback packets.
        // This prevents locking to Hdds before receiving packets from remote peers.
        if !is_self_packet {
            if let Some(detected_dialect) = detector.process_packet(payload, src_addr) {
                let confidence = detector.confidence();
                log::debug!(
                    "[DIALECT-DETECTOR] [OK] Dialect detected: {:?} (confidence: {}%)",
                    detected_dialect,
                    confidence
                );
            }
        } else {
            log::trace!("[DIALECT-DETECTOR] Skipping self-loopback packet");
        }

        is_interop_mode = detector.is_interop_mode();
        if is_interop_mode {
            // v196: In interop mode with mixed vendors (HDDS + foreign), always use Hybrid.
            // Hybrid is the conservative RTPS 2.3 encoding that works with all vendors.
            // Previously we used locked_dialect() which could be FastDDS, breaking HDDS peers.
            encoding_dialect = Dialect::Hybrid;
        } else if let Some(locked) = detector.locked_dialect() {
            // Native mode: should be Dialect::Hdds
            encoding_dialect = locked;
        }
    }

    log::trace!(
        "[SPDP] encoding_dialect={:?}, interop_mode={}",
        encoding_dialect,
        is_interop_mode
    );

    // v124: Extract CDR payload using offset from classifier
    let cdr_payload = if cdr_offset < payload.len() {
        log::debug!(
            "[spdp] v124: Extracting CDR payload at offset {}",
            cdr_offset
        );
        &payload[cdr_offset..]
    } else {
        log::debug!(
            "[spdp] v124: Invalid offset {}, using full payload",
            cdr_offset
        );
        payload
    };

    // Prefer full SPDP parse to extract unicast locators; fallback to partial on fragments
    let spdp_parse = match parse_spdp(cdr_payload) {
        Ok(full) => Ok(full),
        Err(ParseError::TruncatedData) => parse_spdp_partial(cdr_payload),
        Err(e) => Err(e),
    };

    match spdp_parse {
        Ok(mut spdp_data) => {
            log::debug!(
                "[callback] [OK] SPDP parsed (via classifier): GUID={:?}",
                spdp_data.participant_guid
            );

            // First, try to recover metatraffic_unicast locator directly from the
            // SPDP CDR payload. Some vendors (FastDDS) embed a proper
            // PID_METATRAFFIC_UNICAST_LOCATOR but our generic SPDP parser may
            // miss it in corner cases. As a safety net, scan the raw payload.
            if spdp_data.metatraffic_unicast_locators.is_empty() {
                if let Some(loc) = extract_metatraffic_unicast_from_cdr(cdr_payload) {
                    log::debug!(
                        "[SPDP-RECOVER] [OK] Recovered metatraffic_unicast locator from CDR: {}",
                        loc
                    );
                    spdp_data.metatraffic_unicast_locators.push(loc);
                }
            }

            // Fallback: infer metatraffic_unicast locator from source IP if still empty.
            if spdp_data.metatraffic_unicast_locators.is_empty() {
                let inferred_port = port_mapping.metatraffic_unicast;
                let inferred_locator = SocketAddr::new(src_addr.ip(), inferred_port);
                spdp_data
                    .metatraffic_unicast_locators
                    .push(inferred_locator);
                log::debug!(
                    "[SPDP-INFER] [OK] Inferred metatraffic_unicast locator from source: {} (port from config)",
                    inferred_locator
                );
            }

            fsm.handle_spdp(spdp_data.clone());

            // v61 Blocker #2: Send service-request ACKNACK to RTI participants
            // RTI expects ACKNACK responses to service-request endpoints (0x00020082/87)
            // before sending SEDP publications
            let peer_guid_prefix = {
                let bytes = spdp_data.participant_guid.as_bytes();
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&bytes[..12]);
                prefix
            };

            // v90: CRITICAL - Skip our own SPDP multicast loopback!
            // Without this, HDDS sends ACKNACKs to itself instead of RTI
            if peer_guid_prefix == our_guid_prefix {
                log::debug!("[SPDP-FILTER] [!]  Ignoring our own SPDP (multicast loopback)");
                return; // Exit handler early
            }

            // Get dialect encoder for this peer
            let encoder = get_encoder(encoding_dialect);

            // v132: Send immediate SPDP unicast response BEFORE handshake HEARTBEATs.
            //
            // FastDDS reference (frames 11-12):
            // - Frame 11: Peer sends SPDP multicast
            // - Frame 12 (+0.5ms): FastDDS sends SPDP unicast to peer metatraffic_unicast
            // - Frame 15-17: FastDDS sends discovery HEARTBEATs
            // - Frame 18+: Peer responds immediately
            //
            // Without immediate SPDP, some implementations (RTI) wait for periodic SPDP
            // (~200ms) before processing HEARTBEATs, causing 60+ second discovery delays.
            if encoder.requires_immediate_spdp_response()
                && !spdp_data.metatraffic_unicast_locators.is_empty()
            {
                send_immediate_spdp_unicast(
                    &our_guid_prefix,
                    &peer_guid_prefix,
                    &spdp_data.metatraffic_unicast_locators,
                    &transport,
                    port_mapping,
                    encoder.name(),
                );
            }

            // v176: CRITICAL FIX - Pre-allocate SEDP sequence numbers BEFORE building handshake.
            //
            // Race condition: OpenDDS handshake sends HEARTBEATs with lastSeq from atomic counter.
            // If we build handshake BEFORE spawning the retry thread, lastSeq=0 is read.
            // Then the retry thread allocates seq 1,2,3... for DATA(r).
            // OpenDDS receives HEARTBEAT(lastSeq=0) then DATA(r)(seq=1) -> CONFUSED!
            //
            // Fix: Pre-allocate sequence numbers synchronously, THEN build handshake.
            // The handshake will read the correct lastSeq values from the atomic counters.
            let pre_allocated_endpoints = preallocate_sedp_sequence_numbers(&sedp_cache);

            // Send dialect-specific discovery handshake packets (if required)
            // The encoder knows what handshake its dialect needs (e.g., RTI needs HEARTBEATs)
            // NOTE: v176 - Handshake HEARTBEATs now read correct lastSeq from pre-allocated counters
            if let Some(handshake_packets) =
                encoder.build_discovery_handshake(&our_guid_prefix, &peer_guid_prefix)
            {
                for (idx, packet) in handshake_packets.iter().enumerate() {
                    // Prefer UNICAST to peer metatraffic_unicast locators; fallback to multicast
                    if !spdp_data.metatraffic_unicast_locators.is_empty() {
                        for ep in &spdp_data.metatraffic_unicast_locators {
                            match transport.send_to_endpoint(packet, ep) {
                                Ok(_) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE] [OK] Sent packet {} (unicast) to {} [{} dialect]",
                                    idx + 1, ep, encoder.name()
                                ),
                                Err(e) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE] Failed to send packet {}: {} to {}",
                                    idx + 1, e, ep
                                ),
                            }
                        }
                    } else if let Err(e) = transport.send(packet) {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE] Failed to send packet {} (multicast): {}",
                            idx + 1,
                            e
                        );
                    } else {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE] [OK] Sent packet {} (multicast) [{} dialect]",
                            idx + 1,
                            encoder.name()
                        );
                    }
                }
            }

            // Unicast SEDP re-announce to this peer's metatraffic_unicast locators (if available)
            // v176: Pass pre-allocated endpoints to avoid double-allocation
            send_sedp_reannouncements_with_prealloc(
                &spdp_data,
                &our_guid_prefix,
                &peer_guid_prefix,
                transport,
                pre_allocated_endpoints,
                "[SEDP-REANNOUNCE]",
                encoding_dialect,
            );
        }
        Err(e) => {
            log::debug!("[callback] SPDP parse failed (via classifier): {:?}", e);
        }
    }
}

/// Handle SPDP from reassembled fragments.
///
/// # Arguments
/// - `complete_payload`: Complete reassembled SPDP payload
/// - `src_addr`: Source socket address (for metatraffic locator inference)
/// - `our_guid_prefix`: Our participant GUID prefix (for loopback filtering)
/// - `transport`: UDP transport for sending ACKNACKs and SEDP re-announcements
/// - `fsm`: Discovery FSM for state updates
/// - `sedp_cache`: SEDP announcements cache for re-announcements
/// - `dialect_detector`: Dialect detector for SPDP packet monitoring (Phase 1.6)
/// - `port_mapping`: Port mapping for RTI metatraffic locator inference
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_spdp_from_fragments(
    complete_payload: &[u8],
    src_addr: SocketAddr,
    our_guid_prefix: [u8; 12],
    transport: Arc<UdpTransport>,
    fsm: Arc<DiscoveryFsm>,
    sedp_cache: SedpAnnouncementsCache,
    dialect_detector: Arc<
        std::sync::Mutex<crate::core::discovery::multicast::dialect_detector::DialectDetector>,
    >,
    port_mapping: crate::transport::PortMapping,
) {
    // v231: Extract GUID prefix from RTPS header to detect self-loopback BEFORE dialect detection.
    // RTPS header: bytes 8-19 contain the GUID prefix (after magic + version + vendor).
    let packet_guid_prefix: Option<[u8; 12]> = if complete_payload.len() >= 20 {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&complete_payload[8..20]);
        Some(prefix)
    } else {
        None
    };

    let is_self_packet = packet_guid_prefix == Some(our_guid_prefix);

    // Phase 1.6: Feed reassembled SPDP packet to dialect detector
    // and remember detected dialect for SEDP encoding.
    //
    // HDDS-first strategy (same as non-fragment path):
    // - Default = Dialect::Hdds (native mode, fast discovery)
    // - If interop_mode enabled (non-HDDS vendor detected) -> use detected dialect
    let mut encoding_dialect = Dialect::Hdds; // Default: HDDS native mode
    let mut is_interop_mode = false;

    if let Ok(mut detector) = dialect_detector.lock() {
        // v231: Skip dialect detection for self-loopback packets.
        if !is_self_packet {
            if let Some(detected_dialect) = detector.process_packet(complete_payload, src_addr) {
                let confidence = detector.confidence();
                log::debug!(
                    "[DIALECT-DETECTOR] [OK] Dialect detected (from fragments): {:?} (confidence: {}%)",
                    detected_dialect,
                    confidence
                );
            }
        } else {
            log::trace!("[DIALECT-DETECTOR] Skipping self-loopback fragment packet");
        }

        is_interop_mode = detector.is_interop_mode();
        if is_interop_mode {
            // v196: In interop mode with mixed vendors (HDDS + foreign), always use Hybrid.
            // Hybrid is the conservative RTPS 2.3 encoding that works with all vendors.
            // Previously we used locked_dialect() which could be FastDDS, breaking HDDS peers.
            encoding_dialect = Dialect::Hybrid;
        } else if let Some(locked) = detector.locked_dialect() {
            // Native mode: should be Dialect::Hdds
            encoding_dialect = locked;
        }
    }

    log::trace!(
        "[SPDP-FRAG] encoding_dialect={:?}, interop_mode={}",
        encoding_dialect,
        is_interop_mode
    );

    // v122: Extract CDR payload from RTPS packet (same algorithm as non-fragment path)
    let cdr_payload = if complete_payload.len() >= 20 && &complete_payload[0..4] == b"RTPS" {
        let mut offset = 20;
        let mut found_payload: Option<&[u8]> = None;

        for _i in 0..10 {
            if offset + 4 > complete_payload.len() {
                break;
            }

            let submsg_id = complete_payload[offset];
            let flags = complete_payload[offset + 1];
            let octets_to_next = if flags & 0x01 != 0 {
                u16::from_le_bytes([complete_payload[offset + 2], complete_payload[offset + 3]])
            } else {
                u16::from_be_bytes([complete_payload[offset + 2], complete_payload[offset + 3]])
            } as usize;

            if submsg_id == 0x15 || submsg_id == 0x16 {
                let payload_start = if submsg_id == 0x16 {
                    offset + 24
                } else if offset + 8 <= complete_payload.len() {
                    let octets_to_inline_qos = if flags & 0x01 != 0 {
                        u16::from_le_bytes([
                            complete_payload[offset + 6],
                            complete_payload[offset + 7],
                        ])
                    } else {
                        u16::from_be_bytes([
                            complete_payload[offset + 6],
                            complete_payload[offset + 7],
                        ])
                    } as usize;

                    if octets_to_inline_qos > 0 {
                        offset + octets_to_inline_qos
                    } else {
                        offset + 24
                    }
                } else {
                    offset + 24
                };

                if payload_start < complete_payload.len() {
                    found_payload = Some(&complete_payload[payload_start..]);
                    log::debug!(
                        "[spdp-frag] v122: Extracted CDR payload from reassembled RTPS at offset {}",
                        payload_start
                    );
                }
                break;
            }

            if octets_to_next == 0 {
                break;
            }
            offset += 4 + octets_to_next;
        }

        found_payload.unwrap_or_else(|| {
            log::debug!("[spdp-frag] v122: No DATA/DATA_FRAG found, using full payload");
            complete_payload
        })
    } else {
        log::debug!("[spdp-frag] v122: Not an RTPS packet, using full payload");
        complete_payload
    };

    match parse_spdp(cdr_payload) {
        Ok(mut spdp_data) => {
            log::debug!(
                "[callback] [OK] SPDP parsed from reassembled fragments: GUID={:?}",
                spdp_data.participant_guid
            );

            // RTI workaround: infer metatraffic_unicast locator from source IP if not in SPDP
            if spdp_data.metatraffic_unicast_locators.is_empty() {
                let inferred_port = port_mapping.metatraffic_unicast;
                let inferred_locator = SocketAddr::new(src_addr.ip(), inferred_port);
                spdp_data
                    .metatraffic_unicast_locators
                    .push(inferred_locator);
                log::debug!(
                    "[SPDP-INFER] [OK] Inferred metatraffic_unicast locator from source: {} (port from config)",
                    inferred_locator
                );
            }

            fsm.handle_spdp(spdp_data.clone());

            // Service-request ACKNACK (same as non-fragment path)
            let peer_guid_prefix = {
                let bytes = spdp_data.participant_guid.as_bytes();
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&bytes[..12]);
                prefix
            };

            // v90: CRITICAL - Skip our own SPDP multicast loopback!
            if peer_guid_prefix == our_guid_prefix {
                log::debug!(
                    "[SPDP-FILTER] [!]  Ignoring our own SPDP fragment (multicast loopback)"
                );
                return; // Exit handler early
            }

            // Get dialect encoder for this peer
            let encoder = get_encoder(encoding_dialect);

            // v132: Send immediate SPDP unicast response BEFORE handshake HEARTBEATs.
            // (Same logic as non-fragment path)
            if encoder.requires_immediate_spdp_response()
                && !spdp_data.metatraffic_unicast_locators.is_empty()
            {
                send_immediate_spdp_unicast(
                    &our_guid_prefix,
                    &peer_guid_prefix,
                    &spdp_data.metatraffic_unicast_locators,
                    &transport,
                    port_mapping,
                    encoder.name(),
                );
            }

            // Send dialect-specific discovery handshake packets (if required)
            // The encoder knows what handshake its dialect needs (e.g., RTI needs HEARTBEATs)
            if let Some(handshake_packets) =
                encoder.build_discovery_handshake(&our_guid_prefix, &peer_guid_prefix)
            {
                for (idx, packet) in handshake_packets.iter().enumerate() {
                    if !spdp_data.metatraffic_unicast_locators.is_empty() {
                        for ep in &spdp_data.metatraffic_unicast_locators {
                            match transport.send_to_endpoint(packet, ep) {
                                Ok(_) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE-FRAG] [OK] Sent packet {} (unicast) to {} [{} dialect]",
                                    idx + 1, ep, encoder.name()
                                ),
                                Err(e) => log::debug!(
                                    "[DISCOVERY-HANDSHAKE-FRAG] Failed to send packet {}: {} to {}",
                                    idx + 1, e, ep
                                ),
                            }
                        }
                    } else if let Err(e) = transport.send(packet) {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE-FRAG] Failed to send packet {} (multicast): {}",
                            idx + 1,
                            e
                        );
                    } else {
                        log::debug!(
                            "[DISCOVERY-HANDSHAKE-FRAG] [OK] Sent packet {} (multicast) [{} dialect]",
                            idx + 1,
                            encoder.name()
                        );
                    }
                }
            }

            // Unicast SEDP re-announce (if we have peer locators)
            send_sedp_reannouncements(
                &spdp_data,
                &our_guid_prefix,
                &peer_guid_prefix,
                transport,
                sedp_cache,
                "[SEDP-REANNOUNCE-FRAG]",
                encoding_dialect,
            );
        }
        Err(e) => {
            log::debug!(
                "[callback] SPDP parse failed on reassembled payload: {:?}",
                e
            );
        }
    }
}

/// Type alias for pre-allocated SEDP endpoints with sequence numbers.
/// Vec of (SedpData, SedpEndpointKind, seq_num).
type PreallocatedEndpoints = Vec<(SedpData, SedpEndpointKind, u64)>;

/// v176: Pre-allocate SEDP sequence numbers synchronously.
///
/// This function reads the SEDP cache and allocates sequence numbers from the
/// per-writer atomic counters. By calling this BEFORE building handshake HEARTBEATs,
/// the heartbeats will read the correct lastSeq values from the counters.
///
/// # Arguments
/// - `sedp_cache`: SEDP announcements cache
///
/// # Returns
/// Vector of (SedpData, SedpEndpointKind, seq_num) with pre-allocated sequence numbers.
/// Empty vector if cache is empty.
fn preallocate_sedp_sequence_numbers(sedp_cache: &SedpAnnouncementsCache) -> PreallocatedEndpoints {
    let list_guard = sedp_cache.read().unwrap_or_else(|e| e.into_inner());
    if list_guard.is_empty() {
        return Vec::new();
    }

    // v207: Use FIXED positional sequence numbers (1-based index per kind).
    // Must match the scheme used by ControlHandler::retransmit_sedp_data().
    let mut pub_pos = 0u64;
    let mut sub_pos = 0u64;
    list_guard
        .iter()
        .map(|(sd, kind)| {
            let seq_num = match kind {
                SedpEndpointKind::Writer => {
                    pub_pos += 1;
                    pub_pos
                }
                SedpEndpointKind::Reader => {
                    sub_pos += 1;
                    sub_pos
                }
            };
            (sd.clone(), *kind, seq_num)
        })
        .collect()
}

/// v176: Send SEDP re-announcements with pre-allocated sequence numbers.
///
/// This variant uses sequence numbers that were pre-allocated synchronously
/// before building handshake HEARTBEATs, ensuring consistency between the
/// HEARTBEAT lastSeq and the DATA(r) sequence numbers.
///
/// # Arguments
/// - `spdp_data`: SPDP data with peer locators
/// - `our_guid_prefix`: Our participant GUID prefix
/// - `peer_guid_prefix`: Peer participant GUID prefix
/// - `transport`: UDP transport for sending
/// - `pre_allocated`: Pre-allocated endpoints with sequence numbers
/// - `log_prefix`: Log prefix for log::debug! messages
/// - `encoding_dialect`: Dialect for encoding
#[allow(clippy::too_many_arguments)]
fn send_sedp_reannouncements_with_prealloc(
    spdp_data: &SpdpData,
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    transport: Arc<UdpTransport>,
    pre_allocated: PreallocatedEndpoints,
    log_prefix: &str,
    encoding_dialect: Dialect,
) {
    // v176: Skip if no pre-allocated endpoints
    if pre_allocated.is_empty() {
        log::debug!(
            "{} No pre-allocated endpoints, skipping SEDP retries",
            log_prefix
        );
        return;
    }

    // SPDP->SEDP barrier: only send SEDP after a few local SPDP
    // announcements, to give the remote PDP (FastDDS/RTI/...)
    // time to create ParticipantProxyData for our GUID.
    let spdp_sent = SPDP_SENT_COUNT.load(Ordering::Relaxed);
    // Skip SPDP barrier when dialect encoder indicates it's safe.
    // Each dialect encoder defines its own requirement via skip_spdp_barrier().
    let encoder = crate::protocol::dialect::get_encoder(encoding_dialect);
    let skip_spdp_barrier = encoder.skip_spdp_barrier();

    if spdp_sent < 3 && !skip_spdp_barrier {
        log::debug!(
            "{} Skipping SEDP re-announce: only {} SPDP sent so far (<3)",
            log_prefix,
            spdp_sent
        );
        return;
    }

    if spdp_sent < 3 && skip_spdp_barrier {
        log::debug!(
            "{} [INTEROP] Skipping SPDP barrier (spdp_sent={})",
            log_prefix,
            spdp_sent
        );
    }

    // Clone data needed by the retry loop.
    let spdp_data_clone = spdp_data.clone();
    let transport_clone = Arc::clone(&transport);
    let our_prefix = *our_guid_prefix;
    let peer_prefix = *peer_guid_prefix;
    let prefix = log_prefix.to_string();

    // v176: Move pre-allocated endpoints into the thread
    let endpoints = pre_allocated;

    // v125: SEDP Retry Flood Fix
    // - RetryGuard prevents multiple threads per peer (was: 10 SPDP x 120 = 1200 sends)
    // - Pre-allocate seq numbers BEFORE loop (RTPS Sec.8.4.7.5: retransmit = same seq)
    // - Reduced retries: 5 x 500ms = 2.5s (was: 120 x 500ms = 60s)
    std::thread::spawn(move || {
        use std::time::Duration;

        // v125: Acquire RetryGuard - skip if already retrying to this peer
        let _guard = match RetryGuard::try_acquire(peer_prefix) {
            Some(g) => g,
            None => {
                log::debug!(
                    "{} [SEDP-RETRY] peer={:02x}{:02x}...{:02x}{:02x} already active, skipping",
                    prefix,
                    peer_prefix[0],
                    peer_prefix[1],
                    peer_prefix[10],
                    peer_prefix[11]
                );
                return;
            }
        };

        // v176: endpoints already have pre-allocated sequence numbers

        if spdp_data_clone.metatraffic_unicast_locators.is_empty() {
            log::debug!(
                "{} No metatraffic_unicast_locators, skipping SEDP retries",
                prefix
            );
            return;
        }

        log::debug!(
            "{} [SEDP-RETRY] Starting {} endpoints, {} retries to peer {:02x}{:02x}...{:02x}{:02x}",
            prefix,
            endpoints.len(),
            5, // max retries
            peer_prefix[0],
            peer_prefix[1],
            peer_prefix[10],
            peer_prefix[11]
        );

        // v130: Send SEDP immediately first, then retry with delays
        // RTI expects SEDP DATA within ~200ms of ACKNACK request
        // Previous bug: sleep(500ms) BEFORE first send caused 500ms delay
        for retry in 0..5 {
            // v130: Send immediately on first iteration, then delay for retries
            if retry > 0 {
                std::thread::sleep(Duration::from_millis(500));
            }

            for (sd, kind, seq_num) in &endpoints {
                match build_sedp_rtps_packet(
                    sd,
                    *kind,
                    &our_prefix,
                    Some(&peer_prefix),
                    *seq_num,
                    encoding_dialect,
                ) {
                    Ok(mut pkt) => {
                        // v142: Only append HEARTBEAT on first retry to avoid HEARTBEAT storm.
                        // Previous bug: HB was appended to every retry (5x), causing 56475x
                        // more HEARTBEATs than FastDDS reference (225900 vs 4).
                        let has_heartbeat = if retry == 0 {
                            let (reader_id, writer_id) = match kind {
                                SedpEndpointKind::Writer => {
                                    ([0x00, 0x00, 0x03, 0xC7], [0x00, 0x00, 0x03, 0xC2])
                                }
                                SedpEndpointKind::Reader => {
                                    ([0x00, 0x00, 0x04, 0xC7], [0x00, 0x00, 0x04, 0xC2])
                                }
                            };

                            // v209: Use dialect encoder for Final flag decision (same as Path B).
                            // Previous bug: always used Final=true, ignoring dialect.
                            // Hybrid/FastDDS need non-Final to force ACKNACK response.
                            // RTI needs Final=true to prevent HB/ACKNACK storm.
                            let count =
                                (SEDP_HEARTBEAT_COUNT.fetch_add(1, Ordering::Relaxed) + 1) as u32;
                            let use_final = encoder.sedp_heartbeat_final(&writer_id);
                            // v150: firstSeq=1, lastSeq=seq_num
                            let hb = if use_final {
                                build_heartbeat_submessage_final(
                                    &reader_id, &writer_id, 1, *seq_num, count,
                                )
                            } else {
                                build_heartbeat_submessage(
                                    &reader_id, &writer_id, 1, *seq_num, count,
                                )
                            };
                            pkt.extend_from_slice(&hb);
                            true
                        } else {
                            false
                        };

                        for ep in &spdp_data_clone.metatraffic_unicast_locators {
                            match transport_clone.send_to_endpoint(&pkt, ep) {
                                Ok(_) => log::debug!(
                                    "{} [OK] SEDP retry #{} sent ({:?}) seq={} to {}{}",
                                    prefix,
                                    retry + 1,
                                    kind,
                                    seq_num,
                                    ep,
                                    if has_heartbeat { " (+HB)" } else { "" }
                                ),
                                Err(e) => log::debug!(
                                    "{} Failed to send SEDP retry #{} to {}: {}",
                                    prefix,
                                    retry + 1,
                                    ep,
                                    e
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        log::debug!("{} Failed to build SEDP packet: {:?}", prefix, e);
                    }
                }
            }
        }

        log::debug!(
            "{} [SEDP-RETRY] Completed all retries to peer {:02x}{:02x}...{:02x}{:02x}",
            prefix,
            peer_prefix[0],
            peer_prefix[1],
            peer_prefix[10],
            peer_prefix[11]
        );
    });
}

/// Send SEDP re-announcements to peer's unicast locators.
///
/// # Arguments
/// - `spdp_data`: SPDP data with peer locators
/// - `our_guid_prefix`: Our participant GUID prefix
/// - `peer_guid_prefix`: Peer participant GUID prefix
/// - `transport`: UDP transport for sending
/// - `sedp_cache`: SEDP announcements cache
/// - `log_prefix`: Log prefix for log::debug! messages
fn send_sedp_reannouncements(
    spdp_data: &SpdpData,
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    transport: Arc<UdpTransport>,
    sedp_cache: SedpAnnouncementsCache,
    log_prefix: &str,
    encoding_dialect: Dialect,
) {
    // SPDP->SEDP barrier: only send SEDP after a few local SPDP
    // announcements, to give the remote PDP (FastDDS/RTI/...)
    // time to create ParticipantProxyData for our GUID.
    let spdp_sent = SPDP_SENT_COUNT.load(Ordering::Relaxed);
    // Skip SPDP barrier when dialect encoder indicates it's safe.
    // Each dialect encoder defines its own requirement via skip_spdp_barrier().
    let encoder = crate::protocol::dialect::get_encoder(encoding_dialect);
    let skip_spdp_barrier = encoder.skip_spdp_barrier();

    if spdp_sent < 3 && !skip_spdp_barrier {
        log::debug!(
            "{} Skipping SEDP re-announce: only {} SPDP sent so far (<3)",
            log_prefix,
            spdp_sent
        );
        return;
    }

    if spdp_sent < 3 && skip_spdp_barrier {
        log::debug!(
            "{} [INTEROP] Skipping SPDP barrier (spdp_sent={})",
            log_prefix,
            spdp_sent
        );
    }

    // Clone data needed by the retry loop.
    let spdp_data_clone = spdp_data.clone();
    let transport_clone = Arc::clone(&transport);
    let sedp_cache_clone = Arc::clone(&sedp_cache);
    let our_prefix = *our_guid_prefix;
    let peer_prefix = *peer_guid_prefix;
    let prefix = log_prefix.to_string();

    // v125: SEDP Retry Flood Fix
    // - RetryGuard prevents multiple threads per peer (was: 10 SPDP x 120 = 1200 sends)
    // - Pre-allocate seq numbers BEFORE loop (RTPS Sec.8.4.7.5: retransmit = same seq)
    // - Reduced retries: 5 x 500ms = 2.5s (was: 120 x 500ms = 60s)
    std::thread::spawn(move || {
        use std::time::Duration;

        // v125: Acquire RetryGuard - skip if already retrying to this peer
        let _guard = match RetryGuard::try_acquire(peer_prefix) {
            Some(g) => g,
            None => {
                log::debug!(
                    "{} [SEDP-RETRY] peer={:02x}{:02x}...{:02x}{:02x} already active, skipping",
                    prefix,
                    peer_prefix[0],
                    peer_prefix[1],
                    peer_prefix[10],
                    peer_prefix[11]
                );
                return;
            }
        };

        // v207: Use FIXED positional sequence numbers (1-based index per kind).
        // CRITICAL for multi-peer interop: all peers must see the same seq nums
        // so that retransmissions (from ControlHandler) match the initial
        // announcement. With incrementing counters, peer N gets seq=2N-1,2N
        // but retransmit sends seq=1,2 → FastDDS ignores as "below base".
        let endpoints: Vec<_> = {
            let list_guard = sedp_cache_clone.read().unwrap_or_else(|e| e.into_inner());
            if list_guard.is_empty() {
                log::debug!("{} SEDP cache empty, no retries needed", prefix);
                return;
            }
            let mut pub_pos = 0u64;
            let mut sub_pos = 0u64;
            list_guard
                .iter()
                .map(|(sd, kind)| {
                    let seq_num = match kind {
                        SedpEndpointKind::Writer => {
                            pub_pos += 1;
                            pub_pos // Fixed: Writer[0]=1, Writer[1]=2, ...
                        }
                        SedpEndpointKind::Reader => {
                            sub_pos += 1;
                            sub_pos // Fixed: Reader[0]=1, Reader[1]=2, ...
                        }
                    };
                    (sd.clone(), *kind, seq_num)
                })
                .collect()
        };

        if spdp_data_clone.metatraffic_unicast_locators.is_empty() {
            log::debug!(
                "{} No metatraffic_unicast_locators, skipping SEDP retries",
                prefix
            );
            return;
        }

        log::debug!(
            "{} [SEDP-RETRY] Starting {} endpoints, {} retries to peer {:02x}{:02x}...{:02x}{:02x}",
            prefix,
            endpoints.len(),
            5, // max retries
            peer_prefix[0],
            peer_prefix[1],
            peer_prefix[10],
            peer_prefix[11]
        );

        // v130: Send SEDP immediately first, then retry with delays
        // RTI expects SEDP DATA within ~200ms of ACKNACK request
        // Previous bug: sleep(500ms) BEFORE first send caused 500ms delay
        for retry in 0..5 {
            // v130: Send immediately on first iteration, then delay for retries
            if retry > 0 {
                std::thread::sleep(Duration::from_millis(500));
            }

            for (sd, kind, seq_num) in &endpoints {
                match build_sedp_rtps_packet(
                    sd,
                    *kind,
                    &our_prefix,
                    Some(&peer_prefix),
                    *seq_num,
                    encoding_dialect,
                ) {
                    Ok(mut pkt) => {
                        // v142: Only append HEARTBEAT on first retry to avoid HEARTBEAT storm.
                        // Previous bug: HB was appended to every retry (5x), causing 56475x
                        // more HEARTBEATs than FastDDS reference (225900 vs 4).
                        let has_heartbeat = if retry == 0 {
                            let (reader_id, writer_id) = match kind {
                                SedpEndpointKind::Writer => {
                                    ([0x00, 0x00, 0x03, 0xC7], [0x00, 0x00, 0x03, 0xC2])
                                }
                                SedpEndpointKind::Reader => {
                                    ([0x00, 0x00, 0x04, 0xC7], [0x00, 0x00, 0x04, 0xC2])
                                }
                            };
                            let hb_count = SEDP_HEARTBEAT_COUNT.fetch_add(1, Ordering::Relaxed);
                            // v173: Consult dialect encoder for Final flag decision.
                            // RTI requires Final=true to prevent HEARTBEAT/ACKNACK storm.
                            // Other dialects may have different requirements.
                            let encoder = get_encoder(encoding_dialect);
                            let use_final = encoder.sedp_heartbeat_final(&writer_id);
                            let heartbeat = if use_final {
                                build_heartbeat_submessage_final(
                                    &reader_id,
                                    &writer_id,
                                    *seq_num,
                                    *seq_num,
                                    hb_count as u32,
                                )
                            } else {
                                build_heartbeat_submessage(
                                    &reader_id,
                                    &writer_id,
                                    *seq_num,
                                    *seq_num,
                                    hb_count as u32,
                                )
                            };
                            pkt.extend_from_slice(&heartbeat);
                            true
                        } else {
                            false
                        };

                        for ep in &spdp_data_clone.metatraffic_unicast_locators {
                            match transport_clone.send_to_endpoint(&pkt, ep) {
                                Ok(_) => log::debug!(
                                    "{} [OK] SEDP retry #{} sent ({:?}) seq={} to {}{}",
                                    prefix,
                                    retry + 1,
                                    kind,
                                    seq_num,
                                    ep,
                                    if has_heartbeat { " (+HB)" } else { "" }
                                ),
                                Err(e) => log::debug!(
                                    "{} [X] SEDP retry #{} failed ({:?}) seq={} to {}: {}",
                                    prefix,
                                    retry + 1,
                                    kind,
                                    seq_num,
                                    ep,
                                    e
                                ),
                            }
                        }
                    }
                    Err(e) => {
                        log::debug!(
                            "{} Failed to build SEDP packet on retry #{}: {:?}",
                            prefix,
                            retry + 1,
                            e
                        );
                    }
                }
            }
        }

        log::debug!(
            "{} [SEDP-RETRY] Completed for peer {:02x}{:02x}...{:02x}{:02x}",
            prefix,
            peer_prefix[0],
            peer_prefix[1],
            peer_prefix[10],
            peer_prefix[11]
        );
        // _guard is dropped here, allowing future retries to this peer
    });
}

/// Best-effort extractor for PID_METATRAFFIC_UNICAST_LOCATOR (0x0032) from a
/// raw SPDP CDR payload. This is a lightweight, vendor-tolerant parser used
/// when the main SPDP parser did not populate `metatraffic_unicast_locators`.
fn extract_metatraffic_unicast_from_cdr(buf: &[u8]) -> Option<SocketAddr> {
    // Need at least encapsulation (2 bytes) + PID header (4 bytes)
    if buf.len() < 6 {
        return None;
    }

    // Encapsulation is big-endian per CDR spec
    let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);

    // FastDDS and most stacks use PL_CDR_LE (0x0003) here for SPDP.
    // We treat this as little-endian ParameterList for this recovery path.
    let is_le = matches!(encapsulation, CDR_LE | CDR2_LE);

    // Detect padding: standard CDR uses 2-byte padding after encapsulation.
    let mut offset = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
        4
    } else {
        2
    };

    while offset + 4 <= buf.len() {
        let pid = if is_le {
            u16::from_le_bytes([buf[offset], buf[offset + 1]])
        } else {
            u16::from_be_bytes([buf[offset], buf[offset + 1]])
        };
        let length = if is_le {
            u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize
        };

        offset += 4;

        // PID_SENTINEL (0x0001) terminates the list
        if pid == 0x0001 {
            break;
        }

        if offset + length > buf.len() {
            break;
        }

        if pid == PID_METATRAFFIC_UNICAST_LOCATOR && length >= 24 {
            // locator: kind (4) + port (4) + address (16)
            let port_bytes = [
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ];

            // For FastDDS, the locator port is encoded in little-endian.
            let port_u32 = if is_le {
                u32::from_le_bytes(port_bytes)
            } else {
                u32::from_be_bytes(port_bytes)
            };

            if let Ok(port_u16) = u16::try_from(port_u32) {
                let addr = Ipv4Addr::new(
                    buf[offset + 20],
                    buf[offset + 21],
                    buf[offset + 22],
                    buf[offset + 23],
                );
                return Some(SocketAddr::new(addr.into(), port_u16));
            }
        }

        // Advance to next PID (4-byte alignment is already handled by vendors).
        offset += length;
    }

    None
}

/// v132: Send immediate SPDP unicast response to peer.
///
/// Some DDS implementations (RTI Connext) require an immediate SPDP unicast response
/// BEFORE processing discovery HEARTBEATs. This mimics FastDDS behavior (frame 12)
/// where SPDP unicast is sent ~0.5ms after receiving peer's SPDP.
///
/// # Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: Remote participant GUID prefix (for INFO_DST)
/// - `peer_locators`: Peer's metatraffic_unicast locators
/// - `transport`: UDP transport for sending
/// - `port_mapping`: Port mapping for calculating locator ports
/// - `dialect_name`: Dialect name for logging
fn send_immediate_spdp_unicast(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    peer_locators: &[SocketAddr],
    transport: &Arc<UdpTransport>,
    port_mapping: crate::transport::PortMapping,
    dialect_name: &str,
) {
    use crate::config::{DATA_MULTICAST_OFFSET, MULTICAST_IP};
    use crate::core::discovery::GUID;

    // Build our SPDP data using transport locators
    let metatraffic_unicast_locators = transport.get_unicast_locators();
    let user_unicast_port = port_mapping.user_unicast;
    let data_multicast_port = port_mapping.metatraffic_multicast + DATA_MULTICAST_OFFSET;
    let spdp_multicast_port = port_mapping.metatraffic_multicast;

    // Build default unicast locators (user data port)
    let default_unicast_locators: Vec<SocketAddr> = metatraffic_unicast_locators
        .iter()
        .map(|addr| {
            let mut new_addr = *addr;
            new_addr.set_port(user_unicast_port);
            new_addr
        })
        .collect();

    // Build multicast locators
    let default_multicast_locators = vec![SocketAddr::from((MULTICAST_IP, data_multicast_port))];
    let metatraffic_multicast_locators =
        vec![SocketAddr::from((MULTICAST_IP, spdp_multicast_port))];

    // Reconstruct participant GUID from prefix
    let mut guid_bytes = [0u8; 16];
    guid_bytes[..12].copy_from_slice(our_guid_prefix);
    guid_bytes[12..16].copy_from_slice(&[0x00, 0x00, 0x01, 0xC1]); // ENTITYID_PARTICIPANT
    let participant_guid = GUID::from_bytes(guid_bytes);

    // v208: derive domain_id from metatraffic multicast port
    let domain_id = {
        use crate::config::{DOMAIN_ID_GAIN, PORT_BASE};
        (spdp_multicast_port.saturating_sub(PORT_BASE)) / DOMAIN_ID_GAIN
    };
    // Clamp to DDS spec max (RTPS v2.3 Sec.9.6.1.1: valid range 0..232)
    let domain_id = u32::from(domain_id).min(crate::config::MAX_DOMAIN_ID);

    let our_spdp_data = SpdpData {
        participant_guid,
        lease_duration_ms: 30_000, // 30 seconds (standard)
        domain_id,
        metatraffic_unicast_locators,
        default_unicast_locators,
        default_multicast_locators,
        metatraffic_multicast_locators,
        identity_token: None,
    };

    // Get a sequence number (use current SPDP count + 1)
    let seq_num = SPDP_SENT_COUNT.load(Ordering::Relaxed) + 1;

    // Build SPDP RTPS packet targeting peer (unicast mode)
    match build_spdp_rtps_packet(&our_spdp_data, seq_num, Some(peer_guid_prefix)) {
        Ok(packet) => {
            for ep in peer_locators {
                match transport.send_to_endpoint(&packet, ep) {
                    Ok(_) => log::debug!(
                        "[SPDP-UNICAST] [OK] v132: Sent immediate SPDP unicast to {} (seq={}) [{} dialect]",
                        ep, seq_num, dialect_name
                    ),
                    Err(e) => log::debug!(
                        "[SPDP-UNICAST] Failed to send immediate SPDP unicast to {}: {}",
                        ep, e
                    ),
                }
            }
        }
        Err(e) => {
            log::debug!(
                "[SPDP-UNICAST] Failed to build immediate SPDP packet: {:?}",
                e
            );
        }
    }
}

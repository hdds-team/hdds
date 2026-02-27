// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP packet handler.
//!
//!
//! Handles SEDP (Subscription/Endpoint Discovery Protocol) packets including:
//! - SEDP parsing
//! - Endpoint discovery (Writer/Reader)
//! - TopicRegistry updates (writer GUID -> topic mapping)
//! - FSM state updates
//! - v150: Reader proxy notification for ACKNACK state machine

use super::type_lookup_handler::{maybe_request_type_object, TypeLookupHandle};
use crate::core::discovery::multicast::{
    build_heartbeat_submessage_final, build_sedp_rtps_packet, next_subscriptions_seq,
    rtps_packet::SEDP_HEARTBEAT_COUNT, DiscoveryFsm, EndpointKind, SedpEndpointKind,
};
use crate::core::reader::ReaderProxyRegistry;
use crate::engine::TopicRegistry;
use crate::protocol::dialect::{get_encoder, Dialect};
use crate::protocol::discovery::parse_sedp;
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Handle SEDP packet.
///
/// # Arguments
/// - `payload`: Full RTPS packet (including headers)
/// - `cdr_offset`: CDR payload offset within the packet (computed by classifier)
/// - `fsm`: Discovery FSM for state updates
/// - `registry`: Topic registry for writer GUID -> topic mapping
/// - `reader_registry`: v150: Reader proxy registry for ACKNACK state tracking
/// - `transport`: v184: UDP transport for sending responses
/// - `sedp_cache`: v184/v187: SEDP announcements cache for reader re-announcement
/// - `our_guid_prefix`: v184: Our participant GUID prefix
/// - `type_lookup`: Optional TypeLookup handler for missing TypeObjects
/// - `src_addr`: v184: Source address to send responses to
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_sedp_packet(
    payload: &[u8],
    cdr_offset: usize,
    fsm: Arc<DiscoveryFsm>,
    registry: Arc<TopicRegistry>,
    reader_registry: ReaderProxyRegistry,
    transport: Arc<crate::transport::UdpTransport>,
    sedp_cache: super::super::entity_registry::SedpAnnouncementsCache,
    our_guid_prefix: [u8; 12],
    type_lookup: TypeLookupHandle,
    src_addr: std::net::SocketAddr,
) {
    log::debug!(
        "[callback-builder] v125: Received SEDP packet, len={}, cdr_offset={}",
        payload.len(),
        cdr_offset
    );

    // v150: Extract writer GUID and sequence number from RTPS DATA header
    // to notify the reader proxy registry that we received this DATA.
    //
    // RTPS DATA format (after RTPS header at offset 20):
    // - Submessage header: 4 bytes (ID=0x15, flags, length)
    // - extraFlags: 2 bytes
    // - octetsToInlineQos: 2 bytes
    // - readerEntityId: 4 bytes
    // - writerEntityId: 4 bytes
    // - writerSeqNum: 8 bytes (high: i32, low: u32)
    //
    // Writer GUID = RTPS header guid_prefix (bytes 8-20) + writerEntityId (offset 20+12)
    if let Some((writer_guid, seq)) = extract_data_writer_info(payload) {
        log::debug!(
            "[sedp] v150: Notifying reader registry: writer={:02x?}, seq={}",
            writer_guid,
            seq
        );
        reader_registry.on_data(writer_guid, seq);

        // v186: Send vendor-specific confirmation ACKNACK if dialect requires it
        // This is critical for OpenDDS which expects ACKNACK after receiving SEDP DATA(w)
        //
        // Note: We extract dialect from RTPS header vendor ID directly since FSM may not
        // have the dialect locked yet when we receive the first SEDP DATA(w).
        let dialect = fsm
            .get_locked_dialect()
            .or_else(|| extract_vendor_dialect(payload));
        if let Some(dialect) = dialect {
            let encoder = get_encoder(dialect);
            // Extract peer GUID prefix (first 12 bytes) and writer entity ID (last 4 bytes)
            let mut peer_guid_prefix = [0u8; 12];
            peer_guid_prefix.copy_from_slice(&writer_guid[..12]);
            let mut writer_entity_id = [0u8; 4];
            writer_entity_id.copy_from_slice(&writer_guid[12..16]);

            if let Some(confirmation_packet) = encoder.build_sedp_data_confirmation(
                &our_guid_prefix,
                &peer_guid_prefix,
                &writer_entity_id,
                seq,
            ) {
                log::debug!(
                    "[sedp] v186: Sending SEDP DATA confirmation ACKNACK to {:?}, dialect={:?}",
                    src_addr,
                    dialect
                );
                if let Err(e) = transport.send_to_endpoint(&confirmation_packet, &src_addr) {
                    log::debug!("[sedp] v186: Failed to send confirmation ACKNACK: {}", e);
                }
            }
        }
    }

    // v125: Extract CDR payload using offset from classifier
    let cdr_payload = if cdr_offset < payload.len() {
        log::debug!(
            "[sedp] v125: Extracting CDR payload at offset {}",
            cdr_offset
        );
        // Debug: dump first bytes at offset
        if cdr_offset + 2 <= payload.len() {
            let first_bytes = [payload[cdr_offset], payload[cdr_offset + 1]];
            log::debug!(
                "[sedp] DEBUG: First 2 bytes at offset {}: 0x{:02x}{:02x}",
                cdr_offset,
                first_bytes[0],
                first_bytes[1]
            );
        }
        &payload[cdr_offset..]
    } else {
        log::debug!(
            "[sedp] v125: Invalid offset {}, using full payload",
            cdr_offset
        );
        payload
    };

    let peer_guid_prefix = extract_peer_guid_prefix(payload);
    match parse_sedp(cdr_payload) {
        Ok(sedp_data) => {
            let endpoint_guid_bytes = sedp_data.endpoint_guid.as_bytes();
            let endpoint_kind = EndpointKind::from_guid(&sedp_data.endpoint_guid);

            log::debug!(
                "[callback] [OK] SEDP parsed (via classifier): topic={:?}, endpoint=GUID({:?}), kind={:?}",
                sedp_data.topic_name, sedp_data.endpoint_guid, endpoint_kind
            );

            // Register writer GUID -> topic mapping (RTI interop fix)
            if matches!(endpoint_kind, EndpointKind::Writer) {
                log::debug!(
                    "[callback] [*] Writer endpoint detected! Registering writer GUID {:02x?} -> topic '{}'",
                    &endpoint_guid_bytes[..],
                    sedp_data.topic_name
                );
                registry.register_writer_guid(endpoint_guid_bytes, sedp_data.topic_name.clone());

                // v187: Re-announce our Reader endpoints for the same topic if dialect requires it.
                // OpenDDS has a peculiar state machine where it won't trigger PUBLICATION_MATCHED
                // unless it receives a "fresh" DATA(r) after sending its DATA(w).
                // Standard RTPS retransmissions (same seq number) are dropped as duplicates.
                let dialect = fsm
                    .get_locked_dialect()
                    .or_else(|| extract_vendor_dialect(payload));
                if let Some(dialect) = dialect {
                    let encoder = get_encoder(dialect);
                    if encoder.requires_sedp_reader_confirmation() {
                        // v188: Extract peer's GUID prefix from RTPS header for INFO_DST
                        let peer_guid_prefix: Option<[u8; 12]> = if payload.len() >= 20 {
                            let mut prefix = [0u8; 12];
                            prefix.copy_from_slice(&payload[8..20]);
                            Some(prefix)
                        } else {
                            None
                        };

                        send_reader_reannouncement_for_topic(
                            &sedp_data.topic_name,
                            &sedp_cache,
                            &our_guid_prefix,
                            peer_guid_prefix.as_ref(),
                            &transport,
                            &src_addr,
                            dialect,
                        );
                    }
                }
            } else {
                log::debug!("[callback] >>  Reader endpoint - not registering writer mapping");
            }

            if sedp_data.type_object.is_none() {
                let is_local = endpoint_guid_bytes[..12] == our_guid_prefix;
                if !is_local {
                    maybe_request_type_object(
                        &type_lookup,
                        &sedp_data.type_name,
                        src_addr,
                        peer_guid_prefix,
                    );
                }
            }

            fsm.handle_sedp(sedp_data);
        }
        Err(e) => {
            log::debug!("[callback] SEDP parse failed (via classifier): {:?}", e);
        }
    }
}

fn extract_peer_guid_prefix(packet: &[u8]) -> Option<[u8; 12]> {
    if packet.len() < 20 || &packet[0..4] != b"RTPS" {
        return None;
    }
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&packet[8..20]);
    Some(prefix)
}

/// v150: Extract writer GUID and sequence number from RTPS DATA packet.
///
/// # Returns
/// Some((writer_guid, seq)) if extraction succeeds, None otherwise.
fn extract_data_writer_info(packet: &[u8]) -> Option<([u8; 16], i64)> {
    // Need at least RTPS header (20) + DATA submessage header (4) + minimal body (20)
    if packet.len() < 44 {
        return None;
    }

    // Verify RTPS magic
    if &packet[0..4] != b"RTPS" {
        return None;
    }

    // Extract GUID prefix from RTPS header (bytes 8-20)
    let mut guid_prefix = [0u8; 12];
    guid_prefix.copy_from_slice(&packet[8..20]);

    // Find DATA submessage (ID = 0x15)
    let mut offset = 20; // Start after RTPS header

    while offset + 4 <= packet.len() {
        let submsg_id = packet[offset];
        let flags = packet[offset + 1];
        let is_le = flags & 0x01 != 0;

        let octets_to_next = if is_le {
            u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize
        };

        if submsg_id == 0x15 {
            // DATA found
            let data_offset = offset + 4;

            // Check we have enough bytes for writerEntityId + writerSeqNum
            // DATA body starts at data_offset:
            // +0: extraFlags (2), +2: octetsToInlineQos (2), +4: readerEntityId (4), +8: writerEntityId (4), +12: writerSeqNum (8)
            if data_offset + 20 > packet.len() {
                return None;
            }

            // writerEntityId at +8
            let mut writer_entity_id = [0u8; 4];
            writer_entity_id.copy_from_slice(&packet[data_offset + 8..data_offset + 12]);

            // writerSeqNum at +12 (SequenceNumber_t: high i32, low u32)
            let seq = if is_le {
                let high =
                    i32::from_le_bytes(packet[data_offset + 12..data_offset + 16].try_into().ok()?);
                let low =
                    u32::from_le_bytes(packet[data_offset + 16..data_offset + 20].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            } else {
                let high =
                    i32::from_be_bytes(packet[data_offset + 12..data_offset + 16].try_into().ok()?);
                let low =
                    u32::from_be_bytes(packet[data_offset + 16..data_offset + 20].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            };

            // Build full writer GUID: guid_prefix + writer_entity_id
            let mut writer_guid = [0u8; 16];
            writer_guid[..12].copy_from_slice(&guid_prefix);
            writer_guid[12..16].copy_from_slice(&writer_entity_id);

            return Some((writer_guid, seq));
        }

        // Move to next submessage
        if octets_to_next == 0 {
            break;
        }
        offset += 4 + octets_to_next;
    }

    None
}

/// v186: Extract dialect from RTPS header vendor ID.
///
/// RTPS header format:
/// - bytes 0-4: "RTPS" magic
/// - bytes 4-6: protocol version (major, minor)
/// - bytes 6-8: vendor ID (e.g., 0x0103 = OpenDDS)
///
/// # Returns
/// Some(Dialect) if vendor ID maps to a known dialect, None otherwise.
fn extract_vendor_dialect(packet: &[u8]) -> Option<Dialect> {
    // Need at least 8 bytes for vendor ID
    if packet.len() < 8 || &packet[0..4] != b"RTPS" {
        return None;
    }

    let vendor_id = [packet[6], packet[7]];
    match vendor_id {
        [0x01, 0x03] => Some(Dialect::OpenDds),
        [0x01, 0x01] => Some(Dialect::Rti),
        [0x01, 0x0f] => Some(Dialect::FastDds),
        [0x01, 0x10] => Some(Dialect::CycloneDds),
        _ => None,
    }
}

/// Handle SEDP from single DATA_FRAG (RTI workaround for total_frags=0).
///
/// # Arguments
/// - `payload`: Raw SEDP packet payload
/// - `fsm`: Discovery FSM for state updates
/// - `registry`: Topic registry for writer GUID -> topic mapping
pub(super) fn handle_sedp_from_single_fragment(
    payload: &[u8],
    fsm: Arc<DiscoveryFsm>,
    registry: Arc<TopicRegistry>,
) {
    match parse_sedp(payload) {
        Ok(sedp_data) => {
            let endpoint_guid_bytes = sedp_data.endpoint_guid.as_bytes();
            let endpoint_kind = EndpointKind::from_guid(&sedp_data.endpoint_guid);

            log::debug!(
                "[callback] [OK] SEDP parsed from single DATA_FRAG: topic={:?}, endpoint=GUID({:?}), kind={:?}",
                sedp_data.topic_name,
                sedp_data.endpoint_guid,
                endpoint_kind
            );

            // Register writer GUID -> topic mapping (RTI interop fix)
            // Only register Writers (entity_id 0x02, 0x03, 0xC2, etc.)
            if matches!(endpoint_kind, EndpointKind::Writer) {
                log::debug!(
                    "[callback] [*] Writer endpoint detected! Registering writer GUID {:02x?} -> topic '{}'",
                    &endpoint_guid_bytes[..],
                    sedp_data.topic_name
                );
                registry.register_writer_guid(endpoint_guid_bytes, sedp_data.topic_name.clone());
            } else {
                log::debug!("[callback] >>  Reader endpoint - not registering writer mapping");
            }

            fsm.handle_sedp(sedp_data);
        }
        Err(e) => {
            log::debug!("[callback] SEDP parse failed on single DATA_FRAG: {:?}", e);
        }
    }
}

/// Handle SEDP from reassembled fragments.
///
/// # Arguments
/// - `complete_payload`: Complete reassembled SEDP payload
/// - `fsm`: Discovery FSM for state updates
/// - `registry`: Topic registry for writer GUID -> topic mapping
pub(super) fn handle_sedp_from_fragments(
    complete_payload: &[u8],
    fsm: Arc<DiscoveryFsm>,
    registry: Arc<TopicRegistry>,
) {
    match parse_sedp(complete_payload) {
        Ok(sedp_data) => {
            let endpoint_guid_bytes = sedp_data.endpoint_guid.as_bytes();
            let endpoint_kind = EndpointKind::from_guid(&sedp_data.endpoint_guid);

            log::debug!(
                "[callback] [OK] SEDP parsed from reassembled fragments: topic={:?}, endpoint=GUID({:?}), kind={:?}",
                sedp_data.topic_name,
                sedp_data.endpoint_guid,
                endpoint_kind
            );

            // Register writer GUID -> topic mapping (RTI interop fix)
            // Only register Writers (entity_id 0x02, 0x03, 0xC2, etc.)
            if matches!(endpoint_kind, EndpointKind::Writer) {
                log::debug!(
                    "[callback] [*] Writer endpoint detected! Registering writer GUID {:02x?} -> topic '{}'",
                    &endpoint_guid_bytes[..],
                    sedp_data.topic_name
                );
                registry.register_writer_guid(endpoint_guid_bytes, sedp_data.topic_name.clone());
            } else {
                log::debug!("[callback] >>  Reader endpoint - not registering writer mapping");
            }

            fsm.handle_sedp(sedp_data);
        }
        Err(e) => {
            log::debug!(
                "[callback] SEDP parse failed on reassembled payload: {:?}",
                e
            );
        }
    }
}

/// v187: Re-announce our Reader endpoints for a specific topic.
///
/// This is called when we receive a Writer announcement from OpenDDS and need to
/// send our Reader endpoints with NEW sequence numbers. OpenDDS drops DATA(r)
/// with sequence numbers it has already seen, so standard RTPS retransmissions
/// are ineffective.
///
/// # Arguments
/// - `topic_name`: Topic to find matching Reader endpoints for
/// - `sedp_cache`: SEDP announcements cache containing our endpoints
/// - `our_guid_prefix`: Our participant GUID prefix
/// - `peer_guid_prefix`: v188: Peer's GUID prefix for INFO_DST (if dialect requires it)
/// - `transport`: UDP transport for sending packets
/// - `dest_addr`: Destination address (peer's metatraffic unicast)
/// - `dialect`: Encoding dialect to use
fn send_reader_reannouncement_for_topic(
    topic_name: &str,
    sedp_cache: &super::super::entity_registry::SedpAnnouncementsCache,
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: Option<&[u8; 12]>,
    transport: &Arc<crate::transport::UdpTransport>,
    dest_addr: &std::net::SocketAddr,
    dialect: Dialect,
) {
    // Read the cache to find Reader endpoints for the given topic
    let cache_guard = match sedp_cache.read() {
        Ok(guard) => guard,
        Err(e) => {
            log::debug!("[sedp] v187: Failed to read SEDP cache: {}", e);
            return;
        }
    };

    // Find all Reader endpoints for this topic
    let readers_for_topic: Vec<_> = cache_guard
        .iter()
        .filter(|(sd, kind)| {
            matches!(kind, SedpEndpointKind::Reader) && sd.topic_name == topic_name
        })
        .collect();

    if readers_for_topic.is_empty() {
        log::debug!(
            "[sedp] v187: No Reader endpoints found for topic '{}'",
            topic_name
        );
        return;
    }

    log::debug!(
        "[sedp] v187: Found {} Reader endpoint(s) for topic '{}', re-announcing with new seq",
        readers_for_topic.len(),
        topic_name
    );

    // Clone data we need before releasing the lock
    let readers: Vec<_> = readers_for_topic
        .into_iter()
        .map(|(sd, kind)| (sd.clone(), *kind))
        .collect();
    drop(cache_guard);

    // v188: Check if dialect requires INFO_DST for re-announcements
    let encoder = get_encoder(dialect);
    let destination_prefix = if encoder.requires_info_dst_for_reannouncement() {
        peer_guid_prefix
    } else {
        None
    };

    // Re-announce each Reader with a NEW sequence number
    for (sd, kind) in readers {
        // Allocate a NEW sequence number (this is the key difference from retransmissions)
        let new_seq = next_subscriptions_seq();

        log::debug!(
            "[sedp] v187: Re-announcing Reader endpoint for topic '{}' with new seq={}, info_dst={}",
            topic_name,
            new_seq,
            destination_prefix.is_some()
        );

        match build_sedp_rtps_packet(
            &sd,
            kind,
            our_guid_prefix,
            destination_prefix,
            new_seq,
            dialect,
        ) {
            Ok(mut packet) => {
                // v193: Append HEARTBEAT to DATA(r) for OpenDDS reliable protocol completion.
                // OpenDDS needs HEARTBEAT to know what sequence numbers are available so it
                // can send ACKNACK. Without HEARTBEAT, OpenDDS ignores our DATA(r) packets.
                // This matches what spdp_handler.rs does for initial SEDP announcements.
                let reader_id = [0x00, 0x00, 0x04, 0xC7]; // SEDP Subscriptions Reader
                let writer_id = [0x00, 0x00, 0x04, 0xC2]; // SEDP Subscriptions Writer
                let count = (SEDP_HEARTBEAT_COUNT.fetch_add(1, Ordering::Relaxed) + 1) as u32;
                let hb =
                    build_heartbeat_submessage_final(&reader_id, &writer_id, 1, new_seq, count);
                packet.extend_from_slice(&hb);

                if let Err(e) = transport.send_to_endpoint(&packet, dest_addr) {
                    log::debug!(
                        "[sedp] v187: Failed to send Reader re-announcement to {}: {}",
                        dest_addr,
                        e
                    );
                } else {
                    log::debug!(
                        "[sedp] v193: [OK] Sent Reader re-announcement to {} (seq={}, +HB count={})",
                        dest_addr,
                        new_seq,
                        count
                    );
                }
            }
            Err(e) => {
                log::debug!("[sedp] v187: Failed to build SEDP packet: {:?}", e);
            }
        }
    }
}

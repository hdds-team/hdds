// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HEARTBEAT response handler for SEDP and user data endpoints.
//!
//! When receiving HEARTBEAT from remote SEDP Publications Writer,
//! respond with ACKNACK to request the announced DATA.
//!
//! Extended to handle user data HEARTBEATs for RELIABLE QoS.
//! A reliable writer that receives no ACKNACK for its HEARTBEATs keeps
//! retransmitting, and the flood exhausts HDDS's receive pool.
//!
//! ## Problem Solved
//! A remote SEDP Publications writer (writerEntityId=0x000003c2) announces its
//! available sequence numbers with HEARTBEATs. In the reliable protocol
//! (DDSI-RTPS 2.5 8.4) a reader obtains the changes it has not received by
//! answering the HEARTBEAT with an ACKNACK that lists them; without the
//! ACKNACK, HDDS may never receive the DATA announcing the remote DataWriter,
//! so it cannot discover the writer and route user data.
//!
//! ## RTPS Flow
//! 1. Remote writer sends HEARTBEAT: writerEntityId=0x000003c2, firstSeq=1, lastSeq=1
//! 2. HDDS responds with ACKNACK: readerEntityId=0x000003c7, bitmapBase=1, numBits=1
//! 3. Remote writer sends DATA with the SEDP Publications announcement
//! 4. HDDS discovers the remote writer and can route user data
//!
//! ## User Data HEARTBEAT
//! For RELIABLE user data writers, we send positive ACKNACKs (no missing seqs)
//! to confirm receipt and stop retransmission flood.

use crate::core::discovery::multicast::{DiscoveryFsm, Origin};
use crate::core::rtps_constants::{
    RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER, RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
    RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
    RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER, RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER,
    RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
};
#[cfg(test)]
use crate::protocol::builder::build_acknack_packet;
use crate::protocol::builder::build_acknack_packet_with_final;
use crate::protocol::rtps::participant_message::{
    reader_reply_to_heartbeat, PARTICIPANT_MESSAGE_READER, PARTICIPANT_MESSAGE_WRITER,
};
use crate::transport::UdpTransport;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Global ACKNACK counter for SEDP HEARTBEAT responses
static SEDP_ACKNACK_COUNT: AtomicU32 = AtomicU32::new(1);

/// Last timestamp we sent an ACKNACK for user data (rate limiting)
/// We only respond to user data HBs every 100ms to avoid flooding
#[allow(dead_code)] // Reserved for future rate-limiting implementation
static LAST_USER_ACKNACK_TIME_MS: AtomicU64 = AtomicU64::new(0);

/// Minimum interval between user data ACKNACKs (milliseconds)
#[allow(dead_code)] // Reserved for future rate-limiting implementation
const USER_ACKNACK_MIN_INTERVAL_MS: u64 = 100;

/// Counter for skipped HBs (debugging)
#[allow(dead_code)] // Reserved for future rate-limiting implementation
static USER_HB_SKIPPED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Handle incoming HEARTBEAT packet and respond with ACKNACK if needed.
///
/// ## Arguments
/// - `payload`: Full RTPS packet (including headers)
/// - `origin`: where the HEARTBEAT came from, and where a reply may go
///   (RTPS 2.5 8.3.4, 8.3.8.10: `None` behind an INFO_SRC)
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `transport`: UDP transport for sending ACKNACK response
/// - `peer_metatraffic_port`: Fallback metatraffic port (our own, used if peer not in FSM)
/// - `discovery_fsm`: Discovery FSM for looking up peer's actual metatraffic locator
///
/// ## Destination
/// Send ACKNACK to peer's metatraffic unicast port, not the ephemeral source port.
/// A peer receives on the locators it announced (e.g. port 7410), not
/// necessarily on the port it sends from.
///
/// ## Peer locator lookup
/// Look up the peer's actual metatraffic unicast locator from SPDP discovery data
/// instead of using our own metatraffic port. This is needed whenever
/// multiple participants exist on the same domain (different participant_ids
/// = different metatraffic ports).
pub(super) fn handle_heartbeat_packet(
    payload: &[u8],
    origin: Origin,
    our_guid_prefix: [u8; 12],
    transport: Arc<UdpTransport>,
    peer_metatraffic_port: u16,
    discovery_fsm: Arc<DiscoveryFsm>,
) {
    // Parse HEARTBEAT to extract writerEntityId, firstSeq, lastSeq
    let Some(hb) = parse_heartbeat(payload) else {
        log::debug!("[HB-HANDLER] Failed to parse HEARTBEAT packet");
        return;
    };

    log::debug!(
        "[HB-HANDLER] Received HEARTBEAT from {} - writer={:02x?} first={} last={} count={}",
        origin.from(),
        hb.writer_entity_id,
        hb.first_seq,
        hb.last_seq,
        hb.count
    );

    // RTPS v2.5 Sec.8.4.13.3: the peer's BuiltinParticipantMessageWriter is
    // RELIABLE. Its entity id (kind 0xC2) matched neither `is_user_data_writer`
    // (built-in, not user) nor the SEDP/TypeLookup arms below, so it fell
    // into "built-in endpoint we don't handle" and was never ACKNACKed: the
    // writer never learned we held its assertion, and never repaired one we
    // lost.
    if hb.writer_entity_id == RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER {
        answer_participant_message_heartbeat(
            payload,
            origin,
            our_guid_prefix,
            &transport,
            peer_metatraffic_port,
            &discovery_fsm,
            &hb,
        );
        return;
    }

    // Check endpoint type and determine reader/writer entity IDs
    let (reader_entity_id, writer_entity_id, is_user_data) =
        if hb.writer_entity_id == RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER {
            (
                RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
                RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
                false,
            )
        } else if hb.writer_entity_id == RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER {
            (
                RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
                RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
                false,
            )
        } else if hb.writer_entity_id == RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER {
            // XTypes TypeLookup Service: ACKNACK the request writer (0x000300C3)
            // using the request reader entity (0x000300C4) so the requester knows
            // we have received its DATA and will not retransmit.
            (
                RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER,
                RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
                false,
            )
        } else if is_user_data_writer(&hb.writer_entity_id) {
            // User data writer - derive reader entity ID
            // (writer 0x02 -> reader 0x07 WITH_KEY, 0x03 -> 0x04 NO_KEY)
            let reader_id = derive_reader_entity_id(&hb.writer_entity_id);
            (reader_id, hb.writer_entity_id, true)
        } else {
            // Built-in endpoint we don't handle (SPDP, P2P, etc.)
            log::debug!(
                "[HB-HANDLER] Ignoring HEARTBEAT for unhandled endpoint: {:02x?}",
                hb.writer_entity_id
            );
            return;
        };

    // Extract peer GUID prefix from RTPS header
    let peer_guid_prefix: [u8; 12] = if payload.len() >= 20 {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&payload[8..20]);
        prefix
    } else {
        log::debug!("[HB-HANDLER] Packet too short for GUID prefix");
        return;
    };

    // Skip our own HEARTBEATs (multicast loopback)
    if peer_guid_prefix == our_guid_prefix {
        log::debug!("[HB-HANDLER] Ignoring our own HEARTBEAT (loopback)");
        return;
    }

    // Build ACKNACK response
    // Use centralized protocol/builder/acknack.rs instead of duplicated code
    let count = SEDP_ACKNACK_COUNT.fetch_add(1, Ordering::Relaxed);
    let first_seq_u64 = hb.first_seq.max(1) as u64;
    let last_seq_u64 = hb.last_seq.max(1) as u64;

    // Different behavior for SEDP vs user data
    // - SEDP: Request all sequences (we need the discovery data)
    // - User data: Positive ACK (confirm receipt, stop retransmission)
    let missing_seqs: Vec<u64> = if is_user_data {
        // Positive ACKNACK: empty bitmap = "I have everything up to last_seq"
        // This tells the writer to stop retransmitting
        vec![]
    } else {
        // SEDP: Request all sequences from first to last
        (first_seq_u64..=last_seq_u64).collect()
    };

    // Use Final=true for SEDP ACKNACKs.
    // For user data, we use Final=false as it's just confirming receipt.
    let final_flag = !is_user_data; // true for SEDP, false for user data

    let acknack = build_acknack_packet_with_final(
        our_guid_prefix,
        peer_guid_prefix,
        reader_entity_id,
        writer_entity_id,
        // For positive ACK, base should be last_seq + 1 (next expected)
        if is_user_data {
            last_seq_u64 + 1
        } else {
            first_seq_u64
        },
        &missing_seqs,
        count,
        final_flag,
    );

    // Look up peer's metatraffic unicast locator from SPDP discovery data.
    // The peer's GUID prefix identifies which participant sent the HEARTBEAT.
    // We look up their declared metatraffic locator (from SPDP) to send the ACKNACK
    // to the correct port. This is essential when multiple participants exist on the
    // same domain (e.g., several participants with participant_ids 9-13 on
    // one domain).
    //
    // Fallback: If peer not found in FSM (race condition at startup), use
    // our own metatraffic port as fallback (works when both sides are participant_id=0).
    let Some(dest_addr) = resolve_peer_metatraffic_addr(
        &peer_guid_prefix,
        origin,
        peer_metatraffic_port,
        &discovery_fsm,
    ) else {
        log::debug!(
            "[HB-HANDLER] relayed origin (behind an INFO_SRC) and peer {:02x?} unknown to \
             the FSM: no reply address, dropping the ACKNACK",
            &peer_guid_prefix[..4]
        );
        return;
    };

    match transport.send_to_endpoint(&acknack, &dest_addr) {
        Ok(_) => {
            if is_user_data {
                log::debug!(
                    "[HB-HANDLER] Sent positive ACKNACK to {} for user data writer {:02x?} (ack up to seq {})",
                    dest_addr,
                    writer_entity_id,
                    hb.last_seq
                );
            } else {
                log::debug!(
                    "[HB-HANDLER] Sent ACKNACK response to {} (was src={}) for SEDP {:02x?} (seq {}-{})",
                    dest_addr,
                    origin.from(),
                    writer_entity_id,
                    hb.first_seq,
                    hb.last_seq
                );
            }
        }
        Err(e) => {
            log::debug!(
                "[HB-HANDLER] Failed to send ACKNACK to {}: {}",
                dest_addr,
                e
            );
        }
    }
}

/// ACKNACK a peer's BuiltinParticipantMessageWriter HEARTBEAT (RTPS v2.5
/// Sec.8.4.13.3): a positive ack of what this reader already holds, and a
/// request for the newest sequence number alone when it is still missing
/// -- an older, superseded assertion has no value under `history.depth =
/// 1`, so it is never worth asking for (`participant_message::reader_reply_to_heartbeat`).
fn answer_participant_message_heartbeat(
    payload: &[u8],
    origin: Origin,
    our_guid_prefix: [u8; 12],
    transport: &UdpTransport,
    peer_metatraffic_port: u16,
    discovery_fsm: &DiscoveryFsm,
    hb: &HeartbeatData,
) {
    let peer_guid_prefix: [u8; 12] = if payload.len() >= 20 {
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&payload[8..20]);
        prefix
    } else {
        log::debug!("[HB-HANDLER] P2P participant-message HEARTBEAT too short for GUID prefix");
        return;
    };
    if peer_guid_prefix == our_guid_prefix {
        log::debug!("[HB-HANDLER] Ignoring our own participant-message HEARTBEAT (loopback)");
        return;
    }

    let have = discovery_fsm.participant_message_received(&peer_guid_prefix);
    let last_sn = hb.last_seq.max(0) as u64;
    let (bitmap_base, missing) = reader_reply_to_heartbeat(have, last_sn);
    let missing_seqs: Vec<u64> = missing.into_iter().collect();
    let final_flag = missing_seqs.is_empty();

    let Some(dest_addr) = resolve_peer_metatraffic_addr(
        &peer_guid_prefix,
        origin,
        peer_metatraffic_port,
        discovery_fsm,
    ) else {
        log::debug!(
            "[HB-HANDLER] relayed participant-message HEARTBEAT and peer {:02x?} unknown to \
             the FSM: no reply address, dropping the ACKNACK",
            &peer_guid_prefix[..4]
        );
        return;
    };

    let acknack = build_acknack_packet_with_final(
        our_guid_prefix,
        peer_guid_prefix,
        PARTICIPANT_MESSAGE_READER,
        PARTICIPANT_MESSAGE_WRITER,
        bitmap_base,
        &missing_seqs,
        SEDP_ACKNACK_COUNT.fetch_add(1, Ordering::Relaxed),
        final_flag,
    );
    if let Err(e) = transport.send_to_endpoint(&acknack, &dest_addr) {
        log::debug!(
            "[HB-HANDLER] Failed to send participant-message ACKNACK to {}: {}",
            dest_addr,
            e
        );
    }
}

/// Resolve the peer's metatraffic unicast address from SPDP discovery data.
///
/// Looks up the peer's GUID prefix in the DiscoveryFsm to find the metatraffic
/// unicast locator declared in their SPDP announcement. Falls back to using
/// the origin's IP + our own metatraffic port if not found.
///
/// RTPS 2.5 8.3.4 / 8.3.8.10: `origin.reply()` is `None` behind an INFO_SRC.
/// The same-IP preference below and the final fallback both need a real
/// reply address, so both apply only when one exists (`pub(super)` for
/// `heartbeat_handler`'s own tests); the FSM lookup by GUID prefix does not,
/// so a peer already known from SPDP/SEDP is still reachable when relayed.
/// A peer never seen except through a relay resolves to `None`, and the
/// caller must not send an ACKNACK.
fn resolve_peer_metatraffic_addr(
    peer_guid_prefix: &[u8; 12],
    origin: Origin,
    fallback_port: u16,
    fsm: &DiscoveryFsm,
) -> Option<SocketAddr> {
    if let Some(ep) = fsm.metatraffic_locator_for(peer_guid_prefix, origin) {
        log::debug!(
            "[HB-HANDLER] Resolved peer metatraffic locator: {} (prefix={:02x?})",
            ep,
            &peer_guid_prefix[..4]
        );
        return Some(ep);
    }
    // Peer not yet in FSM (race at startup): our own metatraffic port on the
    // reply address, when there is one; behind an INFO_SRC there is none,
    // and no ACKNACK is sent.
    let fallback = origin
        .reply()
        .map(|reply| SocketAddr::new(reply.ip(), fallback_port));
    log::debug!(
        "[HB-HANDLER] Peer not found in FSM, fallback to {:?} (prefix={:02x?})",
        fallback,
        &peer_guid_prefix[..4]
    );
    fallback
}

/// Check if entity ID is a user data writer (not built-in).
///
/// User data writers have entity kind 0x02 (WITH_KEY) or 0x03 (NO_KEY)
/// in the last byte, vs 0xC2/0xC3 for built-in endpoints
/// (RTPS v2.5 Table 9.1).
fn is_user_data_writer(entity_id: &[u8; 4]) -> bool {
    let kind = entity_id[3];
    // 0x02 = WRITER_WITH_KEY, 0x03 = WRITER_NO_KEY (user data)
    // 0xC2 = WRITER_WITH_KEY built-in, 0xC3 = WRITER_NO_KEY built-in
    kind == 0x02 || kind == 0x03
}

/// Derive reader entity ID from writer entity ID.
///
/// Entity kind pairing per RTPS v2.5 Table 9.1:
/// - 0x02 user writer WITH_KEY    -> 0x07 user reader WITH_KEY
/// - 0x03 user writer NO_KEY      -> 0x04 user reader NO_KEY
/// - 0xC2 builtin writer WITH_KEY -> 0xC7 builtin reader WITH_KEY
/// - 0xC3 builtin writer NO_KEY   -> 0xC4 builtin reader NO_KEY
fn derive_reader_entity_id(writer_id: &[u8; 4]) -> [u8; 4] {
    let mut reader_id = *writer_id;
    reader_id[3] = match writer_id[3] {
        0x02 => 0x07, // user writer WITH_KEY -> user reader WITH_KEY
        0x03 => 0x04, // user writer NO_KEY -> user reader NO_KEY
        0xC2 => 0xC7, // builtin writer WITH_KEY -> builtin reader WITH_KEY
        0xC3 => 0xC4, // builtin writer NO_KEY -> builtin reader NO_KEY
        _ => 0x04,    // unknown kind: default to user reader NO_KEY
    };
    reader_id
}

/// Parsed HEARTBEAT data
struct HeartbeatData {
    writer_entity_id: [u8; 4],
    first_seq: i64,
    last_seq: i64,
    count: u32,
    /// RTPS v2.5 Sec.8.3.8.6: FinalFlag - if set, writer expects ACKNACK response
    #[allow(dead_code)] // Reserved for future use in HEARTBEAT response logic
    _final_flag: bool,
    /// RTPS v2.5 Sec.8.3.8.6: LivelinessFlag - if set, this is a liveliness assertion
    _liveliness_flag: bool,
}

/// Parse HEARTBEAT submessage from RTPS packet.
///
/// HEARTBEAT structure (RTPS v2.5 Sec.8.3.8.6):
/// - readerEntityId: 4 bytes
/// - writerEntityId: 4 bytes
/// - firstAvailableSeqNumber: 8 bytes (i64)
/// - lastSeqNumber: 8 bytes (i64)
/// - count: 4 bytes (u32)
fn parse_heartbeat(payload: &[u8]) -> Option<HeartbeatData> {
    // Need at least RTPS header (20) + submessage header (4) + HEARTBEAT (28)
    if payload.len() < 52 {
        return None;
    }

    // Verify RTPS magic
    if &payload[0..4] != b"RTPS" {
        return None;
    }

    // Find HEARTBEAT submessage (ID = 0x07)
    let mut offset = 20; // Start after RTPS header

    while offset + 4 <= payload.len() {
        let submsg_id = payload[offset];
        let flags = payload[offset + 1];
        let is_le = flags & 0x01 != 0;

        let octets_to_next = if is_le {
            u16::from_le_bytes([payload[offset + 2], payload[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize
        };

        if submsg_id == 0x07 {
            // HEARTBEAT found
            let hb_offset = offset + 4;

            if hb_offset + 28 > payload.len() {
                return None;
            }

            // readerEntityId: 4 bytes (big-endian per RTPS spec)
            // let reader_entity_id: [u8; 4] = payload[hb_offset..hb_offset + 4].try_into().ok()?;

            // writerEntityId: 4 bytes (big-endian per RTPS spec)
            let writer_entity_id: [u8; 4] =
                payload[hb_offset + 4..hb_offset + 8].try_into().ok()?;

            // firstAvailableSeqNumber: SequenceNumber_t (RTPS v2.5 Sec.9.3.2)
            // Wire format follows struct declaration: {long high; unsigned long low}
            // CDR serializes struct fields in declaration order: high (4 bytes) then low (4 bytes)
            // The sequence value = high * 2^32 + low
            let first_seq = if is_le {
                let high =
                    i32::from_le_bytes(payload[hb_offset + 8..hb_offset + 12].try_into().ok()?);
                let low =
                    u32::from_le_bytes(payload[hb_offset + 12..hb_offset + 16].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            } else {
                let high =
                    i32::from_be_bytes(payload[hb_offset + 8..hb_offset + 12].try_into().ok()?);
                let low =
                    u32::from_be_bytes(payload[hb_offset + 12..hb_offset + 16].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            };

            // lastSeqNumber: SequenceNumber_t
            let last_seq = if is_le {
                let high =
                    i32::from_le_bytes(payload[hb_offset + 16..hb_offset + 20].try_into().ok()?);
                let low =
                    u32::from_le_bytes(payload[hb_offset + 20..hb_offset + 24].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            } else {
                let high =
                    i32::from_be_bytes(payload[hb_offset + 16..hb_offset + 20].try_into().ok()?);
                let low =
                    u32::from_be_bytes(payload[hb_offset + 20..hb_offset + 24].try_into().ok()?);
                (high as i64) * (1i64 << 32) + (low as i64)
            };

            // count: 4 bytes
            let count = if is_le {
                u32::from_le_bytes(payload[hb_offset + 24..hb_offset + 28].try_into().ok()?)
            } else {
                u32::from_be_bytes(payload[hb_offset + 24..hb_offset + 28].try_into().ok()?)
            };

            // Parse flags: bit 1 = FinalFlag, bit 2 = LivelinessFlag
            let final_flag = flags & 0x02 != 0;
            let liveliness_flag = flags & 0x04 != 0;

            return Some(HeartbeatData {
                writer_entity_id,
                first_seq,
                last_seq,
                count,
                _final_flag: final_flag,
                _liveliness_flag: liveliness_flag,
            });
        }

        // Move to next submessage
        if octets_to_next == 0 {
            break;
        }
        offset += 4 + octets_to_next;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;
    use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
    use crate::protocol::discovery::SpdpData;

    /// RTPS 2.5 8.3.4 / 8.3.8.10: a relayed origin has no reply address, so
    /// it must never stand in for a peer the FSM does not already know from
    /// SPDP/SEDP -- but a peer it DOES know is still reachable, because the
    /// FSM lookup never reads the origin's address at all.
    #[test]
    fn a_relayed_origin_only_resolves_peers_the_fsm_already_knows() {
        let fsm = DiscoveryFsm::new(GUID::new([0x11; 12], [0, 0, 1, 0xC1]), 30_000);
        let known_peer = [0x22; 12];
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(known_peer, [0, 0, 1, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec!["192.0.2.9:7410".parse().unwrap()],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });

        let forwarder: SocketAddr = "10.0.0.5:9999".parse().unwrap();

        // Direct, known peer: the FSM's own locator wins (no IP match, so
        // the first-endpoint fallback applies -- still not the forwarder).
        assert_eq!(
            resolve_peer_metatraffic_addr(&known_peer, Origin::direct(forwarder), 7410, &fsm),
            Some("192.0.2.9:7410".parse().unwrap())
        );

        // Relayed, known peer: still reachable. The FSM lookup never reads
        // the origin's address.
        assert_eq!(
            resolve_peer_metatraffic_addr(&known_peer, Origin::relayed(forwarder), 7410, &fsm),
            Some("192.0.2.9:7410".parse().unwrap()),
            "a peer already known from SPDP/SEDP stays reachable when relayed"
        );

        // Relayed, UNKNOWN peer: no reply address at all -- the forwarder
        // must never stand in for a participant it merely forwarded for.
        let unknown_peer = [0x33; 12];
        assert_eq!(
            resolve_peer_metatraffic_addr(&unknown_peer, Origin::relayed(forwarder), 7410, &fsm),
            None,
            "a relayed forwarder must never be credited as an unknown peer's address"
        );

        // Direct, UNKNOWN peer: the forwarder's address IS a real reply
        // locator, so the port-substitution fallback still applies -- this
        // is the one case where the behaviour must NOT change.
        assert_eq!(
            resolve_peer_metatraffic_addr(&unknown_peer, Origin::direct(forwarder), 7410, &fsm),
            Some("10.0.0.5:7410".parse().unwrap())
        );

        // RTPS 2.5 8.3.8.9 / 8.4.8.2.6: an INFO_REPLY naming another address
        // changes none of the four answers above.
        let named: std::net::SocketAddrV4 = "198.51.100.4:7999".parse().unwrap();
        for (peer, origin, expected) in [
            (
                known_peer,
                Origin::direct(forwarder),
                Some("192.0.2.9:7410"),
            ),
            (
                known_peer,
                Origin::relayed(forwarder),
                Some("192.0.2.9:7410"),
            ),
            (unknown_peer, Origin::relayed(forwarder), None),
            (
                unknown_peer,
                Origin::direct(forwarder),
                Some("10.0.0.5:7410"),
            ),
        ] {
            assert_eq!(
                resolve_peer_metatraffic_addr(&peer, origin.replying_to(Some(named)), 7410, &fsm),
                expected.map(|address| address.parse().unwrap())
            );
        }
    }

    #[test]
    fn test_parse_heartbeat() {
        // Build a minimal HEARTBEAT packet
        let mut packet = Vec::new();

        // RTPS Header (20 bytes)
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // Version
        packet.extend_from_slice(&[0x01, 0x0f]); // FastDDS vendor
        packet.extend_from_slice(&[0x01; 12]); // GUID prefix

        // HEARTBEAT submessage
        packet.push(0x07); // ID
        packet.push(0x01); // Flags: little-endian
        packet.extend_from_slice(&28u16.to_le_bytes()); // Length

        // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xC7]);
        // writerEntityId
        packet.extend_from_slice(&RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER);
        // firstSeq: RTPS SequenceNumber_t = {high: i32, low: u32}
        // For seq=1: high=0, low=1
        packet.extend_from_slice(&0i32.to_le_bytes()); // high
        packet.extend_from_slice(&1u32.to_le_bytes()); // low
                                                       // lastSeq: high=0, low=5
        packet.extend_from_slice(&0i32.to_le_bytes()); // high
        packet.extend_from_slice(&5u32.to_le_bytes()); // low
                                                       // count
        packet.extend_from_slice(&42u32.to_le_bytes());

        let hb = parse_heartbeat(&packet).expect("Should parse HEARTBEAT");
        assert_eq!(hb.writer_entity_id, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER);
        assert_eq!(hb.first_seq, 1);
        assert_eq!(hb.last_seq, 5);
        assert_eq!(hb.count, 42);
    }

    #[test]
    fn test_build_acknack_response() {
        let our_prefix = [1u8; 12];
        let peer_prefix = [2u8; 12];

        // Use centralized build_acknack_packet from protocol/builder/
        let missing_seqs: Vec<u64> = (1..=5).collect();
        let packet = build_acknack_packet(
            our_prefix,
            peer_prefix,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
            1, // seq_base
            &missing_seqs,
            1, // count
        );

        // Verify RTPS header
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(&packet[8..20], &our_prefix);

        // Verify INFO_DST
        assert_eq!(packet[20], 0x0e);
        assert_eq!(&packet[24..36], &peer_prefix);

        // Verify ACKNACK submessage ID
        assert_eq!(packet[36], 0x06);

        // Packet should have valid structure (header + INFO_DST + ACKNACK)
        assert!(
            packet.len() > 36,
            "Packet should include ACKNACK submessage"
        );
    }

    /// A HEARTBEAT of the participant-message writer (RTPS v2.5
    /// Sec.8.4.13), from `peer_prefix`, announcing `[first, last]` at
    /// `count`.
    fn participant_message_heartbeat_packet(
        peer_prefix: [u8; 12],
        first: i64,
        last: i64,
        count: u32,
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
        packet.extend_from_slice(&[0x01, 0x1a]); // HDDS vendor
        packet.extend_from_slice(&peer_prefix);
        packet.push(0x07); // HEARTBEAT
        packet.push(0x01); // LE
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&PARTICIPANT_MESSAGE_READER);
        packet.extend_from_slice(&RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER);
        let (first_high, first_low) = ((first >> 32) as i32, first as u32);
        packet.extend_from_slice(&first_high.to_le_bytes());
        packet.extend_from_slice(&first_low.to_le_bytes());
        let (last_high, last_low) = ((last >> 32) as i32, last as u32);
        packet.extend_from_slice(&last_high.to_le_bytes());
        packet.extend_from_slice(&last_low.to_le_bytes());
        packet.extend_from_slice(&count.to_le_bytes());
        packet
    }

    /// A real transport + a real peer socket: this is end to end through
    /// `handle_heartbeat_packet`, not a unit of the pure helper
    /// (`participant_message::reader_reply_to_heartbeat` already has its
    /// own byte-free tests).
    struct PeerHarness {
        transport: Arc<UdpTransport>,
        fsm: Arc<DiscoveryFsm>,
        peer_socket: std::net::UdpSocket,
        peer_prefix: [u8; 12],
        our_prefix: [u8; 12],
        port_mapping: crate::transport::PortMapping,
        _domain: crate::test_support::domains::DomainLease,
    }

    impl PeerHarness {
        fn new() -> Self {
            let domain = crate::test_support::domains::unique_domain();
            let port_mapping =
                crate::transport::PortMapping::calculate(domain.id(), 0).expect("port mapping");
            let transport = Arc::new(
                UdpTransport::new(domain.id(), 0, port_mapping).expect("a test transport"),
            );
            let peer_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
            peer_socket
                .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .expect("read timeout");
            let our_prefix = [0x41; 12];
            let peer_prefix = [0x42; 12];
            let fsm = Arc::new(DiscoveryFsm::new(
                GUID::new(our_prefix, [0, 0, 1, 0xC1]),
                30_000,
            ));
            fsm.handle_spdp(SpdpData {
                participant_guid: GUID::new(peer_prefix, [0, 0, 1, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: domain.id(),
                metatraffic_unicast_locators: vec![peer_socket.local_addr().expect("addr")],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: None,
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            });
            Self {
                transport,
                fsm,
                peer_socket,
                peer_prefix,
                our_prefix,
                port_mapping,
                _domain: domain,
            }
        }

        fn feed_heartbeat(&self, first: i64, last: i64, count: u32) {
            let packet = participant_message_heartbeat_packet(self.peer_prefix, first, last, count);
            handle_heartbeat_packet(
                &packet,
                Origin::direct(self.peer_socket.local_addr().expect("addr")),
                self.our_prefix,
                self.transport.clone(),
                self.port_mapping.metatraffic_unicast,
                self.fsm.clone(),
            );
        }

        /// The one ACKNACK the peer socket received, if any, within the
        /// read timeout -- a HEARTBEAT this module does not answer leaves
        /// nothing on the socket, so "none arrived" is read as a verdict,
        /// not a failure to wait long enough.
        fn recv_acknack(
            &self,
        ) -> Option<crate::core::discovery::multicast::control_types::AckNackInfo> {
            let mut buf = [0u8; 256];
            let (n, _) = self.peer_socket.recv_from(&mut buf).ok()?;
            crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages(
                &buf[..n],
            )
            .into_iter()
            .next()
        }
    }

    /// RTPS v2.5 Sec.8.4.13.3: a HEARTBEAT past what this reader holds is
    /// answered with a request for the newest sequence number alone, never
    /// the whole missing range -- an older, superseded assertion has no
    /// value under `history.depth = 1`.
    #[test]
    fn a_participant_message_heartbeat_past_what_we_hold_asks_for_the_newest_alone() {
        let h = PeerHarness::new();
        h.feed_heartbeat(1, 9, 3);
        let an = h.recv_acknack().expect("an ACKNACK was sent");
        assert_eq!(an.reader_entity_id, PARTICIPANT_MESSAGE_READER);
        assert_eq!(an.writer_entity_id, PARTICIPANT_MESSAGE_WRITER);
        assert_eq!(an.bitmap_base, 9, "the newest alone, never 1..9");
        assert_eq!(
            an.missing_ranges
                .iter()
                .map(|r| r.end - r.start)
                .sum::<u64>(),
            1,
            "exactly one sequence number requested"
        );
        assert!(an.missing_ranges.iter().any(|r| r.contains(&9)));
    }

    /// A HEARTBEAT this reader already holds the newest sample of gets a
    /// pure positive ACK: nothing to repair.
    #[test]
    fn a_participant_message_heartbeat_we_already_hold_gets_a_pure_ack() {
        let h = PeerHarness::new();
        h.fsm.note_participant_message_received(&h.peer_prefix, 9);
        h.feed_heartbeat(1, 9, 4);
        let an = h.recv_acknack().expect("a pure ACK was sent");
        assert_eq!(an.bitmap_base, 10, "one past the newest held");
        assert!(an.missing_ranges.is_empty());
    }

    /// A prefix the FSM never admitted leaves no record: nothing would ever
    /// purge it, so a stream of forged prefixes would grow the table.
    #[test]
    fn a_participant_message_from_an_unadmitted_prefix_is_not_recorded() {
        let h = PeerHarness::new();
        let stranger = [0xEE; 12];
        h.fsm.note_participant_message_received(&stranger, 5);
        assert_eq!(h.fsm.participant_message_received(&stranger), 0);
        h.fsm.note_participant_message_received(&h.peer_prefix, 5);
        assert_eq!(h.fsm.participant_message_received(&h.peer_prefix), 5);
    }
}

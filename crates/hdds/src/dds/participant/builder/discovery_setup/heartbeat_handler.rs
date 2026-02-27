// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HEARTBEAT response handler for SEDP and user data endpoints.
//!
//! v104: When receiving HEARTBEAT from remote SEDP Publications Writer,
//! respond with ACKNACK to request the announced DATA.
//!
//! v200: Extended to handle user data HEARTBEATs for RELIABLE QoS.
//! Without ACKNACK responses to user data HEARTBEATs, FastDDS keeps
//! retransmitting and floods HDDS with packets, causing pool exhaustion.
//!
//! ## Problem Solved
//! FastDDS sends HEARTBEATs for SEDP Publications (writerEntityId=0x000003c2)
//! announcing available sequence numbers, but HDDS didn't respond with ACKNACKs.
//! Without ACKNACKs, FastDDS never sends the DATA announcing its DataWriter,
//! so HDDS cannot discover the remote writer and route user data.
//!
//! ## RTPS Flow
//! 1. FastDDS sends HEARTBEAT: writerEntityId=0x000003c2, firstSeq=1, lastSeq=1
//! 2. HDDS responds with ACKNACK: readerEntityId=0x000003c7, bitmapBase=1, numBits=1
//! 3. FastDDS sends DATA with SEDP Publications announcement
//! 4. HDDS discovers the remote writer and can route user data
//!
//! ## User Data HEARTBEAT (v200)
//! For RELIABLE user data writers, we send positive ACKNACKs (no missing seqs)
//! to confirm receipt and stop retransmission flood.

use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::rtps_constants::{
    RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
};
#[cfg(test)]
use crate::protocol::builder::build_acknack_packet;
use crate::protocol::builder::build_acknack_packet_with_final;
use crate::transport::UdpTransport;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

/// Global ACKNACK counter for SEDP HEARTBEAT responses
static SEDP_ACKNACK_COUNT: AtomicU32 = AtomicU32::new(1);

/// v202: Last timestamp we sent an ACKNACK for user data (rate limiting)
/// We only respond to user data HBs every 100ms to avoid flooding
#[allow(dead_code)] // Reserved for future rate-limiting implementation
static LAST_USER_ACKNACK_TIME_MS: AtomicU64 = AtomicU64::new(0);

/// v202: Minimum interval between user data ACKNACKs (milliseconds)
#[allow(dead_code)] // Reserved for future rate-limiting implementation
const USER_ACKNACK_MIN_INTERVAL_MS: u64 = 100;

/// v202: Counter for skipped HBs (debugging)
#[allow(dead_code)] // Reserved for future rate-limiting implementation
static USER_HB_SKIPPED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Handle incoming HEARTBEAT packet and respond with ACKNACK if needed.
///
/// ## Arguments
/// - `payload`: Full RTPS packet (including headers)
/// - `src_addr`: Source address of the HEARTBEAT sender
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `transport`: UDP transport for sending ACKNACK response
/// - `peer_metatraffic_port`: Fallback metatraffic port (our own, used if peer not in FSM)
/// - `discovery_fsm`: Discovery FSM for looking up peer's actual metatraffic locator
///
/// ## v106 Fix
/// Send ACKNACK to peer's metatraffic unicast port, not the ephemeral source port.
/// FastDDS listens on port 7410 for ACKNACKs, not on its ephemeral send port.
///
/// ## v207 Fix
/// Look up the peer's actual metatraffic unicast locator from SPDP discovery data
/// instead of using our own metatraffic port. This fixes interop with FastDDS 2.x
/// when multiple participants exist on the same domain (different participant_ids
/// = different metatraffic ports).
pub(super) fn handle_heartbeat_packet(
    payload: &[u8],
    src_addr: SocketAddr,
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
        "[HB-HANDLER] v104: Received HEARTBEAT from {} - writer={:02x?} first={} last={} count={}",
        src_addr,
        hb.writer_entity_id,
        hb.first_seq,
        hb.last_seq,
        hb.count
    );

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
        } else if is_user_data_writer(&hb.writer_entity_id) {
            // v200: User data writer - derive reader entity ID
            // Writer 0xC2 -> Reader 0xC7 (or 0x04 -> 0x07 for WITH_KEY)
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
    // v110: Use centralized protocol/builder/acknack.rs instead of duplicated code
    let count = SEDP_ACKNACK_COUNT.fetch_add(1, Ordering::Relaxed);
    let first_seq_u64 = hb.first_seq.max(1) as u64;
    let last_seq_u64 = hb.last_seq.max(1) as u64;

    // v200: Different behavior for SEDP vs user data
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

    // v163: Use Final=true for SEDP ACKNACKs.
    // RTI requires Final flag to respond with DATA immediately.
    // FastDDS also sets Final=true when requesting SEDP publications.
    // Without Final=true, RTI ignores the ACKNACK and never sends DATA.
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

    // v207: Look up peer's metatraffic unicast locator from SPDP discovery data.
    // The peer's GUID prefix identifies which participant sent the HEARTBEAT.
    // We look up their declared metatraffic locator (from SPDP) to send the ACKNACK
    // to the correct port. This is essential when multiple participants exist on the
    // same domain (e.g., FastDDS EMM with participant_ids 9-13 on domain 2).
    //
    // v106 fallback: If peer not found in FSM (race condition at startup), use
    // our own metatraffic port as fallback (works when both sides are participant_id=0).
    let dest_addr = resolve_peer_metatraffic_addr(
        &peer_guid_prefix,
        src_addr,
        peer_metatraffic_port,
        &discovery_fsm,
    );

    match transport.send_to_endpoint(&acknack, &dest_addr) {
        Ok(_) => {
            if is_user_data {
                log::debug!(
                    "[HB-HANDLER] v200: Sent positive ACKNACK to {} for user data writer {:02x?} (ack up to seq {})",
                    dest_addr,
                    writer_entity_id,
                    hb.last_seq
                );
            } else {
                log::debug!(
                    "[HB-HANDLER] v106: Sent ACKNACK response to {} (was src={}) for SEDP {:02x?} (seq {}-{})",
                    dest_addr,
                    src_addr,
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

/// Resolve the peer's metatraffic unicast address from SPDP discovery data.
///
/// Looks up the peer's GUID prefix in the DiscoveryFsm to find the metatraffic
/// unicast locator declared in their SPDP announcement. Falls back to using
/// src_addr IP + our own metatraffic port if not found.
fn resolve_peer_metatraffic_addr(
    peer_guid_prefix: &[u8; 12],
    src_addr: SocketAddr,
    fallback_port: u16,
    fsm: &DiscoveryFsm,
) -> SocketAddr {
    // Look up peer in the participant database by matching GUID prefix
    let db = fsm.db();
    if let Ok(guard) = db.read() {
        for (guid, info) in guard.iter() {
            if &guid.as_bytes()[..12] == peer_guid_prefix {
                // Found the peer - use their first metatraffic unicast locator
                // that matches the source IP (prefer same interface)
                for ep in &info.endpoints {
                    if ep.ip() == src_addr.ip() {
                        log::debug!(
                            "[HB-HANDLER] v207: Resolved peer metatraffic locator from SPDP: {} (prefix={:02x?})",
                            ep, &peer_guid_prefix[..4]
                        );
                        return *ep;
                    }
                }
                // No IP match - use first available locator
                if let Some(ep) = info.endpoints.first() {
                    log::debug!(
                        "[HB-HANDLER] v207: Using first peer metatraffic locator: {} (prefix={:02x?})",
                        ep, &peer_guid_prefix[..4]
                    );
                    return *ep;
                }
            }
        }
    }

    // Fallback: peer not yet in FSM (race at startup) - use our own metatraffic port
    let fallback = SocketAddr::new(src_addr.ip(), fallback_port);
    log::debug!(
        "[HB-HANDLER] v207: Peer not found in FSM, fallback to {} (prefix={:02x?})",
        fallback,
        &peer_guid_prefix[..4]
    );
    fallback
}

/// Check if entity ID is a user data writer (not built-in).
///
/// User data writers have entity kind 0x02 (NO_KEY) or 0x03 (WITH_KEY)
/// in the last byte, vs 0xC2/0xC3 for built-in endpoints.
fn is_user_data_writer(entity_id: &[u8; 4]) -> bool {
    let kind = entity_id[3];
    // 0x02 = WRITER_NO_KEY, 0x03 = WRITER_WITH_KEY (user data)
    // 0xC2 = WRITER_NO_KEY built-in, 0xC3 = WRITER_WITH_KEY built-in
    kind == 0x02 || kind == 0x03
}

/// Derive reader entity ID from writer entity ID.
///
/// Maps writer kinds to corresponding reader kinds:
/// - 0x02 (WRITER_NO_KEY) -> 0x04 (READER_NO_KEY)
/// - 0x03 (WRITER_WITH_KEY) -> 0x07 (READER_WITH_KEY)
fn derive_reader_entity_id(writer_id: &[u8; 4]) -> [u8; 4] {
    let mut reader_id = *writer_id;
    reader_id[3] = match writer_id[3] {
        0x02 => 0x04, // NO_KEY: writer -> reader
        0x03 => 0x07, // WITH_KEY: writer -> reader
        _ => 0x04,    // Default to NO_KEY reader
    };
    reader_id
}

/// Parsed HEARTBEAT data
struct HeartbeatData {
    writer_entity_id: [u8; 4],
    first_seq: i64,
    last_seq: i64,
    count: u32,
    /// RTPS v2.5 Sec.8.3.7.5: FinalFlag - if set, writer expects ACKNACK response
    #[allow(dead_code)] // Reserved for future use in HEARTBEAT response logic
    _final_flag: bool,
    /// RTPS v2.5 Sec.8.3.7.5: LivelinessFlag - if set, this is a liveliness assertion
    _liveliness_flag: bool,
}

/// Parse HEARTBEAT submessage from RTPS packet.
///
/// HEARTBEAT structure (RTPS v2.5 Sec.8.3.7.5):
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

    #[test]
    fn test_parse_heartbeat() {
        // Build a minimal HEARTBEAT packet
        let mut packet = Vec::new();

        // RTPS Header (20 bytes)
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 3]); // Version
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

        // v110: Use centralized build_acknack_packet from protocol/builder/
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
}

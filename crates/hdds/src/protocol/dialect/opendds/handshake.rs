// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS SEDP handshake protocol
//!
//!
//! OpenDDS has a different SEDP state machine than FastDDS/RTI:
//! - It waits for bidirectional SEDP exchange before announcing user endpoints
//! - HDDS must respond to OpenDDS's builtin HEARTBEAT/ACKNACK correctly
//! - Without proper responses, OpenDDS never sends DATA(w) writer announcements
//!
//! ## PCAP Analysis (opendds2hdds.pcap)
//!
//! Key observations:
//! 1. OpenDDS sends SPDP DATA(p) on multicast 239.255.0.1:7400
//! 2. HDDS responds with SPDP DATA(p)
//! 3. OpenDDS sends HEARTBEATs/ACKNACKs on SEDP endpoints
//! 4. OpenDDS expects responses on BUILTIN_PUBLICATIONS_WRITER (0x000003c2)
//! 5. Without responses, OpenDDS never sends DATA(w)
//!
//! ## Solution
//!
//! Similar to RTI, we need to send HEARTBEATs on our SEDP writers to signal
//! "I exist, ready to exchange endpoint data" even if we have no publications.

use crate::core::discovery::multicast::rtps_packet::{
    get_publications_last_seq, get_subscriptions_last_seq,
};
use crate::protocol::builder::build_acknack_submessage;
use crate::protocol::dialect::{get_encoder, Dialect};

/// P2P BuiltinParticipantMessageWriter entity ID (RTPS v2.3 Table 9.2)
pub const SERVICE_REQUEST_WRITER: [u8; 4] = [0x00, 0x02, 0x00, 0xC2];

/// P2P BuiltinParticipantMessageReader entity ID (RTPS v2.3 Table 9.2)
pub const SERVICE_REQUEST_READER: [u8; 4] = [0x00, 0x02, 0x00, 0xC7];

/// v195: OpenDDS-specific ACKNACK packet builder with RTPS 2.4 header.
///
/// OpenDDS requires RTPS header version to match PID_PROTOCOL_VERSION (2.4).
/// The generic `build_acknack_packet` uses 2.3 which breaks OpenDDS interop.
fn build_acknack_packet_v24(
    our_guid_prefix: [u8; 12],
    dest_guid_prefix: [u8; 12],
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    seq_base: u64,
    missing_seqs: &[u64],
    count: u32,
) -> Vec<u8> {
    let encoder = get_encoder(Dialect::Hybrid);
    let mut packet = Vec::with_capacity(256);

    // RTPS Header (20 bytes) - v195: Using version 2.4 for OpenDDS
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 4]); // Version 2.4 (v195: OpenDDS requires this)
    packet.extend_from_slice(&[0x01, 0xaa]); // Vendor ID (HDDS)
    packet.extend_from_slice(&our_guid_prefix);

    // INFO_DST submessage using DialectEncoder
    let info_dst = encoder.build_info_dst(&dest_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // ACKNACK submessage
    let acknack = build_acknack_submessage(
        reader_entity_id,
        writer_entity_id,
        seq_base,
        missing_seqs,
        count,
    );
    packet.extend_from_slice(&acknack);

    packet
}

/// Build HEARTBEAT for SEDP Publications Writer.
///
/// OpenDDS requires this to complete the SEDP handshake.
/// For initial handshake (no DATA sent yet), we send firstSeq=1, lastSeq=0.
/// For subsequent handshakes, we must use the actual sequence numbers to avoid
/// confusing OpenDDS's reliable delivery state machine.
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: OpenDDS participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_sedp_publications_heartbeat(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    };

    let encoder = get_encoder(Dialect::Hybrid);
    let mut packet = Vec::with_capacity(80);

    // RTPS Header (20 bytes)
    packet.extend_from_slice(b"RTPS");
    // v195: OpenDDS requires RTPS 2.4 header version to match the protocol version
    // in PID_PROTOCOL_VERSION. Using 2.3 causes OpenDDS to reject packets.
    packet.extend_from_slice(&[2, 4]); // Version 2.4 (v195)
    packet.extend_from_slice(&[0x01, 0xaa]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // v175: Get actual sequence number from per-writer counter.
    // HDDS is typically a subscriber-only, so publications writer has no DATA.
    // lastSeq=0 is correct for "no data yet".
    let last_seq = get_publications_last_seq();
    let first_seq = 1; // firstSeq always 1 per RTPS spec

    // HEARTBEAT submessage
    let heartbeat = encoder
        .build_heartbeat(
            &RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, // their reader
            &RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, // our writer
            first_seq,                               // firstSeq = 1 (we'll send from seq 1)
            last_seq,                                // lastSeq = actual sequence number
            1,                                       // count
        )
        .unwrap_or_else(|_| Vec::new());
    packet.extend_from_slice(&heartbeat);

    log::debug!(
        "[OPENDDS-HANDSHAKE] Built SEDP Publications HEARTBEAT: our={:02x?}, peer={:02x?}, lastSeq={}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        last_seq,
        packet.len()
    );

    packet
}

/// Build HEARTBEAT for SEDP Subscriptions Writer.
///
/// OpenDDS expects to receive a HEARTBEAT from our SEDP Subscriptions Writer
/// as part of the discovery handshake.
///
/// v175: CRITICAL FIX - Must use actual sequence numbers, not hardcoded 0.
/// When HDDS has already sent DATA(r) messages, resending lastSeq=0 confuses
/// OpenDDS's reliable delivery state machine and prevents matching.
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: OpenDDS participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_sedp_subscriptions_heartbeat(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
    };

    let encoder = get_encoder(Dialect::Hybrid);
    let mut packet = Vec::with_capacity(80);

    // RTPS Header (20 bytes)
    packet.extend_from_slice(b"RTPS");
    // v195: OpenDDS requires RTPS 2.4 header version to match the protocol version
    // in PID_PROTOCOL_VERSION. Using 2.3 causes OpenDDS to reject packets.
    packet.extend_from_slice(&[2, 4]); // Version 2.4 (v195)
    packet.extend_from_slice(&[0x01, 0xaa]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // v175: Get actual sequence number from per-writer counter.
    // This is CRITICAL for HDDS subscriber - it has DATA(r) with seq numbers.
    // Sending lastSeq=0 after we've sent seq 1, 2, ... confuses OpenDDS!
    let last_seq = get_subscriptions_last_seq();
    let first_seq = 1; // firstSeq always 1 per RTPS spec

    // HEARTBEAT submessage
    let heartbeat = encoder
        .build_heartbeat(
            &RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER, // their reader
            &RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER, // our writer
            first_seq,                                // firstSeq = 1 (we'll send from seq 1)
            last_seq,                                 // lastSeq = actual sequence number
            1,                                        // count
        )
        .unwrap_or_else(|_| Vec::new());
    packet.extend_from_slice(&heartbeat);

    log::debug!(
        "[OPENDDS-HANDSHAKE] Built SEDP Subscriptions HEARTBEAT: our={:02x?}, peer={:02x?}, lastSeq={}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        last_seq,
        packet.len()
    );

    packet
}

/// Build ACKNACK request for SEDP Publications endpoint.
///
/// This tells OpenDDS "I want to receive your writer announcements starting from seq 1".
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: OpenDDS participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_sedp_publications_request(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    };

    // Request from sequence 1
    // bitmapBase=1 with empty bitmap means "I need everything from seq 1 onwards"
    let missing_seqs: Vec<u64> = vec![];

    // v195: Use OpenDDS-specific builder with RTPS 2.4 header
    let packet = build_acknack_packet_v24(
        *our_guid_prefix,
        *peer_guid_prefix,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        1, // seq_base = 1 (request from first sequence)
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[OPENDDS-HANDSHAKE] Built SEDP Publications ACKNACK request: our={:02x?}, peer={:02x?}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        packet.len()
    );

    packet
}

/// Build ACKNACK request for SEDP Subscriptions endpoint.
///
/// v185: OpenDDS expects ACKNACKs on ALL SEDP builtin readers, not just Publications.
/// PCAP analysis shows OpenDDS sends 5 ACKNACKs immediately after SPDP discovery:
/// - SEDP_PUBLICATIONS_READER (0x000003c7)
/// - SEDP_SUBSCRIPTIONS_READER (0x000004c7)
/// - PARTICIPANT_MESSAGE_READER (0x000200c7)
/// - TYPE_LOOKUP_REQUEST_READER (0x000300c4) - optional, not all OpenDDS versions
/// - TYPE_LOOKUP_REPLY_READER (0x000301c4) - optional, not all OpenDDS versions
///
/// Without these ACKNACKs, OpenDDS delays sending DATA(w) by several seconds.
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: OpenDDS participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_sedp_subscriptions_request(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
    };

    // Request from sequence 1
    // bitmapBase=1 with empty bitmap means "I need everything from seq 1 onwards"
    let missing_seqs: Vec<u64> = vec![];

    // v195: Use OpenDDS-specific builder with RTPS 2.4 header
    let packet = build_acknack_packet_v24(
        *our_guid_prefix,
        *peer_guid_prefix,
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
        1, // seq_base = 1 (request from first sequence)
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[OPENDDS-HANDSHAKE] v185: Built SEDP Subscriptions ACKNACK request: our={:02x?}, peer={:02x?}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        packet.len()
    );

    packet
}

/// Build ACKNACK request for Participant Message endpoint (P2P builtin).
///
/// v185: OpenDDS uses P2P BuiltinParticipantMessage for liveliness/management.
/// Sending an ACKNACK on this endpoint signals readiness to receive liveliness data.
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: OpenDDS participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_participant_message_request(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    // Request from sequence 1
    let missing_seqs: Vec<u64> = vec![];

    // v195: Use OpenDDS-specific builder with RTPS 2.4 header
    let packet = build_acknack_packet_v24(
        *our_guid_prefix,
        *peer_guid_prefix,
        SERVICE_REQUEST_READER, // 0x000200C7 - P2P Participant Message Reader
        SERVICE_REQUEST_WRITER, // 0x000200C2 - P2P Participant Message Writer
        1,                      // seq_base = 1 (request from first sequence)
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[OPENDDS-HANDSHAKE] v185: Built Participant Message ACKNACK request: our={:02x?}, peer={:02x?}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        packet.len()
    );

    packet
}

/// Build ACKNACK confirmation for received SEDP DATA(w).
///
/// v186: OpenDDS requires an ACKNACK after receiving SEDP DATA(w) to complete
/// its reliable delivery state machine. Without this, discovery stalls.
///
/// Reference PCAP (reference.pcapng, OpenDDS <-> OpenDDS) shows:
/// - Frame 11: Publisher sends DATA(w)
/// - Frame 13: **Subscriber sends ACKNACK** (acknowledging the DATA)
/// - Frame 14: Subscriber sends DATA(r)
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: OpenDDS participant GUID prefix (12 bytes)
/// - `writer_entity_id`: Entity ID of the writer that sent DATA(w) (e.g., 0x000003c2)
/// - `received_seq`: Sequence number of the received DATA
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_sedp_data_confirmation(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
    writer_entity_id: &[u8; 4],
    received_seq: i64,
) -> Vec<u8> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
    };

    // Map writer entity ID to matching reader entity ID
    // Writer 0x000003c2 (Publications) -> Reader 0x000003c7
    // Writer 0x000004c2 (Subscriptions) -> Reader 0x000004c7
    let reader_entity_id = match writer_entity_id {
        id if id == &RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER => {
            RTPS_ENTITYID_SEDP_PUBLICATIONS_READER
        }
        id if id == &RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER => {
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER
        }
        _ => {
            // Unknown writer, use Publications reader as default
            log::debug!(
                "[OPENDDS-HANDSHAKE] v186: Unknown writer entity ID {:02x?}, using Publications Reader",
                writer_entity_id
            );
            RTPS_ENTITYID_SEDP_PUBLICATIONS_READER
        }
    };

    // ACK everything up to and including received_seq
    // bitmapBase = received_seq + 1, empty bitmap = "received all up to received_seq"
    let seq_base = (received_seq + 1) as u64;
    let missing_seqs: Vec<u64> = vec![];

    // v195: Use OpenDDS-specific builder with RTPS 2.4 header
    let packet = build_acknack_packet_v24(
        *our_guid_prefix,
        *peer_guid_prefix,
        reader_entity_id,
        *writer_entity_id,
        seq_base,
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[OPENDDS-HANDSHAKE] v186: Built SEDP DATA confirmation ACKNACK: writer={:02x?}, seq={}, bitmapBase={}, size={}",
        writer_entity_id,
        received_seq,
        seq_base,
        packet.len()
    );

    packet
}

/// Build empty HEARTBEAT for Service-Request Writer (P2P BuiltinParticipantMessage).
///
/// OpenDDS may use this endpoint for liveliness/participant management.
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: OpenDDS participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_service_request_heartbeat(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    let encoder = get_encoder(Dialect::Hybrid);
    let mut packet = Vec::with_capacity(80);

    // RTPS Header (20 bytes)
    packet.extend_from_slice(b"RTPS");
    // v195: OpenDDS requires RTPS 2.4 header version to match the protocol version
    // in PID_PROTOCOL_VERSION. Using 2.3 causes OpenDDS to reject packets.
    packet.extend_from_slice(&[2, 4]); // Version 2.4 (v195)
    packet.extend_from_slice(&[0x01, 0xaa]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // HEARTBEAT submessage
    // Empty heartbeat: firstSeq=1, lastSeq=0 means "writer exists, no data yet"
    let heartbeat = encoder
        .build_heartbeat(
            &SERVICE_REQUEST_READER, // their reader
            &SERVICE_REQUEST_WRITER, // our writer
            1,                       // firstSeq = 1 (we'll send from seq 1)
            0,                       // lastSeq = 0 (no data yet - empty heartbeat)
            1,                       // count
        )
        .unwrap_or_else(|_| Vec::new());
    packet.extend_from_slice(&heartbeat);

    log::debug!(
        "[OPENDDS-HANDSHAKE] Built Service-Request HEARTBEAT: our={:02x?}, peer={:02x?}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        packet.len()
    );

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_sedp_publications_heartbeat() {
        let our_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let peer_prefix = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];

        let packet = build_sedp_publications_heartbeat(&our_prefix, &peer_prefix);

        // Verify RTPS header
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(packet[4], 2); // Protocol version major
        assert_eq!(packet[5], 4); // Protocol version minor (v195: 2.4 for OpenDDS)
        assert_eq!(&packet[6..8], &[0x01, 0xaa]); // HDDS vendor ID
        assert_eq!(&packet[8..20], &our_prefix[..]); // Our GUID prefix

        // Verify INFO_DST submessage
        assert_eq!(packet[20], 0x0e); // INFO_DST ID
    }

    #[test]
    fn test_build_sedp_publications_request() {
        let our_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let peer_prefix = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];

        let packet = build_sedp_publications_request(&our_prefix, &peer_prefix);

        // Verify RTPS header
        assert_eq!(&packet[0..4], b"RTPS");

        // Verify ACKNACK submessage exists
        assert!(packet.len() > 36); // At least header + INFO_DST + ACKNACK
    }
}

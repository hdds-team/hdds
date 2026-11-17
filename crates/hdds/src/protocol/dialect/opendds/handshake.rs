// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP handshake packets of the OpenDDS dialect (vendor 0x0103).
//!
//! Once a remote participant of this vendor is discovered through SPDP, the
//! dialect does not wait for the periodic reliable-protocol traffic: it sends
//! at once, addressed with INFO_DST to that participant,
//! - a HEARTBEAT from each of our SEDP publications, SEDP subscriptions and
//!   participant-message writers, announcing the sequence range they hold
//!   (an empty range, firstSN=1 lastSN=0, when nothing was written yet);
//! - a pre-emptive ACKNACK from each matching builtin reader, requesting
//!   everything from sequence number 1.
//!
//! Both are ordinary reliable-protocol submessages (DDSI-RTPS 2.5 8.3.7.1
//! AckNack, 8.3.7.5 Heartbeat, 8.3.7.7 InfoDestination); sending them early
//! lets each side's builtin reliable readers request the other side's
//! endpoint announcements without waiting for the first periodic HEARTBEAT.

use crate::core::discovery::multicast::rtps_packet::{
    get_publications_last_seq, get_subscriptions_last_seq,
};
use crate::protocol::builder::build_acknack_submessage;
use crate::protocol::dialect::{get_encoder, Dialect};

/// P2P BuiltinParticipantMessageWriter entity ID (RTPS v2.3 Table 9.2)
pub const SERVICE_REQUEST_WRITER: [u8; 4] = [0x00, 0x02, 0x00, 0xC2];

/// P2P BuiltinParticipantMessageReader entity ID (RTPS v2.3 Table 9.2)
pub const SERVICE_REQUEST_READER: [u8; 4] = [0x00, 0x02, 0x00, 0xC7];

/// ACKNACK packet builder of this dialect, with an RTPS 2.4 header.
///
/// The dialect advertises protocol version 2.4 in PID_PROTOCOL_VERSION and
/// stamps the same version in the RTPS header of every packet it builds, so
/// the two never disagree. The generic `build_acknack_packet` stamps 2.3.
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

    // RTPS Header (20 bytes), protocol version 2.4 (see above)
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 4]); // Version 2.4
    packet.extend_from_slice(&[0x01, 0x1a]); // Vendor ID (HDDS)
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
/// Part of the dialect's discovery handshake (see module docs).
/// For initial handshake (no DATA sent yet), we send firstSeq=1, lastSeq=0.
/// For subsequent handshakes, we must use the actual sequence numbers to avoid
/// announcing a range that contradicts what the peer already received.
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
    // Protocol version 2.4, the version this dialect advertises in
    // PID_PROTOCOL_VERSION (see `build_acknack_packet_v24`).
    packet.extend_from_slice(&[2, 4]); // Version 2.4
    packet.extend_from_slice(&[0x01, 0x1a]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // Actual last sequence number of our SEDP publications writer; 0 while
    // it has written nothing (empty range firstSN=1, lastSN=0).
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
/// Part of the dialect's discovery handshake (see module docs).
///
/// lastSN is the writer's actual last sequence number, not a constant 0:
/// once DATA(r) samples were sent, a HEARTBEAT with lastSN=0 would announce
/// an empty writer and contradict the samples the peer already holds
/// (DDSI-RTPS 2.5 8.3.7.5).
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
    // Protocol version 2.4, the version this dialect advertises in
    // PID_PROTOCOL_VERSION (see `build_acknack_packet_v24`).
    packet.extend_from_slice(&[2, 4]); // Version 2.4
    packet.extend_from_slice(&[0x01, 0x1a]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // Actual last sequence number of our SEDP subscriptions writer: once
    // DATA(r) samples were sent, lastSN=0 would contradict them.
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
/// Requests the peer's writer announcements from sequence number 1 onwards.
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

    // Dialect ACKNACK builder (RTPS 2.4 header)
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
/// The dialect sends a pre-emptive ACKNACK from each of its builtin reliable
/// readers, not only the publications reader:
/// - SEDP_PUBLICATIONS_READER (0x000003c7)
/// - SEDP_SUBSCRIPTIONS_READER (0x000004c7)
/// - PARTICIPANT_MESSAGE_READER (0x000200c7)
///
/// so the peer's writers can send their samples without waiting for the
/// first periodic HEARTBEAT / ACKNACK round.
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

    // Dialect ACKNACK builder (RTPS 2.4 header)
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
        "[OPENDDS-HANDSHAKE] Built SEDP Subscriptions ACKNACK request: our={:02x?}, peer={:02x?}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        packet.len()
    );

    packet
}

/// Build ACKNACK request for Participant Message endpoint (P2P builtin).
///
/// The BuiltinParticipantMessage endpoints carry writer liveliness
/// (Writer Liveliness Protocol of DDSI-RTPS 2.5). The ACKNACK requests the
/// peer's samples from sequence number 1.
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

    // Dialect ACKNACK builder (RTPS 2.4 header)
    let packet = build_acknack_packet_v24(
        *our_guid_prefix,
        *peer_guid_prefix,
        SERVICE_REQUEST_READER, // P2P Participant Message Reader
        SERVICE_REQUEST_WRITER, // P2P Participant Message Writer
        1,                      // seq_base = 1 (request from first sequence)
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[OPENDDS-HANDSHAKE] Built Participant Message ACKNACK request: our={:02x?}, peer={:02x?}, size={}",
        &our_guid_prefix[..4],
        &peer_guid_prefix[..4],
        packet.len()
    );

    packet
}

/// Build ACKNACK confirmation for received SEDP DATA(w).
///
/// When the dialect receives an SEDP DATA(w) from the peer, it acknowledges
/// it at once with a positive ACKNACK (bitmapBase = received SN + 1, empty
/// bitmap) from the matching builtin reader, instead of waiting for the
/// peer's next HEARTBEAT (DDSI-RTPS 2.5 8.3.7.1).
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
                "[OPENDDS-HANDSHAKE] Unknown writer entity ID {:02x?}, using Publications Reader",
                writer_entity_id
            );
            RTPS_ENTITYID_SEDP_PUBLICATIONS_READER
        }
    };

    // ACK everything up to and including received_seq
    // bitmapBase = received_seq + 1, empty bitmap = "received all up to received_seq"
    let seq_base = (received_seq + 1) as u64;
    let missing_seqs: Vec<u64> = vec![];

    // Dialect ACKNACK builder (RTPS 2.4 header)
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
        "[OPENDDS-HANDSHAKE] Built SEDP DATA confirmation ACKNACK: writer={:02x?}, seq={}, bitmapBase={}, size={}",
        writer_entity_id,
        received_seq,
        seq_base,
        packet.len()
    );

    packet
}

/// HEARTBEAT of the Service-Request Writer (P2P BuiltinParticipantMessage).
///
/// Part of the dialect's discovery handshake (see module docs); the
/// BuiltinParticipantMessage endpoints carry writer liveliness. It
/// announces the writer's last liveliness assertion alone, or 1, 0 before
/// the first (`dds::liveliness::handshake_heartbeat`), in an RTPS 2.4
/// message, the version this dialect advertises in PID_PROTOCOL_VERSION
/// (see `build_acknack_packet_v24`).
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
    let (first, last, count) = crate::dds::liveliness::handshake_heartbeat(our_guid_prefix);
    let packet = crate::protocol::rtps::participant_message::build_participant_message_heartbeat(
        our_guid_prefix,
        peer_guid_prefix,
        first,
        last,
        count,
        (2, 4),
    )
    .unwrap_or_default();

    log::debug!(
        "[OPENDDS-HANDSHAKE] Built Service-Request HEARTBEAT [{}, {}]: our={:02x?}, peer={:02x?}, size={}",
        first,
        last,
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
        assert_eq!(packet[5], 4); // Protocol version minor (2.4 in this dialect)
        assert_eq!(&packet[6..8], &[0x01, 0x1a]); // HDDS vendor ID
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

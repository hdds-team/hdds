// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery handshake packets of the RTI dialect.
//!
//! Empty HEARTBEATs from our SEDP publications and subscriptions writers and
//! from the P2P BuiltinParticipantMessage writer (entity ids 0x000003c2,
//! 0x000004c2, 0x000200c2; RTPS 2.5 Table 9.2), sent when a peer is
//! discovered, before SEDP data. An empty HEARTBEAT (firstSN 1, lastSN 0)
//! is legal (RTPS 2.5 Sec.8.3.8.6).
//!
//! 0x000200C2/0x000200C7 are the spec's P2P participant-message endpoints
//! (RTPS 2.5 Sec.8.4.13), not the service-request endpoints a vendor 0x0101
//! participant announces in PID_VENDOR_BUILTIN_ENDPOINT_SET (0x00020082/87
//! in the public Wireshark RTPS dissector).

use crate::core::discovery::multicast::rtps_packet::{
    get_publications_last_seq, get_subscriptions_last_seq,
};
use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
use crate::protocol::builder::build_acknack_packet;
use crate::protocol::dialect::{get_encoder, Dialect};

/// P2P BuiltinParticipantMessageWriter entity ID (RTPS v2.5 Table 9.2).
/// The entityKind octet 0xC2/0xC7 marks a builtin endpoint (Table 9.1).
pub const P2P_PARTICIPANT_MESSAGE_WRITER: [u8; 4] =
    crate::protocol::rtps::participant_message::PARTICIPANT_MESSAGE_WRITER;

/// P2P BuiltinParticipantMessageReader entity ID (RTPS v2.5 Table 9.2).
pub const P2P_PARTICIPANT_MESSAGE_READER: [u8; 4] =
    crate::protocol::rtps::participant_message::PARTICIPANT_MESSAGE_READER;

/// Build preemptive ACKNACK to the peer's P2P participant-message writer.
///
/// ## Purpose
/// An ACKNACK to the P2P participant-message endpoints before SEDP, without
/// a full reliable QoS implementation.
///
/// ## RTPS Structure (Sec.8.3.8.1)
/// - INFO_DST: Target participant GUID prefix
/// - ACKNACK:
///   - readerEntityId: our P2P message reader (0x000200C7)
///   - writerEntityId: their P2P message writer (0x000200C2)
///   - readerSNState: SequenceNumberSet { base: 0, numBits: 0 } (preemptive)
///   - count: 1
///
/// ## Fixed ACKNACK format for interop
/// Changed from NACK (bitmapBase=1, numBits=32, all bits set) to preemptive ACKNACK
/// (bitmapBase=0, numBits=0), which says "I have nothing yet, ready to
/// receive from sequence 1". The previous format was incorrectly requesting
/// sequences 1-32 which violated RTPS protocol (can't NACK samples not announced).
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: Remote participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
///
/// Refactored to use centralized protocol/builder/acknack.rs
/// Fixed to use preemptive ACKNACK (empty bitmap)
#[allow(dead_code)] // Part of RTI dialect handshake API
pub fn build_participant_message_acknack(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    // Preemptive ACKNACK = empty bitmap, base 0
    // This says "I have nothing, please send everything from seq 1"
    let missing_seqs: Vec<u64> = vec![];

    let packet = build_acknack_packet(
        *our_guid_prefix,
        *peer_guid_prefix,
        P2P_PARTICIPANT_MESSAGE_READER,
        P2P_PARTICIPANT_MESSAGE_WRITER,
        0, // seq_base = 0 for preemptive ACKNACK
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[P2P-MESSAGE] Built ACKNACK packet: our_prefix={:02x?}, peer_prefix={:02x?}, size={} bytes",
        &our_guid_prefix[..],
        &peer_guid_prefix[..],
        packet.len()
    );

    packet
}

/// Build preemptive ACKNACK for SEDP Publications endpoint.
///
/// ## Purpose
/// For vendor id 0x0101 we send an explicit ACKNACK request to the remote SEDP
/// Publications Writer to solicit its DataWriter announcements.
///
/// ## RTPS Structure (Sec.8.3.8.1)
/// - INFO_DST: Target participant GUID prefix
/// - ACKNACK:
///   - readerEntityId: SEDP Publications Reader (0x000003c7) - us
///   - writerEntityId: SEDP Publications Writer (0x000003c2) - them
///   - readerSNState: SequenceNumberSet { base: 0, numBits: 0 } (preemptive)
///   - count: 1
///
/// ## Fixed ACKNACK format for interop
/// Changed from NACK to preemptive ACKNACK (bitmapBase=0, numBits=0).
/// See build_participant_message_acknack for detailed explanation.
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: Remote participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
///
/// Refactored to use centralized protocol/builder/acknack.rs
/// Fixed to request from sequence 1 (not 0)
///
/// Per RTPS spec Sec.8.3.8.1:
/// - bitmapBase = first sequence number we want
/// - empty bitmap (numBits=0) = we have nothing, want everything from bitmapBase
///
/// bitmapBase=1 tells the writer "I haven't received seq 1, please send it".
#[allow(dead_code)] // Part of RTI dialect handshake API, used for SEDP publication requests
pub fn build_sedp_publications_request(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    };

    // Request from sequence 1 (not 0)
    // bitmapBase=1 with empty bitmap means "I need everything from seq 1 onwards"
    let missing_seqs: Vec<u64> = vec![];

    let packet = build_acknack_packet(
        *our_guid_prefix,
        *peer_guid_prefix,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        1, // seq_base = 1 (request from first sequence)
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[SEDP-REQUEST] Built SEDP Publications ACKNACK: our_prefix={:02x?}, peer_prefix={:02x?}, size={} bytes",
        &our_guid_prefix[..],
        &peer_guid_prefix[..],
        packet.len()
    );

    packet
}

/// Build empty HEARTBEAT for SEDP Publications Writer.
///
/// ## Purpose
/// For vendor id 0x0101 we answer an ACKNACK requesting our publications with a
/// HEARTBEAT from our SEDP Publications Writer (symmetric handshake).
///
/// Even if we're a pure subscriber with no publications to announce, we still
/// respond with an empty HEARTBEAT (firstSeq=1, lastSeq=0, DDSI-RTPS 2.5
/// Sec.8.3.8.6) to complete the handshake.
///
/// ## RTPS Structure (Sec.8.3.8.6)
/// - INFO_DST: Target participant GUID prefix
/// - HEARTBEAT:
///   - readerEntityId: SEDP Publications Reader (0x000003C7) - them
///   - writerEntityId: SEDP Publications Writer (0x000003C2) - us
///   - firstSN: 1 (we will send from seq 1)
///   - lastSN: 0 (no data yet - empty heartbeat)
///   - count: 1
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: Remote participant GUID prefix (12 bytes)
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
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // Protocol version
    packet.extend_from_slice(&[0x01, 0x1a]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // Get actual sequence number from per-writer counter.
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
        "[SEDP-HEARTBEAT] Built SEDP Publications HEARTBEAT: our_prefix={:02x?}, peer_prefix={:02x?}, lastSeq={}, size={} bytes",
        &our_guid_prefix[..],
        &peer_guid_prefix[..],
        last_seq,
        packet.len()
    );

    packet
}

/// Build HEARTBEAT for SEDP Subscriptions Writer.
///
/// ## Purpose
/// For vendor id 0x0101 we send a HEARTBEAT from our SEDP Subscriptions Writer
/// as soon as the peer is discovered. This "empty HEARTBEAT" (firstSeq=1,
/// lastSeq=0) signals "I'm a writer, no data yet, but ready to send".
///
/// CRITICAL FIX - Must use actual sequence numbers, not hardcoded 0.
/// When HDDS has already sent DATA(r) messages, resending lastSeq=0 confuses
/// the peer's reliable delivery state machine and prevents matching.
///
/// ## RTPS Structure (Sec.8.3.8.6)
/// - INFO_DST: Target participant GUID prefix
/// - HEARTBEAT:
///   - readerEntityId: SEDP Subscriptions Reader (0x000004C7) - them
///   - writerEntityId: SEDP Subscriptions Writer (0x000004C2) - us
///   - firstSN: 1 (we will send from seq 1)
///   - lastSN: actual sequence number from per-writer counter
///   - count: 1
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: Remote participant GUID prefix (12 bytes)
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
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // Protocol version
    packet.extend_from_slice(&[0x01, 0x1a]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // Get actual sequence number from per-writer counter.
    // This is CRITICAL for HDDS subscriber - it has DATA(r) with seq numbers.
    // Sending lastSeq=0 after we've sent seq 1, 2, ... confuses the peer!
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
        "[SEDP-HEARTBEAT] Built SEDP Subscriptions HEARTBEAT: our_prefix={:02x?}, peer_prefix={:02x?}, lastSeq={}, size={} bytes",
        &our_guid_prefix[..],
        &peer_guid_prefix[..],
        last_seq,
        packet.len()
    );

    packet
}

/// HEARTBEAT of the P2P BuiltinParticipantMessage writer, sent in the RTI
/// dialect's initial handshake: "I have this writer endpoint".
///
/// ## RTPS Structure (Sec.8.3.8.6)
/// - INFO_DST: Target participant GUID prefix
/// - HEARTBEAT:
///   - readerEntityId: P2P BuiltinParticipantMessage Reader (0x000200C7) - them
///   - writerEntityId: P2P BuiltinParticipantMessage Writer (0x000200C2) - us
///   - firstSN, lastSN: the writer's last liveliness assertion alone, or
///     1, 0 before the first (`dds::liveliness::handshake_heartbeat`)
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: Remote participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
pub fn build_participant_message_heartbeat(
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
        (RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR),
    )
    .unwrap_or_default();

    log::debug!(
        "[P2P-MESSAGE] Built HEARTBEAT [{}, {}]: our_prefix={:02x?}, peer_prefix={:02x?}, size={} bytes",
        first,
        last,
        &our_guid_prefix[..],
        &peer_guid_prefix[..],
        packet.len()
    );

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_participant_message_acknack() {
        let our_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let peer_prefix = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];

        let packet = build_participant_message_acknack(&our_prefix, &peer_prefix);

        // Verify RTPS header
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(packet[4], RTPS_VERSION_MAJOR); // Protocol version major
        assert_eq!(packet[5], RTPS_VERSION_MINOR); // Protocol version minor
        assert_eq!(&packet[6..8], &[0x01, 0x1a]); // HDDS vendor ID
        assert_eq!(&packet[8..20], &our_prefix[..]); // Our GUID prefix

        // Verify INFO_DST submessage
        assert_eq!(packet[20], 0x0e); // INFO_DST ID
        assert_eq!(packet[21], 0x01); // Flags
        assert_eq!(&packet[24..36], &peer_prefix[..]); // Peer GUID prefix

        // Verify ACKNACK submessage
        assert_eq!(packet[36], 0x06); // ACKNACK ID
        assert_eq!(packet[37], 0x01); // Flags (E=1, F=0)
        assert_eq!(&packet[40..44], &P2P_PARTICIPANT_MESSAGE_READER[..]); // readerEntityId
        assert_eq!(&packet[44..48], &P2P_PARTICIPANT_MESSAGE_WRITER[..]); // writerEntityId

        // Preemptive ACKNACK (bitmapBase=0, numBits=0, no bitmap)
        // Total size: 20 (header) + 16 (INFO_DST) + 28 (ACKNACK submsg) = 64 bytes
        // ACKNACK: 4 (submsg hdr) + 24 (body) = 28 bytes
        // Body: 4 (reader) + 4 (writer) + 8 (base) + 4 (numBits) + 0 (no bitmap) + 4 (count) = 24
        assert_eq!(packet.len(), 64);

        // Verify bitmapBase is 0 and numBits is 0 (preemptive ACKNACK)
        // bitmapBase starts at offset 48 (after submsg hdr + entity IDs)
        let bitmap_base = i32::from_le_bytes([packet[48], packet[49], packet[50], packet[51]])
            as i64
            * (1i64 << 32)
            + u32::from_le_bytes([packet[52], packet[53], packet[54], packet[55]]) as i64;
        assert_eq!(
            bitmap_base, 0,
            "bitmapBase should be 0 for preemptive ACKNACK"
        );

        let num_bits = u32::from_le_bytes([packet[56], packet[57], packet[58], packet[59]]);
        assert_eq!(num_bits, 0, "numBits should be 0 for preemptive ACKNACK");
    }
}

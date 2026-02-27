// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI Service-request builtin endpoints (RTPS Sec.8.5.5.2)
//!
//!
//! RTI/FastDDS use P2P BuiltinParticipantMessage endpoints (entity IDs 0x000200C2/0x000200C7)
//! for reliability handshakes BEFORE sending SEDP publications.
//!
//! This module provides minimal responses to satisfy RTI's handshake protocol.
//! Full implementation would handle liveliness, participant management, etc.
//!
//! v110: Refactored to use centralized protocol/builder/acknack.rs

use crate::core::discovery::multicast::rtps_packet::{
    get_publications_last_seq, get_subscriptions_last_seq,
};
use crate::protocol::builder::build_acknack_packet;
use crate::protocol::dialect::{get_encoder, Dialect};

/// P2P BuiltinParticipantMessageWriter entity ID (RTPS v2.3 Table 9.2)
/// v103: Fix EntityIDs from 0x82/0x87 to 0xC2/0xC7 per RTPS spec.
/// The entityKind byte must have bit 7 set (0xC2) to indicate builtin endpoint.
/// FastDDS uses these correct values and ignores incorrect 0x82/0x87.
pub const SERVICE_REQUEST_WRITER: [u8; 4] = [0x00, 0x02, 0x00, 0xC2];

/// P2P BuiltinParticipantMessageReader entity ID (RTPS v2.3 Table 9.2)
/// v103: Fix EntityIDs from 0x82/0x87 to 0xC2/0xC7 per RTPS spec.
pub const SERVICE_REQUEST_READER: [u8; 4] = [0x00, 0x02, 0x00, 0xC7];

/// Build preemptive ACKNACK for service-request handshake.
///
/// ## Purpose
/// RTI expects ACKNACKs to service-request endpoints before sending SEDP.
/// This minimal handshake satisfies RTI without full reliable QoS implementation.
///
/// ## RTPS Structure (Sec.8.3.7.1)
/// - INFO_DST: Target participant GUID prefix
/// - ACKNACK:
///   - readerEntityId: our P2P message reader (0x000200C7)
///   - writerEntityId: their P2P message writer (0x000200C2)
///   - readerSNState: SequenceNumberSet { base: 0, numBits: 0 } (preemptive)
///   - count: 1
///
/// ## v127: Fixed ACKNACK format for RTI compatibility
/// Changed from NACK (bitmapBase=1, numBits=32, all bits set) to preemptive ACKNACK
/// (bitmapBase=0, numBits=0). FastDDS/RTI use this format to say "I have nothing yet,
/// ready to receive from sequence 1". The previous format was incorrectly requesting
/// sequences 1-32 which violated RTPS protocol (can't NACK samples not announced).
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: RTI participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
///
/// v110: Refactored to use centralized protocol/builder/acknack.rs
/// v127: Fixed to use preemptive ACKNACK (empty bitmap)
#[allow(dead_code)] // Part of RTI handshake API, used for service request ACKNACKs
pub fn build_service_request_acknack(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    // v127: Preemptive ACKNACK = empty bitmap, base 0
    // This says "I have nothing, please send everything from seq 1"
    let missing_seqs: Vec<u64> = vec![];

    let packet = build_acknack_packet(
        *our_guid_prefix,
        *peer_guid_prefix,
        SERVICE_REQUEST_READER,
        SERVICE_REQUEST_WRITER,
        0, // seq_base = 0 for preemptive ACKNACK
        &missing_seqs,
        1, // count
    );

    log::debug!(
        "[SERVICE-REQUEST] Built ACKNACK packet: our_prefix={:02x?}, peer_prefix={:02x?}, size={} bytes",
        &our_guid_prefix[..],
        &peer_guid_prefix[..],
        packet.len()
    );

    packet
}

/// Build preemptive ACKNACK for SEDP Publications endpoint.
///
/// ## Purpose
/// RTI requires explicit ACKNACK requests to SEDP Publications Writer before it will
/// send DataWriter announcements. Without this, RTI silently withholds endpoint discovery.
///
/// ## RTPS Structure (Sec.8.3.7.1)
/// - INFO_DST: Target participant GUID prefix
/// - ACKNACK:
///   - readerEntityId: SEDP Publications Reader (0x000003c7) - us
///   - writerEntityId: SEDP Publications Writer (0x000003c2) - them
///   - readerSNState: SequenceNumberSet { base: 0, numBits: 0 } (preemptive)
///   - count: 1
///
/// ## v127: Fixed ACKNACK format for RTI compatibility
/// Changed from NACK to preemptive ACKNACK (bitmapBase=0, numBits=0).
/// See build_service_request_acknack for detailed explanation.
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: RTI participant GUID prefix (12 bytes)
///
/// ## Returns
/// Complete RTPS packet ready to send via UDP
///
/// v110: Refactored to use centralized protocol/builder/acknack.rs
/// v129: Fixed to request from sequence 1 (not 0)
///
/// Per RTPS spec Sec.8.3.7.1:
/// - bitmapBase = first sequence number we want
/// - empty bitmap (numBits=0) = we have nothing, want everything from bitmapBase
///
/// bitmapBase=1 tells RTI "I haven't received seq 1, please send it"
/// This matches what FastDDS sends when connecting to RTI.
#[allow(dead_code)] // Part of RTI handshake API, used for SEDP publication requests
pub fn build_sedp_publications_request(
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: &[u8; 12],
) -> Vec<u8> {
    use crate::core::rtps_constants::{
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    };

    // v129: Request from sequence 1 (not 0)
    // bitmapBase=1 with empty bitmap means "I need everything from seq 1 onwards"
    let missing_seqs: Vec<u64> = vec![];

    let packet = build_acknack_packet(
        *our_guid_prefix,
        *peer_guid_prefix,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
        RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        1, // v129: seq_base = 1 (request from first sequence)
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
/// ## Purpose (v130)
/// RTI expects to receive a HEARTBEAT from our SEDP Publications Writer when
/// it sends us an ACKNACK requesting our publications. Without this response,
/// RTI won't send us its own SEDP Publications DATA (symmetric handshake).
///
/// Even if we're a pure subscriber with no publications to announce, we must
/// still respond with an empty HEARTBEAT (firstSeq=1, lastSeq=0) to complete
/// the handshake and trigger RTI to send its writer announcements.
///
/// ## RTPS Structure (Sec.8.3.7.1)
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
/// - `peer_guid_prefix`: RTI participant GUID prefix (12 bytes)
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
    packet.extend_from_slice(&[2, 3]); // Version 2.3
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
/// ## Purpose (v129)
/// RTI expects to receive a HEARTBEAT from our SEDP Subscriptions Writer before
/// it will send its SEDP Publications DATA. This "empty HEARTBEAT" (firstSeq=1,
/// lastSeq=0) signals "I'm a writer, no data yet, but ready to send".
///
/// FastDDS sends this pattern immediately upon discovering a peer. Without it,
/// RTI may wait indefinitely for our subscription announcements.
///
/// v175: CRITICAL FIX - Must use actual sequence numbers, not hardcoded 0.
/// When HDDS has already sent DATA(r) messages, resending lastSeq=0 confuses
/// the peer's reliable delivery state machine and prevents matching.
///
/// ## RTPS Structure (Sec.8.3.7.1)
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
/// - `peer_guid_prefix`: RTI participant GUID prefix (12 bytes)
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
    packet.extend_from_slice(&[2, 3]); // Version 2.3
    packet.extend_from_slice(&[0x01, 0xaa]); // Vendor ID (HDDS)
    packet.extend_from_slice(our_guid_prefix);

    // INFO_DST submessage (targeting peer)
    let info_dst = encoder.build_info_dst(peer_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // v175: Get actual sequence number from per-writer counter.
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

/// Build empty HEARTBEAT for Service-Request Writer (P2P BuiltinParticipantMessage).
///
/// ## Purpose (v131)
/// FastDDS sends HEARTBEAT for 0x000200c2 (P2P BuiltinParticipantMessage Writer)
/// as part of its initial handshake with RTI. This signals "I have this writer endpoint."
///
/// ## RTPS Structure (Sec.8.3.7.1)
/// - INFO_DST: Target participant GUID prefix
/// - HEARTBEAT:
///   - readerEntityId: P2P BuiltinParticipantMessage Reader (0x000200C7) - them
///   - writerEntityId: P2P BuiltinParticipantMessage Writer (0x000200C2) - us
///   - firstSN: 1 (we will send from seq 1)
///   - lastSN: 0 (no data yet - empty heartbeat)
///   - count: 1
///
/// ## Arguments
/// - `our_guid_prefix`: Our participant GUID prefix (12 bytes)
/// - `peer_guid_prefix`: RTI participant GUID prefix (12 bytes)
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
    packet.extend_from_slice(&[2, 3]); // Version 2.3
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
        "[SERVICE-HEARTBEAT] Built Service-Request empty HEARTBEAT: our_prefix={:02x?}, peer_prefix={:02x?}, size={} bytes",
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
    fn test_build_service_request_acknack() {
        let our_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let peer_prefix = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120];

        let packet = build_service_request_acknack(&our_prefix, &peer_prefix);

        // Verify RTPS header
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(packet[4], 2); // Protocol version major
        assert_eq!(packet[5], 3); // Protocol version minor
        assert_eq!(&packet[6..8], &[0x01, 0xaa]); // HDDS vendor ID
        assert_eq!(&packet[8..20], &our_prefix[..]); // Our GUID prefix

        // Verify INFO_DST submessage
        assert_eq!(packet[20], 0x0e); // INFO_DST ID
        assert_eq!(packet[21], 0x01); // Flags
        assert_eq!(&packet[24..36], &peer_prefix[..]); // Peer GUID prefix

        // Verify ACKNACK submessage
        assert_eq!(packet[36], 0x06); // ACKNACK ID
        assert_eq!(packet[37], 0x01); // Flags (E=1, F=0)
        assert_eq!(&packet[40..44], &SERVICE_REQUEST_READER[..]); // readerEntityId
        assert_eq!(&packet[44..48], &SERVICE_REQUEST_WRITER[..]); // writerEntityId

        // v127: Preemptive ACKNACK (bitmapBase=0, numBits=0, no bitmap)
        // Total size: 20 (header) + 16 (INFO_DST) + 28 (ACKNACK submsg) = 64 bytes
        // ACKNACK: 4 (submsg hdr) + 24 (body) = 28 bytes
        // Body: 4 (reader) + 4 (writer) + 8 (base) + 4 (numBits) + 0 (no bitmap) + 4 (count) = 24
        assert_eq!(packet.len(), 64);

        // v127: Verify bitmapBase is 0 and numBits is 0 (preemptive ACKNACK)
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

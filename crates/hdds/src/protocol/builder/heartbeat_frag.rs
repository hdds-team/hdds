// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HEARTBEAT_FRAG packet builder for fragment-level heartbeats.
//!
//! Builds complete RTPS packets with HEARTBEAT_FRAG submessages to announce
//! fragment availability for reliable fragmented data.
//! Per RTPS 2.3 spec Sec.8.3.7.6.

use crate::core::rtps_constants::RTPS_SUBMSG_HEARTBEAT_FRAG;

/// Build HEARTBEAT_FRAG submessage according to RTPS spec.
///
/// HEARTBEAT_FRAG format (RTPS v2.3 Sec.8.3.7.6):
/// ```text
/// +------------------+
/// | readerEntityId   |  4 bytes (ENTITYID_UNKNOWN for multicast)
/// +------------------+
/// | writerEntityId   |  4 bytes
/// +------------------+
/// | writerSN         |  8 bytes (sequence number of fragmented message)
/// +------------------+
/// | lastFragmentNum  |  4 bytes (last available fragment number, 1-based)
/// +------------------+
/// | count            |  4 bytes (incremented each time)
/// +------------------+
/// ```
///
/// # Arguments
///
/// - `reader_entity_id`: EntityId of the target DataReader (ENTITYID_UNKNOWN for multicast)
/// - `writer_entity_id`: EntityId of the DataWriter sending fragments
/// - `writer_sn`: Sequence number of the fragmented message
/// - `last_fragment_num`: Last fragment number available (1-based)
/// - `count`: Incremented for each HEARTBEAT_FRAG sent
///
/// # Returns
///
/// Complete HEARTBEAT_FRAG submessage bytes including submessage header.
pub fn build_heartbeat_frag_submessage(
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    writer_sn: u64,
    last_fragment_num: u32,
    count: u32,
) -> Vec<u8> {
    // Submessage payload length:
    // readerEntityId(4) + writerEntityId(4) + writerSN(8) + lastFragmentNum(4) + count(4) = 24
    const SUBMSG_LEN: u16 = 24;

    let mut buf = Vec::with_capacity(4 + SUBMSG_LEN as usize);

    // Submessage header
    buf.push(RTPS_SUBMSG_HEARTBEAT_FRAG); // submessageId = 0x13
    buf.push(0x01); // flags: E=1 (little-endian)
    buf.extend_from_slice(&SUBMSG_LEN.to_le_bytes()); // octetsToNextHeader

    // readerEntityId
    buf.extend_from_slice(&reader_entity_id);

    // writerEntityId
    buf.extend_from_slice(&writer_entity_id);

    // writerSN (sequence number as RTPS SequenceNumber_t: high(4) + low(4))
    let sn_high = (writer_sn >> 32) as u32;
    let sn_low = writer_sn as u32;
    buf.extend_from_slice(&sn_high.to_le_bytes());
    buf.extend_from_slice(&sn_low.to_le_bytes());

    // lastFragmentNum (1-based)
    buf.extend_from_slice(&last_fragment_num.to_le_bytes());

    // count
    buf.extend_from_slice(&count.to_le_bytes());

    buf
}

/// Build complete RTPS packet with HEARTBEAT_FRAG submessage.
///
/// # Arguments
///
/// - `our_guid_prefix`: GUID prefix of the writer sending HEARTBEAT_FRAG
/// - `dest_guid_prefix`: GUID prefix of the target reader (or broadcast)
/// - `reader_entity_id`: EntityId of the target DataReader
/// - `writer_entity_id`: EntityId of the DataWriter
/// - `writer_sn`: Sequence number of the fragmented message
/// - `last_fragment_num`: Last fragment number available (1-based)
/// - `count`: HEARTBEAT_FRAG count for duplicate detection
#[allow(clippy::too_many_arguments)]
pub fn build_heartbeat_frag_packet(
    our_guid_prefix: [u8; 12],
    dest_guid_prefix: [u8; 12],
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    writer_sn: u64,
    last_fragment_num: u32,
    count: u32,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);

    // RTPS Header (20 bytes)
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 3]); // Version 2.3
    packet.extend_from_slice(&[0x01, 0xaa]); // Vendor ID (HDDS)
    packet.extend_from_slice(&our_guid_prefix);

    // INFO_DST submessage (16 bytes)
    packet.push(0x0e); // submessageId = INFO_DST
    packet.push(0x01); // flags: E=1 (little-endian)
    packet.extend_from_slice(&12u16.to_le_bytes()); // octetsToNextHeader = 12
    packet.extend_from_slice(&dest_guid_prefix);

    // HEARTBEAT_FRAG submessage
    let hb_frag = build_heartbeat_frag_submessage(
        reader_entity_id,
        writer_entity_id,
        writer_sn,
        last_fragment_num,
        count,
    );
    packet.extend_from_slice(&hb_frag);

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_heartbeat_frag_submessage_basic() {
        let reader_id = [0x00, 0x00, 0x00, 0x00]; // ENTITYID_UNKNOWN
        let writer_id = [0x00, 0x00, 0x01, 0x03]; // writer entity
        let writer_sn = 42u64;
        let last_frag = 64u32;
        let count = 1;

        let submsg =
            build_heartbeat_frag_submessage(reader_id, writer_id, writer_sn, last_frag, count);

        // Check total length: 4 (header) + 24 (payload) = 28 bytes
        assert_eq!(submsg.len(), 28);

        // Check submessage header
        assert_eq!(submsg[0], RTPS_SUBMSG_HEARTBEAT_FRAG); // submessageId = 0x13
        assert_eq!(submsg[1], 0x01); // flags (little-endian)
        assert_eq!(&submsg[2..4], &24u16.to_le_bytes()); // length

        // Check reader/writer entity IDs
        assert_eq!(&submsg[4..8], &reader_id);
        assert_eq!(&submsg[8..12], &writer_id);

        // Check sequence number (high=0, low=42 in LE)
        assert_eq!(&submsg[12..16], &[0, 0, 0, 0]); // high
        assert_eq!(&submsg[16..20], &[42, 0, 0, 0]); // low

        // Check lastFragmentNum = 64
        assert_eq!(&submsg[20..24], &64u32.to_le_bytes());

        // Check count = 1
        assert_eq!(&submsg[24..28], &1u32.to_le_bytes());
    }

    #[test]
    fn test_build_heartbeat_frag_packet_structure() {
        let our_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let dest_prefix = [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
        let reader_id = [0x00, 0x00, 0x00, 0x00];
        let writer_id = [0x00, 0x00, 0x01, 0x03];

        let packet =
            build_heartbeat_frag_packet(our_prefix, dest_prefix, reader_id, writer_id, 100, 32, 5);

        // Check RTPS header
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(&packet[4..6], &[2, 3]); // version
        assert_eq!(&packet[6..8], &[0x01, 0xaa]); // vendor
        assert_eq!(&packet[8..20], &our_prefix);

        // Check INFO_DST submessage starts at offset 20
        assert_eq!(packet[20], 0x0e); // INFO_DST
        assert_eq!(&packet[24..36], &dest_prefix);

        // Check HEARTBEAT_FRAG submessage starts at offset 36
        assert_eq!(packet[36], RTPS_SUBMSG_HEARTBEAT_FRAG);
    }

    #[test]
    fn test_heartbeat_frag_large_seq_number() {
        let reader_id = [0; 4];
        let writer_id = [0; 4];
        let large_sn = 0x0000_0001_0000_0042u64; // high=1, low=66
        let last_frag = 128;
        let count = 99;

        let submsg =
            build_heartbeat_frag_submessage(reader_id, writer_id, large_sn, last_frag, count);

        // Check sequence number encoding
        assert_eq!(&submsg[12..16], &1u32.to_le_bytes()); // high = 1
        assert_eq!(&submsg[16..20], &66u32.to_le_bytes()); // low = 66
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NACK_FRAG packet builder for fragment-level retransmission requests.
//!
//! Builds complete RTPS packets with NACK_FRAG submessages to request
//! retransmission of specific missing fragments.
//! Per RTPS 2.3 spec Sec.8.3.7.5.

use crate::core::rtps_constants::RTPS_SUBMSG_NACK_FRAG;

/// Build NACK_FRAG submessage according to RTPS spec.
///
/// NACK_FRAG format (RTPS v2.3 Sec.8.3.7.5):
/// ```text
/// +------------------+
/// | readerEntityId   |  4 bytes
/// +------------------+
/// | writerEntityId   |  4 bytes
/// +------------------+
/// | writerSN         |  8 bytes (sequence number of fragmented message)
/// +------------------+
/// | fragmentNumberState:
/// |   bitmapBase     |  4 bytes (first fragment number)
/// |   numBits        |  4 bytes
/// |   bitmap[]       |  variable (u32 words)
/// +------------------+
/// | count            |  4 bytes
/// +------------------+
/// ```
///
/// # Arguments
///
/// - `reader_entity_id`: EntityId of the DataReader requesting fragments
/// - `writer_entity_id`: EntityId of the DataWriter that sent the fragments
/// - `writer_sn`: Sequence number of the fragmented message
/// - `missing_frags`: List of missing fragment numbers (1-based)
/// - `count`: Incremented for each NACK_FRAG sent (for duplicate detection)
///
/// # Returns
///
/// Complete NACK_FRAG submessage bytes including submessage header.
pub fn build_nack_frag_submessage(
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    writer_sn: u64,
    missing_frags: &[u32],
    count: u32,
) -> Vec<u8> {
    // Calculate bitmap base and size
    let frag_base = missing_frags.iter().min().copied().unwrap_or(1);
    let frag_max = missing_frags.iter().max().copied().unwrap_or(1);
    let num_bits = if frag_max >= frag_base {
        (frag_max - frag_base + 1).min(256) // Max 256 bits per RTPS spec
    } else {
        0
    };

    // Build bitmap (u32 array, MSB-first per RTPS spec Sec.8.3.5.5)
    let bitmap_words = num_bits.div_ceil(32) as usize;
    let mut bitmap = vec![0u32; bitmap_words];

    for &frag_num in missing_frags {
        if frag_num >= frag_base && frag_num < frag_base + num_bits {
            let bit_pos = (frag_num - frag_base) as usize;
            let word_idx = bit_pos / 32;
            let bit_idx = bit_pos % 32;
            if word_idx < bitmap.len() {
                // MSB-first ordering per RTPS spec
                bitmap[word_idx] |= 1u32 << (31 - bit_idx);
            }
        }
    }

    // Calculate submessage length
    // readerEntityId(4) + writerEntityId(4) + writerSN(8) +
    // bitmapBase(4) + numBits(4) + bitmap(4*N) + count(4)
    let submsg_len = 4 + 4 + 8 + 4 + 4 + (bitmap_words * 4) + 4;

    let mut buf = Vec::with_capacity(4 + submsg_len);

    // Submessage header
    buf.push(RTPS_SUBMSG_NACK_FRAG); // submessageId = 0x12
    buf.push(0x01); // flags: E=1 (little-endian)
    buf.extend_from_slice(&(submsg_len as u16).to_le_bytes()); // octetsToNextHeader

    // readerEntityId
    buf.extend_from_slice(&reader_entity_id);

    // writerEntityId
    buf.extend_from_slice(&writer_entity_id);

    // writerSN (sequence number as u64 LE, but RTPS uses high/low u32)
    // RTPS SequenceNumber_t: high(4) + low(4) = 8 bytes
    let sn_high = (writer_sn >> 32) as u32;
    let sn_low = writer_sn as u32;
    buf.extend_from_slice(&sn_high.to_le_bytes());
    buf.extend_from_slice(&sn_low.to_le_bytes());

    // fragmentNumberState.bitmapBase (first fragment number)
    buf.extend_from_slice(&frag_base.to_le_bytes());

    // fragmentNumberState.numBits
    buf.extend_from_slice(&num_bits.to_le_bytes());

    // fragmentNumberState.bitmap[]
    for word in &bitmap {
        buf.extend_from_slice(&word.to_le_bytes());
    }

    // count
    buf.extend_from_slice(&count.to_le_bytes());

    buf
}

/// Build complete RTPS packet with NACK_FRAG submessage.
///
/// # Arguments
///
/// - `our_guid_prefix`: GUID prefix of the reader sending NACK_FRAG
/// - `dest_guid_prefix`: GUID prefix of the writer to receive NACK_FRAG
/// - `reader_entity_id`: EntityId of the DataReader
/// - `writer_entity_id`: EntityId of the DataWriter
/// - `writer_sn`: Sequence number of the fragmented message
/// - `missing_frags`: List of missing fragment numbers (1-based)
/// - `count`: NACK_FRAG count for duplicate detection
#[allow(clippy::too_many_arguments)]
pub fn build_nack_frag_packet(
    our_guid_prefix: [u8; 12],
    dest_guid_prefix: [u8; 12],
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    writer_sn: u64,
    missing_frags: &[u32],
    count: u32,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(128);

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

    // NACK_FRAG submessage
    let nack_frag = build_nack_frag_submessage(
        reader_entity_id,
        writer_entity_id,
        writer_sn,
        missing_frags,
        count,
    );
    packet.extend_from_slice(&nack_frag);

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_nack_frag_submessage_basic() {
        let reader_id = [0x00, 0x00, 0x01, 0x04]; // reader entity
        let writer_id = [0x00, 0x00, 0x01, 0x03]; // writer entity
        let writer_sn = 42u64;
        let missing = vec![2, 4, 5]; // Missing fragments 2, 4, 5
        let count = 1;

        let submsg = build_nack_frag_submessage(reader_id, writer_id, writer_sn, &missing, count);

        // Check submessage header
        assert_eq!(submsg[0], RTPS_SUBMSG_NACK_FRAG); // submessageId
        assert_eq!(submsg[1], 0x01); // flags (little-endian)

        // Check reader/writer entity IDs
        assert_eq!(&submsg[4..8], &reader_id);
        assert_eq!(&submsg[8..12], &writer_id);

        // Check sequence number (high=0, low=42 in LE)
        assert_eq!(&submsg[12..16], &[0, 0, 0, 0]); // high
        assert_eq!(&submsg[16..20], &[42, 0, 0, 0]); // low

        // Check bitmapBase = 2 (first missing fragment)
        assert_eq!(&submsg[20..24], &[2, 0, 0, 0]);

        // Check numBits = 4 (covers fragments 2-5)
        assert_eq!(&submsg[24..28], &[4, 0, 0, 0]);
    }

    #[test]
    fn test_build_nack_frag_packet_structure() {
        let our_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let dest_prefix = [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
        let reader_id = [0x00, 0x00, 0x01, 0x04];
        let writer_id = [0x00, 0x00, 0x01, 0x03];
        let missing = vec![1, 3];

        let packet = build_nack_frag_packet(
            our_prefix,
            dest_prefix,
            reader_id,
            writer_id,
            100,
            &missing,
            5,
        );

        // Check RTPS header
        assert_eq!(&packet[0..4], b"RTPS");
        assert_eq!(&packet[4..6], &[2, 3]); // version
        assert_eq!(&packet[6..8], &[0x01, 0xaa]); // vendor
        assert_eq!(&packet[8..20], &our_prefix);

        // Check INFO_DST submessage starts at offset 20
        assert_eq!(packet[20], 0x0e); // INFO_DST
        assert_eq!(&packet[24..36], &dest_prefix);

        // Check NACK_FRAG submessage starts at offset 36
        assert_eq!(packet[36], RTPS_SUBMSG_NACK_FRAG);
    }

    #[test]
    fn test_nack_frag_empty_missing() {
        let reader_id = [0; 4];
        let writer_id = [0; 4];
        let missing: Vec<u32> = vec![];

        let submsg = build_nack_frag_submessage(reader_id, writer_id, 1, &missing, 1);

        // Should still produce valid submessage with empty bitmap
        assert_eq!(submsg[0], RTPS_SUBMSG_NACK_FRAG);
    }
}

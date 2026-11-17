// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NACK_FRAG packet builder for fragment-level retransmission requests.
//!
//! Builds complete RTPS packets with NACK_FRAG submessages to request
//! retransmission of specific missing fragments.
//! Per RTPS 2.5 spec Sec.8.3.8.12.

use crate::core::rtps_constants::{RTPS_SUBMSG_NACK_FRAG, RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
use crate::protocol::rtps::sequence_number_le_bytes;

/// Largest `numBits` a FragmentNumberSet may carry (RTPS v2.5 Sec.9.4.2.8).
///
/// Held as a `u16` so the submessage length below is computed in the width
/// of `octetsToNextHeader` from the start: with at most 256 bits there are
/// at most 8 bitmap words, and the arithmetic never needs narrowing.
const MAX_FRAGMENT_NUMBER_SET_BITS: u16 = 256;

/// Build NACK_FRAG submessage according to RTPS spec.
///
/// NACK_FRAG format (RTPS v2.5 Sec.8.3.8.12):
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
    // The span is converted, not cast: a distance that does not fit in 16
    // bits is certainly past the 256-bit cap and lands on the cap.
    let num_bits: u16 = if frag_max >= frag_base {
        u16::try_from(frag_max - frag_base).map_or(MAX_FRAGMENT_NUMBER_SET_BITS, |span| {
            span.saturating_add(1).min(MAX_FRAGMENT_NUMBER_SET_BITS)
        })
    } else {
        0
    };

    // Build bitmap (u32 array, MSB-first per RTPS spec Sec.8.3.5.5)
    let bitmap_words: u16 = num_bits.div_ceil(32);
    let mut bitmap = vec![0u32; usize::from(bitmap_words)];

    for &frag_num in missing_frags {
        // The offset is computed once, after the lower bound holds, and the
        // upper bound is tested on the OFFSET: `frag_base + num_bits` could
        // overflow a u32 for a base near the top of the range, and a wrapped
        // bound admits every fragment number.
        let Some(offset) = frag_num.checked_sub(frag_base) else {
            continue;
        };
        if offset >= u32::from(num_bits) {
            continue;
        }
        let bit_pos = offset as usize;
        let word_idx = bit_pos / 32;
        let bit_idx = bit_pos % 32;
        if word_idx < bitmap.len() {
            // MSB-first ordering per RTPS spec
            bitmap[word_idx] |= 1u32 << (31 - bit_idx);
        }
    }

    // Calculate submessage length, in the width of octetsToNextHeader:
    // readerEntityId(4) + writerEntityId(4) + writerSN(8) +
    // bitmapBase(4) + numBits(4) + bitmap(4*N) + count(4)
    let submsg_len: u16 = 4 + 4 + 8 + 4 + 4 + (bitmap_words * 4) + 4;

    let mut buf = Vec::with_capacity(4 + usize::from(submsg_len));

    // Submessage header
    buf.push(RTPS_SUBMSG_NACK_FRAG); // submessageId = 0x12
    buf.push(0x01); // flags: E=1 (little-endian)
    buf.extend_from_slice(&submsg_len.to_le_bytes()); // octetsToNextHeader

    // readerEntityId
    buf.extend_from_slice(&reader_entity_id);

    // writerEntityId
    buf.extend_from_slice(&writer_entity_id);

    // writerSN (RTPS SequenceNumber_t: high(4) + low(4) = 8 bytes)
    buf.extend_from_slice(&sequence_number_le_bytes(writer_sn));

    // fragmentNumberState.bitmapBase (first fragment number)
    buf.extend_from_slice(&frag_base.to_le_bytes());

    // fragmentNumberState.numBits
    buf.extend_from_slice(&u32::from(num_bits).to_le_bytes());

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
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // Protocol version
    packet.extend_from_slice(&[0x01, 0x1a]); // Vendor ID (HDDS)
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

    /// A fragment base near the top of the u32 range: an upper bound of
    /// `frag_base + num_bits` would overflow here. The bit for the one
    /// missing fragment is set, and the fragment below the base sets none.
    #[test]
    fn a_base_near_the_top_of_the_range_does_not_overflow() {
        let reader_id = [0x00, 0x00, 0x01, 0x04];
        let writer_id = [0x00, 0x00, 0x01, 0x03];
        let missing = vec![u32::MAX];
        let submsg = build_nack_frag_submessage(reader_id, writer_id, 1, &missing, 1);
        // bitmapBase = u32::MAX (the one missing fragment), numBits = 1, so
        // a bound of `frag_base + num_bits` would wrap to 0.
        // The layout after the SN: bitmapBase(4) numBits(4) bitmap words.
        let bitmap_base = u32::from_le_bytes([submsg[20], submsg[21], submsg[22], submsg[23]]);
        let num_bits = u32::from_le_bytes([submsg[24], submsg[25], submsg[26], submsg[27]]);
        assert_eq!(bitmap_base, u32::MAX);
        assert_eq!(num_bits, 1);
        let word = u32::from_le_bytes([submsg[28], submsg[29], submsg[30], submsg[31]]);
        assert_eq!(
            word,
            1u32 << 31,
            "the one missing fragment is bit 0, MSB-first"
        );
    }

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
        assert_eq!(&packet[4..6], &[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // version
        assert_eq!(&packet[6..8], &[0x01, 0x1a]); // vendor
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

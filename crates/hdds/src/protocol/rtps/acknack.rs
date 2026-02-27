// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ACKNACK submessage encoder (RTPS 2.3 Section 8.3.7.1)
//!
//! The ACKNACK submessage is used to communicate acknowledgments of received
//! DATA messages and to request retransmission of missing DATA messages.

use super::{RtpsEncodeError, RtpsEncodeResult};

/// Encode an ACKNACK submessage per RTPS 2.3 specification.
///
/// # Arguments
///
/// * `reader_id` - EntityId of the Reader sending the ACKNACK
/// * `writer_id` - EntityId of the Writer being acknowledged
/// * `base_sn` - Base sequence number of the SequenceNumberSet
/// * `num_bits` - Number of bits in the bitmap (must match actual bits used)
/// * `bitmap` - Bitmap of missing sequences (bit N = base_sn + N is missing)
/// * `count` - ACKNACK count (monotonically increasing)
///
/// # Returns
///
/// Encoded ACKNACK submessage bytes.
///
/// # RTPS Format
///
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   ACKNACK     |     flags     |      octetsToNextHeader       |
/// +---------------+---------------+-------------------------------+
/// |                         readerId                              |
/// +---------------------------------------------------------------+
/// |                         writerId                              |
/// +---------------------------------------------------------------+
/// |                                                               |
/// +              readerSNState (SequenceNumberSet)                +
/// |                                                               |
/// +---------------------------------------------------------------+
/// |                           count                               |
/// +---------------------------------------------------------------+
/// ```
pub fn encode_acknack(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    base_sn: u64,
    num_bits: u32,
    bitmap: &[u32],
) -> RtpsEncodeResult<Vec<u8>> {
    // Validate num_bits vs bitmap length
    let required_words = num_bits.div_ceil(32) as usize;
    if bitmap.len() < required_words {
        return Err(RtpsEncodeError::InvalidParameter(
            "bitmap too small for specified num_bits",
        ));
    }

    // Calculate submessage length
    // EntityIds (8) + SequenceNumberSet (8 + 4 + bitmap_bytes) + count (4)
    let bitmap_bytes = required_words * 4;
    let submsg_len = 8 + 8 + 4 + bitmap_bytes + 4;

    let mut buf = vec![0u8; 4 + submsg_len];

    // Submessage header
    buf[0] = 0x06; // ACKNACK
    buf[1] = 0x01; // Flags: Endianness=LE
    buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

    let mut offset = 4;

    // Reader EntityId
    buf[offset..offset + 4].copy_from_slice(reader_id);
    offset += 4;

    // Writer EntityId
    buf[offset..offset + 4].copy_from_slice(writer_id);
    offset += 4;

    // SequenceNumberSet: bitmapBase (SequenceNumber_t)
    let base_high = (base_sn >> 32) as i32;
    let base_low = base_sn as u32;
    buf[offset..offset + 4].copy_from_slice(&base_high.to_le_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&base_low.to_le_bytes());
    offset += 4;

    // numBits (ULong) - THIS IS THE FIX: use actual num_bits, not bitmap.len() * 32
    buf[offset..offset + 4].copy_from_slice(&num_bits.to_le_bytes());
    offset += 4;

    // bitmap
    for i in 0..required_words {
        let word = bitmap.get(i).copied().unwrap_or(0);
        buf[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        offset += 4;
    }

    // Count
    // Note: count is added by caller context, but we need a placeholder
    // The count field will be filled by the caller
    buf[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes());

    Ok(buf)
}

/// Encode an ACKNACK submessage with explicit count.
///
/// This is the full version that includes the count field.
pub fn encode_acknack_with_count(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    base_sn: u64,
    num_bits: u32,
    bitmap: &[u32],
    count: u32,
) -> RtpsEncodeResult<Vec<u8>> {
    let mut buf = encode_acknack(reader_id, writer_id, base_sn, num_bits, bitmap)?;

    // Overwrite count at the end
    let count_offset = buf.len() - 4;
    buf[count_offset..].copy_from_slice(&count.to_le_bytes());

    Ok(buf)
}

/// Encode an ACKNACK submessage with explicit count and Final flag.
///
/// Per RTPS v2.5 Sec.8.3.7.1, ACKNACK flags:
/// - Bit 0 (0x01): Endianness (1 = Little Endian)
/// - Bit 1 (0x02): FinalFlag (1 = reader is synchronized, no more data expected)
///
/// The Final flag indicates the reader has received all data and doesn't
/// expect more. Without it, the writer will keep sending HEARTBEATs.
pub fn encode_acknack_with_final(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    base_sn: u64,
    num_bits: u32,
    bitmap: &[u32],
    count: u32,
    final_flag: bool,
) -> RtpsEncodeResult<Vec<u8>> {
    let mut buf = encode_acknack(reader_id, writer_id, base_sn, num_bits, bitmap)?;

    // Set flags: LE (0x01) + Final (0x02) if synchronized
    let flags = if final_flag { 0x03 } else { 0x01 };
    buf[1] = flags;

    // Overwrite count at the end
    let count_offset = buf.len() - 4;
    buf[count_offset..].copy_from_slice(&count.to_le_bytes());

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acknack_positive_ack() {
        // Positive ACK: num_bits=0, empty bitmap
        let reader_id = [0x00, 0x00, 0x04, 0xC7]; // SEDP builtin reader
        let writer_id = [0x00, 0x00, 0x03, 0xC2]; // SEDP publications writer
        let base_sn = 5u64;
        let num_bits = 0u32;
        let bitmap: &[u32] = &[];

        let result =
            encode_acknack_with_count(&reader_id, &writer_id, base_sn, num_bits, bitmap, 1);
        assert!(result.is_ok());

        let buf = result.unwrap();
        assert_eq!(buf[0], 0x06); // ACKNACK
        assert_eq!(buf[1], 0x01); // LE flag

        // Verify numBits is 0
        let num_bits_offset = 4 + 8 + 8; // header + entityIds + seqNum
        let encoded_num_bits = u32::from_le_bytes([
            buf[num_bits_offset],
            buf[num_bits_offset + 1],
            buf[num_bits_offset + 2],
            buf[num_bits_offset + 3],
        ]);
        assert_eq!(encoded_num_bits, 0);
    }

    #[test]
    fn test_acknack_nack_single_sequence() {
        const SINGLE_SEQUENCE_BITMAP: u32 = 0x0000_0001;

        // NACK requesting sequence 1
        let reader_id = [0x00, 0x00, 0x04, 0xC7];
        let writer_id = [0x00, 0x00, 0x03, 0xC2];
        let base_sn = 1u64;
        let num_bits = 1u32; // Only 1 bit needed
        let bitmap: &[u32] = &[SINGLE_SEQUENCE_BITMAP];

        let result =
            encode_acknack_with_count(&reader_id, &writer_id, base_sn, num_bits, bitmap, 1);
        assert!(result.is_ok());

        let buf = result.unwrap();

        // Verify numBits is 1, NOT 32
        let num_bits_offset = 4 + 8 + 8;
        let encoded_num_bits = u32::from_le_bytes([
            buf[num_bits_offset],
            buf[num_bits_offset + 1],
            buf[num_bits_offset + 2],
            buf[num_bits_offset + 3],
        ]);
        assert_eq!(encoded_num_bits, 1, "numBits should be 1, not 32");
    }
}

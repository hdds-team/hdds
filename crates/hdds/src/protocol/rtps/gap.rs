// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! GAP submessage encoder (RTPS 2.3 Section 8.3.7.4)
//!
//! The GAP submessage is sent by a Writer to inform Readers that certain
//! sequence numbers are no longer relevant and will never be sent.

use super::RtpsEncodeResult;

/// Encode a GAP submessage per RTPS 2.3 specification.
///
/// # Arguments
///
/// * `reader_id` - EntityId of the target Reader
/// * `writer_id` - EntityId of the Writer sending the GAP
/// * `gap_start` - First sequence number in the gap
/// * `gap_list_base` - Base of the gap list bitmap
/// * `num_bits` - Number of bits in the gap bitmap
/// * `gap_bitmap` - Bitmap of additional irrelevant sequences
///
/// # Returns
///
/// Encoded GAP submessage bytes.
pub fn encode_gap(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    gap_start: u64,
    gap_list_base: u64,
    num_bits: u32,
    gap_bitmap: &[u32],
) -> RtpsEncodeResult<Vec<u8>> {
    let required_words = num_bits.div_ceil(32) as usize;
    let bitmap_bytes = required_words * 4;

    // entityIds(8) + gapStart(8) + gapListBase(8) + numBits(4) + bitmap
    let submsg_len = 8 + 8 + 8 + 4 + bitmap_bytes;

    let mut buf = vec![0u8; 4 + submsg_len];

    // Submessage header
    buf[0] = 0x08; // GAP
    buf[1] = 0x01; // Flags: LE
    buf[2..4].copy_from_slice(&(submsg_len as u16).to_le_bytes());

    let mut offset = 4;

    // Reader EntityId
    buf[offset..offset + 4].copy_from_slice(reader_id);
    offset += 4;

    // Writer EntityId
    buf[offset..offset + 4].copy_from_slice(writer_id);
    offset += 4;

    // Gap start (SequenceNumber_t)
    let start_high = (gap_start >> 32) as i32;
    let start_low = gap_start as u32;
    buf[offset..offset + 4].copy_from_slice(&start_high.to_le_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&start_low.to_le_bytes());
    offset += 4;

    // Gap list base (SequenceNumber_t)
    let list_high = (gap_list_base >> 32) as i32;
    let list_low = gap_list_base as u32;
    buf[offset..offset + 4].copy_from_slice(&list_high.to_le_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&list_low.to_le_bytes());
    offset += 4;

    // numBits - use actual value, not bitmap.len() * 32
    buf[offset..offset + 4].copy_from_slice(&num_bits.to_le_bytes());
    offset += 4;

    // bitmap
    for i in 0..required_words {
        let word = gap_bitmap.get(i).copied().unwrap_or(0);
        buf[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        offset += 4;
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_encoding() {
        let reader_id = [0x00, 0x00, 0x00, 0x00];
        let writer_id = [0x00, 0x00, 0x03, 0xC2];
        let gap_start = 1u64;
        let gap_list_base = 5u64;
        let num_bits = 0u32;
        let gap_bitmap: &[u32] = &[];

        let result = encode_gap(
            &reader_id,
            &writer_id,
            gap_start,
            gap_list_base,
            num_bits,
            gap_bitmap,
        );
        assert!(result.is_ok());

        let buf = result.unwrap();
        assert_eq!(buf[0], 0x08); // GAP
    }
}

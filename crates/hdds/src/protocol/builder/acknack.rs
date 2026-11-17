// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ACKNACK packet builder for Reliable QoS.
//!
//! Builds complete RTPS packets with ACKNACK submessages for the reliability protocol.
//! Per RTPS 2.5 spec Sec.8.3.8.1.

use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
use crate::protocol::dialect::{get_encoder, Dialect};

/// Largest `numBits` a SequenceNumberSet may carry (RTPS v2.5 Sec.9.4.2.6).
///
/// Visible to the crate because it is also the honest bound on how many
/// missing sequences a caller should bother collecting: everything past it
/// is dropped by `build_acknack_packet_with_final` below, which cannot
/// encode it. `reliability::messages::MAX_BITMAP_BITS` is the same wire
/// limit under another name, on the decoding side.
pub(crate) const MAX_SEQUENCE_NUMBER_SET_BITS: u32 = 256;

/// Number of bitmap bits needed to cover `seq_base..=max_seq`, capped at the
/// SequenceNumberSet maximum. The span is converted, not cast: a distance
/// that does not fit in 32 bits is certainly past the 256-bit cap, so it
/// lands on the cap exactly like any other oversized span. A `max_seq` below
/// the base names nothing above it, so it needs no bits: the subtraction is
/// checked, not assumed, so that the arithmetic feeding the conversion is as
/// total as the conversion itself.
fn acknack_num_bits(seq_base: u64, max_seq: u64) -> u32 {
    match max_seq.checked_sub(seq_base) {
        None => 0,
        Some(span) => u32::try_from(span).map_or(MAX_SEQUENCE_NUMBER_SET_BITS, |span| {
            span.saturating_add(1).min(MAX_SEQUENCE_NUMBER_SET_BITS)
        }),
    }
}

/// Build ACKNACK submessage according to RTPS spec using DialectEncoder.
///
/// This function takes a list of missing sequence numbers, calculates the
/// RTPS bitmap representation, and delegates to DialectEncoder for encoding.
pub fn build_acknack_submessage(
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    seq_base: u64,
    missing_seqs: &[u64],
    count: u32,
) -> Vec<u8> {
    // Calculate bitmap for missing sequences
    let num_bits = if let Some(&max_seq) = missing_seqs.iter().max() {
        acknack_num_bits(seq_base, max_seq)
    } else {
        0u32
    };

    // Build bitmap (u32 array)
    // When num_bits=0 (preemptive ACKNACK), create empty bitmap (no words)
    // This produces bitmapBase=0, numBits=0 which is the standard preemptive format
    let bitmap_words = num_bits.div_ceil(32) as usize;
    let mut bitmap = vec![0u32; bitmap_words]; // Empty when num_bits=0

    // RTPS spec Sec.8.3.5.5 uses MSB-first bit ordering for bitmaps.
    // Bit N in word M represents sequence (bitmapBase + M*32 + N), where bit 0 is the MSB.
    // So to set bit N, we use (1 << (31 - N)) to put it at the MSB position.
    for &seq in missing_seqs {
        // Offset first, bound on the offset: `seq_base + num_bits` is the
        // sum that could wrap, and a wrapped bound admits everything.
        let Some(offset) = seq.checked_sub(seq_base) else {
            continue;
        };
        if offset >= u64::from(num_bits) {
            continue;
        }
        // offset < 256 here, so the narrowing is exact.
        let Ok(bit_pos) = usize::try_from(offset) else {
            continue;
        };
        let word_idx = bit_pos / 32;
        let bit_idx = bit_pos % 32;
        if word_idx < bitmap.len() {
            // MSB-first ordering per RTPS spec Sec.8.3.5.5
            bitmap[word_idx] |= 1u32 << (31 - bit_idx);
        }
    }

    // Use DialectEncoder for RTPS-compliant encoding
    let encoder = get_encoder(Dialect::Hybrid);
    encoder
        .build_acknack(
            &reader_entity_id,
            &writer_entity_id,
            seq_base,
            &bitmap,
            count,
        )
        .unwrap_or_else(|_| Vec::new())
}

/// Build complete RTPS packet with ACKNACK using DialectEncoder.
pub fn build_acknack_packet(
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

    // RTPS Header (20 bytes)
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // Protocol version
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

/// Build complete RTPS packet with ACKNACK and Final flag support.
///
/// Per RTPS v2.5 Sec.8.3.8.1, the Final flag indicates the reader has received
/// all data announced by the writer and doesn't expect more. This stops
/// the HEARTBEAT->ACKNACK cycle.
///
/// # Arguments
/// - `final_flag`: true when reader is synchronized (has all data)
#[allow(clippy::too_many_arguments)] // RTPS ACKNACK fields per spec
pub fn build_acknack_packet_with_final(
    our_guid_prefix: [u8; 12],
    dest_guid_prefix: [u8; 12],
    reader_entity_id: [u8; 4],
    writer_entity_id: [u8; 4],
    seq_base: u64,
    missing_seqs: &[u64],
    count: u32,
    final_flag: bool,
) -> Vec<u8> {
    use crate::protocol::rtps::encode_acknack_with_final;

    let encoder = get_encoder(Dialect::Hybrid);
    let mut packet = Vec::with_capacity(256);

    // RTPS Header (20 bytes)
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // Protocol version
    packet.extend_from_slice(&[0x01, 0x1a]); // Vendor ID (HDDS)
    packet.extend_from_slice(&our_guid_prefix);

    // INFO_DST submessage
    let info_dst = encoder.build_info_dst(&dest_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // ACKNACK submessage with Final flag
    // Calculate bitmap for missing sequences
    let num_bits = if let Some(&max_seq) = missing_seqs.iter().max() {
        acknack_num_bits(seq_base, max_seq)
    } else {
        0u32
    };

    let bitmap_words = num_bits.div_ceil(32) as usize;
    let mut bitmap = vec![0u32; bitmap_words];

    // RTPS spec Sec.8.3.5.5 uses MSB-first bit ordering for bitmaps.
    // Bit N in word M represents sequence (bitmapBase + M*32 + N), where bit 0 is the MSB.
    for &seq in missing_seqs {
        // Offset first, bound on the offset: `seq_base + num_bits` is the
        // sum that could wrap, and a wrapped bound admits everything.
        let Some(offset) = seq.checked_sub(seq_base) else {
            continue;
        };
        if offset >= u64::from(num_bits) {
            continue;
        }
        // offset < 256 here, so the narrowing is exact.
        let Ok(bit_pos) = usize::try_from(offset) else {
            continue;
        };
        let word_idx = bit_pos / 32;
        let bit_idx = bit_pos % 32;
        if word_idx < bitmap.len() {
            // MSB-first ordering per RTPS spec Sec.8.3.5.5
            bitmap[word_idx] |= 1u32 << (31 - bit_idx);
        }
    }

    // Use low-level encoder with Final flag support. An ACKNACK that cannot
    // be encoded yields an EMPTY packet, never a bare RTPS header.
    let Ok(acknack) = encode_acknack_with_final(
        &reader_entity_id,
        &writer_entity_id,
        seq_base,
        num_bits,
        &bitmap,
        count,
        final_flag,
    ) else {
        return Vec::new();
    };

    packet.extend_from_slice(&acknack);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The arithmetic feeding the conversion is total: a `max_seq` below the
    /// base names nothing above it and gets no bits, instead of an underflow.
    #[test]
    fn a_max_below_the_base_needs_no_bits() {
        assert_eq!(acknack_num_bits(10, 5), 0);
        assert_eq!(acknack_num_bits(10, 10), 1);
        assert_eq!(acknack_num_bits(10, 12), 3);
        assert_eq!(acknack_num_bits(1, 1_000), MAX_SEQUENCE_NUMBER_SET_BITS);
        assert_eq!(acknack_num_bits(0, u64::MAX), MAX_SEQUENCE_NUMBER_SET_BITS);
    }

    /// The claim `dds::reader::heartbeat::collect_missing_seqs` rests on:
    /// handing this builder more missing sequences than a SequenceNumberSet
    /// can address changes nothing it emits, so collecting them was pure
    /// cost. Checked on the bytes rather than argued from the code, because
    /// the caller's bound is only free if this holds exactly.
    ///
    /// It pins the MECHANISM, not the width: the fixture is sized from
    /// `MAX_SEQUENCE_NUMBER_SET_BITS`, so it follows that constant rather
    /// than guarding its value. Raising the constant leaves this test green
    /// and fails `a_max_below_the_base_needs_no_bits` instead; removing the
    /// cap from `acknack_num_bits` fails this one. Both were checked.
    #[test]
    fn sequences_past_the_bitmap_width_change_no_byte_of_the_acknack() {
        let our_prefix = [0xAAu8; 12];
        let dest_prefix = [0xBBu8; 12];
        let reader_id = [0x00, 0x00, 0x01, 0x07];
        let writer_id = [0x00, 0x00, 0x01, 0x02];
        let base = 1u64;

        let width = u64::from(MAX_SEQUENCE_NUMBER_SET_BITS);
        let exactly_one_bitmap: Vec<u64> = (base..base + width).collect();
        let far_more: Vec<u64> = (base..base + width * 40).collect();

        let bounded = build_acknack_packet_with_final(
            our_prefix,
            dest_prefix,
            reader_id,
            writer_id,
            base,
            &exactly_one_bitmap,
            7,
            false,
        );
        let unbounded = build_acknack_packet_with_final(
            our_prefix,
            dest_prefix,
            reader_id,
            writer_id,
            base,
            &far_more,
            7,
            false,
        );

        assert!(
            !bounded.is_empty(),
            "the fixture must produce a real packet"
        );
        assert_eq!(
            bounded, unbounded,
            "everything past one bitmap's width is dropped by the builder"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ACKNACK packet builder for Reliable QoS.
//!
//! Builds complete RTPS packets with ACKNACK submessages for the reliability protocol.
//! Per RTPS 2.3 spec Sec.8.3.7.1.

use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
use crate::protocol::dialect::{get_encoder, Dialect};

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
        ((max_seq - seq_base) as u32 + 1).min(256) // Max 256 bits
    } else {
        0u32
    };

    // Build bitmap (u32 array)
    // v127: When num_bits=0 (preemptive ACKNACK), create empty bitmap (no words)
    // This produces bitmapBase=0, numBits=0 which is the standard preemptive format
    let bitmap_words = num_bits.div_ceil(32) as usize;
    let mut bitmap = vec![0u32; bitmap_words]; // Empty when num_bits=0

    // v172: RTPS spec Sec.8.3.5.5 uses MSB-first bit ordering for bitmaps.
    // Bit N in word M represents sequence (bitmapBase + M*32 + N), where bit 0 is the MSB.
    // So to set bit N, we use (1 << (31 - N)) to put it at the MSB position.
    for &seq in missing_seqs {
        if seq >= seq_base && seq < seq_base + num_bits as u64 {
            let bit_pos = (seq - seq_base) as usize;
            let word_idx = bit_pos / 32;
            let bit_idx = bit_pos % 32;
            if word_idx < bitmap.len() {
                // v172: MSB-first ordering per RTPS spec Sec.8.3.5.5
                bitmap[word_idx] |= 1u32 << (31 - bit_idx);
            }
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

/// Build complete RTPS packet with ACKNACK and Final flag support.
///
/// Per RTPS v2.5 Sec.8.3.7.1, the Final flag indicates the reader has received
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
    packet.extend_from_slice(&[0x01, 0xaa]); // Vendor ID (HDDS)
    packet.extend_from_slice(&our_guid_prefix);

    // INFO_DST submessage
    let info_dst = encoder.build_info_dst(&dest_guid_prefix);
    packet.extend_from_slice(&info_dst);

    // ACKNACK submessage with Final flag
    // Calculate bitmap for missing sequences
    let num_bits = if let Some(&max_seq) = missing_seqs.iter().max() {
        ((max_seq - seq_base) as u32 + 1).min(256)
    } else {
        0u32
    };

    let bitmap_words = num_bits.div_ceil(32) as usize;
    let mut bitmap = vec![0u32; bitmap_words];

    // v172: RTPS spec Sec.8.3.5.5 uses MSB-first bit ordering for bitmaps.
    // Bit N in word M represents sequence (bitmapBase + M*32 + N), where bit 0 is the MSB.
    for &seq in missing_seqs {
        if seq >= seq_base && seq < seq_base + num_bits as u64 {
            let bit_pos = (seq - seq_base) as usize;
            let word_idx = bit_pos / 32;
            let bit_idx = bit_pos % 32;
            if word_idx < bitmap.len() {
                // v172: MSB-first ordering per RTPS spec Sec.8.3.5.5
                bitmap[word_idx] |= 1u32 << (31 - bit_idx);
            }
        }
    }

    // Use low-level encoder with Final flag support
    let acknack = encode_acknack_with_final(
        &reader_entity_id,
        &writer_entity_id,
        seq_base,
        num_bits,
        &bitmap,
        count,
        final_flag,
    )
    .unwrap_or_else(|_| Vec::new());

    packet.extend_from_slice(&acknack);
    packet
}

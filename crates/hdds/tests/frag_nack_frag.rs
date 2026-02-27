// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures

//! NACK_FRAG retransmission integration tests.
//!
//! Validates NACK_FRAG submessage construction, wire format, and its
//! integration with FragmentBuffer's missing-fragment detection.
//!
//! These tests exercise:
//! - `build_nack_frag_submessage` / `build_nack_frag_packet` wire format
//! - `build_heartbeat_frag_submessage` / `build_heartbeat_frag_packet` wire format
//! - `FragmentBuffer::get_missing_fragments` for NACK_FRAG generation
//! - Round-trip: insert partial fragments -> detect missing -> build NACK_FRAG -> verify

use hdds::core::discovery::{FragmentBuffer, GUID};
use hdds::protocol::builder::{
    build_heartbeat_frag_packet, build_heartbeat_frag_submessage, build_nack_frag_packet,
    build_nack_frag_submessage,
};

/// Helper: create a test GUID from a simple seed.
fn test_guid(seed: u8) -> GUID {
    GUID::from_bytes([
        seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, 0x00, 0x00, 0x01,
        0x03,
    ])
}

// ---------------------------------------------------------------------------
// Test: NACK_FRAG submessage wire format - basic
// ---------------------------------------------------------------------------

#[test]
fn test_nack_frag_submessage_wire_format() {
    let reader_id = [0x00, 0x00, 0x01, 0x04];
    let writer_id = [0x00, 0x00, 0x01, 0x03];
    let writer_sn = 42u64;
    let missing = vec![2, 4, 5];
    let count = 1u32;

    let submsg = build_nack_frag_submessage(reader_id, writer_id, writer_sn, &missing, count);

    // Submessage header
    assert_eq!(submsg[0], 0x12, "submessageId should be NACK_FRAG (0x12)");
    assert_eq!(submsg[1], 0x01, "flags should be E=1 (little-endian)");

    // octetsToNextHeader (LE u16 at offset 2..4)
    let otnh = u16::from_le_bytes([submsg[2], submsg[3]]);
    assert_eq!(
        otnh as usize,
        submsg.len() - 4,
        "octetsToNextHeader should match remaining payload size"
    );

    // Reader entity ID at offset 4..8
    assert_eq!(&submsg[4..8], &reader_id);

    // Writer entity ID at offset 8..12
    assert_eq!(&submsg[8..12], &writer_id);

    // Sequence number: high(4) + low(4) at offset 12..20
    let sn_high = u32::from_le_bytes(submsg[12..16].try_into().unwrap());
    let sn_low = u32::from_le_bytes(submsg[16..20].try_into().unwrap());
    let decoded_sn = ((sn_high as u64) << 32) | sn_low as u64;
    assert_eq!(decoded_sn, writer_sn, "Decoded sequence number mismatch");

    // bitmapBase at offset 20..24
    let bitmap_base = u32::from_le_bytes(submsg[20..24].try_into().unwrap());
    assert_eq!(bitmap_base, 2, "bitmapBase should be min(missing) = 2");

    // numBits at offset 24..28
    let num_bits = u32::from_le_bytes(submsg[24..28].try_into().unwrap());
    assert_eq!(num_bits, 4, "numBits should cover fragments 2-5 = 4 bits");

    // Bitmap at offset 28..32 (1 word for 4 bits)
    let bitmap_word = u32::from_le_bytes(submsg[28..32].try_into().unwrap());

    // MSB-first ordering per RTPS spec:
    // bit 0 (frag 2): set   -> bit 31
    // bit 1 (frag 3): clear -> bit 30
    // bit 2 (frag 4): set   -> bit 29
    // bit 3 (frag 5): set   -> bit 28
    assert_ne!(
        bitmap_word & (1u32 << 31),
        0,
        "Bit for frag 2 should be set"
    );
    assert_eq!(
        bitmap_word & (1u32 << 30),
        0,
        "Bit for frag 3 should NOT be set"
    );
    assert_ne!(
        bitmap_word & (1u32 << 29),
        0,
        "Bit for frag 4 should be set"
    );
    assert_ne!(
        bitmap_word & (1u32 << 28),
        0,
        "Bit for frag 5 should be set"
    );

    // Count at the end (last 4 bytes)
    let decoded_count = u32::from_le_bytes(submsg[submsg.len() - 4..].try_into().unwrap());
    assert_eq!(decoded_count, count, "NACK_FRAG count mismatch");
}

// ---------------------------------------------------------------------------
// Test: NACK_FRAG full packet structure (RTPS header + INFO_DST + NACK_FRAG)
// ---------------------------------------------------------------------------

#[test]
fn test_nack_frag_packet_structure() {
    let our_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let dest_prefix = [13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
    let reader_id = [0x00, 0x00, 0x01, 0x04];
    let writer_id = [0x00, 0x00, 0x01, 0x03];
    let missing = vec![1, 3, 5, 7];

    let packet = build_nack_frag_packet(
        our_prefix,
        dest_prefix,
        reader_id,
        writer_id,
        100,
        &missing,
        5,
    );

    // RTPS header (20 bytes)
    assert_eq!(&packet[0..4], b"RTPS", "Missing RTPS magic");
    assert_eq!(&packet[4..6], &[2, 3], "Wrong RTPS version");
    assert_eq!(&packet[6..8], &[0x01, 0xaa], "Wrong vendor ID");
    assert_eq!(&packet[8..20], &our_prefix, "Wrong GUID prefix");

    // INFO_DST at offset 20 (4-byte header + 12-byte prefix)
    assert_eq!(packet[20], 0x0e, "Expected INFO_DST submessage (0x0e)");
    assert_eq!(
        &packet[24..36],
        &dest_prefix,
        "Wrong destination GUID prefix in INFO_DST"
    );

    // NACK_FRAG at offset 36
    assert_eq!(
        packet[36], 0x12,
        "Expected NACK_FRAG submessage (0x12) at offset 36"
    );
}

// ---------------------------------------------------------------------------
// Test: NACK_FRAG with empty missing list
// ---------------------------------------------------------------------------

#[test]
fn test_nack_frag_empty_missing_list() {
    let reader_id = [0; 4];
    let writer_id = [0; 4];
    let missing: Vec<u32> = vec![];

    let submsg = build_nack_frag_submessage(reader_id, writer_id, 1, &missing, 1);

    // Should produce valid submessage even with empty list
    assert_eq!(submsg[0], 0x12, "Should still be NACK_FRAG");
    assert!(
        submsg.len() >= 4,
        "Submessage should have at least a header"
    );
}

// ---------------------------------------------------------------------------
// Test: NACK_FRAG with single missing fragment
// ---------------------------------------------------------------------------

#[test]
fn test_nack_frag_single_missing() {
    let reader_id = [0x00, 0x00, 0x00, 0x04];
    let writer_id = [0x00, 0x00, 0x00, 0x02];
    let missing = vec![7];

    let submsg = build_nack_frag_submessage(reader_id, writer_id, 1, &missing, 1);

    // bitmapBase should be 7
    let bitmap_base = u32::from_le_bytes(submsg[20..24].try_into().unwrap());
    assert_eq!(
        bitmap_base, 7,
        "bitmapBase should be the single missing frag"
    );

    // numBits should be 1
    let num_bits = u32::from_le_bytes(submsg[24..28].try_into().unwrap());
    assert_eq!(num_bits, 1, "numBits should be 1 for single missing frag");

    // Bitmap should have bit 0 set (MSB-first: bit 31)
    let bitmap_word = u32::from_le_bytes(submsg[28..32].try_into().unwrap());
    assert_ne!(
        bitmap_word & (1u32 << 31),
        0,
        "Bit for the single missing fragment should be set"
    );
}

// ---------------------------------------------------------------------------
// Test: NACK_FRAG with large sequence number (high bits)
// ---------------------------------------------------------------------------

#[test]
fn test_nack_frag_large_sequence_number() {
    let reader_id = [0; 4];
    let writer_id = [0; 4];
    let large_sn = 0x0000_0002_0000_00FFu64; // high=2, low=255
    let missing = vec![1];

    let submsg = build_nack_frag_submessage(reader_id, writer_id, large_sn, &missing, 1);

    // Check sequence number encoding
    let sn_high = u32::from_le_bytes(submsg[12..16].try_into().unwrap());
    let sn_low = u32::from_le_bytes(submsg[16..20].try_into().unwrap());
    assert_eq!(sn_high, 2, "Sequence number high word should be 2");
    assert_eq!(sn_low, 255, "Sequence number low word should be 255");
}

// ---------------------------------------------------------------------------
// Test: HEARTBEAT_FRAG submessage wire format
// ---------------------------------------------------------------------------

#[test]
fn test_heartbeat_frag_submessage_wire_format() {
    let reader_id = [0x00, 0x00, 0x00, 0x00]; // ENTITYID_UNKNOWN
    let writer_id = [0x00, 0x00, 0x01, 0x03];
    let writer_sn = 42u64;
    let last_frag = 64u32;
    let count = 7u32;

    let submsg = build_heartbeat_frag_submessage(reader_id, writer_id, writer_sn, last_frag, count);

    // Fixed size: 4 (header) + 24 (payload) = 28 bytes
    assert_eq!(
        submsg.len(),
        28,
        "HEARTBEAT_FRAG should be exactly 28 bytes"
    );

    // Submessage ID
    assert_eq!(
        submsg[0], 0x13,
        "submessageId should be HEARTBEAT_FRAG (0x13)"
    );
    assert_eq!(submsg[1], 0x01, "flags should be E=1 (little-endian)");

    // octetsToNextHeader = 24
    let otnh = u16::from_le_bytes([submsg[2], submsg[3]]);
    assert_eq!(otnh, 24, "HEARTBEAT_FRAG octetsToNextHeader should be 24");

    // Entity IDs
    assert_eq!(&submsg[4..8], &reader_id);
    assert_eq!(&submsg[8..12], &writer_id);

    // Sequence number
    let sn_high = u32::from_le_bytes(submsg[12..16].try_into().unwrap());
    let sn_low = u32::from_le_bytes(submsg[16..20].try_into().unwrap());
    assert_eq!(sn_high, 0);
    assert_eq!(sn_low, 42);

    // lastFragmentNum
    let last_frag_decoded = u32::from_le_bytes(submsg[20..24].try_into().unwrap());
    assert_eq!(last_frag_decoded, 64);

    // count
    let count_decoded = u32::from_le_bytes(submsg[24..28].try_into().unwrap());
    assert_eq!(count_decoded, 7);
}

// ---------------------------------------------------------------------------
// Test: HEARTBEAT_FRAG full packet structure
// ---------------------------------------------------------------------------

#[test]
fn test_heartbeat_frag_packet_structure() {
    let our_prefix = [0xAA; 12];
    let dest_prefix = [0xBB; 12];
    let reader_id = [0; 4];
    let writer_id = [0x00, 0x00, 0x01, 0x03];

    let packet =
        build_heartbeat_frag_packet(our_prefix, dest_prefix, reader_id, writer_id, 50, 16, 3);

    // RTPS header
    assert_eq!(&packet[0..4], b"RTPS");
    assert_eq!(&packet[8..20], &our_prefix);

    // INFO_DST
    assert_eq!(packet[20], 0x0e);
    assert_eq!(&packet[24..36], &dest_prefix);

    // HEARTBEAT_FRAG
    assert_eq!(packet[36], 0x13);
}

// ---------------------------------------------------------------------------
// Test: FragmentBuffer get_missing_fragments drives NACK_FRAG generation
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_missing_fragments_drives_nack_frag() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x11);
    let seq_num = 5u64;
    let total_frags = 8u16;

    // Insert only fragments 1, 3, 5, 7 (missing: 2, 4, 6, 8)
    for frag_num in [1u32, 3, 5, 7] {
        let frag_data = vec![frag_num as u8; 64];
        let r = buffer.insert_fragment(guid, seq_num, frag_num, total_frags, frag_data);
        assert!(r.is_none());
    }

    // Query missing fragments
    let result = buffer.get_missing_fragments(&guid, seq_num);
    assert!(result.is_some(), "Should have missing fragment info");

    let (missing, total) = result.unwrap();
    assert_eq!(total, total_frags);
    assert_eq!(missing, vec![2, 4, 6, 8], "Missing fragments mismatch");

    // Build a NACK_FRAG from the missing list
    let reader_id = [0x00, 0x00, 0x00, 0x04];
    let writer_id = [0x00, 0x00, 0x00, 0x02];
    let submsg = build_nack_frag_submessage(reader_id, writer_id, seq_num, &missing, 1);

    // Verify the NACK_FRAG was built correctly
    assert_eq!(submsg[0], 0x12, "Should be NACK_FRAG");

    // bitmapBase should be 2 (first missing)
    let bitmap_base = u32::from_le_bytes(submsg[20..24].try_into().unwrap());
    assert_eq!(bitmap_base, 2, "bitmapBase should be 2");

    // numBits should cover 2..8 = 7 bits
    let num_bits = u32::from_le_bytes(submsg[24..28].try_into().unwrap());
    assert_eq!(num_bits, 7, "numBits should cover fragments 2 through 8");
}

// ---------------------------------------------------------------------------
// Test: get_missing_fragments returns None for unknown sequence
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_missing_unknown_sequence() {
    let buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x22);

    let result = buffer.get_missing_fragments(&guid, 999);
    assert!(result.is_none(), "Unknown sequence should return None");
}

// ---------------------------------------------------------------------------
// Test: get_missing_fragments returns empty for complete sequence
// (sequence is removed on completion, so this should return None)
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_complete_sequence_not_in_pending() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x33);
    let seq_num = 1u64;

    // Complete a 2-fragment sequence
    buffer.insert_fragment(guid, seq_num, 1, 2, vec![0xAA]);
    let result = buffer.insert_fragment(guid, seq_num, 2, 2, vec![0xBB]);
    assert!(result.is_some(), "Should complete");

    // After completion, sequence is removed from pending
    let missing = buffer.get_missing_fragments(&guid, seq_num);
    assert!(
        missing.is_none(),
        "Completed sequence should be removed from pending"
    );
}

// ---------------------------------------------------------------------------
// Test: NACK_FRAG bitmap spans multiple u32 words
// ---------------------------------------------------------------------------

#[test]
fn test_nack_frag_bitmap_multiple_words() {
    let reader_id = [0; 4];
    let writer_id = [0; 4];

    // Missing fragments that span more than 32 bits
    // frag 1 and frag 40 -> numBits = 40, bitmap needs 2 words
    let missing = vec![1, 40];

    let submsg = build_nack_frag_submessage(reader_id, writer_id, 1, &missing, 1);

    let bitmap_base = u32::from_le_bytes(submsg[20..24].try_into().unwrap());
    assert_eq!(bitmap_base, 1, "bitmapBase should be 1");

    let num_bits = u32::from_le_bytes(submsg[24..28].try_into().unwrap());
    assert_eq!(num_bits, 40, "numBits should be 40 to cover frag 1 and 40");

    // 40 bits -> 2 u32 words
    let bitmap_word0 = u32::from_le_bytes(submsg[28..32].try_into().unwrap());
    let bitmap_word1 = u32::from_le_bytes(submsg[32..36].try_into().unwrap());

    // Bit 0 (frag 1) in word 0, MSB-first -> bit 31
    assert_ne!(
        bitmap_word0 & (1u32 << 31),
        0,
        "Bit for frag 1 should be set in word 0"
    );

    // Bit 39 (frag 40) in word 1, position = 39 - 32 = 7, MSB-first -> bit (31-7) = 24
    assert_ne!(
        bitmap_word1 & (1u32 << 24),
        0,
        "Bit for frag 40 should be set in word 1"
    );
}

// ---------------------------------------------------------------------------
// Test: NACK_FRAG count field increments correctly across calls
// ---------------------------------------------------------------------------

#[test]
fn test_nack_frag_count_increment() {
    let reader_id = [0; 4];
    let writer_id = [0; 4];
    let missing = vec![1];

    for expected_count in 1u32..=5 {
        let submsg = build_nack_frag_submessage(reader_id, writer_id, 1, &missing, expected_count);

        let decoded_count = u32::from_le_bytes(submsg[submsg.len() - 4..].try_into().unwrap());
        assert_eq!(
            decoded_count, expected_count,
            "Count field should match provided count"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: get_stale_sequences for NACK_FRAG scheduling
// ---------------------------------------------------------------------------

#[test]
fn test_fragment_buffer_stale_sequences() {
    let mut buffer = FragmentBuffer::new(256, 5000);
    let guid = test_guid(0x44);

    // Insert partial fragments for two sequences
    buffer.insert_fragment(guid, 1, 1, 4, vec![0xAA]);
    buffer.insert_fragment(guid, 2, 1, 3, vec![0xBB]);

    // With 0ms threshold, both should be stale
    let stale = buffer.get_stale_sequences(0);
    assert_eq!(
        stale.len(),
        2,
        "Both sequences should be stale at 0ms threshold"
    );

    // Verify stale sequence details
    for entry in &stale {
        assert_eq!(entry.0, guid, "GUID should match");
        match entry.1 {
            1 => {
                assert_eq!(entry.2, 3, "Seq 1 should have 3 missing (frags 2,3,4)");
                assert_eq!(entry.3, 4, "Seq 1 has 4 total fragments");
            }
            2 => {
                assert_eq!(entry.2, 2, "Seq 2 should have 2 missing (frags 2,3)");
                assert_eq!(entry.3, 3, "Seq 2 has 3 total fragments");
            }
            other => panic!("Unexpected seq_num: {}", other),
        }
    }

    // With very high threshold, none should be stale yet
    let stale_high = buffer.get_stale_sequences(999_999);
    assert!(
        stale_high.is_empty(),
        "No sequences should be stale with high threshold"
    );
}

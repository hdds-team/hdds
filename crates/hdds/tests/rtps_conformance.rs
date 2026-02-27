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

//! RTPS 2.5 Wire Protocol Conformance Tests
//!
//! Validates that HDDS produces spec-compliant RTPS wire format per
//! OMG DDSI-RTPS v2.5 specification.
//!
//! Each test constructs a submessage using HDDS protocol encoders,
//! then inspects the raw bytes to verify they match the spec layout.
//!
//! # References
//!
//! - OMG DDSI-RTPS v2.5 Section 8.3 (Message Structure)
//! - OMG DDSI-RTPS v2.5 Section 9.4.5 (Wire Representation)

use hdds::protocol::builder::{build_data_packet, build_heartbeat_packet};
use hdds::protocol::constants::*;
use hdds::protocol::rtps::{
    encode_acknack_with_count, encode_acknack_with_final, encode_data, encode_gap,
    encode_heartbeat, encode_heartbeat_final, encode_info_dst, encode_info_ts,
};

// ============================================================================
// Helper: read little-endian values from byte slices
// ============================================================================

fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn read_i32_le(buf: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn read_sequence_number_le(buf: &[u8], offset: usize) -> u64 {
    let high = read_i32_le(buf, offset) as i64;
    let low = read_u32_le(buf, offset + 4) as u64;
    ((high << 32) as u64) | low
}

// ============================================================================
// Test 1: RTPS Header Format (Sec.8.3.3)
// ============================================================================

/// Verify RTPS header is exactly 20 bytes with correct magic "RTPS",
/// protocol version, vendor ID, and GUID prefix.
///
/// RTPS Header layout (20 bytes):
/// ```text
/// Offset  Field                Size
/// 0       magic ("RTPS")       4 bytes
/// 4       protocol version     2 bytes (major, minor)
/// 6       vendor ID            2 bytes
/// 8       GUID prefix         12 bytes
/// ```
#[test]
fn test_rtps_header_format() {
    // Build a complete RTPS packet using the data builder
    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let packet = build_data_packet("conformance/test", 1, &payload);

    // Packet must be at least 20 bytes (RTPS header)
    assert!(
        packet.len() >= RTPS_HEADER_SIZE,
        "RTPS packet must be at least {} bytes, got {}",
        RTPS_HEADER_SIZE,
        packet.len()
    );

    // Bytes 0-3: RTPS magic "RTPS" (0x52545053)
    assert_eq!(
        &packet[0..4],
        RTPS_MAGIC,
        "RTPS magic must be 'RTPS' (0x52545053)"
    );

    // Byte 4: Protocol version major (must be 2)
    assert_eq!(
        packet[4], RTPS_VERSION_MAJOR,
        "Protocol version major must be {}",
        RTPS_VERSION_MAJOR
    );

    // Byte 5: Protocol version minor (HDDS uses 2.4 for OpenDDS compat)
    assert_eq!(
        packet[5], RTPS_VERSION_MINOR,
        "Protocol version minor must be {}",
        RTPS_VERSION_MINOR
    );

    // Bytes 6-7: Vendor ID
    assert_eq!(
        &packet[6..8],
        &HDDS_VENDOR_ID,
        "Vendor ID must be HDDS vendor ID [{:#04X}, {:#04X}]",
        HDDS_VENDOR_ID[0],
        HDDS_VENDOR_ID[1]
    );

    // Bytes 8-19: GUID prefix (12 bytes)
    let guid_prefix = &packet[8..20];
    assert_eq!(
        guid_prefix.len(),
        RTPS_GUID_PREFIX_SIZE,
        "GUID prefix must be exactly {} bytes",
        RTPS_GUID_PREFIX_SIZE
    );

    // RTPS header must be exactly 20 bytes
    assert_eq!(RTPS_HEADER_SIZE, 20, "RTPS header size constant must be 20");
}

/// Verify the RTPS header size constant matches the spec.
#[test]
fn test_rtps_header_size_constant() {
    // magic(4) + version(2) + vendorId(2) + guidPrefix(12) = 20
    let expected = 4 + 2 + 2 + 12;
    assert_eq!(
        RTPS_HEADER_SIZE, expected,
        "RTPS_HEADER_SIZE must be {} (magic + version + vendor + prefix)",
        expected
    );
}

// ============================================================================
// Test 2: DATA Submessage Format (Sec.8.3.7.2)
// ============================================================================

/// Verify DATA submessage follows RTPS spec layout.
///
/// DATA submessage layout:
/// ```text
/// Offset  Field                     Size
/// 0       submessageId (0x15)        1 byte
/// 1       flags                      1 byte
/// 2       octetsToNextHeader         2 bytes (LE)
/// 4       extraFlags                 2 bytes (LE)
/// 6       octetsToInlineQos          2 bytes (LE)
/// 8       readerEntityId             4 bytes
/// 12      writerEntityId             4 bytes
/// 16      writerSN (high)            4 bytes (LE)
/// 20      writerSN (low)             4 bytes (LE)
/// 24      serializedPayload          variable
/// ```
#[test]
fn test_data_submessage_format() {
    let reader_id: [u8; 4] = [0x00, 0x00, 0x00, 0x04]; // user reader
    let writer_id: [u8; 4] = [0x00, 0x00, 0x00, 0x03]; // user writer
    let sequence_number: u64 = 42;
    let payload = b"Hello, RTPS!";

    let buf = encode_data(&reader_id, &writer_id, sequence_number, payload)
        .expect("DATA encoding must succeed");

    // Byte 0: submessageId = 0x15 (DATA)
    assert_eq!(
        buf[0], RTPS_SUBMSG_DATA,
        "DATA submessageId must be {:#04X}",
        RTPS_SUBMSG_DATA
    );

    // Byte 1: flags - bit 0 (LE=1), bit 2 (Data present=1)
    // 0x05 = LE(0x01) | DataFlag(0x04)
    assert_ne!(
        buf[1] & 0x01,
        0,
        "DATA endianness flag (bit 0) must be set for LE"
    );
    assert_ne!(
        buf[1] & 0x04,
        0,
        "DATA dataFlag (bit 2) must be set when data present"
    );

    // Bytes 2-3: octetsToNextHeader (LE)
    let octets_to_next = read_u16_le(&buf, 2);
    // Should equal total submessage body size: extraFlags(2) + octetsToInlineQos(2)
    // + readerEntityId(4) + writerEntityId(4) + seqNum(8) + payload
    let expected_body = 2 + 2 + 4 + 4 + 8 + payload.len();
    assert_eq!(
        octets_to_next as usize, expected_body,
        "octetsToNextHeader must be {} (body size without submessage header)",
        expected_body
    );

    // Bytes 4-5: extraFlags (usually 0x0000)
    let extra_flags = read_u16_le(&buf, 4);
    assert_eq!(
        extra_flags, 0,
        "DATA extraFlags must be 0 for standard encoding"
    );

    // Bytes 6-7: octetsToInlineQos
    // Standard value is 16 when no inline QoS: readerEntityId(4) + writerEntityId(4) + seqNum(8)
    let octets_to_inline_qos = read_u16_le(&buf, 6);
    assert_eq!(
        octets_to_inline_qos, 16,
        "octetsToInlineQos must be 16 (entityIds + seqNum)"
    );

    // Bytes 8-11: readerEntityId
    assert_eq!(&buf[8..12], &reader_id, "readerEntityId must match input");

    // Bytes 12-15: writerEntityId
    assert_eq!(&buf[12..16], &writer_id, "writerEntityId must match input");

    // Bytes 16-23: writerSN (SequenceNumber_t = high:i32 + low:u32)
    let sn = read_sequence_number_le(&buf, 16);
    assert_eq!(
        sn, sequence_number,
        "writerSN must match input sequence number"
    );

    // Bytes 24+: serializedPayload
    assert_eq!(
        &buf[24..24 + payload.len()],
        payload,
        "serializedPayload must match input"
    );

    // Total submessage size: 4 (header) + body
    assert_eq!(
        buf.len(),
        4 + expected_body,
        "Total DATA submessage size must be 4 + {}",
        expected_body
    );
}

/// Verify DATA submessage with large sequence numbers (high word non-zero).
#[test]
fn test_data_submessage_large_sequence_number() {
    let reader_id = [0x00, 0x00, 0x00, 0x00];
    let writer_id = [0x00, 0x00, 0x00, 0x02];
    // Sequence number that requires the high word
    let sn: u64 = (1u64 << 32) + 100;
    let payload = b"test";

    let buf = encode_data(&reader_id, &writer_id, sn, payload).expect("DATA encoding must succeed");

    // SequenceNumber_t at offset 16: high=1, low=100
    let sn_high = read_i32_le(&buf, 16);
    let sn_low = read_u32_le(&buf, 20);
    assert_eq!(sn_high, 1, "SN high word must be 1");
    assert_eq!(sn_low, 100, "SN low word must be 100");

    let decoded_sn = read_sequence_number_le(&buf, 16);
    assert_eq!(decoded_sn, sn, "Full sequence number must round-trip");
}

// ============================================================================
// Test 3: HEARTBEAT Submessage Format (Sec.8.3.7.5)
// ============================================================================

/// Verify HEARTBEAT submessage follows RTPS spec layout.
///
/// HEARTBEAT layout (32 bytes total):
/// ```text
/// Offset  Field                     Size
/// 0       submessageId (0x07)        1 byte
/// 1       flags                      1 byte
/// 2       octetsToNextHeader         2 bytes (LE)
/// 4       readerEntityId             4 bytes
/// 8       writerEntityId             4 bytes
/// 12      firstSN (high)             4 bytes (LE)
/// 16      firstSN (low)              4 bytes (LE)
/// 20      lastSN (high)              4 bytes (LE)
/// 24      lastSN (low)               4 bytes (LE)
/// 28      count                      4 bytes (LE)
/// ```
#[test]
fn test_heartbeat_submessage_format() {
    let reader_id = [0x00, 0x00, 0x00, 0x00]; // ENTITYID_UNKNOWN
    let writer_id = [0x00, 0x00, 0x03, 0xC2]; // SEDP publications writer
    let first_sn: u64 = 1;
    let last_sn: u64 = 100;
    let count: u32 = 7;

    let buf = encode_heartbeat(&reader_id, &writer_id, first_sn, last_sn, count)
        .expect("HEARTBEAT encoding must succeed");

    // Total size must be 32 bytes
    assert_eq!(
        buf.len(),
        32,
        "HEARTBEAT submessage must be exactly 32 bytes"
    );

    // Byte 0: submessageId = 0x07
    assert_eq!(
        buf[0], RTPS_SUBMSG_HEARTBEAT,
        "HEARTBEAT submessageId must be {:#04X}",
        RTPS_SUBMSG_HEARTBEAT
    );

    // Byte 1: flags - bit 0 = LE
    assert_ne!(
        buf[1] & 0x01,
        0,
        "HEARTBEAT endianness flag must be set for LE"
    );

    // Bytes 2-3: octetsToNextHeader = 28
    let octets_to_next = read_u16_le(&buf, 2);
    assert_eq!(
        octets_to_next, 28,
        "HEARTBEAT octetsToNextHeader must be 28 (32 - 4)"
    );

    // Bytes 4-7: readerEntityId
    assert_eq!(&buf[4..8], &reader_id, "readerEntityId must match");

    // Bytes 8-11: writerEntityId
    assert_eq!(&buf[8..12], &writer_id, "writerEntityId must match");

    // Bytes 12-19: firstSN
    let decoded_first = read_sequence_number_le(&buf, 12);
    assert_eq!(decoded_first, first_sn, "firstSN must match");

    // Bytes 20-27: lastSN
    let decoded_last = read_sequence_number_le(&buf, 20);
    assert_eq!(decoded_last, last_sn, "lastSN must match");

    // Bytes 28-31: count
    let decoded_count = read_u32_le(&buf, 28);
    assert_eq!(decoded_count, count, "count must match");
}

/// Verify HEARTBEAT Final flag (bit 1) is correctly set.
#[test]
fn test_heartbeat_final_flag() {
    let reader_id = [0x00, 0x00, 0x00, 0x00];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];

    // Non-final HEARTBEAT: flags = 0x01 (LE only)
    let buf_normal = encode_heartbeat(&reader_id, &writer_id, 1, 10, 1)
        .expect("HEARTBEAT encoding must succeed");
    assert_eq!(
        buf_normal[1] & 0x02,
        0,
        "Non-final HEARTBEAT must NOT have Final flag (bit 1)"
    );

    // Final HEARTBEAT: flags = 0x03 (LE + Final)
    let buf_final = encode_heartbeat_final(&reader_id, &writer_id, 1, 10, 1)
        .expect("HEARTBEAT_FINAL encoding must succeed");
    assert_ne!(
        buf_final[1] & 0x02,
        0,
        "Final HEARTBEAT must have Final flag (bit 1) set"
    );
}

// ============================================================================
// Test 4: ACKNACK Submessage Format (Sec.8.3.7.1)
// ============================================================================

/// Verify ACKNACK submessage follows RTPS spec layout.
///
/// ACKNACK layout:
/// ```text
/// Offset  Field                     Size
/// 0       submessageId (0x06)        1 byte
/// 1       flags                      1 byte
/// 2       octetsToNextHeader         2 bytes (LE)
/// 4       readerEntityId             4 bytes
/// 8       writerEntityId             4 bytes
/// 12      readerSNState.bitmapBase   8 bytes (SequenceNumber_t)
/// 20      readerSNState.numBits      4 bytes (LE)
/// 24      readerSNState.bitmap[]     variable (4 bytes per word)
/// ...     count                      4 bytes (LE)
/// ```
#[test]
fn test_acknack_submessage_format() {
    let reader_id = [0x00, 0x00, 0x04, 0xC7]; // SEDP subscriptions reader
    let writer_id = [0x00, 0x00, 0x03, 0xC2]; // SEDP publications writer
    let base_sn: u64 = 5;
    let num_bits: u32 = 32;
    let bitmap: &[u32] = &[0x0000_000F]; // bits 0-3 set (missing SN 5,6,7,8)
    let count: u32 = 3;

    let buf = encode_acknack_with_count(&reader_id, &writer_id, base_sn, num_bits, bitmap, count)
        .expect("ACKNACK encoding must succeed");

    // Byte 0: submessageId = 0x06
    assert_eq!(
        buf[0], RTPS_SUBMSG_ACKNACK,
        "ACKNACK submessageId must be {:#04X}",
        RTPS_SUBMSG_ACKNACK
    );

    // Byte 1: flags - bit 0 = LE
    assert_ne!(
        buf[1] & 0x01,
        0,
        "ACKNACK endianness flag must be set for LE"
    );

    // Bytes 2-3: octetsToNextHeader
    let octets_to_next = read_u16_le(&buf, 2);
    // entityIds(8) + bitmapBase(8) + numBits(4) + bitmap(4) + count(4) = 28
    let expected_body = 8 + 8 + 4 + 4 + 4;
    assert_eq!(
        octets_to_next as usize, expected_body,
        "ACKNACK octetsToNextHeader must be {}",
        expected_body
    );

    // Bytes 4-7: readerEntityId
    assert_eq!(&buf[4..8], &reader_id, "readerEntityId must match");

    // Bytes 8-11: writerEntityId
    assert_eq!(&buf[8..12], &writer_id, "writerEntityId must match");

    // Bytes 12-19: bitmapBase (SequenceNumber_t)
    let decoded_base = read_sequence_number_le(&buf, 12);
    assert_eq!(decoded_base, base_sn, "bitmapBase must match");

    // Bytes 20-23: numBits
    let decoded_num_bits = read_u32_le(&buf, 20);
    assert_eq!(decoded_num_bits, num_bits, "numBits must match");

    // Bytes 24-27: bitmap[0]
    let decoded_bitmap_word = read_u32_le(&buf, 24);
    assert_eq!(decoded_bitmap_word, 0x0000_000F, "bitmap[0] must match");

    // Bytes 28-31: count
    let decoded_count = read_u32_le(&buf, 28);
    assert_eq!(decoded_count, count, "count must match");
}

/// Verify ACKNACK with zero bits (positive ACK, no missing sequences).
#[test]
fn test_acknack_positive_ack_format() {
    let reader_id = [0x00, 0x00, 0x04, 0xC7];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];
    let base_sn: u64 = 10;
    let num_bits: u32 = 0;
    let bitmap: &[u32] = &[];
    let count: u32 = 1;

    let buf = encode_acknack_with_count(&reader_id, &writer_id, base_sn, num_bits, bitmap, count)
        .expect("Positive ACKNACK encoding must succeed");

    // numBits = 0 means pure positive acknowledgment
    let decoded_num_bits = read_u32_le(&buf, 20);
    assert_eq!(
        decoded_num_bits, 0,
        "Positive ACKNACK numBits must be 0 (no missing sequences)"
    );

    // Body: entityIds(8) + bitmapBase(8) + numBits(4) + count(4) = 24
    let octets_to_next = read_u16_le(&buf, 2);
    assert_eq!(
        octets_to_next, 24,
        "Positive ACKNACK octetsToNextHeader must be 24 (no bitmap words)"
    );
}

/// Verify ACKNACK Final flag (bit 1) behavior.
#[test]
fn test_acknack_final_flag() {
    let reader_id = [0x00, 0x00, 0x04, 0xC7];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];

    // Non-final ACKNACK
    let buf_normal = encode_acknack_with_final(&reader_id, &writer_id, 5, 0, &[], 1, false)
        .expect("ACKNACK encoding must succeed");
    assert_eq!(
        buf_normal[1] & 0x02,
        0,
        "Non-final ACKNACK must NOT have Final flag (bit 1)"
    );

    // Final ACKNACK
    let buf_final = encode_acknack_with_final(&reader_id, &writer_id, 5, 0, &[], 1, true)
        .expect("ACKNACK final encoding must succeed");
    assert_ne!(
        buf_final[1] & 0x02,
        0,
        "Final ACKNACK must have Final flag (bit 1) set"
    );
}

// ============================================================================
// Test 5: INFO_DST Submessage Format (Sec.8.3.7.8)
// ============================================================================

/// Verify INFO_DST submessage follows RTPS spec layout.
///
/// INFO_DST layout (16 bytes total):
/// ```text
/// Offset  Field                     Size
/// 0       submessageId (0x0E)        1 byte
/// 1       flags                      1 byte
/// 2       octetsToNextHeader         2 bytes (LE)
/// 4       guidPrefix                12 bytes
/// ```
#[test]
fn test_info_dst_format() {
    let guid_prefix: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];

    let buf = encode_info_dst(&guid_prefix);

    // Total size must be 16 bytes
    assert_eq!(buf.len(), 16, "INFO_DST must be exactly 16 bytes");

    // Byte 0: submessageId = 0x0E
    assert_eq!(
        buf[0], RTPS_SUBMSG_INFO_DST,
        "INFO_DST submessageId must be {:#04X}",
        RTPS_SUBMSG_INFO_DST
    );

    // Byte 1: flags
    assert_ne!(
        buf[1] & 0x01,
        0,
        "INFO_DST endianness flag must be set for LE"
    );

    // Bytes 2-3: octetsToNextHeader = 12
    let octets_to_next = read_u16_le(&buf, 2);
    assert_eq!(
        octets_to_next, 12,
        "INFO_DST octetsToNextHeader must be 12 (GUID prefix size)"
    );

    // Bytes 4-15: guidPrefix (12 bytes, opaque - not endianness-swapped)
    assert_eq!(
        &buf[4..16],
        &guid_prefix,
        "INFO_DST guidPrefix must be written verbatim (12 bytes)"
    );
}

/// Verify INFO_DST with all-zeros and all-ones GUID prefix.
#[test]
fn test_info_dst_boundary_values() {
    // All zeros (GUID_UNKNOWN prefix)
    let zeros: [u8; 12] = [0x00; 12];
    let buf_zeros = encode_info_dst(&zeros);
    assert_eq!(
        &buf_zeros[4..16],
        &zeros,
        "All-zero GUID prefix must be preserved"
    );

    // All ones
    let ones: [u8; 12] = [0xFF; 12];
    let buf_ones = encode_info_dst(&ones);
    assert_eq!(
        &buf_ones[4..16],
        &ones,
        "All-ones GUID prefix must be preserved"
    );
}

// ============================================================================
// Test 6: INFO_TS Submessage Format (Sec.8.3.7.7)
// ============================================================================

/// Verify INFO_TS submessage follows RTPS spec layout.
///
/// INFO_TS layout (12 bytes total):
/// ```text
/// Offset  Field                     Size
/// 0       submessageId (0x09)        1 byte
/// 1       flags                      1 byte
/// 2       octetsToNextHeader         2 bytes (LE)
/// 4       timestamp.seconds          4 bytes (LE)
/// 8       timestamp.fraction         4 bytes (LE)
/// ```
#[test]
fn test_info_ts_format() {
    let timestamp_sec: u32 = 1700000000; // ~2023-11-14
    let timestamp_frac: u32 = 0x80000000; // 0.5 seconds

    let buf = encode_info_ts(timestamp_sec, timestamp_frac);

    // Total size must be 12 bytes
    assert_eq!(buf.len(), 12, "INFO_TS must be exactly 12 bytes");

    // Byte 0: submessageId = 0x09
    assert_eq!(
        buf[0], RTPS_SUBMSG_INFO_TS,
        "INFO_TS submessageId must be {:#04X}",
        RTPS_SUBMSG_INFO_TS
    );

    // Byte 1: flags
    assert_ne!(
        buf[1] & 0x01,
        0,
        "INFO_TS endianness flag must be set for LE"
    );

    // Bytes 2-3: octetsToNextHeader = 8
    let octets_to_next = read_u16_le(&buf, 2);
    assert_eq!(
        octets_to_next, 8,
        "INFO_TS octetsToNextHeader must be 8 (seconds + fraction)"
    );

    // Bytes 4-7: timestamp.seconds (Time_t)
    let decoded_sec = read_u32_le(&buf, 4);
    assert_eq!(decoded_sec, timestamp_sec, "timestamp.seconds must match");

    // Bytes 8-11: timestamp.fraction
    let decoded_frac = read_u32_le(&buf, 8);
    assert_eq!(
        decoded_frac, timestamp_frac,
        "timestamp.fraction must match"
    );
}

/// Verify INFO_TS timestamp boundary values.
#[test]
fn test_info_ts_boundary_values() {
    // Zero timestamp
    let buf_zero = encode_info_ts(0, 0);
    assert_eq!(
        read_u32_le(&buf_zero, 4),
        0,
        "Zero seconds must encode correctly"
    );
    assert_eq!(
        read_u32_le(&buf_zero, 8),
        0,
        "Zero fraction must encode correctly"
    );

    // Maximum timestamp
    let buf_max = encode_info_ts(u32::MAX, u32::MAX);
    assert_eq!(
        read_u32_le(&buf_max, 4),
        u32::MAX,
        "Max seconds must encode correctly"
    );
    assert_eq!(
        read_u32_le(&buf_max, 8),
        u32::MAX,
        "Max fraction must encode correctly"
    );
}

// ============================================================================
// Test 7: GAP Submessage Format (Sec.8.3.7.4)
// ============================================================================

/// Verify GAP submessage follows RTPS spec layout.
///
/// GAP layout:
/// ```text
/// Offset  Field                     Size
/// 0       submessageId (0x08)        1 byte
/// 1       flags                      1 byte
/// 2       octetsToNextHeader         2 bytes (LE)
/// 4       readerEntityId             4 bytes
/// 8       writerEntityId             4 bytes
/// 12      gapStart (SequenceNumber)  8 bytes
/// 20      gapList.bitmapBase         8 bytes
/// 28      gapList.numBits            4 bytes
/// 32      gapList.bitmap[]           variable
/// ```
#[test]
fn test_gap_submessage_format() {
    let reader_id = [0x00, 0x00, 0x00, 0x04];
    let writer_id = [0x00, 0x00, 0x00, 0x03];
    let gap_start: u64 = 5;
    let gap_list_base: u64 = 10;
    let num_bits: u32 = 32;
    let gap_bitmap: &[u32] = &[0x0000_001F]; // bits 0-4 set

    let buf = encode_gap(
        &reader_id,
        &writer_id,
        gap_start,
        gap_list_base,
        num_bits,
        gap_bitmap,
    )
    .expect("GAP encoding must succeed");

    // Byte 0: submessageId = 0x08
    assert_eq!(
        buf[0], RTPS_SUBMSG_GAP,
        "GAP submessageId must be {:#04X}",
        RTPS_SUBMSG_GAP
    );

    // Byte 1: flags
    assert_ne!(buf[1] & 0x01, 0, "GAP endianness flag must be set for LE");

    // Bytes 2-3: octetsToNextHeader
    let octets_to_next = read_u16_le(&buf, 2);
    // entityIds(8) + gapStart(8) + gapListBase(8) + numBits(4) + bitmap(4) = 32
    assert_eq!(octets_to_next, 32, "GAP octetsToNextHeader must be 32");

    // Bytes 4-7: readerEntityId
    assert_eq!(&buf[4..8], &reader_id, "GAP readerEntityId must match");

    // Bytes 8-11: writerEntityId
    assert_eq!(&buf[8..12], &writer_id, "GAP writerEntityId must match");

    // Bytes 12-19: gapStart (SequenceNumber_t)
    let decoded_gap_start = read_sequence_number_le(&buf, 12);
    assert_eq!(decoded_gap_start, gap_start, "gapStart must match");

    // Bytes 20-27: gapList.bitmapBase (SequenceNumber_t)
    let decoded_gap_list_base = read_sequence_number_le(&buf, 20);
    assert_eq!(
        decoded_gap_list_base, gap_list_base,
        "gapList.bitmapBase must match"
    );

    // Bytes 28-31: gapList.numBits
    let decoded_num_bits = read_u32_le(&buf, 28);
    assert_eq!(decoded_num_bits, num_bits, "gapList.numBits must match");

    // Bytes 32-35: gapList.bitmap[0]
    let decoded_bitmap = read_u32_le(&buf, 32);
    assert_eq!(decoded_bitmap, 0x0000_001F, "gapList.bitmap[0] must match");
}

/// Verify GAP with empty bitmap (numBits=0).
#[test]
fn test_gap_empty_bitmap() {
    let reader_id = [0x00, 0x00, 0x00, 0x00];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];
    let gap_start: u64 = 1;
    let gap_list_base: u64 = 5;

    let buf = encode_gap(&reader_id, &writer_id, gap_start, gap_list_base, 0, &[])
        .expect("GAP empty bitmap encoding must succeed");

    let decoded_num_bits = read_u32_le(&buf, 28);
    assert_eq!(
        decoded_num_bits, 0,
        "GAP with no irrelevant sequences must have numBits=0"
    );

    // Body: entityIds(8) + gapStart(8) + gapListBase(8) + numBits(4) = 28
    let octets_to_next = read_u16_le(&buf, 2);
    assert_eq!(
        octets_to_next, 28,
        "GAP with empty bitmap must have octetsToNextHeader=28"
    );
}

// ============================================================================
// Test 8: Endianness Flag (Sec.9.4.5.1.1)
// ============================================================================

/// Verify little-endian flag (0x01) is set in submessage flags for all submessages.
///
/// RTPS v2.5 Sec.9.4.5.1.1: Bit 0 of submessage flags indicates endianness.
/// 0 = Big-Endian, 1 = Little-Endian.
/// HDDS always encodes in Little-Endian.
#[test]
fn test_endianness_flag_all_submessages() {
    let reader_id = [0x00, 0x00, 0x04, 0xC7];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];
    let guid_prefix: [u8; 12] = [0x01; 12];

    // DATA
    let data_buf = encode_data(&reader_id, &writer_id, 1, b"test").expect("DATA encode");
    assert_ne!(data_buf[1] & 0x01, 0, "DATA must have LE flag (bit 0) set");

    // HEARTBEAT
    let hb_buf = encode_heartbeat(&reader_id, &writer_id, 1, 10, 1).expect("HEARTBEAT encode");
    assert_ne!(
        hb_buf[1] & 0x01,
        0,
        "HEARTBEAT must have LE flag (bit 0) set"
    );

    // ACKNACK
    let ack_buf =
        encode_acknack_with_count(&reader_id, &writer_id, 1, 0, &[], 1).expect("ACKNACK encode");
    assert_ne!(
        ack_buf[1] & 0x01,
        0,
        "ACKNACK must have LE flag (bit 0) set"
    );

    // INFO_TS
    let ts_buf = encode_info_ts(12345, 0);
    assert_ne!(ts_buf[1] & 0x01, 0, "INFO_TS must have LE flag (bit 0) set");

    // INFO_DST
    let dst_buf = encode_info_dst(&guid_prefix);
    assert_ne!(
        dst_buf[1] & 0x01,
        0,
        "INFO_DST must have LE flag (bit 0) set"
    );

    // GAP
    let gap_buf = encode_gap(&reader_id, &writer_id, 1, 5, 0, &[]).expect("GAP encode");
    assert_ne!(gap_buf[1] & 0x01, 0, "GAP must have LE flag (bit 0) set");
}

// ============================================================================
// Test 9: Entity ID Well-Known Values (Sec.8.2.4.3)
// ============================================================================

/// Verify ENTITYID_PARTICIPANT value per spec.
#[test]
fn test_entityid_participant() {
    // RTPS v2.5: ENTITYID_PARTICIPANT = {0,0,1,0xC1}
    // EntityId_t is always big-endian per spec.
    assert_eq!(
        RTPS_ENTITYID_PARTICIPANT,
        [0x00, 0x00, 0x01, 0xC1],
        "ENTITYID_PARTICIPANT must be {{0x00, 0x00, 0x01, 0xC1}}"
    );
    // Last byte 0xC1 = built-in participant entity kind
    assert_eq!(
        RTPS_ENTITYID_PARTICIPANT[3], 0xC1,
        "ENTITYID_PARTICIPANT kind byte must be 0xC1"
    );
}

/// Verify SEDP built-in publication writer/reader entity IDs.
#[test]
fn test_entityid_sedp_publications() {
    // ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER = {0,0,3,0xC2}
    assert_eq!(
        RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        [0x00, 0x00, 0x03, 0xC2],
        "SEDP publications writer EntityId must be {{0x00, 0x00, 0x03, 0xC2}}"
    );
    // Last byte: 0xC2 = built-in writer with key
    assert_eq!(
        RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER[3], 0xC2,
        "SEDP publications writer kind must be 0xC2"
    );

    // ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER = {0,0,3,0xC7}
    assert_eq!(
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
        [0x00, 0x00, 0x03, 0xC7],
        "SEDP publications reader EntityId must be {{0x00, 0x00, 0x03, 0xC7}}"
    );
    assert_eq!(
        RTPS_ENTITYID_SEDP_PUBLICATIONS_READER[3], 0xC7,
        "SEDP publications reader kind must be 0xC7"
    );
}

/// Verify SEDP built-in subscription writer/reader entity IDs.
#[test]
fn test_entityid_sedp_subscriptions() {
    // ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER = {0,0,4,0xC2}
    assert_eq!(
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
        [0x00, 0x00, 0x04, 0xC2],
        "SEDP subscriptions writer EntityId must be {{0x00, 0x00, 0x04, 0xC2}}"
    );

    // ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_READER = {0,0,4,0xC7}
    assert_eq!(
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
        [0x00, 0x00, 0x04, 0xC7],
        "SEDP subscriptions reader EntityId must be {{0x00, 0x00, 0x04, 0xC7}}"
    );
}

/// Verify SPDP built-in participant writer/reader entity IDs.
#[test]
fn test_entityid_spdp() {
    // ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER = {0,1,0,0xC2}
    assert_eq!(
        RTPS_ENTITYID_SPDP_WRITER,
        [0x00, 0x01, 0x00, 0xC2],
        "SPDP writer EntityId must be {{0x00, 0x01, 0x00, 0xC2}}"
    );

    // ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER = {0,1,0,0xC7}
    assert_eq!(
        RTPS_ENTITYID_SPDP_READER,
        [0x00, 0x01, 0x00, 0xC7],
        "SPDP reader EntityId must be {{0x00, 0x01, 0x00, 0xC7}}"
    );
}

/// Verify P2P built-in participant message writer/reader entity IDs.
#[test]
fn test_entityid_p2p_participant_message() {
    // ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER = {0,2,0,0xC2}
    assert_eq!(
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER,
        [0x00, 0x02, 0x00, 0xC2],
        "P2P participant message writer must be {{0x00, 0x02, 0x00, 0xC2}}"
    );

    // ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER = {0,2,0,0xC7}
    assert_eq!(
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER,
        [0x00, 0x02, 0x00, 0xC7],
        "P2P participant message reader must be {{0x00, 0x02, 0x00, 0xC7}}"
    );
}

/// Verify entity kind bytes are correct per RTPS Table 9.1.
#[test]
fn test_entity_kind_bytes() {
    // Built-in writers have kind 0xC2
    assert_eq!(RTPS_ENTITYID_SPDP_WRITER[3], 0xC2);
    assert_eq!(RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER[3], 0xC2);
    assert_eq!(RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER[3], 0xC2);
    assert_eq!(
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER[3],
        0xC2
    );

    // Built-in readers have kind 0xC7
    assert_eq!(RTPS_ENTITYID_SPDP_READER[3], 0xC7);
    assert_eq!(RTPS_ENTITYID_SEDP_PUBLICATIONS_READER[3], 0xC7);
    assert_eq!(RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER[3], 0xC7);
    assert_eq!(
        RTPS_ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER[3],
        0xC7
    );

    // User-defined entity kinds
    assert_eq!(
        ENTITY_KIND_USER_WRITER, 0x03,
        "User writer kind must be 0x03"
    );
    assert_eq!(
        ENTITY_KIND_USER_READER, 0x04,
        "User reader kind must be 0x04"
    );
}

// ============================================================================
// Test 10: Vendor ID (Sec.8.3.3.1)
// ============================================================================

/// Verify HDDS vendor ID format and consistency.
#[test]
fn test_vendor_id() {
    // Vendor ID must be exactly 2 bytes
    assert_eq!(HDDS_VENDOR_ID.len(), 2, "Vendor ID must be exactly 2 bytes");

    // Vendor ID array and u16 constant must be consistent
    let vendor_from_array = u16::from_be_bytes(HDDS_VENDOR_ID);
    assert_eq!(
        vendor_from_array, HDDS_VENDOR_ID_U16,
        "HDDS_VENDOR_ID array and u16 must match (big-endian interpretation)"
    );

    // HDDS experimental vendor ID is 0x01AA
    assert_eq!(
        HDDS_VENDOR_ID,
        [0x01, 0xAA],
        "HDDS vendor ID must be [0x01, 0xAA]"
    );
    assert_eq!(
        HDDS_VENDOR_ID_U16, 0x01AA,
        "HDDS vendor ID u16 must be 0x01AA"
    );
}

/// Verify vendor ID appears correctly in a built RTPS packet.
#[test]
fn test_vendor_id_in_packet() {
    let packet = build_data_packet("test/vendor", 1, b"data");

    // Vendor ID is at bytes 6-7 of the RTPS header
    assert_eq!(
        &packet[6..8],
        &HDDS_VENDOR_ID,
        "Vendor ID in RTPS header must match HDDS_VENDOR_ID"
    );
}

/// Verify known vendor IDs for interoperability testing.
#[test]
fn test_known_vendor_ids() {
    // RTI Connext DDS
    assert_eq!(RTI_VENDOR_ID_U16, 0x0101, "RTI vendor ID must be 0x0101");

    // eProsima FastDDS
    assert_eq!(
        EPROSIMA_VENDOR_ID_U16, 0x010F,
        "eProsima vendor ID must be 0x010F"
    );

    // HDDS must NOT collide with known vendor IDs
    assert_ne!(
        HDDS_VENDOR_ID_U16, RTI_VENDOR_ID_U16,
        "HDDS vendor ID must differ from RTI"
    );
    assert_ne!(
        HDDS_VENDOR_ID_U16, EPROSIMA_VENDOR_ID_U16,
        "HDDS vendor ID must differ from eProsima"
    );
}

// ============================================================================
// Additional: Submessage ID Constants
// ============================================================================

/// Verify all submessage ID constants match RTPS Table 8.13.
#[test]
fn test_submessage_id_constants() {
    assert_eq!(RTPS_SUBMSG_ACKNACK, 0x06, "ACKNACK submessage ID");
    assert_eq!(RTPS_SUBMSG_HEARTBEAT, 0x07, "HEARTBEAT submessage ID");
    assert_eq!(RTPS_SUBMSG_GAP, 0x08, "GAP submessage ID");
    assert_eq!(RTPS_SUBMSG_INFO_TS, 0x09, "INFO_TS submessage ID");
    assert_eq!(RTPS_SUBMSG_INFO_DST, 0x0E, "INFO_DST submessage ID");
    assert_eq!(RTPS_SUBMSG_DATA, 0x15, "DATA submessage ID");
    assert_eq!(RTPS_SUBMSG_DATA_FRAG, 0x16, "DATA_FRAG submessage ID");
}

// ============================================================================
// Additional: Full packet integration tests
// ============================================================================

/// Verify a complete RTPS packet (header + submessage) is well-formed.
#[test]
fn test_full_data_packet_structure() {
    let payload = b"integration test payload";
    let packet = build_data_packet("conformance/full", 42, payload);

    // RTPS header (20 bytes)
    assert_eq!(&packet[0..4], b"RTPS", "Magic");
    assert_eq!(packet[4], RTPS_VERSION_MAJOR, "Version major");
    assert_eq!(packet[5], RTPS_VERSION_MINOR, "Version minor");
    assert_eq!(&packet[6..8], &HDDS_VENDOR_ID, "Vendor ID");

    // First submessage at offset 20 must be DATA (0x15)
    assert_eq!(
        packet[20], RTPS_SUBMSG_DATA,
        "First submessage after RTPS header must be DATA"
    );

    // Submessage flags must have LE bit set
    assert_ne!(
        packet[21] & 0x01,
        0,
        "DATA submessage in full packet must have LE flag"
    );
}

/// Verify a complete HEARTBEAT packet is well-formed.
#[test]
fn test_full_heartbeat_packet_structure() {
    let packet = build_heartbeat_packet(1, 100, 5);

    // RTPS header (20 bytes)
    assert_eq!(&packet[0..4], b"RTPS", "Magic");
    assert_eq!(packet[4], RTPS_VERSION_MAJOR, "Version major");
    assert_eq!(packet[5], RTPS_VERSION_MINOR, "Version minor");
    assert_eq!(&packet[6..8], &HDDS_VENDOR_ID, "Vendor ID");

    // HEARTBEAT at offset 20
    assert_eq!(
        packet[20], RTPS_SUBMSG_HEARTBEAT,
        "First submessage must be HEARTBEAT"
    );

    // Total packet = RTPS header (20) + HEARTBEAT (32) = 52
    assert_eq!(
        packet.len(),
        52,
        "HEARTBEAT packet must be exactly 52 bytes (20 header + 32 submessage)"
    );
}

/// Verify GUID prefix size constant is correct.
#[test]
fn test_guid_prefix_size() {
    assert_eq!(
        RTPS_GUID_PREFIX_SIZE, 12,
        "GUID prefix must be exactly 12 bytes per RTPS spec"
    );
}

/// Verify submessage header minimum size.
#[test]
fn test_submessage_header_min_size() {
    // Submessage header: submessageId(1) + flags(1) + octetsToNextHeader(2) = 4
    assert_eq!(
        RTPS_SUBMSG_HEADER_MIN_SIZE, 4,
        "Submessage header minimum size must be 4 bytes"
    );
}

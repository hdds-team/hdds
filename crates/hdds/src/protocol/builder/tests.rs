// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::protocol::constants::RTPS_SUBMSG_DATA;
use crate::reliability::{GapMsg, GapTx, RtpsRange};

#[test]
fn test_build_data_packet_structure() {
    let payload = vec![0x42, 0x43, 0x44, 0x45];
    let packet = build_data_packet("test/topic", 123, &payload);

    assert_eq!(&packet[0..4], b"RTPS");
    // v110: RTPS header is 20 bytes (magic 4 + version 2 + vendor 2 + guid_prefix 12)
    // DATA submessage (0x15) is at offset 20
    assert_eq!(packet[20], RTPS_SUBMSG_DATA);
    assert!(packet.len() > 20);
}

#[test]
fn test_build_heartbeat_packet() {
    let packet = build_heartbeat_packet(1, 100, 5);

    assert_eq!(&packet[0..4], b"RTPS");
    // RTPS header is 20 bytes (magic 4 + version 2 + vendor 2 + guid_prefix 12)
    // HEARTBEAT submessage ID is 0x07
    assert_eq!(packet[20], 0x07);
}

#[test]
fn test_build_acknack_packet_from_ranges() {
    let ranges = vec![10..12, 15..17];
    let packet = build_acknack_packet_from_ranges(&ranges);

    assert_eq!(&packet[0..4], b"RTPS");
    // RTPS header is 20 bytes (magic 4 + version 2 + vendor 2 + guid_prefix 12)
    // ACKNACK submessage ID is 0x06
    assert_eq!(packet[20], 0x06);
}

#[test]
fn test_build_acknack_packet_with_guids() {
    let our_prefix = [1u8; 12];
    let peer_prefix = [2u8; 12];
    let reader_id = [0x00, 0x00, 0x03, 0xC7];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];
    let missing_seqs: Vec<u64> = (1..=5).collect();

    let packet = build_acknack_packet(
        our_prefix,
        peer_prefix,
        reader_id,
        writer_id,
        1,
        &missing_seqs,
        1,
    );

    assert_eq!(&packet[0..4], b"RTPS");
    // Verify GUID prefix is included
    assert_eq!(&packet[8..20], &our_prefix);
    // After RTPS header (20 bytes) comes INFO_DST (16 bytes), then ACKNACK
    // INFO_DST: 0x0e
    assert_eq!(packet[20], 0x0e);
    // ACKNACK is at offset 36
    assert_eq!(packet[36], 0x06);
}

#[test]
fn test_build_gap_packet() {
    let mut tx = GapTx::new();
    let gap = tx
        .build_gap(RtpsRange::new(10, 13))
        .pop()
        .expect("gap message");
    let payload = gap.encode_cdr2_le();
    let packet = build_gap_packet(&payload);

    assert_eq!(&packet[0..4], b"RTPS");
    // v110: RTPS header is 20 bytes, GAP submessage (0x08) at offset 20
    assert_eq!(packet[20], 0x08);

    // v110: GAP submessage structure changed - now built via DialectEncoder
    // The decoder expects raw GAP body starting after submessage header (4 bytes)
    let decoded = GapMsg::decode_cdr2_le(&packet[24..]).expect("decode gap");
    assert_eq!(decoded.gap_start(), gap.gap_start());
    assert_eq!(decoded.lost_sequences(), gap.lost_sequences());
}

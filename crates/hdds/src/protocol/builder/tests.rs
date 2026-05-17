// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::*;
use crate::dds::CdrVersion;
use crate::protocol::builder::helpers::find_data_submsg_offset;
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

/// Invariant: every DATA-carrying builder that goes through the unicast
/// entity-id patcher (`send_packet_to_endpoints`) must produce a packet
/// whose DATA submessage sits exactly at `READER_ENTITY_ID_OFFSET - 8`.
/// Written in response to the FIS_0/1/2 regression that occurred when the
/// dispose builder didn't emit INFO_TS after DATA / DATA_FRAG did — the
/// patcher then wrote the reader entity ID into the wrong bytes.
#[test]
fn builders_honor_reader_entity_id_offset() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
    };

    // 1. build_data_packet_with_context
    let payload = vec![0xAAu8; 8];
    let pkt = build_data_packet_with_context(&ctx, "topic", 1, &payload, CdrVersion::Xcdr2);
    assert!(!pkt.is_empty(), "DATA packet must not be empty");
    let data_off =
        find_data_submsg_offset(&pkt).expect("DATA packet must have a findable DATA submessage");
    assert_eq!(
        data_off + 8,
        READER_ENTITY_ID_OFFSET,
        "DATA packet violates READER_ENTITY_ID_OFFSET contract"
    );

    // 2. build_dispose_packet_with_context
    let pkt = build_dispose_packet_with_context(
        &ctx,
        "topic",
        42,
        &[0xCC; 16],
        &[],
        StatusInfoKind::Disposed,
    );
    let data_off =
        find_data_submsg_offset(&pkt).expect("dispose packet must have a findable DATA submessage");
    assert_eq!(
        data_off + 8,
        READER_ENTITY_ID_OFFSET,
        "dispose packet violates READER_ENTITY_ID_OFFSET contract"
    );

    // 3. build_data_frag_packets (only produces output when payload forces
    //    fragmentation). find_data_submsg_offset locates DATA (0x15) only —
    //    DATA_FRAG (0x16) shares the entity-id layout so we check the offset
    //    manually: after scanning past the leading INFO_TS the submessage id
    //    at that position should be 0x16.
    let big_payload = vec![0xBBu8; DEFAULT_MAX_UNFRAGMENTED_SIZE + 512];
    let frags = build_data_frag_packets(
        &ctx,
        7,
        &big_payload,
        DEFAULT_FRAGMENT_SIZE,
        CdrVersion::Xcdr2,
    );
    assert!(
        !frags.is_empty(),
        "DATA_FRAG builder must yield at least one fragment"
    );
    for (i, frag) in frags.iter().enumerate() {
        // Expected layout: RTPS header (20) + INFO_TS (12) + DATA_FRAG.
        // DATA_FRAG submessage id 0x16 at offset 32, entity ids at offset 40.
        assert_eq!(
            frag[20], 0x09,
            "fragment {} should start with INFO_TS at offset 20",
            i
        );
        assert_eq!(
            frag[32], 0x16,
            "fragment {} should have DATA_FRAG at offset 32 (after INFO_TS)",
            i
        );
        assert!(
            frag.len() >= READER_ENTITY_ID_OFFSET + 8,
            "fragment {} too short to carry entity IDs",
            i
        );
    }
}

/// Golden-byte test: a representative DATA packet built with fixed inputs
/// must produce a known byte pattern. Any accidental change to the packet
/// layout (offset drift, missing INFO_TS, reordered submessages) trips this
/// test before it has a chance to regress Connext interop at runtime.
///
/// We only freeze the bytes that are deterministic across runs. The INFO_TS
/// payload is time-dependent (SystemTime::now()) so we zero those 8 bytes
/// in the expected fixture and in the actual bytes before comparison.
#[test]
fn data_packet_matches_golden_bytes() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
    };
    let payload: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
    let mut pkt = build_data_packet_with_context(&ctx, "T", 1, payload, CdrVersion::Xcdr2);

    // Mask out the time-dependent INFO_TS timestamp (bytes 24..32, after the
    // 4-byte INFO_TS submessage header at bytes 20..24).
    for b in &mut pkt[24..32] {
        *b = 0;
    }

    // RTPS header
    assert_eq!(&pkt[0..4], b"RTPS", "RTPS magic");
    assert_eq!(pkt[4], 0x02, "RTPS version major");
    assert_eq!(&pkt[8..20], &ctx.guid_prefix, "guid prefix");

    // INFO_TS submessage at offset 20, 12 bytes total
    assert_eq!(pkt[20], 0x09, "INFO_TS submessage id");
    assert_eq!(pkt[21], 0x01, "INFO_TS LE flag");
    assert_eq!(
        u16::from_le_bytes([pkt[22], pkt[23]]),
        8,
        "INFO_TS octetsToNext"
    );
    assert_eq!(&pkt[24..32], &[0u8; 8], "INFO_TS timestamp (masked)");

    // DATA submessage at offset 32
    assert_eq!(pkt[32], 0x15, "DATA submessage id");
    assert_eq!(pkt[33], 0x07, "DATA flags: LE + InlineQoS + Data");
    // Entity IDs at the canonical offsets.
    assert_eq!(
        &pkt[READER_ENTITY_ID_OFFSET..READER_ENTITY_ID_OFFSET + 4],
        &ctx.reader_entity_id,
        "readerEntityId position"
    );
    assert_eq!(
        &pkt[READER_ENTITY_ID_OFFSET + 4..READER_ENTITY_ID_OFFSET + 8],
        &ctx.writer_entity_id,
        "writerEntityId position"
    );
}

/// Wire encap consistency: a canonical PLAIN_CDR2_LE context paired with
/// `Xcdr2` keeps the wire encap at 0x0007, while the same context paired
/// with `Xcdr1` degrades to PLAIN_CDR_LE (0x0001) per
/// `encap_kind_for_version`. Catches the prior bug where the writer
/// hard-coded 0x0001 for `@final` and contradicted the SEDP-advertised
/// `[XCDR2, XCDR1]` offered list.
#[test]
fn data_packet_wire_encap_tracks_negotiated_version() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x01; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007, // canonical @final form
    };
    let payload: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
    let pkt_v2 = build_data_packet_with_context(&ctx, "T", 1, payload, CdrVersion::Xcdr2);
    let pkt_v1 = build_data_packet_with_context(&ctx, "T", 1, payload, CdrVersion::Xcdr1);

    // The CDR encapsulation header sits immediately after the inline QoS
    // (PID_TOPIC_NAME for "T" → 12 bytes header+value+pad, plus 4-byte
    // PID_SENTINEL = 16 bytes total). Search for "DEADBEEF" instead of
    // hard-coding the offset to keep the test robust to inline-QoS
    // layout tweaks.
    let needle = [0xDE, 0xAD, 0xBE, 0xEF];
    let off_v2 = pkt_v2
        .windows(4)
        .position(|w| w == needle)
        .expect("payload must appear in v2 packet");
    let off_v1 = pkt_v1
        .windows(4)
        .position(|w| w == needle)
        .expect("payload must appear in v1 packet");
    assert!(off_v2 >= 4, "encap header must precede the payload");
    assert!(off_v1 >= 4, "encap header must precede the payload");

    // Encap is encoded big-endian per RTPS v2.5 §10.7.
    let encap_v2 = u16::from_be_bytes([pkt_v2[off_v2 - 4], pkt_v2[off_v2 - 3]]);
    let encap_v1 = u16::from_be_bytes([pkt_v1[off_v1 - 4], pkt_v1[off_v1 - 3]]);
    assert_eq!(encap_v2, 0x0007, "Xcdr2 should keep PLAIN_CDR2_LE");
    assert_eq!(encap_v1, 0x0001, "Xcdr1 should degrade to PLAIN_CDR_LE");
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

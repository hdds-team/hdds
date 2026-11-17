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
    // RTPS header is 20 bytes (magic 4 + version 2 + vendor 2 + guid_prefix 12)
    // DATA submessage (0x15) is at offset 20
    assert_eq!(packet[20], RTPS_SUBMSG_DATA);
    assert!(packet.len() > 20);
}

/// Invariant: every DATA-carrying builder that goes through the unicast
/// entity-id patcher (`send_packet_to_endpoints`) must produce a packet
/// whose DATA submessage sits exactly at `READER_ENTITY_ID_OFFSET - 8`.
/// A dispose builder that omits the INFO_TS emitted after DATA / DATA_FRAG
/// would make the patcher write the reader entity ID into the wrong bytes.
#[test]
fn builders_honor_reader_entity_id_offset() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
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
    //    fragmentation). find_data_submsg_offset locates DATA (0x15) only --
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

/// Item 8a: `build_data_frag_packets_ts` stamps EVERY fragment's INFO_TS
/// with the SAME caller-supplied `source_ts` (RTPS v2.5 SS8.3.8.11: one
/// source timestamp PER SAMPLE, not per fragment -- see that function's
/// doc). Asserts the raw INFO_TS submessage bytes (offset 20..32: id,
/// flags, length, then the 8-byte `sec`/`frac` timestamp) are
/// byte-identical across every fragment of one call, and that they
/// actually carry the caller's `source_ts` rather than some other value
/// every fragment happens to share (e.g. a stale default).
#[test]
fn build_data_frag_packets_ts_stamps_every_fragment_with_the_same_info_ts() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x22; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    // Big enough for several fragments at the default fragment size, not
    // just the minimum one over the threshold.
    let big_payload = vec![0xEEu8; DEFAULT_MAX_UNFRAGMENTED_SIZE + 3 * DEFAULT_FRAGMENT_SIZE];
    let source_ts = (0x1122_3344u32, 0x5566_7788u32);

    let frags = build_data_frag_packets_ts(
        &ctx,
        99,
        &big_payload,
        DEFAULT_FRAGMENT_SIZE,
        CdrVersion::Xcdr2,
        source_ts,
        false,
    );

    assert!(
        frags.len() >= 3,
        "test payload must force a genuinely multi-fragment burst, got {} fragment(s)",
        frags.len()
    );

    let (ts_sec, ts_frac) = source_ts;
    let mut expected_info_ts = Vec::with_capacity(12);
    expected_info_ts.push(0x09); // INFO_TS submessage id
    expected_info_ts.push(0x01); // LE flag
    expected_info_ts.extend_from_slice(&8u16.to_le_bytes()); // octetsToNext
    expected_info_ts.extend_from_slice(&ts_sec.to_le_bytes());
    expected_info_ts.extend_from_slice(&ts_frac.to_le_bytes());

    for (i, frag) in frags.iter().enumerate() {
        assert!(
            frag.len() >= 32,
            "fragment {} too short to carry a full INFO_TS submessage",
            i
        );
        assert_eq!(
            &frag[20..32],
            expected_info_ts.as_slice(),
            "fragment {} INFO_TS bytes must equal the caller-supplied \
             source_ts, byte-identical to every other fragment of this sample",
            i
        );
    }
}

/// Golden-byte test: a representative DATA packet built with fixed inputs
/// must produce a known byte pattern. Any accidental change to the packet
/// layout (offset drift, missing INFO_TS, reordered submessages) trips this
/// test before it can break cross-vendor interop at runtime.
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
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
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
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let payload: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
    let pkt_v2 = build_data_packet_with_context(&ctx, "T", 1, payload, CdrVersion::Xcdr2);
    let pkt_v1 = build_data_packet_with_context(&ctx, "T", 1, payload, CdrVersion::Xcdr1);

    // The CDR encapsulation header sits immediately after the inline QoS
    // (PID_TOPIC_NAME for "T" -> 12 bytes header+value+pad, plus 4-byte
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

    // Encap is encoded big-endian per RTPS v2.5 sec. 10.7.
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
    let packet = build_gap_packet(&payload, [1u8; 12]);

    assert_eq!(&packet[0..4], b"RTPS");
    // RTPS header is 20 bytes, GAP submessage (0x08) at offset 20
    assert_eq!(packet[20], 0x08);

    // The GAP submessage is built via DialectEncoder.
    // The decoder expects raw GAP body starting after submessage header (4 bytes)
    let decoded = GapMsg::decode_cdr2_le(&packet[24..]).expect("decode gap");
    assert_eq!(decoded.gap_start(), gap.gap_start());
    assert_eq!(decoded.lost_sequences(), gap.lost_sequences());
}

/// A transmitter that was never told its reader and writer sends
/// ENTITYID_UNKNOWN (all zero, RTPS 2.5 9.3.1.2) on both sides, not
/// `00 00 00 C7` / `00 00 00 C2`, entities no participant has.
#[test]
fn a_default_gap_names_entityid_unknown_on_the_wire() {
    let mut tx = GapTx::new();
    let gap = tx
        .build_gap(RtpsRange::new(10, 13))
        .pop()
        .expect("gap message");
    let packet = build_gap_packet(&gap.encode_cdr2_le(), [1u8; 12]);

    assert_eq!(packet[20], 0x08, "GAP submessage");
    assert_eq!(&packet[24..28], &[0u8; 4], "readerId");
    assert_eq!(&packet[28..32], &[0u8; 4], "writerId");
}

/// The deprecated side-named constants are ENTITYID_UNKNOWN: a caller still
/// using them puts the spec's value on the wire.
#[test]
#[allow(deprecated)] // the deprecated constants are what this test pins
fn the_side_named_unknown_constants_are_entityid_unknown() {
    use crate::reliability::{ENTITYID_UNKNOWN, ENTITYID_UNKNOWN_READER, ENTITYID_UNKNOWN_WRITER};
    assert_eq!(ENTITYID_UNKNOWN, [0u8; 4]);
    assert_eq!(ENTITYID_UNKNOWN_READER, [0u8; 4]);
    assert_eq!(ENTITYID_UNKNOWN_WRITER, [0u8; 4]);
}

#[test]
fn test_build_gap_packet_preserves_sequence_number_words() {
    let start = (1u64 << 32) + 10;
    let mut tx = GapTx::new();
    let gap = tx
        .build_gap(RtpsRange::new(start, start + 3))
        .pop()
        .expect("gap message");
    let payload = gap.encode_cdr2_le();

    assert_eq!(&payload[8..12], &1i32.to_le_bytes(), "gapStart.high");
    assert_eq!(&payload[12..16], &10u32.to_le_bytes(), "gapStart.low");

    let packet = build_gap_packet(&payload, [1u8; 12]);
    // The decoder underneath is `parse_gap_body`.
    let parsed =
        crate::core::discovery::multicast::control_parser::scan_all_embedded_control_submessages(
            &packet,
        )
        .0
        .into_iter()
        .next()
        .expect("valid GAP packet")
        .info;
    assert_eq!(parsed.gap_start, start);
    assert_eq!(parsed.gap_list_base, start + 1);
    let mut lost = parsed.gap_list_seqs;
    lost.sort_unstable();
    lost.dedup();
    assert_eq!(lost, vec![start, start + 1, start + 2]);
}

// =============================================================================
// downgrade_data_encap_to_plain_cdr2: D_CDR2_LE (0x0009) -> PLAIN_CDR2_LE (0x0007)
// =============================================================================

/// Find the serializedData encapsulation-kind offset in a HDDS DATA packet
/// (RTPS header 20 + INFO_TS 12 + DATA submsg). Mirrors the offset math used
/// by the function under test, computed independently for the test oracle.
fn encap_kind_offset(packet: &[u8]) -> usize {
    // RTPS header 20 + INFO_TS (id+flags+len 4 + body 8 = 12) -> DATA at 32.
    let data = 32usize;
    assert_eq!(packet[data], 0x15, "expected DATA submessage at offset 32");
    let body = data + 4; // skip DATA submsg header
    let oti = u16::from_le_bytes([packet[body + 2], packet[body + 3]]) as usize;
    let mut start = body + 4 + oti; // inline QoS start
                                    // Walk PID params to the sentinel (Q flag is set on HDDS DATA).
    loop {
        let id = u16::from_le_bytes([packet[start], packet[start + 1]]);
        let plen = u16::from_le_bytes([packet[start + 2], packet[start + 3]]) as usize;
        start += 4 + plen;
        if id == 0x0001 {
            break;
        }
    }
    start
}

/// The key-only DATA of a dispose carries the encapsulation identifier a
/// DATA of the same writer carries at the same CDR version: the canonical
/// kind of the type degraded to its XCDR1 code under XCDR1 (RTPS 2.5
/// 9.4.5.3: the payload is the serialized key; DDS-XTypes 1.3 7.2.2.4.7: the
/// KeyHolder keeps the type's extensibility). It was D_CDR2_LE for every
/// writer.
#[test]
fn a_key_only_payload_takes_the_encapsulation_of_the_writers_data() {
    for canonical in [0x0007u16, 0x0009, 0x000B] {
        for version in [CdrVersion::Xcdr2, CdrVersion::Xcdr1] {
            let ctx = RtpsEndpointContext {
                guid_prefix: [0x11; 12],
                reader_entity_id: [0x00, 0x00, 0x01, 0x02],
                writer_entity_id: [0x00, 0x00, 0x01, 0x03],
                encapsulation_kind: canonical,
                publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
            };
            let data = build_data_packet_with_context(&ctx, "topic", 1, &[1, 2, 3, 4], version);
            let dispose = build_dispose_packet_with_context_ts(
                &ctx,
                "topic",
                2,
                &[0xCC; 16],
                &[1, 2, 3, 4],
                StatusInfoKind::Disposed,
                version,
                (1, 2),
            );
            let d = encap_kind_offset(&data);
            let k = encap_kind_offset(&dispose);
            assert_eq!(
                &dispose[k..k + 2],
                &data[d..d + 2],
                "canonical {canonical:#06x} {version:?}"
            );
            assert_eq!(
                u16::from_be_bytes([dispose[k], dispose[k + 1]]),
                crate::dds::cdr_negotiation::encap_kind_for_version(canonical, version),
                "canonical {canonical:#06x} {version:?}"
            );
            assert_eq!(&dispose[k + 4..k + 8], &[1, 2, 3, 4]);
        }
    }
    // The version-less builder frames XCDR2: a @final writer's dispose is
    // PLAIN_CDR2_LE, not D_CDR2_LE.
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let dispose = build_dispose_packet_with_context(
        &ctx,
        "topic",
        2,
        &[0xCC; 16],
        &[1, 2, 3, 4],
        StatusInfoKind::Disposed,
    );
    let k = encap_kind_offset(&dispose);
    assert_eq!(&dispose[k..k + 2], &[0x00, 0x07]);
}

#[test]
fn downgrade_flips_only_the_two_encap_bytes() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        // canonical @appendable -> wire D_CDR2_LE (0x0009) under Xcdr2
        encapsulation_kind: 0x0009,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    // Body = DHEADER(4) + payload(8) so we exercise a real DHEADER+payload.
    let payload = vec![
        0x10, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
    ];
    let mut packet = build_data_packet_with_context(&ctx, "Square", 7, &payload, CdrVersion::Xcdr2);
    assert!(!packet.is_empty());

    let off = encap_kind_offset(&packet);
    // Sanity: built packet is on-wire big-endian D_CDR2_LE = 00 09.
    assert_eq!(
        &packet[off..off + 2],
        &[0x00, 0x09],
        "expected 00 09 D_CDR2_LE"
    );

    let before = packet.clone();
    let changed = downgrade_data_encap_to_plain_cdr2(&mut packet);
    assert!(changed, "downgrade must report success");

    // The two encap-kind bytes flipped to 00 07 (PLAIN_CDR2_LE).
    assert_eq!(&packet[off..off + 2], &[0x00, 0x07]);

    // EVERY other byte is byte-for-byte identical.
    assert_eq!(packet.len(), before.len());
    for (i, (a, b)) in before.iter().zip(packet.iter()).enumerate() {
        if i == off + 1 {
            continue; // the single changed byte
        }
        assert_eq!(a, b, "byte {i} must be unchanged");
    }
}

#[test]
fn downgrade_noop_on_already_plain_cdr2() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007, // PLAIN_CDR2_LE already
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let payload = vec![0x10, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
    let mut packet = build_data_packet_with_context(&ctx, "Square", 1, &payload, CdrVersion::Xcdr2);
    let off = encap_kind_offset(&packet);
    assert_eq!(&packet[off..off + 2], &[0x00, 0x07], "expected 00 07");

    let before = packet.clone();
    let changed = downgrade_data_encap_to_plain_cdr2(&mut packet);
    assert!(!changed, "already-plain packet must return false");
    assert_eq!(before, packet, "packet must be unchanged");
}

#[test]
fn downgrade_noop_on_non_data_packet() {
    // A HEARTBEAT packet has no DATA submessage.
    let mut packet = build_heartbeat_packet(1, 10, 1);
    assert!(!packet.is_empty());
    let before = packet.clone();
    let changed = downgrade_data_encap_to_plain_cdr2(&mut packet);
    assert!(!changed, "HEARTBEAT must return false");
    assert_eq!(before, packet);
}

#[test]
fn downgrade_noop_on_truncated_and_garbage() {
    // Empty / too short.
    let mut empty: Vec<u8> = Vec::new();
    assert!(!downgrade_data_encap_to_plain_cdr2(&mut empty));

    let mut tiny = vec![0u8; 10];
    assert!(!downgrade_data_encap_to_plain_cdr2(&mut tiny));

    // Header-only (20 bytes) -> no submessage.
    let mut header_only = vec![0u8; 20];
    header_only[0..4].copy_from_slice(b"RTPS");
    assert!(!downgrade_data_encap_to_plain_cdr2(&mut header_only));

    // RTPS header + a DATA submessage header that lies about its length
    // (octetsToNext runs past the buffer) -> must reject, no panic.
    let mut malformed = vec![0u8; 24];
    malformed[0..4].copy_from_slice(b"RTPS");
    malformed[20] = 0x15; // DATA id
    malformed[21] = 0x01; // LE flag, no Q
    malformed[22] = 0xFF; // octetsToNext = 0x00FF (way past end)
    malformed[23] = 0x00;
    let before = malformed.clone();
    assert!(!downgrade_data_encap_to_plain_cdr2(&mut malformed));
    assert_eq!(before, malformed, "malformed packet must be untouched");

    // Pure garbage bytes -> no panic, returns false.
    let mut garbage = vec![0xAB; 64];
    let before = garbage.clone();
    let _ = downgrade_data_encap_to_plain_cdr2(&mut garbage);
    // Garbage with submsg_id 0xAB != 0x15 is walked; whatever happens it must
    // not have flipped a 00 09 we did not author, and must not panic.
    // (We only assert no panic + determinism by running twice.)
    let mut garbage2 = before.clone();
    let r1 = downgrade_data_encap_to_plain_cdr2(&mut garbage);
    let r2 = downgrade_data_encap_to_plain_cdr2(&mut garbage2);
    assert_eq!(r1, r2, "deterministic on garbage");
}

// ----------------------------------------------------------------------
// Inline QoS decoding helpers (house rule for wire fixes: decode the
// built bytes).
// ----------------------------------------------------------------------

/// Walk the inline QoS of the DATA submessage, returning (pid, value)
/// pairs up to (excluding) PID_SENTINEL.
fn inline_qos_pids(packet: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let off = find_data_submsg_offset(packet).expect("DATA submessage not found");
    let flags = packet[off + 1];
    assert_ne!(flags & 0x02, 0, "Q flag must be set: inline QoS expected");
    let otiq = u16::from_le_bytes([packet[off + 6], packet[off + 7]]) as usize;
    let mut p = off + 8 + otiq;
    let mut pids = Vec::new();
    while p + 4 <= packet.len() {
        let pid = u16::from_le_bytes([packet[p], packet[p + 1]]);
        let len = u16::from_le_bytes([packet[p + 2], packet[p + 3]]) as usize;
        if pid == 0x0001 {
            return pids; // PID_SENTINEL
        }
        pids.push((pid, packet[p + 4..p + 4 + len].to_vec()));
        p += 4 + len;
    }
    panic!("PID_SENTINEL not found in inline QoS");
}

/// SequenceNumber_t PID value layout: high i32 LE + low u32 LE
/// (RTPS v2.5 9.4.5.4.2, see `encode_sequence_number_pid`).
fn sn_pid_value(sn: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&((sn >> 32) as i32).to_le_bytes());
    v.extend_from_slice(
        &u32::try_from(sn & 0xFFFF_FFFF)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    v
}

// ----------------------------------------------------------------------
// ECS close-marker builders: byte-level shape tests. Both forms are
// rebuilt with these same builders by the NACK repair path
// (dds::writer::nack::build_ecs_repair_packet), so their wire shape is
// frozen here: any drift would make a repaired close slot differ from
// the live emission, and a classic-model collator would then deliver
// one phantom extra sample per repaired coherent set under loss.
// ----------------------------------------------------------------------

fn ecs_ctx() -> RtpsEndpointContext {
    RtpsEndpointContext {
        guid_prefix: [0x33; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x04],
        writer_entity_id: [0x00, 0x00, 0x01, 0x02],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    }
}

/// `build_ecs_close_marker` must emit EXACTLY the classic close form:
/// RTPS header (20) + INFO_TS (12) + one bare DATA submessage
/// (`D=0 K=0 Q=0`, 4-byte header + 20-byte body) = 56 bytes total, no
/// inline QoS, no payload -- and it must honor the CALLER's reader entity
/// id (per-reader form) rather than the context's.
#[test]
fn ecs_close_marker_shape_is_bare_data() {
    let ctx = ecs_ctx();
    let reader_id = [0x00, 0x00, 0x02, 0x04];
    // high=1 / low=0x25 exercises the SequenceNumber_t high+low split.
    let seq: u64 = (1u64 << 32) | 0x25;
    let pkt = build_ecs_close_marker(&ctx, &reader_id, seq);

    assert_eq!(pkt.len(), 56, "bare close marker is exactly 56 bytes");

    // RTPS header.
    assert_eq!(&pkt[0..4], b"RTPS");
    assert_eq!(&pkt[8..20], &ctx.guid_prefix, "guid prefix");

    // INFO_TS at offset 20 (READER_ENTITY_ID_OFFSET contract prerequisite).
    assert_eq!(pkt[20], 0x09, "INFO_TS submessage id");
    assert_eq!(pkt[21], 0x01, "INFO_TS LE flag");
    assert_eq!(
        u16::from_le_bytes([pkt[22], pkt[23]]),
        8,
        "INFO_TS octetsToNext"
    );

    // DATA submessage header at 32: flags = LE only -> D=0 K=0 Q=0.
    assert_eq!(pkt[32], 0x15, "DATA submessage id");
    assert_eq!(
        pkt[33], 0x01,
        "flags LE only: no payload, no key, no inline QoS"
    );
    assert_eq!(
        u16::from_le_bytes([pkt[34], pkt[35]]),
        20,
        "octetsToNextHeader covers the bare 20-byte body"
    );

    // Body: extraFlags + octetsToInlineQos + entity ids + SN, nothing else.
    assert_eq!(u16::from_le_bytes([pkt[36], pkt[37]]), 0, "extraFlags");
    assert_eq!(
        u16::from_le_bytes([pkt[38], pkt[39]]),
        16,
        "octetsToInlineQos"
    );
    assert_eq!(
        &pkt[READER_ENTITY_ID_OFFSET..READER_ENTITY_ID_OFFSET + 4],
        &reader_id,
        "close marker carries the caller's reader entity id"
    );
    assert_eq!(&pkt[44..48], &ctx.writer_entity_id, "writerEntityId");
    assert_eq!(
        i32::from_le_bytes(pkt[48..52].try_into().unwrap()),
        1,
        "SN high"
    );
    assert_eq!(
        u32::from_le_bytes(pkt[52..56].try_into().unwrap()),
        0x25,
        "SN low"
    );
    // pkt.len() == 56 already proves no inline QoS (thus no
    // PID_COHERENT_SET a classic collator could misread as a phantom
    // singleton set) and no serialized payload follow the SN.
}

/// `build_ecs_data_submessage` (HDDS-native ECS, GROUP scope) must emit a
/// DATA with `D=0 K=0 Q=1` whose inline QoS is exactly PID_TOPIC_NAME +
/// PID_COHERENT_SET + PID_GROUP_COHERENT_SET_HDDS + PID_GROUP_ENTITY_ID +
/// PID_SENTINEL, with no serialized payload after the sentinel.
#[test]
fn ecs_data_submessage_group_scope_shape() {
    let ctx = ecs_ctx();
    let pkt = build_ecs_data_submessage(
        &ctx,
        "CoherentGroup",
        41,      // writer SN consumed by the marker
        36,      // last sample SN of the closed set
        Some(3), // closed GSN
        Some([0x00, 0x00, 0x01, 0x08]),
    );
    assert!(!pkt.is_empty(), "native ECS marker must build");

    // Framing identical to every DATA builder: header + INFO_TS + DATA.
    assert_eq!(&pkt[0..4], b"RTPS");
    assert_eq!(&pkt[8..20], &ctx.guid_prefix, "guid prefix");
    assert_eq!(pkt[20], 0x09, "INFO_TS submessage id");
    assert_eq!(pkt[32], 0x15, "DATA submessage id");
    assert_eq!(pkt[33], 0x03, "flags LE + InlineQoS: D=0 K=0 Q=1");
    assert_eq!(
        u16::from_le_bytes([pkt[34], pkt[35]]) as usize,
        pkt.len() - 36,
        "octetsToNextHeader runs to the end of the packet"
    );
    assert_eq!(u16::from_le_bytes([pkt[36], pkt[37]]), 0, "extraFlags");
    assert_eq!(
        u16::from_le_bytes([pkt[38], pkt[39]]),
        16,
        "octetsToInlineQos"
    );
    assert_eq!(
        &pkt[READER_ENTITY_ID_OFFSET..READER_ENTITY_ID_OFFSET + 4],
        &ctx.reader_entity_id,
        "readerEntityId position"
    );
    assert_eq!(&pkt[44..48], &ctx.writer_entity_id, "writerEntityId");
    assert_eq!(
        i32::from_le_bytes(pkt[48..52].try_into().unwrap()),
        0,
        "SN high"
    );
    assert_eq!(
        u32::from_le_bytes(pkt[52..56].try_into().unwrap()),
        41,
        "SN low = marker's own writer SN"
    );

    // Inline QoS: exact PID set, exact values, emission order.
    let pids = inline_qos_pids(&pkt);
    let observed: Vec<u16> = pids.iter().map(|(pid, _)| *pid).collect();
    assert_eq!(
        observed,
        vec![0x0005, 0x0056, 0x8030, 0x0053],
        "GROUP-scope ECS inline QoS PID set and order"
    );
    assert!(
        pids[0]
            .1
            .windows("CoherentGroup".len())
            .any(|w| w == b"CoherentGroup"),
        "PID_TOPIC_NAME carries the topic string"
    );
    assert_eq!(
        pids[1].1,
        sn_pid_value(36),
        "PID_COHERENT_SET = last sample SN of the set"
    );
    assert_eq!(
        pids[2].1,
        sn_pid_value(3),
        "PID_GROUP_COHERENT_SET_HDDS = closed GSN"
    );
    assert_eq!(
        pids[3].1,
        [0x00, 0x00, 0x01, 0x08],
        "PID_GROUP_ENTITY_ID = publisher group entity"
    );

    // No serialized payload after the sentinel: walk the QoS from its
    // fixed start (32 DATA + 4 header + 4 flags/otiq + 16 ids/SN = 56)
    // and require the sentinel to terminate the packet.
    let mut p = 56usize;
    loop {
        let pid = u16::from_le_bytes([pkt[p], pkt[p + 1]]);
        let plen = u16::from_le_bytes([pkt[p + 2], pkt[p + 3]]) as usize;
        p += 4 + plen;
        if pid == 0x0001 {
            break;
        }
    }
    assert_eq!(p, pkt.len(), "ECS marker carries no serialized payload");
}

/// TOPIC/INSTANCE-scope ECS (no GSN, no publisher entity) must not leak
/// the GROUP-scope PIDs: only PID_TOPIC_NAME + PID_COHERENT_SET remain.
#[test]
fn ecs_data_submessage_topic_scope_omits_group_pids() {
    let ctx = ecs_ctx();
    let pkt = build_ecs_data_submessage(&ctx, "CoherentTopic", 12, 11, None, None);
    assert!(!pkt.is_empty(), "topic-scope ECS marker must build");
    assert_eq!(pkt[33], 0x03, "flags LE + InlineQoS: D=0 K=0 Q=1");

    let pids = inline_qos_pids(&pkt);
    let observed: Vec<u16> = pids.iter().map(|(pid, _)| *pid).collect();
    assert_eq!(
        observed,
        vec![0x0005, 0x0056],
        "TOPIC-scope ECS inline QoS is topic name + coherent set only"
    );
    assert_eq!(
        pids[1].1,
        sn_pid_value(11),
        "PID_COHERENT_SET = last sample SN of the set"
    );
}

/// The complete serialized key is encrypted; no clear encapsulation precedes it.
#[cfg(feature = "security")]
#[test]
fn sealed_dispose_packet_classifies_and_leaks_no_key_bytes() {
    use crate::security::crypto::data_keys::WriterKey;
    use crate::security::crypto::peer_keys::SecretKey;
    use crate::security::crypto::user_data::{
        decode_serialized_payload, encode_serialized_payload,
    };

    let ctx = RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };

    // encode_key-style plaintext: str_len(4, LE, incl NUL) + "BLU\0".
    let mut plain_key = Vec::new();
    plain_key.extend_from_slice(&4u32.to_le_bytes());
    plain_key.extend_from_slice(b"BLU\0");

    let key = WriterKey::for_tests(SecretKey::from_bytes([0x42; 32]));
    let serialized = super::packet::encapsulate_serialized_payload(0x0007, &plain_key, false);
    let sealed = encode_serialized_payload(7, &key, &serialized).expect("seal");

    let key_hash = [0xCC; 16];
    let pkt = build_dispose_packet_with_context_coherent_ts(
        &ctx,
        "topic",
        42,
        &key_hash,
        &sealed,
        StatusInfoKind::Disposed,
        CdrVersion::Xcdr2,
        now_rtps_timestamp(),
        None,
        None,
        None,
        true,
    );
    assert!(!pkt.is_empty(), "sealed dispose packet must build");

    // Still a dispose to every classifier that routes lifecycle DATA.
    assert!(
        is_key_only_data(&pkt),
        "a sealed dispose must still classify as key-only DATA"
    );
    let (iq, is_le) = extract_inline_qos(&pkt).expect("inline QoS must be present");
    let status = extract_status_info(iq, is_le).expect("PID_STATUS_INFO must be present");
    assert_eq!(status & 0x03, 0x01, "StatusInfo must say Disposed");
    assert_eq!(
        extract_key_hash(iq, is_le).expect("PID_KEY_HASH must be present"),
        key_hash,
        "the key-hash metadata stays cleartext, exactly like the sealed write path"
    );

    // The payload region: encapsulation header in cleartext, then the blob.
    let data_off = find_data_submsg_offset(&pkt).expect("DATA submessage");
    let octets_to_inline_qos = u16::from_le_bytes([pkt[data_off + 6], pkt[data_off + 7]]) as usize;
    let payload_start = data_off + 8 + octets_to_inline_qos + iq.len();
    let payload = &pkt[payload_start..];
    assert_eq!(payload, sealed);
    assert_eq!(&payload[..8], &[0, 0, 0, 4, 0, 0, 0, 7]);

    // The instance key fields must not survive anywhere in the packet.
    assert!(
        pkt.windows(plain_key.len()).all(|w| w != &plain_key[..]),
        "the plaintext key bytes leaked into the sealed dispose packet"
    );

    // And the seal is a real one: the blob opens back to the exact key bytes.
    let opened = decode_serialized_payload(7, &key, payload).expect("open the sealed K-payload");
    assert_eq!(opened, serialized, "the sealed K-payload must round-trip");
}

/// A fragment that cannot be framed (fragment_size 65535: the DATA_FRAG body
/// is 32 + 65535 octets, past octetsToNextHeader) empties the WHOLE list.
/// The failed fragment must not go out as an RTPS header plus INFO_TS with
/// no submessage behind it, inside a full-looking list: the writer would
/// report success and the reader would never reassemble.
#[test]
fn a_fragment_that_cannot_be_framed_empties_the_list() {
    let ctx = RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let payload = vec![0xCCu8; 70_000];

    let refused = build_data_frag_packets(&ctx, 9, &payload, 65_535, CdrVersion::Xcdr2);
    assert!(
        refused.is_empty(),
        "a sample with an unframeable fragment is not sent at all, got {} packet(s)",
        refused.len()
    );

    // Positive control: the same sample fragments fine at a sane size, and no
    // packet in the list is a bare header.
    let sent = build_data_frag_packets(&ctx, 9, &payload, DEFAULT_FRAGMENT_SIZE, CdrVersion::Xcdr2);
    assert!(!sent.is_empty());
    for (i, pkt) in sent.iter().enumerate() {
        assert!(
            pkt.len() > 32,
            "packet {} is a header with nothing behind it",
            i
        );
        assert_eq!(
            pkt[32], 0x16,
            "packet {} carries DATA_FRAG after INFO_TS",
            i
        );
    }
}

/// DDS-XTypes 1.3 7.6.3.1.2: the two low bits of the options' second byte
/// count the padding that takes the serialized payload to a multiple of 4,
/// and the padding is there. One body length of each residue, and zero.
#[test]
fn the_options_count_the_padding_that_ends_the_payload_on_four_octets() {
    for (len, padding) in [(0usize, 0u8), (1, 3), (2, 2), (3, 1), (4, 0), (13, 3)] {
        let body: Vec<u8> = (1..=len).map(|i| i as u8).collect();
        let out = super::packet::encapsulate_serialized_payload(0x0007, &body, false);
        assert_eq!(&out[..4], &[0x00, 0x07, 0x00, padding], "len {len}");
        assert_eq!(&out[4..4 + len], body.as_slice(), "len {len}");
        assert_eq!(out.len() % 4, 0, "len {len}");
        assert_eq!(out.len(), 4 + len + usize::from(padding), "len {len}");
        assert!(out[4 + len..].iter().all(|&b| b == 0), "len {len}");
    }
}

/// Record 401/362a: whether `encapsulate_serialized_payload` treats `body`
/// as an already-sealed blob (no padding, zero options) must come from the
/// caller's `sealed` flag, never from a coincidence of `body`'s own bytes.
/// Opaque application data that starts like a CryptoHeader remains ordinary
/// data when the writer does not protect its payload.

#[test]
fn an_ordinary_payload_starting_with_a_crypto_header_is_sent_byte_exact() {
    const CRYPTO_HEADER: [u8; 4] = [0, 0, 0, 4];

    for (tail_len, padding) in [(0usize, 0u8), (1, 3), (2, 2), (3, 1), (5, 3)] {
        let mut body = CRYPTO_HEADER.to_vec();
        body.extend((1..=tail_len).map(|i| i as u8));
        let len = body.len();
        let out = super::packet::encapsulate_serialized_payload(0x0007, &body, false);
        assert_eq!(
            &out[..4],
            &[0x00, 0x07, 0x00, padding],
            "tail_len {tail_len}"
        );
        assert_eq!(&out[4..4 + len], body.as_slice(), "tail_len {tail_len}");
        assert_eq!(out.len() % 4, 0, "tail_len {tail_len}");
        assert_eq!(
            out.len(),
            4 + len + usize::from(padding),
            "tail_len {tail_len}"
        );
        assert!(
            out[4 + len..].iter().all(|&b| b == 0),
            "tail_len {tail_len}"
        );
    }

    // The mirror image: a GENUINELY sealed blob of the same bytes is sent
    // unpadded, options zero, when the caller correctly says `sealed: true`.
    let mut sealed_body = CRYPTO_HEADER.to_vec();
    sealed_body.extend_from_slice(&[0xAA; 7]); // deliberately not a multiple of 4
    let out = super::packet::encapsulate_serialized_payload(0x0007, &sealed_body, true);
    assert_eq!(out, sealed_body);
}

fn padding_ctx() -> RtpsEndpointContext {
    RtpsEndpointContext {
        guid_prefix: [0x11; 12],
        reader_entity_id: [0x00, 0x00, 0x01, 0x02],
        writer_entity_id: [0x00, 0x00, 0x01, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    }
}

/// The body Cyclone DDS 0.11 serializes for `@final struct { unsigned short
/// a; double b; octet c; }` = {0x2233, 1.5, 0x44} under XCDR2, 13 octets.
/// Padded to a 4-octet boundary it travels as `0007 0003` + body + three zero
/// octets: DDS-XTypes 1.3 puts the padding count in the two low bits of the
/// encapsulation options. A DATA of HDDS carries the same serialized payload.
const CYCLONE_U16F64U8_XCDR2_BODY: [u8; 13] = [
    0x33, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x3f, 0x44,
];

#[test]
fn a_data_counts_its_padding_in_the_options_as_a_foreign_writer_does() {
    let ctx = padding_ctx();
    let pkt = build_data_packet_with_context(
        &ctx,
        "topic",
        1,
        &CYCLONE_U16F64U8_XCDR2_BODY,
        CdrVersion::Xcdr2,
    );
    let at = encap_kind_offset(&pkt);
    let mut expected = vec![0x00, 0x07, 0x00, 0x03];
    expected.extend_from_slice(&CYCLONE_U16F64U8_XCDR2_BODY);
    expected.extend_from_slice(&[0, 0, 0]);
    assert_eq!(&pkt[at..], expected.as_slice());
    // The DATA is the last submessage and ends on a 4-octet boundary.
    assert_eq!(pkt.len() % 4, 0);
}

#[test]
fn a_key_only_data_counts_the_padding_it_already_had() {
    let ctx = padding_ctx();
    let pkt = build_dispose_packet_with_context(
        &ctx,
        "topic",
        2,
        &[0xCC; 16],
        &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E],
        StatusInfoKind::Disposed,
    );
    let at = encap_kind_offset(&pkt);
    assert_eq!(
        &pkt[at..],
        &[0x00, 0x07, 0x00, 0x03, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x00, 0x00, 0x00],
        "the three padding octets were there with options 0x0000"
    );
}

/// A fragmented sample carries the count in fragment 1, where the options
/// are, and the padding at the end of the last fragment; sampleSize counts
/// the padding, which is part of the serialized payload.
#[test]
fn a_fragmented_sample_counts_its_padding_in_the_first_fragment() {
    let ctx = padding_ctx();
    let body: Vec<u8> = (0..DEFAULT_MAX_UNFRAGMENTED_SIZE + 1)
        .map(|i| (i % 251) as u8)
        .collect();
    let frags = build_data_frag_packets(&ctx, 3, &body, DEFAULT_FRAGMENT_SIZE, CdrVersion::Xcdr2);
    assert!(frags.len() > 1, "fixture must fragment");
    // DATA_FRAG at 32 (RTPS header 20 + INFO_TS 12): sampleSize at +32, the
    // fragment's octets from +36 to the end of the datagram.
    let sample_size = u32::from_le_bytes(frags[0][64..68].try_into().expect("4 octets"));
    let padding = (4 - (4 + body.len()) % 4) % 4;
    assert_eq!(padding, 3, "fixture: the sample needs padding");
    assert_eq!(sample_size as usize, 4 + body.len() + padding);
    let sample: Vec<u8> = frags.iter().flat_map(|f| f[68..].to_vec()).collect();
    assert_eq!(sample.len(), sample_size as usize);
    assert_eq!(&sample[..4], &[0x00, 0x07, 0x00, 0x03]);
    assert_eq!(&sample[4..4 + body.len()], body.as_slice());
    assert_eq!(&sample[4 + body.len()..], &[0, 0, 0]);
}

/// The HEARTBEAT of a GROUP Publisher's writer, decoded from the bytes
/// against RTPS v2.5 Sec.9.4.5.7: the G flag is the 4th least significant
/// bit, and currentGSN, firstGSN, lastGSN follow `count` as three
/// SequenceNumber_t (high then low), 24 octets, nothing else (D15).
#[test]
fn a_group_heartbeat_carries_current_first_and_last_gsn_after_count() {
    let ctx = ecs_ctx();
    let packet = build_heartbeat_packet_group(&ctx, 3, 0x1_0000_0009, 7, [0x2_0000_000C, 5, 11]);
    let sub = &packet[20..];
    assert_eq!(sub[0], 0x07, "HEARTBEAT");
    assert_eq!(sub[1], 0x01 | 0x08, "E and G, neither F nor L");
    assert_eq!(u16::from_le_bytes([sub[2], sub[3]]), 28 + 24);
    assert_eq!(sub.len(), 4 + 28 + 24, "nothing after lastGSN");
    let body = &sub[4..];
    assert_eq!(&body[4..8], &ctx.writer_entity_id);
    // firstSN = 3 at +8.
    assert_eq!(&body[8..16], &[0, 0, 0, 0, 3, 0, 0, 0]);
    let expected_tail: [u8; 36] = [
        // lastSN = 0x1_0000_0009: high 1, low 9
        1, 0, 0, 0, 9, 0, 0, 0, //
        // count 7
        7, 0, 0, 0, //
        // currentGSN = 0x2_0000_000C: high 2, low 12
        2, 0, 0, 0, 12, 0, 0, 0, //
        // firstGSN 5
        0, 0, 0, 0, 5, 0, 0, 0, //
        // lastGSN 11
        0, 0, 0, 0, 11, 0, 0, 0,
    ];
    assert_eq!(&body[16..], &expected_tail[..]);
    // Everything before the GroupInfo is the plain HEARTBEAT's.
    let plain = build_heartbeat_packet_with_context(&ctx, 3, 0x1_0000_0009, 7);
    assert_eq!(&packet[..21], &plain[..21]);
    assert_eq!(&packet[24..24 + 28], &plain[24..]);
}

/// `DataWriter::assert_liveliness()` with nothing to write (MANUAL_BY_TOPIC,
/// RTPS v2.5 Sec.8.4.13.5 last paragraph, Sec.8.3.7.5): the Liveliness flag
/// is the 3rd least significant bit, set alongside Final -- decoded from
/// the bytes, not inferred from the call. Mutant: `with_liveliness_assertion_flags`
/// ORing in only `0x04` (dropping Final) makes the first assertion fail.
#[test]
fn assert_liveliness_sets_final_and_liveliness_flags_on_the_heartbeat() {
    let ctx = ecs_ctx();
    let plain = build_heartbeat_packet_with_context(&ctx, 1, 0, 9);
    assert_eq!(plain[21], 0x01, "fixture: plain HEARTBEAT carries E alone");
    let asserted = with_liveliness_assertion_flags(plain.clone());
    assert_eq!(asserted[21], 0x01 | 0x02 | 0x04, "E, F and L all set");
    // Nothing else on the submessage moved.
    assert_eq!(asserted[..21], plain[..21]);
    assert_eq!(asserted[22..], plain[22..]);
}

/// A shape `with_liveliness_assertion_flags` does not recognize (not a
/// HEARTBEAT, or no Endianness bit) is refused, this file's convention.
#[test]
fn liveliness_assertion_flags_refuses_a_packet_that_is_not_a_heartbeat() {
    let ctx = ecs_ctx();
    let mut not_a_heartbeat = build_heartbeat_packet_with_context(&ctx, 1, 0, 9);
    not_a_heartbeat[20] = 0x15; // DATA, not HEARTBEAT (0x07)
    assert!(with_liveliness_assertion_flags(not_a_heartbeat).is_empty());
    assert!(with_liveliness_assertion_flags(Vec::new()).is_empty());
}

/// The GAP of one change of a GROUP Publisher's writer, decoded from the
/// bytes against RTPS v2.5 Sec.9.4.5.6: the G flag is the 2nd least
/// significant bit; gapStartGSN and gapEndGSN follow the gapList.
#[test]
fn a_group_gap_carries_its_start_and_end_gsn_after_the_gap_list() {
    let reader = [0, 0, 0x12, 0x07];
    let writer = [0, 0, 0x13, 0x02];
    let prefix = [0x5A; 12];
    let packet = build_gap_packet_group(&reader, &writer, 4, 17, 17, prefix);
    assert_eq!(&packet[8..20], &prefix);
    let sub = &packet[20..];
    let expected: Vec<u8> = [
        // GAP, flags E|G, octetsToNextHeader 44
        &[0x08, 0x01 | 0x02, 44, 0][..],
        &reader,
        &writer,
        // gapStart 4
        &[0, 0, 0, 0, 4, 0, 0, 0],
        // gapList.bitmapBase 5, numBits 0, no bitmap
        &[0, 0, 0, 0, 5, 0, 0, 0],
        &[0, 0, 0, 0],
        // gapStartGSN 17, gapEndGSN 17
        &[0, 0, 0, 0, 17, 0, 0, 0],
        &[0, 0, 0, 0, 17, 0, 0, 0],
    ]
    .concat();
    assert_eq!(sub, expected.as_slice());
}

/// The GAP of a change that is no change for its reader, decoded from the
/// bytes against RTPS v2.5 Sec.9.4.5.6: the F flag is the 3rd least
/// significant bit; filteredCount, a ChangeCount_t (Sec.9.3.2.11, `high`
/// then `low`), follows the gapList, and counts the one change declared.
#[test]
fn a_filtered_gap_carries_its_filtered_count_after_the_gap_list() {
    let reader = [0, 0, 0x12, 0x07];
    let writer = [0, 0, 0x13, 0x02];
    let prefix = [0x5A; 12];
    let packet = build_gap_packet_filtered(&reader, &writer, 4, prefix);
    assert_eq!(&packet[8..20], &prefix);
    let sub = &packet[20..];
    let expected: Vec<u8> = [
        // GAP, flags E|F, octetsToNextHeader 36
        &[0x08, 0x01 | 0x04, 36, 0][..],
        &reader,
        &writer,
        // gapStart 4
        &[0, 0, 0, 0, 4, 0, 0, 0],
        // gapList.bitmapBase 5, numBits 0, no bitmap
        &[0, 0, 0, 0, 5, 0, 0, 0],
        &[0, 0, 0, 0],
        // filteredCount 1
        &[0, 0, 0, 0, 1, 0, 0, 0],
    ]
    .concat();
    assert_eq!(sub, expected.as_slice());
}

/// The inline QoS of a fragmented change goes in its first DATA_FRAG,
/// decoded from the bytes (RTPS v2.5 Sec.9.4.5.4): the Q flag set,
/// octetsToNextHeader grown by the list, the list between sampleSize and
/// the fragment, the fragment's bytes untouched; the other fragments carry
/// none.
#[test]
fn a_fragmented_changes_inline_qos_rides_its_first_fragment() {
    let ctx = ecs_ctx();
    let payload = vec![0x5Au8; 20_000];
    let plain =
        build_data_frag_packets_ts(&ctx, 7, &payload, 1024, CdrVersion::Xcdr2, (1, 2), false);
    assert!(plain.len() > 1, "fragmented");
    let qos = data_frag_inline_qos(&ctx, "FragTopic", Some(5), None, None, None);
    assert!(!qos.is_empty());
    assert_eq!(
        &qos[qos.len() - 4..],
        &[1, 0, 0, 0],
        "ends with the sentinel"
    );
    let mut packets = plain.clone();
    assert!(put_inline_qos_in_first_fragment(&mut packets, &qos));
    let first = &packets[0];
    let sub = &first[32..];
    assert_eq!(sub[0], 0x16, "DATA_FRAG");
    assert_eq!(sub[1], plain[0][33] | 0x02, "Q added to the flags");
    let len = |p: &[u8]| usize::from(u16::from_le_bytes([p[34], p[35]]));
    assert_eq!(len(first), len(&plain[0]) + qos.len());
    // extraFlags, octetsToInlineQos = 28: the list follows the fixed fields.
    assert_eq!(u16::from_le_bytes([sub[6], sub[7]]), 28);
    assert_eq!(&first[68..68 + qos.len()], qos.as_slice());
    assert_eq!(
        &first[68 + qos.len()..],
        &plain[0][68..],
        "the fragment itself"
    );
    assert_eq!(&first[..32], &plain[0][..32], "header and INFO_TS");
    assert_eq!(&first[36..68], &plain[0][36..68], "the fixed fields");
    assert_eq!(&packets[1..], &plain[1..], "no other fragment carries it");
    // PID_COHERENT_SET = 5 inside the list.
    let at = qos
        .windows(4)
        .position(|w| w == [0x56, 0x00, 0x08, 0x00])
        .expect("PID_COHERENT_SET");
    assert_eq!(&qos[at + 4..at + 12], &[0, 0, 0, 0, 5, 0, 0, 0]);
    // A change of no set: no list.
    assert!(data_frag_inline_qos(&ctx, "FragTopic", None, None, None, None).is_empty());
}

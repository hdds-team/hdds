// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::core::discovery::multicast::classifier::walk;
use crate::protocol::constants::*;
use std::convert::TryFrom;

/// Validate RTPS DATA packet header (eliminates duplication across helpers).
///
/// Accepts both RTPS (0x52545053) and the vendor variant RTPX (0x52545058) magic.
/// Accepts a DATA submessage either at the very first submessage (offset 20)
/// or preceded by INFO_TS / INFO_DST / INFO_SRC context submessages.
pub(super) fn validate_rtps_data_packet(rtps_packet: &[u8], min_len: usize) -> bool {
    if rtps_packet.len() < min_len {
        return false;
    }

    let magic_valid = &rtps_packet[0..4] == RTPS_MAGIC || &rtps_packet[0..4] == b"RTPX";
    if !magic_valid {
        return false;
    }

    find_data_submsg_offset(rtps_packet).is_some()
}

/// Locate the DATA submessage within an RTPS packet, skipping any leading
/// non-DATA submessage -- HEADER_EXTENSION, PAD, any INFO_* context
/// submessage, GAP, HEARTBEAT, ACKNACK, or any vendor-specific id -- that
/// precedes it. Returns the offset of the DATA submessage header, or None
/// when the packet contains no DATA submessage.
///
/// This mirrors `extract_writer_guid`'s scanner: both walk the same
/// submessage stream looking for 0x15, and both skip whatever id is
/// not DATA rather than only recognising a fixed whitelist of context ids.
/// The two scanners must agree: a
/// HEADER_EXTENSION (RTPS v2.5 Sec.9.4.5.15) at the head of the message, or
/// a [GAP, INFO_TS, DATA] message (a writer may send the GAP that skips
/// purged history in the same message as the first live DATA), would hit
/// a whitelist bail here while `extract_writer_guid` walked past them.
/// Every seq/inline-QoS/payload extractor that funnels through this
/// function would then return None for those packets, so the sample would be
/// delivered under the seq=0 fallback, which poisons the reliable
/// reorder-gate seed and silently stalls the writer's whole stream. RTPS lets any
/// submessage precede a DATA in a message (Sec.8.3.3), so whitelisting one
/// more context id does not close this failure class; skipping any
/// non-DATA submessage does, and keeps this scanner permanently in sync
/// with `extract_writer_guid`.
///
/// Per RTPS v2.5 Sec.8.3.3.3.3, octetsToNextHeader == 0 means the submessage
/// extends to the end of the message (only valid for the last submessage
/// in the packet). Encountering it on a non-DATA submessage therefore ends
/// the scan with no DATA found -- there is no way to locate a following
/// submessage -- exactly like running off the end of the buffer.
///
/// The chain is walked by `classifier::walk`, the one traversal, rather than
/// by a fourth hand-written copy. That is not tidiness: this copy neither
/// realigned nor recovered, so on a datagram whose first submessage declares
/// a length that does not fit - the shape `walk::recover` exists for - it
/// returned None where the walk finds the DATA, and the sample was then
/// delivered under the seq=0 fallback this very doc describes.
pub(crate) fn find_data_submsg_offset(rtps_packet: &[u8]) -> Option<usize> {
    if rtps_packet.len() < 24 {
        return None;
    }
    let mut found = None;
    walk::for_each_submessage(rtps_packet, |submsg| {
        if submsg.id == RTPS_SUBMSG_DATA {
            found = Some(submsg.offset);
            walk::Step::Stop
        } else {
            walk::Step::Continue
        }
    });
    found
}

#[cfg(test)]
mod find_data_submsg_offset_tests {
    use super::*;
    use crate::protocol::constants::{
        HDDS_VENDOR_ID, RTPS_MAGIC, RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
    };

    fn rtps_header() -> Vec<u8> {
        let mut v = Vec::with_capacity(20);
        v.extend_from_slice(RTPS_MAGIC);
        v.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
        v.extend_from_slice(&HDDS_VENDOR_ID);
        v.extend_from_slice(&[0u8; 12]);
        v
    }

    fn info_ts_le() -> [u8; 12] {
        [
            0x09, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn info_dst_le() -> [u8; 16] {
        [0x0e, 0x01, 0x0c, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    fn pad_le() -> [u8; 4] {
        // PAD: id 0x01, flags 0x01 (LE), octetsToNext = 0 not allowed here
        // so use a no-op PAD with 4 bytes of octets (just zeros).
        [0x01, 0x01, 0x04, 0x00]
    }

    fn minimal_data_submsg() -> [u8; 24] {
        // DATA submessage with 0x05 flags (LE + Data), octetsToNext = 20
        // so that next-submsg scan stops cleanly. Body: extraFlags(2) +
        // octetsToInlineQos(2) + readerId(4) + writerId(4) + writerSN(8) = 20.
        let mut b = [0u8; 24];
        b[0] = RTPS_SUBMSG_DATA;
        b[1] = 0x05;
        b[2..4].copy_from_slice(&20u16.to_le_bytes());
        // octetsToInlineQos = 16 (after seqNum, inline QoS would start)
        b[6..8].copy_from_slice(&16u16.to_le_bytes());
        b
    }

    #[test]
    fn bare_data_at_offset_20() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(find_data_submsg_offset(&pkt), Some(20));
    }

    #[test]
    fn info_ts_then_data_at_offset_32() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_le());
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(find_data_submsg_offset(&pkt), Some(32));
    }

    #[test]
    fn info_dst_then_info_ts_then_data() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_dst_le());
        pkt.extend_from_slice(&info_ts_le());
        pkt.extend_from_slice(&minimal_data_submsg());
        // offset = 20 (header) + 16 (info_dst) + 12 (info_ts) = 48
        assert_eq!(find_data_submsg_offset(&pkt), Some(48));
    }

    #[test]
    fn info_ts_pad_data() {
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_le());
        pkt.extend_from_slice(&pad_le());
        // PAD body (4 bytes) -- keep consistent with otn=4 in pad_le()
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(&minimal_data_submsg());
        // 20 + 12 + (4+4) = 40
        assert_eq!(find_data_submsg_offset(&pkt), Some(40));
    }

    #[test]
    fn two_info_ts_back_to_back_takes_last() {
        // Two consecutive INFO_TS is spec-ambiguous; the function should
        // keep scanning and return the DATA after the second INFO_TS.
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&info_ts_le());
        pkt.extend_from_slice(&info_ts_le());
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(find_data_submsg_offset(&pkt), Some(44));
    }

    #[test]
    fn rejects_truncated_packet() {
        let mut pkt = rtps_header();
        pkt.push(0x09); // start of an INFO_TS but no length
        pkt.push(0x01);
        // Missing the rest.
        assert_eq!(find_data_submsg_offset(&pkt), None);
    }

    #[test]
    fn rejects_too_short_to_hold_rtps_header() {
        let short = vec![0u8; 8];
        assert_eq!(find_data_submsg_offset(&short), None);
    }

    #[test]
    fn heartbeat_then_info_ts_then_data_is_skipped() {
        // HEARTBEAT (0x07) is not a context/pad submessage; the scanner must
        // still skip it like extract_writer_guid does, not bail.
        let mut pkt = rtps_header();
        // HEARTBEAT: id 0x07, flags 0x01 (LE), octetsToNext = 28
        // (readerId 4 + writerId 4 + firstSN 8 + lastSN 8 + count 4).
        pkt.extend_from_slice(&[0x07, 0x01, 0x1c, 0x00]);
        pkt.extend_from_slice(&[0u8; 28]);
        pkt.extend_from_slice(&info_ts_le());
        pkt.extend_from_slice(&minimal_data_submsg());
        // 20 (header) + (4+28) (HEARTBEAT) + 12 (INFO_TS) = 64
        assert_eq!(find_data_submsg_offset(&pkt), Some(64));
    }

    #[test]
    fn acknack_then_data_is_skipped() {
        // ACKNACK (0x06) is not a context/pad submessage either.
        let mut pkt = rtps_header();
        // ACKNACK: id 0x06, flags 0x01 (LE), octetsToNext = 24 (arbitrary
        // body length; contents are irrelevant to the scan).
        pkt.extend_from_slice(&[0x06, 0x01, 0x18, 0x00]);
        pkt.extend_from_slice(&[0u8; 24]);
        pkt.extend_from_slice(&minimal_data_submsg());
        // 20 (header) + (4+24) (ACKNACK) = 48
        assert_eq!(find_data_submsg_offset(&pkt), Some(48));
    }

    #[test]
    fn heartbeat_then_info_ts_with_no_data_returns_none() {
        // Same leading submessages as heartbeat_then_info_ts_then_data_is_skipped
        // but with no DATA following: the scan must run off the end of the
        // buffer and report None, not synthesize a DATA offset.
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&[0x07, 0x01, 0x1c, 0x00]);
        pkt.extend_from_slice(&[0u8; 28]);
        pkt.extend_from_slice(&info_ts_le());
        assert_eq!(find_data_submsg_offset(&pkt), None);
    }

    #[test]
    fn unknown_vendor_submsg_before_data_is_skipped() {
        // 0x80 is not assigned by the RTPS spec; a vendor-specific id must be
        // skipped just like any other non-DATA submessage.
        let mut pkt = rtps_header();
        // id 0x80, flags 0x01 (LE), octetsToNext = 4, 4 bytes of body.
        pkt.extend_from_slice(&[0x80, 0x01, 0x04, 0x00]);
        pkt.extend_from_slice(&[0u8; 4]);
        pkt.extend_from_slice(&minimal_data_submsg());
        // 20 (header) + (4+4) (vendor submsg) = 28
        assert_eq!(find_data_submsg_offset(&pkt), Some(28));
    }

    #[test]
    fn big_endian_submsg_header_supported() {
        // Build INFO_TS with E=0 (big-endian) + octetsToNext=8 encoded BE.
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&[0x09, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(find_data_submsg_offset(&pkt), Some(32));
    }

    #[test]
    fn gap_then_info_ts_then_data() {
        // A writer may send the GAP covering purged history in the same
        // message as the first live DATA: [GAP, INFO_TS, DATA]. The GAP
        // must be skipped like a context submessage or the DATA's sequence
        // number degrades to the seq=0 fallback.
        let mut pkt = rtps_header();
        // GAP submessage: id 0x08, flags 0x01 (LE), octetsToNext = 28
        // (readerId 4 + writerId 4 + gapStart 8 + gapList base 8 + numBits 4).
        pkt.extend_from_slice(&[0x08, 0x01, 0x1c, 0x00]);
        pkt.extend_from_slice(&[0u8; 28]);
        pkt.extend_from_slice(&info_ts_le());
        pkt.extend_from_slice(&minimal_data_submsg());
        // 20 + (4+28) + 12 = 64
        assert_eq!(find_data_submsg_offset(&pkt), Some(64));
    }
}

/// Build standard RTPS header (16 bytes).
#[allow(dead_code)] // Part of builder API, may be used when RTPS builders are expanded
pub(super) fn build_rtps_header() -> [u8; 16] {
    [
        RTPS_MAGIC[0],
        RTPS_MAGIC[1],
        RTPS_MAGIC[2],
        RTPS_MAGIC[3],
        RTPS_VERSION_MAJOR,
        RTPS_VERSION_MINOR,
        HDDS_VENDOR_ID[0],
        HDDS_VENDOR_ID[1],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    ]
}

pub(super) fn try_u16_from_usize(value: usize, context: &str) -> Option<u16> {
    match u16::try_from(value) {
        Ok(v) => Some(v),
        Err(_) => {
            log::debug!(
                "[rtps_builder] {} (value: {}) exceeds u16::MAX ({}).",
                context,
                value,
                u16::MAX
            );
            None
        }
    }
}

pub(super) fn try_u32_from_usize(value: usize, context: &str) -> Option<u32> {
    match u32::try_from(value) {
        Ok(v) => Some(v),
        Err(_) => {
            log::debug!(
                "[rtps_builder] {} (value: {}) exceeds u32::MAX ({}).",
                context,
                value,
                u32::MAX
            );
            None
        }
    }
}

/// Encode a single SequenceNumber_t PID payload (RTPS v2.5 sec. 9.4.5.4.2).
///
/// Wire format: high i32 LE followed by low u32 LE, matching the way
/// writerSN is laid out inside a DATA submessage. Used for
/// PID_COHERENT_SET (0x0056) and PID_GROUP_COHERENT_SET_HDDS (0x8030,
/// HDDS vendor-specific -- see `append_pid_group_coherent_set`); both
/// PIDs carry a SequenceNumber_t per RTPS v2.5 sec. 8.7.5 semantics.
pub(super) fn encode_sequence_number_pid(pid: u16, value: u64) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..2].copy_from_slice(&pid.to_le_bytes());
    buf[2..4].copy_from_slice(&8u16.to_le_bytes());
    // The crate's ONE sequence-number split; this was the third private copy.
    let (sn_high, sn_low) = crate::protocol::rtps::split_sequence_number(value);
    buf[4..8].copy_from_slice(&sn_high.to_le_bytes());
    buf[8..12].copy_from_slice(&sn_low.to_le_bytes());
    buf
}

/// Append `PID_COHERENT_SET` (0x0056) carrying the writer-scoped sequence
/// number of the sample (RTPS v2.5 sec. 8.7.5). Used on regular DATA samples
/// that are part of an active TOPIC- or INSTANCE-scoped coherent set, and
/// on End-of-Coherent-Set DATA submessages (D=0 K=0 Q=1).
pub(super) fn append_pid_coherent_set(buf: &mut Vec<u8>, sn: u64) {
    use crate::protocol::discovery::constants::PID_COHERENT_SET;
    buf.extend_from_slice(&encode_sequence_number_pid(PID_COHERENT_SET, sn));
}

/// Append `PID_GROUP_COHERENT_SET_HDDS` (0x8030, HDDS vendor-specific)
/// carrying the Publisher Group Sequence Number (GSN) the sample belongs
/// to, per RTPS v2.5 sec. 8.7.5 semantics. Present on every DATA sample
/// written while the parent Publisher is inside a
/// `begin_coherent_changes()` / `end_coherent_changes()` window when the
/// access_scope is GROUP, and on the matching ECS DATA marker.
///
/// Deliberately NOT the standard OMG `PID_GROUP_COHERENT_SET` (0x0063):
/// HDDS closes a group set with a bare no-QoS DATA and never emits a
/// vendor-specific group END marker, so member DATA tagged 0x0063 can
/// leave a GROUP-scope subscriber that follows the standard group-coherent
/// model waiting for an end that never comes. An implementation skips a
/// vendor-specific PID it does not recognize (DDSI-RTPS 2.5 Sec.9.4.2.11),
/// so 0x8030 never opens a group set at a foreign reader. See
/// `protocol::discovery::constants::PID_GROUP_COHERENT_SET_HDDS` for the
/// full root-cause writeup.
/// Append the standard `PID_GROUP_COHERENT_SET` (0x0063): the GSN of the
/// first change of the group coherent set (RTPS v2.5 Sec.9.6.4.3). Only in
/// the spec GROUP form, which only readers of the spec class receive (D18):
/// a foreign GROUP reader seeing it waits for a group end it never gets
/// (see `append_pid_group_coherent_set`).
pub(super) fn append_pid_spec_group_coherent_set(buf: &mut Vec<u8>, first_gsn: u64) {
    use crate::protocol::discovery::constants::PID_GROUP_COHERENT_SET;
    buf.extend_from_slice(&encode_sequence_number_pid(
        PID_GROUP_COHERENT_SET,
        first_gsn,
    ));
}

pub(super) fn append_pid_group_coherent_set(buf: &mut Vec<u8>, gsn: u64) {
    use crate::protocol::discovery::constants::PID_GROUP_COHERENT_SET_HDDS;
    buf.extend_from_slice(&encode_sequence_number_pid(
        PID_GROUP_COHERENT_SET_HDDS,
        gsn,
    ));
}

// NOTE: HDDS does not emit PID_ORIGINAL_WRITER_INFO (0x0061) on coherent
// member DATA or on the native ECS marker. Coherent delivery does not need
// it, and a constant (writerGUID, virtualSN) pair across the members of a
// set would let a receiver apply the RTPS v2.5 Sec.8.7.9 duplicate rule
// and keep only one member per set, so a conformant receiver could drop all
// but one member of every coherent set.

/// Append `PID_GROUP_ENTITY_ID` (0x0053) -- standard OMG PID per
/// RTPS v2.5 sec. 9.3.2.1 Group entityId. 4-byte payload encoded as a
/// little-endian u32 of `[entityKey:24][entityKind:8]`. The receiver
/// reads it as the EntityId of the Publisher (writer side) or
/// Subscriber (reader side) that owns the announcing endpoint, so it
/// can group multiple writers in the same Publisher for GROUP-scope
/// coherent_access (DDS v1.4 sec. 2.2.3.6).
///
/// HDDS pins entityKey to `0x000001` (single publisher per participant
/// in the current builder topology); a future multi-publisher API
/// will need to thread the real entityKey through the call sites.
pub(super) fn append_pid_group_entity_id(buf: &mut Vec<u8>, entity_id: [u8; 4]) {
    buf.extend_from_slice(&0x0053u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&entity_id);
}

/// Append a serialised PID_TOPIC_NAME parameter (0x0005) to `qos`.
///
/// Returns false (and leaves `qos` unchanged) if the topic length cannot fit
/// in a u16 parameter-length field. The caller is responsible for appending
/// PID_SENTINEL after this and any other parameters.
pub(super) fn append_pid_topic_name(qos: &mut Vec<u8>, topic: &str) -> bool {
    let topic_bytes = topic.as_bytes();
    let string_len = topic_bytes.len() + 1;
    let param_len = 4 + string_len;
    // RTPS v2.5 Sec.9.4.2.11: parameterLength is the VALUE length rounded up
    // to a multiple of 4, so the value that goes on the wire is the ALIGNED
    // one and that is the one the u16 check has to apply to. This function
    // checked the unaligned length and then cast the aligned one: a topic of
    // 65528..65530 bytes passed the check, aligned to 65536, and truncated
    // to a parameterLength of 0 on the wire, which desynchronises every
    // peer's ParameterList walk - and the padding subtraction below then
    // underflowed. The sibling `build_inline_qos_for_dispose` applies the
    // same rule.
    let aligned_param_len = (param_len + 3) & !3;
    let aligned_param_len_u16 =
        match try_u16_from_usize(aligned_param_len, "inline QoS parameter length") {
            Some(value) => value,
            None => return false,
        };
    let string_len_u32 = match try_u32_from_usize(string_len, "inline QoS string length") {
        Some(value) => value,
        None => return false,
    };
    let padding = aligned_param_len - param_len;

    qos.extend_from_slice(&0x0005u16.to_le_bytes());
    qos.extend_from_slice(&aligned_param_len_u16.to_le_bytes());
    qos.extend_from_slice(&string_len_u32.to_le_bytes());
    qos.extend_from_slice(topic_bytes);
    qos.push(0);
    qos.extend(std::iter::repeat_n(0, padding));
    true
}

/// Build inline QoS parameter list with topic name.
pub(super) fn build_inline_qos_with_topic(topic: &str) -> Vec<u8> {
    build_inline_qos_with_topic_and_coherent(topic, None, None, None, None)
}

/// Build inline QoS parameter list with topic name plus optional coherent-set
/// metadata. Used by the regular DATA path when the writer is inside a
/// `Publisher::begin/end_coherent_changes` window (RTPS v2.5 sec. 8.7.5).
///
/// * `coherent_sn` (`PID_COHERENT_SET` 0x0056) -- the writer-scoped last
///   sample SN of the active coherent set. Present for TOPIC / INSTANCE
///   scope and for GROUP scope (RTPS v2.5 sec. 8.7.5 + DDS v1.4 sec. 2.2.3.6).
/// * `group_sn` (`PID_GROUP_COHERENT_SET_HDDS` 0x8030, HDDS
///   vendor-specific) -- the Publisher's GSN for the active set. Only
///   present for GROUP-scope coherent_access. NOT the standard OMG
///   `PID_GROUP_COHERENT_SET` (0x0063) -- see
///   `append_pid_group_coherent_set` for why.
/// * `publisher_entity_id` (`PID_GROUP_ENTITY_ID` 0x0053, standard PID per
///   RTPS v2.5 sec. 9.3.2.1) -- the EntityId of the owning Publisher. Supplied
///   ONLY under GROUP-scope coherence so receivers can cluster
///   per-Publisher GSNs without aliasing across publishers in the same
///   participant; TOPIC/INSTANCE members never carry it.
pub(super) fn build_inline_qos_with_topic_and_coherent(
    topic: &str,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    key_hash: Option<&[u8; 16]>,
) -> Vec<u8> {
    build_inline_qos_grouped(
        topic,
        coherent_sn,
        group_sn,
        publisher_entity_id,
        None,
        key_hash,
    )
}

/// `PID_GROUP_SEQ_NUM` (0x0064, a SequenceNumber_t, RTPS v2.5 Sec.9.6.4.4)
/// and `PID_WRITER_GROUP_INFO` (0x0065, a WriterGroupInfo_t: one
/// GroupDigest_t, Sec.9.6.4.5, Table 8.88).
pub(super) fn append_group_tag(qos: &mut Vec<u8>, tag: &crate::protocol::group::GroupTag) {
    qos.extend_from_slice(&0x0064u16.to_le_bytes());
    qos.extend_from_slice(&8u16.to_le_bytes());
    let high = u32::try_from(tag.gsn >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(tag.gsn & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    qos.extend_from_slice(&high.to_le_bytes());
    qos.extend_from_slice(&low.to_le_bytes());
    qos.extend_from_slice(&0x0065u16.to_le_bytes());
    qos.extend_from_slice(&4u16.to_le_bytes());
    qos.extend_from_slice(&tag.writer_set);
}

/// The inline QoS of a change, in the spec GROUP form when `group_tag` is
/// given (RTPS v2.5 Sec.8.7.5, Sec.8.7.6, the form a reader of the spec
/// class receives, D18): `PID_GROUP_COHERENT_SET` (0x0063, the set's first
/// GSN) in place of the HDDS vendor `PID_GROUP_COHERENT_SET_HDDS` (0x8030,
/// `group_sn`), then `PID_GROUP_SEQ_NUM` and `PID_WRITER_GROUP_INFO`
/// (`append_group_tag`). Without it, [`build_inline_qos_with_topic_and_coherent`].
pub(super) fn build_inline_qos_grouped(
    topic: &str,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    group_tag: Option<&crate::protocol::group::GroupTag>,
    key_hash: Option<&[u8; 16]>,
) -> Vec<u8> {
    let mut qos = Vec::with_capacity(128);

    if !append_pid_topic_name(&mut qos, topic) {
        return Vec::new();
    }

    if let Some(sn) = coherent_sn {
        append_pid_coherent_set(&mut qos, sn);
    }
    match group_tag {
        Some(tag) => {
            if let Some(first) = tag.set_first_gsn {
                append_pid_spec_group_coherent_set(&mut qos, first);
            }
        }
        None => {
            if let Some(gsn) = group_sn {
                append_pid_group_coherent_set(&mut qos, gsn);
            }
        }
    }
    // PID_GROUP_ENTITY_ID is an SEDP parameter, not an inline QoS one
    // (RTPS v2.5 Table 9.13): the spec form leaves it out, its reader takes
    // the Publisher from the writer's SEDP announcement (G11).
    if let Some(entity_id) = publisher_entity_id.filter(|_| group_tag.is_none()) {
        append_pid_group_entity_id(&mut qos, entity_id);
    }
    if let Some(tag) = group_tag {
        append_group_tag(&mut qos, tag);
    }
    if let Some(hash) = key_hash {
        // PID_KEY_HASH (0x0070) per RTPS v2.5 Sec.9.6.4.8, MD5 form (CDR-BE
        // serialized key, RFC 1321). We emit it on every user DATA so a
        // foreign reader identifies the instance without deserializing the
        // key.
        qos.extend_from_slice(&0x0070u16.to_le_bytes());
        qos.extend_from_slice(&16u16.to_le_bytes());
        qos.extend_from_slice(hash);
    }

    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());

    qos
}

/// Build inline QoS for an End-of-Coherent-Set (ECS) DATA submessage
/// (RTPS v2.5 sec. 8.7.5). Contains:
/// * `PID_TOPIC_NAME` so the receiver routes the marker to the same topic;
/// * `PID_COHERENT_SET` carrying the writer's last sample SN in the set
///   (mandatory whenever coherent_access is enabled);
/// * `PID_GROUP_COHERENT_SET_HDDS` (0x8030, HDDS vendor-specific, NOT the
///   standard 0x0063 -- see `append_pid_group_coherent_set`) carrying the
///   closed GSN (mandatory for GROUP-scope coherent_access);
/// * `PID_GROUP_ENTITY_ID` (when `publisher_entity_id` is supplied) so the
///   receiver can cluster multi-writer GROUP sets by Publisher and apply the
///   atomic delivery barrier across the right writers;
/// * `PID_SENTINEL`.
///
/// No `PID_ORIGINAL_WRITER_INFO` (0x0061): the marker is attributed to the
/// closing writer by its RTPS writerId + writerSN; a constant
/// (GUID, virtualSN) pair would trip the RTPS v2.5 8.7.6 duplicate rule on
/// a foreign receiver.
///
/// No `PID_STATUS_INFO` is emitted so the marker does NOT collide with the
/// inline-QoS-only dispose form (see `extract::is_key_only_data`).
///
/// This is the HDDS-native ECS marker (with inline QoS); classic-model
/// subscribers (vendorId != HDDS) never receive it -- they get the bare,
/// QoS-less close marker built by `build_ecs_close_marker` instead (see
/// `dds::writer::coherent::WriterCoherentBridge::dispatch_ecs`), which
/// carries no PID at all.
pub(super) fn build_inline_qos_for_ecs(
    topic: &str,
    coherent_sn: u64,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    _sample_count: u32,
) -> Vec<u8> {
    let mut qos = Vec::with_capacity(96);

    if !append_pid_topic_name(&mut qos, topic) {
        return Vec::new();
    }

    append_pid_coherent_set(&mut qos, coherent_sn);
    if let Some(gsn) = group_sn {
        append_pid_group_coherent_set(&mut qos, gsn);
    }
    if let Some(entity_id) = publisher_entity_id {
        append_pid_group_entity_id(&mut qos, entity_id);
    }

    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());

    qos
}

/// Status info values for dispose/unregister (DDS-RTPS Sec.9.6.4.9).
///
/// These are the valid bit flags for PID_STATUS_INFO (0x0071).
/// The value is a 4-byte LE field in the inline QoS parameter.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusInfoKind {
    /// Instance disposed by writer (NOT_ALIVE_DISPOSED)
    Disposed = 0x0000_0001,
    /// Writer does not claim ownership any more (NOT_ALIVE_NO_WRITERS)
    Unregistered = 0x0000_0002,
    /// Both disposed and unregistered
    DisposedUnregistered = 0x0000_0003,
}

/// The wire value of a `StatusInfoKind` is its `#[repr(u32)]` discriminant.
/// The conversion is stated ONCE, here beside the repr it depends on, so no
/// encoder carries an `as u32` of its own: an enum-to-repr cast is exact by
/// construction, and this is the one place that says so.
impl From<StatusInfoKind> for u32 {
    #[inline]
    fn from(kind: StatusInfoKind) -> u32 {
        kind as u32 // @audit-ok: #[repr(u32)] discriminant to its own repr type, exact by definition
    }
}

/// The same StatusInfo bits as a byte, for the intra-process ring's
/// lifecycle flag (`IndexEntry::mark_lifecycle`). Stated here, beside the
/// wire conversion, so the two cannot disagree.
impl From<StatusInfoKind> for u8 {
    fn from(kind: StatusInfoKind) -> u8 {
        match kind {
            StatusInfoKind::Disposed => 1,
            StatusInfoKind::Unregistered => 2,
            StatusInfoKind::DisposedUnregistered => 3,
        }
    }
}

impl StatusInfoKind {
    /// What a plain `unregister_instance()` must put on the wire under the
    /// WRITER_DATA_LIFECYCLE policy (DDS v1.4 sec. 2.2.3.21).
    ///
    /// `autodispose_unregistered_instances` defaults to TRUE in DDS, and TRUE
    /// means the writer disposes the instance each time it is unregistered -
    /// so the default carries BOTH bits and remote readers report
    /// NOT_ALIVE_DISPOSED. Only with the policy turned off does an unregister
    /// read as NOT_ALIVE_NO_WRITERS.
    ///
    /// It lives here, beside the wire values, because it is a statement about
    /// what the octet means rather than about any one writer.
    #[must_use]
    pub fn for_unregister(autodispose_unregistered_instances: bool) -> Self {
        if autodispose_unregistered_instances {
            Self::DisposedUnregistered
        } else {
            Self::Unregistered
        }
    }
}

/// [`build_inline_qos_for_dispose_coherent`] with no coherent tags is the
/// non-coherent dispose/unregister inline QoS (PID_TOPIC_NAME +
/// PID_KEY_HASH + PID_STATUS_INFO + PID_SENTINEL) used by
/// `build_dispose_packet_with_context_ts`; its bytes are unchanged from
/// before the coherent variant existed.
///
/// [`build_inline_qos_for_dispose_coherent`] plus the coherent-set tags a
/// dispose/unregister emitted while the writer's publisher has an open
/// coherent set must carry (RTPS v2.5 sec. 8.7.5/sec. 8.7.6, DDS v1.4
/// sec. 2.2.2.4.1.10/sec. 2.2.3.6): a dispose is a CacheChange of the writer like
/// any other (RTPS v2.5 sec. 8.2.3), and "a Data Submessage from this Writer
/// that does not contain a coherent set in-line QoS parameter" ends the
/// set at a spec reader -- so an untagged lifecycle change inside a set
/// would break it for every conformant peer.
///
/// `coherent_sn` is `PID_COHERENT_SET` (0x0056): the set's first writer
/// SN, exactly as a member sample carries it. `group_sn` is
/// `PID_GROUP_COHERENT_SET_HDDS` (0x8030, HDDS vendor-specific) under
/// GROUP access_scope only; when present, `PID_GROUP_ENTITY_ID` (0x0053)
/// is derived and appended exactly as
/// `build_data_packet_with_context_full_keyed_ts` derives it from
/// `group_sn.is_some()` (packet.rs), so a dispose and a sample agree on
/// when the Publisher's group entity id is carried.
///
/// PID order: PID_TOPIC_NAME, [PID_COHERENT_SET], [PID_GROUP_COHERENT_SET_HDDS],
/// [PID_GROUP_ENTITY_ID], PID_KEY_HASH, PID_STATUS_INFO, PID_SENTINEL -- the
/// same relative order the member-DATA path uses for the PIDs they share
/// (RTPS v2.5 sec. 9.4.2.11 does not mandate parameter order, but matching the
/// sample path keeps one mental model and one set of golden bytes).
pub(super) fn build_inline_qos_for_dispose_coherent(
    topic: &str,
    key_hash: &[u8; 16],
    status_info: StatusInfoKind,
    coherent_sn: Option<u64>,
    group: Option<(u64, [u8; 4])>,
    group_tag: Option<&crate::protocol::group::GroupTag>,
) -> Vec<u8> {
    use crate::protocol::discovery::constants::{PID_KEY_HASH, PID_STATUS_INFO};
    let group_sn = group.map(|(gsn, _)| gsn);

    let topic_bytes = topic.as_bytes();
    let string_len = topic_bytes.len() + 1; // including NUL
    let param_len = 4 + string_len;
    // RTPS v2.5 sec. 9.4.2.11: parameterLength is the parameter VALUE length and
    // MUST be a multiple of 4. Round up so parsers locate the next parameter
    // at a 4-aligned offset; pad the value bytes with zeros to match.
    let aligned_param_len = (param_len + 3) & !3;
    let topic_padding = aligned_param_len - param_len;
    let aligned_param_len_u16 =
        match try_u16_from_usize(aligned_param_len, "inline QoS parameter length") {
            Some(value) => value,
            None => return Vec::new(),
        };
    let string_len_u32 = match try_u32_from_usize(string_len, "inline QoS string length") {
        Some(value) => value,
        None => return Vec::new(),
    };

    // PID_TOPIC_NAME total size on wire (PID + len + aligned value)
    let topic_aligned = 4 + aligned_param_len;

    // Same derivation as the member-DATA path (packet.rs,
    // `build_data_packet_with_context_full_keyed_ts`): PID_GROUP_ENTITY_ID
    // is carried only under GROUP scope, naming the writer's Publisher.
    // Not in the spec form: an SEDP parameter, not an inline QoS one (G11).
    let publisher_entity_id = group
        .map(|(_, publisher)| publisher)
        .filter(|_| group_tag.is_none());

    // Total: PID_TOPIC_NAME + [PID_COHERENT_SET(12)] + [PID_GROUP_COHERENT_SET_HDDS(12)]
    // + [PID_GROUP_ENTITY_ID(8)] + PID_KEY_HASH(20) + PID_STATUS_INFO(8) + PID_SENTINEL(4).
    // Inline QoS is a ParameterList per RTPS sec. 9.4.5.3.3 -- NO CDR
    // encapsulation header (encap headers belong to SerializedPayload).
    let total_size = topic_aligned
        + coherent_sn.map_or(0, |_| 12)
        + group_sn.map_or(0, |_| 12)
        + publisher_entity_id.map_or(0, |_| 8)
        + group_tag.map_or(0, |_| 32)
        + 20
        + 8
        + 4;
    let mut qos = Vec::with_capacity(total_size);

    // PID_TOPIC_NAME (0x0005)
    qos.extend_from_slice(&0x0005u16.to_le_bytes());
    qos.extend_from_slice(&aligned_param_len_u16.to_le_bytes());
    qos.extend_from_slice(&string_len_u32.to_le_bytes());
    qos.extend_from_slice(topic_bytes);
    qos.push(0); // NUL
    qos.extend(std::iter::repeat_n(0, topic_padding));

    // PID_COHERENT_SET (0x0056), RTPS v2.5 sec. 8.7.5
    if let Some(sn) = coherent_sn {
        append_pid_coherent_set(&mut qos, sn);
    }
    // PID_GROUP_COHERENT_SET_HDDS (0x8030, HDDS vendor-specific), or in the
    // spec GROUP form the standard PID_GROUP_COHERENT_SET (0x0063).
    match group_tag {
        Some(tag) => {
            if let Some(first) = tag.set_first_gsn {
                append_pid_spec_group_coherent_set(&mut qos, first);
            }
        }
        None => {
            if let Some(gsn) = group_sn {
                append_pid_group_coherent_set(&mut qos, gsn);
            }
        }
    }
    // PID_GROUP_ENTITY_ID (0x0053), RTPS v2.5 sec. 9.3.2.1
    if let Some(entity_id) = publisher_entity_id {
        append_pid_group_entity_id(&mut qos, entity_id);
    }
    // PID_GROUP_SEQ_NUM / PID_WRITER_GROUP_INFO: a lifecycle change of a
    // GROUP Publisher's writer is a CacheChange like a sample (Sec.8.7.5).
    if let Some(tag) = group_tag {
        append_group_tag(&mut qos, tag);
    }

    // PID_KEY_HASH (0x0070) -- 16 bytes key hash
    qos.extend_from_slice(&PID_KEY_HASH.to_le_bytes());
    qos.extend_from_slice(&16u16.to_le_bytes());
    qos.extend_from_slice(key_hash);

    // PID_STATUS_INFO (0x0071) -- 4 bytes status
    //
    // PID_STATUS_INFO is a 4-octet array per DDS-RTPS v2.5 sec. 9.6.4.9
    // (`typedef octet StatusInfo_t[4]`), NOT an integer. The
    // semantically-meaningful flags (D = Disposed, U = Unregistered,
    // F = Filtered) live in OCTET 3 (the last byte), most-significant-bit
    // ordering. Writing the enum discriminant via `to_le_bytes()` (the
    // pre-fix behavior) placed the flag bits in octet 0 instead, which
    // self-interop tolerated (HDDS reads the same wrong layout it
    // writes) but a spec-conformant reader looks at octet 3 and sees "no
    // flags set", so it never observes the dispose / unregister samples
    // HDDS sends.
    //
    // `to_be_bytes()` on a `repr(u32)` enum whose discriminants are
    // `0x01 / 0x02 / 0x03` writes `[0x00, 0x00, 0x00, 0x{01,02,03}]` --
    // the spec-correct layout with the flag bits in octet 3.
    qos.extend_from_slice(&PID_STATUS_INFO.to_le_bytes());
    qos.extend_from_slice(&4u16.to_le_bytes());
    qos.extend_from_slice(&u32::from(status_info).to_be_bytes());

    // PID_SENTINEL (0x0001)
    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());

    qos
}

/// The three readers of a datagram that are NOT the classifier
/// (`HeartbeatMsg::decode_all_from_packet`, `find_data_submsg_offset`,
/// `extract_writer_guid`) must walk the submessage chain exactly as the one
/// traversal does, realigning and recovering the same way, so that they give
/// one answer to one question on the live paths that use them: the NACK
/// retransmission path, the router's "who sent this sample" lookup, and the
/// reliable reader's HEARTBEAT path.
#[cfg(test)]
mod the_three_readers_agree_with_the_one_traversal {
    use crate::core::discovery::multicast::classifier::walk;
    use crate::protocol::builder::extract::extract_writer_guid;
    use crate::reliability::HeartbeatMsg;

    const A_USER_WRITER: [u8; 4] = [0x00, 0x00, 0x12, 0x02];

    /// The body of the real submessage, whichever kind it is.
    fn real_submessage(id: u8) -> Vec<u8> {
        let mut b = Vec::new();
        if id == 0x15 {
            b.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
            b.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
            b.extend_from_slice(&[0x00, 0x01, 0x00, 0xC7]); // readerEntityId
            b.extend_from_slice(&A_USER_WRITER);
            b.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
            b.extend_from_slice(&5u32.to_le_bytes()); // writerSN low
        } else {
            b.extend_from_slice(&[0x00, 0x01, 0x00, 0xC7]); // readerId
            b.extend_from_slice(&[0x00, 0x01, 0x00, 0xC2]); // writerId
            b.extend_from_slice(&0u32.to_le_bytes()); // firstSN high
            b.extend_from_slice(&1u32.to_le_bytes()); // firstSN low
            b.extend_from_slice(&0u32.to_le_bytes()); // lastSN high
            b.extend_from_slice(&9u32.to_le_bytes()); // lastSN low
            b.extend_from_slice(&3u32.to_le_bytes()); // count
        }
        b
    }

    fn rtps_header() -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&[0x02, 0x04, 0x01, 0x12]);
        p.extend_from_slice(&[0xAA; 12]);
        p
    }

    /// Append a submessage, asserting the declared length is the length there.
    fn push_submsg(p: &mut Vec<u8>, id: u8, declared: u16, body: &[u8]) {
        let before = p.len();
        p.push(id);
        p.push(0x01); // E flag: little-endian
        p.extend_from_slice(&declared.to_le_bytes());
        p.extend_from_slice(body);
        assert_eq!(p.len(), before + 4 + body.len(), "body written as measured");
    }

    /// A first submessage declaring a length the datagram does not carry,
    /// then a real one behind it. `walk::recover` exists for this shape; the
    /// three copies just stopped.
    fn poisoned_length_then(id: u8) -> Vec<u8> {
        let mut p = rtps_header();
        // ACKNACK declaring 55983 octets, carrying 24 of zeros. Zeros on
        // purpose: the recovery refuses id 0x00, so it cannot mistake this
        // body for the header it is looking for.
        push_submsg(&mut p, 0x06, 55983, &[0u8; 24]);
        assert_eq!(p.len(), 48, "the real submessage starts at 48");
        let body = real_submessage(id);
        push_submsg(&mut p, id, body.len() as u16, &body);
        p
    }

    /// A sender that declares its BODY and leaves the padding that realigns
    /// the next header undeclared. A conforming sender counts that padding
    /// (RTPS 2.5 9.4.5.1.3), so this is a recovery case and not the norm -
    /// which is exactly why nothing had ever read it.
    ///
    /// The carrier is a PAD, whose contents may be any length. It was an
    /// INFO_TS with a 5-octet body, which is itself invalid (8.3.8.11: too
    /// small for its Time_t) and, once the walk honoured that, ended the
    /// message before the case under test was reached.
    fn under_declared_padding_then(id: u8) -> Vec<u8> {
        let mut p = rtps_header();
        push_submsg(&mut p, 0x01, 5, &[0x11; 5]); // PAD, 5-octet body
        p.extend_from_slice(&[0x00; 3]); // the padding it did not declare
        assert_eq!(p.len(), 32, "the real submessage starts at 32");
        let body = real_submessage(id);
        push_submsg(&mut p, id, body.len() as u16, &body);
        p
    }

    /// What the one traversal sees, so the expectations below are anchored on
    /// it rather than on my arithmetic.
    fn ids_seen_by_the_walk(packet: &[u8]) -> Vec<u8> {
        let mut ids = Vec::new();
        walk::for_each_submessage(packet, |s| {
            ids.push(s.id);
            walk::Step::Continue
        });
        ids
    }

    #[test]
    fn a_declared_length_that_does_not_fit_no_longer_hides_what_is_behind_it() {
        let with_data = poisoned_length_then(0x15);
        let with_hb = poisoned_length_then(0x07);

        assert_eq!(
            ids_seen_by_the_walk(&with_data),
            vec![0x06, 0x15],
            "the one traversal recovers and reaches the DATA"
        );
        assert_eq!(ids_seen_by_the_walk(&with_hb), vec![0x06, 0x07]);

        // Before the migration these three answered None, None and 0.
        assert_eq!(
            super::find_data_submsg_offset(&with_data),
            Some(48),
            "the NACK path could not find the DATA to retransmit"
        );
        assert_eq!(
            extract_writer_guid(&with_data).map(|g| [g[12], g[13], g[14], g[15]]),
            Some(A_USER_WRITER),
            "the router had no writer to attribute the sample to"
        );
        assert_eq!(
            HeartbeatMsg::decode_all_from_packet(&with_hb).len(),
            1,
            "the reliable reader never saw the HEARTBEAT, so it never ACKNACKed"
        );
    }

    #[test]
    fn undeclared_padding_is_stepped_over_by_all_three_and_not_just_by_one() {
        let with_data = under_declared_padding_then(0x15);
        let with_hb = under_declared_padding_then(0x07);

        assert_eq!(ids_seen_by_the_walk(&with_data), vec![0x01, 0x15]);
        assert_eq!(ids_seen_by_the_walk(&with_hb), vec![0x01, 0x07]);

        assert_eq!(super::find_data_submsg_offset(&with_data), Some(32));
        assert_eq!(
            extract_writer_guid(&with_data).map(|g| [g[12], g[13], g[14], g[15]]),
            Some(A_USER_WRITER)
        );
        // This one ALREADY passed before the migration: it was the only copy
        // of the three that realigned. That asymmetry is the finding - the
        // same datagram was read two ways inside one crate.
        assert_eq!(HeartbeatMsg::decode_all_from_packet(&with_hb).len(), 1);
    }
}

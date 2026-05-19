// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::protocol::constants::*;
use std::convert::TryFrom;

/// Validate RTPS DATA packet header (eliminates duplication across helpers).
///
/// Accepts both RTPS (0x52545053) and RTPX (0x52545058) magic for RTI interop.
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
/// INFO_TS (0x09) / INFO_DST (0x0e) / INFO_SRC (0x0c) / INFO_REPLY (0x0d,0x0f)
/// / PAD (0x01) submessages. Returns the offset of the DATA submessage header.
pub(crate) fn find_data_submsg_offset(rtps_packet: &[u8]) -> Option<usize> {
    if rtps_packet.len() < 24 {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= rtps_packet.len() {
        let id = rtps_packet[offset];
        let flags = rtps_packet[offset + 1];
        let otn = if flags & 0x01 != 0 {
            u16::from_le_bytes([rtps_packet[offset + 2], rtps_packet[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([rtps_packet[offset + 2], rtps_packet[offset + 3]]) as usize
        };
        if id == RTPS_SUBMSG_DATA {
            return Some(offset);
        }
        // Only skip known context / pad submessages. Anything else means this
        // packet is not a DATA packet we can reason about.
        match id {
            0x01 | 0x09 | 0x0c | 0x0d | 0x0e | 0x0f => {}
            _ => return None,
        }
        if otn == 0 {
            return None;
        }
        offset = offset + 4 + otn;
    }
    None
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
        // PAD body (4 bytes) — keep consistent with otn=4 in pad_le()
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
    fn rejects_unknown_submsg_before_data() {
        let mut pkt = rtps_header();
        // 0x07 = HEARTBEAT — not a context submessage, should reject
        pkt.extend_from_slice(&[0x07, 0x01, 0x18, 0x00]);
        pkt.extend_from_slice(&[0u8; 24]);
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(find_data_submsg_offset(&pkt), None);
    }

    #[test]
    fn big_endian_submsg_header_supported() {
        // Build INFO_TS with E=0 (big-endian) + octetsToNext=8 encoded BE.
        let mut pkt = rtps_header();
        pkt.extend_from_slice(&[0x09, 0x00, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&minimal_data_submsg());
        assert_eq!(find_data_submsg_offset(&pkt), Some(32));
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

/// Encode a single SequenceNumber_t PID payload (RTPS v2.5 §9.4.5.4.2).
///
/// Wire format: high i32 LE followed by low u32 LE, matching the way
/// writerSN is laid out inside a DATA submessage. Used for
/// PID_COHERENT_SET (0x0056) and PID_GROUP_COHERENT_SET (0x0063); both
/// PIDs carry a SequenceNumber_t per RTPS v2.5 §8.7.5.
pub(super) fn encode_sequence_number_pid(pid: u16, value: u64) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0..2].copy_from_slice(&pid.to_le_bytes());
    buf[2..4].copy_from_slice(&8u16.to_le_bytes());
    let sn_high = (value >> 32) as i32;
    let sn_low = value as u32;
    buf[4..8].copy_from_slice(&sn_high.to_le_bytes());
    buf[8..12].copy_from_slice(&sn_low.to_le_bytes());
    buf
}

/// Append `PID_COHERENT_SET` (0x0056) carrying the writer-scoped sequence
/// number of the sample (RTPS v2.5 §8.7.5). Used on regular DATA samples
/// that are part of an active TOPIC- or INSTANCE-scoped coherent set, and
/// on End-of-Coherent-Set DATA submessages (D=0 K=0 Q=1).
pub(super) fn append_pid_coherent_set(buf: &mut Vec<u8>, sn: u64) {
    use crate::protocol::discovery::constants::PID_COHERENT_SET;
    buf.extend_from_slice(&encode_sequence_number_pid(PID_COHERENT_SET, sn));
}

/// Append `PID_GROUP_COHERENT_SET` (0x0063) carrying the Publisher Group
/// Sequence Number (GSN) the sample belongs to, per RTPS v2.5 §8.7.5.
/// Present on every DATA sample written while the parent Publisher is
/// inside a `begin_coherent_changes()` / `end_coherent_changes()` window
/// when the access_scope is GROUP, and on the matching ECS DATA marker.
pub(super) fn append_pid_group_coherent_set(buf: &mut Vec<u8>, gsn: u64) {
    use crate::protocol::discovery::constants::PID_GROUP_COHERENT_SET;
    buf.extend_from_slice(&encode_sequence_number_pid(PID_GROUP_COHERENT_SET, gsn));
}

/// Append `PID_ORIGINAL_WRITER_INFO` (0x0061) — standard OMG PID per
/// DDS-RTPS v2.5 §9.6.3 OriginalWriterInfo_t. Layout (24 bytes):
/// 12-byte writer guidPrefix, 4-byte writer entityId, 8-byte
/// SequenceNumber_t (high i32 LE + low u32 LE).
///
/// Connext drives its coherent-set delivery off this PID's
/// virtualSeqNumber, not off the OMG `PID_COHERENT_SET` (0x0056). On
/// HDDS the field carries our own writer GUID and the per-publisher
/// GSN — receivers that follow the standard interpretation see a
/// monotonic marker per writer; Connext-style receivers gate coherent
/// flush on the same value.
pub(super) fn append_pid_original_writer_info(
    buf: &mut Vec<u8>,
    writer_guid: &[u8; 16],
    virtual_sn: u64,
) {
    buf.extend_from_slice(&0x0061u16.to_le_bytes());
    buf.extend_from_slice(&24u16.to_le_bytes());
    buf.extend_from_slice(&writer_guid[..16]);
    #[allow(clippy::cast_possible_truncation)]
    let high = (virtual_sn >> 32) as i32;
    #[allow(clippy::cast_possible_truncation)]
    let low = virtual_sn as u32;
    buf.extend_from_slice(&high.to_le_bytes());
    buf.extend_from_slice(&low.to_le_bytes());
}

/// Append `PID_GROUP_ENTITY_ID` (0x0053) — standard OMG PID per
/// RTPS v2.5 §9.3.2.1 Group entityId. 4-byte payload encoded as a
/// little-endian u32 of `[entityKey:24][entityKind:8]`. The receiver
/// reads it as the EntityId of the Publisher (writer side) or
/// Subscriber (reader side) that owns the announcing endpoint, so it
/// can group multiple writers in the same Publisher for GROUP-scope
/// coherent_access (DDS v1.4 §2.2.3.6).
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
fn append_pid_topic_name(qos: &mut Vec<u8>, topic: &str) -> bool {
    let topic_bytes = topic.as_bytes();
    let string_len = topic_bytes.len() + 1;
    let param_len = 4 + string_len;
    if try_u16_from_usize(param_len, "inline QoS parameter length").is_none() {
        return false;
    }
    let string_len_u32 = match try_u32_from_usize(string_len, "inline QoS string length") {
        Some(value) => value,
        None => return false,
    };

    let aligned_param_len = ((param_len + 3) & !3) as u16;
    let padding = aligned_param_len as usize - param_len;

    qos.extend_from_slice(&0x0005u16.to_le_bytes());
    qos.extend_from_slice(&aligned_param_len.to_le_bytes());
    qos.extend_from_slice(&string_len_u32.to_le_bytes());
    qos.extend_from_slice(topic_bytes);
    qos.push(0);
    qos.extend(std::iter::repeat_n(0, padding));
    true
}

/// Build inline QoS parameter list with topic name.
pub(super) fn build_inline_qos_with_topic(topic: &str) -> Vec<u8> {
    build_inline_qos_with_topic_and_coherent(topic, None, None, None, None, None)
}

/// Build inline QoS parameter list with topic name plus optional coherent-set
/// metadata. Used by the regular DATA path when the writer is inside a
/// `Publisher::begin/end_coherent_changes` window (RTPS v2.5 §8.7.5).
///
/// * `coherent_sn` (`PID_COHERENT_SET` 0x0056) — the writer-scoped last
///   sample SN of the active coherent set. Present for TOPIC / INSTANCE
///   scope and for GROUP scope (RTPS v2.5 §8.7.5 + DDS v1.4 §2.2.3.6).
/// * `group_sn` (`PID_GROUP_COHERENT_SET` 0x0063) — the Publisher's GSN
///   for the active set. Only present for GROUP-scope coherent_access.
/// * `publisher_entity_id` (`PID_GROUP_ENTITY_ID` 0x0053, standard PID per
///   RTPS v2.5 §9.3.2.1) — the EntityId of the owning Publisher. Always
///   emitted under GROUP-scope so cross-vendor receivers can cluster
///   per-Publisher GSNs without aliasing across publishers in the same
///   participant.
/// * `original_writer` (`PID_ORIGINAL_WRITER_INFO` 0x0061, standard PID)
///   carrying the writer's own GUID + virtual SN — Connext's coherent
///   delivery gates on this; pure spec-PID receivers ignore it.
pub(super) fn build_inline_qos_with_topic_and_coherent(
    topic: &str,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    original_writer: Option<(&[u8; 16], u64)>,
    key_hash: Option<&[u8; 16]>,
) -> Vec<u8> {
    let mut qos = Vec::with_capacity(128);

    if !append_pid_topic_name(&mut qos, topic) {
        return Vec::new();
    }

    if let Some(sn) = coherent_sn {
        append_pid_coherent_set(&mut qos, sn);
    }
    if let Some(gsn) = group_sn {
        append_pid_group_coherent_set(&mut qos, gsn);
    }
    if let Some(entity_id) = publisher_entity_id {
        append_pid_group_entity_id(&mut qos, entity_id);
    }
    if let Some((guid, virtual_sn)) = original_writer {
        append_pid_original_writer_info(&mut qos, guid, virtual_sn);
    }
    if let Some(hash) = key_hash {
        // PID_KEY_HASH (0x0070) per RTPS v2.5 §9.6.4.8. MD5 form (CDR-BE
        // serialized key, RFC 1321) is what Connext expects on the cross-
        // vendor receive path. RTI emits this on every user DATA in CS_8;
        // Connext gates its instance/coherent delivery on its presence.
        qos.extend_from_slice(&0x0070u16.to_le_bytes());
        qos.extend_from_slice(&16u16.to_le_bytes());
        qos.extend_from_slice(hash);
    }

    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());

    qos
}

/// Build inline QoS for an End-of-Coherent-Set (ECS) DATA submessage
/// (RTPS v2.5 §8.7.5). Contains:
/// * `PID_TOPIC_NAME` so the receiver routes the marker to the same topic;
/// * `PID_COHERENT_SET` carrying the writer's last sample SN in the set
///   (mandatory whenever coherent_access is enabled);
/// * `PID_GROUP_COHERENT_SET` carrying the closed GSN (mandatory for
///   GROUP-scope coherent_access);
/// * `PID_GROUP_ENTITY_ID` (when `publisher_entity_id` is supplied) so the
///   receiver can cluster multi-writer GROUP sets by Publisher and apply the
///   atomic delivery barrier across the right writers;
/// * `PID_ORIGINAL_WRITER_INFO` (when `original_writer` is supplied) carrying
///   the closing writer's GUID + virtual SN so vendors that gate on the
///   standard OMG OriginalWriterInfo PID (DDS-RTPS §9.6.3) can attribute
///   the close-of-set to the right source;
/// * `PID_SENTINEL`.
///
/// No `PID_STATUS_INFO` is emitted so the marker does NOT collide with the
/// inline-QoS-only dispose form (see `extract::is_key_only_data`).
pub(super) fn build_inline_qos_for_ecs(
    topic: &str,
    coherent_sn: u64,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    original_writer: Option<(&[u8; 16], u64)>,
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
    if let Some((guid, virtual_sn)) = original_writer {
        append_pid_original_writer_info(&mut qos, guid, virtual_sn);
    }

    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());

    qos
}

/// Status info values for dispose/unregister (DDS-RTPS Sec.9.6.3.4).
///
/// These are the valid bit flags for PID_STATUS_INFO (0x0071).
/// The value is a 4-byte LE field in the inline QoS parameter.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusInfoKind {
    /// Instance disposed by writer (NOT_ALIVE_DISPOSED)
    Disposed = 0x0000_0001,
    /// Writer no longer claims ownership (NOT_ALIVE_NO_WRITERS)
    Unregistered = 0x0000_0002,
    /// Both disposed and unregistered
    DisposedUnregistered = 0x0000_0003,
}

/// Build inline QoS parameter list for dispose/unregister lifecycle changes.
///
/// Includes: PID_TOPIC_NAME + PID_KEY_HASH + PID_STATUS_INFO + PID_SENTINEL.
/// This is used by DataWriter::dispose() and DataWriter::unregister_instance().
pub(super) fn build_inline_qos_for_dispose(
    topic: &str,
    key_hash: &[u8; 16],
    status_info: StatusInfoKind,
) -> Vec<u8> {
    use crate::protocol::discovery::constants::{PID_KEY_HASH, PID_STATUS_INFO};

    let topic_bytes = topic.as_bytes();
    let string_len = topic_bytes.len() + 1; // including NUL
    let param_len = 4 + string_len;
    // RTPS v2.5 §9.4.2.11: parameterLength is the parameter VALUE length and
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

    // Total: PID_TOPIC_NAME + PID_KEY_HASH(20) + PID_STATUS_INFO(8) + PID_SENTINEL(4).
    // Inline QoS is a ParameterList per RTPS §9.4.5.3.3 — NO CDR
    // encapsulation header (encap headers belong to SerializedPayload).
    let total_size = topic_aligned + 20 + 8 + 4;
    let mut qos = Vec::with_capacity(total_size);

    // PID_TOPIC_NAME (0x0005)
    qos.extend_from_slice(&0x0005u16.to_le_bytes());
    qos.extend_from_slice(&aligned_param_len_u16.to_le_bytes());
    qos.extend_from_slice(&string_len_u32.to_le_bytes());
    qos.extend_from_slice(topic_bytes);
    qos.push(0); // NUL
    qos.extend(std::iter::repeat_n(0, topic_padding));

    // PID_KEY_HASH (0x0070) -- 16 bytes key hash
    qos.extend_from_slice(&PID_KEY_HASH.to_le_bytes());
    qos.extend_from_slice(&16u16.to_le_bytes());
    qos.extend_from_slice(key_hash);

    // PID_STATUS_INFO (0x0071) -- 4 bytes status
    //
    // PID_STATUS_INFO is a 4-octet array per DDS-RTPS v2.5 §9.6.3.4
    // (`typedef octet StatusInfo_t[4]`), NOT an integer. The
    // semantically-meaningful flags (D = Disposed, U = Unregistered,
    // F = Filtered) live in OCTET 3 (the last byte), most-significant-bit
    // ordering. Writing the enum discriminant via `to_le_bytes()` (the
    // pre-fix behavior) placed the flag bits in octet 0 instead, which
    // self-interop tolerated (HDDS reads the same wrong layout it
    // writes) but Connext / Fast DDS rejected: they look at octet 3 and
    // saw "no flags set" — so FinalInstanceState_0/1/2 cross-vendor
    // reported `DATA_NOT_CORRECT` / "Unregistered 0 elements" /
    // "Disposed 0 elements" even though HDDS *was* sending dispose /
    // unregister samples.
    //
    // `to_be_bytes()` on a `repr(u32)` enum whose discriminants are
    // `0x01 / 0x02 / 0x03` writes `[0x00, 0x00, 0x00, 0x{01,02,03}]` —
    // the spec-correct layout with the flag bits in octet 3.
    qos.extend_from_slice(&PID_STATUS_INFO.to_le_bytes());
    qos.extend_from_slice(&4u16.to_le_bytes());
    let status_value: u32 = status_info as u32; // @audit-ok: repr(u32) enum discriminant
    qos.extend_from_slice(&status_value.to_be_bytes());

    // PID_SENTINEL (0x0001)
    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());

    qos
}

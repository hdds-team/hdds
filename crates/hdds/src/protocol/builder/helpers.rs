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

/// Build inline QoS parameter list with topic name.
pub(super) fn build_inline_qos_with_topic(topic: &str) -> Vec<u8> {
    let topic_bytes = topic.as_bytes();
    let string_len = topic_bytes.len() + 1;
    let param_len = 4 + string_len;
    if try_u16_from_usize(param_len, "inline QoS parameter length").is_none() {
        return Vec::new();
    }
    let string_len_u32 = match try_u32_from_usize(string_len, "inline QoS string length") {
        Some(value) => value,
        None => return Vec::new(),
    };

    // PID header (4 bytes) + string payload, aligned to 4
    let unaligned_size = 4 + param_len;
    let aligned_size = (unaligned_size + 3) & !3;
    let padding = aligned_size - unaligned_size;

    // Total = PID_TOPIC_NAME (aligned) + PID_SENTINEL (4 bytes)
    let mut qos = Vec::with_capacity(aligned_size + 4);

    // Inline QoS is a ParameterList — NO CDR encapsulation header.
    // RTPS v2.3 Sec.9.4.2.11: inline QoS starts directly with parameters.
    qos.extend_from_slice(&0x0005u16.to_le_bytes());
    // parameterLength must include the string length field (4) + string + null + padding
    let aligned_param_len = ((param_len + 3) & !3) as u16;
    qos.extend_from_slice(&aligned_param_len.to_le_bytes());
    qos.extend_from_slice(&string_len_u32.to_le_bytes());

    qos.extend_from_slice(topic_bytes);
    qos.push(0);

    qos.extend(std::iter::repeat_n(0, padding));

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
    let param_len_u16 = match try_u16_from_usize(param_len, "inline QoS parameter length") {
        Some(value) => value,
        None => return Vec::new(),
    };
    let string_len_u32 = match try_u32_from_usize(string_len, "inline QoS string length") {
        Some(value) => value,
        None => return Vec::new(),
    };

    // PID_TOPIC_NAME aligned size
    let topic_unaligned = 2 + 2 + param_len; // PID + len + data
    let topic_aligned = (topic_unaligned + 3) & !3;
    let topic_padding = topic_aligned - topic_unaligned;

    // Total: CDR header(4) + PID_TOPIC_NAME(aligned) + PID_KEY_HASH(20) + PID_STATUS_INFO(8) + PID_SENTINEL(4)
    let total_size = 4 + topic_aligned + 20 + 8 + 4;
    let mut qos = Vec::with_capacity(total_size);

    // CDR encapsulation header (ALWAYS big-endian per CDR spec)
    qos.extend_from_slice(&CDR_LE.to_be_bytes());
    qos.extend_from_slice(&[0x00, 0x00]); // Options (reserved)

    // PID_TOPIC_NAME (0x0005)
    qos.extend_from_slice(&0x0005u16.to_le_bytes());
    qos.extend_from_slice(&param_len_u16.to_le_bytes());
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

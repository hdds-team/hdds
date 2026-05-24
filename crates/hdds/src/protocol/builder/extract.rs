// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};
use crate::protocol::constants::{RTPS_MAGIC, RTPS_SUBMSG_DATA};

/// Extract CDR payload from RTPS DATA submessage.
///
/// Returns the serialized data starting after the DATA submessage header
/// (and inline QoS if present). Returns `None` on malformed packets.
///
/// # Layout
///
/// DATA submessage header (24 bytes total):
/// - \[0-3\]: submessage header (id, flags, octetsToNext)
/// - \[4-5\]: extraFlags
/// - \[6-7\]: octetsToInlineQos
/// - \[8-11\]: readerEntityId
/// - \[12-15\]: writerEntityId
/// - \[16-23\]: writerSN
///
/// When the inline QoS flag (Q=bit 1) is set AND `octetsToInlineQos > 0`,
/// an inline QoS parameter list follows the 24-byte header. The payload
/// starts after the PID_SENTINEL (0x0001) that terminates the QoS list.
///
/// When Q=0, the payload starts immediately at offset 24.
///
/// # Important
///
/// Per RTPS v2.5 §8.3.7.2, `octetsToInlineQos` is "undefined" when Q=0.
/// Some vendors (CoreDDS) write a non-zero value (e.g. 16) despite Q=0.
/// Using `octetsToInlineQos` as an offset when Q=0 would misread the
/// serialized CDR payload as PID parameters. Always gate on the Q flag.
pub fn extract_data_payload(rtps_packet: &[u8]) -> Option<&[u8]> {
    if !validate_rtps_data_packet(rtps_packet, 24) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;

    let flags = rtps_packet[data_off + 1];
    let has_inline_qos = flags & 0x02 != 0;
    let is_le = flags & 0x01 != 0;

    let octets_to_qos = if is_le {
        u16::from_le_bytes([rtps_packet[data_off + 6], rtps_packet[data_off + 7]]) as usize
    } else {
        u16::from_be_bytes([rtps_packet[data_off + 6], rtps_packet[data_off + 7]]) as usize
    };

    if has_inline_qos && octets_to_qos > 0 {
        // Inline QoS parameter list present: scan for PID_SENTINEL
        let qos_offset = data_off + 8 + octets_to_qos;

        if rtps_packet.len() < qos_offset + 4 {
            return None;
        }

        let mut offset = qos_offset + 4;

        loop {
            if offset + 4 > rtps_packet.len() {
                return None;
            }

            let pid = u16::from_le_bytes([rtps_packet[offset], rtps_packet[offset + 1]]);
            let len =
                u16::from_le_bytes([rtps_packet[offset + 2], rtps_packet[offset + 3]]) as usize;

            if pid == 0x0001 {
                offset += 4;
                break;
            }

            offset += 4 + len;
            offset = (offset + 3) & !3;
        }

        if offset >= rtps_packet.len() {
            return None;
        }

        Some(&rtps_packet[offset..])
    } else {
        // No inline QoS: payload starts at standard DATA header size (24 bytes)
        let payload_start = data_off + 24;
        if payload_start >= rtps_packet.len() {
            return None;
        }
        Some(&rtps_packet[payload_start..])
    }
}

/// Extract inline QoS from RTPS DATA packet for topic name parsing.
///
/// RTPS DATA layout (offsets in full RTPS packet):
/// - \[20\]: submessageId (0x15)
/// - \[21\]: flags (bit 1 = InlineQos present)
/// - \[22-23\]: submessageLength
/// - \[24-25\]: extraFlags
/// - \[26-27\]: octetsToInlineQos (typically 16)
/// - \[28-31\]: readerEntityId
/// - \[32-35\]: writerEntityId
/// - \[36-43\]: sequenceNumber
/// - \[44+\]: inline QoS (if flag set), then payload
pub fn extract_inline_qos(rtps_packet: &[u8]) -> Option<&[u8]> {
    if !validate_rtps_data_packet(rtps_packet, 44) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;

    // Check InlineQos flag (bit 1 of submessage flags)
    let flags = rtps_packet[data_off + 1];
    if flags & 0x02 == 0 {
        return None; // No inline QoS present
    }

    // octetsToInlineQos at (data_off + 4 [hdr] + 2 [extraFlags]) = data_off + 6
    let octets_to_inline_qos =
        u16::from_le_bytes([rtps_packet[data_off + 6], rtps_packet[data_off + 7]]) as usize;
    let qos_offset = data_off + 8 + octets_to_inline_qos;

    if qos_offset >= rtps_packet.len() {
        return None;
    }

    // Scan PID parameter list to find PID_SENTINEL (0x0001)
    let mut offset = qos_offset;
    loop {
        if offset + 4 > rtps_packet.len() {
            return Some(&rtps_packet[qos_offset..]);
        }

        let pid = u16::from_le_bytes([rtps_packet[offset], rtps_packet[offset + 1]]);
        let len = u16::from_le_bytes([rtps_packet[offset + 2], rtps_packet[offset + 3]]) as usize;

        if pid == 0x0001 {
            return Some(&rtps_packet[qos_offset..offset + 4]);
        }

        offset += 4 + len;
        offset = (offset + 3) & !3;
    }
}

/// Extract sequence number from RTPS DATA packet.
///
/// RTPS DATA submessage layout (per RTPS v2.3 Sec.8.3.7.2):
/// - Offset 20: Submessage header (4 bytes: id, flags, octetsToNext)
/// - Offset 24: extraFlags (2 bytes)
/// - Offset 26: octetsToInlineQos (2 bytes)
/// - Offset 28: readerEntityId (4 bytes)
/// - Offset 32: writerEntityId (4 bytes)
/// - Offset 36: writerSN (8 bytes) <- SequenceNumber_t
///
/// SequenceNumber_t is encoded as two 32-bit values (high, low) in little-endian.
pub fn extract_sequence_number(rtps_packet: &[u8]) -> Option<u64> {
    if !validate_rtps_data_packet(rtps_packet, 44) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;

    // Relative to data_off: hdr(4) + extraFlags(2) + octetsToInlineQos(2) +
    // readerEntityId(4) + writerEntityId(4) = 16 → writerSN at data_off + 16
    let sn_base = data_off + 16;
    if sn_base + 8 > rtps_packet.len() {
        return None;
    }
    let seq_high = u32::from_le_bytes([
        rtps_packet[sn_base],
        rtps_packet[sn_base + 1],
        rtps_packet[sn_base + 2],
        rtps_packet[sn_base + 3],
    ]);
    let seq_low = u32::from_le_bytes([
        rtps_packet[sn_base + 4],
        rtps_packet[sn_base + 5],
        rtps_packet[sn_base + 6],
        rtps_packet[sn_base + 7],
    ]);

    // RTPS SequenceNumber_t: value = high * 2^32 + low
    Some(((seq_high as u64) << 32) | (seq_low as u64))
}

/// Extract writer GUID from RTPS DATA packet.
///
/// The writer GUID consists of:
/// - guidPrefix (12 bytes): From RTPS header at offset 8
/// - writerEntityId (4 bytes): From DATA submessage at offset 28
///
/// Returns a 16-byte array representing the complete writer GUID.
///
/// # RTPS Specification
/// - RTPS v2.3 Sec.8.3.3: RTPS Header format (guidPrefix)
/// - RTPS v2.3 Sec.8.3.7.2: DATA Submessage format (writerEntityId)
pub fn extract_writer_guid(rtps_packet: &[u8]) -> Option<[u8; 16]> {
    // Validate RTPS/RTPX magic and minimum packet size
    if rtps_packet.len() < 20 {
        return None;
    }
    let magic_valid = &rtps_packet[0..4] == RTPS_MAGIC || &rtps_packet[0..4] == b"RTPX";
    if !magic_valid {
        return None;
    }

    // Extract guidPrefix from RTPS header (offset 8, 12 bytes)
    let guid_prefix = &rtps_packet[8..20];

    // Scan submessages to find DATA (0x15)
    let mut offset = 20; // First submessage starts after RTPS header
    while offset + 4 <= rtps_packet.len() {
        let submsg_id = rtps_packet[offset];
        let _flags = rtps_packet[offset + 1];

        // octets_to_next is LE u16 at offset+2
        let octets_to_next =
            u16::from_le_bytes([rtps_packet[offset + 2], rtps_packet[offset + 3]]) as usize;

        // Check if this is DATA submessage (0x15)
        if submsg_id == RTPS_SUBMSG_DATA {
            // writerEntityId starts after:
            // - 4-byte submessage header
            // - extraFlags (1) + octetsToInlineQos (1) + 2 bytes padding
            // - readerEntityId (4 bytes)
            // See RTPS v2.5 Sec.8.3.7.2 Figure 8.31
            let writer_entity_id_offset = offset + 4 + 8;
            if writer_entity_id_offset + 4 > rtps_packet.len() {
                return None;
            }
            let writer_entity_id =
                &rtps_packet[writer_entity_id_offset..writer_entity_id_offset + 4];

            // Combine into full 16-byte GUID
            let mut guid = [0u8; 16];
            guid[0..12].copy_from_slice(guid_prefix);
            guid[12..16].copy_from_slice(writer_entity_id);

            return Some(guid);
        }

        // Move to next submessage
        if octets_to_next == 0 {
            break; // Last submessage
        }
        offset += 4 + octets_to_next;
    }

    None // DATA submessage not found
}

/// Check if a DATA submessage carries a dispose/unregister lifecycle event.
///
/// Two on-wire forms are recognized (both spec-valid per RTPS v2.5 §8.3.7.2):
///
/// 1. K-flag DATA (K=1, D=0): payload is the serialized key. This is HDDS's
///    own emission path (`build_dispose_packet_with_context`).
/// 2. Inline-QoS-only DATA (D=0, K=0, Q=1): empty payload, lifecycle bits
///    live in `PID_STATUS_INFO` carried in inline QoS. This is what Connext
///    (and FastDDS) emit for per-instance unregister/dispose when a matched
///    reader is present — observed on the wire as
///    `Flags: 0x03, Inline QoS, Endianness`, `Data present: Not set`,
///    `Serialized Key: Not set` with PID_STATUS_INFO=0x01/0x02/0x03 +
///    PID_KEY_HASH. Without this branch HDDS silently drops Connext's
///    per-instance dispose, causing FinalInstanceState_0/1/2 cross-vendor
///    timeouts.
///
/// Either form gets routed through `deliver_dispose` so application
/// `get_dispose_events()` sees the per-instance state transition.
pub fn is_key_only_data(rtps_packet: &[u8]) -> bool {
    if !super::helpers::validate_rtps_data_packet(rtps_packet, 24) {
        return false;
    }
    let Some(data_off) = find_data_submsg_offset(rtps_packet) else {
        return false;
    };
    let flags = rtps_packet[data_off + 1];
    let has_key = flags & 0x08 != 0;
    if has_key {
        return true;
    }
    let has_payload = flags & 0x04 != 0;
    let has_inline_qos = flags & 0x02 != 0;
    if has_payload || !has_inline_qos {
        return false;
    }
    // D=0, K=0, Q=1 — a dispose marker iff inline QoS carries PID_STATUS_INFO
    // with at least one of the D/U bits set (Connext / FastDDS per-instance
    // dispose form).
    let Some(inline_qos) = extract_inline_qos(rtps_packet) else {
        return false;
    };
    matches!(extract_status_info(inline_qos), Some(s) if (s & 0x03) != 0)
}

/// Extract PID_STATUS_INFO (0x0071) value from inline QoS parameter list.
///
/// The inline QoS bytes start with a 4-byte CDR encapsulation header,
/// followed by PID parameters. Each parameter: PID(u16) + length(u16) + data.
///
/// Returns the 4-byte StatusInfo value as u32 if PID 0x0071 is found.
/// StatusInfo bits: 0x01 = DISPOSED, 0x02 = UNREGISTERED.
pub fn extract_status_info(inline_qos: &[u8]) -> Option<u32> {
    // Inline QoS is a ParameterList per RTPS v2.5 §9.4.5.3.3 — no CDR
    // encapsulation header. Spec-strict peers (Connext, FastDDS) and HDDS
    // itself now emit the PID list directly.
    let mut offset = 0;

    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = u16::from_le_bytes([inline_qos[offset], inline_qos[offset + 1]]);
        let len = u16::from_le_bytes([inline_qos[offset + 2], inline_qos[offset + 3]]) as usize;

        // PID_SENTINEL -- end of parameter list
        if pid == 0x0001 {
            return None;
        }

        // PID_STATUS_INFO (0x0071) -- 4 bytes
        //
        // The field is a 4-octet array per DDS-RTPS v2.5 §9.6.3.4
        // (`typedef octet StatusInfo_t[4]`), with the
        // D / U / F flag bits in OCTET 3. Reading via
        // `from_be_bytes` puts octet 3 in the low byte of the u32,
        // so callers can still treat the result as the flag bitmask
        // `0x01 = Disposed`, `0x02 = Unregistered`, `0x03 = both`.
        // Reading as little-endian (the pre-fix behavior) would
        // place octet 3 in the high byte and mask flag detection,
        // silently dropping every Connext / Fast DDS dispose /
        // unregister sample.
        if pid == 0x0071 && len >= 4 && offset + 4 + 4 <= inline_qos.len() {
            let value = u32::from_be_bytes([
                inline_qos[offset + 4],
                inline_qos[offset + 5],
                inline_qos[offset + 6],
                inline_qos[offset + 7],
            ]);
            return Some(value);
        }

        offset += 4 + len;
        offset = (offset + 3) & !3; // Align to 4 bytes
    }
}

/// Extract a `SequenceNumber_t` carried in a PID from inline QoS.
///
/// Wire format per RTPS v2.5 §9.4.5.4.2: parameter value is `high i32 LE`
/// followed by `low u32 LE`. Returns the combined u64
/// `((high << 32) | low)` if the PID is present AND has length >= 8.
fn extract_sequence_number_pid(inline_qos: &[u8], target_pid: u16) -> Option<u64> {
    let mut offset = 0;
    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = u16::from_le_bytes([inline_qos[offset], inline_qos[offset + 1]]);
        let len = u16::from_le_bytes([inline_qos[offset + 2], inline_qos[offset + 3]]) as usize;

        if pid == 0x0001 {
            return None;
        }

        if pid == target_pid && len >= 8 && offset + 4 + 8 <= inline_qos.len() {
            let high = i32::from_le_bytes([
                inline_qos[offset + 4],
                inline_qos[offset + 5],
                inline_qos[offset + 6],
                inline_qos[offset + 7],
            ]);
            let low = u32::from_le_bytes([
                inline_qos[offset + 8],
                inline_qos[offset + 9],
                inline_qos[offset + 10],
                inline_qos[offset + 11],
            ]);
            return Some(((high as i64) << 32 | low as i64) as u64);
        }

        offset += 4 + len;
        offset = (offset + 3) & !3;
    }
}

/// Extract `PID_COHERENT_SET` (0x0056) from inline QoS as a u64
/// SequenceNumber_t per RTPS v2.5 §8.7.5.
pub fn extract_coherent_set(inline_qos: &[u8]) -> Option<u64> {
    extract_sequence_number_pid(inline_qos, 0x0056)
}

/// Extract `PID_GROUP_COHERENT_SET` (0x0063) from inline QoS as a u64 GSN
/// per RTPS v2.5 §8.7.5.
pub fn extract_group_coherent_set(inline_qos: &[u8]) -> Option<u64> {
    extract_sequence_number_pid(inline_qos, 0x0063)
}

/// Extract `PID_GROUP_ENTITY_ID` (0x0053) from inline QoS as the
/// 4-byte EntityId of the owning Publisher (writer side) or
/// Subscriber (reader side) per RTPS v2.5 §9.3.2.1. Returned in
/// wire order `[entityKey0, entityKey1, entityKey2, entityKind]`.
///
/// Used by the GROUP-scope coherent-set aggregation to bucket
/// per-Publisher GSNs (two Publishers in the same Participant can
/// legitimately reuse the same GSN, so the key MUST include the
/// publisher EntityId to avoid cross-publisher aliasing —
/// DDS v1.4 §2.2.3.6 GROUP Presentation).
pub fn extract_group_entity_id(inline_qos: &[u8]) -> Option<[u8; 4]> {
    let mut offset = 0;

    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = u16::from_le_bytes([inline_qos[offset], inline_qos[offset + 1]]);
        let len = u16::from_le_bytes([inline_qos[offset + 2], inline_qos[offset + 3]]) as usize;

        if pid == 0x0001 {
            return None;
        }

        if pid == 0x0053 && len >= 4 && offset + 4 + 4 <= inline_qos.len() {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&inline_qos[offset + 4..offset + 8]);
            return Some(buf);
        }

        offset += 4 + len;
        offset = (offset + 3) & !3;
    }
}

/// Recognise an End-of-Coherent-Set (ECS) DATA submessage per RTPS v2.5
/// §8.7.5. Returns `(coherent_sn, group_sn)` when the packet is:
///
/// * a DATA submessage with flags `D=0, K=0, Q=1` (no payload, inline QoS
///   only),
/// * carrying `PID_COHERENT_SET` (mandatory) and optionally
///   `PID_GROUP_COHERENT_SET`,
/// * NOT carrying `PID_STATUS_INFO` with dispose/unregister bits set
///   (which is the inline-QoS-only dispose form recognised by
///   `is_key_only_data`).
///
/// Returns `None` otherwise. The caller routes ECS markers through the
/// per-(writer, gsn) commit path; regular DATA / K-flag DATA / dispose
/// markers go through the normal pipeline.
pub fn extract_ecs_marker(rtps_packet: &[u8]) -> Option<(u64, Option<u64>)> {
    use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};

    if !validate_rtps_data_packet(rtps_packet, 24) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;
    let flags = rtps_packet[data_off + 1];
    let has_data = flags & 0x04 != 0;
    let has_key = flags & 0x08 != 0;
    let has_inline_qos = flags & 0x02 != 0;
    if has_data || has_key || !has_inline_qos {
        return None;
    }

    let inline_qos = extract_inline_qos(rtps_packet)?;

    // If this carries a dispose/unregister StatusInfo bit it is the
    // inline-QoS-only dispose form, not an ECS marker.
    if let Some(status) = extract_status_info(inline_qos) {
        if (status & 0x03) != 0 {
            return None;
        }
    }

    let coherent_sn = extract_coherent_set(inline_qos)?;
    let group_sn = extract_group_coherent_set(inline_qos);
    Some((coherent_sn, group_sn))
}

/// Extract PID_KEY_HASH (0x0070) from inline QoS parameter list.
///
/// Returns the 16-byte key hash if PID 0x0070 is found.
pub fn extract_key_hash(inline_qos: &[u8]) -> Option<[u8; 16]> {
    // Inline QoS has no CDR encapsulation header (see extract_status_info).
    let mut offset = 0;

    loop {
        if offset + 4 > inline_qos.len() {
            return None;
        }

        let pid = u16::from_le_bytes([inline_qos[offset], inline_qos[offset + 1]]);
        let len = u16::from_le_bytes([inline_qos[offset + 2], inline_qos[offset + 3]]) as usize;

        // PID_SENTINEL
        if pid == 0x0001 {
            return None;
        }

        // PID_KEY_HASH (0x0070) -- 16 bytes
        if pid == 0x0070 && len >= 16 && offset + 4 + 16 <= inline_qos.len() {
            let mut key_hash = [0u8; 16];
            key_hash.copy_from_slice(&inline_qos[offset + 4..offset + 4 + 16]);
            return Some(key_hash);
        }

        offset += 4 + len;
        offset = (offset + 3) & !3;
    }
}

#[cfg(test)]
mod tests {
    use super::{extract_data_payload, extract_writer_guid};
    use crate::protocol::constants::RTPS_SUBMSG_DATA;

    /// Build an RTPS packet with a DATA submessage for testing.
    ///
    /// Parameters control the flags, inline QoS region, and an optional
    /// payload suffix. This lets us construct both Q=0 and Q=1 scenarios,
    /// and simulate the CoreDDS case (Q=0, non-zero octetsToInlineQos).
    fn build_data_test_packet(
        flags: u8,
        octets_to_inline_qos: u16,
        inline_qos_payload: &[u8],
        data_payload: &[u8],
    ) -> Vec<u8> {
        // RTPS header (20 bytes)
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 3, 0x01, 0xaa]); // version, vendor
        packet.extend_from_slice(&[0u8; 12]); // guidPrefix

        // DATA submessage header
        let extra_flags: u16 = 0;
        let reader_id: u32 = 0; // ENTITYID_UNKNOWN
        let writer_id: u32 = 0x0102; // user DataWriter
        let seq_num: u64 = 1;

        let header_size: usize = 24; // submsg_hdr + extraFlags + octetsToInlineQos + readerId + writerId + seqNum
        let inline_qos_size = inline_qos_payload.len();
        let total_data_size = header_size + inline_qos_size + data_payload.len();

        // octets_to_next = total submessage size after the 4-byte header
        let octets_to_next = (total_data_size - 4) as u16;

        packet.push(0x15); // submsgId = DATA
        packet.push(flags);
        packet.extend_from_slice(&octets_to_next.to_le_bytes());
        packet.extend_from_slice(&extra_flags.to_le_bytes());
        packet.extend_from_slice(&octets_to_inline_qos.to_le_bytes());
        packet.extend_from_slice(&reader_id.to_le_bytes());
        packet.extend_from_slice(&writer_id.to_le_bytes());
        packet.extend_from_slice(&seq_num.to_le_bytes());

        // Inline QoS region (may be empty for Q=0)
        packet.extend_from_slice(inline_qos_payload);

        // Serialized data payload
        packet.extend_from_slice(data_payload);

        packet
    }

    fn build_data_packet(prefix: [u8; 12], writer_entity_id: [u8; 4]) -> Vec<u8> {
        // Minimal RTPS DATA packet layout required by extract_writer_guid
        let mut packet = vec![0u8; 48];
        packet[0..4].copy_from_slice(b"RTPS");
        packet[4] = 2; // version major
        packet[5] = 3; // version minor
        packet[6] = 0x01; // vendor id (arbitrary)
        packet[7] = 0xaa;
        packet[8..20].copy_from_slice(&prefix);

        // DATA submessage header
        packet[20] = RTPS_SUBMSG_DATA;
        packet[21] = 0x05; // little-endian + inline QoS
        packet[22..24].copy_from_slice(&(24u16).to_le_bytes()); // octets_to_next

        // extraFlags + octetsToInlineQos + padding
        packet[24] = 0;
        packet[25] = 0x10; // inline QoS starts after writerSN (default 16)
        packet[26] = 0;
        packet[27] = 0;

        // readerEntityId (ENTITYID_UNKNOWN)
        packet[28..32].copy_from_slice(&[0, 0, 0, 0]);

        // writerEntityId under test
        packet[32..36].copy_from_slice(&writer_entity_id);

        // writerSN (SequenceNumber_t, little-endian for test)
        packet[36..44].copy_from_slice(&1u64.to_le_bytes());

        packet
    }

    #[test]
    fn extracts_user_writer_entity_id() {
        let prefix = [0xAA; 12];
        let writer_entity_id = [0x00, 0x00, 0x01, 0x02]; // user DataWriter (kind=0x02)
        let packet = build_data_packet(prefix, writer_entity_id);

        let guid = extract_writer_guid(&packet).expect("writer GUID should be parsed");
        assert_eq!(&guid[..12], &prefix);
        assert_eq!(&guid[12..], &writer_entity_id);
    }

    #[test]
    fn extracts_builtin_publications_writer_entity_id() {
        let prefix = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];
        let writer_entity_id = [0x00, 0x01, 0x00, 0xC2]; // SEDPbuiltinPublicationsWriter
        let packet = build_data_packet(prefix, writer_entity_id);

        let guid = extract_writer_guid(&packet).expect("writer GUID should be parsed");
        assert_eq!(&guid[..12], &prefix);
        assert_eq!(&guid[12..], &writer_entity_id);
    }

    // --- extract_data_payload tests ---

    #[test]
    fn extract_payload_q0_returns_data_at_24() {
        // Q=0 (flags & 0x02 == 0), no inline QoS, data at offset 24
        let payload = b"serialized_data_here";
        let packet = build_data_test_packet(0x01, 0, &[], payload);
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }

    #[test]
    fn extract_payload_q0_with_octets_to_qos_16() {
        // CoreDDS case: Q=0 (flags=0x05: D=1, Q=0, E=1), octetsToInlineQos=16
        // but the inline QoS flag is NOT set, so the payload should start at 24
        // regardless of octetsToInlineQos.
        //
        // This would previously fail because the function treated
        // octetsToInlineQos as an absolute data offset and started a PID scan
        // at offset 24+16+4 = 44, past the actual payload.
        let payload = b"SHAPE_DATA";
        let packet = build_data_test_packet(0x05, 16, &[], payload);
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }

    #[test]
    fn extract_payload_q0_truncated_returns_none() {
        // Q=0, packet too short for 24-byte DATA header
        let mut packet = vec![0u8; 42]; // barely enough for header but not for payload
        packet[20] = 0x15; // DATA submsg id
        packet[21] = 0x01; // Q=0, LE
        packet[22..24].copy_from_slice(&4u16.to_le_bytes()); // octets_to_next
                                                             // packet is 42 bytes = RTPS header(20) + DATA hdr start but truncated
        assert!(extract_data_payload(&packet).is_none());
    }

    #[test]
    fn extract_payload_q1_scan_inline_qos() {
        // Q=1, inline QoS present with CDR encapsulation header + PID_SENTINEL.
        // Inline QoS layout per RTPS: 4-byte CDR encapsulation header
        // followed by parameter list.
        let inline_qos: Vec<u8> = {
            let mut qos = Vec::new();
            // CDR encapsulation header: PL_CDR_LE (0x0003) + options (2 bytes)
            qos.extend_from_slice(&0x0003u16.to_le_bytes());
            qos.extend_from_slice(&0x0000u16.to_le_bytes());
            // PID_KEY_HASH (0x0070), len=16, followed by 16 bytes
            qos.extend_from_slice(&0x0070u16.to_le_bytes());
            qos.extend_from_slice(&16u16.to_le_bytes());
            qos.extend_from_slice(&[0xABu8; 16]);
            // PID_SENTINEL (0x0001), len=0
            qos.extend_from_slice(&0x0001u16.to_le_bytes());
            qos.extend_from_slice(&0u16.to_le_bytes());
            qos
        };
        let payload = b"data_after_inline_qos";
        // octetsToInlineQos=16 covers readerId(4)+writerId(4)+seqNum(8)
        // The inline QoS CDR header starts at data_off+24
        let packet = build_data_test_packet(0x03, 16, &inline_qos, payload);
        // flags=0x03: Q=1, E=1 (no D=0, K=0, but that's fine for extraction)
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }

    #[test]
    fn extract_payload_q0_be_endianness() {
        // Q=0, big-endian flags (E flag = 0)
        let payload = b"big_endian_data";
        let packet = build_data_test_packet(0x00, 0, &[], payload);
        // flags=0x00: Q=0, E=0 (big-endian)
        let result = extract_data_payload(&packet);
        assert_eq!(result, Some(payload.as_slice()));
    }
}

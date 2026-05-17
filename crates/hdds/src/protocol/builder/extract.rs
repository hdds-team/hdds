// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::helpers::{find_data_submsg_offset, validate_rtps_data_packet};
use crate::protocol::constants::{RTPS_MAGIC, RTPS_SUBMSG_DATA};

/// Extract CDR2 payload from RTPS DATA packet.
pub fn extract_data_payload(rtps_packet: &[u8]) -> Option<&[u8]> {
    if !validate_rtps_data_packet(rtps_packet, 40) {
        return None;
    }
    let data_off = find_data_submsg_offset(rtps_packet)?;

    // octetsToInlineQos is at (data_off + 4 [submsg header] + 2 [extraFlags]) = data_off + 6
    let octets_to_qos =
        u16::from_le_bytes([rtps_packet[data_off + 6], rtps_packet[data_off + 7]]) as usize;
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
        let len = u16::from_le_bytes([rtps_packet[offset + 2], rtps_packet[offset + 3]]) as usize;

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

/// Check if RTPS DATA submessage has the K (key-only) flag set (bit 3).
///
/// When K flag is set, the DATA payload contains only the serialized key
/// (not full data). This is used for dispose and unregister lifecycle changes.
///
/// RTPS v2.3 Sec.8.3.7.2: DATA submessage flags
/// - Bit 0: Endianness (E flag)
/// - Bit 1: InlineQos (Q flag)
/// - Bit 2: Data present (D flag)
/// - Bit 3: Key present (K flag)
pub fn is_key_only_data(rtps_packet: &[u8]) -> bool {
    if !super::helpers::validate_rtps_data_packet(rtps_packet, 24) {
        return false;
    }
    let Some(data_off) = find_data_submsg_offset(rtps_packet) else {
        return false;
    };
    // DATA submessage flags at (data_off + 1)
    let flags = rtps_packet[data_off + 1];
    flags & 0x08 != 0 // Bit 3 = K flag
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
    use super::extract_writer_guid;
    use crate::protocol::constants::RTPS_SUBMSG_DATA;

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
}

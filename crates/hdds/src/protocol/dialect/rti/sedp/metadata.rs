// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI SEDP Metadata PID Writers
//!
//!
//! Standard PIDs for RTI interoperability:
//! - PID_ENDPOINT_GUID (0x005a) - Must come FIRST
//! - PID_PARTICIPANT_GUID (0x0050)
//! - PID_KEY_HASH (0x0070) - MANDATORY for RTI
//! - PID_TOPIC_NAME (0x0005)
//! - PID_TYPE_NAME (0x0007)
//! - PID_PROTOCOL_VERSION (0x0015) - MANDATORY
//! - PID_VENDOR_ID (0x0016)
//! - PID_TYPE_CONSISTENCY (0x0074) - Required for RTI type matching
//!
//! Note: RTI vendor-specific PIDs (0x8000+) are NOT sent by HDDS.
//! RTI validates that vendor PIDs come from its own vendor ID (0x0101).

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;

/// PID constants - includes required RTI vendor PIDs (0x8000+)
mod pids {
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_ENDPOINT_GUID: u16 = 0x005a;
    pub const PID_KEY_HASH: u16 = 0x0070;
    pub const PID_TOPIC_NAME: u16 = 0x0005;
    pub const PID_TYPE_NAME: u16 = 0x0007;
    pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
    pub const PID_VENDOR_ID: u16 = 0x0016;
    pub const PID_EXPECTS_INLINE_QOS: u16 = 0x0043;
    pub const PID_TYPE_CONSISTENCY: u16 = 0x0074;
}

/// HDDS vendor ID
const VENDOR_ID_HDDS: u16 = 0x01AA;

/// Convert HDDS internal entity_id to RTI/RTPS wire format if needed.
///
/// HDDS runtime generates user entity IDs in little-endian: key=1 -> [0x01, 0x00, 0x00, kind]
/// RTI/RTPS wire format uses big-endian: key=1 -> [0x00, 0x00, 0x01, kind]
///
/// Standard RTPS entity IDs (participant, built-in endpoints) are already big-endian
/// and should NOT be converted. We detect HDDS little-endian format by checking if
/// byte[0] is non-zero while byte[2] is zero (pattern of small LE integers).
#[inline]
fn entity_id_to_wire(entity_id: &[u8; 4]) -> [u8; 4] {
    // Detect HDDS little-endian user entity IDs:
    // - LE key=1: [0x01, 0x00, 0x00, kind] -> needs swap
    // - BE key=1: [0x00, 0x00, 0x01, kind] -> already correct (standard RTPS)
    // - BE key=0x0001C1: [0x00, 0x00, 0x01, 0xC1] -> participant, already correct
    if entity_id[0] != 0 && entity_id[2] == 0 {
        // Little-endian HDDS format - swap bytes 0,1,2
        [entity_id[2], entity_id[1], entity_id[0], entity_id[3]]
    } else {
        // Already in big-endian RTPS format
        *entity_id
    }
}

/// Write PID_ENDPOINT_GUID (0x005a) - 16 bytes
pub fn write_endpoint_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_ENDPOINT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].copy_from_slice(&guid.prefix);
    buf[*offset + 12..*offset + 16].copy_from_slice(&entity_id_to_wire(&guid.entity_id));
    *offset += 16;

    Ok(())
}

/// Write PID_PARTICIPANT_GUID (0x0050) - 16 bytes
pub fn write_participant_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].copy_from_slice(&guid.prefix);
    buf[*offset + 12..*offset + 16].copy_from_slice(&entity_id_to_wire(&guid.entity_id));
    *offset += 16;

    Ok(())
}

/// Write PID_KEY_HASH (0x0070) - 16 bytes
/// MANDATORY for RTI - uses endpoint GUID as key hash
pub fn write_key_hash(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_KEY_HASH.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].copy_from_slice(&guid.prefix);
    buf[*offset + 12..*offset + 16].copy_from_slice(&entity_id_to_wire(&guid.entity_id));
    *offset += 16;

    Ok(())
}

/// Write string parameter with 4-byte alignment
fn write_string_param(pid: u16, s: &str, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    let str_len = s.len();
    let str_with_null = str_len.saturating_add(1);
    let payload_len = str_with_null.saturating_add(4);
    let aligned_payload_len = (payload_len + 3) & !3;

    if aligned_payload_len > usize::from(u16::MAX) {
        return Err(EncodeError::InvalidParameter("string too long".to_string()));
    }

    let total_len = 4 + aligned_payload_len;
    if *offset + total_len > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    let param_len = aligned_payload_len as u16;
    buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&param_len.to_le_bytes());
    *offset += 4;

    let str_len_field = str_with_null as u32;
    buf[*offset..*offset + 4].copy_from_slice(&str_len_field.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + s.len()].copy_from_slice(s.as_bytes());
    *offset += s.len();
    buf[*offset] = 0;
    *offset += 1;

    let padding = aligned_payload_len - payload_len;
    if padding > 0 {
        buf[*offset..*offset + padding].fill(0);
        *offset += padding;
    }

    Ok(())
}

/// Write PID_TOPIC_NAME (0x0005)
pub fn write_topic_name(topic_name: &str, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    write_string_param(pids::PID_TOPIC_NAME, topic_name, buf, offset)
}

/// Write PID_TYPE_NAME (0x0007)
pub fn write_type_name(type_name: &str, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    write_string_param(pids::PID_TYPE_NAME, type_name, buf, offset)
}

/// Write PID_PROTOCOL_VERSION (0x0015) - 4 bytes
/// Use RTPS v2.3 to match RTI capture and minimize surprises.
pub fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = 2; // major = 2
    buf[*offset + 5] = 3; // minor = 3 (RTPS v2.3, matches capture)
    buf[*offset + 6] = 0;
    buf[*offset + 7] = 0;
    *offset += 8;

    Ok(())
}

/// Write PID_VENDOR_ID (0x0016) - 4 bytes
///
/// RTPS spec: VendorId is 2 bytes in big-endian (network order).
/// HDDS vendor ID = 0x01AA -> bytes [0x01, 0xAA]
pub fn write_vendor_id(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_VENDOR_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    // VendorId is big-endian per RTPS spec
    buf[*offset + 4..*offset + 6].copy_from_slice(&VENDOR_ID_HDDS.to_be_bytes());
    buf[*offset + 6] = 0;
    buf[*offset + 7] = 0;
    *offset += 8;

    Ok(())
}

// NOTE: PID_PRODUCT_VERSION (0x8000) is RTI vendor-specific.
// HDDS as vendor 0x01AA must NOT send PIDs >= 0x8000 to RTI.

/// Write PID_EXPECTS_INLINE_QOS (0x0043) - 4 bytes (bool)
pub fn write_expects_inline_qos(
    expects: bool,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_EXPECTS_INLINE_QOS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&(expects as u32).to_le_bytes());
    *offset += 8;

    Ok(())
}

// NOTE: RTI vendor-specific PIDs (0x8000+) are NOT sent by HDDS.
// RTI validates that vendor PIDs come from its own vendor ID (0x0101).
// When HDDS (vendor 0x01AA) sends vendor PIDs, RTI rejects the SEDP.

/// Write PID_TYPE_CONSISTENCY (0x0074) - 8 bytes
///
/// Matches FastDDS wire format exactly for RTI interop:
/// `74 00 08 00 01 00 01 01 00 00 00 00`
///
/// FastDDS encodes this as a DataRepresentationQosPolicy sequence:
/// - `01 00` = sequence length = 1
/// - `01 01` = XCDR1 (0x01) and some flags
/// - `00 00 00 00` = padding
pub fn write_type_consistency(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TYPE_CONSISTENCY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    // Match FastDDS exactly: 01 00 01 01 00 00 00 00
    buf[*offset + 4..*offset + 6].copy_from_slice(&[0x01, 0x00]); // sequence length = 1
    buf[*offset + 6..*offset + 8].copy_from_slice(&[0x01, 0x01]); // element
    buf[*offset + 8..*offset + 12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // padding
    *offset += 12;

    Ok(())
}

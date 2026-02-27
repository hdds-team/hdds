// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS SEDP Metadata PID Writers
//!
//! Standard PIDs for OpenDDS interoperability:
//! - PID_ENDPOINT_GUID (0x005a)
//! - PID_PARTICIPANT_GUID (0x0050)
//! - PID_TOPIC_NAME (0x0005)
//! - PID_TYPE_NAME (0x0007)
//! - PID_PROTOCOL_VERSION (0x0015)
//! - PID_VENDOR_ID (0x0016)
//! - PID_DATA_REPRESENTATION (0x0073) - XCDR2 support

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;

/// PID constants
mod pids {
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_ENDPOINT_GUID: u16 = 0x005a;
    pub const PID_TOPIC_NAME: u16 = 0x0005;
    pub const PID_TYPE_NAME: u16 = 0x0007;
    pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
    pub const PID_VENDOR_ID: u16 = 0x0016;
    pub const PID_DATA_REPRESENTATION: u16 = 0x0073;
    #[allow(dead_code)] // Used by write_type_consistency()
    pub const PID_TYPE_CONSISTENCY: u16 = 0x0074;
}

/// HDDS vendor ID
const VENDOR_ID_HDDS: u16 = 0x01AA;

/// Data representation IDs
const XCDR1: u16 = 0x0000;
const XCDR2: u16 = 0x0002;

/// Convert HDDS internal entity_id to RTPS wire format if needed.
#[inline]
fn entity_id_to_wire(entity_id: &[u8; 4]) -> [u8; 4] {
    if entity_id[0] != 0 && entity_id[2] == 0 {
        [entity_id[2], entity_id[1], entity_id[0], entity_id[3]]
    } else {
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
pub fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = 2; // major = 2
    buf[*offset + 5] = 4; // minor = 4 (RTPS v2.4 for OpenDDS)
    buf[*offset + 6] = 0;
    buf[*offset + 7] = 0;
    *offset += 8;

    Ok(())
}

/// Write PID_VENDOR_ID (0x0016) - 4 bytes
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

/// Write PID_DATA_REPRESENTATION (0x0073) with XCDR1 and XCDR2 support
///
/// OpenDDS uses XTypes and expects XCDR2 support to be advertised.
/// Format: sequence<DataRepresentationId_t>
///   - 4 bytes: sequence length (number of elements)
///   - 2 bytes per element: DataRepresentationId
///   - Padding to 4-byte alignment
pub fn write_data_representation_xcdr2(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    // Sequence with 2 elements: XCDR1 and XCDR2
    // Total payload: 4 (seq_len) + 2 (XCDR1) + 2 (XCDR2) = 8 bytes (aligned)
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DATA_REPRESENTATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes()); // payload length
    *offset += 4;

    // Sequence length = 2
    buf[*offset..*offset + 4].copy_from_slice(&2u32.to_le_bytes());
    *offset += 4;

    // XCDR1 = 0x0000
    buf[*offset..*offset + 2].copy_from_slice(&XCDR1.to_le_bytes());
    *offset += 2;

    // XCDR2 = 0x0002
    buf[*offset..*offset + 2].copy_from_slice(&XCDR2.to_le_bytes());
    *offset += 2;

    Ok(())
}

/// Write PID_TYPE_CONSISTENCY (0x0074) - 8 bytes
///
/// XTypes v1.3 Sec.7.6.3.3.3: TypeConsistencyEnforcementQosPolicy.
/// Format: kind (u16) + ignore_sequence_bounds (u8) + ignore_string_bounds (u8) + padding (4 bytes).
///
/// Setting ALLOW_TYPE_COERCION (kind=1) tells OpenDDS to relax type matching
/// and fall back to name-based matching when TypeInformation is not available.
#[allow(dead_code)] // Part of OpenDDS dialect API, used for XTypes support
pub fn write_type_consistency(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TYPE_CONSISTENCY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    *offset += 4;

    // TypeConsistencyEnforcementQosPolicy:
    // - kind: ALLOW_TYPE_COERCION = 1 (u16)
    // - ignore_sequence_bounds: true (u8)
    // - ignore_string_bounds: true (u8)
    // - ignore_member_names: true (u8)
    // - prevent_type_widening: false (u8)
    // - force_type_validation: false (u8)
    // - padding (1 byte)
    buf[*offset..*offset + 2].copy_from_slice(&1u16.to_le_bytes()); // ALLOW_TYPE_COERCION
    buf[*offset + 2] = 0x01; // ignore_sequence_bounds = true
    buf[*offset + 3] = 0x01; // ignore_string_bounds = true
    buf[*offset + 4] = 0x01; // ignore_member_names = true
    buf[*offset + 5] = 0x00; // prevent_type_widening = false
    buf[*offset + 6] = 0x00; // force_type_validation = false
    buf[*offset + 7] = 0x00; // padding
    *offset += 8;

    Ok(())
}

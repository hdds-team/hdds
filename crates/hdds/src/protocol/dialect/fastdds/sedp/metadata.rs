// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FastDDS SEDP Metadata PID Writers
//!
//! Handles encoding of endpoint identification and metadata PIDs:
//! - PID_ENDPOINT_GUID (0x005a) - Must come FIRST for FastDDS
//! - PID_PARTICIPANT_GUID (0x0050)
//! - PID_TOPIC_NAME (0x0005)
//! - PID_TYPE_NAME (0x0007)
//! - PID_PROTOCOL_VERSION (0x0015)
//! - PID_VENDOR_ID (0x0016)

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;

/// PID constants
// These constants define RTPS PID values for FastDDS SEDP compatibility.
// Used by the write_* functions below when encoding SEDP parameter lists.
mod pids {
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_ENDPOINT_GUID: u16 = 0x005a;
    pub const PID_TOPIC_NAME: u16 = 0x0005;
    pub const PID_TYPE_NAME: u16 = 0x0007;
    pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
    pub const PID_VENDOR_ID: u16 = 0x0016;
}

/// HDDS vendor ID - used in PID_VENDOR_ID for FastDDS interoperability
#[allow(dead_code)] // Part of FastDDS SEDP encoding API, will be used when encoding vendor ID
const VENDOR_ID_HDDS: u16 = 0x01AA;

/// Write PID_ENDPOINT_GUID (0x005a) - 16 bytes.
///
/// FastDDS validates this PID first when parsing SEDP parameter lists.
/// Must appear before PID_PARTICIPANT_GUID for compatibility.
#[allow(dead_code)] // Part of FastDDS SEDP encoding API for future interoperability
pub fn write_endpoint_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_ENDPOINT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].copy_from_slice(&guid.prefix);
    buf[*offset + 12..*offset + 16].copy_from_slice(&guid.entity_id);
    *offset += 16;

    Ok(())
}

/// Write PID_PARTICIPANT_GUID (0x0050) - 16 bytes.
///
/// Links endpoint to its owning participant.
/// FastDDS EDPSimpleListeners validates participant exists before accepting endpoint.
#[allow(dead_code)] // Part of FastDDS SEDP encoding API for future interoperability
pub fn write_participant_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].copy_from_slice(&guid.prefix);
    buf[*offset + 12..*offset + 16].copy_from_slice(&guid.entity_id);
    *offset += 16;

    Ok(())
}

/// Write string parameter (topic name, type name).
///
/// Format: PID (u16) + length (u16) + str_len (u32) + string bytes + null terminator + padding
#[allow(dead_code)] // Helper for write_topic_name and write_type_name, part of FastDDS SEDP encoding API
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
    buf[*offset] = 0; // null terminator
    *offset += 1;

    // Padding to 4-byte boundary
    let padding = aligned_payload_len - payload_len;
    if padding > 0 {
        buf[*offset..*offset + padding].fill(0);
        *offset += padding;
    }

    Ok(())
}

/// Write PID_TOPIC_NAME (0x0005).
#[allow(dead_code)] // Part of FastDDS SEDP encoding API for future interoperability
pub fn write_topic_name(topic_name: &str, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    write_string_param(pids::PID_TOPIC_NAME, topic_name, buf, offset)
}

/// Write PID_TYPE_NAME (0x0007).
#[allow(dead_code)] // Part of FastDDS SEDP encoding API for future interoperability
pub fn write_type_name(type_name: &str, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    write_string_param(pids::PID_TYPE_NAME, type_name, buf, offset)
}

/// Write PID_PROTOCOL_VERSION (0x0015) - 4 bytes.
///
/// Format: major (u8) + minor (u8) + padding (2 bytes).
/// RTPS v2.3 for FastDDS compatibility.
#[allow(dead_code)] // Part of FastDDS SEDP encoding API for future interoperability
pub fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = 2; // major = 2
    buf[*offset + 5] = 3; // minor = 3 (RTPS v2.3)
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0; // padding
    *offset += 8;

    Ok(())
}

/// Write PID_VENDOR_ID (0x0016) - 4 bytes.
///
/// Format: vendor_id (u16 LE) + padding (2 bytes).
#[allow(dead_code)] // Part of FastDDS SEDP encoding API for future interoperability
pub fn write_vendor_id(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_VENDOR_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 6].copy_from_slice(&VENDOR_ID_HDDS.to_le_bytes());
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0; // padding
    *offset += 8;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_guid_encoding() {
        let guid = Guid {
            prefix: [
                0x01, 0x0F, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0x04],
        };
        let mut buf = [0u8; 32];
        let mut offset = 0;

        write_endpoint_guid(&guid, &mut buf, &mut offset).expect("write_endpoint_guid failed");

        assert_eq!(offset, 20);
        // PID_ENDPOINT_GUID = 0x005a
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), 0x005a);
        // Length = 16
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 16);
        // Prefix
        assert_eq!(&buf[4..16], &guid.prefix);
        // Entity ID
        assert_eq!(&buf[16..20], &guid.entity_id);
    }

    #[test]
    fn test_string_param_alignment() {
        let mut buf = [0u8; 64];
        let mut offset = 0;

        write_topic_name("Test", &mut buf, &mut offset).expect("write_topic_name failed");

        // PID header (4) + str_len (4) + "Test\0" (5) + padding (3) = 16
        assert_eq!(offset, 16);
        assert_eq!(offset % 4, 0, "must be 4-byte aligned");
    }
}

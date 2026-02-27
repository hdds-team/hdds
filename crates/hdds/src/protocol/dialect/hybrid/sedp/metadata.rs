// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Hybrid SEDP Metadata PID Writers
//!
//! Standard PIDs only - no vendor extensions.

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;

/// PID constants
#[allow(dead_code)] // PIDs used by public API functions
mod pids {
    pub const PID_ENDPOINT_GUID: u16 = 0x005a;
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_TOPIC_NAME: u16 = 0x0005;
    pub const PID_TYPE_NAME: u16 = 0x0007;
}

/// Write PID_ENDPOINT_GUID (0x005a) - 16 bytes
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_endpoint_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_ENDPOINT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    buf[*offset + 4..*offset + 16].copy_from_slice(&guid.prefix);
    buf[*offset + 16..*offset + 20].copy_from_slice(&guid.entity_id);
    *offset += 20;

    Ok(())
}

/// Write PID_PARTICIPANT_GUID (0x0050) - 16 bytes
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_participant_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    buf[*offset + 4..*offset + 16].copy_from_slice(&guid.prefix);
    buf[*offset + 16..*offset + 20].copy_from_slice(&guid.entity_id);
    *offset += 20;

    Ok(())
}

/// Write string parameter (topic name, type name).
#[allow(dead_code)] // Helper used by public write_topic_name/write_type_name
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

/// Write PID_TOPIC_NAME (0x0005) - variable length
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_topic_name(name: &str, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    write_string_param(pids::PID_TOPIC_NAME, name, buf, offset)
}

/// Write PID_TYPE_NAME (0x0007) - variable length
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_type_name(name: &str, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    write_string_param(pids::PID_TYPE_NAME, name, buf, offset)
}

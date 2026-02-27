// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP Metadata PID Writers
//!
//! Handles encoding of endpoint identification and metadata PIDs:
//! - PID_PARTICIPANT_GUID (0x0050) - Participant identifier (16 bytes, v110: FastDDS interop)
//! - PID_ENDPOINT_GUID (0x005a) - Endpoint identifier (16 bytes)
//! - PID_TOPIC_NAME (0x0005) - Topic name string
//! - PID_TYPE_NAME (0x0007) - Type name string
//! - PID_PROTOCOL_VERSION (0x0015) - RTPS version (major.minor)
//! - PID_VENDOR_ID (0x0016) - Vendor identifier (0x01AA = HDDS)
//! - PID_PRODUCT_VERSION (0x8000) - Product version (major.minor.release.build)
//! - PID_DATA_REPRESENTATION (0x0073) - Data representation and compression
//! - PID_RECV_QUEUE_SIZE (0x0018) - Deprecated queue size marker
//! - PID_GROUP_ENTITY_ID (0x0053) - Publisher/Subscriber owner
//! - PID_ENTITY_VIRTUAL_GUID (0x8002) - Virtual GUID for multi-NIC
//! - PID_EXPECTS_VIRTUAL_HB (0x8009) - Virtual heartbeat flag
//! - PID_TYPE_CONSISTENCY (0x0074) - Type coercion policy
//! - PID_ENDPOINT_PROPERTY_CHANGE_EPOCH (0x8015) - Property versioning

use super::super::super::constants::{
    PID_DATA_REPRESENTATION, PID_ENDPOINT_GUID, PID_ENDPOINT_PROPERTY_CHANGE_EPOCH,
    PID_ENTITY_VIRTUAL_GUID, PID_EXPECTS_INLINE_QOS, PID_EXPECTS_VIRTUAL_HB, PID_GROUP_ENTITY_ID,
    PID_KEY_HASH, PID_PARTICIPANT_GUID, PID_PRODUCT_VERSION, PID_PROTOCOL_VERSION,
    PID_RECV_QUEUE_SIZE, PID_TOPIC_NAME, PID_TYPE_CONSISTENCY, PID_TYPE_NAME, PID_VENDOR_ID,
};
use super::super::super::types::ParseError;
use crate::core::discovery::GUID;

/// Write string parameter (topic name, type name).
///
/// Format: PID (u16) + length (u16) + str_len (u32) + string bytes + null terminator + padding
pub fn write_string_param(
    pid: u16,
    s: &str,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    let str_len = s.len();
    let str_with_null = str_len.checked_add(1).ok_or(ParseError::InvalidFormat)?;
    let payload_len = str_with_null
        .checked_add(4)
        .ok_or(ParseError::InvalidFormat)?;
    let aligned_payload_len = (payload_len + 3) & !3;
    if aligned_payload_len > usize::from(u16::MAX) {
        return Err(ParseError::InvalidFormat);
    }
    let param_len = u16::try_from(aligned_payload_len).map_err(|_| ParseError::InvalidFormat)?;
    let total_len = 4 + aligned_payload_len;

    if *offset + total_len > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&param_len.to_le_bytes());
    *offset += 4;

    let str_len_field = u32::try_from(str_with_null).map_err(|_| ParseError::InvalidFormat)?;
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

/// Write PID_PARTICIPANT_GUID (0x0050) - 16 bytes.
/// v110: FastDDS interop requirement - links endpoint to participant.
/// FastDDS EDPSimpleListeners validates participant exists before accepting endpoint.
pub fn write_participant_guid(
    participant_guid: &GUID,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 4 + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_PARTICIPANT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 16].copy_from_slice(&participant_guid.as_bytes());
    *offset += 16;
    Ok(())
}

/// Write PID_ENDPOINT_GUID (0x005a) - 16 bytes.
/// RTI expects this FIRST to identify the endpoint before parsing other PIDs.
pub fn write_endpoint_guid(
    endpoint_guid: &GUID,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 4 + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_ENDPOINT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 16].copy_from_slice(&endpoint_guid.as_bytes());
    *offset += 16;
    Ok(())
}

/// Write PID_KEY_HASH (0x0070) - 16 bytes.
/// FastDDS serializes this immediately after the endpoint GUID.
pub fn write_key_hash(
    endpoint_guid: &GUID,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 4 + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_KEY_HASH.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 16].copy_from_slice(&endpoint_guid.as_bytes());
    *offset += 16;
    Ok(())
}

/// Write PID_TOPIC_NAME (0x0005).
pub fn write_topic_name(
    topic_name: &str,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    write_string_param(PID_TOPIC_NAME, topic_name, buf, offset)
}

/// Write PID_TYPE_NAME (0x0007).
pub fn write_type_name(
    type_name: &str,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    write_string_param(PID_TYPE_NAME, type_name, buf, offset)
}

/// Write PID_PROTOCOL_VERSION (0x0015) - 4 bytes.
/// Format: major (u8) + minor (u8) + padding (2 bytes).
pub fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = 2; // major = 2
    buf[*offset + 5] = 3; // minor = 3 (RTPS v2.3)
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0; // padding
    *offset += 8;
    Ok(())
}

/// Write PID_VENDOR_ID (0x0016) - 4 bytes.
/// Format: vendor_id (u16 LE) + padding (2 bytes).
pub fn write_vendor_id(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_VENDOR_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..(*offset + 6)].copy_from_slice(&0x01AAu16.to_le_bytes()); // HDDS vendor ID
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0; // padding
    *offset += 8;
    Ok(())
}

/// Write PID_PRODUCT_VERSION (0x8000) - 4 bytes.
/// Format: major.minor.release.build (4 bytes).
/// RTI sends this in SEDP announcements (frame 30 in gold standard).
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_product_version(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_PRODUCT_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = 0x00; // major = 0
    buf[*offset + 5] = 0x02; // minor = 2 (HDDS v0.2.x)
    buf[*offset + 6] = 0x00; // release = 0
    buf[*offset + 7] = 0x00; // build = 0
    *offset += 8;
    Ok(())
}

/// Write PID_DATA_REPRESENTATION (0x0073) - 12 bytes.
/// Format: seq_len (u32) + data_rep_id (u16) + padding (u16) + compression_mask (u32).
///
/// NOTE: This is a legacy function used only by tests. Production code uses
/// dialect-specific encoders which decide XCDR1 vs XCDR2 automatically.
/// Default is XCDR1 (0x0000) for maximum compatibility.
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_data_representation(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_DATA_REPRESENTATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&12u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&1u32.to_le_bytes()); // sequence length = 1
                                                                        // Default to XCDR1 for compatibility. Dialect encoders handle XCDR2 when needed.
    let data_rep_id: u16 = 0x0000; // XCDR1
    buf[*offset + 8..*offset + 10].copy_from_slice(&data_rep_id.to_le_bytes());
    buf[*offset + 10..*offset + 12].copy_from_slice(&0u16.to_le_bytes()); // padding
    buf[*offset + 12..*offset + 16].copy_from_slice(&0x00000007u32.to_le_bytes());
    *offset += 16;
    Ok(())
}

/// Write PID_DATA_REPRESENTATION (0x0073) with XCDR2 support - 8 bytes.
/// Format: seq_len (u32) + data_rep_id (u16) + padding (u16).
///
/// This is a minimal version matching OpenDDS's format:
/// - Sequence length = 1
/// - Data representation = XCDR2 (0x0002)
/// - No compression mask (OpenDDS doesn't use it)
///
/// Required for OpenDDS interop: OpenDDS writer advertises XCDR2 and expects
/// the reader to also support XCDR2. Without this, OpenDDS won't match with
/// HDDS readers.
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_data_representation_xcdr2(
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_DATA_REPRESENTATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes()); // 8 bytes payload
    buf[*offset + 4..*offset + 8].copy_from_slice(&1u32.to_le_bytes()); // sequence length = 1
    let data_rep_id: u16 = 0x0002; // XCDR2_DATA_REPRESENTATION
    buf[*offset + 8..*offset + 10].copy_from_slice(&data_rep_id.to_le_bytes());
    buf[*offset + 10..*offset + 12].copy_from_slice(&0u16.to_le_bytes()); // padding
    *offset += 12;
    Ok(())
}

/// Write PID_DATA_REPRESENTATION (0x0073) with BOTH XCDR1 and XCDR2 - 12 bytes.
/// Format: seq_len (u32) + data_rep_id_1 (u16) + data_rep_id_2 (u16) + padding (4 bytes to align).
///
/// Advertises support for both XCDR1 (0x0000) and XCDR2 (0x0002) serialization formats.
/// This enables interop with:
/// - CycloneDDS: Uses XCDR1 by default
/// - OpenDDS: Uses XCDR2
/// - FastDDS: Supports both
/// - RTI: Supports both
///
/// CycloneDDS matching requires at least one common data representation between
/// writer and reader. By advertising both, HDDS can match with any vendor.
pub fn write_data_representation_both(
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    // Header (4) + seq_len (4) + 2 x data_rep_id (4) = 12 bytes total
    if *offset + 12 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_DATA_REPRESENTATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes()); // 8 bytes payload (seq_len + 2 reps)
    buf[*offset + 4..*offset + 8].copy_from_slice(&2u32.to_le_bytes()); // sequence length = 2
                                                                        // XCDR1 first (0x0000) - for CycloneDDS compatibility
    buf[*offset + 8..*offset + 10].copy_from_slice(&0x0000u16.to_le_bytes());
    // XCDR2 second (0x0002) - for OpenDDS compatibility
    buf[*offset + 10..*offset + 12].copy_from_slice(&0x0002u16.to_le_bytes());
    *offset += 12;
    Ok(())
}

/// Write PID_RECV_QUEUE_SIZE (0x0018) - 4 bytes.
/// Value: 0xffffffff (deprecated marker).
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_recv_queue_size(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_RECV_QUEUE_SIZE.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    *offset += 8;
    Ok(())
}

/// Write PID_GROUP_ENTITY_ID (0x0053) - 4 bytes.
/// Identifies the Publisher/Subscriber that owns this endpoint.
/// Format: 0x80000009 (Subscriber entity).
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_group_entity_id(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_GROUP_ENTITY_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0x80000009u32.to_le_bytes());
    *offset += 8;
    Ok(())
}

/// Write PID_EXPECTS_INLINE_QOS (0x0043) - 4 bytes.
/// FastDDS sets this false for builtin subscriptions.
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_expects_inline_qos(
    expect_inline_qos: bool,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_EXPECTS_INLINE_QOS.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&(expect_inline_qos as u32).to_le_bytes());
    *offset += 8;
    Ok(())
}

/// Write PID_ENTITY_VIRTUAL_GUID (0x8002) - 16 bytes.
/// RTI vendor-specific: Virtual GUID for endpoint (multi-NIC scenarios).
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_entity_virtual_guid(
    endpoint_guid: &GUID,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 4 + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_ENTITY_VIRTUAL_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 16].copy_from_slice(&endpoint_guid.as_bytes());
    *offset += 16;
    Ok(())
}

/// Write PID_EXPECTS_VIRTUAL_HB (0x8009) - 4 bytes.
/// RTI vendor-specific: Endpoint expects virtual heartbeats.
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_expects_virtual_hb(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_EXPECTS_VIRTUAL_HB.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // false
    *offset += 8;
    Ok(())
}

/// Write PID_TYPE_CONSISTENCY (0x0074) - 8 bytes.
/// XTypes v1.3 Sec.7.6.3.3.3: TypeConsistencyEnforcementQosPolicy.
/// Format: kind (u16) + ignore_sequence_bounds (u8) + ignore_string_bounds (u8) + padding (4 bytes).
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_type_consistency(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 4 + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_TYPE_CONSISTENCY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 2].copy_from_slice(&1u16.to_le_bytes()); // ALLOW_TYPE_COERCION
    buf[*offset + 2] = 0x01; // ignore_sequence_bounds = true
    buf[*offset + 3] = 0x01; // ignore_string_bounds = true
    buf[*offset + 4..*offset + 8].fill(0); // padding
    *offset += 8;
    Ok(())
}

/// Write PID_ENDPOINT_PROPERTY_CHANGE_EPOCH (0x8015) - 8 bytes.
/// RTI vendor-specific: Endpoint property change epoch (versioning).
/// Format: SequenceNumber_t (high32 + low32) - use 0:1 as default.
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_endpoint_property_change_epoch(
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 4 + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_ENDPOINT_PROPERTY_CHANGE_EPOCH.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&0u32.to_le_bytes()); // high = 0
    buf[*offset + 4..*offset + 8].copy_from_slice(&1u32.to_le_bytes()); // low = 1
    *offset += 8;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn string_param_lengths_are_4_byte_aligned() {
        let mut buf = [0u8; 64];
        let mut offset = 0;

        write_topic_name("TemperatureTopic", &mut buf, &mut offset).expect("write topic");

        let param_len = u16::from_le_bytes(buf[2..4].try_into().expect("param len bytes"));
        assert_eq!(param_len, 24);
        assert_eq!(param_len % 4, 0);
        assert_eq!(offset, usize::from(4 + param_len));

        let stored_len = u32::from_le_bytes(buf[4..8].try_into().expect("stored len bytes"));
        assert_eq!(stored_len, 17);

        assert_eq!(&buf[8..25], b"TemperatureTopic\0");
        assert_eq!(&buf[25..28], &[0u8; 3]);
    }
}

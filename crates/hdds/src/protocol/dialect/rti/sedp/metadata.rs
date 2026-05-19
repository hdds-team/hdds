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
    pub const PID_GROUP_ENTITY_ID: u16 = 0x0053;
    pub const PID_TYPE_CONSISTENCY: u16 = 0x0074;
}

/// HDDS vendor ID
const VENDOR_ID_HDDS: u16 = 0x01AA;

/// Write PID_ENDPOINT_GUID (0x005a) - 16 bytes
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

/// Write PID_PARTICIPANT_GUID (0x0050) - 16 bytes
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
    buf[*offset + 12..*offset + 16].copy_from_slice(&guid.entity_id);
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

/// Write PID_GROUP_ENTITY_ID (0x0053) - 4 bytes.
///
/// Identifies the Publisher or Subscriber that owns this endpoint per
/// RTPS v2.5 §9.3.2.1. Connext uses this to map endpoint-level PIDs
/// (`PID_COHERENT_SET`, `PID_PARTITION`, etc.) back to a known group when
/// the announcement comes from a non-RTI vendor.
///
/// EntityKind values per RTPS v2.5 §9.3.2.1 + observed RTI Connext usage:
/// * `0x08` = USER_DEFINED_PUBLISHER_GROUP
/// * `0x09` = USER_DEFINED_SUBSCRIBER_GROUP
///
/// `is_writer` distinguishes the two. We always pin entityKey to `0x000001`
/// (single publisher / subscriber per participant), matching the RTI
/// observed `0x00000108` / `0x00000109` pattern. EntityId is encoded as a
/// little-endian u32 of [entityKey:24][entityKind:8].
pub fn write_group_entity_id(
    is_writer: bool,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    let entity_kind: u8 = if is_writer { 0x08 } else { 0x09 };
    let entity_id_bytes = [0x00, 0x00, 0x01, entity_kind];
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_GROUP_ENTITY_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&entity_id_bytes);
    *offset += 8;
    Ok(())
}

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

/// Write PID_DATA_REPRESENTATION (0x0073) from the offered QoS.
///
/// Honors `qos.data_representation` exactly:
/// - If the list is non-empty, writes those representation IDs in order.
/// - If the list is empty (or no QoS provided), advertises XCDR2 (0x0002) only,
///   matching the writer's encoding (HDDS has no XCDR1 encode path).
///
/// Layout: `seq_len (u32) + N * u16 + pad` aligned to 4 bytes.
pub fn write_data_representation(
    qos: Option<&crate::protocol::dialect::QosProfile>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    // Build the representation list
    let reprs: &[u16] = match qos {
        Some(q) if !q.data_representation.is_empty() => &q.data_representation,
        _ => &[0x0002u16],
    };

    let seq_len = reprs.len() as u32;
    let payload_len = 4 + reprs.len() * 2; // seq_len(4) + N * u16
    let padded_len = (payload_len + 3) & !3;
    if *offset + 4 + padded_len > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&0x0073u16.to_le_bytes()); // PID_DATA_REPRESENTATION
    buf[*offset + 2..*offset + 4].copy_from_slice(&(padded_len as u16).to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&seq_len.to_le_bytes());
    let mut pos = *offset + 8;
    for &r in reprs {
        buf[pos..pos + 2].copy_from_slice(&r.to_le_bytes());
        pos += 2;
    }
    while pos < *offset + 4 + padded_len {
        buf[pos] = 0;
        pos += 1;
    }
    *offset = pos;

    Ok(())
}

/// Write PID_TYPE_CONSISTENCY_ENFORCEMENT (0x0074) - 8 byte payload.
///
/// Encodes a TypeConsistencyEnforcementQosPolicy per DDS-XTypes v1.3
/// (OMG formal/2020-02-04) section 7.6.3.5. The IDL enum in that section
/// orders the kind values as:
///
/// ```text
/// @bit_bound(16)
/// enum TypeConsistencyKind {
///     DISALLOW_TYPE_COERCION, // = 0 (strict — pre-XTypes default)
///     ALLOW_TYPE_COERCION     // = 1 (permissive — XTypes default)
/// };
///
/// struct TypeConsistencyEnforcementQosPolicy {
///     TypeConsistencyKind kind;
///     boolean ignore_sequence_bounds;
///     boolean ignore_string_bounds;
///     boolean ignore_member_names;
///     boolean prevent_type_widening;
///     boolean force_type_validation;
/// };
/// ```
///
/// Wire layout (8 bytes, LE): `kind(u16) ignore_seq(u8) ignore_str(u8)
/// ignore_names(u8) prevent_widening(u8) force_validation(u8) padding(u8)`.
///
/// Emit the permissive interop default used by FastDDS and the HDDS
/// dormant dialects (`discovery/sedp/build/metadata.rs` +
/// `opendds/sedp/metadata.rs`): `ALLOW_TYPE_COERCION` with
/// `ignore_sequence_bounds = ignore_string_bounds = true`. Hex: `01 00
/// 01 01 00 00 00 00`. Relaxing sequence/string bounds avoids matching
/// failures when peers advertise nominally-equivalent bounded types
/// with slightly different caps (common in real-world shape_main
/// scenarios); the remaining flags stay at their strict defaults.
pub fn write_type_consistency(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TYPE_CONSISTENCY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    // TypeConsistencyEnforcement per DDS-XTypes 1.3 §7.6.3.5, encoded to
    // the FastDDS-interoperable permissive profile `01 00 01 01 00 00 00 00`:
    //   kind                    = ALLOW_TYPE_COERCION (u16 LE = 0x0001)
    //   ignore_sequence_bounds  = true
    //   ignore_string_bounds    = true
    //   ignore_member_names     = false
    //   prevent_type_widening   = false
    //   force_type_validation   = false
    //   (1 byte padding to reach the declared 8-byte payload length)
    buf[*offset + 4..*offset + 12]
        .copy_from_slice(&[0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00]);
    *offset += 12;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock the wire payload for PID_TYPE_CONSISTENCY_ENFORCEMENT.
    ///
    /// Expected bytes: `74 00 08 00 01 00 01 01 00 00 00 00`.
    /// - `74 00`      = PID_TYPE_CONSISTENCY_ENFORCEMENT (LE u16 = 0x0074)
    /// - `08 00`      = payload length (LE u16 = 8)
    /// - `01 00`      = `kind` = ALLOW_TYPE_COERCION (DDS-XTypes 1.3 §7.6.3.5 enum value 1)
    /// - `01`         = `ignore_sequence_bounds` = true
    /// - `01`         = `ignore_string_bounds` = true
    /// - `00`         = `ignore_member_names` = false
    /// - `00`         = `prevent_type_widening` = false
    /// - `00`         = `force_type_validation` = false
    /// - `00`         = padding
    ///
    /// If this test breaks, check whether the change is an intentional
    /// TypeConsistencyEnforcement policy change (re-read the spec to
    /// confirm the `kind` enum ordering) or an accidental drift.
    #[test]
    fn write_type_consistency_emits_permissive_profile() {
        let mut buf = [0xFFu8; 16];
        let mut offset = 0usize;

        write_type_consistency(&mut buf, &mut offset).expect("encode must succeed");

        assert_eq!(offset, 12, "PID header (4 bytes) + payload (8 bytes)");
        assert_eq!(
            &buf[..12],
            &[0x74, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00],
        );
    }

    /// Sanity check: bytes 4..6 decode as a `u16` kind field with value 1
    /// (ALLOW_TYPE_COERCION). Guards against byte-order confusion because
    /// `0x00 01` and `0x01 00` both look innocuous in a static array but
    /// decode to different enum values.
    #[test]
    fn write_type_consistency_kind_field_is_allow() {
        let mut buf = [0u8; 12];
        let mut offset = 0usize;
        write_type_consistency(&mut buf, &mut offset).expect("encode must succeed");

        let kind = u16::from_le_bytes([buf[4], buf[5]]);
        assert_eq!(kind, 1, "kind must decode as ALLOW_TYPE_COERCION (= 1)");
    }

    #[test]
    fn write_type_consistency_rejects_buffer_too_small() {
        let mut buf = [0u8; 11];
        let mut offset = 0usize;

        let err = write_type_consistency(&mut buf, &mut offset)
            .expect_err("must fail when buffer is smaller than 12 bytes");
        assert!(matches!(err, EncodeError::BufferTooSmall));
        assert_eq!(offset, 0, "offset must not advance on failure");
    }
}

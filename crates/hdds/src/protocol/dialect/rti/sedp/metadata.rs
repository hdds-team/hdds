// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI dialect SEDP Metadata PID Writers
//!
//!
//! Standard PIDs this dialect writes:
//! - PID_ENDPOINT_GUID (0x005a)
//! - PID_PARTICIPANT_GUID (0x0050)
//! - PID_KEY_HASH (0x0070) - always sent
//! - PID_TOPIC_NAME (0x0005)
//! - PID_TYPE_NAME (0x0007)
//! - PID_PROTOCOL_VERSION (0x0015) - MANDATORY
//! - PID_VENDOR_ID (0x0016)
//! - PID_TYPE_CONSISTENCY (0x0074) - type matching (DDS-XTypes 1.3 Sec.7.6.3.4)
//!
//! Note: vendor-specific PIDs (0x8000+) owned by vendor id 0x0101 are NOT sent
//! by HDDS: a vendor-range PID takes its meaning from the sender's vendor id
//! (DDSI-RTPS 2.5 Sec.9.4.2.11, Table 9.6).

use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};
use crate::protocol::dialect::common::{cdr_length, parameter_length};
use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;
use crate::protocol::discovery::types::TypeConsistencyEnforcement;

/// PID constants (standard PIDs; no vendor-specific PIDs are written)
mod pids {
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_ENDPOINT_GUID: u16 = 0x005a;
    pub const PID_KEY_HASH: u16 = 0x0070;
    pub const PID_TOPIC_NAME: u16 = 0x0005;
    pub const PID_TYPE_NAME: u16 = 0x0007;
    pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
    pub const PID_VENDOR_ID: u16 = 0x0016;
    pub const PID_EXPECTS_INLINE_QOS: u16 = 0x0043;
    pub const PID_GROUP_GUID: u16 = 0x0052;
    pub const PID_GROUP_ENTITY_ID: u16 = 0x0053;
    pub const PID_TYPE_CONSISTENCY: u16 = 0x0074;
}

/// HDDS vendor ID (official DDS Foundation assignment, 2026-07)
const VENDOR_ID_HDDS: u16 = 0x011A;

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
/// Always sent by this dialect - uses endpoint GUID as key hash
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

    // parameterLength is a u16 and the CDR string prefix a u32: a string
    // that fits neither is refused here, before anything is written.
    let param_len = parameter_length(aligned_payload_len)?;
    let str_len_field = cdr_length(str_with_null)?;

    let total_len = 4 + aligned_payload_len;
    if *offset + total_len > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&param_len.to_le_bytes());
    *offset += 4;

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
/// Writes the RTPS protocol version from `RTPS_VERSION_MAJOR/MINOR`.
pub fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = RTPS_VERSION_MAJOR; // major = 2
    buf[*offset + 5] = RTPS_VERSION_MINOR; // minor = 4 (RTPS v2.4)
    buf[*offset + 6] = 0;
    buf[*offset + 7] = 0;
    *offset += 8;

    Ok(())
}

/// Write PID_VENDOR_ID (0x0016) - 4 bytes
///
/// RTPS spec: VendorId is 2 bytes in big-endian (network order).
/// HDDS vendor ID = 0x011A -> bytes [0x01, 0x1A]
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

// NOTE: PID_PRODUCT_VERSION (0x8000) is vendor-specific to vendor id 0x0101.
// HDDS as vendor 0x011A does NOT send another vendor's PIDs >= 0x8000.

/// Write PID_GROUP_ENTITY_ID (0x0053) - 4 bytes.
///
/// Identifies the Publisher or Subscriber that owns this endpoint per
/// RTPS v2.5 Sec.9.3.2.1, so a receiver can map endpoint-level PIDs
/// (`PID_COHERENT_SET`, `PID_PARTITION`, etc.) back to a known group.
///
/// EntityKind values per RTPS v2.5 Sec.9.3.2.1:
/// * `0x08` = USER_DEFINED_PUBLISHER_GROUP
/// * `0x09` = USER_DEFINED_SUBSCRIBER_GROUP
///
/// `group` is the endpoint's own Publisher or Subscriber
/// (`SedpEndpointData::group_entity_id`): each Publisher of a participant
/// has its own key.
/// Write PID_GROUP_GUID (0x0052) - 16 bytes.
/// Full GUID of the Publisher/Subscriber group owning this endpoint:
/// participant guidPrefix + the same group entityId convention as
/// PID_GROUP_ENTITY_ID below. A GROUP-presentation subscriber needs it to
/// associate all writers of one remote Publisher before it can collate
/// group-coherent/ordered samples.
pub fn write_group_guid(
    guid: &Guid,
    group: [u8; 4],
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_GROUP_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 12].copy_from_slice(&guid.prefix);
    buf[*offset + 12..*offset + 16].copy_from_slice(&group);
    *offset += 16;
    Ok(())
}

pub fn write_group_entity_id(
    group: [u8; 4],
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    let entity_id_bytes = group;
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

// NOTE: vendor-specific PIDs (0x8000+) owned by vendor id 0x0101 are NOT sent
// by HDDS (vendor 0x011A): a vendor-range PID takes its meaning from the
// sender's vendor id (DDSI-RTPS 2.5 Sec.9.4.2.11, Table 9.6).

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

    // `reprs` comes from user QoS: both lengths are converted, not assumed small.
    let seq_len = cdr_length(reprs.len())?;
    let payload_len = 4 + reprs.len() * 2; // seq_len(4) + N * u16
    let padded_len = (payload_len + 3) & !3;
    let param_len = parameter_length(padded_len)?;
    if *offset + 4 + padded_len > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&0x0073u16.to_le_bytes()); // PID_DATA_REPRESENTATION
    buf[*offset + 2..*offset + 4].copy_from_slice(&param_len.to_le_bytes());
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
///     DISALLOW_TYPE_COERCION, // = 0 (strict -- pre-XTypes default)
///     ALLOW_TYPE_COERCION     // = 1 (permissive -- XTypes default)
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
/// `policy` is the local endpoint's QoS. When `None`, falls back to the
/// XTypes spec default (ALLOW_TYPE_COERCION, ignore_sequence_bounds=true,
/// ignore_string_bounds=true) -- the permissive profile used by HDDS
/// endpoints that have not set a custom policy.
pub fn write_type_consistency(
    policy: Option<&TypeConsistencyEnforcement>,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // Resolve effective policy: use caller-supplied value or the permissive
    // wire default (ignore_member_names=true matches the matcher default_policy).
    let permissive_default = TypeConsistencyEnforcement {
        ignore_member_names: true,
        ..TypeConsistencyEnforcement::default()
    };
    let p = policy.unwrap_or(&permissive_default);

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TYPE_CONSISTENCY.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    // 8-byte payload per DDS-XTypes v1.3 sec. 7.6.3.5 (LE):
    //   kind                   u16  (2 bytes)
    //   ignore_sequence_bounds u8   (1 byte)
    //   ignore_string_bounds   u8   (1 byte)
    //   ignore_member_names    u8   (1 byte)
    //   prevent_type_widening  u8   (1 byte)
    //   force_type_validation  u8   (1 byte)
    //   padding                u8   (1 byte, always 0)
    buf[*offset + 4..*offset + 6].copy_from_slice(&p.kind.to_le_bytes());
    buf[*offset + 6] = u8::from(p.ignore_sequence_bounds);
    buf[*offset + 7] = u8::from(p.ignore_string_bounds);
    buf[*offset + 8] = u8::from(p.ignore_member_names);
    buf[*offset + 9] = u8::from(p.prevent_type_widening);
    buf[*offset + 10] = u8::from(p.force_type_validation);
    buf[*offset + 11] = 0x00; // padding
    *offset += 12;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock the wire payload for PID_TYPE_CONSISTENCY_ENFORCEMENT.
    ///
    /// Expected bytes: `74 00 08 00 01 00 01 01 01 00 00 00`.
    /// - `74 00`      = PID_TYPE_CONSISTENCY_ENFORCEMENT (LE u16 = 0x0074)
    /// - `08 00`      = payload length (LE u16 = 8)
    /// - `01 00`      = `kind` = ALLOW_TYPE_COERCION (DDS-XTypes 1.3 sec. 7.6.3.5 enum value 1)
    /// - `01`         = `ignore_sequence_bounds` = true
    /// - `01`         = `ignore_string_bounds` = true
    /// - `01`         = `ignore_member_names` = true (permissive default)
    /// - `00`         = `prevent_type_widening` = false
    /// - `00`         = `force_type_validation` = false
    /// - `00`         = padding
    ///
    /// If this test breaks, check whether the change is an intentional
    /// TypeConsistencyEnforcement policy change (re-read the spec to
    /// confirm the `kind` enum ordering) or an accidental drift.
    #[test]
    fn write_type_consistency_emits_permissive_profile() -> Result<(), EncodeError> {
        let mut buf = [0xFFu8; 16];
        let mut offset = 0usize;

        write_type_consistency(None, &mut buf, &mut offset)?;

        assert_eq!(offset, 12, "PID header (4 bytes) + payload (8 bytes)");
        assert_eq!(
            &buf[..12],
            &[0x74, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00],
        );
        Ok(())
    }

    /// Sanity check: bytes 4..6 decode as a `u16` kind field with value 1
    /// (ALLOW_TYPE_COERCION). Guards against byte-order confusion because
    /// `0x00 01` and `0x01 00` both look innocuous in a static array but
    /// decode to different enum values.
    #[test]
    fn write_type_consistency_kind_field_is_allow() -> Result<(), EncodeError> {
        let mut buf = [0u8; 12];
        let mut offset = 0usize;
        write_type_consistency(None, &mut buf, &mut offset)?;

        let kind = u16::from_le_bytes([buf[4], buf[5]]);
        assert_eq!(kind, 1, "kind must decode as ALLOW_TYPE_COERCION (= 1)");
        Ok(())
    }

    #[test]
    fn write_type_consistency_rejects_buffer_too_small() {
        let mut buf = [0u8; 11];
        let mut offset = 0usize;

        let err = write_type_consistency(None, &mut buf, &mut offset)
            .expect_err("must fail when buffer is smaller than 12 bytes");
        assert!(matches!(err, EncodeError::BufferTooSmall));
        assert_eq!(offset, 0, "offset must not advance on failure");
    }

    /// Strict policy (DISALLOW_TYPE_COERCION + force_type_validation) is emitted
    /// faithfully -- the peer must see the real policy, not a hardcoded permissive one.
    #[test]
    fn write_type_consistency_strict_policy_round_trips() -> Result<(), EncodeError> {
        use crate::protocol::discovery::types::TypeConsistencyEnforcement;

        let policy = TypeConsistencyEnforcement {
            kind: 0, // DISALLOW_TYPE_COERCION
            ignore_sequence_bounds: false,
            ignore_string_bounds: false,
            ignore_member_names: false,
            prevent_type_widening: true,
            force_type_validation: true,
        };

        let mut buf = [0u8; 16];
        let mut offset = 0usize;
        write_type_consistency(Some(&policy), &mut buf, &mut offset)?;

        assert_eq!(offset, 12);
        // kind = 0 (DISALLOW) LE
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 0);
        // ignore_sequence_bounds = false
        assert_eq!(buf[6], 0);
        // ignore_string_bounds = false
        assert_eq!(buf[7], 0);
        // ignore_member_names = false
        assert_eq!(buf[8], 0);
        // prevent_type_widening = true
        assert_eq!(buf[9], 1);
        // force_type_validation = true
        assert_eq!(buf[10], 1);
        // padding = 0
        assert_eq!(buf[11], 0);
        Ok(())
    }
}

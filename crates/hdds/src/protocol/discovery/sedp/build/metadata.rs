// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP Metadata PID Writers
//!
//! Handles encoding of endpoint identification and metadata PIDs:
//! - PID_PARTICIPANT_GUID (0x0050) - Participant identifier (16 bytes, v110)
//! - PID_ENDPOINT_GUID (0x005a) - Endpoint identifier (16 bytes)
//! - PID_TOPIC_NAME (0x0005) - Topic name string
//! - PID_TYPE_NAME (0x0007) - Type name string
//! - PID_PROTOCOL_VERSION (0x0015) - RTPS version (major.minor)
//! - PID_VENDOR_ID (0x0016) - Vendor identifier (0x011A = HDDS)
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
    PID_GROUP_GUID, PID_HDDS_SHM_CAPABILITY, PID_KEY_HASH, PID_PARTICIPANT_GUID,
    PID_PRODUCT_VERSION, PID_PROTOCOL_VERSION, PID_RECV_QUEUE_SIZE, PID_TOPIC_NAME,
    PID_TYPE_CONSISTENCY, PID_TYPE_NAME, PID_USER_DATA, PID_VENDOR_ID,
};
use super::super::super::types::{parameter_length, wire_u32, ParseError};
use crate::core::discovery::GUID;
use crate::core::rtps_constants::{RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR};

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
/// links the endpoint to its owning participant, so a receiver can
/// attach the endpoint to the participant it discovered through SPDP.
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
/// HDDS writes it FIRST so the endpoint is identified before the other PIDs.
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
/// Written immediately after the endpoint GUID.
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

/// Write PID_USER_DATA (0x002c), the application's `UserDataQosPolicy`
/// (DDS-RTPS Sec.9.6.2.2.1), as a length-prefixed, null-terminated string --
/// the same encoding `write_string_param` already uses for PID_TOPIC_NAME /
/// PID_TYPE_NAME and that `sedp/parse.rs::parse_user_data_parameter` expects
/// (4-byte octet-sequence length, bytes, trailing NUL trimmed on parse).
///
/// This carries ONLY what the application set via `QoS::user_data`; it must
/// never carry an HDDS-internal capability hint (see
/// `PID_HDDS_SHM_CAPABILITY` / `write_hdds_shm_capability` below for that).
/// `build_sedp_with_options` calls this whenever `sedp_data.user_data` is
/// `Some`, for every dialect that routes through it.
pub fn write_user_data(
    user_data: &str,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    write_string_param(PID_USER_DATA, user_data, buf, offset)
}

/// Write `PID_HDDS_SHM_CAPABILITY` (0x8031), the HDDS vendor-specific SHM
/// transport capability hint (e.g. "shm=1;host_id=XXXXXXXX;v=1"). Same
/// string encoding as `write_user_data`; the only difference is the PID.
///
/// Only the HDDS dialect encoder ever populates
/// `LegacySedpData::shm_capability` with `Some` (see
/// `dialect::mod::SedpEndpointData::hdds_shm_capability` and
/// `dialect::hdds::HddsEncoder::build_sedp`); every other dialect keeps it at
/// `None`, so `build_sedp_with_options` never reaches this call for a
/// foreign-dialect frame. See `PID_HDDS_SHM_CAPABILITY`'s doc for why this
/// must never be PID_USER_DATA.
pub fn write_hdds_shm_capability(
    hint: &str,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    write_string_param(PID_HDDS_SHM_CAPABILITY, hint, buf, offset)
}

/// Write PID_PROTOCOL_VERSION (0x0015) - 4 bytes.
/// Format: major (u8) + minor (u8) + padding (2 bytes).
pub fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = RTPS_VERSION_MAJOR; // major = 2
    buf[*offset + 5] = RTPS_VERSION_MINOR; // minor = 4 (RTPS v2.4)
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0; // padding
    *offset += 8;
    Ok(())
}

/// Write PID_VENDOR_ID (0x0016) - 4 bytes.
/// Format: VendorId_t (octet[2]) + padding (2 bytes).
///
/// VendorId_t is an octet array (RTPS v2.5 Sec.8.3.3.1 / Table 9.1), NOT a
/// 16-bit integer, so it must be written byte-for-byte in declared order
/// (0x01, 0x1A) -- matching the RTPS message header vendorId. Writing it via
/// `0x011Au16.to_le_bytes()` would reverse it to (0x1A, 0x01) on little-endian
/// hosts, which strict receivers reject when validating the DiscoveredWriterData.
pub fn write_vendor_id(buf: &mut [u8], offset: &mut usize) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_VENDOR_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = 0x01; // HDDS VendorId_t byte 0
    buf[*offset + 5] = 0x1A; // HDDS VendorId_t byte 1
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0; // padding
    *offset += 8;
    Ok(())
}

/// Write PID_PRODUCT_VERSION (0x8000) - 4 bytes.
/// Format: major.minor.release.build (4 bytes).
/// Vendor-range PID owned by vendor id 0x0101; HDDS does not emit it.
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
    buf[*offset + 12..*offset + 16].copy_from_slice(&0x0000_0007u32.to_le_bytes());
    *offset += 16;
    Ok(())
}

/// Write PID_DATA_REPRESENTATION (0x0073) with XCDR2 support - 8 bytes.
/// Format: seq_len (u32) + data_rep_id (u16) + padding (u16).
///
/// Minimal form:
/// - Sequence length = 1
/// - Data representation = XCDR2 (0x0002)
/// - No compression mask
///
/// A reader matches a writer only if the reader's list contains the
/// writer's representation (DDS-XTypes v1.3 Sec.7.6.3.1.1), so an HDDS reader
/// must list XCDR2 to match a writer that offers XCDR2.
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
///
/// Matching requires the writer's representation to appear in the reader's
/// list (DDS-XTypes v1.3 Sec.7.6.3.1.1). By advertising both, HDDS matches a
/// peer whichever of the two it uses.
///
/// Currently uncalled: the SEDP advertising path picks a single representation
/// per writer at match time. This helper will be activated once the
/// `DataWriter` runtime dispatches the encoded form from the QoS-negotiated
/// `data_representation` rather than hardcoding it.
#[allow(dead_code)]
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
                                                                        // XCDR1 first (0x0000)
    buf[*offset + 8..*offset + 10].copy_from_slice(&0x0000u16.to_le_bytes());
    // XCDR2 second (0x0002)
    buf[*offset + 10..*offset + 12].copy_from_slice(&0x0002u16.to_le_bytes());
    *offset += 12;
    Ok(())
}

/// Write PID_DATA_REPRESENTATION (0x0073) from a list of representation IDs.
/// Encodes exactly the representations specified in the QoS.
pub fn write_data_representation_list(
    reprs: &[u16],
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    // `reprs` comes from user QoS: both lengths are converted, not assumed small.
    let seq_len = wire_u32(reprs.len())?;
    let payload_len = 4 + reprs.len() * 2; // seq_len(4) + N * u16
                                           // Pad to 4-byte alignment
    let padded_len = (payload_len + 3) & !3;
    let param_len = parameter_length(padded_len)?;
    if *offset + 4 + padded_len > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_DATA_REPRESENTATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&param_len.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&seq_len.to_le_bytes());
    let mut pos = *offset + 8;
    for &r in reprs {
        buf[pos..pos + 2].copy_from_slice(&r.to_le_bytes());
        pos += 2;
    }
    // Zero-fill padding
    while pos < *offset + 4 + padded_len {
        buf[pos] = 0;
        pos += 1;
    }
    *offset = pos;
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
    buf[*offset + 4..*offset + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    *offset += 8;
    Ok(())
}

/// The group of an endpoint announced with none: a Subscriber group
/// (EntityKind 0x09, RTPS v2.5 Sec.9.3.1.2) with key 0x000001 for a reader,
/// a Publisher group (0x08) for a writer. A writer of HDDS always names its
/// own Publisher (`SedpData::group_entity_id`); readers do not have one yet.
#[must_use]
pub fn default_group_entity_id(is_writer: bool) -> [u8; 4] {
    [0x00, 0x00, 0x01, if is_writer { 0x08 } else { 0x09 }]
}

/// Write PID_GROUP_ENTITY_ID (0x0053) - 4 bytes: `group`, the EntityId of
/// the Publisher/Subscriber that owns this endpoint (EntityKind 0x08 for a
/// Publisher, 0x09 for a Subscriber, RTPS v2.5 Sec.9.3.1.2). Strict peers
/// key their group-coherent bookkeeping on this value; two Publishers of
/// one participant name two groups.
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_group_entity_id(
    group: [u8; 4],
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_GROUP_ENTITY_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&group);
    *offset += 8;
    Ok(())
}

/// Write PID_GROUP_GUID (0x0052) - 16 bytes.
/// Full GUID of the Publisher/Subscriber group that owns this endpoint:
/// participant guidPrefix + `group` (as PID_GROUP_ENTITY_ID above). Strict
/// peers use it to associate all writers of one Publisher for
/// GROUP-presentation coherent/ordered delivery (RTPS v2.5 Sec.8.7.5,
/// `WriterProxy::remoteGroupGuid`).
#[allow(dead_code)] // Public API for SEDP encoding
pub fn write_group_guid(
    endpoint_guid: &[u8; 16],
    group: [u8; 4],
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 20 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&PID_GROUP_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    buf[*offset + 4..*offset + 16].copy_from_slice(&endpoint_guid[..12]);
    buf[*offset + 16..*offset + 20].copy_from_slice(&group);
    *offset += 20;
    Ok(())
}

/// Write PID_EXPECTS_INLINE_QOS (0x0043) - 4 bytes.
/// HDDS writes false: its readers do not require inline QoS.
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
/// Vendor 0x0101 vendor-specific PID: Virtual GUID for endpoint (multi-NIC scenarios).
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
/// Vendor 0x0101 vendor-specific PID: Endpoint expects virtual heartbeats.
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
/// Vendor 0x0101 vendor-specific PID: Endpoint property change epoch (versioning).
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

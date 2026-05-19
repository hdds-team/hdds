// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP Builder - CDR encoding of SEDP endpoint discovery messages
//!
//! Handles building SEDP discovery announcement packets with:
//! - Endpoint metadata (topic, type, GUID)
//! - QoS policies (reliability, durability, history)
//! - Type information (TypeObject CDR2 payload)
//! - Locator announcements
//! - Vendor-specific PIDs for RTI compatibility
//!
//! # Module Organization
//! - `metadata` - Endpoint identification PIDs (GUID, topic, type, versions)
//! - `qos` - QoS policy PIDs (reliability, durability, history, etc.)
//! - `locators` - Network locator PIDs (unicast, multicast)

mod locators;
mod metadata;
/// QoS PID serialization for SEDP endpoint discovery.
pub mod qos;
mod type_information;

use crate::protocol::discovery::constants::{PID_SENTINEL, PID_TYPE_OBJECT};
use crate::protocol::discovery::types::{ParseError, SedpData};
use crate::xtypes::CompleteTypeObject;
use crate::Cdr2Encode;
use std::convert::TryFrom;

/// Build SEDP discovery announcement packet.
///
/// # Arguments
/// - `sedp_data`: Endpoint metadata to encode (topic name, type name, endpoint GUID, optional TypeObject).
/// - `buf`: Destination buffer that receives the encoded parameter list.
///
/// # Returns
/// Number of bytes copied into `buf`.
///
/// # Errors
/// - `ParseError::BufferTooSmall` if the provided buffer cannot hold the encoding.
/// - `ParseError::EncodingError` when the TypeObject CDR2 encoding fails.
/// - `ParseError::InvalidFormat` for values that exceed RTPS size limits.
///
/// # PID Write Order
/// The order of PID writes is CRITICAL for RTI compatibility. Do not reorder without careful testing.
/// This sequence matches the RTI gold standard (frame 30 in reference captures):
///
/// 1. CDR encapsulation header (0x0003 = PL_CDR_LE)
/// 2. PID_ENDPOINT_GUID - RTI requires this FIRST for endpoint identification
/// 3. PID_TOPIC_NAME, PID_TYPE_NAME - String parameters
/// 4. PID_PROTOCOL_VERSION, PID_VENDOR_ID, PID_PRODUCT_VERSION - Version metadata
/// 5. PID_DATA_REPRESENTATION, PID_RECV_QUEUE_SIZE - Data format info
/// 6. PID_GROUP_ENTITY_ID - Publisher/Subscriber ownership
/// 7. PID_ENTITY_VIRTUAL_GUID, PID_EXPECTS_VIRTUAL_HB - RTI vendor PIDs
/// 8. PID_TYPE_CONSISTENCY, PID_ENDPOINT_PROPERTY_CHANGE_EPOCH - XTypes compatibility
/// 9. QoS PIDs - RELIABILITY, DURABILITY, HISTORY, DEADLINE, OWNERSHIP, LIVELINESS, etc.
/// 10. PID_UNICAST_LOCATOR - Network locators
/// 11. PID_TYPE_OBJECT - TypeObject CDR2 (if present)
/// 12. PID_SENTINEL - Terminator
pub fn build_sedp(sedp_data: &SedpData, buf: &mut [u8]) -> Result<usize, ParseError> {
    let mut offset = 0;
    // NOTE: This legacy builder is only used by tests now. Production code uses
    // build_sedp_for_dialect() with dialect-specific encoders.
    // interop_minimal mode is no longer needed - dialect encoders handle this.
    let interop_minimal = false;

    // CDR encapsulation header (ALWAYS big-endian per CDR spec)
    // 0x0003 = PL_CDR_LE (Parameter List, Little-Endian data)
    if buf.len() < 4 {
        return Err(ParseError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset += 4;

    // ===== METADATA SECTION =====
    // FastDDS expects PID_ENDPOINT_GUID before PID_PARTICIPANT_GUID when parsing SEDP parameter
    // lists (FASTDDS_DISCOVERY_INDEX.md:L95-L101 + ReaderProxyData.cpp:L432-L512). Matching that
    // ordering prevents FastDDS from discarding the endpoint announcement.
    metadata::write_endpoint_guid(&sedp_data.endpoint_guid, buf, &mut offset)?;
    metadata::write_participant_guid(&sedp_data.participant_guid, buf, &mut offset)?;
    if !interop_minimal {
        metadata::write_key_hash(&sedp_data.endpoint_guid, buf, &mut offset)?;
    }

    // String parameters
    metadata::write_topic_name(&sedp_data.topic_name, buf, &mut offset)?;
    metadata::write_type_name(&sedp_data.type_name, buf, &mut offset)?;

    // Version metadata (standard PIDs only)
    metadata::write_protocol_version(buf, &mut offset)?;
    metadata::write_vendor_id(buf, &mut offset)?;
    // NOTE: Removed PID_PRODUCT_VERSION (0x8000) - RTI rejects vendor PIDs from non-RTI vendors
    // metadata::write_product_version(buf, &mut offset)?;

    // Data representation - write from QoS if specified, otherwise advertise XCDR2 only.
    // HDDS serializes XCDR2 exclusively (no encode_cdr1 path), so advertising XCDR1
    // would be a lie that RTI Connext catches and reports as INCOMPATIBLE_QOS policy 23.
    if let Some(ref qos) = sedp_data.qos {
        if !qos.data_representation.is_empty() {
            metadata::write_data_representation_list(&qos.data_representation, buf, &mut offset)?;
        } else {
            metadata::write_data_representation_xcdr2(buf, &mut offset)?;
        }
    } else {
        metadata::write_data_representation_xcdr2(buf, &mut offset)?;
    }

    // Additional metadata (commented out for minimal profile)
    // NOTE: Removed vendor PIDs (0x8002, 0x8009) - RTI rejects these from non-RTI vendors
    // PID_GROUP_ENTITY_ID (0x0053) emitted unconditionally per RTPS v2.5 §9.3.2.1
    // so peers can associate endpoint-level PIDs (PID_COHERENT_SET,
    // PID_PARTITION) with the announcing publisher / subscriber group.
    metadata::write_group_entity_id(buf, &mut offset)?;
    // if !interop_minimal {
    //     metadata::write_recv_queue_size(buf, &mut offset)?;
    //     metadata::write_expects_inline_qos(false, buf, &mut offset)?;
    //     metadata::write_entity_virtual_guid(&sedp_data.endpoint_guid, buf, &mut offset)?;  // 0x8002
    //     metadata::write_expects_virtual_hb(buf, &mut offset)?;  // 0x8009
    // }

    // PID_TYPE_CONSISTENCY remains intentionally unsent: it would advertise
    // a `TypeConsistencyEnforcementQos` policy that we do not currently
    // honour at runtime, and FastDDS readers log an error if the QoS is
    // present without an accompanying matched-type-information validation
    // path. The actual TypeInformation now ships via PID_TYPE_INFORMATION
    // (see TYPE OBJECT / TYPE INFORMATION SECTION below).
    // PID_ENDPOINT_PROPERTY_CHANGE_EPOCH (0x8015) is an RTI vendor PID and
    // remains unsent.

    // ===== LOCATORS SECTION =====
    locators::write_unicast_locators(&sedp_data.unicast_locators, buf, &mut offset)?;

    // ===== QOS SECTION =====
    // Core QoS policies (order matches RTI frame 30)
    qos::write_reliability(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_durability(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_durability_service(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_history(sedp_data.qos.as_ref(), buf, &mut offset)?;

    // Additional QoS policies
    qos::write_deadline(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_lifespan(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_ownership(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_ownership_strength(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_liveliness(buf, &mut offset)?;
    qos::write_time_based_filter(buf, &mut offset)?;
    qos::write_partition(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_resource_limits(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_presentation(sedp_data.qos.as_ref(), buf, &mut offset)?;

    // ===== TYPE OBJECT / TYPE INFORMATION SECTION =====
    // PID_TYPE_OBJECT (0x0072) - CDR2-encoded CompleteTypeObject
    if let Some(ref type_obj) = sedp_data.type_object {
        write_type_object(type_obj, buf, &mut offset)?;
        // PID_TYPE_INFORMATION (0x0075) per DDS-XTypes v1.3 §7.6.3.2.
        // Cross-vendor readers (Fast DDS 3.x in particular) consult this
        // PID for type-identifier matching alongside PID_TYPE_OBJECT.
        // Soft-skip when the type cannot derive a `MinimalTypeObject`
        // (non-Struct variants today) so the rest of the SEDP packet still
        // serialises cleanly. See `type_information` module docstring +
        // ADR-CHANTIER-1.5-PHASE-0 §7bis for the FastDDS-mimicry rationale.
        if let Some(info) = type_information::derive_type_information(type_obj) {
            let _ = type_information::write_type_information(&info, buf, &mut offset)?;
        }
    }

    // ===== SENTINEL =====
    if offset + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_SENTINEL.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&0u16.to_le_bytes());
    offset += 4;

    Ok(offset)
}

/// Write PID_TYPE_OBJECT (0x0072) with CDR2-encoded TypeObject payload.
fn write_type_object(
    type_obj: &CompleteTypeObject,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    let mut type_obj_buf = vec![0u8; type_obj.max_cdr2_size()];
    let type_obj_len = type_obj
        .encode_cdr2_le(&mut type_obj_buf)
        .map_err(|_| ParseError::EncodingError)?;

    let aligned_len = (type_obj_len + 3) & !3;
    if aligned_len > u16::MAX as usize {
        return Err(ParseError::InvalidFormat);
    }
    if *offset + 4 + aligned_len > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    // Write PID header
    buf[*offset..*offset + 2].copy_from_slice(&PID_TYPE_OBJECT.to_le_bytes());
    let payload_len = u16::try_from(aligned_len).map_err(|_| ParseError::InvalidFormat)?;
    buf[*offset + 2..*offset + 4].copy_from_slice(&payload_len.to_le_bytes());
    *offset += 4;

    // Write CDR2 payload
    buf[*offset..*offset + type_obj_len].copy_from_slice(&type_obj_buf[..type_obj_len]);
    *offset += type_obj_len;

    // Align to 4-byte boundary
    let padding = aligned_len - type_obj_len;
    if padding > 0 {
        buf[*offset..*offset + padding].fill(0);
        *offset += padding;
    }

    Ok(())
}

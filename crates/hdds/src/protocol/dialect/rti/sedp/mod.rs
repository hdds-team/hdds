// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI dialect SEDP Builder
//!
//! Builds SEDP endpoint announcements for peers with vendor id 0x0101.
//!
//!
//! # Strategy
//!
//! **HDDS never sends vendor-specific PIDs (0x8000+) owned by another vendor.**
//! A vendor-range PID takes its meaning from the sender's vendor id
//! (DDSI-RTPS 2.5 Sec.9.4.2.11, Table 9.6), so HDDS (vendor 0x011A) only
//! writes standard PIDs here.
//!
//! # PID Set
//!
//! This encoder writes, in this order (see `build_sedp`):
//! 1. PID_UNICAST_LOCATOR (0x002f), PID_EXPECTS_INLINE_QOS (0x0043)
//! 2. PID_GROUP_GUID (0x0052), PID_GROUP_ENTITY_ID (0x0053)
//! 3. PID_PARTICIPANT_GUID (0x0050)
//! 4. PID_TOPIC_NAME (0x0005), PID_TYPE_NAME (0x0007)
//! 5. PID_KEY_HASH (0x0070) - always sent
//! 6. PID_ENDPOINT_GUID (0x005a)
//! 7. PID_PROTOCOL_VERSION (0x0015), PID_VENDOR_ID (0x0016)
//! 8. Core QoS PIDs (RELIABILITY, DURABILITY, etc.), PID_DATA_REPRESENTATION,
//!    PID_TYPE_CONSISTENCY
//! 9. PID_SENTINEL (0x0001)
//!
//! # PIDs NOT Sent (vendor-specific to vendor id 0x0101)
//!
//! - PID_PRODUCT_VERSION (0x8000)
//! - PID_ENTITY_VIRTUAL_GUID (0x8002)
//! - PID_EXPECTS_VIRTUAL_HB (0x8009)
//! - PID_ENDPOINT_PROPERTY_CHANGE_EPOCH (0x8015)
//! - PID_TYPE_OBJECT_LB (0x8021)

mod locators;
mod metadata;
mod qos;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::SedpEndpointData;
use std::convert::TryFrom;

/// PID constants
mod pids {
    pub const PID_SENTINEL: u16 = 0x0001;
    #[allow(dead_code)] // Part of RTI XTypes API, used for TypeObject support
    pub const PID_TYPE_OBJECT_LB: u16 = 0x8021;
}

/// Build SEDP discovery announcement for a peer with vendor id 0x0101.
///
/// Uses a minimal standard PID set.
/// Does NOT include vendor-specific PIDs (0x8000+).
// @audit-ok: Sequential builder (cyclo 28, cogni 2) - linear write_xxx calls without complex branching
pub fn build_sedp(data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
    // Pre-allocate buffer (1KB - minimal SEDP)
    let mut buf = vec![0u8; 1024];
    let mut offset = 0;

    // CDR encapsulation header (PL_CDR_LE = 0x0003)
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset += 4;

    // ===== PID ORDER =====
    //
    // This dialect writes the SEDP PIDs in this order:
    // 1. PID_UNICAST_LOCATOR
    // 2. PID_EXPECTS_INLINE_QOS
    // 3. PID_PARTICIPANT_GUID
    // 4. PID_TOPIC_NAME, PID_TYPE_NAME
    // 5. PID_KEY_HASH
    // 6. PID_ENDPOINT_GUID
    // 7. PID_PROTOCOL_VERSION, PID_VENDOR_ID
    // 8. QoS PIDs...
    //
    // ENDPOINT_GUID is not written first: the order above is kept.

    // ===== LOCATORS SECTION (FIRST) =====
    for locator in data.unicast_locators {
        locators::write_unicast_locator(locator, &mut buf, &mut offset)?;
    }

    // PID_EXPECTS_INLINE_QOS (0x0043)
    metadata::write_expects_inline_qos(false, &mut buf, &mut offset)?;

    // PID_GROUP_ENTITY_ID (0x0053) -- Publisher / Subscriber group entityId.
    // Lets a receiver associate endpoint-level inline-QoS PIDs
    // (PID_COHERENT_SET, PID_PARTITION) with the announcing group
    // (RTPS v2.5 Sec.9.3.2.1).
    // The endpoint kind is derived from the entityId nibble:
    //   0x02 = writer-with-key, 0x03 = writer-no-key -> publisher group
    //   0x07 = reader-with-key, 0x04 = reader-no-key -> subscriber group
    let is_writer = matches!(data.endpoint_guid.entity_id[3], 0x02 | 0x03);
    // PID_GROUP_GUID (0x0052) precedes it: GROUP-presentation subscribers
    // key their remote-group association on the full group GUID.
    let group = data
        .group_entity_id
        .unwrap_or(crate::protocol::discovery::sedp::build::default_group_entity_id(is_writer));
    metadata::write_group_guid(&data.endpoint_guid, group, &mut buf, &mut offset)?;
    metadata::write_group_entity_id(group, &mut buf, &mut offset)?;

    // PID_PARTICIPANT_GUID
    metadata::write_participant_guid(&data.participant_guid, &mut buf, &mut offset)?;

    // String parameters
    metadata::write_topic_name(data.topic_name, &mut buf, &mut offset)?;
    metadata::write_type_name(data.type_name, &mut buf, &mut offset)?;

    // PID_KEY_HASH - always sent by this dialect
    metadata::write_key_hash(&data.endpoint_guid, &mut buf, &mut offset)?;

    // PID_ENDPOINT_GUID
    metadata::write_endpoint_guid(&data.endpoint_guid, &mut buf, &mut offset)?;

    // Version metadata (standard PIDs only)
    metadata::write_protocol_version(&mut buf, &mut offset)?;
    metadata::write_vendor_id(&mut buf, &mut offset)?;

    // ===== QOS SECTION =====
    // Full QoS set: every standard QoS PID is written explicitly rather
    // than left to the receiver's defaults.
    qos::write_durability(data.qos, &mut buf, &mut offset)?;
    qos::write_durability_service(&mut buf, &mut offset)?;
    qos::write_deadline(data.qos, &mut buf, &mut offset)?;
    crate::protocol::dialect::write_latency_budget_pid(data.qos, &mut buf, &mut offset, false)?;
    crate::protocol::dialect::write_liveliness_pid(data.qos, &mut buf, &mut offset)?;
    qos::write_reliability(data.qos, &mut buf, &mut offset)?;
    qos::write_lifespan(data.qos, &mut buf, &mut offset)?;
    qos::write_user_data(&mut buf, &mut offset)?;
    qos::write_ownership(data.qos, &mut buf, &mut offset)?;
    qos::write_ownership_strength(data.qos, &mut buf, &mut offset)?;
    crate::protocol::dialect::write_destination_order_pid(data.qos, &mut buf, &mut offset, false)?;
    qos::write_presentation(data.qos, &mut buf, &mut offset)?;
    qos::write_partition(data.qos, &mut buf, &mut offset)?;
    qos::write_topic_data(&mut buf, &mut offset)?;
    qos::write_group_data(&mut buf, &mut offset)?;
    // Note: PID_HISTORY is intentionally not written by this dialect

    // PID_DATA_REPRESENTATION (0x0073) -- honor the offered QoS.
    // When no QoS is set, advertise both XCDR1 and XCDR2 so the remote peer
    // can pick the representation it prefers.
    metadata::write_data_representation(data.qos, &mut buf, &mut offset)?;

    // PID_TYPE_CONSISTENCY (0x0074) - written after all QoS PIDs.
    // Used for endpoint type matching (DDS-XTypes 1.3 Sec.7.6.3.4). Forward the local endpoint's
    // actual policy; fall back to the XTypes permissive default when absent.
    metadata::write_type_consistency(data.type_consistency.as_ref(), &mut buf, &mut offset)?;

    // ===== TYPE OBJECT =====
    //
    // PID_TYPE_OBJECT_LB (0x8021) is vendor-specific to vendor id 0x0101; a
    // vendor-range PID takes its meaning from the sender's vendor id
    // (DDSI-RTPS 2.5 Sec.9.4.2.11), so HDDS (vendor 0x011A) does not send it.
    //
    // Endpoints still match on topic/type name without a TypeObject.
    //
    // if let Some(type_obj_bytes) = data.type_object {
    //     write_type_object_lb(type_obj_bytes, &mut buf, &mut offset)?;
    // }
    let _ = data.type_object; // Silence unused warning

    // ===== SENTINEL =====
    write_sentinel(&mut buf, &mut offset)?;

    // Truncate to actual size
    buf.truncate(offset);
    Ok(buf)
}

/// Write PID_SENTINEL (0x0001)
fn write_sentinel(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 4 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_SENTINEL.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&0u16.to_le_bytes());
    *offset += 4;
    Ok(())
}

/// Write PID_TYPE_OBJECT_LB (0x8021) from pre-compressed bytes.
///
/// Expects `type_obj_bytes` to contain a ZLIB-compressed CompleteTypeObject
/// encoded in CDR2 format, optionally preceded by vendor 0x0101 metadata
/// (class_id, uncompressed_len, compressed_len). The payload is already
/// structured and this function simply writes it as-is.
#[allow(dead_code)] // Part of RTI XTypes API, used for TypeObject exchange
fn write_type_object_lb(
    type_obj_bytes: &[u8],
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    let payload_len = type_obj_bytes.len();
    if payload_len == 0 {
        return Ok(()); // Nothing to write
    }

    if payload_len > u16::MAX as usize {
        return Err(EncodeError::InvalidParameter(
            "TypeObject too large for PID_TYPE_OBJECT_LB".to_string(),
        ));
    }

    // Parameter length must be 4-byte aligned in RTPS ParameterList.
    let aligned_payload_len = (payload_len + 3) & !3;
    if aligned_payload_len > u16::MAX as usize {
        return Err(EncodeError::InvalidParameter(
            "Aligned TypeObject too large for PID_TYPE_OBJECT_LB".to_string(),
        ));
    }

    let total_len = 4 + aligned_payload_len;
    if *offset + total_len > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // PID header
    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TYPE_OBJECT_LB.to_le_bytes());
    let len_u16 = u16::try_from(aligned_payload_len)
        .map_err(|_| EncodeError::InvalidParameter("TypeObject length overflow".to_string()))?;
    buf[*offset + 2..*offset + 4].copy_from_slice(&len_u16.to_le_bytes());
    *offset += 4;

    // Payload
    buf[*offset..*offset + payload_len].copy_from_slice(type_obj_bytes);
    *offset += payload_len;

    // 4-byte alignment padding
    let padding = aligned_payload_len - payload_len;
    if padding > 0 {
        if *offset + padding > buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[*offset..*offset + padding].fill(0);
        *offset += padding;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dialect::Guid;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0x04],
        }
    }

    fn test_participant_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0xC1],
        }
    }

    #[test]
    fn test_build_sedp_rti() {
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 7411));
        let locators = vec![addr];

        let data = SedpEndpointData {
            endpoint_guid: test_guid(),
            participant_guid: test_participant_guid(),
            topic_name: "TestTopic",
            type_name: "TestType",
            unicast_locators: &locators,
            multicast_locators: &[],
            qos: None,
            type_object: None,
            user_data: None,
            hdds_shm_capability: None,
            hdds_peer_destination: false,
            group_entity_id: None,
            type_consistency: None,
            #[cfg(feature = "xtypes-structural-assignability")]
            type_information: None,
            emit_type_object_pid: true,
        };

        let result = build_sedp(&data);
        assert!(result.is_ok());

        let buf = result.expect("build_sedp should succeed");
        // Check CDR header
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn test_rti_has_key_hash() {
        let data = SedpEndpointData {
            endpoint_guid: test_guid(),
            participant_guid: test_participant_guid(),
            topic_name: "T",
            type_name: "T",
            unicast_locators: &[],
            multicast_locators: &[],
            qos: None,
            type_object: None,
            user_data: None,
            hdds_shm_capability: None,
            hdds_peer_destination: false,
            group_entity_id: None,
            type_consistency: None,
            #[cfg(feature = "xtypes-structural-assignability")]
            type_information: None,
            emit_type_object_pid: true,
        };

        let buf = build_sedp(&data).expect("build_sedp should succeed");

        // Find PID_KEY_HASH (0x0070)
        let pid_bytes = 0x0070u16.to_le_bytes();
        let found = buf.windows(2).position(|w| w == pid_bytes);
        assert!(found.is_some(), "PID_KEY_HASH must be present for RTI");
    }

    /// The RTI dialect SEDP writes no vendor-range PID (0x8000-0xffff): HDDS
    /// sends it under its own vendor id 0x011A, and a vendor-range PID is
    /// read per the sender's vendor id (DDSI-RTPS 2.5 Sec.9.6.2.2.1). Decoded
    /// from the emitted bytes, for a writer and a reader, with and without a
    /// TypeObject offered.
    #[test]
    fn the_rti_dialect_sedp_writes_no_vendor_range_pid() {
        let mut type_object_bytes = vec![0x01u8, 0, 0, 0];
        type_object_bytes.extend_from_slice(&[0xAA; 12]);
        for entity_kind in [0x02u8, 0x07] {
            for type_object in [None, Some(type_object_bytes.as_slice())] {
                let mut endpoint = test_guid();
                endpoint.entity_id[3] = entity_kind;
                let data = SedpEndpointData {
                    endpoint_guid: endpoint,
                    participant_guid: test_participant_guid(),
                    topic_name: "Square",
                    type_name: "ShapeType",
                    unicast_locators: &[],
                    multicast_locators: &[],
                    qos: None,
                    type_object,
                    user_data: None,
                    hdds_shm_capability: None,
                    hdds_peer_destination: false,
                    group_entity_id: None,
                    type_consistency: None,
                    #[cfg(feature = "xtypes-structural-assignability")]
                    type_information: None,
                    emit_type_object_pid: true,
                };
                let buf = build_sedp(&data).expect("build_sedp should succeed");
                let mut offset = 4;
                loop {
                    let pid = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
                    let len = usize::from(u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]));
                    offset += 4;
                    if pid == pids::PID_SENTINEL {
                        break;
                    }
                    assert!(pid < 0x8000, "vendor-range PID {pid:#06x} written");
                    offset += len;
                }
                assert_eq!(offset, buf.len());
            }
        }
    }
}

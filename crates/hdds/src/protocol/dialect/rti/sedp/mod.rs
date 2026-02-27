// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI Connext SEDP Builder
//!
//! Builds SEDP endpoint announcements for RTI Connext interop.
//!
//!
//! # RTI Interop Strategy
//!
//! RTI Connext is strict about SEDP parsing. The key insight is that
//! **RTI vendor PIDs (0x8000+) should NOT be sent by non-RTI implementations**.
//! RTI validates that vendor PIDs come from its own vendor ID (0x0101).
//!
//! When HDDS (vendor 0x01AA) sends RTI vendor PIDs, RTI rejects the SEDP
//! announcement with `subscriptionReaderListenerOnSampleLost`.
//!
//! # Minimal PID Set for RTI Interop
//!
//! This encoder uses a minimal PID set that RTI accepts:
//! 1. PID_ENDPOINT_GUID (0x005a) - FIRST, RTI validates this
//! 2. PID_PARTICIPANT_GUID (0x0050)
//! 3. PID_KEY_HASH (0x0070) - MANDATORY for RTI
//! 4. PID_TOPIC_NAME (0x0005), PID_TYPE_NAME (0x0007)
//! 5. PID_PROTOCOL_VERSION (0x0015), PID_VENDOR_ID (0x0016)
//! 6. PID_UNICAST_LOCATOR (0x002f)
//! 7. Core QoS PIDs (RELIABILITY, DURABILITY, HISTORY, etc.)
//! 8. PID_SENTINEL (0x0001)
//!
//! # PIDs NOT Sent (RTI vendor-specific)
//!
//! - PID_PRODUCT_VERSION (0x8000) - RTI vendor
//! - PID_ENTITY_VIRTUAL_GUID (0x8002) - RTI vendor (ignored from non-RTI)
//! - PID_EXPECTS_VIRTUAL_HB (0x8009) - RTI vendor (ignored from non-RTI)
//! - PID_ENDPOINT_PROPERTY_CHANGE_EPOCH (0x8015) - RTI vendor (ignored from non-RTI)
//! - PID_TYPE_OBJECT_LB (0x8021) - RTI vendor (causes `subscriptionReaderListenerOnSampleLost`)

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

/// Build SEDP discovery announcement for RTI Connext.
///
/// Uses a minimal PID set that RTI accepts from non-RTI vendors.
/// Does NOT include RTI vendor-specific PIDs (0x8000+).
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

    // ===== PID ORDER MATCHING FASTDDS =====
    //
    // FastDDS SEDP (which RTI accepts) uses this PID order:
    // 1. PID_UNICAST_LOCATOR
    // 2. PID_EXPECTS_INLINE_QOS
    // 3. PID_PARTICIPANT_GUID
    // 4. PID_TOPIC_NAME, PID_TYPE_NAME
    // 5. PID_KEY_HASH
    // 6. PID_ENDPOINT_GUID
    // 7. PID_PROTOCOL_VERSION, PID_VENDOR_ID
    // 8. QoS PIDs...
    //
    // HDDS was putting ENDPOINT_GUID first, which RTI rejects.

    // ===== LOCATORS SECTION (FIRST like FastDDS) =====
    for locator in data.unicast_locators {
        locators::write_unicast_locator(locator, &mut buf, &mut offset)?;
    }

    // PID_EXPECTS_INLINE_QOS (0x0043)
    metadata::write_expects_inline_qos(false, &mut buf, &mut offset)?;

    // PID_PARTICIPANT_GUID
    metadata::write_participant_guid(&data.participant_guid, &mut buf, &mut offset)?;

    // String parameters
    metadata::write_topic_name(data.topic_name, &mut buf, &mut offset)?;
    metadata::write_type_name(data.type_name, &mut buf, &mut offset)?;

    // PID_KEY_HASH - MANDATORY for RTI
    metadata::write_key_hash(&data.endpoint_guid, &mut buf, &mut offset)?;

    // PID_ENDPOINT_GUID
    metadata::write_endpoint_guid(&data.endpoint_guid, &mut buf, &mut offset)?;

    // Version metadata (standard PIDs only)
    metadata::write_protocol_version(&mut buf, &mut offset)?;
    metadata::write_vendor_id(&mut buf, &mut offset)?;

    // ===== QOS SECTION =====
    // Full QoS set matching FastDDS (which works with RTI).
    // RTI may expect all standard QoS PIDs to be present for proper matching.
    qos::write_durability(data.qos, &mut buf, &mut offset)?;
    qos::write_durability_service(&mut buf, &mut offset)?;
    qos::write_deadline(&mut buf, &mut offset)?;
    qos::write_latency_budget(&mut buf, &mut offset)?;
    qos::write_liveliness(&mut buf, &mut offset)?;
    qos::write_reliability(data.qos, &mut buf, &mut offset)?;
    qos::write_lifespan(&mut buf, &mut offset)?;
    qos::write_user_data(&mut buf, &mut offset)?;
    qos::write_ownership(&mut buf, &mut offset)?;
    qos::write_destination_order(&mut buf, &mut offset)?;
    qos::write_presentation(&mut buf, &mut offset)?;
    qos::write_partition(&mut buf, &mut offset)?;
    qos::write_topic_data(&mut buf, &mut offset)?;
    qos::write_group_data(&mut buf, &mut offset)?;
    // Note: We intentionally skip PID_HISTORY as FastDDS doesn't send it for subscribers

    // PID_TYPE_CONSISTENCY (0x0074) - FastDDS sends this after all QoS PIDs
    // RTI requires this for endpoint type matching
    metadata::write_type_consistency(&mut buf, &mut offset)?;

    // ===== TYPE OBJECT =====
    //
    // PID_TYPE_OBJECT_LB (0x8021) is an RTI vendor-specific PID. RTI validates
    // that vendor PIDs (0x8000+) come from its own vendor ID (0x0101). When
    // HDDS (vendor 0x01AA) sends this PID, RTI rejects the SEDP with
    // `subscriptionReaderListenerOnSampleLost`.
    //
    // SOLUTION: Do NOT send PID_TYPE_OBJECT_LB for RTI interop.
    // RTI can still match endpoints based on topic/type name without TypeObject.
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
/// encoded in CDR2 format, optionally preceded by RTI metadata
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
        };

        let buf = build_sedp(&data).expect("build_sedp should succeed");

        // Find PID_KEY_HASH (0x0070)
        let pid_bytes = 0x0070u16.to_le_bytes();
        let found = buf.windows(2).position(|w| w == pid_bytes);
        assert!(found.is_some(), "PID_KEY_HASH must be present for RTI");
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS SEDP Builder
//!
//! Builds SEDP endpoint announcements for OpenDDS interoperability.
//!
//!
//! # OpenDDS Interop Requirements
//!
//! OpenDDS (vendor 0x0103) uses XTypes and requires:
//! - PID_DATA_REPRESENTATION (0x0073) with XCDR2 support
//! - PID_TYPE_INFORMATION (0x0075) for XTypes matching
//!
//! Without these PIDs, OpenDDS won't send user DATA even after matching.
//!
//! # PID Order
//!
//! The PID order follows standard RTPS conventions:
//! 1. CDR encapsulation header (PL_CDR_LE)
//! 2. Locators (PID_UNICAST_LOCATOR)
//! 3. Identity (PID_PARTICIPANT_GUID, PID_ENDPOINT_GUID)
//! 4. Strings (PID_TOPIC_NAME, PID_TYPE_NAME)
//! 5. Version (PID_PROTOCOL_VERSION, PID_VENDOR_ID)
//! 6. XTypes (PID_DATA_REPRESENTATION, PID_TYPE_INFORMATION)
//! 7. QoS (RELIABILITY, DURABILITY, HISTORY, etc.)
//! 8. PID_SENTINEL

mod locators;
mod metadata;
mod qos;
mod type_info;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::SedpEndpointData;

/// PID constants
mod pids {
    pub const PID_SENTINEL: u16 = 0x0001;
}

/// Build SEDP discovery announcement for OpenDDS.
///
/// Includes PID_TYPE_INFORMATION (0x0075) for XTypes compatibility.
// @audit-ok: Sequential builder (cyclo 19, cogni 2) - linear write_xxx calls without complex branching
pub fn build_sedp(data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
    // Pre-allocate buffer (2KB - typical SEDP with TypeInfo)
    let mut buf = vec![0u8; 2048];
    let mut offset = 0;

    // CDR encapsulation header (PL_CDR_LE = 0x0003)
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset += 4;

    // ===== LOCATORS SECTION =====
    for locator in data.unicast_locators {
        locators::write_unicast_locator(locator, &mut buf, &mut offset)?;
    }

    // ===== IDENTITY SECTION =====
    metadata::write_participant_guid(&data.participant_guid, &mut buf, &mut offset)?;
    metadata::write_endpoint_guid(&data.endpoint_guid, &mut buf, &mut offset)?;

    // ===== STRING SECTION =====
    metadata::write_topic_name(data.topic_name, &mut buf, &mut offset)?;
    metadata::write_type_name(data.type_name, &mut buf, &mut offset)?;

    // ===== VERSION SECTION =====
    metadata::write_protocol_version(&mut buf, &mut offset)?;
    metadata::write_vendor_id(&mut buf, &mut offset)?;

    // ===== XTYPES SECTION =====
    // PID_DATA_REPRESENTATION (0x0073) - CRITICAL for OpenDDS
    // OpenDDS writer advertises XCDR2, reader must support it
    metadata::write_data_representation_xcdr2(&mut buf, &mut offset)?;

    // Info: PID_TYPE_CONSISTENCY (0x0074) removed - OpenDDS doesn't send it in DATA(w)
    // and may not expect it in DATA(r). The TypeInformation hash matching should suffice.
    // metadata::write_type_consistency(&mut buf, &mut offset)?;

    // PID_TYPE_INFORMATION (0x0075) - XTypes TypeInformation
    // Required for OpenDDS XTypes matching - TYPE_CONSISTENCY fallback doesn't work
    type_info::write_type_information(&mut buf, &mut offset)?;

    // ===== QOS SECTION =====
    qos::write_durability(data.qos, &mut buf, &mut offset)?;
    qos::write_reliability(data.qos, &mut buf, &mut offset)?;
    qos::write_history(data.qos, &mut buf, &mut offset)?;
    qos::write_deadline(&mut buf, &mut offset)?;
    qos::write_liveliness(&mut buf, &mut offset)?;
    qos::write_ownership(&mut buf, &mut offset)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::dialect::Guid;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x03, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0x04],
        }
    }

    fn test_participant_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x03, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0xC1],
        }
    }

    #[test]
    fn test_build_sedp_opendds() {
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 22), 7411));
        let locators = vec![addr];

        let data = SedpEndpointData {
            endpoint_guid: test_guid(),
            participant_guid: test_participant_guid(),
            topic_name: "TemperatureTopic",
            type_name: "TemperatureModule::Temperature",
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

        // Check PID_DATA_REPRESENTATION (0x0073) is present
        let pid_data_rep = 0x0073u16.to_le_bytes();
        let found_data_rep = buf.windows(2).position(|w| w == pid_data_rep);
        assert!(
            found_data_rep.is_some(),
            "PID_DATA_REPRESENTATION must be present"
        );

        // Info: PID_TYPE_CONSISTENCY (0x0074) is no longer sent for OpenDDS
        // OpenDDS doesn't include it in DATA(w), so we removed it from DATA(r) as well
        // let pid_type_consistency = 0x0074u16.to_le_bytes();
        // let found_type_consistency = buf.windows(2).position(|w| w == pid_type_consistency);
        // assert!(found_type_consistency.is_some(), "PID_TYPE_CONSISTENCY must be present for OpenDDS");

        // PID_TYPE_INFORMATION (0x0075) - Required for OpenDDS XTypes matching
        // TYPE_CONSISTENCY fallback experiment showed OpenDDS still needs TypeInfo
        let pid_type_info = 0x0075u16.to_le_bytes();
        let found_type_info = buf.windows(2).position(|w| w == pid_type_info);
        assert!(
            found_type_info.is_some(),
            "PID_TYPE_INFORMATION must be present for OpenDDS XTypes"
        );
    }
}

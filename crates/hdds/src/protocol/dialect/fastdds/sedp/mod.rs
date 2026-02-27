// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FastDDS SEDP Builder
//!
//! Builds SEDP endpoint announcements for FastDDS interop.
//!
//!
//! # FastDDS-specific quirks:
//! - PID_ENDPOINT_GUID must appear before PID_PARTICIPANT_GUID
//! - No PID_KEY_HASH required (FastDDS doesn't use it)
//! - No TypeObject required (static types mode)
//! - PL_CDR_LE encapsulation (0x0003)
//! - Minimal metadata for interop mode

mod locators;
mod metadata;
mod qos;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
#[cfg(test)]
use crate::protocol::dialect::Guid;
use crate::protocol::dialect::SedpEndpointData;

/// PID constants for SEDP encoding
mod pids {
    #[allow(dead_code)] // Used by write_sentinel function
    pub const PID_SENTINEL: u16 = 0x0001;
}

/// Build SEDP discovery announcement for FastDDS.
///
/// This implements the FastDDS-certified SEDP encoding order:
/// 1. CDR encapsulation header (PL_CDR_LE = 0x0003)
/// 2. PID_ENDPOINT_GUID - FastDDS validates this first
/// 3. PID_PARTICIPANT_GUID - Links to participant
/// 4. PID_TOPIC_NAME, PID_TYPE_NAME
/// 5. PID_PROTOCOL_VERSION, PID_VENDOR_ID
/// 6. PID_UNICAST_LOCATOR - Per-endpoint locators
/// 7. QoS PIDs - RELIABILITY, DURABILITY, HISTORY, etc.
/// 8. PID_SENTINEL - Terminator
#[allow(dead_code)] // Reserved for future FastDDS dialect support
                    // @audit-ok: Sequential builder (cyclo 17, cogni 2) - linear write_xxx calls without complex branching
pub fn build_sedp(data: &SedpEndpointData) -> EncodeResult<Vec<u8>> {
    // Pre-allocate buffer (1KB typical for SEDP)
    let mut buf = vec![0u8; 1024];
    let mut offset = 0;

    // CDR encapsulation header (ALWAYS big-endian per CDR spec)
    // 0x0003 = PL_CDR_LE (Parameter List, Little-Endian data)
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset += 4;

    // ===== METADATA SECTION =====
    // FastDDS expects PID_ENDPOINT_GUID before PID_PARTICIPANT_GUID
    metadata::write_endpoint_guid(&data.endpoint_guid, &mut buf, &mut offset)?;
    metadata::write_participant_guid(&data.participant_guid, &mut buf, &mut offset)?;

    // String parameters
    metadata::write_topic_name(data.topic_name, &mut buf, &mut offset)?;
    metadata::write_type_name(data.type_name, &mut buf, &mut offset)?;

    // Version metadata
    metadata::write_protocol_version(&mut buf, &mut offset)?;
    metadata::write_vendor_id(&mut buf, &mut offset)?;

    // ===== LOCATORS SECTION =====
    for locator in data.unicast_locators {
        locators::write_unicast_locator(locator, &mut buf, &mut offset)?;
    }

    // ===== QOS SECTION =====
    qos::write_reliability(data.qos, &mut buf, &mut offset)?;
    qos::write_durability(data.qos, &mut buf, &mut offset)?;
    qos::write_history(data.qos, &mut buf, &mut offset)?;
    qos::write_deadline(&mut buf, &mut offset)?;
    qos::write_ownership(&mut buf, &mut offset)?;
    qos::write_liveliness(&mut buf, &mut offset)?;

    // ===== SENTINEL =====
    write_sentinel(&mut buf, &mut offset)?;

    // Truncate to actual size
    buf.truncate(offset);
    Ok(buf)
}

/// Write PID_SENTINEL (0x0001) - parameter list terminator
#[allow(dead_code)] // Used by build_sedp function
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
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    fn test_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x0F, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0x04], // User writer
        }
    }

    fn test_participant_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x0F, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0xC1], // Participant
        }
    }

    #[test]
    fn test_build_sedp_basic() {
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
        // Check ends with sentinel
        let len = buf.len();
        assert_eq!(&buf[len - 4..len - 2], &[0x01, 0x00]); // PID_SENTINEL LE
    }

    #[test]
    fn test_endpoint_guid_before_participant() {
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

        // Find PID_ENDPOINT_GUID (0x005a) and PID_PARTICIPANT_GUID (0x0050)
        let endpoint_pid_pos = find_pid(&buf, 0x005a);
        let participant_pid_pos = find_pid(&buf, 0x0050);

        assert!(endpoint_pid_pos.is_some(), "PID_ENDPOINT_GUID not found");
        assert!(
            participant_pid_pos.is_some(),
            "PID_PARTICIPANT_GUID not found"
        );
        assert!(
            endpoint_pid_pos.expect("endpoint pos set")
                < participant_pid_pos.expect("participant pos set"),
            "PID_ENDPOINT_GUID must appear before PID_PARTICIPANT_GUID for FastDDS"
        );
    }

    fn find_pid(buf: &[u8], pid: u16) -> Option<usize> {
        let pid_bytes = pid.to_le_bytes();
        buf.windows(2).position(|w| w == pid_bytes)
    }
}

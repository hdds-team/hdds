// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTI Connext SPDP Builder
//!
//! Builds SPDP participant announcements for RTI Connext interop.
//!
//!
//! # RTI-specific requirements:
//! - BUILTIN_ENDPOINT_SET at position 2 (right after GUID)
//! - BUILTIN_ENDPOINT_QOS required
//! - Full property list (7 properties)
//! - Vendor-specific PIDs: PRODUCT_VERSION, RTI_DOMAIN_ID, TRANSPORT_INFO_LIST
//! - REACHABILITY_LEASE_DURATION
//! - VENDOR_BUILTIN_ENDPOINT_SET

use std::net::SocketAddr;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;

/// PID constants for SPDP encoding
mod pids {
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
    pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
    pub const PID_VENDOR_ID: u16 = 0x0016;
    pub const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
    pub const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
    #[allow(dead_code)] // Part of RTPS spec, used for multicast locator announcements
    pub const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
    #[allow(dead_code)] // Part of RTPS spec, used for default multicast locators
    pub const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;
    pub const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
    pub const PID_DOMAIN_ID: u16 = 0x000f;
    pub const PID_PRODUCT_VERSION: u16 = 0x8000;
    pub const PID_RTI_DOMAIN_ID: u16 = 0x800f;
    pub const PID_TRANSPORT_INFO_LIST: u16 = 0x8010;
    pub const PID_REACHABILITY_LEASE_DURATION: u16 = 0x8016;
    pub const PID_VENDOR_BUILTIN_ENDPOINT_SET: u16 = 0x8017;
    pub const PID_SENTINEL: u16 = 0x0001;
}

/// HDDS vendor ID
const VENDOR_ID_HDDS: u16 = 0x01AA;

/// Builtin endpoint set flags for RTI interop.
///
/// RTI Connext requires specific builtin endpoints to be announced for proper
/// discovery and liveliness handling. The generic HDDS constant (0x00000C3F)
/// is insufficient - RTI needs the Participant Stateless Message endpoints.
///
/// Value 0x000F0C3F matches what FastDDS sends (and RTI accepts):
/// - Bits 0-5   (0x003F):  SPDP + SEDP announcer/detector endpoints
/// - Bits 10-11 (0x0C00):  Participant Message Writer/Reader (liveliness)
/// - Bits 16-19 (0xF0000): Participant Stateless Message endpoints
///
/// Without bits 16-19, RTI logs `subscriptionReaderListenerOnSampleLost` and
/// refuses to send its SEDP publications DATA, breaking endpoint matching.
const BUILTIN_ENDPOINT_SET_RTI: u32 = 0x000F0C3F;
/// Build SPDP participant announcement for RTI Connext.
// @audit-ok: Sequential builder (cyclo 17, cogni 2) - linear write_xxx calls without complex branching
pub fn build_spdp(
    participant_guid: &Guid,
    unicast_locators: &[SocketAddr],
    multicast_locators: &[SocketAddr],
    lease_duration_sec: u32,
) -> EncodeResult<Vec<u8>> {
    // Pre-allocate buffer (1KB for RTI SPDP with properties)
    let mut buf = vec![0u8; 1024];
    let mut offset = 0;

    // CDR encapsulation header
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]); // PL_CDR_LE
    offset += 4;

    // v126: Match FastDDS SPDP PID order for RTI compatibility
    // FastDDS order: PROTOCOL_VERSION, VENDOR_ID, PARTICIPANT_GUID, BUILTIN_ENDPOINT_SET, ...

    // Position 1: PID_PROTOCOL_VERSION
    write_protocol_version(&mut buf, &mut offset)?;

    // Position 2: PID_VENDOR_ID
    write_vendor_id(&mut buf, &mut offset)?;

    // Position 3: PID_PARTICIPANT_GUID
    write_participant_guid(participant_guid, &mut buf, &mut offset)?;

    // Position 4: PID_BUILTIN_ENDPOINT_SET - CRITICAL for RTI
    write_builtin_endpoint_set(&mut buf, &mut offset)?;

    // v126: REMOVED PID_BUILTIN_ENDPOINT_QOS (0x0077)
    // FastDDS does NOT send this PID, and RTI accepts FastDDS.

    // Locators - BEFORE properties (RTI requirement)
    // v126: Only unicast locators - FastDDS does NOT send multicast locators in SPDP
    for locator in unicast_locators {
        write_locator(
            pids::PID_DEFAULT_UNICAST_LOCATOR,
            locator,
            &mut buf,
            &mut offset,
        )?;
        write_locator(
            pids::PID_METATRAFFIC_UNICAST_LOCATOR,
            locator,
            &mut buf,
            &mut offset,
        )?;
    }

    // v126: REMOVED multicast locators - FastDDS doesn't send these
    // for locator in multicast_locators {
    //     write_locator(pids::PID_DEFAULT_MULTICAST_LOCATOR, locator, &mut buf, &mut offset)?;
    //     write_locator(pids::PID_METATRAFFIC_MULTICAST_LOCATOR, locator, &mut buf, &mut offset)?;
    // }
    let _ = multicast_locators; // Suppress unused warning

    // PID_PARTICIPANT_LEASE_DURATION
    write_lease_duration(lease_duration_sec, &mut buf, &mut offset)?;

    // PID_DOMAIN_ID
    write_domain_id(&mut buf, &mut offset)?;

    // Vendor-specific PIDs for RTI
    write_product_version(&mut buf, &mut offset)?;
    write_rti_domain_id(&mut buf, &mut offset)?;
    write_transport_info_list(&mut buf, &mut offset)?;
    write_reachability_lease_duration(&mut buf, &mut offset)?;
    write_vendor_builtin_endpoint_set(&mut buf, &mut offset)?;

    // PID_SENTINEL
    write_sentinel(&mut buf, &mut offset)?;

    buf.truncate(offset);
    Ok(buf)
}

fn write_participant_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
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

fn write_builtin_endpoint_set(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_BUILTIN_ENDPOINT_SET.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&BUILTIN_ENDPOINT_SET_RTI.to_le_bytes());
    *offset += 4;

    Ok(())
}

fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset] = 2; // major
    buf[*offset + 1] = 6; // minor (RTPS v2.6 for RTI)
    buf[*offset + 2] = 0;
    buf[*offset + 3] = 0;
    *offset += 4;

    Ok(())
}

fn write_vendor_id(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_VENDOR_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 2].copy_from_slice(&VENDOR_ID_HDDS.to_le_bytes());
    buf[*offset + 2] = 0;
    buf[*offset + 3] = 0;
    *offset += 4;

    Ok(())
}

fn write_locator(
    pid: u16,
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 28 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // UDPV4
    *offset += 4;

    let port = u32::from(addr.port());
    buf[*offset..*offset + 4].copy_from_slice(&port.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].fill(0);
    *offset += 12;

    match addr {
        SocketAddr::V4(v4) => {
            buf[*offset..*offset + 4].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(_) => {
            buf[*offset..*offset + 4].fill(0);
        }
    }
    *offset += 4;

    Ok(())
}

fn write_lease_duration(seconds: u32, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_LEASE_DURATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&seconds.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes());
    *offset += 8;

    Ok(())
}

fn write_domain_id(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_DOMAIN_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&0u32.to_le_bytes());
    *offset += 4;

    Ok(())
}

fn write_product_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PRODUCT_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset] = 0x00; // major
    buf[*offset + 1] = 0x02; // minor (HDDS v0.2.x)
    buf[*offset + 2] = 0x00;
    buf[*offset + 3] = 0x00;
    *offset += 4;

    Ok(())
}

fn write_rti_domain_id(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_RTI_DOMAIN_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&0u32.to_le_bytes());
    *offset += 4;

    Ok(())
}

fn write_transport_info_list(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    let size = 12; // seq_length(4) + classId(4) + messageSizeMax(4)

    if *offset + 4 + size > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_TRANSPORT_INFO_LIST.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&(size as u16).to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // sequence length = 1
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // classId = UDPv4
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&65507u32.to_le_bytes()); // messageSizeMax
    *offset += 4;

    Ok(())
}

fn write_reachability_lease_duration(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_REACHABILITY_LEASE_DURATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    *offset += 4;
    // INFINITE duration
    buf[*offset..*offset + 4].copy_from_slice(&0x7FFFFFFFu32.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    *offset += 8;

    Ok(())
}

fn write_vendor_builtin_endpoint_set(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_VENDOR_BUILTIN_ENDPOINT_SET.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    *offset += 4;
    buf[*offset..*offset + 4].copy_from_slice(&0x00000003u32.to_le_bytes()); // bits 0+1
    *offset += 4;

    Ok(())
}

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
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_guid() -> Guid {
        Guid {
            prefix: [
                0x01, 0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0xC1],
        }
    }

    #[test]
    fn test_build_spdp_rti() {
        let guid = test_guid();
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 7411));
        let unicast = vec![addr];

        let result = build_spdp(&guid, &unicast, &[], 100);
        assert!(result.is_ok());

        let buf = result.expect("build_spdp should succeed");
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00]);
    }

    #[test]
    fn test_rti_has_builtin_endpoint_set_early() {
        let guid = test_guid();
        let result = build_spdp(&guid, &[], &[], 100).expect("build_spdp should succeed");

        // Find PID_BUILTIN_ENDPOINT_SET (0x0058)
        let pid_bytes = 0x0058u16.to_le_bytes();
        let pos = result.windows(2).position(|w| w == pid_bytes);
        assert!(pos.is_some(), "PID_BUILTIN_ENDPOINT_SET must be present");
        // Should be early in packet (after GUID at offset 4+20=24)
        assert!(
            pos.expect("pos must be set") < 50,
            "BUILTIN_ENDPOINT_SET should be early"
        );
    }
}

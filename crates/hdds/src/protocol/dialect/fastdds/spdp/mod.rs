// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FastDDS SPDP Builder
//!
//! Builds SPDP participant announcements for FastDDS interop.
//!
//!
//! # FastDDS-specific notes:
//! - FastDDS tolerates minimal SPDP with standard PIDs
//! - No RTI-specific vendor PIDs required (PRODUCT_VERSION, RTI_DOMAIN_ID, etc.)
//! - Simpler property list (just hostname + process_id)
//! - Standard BUILTIN_ENDPOINT_SET flags

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
    pub const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
    pub const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;
    pub const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
    pub const PID_SENTINEL: u16 = 0x0001;
}

/// HDDS vendor ID
const VENDOR_ID_HDDS: u16 = 0x01AA;

/// Builtin endpoint set flags (standard DDS)
const BUILTIN_ENDPOINT_SET_DEFAULT: u32 = 0x0000003F; // Basic SEDP endpoints

/// Build SPDP participant announcement for FastDDS.
///
/// This implements a minimal SPDP that FastDDS accepts:
/// 1. CDR encapsulation header (PL_CDR_LE)
/// 2. PID_PARTICIPANT_GUID
/// 3. PID_BUILTIN_ENDPOINT_SET
/// 4. PID_PROTOCOL_VERSION
/// 5. PID_VENDOR_ID
/// 6. Locators (unicast + multicast)
/// 7. PID_PARTICIPANT_LEASE_DURATION
/// 8. PID_SENTINEL
// @audit-ok: Sequential builder (cyclo 14, cogni 3) - linear write_xxx calls without complex branching
pub fn build_spdp(
    participant_guid: &Guid,
    unicast_locators: &[SocketAddr],
    multicast_locators: &[SocketAddr],
    lease_duration_sec: u32,
) -> EncodeResult<Vec<u8>> {
    // Pre-allocate buffer (512 bytes typical for SPDP)
    let mut buf = vec![0u8; 512];
    let mut offset = 0;

    // CDR encapsulation header
    if buf.len() < 4 {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]); // PL_CDR_LE
    offset += 4;

    // PID_PARTICIPANT_GUID (0x0050) - 16 bytes
    write_participant_guid(participant_guid, &mut buf, &mut offset)?;

    // PID_BUILTIN_ENDPOINT_SET (0x0058) - 4 bytes
    write_builtin_endpoint_set(&mut buf, &mut offset)?;

    // PID_PROTOCOL_VERSION (0x0015) - 4 bytes
    write_protocol_version(&mut buf, &mut offset)?;

    // PID_VENDOR_ID (0x0016) - 4 bytes
    write_vendor_id(&mut buf, &mut offset)?;

    // Locators
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

    for locator in multicast_locators {
        write_locator(
            pids::PID_DEFAULT_MULTICAST_LOCATOR,
            locator,
            &mut buf,
            &mut offset,
        )?;
        write_locator(
            pids::PID_METATRAFFIC_MULTICAST_LOCATOR,
            locator,
            &mut buf,
            &mut offset,
        )?;
    }

    // PID_PARTICIPANT_LEASE_DURATION (0x0002) - 8 bytes
    write_lease_duration(lease_duration_sec, &mut buf, &mut offset)?;

    // PID_SENTINEL
    write_sentinel(&mut buf, &mut offset)?;

    // Truncate to actual size
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

    buf[*offset..*offset + 4].copy_from_slice(&BUILTIN_ENDPOINT_SET_DEFAULT.to_le_bytes());
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

    buf[*offset] = 2; // major = 2
    buf[*offset + 1] = 3; // minor = 3 (RTPS v2.3)
    buf[*offset + 2] = 0; // padding
    buf[*offset + 3] = 0; // padding
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
    buf[*offset + 2] = 0; // padding
    buf[*offset + 3] = 0; // padding
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

    // PID header
    buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
    *offset += 4;

    // Locator_t: kind(4) + port(4) + address(16)
    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // LOCATOR_KIND_UDPV4
    *offset += 4;

    let port = u32::from(addr.port());
    buf[*offset..*offset + 4].copy_from_slice(&port.to_le_bytes());
    *offset += 4;

    // Address: IPv4 in last 4 bytes
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
    buf[*offset + 4..*offset + 8].copy_from_slice(&0u32.to_le_bytes()); // nanoseconds = 0
    *offset += 8;

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
                0x01, 0x0F, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ],
            entity_id: [0x00, 0x00, 0x01, 0xC1], // Participant
        }
    }

    #[test]
    fn test_build_spdp_basic() {
        let guid = test_guid();
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 7411));
        let unicast = vec![addr];
        let multicast = vec![];

        let result = build_spdp(&guid, &unicast, &multicast, 100);
        assert!(result.is_ok());

        let buf = result.expect("build_spdp should succeed");
        // Check CDR header
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00]);
        // Check ends with sentinel
        let len = buf.len();
        assert_eq!(&buf[len - 4..len - 2], &[0x01, 0x00]); // PID_SENTINEL LE
    }

    #[test]
    fn test_spdp_contains_participant_guid() {
        let guid = test_guid();
        let result = build_spdp(&guid, &[], &[], 100).expect("build_spdp should succeed");

        // Find PID_PARTICIPANT_GUID (0x0050)
        let pid_bytes = 0x0050u16.to_le_bytes();
        let found = result.windows(2).position(|w| w == pid_bytes);
        assert!(found.is_some(), "PID_PARTICIPANT_GUID not found");
    }
}

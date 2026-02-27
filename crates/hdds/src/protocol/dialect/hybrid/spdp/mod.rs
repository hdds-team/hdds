// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Hybrid SPDP encoder - conservative fallback
//!
//! Standard PIDs only, no vendor extensions.
//! Should work with any RTPS 2.3+ implementation.
//!

use std::net::{IpAddr, SocketAddr};

use crate::protocol::dialect::error::{EncodeError, EncodeResult};
use crate::protocol::dialect::Guid;

/// PID constants
mod pids {
    pub const PID_PARTICIPANT_GUID: u16 = 0x0050;
    pub const PID_PROTOCOL_VERSION: u16 = 0x0015;
    pub const PID_VENDOR_ID: u16 = 0x0016;
    pub const PID_PARTICIPANT_LEASE_DURATION: u16 = 0x0002;
    pub const PID_DEFAULT_UNICAST_LOCATOR: u16 = 0x0031;
    pub const PID_DEFAULT_MULTICAST_LOCATOR: u16 = 0x0048;
    pub const PID_METATRAFFIC_UNICAST_LOCATOR: u16 = 0x0032;
    pub const PID_METATRAFFIC_MULTICAST_LOCATOR: u16 = 0x0033;
    pub const PID_BUILTIN_ENDPOINT_SET: u16 = 0x0058;
    #[allow(dead_code)] // Part of RTPS spec, may be used in future
    pub const PID_SENTINEL: u16 = 0x0001;
}

/// Build Hybrid SPDP announcement
///
/// Standard PIDs only - no vendor extensions.
// @audit-ok: Sequential builder (cyclo 12, cogni 2) - linear write_xxx calls without complex branching
pub fn build_spdp(
    participant_guid: &Guid,
    unicast_locators: &[SocketAddr],
    multicast_locators: &[SocketAddr],
    lease_duration_sec: u32,
) -> EncodeResult<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    #[allow(unused_assignments)] // Initial value needed for clarity, immediately overwritten
    let mut offset = 0;

    // CDR encapsulation header (PL_CDR_LE)
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset = 4;

    // 1. PID_PROTOCOL_VERSION (2 bytes)
    write_protocol_version(&mut buf, &mut offset)?;

    // 2. PID_VENDOR_ID (HDDS)
    write_vendor_id(&mut buf, &mut offset)?;

    // 3. PID_PARTICIPANT_GUID
    write_participant_guid(participant_guid, &mut buf, &mut offset)?;

    // 4. PID_BUILTIN_ENDPOINT_SET
    write_builtin_endpoint_set(&mut buf, &mut offset)?;

    // 5. PID_PARTICIPANT_LEASE_DURATION
    write_lease_duration(lease_duration_sec, &mut buf, &mut offset)?;

    // 6. Locators
    for addr in unicast_locators {
        write_default_unicast_locator(addr, &mut buf, &mut offset)?;
        write_metatraffic_unicast_locator(addr, &mut buf, &mut offset)?;
    }
    for addr in multicast_locators {
        write_default_multicast_locator(addr, &mut buf, &mut offset)?;
        write_metatraffic_multicast_locator(addr, &mut buf, &mut offset)?;
    }

    // 7. PID_SENTINEL
    buf[offset..offset + 4].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
    offset += 4;

    buf.truncate(offset);
    Ok(buf)
}

fn write_protocol_version(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PROTOCOL_VERSION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    // v194: Changed from 2.3 to 2.4 to match RTPS header version (v192 fix).
    // OpenDDS requires PID_PROTOCOL_VERSION to match the header version.
    buf[*offset + 4] = 2; // major
    buf[*offset + 5] = 4; // minor (RTPS 2.4 per v192)
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0;
    *offset += 8;

    Ok(())
}

fn write_vendor_id(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_VENDOR_ID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4] = 0x01; // HDDS vendor ID
    buf[*offset + 5] = 0xAA;
    buf[*offset + 6] = 0; // padding
    buf[*offset + 7] = 0;
    *offset += 8;

    Ok(())
}

fn write_participant_guid(guid: &Guid, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 20 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_GUID.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&16u16.to_le_bytes());
    buf[*offset + 4..*offset + 16].copy_from_slice(&guid.prefix);
    buf[*offset + 16..*offset + 20].copy_from_slice(&guid.entity_id);
    *offset += 20;

    Ok(())
}

fn write_builtin_endpoint_set(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // Extended builtin endpoints for RTI interop (v120)
    //
    // Value 0x000F0C3F is the "superset" that works with all vendors:
    // - Bits 0-5   (0x003F):  SPDP + SEDP announcer/detector endpoints
    // - Bits 10-11 (0x0C00):  Participant Message Writer/Reader (liveliness)
    // - Bits 16-19 (0xF0000): Participant Stateless Message endpoints
    //
    // RTI Connext REQUIRES bits 16-19, otherwise it logs
    // `subscriptionReaderListenerOnSampleLost` and refuses SEDP matching.
    //
    // FastDDS/Cyclone ignore unknown bits per RTPS spec, so this is safe.
    let endpoints: u32 = 0x000F0C3F;

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_BUILTIN_ENDPOINT_SET.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&4u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&endpoints.to_le_bytes());
    *offset += 8;

    Ok(())
}

fn write_lease_duration(sec: u32, buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    if *offset + 12 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pids::PID_PARTICIPANT_LEASE_DURATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&8u16.to_le_bytes());
    buf[*offset + 4..*offset + 8].copy_from_slice(&sec.to_le_bytes());
    buf[*offset + 8..*offset + 12].copy_from_slice(&0u32.to_le_bytes()); // fraction
    *offset += 12;

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

    // Locator_t: kind(4) + port(4) + address(16)
    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // UDPV4
    *offset += 4;

    buf[*offset..*offset + 4].copy_from_slice(&u32::from(addr.port()).to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 12].fill(0);
    *offset += 12;

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            buf[*offset..*offset + 4].copy_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            buf[*offset..*offset + 4].copy_from_slice(&ipv6.octets()[12..16]);
        }
    }
    *offset += 4;

    Ok(())
}

fn write_default_unicast_locator(
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    write_locator(pids::PID_DEFAULT_UNICAST_LOCATOR, addr, buf, offset)
}

fn write_default_multicast_locator(
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    write_locator(pids::PID_DEFAULT_MULTICAST_LOCATOR, addr, buf, offset)
}

fn write_metatraffic_unicast_locator(
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    write_locator(pids::PID_METATRAFFIC_UNICAST_LOCATOR, addr, buf, offset)
}

fn write_metatraffic_multicast_locator(
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    write_locator(pids::PID_METATRAFFIC_MULTICAST_LOCATOR, addr, buf, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_spdp_hybrid() {
        let guid = Guid {
            prefix: [0x01; 12],
            entity_id: [0x00, 0x00, 0x01, 0xc1],
        };

        let unicast = vec!["192.168.1.100:7411"
            .parse::<SocketAddr>()
            .expect("valid unicast addr")];
        let multicast = vec!["239.255.0.1:7400"
            .parse::<SocketAddr>()
            .expect("valid multicast addr")];

        let result = build_spdp(&guid, &unicast, &multicast, 100);
        assert!(result.is_ok());

        let buf = result.expect("build_spdp should succeed");

        // Verify PL_CDR_LE header
        assert_eq!(&buf[0..4], &[0x00, 0x03, 0x00, 0x00]);

        // Verify sentinel at end
        let len = buf.len();
        assert_eq!(&buf[len - 4..], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_hybrid_has_vendor_id() {
        let guid = Guid {
            prefix: [0x02; 12],
            entity_id: [0x00, 0x00, 0x01, 0xc1],
        };

        let buf = build_spdp(&guid, &[], &[], 100).expect("build_spdp should succeed");

        // Check for HDDS vendor ID (0x01AA)
        let has_hdds_vendor = buf.windows(4).any(|w| w[0] == 0x01 && w[1] == 0xAA);

        assert!(has_hdds_vendor, "Missing HDDS vendor ID");
    }
}

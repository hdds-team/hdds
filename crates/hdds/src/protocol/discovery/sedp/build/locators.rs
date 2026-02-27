// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP Locator PID Writers
//!
//! Handles encoding of network locator PIDs:
//! - PID_UNICAST_LOCATOR (0x002f) - Per-endpoint unicast locator (FastDDS compatibility)
//! - PID_METATRAFFIC_UNICAST_LOCATOR (0x0032) - Where to send metadata (unused in current impl)
//!
//! Locator Format (24 bytes):
//! - kind (u32) - LOCATOR_KIND_UDPV4 = 1, LOCATOR_KIND_UDPV6 = 2
//! - port (u32) - UDP port number
//! - address (16 bytes) - IPv4 in last 4 bytes, IPv6 uses all 16 bytes

use super::super::super::constants::PID_UNICAST_LOCATOR;
use super::super::super::types::ParseError;
use std::net::{IpAddr, SocketAddr};

/// Write PID_UNICAST_LOCATOR (0x002f) - announces where to send user data.
///
/// FastDDS expects PID_UNICAST_LOCATOR (per-endpoint) rather than the participant-level
/// PID_DEFAULT_UNICAST_LOCATOR. Encodes a SocketAddr as an RTPS Locator_t (24 bytes):
/// - kind: 1 for UDPv4, 2 for UDPv6
/// - port: UDP port (u32)
/// - address: 16 bytes (IPv4 in last 4 bytes, IPv6 uses all 16)
pub fn write_unicast_locator(
    locator: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    if *offset + 4 + 24 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&PID_UNICAST_LOCATOR.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes()); // locator size
    *offset += 4;

    // Locator_t: kind (4 bytes) + port (4 bytes) + address (16 bytes)
    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // LOCATOR_KIND_UDPV4 = 1
    *offset += 4;

    let port = u32::from(locator.port());
    buf[*offset..*offset + 4].copy_from_slice(&port.to_le_bytes());
    *offset += 4;

    // IPv4 address in last 4 bytes of 16-byte address field
    buf[*offset..*offset + 12].fill(0);
    *offset += 12;
    match locator.ip() {
        IpAddr::V4(ipv4) => {
            buf[*offset..*offset + 4].copy_from_slice(&ipv4.octets());
        }
        IpAddr::V6(_) => {
            buf[*offset..*offset + 4].fill(0);
        }
    }
    *offset += 4;

    Ok(())
}

/// Write all unicast locators from a list.
///
/// This is the primary entry point for writing locators in SEDP announcements.
/// Iterates through the provided locators and writes each as PID_UNICAST_LOCATOR (0x002f).
pub fn write_unicast_locators(
    locators: &[SocketAddr],
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    for locator in locators {
        write_unicast_locator(locator, buf, offset)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn locator_fields_use_little_endian() {
        let mut buf = [0u8; 64];
        let mut offset = 0;
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 22), 7411));

        write_unicast_locator(&addr, &mut buf, &mut offset).expect("write locator");

        assert_eq!(offset, 28);
        assert_eq!(
            &buf[0..2],
            &PID_UNICAST_LOCATOR.to_le_bytes(),
            "PID header should advertise PID_UNICAST_LOCATOR"
        );
        assert_eq!(
            u16::from_le_bytes(buf[2..4].try_into().expect("len bytes")),
            24
        );
        assert_eq!(
            u32::from_le_bytes(buf[4..8].try_into().expect("kind bytes")),
            1
        );
        assert_eq!(
            u32::from_le_bytes(buf[8..12].try_into().expect("port bytes")),
            7411
        );
        assert_eq!(
            &buf[24..28],
            &Ipv4Addr::new(192, 168, 1, 22).octets(),
            "IPv4 octets must live in the tail of the address field"
        );
    }
}

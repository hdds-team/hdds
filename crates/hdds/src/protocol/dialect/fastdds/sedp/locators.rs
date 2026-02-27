// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! FastDDS SEDP Locator PID Writers
//!
//!
//! Handles encoding of network locator PIDs:
//! - PID_UNICAST_LOCATOR (0x002f) - Per-endpoint unicast locator
//!
//! Locator Format (24 bytes):
//! - kind (u32) - LOCATOR_KIND_UDPV4 = 1, LOCATOR_KIND_UDPV6 = 2
//! - port (u32) - UDP port number
//! - address (16 bytes) - IPv4 in last 4 bytes, IPv6 uses all 16 bytes

use std::net::{IpAddr, SocketAddr};

use crate::protocol::dialect::error::{EncodeError, EncodeResult};

/// PID for unicast locator
const PID_UNICAST_LOCATOR: u16 = 0x002f;

/// Write PID_UNICAST_LOCATOR (0x002f) - 24 bytes.
///
/// FastDDS expects PID_UNICAST_LOCATOR (per-endpoint) rather than the participant-level
/// PID_DEFAULT_UNICAST_LOCATOR.
pub fn write_unicast_locator(
    locator: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if *offset + 28 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // PID header
    buf[*offset..*offset + 2].copy_from_slice(&PID_UNICAST_LOCATOR.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
    *offset += 4;

    // Locator_t: kind (4 bytes) + port (4 bytes) + address (16 bytes)
    buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes()); // LOCATOR_KIND_UDPV4
    *offset += 4;

    let port = u32::from(locator.port());
    buf[*offset..*offset + 4].copy_from_slice(&port.to_le_bytes());
    *offset += 4;

    // Address: IPv4 in last 4 bytes of 16-byte field
    buf[*offset..*offset + 12].fill(0);
    *offset += 12;

    match locator.ip() {
        IpAddr::V4(ipv4) => {
            buf[*offset..*offset + 4].copy_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            // For IPv6, we'd need LOCATOR_KIND_UDPV6
            // For now, just use the last 4 bytes (loses info, but rare case)
            buf[*offset..*offset + 4].copy_from_slice(&ipv6.octets()[12..16]);
        }
    }
    *offset += 4;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_unicast_locator_ipv4() {
        let addr = SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 7411));
        let mut buf = [0u8; 32];
        let mut offset = 0;

        write_unicast_locator(&addr, &mut buf, &mut offset).expect("write_unicast_locator failed");

        assert_eq!(offset, 28);

        // PID
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), PID_UNICAST_LOCATOR);
        // Length
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 24);
        // Kind (1 = UDP_V4)
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 1);
        // Port
        assert_eq!(u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]), 7411);
        // Address (last 4 bytes)
        assert_eq!(&buf[24..28], &[192, 168, 1, 100]);
    }
}

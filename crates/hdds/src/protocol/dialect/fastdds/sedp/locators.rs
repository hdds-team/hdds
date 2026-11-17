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

use std::net::SocketAddr;

use crate::protocol::dialect::error::{EncodeError, EncodeResult};

/// PID for unicast locator
#[cfg(test)]
const PID_UNICAST_LOCATOR: u16 = 0x002f;

/// Write PID_UNICAST_LOCATOR (0x002f) - 24 bytes.
///
/// This dialect announces each endpoint's own PID_UNICAST_LOCATOR rather than
/// relying on the participant-level PID_DEFAULT_UNICAST_LOCATOR.
pub fn write_unicast_locator(
    locator: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    crate::protocol::rtps::encode_unicast_locator(locator, buf, offset)
        .map_err(|_| EncodeError::BufferTooSmall)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

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

    #[test]
    fn test_unicast_locator_ipv6() {
        let ip = Ipv6Addr::new(
            0x2001, 0x0db8, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x1111, 0x2222,
        );
        let addr = SocketAddr::from(SocketAddrV6::new(ip, 7411, 0, 0));
        let mut buf = [0u8; 32];
        let mut offset = 0;

        write_unicast_locator(&addr, &mut buf, &mut offset).expect("write_unicast_locator failed");

        assert_eq!(offset, 28);
        assert_eq!(u16::from_le_bytes([buf[0], buf[1]]), PID_UNICAST_LOCATOR);
        assert_eq!(u16::from_le_bytes([buf[2], buf[3]]), 24);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), 2);
        assert_eq!(u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]), 7411);
        assert_eq!(&buf[12..28], &ip.octets());
    }
}

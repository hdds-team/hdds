// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Locator encoding for RTPS discovery (PID_UNICAST_LOCATOR, PID_MULTICAST_LOCATOR)
//!
//! Locators specify network addresses where participants can be reached.

use std::net::SocketAddr;

use super::{RtpsEncodeError, RtpsEncodeResult};

/// Encode one locator parameter with the supplied PID.
///
/// SPDP uses participant-level locator PIDs while SEDP uses endpoint-level
/// locator PIDs. Their 24-byte `Locator_t` payload is identical.
pub(crate) fn encode_locator_parameter(
    pid: u16,
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> RtpsEncodeResult<()> {
    if *offset + 28 > buf.len() {
        return Err(RtpsEncodeError::BufferTooSmall);
    }

    buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
    *offset += 4;

    let kind = match addr {
        SocketAddr::V4(_) => 1u32,
        SocketAddr::V6(_) => 2u32,
    };
    buf[*offset..*offset + 4].copy_from_slice(&kind.to_le_bytes());
    *offset += 4;

    buf[*offset..*offset + 4].copy_from_slice(&u32::from(addr.port()).to_le_bytes());
    *offset += 4;

    match addr {
        SocketAddr::V4(v4) => {
            buf[*offset..*offset + 12].fill(0);
            buf[*offset + 12..*offset + 16].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf[*offset..*offset + 16].copy_from_slice(&v6.ip().octets());
        }
    }
    *offset += 16;

    Ok(())
}

/// Encode a PID_UNICAST_LOCATOR parameter.
///
/// # Arguments
///
/// * `addr` - Socket address (IPv4 or IPv6)
/// * `buf` - Buffer to write to
/// * `offset` - Current offset in buffer (updated after write)
///
/// # Returns
///
/// Ok(()) on success, or error if buffer too small.
pub fn encode_unicast_locator(
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> RtpsEncodeResult<()> {
    encode_locator_parameter(0x002F, addr, buf, offset)
}

/// Encode a PID_MULTICAST_LOCATOR parameter.
///
/// # Arguments
///
/// * `addr` - Multicast socket address (IPv4 or IPv6)
/// * `buf` - Buffer to write to
/// * `offset` - Current offset in buffer (updated after write)
///
/// # Returns
///
/// Ok(()) on success, or error if buffer too small.
pub fn encode_multicast_locator(
    addr: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> RtpsEncodeResult<()> {
    encode_locator_parameter(0x0030, addr, buf, offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn test_unicast_locator_encoding() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 7410));
        let mut buf = vec![0u8; 32];
        let mut offset = 0;

        let result = encode_unicast_locator(&addr, &mut buf, &mut offset);
        assert!(result.is_ok());
        assert_eq!(offset, 28);

        // Verify PID
        let pid = u16::from_le_bytes([buf[0], buf[1]]);
        assert_eq!(pid, 0x002F);

        // Verify port
        let port = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(port, 7410);
    }

    #[test]
    fn custom_pid_preserves_ipv6_locator() {
        let ip = Ipv6Addr::new(
            0x2001, 0x0db8, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x1111, 0x2222,
        );
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, 7411, 0, 0));
        let mut buf = [0u8; 28];
        let mut offset = 0;

        encode_locator_parameter(0x0031, &addr, &mut buf, &mut offset)
            .expect("encode IPv6 locator");

        assert_eq!(offset, 28);
        assert_eq!(&buf[0..2], &0x0031u16.to_le_bytes());
        assert_eq!(&buf[2..4], &24u16.to_le_bytes());
        assert_eq!(&buf[4..8], &2u32.to_le_bytes());
        assert_eq!(&buf[8..12], &7411u32.to_le_bytes());
        assert_eq!(&buf[12..28], &ip.octets());
    }
}

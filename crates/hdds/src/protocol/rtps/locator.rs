// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Locator encoding for RTPS discovery (PID_UNICAST_LOCATOR, PID_MULTICAST_LOCATOR)
//!
//! Locators specify network addresses where participants can be reached.

use std::net::SocketAddr;

use super::{RtpsEncodeError, RtpsEncodeResult};

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
    // PID_UNICAST_LOCATOR (0x002F) - 24 bytes payload
    if *offset + 28 > buf.len() {
        return Err(RtpsEncodeError::BufferTooSmall);
    }

    // PID header
    buf[*offset..*offset + 2].copy_from_slice(&0x002Fu16.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
    *offset += 4;

    // Locator kind (1 = UDP_v4, 2 = UDP_v6)
    let kind = match addr {
        SocketAddr::V4(_) => 1u32,
        SocketAddr::V6(_) => 2u32,
    };
    buf[*offset..*offset + 4].copy_from_slice(&kind.to_le_bytes());
    *offset += 4;

    // Port
    buf[*offset..*offset + 4].copy_from_slice(&(addr.port() as u32).to_le_bytes());
    *offset += 4;

    // Address (16 bytes, IPv4 mapped to last 4 bytes)
    match addr {
        SocketAddr::V4(v4) => {
            buf[*offset..*offset + 12].copy_from_slice(&[0u8; 12]);
            buf[*offset + 12..*offset + 16].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf[*offset..*offset + 16].copy_from_slice(&v6.ip().octets());
        }
    }
    *offset += 16;

    Ok(())
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
    // PID_MULTICAST_LOCATOR (0x0030) - 24 bytes payload
    if *offset + 28 > buf.len() {
        return Err(RtpsEncodeError::BufferTooSmall);
    }

    // PID header
    buf[*offset..*offset + 2].copy_from_slice(&0x0030u16.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
    *offset += 4;

    // Locator kind
    let kind = match addr {
        SocketAddr::V4(_) => 1u32,
        SocketAddr::V6(_) => 2u32,
    };
    buf[*offset..*offset + 4].copy_from_slice(&kind.to_le_bytes());
    *offset += 4;

    // Port
    buf[*offset..*offset + 4].copy_from_slice(&(addr.port() as u32).to_le_bytes());
    *offset += 4;

    // Address
    match addr {
        SocketAddr::V4(v4) => {
            buf[*offset..*offset + 12].copy_from_slice(&[0u8; 12]);
            buf[*offset + 12..*offset + 16].copy_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            buf[*offset..*offset + 16].copy_from_slice(&v6.ip().octets());
        }
    }
    *offset += 16;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

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
}

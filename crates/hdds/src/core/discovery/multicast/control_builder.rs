// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS control message builders.

/// Build FastDDS-style Unknown\[80\] vendor-specific submessage (v141).
///
/// This submessage contains a locator that echoes the peer's unicast address back to them.
/// FastDDS includes this after HEARTBEAT for SEDP endpoints, and RTI uses it to confirm
/// where to send DATA responses.
///
/// Format (60 bytes total):
/// - Submessage header: 4 bytes (type=0x80, flags=0x01, length=56)
/// - numLocators: 4 bytes (u32 LE) = 1
/// - Locator 1: 24 bytes (port, kind, address)
/// - Locator 2 / metadata: 24 bytes (second locator or zeros)
///
/// This mirrors the FastDDS wire format observed in interop captures.
pub fn build_unknown80_locator(peer_ip: std::net::IpAddr, peer_port: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 60]; // 4 header + 56 payload

    // Submessage header
    buf[0] = 0x80; // Vendor-specific submessage ID
    buf[1] = 0x01; // Flags: Little-endian
    buf[2..4].copy_from_slice(&56u16.to_le_bytes()); // octetsToNextHeader

    // numLocators = 1
    buf[4..8].copy_from_slice(&1u32.to_le_bytes());

    // Locator 1: peer's metatraffic unicast locator
    // Port (4 bytes at offset 8)
    buf[8..12].copy_from_slice(&(peer_port as u32).to_le_bytes());

    // Locator kind (4 bytes at offset 12) - 0 for UDPv4 in FastDDS's format
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());

    // Address (16 bytes at offset 16-31)
    // IPv4 is stored in the last 4 bytes, preceded by 12 zeros
    match peer_ip {
        std::net::IpAddr::V4(v4) => {
            buf[28..32].copy_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            buf[16..32].copy_from_slice(&v6.octets());
        }
    }

    // Remaining 24 bytes (offset 32-55) are zeros in FastDDS captures
    // (possibly timestamp echo or second locator, left as zeros)

    log::trace!(
        "[v141] Built Unknown[80] locator for {}:{}",
        peer_ip,
        peer_port
    );
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_build_unknown80_locator() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let peer_port = 7410u16;

        let buf = build_unknown80_locator(peer_ip, peer_port);

        // Verify length
        assert_eq!(buf.len(), 60, "Unknown[80] should be 60 bytes");

        // Verify submessage header
        assert_eq!(buf[0], 0x80, "Submessage ID should be 0x80");
        assert_eq!(buf[1], 0x01, "Flags should be 0x01 (LE)");
        assert_eq!(
            u16::from_le_bytes([buf[2], buf[3]]),
            56,
            "Length should be 56"
        );

        // Verify numLocators
        assert_eq!(
            u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            1,
            "numLocators should be 1"
        );

        // Verify port
        assert_eq!(
            u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            7410,
            "Port should be 7410"
        );

        // Verify IP address at offset 28-31
        assert_eq!(&buf[28..32], &[192, 0, 2, 1], "IP should be 192.0.2.1");
    }

    #[test]
    fn test_build_unknown80_locator_ipv6() {
        use std::net::Ipv6Addr;

        let peer_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let peer_port = 7410u16;

        let buf = build_unknown80_locator(peer_ip, peer_port);

        // Verify length
        assert_eq!(buf.len(), 60);

        // Verify IPv6 address at offset 16-31
        let expected_ipv6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(&buf[16..32], &expected_ipv6);
    }
}

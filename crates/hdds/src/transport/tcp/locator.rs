// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TCP locator handling for RTPS discovery.
//!
//! Extends RTPS locators with TCP-specific kinds:
//! - `LOCATOR_KIND_TCPv4` (4) - TCP over IPv4
//! - `LOCATOR_KIND_TCPv6` (8) - TCP over IPv6
//!
//! These values follow vendor conventions (RTI, FastDDS use similar ranges).
//!
//! # Wire Format
//!
//! TCP locators use the standard RTPS Locator_t format:
//!
//! ```text
//! struct Locator_t {
//!     long kind;           // 4 bytes: LOCATOR_KIND_TCPv4 (4) or TCPv6 (8)
//!     unsigned long port;  // 4 bytes: TCP port number
//!     octet address[16];   // 16 bytes: IPv4 (last 4) or IPv6 address
//! };
//! ```
//!
//! # Example
//!
//! ```
//! use hdds::transport::tcp::{TcpLocator, LOCATOR_KIND_TCPV4};
//! use std::net::SocketAddr;
//!
//! let addr: SocketAddr = "192.168.1.100:7410".parse().unwrap();
//! let locator = TcpLocator::from_socket_addr(&addr);
//!
//! assert_eq!(locator.kind(), LOCATOR_KIND_TCPV4);
//! assert_eq!(locator.port(), 7410);
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

// ============================================================================
// Constants
// ============================================================================

/// Locator kind: Invalid locator.
pub const LOCATOR_KIND_INVALID: i32 = -1;

/// Locator kind: Reserved.
pub const LOCATOR_KIND_RESERVED: i32 = 0;

/// Locator kind: UDP over IPv4 (standard RTPS).
pub const LOCATOR_KIND_UDPV4: i32 = 1;

/// Locator kind: UDP over IPv6 (standard RTPS).
pub const LOCATOR_KIND_UDPV6: i32 = 2;

/// Locator kind: TCP over IPv4 (vendor extension).
///
/// Value 4 follows RTI Connext convention.
pub const LOCATOR_KIND_TCPV4: i32 = 4;

/// Locator kind: TCP over IPv6 (vendor extension).
///
/// Value 8 follows RTI Connext convention.
pub const LOCATOR_KIND_TCPV6: i32 = 8;

/// Locator kind: Shared Memory (vendor extension).
pub const LOCATOR_KIND_SHM: i32 = 16;

/// Invalid port value.
pub const LOCATOR_PORT_INVALID: u32 = 0;

/// Locator address length (16 bytes).
pub const LOCATOR_ADDRESS_LEN: usize = 16;

/// Total locator size (4 + 4 + 16 = 24 bytes).
pub const LOCATOR_SIZE: usize = 24;

// ============================================================================
// TcpLocator
// ============================================================================

/// TCP-specific locator representation.
///
/// Wraps a standard RTPS locator with TCP-specific semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TcpLocator {
    /// Locator kind (LOCATOR_KIND_TCPv4 or LOCATOR_KIND_TCPv6)
    kind: i32,

    /// TCP port number
    port: u32,

    /// Address bytes (16 bytes, IPv4 in last 4)
    address: [u8; 16],
}

impl TcpLocator {
    /// Create a new TCP locator from components.
    pub fn new(kind: i32, port: u32, address: [u8; 16]) -> Self {
        Self {
            kind,
            port,
            address,
        }
    }

    /// Create an invalid locator.
    pub fn invalid() -> Self {
        Self {
            kind: LOCATOR_KIND_INVALID,
            port: LOCATOR_PORT_INVALID,
            address: [0u8; 16],
        }
    }

    /// Create a TCPv4 locator from IPv4 address and port.
    pub fn tcp_v4(addr: Ipv4Addr, port: u16) -> Self {
        let mut address = [0u8; 16];
        // IPv4 address goes in the last 4 bytes (RTPS convention)
        address[12..16].copy_from_slice(&addr.octets());
        Self {
            kind: LOCATOR_KIND_TCPV4,
            port: port as u32,
            address,
        }
    }

    /// Create a TCPv6 locator from IPv6 address and port.
    pub fn tcp_v6(addr: Ipv6Addr, port: u16) -> Self {
        Self {
            kind: LOCATOR_KIND_TCPV6,
            port: port as u32,
            address: addr.octets(),
        }
    }

    /// Create a TCP locator from a socket address.
    pub fn from_socket_addr(addr: &SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::tcp_v4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Self::tcp_v6(*v6.ip(), v6.port()),
        }
    }

    /// Try to convert to a socket address.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self.kind {
            LOCATOR_KIND_TCPV4 => {
                let ip = Ipv4Addr::new(
                    self.address[12],
                    self.address[13],
                    self.address[14],
                    self.address[15],
                );
                Some(SocketAddr::V4(SocketAddrV4::new(ip, self.port as u16)))
            }
            LOCATOR_KIND_TCPV6 => {
                let ip = Ipv6Addr::from(self.address);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    self.port as u16,
                    0,
                    0,
                )))
            }
            _ => None,
        }
    }

    /// Get the locator kind.
    pub fn kind(&self) -> i32 {
        self.kind
    }

    /// Get the port number.
    pub fn port(&self) -> u32 {
        self.port
    }

    /// Get the raw address bytes.
    pub fn address(&self) -> &[u8; 16] {
        &self.address
    }

    /// Check if this is a valid TCP locator.
    pub fn is_valid(&self) -> bool {
        self.kind == LOCATOR_KIND_TCPV4 || self.kind == LOCATOR_KIND_TCPV6
    }

    /// Check if this is a TCPv4 locator.
    pub fn is_tcp_v4(&self) -> bool {
        self.kind == LOCATOR_KIND_TCPV4
    }

    /// Check if this is a TCPv6 locator.
    pub fn is_tcp_v6(&self) -> bool {
        self.kind == LOCATOR_KIND_TCPV6
    }

    /// Get the IP address if valid.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        match self.kind {
            LOCATOR_KIND_TCPV4 => {
                let ip = Ipv4Addr::new(
                    self.address[12],
                    self.address[13],
                    self.address[14],
                    self.address[15],
                );
                Some(IpAddr::V4(ip))
            }
            LOCATOR_KIND_TCPV6 => {
                let ip = Ipv6Addr::from(self.address);
                Some(IpAddr::V6(ip))
            }
            _ => None,
        }
    }

    /// Serialize to bytes (24 bytes, little-endian for kind/port).
    pub fn to_bytes(&self) -> [u8; LOCATOR_SIZE] {
        let mut buf = [0u8; LOCATOR_SIZE];
        buf[0..4].copy_from_slice(&(self.kind as u32).to_le_bytes());
        buf[4..8].copy_from_slice(&self.port.to_le_bytes());
        buf[8..24].copy_from_slice(&self.address);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < LOCATOR_SIZE {
            return None;
        }
        let kind = i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let port = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut address = [0u8; 16];
        address.copy_from_slice(&buf[8..24]);
        Some(Self {
            kind,
            port,
            address,
        })
    }

    /// Serialize to bytes with big-endian (network byte order).
    ///
    /// Some contexts use big-endian for locators.
    pub fn to_bytes_be(&self) -> [u8; LOCATOR_SIZE] {
        let mut buf = [0u8; LOCATOR_SIZE];
        buf[0..4].copy_from_slice(&(self.kind as u32).to_be_bytes());
        buf[4..8].copy_from_slice(&self.port.to_be_bytes());
        buf[8..24].copy_from_slice(&self.address);
        buf
    }

    /// Deserialize from big-endian bytes.
    pub fn from_bytes_be(buf: &[u8]) -> Option<Self> {
        if buf.len() < LOCATOR_SIZE {
            return None;
        }
        let kind = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let port = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let mut address = [0u8; 16];
        address.copy_from_slice(&buf[8..24]);
        Some(Self {
            kind,
            port,
            address,
        })
    }
}

impl Default for TcpLocator {
    fn default() -> Self {
        Self::invalid()
    }
}

impl From<SocketAddr> for TcpLocator {
    fn from(addr: SocketAddr) -> Self {
        Self::from_socket_addr(&addr)
    }
}

impl std::fmt::Display for TcpLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind_str = match self.kind {
            LOCATOR_KIND_INVALID => "INVALID",
            LOCATOR_KIND_RESERVED => "RESERVED",
            LOCATOR_KIND_UDPV4 => "UDPv4",
            LOCATOR_KIND_UDPV6 => "UDPv6",
            LOCATOR_KIND_TCPV4 => "TCPv4",
            LOCATOR_KIND_TCPV6 => "TCPv6",
            LOCATOR_KIND_SHM => "SHM",
            other => return write!(f, "Locator(kind={}, port={})", other, self.port),
        };

        if let Some(addr) = self.to_socket_addr() {
            write!(f, "{}:{}", kind_str, addr)
        } else {
            write!(f, "{}:port={}", kind_str, self.port)
        }
    }
}

// ============================================================================
// Locator list utilities
// ============================================================================

/// Filter TCP locators from a list of raw locator bytes.
///
/// Input: slice of 24-byte locator entries
/// Output: vector of valid TCP locators
pub fn filter_tcp_locators(locators: &[u8]) -> Vec<TcpLocator> {
    let mut result = Vec::new();
    let mut offset = 0;

    while offset + LOCATOR_SIZE <= locators.len() {
        if let Some(loc) = TcpLocator::from_bytes(&locators[offset..]) {
            if loc.is_valid() {
                result.push(loc);
            }
        }
        offset += LOCATOR_SIZE;
    }

    result
}

/// Check if a locator kind is TCP.
pub fn is_tcp_locator_kind(kind: i32) -> bool {
    kind == LOCATOR_KIND_TCPV4 || kind == LOCATOR_KIND_TCPV6
}

/// Check if a locator kind is UDP.
pub fn is_udp_locator_kind(kind: i32) -> bool {
    kind == LOCATOR_KIND_UDPV4 || kind == LOCATOR_KIND_UDPV6
}

/// Convert a UDP locator kind to the equivalent TCP kind.
pub fn udp_to_tcp_kind(kind: i32) -> i32 {
    match kind {
        LOCATOR_KIND_UDPV4 => LOCATOR_KIND_TCPV4,
        LOCATOR_KIND_UDPV6 => LOCATOR_KIND_TCPV6,
        other => other,
    }
}

/// Convert a TCP locator kind to the equivalent UDP kind.
pub fn tcp_to_udp_kind(kind: i32) -> i32 {
    match kind {
        LOCATOR_KIND_TCPV4 => LOCATOR_KIND_UDPV4,
        LOCATOR_KIND_TCPV6 => LOCATOR_KIND_UDPV6,
        other => other,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_v4_locator() {
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let locator = TcpLocator::tcp_v4(addr, 7410);

        assert_eq!(locator.kind(), LOCATOR_KIND_TCPV4);
        assert_eq!(locator.port(), 7410);
        assert!(locator.is_valid());
        assert!(locator.is_tcp_v4());
        assert!(!locator.is_tcp_v6());

        let ip = locator.ip_addr().unwrap();
        assert_eq!(ip, IpAddr::V4(addr));

        let socket_addr = locator.to_socket_addr().unwrap();
        assert_eq!(socket_addr, "192.168.1.100:7410".parse().unwrap());
    }

    #[test]
    fn test_tcp_v6_locator() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let locator = TcpLocator::tcp_v6(addr, 8080);

        assert_eq!(locator.kind(), LOCATOR_KIND_TCPV6);
        assert_eq!(locator.port(), 8080);
        assert!(locator.is_valid());
        assert!(!locator.is_tcp_v4());
        assert!(locator.is_tcp_v6());

        let ip = locator.ip_addr().unwrap();
        assert_eq!(ip, IpAddr::V6(addr));
    }

    #[test]
    fn test_from_socket_addr() {
        let v4: SocketAddr = "10.0.0.1:9000".parse().unwrap();
        let locator = TcpLocator::from_socket_addr(&v4);
        assert!(locator.is_tcp_v4());
        assert_eq!(locator.to_socket_addr().unwrap(), v4);

        let v6: SocketAddr = "[::1]:9001".parse().unwrap();
        let locator = TcpLocator::from_socket_addr(&v6);
        assert!(locator.is_tcp_v6());
        assert_eq!(locator.to_socket_addr().unwrap(), v6);
    }

    #[test]
    fn test_invalid_locator() {
        let locator = TcpLocator::invalid();
        assert!(!locator.is_valid());
        assert_eq!(locator.kind(), LOCATOR_KIND_INVALID);
        assert!(locator.to_socket_addr().is_none());
        assert!(locator.ip_addr().is_none());
    }

    #[test]
    fn test_serialization_le() {
        let locator = TcpLocator::tcp_v4(Ipv4Addr::new(192, 168, 1, 1), 7410);
        let bytes = locator.to_bytes();

        assert_eq!(bytes.len(), LOCATOR_SIZE);

        // Kind should be LOCATOR_KIND_TCPV4 = 4 (little-endian)
        assert_eq!(bytes[0..4], [4, 0, 0, 0]);

        // Port should be 7410 = 0x1CF2 (little-endian)
        assert_eq!(bytes[4..8], [0xF2, 0x1C, 0, 0]);

        // IPv4 address in last 4 bytes
        assert_eq!(bytes[20..24], [192, 168, 1, 1]);

        // Deserialize
        let recovered = TcpLocator::from_bytes(&bytes).unwrap();
        assert_eq!(recovered, locator);
    }

    #[test]
    fn test_serialization_be() {
        let locator = TcpLocator::tcp_v4(Ipv4Addr::new(192, 168, 1, 1), 7410);
        let bytes = locator.to_bytes_be();

        // Kind should be LOCATOR_KIND_TCPV4 = 4 (big-endian)
        assert_eq!(bytes[0..4], [0, 0, 0, 4]);

        // Port should be 7410 = 0x1CF2 (big-endian)
        assert_eq!(bytes[4..8], [0, 0, 0x1C, 0xF2]);

        let recovered = TcpLocator::from_bytes_be(&bytes).unwrap();
        assert_eq!(recovered, locator);
    }

    #[test]
    fn test_display() {
        let locator = TcpLocator::tcp_v4(Ipv4Addr::new(192, 168, 1, 1), 7410);
        let s = locator.to_string();
        assert!(s.contains("TCPv4"));
        assert!(s.contains("192.168.1.1"));
        assert!(s.contains("7410"));

        let invalid = TcpLocator::invalid();
        let s = invalid.to_string();
        assert!(s.contains("INVALID"));
    }

    #[test]
    fn test_filter_tcp_locators() {
        let mut data = Vec::new();

        // Add a TCPv4 locator
        let tcp = TcpLocator::tcp_v4(Ipv4Addr::new(10, 0, 0, 1), 7400);
        data.extend_from_slice(&tcp.to_bytes());

        // Add a UDPv4 locator (should be filtered out)
        let mut udp_bytes = [0u8; 24];
        udp_bytes[0..4].copy_from_slice(&1u32.to_le_bytes()); // LOCATOR_KIND_UDPV4
        udp_bytes[4..8].copy_from_slice(&7401u32.to_le_bytes());
        data.extend_from_slice(&udp_bytes);

        // Add another TCPv6 locator
        let tcp6 = TcpLocator::tcp_v6(Ipv6Addr::LOCALHOST, 7402);
        data.extend_from_slice(&tcp6.to_bytes());

        let filtered = filter_tcp_locators(&data);
        assert_eq!(filtered.len(), 2);
        assert!(filtered[0].is_tcp_v4());
        assert!(filtered[1].is_tcp_v6());
    }

    #[test]
    fn test_kind_helpers() {
        assert!(is_tcp_locator_kind(LOCATOR_KIND_TCPV4));
        assert!(is_tcp_locator_kind(LOCATOR_KIND_TCPV6));
        assert!(!is_tcp_locator_kind(LOCATOR_KIND_UDPV4));

        assert!(is_udp_locator_kind(LOCATOR_KIND_UDPV4));
        assert!(is_udp_locator_kind(LOCATOR_KIND_UDPV6));
        assert!(!is_udp_locator_kind(LOCATOR_KIND_TCPV4));

        assert_eq!(udp_to_tcp_kind(LOCATOR_KIND_UDPV4), LOCATOR_KIND_TCPV4);
        assert_eq!(udp_to_tcp_kind(LOCATOR_KIND_UDPV6), LOCATOR_KIND_TCPV6);
        assert_eq!(udp_to_tcp_kind(LOCATOR_KIND_SHM), LOCATOR_KIND_SHM);

        assert_eq!(tcp_to_udp_kind(LOCATOR_KIND_TCPV4), LOCATOR_KIND_UDPV4);
        assert_eq!(tcp_to_udp_kind(LOCATOR_KIND_TCPV6), LOCATOR_KIND_UDPV6);
    }

    #[test]
    fn test_from_trait() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let locator: TcpLocator = addr.into();
        assert!(locator.is_tcp_v4());
        assert_eq!(locator.port(), 8080);
    }

    #[test]
    fn test_default() {
        let locator = TcpLocator::default();
        assert!(!locator.is_valid());
        assert_eq!(locator.kind(), LOCATOR_KIND_INVALID);
    }

    #[test]
    fn test_hash_eq() {
        use std::collections::HashSet;

        let loc1 = TcpLocator::tcp_v4(Ipv4Addr::new(192, 168, 1, 1), 7410);
        let loc2 = TcpLocator::tcp_v4(Ipv4Addr::new(192, 168, 1, 1), 7410);
        let loc3 = TcpLocator::tcp_v4(Ipv4Addr::new(192, 168, 1, 2), 7410);

        assert_eq!(loc1, loc2);
        assert_ne!(loc1, loc3);

        let mut set = HashSet::new();
        set.insert(loc1);
        set.insert(loc2); // Should not add (duplicate)
        set.insert(loc3);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_from_bytes_short_buffer() {
        let short = [0u8; 10];
        assert!(TcpLocator::from_bytes(&short).is_none());
        assert!(TcpLocator::from_bytes_be(&short).is_none());
    }
}

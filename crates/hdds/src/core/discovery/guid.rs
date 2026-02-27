// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS GUID (Globally Unique Identifier) implementation.

use std::fmt;

/// RTPS GUID (Globally Unique Identifier)
///
/// 16-byte identifier following DDS-RTPS v2.3 spec.
///
/// # Structure
/// - Prefix: 12 bytes (host/vendor unique)
/// - Entity ID: 4 bytes (entity within participant)
///
/// # Display Format
/// Hex with dots: "01.0f.ac.10.00.00.00.00.00.00.00.01.00.00.01.c1"
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct GUID {
    pub prefix: [u8; 12],
    pub entity_id: [u8; 4],
}

impl GUID {
    /// Create GUID from raw bytes (16 bytes total)
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::GUID;
    ///
    /// let bytes = [1, 15, 172, 16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 193];
    /// let guid = GUID::from_bytes(bytes);
    /// ```
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let mut prefix = [0u8; 12];
        let mut entity_id = [0u8; 4];
        prefix.copy_from_slice(&bytes[0..12]);
        entity_id.copy_from_slice(&bytes[12..16]);
        Self { prefix, entity_id }
    }

    /// Create GUID from separate prefix and entity ID
    pub fn new(prefix: [u8; 12], entity_id: [u8; 4]) -> Self {
        Self { prefix, entity_id }
    }

    /// Convert GUID to 16-byte array
    pub fn as_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..12].copy_from_slice(&self.prefix);
        bytes[12..16].copy_from_slice(&self.entity_id);
        bytes
    }

    /// Create GUID with all zeros (invalid/placeholder)
    pub fn zero() -> Self {
        Self {
            prefix: [0; 12],
            entity_id: [0; 4],
        }
    }

    /// Check if GUID is zero (invalid)
    pub fn is_zero(&self) -> bool {
        self.prefix.iter().all(|&b| b == 0) && self.entity_id.iter().all(|&b| b == 0)
    }

    /// Create a synthetic GUID from a socket address.
    ///
    /// Used for static peer registration when the remote doesn't participate
    /// in SPDP discovery. The GUID is deterministic: same address -> same GUID.
    ///
    /// # Layout
    /// - Prefix bytes 0-3: 0xFE (static peer marker)
    /// - Prefix bytes 4-7: IP address (IPv4) or last 4 bytes (IPv6)
    /// - Prefix bytes 8-9: Port (big-endian)
    /// - Prefix bytes 10-11: 0x00 (reserved)
    /// - Entity ID: [0x00, 0x00, 0x01, 0xC1] (PARTICIPANT)
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::GUID;
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "192.168.1.100:7411".parse().unwrap();
    /// let guid = GUID::from_socket_addr(&addr);
    /// assert!(!guid.is_zero());
    /// ```
    pub fn from_socket_addr(addr: &std::net::SocketAddr) -> Self {
        let mut prefix = [0u8; 12];
        // Static peer marker
        prefix[0] = 0xFE;
        prefix[1] = 0xFE;
        prefix[2] = 0xFE;
        prefix[3] = 0xFE;

        // IP address
        match addr.ip() {
            std::net::IpAddr::V4(ipv4) => {
                prefix[4..8].copy_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                // Use last 4 bytes of IPv6 (often contains embedded IPv4)
                let octets = ipv6.octets();
                prefix[4..8].copy_from_slice(&octets[12..16]);
            }
        }

        // Port (big-endian)
        let port_bytes = addr.port().to_be_bytes();
        prefix[8] = port_bytes[0];
        prefix[9] = port_bytes[1];

        // Reserved
        prefix[10] = 0x00;
        prefix[11] = 0x00;

        // Entity ID: PARTICIPANT (per RTPS spec)
        let entity_id = [0x00, 0x00, 0x01, 0xC1];

        Self { prefix, entity_id }
    }
}

impl fmt::Display for GUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format: "01.0f.ac.10.00.00.00.00.00.00.00.01.00.00.01.c1"
        for (i, byte) in self.prefix.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        for byte in &self.entity_id {
            write!(f, ".{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for GUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GUID({})", self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid_from_bytes() {
        let bytes = [1, 15, 172, 16, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 193];
        let guid = GUID::from_bytes(bytes);

        assert_eq!(guid.prefix[0], 1);
        assert_eq!(guid.prefix[1], 15);
        assert_eq!(guid.entity_id[0], 0);
        assert_eq!(guid.entity_id[3], 193);
    }

    #[test]
    fn test_guid_display() {
        let guid = GUID::new([1, 15, 172, 16, 0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 1, 193]);
        let display = crate::core::string_utils::format_string(format_args!("{}", guid));
        assert_eq!(display, "01.0f.ac.10.00.00.00.00.00.00.00.01.00.00.01.c1");
    }

    #[test]
    fn test_guid_equality() {
        let guid1 = GUID::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], [13, 14, 15, 16]);
        let guid2 = GUID::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], [13, 14, 15, 16]);
        let guid3 = GUID::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], [13, 14, 15, 99]);

        assert_eq!(guid1, guid2);
        assert_ne!(guid1, guid3);
    }

    #[test]
    fn test_guid_as_bytes() {
        let orig = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let guid = GUID::from_bytes(orig);
        let bytes = guid.as_bytes();
        assert_eq!(orig, bytes);
    }

    #[test]
    fn test_guid_zero() {
        let guid = GUID::zero();
        assert!(guid.is_zero());

        let non_zero = GUID::new([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [0, 0, 0, 0]);
        assert!(!non_zero.is_zero());
    }
}

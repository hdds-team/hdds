// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Lite types

use core::fmt;

/// RTPS Protocol version (2.5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    /// Major version
    pub major: u8,
    /// Minor version
    pub minor: u8,
}

impl ProtocolVersion {
    /// RTPS v2.5
    pub const RTPS_2_5: Self = Self { major: 2, minor: 5 };

    /// Create a new protocol version
    pub const fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::RTPS_2_5
    }
}

/// Vendor ID (assigned by OMG)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorId(pub [u8; 2]);

impl VendorId {
    /// HDDS vendor ID (unofficial, for testing)
    pub const HDDS: Self = Self([0x01, 0x14]); // 0x0114 = 276 (unofficial)

    /// Create a new vendor ID
    pub const fn new(id: [u8; 2]) -> Self {
        Self(id)
    }
}

impl Default for VendorId {
    fn default() -> Self {
        Self::HDDS
    }
}

/// GUID Prefix (12 bytes)
///
/// Uniquely identifies a participant on the network.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuidPrefix(pub [u8; 12]);

impl GuidPrefix {
    /// Unknown GUID prefix
    pub const UNKNOWN: Self = Self([0; 12]);

    /// Create a new GUID prefix
    pub const fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl Default for GuidPrefix {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl fmt::Debug for GuidPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GuidPrefix(")?;
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

/// Entity ID (4 bytes)
///
/// Identifies a specific entity (reader/writer) within a participant.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntityId(pub [u8; 4]);

impl EntityId {
    /// Unknown entity
    pub const UNKNOWN: Self = Self([0x00, 0x00, 0x00, 0x00]);

    /// Built-in participant
    pub const PARTICIPANT: Self = Self([0x00, 0x00, 0x01, 0xc1]);

    /// Built-in SEDP publications writer
    pub const SEDP_BUILTIN_PUBLICATIONS_WRITER: Self = Self([0x00, 0x00, 0x03, 0xc2]);

    /// Built-in SEDP publications reader
    pub const SEDP_BUILTIN_PUBLICATIONS_READER: Self = Self([0x00, 0x00, 0x03, 0xc7]);

    /// Built-in SEDP subscriptions writer
    pub const SEDP_BUILTIN_SUBSCRIPTIONS_WRITER: Self = Self([0x00, 0x00, 0x04, 0xc2]);

    /// Built-in SEDP subscriptions reader
    pub const SEDP_BUILTIN_SUBSCRIPTIONS_READER: Self = Self([0x00, 0x00, 0x04, 0xc7]);

    /// Create a new entity ID
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Get bytes
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Check if this is a built-in entity
    pub const fn is_builtin(&self) -> bool {
        // Built-in entities have 0xc0 bit set in last byte
        self.0[3] & 0xc0 == 0xc0
    }

    /// Check if this is a writer entity
    pub const fn is_writer(&self) -> bool {
        // Writers have 0x02 bit set in last byte
        self.0[3] & 0x02 == 0x02
    }

    /// Check if this is a reader entity
    pub const fn is_reader(&self) -> bool {
        // Readers have 0x07 bit set in last byte
        self.0[3] & 0x07 == 0x07
    }
}

impl Default for EntityId {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl fmt::Debug for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntityId({:02x}{:02x}{:02x}{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// GUID (16 bytes) = GuidPrefix (12) + EntityId (4)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GUID {
    /// GUID prefix
    pub prefix: GuidPrefix,
    /// Entity ID
    pub entity_id: EntityId,
}

impl GUID {
    /// Unknown GUID
    pub const UNKNOWN: Self = Self {
        prefix: GuidPrefix::UNKNOWN,
        entity_id: EntityId::UNKNOWN,
    };

    /// Create a new GUID
    pub const fn new(prefix: GuidPrefix, entity_id: EntityId) -> Self {
        Self { prefix, entity_id }
    }

    /// Convert to 16-byte array
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..12].copy_from_slice(&self.prefix.0);
        bytes[12..16].copy_from_slice(&self.entity_id.0);
        bytes
    }

    /// Create from 16-byte array
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let mut prefix = [0u8; 12];
        let mut entity_id = [0u8; 4];
        prefix.copy_from_slice(&bytes[0..12]);
        entity_id.copy_from_slice(&bytes[12..16]);
        Self {
            prefix: GuidPrefix(prefix),
            entity_id: EntityId(entity_id),
        }
    }
}

impl Default for GUID {
    fn default() -> Self {
        Self::UNKNOWN
    }
}

impl fmt::Debug for GUID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GUID({:?}:{:?})", self.prefix, self.entity_id)
    }
}

/// Sequence Number (64-bit)
///
/// Monotonically increasing counter for samples.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceNumber(pub i64);

impl SequenceNumber {
    /// Unknown sequence number
    pub const UNKNOWN: Self = Self(-1);

    /// Minimum valid sequence number
    pub const MIN: Self = Self(1);

    /// Create a new sequence number
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Get the value
    pub const fn value(&self) -> i64 {
        self.0
    }

    /// Increment by 1
    pub fn increment(&mut self) {
        self.0 = self.0.saturating_add(1);
    }

    /// Get next sequence number
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl Default for SequenceNumber {
    fn default() -> Self {
        Self::MIN
    }
}

impl fmt::Debug for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SequenceNumber({})", self.0)
    }
}

impl fmt::Display for SequenceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Locator (24 bytes)
///
/// Network address for RTPS communication.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Locator {
    /// Locator kind (1 = UDPv4, 2 = UDPv6)
    pub kind: i32,
    /// Port number
    pub port: u32,
    /// IPv4/IPv6 address (16 bytes)
    pub address: [u8; 16],
}

impl Locator {
    /// Invalid locator
    pub const INVALID: Self = Self {
        kind: -1,
        port: 0,
        address: [0; 16],
    };

    /// UDPv4 locator kind
    pub const KIND_UDPV4: i32 = 1;

    /// UDPv6 locator kind
    pub const KIND_UDPV6: i32 = 2;

    /// Create a new UDPv4 locator
    pub const fn udpv4(ip: [u8; 4], port: u16) -> Self {
        let mut address = [0u8; 16];
        // IPv4-mapped IPv6 address format: ::ffff:a.b.c.d
        address[10] = 0xff;
        address[11] = 0xff;
        address[12] = ip[0];
        address[13] = ip[1];
        address[14] = ip[2];
        address[15] = ip[3];

        Self {
            kind: Self::KIND_UDPV4,
            port: port as u32,
            address,
        }
    }

    /// Check if locator is valid
    pub const fn is_valid(&self) -> bool {
        self.kind > 0 && self.port > 0
    }
}

impl Default for Locator {
    fn default() -> Self {
        Self::INVALID
    }
}

impl fmt::Debug for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.kind == Self::KIND_UDPV4 {
            write!(
                f,
                "Locator(UDPv4, {}.{}.{}.{}:{})",
                self.address[12], self.address[13], self.address[14], self.address[15], self.port
            )
        } else if self.kind == Self::KIND_UDPV6 {
            write!(f, "Locator(UDPv6, [...]:{})", self.port)
        } else {
            write!(f, "Locator(Invalid)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version() {
        let v = ProtocolVersion::RTPS_2_5;
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 5);
    }

    #[test]
    fn test_guid_prefix() {
        let prefix = GuidPrefix::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(prefix.as_bytes()[0], 1);
        assert_eq!(prefix.as_bytes()[11], 12);
    }

    #[test]
    fn test_entity_id_builtin() {
        assert!(EntityId::PARTICIPANT.is_builtin());
        assert!(EntityId::SEDP_BUILTIN_PUBLICATIONS_WRITER.is_builtin());
        assert!(!EntityId::UNKNOWN.is_builtin());
    }

    #[test]
    fn test_entity_id_writer_reader() {
        assert!(EntityId::SEDP_BUILTIN_PUBLICATIONS_WRITER.is_writer());
        assert!(EntityId::SEDP_BUILTIN_PUBLICATIONS_READER.is_reader());
    }

    #[test]
    fn test_guid_conversion() {
        let guid = GUID::new(
            GuidPrefix::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            EntityId::new([13, 14, 15, 16]),
        );

        let bytes = guid.to_bytes();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[11], 12);
        assert_eq!(bytes[12], 13);
        assert_eq!(bytes[15], 16);

        let restored = GUID::from_bytes(bytes);
        assert_eq!(restored, guid);
    }

    #[test]
    fn test_sequence_number() {
        let mut seq = SequenceNumber::new(1);
        assert_eq!(seq.value(), 1);

        seq.increment();
        assert_eq!(seq.value(), 2);

        let next = seq.next();
        assert_eq!(next.value(), 3);
        assert_eq!(seq.value(), 2); // Original unchanged
    }

    #[test]
    fn test_locator_udpv4() {
        let loc = Locator::udpv4([192, 168, 1, 100], 7400);
        assert_eq!(loc.kind, Locator::KIND_UDPV4);
        assert_eq!(loc.port, 7400);
        assert_eq!(loc.address[12], 192);
        assert_eq!(loc.address[13], 168);
        assert_eq!(loc.address[14], 1);
        assert_eq!(loc.address[15], 100);
        assert!(loc.is_valid());
    }

    #[test]
    fn test_locator_invalid() {
        let loc = Locator::INVALID;
        assert!(!loc.is_valid());
    }
}

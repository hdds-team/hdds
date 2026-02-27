// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS vendor parameter for IP mobility.
//!
//! Defines the PID_HDDS_MOBILITY parameter that is included in SPDP
//! announcements to allow peers to track mobility state.

use std::hash::{Hash, Hasher};
use std::net::IpAddr;

/// RTPS Vendor-specific Parameter ID for HDDS mobility.
///
/// Uses the vendor-specific range (0x8000 - 0xFFFF).
pub const PID_HDDS_MOBILITY: u16 = 0x8001;

/// Mobility parameter payload.
///
/// Included in SPDP announcements to enable peers to track mobility state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MobilityParameter {
    /// Mobility epoch (monotonic, incremented on each IP change).
    pub epoch: u32,

    /// Stable host ID (identifies the machine across IP changes).
    pub host_id: u64,

    /// Hash of current locators (for quick comparison).
    pub locator_hash: u32,
}

impl MobilityParameter {
    /// Create a new mobility parameter.
    pub fn new(epoch: u32, host_id: u64, locator_hash: u32) -> Self {
        Self {
            epoch,
            host_id,
            locator_hash,
        }
    }

    /// Create from current state.
    pub fn from_state(epoch: u32, host_id: u64, locators: &[IpAddr]) -> Self {
        Self {
            epoch,
            host_id,
            locator_hash: hash_locators(locators),
        }
    }

    /// Encode to bytes (little-endian).
    pub fn encode(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.epoch.to_le_bytes());
        buf[4..12].copy_from_slice(&self.host_id.to_le_bytes());
        buf[12..16].copy_from_slice(&self.locator_hash.to_le_bytes());
        buf
    }

    /// Encode to Vec for flexibility.
    pub fn encode_vec(&self) -> Vec<u8> {
        self.encode().to_vec()
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        Some(Self {
            epoch: u32::from_le_bytes(data[0..4].try_into().ok()?),
            host_id: u64::from_le_bytes(data[4..12].try_into().ok()?),
            locator_hash: u32::from_le_bytes(data[12..16].try_into().ok()?),
        })
    }

    /// Size of the encoded parameter.
    pub const fn encoded_size() -> usize {
        16
    }

    /// Check if this represents the same host as another parameter.
    pub fn same_host(&self, other: &Self) -> bool {
        self.host_id == other.host_id
    }

    /// Check if this is a newer epoch than another parameter.
    pub fn is_newer_than(&self, other: &Self) -> bool {
        // Handle wraparound using signed comparison
        let diff = self.epoch.wrapping_sub(other.epoch) as i32;
        diff > 0
    }

    /// Check if locators have changed (different hash).
    pub fn locators_changed(&self, other: &Self) -> bool {
        self.locator_hash != other.locator_hash
    }
}

/// Hash a list of locators for quick comparison.
pub fn hash_locators(locators: &[IpAddr]) -> u32 {
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();

    // Sort for deterministic hash regardless of order
    let mut sorted: Vec<_> = locators.iter().collect();
    sorted.sort_by_key(|a| match a {
        IpAddr::V4(v4) => (0, v4.octets().to_vec()),
        IpAddr::V6(v6) => (1, v6.octets().to_vec()),
    });

    for addr in sorted {
        addr.hash(&mut hasher);
    }

    // Take lower 32 bits
    hasher.finish() as u32
}

/// RTPS parameter header for vendor parameters.
#[derive(Clone, Copy, Debug)]
pub struct ParameterHeader {
    /// Parameter ID.
    pub id: u16,

    /// Parameter length (excluding header).
    pub length: u16,
}

impl ParameterHeader {
    /// Create header for mobility parameter.
    pub fn mobility() -> Self {
        Self {
            id: PID_HDDS_MOBILITY,
            length: MobilityParameter::encoded_size() as u16,
        }
    }

    /// Encode to bytes.
    pub fn encode(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&self.id.to_le_bytes());
        buf[2..4].copy_from_slice(&self.length.to_le_bytes());
        buf
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        Some(Self {
            id: u16::from_le_bytes(data[0..2].try_into().ok()?),
            length: u16::from_le_bytes(data[2..4].try_into().ok()?),
        })
    }
}

/// Encode a complete mobility parameter (header + payload).
pub fn encode_mobility_parameter(param: &MobilityParameter) -> Vec<u8> {
    let header = ParameterHeader::mobility();
    let mut buf = Vec::with_capacity(4 + 16);
    buf.extend_from_slice(&header.encode());
    buf.extend_from_slice(&param.encode());
    buf
}

/// Decode mobility parameter from RTPS parameter list.
///
/// Searches through parameters looking for PID_HDDS_MOBILITY.
pub fn find_mobility_parameter(params: &[u8]) -> Option<MobilityParameter> {
    let mut offset = 0;

    while offset + 4 <= params.len() {
        let header = ParameterHeader::decode(&params[offset..])?;
        offset += 4;

        if offset + header.length as usize > params.len() {
            break;
        }

        if header.id == PID_HDDS_MOBILITY && header.length >= 16 {
            return MobilityParameter::decode(&params[offset..]);
        }

        // Skip to next parameter (4-byte aligned)
        let padded_length = (header.length as usize + 3) & !3;
        offset += padded_length;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_mobility_parameter_new() {
        let param = MobilityParameter::new(1, 0x123456789ABCDEF0, 0xDEADBEEF);
        assert_eq!(param.epoch, 1);
        assert_eq!(param.host_id, 0x123456789ABCDEF0);
        assert_eq!(param.locator_hash, 0xDEADBEEF);
    }

    #[test]
    fn test_mobility_parameter_from_state() {
        let locators = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        let param = MobilityParameter::from_state(5, 12345, &locators);
        assert_eq!(param.epoch, 5);
        assert_eq!(param.host_id, 12345);
        assert_ne!(param.locator_hash, 0); // Should have computed hash
    }

    #[test]
    fn test_mobility_parameter_encode_decode() {
        let original = MobilityParameter::new(42, 0x123456789ABCDEF0, 0xDEADBEEF);
        let encoded = original.encode();

        assert_eq!(encoded.len(), 16);

        let decoded = MobilityParameter::decode(&encoded).expect("should decode");
        assert_eq!(decoded.epoch, original.epoch);
        assert_eq!(decoded.host_id, original.host_id);
        assert_eq!(decoded.locator_hash, original.locator_hash);
    }

    #[test]
    fn test_mobility_parameter_decode_short() {
        let short_data = [0u8; 10];
        assert!(MobilityParameter::decode(&short_data).is_none());
    }

    #[test]
    fn test_mobility_parameter_same_host() {
        let p1 = MobilityParameter::new(1, 12345, 100);
        let p2 = MobilityParameter::new(2, 12345, 200);
        let p3 = MobilityParameter::new(1, 67890, 100);

        assert!(p1.same_host(&p2));
        assert!(!p1.same_host(&p3));
    }

    #[test]
    fn test_mobility_parameter_is_newer_than() {
        let p1 = MobilityParameter::new(1, 0, 0);
        let p2 = MobilityParameter::new(2, 0, 0);
        let p3 = MobilityParameter::new(3, 0, 0);

        assert!(p2.is_newer_than(&p1));
        assert!(p3.is_newer_than(&p2));
        assert!(!p1.is_newer_than(&p2));
    }

    #[test]
    fn test_mobility_parameter_is_newer_wraparound() {
        let old = MobilityParameter::new(u32::MAX - 1, 0, 0);
        let new = MobilityParameter::new(1, 0, 0);

        // After wraparound, 1 is newer than MAX-1
        assert!(new.is_newer_than(&old));
    }

    #[test]
    fn test_mobility_parameter_locators_changed() {
        let p1 = MobilityParameter::new(1, 0, 100);
        let p2 = MobilityParameter::new(1, 0, 200);
        let p3 = MobilityParameter::new(2, 0, 100);

        assert!(p1.locators_changed(&p2));
        assert!(!p1.locators_changed(&p3));
    }

    #[test]
    fn test_mobility_parameter_default() {
        let param = MobilityParameter::default();
        assert_eq!(param.epoch, 0);
        assert_eq!(param.host_id, 0);
        assert_eq!(param.locator_hash, 0);
    }

    #[test]
    fn test_hash_locators_empty() {
        let hash = hash_locators(&[]);
        // Empty list should still produce a hash
        assert_eq!(hash, hash_locators(&[])); // Consistent
    }

    #[test]
    fn test_hash_locators_deterministic() {
        let locators = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];

        let hash1 = hash_locators(&locators);
        let hash2 = hash_locators(&locators);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_locators_order_independent() {
        let locators1 = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let locators2 = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        ];

        assert_eq!(hash_locators(&locators1), hash_locators(&locators2));
    }

    #[test]
    fn test_hash_locators_different() {
        let locators1 = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))];
        let locators2 = vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))];

        assert_ne!(hash_locators(&locators1), hash_locators(&locators2));
    }

    #[test]
    fn test_hash_locators_v4_v6() {
        let v4 = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        let v6 = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];

        assert_ne!(hash_locators(&v4), hash_locators(&v6));
    }

    #[test]
    fn test_parameter_header_mobility() {
        let header = ParameterHeader::mobility();
        assert_eq!(header.id, PID_HDDS_MOBILITY);
        assert_eq!(header.length, 16);
    }

    #[test]
    fn test_parameter_header_encode_decode() {
        let original = ParameterHeader::mobility();
        let encoded = original.encode();

        assert_eq!(encoded.len(), 4);

        let decoded = ParameterHeader::decode(&encoded).expect("should decode");
        assert_eq!(decoded.id, original.id);
        assert_eq!(decoded.length, original.length);
    }

    #[test]
    fn test_encode_mobility_parameter() {
        let param = MobilityParameter::new(1, 12345, 67890);
        let encoded = encode_mobility_parameter(&param);

        assert_eq!(encoded.len(), 20); // 4 header + 16 payload
    }

    #[test]
    fn test_find_mobility_parameter() {
        let param = MobilityParameter::new(42, 0x123456789ABCDEF0, 0xDEADBEEF);
        let encoded = encode_mobility_parameter(&param);

        let found = find_mobility_parameter(&encoded).expect("should find");
        assert_eq!(found.epoch, 42);
        assert_eq!(found.host_id, 0x123456789ABCDEF0);
    }

    #[test]
    fn test_find_mobility_parameter_not_found() {
        let data = [0u8; 32]; // No valid parameter
        assert!(find_mobility_parameter(&data).is_none());
    }

    #[test]
    fn test_find_mobility_parameter_with_other_params() {
        // Simulate other parameters before mobility
        let mut params = Vec::new();

        // Add a dummy parameter (PID=0x1234, length=8)
        params.extend_from_slice(&0x1234u16.to_le_bytes());
        params.extend_from_slice(&8u16.to_le_bytes());
        params.extend_from_slice(&[0u8; 8]); // Dummy data

        // Add mobility parameter
        let mobility = MobilityParameter::new(99, 0xABCD, 0x1234);
        params.extend(encode_mobility_parameter(&mobility));

        let found = find_mobility_parameter(&params).expect("should find");
        assert_eq!(found.epoch, 99);
    }

    #[test]
    fn test_pid_hdds_mobility_in_vendor_range() {
        // Verify PID_HDDS_MOBILITY is in vendor-specific range (0x8000-0xFFFF)
        // Upper bound check (<=0xFFFF) is implicit since PID_HDDS_MOBILITY is u16
        const {
            assert!(PID_HDDS_MOBILITY >= 0x8000);
        }
    }

    #[test]
    fn test_mobility_parameter_encoded_size() {
        assert_eq!(MobilityParameter::encoded_size(), 16);
    }
}

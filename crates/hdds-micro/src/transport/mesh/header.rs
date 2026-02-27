// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mesh packet header

use crate::error::{Error, Result};

/// Mesh header size in bytes
pub const MESH_HEADER_SIZE: usize = 7;

/// Mesh header magic byte
const MESH_MAGIC: u8 = 0x4D; // 'M' for Mesh

/// Mesh packet flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeshFlags(u8);

impl MeshFlags {
    /// No flags set
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Message requires acknowledgment
    pub const ACK_REQUIRED: Self = Self(0x01);

    /// Message is an acknowledgment
    pub const IS_ACK: Self = Self(0x02);

    /// Message is a route request
    pub const ROUTE_REQUEST: Self = Self(0x04);

    /// Message is a route reply
    pub const ROUTE_REPLY: Self = Self(0x08);

    /// Message is a beacon
    pub const BEACON: Self = Self(0x10);

    /// Check if flag is set
    pub fn contains(&self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Set a flag
    pub fn set(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    /// Clear a flag
    pub fn clear(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }

    /// Get raw value
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// Create from raw value
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }
}

/// Mesh packet header
///
/// ```text
/// +-------+-------+-------+-------+-------+---------------+
/// | Magic |  Src  |  Dst  | SeqHi | SeqLo | TTL | Flags   |
/// |  1B   |  1B   |  1B   |  1B   |  1B   | 4b  |   4b    |
/// +-------+-------+-------+-------+-------+---------------+
/// Total: 7 bytes
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshHeader {
    /// Source node ID
    pub src: u8,
    /// Destination node ID (0xFF = broadcast)
    pub dst: u8,
    /// Sequence number (for duplicate detection)
    pub seq: u16,
    /// Time-to-live (hops remaining)
    pub ttl: u8,
    /// Flags
    pub flags: MeshFlags,
    /// Hop count (how many hops traversed)
    pub hop_count: u8,
}

impl MeshHeader {
    /// Create a new mesh header
    pub fn new(src: u8, dst: u8, seq: u16, ttl: u8) -> Self {
        Self {
            src,
            dst,
            seq,
            ttl,
            flags: MeshFlags::empty(),
            hop_count: 0,
        }
    }

    /// Create a broadcast header
    pub fn broadcast(src: u8, seq: u16, ttl: u8) -> Self {
        Self::new(src, 0xFF, seq, ttl)
    }

    /// Check if this is a broadcast message
    pub fn is_broadcast(&self) -> bool {
        self.dst == 0xFF
    }

    /// Create header for relay (decrements TTL, increments hop)
    pub fn for_relay(&self) -> Option<Self> {
        if self.ttl == 0 {
            return None;
        }

        Some(Self {
            src: self.src,
            dst: self.dst,
            seq: self.seq,
            ttl: self.ttl - 1,
            flags: self.flags,
            hop_count: self.hop_count.saturating_add(1),
        })
    }

    /// Encode header to buffer
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < MESH_HEADER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        buf[0] = MESH_MAGIC;
        buf[1] = self.src;
        buf[2] = self.dst;
        buf[3] = (self.seq >> 8) as u8;
        buf[4] = (self.seq & 0xFF) as u8;
        // Pack TTL (4 bits) and hop_count (4 bits) together
        buf[5] = (self.ttl & 0x0F) | ((self.hop_count & 0x0F) << 4);
        buf[6] = self.flags.bits();

        Ok(MESH_HEADER_SIZE)
    }

    /// Decode header from buffer
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < MESH_HEADER_SIZE {
            return Err(Error::BufferTooSmall);
        }

        if buf[0] != MESH_MAGIC {
            return Err(Error::InvalidData);
        }

        let src = buf[1];
        let dst = buf[2];
        let seq = ((buf[3] as u16) << 8) | (buf[4] as u16);
        let ttl = buf[5] & 0x0F;
        let hop_count = (buf[5] >> 4) & 0x0F;
        let flags = MeshFlags::from_bits(buf[6]);

        Ok(Self {
            src,
            dst,
            seq,
            ttl,
            flags,
            hop_count,
        })
    }

    /// Get unique message ID for duplicate detection
    pub fn message_id(&self) -> u32 {
        ((self.src as u32) << 16) | (self.seq as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let header = MeshHeader {
            src: 1,
            dst: 2,
            seq: 0x1234,
            ttl: 5,
            flags: MeshFlags::empty(),
            hop_count: 2,
        };

        let mut buf = [0u8; 16];
        let len = header.encode(&mut buf).unwrap();
        assert_eq!(len, MESH_HEADER_SIZE);

        let decoded = MeshHeader::decode(&buf).unwrap();
        assert_eq!(decoded.src, 1);
        assert_eq!(decoded.dst, 2);
        assert_eq!(decoded.seq, 0x1234);
        assert_eq!(decoded.ttl, 5);
        assert_eq!(decoded.hop_count, 2);
    }

    #[test]
    fn test_header_broadcast() {
        let header = MeshHeader::broadcast(5, 100, 3);
        assert!(header.is_broadcast());
        assert_eq!(header.dst, 0xFF);
        assert_eq!(header.src, 5);
        assert_eq!(header.seq, 100);
        assert_eq!(header.ttl, 3);
    }

    #[test]
    fn test_header_for_relay() {
        let header = MeshHeader::new(1, 2, 100, 3);
        assert_eq!(header.hop_count, 0);

        let relayed = header.for_relay().unwrap();
        assert_eq!(relayed.ttl, 2);
        assert_eq!(relayed.hop_count, 1);

        // TTL 0 should not relay
        let last_hop = MeshHeader::new(1, 2, 100, 0);
        assert!(last_hop.for_relay().is_none());
    }

    #[test]
    fn test_header_buffer_too_small() {
        let header = MeshHeader::new(1, 2, 100, 3);
        let mut buf = [0u8; 4];
        assert!(header.encode(&mut buf).is_err());
    }

    #[test]
    fn test_header_invalid_magic() {
        let buf = [0x00, 1, 2, 0, 100, 3, 0];
        assert!(MeshHeader::decode(&buf).is_err());
    }

    #[test]
    fn test_flags() {
        let mut flags = MeshFlags::empty();
        assert!(!flags.contains(MeshFlags::ACK_REQUIRED));

        flags.set(MeshFlags::ACK_REQUIRED);
        assert!(flags.contains(MeshFlags::ACK_REQUIRED));

        flags.set(MeshFlags::BEACON);
        assert!(flags.contains(MeshFlags::ACK_REQUIRED));
        assert!(flags.contains(MeshFlags::BEACON));

        flags.clear(MeshFlags::ACK_REQUIRED);
        assert!(!flags.contains(MeshFlags::ACK_REQUIRED));
        assert!(flags.contains(MeshFlags::BEACON));
    }

    #[test]
    fn test_message_id() {
        let h1 = MeshHeader::new(1, 2, 100, 3);
        let h2 = MeshHeader::new(1, 2, 100, 3);
        let h3 = MeshHeader::new(1, 2, 101, 3);
        let h4 = MeshHeader::new(2, 2, 100, 3);

        assert_eq!(h1.message_id(), h2.message_id());
        assert_ne!(h1.message_id(), h3.message_id());
        assert_ne!(h1.message_id(), h4.message_id());
    }
}

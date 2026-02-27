// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Submessages
//!
//! Minimal subset for BEST_EFFORT QoS:
//! - DATA: User data
//! - HEARTBEAT: Writer liveliness
//! - ACKNACK: Reader acknowledgment (optional for RELIABLE)

use super::types::{EntityId, SequenceNumber};
use crate::error::{Error, Result};

/// Submessage kind (1 byte)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubmessageKind {
    /// DATA submessage (0x15)
    Data = 0x15,
    /// HEARTBEAT submessage (0x07)
    Heartbeat = 0x07,
    /// ACKNACK submessage (0x06)
    AckNack = 0x06,
}

impl SubmessageKind {
    /// Parse from byte
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x15 => Some(Self::Data),
            0x07 => Some(Self::Heartbeat),
            0x06 => Some(Self::AckNack),
            _ => None,
        }
    }
}

// Compile-time assertion to ensure enum discriminants are correct
const _: () = {
    assert!(
        SubmessageKind::Data as u8 == 0x15,
        "DATA submessage ID must be 0x15"
    );
    assert!(
        SubmessageKind::Heartbeat as u8 == 0x07,
        "HEARTBEAT submessage ID must be 0x07"
    );
    assert!(
        SubmessageKind::AckNack as u8 == 0x06,
        "ACKNACK submessage ID must be 0x06"
    );
};

/// Submessage flags (1 byte)
///
/// Bit 0: Endianness (0 = Big-Endian, 1 = Little-Endian)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmessageFlags(pub u8);

impl SubmessageFlags {
    /// Little-endian flag
    pub const LITTLE_ENDIAN: u8 = 0x01;

    /// Check if little-endian
    pub const fn is_little_endian(&self) -> bool {
        self.0 & Self::LITTLE_ENDIAN != 0
    }

    /// Create flags for little-endian
    pub const fn little_endian() -> Self {
        Self(Self::LITTLE_ENDIAN)
    }

    /// Create flags for big-endian
    pub const fn big_endian() -> Self {
        Self(0)
    }
}

impl Default for SubmessageFlags {
    fn default() -> Self {
        // Default to little-endian (most common)
        Self::little_endian()
    }
}

/// Submessage header (4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmessageHeader {
    /// Submessage kind
    pub kind: SubmessageKind,
    /// Flags
    pub flags: SubmessageFlags,
    /// Octets to next header (length of submessage body)
    pub octets_to_next: u16,
}

impl SubmessageHeader {
    /// Size of submessage header in bytes
    pub const SIZE: usize = 4;

    /// Create a new submessage header
    pub const fn new(kind: SubmessageKind, flags: SubmessageFlags, octets_to_next: u16) -> Self {
        Self {
            kind,
            flags,
            octets_to_next,
        }
    }

    /// Encode header to bytes (4 bytes)
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Use explicit match instead of enum cast to avoid Xtensa LLVM compiler bugs
        buf[0] = match self.kind {
            SubmessageKind::Data => 0x15,
            SubmessageKind::Heartbeat => 0x07,
            SubmessageKind::AckNack => 0x06,
        };
        buf[1] = self.flags.0;

        // Encode octets_to_next (little-endian for simplicity)
        buf[2] = (self.octets_to_next & 0xff) as u8;
        buf[3] = ((self.octets_to_next >> 8) & 0xff) as u8;

        Ok(Self::SIZE)
    }

    /// Decode header from bytes
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        let kind = SubmessageKind::from_u8(buf[0]).ok_or(Error::InvalidSubmessage)?;
        let flags = SubmessageFlags(buf[1]);

        // Decode octets_to_next (always little-endian in header)
        let octets_to_next = u16::from_le_bytes([buf[2], buf[3]]);

        Ok(Self {
            kind,
            flags,
            octets_to_next,
        })
    }
}

/// DATA submessage
///
/// Carries user data from writer to reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Data {
    /// Reader entity ID
    pub reader_id: EntityId,
    /// Writer entity ID
    pub writer_id: EntityId,
    /// Sequence number
    pub writer_sn: SequenceNumber,
}

impl Data {
    /// Minimum size (without payload)
    /// Layout: 4 (submsg header) + 2 (extraFlags) + 2 (octetsToInlineQos) + 4 (readerId) + 4 (writerId) + 8 (seqNum) = 24
    pub const MIN_SIZE: usize = 24;

    /// Create a new DATA submessage
    pub const fn new(reader_id: EntityId, writer_id: EntityId, writer_sn: SequenceNumber) -> Self {
        Self {
            reader_id,
            writer_id,
            writer_sn,
        }
    }

    /// Encode DATA submessage (header + fixed fields, no payload)
    ///
    /// Encodes per RTPS 2.3 Sec.8.3.7.2:
    /// - Submessage header: id=0x15, flags=0x05 (LE + data present), octetsToNext
    /// - extraFlags (2 bytes)
    /// - octetsToInlineQos = 16 (skip to payload after readerId+writerId+seqNum)
    /// - readerEntityId (4 bytes)
    /// - writerEntityId (4 bytes)
    /// - writerSN (8 bytes as high:i32 + low:u32)
    ///
    /// Payload should be appended separately by caller.
    pub fn encode_header(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Submessage header (4 bytes)
        // Flags: 0x05 = bit0 (LE) + bit2 (data present, no key)
        // Note: octets_to_next will be updated by caller to include payload
        let header = SubmessageHeader::new(
            SubmessageKind::Data,
            SubmessageFlags(0x05), // LE + data present
            20,                    // fixed fields size (will be updated with payload)
        );
        header.encode(&mut buf[0..4])?;

        // Extra flags (2 bytes) - reserved, set to 0
        buf[4] = 0x00;
        buf[5] = 0x00;

        // Octets to inline QoS (2 bytes)
        // Value = 16: offset from here to serialized payload (4+4+8 = entityIds + seqNum)
        buf[6] = 0x10; // 16 in LE
        buf[7] = 0x00;

        // Reader entity ID (4 bytes)
        buf[8..12].copy_from_slice(self.reader_id.as_bytes());

        // Writer entity ID (4 bytes)
        buf[12..16].copy_from_slice(self.writer_id.as_bytes());

        // Writer sequence number (8 bytes)
        // RTPS SequenceNumber_t: high (i32) + low (u32) in little-endian
        let sn = self.writer_sn.value();
        let sn_high = (sn >> 32) as i32;
        let sn_low = sn as u32;
        buf[16..20].copy_from_slice(&sn_high.to_le_bytes());
        buf[20..24].copy_from_slice(&sn_low.to_le_bytes());

        Ok(Self::MIN_SIZE)
    }

    /// Decode DATA submessage (header + fixed fields)
    ///
    /// Decodes per RTPS 2.3 Sec.8.3.7.2. Uses octetsToInlineQos to find payload.
    ///
    /// Returns (Data, payload_offset)
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Verify submessage header
        let header = SubmessageHeader::decode(&buf[0..4])?;
        if header.kind != SubmessageKind::Data {
            return Err(Error::InvalidSubmessage);
        }

        // Skip extraFlags (2 bytes at offset 4)
        // Read octetsToInlineQos (2 bytes at offset 6)
        let octets_to_inline_qos = u16::from_le_bytes([buf[6], buf[7]]) as usize;

        // Reader entity ID (4 bytes at offset 8)
        let mut reader_id_bytes = [0u8; 4];
        reader_id_bytes.copy_from_slice(&buf[8..12]);
        let reader_id = EntityId::new(reader_id_bytes);

        // Writer entity ID (4 bytes at offset 12)
        let mut writer_id_bytes = [0u8; 4];
        writer_id_bytes.copy_from_slice(&buf[12..16]);
        let writer_id = EntityId::new(writer_id_bytes);

        // Writer sequence number (8 bytes at offset 16)
        // RTPS SequenceNumber_t: high (i32) + low (u32) in little-endian
        let sn_high = i32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let sn_low = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let sn_value = ((sn_high as i64) << 32) | (sn_low as i64);
        let writer_sn = SequenceNumber::new(sn_value);

        let data = Self {
            reader_id,
            writer_id,
            writer_sn,
        };

        // Payload offset = 8 (submsg header + extraFlags + octetsToInlineQos) + octetsToInlineQos
        // Standard value: 8 + 16 = 24
        let payload_offset = 8 + octets_to_inline_qos;

        Ok((data, payload_offset))
    }
}

/// HEARTBEAT submessage
///
/// Announces writer's available sequence number range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    /// Reader entity ID
    pub reader_id: EntityId,
    /// Writer entity ID
    pub writer_id: EntityId,
    /// First available sequence number
    pub first_sn: SequenceNumber,
    /// Last available sequence number
    pub last_sn: SequenceNumber,
    /// Heartbeat count
    pub count: u32,
}

impl Heartbeat {
    /// Size of HEARTBEAT submessage
    pub const SIZE: usize = 32; // 4 (header) + 28 (fixed fields)

    /// Create a new HEARTBEAT submessage
    pub const fn new(
        reader_id: EntityId,
        writer_id: EntityId,
        first_sn: SequenceNumber,
        last_sn: SequenceNumber,
        count: u32,
    ) -> Self {
        Self {
            reader_id,
            writer_id,
            first_sn,
            last_sn,
            count,
        }
    }

    /// Encode HEARTBEAT submessage
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Submessage header
        let header =
            SubmessageHeader::new(SubmessageKind::Heartbeat, SubmessageFlags::default(), 28);
        header.encode(&mut buf[0..4])?;

        // Reader entity ID
        buf[4..8].copy_from_slice(self.reader_id.as_bytes());

        // Writer entity ID
        buf[8..12].copy_from_slice(self.writer_id.as_bytes());

        // First sequence number (8 bytes)
        let first_sn_bytes = self.first_sn.value().to_le_bytes();
        buf[12..20].copy_from_slice(&first_sn_bytes);

        // Last sequence number (8 bytes)
        let last_sn_bytes = self.last_sn.value().to_le_bytes();
        buf[20..28].copy_from_slice(&last_sn_bytes);

        // Count (4 bytes)
        let count_bytes = self.count.to_le_bytes();
        buf[28..32].copy_from_slice(&count_bytes);

        Ok(Self::SIZE)
    }

    /// Decode HEARTBEAT submessage
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Verify submessage header
        let header = SubmessageHeader::decode(&buf[0..4])?;
        if header.kind != SubmessageKind::Heartbeat {
            return Err(Error::InvalidSubmessage);
        }

        // Reader entity ID
        let mut reader_id_bytes = [0u8; 4];
        reader_id_bytes.copy_from_slice(&buf[4..8]);
        let reader_id = EntityId::new(reader_id_bytes);

        // Writer entity ID
        let mut writer_id_bytes = [0u8; 4];
        writer_id_bytes.copy_from_slice(&buf[8..12]);
        let writer_id = EntityId::new(writer_id_bytes);

        // First sequence number
        let mut first_sn_bytes = [0u8; 8];
        first_sn_bytes.copy_from_slice(&buf[12..20]);
        let first_sn = SequenceNumber::new(i64::from_le_bytes(first_sn_bytes));

        // Last sequence number
        let mut last_sn_bytes = [0u8; 8];
        last_sn_bytes.copy_from_slice(&buf[20..28]);
        let last_sn = SequenceNumber::new(i64::from_le_bytes(last_sn_bytes));

        // Count
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&buf[28..32]);
        let count = u32::from_le_bytes(count_bytes);

        Ok(Self {
            reader_id,
            writer_id,
            first_sn,
            last_sn,
            count,
        })
    }
}

/// ACKNACK submessage
///
/// Reader acknowledges received samples and requests missing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckNack {
    /// Reader entity ID
    pub reader_id: EntityId,
    /// Writer entity ID
    pub writer_id: EntityId,
    /// Base sequence number
    pub reader_sn_state_base: SequenceNumber,
    /// Count
    pub count: u32,
}

impl AckNack {
    /// Minimum size (without bitmap)
    pub const MIN_SIZE: usize = 24; // 4 (header) + 20 (fixed fields)

    /// Create a new ACKNACK submessage
    pub const fn new(
        reader_id: EntityId,
        writer_id: EntityId,
        reader_sn_state_base: SequenceNumber,
        count: u32,
    ) -> Self {
        Self {
            reader_id,
            writer_id,
            reader_sn_state_base,
            count,
        }
    }

    /// Encode ACKNACK submessage (simplified: no bitmap for embedded)
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Submessage header
        let header = SubmessageHeader::new(SubmessageKind::AckNack, SubmessageFlags::default(), 20);
        header.encode(&mut buf[0..4])?;

        // Reader entity ID
        buf[4..8].copy_from_slice(self.reader_id.as_bytes());

        // Writer entity ID
        buf[8..12].copy_from_slice(self.writer_id.as_bytes());

        // Base sequence number (8 bytes)
        let base_sn_bytes = self.reader_sn_state_base.value().to_le_bytes();
        buf[12..20].copy_from_slice(&base_sn_bytes);

        // Count (4 bytes)
        let count_bytes = self.count.to_le_bytes();
        buf[20..24].copy_from_slice(&count_bytes);

        Ok(Self::MIN_SIZE)
    }

    /// Decode ACKNACK submessage
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < Self::MIN_SIZE {
            return Err(Error::BufferTooSmall);
        }

        // Verify submessage header
        let header = SubmessageHeader::decode(&buf[0..4])?;
        if header.kind != SubmessageKind::AckNack {
            return Err(Error::InvalidSubmessage);
        }

        // Reader entity ID
        let mut reader_id_bytes = [0u8; 4];
        reader_id_bytes.copy_from_slice(&buf[4..8]);
        let reader_id = EntityId::new(reader_id_bytes);

        // Writer entity ID
        let mut writer_id_bytes = [0u8; 4];
        writer_id_bytes.copy_from_slice(&buf[8..12]);
        let writer_id = EntityId::new(writer_id_bytes);

        // Base sequence number
        let mut base_sn_bytes = [0u8; 8];
        base_sn_bytes.copy_from_slice(&buf[12..20]);
        let reader_sn_state_base = SequenceNumber::new(i64::from_le_bytes(base_sn_bytes));

        // Count
        let mut count_bytes = [0u8; 4];
        count_bytes.copy_from_slice(&buf[20..24]);
        let count = u32::from_le_bytes(count_bytes);

        Ok(Self {
            reader_id,
            writer_id,
            reader_sn_state_base,
            count,
        })
    }
}

/// Generic submessage enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Submessage {
    /// DATA submessage
    Data(Data),
    /// HEARTBEAT submessage
    Heartbeat(Heartbeat),
    /// ACKNACK submessage
    AckNack(AckNack),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submessage_header_encode_decode() {
        let header =
            SubmessageHeader::new(SubmessageKind::Data, SubmessageFlags::little_endian(), 100);

        let mut buf = [0u8; 16];
        header.encode(&mut buf).unwrap();

        let decoded = SubmessageHeader::decode(&buf).unwrap();
        assert_eq!(decoded.kind, SubmessageKind::Data);
        assert_eq!(decoded.octets_to_next, 100);
    }

    #[test]
    fn test_data_encode_decode() {
        let data = Data::new(
            EntityId::new([0, 0, 0, 1]),
            EntityId::new([0, 0, 0, 2]),
            SequenceNumber::new(42),
        );

        let mut buf = [0u8; 64];
        let written = data.encode_header(&mut buf).unwrap();
        assert_eq!(written, Data::MIN_SIZE);

        let (decoded, offset) = Data::decode(&buf).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(offset, Data::MIN_SIZE);
    }

    #[test]
    fn test_heartbeat_encode_decode() {
        let hb = Heartbeat::new(
            EntityId::new([0, 0, 0, 1]),
            EntityId::new([0, 0, 0, 2]),
            SequenceNumber::new(1),
            SequenceNumber::new(10),
            5,
        );

        let mut buf = [0u8; 64];
        let written = hb.encode(&mut buf).unwrap();
        assert_eq!(written, Heartbeat::SIZE);

        let decoded = Heartbeat::decode(&buf).unwrap();
        assert_eq!(decoded, hb);
    }

    #[test]
    fn test_acknack_encode_decode() {
        let acknack = AckNack::new(
            EntityId::new([0, 0, 0, 1]),
            EntityId::new([0, 0, 0, 2]),
            SequenceNumber::new(5),
            3,
        );

        let mut buf = [0u8; 64];
        let written = acknack.encode(&mut buf).unwrap();
        assert_eq!(written, AckNack::MIN_SIZE);

        let decoded = AckNack::decode(&buf).unwrap();
        assert_eq!(decoded, acknack);
    }
}

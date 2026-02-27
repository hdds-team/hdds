// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CONTROL stream message encoding and decoding.
//!
//! CONTROL messages are sent on stream_id=0 and handle:
//! - Session establishment (HELLO)
//! - Stream mapping (MAP_ADD, MAP_ACK, MAP_REQ)
//! - Acknowledgments (ACK, STATE_ACK)
//!
//! # Wire Format
//!
//! All CONTROL messages start with a `ctrl_type: u8` followed by type-specific fields.
//! Fields are encoded in order using varints where applicable.
//!
//! # Message Types
//!
//! | Type | Name | Description |
//! |------|------|-------------|
//! | 0x01 | HELLO | Session handshake |
//! | 0x02 | MAP_ADD | Add stream mapping |
//! | 0x03 | MAP_ACK | Acknowledge mapping |
//! | 0x04 | MAP_REQ | Request mapping info |
//! | 0x05 | ACK | Acknowledge records |
//! | 0x06 | STATE_ACK | Acknowledge state (for delta sync) |
//! | 0x07 | KEYFRAME_REQ | Request keyframe (optional) |

use super::varint::{decode_varint, decode_varint_u16, encode_varint, varint_len};

/// CONTROL message types.
pub mod ctrl_type {
    pub const HELLO: u8 = 0x01;
    pub const MAP_ADD: u8 = 0x02;
    pub const MAP_ACK: u8 = 0x03;
    pub const MAP_REQ: u8 = 0x04;
    pub const ACK: u8 = 0x05;
    pub const STATE_ACK: u8 = 0x06;
    pub const KEYFRAME_REQ: u8 = 0x07;
}

/// Feature flags for HELLO message.
pub mod features {
    /// Supports delta encoding.
    pub const DELTA: u8 = 0x01;
    /// Supports LZ4 compression.
    pub const COMPRESSION: u8 = 0x02;
    /// Supports fragmentation.
    pub const FRAGMENTATION: u8 = 0x04;
}

/// Error during CONTROL message encoding or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// Buffer too small for encoding.
    BufferTooSmall,
    /// Truncated message.
    Truncated,
    /// Unknown control message type.
    UnknownType(u8),
    /// Varint decoding error.
    VarintError,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooSmall => write!(f, "buffer too small for control message"),
            Self::Truncated => write!(f, "truncated control message"),
            Self::UnknownType(t) => write!(f, "unknown control message type: 0x{:02X}", t),
            Self::VarintError => write!(f, "varint decode error"),
        }
    }
}

impl std::error::Error for ControlError {}

// ============================================================================
// HELLO (0x01)
// ============================================================================

/// HELLO message for session establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Protocol version (should be 1).
    pub proto_ver: u8,
    /// Supported features bitmap.
    pub features: u8,
    /// Maximum transmission unit.
    pub mtu: u16,
    /// Node identifier.
    pub node_id: u8,
    /// Session identifier.
    pub session_id: u16,
    /// Mapping epoch counter.
    pub map_epoch: u16,
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            proto_ver: 1,
            features: features::DELTA | features::COMPRESSION | features::FRAGMENTATION,
            mtu: 256,
            node_id: 0,
            session_id: 0,
            map_epoch: 0,
        }
    }
}

impl Hello {
    /// Encode HELLO message.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(ControlError::BufferTooSmall);
        }

        let mut offset = 0;

        buf[offset] = ctrl_type::HELLO;
        offset += 1;

        buf[offset] = self.proto_ver;
        offset += 1;

        buf[offset] = self.features;
        offset += 1;

        offset += encode_varint(u64::from(self.mtu), &mut buf[offset..]);

        buf[offset] = self.node_id;
        offset += 1;

        offset += encode_varint(u64::from(self.session_id), &mut buf[offset..]);
        offset += encode_varint(u64::from(self.map_epoch), &mut buf[offset..]);

        Ok(offset)
    }

    /// Decode HELLO message (assumes ctrl_type already read).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        if buf.len() < 3 {
            return Err(ControlError::Truncated);
        }

        let mut offset = 0;

        let proto_ver = buf[offset];
        offset += 1;

        let features = buf[offset];
        offset += 1;

        let (mtu, mtu_len) =
            decode_varint_u16(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += mtu_len;

        if offset >= buf.len() {
            return Err(ControlError::Truncated);
        }

        let node_id = buf[offset];
        offset += 1;

        let (session_id, sid_len) =
            decode_varint_u16(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += sid_len;

        let (map_epoch, epoch_len) =
            decode_varint_u16(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += epoch_len;

        Ok((
            Self {
                proto_ver,
                features,
                mtu,
                node_id,
                session_id,
                map_epoch,
            },
            offset,
        ))
    }

    /// Calculate encoded size.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        1 // ctrl_type
        + 1 // proto_ver
        + 1 // features
        + varint_len(u64::from(self.mtu))
        + 1 // node_id
        + varint_len(u64::from(self.session_id))
        + varint_len(u64::from(self.map_epoch))
    }
}

// ============================================================================
// MAP_ADD (0x02)
// ============================================================================

/// Stream flags for MAP_ADD.
pub mod stream_flags {
    use super::super::record::Priority;

    /// Stream uses reliable delivery.
    pub const RELIABLE: u8 = 0x01;
    /// Stream uses delta encoding.
    pub const DELTA_ENABLED: u8 = 0x02;
    /// Priority mask (bits 2-3).
    pub const PRIORITY_MASK: u8 = 0x0C;
    pub const PRIORITY_SHIFT: u8 = 2;

    /// Set priority in stream flags.
    #[must_use]
    pub const fn set_priority(flags: u8, priority: Priority) -> u8 {
        (flags & !PRIORITY_MASK) | ((priority as u8) << PRIORITY_SHIFT)
    }

    /// Get priority from stream flags.
    #[must_use]
    pub const fn get_priority(flags: u8) -> Priority {
        Priority::from_bits((flags & PRIORITY_MASK) >> PRIORITY_SHIFT)
    }
}

/// MAP_ADD message to register a stream mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapAdd {
    /// Mapping epoch.
    pub epoch: u16,
    /// Stream ID to map.
    pub stream_id: u8,
    /// Topic name hash (64-bit).
    pub topic_hash: u64,
    /// Type name hash (64-bit).
    pub type_hash: u64,
    /// Stream configuration flags.
    pub stream_flags: u8,
}

impl MapAdd {
    /// Encode MAP_ADD message.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(ControlError::BufferTooSmall);
        }

        let mut offset = 0;

        buf[offset] = ctrl_type::MAP_ADD;
        offset += 1;

        offset += encode_varint(u64::from(self.epoch), &mut buf[offset..]);

        buf[offset] = self.stream_id;
        offset += 1;

        buf[offset..offset + 8].copy_from_slice(&self.topic_hash.to_le_bytes());
        offset += 8;

        buf[offset..offset + 8].copy_from_slice(&self.type_hash.to_le_bytes());
        offset += 8;

        buf[offset] = self.stream_flags;
        offset += 1;

        Ok(offset)
    }

    /// Decode MAP_ADD message (assumes ctrl_type already read).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        let mut offset = 0;

        let (epoch, epoch_len) =
            decode_varint_u16(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += epoch_len;

        if buf.len() < offset + 18 {
            // 1 + 8 + 8 + 1
            return Err(ControlError::Truncated);
        }

        let stream_id = buf[offset];
        offset += 1;

        #[allow(clippy::expect_used)] // slice length verified by bounds check above
        let topic_hash = u64::from_le_bytes(buf[offset..offset + 8].try_into().expect("8 bytes"));
        offset += 8;

        #[allow(clippy::expect_used)] // slice length verified by bounds check above
        let type_hash = u64::from_le_bytes(buf[offset..offset + 8].try_into().expect("8 bytes"));
        offset += 8;

        let stream_flags = buf[offset];
        offset += 1;

        Ok((
            Self {
                epoch,
                stream_id,
                topic_hash,
                type_hash,
                stream_flags,
            },
            offset,
        ))
    }

    /// Calculate encoded size.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        1 // ctrl_type
        + varint_len(u64::from(self.epoch))
        + 1 // stream_id
        + 8 // topic_hash
        + 8 // type_hash
        + 1 // stream_flags
    }
}

// ============================================================================
// MAP_ACK (0x03)
// ============================================================================

/// MAP_ACK message to acknowledge a stream mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapAck {
    /// Mapping epoch.
    pub epoch: u16,
    /// Stream ID acknowledged.
    pub stream_id: u8,
}

impl MapAck {
    /// Encode MAP_ACK message.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(ControlError::BufferTooSmall);
        }

        let mut offset = 0;

        buf[offset] = ctrl_type::MAP_ACK;
        offset += 1;

        offset += encode_varint(u64::from(self.epoch), &mut buf[offset..]);

        buf[offset] = self.stream_id;
        offset += 1;

        Ok(offset)
    }

    /// Decode MAP_ACK message (assumes ctrl_type already read).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        let mut offset = 0;

        let (epoch, epoch_len) =
            decode_varint_u16(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += epoch_len;

        if buf.len() < offset + 1 {
            return Err(ControlError::Truncated);
        }

        let stream_id = buf[offset];
        offset += 1;

        Ok((Self { epoch, stream_id }, offset))
    }

    /// Calculate encoded size.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        1 + varint_len(u64::from(self.epoch)) + 1
    }
}

// ============================================================================
// MAP_REQ (0x04)
// ============================================================================

/// MAP_REQ message to request mapping info for an unknown stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapReq {
    /// Mapping epoch.
    pub epoch: u16,
    /// Stream ID to request.
    pub stream_id: u8,
}

impl MapReq {
    /// Encode MAP_REQ message.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(ControlError::BufferTooSmall);
        }

        let mut offset = 0;

        buf[offset] = ctrl_type::MAP_REQ;
        offset += 1;

        offset += encode_varint(u64::from(self.epoch), &mut buf[offset..]);

        buf[offset] = self.stream_id;
        offset += 1;

        Ok(offset)
    }

    /// Decode MAP_REQ message (assumes ctrl_type already read).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        let mut offset = 0;

        let (epoch, epoch_len) =
            decode_varint_u16(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += epoch_len;

        if buf.len() < offset + 1 {
            return Err(ControlError::Truncated);
        }

        let stream_id = buf[offset];
        offset += 1;

        Ok((Self { epoch, stream_id }, offset))
    }

    /// Calculate encoded size.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        1 + varint_len(u64::from(self.epoch)) + 1
    }
}

// ============================================================================
// ACK (0x05)
// ============================================================================

/// ACK message to acknowledge received records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// Stream ID being acknowledged.
    pub stream_id: u8,
    /// Last contiguously received sequence number.
    pub last_seq: u32,
    /// Bitmask for selective ACK (reserved in v1).
    pub bitmask: u16,
}

impl Ack {
    /// Create a simple ACK (no bitmask).
    #[must_use]
    pub fn new(stream_id: u8, last_seq: u32) -> Self {
        Self {
            stream_id,
            last_seq,
            bitmask: 0,
        }
    }

    /// Encode ACK message.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(ControlError::BufferTooSmall);
        }

        let mut offset = 0;

        buf[offset] = ctrl_type::ACK;
        offset += 1;

        buf[offset] = self.stream_id;
        offset += 1;

        offset += encode_varint(u64::from(self.last_seq), &mut buf[offset..]);
        offset += encode_varint(u64::from(self.bitmask), &mut buf[offset..]);

        Ok(offset)
    }

    /// Decode ACK message (assumes ctrl_type already read).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        if buf.is_empty() {
            return Err(ControlError::Truncated);
        }

        let mut offset = 0;

        let stream_id = buf[offset];
        offset += 1;

        let (last_seq, seq_len) =
            decode_varint(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += seq_len;

        let (bitmask, bm_len) =
            decode_varint_u16(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += bm_len;

        Ok((
            Self {
                stream_id,
                last_seq: last_seq as u32,
                bitmask,
            },
            offset,
        ))
    }

    /// Calculate encoded size.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        1 // ctrl_type
        + 1 // stream_id
        + varint_len(u64::from(self.last_seq))
        + varint_len(u64::from(self.bitmask))
    }
}

// ============================================================================
// STATE_ACK (0x06)
// ============================================================================

/// STATE_ACK message to acknowledge delta state sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateAck {
    /// Stream ID.
    pub stream_id: u8,
    /// Last fully synced (keyframe) sequence.
    pub last_full_seq: u32,
}

impl StateAck {
    /// Encode STATE_ACK message.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        let size = self.encoded_size();
        if buf.len() < size {
            return Err(ControlError::BufferTooSmall);
        }

        let mut offset = 0;

        buf[offset] = ctrl_type::STATE_ACK;
        offset += 1;

        buf[offset] = self.stream_id;
        offset += 1;

        offset += encode_varint(u64::from(self.last_full_seq), &mut buf[offset..]);

        Ok(offset)
    }

    /// Decode STATE_ACK message (assumes ctrl_type already read).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        if buf.is_empty() {
            return Err(ControlError::Truncated);
        }

        let mut offset = 0;

        let stream_id = buf[offset];
        offset += 1;

        let (last_full_seq, seq_len) =
            decode_varint(&buf[offset..]).map_err(|_| ControlError::VarintError)?;
        offset += seq_len;

        Ok((
            Self {
                stream_id,
                last_full_seq: last_full_seq as u32,
            },
            offset,
        ))
    }

    /// Calculate encoded size.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        1 + 1 + varint_len(u64::from(self.last_full_seq))
    }
}

// ============================================================================
// KEYFRAME_REQ (0x07) - Optional
// ============================================================================

/// KEYFRAME_REQ message to request a keyframe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyframeReq {
    /// Stream ID to request keyframe for.
    pub stream_id: u8,
}

impl KeyframeReq {
    /// Encode KEYFRAME_REQ message.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        if buf.len() < 2 {
            return Err(ControlError::BufferTooSmall);
        }

        buf[0] = ctrl_type::KEYFRAME_REQ;
        buf[1] = self.stream_id;
        Ok(2)
    }

    /// Decode KEYFRAME_REQ message (assumes ctrl_type already read).
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        if buf.is_empty() {
            return Err(ControlError::Truncated);
        }

        Ok((Self { stream_id: buf[0] }, 1))
    }

    /// Calculate encoded size.
    #[must_use]
    pub const fn encoded_size(&self) -> usize {
        2
    }
}

// ============================================================================
// Unified ControlMessage enum
// ============================================================================

/// Unified CONTROL message type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    Hello(Hello),
    MapAdd(MapAdd),
    MapAck(MapAck),
    MapReq(MapReq),
    Ack(Ack),
    StateAck(StateAck),
    KeyframeReq(KeyframeReq),
}

impl ControlMessage {
    /// Encode control message to buffer.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, ControlError> {
        match self {
            Self::Hello(m) => m.encode(buf),
            Self::MapAdd(m) => m.encode(buf),
            Self::MapAck(m) => m.encode(buf),
            Self::MapReq(m) => m.encode(buf),
            Self::Ack(m) => m.encode(buf),
            Self::StateAck(m) => m.encode(buf),
            Self::KeyframeReq(m) => m.encode(buf),
        }
    }

    /// Decode control message from buffer.
    // @audit-ok: Simple pattern matching (cyclo 17, cogni 2) - control type dispatch to message decoders
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ControlError> {
        if buf.is_empty() {
            return Err(ControlError::Truncated);
        }

        let ctrl_type = buf[0];
        let payload = &buf[1..];

        match ctrl_type {
            ctrl_type::HELLO => {
                let (msg, len) = Hello::decode(payload)?;
                Ok((Self::Hello(msg), 1 + len))
            }
            ctrl_type::MAP_ADD => {
                let (msg, len) = MapAdd::decode(payload)?;
                Ok((Self::MapAdd(msg), 1 + len))
            }
            ctrl_type::MAP_ACK => {
                let (msg, len) = MapAck::decode(payload)?;
                Ok((Self::MapAck(msg), 1 + len))
            }
            ctrl_type::MAP_REQ => {
                let (msg, len) = MapReq::decode(payload)?;
                Ok((Self::MapReq(msg), 1 + len))
            }
            ctrl_type::ACK => {
                let (msg, len) = Ack::decode(payload)?;
                Ok((Self::Ack(msg), 1 + len))
            }
            ctrl_type::STATE_ACK => {
                let (msg, len) = StateAck::decode(payload)?;
                Ok((Self::StateAck(msg), 1 + len))
            }
            ctrl_type::KEYFRAME_REQ => {
                let (msg, len) = KeyframeReq::decode(payload)?;
                Ok((Self::KeyframeReq(msg), 1 + len))
            }
            _ => Err(ControlError::UnknownType(ctrl_type)),
        }
    }

    /// Calculate encoded size.
    #[must_use]
    pub fn encoded_size(&self) -> usize {
        match self {
            Self::Hello(m) => m.encoded_size(),
            Self::MapAdd(m) => m.encoded_size(),
            Self::MapAck(m) => m.encoded_size(),
            Self::MapReq(m) => m.encoded_size(),
            Self::Ack(m) => m.encoded_size(),
            Self::StateAck(m) => m.encoded_size(),
            Self::KeyframeReq(m) => m.encoded_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let hello = Hello {
            proto_ver: 1,
            features: features::DELTA | features::COMPRESSION,
            mtu: 512,
            node_id: 42,
            session_id: 1000,
            map_epoch: 5,
        };

        let mut buf = [0u8; 64];
        let encoded_len = hello.encode(&mut buf).expect("encode");

        // Verify ctrl_type
        assert_eq!(buf[0], ctrl_type::HELLO);

        // Decode
        let (decoded, decoded_len) = Hello::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, hello);
    }

    #[test]
    fn test_map_add_roundtrip() {
        let map_add = MapAdd {
            epoch: 1,
            stream_id: 5,
            topic_hash: 0x123456789ABCDEF0,
            type_hash: 0xFEDCBA9876543210,
            stream_flags: stream_flags::RELIABLE | stream_flags::DELTA_ENABLED,
        };

        let mut buf = [0u8; 64];
        let encoded_len = map_add.encode(&mut buf).expect("encode");

        assert_eq!(buf[0], ctrl_type::MAP_ADD);

        let (decoded, decoded_len) = MapAdd::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, map_add);
    }

    #[test]
    fn test_map_ack_roundtrip() {
        let map_ack = MapAck {
            epoch: 100,
            stream_id: 10,
        };

        let mut buf = [0u8; 64];
        let encoded_len = map_ack.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = MapAck::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, map_ack);
    }

    #[test]
    fn test_ack_roundtrip() {
        let ack = Ack {
            stream_id: 5,
            last_seq: 12345,
            bitmask: 0,
        };

        let mut buf = [0u8; 64];
        let encoded_len = ack.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = Ack::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, ack);
    }

    #[test]
    fn test_state_ack_roundtrip() {
        let state_ack = StateAck {
            stream_id: 3,
            last_full_seq: 999,
        };

        let mut buf = [0u8; 64];
        let encoded_len = state_ack.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = StateAck::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, state_ack);
    }

    #[test]
    fn test_keyframe_req_roundtrip() {
        let req = KeyframeReq { stream_id: 7 };

        let mut buf = [0u8; 64];
        let encoded_len = req.encode(&mut buf).expect("encode");

        let (decoded, decoded_len) = KeyframeReq::decode(&buf[1..encoded_len]).expect("decode");
        assert_eq!(decoded_len + 1, encoded_len);
        assert_eq!(decoded, req);
    }

    #[test]
    fn test_control_message_unified() {
        let messages: Vec<ControlMessage> = vec![
            ControlMessage::Hello(Hello::default()),
            ControlMessage::MapAdd(MapAdd {
                epoch: 1,
                stream_id: 1,
                topic_hash: 123,
                type_hash: 456,
                stream_flags: 0,
            }),
            ControlMessage::MapAck(MapAck {
                epoch: 1,
                stream_id: 1,
            }),
            ControlMessage::MapReq(MapReq {
                epoch: 1,
                stream_id: 1,
            }),
            ControlMessage::Ack(Ack::new(1, 100)),
            ControlMessage::StateAck(StateAck {
                stream_id: 1,
                last_full_seq: 50,
            }),
            ControlMessage::KeyframeReq(KeyframeReq { stream_id: 1 }),
        ];

        for msg in messages {
            let mut buf = [0u8; 64];
            let encoded_len = msg.encode(&mut buf).expect("encode");

            let (decoded, decoded_len) =
                ControlMessage::decode(&buf[..encoded_len]).expect("decode");
            assert_eq!(decoded_len, encoded_len);
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn test_unknown_ctrl_type() {
        let buf = [0xFF, 0x00, 0x00];
        assert_eq!(
            ControlMessage::decode(&buf),
            Err(ControlError::UnknownType(0xFF))
        );
    }

    #[test]
    fn test_stream_flags_priority() {
        use super::super::record::Priority;

        let flags = stream_flags::set_priority(0, Priority::P0);
        assert_eq!(stream_flags::get_priority(flags), Priority::P0);

        let flags = stream_flags::set_priority(stream_flags::RELIABLE, Priority::P2);
        assert_eq!(stream_flags::get_priority(flags), Priority::P2);
        assert_eq!(flags & stream_flags::RELIABLE, stream_flags::RELIABLE);
    }

    #[test]
    fn test_buffer_too_small() {
        let hello = Hello::default();
        let mut buf = [0u8; 2]; // Too small
        assert_eq!(hello.encode(&mut buf), Err(ControlError::BufferTooSmall));
    }

    #[test]
    fn test_truncated_decode() {
        // Empty buffer
        assert_eq!(ControlMessage::decode(&[]), Err(ControlError::Truncated));

        // Just ctrl_type, no payload
        assert_eq!(
            ControlMessage::decode(&[ctrl_type::HELLO]),
            Err(ControlError::Truncated)
        );
    }
}

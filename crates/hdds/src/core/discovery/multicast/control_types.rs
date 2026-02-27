// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Control message data types for RTPS protocol messages.

use std::net::SocketAddr;

/// Maximum size of a control message (HEARTBEAT = 28 bytes + headers)
/// v190: Increased from 128 to 256 to handle OpenDDS HEARTBEATs (132-216 bytes)
pub const CONTROL_MSG_MAX_SIZE: usize = 256;

/// Control message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlMessageKind {
    /// HEARTBEAT from remote writer
    Heartbeat,
    /// ACKNACK from remote reader (informational)
    AckNack,
    /// GAP from remote writer
    Gap,
    /// NACK_FRAG from remote reader (fragment retransmission request)
    NackFrag,
}

/// Parsed HEARTBEAT data for batching
#[derive(Debug, Clone)]
pub struct HeartbeatInfo {
    /// Writer entity ID (4 bytes)
    pub writer_entity_id: [u8; 4],
    /// First available sequence number
    pub first_seq: i64,
    /// Last sequence number
    pub last_seq: i64,
    /// HEARTBEAT count (for duplicate detection)
    pub count: u32,
    /// FinalFlag - writer expects immediate ACKNACK
    pub final_flag: bool,
    /// LivelinessFlag - liveliness assertion only
    pub liveliness_flag: bool,
}

/// Parsed ACKNACK data for v137 SEDP response and v202 user data retransmission
#[derive(Debug, Clone)]
pub struct AckNackInfo {
    /// Reader entity ID (4 bytes) - what they're reading FROM
    pub reader_entity_id: [u8; 4],
    /// Writer entity ID (4 bytes) - what they want us to write TO
    pub writer_entity_id: [u8; 4],
    /// v202: Missing sequence ranges extracted from RTPS ACKNACK bitmap.
    /// Format: Vec of [start..end) ranges where end is exclusive.
    /// Empty if reader has received all sequences (pure ACK).
    pub missing_ranges: Vec<std::ops::Range<u64>>,
}

/// Parsed NACK_FRAG data for fragment retransmission (RTPS v2.3 Sec.8.3.7.5)
#[derive(Debug, Clone)]
pub struct NackFragInfo {
    /// Reader entity ID (4 bytes) - reader requesting fragments
    pub reader_entity_id: [u8; 4],
    /// Writer entity ID (4 bytes) - writer to retransmit from
    pub writer_entity_id: [u8; 4],
    /// Sequence number of the fragmented message
    pub writer_sn: u64,
    /// Missing fragment numbers (1-based, as per RTPS spec)
    pub missing_fragments: Vec<u32>,
    /// NACK_FRAG count (for duplicate detection)
    pub count: u32,
}

/// Control message passed through the channel (stack-allocated, no pool)
#[derive(Clone)]
pub struct ControlMessage {
    /// Message kind
    pub kind: ControlMessageKind,
    /// Source address
    pub src_addr: SocketAddr,
    /// Peer GUID prefix (12 bytes, extracted from RTPS header)
    pub peer_guid_prefix: [u8; 12],
    /// Parsed HEARTBEAT info (if kind == Heartbeat)
    pub heartbeat: Option<HeartbeatInfo>,
    /// Parsed ACKNACK info (if kind == AckNack)
    pub acknack: Option<AckNackInfo>,
    /// Parsed NACK_FRAG info (if kind == NackFrag)
    pub nack_frag: Option<NackFragInfo>,
    /// Raw message bytes (stack buffer, no allocation)
    data: [u8; CONTROL_MSG_MAX_SIZE],
    /// Actual length of data
    len: usize,
}

impl ControlMessage {
    /// Create a new control message from raw packet data
    pub fn new(kind: ControlMessageKind, src_addr: SocketAddr, packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 || packet.len() > CONTROL_MSG_MAX_SIZE {
            return None;
        }

        // Extract peer GUID prefix from RTPS header
        let mut peer_guid_prefix = [0u8; 12];
        peer_guid_prefix.copy_from_slice(&packet[8..20]);

        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        data[..packet.len()].copy_from_slice(packet);

        Some(Self {
            kind,
            src_addr,
            peer_guid_prefix,
            heartbeat: None,
            acknack: None,
            nack_frag: None,
            data,
            len: packet.len(),
        })
    }

    /// Create a HEARTBEAT control message with parsed info
    pub fn heartbeat(
        src_addr: SocketAddr,
        peer_guid_prefix: [u8; 12],
        info: HeartbeatInfo,
        packet: &[u8],
    ) -> Option<Self> {
        if packet.len() > CONTROL_MSG_MAX_SIZE {
            return None;
        }

        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        let len = packet.len().min(CONTROL_MSG_MAX_SIZE);
        data[..len].copy_from_slice(&packet[..len]);

        Some(Self {
            kind: ControlMessageKind::Heartbeat,
            src_addr,
            peer_guid_prefix,
            heartbeat: Some(info),
            acknack: None,
            nack_frag: None,
            data,
            len,
        })
    }

    /// Create an ACKNACK control message with parsed info (v137)
    pub fn acknack(
        src_addr: SocketAddr,
        peer_guid_prefix: [u8; 12],
        info: AckNackInfo,
        packet: &[u8],
    ) -> Option<Self> {
        if packet.len() > CONTROL_MSG_MAX_SIZE {
            return None;
        }

        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        let len = packet.len().min(CONTROL_MSG_MAX_SIZE);
        data[..len].copy_from_slice(&packet[..len]);

        Some(Self {
            kind: ControlMessageKind::AckNack,
            src_addr,
            peer_guid_prefix,
            heartbeat: None,
            acknack: Some(info),
            nack_frag: None,
            data,
            len,
        })
    }

    /// Create a NACK_FRAG control message with parsed info
    pub fn nack_frag(
        src_addr: SocketAddr,
        peer_guid_prefix: [u8; 12],
        info: NackFragInfo,
        packet: &[u8],
    ) -> Option<Self> {
        if packet.len() > CONTROL_MSG_MAX_SIZE {
            return None;
        }

        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        let len = packet.len().min(CONTROL_MSG_MAX_SIZE);
        data[..len].copy_from_slice(&packet[..len]);

        Some(Self {
            kind: ControlMessageKind::NackFrag,
            src_addr,
            peer_guid_prefix,
            heartbeat: None,
            acknack: None,
            nack_frag: Some(info),
            data,
            len,
        })
    }

    /// Get raw packet data
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl std::fmt::Debug for ControlMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlMessage")
            .field("kind", &self.kind)
            .field("src_addr", &self.src_addr)
            .field("len", &self.len)
            .field("heartbeat", &self.heartbeat)
            .finish()
    }
}

/// Writer state for HEARTBEAT batching
#[derive(Debug)]
pub struct WriterState {
    /// First available sequence number (for NACK range)
    pub first_seq: i64,
    /// Highest sequence number seen
    pub highest_seq: i64,
    /// Last HEARTBEAT count (for duplicate detection)
    pub last_count: u32,
    /// Peer IP address for ACKNACK responses
    pub peer_ip: std::net::IpAddr,
    /// v196: Peer port for ACKNACK responses (from HEARTBEAT source)
    pub peer_port: u16,
    /// Peer GUID prefix (needed for ACKNACK packet)
    pub peer_guid_prefix: [u8; 12],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_message_size() {
        // Verify ControlMessage fits in L2 cache line (512 bytes)
        assert!(
            std::mem::size_of::<ControlMessage>() <= 512,
            "ControlMessage should be compact"
        );
    }
}

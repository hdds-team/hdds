// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Packet metadata types for RTPS classification and routing.
//!
//!
//! Defines `PacketKind` for RTPS submessage types (RTPS v2.3 Table 8.13),
//! `RtpsContext` for stateful parsing (INFO_DST/INFO_TS), and `RxMeta`
//! for passing packet metadata through the listener-to-FSM pipeline.

use crate::core::discovery::GUID;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::time::Instant;

/// Packet classification for RTPS protocol
///
/// Maps RTPS submessage IDs to packet types per RTPS v2.3 Table 8.13.
/// Extended for full RTPS support (not just discovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// DATA submessage (0x15) - contains serialized data
    Data,
    /// HEARTBEAT submessage (0x07) - reliable QoS heartbeat
    Heartbeat,
    /// ACKNACK submessage (0x06) - acknowledgment/negative acknowledgment
    AckNack,
    /// DATA_FRAG submessage (0x16) - fragmented data
    DataFrag,
    /// GAP submessage (0x08) - indicates missing sequence numbers
    Gap,
    /// NACK_FRAG submessage (0x12) - request retransmission of specific fragments
    NackFrag,
    /// HEARTBEAT_FRAG submessage (0x13) - fragment-level heartbeat for reliable fragmented data
    HeartbeatFrag,
    /// INFO_TS submessage (0x09) - timestamp information
    InfoTs,
    /// INFO_SRC submessage (0x0c) - source GUID prefix
    InfoSrc,
    /// INFO_DST submessage (0x0e) - destination GUID prefix
    InfoDst,
    /// INFO_REPLY submessage (0x0f) - unicast reply locator list
    InfoReply,
    /// PAD submessage (0x01) - padding to alignment boundary
    Pad,
    /// Custom: SPDP participant discovery (DATA with specific topic)
    SPDP,
    /// Custom: SEDP endpoint discovery (DATA with endpoint info)
    SEDP,
    /// Custom: TypeLookup (XTypes request/reply)
    TypeLookup,
    /// Invalid packet (malformed RTPS header)
    Invalid,
    /// Unknown submessage ID (not handled)
    Unknown,
}

/// RTPS Context State for stateful parsing (v61 Blocker #1)
///
/// INFO_DST and INFO_TS submessages set context for subsequent submessages
/// in the same RTPS message (RTPS v2.5 Sec.8.3.7.5, Sec.8.3.7.7).
///
/// This context must be maintained while scanning submessages and applied
/// to DATA/HEARTBEAT/etc when they are processed.
#[derive(Debug, Clone, Copy, Default)]
pub struct RtpsContext {
    /// Destination GUID prefix from INFO_DST (0x0e)
    ///
    /// When present, subsequent submessages are directed to this participant.
    /// None = broadcast/multicast (all participants).
    pub destination_guid_prefix: Option<[u8; 12]>,

    /// Source timestamp from INFO_TS (0x09)
    ///
    /// Timestamp applied to subsequent DATA submessages.
    /// Encoded as RTPS Time_t (seconds + fraction).
    pub source_timestamp: Option<(i32, u32)>, // (seconds, fraction)
}

/// Fragment metadata for DATA_FRAG submessages (RTPS v2.3 Sec.8.3.7.4)
#[derive(Debug, Clone, Copy)]
pub struct FragmentMetadata {
    /// Writer GUID (from RTPS header GUID prefix + writerEntityId)
    pub writer_guid: GUID,
    /// Sequence number
    pub seq_num: u64,
    /// Fragment number (1-based)
    pub frag_num: u32,
    /// Total number of fragments
    pub total_frags: u16,
}

/// Minimal metadata for received multicast packet
///
/// Stored in RxRing alongside BufferId. Total size ~48 bytes (v61: added rtps_context).
/// Designed for lock-free SPSC queue passing from listener thread to FSM.
#[derive(Debug, Clone, Copy)]
pub struct RxMeta {
    /// Source socket address (IPv4 or IPv6)
    pub sock: SocketAddr,
    /// Payload length in bytes (capped at u16::MAX = 65535)
    pub len: u16,
    /// Timestamp when packet was received (for latency tracking)
    pub ts: Instant,
    /// Classified packet type
    pub kind: PacketKind,
    /// Offset to DATA submessage payload (for RTI vendor-specific headers)
    /// None for standard HDDS packets, Some(offset) after recovery
    pub data_payload_offset: Option<u16>,
    /// Fragment metadata (only for PacketKind::DataFrag)
    pub frag_meta: Option<FragmentMetadata>,
    /// v61 Blocker #1: RTPS context state (INFO_DST/INFO_TS)
    ///
    /// Accumulated from INFO_DST and INFO_TS submessages while scanning.
    /// Applied to DATA/HEARTBEAT submessages for correct routing and timestamps.
    pub rtps_context: RtpsContext,
}

impl RxMeta {
    /// Create new RxMeta from received packet
    ///
    /// # Arguments
    /// - `sock`: Source address from `recv_from()`
    /// - `len`: Payload length (will be capped to u16::MAX if larger)
    /// - `kind`: Classified packet type
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::multicast::{RxMeta, PacketKind};
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:7400".parse()
    ///     .expect("Socket address parsing should succeed");
    /// let meta = RxMeta::new(addr, 512, PacketKind::SPDP);
    /// assert_eq!(meta.len, 512);
    /// assert_eq!(meta.kind, PacketKind::SPDP);
    /// ```
    pub fn new(sock: SocketAddr, len: usize, kind: PacketKind) -> Self {
        let len = u16::try_from(len).unwrap_or(u16::MAX);

        Self {
            sock,
            len,
            ts: Instant::now(),
            kind,
            data_payload_offset: None,
            frag_meta: None,
            rtps_context: RtpsContext::default(), // v61: Initialize empty context
        }
    }

    /// Create new RxMeta with explicit DATA payload offset
    ///
    /// Used when classifier recovery finds DATA submessage at non-standard offset
    /// (e.g., RTI packets with vendor-specific headers)
    pub fn new_with_offset(sock: SocketAddr, len: usize, kind: PacketKind, offset: usize) -> Self {
        let len = u16::try_from(len).unwrap_or(u16::MAX);

        let offset = u16::try_from(offset).ok();

        Self {
            sock,
            len,
            ts: Instant::now(),
            kind,
            data_payload_offset: offset,
            frag_meta: None,
            rtps_context: RtpsContext::default(), // v61
        }
    }

    /// Create new RxMeta with fragment metadata (for DATA_FRAG packets)
    pub fn new_with_fragment(
        sock: SocketAddr,
        len: usize,
        kind: PacketKind,
        offset: usize,
        frag_meta: FragmentMetadata,
    ) -> Self {
        let len = u16::try_from(len).unwrap_or(u16::MAX);

        let offset = u16::try_from(offset).ok();

        Self {
            sock,
            len,
            ts: Instant::now(),
            kind,
            data_payload_offset: offset,
            frag_meta: Some(frag_meta),
            rtps_context: RtpsContext::default(), // v61
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_kind_variants() {
        // Verify PacketKind variants exist (RTPS v2.3 Table 8.13)
        let _ = PacketKind::Data;
        let _ = PacketKind::Heartbeat;
        let _ = PacketKind::AckNack;
        let _ = PacketKind::DataFrag;
        let _ = PacketKind::Gap;
        let _ = PacketKind::NackFrag;
        let _ = PacketKind::HeartbeatFrag;
        let _ = PacketKind::InfoTs;
        let _ = PacketKind::InfoSrc;
        let _ = PacketKind::InfoDst;
        let _ = PacketKind::InfoReply;
        let _ = PacketKind::Pad;
        let _ = PacketKind::SPDP;
        let _ = PacketKind::SEDP;
        let _ = PacketKind::TypeLookup;
        let _ = PacketKind::Invalid;
        let _ = PacketKind::Unknown;
    }

    #[test]
    fn test_rx_meta_creation() {
        let addr: SocketAddr = "192.168.1.100:7400"
            .parse()
            .expect("Socket address parsing should succeed");
        let meta = RxMeta::new(addr, 1024, PacketKind::Data);

        assert_eq!(meta.sock, addr);
        assert_eq!(meta.len, 1024);
        assert_eq!(meta.kind, PacketKind::Data);
    }

    #[test]
    fn test_rx_meta_len_overflow() {
        // Test that len > u16::MAX is capped
        let addr: SocketAddr = "127.0.0.1:7400"
            .parse()
            .expect("Socket address parsing should succeed");
        let meta = RxMeta::new(addr, 70000, PacketKind::Heartbeat);

        assert_eq!(meta.len, u16::MAX);
    }

    #[test]
    fn test_rx_meta_size() {
        // Ensure RxMeta fits in expected memory budget
        // SocketAddr (28 bytes max) + u16 (2) + Instant (12) + PacketKind (1) +
        // Option<u16> (4) + Option<FragmentMetadata> (48) + RtpsContext (28) + padding
        let size = std::mem::size_of::<RxMeta>();
        println!("RxMeta size: {} bytes", size);
        assert!(size <= 140); // v61: Increased to accommodate RtpsContext (128 bytes actual)
    }
}

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
use std::net::{SocketAddr, SocketAddrV4};
use std::time::Instant;

/// Where an RTPS message came from, and where a reply to it may go.
///
/// RTPS 2.5 8.3.4 (receiver initial state): the receiver's reply locator
/// starts as the datagram's source address. RTPS 2.5 8.3.8.10 (InfoSource):
/// an INFO_SRC sets it to LOCATOR_INVALID for the submessages behind it.
/// A submessage that follows an INFO_SRC therefore has no reply address:
/// the datagram's actual sender (a forwarder, relay, or router) must never
/// be used as, or to derive, a locator for the participant the INFO_SRC
/// names.
///
/// RTPS 2.5 8.3.8.9 (InfoReply) and 9.4.5.15 (InfoReplyIp4): an INFO_REPLY
/// replaces the Receiver's reply locators for the submessages that follow
/// it in the same message (`receiver_reply_locator`). The spec reads them
/// in ONE place: the Reliable StatelessWriter answering an ACKNACK
/// (8.4.8.2.6, T6/T8: "This is the only source of information for the
/// StatelessWriter to determine where to send the reply to"). Stateful
/// endpoints answer through the proxy of the matched endpoint and its
/// DISCOVERED locators (ReaderProxy 8.4.7.5, WriterProxy 8.4.10.4; 8.4.9.2,
/// 8.4.12.2), so an INFO_REPLY never redirects them: `reply` ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    from: SocketAddr,
    reply: Reply,
}

/// The receiver's reply locator for one message (RTPS 2.5 Table 8.17,
/// `unicastReplyLocatorList` / `multicastReplyLocatorList`), reduced to the
/// one destination a reply uses, as a walk of the message decides it.
///
/// Only UDPv4 is carried: it is the only kind a reply here is ever sent on
/// (the SPDP locator parser skips UDPv6 for the same reason), and a 6-octet
/// address keeps `RxMeta` within its budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReplyTo {
    /// The datagram's sender (8.3.4 initial state).
    Sender,
    /// LOCATOR_INVALID: behind an INFO_SRC (8.3.8.10), or behind an
    /// INFO_REPLY that named no locator this participant can send to.
    Invalid,
    /// The locator an INFO_REPLY named (8.3.8.9).
    Locator(SocketAddrV4),
}

/// `Origin`'s reply state and whether the sender is the source, in eight
/// octets (`ReplyTo::Sender` is never relayed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    Sender,
    Invalid { relayed: bool },
    Locator { to: SocketAddrV4, relayed: bool },
}

impl Origin {
    /// The message's source is `from` itself: a reply may go there.
    pub fn direct(from: SocketAddr) -> Self {
        Self {
            from,
            reply: Reply::Sender,
        }
    }

    /// `from` only forwarded this message (it sits behind an INFO_SRC):
    /// no reply locator survives.
    pub fn relayed(from: SocketAddr) -> Self {
        Self {
            from,
            reply: Reply::Invalid { relayed: true },
        }
    }

    /// This origin, behind an INFO_REPLY (RTPS 2.5 8.3.8.9) that named
    /// `locator` as the place to reply to, or (`None`) named nothing usable.
    /// The source is unchanged: an INFO_REPLY says where to answer, not who
    /// is speaking.
    #[must_use]
    pub fn replying_to(self, locator: Option<SocketAddrV4>) -> Self {
        let relayed = self.reply().is_none();
        Self {
            from: self.from,
            reply: match locator {
                Some(to) => Reply::Locator { to, relayed },
                None => Reply::Invalid { relayed },
            },
        }
    }

    /// `from`, with the source and reply locator a walk of the message
    /// decided. `ReplyTo::Sender` needs a direct origin: a relayed one
    /// has no sender to reply to.
    pub(crate) fn with_reply(from: SocketAddr, relayed: bool, reply: ReplyTo) -> Self {
        let reply = match reply {
            ReplyTo::Sender if !relayed => Reply::Sender,
            ReplyTo::Sender | ReplyTo::Invalid => Reply::Invalid { relayed },
            ReplyTo::Locator(to) => Reply::Locator { to, relayed },
        };
        Self { from, reply }
    }

    /// The datagram's sender (the forwarder, when relayed). For logs and
    /// metrics only: never a destination, and never a source to derive a
    /// locator from.
    pub fn from(&self) -> SocketAddr {
        self.from
    }

    /// The datagram's sender when it IS the message's source (no INFO_SRC
    /// in force, RTPS 2.5 8.3.4 / 8.3.8.10): the address this participant
    /// falls back to, or reads a peer's address from, while it has no
    /// discovered locator for the peer. `None` behind an INFO_SRC.
    ///
    /// An INFO_REPLY does not change it: every endpoint here that answers
    /// is stateful and answers through its proxy's discovered locators,
    /// never the Receiver's reply locators (see `receiver_reply_locator`).
    pub fn reply(&self) -> Option<SocketAddr> {
        match self.reply {
            Reply::Sender
            | Reply::Invalid { relayed: false }
            | Reply::Locator { relayed: false, .. } => Some(self.from),
            Reply::Invalid { relayed: true } | Reply::Locator { relayed: true, .. } => None,
        }
    }

    /// The Receiver's unicast reply locator for this message (RTPS 2.5
    /// Table 8.17, 8.3.8.9, 8.3.8.10): the locator an INFO_REPLY named, else
    /// the datagram's sender, else `None` (behind an INFO_SRC, or an
    /// INFO_REPLY that named nothing usable).
    ///
    /// Only a Reliable StatelessWriter answering an ACKNACK may send there
    /// (8.4.8.2.6). HDDS has none: its stateless writers (SPDP, 8.5.3.2;
    /// ParticipantStatelessMessage) are best-effort, which receive no
    /// ACKNACK (8.4.8.1). Every other answer goes through `reply` and the
    /// proxies, which is what keeps an unauthenticated INFO_REPLY from
    /// redirecting repairs to a third party.
    pub fn receiver_reply_locator(&self) -> Option<SocketAddr> {
        match self.reply {
            Reply::Sender => Some(self.from),
            Reply::Invalid { .. } => None,
            Reply::Locator { to, .. } => Some(SocketAddr::V4(to)),
        }
    }
}

/// Packet classification for RTPS protocol
///
/// Maps RTPS submessage IDs to packet types per RTPS v2.3 Table 8.13.
/// Extended for full RTPS support (not just discovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    /// DATA submessage (0x15) - contains serialized data
    Data,
    /// Not a datagram: the place a remote writer's departure takes in the
    /// receive ring, behind the writer's data queued before it
    /// (`engine::departures`). Carries no buffer.
    Departure,
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
    /// PARTICIPANT_MESSAGE_DATA (RTPS v2.5 Sec.8.4.13).
    ///
    /// DATA from the P2P participant-message writer (0x000200c2) or addressed
    /// to its reader (0x000200c7). Its payload is a CDR STRUCT -
    /// `{ guidPrefix, kind, sequence<octet> }` - not a ParameterList, so no
    /// discovery parser has any business reading it.
    ///
    /// We ask for this traffic: bits 10 and 11 of our own
    /// `PID_BUILTIN_ENDPOINT_SET` default (0x000F_0C3F) declare both the
    /// writer and the reader, so every conforming peer with a liveliness
    /// policy to assert may send it, periodically, for as long as it lives.
    /// Naming it here matters: were it unclaimed, the datagram would be named
    /// user `Data` and go to the content guesser in `handle_data_packet`,
    /// which would refuse it by encapsulation (`InvalidEncapsulation`) rather
    /// than by any written rule.
    ///
    /// Delivered to the discovery dispatch, which reads its kind: a MANUAL
    /// assertion renews the sender's MANUAL_BY_PARTICIPANT writers. Its
    /// datagram, like any message of the sender, renews its AUTOMATIC ones
    /// (`dds::liveliness`).
    ParticipantMessage,
    /// A DATA whose writerEntityId names a BUILT-IN entity no endpoint of
    /// ours implements (RTPS v2.5 Sec.9.3.1.2 Table 9.1: entityKind octet
    /// 0b11xxxxxx).
    ///
    /// Not user data, and not ours to interpret. It is named here so the
    /// dispatch can drop it BY NAME and count it. The alternative is that a
    /// DATA no builtin endpoint claims is named `Data`, goes to
    /// `handle_data_packet`, and has its TYPE GUESSED FROM ITS PAYLOAD - the
    /// exact inversion of Sec.8.3.8.2, where a DATA is what its WRITER says it
    /// is. Through the production dispatch, that makes one participant
    /// announcement carried by the DCPSTopic writer (0x000002c2) register a
    /// participant; so would the same announcement carried by an ordinary
    /// application writer (0x00001202); and an ENDPOINT announcement carried
    /// by either would register a participant with the partial parser's
    /// constants - a 100-second lease and no locator at all.
    ///
    /// The set is open on purpose. Every builtin id a later spec revision or
    /// a vendor adds lands here and is dropped with its id in the log, rather
    /// than falling through to a parser that will find SOMETHING in any
    /// parameter list. `0x000002c2` (the SEDP Topic writer, DCPSTopic, which
    /// a peer may run when that builtin topic is enabled) is the one we know by
    /// name today: we announce no bits 6/7, so we do not solicit it, but we
    /// are on the wire with peers that do.
    UnknownBuiltin,
    /// DDS-Security: secure participant discovery (DDS Security v1.1 Sec.7.4.1.6).
    ///
    /// DATA submessage whose writerEntityId is `RTPS_ENTITYID_SPDP_SECURE_WRITER`
    /// (0xff0101c2) or whose reader is the matching secure reader. HDDS reads
    /// participant status changes there, under the discovery protection
    /// policy (`DiscoveryFsm::open_sealed_departure`); data updates are dropped.
    SecureSPDP,
    /// DDS-Security: secure SEDP endpoint discovery (DDS Security v1.1 sec. 7.4.1.3).
    ///
    /// Covers both SecurePublications (0xff0003xx) and SecureSubscriptions
    /// (0xff0004xx) writer/reader pairs. Payload is encrypted just like the
    /// plain SEDP equivalent (parameter list), but the writer GUID lives in
    /// the secure-vendor namespace and the wire bytes are wrapped in
    /// SecureSubMsg / SecureBodySubMsg.
    SecureSEDP,
    /// DDS-Security: ParticipantVolatileMessageSecure (DDS Security v1.1 sec. 7.4.4).
    ///
    /// A CLEAR DATA of the volatile secure endpoints, EntityIds 0xff0202c3
    /// (writer) / 0xff0202c4 (reader). The topic is submessage-protected
    /// (Sec.7.4.4.1, Table 17): its DATA travels as a SEC_PREFIX opened under
    /// the peer's KxKeys, so what the classifier names here is refused.
    SecureVolatile,
    /// DDS-Security: ParticipantStatelessMessage (DDS Security v1.1 sec. 7.4.5).
    ///
    /// Carries the authentication-handshake tokens BEFORE any crypto material
    /// is available, so payload is plaintext PKI-DH data wrapped in a normal
    /// DATA submessage with NO_KEY entityIds 0x000201c3 / 0x000201c4. It is
    /// classified and dropped: the handshake content is not processed here.
    Stateless,
    /// Invalid packet (malformed RTPS header)
    Invalid,
    /// Unknown submessage ID (not handled)
    Unknown,
}

/// RTPS Context State for stateful parsing
///
/// INFO_DST and INFO_TS submessages set context for subsequent submessages
/// in the same RTPS message (RTPS v2.5 Sec.8.3.8.8, Sec.8.3.8.11).
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

/// The sample a DATA_FRAG is a piece of, as the submessage declares it.
///
/// The two fields are read straight off the wire (`fragmentSize` and
/// `sampleSize`, RTPS v2.5 Sec.8.3.8.3); the fragment COUNT is derived from
/// them and never carried, so no reader can hold a count that disagrees with
/// the geometry it came from.
///
/// A bare `total_frags` computed separately by `classify_data_frag` and
/// `scan_all_data_frags` would need a fallback such as
/// `if fragmentSize > 0 { ceil } else { fragmentsInSubmessage }`, and that
/// fallback lets the two disagree: on `fragmentSize = 0,
/// fragmentsInSubmessage = 1` the classifier would announce "fragment 1 of 1"
/// while the scan refuses to read anything, and the reassembly door would take
/// the classifier's word, handing a subscriber 28 octets as a complete sample
/// of a declared 64. There is no such fallback here - a sample whose
/// fragments are zero octets long has no fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentGeometry {
    /// `fragmentSize`: the length of every fragment of the sample but the last.
    pub fragment_size: u16,
    /// `sampleSize`: the length of the whole serialized sample.
    pub sample_size: u32,
}

impl FragmentGeometry {
    /// `ceil(sampleSize / fragmentSize)`, or 0 when the geometry describes no
    /// fragment at all.
    ///
    /// A `u32` like `frag_num`: sampleSize is a 32-bit field and fragmentSize
    /// can be as small as 1, so the count is not bounded by the 16-bit
    /// fragmentsInSubmessage field. A `u16` would silently wrap the total for
    /// any sample over 65535 fragments and make its reassembly complete early.
    ///
    /// Computed in the width of `sample_size`: the quotient never exceeds it.
    #[inline]
    pub fn total_fragments(self) -> u32 {
        if self.fragment_size == 0 {
            return 0;
        }
        self.sample_size.div_ceil(u32::from(self.fragment_size))
    }

    /// The length fragment `frag_num` must carry, or `None` when the geometry
    /// has no such fragment.
    ///
    /// Every fragment but the last is exactly `fragment_size` octets; the last
    /// carries the remainder. A fragment shorter than this is a hole that
    /// count-based completion cannot see - it completes the sample short and
    /// shifts everything behind the hole.
    #[inline]
    pub fn expected_fragment_len(self, frag_num: u32) -> Option<usize> {
        let total = self.total_fragments();
        if frag_num == 0 || frag_num > total {
            return None;
        }
        let frag_size = u32::from(self.fragment_size);
        if frag_num < total {
            return Some(frag_size as usize);
        }
        // Last fragment: what the whole sample has left. `total` is the
        // ceiling of the division, so the product below never exceeds
        // `sample_size` and the subtraction never wraps.
        Some((self.sample_size - (total - 1) * frag_size) as usize)
    }
}

/// Fragment metadata for DATA_FRAG submessages (RTPS v2.5 Sec.8.3.8.3)
#[derive(Debug, Clone, Copy)]
pub struct FragmentMetadata {
    /// Writer GUID (from RTPS header GUID prefix + writerEntityId)
    pub writer_guid: GUID,
    /// Sequence number
    pub seq_num: u64,
    /// Fragment number (1-based)
    pub frag_num: u32,
    /// The sample this fragment is a piece of.
    pub geometry: FragmentGeometry,
}

impl FragmentMetadata {
    /// The sample's fragment count, derived from its geometry.
    #[inline]
    pub fn total_frags(&self) -> u32 {
        self.geometry.total_fragments()
    }
}

/// Minimal metadata for received multicast packet
///
/// Stored in RxRing alongside BufferId. Total size ~48 bytes (including rtps_context).
/// Designed for lock-free SPSC queue passing from listener thread to FSM.
#[derive(Debug, Clone, Copy)]
pub struct RxMeta {
    /// Where this packet came from, and where a reply may go.
    pub origin: Origin,
    /// Payload length in bytes (capped at u16::MAX = 65535)
    pub len: u16,
    /// Timestamp when packet was received (for latency tracking)
    pub ts: Instant,
    /// Classified packet type
    pub kind: PacketKind,
    /// Offset to DATA submessage payload (for vendor-specific headers)
    /// None for standard HDDS packets, Some(offset) after recovery
    pub data_payload_offset: Option<u16>,
    /// Fragment metadata (only for PacketKind::DataFrag)
    pub frag_meta: Option<FragmentMetadata>,
    /// RTPS context state (INFO_DST/INFO_TS)
    ///
    /// Accumulated from INFO_DST and INFO_TS submessages while scanning.
    /// Applied to DATA/HEARTBEAT submessages for correct routing and timestamps.
    pub rtps_context: RtpsContext,
    /// The HEARTBEATs and GAPs of this datagram were handed to the control
    /// thread, which answers them: the Router applies only their reorder-gate
    /// effects for user writers, and answers nothing itself. False when no
    /// control thread exists (the Router answers, as the unicast door does).
    pub control_answers: bool,
    /// False only when the listener scanned this datagram and found no
    /// HEARTBEAT or GAP in it: the Router then skips its own scan. True
    /// (the default) whenever nobody scanned, so the Router does.
    pub controls_may_ride: bool,
}

impl RxMeta {
    /// Create new RxMeta from received packet
    ///
    /// # Arguments
    /// - `origin`: where the packet came from, and where a reply may go
    /// - `len`: Payload length (will be capped to u16::MAX if larger)
    /// - `kind`: Classified packet type
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::multicast::{Origin, RxMeta, PacketKind};
    /// use std::net::SocketAddr;
    ///
    /// let addr: SocketAddr = "127.0.0.1:7400".parse()
    ///     .expect("Socket address parsing should succeed");
    /// let meta = RxMeta::new(Origin::direct(addr), 512, PacketKind::SPDP);
    /// assert_eq!(meta.len, 512);
    /// assert_eq!(meta.kind, PacketKind::SPDP);
    /// ```
    pub fn new(origin: Origin, len: usize, kind: PacketKind) -> Self {
        let len = u16::try_from(len).unwrap_or(u16::MAX);

        Self {
            origin,
            len,
            ts: Instant::now(),
            kind,
            data_payload_offset: None,
            frag_meta: None,
            rtps_context: RtpsContext::default(),
            control_answers: false,
            controls_may_ride: true,
        }
    }

    /// Create new RxMeta with explicit DATA payload offset
    ///
    /// Used when classifier recovery finds DATA submessage at non-standard offset
    /// (e.g., packets with vendor-specific headers)
    pub fn new_with_offset(origin: Origin, len: usize, kind: PacketKind, offset: usize) -> Self {
        let len = u16::try_from(len).unwrap_or(u16::MAX);

        let offset = u16::try_from(offset).ok();

        Self {
            origin,
            len,
            ts: Instant::now(),
            kind,
            data_payload_offset: offset,
            frag_meta: None,
            rtps_context: RtpsContext::default(),
            control_answers: false,
            controls_may_ride: true,
        }
    }

    /// Create new RxMeta with fragment metadata (for DATA_FRAG packets)
    pub fn new_with_fragment(
        origin: Origin,
        len: usize,
        kind: PacketKind,
        offset: usize,
        frag_meta: FragmentMetadata,
    ) -> Self {
        let len = u16::try_from(len).unwrap_or(u16::MAX);

        let offset = u16::try_from(offset).ok();

        Self {
            origin,
            len,
            ts: Instant::now(),
            kind,
            data_payload_offset: offset,
            frag_meta: Some(frag_meta),
            rtps_context: RtpsContext::default(),
            control_answers: false,
            controls_may_ride: true,
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
        // DDS-Security v1.1 sec. 7.4.1.3 secure builtins
        let _ = PacketKind::SecureSPDP;
        let _ = PacketKind::SecureSEDP;
        let _ = PacketKind::SecureVolatile;
        let _ = PacketKind::Stateless;
        let _ = PacketKind::Invalid;
        let _ = PacketKind::Unknown;
    }

    #[test]
    fn test_rx_meta_creation() {
        let addr: SocketAddr = "192.168.1.100:7400"
            .parse()
            .expect("Socket address parsing should succeed");
        let meta = RxMeta::new(Origin::direct(addr), 1024, PacketKind::Data);

        assert_eq!(meta.origin.from(), addr);
        assert_eq!(meta.origin.reply(), Some(addr));
        assert_eq!(meta.len, 1024);
        assert_eq!(meta.kind, PacketKind::Data);
    }

    #[test]
    fn test_rx_meta_len_overflow() {
        // Test that len > u16::MAX is capped
        let addr: SocketAddr = "127.0.0.1:7400"
            .parse()
            .expect("Socket address parsing should succeed");
        let meta = RxMeta::new(Origin::direct(addr), 70000, PacketKind::Heartbeat);

        assert_eq!(meta.len, u16::MAX);
    }

    /// RTPS 2.5 8.3.8.10: a relayed origin has no reply locator, whatever
    /// the forwarder's own address was.
    #[test]
    fn a_relayed_origin_has_no_reply_locator() {
        let forwarder: SocketAddr = "10.0.0.1:7400".parse().expect("valid address");
        let origin = Origin::relayed(forwarder);
        assert_eq!(origin.from(), forwarder, "kept for logs and metrics");
        assert_eq!(origin.reply(), None, "no reply address behind an INFO_SRC");
    }

    /// RTPS 2.5 8.3.8.9: an INFO_REPLY changes the Receiver's reply locator
    /// (the locator it names, or none) and nothing else: `reply`, which the
    /// stateful endpoints fall back to, stays the sender when the sender is
    /// the source, and behind an INFO_SRC stays `None`.
    #[test]
    fn an_info_reply_changes_the_receiver_reply_locator_only() {
        let sender: SocketAddr = "10.0.0.1:7400".parse().expect("valid address");
        let named: SocketAddrV4 = "10.0.0.2:7411".parse().expect("valid address");

        let direct = Origin::direct(sender).replying_to(Some(named));
        assert_eq!(direct.receiver_reply_locator(), Some(SocketAddr::V4(named)));
        assert_eq!(direct.reply(), Some(sender));
        assert_eq!(direct.from(), sender);

        let relayed = Origin::relayed(sender).replying_to(Some(named));
        assert_eq!(
            relayed.receiver_reply_locator(),
            Some(SocketAddr::V4(named))
        );
        assert_eq!(relayed.reply(), None);

        let unusable = Origin::direct(sender).replying_to(None);
        assert_eq!(
            unusable.receiver_reply_locator(),
            None,
            "the lists are replaced, not kept"
        );
        assert_eq!(unusable.reply(), Some(sender));

        assert_eq!(
            Origin::direct(sender).receiver_reply_locator(),
            Some(sender)
        );
        assert_eq!(Origin::relayed(sender).receiver_reply_locator(), None);
        assert_eq!(
            Origin::with_reply(sender, true, ReplyTo::Sender).receiver_reply_locator(),
            None,
            "a relayed origin has no sender to reply to"
        );
    }

    #[test]
    fn test_rx_meta_size() {
        // Ensure RxMeta fits in expected memory budget: one ring slot each.
        // Origin (SocketAddr 32 + the reply state 8, see `Reply`) + u16 (2) +
        // Instant (16) + PacketKind (1) + Option<u16> (4) +
        // Option<FragmentMetadata> (48) + RtpsContext (28), aligned to 8:
        // 144 measured. The reply state (an INFO_REPLY locator, RTPS 2.5
        // 8.3.8.9) accounts for 8 of those octets; nothing else may grow the
        // budget unnoticed.
        let size = std::mem::size_of::<RxMeta>();
        println!("RxMeta size: {} bytes", size);
        assert!(size <= 144);
    }
}

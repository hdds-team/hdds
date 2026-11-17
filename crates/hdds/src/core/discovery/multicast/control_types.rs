// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Control message data types for RTPS protocol messages.

use super::meta::Origin;

/// Maximum size of a control message (HEARTBEAT = 28 bytes + headers)
/// Sized to hold HEARTBEAT datagrams that carry INFO_DST/INFO_TS and other
/// submessages alongside the HEARTBEAT.
pub const CONTROL_MSG_MAX_SIZE: usize = 256;

// A held packet's length fits the `u16` that stores it, which keeps
// `ControlMessage` within its 512-octet budget.
const _: () = assert!(CONTROL_MSG_MAX_SIZE <= u16::MAX as usize);

/// The stored length of a held packet, at most `CONTROL_MSG_MAX_SIZE`.
fn control_len(len: usize) -> u16 {
    u16::try_from(len.min(CONTROL_MSG_MAX_SIZE)).unwrap_or(u16::MAX)
}

/// ENTITYID_UNKNOWN (RTPS 2.5 9.3.1.2): as the readerId of a HEARTBEAT or
/// GAP, every reader matched with the writer. One definition, in
/// `reliability`.
pub(crate) use crate::reliability::ENTITYID_UNKNOWN;

/// A parsed HEARTBEAT or GAP and the reader it addresses (its readerId).
///
/// `HeartbeatInfo` and `GapInfo` are public and exhaustive, so the readerId
/// travels beside them rather than inside.
#[derive(Debug, Clone)]
pub(crate) struct Addressed<T> {
    /// The readerId of the submessage; ENTITYID_UNKNOWN addresses every
    /// reader matched with the writer.
    pub(crate) reader_entity_id: [u8; 4],
    pub(crate) info: T,
    /// A GAP's filteredCount, when its FilteredCountFlag is set (RTPS v2.5
    /// Sec.8.3.8.4, Sec.9.4.5.6); `None` for a HEARTBEAT.
    pub(crate) filtered_count: Option<u64>,
    /// The GroupInfo, when the GroupInfoFlag is set and its values are
    /// valid (RTPS v2.5 Sec.9.4.5.6, Sec.9.4.5.7).
    pub(crate) group_info: Option<GroupInfo>,
}

/// The GroupInfo of a HEARTBEAT or a GAP from a GROUP Publisher's writer
/// (RTPS v2.5 Sec.8.3.8.4, Sec.8.3.8.6; wire layout Sec.9.4.5.6,
/// Sec.9.4.5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GroupInfo {
    /// currentGSN, firstGSN, lastGSN of a HEARTBEAT.
    Heartbeat {
        /// The last GSN written by any writer of the Publisher.
        current_gsn: u64,
        /// The GSN of the HEARTBEAT's firstSN.
        first_gsn: u64,
        /// The GSN of the HEARTBEAT's lastSN.
        last_gsn: u64,
        /// Optional PIM roster digests; the UDP PSM omits these fields.
        writer_set: Option<([u8; 4], [u8; 4])>,
    },
    /// gapStartGSN, gapEndGSN of a GAP.
    Gap {
        /// The GSN of the GAP's gapStart.
        start_gsn: u64,
        /// The end of the range of GSNs from `start_gsn` not available.
        end_gsn: u64,
    },
}

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

/// Parsed ACKNACK data for SEDP responses and user data retransmission.
#[derive(Debug, Clone)]
pub struct AckNackInfo {
    /// Reader entity ID (4 bytes) - what they're reading FROM
    pub reader_entity_id: [u8; 4],
    /// Writer entity ID (4 bytes) - what they want us to write TO
    pub writer_entity_id: [u8; 4],
    /// Missing sequence ranges extracted from RTPS ACKNACK bitmap.
    /// Format: Vec of [start..end) ranges where end is exclusive.
    /// Empty if reader has received all sequences (pure ACK).
    pub missing_ranges: Vec<std::ops::Range<u64>>,
    /// readerSNState.bitmapBase: the next sequence the reader expects (its cumulative
    /// ack is bitmapBase - 1). A reader that has everything ACKs bitmapBase = last_sn + 1.
    /// A late joiner that has received nothing ACKs bitmapBase = 1 with an EMPTY bitmap,
    /// so `missing_ranges` alone cannot detect it; control.rs compares this against our
    /// last published SEDP seq to decide whether the peer is behind.
    pub bitmap_base: u64,
    /// Count_t, absent only from a truncated submessage (RTPS 2.5 8.3.8.1:
    /// a reader increments it with every ACKNACK, so a repeat is a duplicate).
    pub count: Option<u32>,
}

/// Parsed GAP data for irrelevant-sequence notification (RTPS v2.5 Sec.8.3.8.4).
#[derive(Debug, Clone)]
pub struct GapInfo {
    /// Writer entity ID (4 bytes) originating the GAP.
    pub writer_entity_id: [u8; 4],
    /// First sequence number declared irrelevant (inclusive).
    pub gap_start: u64,
    /// First sequence number NOT in the implicit irrelevant range; equals gapList.base
    /// on the wire (RTPS v2.5 sec 8.3.8.4). The contiguous range [gap_start,
    /// gap_list_base - 1] is unconditionally irrelevant. Used by Arm 2 (ACKNACK-base
    /// advance) to advance the per-writer cumulative-ack floor without inspecting the
    /// bitmap.
    pub gap_list_base: u64,
    /// Additional sequences from the SNSet bitmap also declared irrelevant.
    /// Corresponds to the gapList SequenceNumberSet in the wire format.
    pub gap_list_seqs: Vec<u64>,
}

/// Parsed NACK_FRAG data for fragment retransmission (RTPS v2.5 Sec.8.3.8.12)
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

/// Parsed extensions of a GAP, retained independently of the truncated
/// diagnostic packet. Only a GAP with extensions allocates this record.
#[derive(Clone)]
struct GapMetadata {
    filtered_count: Option<u64>,
    group: Option<[u64; 2]>,
}

/// Control message passed through the channel (stack-allocated, no pool)
#[derive(Clone)]
pub struct ControlMessage {
    /// Message kind
    pub kind: ControlMessageKind,
    /// Where this message came from, and where a reply may go.
    pub origin: Origin,
    /// Peer GUID prefix (12 bytes, extracted from RTPS header)
    pub peer_guid_prefix: [u8; 12],
    /// Parsed HEARTBEAT info (if kind == Heartbeat)
    pub heartbeat: Option<HeartbeatInfo>,
    /// Parsed ACKNACK info (if kind == AckNack)
    pub acknack: Option<AckNackInfo>,
    /// Parsed GAP info (if kind == Gap)
    pub gap: Option<GapInfo>,
    /// Parsed NACK_FRAG info (if kind == NackFrag)
    pub nack_frag: Option<NackFragInfo>,
    /// Raw message bytes (stack buffer, no allocation)
    data: [u8; CONTROL_MSG_MAX_SIZE],
    /// Actual length of data
    len: u16,
    /// Its datagram also rides the receive ring, behind the DATA it follows:
    /// the Router applies the reorder-gate effects of a user writer's
    /// HEARTBEAT or GAP there, in arrival order, so this thread applies none
    /// of them (`control::applies_gate_on_control`). The ACKNACK answer and the
    /// discovery effects stay here.
    pub(crate) rides_ring: bool,
    /// The readerId of a HEARTBEAT or GAP: the reader it addresses, or
    /// ENTITYID_UNKNOWN for every reader matched with the writer (RTPS 2.5
    /// 8.3.8.4, 8.3.8.6).
    reader_entity_id: [u8; 4],
    /// Complete parsed GAP extensions, kept off the control queue's inline
    /// record. Ordinary control messages need no allocation for metadata.
    gap_metadata: Option<Box<GapMetadata>>,
    /// A GAP with valid GroupInfo (the GroupInfoFlag, RTPS v2.5
    /// Sec.9.4.5.6): it names the GSNs of the changes it declares.
    gap_names_gsns: bool,
    /// Whether an ACKNACK or NACK_FRAG arrived wrapped in a DDS-Security
    /// SEC_PREFIX/SEC_BODY/SEC_POSTFIX envelope that decoded under the
    /// sender's announced DatareaderCryptoTokens key
    /// (`decode_datareader_submessage`). `false` for every message built
    /// straight off the wire by [`Self::acknack`]/[`Self::nack_frag`] (the
    /// bytes parsed were never inside such an envelope, by construction:
    /// `parse_all_acknack_submessages` only ever sees a plaintext ACKNACK);
    /// `true` only for the synthetic message
    /// [`Self::protected`] builds after a successful decode
    /// (`discovery_setup::dispatch::DiscoveryDispatch::handle_secure_sedp`).
    /// A secure builtin writer's refusal of a CLEAR ACKNACK/NACK_FRAG
    /// (`control::run_loop`) reads this flag, never the submessage bytes
    /// themselves: by the time a message reaches that check its protection
    /// has already been removed.
    ///
    /// `cfg`-gated: both the field and its accessors
    /// ([`Self::protected`], [`Self::was_protected`]) exist only where
    /// DDS-Security does. Left ungated, every reader of them sits behind
    /// `feature = "security"` too, which makes the field and its methods
    /// dead code on the default feature set -- `clippy -D warnings`
    /// refuses dead code it finds there, the same hazard the
    /// `secure_builtins` module's own entity-id table warns about.
    #[cfg(feature = "security")]
    was_protected: bool,
}

impl ControlMessage {
    /// Create a new control message from raw packet data
    pub fn new(kind: ControlMessageKind, origin: Origin, packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 || packet.len() > CONTROL_MSG_MAX_SIZE {
            return None;
        }

        // Extract peer GUID prefix from RTPS header
        let mut peer_guid_prefix = [0u8; 12];
        peer_guid_prefix.copy_from_slice(&packet[8..20]);

        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        data[..packet.len()].copy_from_slice(packet);

        Some(Self {
            rides_ring: false,
            kind,
            origin,
            peer_guid_prefix,
            heartbeat: None,
            acknack: None,
            gap: None,
            nack_frag: None,
            data,
            len: control_len(packet.len()),
            reader_entity_id: ENTITYID_UNKNOWN,
            gap_metadata: None,
            gap_names_gsns: false,
            #[cfg(feature = "security")]
            was_protected: false,
        })
    }

    /// Create a HEARTBEAT control message with parsed info
    pub fn heartbeat(
        origin: Origin,
        peer_guid_prefix: [u8; 12],
        info: HeartbeatInfo,
        packet: &[u8],
    ) -> Option<Self> {
        // Oversized packets are TRUNCATED, not rejected. The parsed `info`
        // passed in is complete (parsing ran on the full datagram); the raw
        // copy kept here is diagnostic-only and has no consumer outside this
        // type. Rejecting would silently drop every compound nack train
        // ([INFO_DST, ACKNACK, NACK_FRAG x N] datagrams can reach 65 KB
        // against CONTROL_MSG_MAX_SIZE = 256), which would kill both the ACKNACK
        // full-sample retransmit and the NACK_FRAG selective retransmit: a
        // large sample sent to such a reader would never complete.
        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        let len = packet.len().min(CONTROL_MSG_MAX_SIZE);
        data[..len].copy_from_slice(&packet[..len]);

        Some(Self {
            rides_ring: false,
            kind: ControlMessageKind::Heartbeat,
            origin,
            peer_guid_prefix,
            heartbeat: Some(info),
            acknack: None,
            gap: None,
            nack_frag: None,
            data,
            len: control_len(len),
            reader_entity_id: ENTITYID_UNKNOWN,
            gap_metadata: None,
            gap_names_gsns: false,
            #[cfg(feature = "security")]
            was_protected: false,
        })
    }

    /// Create an ACKNACK control message with parsed info.
    pub fn acknack(
        origin: Origin,
        peer_guid_prefix: [u8; 12],
        info: AckNackInfo,
        packet: &[u8],
    ) -> Option<Self> {
        // Oversized packets are TRUNCATED, not rejected. The parsed `info`
        // passed in is complete (parsing ran on the full datagram); the raw
        // copy kept here is diagnostic-only and has no consumer outside this
        // type. Rejecting would silently drop every compound nack train
        // ([INFO_DST, ACKNACK, NACK_FRAG x N] datagrams can reach 65 KB
        // against CONTROL_MSG_MAX_SIZE = 256), which would kill both the ACKNACK
        // full-sample retransmit and the NACK_FRAG selective retransmit: a
        // large sample sent to such a reader would never complete.
        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        let len = packet.len().min(CONTROL_MSG_MAX_SIZE);
        data[..len].copy_from_slice(&packet[..len]);

        Some(Self {
            rides_ring: false,
            kind: ControlMessageKind::AckNack,
            origin,
            peer_guid_prefix,
            heartbeat: None,
            acknack: Some(info),
            gap: None,
            nack_frag: None,
            data,
            len: control_len(len),
            reader_entity_id: ENTITYID_UNKNOWN,
            gap_metadata: None,
            gap_names_gsns: false,
            #[cfg(feature = "security")]
            was_protected: false,
        })
    }

    /// Create a GAP control message with parsed info (RTPS v2.5 sec 8.3.8.4).
    pub fn gap(
        origin: Origin,
        peer_guid_prefix: [u8; 12],
        info: GapInfo,
        packet: &[u8],
    ) -> Option<Self> {
        // Oversized packets are TRUNCATED, not rejected. The parsed `info`
        // passed in is complete (parsing ran on the full datagram); the raw
        // copy kept here is diagnostic-only and has no consumer outside this
        // type. Rejecting would silently drop every compound nack train
        // ([INFO_DST, ACKNACK, NACK_FRAG x N] datagrams can reach 65 KB
        // against CONTROL_MSG_MAX_SIZE = 256), which would kill both the ACKNACK
        // full-sample retransmit and the NACK_FRAG selective retransmit: a
        // large sample sent to such a reader would never complete.
        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        let len = packet.len().min(CONTROL_MSG_MAX_SIZE);
        data[..len].copy_from_slice(&packet[..len]);

        Some(Self {
            rides_ring: false,
            kind: ControlMessageKind::Gap,
            origin,
            peer_guid_prefix,
            heartbeat: None,
            acknack: None,
            gap: Some(info),
            nack_frag: None,
            data,
            len: control_len(len),
            reader_entity_id: ENTITYID_UNKNOWN,
            gap_metadata: None,
            gap_names_gsns: false,
            #[cfg(feature = "security")]
            was_protected: false,
        })
    }

    /// Create a NACK_FRAG control message with parsed info
    pub fn nack_frag(
        origin: Origin,
        peer_guid_prefix: [u8; 12],
        info: NackFragInfo,
        packet: &[u8],
    ) -> Option<Self> {
        // Oversized packets are TRUNCATED, not rejected. The parsed `info`
        // passed in is complete (parsing ran on the full datagram); the raw
        // copy kept here is diagnostic-only and has no consumer outside this
        // type. Rejecting would silently drop every compound nack train
        // ([INFO_DST, ACKNACK, NACK_FRAG x N] datagrams can reach 65 KB
        // against CONTROL_MSG_MAX_SIZE = 256), which would kill both the ACKNACK
        // full-sample retransmit and the NACK_FRAG selective retransmit: a
        // large sample sent to such a reader would never complete.
        let mut data = [0u8; CONTROL_MSG_MAX_SIZE];
        let len = packet.len().min(CONTROL_MSG_MAX_SIZE);
        data[..len].copy_from_slice(&packet[..len]);

        Some(Self {
            rides_ring: false,
            kind: ControlMessageKind::NackFrag,
            origin,
            peer_guid_prefix,
            heartbeat: None,
            acknack: None,
            gap: None,
            nack_frag: Some(info),
            data,
            len: control_len(len),
            reader_entity_id: ENTITYID_UNKNOWN,
            gap_metadata: None,
            gap_names_gsns: false,
            #[cfg(feature = "security")]
            was_protected: false,
        })
    }

    /// Get raw packet data
    /// The GroupInfo of this HEARTBEAT (its G flag, RTPS v2.5 Sec.9.4.5.7),
    /// read again from the message's bytes: only a HEARTBEAT with the G
    /// flag is walked.
    pub(crate) fn heartbeat_group_info(&self) -> Option<GroupInfo> {
        let hb = self.heartbeat.as_ref()?;
        super::control_parser::scan_all_embedded_control_submessages(self.data())
            .1
            .into_iter()
            .find(|found| found.info.writer_entity_id == hb.writer_entity_id)
            .and_then(|found| found.group_info)
    }

    pub fn data(&self) -> &[u8] {
        &self.data[..usize::from(self.len)]
    }

    /// A HEARTBEAT control message for the reader its readerId names.
    pub(crate) fn addressed_heartbeat(
        origin: Origin,
        peer_guid_prefix: [u8; 12],
        heartbeat: Addressed<HeartbeatInfo>,
        packet: &[u8],
    ) -> Option<Self> {
        Self::heartbeat(origin, peer_guid_prefix, heartbeat.info, packet)
            .map(|msg| msg.addressed_to(heartbeat.reader_entity_id))
    }

    /// A GAP control message for the reader its readerId names.
    pub(crate) fn addressed_gap(
        origin: Origin,
        peer_guid_prefix: [u8; 12],
        gap: Addressed<GapInfo>,
        packet: &[u8],
    ) -> Option<Self> {
        Self::gap(origin, peer_guid_prefix, gap.info, packet).map(|mut msg| {
            msg.gap_names_gsns = gap.group_info.is_some();
            let group = match gap.group_info {
                Some(GroupInfo::Gap { start_gsn, end_gsn }) => Some([start_gsn, end_gsn]),
                _ => None,
            };
            if gap.filtered_count.is_some() || group.is_some() {
                msg.gap_metadata = Some(Box::new(GapMetadata {
                    filtered_count: gap.filtered_count,
                    group,
                }));
            }
            msg.addressed_to(gap.reader_entity_id)
        })
    }

    /// Whether this GAP names the GSNs of what it declares (valid
    /// GroupInfo).
    pub(crate) fn gap_group_info(&self) -> Option<GroupInfo> {
        self.gap_metadata
            .as_ref()
            .and_then(|metadata| metadata.group)
            .map(|[start_gsn, end_gsn]| GroupInfo::Gap { start_gsn, end_gsn })
    }

    pub(crate) fn gap_names_gsns(&self) -> bool {
        self.gap_names_gsns
    }

    /// The filteredCount of this GAP, when it carries one.
    pub(crate) fn gap_filtered_count(&self) -> Option<u64> {
        self.gap_metadata
            .as_ref()
            .and_then(|metadata| metadata.filtered_count)
    }

    /// This HEARTBEAT or GAP addresses the reader `reader_entity_id`.
    pub(crate) fn addressed_to(mut self, reader_entity_id: [u8; 4]) -> Self {
        self.reader_entity_id = reader_entity_id;
        self
    }

    /// Marks this message as riding the receive ring with its datagram
    /// (`rides_ring`).
    pub(crate) fn riding_ring(mut self, yes: bool) -> Self {
        self.rides_ring = yes;
        self
    }

    /// The reader this HEARTBEAT or GAP addresses (ENTITYID_UNKNOWN: all).
    pub(crate) fn reader_entity_id(&self) -> [u8; 4] {
        self.reader_entity_id
    }

    /// Mark this ACKNACK or NACK_FRAG as having arrived under DDS-Security
    /// submessage protection, successfully decoded before this message was
    /// built (`DiscoveryDispatch::handle_secure_sedp`). Only that call site
    /// has anything to mark: every OTHER constructor here builds straight
    /// off a plaintext parse, so its default of `false` already says the
    /// true thing.
    #[cfg(feature = "security")]
    pub(crate) fn protected(mut self) -> Self {
        self.was_protected = true;
        self
    }

    /// Whether this message's own [`Self::protected`] was called -- see
    /// that method and the field's own doc for why this is never computed
    /// from the submessage bytes carried here.
    #[cfg(feature = "security")]
    pub(crate) fn was_protected(&self) -> bool {
        self.was_protected
    }
}

impl std::fmt::Debug for ControlMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlMessage")
            .field("kind", &self.kind)
            .field("origin", &self.origin)
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
    /// Peer address for ACKNACK responses. `None` when no HEARTBEAT batched
    /// into this state could be resolved to a reply address (relayed, and
    /// the peer announced no metatraffic locator of its own): the sequence
    /// bounds above still track what the writer announced, and the flush
    /// simply has nothing to send to yet.
    pub peer_addr: Option<std::net::SocketAddr>,
    /// Peer GUID prefix (needed for ACKNACK packet)
    pub peer_guid_prefix: [u8; 12],
}

impl WriterState {
    /// This state and `newer`'s announcement of the same writer, folded:
    /// the later of each sequence bound and count.
    pub(crate) fn folded_with(&self, newer: &Self) -> Self {
        Self {
            first_seq: self.first_seq.max(newer.first_seq),
            highest_seq: self.highest_seq.max(newer.highest_seq),
            last_count: self.last_count.max(newer.last_count),
            // Never replace a known-good address with "unknown": prefer
            // whichever of the two folded announcements actually resolved
            // one.
            peer_addr: newer.peer_addr.or(self.peer_addr),
            peer_guid_prefix: newer.peer_guid_prefix,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A GAP with valid GroupInfo keeps saying so as a control message,
    /// which the reader's door reads (`release_reorder_gate`); one without
    /// does not.
    #[test]
    fn a_gap_message_says_whether_it_names_gsns() {
        let packet = crate::protocol::builder::build_gap_packet_group(
            &[0, 0, 0, 0],
            &[0, 0, 0x01, 0x02],
            3,
            7,
            7,
            [0x44; 12],
        );
        let plain = crate::protocol::builder::build_gap_packet_from_parts(
            &[0, 0, 0, 0],
            &[0, 0, 0x01, 0x02],
            3,
            4,
            &[],
            [0x44; 12],
        );
        let origin = super::super::meta::Origin::direct("127.0.0.1:9".parse().expect("addr"));
        for (bytes, names) in [(&packet, true), (&plain, false)] {
            let mut padded = bytes.clone();
            // The walk reads a datagram of at least 52 octets.
            padded.extend_from_slice(&[0x01, 0x01, 0x00, 0x00].repeat(4));
            let gap = super::super::control_parser::scan_all_embedded_control_submessages(&padded)
                .0
                .pop()
                .expect("a GAP");
            let msg =
                ControlMessage::addressed_gap(origin, [0x44; 12], gap, &padded).expect("a message");
            assert_eq!(msg.gap_names_gsns(), names);
        }
    }

    /// Complete parsed GAP extensions survive the channel's diagnostic
    /// packet truncation and cloning (RTPS 2.5 Sec.9.4.5.6).
    #[test]
    fn a_gap_keeps_parsed_metadata_and_clones_after_raw_packet_truncation() {
        let origin = super::super::meta::Origin::direct("127.0.0.1:9".parse().unwrap());
        for (group, filtered) in [(false, false), (false, true), (true, false), (true, true)] {
            let mut gap = if group {
                crate::protocol::builder::build_gap_packet_group(
                    &[0; 4],
                    &[0, 0, 1, 2],
                    3,
                    7,
                    9,
                    [0x44; 12],
                )
            } else {
                crate::protocol::builder::build_gap_packet_from_parts(
                    &[0; 4],
                    &[0, 0, 1, 2],
                    3,
                    4,
                    &[],
                    [0x44; 12],
                )
            };
            if filtered {
                gap[21] |= 0x04;
                let len = u16::from_le_bytes([gap[22], gap[23]]) + 8;
                gap[22..24].copy_from_slice(&len.to_le_bytes());
                gap.extend_from_slice(&0i32.to_le_bytes());
                gap.extend_from_slice(&5u32.to_le_bytes());
            }
            let mut packet = gap[..20].to_vec();
            // PAD makes the entire GAP lie beyond the retained raw copy.
            packet.extend_from_slice(&[0x01, 0x01, 240, 0]);
            packet.extend_from_slice(&[0; 240]);
            packet.extend_from_slice(&gap[20..]);
            let parsed =
                super::super::control_parser::scan_all_embedded_control_submessages(&packet)
                    .0
                    .pop()
                    .expect("a complete GAP");
            assert_eq!(parsed.filtered_count, filtered.then_some(5));
            let expected_group = group.then_some(GroupInfo::Gap {
                start_gsn: 7,
                end_gsn: 9,
            });
            assert_eq!(parsed.group_info, expected_group);
            let msg = ControlMessage::addressed_gap(origin, [0x44; 12], parsed, &packet).unwrap();
            assert_eq!(msg.data(), &packet[..CONTROL_MSG_MAX_SIZE]);
            assert_eq!(msg.gap_metadata.is_some(), group || filtered);
            let cloned = msg.clone();
            drop(msg);
            assert_eq!(
                cloned.gap_filtered_count(),
                filtered.then_some(5),
                "parsed filteredCount was lost"
            );
            assert_eq!(
                cloned.gap_group_info(),
                expected_group,
                "parsed GroupInfo was lost"
            );
            assert_eq!(cloned.gap_names_gsns(), group);
            assert_eq!(cloned.gap.as_ref().unwrap().gap_start, 3);
        }
    }

    #[test]
    fn test_control_message_size() {
        // Verify the inline control queue record fits its 512-byte budget.
        eprintln!(
            "ControlMessage: {} B",
            std::mem::size_of::<ControlMessage>()
        );
        assert!(
            std::mem::size_of::<ControlMessage>() <= 512,
            "ControlMessage should be compact"
        );
    }

    /// Two batched announcements of one writer fold into the later of each
    /// bound AND the later count: a reader answered from the folded state
    /// then holds the count of the HEARTBEAT to every reader, and ignores it
    /// as a duplicate (RTPS 2.5 8.3.8.6) instead of answering twice.
    #[test]
    fn a_folded_writer_state_keeps_the_later_bounds_and_count() {
        let state = |first_seq, highest_seq, last_count, port| WriterState {
            first_seq,
            highest_seq,
            last_count,
            peer_addr: Some(std::net::SocketAddr::new(
                std::net::Ipv4Addr::LOCALHOST.into(),
                port,
            )),
            peer_guid_prefix: [0x41; 12],
        };
        let folded = state(1, 3, 3, 7410).folded_with(&state(2, 5, 4, 7411));
        assert_eq!(
            (
                folded.first_seq,
                folded.highest_seq,
                folded.last_count,
                folded.peer_addr.map(|a| a.port())
            ),
            (2, 5, 4, Some(7411))
        );
        let folded = state(2, 5, 4, 7410).folded_with(&state(1, 3, 3, 7411));
        assert_eq!(
            (folded.first_seq, folded.highest_seq, folded.last_count),
            (2, 5, 4)
        );
    }

    /// RTPS 2.5 8.3.4 / 8.3.8.10: a relayed HEARTBEAT with no metatraffic
    /// locator of its own folds in with `peer_addr: None` -- and must not
    /// blank out an address a previous (or later) announcement resolved.
    #[test]
    fn folding_never_regresses_a_known_address_to_unknown() {
        let with_addr = WriterState {
            first_seq: 1,
            highest_seq: 3,
            last_count: 1,
            peer_addr: Some(std::net::SocketAddr::new(
                std::net::Ipv4Addr::LOCALHOST.into(),
                7410,
            )),
            peer_guid_prefix: [0x41; 12],
        };
        let without_addr = WriterState {
            first_seq: 2,
            highest_seq: 5,
            last_count: 2,
            peer_addr: None,
            peer_guid_prefix: [0x41; 12],
        };

        assert_eq!(
            with_addr.folded_with(&without_addr).peer_addr,
            with_addr.peer_addr,
            "a later announcement with no address must not erase the earlier one"
        );
        assert_eq!(
            without_addr.folded_with(&with_addr).peer_addr,
            with_addr.peer_addr,
            "a later announcement WITH an address always wins"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS reliability protocol messages
//!
//! Consolidates all message types used by Reliable QoS:
//! - HEARTBEAT: Writer announces available sequence range
//! - GAP: Writer declares lost/unavailable sequences
//! - NACK: Reader requests retransmission
//! - INFO_TS: Source timestamp for DATA submessages
//! - INFO_DST: Destination GUID prefix for targeted delivery

use std::convert::{TryFrom, TryInto};
use std::ops::Range;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::RtpsRange;
use crate::core::discovery::multicast::classifier::walk;

// ============================================================================
// HEARTBEAT
// ============================================================================

/// GUID prefix length (12 bytes).
pub const GUID_PREFIX_LEN: usize = 12;
/// Entity ID length (4 bytes).
pub const ENTITY_ID_LEN: usize = 4;

/// Heartbeat message (RTPS HEARTBEAT submessage per DDS-RTPS v2.5 Sec.8.3.8.6).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatMsg {
    /// First (oldest) sequence number in writer's cache.
    pub first_seq: u64,
    /// Last (newest) sequence number written by writer.
    pub last_seq: u64,
    /// Monotonic heartbeat counter (anti-replay).
    pub count: u32,
    /// Writer's GUID prefix (from RTPS header)
    pub writer_guid_prefix: [u8; GUID_PREFIX_LEN],
    /// Writer's entity ID (from HEARTBEAT submessage)
    pub writer_entity_id: [u8; ENTITY_ID_LEN],
    /// Reader's entity ID (from HEARTBEAT submessage) - can be UNKNOWN
    pub reader_entity_id: [u8; ENTITY_ID_LEN],
}

impl HeartbeatMsg {
    /// Create a new heartbeat message.
    #[must_use]
    pub fn new(first_seq: u64, last_seq: u64, count: u32) -> Self {
        Self {
            first_seq,
            last_seq,
            count,
            writer_guid_prefix: [0; GUID_PREFIX_LEN],
            writer_entity_id: [0; ENTITY_ID_LEN],
            reader_entity_id: [0; ENTITY_ID_LEN],
        }
    }

    /// Decode the body of one HEARTBEAT submessage.
    ///
    /// The bound lives here rather than at every call site: a `HeartbeatMsg`
    /// cannot be built from fewer than the 28 octets Sec.8.3.8.6 fixes, so
    /// no walk can hand one out by forgetting to check. `payload` may be
    /// LONGER than 28 - a sentinel submessage runs to the end of the
    /// datagram - and the surplus is not ours to read.
    fn decode_body(
        payload: &[u8],
        little_endian: bool,
        writer_guid_prefix: [u8; GUID_PREFIX_LEN],
    ) -> Option<Self> {
        /// readerEntityId(4) + writerEntityId(4) + firstSN(8) + lastSN(8) + count(4).
        const HEARTBEAT_BODY_LEN: usize = 28;
        if payload.len() < HEARTBEAT_BODY_LEN {
            return None;
        }

        // Entity ids are octet arrays, so they carry no endianness.
        let mut reader_entity_id = [0u8; ENTITY_ID_LEN];
        let mut writer_entity_id = [0u8; ENTITY_ID_LEN];
        reader_entity_id.copy_from_slice(&payload[0..4]);
        writer_entity_id.copy_from_slice(&payload[4..8]);

        // DDSI-RTPS 9.4.2.5: SequenceNumber_t is {long high, unsigned long low}.
        let (first_high, first_low, last_high, last_low, count) = if little_endian {
            (
                i32::from_le_bytes(payload[8..12].try_into().ok()?),
                u32::from_le_bytes(payload[12..16].try_into().ok()?),
                i32::from_le_bytes(payload[16..20].try_into().ok()?),
                u32::from_le_bytes(payload[20..24].try_into().ok()?),
                u32::from_le_bytes(payload[24..28].try_into().ok()?),
            )
        } else {
            (
                i32::from_be_bytes(payload[8..12].try_into().ok()?),
                u32::from_be_bytes(payload[12..16].try_into().ok()?),
                i32::from_be_bytes(payload[16..20].try_into().ok()?),
                u32::from_be_bytes(payload[20..24].try_into().ok()?),
                u32::from_be_bytes(payload[24..28].try_into().ok()?),
            )
        };

        Some(Self {
            first_seq: ((first_high as i64) << 32 | first_low as i64) as u64,
            last_seq: ((last_high as i64) << 32 | last_low as i64) as u64,
            count,
            writer_guid_prefix,
            writer_entity_id,
            reader_entity_id,
        })
    }

    /// Decode EVERY HEARTBEAT submessage of a full RTPS datagram, in wire
    /// order.
    ///
    /// Sec.8.3.3: submessages are independently valid, and a participant
    /// batches one HEARTBEAT per writer it is announcing for - so a
    /// datagram routinely carries several, each naming a different
    /// `writerEntityId`. Reading only the first leaves every other writer's
    /// announcement unanswered, and that writer reannounces the same range
    /// forever.
    ///
    /// Packet format:
    /// - RTPS Header (20 bytes): "RTPS" + version(2) + vendorId(2) + guidPrefix(12)
    /// - Submessage header (4 bytes): submessageId(1) + flags(1) + length(2)
    /// - HEARTBEAT payload: readerEntityId(4) + writerEntityId(4) + firstSN(8) + lastSN(8) + count(4)
    ///
    /// Every multi-byte field is read with the endianness the submessage
    /// declares in bit 0 of its own flags (Sec.8.3.3.3) - the lengths that
    /// drive the walk as much as the body. A big-endian peer writes
    /// `octetsToNextHeader = 28` as `00 1c`, which read little-endian is
    /// 7168: the walk then runs past the end of the datagram and the
    /// HEARTBEAT is never found. Read the body little-endian and a lastSN
    /// of 5 comes back as 83 886 080.
    ///
    /// A 0x07 this walk cannot read is ONE lost announcement, not a lost
    /// datagram (Sec.8.3.3 again): it is skipped, and the ones behind it
    /// are still decoded. A declared length that runs PAST the end of the
    /// datagram is different in kind - the next header's position becomes
    /// unknowable - so it ends the walk.
    ///
    /// This walk is deliberately NOT the classifier's
    /// (`core::discovery::multicast::classifier::walk`): that one recovers
    /// from an impossible length by scanning forward for a plausible
    /// header, which is a heuristic earned by one measured vendor packet on
    /// the discovery path. Adding it here would change what this decoder
    /// accepts on a path no interop matrix has measured. Unifying the two
    /// is a separate piece of work; being spec-correct is not.
    #[must_use]
    pub fn decode_all_from_packet(packet: &[u8]) -> Vec<Self> {
        /// HEARTBEAT submessage id (RTPS v2.5 Table 8.13).
        const HEARTBEAT_ID: u8 = 0x07;

        let mut found = Vec::new();

        // Minimum: RTPS header(20) + submsg header(4) + HEARTBEAT payload(28) = 52 bytes
        if packet.len() < 52 || &packet[0..4] != b"RTPS" {
            return found;
        }

        // Extract GUID prefix from RTPS header (bytes 8-20)
        let mut writer_guid_prefix = [0u8; GUID_PREFIX_LEN];
        writer_guid_prefix.copy_from_slice(&packet[8..20]);

        walk::for_each_submessage(packet, |submsg| {
            if submsg.id != HEARTBEAT_ID {
                return walk::Step::Continue;
            }
            let payload_start = submsg.offset + 4;
            // The DECLARED length, not `body_end`. The two differ only when a
            // submessage claims more octets than the datagram carries, and
            // this decoder has always refused that packet rather than read a
            // truncated HEARTBEAT as a whole one. What a body MEANS is not
            // this commit's business; the traversal that finds it is.
            //
            // Sec.8.3.3.3: a zero length means this is the last submessage
            // and it runs to the end of the datagram.
            let payload_end = if submsg.octets_to_next == 0 {
                packet.len()
            } else {
                payload_start + submsg.octets_to_next as usize
            };
            match packet.get(payload_start..payload_end).and_then(|body| {
                Self::decode_body(body, submsg.flags & 0x01 != 0, writer_guid_prefix)
            }) {
                Some(hb) => found.push(hb),
                None => log::debug!(
                    "[reader] skipping an unreadable HEARTBEAT submessage at offset {}",
                    submsg.offset
                ),
            }
            walk::Step::Continue
        });

        found
    }
}

// ============================================================================
// GAP (with SequenceNumberSet)
// ============================================================================

/// RTPS Entity ID (4 bytes).
pub type EntityId = [u8; 4];

/// RTPS constant ENTITYID_UNKNOWN (RTPS 2.5 9.3.1.2): all zero. As the
/// readerId of a DATA, HEARTBEAT or GAP it addresses every reader of the
/// receiving participant matched with the writer.
pub const ENTITYID_UNKNOWN: EntityId = [0x00, 0x00, 0x00, 0x00];

pub const MAX_BITMAP_BITS: u32 = 256;
pub const WORD_BITS: u32 = 32;
pub const BITMAP_WORDS: usize = 8;

/// SequenceNumberSet representation used by GAP/ACKNACK submessages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceNumberSet {
    base: i64,
    num_bits: u32,
    bitmap: [u32; BITMAP_WORDS],
}

impl SequenceNumberSet {
    /// Maximum number of bitmap bits (RTPS limit).
    pub const MAX_BITS: u32 = MAX_BITMAP_BITS;

    /// Create an empty set with the provided base sequence number.
    pub fn empty(base: i64) -> Self {
        Self {
            base,
            num_bits: 0,
            bitmap: [0; BITMAP_WORDS],
        }
    }

    /// Create from explicit sequence numbers (must be >= base and < base + 256).
    pub fn from_sequences(base: i64, sequences: &[u64]) -> Option<Self> {
        if base < 0 {
            return None;
        }

        if sequences.is_empty() {
            return Some(Self::empty(base));
        }

        let mut set = Self::empty(base);
        let mut max_offset: u32 = 0;
        let base_u64 = u64::try_from(base).ok()?;

        for &seq in sequences {
            if seq < base_u64 {
                return None;
            }
            let offset = seq - base_u64;
            if offset >= u64::from(MAX_BITMAP_BITS) {
                return None;
            }

            let word = usize::try_from(offset / u64::from(WORD_BITS)).ok()?;
            let bit = u32::try_from(offset % u64::from(WORD_BITS)).ok()?;
            set.bitmap[word] |= 1 << (31 - bit);
            #[allow(clippy::expect_used)] // offset verified < MAX_BITMAP_BITS (256) above
            let off32 = u32::try_from(offset).expect("offset < MAX_BITMAP_BITS");
            max_offset = max_offset.max(off32);
        }

        set.num_bits = if max_offset == 0 {
            WORD_BITS
        } else {
            ((max_offset / WORD_BITS) + 1) * WORD_BITS
        };

        Some(set)
    }

    /// Construct from raw bitmap words (used by decoder).
    pub(crate) fn from_raw(base: i64, num_bits: u32, words: &[u32]) -> Option<Self> {
        if base < 0 || num_bits > MAX_BITMAP_BITS {
            return None;
        }
        if words.len() > BITMAP_WORDS {
            return None;
        }

        let mut bitmap = [0u32; BITMAP_WORDS];
        for (idx, word) in words.iter().enumerate() {
            bitmap[idx] = *word;
        }

        Some(Self {
            base,
            num_bits,
            bitmap,
        })
    }

    /// Number of bitmap words that need to be transmitted.
    pub fn word_count(&self) -> usize {
        Self::word_count_for_bits(self.num_bits)
    }

    /// Compute number of words required for a given bit count.
    pub fn word_count_for_bits(bits: u32) -> usize {
        if bits == 0 {
            0
        } else {
            #[allow(clippy::expect_used)]
            // bits <= MAX_BITMAP_BITS (256), result always fits in usize
            usize::try_from(bits.div_ceil(WORD_BITS)).expect("word count fits")
        }
    }

    /// Base sequence number of the set.
    pub fn base(&self) -> i64 {
        self.base
    }

    /// Number of bitmap bits actually used.
    pub fn num_bits(&self) -> u32 {
        self.num_bits
    }

    /// Access bitmap word for encoding purposes.
    pub fn bitmap_word(&self, idx: usize) -> u32 {
        self.bitmap[idx]
    }

    /// Iterate through all sequence numbers contained in the set.
    pub fn iter(&self) -> SequenceNumberIter {
        SequenceNumberIter {
            base: self.base as u64,
            num_bits: self.num_bits,
            bitmap: self.bitmap,
            index: 0,
        }
    }
}

/// Iterator over sequences contained in a `SequenceNumberSet`.
#[derive(Clone)]
pub struct SequenceNumberIter {
    base: u64,
    num_bits: u32,
    bitmap: [u32; BITMAP_WORDS],
    index: u32,
}

impl Iterator for SequenceNumberIter {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.num_bits {
            let offset = self.index;
            let word = (offset / WORD_BITS) as usize;
            let bit = offset % WORD_BITS;
            let mask = 1u32 << (31 - bit);
            self.index += 1;
            if self.bitmap[word] & mask != 0 {
                return Some(self.base + offset as u64);
            }
        }
        None
    }
}

impl IntoIterator for &SequenceNumberSet {
    type Item = u64;
    type IntoIter = SequenceNumberIter;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// GAP message (writer -> reader, RTPS GAP submessage per DDS-RTPS v2.5 Sec.8.3.8.4).
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapMsg {
    reader_id: EntityId,
    writer_id: EntityId,
    gap_start: u64,
    gap_list: SequenceNumberSet,
}

impl GapMsg {
    /// Create GAP message from raw components.
    #[must_use]
    pub fn new(
        reader_id: EntityId,
        writer_id: EntityId,
        gap_start: u64,
        gap_list: SequenceNumberSet,
    ) -> Self {
        Self {
            reader_id,
            writer_id,
            gap_start,
            gap_list,
        }
    }

    /// Convenience for contiguous ranges `[start, end)`.
    pub fn contiguous(reader_id: EntityId, writer_id: EntityId, range: RtpsRange) -> Option<Self> {
        if range.start >= range.end {
            return None;
        }

        let base = (range.start + 1) as i64;
        let extra: Vec<u64> = ((range.start + 1)..range.end).collect();
        let gap_list = SequenceNumberSet::from_sequences(base, &extra)?;

        Some(Self::new(reader_id, writer_id, range.start, gap_list))
    }

    /// Entity ID of the target reader.
    #[must_use]
    pub fn reader_id(&self) -> EntityId {
        self.reader_id
    }

    /// Entity ID of the originating writer.
    #[must_use]
    pub fn writer_id(&self) -> EntityId {
        self.writer_id
    }

    /// First lost sequence number (inclusive).
    #[must_use]
    pub fn gap_start(&self) -> u64 {
        self.gap_start
    }

    /// Bitmap of additional lost sequences.
    #[must_use]
    pub fn gap_list(&self) -> &SequenceNumberSet {
        &self.gap_list
    }

    /// Expand into explicit sequence numbers.
    #[must_use]
    pub fn lost_sequences(&self) -> Vec<u64> {
        let mut seqs = Vec::with_capacity(1);
        seqs.push(self.gap_start);
        seqs.extend(self.gap_list.iter());
        seqs.sort_unstable();
        seqs
    }

    /// Convert to contiguous ranges `[start, end)`.
    #[must_use]
    pub fn lost_ranges(&self) -> Vec<Range<u64>> {
        let sequences = self.lost_sequences();
        if sequences.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut start = sequences[0];
        let mut prev = sequences[0];

        for seq in sequences.iter().skip(1) {
            if *seq == prev + 1 {
                prev = *seq;
            } else {
                ranges.push(RtpsRange::from_inclusive(start, prev).into_range());
                start = *seq;
                prev = *seq;
            }
        }
        ranges.push(RtpsRange::from_inclusive(start, prev).into_range());
        ranges
    }

    /// Encode into CDR (little-endian) payload.
    #[must_use]
    pub fn encode_cdr2_le(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 4 + 8 + 8 + 4 + (self.gap_list.word_count() * 4));

        buf.extend_from_slice(&self.reader_id);
        buf.extend_from_slice(&self.writer_id);
        // DDSI-RTPS 9.4.2.5: SequenceNumber_t is { long high; unsigned long
        // low }. Splitting the 64-bit sequence into those two words is the
        // encoding, not a loss - the high word carries every bit the low word
        // drops, and `decode_cdr2_le` below reassembles them. Proven above
        // 2^32 by `test_build_gap_packet_preserves_sequence_number_words`
        // (protocol/builder/tests.rs), which asserts high == 1, low == 10 for
        // a start of (1 << 32) + 10.
        let gap_start = self.gap_start as i64;
        let gap_start_high = (gap_start >> 32) as i32;
        let gap_start_low = gap_start as u32; // @audit-ok: RTPS SN low word, see above
        buf.extend_from_slice(&gap_start_high.to_le_bytes());
        buf.extend_from_slice(&gap_start_low.to_le_bytes());
        let base = self.gap_list.base();
        let base_high = (base >> 32) as i32;
        let base_low = base as u32; // @audit-ok: RTPS SN low word, see above
        buf.extend_from_slice(&base_high.to_le_bytes());
        buf.extend_from_slice(&base_low.to_le_bytes());
        buf.extend_from_slice(&self.gap_list.num_bits().to_le_bytes());

        for word in 0..self.gap_list.word_count() {
            buf.extend_from_slice(&self.gap_list.bitmap_word(word).to_le_bytes());
        }

        buf
    }

    /// Decode from CDR (little-endian) payload.
    pub fn decode_cdr2_le(buf: &[u8]) -> Option<Self> {
        let mut offset = 0usize;
        if buf.len() < 4 + 4 + 8 + 8 + 4 {
            return None;
        }

        let reader_id = buf[offset..offset + 4].try_into().ok()?;
        offset += 4;
        let writer_id = buf[offset..offset + 4].try_into().ok()?;
        offset += 4;

        let gap_start_high = i32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?);
        let gap_start_low = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().ok()?);
        let gap_start = ((gap_start_high as i64) << 32) | i64::from(gap_start_low);
        if gap_start < 0 {
            return None;
        }
        offset += 8;

        let base_high = i32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?);
        let base_low = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().ok()?);
        let base = ((base_high as i64) << 32) | i64::from(base_low);
        offset += 8;

        let num_bits = u32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?);
        offset += 4;

        if num_bits > MAX_BITMAP_BITS {
            return None;
        }

        let word_count = SequenceNumberSet::word_count_for_bits(num_bits);
        if buf.len() < offset + word_count * 4 {
            return None;
        }

        let mut words = Vec::with_capacity(word_count);
        for _ in 0..word_count {
            let word = u32::from_le_bytes(buf[offset..offset + 4].try_into().ok()?);
            words.push(word);
            offset += 4;
        }

        let gap_list = SequenceNumberSet::from_raw(base, num_bits, &words)?;

        Some(Self::new(reader_id, writer_id, gap_start as u64, gap_list))
    }
}

// ============================================================================
// NACK
// ============================================================================

/// NACK message (reader -> writer, RTPS ACKNACK submessage per DDS-RTPS v2.5 Sec.8.3.8.1).
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NackMsg {
    /// Missing sequence ranges [start..end)
    pub ranges: Vec<Range<u64>>,
}

impl NackMsg {
    /// Create new NACK message.
    pub fn new(ranges: Vec<Range<u64>>) -> Self {
        Self { ranges }
    }

    /// Create NACK message from any range iterator.
    pub fn from_ranges<I>(ranges: I) -> Self
    where
        I: IntoIterator<Item = Range<u64>>,
    {
        Self {
            ranges: ranges.into_iter().collect(),
        }
    }

    /// Encode to CDR2 little-endian bytes.
    pub fn encode_cdr2_le(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.ranges.len() * 16);
        let range_count = u32::try_from(self.ranges.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&range_count.to_le_bytes());

        for range in &self.ranges {
            buf.extend_from_slice(&range.start.to_le_bytes());
            buf.extend_from_slice(&range.end.to_le_bytes());
        }

        buf
    }

    /// Decode from CDR2 little-endian bytes.
    pub fn decode_cdr2_le(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }

        let num_ranges = u32::from_le_bytes(buf[0..4].try_into().ok()?);
        let num_ranges = usize::try_from(num_ranges).ok()?;
        let expected_len = 4 + num_ranges * 16;
        if buf.len() < expected_len {
            return None;
        }

        let mut ranges = Vec::with_capacity(num_ranges);
        let mut offset = 4;

        for _ in 0..num_ranges {
            let start = u64::from_le_bytes(buf[offset..offset + 8].try_into().ok()?);
            let end = u64::from_le_bytes(buf[offset + 8..offset + 16].try_into().ok()?);
            ranges.push(start..end);
            offset += 16;
        }

        Some(Self { ranges })
    }

    /// Get total number of missing sequences.
    pub fn total_missing(&self) -> u64 {
        self.ranges.iter().map(|r| r.end - r.start).sum()
    }
}

// ============================================================================
// INFO_TS
// ============================================================================

/// RTPS fraction representing 0.5 seconds (2^31)
pub const RTPS_FRACTION_HALF_SECOND: u32 = 0x8000_0000;

/// INFO_TS message (RTPS INFO_TS submessage per DDS-RTPS v2.5 Sec.8.3.8.11)
///
/// Provides source timestamp for subsequent DATA submessages in the same RTPS message.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InfoTsMsg {
    /// Timestamp in nanoseconds since UNIX epoch (Jan 1, 1970)
    nanos: u64,
}

impl InfoTsMsg {
    /// Create timestamp from current system time
    pub fn now() -> Self {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| {
                log::debug!("[HDDS] WARNING: System time before UNIX epoch, using timestamp 0");
                Duration::from_secs(0)
            });

        Self {
            nanos: duration.as_nanos() as u64,
        }
    }

    /// Create timestamp from nanoseconds since UNIX epoch
    pub fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// Create timestamp from RTPS format (seconds + fraction)
    pub fn from_rtps(seconds: i32, fraction: u32) -> Self {
        let nanos_from_secs = i64::from(seconds) * 1_000_000_000;
        let nanos_from_fraction = ((fraction as u64) * 1_000_000_000) >> 32;

        Self {
            nanos: (nanos_from_secs + nanos_from_fraction as i64) as u64,
        }
    }

    /// Get timestamp in nanoseconds since UNIX epoch
    #[must_use]
    pub fn as_nanos(&self) -> u64 {
        self.nanos
    }

    /// Convert to RTPS format (seconds, fraction)
    #[must_use]
    pub fn to_rtps(&self) -> (i32, u32) {
        let seconds_total = self.nanos / 1_000_000_000;
        let seconds = match i32::try_from(seconds_total) {
            Ok(value) => value,
            Err(_) => {
                log::debug!(
                    "[info_ts] Timestamp {}ns exceeds RTPS seconds range; clamping",
                    self.nanos
                );
                i32::MAX
            }
        };

        let nanos_remainder = self.nanos % 1_000_000_000;
        #[allow(clippy::expect_used)] // remainder of % 1_000_000_000 always fits in u32
        let nanos_remainder =
            u32::try_from(nanos_remainder).expect("nanosecond remainder must be < 1_000_000_000");

        let fraction = ((u64::from(nanos_remainder)) << 32) / 1_000_000_000;
        #[allow(clippy::expect_used)] // (x << 32) / 1_000_000_000 where x < 1B always < 2^32
        let fraction = u32::try_from(fraction).expect("fraction fits in u32");

        (seconds, fraction)
    }

    /// Encode to CDR2 little-endian bytes
    #[must_use]
    pub fn encode_cdr2_le(&self) -> [u8; 8] {
        let (seconds, fraction) = self.to_rtps();

        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&seconds.to_le_bytes());
        buf[4..].copy_from_slice(&fraction.to_le_bytes());
        buf
    }

    /// Decode from CDR2 little-endian bytes
    pub fn decode_cdr2_le(buf: &[u8]) -> Option<Self> {
        if buf.len() < 8 {
            return None;
        }

        let seconds = i32::from_le_bytes(buf[0..4].try_into().ok()?);
        let fraction = u32::from_le_bytes(buf[4..8].try_into().ok()?);

        Some(Self::from_rtps(seconds, fraction))
    }

    /// Get elapsed time since this timestamp
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        let now = InfoTsMsg::now();
        if now.nanos >= self.nanos {
            Duration::from_nanos(now.nanos - self.nanos)
        } else {
            Duration::ZERO
        }
    }

    /// Check if timestamp is in the past
    #[must_use]
    pub fn is_past(&self) -> bool {
        self.nanos < InfoTsMsg::now().nanos
    }

    /// Check if timestamp is in the future
    #[must_use]
    pub fn is_future(&self) -> bool {
        self.nanos > InfoTsMsg::now().nanos
    }
}

impl Default for InfoTsMsg {
    fn default() -> Self {
        Self::now()
    }
}

// ============================================================================
// INFO_DST
// ============================================================================

/// Participant GUID prefix type alias.
pub type GuidPrefix = [u8; GUID_PREFIX_LEN];

/// INFO_DST message (RTPS INFO_DST submessage per DDS-RTPS v2.5 Sec.8.3.8.8).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InfoDstMsg {
    guid_prefix: GuidPrefix,
}

impl InfoDstMsg {
    /// Create INFO_DST message with specific GUID prefix.
    #[must_use]
    pub fn new(guid_prefix: GuidPrefix) -> Self {
        Self { guid_prefix }
    }

    /// Broadcast/multicast INFO_DST (all zeros).
    #[must_use]
    pub fn broadcast() -> Self {
        Self {
            guid_prefix: [0; GUID_PREFIX_LEN],
        }
    }

    /// Accessor for the GUID prefix.
    #[must_use]
    pub fn guid_prefix(&self) -> &GuidPrefix {
        &self.guid_prefix
    }

    /// Returns `true` when the prefix is all zeros (broadcast).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.guid_prefix.iter().all(|&b| b == 0)
    }

    /// Encode to CDR little-endian bytes.
    #[must_use]
    pub fn encode_cdr2_le(&self) -> [u8; GUID_PREFIX_LEN] {
        self.guid_prefix
    }

    /// Decode from CDR little-endian bytes.
    pub fn decode_cdr2_le(buf: &[u8]) -> Option<Self> {
        if buf.len() < GUID_PREFIX_LEN {
            return None;
        }

        let mut guid_prefix = [0u8; GUID_PREFIX_LEN];
        guid_prefix.copy_from_slice(&buf[..GUID_PREFIX_LEN]);
        Some(Self { guid_prefix })
    }

    /// Format GUID prefix as `XX:YY:...` hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.guid_prefix
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Default for InfoDstMsg {
    fn default() -> Self {
        Self::broadcast()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `decode_from_packet` was a one-line wrapper over the walk below and
    /// is gone (no production caller was left). The tests keep the
    /// shape they were written with, over the LIVE walk.
    fn first_heartbeat_of(packet: &[u8]) -> Option<HeartbeatMsg> {
        HeartbeatMsg::decode_all_from_packet(packet)
            .into_iter()
            .next()
    }

    /// Guid prefix the fixtures put in the RTPS header, distinctive enough
    /// that reading the header as a body shows up immediately.
    const PREFIX: [u8; GUID_PREFIX_LEN] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];
    const READER_ID: [u8; ENTITY_ID_LEN] = [0x00, 0x00, 0x01, 0x07];
    const WRITER_ID: [u8; ENTITY_ID_LEN] = [0x00, 0x00, 0x01, 0x02];
    /// A second writer of the same participant, so a batched datagram is
    /// distinguishable announcement by announcement.
    const OTHER_WRITER_ID: [u8; ENTITY_ID_LEN] = [0x00, 0x00, 0x0B, 0x02];

    /// One submessage, as a fixture describes it before serialisation.
    struct Sub {
        id: u8,
        /// Flags WITHOUT the endianness bit; the builder owns bit 0.
        flags: u8,
        body: Vec<u8>,
    }

    /// Serialise a HEARTBEAT body in the requested endianness.
    ///
    /// Asserts its own length, because every fixture below depends on the
    /// body being exactly the 28 octets Sec.8.3.8.6 fixes.
    fn heartbeat_body(first_seq: u64, last_seq: u64, count: u32, little_endian: bool) -> Vec<u8> {
        let mut body = Vec::with_capacity(28);
        body.extend_from_slice(&READER_ID);
        body.extend_from_slice(&WRITER_ID);

        for seq in [first_seq, last_seq] {
            // DDSI-RTPS 9.4.2.5: SequenceNumber_t is {long high, unsigned
            // long low}. try_from rather than a cast so a fixture that
            // outgrows the encoding fails here instead of silently
            // truncating.
            let high = u32::try_from(seq >> 32).expect("fixture high word fits");
            let low = u32::try_from(seq & 0xFFFF_FFFF).expect("fixture low word fits");
            if little_endian {
                body.extend_from_slice(&high.to_le_bytes());
                body.extend_from_slice(&low.to_le_bytes());
            } else {
                body.extend_from_slice(&high.to_be_bytes());
                body.extend_from_slice(&low.to_be_bytes());
            }
        }

        if little_endian {
            body.extend_from_slice(&count.to_le_bytes());
        } else {
            body.extend_from_slice(&count.to_be_bytes());
        }

        assert_eq!(body.len(), 28, "HEARTBEAT body is a fixed 28 octets");
        body
    }

    /// Build a well-formed RTPS datagram carrying `subs`.
    ///
    /// The builder asserts the invariants the decoder is entitled to rely
    /// on, so a fixture that drifts fails HERE rather than making a test
    /// pass for the wrong reason: every submessage header lands on a
    /// 4-byte boundary, and every declared length is the length of the
    /// body that follows it.
    fn datagram(little_endian: bool, subs: &[Sub]) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[0x02, 0x05]);
        packet.extend_from_slice(&[0x01, 0x1A]);
        packet.extend_from_slice(&PREFIX);
        assert_eq!(packet.len(), 20, "RTPS header is 20 octets");

        for sub in subs {
            assert_eq!(
                packet.len() % 4,
                0,
                "Sec.9.4.1: submessage headers are 4-byte aligned"
            );
            let len = u16::try_from(sub.body.len()).expect("fixture body fits octetsToNextHeader");
            packet.push(sub.id);
            packet.push(sub.flags | u8::from(little_endian));
            if little_endian {
                packet.extend_from_slice(&len.to_le_bytes());
            } else {
                packet.extend_from_slice(&len.to_be_bytes());
            }
            packet.extend_from_slice(&sub.body);
            // Sec.9.4.1: pad up to the next boundary. The padding is NOT
            // counted in octetsToNextHeader - stepping over it is the
            // reader's job, which is exactly what one of the tests below
            // pins.
            while packet.len() % 4 != 0 {
                packet.push(0x00);
            }
        }

        packet
    }

    /// A HEARTBEAT alone in a datagram, in the requested endianness.
    fn lone_heartbeat(first_seq: u64, last_seq: u64, count: u32, little_endian: bool) -> Vec<u8> {
        datagram(
            little_endian,
            &[Sub {
                id: 0x07,
                flags: 0x02, // FinalFlag, which is bit 1 and NOT an alignment flag
                body: heartbeat_body(first_seq, last_seq, count, little_endian),
            }],
        )
    }

    #[test]
    fn a_big_endian_heartbeat_decodes_exactly_like_its_little_endian_twin() {
        let le = first_heartbeat_of(&lone_heartbeat(3, 5, 7, true))
            .expect("little-endian HEARTBEAT must decode");
        let be = first_heartbeat_of(&lone_heartbeat(3, 5, 7, false))
            .expect("big-endian HEARTBEAT must decode");

        // The endianness is a transport detail; the decoded message is not.
        assert_eq!(le, be, "the same HEARTBEAT must decode to the same message");

        // Spelled out rather than left to the comparison: reading a
        // big-endian lastSN of 5 as little-endian yields 83 886 080, which
        // the reader turns into a gap range of that many sequences.
        assert_eq!(be.first_seq, 3);
        assert_eq!(be.last_seq, 5, "a lastSN of 5 is 5, not 83 886 080");
        assert_eq!(be.count, 7);
        assert_eq!(be.writer_guid_prefix, PREFIX);
        assert_eq!(be.writer_entity_id, WRITER_ID);
        assert_eq!(be.reader_entity_id, READER_ID);
    }

    #[test]
    fn a_big_endian_heartbeat_behind_another_submessage_is_still_found() {
        // Walking to the second submessage means reading the FIRST one's
        // octetsToNextHeader, which must be read in the datagram's own
        // byte order: a hard-coded little-endian read would send the walk
        // past the end of the datagram.
        let packet = datagram(
            false,
            &[
                Sub {
                    id: 0x09, // INFO_TS
                    flags: 0x00,
                    body: vec![0x00; 8],
                },
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: heartbeat_body(10, 42, 3, false),
                },
            ],
        );

        let hb = first_heartbeat_of(&packet).expect("a HEARTBEAT behind an INFO_TS must be found");
        assert_eq!(hb.first_seq, 10);
        assert_eq!(hb.last_seq, 42);
        assert_eq!(hb.count, 3);
    }

    #[test]
    fn a_submessage_whose_length_is_not_a_multiple_of_four_is_realigned() {
        // 21 octets of body, so the next header sits 3 octets of padding
        // further on. The DATA carries the InlineQos flag (bit 1) set,
        // which the previous code read as "no realignment needed" - bit 1
        // is submessage-specific and says nothing about alignment, so the
        // walk landed 3 octets short and never found the HEARTBEAT.
        let packet = datagram(
            true,
            &[
                Sub {
                    id: 0x15,    // DATA
                    flags: 0x02, // InlineQos
                    body: vec![0xEE; 21],
                },
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: heartbeat_body(1, 9, 4, true),
                },
            ],
        );

        let hb = first_heartbeat_of(&packet).expect("the walk must step over Sec.9.4.1 padding");
        assert_eq!(hb.first_seq, 1);
        assert_eq!(hb.last_seq, 9);
        assert_eq!(hb.count, 4);
    }

    #[test]
    fn the_sentinel_ends_the_chain() {
        // An ACKNACK declaring octetsToNextHeader = 0 is the last
        // submessage (Sec.8.3.3.3). What follows is its body, not a
        // header - even when the body happens to start with 0x07.
        let mut packet = datagram(
            true,
            &[Sub {
                id: 0x06, // ACKNACK
                flags: 0x00,
                body: Vec::new(),
            }],
        );
        packet.extend_from_slice(&[0x07, 0x03]);
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&heartbeat_body(1, 1, 1, true));

        assert!(
            first_heartbeat_of(&packet).is_none(),
            "nothing behind the sentinel is a submessage"
        );
    }

    #[test]
    fn a_heartbeat_that_is_the_last_submessage_may_declare_length_zero() {
        // Sec.9.4.5.1.3: octetsToNextHeader == 0 on a submessage that is not
        // PAD or INFO_TS means it runs to the end of the datagram. The
        // previous code compared that 0 against the 28-octet minimum and
        // refused the packet.
        let mut packet = datagram(true, &[]);
        packet.extend_from_slice(&[0x07, 0x03]);
        packet.extend_from_slice(&0u16.to_le_bytes());
        packet.extend_from_slice(&heartbeat_body(2, 6, 8, true));

        let hb = first_heartbeat_of(&packet)
            .expect("a sentinel HEARTBEAT runs to the end of the datagram");
        assert_eq!(hb.first_seq, 2);
        assert_eq!(hb.last_seq, 6);
        assert_eq!(hb.count, 8);
    }

    #[test]
    fn a_length_past_the_end_of_the_datagram_is_refused() {
        let mut packet = lone_heartbeat(1, 1, 1, true);
        // 7168 is what a big-endian 28 reads as when taken little-endian:
        // the value a decoder ignoring the E flag computes for a conforming peer.
        packet[22..24].copy_from_slice(&7168u16.to_le_bytes());

        assert!(
            first_heartbeat_of(&packet).is_none(),
            "a body that does not fit the datagram must be refused, not read"
        );
    }

    #[test]
    fn a_datagram_without_a_heartbeat_yields_nothing() {
        let packet = datagram(
            true,
            &[Sub {
                id: 0x15, // DATA
                flags: 0x00,
                body: vec![0x00; 32],
            }],
        );

        assert!(first_heartbeat_of(&packet).is_none());
    }
    #[test]
    fn a_malformed_heartbeat_does_not_hide_the_conforming_one_behind_it() {
        // Sec.8.3.3: submessages are independently valid. A 0x07 that
        // declares fewer octets than the 28 Sec.8.3.8.6 fixes is ONE
        // unreadable submessage, not an unreadable datagram - the walk must
        // step over it and keep looking, exactly as it steps over a DATA it
        // does not want. Refusing the packet threw away the conforming
        // HEARTBEAT behind it, so the reader NACKed nothing and the writer
        // reannounced the same range forever.
        let packet = datagram(
            false,
            &[
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: vec![0x00; 12],
                },
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: heartbeat_body(3, 5, 7, false),
                },
            ],
        );
        assert_eq!(
            packet.len(),
            68,
            "minimal case: header 20 + (4 + 12) + (4 + 28)"
        );

        let hb = first_heartbeat_of(&packet)
            .expect("a short 0x07 must not hide the HEARTBEAT behind it");
        assert_eq!(hb.first_seq, 3);
        assert_eq!(hb.last_seq, 5);
        assert_eq!(hb.count, 7);
        assert_eq!(hb.writer_entity_id, WRITER_ID);
    }

    /// Give a HEARTBEAT body a writer other than `WRITER_ID`.
    fn from_writer(mut body: Vec<u8>, writer: [u8; ENTITY_ID_LEN]) -> Vec<u8> {
        assert_eq!(body.len(), 28, "only a full HEARTBEAT body has a writerId");
        body[4..8].copy_from_slice(&writer);
        body
    }

    #[test]
    fn every_heartbeat_of_a_batched_datagram_is_decoded() {
        // Sec.8.3.3: submessages are independently valid, and a participant
        // batches one HEARTBEAT per writer it announces for. Reading only
        // the first left every other writer unanswered, so that writer
        // reannounced the same range forever.
        let packet = datagram(
            true,
            &[
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: heartbeat_body(3, 5, 7, true),
                },
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: from_writer(heartbeat_body(100, 200, 9, true), OTHER_WRITER_ID),
                },
            ],
        );

        let hbs = HeartbeatMsg::decode_all_from_packet(&packet);
        assert_eq!(hbs.len(), 2, "both announcements must be decoded");
        assert_eq!(hbs[0].writer_entity_id, WRITER_ID);
        assert_eq!((hbs[0].first_seq, hbs[0].last_seq, hbs[0].count), (3, 5, 7));
        assert_eq!(hbs[1].writer_entity_id, OTHER_WRITER_ID);
        assert_eq!(
            (hbs[1].first_seq, hbs[1].last_seq, hbs[1].count),
            (100, 200, 9)
        );

        // The singular door still answers with the first, and answers the
        // same first: there is ONE walk under both, not two that can drift.
        assert_eq!(first_heartbeat_of(&packet).as_ref(), hbs.first());
    }

    #[test]
    fn a_malformed_heartbeat_between_two_conforming_ones_costs_only_itself() {
        // The skip is per-submessage, not per-datagram: what precedes the
        // unreadable 0x07 is kept and what follows it is still read.
        let packet = datagram(
            true,
            &[
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: heartbeat_body(1, 2, 1, true),
                },
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: vec![0x00; 12],
                },
                Sub {
                    id: 0x07,
                    flags: 0x02,
                    body: from_writer(heartbeat_body(40, 41, 2, true), OTHER_WRITER_ID),
                },
            ],
        );

        let hbs = HeartbeatMsg::decode_all_from_packet(&packet);
        assert_eq!(hbs.len(), 2, "one unreadable 0x07 costs exactly one");
        assert_eq!(hbs[0].last_seq, 2);
        assert_eq!(hbs[1].last_seq, 41);
        assert_eq!(hbs[1].writer_entity_id, OTHER_WRITER_ID);
    }
}

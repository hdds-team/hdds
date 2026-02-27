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

// ============================================================================
// HEARTBEAT
// ============================================================================

/// GUID prefix length (12 bytes).
pub const GUID_PREFIX_LEN: usize = 12;
/// Entity ID length (4 bytes).
pub const ENTITY_ID_LEN: usize = 4;

/// Heartbeat message (RTPS HEARTBEAT submessage per DDS-RTPS v2.5 Sec.8.3.7.5).
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

    /// Encode to CDR2 little-endian bytes.
    #[must_use]
    pub fn encode_cdr2_le(&self) -> [u8; 20] {
        let mut buf = [0u8; 20];
        buf[0..8].copy_from_slice(&self.first_seq.to_le_bytes());
        buf[8..16].copy_from_slice(&self.last_seq.to_le_bytes());
        buf[16..20].copy_from_slice(&self.count.to_le_bytes());
        buf
    }

    /// Decode from CDR2 little-endian bytes (legacy: sequence info only).
    pub fn decode_cdr2_le(buf: &[u8]) -> Option<Self> {
        if buf.len() < 20 {
            return None;
        }

        let first_seq = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        let last_seq = u64::from_le_bytes(buf[8..16].try_into().ok()?);
        let count = u32::from_le_bytes(buf[16..20].try_into().ok()?);

        Some(Self {
            first_seq,
            last_seq,
            count,
            writer_guid_prefix: [0; GUID_PREFIX_LEN],
            writer_entity_id: [0; ENTITY_ID_LEN],
            reader_entity_id: [0; ENTITY_ID_LEN],
        })
    }

    /// Decode from full RTPS packet buffer.
    ///
    /// Extracts GUID prefix from RTPS header and entity IDs from HEARTBEAT submessage.
    ///
    /// Packet format:
    /// - RTPS Header (20 bytes): "RTPS" + version(2) + vendorId(2) + guidPrefix(12)
    /// - Submessage header (4 bytes): submessageId(1) + flags(1) + length(2)
    /// - HEARTBEAT payload: readerEntityId(4) + writerEntityId(4) + firstSN(8) + lastSN(8) + count(4)
    pub fn decode_from_packet(packet: &[u8]) -> Option<Self> {
        // Minimum: RTPS header(20) + submsg header(4) + HEARTBEAT payload(28) = 52 bytes
        if packet.len() < 52 {
            return None;
        }

        // Verify RTPS magic
        if &packet[0..4] != b"RTPS" {
            return None;
        }

        // Extract GUID prefix from RTPS header (bytes 8-20)
        let mut writer_guid_prefix = [0u8; GUID_PREFIX_LEN];
        writer_guid_prefix.copy_from_slice(&packet[8..20]);

        // Find HEARTBEAT submessage (0x07)
        let mut offset = 20; // Start after RTPS header
        while offset + 4 <= packet.len() {
            let submsg_id = packet[offset];
            let submsg_flags = packet[offset + 1];
            let submsg_len = u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize;

            if submsg_id == 0x07 {
                // HEARTBEAT found
                let payload_start = offset + 4;
                let payload_end = payload_start + submsg_len;
                if payload_end > packet.len() || submsg_len < 28 {
                    return None;
                }

                let payload = &packet[payload_start..payload_end];

                // Parse HEARTBEAT payload: readerEntityId(4) + writerEntityId(4) + firstSN(8) + lastSN(8) + count(4)
                let mut reader_entity_id = [0u8; ENTITY_ID_LEN];
                let mut writer_entity_id = [0u8; ENTITY_ID_LEN];
                reader_entity_id.copy_from_slice(&payload[0..4]);
                writer_entity_id.copy_from_slice(&payload[4..8]);

                // Sequence numbers: RTPS uses high(4) + low(4) format
                let first_high = i32::from_le_bytes(payload[8..12].try_into().ok()?);
                let first_low = u32::from_le_bytes(payload[12..16].try_into().ok()?);
                let last_high = i32::from_le_bytes(payload[16..20].try_into().ok()?);
                let last_low = u32::from_le_bytes(payload[20..24].try_into().ok()?);
                let count = u32::from_le_bytes(payload[24..28].try_into().ok()?);

                let first_seq = ((first_high as i64) << 32 | first_low as i64) as u64;
                let last_seq = ((last_high as i64) << 32 | last_low as i64) as u64;

                return Some(Self {
                    first_seq,
                    last_seq,
                    count,
                    writer_guid_prefix,
                    writer_entity_id,
                    reader_entity_id,
                });
            }

            // Skip to next submessage
            offset += 4 + submsg_len;
            // Align to 4 bytes if needed (depends on flags)
            if submsg_flags & 0x02 == 0 && !submsg_len.is_multiple_of(4) {
                offset += 4 - (submsg_len % 4);
            }
        }

        None // No HEARTBEAT submessage found
    }
}

// ============================================================================
// GAP (with SequenceNumberSet)
// ============================================================================

/// RTPS Entity ID (4 bytes).
pub type EntityId = [u8; 4];

/// RTPS constant: ENTITYID_UNKNOWN (reader side).
pub const ENTITYID_UNKNOWN_READER: EntityId = [0x00, 0x00, 0x00, 0xC7];

/// RTPS constant: generic USER_DATA writer entity (best-effort fallback).
pub const ENTITYID_UNKNOWN_WRITER: EntityId = [0x00, 0x00, 0x00, 0xC2];

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

/// GAP message (writer -> reader, RTPS GAP submessage per DDS-RTPS v2.5 Sec.8.3.7.4).
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
        buf.extend_from_slice(&(self.gap_start as i64).to_le_bytes());
        buf.extend_from_slice(&self.gap_list.base().to_le_bytes());
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

        let gap_start = i64::from_le_bytes(buf[offset..offset + 8].try_into().ok()?);
        if gap_start < 0 {
            return None;
        }
        offset += 8;

        let base = i64::from_le_bytes(buf[offset..offset + 8].try_into().ok()?);
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

/// NACK message (reader -> writer, RTPS ACKNACK submessage per DDS-RTPS v2.5 Sec.8.3.7.1).
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

/// INFO_TS message (RTPS INFO_TS submessage per DDS-RTPS v2.5 Sec.8.3.7.7)
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

/// INFO_DST message (RTPS INFO_DST submessage per DDS-RTPS v2.5 Sec.8.3.7.5).
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

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS control message parsers (HEARTBEAT, ACKNACK).
//!

use super::classifier::walk;
use super::control_types::{
    AckNackInfo, Addressed, GapInfo, GroupInfo, HeartbeatInfo, NackFragInfo,
};

/// Parse a HEARTBEAT submessage body (shared by the single-result, all-results,
/// and combined embedded-GAP+HEARTBEAT scanners below so the field layout is
/// defined in exactly one place).
///
/// `hb_offset` is the offset of the HEARTBEAT body, i.e. `submsg_offset + 4`
/// (right after the 4-byte submessage header). Caller has already verified
/// `hb_offset + 28 <= packet.len()`.
/// Fixed head of an ACKNACK body, before the variable-length bitmap:
/// readerEntityId 4, writerEntityId 4, readerSNState.bitmapBase 8,
/// readerSNState.numBits 4 (RTPS v2.5 Sec.8.3.8.1).
const ACKNACK_BODY_MIN_LEN: usize = 20;

/// DDS-Security 1.1 Sec.7.3.7.6/.7 submessage ids: these two bracket a
/// protected submessage whatever transformation sealed it. Defined here
/// (not imported from `security::crypto::secure_submessage`, which is
/// `cfg(feature = "security")`-gated) because recognizing an envelope's
/// bounds, to avoid misreading what is inside it, is a core-RTPS-parsing
/// concern independent of whether this build can actually decode one.
const SEC_PREFIX_ID: u8 = 0x31;
const SEC_POSTFIX_ID: u8 = 0x32;

/// Whether a submessage read while walking is "envelope-owned": sitting
/// between some SEC_PREFIX and its closing SEC_POSTFIX, as the AES256_GMAC
/// transformation leaves it (Sec.9.5.3.3.4.5's "authenticating only"
/// column) -- authenticated, not encrypted, so its plaintext bytes are
/// still sitting in the datagram exactly as if they were an independent,
/// unprotected submessage. The ordinary
/// (non-secure) ACKNACK/NACK_FRAG scanners must not read straight through a
/// SEC_PREFIX and SEC_POSTFIX (neither is an ACKNACK/NACK_FRAG id, so
/// neither trips either scanner) and re-find the GMAC-visible submessage
/// in between as a genuinely separate CLEAR one. On a secure SEDP writer
/// that is a protocol violation to refuse (`secure_sedp_acknack_must_be_refused`),
/// so a *correctly* protected ACKNACK would be refused and counted as
/// undecodable, never reaching the decode performed for it on the secure path.
/// Tracked as one running flag rather than precomputed spans because the
/// two scanners below make one linear pass each and the flag toggles in
/// wire order, same as `RtpsContext` does for INFO_DST/INFO_TS.
struct EnvelopeTracker {
    inside: bool,
}

impl EnvelopeTracker {
    fn new() -> Self {
        Self { inside: false }
    }

    /// Update on seeing submessage `id`; returns whether `id` itself is
    /// envelope-owned plaintext that a CLEAR-only scanner must skip. The
    /// SEC_PREFIX and SEC_POSTFIX submessages themselves are not ACKNACK or
    /// NACK_FRAG ids, so callers never need to ask about them specifically,
    /// but this still answers `false` for both: a scanner that only checks
    /// `id == 0x06`/`0x12` never calls this on them in practice.
    fn observe(&mut self, id: u8) -> bool {
        if id == SEC_PREFIX_ID {
            self.inside = true;
            return false;
        }
        if id == SEC_POSTFIX_ID {
            self.inside = false;
            return false;
        }
        self.inside
    }
}

/// Fixed head of a NACK_FRAG body, before the bitmap: readerEntityId 4,
/// writerEntityId 4, writerSN 8, fragmentNumberState.bitmapBase 4,
/// fragmentNumberState.numBits 4 (RTPS v2.5 Sec.8.3.8.12).
const NACK_FRAG_BODY_MIN_LEN: usize = 24;

/// Fixed HEARTBEAT body: readerEntityId 4, writerEntityId 4, firstSN 8,
/// lastSN 8, count 4 (RTPS v2.5 Sec.8.3.8.6).
const HEARTBEAT_BODY_LEN: usize = 28;

/// Fixed head of a GAP body, before the variable-length bitmap:
/// readerEntityId 4, writerEntityId 4, gapStart 8, gapList.base 8,
/// gapList.numBits 4 (RTPS v2.5 Sec.8.3.8.4).
const GAP_BODY_MIN_LEN: usize = 28;

fn parse_heartbeat_body(body: &[u8], flags: u8, is_le: bool) -> Option<HeartbeatInfo> {
    // `body` is bounded by the submessage, so a HEARTBEAT that declares a
    // length shorter than its own fixed 28-octet body (RTPS v2.5
    // Sec.8.3.8.6) is refused here instead of spilling into whatever
    // follows it in the datagram.
    if body.len() < HEARTBEAT_BODY_LEN {
        return None;
    }
    // writerEntityId: 4 bytes at +4 (after readerEntityId)
    let writer_entity_id: [u8; 4] = body[4..8].try_into().ok()?;

    // firstSeq: SequenceNumber_t {high: i32, low: u32} at +8
    let first_seq = if is_le {
        let high = i32::from_le_bytes(body[8..12].try_into().ok()?);
        let low = u32::from_le_bytes(body[12..16].try_into().ok()?);
        (high as i64) * (1i64 << 32) + (low as i64)
    } else {
        let high = i32::from_be_bytes(body[8..12].try_into().ok()?);
        let low = u32::from_be_bytes(body[12..16].try_into().ok()?);
        (high as i64) * (1i64 << 32) + (low as i64)
    };

    // lastSeq: SequenceNumber_t at +16
    let last_seq = if is_le {
        let high = i32::from_le_bytes(body[16..20].try_into().ok()?);
        let low = u32::from_le_bytes(body[20..24].try_into().ok()?);
        (high as i64) * (1i64 << 32) + (low as i64)
    } else {
        let high = i32::from_be_bytes(body[16..20].try_into().ok()?);
        let low = u32::from_be_bytes(body[20..24].try_into().ok()?);
        (high as i64) * (1i64 << 32) + (low as i64)
    };

    // count: u32 at +24
    let count = if is_le {
        u32::from_le_bytes(body[24..28].try_into().ok()?)
    } else {
        u32::from_be_bytes(body[24..28].try_into().ok()?)
    };

    // Flags: bit 1 = FinalFlag, bit 2 = LivelinessFlag
    let final_flag = flags & 0x02 != 0;
    let liveliness_flag = flags & 0x04 != 0;

    Some(HeartbeatInfo {
        writer_entity_id,
        first_seq,
        last_seq,
        count,
        final_flag,
        liveliness_flag,
    })
}

/// One submessage of an RTPS message, as the walks of this module read it
/// (RTPS v2.5 Sec.8.3.3).
///
/// `body` is the half-open range of THIS submessage's body. It is bounded by
/// the submessage, never by the datagram: `octetsToNextHeader == 0` means
/// "this submessage extends to the end of the message" (Sec.8.3.3.3), any
/// other value describes the body exactly. Checking the body against
/// `packet.len()` instead would have two consequences on a datagram that
/// declares a length shorter than the body it carries: the body parser is
/// handed the NEXT submessage's header as content, and the walk advances by
/// as little as five octets, so a single 64 KiB datagram of `07 01 01 00`
/// headers would yield 13 097 HEARTBEATs.
///
/// The walk of `classifier::walk` is what advances between submessages; this
/// is only the shape the three parsers below read.
///
/// It carries no traversal of its own: advancing between submessages,
/// including realigning on the 4-octet boundary of Sec.9.4.1, is the shared
/// walk's job, the same one the walks of `router.rs` use.
struct Submessage {
    id: u8,
    flags: u8,
    is_le: bool,
    body_start: usize,
    body_end: usize,
}

impl Submessage {
    fn of(found: &walk::Submessage) -> Self {
        Self {
            id: found.id,
            flags: found.flags,
            // Endianness of every multi-byte field of this submessage
            // (Sec.8.3.3.3, E flag = bit 0).
            is_le: found.flags & 0x01 != 0,
            body_start: found.offset + 4,
            body_end: found.body_end,
        }
    }
}

/// Distinct ACKNACKs collected from ONE datagram.
///
/// One ACKNACK names one (readerEntityId, writerEntityId) pair, so a peer
/// with several readers matched to several of our writers legitimately sends
/// a handful in one datagram. The bound exists for the same reason as
/// `MAX_EMBEDDED_GAPS_PER_PACKET`: without it a 64 KiB datagram of 28-octet
/// ACKNACKs yields 2339 of them,
/// dispatched one control message each into a 1024-slot channel whose
/// overflow is a silent drop.
const MAX_EMBEDDED_ACKNACKS_PER_PACKET: usize = 64;

/// Parse ALL ACKNACK submessages of an RTPS message, in wire order.
///
/// A datagram carries one ACKNACK per (reader, writer) pair, and reading
/// only the first one leaves every other writer named in it without a
/// repair request -- its reader then NACKs the same sequences forever.
///
/// Duplicates for the same pair are NOT coalesced: they are returned in wire
/// order so the last one processed wins, which is what the RTPS Count_t
/// ordering asks for (this parser does not read `count`, and the submessage
/// order of a datagram is the peer's own ordering).
pub fn parse_all_acknack_submessages(packet: &[u8]) -> Vec<AckNackInfo> {
    // Need at least RTPS header (20) + submessage header (4) + ACKNACK body (minimum 20)
    // ACKNACK body: readerEntityId(4) + writerEntityId(4) + bitmapBase(8) + numBits(4) = 20 min
    let mut out: Vec<AckNackInfo> = Vec::new();
    if packet.len() < 44 {
        return out;
    }

    // Verify RTPS magic
    if &packet[0..4] != b"RTPS" {
        return out;
    }

    // Find ACKNACK submessages (ID = 0x06)
    let mut envelope = EnvelopeTracker::new();
    walk::for_each_submessage(packet, |found| {
        let sub = Submessage::of(found);
        let envelope_owned = envelope.observe(sub.id);
        if sub.id == 0x06 && !envelope_owned {
            if out.len() >= MAX_EMBEDDED_ACKNACKS_PER_PACKET {
                log::debug!(
                    "[PARSE-ACKNACK] datagram carries more than {} ACKNACKs, ignoring the rest",
                    MAX_EMBEDDED_ACKNACKS_PER_PACKET
                );
                return walk::Step::Stop;
            }
            // Body bounded by the submessage, never by the datagram; a
            // short-declared ACKNACK is SKIPPED, not fatal (see
            // `parse_heartbeat_submessage`).
            if let Some(info) = parse_acknack_body(&packet[sub.body_start..sub.body_end], sub.is_le)
            {
                out.push(info);
            }
        }

        // Sec.8.3.3.3: a zero octetsToNextHeader means this submessage is
        // the last one of the message.
        walk::Step::Continue
    });

    out
}

/// Parse an ACKNACK submessage body (RTPS v2.5 Sec.8.3.8.1), shared by the
/// single-result and all-results readers above so the field layout is
/// defined in exactly one place.
///
/// `body` is already bounded by the submessage.
fn parse_acknack_body(body: &[u8], is_le: bool) -> Option<AckNackInfo> {
    if body.len() < ACKNACK_BODY_MIN_LEN {
        return None;
    }

    // readerEntityId: 4 bytes at +0
    let reader_entity_id: [u8; 4] = body[0..4].try_into().ok()?;

    // writerEntityId: 4 bytes at +4
    let writer_entity_id: [u8; 4] = body[4..8].try_into().ok()?;

    // Extract readerSNState (SequenceNumberSet) for retransmission
    // bitmapBase: 8 bytes at +8 (SequenceNumber_t = high:i32 + low:u32)
    // numBits: 4 bytes at +16 (u32)
    // bitmap: variable, (numBits + 31) / 32 * 4 bytes
    //
    // RTPS SequenceNumber_t is NOT a single i64, it's two words:
    //   - First 4 bytes: high word (signed i32)
    //   - Next 4 bytes: low word (unsigned u32)
    // The endianness flag affects each word individually, NOT the combined layout.
    // Combined value = (high << 32) | low
    let (sn_high, sn_low) = if is_le {
        let high = i32::from_le_bytes(body[8..12].try_into().ok()?);
        let low = u32::from_le_bytes(body[12..16].try_into().ok()?);
        (high, low)
    } else {
        let high = i32::from_be_bytes(body[8..12].try_into().ok()?);
        let low = u32::from_be_bytes(body[12..16].try_into().ok()?);
        (high, low)
    };
    // Combine into 64-bit sequence number (high can be negative for special values)
    let bitmap_base = ((sn_high as i64) << 32) | (sn_low as i64);

    let num_bits = if is_le {
        u32::from_le_bytes(body[16..20].try_into().ok()?)
    } else {
        u32::from_be_bytes(body[16..20].try_into().ok()?)
    };

    // Convert RTPS bitmap to missing_ranges
    let missing_ranges = parse_rtps_bitmap_to_ranges(
        &body[ACKNACK_BODY_MIN_LEN..],
        bitmap_base as u64,
        num_bits,
        is_le,
    );

    // Count_t follows the bitmap (RTPS 2.5 9.4.5.3).
    let count_at = usize::try_from(num_bits.min(256).div_ceil(32))
        .ok()
        .map(|words| ACKNACK_BODY_MIN_LEN + words * 4);
    let count = count_at
        .and_then(|at| body.get(at..at + 4))
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(|b| {
            if is_le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        });

    Some(AckNackInfo {
        reader_entity_id,
        writer_entity_id,
        missing_ranges,
        bitmap_base: bitmap_base as u64,
        count,
    })
}

/// Convert RTPS SequenceNumberSet bitmap to missing sequence ranges.
///
/// HDDS ACKNACK bitmap semantics (matching our builder in acknack.rs):
/// - bitmapBase is the first sequence number in the set
/// - Bit N corresponds to sequence (bitmapBase + N)
/// - Bit value 1 = sequence is MISSING (reader doesn't have it, needs retransmit)
/// - Bit value 0 = sequence is RECEIVED (reader already has it)
///
/// NOTE: This follows HDDS's internal convention where bit=1 means MISSING.
/// The builder (build_acknack_packet_with_final) sets bits for missing sequences,
/// so the parser must interpret them the same way for HDDS-to-HDDS interop.
///
/// This function extracts contiguous ranges of missing sequences.
fn parse_rtps_bitmap_to_ranges(
    bitmap_bytes: &[u8],
    bitmap_base: u64,
    num_bits: u32,
    is_le: bool,
) -> Vec<std::ops::Range<u64>> {
    let mut ranges = Vec::new();

    if num_bits == 0 {
        return ranges;
    }

    // Limit num_bits to reasonable value (256 per RTPS spec)
    let num_bits = num_bits.min(256) as usize;
    let word_count = num_bits.div_ceil(32);

    if bitmap_bytes.len() < word_count * 4 {
        return ranges;
    }

    let mut range_start: Option<u64> = None;

    for bit_idx in 0..num_bits {
        let word_idx = bit_idx / 32;
        let bit_in_word = bit_idx % 32;

        let word_offset = word_idx * 4;
        let word = if is_le {
            u32::from_le_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            u32::from_be_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        };

        // RTPS bitmap bit ordering - bit 0 is MSB (bit 31 of first word)
        // HDDS convention: bit=1 means MISSING (matches our builder)
        let bit_mask = 1u32 << (31 - bit_in_word);
        let is_missing = (word & bit_mask) != 0; // bit=1 -> MISSING
                                                 // saturating_add: no overflow panic
        let seq = bitmap_base.saturating_add(bit_idx as u64);

        if is_missing {
            if range_start.is_none() {
                range_start = Some(seq);
            }
        } else if let Some(start) = range_start {
            ranges.push(start..seq);
            range_start = None;
        }
    }

    // Close any open range at the end
    if let Some(start) = range_start {
        // saturating_add: no overflow panic on malformed packets
        ranges.push(start..bitmap_base.saturating_add(num_bits as u64));
    }

    ranges
}

/// Parse a GAP submessage body (shared by `parse_gap_submessage` and the
/// combined embedded-GAP+HEARTBEAT scanner below so the field layout and the
/// implicit-range materialization RTPS 2.5 sec 8.3.8.4 logic live in exactly
/// one place).
///
/// `g` is the offset of the GAP body, i.e. `submsg_offset + 4` (right after
/// the 4-byte submessage header). Caller has already verified
/// `g + 28 <= packet.len()`.
fn parse_gap_body(body: &[u8], is_le: bool) -> Option<GapInfo> {
    // `body` is bounded by the submessage (see `parse_heartbeat_body`).
    if body.len() < GAP_BODY_MIN_LEN {
        return None;
    }
    // writerEntityId at body offset +4
    let writer_entity_id: [u8; 4] = body[4..8].try_into().ok()?;

    // gapStart SequenceNumber_t at body offset +8
    let gap_start: u64 = if is_le {
        let high = i32::from_le_bytes(body[8..12].try_into().ok()?);
        let low = u32::from_le_bytes(body[12..16].try_into().ok()?);
        ((high as i64) << 32 | low as i64) as u64
    } else {
        let high = i32::from_be_bytes(body[8..12].try_into().ok()?);
        let low = u32::from_be_bytes(body[12..16].try_into().ok()?);
        ((high as i64) << 32 | low as i64) as u64
    };

    // gapList.base SequenceNumber_t at body offset +16
    let list_base: u64 = if is_le {
        let high = i32::from_le_bytes(body[16..20].try_into().ok()?);
        let low = u32::from_le_bytes(body[20..24].try_into().ok()?);
        ((high as i64) << 32 | low as i64) as u64
    } else {
        let high = i32::from_be_bytes(body[16..20].try_into().ok()?);
        let low = u32::from_be_bytes(body[20..24].try_into().ok()?);
        ((high as i64) << 32 | low as i64) as u64
    };

    // RTPS v2.5 Sec.8.3.8.4.3: a GAP is invalid when gapStart is zero or
    // negative, or when gapList is invalid, whose minimum must be >= 1
    // (Sec.8.3.5.5). Both are SequenceNumber_t, signed on the wire; the casts
    // above turn a negative one into a u64 at or above 2^63, so "negative"
    // reads here as "above i64::MAX".
    //
    // This is the ONE place every received GAP is decoded, on every door, so
    // the refusal lives here. Accepting such a GAP is not harmless: on a
    // reader whose reorder gate is not yet seeded, `ReorderGate::on_gap`
    // starts from gapStart, so a negative one would move the gate's base to
    // about 2^63. Every later DATA from that writer would then read as already
    // delivered and be dropped without a signal, and a HEARTBEAT can only move
    // the base forward - the writer would be blinded for that reader for good,
    // by one malformed submessage.
    const MAX_SEQUENCE_NUMBER: u64 = i64::MAX as u64;
    if gap_start == 0
        || gap_start > MAX_SEQUENCE_NUMBER
        || list_base == 0
        || list_base > MAX_SEQUENCE_NUMBER
    {
        log::debug!(
            "[control_parser] invalid GAP refused (Sec.8.3.8.4.3): gapStart={} gapList.base={} (as signed: {} / {})",
            gap_start,
            list_base,
            gap_start as i64,
            list_base as i64
        );
        return None;
    }

    // gapList.numBits at body offset +24
    let num_bits: u32 = if is_le {
        u32::from_le_bytes(body[24..28].try_into().ok()?)
    } else {
        u32::from_be_bytes(body[24..28].try_into().ok()?)
    };

    // Clamp to RTPS spec limit (256 bits)
    let num_bits = num_bits.min(256);
    let word_count = num_bits.div_ceil(32) as usize;

    // Expand the bitmap into individual sequence numbers.
    // Bit N set (MSB-first) means sequence (list_base + N) is irrelevant.
    let mut gap_list_seqs: Vec<u64> = Vec::new();
    let bitmap_start = GAP_BODY_MIN_LEN;
    if bitmap_start + word_count * 4 <= body.len() {
        for bit_idx in 0..num_bits as usize {
            let word_idx = bit_idx / 32;
            let bit_in_word = bit_idx % 32;
            let word_offset = bitmap_start + word_idx * 4;
            let word = if is_le {
                u32::from_le_bytes(
                    body[word_offset..word_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                )
            } else {
                u32::from_be_bytes(
                    body[word_offset..word_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                )
            };
            // RTPS bitmap: bit 0 is the most-significant bit (bit 31) of
            // the first word.
            let mask = 1u32 << (31 - bit_in_word);
            if word & mask != 0 {
                let seq = list_base.saturating_add(bit_idx as u64);
                if seq > 0 {
                    gap_list_seqs.push(seq);
                }
            }
        }
    }

    // RTPS 2.5 sec 8.3.8.4: a GAP declares irrelevant the CONTIGUOUS range
    // [gapStart, gapList.base - 1] IN ADDITION to the bitmap-set sequences at or
    // after gapList.base. The bitmap expansion above only covers the latter. Without
    // the implicit leading range, a late-joining reader would still wait forever for
    // sequences the writer purged (e.g. HEARTBEAT firstSN=1 then GAP gapStart=1
    // gapList.base=36 => [1,35] irrelevant). Cap the materialized range defensively
    // against a malformed oversized GAP.
    if list_base > gap_start {
        const MAX_GAP_RANGE: u64 = 1 << 16;
        let end = list_base.min(gap_start.saturating_add(MAX_GAP_RANGE));
        for seq in gap_start..end {
            if seq > 0 {
                gap_list_seqs.push(seq);
            }
        }
    }

    Some(GapInfo {
        writer_entity_id,
        gap_start,
        gap_list_base: list_base,
        gap_list_seqs,
    })
}

/// A normal compound datagram carries only a handful of writers. Keep the
/// all-GAP scanner bounded because each parsed GAP may materialize a large
/// implicit irrelevant-sequence range.
const MAX_EMBEDDED_GAPS_PER_PACKET: usize = 64;

/// Same bound, same reason, for HEARTBEATs.
///
/// Bounding each body by its own submessage already refuses the
/// impossible-length datagram, but a datagram of WELL-FORMED 32-octet
/// HEARTBEATs is syntactically irreproachable and still yields 2047 of them
/// out of one 65 535-octet packet, each becoming a `ControlMessage` in a
/// channel of capacity `CONTROL_CHANNEL_CAPACITY` (1024). Two datagrams
/// would be enough to flush every other peer's control traffic out of it.
///
/// A participant has three builtin reliable writers whose HEARTBEATs a
/// peer may bundle in one datagram (SEDP publications, subscriptions and
/// participant-message), so 64 leaves twenty times that need. Truncation is safe here and nowhere
/// else: HEARTBEATs are idempotent and reannounced periodically, which is
/// why the listener already drops them when the channel is full. It is
/// logged rather than silent, because a bound that leaves no trace is
/// indistinguishable from a parser that lost the data.
const MAX_EMBEDDED_HEARTBEATS_PER_PACKET: usize = 64;

/// Distinct samples whose fragment requests are collected from ONE datagram.
///
/// An entry is one (writerEntityId, writerSN) pair, i.e. one SAMPLE, not one
/// submessage: a reader may split a single sample's missing-fragment set
/// across many NACK_FRAG submessages and they all coalesce into one entry. The
/// bound is therefore on how many different samples a peer may ask about in
/// one datagram, which is naturally a handful.
///
/// Without it, a 64 KiB datagram of 28-octet NACK_FRAGs carrying distinct
/// sequence numbers yields 2339 entries, dispatched as 2339 control messages
/// into a 1024-slot channel whose overflow is a silent drop - the reliability
/// traffic of every other peer is discarded to make room for one datagram -
/// and costs about 2 ms of CPU on the receive path (release build). Same bound and same reason as
/// `MAX_EMBEDDED_GAPS_PER_PACKET`.
const MAX_EMBEDDED_NACK_FRAGS_PER_PACKET: usize = 64;

/// A parsed HEARTBEAT or GAP with its readerId, the first four octets of
/// both bodies (RTPS v2.5 Sec.8.3.8.4, 8.3.8.6).
fn addressed<T>(body: &[u8], info: T) -> Option<Addressed<T>> {
    Some(Addressed {
        reader_entity_id: body.get(..4)?.try_into().ok()?,
        info,
        filtered_count: None,
        group_info: None,
    })
}

/// A SequenceNumber_t at `at` in `body` (`high` signed, `low` unsigned,
/// RTPS v2.5 Sec.9.3.2), `None` when the body is too short.
fn sequence_number_at(body: &[u8], at: usize, is_le: bool) -> Option<i64> {
    let high: [u8; 4] = body.get(at..at + 4)?.try_into().ok()?;
    let low: [u8; 4] = body.get(at + 4..at + 8)?.try_into().ok()?;
    let (high, low) = if is_le {
        (i32::from_le_bytes(high), u32::from_le_bytes(low))
    } else {
        (i32::from_be_bytes(high), u32::from_be_bytes(low))
    };
    Some((i64::from(high) << 32) | i64::from(low))
}

/// The GroupInfo of a HEARTBEAT body whose GroupInfoFlag (`flags & 0x08`)
/// is set: currentGSN, firstGSN, lastGSN after `count` (RTPS v2.5
/// Sec.9.4.5.7, D15). `None` without the flag, with a body too short to
/// hold it, or with values the validity rules of Sec.8.3.8.6.3 refuse,
/// except `currentGSN > lastGSN`: currentGSN is the Publisher's last GSN,
/// which runs past this writer's lastGSN whenever another writer of the
/// Publisher wrote last (D3). The HEARTBEAT itself stays valid without
/// its GroupInfo.
fn heartbeat_group_info(body: &[u8], flags: u8, is_le: bool) -> Option<GroupInfo> {
    if flags & 0x08 == 0 {
        return None;
    }
    let current = sequence_number_at(body, HEARTBEAT_BODY_LEN, is_le)?;
    let first = sequence_number_at(body, HEARTBEAT_BODY_LEN + 8, is_le)?;
    let last = sequence_number_at(body, HEARTBEAT_BODY_LEN + 16, is_le)?;
    if current <= 0 || first <= 0 || last < 0 || last < first - 1 || current < first {
        log::debug!(
            "[control_parser] invalid HEARTBEAT GroupInfo ignored (Sec.8.3.8.6.3): current={} first={} last={}",
            current,
            first,
            last
        );
        return None;
    }
    Some(GroupInfo::Heartbeat {
        current_gsn: current.unsigned_abs(),
        first_gsn: first.unsigned_abs(),
        last_gsn: last.unsigned_abs(),
        // The PIM (8.3.8.6) includes these digests; the UDP PSM
        // (9.4.5.7) ends after lastGSN. Accept both representations.
        writer_set: body
            .get(HEARTBEAT_BODY_LEN + 24..HEARTBEAT_BODY_LEN + 32)
            .and_then(|bytes| {
                let first: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
                let second: [u8; 4] = bytes.get(4..)?.try_into().ok()?;
                Some((first, second))
            }),
    })
}

/// The GroupInfo of a GAP body whose GroupInfoFlag (`flags & 0x02`) is
/// set: gapStartGSN, gapEndGSN after the gapList (RTPS v2.5 Sec.9.4.5.6).
/// `None` without the flag, with a body too short to hold it, or with
/// values the validity rules of Sec.8.3.8.4.3 refuse.
fn gap_group_info(body: &[u8], flags: u8, is_le: bool) -> Option<GroupInfo> {
    if flags & 0x02 == 0 {
        return None;
    }
    let num_bits_bytes: [u8; 4] = body.get(24..28)?.try_into().ok()?;
    let num_bits = if is_le {
        u32::from_le_bytes(num_bits_bytes)
    } else {
        u32::from_be_bytes(num_bits_bytes)
    };
    if num_bits > 256 {
        return None;
    }
    let at = GAP_BODY_MIN_LEN + usize::try_from(num_bits.div_ceil(32)).ok()? * 4;
    let start = sequence_number_at(body, at, is_le)?;
    let end = sequence_number_at(body, at + 8, is_le)?;
    if start <= 0 || end <= 0 || end < start - 1 {
        log::debug!(
            "[control_parser] invalid GAP GroupInfo ignored (Sec.8.3.8.4.3): start={} end={}",
            start,
            end
        );
        return None;
    }
    Some(GroupInfo::Gap {
        start_gsn: start.unsigned_abs(),
        end_gsn: end.unsigned_abs(),
    })
}

/// The filteredCount of a GAP body, when its FilteredCountFlag (`flags &
/// 0x04`) is set (RTPS v2.5 Sec.9.4.5.6): a ChangeCount_t (`high` signed,
/// `low` unsigned, Sec.9.3.2.11) after the gapList, and after the
/// gapStartGSN and gapEndGSN when the GroupInfoFlag (`flags & 0x02`) is set.
/// `None` without the flag, or when the body is too short to hold it or
/// the count is negative (malformed: the count is taken as absent, the
/// changes as not filtered).
fn gap_filtered_count(body: &[u8], flags: u8, is_le: bool) -> Option<u64> {
    if flags & 0x04 == 0 || body.len() < GAP_BODY_MIN_LEN {
        return None;
    }
    let word = |at: usize| -> Option<[u8; 4]> { body.get(at..at + 4)?.try_into().ok() };
    let u32_at = |at: usize| -> Option<u32> {
        let bytes = word(at)?;
        Some(if is_le {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    };
    // gapList.numBits at body offset +24; the bitmap holds ceil(numBits/32)
    // words (Sec.9.4.2.6).
    let num_bits = u32_at(24)?;
    if num_bits > 256 {
        return None;
    }
    let mut at = GAP_BODY_MIN_LEN + usize::try_from(num_bits.div_ceil(32)).ok()? * 4;
    if flags & 0x02 != 0 {
        at += 16;
    }
    let high = i32::from_ne_bytes(u32_at(at)?.to_ne_bytes());
    let low = u32_at(at + 4)?;
    let high = u64::try_from(high).ok()?;
    Some((high << 32) | u64::from(low))
}

/// Fuzzing entry point for the embedded HEARTBEAT/GAP walk. Compiled only
/// under `--cfg fuzzing` (set by cargo-fuzz), so the production API is unchanged.
#[cfg(fuzzing)]
pub fn fuzz_scan_embedded_control(packet: &[u8]) {
    let _ = scan_all_embedded_control_submessages(packet);
}

/// Single-pass scan for embedded control submessages inside a Data-classified
/// compound RTPS packet.
///
/// The packet classifier (`classify_rtps`) assigns ONE `PacketKind` per RTPS
/// packet, and a compound message like `[GAP, INFO_TS, DATA]` or
/// `[INFO_TS, DATA, HEARTBEAT]` classifies as `PacketKind::Data`
/// once a DATA submessage is found. The listener's hot receive path already
/// walks every submessage header in such packets to find embedded HEARTBEATs
/// (see `listener.rs`); this function extends that SAME walk to also collect
/// embedded GAPs, so a second full submessage scan is never needed.
///
/// Returns `(embedded GAPs, embedded HEARTBEATs, has NACK_FRAG)`. Collections
/// preserve wire order. GAP collection is capped at 64 entries to bound work
/// on malformed packets; NACK_FRAG bodies are decoded by the existing
/// coalescing parser only when the boolean reports one.
pub(crate) fn scan_all_embedded_control_submessages(
    packet: &[u8],
) -> (Vec<Addressed<GapInfo>>, Vec<Addressed<HeartbeatInfo>>, bool) {
    let mut gaps: Vec<Addressed<GapInfo>> = Vec::new();
    let mut heartbeats: Vec<Addressed<HeartbeatInfo>> = Vec::new();
    let mut has_nack_frag = false;
    let mut truncated = false;

    if packet.len() < 52 || &packet[0..4] != b"RTPS" {
        return (gaps, heartbeats, has_nack_frag);
    }

    walk::for_each_submessage(packet, |found| {
        let sub = Submessage::of(found);
        // Extra cost for packets without a GAP: one u8 compare per submessage
        // header, same shape as the id == 0x07 check below.
        if sub.id == 0x08 {
            if gaps.len() < MAX_EMBEDDED_GAPS_PER_PACKET {
                let body = &packet[sub.body_start..sub.body_end];
                if let Some(mut gap) =
                    parse_gap_body(body, sub.is_le).and_then(|g| addressed(body, g))
                {
                    gap.filtered_count = gap_filtered_count(body, sub.flags, sub.is_le);
                    gap.group_info = gap_group_info(body, sub.flags, sub.is_le);
                    gaps.push(gap);
                }
            } else if !truncated {
                truncated = true;
                log::debug!(
                    "[SCAN-CTRL] datagram carries more than {} GAPs, ignoring the rest",
                    MAX_EMBEDDED_GAPS_PER_PACKET
                );
            }
        } else if sub.id == 0x07 {
            if heartbeats.len() < MAX_EMBEDDED_HEARTBEATS_PER_PACKET {
                let body = &packet[sub.body_start..sub.body_end];
                if let Some(mut hb) = parse_heartbeat_body(body, sub.flags, sub.is_le)
                    .and_then(|h| addressed(body, h))
                {
                    hb.group_info = heartbeat_group_info(body, sub.flags, sub.is_le);
                    heartbeats.push(hb);
                }
            } else if !truncated {
                truncated = true;
                log::debug!(
                    "[SCAN-CTRL] datagram carries more than {} HEARTBEATs, ignoring the rest",
                    MAX_EMBEDDED_HEARTBEATS_PER_PACKET
                );
            }
        } else if sub.id == 0x12 {
            has_nack_frag = true;
        }

        // Sec.8.3.3.3: a zero octetsToNextHeader means this submessage is
        // the last one of the message.
        walk::Step::Continue
    });

    (gaps, heartbeats, has_nack_frag)
}

/// Parse ALL NACK_FRAG submessages in an RTPS message, coalesced per
/// (writerEntityId, writerSN).
///
/// A reader may bundle its fragment nacks as one compound message
/// `[INFO_DST, ACKNACK, NACK_FRAG x N]`, splitting a single sample's
/// missing-fragment set across several NACK_FRAG submessages (RTPS v2.5
/// Sec.8.3.3 lets one message carry any number of submessages).
/// Returning only the first submessage would drop the rest of the request,
/// so the writer-side selective retransmit would never see the full
/// picture -- or, when the packet classified as AckNack, any of it.
/// Coalescing here keeps the per-sample dispatch downstream (one
/// `ControlMessage` per sample, not per submessage) and unions duplicate
/// fragment requests instead of re-dispatching them.
///
/// Bounded at `MAX_EMBEDDED_NACK_FRAGS_PER_PACKET` distinct samples; a
/// sample already collected keeps absorbing its later submessages past that
/// bound.
pub fn parse_all_nack_frag_submessages(packet: &[u8]) -> Vec<NackFragInfo> {
    // Need at least RTPS header (20) + submessage header (4) + NACK_FRAG body (minimum 24)
    // NACK_FRAG body: readerEntityId(4) + writerEntityId(4) + writerSN(8) + bitmapBase(4) + numBits(4) = 24 min
    let mut out: Vec<NackFragInfo> = Vec::new();
    let mut truncated = false;
    if packet.len() < 48 {
        return out;
    }

    // Verify RTPS magic
    if &packet[0..4] != b"RTPS" {
        return out;
    }

    // Find NACK_FRAG submessages (ID = 0x12)
    let mut envelope = EnvelopeTracker::new();
    walk::for_each_submessage(packet, |found| {
        let sub = Submessage::of(found);
        let envelope_owned = envelope.observe(sub.id);
        if sub.id == 0x12 && !envelope_owned {
            // Body bounded by the submessage; a short-declared NACK_FRAG is
            // SKIPPED, not fatal (see `parse_heartbeat_submessage`).
            let body = &packet[sub.body_start..sub.body_end];
            if body.len() < NACK_FRAG_BODY_MIN_LEN {
                return walk::Step::Continue;
            }

            // readerEntityId: 4 bytes at +0
            let reader_entity_id: [u8; 4] = body[0..4].try_into().unwrap_or_default();

            // writerEntityId: 4 bytes at +4
            let writer_entity_id: [u8; 4] = body[4..8].try_into().unwrap_or_default();

            // writerSN: 8 bytes at +8 (SequenceNumber_t = high:i32 + low:u32)
            let (sn_high, sn_low) = if sub.is_le {
                let high = i32::from_le_bytes(body[8..12].try_into().unwrap_or_default());
                let low = u32::from_le_bytes(body[12..16].try_into().unwrap_or_default());
                (high, low)
            } else {
                let high = i32::from_be_bytes(body[8..12].try_into().unwrap_or_default());
                let low = u32::from_be_bytes(body[12..16].try_into().unwrap_or_default());
                (high, low)
            };
            let writer_sn = ((sn_high as i64) << 32) | (sn_low as i64);

            // fragmentNumberState.bitmapBase: 4 bytes at +16 (first fragment number, u32)
            let bitmap_base = if sub.is_le {
                u32::from_le_bytes(body[16..20].try_into().unwrap_or_default())
            } else {
                u32::from_be_bytes(body[16..20].try_into().unwrap_or_default())
            };

            // fragmentNumberState.numBits: 4 bytes at +20
            let num_bits = if sub.is_le {
                u32::from_le_bytes(body[20..24].try_into().unwrap_or_default())
            } else {
                u32::from_be_bytes(body[20..24].try_into().unwrap_or_default())
            };

            // Which entry this submessage belongs to, decided BEFORE the
            // bitmap is decoded: past the cap a new sample costs one lookup
            // per submessage instead of a full body decode.
            //
            // A sample already in `out` is ALWAYS coalesced, cap or not.
            // Refusing it would drop the tail of a fragment request that has
            // already been accepted, which is the very defect this parser
            // exists to avoid - the cap bounds how many samples a datagram may
            // introduce, not how completely each one is read.
            let existing = out.iter().position(|e| {
                e.writer_entity_id == writer_entity_id && e.writer_sn == writer_sn as u64
            });
            if existing.is_none() && out.len() >= MAX_EMBEDDED_NACK_FRAGS_PER_PACKET {
                if !truncated {
                    truncated = true;
                    log::debug!(
                        "[PARSE-NACKFRAG] datagram asks about more than {} samples, ignoring the rest",
                        MAX_EMBEDDED_NACK_FRAGS_PER_PACKET
                    );
                }
                return walk::Step::Continue;
            }

            // Parse bitmap to get missing fragment numbers
            let bitmap_offset = NACK_FRAG_BODY_MIN_LEN;
            let missing_fragments =
                parse_fragment_bitmap(&body[bitmap_offset..], bitmap_base, num_bits, sub.is_le);

            // count: after bitmap
            let bitmap_words = num_bits.div_ceil(32) as usize;
            let count_offset = bitmap_offset + bitmap_words * 4;
            let count = if count_offset + 4 <= body.len() {
                if sub.is_le {
                    u32::from_le_bytes(
                        body[count_offset..count_offset + 4]
                            .try_into()
                            .unwrap_or_default(),
                    )
                } else {
                    u32::from_be_bytes(
                        body[count_offset..count_offset + 4]
                            .try_into()
                            .unwrap_or_default(),
                    )
                }
            } else {
                0
            };

            // Coalesce with an earlier submessage for the same sample: union
            // the missing sets, keep the highest count.
            if let Some(idx) = existing {
                let entry = &mut out[idx];
                for frag in missing_fragments {
                    if !entry.missing_fragments.contains(&frag) {
                        entry.missing_fragments.push(frag);
                    }
                }
                entry.count = entry.count.max(count);
            } else {
                out.push(NackFragInfo {
                    reader_entity_id,
                    writer_entity_id,
                    writer_sn: writer_sn as u64,
                    missing_fragments,
                    count,
                });
            }
        }

        // Sec.8.3.3.3: a zero octetsToNextHeader means this submessage is
        // the last one of the message.
        walk::Step::Continue
    });

    out
}

/// Parse fragment bitmap to get list of missing fragment numbers.
///
/// NACK_FRAG uses fragmentNumberState (similar to SequenceNumberSet but for fragments).
/// - bitmapBase is the first fragment number (1-based per RTPS spec)
/// - Bit N corresponds to fragment (bitmapBase + N)
/// - Bit value 1 = fragment is MISSING
/// - Bit value 0 = fragment is received
fn parse_fragment_bitmap(
    bitmap_bytes: &[u8],
    bitmap_base: u32,
    num_bits: u32,
    is_le: bool,
) -> Vec<u32> {
    let mut missing = Vec::new();

    if num_bits == 0 {
        return missing;
    }

    // Limit num_bits to reasonable value (256 per RTPS spec)
    // Keep native u32 type for consistency with bitmap_base
    let num_bits = num_bits.min(256);
    let word_count = num_bits.div_ceil(32) as usize;

    if bitmap_bytes.len() < word_count * 4 {
        return missing;
    }

    for bit_idx in 0..num_bits {
        let word_idx = (bit_idx / 32) as usize;
        let bit_in_word = bit_idx % 32;

        let word_offset = word_idx * 4;
        let word = if is_le {
            u32::from_le_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        } else {
            u32::from_be_bytes(
                bitmap_bytes[word_offset..word_offset + 4]
                    .try_into()
                    .unwrap_or([0; 4]),
            )
        };

        // RTPS bitmap bit ordering - bit 0 is MSB (bit 31 of first word)
        let bit_mask = 1u32 << (31 - bit_in_word);
        let is_missing = (word & bit_mask) != 0;

        if is_missing {
            // saturating_add: no overflow panic on malformed packets
            missing.push(bitmap_base.saturating_add(bit_idx));
        }
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    // These helpers give the tests a single-result view (first GAP, first
    // HEARTBEAT, ...) while exercising the same walk production uses.
    fn first_gap(packet: &[u8]) -> Option<GapInfo> {
        scan_all_embedded_control_submessages(packet)
            .0
            .into_iter()
            .next()
            .map(|gap| gap.info)
    }
    fn all_heartbeats(packet: &[u8]) -> Vec<HeartbeatInfo> {
        scan_all_embedded_control_submessages(packet)
            .1
            .into_iter()
            .map(|hb| hb.info)
            .collect()
    }
    fn first_heartbeat(packet: &[u8]) -> Option<HeartbeatInfo> {
        all_heartbeats(packet).into_iter().next()
    }
    fn first_acknack(packet: &[u8]) -> Option<AckNackInfo> {
        parse_all_acknack_submessages(packet).into_iter().next()
    }
    fn first_nack_frag(packet: &[u8]) -> Option<NackFragInfo> {
        parse_all_nack_frag_submessages(packet).into_iter().next()
    }
    fn all_gaps_and_heartbeats(packet: &[u8]) -> (Vec<GapInfo>, Vec<HeartbeatInfo>) {
        let (gaps, heartbeats, _) = scan_all_embedded_control_submessages(packet);
        (
            gaps.into_iter().map(|gap| gap.info).collect(),
            heartbeats.into_iter().map(|hb| hb.info).collect(),
        )
    }
    fn first_gap_and_heartbeats(packet: &[u8]) -> (Option<GapInfo>, Vec<HeartbeatInfo>) {
        let (gaps, heartbeats) = all_gaps_and_heartbeats(packet);
        (gaps.into_iter().next(), heartbeats)
    }

    #[test]
    fn test_parse_heartbeat() {
        // Build minimal HEARTBEAT packet
        let mut packet = Vec::new();

        // RTPS Header (20 bytes)
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 4]); // Version
        packet.extend_from_slice(&[0x01, 0x0f]); // FastDDS vendor
        packet.extend_from_slice(&[0x01; 12]); // GUID prefix

        // HEARTBEAT submessage
        packet.push(0x07); // ID
        packet.push(0x03); // Flags: little-endian + FinalFlag
        packet.extend_from_slice(&28u16.to_le_bytes()); // Length

        // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x04]);
        // writerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x03]);
        // firstSeq: {high=0, low=1}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&1u32.to_le_bytes());
        // lastSeq: {high=0, low=5}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&5u32.to_le_bytes());
        // count
        packet.extend_from_slice(&42u32.to_le_bytes());

        let hb = first_heartbeat(&packet).expect("Should parse");
        assert_eq!(hb.writer_entity_id, [0x00, 0x00, 0x01, 0x03]);
        assert_eq!(hb.first_seq, 1);
        assert_eq!(hb.last_seq, 5);
        assert_eq!(hb.count, 42);
        assert!(hb.final_flag);
        assert!(!hb.liveliness_flag);
    }

    #[test]
    fn test_parse_bitmap_to_ranges_empty() {
        let ranges = parse_rtps_bitmap_to_ranges(&[], 1, 0, true);
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_parse_bitmap_to_ranges_single_missing() {
        // Bitmap with bit 0 set (MSB) = sequence 1 missing
        // When is_le=false, [0x80, 0x00, 0x00, 0x00] is read as 0x80_00_00_00 (BE)
        // Bit 0 (MSB = bit 31) is then correctly detected as set
        let bitmap = [0x80, 0x00, 0x00, 0x00]; // bit 0 set in MSB
        let ranges = parse_rtps_bitmap_to_ranges(&bitmap, 1, 1, false);
        assert_eq!(ranges, vec![1..2]);
    }

    #[test]
    fn test_parse_bitmap_to_ranges_single_missing_le() {
        // For little-endian encoded packets, [0x00, 0x00, 0x00, 0x80] is read as 0x80_00_00_00
        // which has bit 31 (= bitmap bit 0) set
        let bitmap = [0x00, 0x00, 0x00, 0x80]; // bit 0 set when read as LE
        let ranges = parse_rtps_bitmap_to_ranges(&bitmap, 1, 1, true);
        assert_eq!(ranges, vec![1..2]);
    }

    #[test]
    fn test_parse_nack_frag() {
        // Build minimal NACK_FRAG packet requesting fragments 2 and 4
        let mut packet = Vec::new();

        // RTPS Header (20 bytes)
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 4]); // Version
        packet.extend_from_slice(&[0x01, 0x1A]); // HDDS vendor
        packet.extend_from_slice(&[0x01; 12]); // GUID prefix

        // NACK_FRAG submessage
        packet.push(0x12); // ID = NACK_FRAG
        packet.push(0x01); // Flags: little-endian
                           // octetsToNextHeader = 4 + 4 + 8 + 4 + 4 + 4 + 4 = 32
        packet.extend_from_slice(&32u16.to_le_bytes());

        // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x04]);
        // writerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x03]);
        // writerSN: {high=0, low=42}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&42u32.to_le_bytes());
        // fragmentNumberState.bitmapBase = 2
        packet.extend_from_slice(&2u32.to_le_bytes());
        // fragmentNumberState.numBits = 4 (covers fragments 2, 3, 4, 5)
        packet.extend_from_slice(&4u32.to_le_bytes());
        // bitmap: bits for fragments 2 and 4 set (bit 0 and bit 2 set)
        // MSB-first: bit 0 = fragment 2, bit 2 = fragment 4
        // Binary: 1010_0000_... = 0xA0000000 in LE = [0x00, 0x00, 0x00, 0xA0]
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0xA0]);
        // count
        packet.extend_from_slice(&5u32.to_le_bytes());

        let nf = first_nack_frag(&packet).expect("Should parse");
        assert_eq!(nf.reader_entity_id, [0x00, 0x00, 0x01, 0x04]);
        assert_eq!(nf.writer_entity_id, [0x00, 0x00, 0x01, 0x03]);
        assert_eq!(nf.writer_sn, 42);
        assert_eq!(nf.missing_fragments, vec![2, 4]);
        assert_eq!(nf.count, 5);
    }

    #[test]
    fn test_parse_gap_includes_implicit_leading_range() {
        // GAP gapStart=1, gapList.base=36, empty bitmap (a writer that purged SN 1..35).
        // RTPS 2.5 sec 8.3.8.4: [gapStart, base-1] = [1,35] are ALL irrelevant. The parser
        // must materialize that implicit range, not just the bitmap, or a late-joiner
        // Durability reader waits forever for the purged sample 1.
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 4]); // Version
        packet.extend_from_slice(&[0x01, 0x03]); // vendor (opendds)
        packet.extend_from_slice(&[0x01; 12]); // GUID prefix

        packet.push(0x08); // GAP submessage ID
        packet.push(0x01); // Flags: little-endian
        packet.extend_from_slice(&28u16.to_le_bytes()); // octetsToNextHeader

        // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x07]);
        // writerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        // gapStart: {high=0, low=1}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&1u32.to_le_bytes());
        // gapList.base: {high=0, low=36}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&36u32.to_le_bytes());
        // gapList.numBits = 0 (empty bitmap)
        packet.extend_from_slice(&0u32.to_le_bytes());

        let gap = first_gap(&packet).expect("should parse GAP");
        assert_eq!(gap.writer_entity_id, [0x00, 0x00, 0x00, 0x02]);
        assert_eq!(gap.gap_start, 1);
        // Implicit range [1,35] must be present.
        for seq in 1..=35u64 {
            assert!(
                gap.gap_list_seqs.contains(&seq),
                "implicit irrelevant seq {seq} missing from gap_list_seqs"
            );
        }
        // base (36) and beyond are NOT in the empty bitmap -> must NOT be declared irrelevant.
        assert!(!gap.gap_list_seqs.contains(&36));
    }

    /// GAP-first compound: some vendors bundle [INFO_DST, GAP, HEARTBEAT] in
    /// ONE RTPS message during durable history replay. Both extractors must
    /// coexist on the same buffer: parse_gap_submessage finds the GAP
    /// (gapStart=1, gapList.base=52, empty bitmap) AND
    /// parse_all_heartbeat_submessages finds the trailing HEARTBEAT
    /// (firstSN=52, lastSN=52). This is the wire shape the listener's
    /// embedded-HEARTBEAT extraction depends on.
    #[test]
    fn test_parse_gap_first_compound_extracts_gap_and_heartbeat() {
        let mut packet = Vec::new();

        // RTPS Header (20 bytes)
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[2, 5]); // Version
        packet.extend_from_slice(&[0x01, 0x1A]); // HDDS vendor
        packet.extend_from_slice(&[0x0A; 12]); // GUID prefix

        // INFO_DST submessage (ID 0x0e, body = destination guidPrefix, 12 bytes)
        packet.push(0x0e);
        packet.push(0x01); // Flags: little-endian
        packet.extend_from_slice(&12u16.to_le_bytes()); // octetsToNextHeader
        packet.extend_from_slice(&[0x0B; 12]); // destination guidPrefix

        // GAP submessage (ID 0x08): gapStart=1, gapList.base=52, numBits=0
        packet.push(0x08);
        packet.push(0x01); // Flags: little-endian
        packet.extend_from_slice(&28u16.to_le_bytes()); // octetsToNextHeader

        // readerEntityId = ENTITYID_UNKNOWN
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // writerEntityId = 0x00000102 (user writer)
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]);
        // gapStart: {high=0, low=1}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&1u32.to_le_bytes());
        // gapList.base: {high=0, low=52}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&52u32.to_le_bytes());
        // gapList.numBits = 0 (empty bitmap)
        packet.extend_from_slice(&0u32.to_le_bytes());

        // HEARTBEAT submessage (ID 0x07): firstSN=52, lastSN=52, count=2
        packet.push(0x07);
        packet.push(0x01); // Flags: little-endian ONLY (not FINAL)
        packet.extend_from_slice(&28u16.to_le_bytes()); // octetsToNextHeader

        // readerEntityId = ENTITYID_UNKNOWN
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // writerEntityId = 0x00000102 (same user writer)
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]);
        // firstSeq: {high=0, low=52}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&52u32.to_le_bytes());
        // lastSeq: {high=0, low=52}
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&52u32.to_le_bytes());
        // count
        packet.extend_from_slice(&2u32.to_le_bytes());

        // (a) The GAP extractor finds the GAP despite the leading INFO_DST.
        let gap = first_gap(&packet).expect("should parse GAP from compound");
        assert_eq!(gap.writer_entity_id, [0x00, 0x00, 0x01, 0x02]);
        assert_eq!(gap.gap_start, 1);
        assert_eq!(gap.gap_list_base, 52);
        // Implicit contiguous range [1,51] is materialized; 52 itself is NOT.
        assert!(gap.gap_list_seqs.contains(&51));
        assert!(!gap.gap_list_seqs.contains(&52));

        // (b) The HEARTBEAT extractor finds exactly ONE HB on the SAME buffer.
        let hbs = all_heartbeats(&packet);
        assert_eq!(hbs.len(), 1, "expected exactly one embedded HEARTBEAT");
        assert_eq!(hbs[0].writer_entity_id, [0x00, 0x00, 0x01, 0x02]);
        assert_eq!(hbs[0].first_seq, 52);
        assert_eq!(hbs[0].last_seq, 52);
        assert_eq!(hbs[0].count, 2);
        assert!(!hbs[0].final_flag);
    }

    /// Builds the RTPS 2.x header (20 bytes) shared by the
    /// `parse_embedded_gap_and_heartbeats` tests below: magic "RTPS" (4) +
    /// version (2) + vendor (2) + guidPrefix (12).
    fn push_rtps_header(packet: &mut Vec<u8>) {
        packet.extend_from_slice(b"RTPS"); // offset 0..4
        packet.extend_from_slice(&[2, 4]); // offset 4..6: protocol version 2.4
        packet.extend_from_slice(&[0x01, 0x03]); // offset 6..8: vendor (opendds)
        packet.extend_from_slice(&[0x0A; 12]); // offset 8..20: GUID prefix
    }

    /// Appends a GAP submessage (id 0x08) with an empty bitmap: writerEntityId
    /// `writer_id`, gapStart={high:0,low:gap_start}, gapList.base={high:0,low:gap_list_base}.
    /// Body layout (28 bytes, offsets relative to submessage body start):
    ///   +0  readerEntityId  (4 bytes, ENTITYID_UNKNOWN)
    ///   +4  writerEntityId  (4 bytes)
    ///   +8  gapStart.high   (4 bytes, i32 LE)
    ///   +12 gapStart.low    (4 bytes, u32 LE)
    ///   +16 gapList.base.high (4 bytes, i32 LE)
    ///   +20 gapList.base.low  (4 bytes, u32 LE)
    ///   +24 gapList.numBits (4 bytes, u32 LE = 0 -> no bitmap words follow)
    fn push_gap_submessage(
        packet: &mut Vec<u8>,
        writer_id: [u8; 4],
        gap_start: u32,
        gap_list_base: u32,
    ) {
        packet.push(0x08); // submessage id: GAP
        packet.push(0x01); // flags: little-endian only
        packet.extend_from_slice(&28u16.to_le_bytes()); // octetsToNextHeader = 28 (empty bitmap)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId = UNKNOWN
        packet.extend_from_slice(&writer_id); // writerEntityId
        packet.extend_from_slice(&0i32.to_le_bytes()); // gapStart.high = 0
        packet.extend_from_slice(&gap_start.to_le_bytes()); // gapStart.low
        packet.extend_from_slice(&0i32.to_le_bytes()); // gapList.base.high = 0
        packet.extend_from_slice(&gap_list_base.to_le_bytes()); // gapList.base.low
        packet.extend_from_slice(&0u32.to_le_bytes()); // gapList.numBits = 0
    }

    /// Appends an INFO_TS submessage (id 0x09) with a zeroed Time_t body (8
    /// bytes: seconds:i32 LE + fraction:u32 LE). Pure filler between GAP and
    /// DATA to form the compound message [GAP, INFO_TS, DATA].
    fn push_info_ts_submessage(packet: &mut Vec<u8>) {
        packet.push(0x09); // submessage id: INFO_TS
        packet.push(0x01); // flags: little-endian, timestamp present
        packet.extend_from_slice(&8u16.to_le_bytes()); // octetsToNextHeader = 8
        packet.extend_from_slice(&0i32.to_le_bytes()); // seconds = 0
        packet.extend_from_slice(&0u32.to_le_bytes()); // fraction = 0
    }

    /// Appends a minimal DATA submessage (id 0x15) as the last submessage in
    /// the packet -- exactly what makes `classify_rtps` resolve the WHOLE
    /// compound packet to `PacketKind::Data` in the real listener, hiding any
    /// preceding GAP/HEARTBEAT from the id-based dispatch in listener.rs.
    /// Body layout (20 bytes, no serializedPayload, offsets relative to body):
    ///   +0  extraFlags          (2 bytes)
    ///   +2  octetsToInlineQos   (2 bytes)
    ///   +4  readerEntityId      (4 bytes, ENTITYID_UNKNOWN)
    ///   +8  writerEntityId      (4 bytes)
    ///   +12 writerSN.high       (4 bytes, i32 LE)
    ///   +16 writerSN.low        (4 bytes, u32 LE)
    fn push_data_submessage(packet: &mut Vec<u8>, writer_id: [u8; 4], seq: u32) {
        packet.push(0x15); // submessage id: DATA
        packet.push(0x05); // flags: little-endian + DataFlag (no inline QoS)
        packet.extend_from_slice(&20u16.to_le_bytes()); // octetsToNextHeader = 20
        packet.extend_from_slice(&[0x00, 0x00]); // extraFlags
        packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos = 16 (rest of header)
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId = UNKNOWN
        packet.extend_from_slice(&writer_id); // writerEntityId
        packet.extend_from_slice(&0i32.to_le_bytes()); // writerSN.high = 0
        packet.extend_from_slice(&seq.to_le_bytes()); // writerSN.low
    }

    /// Appends a NACK_FRAG requesting fragments `bitmap_base` and
    /// `bitmap_base + 2` for one writer sample.
    fn push_nack_frag_submessage(
        packet: &mut Vec<u8>,
        reader_id: [u8; 4],
        writer_id: [u8; 4],
        writer_sn: u32,
        bitmap_base: u32,
    ) {
        packet.push(0x12);
        packet.push(0x01); // little-endian
        packet.extend_from_slice(&32u16.to_le_bytes());
        packet.extend_from_slice(&reader_id);
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes());
        packet.extend_from_slice(&writer_sn.to_le_bytes());
        packet.extend_from_slice(&bitmap_base.to_le_bytes());
        packet.extend_from_slice(&3u32.to_le_bytes());
        packet.extend_from_slice(&0xA000_0000u32.to_le_bytes());
        packet.extend_from_slice(&1u32.to_le_bytes());
    }

    /// (a) [GAP, INFO_TS, DATA] compound, a writer's purge-then-write in one
    /// message: the classifier resolves this to
    /// `PacketKind::Data` (DATA is last), so the embedded-HEARTBEAT scan block
    /// in listener.rs is the only place that ever sees the GAP. Verifies the
    /// combined single-pass scanner extracts it with the exact fields the
    /// standalone-GAP path (`parse_gap_submessage`) would have produced.
    #[test]
    fn test_parse_embedded_gap_and_heartbeats_extracts_gap_from_compound_data() {
        let writer_id = [0x00, 0x00, 0x01, 0x02]; // user writer, entity kind 0x02
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_gap_submessage(&mut packet, writer_id, 66, 67);
        push_info_ts_submessage(&mut packet);
        push_data_submessage(&mut packet, writer_id, 67);

        let (gap, hbs) = first_gap_and_heartbeats(&packet);

        let gap = gap.expect("embedded GAP must be extracted from compound Data packet");
        assert_eq!(gap.writer_entity_id, writer_id);
        assert_eq!(gap.gap_start, 66);
        assert_eq!(gap.gap_list_base, 67);
        // Implicit contiguous range [gapStart, gapList.base - 1] = {66} only;
        // empty bitmap contributes nothing past gapList.base.
        assert_eq!(gap.gap_list_seqs, vec![66u64]);

        // No HEARTBEAT submessage was embedded in this packet.
        assert!(hbs.is_empty());
    }

    /// (b) A Data packet with no embedded GAP must not synthesize one -- the
    /// single-pass scanner should return `None` for the GAP half exactly like
    /// `parse_gap_submessage` does on the same buffer.
    #[test]
    fn test_parse_embedded_gap_and_heartbeats_no_gap_in_plain_data() {
        let writer_id = [0x00, 0x00, 0x01, 0x02];
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_info_ts_submessage(&mut packet);
        push_data_submessage(&mut packet, writer_id, 67);

        let (gap, hbs) = first_gap_and_heartbeats(&packet);

        assert!(gap.is_none());
        assert!(hbs.is_empty());
        // Cross-check against the standalone parser on the same buffer.
        assert!(first_gap(&packet).is_none());
    }

    /// (c) SEDP-writer GAP (entity kind 0xC2, e.g. SEDP Publications writer
    /// 0x000003c2) embedded in a compound Data packet. The standalone-GAP
    /// path (control.rs `is_sedp_endpoint` at the CONTROL handler, not here)
    /// is what decides to skip SEDP GAPs -- this parser, like
    /// `parse_gap_submessage`, must NOT filter by entity kind itself, so the
    /// control handler keeps a single point of truth for that policy.
    #[test]
    fn test_parse_embedded_gap_and_heartbeats_forwards_sedp_gap_unfiltered() {
        let sedp_writer_id = [0x00, 0x00, 0x03, 0xC2]; // SEDP Publications writer
        let data_writer_id = [0x00, 0x00, 0x01, 0x02];
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_gap_submessage(&mut packet, sedp_writer_id, 10, 12);
        push_data_submessage(&mut packet, data_writer_id, 12);

        let (gap, _hbs) = first_gap_and_heartbeats(&packet);

        let gap =
            gap.expect("SEDP-writer GAP must still be extracted (filtering is control.rs's job)");
        assert_eq!(gap.writer_entity_id, sedp_writer_id);
        assert_eq!(gap.gap_start, 10);
        assert_eq!(gap.gap_list_base, 12);
    }

    /// A Data-classified datagram can carry GAPs for several writers. The
    /// listener must forward every one rather than silently crediting only the
    /// first writer's purge range.
    #[test]
    fn test_parse_all_embedded_gaps_keeps_each_writer() {
        let writer_a = [0x00, 0x00, 0x01, 0x02];
        let writer_b = [0x00, 0x00, 0x02, 0x02];
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_gap_submessage(&mut packet, writer_a, 10, 12);
        push_gap_submessage(&mut packet, writer_b, 20, 23);
        push_data_submessage(&mut packet, writer_b, 23);

        let (gaps, heartbeats) = all_gaps_and_heartbeats(&packet);

        assert!(heartbeats.is_empty());
        assert_eq!(gaps.len(), 2);
        assert_eq!(gaps[0].writer_entity_id, writer_a);
        assert_eq!(gaps[0].gap_list_seqs, vec![10, 11]);
        assert_eq!(gaps[1].writer_entity_id, writer_b);
        assert_eq!(gaps[1].gap_list_seqs, vec![20, 21, 22]);

        // The first-GAP view returns the first GAP of the datagram.
        let (first_gap, _) = first_gap_and_heartbeats(&packet);
        assert_eq!(first_gap.expect("first GAP").writer_entity_id, writer_a);
    }

    #[test]
    fn test_parse_all_embedded_gaps_is_bounded() {
        let writer = [0x00, 0x00, 0x01, 0x02];
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        for seq in 1..=(MAX_EMBEDDED_GAPS_PER_PACKET as u32 + 1) {
            push_gap_submessage(&mut packet, writer, seq, seq + 1);
        }
        push_data_submessage(&mut packet, writer, 100);

        let (gaps, _) = all_gaps_and_heartbeats(&packet);

        assert_eq!(gaps.len(), MAX_EMBEDDED_GAPS_PER_PACKET);
        assert_eq!(gaps.first().expect("first GAP").gap_start, 1);
        assert_eq!(
            gaps.last().expect("last bounded GAP").gap_start,
            MAX_EMBEDDED_GAPS_PER_PACKET as u64
        );
    }

    #[test]
    fn test_data_compound_reports_embedded_nack_frag() {
        let reader = [0x00, 0x00, 0x01, 0x04];
        let writer = [0x00, 0x00, 0x01, 0x03];
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_info_ts_submessage(&mut packet);
        push_data_submessage(&mut packet, writer, 41);
        push_nack_frag_submessage(&mut packet, reader, writer, 42, 2);

        let (kind, _, _, _) = crate::core::discovery::multicast::classify_rtps(&packet);
        assert_eq!(kind, crate::core::discovery::multicast::PacketKind::Data);

        let (gaps, heartbeats, has_nack_frag) = scan_all_embedded_control_submessages(&packet);
        assert!(gaps.is_empty());
        assert!(heartbeats.is_empty());
        assert!(has_nack_frag);

        let nack_frags = parse_all_nack_frag_submessages(&packet);
        assert_eq!(nack_frags.len(), 1);
        assert_eq!(nack_frags[0].reader_entity_id, reader);
        assert_eq!(nack_frags[0].writer_entity_id, writer);
        assert_eq!(nack_frags[0].writer_sn, 42);
        assert_eq!(nack_frags[0].missing_fragments, vec![2, 4]);
    }

    #[test]
    fn test_parse_fragment_bitmap_empty() {
        let missing = parse_fragment_bitmap(&[], 1, 0, true);
        assert!(missing.is_empty());
    }

    #[test]
    fn test_parse_fragment_bitmap_single() {
        // Bitmap with bit 0 set = fragment 1 missing
        let bitmap = [0x00, 0x00, 0x00, 0x80]; // bit 0 set when read as LE
        let missing = parse_fragment_bitmap(&bitmap, 1, 1, true);
        assert_eq!(missing, vec![1]);
    }

    /// Appends a conforming HEARTBEAT submessage (id 0x07, little-endian,
    /// octetsToNextHeader = 28 = the fixed body of RTPS v2.5 Sec.8.3.8.6).
    fn push_heartbeat_submessage(packet: &mut Vec<u8>, writer_id: [u8; 4], first: u32, last: u32) {
        packet.push(0x07);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&28u16.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes()); // firstSN.high
        packet.extend_from_slice(&first.to_le_bytes()); // firstSN.low
        packet.extend_from_slice(&0i32.to_le_bytes()); // lastSN.high
        packet.extend_from_slice(&last.to_le_bytes()); // lastSN.low
        packet.extend_from_slice(&7u32.to_le_bytes()); // count
    }

    /// Appends a conforming ACKNACK submessage (id 0x06, little-endian,
    /// empty bitmap: 20-octet body + 4-octet count).
    fn push_acknack_submessage(packet: &mut Vec<u8>, writer_id: [u8; 4], base: u32) {
        packet.push(0x06);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&24u16.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes()); // bitmapBase.high
        packet.extend_from_slice(&base.to_le_bytes()); // bitmapBase.low
        packet.extend_from_slice(&0u32.to_le_bytes()); // numBits = 0
        packet.extend_from_slice(&3u32.to_le_bytes()); // count
    }

    /// Appends a submessage whose `octetsToNextHeader` is `declared` while it
    /// actually carries `declared` octets of `filler` - i.e. a header that is
    /// self-consistent but declares LESS than the fixed body its id requires.
    ///
    /// This is the shape a conforming peer never sends and a hostile or buggy
    /// one can: the walk must skip it without reading into what follows.
    fn push_short_declared(packet: &mut Vec<u8>, id: u8, declared: u16, filler: u8) {
        packet.push(id);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&declared.to_le_bytes());
        packet.extend(std::iter::repeat_n(filler, usize::from(declared)));
    }

    /// Every ACKNACK of a datagram is returned, in wire order, and the count
    /// is bounded exactly like the GAPs and the HEARTBEATs are.
    ///
    /// The bound matters because 2339 conforming 28-octet ACKNACKs fit in
    /// one 64 KiB datagram and the listener dispatches one control message
    /// per ACKNACK into a 1024-slot channel that drops silently when full.
    #[test]
    fn every_acknack_is_returned_and_the_count_is_capped() {
        let mut three = Vec::new();
        push_rtps_header(&mut three);
        let writers = [
            [0x00, 0x00, 0x01, 0x03],
            [0x00, 0x00, 0x03, 0x03],
            [0x00, 0x00, 0x05, 0x03],
        ];
        for (i, w) in writers.iter().enumerate() {
            push_acknack_submessage(&mut three, *w, i as u32 + 1);
        }
        let out = parse_all_acknack_submessages(&three);
        assert_eq!(
            out.iter().map(|a| a.writer_entity_id).collect::<Vec<_>>(),
            writers.to_vec(),
            "every ACKNACK, in wire order"
        );
        assert_eq!(
            first_acknack(&three).map(|a| a.writer_entity_id),
            Some(writers[0]),
            "the first-only view still answers with the first"
        );

        let mut flood = Vec::new();
        push_rtps_header(&mut flood);
        let mut pushed = 0u32;
        while flood.len() + 28 <= 65535 {
            push_acknack_submessage(&mut flood, [0x00, 0x00, 0x01, 0x03], pushed);
            pushed += 1;
        }
        assert!(
            pushed as usize > MAX_EMBEDDED_ACKNACKS_PER_PACKET * 4,
            "fixture must exceed the cap by a wide margin, pushed {pushed}"
        );
        assert_eq!(
            parse_all_acknack_submessages(&flood).len(),
            MAX_EMBEDDED_ACKNACKS_PER_PACKET
        );
    }

    /// Appends a DDS-Security submessage-protection envelope header
    /// (SEC_PREFIX, id 0x31) with a conforming 20-octet CryptoHeader
    /// (Sec.9.5.2.3: transformation_kind[4] + transformation_key_id[4] +
    /// session_id[4] + initialization_vector_suffix[8]).
    fn push_sec_prefix(packet: &mut Vec<u8>) {
        packet.push(0x31);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&20u16.to_le_bytes());
        packet.extend_from_slice(&[0xAA; 20]); // CryptoHeader, content irrelevant here
    }

    /// Appends a DDS-Security submessage-protection envelope trailer
    /// (SEC_POSTFIX, id 0x32) with a conforming 20-octet CryptoFooter and
    /// zero receiver-specific MACs (Sec.9.5.2.5: common_mac[16] +
    /// receiver_specific_macs length[4]).
    fn push_sec_postfix(packet: &mut Vec<u8>) {
        packet.push(0x32);
        packet.push(0x01); // E flag: little-endian
        packet.extend_from_slice(&20u16.to_le_bytes());
        packet.extend_from_slice(&[0xBB; 16]); // common_mac
        packet.extend_from_slice(&0u32.to_le_bytes()); // receiver_specific_macs: none
    }

    /// AES256_GMAC ("authenticating only",
    /// Sec.9.5.3.3.4.5) leaves the submessage it protects sitting in the
    /// datagram as plaintext between its SEC_PREFIX and SEC_POSTFIX. A
    /// clear-only scanner that does not know about the envelope reads
    /// straight through both (neither is an ACKNACK id) and finds that
    /// plaintext ACKNACK as if it were an independent, unprotected one.
    ///
    /// The test isolates `EnvelopeTracker`'s exclusion (`!envelope_owned`):
    /// the ACKNACK inside the envelope must not appear in `out`, so the
    /// count stays at 1.
    #[test]
    fn an_acknack_between_sec_prefix_and_sec_postfix_is_not_a_clear_one() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_sec_prefix(&mut packet);
        push_acknack_submessage(&mut packet, [0x00, 0x00, 0x03, 0xc3], 1);
        push_sec_postfix(&mut packet);

        let out = parse_all_acknack_submessages(&packet);
        assert!(
            out.is_empty(),
            "the GMAC-visible ACKNACK between SEC_PREFIX and SEC_POSTFIX is \
             envelope-owned plaintext, not a genuinely separate clear \
             ACKNACK: {out:?}"
        );
    }

    /// The exclusion is scoped to the envelope's SPAN, not to the whole rest
    /// of the datagram: a second, genuinely independent clear ACKNACK after
    /// the SEC_POSTFIX closes it must still be found. DDS-Security 1.1 does
    /// not forbid a protected control submessage and a plain one from
    /// sharing one RTPS message (the SEC_POSTFIX's own closing is exactly
    /// what `EnvelopeTracker::observe` uses to turn `inside` back off).
    #[test]
    fn a_clear_acknack_after_the_envelope_closes_is_still_found() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_sec_prefix(&mut packet);
        push_acknack_submessage(&mut packet, [0x00, 0x00, 0x03, 0xc3], 1);
        push_sec_postfix(&mut packet);
        push_acknack_submessage(&mut packet, [0x00, 0x00, 0x04, 0xc2], 7);

        let out = parse_all_acknack_submessages(&packet);
        assert_eq!(
            out.iter().map(|a| a.writer_entity_id).collect::<Vec<_>>(),
            vec![[0x00, 0x00, 0x04, 0xc2]],
            "only the clear ACKNACK outside the envelope, the protected one stays excluded"
        );
    }

    /// The same property for NACK_FRAG (the refusal gate
    /// and this exclusion are symmetric between the two control kinds).
    #[test]
    fn a_nack_frag_between_sec_prefix_and_sec_postfix_is_not_a_clear_one() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_sec_prefix(&mut packet);
        packet.push(0x12); // NACK_FRAG id
        packet.push(0x01); // E flag: little-endian
                           // octetsToNextHeader = 4 + 4 + 8 + 4 + 4 + 4 + 4 = 32
        packet.extend_from_slice(&32u16.to_le_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xc3]); // writerEntityId
        packet.extend_from_slice(&0i32.to_le_bytes()); // writerSN.high
        packet.extend_from_slice(&1u32.to_le_bytes()); // writerSN.low
        packet.extend_from_slice(&1u32.to_le_bytes()); // fragmentNumberState.bitmapBase
        packet.extend_from_slice(&1u32.to_le_bytes()); // numBits
        packet.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]); // bitmap word
        packet.extend_from_slice(&3u32.to_le_bytes()); // count
        push_sec_postfix(&mut packet);

        let out = parse_all_nack_frag_submessages(&packet);
        assert!(
            out.is_empty(),
            "the GMAC-visible NACK_FRAG between SEC_PREFIX and SEC_POSTFIX is \
             envelope-owned plaintext: {out:?}"
        );
    }

    /// The cap is a POLICY choice, not a wire property, so it is pinned to
    /// its literal here rather than only to itself: every other assertion in
    /// this module compares against the constant, which would follow it
    /// silently if someone raised it.
    ///
    /// 64 samples per datagram against the 1024 slots of the control channel
    /// (`CONTROL_CHANNEL_CAPACITY`) leaves fifteen other peers able to be
    /// heard while one datagram is being served. Raising it must be a
    /// deliberate edit of this line.
    #[test]
    fn the_nack_frag_cap_is_the_value_the_channel_can_absorb() {
        assert_eq!(MAX_EMBEDDED_NACK_FRAGS_PER_PACKET, 64);
        assert_eq!(MAX_EMBEDDED_GAPS_PER_PACKET, 64);
        assert_eq!(MAX_EMBEDDED_HEARTBEATS_PER_PACKET, 64);
        assert_eq!(MAX_EMBEDDED_ACKNACKS_PER_PACKET, 64);
    }

    /// One 64 KiB datagram of conforming NACK_FRAGs, each naming a different
    /// sample, must not turn into thousands of control messages.
    ///
    /// Without a bound, 2339 submessages fit in 65 512 octets and all 2339
    /// would come back, to be dispatched one control message each into a
    /// 1024-slot channel that drops silently when full - so one peer's
    /// datagram would discard every other peer's reliability traffic - at
    /// about 2 ms of receive-path CPU per datagram (release build).
    ///
    /// Unlike a fixture sized from the constant it guards, this one is sized
    /// by the datagram limit: raising the cap makes the returned count follow
    /// it, which is why the literal is pinned separately above.
    #[test]
    fn well_formed_nack_frags_are_capped_like_gaps_are() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        let mut pushed = 0u32;
        while packet.len() + 36 <= 65535 {
            push_nack_frag_submessage(
                &mut packet,
                [0x00, 0x00, 0x00, 0x00],
                [0x00, 0x00, 0x01, 0x04],
                pushed,
                1,
            );
            pushed += 1;
        }
        assert!(
            pushed as usize > MAX_EMBEDDED_NACK_FRAGS_PER_PACKET * 4,
            "fixture must exceed the cap by a wide margin, pushed {pushed}"
        );

        let out = parse_all_nack_frag_submessages(&packet);
        assert_eq!(
            out.len(),
            MAX_EMBEDDED_NACK_FRAGS_PER_PACKET,
            "one datagram must not introduce more than the cap of samples"
        );
    }

    /// The other side of the threshold: a datagram asking about exactly the
    /// cap worth of samples is returned whole, in wire order, with each
    /// sample's fragment intact.
    #[test]
    fn exactly_the_cap_worth_of_nack_frag_samples_is_returned_whole() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        for sn in 0..MAX_EMBEDDED_NACK_FRAGS_PER_PACKET as u32 {
            push_nack_frag_submessage(
                &mut packet,
                [0x00, 0x00, 0x00, 0x00],
                [0x00, 0x00, 0x01, 0x04],
                sn,
                sn + 100,
            );
        }

        let out = parse_all_nack_frag_submessages(&packet);
        assert_eq!(out.len(), MAX_EMBEDDED_NACK_FRAGS_PER_PACKET);
        for (i, info) in out.iter().enumerate() {
            assert_eq!(info.writer_sn, i as u64, "wire order");
            // The helper sets bits 0 and 2 of the fragment bitmap.
            assert_eq!(info.missing_fragments, vec![i as u32 + 100, i as u32 + 102]);
        }
    }

    /// The cap bounds how many samples a datagram may INTRODUCE, never how
    /// completely an accepted one is read.
    ///
    /// A reader may split one sample's missing-fragment set across many
    /// submessages. A cap that refused those once `out` is full would drop
    /// the tail of a request it had already accepted - which this parser
    /// exists to avoid - so a sample already collected keeps absorbing its
    /// later submessages.
    #[test]
    fn a_sample_already_collected_is_still_coalesced_past_the_cap() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        for sn in 0..MAX_EMBEDDED_NACK_FRAGS_PER_PACKET as u32 {
            push_nack_frag_submessage(
                &mut packet,
                [0x00, 0x00, 0x00, 0x00],
                [0x00, 0x00, 0x01, 0x04],
                sn,
                1,
            );
        }
        // Past the cap: a second request for sample 0, naming another fragment.
        push_nack_frag_submessage(
            &mut packet,
            [0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x01, 0x04],
            0,
            9,
        );
        // Past the cap: a brand new sample, which must be the one refused.
        push_nack_frag_submessage(
            &mut packet,
            [0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x01, 0x04],
            9999,
            1,
        );

        let out = parse_all_nack_frag_submessages(&packet);
        assert_eq!(out.len(), MAX_EMBEDDED_NACK_FRAGS_PER_PACKET);
        assert_eq!(
            out[0].missing_fragments,
            vec![1, 3, 9, 11],
            "the late submessage of an accepted sample must still be unioned in"
        );
        assert!(
            !out.iter().any(|e| e.writer_sn == 9999),
            "a new sample past the cap must be refused"
        );
    }

    /// A HEARTBEAT whose submessage declares less than the 28-octet body the
    /// spec fixes must be SKIPPED, and the conforming HEARTBEAT behind it
    /// must still be found.
    ///
    /// The two writer entity ids separate the two failures this pins at once:
    /// reading `0xAA` back would mean the body was taken from beyond the
    /// short submessage (the datagram-bounded read), and `None` would mean a
    /// malformed submessage silently discarded a conforming one.
    #[test]
    fn a_short_declared_heartbeat_does_not_hide_the_conforming_one() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_short_declared(&mut packet, 0x07, 12, 0xAA);
        push_heartbeat_submessage(&mut packet, [0xBB; 4], 1, 9);

        let hb = first_heartbeat(&packet).expect("conforming HEARTBEAT behind it");
        assert_eq!(hb.writer_entity_id, [0xBB; 4]);
        assert_eq!(hb.first_seq, 1);
        assert_eq!(hb.last_seq, 9);

        let all = all_heartbeats(&packet);
        assert_eq!(all.len(), 1, "the short-declared one must not be counted");
        assert_eq!(all[0].writer_entity_id, [0xBB; 4]);

        let (_, embedded, _) = scan_all_embedded_control_submessages(&packet);
        assert_eq!(embedded.len(), 1);
        assert_eq!(embedded[0].info.writer_entity_id, [0xBB; 4]);
    }

    /// Same rule for GAP.
    #[test]
    fn a_short_declared_gap_does_not_hide_the_conforming_one() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_short_declared(&mut packet, 0x08, 12, 0xAA);
        push_gap_submessage(&mut packet, [0xBB; 4], 10, 11);

        let gap = first_gap(&packet).expect("conforming GAP behind it");
        assert_eq!(gap.writer_entity_id, [0xBB; 4]);

        let (gaps, _, _) = scan_all_embedded_control_submessages(&packet);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].info.writer_entity_id, [0xBB; 4]);
    }

    /// Same rule for ACKNACK.
    #[test]
    fn a_short_declared_acknack_does_not_hide_the_conforming_one() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        push_short_declared(&mut packet, 0x06, 8, 0xAA);
        push_acknack_submessage(&mut packet, [0xBB; 4], 5);

        let an = first_acknack(&packet).expect("conforming ACKNACK behind it");
        assert_eq!(an.writer_entity_id, [0xBB; 4]);
        assert_eq!(an.bitmap_base, 5);
    }

    /// A datagram of HEARTBEAT headers that each declare one octet must not
    /// advance the walk five octets at a time and yield 13 097 HEARTBEATs out
    /// of a single 64 KiB datagram - one per five octets of attacker-chosen
    /// bytes. Each one becomes a `ControlMessage` pushed into a channel of
    /// capacity `CONTROL_CHANNEL_CAPACITY` (1024) whose overflow is a silent
    /// drop, so a single unauthenticated packet would flush every legitimate
    /// HEARTBEAT and ACKNACK of every other peer out of it.
    ///
    /// Bounding each body by its own submessage refuses all of them: a
    /// HEARTBEAT that declares one octet cannot carry a 28-octet body.
    #[test]
    fn an_impossible_octets_to_next_header_cannot_amplify_the_heartbeat_count() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        while packet.len() + 5 <= crate::config::MAX_PACKET_SIZE {
            // id 0x07, E flag, octetsToNextHeader = 1, one octet of body.
            packet.extend_from_slice(&[0x07, 0x01, 0x01, 0x00, 0x00]);
        }
        assert!(
            packet.len() > 65_000,
            "fixture must be a full-size datagram"
        );

        assert!(all_heartbeats(&packet).is_empty());
        let (_, embedded, _) = scan_all_embedded_control_submessages(&packet);
        assert!(embedded.is_empty());
        assert!(first_heartbeat(&packet).is_none());
    }

    /// The same shape on the three other submessage kinds this module walks.
    #[test]
    fn an_impossible_octets_to_next_header_cannot_amplify_gap_or_nack_frag() {
        for id in [0x08u8, 0x06, 0x12] {
            let mut packet = Vec::new();
            push_rtps_header(&mut packet);
            while packet.len() + 5 <= crate::config::MAX_PACKET_SIZE {
                packet.extend_from_slice(&[id, 0x01, 0x01, 0x00, 0x00]);
            }
            let (gaps, _, _) = scan_all_embedded_control_submessages(&packet);
            assert!(gaps.is_empty(), "id {id:#04x} produced GAPs");
            assert!(first_gap(&packet).is_none(), "id {id:#04x}");
            assert!(first_acknack(&packet).is_none(), "id {id:#04x}");
            assert!(
                parse_all_nack_frag_submessages(&packet).is_empty(),
                "id {id:#04x}"
            );
        }
    }

    /// A datagram of WELL-FORMED HEARTBEATs is syntactically irreproachable
    /// and the per-submessage bound does not touch it: 2047 of
    /// them fit in one 65 535-octet packet, twice the control channel's
    /// capacity. The HEARTBEAT path is capped like the GAP path, in the same
    /// loop.
    ///
    /// WHAT THIS PINS, AND WHAT IT DOES NOT. The fixture is sized FROM
    /// `MAX_EMBEDDED_HEARTBEATS_PER_PACKET`, so it follows the constant
    /// instead of guarding it: raising 64 to 128 leaves this test green.
    /// It pins the MECHANISM - that a cap exists and
    /// truncates - plus an upper bound, since the `pushed > cap * 4`
    /// assertion below fails once the constant passes ~512. The exact value
    /// is a policy choice, not a wire property: any figure comfortably under
    /// the control channel's 1024 slots serves. Do not contort the fixture
    /// to pin a number that nothing on the wire fixes.
    #[test]
    fn well_formed_heartbeats_are_capped_like_gaps_are() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        let mut pushed = 0usize;
        while packet.len() + 32 <= crate::config::MAX_PACKET_SIZE {
            push_heartbeat_submessage(&mut packet, [0xBB; 4], 1, 9);
            pushed += 1;
        }
        assert!(
            pushed > MAX_EMBEDDED_HEARTBEATS_PER_PACKET * 4,
            "fixture must overshoot the cap by a wide margin, got {pushed}"
        );

        assert_eq!(
            all_heartbeats(&packet).len(),
            MAX_EMBEDDED_HEARTBEATS_PER_PACKET
        );
        let (_, embedded, _) = scan_all_embedded_control_submessages(&packet);
        assert_eq!(embedded.len(), MAX_EMBEDDED_HEARTBEATS_PER_PACKET);
    }

    /// The cap must not fire one entry early: a datagram carrying exactly
    /// the cap is returned whole. Pins the threshold from the other side,
    /// so an off-by-one in either direction fails a test.
    #[test]
    fn exactly_the_cap_worth_of_heartbeats_is_returned_whole() {
        let mut packet = Vec::new();
        push_rtps_header(&mut packet);
        for _ in 0..MAX_EMBEDDED_HEARTBEATS_PER_PACKET {
            push_heartbeat_submessage(&mut packet, [0xBB; 4], 1, 9);
        }

        assert_eq!(
            all_heartbeats(&packet).len(),
            MAX_EMBEDDED_HEARTBEATS_PER_PACKET
        );
        let (_, embedded, _) = scan_all_embedded_control_submessages(&packet);
        assert_eq!(embedded.len(), MAX_EMBEDDED_HEARTBEATS_PER_PACKET);
    }
    /// A conforming BIG-ENDIAN peer is read in its own byte order.
    ///
    /// Sec.8.3.3.3 puts the endianness of every field of a submessage in bit 0
    /// of its flags, and this file honours it everywhere. A little-endian-only
    /// fixture could not prove it (forcing `is_le` to true would break
    /// nothing), and the same holds for the DATA_FRAG fixtures: a builder
    /// written once in a single byte order leaves the other branch live and
    /// unread.
    ///
    /// The numbers are chosen so that reading them the wrong way round cannot
    /// coincide: sequence 5 read as little-endian when it is big-endian is
    /// 83886080.
    #[test]
    fn a_big_endian_peer_is_read_in_its_own_byte_order() {
        let mut packet = Vec::new();
        packet.extend_from_slice(b"RTPS");
        packet.extend_from_slice(&[0x02, 0x05, 0x01, 0x1A]);
        packet.extend_from_slice(&[0x0B; 12]);

        // HEARTBEAT, big-endian: E flag clear.
        packet.push(0x07);
        packet.push(0x00);
        packet.extend_from_slice(&28u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xC2]); // SEDP pub writer
        packet.extend_from_slice(&0i32.to_be_bytes()); // firstSN.high
        packet.extend_from_slice(&5u32.to_be_bytes()); // firstSN.low
        packet.extend_from_slice(&0i32.to_be_bytes()); // lastSN.high
        packet.extend_from_slice(&9u32.to_be_bytes()); // lastSN.low
        packet.extend_from_slice(&7u32.to_be_bytes()); // count

        // ACKNACK, big-endian, behind it in the same datagram.
        packet.push(0x06);
        packet.push(0x00);
        packet.extend_from_slice(&24u16.to_be_bytes());
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // readerEntityId
        packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xC2]); // writerEntityId
        packet.extend_from_slice(&0i32.to_be_bytes()); // bitmapBase.high
        packet.extend_from_slice(&11u32.to_be_bytes()); // bitmapBase.low
        packet.extend_from_slice(&0u32.to_be_bytes()); // numBits
        packet.extend_from_slice(&3u32.to_be_bytes()); // count

        let hb = first_heartbeat(&packet).expect("the big-endian HEARTBEAT is read");
        assert_eq!(
            hb.first_seq, 5,
            "83886080 is this number read the wrong way"
        );
        assert_eq!(hb.last_seq, 9);

        let ack = first_acknack(&packet).expect("and so is the ACKNACK behind it");
        assert_eq!(ack.bitmap_base, 11);
    }

    /// GAP octets written from RTPS v2.5 Sec.9.4.5.6 by hand, not by an
    /// encoder of ours: after the gapList come gapStartGSN and gapEndGSN
    /// when the GroupInfoFlag (G, 0x02) is set, then the filteredCount, a
    /// ChangeCount_t (high: long, low: unsigned long, Sec.9.3.2.11), when
    /// the FilteredCountFlag (F, 0x04) is set. Little-endian, F only, one
    /// bitmap word; then big-endian with G and F; then F clear with octets
    /// after the gapList; then F set with the count cut off.
    #[test]
    fn a_gap_filtered_count_is_read_where_the_flags_place_it() {
        let header: [u8; 20] = [
            0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x01, // RTPS 2.5, vendor 01.01
            0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
        ];
        // GAP, flags E|F, octetsToNextHeader 40.
        let le_f: [u8; 44] = [
            0x08, 0x05, 0x28, 0x00, //
            0x00, 0x00, 0x00, 0x00, // readerId UNKNOWN
            0x00, 0x00, 0x01, 0x02, // writerId
            0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // gapStart 5
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, // gapList.base 6
            0x01, 0x00, 0x00, 0x00, // numBits 1
            0x00, 0x00, 0x00, 0x80, // bitmap: 6
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // filteredCount 2
        ];
        // GAP, flags G|F (big-endian), octetsToNextHeader 52.
        let be_gf: [u8; 56] = [
            0x08, 0x06, 0x00, 0x34, //
            0x00, 0x00, 0x00, 0x00, // readerId UNKNOWN
            0x00, 0x00, 0x01, 0x02, // writerId
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, // gapStart 7
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, // gapList.base 10
            0x00, 0x00, 0x00, 0x00, // numBits 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, // gapStartGSN 21
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, // gapEndGSN 23
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // filteredCount 3
        ];
        // GAP, flags E only, octets after the gapList that are not a count.
        let le_no_f: [u8; 40] = [
            0x08, 0x01, 0x24, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x01, 0x02, //
            0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, //
        ];
        // GAP, flags E|F, the count cut off: octetsToNextHeader 28.
        let le_f_short: [u8; 32] = [
            0x08, 0x05, 0x1C, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x01, 0x02, //
            0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, //
            0x00, 0x00, 0x00, 0x00, //
        ];
        let read = |gap: &[u8]| {
            let mut packet = header.to_vec();
            packet.extend_from_slice(gap);
            push_heartbeat_submessage(&mut packet, [0xBB; 4], 1, 9);
            let (gaps, _, _) = scan_all_embedded_control_submessages(&packet);
            assert_eq!(gaps.len(), 1, "one GAP");
            (gaps[0].filtered_count, gaps[0].info.clone())
        };
        let (count, gap) = read(&le_f);
        assert_eq!(count, Some(2));
        assert_eq!((gap.gap_start, gap.gap_list_base), (5, 6));
        assert!(
            gap.gap_list_seqs.contains(&6),
            "the bitmap is read before the count"
        );
        let (count, gap) = read(&be_gf);
        assert_eq!(count, Some(3), "after the two GSNs");
        assert_eq!((gap.gap_start, gap.gap_list_base), (7, 10));
        assert_eq!(read(&le_no_f).0, None, "no flag, no count");
        assert_eq!(read(&le_f_short).0, None, "a count cut off is no count");
    }

    /// An RTPS message holding the one submessage `id`, `flags`, `body`.
    fn one_submessage(id: u8, flags: u8, body: &[u8], is_le: bool) -> Vec<u8> {
        let mut packet = b"RTPS".to_vec();
        packet.extend_from_slice(&[2, 5, 0x01, 0x1A]);
        packet.extend_from_slice(&[0x44; 12]);
        let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
        packet.push(id);
        packet.push(flags);
        packet.extend_from_slice(&if is_le {
            len.to_le_bytes()
        } else {
            len.to_be_bytes()
        });
        packet.extend_from_slice(body);
        packet
    }

    /// A SequenceNumber_t, high then low (RTPS v2.5 Sec.9.3.2).
    fn sn(value: i64, is_le: bool) -> Vec<u8> {
        let high = i32::try_from(value >> 32).unwrap_or(-1);
        let low = (value & 0xFFFF_FFFF) as u32;
        if is_le {
            [high.to_le_bytes(), low.to_le_bytes()].concat()
        } else {
            [high.to_be_bytes(), low.to_be_bytes()].concat()
        }
    }

    /// A HEARTBEAT body: readerId, writerId, firstSN, lastSN, count, then
    /// `group` as SequenceNumbers (RTPS v2.5 Sec.9.4.5.7).
    fn heartbeat_body(first: i64, last: i64, group: &[i64], is_le: bool) -> Vec<u8> {
        let mut body = vec![0, 0, 0x12, 0x07, 0, 0, 0x13, 0x02];
        body.extend(sn(first, is_le));
        body.extend(sn(last, is_le));
        body.extend_from_slice(&if is_le {
            9u32.to_le_bytes()
        } else {
            9u32.to_be_bytes()
        });
        for gsn in group {
            body.extend(sn(*gsn, is_le));
        }
        body
    }

    fn heartbeat_group_of(packet: &[u8]) -> (Option<HeartbeatInfo>, Option<GroupInfo>) {
        let mut heartbeats = scan_all_embedded_control_submessages(packet).1;
        if heartbeats.is_empty() {
            return (None, None);
        }
        let hb = heartbeats.remove(0);
        (Some(hb.info), hb.group_info)
    }

    /// RTPS v2.5 Sec.9.4.5.7: with G (0x08) set, currentGSN, firstGSN and
    /// lastGSN follow `count`, in the submessage's byte order.
    #[test]
    fn a_heartbeat_with_g_yields_its_three_group_sequence_numbers() {
        for is_le in [true, false] {
            let flags = 0x08 | u8::from(is_le);
            let body = heartbeat_body(2, 6, &[0x3_0000_0010, 4, 9], is_le);
            let (hb, group) = heartbeat_group_of(&one_submessage(0x07, flags, &body, is_le));
            let hb = hb.expect("the HEARTBEAT itself");
            assert_eq!((hb.first_seq, hb.last_seq, hb.count), (2, 6, 9));
            assert!(
                !hb.final_flag && !hb.liveliness_flag,
                "G is neither F nor L"
            );
            assert_eq!(
                group,
                Some(GroupInfo::Heartbeat {
                    current_gsn: 0x3_0000_0010,
                    first_gsn: 4,
                    last_gsn: 9,
                    writer_set: None
                }),
                "little endian: {}",
                is_le
            );
        }
    }

    #[test]
    fn a_pim_heartbeat_retains_optional_roster_digests() {
        for is_le in [true, false] {
            let mut body = heartbeat_body(1, 3, &[9, 2, 6], is_le);
            let writer_set = [0x11, 0x22, 0x33, 0x44];
            let secure_set = [0x55, 0x66, 0x77, 0x88];
            body.extend_from_slice(&writer_set);
            body.extend_from_slice(&secure_set);
            let (_, group) =
                heartbeat_group_of(&one_submessage(0x07, 0x08 | u8::from(is_le), &body, is_le));
            assert!(
                matches!(group, Some(GroupInfo::Heartbeat { writer_set: Some((public, secure)), .. }) if public == writer_set && secure == secure_set)
            );
        }
    }

    /// The same bytes without G carry no GroupInfo, and G on a body too
    /// short to hold it leaves the HEARTBEAT valid without one.
    #[test]
    fn a_heartbeat_without_g_or_too_short_for_it_has_no_group_info() {
        let body = heartbeat_body(2, 6, &[12, 4, 9], true);
        let (hb, group) = heartbeat_group_of(&one_submessage(0x07, 0x01, &body, true));
        assert!(hb.is_some());
        assert_eq!(group, None, "no G, no GroupInfo");
        let short = heartbeat_body(2, 6, &[12, 4], true);
        let (hb, group) = heartbeat_group_of(&one_submessage(0x07, 0x09, &short, true));
        assert_eq!(hb.map(|hb| hb.last_seq), Some(6), "the HEARTBEAT stays");
        assert_eq!(group, None, "16 of the 24 octets are no GroupInfo");
    }

    /// Sec.8.3.8.6.3 refuses currentGSN > lastGSN, which a GROUP writer
    /// whose sibling wrote last always sends (an inconsistency of the spec
    /// itself): accepted. Its other GroupInfo rules hold: each one, broken, leaves
    /// the HEARTBEAT without GroupInfo.
    #[test]
    fn a_heartbeat_group_info_is_checked_except_current_above_last() {
        let read = |group: [i64; 3]| {
            let body = heartbeat_body(1, 1, &group, true);
            heartbeat_group_of(&one_submessage(0x07, 0x09, &body, true))
        };
        let (_, group) = read([40, 3, 7]);
        assert_eq!(
            group,
            Some(GroupInfo::Heartbeat {
                current_gsn: 40,
                first_gsn: 3,
                last_gsn: 7,
                writer_set: None
            }),
            "currentGSN above lastGSN is accepted (D3)"
        );
        // Boundaries that are valid: lastGSN = firstGSN - 1, currentGSN =
        // firstGSN.
        assert!(read([5, 5, 4]).1.is_some());
        for (bad, why) in [
            ([0, 3, 7], "currentGSN zero"),
            ([-1, 3, 7], "currentGSN negative"),
            ([9, 0, 7], "firstGSN zero"),
            ([9, 3, -1], "lastGSN negative"),
            ([9, 5, 3], "lastGSN below firstGSN - 1"),
            ([4, 5, 9], "currentGSN below firstGSN"),
        ] {
            let (hb, group) = read(bad);
            assert!(hb.is_some(), "{}: the HEARTBEAT stays", why);
            assert_eq!(group, None, "{}", why);
        }
    }

    /// A GAP body: readerId, writerId, gapStart, gapList (base, numBits,
    /// bitmap), then `tail` (RTPS v2.5 Sec.9.4.5.6).
    fn gap_body(
        start: i64,
        base: i64,
        bitmap: &[u32],
        num_bits: u32,
        tail: &[u8],
        is_le: bool,
    ) -> Vec<u8> {
        let mut body = vec![0, 0, 0x12, 0x07, 0, 0, 0x13, 0x02];
        body.extend(sn(start, is_le));
        body.extend(sn(base, is_le));
        let word = |w: u32| {
            if is_le {
                w.to_le_bytes()
            } else {
                w.to_be_bytes()
            }
        };
        body.extend_from_slice(&word(num_bits));
        for w in bitmap {
            body.extend_from_slice(&word(*w));
        }
        body.extend_from_slice(tail);
        body
    }

    fn gap_group_of(packet: &[u8]) -> (Option<GapInfo>, Option<GroupInfo>, Option<u64>) {
        let mut gaps = scan_all_embedded_control_submessages(packet).0;
        if gaps.is_empty() {
            return (None, None, None);
        }
        let gap = gaps.remove(0);
        (Some(gap.info), gap.group_info, gap.filtered_count)
    }

    /// RTPS v2.5 Sec.9.4.5.6: with G (0x02) set, gapStartGSN and gapEndGSN
    /// follow the gapList's bitmap, before a filteredCount (F, 0x04).
    #[test]
    fn a_gap_with_g_yields_its_start_and_end_gsn_after_the_bitmap() {
        for is_le in [true, false] {
            let flags = 0x02 | u8::from(is_le);
            let tail = [sn(21, is_le), sn(0x1_0000_0003, is_le)].concat();
            let body = gap_body(5, 8, &[0x8000_0000], 1, &tail, is_le);
            let (gap, group, filtered) = gap_group_of(&one_submessage(0x08, flags, &body, is_le));
            let gap = gap.expect("the GAP itself");
            assert_eq!((gap.gap_start, gap.gap_list_base), (5, 8));
            assert_eq!(gap.gap_list_seqs, vec![8, 5, 6, 7]);
            assert_eq!(
                group,
                Some(GroupInfo::Gap {
                    start_gsn: 21,
                    end_gsn: 0x1_0000_0003
                }),
                "little endian: {}",
                is_le
            );
            assert_eq!(filtered, None);
            // With F too, the filteredCount comes after the GroupInfo.
            let counted = [tail.clone(), sn(2, is_le)].concat();
            let body = gap_body(5, 8, &[0x8000_0000], 1, &counted, is_le);
            let (_, group, filtered) =
                gap_group_of(&one_submessage(0x08, flags | 0x04, &body, is_le));
            assert!(group.is_some());
            assert_eq!(filtered, Some(2));
        }
    }

    /// Without G, or with GroupInfo the Sec.8.3.8.4.3 rules refuse, a GAP
    /// carries none; the GAP itself stays.
    #[test]
    fn a_gap_group_info_is_absent_without_g_and_checked_with_it() {
        let read = |flags: u8, start: i64, end: i64| {
            let tail = [sn(start, true), sn(end, true)].concat();
            let body = gap_body(5, 6, &[], 0, &tail, true);
            gap_group_of(&one_submessage(0x08, flags, &body, true))
        };
        assert_eq!(read(0x01, 21, 21).1, None, "no G, no GroupInfo");
        assert_eq!(
            read(0x03, 21, 20).1,
            Some(GroupInfo::Gap {
                start_gsn: 21,
                end_gsn: 20
            }),
            "gapEndGSN = gapStartGSN - 1 is valid"
        );
        for (start, end, why) in [
            (0, 4, "gapStartGSN zero"),
            (-2, 4, "gapStartGSN negative"),
            (4, 0, "gapEndGSN zero"),
            (9, 7, "gapEndGSN below gapStartGSN - 1"),
        ] {
            let (gap, group, _) = read(0x03, start, end);
            assert!(gap.is_some(), "{}: the GAP stays", why);
            assert_eq!(group, None, "{}", why);
        }
    }
}

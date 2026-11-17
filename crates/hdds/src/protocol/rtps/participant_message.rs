// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The builtin participant-message endpoints (RTPS v2.5 Sec.8.4.13): what
//! carries a participant's liveliness assertions (Writer Liveliness
//! Protocol, Sec.8.4.13.5).
//!
//! `ParticipantMessageData` (Sec.9.6.3.1) is a CDR struct, not a
//! ParameterList:
//!
//! ```text
//! GuidPrefix_t    participantGuidPrefix;   // 12 octets
//! octet           kind[4];                 // {0,0,0,1} AUTOMATIC, {0,0,0,2} MANUAL_BY_PARTICIPANT
//! sequence<octet> data;                    // u32 length, then the octets
//! ```
//!
//! `participantGuidPrefix` and `kind` are its key: one instance per kind.

use super::{encode_data, encode_gap, encode_heartbeat, encode_heartbeat_final, encode_info_dst};
use super::{encode_info_ts, RtpsEncodeError, RtpsEncodeResult};
use std::ops::Range;

/// BuiltinParticipantMessageWriter (RTPS v2.5 Table 9.2).
pub const PARTICIPANT_MESSAGE_WRITER: [u8; 4] = [0x00, 0x02, 0x00, 0xC2];

/// BuiltinParticipantMessageReader (RTPS v2.5 Table 9.2).
pub const PARTICIPANT_MESSAGE_READER: [u8; 4] = [0x00, 0x02, 0x00, 0xC7];

/// `BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_WRITER` (RTPS v2.5 Sec.8.5.3.1,
/// bit 10 of `BuiltinEndpointSet_t`).
pub const BUILTIN_PARTICIPANT_MESSAGE_WRITER: u32 = 1 << 10;

/// `BUILTIN_ENDPOINT_PARTICIPANT_MESSAGE_DATA_READER` (bit 11).
pub const BUILTIN_PARTICIPANT_MESSAGE_READER: u32 = 1 << 11;

/// `PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE`.
pub const KIND_AUTOMATIC: [u8; 4] = [0, 0, 0, 1];

/// `PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE`.
pub const KIND_MANUAL: [u8; 4] = [0, 0, 0, 2];

/// The longest `data` a received message may carry: an implementation
/// supports at least 128 octets (Sec.9.6.3.1); what is longer is refused.
const MAX_DATA: usize = 4096;

/// A decoded `ParticipantMessageData`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParticipantMessage {
    pub participant_guid_prefix: [u8; 12],
    pub kind: [u8; 4],
}

/// The serialized payload of a message with empty `data`, CDR little
/// endian (encapsulation `CDR_LE`, RTPS v2.5 Sec.10.2).
#[must_use]
pub fn encode_participant_message_data(prefix: &[u8; 12], kind: [u8; 4]) -> [u8; 24] {
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&[0x00, 0x01, 0x00, 0x00]);
    buf[4..16].copy_from_slice(prefix);
    buf[16..20].copy_from_slice(&kind);
    // sequence<octet> data: length 0.
    buf
}

/// Read a serialized `ParticipantMessageData` (encapsulation header
/// included): `CDR_BE` or `CDR_LE`, the sequence length in that byte
/// order, the sequence within the payload.
pub fn decode_participant_message_data(payload: &[u8]) -> Option<ParticipantMessage> {
    if payload.len() < 24 {
        return None;
    }
    let little_endian = match [payload[0], payload[1]] {
        [0x00, 0x00] => false,
        [0x00, 0x01] => true,
        _ => return None,
    };
    let mut participant_guid_prefix = [0u8; 12];
    participant_guid_prefix.copy_from_slice(&payload[4..16]);
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&payload[16..20]);
    let len_bytes = [payload[20], payload[21], payload[22], payload[23]];
    let len = if little_endian {
        u32::from_le_bytes(len_bytes)
    } else {
        u32::from_be_bytes(len_bytes)
    };
    let len = usize::try_from(len).ok()?;
    if len > MAX_DATA || payload.len() < 24 + len {
        return None;
    }
    Some(ParticipantMessage {
        participant_guid_prefix,
        kind,
    })
}

fn header(version: (u8, u8), our_prefix: &[u8; 12]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(128);
    packet.extend_from_slice(crate::core::rtps_constants::RTPS_MAGIC);
    packet.extend_from_slice(&[version.0, version.1]);
    packet.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
    packet.extend_from_slice(our_prefix);
    packet
}

/// One liveliness assertion of the participant `our_prefix` to the
/// participant `destination`: INFO_DST, INFO_TS, the DATA of sequence
/// number `sn` (the instance `kind`, empty data), and a final HEARTBEAT
/// announcing `sn` alone, so a reliable reader expects nothing older.
pub fn build_participant_message(
    our_prefix: &[u8; 12],
    destination: &[u8; 12],
    sn: u64,
    kind: [u8; 4],
    heartbeat_count: u32,
    timestamp: (u32, u32),
) -> RtpsEncodeResult<Vec<u8>> {
    if sn == 0 {
        return Err(RtpsEncodeError::InvalidParameter(
            "sequence numbers start at 1",
        ));
    }
    let version = (
        crate::core::rtps_constants::RTPS_VERSION_MAJOR,
        crate::core::rtps_constants::RTPS_VERSION_MINOR,
    );
    let mut packet = header(version, our_prefix);
    packet.extend_from_slice(&encode_info_dst(destination));
    packet.extend_from_slice(&encode_info_ts(timestamp.0, timestamp.1));
    let payload = encode_participant_message_data(our_prefix, kind);
    packet.extend_from_slice(&encode_data(
        &PARTICIPANT_MESSAGE_READER,
        &PARTICIPANT_MESSAGE_WRITER,
        sn,
        &payload,
    )?);
    packet.extend_from_slice(&encode_heartbeat_final(
        &PARTICIPANT_MESSAGE_READER,
        &PARTICIPANT_MESSAGE_WRITER,
        sn,
        sn,
        heartbeat_count,
    )?);
    Ok(packet)
}

/// A HEARTBEAT of the participant-message writer of `our_prefix` alone,
/// to `destination`, announcing `[first_sn, last_sn]` (`1, 0` before any
/// assertion), in an RTPS message of `version`: the one a discovery
/// handshake sends (RTPS v2.5 Sec.8.3.8.6).
pub fn build_participant_message_heartbeat(
    our_prefix: &[u8; 12],
    destination: &[u8; 12],
    first_sn: u64,
    last_sn: u64,
    count: u32,
    version: (u8, u8),
) -> RtpsEncodeResult<Vec<u8>> {
    let mut packet = header(version, our_prefix);
    packet.extend_from_slice(&encode_info_dst(destination));
    packet.extend_from_slice(&encode_heartbeat(
        &PARTICIPANT_MESSAGE_READER,
        &PARTICIPANT_MESSAGE_WRITER,
        first_sn,
        last_sn,
        count,
    )?);
    Ok(packet)
}

/// A GAP of the participant-message writer of `our_prefix`, to
/// `destination`, declaring `[gap_start, gap_list_base)` irrelevant (RTPS
/// v2.5 Sec.8.3.8.4): the numbers its KEEP_LAST(1) HistoryCache no longer
/// holds because a newer assertion superseded them (Sec.8.4.13.3).
pub fn build_participant_message_gap(
    our_prefix: &[u8; 12],
    destination: &[u8; 12],
    gap_start: u64,
    gap_list_base: u64,
) -> RtpsEncodeResult<Vec<u8>> {
    let version = (
        crate::core::rtps_constants::RTPS_VERSION_MAJOR,
        crate::core::rtps_constants::RTPS_VERSION_MINOR,
    );
    let mut packet = header(version, our_prefix);
    packet.extend_from_slice(&encode_info_dst(destination));
    packet.extend_from_slice(&encode_gap(
        &PARTICIPANT_MESSAGE_READER,
        &PARTICIPANT_MESSAGE_WRITER,
        gap_start,
        gap_list_base,
        0,
        &[],
    )?);
    Ok(packet)
}

/// What the participant-message writer, holding `last_sn` (0 before any
/// assertion), answers an ACKNACK naming it with.
///
/// RTPS v2.5 Sec.8.4.13.3 fixes `history.depth = 1`: the writer's
/// HistoryCache never holds more than its current sample, so an ACKNACK
/// naming an older sequence number gets a GAP (Sec.8.3.8.4), never a
/// retransmit, and the current sample is resent only while the peer still
/// lacks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WriterAcknackReply {
    /// Resend the current sample (`last_sn`): the peer still lacks it.
    pub resend_last: bool,
    /// A GAP covering `[1, gap_upto)`, when the peer asked for (or is
    /// behind on) a number this writer superseded.
    pub gap_upto: Option<u64>,
}

/// Decide `WriterAcknackReply` from the writer's own `last_sn` and the
/// ACKNACK's `bitmap_base` (readerSNState.bitmapBase: the next sequence
/// the peer expects) and `missing_ranges` (its explicit holes).
#[must_use]
pub fn writer_reply_to_acknack(
    last_sn: u64,
    bitmap_base: u64,
    missing_ranges: &[Range<u64>],
) -> WriterAcknackReply {
    if last_sn == 0 {
        // Nothing was ever asserted: nothing exists to resend or retire.
        return WriterAcknackReply::default();
    }
    let peer_behind = bitmap_base <= last_sn || missing_ranges.iter().any(|r| r.start <= last_sn);
    if !peer_behind {
        // The peer already holds the current sample: a pure ACK.
        return WriterAcknackReply::default();
    }
    WriterAcknackReply {
        resend_last: true,
        gap_upto: (last_sn > 1).then_some(last_sn),
    }
}

/// What the participant-message reader, holding `have` (0 before any
/// receipt) from one peer's writer, answers that writer's HEARTBEAT
/// `last_sn` with: the ACKNACK's bitmapBase, and the one sequence number
/// worth requesting, if any.
///
/// RTPS v2.5 Sec.8.4.13.3 (`history.depth = 1` on both ends of this
/// endpoint pair): an assertion older than the writer's current one has
/// no value to a KEEP_LAST(1) reader, so only the newest is ever worth
/// asking for; the bitmapBase is set to the newest number itself rather
/// than to `have + 1`, so the writer's GAP answers a hole this reader
/// never meant to chase.
#[must_use]
pub fn reader_reply_to_heartbeat(have: u64, last_sn: u64) -> (u64, Option<u64>) {
    if last_sn == 0 || have >= last_sn {
        (have.max(last_sn) + 1, None)
    } else {
        (last_sn, Some(last_sn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const PEER: [u8; 12] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
    ];

    fn le32(b: &[u8]) -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }

    /// Every byte of an assertion, read back by hand (RTPS v2.5 Sec.8.3.3,
    /// Sec.9.4.5, Sec.9.6.3.1).
    #[test]
    fn an_automatic_assertion_carries_its_participant_and_kind() {
        let p = build_participant_message(&OURS, &PEER, 7, KIND_AUTOMATIC, 9, (100, 200))
            .expect("built");
        assert_eq!(&p[0..4], b"RTPS");
        assert_eq!(&p[6..8], &[0x01, 0x1A], "vendor HDDS");
        assert_eq!(&p[8..20], &OURS);
        // INFO_DST
        assert_eq!(p[20], 0x0E);
        assert_eq!(&p[24..36], &PEER);
        // INFO_TS
        assert_eq!(p[36], 0x09);
        assert_eq!(le32(&p[40..44]), 100);
        // DATA: E and D flags, no inline QoS
        let d = 48;
        assert_eq!(p[d], 0x15);
        assert_eq!(p[d + 1], 0x05);
        let data_len = usize::from(u16::from_le_bytes([p[d + 2], p[d + 3]]));
        assert_eq!(data_len, 20 + 24);
        assert_eq!(
            u16::from_le_bytes([p[d + 6], p[d + 7]]),
            16,
            "octetsToInlineQos"
        );
        assert_eq!(&p[d + 8..d + 12], &PARTICIPANT_MESSAGE_READER);
        assert_eq!(&p[d + 12..d + 16], &PARTICIPANT_MESSAGE_WRITER);
        assert_eq!(le32(&p[d + 16..d + 20]), 0, "sn high");
        assert_eq!(le32(&p[d + 20..d + 24]), 7, "sn low");
        let payload = &p[d + 24..d + 48];
        assert_eq!(&payload[0..4], &[0x00, 0x01, 0x00, 0x00], "CDR_LE");
        assert_eq!(&payload[4..16], &OURS, "participantGuidPrefix");
        assert_eq!(&payload[16..20], &[0, 0, 0, 1], "kind, octets in order");
        assert_eq!(le32(&payload[20..24]), 0, "empty data");
        // HEARTBEAT, final, announcing sn alone
        let h = d + 4 + data_len;
        assert_eq!(p[h], 0x07);
        assert_eq!(p[h + 1], 0x03, "E and F");
        assert_eq!(&p[h + 4..h + 8], &PARTICIPANT_MESSAGE_READER);
        assert_eq!(&p[h + 8..h + 12], &PARTICIPANT_MESSAGE_WRITER);
        assert_eq!(le32(&p[h + 16..h + 20]), 7, "firstSN");
        assert_eq!(le32(&p[h + 24..h + 28]), 7, "lastSN");
        assert_eq!(le32(&p[h + 28..h + 32]), 9, "count");
        assert_eq!(p.len(), h + 32);
    }

    #[test]
    fn a_message_reads_back_in_either_byte_order() {
        let le = encode_participant_message_data(&OURS, KIND_MANUAL);
        let got = decode_participant_message_data(&le).expect("decoded");
        assert_eq!(got.participant_guid_prefix, OURS);
        assert_eq!(got.kind, KIND_MANUAL);
        let mut be = le;
        be[0..4].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert_eq!(decode_participant_message_data(&be), Some(got));
        // Cyclone DDS sends one octet of data (`sequenceSize: 1`).
        let mut cyclone = le.to_vec();
        cyclone[20..24].copy_from_slice(&1u32.to_le_bytes());
        cyclone.push(0);
        assert_eq!(decode_participant_message_data(&cyclone), Some(got));
    }

    #[test]
    fn a_truncated_or_foreign_message_is_refused() {
        let le = encode_participant_message_data(&OURS, KIND_AUTOMATIC);
        assert_eq!(decode_participant_message_data(&le[..23]), None);
        let mut pl = le;
        pl[1] = 0x03; // PL_CDR_LE: not this struct's encapsulation
        assert_eq!(decode_participant_message_data(&pl), None);
        let mut long = le;
        long[20..24].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            decode_participant_message_data(&long),
            None,
            "data past the end"
        );
    }

    #[test]
    fn a_handshake_heartbeat_announces_the_range_it_is_given() {
        let p = build_participant_message_heartbeat(&OURS, &PEER, 1, 0, 1, (2, 4)).expect("built");
        assert_eq!(&p[4..6], &[2, 4]);
        assert_eq!(p[36], 0x07);
        assert_eq!(p[37], 0x01, "not final: the reader answers");
        assert_eq!(le32(&p[52..56]), 1, "firstSN");
        assert_eq!(le32(&p[60..64]), 0, "lastSN");
        assert_eq!(p.len(), 20 + 16 + 32);
    }

    /// Every byte of a GAP retiring the numbers a KEEP_LAST(1) writer no
    /// longer holds (RTPS v2.5 Sec.8.3.8.4, Sec.8.4.13.3).
    #[test]
    fn a_gap_retires_everything_before_the_current_sample() {
        let p = build_participant_message_gap(&OURS, &PEER, 1, 5).expect("built");
        assert_eq!(&p[8..20], &OURS);
        assert_eq!(p[20], 0x0E, "INFO_DST");
        assert_eq!(&p[24..36], &PEER);
        let g = 36;
        assert_eq!(p[g], 0x08, "GAP");
        assert_eq!(&p[g + 4..g + 8], &PARTICIPANT_MESSAGE_READER);
        assert_eq!(&p[g + 8..g + 12], &PARTICIPANT_MESSAGE_WRITER);
        assert_eq!(le32(&p[g + 16..g + 20]), 1, "gapStart");
        assert_eq!(le32(&p[g + 24..g + 28]), 5, "gapListBase");
        assert_eq!(le32(&p[g + 28..g + 32]), 0, "numBits");
    }

    #[test]
    fn a_writer_with_nothing_asserted_answers_nothing() {
        assert_eq!(
            writer_reply_to_acknack(0, 1, &[]),
            WriterAcknackReply::default()
        );
        assert_eq!(
            writer_reply_to_acknack(0, 1, &[Range { start: 1, end: 2 }]),
            WriterAcknackReply::default()
        );
    }

    #[test]
    fn a_peer_already_holding_the_current_sample_gets_no_answer() {
        // Pure ACK: bitmapBase past last_sn, no explicit holes.
        assert_eq!(
            writer_reply_to_acknack(7, 8, &[]),
            WriterAcknackReply::default()
        );
    }

    #[test]
    fn a_peer_behind_gets_the_current_sample_and_a_gap_for_the_rest() {
        // bitmapBase <= last_sn: the peer has not yet acked the current one.
        assert_eq!(
            writer_reply_to_acknack(5, 1, &[]),
            WriterAcknackReply {
                resend_last: true,
                gap_upto: Some(5),
            }
        );
        // The exact boundary bitmap_base == last_sn: the peer's cumulative
        // ack is last_sn - 1, so it still lacks the current sample.
        assert_eq!(
            writer_reply_to_acknack(9, 9, &[]),
            WriterAcknackReply {
                resend_last: true,
                gap_upto: Some(9),
            },
            "bitmap_base == last_sn is still behind, not yet synchronized"
        );
        // An explicit hole naming a superseded number: same answer, no GAP
        // of a single sample (last_sn == 1 has nothing before it).
        assert_eq!(
            writer_reply_to_acknack(1, 2, &[Range { start: 1, end: 2 }]),
            WriterAcknackReply {
                resend_last: true,
                gap_upto: None,
            }
        );
    }

    #[test]
    fn a_reader_holding_the_newest_sends_a_pure_ack() {
        assert_eq!(reader_reply_to_heartbeat(9, 9), (10, None));
        assert_eq!(
            reader_reply_to_heartbeat(9, 5),
            (10, None),
            "ahead: still a pure ack"
        );
        assert_eq!(
            reader_reply_to_heartbeat(0, 0),
            (1, None),
            "writer asserted nothing"
        );
    }

    #[test]
    fn a_reader_behind_asks_for_the_newest_alone() {
        // Behind by several: only the newest is ever worth asking for, the
        // older superseded ones are never requested.
        assert_eq!(reader_reply_to_heartbeat(2, 9), (9, Some(9)));
        assert_eq!(
            reader_reply_to_heartbeat(0, 1),
            (1, Some(1)),
            "first ever assertion"
        );
    }
}

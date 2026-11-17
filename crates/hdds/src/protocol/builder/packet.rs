// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::helpers::{build_inline_qos_for_ecs, build_inline_qos_with_topic};
// DATA/GAP submessages are built through the DialectEncoder.
use crate::dds::cdr_negotiation::encap_kind_for_version;
use crate::dds::CdrVersion;
use crate::protocol::constants::*;
use crate::protocol::dialect::{get_encoder, Dialect};
use crate::protocol::rtps::{encode_info_ts, sequence_number_le_bytes};

/// Current wall-clock as (sec, frac) where frac is 2^-32 seconds (RTPS v2.5 sec. 9.3.2).
///
/// `pub(crate)`: the write() site (`dds::writer::runtime`) and the ECS
/// close path (`dds::writer::coherent`) call this directly to capture
/// ONE timestamp that serves both to build the live packet AND
/// journaled in the history cache, so a later repair can replay the
/// exact same value instead of calling this again.
pub(crate) fn now_rtps_timestamp() -> (u32, u32) {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    // Time_t.seconds is 32 bits wide: past 2106 the clock saturates at the
    // last representable second, as it always has here.
    let sec = u32::try_from(d.as_secs()).unwrap_or(u32::MAX);
    // The fraction of a second is below 1.0 by `Duration`'s contract
    // (`subsec_nanos() < 1_000_000_000`), so (nanos << 32) / 1e9 < 2^32 and
    // the conversion succeeds; the fallback is the largest fraction, chosen
    // so a violated contract could never read as a smaller timestamp.
    let frac =
        u32::try_from((u64::from(d.subsec_nanos()) << 32) / 1_000_000_000).unwrap_or(u32::MAX);
    (sec, frac)
}

/// The SerializedPayload of a user DATA, DATA_FRAG or key-only DATA: the
/// encapsulation identifier `wire_encap`, the options, `body`, then zeros up
/// to the next multiple of 4.
///
/// DDS-XTypes 1.3 7.6.3.1.2: "Implementations of this specification shall
/// set the least significant two bits in the second byte of the options
/// field to a value that encodes the number of padding bytes needed after
/// the end of the serialized payload in order to reach the next 4-byte
/// aligned offset", and the receiver reads them "to determine where the
/// serialized data exactly ended". The padding is appended and counted, so
/// a receiver that honours the count recovers `body` exactly, and one that
/// ignores it reads at most three zero octets past the last member.
///
/// A protected body already replaces the complete SerializedPayload
/// (DDS-Security 1.1 Sec.9.5.3.3.4.4). Its encapsulation is inside the
/// cryptographic content; the builder must copy the protected octets exactly.
pub(crate) fn encapsulate_serialized_payload(
    wire_encap: u16,
    body: &[u8],
    sealed: bool,
) -> Vec<u8> {
    if sealed {
        return body.to_vec();
    }
    let padding: u8 = match body.len() % 4 {
        0 => 0,
        1 => 3,
        2 => 2,
        _ => 1,
    };
    let len = 4 + body.len() + usize::from(padding);
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&wire_encap.to_be_bytes());
    out.extend_from_slice(&[0x00, padding]);
    out.extend_from_slice(body);
    out.resize(len, 0);
    out
}

/// Narrow a DATA submessage body length to `octetsToNextHeader` (u16).
///
/// The packet builders in this file signal failure with an empty packet
/// (see their `inline_qos.is_empty()` checks); a body that does not fit the
/// header follows the same convention rather than shipping a wrapped
/// length. The non-fragmented path is only entered for payloads under
/// `DEFAULT_MAX_UNFRAGMENTED_SIZE` (`should_fragment`), so this fires only
/// on a caller that bypassed fragmentation.
fn data_body_octets(submsg_body_len: usize) -> Option<u16> {
    match u16::try_from(submsg_body_len) {
        Ok(len) => Some(len),
        Err(_) => {
            log::error!(
                "[builder] DATA body of {} octets exceeds octetsToNextHeader (u16); packet dropped",
                submsg_body_len
            );
            None
        }
    }
}

/// RTPS endpoint context used when building DATA packets.
///
/// Carries the GUID prefix and entity IDs so that user DATA packets can be
/// aligned with the GUIDs announced via SPDP/SEDP.
#[derive(Clone, Copy, Debug)]
pub struct RtpsEndpointContext {
    pub guid_prefix: [u8; 12],
    pub reader_entity_id: [u8; 4],
    pub writer_entity_id: [u8; 4],
    /// Canonical (XCDR2) RTPS encapsulation kind for the type's extensibility.
    ///
    /// * `@final` -> `PLAIN_CDR2_LE` (0x0007)
    /// * `@appendable` -> `D_CDR2_LE` (0x0009) -- delimited CDR2 with DHEADER
    ///   per DDS-XTypes v1.3 sec. 7.6.3.1.2
    /// * `@mutable` -> `PL_CDR2_LE` (0x000B)
    ///
    /// The actual wire encap kind is derived per-write from this canonical
    /// form combined with the writer's `effective_cdr_version()` via
    /// `encap_kind_for_version`. Legacy XCDR1 wire codes (`0x0001`,
    /// `0x0003`) are passed through unchanged for back-compat.
    pub encapsulation_kind: u16,
    /// EntityId of the Publisher the writer belongs to (RTPS v2.5
    /// Sec.9.3.1.2, kind 0x08 USER_DEFINED_PUBLISHER_GROUP): what
    /// `PID_GROUP_ENTITY_ID` and `PID_GROUP_GUID` name for this writer, in
    /// SEDP and on a GROUP-scope member or end of set. Each Publisher of a
    /// participant has its own (`Publisher::entity_id`). Not used by a
    /// reader's context.
    pub publisher_entity_id: [u8; 4],
}

/// Byte offset of readerEntityId within a standard RTPS DATA packet built
/// by `build_data_packet_with_context` / `build_single_data_frag_packet` /
/// `build_dispose_packet_with_context`.
///
/// Layout: RTPS header (20) + INFO_TS (12) + DATA submsg header (4) +
/// extraFlags (2) + octetsToInlineQos (2) = offset 40.
/// Used by `send_packet_to_endpoints()` to patch per-reader entity IDs
/// for cross-vendor interop (RTPS v2.5 Sec.8.3.8.2).
///
/// **INVARIANT**: every DATA-carrying builder in this crate MUST emit an
/// `INFO_TS` submessage immediately after the RTPS header, so that
/// `find_data_submsg_offset(bytes) + 20 == READER_ENTITY_ID_OFFSET` holds.
/// Guarded by `tests::builders_honor_reader_entity_id_offset`. When adding
/// a new DATA-emitting builder, extend that test to cover it.
pub const READER_ENTITY_ID_OFFSET: usize = 40;

/// Build RTPS DATA packet with topic name and sequence number.
///
/// Uses DialectEncoder for the DATA header and includes HDDS-specific inline
/// QoS with topic name for intra-HDDS routing without discovery.
///
/// This function is HDDS-specific (inline QoS with topic name).
/// For interop with external stacks, use build_data_packet_with_context().
pub fn build_data_packet(topic: &str, sequence: u64, payload: &[u8]) -> Vec<u8> {
    // Intra-HDDS mode: include inline QoS with topic for local routing
    let inline_qos = build_inline_qos_with_topic(topic);
    if inline_qos.is_empty() {
        return Vec::new();
    }

    // Use USER DATA entity IDs (not SEDP built-in endpoints!)
    // Reader entity ID: 0x00000004 (user-defined reader)
    // Writer entity ID: 0x00000002 (user-defined writer)
    let reader_id: [u8; 4] = [0x00, 0x00, 0x00, 0x04];
    let writer_id: [u8; 4] = [0x00, 0x00, 0x00, 0x02];

    // Combine inline QoS + payload for DATA submessage
    let mut combined_payload = Vec::with_capacity(inline_qos.len() + payload.len());
    combined_payload.extend_from_slice(&inline_qos);
    combined_payload.extend_from_slice(payload);

    // Build RTPS header (20 bytes)
    let mut packet = Vec::with_capacity(20 + 24 + combined_payload.len());
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // 12-byte GUID prefix

    // Use DialectEncoder for DATA submessage
    // Inline QoS is embedded in combined_payload, encoder builds standard DATA header
    let encoder = get_encoder(Dialect::Hybrid);
    let Ok(data_submsg) =
        encoder.build_data(&reader_id, &writer_id, sequence, &combined_payload, None)
    else {
        return Vec::new();
    };

    packet.extend_from_slice(&data_submsg);
    packet
}

/// Build RTPS HEARTBEAT packet using DialectEncoder.
///
/// Uses the Hybrid encoder for consistent RTPS-compliant encoding.
///
/// NOTE: This function uses hardcoded SEDP entity IDs. For user data endpoints,
/// use `build_heartbeat_packet_with_context` which uses the correct entity IDs.
pub fn build_heartbeat_packet(first_seq: u64, last_seq: u64, count: u32) -> Vec<u8> {
    // Build RTPS header (20 bytes)
    let mut packet = Vec::with_capacity(20 + 32);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // 12-byte GUID prefix

    // Use DialectEncoder for HEARTBEAT submessage
    let encoder = get_encoder(Dialect::Hybrid);
    let Ok(heartbeat) = encoder.build_heartbeat(
        &RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
        &RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        first_seq,
        last_seq,
        count,
    ) else {
        return Vec::new();
    };

    packet.extend_from_slice(&heartbeat);
    packet
}

/// Build RTPS HEARTBEAT packet using explicit endpoint context.
///
/// For RELIABLE user data writers, sends HEARTBEATs with the correct
/// writer entity ID (from context) so readers can match and respond with
/// proper ACKNACKs for retransmission.
///
/// Uses the Hybrid encoder for consistent RTPS-compliant encoding.
pub fn build_heartbeat_packet_with_context(
    ctx: &RtpsEndpointContext,
    first_seq: u64,
    last_seq: u64,
    count: u32,
) -> Vec<u8> {
    // Build RTPS header (20 bytes)
    let mut packet = Vec::with_capacity(20 + 32);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);

    // Use DialectEncoder for HEARTBEAT submessage
    let encoder = get_encoder(Dialect::Hybrid);
    let Ok(heartbeat) = encoder.build_heartbeat(
        &ctx.reader_entity_id,
        &ctx.writer_entity_id,
        first_seq,
        last_seq,
        count,
    ) else {
        return Vec::new();
    };

    packet.extend_from_slice(&heartbeat);
    packet
}

/// HEARTBEAT LivelinessFlag 'L' (RTPS v2.5 Sec.8.3.7.5, Sec.9.4.5.7): the
/// 3rd least significant bit of the flags -- a MANUAL_BY_TOPIC writer
/// asserted its liveliness (`DataWriter::assert_liveliness`) with nothing
/// new to write.
const HEARTBEAT_LIVELINESS_FLAG: u8 = 0x04;

/// HEARTBEAT FinalFlag 'F' (RTPS v2.5 Sec.8.3.8.6): the Writer does not
/// require an ACKNACK in response.
const HEARTBEAT_FINAL_FLAG: u8 = 0x02;

/// A HEARTBEAT with the Final and Liveliness flags set (RTPS v2.5
/// Sec.8.4.13.5 last paragraph, Sec.8.3.7.5): a MANUAL_BY_TOPIC writer
/// asserting its liveliness with nothing new to write. `packet` is an RTPS
/// header then exactly one little-endian HEARTBEAT submessage, as
/// `build_heartbeat_packet_with_context` produces; an unexpected shape
/// yields an EMPTY packet (this file's refusal convention, as
/// `with_group_info` below).
pub fn with_liveliness_assertion_flags(mut packet: Vec<u8>) -> Vec<u8> {
    const SUBMESSAGE: usize = 20;
    if packet.len() < SUBMESSAGE + 2
        || packet[SUBMESSAGE] != 0x07
        || packet[SUBMESSAGE + 1] & 0x01 == 0
    {
        return Vec::new();
    }
    packet[SUBMESSAGE + 1] |= HEARTBEAT_FINAL_FLAG | HEARTBEAT_LIVELINESS_FLAG;
    packet
}

/// HEARTBEAT GroupInfoFlag 'G' (RTPS v2.5 Sec.9.4.5.7): the 4th least
/// significant bit of the flags.
pub const HEARTBEAT_GROUP_INFO_FLAG: u8 = 0x08;

/// GAP GroupInfoFlag 'G' (RTPS v2.5 Sec.9.4.5.6): the 2nd least
/// significant bit of the flags.
pub const GAP_GROUP_INFO_FLAG: u8 = 0x02;

/// Set the GroupInfoFlag `flag` on the one submessage of `packet` (an RTPS
/// header then exactly one little-endian submessage, as the builders of
/// this file produce) and append `gsns` as SequenceNumber_t after its body
/// (or a GAP's FilteredCountFlag and its filteredCount, which has the same
/// layout, `build_gap_packet_filtered`).
/// An unexpected shape yields an EMPTY packet, this file's refusal
/// convention.
fn with_group_info(mut packet: Vec<u8>, flag: u8, gsns: &[u64]) -> Vec<u8> {
    const SUBMESSAGE: usize = 20;
    if packet.len() < SUBMESSAGE + 4 || packet[SUBMESSAGE + 1] & 0x01 == 0 {
        return Vec::new();
    }
    let body = usize::from(u16::from_le_bytes([
        packet[SUBMESSAGE + 2],
        packet[SUBMESSAGE + 3],
    ]));
    if SUBMESSAGE + 4 + body != packet.len() {
        return Vec::new();
    }
    let Ok(grown) = u16::try_from(body + 8 * gsns.len()) else {
        return Vec::new();
    };
    packet[SUBMESSAGE + 1] |= flag;
    packet[SUBMESSAGE + 2..SUBMESSAGE + 4].copy_from_slice(&grown.to_le_bytes());
    for gsn in gsns {
        packet.extend_from_slice(&sequence_number_le_bytes(*gsn));
    }
    packet
}

/// The HEARTBEAT of a GROUP Publisher's writer, with its GroupInfo:
/// `[currentGSN, firstGSN, lastGSN]` after `count` (RTPS v2.5 Sec.9.4.5.7,
/// 24 octets: the wire layout governs the PIM's writerSet and
/// secureWriterSet, which it does not carry, D15).
pub fn build_heartbeat_packet_group(
    ctx: &RtpsEndpointContext,
    first_seq: u64,
    last_seq: u64,
    count: u32,
    group_info: [u64; 3],
) -> Vec<u8> {
    with_group_info(
        build_heartbeat_packet_with_context(ctx, first_seq, last_seq, count),
        HEARTBEAT_GROUP_INFO_FLAG,
        &group_info,
    )
}

/// A GAP of the one change `seq` of a GROUP Publisher's writer, with its
/// GroupInfo `gapStartGSN = gap_start_gsn`, `gapEndGSN = gap_end_gsn`
/// (RTPS v2.5 Sec.8.3.8.4, Sec.9.4.5.6).
pub fn build_gap_packet_group(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    seq: u64,
    gap_start_gsn: u64,
    gap_end_gsn: u64,
    guid_prefix: [u8; 12],
) -> Vec<u8> {
    let Some(next) = seq.checked_add(1) else {
        return Vec::new();
    };
    with_group_info(
        build_gap_packet_from_parts(reader_id, writer_id, seq, next, &[], guid_prefix),
        GAP_GROUP_INFO_FLAG,
        &[gap_start_gsn, gap_end_gsn],
    )
}

/// GAP FilteredCountFlag 'F' (RTPS v2.5 Sec.9.4.5.6): the 3rd least
/// significant bit of the flags.
pub const GAP_FILTERED_COUNT_FLAG: u8 = 0x04;

/// The GAP of `writer_id`'s change `seq` that `reader_id` is not sent
/// because it is no change for that reader: `[seq, seq + 1)`, its
/// FilteredCountFlag set and its filteredCount 1 (RTPS v2.5 Sec.8.3.8.4,
/// Sec.9.4.5.6), so the reader knows it irrelevant, not lost (Sec.8.4.9.2,
/// transition T4: "Filtered changes should not be treated as samples
/// lost"). A ChangeCount_t (Sec.9.3.2.11: `high` long, `low` unsigned
/// long) has the wire layout of a SequenceNumber_t. A receiver that reads
/// no filteredCount (RTPS before v2.5) skips it with the submessage's
/// octetsToNextHeader, as it skips every trailing element it does not know.
pub fn build_gap_packet_filtered(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    seq: u64,
    guid_prefix: [u8; 12],
) -> Vec<u8> {
    let Some(next) = seq.checked_add(1) else {
        return Vec::new();
    };
    with_group_info(
        build_gap_packet_from_parts(reader_id, writer_id, seq, next, &[], guid_prefix),
        GAP_FILTERED_COUNT_FLAG,
        &[1],
    )
}

/// Build RTPS GAP packet using DialectEncoder.
///
/// Built with DialectEncoder::build_gap().
///
/// This function takes a pre-encoded GapMsg payload.
/// The GapMsg struct has reader/writer entity IDs and sequence info embedded.
/// We extract them from the payload and delegate to DialectEncoder.
pub fn build_gap_packet(payload: &[u8], guid_prefix: [u8; 12]) -> Vec<u8> {
    // GAP payload format (from GapMsg::encode_cdr2_le):
    // - reader_entity_id: 4 bytes (offset 0)
    // - writer_entity_id: 4 bytes (offset 4)
    // - gap_start: 8 bytes (offset 8)
    // - gap_list_base: 8 bytes (offset 16)
    // - num_bits: 4 bytes (offset 24)
    // - bitmap: variable (offset 28)
    if payload.len() < 28 {
        return Vec::new();
    }

    let reader_id: [u8; 4] = payload[0..4].try_into().unwrap_or([0; 4]);
    let writer_id: [u8; 4] = payload[4..8].try_into().unwrap_or([0; 4]);

    let gap_start_high = i32::from_le_bytes(payload[8..12].try_into().unwrap_or([0; 4]));
    let gap_start_low = u32::from_le_bytes(payload[12..16].try_into().unwrap_or([0; 4]));
    let gap_start = ((gap_start_high as i64) << 32 | gap_start_low as i64) as u64;

    let gap_list_base_high = i32::from_le_bytes(payload[16..20].try_into().unwrap_or([0; 4]));
    let gap_list_base_low = u32::from_le_bytes(payload[20..24].try_into().unwrap_or([0; 4]));
    let gap_list_base = ((gap_list_base_high as i64) << 32 | gap_list_base_low as i64) as u64;

    let num_bits = u32::from_le_bytes(payload[24..28].try_into().unwrap_or([0; 4]));
    let bitmap_words = num_bits.div_ceil(32) as usize;

    let mut bitmap = Vec::with_capacity(bitmap_words);
    for i in 0..bitmap_words {
        let offset = 28 + i * 4;
        if offset + 4 <= payload.len() {
            let word = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap_or([0; 4]));
            bitmap.push(word);
        }
    }

    build_gap_packet_from_parts(
        &reader_id,
        &writer_id,
        gap_start,
        gap_list_base,
        &bitmap,
        guid_prefix,
    )
}

/// Build an RTPS GAP packet from explicit GAP fields (RTPS v2.5 SS8.3.8.4).
///
/// Same framing as [`build_gap_packet`] (RTPS header with OUR vendor id and
/// the caller's `guid_prefix`, then one GAP submessage) but takes the GAP
/// fields directly instead of a pre-encoded `GapMsg` payload, so callers
/// that already hold the sequence numbers (e.g. the ECS close-slot repair,
/// which retires exactly one SN) avoid the intermediate payload encoding
/// and its byte-layout coupling entirely.
pub fn build_gap_packet_from_parts(
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    gap_start: u64,
    gap_list_base: u64,
    bitmap: &[u32],
    guid_prefix: [u8; 12],
) -> Vec<u8> {
    // Build RTPS header (20 bytes)
    let mut packet = Vec::with_capacity(20 + 40);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    // The header prefix MUST be the sending writer's real participant prefix:
    // reliable readers attribute a GAP to a writer proxy by (header prefix,
    // writerEntityId); an unattributable GAP is dropped, the reader never
    // advances past the gapped range, and in-order delivery stalls forever.
    packet.extend_from_slice(&guid_prefix);

    // Use DialectEncoder for GAP submessage. A GAP that cannot be encoded
    // yields an EMPTY packet, the convention every caller in this file
    // tests for, never an RTPS header with nothing behind it.
    let encoder = get_encoder(Dialect::Hybrid);
    let Ok(gap_submsg) = encoder.build_gap(reader_id, writer_id, gap_start, gap_list_base, bitmap)
    else {
        return Vec::new();
    };

    packet.extend_from_slice(&gap_submsg);
    packet
}

/// Build RTPS DATA packet using an explicit RTPS endpoint context.
///
/// Built with DialectEncoder::build_data(), with a CDR encapsulation header
/// (PLAIN_CDR_LE) for cross-vendor interop (DDSI-RTPS 2.5 Sec.10.5).
///
/// This variant aligns the RTPS header GUID prefix and DATA writer entity ID
/// with the GUID announced via SPDP/SEDP so that any receiver can correctly
/// associate DATA with the writers it discovered.
///
/// Since this function is used for interop with external DDS stacks,
/// it does NOT include inline QoS with topic name - topic matching is
/// already done via SEDP discovery.
///
/// # CDR Encapsulation
///
/// The payload from `DDS::encode(buf, version)` contains raw CDR-encoded data without
/// the 4-byte encapsulation header. For DDS interoperability, user data must be
/// prefixed with a CDR encapsulation header:
///
/// ```text
/// [encapsulation_kind: u16 BE][options: u16] + [CDR payload]
/// ```
///
/// The wire encap kind is derived from `ctx.encapsulation_kind` (the type's
/// canonical XCDR2 form) and `version` via
/// `encap_kind_for_version`,
/// so the wire header stays consistent with the bytes produced by
/// `T::encode(buf, version)`.
pub fn build_data_packet_with_context(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
    version: CdrVersion,
) -> Vec<u8> {
    build_data_packet_with_context_ts(ctx, topic, sequence, payload, version, now_rtps_timestamp())
}

/// Same as [`build_data_packet_with_context`] but takes the wire INFO_TS
/// as an explicit input instead of reading the clock internally.
///
/// Cold repair call sites (`nack.rs::on_nack`, `runtime.rs::replay_to`)
/// pass the journaled `change.metadata.source_ts` here so a retransmit
/// or a TRANSIENT_LOCAL replay reproduces the exact same wire timestamp
/// as the original live emission; the live write path (and any caller
/// that just wants "now") uses [`build_data_packet_with_context`], which
/// captures `now_rtps_timestamp()` once and delegates here -- so the
/// live small-DATA wire bytes are unchanged (same clock call, same
/// value, just moved to the caller).
pub fn build_data_packet_with_context_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
    version: CdrVersion,
    source_ts: (u32, u32),
) -> Vec<u8> {
    build_data_packet_with_context_full_ts(
        ctx, topic, sequence, payload, version, source_ts, None, None,
    )
}

/// Coherent-aware DATA packet builder. Same wire format as
/// [`build_data_packet_with_context`] but with optional PID_COHERENT_SET +
/// PID_GROUP_COHERENT_SET_HDDS (0x8030, HDDS vendor-specific, not the
/// standard 0x0063 -- see
/// `builder::helpers::append_pid_group_coherent_set`) appended in inline
/// QoS per RTPS v2.5 sec. 8.7.5 semantics.
///
/// Pass `coherent_sn = Some(writer_sn)` when the writer is inside a
/// `Publisher::begin/end_coherent_changes` window so receivers can identify
/// which samples belong to the set; pass `group_sn = Some(gsn)` additionally
/// when the publisher access_scope is GROUP so the receiver can correlate
/// samples from multiple writers in the same Publisher.
pub fn build_data_packet_with_context_full(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
    version: CdrVersion,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
) -> Vec<u8> {
    build_data_packet_with_context_full_ts(
        ctx,
        topic,
        sequence,
        payload,
        version,
        now_rtps_timestamp(),
        coherent_sn,
        group_sn,
    )
}

/// Same as [`build_data_packet_with_context_full`] but takes the wire
/// INFO_TS as an explicit input; see
/// [`build_data_packet_with_context_ts`] for the rationale.
#[allow(clippy::too_many_arguments)]
pub fn build_data_packet_with_context_full_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
    version: CdrVersion,
    source_ts: (u32, u32),
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
) -> Vec<u8> {
    build_data_packet_with_context_full_keyed_ts(
        ctx,
        topic,
        sequence,
        payload,
        version,
        source_ts,
        coherent_sn,
        group_sn,
        None,
        false,
    )
}

/// Same as [`build_data_packet_with_context_full`] but accepts an
/// `Option<&[u8; 16]>` `key_hash` to emit as `PID_KEY_HASH` (0x0070) in
/// the inline QoS. Required for cross-vendor instance addressing by the
/// MD5 key hash (RTPS v2.5 Sec.9.6.4.8); the existing 9-argument helper keeps
/// non-keyed call sites
/// unchanged.
#[allow(clippy::too_many_arguments)]
pub fn build_data_packet_with_context_full_keyed(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
    version: CdrVersion,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    key_hash: Option<&[u8; 16]>,
) -> Vec<u8> {
    build_data_packet_with_context_full_keyed_ts(
        ctx,
        topic,
        sequence,
        payload,
        version,
        now_rtps_timestamp(),
        coherent_sn,
        group_sn,
        key_hash,
        // No sealing state to report: this entry point (and everything
        // above it in the delegation chain) is never fed an already-sealed
        // payload -- the live write() path that can calls the `_ts`
        // variant below directly with its own `sealed` flag.
        false,
    )
}

/// Same as [`build_data_packet_with_context_full_keyed`] but takes the
/// wire INFO_TS as an explicit input instead of reading the clock
/// internally, and `sealed` instead of hardcoding "never sealed". This is
/// the REAL implementation every other `build_data_packet_with_context*`
/// variant above delegates to (with `now_rtps_timestamp()` captured once
/// for callers that don't have a journaled timestamp to replay); see
/// [`build_data_packet_with_context_ts`] for the repair-fidelity
/// rationale.
#[allow(clippy::too_many_arguments)]
pub fn build_data_packet_with_context_full_keyed_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
    version: CdrVersion,
    source_ts: (u32, u32),
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    key_hash: Option<&[u8; 16]>,
    sealed: bool,
) -> Vec<u8> {
    build_data_packet_grouped_ts(
        ctx,
        topic,
        sequence,
        payload,
        version,
        source_ts,
        coherent_sn,
        group_sn,
        None,
        key_hash,
        sealed,
    )
}

/// [`build_data_packet_with_context_full_keyed_ts`] for a change of a
/// GROUP Publisher's writer: `group_tag` adds `PID_GROUP_SEQ_NUM` and
/// `PID_WRITER_GROUP_INFO` (RTPS v2.5 Sec.8.7.5, Sec.9.6.4.4-5, D5/D10).
///
/// `sealed`: whether `payload` was already produced by
/// `security::crypto::user_data::encode_serialized_payload` -- the writer's own
/// record (`DataWriter::seal_payload_for_wire`'s return, or the journaled
/// `ChangeMetadata::key_epoch` on a repair/replay path), passed straight to
/// [`encapsulate_serialized_payload`]. See that function's doc for why this
/// must never be re-derived from `payload`'s bytes.
#[allow(clippy::too_many_arguments)]
pub fn build_data_packet_grouped_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
    version: CdrVersion,
    source_ts: (u32, u32),
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    group_tag: Option<&crate::protocol::group::GroupTag>,
    key_hash: Option<&[u8; 16]>,
    sealed: bool,
) -> Vec<u8> {
    let encapsulated_payload = encapsulate_serialized_payload(
        encap_kind_for_version(ctx.encapsulation_kind, version),
        payload,
        sealed,
    );

    // Build inline QoS with topic name for cross-process routing.
    // Without this, the router has to rely on GUID-based routing which requires
    // SEDP to have registered the writer first -- a race condition.
    //
    // PID_ORIGINAL_WRITER_INFO (0x0061) is deliberately NOT emitted here.
    // RTPS v2.5 Sec.8.7.9: readers may treat DATAs carrying the same
    // (originalWriterGUID, originalWriterSN) pair as duplicates of one
    // virtual sample. Stamping every member of a coherent set with a
    // CONSTANT virtual SN (set-first SN, or GSN under GROUP scope) would
    // let a reader applying that rule collapse the members of each set
    // into a single delivered sample. Members carry only PID_COHERENT_SET
    // [+ TOPIC_NAME / KEY_HASH]; coherent delivery (RTPS v2.5 Sec.8.7.6)
    // does not need 0x0061, and the HDDS self reader never parses 0x0061
    // at all.
    //
    // PID_GROUP_ENTITY_ID (0x0053) is emitted ONLY under GROUP-scope
    // coherence (group_sn tagged). GROUP subscribers bucket sets per
    // (participant_prefix, publisher_entity_id, GSN) so two Publishers in
    // the same Participant cannot alias on the same GSN. TOPIC/INSTANCE
    // members must NOT carry it: the PID only has meaning for a
    // GROUP-scope set, and the HDDS self reader only consumes it on the
    // GROUP branch (extract_group_entity_id -> stage_group_sample). The
    // value is the writer's Publisher (`ctx.publisher_entity_id`), the one
    // its SEDP announcement names in PID_GROUP_ENTITY_ID / PID_GROUP_GUID:
    // two Publishers of one participant are told apart.
    let publisher_entity_id = group_sn.map(|_| ctx.publisher_entity_id);
    let inline_qos = super::helpers::build_inline_qos_grouped(
        topic,
        coherent_sn,
        group_sn,
        publisher_entity_id,
        group_tag,
        key_hash,
    );
    if inline_qos.is_empty() {
        return Vec::new();
    }

    // DATA submessage body: extraFlags(2) + octetsToInlineQos(2) + entityIds(8) + seq(8)
    //                       + inline_qos + payload
    let submsg_body_len = 20 + inline_qos.len() + encapsulated_payload.len();
    let Some(octets_to_next) = data_body_octets(submsg_body_len) else {
        return Vec::new();
    };

    // INFO_TS carries the writer's source_timestamp. RTPS v2.5 sec. 8.3.8.11 + sec. 8.7.2.2.5:
    // without it, source_timestamp is TIME_INVALID and lifespan filtering is undefined.
    // Readers need it to compute per-sample expiry under the LIFESPAN QoS policy.
    //
    // source_ts is a caller-supplied INPUT, not a fresh clock read: the
    // write() site captures it once (runtime.rs) and journals it
    // alongside the change, so a cold repair can replay the SAME value
    // and reproduce the live wire bytes byte-for-byte instead of
    // re-stamping (see build_data_packet_with_context_ts).
    let (ts_sec, ts_frac) = source_ts;
    let info_ts = encode_info_ts(ts_sec, ts_frac);

    // Build RTPS header (20 bytes) + INFO_TS (12 bytes) + DATA submessage
    let mut packet = Vec::with_capacity(20 + info_ts.len() + 4 + submsg_body_len);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);

    // INFO_TS submessage (12 bytes) -- applies to subsequent submessages in this packet
    packet.extend_from_slice(&info_ts);

    // DATA submessage header (4 bytes)
    packet.push(0x15); // DATA submessage ID
    packet.push(0x07); // Flags: LE=1 + InlineQoS=1 + Data=1
    packet.extend_from_slice(&octets_to_next.to_le_bytes());

    // extraFlags + octetsToInlineQos
    packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos (standard: 16)

    // Reader/Writer entity IDs
    packet.extend_from_slice(&ctx.reader_entity_id);
    packet.extend_from_slice(&ctx.writer_entity_id);

    // Sequence number (SequenceNumber_t = high:i32 + low:u32)
    packet.extend_from_slice(&sequence_number_le_bytes(sequence));

    // Inline QoS (PID_TOPIC_NAME [+ PID_COHERENT_SET] [+ PID_GROUP_COHERENT_SET_HDDS] + PID_SENTINEL)
    packet.extend_from_slice(&inline_qos);

    // Serialized payload
    packet.extend_from_slice(&encapsulated_payload);

    packet
}

/// Build an End-of-Coherent-Set (ECS) DATA submessage per RTPS v2.5 sec. 8.7.5.
///
/// The ECS is a DATA submessage with `D=0 K=0 Q=1` (no payload, inline QoS
/// only). Inline QoS carries:
/// * `PID_TOPIC_NAME` for routing
/// * `PID_COHERENT_SET` = the writer's last sample SN in the set
///   (writer-scoped close marker)
/// * `PID_GROUP_COHERENT_SET_HDDS` (0x8030, HDDS vendor-specific) = the
///   Publisher GSN being closed (only when the publisher access_scope is
///   GROUP)
/// * `PID_SENTINEL`
///
/// The ECS submessage consumes the writer's next sequence number (`sequence`)
/// so it participates in the reliable retransmit protocol (HEARTBEAT /
/// ACKNACK) like any other DATA. Receivers that match GROUP-scope
/// coherent_access flush their per-(writer, gsn) buffer on ECS arrival; this
/// is what releases a buffered coherent set at the reader.
///
/// Live emission is `dds::writer::coherent::dispatch_ecs` (HDDS-reader
/// branch); the NACK repair path (`dds::writer::nack::build_ecs_repair_packet`)
/// rebuilds a NACKed close slot with this same builder for HDDS readers so
/// repairs keep the live wire form. The wire shape (ids, flags,
/// octetsToNextHeader, PIDs) is frozen by
/// `tests::ecs_data_submessage_group_scope_shape`.
pub fn build_ecs_data_submessage(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    coherent_sn: u64,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
) -> Vec<u8> {
    build_ecs_data_submessage_ts(
        ctx,
        topic,
        sequence,
        coherent_sn,
        group_sn,
        publisher_entity_id,
        now_rtps_timestamp(),
    )
}

/// Same as [`build_ecs_data_submessage`] but takes the wire INFO_TS as an
/// explicit input. The live ECS emission (`dds::writer::coherent::
/// WriterCoherentBridge::emit_ecs_data`) captures one timestamp and both
/// builds the live packet AND journals it via
/// `HistoryCache::insert_with_metadata`; the NACK repair path
/// (`dds::writer::nack::build_ecs_repair_packet`) replays that journaled
/// `source_ts` here instead of stamping a fresh one.
#[allow(clippy::too_many_arguments)]
pub fn build_ecs_data_submessage_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    coherent_sn: u64,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    source_ts: (u32, u32),
) -> Vec<u8> {
    // Sample count of 1 covers single-sample coherent sets and their
    // auto-default count=1 siblings. Multi-sample sets pass the
    // real count via build_ecs_data_submessage_count.
    build_ecs_data_submessage_count_ts(
        ctx,
        topic,
        sequence,
        coherent_sn,
        group_sn,
        publisher_entity_id,
        1,
        source_ts,
    )
}

/// Same as [`build_ecs_data_submessage`] but lets the caller pass the
/// explicit `sample_count` for the closed set. Required when the writer
/// emitted more than one sample inside the begin/end_coherent_changes
/// window (multi-sample coherent sets, `--coherent-sample-count > 1`).
#[allow(clippy::too_many_arguments)]
pub fn build_ecs_data_submessage_count(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    coherent_sn: u64,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    sample_count: u32,
) -> Vec<u8> {
    build_ecs_data_submessage_count_ts(
        ctx,
        topic,
        sequence,
        coherent_sn,
        group_sn,
        publisher_entity_id,
        sample_count,
        now_rtps_timestamp(),
    )
}

/// Same as [`build_ecs_data_submessage_count`] but takes the wire
/// INFO_TS as an explicit input; see [`build_ecs_data_submessage_ts`]
/// for the rationale.
#[allow(clippy::too_many_arguments)]
pub fn build_ecs_data_submessage_count_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    coherent_sn: u64,
    group_sn: Option<u64>,
    publisher_entity_id: Option<[u8; 4]>,
    sample_count: u32,
    source_ts: (u32, u32),
) -> Vec<u8> {
    // No PID_ORIGINAL_WRITER_INFO (0x0061) on the ECS marker either: the
    // marker is already attributed to the closing writer by its RTPS
    // writerId + writerSN, and receivers applying the RTPS v2.5 8.7.6
    // duplicate rule to a constant (GUID, virtualSN) pair would collapse
    // markers. The HDDS self reader commits via on_ecs off
    // PID_COHERENT_SET alone and never parses 0x0061.
    let inline_qos = build_inline_qos_for_ecs(
        topic,
        coherent_sn,
        group_sn,
        publisher_entity_id,
        sample_count,
    );
    ecs_packet(ctx, sequence, &inline_qos, source_ts)
}

/// The end of a group coherent set in the RTPS v2.5 GROUP form, the one a
/// reader of the spec class receives (Sec.8.7.6, Table 9.23, D18): no
/// payload; `PID_COHERENT_SET` = the writer's first SN in the set, or the
/// end of set's own SN when it wrote none (`tag.part_first_sn`, D6);
/// `PID_GROUP_COHERENT_SET` (0x0063) = the set's first GSN;
/// `PID_GROUP_SEQ_NUM` = the last GSN of the set
/// plus one, shared by every writer's end of the set (D2);
/// `PID_WRITER_GROUP_INFO` = the Publisher's writerSet. No
/// `PID_GROUP_ENTITY_ID`: an SEDP parameter, not an inline QoS one (G11).
pub fn build_ecs_spec_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    tag: &crate::protocol::group::GroupTag,
    source_ts: (u32, u32),
) -> Vec<u8> {
    let mut qos = Vec::with_capacity(96);
    if !super::helpers::append_pid_topic_name(&mut qos, topic) {
        return Vec::new();
    }
    super::helpers::append_pid_coherent_set(&mut qos, tag.part_first_sn.unwrap_or(sequence));
    if let Some(first) = tag.set_first_gsn {
        super::helpers::append_pid_spec_group_coherent_set(&mut qos, first);
    }
    super::helpers::append_group_tag(&mut qos, tag);
    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());
    ecs_packet(ctx, sequence, &qos, source_ts)
}

/// An end-of-set DATA (D=0 K=0 Q=1, no payload) carrying `inline_qos`.
fn ecs_packet(
    ctx: &RtpsEndpointContext,
    sequence: u64,
    inline_qos: &[u8],
    source_ts: (u32, u32),
) -> Vec<u8> {
    if inline_qos.is_empty() {
        return Vec::new();
    }

    // DATA submessage body without payload: extraFlags(2) + octetsToInlineQos(2)
    //                                     + entityIds(8) + seq(8) + inline_qos
    let submsg_body_len = 20 + inline_qos.len();
    let Some(octets_to_next) = data_body_octets(submsg_body_len) else {
        return Vec::new();
    };

    let (ts_sec, ts_frac) = source_ts;
    let info_ts = encode_info_ts(ts_sec, ts_frac);

    let mut packet = Vec::with_capacity(20 + info_ts.len() + 4 + submsg_body_len);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);

    packet.extend_from_slice(&info_ts);

    // DATA submessage header (4 bytes)
    packet.push(0x15);
    // Flags: LE=1 + InlineQoS=1, Data=0, Key=0 (ECS marker, no payload).
    packet.push(0x03);
    packet.extend_from_slice(&octets_to_next.to_le_bytes());

    packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos

    packet.extend_from_slice(&ctx.reader_entity_id);
    packet.extend_from_slice(&ctx.writer_entity_id);

    packet.extend_from_slice(&sequence_number_le_bytes(sequence));

    packet.extend_from_slice(inline_qos);

    packet
}

/// Build a classic-model coherent-set close marker: a bare DATA submessage
/// (`D=0 K=0 Q=0`, no payload, no inline QoS) addressed to one reader.
///
/// This is the set-end form RTPS v2.5 Sec.8.7.6 defines: a real DATA
/// submessage on the writer's SN stream that carries NO `PID_COHERENT_SET`
/// ends the writer's open coherent set. A subscriber that follows that rule
/// reads the untagged sample as "the currently-open coherent set is now
/// closed" and releases the set to the application. Because it is a real DATA it also
/// fills the writer SN contiguously (no hole, so the RELIABLE reader never
/// stalls NACKing the slot) -- unlike a GAP, which retires the SN but does not
/// signal set-close, and unlike the HDDS-native ECS marker, which carries a
/// distinct `PID_COHERENT_SET` value the classic collator mistakes for a
/// phantom singleton set.
///
/// Emitted on the per-reader classic-vendor branch of `dispatch_ecs` (live
/// close path) and rebuilt with this same builder by the NACK repair path
/// (`dds::writer::nack::build_ecs_repair_packet`) when a classic reader NACKs
/// a close slot, so repairs keep the live wire form. HDDS-self readers still
/// receive the real ECS DATA (with `PID_COHERENT_SET`) they need to commit
/// via `on_ecs`. The wire shape (56 bytes: header + INFO_TS + one bare DATA,
/// no inline QoS, no payload) is frozen by
/// `tests::ecs_close_marker_shape_is_bare_data`.
pub fn build_ecs_close_marker(
    ctx: &RtpsEndpointContext,
    reader_entity_id: &[u8; 4],
    seq: u64,
) -> Vec<u8> {
    build_ecs_close_marker_ts(ctx, reader_entity_id, seq, now_rtps_timestamp())
}

/// Same as [`build_ecs_close_marker`] but takes the wire INFO_TS as an
/// explicit input; see [`build_ecs_data_submessage_ts`] for the
/// repair-fidelity rationale (the classic-vendor close-marker leg of
/// `dds::writer::nack::build_ecs_repair_packet` replays the journaled
/// `source_ts` here too).
pub fn build_ecs_close_marker_ts(
    ctx: &RtpsEndpointContext,
    reader_entity_id: &[u8; 4],
    seq: u64,
    source_ts: (u32, u32),
) -> Vec<u8> {
    // Bare DATA body: extraFlags(2) + octetsToInlineQos(2) + entityIds(8)
    //               + seq(8) = 20. No inline QoS (Q=0), no payload (D=0).
    const DATA_BODY_LEN: u16 = 20;

    let (ts_sec, ts_frac) = source_ts;
    let info_ts = encode_info_ts(ts_sec, ts_frac);

    let mut packet = Vec::with_capacity(20 + info_ts.len() + 4 + DATA_BODY_LEN as usize);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);

    packet.extend_from_slice(&info_ts);

    // DATA submessage header: id=0x15, flags=LE only (0x01 -> D=0 K=0 Q=0).
    packet.push(0x15);
    packet.push(0x01);
    packet.extend_from_slice(&DATA_BODY_LEN.to_le_bytes());

    packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos

    packet.extend_from_slice(reader_entity_id);
    packet.extend_from_slice(&ctx.writer_entity_id);

    packet.extend_from_slice(&sequence_number_le_bytes(seq));

    packet
}

/// Downgrade a fully-built RTPS DATA packet's user-data encapsulation kind
/// from `D_CDR2_LE` (0x0009, delimited CDR2) to `PLAIN_CDR2_LE` (0x0007,
/// plain CDR2) in place, flipping ONLY the 2 encapsulation-kind bytes.
///
/// Everything else (RTPS header, INFO_TS / INFO_DST submessages, the DATA
/// submessage framing, the inline QoS, the DHEADER, and the serialized
/// payload body) is left byte-for-byte identical. HDDS applies it only to
/// readers whose dialect, resolved once at pairing, takes the plain CDR2
/// kind 0x0007 with the DHEADER kept in the body (the zzdds dialect).
///
/// The encapsulation kind is stored big-endian on the wire (matching the
/// `wire_encap.to_be_bytes()` emission in the DATA builders above), so the
/// kind bytes are `00 09` for D_CDR2_LE and become `00 07` for PLAIN_CDR2_LE.
///
/// # Returns
///
/// * `true` if a DATA submessage was found and its encapsulation kind was
///   `00 09` and has been overwritten with `00 07`.
/// * `false` if the packet is malformed, too short, contains no DATA
///   submessage, or the encapsulation kind was not `00 09`. In every
///   `false` case the packet is left completely unmodified.
///
/// This function never panics and never indexes out of bounds: every read
/// and write is bounds-checked.
pub fn downgrade_data_encap_to_plain_cdr2(packet: &mut [u8]) -> bool {
    const RTPS_HEADER_LEN: usize = 20;
    const SUBMSG_HEADER_LEN: usize = 4;
    const DATA_SUBMSG_ID: u8 = 0x15;
    const FLAG_ENDIANNESS: u8 = 0x01; // bit 0: little-endian when set
    const FLAG_INLINE_QOS: u8 = 0x02; // bit 1: Q flag
    const PID_SENTINEL: u16 = 0x0001;

    // A valid packet must at least contain the RTPS header plus one
    // submessage header.
    if packet.len() < RTPS_HEADER_LEN + SUBMSG_HEADER_LEN {
        return false;
    }

    // Walk submessages starting right after the 20-byte RTPS header.
    let mut offset = RTPS_HEADER_LEN;
    while offset + SUBMSG_HEADER_LEN <= packet.len() {
        let submsg_id = packet[offset];
        let flags = packet[offset + 1];
        let little_endian = (flags & FLAG_ENDIANNESS) != 0;

        // octetsToNextHeader is a u16 whose endianness follows the
        // submessage's own E flag (RTPS v2.5 Sec.8.3.3.3).
        let len_lo = packet[offset + 2];
        let len_hi = packet[offset + 3];
        let octets_to_next = if little_endian {
            u16::from_le_bytes([len_lo, len_hi]) as usize
        } else {
            u16::from_be_bytes([len_lo, len_hi]) as usize
        };

        let body_start = offset + SUBMSG_HEADER_LEN;

        // octetsToNextHeader == 0 means "to the end of the message"
        // (RTPS v2.5 Sec.8.3.3.3.3).
        let body_end = if octets_to_next == 0 {
            packet.len()
        } else {
            body_start.saturating_add(octets_to_next)
        };

        // A declared length that runs past the buffer is malformed.
        if body_end > packet.len() || body_end < body_start {
            return false;
        }

        if submsg_id == DATA_SUBMSG_ID {
            return downgrade_data_submsg_body(
                packet,
                body_start,
                body_end,
                little_endian,
                (flags & FLAG_INLINE_QOS) != 0,
                PID_SENTINEL,
            );
        }

        // Not the DATA submessage; advance. A zero-length non-DATA
        // submessage would loop forever, so bail out.
        if octets_to_next == 0 {
            return false;
        }
        offset = body_end;
    }

    false
}

/// Locate the serializedData start within a DATA submessage body and, if its
/// encapsulation kind is `00 09` (D_CDR2_LE), overwrite it with `00 07`
/// (PLAIN_CDR2_LE). Returns `true` on a successful flip, `false` otherwise.
///
/// `body_start`/`body_end` bound the DATA submessage body (everything after
/// the 4-byte submessage header). All accesses are bounds-checked against
/// `body_end` and `packet.len()`.
fn downgrade_data_submsg_body(
    packet: &mut [u8],
    body_start: usize,
    body_end: usize,
    little_endian: bool,
    q_flag: bool,
    pid_sentinel: u16,
) -> bool {
    // DATA body: extraFlags(2) + octetsToInlineQos(2) + readerId(4) +
    // writerId(4) + writerSN(8) [+ inlineQoS if Q] + serializedData.
    // Need at least extraFlags + octetsToInlineQos.
    if body_start + 4 > body_end {
        return false;
    }

    let oti_lo = packet[body_start + 2];
    let oti_hi = packet[body_start + 3];
    let octets_to_inline_qos = if little_endian {
        u16::from_le_bytes([oti_lo, oti_hi]) as usize
    } else {
        u16::from_be_bytes([oti_lo, oti_hi]) as usize
    };

    // start = byte right after octetsToInlineQos + octetsToInlineQos.
    // (octetsToInlineQos counts from the byte after itself, normally 16 =
    // readerId + writerId + writerSN.)
    let mut start = match (body_start + 4).checked_add(octets_to_inline_qos) {
        Some(s) => s,
        None => return false,
    };

    if q_flag {
        // `start` currently points at the inline QoS list. Walk PID params
        // (id u16 + len u16 + value[len]) until PID_SENTINEL, then move past
        // it; serializedData begins right after the sentinel's value.
        loop {
            // Need id(2) + len(2).
            if start + 4 > body_end {
                return false;
            }
            let id = if little_endian {
                u16::from_le_bytes([packet[start], packet[start + 1]])
            } else {
                u16::from_be_bytes([packet[start], packet[start + 1]])
            };
            let plen = if little_endian {
                u16::from_le_bytes([packet[start + 2], packet[start + 3]]) as usize
            } else {
                u16::from_be_bytes([packet[start + 2], packet[start + 3]]) as usize
            };

            // RTPS ParameterList values are padded to a 4-byte boundary
            // (DDS-RTPS v2.5 Sec.9.4.2.11). Advance by the aligned length so the
            // walk stays in sync even if a peer reports an unaligned value len
            // PID_SENTINEL carries plen==0, so alignment is a
            // no-op for it.
            let plen_aligned = (plen + 3) & !3;
            let next = match start
                .checked_add(4)
                .and_then(|v| v.checked_add(plen_aligned))
            {
                Some(n) => n,
                None => return false,
            };
            if next > body_end {
                return false;
            }
            start = next;

            if id == pid_sentinel {
                // serializedData starts right after the sentinel param.
                break;
            }
        }
    }

    // serializedData begins at `start`: 2 bytes encapsulation kind.
    if start + 2 > body_end || start + 2 > packet.len() {
        return false;
    }

    // On-wire encapsulation kind is big-endian: D_CDR2_LE == 0x0009 -> 00 09.
    if packet[start] == 0x00 && packet[start + 1] == 0x09 {
        packet[start + 1] = 0x07; // 00 09 -> 00 07 (PLAIN_CDR2_LE)
        return true;
    }

    false
}

/// Prepend an 8-byte HEADER_EXTENSION submessage immediately after the 20-byte
/// RTPS header of a fully-built outgoing packet (RTPS v2.5 Sec.9.4.5.15):
///
/// ```text
/// [id=0x00][flags=0x03 (E + MessageLength)][octetsToNextHeader=4 LE][u32 message_length LE]
/// ```
///
/// `message_length` carries the octet length of the entire resulting RTPS
/// message (header + all submessages), per the HeaderExtension MessageLength
/// member.
///
/// HDDS adds it only for readers whose dialect, resolved once at pairing,
/// is the InterCOM DDS dialect (vendorId 0x0105); those readers get every
/// user DATA with a leading HEADER_EXTENSION. This helper is applied per-reader
/// on the cold (discovery-resolved) path in `send_packet_to_endpoints`, so
/// non-InterCOM peers and the self path stay byte-identical.
///
/// Inserting after the RTPS header keeps every DATA-submessage offset patcher
/// correct: callers MUST apply the per-reader `readerEntityId` patch (at
/// [`READER_ENTITY_ID_OFFSET`]) BEFORE calling this, because afterwards the
/// DATA submessage is shifted by 8 bytes. `find_data_submsg_offset` already
/// skips a leading HEADER_EXTENSION on receive.
///
/// Returns the packet unchanged if it is too short to contain an RTPS header,
/// or too long for the 32-bit MessageLength member to describe.
pub fn prepend_header_extension(packet: &[u8]) -> Vec<u8> {
    const RTPS_HEADER_LEN: usize = 20;
    const HEADER_EXT_LEN: usize = 8;
    if packet.len() < RTPS_HEADER_LEN {
        return packet.to_vec();
    }
    let total_len = packet.len() + HEADER_EXT_LEN;
    let Ok(message_length) = u32::try_from(total_len) else {
        return packet.to_vec();
    };
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&packet[..RTPS_HEADER_LEN]);
    // HEADER_EXTENSION submessage header: id=0x00, flags=0x03
    // (E=little-endian + MessageLength present), octetsToNextHeader=4 (LE u16).
    out.push(RTPS_SUBMSG_HEADER_EXTENSION);
    out.push(0x03);
    out.extend_from_slice(&4u16.to_le_bytes());
    // MessageLength member: total octets of the resulting RTPS message (LE u32).
    out.extend_from_slice(&message_length.to_le_bytes());
    out.extend_from_slice(&packet[RTPS_HEADER_LEN..]);
    out
}

// =============================================================================
// DATA_FRAG: Automatic Fragmentation for Large Payloads
// =============================================================================

/// Default fragment size for DATA_FRAG (bytes)
///
/// RTPS overhead: header (20) + DATA_FRAG header (36) + encapsulation (4) = 60 bytes
/// UDP MTU 1500 - 60 = 1440 usable, use 1024 for alignment and compatibility.
///
/// Keep this MTU-sized. With 64 KB fragments (one datagram per fragment,
/// kernel IP fragmentation) a receiver socket buffer holds only a few
/// datagrams, so a burst overflows it and the HEARTBEATs sharing that socket
/// are lost with the data. At 1024 each fragment is one unfragmented UDP
/// datagram, and burst holes are recovered through NACK_FRAG (see the
/// compound-packet parsing in the multicast listener and the truncation fix
/// in ControlMessage).
pub const DEFAULT_FRAGMENT_SIZE: usize = 1024;

/// Maximum payload size before automatic fragmentation (bytes)
///
/// Payloads <= this size use single DATA submessage.
/// Payloads > this size are fragmented into DATA_FRAG submessages.
pub const DEFAULT_MAX_UNFRAGMENTED_SIZE: usize = 8192;

/// Build fragmented DATA_FRAG packets for large payloads.
///
/// When a payload exceeds `DEFAULT_MAX_UNFRAGMENTED_SIZE`, this function
/// splits it into multiple DATA_FRAG submessages, each containing at most
/// `fragment_size` bytes of payload data.
///
/// # Arguments
///
/// * `ctx` - RTPS endpoint context (GUID prefix, entity IDs)
/// * `sequence` - Sequence number for this sample
/// * `payload` - Full payload to fragment (already CDR-encoded)
/// * `fragment_size` - Size of each fragment (default: 1024)
///
/// # Returns
///
/// Vector of RTPS packets, each containing one DATA_FRAG submessage.
/// If payload fits in a single DATA (<=8KB), returns empty vector.
///
/// # Example
///
/// ```ignore
/// let payload = vec![0u8; 50000]; // 50KB payload
/// let packets = build_data_frag_packets(&ctx, seq, &payload, 1024);
/// assert_eq!(packets.len(), 49); // 50000 / 1024 = 49 fragments
/// for packet in packets {
///     transport.send(&packet)?;
/// }
/// ```
pub fn build_data_frag_packets(
    ctx: &RtpsEndpointContext,
    sequence: u64,
    payload: &[u8],
    fragment_size: usize,
    version: CdrVersion,
) -> Vec<Vec<u8>> {
    // NOT used by the live write() path (dds::writer::runtime::DataWriter::
    // write): that path calls build_data_frag_packets_ts with ONE timestamp
    // captured before fragmenting, so every fragment of a sample carries the
    // SAME INFO_TS (RTPS v2.5 SS8.3.8.11 defines one source timestamp PER
    // SAMPLE, not per fragment). This fresh-clock-per-fragment variant
    // remains for callers with no single sample-level timestamp to give
    // (e.g. `protocol::builder::tests`) and as the base every fragment's
    // structure is built from (see build_data_frag_packets_inner). Never
    // fed an already-sealed payload, so `sealed` is hardcoded false.
    build_data_frag_packets_inner(ctx, sequence, payload, fragment_size, version, None, false)
}

/// Same as [`build_data_frag_packets`] but stamps every fragment's
/// INFO_TS with the SAME caller-supplied `source_ts` instead of a fresh
/// clock read per fragment, and takes `sealed` instead of hardcoding
/// "never sealed".
///
/// This IS the live write() path since the item-4 fix
/// (`dds::writer::runtime::DataWriter::write`'s DATA_FRAG branch captures
/// one `now_rtps_timestamp()` and passes it here), and it is also what
/// `nack.rs::on_nack` and `runtime.rs::replay_to` replay from the
/// journaled `ChangeMetadata::source_ts` -- so a repaired or replayed
/// fragmented sample reproduces the live INFO_TS exactly, the same
/// guarantee the non-fragmented DATA path already had. This covers the
/// timestamp only: the per-reader readerEntityId patch is applied
/// separately by every DATA_FRAG leg via
/// `dds::writer::runtime::finalize_for_reader(.., fragmented: true)`,
/// which -- unlike the non-fragmented path -- withholds the zzdds/InterCOM
/// vendor transforms on every fragmented leg (see that function's doc).
///
/// `sealed`: as for [`build_data_packet_grouped_ts`] -- the writer's own
/// record of whether `payload` is already a sealed blob, carried to
/// [`encapsulate_serialized_payload`], never re-derived from the bytes.
pub fn build_data_frag_packets_ts(
    ctx: &RtpsEndpointContext,
    sequence: u64,
    payload: &[u8],
    fragment_size: usize,
    version: CdrVersion,
    source_ts: (u32, u32),
    sealed: bool,
) -> Vec<Vec<u8>> {
    build_data_frag_packets_inner(
        ctx,
        sequence,
        payload,
        fragment_size,
        version,
        Some(source_ts),
        sealed,
    )
}

fn build_data_frag_packets_inner(
    ctx: &RtpsEndpointContext,
    sequence: u64,
    payload: &[u8],
    fragment_size: usize,
    version: CdrVersion,
    fixed_source_ts: Option<(u32, u32)>,
    sealed: bool,
) -> Vec<Vec<u8>> {
    // Prepend the CDR encapsulation header (4 bytes) like the non-fragmented
    // DATA path does. The encapsulation is part of the serialized sample, so
    // it must appear once at the start of fragment 1 (DDSI-RTPS 2.5
    // Sec.10.2): a reader takes the first 4 bytes of the reassembled sample
    // as the encapsulation header, so without it the sample cannot be
    // deserialized.
    // The padding and its count are those of the whole sample: the options
    // travel in fragment 1, the padding at the end of the last fragment.
    let encapsulated = encapsulate_serialized_payload(
        encap_kind_for_version(ctx.encapsulation_kind, version),
        payload,
        sealed,
    );

    let total_size = encapsulated.len();

    // Don't fragment small payloads
    if total_size <= DEFAULT_MAX_UNFRAGMENTED_SIZE {
        return Vec::new();
    }

    let num_fragments = total_size.div_ceil(fragment_size);
    let mut packets = Vec::with_capacity(num_fragments);

    // DATA_FRAG carries fragmentSize as a u16 and sampleSize as a u32 (RTPS
    // v2.5 Sec.9.4.5.4). A value that does not fit is refused, not clamped:
    // announcing a smaller fragmentSize than the slices actually carry would
    // corrupt every reassembly on the receive side.
    let Ok(fragment_size_u16) = u16::try_from(fragment_size) else {
        log::error!(
            "[builder] fragment_size {} exceeds DATA_FRAG fragmentSize (u16); sample not fragmented",
            fragment_size
        );
        return Vec::new();
    };
    let Ok(total_size_u32) = u32::try_from(total_size) else {
        log::error!(
            "[builder] sample of {} octets exceeds DATA_FRAG sampleSize (u32); sample not fragmented",
            total_size
        );
        return Vec::new();
    };

    // Fragment numbering starts at 1 per RTPS spec. There are at most
    // `total_size` fragments and total_size fits a u32 (checked above), so
    // the counter cannot wrap before the last fragment; the saturating step
    // only guards the increment that follows the final one.
    let mut frag_starting_num: u32 = 1;
    for frag_data in encapsulated.chunks(fragment_size) {
        // fixed_source_ts is None on the live path (build_data_frag_packets):
        // each fragment reads its own fresh timestamp. It is Some(..) only on the repair path
        // (build_data_frag_packets_ts): every fragment gets the SAME
        // journaled timestamp instead.
        let Some(packet) = build_single_data_frag_packet(
            ctx,
            sequence,
            frag_starting_num,
            1, // fragments_in_submessage: we send 1 fragment per packet
            fragment_size_u16,
            total_size_u32,
            frag_data,
            fixed_source_ts.unwrap_or_else(now_rtps_timestamp),
        ) else {
            // One fragment that cannot be framed means the sample cannot be
            // sent: an EMPTY list is this file's "build failed", and the
            // writer reports it. Sending the failed fragment as an RTPS header
            // plus INFO_TS with no DATA_FRAG behind it, inside a full list,
            // would make the writer report success while the reader never
            // reassembles and never learns why.
            log::error!(
                "[builder] DATA_FRAG #{} of seq {} does not fit octetsToNextHeader \
                 (fragment_size {}); sample not sent",
                frag_starting_num,
                sequence,
                fragment_size
            );
            return Vec::new();
        };
        packets.push(packet);
        frag_starting_num = frag_starting_num.saturating_add(1);
    }

    packets
}

/// The inline QoS of a DATA_FRAG change (RTPS v2.5 Sec.8.7.6 for coherent
/// tags, Sec.9.4.5.4/9.6.4.8 for KeyHash). Sec.9.4.5.4 carries it in the form
/// a DATA of the same change carries it (`build_data_packet_grouped_ts`):
/// `group_tag` gives the spec GROUP form, its absence today's. Empty for a
/// unkeyed change of no set and no GROUP Publisher.
pub fn data_frag_inline_qos(
    ctx: &RtpsEndpointContext,
    topic: &str,
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    group_tag: Option<&crate::protocol::group::GroupTag>,
    key_hash: Option<&[u8; 16]>,
) -> Vec<u8> {
    if coherent_sn.is_none() && group_sn.is_none() && group_tag.is_none() && key_hash.is_none() {
        return Vec::new();
    }
    let publisher_entity_id = group_sn.map(|_| ctx.publisher_entity_id);
    super::helpers::build_inline_qos_grouped(
        topic,
        coherent_sn,
        group_sn,
        publisher_entity_id,
        group_tag,
        key_hash,
    )
}

/// Put `inline_qos` in the first of the DATA_FRAG `packets` (each an RTPS
/// header, an INFO_TS and one DATA_FRAG, as `build_data_frag_packets_ts`
/// builds them): its Q flag set, the parameter list between the fixed
/// fields and the fragment (RTPS v2.5 Sec.9.4.5.4). The other fragments
/// carry none. Returns false, leaving the packets as they were, when the
/// first is not of that shape or the list would not fit the submessage.
pub fn put_inline_qos_in_first_fragment(packets: &mut [Vec<u8>], inline_qos: &[u8]) -> bool {
    // RTPS header 20, INFO_TS 12, then the DATA_FRAG submessage: its
    // header 4 and fixed fields 32 (extraFlags, octetsToInlineQos = 28,
    // readerId, writerId, writerSN, fragmentStartingNum,
    // fragmentsInSubmessage, fragmentSize, sampleSize).
    const SUBMESSAGE: usize = 32;
    const INLINE_QOS: usize = SUBMESSAGE + 4 + 32;
    let Some(first) = packets.first_mut() else {
        return false;
    };
    if first.len() < INLINE_QOS || first[SUBMESSAGE] != 0x16 || first[SUBMESSAGE + 1] & 0x01 == 0 {
        return false;
    }
    let body = usize::from(u16::from_le_bytes([
        first[SUBMESSAGE + 2],
        first[SUBMESSAGE + 3],
    ]));
    let Ok(grown) = u16::try_from(body + inline_qos.len()) else {
        return false;
    };
    first[SUBMESSAGE + 1] |= 0x02;
    first[SUBMESSAGE + 2..SUBMESSAGE + 4].copy_from_slice(&grown.to_le_bytes());
    first.splice(INLINE_QOS..INLINE_QOS, inline_qos.iter().copied());
    true
}

/// Build a single DATA_FRAG packet.
///
/// Internal helper for `build_data_frag_packets` /
/// `build_data_frag_packets_ts`.
#[allow(clippy::too_many_arguments)]
fn build_single_data_frag_packet(
    ctx: &RtpsEndpointContext,
    sequence: u64,
    fragment_starting_num: u32,
    fragments_in_submessage: u16,
    fragment_size: u16,
    data_size: u32,
    fragment_data: &[u8],
    source_ts: (u32, u32),
) -> Option<Vec<u8>> {
    let (ts_sec, ts_frac) = source_ts;
    let info_ts = encode_info_ts(ts_sec, ts_frac);

    // The submessage FIRST: if it cannot be framed there is no packet, not a
    // header with nothing behind it.
    let encoder = get_encoder(Dialect::Hybrid);
    let data_frag_submsg = encoder
        .build_data_frag(
            &ctx.reader_entity_id,
            &ctx.writer_entity_id,
            sequence,
            fragment_starting_num,
            fragments_in_submessage,
            data_size,
            fragment_size,
            fragment_data,
        )
        .ok()?;

    // Build RTPS header (20) + INFO_TS (12) + DATA_FRAG
    let mut packet = Vec::with_capacity(20 + info_ts.len() + data_frag_submsg.len());
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);
    packet.extend_from_slice(&info_ts);
    packet.extend_from_slice(&data_frag_submsg);
    Some(packet)
}

/// Check if payload should be fragmented.
///
/// Returns true if payload exceeds `DEFAULT_MAX_UNFRAGMENTED_SIZE`.
#[inline]
pub fn should_fragment(payload_len: usize) -> bool {
    payload_len > DEFAULT_MAX_UNFRAGMENTED_SIZE
}

// =============================================================================
// DISPOSE / UNREGISTER: Instance Lifecycle Packets
// =============================================================================

/// Build RTPS DATA packet for dispose or unregister (key-only, with StatusInfo).
///
/// DDS-RTPS Sec.9.6.4.9: A dispose/unregister sends a DATA submessage with:
/// - K flag set (bit 3) instead of D flag (bit 2)
/// - PID_KEY_HASH in inline QoS with the instance key hash
/// - PID_STATUS_INFO in inline QoS with DISPOSED/UNREGISTERED flags
/// - Serialized key as payload (CDR encapsulated key hash)
///
/// This is used by DataWriter::dispose() and DataWriter::unregister_instance().
/// Stamps INFO_TS with the current time and frames the key as XCDR2; see
/// [`build_dispose_packet_with_context_ts`] to reproduce a journaled one or
/// to frame it as XCDR1.
pub fn build_dispose_packet_with_context(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    key_hash: &[u8; 16],
    serialized_key: &[u8],
    status_info: super::helpers::StatusInfoKind,
) -> Vec<u8> {
    build_dispose_packet_with_context_ts(
        ctx,
        topic,
        sequence,
        key_hash,
        serialized_key,
        status_info,
        CdrVersion::Xcdr2,
        now_rtps_timestamp(),
    )
}

/// [`build_dispose_packet_with_context`] with the INFO_TS the change carried
/// when it was emitted live: a repaired or replayed dispose reproduces the
/// source timestamp of the original, exactly as a repaired sample does
/// (RTPS 2.5 8.3.8.11: one source timestamp per change). `version` is the
/// CDR version `serialized_key` was encoded with.
///
/// Delegates to [`build_dispose_packet_with_context_coherent_ts`] with no
/// coherent tags, so its bytes are unchanged from before that function
/// existed. Use the coherent variant directly for a lifecycle change
/// emitted while the writer's publisher has an open coherent set.
#[allow(clippy::too_many_arguments)]
pub fn build_dispose_packet_with_context_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    key_hash: &[u8; 16],
    serialized_key: &[u8],
    status_info: super::helpers::StatusInfoKind,
    version: CdrVersion,
    source_ts: (u32, u32),
) -> Vec<u8> {
    build_dispose_packet_with_context_coherent_ts(
        ctx,
        topic,
        sequence,
        key_hash,
        serialized_key,
        status_info,
        version,
        source_ts,
        None,
        None,
        None,
        // No sealing state to report: this entry point is never fed an
        // already-sealed key payload -- the live dispose/unregister path
        // (`DataWriter::emit_lifecycle_change`) calls the coherent variant
        // below directly with its own `sealed` flag.
        false,
    )
}

/// [`build_dispose_packet_with_context_ts`] plus the coherent-set tags
/// (RTPS v2.5 sec. 8.7.5/sec. 8.7.6) a dispose/unregister emitted while the
/// writer's publisher has an open coherent set must carry, exactly like a
/// member DATA sample does:
///
/// * `coherent_sn` -- `PID_COHERENT_SET` (0x0056), the set's first writer
///   SN.
/// * `group_sn` -- `PID_GROUP_COHERENT_SET_HDDS` (0x8030, HDDS
///   vendor-specific), present only under GROUP access_scope; when
///   present, `PID_GROUP_ENTITY_ID` (0x0053) is also carried, derived
///   exactly as `build_data_packet_with_context_full_keyed_ts` derives it
///   (see [`super::helpers::build_inline_qos_for_dispose_coherent`]).
///
/// `sealed`: whether `serialized_key` was already produced by
/// `security::crypto::user_data::encode_serialized_payload` -- the writer's own
/// record, carried to [`encapsulate_serialized_payload`]; see that
/// function's doc for why this must never be re-derived from the bytes.
///
/// Both `None` and `sealed = false` reproduces
/// [`build_dispose_packet_with_context_ts`]'s bytes exactly (that function
/// delegates here).
#[allow(clippy::too_many_arguments)]
pub fn build_dispose_packet_with_context_coherent_ts(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    key_hash: &[u8; 16],
    serialized_key: &[u8],
    status_info: super::helpers::StatusInfoKind,
    version: CdrVersion,
    source_ts: (u32, u32),
    coherent_sn: Option<u64>,
    group_sn: Option<u64>,
    group_tag: Option<&crate::protocol::group::GroupTag>,
    sealed: bool,
) -> Vec<u8> {
    use super::helpers::build_inline_qos_for_dispose_coherent;

    // Per RTPS v2.5 sec. 9.4.5.3.2: K-flag DATA payload is the serialized @key
    // fields wrapped in a CDR encapsulation header. Spec-strict peers parse
    // this and use it to reconstruct the dispose target. Fall back to an
    // empty payload when the caller could not supply key bytes (drop-time
    // unregister has no `&T`); peer behavior in that case is implementation
    // defined.
    //
    // The encapsulation must match the writer's regular data path:
    // a foreign reader may drop a lifecycle sample whose encapsulation does
    // not match, even though the rest of the packet is well-formed, and a peer
    // that reads a @final key as D_CDR2 takes its first word for a DHEADER.
    // So the K payload takes the same identifier as a DATA of this writer
    // at this version: the canonical kind of the type (PLAIN_CDR2_LE for
    // @final, D_CDR2_LE for @appendable, PL_CDR2_LE for @mutable) degraded
    // to its XCDR1 code under XCDR1, exactly as the data path does. It used
    // to be D_CDR2_LE for every type.
    //
    // The key is padded to a multiple of 4 octets so the DATA submessage
    // stays aligned, and the options count that padding, as for a sample.
    // Options saying 0 behind up to three padding octets would tell a
    // receiver honouring them that the padding was key.
    let key_payload = encapsulate_serialized_payload(
        encap_kind_for_version(ctx.encapsulation_kind, version),
        serialized_key,
        sealed,
    );

    let inline_qos = build_inline_qos_for_dispose_coherent(
        topic,
        key_hash,
        status_info,
        coherent_sn,
        group_sn.map(|gsn| (gsn, ctx.publisher_entity_id)),
        group_tag,
    );
    if inline_qos.is_empty() {
        return Vec::new();
    }

    // DATA submessage body: extraFlags(2) + octetsToInlineQos(2) + entityIds(8) + seq(8)
    //                       + inline_qos + key_payload
    let submsg_body_len = 20 + inline_qos.len() + key_payload.len();
    let Some(octets_to_next) = data_body_octets(submsg_body_len) else {
        return Vec::new();
    };

    // Align with the regular DATA path: prepend INFO_TS so that
    // send_packet_to_endpoints()'s readerEntityId patch lands at the right
    // offset (READER_ENTITY_ID_OFFSET = 40, which assumes a leading INFO_TS).
    let (ts_sec, ts_frac) = source_ts;
    let info_ts = encode_info_ts(ts_sec, ts_frac);

    // Build RTPS header (20 bytes) + INFO_TS (12 bytes) + DATA submessage
    let mut packet = Vec::with_capacity(20 + info_ts.len() + 4 + submsg_body_len);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);

    // INFO_TS submessage (12 bytes)
    packet.extend_from_slice(&info_ts);

    // DATA submessage header (4 bytes)
    packet.push(0x15); // DATA submessage ID
    packet.push(0x0B); // Flags: LE=1 + InlineQoS=1 + Key=1 (bits 0,1,3)
    packet.extend_from_slice(&octets_to_next.to_le_bytes());

    // extraFlags + octetsToInlineQos
    packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos (standard: 16)

    // Reader/Writer entity IDs
    packet.extend_from_slice(&ctx.reader_entity_id);
    packet.extend_from_slice(&ctx.writer_entity_id);

    // Sequence number (SequenceNumber_t = high:i32 + low:u32)
    packet.extend_from_slice(&sequence_number_le_bytes(sequence));

    // Inline QoS (PID_TOPIC_NAME [+ PID_COHERENT_SET] [+ PID_GROUP_COHERENT_SET_HDDS]
    // [+ PID_GROUP_ENTITY_ID] + PID_KEY_HASH + PID_STATUS_INFO + PID_SENTINEL)
    packet.extend_from_slice(&inline_qos);

    // Serialized key payload (CDR encapsulated key hash)
    packet.extend_from_slice(&key_payload);

    packet
}

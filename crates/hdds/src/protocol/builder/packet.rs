// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::helpers::build_inline_qos_with_topic;
// v110: Removed unused imports (build_rtps_header, try_u16_from_usize)
// - Now using DialectEncoder for DATA/GAP submessages
use crate::protocol::constants::*;
use crate::protocol::dialect::{get_encoder, Dialect};
use std::ops::Range;

/// RTPS endpoint context used when building DATA packets.
///
/// Carries the GUID prefix and entity IDs so that user DATA packets can be
/// aligned with the GUIDs announced via SPDP/SEDP.
#[derive(Clone, Copy, Debug)]
pub struct RtpsEndpointContext {
    pub guid_prefix: [u8; 12],
    pub reader_entity_id: [u8; 4],
    pub writer_entity_id: [u8; 4],
}

/// Build RTPS DATA packet with topic name and sequence number.
///
/// v110: Partially refactored - uses DialectEncoder for DATA header,
/// but still includes HDDS-specific inline QoS with topic name for
/// intra-HDDS routing without discovery.
///
/// This function is HDDS-specific (inline QoS with topic name).
/// For interop with external stacks, use build_data_packet_with_context().
pub fn build_data_packet(topic: &str, sequence: u64, payload: &[u8]) -> Vec<u8> {
    // Intra-HDDS mode: include inline QoS with topic for local routing
    let inline_qos = build_inline_qos_with_topic(topic);
    if inline_qos.is_empty() {
        return Vec::new();
    }

    // v105: Use USER DATA entity IDs (not SEDP built-in endpoints!)
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
    let data_submsg = encoder
        .build_data(&reader_id, &writer_id, sequence, &combined_payload, None)
        .unwrap_or_else(|_| Vec::new());

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
    let heartbeat = encoder
        .build_heartbeat(
            &RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
            &RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
            first_seq,
            last_seq,
            count,
        )
        .unwrap_or_else(|_| Vec::new());

    packet.extend_from_slice(&heartbeat);
    packet
}

/// Build RTPS HEARTBEAT packet using explicit endpoint context.
///
/// v200: For RELIABLE user data writers, sends HEARTBEATs with the correct
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
    let heartbeat = encoder
        .build_heartbeat(
            &ctx.reader_entity_id,
            &ctx.writer_entity_id,
            first_seq,
            last_seq,
            count,
        )
        .unwrap_or_else(|_| Vec::new());

    packet.extend_from_slice(&heartbeat);
    packet
}

/// Build RTPS ACKNACK packet from gap ranges using DialectEncoder.
///
/// Converts ranges to RTPS-standard SequenceNumberSet (bitmap) format.
/// Uses the Hybrid encoder for consistent RTPS-compliant encoding.
///
/// Note: This version uses hardcoded entity IDs and GUID prefix.
/// For SEDP/discovery use, prefer `acknack::build_acknack_packet` which
/// takes explicit entity IDs and GUID prefixes.
pub fn build_acknack_packet_from_ranges(gap_ranges: &[Range<u64>]) -> Vec<u8> {
    if gap_ranges.is_empty() {
        return Vec::new();
    }

    // Find base and convert ranges to missing sequence numbers
    let base_sn = gap_ranges.iter().map(|r| r.start).min().unwrap_or(1);
    let max_sn = gap_ranges.iter().map(|r| r.end).max().unwrap_or(base_sn);

    // Build bitmap from ranges (RTPS max 256 bits)
    let num_bits = ((max_sn - base_sn) as u32).min(256);
    let bitmap_words = num_bits.div_ceil(32) as usize;
    let mut bitmap = vec![0u32; bitmap_words.max(1)];

    for range in gap_ranges {
        for seq in range.clone() {
            if seq >= base_sn && seq < base_sn + num_bits as u64 {
                let bit_pos = (seq - base_sn) as usize;
                let word_idx = bit_pos / 32;
                let bit_idx = bit_pos % 32;
                if word_idx < bitmap.len() {
                    bitmap[word_idx] |= 1 << bit_idx;
                }
            }
        }
    }

    // Build RTPS header (20 bytes)
    let mut packet = Vec::with_capacity(20 + 64);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // 12-byte GUID prefix

    // Use DialectEncoder for ACKNACK submessage (RTPS-compliant bitmap format)
    static ACKNACK_COUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let count = ACKNACK_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let encoder = get_encoder(Dialect::Hybrid);
    let acknack = encoder
        .build_acknack(
            &RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
            &RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
            base_sn,
            &bitmap,
            count,
        )
        .unwrap_or_else(|_| Vec::new());

    packet.extend_from_slice(&acknack);
    packet
}

/// Build RTPS GAP packet using DialectEncoder.
///
/// v110: Refactored to use DialectEncoder::build_gap() for consistency.
///
/// This function takes pre-encoded GapMsg payload for backward compatibility.
/// The GapMsg struct has reader/writer entity IDs and sequence info embedded.
/// We extract them from the payload and delegate to DialectEncoder.
pub fn build_gap_packet(payload: &[u8]) -> Vec<u8> {
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

    // Build RTPS header (20 bytes)
    let mut packet = Vec::with_capacity(20 + 40);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]); // 12-byte GUID prefix

    // Use DialectEncoder for GAP submessage
    let encoder = get_encoder(Dialect::Hybrid);
    let gap_submsg = encoder
        .build_gap(&reader_id, &writer_id, gap_start, gap_list_base, &bitmap)
        .unwrap_or_else(|_| Vec::new());

    packet.extend_from_slice(&gap_submsg);
    packet
}

/// Build RTPS DATA packet using an explicit RTPS endpoint context.
///
/// v110: Refactored to use DialectEncoder::build_data() for consistency.
/// v174: Added CDR encapsulation header (PLAIN_CDR_LE) for RTI interop.
///
/// This variant aligns the RTPS header GUID prefix and DATA writer entity ID
/// with the GUID announced via SPDP/SEDP so that external stacks (FastDDS,
/// RTI, Cyclone) can correctly associate DATA with discovered writers.
///
/// Since this function is used for interop with external DDS stacks,
/// it does NOT include inline QoS with topic name - topic matching is
/// already done via SEDP discovery.
///
/// # CDR Encapsulation (v174)
///
/// The payload from `DDS::encode_cdr2()` contains raw CDR-encoded data without
/// the 4-byte encapsulation header. For DDS interoperability, user data must be
/// prefixed with a CDR encapsulation header:
///
/// ```text
/// [encapsulation_kind: u16 BE][options: u16] + [CDR payload]
/// ```
///
/// RTI and FastDDS expect `PLAIN_CDR_LE` (0x0001) for user data.
pub fn build_data_packet_with_context(
    ctx: &RtpsEndpointContext,
    topic: &str,
    sequence: u64,
    payload: &[u8],
) -> Vec<u8> {
    // v235: Prepend CDR encapsulation header (PLAIN_CDR_LE = 0x0001)
    let mut encapsulated_payload = Vec::with_capacity(4 + payload.len());
    encapsulated_payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // PLAIN_CDR_LE
    encapsulated_payload.extend_from_slice(payload);

    // v235: Build inline QoS with topic name for cross-process routing.
    // Without this, the router has to rely on GUID-based routing which requires
    // SEDP to have registered the writer first — a race condition.
    let inline_qos = build_inline_qos_with_topic(topic);
    if inline_qos.is_empty() {
        return Vec::new();
    }

    // DATA submessage body: extraFlags(2) + octetsToInlineQos(2) + entityIds(8) + seq(8)
    //                       + inline_qos + payload
    let submsg_body_len = 20 + inline_qos.len() + encapsulated_payload.len();

    // Build RTPS header (20 bytes) + DATA submessage
    let mut packet = Vec::with_capacity(20 + 4 + submsg_body_len);
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);

    // DATA submessage header (4 bytes)
    packet.push(0x15); // DATA submessage ID
    packet.push(0x07); // Flags: LE=1 + InlineQoS=1 + Data=1
    packet.extend_from_slice(&(submsg_body_len as u16).to_le_bytes());

    // extraFlags + octetsToInlineQos
    packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos (standard: 16)

    // Reader/Writer entity IDs
    packet.extend_from_slice(&ctx.reader_entity_id);
    packet.extend_from_slice(&ctx.writer_entity_id);

    // Sequence number (SequenceNumber_t = high:i32 + low:u32)
    let sn_high = (sequence >> 32) as i32;
    let sn_low = sequence as u32;
    packet.extend_from_slice(&sn_high.to_le_bytes());
    packet.extend_from_slice(&sn_low.to_le_bytes());

    // Inline QoS (CDR header + PID_TOPIC_NAME + PID_SENTINEL)
    packet.extend_from_slice(&inline_qos);

    // Serialized payload
    packet.extend_from_slice(&encapsulated_payload);

    packet
}

// =============================================================================
// DATA_FRAG: Automatic Fragmentation for Large Payloads
// =============================================================================

/// Default fragment size for DATA_FRAG (bytes)
///
/// RTPS overhead: header (20) + DATA_FRAG header (36) + encapsulation (4) = 60 bytes
/// UDP MTU 1500 - 60 = 1440 usable, use 1024 for alignment and compatibility.
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
) -> Vec<Vec<u8>> {
    let total_size = payload.len();

    // Don't fragment small payloads
    if total_size <= DEFAULT_MAX_UNFRAGMENTED_SIZE {
        return Vec::new();
    }

    let num_fragments = total_size.div_ceil(fragment_size);
    let mut packets = Vec::with_capacity(num_fragments);

    // Clamp to RTPS limits: fragment_size fits in u16, total_size in u32
    let fragment_size_u16 = fragment_size.min(u16::MAX as usize) as u16;
    let total_size_u32 = total_size.min(u32::MAX as usize) as u32;

    for frag_idx in 0..num_fragments {
        let start = frag_idx * fragment_size;
        let end = (start + fragment_size).min(total_size);
        let frag_data = &payload[start..end];

        // Fragment numbering starts at 1 per RTPS spec
        // Clamp to u32::MAX per RTPS DataFrag.fragmentStartingNum
        let frag_starting_num = (frag_idx + 1).min(u32::MAX as usize) as u32;

        let packet = build_single_data_frag_packet(
            ctx,
            sequence,
            frag_starting_num,
            1, // fragments_in_submessage: we send 1 fragment per packet
            fragment_size_u16,
            total_size_u32,
            frag_data,
        );
        packets.push(packet);
    }

    packets
}

/// Build a single DATA_FRAG packet.
///
/// Internal helper for `build_data_frag_packets`.
fn build_single_data_frag_packet(
    ctx: &RtpsEndpointContext,
    sequence: u64,
    fragment_starting_num: u32,
    fragments_in_submessage: u16,
    fragment_size: u16,
    data_size: u32,
    fragment_data: &[u8],
) -> Vec<u8> {
    // Build RTPS header (20 bytes)
    let mut packet = Vec::with_capacity(20 + 40 + fragment_data.len());
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&ctx.guid_prefix);

    // Use DialectEncoder for DATA_FRAG submessage
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
        .unwrap_or_else(|_| Vec::new());

    packet.extend_from_slice(&data_frag_submsg);
    packet
}

/// Check if payload should be fragmented.
///
/// Returns true if payload exceeds `DEFAULT_MAX_UNFRAGMENTED_SIZE`.
#[inline]
pub fn should_fragment(payload_len: usize) -> bool {
    payload_len > DEFAULT_MAX_UNFRAGMENTED_SIZE
}

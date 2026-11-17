// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS packet construction for discovery (SPDP and SEDP).
//!
//!
//! This module provides functions to build complete RTPS packets with
//! proper headers and submessages, ensuring interoperability with
//! other DDS implementations.

use crate::core::rtps_constants::*;
use crate::protocol::dialect::{
    build_sedp_for_dialect, get_encoder, Dialect, Guid, QosProfile, SedpEndpointData,
};
use crate::protocol::discovery::{build_spdp, ParseError, SedpData, SpdpData};
#[cfg(feature = "xtypes")]
use crate::xtypes::CompleteTypeObject;
#[cfg(feature = "xtypes")]
use crate::Cdr2Encode;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Global SEDP sequence number counter (Reliable QoS requirement)
/// Shared by all SEDP endpoints (both Publications and Subscriptions writers)
/// DEPRECATED: Use SEDP_PUBLICATIONS_SEQ_NUM or SEDP_SUBSCRIPTIONS_SEQ_NUM instead
pub static SEDP_SEQ_NUM: AtomicU64 = AtomicU64::new(1);

/// SEDP Publications Writer sequence number counter (0x000003C2)
/// Per RTPS spec, each writer must maintain its own sequence number space.
/// Kept separate from the other SEDP writers' counters: a reliable writer needs its own
/// sequence number space.
pub static SEDP_PUBLICATIONS_SEQ_NUM: AtomicU64 = AtomicU64::new(0);

/// SEDP Subscriptions Writer sequence number counter (0x000004C2)
/// Per RTPS spec, each writer must maintain its own sequence number space.
/// Kept separate from the other SEDP writers' counters: a reliable writer needs its own
/// sequence number space.
pub static SEDP_SUBSCRIPTIONS_SEQ_NUM: AtomicU64 = AtomicU64::new(0);

/// Global HEARTBEAT counter for SEDP endpoints.
///
/// Sized as the wire field it feeds: HEARTBEAT.count is a Count_t, a 32-bit
/// word (RTPS v2.5 Sec.9.4.5.6), so the counter is 32-bit and callers add
/// with `wrapping_add` rather than narrowing a wider counter.
pub static SEDP_HEARTBEAT_COUNT: AtomicU32 = AtomicU32::new(1);

/// The next SEDP HEARTBEAT `Count_t`, strictly greater than every value this
/// function has returned before (until the 32-bit wrap).
///
/// The ONE accessor: every reader of the counter must take the same
/// (post-increment) value, otherwise two consecutive HEARTBEATs could carry
/// the SAME count. DDSI-RTPS v2.5 Sec.8.3.8.6 has a reader ignore a HEARTBEAT
/// whose count does not exceed the last one seen from that writer, so the
/// second of the pair would be discarded - and on the SEDP retry path that
/// HEARTBEAT is the only thing that drives a peer to re-NACK.
#[inline]
pub fn next_sedp_heartbeat_count() -> u32 {
    SEDP_HEARTBEAT_COUNT
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .wrapping_add(1)
}

/// Convert a duration since the UNIX epoch to an RTPS Time_t (seconds,
/// fraction) pair (RTPS v2.5 Sec.9.3.2). The fraction is `nanos * 2^32 /
/// 10^9`; `subsec_nanos()` is below 10^9 so the quotient is below 2^32, and
/// the fallback in the fraction arm exists only to make the conversion total.
/// Seconds past the 32-bit range are clamped, as INFO_TS has always done here.
pub fn rtps_time_from_unix(duration: Duration) -> (u32, u32) {
    let seconds = u32::try_from(duration.as_secs()).unwrap_or_else(|_| {
        log::debug!("[RTPS] WARNING: Timestamp exceeds RTPS seconds range, clamping to u32::MAX");
        u32::MAX
    });
    let fraction = (u64::from(duration.subsec_nanos()) << 32) / 1_000_000_000;
    let fraction = u32::try_from(fraction).unwrap_or(u32::MAX);
    (seconds, fraction)
}

/// Get the current lastSeq for SEDP Publications Writer
pub fn get_publications_last_seq() -> u64 {
    SEDP_PUBLICATIONS_SEQ_NUM.load(std::sync::atomic::Ordering::Relaxed)
}

/// Get the current lastSeq for SEDP Subscriptions Writer
pub fn get_subscriptions_last_seq() -> u64 {
    SEDP_SUBSCRIPTIONS_SEQ_NUM.load(std::sync::atomic::Ordering::Relaxed)
}

/// Allocate the next sequence number for SEDP Publications Writer.
///
/// No SEDP message of a participant takes its number from here: every
/// number comes from the participant's `SedpHistory`, and a number taken
/// here is one that history hands out again. Kept for API compatibility.
pub fn next_publications_seq() -> u64 {
    SEDP_PUBLICATIONS_SEQ_NUM.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// Allocate the next sequence number for SEDP Subscriptions Writer. See
/// [`next_publications_seq`]: no SEDP message takes its number from here.
pub fn next_subscriptions_seq() -> u64 {
    SEDP_SUBSCRIPTIONS_SEQ_NUM.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// Raise the SEDP Publications high-water to at least `pos`.
///
/// Every SEDP message takes its number from the participant's `SedpHistory`
/// (announcement, dispose, re-announcement alike), which raises
/// this counter to each number it hands out, so that `get_*_last_seq`
/// (the lastSN of the dialect handshake HEARTBEATs) covers them.
pub fn bump_publications_high_water(pos: u64) {
    SEDP_PUBLICATIONS_SEQ_NUM.fetch_max(pos, std::sync::atomic::Ordering::Relaxed);
}

/// Raise the SEDP Subscriptions high-water to at least `pos`. See
/// [`bump_publications_high_water`].
pub fn bump_subscriptions_high_water(pos: u64) {
    SEDP_SUBSCRIPTIONS_SEQ_NUM.fetch_max(pos, std::sync::atomic::Ordering::Relaxed);
}

/// RTPS SPDP built-in participant reader entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_READER = 0x000100C7)
const RTPS_ENTITYID_SPDP_READER: [u8; 4] = [0x00, 0x01, 0x00, 0xC7];

/// RTPS SPDP built-in participant writer entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_WRITER = 0x000100C2)
const RTPS_ENTITYID_SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];

// The entity ids come from the shared constants in
// crate::core::rtps_constants (little-endian byte layout), not from local copies.
use crate::core::rtps_constants::{
    RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
    RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER, RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
};

/// Build INFO_DST submessage using DialectEncoder (RTPS v2.5 Sec.8.3.8.8)
///
/// Delegates to the dialect encoder for vendor-compatible INFO_DST encoding.
fn build_info_dst_submessage(guid_prefix: &[u8; 12]) -> Vec<u8> {
    // Use Hybrid encoder (conservative fallback) for discovery packets
    let encoder = get_encoder(Dialect::Hybrid);
    encoder.build_info_dst(guid_prefix)
}

/// Build INFO_TS submessage using DialectEncoder (RTPS v2.5 Sec.8.3.8.11)
///
/// Delegates to the dialect encoder for vendor-compatible INFO_TS encoding.
fn build_info_ts_submessage() -> Vec<u8> {
    // Get current system time and convert to RTPS format
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| {
            log::debug!("[RTPS] WARNING: System time before UNIX epoch, using timestamp 0");
            std::time::Duration::from_secs(0)
        });

    let (seconds_u32, fraction_u32) = rtps_time_from_unix(duration);

    // Use Hybrid encoder (conservative fallback) for discovery packets
    let encoder = get_encoder(Dialect::Hybrid);
    encoder.build_info_ts(seconds_u32, fraction_u32)
}

/// Build complete RTPS packet for SPDP participant announcement.
///
/// # Arguments
///
/// - `spdp_data`: Participant metadata (GUID, lease duration, locators)
///
/// # Returns
///
/// Complete RTPS packet ready to be sent via UDP multicast to 239.255.0.1:7400.
/// The packet includes:
/// - RTPS Header (16 bytes)
/// - DATA Submessage (variable length)
/// - CDR-encapsulated SPDP payload
///
/// # Errors
///
/// Returns `ParseError::BufferTooSmall` if the internal buffer cannot hold the packet.
///
/// # RTPS Structure
///
/// ```text
/// [RTPS Header - 20 bytes]
///   - Magic: "RTPS" (0x52 0x54 0x50 0x53) - 4 bytes
///   - Version: 2.3 (0x02 0x03) - 2 bytes
///   - Vendor ID: 0x011A (HDDS, official DDS Foundation assignment) - 2 bytes
///   - GUID prefix: First 12 bytes of participant GUID - 12 bytes
///
/// [DATA Submessage Header - 24 bytes]
///   - Submessage ID: 0x09 (DATA)
///   - Flags: 0x01 (little-endian, no inline QoS)
///   - Octets to next header: payload_len + 20
///   - Extra flags: 0x00 0x00
///   - Octets to inline QoS: 0x00 0x00 (no inline QoS for SPDP)
///   - Reader Entity ID: ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER
///   - Writer Entity ID: ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER
///   - Writer sequence number: (starts at 1, increments per announcement)
///
/// [SPDP Payload - variable]
///   - CDR encapsulation header (4 bytes)
///   - PID_PARTICIPANT_GUID (16 bytes)
///   - PID_PARTICIPANT_LEASE_DURATION (8 bytes)
///   - PID_METATRAFFIC_UNICAST_LOCATOR (24 bytes per locator)
///   - PID_SENTINEL (4 bytes)
/// ```
///
/// # RTPS Specification References
///
/// - RTPS v2.3 Section 8.3.3: RTPS Header format
/// - RTPS v2.3 Section 8.3.7: DATA Submessage format
/// - RTPS v2.3 Section 9.3.1: SPDP protocol
///
/// # Examples
///
/// ```ignore
/// use hdds::core::discovery::multicast::{build_spdp_rtps_packet, SpdpData};
/// use hdds::core::discovery::GUID;
///
/// let guid = GUID::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0xC1]);
/// let spdp_data = SpdpData {
///     participant_guid: guid,
///     lease_duration_ms: 30_000,
///     domain_id: 0,
///     metatraffic_unicast_locators: vec![],
///     default_unicast_locators: vec![],
///     default_multicast_locators: vec![],
///     metatraffic_multicast_locators: vec![],
/// };
///
/// let packet = build_spdp_rtps_packet(&spdp_data, 1)?;
/// // Send packet to 239.255.0.1:7400
/// ```
/// `destination_prefix` selects unicast (`Some`) or multicast (`None`).
pub fn build_spdp_rtps_packet(
    spdp_data: &SpdpData,
    sequence_number: u64,
    destination_prefix: Option<&[u8; 12]>, // None = multicast, Some = unicast to peer
) -> Result<Vec<u8>, ParseError> {
    // Step 1: Build SPDP CDR payload
    let mut payload_buf = vec![0u8; 8192];
    let payload_len = build_spdp(spdp_data, &mut payload_buf)?;

    // Step 2: Validate payload size (DialectEncoder handles submessage length)
    if payload_len > u16::MAX as usize - 24 {
        return Err(ParseError::BufferTooSmall);
    }

    // Step 3: Build INFO_DST and INFO_TS submessages
    // Use peer GUID prefix for unicast, zeros for multicast
    let guid_prefix = destination_prefix.unwrap_or(&[0u8; 12]);
    let info_dst = build_info_dst_submessage(guid_prefix);
    let info_ts = build_info_ts_submessage();

    // Step 4: Build DATA submessage using DialectEncoder
    // The DATA submessage is built by DialectEncoder::build_data().
    let encoder = get_encoder(Dialect::Hybrid);
    let data_submsg = encoder
        .build_data(
            &RTPS_ENTITYID_SPDP_READER,
            &RTPS_ENTITYID_SPDP_WRITER,
            sequence_number,
            &payload_buf[..payload_len],
            None,
        )
        .map_err(|_| ParseError::EncodingError)?;

    // Step 5: Build complete RTPS packet
    // Packet size: 20 (header) + 16 (INFO_DST) + 12 (INFO_TS) + DATA submessage
    let mut packet = Vec::with_capacity(20 + 16 + 12 + data_submsg.len());

    // ===== RTPS Header (20 bytes) =====
    packet.extend_from_slice(RTPS_MAGIC); // Magic (4 bytes)
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]); // Version 2.3 (2 bytes)
    packet.extend_from_slice(&HDDS_VENDOR_ID); // Vendor ID (2 bytes)
    packet.extend_from_slice(&spdp_data.participant_guid.as_bytes()[0..12]); // GUID prefix (12 bytes)

    // ===== INFO_DST Submessage (16 bytes) - RTPS v2.5 Sec.8.3.8.8 =====
    packet.extend_from_slice(&info_dst);

    // ===== INFO_TS Submessage (12 bytes) - RTPS v2.5 Sec.8.3.8.11 =====
    packet.extend_from_slice(&info_ts);

    // ===== DATA Submessage (via DialectEncoder) =====
    packet.extend_from_slice(&data_submsg);

    Ok(packet)
}

/// Build the RTPS packet announcing that a participant is going away: the
/// dispose and unregister of its instance of the SPDP built-in topic
/// (DCPSParticipant): PID_STATUS_INFO, RTPS v2.5 Sec.9.6.4.9.
///
/// A DATA of the SPDP writer with no serialized payload (flags E|Q, D=0),
/// whose inline QoS carries PID_STATUS_INFO = DISPOSED|UNREGISTERED and
/// PID_KEY_HASH = the participant GUID, the instance key of DCPSParticipant
/// (Sec.9.6.4.8).
/// `sequence_number` continues the SPDP writer's own stream.
pub fn build_spdp_dispose_packet(
    participant_guid: &crate::core::discovery::GUID,
    sequence_number: u64,
) -> Vec<u8> {
    build_participant_dispose_packet(
        participant_guid,
        sequence_number,
        RTPS_ENTITYID_SPDP_READER,
        RTPS_ENTITYID_SPDP_WRITER,
    )
}

/// Participant status change on the specified builtin participant topic.
pub(crate) fn build_participant_dispose_packet(
    participant_guid: &crate::core::discovery::GUID,
    sequence_number: u64,
    reader: [u8; 4],
    writer: [u8; 4],
) -> Vec<u8> {
    const PID_KEY_HASH: u16 = 0x0070;
    const PID_STATUS_INFO: u16 = 0x0071;
    const PID_SENTINEL: u16 = 0x0001;
    // DISPOSED (0x1) | UNREGISTERED (0x2), in the last octet of the
    // StatusInfo_t flags, which are an octet array (Sec.9.6.4.9).
    const DISPOSED_UNREGISTERED: [u8; 4] = [0, 0, 0, 0x03];

    let mut inline_qos = Vec::with_capacity(32);
    inline_qos.extend_from_slice(&PID_STATUS_INFO.to_le_bytes());
    inline_qos.extend_from_slice(&4u16.to_le_bytes());
    inline_qos.extend_from_slice(&DISPOSED_UNREGISTERED);
    inline_qos.extend_from_slice(&PID_KEY_HASH.to_le_bytes());
    inline_qos.extend_from_slice(&16u16.to_le_bytes());
    inline_qos.extend_from_slice(&participant_guid.as_bytes());
    inline_qos.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    inline_qos.extend_from_slice(&0u16.to_le_bytes());

    // extraFlags 2, octetsToInlineQos 2, readerId 4, writerId 4, writerSN 8,
    // then the inline QoS: 52 octets, as on the reference wire.
    let octets_to_next = 20 + inline_qos.len();
    let mut data = Vec::with_capacity(4 + octets_to_next);
    data.push(0x15); // DATA
    data.push(0x03); // E | Q
    data.extend_from_slice(
        &u16::try_from(octets_to_next)
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    data.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    data.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    data.extend_from_slice(&reader);
    data.extend_from_slice(&writer);
    let high = u32::try_from(sequence_number >> 32).unwrap_or(0);
    let low = u32::try_from(sequence_number & 0xFFFF_FFFF).unwrap_or(0);
    data.extend_from_slice(&high.to_le_bytes());
    data.extend_from_slice(&low.to_le_bytes());
    data.extend_from_slice(&inline_qos);

    let info_dst = build_info_dst_submessage(&[0u8; 12]);
    let info_ts = build_info_ts_submessage();
    let mut packet = Vec::with_capacity(20 + info_dst.len() + info_ts.len() + data.len());
    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&participant_guid.as_bytes()[0..12]);
    packet.extend_from_slice(&info_dst);
    packet.extend_from_slice(&info_ts);
    packet.extend_from_slice(&data);
    packet
}

/// Endpoint type for SEDP announcements (DataWriter or DataReader).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SedpEndpointKind {
    /// DataWriter endpoint (uses SEDP Publications entity IDs)
    Writer,
    /// DataReader endpoint (uses SEDP Subscriptions entity IDs)
    Reader,
}

/// Build complete RTPS packet for SEDP endpoint announcement.
///
/// # Arguments
///
/// - `sedp_data`: Endpoint metadata (topic, type, endpoint GUID, QoS, type object)
/// - `endpoint_kind`: Whether this is a Writer or Reader endpoint
/// - `participant_guid_prefix`: First 12 bytes of the participant GUID (for RTPS header)
///
/// # Returns
///
/// Complete RTPS packet ready to be sent via UDP multicast to 239.255.0.2:7400 (SEDP address).
/// The packet includes:
/// - RTPS Header (16 bytes)
/// - DATA Submessage (variable length)
/// - CDR-encapsulated SEDP payload
///
/// # Errors
///
/// Returns `ParseError::BufferTooSmall` if the internal buffer cannot hold the packet.
///
/// # RTPS Structure
///
/// Same structure as SPDP but with different entity IDs:
/// - For Writer endpoints: Uses SEDP_PUBLICATIONS_WRITER/READER entity IDs
/// - For Reader endpoints: Uses SEDP_SUBSCRIPTIONS_WRITER/READER entity IDs
///
/// # RTPS Specification References
///
/// - RTPS v2.3 Section 8.5.4: SEDP protocol
/// - RTPS v2.3 Section 9.3.1.2: Built-in entity IDs
///
/// # Examples
///
/// ```ignore
/// use hdds::core::discovery::multicast::{build_sedp_rtps_packet, SedpData, SedpEndpointKind};
/// use hdds::core::discovery::GUID;
///
/// let guid = GUID::from_bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x02]);
/// let sedp_data = SedpData {
///     topic_name: "example_topic".to_string(),
///     type_name: "ExampleType".to_string(),
///     endpoint_guid: guid,
///     qos_hash: 0x12345678,
///     type_object: None,
///     unicast_locators: vec![],
///     has_explicit_reliability: false,
///     has_explicit_ownership: false,
///     has_ownership_strength: false,
/// };
///
/// let participant_prefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// let packet = build_sedp_rtps_packet(&sedp_data, SedpEndpointKind::Writer, &participant_prefix)?;
/// // Send packet to 239.255.0.2:7400
/// ```
/// `destination_prefix` selects unicast (`Some`) or multicast (`None`).
///
/// Tests only. PID_TYPE_OBJECT follows the destination's vendor bytes
/// (`TypeObjectPid::of_destination`): this builder does not know the
/// recipient's version. Every send path goes through
/// `build_sedp_rtps_packet_for`, with the class discovery decided for the
/// recipient (`DiscoveryFsm::type_object_pid_for`).
#[cfg(test)]
pub(crate) fn build_sedp_rtps_packet(
    sedp_data: &SedpData,
    endpoint_kind: SedpEndpointKind,
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>, // None = multicast, Some = unicast to peer
    seq_num: u64,                          // Sequence number for Reliable QoS (must increment)
    dialect: Dialect,                      // Dialect for vendor-specific encoding
) -> Result<Vec<u8>, ParseError> {
    build_sedp_rtps_packet_for(
        sedp_data,
        endpoint_kind,
        participant_guid_prefix,
        destination_prefix,
        seq_num,
        dialect,
        TypeObjectPid::of_destination(destination_prefix),
    )
}

/// Whether the participant of `prefix`, announcing `vendor_id` in its SPDP
/// (PID_VENDORID), is HDDS. The vendor bytes of the GUID prefix decide (RTPS
/// v2.5 Sec.9.3.1.5: its first two octets are the vendorId); PID_VENDORID
/// only when the prefix carries another value.
#[must_use]
pub(crate) fn is_hdds_participant(prefix: &[u8; 12], vendor_id: Option<u16>) -> bool {
    prefix[0..2] == HDDS_VENDOR_ID
        || vendor_id == Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16)
}

/// Whether an SEDP announcement carries PID_TYPE_OBJECT (0x0072), HDDS's
/// own `CompleteTypeObject` CDR2 encoding, which only an HDDS peer reads.
///
/// Decided per recipient from what its SPDP announced (`TypeObjectPid::of`)
/// and kept by discovery (`DiscoveryFsm::type_object_pid_for`, which says
/// `None` for a participant it does not know): every send path reads it
/// there, never from a datagram. PID_TYPE_INFORMATION (0x0075) is not
/// affected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeObjectPid {
    /// The announcement carries PID_TYPE_OBJECT.
    Emit,
    /// The announcement leaves it out.
    Withhold,
}

impl TypeObjectPid {
    /// The class of the participant of `prefix` announcing `vendor_id` and
    /// `hdds_capabilities` (`PID_HDDS_CAPABILITIES`) in its SPDP.
    ///
    /// `Emit` only to HDDS announcing `CAP_TYPE_OBJECT_SPEC_STRINGS`. A
    /// foreign vendor would read the PID as a spec TypeObject it cannot
    /// decode. HDDS 1.4.x, which announces no capabilities, compares the
    /// TI_STRING8_SMALL (0x70) DDS-XTypes 1.3 Sec.7.3.4.4 requires with the
    /// bare TK_STRING8 (0x20) of its own types as two incompatible
    /// TypeIdentifier variants: it pairs with the writer, then drops every
    /// sample without reporting it. Without PID_TYPE_OBJECT it matches, on
    /// the type name and PID_TYPE_INFORMATION, and receives.
    #[must_use]
    pub fn of(prefix: &[u8; 12], vendor_id: Option<u16>, hdds_capabilities: Option<u32>) -> Self {
        if is_hdds_participant(prefix, vendor_id)
            && hdds_capabilities.is_some_and(|caps| {
                caps & crate::protocol::group::CAP_TYPE_OBJECT_SPEC_STRINGS != 0
            })
        {
            Self::Emit
        } else {
            Self::Withhold
        }
    }

    /// The class from the destination GUID prefix alone, for the tests'
    /// `build_sedp_rtps_packet`: `Emit` toward an HDDS prefix, `Withhold`
    /// toward any other and when there is no destination.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn of_destination(destination_prefix: Option<&[u8; 12]>) -> Self {
        if destination_prefix.is_some_and(|prefix| prefix[0..2] == HDDS_VENDOR_ID) {
            Self::Emit
        } else {
            Self::Withhold
        }
    }
}

/// `build_sedp_rtps_packet` for a recipient whose class discovery decided:
/// `type_object` says whether the announcement carries PID_TYPE_OBJECT.
///
/// The TypeObject is encoded whatever the class: PID_TYPE_INFORMATION is
/// derived from it. Copies of one sequence number built with two classes
/// are harmless to an HDDS receiver, which reads every copy and keeps a
/// TypeObject it is given (no deduplication of SEDP by sequence number);
/// only an HDDS peer announcing the capability is ever `Emit`.
pub fn build_sedp_rtps_packet_for(
    sedp_data: &SedpData,
    endpoint_kind: SedpEndpointKind,
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>,
    seq_num: u64,
    dialect: Dialect,
    type_object: TypeObjectPid,
) -> Result<Vec<u8>, ParseError> {
    build_sedp_rtps_packet_secured(
        sedp_data,
        endpoint_kind,
        participant_guid_prefix,
        destination_prefix,
        seq_num,
        dialect,
        type_object,
        None,
    )
}

/// [`build_sedp_rtps_packet_for`], the endpoint's `EndpointSecurityInfo`
/// announced in `PID_ENDPOINT_SECURITY_INFO` when given (DDS-Security v1.1
/// Sec.7.4.1.5, Table 12: "security_info, EndpointSecurityInfo,
/// PID_ENDPOINT_SECURITY_INFO, 0x1004").
#[allow(clippy::too_many_arguments)]
pub fn build_sedp_rtps_packet_secured(
    sedp_data: &SedpData,
    endpoint_kind: SedpEndpointKind,
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>,
    seq_num: u64,
    dialect: Dialect,
    type_object: TypeObjectPid,
    security: Option<crate::protocol::discovery::EndpointSecurityInfo>,
) -> Result<Vec<u8>, ParseError> {
    #[cfg(feature = "xtypes")]
    let type_object_bytes = build_type_object_for_dialect(sedp_data, dialect);
    #[cfg(feature = "xtypes")]
    {
        match (&type_object_bytes, dialect) {
            (Some(bytes), d) => log::debug!(
                "[SEDP-BUILD] dialect={:?} topic='{}' type_object_len={} bytes, PID_TYPE_OBJECT {}",
                d,
                sedp_data.topic_name,
                bytes.len(),
                if type_object == TypeObjectPid::Emit {
                    "on the wire"
                } else {
                    "withheld (the TypeObject feeds PID_TYPE_INFORMATION only)"
                }
            ),
            (None, d) => log::debug!(
                "[SEDP-BUILD] dialect={:?} topic='{}' has NO TypeObject",
                d,
                sedp_data.topic_name
            ),
        }
    }
    #[cfg(not(feature = "xtypes"))]
    let type_object_bytes: Option<Vec<u8>> = None;

    // Step 1: Build SEDP CDR payload using dialect encoder
    // Convert SedpData to the SedpEndpointData format
    let endpoint_guid = Guid {
        prefix: sedp_data.endpoint_guid.as_bytes()[..12]
            .try_into()
            .map_err(|_| ParseError::InvalidFormat)?,
        entity_id: sedp_data.endpoint_guid.as_bytes()[12..16]
            .try_into()
            .map_err(|_| ParseError::InvalidFormat)?,
    };

    let participant_guid = Guid {
        prefix: *participant_guid_prefix,
        entity_id: [0x00, 0x00, 0x01, 0xC1], // Standard participant entity ID
    };

    // Map DDS QoS (if present) to dialect-agnostic QosProfile for SEDP PIDs.
    let qos_profile: Option<QosProfile> = sedp_data.qos.as_ref().map(|q| {
        use crate::dds::qos::{Durability, History, OwnershipKind, Reliability};

        let (history_kind, history_depth) = match q.history {
            History::KeepLast(depth) => (0, depth), // KEEP_LAST
            History::KeepAll => (1, 0),             // KEEP_ALL
        };

        let (deadline_secs, deadline_nanos) = if q.deadline.is_infinite() {
            (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
        } else {
            (
                u32::try_from(q.deadline.period.as_secs()).unwrap_or(u32::MAX),
                q.deadline.period.subsec_nanos(),
            )
        };

        let (lifespan_secs, lifespan_nanos) = if q.lifespan.is_infinite() {
            (0x7FFF_FFFFu32, 0xFFFF_FFFFu32)
        } else {
            (
                u32::try_from(q.lifespan.duration.as_secs()).unwrap_or(u32::MAX),
                q.lifespan.duration.subsec_nanos(),
            )
        };

        let liveliness_lease =
            crate::protocol::dialect::profile_duration(q.liveliness.lease_duration);
        let latency_budget = crate::protocol::dialect::profile_duration(q.latency_budget.duration);

        use crate::dds::qos::PresentationAccessScope;
        let presentation_scope = match q.presentation.access_scope {
            PresentationAccessScope::Instance => 0u32,
            PresentationAccessScope::Topic => 1u32,
            PresentationAccessScope::Group => 2u32,
        };

        QosProfile {
            reliability_kind: match q.reliability {
                Reliability::BestEffort => 1, // BEST_EFFORT
                Reliability::Reliable => 2,   // RELIABLE
            },
            reliability_max_blocking_time: Some(q.reliability_max_blocking_time),
            durability_kind: match q.durability {
                Durability::Volatile => 0,       // VOLATILE
                Durability::TransientLocal => 1, // TRANSIENT_LOCAL
                Durability::Transient => 2,      // TRANSIENT
                Durability::Persistent => 3,     // PERSISTENT
            },
            history_kind,
            history_depth,
            ownership_kind: match q.ownership.kind {
                OwnershipKind::Shared => 0,
                OwnershipKind::Exclusive => 1,
            },
            ownership_strength: q.ownership_strength.value,
            deadline_period_sec: deadline_secs,
            deadline_period_nsec: deadline_nanos,
            lifespan_sec: lifespan_secs,
            lifespan_nsec: lifespan_nanos,
            liveliness_kind: match q.liveliness.kind {
                crate::dds::qos::LivelinessKind::Automatic => 0,
                crate::dds::qos::LivelinessKind::ManualByParticipant => 1,
                crate::dds::qos::LivelinessKind::ManualByTopic => 2,
            },
            liveliness_lease_sec: liveliness_lease.0,
            liveliness_lease_nsec: liveliness_lease.1,
            latency_budget_sec: latency_budget.0,
            latency_budget_nsec: latency_budget.1,
            destination_order_kind: u32::from(q.destination_order.uses_source_timestamp()),
            presentation_access_scope: presentation_scope,
            presentation_coherent: q.presentation.coherent_access,
            presentation_ordered: q.presentation.ordered_access,
            partition_names: q.partition.names.clone(),
            // A writer announces the one representation it offers and
            // encodes (its list is resolved at creation), a reader the list
            // it requests, `[XCDR, XCDR2]` when it set none
            // (`announced_data_representation`, the one reading every local
            // verdict applies too). Announcing `[XCDR2]` alone for a reader
            // made peers that omit the PID (XCDR by default, DDS-XTypes v1.3
            // Sec.7.6.3.1.1) incompatible with our readers.
            data_representation: crate::dds::cdr_negotiation::announced_data_representation(
                match endpoint_kind {
                    SedpEndpointKind::Writer => {
                        crate::core::discovery::multicast::fsm::EndpointKind::Writer
                    }
                    SedpEndpointKind::Reader => {
                        crate::core::discovery::multicast::fsm::EndpointKind::Reader
                    }
                },
                &q.data_representation,
            )
            .to_vec(),
            // TIME_BASED_FILTER: map minimum_separation to RTPS Duration_t.
            // RTPS v2.5 sec. 9.3.2: fraction is 2^-32 seconds (NOT nanoseconds).
            // Zero when filter is disabled (the common case -- no overhead).
            minimum_separation_sec: if q.time_based_filter.is_disabled() {
                0
            } else {
                u32::try_from(q.time_based_filter.minimum_separation.as_secs()).unwrap_or(u32::MAX)
            },
            minimum_separation_frac: if q.time_based_filter.is_disabled() {
                0
            } else {
                let nanos = q.time_based_filter.minimum_separation.subsec_nanos() as u64;
                u32::try_from((nanos << 32) / 1_000_000_000).unwrap_or(u32::MAX)
            },
        }
    });

    let endpoint_data = SedpEndpointData {
        endpoint_guid,
        participant_guid,
        topic_name: &sedp_data.topic_name,
        type_name: &sedp_data.type_name,
        unicast_locators: &sedp_data.unicast_locators,
        multicast_locators: &[],
        qos: qos_profile.as_ref(),
        type_object: type_object_bytes.as_deref(),
        // The application's UserDataQosPolicy, set by announce.rs from
        // qos.user_data. Never an internal capability hint (see
        // SedpEndpointData::user_data doc).
        user_data: sedp_data.user_data.as_deref(),
        // The HDDS SHM capability hint, set by announce.rs and gated there on
        // ShmPolicy. The HDDS dialect encoder is the only one that reads this
        // field (see SedpEndpointData::hdds_shm_capability doc).
        hdds_shm_capability: sedp_data.shm_capability.as_deref(),
        // Gate on the DESTINATION vendor, same rule as `emit_type_object_pid`
        // below: the SEDP flush and retransmit paths encode with the Hybrid
        // dialect even toward HDDS peers, so without this the SHM hint would
        // travel only on some copies of the announcement and the pairing
        // would resolve from whichever copy happened to arrive first. A
        // multicast frame and every frame addressed to a foreign vendor leave
        // this false, so no foreign-vendor byte moves.
        //
        // An HDDS peer running DDS-Security has a prefix bound to its
        // certificate, not its vendor id (DDS-Security 1.1 Sec.9.3.3,
        // Table 52): it is known by the class discovery keeps for it, which
        // only an HDDS participant gets (`TypeObjectPid::of`).
        hdds_peer_destination: destination_prefix
            .is_some_and(|prefix| prefix[0..2] == HDDS_VENDOR_ID)
            || (destination_prefix.is_some() && type_object == TypeObjectPid::Emit),
        group_entity_id: sedp_data.group_entity_id,
        type_consistency: sedp_data.type_consistency.clone(),
        // Thread the pre-computed TypeInformation (with deps) so the HDDS
        // dialect encoder can pass it to build_sedp without re-deriving.
        #[cfg(feature = "xtypes-structural-assignability")]
        type_information: sedp_data.type_information.clone(),
        // PID_TYPE_OBJECT (0x0072) carries HDDS' internal CompleteTypeObject
        // encoding: decided for the RECIPIENT (`TypeObjectPid`), not from the
        // encoding dialect, since the flush/retransmit paths use the Hybrid
        // dialect even toward HDDS peers, and receivers dedup SEDP copies by
        // writer SN, so the class must hold for EVERY copy sent to a peer.
        emit_type_object_pid: type_object == TypeObjectPid::Emit,
    };

    // Use dialect-specific encoder
    let mut payload =
        build_sedp_for_dialect(dialect, &endpoint_data).map_err(|_| ParseError::EncodingError)?;
    if let Some(security) = security {
        insert_endpoint_security_info(&mut payload, security)?;
    }

    // Step 2: Validate payload size (DialectEncoder handles submessage length)
    if payload.len() > u16::MAX as usize - 24 {
        return Err(ParseError::BufferTooSmall);
    }

    // Step 3: Select entity IDs based on endpoint kind
    let (reader_id, writer_id) = sedp_entity_ids(endpoint_kind);

    // Step 4: Build DATA submessage using DialectEncoder
    // The DATA submessage is built by DialectEncoder::build_data().
    let encoder = get_encoder(dialect);
    let data_submsg = encoder
        .build_data(&reader_id, &writer_id, seq_num, &payload, None)
        .map_err(|_| ParseError::EncodingError)?;

    Ok(frame_sedp_submessage(
        &data_submsg,
        participant_guid_prefix,
        destination_prefix,
        dialect,
    ))
}

/// `PID_ENDPOINT_SECURITY_INFO` (DDS-Security v1.1 Sec.7.4.1.5, Table 12).
pub(crate) const PID_ENDPOINT_SECURITY_INFO: u16 = 0x1004;

/// Put `PID_ENDPOINT_SECURITY_INFO` into the serialized ParameterList
/// `payload` (encapsulation header first), right before its PID_SENTINEL:
/// the two masks of `EndpointSecurityInfo` (Sec.7.2.8), in the
/// ParameterList's own byte order (PL_CDR_LE 0x0003, PL_CDR_BE 0x0002,
/// DDSI-RTPS v2.5 Sec.10.2).
///
/// A payload that is not a ParameterList ending in PID_SENTINEL is refused:
/// the announcement would otherwise go out without the security info it was
/// built to carry.
fn insert_endpoint_security_info(
    payload: &mut Vec<u8>,
    security: crate::protocol::discovery::EndpointSecurityInfo,
) -> Result<(), ParseError> {
    let little = match payload.get(0..2) {
        Some([0x00, 0x03]) => true,
        Some([0x00, 0x02]) => false,
        _ => return Err(ParseError::EncodingError),
    };
    let sentinel: [u8; 4] = if little {
        [0x01, 0x00, 0x00, 0x00]
    } else {
        [0x00, 0x01, 0x00, 0x00]
    };
    if payload.len() < 8 || payload[payload.len() - 4..] != sentinel {
        return Err(ParseError::EncodingError);
    }
    let at = payload.len() - 4;
    let mut parameter = Vec::with_capacity(12);
    let (pid, len, mask, plugin) = if little {
        (
            PID_ENDPOINT_SECURITY_INFO.to_le_bytes(),
            8u16.to_le_bytes(),
            security.endpoint_security_attributes.to_le_bytes(),
            security.plugin_endpoint_security_attributes.to_le_bytes(),
        )
    } else {
        (
            PID_ENDPOINT_SECURITY_INFO.to_be_bytes(),
            8u16.to_be_bytes(),
            security.endpoint_security_attributes.to_be_bytes(),
            security.plugin_endpoint_security_attributes.to_be_bytes(),
        )
    };
    parameter.extend_from_slice(&pid);
    parameter.extend_from_slice(&len);
    parameter.extend_from_slice(&mask);
    parameter.extend_from_slice(&plugin);
    payload.splice(at..at, parameter);
    Ok(())
}

/// The SEDP built-in (reader, writer) entity ids for `kind`: publications
/// (0x000003C7, 0x000003C2) for a DataWriter, subscriptions (0x000004C7,
/// 0x000004C2) for a DataReader (RTPS v2.5 Sec.9.3.1.3).
pub fn sedp_entity_ids(kind: SedpEndpointKind) -> ([u8; 4], [u8; 4]) {
    match kind {
        SedpEndpointKind::Writer => (
            RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        ),
        SedpEndpointKind::Reader => (
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
        ),
    }
}

/// Put one SEDP submessage in an RTPS message: the header under our prefix,
/// then INFO_TS, then INFO_DST when the message is addressed to one peer,
/// in the dialect's order, then `submessage`.
fn frame_sedp_submessage(
    submessage: &[u8],
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>,
    dialect: Dialect,
) -> Vec<u8> {
    let encoder = get_encoder(dialect);

    // Step 5: Build INFO_TS submessage and optional INFO_DST
    //
    // For multicast SEDP (destination_prefix = None), do NOT send INFO_DST with
    // a GUIDPREFIX_UNKNOWN (all zeros). A receiver may treat an explicit
    // INFO_DST + unknown prefix as "not for me" and drop the message before it
    // reaches the EDP listeners. For multicast we
    // simply omit INFO_DST so that the default destination semantics apply.
    //
    // For unicast SEDP (destination_prefix = Some(peer_prefix)), we include
    // INFO_DST with the peer GUID prefix so that the MessageReceiver can route
    // the DATA submessage to the correct participant.
    let info_ts = build_info_ts_submessage();

    // Get dialect-specific RTPS version and submessage ordering
    let (version_major, version_minor) = encoder.rtps_version();
    let info_ts_first = encoder.info_ts_before_info_dst();

    // Build INFO_DST submessage for unicast
    let info_dst_data = destination_prefix.map(build_info_dst_submessage);

    // Step 6: Build complete RTPS packet
    // Packet size: 20 (header) + optional 16 (INFO_DST) + 12 (INFO_TS) + DATA submessage
    let mut packet = Vec::with_capacity(
        20 + if info_dst_data.is_some() { 16 } else { 0 } + 12 + submessage.len(),
    );

    // ===== RTPS Header (20 bytes) =====
    packet.extend_from_slice(RTPS_MAGIC); // Magic (4 bytes)
                                          // Use dialect-specific RTPS version (OpenDDS uses 2.4, others use 2.3)
    packet.extend_from_slice(&[version_major, version_minor]); // Version (2 bytes)
    packet.extend_from_slice(&HDDS_VENDOR_ID); // Vendor ID (2 bytes)
    packet.extend_from_slice(&participant_guid_prefix[0..12]); // GUID prefix (12 bytes)

    // Dialect-specific submessage ordering
    // OpenDDS: INFO_TS -> INFO_DST -> DATA
    // Default (HDDS, RTI and FastDDS dialects): INFO_DST -> INFO_TS -> DATA
    if info_ts_first {
        // ===== INFO_TS Submessage (12 bytes) - OpenDDS style =====
        packet.extend_from_slice(&info_ts);

        // ===== INFO_DST Submessage (16 bytes) - unicast only =====
        if let Some(info_dst) = &info_dst_data {
            packet.extend_from_slice(info_dst);
        }
    } else {
        // ===== INFO_DST Submessage (16 bytes) - RTPS v2.5 Sec.8.3.8.8 (unicast only) =====
        if let Some(info_dst) = &info_dst_data {
            packet.extend_from_slice(info_dst);
        }

        // ===== INFO_TS Submessage (12 bytes) - RTPS v2.5 Sec.8.3.8.11 =====
        packet.extend_from_slice(&info_ts);
    }

    // ===== DATA Submessage (via DialectEncoder) =====
    packet.extend_from_slice(submessage);

    packet
}

/// Build the RTPS packet announcing that a local DataWriter or DataReader
/// was deleted: the dispose and unregister of its instance of the SEDP
/// built-in topic (RTPS v2.5 Sec.8.5.4.4, Tables 8.82 and 8.83: the
/// data-object is deleted each time its endpoint is deleted).
///
/// A DATA of the SEDP writer of `kind` (flags E|Q|K, 0x0b) whose inline QoS
/// carries PID_KEY_HASH = the endpoint GUID (Sec.9.6.4.8) and
/// PID_STATUS_INFO = DISPOSED|UNREGISTERED (Sec.9.6.4.9), and whose
/// serialized payload is the key-only form of the built-in topic: a PL_CDR_LE
/// ParameterList holding PID_ENDPOINT_GUID alone (Sec.9.6.3.2). The inline
/// QoS carries both PIDs and the payload carries the key, so a receiver can
/// identify the endpoint from either. Framed like the
/// announcement (`build_sedp_rtps_packet`); `sequence_number` continues the
/// SEDP writer's own stream.
pub fn build_sedp_dispose_packet(
    endpoint_guid: &crate::core::discovery::GUID,
    kind: SedpEndpointKind,
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>,
    sequence_number: u64,
    dialect: Dialect,
) -> Vec<u8> {
    const PID_SENTINEL: u16 = 0x0001;
    const PID_ENDPOINT_GUID: u16 = 0x005a;
    const PID_KEY_HASH: u16 = 0x0070;
    const PID_STATUS_INFO: u16 = 0x0071;
    // DISPOSED (0x1) | UNREGISTERED (0x2), in the last octet of the
    // StatusInfo_t flags, which are an octet array (Sec.9.6.4.9).
    const DISPOSED_UNREGISTERED: [u8; 4] = [0, 0, 0, 0x03];
    // PL_CDR_LE encapsulation, options 0 (Sec.10.3, Table 10.1).
    const PL_CDR_LE: [u8; 4] = [0x00, 0x03, 0x00, 0x00];
    // E (little-endian) | Q (inline QoS) | K (serialized key), Sec.9.4.5.4.
    const FLAGS_E_Q_K: u8 = 0x0b;

    let guid = endpoint_guid.as_bytes();
    let mut inline_qos = Vec::with_capacity(32);
    inline_qos.extend_from_slice(&PID_KEY_HASH.to_le_bytes());
    inline_qos.extend_from_slice(&16u16.to_le_bytes());
    inline_qos.extend_from_slice(&guid);
    inline_qos.extend_from_slice(&PID_STATUS_INFO.to_le_bytes());
    inline_qos.extend_from_slice(&4u16.to_le_bytes());
    inline_qos.extend_from_slice(&DISPOSED_UNREGISTERED);
    inline_qos.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    inline_qos.extend_from_slice(&0u16.to_le_bytes());

    let mut key = Vec::with_capacity(28);
    key.extend_from_slice(&PL_CDR_LE);
    key.extend_from_slice(&PID_ENDPOINT_GUID.to_le_bytes());
    key.extend_from_slice(&16u16.to_le_bytes());
    key.extend_from_slice(&guid);
    key.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    key.extend_from_slice(&0u16.to_le_bytes());

    // extraFlags 2, octetsToInlineQos 2, readerId 4, writerId 4, writerSN 8,
    // the inline QoS, the key: 80 octets, as on the reference wire.
    let (reader_id, writer_id) = sedp_entity_ids(kind);
    let octets_to_next = 20 + inline_qos.len() + key.len();
    let mut data = Vec::with_capacity(4 + octets_to_next);
    data.push(0x15); // DATA
    data.push(FLAGS_E_Q_K);
    data.extend_from_slice(
        &u16::try_from(octets_to_next)
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    data.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
    data.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    data.extend_from_slice(&reader_id);
    data.extend_from_slice(&writer_id);
    let high = u32::try_from(sequence_number >> 32).unwrap_or(0);
    let low = u32::try_from(sequence_number & 0xFFFF_FFFF).unwrap_or(0);
    data.extend_from_slice(&high.to_le_bytes());
    data.extend_from_slice(&low.to_le_bytes());
    data.extend_from_slice(&inline_qos);
    data.extend_from_slice(&key);

    frame_sedp_submessage(&data, participant_guid_prefix, destination_prefix, dialect)
}

/// Build RTPS packet for TypeLookup request/response (HDDS-only).
///
/// Uses the built-in TypeLookup entity IDs and CDR2 payload.
pub fn build_type_lookup_rtps_packet(
    payload: &[u8],
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>,
    seq_num: u64,
) -> Result<Vec<u8>, ParseError> {
    if payload.len() > u16::MAX as usize - 24 {
        return Err(ParseError::BufferTooSmall);
    }

    let encoder = get_encoder(Dialect::Hdds);
    let data_submsg = encoder
        .build_data(
            &RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER,
            &RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
            seq_num,
            payload,
            None,
        )
        .map_err(|_| ParseError::EncodingError)?;

    let info_ts = build_info_ts_submessage();
    let info_dst = destination_prefix.map(build_info_dst_submessage);

    let (version_major, version_minor) = encoder.rtps_version();
    let info_ts_first = encoder.info_ts_before_info_dst();

    let mut packet =
        Vec::with_capacity(20 + if info_dst.is_some() { 16 } else { 0 } + 12 + data_submsg.len());

    packet.extend_from_slice(RTPS_MAGIC);
    packet.extend_from_slice(&[version_major, version_minor]);
    packet.extend_from_slice(&HDDS_VENDOR_ID);
    packet.extend_from_slice(&participant_guid_prefix[0..12]);

    if info_ts_first {
        packet.extend_from_slice(&info_ts);
        if let Some(info_dst) = &info_dst {
            packet.extend_from_slice(info_dst);
        }
    } else {
        if let Some(info_dst) = &info_dst {
            packet.extend_from_slice(info_dst);
        }
        packet.extend_from_slice(&info_ts);
    }

    packet.extend_from_slice(&data_submsg);

    Ok(packet)
}

#[cfg(feature = "xtypes")]
fn encode_type_object_cdr2(type_obj: &CompleteTypeObject) -> Result<Vec<u8>, ParseError> {
    let mut buf = vec![0u8; type_obj.max_cdr2_size()];
    let len = type_obj
        .encode_cdr2_le(&mut buf)
        .map_err(|_| ParseError::EncodingError)?;
    buf.truncate(len);
    Ok(buf)
}

/// Build dialect-specific TypeObject payload (standard PID_TYPE_OBJECT).
///
/// An encode failure of `encode_type_object_cdr2(type_obj)` must not be
/// discarded silently: the caller's debug log (`build_sedp_rtps_packet`)
/// only sees this function's `None` return, and logs the SAME "has NO
/// TypeObject" message whether there was genuinely nothing to encode
/// (`sedp_data.type_object` is `None`, the `?` above) or the encoder failed
/// on a real `CompleteTypeObject` (an under-estimated `max_cdr2_size()` or
/// an encoder bug). The failure case is logged here, at `error!` (an
/// encoder bug on our own outgoing data is a local defect, not routine), so
/// the two cases are distinguishable in the log even though the caller's
/// message text is the same. Still returns
/// `None` on failure (log-and-continue, not propagate): failing the whole
/// SEDP packet build over a TypeObject encode error would cost the endpoint
/// its announcement entirely, worse than a peer falling back to placeholder
/// xtypes introspection.
#[cfg(feature = "xtypes")]
fn build_type_object_for_dialect(sedp_data: &SedpData, dialect: Dialect) -> Option<Vec<u8>> {
    let type_obj = sedp_data.type_object.as_ref()?;
    match dialect {
        // OpenDDS: the encoder never writes PID_TYPE_OBJECT, it derives the
        // endpoint's PID_TYPE_INFORMATION from this object.
        Dialect::Hdds | Dialect::Hybrid | Dialect::OpenDds => {
            match encode_type_object_cdr2(type_obj) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    log::error!(
                    "[SEDP-BUILD] dialect={:?} topic='{}' type='{}' TypeObject ENCODE FAILED: {:?}; PID_TYPE_OBJECT omitted from this announcement",
                    dialect,
                    sedp_data.topic_name,
                    sedp_data.type_name,
                    e
                );
                    None
                }
            }
        }
        _ => None,
    }
}

#[cfg(not(feature = "xtypes"))]
fn build_type_object_for_dialect(_sedp_data: &SedpData, _dialect: Dialect) -> Option<Vec<u8>> {
    None
}

/// Build HEARTBEAT submessage using DialectEncoder (RTPS v2.5 Sec.8.3.8.6)
///
/// Delegates to the dialect encoder for vendor-compatible HEARTBEAT encoding.
///
/// ## Arguments
/// - `reader_entity_id`: Target reader (e.g., SEDP Publications Reader 0x000003C7)
/// - `writer_entity_id`: Source writer (e.g., SEDP Publications Writer 0x000003C2)
/// - `first_sn`: First available sequence number
/// - `last_sn`: Last available sequence number
/// - `count`: HEARTBEAT counter (increment on each send)
///
/// ## Returns
/// 32-byte HEARTBEAT submessage ready to append to RTPS packet
pub fn build_heartbeat_submessage(
    reader_entity_id: &[u8; 4],
    writer_entity_id: &[u8; 4],
    first_sn: u64,
    last_sn: u64,
    count: u32,
) -> Vec<u8> {
    // Use Hybrid encoder (conservative fallback) for discovery packets
    let encoder = get_encoder(Dialect::Hybrid);
    encoder
        .build_heartbeat(reader_entity_id, writer_entity_id, first_sn, last_sn, count)
        .unwrap_or_else(|_| Vec::new())
}

/// Build HEARTBEAT submessage with Final flag for SEDP endpoints.
///
/// The Final flag is CRITICAL for interop - it tells the reader it is
/// not required to respond with ACKNACK (DDSI-RTPS 2.5 Sec.8.3.8.6), which
/// prevents an endless HEARTBEAT/ACKNACK loop.
///
/// ## Arguments
/// - `reader_entity_id`: Target reader entity ID
/// - `writer_entity_id`: Our writer entity ID
/// - `first_sn`: First available sequence number
/// - `last_sn`: Last available sequence number
/// - `count`: HEARTBEAT counter (increment on each send)
///
/// ## Returns
/// 32-byte HEARTBEAT submessage with Final flag set (flags=0x03)
pub fn build_heartbeat_submessage_final(
    reader_entity_id: &[u8; 4],
    writer_entity_id: &[u8; 4],
    first_sn: u64,
    last_sn: u64,
    count: u32,
) -> Vec<u8> {
    use crate::protocol::rtps::encode_heartbeat_final;
    encode_heartbeat_final(reader_entity_id, writer_entity_id, first_sn, last_sn, count)
        .unwrap_or_else(|_| Vec::new())
}

#[cfg(test)]
#[path = "rtps_packet_qos_tests.rs"]
mod qos_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;
    use std::net::SocketAddr;

    fn verify_rtps_header(packet: &[u8], guid: &GUID) {
        assert_eq!(&packet[0..4], b"RTPS", "RTPS magic mismatch");
        assert_eq!(&packet[4..6], &[0x02, 0x04], "RTPS version mismatch");
        assert_eq!(&packet[6..8], &HDDS_VENDOR_ID, "Vendor ID mismatch");
        assert_eq!(
            &packet[8..20],
            &guid.as_bytes()[0..12],
            "GUID prefix mismatch"
        );
    }

    fn verify_info_submessages(packet: &[u8]) {
        // INFO_DST at offset 20
        assert_eq!(packet[20], RTPS_SUBMSG_INFO_DST, "INFO_DST ID mismatch");
        assert_eq!(packet[21], 0x01, "INFO_DST flags mismatch");
        assert_eq!(
            u16::from_le_bytes([packet[22], packet[23]]),
            12,
            "INFO_DST size"
        );

        // INFO_TS at offset 36
        assert_eq!(packet[36], RTPS_SUBMSG_INFO_TS, "INFO_TS ID mismatch");
        assert_eq!(packet[37], 0x01, "INFO_TS flags mismatch");
        assert_eq!(
            u16::from_le_bytes([packet[38], packet[39]]),
            8,
            "INFO_TS size"
        );
    }

    fn verify_data_submessage(packet: &[u8]) {
        assert_eq!(packet[48], RTPS_SUBMSG_DATA, "DATA ID mismatch");
        assert_eq!(packet[49], 0x05, "DATA flags mismatch");
        // Extra flags (2 bytes) + octetsToInlineQos (2 bytes) at offsets 52..56
        let octets_to_inline_qos = u16::from_le_bytes([packet[54], packet[55]]);
        assert_eq!(
            octets_to_inline_qos, 16,
            "SPDP octetsToInlineQos mismatch (expected 16)"
        );
        assert_eq!(&packet[56..60], &RTPS_ENTITYID_SPDP_READER, "Reader ID");
        assert_eq!(&packet[60..64], &RTPS_ENTITYID_SPDP_WRITER, "Writer ID");

        // Sequence number in RTPS format: (high: i32, low: u32)
        // For seq=1: high=0, low=1
        let seq_high = i32::from_le_bytes(packet[64..68].try_into().expect("seq_high"));
        let seq_low = u32::from_le_bytes(packet[68..72].try_into().expect("seq_low"));
        let seq = ((seq_high as i64) << 32 | seq_low as i64) as u64;
        assert_eq!(seq, 1, "Sequence number mismatch");
    }

    /// An SEDP announcement of a writer, as `announce.rs` builds it.
    fn an_endpoint(prefix: [u8; 12]) -> SedpData {
        SedpData {
            topic_name: "Square".to_string(),
            type_name: "ShapeType".to_string(),
            participant_guid: GUID::new(prefix, [0, 0, 1, 0xc1]),
            endpoint_guid: GUID::new(prefix, [0, 0, 0x12, 0x02]),
            qos_hash: 0,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// The ParameterList of the DATA of an SEDP datagram, as (pid, value)
    /// pairs, read from its encapsulation.
    fn parameters(packet: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let payload_at = crate::core::discovery::multicast::classifier::classify_rtps(packet)
            .1
            .expect("a DATA");
        let payload = &packet[payload_at..];
        assert_eq!(&payload[..2], &[0x00, 0x03], "PL_CDR_LE");
        let mut out = Vec::new();
        let mut at = 4;
        loop {
            let pid = u16::from_le_bytes([payload[at], payload[at + 1]]);
            let len = usize::from(u16::from_le_bytes([payload[at + 2], payload[at + 3]]));
            out.push((pid, payload[at + 4..at + 4 + len].to_vec()));
            if pid == 0x0001 {
                assert_eq!(at + 4, payload.len(), "nothing after PID_SENTINEL");
                return out;
            }
            at += 4 + len;
        }
    }

    /// DDS-Security v1.1 Sec.7.4.1.5, Table 12: the endpoint's
    /// `EndpointSecurityInfo` in `PID_ENDPOINT_SECURITY_INFO` (0x1004), its
    /// two masks in the ParameterList's byte order (Sec.7.2.8), last before
    /// the sentinel; absent when there is none.
    #[test]
    fn the_endpoint_security_info_is_announced_in_its_own_parameter() {
        let ours = [0x01, 0x1a, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3];
        let info = crate::protocol::discovery::EndpointSecurityInfo {
            endpoint_security_attributes: 0x8000_0037,
            plugin_endpoint_security_attributes: 0x8000_0002,
        };
        for dialect in [
            Dialect::Hdds,
            Dialect::Hybrid,
            Dialect::FastDds,
            Dialect::Rti,
        ] {
            let with = build_sedp_rtps_packet_secured(
                &an_endpoint(ours),
                SedpEndpointKind::Writer,
                &ours,
                None,
                1,
                dialect,
                TypeObjectPid::Withhold,
                Some(info),
            )
            .expect("build");
            let params = parameters(&with);
            let n = params.len();
            assert_eq!(params[n - 1].0, 0x0001, "{:?}: the sentinel last", dialect);
            assert_eq!(
                params[n - 2],
                (0x1004, vec![0x37, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x80]),
                "{:?}",
                dialect
            );
            assert_eq!(params.iter().filter(|p| p.0 == 0x1004).count(), 1);

            let without = build_sedp_rtps_packet_for(
                &an_endpoint(ours),
                SedpEndpointKind::Writer,
                &ours,
                None,
                1,
                dialect,
                TypeObjectPid::Withhold,
            )
            .expect("build");
            assert!(
                parameters(&without).iter().all(|p| p.0 != 0x1004),
                "{:?}: no security info, no parameter",
                dialect
            );
            assert_eq!(with.len(), without.len() + 12, "{:?}", dialect);
        }
    }

    /// The parameter follows the ParameterList's byte order, and a payload
    /// that is not a ParameterList ending in its sentinel is refused rather
    /// than sent without the info.
    #[test]
    fn the_endpoint_security_info_follows_the_encapsulation() {
        let info = crate::protocol::discovery::EndpointSecurityInfo {
            endpoint_security_attributes: 0x8000_0004,
            plugin_endpoint_security_attributes: 0x8000_0000,
        };
        let mut be = vec![0x00, 0x02, 0, 0, 0x00, 0x01, 0x00, 0x00];
        insert_endpoint_security_info(&mut be, info).expect("PL_CDR_BE");
        assert_eq!(
            be,
            vec![
                0x00, 0x02, 0, 0, 0x10, 0x04, 0x00, 0x08, 0x80, 0x00, 0x00, 0x04, 0x80, 0x00, 0x00,
                0x00, 0x00, 0x01, 0x00, 0x00
            ]
        );
        for bad in [
            vec![0x00, 0x01, 0, 0, 0x01, 0x00, 0x00, 0x00],
            vec![0x00, 0x03, 0, 0, 0x02, 0x00, 0x00, 0x00],
            vec![0x00, 0x03],
        ] {
            let mut payload = bad.clone();
            assert!(
                insert_endpoint_security_info(&mut payload, info).is_err(),
                "{:?}",
                bad
            );
            assert_eq!(payload, bad, "left untouched");
        }
    }

    #[test]
    fn test_build_spdp_rtps_packet_structure() {
        let guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1]);
        let spdp_data = SpdpData {
            participant_guid: guid,
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };

        let packet = build_spdp_rtps_packet(&spdp_data, 1, None).expect("Failed to build");

        verify_rtps_header(&packet, &guid);
        verify_info_submessages(&packet);
        verify_data_submessage(&packet);

        // Packet size validation (extended PIDs included)
        assert!(packet.len() >= 120, "Packet too small: {}", packet.len());
        assert!(packet.len() < 1024, "Packet too large: {}", packet.len());
    }

    #[test]
    fn test_spdp_packet_with_locators() {
        let guid = GUID::from_bytes([0; 16]);
        let spdp_data = SpdpData {
            participant_guid: guid,
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec!["192.168.1.100:7410"
                .parse::<SocketAddr>()
                .expect("Valid socket address")],
            default_unicast_locators: vec!["192.168.1.100:7411"
                .parse::<SocketAddr>()
                .expect("Valid socket address")],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };

        let packet = build_spdp_rtps_packet(&spdp_data, 42, None).expect("Failed to build packet");

        // Verify RTPS magic
        assert_eq!(&packet[0..4], b"RTPS");

        // Verify sequence number in RTPS format: (high: i32, low: u32)
        // For seq=42: high=0, low=42
        let seq_high = i32::from_le_bytes(packet[64..68].try_into().expect("seq_high"));
        let seq_low = u32::from_le_bytes(packet[68..72].try_into().expect("seq_low"));
        let seq = ((seq_high as i64) << 32 | seq_low as i64) as u64;
        assert_eq!(seq, 42, "Sequence number should increment");

        // Packet should be longer due to locator parameter + INFO_DST (16) + INFO_TS (12) overhead
        assert!(
            packet.len() > 128,
            "Expected larger packet with locators and INFO submessages"
        );

        // Locate first PID_METATRAFFIC_UNICAST_LOCATOR and validate LE locator fields.
        use crate::protocol::discovery::constants::PID_METATRAFFIC_UNICAST_LOCATOR;
        use std::net::Ipv4Addr;

        // Packet structure:
        // - RTPS Header: 20 bytes
        // - INFO_DST: 16 bytes
        // - INFO_TS: 12 bytes
        // - DATA header: 24 bytes
        // - CDR encapsulation header: 4 bytes
        // - PIDs start at offset 76
        let mut i = 76; // skip RTPS header + INFO submessages + DATA header + CDR header
        let mut found = false;
        while i + 4 <= packet.len() {
            let pid = u16::from_le_bytes([packet[i], packet[i + 1]]);
            let length = u16::from_le_bytes([packet[i + 2], packet[i + 3]]);
            i += 4;
            if pid == PID_METATRAFFIC_UNICAST_LOCATOR {
                assert_eq!(length, 24, "METATRAFFIC_UNICAST length must be 24");
                assert!(i + 24 <= packet.len(), "locator payload truncated");
                let kind = u32::from_le_bytes(packet[i..i + 4].try_into().expect("kind bytes"));
                let port = u32::from_le_bytes(packet[i + 4..i + 8].try_into().expect("port bytes"));
                let addr_tail: [u8; 4] =
                    packet[i + 20..i + 24].try_into().expect("addr tail bytes");
                assert_eq!(kind, 1, "locator kind must be UDPv4 (1)");
                assert_eq!(port, 7410, "locator port must be 7410 for metatraffic");
                assert_eq!(
                    addr_tail,
                    Ipv4Addr::new(192, 168, 1, 100).octets(),
                    "IPv4 must live in last 4 bytes of locator address"
                );
                found = true;
                break;
            }
            i += length as usize;
        }
        assert!(
            found,
            "PID_METATRAFFIC_UNICAST_LOCATOR not found in SPDP packet"
        );
    }

    /// A writer of a one-member @final struct, with its TypeObject.
    #[cfg(feature = "xtypes")]
    fn gate_sedp_data() -> SedpData {
        use crate::xtypes::{
            CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
            CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
            TypeIdentifier, TypeKind,
        };

        let type_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("GateT"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::primitive(TypeKind::TK_FLOAT32),
                },
                detail: CompleteMemberDetail::new("value"),
            }],
        });

        let guid = GUID::from_bytes([0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0x02]);
        SedpData {
            topic_name: "gate_topic".to_string(),
            type_name: "GateT".to_string(),
            participant_guid: guid,
            endpoint_guid: guid,
            qos_hash: 0,
            qos: None,
            type_object: Some(type_obj),
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            type_information: None,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// Locate the serializedPayload (PL_CDR_LE encapsulation) and parse it.
    #[cfg(feature = "xtypes")]
    fn parse_payload(packet: &[u8]) -> crate::protocol::discovery::types::SedpData {
        let encap = [0x00u8, 0x03, 0x00, 0x00];
        for off in 0..packet.len().saturating_sub(4) {
            if packet[off..off + 4] == encap {
                if let Ok(sd) = crate::protocol::discovery::sedp::parse::parse_sedp(&packet[off..])
                {
                    return sd;
                }
            }
        }
        panic!("SEDP payload must be locatable and parseable")
    }

    /// Destination gate: SEDP copies bound for non-HDDS peers (GUID
    /// prefix vendor bytes != 0x011A, RTPS v2.3 Sec 9.3.1.5) must omit
    /// PID_TYPE_OBJECT (0x0072), and so must destination-less copies, whose
    /// recipient is not known; HDDS-bound copies keep it. The HDDS-internal
    /// 0x0072 payload is not the spec TypeObject a foreign reader would
    /// decode.
    #[cfg(feature = "xtypes")]
    #[test]
    fn sedp_type_object_pid_gated_on_destination_vendor() {
        let sedp_data = gate_sedp_data();
        let our_prefix: [u8; 12] = [0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let hdds_peer: [u8; 12] = [0x01, 0x1A, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        let rti_peer: [u8; 12] = [0x01, 0x01, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];

        for dialect in [Dialect::Hybrid, Dialect::Hdds] {
            let to_rti = build_sedp_rtps_packet(
                &sedp_data,
                SedpEndpointKind::Writer,
                &our_prefix,
                Some(&rti_peer),
                1,
                dialect,
            )
            .expect("rti-bound packet must build");
            assert!(
                parse_payload(&to_rti).type_object.is_none(),
                "{dialect:?}: non-HDDS-bound SEDP must omit PID_TYPE_OBJECT"
            );

            let to_hdds = build_sedp_rtps_packet(
                &sedp_data,
                SedpEndpointKind::Writer,
                &our_prefix,
                Some(&hdds_peer),
                1,
                dialect,
            )
            .expect("hdds-bound packet must build");
            assert!(
                parse_payload(&to_hdds).type_object.is_some(),
                "{dialect:?}: HDDS-bound SEDP must keep PID_TYPE_OBJECT"
            );

            let no_dest = build_sedp_rtps_packet(
                &sedp_data,
                SedpEndpointKind::Writer,
                &our_prefix,
                None,
                1,
                dialect,
            )
            .expect("destination-less packet must build");
            assert!(
                parse_payload(&no_dest).type_object.is_none(),
                "{dialect:?}: destination-less SEDP must omit PID_TYPE_OBJECT"
            );
        }
    }

    /// The SHM capability hint goes to an HDDS peer whatever its prefix
    /// begins with: running DDS-Security, its prefix is bound to its
    /// certificate (DDS-Security 1.1 Sec.9.3.3, Table 52), not led by the
    /// vendor id, and it is known by the class discovery keeps for it. A
    /// recipient of that prefix that discovery does not class HDDS gets no
    /// hint.
    #[cfg(feature = "xtypes")]
    #[test]
    fn the_shm_hint_reaches_an_hdds_peer_whatever_its_prefix_begins_with() {
        let mut sedp_data = gate_sedp_data();
        sedp_data.shm_capability = Some("shm=1;host_id=0000abcd;v=1".to_string());
        let our_prefix: [u8; 12] = [0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let bound_peer: [u8; 12] = [0xbe, 0x8b, 0x4f, 0x5e, 0xe2, 0x4e, 9, 9, 9, 9, 9, 9];
        for (class, expected) in [
            (TypeObjectPid::Emit, true),
            (TypeObjectPid::Withhold, false),
        ] {
            let packet = build_sedp_rtps_packet_for(
                &sedp_data,
                SedpEndpointKind::Writer,
                &our_prefix,
                Some(&bound_peer),
                1,
                Dialect::Hybrid,
                class,
            )
            .expect("build");
            assert_eq!(
                parse_payload(&packet).shm_capability.is_some(),
                expected,
                "{:?}",
                class
            );
        }
    }

    /// The class of a recipient, from what its SPDP announced: only HDDS
    /// announcing the CAP_TYPE_OBJECT_SPEC_STRINGS bit gets PID_TYPE_OBJECT.
    /// 1.4.x (no capabilities), HDDS announcing capabilities without the bit,
    /// and every foreign vendor do not, whatever they say. HDDS is told by
    /// the vendor bytes of the GUID prefix first, PID_VENDORID second.
    #[test]
    fn type_object_pid_is_emitted_only_to_hdds_announcing_the_capability() {
        use crate::protocol::group::{CAP_SPEC_GROUP_COHERENT, CAP_TYPE_OBJECT_SPEC_STRINGS};
        let hdds_prefix = [0x01, 0x1A, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let other_prefix = [0x01, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let hdds = Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16);
        let cap = Some(CAP_TYPE_OBJECT_SPEC_STRINGS);
        assert_eq!(
            TypeObjectPid::of(&hdds_prefix, hdds, cap),
            TypeObjectPid::Emit
        );
        assert_eq!(
            TypeObjectPid::of(&hdds_prefix, None, cap),
            TypeObjectPid::Emit,
            "prefix"
        );
        assert_eq!(
            TypeObjectPid::of(&other_prefix, hdds, cap),
            TypeObjectPid::Emit,
            "PID"
        );
        assert_eq!(
            TypeObjectPid::of(&hdds_prefix, hdds, Some(u32::MAX)),
            TypeObjectPid::Emit
        );
        for caps in [None, Some(0), Some(CAP_SPEC_GROUP_COHERENT)] {
            assert_eq!(
                TypeObjectPid::of(&hdds_prefix, hdds, caps),
                TypeObjectPid::Withhold,
                "{caps:?}"
            );
        }
        assert_eq!(
            TypeObjectPid::of(&other_prefix, Some(0x0110), cap),
            TypeObjectPid::Withhold
        );
        assert_eq!(
            TypeObjectPid::of(&other_prefix, None, cap),
            TypeObjectPid::Withhold
        );
        assert_eq!(
            TypeObjectPid::of_destination(None),
            TypeObjectPid::Withhold,
            "no destination"
        );
    }

    /// The PIDs of the parameter list of the first DATA submessage of an
    /// SEDP datagram, read from the bytes.
    fn sedp_pids(packet: &[u8]) -> Vec<u16> {
        let mut pids = Vec::new();
        let mut at = 20; // RTPS header
        while at + 4 <= packet.len() {
            let id = packet[at];
            let len = usize::from(u16::from_le_bytes([packet[at + 2], packet[at + 3]]));
            if id == 0x15 {
                let body = at + 4;
                let to_inline =
                    usize::from(u16::from_le_bytes([packet[body + 2], packet[body + 3]]));
                // extraFlags + octetsToInlineQos, then the encapsulation.
                let mut p = body + 4 + to_inline + 4;
                while p + 4 <= body + len {
                    let pid = u16::from_le_bytes([packet[p], packet[p + 1]]);
                    let plen = usize::from(u16::from_le_bytes([packet[p + 2], packet[p + 3]]));
                    if pid == 0x0001 {
                        break;
                    }
                    pids.push(pid);
                    p += 4 + plen;
                }
                return pids;
            }
            at += 4 + len;
        }
        pids
    }

    /// A Withhold announcement leaves PID_TYPE_OBJECT (0x0072) out and keeps
    /// PID_TYPE_INFORMATION (0x0075), with which a 1.4.x reader matches; an
    /// Emit one carries both. Read from the datagram bytes, for every dialect
    /// an HDDS peer can be encoded with.
    #[cfg(feature = "xtypes")]
    #[test]
    fn a_withheld_type_object_keeps_the_type_information() {
        let sedp_data = gate_sedp_data();
        let our_prefix: [u8; 12] = [0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let peer: [u8; 12] = [0x01, 0x1A, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        for dialect in [Dialect::Hybrid, Dialect::Hdds] {
            for (class, with_object) in [
                (TypeObjectPid::Emit, true),
                (TypeObjectPid::Withhold, false),
            ] {
                for destination in [Some(&peer), None] {
                    let packet = build_sedp_rtps_packet_for(
                        &sedp_data,
                        SedpEndpointKind::Writer,
                        &our_prefix,
                        destination,
                        1,
                        dialect,
                        class,
                    )
                    .expect("packet must build");
                    let pids = sedp_pids(&packet);
                    assert_eq!(
                        pids.contains(&0x0072),
                        with_object,
                        "{dialect:?} {class:?} {destination:?}: {pids:04x?}"
                    );
                    assert!(
                        pids.contains(&0x0075),
                        "{dialect:?} {class:?} {destination:?}: {pids:04x?}"
                    );
                }
            }
        }
    }

    /// Discovery keeps the class a peer announced, the send paths read it:
    /// an HDDS peer without PID_HDDS_CAPABILITIES (1.4.x) is withheld the
    /// PID, one announcing it is sent it, an unknown one is withheld it.
    #[test]
    fn discovery_keeps_the_type_object_class_a_peer_announced() {
        use crate::core::discovery::multicast::DiscoveryFsm;
        use crate::protocol::discovery::spdp::SpdpData;
        let spdp = |prefix: [u8; 12], caps: Option<u32>| SpdpData {
            participant_guid: GUID::new(prefix, [0, 0, 1, 0xc1]),
            lease_duration_ms: 30_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            hdds_capabilities: caps,
            builtin_endpoint_set: None,
        };
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let old = [0x01, 0x1A, 1, 4, 8, 0, 0, 0, 0, 0, 0, 1];
        let new = [0x01, 0x1A, 1, 5, 0, 0, 0, 0, 0, 0, 0, 2];
        assert_eq!(fsm.type_object_pid_for(&new), None, "unknown");
        fsm.handle_spdp(spdp(old, None));
        fsm.handle_spdp(spdp(new, Some(crate::protocol::group::LOCAL_CAPABILITIES)));
        assert_eq!(fsm.type_object_pid_for(&old), Some(TypeObjectPid::Withhold));
        assert_eq!(fsm.type_object_pid_for(&new), Some(TypeObjectPid::Emit));
        // A later announcement without the PID changes nothing.
        fsm.handle_spdp(spdp(new, None));
        assert_eq!(fsm.type_object_pid_for(&new), Some(TypeObjectPid::Emit));
    }

    /// An announcement encoded for an OpenDDS peer carries the
    /// PID_TYPE_INFORMATION of the endpoint's own type, the value the
    /// generic path announces, and still no PID_TYPE_OBJECT.
    #[cfg(feature = "xtypes")]
    #[test]
    fn opendds_announcement_carries_the_endpoints_own_type_information() {
        let sedp_data = gate_sedp_data();
        let our_prefix: [u8; 12] = [0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let opendds_peer: [u8; 12] = [0x01, 0x03, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];
        let build = |dialect| {
            parse_payload(
                &build_sedp_rtps_packet(
                    &sedp_data,
                    SedpEndpointKind::Writer,
                    &our_prefix,
                    Some(&opendds_peer),
                    1,
                    dialect,
                )
                .expect("packet must build"),
            )
        };
        let opendds = build(Dialect::OpenDds);
        let generic = build(Dialect::Hdds);
        assert!(opendds.type_object.is_none(), "no PID_TYPE_OBJECT");
        let info = opendds.type_information.expect("PID_TYPE_INFORMATION");
        assert_eq!(Some(info), generic.type_information);

        // Without a TypeObject, none.
        let mut bare = gate_sedp_data();
        bare.type_object = None;
        let packet = build_sedp_rtps_packet(
            &bare,
            SedpEndpointKind::Writer,
            &our_prefix,
            Some(&opendds_peer),
            1,
            Dialect::OpenDds,
        )
        .expect("packet must build");
        assert!(parse_payload(&packet).type_information.is_none());
    }

    /// The PID_RELIABILITY (0x001a) a SEDP announcement carries: kind, then
    /// max_blocking_time as RTPS Duration_t (seconds, fraction in 2^-32 s).
    fn announced_reliability(packet: &[u8]) -> (u32, u32, u32) {
        let encap = [0x00u8, 0x03, 0x00, 0x00];
        let start = (0..packet.len().saturating_sub(4))
            .find(|&off| packet[off..off + 4] == encap)
            .expect("PL_CDR_LE payload");
        let mut i = start + 4;
        while i + 4 <= packet.len() {
            let pid = u16::from_le_bytes([packet[i], packet[i + 1]]);
            let length = usize::from(u16::from_le_bytes([packet[i + 2], packet[i + 3]]));
            i += 4;
            if pid == 0x0001 {
                break;
            }
            if pid == 0x001a {
                assert_eq!(length, 12, "PID_RELIABILITY is 12 octets");
                let word = |at: usize| {
                    u32::from_le_bytes(packet[i + at..i + at + 4].try_into().expect("4 bytes"))
                };
                return (word(0), word(4), word(8));
            }
            i += length;
        }
        panic!("no PID_RELIABILITY in the announcement")
    }

    /// RTPS v2.5 Sec.9.3.2 / DDS v1.4 Sec.2.2.3.14: the announced
    /// max_blocking_time is the writer's, in every dialect that builds a
    /// SEDP announcement (CoreDX, InterCOM, OpenSplice, GurumDDS and Dust
    /// refuse to, `UnsupportedDialect`): 1.5 s is
    /// (1, 0x8000_0000), the 100 ms default (0, 0x1999_999A), an infinite
    /// one (0x7FFF_FFFF, 0xFFFF_FFFF), never a fixed 100 ms regardless of the
    /// QoS (nor a fixed infinite value for OpenDDS).
    #[test]
    fn sedp_announces_the_configured_max_blocking_time() {
        let guid = GUID::from_bytes([0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0x02]);
        let our_prefix: [u8; 12] = [0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let cases = [
            (
                std::time::Duration::from_millis(1500),
                (1u32, 0x8000_0000u32),
            ),
            (std::time::Duration::from_millis(100), (0, 0x1999_999A)),
            (std::time::Duration::MAX, (0x7FFF_FFFF, 0xFFFF_FFFF)),
        ];
        for dialect in [
            Dialect::Hdds,
            Dialect::Hybrid,
            Dialect::FastDds,
            Dialect::Rti,
            Dialect::OpenDds,
            Dialect::CycloneDds,
        ] {
            for (wait, (sec, fraction)) in cases {
                let sedp_data = SedpData {
                    topic_name: "blocking_topic".to_string(),
                    type_name: "BlockingT".to_string(),
                    participant_guid: guid,
                    endpoint_guid: guid,
                    qos_hash: 0,
                    qos: Some(crate::dds::QoS::reliable().max_blocking_time(wait)),
                    type_object: None,
                    dependents: Vec::new(),
                    type_object_legacy_v1: false,
                    type_information: None,
                    unicast_locators: vec![],
                    user_data: None,
                    shm_capability: None,
                    has_explicit_reliability: true,
                    has_explicit_ownership: false,
                    has_ownership_strength: false,
                    type_consistency: None,
                    group_entity_id: None,
                    endpoint_security_info: None,
                };
                let packet = build_sedp_rtps_packet(
                    &sedp_data,
                    SedpEndpointKind::Writer,
                    &our_prefix,
                    None,
                    1,
                    dialect,
                )
                .unwrap_or_else(|e| panic!("{dialect:?}: {e:?}"));
                assert_eq!(
                    announced_reliability(&packet),
                    (2, sec, fraction),
                    "{dialect:?}, {wait:?}"
                );
            }
        }
    }

    /// The PID_DATA_REPRESENTATION sequence of one SEDP announcement,
    /// decoded from its bytes; `None` when the PID is absent.
    fn announced_data_representation_pid(packet: &[u8]) -> Option<Vec<u16>> {
        let encap = [0x00u8, 0x03, 0x00, 0x00];
        let start = (0..packet.len().saturating_sub(4))
            .find(|&off| packet[off..off + 4] == encap)
            .expect("PL_CDR_LE payload");
        let mut i = start + 4;
        while i + 4 <= packet.len() {
            let pid = u16::from_le_bytes([packet[i], packet[i + 1]]);
            let length = usize::from(u16::from_le_bytes([packet[i + 2], packet[i + 3]]));
            i += 4;
            if pid == 0x0001 {
                return None;
            }
            if pid == 0x0073 {
                let count = u32::from_le_bytes(packet[i..i + 4].try_into().expect("4 bytes"));
                let count = usize::try_from(count).expect("count fits usize");
                assert!(4 + 2 * count <= length, "sequence inside the parameter");
                return Some(
                    (0..count)
                        .map(|k| u16::from_le_bytes([packet[i + 4 + 2 * k], packet[i + 5 + 2 * k]]))
                        .collect(),
                );
            }
            i += length;
        }
        None
    }

    /// What an endpoint announces is what `announced_data_representation`
    /// says, the reading every local verdict applies: a writer its one
    /// representation (the first element; a writer of this participant
    /// that set no list was resolved to `[XCDR]` at creation, and an empty
    /// list here is the spec default `[XCDR]` too), a reader its whole list,
    /// `[XCDR, XCDR2]` when it set none. Decoded from the bytes, for a
    /// writer and a reader, in every dialect that builds an announcement.
    /// A writer that set no list must not announce `[XCDR, XCDR2]`, nor one
    /// that set `[XCDR2, XCDR]` both.
    #[test]
    fn a_default_endpoint_announces_what_the_local_verdict_reads() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let our_prefix: [u8; 12] = [0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let reader_default =
            crate::dds::cdr_negotiation::announced_data_representation(EndpointKind::Reader, &[]);
        assert_eq!(reader_default, &[0x0000, 0x0002]);
        let writer_default =
            crate::dds::cdr_negotiation::announced_data_representation(EndpointKind::Writer, &[]);
        assert_eq!(writer_default, &[0x0000]);
        let mut both_xcdr2_first = crate::dds::QoS::reliable();
        both_xcdr2_first.data_representation = vec![0x0002, 0x0000];
        for (kind, entity_kind) in [
            (SedpEndpointKind::Writer, 0x02u8),
            (SedpEndpointKind::Reader, 0x07u8),
        ] {
            let is_writer = kind == SedpEndpointKind::Writer;
            let expected_default = if is_writer {
                writer_default
            } else {
                reader_default
            };
            for dialect in [
                Dialect::Hdds,
                Dialect::Hybrid,
                Dialect::FastDds,
                Dialect::Rti,
                Dialect::OpenDds,
                Dialect::CycloneDds,
            ] {
                for (qos, expected) in [
                    (crate::dds::QoS::best_effort(), expected_default.to_vec()),
                    (crate::dds::QoS::reliable(), expected_default.to_vec()),
                    (
                        crate::dds::QoS::reliable().data_representation_xcdr2(),
                        vec![0x0002],
                    ),
                    (
                        crate::dds::QoS::reliable().data_representation_xcdr1(),
                        vec![0x0000],
                    ),
                    (
                        both_xcdr2_first.clone(),
                        if is_writer {
                            vec![0x0002]
                        } else {
                            vec![0x0002, 0x0000]
                        },
                    ),
                ] {
                    let guid = GUID::from_bytes([
                        0x01,
                        0x1A,
                        3,
                        4,
                        5,
                        6,
                        7,
                        8,
                        9,
                        10,
                        11,
                        12,
                        0,
                        0,
                        0,
                        entity_kind,
                    ]);
                    let sedp_data = SedpData {
                        topic_name: "datarep_topic".to_string(),
                        type_name: "DatarepT".to_string(),
                        participant_guid: guid,
                        endpoint_guid: guid,
                        qos_hash: 0,
                        qos: Some(qos),
                        type_object: None,
                        dependents: Vec::new(),
                        type_object_legacy_v1: false,
                        type_information: None,
                        unicast_locators: vec![],
                        user_data: None,
                        shm_capability: None,
                        has_explicit_reliability: true,
                        has_explicit_ownership: true,
                        has_ownership_strength: false,
                        type_consistency: None,
                        group_entity_id: None,
                        endpoint_security_info: None,
                    };
                    let packet =
                        build_sedp_rtps_packet(&sedp_data, kind, &our_prefix, None, 1, dialect)
                            .unwrap_or_else(|e| panic!("{dialect:?}: {e:?}"));
                    assert_eq!(
                        announced_data_representation_pid(&packet),
                        Some(expected),
                        "{kind:?} {dialect:?}"
                    );
                }
            }
        }
    }
}

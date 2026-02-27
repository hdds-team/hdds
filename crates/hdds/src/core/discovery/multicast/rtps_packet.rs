// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS packet construction for discovery (SPDP and SEDP).
//!
//!
//! This module provides functions to build complete RTPS packets with
//! proper headers and submessages, ensuring interoperability with
//! RTI Connext, FastDDS, and other DDS implementations.

use crate::core::rtps_constants::*;
use crate::protocol::dialect::{
    build_sedp_for_dialect, get_encoder, Dialect, Guid, QosProfile, SedpEndpointData,
};
use crate::protocol::discovery::{build_spdp, ParseError, SedpData, SpdpData};
#[cfg(feature = "xtypes")]
use crate::xtypes::CompleteTypeObject;
#[cfg(feature = "xtypes")]
use crate::Cdr2Encode;
use std::sync::atomic::AtomicU64;
use std::time::{SystemTime, UNIX_EPOCH};

/// Global SEDP sequence number counter (Reliable QoS requirement)
/// Shared by all SEDP endpoints (both Publications and Subscriptions writers)
/// DEPRECATED: Use SEDP_PUBLICATIONS_SEQ_NUM or SEDP_SUBSCRIPTIONS_SEQ_NUM instead
pub static SEDP_SEQ_NUM: AtomicU64 = AtomicU64::new(1);

/// SEDP Publications Writer sequence number counter (0x000003C2)
/// Per RTPS spec, each writer must maintain its own sequence number space.
/// v174: Split from shared SEDP_SEQ_NUM for correct reliable protocol.
pub static SEDP_PUBLICATIONS_SEQ_NUM: AtomicU64 = AtomicU64::new(0);

/// SEDP Subscriptions Writer sequence number counter (0x000004C2)
/// Per RTPS spec, each writer must maintain its own sequence number space.
/// v174: Split from shared SEDP_SEQ_NUM for correct reliable protocol.
pub static SEDP_SUBSCRIPTIONS_SEQ_NUM: AtomicU64 = AtomicU64::new(0);

/// Global HEARTBEAT counter for SEDP endpoints
pub static SEDP_HEARTBEAT_COUNT: AtomicU64 = AtomicU64::new(1);

/// Get the current lastSeq for SEDP Publications Writer
pub fn get_publications_last_seq() -> u64 {
    SEDP_PUBLICATIONS_SEQ_NUM.load(std::sync::atomic::Ordering::Relaxed)
}

/// Get the current lastSeq for SEDP Subscriptions Writer
pub fn get_subscriptions_last_seq() -> u64 {
    SEDP_SUBSCRIPTIONS_SEQ_NUM.load(std::sync::atomic::Ordering::Relaxed)
}

/// Allocate the next sequence number for SEDP Publications Writer
pub fn next_publications_seq() -> u64 {
    SEDP_PUBLICATIONS_SEQ_NUM.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// Allocate the next sequence number for SEDP Subscriptions Writer
pub fn next_subscriptions_seq() -> u64 {
    SEDP_SUBSCRIPTIONS_SEQ_NUM.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
}

/// RTPS SPDP built-in participant reader entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_READER = 0x000100C7)
const RTPS_ENTITYID_SPDP_READER: [u8; 4] = [0x00, 0x01, 0x00, 0xC7];

/// RTPS SPDP built-in participant writer entity ID (ENTITYID_SPDP_BUILTIN_RTPSParticipant_WRITER = 0x000100C2)
const RTPS_ENTITYID_SPDP_WRITER: [u8; 4] = [0x00, 0x01, 0x00, 0xC2];

// v91: REMOVED local duplicate constants (BIG ENDIAN bug!)
// Now using global LE constants from crate::core::rtps_constants::*
use crate::core::rtps_constants::{
    RTPS_ENTITYID_SEDP_PUBLICATIONS_READER, RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
    RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
    RTPS_ENTITYID_TYPELOOKUP_READER, RTPS_ENTITYID_TYPELOOKUP_WRITER,
};

/// Build INFO_DST submessage using DialectEncoder (RTPS v2.3 Sec.8.3.7.5)
///
/// Delegates to the dialect encoder for vendor-compatible INFO_DST encoding.
fn build_info_dst_submessage(guid_prefix: &[u8; 12]) -> Vec<u8> {
    // Use Hybrid encoder (conservative fallback) for discovery packets
    let encoder = get_encoder(Dialect::Hybrid);
    encoder.build_info_dst(guid_prefix)
}

/// Build INFO_TS submessage using DialectEncoder (RTPS v2.3 Sec.8.3.7.7)
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

    let seconds = duration.as_secs();
    let nanos = duration.subsec_nanos();

    // Convert seconds to u32 (RTPS timestamp format)
    let seconds_u32 = if seconds > u32::MAX as u64 {
        log::debug!("[RTPS] WARNING: Timestamp exceeds RTPS seconds range, clamping to u32::MAX");
        u32::MAX
    } else {
        seconds as u32
    };

    // Convert nanoseconds to RTPS fraction (2^32 * nanos / 1_000_000_000)
    let fraction = ((nanos as u64) << 32) / 1_000_000_000;
    let fraction_u32 = fraction as u32;

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
///   - Vendor ID: 0x01AA (HDDS experimental) - 2 bytes
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
/// v61 Blocker #5: Added destination_prefix parameter for unicast support
pub fn build_spdp_rtps_packet(
    spdp_data: &SpdpData,
    sequence_number: u64,
    destination_prefix: Option<&[u8; 12]>, // v61: None = multicast, Some = unicast to peer
) -> Result<Vec<u8>, ParseError> {
    // Step 1: Build SPDP CDR payload
    let mut payload_buf = vec![0u8; 8192];
    let payload_len = build_spdp(spdp_data, &mut payload_buf)?;

    // Step 2: Validate payload size (DialectEncoder handles submessage length)
    if payload_len > u16::MAX as usize - 24 {
        return Err(ParseError::BufferTooSmall);
    }

    // Step 3: Build INFO_DST and INFO_TS submessages
    // v61: Use peer GUID prefix for unicast, zeros for multicast
    let guid_prefix = destination_prefix.unwrap_or(&[0u8; 12]);
    let info_dst = build_info_dst_submessage(guid_prefix);
    let info_ts = build_info_ts_submessage();

    // Step 4: Build DATA submessage using DialectEncoder
    // v110: Migrated from manual construction to DialectEncoder::build_data()
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

    // ===== INFO_DST Submessage (16 bytes) - RTPS v2.3 Sec.8.3.7.5 =====
    packet.extend_from_slice(&info_dst);

    // ===== INFO_TS Submessage (12 bytes) - RTPS v2.3 Sec.8.3.7.7 =====
    packet.extend_from_slice(&info_ts);

    // ===== DATA Submessage (via DialectEncoder) =====
    packet.extend_from_slice(&data_submsg);

    Ok(packet)
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
/// };
///
/// let participant_prefix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// let packet = build_sedp_rtps_packet(&sedp_data, SedpEndpointKind::Writer, &participant_prefix)?;
/// // Send packet to 239.255.0.2:7400
/// ```
/// v61 Blocker #5: Added destination_prefix parameter for unicast support
pub fn build_sedp_rtps_packet(
    sedp_data: &SedpData,
    endpoint_kind: SedpEndpointKind,
    participant_guid_prefix: &[u8; 12],
    destination_prefix: Option<&[u8; 12]>, // v61: None = multicast, Some = unicast to peer
    seq_num: u64,                          // v72: Sequence number for Reliable QoS (must increment)
    dialect: Dialect,                      // Dialect for vendor-specific encoding
) -> Result<Vec<u8>, ParseError> {
    #[cfg(feature = "xtypes")]
    let type_object_bytes = build_type_object_for_dialect(sedp_data, dialect);
    #[cfg(feature = "xtypes")]
    {
        match (&type_object_bytes, dialect) {
            (Some(bytes), d) => log::debug!(
                "[SEDP-BUILD] dialect={:?} topic='{}' type_object_len={} bytes",
                d,
                sedp_data.topic_name,
                bytes.len()
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
    // Convert legacy SedpData to new SedpEndpointData format
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
        use crate::dds::qos::{Durability, History, Reliability};

        let (history_kind, history_depth) = match q.history {
            History::KeepLast(depth) => (0, depth), // KEEP_LAST
            History::KeepAll => (1, 0),             // KEEP_ALL
        };

        QosProfile {
            reliability_kind: match q.reliability {
                Reliability::BestEffort => 1, // BEST_EFFORT
                Reliability::Reliable => 2,   // RELIABLE
            },
            durability_kind: match q.durability {
                Durability::Volatile => 0,       // VOLATILE
                Durability::TransientLocal => 1, // TRANSIENT_LOCAL
                Durability::Persistent => 3,     // PERSISTENT
            },
            history_kind,
            history_depth,
            ..Default::default()
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
    };

    // Use dialect-specific encoder
    let payload =
        build_sedp_for_dialect(dialect, &endpoint_data).map_err(|_| ParseError::EncodingError)?;

    // Step 2: Validate payload size (DialectEncoder handles submessage length)
    if payload.len() > u16::MAX as usize - 24 {
        return Err(ParseError::BufferTooSmall);
    }

    // Step 3: Select entity IDs based on endpoint kind
    let (reader_id, writer_id) = match endpoint_kind {
        SedpEndpointKind::Writer => (
            RTPS_ENTITYID_SEDP_PUBLICATIONS_READER,
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER,
        ),
        SedpEndpointKind::Reader => (
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_READER,
            RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
        ),
    };

    // Step 4: Build DATA submessage using DialectEncoder
    // v110: Migrated from manual construction to DialectEncoder::build_data()
    let encoder = get_encoder(dialect);
    let data_submsg = encoder
        .build_data(&reader_id, &writer_id, seq_num, &payload, None)
        .map_err(|_| ParseError::EncodingError)?;

    // Step 5: Build INFO_TS submessage and optional INFO_DST
    //
    // For multicast SEDP (destination_prefix = None), do NOT send INFO_DST with
    // a GUIDPREFIX_UNKNOWN (all zeros). Some stacks (including FastDDS in certain
    // configurations) treat an explicit INFO_DST + unknown prefix as "not for me"
    // and drop the message before it reaches the EDP listeners. For multicast we
    // simply omit INFO_DST so that the default destination semantics apply.
    //
    // For unicast SEDP (destination_prefix = Some(peer_prefix)), we include
    // INFO_DST with the peer GUID prefix so that the MessageReceiver can route
    // the DATA submessage to the correct participant.
    let info_ts = build_info_ts_submessage();

    // v191: Get dialect-specific RTPS version and submessage ordering
    let (version_major, version_minor) = encoder.rtps_version();
    let info_ts_first = encoder.info_ts_before_info_dst();

    // v191: Build INFO_DST submessage for unicast
    let info_dst_data = destination_prefix.map(build_info_dst_submessage);

    // Step 6: Build complete RTPS packet
    // Packet size: 20 (header) + optional 16 (INFO_DST) + 12 (INFO_TS) + DATA submessage
    let mut packet = Vec::with_capacity(
        20 + if info_dst_data.is_some() { 16 } else { 0 } + 12 + data_submsg.len(),
    );

    // ===== RTPS Header (20 bytes) =====
    packet.extend_from_slice(RTPS_MAGIC); // Magic (4 bytes)
                                          // v191: Use dialect-specific RTPS version (OpenDDS uses 2.4, others use 2.3)
    packet.extend_from_slice(&[version_major, version_minor]); // Version (2 bytes)
    packet.extend_from_slice(&HDDS_VENDOR_ID); // Vendor ID (2 bytes)
    packet.extend_from_slice(&participant_guid_prefix[0..12]); // GUID prefix (12 bytes)

    // v191: Dialect-specific submessage ordering
    // OpenDDS: INFO_TS -> INFO_DST -> DATA
    // Default (HDDS/RTI/FastDDS): INFO_DST -> INFO_TS -> DATA
    if info_ts_first {
        // ===== INFO_TS Submessage (12 bytes) - OpenDDS style =====
        packet.extend_from_slice(&info_ts);

        // ===== INFO_DST Submessage (16 bytes) - unicast only =====
        if let Some(info_dst) = &info_dst_data {
            packet.extend_from_slice(info_dst);
        }
    } else {
        // ===== INFO_DST Submessage (16 bytes) - RTPS v2.3 Sec.8.3.7.5 (unicast only) =====
        if let Some(info_dst) = &info_dst_data {
            packet.extend_from_slice(info_dst);
        }

        // ===== INFO_TS Submessage (12 bytes) - RTPS v2.3 Sec.8.3.7.7 =====
        packet.extend_from_slice(&info_ts);
    }

    // ===== DATA Submessage (via DialectEncoder) =====
    packet.extend_from_slice(&data_submsg);

    Ok(packet)
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
            &RTPS_ENTITYID_TYPELOOKUP_READER,
            &RTPS_ENTITYID_TYPELOOKUP_WRITER,
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
#[cfg(feature = "xtypes")]
fn build_type_object_for_dialect(sedp_data: &SedpData, dialect: Dialect) -> Option<Vec<u8>> {
    let type_obj = sedp_data.type_object.as_ref()?;
    match dialect {
        Dialect::Hdds | Dialect::Hybrid => encode_type_object_cdr2(type_obj).ok(),
        _ => None,
    }
}

#[cfg(not(feature = "xtypes"))]
fn build_type_object_for_dialect(_sedp_data: &SedpData, _dialect: Dialect) -> Option<Vec<u8>> {
    None
}

/// Build HEARTBEAT submessage using DialectEncoder (RTPS v2.5 Sec.8.3.7.5)
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
/// v173: The Final flag is CRITICAL for RTI interop - it tells RTI not to
/// respond with ACKNACK, which prevents the infinite HEARTBEAT/ACKNACK loop.
/// Without Final=true, RTI sends ACKNACK for every HEARTBEAT, causing a storm.
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
        };

        let packet = build_spdp_rtps_packet(&spdp_data, 1, None).expect("Failed to build");

        verify_rtps_header(&packet, &guid);
        verify_info_submessages(&packet);
        verify_data_submessage(&packet);

        // Packet size validation (v82+ with extended PIDs)
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
}

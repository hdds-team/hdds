// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Properties and QoS PID Handlers for SPDP
//!
//!
//! Handles parsing of participant properties and QoS-related PIDs:
//! - PID_PARTICIPANT_LEASE_DURATION (0x0002)
//! - PID_BUILTIN_ENDPOINT_SET (0x0058)
//! - PID_PROPERTY_LIST (0x0059)
//! - PID_ENTITY_NAME (0x0062)

use crate::protocol::discovery::types::ParseError;

/// Parse PID_PARTICIPANT_LEASE_DURATION (0x0002)
///
/// The lease duration specifies how long the participant announcement is valid.
/// If no new announcement is received within this period, the participant is
/// considered to have left the network.
///
/// # Structure (8 bytes)
/// ```text
/// struct Duration_t {
///   long seconds;     // 4 bytes: seconds (endian-sensitive)
///   unsigned long fraction; // 4 bytes: nanosecond fraction (2^-32 seconds)
/// };
/// ```
///
/// Default: 100 seconds (per RTPS v2.3 Sec.8.5.4.1)
pub(super) fn parse_participant_lease_duration_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
    lease_duration_ms: &mut u64,
) -> Result<(), ParseError> {
    if length >= 8 {
        let seconds = if is_little_endian {
            u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ])
        } else {
            u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ])
        };
        *lease_duration_ms = seconds as u64 * 1000;
    }
    Ok(())
}

/// Parse PID_BUILTIN_ENDPOINT_SET (0x0058)
///
/// Phase 1.6: Parse builtin endpoint mask for debugging.
/// Shows which SEDP endpoints remote participant supports.
///
/// # BuiltinEndpointSet_t Bitmask (RTPS v2.3 Table 9.12)
/// - Bit 0 (0x00000001): SPDPbuiltinParticipantWriter
/// - Bit 1 (0x00000002): SPDPbuiltinParticipantReader
/// - Bit 2 (0x00000004): SEDPbuiltinPublicationsWriter (CRITICAL for receiving SEDP!)
/// - Bit 3 (0x00000008): SEDPbuiltinPublicationsReader
/// - Bit 4 (0x00000010): SEDPbuiltinSubscriptionsWriter
/// - Bit 5 (0x00000020): SEDPbuiltinSubscriptionsReader
/// - Bit 10 (0x00000400): ParticipantMessageDataWriter
/// - Bit 11 (0x00000800): ParticipantMessageDataReader
///
/// Standard value: 0x00003f (bits 0-5)
/// RTI sends: 0x00000c3f (includes bits 10-11 for ParticipantMessage)
pub(super) fn parse_builtin_endpoint_set_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Result<(), ParseError> {
    if length >= 4 {
        let mask = if is_little_endian {
            u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ])
        } else {
            u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ])
        };
        log::debug!(
            "[spdp] Remote participant builtin endpoints: 0x{:08x}",
            mask
        );
        // Bit 2 (0x04) = SEDPbuiltinPublicationsWriter (CRITICAL for receiving SEDP!)
        if mask & 0x04 != 0 {
            log::debug!("[spdp]   [OK] Has SEDPbuiltinPublicationsWriter");
        }
        // Bit 3 (0x08) = SEDPbuiltinPublicationsReader
        if mask & 0x08 != 0 {
            log::debug!("[spdp]   [OK] Has SEDPbuiltinPublicationsReader");
        }
        // Bit 4 (0x10) = SEDPbuiltinSubscriptionsWriter
        if mask & 0x10 != 0 {
            log::debug!("[spdp]   [OK] Has SEDPbuiltinSubscriptionsWriter");
        }
        // Bit 5 (0x20) = SEDPbuiltinSubscriptionsReader
        if mask & 0x20 != 0 {
            log::debug!("[spdp]   [OK] Has SEDPbuiltinSubscriptionsReader");
        }
    }
    Ok(())
}

/// Parse PID_PROPERTY_LIST (0x0059)
///
/// Properties (sequence of Property_t); skip content but don't warn.
/// Properties are used for vendor-specific configuration and metadata.
///
/// # Structure
/// ```text
/// struct Property_t {
///   string name;
///   string value;
/// };
/// sequence<Property_t> PropertySeq;
/// ```
pub(super) fn parse_property_list_pid(
    _buf: &[u8],
    _offset: usize,
    length: usize,
) -> Result<(), ParseError> {
    // Properties (sequence of Property_t); skip content but don't warn
    log::debug!("[spdp] Property list ({} bytes)", length);
    Ok(())
}

/// Parse PID_ENTITY_NAME (0x0062)
///
/// Participant name (string parameter), parse for diagnostics.
/// This is a human-readable name assigned to the participant,
/// useful for debugging and monitoring.
///
/// # Structure
/// ```text
/// struct EntityName_t {
///   long length;     // 4 bytes: string length (includes null terminator)
///   char name[length]; // Variable: UTF-8 string
/// };
/// ```
pub(super) fn parse_entity_name_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
) -> Result<(), ParseError> {
    if length >= 4 {
        let str_len = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]) as usize;
        if length >= 4 + str_len && str_len > 0 && offset + 4 + str_len <= buf.len() {
            if let Ok(name) = std::str::from_utf8(&buf[offset + 4..offset + 4 + str_len - 1]) {
                log::debug!("[spdp] Participant name: {}", name);
            }
        }
    }
    Ok(())
}

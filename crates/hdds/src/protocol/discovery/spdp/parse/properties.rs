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
    if length < 8 {
        return Err(ParseError::TruncatedData);
    }
    let end = offset.checked_add(8).ok_or(ParseError::TruncatedData)?;
    let duration = buf.get(offset..end).ok_or(ParseError::TruncatedData)?;
    let seconds = if is_little_endian {
        i32::from_le_bytes([duration[0], duration[1], duration[2], duration[3]])
    } else {
        i32::from_be_bytes([duration[0], duration[1], duration[2], duration[3]])
    };
    let fraction = if is_little_endian {
        u32::from_le_bytes([duration[4], duration[5], duration[6], duration[7]])
    } else {
        u32::from_be_bytes([duration[4], duration[5], duration[6], duration[7]])
    };

    if seconds == i32::MAX && fraction == u32::MAX {
        *lease_duration_ms = u64::MAX;
        return Ok(());
    }
    if seconds < 0 {
        return Err(ParseError::InvalidFormat);
    }

    // Round a non-zero RTPS fraction up to milliseconds so a positive
    // sub-second lease never aliases the zero-duration dispose sentinel.
    let fractional_ms = if fraction == 0 {
        0
    } else {
        ((u64::from(fraction) * 1000) + ((1u64 << 32) - 1)) >> 32
    };
    *lease_duration_ms = (seconds as u64)
        .saturating_mul(1000)
        .saturating_add(fractional_ms);
    Ok(())
}

/// Parse PID_BUILTIN_ENDPOINT_SET (0x0058)
///
/// Parse builtin endpoint mask for debugging.
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
/// Common value: 0x00000c3f (adds bits 10-11 for ParticipantMessage)
pub(super) fn parse_builtin_endpoint_set_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Result<Option<u32>, ParseError> {
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
        return Ok(Some(mask));
    }
    Ok(None)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participant_lease_decodes_rtps_fraction_and_infinite() {
        let mut lease_ms = 0;
        let half_second = [0, 0, 0, 0, 0, 0, 0, 0x80];
        parse_participant_lease_duration_pid(&half_second, 0, 8, true, &mut lease_ms).unwrap();
        assert_eq!(lease_ms, 500);

        let half_second_big_endian = [0, 0, 0, 0, 0x80, 0, 0, 0];
        parse_participant_lease_duration_pid(&half_second_big_endian, 0, 8, false, &mut lease_ms)
            .unwrap();
        assert_eq!(lease_ms, 500);

        let one_fraction_tick = [0, 0, 0, 0, 1, 0, 0, 0];
        parse_participant_lease_duration_pid(&one_fraction_tick, 0, 8, true, &mut lease_ms)
            .unwrap();
        assert_eq!(lease_ms, 1, "a positive lease must not decode as dispose");

        let infinite = [0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff];
        parse_participant_lease_duration_pid(&infinite, 0, 8, true, &mut lease_ms).unwrap();
        assert_eq!(lease_ms, u64::MAX);
    }

    #[test]
    fn participant_lease_rejects_negative_and_truncated_duration() {
        let mut lease_ms = 100_000;
        let negative = [0xff; 8];
        assert_eq!(
            parse_participant_lease_duration_pid(&negative, 0, 8, true, &mut lease_ms),
            Err(ParseError::InvalidFormat)
        );
        assert_eq!(
            parse_participant_lease_duration_pid(&[0; 4], 0, 8, true, &mut lease_ms),
            Err(ParseError::TruncatedData)
        );
        assert_eq!(
            parse_participant_lease_duration_pid(&[0; 8], 0, 4, true, &mut lease_ms),
            Err(ParseError::TruncatedData)
        );
    }
}

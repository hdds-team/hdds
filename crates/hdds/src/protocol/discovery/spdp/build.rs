// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP Building Functions
//!
//! Implements building of SPDP (Simple Participant Discovery Protocol) messages
//! according to DDS-RTPS v2.3 Sec.8.5.4 specification.

use crate::protocol::discovery::constants::{
    BUILTIN_ENDPOINT_SET_DEFAULT, BUILTIN_ENDPOINT_SET_SECURITY, PID_BUILTIN_ENDPOINT_SET,
    PID_DEFAULT_MULTICAST_LOCATOR, PID_DEFAULT_UNICAST_LOCATOR, PID_DOMAIN_ID, PID_IDENTITY_TOKEN,
    PID_METATRAFFIC_UNICAST_LOCATOR, PID_PARTICIPANT_GUID, PID_PARTICIPANT_LEASE_DURATION,
    PID_PARTICIPANT_SECURITY_INFO, PID_PERMISSIONS_TOKEN, PID_PROPERTY_LIST, PID_PROTOCOL_VERSION,
    PID_SENTINEL, PID_VENDOR_ID,
};
// Removed PID_BUILTIN_ENDPOINT_QOS and BUILTIN_ENDPOINT_QOS_DEFAULT
// The PID is optional; we omit it.
// Info: vendor-specific PIDs (0x8000+) removed from generic builder.
// PID_PRODUCT_VERSION, PID_RTI_DOMAIN_ID, PID_TRANSPORT_INFO_LIST,
// PID_REACHABILITY_LEASE_DURATION, PID_VENDOR_BUILTIN_ENDPOINT_SET
// These belong ONLY in the vendor id 0x0101 dialect encoder (protocol/dialect/rti/).
use crate::protocol::discovery::spdp::types::SpdpData;
use crate::protocol::discovery::types::{parameter_length, wire_u32, ParseError};
/// Build SPDP participant announcement packet.
///
/// # Arguments
/// - `spdp_data`: Participant metadata (GUID, lease duration, locators).
/// - `buf`: Destination buffer that receives the RTPS parameter list.
///
/// # Returns
/// Number of bytes written to `buf`.
///
/// # Errors
/// - `ParseError::BufferTooSmall` when the output buffer cannot hold the encoding.
pub fn build_spdp(spdp_data: &SpdpData, buf: &mut [u8]) -> Result<usize, ParseError> {
    let mut offset = 0;

    if buf.len() < 4 {
        return Err(ParseError::BufferTooSmall);
    }
    // CDR encapsulation header (ALWAYS big-endian per CDR spec)
    // 0x0003 = PL_CDR_LE (Parameter List, Little-Endian data)
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset += 4;

    // SPDP PID order:
    // PROTOCOL_VERSION, VENDOR_ID, PARTICIPANT_GUID, BUILTIN_ENDPOINT_SET, ...

    // Position 1: PID_PROTOCOL_VERSION (MANDATORY per RTPS v2.3 Table 8.73)
    if offset + 4 + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_PROTOCOL_VERSION.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
    offset += 4;
    buf[offset] = 2; // RTPS major version 2
                     // Changed from 3 to 4: PID_PROTOCOL_VERSION announces
                     // the same version as the message header (v2.4 per v192).
    buf[offset + 1] = 4; // RTPS minor version 4 (RTPS v2.4)
    buf[offset + 2] = 0; // padding
    buf[offset + 3] = 0; // padding
    offset += 4;

    // Position 2: PID_VENDOR_ID (MANDATORY per RTPS v2.3 Table 8.73)
    if offset + 4 + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_VENDOR_ID.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
    offset += 4;
    buf[offset] = 0x01; // HDDS vendor ID byte 0
    buf[offset + 1] = 0x1a; // HDDS vendor ID byte 1
    buf[offset + 2] = 0; // padding
    buf[offset + 3] = 0; // padding
    offset += 4;

    // Position 3: PID_PARTICIPANT_GUID
    if offset + 4 + 16 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_PARTICIPANT_GUID.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&16u16.to_le_bytes());
    offset += 4;
    buf[offset..offset + 16].copy_from_slice(&spdp_data.participant_guid.as_bytes());
    offset += 16;

    // Position 4: PID_BUILTIN_ENDPOINT_SET (CRITICAL for cross-vendor interop)
    // RTPS v2.3 spec section 9.3.2, Table 9.12
    if offset + 4 + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_BUILTIN_ENDPOINT_SET.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes()); // uint32 = 4 bytes
    offset += 4;
    // When PID_PARTICIPANT_SECURITY_INFO is present the participant is
    // security-enabled; OR in the secure builtin endpoints it serves
    // (`BUILTIN_ENDPOINT_SET_SECURITY`, DDS Security v1.1 Sec.7.4.1.4
    // Table 11), and only those.
    #[allow(unused_mut)]
    let mut builtin_ep_set = if spdp_data.participant_security_info.is_some() {
        BUILTIN_ENDPOINT_SET_DEFAULT | BUILTIN_ENDPOINT_SET_SECURITY
    } else {
        BUILTIN_ENDPOINT_SET_DEFAULT
    };
    // TypeLookup Service endpoints (BuiltinEndpointSet bits 12-15, mask 0xF000)
    // per DDS-XTypes v1.3 Table 7.6.3.3.4.1. This is the GENERIC multicast SPDP
    // build -- the one actually on the wire (the per-dialect spdp builders are
    // not on the live multicast path). Advertised only when the OMG TypeLookup
    // serve path is compiled in, so cross-vendor writers know to fetch HDDS's
    // dependency TypeObjects. Default OFF => shipped SPDP wire byte-identical.
    #[cfg(feature = "xtypes-structural-assignability")]
    {
        builtin_ep_set |= 0x0000_F000;
    }
    buf[offset..offset + 4].copy_from_slice(&builtin_ep_set.to_le_bytes());
    offset += 4;

    // REMOVED PID_BUILTIN_ENDPOINT_QOS (0x0077)
    // The PID is optional and we omit it.

    // CRITICAL - Write locators BEFORE PID_PROPERTY_LIST!
    // PID_PROPERTY_LIST is 400+ bytes and can cause packet truncation.
    // Locators MUST be early in the packet to ensure they're always received.

    // Position 6: PID_DEFAULT_UNICAST_LOCATOR (0x0031) [MANDATORY] - Port 7411 for USER DATA
    for locator in &spdp_data.default_unicast_locators {
        crate::protocol::rtps::encode_locator_parameter(
            PID_DEFAULT_UNICAST_LOCATOR,
            locator,
            buf,
            &mut offset,
        )
        .map_err(|_| ParseError::BufferTooSmall)?;
    }

    // Position 7: PID_METATRAFFIC_UNICAST_LOCATOR (0x0032) - Port 7410 for SEDP/ACKNACK
    for locator in &spdp_data.metatraffic_unicast_locators {
        crate::protocol::rtps::encode_locator_parameter(
            PID_METATRAFFIC_UNICAST_LOCATOR,
            locator,
            buf,
            &mut offset,
        )
        .map_err(|_| ParseError::BufferTooSmall)?;
    }

    // Position 8: PID_METATRAFFIC_MULTICAST_LOCATOR (0x0033) - still not
    // announced (no measured need; SPDP itself proves the metatraffic group
    // reachable).
    // for locator in &spdp_data.metatraffic_multicast_locators {
    //     write_locator(buf, &mut offset, PID_METATRAFFIC_MULTICAST_LOCATOR, locator)?;
    // }

    // Position 9: PID_DEFAULT_MULTICAST_LOCATOR (0x0048).
    // Announced because a peer
    // may decide whether to receive user data from this participant over
    // multicast from this parameter: without it, a peer that sends to its
    // own announced default multicast group can have the matching receive
    // path unarmed for HDDS, and large payloads on that group are never
    // read. The parameter is ParticipantProxy::defaultMulticastLocatorList
    // (RTPS 2.5 Table 9.19 maps it).
    for locator in &spdp_data.default_multicast_locators {
        crate::protocol::rtps::encode_locator_parameter(
            PID_DEFAULT_MULTICAST_LOCATOR,
            locator,
            buf,
            &mut offset,
        )
        .map_err(|_| ParseError::BufferTooSmall)?;
    }

    // Position 10+: optional participant metadata.
    // Retain the existing non-timestamp fields. Do not advertise timestamps
    // unless they are backed by real lifecycle data.
    {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "hdds-host".to_string());
        let process_id = std::process::id().to_string();

        // Get executable path from std::env::current_exe()
        let executable_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "/usr/bin/hdds".to_string());

        // Target platform (e.g., "x86_64_linux")
        let target = format!("{}_{}", std::env::consts::ARCH, std::env::consts::OS);

        // Username
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "hdds-user".to_string());

        let properties = [
            ("dds.sys_info.hostname", hostname.as_str()),
            ("dds.sys_info.process_id", process_id.as_str()),
            ("dds.sys_info.executable_filepath", executable_path.as_str()),
            ("dds.sys_info.target", target.as_str()),
            ("dds.sys_info.username", username.as_str()),
        ];

        // Format: num_properties(4) followed by Property_t values.
        // Each property: name_len(4) + name_bytes(aligned) + value_len(4) + value_bytes(aligned)

        let align_4 = |len: usize| (len + 3) & !3; // Round up to multiple of 4

        // Helper to calculate property size
        let calc_prop_size = |name: &str, value: &str| {
            let name_len = name.len() + 1;
            let name_aligned = align_4(name_len);
            let value_len = value.len() + 1;
            let value_aligned = align_4(value_len);
            4 + name_aligned + 4 + value_aligned
        };

        let total_properties_size = 4 + properties
            .iter()
            .map(|(name, value)| calc_prop_size(name, value))
            .sum::<usize>();

        // Write PID_PROPERTY_LIST header
        let param_len = parameter_length(total_properties_size)?;
        if offset + 4 + total_properties_size > buf.len() {
            return Err(ParseError::BufferTooSmall);
        }
        buf[offset..offset + 2].copy_from_slice(&PID_PROPERTY_LIST.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&param_len.to_le_bytes());
        offset += 4;

        let property_count = wire_u32(properties.len())?;
        buf[offset..offset + 4].copy_from_slice(&property_count.to_le_bytes());
        offset += 4;

        // Helper to write a property
        let mut write_property = |name: &str, value: &str| -> Result<(), ParseError> {
            let name_len = name.len() + 1;
            let name_aligned = align_4(name_len);
            let value_len = value.len() + 1;
            let value_aligned = align_4(value_len);

            if offset + 4 + name_aligned + 4 + value_aligned > buf.len() {
                return Err(ParseError::BufferTooSmall);
            }

            // Write name length and name
            buf[offset..offset + 4].copy_from_slice(&wire_u32(name_len)?.to_le_bytes());
            offset += 4;
            buf[offset..offset + name.len()].copy_from_slice(name.as_bytes());
            buf[offset + name.len()] = 0; // null terminator
                                          // Zero-fill padding
            for i in name_len..name_aligned {
                buf[offset + i] = 0;
            }
            offset += name_aligned;

            // Write value length and value
            buf[offset..offset + 4].copy_from_slice(&wire_u32(value_len)?.to_le_bytes());
            offset += 4;
            buf[offset..offset + value.len()].copy_from_slice(value.as_bytes());
            buf[offset + value.len()] = 0; // null terminator
                                           // Zero-fill padding
            for i in value_len..value_aligned {
                buf[offset + i] = 0;
            }
            offset += value_aligned;

            Ok(())
        };

        for (name, value) in properties {
            write_property(name, value)?;
        }
    }

    // Locators already written BEFORE PID_PROPERTY_LIST (lines 651-669)
    // This ensures they're always in the packet even if PROPERTY_LIST causes truncation.

    // Position N: PID_PARTICIPANT_LEASE_DURATION
    if offset + 4 + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_PARTICIPANT_LEASE_DURATION.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&8u16.to_le_bytes());
    offset += 4;

    // RTPS Duration_t carries seconds as a signed 32-bit field, so the
    // saturated value is i32::MAX. Widening a positive compile-time constant
    // to u32 keeps its value.
    const DURATION_SECONDS_MAX: u32 = i32::MAX as u32; // @audit-ok: positive literal constant, u32 holds it exactly
    let (seconds, fraction) = if spdp_data.lease_duration_ms == u64::MAX {
        (DURATION_SECONDS_MAX, u32::MAX)
    } else {
        // A lease past i32::MAX seconds saturates. The conversion decides,
        // not a comparison followed by a cast.
        match u32::try_from(spdp_data.lease_duration_ms / 1000) {
            Ok(whole_seconds) if whole_seconds <= DURATION_SECONDS_MAX => {
                let remaining_ms = spdp_data.lease_duration_ms % 1000;
                // RTPS Duration_t stores 2^-32 second units, not nanoseconds.
                // `% 1000` bounds remaining_ms at 999 and (999 << 32) / 1000 =
                // 4_290_672_328 fits a u32, so the conversion succeeds; it is
                // still a conversion, and a failure would be an encoding
                // error rather than a wrapped fraction. Asserted by
                // `a_999_ms_lease_remainder_fills_the_fraction_without_wrapping`.
                let fraction = u32::try_from((remaining_ms << 32) / 1000)
                    .map_err(|_| ParseError::EncodingError)?;
                (whole_seconds, fraction)
            }
            _ => {
                log::debug!(
                    "[spdp] Lease duration {} ms exceeds RTPS Duration_t; clamping",
                    spdp_data.lease_duration_ms
                );
                (DURATION_SECONDS_MAX, u32::MAX)
            }
        }
    };
    buf[offset..offset + 4].copy_from_slice(&seconds.to_le_bytes());
    buf[offset + 4..offset + 8].copy_from_slice(&fraction.to_le_bytes());
    offset += 8;

    // Standard PID_DOMAIN_ID must trail the lease duration and lead the vendor block
    if offset + 4 + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_DOMAIN_ID.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&spdp_data.domain_id.to_le_bytes()); // use actual domain_id
    offset += 4;

    // DDS Security v1.1 sec. 7.4.1.4: PID_IDENTITY_TOKEN (0x1001) and
    // PID_PERMISSIONS_TOKEN (0x1007) carry serialized DataHolder structures
    // (sec. 7.2.4). Length is the parameter value length aligned to 4 bytes
    // (RTPS v2.5 sec. 9.4.2.11).
    let write_token =
        |buf: &mut [u8], offset: &mut usize, pid: u16, bytes: &[u8]| -> Result<(), ParseError> {
            let aligned_len = (bytes.len() + 3) & !3;
            let param_len = parameter_length(aligned_len)?;
            if *offset + 4 + aligned_len > buf.len() {
                return Err(ParseError::BufferTooSmall);
            }
            buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
            buf[*offset + 2..*offset + 4].copy_from_slice(&param_len.to_le_bytes());
            *offset += 4;
            buf[*offset..*offset + bytes.len()].copy_from_slice(bytes);
            for i in bytes.len()..aligned_len {
                buf[*offset + i] = 0;
            }
            *offset += aligned_len;
            Ok(())
        };

    if let Some(ref token) = spdp_data.identity_token {
        write_token(buf, &mut offset, PID_IDENTITY_TOKEN, token)?;
    }
    if let Some(ref token) = spdp_data.permissions_token {
        write_token(buf, &mut offset, PID_PERMISSIONS_TOKEN, token)?;
    }

    // DDS Security v1.1 sec. 7.4.1.5 PID_PARTICIPANT_SECURITY_INFO (0x1005)
    // is required so a remote participant recognizes us as security-aware
    // and starts the PKI-DH handshake. Without it the IdentityToken /
    // PermissionsToken alone are not sufficient.
    if let Some(info) = spdp_data.participant_security_info {
        if offset + 4 + 8 > buf.len() {
            return Err(ParseError::BufferTooSmall);
        }
        buf[offset..offset + 2].copy_from_slice(&PID_PARTICIPANT_SECURITY_INFO.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&8u16.to_le_bytes());
        offset += 4;
        buf[offset..offset + 8].copy_from_slice(&info);
        offset += 8;
    }

    // Info: a PID in the vendor range is interpreted relative to the
    // sender's vendor id (DDSI-RTPS 2.5 Sec.9.4.2.11), so HDDS (vendor 0x011A)
    // emits only its own (here PID_HDDS_CAPABILITIES), never PIDs whose
    // meaning belongs to another vendor (e.g. 0x0101).
    if let Some(capabilities) = spdp_data.hdds_capabilities {
        if offset + 4 + 4 > buf.len() {
            return Err(ParseError::BufferTooSmall);
        }
        buf[offset..offset + 2].copy_from_slice(
            &crate::protocol::discovery::constants::PID_HDDS_CAPABILITIES.to_le_bytes(),
        );
        buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&capabilities.to_le_bytes());
        offset += 4;
    }

    // Position N+1 (final): PID_SENTINEL (marks end of parameter list)
    if offset + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_SENTINEL.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&0u16.to_le_bytes());
    offset += 4;

    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;

    fn read_cdr_string(bytes: &[u8], offset: &mut usize) -> String {
        let length = u32::from_le_bytes(
            bytes[*offset..*offset + 4]
                .try_into()
                .expect("CDR string length"),
        ) as usize;
        *offset += 4;
        assert!(length > 0, "CDR strings include a null terminator");
        let value = std::str::from_utf8(&bytes[*offset..*offset + length - 1])
            .expect("UTF-8 property")
            .to_string();
        *offset += (length + 3) & !3;
        value
    }

    /// The `PID_BUILTIN_ENDPOINT_SET` an announcement carries.
    fn announced_builtin_endpoints(security_info: Option<[u8; 8]>) -> u32 {
        let data = SpdpData {
            participant_guid: GUID::new([0x11; 12], [0x00, 0x00, 0x01, 0xc1]),
            lease_duration_ms: 10_000,
            domain_id: 0,
            metatraffic_unicast_locators: Vec::new(),
            default_unicast_locators: Vec::new(),
            default_multicast_locators: Vec::new(),
            metatraffic_multicast_locators: Vec::new(),
            identity_token: None,
            permissions_token: None,
            participant_security_info: security_info,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        let mut packet = vec![0u8; 2048];
        let written = build_spdp(&data, &mut packet).expect("build SPDP");
        packet.truncate(written);
        let mut offset = 4usize;
        while offset + 4 <= packet.len() {
            let pid = u16::from_le_bytes([packet[offset], packet[offset + 1]]);
            let length = u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
            offset += 4;
            if pid == PID_BUILTIN_ENDPOINT_SET {
                return u32::from_le_bytes(
                    packet[offset..offset + 4].try_into().expect("four octets"),
                );
            }
            assert_ne!(pid, PID_SENTINEL, "no PID_BUILTIN_ENDPOINT_SET");
            offset += length;
        }
        panic!("no PID_BUILTIN_ENDPOINT_SET");
    }

    /// The builtin endpoints an announcement names are read back on
    /// receive, the participant-message writer and reader (bits 10 and 11,
    /// RTPS v2.5 Sec.8.4.13) among them.
    #[test]
    fn the_announced_endpoints_are_read_back() {
        let data = SpdpData {
            participant_guid: GUID::new([0x12; 12], [0x00, 0x00, 0x01, 0xc1]),
            lease_duration_ms: 10_000,
            domain_id: 0,
            metatraffic_unicast_locators: Vec::new(),
            default_unicast_locators: Vec::new(),
            default_multicast_locators: Vec::new(),
            metatraffic_multicast_locators: Vec::new(),
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        let mut packet = vec![0u8; 2048];
        let written = build_spdp(&data, &mut packet).expect("build SPDP");
        let parsed = crate::protocol::discovery::parse_spdp(&packet[..written]).expect("parse");
        let set = parsed.builtin_endpoint_set.expect("announced");
        assert_eq!(set, announced_builtin_endpoints(None));
        assert_eq!(set & 0x0C00, 0x0C00);
    }

    /// A participant running with security announces, on top of the default
    /// set, the secure builtin endpoints it serves and no other
    /// (`BUILTIN_ENDPOINT_SET_SECURITY`): DCPSParticipantsSecure (bits 26-27)
    /// and DCPSTopic (28-29, RTPS v2.5 Sec.9.3.2) were announced and not
    /// served, the volatile key channel it does serve (24-25) was not.
    #[test]
    fn a_secure_announcement_names_the_secure_endpoints_served_and_no_other() {
        let typelookup = if cfg!(feature = "xtypes-structural-assignability") {
            0x0000_F000
        } else {
            0
        };
        let plain = announced_builtin_endpoints(None);
        assert_eq!(plain, BUILTIN_ENDPOINT_SET_DEFAULT | typelookup);
        let secure = announced_builtin_endpoints(Some([1, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(secure, plain | BUILTIN_ENDPOINT_SET_SECURITY);
        for bit in [20, 21, 26, 27, 28, 29] {
            assert_eq!(secure & (1 << bit), 0, "bit {bit}: nobody serves it");
        }
        for bit in [22, 23, 24, 25] {
            assert_ne!(secure & (1 << bit), 0, "bit {bit}: served, so announced");
        }
    }

    #[test]
    fn property_list_omits_fabricated_timestamps() {
        let data = SpdpData {
            participant_guid: GUID::new([0x11; 12], [0x00, 0x00, 0x01, 0xc1]),
            lease_duration_ms: 10_000,
            domain_id: 0,
            metatraffic_unicast_locators: Vec::new(),
            default_unicast_locators: Vec::new(),
            default_multicast_locators: Vec::new(),
            metatraffic_multicast_locators: Vec::new(),
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        let mut packet = vec![0u8; 2048];
        let written = build_spdp(&data, &mut packet).expect("build SPDP");
        packet.truncate(written);

        let mut offset = 4usize;
        let mut properties = None;
        while offset + 4 <= packet.len() {
            let pid = u16::from_le_bytes([packet[offset], packet[offset + 1]]);
            let length = u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
            offset += 4;
            if pid == PID_SENTINEL {
                break;
            }
            if pid == PID_PROPERTY_LIST {
                let end = offset + length;
                let count = u32::from_le_bytes(
                    packet[offset..offset + 4]
                        .try_into()
                        .expect("property count"),
                );
                offset += 4;
                let mut decoded = Vec::new();
                for _ in 0..count {
                    let name = read_cdr_string(&packet[..end], &mut offset);
                    let value = read_cdr_string(&packet[..end], &mut offset);
                    decoded.push((name, value));
                }
                assert_eq!(offset, end, "property list length matches encoded values");
                properties = Some(decoded);
                break;
            }
            offset += length;
        }

        let properties = properties.expect("PID_PROPERTY_LIST");
        let names: Vec<&str> = properties.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "dds.sys_info.hostname",
                "dds.sys_info.process_id",
                "dds.sys_info.executable_filepath",
                "dds.sys_info.target",
                "dds.sys_info.username",
            ]
        );
        assert!(properties.iter().all(|(_, value)| !value.is_empty()));
        assert!(!packet
            .windows(b"2025-11-11".len())
            .any(|window| window == b"2025-11-11"));
    }

    /// The SPDP HDDS sends to every vendor writes, in the vendor-specific
    /// range (0x8000-0xffff), only HDDS's own PID: a vendor-range PID is read
    /// per the sender's vendor id (DDSI-RTPS 2.5 Sec.9.6.2.2.1, Table 9.6),
    /// so another vendor's PID under 0x011A would be misread. PID_DOMAIN_ID
    /// carries the participant's domain. Decoded from the emitted bytes.
    #[test]
    fn the_announcement_writes_no_other_vendors_pid_and_the_real_domain() {
        for (domain, security) in [(0u32, None), (42, Some([1, 0, 0, 0, 0, 0, 0, 0]))] {
            let data = SpdpData {
                participant_guid: GUID::new([0x11; 12], [0x00, 0x00, 0x01, 0xc1]),
                lease_duration_ms: 10_000,
                domain_id: domain,
                metatraffic_unicast_locators: vec!["192.0.2.1:7410".parse().expect("addr")],
                default_unicast_locators: vec!["192.0.2.1:7411".parse().expect("addr")],
                default_multicast_locators: vec!["239.255.0.1:7401".parse().expect("addr")],
                metatraffic_multicast_locators: Vec::new(),
                identity_token: None,
                permissions_token: None,
                participant_security_info: security,
                vendor_id: None,
                hdds_capabilities: Some(1),
                builtin_endpoint_set: None,
            };
            let mut packet = vec![0u8; 2048];
            let written = build_spdp(&data, &mut packet).expect("build SPDP");
            packet.truncate(written);
            let mut offset = 4usize;
            let mut announced_domain = None;
            loop {
                let pid = u16::from_le_bytes([packet[offset], packet[offset + 1]]);
                let length = u16::from_le_bytes([packet[offset + 2], packet[offset + 3]]) as usize;
                offset += 4;
                if pid == PID_SENTINEL {
                    break;
                }
                if pid >= 0x8000 {
                    assert_eq!(
                        pid,
                        crate::protocol::discovery::constants::PID_HDDS_CAPABILITIES,
                        "vendor-range PID {pid:#06x} is not HDDS's own"
                    );
                }
                if pid == PID_DOMAIN_ID {
                    announced_domain = Some(u32::from_le_bytes(
                        packet[offset..offset + 4].try_into().expect("four octets"),
                    ));
                }
                offset += length;
            }
            assert_eq!(offset, packet.len());
            assert_eq!(announced_domain, Some(domain));
        }
    }
}

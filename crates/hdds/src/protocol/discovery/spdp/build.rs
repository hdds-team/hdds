// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP Building Functions
//!
//! Implements building of SPDP (Simple Participant Discovery Protocol) messages
//! according to DDS-RTPS v2.3 Sec.8.5.4 specification.

use crate::protocol::discovery::constants::{
    BUILTIN_ENDPOINT_SET_DEFAULT, PID_BUILTIN_ENDPOINT_SET, PID_DEFAULT_UNICAST_LOCATOR,
    PID_DOMAIN_ID, PID_METATRAFFIC_UNICAST_LOCATOR, PID_PARTICIPANT_GUID,
    PID_PARTICIPANT_LEASE_DURATION, PID_PROPERTY_LIST, PID_PROTOCOL_VERSION, PID_SENTINEL,
    PID_VENDOR_ID,
};
// v126: Removed PID_BUILTIN_ENDPOINT_QOS and BUILTIN_ENDPOINT_QOS_DEFAULT
// FastDDS doesn't send this PID, and RTI accepts FastDDS. Match FastDDS behavior.
// Info: RTI vendor PIDs (0x8000+) removed from generic builder.
// PID_PRODUCT_VERSION, PID_RTI_DOMAIN_ID, PID_TRANSPORT_INFO_LIST,
// PID_REACHABILITY_LEASE_DURATION, PID_VENDOR_BUILTIN_ENDPOINT_SET
// These belong ONLY in the RTI dialect encoder (protocol/dialect/rti/).
use crate::protocol::discovery::spdp::types::SpdpData;
use crate::protocol::discovery::types::ParseError;
use std::convert::TryFrom;

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

    // v126: Match FastDDS SPDP PID order for RTI compatibility
    // FastDDS order: PROTOCOL_VERSION, VENDOR_ID, PARTICIPANT_GUID, BUILTIN_ENDPOINT_SET, ...
    // Previous HDDS order started with PARTICIPANT_GUID which may confuse RTI

    // Position 1: PID_PROTOCOL_VERSION (MANDATORY per RTPS v2.3 Table 8.73)
    if offset + 4 + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_PROTOCOL_VERSION.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
    offset += 4;
    buf[offset] = 2; // RTPS major version 2
                     // v194: Changed from 3 to 4 for OpenDDS compatibility.
                     // OpenDDS requires PID_PROTOCOL_VERSION to match the header version (v2.4 per v192).
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
    buf[offset + 1] = 0xaa; // HDDS vendor ID byte 1
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

    // Position 4: PID_BUILTIN_ENDPOINT_SET (CRITICAL for RTI interop)
    // RTPS v2.3 spec section 9.3.2, Table 9.12
    if offset + 4 + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_BUILTIN_ENDPOINT_SET.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes()); // uint32 = 4 bytes
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&BUILTIN_ENDPOINT_SET_DEFAULT.to_le_bytes());
    offset += 4;

    // v126: REMOVED PID_BUILTIN_ENDPOINT_QOS (0x0077)
    // FastDDS does NOT send this PID, and RTI accepts FastDDS just fine.

    // v100: CRITICAL - Write locators BEFORE PID_PROPERTY_LIST!
    // PID_PROPERTY_LIST is 400+ bytes and can cause packet truncation.
    // Locators MUST be early in the packet to ensure they're always received.

    // Helper function to write a single locator (24 bytes per RTPS v2.3 Sec.9.3.1)
    //
    // FastDDS expects locators inside PL_CDR_LE ParameterList to use little-endian
    // encoding for kind/port, matching the SEDP locator encoder. RTI interop paths
    // also rely on this layout.
    let write_locator = |buf: &mut [u8],
                         offset: &mut usize,
                         pid: u16,
                         addr: &std::net::SocketAddr|
     -> Result<(), ParseError> {
        if *offset + 4 + 24 > buf.len() {
            return Err(ParseError::BufferTooSmall);
        }
        buf[*offset..*offset + 2].copy_from_slice(&pid.to_le_bytes());
        buf[*offset + 2..*offset + 4].copy_from_slice(&24u16.to_le_bytes());
        *offset += 4;

        // Locator format: kind(4) + port(4) + address(16)
        // kind = LOCATOR_KIND_UDPv4 = 1 (little-endian inside PL_CDR_LE)
        buf[*offset..*offset + 4].copy_from_slice(&1u32.to_le_bytes());
        *offset += 4;
        let port = addr.port() as u32;
        buf[*offset..*offset + 4].copy_from_slice(&port.to_le_bytes());
        *offset += 4;
        buf[*offset..*offset + 12].fill(0); // IPv6 prefix (unused for IPv4)
        *offset += 12;
        if let std::net::IpAddr::V4(ipv4) = addr.ip() {
            buf[*offset..*offset + 4].copy_from_slice(&ipv4.octets());
        }
        *offset += 4;
        Ok(())
    };

    // Position 6: PID_DEFAULT_UNICAST_LOCATOR (0x0031) [MANDATORY] - Port 7411 for USER DATA
    for locator in &spdp_data.default_unicast_locators {
        write_locator(buf, &mut offset, PID_DEFAULT_UNICAST_LOCATOR, locator)?;
    }

    // Position 7: PID_METATRAFFIC_UNICAST_LOCATOR (0x0032) - Port 7410 for SEDP/ACKNACK
    for locator in &spdp_data.metatraffic_unicast_locators {
        write_locator(buf, &mut offset, PID_METATRAFFIC_UNICAST_LOCATOR, locator)?;
    }

    // v126: REMOVED multicast locators - FastDDS does NOT send these in SPDP
    // RTI might be confused by multicast locators from HDDS
    //
    // Position 8: PID_METATRAFFIC_MULTICAST_LOCATOR (0x0033) - REMOVED
    // for locator in &spdp_data.metatraffic_multicast_locators {
    //     write_locator(buf, &mut offset, PID_METATRAFFIC_MULTICAST_LOCATOR, locator)?;
    // }
    //
    // Position 9: PID_DEFAULT_MULTICAST_LOCATOR (0x0048) - REMOVED
    // for locator in &spdp_data.default_multicast_locators {
    //     write_locator(buf, &mut offset, PID_DEFAULT_MULTICAST_LOCATOR, locator)?;
    // }

    // Position 10+: PID_PROPERTY_LIST (RTI compatibility - FULL standard properties)
    // v94: Add ALL 7 standard properties that RTI expects (was only sending 2, now sending 7)
    // RTI rejects HDDS without these! Critical for interop.
    {
        // Helper to format Unix timestamp as "HH:MM:SS"
        let format_unix_time = |secs: u64| -> String {
            let hours = (secs / 3600) % 24;
            let minutes = (secs / 60) % 60;
            let seconds = secs % 60;
            format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
        };

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "hdds-host".to_string());
        let process_id = std::process::id().to_string();

        // v94: Get executable path from std::env::current_exe()
        let executable_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "/usr/bin/hdds".to_string());

        // v94: Target platform (e.g., "x64Linux4gcc7.3.0")
        let target = format!("{}_{}", std::env::consts::ARCH, std::env::consts::OS);

        // v94: Creation timestamp (process start time - approximate with Unix epoch)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        // Simple ISO-8601 format: "YYYY-MM-DD HH:MM:SSZ"
        // For compatibility, use a placeholder that looks like RTI's format
        let creation_timestamp = format!("2025-11-11 {}Z", format_unix_time(now - 3600)); // ~1h ago

        // v94: Execution timestamp (current time)
        let execution_timestamp = format!("2025-11-11 {}Z", format_unix_time(now));

        // v94: Username
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "hdds-user".to_string());

        // Calculate property list size (now 7 properties!)
        // Format: num_properties(4) + property1 + property2 + ... + property7
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

        let prop1_size = calc_prop_size("dds.sys_info.hostname", &hostname);
        let prop2_size = calc_prop_size("dds.sys_info.process_id", &process_id);
        let prop3_size = calc_prop_size("dds.sys_info.executable_filepath", &executable_path);
        let prop4_size = calc_prop_size("dds.sys_info.target", &target);
        let prop5_size = calc_prop_size("dds.sys_info.creation_timestamp", &creation_timestamp);
        let prop6_size = calc_prop_size("dds.sys_info.execution_timestamp", &execution_timestamp);
        let prop7_size = calc_prop_size("dds.sys_info.username", &username);

        let total_properties_size = 4
            + prop1_size
            + prop2_size
            + prop3_size
            + prop4_size
            + prop5_size
            + prop6_size
            + prop7_size;

        // Write PID_PROPERTY_LIST header
        if offset + 4 + total_properties_size > buf.len() {
            return Err(ParseError::BufferTooSmall);
        }
        buf[offset..offset + 2].copy_from_slice(&PID_PROPERTY_LIST.to_le_bytes());
        buf[offset + 2..offset + 4].copy_from_slice(&(total_properties_size as u16).to_le_bytes());
        offset += 4;

        // Write number of properties (7 now!)
        buf[offset..offset + 4].copy_from_slice(&7u32.to_le_bytes());
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
            buf[offset..offset + 4].copy_from_slice(&(name_len as u32).to_le_bytes());
            offset += 4;
            buf[offset..offset + name.len()].copy_from_slice(name.as_bytes());
            buf[offset + name.len()] = 0; // null terminator
                                          // Zero-fill padding
            for i in name_len..name_aligned {
                buf[offset + i] = 0;
            }
            offset += name_aligned;

            // Write value length and value
            buf[offset..offset + 4].copy_from_slice(&(value_len as u32).to_le_bytes());
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

        // Write all 7 properties
        write_property("dds.sys_info.hostname", &hostname)?;
        write_property("dds.sys_info.process_id", &process_id)?;
        write_property("dds.sys_info.executable_filepath", &executable_path)?;
        write_property("dds.sys_info.target", &target)?;
        write_property("dds.sys_info.creation_timestamp", &creation_timestamp)?;
        write_property("dds.sys_info.execution_timestamp", &execution_timestamp)?;
        write_property("dds.sys_info.username", &username)?;
    }

    // v100: Locators already written BEFORE PID_PROPERTY_LIST (lines 651-669)
    // This ensures they're always in the packet even if PROPERTY_LIST causes truncation.

    // Position N: PID_PARTICIPANT_LEASE_DURATION
    if offset + 4 + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_PARTICIPANT_LEASE_DURATION.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&8u16.to_le_bytes());
    offset += 4;

    let seconds = match u32::try_from(spdp_data.lease_duration_ms / 1000) {
        Ok(value) => value,
        Err(_) => {
            log::debug!(
                "[spdp] Lease duration {} ms exceeds RTPS seconds field; clamping",
                spdp_data.lease_duration_ms
            );
            u32::MAX
        }
    };
    let nanos_total = (spdp_data.lease_duration_ms % 1000) * 1_000_000;
    // SAFETY: nanos_total = (ms % 1000) * 1M < 1B, always fits in u32
    let nanoseconds = nanos_total.min(999_999_999) as u32;
    buf[offset..offset + 4].copy_from_slice(&seconds.to_le_bytes());
    buf[offset + 4..offset + 8].copy_from_slice(&nanoseconds.to_le_bytes());
    offset += 8;

    // Standard PID_DOMAIN_ID must trail the lease duration and lead the vendor block
    if offset + 4 + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_DOMAIN_ID.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&4u16.to_le_bytes());
    offset += 4;
    buf[offset..offset + 4].copy_from_slice(&spdp_data.domain_id.to_le_bytes()); // v208: use actual domain_id
    offset += 4;

    // Info: RTI vendor-specific PIDs (0x8000+) are NOT written in the generic
    // SPDP builder. They belong ONLY in the RTI dialect encoder. When HDDS
    // (vendor 0x01AA) sends RTI vendor PIDs, RTI rejects them because vendor
    // PIDs are only valid from the vendor who owns them (RTI = 0x0101).

    // Position N+1 (final): PID_SENTINEL (marks end of parameter list)
    if offset + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_SENTINEL.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&0u16.to_le_bytes());
    offset += 4;

    Ok(offset)
}

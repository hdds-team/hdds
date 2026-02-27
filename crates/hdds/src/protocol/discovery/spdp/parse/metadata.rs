// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Metadata PID Handlers for SPDP
//!
//! Handles parsing of participant metadata PIDs:
//! - PID_PARTICIPANT_GUID (0x0050) - REQUIRED
//! - PID_VENDOR_ID (0x0016)
//! - PID_PROTOCOL_VERSION (0x0015)
//! - PID_DOMAIN_ID (0x000f)

use crate::core::discovery::GUID;
use crate::protocol::discovery::types::ParseError;

/// Parse PID_PARTICIPANT_GUID (0x0050)
///
/// The participant GUID is REQUIRED for SPDP per RTPS v2.3 Sec.8.5.4.
/// This is the unique identifier for the discovered participant.
///
/// # GUID Structure (16 bytes)
/// ```text
/// struct GUID_t {
///   GuidPrefix_t prefix; // 12 bytes: host ID + application ID + instance ID
///   EntityId_t entityId;  // 4 bytes: entity kind (0xc1 for participant)
/// };
/// ```
pub(super) fn parse_participant_guid_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    participant_guid: &mut Option<GUID>,
) -> Result<(), ParseError> {
    if length >= 16 {
        let mut guid_bytes = [0u8; 16];
        guid_bytes.copy_from_slice(&buf[offset..offset + 16]);
        *participant_guid = Some(GUID::from_bytes(guid_bytes));
    }
    Ok(())
}

/// Parse PID_PROTOCOL_VERSION (0x0015)
///
/// RTPS protocol version (major.minor) used by the remote participant.
/// Standard DDS uses RTPS v2.3 (major=2, minor=3).
///
/// # Structure (4 bytes)
/// ```text
/// struct ProtocolVersion_t {
///   octet major; // 1 byte
///   octet minor; // 1 byte
///   octet padding[2]; // 2 bytes padding
/// };
/// ```
pub(super) fn parse_protocol_version_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    proto_maj_min: &mut Option<(u8, u8)>,
) -> Result<(), ParseError> {
    if length >= 4 {
        // major (u8), minor (u8), padding(2)
        let major = buf[offset];
        let minor = buf[offset + 1];
        *proto_maj_min = Some((major, minor));
        log::debug!("[spdp] Protocol version: {}.{}", major, minor);
    }
    Ok(())
}

/// Parse PID_VENDOR_ID (0x0016)
///
/// Vendor identification for interoperability diagnostics.
///
/// # Known Vendor IDs
/// - 0x0101: RTI Connext DDS
/// - 0x0102: ADLink OpenSplice
/// - 0x0103: OCI OpenDDS
/// - 0x010f: eProsima FastDDS
/// - 0x0131: HDDS
///
/// # Structure (4 bytes)
/// ```text
/// struct VendorId_t {
///   octet[2] vendorId; // 2 bytes: little-endian vendor ID
///   octet padding[2];  // 2 bytes padding
/// };
/// ```
pub(super) fn parse_vendor_id_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    vendor_id: &mut Option<u16>,
) -> Result<(), ParseError> {
    if length >= 4 {
        let vend = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        *vendor_id = Some(vend);
        log::debug!("[spdp] Vendor ID in SPDP: 0x{:04x}", vend);
    }
    Ok(())
}

/// Parse PID_DOMAIN_ID (0x000f)
///
/// Domain identifier for the remote participant.
///
/// # Structure (4 bytes)
/// ```text
/// struct DomainId_t {
///   long domain_id; // 4 bytes, typically 0 for single-domain tests
/// };
/// ```
pub(super) fn parse_domain_id_pid(
    buf: &[u8],
    offset: usize,
    length: usize,
    domain_id: &mut Option<u32>,
) -> Result<(), ParseError> {
    if length >= 4 {
        let value = u32::from_le_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ]);
        *domain_id = Some(value);
        log::debug!("[spdp] Domain ID in SPDP: {}", value);
    }
    Ok(())
}

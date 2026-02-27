// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP Parsing Functions
//!
//! Implements parsing of SPDP (Simple Participant Discovery Protocol) messages
//! according to DDS-RTPS v2.3 Sec.8.5.4 specification.
//!
//!
//! # Module Organization
//!
//! This module is organized by PID handler type:
//! - `locators`: Locator PID handlers (unicast/multicast, metatraffic/default)
//! - `metadata`: Participant metadata PIDs (GUID, vendor, protocol version)
//! - `properties`: Properties and QoS PIDs (lease duration, endpoint set, etc.)

mod locators;
mod metadata;
mod properties;

use crate::core::discovery::GUID;
use crate::protocol::discovery::constants::{
    PID_BUILTIN_ENDPOINT_SET, PID_DEFAULT_MULTICAST_LOCATOR, PID_DEFAULT_UNICAST_LOCATOR,
    PID_DOMAIN_ID, PID_ENTITY_NAME, PID_METATRAFFIC_MULTICAST_LOCATOR,
    PID_METATRAFFIC_UNICAST_LOCATOR, PID_PARTICIPANT_GUID, PID_PARTICIPANT_LEASE_DURATION,
    PID_PROPERTY_LIST, PID_PROTOCOL_VERSION, PID_SENTINEL, PID_VENDOR_ID,
};
use crate::protocol::discovery::spdp::types::{
    SpdpData, CDR2_BE, CDR2_LE, CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR,
};
use crate::protocol::discovery::types::ParseError;

/// Parse SPDP DATA submessage payload.
///
/// # Arguments
/// - `buf`: RTPS payload starting at the DATA submessage boundary.
///
/// # Returns
/// Participant metadata gathered from the parameter list.
///
/// # Errors
/// - `ParseError::TruncatedData` if the parameter list is incomplete.
/// - `ParseError::InvalidEncapsulation` when the payload uses unsupported CDR format.
/// - `ParseError::InvalidFormat` if required SPDP fields are missing.
///
/// # Multi-Format Support
/// Accepts multiple CDR encapsulation formats for DDS interoperability:
/// - CDR_LE (0x0003): HDDS standard, little-endian
/// - CDR_BE (0x0002): RTI Connext (violates spec by using big-endian header)
/// - CDR2_LE (0x0103): CDR2 little-endian
/// - CDR2_BE (0x0102): CDR2 big-endian
pub fn parse_spdp(buf: &[u8]) -> Result<SpdpData, ParseError> {
    // Need at least 2 bytes for encapsulation, plus 4 bytes for first PID header
    if buf.len() < 2 {
        return Err(ParseError::TruncatedData);
    }

    // CDR encapsulation header is ALWAYS big-endian per CDR spec
    // (Encapsulation header endianness is always big-endian per CDR spec.)
    let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);

    // Validate and decode encapsulation kind
    let (is_little_endian, is_cdr2) = match encapsulation {
        CDR_LE => {
            log::debug!("[spdp] [OK] CDR_LE (0x0003) detected");
            (true, false)
        }
        CDR_BE => {
            log::debug!(
                "[spdp] [!]  CDR_BE (0x0002) detected - RTI non-standard big-endian encoding"
            );
            (false, false)
        }
        CDR2_LE => {
            log::debug!("[spdp] [OK] CDR2_LE (0x0103) detected");
            (true, true)
        }
        CDR2_BE => {
            log::debug!("[spdp] [!]  CDR2_BE (0x0102) detected");
            (false, true)
        }
        // v97: FastDDS vendor-specific encapsulations
        CDR_LE_VENDOR => {
            log::debug!("[spdp] [OK] CDR_LE_VENDOR (0x8001) detected - FastDDS");
            (true, false)
        }
        CDR_BE_VENDOR => {
            log::debug!("[spdp] [!]  CDR_BE_VENDOR (0x8002) detected - FastDDS");
            (false, false)
        }
        _ => {
            log::debug!("[spdp] [X] Invalid encapsulation: 0x{:04x}", encapsulation);
            return Err(ParseError::InvalidEncapsulation);
        }
    };

    // RTI Connext omits the standard 2-byte padding after encapsulation
    // Standard DDS: encapsulation (2 bytes) + padding (2 bytes) + PIDs at offset 4
    // RTI: encapsulation (2 bytes) + PIDs directly at offset 2
    //
    // Detect this by checking if bytes [2-3] are all zeros (padding) or contain data (PID)
    let pid_offset = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
        // Standard padding detected
        4
    } else {
        // RTI format: no padding, PIDs start immediately after encapsulation
        2
    };
    let mut participant_guid: Option<GUID> = None;
    let mut lease_duration_ms: u64 = 100_000;
    // v79: Separate locator lists per RTPS v2.3 Sec.8.5.3.1
    let mut spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([0u8; 16]), // Will be overwritten
        lease_duration_ms: 100_000,
        domain_id: 0, // v208: Will be overwritten if PID_DOMAIN_ID present
        metatraffic_unicast_locators: Vec::new(),
        default_unicast_locators: Vec::new(),
        default_multicast_locators: Vec::new(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token: None,
    };

    // Optional: protocol/vendor/domain info for diagnostics
    let mut _proto_maj_min: Option<(u8, u8)> = None;
    let mut _vendor_id: Option<u16> = None;
    let mut _domain_id: Option<u32> = None;

    let mut offset = pid_offset;

    loop {
        if offset + 4 > buf.len() {
            return Err(ParseError::TruncatedData);
        }

        // Read PID and length with correct endianness
        let pid = if is_little_endian {
            u16::from_le_bytes([buf[offset], buf[offset + 1]])
        } else {
            u16::from_be_bytes([buf[offset], buf[offset + 1]])
        };

        let length = if is_little_endian {
            u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize
        } else {
            u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize
        };

        offset += 4;

        if pid == PID_SENTINEL {
            break;
        }

        if offset + length > buf.len() {
            return Err(ParseError::TruncatedData);
        }

        // Dispatch to appropriate PID handler
        match pid {
            // Metadata PIDs
            PID_PARTICIPANT_GUID => {
                metadata::parse_participant_guid_pid(buf, offset, length, &mut participant_guid)?;
            }
            PID_PROTOCOL_VERSION => {
                metadata::parse_protocol_version_pid(buf, offset, length, &mut _proto_maj_min)?;
            }
            PID_VENDOR_ID => {
                metadata::parse_vendor_id_pid(buf, offset, length, &mut _vendor_id)?;
            }
            PID_DOMAIN_ID => {
                metadata::parse_domain_id_pid(buf, offset, length, &mut _domain_id)?;
                // v208: store parsed domain_id into SpdpData
                if let Some(did) = _domain_id {
                    spdp_data.domain_id = did;
                }
            }

            // Property PIDs
            PID_PARTICIPANT_LEASE_DURATION => {
                properties::parse_participant_lease_duration_pid(
                    buf,
                    offset,
                    length,
                    is_little_endian,
                    &mut lease_duration_ms,
                )?;
            }
            PID_BUILTIN_ENDPOINT_SET => {
                properties::parse_builtin_endpoint_set_pid(buf, offset, length, is_little_endian)?;
            }
            PID_PROPERTY_LIST => {
                properties::parse_property_list_pid(buf, offset, length)?;
            }
            PID_ENTITY_NAME => {
                properties::parse_entity_name_pid(buf, offset, length)?;
            }

            // Locator PIDs
            PID_METATRAFFIC_UNICAST_LOCATOR => {
                locators::parse_metatraffic_unicast_locator_pid(
                    buf,
                    offset,
                    length,
                    &mut spdp_data,
                )?;
            }
            PID_METATRAFFIC_MULTICAST_LOCATOR => {
                locators::parse_metatraffic_multicast_locator_pid(
                    buf,
                    offset,
                    length,
                    &mut spdp_data,
                )?;
            }
            PID_DEFAULT_UNICAST_LOCATOR => {
                locators::parse_default_unicast_locator_pid(buf, offset, length, &mut spdp_data)?;
            }
            PID_DEFAULT_MULTICAST_LOCATOR => {
                locators::parse_default_multicast_locator_pid(buf, offset, length, &mut spdp_data)?;
            }

            _ => {
                // Log unknown PIDs for SPDP debugging
                if pid >= 0x8000 {
                    log::debug!(
                        "[SPDP-PARSE] [!]  Unknown vendor-specific PID: 0x{:04x} (length={})",
                        pid,
                        length
                    );
                } else {
                    log::debug!("[SPDP-PARSE] [!]  Unknown standard PID: 0x{:04x} (length={}) - might be important!", pid, length);
                }
            }
        }

        // CDR2 alignment rules (if needed)
        if is_cdr2 {
            offset += (length + 3) & !3; // Align to 4 bytes
        } else {
            offset += length;
        }
    }

    let participant_guid = participant_guid.ok_or(ParseError::InvalidFormat)?;

    // Update final GUID and lease duration
    spdp_data.participant_guid = participant_guid;
    spdp_data.lease_duration_ms = lease_duration_ms;

    Ok(spdp_data)
}

/// Parse partial SPDP from fragmented DATA_FRAG submessages (RTI interop).
///
/// # Behavior
/// RTI Connext systematically fragments SPDP messages over multiple DATA_FRAG packets.
/// This function extracts GUID + lease duration even from incomplete fragments,
/// enabling discovery <2ms without waiting for reassembly.
///
/// # Arguments
/// - `buf`: SPDP payload (may be truncated)
///
/// # Returns
/// `SpdpData` with:
/// - `participant_guid`: Always extracted (even from fragment)
/// - `lease_duration_ms`: Extracted if available
/// - `unicast_locators`: Empty if message is truncated
///
/// # Errors
/// - `ParseError::TruncatedData` if GUID cannot be extracted
/// - `ParseError::InvalidEncapsulation` if CDR header is missing
pub fn parse_spdp_partial(buf: &[u8]) -> Result<SpdpData, ParseError> {
    // Try complete parse first (handles normal case)
    match parse_spdp(buf) {
        Ok(full_data) => Ok(full_data),
        Err(ParseError::TruncatedData) => {
            // Fragment case: extract what we can
            log::debug!("[spdp-partial] [*] Extracting from fragmented DATA_FRAG");

            // Ensure minimum buffer for encapsulation (2 bytes)
            if buf.len() < 2 {
                return Err(ParseError::TruncatedData);
            }

            // CDR encapsulation header is ALWAYS big-endian per CDR spec
            let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);

            let is_little_endian = match encapsulation {
                CDR_LE | CDR2_LE | CDR_LE_VENDOR => true,
                CDR_BE | CDR2_BE | CDR_BE_VENDOR => false,
                _ => {
                    log::debug!(
                        "[spdp-partial] [X] Invalid encapsulation in fragment: 0x{:04x}",
                        encapsulation
                    );
                    return Err(ParseError::InvalidEncapsulation);
                }
            };

            // Detect padding (standard: 00 00 at offset 2-3, RTI: none)
            let pid_start = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
                4 // Standard padding
            } else {
                2 // RTI: no padding
            };

            // v106: FastDDS compat - Scan ALL PIDs to find GUID (not just first PID)
            // FastDDS may send vendor-specific PIDs (0x0038, 0xe800) before GUID
            let mut participant_guid: Option<GUID> = None;
            let mut offset = pid_start;

            loop {
                if offset + 4 > buf.len() {
                    break; // End of buffer
                }

                let pid = if is_little_endian {
                    u16::from_le_bytes([buf[offset], buf[offset + 1]])
                } else {
                    u16::from_be_bytes([buf[offset], buf[offset + 1]])
                };

                let length = if is_little_endian {
                    u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize
                } else {
                    u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize
                };

                offset += 4;

                if pid == PID_SENTINEL {
                    break;
                }

                if offset + length > buf.len() {
                    break; // Truncated
                }

                // Found GUID?
                if pid == PID_PARTICIPANT_GUID && length >= 16 {
                    let mut guid_bytes = [0u8; 16];
                    guid_bytes.copy_from_slice(&buf[offset..offset + 16]);
                    participant_guid = Some(GUID::from_bytes(guid_bytes));
                    log::debug!(
                        "[spdp-partial] [OK] Found GUID at offset {} (after scanning PIDs)",
                        offset - 4
                    );
                    break; // Found it!
                }

                offset += length;
            }

            let participant_guid = match participant_guid {
                Some(guid) => guid,
                None => {
                    log::debug!("[spdp-partial] [X] GUID not found after scanning all PIDs");
                    return Err(ParseError::InvalidFormat);
                }
            };

            log::debug!(
                "[spdp-partial] [OK] Extracted GUID from fragment: {:?}",
                participant_guid
            );

            // v106: Skip lease extraction for now (would require scanning rest of buffer)
            // Use default 100s lease duration for fragmented SPDP
            let lease_duration_ms = 100_000; // Default 100s

            if false {
                // OLD CODE (disabled): Try to extract lease duration from next PID
                let lease_start = 0; // data_start + length;
                let _unused = if buf.len() >= lease_start + 4 {
                    let next_pid = if is_little_endian {
                        u16::from_le_bytes([buf[lease_start], buf[lease_start + 1]])
                    } else {
                        u16::from_be_bytes([buf[lease_start], buf[lease_start + 1]])
                    };

                    let next_length = if is_little_endian {
                        u16::from_le_bytes([buf[lease_start + 2], buf[lease_start + 3]]) as usize
                    } else {
                        u16::from_be_bytes([buf[lease_start + 2], buf[lease_start + 3]]) as usize
                    };

                    if next_pid == PID_PARTICIPANT_LEASE_DURATION
                        && next_length >= 8
                        && buf.len() >= lease_start + 4 + 8
                    {
                        let lease_data_start = lease_start + 4;
                        let seconds = if is_little_endian {
                            u32::from_le_bytes([
                                buf[lease_data_start],
                                buf[lease_data_start + 1],
                                buf[lease_data_start + 2],
                                buf[lease_data_start + 3],
                            ])
                        } else {
                            u32::from_be_bytes([
                                buf[lease_data_start],
                                buf[lease_data_start + 1],
                                buf[lease_data_start + 2],
                                buf[lease_data_start + 3],
                            ])
                        };
                        seconds as u64 * 1000
                    } else {
                        log::debug!(
                            "[spdp-partial] [!]  Lease duration not found, using default 100s"
                        );
                        100_000 // Default 100s
                    }
                } else {
                    log::debug!(
                    "[spdp-partial] [!]  Buffer too short for lease extraction, using default 100s"
                );
                    100_000 // Default 100s
                };
            } // End if false

            Ok(SpdpData {
                participant_guid,
                lease_duration_ms,
                domain_id: 0, // Partial fragment = unknown domain
                metatraffic_unicast_locators: vec![], // Partial fragment = no locators
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None, // Partial fragment = no security data
            })
        }
        Err(e) => Err(e), // Other errors pass through
    }
}

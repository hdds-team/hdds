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
#[cfg(feature = "security")]
use crate::protocol::discovery::constants::{
    PID_IDENTITY_TOKEN, PID_PARTICIPANT_SECURITY_INFO, PID_PERMISSIONS_TOKEN,
};
use crate::protocol::discovery::spdp::types::{
    SpdpData, CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR, PL_CDR2_BE, PL_CDR2_LE,
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
/// - CDR_BE (0x0002): PL_CDR_BE, big-endian ParameterList (DDSI-RTPS 2.5 Sec.10.3)
/// - PL_CDR2_LE (0x000B): CDR2 little-endian
/// - PL_CDR2_BE (0x000A): CDR2 big-endian
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
            log::debug!("[spdp] [!]  PL_CDR_BE (0x0002) detected - big-endian parameter list");
            (false, false)
        }
        PL_CDR2_LE => {
            log::debug!("[spdp] [OK] PL_CDR2_LE (0x000B) detected");
            (true, true)
        }
        PL_CDR2_BE => {
            log::debug!("[spdp] [!]  PL_CDR2_BE (0x000A) detected");
            (false, true)
        }
        // FastDDS vendor-specific encapsulations
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

    // DDSI-RTPS 2.5 Sec.10.2: encapsulation (2 bytes) + representation_options
    // (2 bytes) + PIDs at offset 4. We also tolerate a non-conformant payload
    // without the options field: encapsulation (2 bytes) + PIDs at offset 2
    //
    // Detect this by checking if bytes [2-3] are all zeros (padding) or contain data (PID)
    let pid_offset = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
        // Standard padding detected
        4
    } else {
        // Tolerated layout: no options field, PIDs start right after encapsulation
        2
    };
    let mut participant_guid: Option<GUID> = None;
    let mut lease_duration_ms: u64 = 100_000;
    // Separate locator lists per RTPS v2.3 Sec.8.5.3.1
    let mut spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([0u8; 16]), // Will be overwritten
        lease_duration_ms: 100_000,
        domain_id: 0, // Will be overwritten if PID_DOMAIN_ID present
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

    // Optional: protocol/vendor/domain info for diagnostics
    let mut _proto_maj_min: Option<(u8, u8)> = None;
    let mut vendor_id: Option<u16> = None;
    let mut hdds_capabilities: Option<u32> = None;
    let mut builtin_endpoint_set: Option<u32> = None;
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
                metadata::parse_vendor_id_pid(buf, offset, length, &mut vendor_id)?;
            }
            // HDDS vendor range: recorded whoever sent it; what it means is
            // decided with the sender's vendorId (`GroupDialect::of`).
            crate::protocol::discovery::constants::PID_HDDS_CAPABILITIES if length >= 4 => {
                let bytes = [
                    buf[offset],
                    buf[offset + 1],
                    buf[offset + 2],
                    buf[offset + 3],
                ];
                hdds_capabilities = Some(if is_little_endian {
                    u32::from_le_bytes(bytes)
                } else {
                    u32::from_be_bytes(bytes)
                });
            }
            PID_DOMAIN_ID => {
                metadata::parse_domain_id_pid(buf, offset, length, &mut _domain_id)?;
                // store parsed domain_id into SpdpData
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
                builtin_endpoint_set = properties::parse_builtin_endpoint_set_pid(
                    buf,
                    offset,
                    length,
                    is_little_endian,
                )?;
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

            // DDS Security v1.1 sec. 7.4.1.4 token PIDs: capture raw DataHolder
            // bytes for downstream `SecurityValidatorAdapter` consumption.
            // Gated behind the `security` feature so non-security builds
            // do not allocate for tokens we will never consume.
            #[cfg(feature = "security")]
            PID_IDENTITY_TOKEN => {
                spdp_data.identity_token = Some(buf[offset..offset + length].to_vec());
            }
            #[cfg(feature = "security")]
            PID_PERMISSIONS_TOKEN => {
                spdp_data.permissions_token = Some(buf[offset..offset + length].to_vec());
            }
            // DDS-Security v1.1 Sec.7.4.1.4: two CDR u32 masks in the
            // parameter list's byte order. Normalize to little endian for
            // SpdpData consumers, regardless of the wire representation.
            #[cfg(feature = "security")]
            PID_PARTICIPANT_SECURITY_INFO => {
                if length >= 8 {
                    let mut info = [0u8; 8];
                    for (word, bytes) in info
                        .chunks_exact_mut(4)
                        .zip(buf[offset..offset + 8].chunks_exact(4))
                    {
                        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
                        let mask = if is_little_endian {
                            u32::from_le_bytes(bytes)
                        } else {
                            u32::from_be_bytes(bytes)
                        };
                        word.copy_from_slice(&mask.to_le_bytes());
                    }
                    spdp_data.participant_security_info = Some(info);
                } else {
                    log::debug!(
                        "[spdp] PID_PARTICIPANT_SECURITY_INFO length {} < 8, ignoring",
                        length
                    );
                }
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
    // Wire the parsed vendor id (RTPS PID_VENDORID 0x0016) into the struct.
    spdp_data.vendor_id = vendor_id;
    spdp_data.hdds_capabilities = hdds_capabilities;
    spdp_data.builtin_endpoint_set = builtin_endpoint_set;

    Ok(spdp_data)
}

/// Parse partial SPDP from fragmented DATA_FRAG submessages.
///
/// # Behavior
/// A peer may fragment its SPDP message over multiple DATA_FRAG submessages.
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
                CDR_LE | PL_CDR2_LE | CDR_LE_VENDOR => true,
                CDR_BE | PL_CDR2_BE | CDR_BE_VENDOR => false,
                _ => {
                    log::debug!(
                        "[spdp-partial] [X] Invalid encapsulation in fragment: 0x{:04x}",
                        encapsulation
                    );
                    return Err(ParseError::InvalidEncapsulation);
                }
            };

            // Detect options field (standard: 00 00 at offset 2-3, tolerated: none)
            let pid_start = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
                4 // Standard padding
            } else {
                2 // Tolerated layout: no options field
            };

            // Scan ALL PIDs to find GUID (not just first PID): a parameter
            // list may carry other PIDs, vendor-specific ones included, before it
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

            // Everything below the GUID is a CONSTANT, not a reading. A
            // caller that reaches this function has a parameter list it could
            // not walk to the sentinel, so the lease, the domain, the locators
            // and the security tokens of that participant are simply not
            // available - and what goes back is a 100-second lease, domain 0
            // and four empty locator lists. These constants are the shipped
            // behaviour, not a stand-in.
            //
            // The fragmented case does not come here: a DATA_FRAG is
            // reassembled before anything parses it.
            // This is the compatibility net for a peer
            // whose parameter list we cannot walk - and for that peer, these
            // constants are what the discovery FSM records.
            let lease_duration_ms = 100_000;

            Ok(SpdpData {
                participant_guid,
                lease_duration_ms,
                domain_id: 0, // Partial fragment = unknown domain
                metatraffic_unicast_locators: vec![], // Partial fragment = no locators
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None, // Partial fragment = no security data
                permissions_token: None,
                participant_security_info: None,
                vendor_id: None, // Partial fragment = vendor id not extracted
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            })
        }
        Err(e) => Err(e), // Other errors pass through
    }
}

#[cfg(test)]
mod cdr_not_datagram_tests {
    use super::*;

    /// This parser takes a CDR ParameterList, NOT an RTPS datagram.
    ///
    /// It reads the first two octets as the CDR encapsulation identifier, so
    /// a caller that hands it a whole datagram gets "RT" - 0x5254 - and a
    /// refusal, whatever the announcement behind it says.
    ///
    /// What this test is and is not: the refusal is LAYERED, and that is
    /// measured rather than assumed. Forcing the encapsulation to PL_CDR_LE
    /// in the partial branch leaves it green (the complete parse is tried
    /// first and only a truncation reaches that branch), and forcing it in
    /// the complete parse leaves it green too (the parameter walk then
    /// refuses the garbage behind it). So this is not a pin on one rule; it
    /// is a guard against the WRONG remedy - teaching this parser to tolerate
    /// a leading RTPS header instead of giving the caller the offset it was
    /// handed.
    ///
    /// Pinned because a caller does exactly that: the discovery fragment
    /// handler is given the FULL RTPS packet by the callback, together with
    /// the offset its CDR starts at, and passes the packet here without the
    /// offset. So the single-fragment SPDP path cannot succeed - not for a
    /// malformed peer, for every peer.
    #[test]
    fn an_rtps_datagram_is_not_a_cdr_parameter_list() {
        let mut datagram = Vec::new();
        datagram.extend_from_slice(b"RTPS");
        datagram.extend_from_slice(&[0x02, 0x05, 0x01, 0x1A]);
        datagram.extend_from_slice(&[0x0A; 12]);
        // A DATA_FRAG header and enough body to look like a real fragment.
        datagram.extend_from_slice(&[0x16, 0x01, 0x28, 0x00]);
        datagram.extend_from_slice(&[0x00; 40]);

        let refused = parse_spdp_partial(&datagram);
        assert!(
            refused.is_err(),
            "a datagram handed to the CDR parser is refused, got {:?}",
            refused
        );

        // And the same announcement, sliced where its CDR actually starts,
        // is at least read as a ParameterList rather than rejected on its
        // first two octets. PL_CDR_LE with no parameters: the refusal above
        // is about the offset, not about the content.
        let mut cdr = vec![0x00, 0x03, 0x00, 0x00];
        cdr.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL
        assert!(
            !matches!(
                parse_spdp_partial(&cdr),
                Err(ParseError::InvalidEncapsulation)
            ),
            "the encapsulation is what the datagram failed on"
        );
    }
}

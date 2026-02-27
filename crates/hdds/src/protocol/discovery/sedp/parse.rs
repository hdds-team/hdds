// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP Parser - CDR decoding of SEDP endpoint discovery messages
//!
//! Handles parsing of SEDP DATA submessages containing endpoint metadata including:
//! - Topic and type names
//! - Endpoint GUIDs
//! - QoS policies (reliability, durability, history)
//! - Type information (TypeObject, compressed via ZLIB)
//! - Vendor-specific extensions (RTI, FastDDS)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::discovery::GUID;
use crate::protocol::discovery::constants::{
    CDR2_BE, CDR2_LE, CDR_BE, CDR_BE_VENDOR, CDR_LE, CDR_LE_VENDOR, PID_BUILTIN_ENDPOINT_SET,
    PID_DATA_REPRESENTATION, PID_DURABILITY, PID_DURABILITY_SERVICE, PID_ENDPOINT_GUID,
    PID_HISTORY, PID_METATRAFFIC_UNICAST_LOCATOR, PID_PARTICIPANT_GUID,
    PID_PARTICIPANT_LEASE_DURATION, PID_PRESENTATION, PID_RELIABILITY, PID_SENTINEL,
    PID_TOPIC_NAME, PID_TYPE_NAME, PID_TYPE_OBJECT, PID_TYPE_OBJECT_LB, PID_UNICAST_LOCATOR,
    PID_USER_DATA,
};
use crate::protocol::discovery::hash::simple_hash;
use crate::protocol::discovery::types::{ParseError, SedpData};
use crate::xtypes::{decompress_type_object, CompleteTypeObject};
use crate::Cdr2Decode;

/// Parse a string parameter from CDR-encoded buffer.
///
/// Format: length (u32) + string bytes + null terminator.
/// The length field uses the same endianness as the CDR payload.
pub(super) fn parse_string_parameter(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<String> {
    if length < 4 {
        return None;
    }

    let str_len = read_u32(buf, offset, is_little_endian) as usize;

    if offset + 4 + str_len > buf.len() || str_len == 0 {
        return None;
    }

    let bytes = &buf[offset + 4..offset + 4 + str_len - 1];
    std::str::from_utf8(bytes).ok().map(|s| s.to_string())
}

fn parse_user_data_parameter(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<String> {
    if length < 4 || offset + length > buf.len() {
        return None;
    }

    let len_bytes = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    let data_len = if is_little_endian {
        u32::from_le_bytes(len_bytes)
    } else {
        u32::from_be_bytes(len_bytes)
    } as usize;

    if data_len == 0 || data_len + 4 > length {
        return None;
    }

    let mut data = &buf[offset + 4..offset + 4 + data_len];
    if let Some((&0, trimmed)) = data.split_last() {
        data = trimmed;
    }

    std::str::from_utf8(data).ok().map(|s| s.to_string())
}

// TypeObject decompression moved to xtypes::type_object::codec module
// Use decompress_type_object() from crate::xtypes instead

// =========================================================================
// Endianness-aware primitive readers
// =========================================================================
// CDR payload endianness is determined by the encapsulation header.
// These helpers centralize the LE/BE dispatch to avoid repeating
// if/else blocks in every PID handler.

fn read_u16(buf: &[u8], offset: usize, is_little_endian: bool) -> u16 {
    let bytes = [buf[offset], buf[offset + 1]];
    if is_little_endian {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    }
}

fn read_u32(buf: &[u8], offset: usize, is_little_endian: bool) -> u32 {
    let bytes = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    if is_little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

fn read_i32(buf: &[u8], offset: usize, is_little_endian: bool) -> i32 {
    let bytes = [
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ];
    if is_little_endian {
        i32::from_le_bytes(bytes)
    } else {
        i32::from_be_bytes(bytes)
    }
}

/// Parse PID_DURABILITY_SERVICE (0x001e) from CDR-encoded buffer.
///
/// Format: cleanup_delay (Duration_t = 8 bytes) + history_kind (u32) +
///         history_depth (u32) + max_samples (i32) + max_instances (i32) +
///         max_samples_per_instance (i32) = 28 bytes total.
fn parse_durability_service(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<crate::dds::qos::DurabilityService> {
    if length < 28 {
        return None;
    }

    let cleanup_secs = read_u32(buf, offset, is_little_endian);
    let cleanup_nsecs = read_u32(buf, offset + 4, is_little_endian);
    // history_kind at offset+8 (not used directly, DurabilityService uses KEEP_LAST)
    let history_depth = read_u32(buf, offset + 12, is_little_endian);
    let max_samples = read_i32(buf, offset + 16, is_little_endian);
    let max_instances = read_i32(buf, offset + 20, is_little_endian);
    let max_samples_per_instance = read_i32(buf, offset + 24, is_little_endian);

    // Convert Duration_t to microseconds
    let cleanup_delay_us = (cleanup_secs as u64) * 1_000_000 + (cleanup_nsecs as u64) / 1_000;

    let ds = crate::dds::qos::DurabilityService::new(
        cleanup_delay_us,
        history_depth,
        max_samples,
        max_instances,
        max_samples_per_instance,
    );
    log::debug!(
        "[SEDP-QOS] PID_DURABILITY_SERVICE parsed: depth={} max_samples={} max_instances={} max_spi={}",
        history_depth, max_samples, max_instances, max_samples_per_instance
    );
    Some(ds)
}

/// Parse PID_PRESENTATION (0x0021) from CDR-encoded buffer.
///
/// Format: access_scope (u32) + coherent_access (u8) + ordered_access (u8) + 2 padding = 8 bytes.
fn parse_presentation(
    buf: &[u8],
    offset: usize,
    length: usize,
    is_little_endian: bool,
) -> Option<crate::dds::qos::Presentation> {
    if length < 8 {
        return None;
    }

    let scope_kind = read_u32(buf, offset, is_little_endian);
    let coherent = buf[offset + 4] != 0;
    let ordered = buf[offset + 5] != 0;
    let access_scope = match scope_kind {
        0 => crate::dds::qos::PresentationAccessScope::Instance,
        1 => crate::dds::qos::PresentationAccessScope::Topic,
        2 => crate::dds::qos::PresentationAccessScope::Group,
        _ => crate::dds::qos::PresentationAccessScope::Instance,
    };
    log::debug!(
        "[SEDP-QOS] PID_PRESENTATION parsed: scope={} coherent={} ordered={}",
        scope_kind,
        coherent,
        ordered
    );
    Some(crate::dds::qos::Presentation::new(
        access_scope,
        coherent,
        ordered,
    ))
}

/// Parse SEDP DATA submessage payload.
///
/// # Arguments
/// - `buf`: RTPS payload positioned at the DATA submessage.
///
/// # Returns
/// Endpoint metadata containing topic/type names, endpoint GUID, QoS hash, and optional TypeObject.
///
/// # Errors
/// - `ParseError::TruncatedData` if the payload terminates mid-parameter.
/// - `ParseError::InvalidEncapsulation` when the encapsulation is not CDR little-endian.
/// - `ParseError::InvalidFormat` if required SEDP parameters are missing.
///
/// # Multi-Format Support (v62)
/// Accepts multiple CDR encapsulation formats for DDS interoperability:
/// - CDR_LE (0x0003): HDDS standard, little-endian
/// - CDR_BE (0x0002): RTI Connext (non-standard big-endian header)
/// - CDR2_LE (0x0103): CDR2 little-endian
/// - CDR2_BE (0x0102): CDR2 big-endian
pub fn parse_sedp(buf: &[u8]) -> Result<SedpData, ParseError> {
    if buf.len() < 2 {
        return Err(ParseError::TruncatedData);
    }

    // CDR encapsulation header is ALWAYS big-endian per CDR spec
    let encapsulation = u16::from_be_bytes([buf[0], buf[1]]);

    // v62: Accept all CDR formats (mirror SPDP parser robustness)
    // NOTE: _is_cdr2 is detected but not yet used. CDR2 (XCDR2) has different
    // encoding rules for optional members and DHEADER. PID-based parameter lists
    // are self-delimiting so CDR1/CDR2 parse identically for now, but XCDR2
    // extensions (e.g., optional members with MEMBER_ID headers) would need
    // special handling here.
    let (is_little_endian, _is_cdr2) = match encapsulation {
        CDR_LE => {
            log::debug!("[sedp] [OK] CDR_LE (0x0003) detected");
            (true, false)
        }
        CDR_BE => {
            log::debug!(
                "[sedp] [!]  CDR_BE (0x0002) detected - RTI non-standard big-endian encoding"
            );
            (false, false)
        }
        CDR2_LE => {
            log::debug!("[sedp] [OK] CDR2_LE (0x0103) detected");
            (true, true)
        }
        CDR2_BE => {
            log::debug!("[sedp] [!]  CDR2_BE (0x0102) detected");
            (false, true)
        }
        // v97: FastDDS vendor-specific encapsulations
        CDR_LE_VENDOR => {
            log::debug!("[sedp] [OK] CDR_LE_VENDOR (0x8001) detected - FastDDS");
            (true, false)
        }
        CDR_BE_VENDOR => {
            log::debug!("[sedp] [!]  CDR_BE_VENDOR (0x8002) detected - FastDDS");
            (false, false)
        }
        _ => {
            log::debug!(
                "[sedp] [X] Invalid encapsulation: 0x{:04x} buf_head={:02x?}",
                encapsulation,
                &buf[..buf.len().min(16)]
            );
            return Err(ParseError::InvalidEncapsulation);
        }
    };

    // =========================================================================
    // Padding Detection Logic
    // =========================================================================
    //
    // CDR encapsulation has a 4-byte header: 2 bytes for encapsulation ID + 2 bytes options.
    // Per the CDR spec, bytes 2-3 are "options" but most implementations use them as padding.
    //
    // Standard DDS layout (HDDS, FastDDS, CycloneDDS, OpenDDS):
    //   [0-1] Encapsulation ID (e.g., 0x0003 for CDR_LE)
    //   [2-3] Options/padding (typically 0x0000)
    //   [4+]  Parameter list starts here
    //
    // RTI Connext non-standard layout:
    //   [0-1] Encapsulation ID
    //   [2+]  Parameter list starts immediately (no padding!)
    //
    // Detection: If bytes 2-3 are both 0x00, assume standard 2-byte padding.
    // This heuristic works because valid PIDs are never 0x0000 (that's reserved).
    //
    // CAVEAT: In XCDR2 (PL_CDR2), bytes 2-3 are an "options" field that may be
    // non-zero (encoding flags). If a participant sends CDR2 with non-zero options,
    // this heuristic would incorrectly skip padding and shift all offsets by 2.
    // Current mitigation: PID parsing is self-delimiting (each PID carries its
    // length), so a 2-byte offset error would cause the first PID read to fail
    // and return TruncatedData/InvalidFormat rather than silently corrupt data.
    // =========================================================================
    let pid_offset = if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
        4 // Standard padding detected
    } else {
        2 // RTI format: no padding
    };

    let mut offset = pid_offset;
    let mut topic_name: Option<String> = None;
    let mut type_name: Option<String> = None;
    let mut participant_guid: Option<GUID> = None; // v110: Parse PID_PARTICIPANT_GUID for FastDDS interop
    let mut endpoint_guid: Option<GUID> = None;
    let mut type_object: Option<CompleteTypeObject> = None;
    let mut is_participant_data = false; // v59: Detect ParticipantData vs Publication/Subscription

    // v61: Build QoS from PIDs instead of throwing them away
    let mut qos_reliability: Option<crate::dds::qos::Reliability> = None;
    let mut qos_durability: Option<crate::dds::qos::Durability> = None;
    let mut qos_history: Option<crate::dds::qos::History> = None;

    // v234: Parse PID_PRESENTATION for Presentation QoS
    let mut qos_presentation: Option<crate::dds::qos::Presentation> = None;

    // v235: Parse PID_DURABILITY_SERVICE for DurabilityService QoS
    let mut qos_durability_service: Option<crate::dds::qos::DurabilityService> = None;

    // v143: Parse PID_UNICAST_LOCATOR for OpenDDS interop - CRITICAL for knowing where to send user data
    let mut unicast_locators: Vec<SocketAddr> = Vec::new();
    let mut user_data: Option<String> = None;

    // =========================================================================
    // PID (Parameter ID) Parsing Loop
    // =========================================================================
    //
    // ## CDR Encapsulation & Endianness (OMG CDR Spec)
    //
    // The CDR (Common Data Representation) spec defines a 2-level encoding:
    //   1. The encapsulation header (bytes 0-1) is ALWAYS big-endian (network order)
    //   2. The payload data uses the endianness indicated BY the header
    //
    // This is why we read the encapsulation with from_be_bytes() above (line 115),
    // but use `is_little_endian` for all PID/length/value parsing below.
    //
    // ## Why Both LE and BE Are Supported
    //
    // Different DDS vendors use different endianness in their CDR encoding:
    //   - HDDS, FastDDS, CycloneDDS: CDR_LE (0x0003) - little-endian payload
    //   - RTI Connext: CDR_BE (0x0002) - big-endian payload (less common)
    //
    // For interoperability, we must handle both. The `is_little_endian` flag
    // (set from the encapsulation header) tells us how to decode each PID.
    //
    // ## PID Structure (4-byte header + variable payload)
    //
    //   Offset 0-1: Parameter ID (u16, endian-dependent)
    //   Offset 2-3: Length in bytes (u16, endian-dependent)
    //   Offset 4+:  Parameter value (length bytes, endian-dependent)
    //
    // The loop continues until PID_SENTINEL (0x0001) is encountered.
    // =========================================================================
    loop {
        // Ensure we have at least 4 bytes for the PID header (id + length)
        if offset + 4 > buf.len() {
            return Err(ParseError::TruncatedData);
        }

        // v62: Read PID and length with correct endianness
        // NOTE: The endianness here matches the CDR payload encoding, NOT the header
        let pid = if is_little_endian {
            u16::from_le_bytes([buf[offset], buf[offset + 1]])
        } else {
            u16::from_be_bytes([buf[offset], buf[offset + 1]])
        };

        let length = if is_little_endian {
            u16::from_le_bytes([buf[offset + 2], buf[offset + 3]])
        } else {
            u16::from_be_bytes([buf[offset + 2], buf[offset + 3]])
        } as usize;

        offset += 4; // Move past PID header to parameter value

        // PID_SENTINEL marks end of parameter list
        if pid == PID_SENTINEL {
            break;
        }

        // Validate we have enough data for this parameter's value
        if offset + length > buf.len() {
            return Err(ParseError::TruncatedData);
        }

        match pid {
            PID_TOPIC_NAME => {
                topic_name = parse_string_parameter(buf, offset, length, is_little_endian);
            }
            PID_TYPE_NAME => {
                type_name = parse_string_parameter(buf, offset, length, is_little_endian);
            }
            PID_ENDPOINT_GUID => {
                if length >= 16 {
                    let mut guid_bytes = [0u8; 16];
                    guid_bytes.copy_from_slice(&buf[offset..offset + 16]);
                    endpoint_guid = Some(GUID::from_bytes(guid_bytes));
                }
            }
            PID_TYPE_OBJECT => {
                if length > 0 {
                    match CompleteTypeObject::decode_cdr2_le(&buf[offset..offset + length]) {
                        Ok((type_obj, _consumed)) => {
                            type_object = Some(type_obj);
                        }
                        Err(e) => {
                            // Non-critical: TypeObject decode is best-effort.
                            // Small payloads (< ~50 bytes) are likely TypeIdentifier
                            // hashes from other vendors, not full CompleteTypeObjects.
                            log::debug!(
                                "[SEDP-PARSE] PID_TYPE_OBJECT decode failed: {:?} (length={})",
                                e,
                                length
                            );
                        }
                    }
                }
            }
            PID_RELIABILITY => {
                if length >= 4 {
                    let reliability_kind = read_u32(buf, offset, is_little_endian);
                    qos_reliability = match reliability_kind {
                        1 => Some(crate::dds::qos::Reliability::BestEffort),
                        2 => Some(crate::dds::qos::Reliability::Reliable),
                        _ => None,
                    };
                    log::debug!("[SEDP-QOS] [?] PID_RELIABILITY parsed: kind={} (1=BEST_EFFORT, 2=RELIABLE) -> {:?}",
                              reliability_kind, qos_reliability);
                }
            }
            PID_DURABILITY => {
                if length >= 4 {
                    let durability_kind = read_u32(buf, offset, is_little_endian);
                    qos_durability = match durability_kind {
                        0 => Some(crate::dds::qos::Durability::Volatile),
                        1 => Some(crate::dds::qos::Durability::TransientLocal),
                        // TRANSIENT (kind=2) mapped to TransientLocal: HDDS does not implement
                        // distributed cache (TRANSIENT requires a persistence service that
                        // outlives the DataWriter). TransientLocal is the closest behavior.
                        2 => Some(crate::dds::qos::Durability::TransientLocal),
                        3 => Some(crate::dds::qos::Durability::Persistent),
                        _ => None,
                    };
                    log::debug!("[SEDP-QOS] [?] PID_DURABILITY parsed: kind={} (0=VOLATILE, 1=TRANSIENT_LOCAL, 2=TRANSIENT, 3=PERSISTENT) -> {:?}",
                              durability_kind, qos_durability);
                }
            }
            PID_DURABILITY_SERVICE => {
                if qos_durability_service.is_none() {
                    qos_durability_service =
                        parse_durability_service(buf, offset, length, is_little_endian);
                }
            }
            PID_HISTORY => {
                if length >= 8 {
                    let history_kind = read_u32(buf, offset, is_little_endian);
                    let history_depth = read_u32(buf, offset + 4, is_little_endian);
                    qos_history = match history_kind {
                        0 => Some(crate::dds::qos::History::KeepLast(history_depth)),
                        1 => Some(crate::dds::qos::History::KeepAll),
                        _ => None,
                    };
                    log::debug!(
                        "[SEDP-QOS] [?] PID_HISTORY parsed: kind={} depth={} (0=KEEP_LAST, 1=KEEP_ALL) -> {:?}",
                        history_kind,
                        history_depth,
                        qos_history
                    );
                }
            }
            PID_PRESENTATION => {
                if qos_presentation.is_none() {
                    qos_presentation = parse_presentation(buf, offset, length, is_little_endian);
                }
            }
            PID_DATA_REPRESENTATION => {
                if length >= 4 {
                    let seq_len = read_u32(buf, offset, is_little_endian);
                    if seq_len > 0 && length >= 6 {
                        let data_repr = read_u16(buf, offset + 4, is_little_endian);
                        log::debug!("[SEDP-QOS] [?] PID_DATA_REPRESENTATION detected: 0x{:04x} (0=XCDR1, 2=XCDR2)", data_repr);
                    }
                }
            }
            PID_USER_DATA => {
                if user_data.is_none() {
                    user_data = parse_user_data_parameter(buf, offset, length, is_little_endian);
                }
            }
            // v110: Parse PID_PARTICIPANT_GUID - FastDDS/RTI interop requirement
            // Links endpoint to participant for validation in EDPSimpleListeners
            PID_PARTICIPANT_GUID => {
                if length >= 16 {
                    let mut guid_bytes = [0u8; 16];
                    guid_bytes.copy_from_slice(&buf[offset..offset + 16]);
                    participant_guid = Some(GUID::from_bytes(guid_bytes));
                    log::debug!(
                        "[SEDP-PARSE] [*] PID_PARTICIPANT_GUID (0x0050) parsed: {:?}",
                        participant_guid
                    );
                } else {
                    log::debug!(
                        "[SEDP-PARSE] [!]  PID_PARTICIPANT_GUID has invalid length: {}",
                        length
                    );
                    is_participant_data = true; // Don't require topic_name/type_name/endpoint_guid
                }
            }
            PID_PARTICIPANT_LEASE_DURATION => {
                log::debug!("[SEDP-PARSE] [*] PID_PARTICIPANT_LEASE_DURATION (0x0002) - skipping");
                is_participant_data = true;
            }
            PID_BUILTIN_ENDPOINT_SET => {
                log::debug!("[SEDP-PARSE] [*] PID_BUILTIN_ENDPOINT_SET (0x0058) - skipping");
                is_participant_data = true;
            }
            PID_METATRAFFIC_UNICAST_LOCATOR => {
                log::debug!("[SEDP-PARSE] [*] PID_METATRAFFIC_UNICAST_LOCATOR (0x0032) - skipping");
                is_participant_data = true;
            }
            // v143: Parse PID_UNICAST_LOCATOR (0x002f) - CRITICAL for OpenDDS interop
            // This tells HDDS where to send user data to the remote endpoint.
            // Format: kind (4 bytes) + port (4 bytes) + address (16 bytes) = 24 bytes
            PID_UNICAST_LOCATOR => {
                if length >= 24 {
                    let kind = if is_little_endian {
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

                    let port = if is_little_endian {
                        u32::from_le_bytes([
                            buf[offset + 4],
                            buf[offset + 5],
                            buf[offset + 6],
                            buf[offset + 7],
                        ])
                    } else {
                        u32::from_be_bytes([
                            buf[offset + 4],
                            buf[offset + 5],
                            buf[offset + 6],
                            buf[offset + 7],
                        ])
                    };

                    // Address is 16 bytes starting at offset + 8
                    // IPv4: kind=1, address in last 4 bytes (offset + 20..offset + 24)
                    // IPv6: kind=2, address in all 16 bytes
                    let socket_addr: Option<SocketAddr> = match kind {
                        1 => {
                            // LOCATOR_KIND_UDPV4 - IPv4 address in last 4 bytes
                            let ip = Ipv4Addr::new(
                                buf[offset + 20],
                                buf[offset + 21],
                                buf[offset + 22],
                                buf[offset + 23],
                            );
                            Some(SocketAddr::new(IpAddr::V4(ip), port as u16))
                        }
                        2 => {
                            // LOCATOR_KIND_UDPV6 - IPv6 address in all 16 bytes
                            let mut addr_bytes = [0u8; 16];
                            addr_bytes.copy_from_slice(&buf[offset + 8..offset + 24]);
                            let ip = Ipv6Addr::from(addr_bytes);
                            Some(SocketAddr::new(IpAddr::V6(ip), port as u16))
                        }
                        _ => {
                            log::debug!(
                                "[SEDP-PARSE] [!]  PID_UNICAST_LOCATOR: unknown kind={}",
                                kind
                            );
                            None
                        }
                    };

                    if let Some(addr) = socket_addr {
                        log::debug!(
                            "[SEDP-PARSE] [*] PID_UNICAST_LOCATOR (0x002f): {} (kind={})",
                            addr,
                            kind
                        );
                        unicast_locators.push(addr);
                    }
                } else {
                    log::debug!(
                        "[SEDP-PARSE] [!]  PID_UNICAST_LOCATOR: invalid length {} (expected 24)",
                        length
                    );
                }
            }
            // v59 FIX: Handle RTI compressed TypeObject
            // Reference: RTI Connext v6.1.0 mig_rtps.h, OMG RTPS v2.5 Sec.9.6.3.1, XTypes v1.3 Sec.7.3
            PID_TYPE_OBJECT_LB => {
                // PID_TYPE_OBJECT_LB - ZLIB-compressed CompleteTypeObject
                match decompress_type_object(buf, offset, length) {
                    Ok(decompressed) => match CompleteTypeObject::decode_cdr2_le(&decompressed) {
                        Ok((type_obj, _)) => {
                            type_object = Some(type_obj);
                            log::debug!("[SEDP-PARSE] [OK] Parsed CompleteTypeObject from compressed ZLIB (0x8021)");
                        }
                        Err(_) => {
                            log::debug!("[SEDP-PARSE] [!]  Failed to parse CompleteTypeObject from decompressed data");
                        }
                    },
                    Err(_) => {
                        log::debug!(
                            "[SEDP-PARSE] [!]  Failed to decompress ZLIB data for TypeObject"
                        );
                    }
                }
            }
            _ => {
                // Log unknown PIDs so we can see what we're missing!
                // This is CRITICAL for debugging interop issues.
                // Don't fail on unknown PIDs - only fail if CRITICAL fields are missing
                if pid >= 0x8000 {
                    // Vendor-specific PID (RTI, eProsima, etc.)
                    log::debug!(
                        "[SEDP-PARSE] [i]  Skipping vendor-specific PID: 0x{:04x} (length={})",
                        pid,
                        length
                    );
                } else {
                    // Standard DDS PID we don't handle yet
                    log::debug!(
                        "[SEDP-PARSE] [i]  Skipping unknown standard PID: 0x{:04x} (length={})",
                        pid,
                        length
                    );
                }
            }
        }

        offset += (length + 3) & !3;
    }

    // v59 FIX: ParticipantData SEDP doesn't have topic_name/type_name/endpoint_guid
    // Only Publication/Subscription announcements need these fields
    if is_participant_data {
        // ParticipantData - ignore and return error so caller skips it
        log::debug!(
            "[SEDP-PARSE] [i]  Ignoring ParticipantData SEDP (not a Publication/Subscription)"
        );
        return Err(ParseError::InvalidFormat);
    }

    let topic_name = topic_name.ok_or(ParseError::InvalidFormat)?;
    let type_name = type_name.ok_or(ParseError::InvalidFormat)?;
    let endpoint_guid = endpoint_guid.ok_or(ParseError::InvalidFormat)?;
    let qos_hash = simple_hash(&topic_name);

    // v110: Derive participant_guid from endpoint_guid if not explicitly provided
    // FastDDS EDPSimpleListeners requires this to link endpoint to participant
    let final_participant_guid = participant_guid.unwrap_or_else(|| {
        // Derive from endpoint_guid: copy prefix + use participant entity ID
        let mut pguid_bytes = [0u8; 16];
        pguid_bytes[..12].copy_from_slice(&endpoint_guid.as_bytes()[..12]); // Copy prefix
        pguid_bytes[12..16].copy_from_slice(&[0x00, 0x00, 0x01, 0xC1]); // Participant entityId
        GUID::from_bytes(pguid_bytes)
    });

    // v61: Build QoS object from parsed PIDs if ANY QoS values were found
    let qos = if qos_reliability.is_some()
        || qos_durability.is_some()
        || qos_history.is_some()
        || qos_presentation.is_some()
        || qos_durability_service.is_some()
    {
        // Start with default QoS and override with parsed values
        let mut qos_obj = crate::dds::qos::QoS::default();

        if let Some(reliability) = qos_reliability {
            qos_obj.reliability = reliability;
        }
        if let Some(durability) = qos_durability {
            qos_obj.durability = durability;
        }
        if let Some(history) = qos_history {
            qos_obj.history = history;
        }
        if let Some(presentation) = qos_presentation {
            qos_obj.presentation = presentation;
        }
        if let Some(ds) = qos_durability_service {
            qos_obj.durability_service = ds;
        }

        log::debug!(
            "[SEDP-QOS] [OK] Built QoS from PIDs: reliability={:?}, durability={:?}, history={:?}, presentation={:?}, durability_service.depth={}",
            qos_obj.reliability, qos_obj.durability, qos_obj.history, qos_obj.presentation,
            qos_obj.durability_service.history_depth
        );
        Some(qos_obj)
    } else {
        // No QoS PIDs found - will apply vendor defaults later
        log::debug!("[SEDP-QOS] [!]  No QoS PIDs found in SEDP - will apply vendor defaults");
        None
    };

    // v143: Log parsed unicast locators for OpenDDS interop debugging
    if !unicast_locators.is_empty() {
        log::debug!(
            "[SEDP-PARSE] [*] Parsed {} unicast locator(s): {:?}",
            unicast_locators.len(),
            unicast_locators
        );
    }

    Ok(SedpData {
        topic_name,
        type_name,
        participant_guid: final_participant_guid, // v110: Always populated (explicit or derived)
        endpoint_guid,
        qos_hash,
        qos, // v61: Return actual QoS parsed from PIDs!
        type_object,
        unicast_locators, // v143: Now parsed from PID_UNICAST_LOCATOR for OpenDDS interop
        user_data,
    })
}

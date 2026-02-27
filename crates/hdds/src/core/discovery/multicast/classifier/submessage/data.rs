// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DATA and DATA_FRAG submessage handlers.
//!
//!
//! DATA submessages carry user data or discovery information (SPDP/SEDP).
//! DATA_FRAG submessages carry fragmented data with reassembly metadata.

use super::super::super::{FragmentMetadata, PacketKind};
use crate::config::CLASSIFIER_SCAN_WINDOW;
use crate::core::discovery::GUID;

/// Handle DATA submessage with entity_id-based classification.
///
/// DATA submessage layout (RTPS v2.5 Sec.8.3.7.2):
/// - extraFlags (1) + octetsToInlineQos (1) + padding (2)
/// - readerEntityId (4)
/// - writerEntityId (4) <-- used for SPDP/SEDP classification
///
/// # Arguments
/// * `buf` - Raw packet buffer
/// * `offset` - Offset to DATA submessage start
///
/// # Returns
/// PacketKind::SPDP, PacketKind::SEDP, PacketKind::TypeLookup, or PacketKind::Data
pub(in crate::core::discovery::multicast::classifier) fn classify_data(
    buf: &[u8],
    offset: usize,
) -> PacketKind {
    crate::trace_fn!("classify_data");
    // Extract writerEntityId to determine if this is discovery data
    if offset + 4 + 8 + 4 <= buf.len() {
        let writer_entity_id = &buf[offset + 4 + 8..offset + 4 + 12];

        // v62: Use correct RTPS entity IDs from rtps_constants.rs
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
            RTPS_ENTITYID_SPDP_WRITER,
        };

        match writer_entity_id {
            w if w == RTPS_ENTITYID_SPDP_WRITER => {
                log::debug!(
                    "[CLASSIFY] SPDP participant discovery detected (entity_id={:02x?})",
                    w
                );
                PacketKind::SPDP
            }
            w if w == RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER => {
                log::debug!(
                    "[CLASSIFY] SEDP publications writer detected (entity_id={:02x?})",
                    w
                );
                PacketKind::SEDP
            }
            w if w == RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER => {
                log::debug!(
                    "[CLASSIFY] SEDP subscriptions writer detected (entity_id={:02x?})",
                    w
                );
                PacketKind::SEDP
            }
            w if w == crate::core::rtps_constants::RTPS_ENTITYID_TYPELOOKUP_WRITER => {
                log::debug!(
                    "[CLASSIFY] TypeLookup writer detected (entity_id={:02x?})",
                    w
                );
                PacketKind::TypeLookup
            }
            _ => PacketKind::Data, // User data
        }
    } else {
        PacketKind::Data // Not enough data to check, assume user data
    }
}

/// Handle DATA_FRAG submessage with entity_id-based classification and fragment metadata extraction.
///
/// DATA_FRAG layout is similar to DATA but includes fragment metadata.
///
/// # Arguments
/// * `buf` - Raw packet buffer
/// * `offset` - Offset to DATA_FRAG submessage start
/// * `flags` - Submessage flags (bit 0 = endianness)
/// * `guid_prefix` - GUID prefix from RTPS header (for constructing full writerGUID)
/// * `fragment_metadata` - Output parameter for fragment metadata
///
/// # Returns
/// (PacketKind, bool) - classification and whether this is a valid discovery packet
pub(in crate::core::discovery::multicast::classifier) fn classify_data_frag(
    buf: &[u8],
    offset: usize,
    flags: u8,
    guid_prefix: [u8; 12],
    fragment_metadata: &mut Option<FragmentMetadata>,
) -> (PacketKind, bool) {
    crate::trace_fn!("classify_data_frag");
    // DATA_FRAG layout: check entity_id for SEDP classification
    if offset + 4 + 8 + 4 <= buf.len() {
        let writer_entity_id = &buf[offset + 4 + 8..offset + 4 + 12];

        // v62: Use correct RTPS entity IDs from rtps_constants.rs
        use crate::core::rtps_constants::{
            RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
            RTPS_ENTITYID_SPDP_WRITER,
        };

        let kind = match writer_entity_id {
            w if w == RTPS_ENTITYID_SPDP_WRITER => {
                log::debug!("[CLASSIFY] SPDP fragment detected (entity_id={:02x?})", w);
                PacketKind::SPDP
            }
            w if w == RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER => {
                log::debug!(
                    "[CLASSIFY] SEDP publications fragment detected (entity_id={:02x?})",
                    w
                );
                PacketKind::SEDP
            }
            w if w == RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER => {
                log::debug!(
                    "[CLASSIFY] SEDP subscriptions fragment detected (entity_id={:02x?})",
                    w
                );
                PacketKind::SEDP
            }
            _ => PacketKind::DataFrag, // User data fragment
        };

        // Extract fragment metadata if buffer is large enough
        if offset + 36 <= buf.len() {
            // Try reading writerSeqNum as two u32 instead of one u64
            let seq_high = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 16],
                    buf[offset + 17],
                    buf[offset + 18],
                    buf[offset + 19],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 16],
                    buf[offset + 17],
                    buf[offset + 18],
                    buf[offset + 19],
                ])
            };

            let seq_low = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 20],
                    buf[offset + 21],
                    buf[offset + 22],
                    buf[offset + 23],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 20],
                    buf[offset + 21],
                    buf[offset + 22],
                    buf[offset + 23],
                ])
            };

            log::debug!(
                "[FRAG-SEQ] seqHigh={} seqLow={} (combined={})",
                seq_high,
                seq_low,
                ((seq_high as u64) << 32) | (seq_low as u64)
            );

            // Parse fragment metadata (RTPS 2.3 Sec 8.3.7.4)
            // DATA_FRAG layout after submessage header (4 bytes):
            // +4-7: extraFlags(2) + octetsToInlineQos(2)
            // +8-11: readerEntityId
            // +12-15: writerEntityId
            // +16-23: writerSeqNum (high:4 + low:4)
            // +24-27: fragmentStartingNum (u32)
            // +28-29: fragmentsInSubmessage (u16)
            // +30-31: fragmentSize (u16)
            // +32-35: dataSize (u32)
            // +36+: SerializedData payload
            let frag_starting_num = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 24],
                    buf[offset + 25],
                    buf[offset + 26],
                    buf[offset + 27],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 24],
                    buf[offset + 25],
                    buf[offset + 26],
                    buf[offset + 27],
                ])
            };

            let frags_in_submessage = if flags & 0x01 != 0 {
                u16::from_le_bytes([buf[offset + 28], buf[offset + 29]])
            } else {
                u16::from_be_bytes([buf[offset + 28], buf[offset + 29]])
            };

            let frag_size = if flags & 0x01 != 0 {
                u16::from_le_bytes([buf[offset + 30], buf[offset + 31]])
            } else {
                u16::from_be_bytes([buf[offset + 30], buf[offset + 31]])
            };

            // Read total data size (u32 at offset +32)
            let data_size = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 32],
                    buf[offset + 33],
                    buf[offset + 34],
                    buf[offset + 35],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 32],
                    buf[offset + 33],
                    buf[offset + 34],
                    buf[offset + 35],
                ])
            };

            // Calculate total number of fragments from data_size / fragment_size
            let total_frags = if frag_size > 0 {
                (data_size as usize).div_ceil(frag_size as usize) as u16
            } else {
                frags_in_submessage
            };

            // Extract writerEntityId (offset +12-15) to construct full writerGUID
            let writer_entity_id = if flags & 0x01 != 0 {
                u32::from_le_bytes([
                    buf[offset + 12],
                    buf[offset + 13],
                    buf[offset + 14],
                    buf[offset + 15],
                ])
            } else {
                u32::from_be_bytes([
                    buf[offset + 12],
                    buf[offset + 13],
                    buf[offset + 14],
                    buf[offset + 15],
                ])
            };

            // Construct full writerGUID from GUID prefix + writerEntityId
            // Convert u32 entity_id to [u8; 4] bytes (preserve endianness from parsing)
            let entity_id_bytes = if flags & 0x01 != 0 {
                writer_entity_id.to_le_bytes()
            } else {
                writer_entity_id.to_be_bytes()
            };
            let writer_guid = GUID::new(guid_prefix, entity_id_bytes);
            let seq_num = ((seq_high as u64) << 32) | (seq_low as u64);

            // Store fragment metadata for callback
            *fragment_metadata = Some(FragmentMetadata {
                writer_guid,
                seq_num,
                frag_num: frag_starting_num,
                total_frags,
            });

            log::debug!(
                "[FRAG-META] writerGUID={:?} seqNum={} frag={}/{}",
                writer_guid,
                seq_num,
                frag_starting_num,
                total_frags
            );

            // Phase 1.6: Accept ALL fragments for fragment reassembly buffer
            // (Previously we only accepted fragment #1)
            (kind, true)
        } else {
            (kind, false) // Buffer too small, skip
        }
    } else {
        (PacketKind::DataFrag, false) // Not enough data to check, assume user data
    }
}

/// Calculate payload offset for DATA/DATA_FRAG submessages.
///
/// Payload offset depends on submessage type:
///
/// DATA_FRAG structure (RTPS 2.3 Sec.8.3.7.4):
///   +0-3:   submessageId, flags, octetsToNextHeader (4 bytes)
///   +4-23:  fragment metadata (20 bytes)
///   +24:    encapsulation starts here
///
/// DATA structure (RTPS 2.3 Sec.8.3.7.2):
///   +0-3:   submessageId, flags, octetsToNextHeader (4 bytes)
///   +4-5:   extraFlags (2 bytes)
///   +6-7:   octetsToInlineQos (2 bytes) <- IMPORTANT!
///   +8-11:  readerEntityId (4 bytes)
///   +12-15: writerEntityId (4 bytes)
///   +16-23: writerSeqNum (8 bytes)
///   +24:    InlineQoS parameters (if octetsToInlineQos > 0)
///   +24+octetsToInlineQos: encapsulation starts here
///
/// # Arguments
/// * `buf` - Raw packet buffer
/// * `offset` - Offset to submessage start
/// * `flags` - Submessage flags (bit 0 = endianness, bit 1 = Q flag)
/// * `kind` - PacketKind classification
///
/// # Returns
/// Payload offset (byte position where encapsulation header starts)
pub(in crate::core::discovery::multicast::classifier) fn calculate_payload_offset(
    buf: &[u8],
    offset: usize,
    flags: u8,
    kind: PacketKind,
) -> usize {
    crate::trace_fn!("calculate_payload_offset");
    // Both DATA and DATA_FRAG have octetsToInlineQos field
    // CRITICAL: octetsToInlineQos is an ABSOLUTE offset from submessage start,
    // not a relative size to add!
    //
    // From RTPS 2.3 spec:
    // - If Q flag is set (bit 1): offset points to InlineQoS ParameterList
    // - If Q flag is NOT set: offset points directly to SerializedData
    //
    // Read octetsToInlineQos from the header (at offset +6-7)
    let payload_offset_value =
        if offset + 8 <= buf.len() {
            let octets_to_inline_qos = if flags & 0x01 != 0 {
                u16::from_le_bytes([buf[offset + 6], buf[offset + 7]])
            } else {
                u16::from_be_bytes([buf[offset + 6], buf[offset + 7]])
            };

            let has_inline_qos = (flags & 0x02) != 0; // Q flag (bit 1)

            // DEBUG: Always log octetsToInlineQos to understand the packets
            log::debug!(
            "[PAYLOAD-OFFSET-DEBUG] {} at offset={} flags=0x{:02x} octetsToInlineQos={} Q_flag={}",
            if matches!(kind, PacketKind::Data | PacketKind::TypeLookup) {
                "DATA"
            } else {
                "DATA_FRAG"
            },
            offset, flags, octets_to_inline_qos, has_inline_qos
        );

            // RTPS 2.3 spec: octetsToInlineQos behavior
            // - If > 0: absolute offset from submessage start to SerializedData
            // - If == 0: no InlineQoS, use default header size (24 bytes)
            //
            // RTI DATA_FRAG compact format discovery:
            // writerSeqNum (8 bytes) ends at offset +24
            // Encapsulation header (4 bytes: 00 03 00 00 for CDR_LE) starts at +24
            // PID parameters start at +28
            if matches!(kind, PacketKind::DataFrag) {
                // DATA_FRAG: Payload (with encapsulation) starts at +36
                // (4 submessage header + 20 standard headers + 12 fragment metadata)
                // Fragment metadata: fragmentStartingNum(4) + fragmentsInSubmessage(2)
                //                  + fragmentSize(2) + sampleSize(4) = 12 bytes
                offset + 36
            } else if octets_to_inline_qos > 0 && has_inline_qos {
                // DATA with inline QoS: scan for PID_SENTINEL to find SerializedData start
                // v137: Only scan when Q flag is set - without inline QoS, data starts at offset+24
                // Accept all RTI sentinel variants (0x0001, 0x3F01, 0x3F02, 0x3F03, 0x3F41)
                const PID_SENTINEL: u16 = 0x0001;
                const PID_SENTINEL_EXTENDED: u16 = 0x3F01;
                const PID_SENTINEL_ALT: u16 = 0x3F02;
                const PID_SENTINEL_LEGACY: u16 = 0x3F03;
                const PID_SENTINEL_COMPLETE: u16 = 0x3F41;
                let mut p = offset + 8 + octets_to_inline_qos as usize;
                let mut payload_off = None;
                let scan_limit = (p + CLASSIFIER_SCAN_WINDOW).min(buf.len());
                while p + 4 <= scan_limit {
                    let pid = if flags & 0x01 != 0 {
                        u16::from_le_bytes([buf[p], buf[p + 1]])
                    } else {
                        u16::from_be_bytes([buf[p], buf[p + 1]])
                    };
                    let len = if flags & 0x01 != 0 {
                        u16::from_le_bytes([buf[p + 2], buf[p + 3]]) as usize
                    } else {
                        u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize
                    };
                    p += 4;
                    if matches!(
                        pid,
                        PID_SENTINEL
                            | PID_SENTINEL_EXTENDED
                            | PID_SENTINEL_ALT
                            | PID_SENTINEL_LEGACY
                            | PID_SENTINEL_COMPLETE
                    ) {
                        payload_off = Some(p);
                        break;
                    }
                    if p + len > buf.len() {
                        break;
                    }
                    p += (len + 3) & !3;
                }
                payload_off.unwrap_or(offset + 24)
            } else {
                // Default: encapsulation starts after standard 24-byte header
                offset + 24
            }
        } else {
            offset + 24 // Fallback: assume standard header size
        };
    payload_offset_value
}

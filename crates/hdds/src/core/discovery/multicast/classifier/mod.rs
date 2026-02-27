// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Packet Classifier - Main orchestration module.
//!
//!
//! This module coordinates RTPS packet classification by:
//! 1. Validating RTPS header (via header module)
//! 2. Scanning submessages (via submessage module)
//! 3. Accumulating RTPS context (INFO_DST, INFO_TS)
//! 4. Returning classification tuple

mod header;
mod submessage;

use super::{FragmentMetadata, PacketKind, RtpsContext};
use crate::config::CLASSIFIER_SCAN_WINDOW;

/// Classify RTPS packet by scanning all submessages.
///
/// RTPS packet structure (DDS-RTPS v2.3 Sec.8.3):
/// ```text
/// Offset  | Field              | Size | Value
/// --------|--------------------|------|--------
/// 0-3     | Protocol           | 4    | "RTPS" (0x52 0x54 0x50 0x53)
/// 4-5     | Version            | 2    | 2.3 (0x02 0x03)
/// 6-7     | Vendor ID          | 2    | varies (RTI=0x0101, HDDS=0x01aa)
/// 8-19    | GUID prefix        | 12   | participant GUID prefix (12 bytes per RTPS v2.3!)
/// 20+     | Submessages...     | var  | Multiple submessages (Sec.8.3.3)
/// ```
///
/// Submessage structure (Sec.8.3.3):
/// ```text
/// Offset  | Field              | Size | Value (RTPS v2.3 Table 8.13)
/// --------|--------------------|------|--------
/// 0       | Submessage ID      | 1    | 0x15=DATA, 0x16=DATA_FRAG, 0x06=HB, 0x09=INFO_TS, ...
/// 1       | Flags              | 1    | bit 0 = endianness (E)
/// 2-3     | octetsToNextHeader | 2    | length to next submessage (0=last)
/// 4+      | Submessage content | var  | submessage-specific data
/// ```
///
/// # Spec Compliance
/// Per RTPS v2.3 Sec.8.3.3.1, a single RTPS message can contain multiple submessages.
/// This scanner iterates through ALL submessages to classify the packet correctly.
///
/// # Arguments
/// * `buf` - Raw packet buffer
///
/// # Returns
/// Tuple of `(PacketKind, Option<payload_offset>, Option<FragmentMetadata>, RtpsContext)` where:
/// - payload_offset is the byte offset to the DATA submessage payload (after 4-byte submessage header).
///   None for non-DATA packets or standard offset (20+4=24 for simple DATA submessage).
/// - FragmentMetadata is present for PacketKind::DataFrag packets
/// - RtpsContext contains accumulated INFO_DST/INFO_TS state from scanning (v61 Blocker #1)
///
/// # Examples
/// ```
/// use hdds::core::discovery::multicast::{classify_rtps, PacketKind};
///
/// let mut pkt = vec![0u8; 48];
/// // RTPS header
/// pkt[0..4].copy_from_slice(b"RTPS");  // Protocol ID
/// pkt[4] = 0x02; pkt[5] = 0x03;       // Version 2.3
/// pkt[6] = 0x01; pkt[7] = 0xaa;       // Vendor ID (HDDS)
/// // GUID prefix at [8..20] left as zeros
/// // DATA submessage at offset 20
/// pkt[20] = 0x15;                      // DATA submessage ID
/// pkt[21] = 0x01;                      // Flags (little-endian)
/// pkt[22] = 24; pkt[23] = 0;          // octetsToNextHeader
///
/// let (kind, _offset, _meta, _ctx) = classify_rtps(&pkt);
/// assert_eq!(kind, PacketKind::Data);
/// ```
pub fn classify_rtps(
    buf: &[u8],
) -> (
    PacketKind,
    Option<usize>,
    Option<FragmentMetadata>,
    RtpsContext,
) {
    crate::trace_fn!("classify_rtps");
    // Step 1: Validate RTPS header and extract metadata
    let rtps_header = match header::validate_and_extract_header(buf) {
        Ok(header) => header,
        Err(error_tuple) => return error_tuple,
    };

    let vendor_id = rtps_header.vendor_id;
    let guid_prefix = rtps_header.guid_prefix;

    // Step 2: Scan all submessages starting at offset 20 (after 20-byte RTPS header)
    let mut offset = 20;
    let mut found_kind = PacketKind::Unknown;
    let mut data_payload_offset: Option<usize> = None;
    let mut fragment_metadata: Option<FragmentMetadata> = None;

    // v61 Blocker #1: RTPS context accumulator
    // INFO_DST and INFO_TS submessages set state for subsequent submessages
    // Per RTPS v2.5 Sec.8.3.7.5 (INFO_DST) and Sec.8.3.7.7 (INFO_TS)
    let mut rtps_context = RtpsContext::default();

    log::debug!("[CLASSIFY] Starting submessage scan for vendor 0x{:04x}, packet length={}, starting offset={}",
              vendor_id, buf.len(), offset);

    while offset + 4 <= buf.len() {
        let submessage_id = buf[offset];
        let flags = buf[offset + 1];

        // Read octetsToNextHeader (2 bytes, endianness depends on E flag in bit 0)
        let octets_to_next = if flags & 0x01 != 0 {
            // Little-endian (E flag set)
            u16::from_le_bytes([buf[offset + 2], buf[offset + 3]])
        } else {
            // Big-endian (E flag clear)
            u16::from_be_bytes([buf[offset + 2], buf[offset + 3]])
        };

        log::debug!(
            "[RTPS-DEBUG] Submessage at offset {}: ID=0x{:02x} flags=0x{:02x} octets_to_next={}",
            offset,
            submessage_id,
            flags,
            octets_to_next
        );

        // Extra debug for RTI packets
        if vendor_id == 0x0101 {
            log::debug!(
                "[CLASSIFY-RTI] Submsg ID=0x{:02x} at offset {} (octets_to_next={})",
                submessage_id,
                offset,
                octets_to_next
            );
        }

        // Step 3: Classify this submessage (RTPS v2.3 Table 8.13)
        let kind = match submessage_id {
            0x01 => PacketKind::Pad,                // PAD submessage (alignment padding)
            0x06 => submessage::classify_acknack(), // ACKNACK submessage
            0x07 => submessage::classify_heartbeat(), // HEARTBEAT submessage
            0x08 => submessage::classify_gap(),     // GAP submessage (missing sequence numbers)
            0x09 => submessage::classify_info_ts(buf, offset, flags, &mut rtps_context),
            0x12 => submessage::classify_nack_frag(), // NACK_FRAG submessage (RTPS v2.3 Sec.8.3.7.5)
            0x13 => submessage::classify_heartbeat_frag(), // HEARTBEAT_FRAG submessage (RTPS v2.3 Sec.8.3.7.6)
            0x0c => PacketKind::InfoSrc,                   // INFO_SRC (source GUID prefix)
            0x0d => PacketKind::InfoReply, // INFO_REPLY_IP4 (IPv4 unicast reply locator)
            0x0e => submessage::classify_info_dst(buf, offset, &mut rtps_context),
            0x0f => PacketKind::InfoReply, // INFO_REPLY (unicast reply locator list)
            0x15 => submessage::classify_data(buf, offset),
            0x16 => {
                let (frag_kind, _is_valid) = submessage::classify_data_frag(
                    buf,
                    offset,
                    flags,
                    guid_prefix,
                    &mut fragment_metadata,
                );
                frag_kind
            }

            // RTI Connext proprietary submessages (vendor_id 0x0101)
            0x6e | 0x8f | 0x3f => submessage::classify_rti_proprietary(submessage_id, vendor_id),

            // eProsima FastDDS proprietary submessages (vendor_id 0x010F)
            0x80 => submessage::classify_eprosima_proprietary(submessage_id, vendor_id),

            _ => submessage::classify_unknown(submessage_id, vendor_id),
        };

        // Step 4: Prioritize DATA and DATA_FRAG packets (discovery packets)
        // For RTI packets, DATA_FRAG often contains the actual SPDP data
        //
        // Filter criteria:
        // 1. DATA packets: octets_to_next >= 16 (min discovery payload) OR octets_to_next == 0 (last submessage)
        //    v197: Fixed - octets_to_next=0 is valid for user DATA packets (last submessage sentinel)
        // 2. DATA_FRAG packets must be fragment #1 (only first fragment has encapsulation)
        let is_valid_discovery_packet = if matches!(kind, PacketKind::Data | PacketKind::TypeLookup)
        {
            octets_to_next >= 16 || octets_to_next == 0
        } else if matches!(kind, PacketKind::DataFrag) {
            // DATA_FRAG: Already validated in classify_data_frag
            fragment_metadata.is_some()
        } else {
            true // Other packet types
        };

        if matches!(
            kind,
            PacketKind::Data
                | PacketKind::DataFrag
                | PacketKind::SEDP
                | PacketKind::SPDP
                | PacketKind::TypeLookup
        ) && is_valid_discovery_packet
        {
            // For RTI and HDDS vendors, prefer DATA_FRAG over small DATA submessages
            // DATA_FRAG is at offset + 4, but has additional headers
            // RTI = 0x0101, HDDS = 0x01AA
            let should_update = if vendor_id == 0x0101 || vendor_id == 0x01AA {
                // RTI/HDDS: prefer DATA_FRAG, or DATA with large payload
                matches!(kind, PacketKind::DataFrag)
                    || (matches!(kind, PacketKind::Data) && octets_to_next > 100)
            } else {
                // Other vendors: prefer DATA over DATA_FRAG
                matches!(kind, PacketKind::Data | PacketKind::TypeLookup)
                    || !matches!(found_kind, PacketKind::Data | PacketKind::TypeLookup)
            };

            // Always prioritize SEDP/SPDP classification over generic Data/DataFrag
            if matches!(kind, PacketKind::SEDP | PacketKind::SPDP) {
                found_kind = kind;
                // SEDP/SPDP are always DATA submessages, calculate payload offset
            } else if should_update || matches!(found_kind, PacketKind::Unknown) {
                found_kind = kind;
            }

            // Step 5: Calculate payload offset for any DATA/DataFrag/SEDP/SPDP packet we're using
            if matches!(
                found_kind,
                PacketKind::Data
                    | PacketKind::DataFrag
                    | PacketKind::SEDP
                    | PacketKind::SPDP
                    | PacketKind::TypeLookup
            ) && (kind == found_kind || matches!(kind, PacketKind::SEDP | PacketKind::SPDP))
            {
                let payload_offset_value =
                    submessage::calculate_payload_offset(buf, offset, flags, kind);
                data_payload_offset = Some(payload_offset_value);
                log::debug!("[RTPS-DEBUG] Found {} submessage at offset {}, payload at offset {}, octets_to_next={}",
                          if matches!(kind, PacketKind::DataFrag) { "DATA_FRAG" } else { "DATA" },
                          offset, payload_offset_value, octets_to_next);

                // For RTI DATA_FRAG, continue scanning in case there are multiple fragments
                // For standard DATA/SEDP/SPDP with large payload, we can stop
                // v137: Include SEDP/SPDP in break condition to prevent HEARTBEAT from overwriting cdr_offset
                if matches!(
                    kind,
                    PacketKind::Data | PacketKind::SEDP | PacketKind::SPDP | PacketKind::TypeLookup
                ) && octets_to_next > 100
                {
                    break;
                }
            }
        } else if matches!(found_kind, PacketKind::Unknown) && !matches!(kind, PacketKind::Unknown)
        {
            // Update found_kind if we haven't found anything yet
            // v136: Don't override found_kind with INFO_* submessages - they're context, not primary type
            // INFO_DST and INFO_TS are just context for subsequent DATA submessages
            if !matches!(
                kind,
                PacketKind::InfoDst
                    | PacketKind::InfoTs
                    | PacketKind::InfoSrc
                    | PacketKind::InfoReply
            ) {
                found_kind = kind;
            }
        }

        // Step 6: Move to next submessage
        // Per spec Sec.8.3.3: next submessage at offset + 4 (header) + octetsToNextHeader
        if octets_to_next == 0 {
            // Last submessage in packet
            log::debug!("[RTPS-DEBUG] Reached sentinel (octets_to_next=0)");
            break;
        }

        let next_offset = offset + 4 + octets_to_next as usize;

        // Validate next_offset doesn't exceed buffer
        if next_offset > buf.len() {
            log::debug!("[RTPS-DEBUG] Invalid octets_to_next={} would exceed buffer (offset={}, buf.len={})",
                      octets_to_next, offset, buf.len());

            // For ANY submessage with invalid octets_to_next (including RTI's broken ACKNACK),
            // try to recover by scanning forward for next valid submessage
            // RTI sends ACKNACK with octets_to_next=55983 followed by valid DATA_FRAG
            if true
            // Always try recovery for invalid octets_to_next
            {
                log::debug!(
                    "[CLASSIFY] Attempting to recover: scanning forward for next submessage"
                );

                // Scan forward in 4-byte increments (submessages are 4-byte aligned)
                let mut scan_offset = offset + 4;
                let mut recovered = false;

                // Limit scan to next CLASSIFIER_SCAN_WINDOW bytes to avoid excessive searching
                let scan_limit = (scan_offset + CLASSIFIER_SCAN_WINDOW).min(buf.len());

                while scan_offset + 4 <= scan_limit {
                    // Align to 4-byte boundary
                    scan_offset = (scan_offset + 3) & !3;

                    if scan_offset + 4 > buf.len() {
                        break;
                    }

                    let potential_id = buf[scan_offset];
                    let potential_flags = buf[scan_offset + 1];

                    // Check if this looks like a valid submessage header
                    // Valid IDs: 0x01-0x15, 0x80-0xff
                    // Valid flags: bit 0 = endianness, other bits should be reasonable
                    if (potential_id <= 0x15 || potential_id >= 0x80) && potential_flags < 0x20 {
                        let test_octets = if potential_flags & 0x01 != 0 {
                            u16::from_le_bytes([buf[scan_offset + 2], buf[scan_offset + 3]])
                        } else {
                            u16::from_be_bytes([buf[scan_offset + 2], buf[scan_offset + 3]])
                        };

                        // Verify octets_to_next is reasonable
                        let test_next = scan_offset + 4 + test_octets as usize;
                        if test_next <= buf.len() || test_octets == 0 {
                            log::debug!("[CLASSIFY] Recovery successful: found potential submessage 0x{:02x} at offset {}",
                                      potential_id, scan_offset);
                            offset = scan_offset;
                            recovered = true;
                            break;
                        }
                    }

                    scan_offset += 4;
                }

                if !recovered {
                    log::debug!(
                        "[CLASSIFY] Recovery failed: no valid submessage found, stopping scan"
                    );
                    break;
                }

                // Continue with recovered offset (don't increment, let loop reprocess)
                continue;
            } else {
                // For known submessage types with invalid length, stop scanning
                break;
            }
        }

        offset = next_offset;

        // Align to 4-byte boundary (spec Sec.8.3.3.1)
        offset = (offset + 3) & !3;
    }

    log::debug!(
        "[RTPS-DEBUG] Final classification: {:?}, payload_offset: {:?}, fragment_metadata: {:?}, rtps_context: {:?}",
        found_kind, data_payload_offset, fragment_metadata, rtps_context
    );
    (
        found_kind,
        data_payload_offset,
        fragment_metadata,
        rtps_context,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_data() {
        // Create minimal valid DATA packet (44 bytes minimum: 20 header + 24 submessage)
        let mut buf = vec![0u8; 60]; // Increased to 60 for payload space
        buf[0..4].copy_from_slice(b"RTPS");
        buf[20] = 0x15; // DATA submessageId (RTPS v2.3 Table 8.13)
        buf[21] = 0x01; // flags: little-endian
        buf[22] = 32; // octetsToNextHeader (low byte)
        buf[23] = 0; // octetsToNextHeader (high byte)
                     // octetsToInlineQos at offset 26-27: set to 16 (no inline QoS)
        buf[26] = 16; // octetsToInlineQos = 16 (fixed fields size)
        buf[27] = 0;

        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Data);
        // DATA at offset 20, octetsToInlineQos=16
        // Payload offset = 20 + 16 + 8 = 44 (per RTPS v2.3 Sec.8.3.7.2)
        assert_eq!(offset, Some(44)); // 20 + 16 + 8
        assert!(frag_meta.is_none()); // DATA has no fragment metadata
    }

    #[test]
    fn test_classify_heartbeat() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        buf[20] = 0x07; // HEARTBEAT (0x07 per RTPS v2.3 Table 8.13)
        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Heartbeat);
        assert_eq!(offset, None); // No DATA payload for non-DATA packets
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_acknack() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        buf[20] = 0x06; // ACKNACK (0x06 per RTPS v2.3 Table 8.13)
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::AckNack);
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_datafrag() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        buf[20] = 0x16; // DATA_FRAG (RTPS v2.3 Table 8.13)
        let (kind, _offset, _frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::DataFrag);
        // Note: frag_meta will be None because buffer is too small for full DATA_FRAG headers
    }

    #[test]
    fn test_classify_invalid_magic() {
        let buf = vec![0u8; 24];
        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Invalid);
        assert_eq!(offset, None);
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_truncated() {
        let buf = vec![0u8; 10];
        let (kind, offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Invalid);
        assert_eq!(offset, None);
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_unknown_submessage() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        buf[20] = 0xFF; // Unknown submessage ID (now at offset 20, not 16!)
        let (kind, _offset, _frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::Unknown);
    }

    #[test]
    fn test_classify_nack_frag() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        buf[20] = 0x12; // NACK_FRAG (0x12 per RTPS v2.3 Sec.8.3.7.5)
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::NackFrag);
        assert!(frag_meta.is_none());
    }

    #[test]
    fn test_classify_heartbeat_frag() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(b"RTPS");
        buf[20] = 0x13; // HEARTBEAT_FRAG (0x13 per RTPS v2.3 Sec.8.3.7.6)
        let (kind, _offset, frag_meta, _ctx) = classify_rtps(&buf);
        assert_eq!(kind, PacketKind::HeartbeatFrag);
        assert!(frag_meta.is_none());
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! INFO submessage handlers (INFO_TS, INFO_DST).
//!
//! INFO submessages provide context for subsequent DATA submessages:
//! - INFO_TS: Sets source timestamp (RTPS v2.5 Sec.8.3.7.7)
//! - INFO_DST: Sets destination GUID prefix (RTPS v2.5 Sec.8.3.7.5)

use super::super::super::{PacketKind, RtpsContext};

/// Handle INFO_TS submessage (timestamp information).
///
/// RTPS v2.5 Sec.8.3.7.7: Sets source timestamp for subsequent DATA submessages.
/// Structure (12 bytes): submessageId (1) + flags (1) + octetsToNextHeader (2) + timestamp (8)
/// Timestamp: seconds (i32) + fraction (u32)
///
/// # Arguments
/// * `buf` - Raw packet buffer
/// * `offset` - Offset to INFO_TS submessage start
/// * `flags` - Submessage flags (bit 0 = endianness)
/// * `rtps_context` - Mutable context to store timestamp
///
/// # Returns
/// PacketKind::InfoTs
pub(in crate::core::discovery::multicast::classifier) fn classify_info_ts(
    buf: &[u8],
    offset: usize,
    flags: u8,
    rtps_context: &mut RtpsContext,
) -> PacketKind {
    crate::trace_fn!("classify_info_ts");
    // INFO_TS structure: 4-byte header + 8-byte timestamp
    if offset + 4 + 8 <= buf.len() {
        let timestamp_seconds = if flags & 0x01 != 0 {
            i32::from_le_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ])
        } else {
            i32::from_be_bytes([
                buf[offset + 4],
                buf[offset + 5],
                buf[offset + 6],
                buf[offset + 7],
            ])
        };
        let timestamp_fraction = if flags & 0x01 != 0 {
            u32::from_le_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
            ])
        } else {
            u32::from_be_bytes([
                buf[offset + 8],
                buf[offset + 9],
                buf[offset + 10],
                buf[offset + 11],
            ])
        };
        rtps_context.source_timestamp = Some((timestamp_seconds, timestamp_fraction));
        log::debug!(
            "[RTPS-CONTEXT] INFO_TS: timestamp=({}, {})",
            timestamp_seconds,
            timestamp_fraction
        );
    }
    PacketKind::InfoTs
}

/// Handle INFO_DST submessage (destination GUID prefix).
///
/// RTPS v2.5 Sec.8.3.7.5: Sets destination for subsequent submessages.
/// Structure (16 bytes): submessageId (1) + flags (1) + octetsToNextHeader (2) + guidPrefix (12)
///
/// # Arguments
/// * `buf` - Raw packet buffer
/// * `offset` - Offset to INFO_DST submessage start
/// * `rtps_context` - Mutable context to store destination GUID prefix
///
/// # Returns
/// PacketKind::InfoDst
pub(in crate::core::discovery::multicast::classifier) fn classify_info_dst(
    buf: &[u8],
    offset: usize,
    rtps_context: &mut RtpsContext,
) -> PacketKind {
    crate::trace_fn!("classify_info_dst");
    // INFO_DST structure: 4-byte header + 12-byte GUID prefix
    if offset + 4 + 12 <= buf.len() {
        let mut dest_prefix = [0u8; 12];
        dest_prefix.copy_from_slice(&buf[offset + 4..offset + 16]);
        rtps_context.destination_guid_prefix = Some(dest_prefix);
        log::debug!("[RTPS-CONTEXT] INFO_DST: dest_prefix={:02x?}", dest_prefix);
    }
    PacketKind::InfoDst
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Vendor-specific and unknown submessage handlers.
//!
//! Handles vendor id 0x0101 submessage ids, eProsima/FastDDS submessages, and unknown types.

use super::super::super::PacketKind;
use crate::core::rtps_constants::EPROSIMA_VENDOR_ID_U16;

/// Handle submessage ids 0x6e, 0x8f, 0x3f under vendor_id 0x0101.
///
/// The ids were reported in a hexdump of a Connext 6.1 peer's traffic during
/// early interop work; no Connext capture on disk (6.1, 7.3, 7.7) carries
/// them. 0x6e and 0x3f are not vendor-specific ids at all (DDSI-RTPS 2.5
/// Sec.9.4.5.1 reserves 0x80-0xff). Whatever they are, an unknown submessage
/// is ignored and parsing continues (Sec.8.3.4.1 rule 3): this logs the
/// listed ids for vendor_id 0x0101 and classifies them as Unknown, the result
/// `classify_unknown` gives.
///
/// # Arguments
/// * `submessage_id` - The submessage ID byte
/// * `vendor_id` - Vendor ID from RTPS header
///
/// # Returns
/// PacketKind::Unknown
pub(in crate::core::discovery::multicast::classifier) fn classify_rti_proprietary(
    submessage_id: u8,
    vendor_id: u16,
) -> PacketKind {
    crate::trace_fn!("classify_rti_proprietary");
    if vendor_id == 0x0101 {
        match submessage_id {
            0x6e | 0x8f | 0x3f => log::debug!(
                "[VENDOR-0x0101] Submessage {submessage_id:#04x}: not interpreted, skipped"
            ),
            _ => {}
        }
    }
    PacketKind::Unknown
}

/// Handle eProsima FastDDS proprietary submessages.
///
/// eProsima FastDDS (vendor_id 0x010F) uses vendor-specific submessage IDs (>= 0x80).
/// Reference: https://github.com/eProsima/Fast-DDS
///
/// # Arguments
/// * `submessage_id` - The submessage ID byte
/// * `vendor_id` - Vendor ID from RTPS header
///
/// # Returns
/// PacketKind::Unknown
pub(in crate::core::discovery::multicast::classifier) fn classify_eprosima_proprietary(
    submessage_id: u8,
    vendor_id: u16,
) -> PacketKind {
    crate::trace_fn!("classify_eprosima_proprietary");
    if vendor_id == EPROSIMA_VENDOR_ID_U16 {
        match submessage_id {
            0x80 => log::debug!("[EPROSIMA-PROPRIETARY] Submessage 0x80 (FastDDS proprietary)"),
            0x81..=0xFF => {
                log::debug!(
                    "[EPROSIMA-PROPRIETARY] Submessage 0x{:02x} (FastDDS vendor-specific)",
                    submessage_id
                )
            }
            _ => {}
        }
    }
    PacketKind::Unknown
}

/// Handle unknown submessage types.
///
/// # Arguments
/// * `submessage_id` - The submessage ID byte
/// * `vendor_id` - Vendor ID from RTPS header
///
/// # Returns
/// PacketKind::Unknown
pub(in crate::core::discovery::multicast::classifier) fn classify_unknown(
    submessage_id: u8,
    vendor_id: u16,
) -> PacketKind {
    crate::trace_fn!("classify_unknown");
    if submessage_id >= 0x80 {
        log::debug!(
            "[RTPS-DEBUG] Vendor-specific submessage ID: 0x{:02x} (vendor=0x{:04x})",
            submessage_id,
            vendor_id
        );
    } else {
        log::debug!(
            "[RTPS-DEBUG] Unknown submessage ID: 0x{:02x}",
            submessage_id
        );
    }
    PacketKind::Unknown
}

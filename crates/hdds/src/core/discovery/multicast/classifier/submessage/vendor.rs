// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Vendor-specific and unknown submessage handlers.
//!
//! Handles RTI proprietary submessages, eProsima/FastDDS submessages, and unknown types.

use super::super::super::PacketKind;
use crate::core::rtps_constants::EPROSIMA_VENDOR_ID_U16;

/// Handle RTI proprietary submessages.
///
/// RTI Connext (vendor_id 0x0101) uses vendor-specific submessage IDs (>= 0x80).
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
            0x6e => log::debug!("[RTI-PROPRIETARY] Submessage 0x6e (RTI metadata/optimization)"),
            0x8f => log::debug!("[RTI-PROPRIETARY] Submessage 0x8f (RTI security/routing)"),
            0x3f => log::debug!("[RTI-PROPRIETARY] Submessage 0x3f (RTI custom)"),
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

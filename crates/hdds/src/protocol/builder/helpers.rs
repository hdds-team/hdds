// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use crate::protocol::constants::*;
use std::convert::TryFrom;

/// Validate RTPS DATA packet header (eliminates duplication across helpers).
///
/// Accepts both RTPS (0x52545053) and RTPX (0x52545058) magic for RTI interop.
///
/// RTPS Header layout (20 bytes total):
/// - Magic "RTPS": 4 bytes (offset 0-3)
/// - Protocol version: 2 bytes (offset 4-5)
/// - Vendor ID: 2 bytes (offset 6-7)
/// - GUID Prefix: 12 bytes (offset 8-19)
/// - First submessage starts at offset 20
pub(super) fn validate_rtps_data_packet(rtps_packet: &[u8], min_len: usize) -> bool {
    if rtps_packet.len() < min_len {
        return false;
    }

    // Accept both RTPS and RTPX magic (RTI vendor extension)
    let magic_valid = &rtps_packet[0..4] == RTPS_MAGIC || &rtps_packet[0..4] == b"RTPX";

    // First submessage ID is at offset 20 (after 20-byte RTPS header)
    magic_valid && rtps_packet.len() > 20 && rtps_packet[20] == RTPS_SUBMSG_DATA
}

/// Build standard RTPS header (16 bytes).
#[allow(dead_code)] // Part of builder API, may be used when RTPS builders are expanded
pub(super) fn build_rtps_header() -> [u8; 16] {
    [
        RTPS_MAGIC[0],
        RTPS_MAGIC[1],
        RTPS_MAGIC[2],
        RTPS_MAGIC[3],
        RTPS_VERSION_MAJOR,
        RTPS_VERSION_MINOR,
        HDDS_VENDOR_ID[0],
        HDDS_VENDOR_ID[1],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
    ]
}

pub(super) fn try_u16_from_usize(value: usize, context: &str) -> Option<u16> {
    match u16::try_from(value) {
        Ok(v) => Some(v),
        Err(_) => {
            log::debug!(
                "[rtps_builder] {} (value: {}) exceeds u16::MAX ({}).",
                context,
                value,
                u16::MAX
            );
            None
        }
    }
}

pub(super) fn try_u32_from_usize(value: usize, context: &str) -> Option<u32> {
    match u32::try_from(value) {
        Ok(v) => Some(v),
        Err(_) => {
            log::debug!(
                "[rtps_builder] {} (value: {}) exceeds u32::MAX ({}).",
                context,
                value,
                u32::MAX
            );
            None
        }
    }
}

/// Build inline QoS parameter list with topic name.
pub(super) fn build_inline_qos_with_topic(topic: &str) -> Vec<u8> {
    let topic_bytes = topic.as_bytes();
    let string_len = topic_bytes.len() + 1;
    let param_len = 4 + string_len;
    let param_len_u16 = match try_u16_from_usize(param_len, "inline QoS parameter length") {
        Some(value) => value,
        None => return Vec::new(),
    };
    let string_len_u32 = match try_u32_from_usize(string_len, "inline QoS string length") {
        Some(value) => value,
        None => return Vec::new(),
    };

    let unaligned_size = 4 + 2 + 2 + param_len;
    let aligned_size = (unaligned_size + 3) & !3;
    let padding = aligned_size - unaligned_size;

    let mut qos = Vec::with_capacity(aligned_size + 4);

    // CDR encapsulation header (ALWAYS big-endian per CDR spec)
    qos.extend_from_slice(&CDR_LE.to_be_bytes());
    qos.extend_from_slice(&[0x00, 0x00]); // Options (reserved)
    qos.extend_from_slice(&0x0005u16.to_le_bytes());
    qos.extend_from_slice(&param_len_u16.to_le_bytes());
    qos.extend_from_slice(&string_len_u32.to_le_bytes());

    qos.extend_from_slice(topic_bytes);
    qos.push(0);

    qos.extend(std::iter::repeat_n(0, padding));

    qos.extend_from_slice(&0x0001u16.to_le_bytes());
    qos.extend_from_slice(&0x0000u16.to_le_bytes());

    qos
}

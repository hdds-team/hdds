// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS packet header validation and extraction.
//!
//! This module handles the initial 20-byte RTPS header according to DDS-RTPS v2.3 Sec.8.3:
//! - Magic validation ("RTPS" or "RTPX")
//! - Version and vendor ID extraction
//! - GUID prefix extraction (12 bytes)
//! - Debug hex dump for RTI packets

use super::super::{PacketKind, RtpsContext};
#[cfg(feature = "rti-hexdump")]
use crate::config::DEBUG_DUMP_SIZE;

/// Validated RTPS header data extracted from packet.
pub(super) struct RtpsHeader {
    pub vendor_id: u16,
    pub guid_prefix: [u8; 12],
}

/// Validate RTPS packet header and extract metadata.
///
/// # Arguments
/// * `buf` - Raw packet buffer (must be >= 24 bytes)
///
/// # Returns
/// * `Ok(RtpsHeader)` if valid RTPS packet
/// * `Err((PacketKind::Invalid, ...))` if validation fails
pub(super) fn validate_and_extract_header(
    buf: &[u8],
) -> Result<
    RtpsHeader,
    (
        PacketKind,
        Option<usize>,
        Option<super::super::FragmentMetadata>,
        RtpsContext,
    ),
> {
    crate::trace_fn!("validate_and_extract_header");
    // Check minimum RTPS header size (20 bytes header + 4 bytes submessage header)
    if buf.len() < 24 {
        log::debug!(
            "[RTPS-DEBUG] Packet too short: {} bytes (need >= 24)",
            buf.len()
        );
        return Err((PacketKind::Invalid, None, None, RtpsContext::default()));
    }

    // Verify RTPS magic ("RTPS" or "RTPX" at offset 0)
    // RTPS (0x52545053) = standard DDS-RTPS v2.3
    // RTPX (0x52545058) = RTI Connext with vendor extensions (security, QoS, etc.)
    if &buf[0..4] != b"RTPS" && &buf[0..4] != b"RTPX" {
        log::debug!(
            "[RTPS-DEBUG] Invalid magic: {:?} (expected RTPS or RTPX)",
            &buf[0..4]
        );
        return Err((PacketKind::Invalid, None, None, RtpsContext::default()));
    }

    // Debug: Print RTPS header
    let vendor_id = u16::from_be_bytes([buf[6], buf[7]]);
    log::debug!(
        "[RTPS-DEBUG] Header: magic={:?} version={}.{} vendor_id=0x{:04x}",
        &buf[0..4],
        buf[4],
        buf[5],
        vendor_id
    );
    log::debug!("[RTPS-DEBUG] GUID prefix (12 bytes): {:02x?}", &buf[8..20]);

    // Extra debug for RTI packets: dump first 128 bytes in hex
    // Only compiled with: cargo build --features rti-hexdump
    #[cfg(feature = "rti-hexdump")]
    if vendor_id == 0x0101 && buf.len() > 16 {
        dump_rti_packet_hex(buf);
    }

    // Extract GUID prefix from RTPS header (needed for FragmentMetadata)
    // RTPS v2.3: GUID prefix is 12 bytes, NOT 8!
    let guid_prefix = [
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        buf[18], buf[19],
    ];

    Ok(RtpsHeader {
        vendor_id,
        guid_prefix,
    })
}

/// Dump RTI packet first DEBUG_DUMP_SIZE bytes in hex format for debugging.
/// Only compiled with: cargo build --features rti-hexdump
#[cfg(feature = "rti-hexdump")]
fn dump_rti_packet_hex(buf: &[u8]) {
    let dump_len = DEBUG_DUMP_SIZE.min(buf.len());
    log::debug!("[RTI-HEXDUMP] First {} bytes:", dump_len);

    // Print in rows of 16 bytes with offset
    for row_start in (0..dump_len).step_by(16) {
        let row_end = (row_start + 16).min(dump_len);
        let row = &buf[row_start..row_end];

        eprint!("[RTI-HEXDUMP]   {:04x}: ", row_start);

        // Hex values
        for byte in row {
            eprint!("{:02x} ", byte);
        }

        // Padding if incomplete row
        for _ in 0..(16 - row.len()) {
            eprint!("   ");
        }

        // ASCII representation
        eprint!(" |");
        for byte in row {
            if *byte >= 0x20 && *byte <= 0x7e {
                eprint!("{}", *byte as char);
            } else {
                eprint!(".");
            }
        }
        log::debug!("|");
    }

    // Look for SPDP PID patterns (0x0050 = PARTICIPANT_GUID in big-endian)
    for i in 20..dump_len.saturating_sub(4) {
        if buf[i] == 0x00 && buf[i + 1] == 0x50 {
            log::debug!(
                "[RTI-HEXDUMP] [!] Found potential SPDP PID_PARTICIPANT_GUID at offset {}",
                i
            );
        } else if buf[i] == 0x50 && buf[i + 1] == 0x00 {
            log::debug!(
                "[RTI-HEXDUMP] [!] Found potential SPDP PID_PARTICIPANT_GUID (LE) at offset {}",
                i
            );
        }
    }
}

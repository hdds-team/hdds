// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![no_main]

//! Fuzz the RTPS control parsers: ACKNACK and NACK_FRAG through their public
//! parsers, HEARTBEAT and GAP through the embedded-control walk, reached via
//! `fuzz_scan_embedded_control` (compiled only under `--cfg fuzzing`).

use hdds::core::discovery::multicast::control_parser::{
    fuzz_scan_embedded_control, parse_all_acknack_submessages, parse_all_nack_frag_submessages,
};
use libfuzzer_sys::fuzz_target;

/// RTPS header: "RTPS" magic, protocol version 2.5, vendor id, GUID prefix.
const RTPS_HEADER: [u8; 20] = [
    b'R', b'T', b'P', b'S', 0x02, 0x05, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

fuzz_target!(|data: &[u8]| {
    // Straight off the socket: the magic check refuses almost every input,
    // which is itself part of what is exercised.
    let _ = parse_all_acknack_submessages(data);
    let _ = parse_all_nack_frag_submessages(data);

    // The same bytes behind a well-formed header, so the submessage walk
    // is reached instead of stopping at the magic check.
    let mut packet = Vec::with_capacity(RTPS_HEADER.len() + data.len());
    packet.extend_from_slice(&RTPS_HEADER);
    packet.extend_from_slice(data);
    let _ = parse_all_acknack_submessages(&packet);
    let _ = parse_all_nack_frag_submessages(&packet);
    fuzz_scan_embedded_control(&packet);
});

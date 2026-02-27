// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![no_main]

use libfuzzer_sys::fuzz_target;
use hdds::core::discovery::multicast::control_parser::{
    parse_heartbeat_submessage,
    parse_acknack_submessage,
    parse_nack_frag_submessage,
};

fuzz_target!(|data: &[u8]| {
    // Fuzz HEARTBEAT parser
    let _ = parse_heartbeat_submessage(data);

    // Fuzz ACKNACK parser
    let _ = parse_acknack_submessage(data);

    // Fuzz NACK_FRAG parser
    let _ = parse_nack_frag_submessage(data);
});

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fuzz target for RTPS protocol parsers (SPDP/SEDP)
//!
//! This fuzzer tests the parser's robustness against malformed input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz SPDP parser - must not panic on any input
    let _ = hdds::protocol::discovery::parse_spdp(data);

    // Fuzz SPDP partial parser (for fragmented messages)
    let _ = hdds::protocol::discovery::parse_spdp_partial(data);

    // Fuzz SEDP parser
    let _ = hdds::protocol::discovery::parse_sedp(data);
});

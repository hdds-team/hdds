// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![no_main]

use libfuzzer_sys::fuzz_target;
use hdds::protocol::discovery::sedp::parse::parse_sedp;

fuzz_target!(|data: &[u8]| {
    // Fuzz SEDP endpoint discovery parser
    let _ = parse_sedp(data);
});

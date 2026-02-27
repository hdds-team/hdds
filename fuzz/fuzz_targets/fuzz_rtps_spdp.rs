// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![no_main]

use libfuzzer_sys::fuzz_target;
use hdds::protocol::discovery::spdp::parse::{parse_spdp, parse_spdp_partial};

fuzz_target!(|data: &[u8]| {
    // Fuzz full SPDP parser
    let _ = parse_spdp(data);

    // Fuzz partial SPDP parser (for fragments)
    let _ = parse_spdp_partial(data);
});

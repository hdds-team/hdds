// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![no_main]

use libfuzzer_sys::fuzz_target;
use hdds::security::access::permissions::{PermissionsConfig, GovernanceConfig};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string (XML is text-based)
    if let Ok(xml) = std::str::from_utf8(data) {
        // Fuzz permissions XML parser
        let _ = PermissionsConfig::parse(xml);

        // Fuzz governance XML parser
        let _ = GovernanceConfig::parse(xml);
    }
});

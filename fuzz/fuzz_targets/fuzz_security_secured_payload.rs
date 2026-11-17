// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CryptoHeader, CryptoContent and CryptoFooter parsing before key lookup.
#![no_main]
use hdds::security::crypto::user_data::secured_payload_key_id;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The receive-path lookup validates complete crypto elements before
    // acquiring the writer's secret material. No keys are needed to fuzz it.
    let _ = secured_payload_key_id(data);
});

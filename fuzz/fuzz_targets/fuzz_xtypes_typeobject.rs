// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![no_main]

use libfuzzer_sys::fuzz_target;
use hdds::Cdr2Decode;
use hdds::xtypes::{decompress_type_object, CompleteTypeObject, MinimalTypeObject, TypeIdentifier};

fuzz_target!(|data: &[u8]| {
    // Fuzz the XTypes CompleteTypeObject CDR2 decoder. This is reached
    // directly on foreign-vendor wire bytes: SEDP PID_TYPE_OBJECT and
    // PID_TYPE_OBJECT_LB parameters, and the TypeLookup service response.
    let _ = CompleteTypeObject::decode_cdr2_le(data);

    // Fuzz the MinimalTypeObject CDR2 decoder (same wire family, smaller
    // encoding used for the minimal-hash discovery path).
    let _ = MinimalTypeObject::decode_cdr2_le(data);

    // Fuzz the TypeIdentifier CDR2 decoder, the discriminated union that
    // every TypeObject field bottoms out in.
    let _ = TypeIdentifier::decode_cdr2_le(data);

    // Fuzz the ZLIB decompression helper used on the RTI
    // PID_TYPE_OBJECT_LB path: offset/length come from the first two
    // bytes of the fuzz input, the rest is the (attacker-controlled)
    // buffer it slices into. `decompress_type_object` itself does not
    // bounds-check offset/length (it slices `buf[offset..offset+length]`
    // directly); the real caller (sedp/parse.rs) always checks
    // `offset + length <= buf.len()` before calling it, so this harness
    // applies the same guard rather than fuzzing a known-unguarded slice.
    if data.len() >= 2 {
        let offset = data[0] as usize;
        let length = data[1] as usize;
        let rest = &data[2..];
        if offset + length <= rest.len() {
            let _ = decompress_type_object(rest, offset, length);
        }
    }
});

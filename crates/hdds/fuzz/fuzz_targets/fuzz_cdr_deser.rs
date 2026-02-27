// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fuzz target for CDR2 deserialization
//!
//! Feeds arbitrary bytes to the CDR2 decoder and Cdr2Decode trait
//! implementations. None of these operations should panic on any input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // ----------------------------------------------------------------
    // 1. Fuzz DecoderLE header validation - must not panic
    // ----------------------------------------------------------------
    let _ = hdds::core::ser::DecoderLE::new(data);

    // ----------------------------------------------------------------
    // 2. Fuzz low-level Cursor reads - must not panic
    // ----------------------------------------------------------------
    {
        let mut cursor = hdds::core::ser::Cursor::new(data);
        let _ = cursor.read_u8();
        let _ = cursor.read_u16_le();
        let _ = cursor.read_u32_le();
        let _ = cursor.read_u64_le();
        let _ = cursor.read_i32_le();
        let _ = cursor.read_f64_le();
        let _ = cursor.read_bytes(4);
    }

    // Also test sequential reads from a fresh cursor
    {
        let mut cursor = hdds::core::ser::Cursor::new(data);
        while cursor.remaining() > 0 {
            if cursor.read_u8().is_err() {
                break;
            }
        }
    }

    // ----------------------------------------------------------------
    // 3. Fuzz Cdr2Decode trait impls for primitive types - must not panic
    // ----------------------------------------------------------------
    let _ = <u8 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <i8 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <u16 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <i16 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <u32 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <i32 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <u64 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <i64 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <f32 as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <f64 as hdds::Cdr2Decode>::decode_cdr2_le(data);

    // ----------------------------------------------------------------
    // 4. Fuzz String decoding - must not panic (may return InvalidEncoding)
    // ----------------------------------------------------------------
    let _ = <String as hdds::Cdr2Decode>::decode_cdr2_le(data);

    // ----------------------------------------------------------------
    // 5. Fuzz Vec<T> decoding for various element types - must not panic
    //    Note: large length fields could cause OOM; Vec::with_capacity
    //    is bounded by available data, so this is generally safe for
    //    short fuzz inputs.
    // ----------------------------------------------------------------
    let _ = <Vec<u8> as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <Vec<u32> as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <Vec<i32> as hdds::Cdr2Decode>::decode_cdr2_le(data);
    let _ = <Vec<f64> as hdds::Cdr2Decode>::decode_cdr2_le(data);

    // ----------------------------------------------------------------
    // 6. Fuzz PL_CDR2 struct decoding - must not panic
    // ----------------------------------------------------------------
    let _ = hdds::core::ser::decode_pl_cdr2_struct(data, |_member_id, _src, _offset, _end| {
        Ok(())
    });
});

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::wildcard_imports)] // Test utility imports
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures

/// Golden roundtrip tests for CDR2 v2 LE serialization
///
/// Phase 2: Header encoding/decoding validation.
/// Phase 3: Primitive, string, sequence, and struct encoding roundtrips
///          using both Cursor (low-level) and Cdr2Encode/Cdr2Decode (trait-level) APIs.
use hdds::core::ser::{Cursor, CursorMut, DecoderLE, EncoderLE};
use hdds::{Cdr2Decode, Cdr2Encode};

#[test]
fn test_roundtrip_header_basic() {
    // Test: Create encoder, verify header can be decoded
    let mut buf = [0u8; 256];

    // Encode
    let enc = EncoderLE::new(&mut buf).expect("encode header");
    let encoded_len = enc.offset();
    assert_eq!(encoded_len, 8, "Header should be exactly 8 bytes");

    // Decode
    let dec = DecoderLE::new(&buf).unwrap();
    assert_eq!(
        dec.offset(),
        8,
        "Decoder should be at offset 8 after header"
    );
}

#[test]
fn test_roundtrip_header_verify_bytes() {
    // Test: Verify exact byte layout of header
    let mut buf = [0xFF; 256]; // Pre-fill with 0xFF to detect overwrites

    let _enc = EncoderLE::new(&mut buf).expect("encode header");

    // Verify CDR2 v2 LE header format
    assert_eq!(buf[0], 0xCE, "Magic byte 0 (LE)");
    assert_eq!(buf[1], 0xCA, "Magic byte 1 (LE)");
    assert_eq!(buf[2], 0x02, "Version major (CDR2)");
    assert_eq!(buf[3], 0x00, "Version minor");
    assert_eq!(buf[4], 0x00, "Flags (LE canonical)");
    assert_eq!(buf[5], 0x00, "Reserved");
    assert_eq!(buf[6], 0x00, "Reserved");
    assert_eq!(buf[7], 0x00, "Reserved");

    // Verify payload area is untouched
    assert_eq!(buf[8], 0xFF, "Payload area should be untouched");
}

#[test]
fn test_roundtrip_multiple_buffers() {
    // Test: Encode/decode in multiple buffers to verify no cross-contamination
    let mut buf1 = [0xAA; 64];
    let mut buf2 = [0xBB; 64];

    // Encode buf1
    let _enc1 = EncoderLE::new(&mut buf1).expect("encode header");

    // Encode buf2
    let _enc2 = EncoderLE::new(&mut buf2).expect("encode header");

    // Both should have identical headers
    assert_eq!(buf1[0..8], buf2[0..8], "Headers should be identical");

    // But different payload areas
    assert_eq!(buf1[8], 0xAA);
    assert_eq!(buf2[8], 0xBB);

    // Decode both
    let dec1 = DecoderLE::new(&buf1).expect("decode header");
    let dec2 = DecoderLE::new(&buf2).expect("decode header");
    assert_eq!(dec1.offset(), 8);
    assert_eq!(dec2.offset(), 8);
}

#[test]
fn test_roundtrip_minimum_buffer() {
    // Test: Exact 8-byte buffer (minimum valid size)
    let mut buf = [0u8; 8];

    let enc = EncoderLE::new(&mut buf).expect("encode header");
    assert_eq!(enc.offset(), 8);

    let dec = DecoderLE::new(&buf).expect("decode header");
    assert_eq!(dec.offset(), 8);
}

// ============================================================================
// Phase 3: Primitive type roundtrips via Cursor (low-level)
// ============================================================================

#[test]
fn test_roundtrip_cursor_u8() {
    let mut buf = [0u8; 16];
    let mut w = CursorMut::new(&mut buf);
    w.write_u8(0).unwrap();
    w.write_u8(127).unwrap();
    w.write_u8(255).unwrap();
    let written = w.offset();
    assert_eq!(written, 3);

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u8().unwrap(), 0);
    assert_eq!(r.read_u8().unwrap(), 127);
    assert_eq!(r.read_u8().unwrap(), 255);
    assert!(r.is_eof());
}

#[test]
fn test_roundtrip_cursor_u16() {
    let mut buf = [0u8; 16];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_u16_le(0).unwrap();
        w.write_u16_le(0xABCD).unwrap();
        w.write_u16_le(0xFFFF).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u16_le().unwrap(), 0);
    assert_eq!(r.read_u16_le().unwrap(), 0xABCD);
    assert_eq!(r.read_u16_le().unwrap(), 0xFFFF);
}

#[test]
fn test_roundtrip_cursor_u32() {
    let mut buf = [0u8; 16];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_u32_le(0).unwrap();
        w.write_u32_le(0xDEAD_BEEF).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u32_le().unwrap(), 0);
    assert_eq!(r.read_u32_le().unwrap(), 0xDEAD_BEEF);
}

#[test]
fn test_roundtrip_cursor_u64() {
    let mut buf = [0u8; 32];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_u64_le(0).unwrap();
        w.write_u64_le(0x0102_0304_0506_0708).unwrap();
        w.write_u64_le(u64::MAX).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u64_le().unwrap(), 0);
    assert_eq!(r.read_u64_le().unwrap(), 0x0102_0304_0506_0708);
    assert_eq!(r.read_u64_le().unwrap(), u64::MAX);
}

#[test]
fn test_roundtrip_cursor_i32() {
    let mut buf = [0u8; 32];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_i32_le(0).unwrap();
        w.write_i32_le(-1).unwrap();
        w.write_i32_le(i32::MIN).unwrap();
        w.write_i32_le(i32::MAX).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_i32_le().unwrap(), 0);
    assert_eq!(r.read_i32_le().unwrap(), -1);
    assert_eq!(r.read_i32_le().unwrap(), i32::MIN);
    assert_eq!(r.read_i32_le().unwrap(), i32::MAX);
}

#[test]
fn test_roundtrip_cursor_f64() {
    let mut buf = [0u8; 64];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_f64_le(0.0).unwrap();
        w.write_f64_le(-1.5).unwrap();
        w.write_f64_le(std::f64::consts::PI).unwrap();
        w.write_f64_le(f64::INFINITY).unwrap();
        w.write_f64_le(f64::NEG_INFINITY).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_f64_le().unwrap(), 0.0);
    assert_eq!(r.read_f64_le().unwrap(), -1.5);
    assert!((r.read_f64_le().unwrap() - std::f64::consts::PI).abs() < f64::EPSILON);
    assert_eq!(r.read_f64_le().unwrap(), f64::INFINITY);
    assert_eq!(r.read_f64_le().unwrap(), f64::NEG_INFINITY);
}

#[test]
fn test_roundtrip_cursor_f64_nan() {
    // NaN requires special handling: NaN != NaN
    let mut buf = [0u8; 8];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_f64_le(f64::NAN).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    let val = r.read_f64_le().unwrap();
    assert!(val.is_nan());
}

#[test]
fn test_roundtrip_cursor_bool_as_u8() {
    // CDR encodes booleans as single u8 (0 = false, 1 = true)
    let mut buf = [0u8; 4];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_u8(0).unwrap(); // false
        w.write_u8(1).unwrap(); // true
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u8().unwrap(), 0);
    assert_eq!(r.read_u8().unwrap(), 1);
}

#[test]
fn test_roundtrip_cursor_bytes() {
    let payload = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let mut buf = [0u8; 32];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_bytes(&payload).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_bytes(6).unwrap(), &payload);
}

#[test]
fn test_roundtrip_cursor_alignment() {
    // Write u8 then align to 4-byte boundary before writing u32
    let mut buf = [0u8; 16];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_u8(0xAA).unwrap(); // offset 1
        w.align(4).unwrap(); // offset -> 4
        w.write_u32_le(0x12345678).unwrap(); // offset -> 8
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u8().unwrap(), 0xAA);
    r.align(4).unwrap();
    assert_eq!(r.read_u32_le().unwrap(), 0x12345678);
}

#[test]
fn test_roundtrip_cursor_mixed_types() {
    // Simulate a struct: { flag: u8, _pad: [3], id: u32, value: f64, tag: i32 }
    let mut buf = [0u8; 32];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_u8(1).unwrap(); // flag
        w.align(4).unwrap(); // padding to 4-byte boundary
        w.write_u32_le(42).unwrap(); // id
        w.align(8).unwrap(); // padding to 8-byte boundary
        w.write_f64_le(std::f64::consts::PI).unwrap(); // value
        w.write_i32_le(-99).unwrap(); // tag
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u8().unwrap(), 1);
    r.align(4).unwrap();
    assert_eq!(r.read_u32_le().unwrap(), 42);
    r.align(8).unwrap();
    assert!((r.read_f64_le().unwrap() - std::f64::consts::PI).abs() < f64::EPSILON);
    assert_eq!(r.read_i32_le().unwrap(), -99);
}

// ============================================================================
// Phase 3: Primitive type roundtrips via Cdr2Encode/Cdr2Decode traits
// ============================================================================

#[test]
fn test_roundtrip_cdr2_u8() {
    let mut buf = [0u8; 4];
    let val: u8 = 0xAB;
    let written = val.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 1);
    let (decoded, consumed) = u8::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, val);
    assert_eq!(consumed, 1);
}

#[test]
fn test_roundtrip_cdr2_i8() {
    let mut buf = [0u8; 4];
    let val: i8 = -42;
    let written = val.encode_cdr2_le(&mut buf).unwrap();
    let (decoded, _) = i8::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, val);
}

#[test]
fn test_roundtrip_cdr2_i16() {
    let mut buf = [0u8; 4];
    for val in [0i16, -1, i16::MIN, i16::MAX, 1234] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 2);
        let (decoded, consumed) = i16::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 2);
    }
}

#[test]
fn test_roundtrip_cdr2_u16() {
    let mut buf = [0u8; 4];
    for val in [0u16, 0xFFFF, 0xABCD, 1] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        let (decoded, _) = u16::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
    }
}

#[test]
fn test_roundtrip_cdr2_i32() {
    let mut buf = [0u8; 8];
    for val in [0i32, -1, i32::MIN, i32::MAX, 42, -999_999] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 4);
        let (decoded, consumed) = i32::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 4);
    }
}

#[test]
fn test_roundtrip_cdr2_u32() {
    let mut buf = [0u8; 8];
    for val in [0u32, u32::MAX, 0xDEAD_BEEF, 1] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        let (decoded, _) = u32::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
    }
}

#[test]
fn test_roundtrip_cdr2_i64() {
    let mut buf = [0u8; 16];
    for val in [0i64, -1, i64::MIN, i64::MAX] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 8);
        let (decoded, consumed) = i64::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 8);
    }
}

#[test]
fn test_roundtrip_cdr2_u64() {
    let mut buf = [0u8; 16];
    for val in [0u64, u64::MAX, 0x0102_0304_0506_0708] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        let (decoded, _) = u64::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
    }
}

#[test]
fn test_roundtrip_cdr2_f32() {
    let mut buf = [0u8; 8];
    for val in [
        0.0f32,
        -1.5,
        std::f32::consts::PI,
        f32::INFINITY,
        f32::NEG_INFINITY,
    ] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 4);
        let (decoded, consumed) = f32::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 4);
    }
}

#[test]
fn test_roundtrip_cdr2_f32_nan() {
    let mut buf = [0u8; 8];
    let written = f32::NAN.encode_cdr2_le(&mut buf).unwrap();
    let (decoded, _) = f32::decode_cdr2_le(&buf[..written]).unwrap();
    assert!(decoded.is_nan());
}

#[test]
fn test_roundtrip_cdr2_f64() {
    let mut buf = [0u8; 16];
    for val in [
        0.0f64,
        -1.5,
        std::f64::consts::PI,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        let written = val.encode_cdr2_le(&mut buf).unwrap();
        assert_eq!(written, 8);
        let (decoded, consumed) = f64::decode_cdr2_le(&buf[..written]).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, 8);
    }
}

// ============================================================================
// Phase 3: String roundtrips via Cdr2Encode/Cdr2Decode
// ============================================================================

#[test]
fn test_roundtrip_cdr2_string_basic() {
    let mut buf = [0u8; 256];
    let original = "Hello, CDR2!".to_string();
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    // 4 (length) + 12 (chars) + 1 (null) = 17
    assert_eq!(written, 17);
    let (decoded, consumed) = String::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, 17);
}

#[test]
fn test_roundtrip_cdr2_string_empty() {
    let mut buf = [0u8; 16];
    let original = String::new();
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    // 4 (length=0) + 0 (chars) + 1 (null) = 5
    assert_eq!(written, 5);
    let (decoded, consumed) = String::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, 5);
}

#[test]
fn test_roundtrip_cdr2_string_unicode() {
    let mut buf = [0u8; 256];
    // Multi-byte UTF-8 characters
    let original = "cafe\u{0301}".to_string(); // "cafe" + combining accent
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    let (decoded, consumed) = String::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

#[test]
fn test_roundtrip_cdr2_str_ref() {
    // Test encoding a &str and decoding as String
    let mut buf = [0u8; 64];
    let original: &str = "bounded test";
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    let (decoded, consumed) = String::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

#[test]
fn test_roundtrip_cdr2_string_long() {
    let mut buf = vec![0u8; 2048];
    // 1000 character string
    let original: String = (0..1000)
        .map(|i| char::from(b'A' + (i % 26) as u8))
        .collect();
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 4 + 1000 + 1);
    let (decoded, consumed) = String::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

// ============================================================================
// Phase 3: Sequence (Vec<T>) roundtrips via Cdr2Encode/Cdr2Decode
// ============================================================================

#[test]
fn test_roundtrip_cdr2_vec_u32() {
    let mut buf = [0u8; 256];
    let original: Vec<u32> = vec![1, 2, 3, 0xDEAD_BEEF, u32::MAX];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    // 4 (length) + 5 * 4 (elements) = 24
    assert_eq!(written, 24);
    let (decoded, consumed) = Vec::<u32>::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, 24);
}

#[test]
fn test_roundtrip_cdr2_vec_empty() {
    let mut buf = [0u8; 16];
    let original: Vec<i32> = vec![];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 4); // only the length prefix
    let (decoded, consumed) = Vec::<i32>::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, 4);
}

#[test]
fn test_roundtrip_cdr2_vec_u8() {
    let mut buf = [0u8; 64];
    let original: Vec<u8> = vec![0, 1, 127, 255];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 4 + 4); // 4 (length) + 4 (elements)
    let (decoded, consumed) = Vec::<u8>::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

#[test]
fn test_roundtrip_cdr2_vec_f64() {
    let mut buf = [0u8; 256];
    let original: Vec<f64> = vec![0.0, -1.5, std::f64::consts::PI, f64::INFINITY];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 4 + 4 * 8);
    let (decoded, consumed) = Vec::<f64>::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

#[test]
fn test_roundtrip_cdr2_vec_i16() {
    let mut buf = [0u8; 64];
    let original: Vec<i16> = vec![i16::MIN, -1, 0, 1, i16::MAX];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 4 + 5 * 2);
    let (decoded, consumed) = Vec::<i16>::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

// ============================================================================
// Phase 3: Struct encoding roundtrips (field-by-field via Cursor)
// ============================================================================

#[test]
fn test_roundtrip_point_cursor() {
    // Simulate struct Point { x: i32, y: i32, z: u8 }
    // Field-by-field encoding via CursorMut
    let mut buf = [0u8; 256];

    // Write CDR2 header first, then fields
    let _enc = EncoderLE::new(&mut buf).unwrap();
    // Now write fields starting at offset 8
    let mut w = CursorMut::new(&mut buf[8..]);
    w.write_i32_le(42).unwrap(); // x
    w.write_i32_le(123).unwrap(); // y
    w.write_u8(1).unwrap(); // z
    let payload_len = w.offset();
    let total_len = 8 + payload_len;
    assert_eq!(total_len, 17); // 8 header + 4 + 4 + 1

    // Decode: verify header, then read fields
    let _dec = DecoderLE::new(&buf[..total_len]).unwrap();
    let mut r = Cursor::new(&buf[8..total_len]);
    assert_eq!(r.read_i32_le().unwrap(), 42);
    assert_eq!(r.read_i32_le().unwrap(), 123);
    assert_eq!(r.read_u8().unwrap(), 1);
    assert!(r.is_eof());
}

#[test]
fn test_roundtrip_sensor_reading_cursor() {
    // Simulate struct SensorReading { timestamp: u64, value: f64, sensor_id: u32, active: u8 }
    let mut buf = [0u8; 256];
    let _enc = EncoderLE::new(&mut buf).unwrap();

    let mut w = CursorMut::new(&mut buf[8..]);
    w.write_u64_le(1_700_000_000_000).unwrap(); // timestamp (millis)
    w.write_f64_le(23.456).unwrap(); // value
    w.write_u32_le(42).unwrap(); // sensor_id
    w.write_u8(1).unwrap(); // active (bool as u8)
    let payload_len = w.offset();
    let total_len = 8 + payload_len;
    // 8 header + 8 + 8 + 4 + 1 = 29
    assert_eq!(total_len, 29);

    let _dec = DecoderLE::new(&buf[..total_len]).unwrap();
    let mut r = Cursor::new(&buf[8..total_len]);
    assert_eq!(r.read_u64_le().unwrap(), 1_700_000_000_000);
    assert!((r.read_f64_le().unwrap() - 23.456).abs() < f64::EPSILON);
    assert_eq!(r.read_u32_le().unwrap(), 42);
    assert_eq!(r.read_u8().unwrap(), 1);
    assert!(r.is_eof());
}

#[test]
fn test_roundtrip_struct_with_alignment_cursor() {
    // Simulate struct with mixed alignment:
    // { flag: u8, _pad3, id: u32, _pad4, data: f64 }
    let mut buf = [0u8; 256];
    let _enc = EncoderLE::new(&mut buf).unwrap();

    let mut w = CursorMut::new(&mut buf[8..]);
    w.write_u8(0xFF).unwrap(); // flag (offset 0)
    w.align(4).unwrap(); // pad to 4 (offset 4)
    w.write_u32_le(12345).unwrap(); // id (offset 4-8)
    w.align(8).unwrap(); // pad to 8 (offset 8)
    w.write_f64_le(99.99).unwrap(); // data (offset 8-16)
    let payload_len = w.offset();
    let total_len = 8 + payload_len;

    let _dec = DecoderLE::new(&buf[..total_len]).unwrap();
    let mut r = Cursor::new(&buf[8..total_len]);
    assert_eq!(r.read_u8().unwrap(), 0xFF);
    r.align(4).unwrap();
    assert_eq!(r.read_u32_le().unwrap(), 12345);
    r.align(8).unwrap();
    assert!((r.read_f64_le().unwrap() - 99.99).abs() < f64::EPSILON);
    assert!(r.is_eof());
}

// ============================================================================
// Phase 3: Struct encoding roundtrips via Cdr2Encode/Cdr2Decode traits
// ============================================================================

#[test]
fn test_roundtrip_cdr2_struct_manual_impl() {
    // Define a struct and manually implement Cdr2Encode/Cdr2Decode
    // (same pattern as hdds_gen would produce)
    #[derive(Debug, Clone, PartialEq)]
    struct Point3D {
        x: i32,
        y: i32,
        z: u8,
    }

    impl Cdr2Encode for Point3D {
        fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, hdds::CdrError> {
            let needed = 4 + 4 + 1; // i32 + i32 + u8
            if dst.len() < needed {
                return Err(hdds::CdrError::BufferTooSmall);
            }
            let mut offset = 0;
            dst[offset..offset + 4].copy_from_slice(&self.x.to_le_bytes());
            offset += 4;
            dst[offset..offset + 4].copy_from_slice(&self.y.to_le_bytes());
            offset += 4;
            dst[offset] = self.z;
            offset += 1;
            Ok(offset)
        }

        fn max_cdr2_size(&self) -> usize {
            9
        }
    }

    impl Cdr2Decode for Point3D {
        fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
            if src.len() < 9 {
                return Err(hdds::CdrError::UnexpectedEof);
            }
            let x = i32::from_le_bytes([src[0], src[1], src[2], src[3]]);
            let y = i32::from_le_bytes([src[4], src[5], src[6], src[7]]);
            let z = src[8];
            Ok((Point3D { x, y, z }, 9))
        }
    }

    let point = Point3D {
        x: 42,
        y: -123,
        z: 7,
    };
    let mut buf = [0u8; 64];
    let written = point.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 9);
    let (decoded, consumed) = Point3D::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, point);
    assert_eq!(consumed, 9);
}

#[test]
fn test_roundtrip_cdr2_struct_with_string() {
    // Struct with a variable-length string field
    #[derive(Debug, Clone, PartialEq)]
    struct LabelledValue {
        value: f64,
        label: String,
    }

    impl Cdr2Encode for LabelledValue {
        fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, hdds::CdrError> {
            let mut offset = 0;
            let used = self.value.encode_cdr2_le(&mut dst[offset..])?;
            offset += used;
            let used = self.label.encode_cdr2_le(&mut dst[offset..])?;
            offset += used;
            Ok(offset)
        }

        fn max_cdr2_size(&self) -> usize {
            8 + self.label.max_cdr2_size()
        }
    }

    impl Cdr2Decode for LabelledValue {
        fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
            let mut offset = 0;
            let (value, used) = f64::decode_cdr2_le(&src[offset..])?;
            offset += used;
            let (label, used) = String::decode_cdr2_le(&src[offset..])?;
            offset += used;
            Ok((LabelledValue { value, label }, offset))
        }
    }

    let original = LabelledValue {
        value: 98.6,
        label: "temperature".to_string(),
    };
    let mut buf = [0u8; 256];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    // 8 (f64) + 4 (strlen) + 11 (chars) + 1 (null) = 24
    assert_eq!(written, 24);
    let (decoded, consumed) = LabelledValue::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

#[test]
fn test_roundtrip_cdr2_struct_with_sequence() {
    // Struct containing a Vec of primitives
    #[derive(Debug, Clone, PartialEq)]
    struct Polygon {
        vertex_count: u32,
        x_coords: Vec<f32>,
        y_coords: Vec<f32>,
    }

    impl Cdr2Encode for Polygon {
        fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, hdds::CdrError> {
            let mut offset = 0;
            let used = self.vertex_count.encode_cdr2_le(&mut dst[offset..])?;
            offset += used;
            let used = self.x_coords.encode_cdr2_le(&mut dst[offset..])?;
            offset += used;
            let used = self.y_coords.encode_cdr2_le(&mut dst[offset..])?;
            offset += used;
            Ok(offset)
        }

        fn max_cdr2_size(&self) -> usize {
            4 + self.x_coords.max_cdr2_size() + self.y_coords.max_cdr2_size()
        }
    }

    impl Cdr2Decode for Polygon {
        fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
            let mut offset = 0;
            let (vertex_count, used) = u32::decode_cdr2_le(&src[offset..])?;
            offset += used;
            let (x_coords, used) = Vec::<f32>::decode_cdr2_le(&src[offset..])?;
            offset += used;
            let (y_coords, used) = Vec::<f32>::decode_cdr2_le(&src[offset..])?;
            offset += used;
            Ok((
                Polygon {
                    vertex_count,
                    x_coords,
                    y_coords,
                },
                offset,
            ))
        }
    }

    let original = Polygon {
        vertex_count: 3,
        x_coords: vec![1.0, 2.0, 3.0],
        y_coords: vec![4.0, 5.0, 6.0],
    };
    let mut buf = [0u8; 256];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    // 4 (vertex_count) + 4 (x_len) + 3*4 (x_data) + 4 (y_len) + 3*4 (y_data) = 4+16+16 = 36
    assert_eq!(written, 36);
    let (decoded, consumed) = Polygon::decode_cdr2_le(&buf[..written]).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(consumed, written);
}

// ============================================================================
// Phase 3: Error cases
// ============================================================================

#[test]
fn test_cdr2_encode_buffer_too_small() {
    let mut buf = [0u8; 2];
    let val: u32 = 42;
    assert!(val.encode_cdr2_le(&mut buf).is_err());
}

#[test]
fn test_cdr2_decode_buffer_too_small() {
    let buf = [0u8; 2];
    assert!(u32::decode_cdr2_le(&buf).is_err());
    assert!(f64::decode_cdr2_le(&buf).is_err());
    assert!(i64::decode_cdr2_le(&buf).is_err());
}

#[test]
fn test_cdr2_string_decode_truncated() {
    // Encode a string, then truncate the buffer mid-string
    let mut buf = [0u8; 64];
    let original = "hello".to_string();
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 10); // 4 + 5 + 1
                             // Truncate: only give 6 bytes (need 10)
    assert!(String::decode_cdr2_le(&buf[..6]).is_err());
}

#[test]
fn test_cdr2_vec_decode_truncated() {
    // Encode a vec, then truncate mid-elements
    let mut buf = [0u8; 64];
    let original: Vec<u32> = vec![1, 2, 3];
    let written = original.encode_cdr2_le(&mut buf).unwrap();
    assert_eq!(written, 16); // 4 + 3*4
                             // Truncate: only give 10 bytes (need 16)
    assert!(Vec::<u32>::decode_cdr2_le(&buf[..10]).is_err());
}

#[test]
fn test_cursor_read_past_end() {
    let buf = [0u8; 2];
    let mut r = Cursor::new(&buf);
    assert!(r.read_u32_le().is_err());
}

#[test]
fn test_cursor_write_past_end() {
    let mut buf = [0u8; 2];
    let mut w = CursorMut::new(&mut buf);
    assert!(w.write_u32_le(1).is_err());
}

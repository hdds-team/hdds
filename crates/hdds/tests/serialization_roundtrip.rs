// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// Golden roundtrip tests for CDR2 v2 LE serialization
///
/// Phase 2: Header encoding/decoding validation.
/// Phase 3: Primitive, string, sequence, and struct encoding roundtrips
///          using both Cursor (low-level) and Cdr2Encode/Cdr2Decode (trait-level) APIs.
use hdds::core::ser::{Cursor, CursorMut};
use hdds::{Cdr2Decode, Cdr2Encode};

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
    // @audit-ok: standard test vectors for u32 cursor roundtrip
    let mut buf = [0u8; 16];
    let written = {
        let mut w = CursorMut::new(&mut buf);
        w.write_u32_le(0).unwrap();
        w.write_u32_le(0xDEAD_BEEF).unwrap();
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u32_le().unwrap(), 0);
    assert_eq!(r.read_u32_le().unwrap(), 0xDEAD_BEEF); // @audit-ok: matches write above
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
        // @audit-ok: alignment test vectors -- values chosen for easy visual inspection
        w.write_u8(0xAA).unwrap(); // offset 1
        w.align(4).unwrap(); // offset -> 4
        w.write_u32_le(0x12345678).unwrap(); // offset -> 8
        w.offset()
    };

    let mut r = Cursor::new(&buf[..written]);
    assert_eq!(r.read_u8().unwrap(), 0xAA); // @audit-ok: matches write above
    r.align(4).unwrap();
    assert_eq!(r.read_u32_le().unwrap(), 0x12345678); // @audit-ok: matches write above
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
    // @audit-ok: boundary + sentinel test vectors for CDR2 u32 roundtrip
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
    // @audit-ok: boundary + sentinel test vectors for CDR2 Vec<u32> roundtrip
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

        fn encode_cdr2_le_at(
            &self,
            dst: &mut [u8],
            offset: &mut usize,
        ) -> Result<(), hdds::CdrError> {
            let len = self.encode_cdr2_le(&mut dst[*offset..])?;
            *offset += len;
            Ok(())
        }
    }

    impl Cdr2Decode for Point3D {
        fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
            let mut offset = 0;
            let value = Self::decode_cdr2_le_at(src, &mut offset)?;
            Ok((value, offset))
        }

        fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, hdds::CdrError> {
            let x = i32::decode_cdr2_le_at(src, offset)?;
            let y = i32::decode_cdr2_le_at(src, offset)?;
            let z = u8::decode_cdr2_le_at(src, offset)?;
            Ok(Point3D { x, y, z })
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

        fn encode_cdr2_le_at(
            &self,
            dst: &mut [u8],
            offset: &mut usize,
        ) -> Result<(), hdds::CdrError> {
            let len = self.encode_cdr2_le(&mut dst[*offset..])?;
            *offset += len;
            Ok(())
        }
    }

    impl Cdr2Decode for LabelledValue {
        fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
            let mut offset = 0;
            let value = Self::decode_cdr2_le_at(src, &mut offset)?;
            Ok((value, offset))
        }

        fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, hdds::CdrError> {
            let value = f64::decode_cdr2_le_at(src, offset)?;
            let label = String::decode_cdr2_le_at(src, offset)?;
            Ok(LabelledValue { value, label })
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

        fn encode_cdr2_le_at(
            &self,
            dst: &mut [u8],
            offset: &mut usize,
        ) -> Result<(), hdds::CdrError> {
            let len = self.encode_cdr2_le(&mut dst[*offset..])?;
            *offset += len;
            Ok(())
        }
    }

    impl Cdr2Decode for Polygon {
        fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
            let mut offset = 0;
            let value = Self::decode_cdr2_le_at(src, &mut offset)?;
            Ok((value, offset))
        }

        fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, hdds::CdrError> {
            let vertex_count = u32::decode_cdr2_le_at(src, offset)?;
            let x_coords = Vec::<f32>::decode_cdr2_le_at(src, offset)?;
            let y_coords = Vec::<f32>::decode_cdr2_le_at(src, offset)?;
            Ok(Polygon {
                vertex_count,
                x_coords,
                y_coords,
            })
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

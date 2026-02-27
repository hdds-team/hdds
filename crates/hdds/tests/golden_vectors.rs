// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// CDR2 Golden Vectors: binary reference files for spec compliance verification.
//
// Default mode: VERIFY -- compares encoded bytes against existing .bin files.
// Regeneration: set env GOLDEN_REGEN=1 to overwrite .bin + .hex files.
//
// Each test encodes a known deterministic value and verifies byte-exact
// roundtrip: encode -> decode -> re-encode == original bytes.

#![allow(clippy::float_cmp)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation)]

use hdds::{Cdr2Decode, Cdr2Encode, CdrError};
use std::fs;
use std::path::PathBuf;

const GOLDEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/cdr2");

fn is_regen_mode() -> bool {
    std::env::var("GOLDEN_REGEN").is_ok()
}

fn golden_path(name: &str, ext: &str) -> PathBuf {
    PathBuf::from(GOLDEN_DIR).join(format!("{name}.{ext}"))
}

fn write_golden(name: &str, bytes: &[u8]) {
    let bin_path = golden_path(name, "bin");
    let hex_path = golden_path(name, "hex");
    fs::write(&bin_path, bytes).unwrap();

    let mut hex = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        use std::fmt::Write;
        write!(hex, "{:08x}  ", i * 16).unwrap();
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            write!(hex, "{b:02x} ").unwrap();
        }
        let missing = 16 - chunk.len();
        for _ in 0..missing {
            hex.push_str("   ");
        }
        if chunk.len() <= 8 {
            hex.push(' ');
        }
        hex.push(' ');
        hex.push('|');
        for b in chunk {
            if b.is_ascii_graphic() || *b == b' ' {
                hex.push(*b as char);
            } else {
                hex.push('.');
            }
        }
        hex.push('|');
        hex.push('\n');
    }
    fs::write(&hex_path, &hex).unwrap();
}

fn encode_value<T: Cdr2Encode>(val: &T) -> Vec<u8> {
    let max = val.max_cdr2_size();
    let mut buf = vec![0u8; max];
    let n = val.encode_cdr2_le(&mut buf).unwrap();
    buf.truncate(n);
    buf
}

/// Core golden vector test function.
///
/// - Encodes `val` to bytes
/// - In regen mode: writes .bin + .hex
/// - In verify mode: compares against existing .bin (fails if missing or different)
/// - Always: roundtrip decode + re-encode must be byte-identical
fn golden_test<T: Cdr2Encode + Cdr2Decode + PartialEq + std::fmt::Debug>(
    name: &str,
    val: &T,
) -> Vec<u8> {
    let encoded = encode_value(val);

    if is_regen_mode() {
        write_golden(name, &encoded);
    } else {
        let bin_path = golden_path(name, "bin");
        let expected = fs::read(&bin_path).unwrap_or_else(|e| {
            panic!("Golden vector {name}.bin not found ({e}). Run with GOLDEN_REGEN=1 to generate.")
        });
        assert_eq!(
            encoded,
            expected,
            "{name}: encoded bytes differ from golden .bin ({} bytes encoded vs {} expected)",
            encoded.len(),
            expected.len()
        );
    }

    // Roundtrip: decode
    let (decoded, consumed) = T::decode_cdr2_le(&encoded).unwrap();
    assert_eq!(
        consumed,
        encoded.len(),
        "{name}: consumed != encoded length"
    );
    assert_eq!(&decoded, val, "{name}: roundtrip value mismatch");

    // Re-encode must be byte-identical
    let re_encoded = encode_value(&decoded);
    assert_eq!(
        re_encoded, encoded,
        "{name}: re-encoded bytes differ from original"
    );

    encoded
}

/// Variant for types where PartialEq doesn't work (e.g., NaN).
/// Verifies encode + decode + re-encode byte stability only.
fn golden_test_bytes_only<T: Cdr2Encode + Cdr2Decode>(name: &str, val: &T) -> Vec<u8> {
    let encoded = encode_value(val);

    if is_regen_mode() {
        write_golden(name, &encoded);
    } else {
        let bin_path = golden_path(name, "bin");
        let expected = fs::read(&bin_path).unwrap_or_else(|e| {
            panic!("Golden vector {name}.bin not found ({e}). Run with GOLDEN_REGEN=1 to generate.")
        });
        assert_eq!(
            encoded, expected,
            "{name}: encoded bytes differ from golden"
        );
    }

    let (decoded, consumed) = T::decode_cdr2_le(&encoded).unwrap();
    assert_eq!(
        consumed,
        encoded.len(),
        "{name}: consumed != encoded length"
    );

    let re_encoded = encode_value(&decoded);
    assert_eq!(
        re_encoded, encoded,
        "{name}: re-encoded bytes differ from original"
    );

    encoded
}

// ===========================================================================
// Primitives (12 vectors)
// ===========================================================================

#[test]
fn golden_primitive_u8() {
    golden_test("primitive_u8", &0xABu8);
}

#[test]
fn golden_primitive_u16() {
    golden_test("primitive_u16", &0xCAFEu16);
}

#[test]
fn golden_primitive_u32() {
    golden_test("primitive_u32", &0xDEADBEEFu32);
}

#[test]
fn golden_primitive_u64() {
    golden_test("primitive_u64", &0xDEADBEEFCAFEBABEu64);
}

#[test]
fn golden_primitive_i8() {
    golden_test("primitive_i8", &(-1i8));
}

#[test]
fn golden_primitive_i16() {
    golden_test("primitive_i16", &(-256i16));
}

#[test]
fn golden_primitive_i32() {
    golden_test("primitive_i32", &(-42i32));
}

#[test]
fn golden_primitive_i64() {
    golden_test("primitive_i64", &(-1_000_000_000_000i64));
}

#[test]
fn golden_primitive_f32() {
    golden_test("primitive_f32", &std::f32::consts::PI);
}

#[test]
fn golden_primitive_f64() {
    golden_test("primitive_f64", &std::f64::consts::E);
}

#[test]
fn golden_primitive_bool_true() {
    // CDR2 encodes bool as u8: 1 = true
    let bytes = golden_test("primitive_bool_true", &1u8);
    assert_eq!(bytes, [1]);
}

#[test]
fn golden_primitive_bool_false() {
    // CDR2 encodes bool as u8: 0 = false
    let bytes = golden_test("primitive_bool_false", &0u8);
    assert_eq!(bytes, [0]);
}

// ===========================================================================
// Edge cases (5 vectors)
// ===========================================================================

#[test]
fn golden_edge_f64_nan() {
    let val = f64::NAN;
    let encoded = golden_test_bytes_only("edge_f64_nan", &val);
    let (decoded, _) = f64::decode_cdr2_le(&encoded).unwrap();
    assert!(decoded.is_nan());
}

#[test]
fn golden_edge_f64_infinity() {
    golden_test("edge_f64_infinity", &f64::INFINITY);
}

#[test]
fn golden_edge_f64_neg_infinity() {
    golden_test("edge_f64_neg_infinity", &f64::NEG_INFINITY);
}

#[test]
fn golden_edge_u64_max() {
    golden_test("edge_u64_max", &u64::MAX);
}

#[test]
fn golden_edge_i32_min() {
    golden_test("edge_i32_min", &i32::MIN);
}

// ===========================================================================
// Strings (4 vectors)
// ===========================================================================

#[test]
fn golden_string_empty() {
    golden_test("string_empty", &String::new());
}

#[test]
fn golden_string_hello() {
    golden_test("string_hello", &"Hello, CDR2!".to_string());
}

#[test]
fn golden_string_unicode() {
    golden_test("string_unicode", &"Rust DDS".to_string());
}

#[test]
fn golden_string_long_256() {
    // 256-byte bounded string (max common DDS bound)
    let s: String = (0..256).map(|i| (b'A' + (i % 26) as u8) as char).collect();
    golden_test("string_long_256", &s);
}

// ===========================================================================
// Vectors (5 vectors)
// ===========================================================================

#[test]
fn golden_vec_u32_empty() {
    let v: Vec<u32> = vec![];
    golden_test("vec_u32_empty", &v);
}

#[test]
fn golden_vec_u32_five() {
    let v: Vec<u32> = vec![1, 2, 3, 4, 5];
    golden_test("vec_u32_five", &v);
}

#[test]
fn golden_vec_f64_four() {
    let v: Vec<f64> = vec![1.0, 2.5, -7.125, 0.0];
    golden_test("vec_f64_four", &v);
}

#[test]
fn golden_vec_string_three() {
    let v: Vec<String> = vec!["alpha".into(), "beta".into(), "gamma".into()];
    golden_test("vec_string_three", &v);
}

#[test]
fn golden_vec_nested_vec() {
    // Vec<Vec<u32>> -- nested sequences
    let v: Vec<Vec<u32>> = vec![vec![1, 2], vec![3, 4, 5], vec![]];
    golden_test("vec_nested_vec", &v);
}

// ===========================================================================
// Maps (3 vectors) -- deterministic (sorted key encoding, NOT HashMap)
// ===========================================================================

/// A deterministic map: entries pre-sorted by key, encoded as CDR2 sequence
/// of (key, value) pairs. No HashMap involved -- byte output is stable.
#[derive(Debug, Clone, PartialEq)]
struct SortedMap<K: Ord + Clone, V: Clone> {
    entries: Vec<(K, V)>,
}

impl<K, V> SortedMap<K, V>
where
    K: Ord + Clone + Cdr2Encode + Cdr2Decode,
    V: Clone + Cdr2Encode + Cdr2Decode,
{
    fn new(mut entries: Vec<(K, V)>) -> Self {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Self { entries }
    }
}

impl<K, V> Cdr2Encode for SortedMap<K, V>
where
    K: Ord + Clone + Cdr2Encode,
    V: Clone + Cdr2Encode,
{
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        // CDR2 map: u32 length + sequence of (K, V)
        let len = self.entries.len() as u32;
        if dst.len() < 4 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[0..4].copy_from_slice(&len.to_le_bytes());
        let mut offset = 4;
        for (k, v) in &self.entries {
            let n = k.encode_cdr2_le(&mut dst[offset..])?;
            offset += n;
            let n = v.encode_cdr2_le(&mut dst[offset..])?;
            offset += n;
        }
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        let mut size = 4;
        for (k, v) in &self.entries {
            size += k.max_cdr2_size() + v.max_cdr2_size();
        }
        size
    }
}

impl<K, V> Cdr2Decode for SortedMap<K, V>
where
    K: Ord + Clone + Cdr2Decode,
    V: Clone + Cdr2Decode,
{
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        if src.len() < 4 {
            return Err(CdrError::UnexpectedEof);
        }
        let len = u32::from_le_bytes(src[0..4].try_into().unwrap()) as usize;
        let mut offset = 4;
        let mut entries = Vec::with_capacity(len);
        for _ in 0..len {
            let (k, n) = K::decode_cdr2_le(&src[offset..])?;
            offset += n;
            let (v, n) = V::decode_cdr2_le(&src[offset..])?;
            offset += n;
            entries.push((k, v));
        }
        Ok((Self { entries }, offset))
    }
}

#[test]
fn golden_map_u32_u32_empty() {
    let m: SortedMap<u32, u32> = SortedMap::new(vec![]);
    golden_test("map_u32_u32_empty", &m);
}

#[test]
fn golden_map_string_i32_populated() {
    let m = SortedMap::<String, i32>::new(vec![
        ("alpha".into(), 1),
        ("beta".into(), 2),
        ("gamma".into(), 3),
    ]);
    golden_test("map_string_i32_populated", &m);
}

#[test]
fn golden_map_string_struct_nested() {
    let m = SortedMap::<String, Point3D>::new(vec![
        (
            "origin".into(),
            Point3D {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
        ),
        (
            "target".into(),
            Point3D {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
        ),
    ]);
    golden_test("map_string_struct_nested", &m);
}

// ===========================================================================
// Structs (3 vectors)
// ===========================================================================

#[derive(Debug, Clone, PartialEq)]
struct Point3D {
    x: f64,
    y: f64,
    z: f64,
}

impl Cdr2Encode for Point3D {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        if dst.len() < 24 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[0..8].copy_from_slice(&self.x.to_le_bytes());
        dst[8..16].copy_from_slice(&self.y.to_le_bytes());
        dst[16..24].copy_from_slice(&self.z.to_le_bytes());
        Ok(24)
    }
    fn max_cdr2_size(&self) -> usize {
        24
    }
}

impl Cdr2Decode for Point3D {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        if src.len() < 24 {
            return Err(CdrError::UnexpectedEof);
        }
        let x = f64::from_le_bytes(src[0..8].try_into().unwrap());
        let y = f64::from_le_bytes(src[8..16].try_into().unwrap());
        let z = f64::from_le_bytes(src[16..24].try_into().unwrap());
        Ok((Self { x, y, z }, 24))
    }
}

#[test]
fn golden_struct_point3d() {
    let p = Point3D {
        x: 1.0,
        y: 2.0,
        z: 3.0,
    };
    let bytes = golden_test("struct_point3d", &p);
    assert_eq!(bytes.len(), 24);
}

#[derive(Debug, Clone, PartialEq)]
struct LabelledValue {
    value: f64,
    label: String,
}

impl Cdr2Encode for LabelledValue {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        if dst.len() < offset + 8 {
            return Err(CdrError::BufferTooSmall);
        }
        dst[offset..offset + 8].copy_from_slice(&self.value.to_le_bytes());
        offset += 8;
        let n = self.label.encode_cdr2_le(&mut dst[offset..])?;
        offset += n;
        Ok(offset)
    }
    fn max_cdr2_size(&self) -> usize {
        8 + self.label.max_cdr2_size()
    }
}

impl Cdr2Decode for LabelledValue {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        if src.len() < 8 {
            return Err(CdrError::UnexpectedEof);
        }
        let value = f64::from_le_bytes(src[0..8].try_into().unwrap());
        let (label, n) = String::decode_cdr2_le(&src[8..])?;
        Ok((Self { value, label }, 8 + n))
    }
}

#[test]
fn golden_struct_labelled_value() {
    golden_test(
        "struct_labelled_value",
        &LabelledValue {
            value: 42.0,
            label: "temperature".to_string(),
        },
    );
}

#[derive(Debug, Clone, PartialEq)]
struct Segment {
    start: Point3D,
    end: Point3D,
    name: String,
}

impl Cdr2Encode for Segment {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;
        offset += self.start.encode_cdr2_le(&mut dst[offset..])?;
        offset += self.end.encode_cdr2_le(&mut dst[offset..])?;
        offset += self.name.encode_cdr2_le(&mut dst[offset..])?;
        Ok(offset)
    }
    fn max_cdr2_size(&self) -> usize {
        self.start.max_cdr2_size() + self.end.max_cdr2_size() + self.name.max_cdr2_size()
    }
}

impl Cdr2Decode for Segment {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let (start, n) = Point3D::decode_cdr2_le(&src[offset..])?;
        offset += n;
        let (end, n) = Point3D::decode_cdr2_le(&src[offset..])?;
        offset += n;
        let (name, n) = String::decode_cdr2_le(&src[offset..])?;
        offset += n;
        Ok((Self { start, end, name }, offset))
    }
}

#[test]
fn golden_struct_nested_segment() {
    golden_test(
        "struct_nested_segment",
        &Segment {
            start: Point3D {
                x: 0.0,
                y: 0.0,
                z: 0.0,
            },
            end: Point3D {
                x: 10.0,
                y: 20.0,
                z: 30.0,
            },
            name: "path_a".to_string(),
        },
    );
}

// ===========================================================================
// Native bool (Phase 2 -- uses core impl, not u8 hack)
// ===========================================================================

#[test]
fn golden_bool_native_true() {
    golden_test("bool_native_true", &true);
}

#[test]
fn golden_bool_native_false() {
    golden_test("bool_native_false", &false);
}

// ===========================================================================
// char8 (Phase 2 -- XTypes 1.3 Section 7.4.1.4)
// ===========================================================================

#[test]
fn golden_char8_a() {
    golden_test("char8_a", &'A');
}

#[test]
fn golden_char8_zero() {
    golden_test("char8_zero", &'\0');
}

// ===========================================================================
// Fixed-size arrays (Phase 2 -- XTypes 1.3 Section 7.4.4.2, NO length prefix)
// ===========================================================================

#[test]
fn golden_array_u32_fixed_3() {
    let arr: [u32; 3] = [10, 20, 30];
    let bytes = golden_test("array_u32_fixed_3", &arr);
    assert_eq!(bytes.len(), 12); // 3 * 4, no length prefix
}

#[test]
fn golden_array_f64_fixed_2() {
    let arr: [f64; 2] = [std::f64::consts::PI, std::f64::consts::E];
    golden_test("array_f64_fixed_2", &arr);
}

// ===========================================================================
// Optional (Phase 2 -- XTypes 1.3 Section 7.4.3.5, 1-byte presence flag)
// ===========================================================================

#[test]
fn golden_optional_u32_present() {
    let val: Option<u32> = Some(42);
    let bytes = golden_test("optional_u32_present", &val);
    assert_eq!(bytes.len(), 5); // 1 flag + 4 u32
}

#[test]
fn golden_optional_u32_absent() {
    let val: Option<u32> = None;
    let bytes = golden_test("optional_u32_absent", &val);
    assert_eq!(bytes.len(), 1); // just the flag
}

#[test]
fn golden_optional_string_present() {
    let val: Option<String> = Some("hello".to_string());
    golden_test("optional_string_present", &val);
}

// ===========================================================================
// BTreeMap (Phase 2 -- deterministic map via core impl)
// ===========================================================================

#[test]
fn golden_btreemap_string_i32() {
    let mut m = std::collections::BTreeMap::new();
    m.insert("alpha".to_string(), 1i32);
    m.insert("beta".to_string(), 2i32);
    m.insert("gamma".to_string(), 3i32);
    golden_test("btreemap_string_i32", &m);
}

// ===========================================================================
// Inventory: verify all golden files exist
// ===========================================================================

const ALL_GOLDEN_VECTORS: &[&str] = &[
    // Primitives (12)
    "primitive_u8",
    "primitive_u16",
    "primitive_u32",
    "primitive_u64",
    "primitive_i8",
    "primitive_i16",
    "primitive_i32",
    "primitive_i64",
    "primitive_f32",
    "primitive_f64",
    "primitive_bool_true",
    "primitive_bool_false",
    // Edge cases (5)
    "edge_f64_nan",
    "edge_f64_infinity",
    "edge_f64_neg_infinity",
    "edge_u64_max",
    "edge_i32_min",
    // Strings (4)
    "string_empty",
    "string_hello",
    "string_unicode",
    "string_long_256",
    // Vectors (5)
    "vec_u32_empty",
    "vec_u32_five",
    "vec_f64_four",
    "vec_string_three",
    "vec_nested_vec",
    // Maps (3)
    "map_u32_u32_empty",
    "map_string_i32_populated",
    "map_string_struct_nested",
    // Structs (3)
    "struct_point3d",
    "struct_labelled_value",
    "struct_nested_segment",
    // Native bool (2)
    "bool_native_true",
    "bool_native_false",
    // char8 (2)
    "char8_a",
    "char8_zero",
    // Arrays (2)
    "array_u32_fixed_3",
    "array_f64_fixed_2",
    // Optional (3)
    "optional_u32_present",
    "optional_u32_absent",
    "optional_string_present",
    // BTreeMap (1)
    "btreemap_string_i32",
];

#[test]
fn golden_verify_all_exist() {
    for name in ALL_GOLDEN_VECTORS {
        let bin = golden_path(name, "bin");
        let hex = golden_path(name, "hex");
        assert!(bin.exists(), "Missing golden vector: {name}.bin");
        assert!(hex.exists(), "Missing golden vector: {name}.hex");
        let data = fs::read(&bin).unwrap();
        assert!(!data.is_empty(), "Empty golden vector: {name}.bin");
    }
    eprintln!(
        "Golden vectors inventory: {count} vectors verified",
        count = ALL_GOLDEN_VECTORS.len()
    );
}

# CDR2 Golden Vectors Manifest

**Version:** HDDS 1.0.8
**Generated:** 2026-02-17
**Spec:** OMG XTypes 1.3 Section 7.4.3 (CDR2 encoding)
**Encoding:** CDR2 Little-Endian (Encapsulation ID 0x000A)
**Test file:** `crates/hdds/tests/golden_vectors.rs`

## Verification

```bash
# Verify mode (default): compares encoded output against .bin files
cargo test --test golden_vectors

# Regeneration mode: overwrites .bin + .hex files
GOLDEN_REGEN=1 cargo test --test golden_vectors
```

## Vectors (42 total)

### Primitives (12)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `primitive_u8` | uint8 | 1 | 0xAB | XTypes 1.3 7.4.3.4 |
| `primitive_u16` | uint16 | 2 | 0xCAFE | XTypes 1.3 7.4.3.4 |
| `primitive_u32` | uint32 | 4 | 0xDEADBEEF | XTypes 1.3 7.4.3.4 |
| `primitive_u64` | uint64 | 8 | 0xDEADBEEFCAFEBABE | XTypes 1.3 7.4.3.4 |
| `primitive_i8` | int8 | 1 | -1 | XTypes 1.3 7.4.3.4 |
| `primitive_i16` | int16 | 2 | -256 | XTypes 1.3 7.4.3.4 |
| `primitive_i32` | int32 | 4 | -42 | XTypes 1.3 7.4.3.4 |
| `primitive_i64` | int64 | 8 | -1000000000000 | XTypes 1.3 7.4.3.4 |
| `primitive_f32` | float32 | 4 | PI (3.14159...) | XTypes 1.3 7.4.3.4 |
| `primitive_f64` | float64 | 8 | E (2.71828...) | XTypes 1.3 7.4.3.4 |
| `primitive_bool_true` | boolean | 1 | true (0x01) | XTypes 1.3 7.4.3.4 |
| `primitive_bool_false` | boolean | 1 | false (0x00) | XTypes 1.3 7.4.3.4 |

### Edge Cases (5)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `edge_f64_nan` | float64 | 8 | NaN (canonical) | IEEE 754-2008 |
| `edge_f64_infinity` | float64 | 8 | +Infinity | IEEE 754-2008 |
| `edge_f64_neg_infinity` | float64 | 8 | -Infinity | IEEE 754-2008 |
| `edge_u64_max` | uint64 | 8 | 0xFFFFFFFFFFFFFFFF | XTypes 1.3 7.4.3.4 |
| `edge_i32_min` | int32 | 4 | -2147483648 | XTypes 1.3 7.4.3.4 |

### Strings (4)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `string_empty` | string | 5 | "" (len=1, NUL) | XTypes 1.3 7.4.3.5 |
| `string_hello` | string | 17 | "Hello, CDR2!" | XTypes 1.3 7.4.3.5 |
| `string_unicode` | string | 13 | "Rust DDS" (UTF-8) | XTypes 1.3 7.4.3.5 |
| `string_long_256` | string | 261 | 256-char A-Z repeating | XTypes 1.3 7.4.3.5 |

### Sequences (5)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `vec_u32_empty` | sequence<uint32> | 4 | [] (len=0) | XTypes 1.3 7.4.3.6 |
| `vec_u32_five` | sequence<uint32> | 24 | [1, 2, 3, 4, 5] | XTypes 1.3 7.4.3.6 |
| `vec_f64_four` | sequence<float64> | 36 | [1.0, 2.5, -7.125, 0.0] | XTypes 1.3 7.4.3.6 |
| `vec_string_three` | sequence<string> | 33 | ["alpha", "beta", "gamma"] | XTypes 1.3 7.4.3.6 |
| `vec_nested_vec` | sequence<sequence<uint32>> | 36 | [[1,2], [3,4,5], []] | XTypes 1.3 7.4.3.6 |

### Maps (3)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `map_u32_u32_empty` | map<uint32,uint32> | 4 | {} (len=0) | XTypes 1.3 7.4.3.8 |
| `map_string_i32_populated` | map<string,int32> | 45 | {"alpha":1, "beta":2, "gamma":3} (sorted) | XTypes 1.3 7.4.3.8 |
| `map_string_struct_nested` | map<string,struct{f64,f64,f64}> | 74 | {"origin":(0,0,0), "target":(1,2,3)} (sorted) | XTypes 1.3 7.4.3.8 |

### Structs (3)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `struct_point3d` | struct{f64,f64,f64} | 24 | {x:1.0, y:2.0, z:3.0} | XTypes 1.3 7.4.3.7 |
| `struct_labelled_value` | struct{f64,string} | 24 | {value:42.0, label:"temperature"} | XTypes 1.3 7.4.3.7 |
| `struct_nested_segment` | struct{Point3D,Point3D,string} | 59 | {start:origin, end:(10,20,30), name:"path_a"} | XTypes 1.3 7.4.3.7 |

### Native Boolean (2)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `bool_native_true` | boolean | 1 | true (0x01) | XTypes 1.3 7.4.1.3 |
| `bool_native_false` | boolean | 1 | false (0x00) | XTypes 1.3 7.4.1.3 |

### char8 (2)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `char8_a` | char8 | 1 | 'A' (0x41) | XTypes 1.3 7.4.1.4 |
| `char8_zero` | char8 | 1 | '\0' (0x00) | XTypes 1.3 7.4.1.4 |

### Fixed-Size Arrays (2)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `array_u32_fixed_3` | uint32[3] | 12 | [10, 20, 30] (no length prefix) | XTypes 1.3 7.4.4.2 |
| `array_f64_fixed_2` | float64[2] | 16 | [PI, E] | XTypes 1.3 7.4.4.2 |

### Optional Members (3)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `optional_u32_present` | @optional uint32 | 5 | Some(42) -- flag=1 + value | XTypes 1.3 7.4.3.5 |
| `optional_u32_absent` | @optional uint32 | 1 | None -- flag=0 | XTypes 1.3 7.4.3.5 |
| `optional_string_present` | @optional string | 11 | Some("hello") | XTypes 1.3 7.4.3.5 |

### BTreeMap (1)

| Name | CDR2 Type | Size (bytes) | Value | Spec Ref |
|------|-----------|:------------:|-------|----------|
| `btreemap_string_i32` | map<string,int32> | 45 | {"alpha":1, "beta":2, "gamma":3} (deterministic) | XTypes 1.3 7.4.4.3 |

## Determinism Guarantees

- All vectors are byte-stable across runs (no randomized output).
- Maps use sorted-key canonical encoding (no `HashMap`).
- NaN uses Rust's canonical `f64::NAN` bit pattern (0x7FF8000000000000).
- Verify mode (default) will fail if encoded output differs from stored `.bin`.

## File Format

Each vector produces two files:
- `<name>.bin` -- raw CDR2 bytes (no encapsulation header)
- `<name>.hex` -- annotated hex dump (xxd-style: offset | hex | ASCII)

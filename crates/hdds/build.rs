// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// Build script for HDDS
//
// Generates Rust types with CDR2 traits from IDL definitions.
//
// Pipeline: IDL -> Parser -> Codegen -> src/generated/
//
// Phase 7a MVP: Hardcoded Temperature struct for validation.
// Phase 8: Full IDL parser integration via hdds-gen.
//
// This build script generates the Temperature struct used by internal tests.
// Users generate their own types via: hdds_gen rust Temperature.idl -o temperature.rs
// and the generated code will import `use hdds::*` (correct dependency flow).
//
// Output Structure:
//   src/generated/
//   +-- mod.rs           (auto-generated aggregator)
//   +-- temperature.rs   (Temperature struct with CDR2 traits)
//
// Naming Convention:
//   snake_case IDL filename -> module name (temperature.idl -> temperature.rs)

use std::fs;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR")?;
    let generated_dir = Path::new(&out_dir).join("generated");

    // Create generated directory in OUT_DIR (cargo publish safe)
    fs::create_dir_all(&generated_dir)?;

    // Phase 7a MVP: Generate hardcoded Temperature struct
    // Phase 8: Parse idl/*.idl files and invoke hdds-gen backend
    generate_temperature_struct(&generated_dir)?;

    // Generate mod.rs aggregator
    generate_mod_rs(&generated_dir)?;

    // Stage the typed cross-language fixture under OUT_DIR so package builds
    // never write into the source tree. The interop harness supplies the real
    // generated file; regular all-target builds use the compile-only stub.
    // The harness generates it under the target directory it builds into:
    // CARGO_TARGET_DIR when set (a worktree building into a shared target),
    // else the workspace's own target/.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Path::new(&manifest_dir).join("../../target"));
    let typed_test_source = target_dir.join("typed-test/interop_types.rs");
    let typed_test_dir = Path::new(&out_dir).join("typed-test");
    let typed_test_file = typed_test_dir.join("interop_types.rs");
    fs::create_dir_all(&typed_test_dir)?;
    if typed_test_source.exists() {
        fs::copy(&typed_test_source, &typed_test_file)?;
        // Only declare the dependency when the file is really there. Cargo treats a
        // `rerun-if-changed` path that does not exist as permanently stale, so
        // declaring it unconditionally rebuilt this script, then `hdds`, then every
        // dependent crate, on EVERY cargo invocation of a normal checkout, where the
        // typed-test input is never generated.
        println!("cargo:rerun-if-changed={}", typed_test_source.display());
    } else {
        fs::write(&typed_test_file, generate_interop_stub())?;
    }
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");

    // Rebuild if build script changes
    println!("cargo:rerun-if-changed=build.rs");

    // Build identification: embed the source commit so any shipped artifact
    // (shape_main for the OMG interop harness, libhdds_c, ...) can be tied
    // back to its source. `HDDS_BUILD_GIT_SHA` set in the environment wins
    // (packaged builds without a .git); otherwise ask git; otherwise "unknown".
    let git_sha = std::env::var("HDDS_BUILD_GIT_SHA")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=HDDS_BUILD_GIT_SHA={}", git_sha);
    println!("cargo:rerun-if-env-changed=HDDS_BUILD_GIT_SHA");

    // Dirty flag beside the commit: a provenance consumer (e.g. the
    // interop-smoke harness's `--build-info`) needs to know whether the
    // tree that produced this binary matched HDDS_BUILD_GIT_SHA exactly, or
    // carried uncommitted changes on top of it. `HDDS_BUILD_GIT_DIRTY` set
    // in the environment wins (packaged builds without a .git); otherwise
    // ask git; otherwise "unknown" (never silently claim "clean").
    let git_dirty = std::env::var("HDDS_BUILD_GIT_DIRTY")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["status", "--porcelain"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| {
                    if String::from_utf8_lossy(&o.stdout).trim().is_empty() {
                        "false".to_string()
                    } else {
                        "true".to_string()
                    }
                })
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=HDDS_BUILD_GIT_DIRTY={}", git_dirty);
    println!("cargo:rerun-if-env-changed=HDDS_BUILD_GIT_DIRTY");
    // Rerun when the commit moves. HEAD alone is not enough: on a branch it
    // holds "ref: refs/heads/<name>" and does not change when the branch
    // advances, so an incremental build would keep the previous commit's
    // id. Watch HEAD, the ref it resolves to, and packed-refs (where the
    // loose ref goes after a gc). Worktrees are handled by --git-path.
    let git_path = |arg: &str| {
        std::process::Command::new("git")
            .args(["rev-parse", "--git-path", arg])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|p| !p.is_empty())
    };
    let mut watched = Vec::new();
    watched.extend(git_path("HEAD"));
    if let Some(full_ref) = std::process::Command::new("git")
        .args(["rev-parse", "--symbolic-full-name", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|r| r.starts_with("refs/"))
    {
        watched.extend(git_path(&full_ref));
    }
    watched.extend(git_path("packed-refs"));
    for path in watched {
        println!("cargo:rerun-if-changed={}", path);
    }

    // Phase 8: Uncomment when IDL files are added
    // println!("cargo:rerun-if-changed=idl/");

    Ok(())
}

/// Generate a stub for `interop_types.rs` so `--all-targets` compiles
/// even when `hdds_gen` hasn't been run yet.
/// Real file is created by: `scripts/test-sdk-typed.sh`
const fn generate_interop_stub() -> &'static str {
    "\
// Auto-generated stub -- real types created by scripts/test-sdk-typed.sh
// This stub allows cargo check/clippy --all-targets to pass.
// Do NOT edit -- it will be overwritten by hdds_gen.

use hdds::core::ser::{Cdr2Encode, Cdr2Decode, CdrError};

#[derive(Debug, Clone, PartialEq)]
#[repr(u32)]
pub enum SensorKind { TEMPERATURE = 0, PRESSURE = 1, HUMIDITY = 2 }

#[derive(Debug, Clone, PartialEq)]
pub struct GeoPoint { pub latitude: f64, pub longitude: f64 }

#[derive(Debug, Clone, PartialEq)]
pub struct SensorReading {
    pub sensor_id: u32,
    pub kind: SensorKind,
    pub value: f32,
    pub label: String,
    pub timestamp_ns: i64,
    pub history: Vec<f32>,
    pub error_code: Option<i32>,
    pub location: GeoPoint,
}

impl Cdr2Encode for SensorReading {
    fn encode_cdr2_le(&self, _buf: &mut [u8]) -> Result<usize, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn max_cdr2_size(&self) -> usize { 0 }
    fn encode_cdr2_le_at(&self, _buf: &mut [u8], _offset: &mut usize) -> Result<(), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

impl Cdr2Decode for SensorReading {
    fn decode_cdr2_le(_buf: &[u8]) -> Result<(Self, usize), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn decode_cdr2_le_at(_src: &[u8], _offset: &mut usize) -> Result<Self, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

impl ::hdds::dds::DDS for SensorReading {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        static DESC: hdds::core::types::TypeDescriptor = hdds::core::types::TypeDescriptor {
            type_id: 0,
            type_name: \"SensorReading\",
            size_bytes: 0,
            alignment: 8,
            is_variable_size: true,
            fields: &[],
        };
        &DESC
    }
    fn encode(&self, _buf: &mut [u8], _version: hdds::CdrVersion) -> hdds::api::Result<usize> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn decode(_buf: &[u8], _version: hdds::CdrVersion) -> hdds::api::Result<Self> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KeyedSample {
    pub id: u32,
    pub active: bool,
    pub kind: SensorKind,
    pub name: String,
    pub origin: GeoPoint,
    pub reading: f32,
}

impl Cdr2Encode for KeyedSample {
    fn encode_cdr2_le(&self, _buf: &mut [u8]) -> Result<usize, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn max_cdr2_size(&self) -> usize { 0 }
    fn encode_cdr2_le_at(&self, _buf: &mut [u8], _offset: &mut usize) -> Result<(), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

impl Cdr2Decode for KeyedSample {
    fn decode_cdr2_le(_buf: &[u8]) -> Result<(Self, usize), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn decode_cdr2_le_at(_src: &[u8], _offset: &mut usize) -> Result<Self, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct FinalProbe { pub id: u32, pub label: String }

impl Cdr2Encode for FinalProbe {
    fn encode_cdr2_le(&self, _buf: &mut [u8]) -> Result<usize, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn max_cdr2_size(&self) -> usize { 0 }
    fn encode_cdr2_le_at(&self, _buf: &mut [u8], _offset: &mut usize) -> Result<(), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

impl Cdr2Decode for FinalProbe {
    fn decode_cdr2_le(_buf: &[u8]) -> Result<(Self, usize), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn decode_cdr2_le_at(_src: &[u8], _offset: &mut usize) -> Result<Self, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

impl ::hdds::dds::DDS for FinalProbe {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        static DESC: hdds::core::types::TypeDescriptor = hdds::core::types::TypeDescriptor {
            type_id: 0,
            type_name: \"FinalProbe\",
            size_bytes: 0,
            alignment: 4,
            is_variable_size: true,
            fields: &[],
        };
        &DESC
    }
    fn encode(&self, _buf: &mut [u8], _version: hdds::CdrVersion) -> hdds::api::Result<usize> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn decode(_buf: &[u8], _version: hdds::CdrVersion) -> hdds::api::Result<Self> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MutableProbe { pub id: u32, pub label: String }

impl Cdr2Encode for MutableProbe {
    fn encode_cdr2_le(&self, _buf: &mut [u8]) -> Result<usize, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn max_cdr2_size(&self) -> usize { 0 }
    fn encode_cdr2_le_at(&self, _buf: &mut [u8], _offset: &mut usize) -> Result<(), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

impl Cdr2Decode for MutableProbe {
    fn decode_cdr2_le(_buf: &[u8]) -> Result<(Self, usize), CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn decode_cdr2_le_at(_src: &[u8], _offset: &mut usize) -> Result<Self, CdrError> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}

impl ::hdds::dds::DDS for MutableProbe {
    fn type_descriptor() -> &'static hdds::core::types::TypeDescriptor {
        static DESC: hdds::core::types::TypeDescriptor = hdds::core::types::TypeDescriptor {
            type_id: 0,
            type_name: \"MutableProbe\",
            size_bytes: 0,
            alignment: 4,
            is_variable_size: true,
            fields: &[],
        };
        &DESC
    }
    fn encode(&self, _buf: &mut [u8], _version: hdds::CdrVersion) -> hdds::api::Result<usize> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
    fn decode(_buf: &[u8], _version: hdds::CdrVersion) -> hdds::api::Result<Self> {
        panic!(\"stub: run scripts/test-sdk-typed.sh to generate real interop types\")
    }
}
"
}

/// Generate Temperature struct with CDR2 traits (Phase 7a hardcoded MVP)
///
/// Implements:
/// - Struct definition: `struct Temperature { value: f32, timestamp: u32 }`
/// - `Cdr2Encode` trait with alignment and bounds checking
/// - `Cdr2Decode` trait with UTF-8 validation
/// - DDS marker trait
///
/// # Wire Format
///
/// ```text
/// Offset | Field     | Type | Alignment | Size
/// -------|-----------|------|-----------|-----
/// 0      | value     | f32  | 4-byte    | 4
/// 4      | timestamp | u32  | 4-byte    | 4
/// -------|-----------|------|-----------|-----
/// Total: 8 bytes (no padding needed, both fields align=4)
/// ```
#[allow(clippy::too_many_lines, clippy::uninlined_format_args)]
fn generate_temperature_struct(output_dir: &Path) -> std::io::Result<()> {
    let output_path = output_dir.join("temperature.rs");

    // Compute type_id using FNV-1a hash (same algorithm as hdds-codegen)
    let type_name = "Temperature";
    let type_id = compute_fnv1a_hash(type_name);

    // Generate full Temperature module with type_descriptor() impl
    let code = format!("// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Generated by build.rs (Phase 7a MVP + Task 1.2)
// DO NOT EDIT - Changes will be overwritten on next build

use hdds::core::ser::{{Cdr2Encode, Cdr2Decode, cursor::{{Cursor, CursorMut}}}};

/// Temperature sensor data (Phase 7a test case)
///
/// # Fields
///
/// - `value`: Temperature in degrees Celsius (f32)
/// - `timestamp`: Unix epoch seconds (i32, matches IDL 'long')
///
/// # CDR2 Encoding
///
/// Wire format (8 bytes total, little-endian):
/// ```text
/// [f32 value][u32 timestamp]
/// ```
///
/// Both fields are 4-byte aligned, no padding required.
#[derive(Debug, Clone, PartialEq)]
pub struct Temperature {{
    /// Temperature value in degrees Celsius
    pub value: f32,
    /// Unix epoch timestamp in seconds (i32 to match IDL 'long')
    pub timestamp: i32,
}}

// === DDS trait impl (Task 1.2 - full implementation without proc-macro) ===
impl ::hdds::dds::DDS for Temperature {{
    fn type_descriptor() -> &'static ::hdds::core::types::TypeDescriptor {{
        static DESC: ::hdds::core::types::TypeDescriptor = ::hdds::core::types::TypeDescriptor {{
            type_id: {:#010X},
            type_name: \"Temperature\",  // Simple name to match the IDL (no module)
            size_bytes: 8,
            alignment: 4,
            is_variable_size: false,
            fields: &[
                ::hdds::core::types::FieldLayout {{
                    name: \"value\",
                    offset_bytes: 0,
                    field_type: ::hdds::core::types::FieldType::Primitive(::hdds::core::types::PrimitiveKind::F32),
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                }},
                ::hdds::core::types::FieldLayout {{
                    name: \"timestamp\",
                    offset_bytes: 4,
                    field_type: ::hdds::core::types::FieldType::Primitive(::hdds::core::types::PrimitiveKind::I32),  // Match IDL 'long'
                    alignment: 4,
                    size_bytes: 4,
                    element_type: None,
                }},
            ],
        }};
        &DESC
    }}

    fn encode(&self, buf: &mut [u8], _version: ::hdds::CdrVersion) -> ::hdds::dds::Result<usize> {{
        use ::hdds::core::ser::Cdr2Encode;
        self.encode_cdr2_le(buf).map_err(Into::into)
    }}

    fn decode(buf: &[u8], _version: ::hdds::CdrVersion) -> ::hdds::dds::Result<Self> {{
        use ::hdds::core::ser::Cdr2Decode;
        Self::decode_cdr2_le(buf).map(|(val, _)| val).map_err(Into::into)
    }}

    /// @final, two 4-byte members: the body is the same under XCDR1 and
    /// XCDR2, so the XCDR1 it is labelled with is XCDR1.
    fn encodes_xcdr1_natively() -> bool {{
        true
    }}

    fn get_type_object() -> Option<::hdds::xtypes::CompleteTypeObject> {{
        Some(::hdds::xtypes::CompleteTypeObject::Struct(
            ::hdds::xtypes::CompleteStructType {{
                struct_flags: ::hdds::xtypes::StructTypeFlag::IS_FINAL,
                header: ::hdds::xtypes::CompleteStructHeader {{
                    base_type: None,
                    detail: ::hdds::xtypes::CompleteTypeDetail::new(\"Temperature\"),  // Simple name
                }},
                member_seq: vec![
                    ::hdds::xtypes::CompleteStructMember {{
                        common: ::hdds::xtypes::CommonStructMember {{
                            member_id: 0,
                            member_flags: ::hdds::xtypes::MemberFlag::empty(),
                            member_type_id: ::hdds::xtypes::TypeIdentifier::TK_FLOAT32,
                        }},
                        detail: ::hdds::xtypes::CompleteMemberDetail::new(\"value\"),
                    }},
                    ::hdds::xtypes::CompleteStructMember {{
                        common: ::hdds::xtypes::CommonStructMember {{
                            member_id: 1,
                            member_flags: ::hdds::xtypes::MemberFlag::empty(),
                            member_type_id: ::hdds::xtypes::TypeIdentifier::TK_INT32,  // Match IDL 'long'
                        }},
                        detail: ::hdds::xtypes::CompleteMemberDetail::new(\"timestamp\"),
                    }},
                ],
            }}
        ))
    }}
}}

// === CDR2 low-level encode/decode impls (manual, Phase 7a) ===
impl Cdr2Encode for Temperature {{
    fn encode_cdr2_le(&self, buf: &mut [u8]) -> Result<usize, hdds::core::ser::CdrError> {{
        use hdds::core::ser::{{CursorMut, CdrError}};

        let mut cursor = CursorMut::new(buf);
        cursor.write_bytes(&self.value.to_le_bytes())
            .map_err(|_| CdrError::BufferTooSmall)?;
        cursor.write_bytes(&self.timestamp.to_le_bytes())
            .map_err(|_| CdrError::BufferTooSmall)?;
        Ok(cursor.offset())
    }}

    fn max_cdr2_size(&self) -> usize {{
        8  // Fixed size: f32 (4) + i32 (4)
    }}

    fn encode_cdr2_le_at(
        &self,
        dst: &mut [u8],
        offset: &mut usize,
    ) -> Result<(), hdds::core::ser::CdrError> {{
        Cdr2Encode::encode_cdr2_le_at(&self.value, dst, offset)?;
        Cdr2Encode::encode_cdr2_le_at(&self.timestamp, dst, offset)?;
        Ok(())
    }}
}}

impl Cdr2Decode for Temperature {{
    fn decode_cdr2_le(buf: &[u8]) -> Result<(Self, usize), hdds::core::ser::CdrError> {{
        let mut offset = 0;
        let value = Self::decode_cdr2_le_at(buf, &mut offset)?;
        Ok((value, offset))
    }}

    fn decode_cdr2_le_at(
        src: &[u8],
        offset: &mut usize,
    ) -> Result<Self, hdds::core::ser::CdrError> {{
        let value = Cdr2Decode::decode_cdr2_le_at(src, offset)?;
        let timestamp = Cdr2Decode::decode_cdr2_le_at(src, offset)?;
        Ok(Self {{ value, timestamp }})
    }}
}}
", type_id);

    let mut file = fs::File::create(&output_path)?;
    file.write_all(code.as_bytes())?;

    Ok(())
}

/// Compute FNV-1a hash (32-bit) for type ID
/// Same algorithm as hdds-codegen and hdds-gen
fn compute_fnv1a_hash(s: &str) -> u32 {
    let mut hash = 2_166_136_261_u32;
    for byte in s.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// Generate mod.rs aggregator for generated modules
///
/// Creates a module file that:
/// - Warns users not to edit (auto-generated)
/// - Silences linter warnings (generated code)
/// - Declares public submodules for each generated type
///
/// # Output Example
///
/// ```rust
/// // Auto-generated by build.rs
/// #![allow(dead_code, clippy::all)]
///
/// pub mod temperature;
/// ```
fn generate_mod_rs(output_dir: &Path) -> std::io::Result<()> {
    let output_path = output_dir.join("mod.rs");

    let code = "\
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//
// Auto-generated by build.rs
// DO NOT EDIT - Changes will be overwritten on next build
//
// This module aggregates all generated types from IDL definitions.
// Phase 7a: temperature (hardcoded MVP)
// Phase 8: Full IDL parser integration

pub mod temperature {
    include!(concat!(env!(\"OUT_DIR\"), \"/generated/temperature.rs\"));
}
";

    let mut file = fs::File::create(&output_path)?;
    file.write_all(code.as_bytes())?;

    Ok(())
}

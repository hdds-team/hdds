// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Dynamic Types for DDS
//!
//! Runtime type manipulation without compile-time type knowledge.
//! Enables generic tools, bridges, and introspection.
//!
//! # Features
//!
//! - **TypeDescriptor**: Runtime type description (primitives, structs, sequences, etc.)
//! - **DynamicData**: Type-erased data container with field access
//! - **Builder API**: Fluent interface for building type descriptors
//! - **CDR Support**: Encode/decode DynamicData to/from CDR wire format
//!
//! # Example
//!
//! ```rust
//! use hdds::dynamic::{TypeDescriptorBuilder, DynamicData, PrimitiveKind};
//! use std::sync::Arc;
//!
//! // Build a type descriptor at runtime
//! let descriptor = Arc::new(TypeDescriptorBuilder::new("SensorReading")
//!     .field("sensor_id", PrimitiveKind::U32)
//!     .field("temperature", PrimitiveKind::F64)
//!     .field("timestamp", PrimitiveKind::U64)
//!     .build());
//!
//! // Create dynamic data
//! let mut data = DynamicData::new(&descriptor);
//! data.set("sensor_id", 42u32).unwrap();
//! data.set("temperature", 23.5f64).unwrap();
//! data.set("timestamp", 1702900000u64).unwrap();
//!
//! // Access fields
//! let temp: f64 = data.get("temperature").unwrap();
//! assert_eq!(temp, 23.5);
//! ```

mod builder;
mod cdr_dynamic;
mod dynamic_data;
/// JSON projection of dynamically decoded samples (feature `json`).
#[cfg(feature = "json")]
pub mod json;
/// KeyHash of a dynamic sample (RTPS 2.5 9.6.4.8).
mod key_hash;
mod type_descriptor;
mod value;
mod xtypes_bridge;

// RESEARCH-ONLY additive test module (union EquivalenceHash crack). Test-gated;
// compiles to nothing in non-test builds.
#[cfg(test)]
mod union_hash_crack;

pub use builder::TypeDescriptorBuilder;
pub use cdr_dynamic::{
    decode_dynamic, decode_dynamic_with_version, encode_dynamic, encode_dynamic_with_version,
    DynamicCdrError,
};
pub use dynamic_data::DynamicData;
pub use type_descriptor::{
    ArrayDescriptor, EnumDescriptor, EnumVariant, Extensibility, FieldDescriptor, PrimitiveKind,
    SequenceDescriptor, TryConstructKind, TypeDescriptor, TypeKind, UnionCase, UnionDescriptor,
};
pub use value::DynamicValue;
pub use xtypes_bridge::{
    complete_type_object_minimal_hash, type_descriptor_from_xtypes,
    type_descriptor_from_xtypes_with_registry, type_descriptor_to_xtypes,
    type_descriptor_to_xtypes_complete, HashMapTypeRegistry, TypeRegistry,
};

#[cfg(feature = "xtypes")]
pub use xtypes_bridge::debug_type_object_inner_cdr2;

#[cfg(feature = "xtypes-structural-assignability")]
pub use xtypes_bridge::{collect_nested_type_objects, complete_type_object_with_complete_refs};

pub(crate) use xtypes_bridge::complete_to_minimal_type_object;
#[cfg(feature = "xtypes-structural-assignability")]
pub(crate) use xtypes_bridge::complete_to_minimal_with_dependencies;

#[cfg(target_os = "windows")]
pub const LONG_DOUBLE_SIZE: usize = 8;
#[cfg(not(target_os = "windows"))]
pub const LONG_DOUBLE_SIZE: usize = 16;

#[cfg(target_os = "windows")]
pub const LONG_DOUBLE_ALIGN: usize = 8;
#[cfg(not(target_os = "windows"))]
pub const LONG_DOUBLE_ALIGN: usize = 16;

#[cfg(test)]
mod mutable_header_tests;
#[cfg(test)]
mod tests;

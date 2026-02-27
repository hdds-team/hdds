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
mod type_descriptor;
mod value;
mod xtypes_bridge;

pub use builder::TypeDescriptorBuilder;
pub use cdr_dynamic::{decode_dynamic, encode_dynamic, DynamicCdrError};
pub use dynamic_data::DynamicData;
pub use type_descriptor::{
    ArrayDescriptor, EnumDescriptor, EnumVariant, FieldDescriptor, PrimitiveKind,
    SequenceDescriptor, TypeDescriptor, TypeKind, UnionCase, UnionDescriptor,
};
pub use value::DynamicValue;
pub use xtypes_bridge::{
    type_descriptor_from_xtypes, type_descriptor_from_xtypes_with_registry, HashMapTypeRegistry,
    TypeRegistry,
};

#[cfg(target_os = "windows")]
pub const LONG_DOUBLE_SIZE: usize = 8;
#[cfg(not(target_os = "windows"))]
pub const LONG_DOUBLE_SIZE: usize = 16;

#[cfg(target_os = "windows")]
pub const LONG_DOUBLE_ALIGN: usize = 8;
#[cfg(not(target_os = "windows"))]
pub const LONG_DOUBLE_ALIGN: usize = 16;

#[cfg(test)]
mod tests;

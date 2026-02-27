// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Type descriptor for runtime field layout and serialization metadata.
//!
//! Defines `TypeDescriptor` and `FieldLayout` for describing message types
//! at runtime. Used by CDR serialization and XTypes type matching.

/// Field type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Primitive(PrimitiveKind),
    Sequence,
    Array,
    Struct,
    String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveKind {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Bool,
    String, // For hdds_gen compatibility
}

/// Layout of a single field (runtime/compile-time descriptor)
#[derive(Debug)]
pub struct FieldLayout {
    pub name: &'static str,
    pub offset_bytes: u32,
    pub field_type: FieldType,
    pub alignment: u8,
    pub size_bytes: u32,
    pub element_type: Option<&'static TypeDescriptor>,
}

/// Type descriptor: metadata for serialization/discovery
#[derive(Debug)]
pub struct TypeDescriptor {
    pub type_id: u32,            // FNV-1a hash
    pub type_name: &'static str, // e.g., "Point"
    pub size_bytes: u32,         // total serialized size (if fixed)
    pub alignment: u8,           // max alignment of fields
    pub is_variable_size: bool,  // true if contains sequence/string
    pub fields: &'static [FieldLayout],
}

impl TypeDescriptor {
    /// Placeholder for manual registration (before macro T0.5+)
    pub const fn new(
        type_id: u32,
        type_name: &'static str,
        size_bytes: u32,
        alignment: u8,
        is_variable_size: bool,
        fields: &'static [FieldLayout],
    ) -> Self {
        Self {
            type_id,
            type_name,
            size_bytes,
            alignment,
            is_variable_size,
            fields,
        }
    }
}

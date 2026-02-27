// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Safe message descriptor model for TypeObject building.
//!
//!
//! Defines `MessageDescriptor`, `MessageMember`, and `FieldType` for
//! representing ROS 2 message types in a safe, Rust-friendly way.

use crate::core::types::ROS_HASH_SIZE;

/// Primitive ROS 2 field types supported by the builder.
#[derive(Clone, Copy, Debug)]
pub enum PrimitiveType {
    Float32,
    Float64,
    LongDouble,
    Char8,
    Char16,
    Boolean,
    Octet,
    UInt8,
    Int8,
    UInt16,
    Int16,
    UInt32,
    Int32,
    UInt64,
    Int64,
}

impl PrimitiveType {
    // @audit-ok: Simple pattern matching (cyclo 15, cogni 1) - dispatch table for type conversion
    pub const fn to_type_kind(self) -> crate::xtypes::TypeKind {
        use crate::xtypes::TypeKind;

        match self {
            Self::Float32 => TypeKind::TK_FLOAT32,
            Self::Float64 => TypeKind::TK_FLOAT64,
            Self::LongDouble => TypeKind::TK_FLOAT128,
            Self::Char8 => TypeKind::TK_CHAR8,
            Self::Char16 => TypeKind::TK_CHAR16,
            Self::Boolean => TypeKind::TK_BOOLEAN,
            Self::Octet | Self::UInt8 => TypeKind::TK_UINT8,
            Self::Int8 => TypeKind::TK_INT8,
            Self::UInt16 => TypeKind::TK_UINT16,
            Self::Int16 => TypeKind::TK_INT16,
            Self::UInt32 => TypeKind::TK_UINT32,
            Self::Int32 => TypeKind::TK_INT32,
            Self::UInt64 => TypeKind::TK_UINT64,
            Self::Int64 => TypeKind::TK_INT64,
        }
    }
}

/// High-level field description used by the builder.
#[derive(Clone, Debug)]
pub enum FieldType<'a> {
    Primitive(PrimitiveType),
    String {
        bound: Option<u32>,
    },
    WString {
        bound: Option<u32>,
    },
    Nested(&'a MessageDescriptor<'a>),
    Array {
        element: Box<FieldType<'a>>,
        dimensions: Vec<u32>,
    },
    Sequence {
        element: Box<FieldType<'a>>,
        bound: Option<u32>,
    },
}

/// Description of a single struct member.
#[derive(Clone, Debug)]
pub struct MessageMember<'a> {
    pub name: &'a str,
    pub field_type: FieldType<'a>,
    pub is_key: bool,
}

/// Description of a ROS 2 message.
#[derive(Clone, Debug)]
pub struct MessageDescriptor<'a> {
    pub namespace: &'a str,
    pub name: &'a str,
    pub members: &'a [MessageMember<'a>],
    pub ros_hash_version: u8,
    pub ros_hash: &'a [u8; ROS_HASH_SIZE],
}

impl MessageDescriptor<'_> {
    /// Compute the fully-qualified name (`namespace::name`).
    pub fn fqn(&self) -> String {
        if self.namespace.is_empty() {
            self.name.to_string()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }
}

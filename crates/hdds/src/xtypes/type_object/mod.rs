// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeObject per OMG DDS-XTypes v1.3 specification
//!
//!
//! Section 7.3.4: TypeObject - Runtime type representation

use super::TypeIdentifier;

mod alias;
mod annotations;
mod bitmasks;
mod bitsets;
pub mod codec;
mod collections;
mod details;
mod enums;
mod structs;
mod unions;

pub use alias::*;
pub use annotations::*;
pub use bitmasks::*;
pub use bitsets::*;
pub use codec::{compress_type_object, decompress_type_object};
pub use collections::*;
pub use details::*;
pub use enums::*;
pub use structs::*;
pub use unions::*;

/// TypeObject - Runtime representation of a DDS type
///
/// Per DDS-XTypes v1.3 spec section 7.3.4:
/// "The TypeObject is a complete, self-contained representation of a DDS type
/// that can be serialized and transmitted over the wire."
///
/// There are two kinds:
/// - **Complete**: Full metadata (names, annotations, comments)
/// - **Minimal**: Assignability info only (wire format, member order)
#[derive(Debug, Clone, PartialEq)]
pub enum TypeObject {
    /// Complete TypeObject (full structural equality)
    Complete(CompleteTypeObject),

    /// Minimal TypeObject (assignability-based)
    Minimal(MinimalTypeObject),
}

/// CompleteTypeObject - All DDS types with full metadata
#[derive(Debug, Clone, PartialEq)]
pub enum CompleteTypeObject {
    /// Structure type
    Struct(CompleteStructType),

    /// Union type (discriminated)
    Union(CompleteUnionType),

    /// Enumeration type
    Enumerated(CompleteEnumeratedType),

    /// Bitmask type
    Bitmask(CompleteBitmaskType),

    /// Bitset type (IDL 4.2)
    Bitset(CompleteBitsetType),

    /// Sequence type (bounded or unbounded)
    Sequence(CompleteSequenceType),

    /// Array type (fixed-size, multi-dimensional)
    Array(CompleteArrayType),

    /// Map type (key-value collection)
    Map(CompleteMapType),

    /// Type alias (typedef)
    Alias(CompleteAliasType),

    /// Annotation type (IDL 4.2)
    Annotation(CompleteAnnotationType),
}

/// MinimalTypeObject - All DDS types with minimal metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinimalTypeObject {
    /// Structure type
    Struct(MinimalStructType),

    /// Union type (discriminated)
    Union(MinimalUnionType),

    /// Enumeration type
    Enumerated(MinimalEnumeratedType),

    /// Bitmask type
    Bitmask(MinimalBitmaskType),

    /// Bitset type (IDL 4.2)
    Bitset(MinimalBitsetType),

    /// Sequence type (bounded or unbounded)
    Sequence(MinimalSequenceType),

    /// Array type (fixed-size, multi-dimensional)
    Array(MinimalArrayType),

    /// Map type (key-value collection)
    Map(MinimalMapType),

    /// Type alias (typedef)
    Alias(MinimalAliasType),

    /// Annotation type (IDL 4.2)
    Annotation(MinimalAnnotationType),
}

#[cfg(test)]
mod tests;

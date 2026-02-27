// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Type and member detail structures per OMG DDS-XTypes v1.3.
//!
//!
//! Metadata for names, annotations, and verbatim documentation.

use super::TypeIdentifier;

// ============================================================================
// Detail Structures (Names, Annotations)
// ============================================================================

/// CompleteTypeDetail - Complete type metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteTypeDetail {
    /// Type name (fully qualified)
    ///
    /// Example: "com::example::Temperature"
    pub type_name: String,

    /// Annotations applied to this type
    pub ann_builtin: Option<AppliedBuiltinTypeAnnotations>,

    /// Custom annotations
    pub ann_custom: Option<Vec<AppliedAnnotation>>,
}

/// MinimalTypeDetail - Minimal type metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalTypeDetail {
    // Empty for minimal - no names or annotations
}

/// CompleteMemberDetail - Complete member metadata
#[derive(Debug, Clone, PartialEq)]
pub struct CompleteMemberDetail {
    /// Member name
    ///
    /// Example: "temperature", "sensor_id"
    pub name: String,

    /// Annotations applied to this member
    pub ann_builtin: Option<AppliedBuiltinMemberAnnotations>,

    /// Custom annotations
    pub ann_custom: Option<Vec<AppliedAnnotation>>,
}

/// MinimalMemberDetail - Minimal member metadata
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalMemberDetail {
    /// Name hash (MD5 hash of member name, truncated to 32 bits)
    pub name_hash: u32,
}

/// AppliedBuiltinTypeAnnotations - Built-in type annotations
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppliedBuiltinTypeAnnotations {
    /// @verbatim annotation (language-specific type name)
    pub verbatim: Option<String>,
}

/// AppliedBuiltinMemberAnnotations - Built-in member annotations
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AppliedBuiltinMemberAnnotations {
    /// @unit annotation (e.g., "meters", "celsius")
    pub unit: Option<String>,

    /// @min annotation (minimum value)
    pub min: Option<f64>,

    /// @max annotation (maximum value)
    pub max: Option<f64>,

    /// @hash_id annotation (custom hash value)
    pub hash_id: Option<String>,
}

/// AppliedAnnotation - Custom annotation application
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedAnnotation {
    /// Annotation type identifier
    pub annotation_type_id: TypeIdentifier,

    /// Annotation parameters (name -> value)
    pub param_seq: Vec<AnnotationParameterValue>,
}

/// CompleteAnnotationParameter - Complete annotation parameter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAnnotationParameter {
    /// Common parameter info
    pub common: CommonAnnotationParameter,

    /// Parameter name
    pub name: String,

    /// Default value (optional)
    pub default_value: Option<AnnotationParameterValue>,
}

/// MinimalAnnotationParameter - Minimal annotation parameter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalAnnotationParameter {
    /// Common parameter info
    pub common: CommonAnnotationParameter,

    /// Name hash
    pub name_hash: u32,

    /// Default value (optional)
    pub default_value: Option<AnnotationParameterValue>,
}

/// CommonAnnotationParameter - Info shared between Complete and Minimal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonAnnotationParameter {
    /// Parameter flags
    pub member_flags: AnnotationParameterFlag,

    /// Parameter type
    pub member_type_id: TypeIdentifier,
}

/// AnnotationParameterValue - Value of an annotation parameter
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationParameterValue {
    /// Boolean value
    Boolean(bool),

    /// Integer value
    Int32(i32),

    /// String value
    String(String),

    /// Enumeration value
    Enumerated(i32),
}

// ============================================================================
// Flags (bitflags)
// ============================================================================

/// StructTypeFlag - Struct extensibility and properties
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StructTypeFlag(pub u16);

impl StructTypeFlag {
    /// @final (default) - No changes allowed
    pub const IS_FINAL: Self = Self(0x0001);

    /// @appendable - Can add members at end
    pub const IS_APPENDABLE: Self = Self(0x0002);

    /// @mutable - Can add/remove members anywhere
    pub const IS_MUTABLE: Self = Self(0x0004);

    /// Struct is nested (used within another struct)
    pub const IS_NESTED: Self = Self(0x0008);

    /// Use hash-based member IDs (@autoid(HASH))
    pub const IS_AUTOID_HASH: Self = Self(0x0010);

    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if flag is set
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// MemberFlag - Member properties (@key, @optional, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct MemberFlag(pub u16);

impl MemberFlag {
    /// @optional or TRY_CONSTRUCT1
    pub const TRY_CONSTRUCT1: Self = Self(0x0001);

    /// TRY_CONSTRUCT2
    pub const TRY_CONSTRUCT2: Self = Self(0x0002);

    /// @external (not serialized)
    pub const IS_EXTERNAL: Self = Self(0x0004);

    /// @optional
    pub const IS_OPTIONAL: Self = Self(0x0008);

    /// @must_understand
    pub const IS_MUST_UNDERSTAND: Self = Self(0x0010);

    /// @key
    pub const IS_KEY: Self = Self(0x0020);

    /// Has @default value
    pub const IS_DEFAULT: Self = Self(0x0040);

    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if flag is set
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// EnumeratedLiteralFlag - Enumeration literal flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct EnumeratedLiteralFlag(pub u16);

impl EnumeratedLiteralFlag {
    /// Empty flags (reserved for future)
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// CollectionElementFlag - Collection element flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CollectionElementFlag(pub u16);

impl CollectionElementFlag {
    /// Empty flags (reserved for future)
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// UnionTypeFlag - Union extensibility flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct UnionTypeFlag(pub u16);

impl UnionTypeFlag {
    /// @final (default) - No changes allowed
    pub const IS_FINAL: Self = Self(0x0001);

    /// @appendable - Can add cases
    pub const IS_APPENDABLE: Self = Self(0x0002);

    /// @mutable - Can add/remove cases
    pub const IS_MUTABLE: Self = Self(0x0004);

    /// Union is nested
    pub const IS_NESTED: Self = Self(0x0008);

    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if flag is set
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) != 0
    }
}

/// BitflagFlag - Bitmask flag flags (reserved)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BitflagFlag(pub u16);

impl BitflagFlag {
    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// BitsetTypeFlag - Bitset type flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BitsetTypeFlag(pub u16);

impl BitsetTypeFlag {
    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// BitfieldFlag - Bitfield flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct BitfieldFlag(pub u16);

impl BitfieldFlag {
    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// AliasTypeFlag - Alias type flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct AliasTypeFlag(pub u16);

impl AliasTypeFlag {
    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// TypeRelationFlag - Type relation flags (for aliases)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct TypeRelationFlag(pub u16);

impl TypeRelationFlag {
    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }
}

/// AnnotationParameterFlag - Annotation parameter flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct AnnotationParameterFlag(pub u16);

impl AnnotationParameterFlag {
    /// Empty flags
    pub const fn empty() -> Self {
        Self(0)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

impl CompleteTypeDetail {
    /// Create a simple type detail with just a name
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            ann_builtin: None,
            ann_custom: None,
        }
    }
}

impl MinimalTypeDetail {
    /// Create a minimal type detail (empty)
    pub const fn new() -> Self {
        Self {}
    }
}

impl Default for MinimalTypeDetail {
    fn default() -> Self {
        Self::new()
    }
}

impl CompleteMemberDetail {
    /// Create a simple member detail with just a name
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ann_builtin: None,
            ann_custom: None,
        }
    }
}

impl MinimalMemberDetail {
    /// Create from member name (computes hash)
    pub fn from_name(name: &str) -> Self {
        // Compute MD5 hash of name, truncate to 32 bits
        #[cfg(feature = "xtypes")]
        {
            use md5::{Digest, Md5};
            let mut hasher = Md5::new();
            hasher.update(name.as_bytes());
            let result = hasher.finalize();
            let name_hash = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
            Self { name_hash }
        }

        #[cfg(not(feature = "xtypes"))]
        {
            // Fallback: use simple hash
            let _ = name;
            Self { name_hash: 0 }
        }
    }
}

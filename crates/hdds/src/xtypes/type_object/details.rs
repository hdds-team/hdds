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
///
/// DDS-XTypes 1.3 Annex B (spec text lines 12751-12754): an APPENDABLE record
/// holding `@optional AppliedVerbatimAnnotation verbatim`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppliedBuiltinTypeAnnotations {
    /// `@verbatim(placement="...", language="...", text="...")`
    pub verbatim: Option<AppliedVerbatimAnnotation>,
}

/// AppliedVerbatimAnnotation - the three parameters of an applied
/// `@verbatim` (DDS-XTypes 1.3 Annex B, spec text lines 12680-12686, FINAL:
/// `string<32> placement; string<32> language; string text;`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppliedVerbatimAnnotation {
    /// Where the text goes (e.g. `BEGIN_FILE`, `BEFORE_DECLARATION`)
    pub placement: String,
    /// Target language (e.g. `c++`, `*`)
    pub language: String,
    /// The verbatim text
    pub text: String,
}

/// AppliedBuiltinMemberAnnotations - Built-in member annotations
///
/// DDS-XTypes 1.3 Annex B (spec text lines 12692-12698): an APPENDABLE
/// record of four @optional fields. `min` and `max` are
/// `AnnotationParameterValue`s, the literal as the IDL wrote it
/// (`@min`, `@max`, or both bounds of `@range`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppliedBuiltinMemberAnnotations {
    /// @unit annotation (e.g., "meters", "celsius")
    pub unit: Option<String>,

    /// @min annotation, or the lower bound of @range
    pub min: Option<AnnotationParameterValue>,

    /// @max annotation, or the upper bound of @range
    pub max: Option<AnnotationParameterValue>,

    /// @hash_id annotation (custom hash value)
    pub hash_id: Option<String>,
}

/// AppliedAnnotationParameter - One named parameter in an applied annotation
///
/// Per OMG DDS-XTypes v1.3 sec. 7.3.4.8.10 IDL:
/// `struct AppliedAnnotationParameter { NameHash paramname_hash; AnnotationParameterValue value; };`
/// `@extensibility(FINAL)` -- no DHEADER on the wire; fields packed directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedAnnotationParameter {
    /// MD5(param_name)[0..4] per XTypes v1.3 sec. 7.3.4.6 `typedef uint32 NameHash`.
    pub paramname_hash: u32,
    /// Parameter value -- a union over the 4 supported TypeKind case labels.
    pub value: AnnotationParameterValue,
}

/// AppliedAnnotation - Custom annotation application
///
/// Per OMG DDS-XTypes v1.3 sec. 7.3.4.8.10 IDL:
/// ```text
/// @extensibility(FINAL)
/// struct AppliedAnnotation {
///     TypeIdentifier annotation_typeid;
///     @optional AppliedAnnotationParameterSeq param_seq;
/// };
/// ```
/// `@extensibility(FINAL)` -- no DHEADER on the wire.
/// `@optional param_seq` -- encoded as `bool` discriminator + (if true) sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedAnnotation {
    /// Annotation type identifier
    pub annotation_type_id: TypeIdentifier,

    /// Annotation parameters -- `None` when the annotation carries only default values
    /// (the `@optional` field is absent on the wire); `Some(vec![])` is distinct
    /// from `None` on the wire (bool=true, seq_len=0 vs bool=false).
    pub param_seq: Option<Vec<AppliedAnnotationParameter>>,
}

/// CompleteAnnotationParameter - Complete annotation parameter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompleteAnnotationParameter {
    /// Common parameter info
    pub common: CommonAnnotationParameter,

    /// Parameter name
    pub name: String,

    /// Default value (Annex B: not optional)
    pub default_value: AnnotationParameterValue,
}

/// MinimalAnnotationParameter - Minimal annotation parameter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinimalAnnotationParameter {
    /// Common parameter info
    pub common: CommonAnnotationParameter,

    /// Name hash
    pub name_hash: u32,

    /// Default value (Annex B: not optional)
    pub default_value: AnnotationParameterValue,
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
///
/// DDS-XTypes 1.3 Annex B, `union AnnotationParameterValue switch (octet)`:
/// one variant per case label, the discriminator being the `TypeKind` of the
/// value. Floating point values are kept as their IEEE 754 bit patterns, so
/// the value is `Eq` and re-encodes to the octets it was decoded from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationParameterValue {
    /// `TK_BOOLEAN`
    Boolean(bool),

    /// `TK_BYTE` (octet)
    Byte(u8),

    /// `TK_INT8`
    Int8(i8),

    /// `TK_UINT8`
    Uint8(u8),

    /// `TK_INT16`
    Int16(i16),

    /// `TK_UINT16`
    Uint16(u16),

    /// `TK_INT32`
    Int32(i32),

    /// `TK_UINT32`
    Uint32(u32),

    /// `TK_INT64`
    Int64(i64),

    /// `TK_UINT64`
    Uint64(u64),

    /// `TK_FLOAT32`, as `f32::to_bits`
    Float32(u32),

    /// `TK_FLOAT64`, as `f64::to_bits`
    Float64(u64),

    /// `TK_FLOAT128`: the 16 octets of an IEEE 754 binary128, little endian
    Float128([u8; 16]),

    /// `TK_CHAR8`
    Char8(u8),

    /// `TK_CHAR16`: one UTF-16 code unit
    Char16(u16),

    /// `TK_STRING8`
    String(String),

    /// `TK_STRING16`: UTF-16 code units, no terminator
    String16(Vec<u16>),

    /// `TK_ENUM`
    Enumerated(i32),

    /// The `default` case, `ExtendedAnnotationParameterValue` (an empty
    /// `@mutable` struct reserved for extension), under any discriminator
    /// that is not one of the labels above. `body` holds the octets inside
    /// its DHEADER, empty today.
    Extended {
        /// The discriminator it was received with.
        discriminator: u8,
        /// The struct's members, inside its DHEADER.
        body: Vec<u8>,
    },
}

impl AnnotationParameterValue {
    /// A `TK_FLOAT32` value.
    pub fn float32(v: f32) -> Self {
        Self::Float32(v.to_bits())
    }

    /// A `TK_FLOAT64` value.
    pub fn float64(v: f64) -> Self {
        Self::Float64(v.to_bits())
    }
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

/// EnumTypeFlag - the flags of an enumerated type.
///
/// DDS-XTypes 1.3 Annex B declares `typedef TypeFlag EnumTypeFlag;` (spec text
/// line 12372), the same 16-bit TypeFlag bitmask as `StructTypeFlag`. An
/// enumeration "may be final or appendable on a type-by-type basis" (7.2.3
/// Table 12), and the flag that says which is serialized as the first field of
/// `{Complete,Minimal}EnumeratedType`: it is part of the EquivalenceHash. The
/// IDL comment "unused" means it plays no part in assignability.
///
/// An enum is written with `IS_APPENDABLE` (0x0002) and a bitmask with 0x0000
/// unless the builder or generator says otherwise. A builder or generator that
/// writes another value (`IS_FINAL` for a `@final` enum, or for one without
/// annotation under a final default) moves that enum's EquivalenceHashes, and
/// those of every type referencing it.
pub type EnumTypeFlag = StructTypeFlag;

/// BitmaskTypeFlag - the flags of a bitmask type (`typedef TypeFlag
/// BitmaskTypeFlag;`, spec text line 12373); see [`EnumTypeFlag`].
pub type BitmaskTypeFlag = StructTypeFlag;

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

    /// IS_DEFAULT (`D`, `@position(6)` = 0x0040) -- marks the enum's default
    /// literal. Per DDS-XTypes v1.3 sec. 7.2.2.4.1 Table 9 the `D` flag is the only
    /// flag applicable to an `EnumeratedLiteralFlag` (IDL line 133). The default
    /// literal is the first enumerator in declaration order (OMG IDL enum default
    /// semantics) unless overridden by `@default_literal`. The default literal
    /// carries this bit, so it must be present for the enum EquivalenceHash to
    /// byte-match a conformant implementation's.
    pub const IS_DEFAULT: Self = Self(0x0040);
}

/// CollectionTypeFlag - Collection type flags (DDS-XTypes 1.3 Annex B,
/// `typedef TypeFlag CollectionTypeFlag; // Unused. No flags apply`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct CollectionTypeFlag(pub u16);

/// CollectionElementFlag - Collection element flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CollectionElementFlag(pub u16);

impl CollectionElementFlag {
    /// Empty flags (reserved for future)
    pub const fn empty() -> Self {
        Self(0)
    }

    /// TRY_CONSTRUCT1 (0x0001) - low bit of the TryConstructKind.
    ///
    /// Per DDS-XTypes v1.3 sec. 7.2.2.4.2 the default `TryConstructKind` for a
    /// collection element is `DISCARD`, encoded as TRY_CONSTRUCT1 set /
    /// TRY_CONSTRUCT2 clear. HDDS therefore sets
    /// this bit in the `CollectionElementFlag` of every plain collection's
    /// `PlainCollectionHeader` (sec. 7.3.4.4), exactly as struct members carry
    /// `MemberFlag::TRY_CONSTRUCT1`. Emitting empty flags here perturbs the
    /// collection TypeIdentifier bytes and the enclosing EquivalenceHash.
    pub const TRY_CONSTRUCT1: Self = Self(0x0001);
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

/// AnnotationTypeFlag - Annotation type flags (DDS-XTypes 1.3 Annex B,
/// `typedef TypeFlag AnnotationTypeFlag; // Unused. No flags apply`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct AnnotationTypeFlag(pub u16);

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

    /// Create a member detail whose Minimal name_hash is derived from
    /// `hash_name` rather than `name`.
    ///
    /// This is used when the DDS-XML `@hashid("alias")` annotation is present:
    /// `name` is the actual field name (e.g. "x2") while `hash_name` is the
    /// canonical alias (e.g. "x1") whose MD5 hash appears in the Minimal
    /// TypeObject so that the two types hash-match (DDS-XTypes sec. 7.3.1.2.1.1).
    ///
    /// When `name == hash_name` this is equivalent to [`Self::new`].
    pub fn new_with_hash_name(name: impl Into<String>, hash_name: impl Into<String>) -> Self {
        let name_str: String = name.into();
        let hash_name_str: String = hash_name.into();
        let ann_builtin = if name_str != hash_name_str {
            Some(AppliedBuiltinMemberAnnotations {
                hash_id: Some(hash_name_str),
                ..Default::default()
            })
        } else {
            None
        };
        Self {
            name: name_str,
            ann_builtin,
            ann_custom: None,
        }
    }

    /// Return the name to use for Minimal name_hash computation.
    ///
    /// The string the member's `@hashid` id is computed from: the
    /// `ann_builtin.hash_id` value when present and not empty, otherwise the
    /// member's name (DDS-XTypes 1.3 7.3.1.2.1.1: `@hashid` without a
    /// parameter, or with the empty string, hashes the member name).
    pub fn hash_name(&self) -> &str {
        self.ann_builtin
            .as_ref()
            .and_then(|a| a.hash_id.as_deref())
            .filter(|h| !h.is_empty())
            .unwrap_or(&self.name)
    }
}

/// Compute the 32-bit NameHash for a member/parameter name per
/// XTypes v1.3 sec. 7.3.4.6: `u32::from_le_bytes(MD5(name)[0..4])`.
///
/// Returns `0` when the `xtypes` feature is disabled so callers can
/// still build without the `md5` dependency in degraded mode.
#[cfg(feature = "xtypes")]
pub(crate) fn compute_name_hash(name: &str) -> u32 {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(name.as_bytes());
    let result = hasher.finalize();
    u32::from_le_bytes([result[0], result[1], result[2], result[3]])
}

#[cfg(not(feature = "xtypes"))]
pub(crate) fn compute_name_hash(_name: &str) -> u32 {
    0
}

impl MinimalMemberDetail {
    /// Create from member name (computes hash per XTypes v1.3 sec. 7.3.4.6).
    pub fn from_name(name: &str) -> Self {
        Self {
            name_hash: compute_name_hash(name),
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeIdentifier per OMG DDS-XTypes v1.3 specification
//!
//!
//! Section 7.3.4: Representing Types with TypeIdentifier and TypeObject

use super::{EquivalenceHash, TypeKind};
use std::convert::TryFrom;
use std::fmt;

/// EquivalenceKind - determines which equivalence relation to use
///
/// Per DDS-XTypes v1.3 spec section 7.3.1:
/// - **MINIMAL**: Assignability (can writer data be read by reader?)
/// - **COMPLETE**: Full equivalence (names, annotations, everything matches)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EquivalenceKind {
    /// Minimal equivalence (assignability-based)
    ///
    /// Two types are equivalent if one can be assigned to the other.
    /// This is used for runtime type compatibility checking.
    Minimal = 0x10,

    /// Complete equivalence (full structural equality)
    ///
    /// Two types are equivalent if they are structurally identical including
    /// names, member names, annotations, etc.
    Complete = 0x20,

    /// Both equivalences coincide (EK_BOTH, wire 0xF3)
    ///
    /// Per DDS-XTypes v1.3 sec. 7.3.4.4 IDL, a `PlainCollectionHeader` whose
    /// element TypeIdentifier is fully self-describing (a primitive, string,
    /// or other non-hash kind) carries `equiv_kind = EK_BOTH`: the minimal
    /// and complete TypeObjects of the collection are identical, so neither
    /// equivalence is distinguished. The spec-conformant value here is 0xF3;
    /// emitting EK_COMPLETE instead changes the collection
    /// TypeIdentifier bytes and therefore the enclosing type's EquivalenceHash.
    Both = 0x30,
}

impl EquivalenceKind {
    pub const fn to_u8(self) -> u8 {
        match self {
            EquivalenceKind::Minimal => 0x10,
            EquivalenceKind::Complete => 0x20,
            EquivalenceKind::Both => 0x30,
        }
    }
}

/// StronglyConnectedComponentId - for types with cyclic dependencies
///
/// Per DDS-XTypes v1.3 spec section 7.3.4.11:
/// Used when types reference each other (e.g., `Node { next: Option<Node> }`).
///
/// The `sc_component_id` carries a `TypeObjectHashId` value: per OMG
/// DDS-XTypes v1.3 sec. 7.3.4.6.5 / sec. 7.3.4.6.6 (Minimal / Complete Hash
/// `TypeIdentifier`s) and the IDL annex, `TypeObjectHashId` is an
/// `@extensibility(FINAL) @nested union switch(octet)` whose
/// discriminator is `EK_MINIMAL = 0xF1` or `EK_COMPLETE = 0xF2`. The
/// 1-byte discriminator precedes the 14-byte hash on the wire; the
/// `kind` field below carries it so the encoder / decoder round-trip
/// it correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StronglyConnectedComponentId {
    /// TypeObjectHashId union tag -- selects between Minimal and Complete
    /// equivalence hashes per XTypes v1.3 sec. 7.3.4.5 line 12307.
    pub kind: EquivalenceKind,

    /// Hash of the strongly connected component
    pub sc_component_id: EquivalenceHash,

    /// Number of types in the component
    pub scc_length: i32,

    /// Index of this type within the component (0-based)
    pub scc_index: i32,
}

/// Plain-collection element header per OMG DDS-XTypes v1.3 sec. 7.3.4.4 IDL
/// (`PlainCollectionHeader`). Carries the equivalence kind that selects
/// between Minimal and Complete hashes for the contained TypeIdentifiers,
/// plus the per-element collection flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlainCollectionHeader {
    /// Minimal vs Complete equivalence for the collection's element /
    /// key TypeIdentifiers (XTypes v1.3 sec. 7.3.4.6.5 / sec. 7.3.4.6.6).
    pub equiv_kind: EquivalenceKind,
    /// Per-element collection flags (`CollectionElementFlag`, u16). See
    /// `crate::xtypes::type_object::CollectionElementFlag` for
    /// the bit definitions.
    pub element_flags: crate::xtypes::type_object::CollectionElementFlag,
}

/// `PlainSequenceSElemDefn` per OMG DDS-XTypes v1.3 sec. 7.3.4.4 IDL:
/// `sequence<element, bound>` whose `bound` fits in an `SBound` (`u8`).
/// Element identifier is `@external` in the IDL; on the wire this is
/// just the inner TypeIdentifier serialized in place.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlainSequenceSElemDefn {
    pub header: PlainCollectionHeader,
    /// `SBound` -- maximum number of elements (1..=255).
    pub bound: u8,
    pub element_identifier: Box<TypeIdentifier>,
}

/// `PlainSequenceLElemDefn` per OMG DDS-XTypes v1.3 sec. 7.3.4.4 IDL:
/// `sequence<element, bound>` whose `bound` is an `LBound` (`u32`),
/// typically used when the bound exceeds 255 or for unbounded
/// sequences encoded with `bound == 0`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlainSequenceLElemDefn {
    pub header: PlainCollectionHeader,
    /// `LBound` -- maximum number of elements; `0` denotes unbounded.
    pub bound: u32,
    pub element_identifier: Box<TypeIdentifier>,
}

/// `PlainArraySElemDefn` per OMG DDS-XTypes v1.3 sec. 7.3.4.4 IDL: fixed
/// array `element[dim1][dim2]...[dimN]` whose dimensions all fit in
/// `SBound` (`u8`). Use [`PlainArrayLElemDefn`] when any dimension
/// exceeds 255.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlainArraySElemDefn {
    pub header: PlainCollectionHeader,
    /// `SBoundSeq` -- dimensions of the multi-dimensional array
    /// (1..=255 each).
    pub array_bound_seq: Vec<u8>,
    pub element_identifier: Box<TypeIdentifier>,
}

/// `PlainArrayLElemDefn` per OMG DDS-XTypes v1.3 sec. 7.3.4.4 IDL: fixed
/// array `element[dim1][dim2]...[dimN]` whose dimensions are `LBound`
/// (`u32`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlainArrayLElemDefn {
    pub header: PlainCollectionHeader,
    /// `LBoundSeq` -- dimensions of the multi-dimensional array.
    pub array_bound_seq: Vec<u32>,
    pub element_identifier: Box<TypeIdentifier>,
}

/// `PlainMapSTypeDefn` per OMG DDS-XTypes v1.3 sec. 7.3.4.4 IDL:
/// `map<key, element, bound>` whose `bound` fits in an `SBound`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlainMapSTypeDefn {
    pub header: PlainCollectionHeader,
    /// `SBound` -- maximum number of entries (1..=255).
    pub bound: u8,
    pub element_identifier: Box<TypeIdentifier>,
    /// Per-key flags (`CollectionElementFlag`). Mirrors the element
    /// flags but applies to the key TypeIdentifier.
    pub key_flags: crate::xtypes::type_object::CollectionElementFlag,
    pub key_identifier: Box<TypeIdentifier>,
}

/// `PlainMapLTypeDefn` per OMG DDS-XTypes v1.3 sec. 7.3.4.4 IDL:
/// `map<key, element, bound>` whose `bound` is an `LBound`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PlainMapLTypeDefn {
    pub header: PlainCollectionHeader,
    /// `LBound` -- maximum number of entries; `0` denotes unbounded.
    pub bound: u32,
    pub element_identifier: Box<TypeIdentifier>,
    pub key_flags: crate::xtypes::type_object::CollectionElementFlag,
    pub key_identifier: Box<TypeIdentifier>,
}

/// TypeIdentifier - uniquely identifies a DDS type
///
/// Per DDS-XTypes v1.3 spec section 7.3.4:
/// "The TypeIdentifier uniquely identifies a type (a set of equivalent types
/// according to an equivalence relationship: COMPLETE, MINIMAL)."
///
/// # TypeIdentifier Variants
///
/// 1. **Primitive**: Direct identification (TK_INT32, TK_FLOAT64, etc.)
/// 2. **String**: Bounded strings (length <= 255 or length > 255)
/// 3. **Hash**: Complex types (structs, unions, enums) - most common
/// 4. **StronglyConnected**: Types with cyclic dependencies
///
/// # Example
///
/// ```ignore
/// use hdds::xtypes::{TypeIdentifier, TypeKind, EquivalenceHash};
///
/// // Primitive type (int32)
/// let int32_id = TypeIdentifier::Primitive(TypeKind::TK_INT32);
///
/// // Bounded string (length 64)
/// let string_id = TypeIdentifier::StringSmall { bound: 64 };
///
/// // Complex type (struct Temperature)
/// let hash = EquivalenceHash::compute(/* ... */);
/// let struct_id = TypeIdentifier::Complete(hash);
/// ```
#[derive(Clone)]
pub enum TypeIdentifier {
    /// Primitive types (boolean, integers, floats, chars)
    ///
    /// Used for: TK_BOOLEAN, TK_INT32, TK_FLOAT64, etc.
    ///
    /// No hashing needed - primitives are identified directly by TypeKind.
    Primitive(TypeKind),

    /// 8-bit string with small bound (length <= 255)
    ///
    /// Corresponds to: `string<bound>` where 0 < bound <= 255
    ///
    /// If bound == 0, represents unbounded string (use with caution).
    StringSmall { bound: u8 },

    /// 8-bit string with large bound (length > 255)
    ///
    /// Corresponds to: `string<bound>` where bound > 255
    StringLarge { bound: u32 },

    /// 16-bit string (UTF-16) with small bound (length <= 255)
    ///
    /// Corresponds to: `wstring<bound>` where 0 < bound <= 255
    WStringSmall { bound: u8 },

    /// 16-bit string (UTF-16) with large bound (length > 255)
    ///
    /// Corresponds to: `wstring<bound>` where bound > 255
    WStringLarge { bound: u32 },

    /// Hash-based TypeIdentifier (Minimal equivalence)
    ///
    /// Most common variant for complex types (structs, enums, unions, etc.)
    ///
    /// The hash is computed from the MinimalTypeObject representation.
    /// Two types with different names but same structure can have the same hash.
    Minimal(EquivalenceHash),

    /// Hash-based TypeIdentifier (Complete equivalence)
    ///
    /// Used when full structural equivalence is required (including names).
    ///
    /// The hash is computed from the CompleteTypeObject representation.
    /// Two types are equivalent only if everything matches (names, annotations, etc.)
    Complete(EquivalenceHash),

    /// Strongly connected component (cyclic dependencies)
    ///
    /// Used for types that reference each other (e.g., linked lists, trees).
    ///
    /// Example:
    /// ```idl
    /// struct Node {
    ///     long value;
    ///     sequence<Node> children;  // Cyclic reference
    /// };
    /// ```
    StronglyConnected(StronglyConnectedComponentId),

    /// Plain `sequence<T, bound>` with `bound <= 255`
    /// (DDS-XTypes v1.3 sec. 7.3.4.4 -- `TI_PLAIN_SEQUENCE_SMALL = 0x80`).
    PlainSequenceSmall(PlainSequenceSElemDefn),

    /// Plain `sequence<T, bound>` with `bound > 255` or unbounded
    /// (DDS-XTypes v1.3 sec. 7.3.4.4 -- `TI_PLAIN_SEQUENCE_LARGE = 0x81`).
    PlainSequenceLarge(PlainSequenceLElemDefn),

    /// Plain fixed array `T[d1][...][dN]` with all dimensions `<= 255`
    /// (DDS-XTypes v1.3 sec. 7.3.4.4 -- `TI_PLAIN_ARRAY_SMALL = 0x90`).
    PlainArraySmall(PlainArraySElemDefn),

    /// Plain fixed array with any dimension `> 255`
    /// (DDS-XTypes v1.3 sec. 7.3.4.4 -- `TI_PLAIN_ARRAY_LARGE = 0x91`).
    PlainArrayLarge(PlainArrayLElemDefn),

    /// Plain `map<K, V, bound>` with `bound <= 255`
    /// (DDS-XTypes v1.3 sec. 7.3.4.4 -- `TI_PLAIN_MAP_SMALL = 0xA0`).
    PlainMapSmall(PlainMapSTypeDefn),

    /// Plain `map<K, V, bound>` with `bound > 255` or unbounded
    /// (DDS-XTypes v1.3 sec. 7.3.4.4 -- `TI_PLAIN_MAP_LARGE = 0xA1`).
    PlainMapLarge(PlainMapLTypeDefn),
}

impl PartialEq for TypeIdentifier {
    // @audit-ok: flat enum variant dispatch (14 arms), no nesting
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Primitive(a), Self::Primitive(b)) => a == b,
            (Self::StringSmall { bound: a }, Self::StringSmall { bound: b }) => a == b,
            (Self::StringLarge { bound: a }, Self::StringLarge { bound: b }) => a == b,
            (Self::WStringSmall { bound: a }, Self::WStringSmall { bound: b }) => a == b,
            (Self::WStringLarge { bound: a }, Self::WStringLarge { bound: b }) => a == b,
            (Self::Minimal(a), Self::Minimal(b)) => a == b,
            (Self::Complete(a), Self::Complete(b)) => a == b,
            (Self::StronglyConnected(a), Self::StronglyConnected(b)) => a == b,
            (Self::PlainSequenceSmall(a), Self::PlainSequenceSmall(b)) => a == b,
            (Self::PlainSequenceLarge(a), Self::PlainSequenceLarge(b)) => a == b,
            (Self::PlainArraySmall(a), Self::PlainArraySmall(b)) => a == b,
            (Self::PlainArrayLarge(a), Self::PlainArrayLarge(b)) => a == b,
            (Self::PlainMapSmall(a), Self::PlainMapSmall(b)) => a == b,
            (Self::PlainMapLarge(a), Self::PlainMapLarge(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for TypeIdentifier {}

impl std::hash::Hash for TypeIdentifier {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Self::Primitive(kind) => kind.hash(state),
            Self::StringSmall { bound } => bound.hash(state),
            Self::StringLarge { bound } => bound.hash(state),
            Self::WStringSmall { bound } => bound.hash(state),
            Self::WStringLarge { bound } => bound.hash(state),
            Self::Minimal(hash) => hash.hash(state),
            Self::Complete(hash) => hash.hash(state),
            Self::StronglyConnected(sc) => sc.hash(state),
            Self::PlainSequenceSmall(sd) => sd.hash(state),
            Self::PlainSequenceLarge(ld) => ld.hash(state),
            Self::PlainArraySmall(sd) => sd.hash(state),
            Self::PlainArrayLarge(ld) => ld.hash(state),
            Self::PlainMapSmall(sd) => sd.hash(state),
            Self::PlainMapLarge(ld) => ld.hash(state),
        }
    }
}

impl TypeIdentifier {
    /// Create a TypeIdentifier for a primitive type
    pub const fn primitive(kind: TypeKind) -> Self {
        TypeIdentifier::Primitive(kind)
    }

    /// Create a TypeIdentifier for a bounded string (8-bit)
    pub fn string(bound: u32) -> Self {
        if let Ok(small) = u8::try_from(bound) {
            TypeIdentifier::StringSmall { bound: small }
        } else {
            TypeIdentifier::StringLarge { bound }
        }
    }

    /// Create a TypeIdentifier for a bounded wstring (16-bit, UTF-16)
    pub fn wstring(bound: u32) -> Self {
        if let Ok(small) = u8::try_from(bound) {
            TypeIdentifier::WStringSmall { bound: small }
        } else {
            TypeIdentifier::WStringLarge { bound }
        }
    }

    /// Create a TypeIdentifier from a Minimal EquivalenceHash
    pub const fn minimal(hash: EquivalenceHash) -> Self {
        TypeIdentifier::Minimal(hash)
    }

    /// Create a TypeIdentifier from a Complete EquivalenceHash
    pub const fn complete(hash: EquivalenceHash) -> Self {
        TypeIdentifier::Complete(hash)
    }

    /// Returns true if this is a primitive type
    pub const fn is_primitive(&self) -> bool {
        matches!(self, TypeIdentifier::Primitive(_))
    }

    /// Returns true if this is a string type
    pub const fn is_string(&self) -> bool {
        matches!(
            self,
            TypeIdentifier::StringSmall { .. }
                | TypeIdentifier::StringLarge { .. }
                | TypeIdentifier::WStringSmall { .. }
                | TypeIdentifier::WStringLarge { .. }
        )
    }

    /// Returns true if this is a hash-based type (Minimal or Complete)
    pub const fn is_hash_based(&self) -> bool {
        matches!(
            self,
            TypeIdentifier::Minimal(_) | TypeIdentifier::Complete(_)
        )
    }

    /// Returns true if this is a strongly connected component
    pub const fn is_strongly_connected(&self) -> bool {
        matches!(self, TypeIdentifier::StronglyConnected(_))
    }

    /// Returns true if this is a plain collection TypeIdentifier
    /// (sequence, array, or map) per DDS-XTypes v1.3 sec. 7.3.4.6.4
    /// "Indirect Hash TypeIdentifiers".
    pub const fn is_plain_collection(&self) -> bool {
        matches!(
            self,
            TypeIdentifier::PlainSequenceSmall(_)
                | TypeIdentifier::PlainSequenceLarge(_)
                | TypeIdentifier::PlainArraySmall(_)
                | TypeIdentifier::PlainArrayLarge(_)
                | TypeIdentifier::PlainMapSmall(_)
                | TypeIdentifier::PlainMapLarge(_)
        )
    }

    /// Get the EquivalenceKind if this is a hash-based TypeIdentifier
    pub const fn equivalence_kind(&self) -> Option<EquivalenceKind> {
        match self {
            TypeIdentifier::Minimal(_) => Some(EquivalenceKind::Minimal),
            TypeIdentifier::Complete(_) => Some(EquivalenceKind::Complete),
            _ => None,
        }
    }

    /// Get the EquivalenceHash if this is hash-based
    pub fn get_hash(&self) -> Option<&EquivalenceHash> {
        match self {
            TypeIdentifier::Minimal(h) | TypeIdentifier::Complete(h) => Some(h),
            _ => None,
        }
    }

    /// Returns the TypeKind if this is a primitive type
    pub const fn get_primitive_kind(&self) -> Option<TypeKind> {
        match self {
            TypeIdentifier::Primitive(kind) => Some(*kind),
            _ => None,
        }
    }
}

impl fmt::Debug for TypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeIdentifier::Primitive(kind) => write!(f, "TypeId::Primitive({:?})", kind),
            TypeIdentifier::StringSmall { bound } => {
                write!(f, "TypeId::String<{}>", bound)
            }
            TypeIdentifier::StringLarge { bound } => {
                write!(f, "TypeId::String<{}>", bound)
            }
            TypeIdentifier::WStringSmall { bound } => {
                write!(f, "TypeId::WString<{}>", bound)
            }
            TypeIdentifier::WStringLarge { bound } => {
                write!(f, "TypeId::WString<{}>", bound)
            }
            TypeIdentifier::Minimal(hash) => write!(f, "TypeId::Minimal({})", hash),
            TypeIdentifier::Complete(hash) => write!(f, "TypeId::Complete({})", hash),
            TypeIdentifier::StronglyConnected(sc) => {
                write!(
                    f,
                    "TypeId::StronglyConnected({}[{}/{}])",
                    sc.sc_component_id, sc.scc_index, sc.scc_length
                )
            }
            TypeIdentifier::PlainSequenceSmall(sd) => write!(
                f,
                "TypeId::PlainSeq<{}>[{:?}]",
                sd.bound, sd.element_identifier
            ),
            TypeIdentifier::PlainSequenceLarge(ld) => write!(
                f,
                "TypeId::PlainSeq<{}>[{:?}]",
                ld.bound, ld.element_identifier
            ),
            TypeIdentifier::PlainArraySmall(sd) => write!(
                f,
                "TypeId::PlainArray<{:?}>[{:?}]",
                sd.array_bound_seq, sd.element_identifier
            ),
            TypeIdentifier::PlainArrayLarge(ld) => write!(
                f,
                "TypeId::PlainArray<{:?}>[{:?}]",
                ld.array_bound_seq, ld.element_identifier
            ),
            TypeIdentifier::PlainMapSmall(sd) => write!(
                f,
                "TypeId::PlainMap<{}>[{:?} -> {:?}]",
                sd.bound, sd.key_identifier, sd.element_identifier
            ),
            TypeIdentifier::PlainMapLarge(ld) => write!(
                f,
                "TypeId::PlainMap<{}>[{:?} -> {:?}]",
                ld.bound, ld.key_identifier, ld.element_identifier
            ),
        }
    }
}

impl fmt::Display for TypeIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeIdentifier::Primitive(kind) => write!(f, "{:?}", kind),
            TypeIdentifier::StringSmall { bound } => write!(f, "string<{}>", bound),
            TypeIdentifier::StringLarge { bound } => write!(f, "string<{}>", bound),
            TypeIdentifier::WStringSmall { bound } => write!(f, "wstring<{}>", bound),
            TypeIdentifier::WStringLarge { bound } => write!(f, "wstring<{}>", bound),
            TypeIdentifier::Minimal(hash) => write!(f, "TypeId(MIN:{})", hash),
            TypeIdentifier::Complete(hash) => write!(f, "TypeId(COM:{})", hash),
            TypeIdentifier::StronglyConnected(sc) => {
                write!(f, "TypeId(SC:{})", sc.sc_component_id)
            }
            TypeIdentifier::PlainSequenceSmall(sd) => {
                write!(f, "sequence<{}, {}>", sd.element_identifier, sd.bound)
            }
            TypeIdentifier::PlainSequenceLarge(ld) => {
                write!(f, "sequence<{}, {}>", ld.element_identifier, ld.bound)
            }
            TypeIdentifier::PlainArraySmall(sd) => {
                write!(f, "{}", sd.element_identifier)?;
                for d in &sd.array_bound_seq {
                    write!(f, "[{}]", d)?;
                }
                Ok(())
            }
            TypeIdentifier::PlainArrayLarge(ld) => {
                write!(f, "{}", ld.element_identifier)?;
                for d in &ld.array_bound_seq {
                    write!(f, "[{}]", d)?;
                }
                Ok(())
            }
            TypeIdentifier::PlainMapSmall(sd) => write!(
                f,
                "map<{}, {}, {}>",
                sd.key_identifier, sd.element_identifier, sd.bound
            ),
            TypeIdentifier::PlainMapLarge(ld) => write!(
                f,
                "map<{}, {}, {}>",
                ld.key_identifier, ld.element_identifier, ld.bound
            ),
        }
    }
}

// Convenience constructors for common primitives
impl TypeIdentifier {
    /// TypeIdentifier for boolean
    pub const TK_BOOLEAN: Self = TypeIdentifier::Primitive(TypeKind::TK_BOOLEAN);
    /// TypeIdentifier for byte/octet
    pub const TK_BYTE: Self = TypeIdentifier::Primitive(TypeKind::TK_BYTE);
    /// TypeIdentifier for int8
    pub const TK_INT8: Self = TypeIdentifier::Primitive(TypeKind::TK_INT8);
    /// TypeIdentifier for int16
    pub const TK_INT16: Self = TypeIdentifier::Primitive(TypeKind::TK_INT16);
    /// TypeIdentifier for int32
    pub const TK_INT32: Self = TypeIdentifier::Primitive(TypeKind::TK_INT32);
    /// TypeIdentifier for int64
    pub const TK_INT64: Self = TypeIdentifier::Primitive(TypeKind::TK_INT64);
    /// TypeIdentifier for uint8
    pub const TK_UINT8: Self = TypeIdentifier::Primitive(TypeKind::TK_UINT8);
    /// TypeIdentifier for uint16
    pub const TK_UINT16: Self = TypeIdentifier::Primitive(TypeKind::TK_UINT16);
    /// TypeIdentifier for uint32
    pub const TK_UINT32: Self = TypeIdentifier::Primitive(TypeKind::TK_UINT32);
    /// TypeIdentifier for uint64
    pub const TK_UINT64: Self = TypeIdentifier::Primitive(TypeKind::TK_UINT64);
    /// TypeIdentifier for float32
    pub const TK_FLOAT32: Self = TypeIdentifier::Primitive(TypeKind::TK_FLOAT32);
    /// TypeIdentifier for float64
    pub const TK_FLOAT64: Self = TypeIdentifier::Primitive(TypeKind::TK_FLOAT64);
    /// TypeIdentifier for char8
    pub const TK_CHAR8: Self = TypeIdentifier::Primitive(TypeKind::TK_CHAR8);
    /// TypeIdentifier for char16
    pub const TK_CHAR16: Self = TypeIdentifier::Primitive(TypeKind::TK_CHAR16);
    /// TypeIdentifier for an unbounded string8, held INERT as
    /// `Primitive(TypeKind::TK_STRING8)`.
    ///
    /// That value is not spec-legal, and the constant is deliberately left at
    /// it. See the GUARDRAIL below, which is now backed by a measurement
    /// rather than by an argument. The legal value is `StringSmall { bound: 0 }`
    /// and `TypeIdentifier::string(0)` produces it for every caller that needs
    /// a real string TypeIdentifier; only this constant stays inert.
    ///
    /// Why the legal value is `StringSmall { bound: 0 }`: DDS-XTypes v1.3 7.3.4.4 gives a string the `TI_STRING8_SMALL`
    /// (0x70) or `TI_STRING8_LARGE` (0x71) discriminator plus a bound, and
    /// `TK_STRING8` (0x20) belongs to the `TypeKind` union, a different one.
    /// The encoder writes a `Primitive` discriminator verbatim, so the constant
    /// put a bare 0x20 on the wire that this crate's OWN decoder refuses. The
    /// crate already knew: `type_kind.rs` asserts
    /// `!TypeKind::TK_STRING8.is_primitive()`.
    ///
    /// Bound 0 means unbounded, which is the convention this crate had already
    /// settled on independently in three places: `TypeIdentifier::string()`'s
    /// own doc, both dynamic-type builders (`xtypes/builder/core.rs`,
    /// `xtypes/builder/ros.rs`) calling `string(bound.unwrap_or(0))`, and the
    /// assignability matcher, which documents `StringSmall{0}` as "the
    /// spec-conformant TI_STRING8_SMALL encoding".
    ///
    /// GUARDRAIL, kept because its second half still stands: the reason this
    /// constant was left broken was that fixing it makes the
    /// `CompleteTypeObject` CDR2 round-trip succeed, and HDDS's TypeObject is
    /// not yet hash-exact, so a partial one can flip a strict vendor from
    /// name-accept to hash-REJECT. (The shape_main ShapeType no longer
    /// carries this form: its `@key color` is `TypeIdentifier::string(128)`
    /// and that TypeObject round-trips. The matcher still
    /// reads this inert form as the unbounded string it denotes,
    /// `string_identifier_as_spec_form`, for a peer that announces it.) What
    /// has since been established is that PID_TYPE_OBJECT emission is gated
    /// on the DESTINATION VENDOR
    /// (`core/discovery/multicast/rtps_packet.rs:506`), not on whether a
    /// round-trip succeeds, so foreign vendors do not receive this PID on the
    /// unicast path and fixing the discriminator arms nothing new there. The
    /// remaining exposure is the destination-less multicast copy, which keeps
    /// the PID by design. Do not widen emission on the back of this constant.
    ///
    /// THAT REMAINING EXPOSURE IS NOT THEORETICAL. A peer that reads the
    /// multicast copy can parse the CompleteTypeObject once the legal
    /// discriminator makes it round-trip, and then reject the match on a hash
    /// HDDS cannot yet produce exactly (the writer side reports
    /// INCOMPATIBLE_QOS and the reader receives nothing). Keeping the inert
    /// value avoids that. Arming the legal value is a package deal with a
    /// hash-exact TypeObject AND a multicast gate, and it is re-validated
    /// against the interoperability tests before it lands, not after.
    pub const TK_STRING8: Self = TypeIdentifier::Primitive(TypeKind::TK_STRING8);
    /// TypeIdentifier for an unbounded string16, held INERT as
    /// `Primitive(TypeKind::TK_STRING16)` for exactly the reasons given on
    /// `TK_STRING8` above. `TypeIdentifier::wstring(0)` is the legal value.
    pub const TK_STRING16: Self = TypeIdentifier::Primitive(TypeKind::TK_STRING16);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typeid_primitive() {
        let id = TypeIdentifier::primitive(TypeKind::TK_INT32);
        assert!(id.is_primitive());
        assert_eq!(id.get_primitive_kind(), Some(TypeKind::TK_INT32));
        assert!(!id.is_string());
        assert!(!id.is_hash_based());
    }

    #[test]
    fn test_typeid_string_small() {
        let id = TypeIdentifier::string(64);
        assert!(id.is_string());
        assert!(!id.is_primitive());
        assert!(!id.is_hash_based());
        assert_eq!(id, TypeIdentifier::StringSmall { bound: 64 });
    }

    #[test]
    fn test_typeid_string_large() {
        let id = TypeIdentifier::string(1024);
        assert!(id.is_string());
        assert_eq!(id, TypeIdentifier::StringLarge { bound: 1024 });
    }

    #[test]
    fn test_typeid_wstring() {
        let small = TypeIdentifier::wstring(128);
        let large = TypeIdentifier::wstring(512);

        assert!(small.is_string());
        assert!(large.is_string());
        assert_eq!(small, TypeIdentifier::WStringSmall { bound: 128 });
        assert_eq!(large, TypeIdentifier::WStringLarge { bound: 512 });
    }

    #[test]
    fn test_typeid_minimal_hash() {
        let hash = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        let id = TypeIdentifier::minimal(hash);

        assert!(id.is_hash_based());
        assert!(!id.is_primitive());
        assert!(!id.is_string());
        assert_eq!(id.equivalence_kind(), Some(EquivalenceKind::Minimal));
        assert_eq!(id.get_hash(), Some(&hash));
    }

    #[test]
    fn test_typeid_complete_hash() {
        let hash = EquivalenceHash::from_bytes([
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140,
        ]);
        let id = TypeIdentifier::complete(hash);

        assert!(id.is_hash_based());
        assert_eq!(id.equivalence_kind(), Some(EquivalenceKind::Complete));
        assert_eq!(id.get_hash(), Some(&hash));
    }

    #[test]
    fn test_typeid_strongly_connected() {
        let hash = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        let sc = StronglyConnectedComponentId {
            kind: EquivalenceKind::Minimal,
            sc_component_id: hash,
            scc_length: 3,
            scc_index: 1,
        };
        let id = TypeIdentifier::StronglyConnected(sc);

        assert!(id.is_strongly_connected());
        assert!(!id.is_primitive());
        assert!(!id.is_hash_based());
    }

    #[test]
    fn test_typeid_constants() {
        assert_eq!(
            TypeIdentifier::TK_BOOLEAN.get_primitive_kind(),
            Some(TypeKind::TK_BOOLEAN)
        );
        assert_eq!(
            TypeIdentifier::TK_INT32.get_primitive_kind(),
            Some(TypeKind::TK_INT32)
        );
        assert_eq!(
            TypeIdentifier::TK_FLOAT64.get_primitive_kind(),
            Some(TypeKind::TK_FLOAT64)
        );
    }

    #[test]
    fn test_typeid_equality() {
        let id1 = TypeIdentifier::primitive(TypeKind::TK_INT32);
        let id2 = TypeIdentifier::primitive(TypeKind::TK_INT32);
        let id3 = TypeIdentifier::primitive(TypeKind::TK_INT64);

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_typeid_debug() {
        let id = TypeIdentifier::primitive(TypeKind::TK_INT32);
        let debug_str = format!("{:?}", id);
        assert!(debug_str.contains("TypeId::Primitive"));
        assert!(debug_str.contains("TK_INT32"));
    }

    #[test]
    fn test_typeid_display() {
        let id1 = TypeIdentifier::primitive(TypeKind::TK_INT32);
        let id2 = TypeIdentifier::string(64);

        assert_eq!(format!("{}", id1), "TK_INT32");
        assert_eq!(format!("{}", id2), "string<64>");
    }

    #[test]
    fn test_equivalence_kind() {
        assert_eq!(EquivalenceKind::Minimal.to_u8(), 0x10);
        assert_eq!(EquivalenceKind::Complete.to_u8(), 0x20);
    }

    /// The string TypeIdentifier constants are deliberately INERT.
    ///
    /// Arming them (pointing them at the spec-legal `StringSmall`/`WStringSmall`
    /// forms) makes HDDS' `CompleteTypeObject` round-trip for a foreign reader
    /// of the destination-less multicast SEDP copy, which then rejects us on a
    /// hash HDDS cannot yet produce exactly, which breaks matching with that
    /// peer (see the guardrail on `TK_STRING8`). This test exists so the
    /// change cannot land again by accident; arming it is a package deal with a
    /// hash-exact TypeObject and a multicast gate, re-validated on the rig.
    #[test]
    fn string_type_identifier_constants_stay_inert() {
        assert!(
            matches!(
                TypeIdentifier::TK_STRING8,
                TypeIdentifier::Primitive(TypeKind::TK_STRING8)
            ),
            "TK_STRING8 was armed to a spec-legal form; see the guardrail on the constant"
        );
        assert!(
            matches!(
                TypeIdentifier::TK_STRING16,
                TypeIdentifier::Primitive(TypeKind::TK_STRING16)
            ),
            "TK_STRING16 was armed to a spec-legal form; see the guardrail on the constant"
        );
        // The legal forms stay reachable for every caller that needs a real
        // string TypeIdentifier; only the two constants are held back.
        assert!(matches!(
            TypeIdentifier::string(0),
            TypeIdentifier::StringSmall { bound: 0 }
        ));
        assert!(matches!(
            TypeIdentifier::wstring(0),
            TypeIdentifier::WStringSmall { bound: 0 }
        ));
    }
}

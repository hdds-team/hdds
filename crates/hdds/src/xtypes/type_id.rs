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
}

impl EquivalenceKind {
    pub const fn to_u8(self) -> u8 {
        match self {
            EquivalenceKind::Minimal => 0x10,
            EquivalenceKind::Complete => 0x20,
        }
    }
}

/// StronglyConnectedComponentId - for types with cyclic dependencies
///
/// Per DDS-XTypes v1.3 spec section 7.3.4.11:
/// Used when types reference each other (e.g., `Node { next: Option<Node> }`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StronglyConnectedComponentId {
    /// Hash of the strongly connected component
    pub sc_component_id: EquivalenceHash,

    /// Number of types in the component
    pub scc_length: i32,

    /// Index of this type within the component (0-based)
    pub scc_index: i32,
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

    /// Inline type object (hdds extension)
    ///
    /// Embeds a complete type definition directly in the parent TypeObject,
    /// making it self-contained without requiring hash-based registry lookups.
    /// Used by hdds_gen for nested struct/enum fields so that XTypes auto-decode
    /// can resolve the full type hierarchy from a single discovered TypeObject.
    Inline(Box<super::type_object::CompleteTypeObject>),
}

// Manual PartialEq/Eq/Hash because CompleteTypeObject does not derive Eq/Hash.
impl PartialEq for TypeIdentifier {
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
            (Self::Inline(a), Self::Inline(b)) => a == b,
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
            Self::Inline(_) => {
                // Inline objects are not expected to be used as map keys;
                // hash discriminant only (collisions are acceptable).
                0u8.hash(state);
            }
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

    /// Returns true if this is an inline type object
    pub const fn is_inline(&self) -> bool {
        matches!(self, TypeIdentifier::Inline(_))
    }

    /// Get the inline CompleteTypeObject if this is an Inline variant
    pub fn get_inline(&self) -> Option<&super::type_object::CompleteTypeObject> {
        match self {
            TypeIdentifier::Inline(obj) => Some(obj),
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
            TypeIdentifier::Inline(obj) => write!(f, "TypeId::Inline({:?})", obj),
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
            TypeIdentifier::Inline(_) => write!(f, "TypeId(Inline)"),
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
    /// TypeIdentifier for string8 (unbounded)
    pub const TK_STRING8: Self = TypeIdentifier::Primitive(TypeKind::TK_STRING8);
    /// TypeIdentifier for string16 (unbounded)
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
}

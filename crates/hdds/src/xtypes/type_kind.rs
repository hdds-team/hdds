// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TypeKind constants per OMG DDS-XTypes v1.3 specification
//!
//! Section 7.2.2: TypeKind enumeration

/// TypeKind identifies primitive and constructed types
///
/// Per DDS-XTypes v1.3 spec, TypeKind values are used to:
/// - Identify primitive types directly in TypeIdentifier
/// - Discriminate TypeObject unions
/// - Specify element types in collections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum TypeKind {
    // --- Primitive types (0x00-0x0F) ---
    /// No type (void, invalid)
    TK_NONE = 0x00,

    /// Boolean (1 byte)
    TK_BOOLEAN = 0x01,

    /// Unsigned 8-bit integer (byte, octet)
    TK_BYTE = 0x02,

    /// Signed 16-bit integer
    TK_INT16 = 0x03,

    /// Signed 32-bit integer
    TK_INT32 = 0x04,

    /// Signed 64-bit integer
    TK_INT64 = 0x05,

    /// Unsigned 16-bit integer
    TK_UINT16 = 0x06,

    /// Unsigned 32-bit integer
    TK_UINT32 = 0x07,

    /// Unsigned 64-bit integer
    TK_UINT64 = 0x08,

    /// 32-bit IEEE floating point
    TK_FLOAT32 = 0x09,

    /// 64-bit IEEE floating point
    TK_FLOAT64 = 0x0A,

    /// 128-bit IEEE floating point (not widely supported)
    TK_FLOAT128 = 0x0B,

    /// Signed 8-bit integer
    TK_INT8 = 0x0C,

    /// Unsigned 8-bit integer (alias for TK_BYTE)
    TK_UINT8 = 0x0D,

    /// Single character (8-bit)
    TK_CHAR8 = 0x10,

    /// Wide character (16-bit, UTF-16)
    TK_CHAR16 = 0x11,

    // --- String types ---
    /// 8-bit character string (unbounded or bounded)
    TK_STRING8 = 0x20,

    /// 16-bit character string (unbounded or bounded, UTF-16)
    TK_STRING16 = 0x21,

    // --- Constructed/Collection types ---
    /// Type alias (typedef)
    TK_ALIAS = 0x30,

    /// Enumeration
    TK_ENUM = 0x31,

    /// Bitmask
    TK_BITMASK = 0x32,

    /// Annotation (IDL 4.2)
    TK_ANNOTATION = 0x33,

    /// Structure (struct)
    TK_STRUCTURE = 0x40,

    /// Union (discriminated union)
    TK_UNION = 0x41,

    /// Bitset (IDL 4.2 bitfield struct)
    TK_BITSET = 0x42,

    /// Sequence (bounded or unbounded)
    TK_SEQUENCE = 0x50,

    /// Array (fixed-size, multi-dimensional)
    TK_ARRAY = 0x51,

    /// Map (key-value collection)
    TK_MAP = 0x52,
}

impl TypeKind {
    /// Returns true if this is a primitive type
    ///
    /// Primitive types can be used directly in TypeIdentifier without hashing
    pub const fn is_primitive(self) -> bool {
        matches!(
            self,
            TypeKind::TK_BOOLEAN
                | TypeKind::TK_BYTE
                | TypeKind::TK_INT16
                | TypeKind::TK_INT32
                | TypeKind::TK_INT64
                | TypeKind::TK_UINT16
                | TypeKind::TK_UINT32
                | TypeKind::TK_UINT64
                | TypeKind::TK_FLOAT32
                | TypeKind::TK_FLOAT64
                | TypeKind::TK_FLOAT128
                | TypeKind::TK_INT8
                | TypeKind::TK_UINT8
                | TypeKind::TK_CHAR8
                | TypeKind::TK_CHAR16
        )
    }

    /// Returns true if this is a string type
    pub const fn is_string(self) -> bool {
        matches!(self, TypeKind::TK_STRING8 | TypeKind::TK_STRING16)
    }

    /// Returns true if this is a collection type (sequence, array, map)
    pub const fn is_collection(self) -> bool {
        matches!(
            self,
            TypeKind::TK_SEQUENCE | TypeKind::TK_ARRAY | TypeKind::TK_MAP
        )
    }

    /// Returns true if this is a constructed type (struct, union, enum, etc.)
    pub const fn is_constructed(self) -> bool {
        matches!(
            self,
            TypeKind::TK_ALIAS
                | TypeKind::TK_ENUM
                | TypeKind::TK_BITMASK
                | TypeKind::TK_ANNOTATION
                | TypeKind::TK_STRUCTURE
                | TypeKind::TK_UNION
                | TypeKind::TK_BITSET
        )
    }

    /// Returns the size in bytes for primitive types, None for others
    pub const fn primitive_size(self) -> Option<usize> {
        match self {
            TypeKind::TK_BOOLEAN
            | TypeKind::TK_BYTE
            | TypeKind::TK_INT8
            | TypeKind::TK_UINT8
            | TypeKind::TK_CHAR8 => Some(1),
            TypeKind::TK_INT16 | TypeKind::TK_UINT16 | TypeKind::TK_CHAR16 => Some(2),
            TypeKind::TK_INT32 | TypeKind::TK_UINT32 | TypeKind::TK_FLOAT32 => Some(4),
            TypeKind::TK_INT64 | TypeKind::TK_UINT64 | TypeKind::TK_FLOAT64 => Some(8),
            TypeKind::TK_FLOAT128 => Some(16),
            _ => None,
        }
    }

    /// Return the canonical u8 representation for this TypeKind.
    ///
    /// This avoids unchecked casts and keeps the mapping explicit.
    pub const fn to_u8(self) -> u8 {
        match self {
            TypeKind::TK_NONE => 0x00,
            TypeKind::TK_BOOLEAN => 0x01,
            TypeKind::TK_BYTE => 0x02,
            TypeKind::TK_INT16 => 0x03,
            TypeKind::TK_INT32 => 0x04,
            TypeKind::TK_INT64 => 0x05,
            TypeKind::TK_UINT16 => 0x06,
            TypeKind::TK_UINT32 => 0x07,
            TypeKind::TK_UINT64 => 0x08,
            TypeKind::TK_FLOAT32 => 0x09,
            TypeKind::TK_FLOAT64 => 0x0A,
            TypeKind::TK_FLOAT128 => 0x0B,
            TypeKind::TK_INT8 => 0x0C,
            TypeKind::TK_UINT8 => 0x0D,
            TypeKind::TK_CHAR8 => 0x10,
            TypeKind::TK_CHAR16 => 0x11,
            TypeKind::TK_STRING8 => 0x20,
            TypeKind::TK_STRING16 => 0x21,
            TypeKind::TK_ALIAS => 0x30,
            TypeKind::TK_ENUM => 0x31,
            TypeKind::TK_BITMASK => 0x32,
            TypeKind::TK_ANNOTATION => 0x33,
            TypeKind::TK_STRUCTURE => 0x40,
            TypeKind::TK_UNION => 0x41,
            TypeKind::TK_BITSET => 0x42,
            TypeKind::TK_SEQUENCE => 0x50,
            TypeKind::TK_ARRAY => 0x51,
            TypeKind::TK_MAP => 0x52,
        }
    }

    /// Convert from u8 discriminator
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(TypeKind::TK_NONE),
            0x01 => Some(TypeKind::TK_BOOLEAN),
            0x02 => Some(TypeKind::TK_BYTE),
            0x03 => Some(TypeKind::TK_INT16),
            0x04 => Some(TypeKind::TK_INT32),
            0x05 => Some(TypeKind::TK_INT64),
            0x06 => Some(TypeKind::TK_UINT16),
            0x07 => Some(TypeKind::TK_UINT32),
            0x08 => Some(TypeKind::TK_UINT64),
            0x09 => Some(TypeKind::TK_FLOAT32),
            0x0A => Some(TypeKind::TK_FLOAT64),
            0x0B => Some(TypeKind::TK_FLOAT128),
            0x0C => Some(TypeKind::TK_INT8),
            0x0D => Some(TypeKind::TK_UINT8),
            0x10 => Some(TypeKind::TK_CHAR8),
            0x11 => Some(TypeKind::TK_CHAR16),
            0x20 => Some(TypeKind::TK_STRING8),
            0x21 => Some(TypeKind::TK_STRING16),
            0x30 => Some(TypeKind::TK_ALIAS),
            0x31 => Some(TypeKind::TK_ENUM),
            0x32 => Some(TypeKind::TK_BITMASK),
            0x33 => Some(TypeKind::TK_ANNOTATION),
            0x40 => Some(TypeKind::TK_STRUCTURE),
            0x41 => Some(TypeKind::TK_UNION),
            0x42 => Some(TypeKind::TK_BITSET),
            0x50 => Some(TypeKind::TK_SEQUENCE),
            0x51 => Some(TypeKind::TK_ARRAY),
            0x52 => Some(TypeKind::TK_MAP),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_typekind_primitives() {
        assert!(TypeKind::TK_BOOLEAN.is_primitive());
        assert!(TypeKind::TK_INT32.is_primitive());
        assert!(TypeKind::TK_FLOAT64.is_primitive());
        assert!(!TypeKind::TK_STRING8.is_primitive());
        assert!(!TypeKind::TK_STRUCTURE.is_primitive());
    }

    #[test]
    fn test_typekind_strings() {
        assert!(TypeKind::TK_STRING8.is_string());
        assert!(TypeKind::TK_STRING16.is_string());
        assert!(!TypeKind::TK_CHAR8.is_string());
    }

    #[test]
    fn test_typekind_collections() {
        assert!(TypeKind::TK_SEQUENCE.is_collection());
        assert!(TypeKind::TK_ARRAY.is_collection());
        assert!(TypeKind::TK_MAP.is_collection());
        assert!(!TypeKind::TK_STRUCTURE.is_collection());
    }

    #[test]
    fn test_typekind_constructed() {
        assert!(TypeKind::TK_STRUCTURE.is_constructed());
        assert!(TypeKind::TK_UNION.is_constructed());
        assert!(TypeKind::TK_ENUM.is_constructed());
        assert!(!TypeKind::TK_INT32.is_constructed());
    }

    #[test]
    fn test_typekind_primitive_size() {
        assert_eq!(TypeKind::TK_BOOLEAN.primitive_size(), Some(1));
        assert_eq!(TypeKind::TK_INT16.primitive_size(), Some(2));
        assert_eq!(TypeKind::TK_INT32.primitive_size(), Some(4));
        assert_eq!(TypeKind::TK_INT64.primitive_size(), Some(8));
        assert_eq!(TypeKind::TK_FLOAT128.primitive_size(), Some(16));
        assert_eq!(TypeKind::TK_STRING8.primitive_size(), None);
    }

    #[test]
    fn test_typekind_from_u8() {
        assert_eq!(TypeKind::from_u8(0x01), Some(TypeKind::TK_BOOLEAN));
        assert_eq!(TypeKind::from_u8(0x04), Some(TypeKind::TK_INT32));
        assert_eq!(TypeKind::from_u8(0x40), Some(TypeKind::TK_STRUCTURE));
        assert_eq!(TypeKind::from_u8(0xFF), None);
    }

    #[test]
    fn test_typekind_repr() {
        assert_eq!(TypeKind::TK_BOOLEAN.to_u8(), 0x01);
        assert_eq!(TypeKind::TK_INT32.to_u8(), 0x04);
        assert_eq!(TypeKind::TK_STRUCTURE.to_u8(), 0x40);
    }
}

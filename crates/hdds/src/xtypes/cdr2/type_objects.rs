// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Top-level TypeObject definitions
//!
//!
//! CompleteTypeObject and MinimalTypeObject are the top-level containers
//! for all XTypes type representations.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.5 (TypeObject)

use super::primitives::{decode_u8, encode_u8};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::TypeKind;

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CompleteTypeObject / MinimalTypeObject CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteTypeObject {
    // @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - dispatch to variant max_cdr2_size
    fn max_cdr2_size(&self) -> usize {
        1 + match self {
            CompleteTypeObject::Struct(s) => s.max_cdr2_size(),
            CompleteTypeObject::Union(u) => u.max_cdr2_size(),
            CompleteTypeObject::Enumerated(e) => e.max_cdr2_size(),
            CompleteTypeObject::Bitmask(b) => b.max_cdr2_size(),
            CompleteTypeObject::Bitset(b) => b.max_cdr2_size(),
            CompleteTypeObject::Sequence(s) => s.max_cdr2_size(),
            CompleteTypeObject::Array(a) => a.max_cdr2_size(),
            CompleteTypeObject::Map(m) => m.max_cdr2_size(),
            CompleteTypeObject::Alias(a) => a.max_cdr2_size(),
            CompleteTypeObject::Annotation(a) => a.max_cdr2_size(),
        }
    }

    // @audit-ok: two flat matches over the same 10 variants, no nesting -
    // discriminant byte then variant dispatch (measured cyclomatic 22,
    // cognitive 2).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        let discriminator: u8 = match self {
            CompleteTypeObject::Struct(_) => TypeKind::TK_STRUCTURE.to_u8(),
            CompleteTypeObject::Union(_) => TypeKind::TK_UNION.to_u8(),
            CompleteTypeObject::Enumerated(_) => TypeKind::TK_ENUM.to_u8(),
            CompleteTypeObject::Bitmask(_) => TypeKind::TK_BITMASK.to_u8(),
            CompleteTypeObject::Bitset(_) => TypeKind::TK_BITSET.to_u8(),
            CompleteTypeObject::Sequence(_) => TypeKind::TK_SEQUENCE.to_u8(),
            CompleteTypeObject::Array(_) => TypeKind::TK_ARRAY.to_u8(),
            CompleteTypeObject::Map(_) => TypeKind::TK_MAP.to_u8(),
            CompleteTypeObject::Alias(_) => TypeKind::TK_ALIAS.to_u8(),
            CompleteTypeObject::Annotation(_) => TypeKind::TK_ANNOTATION.to_u8(),
        };
        encode_u8(discriminator, dst, offset)?;
        match self {
            CompleteTypeObject::Struct(s) => s.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Union(u) => u.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Enumerated(e) => e.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Bitmask(b) => b.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Bitset(b) => b.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Sequence(s) => s.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Array(a) => a.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Map(m) => m.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Alias(a) => a.encode_cdr2_le_at(dst, offset),
            CompleteTypeObject::Annotation(a) => a.encode_cdr2_le_at(dst, offset),
        }
    }
}

impl Cdr2Decode for CompleteTypeObject {
    // @audit-ok: Simple pattern matching (cyclo 23, cogni 1) - discriminator dispatch to variant decoders
    /// Discriminator dispatcher for the @FINAL union `TypeObject` per XTypes
    /// v1.3 spec sec. 7.3.4.5. Each variant is independently APPENDABLE or FINAL
    /// per its own IDL declaration; DHEADER framing lives on the variant impls, not here.
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        // Spec discriminator labels -- see Cdr2Encode for the sec. 7.3.4.5
        // citation. Local const required because `match` patterns must
        // be const items, not `const fn` calls.
        const TK_STRUCTURE: u8 = TypeKind::TK_STRUCTURE.to_u8();
        const TK_UNION: u8 = TypeKind::TK_UNION.to_u8();
        const TK_ENUM: u8 = TypeKind::TK_ENUM.to_u8();
        const TK_BITMASK: u8 = TypeKind::TK_BITMASK.to_u8();
        const TK_BITSET: u8 = TypeKind::TK_BITSET.to_u8();
        const TK_SEQUENCE: u8 = TypeKind::TK_SEQUENCE.to_u8();
        const TK_ARRAY: u8 = TypeKind::TK_ARRAY.to_u8();
        const TK_MAP: u8 = TypeKind::TK_MAP.to_u8();
        const TK_ALIAS: u8 = TypeKind::TK_ALIAS.to_u8();
        const TK_ANNOTATION: u8 = TypeKind::TK_ANNOTATION.to_u8();

        let discriminator = decode_u8(src, offset)?;

        match discriminator {
            TK_STRUCTURE => Ok(CompleteTypeObject::Struct(
                CompleteStructType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_UNION => Ok(CompleteTypeObject::Union(
                CompleteUnionType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_ENUM => Ok(CompleteTypeObject::Enumerated(
                CompleteEnumeratedType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_BITMASK => Ok(CompleteTypeObject::Bitmask(
                CompleteBitmaskType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_BITSET => Ok(CompleteTypeObject::Bitset(
                CompleteBitsetType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_SEQUENCE => Ok(CompleteTypeObject::Sequence(
                CompleteSequenceType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_ARRAY => Ok(CompleteTypeObject::Array(
                CompleteArrayType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_MAP => Ok(CompleteTypeObject::Map(CompleteMapType::decode_cdr2_le_at(
                src, offset,
            )?)),
            TK_ALIAS => Ok(CompleteTypeObject::Alias(
                CompleteAliasType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_ANNOTATION => Ok(CompleteTypeObject::Annotation(
                CompleteAnnotationType::decode_cdr2_le_at(src, offset)?,
            )),
            _ => Err(CdrError::InvalidEncoding),
        }
    }
}

impl Cdr2Encode for MinimalTypeObject {
    // @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - dispatch to variant max_cdr2_size
    fn max_cdr2_size(&self) -> usize {
        1 + match self {
            MinimalTypeObject::Struct(s) => s.max_cdr2_size(),
            MinimalTypeObject::Union(u) => u.max_cdr2_size(),
            MinimalTypeObject::Enumerated(e) => e.max_cdr2_size(),
            MinimalTypeObject::Bitmask(b) => b.max_cdr2_size(),
            MinimalTypeObject::Bitset(b) => b.max_cdr2_size(),
            MinimalTypeObject::Sequence(s) => s.max_cdr2_size(),
            MinimalTypeObject::Array(a) => a.max_cdr2_size(),
            MinimalTypeObject::Map(m) => m.max_cdr2_size(),
            MinimalTypeObject::Alias(a) => a.max_cdr2_size(),
            // Other variants not handled (Annotation) - use conservative estimate
            _ => 4096,
        }
    }

    // @audit-ok: two flat matches over the same 10 variants, no nesting -
    // discriminant byte then variant dispatch (measured cyclomatic 22,
    // cognitive 2).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        let discriminator: u8 = match self {
            MinimalTypeObject::Struct(_) => TypeKind::TK_STRUCTURE.to_u8(),
            MinimalTypeObject::Union(_) => TypeKind::TK_UNION.to_u8(),
            MinimalTypeObject::Enumerated(_) => TypeKind::TK_ENUM.to_u8(),
            MinimalTypeObject::Bitmask(_) => TypeKind::TK_BITMASK.to_u8(),
            MinimalTypeObject::Bitset(_) => TypeKind::TK_BITSET.to_u8(),
            MinimalTypeObject::Sequence(_) => TypeKind::TK_SEQUENCE.to_u8(),
            MinimalTypeObject::Array(_) => TypeKind::TK_ARRAY.to_u8(),
            MinimalTypeObject::Map(_) => TypeKind::TK_MAP.to_u8(),
            MinimalTypeObject::Alias(_) => TypeKind::TK_ALIAS.to_u8(),
            MinimalTypeObject::Annotation(_) => TypeKind::TK_ANNOTATION.to_u8(),
        };
        encode_u8(discriminator, dst, offset)?;
        match self {
            MinimalTypeObject::Struct(s) => s.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Union(u) => u.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Enumerated(e) => e.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Bitmask(b) => b.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Bitset(b) => b.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Sequence(s) => s.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Array(a) => a.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Map(m) => m.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Alias(a) => a.encode_cdr2_le_at(dst, offset),
            MinimalTypeObject::Annotation(a) => a.encode_cdr2_le_at(dst, offset),
        }
    }
}

impl Cdr2Decode for MinimalTypeObject {
    // @audit-ok: Simple pattern matching (cyclo 23, cogni 1) - discriminator dispatch to variant decoders
    /// Discriminator dispatcher for the @FINAL union `TypeObject` per XTypes
    /// v1.3 spec sec. 7.3.4.5. Each variant is independently APPENDABLE or FINAL
    /// per its own IDL declaration; DHEADER framing lives on the variant
    /// impls.
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        const TK_STRUCTURE: u8 = TypeKind::TK_STRUCTURE.to_u8();
        const TK_UNION: u8 = TypeKind::TK_UNION.to_u8();
        const TK_ENUM: u8 = TypeKind::TK_ENUM.to_u8();
        const TK_BITMASK: u8 = TypeKind::TK_BITMASK.to_u8();
        const TK_BITSET: u8 = TypeKind::TK_BITSET.to_u8();
        const TK_SEQUENCE: u8 = TypeKind::TK_SEQUENCE.to_u8();
        const TK_ARRAY: u8 = TypeKind::TK_ARRAY.to_u8();
        const TK_MAP: u8 = TypeKind::TK_MAP.to_u8();
        const TK_ALIAS: u8 = TypeKind::TK_ALIAS.to_u8();
        const TK_ANNOTATION: u8 = TypeKind::TK_ANNOTATION.to_u8();

        let discriminator = decode_u8(src, offset)?;

        match discriminator {
            TK_STRUCTURE => Ok(MinimalTypeObject::Struct(
                MinimalStructType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_UNION => Ok(MinimalTypeObject::Union(
                MinimalUnionType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_ENUM => Ok(MinimalTypeObject::Enumerated(
                MinimalEnumeratedType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_BITMASK => Ok(MinimalTypeObject::Bitmask(
                MinimalBitmaskType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_BITSET => Ok(MinimalTypeObject::Bitset(
                MinimalBitsetType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_SEQUENCE => Ok(MinimalTypeObject::Sequence(
                MinimalSequenceType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_ARRAY => Ok(MinimalTypeObject::Array(
                MinimalArrayType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_MAP => Ok(MinimalTypeObject::Map(MinimalMapType::decode_cdr2_le_at(
                src, offset,
            )?)),
            TK_ALIAS => Ok(MinimalTypeObject::Alias(
                MinimalAliasType::decode_cdr2_le_at(src, offset)?,
            )),
            TK_ANNOTATION => Ok(MinimalTypeObject::Annotation(
                MinimalAnnotationType::decode_cdr2_le_at(src, offset)?,
            )),
            _ => Err(CdrError::InvalidEncoding),
        }
    }
}

// ============================================================================
// EquivalenceHash Integration
// ============================================================================

/// Serialize the OUTER `@appendable union TypeObject` and MD5-hash it per
/// XTypes v1.3 sec. 7.3.4.8.
///
/// The EquivalenceHash is defined over the OUTER `TypeObject` union, NOT the
/// inner `CompleteTypeObject` / `MinimalTypeObject`:
///
/// ```text
/// @appendable union TypeObject switch (octet) {
///   case EK_COMPLETE: CompleteTypeObject  complete;
///   case EK_MINIMAL:  MinimalTypeObject   minimal;
/// };
/// ```
///
/// As an APPENDABLE union the XCDR2 stream is: a 4-byte DHEADER (the size of
/// the discriminator + selected member), the discriminator octet (`EK_COMPLETE`
/// / `EK_MINIMAL`), then the inner TypeObject. Hashing this single, wrapped
/// stream (rather than the bare inner union) is what makes the resulting hash
/// match other spec-conformant vendors, and it also fixes the inner struct
/// alignment (the inner TK discriminator lands at offset 5, so `struct_flags`
/// needs no leading pad byte).
#[cfg(feature = "xtypes")]
fn wrapped_type_object_hash<F>(
    ek: u8,
    max_inner: usize,
    encode_inner: F,
) -> Result<crate::xtypes::EquivalenceHash, CdrError>
where
    F: Fn(&mut [u8], &mut usize) -> Result<(), CdrError>,
{
    use super::dheader::encode_dheader_at;
    // 4 (DHEADER) + 1 (EK octet) + inner TypeObject body.
    let mut size = max_inner.checked_add(5).ok_or(CdrError::DataTooLarge)?;
    let mut buf = Vec::new();
    loop {
        buf.try_reserve_exact(size - buf.len())
            .map_err(|_| CdrError::DataTooLarge)?;
        buf.resize(size, 0);
        // Inline collection identifiers are recursive, so the initial size
        // estimate may be too small. Restart the entire stream on each retry
        // to preserve alignment and recompute every DHEADER.
        let mut offset = 0usize;
        match encode_dheader_at(&mut buf, &mut offset, |dst, off| {
            encode_u8(ek, dst, off)?;
            encode_inner(dst, off)
        }) {
            Ok(()) => return Ok(crate::xtypes::EquivalenceHash::compute(&buf[..offset])),
            Err(CdrError::BufferTooSmall) => {
                size = size.checked_mul(2).ok_or(CdrError::DataTooLarge)?;
            }
            Err(err) => return Err(err),
        }
    }
}

impl CompleteTypeObject {
    /// Compute the EquivalenceHash for this TypeObject
    ///
    /// Per DDS-XTypes v1.3 spec section 7.3.4.8:
    /// 1. Serialize TypeObject to CDR2 format
    /// 2. Compute MD5 hash (16 bytes)
    /// 3. Truncate to 14 bytes
    ///
    /// # Returns
    ///
    /// `Ok(EquivalenceHash)` on success, `Err(CdrError)` on serialization failure
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::xtypes::{CompleteTypeObject, CompleteStructType};
    ///
    /// let type_obj = CompleteTypeObject::Struct(/* ... */);
    /// let hash = type_obj.compute_equivalence_hash()?;
    /// ```
    #[cfg(feature = "xtypes")]
    pub fn compute_equivalence_hash(&self) -> Result<crate::xtypes::EquivalenceHash, CdrError> {
        // Hash the OUTER TypeObject union (DHEADER + EK_COMPLETE + inner), per
        // XTypes v1.3 sec. 7.3.4.8 -- see `wrapped_type_object_hash`.
        wrapped_type_object_hash(
            crate::xtypes::discriminators::EK_COMPLETE,
            self.max_cdr2_size(),
            |dst, off| self.encode_cdr2_le_at(dst, off),
        )
    }

    /// DEBUG-ONLY: raw inner CDR2-LE bytes that feed `compute_equivalence_hash`
    /// (no outer `TypeObject` union wrapper). Used by the dds-xtypes interop
    /// driver `HDDS_TYPEID_DEBUG` falsification path.
    #[doc(hidden)]
    #[cfg(feature = "xtypes")]
    pub fn debug_inner_cdr2_le(&self) -> Result<Vec<u8>, CdrError> {
        let mut buf = vec![0u8; self.max_cdr2_size()];
        let len = self.encode_cdr2_le(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Compute the EquivalenceHash (fallback when feature "xtypes" disabled)
    #[cfg(not(feature = "xtypes"))]
    pub fn compute_equivalence_hash(&self) -> Result<crate::xtypes::EquivalenceHash, CdrError> {
        Ok(crate::xtypes::EquivalenceHash::zero())
    }
}

impl MinimalTypeObject {
    /// Compute the EquivalenceHash for this TypeObject
    ///
    /// Per DDS-XTypes v1.3 spec section 7.3.4.8:
    /// 1. Serialize TypeObject to CDR2 format
    /// 2. Compute MD5 hash (16 bytes)
    /// 3. Truncate to 14 bytes
    ///
    /// # Returns
    ///
    /// `Ok(EquivalenceHash)` on success, `Err(CdrError)` on serialization failure
    ///
    /// # Example
    ///
    /// ```ignore
    /// use hdds::xtypes::{MinimalTypeObject, MinimalStructType};
    ///
    /// let type_obj = MinimalTypeObject::Struct(/* ... */);
    /// let hash = type_obj.compute_equivalence_hash()?;
    /// ```
    #[cfg(feature = "xtypes")]
    pub fn compute_equivalence_hash(&self) -> Result<crate::xtypes::EquivalenceHash, CdrError> {
        // Hash the OUTER TypeObject union (DHEADER + EK_MINIMAL + inner), per
        // XTypes v1.3 sec. 7.3.4.8 -- see `wrapped_type_object_hash`.
        wrapped_type_object_hash(
            crate::xtypes::discriminators::EK_MINIMAL,
            self.max_cdr2_size(),
            |dst, off| self.encode_cdr2_le_at(dst, off),
        )
    }

    /// DEBUG-ONLY: raw inner CDR2-LE bytes that feed `compute_equivalence_hash`
    /// (no outer `TypeObject` union wrapper). Used by the dds-xtypes interop
    /// driver `HDDS_TYPEID_DEBUG` falsification path.
    #[doc(hidden)]
    #[cfg(feature = "xtypes")]
    pub fn debug_inner_cdr2_le(&self) -> Result<Vec<u8>, CdrError> {
        let mut buf = vec![0u8; self.max_cdr2_size()];
        let len = self.encode_cdr2_le(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Compute the EquivalenceHash (fallback when feature "xtypes" disabled)
    #[cfg(not(feature = "xtypes"))]
    pub fn compute_equivalence_hash(&self) -> Result<crate::xtypes::EquivalenceHash, CdrError> {
        Ok(crate::xtypes::EquivalenceHash::zero())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::primitives::{align_offset, padding_for_alignment};
    use super::*;
    use crate::xtypes::{EquivalenceHash, TypeIdentifier, TypeKind};

    #[test]
    fn test_align_offset() {
        assert_eq!(align_offset(0, 4), 0);
        assert_eq!(align_offset(1, 4), 4);
        assert_eq!(align_offset(2, 4), 4);
        assert_eq!(align_offset(3, 4), 4);
        assert_eq!(align_offset(4, 4), 4);
        assert_eq!(align_offset(5, 4), 8);
    }

    #[test]
    fn test_padding_for_alignment() {
        assert_eq!(padding_for_alignment(0, 4), 0);
        assert_eq!(padding_for_alignment(1, 4), 3);
        assert_eq!(padding_for_alignment(2, 4), 2);
        assert_eq!(padding_for_alignment(3, 4), 1);
        assert_eq!(padding_for_alignment(4, 4), 0);
    }

    #[test]
    fn test_typeid_primitive_roundtrip() {
        let type_id = TypeIdentifier::Primitive(TypeKind::TK_INT32);
        let mut buf = vec![0u8; 256];

        let encoded_len = type_id
            .encode_cdr2_le(&mut buf)
            .expect("CDR2 internal TypeIdentifier (Primitive): encode should succeed");
        let (decoded, _used) = TypeIdentifier::decode_cdr2_le(&buf[..encoded_len])
            .expect("CDR2 internal TypeIdentifier (Primitive): decode should succeed");

        assert_eq!(decoded, type_id);
    }

    #[test]
    fn test_typeid_string_small_roundtrip() {
        let type_id = TypeIdentifier::StringSmall { bound: 64 };
        let mut buf = vec![0u8; 256];

        let encoded_len = type_id
            .encode_cdr2_le(&mut buf)
            .expect("CDR2 internal TypeIdentifier (StringSmall): encode should succeed");
        let (decoded, _used) = TypeIdentifier::decode_cdr2_le(&buf[..encoded_len])
            .expect("CDR2 internal TypeIdentifier (StringSmall): decode should succeed");

        assert_eq!(decoded, type_id);
    }

    #[test]
    fn test_typeid_minimal_hash_roundtrip() {
        let hash = EquivalenceHash::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
        let type_id = TypeIdentifier::Minimal(hash);
        let mut buf = vec![0u8; 256];

        let encoded_len = type_id
            .encode_cdr2_le(&mut buf)
            .expect("CDR2 internal TypeIdentifier (Minimal): encode should succeed");
        let (decoded, _used) = TypeIdentifier::decode_cdr2_le(&buf[..encoded_len])
            .expect("CDR2 internal TypeIdentifier (Minimal): decode should succeed");

        assert_eq!(decoded, type_id);
    }

    #[test]
    fn test_struct_type_flag_roundtrip() {
        let flag = StructTypeFlag::IS_FINAL;
        let mut buf = vec![0u8; 16];

        let encoded_len = flag
            .encode_cdr2_le(&mut buf)
            .expect("CDR2 internal StructTypeFlag: encode should succeed");
        let (decoded, _used) = StructTypeFlag::decode_cdr2_le(&buf[..encoded_len])
            .expect("CDR2 internal StructTypeFlag: decode should succeed");

        assert_eq!(decoded.0, flag.0);
    }

    #[test]
    fn test_member_flag_roundtrip() {
        let flag = MemberFlag::IS_KEY;
        let mut buf = vec![0u8; 16];

        let encoded_len = flag
            .encode_cdr2_le(&mut buf)
            .expect("CDR2 internal MemberFlag: encode should succeed");
        let (decoded, _used) = MemberFlag::decode_cdr2_le(&buf[..encoded_len])
            .expect("CDR2 internal MemberFlag: decode should succeed");

        assert_eq!(decoded.0, flag.0);
    }

    #[test]
    fn test_common_struct_member_roundtrip() {
        let member = CommonStructMember {
            member_id: 42,
            member_flags: MemberFlag::IS_KEY,
            member_type_id: TypeIdentifier::TK_INT64,
        };

        let mut buf = vec![0u8; 128];
        let encoded_len = member
            .encode_cdr2_le(&mut buf)
            .expect("CDR2 internal CommonStructMember: encode should succeed");
        let (decoded, _used) = CommonStructMember::decode_cdr2_le(&buf[..encoded_len])
            .expect("CDR2 internal CommonStructMember: decode should succeed");

        assert_eq!(decoded.member_id, 42);
        assert_eq!(decoded.member_flags.0, MemberFlag::IS_KEY.0);
        assert_eq!(decoded.member_type_id, TypeIdentifier::TK_INT64);
    }

    #[test]
    #[cfg(feature = "xtypes")]
    fn test_equivalence_hash_struct_vs_enum() {
        // Create a struct TypeObject
        let struct_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("MyStruct"),
            },
            member_seq: vec![],
        });

        // Create an enum TypeObject
        let enum_obj = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: 16,
                detail: CompleteTypeDetail::new("MyEnum"),
            },
            literal_seq: vec![CompleteEnumeratedLiteral {
                common: CommonEnumeratedLiteral {
                    value: 0,
                    flags: EnumeratedLiteralFlag::empty(),
                },
                detail: CompleteMemberDetail::new("VALUE"),
            }],
        });

        // Compute hashes
        let hash_struct = struct_obj
            .compute_equivalence_hash()
            .expect("CDR2 internal: struct equivalence hash computation should succeed");
        let hash_enum = enum_obj
            .compute_equivalence_hash()
            .expect("CDR2 internal: enum equivalence hash computation should succeed");

        // Verify different type kinds = different hashes
        assert_ne!(hash_struct, hash_enum);
    }

    #[test]
    #[cfg(feature = "xtypes")]
    fn test_shapetype_complete_roundtrip() {
        use crate::xtypes::discriminators::{TI_PLAIN_SEQUENCE_SMALL, TI_STRING8_SMALL};
        use crate::xtypes::type_id::{PlainCollectionHeader, PlainSequenceSElemDefn};
        use crate::xtypes::EquivalenceKind;

        // Structurally-correct ShapeType CompleteTypeObject for the OMG
        // shape.idl:
        //   @appendable struct ShapeType {
        //     @key string<128> color;
        //     int32 x; int32 y; int32 shapesize;
        //     sequence<uint8> additional_payload_size;
        //   };
        //
        // Wire encoding per OMG DDS-XTypes v1.3 sec. 7.3.4.4 / sec. 7.3.4.5, matching
        // the CompleteTypeObject a vendor codegen emits for this IDL:
        //   - color: TI_STRING8_SMALL (0x70) + bound 128, NOT a bare primitive
        //     octet (the old TK_STRING8 = 0x20 form is non-spec and fails the
        //     strict decoder; see the TK_STRING8 guardrail in type_id.rs).
        //   - additional_payload_size: TI_PLAIN_SEQUENCE_SMALL (0x80),
        //     unbounded (bound 0), element TK_UINT8 (0x0D), NOT a scalar uint8.
        //   - every member carries TRY_CONSTRUCT1 (0x01 = DISCARD, the default
        //     TryConstructKind); color additionally carries IS_KEY (0x20).
        // The flag newtypes implement no BitOr, so combine via the inner u16.
        let key_member = MemberFlag(MemberFlag::IS_KEY.0 | MemberFlag::TRY_CONSTRUCT1.0);
        let plain_member = MemberFlag::TRY_CONSTRUCT1;

        let int32_member = |member_id: u32, name: &str| CompleteStructMember {
            common: CommonStructMember {
                member_id,
                member_flags: plain_member,
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new(name),
        };

        let payload_seq = TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
            header: PlainCollectionHeader {
                // Spec-canonical for a primitive element is EK_BOTH (0xF3);
                // HDDS has no EK_BOTH wire variant yet, so Complete (0xF2) is
                // used. The element identifier (uint8) is identical under
                // either equivalence, so this stays structurally faithful.
                equiv_kind: EquivalenceKind::Complete,
                element_flags: CollectionElementFlag(MemberFlag::TRY_CONSTRUCT1.0),
            },
            bound: 0, // unbounded sequence<uint8>
            element_identifier: Box::new(TypeIdentifier::TK_UINT8),
        });

        let obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("ShapeType"),
            },
            member_seq: vec![
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 0,
                        member_flags: key_member,
                        member_type_id: TypeIdentifier::StringSmall { bound: 128 },
                    },
                    detail: CompleteMemberDetail::new("color"),
                },
                int32_member(1, "x"),
                int32_member(2, "y"),
                int32_member(3, "shapesize"),
                CompleteStructMember {
                    common: CommonStructMember {
                        member_id: 4,
                        member_flags: plain_member,
                        member_type_id: payload_seq,
                    },
                    detail: CompleteMemberDetail::new("additional_payload_size"),
                },
            ],
        });

        // 1) Encode then decode must SUCCEED. The previous TK_STRING8 (0x20)
        //    form failed the spec-strict decoder; this structurally-correct
        //    form must round-trip.
        let mut buf = vec![0u8; obj.max_cdr2_size()];
        let len = obj
            .encode_cdr2_le(&mut buf)
            .expect("ShapeType CompleteTypeObject must encode");
        let (decoded, used) = CompleteTypeObject::decode_cdr2_le(&buf[..len])
            .expect("ShapeType CompleteTypeObject must round-trip (decode)");

        // 2) Decode consumes exactly the encoded bytes and reproduces the
        //    original structure (all 5 members, types and flags preserved).
        assert_eq!(used, len, "decode must consume all encoded bytes");
        assert_eq!(decoded, obj, "decoded ShapeType must equal the original");

        // 3) Re-encode determinism.
        let mut buf2 = vec![0u8; decoded.max_cdr2_size()];
        let len2 = decoded.encode_cdr2_le(&mut buf2).expect("re-encode");
        assert_eq!(&buf[..len], &buf2[..len2], "round-trip bytes differ");

        // 4) Wire shape: color serializes as TI_STRING8_SMALL (0x70) + bound
        //    128, and the payload as TI_PLAIN_SEQUENCE_SMALL (0x80).
        assert!(
            buf[..len].windows(2).any(|w| w == [TI_STRING8_SMALL, 128]),
            "color must encode as TI_STRING8_SMALL(0x70)+bound 128"
        );
        assert!(
            buf[..len].contains(&TI_PLAIN_SEQUENCE_SMALL),
            "additional_payload_size must encode as TI_PLAIN_SEQUENCE_SMALL(0x80)"
        );

        // 5) The CompleteTypeObject hashes without error and deterministically.
        //    The EquivalenceHash is a local cache key; it need not match any
        //    peer vendor's hash for the same type (cross-vendor matching is
        //    structural, not hash-based).
        let h1 = obj.compute_equivalence_hash().expect("hash");
        let h2 = obj.compute_equivalence_hash().expect("hash");
        assert_eq!(h1, h2, "EquivalenceHash must be deterministic");
    }
}

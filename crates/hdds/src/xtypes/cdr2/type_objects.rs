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

use super::helpers::encode_fields_sequential;
use super::primitives::{decode_u8, encode_u8};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CompleteTypeObject / MinimalTypeObject CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteTypeObject {
    // @audit-ok: Closures with pattern matching (cyclo 24, cogni 4) - discriminant encoder + variant dispatcher
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        // Closure cognitive 2: Simple match variant->discriminant
        let mut encode_discriminator = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            let discriminator: u8 = match self {
                CompleteTypeObject::Struct(_) => 0x01,
                CompleteTypeObject::Union(_) => 0x02,
                CompleteTypeObject::Enumerated(_) => 0x03,
                CompleteTypeObject::Bitmask(_) => 0x04,
                CompleteTypeObject::Bitset(_) => 0x05,
                CompleteTypeObject::Sequence(_) => 0x06,
                CompleteTypeObject::Array(_) => 0x07,
                CompleteTypeObject::Map(_) => 0x08,
                CompleteTypeObject::Alias(_) => 0x09,
                CompleteTypeObject::Annotation(_) => 0x0A,
            };
            encode_u8(discriminator, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_variant = |buf: &mut [u8]| -> Result<usize, CdrError> {
            match self {
                CompleteTypeObject::Struct(s) => s.encode_cdr2_le(buf),
                CompleteTypeObject::Union(u) => u.encode_cdr2_le(buf),
                CompleteTypeObject::Enumerated(e) => e.encode_cdr2_le(buf),
                CompleteTypeObject::Bitmask(b) => b.encode_cdr2_le(buf),
                CompleteTypeObject::Bitset(b) => b.encode_cdr2_le(buf),
                CompleteTypeObject::Sequence(s) => s.encode_cdr2_le(buf),
                CompleteTypeObject::Array(a) => a.encode_cdr2_le(buf),
                CompleteTypeObject::Map(m) => m.encode_cdr2_le(buf),
                CompleteTypeObject::Alias(a) => a.encode_cdr2_le(buf),
                CompleteTypeObject::Annotation(a) => a.encode_cdr2_le(buf),
            }
        };

        encode_fields_sequential(dst, &mut [&mut encode_discriminator, &mut encode_variant])
    }

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
}

impl Cdr2Decode for CompleteTypeObject {
    // @audit-ok: Simple pattern matching (cyclo 23, cogni 1) - discriminator dispatch to variant decoders
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let discriminator = decode_u8(src, &mut offset)?;

        match discriminator {
            0x01 => {
                // Struct
                let (s, used) = CompleteStructType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Struct(s), offset))
            }
            0x02 => {
                // Union
                let (u, used) = CompleteUnionType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Union(u), offset))
            }
            0x03 => {
                // Enumerated
                let (e, used) = CompleteEnumeratedType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Enumerated(e), offset))
            }
            0x04 => {
                // Bitmask
                let (b, used) = CompleteBitmaskType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Bitmask(b), offset))
            }
            0x05 => {
                // Bitset
                let (b, used) = CompleteBitsetType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Bitset(b), offset))
            }
            0x06 => {
                // Sequence
                let (s, used) = CompleteSequenceType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Sequence(s), offset))
            }
            0x07 => {
                // Array
                let (a, used) = CompleteArrayType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Array(a), offset))
            }
            0x08 => {
                // Map
                let (m, used) = CompleteMapType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Map(m), offset))
            }
            0x09 => {
                // Alias
                let (a, used) = CompleteAliasType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Alias(a), offset))
            }
            0x0A => {
                // Annotation
                let (a, used) = CompleteAnnotationType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((CompleteTypeObject::Annotation(a), offset))
            }
            _ => Err(CdrError::InvalidEncoding),
        }
    }
}

impl Cdr2Encode for MinimalTypeObject {
    // @audit-ok: Closures with pattern matching (cyclo 24, cogni 4) - discriminant encoder + variant dispatcher
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        // Closure cognitive 2: Simple match variant->discriminant
        let mut encode_discriminator = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            let discriminator: u8 = match self {
                MinimalTypeObject::Struct(_) => 0x01,
                MinimalTypeObject::Union(_) => 0x02,
                MinimalTypeObject::Enumerated(_) => 0x03,
                MinimalTypeObject::Bitmask(_) => 0x04,
                MinimalTypeObject::Bitset(_) => 0x05,
                MinimalTypeObject::Sequence(_) => 0x06,
                MinimalTypeObject::Array(_) => 0x07,
                MinimalTypeObject::Map(_) => 0x08,
                MinimalTypeObject::Alias(_) => 0x09,
                MinimalTypeObject::Annotation(_) => 0x0A,
            };
            encode_u8(discriminator, buf, &mut local)?;
            Ok(local)
        };
        // Closure cognitive 2: Dispatch to variant encoders
        let mut encode_variant = |buf: &mut [u8]| -> Result<usize, CdrError> {
            match self {
                MinimalTypeObject::Struct(s) => s.encode_cdr2_le(buf),
                MinimalTypeObject::Union(u) => u.encode_cdr2_le(buf),
                MinimalTypeObject::Enumerated(e) => e.encode_cdr2_le(buf),
                MinimalTypeObject::Bitmask(b) => b.encode_cdr2_le(buf),
                MinimalTypeObject::Bitset(b) => b.encode_cdr2_le(buf),
                MinimalTypeObject::Sequence(s) => s.encode_cdr2_le(buf),
                MinimalTypeObject::Array(a) => a.encode_cdr2_le(buf),
                MinimalTypeObject::Map(m) => m.encode_cdr2_le(buf),
                MinimalTypeObject::Alias(a) => a.encode_cdr2_le(buf),
                MinimalTypeObject::Annotation(a) => a.encode_cdr2_le(buf),
            }
        };

        encode_fields_sequential(dst, &mut [&mut encode_discriminator, &mut encode_variant])
    }

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
}

impl Cdr2Decode for MinimalTypeObject {
    // @audit-ok: Simple pattern matching (cyclo 23, cogni 1) - discriminator dispatch to variant decoders
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let discriminator = decode_u8(src, &mut offset)?;

        match discriminator {
            0x01 => {
                // Struct
                let (s, used) = MinimalStructType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Struct(s), offset))
            }
            0x02 => {
                // Union
                let (u, used) = MinimalUnionType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Union(u), offset))
            }
            0x03 => {
                // Enumerated
                let (e, used) = MinimalEnumeratedType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Enumerated(e), offset))
            }
            0x04 => {
                // Bitmask
                let (b, used) = MinimalBitmaskType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Bitmask(b), offset))
            }
            0x05 => {
                // Bitset
                let (b, used) = MinimalBitsetType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Bitset(b), offset))
            }
            0x06 => {
                // Sequence
                let (s, used) = MinimalSequenceType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Sequence(s), offset))
            }
            0x07 => {
                // Array
                let (a, used) = MinimalArrayType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Array(a), offset))
            }
            0x08 => {
                // Map
                let (m, used) = MinimalMapType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Map(m), offset))
            }
            0x09 => {
                // Alias
                let (a, used) = MinimalAliasType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Alias(a), offset))
            }
            0x0A => {
                // Annotation
                let (a, used) = MinimalAnnotationType::decode_cdr2_le(&src[offset..])?;
                offset += used;
                Ok((MinimalTypeObject::Annotation(a), offset))
            }
            _ => Err(CdrError::InvalidEncoding),
        }
    }
}

// ============================================================================
// EquivalenceHash Integration
// ============================================================================

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
        let mut buf = vec![0u8; self.max_cdr2_size()];
        let len = self.encode_cdr2_le(&mut buf)?;
        Ok(crate::xtypes::EquivalenceHash::compute(&buf[..len]))
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
        let mut buf = vec![0u8; self.max_cdr2_size()];
        let len = self.encode_cdr2_le(&mut buf)?;
        Ok(crate::xtypes::EquivalenceHash::compute(&buf[..len]))
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
}

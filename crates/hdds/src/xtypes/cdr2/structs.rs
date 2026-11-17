// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Struct type definitions
//!
//! Complete and Minimal struct types, headers, and members.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.1 (Struct Types)

use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::members::{
    decode_complete_struct_member_internal, decode_minimal_struct_member_internal,
};
use super::primitives::{decode_u16, encode_u16, encode_vec};
use super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::{TypeIdentifier, TypeKind};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// base_type: a TypeIdentifier, not an @optional
// ============================================================================

/// Encode a struct header's `base_type`.
///
/// DDS-XTypes 1.3 Annex B (dds-xtypes_typeobject.idl, `CompleteStructHeader`
/// and `MinimalStructHeader`, spec text lines 12776-12787) declares
/// `TypeIdentifier base_type;` with no `@optional`: the identifier itself is
/// serialized, and a struct without a base type carries `TK_NONE`. The model
/// keeps `Option<TypeIdentifier>`, `None` standing for that `TK_NONE`. Writing
/// it as an @optional (a presence octet, then the identifier) happened to give
/// the same single 0x00 octet for `None`, and shifted every derived struct by
/// one octet in front of its base identifier.
fn encode_base_type(
    base_type: Option<&TypeIdentifier>,
    dst: &mut [u8],
    offset: &mut usize,
) -> Result<(), CdrError> {
    match base_type {
        Some(id) => id.encode_cdr2_le_at(dst, offset),
        None => TypeIdentifier::Primitive(TypeKind::TK_NONE).encode_cdr2_le_at(dst, offset),
    }
}

/// Decode a struct header's `base_type` (see [`encode_base_type`]): `TK_NONE`
/// is "no base type".
fn decode_base_type(src: &[u8], offset: &mut usize) -> Result<Option<TypeIdentifier>, CdrError> {
    match decode_type_identifier_internal(src, offset)? {
        TypeIdentifier::Primitive(TypeKind::TK_NONE) => Ok(None),
        id => Ok(Some(id)),
    }
}

// ============================================================================
// StructHeader CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteStructHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + 32 + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_base_type(self.base_type.as_ref(), dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CompleteStructHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_struct_header_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteStructHeader decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_complete_struct_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteStructHeader, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let base_type = decode_base_type(src, offset)?;
        let detail =
            super::helpers::decode_detail_with_reencoding::<CompleteTypeDetail>(src, offset)?;
        Ok(CompleteStructHeader { base_type, detail })
    })
}

impl Cdr2Encode for MinimalStructHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + 32 + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_base_type(self.base_type.as_ref(), dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for MinimalStructHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_struct_header_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalStructHeader decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_minimal_struct_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalStructHeader, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let base_type = decode_base_type(src, offset)?;
        // MinimalTypeDetail is empty (encodes as 0 bytes)
        let detail =
            super::helpers::decode_detail_with_reencoding::<MinimalTypeDetail>(src, offset)?;
        Ok(MinimalStructHeader { base_type, detail })
    })
}

// ============================================================================
// CompleteStructType / MinimalStructType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteStructType {
    fn max_cdr2_size(&self) -> usize {
        super::helpers::max_size_type_with_members(&self.header, &self.member_seq)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.struct_flags.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        // XTypes v1.3 sec. 7.4.3.5.3: a sequence whose element type is itself
        // DHEADER-delimited (CompleteStructMember is @APPENDABLE) is preceded
        // by its own DHEADER. The CompleteStructMemberSeq is "Ordered by the
        // member_index" (DDS-XTypes v1.3 TypeObject IDL), i.e. declaration
        // order -- NOT sorted by member_id. This differs from the
        // MinimalStructMemberSeq (sorted by member_id). For a @mutable struct
        // with non-monotonic explicit IDs (e.g. struct_m3 = {x1=1, x3=3, x2=2})
        // the Complete member order must therefore preserve the source order so
        // the EquivalenceHash matches conformant implementations.
        // The member_seq is already in declaration order from the builder.
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec(&self.member_seq, dst, offset, |member, dst, offset| {
                member.encode_cdr2_le_at(dst, offset)
            })
        })?;
        Ok(())
    }
}

impl Cdr2Decode for CompleteStructType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let struct_flags = StructTypeFlag(decode_u16(src, offset)?);

        // Decode header using internal helper
        let header = decode_complete_struct_header_internal(src, offset)?;

        // Decode member_seq: DHEADER-delimited per XTypes v1.3 sec. 7.4.3.5.3.
        let member_seq = decode_dheader_at(src, offset, |src, offset| {
            super::helpers::decode_member_sequence(
                src,
                offset,
                decode_complete_struct_member_internal,
            )
        })?;

        Ok(CompleteStructType {
            struct_flags,
            header,
            member_seq,
        })
    }
}

impl Cdr2Encode for MinimalStructType {
    fn max_cdr2_size(&self) -> usize {
        super::helpers::max_size_type_with_members(&self.header, &self.member_seq)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.struct_flags.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        // XTypes v1.3 sec. 7.4.3.5.3: DHEADER-delimited member sequence (the
        // element type MinimalStructMember is @APPENDABLE). The member order is
        // the declaration (member_index) order, the order conformant
        // implementations hash: for a @mutable struct with non-monotonic
        // explicit IDs (struct_m3 = {x1=1, x3=3, x2=2}) the Minimal member
        // order is x1,x3,x2, not the member_id-sorted x1,x2,x3. The member_seq
        // is already in declaration order from the builder.
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec(&self.member_seq, dst, offset, |member, dst, offset| {
                member.encode_cdr2_le_at(dst, offset)
            })
        })?;
        Ok(())
    }
}

impl Cdr2Decode for MinimalStructType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let struct_flags = StructTypeFlag(decode_u16(src, offset)?);

        // Decode header using internal helper
        let header = decode_minimal_struct_header_internal(src, offset)?;

        // Decode member_seq: DHEADER-delimited per XTypes v1.3 sec. 7.4.3.5.3.
        let member_seq = decode_dheader_at(src, offset, |src, offset| {
            super::helpers::decode_member_sequence(
                src,
                offset,
                decode_minimal_struct_member_internal,
            )
        })?;

        Ok(MinimalStructType {
            struct_flags,
            header,
            member_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{MemberFlag, TypeIdentifier, TypeKind};

    fn make_minimal_member(member_id: u32, name_hash: u32) -> MinimalStructMember {
        MinimalStructMember {
            common: CommonStructMember {
                member_id,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
            },
            detail: MinimalMemberDetail { name_hash },
        }
    }

    fn make_complete_member(member_id: u32, name: &str) -> CompleteStructMember {
        CompleteStructMember {
            common: CommonStructMember {
                member_id,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
            },
            detail: CompleteMemberDetail {
                name: name.to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        }
    }

    fn minimal_header() -> MinimalStructHeader {
        MinimalStructHeader {
            base_type: None,
            detail: MinimalTypeDetail::new(),
        }
    }

    /// `base_type` is the TypeIdentifier itself (DDS-XTypes 1.3 Annex B,
    /// spec lines 12776-12787), not an @optional: a derived struct's header
    /// is DHEADER + the base identifier, and no base is the single octet
    /// TK_NONE. The bytes are Cyclone 0.11's for a header naming a Minimal
    /// base (`DerivedA` in tests/golden/typeobject).
    #[test]
    fn base_type_is_the_identifier_itself_not_an_optional() {
        let base = TypeIdentifier::Minimal(crate::xtypes::EquivalenceHash::from_bytes([
            0x6e, 0x6f, 0xee, 0x1f, 0x24, 0x3c, 0xac, 0x52, 0x39, 0x96, 0x68, 0xce, 0xf9, 0x35,
        ]));
        let derived = MinimalStructHeader {
            base_type: Some(base),
            detail: MinimalTypeDetail::new(),
        };
        let mut buf = vec![0u8; 64];
        let mut off = 0usize;
        derived
            .encode_cdr2_le_at(&mut buf, &mut off)
            .expect("encode");
        let wire = [
            0x0f, 0x00, 0x00, 0x00, 0xf1, 0x6e, 0x6f, 0xee, 0x1f, 0x24, 0x3c, 0xac, 0x52, 0x39,
            0x96, 0x68, 0xce, 0xf9, 0x35,
        ];
        assert_eq!(&buf[..off], &wire);
        let mut read = 0usize;
        let back = MinimalStructHeader::decode_cdr2_le_at(&wire, &mut read).expect("decode");
        assert_eq!((back, read), (derived, wire.len()));

        let plain = minimal_header();
        let mut off = 0usize;
        plain.encode_cdr2_le_at(&mut buf, &mut off).expect("encode");
        assert_eq!(&buf[..off], &[0x01, 0x00, 0x00, 0x00, 0x00]);
        let mut read = 0usize;
        let back = MinimalStructHeader::decode_cdr2_le_at(&buf[..off], &mut read).expect("decode");
        assert_eq!(back.base_type, None);
    }

    /// MinimalStructMemberSeq is emitted in declaration (member_index) order,
    /// NOT sorted by member_id. Per the DDS-XTypes v1.3 TypeObject IDL the
    /// MinimalStructMemberSeq is "Ordered by common.member_id", but HDDS
    /// preserves the source (member_index) order for the serialized
    /// MinimalTypeObject that feeds the EquivalenceHash, the order conformant
    /// implementations hash -- e.g. a @mutable struct {x1=1, x3=3, x2=2} hashes with
    /// member order x1,x3,x2. The encoder therefore preserves the source order,
    /// and a non-monotonic source must round-trip back to the SAME order.
    #[test]
    fn minimal_struct_members_emit_in_declaration_order() {
        let header = minimal_header();

        let decl = MinimalStructType {
            struct_flags: StructTypeFlag::IS_MUTABLE,
            header,
            member_seq: vec![
                make_minimal_member(1, 0x11),
                make_minimal_member(3, 0x33),
                make_minimal_member(2, 0x22),
            ],
        };

        let mut buf = vec![0u8; decl.max_cdr2_size()];
        let len = decl.encode_cdr2_le(&mut buf).expect("encode");

        // Round-trip: decode and confirm the declaration order (1, 3, 2) is
        // preserved verbatim -- the encoder does NOT reorder by member_id.
        let (decoded, used) =
            MinimalStructType::decode_cdr2_le(&buf[..len]).expect("decode round-trip");
        assert_eq!(used, len, "decoder consumes full input");
        let ids: Vec<u32> = decoded
            .member_seq
            .iter()
            .map(|m| m.common.member_id)
            .collect();
        assert_eq!(
            ids,
            vec![1, 3, 2],
            "minimal member order is declaration (member_index) order, not sorted"
        );
    }

    /// CompleteStructMemberSeq is emitted in declaration (member_index) order
    /// per the DDS-XTypes v1.3 TypeObject IDL ("Ordered by the member_index").
    #[test]
    fn complete_struct_members_emit_in_declaration_order() {
        let header = CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail {
                type_name: "Mixed".to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        };

        let decl = CompleteStructType {
            struct_flags: StructTypeFlag::IS_MUTABLE,
            header,
            member_seq: vec![
                make_complete_member(1, "x1"),
                make_complete_member(3, "x3"),
                make_complete_member(2, "x2"),
            ],
        };

        let mut buf = vec![0u8; decl.max_cdr2_size()];
        let len = decl.encode_cdr2_le(&mut buf).expect("encode");

        let (decoded, used) =
            CompleteStructType::decode_cdr2_le(&buf[..len]).expect("decode round-trip");
        assert_eq!(used, len, "decoder consumes full input");
        let ids: Vec<u32> = decoded
            .member_seq
            .iter()
            .map(|m| m.common.member_id)
            .collect();
        assert_eq!(
            ids,
            vec![1, 3, 2],
            "complete member order is declaration (member_index) order, not sorted"
        );
    }
}

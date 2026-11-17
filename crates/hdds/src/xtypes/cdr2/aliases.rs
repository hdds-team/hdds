// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Alias type definitions
//!
//! Complete and Minimal alias types (type aliases/typedefs).
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.6 (Alias Types)

use super::annotations::{
    applied_annotation_seq_max, decode_applied_annotation_seq, encode_applied_annotation_seq,
};
use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::primitives::{decode_option, encode_option};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::TypeIdentifier;

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CompleteAliasType / MinimalAliasType CDR2 (0x09)
// ============================================================================

// Alias Headers -- `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
impl Cdr2Encode for CompleteAliasHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.detail.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.detail.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for CompleteAliasHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let detail = CompleteTypeDetail::decode_cdr2_le_at(src, offset)?;
            Ok(CompleteAliasHeader { detail })
        })
    }
}

impl Cdr2Encode for MinimalAliasHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.detail.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.detail.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for MinimalAliasHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let detail = MinimalTypeDetail::decode_cdr2_le_at(src, offset)?;
            Ok(MinimalAliasHeader { detail })
        })
    }
}

// CommonAliasBody -- @FINAL per spec line 12972
impl Cdr2Encode for CommonAliasBody {
    fn max_cdr2_size(&self) -> usize {
        self.related_flags.max_cdr2_size() + self.related_type.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        self.related_flags.encode_cdr2_le_at(dst, offset)?;
        self.related_type.encode_cdr2_le_at(dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for CommonAliasBody {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let related_flags = TypeRelationFlag::decode_cdr2_le_at(src, offset)?;
        let related_type = TypeIdentifier::decode_cdr2_le_at(src, offset)?;
        Ok(CommonAliasBody {
            related_flags,
            related_type,
        })
    }
}

// CompleteAliasBody / MinimalAliasBody -- `@extensibility(APPENDABLE)` per
// DDS-XTypes 1.3 Annex B (spec lines 12979-12989).
//
// CompleteAliasBody = DHEADER + CommonAliasBody + @optional
// AppliedBuiltinMemberAnnotations ann_builtin + @optional AppliedAnnotationSeq
// ann_custom (each @optional a presence octet, then the value).
impl Cdr2Encode for CompleteAliasBody {
    fn max_cdr2_size(&self) -> usize {
        let builtin = self.ann_builtin.as_ref().map_or(0, |a| a.max_cdr2_size());
        let custom = self
            .ann_custom
            .as_deref()
            .map_or(0, applied_annotation_seq_max);
        // DHEADER (4 bytes + up to 3 pad) + payload + two presence octets
        4 + 3 + self.common.max_cdr2_size() + 2 + builtin + custom
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            encode_option(&self.ann_builtin, dst, offset, |ann, dst, offset| {
                ann.encode_cdr2_le_at(dst, offset)
            })?;
            encode_option(&self.ann_custom, dst, offset, |vec, dst, offset| {
                encode_applied_annotation_seq(vec, dst, offset)
            })?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CompleteAliasBody {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let common = CommonAliasBody::decode_cdr2_le_at(src, offset)?;
            let ann_builtin = decode_option(src, offset, |src, offset| {
                AppliedBuiltinMemberAnnotations::decode_cdr2_le_at(src, offset)
            })?;
            let ann_custom = decode_option(src, offset, decode_applied_annotation_seq)?;
            Ok(CompleteAliasBody {
                common,
                ann_builtin,
                ann_custom,
            })
        })
    }
}

impl Cdr2Encode for MinimalAliasBody {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.common.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for MinimalAliasBody {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let common = CommonAliasBody::decode_cdr2_le_at(src, offset)?;
            Ok(MinimalAliasBody { common })
        })
    }
}

// Complete/Minimal AliasType
impl Cdr2Encode for CompleteAliasType {
    fn max_cdr2_size(&self) -> usize {
        self.alias_flags.max_cdr2_size() + self.header.max_cdr2_size() + self.body.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        self.alias_flags.encode_cdr2_le_at(dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        self.body.encode_cdr2_le_at(dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for CompleteAliasType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let alias_flags = AliasTypeFlag::decode_cdr2_le_at(src, offset)?;
        let header = CompleteAliasHeader::decode_cdr2_le_at(src, offset)?;
        let body = CompleteAliasBody::decode_cdr2_le_at(src, offset)?;
        Ok(CompleteAliasType {
            alias_flags,
            header,
            body,
        })
    }
}

impl Cdr2Encode for MinimalAliasType {
    fn max_cdr2_size(&self) -> usize {
        self.alias_flags.max_cdr2_size() + self.header.max_cdr2_size() + self.body.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        self.alias_flags.encode_cdr2_le_at(dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        self.body.encode_cdr2_le_at(dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for MinimalAliasType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let alias_flags = AliasTypeFlag::decode_cdr2_le_at(src, offset)?;
        let header = MinimalAliasHeader::decode_cdr2_le_at(src, offset)?;
        let body = MinimalAliasBody::decode_cdr2_le_at(src, offset)?;
        Ok(MinimalAliasType {
            alias_flags,
            header,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{
        AnnotationParameterValue, CollectionElementFlag, EquivalenceKind, PlainCollectionHeader,
        PlainSequenceSElemDefn, TypeKind,
    };

    fn lseq_body() -> CompleteAliasBody {
        CompleteAliasBody {
            common: CommonAliasBody {
                related_flags: TypeRelationFlag::empty(),
                related_type: TypeIdentifier::PlainSequenceSmall(PlainSequenceSElemDefn {
                    header: PlainCollectionHeader {
                        equiv_kind: EquivalenceKind::Both,
                        element_flags: CollectionElementFlag::TRY_CONSTRUCT1,
                    },
                    bound: 0,
                    element_identifier: Box::new(TypeIdentifier::Primitive(TypeKind::TK_INT32)),
                }),
            },
            ann_builtin: None,
            ann_custom: None,
        }
    }

    fn encode(body: &CompleteAliasBody) -> Vec<u8> {
        let mut buf = vec![0u8; body.max_cdr2_size()];
        let mut off = 0usize;
        body.encode_cdr2_le_at(&mut buf, &mut off).expect("encode");
        buf.truncate(off);
        buf
    }

    /// `typedef sequence<long> LSeq;`: Cyclone DDS 0.11's CompleteAliasBody
    /// (tests/golden/typeobject, `LSeq C`) is DHEADER, CommonAliasBody, then
    /// the two absent @optional annotation fields, and no type detail
    /// (DDS-XTypes 1.3 Annex B, spec lines 12979-12984).
    #[test]
    fn complete_alias_body_is_common_then_two_optional_annotation_fields() {
        let wire = [
            0x0a, 0x00, 0x00, 0x00, // DHEADER: 10
            0x00, 0x00, // related_flags
            0x80, 0xf3, 0x01, 0x00, 0x00, 0x04, // sequence<long>, EK_BOTH, TRY_CONSTRUCT1
            0x00, 0x00, // ann_builtin, ann_custom absent
        ];
        assert_eq!(encode(&lseq_body()), wire);
        let mut off = 0usize;
        let back = CompleteAliasBody::decode_cdr2_le_at(&wire, &mut off).expect("decode");
        assert_eq!((back, off), (lseq_body(), wire.len()));
    }

    /// An annotated alias carries its AppliedBuiltinMemberAnnotations, a
    /// delimited record of its own, in the body.
    #[test]
    fn complete_alias_body_carries_builtin_annotations() {
        let mut body = lseq_body();
        body.ann_builtin = Some(AppliedBuiltinMemberAnnotations {
            max: Some(AnnotationParameterValue::Int32(7)),
            ..Default::default()
        });
        let wire = [
            0x1a, 0x00, 0x00, 0x00, // DHEADER: 26
            0x00, 0x00, 0x80, 0xf3, 0x01, 0x00, 0x00, 0x04, // common
            0x01, 0x00, 0x00, 0x00, // ann_builtin present, pad
            0x09, 0x00, 0x00, 0x00, // its DHEADER: 9
            0x00, 0x00, 0x01, 0x04, 0x07, 0x00, 0x00,
            0x00, // unit, min absent; max: TK_INT32 7
            0x00, // hash_id absent
            0x00, // ann_custom absent
        ];
        let got = encode(&body);
        assert_eq!(got, wire);
        let mut off = 0usize;
        let back = CompleteAliasBody::decode_cdr2_le_at(&wire, &mut off).expect("decode");
        assert_eq!((back, off), (body, wire.len()));
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Type and member detail metadata
//!
//!
//! TypeDetail and MemberDetail provide optional descriptive information.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.6 (TypeDetail)

use super::annotations::{
    applied_annotation_seq_max, decode_applied_annotation_seq, encode_applied_annotation_seq,
};
use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::primitives::{
    decode_option, decode_string, decode_u8, encode_option, encode_string, encode_u8,
};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// Detail Structures CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteTypeDetail {
    fn max_cdr2_size(&self) -> usize {
        let builtin = self.ann_builtin.as_ref().map_or(0, |a| a.max_cdr2_size());
        let custom = self
            .ann_custom
            .as_deref()
            .map_or(0, applied_annotation_seq_max);
        // two presence octets, the annotations, then the name (up to 3 pad,
        // length, bytes, NUL)
        2 + builtin + custom + 3 + 4 + self.type_name.len() + 1
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        // XTypes v1.3 sec. 7.3.4.6 CompleteTypeDetail field order is
        // `ann_builtin`, `ann_custom`, then `type_name`. The order is
        // load-bearing for the canonical EquivalenceHash (sec. 7.3.4.8).
        encode_option(&self.ann_builtin, dst, offset, |ann, dst, offset| {
            ann.encode_cdr2_le_at(dst, offset)
        })?;
        encode_option(&self.ann_custom, dst, offset, |vec, dst, offset| {
            // AppliedAnnotationSeq is "Sorted by AppliedAnnotation.annotation_typeid"
            // (Annex B); TypeIdentifier has no Ord, so the builder sorts and
            // the encoder preserves source order.
            encode_applied_annotation_seq(vec, dst, offset)
        })?;
        encode_string(&self.type_name, dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for CompleteTypeDetail {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        // Mirror the sec. 7.3.4.6 field order used by the encoder.
        let ann_builtin = decode_option(src, offset, |src, offset| {
            AppliedBuiltinTypeAnnotations::decode_cdr2_le_at(src, offset)
        })?;
        let ann_custom = decode_option(src, offset, decode_applied_annotation_seq)?;

        let type_name = decode_string(src, offset)?;

        Ok(CompleteTypeDetail {
            type_name,
            ann_builtin,
            ann_custom,
        })
    }
}

impl Cdr2Encode for MinimalTypeDetail {
    fn max_cdr2_size(&self) -> usize {
        0
    }

    fn encode_cdr2_le_at(&self, _dst: &mut [u8], _offset: &mut usize) -> Result<(), CdrError> {
        Ok(())
    }
}

impl Cdr2Decode for MinimalTypeDetail {
    fn decode_cdr2_le(_src: &[u8]) -> Result<(Self, usize), CdrError> {
        Ok((MinimalTypeDetail {}, 0))
    }

    fn decode_cdr2_le_at(_src: &[u8], _offset: &mut usize) -> Result<Self, CdrError> {
        // MinimalTypeDetail is empty -- no bytes consumed, offset unchanged.
        Ok(MinimalTypeDetail {})
    }
}

// ============================================================================
// AppliedBuiltinTypeAnnotations
// ============================================================================

/// `@extensibility(APPENDABLE) struct AppliedBuiltinTypeAnnotations {
/// @optional AppliedVerbatimAnnotation verbatim; }` (DDS-XTypes 1.3 Annex B,
/// spec text lines 12751-12754), the verbatim record being FINAL
/// `{ string<32> placement; string<32> language; string text; }` (lines
/// 12680-12686): a DHEADER, a presence octet, then three strings.
impl Cdr2Encode for AppliedBuiltinTypeAnnotations {
    fn max_cdr2_size(&self) -> usize {
        let verbatim = self.verbatim.as_ref().map_or(0, |v| {
            3 * (3 + 4 + 1) + v.placement.len() + v.language.len() + v.text.len()
        });
        4 + 3 + 1 + verbatim
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_option(&self.verbatim, dst, offset, |v, dst, offset| {
                encode_string(&v.placement, dst, offset)?;
                encode_string(&v.language, dst, offset)?;
                encode_string(&v.text, dst, offset)
            })
        })
    }
}

impl Cdr2Decode for AppliedBuiltinTypeAnnotations {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let verbatim = decode_option(src, offset, |src, offset| {
                Ok(AppliedVerbatimAnnotation {
                    placement: decode_string(src, offset)?,
                    language: decode_string(src, offset)?,
                    text: decode_string(src, offset)?,
                })
            })?;
            Ok(AppliedBuiltinTypeAnnotations { verbatim })
        })
    }
}

// ============================================================================
// AppliedBuiltinMemberAnnotations
// ============================================================================

/// `@extensibility(APPENDABLE) struct AppliedBuiltinMemberAnnotations` per
/// DDS-XTypes 1.3 Annex B (spec text lines 12692-12698):
///
/// ```text
/// @optional string                   unit;    // @unit("<unit>")
/// @optional AnnotationParameterValue min;     // @min , @range
/// @optional AnnotationParameterValue max;     // @max , @range
/// @optional string                   hash_id; // @hashid("<membername>")
/// ```
///
/// APPENDABLE, so the four fields sit behind a DHEADER (XCDR2 rule (30),
/// 7.4.3.4); each @optional member of a non-mutable type is a presence octet
/// then the value. The same record is the `ann_builtin` of a
/// `CompleteMemberDetail`, a `CompleteAliasBody` and a
/// `CompleteElementDetail`.
impl Cdr2Encode for AppliedBuiltinMemberAnnotations {
    fn max_cdr2_size(&self) -> usize {
        let string = |s: &Option<String>| s.as_ref().map_or(0, |s| 3 + 4 + s.len() + 1);
        let value =
            |v: &Option<AnnotationParameterValue>| v.as_ref().map_or(0, |v| v.max_cdr2_size());
        // DHEADER (4 + up to 3 pad), four presence octets, the values.
        4 + 3 + 4 + string(&self.unit) + value(&self.min) + value(&self.max) + string(&self.hash_id)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_option(&self.unit, dst, offset, |s: &String, dst, offset| {
                encode_string(s.as_str(), dst, offset)
            })?;
            encode_option(&self.min, dst, offset, |v, dst, offset| {
                v.encode_cdr2_le_at(dst, offset)
            })?;
            encode_option(&self.max, dst, offset, |v, dst, offset| {
                v.encode_cdr2_le_at(dst, offset)
            })?;
            encode_option(&self.hash_id, dst, offset, |s: &String, dst, offset| {
                encode_string(s.as_str(), dst, offset)
            })
        })
    }
}

impl Cdr2Decode for AppliedBuiltinMemberAnnotations {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let unit = decode_option(src, offset, decode_string)?;
            let min = decode_option(src, offset, |src, offset| {
                AnnotationParameterValue::decode_cdr2_le_at(src, offset)
            })?;
            let max = decode_option(src, offset, |src, offset| {
                AnnotationParameterValue::decode_cdr2_le_at(src, offset)
            })?;
            let hash_id = decode_option(src, offset, decode_string)?;
            Ok(AppliedBuiltinMemberAnnotations {
                unit,
                min,
                max,
                hash_id,
            })
        })
    }
}

impl Cdr2Encode for CompleteMemberDetail {
    // @audit-ok: Sequential encoding (cyclo 12, cogni 0) - linear option encoding without branching logic

    fn max_cdr2_size(&self) -> usize {
        let builtin = self.ann_builtin.as_ref().map_or(0, |a| a.max_cdr2_size());
        let custom = self
            .ann_custom
            .as_deref()
            .map_or(0, applied_annotation_seq_max);
        // the name (up to 3 pad, length, bytes, NUL), two presence octets,
        // the annotations
        3 + 4 + self.name.len() + 1 + 2 + builtin + custom
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_string(&self.name, dst, offset)?;
        encode_option(&self.ann_builtin, dst, offset, |ann, dst, offset| {
            ann.encode_cdr2_le_at(dst, offset)
        })?;
        encode_option(&self.ann_custom, dst, offset, |vec, dst, offset| {
            // Source order, as for CompleteTypeDetail::ann_custom.
            encode_applied_annotation_seq(vec, dst, offset)
        })?;
        Ok(())
    }
}

impl Cdr2Decode for CompleteMemberDetail {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let name = decode_string(src, offset)?;

        let ann_builtin = decode_option(src, offset, |src, offset| {
            AppliedBuiltinMemberAnnotations::decode_cdr2_le_at(src, offset)
        })?;

        let ann_custom = decode_option(src, offset, decode_applied_annotation_seq)?;

        Ok(CompleteMemberDetail {
            name,
            ann_builtin,
            ann_custom,
        })
    }
}

impl Cdr2Encode for MinimalMemberDetail {
    fn max_cdr2_size(&self) -> usize {
        4 // NameHash = octet[4], 1-byte aligned, no padding
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        // XTypes v1.3 sec. 7.3.4.6: `MinimalMemberDetail { NameHash name_hash; }`
        // where `typedef octet NameHash[4]`. As an octet array it has 1-byte
        // alignment and is written as 4 raw bytes with NO 4-byte padding (a
        // plain `uint32` would force alignment and corrupt the EquivalenceHash).
        for b in self.name_hash.to_le_bytes() {
            encode_u8(b, dst, offset)?;
        }
        Ok(())
    }
}

impl Cdr2Decode for MinimalMemberDetail {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        // NameHash = octet[4]: 4 raw bytes, 1-byte aligned (see encoder).
        let b0 = decode_u8(src, offset)?;
        let b1 = decode_u8(src, offset)?;
        let b2 = decode_u8(src, offset)?;
        let b3 = decode_u8(src, offset)?;
        let name_hash = u32::from_le_bytes([b0, b1, b2, b3]);
        Ok(MinimalMemberDetail { name_hash })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(detail: &CompleteMemberDetail) -> Vec<u8> {
        let mut buf = vec![0u8; detail.max_cdr2_size()];
        let mut off = 0usize;
        detail
            .encode_cdr2_le_at(&mut buf, &mut off)
            .expect("encode");
        buf.truncate(off);
        buf
    }

    fn annotated(name: &str, ann: AppliedBuiltinMemberAnnotations) -> CompleteMemberDetail {
        CompleteMemberDetail {
            name: name.to_string(),
            ann_builtin: Some(ann),
            ann_custom: None,
        }
    }

    /// The member details of `@final struct Annot { @unit("m") long a;
    /// @min(1) @max(10) long b; ... }` exactly as Cyclone DDS 0.11 idlc
    /// serializes them (tests/golden/typeobject, `Annot C`): the builtin
    /// annotations are an APPENDABLE record behind its own DHEADER, and
    /// `min` / `max` are AnnotationParameterValues (DDS-XTypes 1.3 Annex B,
    /// spec lines 12692-12698).
    #[test]
    fn builtin_member_annotations_are_a_delimited_record_with_min_and_max() {
        let unit = annotated(
            "a",
            AppliedBuiltinMemberAnnotations {
                unit: Some("m".to_string()),
                ..Default::default()
            },
        );
        let unit_wire = [
            0x02, 0x00, 0x00, 0x00, 0x61, 0x00, // name "a"
            0x01, 0x00, // ann_builtin present, pad
            0x0d, 0x00, 0x00, 0x00, // DHEADER: 13
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x6d, 0x00, // unit "m"
            0x00, 0x00, 0x00, // min, max, hash_id absent
            0x00, // ann_custom absent
        ];
        assert_eq!(encode(&unit), unit_wire);

        let range = annotated(
            "b",
            AppliedBuiltinMemberAnnotations {
                min: Some(AnnotationParameterValue::Int32(1)),
                max: Some(AnnotationParameterValue::Int32(10)),
                ..Default::default()
            },
        );
        let range_wire = [
            0x02, 0x00, 0x00, 0x00, 0x62, 0x00, // name "b"
            0x01, 0x00, // ann_builtin present, pad
            0x11, 0x00, 0x00, 0x00, // DHEADER: 17
            0x00, // unit absent
            0x01, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // min: TK_INT32 1
            0x01, 0x04, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, // max: TK_INT32 10
            0x00, // hash_id absent
            0x00, // ann_custom absent
        ];
        assert_eq!(encode(&range), range_wire);

        for (detail, wire) in [(unit, &unit_wire[..]), (range, &range_wire[..])] {
            let mut off = 0usize;
            let back = CompleteMemberDetail::decode_cdr2_le_at(wire, &mut off).expect("decode");
            assert_eq!((back, off), (detail, wire.len()));
        }
    }
}

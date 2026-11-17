// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Enumeration type definitions
//!
//!
//! Complete and Minimal enumeration types, headers, and literals.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.3 (Enumerated Types)

use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::helpers::{checked_usize, sequence_capacity};
use super::primitives::{
    align_offset, decode_i16, decode_i32, decode_u16, decode_u32, encode_i16, encode_i32,
    encode_u16, encode_vec_sorted,
};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CommonEnumeratedLiteral CDR2 Encoding/Decoding
// ============================================================================

// CommonEnumeratedLiteral -- `@extensibility(APPENDABLE)` per XTypes v1.3 spec line 13159.
impl Cdr2Encode for CommonEnumeratedLiteral {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload (i32 + u16)
        4 + 3 + 4 + 2
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_i32(self.value, dst, offset)?;
            encode_u16(self.flags.0, dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CommonEnumeratedLiteral {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_common_enumerated_literal_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CommonEnumeratedLiteral decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_common_enumerated_literal_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CommonEnumeratedLiteral, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let value = decode_i32(src, offset)?;
        let flags = EnumeratedLiteralFlag(decode_u16(src, offset)?);
        Ok(CommonEnumeratedLiteral { value, flags })
    })
}

// ============================================================================
// CompleteEnumeratedLiteral / MinimalEnumeratedLiteral CDR2 Encoding/Decoding
// ============================================================================

// Complete/MinimalEnumeratedLiteral -- `@extensibility(APPENDABLE)` per spec lines 13167, 13177.
impl Cdr2Encode for CompleteEnumeratedLiteral {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CompleteEnumeratedLiteral {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_enumerated_literal_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteEnumeratedLiteral decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_complete_enumerated_literal_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteEnumeratedLiteral, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_enumerated_literal_internal(src, offset)?;
        let detail = CompleteMemberDetail::decode_cdr2_le_at(src, offset)?;
        Ok(CompleteEnumeratedLiteral { common, detail })
    })
}

impl Cdr2Encode for MinimalEnumeratedLiteral {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for MinimalEnumeratedLiteral {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_enumerated_literal_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalEnumeratedLiteral decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_minimal_enumerated_literal_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalEnumeratedLiteral, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_enumerated_literal_internal(src, offset)?;
        let detail = MinimalMemberDetail::decode_cdr2_le_at(src, offset)?;
        Ok(MinimalEnumeratedLiteral { common, detail })
    })
}

// ============================================================================
// EnumeratedHeader CDR2 Encoding/Decoding
// ============================================================================

// Complete/MinimalEnumeratedHeader -- `@extensibility(APPENDABLE)` per spec lines 13196, 13203.
impl Cdr2Encode for CompleteEnumeratedHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + 2 + self.detail.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_i16(self.bit_bound, dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CompleteEnumeratedHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_enumerated_header_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteEnumeratedHeader decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_complete_enumerated_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteEnumeratedHeader, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let bit_bound = decode_i16(src, offset)?;
        let detail = CompleteTypeDetail::decode_cdr2_le_at(src, offset)?;
        Ok(CompleteEnumeratedHeader { bit_bound, detail })
    })
}

impl Cdr2Encode for MinimalEnumeratedHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + 2 + self.detail.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_i16(self.bit_bound, dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for MinimalEnumeratedHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_enumerated_header_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalEnumeratedHeader decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_minimal_enumerated_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalEnumeratedHeader, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let bit_bound = decode_i16(src, offset)?;
        // MinimalTypeDetail is empty, but decode it for consistency
        let detail = MinimalTypeDetail::decode_cdr2_le_at(src, offset)?;
        Ok(MinimalEnumeratedHeader { bit_bound, detail })
    })
}

// ============================================================================
// CompleteEnumeratedType / MinimalEnumeratedType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteEnumeratedType {
    fn max_cdr2_size(&self) -> usize {
        // 2 (enum_flags + pad) + header + 4 (literal_seq DHEADER) + 4 (count)
        // + literals.
        2 + self.header.max_cdr2_size()
            + 4
            + 4
            + self
                .literal_seq
                .iter()
                .map(|l| l.max_cdr2_size())
                .sum::<usize>()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        // EnumTypeFlag enum_flags: the declared extensibility (see
        // MinimalEnumeratedType::encode).
        encode_u16(self.enum_flags.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        // DHEADER-framed literal_seq (XCDR2 sec. 7.4.3.5.3); XTypes v1.3 sec. 7.3.4.5:
        // CompleteEnumeratedLiteralSeq is ordered by ascending `value` for a
        // stable EquivalenceHash.
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec_sorted(
                &self.literal_seq,
                dst,
                offset,
                |l| l.common.value,
                |literal, dst, offset| literal.encode_cdr2_le_at(dst, offset),
            )
        })?;
        Ok(())
    }
}

impl Cdr2Decode for CompleteEnumeratedType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let enum_flags: EnumTypeFlag = StructTypeFlag(decode_u16(src, offset)?);
        let header = decode_complete_enumerated_header_internal(src, offset)?;

        // literal_seq is DHEADER-framed (byte size of count + elements).
        let literal_seq = decode_dheader_at(src, offset, |src, offset| {
            let literal_len = decode_u32(src, offset)?;
            let capacity = checked_usize(literal_len, "enumeration literal sequence length")?;
            let mut literal_seq = Vec::with_capacity(sequence_capacity(capacity, src, *offset));
            for _ in 0..capacity {
                // Align each element to 4 bytes (CDR2 struct alignment in sequences)
                *offset = align_offset(*offset, 4);
                let literal = decode_complete_enumerated_literal_internal(src, offset)?;
                literal_seq.push(literal);
            }
            Ok(literal_seq)
        })?;

        Ok(CompleteEnumeratedType {
            enum_flags,
            header,
            literal_seq,
        })
    }
}

impl Cdr2Encode for MinimalEnumeratedType {
    fn max_cdr2_size(&self) -> usize {
        // 2 (enum_flags + pad) + header + 4 (literal_seq DHEADER) + 4 (count)
        // + literals.
        2 + self.header.max_cdr2_size()
            + 4
            + 4
            + self
                .literal_seq
                .iter()
                .map(|l| l.max_cdr2_size())
                .sum::<usize>()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        // MinimalEnumeratedType is `@extensibility(FINAL)` and begins with the
        // `EnumTypeFlag enum_flags` field (DDS-XTypes 1.3 Annex B, spec lines
        // 13211-13224). The IDL marks it "unused" for assignability, but it is
        // serialized, and conformant vendors write the enum's DECLARED
        // extensibility there: Cyclone 0.11 writes 0x0001 for `@final enum`
        // and 0x0002 for `@appendable enum` (tests/golden/typeobject). The
        // value is the builder's; the encoder writes what the model holds.
        encode_u16(self.enum_flags.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        // The literal_seq element type (MinimalEnumeratedLiteral) is a non-
        // primitive APPENDABLE struct, so the sequence is preceded by a DHEADER
        // giving the byte size of (count + elements) per XCDR2 (sec. 7.4.3.5.3).
        // XTypes v1.3 sec. 7.3.4.5: MinimalEnumeratedLiteralSeq is ordered by
        // ascending `value` so the EquivalenceHash is bitwise-identical
        // across vendors.
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec_sorted(
                &self.literal_seq,
                dst,
                offset,
                |l| l.common.value,
                |literal, dst, offset| literal.encode_cdr2_le_at(dst, offset),
            )
        })?;
        Ok(())
    }
}

impl Cdr2Decode for MinimalEnumeratedType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        // enum_flags (EnumTypeFlag, u16): kept, it is part of the object (and
        // of its hash) even though assignability ignores it.
        let enum_flags: EnumTypeFlag = StructTypeFlag(decode_u16(src, offset)?);
        let header = decode_minimal_enumerated_header_internal(src, offset)?;

        // literal_seq is DHEADER-framed (byte size of count + elements).
        let literal_seq = decode_dheader_at(src, offset, |src, offset| {
            let literal_len = decode_u32(src, offset)?;
            let capacity =
                checked_usize(literal_len, "minimal enumeration literal sequence length")?;
            let mut literal_seq = Vec::with_capacity(sequence_capacity(capacity, src, *offset));
            for _ in 0..capacity {
                // Align each element to 4 bytes (CDR2 struct alignment in sequences)
                *offset = align_offset(*offset, 4);
                let literal = decode_minimal_enumerated_literal_internal(src, offset)?;
                literal_seq.push(literal);
            }
            Ok(literal_seq)
        })?;

        Ok(MinimalEnumeratedType {
            enum_flags,
            header,
            literal_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_literal(value: i32, name_hash: u32) -> MinimalEnumeratedLiteral {
        MinimalEnumeratedLiteral {
            common: CommonEnumeratedLiteral {
                value,
                flags: EnumeratedLiteralFlag(0),
            },
            detail: MinimalMemberDetail { name_hash },
        }
    }

    fn make_complete_literal(value: i32, name: &str) -> CompleteEnumeratedLiteral {
        CompleteEnumeratedLiteral {
            common: CommonEnumeratedLiteral {
                value,
                flags: EnumeratedLiteralFlag(0),
            },
            detail: CompleteMemberDetail {
                name: name.to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        }
    }

    /// XTypes v1.3 sec. 7.3.4.5: MinimalEnumeratedLiteralSeq must be
    /// serialized with literals in ascending `value` order so the
    /// resulting bytes (and the derived EquivalenceHash) are stable
    /// regardless of how the producer populates the source Vec.
    #[test]
    fn minimal_enum_literals_emit_sorted_by_value() {
        let header = MinimalEnumeratedHeader {
            bit_bound: 32,
            detail: MinimalTypeDetail {},
        };

        let unsorted = MinimalEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: header.clone(),
            literal_seq: vec![
                make_minimal_literal(7, 0xAA00_AA00),
                make_minimal_literal(-3, 0xBB00_BB00),
                make_minimal_literal(0, 0xCC00_CC00),
                make_minimal_literal(2, 0xDD00_DD00),
            ],
        };
        let sorted = MinimalEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header,
            literal_seq: vec![
                make_minimal_literal(-3, 0xBB00_BB00),
                make_minimal_literal(0, 0xCC00_CC00),
                make_minimal_literal(2, 0xDD00_DD00),
                make_minimal_literal(7, 0xAA00_AA00),
            ],
        };

        let mut buf_unsorted = vec![0u8; unsorted.max_cdr2_size()];
        let len_unsorted = unsorted
            .encode_cdr2_le(&mut buf_unsorted)
            .expect("encode unsorted");
        let mut buf_sorted = vec![0u8; sorted.max_cdr2_size()];
        let len_sorted = sorted
            .encode_cdr2_le(&mut buf_sorted)
            .expect("encode sorted");

        assert_eq!(
            len_unsorted, len_sorted,
            "unsorted and sorted inputs must produce equal-length wire output"
        );
        assert_eq!(
            &buf_unsorted[..len_unsorted],
            &buf_sorted[..len_sorted],
            "unsorted input must produce bytes identical to sorted input \
             (ascending value ordering enforcement)"
        );

        // Round-trip: decode the unsorted-input bytes and confirm we
        // recover the literals in ascending `value` order with their
        // associated `name_hash` riding the sort.
        let (decoded, used) = MinimalEnumeratedType::decode_cdr2_le(&buf_unsorted[..len_unsorted])
            .expect("decode round-trip");
        assert_eq!(used, len_unsorted, "decoder consumes full input");
        let values: Vec<i32> = decoded.literal_seq.iter().map(|l| l.common.value).collect();
        assert_eq!(values, vec![-3, 0, 2, 7], "decoded values are sorted");
        let hashes: Vec<u32> = decoded
            .literal_seq
            .iter()
            .map(|l| l.detail.name_hash)
            .collect();
        assert_eq!(
            hashes,
            vec![0xBB00_BB00, 0xCC00_CC00, 0xDD00_DD00, 0xAA00_AA00],
            "name_hash follows its owning literal after sort"
        );
    }

    /// XTypes v1.3 sec. 7.3.4.5 ascending `value` order with negative values:
    /// i32 ordering must place negative values before non-negative ones
    /// (`-10 < -1 < 0 < 5`). Locks the i32 (signed) sort key so a
    /// future refactor to u32 surface would surface as a test failure.
    #[test]
    fn minimal_enum_literals_with_negative_values_sort_correctly() {
        let header = MinimalEnumeratedHeader {
            bit_bound: 32,
            detail: MinimalTypeDetail {},
        };

        let unsorted = MinimalEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header,
            literal_seq: vec![
                make_minimal_literal(5, 0x05),
                make_minimal_literal(-10, 0xF6),
                make_minimal_literal(0, 0x00),
                make_minimal_literal(-1, 0xFF),
            ],
        };

        let mut buf = vec![0u8; unsorted.max_cdr2_size()];
        let len = unsorted.encode_cdr2_le(&mut buf).expect("encode");
        let (decoded, _used) =
            MinimalEnumeratedType::decode_cdr2_le(&buf[..len]).expect("round-trip");
        let values: Vec<i32> = decoded.literal_seq.iter().map(|l| l.common.value).collect();
        assert_eq!(
            values,
            vec![-10, -1, 0, 5],
            "negative i32 values precede positives in ascending order"
        );
    }

    /// XTypes v1.3 sec. 7.3.4.5: CompleteEnumeratedLiteralSeq, same ascending
    /// `value` ordering guarantee as MinimalEnumeratedLiteralSeq above, with
    /// the Complete variant.
    #[test]
    fn complete_enum_literals_emit_sorted_by_value() {
        let header = CompleteEnumeratedHeader {
            bit_bound: 32,
            detail: CompleteTypeDetail {
                type_name: "Color".to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        };

        let unsorted = CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: header.clone(),
            literal_seq: vec![
                make_complete_literal(5, "ORANGE"),
                make_complete_literal(-1, "BLACK"),
                make_complete_literal(2, "RED"),
            ],
        };
        let sorted = CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header,
            literal_seq: vec![
                make_complete_literal(-1, "BLACK"),
                make_complete_literal(2, "RED"),
                make_complete_literal(5, "ORANGE"),
            ],
        };

        let mut buf_unsorted = vec![0u8; unsorted.max_cdr2_size()];
        let len_unsorted = unsorted
            .encode_cdr2_le(&mut buf_unsorted)
            .expect("encode unsorted");
        let mut buf_sorted = vec![0u8; sorted.max_cdr2_size()];
        let len_sorted = sorted
            .encode_cdr2_le(&mut buf_sorted)
            .expect("encode sorted");

        assert_eq!(
            len_unsorted, len_sorted,
            "unsorted and sorted inputs must produce equal-length wire output"
        );
        assert_eq!(
            &buf_unsorted[..len_unsorted],
            &buf_sorted[..len_sorted],
            "unsorted input must produce bytes identical to sorted input \
             (ascending value ordering enforcement)"
        );
    }
}

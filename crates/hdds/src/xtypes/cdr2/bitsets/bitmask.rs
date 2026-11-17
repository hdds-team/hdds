// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitmask encoding for Complete/Minimal types.
//!
//! DDS-XTypes 1.3 Annex B (spec text lines 13233-13289):
//!
//! ```text
//! @appendable struct CompleteBitmaskType {
//!     BitmaskTypeFlag    bitmask_flags;
//!     CompleteBitmaskHeader header;     // = CompleteEnumeratedHeader, @appendable:
//!                                       //   BitBound bit_bound; CompleteTypeDetail detail;
//!     CompleteBitflagSeq flag_seq;      // @appendable CompleteBitflag elements:
//!                                       //   CommonBitflag { u16 position; u16 flags; }
//!                                       //   CompleteMemberDetail detail;
//! };
//! @appendable struct MinimalBitmaskType {
//!     BitmaskTypeFlag    bitmask_flags;
//!     MinimalBitmaskHeader header;      // = MinimalEnumeratedHeader: BitBound bit_bound;
//!     MinimalBitflagSeq  flag_seq;      // CommonBitflag, then NameHash name_hash;
//! };
//! ```
//!
//! Unlike the enumerated type, both bitmask types are APPENDABLE, so the whole
//! body sits behind a DHEADER. The Cyclone 0.11 idlc oracle serializes exactly
//! this layout (tests/golden/typeobject); an earlier reading of the layout
//! took the `bitmask_flags` + padding for "a reserved u32" and the
//! `position` + `flags` pair for "a u32 position", which encodes the same bytes
//! only while every flag is zero and the header carries no annotation.

use super::super::dheader::{decode_dheader_at, encode_dheader_at};
use super::super::helpers::{checked_usize, sequence_capacity};
use super::super::primitives::{
    align_offset, decode_i16, decode_u16, decode_u32, encode_i16, encode_u16, encode_vec_sorted,
};
use super::bitflag::{decode_complete_bitflag_internal, decode_minimal_bitflag_internal};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::type_object::{
    BitmaskTypeFlag, CompleteBitmaskHeader, CompleteBitmaskType, CompleteTypeDetail,
    MinimalBitmaskHeader, MinimalBitmaskType, MinimalTypeDetail, StructTypeFlag,
};

// ============================================================================
// BitmaskHeader CDR2 Encoding/Decoding (= {Complete,Minimal}EnumeratedHeader)
// ============================================================================

impl Cdr2Encode for CompleteBitmaskHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + bit_bound + detail
        4 + 3 + 2 + self.detail.max_cdr2_size()
    }

    /// `CompleteBitmaskHeader` is a typedef of the `@appendable`
    /// `CompleteEnumeratedHeader`: DHEADER, then `bit_bound`, then the
    /// `CompleteTypeDetail`.
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_i16(self.bit_bound, dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for CompleteBitmaskHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let bit_bound = decode_i16(src, offset)?;
            let detail = CompleteTypeDetail::decode_cdr2_le_at(src, offset)?;
            Ok(CompleteBitmaskHeader { bit_bound, detail })
        })
    }
}

impl Cdr2Encode for MinimalBitmaskHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + bit_bound
        4 + 3 + 2
    }

    /// `MinimalBitmaskHeader` is a typedef of the `@appendable`
    /// `MinimalEnumeratedHeader`: DHEADER, then `bit_bound`.
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_i16(self.bit_bound, dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for MinimalBitmaskHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let bit_bound = decode_i16(src, offset)?;
            let detail = MinimalTypeDetail::decode_cdr2_le_at(src, offset)?;
            Ok(MinimalBitmaskHeader { bit_bound, detail })
        })
    }
}

// ============================================================================
// CompleteBitmaskType / MinimalBitmaskType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteBitmaskType {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4+3) + bitmask_flags (2) + header + seq DHEADER (4+3) +
        // count (4) + elements (each 4-aligned).
        7 + 2
            + self.header.max_cdr2_size()
            + 7
            + 4
            + self
                .flag_seq
                .iter()
                .map(|f| 3 + f.max_cdr2_size())
                .sum::<usize>()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_u16(self.bitmask_flags.0, dst, offset)?;
            self.header.encode_cdr2_le_at(dst, offset)?;
            // CompleteBitflagSeq: elements are @appendable, so the sequence is
            // DHEADER-delimited (XCDR2 7.4.3.5.3), "Ordered by
            // Bitflag.position" (Annex B).
            encode_dheader_at(dst, offset, |dst, offset| {
                encode_vec_sorted(
                    &self.flag_seq,
                    dst,
                    offset,
                    |f| f.common.position,
                    |flag, dst, offset| flag.encode_cdr2_le_at(dst, offset),
                )
            })
        })
    }
}

impl Cdr2Decode for CompleteBitmaskType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let bitmask_flags: BitmaskTypeFlag = StructTypeFlag(decode_u16(src, offset)?);
            let header = CompleteBitmaskHeader::decode_cdr2_le_at(src, offset)?;
            let flag_seq = decode_dheader_at(src, offset, |src, offset| {
                let count = checked_usize(decode_u32(src, offset)?, "bitflag sequence length")?;
                let mut flag_seq = Vec::with_capacity(sequence_capacity(count, src, *offset));
                for _ in 0..count {
                    *offset = align_offset(*offset, 4);
                    flag_seq.push(decode_complete_bitflag_internal(src, offset)?);
                }
                Ok(flag_seq)
            })?;
            Ok(CompleteBitmaskType {
                bitmask_flags,
                header,
                flag_seq,
            })
        })
    }
}

impl Cdr2Encode for MinimalBitmaskType {
    fn max_cdr2_size(&self) -> usize {
        7 + 2
            + self.header.max_cdr2_size()
            + 7
            + 4
            + self
                .flag_seq
                .iter()
                .map(|f| 3 + f.max_cdr2_size())
                .sum::<usize>()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_u16(self.bitmask_flags.0, dst, offset)?;
            self.header.encode_cdr2_le_at(dst, offset)?;
            encode_dheader_at(dst, offset, |dst, offset| {
                encode_vec_sorted(
                    &self.flag_seq,
                    dst,
                    offset,
                    |f| f.common.position,
                    |flag, dst, offset| flag.encode_cdr2_le_at(dst, offset),
                )
            })
        })
    }
}

impl Cdr2Decode for MinimalBitmaskType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let bitmask_flags: BitmaskTypeFlag = StructTypeFlag(decode_u16(src, offset)?);
            let header = MinimalBitmaskHeader::decode_cdr2_le_at(src, offset)?;
            let flag_seq = decode_dheader_at(src, offset, |src, offset| {
                let count =
                    checked_usize(decode_u32(src, offset)?, "minimal bitflag sequence length")?;
                let mut flag_seq = Vec::with_capacity(sequence_capacity(count, src, *offset));
                for _ in 0..count {
                    *offset = align_offset(*offset, 4);
                    flag_seq.push(decode_minimal_bitflag_internal(src, offset)?);
                }
                Ok(flag_seq)
            })?;
            Ok(MinimalBitmaskType {
                bitmask_flags,
                header,
                flag_seq,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::type_object::{
        BitflagFlag, CommonBitflag, CompleteBitflag, CompleteMemberDetail, MinimalBitflag,
        MinimalMemberDetail,
    };

    fn make_minimal_flag(position: u16, name_hash: u32) -> MinimalBitflag {
        MinimalBitflag {
            common: CommonBitflag {
                position,
                flags: BitflagFlag(0),
            },
            detail: MinimalMemberDetail { name_hash },
        }
    }

    /// XTypes v1.3 sec. 7.3.4.5: MinimalBitflagSeq must be emitted in
    /// ascending `position` order. Two source Vecs that differ only in
    /// element order must produce byte-identical wire output, and the
    /// decoded positions must come back sorted.
    #[test]
    fn minimal_bitmask_flags_emit_sorted_by_position() {
        let header = MinimalBitmaskHeader {
            bit_bound: 32,
            detail: MinimalTypeDetail::new(),
        };

        let unsorted = MinimalBitmaskType {
            bitmask_flags: crate::xtypes::StructTypeFlag::empty(),
            header: header.clone(),
            flag_seq: vec![
                make_minimal_flag(31, 0xFF),
                make_minimal_flag(0, 0x01),
                make_minimal_flag(15, 0x0F),
                make_minimal_flag(7, 0x07),
            ],
        };
        let sorted = MinimalBitmaskType {
            bitmask_flags: crate::xtypes::StructTypeFlag::empty(),
            header,
            flag_seq: vec![
                make_minimal_flag(0, 0x01),
                make_minimal_flag(7, 0x07),
                make_minimal_flag(15, 0x0F),
                make_minimal_flag(31, 0xFF),
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

        assert_eq!(len_unsorted, len_sorted, "wire length must match");
        assert_eq!(
            &buf_unsorted[..len_unsorted],
            &buf_sorted[..len_sorted],
            "unsorted input must produce bytes identical to sorted input \
             (ascending position ordering, Minimal)"
        );

        let (decoded, used) = MinimalBitmaskType::decode_cdr2_le(&buf_unsorted[..len_unsorted])
            .expect("decode round-trip");
        assert_eq!(used, len_unsorted, "decoder consumes full input");
        let positions: Vec<u16> = decoded.flag_seq.iter().map(|f| f.common.position).collect();
        assert_eq!(
            positions,
            vec![0, 7, 15, 31],
            "decoded positions are sorted"
        );
    }

    /// XTypes v1.3 sec. 7.3.4.5: same ascending `position` ordering guarantee
    /// for CompleteBitmaskType.
    #[test]
    fn complete_bitmask_flags_emit_sorted_by_position() {
        let header = CompleteBitmaskHeader {
            bit_bound: 16,
            detail: CompleteTypeDetail {
                type_name: "Flags".to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        };

        let make = |position: u16, name: &str| CompleteBitflag {
            common: CommonBitflag {
                position,
                flags: BitflagFlag(0),
            },
            detail: CompleteMemberDetail {
                name: name.to_string(),
                ann_builtin: None,
                ann_custom: None,
            },
        };

        let unsorted = CompleteBitmaskType {
            bitmask_flags: crate::xtypes::StructTypeFlag::empty(),
            header: header.clone(),
            flag_seq: vec![make(10, "j"), make(2, "c"), make(5, "f")],
        };
        let sorted = CompleteBitmaskType {
            bitmask_flags: crate::xtypes::StructTypeFlag::empty(),
            header,
            flag_seq: vec![make(2, "c"), make(5, "f"), make(10, "j")],
        };

        let mut buf_unsorted = vec![0u8; unsorted.max_cdr2_size()];
        let len_unsorted = unsorted
            .encode_cdr2_le(&mut buf_unsorted)
            .expect("encode unsorted");
        let mut buf_sorted = vec![0u8; sorted.max_cdr2_size()];
        let len_sorted = sorted
            .encode_cdr2_le(&mut buf_sorted)
            .expect("encode sorted");

        assert_eq!(len_unsorted, len_sorted, "wire length must match");
        assert_eq!(
            &buf_unsorted[..len_unsorted],
            &buf_sorted[..len_sorted],
            "unsorted input must produce bytes identical to sorted input \
             (ascending position ordering, Complete)"
        );
    }
}

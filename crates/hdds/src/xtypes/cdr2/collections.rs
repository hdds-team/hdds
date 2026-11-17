// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Collection type definitions
//!
//!
//! Sequence, array, map, and string types.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.5 (Collection Types)

use super::annotations::{
    applied_annotation_seq_max, decode_applied_annotation_seq, encode_applied_annotation_seq,
};
use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::helpers::{checked_usize, sequence_capacity};
use super::primitives::{
    decode_option, decode_u16, decode_u32, encode_option, encode_u16, encode_u32, encode_vec,
};
use super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// Sequence/Array/Map Collection Support (0x06, 0x07, 0x08) CDR2
// ============================================================================

/// CollectionElementFlag - Collection element flags (u16)
impl Cdr2Encode for CollectionElementFlag {
    fn max_cdr2_size(&self) -> usize {
        4 // u16 + 2-byte alignment padding
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.0, dst, offset)
    }
}

impl Cdr2Decode for CollectionElementFlag {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let flags = decode_u16(src, offset)?;
        Ok(Self(flags))
    }
}

// ============================================================================
// Collection headers, elements and objects -- DDS-XTypes 1.3 Annex B
// (spec text lines 13020-13150)
// ============================================================================
//
//   @final      CompleteElementDetail { @optional AppliedBuiltinMemberAnnotations ann_builtin;
//                                       @optional AppliedAnnotationSeq ann_custom; }
//   @final      CommonCollectionElement { CollectionElementFlag element_flags; TypeIdentifier type; }
//   @appendable CompleteCollectionElement { common; CompleteElementDetail detail; }
//   @appendable MinimalCollectionElement { common; }
//   @final      CommonCollectionHeader { LBound bound; }
//   @appendable CompleteCollectionHeader { common; @optional CompleteTypeDetail detail; }
//   @appendable MinimalCollectionHeader { common; }
//   @final      Complete/MinimalSequenceType { CollectionTypeFlag collection_flag; header; element; }
//   @final      CommonArrayHeader { LBoundSeq bound_seq; }
//   @appendable CompleteArrayHeader { common; CompleteTypeDetail detail; }
//   @appendable CompleteArrayType { CollectionTypeFlag collection_flag; header; element; }
//   @final      Complete/MinimalMapType { collection_flag; header; key; element; }

/// Upper bound of a `CompleteElementDetail`: two presence octets and the
/// annotations.
fn element_detail_max(d: &CompleteElementDetail) -> usize {
    2 + d.ann_builtin.as_ref().map_or(0, |a| a.max_cdr2_size())
        + d.ann_custom
            .as_deref()
            .map_or(0, applied_annotation_seq_max)
}

fn encode_element_detail(
    d: &CompleteElementDetail,
    dst: &mut [u8],
    offset: &mut usize,
) -> Result<(), CdrError> {
    encode_option(&d.ann_builtin, dst, offset, |a, dst, offset| {
        a.encode_cdr2_le_at(dst, offset)
    })?;
    encode_option(&d.ann_custom, dst, offset, |v, dst, offset| {
        encode_applied_annotation_seq(v, dst, offset)
    })
}

fn decode_element_detail(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteElementDetail, CdrError> {
    let ann_builtin = decode_option(src, offset, |src, offset| {
        AppliedBuiltinMemberAnnotations::decode_cdr2_le_at(src, offset).map(Box::new)
    })?;
    let ann_custom = decode_option(src, offset, decode_applied_annotation_seq)?;
    Ok(CompleteElementDetail {
        ann_builtin,
        ann_custom,
    })
}

impl Cdr2Encode for CompleteCollectionHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 + up to 3 pad) + bound + presence octet + detail
        4 + 3 + 4 + 1 + self.detail.as_ref().map_or(0, |d| d.max_cdr2_size())
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_u32(self.bound, dst, offset)?;
            encode_option(&self.detail, dst, offset, |d, dst, offset| {
                d.encode_cdr2_le_at(dst, offset)
            })
        })
    }
}

impl Cdr2Decode for CompleteCollectionHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let bound = decode_u32(src, offset)?;
            let detail = decode_option(src, offset, |src, offset| {
                CompleteTypeDetail::decode_cdr2_le_at(src, offset)
            })?;
            Ok(CompleteCollectionHeader { bound, detail })
        })
    }
}

impl Cdr2Encode for MinimalCollectionHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload (4 bytes)
        4 + 3 + 4
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_u32(self.bound, dst, offset)
        })
    }
}

impl Cdr2Decode for MinimalCollectionHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let bound = decode_u32(src, offset)?;
            Ok(Self { bound })
        })
    }
}

impl Cdr2Encode for CompleteCollectionElement {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 + up to 3 pad) + flags + identifier + detail
        4 + 3 + 2 + self.type_id.max_cdr2_size() + element_detail_max(&self.detail)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_u16(self.flags.0, dst, offset)?;
            self.type_id.encode_cdr2_le_at(dst, offset)?;
            encode_element_detail(&self.detail, dst, offset)
        })
    }
}

impl Cdr2Decode for CompleteCollectionElement {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let flags = CollectionElementFlag(decode_u16(src, offset)?);
            let type_id = decode_type_identifier_internal(src, offset)?;
            let detail = decode_element_detail(src, offset)?;
            Ok(CompleteCollectionElement {
                flags,
                type_id,
                detail,
            })
        })
    }
}

impl Cdr2Encode for MinimalCollectionElement {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + 4 + self.type_id.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_u16(self.flags.0, dst, offset)?;
            self.type_id.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for MinimalCollectionElement {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_collection_element_internal(src, offset)
    }
}

/// `MinimalCollectionElement`, @appendable: DHEADER, flags, identifier.
pub(super) fn decode_minimal_collection_element_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalCollectionElement, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let flags_value = decode_u16(src, offset)?;
        let flags = CollectionElementFlag(flags_value);
        let type_id = decode_type_identifier_internal(src, offset)?;
        Ok(MinimalCollectionElement { flags, type_id })
    })
}

// Sequences: @final { collection_flag; header; element; }

impl Cdr2Encode for CompleteSequenceType {
    fn max_cdr2_size(&self) -> usize {
        2 + self.header.max_cdr2_size() + self.element.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.collection_flag.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        self.element.encode_cdr2_le_at(dst, offset)
    }
}

impl Cdr2Decode for CompleteSequenceType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let collection_flag = CollectionTypeFlag(decode_u16(src, offset)?);
        let header = CompleteCollectionHeader::decode_cdr2_le_at(src, offset)?;
        let element = CompleteCollectionElement::decode_cdr2_le_at(src, offset)?;
        Ok(CompleteSequenceType {
            collection_flag,
            header,
            element,
        })
    }
}

impl Cdr2Encode for MinimalSequenceType {
    fn max_cdr2_size(&self) -> usize {
        2 + self.header.max_cdr2_size() + self.element.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.collection_flag.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        self.element.encode_cdr2_le_at(dst, offset)
    }
}

impl Cdr2Decode for MinimalSequenceType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let collection_flag = CollectionTypeFlag(decode_u16(src, offset)?);
        let header = MinimalCollectionHeader::decode_cdr2_le_at(src, offset)?;
        let element = decode_minimal_collection_element_internal(src, offset)?;
        Ok(MinimalSequenceType {
            collection_flag,
            header,
            element,
        })
    }
}

// Arrays: CompleteArrayType is @appendable { collection_flag; header; element; },
// CompleteArrayHeader @appendable { bound_seq; detail; }.

impl Cdr2Encode for CompleteArrayHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 + up to 3 pad) + bound_seq (length, bounds) + detail
        4 + 3 + 4 + 4 * self.bound_seq.len() + self.detail.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec(&self.bound_seq, dst, offset, |b, dst, offset| {
                encode_u32(*b, dst, offset)
            })?;
            self.detail.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for CompleteArrayHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let bound_seq = decode_bound_seq(src, offset)?;
            let detail = CompleteTypeDetail::decode_cdr2_le_at(src, offset)?;
            Ok(CompleteArrayHeader { bound_seq, detail })
        })
    }
}

/// An LBoundSeq: length, then the bounds.
fn decode_bound_seq(src: &[u8], offset: &mut usize) -> Result<Vec<u32>, CdrError> {
    let count = checked_usize(decode_u32(src, offset)?, "array bound sequence length")?;
    let mut bound_seq = Vec::new();
    for _ in 0..count {
        bound_seq.push(decode_u32(src, offset)?);
    }
    Ok(bound_seq)
}

impl Cdr2Encode for CompleteArrayType {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 + up to 3 pad) + flag + header + element
        4 + 3 + 2 + self.header.max_cdr2_size() + self.element.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_u16(self.collection_flag.0, dst, offset)?;
            self.header.encode_cdr2_le_at(dst, offset)?;
            self.element.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for CompleteArrayType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let collection_flag = CollectionTypeFlag(decode_u16(src, offset)?);
            let header = CompleteArrayHeader::decode_cdr2_le_at(src, offset)?;
            let element = CompleteCollectionElement::decode_cdr2_le_at(src, offset)?;
            Ok(CompleteArrayType {
                collection_flag,
                header,
                element,
            })
        })
    }
}

// MinimalArrayType keeps its pre-Annex-B layout: see its definition.

impl Cdr2Encode for MinimalArrayType {
    fn max_cdr2_size(&self) -> usize {
        self.header.max_cdr2_size() + self.element.max_cdr2_size() + 4 + (self.bound_seq.len() * 4)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        self.header.encode_cdr2_le_at(dst, offset)?;
        self.element.encode_cdr2_le_at(dst, offset)?;
        encode_vec(&self.bound_seq, dst, offset, |item, dst, offset| {
            encode_u32(*item, dst, offset)
        })?;
        Ok(())
    }
}

impl Cdr2Decode for MinimalArrayType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        // Decode header
        let header = MinimalCollectionHeader::decode_cdr2_le_at(src, offset)?;

        // Decode element
        let element = decode_minimal_collection_element_internal(src, offset)?;

        // Decode bound_seq
        let bounds_count = decode_u32(src, offset)?;
        let capacity = checked_usize(bounds_count, "collection bound sequence length")?;
        let mut bound_seq = Vec::with_capacity(sequence_capacity(capacity, src, *offset));
        for _ in 0..capacity {
            let bound = decode_u32(src, offset)?;
            bound_seq.push(bound);
        }

        Ok(MinimalArrayType {
            header,
            element,
            bound_seq,
        })
    }
}

// Maps: @final { collection_flag; header; key; element; }

impl Cdr2Encode for CompleteMapType {
    fn max_cdr2_size(&self) -> usize {
        2 + self.header.max_cdr2_size() + self.key.max_cdr2_size() + self.element.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.collection_flag.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        self.key.encode_cdr2_le_at(dst, offset)?;
        self.element.encode_cdr2_le_at(dst, offset)
    }
}

impl Cdr2Decode for CompleteMapType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let collection_flag = CollectionTypeFlag(decode_u16(src, offset)?);
        let header = CompleteCollectionHeader::decode_cdr2_le_at(src, offset)?;
        let key = CompleteCollectionElement::decode_cdr2_le_at(src, offset)?;
        let element = CompleteCollectionElement::decode_cdr2_le_at(src, offset)?;
        Ok(CompleteMapType {
            collection_flag,
            header,
            key,
            element,
        })
    }
}

impl Cdr2Encode for MinimalMapType {
    fn max_cdr2_size(&self) -> usize {
        2 + self.header.max_cdr2_size() + self.key.max_cdr2_size() + self.element.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.collection_flag.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        self.key.encode_cdr2_le_at(dst, offset)?;
        self.element.encode_cdr2_le_at(dst, offset)
    }
}

impl Cdr2Decode for MinimalMapType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let collection_flag = CollectionTypeFlag(decode_u16(src, offset)?);
        let header = MinimalCollectionHeader::decode_cdr2_le_at(src, offset)?;
        let key = decode_minimal_collection_element_internal(src, offset)?;
        let element = decode_minimal_collection_element_internal(src, offset)?;
        Ok(MinimalMapType {
            collection_flag,
            header,
            key,
            element,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::{TypeIdentifier, TypeKind};

    fn element() -> CompleteCollectionElement {
        CompleteCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
            detail: CompleteElementDetail::default(),
        }
    }

    fn minimal_element() -> MinimalCollectionElement {
        MinimalCollectionElement {
            flags: CollectionElementFlag::empty(),
            type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
        }
    }

    /// Encode at stream offset 1, as behind the TypeObject discriminator,
    /// and decode back; return the octets.
    fn round_trip<T: Cdr2Encode + Cdr2Decode + PartialEq + std::fmt::Debug>(v: &T) -> Vec<u8> {
        let mut buf = vec![0u8; 1 + v.max_cdr2_size()];
        let mut off = 1usize;
        v.encode_cdr2_le_at(&mut buf, &mut off).expect("encode");
        let mut back_off = 1usize;
        let back = T::decode_cdr2_le_at(&buf[..off], &mut back_off).expect("decode");
        assert_eq!((&back, back_off), (v, off));
        buf.truncate(off);
        buf
    }

    /// `collection_flag` is a field of its own, the first of the object
    /// (Annex B): a flag of 0 falls where the header's alignment padding
    /// would be, so only a non-zero one shows it is written and read.
    #[test]
    fn the_collection_flag_is_written_and_read() {
        let flag = CollectionTypeFlag(0x1234);
        let header = CompleteCollectionHeader {
            bound: 3,
            detail: None,
        };
        let minimal_header = MinimalCollectionHeader { bound: 3 };
        for bytes in [
            round_trip(&CompleteSequenceType {
                collection_flag: flag,
                header: header.clone(),
                element: element(),
            }),
            round_trip(&MinimalSequenceType {
                collection_flag: flag,
                header: minimal_header.clone(),
                element: minimal_element(),
            }),
            round_trip(&CompleteMapType {
                collection_flag: flag,
                header,
                key: element(),
                element: element(),
            }),
            round_trip(&MinimalMapType {
                collection_flag: flag,
                header: minimal_header,
                key: minimal_element(),
                element: minimal_element(),
            }),
        ] {
            assert_eq!(&bytes[2..4], &[0x34, 0x12], "{bytes:02x?}");
        }
        let array = round_trip(&CompleteArrayType {
            collection_flag: flag,
            header: CompleteArrayHeader {
                bound_seq: vec![2],
                detail: CompleteTypeDetail::new("A"),
            },
            element: element(),
        });
        // Behind the array's own DHEADER.
        assert_eq!(&array[8..10], &[0x34, 0x12], "{array:02x?}");
    }

    /// The element detail carries annotations: a builtin one round-trips
    /// and is written behind the identifier.
    #[test]
    fn a_collection_element_carries_its_annotations() {
        let mut e = element();
        e.detail.ann_builtin = Some(Box::new(AppliedBuiltinMemberAnnotations {
            unit: Some("m".to_string()),
            ..Default::default()
        }));
        let bytes = round_trip(&e);
        assert_eq!(
            bytes[10], 0x04,
            "TK_INT32 identifier, behind DHEADER and flags"
        );
        assert_eq!(bytes[11], 0x01, "ann_builtin present");
    }
}

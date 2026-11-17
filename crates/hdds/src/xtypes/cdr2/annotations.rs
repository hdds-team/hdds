// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Annotation type definitions
//!
//!
//! Complete and Minimal annotation types, headers, and parameters.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.10 (Annotation Types)

use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::helpers::{checked_usize, sequence_capacity};
use super::primitives::{
    align_offset, decode_aligned, decode_bool, decode_i16, decode_i32, decode_option,
    decode_string, decode_u16, decode_u32, decode_u8, encode_aligned, encode_bool, encode_i16,
    encode_i32, encode_option, encode_string, encode_u16, encode_u32, encode_u8, encode_vec,
};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::{TypeIdentifier, TypeKind};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CompleteAnnotationType / MinimalAnnotationType CDR2 (0x0A)
// ============================================================================

// AnnotationParameterFlag
impl Cdr2Encode for AnnotationParameterFlag {
    fn max_cdr2_size(&self) -> usize {
        4 // 2 bytes + alignment
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.0, dst, offset)
    }
}

impl Cdr2Decode for AnnotationParameterFlag {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let flags = decode_u16(src, offset)?;
        Ok(AnnotationParameterFlag(flags))
    }
}

// AnnotationParameterValue (discriminated union enum).
// DDS-XTypes 1.3 Annex B, spec text lines 12609-12654: `@extensibility(FINAL)
// union AnnotationParameterValue switch (octet)`, the case labels being the
// TK_* of the value, and a `default` case carrying the empty `@mutable`
// struct ExtendedAnnotationParameterValue (lines 12601-12604). FINAL: the
// octet discriminator, then the member at its own alignment, no DHEADER.

/// The case labels of AnnotationParameterValue other than `default`.
const PARAMETER_VALUE_LABELS: [TypeKind; 18] = [
    TypeKind::TK_BOOLEAN,
    TypeKind::TK_BYTE,
    TypeKind::TK_INT8,
    TypeKind::TK_UINT8,
    TypeKind::TK_INT16,
    TypeKind::TK_UINT16,
    TypeKind::TK_INT32,
    TypeKind::TK_UINT32,
    TypeKind::TK_INT64,
    TypeKind::TK_UINT64,
    TypeKind::TK_FLOAT32,
    TypeKind::TK_FLOAT64,
    TypeKind::TK_FLOAT128,
    TypeKind::TK_CHAR8,
    TypeKind::TK_CHAR16,
    TypeKind::TK_ENUM,
    TypeKind::TK_STRING8,
    TypeKind::TK_STRING16,
];

fn is_parameter_value_label(discriminator: u8) -> bool {
    PARAMETER_VALUE_LABELS
        .iter()
        .any(|k| k.to_u8() == discriminator)
}

impl Cdr2Encode for AnnotationParameterValue {
    fn max_cdr2_size(&self) -> usize {
        // The discriminator, up to 3 octets of padding, the member.
        4 + match self {
            AnnotationParameterValue::Boolean(_)
            | AnnotationParameterValue::Byte(_)
            | AnnotationParameterValue::Int8(_)
            | AnnotationParameterValue::Uint8(_)
            | AnnotationParameterValue::Char8(_) => 1,
            AnnotationParameterValue::Int16(_)
            | AnnotationParameterValue::Uint16(_)
            | AnnotationParameterValue::Char16(_) => 2,
            AnnotationParameterValue::Int32(_)
            | AnnotationParameterValue::Uint32(_)
            | AnnotationParameterValue::Float32(_)
            | AnnotationParameterValue::Enumerated(_) => 4,
            AnnotationParameterValue::Int64(_)
            | AnnotationParameterValue::Uint64(_)
            | AnnotationParameterValue::Float64(_) => 8,
            AnnotationParameterValue::Float128(_) => 16,
            AnnotationParameterValue::String(s) => 4 + s.len() + 1,
            AnnotationParameterValue::String16(units) => 4 + 2 * units.len(),
            AnnotationParameterValue::Extended { body, .. } => 4 + body.len(),
        }
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        type V = AnnotationParameterValue;
        let label =
            |k: TypeKind, dst: &mut [u8], offset: &mut usize| encode_u8(k.to_u8(), dst, offset);
        match self {
            V::Boolean(b) => {
                label(TypeKind::TK_BOOLEAN, dst, offset)?;
                encode_bool(*b, dst, offset)
            }
            V::Byte(v) => {
                label(TypeKind::TK_BYTE, dst, offset)?;
                encode_u8(*v, dst, offset)
            }
            V::Int8(v) => {
                label(TypeKind::TK_INT8, dst, offset)?;
                encode_aligned(&v.to_le_bytes(), 1, dst, offset)
            }
            V::Uint8(v) => {
                label(TypeKind::TK_UINT8, dst, offset)?;
                encode_u8(*v, dst, offset)
            }
            V::Int16(v) => {
                label(TypeKind::TK_INT16, dst, offset)?;
                encode_i16(*v, dst, offset)
            }
            V::Uint16(v) => {
                label(TypeKind::TK_UINT16, dst, offset)?;
                encode_u16(*v, dst, offset)
            }
            V::Int32(v) => {
                label(TypeKind::TK_INT32, dst, offset)?;
                encode_i32(*v, dst, offset)
            }
            V::Uint32(v) => {
                label(TypeKind::TK_UINT32, dst, offset)?;
                encode_u32(*v, dst, offset)
            }
            V::Int64(v) => {
                label(TypeKind::TK_INT64, dst, offset)?;
                encode_aligned(&v.to_le_bytes(), 4, dst, offset)
            }
            V::Uint64(v) => {
                label(TypeKind::TK_UINT64, dst, offset)?;
                encode_aligned(&v.to_le_bytes(), 4, dst, offset)
            }
            V::Float32(bits) => {
                label(TypeKind::TK_FLOAT32, dst, offset)?;
                encode_u32(*bits, dst, offset)
            }
            V::Float64(bits) => {
                label(TypeKind::TK_FLOAT64, dst, offset)?;
                encode_aligned(&bits.to_le_bytes(), 4, dst, offset)
            }
            V::Float128(octets) => {
                label(TypeKind::TK_FLOAT128, dst, offset)?;
                encode_aligned(octets, 4, dst, offset)
            }
            V::Char8(v) => {
                label(TypeKind::TK_CHAR8, dst, offset)?;
                encode_u8(*v, dst, offset)
            }
            V::Char16(v) => {
                label(TypeKind::TK_CHAR16, dst, offset)?;
                encode_u16(*v, dst, offset)
            }
            V::Enumerated(v) => {
                label(TypeKind::TK_ENUM, dst, offset)?;
                encode_i32(*v, dst, offset)
            }
            V::String(s) => {
                label(TypeKind::TK_STRING8, dst, offset)?;
                encode_string(s, dst, offset)
            }
            V::String16(units) => {
                // DDS-XTypes 1.3 7.4.1.1.2: the length of a String<Char16> is
                // its size in octets, two per UTF-16 unit, no terminator.
                label(TypeKind::TK_STRING16, dst, offset)?;
                let len = units
                    .len()
                    .checked_mul(2)
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| CdrError::Other("string16 too long".into()))?;
                encode_u32(len, dst, offset)?;
                for unit in units {
                    encode_u16(*unit, dst, offset)?;
                }
                Ok(())
            }
            V::Extended {
                discriminator,
                body,
            } => {
                // Under a case label it would decode as that case.
                if is_parameter_value_label(*discriminator) {
                    return Err(CdrError::Other(format!(
                        "extended AnnotationParameterValue under the case label {discriminator:#04x}"
                    )));
                }
                encode_u8(*discriminator, dst, offset)?;
                let len = u32::try_from(body.len())
                    .map_err(|_| CdrError::Other("extended value too long".into()))?;
                encode_u32(len, dst, offset)?;
                encode_aligned(body, 1, dst, offset)
            }
        }
    }
}

impl Cdr2Decode for AnnotationParameterValue {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        type V = AnnotationParameterValue;
        let discriminator = decode_u8(src, offset)?;
        let is = |k: TypeKind| discriminator == k.to_u8();
        let value = if is(TypeKind::TK_BOOLEAN) {
            V::Boolean(decode_bool(src, offset)?)
        } else if is(TypeKind::TK_BYTE) {
            V::Byte(decode_u8(src, offset)?)
        } else if is(TypeKind::TK_INT8) {
            V::Int8(i8::from_le_bytes(decode_aligned::<1>(src, 1, offset)?))
        } else if is(TypeKind::TK_UINT8) {
            V::Uint8(decode_u8(src, offset)?)
        } else if is(TypeKind::TK_INT16) {
            V::Int16(decode_i16(src, offset)?)
        } else if is(TypeKind::TK_UINT16) {
            V::Uint16(decode_u16(src, offset)?)
        } else if is(TypeKind::TK_INT32) {
            V::Int32(decode_i32(src, offset)?)
        } else if is(TypeKind::TK_UINT32) {
            V::Uint32(decode_u32(src, offset)?)
        } else if is(TypeKind::TK_INT64) {
            V::Int64(i64::from_le_bytes(decode_aligned::<8>(src, 4, offset)?))
        } else if is(TypeKind::TK_UINT64) {
            V::Uint64(u64::from_le_bytes(decode_aligned::<8>(src, 4, offset)?))
        } else if is(TypeKind::TK_FLOAT32) {
            V::Float32(decode_u32(src, offset)?)
        } else if is(TypeKind::TK_FLOAT64) {
            V::Float64(u64::from_le_bytes(decode_aligned::<8>(src, 4, offset)?))
        } else if is(TypeKind::TK_FLOAT128) {
            V::Float128(decode_aligned::<16>(src, 4, offset)?)
        } else if is(TypeKind::TK_CHAR8) {
            V::Char8(decode_u8(src, offset)?)
        } else if is(TypeKind::TK_CHAR16) {
            V::Char16(decode_u16(src, offset)?)
        } else if is(TypeKind::TK_ENUM) {
            V::Enumerated(decode_i32(src, offset)?)
        } else if is(TypeKind::TK_STRING8) {
            V::String(decode_string(src, offset)?)
        } else if is(TypeKind::TK_STRING16) {
            let len = checked_usize(decode_u32(src, offset)?, "AnnotationParameterValue length")?;
            if len % 2 != 0 {
                return Err(CdrError::Other(format!(
                    "string16 length {len} is not a whole number of UTF-16 units"
                )));
            }
            // Grown unit by unit: every unit is read from the input, so a
            // length beyond it fails at its end without allocating for it.
            let mut units = Vec::new();
            for _ in 0..len / 2 {
                units.push(decode_u16(src, offset)?);
            }
            V::String16(units)
        } else {
            // `default`: ExtendedAnnotationParameterValue, @mutable, so
            // delimited by its DHEADER.
            let len = checked_usize(decode_u32(src, offset)?, "AnnotationParameterValue length")?;
            let end = offset
                .checked_add(len)
                .filter(|end| *end <= src.len())
                .ok_or(CdrError::UnexpectedEof)?;
            let body = src[*offset..end].to_vec();
            *offset = end;
            V::Extended {
                discriminator,
                body,
            }
        };
        Ok(value)
    }
}

// Annotation Headers -- `@extensibility(APPENDABLE)`, DDS-XTypes 1.3 Annex B
// (spec text lines 12937-12946): the Complete header is the annotation's
// QualifiedTypeName alone, the Minimal header is empty.
impl Cdr2Encode for CompleteAnnotationHeader {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + string length + name + NUL
        4 + 3 + 4 + self.annotation_name.len() + 1
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_string(&self.annotation_name, dst, offset)
        })
    }
}

impl Cdr2Decode for CompleteAnnotationHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let annotation_name = decode_string(src, offset)?;
            Ok(CompleteAnnotationHeader { annotation_name })
        })
    }
}

impl Cdr2Encode for MinimalAnnotationHeader {
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

impl Cdr2Decode for MinimalAnnotationHeader {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let detail = MinimalTypeDetail::decode_cdr2_le_at(src, offset)?;
            Ok(MinimalAnnotationHeader { detail })
        })
    }
}

// CommonAnnotationParameter
impl Cdr2Encode for CommonAnnotationParameter {
    fn max_cdr2_size(&self) -> usize {
        self.member_flags.max_cdr2_size() + self.member_type_id.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        self.member_flags.encode_cdr2_le_at(dst, offset)?;
        self.member_type_id.encode_cdr2_le_at(dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for CommonAnnotationParameter {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let member_flags = AnnotationParameterFlag::decode_cdr2_le_at(src, offset)?;
        let member_type_id = TypeIdentifier::decode_cdr2_le_at(src, offset)?;
        Ok(CommonAnnotationParameter {
            member_flags,
            member_type_id,
        })
    }
}

// CompleteAnnotationParameter -- `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
// `default_value` is not @optional in Annex B (spec text lines 12915-12920).
impl Cdr2Encode for CompleteAnnotationParameter {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + common + name (up to 3 pad,
        // length, octets, NUL) + value
        4 + 3
            + self.common.max_cdr2_size()
            + 3
            + 4
            + self.name.len()
            + 1
            + self.default_value.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            encode_string(&self.name, dst, offset)?;
            self.default_value.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for CompleteAnnotationParameter {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let common = CommonAnnotationParameter::decode_cdr2_le_at(src, offset)?;
            let name = decode_string(src, offset)?;
            let default_value = AnnotationParameterValue::decode_cdr2_le_at(src, offset)?;
            Ok(CompleteAnnotationParameter {
                common,
                name,
                default_value,
            })
        })
    }
}

// MinimalAnnotationParameter -- `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
// `name_hash` is a NameHash, octet[4]: four octets with no alignment of
// their own; `default_value` is not @optional (spec text lines 12926-12931).
impl Cdr2Encode for MinimalAnnotationParameter {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + common + NameHash + value
        4 + 3 + self.common.max_cdr2_size() + 4 + self.default_value.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            for b in self.name_hash.to_le_bytes() {
                encode_u8(b, dst, offset)?;
            }
            self.default_value.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for MinimalAnnotationParameter {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let common = CommonAnnotationParameter::decode_cdr2_le_at(src, offset)?;
            let mut name_hash = [0u8; 4];
            for b in &mut name_hash {
                *b = decode_u8(src, offset)?;
            }
            let name_hash = u32::from_le_bytes(name_hash);
            let default_value = AnnotationParameterValue::decode_cdr2_le_at(src, offset)?;
            Ok(MinimalAnnotationParameter {
                common,
                name_hash,
                default_value,
            })
        })
    }
}

// ============================================================================
// AppliedAnnotationParameter / AppliedAnnotation / AppliedAnnotationSeq
// ============================================================================
//
// DDS-XTypes 1.3 Annex B (spec text lines 12658-12677):
//
//   @extensibility(APPENDABLE) @nested
//   struct AppliedAnnotationParameter { NameHash paramname_hash; AnnotationParameterValue value; };
//   // Sorted by AppliedAnnotationParameter.paramname_hash
//   typedef sequence<AppliedAnnotationParameter> AppliedAnnotationParameterSeq;
//
//   @extensibility(APPENDABLE) @nested
//   struct AppliedAnnotation { TypeIdentifier annotation_typeid; @optional AppliedAnnotationParameterSeq param_seq; };
//   // Sorted by AppliedAnnotation.annotation_typeid
//   typedef sequence<AppliedAnnotation> AppliedAnnotationSeq;
//
// Both structs are APPENDABLE, so each one sits behind a DHEADER, and a
// sequence of either (element type not primitive) is itself preceded by a
// DHEADER (XCDR2 7.4.3.5.3). Fast DDS 3.4's serializer writes exactly this
// (wire test below).
// The encoder keeps the source order of both sequences: the "Sorted by"
// order is the builder's to establish.

impl Cdr2Encode for AppliedAnnotationParameter {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 + up to 3 pad) + NameHash (4) + value
        4 + 3 + 4 + self.value.max_cdr2_size()
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            // NameHash = octet[4]: four octets, no alignment of its own.
            for b in self.paramname_hash.to_le_bytes() {
                encode_u8(b, dst, offset)?;
            }
            self.value.encode_cdr2_le_at(dst, offset)
        })
    }
}

impl Cdr2Decode for AppliedAnnotationParameter {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let mut name_hash = [0u8; 4];
            for b in &mut name_hash {
                *b = decode_u8(src, offset)?;
            }
            let value = AnnotationParameterValue::decode_cdr2_le_at(src, offset)?;
            Ok(AppliedAnnotationParameter {
                paramname_hash: u32::from_le_bytes(name_hash),
                value,
            })
        })
    }
}

/// Upper bound of a DHEADER-delimited sequence of `items`.
fn delimited_seq_max<T: Cdr2Encode>(items: &[T]) -> usize {
    // DHEADER (4 + up to 3 pad) + count (4) + each element (up to 3 pad)
    7 + 4 + items.iter().map(|i| 3 + i.max_cdr2_size()).sum::<usize>()
}

/// Decode the count and the 4-aligned elements of a DHEADER-delimited
/// sequence (the DHEADER is read by the caller's `decode_dheader_at`).
fn decode_delimited_elements<T: Cdr2Decode>(
    src: &[u8],
    offset: &mut usize,
    context: &str,
) -> Result<Vec<T>, CdrError> {
    let count = checked_usize(decode_u32(src, offset)?, context)?;
    let mut items = Vec::with_capacity(sequence_capacity(count, src, *offset));
    for _ in 0..count {
        *offset = align_offset(*offset, 4);
        if *offset > src.len() {
            return Err(CdrError::UnexpectedEof);
        }
        items.push(T::decode_cdr2_le_at(src, offset)?);
    }
    Ok(items)
}

impl Cdr2Encode for AppliedAnnotation {
    fn max_cdr2_size(&self) -> usize {
        let seq = self.param_seq.as_deref().map_or(0, delimited_seq_max);
        // DHEADER (4 + up to 3 pad) + identifier + presence octet + sequence
        4 + 3 + self.annotation_type_id.max_cdr2_size() + 1 + seq
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.annotation_type_id.encode_cdr2_le_at(dst, offset)?;
            encode_option(&self.param_seq, dst, offset, |params, dst, offset| {
                encode_dheader_at(dst, offset, |dst, offset| {
                    encode_vec(params, dst, offset, |param, dst, offset| {
                        param.encode_cdr2_le_at(dst, offset)
                    })
                })
            })
        })
    }
}

impl Cdr2Decode for AppliedAnnotation {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_dheader_at(src, offset, |src, offset| {
            let annotation_type_id = TypeIdentifier::decode_cdr2_le_at(src, offset)?;
            let param_seq = decode_option(src, offset, |src, offset| {
                decode_dheader_at(src, offset, |src, offset| {
                    decode_delimited_elements(src, offset, "AppliedAnnotationParameterSeq length")
                })
            })?;
            Ok(AppliedAnnotation {
                annotation_type_id,
                param_seq,
            })
        })
    }
}

/// Upper bound of an `AppliedAnnotationSeq`.
pub(super) fn applied_annotation_seq_max(anns: &[AppliedAnnotation]) -> usize {
    delimited_seq_max(anns)
}

/// Encode an `AppliedAnnotationSeq`: DHEADER, count, the 4-aligned
/// APPENDABLE `AppliedAnnotation`s, in source order.
pub(super) fn encode_applied_annotation_seq(
    anns: &[AppliedAnnotation],
    dst: &mut [u8],
    offset: &mut usize,
) -> Result<(), CdrError> {
    encode_dheader_at(dst, offset, |dst, offset| {
        encode_vec(anns, dst, offset, |ann, dst, offset| {
            ann.encode_cdr2_le_at(dst, offset)
        })
    })
}

/// Decode an `AppliedAnnotationSeq` (see [`encode_applied_annotation_seq`]).
pub(super) fn decode_applied_annotation_seq(
    src: &[u8],
    offset: &mut usize,
) -> Result<Vec<AppliedAnnotation>, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        decode_delimited_elements(src, offset, "AppliedAnnotationSeq length")
    })
}

// Complete/Minimal AnnotationType -- `@extensibility(FINAL)`, DDS-XTypes 1.3
// Annex B (spec text lines 12953-12964): the AnnotationTypeFlag, the header,
// the parameter sequence. The parameters are @appendable, so the sequence is
// DHEADER-delimited (XCDR2 7.4.3.5.3). Annex B orders the Complete sequence
// by `name` and the Minimal one by `name_hash`; the encoder establishes the
// order, so two permutations of one set give the same bytes.
impl Cdr2Encode for CompleteAnnotationType {
    fn max_cdr2_size(&self) -> usize {
        // flag (2) + header + parameter sequence
        2 + 2 + self.header.max_cdr2_size() + delimited_seq_max(&self.member_seq)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.annotation_flag.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        let mut params: Vec<&CompleteAnnotationParameter> = self.member_seq.iter().collect();
        params.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec(&params, dst, offset, |param, dst, offset| {
                param.encode_cdr2_le_at(dst, offset)
            })
        })
    }
}

impl Cdr2Decode for CompleteAnnotationType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let annotation_flag = AnnotationTypeFlag(decode_u16(src, offset)?);
        let header = CompleteAnnotationHeader::decode_cdr2_le_at(src, offset)?;
        let member_seq = decode_dheader_at(src, offset, |src, offset| {
            decode_delimited_elements(src, offset, "annotation parameter sequence length")
        })?;
        Ok(CompleteAnnotationType {
            annotation_flag,
            header,
            member_seq,
        })
    }
}

impl Cdr2Encode for MinimalAnnotationType {
    fn max_cdr2_size(&self) -> usize {
        // flag (2) + header + parameter sequence
        2 + 2 + self.header.max_cdr2_size() + delimited_seq_max(&self.member_seq)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.annotation_flag.0, dst, offset)?;
        self.header.encode_cdr2_le_at(dst, offset)?;
        // NameHash is octet[4]: ordered as octets, which for the
        // little-endian `u32` held here is the order of its LE bytes.
        let mut params: Vec<&MinimalAnnotationParameter> = self.member_seq.iter().collect();
        params.sort_by_key(|p| p.name_hash.to_le_bytes());
        encode_dheader_at(dst, offset, |dst, offset| {
            encode_vec(&params, dst, offset, |param, dst, offset| {
                param.encode_cdr2_le_at(dst, offset)
            })
        })
    }
}

impl Cdr2Decode for MinimalAnnotationType {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        let annotation_flag = AnnotationTypeFlag(decode_u16(src, offset)?);
        let header = MinimalAnnotationHeader::decode_cdr2_le_at(src, offset)?;
        let member_seq = decode_dheader_at(src, offset, |src, offset| {
            decode_delimited_elements(src, offset, "minimal annotation parameter sequence length")
        })?;
        Ok(MinimalAnnotationType {
            annotation_flag,
            header,
            member_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xtypes::type_object::compute_name_hash;

    /// Lock the wire-level discriminator byte emitted by each supported
    /// `AnnotationParameterValue` variant against the OMG DDS-XTypes
    /// v1.3 sec. 7.3.4.8.10 IDL union case labels. Any drift in these
    /// bytes would silently break cross-vendor annotation matching, so
    /// the assertions are the spec citation reified as a test.
    #[test]
    fn annotation_param_value_discriminators_match_xtypes_v1_3_spec() {
        let mut buf = [0u8; 64];

        let len = AnnotationParameterValue::Boolean(true)
            .encode_cdr2_le(&mut buf)
            .expect("encode bool");
        assert_eq!(buf[0], 0x01, "Boolean must be TK_BOOLEAN=0x01");
        assert!(len >= 2);

        let len = AnnotationParameterValue::Int32(42)
            .encode_cdr2_le(&mut buf)
            .expect("encode i32");
        assert_eq!(buf[0], 0x04, "Int32 must be TK_INT32=0x04");
        assert!(len >= 5);

        let len = AnnotationParameterValue::String("x".to_string())
            .encode_cdr2_le(&mut buf)
            .expect("encode string");
        assert_eq!(buf[0], 0x20, "String must be TK_STRING8=0x20");
        assert!(len >= 5);

        let len = AnnotationParameterValue::Enumerated(7)
            .encode_cdr2_le(&mut buf)
            .expect("encode enum");
        assert_eq!(buf[0], 0x40, "Enumerated must be TK_ENUM=0x40");
        assert!(len >= 5);
    }

    /// Round-trip the 4 supported variants through encode + decode to
    /// confirm symmetry of the spec discriminator change.
    #[test]
    fn annotation_param_value_round_trip_supported_variants() {
        let cases = [
            AnnotationParameterValue::Boolean(true),
            AnnotationParameterValue::Boolean(false),
            AnnotationParameterValue::Int32(0),
            AnnotationParameterValue::Int32(-1),
            AnnotationParameterValue::Int32(i32::MAX),
            AnnotationParameterValue::String(String::new()),
            AnnotationParameterValue::String("hello".to_string()),
            AnnotationParameterValue::Enumerated(0),
            AnnotationParameterValue::Enumerated(255),
        ];
        for case in cases {
            let mut buf = vec![0u8; 256];
            let len = case.encode_cdr2_le(&mut buf).expect("encode succeeds");
            let (decoded, used) =
                AnnotationParameterValue::decode_cdr2_le(&buf[..len]).expect("decode succeeds");
            assert_eq!(decoded, case, "round-trip preserves value");
            assert_eq!(used, len, "decoder consumes all bytes");
        }
    }

    /// Every discriminator that is not a case label is the `default` case,
    /// ExtendedAnnotationParameterValue, delimited by its DHEADER: it decodes
    /// with its body and re-encodes to the same octets. Among them TK_NONE,
    /// TK_ALIAS, TK_BITMASK and TK_STRUCTURE, which are TypeKinds but not
    /// case labels.
    #[test]
    fn a_discriminator_that_is_no_case_label_is_the_extended_value() {
        for disc in [0x00u8, 0x30, 0x41, 0x51, 0x7F, 0xFF] {
            let wire = [disc, 0, 0, 0, 2, 0, 0, 0, 0xAA, 0xBB];
            let (value, used) = AnnotationParameterValue::decode_cdr2_le(&wire).expect("decode");
            assert_eq!(
                value,
                AnnotationParameterValue::Extended {
                    discriminator: disc,
                    body: vec![0xAA, 0xBB],
                },
                "{disc:#04x}"
            );
            assert_eq!(used, wire.len());
            let mut buf = vec![0u8; value.max_cdr2_size()];
            let len = value.encode_cdr2_le(&mut buf).expect("encode");
            assert_eq!(&buf[..len], &wire[..], "{disc:#04x}");
        }
    }

    /// An extended value under a case label would be read back as that
    /// case: it is refused at encode.
    #[test]
    fn an_extended_value_under_a_case_label_is_refused() {
        for label in PARAMETER_VALUE_LABELS {
            let value = AnnotationParameterValue::Extended {
                discriminator: label.to_u8(),
                body: Vec::new(),
            };
            let mut buf = vec![0u8; value.max_cdr2_size()];
            assert!(value.encode_cdr2_le(&mut buf).is_err(), "{label:?}");
        }
    }

    /// Lengths the input cannot hold are refused, never read past: a
    /// string16 of an odd number of octets, and a string16 or extended body
    /// longer than what remains.
    #[test]
    fn a_parameter_value_length_beyond_the_input_is_refused() {
        for wire in [
            &[0x21u8, 0, 0, 0, 3, 0, 0, 0, 0x68, 0, 0][..],
            &[0x21, 0, 0, 0, 4, 0, 0, 0, 0x68, 0][..],
            &[0x7F, 0, 0, 0, 3, 0, 0, 0, 0xAA, 0xBB][..],
            &[0x0B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..],
            &[0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..],
        ] {
            assert!(
                AnnotationParameterValue::decode_cdr2_le(wire).is_err(),
                "{wire:02x?}"
            );
        }
    }

    /// The values the vectors decode to, case by case: the discriminator
    /// selects the variant and the value is read at its own width.
    #[test]
    fn every_parameter_value_case_decodes_to_its_variant() {
        use AnnotationParameterValue as V;
        let expected = [
            V::Boolean(true),
            V::Byte(0xAB),
            V::Int8(-2),
            V::Uint8(0xFE),
            V::Int16(-300),
            V::Uint16(60000),
            V::Int32(-3),
            V::Uint32(4_000_000_000),
            V::Int64(-5_000_000_000),
            V::Uint64(18_000_000_000_000_000_000),
            V::float32(1.5),
            V::float64(2.25),
            V::Float128({
                let mut o = [0u8; 16];
                o[14] = 0xFF;
                o[15] = 0x3F;
                o
            }),
            V::Char8(b'Z'),
            V::Char16(0x00E9),
            V::Enumerated(5),
            V::String("abc".to_string()),
            V::String16(vec![0x0068, 0x00E9]),
            V::Extended {
                discriminator: 0x7F,
                body: Vec::new(),
            },
        ];
        assert_eq!(expected.len(), PARAMETER_VALUE_VECTORS.len());
        for ((_, wire_hex), value) in PARAMETER_VALUE_VECTORS.iter().zip(expected) {
            check(&value, wire_hex);
        }
    }

    #[cfg(feature = "xtypes")]
    fn make_minimal_param(name: &str) -> MinimalAnnotationParameter {
        MinimalAnnotationParameter {
            common: CommonAnnotationParameter {
                member_flags: AnnotationParameterFlag(0),
                member_type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
            },
            name_hash: compute_name_hash(name),
            default_value: AnnotationParameterValue::Int32(0),
        }
    }

    /// DDS-XTypes 1.3 Annex B: MinimalAnnotationParameterSeq is ordered by
    /// name_hash, a NameHash (octet[4]), so in the order of its octets. The MD5-derived hash makes
    /// the sort key opaque, so the test seeds names whose hashes happen
    /// to differ and asserts that byte output is invariant under input
    /// permutations.
    ///
    /// Gated on `xtypes` because the assertion (two permutations of the
    /// same set yield identical bytes) depends on distinct non-zero
    /// hashes. Under `--no-default-features` all `compute_name_hash`
    /// values collapse to 0, the stable sort preserves source order,
    /// and the two permutations encode to different bytes -- a correct
    /// outcome for that degenerate configuration, but not what this
    /// test is meant to lock.
    #[cfg(feature = "xtypes")]
    #[test]
    fn minimal_annotation_params_emit_sorted_by_name_hash() {
        let header = MinimalAnnotationHeader {
            detail: MinimalTypeDetail::new(),
        };

        let names = ["zeta", "alpha", "mu", "kappa"];
        let mut perm_a: Vec<MinimalAnnotationParameter> =
            names.iter().map(|n| make_minimal_param(n)).collect();
        let mut perm_b = perm_a.clone();
        perm_b.reverse(); // different source order, same set

        let type_a = MinimalAnnotationType {
            annotation_flag: AnnotationTypeFlag::default(),
            header: header.clone(),
            member_seq: perm_a.clone(),
        };
        let type_b = MinimalAnnotationType {
            annotation_flag: AnnotationTypeFlag::default(),
            header,
            member_seq: perm_b.clone(),
        };

        let mut buf_a = vec![0u8; type_a.max_cdr2_size()];
        let len_a = type_a.encode_cdr2_le(&mut buf_a).expect("encode perm_a");
        let mut buf_b = vec![0u8; type_b.max_cdr2_size()];
        let len_b = type_b.encode_cdr2_le(&mut buf_b).expect("encode perm_b");

        assert_eq!(len_a, len_b, "wire length must match across permutations");
        assert_eq!(
            &buf_a[..len_a],
            &buf_b[..len_b],
            "two source permutations must produce identical bytes \
             (name_hash ordering enforcement)"
        );

        // Round-trip: the decoded member_seq must be in ascending
        // name_hash order.
        let (decoded, used) =
            MinimalAnnotationType::decode_cdr2_le(&buf_a[..len_a]).expect("decode round-trip");
        assert_eq!(used, len_a, "decoder consumes full input");
        let hashes: Vec<[u8; 4]> = decoded
            .member_seq
            .iter()
            .map(|p| p.name_hash.to_le_bytes())
            .collect();
        let mut sorted_hashes = hashes.clone();
        sorted_hashes.sort();
        assert_eq!(
            hashes, sorted_hashes,
            "decoded name_hashes are in ascending octet order"
        );

        // Sanity: with 4 distinct names whose hashes are unlikely to
        // collide, all 4 should be present.
        assert_eq!(decoded.member_seq.len(), 4);

        // Also sort both perm Vecs locally by name_hash and confirm
        // the in-memory order would match the wire after sort. Drops
        // the unused mut warnings.
        perm_a.sort_by_key(|p| p.name_hash.to_le_bytes());
        perm_b.sort_by_key(|p| p.name_hash.to_le_bytes());
        assert_eq!(perm_a, perm_b);
    }

    /// DDS-XTypes 1.3 Annex B: CompleteAnnotationParameterSeq is ordered by
    /// `name`: two permutations give the same bytes, in name order.
    #[test]
    fn complete_annotation_params_emit_sorted_by_name() {
        let header = CompleteAnnotationHeader {
            annotation_name: "MyAnnot".to_string(),
        };

        fn make_complete(name: &str) -> CompleteAnnotationParameter {
            CompleteAnnotationParameter {
                common: CommonAnnotationParameter {
                    member_flags: AnnotationParameterFlag(0),
                    member_type_id: TypeIdentifier::primitive(TypeKind::TK_INT32),
                },
                name: name.to_string(),
                default_value: AnnotationParameterValue::Int32(0),
            }
        }

        let names = ["sigma", "delta", "omega"];
        let perm_a: Vec<_> = names.iter().map(|n| make_complete(n)).collect();
        let mut perm_b = perm_a.clone();
        perm_b.reverse();

        let type_a = CompleteAnnotationType {
            annotation_flag: AnnotationTypeFlag::default(),
            header: header.clone(),
            member_seq: perm_a,
        };
        let type_b = CompleteAnnotationType {
            annotation_flag: AnnotationTypeFlag::default(),
            header,
            member_seq: perm_b,
        };

        let mut buf_a = vec![0u8; type_a.max_cdr2_size()];
        let len_a = type_a.encode_cdr2_le(&mut buf_a).expect("encode perm_a");
        let mut buf_b = vec![0u8; type_b.max_cdr2_size()];
        let len_b = type_b.encode_cdr2_le(&mut buf_b).expect("encode perm_b");

        assert_eq!(len_a, len_b, "wire length must match across permutations");
        assert_eq!(
            &buf_a[..len_a],
            &buf_b[..len_b],
            "two source permutations must produce identical Complete bytes"
        );
        let (decoded, _) = CompleteAnnotationType::decode_cdr2_le(&buf_a[..len_a]).expect("decode");
        let order: Vec<&str> = decoded.member_seq.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(order, ["delta", "omega", "sigma"]);
    }

    // =========================================================================
    // AppliedAnnotationParameter + AppliedAnnotation round-trip tests
    // =========================================================================

    /// `AppliedAnnotationParameter` round-trip: encode then decode must
    /// reproduce the same struct. Covers all four supported value variants.
    #[test]
    fn applied_annotation_parameter_round_trips_all_value_variants() {
        let cases = [
            AppliedAnnotationParameter {
                paramname_hash: 0x1234_5678,
                value: AnnotationParameterValue::Boolean(true),
            },
            AppliedAnnotationParameter {
                paramname_hash: 0x0000_0000,
                value: AnnotationParameterValue::Int32(-42),
            },
            AppliedAnnotationParameter {
                paramname_hash: 0xDEAD_BEEF,
                value: AnnotationParameterValue::String("hello".to_string()),
            },
            AppliedAnnotationParameter {
                paramname_hash: 0xFFFF_FFFF,
                value: AnnotationParameterValue::Enumerated(7),
            },
        ];
        for case in cases {
            let mut buf = vec![0u8; 256];
            let len = case.encode_cdr2_le(&mut buf).expect("encode succeeds");
            let (decoded, used) =
                AppliedAnnotationParameter::decode_cdr2_le(&buf[..len]).expect("decode succeeds");
            assert_eq!(
                decoded, case,
                "round-trip preserves AppliedAnnotationParameter"
            );
            assert_eq!(used, len, "decoder consumes all encoded bytes");
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn annotation_typeid() -> TypeIdentifier {
        TypeIdentifier::Complete(crate::xtypes::EquivalenceHash::from_bytes([
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        ]))
    }

    fn applied_param() -> AppliedAnnotationParameter {
        AppliedAnnotationParameter {
            paramname_hash: u32::from_le_bytes([0x2c, 0x63, 0x4c, 0xbb]),
            value: AnnotationParameterValue::Int32(7),
        }
    }

    fn check<T: Cdr2Encode + Cdr2Decode + PartialEq + std::fmt::Debug>(value: &T, wire_hex: &str) {
        let wire = unhex(wire_hex);
        let mut buf = vec![0u8; value.max_cdr2_size()];
        let len = value.encode_cdr2_le(&mut buf).expect("encode");
        assert_eq!(&buf[..len], &wire[..], "encoded bytes");
        let (back, used) = T::decode_cdr2_le(&wire).expect("decode");
        assert_eq!((&back, used), (value, wire.len()));
    }

    /// AppliedAnnotationParameter is APPENDABLE (DDS-XTypes 1.3 Annex B, spec
    /// lines 12658-12662): DHEADER, the NameHash octets, the value. The bytes
    /// are Fast DDS 3.4's serializer's for the same record.
    #[test]
    fn applied_annotation_parameter_is_a_delimited_record() {
        check(&applied_param(), "0c0000002c634cbb0400000007000000");
    }

    /// AppliedAnnotation is APPENDABLE and its @optional parameter sequence,
    /// of APPENDABLE elements, carries its own DHEADER (spec lines
    /// 12671-12675, XCDR2 7.4.3.5.3). Fast DDS 3.4's bytes, with and without
    /// parameters.
    #[test]
    fn applied_annotation_is_a_delimited_record_with_a_delimited_sequence() {
        check(
            &AppliedAnnotation {
                annotation_type_id: annotation_typeid(),
                param_seq: Some(vec![applied_param()]),
            },
            "28000000f21112131415161718191a1b1c1d1e0114000000010000000c0000002c634cbb\
             0400000007000000",
        );
        check(
            &AppliedAnnotation {
                annotation_type_id: annotation_typeid(),
                param_seq: None,
            },
            "10000000f21112131415161718191a1b1c1d1e00",
        );
    }

    /// The AppliedAnnotationSeq of a member detail is DHEADER-delimited too:
    /// Fast DDS 3.4's CompleteMemberDetail for a member `m` carrying the
    /// annotation above.
    #[test]
    fn a_member_s_applied_annotation_seq_is_delimited() {
        check(
            &CompleteMemberDetail {
                name: "m".to_string(),
                ann_builtin: None,
                ann_custom: Some(vec![AppliedAnnotation {
                    annotation_type_id: annotation_typeid(),
                    param_seq: Some(vec![applied_param()]),
                }]),
            },
            "020000006d000001300000000100000028000000f21112131415161718191a1b1c1d1e01\
             14000000010000000c0000002c634cbb0400000007000000",
        );
    }

    /// AppliedBuiltinTypeAnnotations is APPENDABLE and holds an
    /// AppliedVerbatimAnnotation of three strings (spec lines 12680-12686,
    /// 12751-12754): Fast DDS 3.4's CompleteTypeDetail of a type `T` with
    /// `@verbatim(placement="BEGIN_FILE", language="c++", text="// hi")`.
    #[test]
    fn a_type_s_verbatim_annotation_is_a_delimited_record_of_three_strings() {
        check(
            &CompleteTypeDetail {
                type_name: "T".to_string(),
                ann_builtin: Some(AppliedBuiltinTypeAnnotations {
                    verbatim: Some(AppliedVerbatimAnnotation {
                        placement: "BEGIN_FILE".to_string(),
                        language: "c++".to_string(),
                        text: "// hi".to_string(),
                    }),
                }),
                ann_custom: None,
            },
            "0100000026000000010000000b000000424547494e5f46494c45000004000000632b2b00\
             060000002f2f206869000000020000005400",
        );
    }

    /// `AppliedAnnotation` with two parameters round-trips through encode+decode.
    #[test]
    fn applied_annotation_round_trips_with_two_params() {
        let ann = AppliedAnnotation {
            annotation_type_id: TypeIdentifier::Primitive(TypeKind::TK_FLOAT32),
            param_seq: Some(vec![
                AppliedAnnotationParameter {
                    paramname_hash: 0xAAAA_BBBB,
                    value: AnnotationParameterValue::Int32(10),
                },
                AppliedAnnotationParameter {
                    paramname_hash: 0xCCCC_DDDD,
                    value: AnnotationParameterValue::Boolean(false),
                },
            ]),
        };
        let mut buf = vec![0u8; 512];
        let len = ann.encode_cdr2_le(&mut buf).expect("encode succeeds");
        let (decoded, used) =
            AppliedAnnotation::decode_cdr2_le(&buf[..len]).expect("decode succeeds");
        assert_eq!(decoded, ann, "round-trip with two params");
        assert_eq!(used, len, "decoder consumes all encoded bytes");
    }

    /// Every case of AnnotationParameterValue (DDS-XTypes 1.3 Annex B, spec
    /// lines 12611-12654) as Fast DDS 3.4's Annex B serializer writes it
    /// (`fastdds_annotation_probe.cpp`), except two where it departs from the
    /// specification and the spec form is used:
    /// - string16: Fast DDS writes the length 2 (characters); 7.4.1.1.2
    ///   makes the length of a String<Char16> its size in bytes, 4 here.
    /// - float128: Fast DDS writes the x87 80-bit `long double` and six
    ///   uninitialized octets; the value is carried as 16 opaque octets, so
    ///   only the layout (octet discriminator, 4-aligned, 16 octets) is
    ///   Fast DDS's, the octets are the IEEE 754 binary128 of 1.0.
    const PARAMETER_VALUE_VECTORS: &[(&str, &str)] = &[
        ("boolean", "0101"),
        ("byte", "02ab"),
        ("int8", "0cfe"),
        ("uint8", "0dfe"),
        ("int16", "0300d4fe"),
        ("uint16", "060060ea"),
        ("int32", "04000000fdffffff"),
        ("uint32", "0700000000286bee"),
        ("int64", "05000000000efad5feffffff"),
        ("uint64", "08000000000008c5a1d8ccf9"),
        ("float32", "090000000000c03f"),
        ("float64", "0a0000000000000000000240"),
        ("float128", "0b0000000000000000000000000000000000ff3f"),
        ("char8", "105a"),
        ("char16", "1100e900"),
        ("enum", "4000000005000000"),
        ("string8", "200000000400000061626300"),
        ("string16", "21000000040000006800e900"),
        ("extended", "7f00000000000000"),
    ];

    #[test]
    fn every_parameter_value_case_round_trips() {
        for (case, wire_hex) in PARAMETER_VALUE_VECTORS {
            let wire = unhex(wire_hex);
            let (value, used) = AnnotationParameterValue::decode_cdr2_le(&wire)
                .unwrap_or_else(|e| panic!("{case}: decode: {e:?}"));
            assert_eq!(used, wire.len(), "{case}: consumed");
            let mut buf = vec![0u8; value.max_cdr2_size()];
            let len = value
                .encode_cdr2_le(&mut buf)
                .unwrap_or_else(|e| panic!("{case}: encode: {e:?}"));
            assert_eq!(&buf[..len], &wire[..], "{case}: re-encoded");
        }
    }
}

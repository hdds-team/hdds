// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Enumeration type definitions
//!
//!
//! Complete and Minimal enumeration types, headers, and literals.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.3 (Enumerated Types)

use super::helpers::{checked_usize, encode_fields_sequential};
use super::primitives::{
    align_offset, decode_i16, decode_i32, decode_u16, decode_u32, encode_i16, encode_i32,
    encode_u16, encode_vec,
};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CommonEnumeratedLiteral CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CommonEnumeratedLiteral {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_value = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_i32(self.value, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_flags = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u16(self.flags.0, buf, &mut local)?;
            Ok(local)
        };

        encode_fields_sequential(dst, &mut [&mut encode_value, &mut encode_flags])
    }

    fn max_cdr2_size(&self) -> usize {
        4 + 2 // i32 + u16
    }
}

impl Cdr2Decode for CommonEnumeratedLiteral {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_common_enumerated_literal_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CommonEnumeratedLiteral decoding
pub(super) fn decode_common_enumerated_literal_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CommonEnumeratedLiteral, CdrError> {
    let value = decode_i32(src, offset)?;
    let flags = EnumeratedLiteralFlag(decode_u16(src, offset)?);

    Ok(CommonEnumeratedLiteral { value, flags })
}

// ============================================================================
// CompleteEnumeratedLiteral / MinimalEnumeratedLiteral CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteEnumeratedLiteral {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteEnumeratedLiteral {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_enumerated_literal_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteEnumeratedLiteral decoding
pub(super) fn decode_complete_enumerated_literal_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteEnumeratedLiteral, CdrError> {
    let common = decode_common_enumerated_literal_internal(src, offset)?;

    let (detail, used) = CompleteMemberDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(CompleteEnumeratedLiteral { common, detail })
}

impl Cdr2Encode for MinimalEnumeratedLiteral {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalEnumeratedLiteral {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_enumerated_literal_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalEnumeratedLiteral decoding
pub(super) fn decode_minimal_enumerated_literal_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalEnumeratedLiteral, CdrError> {
    let common = decode_common_enumerated_literal_internal(src, offset)?;

    let (detail, used) = MinimalMemberDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(MinimalEnumeratedLiteral { common, detail })
}

// ============================================================================
// EnumeratedHeader CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteEnumeratedHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_bit_bound = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_i16(self.bit_bound, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_bit_bound, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        2 + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteEnumeratedHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_enumerated_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteEnumeratedHeader decoding
pub(super) fn decode_complete_enumerated_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteEnumeratedHeader, CdrError> {
    let bit_bound = decode_i16(src, offset)?;

    let (detail, used) = CompleteTypeDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(CompleteEnumeratedHeader { bit_bound, detail })
}

impl Cdr2Encode for MinimalEnumeratedHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Encode bit_bound (i16)
        encode_i16(self.bit_bound, dst, &mut offset)?;

        // Encode detail (empty for MinimalTypeDetail)
        let detail_len = self.detail.encode_cdr2_le(&mut dst[offset..])?;
        offset += detail_len;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        2 + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalEnumeratedHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_enumerated_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalEnumeratedHeader decoding
pub(super) fn decode_minimal_enumerated_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalEnumeratedHeader, CdrError> {
    let bit_bound = decode_i16(src, offset)?;

    // MinimalTypeDetail is empty, but decode it for consistency
    let (detail, used) = MinimalTypeDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(MinimalEnumeratedHeader { bit_bound, detail })
}

// ============================================================================
// CompleteEnumeratedType / MinimalEnumeratedType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteEnumeratedType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Encode header
        let header_len = self.header.encode_cdr2_le(&mut dst[offset..])?;
        offset += header_len;

        // Encode literal_seq (Vec<CompleteEnumeratedLiteral>)
        encode_vec(
            &self.literal_seq,
            dst,
            &mut offset,
            |literal, dst, offset| {
                let len = literal.encode_cdr2_le(&mut dst[*offset..])?;
                *offset += len;
                Ok(())
            },
        )?;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        self.header.max_cdr2_size()
            + 4
            + self
                .literal_seq
                .iter()
                .map(|l| l.max_cdr2_size())
                .sum::<usize>()
    }
}

impl Cdr2Decode for CompleteEnumeratedType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        // Decode header using internal helper
        let header = decode_complete_enumerated_header_internal(src, &mut offset)?;

        // Decode literal_seq using internal helper for proper offset tracking
        let literal_len = decode_u32(src, &mut offset)?;
        let capacity = checked_usize(literal_len, "enumeration literal sequence length")?;
        let mut literal_seq = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // Align each element to 4 bytes (CDR2 struct alignment in sequences)
            offset = align_offset(offset, 4);
            let literal = decode_complete_enumerated_literal_internal(src, &mut offset)?;
            literal_seq.push(literal);
        }

        Ok((
            CompleteEnumeratedType {
                header,
                literal_seq,
            },
            offset,
        ))
    }
}

impl Cdr2Encode for MinimalEnumeratedType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Encode header
        let header_len = self.header.encode_cdr2_le(&mut dst[offset..])?;
        offset += header_len;

        // Encode literal_seq (Vec<MinimalEnumeratedLiteral>)
        encode_vec(
            &self.literal_seq,
            dst,
            &mut offset,
            |literal, dst, offset| {
                let len = literal.encode_cdr2_le(&mut dst[*offset..])?;
                *offset += len;
                Ok(())
            },
        )?;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        self.header.max_cdr2_size()
            + 4
            + self
                .literal_seq
                .iter()
                .map(|l| l.max_cdr2_size())
                .sum::<usize>()
    }
}

impl Cdr2Decode for MinimalEnumeratedType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        // Decode header using internal helper
        let header = decode_minimal_enumerated_header_internal(src, &mut offset)?;

        // Decode literal_seq using internal helper for proper offset tracking
        let literal_len = decode_u32(src, &mut offset)?;
        let capacity = checked_usize(literal_len, "minimal enumeration literal sequence length")?;
        let mut literal_seq = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // Align each element to 4 bytes (CDR2 struct alignment in sequences)
            offset = align_offset(offset, 4);
            let literal = decode_minimal_enumerated_literal_internal(src, &mut offset)?;
            literal_seq.push(literal);
        }

        Ok((
            MinimalEnumeratedType {
                header,
                literal_seq,
            },
            offset,
        ))
    }
}

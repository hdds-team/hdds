// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitfield encoding for different bit widths.
//!

use super::super::helpers::encode_fields_sequential;
use super::super::primitives::{decode_u16, decode_u8, encode_u16, encode_u8};
use super::super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::type_object::{
    BitfieldFlag, CommonBitfield, CompleteBitfield, CompleteMemberDetail, MinimalBitfield,
    MinimalMemberDetail,
};

// ============================================================================
// CommonBitfield CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CommonBitfield {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_position = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u16(self.position, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_flags = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u16(self.flags.0, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_bit_count = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u8(self.bit_count, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_holder = |buf: &mut [u8]| self.holder_type.encode_cdr2_le(buf);

        encode_fields_sequential(
            dst,
            &mut [
                &mut encode_position,
                &mut encode_flags,
                &mut encode_bit_count,
                &mut encode_holder,
            ],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        // position (2) + flags (2) + bit_count (1) + holder_type (32) + alignment
        64
    }
}

impl Cdr2Decode for CommonBitfield {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_common_bitfield_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CommonBitfield decoding
pub(super) fn decode_common_bitfield_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CommonBitfield, CdrError> {
    let position = decode_u16(src, offset)?;
    let flags = BitfieldFlag(decode_u16(src, offset)?);
    let bit_count = decode_u8(src, offset)?;

    // Decode TypeIdentifier using internal helper for proper offset tracking
    let holder_type = decode_type_identifier_internal(src, offset)?;

    Ok(CommonBitfield {
        position,
        flags,
        bit_count,
        holder_type,
    })
}

// ============================================================================
// CompleteBitfield / MinimalBitfield CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteBitfield {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteBitfield {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_bitfield_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteBitfield decoding
pub(super) fn decode_complete_bitfield_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteBitfield, CdrError> {
    let common = decode_common_bitfield_internal(src, offset)?;

    let (detail, used) = CompleteMemberDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(CompleteBitfield { common, detail })
}

impl Cdr2Encode for MinimalBitfield {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalBitfield {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_bitfield_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalBitfield decoding
pub(super) fn decode_minimal_bitfield_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalBitfield, CdrError> {
    let common = decode_common_bitfield_internal(src, offset)?;

    let (detail, used) = MinimalMemberDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(MinimalBitfield { common, detail })
}

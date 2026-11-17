// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitfield encoding for different bit widths.
//!

use super::super::dheader::{decode_dheader_at, encode_dheader_at};
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
    fn max_cdr2_size(&self) -> usize {
        // position (2) + flags (2) + bit_count (1) + holder_type (32) + alignment
        64
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.position, dst, offset)?;
        encode_u16(self.flags.0, dst, offset)?;
        encode_u8(self.bit_count, dst, offset)?;
        self.holder_type.encode_cdr2_le_at(dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for CommonBitfield {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_common_bitfield_internal(src, offset)
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

// Complete/MinimalBitfield -- `@extensibility(APPENDABLE)` per XTypes v1.3 spec lines 13300, 13309.
impl Cdr2Encode for CompleteBitfield {
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

impl Cdr2Decode for CompleteBitfield {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_bitfield_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteBitfield decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_complete_bitfield_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteBitfield, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_bitfield_internal(src, offset)?;
        let detail = CompleteMemberDetail::decode_cdr2_le_at(src, offset)?;
        Ok(CompleteBitfield { common, detail })
    })
}

impl Cdr2Encode for MinimalBitfield {
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

impl Cdr2Decode for MinimalBitfield {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_bitfield_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalBitfield decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_minimal_bitfield_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalBitfield, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_bitfield_internal(src, offset)?;
        let detail = MinimalMemberDetail::decode_cdr2_le_at(src, offset)?;
        Ok(MinimalBitfield { common, detail })
    })
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitflag encoding for different bit widths.
//!

use super::super::dheader::{decode_dheader_at, encode_dheader_at};
use super::super::primitives::{decode_u16, encode_u16};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::type_object::{
    BitflagFlag, CommonBitflag, CompleteBitflag, CompleteMemberDetail, MinimalBitflag,
    MinimalMemberDetail,
};

// ============================================================================
// CommonBitflag CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CommonBitflag {
    fn max_cdr2_size(&self) -> usize {
        8 // position (2) + flags (2) + alignment (4)
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u16(self.position, dst, offset)?;
        encode_u16(self.flags.0, dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for CommonBitflag {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_common_bitflag_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CommonBitflag decoding
pub(super) fn decode_common_bitflag_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CommonBitflag, CdrError> {
    let position = decode_u16(src, offset)?;
    let flags = BitflagFlag(decode_u16(src, offset)?);

    Ok(CommonBitflag { position, flags })
}

// ============================================================================
// CompleteBitflag / MinimalBitflag CDR2 Encoding/Decoding
// ============================================================================

// Complete/MinimalBitflag -- `@extensibility(APPENDABLE)` per XTypes v1.3 spec lines 13240, 13249.
impl Cdr2Encode for CompleteBitflag {
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

impl Cdr2Decode for CompleteBitflag {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_bitflag_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteBitflag decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_complete_bitflag_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteBitflag, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_bitflag_internal(src, offset)?;
        let detail = CompleteMemberDetail::decode_cdr2_le_at(src, offset)?;
        Ok(CompleteBitflag { common, detail })
    })
}

impl Cdr2Encode for MinimalBitflag {
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

impl Cdr2Decode for MinimalBitflag {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_bitflag_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalBitflag decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_minimal_bitflag_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalBitflag, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_bitflag_internal(src, offset)?;
        let detail = MinimalMemberDetail::decode_cdr2_le_at(src, offset)?;
        Ok(MinimalBitflag { common, detail })
    })
}

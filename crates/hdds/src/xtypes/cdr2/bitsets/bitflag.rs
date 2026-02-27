// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitflag encoding for different bit widths.
//!

use super::super::helpers::encode_fields_sequential;
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

        encode_fields_sequential(dst, &mut [&mut encode_position, &mut encode_flags])
    }

    fn max_cdr2_size(&self) -> usize {
        8 // position (2) + flags (2) + alignment (4)
    }
}

impl Cdr2Decode for CommonBitflag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_common_bitflag_internal(src, &mut offset)?;
        Ok((result, offset))
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

impl Cdr2Encode for CompleteBitflag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteBitflag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_bitflag_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteBitflag decoding
pub(super) fn decode_complete_bitflag_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteBitflag, CdrError> {
    let common = decode_common_bitflag_internal(src, offset)?;

    let (detail, used) = CompleteMemberDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(CompleteBitflag { common, detail })
}

impl Cdr2Encode for MinimalBitflag {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalBitflag {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_bitflag_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalBitflag decoding
pub(super) fn decode_minimal_bitflag_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalBitflag, CdrError> {
    let common = decode_common_bitflag_internal(src, offset)?;

    let (detail, used) = MinimalMemberDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(MinimalBitflag { common, detail })
}

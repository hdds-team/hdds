// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Bitset CDR2 serialization for different bit widths (u8/u16/u32/u64).
//!
//!

use super::super::helpers::{checked_usize, encode_fields_sequential};
use super::super::primitives::{
    align_offset, decode_u16, decode_u32, decode_u8, encode_u16, encode_u8, encode_vec,
};
use super::super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::type_object::{
    BitsetTypeFlag, CompleteBitsetHeader, CompleteBitsetType, CompleteTypeDetail,
    MinimalBitsetHeader, MinimalBitsetType, MinimalTypeDetail,
};

use super::bitfield::{decode_complete_bitfield_internal, decode_minimal_bitfield_internal};

// ============================================================================
// BitsetHeader CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteBitsetHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_base_type = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            if let Some(ref base) = self.base_type {
                encode_u8(1, buf, &mut local)?;
                let len = base.encode_cdr2_le(&mut buf[local..])?;
                local += len;
            } else {
                encode_u8(0, buf, &mut local)?;
            }
            Ok(local)
        };
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_base_type, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        1 + 32 + self.detail.max_cdr2_size() // flag + optional TypeIdentifier + detail
    }
}

impl Cdr2Decode for CompleteBitsetHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_bitset_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteBitsetHeader decoding
pub(super) fn decode_complete_bitset_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteBitsetHeader, CdrError> {
    // Decode base_type (Option<TypeIdentifier>)
    let base_type_present = decode_u8(src, offset)?;
    let base_type = if base_type_present == 1 {
        Some(decode_type_identifier_internal(src, offset)?)
    } else {
        None
    };

    let (detail, used) = CompleteTypeDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(CompleteBitsetHeader { base_type, detail })
}

impl Cdr2Encode for MinimalBitsetHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_base_type = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            if let Some(ref base) = self.base_type {
                encode_u8(1, buf, &mut local)?;
                let len = base.encode_cdr2_le(&mut buf[local..])?;
                local += len;
            } else {
                encode_u8(0, buf, &mut local)?;
            }
            Ok(local)
        };
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_base_type, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        1 + 32 + self.detail.max_cdr2_size() // flag + optional TypeIdentifier + detail
    }
}

impl Cdr2Decode for MinimalBitsetHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_bitset_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalBitsetHeader decoding
pub(super) fn decode_minimal_bitset_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalBitsetHeader, CdrError> {
    // Decode base_type (Option<TypeIdentifier>)
    let base_type_present = decode_u8(src, offset)?;
    let base_type = if base_type_present == 1 {
        Some(decode_type_identifier_internal(src, offset)?)
    } else {
        None
    };

    // MinimalTypeDetail is empty, but decode it for consistency
    let (detail, used) = MinimalTypeDetail::decode_cdr2_le(&src[*offset..])?;
    *offset += used;

    Ok(MinimalBitsetHeader { base_type, detail })
}

// ============================================================================
// CompleteBitsetType / MinimalBitsetType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteBitsetType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_flags = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u16(self.bitset_flags.0, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_header = |buf: &mut [u8]| self.header.encode_cdr2_le(buf);
        let mut encode_fields = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_vec(&self.field_seq, buf, &mut local, |field, buf, offset| {
                let len = field.encode_cdr2_le(&mut buf[*offset..])?;
                *offset += len;
                Ok(())
            })?;
            Ok(local)
        };

        encode_fields_sequential(
            dst,
            &mut [&mut encode_flags, &mut encode_header, &mut encode_fields],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        // Conservative estimate
        4 + self.header.max_cdr2_size()
            + 4
            + self
                .field_seq
                .iter()
                .map(|f| f.max_cdr2_size())
                .sum::<usize>()
    }
}

impl Cdr2Decode for CompleteBitsetType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let bitset_flags = BitsetTypeFlag(decode_u16(src, &mut offset)?);

        // Decode header using internal helper
        let header = decode_complete_bitset_header_internal(src, &mut offset)?;

        // Decode field_seq using internal helper for proper offset tracking
        let field_len = decode_u32(src, &mut offset)?;
        let capacity = checked_usize(field_len, "bitfield sequence length")?;
        let mut field_seq = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // Align each element to 4 bytes (CDR2 struct alignment in sequences)
            offset = align_offset(offset, 4);
            let field = decode_complete_bitfield_internal(src, &mut offset)?;
            field_seq.push(field);
        }

        Ok((
            CompleteBitsetType {
                bitset_flags,
                header,
                field_seq,
            },
            offset,
        ))
    }
}

impl Cdr2Encode for MinimalBitsetType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_flags = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u16(self.bitset_flags.0, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_header = |buf: &mut [u8]| self.header.encode_cdr2_le(buf);
        let mut encode_fields = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_vec(&self.field_seq, buf, &mut local, |field, buf, offset| {
                let len = field.encode_cdr2_le(&mut buf[*offset..])?;
                *offset += len;
                Ok(())
            })?;
            Ok(local)
        };

        encode_fields_sequential(
            dst,
            &mut [&mut encode_flags, &mut encode_header, &mut encode_fields],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        // Conservative estimate
        4 + self.header.max_cdr2_size()
            + 4
            + self
                .field_seq
                .iter()
                .map(|f| f.max_cdr2_size())
                .sum::<usize>()
    }
}

impl Cdr2Decode for MinimalBitsetType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let bitset_flags = BitsetTypeFlag(decode_u16(src, &mut offset)?);

        // Decode header using internal helper
        let header = decode_minimal_bitset_header_internal(src, &mut offset)?;

        // Decode field_seq using internal helper for proper offset tracking
        let field_len = decode_u32(src, &mut offset)?;
        let capacity = checked_usize(field_len, "minimal bitfield sequence length")?;
        let mut field_seq = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            // Align each element to 4 bytes (CDR2 struct alignment in sequences)
            offset = align_offset(offset, 4);
            let field = decode_minimal_bitfield_internal(src, &mut offset)?;
            field_seq.push(field);
        }

        Ok((
            MinimalBitsetType {
                bitset_flags,
                header,
                field_seq,
            },
            offset,
        ))
    }
}

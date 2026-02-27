// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Struct type definitions
//!
//! Complete and Minimal struct types, headers, and members.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.1 (Struct Types)

use super::helpers::encode_fields_sequential;
use super::members::{
    decode_complete_struct_member_internal, decode_minimal_struct_member_internal,
};
use super::primitives::{decode_option, decode_u16, encode_option, encode_u16, encode_vec};
use super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// StructHeader CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteStructHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_base_type = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_option(&self.base_type, buf, &mut local, |type_id, buf, offset| {
                let len = type_id.encode_cdr2_le(&mut buf[*offset..])?;
                *offset += len;
                Ok(())
            })?;
            Ok(local)
        };
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_base_type, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        32 + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteStructHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_struct_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteStructHeader decoding
pub(super) fn decode_complete_struct_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteStructHeader, CdrError> {
    let base_type = decode_option(src, offset, |src, offset| {
        decode_type_identifier_internal(src, offset)
    })?;

    let detail = super::helpers::decode_detail_with_reencoding::<CompleteTypeDetail>(src, offset)?;

    Ok(CompleteStructHeader { base_type, detail })
}

impl Cdr2Encode for MinimalStructHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_base_type = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_option(&self.base_type, buf, &mut local, |type_id, buf, offset| {
                let len = type_id.encode_cdr2_le(&mut buf[*offset..])?;
                *offset += len;
                Ok(())
            })?;
            Ok(local)
        };
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_base_type, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        32 + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalStructHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_struct_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalStructHeader decoding
pub(super) fn decode_minimal_struct_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalStructHeader, CdrError> {
    let base_type = decode_option(src, offset, |src, offset| {
        decode_type_identifier_internal(src, offset)
    })?;

    // MinimalTypeDetail is empty (encodes as 0 bytes)
    let detail = super::helpers::decode_detail_with_reencoding::<MinimalTypeDetail>(src, offset)?;

    Ok(MinimalStructHeader { base_type, detail })
}

// ============================================================================
// CompleteStructType / MinimalStructType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteStructType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Flags
        encode_u16(self.struct_flags.0, dst, &mut offset)?;

        // Header (sub-buffer OK: decode also uses sub-slicing for header internals)
        let header_len = self.header.encode_cdr2_le(&mut dst[offset..])?;
        offset += header_len;

        // Member sequence: use global offset so encode_u32 alignment matches decoder
        encode_vec(&self.member_seq, dst, &mut offset, |member, buf, offset| {
            let len = member.encode_cdr2_le(&mut buf[*offset..])?;
            *offset += len;
            Ok(())
        })?;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        super::helpers::max_size_type_with_members(&self.header, &self.member_seq)
    }
}

impl Cdr2Decode for CompleteStructType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let struct_flags = StructTypeFlag(decode_u16(src, &mut offset)?);

        // Decode header using internal helper
        let header = decode_complete_struct_header_internal(src, &mut offset)?;

        // Decode member_seq using helper for proper alignment
        let member_seq = super::helpers::decode_member_sequence(
            src,
            &mut offset,
            decode_complete_struct_member_internal,
        )?;

        Ok((
            CompleteStructType {
                struct_flags,
                header,
                member_seq,
            },
            offset,
        ))
    }
}

impl Cdr2Encode for MinimalStructType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Flags
        encode_u16(self.struct_flags.0, dst, &mut offset)?;

        // Header (sub-buffer OK: decode also uses sub-slicing for header internals)
        let header_len = self.header.encode_cdr2_le(&mut dst[offset..])?;
        offset += header_len;

        // Member sequence: use global offset so encode_u32 alignment matches decoder
        encode_vec(&self.member_seq, dst, &mut offset, |member, buf, offset| {
            let len = member.encode_cdr2_le(&mut buf[*offset..])?;
            *offset += len;
            Ok(())
        })?;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        super::helpers::max_size_type_with_members(&self.header, &self.member_seq)
    }
}

impl Cdr2Decode for MinimalStructType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let struct_flags = StructTypeFlag(decode_u16(src, &mut offset)?);

        // Decode header using internal helper
        let header = decode_minimal_struct_header_internal(src, &mut offset)?;

        // Decode member_seq using helper for proper alignment
        let member_seq = super::helpers::decode_member_sequence(
            src,
            &mut offset,
            decode_minimal_struct_member_internal,
        )?;

        Ok((
            MinimalStructType {
                struct_flags,
                header,
                member_seq,
            },
            offset,
        ))
    }
}

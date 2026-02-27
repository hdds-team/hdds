// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Union type definitions
//!
//! Complete and Minimal union types, headers, and members.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.2 (Union Types)

use super::helpers::encode_fields_sequential;
use super::members::{decode_complete_union_member_internal, decode_minimal_union_member_internal};
use super::primitives::{decode_u16, encode_u16, encode_vec};
use super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// UnionHeader CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteUnionHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_discriminator = |buf: &mut [u8]| self.discriminator.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_discriminator, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        32 + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteUnionHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_union_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteUnionHeader decoding
pub(super) fn decode_complete_union_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteUnionHeader, CdrError> {
    let discriminator = decode_type_identifier_internal(src, offset)?;
    let detail = super::helpers::decode_detail_with_reencoding::<CompleteTypeDetail>(src, offset)?;

    Ok(CompleteUnionHeader {
        discriminator,
        detail,
    })
}

impl Cdr2Encode for MinimalUnionHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_discriminator = |buf: &mut [u8]| self.discriminator.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_discriminator, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        32 + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalUnionHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_union_header_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalUnionHeader decoding
pub(super) fn decode_minimal_union_header_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalUnionHeader, CdrError> {
    let discriminator = decode_type_identifier_internal(src, offset)?;

    // MinimalTypeDetail is empty (encodes as 0 bytes)
    let detail = super::helpers::decode_detail_with_reencoding::<MinimalTypeDetail>(src, offset)?;

    Ok(MinimalUnionHeader {
        discriminator,
        detail,
    })
}

// ============================================================================
// CompleteUnionType / MinimalUnionType CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteUnionType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Flags
        encode_u16(self.union_flags.0, dst, &mut offset)?;

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

impl Cdr2Decode for CompleteUnionType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let union_flags = UnionTypeFlag(decode_u16(src, &mut offset)?);

        // Decode header using internal helper
        let header = decode_complete_union_header_internal(src, &mut offset)?;

        // Decode member_seq using helper for proper alignment
        let member_seq = super::helpers::decode_member_sequence(
            src,
            &mut offset,
            decode_complete_union_member_internal,
        )?;

        Ok((
            CompleteUnionType {
                union_flags,
                header,
                member_seq,
            },
            offset,
        ))
    }
}

impl Cdr2Encode for MinimalUnionType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Encode union_flags (u16)
        encode_u16(self.union_flags.0, dst, &mut offset)?;

        // Encode header
        let header_len = self.header.encode_cdr2_le(&mut dst[offset..])?;
        offset += header_len;

        // Encode member_seq (Vec<MinimalUnionMember>)
        encode_vec(&self.member_seq, dst, &mut offset, |member, dst, offset| {
            let len = member.encode_cdr2_le(&mut dst[*offset..])?;
            *offset += len;
            Ok(())
        })?;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        super::helpers::max_size_type_with_members(&self.header, &self.member_seq)
    }
}

impl Cdr2Decode for MinimalUnionType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let union_flags = UnionTypeFlag(decode_u16(src, &mut offset)?);

        // Decode header using internal helper
        let header = decode_minimal_union_header_internal(src, &mut offset)?;

        // Decode member_seq using helper for proper alignment
        let member_seq = super::helpers::decode_member_sequence(
            src,
            &mut offset,
            decode_minimal_union_member_internal,
        )?;

        Ok((
            MinimalUnionType {
                union_flags,
                header,
                member_seq,
            },
            offset,
        ))
    }
}

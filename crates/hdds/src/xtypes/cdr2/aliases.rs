// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Alias type definitions
//!
//! Complete and Minimal alias types (type aliases/typedefs).
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.8.6 (Alias Types)

use super::helpers::encode_fields_sequential;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use crate::xtypes::TypeIdentifier;

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CompleteAliasType / MinimalAliasType CDR2 (0x09)
// ============================================================================

// Alias Headers
impl Cdr2Encode for CompleteAliasHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        self.detail.encode_cdr2_le(dst)
    }

    fn max_cdr2_size(&self) -> usize {
        self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteAliasHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let (detail, used) = CompleteTypeDetail::decode_cdr2_le(src)?;
        Ok((CompleteAliasHeader { detail }, used))
    }
}

impl Cdr2Encode for MinimalAliasHeader {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        self.detail.encode_cdr2_le(dst)
    }

    fn max_cdr2_size(&self) -> usize {
        self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalAliasHeader {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let (detail, used) = MinimalTypeDetail::decode_cdr2_le(src)?;
        Ok((MinimalAliasHeader { detail }, used))
    }
}

// Alias Bodies
impl Cdr2Encode for CommonAliasBody {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_flags = |buf: &mut [u8]| self.related_flags.encode_cdr2_le(buf);
        let mut encode_type = |buf: &mut [u8]| self.related_type.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_flags, &mut encode_type])
    }

    fn max_cdr2_size(&self) -> usize {
        self.related_flags.max_cdr2_size() + self.related_type.max_cdr2_size()
    }
}

impl Cdr2Decode for CommonAliasBody {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (related_flags, used) = TypeRelationFlag::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let (related_type, used) = TypeIdentifier::decode_cdr2_le(&src[offset..])?;
        offset += used;

        Ok((
            CommonAliasBody {
                related_flags,
                related_type,
            },
            offset,
        ))
    }
}

impl Cdr2Encode for CompleteAliasBody {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteAliasBody {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (common, used) = CommonAliasBody::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let (detail, used) = CompleteTypeDetail::decode_cdr2_le(&src[offset..])?;
        offset += used;

        Ok((CompleteAliasBody { common, detail }, offset))
    }
}

impl Cdr2Encode for MinimalAliasBody {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        self.common.encode_cdr2_le(dst)
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalAliasBody {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let (common, used) = CommonAliasBody::decode_cdr2_le(src)?;
        Ok((MinimalAliasBody { common }, used))
    }
}

// Complete/Minimal AliasType
impl Cdr2Encode for CompleteAliasType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_flags = |buf: &mut [u8]| self.alias_flags.encode_cdr2_le(buf);
        let mut encode_header = |buf: &mut [u8]| self.header.encode_cdr2_le(buf);
        let mut encode_body = |buf: &mut [u8]| self.body.encode_cdr2_le(buf);

        encode_fields_sequential(
            dst,
            &mut [&mut encode_flags, &mut encode_header, &mut encode_body],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        self.alias_flags.max_cdr2_size() + self.header.max_cdr2_size() + self.body.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteAliasType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (alias_flags, used) = AliasTypeFlag::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let (header, used) = CompleteAliasHeader::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let (body, used) = CompleteAliasBody::decode_cdr2_le(&src[offset..])?;
        offset += used;

        Ok((
            CompleteAliasType {
                alias_flags,
                header,
                body,
            },
            offset,
        ))
    }
}

impl Cdr2Encode for MinimalAliasType {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_flags = |buf: &mut [u8]| self.alias_flags.encode_cdr2_le(buf);
        let mut encode_header = |buf: &mut [u8]| self.header.encode_cdr2_le(buf);
        let mut encode_body = |buf: &mut [u8]| self.body.encode_cdr2_le(buf);

        encode_fields_sequential(
            dst,
            &mut [&mut encode_flags, &mut encode_header, &mut encode_body],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        self.alias_flags.max_cdr2_size() + self.header.max_cdr2_size() + self.body.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalAliasType {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;

        let (alias_flags, used) = AliasTypeFlag::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let (header, used) = MinimalAliasHeader::decode_cdr2_le(&src[offset..])?;
        offset += used;

        let (body, used) = MinimalAliasBody::decode_cdr2_le(&src[offset..])?;
        offset += used;

        Ok((
            MinimalAliasType {
                alias_flags,
                header,
                body,
            },
            offset,
        ))
    }
}

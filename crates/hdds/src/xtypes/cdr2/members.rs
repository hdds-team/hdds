// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Common member definitions
//!
//!
//! Shared member structures for structs, unions, enums, and bitsets.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.7 (Member Definitions)

use super::helpers::{checked_usize, encode_fields_sequential};
use super::primitives::{decode_i32, decode_u16, decode_u32, encode_i32, encode_u16, encode_u32};
use super::type_identifier::decode_type_identifier_internal;
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use std::convert::TryFrom;

#[allow(clippy::wildcard_imports)]
use crate::xtypes::type_object::*;

// ============================================================================
// CommonStructMember CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CommonStructMember {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_member_id = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u32(self.member_id, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_member_flags = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u16(self.member_flags.0, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_type_id = |buf: &mut [u8]| self.member_type_id.encode_cdr2_le(buf);

        encode_fields_sequential(
            dst,
            &mut [
                &mut encode_member_id,
                &mut encode_member_flags,
                &mut encode_type_id,
            ],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        // member_id (4) + member_flags (2) + TypeIdentifier (32) + padding
        64
    }
}

impl Cdr2Decode for CommonStructMember {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_common_struct_member_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset
pub(super) fn decode_common_struct_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CommonStructMember, CdrError> {
    let member_id = decode_u32(src, offset)?;
    let member_flags = MemberFlag(decode_u16(src, offset)?);

    // Decode TypeIdentifier using internal helper for proper offset tracking
    let member_type_id = decode_type_identifier_internal(src, offset)?;

    Ok(CommonStructMember {
        member_id,
        member_flags,
        member_type_id,
    })
}

// ============================================================================
// CompleteStructMember / MinimalStructMember CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteStructMember {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteStructMember {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_struct_member_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteStructMember decoding
pub(super) fn decode_complete_struct_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteStructMember, CdrError> {
    let common = decode_common_struct_member_internal(src, offset)?;
    let detail =
        super::helpers::decode_detail_with_reencoding::<CompleteMemberDetail>(src, offset)?;

    Ok(CompleteStructMember { common, detail })
}

impl Cdr2Encode for MinimalStructMember {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_common = |buf: &mut [u8]| self.common.encode_cdr2_le(buf);
        let mut encode_detail = |buf: &mut [u8]| self.detail.encode_cdr2_le(buf);

        encode_fields_sequential(dst, &mut [&mut encode_common, &mut encode_detail])
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalStructMember {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_struct_member_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalStructMember decoding
pub(super) fn decode_minimal_struct_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalStructMember, CdrError> {
    let common = decode_common_struct_member_internal(src, offset)?;
    let detail = super::helpers::decode_detail_with_reencoding::<MinimalMemberDetail>(src, offset)?;

    Ok(MinimalStructMember { common, detail })
}

// ============================================================================
// CommonUnionMember CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CommonUnionMember {
    // @audit-ok: Sequential encoding (cyclo 12, cogni 2) - multiple field encoders without complex branching
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut encode_member_id = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u32(self.member_id, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_member_flags = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            encode_u16(self.member_flags.0, buf, &mut local)?;
            Ok(local)
        };
        let mut encode_type_id = |buf: &mut [u8]| self.member_type_id.encode_cdr2_le(buf);
        let mut encode_labels = |buf: &mut [u8]| -> Result<usize, CdrError> {
            let mut local = 0;
            let label_len = u32::try_from(self.label_seq.len()).map_err(|_| {
                CdrError::Other("Union label sequence exceeds u32::MAX elements".into())
            })?;
            encode_u32(label_len, buf, &mut local)?;
            for label in &self.label_seq {
                encode_i32(*label, buf, &mut local)?;
            }
            Ok(local)
        };

        encode_fields_sequential(
            dst,
            &mut [
                &mut encode_member_id,
                &mut encode_member_flags,
                &mut encode_type_id,
                &mut encode_labels,
            ],
        )
    }

    fn max_cdr2_size(&self) -> usize {
        // member_id (4) + member_flags (2) + TypeIdentifier (32) + label_seq length (4) + labels (4 * N) + padding
        128 + self.label_seq.len() * 4
    }
}

impl Cdr2Decode for CommonUnionMember {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_common_union_member_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset
pub(super) fn decode_common_union_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CommonUnionMember, CdrError> {
    let member_id = decode_u32(src, offset)?;
    let member_flags = MemberFlag(decode_u16(src, offset)?);

    // Decode TypeIdentifier using internal helper for proper offset tracking
    let member_type_id = decode_type_identifier_internal(src, offset)?;

    // Decode label_seq (Vec<i32>)
    let label_count = checked_usize(decode_u32(src, offset)?, "union label sequence length")?;
    let mut label_seq = Vec::with_capacity(label_count);
    for _ in 0..label_count {
        label_seq.push(decode_i32(src, offset)?);
    }

    Ok(CommonUnionMember {
        member_id,
        member_flags,
        member_type_id,
        label_seq,
    })
}

// ============================================================================
// CompleteUnionMember / MinimalUnionMember CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CompleteUnionMember {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Encode common
        let common_len = self.common.encode_cdr2_le(&mut dst[offset..])?;
        offset += common_len;

        // Encode detail
        let detail_len = self.detail.encode_cdr2_le(&mut dst[offset..])?;
        offset += detail_len;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for CompleteUnionMember {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_complete_union_member_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for CompleteUnionMember decoding
pub(super) fn decode_complete_union_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteUnionMember, CdrError> {
    let common = decode_common_union_member_internal(src, offset)?;
    let detail =
        super::helpers::decode_detail_with_reencoding::<CompleteMemberDetail>(src, offset)?;

    Ok(CompleteUnionMember { common, detail })
}

impl Cdr2Encode for MinimalUnionMember {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, CdrError> {
        let mut offset = 0;

        // Encode common
        let common_len = self.common.encode_cdr2_le(&mut dst[offset..])?;
        offset += common_len;

        // Encode detail
        let detail_len = self.detail.encode_cdr2_le(&mut dst[offset..])?;
        offset += detail_len;

        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }
}

impl Cdr2Decode for MinimalUnionMember {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), CdrError> {
        let mut offset = 0;
        let result = decode_minimal_union_member_internal(src, &mut offset)?;
        Ok((result, offset))
    }
}

/// Internal helper that tracks offset for MinimalUnionMember decoding
pub(super) fn decode_minimal_union_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalUnionMember, CdrError> {
    let common = decode_common_union_member_internal(src, offset)?;
    let detail = super::helpers::decode_detail_with_reencoding::<MinimalMemberDetail>(src, offset)?;

    Ok(MinimalUnionMember { common, detail })
}

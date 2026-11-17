// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Common member definitions
//!
//!
//! Shared member structures for structs, unions, enums, and bitsets.
//!
//! # References
//! - XTypes v1.3 Spec: Section 7.3.4.7 (Member Definitions)

use super::dheader::{decode_dheader_at, encode_dheader_at};
use super::helpers::{checked_usize, sequence_capacity};
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
    fn max_cdr2_size(&self) -> usize {
        // member_id (4) + member_flags (2) + TypeIdentifier (32) + padding
        64
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u32(self.member_id, dst, offset)?;
        encode_u16(self.member_flags.0, dst, offset)?;
        self.member_type_id.encode_cdr2_le_at(dst, offset)?;
        Ok(())
    }
}

impl Cdr2Decode for CommonStructMember {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_common_struct_member_internal(src, offset)
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
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CompleteStructMember {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_struct_member_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteStructMember decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_complete_struct_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteStructMember, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_struct_member_internal(src, offset)?;
        let detail =
            super::helpers::decode_detail_with_reencoding::<CompleteMemberDetail>(src, offset)?;
        Ok(CompleteStructMember { common, detail })
    })
}

impl Cdr2Encode for MinimalStructMember {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for MinimalStructMember {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_struct_member_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalStructMember decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_minimal_struct_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalStructMember, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_struct_member_internal(src, offset)?;
        let detail =
            super::helpers::decode_detail_with_reencoding::<MinimalMemberDetail>(src, offset)?;
        Ok(MinimalStructMember { common, detail })
    })
}

// ============================================================================
// CommonUnionMember CDR2 Encoding/Decoding
// ============================================================================

impl Cdr2Encode for CommonUnionMember {
    // @audit-ok: Sequential encoding (cyclo 12, cogni 2) - multiple field encoders without complex branching

    fn max_cdr2_size(&self) -> usize {
        // member_id (4) + member_flags (2) + TypeIdentifier (32) + label_seq length (4) + labels (4 * N) + padding
        128 + self.label_seq.len() * 4
    }

    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_u32(self.member_id, dst, offset)?;
        // Wire convention: a @key discriminator is expressed via IS_KEY on the DISCRIMINATOR
        // member flags only; union branch members are never key-flagged on
        // the wire. HDDS keeps IS_KEY mirrored onto the members internally
        // (the matcher's key-agreement rule inspects member flags), so the
        // bit is stripped here and re-injected by the union TypeObject
        // decoders (see cdr2/unions.rs).
        let wire_flags = self.member_flags.0 & !crate::xtypes::MemberFlag::IS_KEY.0;
        encode_u16(wire_flags, dst, offset)?;
        self.member_type_id.encode_cdr2_le_at(dst, offset)?;
        let label_len = u32::try_from(self.label_seq.len()).map_err(|_| {
            CdrError::Other("Union label sequence exceeds u32::MAX elements".into())
        })?;
        encode_u32(label_len, dst, offset)?;
        for label in &self.label_seq {
            encode_i32(*label, dst, offset)?;
        }
        Ok(())
    }
}

impl Cdr2Decode for CommonUnionMember {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_common_union_member_internal(src, offset)
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
    let mut label_seq = Vec::with_capacity(sequence_capacity(label_count, src, *offset));
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
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for CompleteUnionMember {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_complete_union_member_internal(src, offset)
    }
}

/// Internal helper that tracks offset for CompleteUnionMember decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_complete_union_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<CompleteUnionMember, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_union_member_internal(src, offset)?;
        let detail =
            super::helpers::decode_detail_with_reencoding::<CompleteMemberDetail>(src, offset)?;
        Ok(CompleteUnionMember { common, detail })
    })
}

impl Cdr2Encode for MinimalUnionMember {
    fn max_cdr2_size(&self) -> usize {
        // DHEADER (4 bytes + up to 3 pad) + payload
        4 + 3 + self.common.max_cdr2_size() + self.detail.max_cdr2_size()
    }

    /// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
    fn encode_cdr2_le_at(&self, dst: &mut [u8], offset: &mut usize) -> Result<(), CdrError> {
        encode_dheader_at(dst, offset, |dst, offset| {
            self.common.encode_cdr2_le_at(dst, offset)?;
            self.detail.encode_cdr2_le_at(dst, offset)?;
            Ok(())
        })
    }
}

impl Cdr2Decode for MinimalUnionMember {
    fn decode_cdr2_le_at(src: &[u8], offset: &mut usize) -> Result<Self, CdrError> {
        decode_minimal_union_member_internal(src, offset)
    }
}

/// Internal helper that tracks offset for MinimalUnionMember decoding.
/// `@extensibility(APPENDABLE)` per XTypes v1.3 Sec.7.4.3.4 rule (30).
pub(super) fn decode_minimal_union_member_internal(
    src: &[u8],
    offset: &mut usize,
) -> Result<MinimalUnionMember, CdrError> {
    decode_dheader_at(src, offset, |src, offset| {
        let common = decode_common_union_member_internal(src, offset)?;
        let detail =
            super::helpers::decode_detail_with_reencoding::<MinimalMemberDetail>(src, offset)?;
        Ok(MinimalUnionMember { common, detail })
    })
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Helpers for PL_CDR2 (Parameter List CDR2) mutable structs.
//!
//!
//! These helpers centralize the XTypes v1.3 encoding pattern:
//! - DHEADER (u32) delimiter for the struct payload
//! - MemberId (u32) before each member
//! - Optional members omitted entirely
//! - Alignment applied before each member payload
//!
//! They are intended for use by `hdds_gen` and manual sandbox types until the
//! code generator emits PL_CDR2 directly.

use super::traits::CdrError;

/// Length code for EMHEADER1 (XTypes v1.3 Sec.7.4.3.4.3)
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)] // Part of XTypes PL_CDR2 spec, variants used based on member sizes
enum LengthCode {
    Lc1 = 0,
    Lc2 = 1,
    Lc4 = 2,
    Lc8 = 3,
    NextInt = 5, // NEXTINT reused as length
}

impl LengthCode {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Align an absolute offset to the given power-of-two boundary.
#[inline]
pub const fn align_offset(offset: usize, alignment: usize) -> usize {
    if alignment == 0 {
        offset
    } else {
        (offset + alignment - 1) & !(alignment - 1)
    }
}

/// Compute padding needed to reach the given alignment.
#[inline]
pub const fn padding_for_alignment(offset: usize, alignment: usize) -> usize {
    align_offset(offset, alignment) - offset
}

/// Encoder descriptor for a PL_CDR2 member.
#[allow(clippy::type_complexity)] // FnMut closure type for CDR encoding
pub struct PlMemberEncoder<'a> {
    pub member_id: u32,
    /// Alignment to apply before invoking `encode`.
    pub align: usize,
    /// Encode the member payload at the given absolute offset.
    ///
    /// The closure must return the number of bytes written.
    pub encode: &'a mut dyn FnMut(&mut [u8], usize) -> Result<usize, CdrError>,
}

/// Encode a mutable struct in PL_CDR2.
///
/// Layout: `[DHEADER:u32][MemberId][member payload]...`
pub fn encode_pl_cdr2_struct(
    dst: &mut [u8],
    members: &mut [PlMemberEncoder<'_>],
) -> Result<usize, CdrError> {
    let mut offset: usize = 0;

    if dst.len() < 4 {
        return Err(CdrError::BufferTooSmall);
    }

    // Reserve space for DHEADER (payload length)
    offset += 4;

    for m in members.iter_mut() {
        // EMHEADER1: LC=NEXTINT (reuse NEXTINT as member length), M_FLAG=0
        if dst.len() < offset + 4 {
            return Err(CdrError::BufferTooSmall);
        }
        let em = (LengthCode::NextInt.as_u32() << 28) | (m.member_id & 0x0fff_ffff);
        dst[offset..offset + 4].copy_from_slice(&em.to_le_bytes());
        offset += 4;

        // Placeholder for NEXTINT (member length)
        if dst.len() < offset + 4 {
            return Err(CdrError::BufferTooSmall);
        }
        let nextint_pos = offset;
        offset += 4;

        let member_start = offset;

        // Align member payload
        let aligned = align_offset(offset, m.align.max(1));
        if aligned > offset {
            if dst.len() < aligned {
                return Err(CdrError::BufferTooSmall);
            }
            dst[offset..aligned].fill(0);
            offset = aligned;
        }

        let used = (m.encode)(&mut dst[offset..], offset)?;
        offset += used;

        // Fill NEXTINT with member length (including any per-element DHEADERs written by encoder)
        let member_len = offset - member_start;
        let member_len_u32 = u32::try_from(member_len).map_err(|_| CdrError::InvalidEncoding)?;
        dst[nextint_pos..nextint_pos + 4].copy_from_slice(&member_len_u32.to_le_bytes());
    }

    let payload_len = u32::try_from(offset - 4).map_err(|_| CdrError::InvalidEncoding)?;
    dst[..4].copy_from_slice(&payload_len.to_le_bytes());
    Ok(offset)
}

/// Decode a mutable struct in PL_CDR2.
///
/// Calls `visitor` for each member encountered. The visitor receives the
/// `member_id`, the full source buffer, a mutable offset (pointing just
/// after the MemberId), and the end offset of the struct payload.
pub fn decode_pl_cdr2_struct<F>(src: &[u8], mut visitor: F) -> Result<(), CdrError>
where
    F: FnMut(u32, &[u8], &mut usize, usize) -> Result<(), CdrError>,
{
    if src.len() < 4 {
        return Err(CdrError::UnexpectedEof);
    }
    let payload_len = {
        let mut tmp = [0u8; 4];
        tmp.copy_from_slice(&src[..4]);
        u32::from_le_bytes(tmp) as usize
    };

    let end = 4 + payload_len;
    if end > src.len() {
        return Err(CdrError::UnexpectedEof);
    }

    let mut offset = 4;
    while offset < end {
        if src.len() < offset + 8 {
            return Err(CdrError::UnexpectedEof);
        }
        // SAFETY: Bounds checked at line 143 (src.len() < offset + 8)
        #[allow(clippy::expect_used)] // bounds validated above: src.len() >= offset + 8
        let em = u32::from_le_bytes(
            src[offset..offset + 4]
                .try_into()
                .expect("em bytes checked"),
        );
        offset += 4;
        let lc = (em >> 28) & 0x7;
        let member_id = em & 0x0fff_ffff;

        let member_len = if lc == LengthCode::NextInt.as_u32() {
            // SAFETY: Bounds checked at line 143 (src.len() < offset + 8)
            #[allow(clippy::expect_used)] // bounds validated above: src.len() >= offset + 8
            let len = u32::from_le_bytes(
                src[offset..offset + 4]
                    .try_into()
                    .expect("len bytes checked"),
            ) as usize;
            offset += 4;
            len
        } else {
            end.saturating_sub(offset)
        };
        let member_end = offset.saturating_add(member_len).min(end);

        visitor(member_id, src, &mut offset, member_end)?;
    }

    Ok(())
}

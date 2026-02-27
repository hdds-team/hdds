// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CDR2 encoding/decoding helper functions
//!
//! This module provides reusable helpers to eliminate duplication in CDR2 serialization code.
//! These helpers encapsulate common patterns found across unions.rs, structs.rs, and members.rs.
//!
//! # Design Rationale
//!
//! The XTypes v1.3 CDR2 encoding is highly repetitive:
//! - Sequential field encoding with offset tracking
//! - Detail decoding with re-encoding to determine size
//! - Member sequence decoding with 4-byte alignment
//! - Max size calculations for composite types
//!
//! These helpers reduce ~250 lines of duplication while preserving exact CDR2 semantics.
//!
//! # Performance
//!
//! All helpers use `#[inline]` to ensure zero-cost abstraction.
//! The generated code is identical to hand-written encoding/decoding.

use super::primitives::{align_offset, decode_u32};
use crate::core::ser::traits::{Cdr2Decode, Cdr2Encode, CdrError};
use std::convert::TryFrom;

/// Encodes multiple fields sequentially, tracking offset automatically.
///
/// This helper eliminates the boilerplate of:
/// 1. Initializing `offset = 0`
/// 2. Encoding each field and updating offset
/// 3. Returning the final offset
///
/// # Arguments
///
/// * `dst` - Destination buffer for encoded data
/// * `encoders` - Mutable slice of encoding closures (each returns bytes written)
///
/// # Returns
///
/// Total bytes written to `dst`
///
/// # Errors
///
/// Returns `CdrError` if any field encoding fails (buffer too small, invalid data, etc.)
///
/// # Examples
///
/// ```ignore
/// // Before (8-10 lines):
/// let mut offset = 0;
/// let field1_len = self.field1.encode_cdr2_le(&mut dst[offset..])?;
/// offset += field1_len;
/// let field2_len = self.field2.encode_cdr2_le(&mut dst[offset..])?;
/// offset += field2_len;
/// Ok(offset)
///
/// // After (3 lines):
/// let mut encode_field1 = |buf: &mut [u8]| self.field1.encode_cdr2_le(buf);
/// let mut encode_field2 = |buf: &mut [u8]| self.field2.encode_cdr2_le(buf);
/// encode_fields_sequential(dst, &mut [&mut encode_field1, &mut encode_field2])
/// ```
///
/// # CDR2 Specification
///
/// Per XTypes v1.3 Sec.7.3.1.2, struct members are encoded sequentially with proper alignment.
/// This helper maintains the required sequencing while eliminating manual offset tracking.
type EncoderFn<'a> = dyn FnMut(&mut [u8]) -> Result<usize, CdrError> + 'a;

#[cfg_attr(not(test), allow(dead_code))]
#[inline]
/// Encodes a sequence of struct fields back-to-back, returning bytes written.
pub fn encode_fields_sequential<'a>(
    dst: &mut [u8],
    encoders: &mut [&'a mut EncoderFn<'a>],
) -> Result<usize, CdrError> {
    let mut offset = 0;
    for encoder in encoders {
        let len = encoder(&mut dst[offset..])?;
        offset += len;
    }
    Ok(offset)
}

/// Decodes a detail field and updates offset with bytes consumed.
///
/// # Arguments
///
/// * `src` - Source buffer containing encoded data
/// * `offset` - Current offset (will be updated to point after the decoded detail)
///
/// # Returns
///
/// The decoded detail object
///
/// # Errors
///
/// Returns `CdrError` if decoding fails
///
/// # Type Parameters
///
/// * `T` - The detail type (must implement `Cdr2Decode`)
///
/// # Examples
///
/// ```ignore
/// let detail = decode_detail_with_reencoding::<CompleteTypeDetail>(src, offset)?;
/// ```
///
/// # CDR2 Specification
///
/// Per XTypes v1.3 Sec.7.3.1.1, type details use variable-length encoding.
/// The decode returns both the value and bytes consumed.
#[inline]
pub fn decode_detail_with_reencoding<T>(src: &[u8], offset: &mut usize) -> Result<T, CdrError>
where
    T: Cdr2Decode,
{
    let (detail, used) = T::decode_cdr2_le(&src[*offset..])?;
    *offset += used;
    Ok(detail)
}

/// Decodes a sequence of members with 4-byte alignment per element.
///
/// # Problem
///
/// CDR2 requires each struct element in a sequence to be aligned to 4 bytes (XTypes v1.3 Sec.7.3.1.2).
/// This alignment logic is repeated for every member sequence decode.
///
/// # Arguments
///
/// * `src` - Source buffer containing encoded sequence
/// * `offset` - Current offset (will be updated to point after the sequence)
/// * `decode_fn` - Function to decode individual members
///
/// # Returns
///
/// Vector of decoded members
///
/// # Errors
///
/// Returns `CdrError` if sequence length decode fails, alignment fails, or any member decode fails
///
/// # Type Parameters
///
/// * `T` - The member type
/// * `F` - Decode function type (`Fn(&[u8], &mut usize) -> Result<T, CdrError>`)
///
/// # Examples
///
/// ```ignore
/// // Before (8 lines):
/// let member_len = decode_u32(src, offset)?;
/// let mut member_seq = Vec::with_capacity(member_len as usize);
/// for _ in 0..member_len {
///     *offset = align_offset(*offset, 4);
///     let member = decode_complete_struct_member_internal(src, offset)?;
///     member_seq.push(member);
/// }
///
/// // After (1 line):
/// let member_seq = decode_member_sequence(src, offset, decode_complete_struct_member_internal)?;
/// ```
///
/// # CDR2 Specification
///
/// Per XTypes v1.3 Sec.7.3.1.2.1, sequences of struct types require 4-byte alignment for each element.
/// This helper ensures correct alignment while eliminating manual loop boilerplate.
#[inline]
pub fn decode_member_sequence<T, F>(
    src: &[u8],
    offset: &mut usize,
    decode_fn: F,
) -> Result<Vec<T>, CdrError>
where
    F: Fn(&[u8], &mut usize) -> Result<T, CdrError>,
{
    let member_len = checked_usize(decode_u32(src, offset)?, "member sequence length")?;
    let mut member_seq = Vec::with_capacity(member_len);

    for _ in 0..member_len {
        // Align each element to 4 bytes (CDR2 struct alignment in sequences)
        *offset = align_offset(*offset, 4);
        let member = decode_fn(src, offset)?;
        member_seq.push(member);
    }

    Ok(member_seq)
}

/// Calculates max CDR2 size for types with header and member sequences.
///
/// # Formula
///
/// ```text
/// max_size = flags (4 bytes)
///          + header.max_cdr2_size()
///          + length_prefix (4 bytes)
///          + sum(member.max_cdr2_size())
/// ```
///
/// This is a **conservative estimate** (worst-case size).
/// Actual encoded size may be smaller due to optimizations.
///
/// # Arguments
///
/// * `header` - The header object (CompleteStructHeader, MinimalStructHeader, etc.)
/// * `member_seq` - Slice of members (CompleteStructMember, MinimalStructMember, etc.)
///
/// # Returns
///
/// Maximum possible CDR2 encoding size in bytes
///
/// # Type Parameters
///
/// * `H` - Header type (must implement `Cdr2Encode`)
/// * `M` - Member type (must implement `Cdr2Encode`)
///
/// # Examples
///
/// ```ignore
/// // Before (10 lines):
/// fn max_cdr2_size(&self) -> usize {
///     4 + self.header.max_cdr2_size()
///         + 4
///         + self
///             .member_seq
///             .iter()
///             .map(|m| m.max_cdr2_size())
///             .sum::<usize>()
/// }
///
/// // After (3 lines):
/// fn max_cdr2_size(&self) -> usize {
///     max_size_type_with_members(&self.header, &self.member_seq)
/// }
/// ```
///
/// # CDR2 Specification
///
/// Per XTypes v1.3 Sec.7.3.1.2, struct types encode flags (4 bytes), header, length (4 bytes),
/// then member sequence. This helper calculates the maximum buffer size needed.
#[inline]
pub fn max_size_type_with_members<H, M>(header: &H, member_seq: &[M]) -> usize
where
    H: Cdr2Encode,
    M: Cdr2Encode,
{
    4 + header.max_cdr2_size() + 4 + member_seq.iter().map(|m| m.max_cdr2_size()).sum::<usize>()
}

/// Maximum allowed sequence length to prevent allocation bombs from malformed input.
/// 1M elements is far beyond any legitimate DDS type while still catching OOM attacks.
const MAX_SEQUENCE_LENGTH: usize = 1_000_000;

#[inline]
pub(super) fn checked_usize(value: u32, context: &str) -> Result<usize, CdrError> {
    let len = usize::try_from(value)
        .map_err(|_| CdrError::Other(format!("{context} exceeds platform capacity")))?;

    // Security: Prevent allocation bombs from malformed RTPS packets
    if len > MAX_SEQUENCE_LENGTH {
        return Err(CdrError::Other(format!(
            "{context} exceeds maximum allowed ({MAX_SEQUENCE_LENGTH})"
        )));
    }

    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_fields_sequential() {
        let mut dst = vec![0u8; 100];

        let mut field1 = |buf: &mut [u8]| -> Result<usize, CdrError> {
            buf[0..4].copy_from_slice(&42u32.to_le_bytes());
            Ok(4)
        };
        let mut field2 = |buf: &mut [u8]| -> Result<usize, CdrError> {
            buf[0..4].copy_from_slice(&123u32.to_le_bytes());
            Ok(4)
        };
        let mut field3 = |buf: &mut [u8]| -> Result<usize, CdrError> {
            buf[0..4].copy_from_slice(&999u32.to_le_bytes());
            Ok(4)
        };

        let result =
            encode_fields_sequential(&mut dst, &mut [&mut field1, &mut field2, &mut field3]);

        let written =
            result.expect("encode_fields_sequential should succeed for three u32 encoders");
        assert_eq!(written, 12);

        assert_eq!(u32::from_le_bytes([dst[0], dst[1], dst[2], dst[3]]), 42);
        assert_eq!(u32::from_le_bytes([dst[4], dst[5], dst[6], dst[7]]), 123);
        assert_eq!(u32::from_le_bytes([dst[8], dst[9], dst[10], dst[11]]), 999);
    }

    #[test]
    fn test_encode_fields_sequential_buffer_too_small() {
        let mut dst = vec![0u8; 5];

        let mut field1 = |buf: &mut [u8]| -> Result<usize, CdrError> {
            if buf.len() < 4 {
                Err(CdrError::BufferTooSmall)
            } else {
                buf[0..4].copy_from_slice(&42u32.to_le_bytes());
                Ok(4)
            }
        };
        let mut field2 = |buf: &mut [u8]| -> Result<usize, CdrError> {
            if buf.len() < 4 {
                Err(CdrError::BufferTooSmall)
            } else {
                buf[0..4].copy_from_slice(&123u32.to_le_bytes());
                Ok(4)
            }
        };

        let result = encode_fields_sequential(&mut dst, &mut [&mut field1, &mut field2]);

        assert!(result.is_err());
    }

    #[test]
    fn test_max_size_type_with_members() {
        struct MockHeader;
        impl Cdr2Encode for MockHeader {
            fn encode_cdr2_le(&self, _dst: &mut [u8]) -> Result<usize, CdrError> {
                Ok(16)
            }
            fn max_cdr2_size(&self) -> usize {
                16
            }
        }

        struct MockMember;
        impl Cdr2Encode for MockMember {
            fn encode_cdr2_le(&self, _dst: &mut [u8]) -> Result<usize, CdrError> {
                Ok(8)
            }
            fn max_cdr2_size(&self) -> usize {
                8
            }
        }

        let header = MockHeader;
        let members = vec![MockMember, MockMember, MockMember];

        let max_size = max_size_type_with_members(&header, &members);

        assert_eq!(max_size, 48);
    }

    #[test]
    fn test_max_size_type_with_members_empty() {
        struct MockHeader;
        impl Cdr2Encode for MockHeader {
            fn encode_cdr2_le(&self, _dst: &mut [u8]) -> Result<usize, CdrError> {
                Ok(16)
            }
            fn max_cdr2_size(&self) -> usize {
                16
            }
        }

        let header = MockHeader;
        let members: Vec<MockHeader> = vec![];

        let max_size = max_size_type_with_members(&header, &members);

        assert_eq!(max_size, 24);
    }
}

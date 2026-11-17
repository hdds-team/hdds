// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Common utilities shared across all dialect encoders
//!
//! These functions handle low-level byte manipulation and alignment
//! that are identical across all RTPS implementations.

use std::net::SocketAddr;

use super::error::{EncodeError, EncodeResult};

// ===== Byte Writing Utilities =====

/// Write a u16 in little-endian format
#[inline]
pub fn write_u16_le(buf: &mut [u8], offset: &mut usize, val: u16) -> EncodeResult<()> {
    if *offset + 2 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 2].copy_from_slice(&val.to_le_bytes());
    *offset += 2;
    Ok(())
}

/// Write a u32 in little-endian format
#[inline]
pub fn write_u32_le(buf: &mut [u8], offset: &mut usize, val: u32) -> EncodeResult<()> {
    if *offset + 4 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 4].copy_from_slice(&val.to_le_bytes());
    *offset += 4;
    Ok(())
}

/// Write a u64 in little-endian format
#[inline]
pub fn write_u64_le(buf: &mut [u8], offset: &mut usize, val: u64) -> EncodeResult<()> {
    if *offset + 8 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + 8].copy_from_slice(&val.to_le_bytes());
    *offset += 8;
    Ok(())
}

/// Write raw bytes
#[inline]
pub fn write_bytes(buf: &mut [u8], offset: &mut usize, data: &[u8]) -> EncodeResult<()> {
    if *offset + data.len() > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset..*offset + data.len()].copy_from_slice(data);
    *offset += data.len();
    Ok(())
}

// ===== Alignment Utilities =====

/// Align offset to 4-byte boundary (with zero padding)
#[inline]
pub fn align_to_4(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    while !(*offset).is_multiple_of(4) {
        if *offset >= buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[*offset] = 0;
        *offset += 1;
    }
    Ok(())
}

/// Align offset to 8-byte boundary (with zero padding)
#[inline]
pub fn align_to_8(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    while !(*offset).is_multiple_of(8) {
        if *offset >= buf.len() {
            return Err(EncodeError::BufferTooSmall);
        }
        buf[*offset] = 0;
        *offset += 1;
    }
    Ok(())
}

// ===== PID Writing Utilities =====

/// Write a PID header (pid + length)
#[inline]
pub fn write_pid_header(
    buf: &mut [u8],
    offset: &mut usize,
    pid: u16,
    len: u16,
) -> EncodeResult<()> {
    write_u16_le(buf, offset, pid)?;
    write_u16_le(buf, offset, len)?;
    Ok(())
}

/// Write PID_SENTINEL (0x0001, length 0)
#[inline]
pub fn write_sentinel(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    write_pid_header(buf, offset, 0x0001, 0)
}

// ===== CDR Encapsulation =====

/// CDR encapsulation kinds
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdrEncapsulation {
    /// CDR Big-Endian
    CdrBe = 0x0000,
    /// CDR Little-Endian
    CdrLe = 0x0001,
    /// Parameter List CDR Big-Endian
    PlCdrBe = 0x0002,
    /// Parameter List CDR Little-Endian
    PlCdrLe = 0x0003,
    /// XCDR1 Big-Endian
    Xcdr1Be = 0x0004,
    /// XCDR1 Little-Endian
    Xcdr1Le = 0x0005,
    /// XCDR2 Big-Endian
    Xcdr2Be = 0x0006,
    /// XCDR2 Little-Endian
    Xcdr2Le = 0x0007,
    /// Parameter List XCDR2 Big-Endian
    PlXcdr2Be = 0x000A,
    /// Parameter List XCDR2 Little-Endian
    PlXcdr2Le = 0x000B,
}

/// Write CDR encapsulation header (4 bytes)
#[inline]
pub fn write_cdr_header(
    buf: &mut [u8],
    offset: &mut usize,
    kind: CdrEncapsulation,
) -> EncodeResult<()> {
    if *offset + 4 > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    let kind_val = kind as u16;
    // Encapsulation header is always big-endian per CDR spec
    buf[*offset] = (kind_val >> 8) as u8;
    buf[*offset + 1] = (kind_val & 0xFF) as u8;
    buf[*offset + 2] = 0x00; // options
    buf[*offset + 3] = 0x00; // options
    *offset += 4;
    Ok(())
}

// ===== RTPS Constants =====

/// RTPS protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub const V2_1: Self = Self { major: 2, minor: 1 };
    pub const V2_2: Self = Self { major: 2, minor: 2 };
    pub const V2_3: Self = Self { major: 2, minor: 3 };
    pub const V2_4: Self = Self { major: 2, minor: 4 };
    pub const V2_5: Self = Self { major: 2, minor: 5 };
    pub const V2_6: Self = Self { major: 2, minor: 6 };
}

/// Duration with seconds and nanoseconds (DDS Duration_t)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duration {
    pub seconds: u32,
    pub nanoseconds: u32,
}

impl Duration {
    /// Infinite duration (max u32 for both fields)
    pub const INFINITE: Self = Self {
        seconds: u32::MAX,
        nanoseconds: u32::MAX,
    };

    /// Zero duration
    pub const ZERO: Self = Self {
        seconds: 0,
        nanoseconds: 0,
    };
}

/// Write a Duration_t (8 bytes)
#[inline]
pub fn write_duration(buf: &mut [u8], offset: &mut usize, duration: Duration) -> EncodeResult<()> {
    write_u32_le(buf, offset, duration.seconds)?;
    write_u32_le(buf, offset, duration.nanoseconds)?;
    Ok(())
}

// ===== String Encoding =====

/// Write a CDR string (length-prefixed, null-terminated, aligned)
pub fn write_cdr_string(buf: &mut [u8], offset: &mut usize, s: &str) -> EncodeResult<()> {
    let bytes = s.as_bytes();
    let len_with_null = bytes.len() + 1; // +1 for null terminator

    // Write length (u32)
    write_u32_le(buf, offset, cdr_length(len_with_null)?)?;

    // Write string bytes
    write_bytes(buf, offset, bytes)?;

    // Write null terminator
    if *offset >= buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }
    buf[*offset] = 0;
    *offset += 1;

    // Align to 4-byte boundary
    align_to_4(buf, offset)?;

    Ok(())
}

// ===== Wire-width conversions =====
//
// Every length that reaches the wire is computed in `usize` and stored in a
// narrower field. These conversions are checked: a value that does not fit
// is an encoding error, never a wrapped field.

/// Narrow a submessage body length to `octetsToNextHeader` (u16, RTPS v2.5
/// Sec.9.4.5.1.3).
///
/// The rule lives in `protocol::rtps::octets_to_next_header` (with its one
/// exception, the last-submessage sentinel, next to it); this is the same
/// rule in the dialect layer's error type, not a second statement of it.
#[inline]
pub fn octets_to_next_header(submsg_len: usize) -> EncodeResult<u16> {
    crate::protocol::rtps::octets_to_next_header(submsg_len)
        .map_err(|e| EncodeError::InvalidParameter(e.to_string()))
}

/// Narrow a ParameterList value length to `parameterLength` (u16, RTPS v2.5
/// Sec.9.4.2.11).
#[inline]
pub fn parameter_length(len: usize) -> EncodeResult<u16> {
    u16::try_from(len).map_err(|_| {
        EncodeError::InvalidParameter("parameter value exceeds parameterLength (u16)".into())
    })
}

/// Narrow a CDR string or sequence length to its 32-bit prefix.
#[inline]
pub fn cdr_length(len: usize) -> EncodeResult<u32> {
    u32::try_from(len)
        .map_err(|_| EncodeError::InvalidParameter("length exceeds the CDR u32 prefix".into()))
}

// ===== SequenceNumberSet =====

/// Number of bits a SequenceNumberSet / FragmentNumberSet bitmap actually
/// uses: the position of the highest set bit plus one, or 0 when every word
/// is zero (RTPS v2.5 Sec.9.4.2.6, `numBits`).
///
/// One copy for every dialect encoder, so the arithmetic is checked once:
/// the word index is converted, not cast, and a bitmap too long for `numBits`
/// to describe is refused instead of wrapping.
pub fn sequence_number_set_num_bits(bitmap: &[u32]) -> EncodeResult<u32> {
    let Some(idx) = bitmap.iter().rposition(|&word| word != 0) else {
        return Ok(0);
    };
    // For a non-zero word, 32 - leading_zeros is the highest set bit + 1.
    let bits_in_last_word = 32 - bitmap[idx].leading_zeros();
    u32::try_from(idx)
        .ok()
        .and_then(|words| words.checked_mul(32))
        .and_then(|bits| bits.checked_add(bits_in_last_word))
        .ok_or_else(|| EncodeError::InvalidParameter("bitmap too long for numBits".into()))
}

// ===== Locator Encoding =====

/// PID for unicast locator
pub const PID_UNICAST_LOCATOR: u16 = 0x002f;

/// Write PID_UNICAST_LOCATOR (0x002f) - 24 bytes
///
/// Standard locator encoding shared across all dialects.
pub fn write_unicast_locator(
    locator: &SocketAddr,
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    crate::protocol::rtps::encode_locator_parameter(PID_UNICAST_LOCATOR, locator, buf, offset)
        .map_err(|_| EncodeError::BufferTooSmall)
}

// ===== Standard SPDP =====

/// Build the standard HDDS SPDP ParameterList (`protocol::discovery::build_spdp`,
/// the one on the live discovery path) for the dialects that use it as is.
///
/// `domain_id` goes into PID_DOMAIN_ID.
pub(crate) fn build_standard_spdp(
    participant_guid: &super::Guid,
    unicast_locators: &[SocketAddr],
    multicast_locators: &[SocketAddr],
    lease_duration_sec: u32,
    domain_id: u32,
) -> EncodeResult<Vec<u8>> {
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::SpdpData;

    let mut guid_bytes = [0u8; 16];
    guid_bytes[..12].copy_from_slice(&participant_guid.prefix);
    guid_bytes[12..16].copy_from_slice(&participant_guid.entity_id);

    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes(guid_bytes),
        lease_duration_ms: u64::from(lease_duration_sec) * 1000,
        domain_id,
        metatraffic_unicast_locators: unicast_locators.to_vec(),
        default_unicast_locators: unicast_locators.to_vec(),
        default_multicast_locators: multicast_locators.to_vec(),
        metatraffic_multicast_locators: multicast_locators.to_vec(),
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };

    let mut buf = vec![0u8; 2048];
    let len = crate::protocol::discovery::build_spdp(&spdp_data, &mut buf)
        .map_err(|_| EncodeError::BufferTooSmall)?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_U32_VALUE: u32 = 0x1234_5678;

    #[test]
    fn test_write_u32_le() {
        let mut buf = [0u8; 8];
        let mut offset = 0;
        write_u32_le(&mut buf, &mut offset, TEST_U32_VALUE).expect("write_u32_le failed");
        assert_eq!(&buf[0..4], &[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_align_to_4() {
        let mut buf = [0xFFu8; 8];
        let mut offset = 1;
        align_to_4(&mut buf, &mut offset).expect("align_to_4 failed");
        assert_eq!(offset, 4);
        assert_eq!(&buf[1..4], &[0, 0, 0]);
    }

    #[test]
    fn test_write_cdr_string() {
        let mut buf = [0u8; 32];
        let mut offset = 0;
        write_cdr_string(&mut buf, &mut offset, "test").expect("write_cdr_string failed");
        // length (5) + "test" + null + padding to align
        assert_eq!(&buf[0..4], &[5, 0, 0, 0]); // length = 5
        assert_eq!(&buf[4..9], b"test\0");
        assert_eq!(offset, 12); // aligned to 4
    }
}

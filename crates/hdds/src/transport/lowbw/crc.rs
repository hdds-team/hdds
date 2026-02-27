// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! CRC-16/CCITT-FALSE checksum for frame integrity.
//!
//! This CRC variant is widely used and has good error detection properties.
//!
//! # Parameters (CRC-16/CCITT-FALSE)
//!
//! | Parameter | Value |
//! |-----------|-------|
//! | Polynomial | 0x1021 |
//! | Init | 0xFFFF |
//! | RefIn | false |
//! | RefOut | false |
//! | XorOut | 0x0000 |
//!
//! # Test Vector
//!
//! ```
//! use hdds::transport::lowbw::crc::crc16_ccitt;
//!
//! // Standard test vector: "123456789" -> 0x29B1
//! let crc = crc16_ccitt(b"123456789");
//! assert_eq!(crc, 0x29B1);
//! ```

/// CRC-16/CCITT-FALSE polynomial.
const POLY: u16 = 0x1021;

/// Initial value for CRC calculation.
const INIT: u16 = 0xFFFF;

/// Precomputed lookup table for CRC-16/CCITT-FALSE.
///
/// Generated at compile time for maximum performance.
const CRC_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut j = 0;
        while j < 8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ POLY;
            } else {
                crc <<= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// Calculate CRC-16/CCITT-FALSE checksum.
///
/// # Arguments
///
/// * `data` - The data to checksum
///
/// # Returns
///
/// 16-bit CRC value.
#[inline]
#[must_use]
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    crc16_ccitt_update(INIT, data)
}

/// Update an existing CRC with more data.
///
/// Useful for streaming CRC calculation.
#[inline]
#[must_use]
pub fn crc16_ccitt_update(crc: u16, data: &[u8]) -> u16 {
    let mut crc = crc;
    for &byte in data {
        let index = ((crc >> 8) ^ u16::from(byte)) as usize;
        crc = (crc << 8) ^ CRC_TABLE[index];
    }
    crc
}

/// Verify data against an expected CRC.
///
/// # Arguments
///
/// * `data` - The data to verify
/// * `expected_crc` - The expected CRC value
///
/// # Returns
///
/// `true` if the CRC matches, `false` otherwise.
#[inline]
#[must_use]
pub fn verify_crc16(data: &[u8], expected_crc: u16) -> bool {
    crc16_ccitt(data) == expected_crc
}

/// Append CRC to a buffer (big-endian, as per convention).
///
/// # Arguments
///
/// * `buf` - Buffer containing data, with 2 bytes reserved at the end for CRC
/// * `data_len` - Length of actual data (CRC will be written at `data_len..data_len+2`)
#[inline]
pub fn append_crc16(buf: &mut [u8], data_len: usize) {
    let crc = crc16_ccitt(&buf[..data_len]);
    buf[data_len] = (crc >> 8) as u8; // High byte first (big-endian)
    buf[data_len + 1] = crc as u8;
}

/// Extract and verify CRC from a buffer.
///
/// Assumes CRC is stored as the last 2 bytes in big-endian format.
///
/// # Arguments
///
/// * `buf` - Buffer containing data + CRC (minimum 3 bytes)
///
/// # Returns
///
/// `Some(data_slice)` if CRC is valid, `None` if invalid or buffer too small.
#[inline]
#[must_use]
pub fn verify_and_strip_crc(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 3 {
        return None;
    }

    let data_len = buf.len() - 2;
    let data = &buf[..data_len];
    let stored_crc = u16::from_be_bytes([buf[data_len], buf[data_len + 1]]);

    if verify_crc16(data, stored_crc) {
        Some(data)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard test vector from CRC catalog.
    #[test]
    fn test_crc16_ccitt_standard_vector() {
        let crc = crc16_ccitt(b"123456789");
        assert_eq!(crc, 0x29B1, "Standard test vector must produce 0x29B1");
    }

    #[test]
    fn test_crc16_empty() {
        // Empty data should return init value XOR xorout (0xFFFF ^ 0x0000 = 0xFFFF)
        let crc = crc16_ccitt(&[]);
        assert_eq!(crc, 0xFFFF);
    }

    #[test]
    fn test_crc16_single_byte() {
        // Single byte tests for sanity
        let crc = crc16_ccitt(&[0x00]);
        assert_ne!(crc, 0xFFFF); // Should change from init

        let crc = crc16_ccitt(&[0xFF]);
        assert_ne!(crc, 0xFFFF);
    }

    #[test]
    fn test_crc16_incremental() {
        // CRC of "123456789" computed incrementally should match single-shot
        let data = b"123456789";

        let single_shot = crc16_ccitt(data);

        let mut incremental = INIT;
        for chunk in data.chunks(3) {
            incremental = crc16_ccitt_update(incremental, chunk);
        }

        assert_eq!(incremental, single_shot);
    }

    #[test]
    fn test_verify_crc16() {
        let data = b"Hello, World!";
        let crc = crc16_ccitt(data);

        assert!(verify_crc16(data, crc));
        assert!(!verify_crc16(data, crc.wrapping_add(1)));
        assert!(!verify_crc16(data, 0));
    }

    #[test]
    fn test_append_crc16() {
        let mut buf = [0u8; 15];
        buf[..13].copy_from_slice(b"Hello, World!");

        append_crc16(&mut buf, 13);

        let expected_crc = crc16_ccitt(b"Hello, World!");
        assert_eq!(buf[13], (expected_crc >> 8) as u8);
        assert_eq!(buf[14], expected_crc as u8);
    }

    #[test]
    fn test_verify_and_strip_crc() {
        // Valid data + CRC
        let data = b"Test data";
        let crc = crc16_ccitt(data);
        let mut buf = Vec::with_capacity(data.len() + 2);
        buf.extend_from_slice(data);
        buf.push((crc >> 8) as u8);
        buf.push(crc as u8);

        let result = verify_and_strip_crc(&buf);
        assert!(result.is_some());
        assert_eq!(result.expect("valid CRC"), data);

        // Corrupted CRC
        let mut corrupted = buf.clone();
        corrupted[buf.len() - 1] ^= 0xFF;
        assert!(verify_and_strip_crc(&corrupted).is_none());

        // Too short
        assert!(verify_and_strip_crc(&[0x00, 0x00]).is_none());
        assert!(verify_and_strip_crc(&[0x00]).is_none());
        assert!(verify_and_strip_crc(&[]).is_none());
    }

    #[test]
    fn test_crc16_detects_single_bit_flip() {
        let data = b"Original data";
        let original_crc = crc16_ccitt(data);

        // Flip each bit and verify CRC changes
        let mut modified = data.to_vec();
        for i in 0..modified.len() {
            for bit in 0..8 {
                modified[i] ^= 1 << bit;
                let new_crc = crc16_ccitt(&modified);
                assert_ne!(
                    new_crc, original_crc,
                    "CRC should detect single bit flip at byte {} bit {}",
                    i, bit
                );
                modified[i] ^= 1 << bit; // Restore
            }
        }
    }

    #[test]
    fn test_crc16_table_generation() {
        // Verify the table matches manual calculation for a few entries
        // Entry 0: all zeros processed -> 0
        assert_eq!(CRC_TABLE[0], 0);

        // Entry 1: single bit set
        let mut crc: u16 = 1 << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ POLY;
            } else {
                crc <<= 1;
            }
        }
        assert_eq!(CRC_TABLE[1], crc);
    }

    #[test]
    fn test_known_values() {
        // Additional known values for validation
        // These are computed with reference implementations

        // Empty string
        assert_eq!(crc16_ccitt(b""), 0xFFFF);

        // Single 'A'
        let crc_a = crc16_ccitt(b"A");
        // The exact value depends on the algorithm, but it should be consistent
        assert_ne!(crc_a, 0xFFFF);

        // Two identical inputs should produce identical CRCs
        assert_eq!(crc16_ccitt(b"test"), crc16_ccitt(b"test"));

        // Different inputs should (very likely) produce different CRCs
        assert_ne!(crc16_ccitt(b"test1"), crc16_ccitt(b"test2"));
    }
}

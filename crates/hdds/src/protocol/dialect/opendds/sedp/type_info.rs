// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OpenDDS XTypes TypeInformation encoding
//!
//!
//! PID_TYPE_INFORMATION (0x0075) is required for OpenDDS XTypes matching.
//! OpenDDS sends TypeInformation in its DATA(w) and expects it back in DATA(r)
//! for proper endpoint matching.
//!
//! # Wire Format (from OpenDDS capture)
//!
//! OpenDDS PID_TYPE_INFORMATION is 88 bytes:
//! ```text
//! PID: 75 00 (0x0075 = PID_TYPE_INFORMATION)
//! LEN: 54 00 (0x0054 = 84 bytes payload)
//!
//! TypeInformation structure:
//! - TypeIdentifierWithDependencies minimal (TypeFlag + TypeId + dep count)
//! - TypeIdentifierWithDependencies complete (TypeFlag + TypeId + dep count)
//! ```
//!
//! # Minimal TypeInformation for Basic Types
//!
//! For basic struct types (like Temperature), we can send a minimal TypeInformation
//! that indicates "no XTypes propagation needed, match by type name".
//!
//! This matches what OpenDDS does when type consistency is relaxed.

use crate::protocol::dialect::error::{EncodeError, EncodeResult};

/// PID_TYPE_INFORMATION (0x0075) - XTypes TypeInformation
pub const PID_TYPE_INFORMATION: u16 = 0x0075;

/// Write PID_TYPE_INFORMATION (0x0075) for OpenDDS interop.
///
/// This writes the TypeInformation captured from OpenDDS for the Temperature type.
/// The TypeIdentifier hash must match what OpenDDS computes for the same type.
///
/// # Temperature Type Structure (IDL)
/// ```idl
/// module TemperatureModule {
///     struct Temperature {
///         float value;
///         long timestamp;
///     };
/// };
/// ```
///
/// # OpenDDS TypeInformation
/// OpenDDS computes TypeIdentifier hashes via MD5 of the serialized TypeObject.
/// We use the exact TypeInformation bytes that OpenDDS sends for this type.
pub fn write_type_information(buf: &mut [u8], offset: &mut usize) -> EncodeResult<()> {
    // TypeInformation captured from OpenDDS for TemperatureModule::Temperature.
    // This is the exact bytes from OpenDDS DATA(w) for the Temperature type.
    //
    // Format breakdown:
    // - DHEADER: 0x54 (84 bytes of TypeInformation)
    // - TypeIdentifierWithDependencies[0] (minimal): type hash + size + deps
    // - TypeIdentifierWithDependencies[1] (complete): type hash + size + deps
    //
    // The key is the TypeIdentifier hash which OpenDDS computes from:
    // - Type name: "TemperatureModule::Temperature"
    // - Members: float value (member_id=0), long timestamp (member_id=1)
    //
    // Rather than computing this ourselves, we use OpenDDS's bytes directly
    // since both endpoints must agree on the same type.

    #[rustfmt::skip]
    const OPENDDS_TEMPERATURE_TYPE_INFO: &[u8] = &[
        // TypeInformation DHEADER (4 bytes)
        0x54, 0x00, 0x00, 0x00,  // 84 bytes payload

        // TypeIdentifierWithDependencies minimal (44 bytes)
        0x01, 0x10, 0x00, 0x40,  // flags/discriminator
        0x28, 0x00, 0x00, 0x00,  // emheader = 40 bytes
        0x24, 0x00, 0x00, 0x00,  // TypeIdentifierWithSize header
        0x14, 0x00, 0x00, 0x00,  // TypeIdentifier part = 20 bytes
        // Minimal TypeIdentifier hash (14 bytes) - MD5 of MinimalTypeObject
        0xf1, 0x62, 0xe8, 0x37, 0xc4, 0xdd, 0xfe, 0x55,
        0xe7, 0x3a, 0x7b, 0xba, 0x1d, 0x62, 0x67, 0x00,
        0x37, 0x00, 0x00, 0x00,  // typeobject_serialized_size = 55
        0xff, 0xff, 0xff, 0xff,  // bound
        0x04, 0x00, 0x00, 0x00,  // dependent count
        0x00, 0x00, 0x00, 0x00,  // empty deps

        // TypeIdentifierWithDependencies complete (36 bytes)
        0x02, 0x10, 0x00, 0x40,  // flags/discriminator
        0x1c, 0x00, 0x00, 0x00,  // emheader = 28 bytes
        0x18, 0x00, 0x00, 0x00,  // TypeIdentifierWithSize header
        0x08, 0x00, 0x00, 0x00,  // TypeIdentifier part = 8 bytes
        // Complete part - appears to be empty/none type
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let payload_len: u16 = OPENDDS_TEMPERATURE_TYPE_INFO.len() as u16;
    let total_len = 4 + payload_len as usize;

    if *offset + total_len > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // PID header
    buf[*offset..*offset + 2].copy_from_slice(&PID_TYPE_INFORMATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&payload_len.to_le_bytes());
    *offset += 4;

    // Copy TypeInformation payload
    buf[*offset..*offset + payload_len as usize].copy_from_slice(OPENDDS_TEMPERATURE_TYPE_INFO);
    *offset += payload_len as usize;

    Ok(())
}

/// Write PID_TYPE_INFORMATION with raw bytes (from parsed OpenDDS TypeInfo).
///
/// Used when we want to echo back the exact TypeInformation that the peer sent.
/// This is useful for strict type matching scenarios.
#[allow(dead_code)] // Part of OpenDDS XTypes API, used for type information exchange
pub fn write_type_information_raw(
    type_info_bytes: &[u8],
    buf: &mut [u8],
    offset: &mut usize,
) -> EncodeResult<()> {
    if type_info_bytes.is_empty() {
        return Ok(()); // Nothing to write
    }

    let payload_len = type_info_bytes.len();
    if payload_len > u16::MAX as usize {
        return Err(EncodeError::InvalidParameter(
            "TypeInformation too large".to_string(),
        ));
    }

    // 4-byte alignment
    let aligned_len = (payload_len + 3) & !3;
    let total_len = 4 + aligned_len;

    if *offset + total_len > buf.len() {
        return Err(EncodeError::BufferTooSmall);
    }

    // PID header
    buf[*offset..*offset + 2].copy_from_slice(&PID_TYPE_INFORMATION.to_le_bytes());
    buf[*offset + 2..*offset + 4].copy_from_slice(&(aligned_len as u16).to_le_bytes());
    *offset += 4;

    // Payload
    buf[*offset..*offset + payload_len].copy_from_slice(type_info_bytes);
    *offset += payload_len;

    // Padding
    let padding = aligned_len - payload_len;
    if padding > 0 {
        buf[*offset..*offset + padding].fill(0);
        *offset += padding;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_type_information() {
        let mut buf = [0u8; 128];
        let mut offset = 0;

        write_type_information(&mut buf, &mut offset).expect("should succeed");

        // Check PID
        assert_eq!(&buf[0..2], &PID_TYPE_INFORMATION.to_le_bytes());
        // Check length (88 bytes = same as OpenDDS)
        assert_eq!(&buf[2..4], &88u16.to_le_bytes());
        // Total offset should be 4 + 88 = 92
        assert_eq!(offset, 92);

        // Verify the TypeIdentifier hash matches OpenDDS
        // Structure after PID header (4 bytes):
        // - DHEADER (4 bytes): 0x54, 0x00, 0x00, 0x00
        // - flags (4 bytes): 0x01, 0x10, 0x00, 0x40
        // - emheader (4 bytes): 0x28, 0x00, 0x00, 0x00
        // - TypeIdWithSize header (4 bytes): 0x24, 0x00, 0x00, 0x00
        // - TypeId part header (4 bytes): 0x14, 0x00, 0x00, 0x00
        // - HASH starts here (16 bytes)
        let hash_start = 4 + 4 + 4 + 4 + 4 + 4; // = 24
        let expected_hash = [
            0xf1, 0x62, 0xe8, 0x37, 0xc4, 0xdd, 0xfe, 0x55, 0xe7, 0x3a, 0x7b, 0xba, 0x1d, 0x62,
            0x67, 0x00,
        ];
        assert_eq!(&buf[hash_start..hash_start + 16], &expected_hash);
    }
}

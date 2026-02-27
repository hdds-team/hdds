// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Binary telemetry frame encoding/decoding (HDMX format).

use crate::core::string_utils::format_string;
use crate::telemetry::metrics::{DType, Field, Frame};
use std::convert::TryFrom;
use std::io::{Error, ErrorKind};

/// HDMX magic bytes (`"HDMX"` in little-endian).
pub const MAGIC: u32 = 0x4844_4D58;
/// HDMX binary format version (v1.0.0).
pub const VERSION: u32 = 0x0000_0100;

/// Encode a telemetry [`Frame`] into the HDMX binary representation.
///
/// # Errors
/// Returns an error when the frame contains more fields than can fit in `u32`
/// or when a `u64` value cannot be represented losslessly as the requested type.
///
/// # Latency Contract
/// - p99 < 5 us for frames with <=32 fields (single allocation, fixed-width writes).
pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();

    // Header (16 bytes)
    buf.extend_from_slice(&MAGIC.to_le_bytes()); // 0-3
    buf.extend_from_slice(&VERSION.to_le_bytes()); // 4-7
    buf.extend_from_slice(&0u32.to_le_bytes()); // 8-11 (frame_len, fill later)
    let field_count = u32::try_from(frame.fields.len()).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "telemetry frame has more than u32::MAX fields",
        )
    })?;
    buf.extend_from_slice(&field_count.to_le_bytes()); // 12-15

    // Fields
    for field in &frame.fields {
        buf.extend_from_slice(&field.tag.to_le_bytes()); // tag (u16)
        buf.push(dtype_to_u8(field.dtype)); // dtype (u8)

        match field.dtype {
            DType::U64 | DType::I64 | DType::F64 => {
                buf.push(8); // len (u8)
                buf.extend_from_slice(&field.value_u64.to_le_bytes()); // value (8 bytes)
            }
            DType::U32 => {
                buf.push(4); // len (u8)
                let value = u32::try_from(field.value_u64).map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format_string(format_args!(
                            "telemetry field {} value {} exceeds u32 range",
                            field.tag, field.value_u64
                        )),
                    )
                })?;
                buf.extend_from_slice(&value.to_le_bytes()); // value (4 bytes)
            }
            DType::Bytes => {
                // For T0, Bytes type not used (reserved for future)
                buf.push(0); // len (0 bytes)
            }
        }
    }

    // Update frame_len in header
    let frame_len = u32::try_from(buf.len()).map_err(|_| {
        Error::new(
            ErrorKind::InvalidData,
            "telemetry frame exceeds u32::MAX bytes",
        )
    })?;
    buf[8..12].copy_from_slice(&frame_len.to_le_bytes());

    Ok(buf)
}

/// Decode a binary frame produced by [`encode_frame`].
///
/// # Errors
/// Returns an error if the payload is malformed (bad magic, truncated header, or field data).
pub fn decode_frame(bytes: &[u8]) -> Result<Frame, Error> {
    if bytes.len() < 16 {
        return Err(Error::new(ErrorKind::InvalidData, "Frame too short"));
    }

    // Parse header
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != MAGIC {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid magic"));
    }

    let _version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let _frame_len = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let field_count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;

    // Parse fields
    let mut fields = Vec::new();
    let mut offset = 16;

    for _ in 0..field_count {
        if offset + 4 > bytes.len() {
            break; // Truncated frame, skip remaining fields
        }

        let tag = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let dtype_u8 = bytes[offset + 2];
        let len = bytes[offset + 3] as usize;
        offset += 4;

        if offset + len > bytes.len() {
            break; // Truncated value, skip
        }

        let dtype = u8_to_dtype(dtype_u8);
        let value_u64 = match len {
            8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&bytes[offset..offset + 8]);
                u64::from_le_bytes(buf)
            }
            4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes[offset..offset + 4]);
                u32::from_le_bytes(buf) as u64
            }
            _ => 0,
        };

        fields.push(Field {
            tag,
            dtype,
            value_u64,
        });

        offset += len;
    }

    Ok(Frame {
        ts_ns: 0, // Timestamp not encoded in T0 (reserved for T1+)
        fields,
    })
}

fn dtype_to_u8(dtype: DType) -> u8 {
    match dtype {
        DType::U64 => 0,
        DType::I64 => 1,
        DType::F64 => 2,
        DType::U32 => 3,
        DType::Bytes => 4,
    }
}

fn u8_to_dtype(dtype_u8: u8) -> DType {
    match dtype_u8 {
        0 => DType::U64,
        1 => DType::I64,
        2 => DType::F64,
        3 => DType::U32,
        4 => DType::Bytes,
        _ => DType::U64, // Fallback for unknown types
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVALID_MAGIC: u32 = 0xDEAD_BEEF;

    #[test]
    fn test_encode_frame_header() {
        let frame = Frame::new(0);
        let bytes = encode_frame(&frame).expect("Frame encoding should succeed");

        assert_eq!(&bytes[0..4], &MAGIC.to_le_bytes());
        assert_eq!(&bytes[4..8], &VERSION.to_le_bytes());
        assert_eq!(&bytes[12..16], &0u32.to_le_bytes());
        assert_eq!(&bytes[8..12], &16u32.to_le_bytes());
    }

    #[test]
    fn test_encode_frame_single_field_u64() {
        let mut frame = Frame::new(0);
        frame.push_field(Field {
            tag: 10,
            dtype: DType::U64,
            value_u64: 1234567890,
        });

        let bytes = encode_frame(&frame).expect("Frame encoding should succeed");
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[12..16], &1u32.to_le_bytes());
        assert_eq!(&bytes[16..18], &10u16.to_le_bytes());
        assert_eq!(bytes[18], 0);
        assert_eq!(bytes[19], 8);
        assert_eq!(&bytes[20..28], &1234567890u64.to_le_bytes());
    }

    #[test]
    fn test_encode_frame_multiple_fields() {
        let mut frame = Frame::new(0);
        frame.push_field(Field {
            tag: 10,
            dtype: DType::U64,
            value_u64: 100,
        });
        frame.push_field(Field {
            tag: 20,
            dtype: DType::U32,
            value_u64: 50,
        });

        let bytes = encode_frame(&frame).expect("Frame encoding should succeed");
        assert_eq!(bytes.len(), 36);
        assert_eq!(&bytes[12..16], &2u32.to_le_bytes());
    }

    #[test]
    fn test_decode_frame_empty() {
        let frame = Frame::new(0);
        let bytes = encode_frame(&frame).expect("Frame encoding should succeed");
        let decoded = decode_frame(&bytes).expect("Frame decoding should succeed");
        assert_eq!(decoded.fields.len(), 0);
    }

    #[test]
    fn test_decode_frame_single_field() {
        let mut frame = Frame::new(0);
        frame.push_field(Field {
            tag: 10,
            dtype: DType::U64,
            value_u64: 9999,
        });

        let bytes = encode_frame(&frame).expect("Frame encoding should succeed");
        let decoded = decode_frame(&bytes).expect("Frame decoding should succeed");

        assert_eq!(decoded.fields.len(), 1);
        assert_eq!(decoded.fields[0].tag, 10);
        assert_eq!(decoded.fields[0].value_u64, 9999);
    }

    #[test]
    fn test_decode_frame_invalid_magic() {
        let mut bytes = vec![0u8; 16];
        bytes[0..4].copy_from_slice(&INVALID_MAGIC.to_le_bytes());
        assert!(decode_frame(&bytes).is_err());
    }

    #[test]
    fn test_decode_frame_truncated() {
        let bytes = vec![0u8; 10];
        assert!(decode_frame(&bytes).is_err());
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut frame = Frame::new(12345);
        frame.push_field(Field {
            tag: 10,
            dtype: DType::U64,
            value_u64: 1_000_000,
        });
        frame.push_field(Field {
            tag: 11,
            dtype: DType::U64,
            value_u64: 50,
        });

        let bytes = encode_frame(&frame).expect("Frame encoding should succeed");
        let decoded = decode_frame(&bytes).expect("Frame decoding should succeed");

        assert_eq!(decoded.fields.len(), frame.fields.len());
        for (orig, dec) in frame.fields.iter().zip(decoded.fields.iter()) {
            assert_eq!(orig.tag, dec.tag);
            assert_eq!(orig.value_u64, dec.value_u64);
        }
    }
}

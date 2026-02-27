// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Read/write cursors for CDR2 buffer manipulation.
//!

use super::{SerError, SerResult};

/// Generate write methods for primitive types (eliminates code duplication)
///
/// Each generated method:
/// 1. Checks buffer bounds (returns `SerError::WriteFailed` if overflow)
/// 2. Converts value to little-endian bytes via `to_le_bytes()`
/// 3. Copies bytes to buffer
/// 4. Advances offset
macro_rules! impl_write_le {
    ($name:ident, $type:ty, $size:expr) => {
        pub fn $name(&mut self, value: $type) -> SerResult<()> {
            if self.offset + $size > self.buffer.len() {
                return Err(SerError::WriteFailed {
                    offset: self.offset,
                    reason: "buffer too small".into(),
                });
            }
            let bytes = value.to_le_bytes();
            self.buffer[self.offset..self.offset + $size].copy_from_slice(&bytes);
            self.offset += $size;
            Ok(())
        }
    };
}

/// Generate read methods for primitive types (eliminates code duplication)
///
/// Each generated method:
/// 1. Checks buffer bounds (returns `SerError::ReadFailed` if overflow)
/// 2. Reads N bytes from buffer
/// 3. Converts bytes to value via `from_le_bytes()`
/// 4. Advances offset
macro_rules! impl_read_le {
    ($name:ident, $type:ty, $size:expr) => {
        pub fn $name(&mut self) -> SerResult<$type> {
            if self.offset + $size > self.buffer.len() {
                return Err(SerError::ReadFailed {
                    offset: self.offset,
                    reason: "unexpected end of buffer".into(),
                });
            }
            let mut bytes = [0u8; $size];
            bytes.copy_from_slice(&self.buffer[self.offset..self.offset + $size]);
            self.offset += $size;
            Ok(<$type>::from_le_bytes(bytes))
        }
    };
}

/// Generate common cursor methods (offset, remaining, align)
///
/// Eliminates duplication between CursorMut and Cursor by generating identical methods
/// with cursor-specific error types and messages.
macro_rules! impl_cursor_common {
    ($error_variant:ident, $align_err_msg:expr) => {
        pub fn offset(&self) -> usize {
            self.offset
        }

        pub fn remaining(&self) -> usize {
            self.buffer.len().saturating_sub(self.offset)
        }

        pub fn align(&mut self, alignment: u8) -> SerResult<()> {
            if alignment <= 1 {
                return Ok(());
            }
            let mask = (alignment as usize) - 1;
            self.offset = (self.offset + mask) & !mask;
            if self.offset > self.buffer.len() {
                return Err(SerError::$error_variant {
                    offset: self.offset,
                    reason: $align_err_msg.into(),
                });
            }
            Ok(())
        }
    };
}

/// Mutable cursor for writing (bounds-checked, zero-copy)
pub struct CursorMut<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> CursorMut<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    // Generate write methods via macro (DRY principle)
    impl_write_le!(write_u8, u8, 1);
    impl_write_le!(write_u16_le, u16, 2);
    impl_write_le!(write_u32_le, u32, 4);
    impl_write_le!(write_u64_le, u64, 8);

    pub fn write_i32_le(&mut self, value: i32) -> SerResult<()> {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_f64_le(&mut self, value: f64) -> SerResult<()> {
        self.write_u64_le(value.to_bits())
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> SerResult<()> {
        if self.offset + data.len() > self.buffer.len() {
            return Err(SerError::WriteFailed {
                offset: self.offset,
                reason: "buffer too small".into(),
            });
        }
        self.buffer[self.offset..self.offset + data.len()].copy_from_slice(data);
        self.offset += data.len();
        Ok(())
    }

    // Generate common cursor methods (offset, remaining, align) via macro
    impl_cursor_common!(WriteFailed, "buffer too small");
}

/// Immutable cursor for reading (bounds-checked, zero-copy)
pub struct Cursor<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    // Generate read methods via macro (DRY principle)
    impl_read_le!(read_u8, u8, 1);
    impl_read_le!(read_u16_le, u16, 2);
    impl_read_le!(read_u32_le, u32, 4);
    impl_read_le!(read_u64_le, u64, 8);

    pub fn read_i32_le(&mut self) -> SerResult<i32> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(self.read_bytes(4)?);
        Ok(i32::from_le_bytes(buf))
    }

    pub fn read_f64_le(&mut self) -> SerResult<f64> {
        Ok(f64::from_bits(self.read_u64_le()?))
    }

    pub fn read_bytes(&mut self, len: usize) -> SerResult<&'a [u8]> {
        if self.offset + len > self.buffer.len() {
            return Err(SerError::ReadFailed {
                offset: self.offset,
                reason: "unexpected end of buffer".into(),
            });
        }
        let slice = &self.buffer[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    // Generate common cursor methods (offset, remaining, align) via macro
    impl_cursor_common!(ReadFailed, "unexpected end of buffer");

    pub fn is_eof(&self) -> bool {
        self.offset >= self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PI64: f64 = std::f64::consts::PI;

    /// Test values for serialization verification
    const TEST_U8: u8 = 0xAB;
    const TEST_U16: u16 = 0xCDEF;
    const TEST_U16_ALT: u16 = 0xABCD;
    const TEST_U16_ALT2: u16 = 0x2233;
    const TEST_U16_ALT3: u16 = 0x0102;
    const TEST_U32: u32 = 0x1234_5678;
    const TEST_U32_ALT: u32 = 0x4455_6677;
    const TEST_U32_ALT2: u32 = 0x0A0B_0C0D;
    const TEST_U64: u64 = 0x1122_3344_5566_7788;
    const TEST_U64_ALT: u64 = 0x0102_0304_0506_0708;

    #[test]
    fn test_cursor_mut_write_overflow_reports_offset() {
        let mut buffer = [0u8; 2];
        let mut cursor = CursorMut::new(&mut buffer);
        cursor
            .write_u16_le(TEST_U16_ALT)
            .expect("Write u16 should succeed");

        let err = cursor.write_u8(0xFF).unwrap_err();
        match err {
            SerError::WriteFailed { offset, reason } => {
                assert_eq!(offset, 2);
                assert_eq!(reason, "buffer too small");
            }
            other => std::panic::panic_any(crate::core::string_utils::format_string(format_args!(
                "unexpected error {:?}",
                other
            ))),
        }
    }

    #[test]
    fn test_cursor_read_overflow_reports_offset() {
        let buffer = [0u8; 1];
        let mut cursor = Cursor::new(&buffer);
        assert_eq!(cursor.read_u8().expect("Read u8 should succeed"), 0);

        let err = cursor.read_u8().unwrap_err();
        match err {
            SerError::ReadFailed { offset, reason } => {
                assert_eq!(offset, 1);
                assert_eq!(reason, "unexpected end of buffer");
            }
            other => std::panic::panic_any(crate::core::string_utils::format_string(format_args!(
                "unexpected error {:?}",
                other
            ))),
        }
    }

    #[test]
    fn test_cursor_mut_align_overflow() {
        let mut buffer = [0u8; 2];
        let mut cursor = CursorMut::new(&mut buffer);
        cursor.write_u16_le(1).expect("Write u16 should succeed");
        let err = cursor.align(8).unwrap_err();
        match err {
            SerError::WriteFailed { offset, reason } => {
                assert_eq!(offset, 8);
                assert_eq!(reason, "buffer too small");
            }
            other => std::panic::panic_any(crate::core::string_utils::format_string(format_args!(
                "unexpected error {:?}",
                other
            ))),
        }
    }

    #[test]
    fn test_cursor_align_overflow() {
        let buffer = [0u8; 2];
        let mut cursor = Cursor::new(&buffer);
        cursor.read_u16_le().expect("Read u16 should succeed");
        let err = cursor.align(8).unwrap_err();
        match err {
            SerError::ReadFailed { offset, reason } => {
                assert_eq!(offset, 8);
                assert_eq!(reason, "unexpected end of buffer");
            }
            other => std::panic::panic_any(crate::core::string_utils::format_string(format_args!(
                "unexpected error {:?}",
                other
            ))),
        }
    }

    #[test]
    fn test_cursor_roundtrip_across_numeric_types() {
        let mut buffer = [0u8; 64];
        let mut writer = CursorMut::new(&mut buffer);
        writer.write_u8(TEST_U8).expect("Write u8 should succeed");
        writer
            .write_u16_le(TEST_U16)
            .expect("Write u16 should succeed");
        writer
            .write_u32_le(TEST_U32)
            .expect("Write u32 should succeed");
        writer
            .write_u64_le(TEST_U64)
            .expect("Write u64 should succeed");
        writer.write_i32_le(-42).expect("Write i32 should succeed");
        writer.write_f64_le(6.25).expect("Write f64 should succeed");
        writer.align(8).expect("Align should succeed");
        writer
            .write_bytes(&[1, 2, 3, 4])
            .expect("Write bytes should succeed");
        let written = writer.offset();
        assert!(written > 0);
        assert!(writer.remaining() < buffer.len());

        let mut reader = Cursor::new(&buffer);
        assert_eq!(reader.read_u8().expect("Read u8 should succeed"), TEST_U8);
        assert_eq!(
            reader.read_u16_le().expect("Read u16 should succeed"),
            TEST_U16
        );
        assert_eq!(
            reader.read_u32_le().expect("Read u32 should succeed"),
            TEST_U32
        );
        assert_eq!(
            reader.read_u64_le().expect("Read u64 should succeed"),
            TEST_U64
        );
        assert_eq!(reader.read_i32_le().expect("Read i32 should succeed"), -42);
        assert!(
            (reader.read_f64_le().expect("Read f64 should succeed") - 6.25).abs() < f64::EPSILON
        );
        reader.align(8).expect("Align should succeed");
        assert_eq!(
            reader.read_bytes(4).expect("Read bytes should succeed"),
            &[1, 2, 3, 4]
        );
        assert_eq!(reader.remaining(), buffer.len() - written);
    }

    #[test]
    fn test_cursor_mut_write_primitives_content() {
        let mut buffer = [0u8; 24];
        let mut cursor = CursorMut::new(&mut buffer);
        cursor.write_u8(0x11).expect("Write u8 should succeed");
        cursor
            .write_u16_le(TEST_U16_ALT2)
            .expect("Write u16 should succeed");
        cursor.align(4).expect("Align should succeed");
        cursor
            .write_u32_le(TEST_U32_ALT)
            .expect("Write u32 should succeed");
        cursor.write_i32_le(-123).expect("Write i32 should succeed");
        cursor.write_f64_le(PI64).expect("Write f64 should succeed");
        cursor
            .write_bytes(&[0xAA, 0xBB])
            .expect("Write bytes should succeed");

        let offset = cursor.offset();
        assert_eq!(offset, 22);
        assert_eq!(cursor.remaining(), buffer.len() - offset);
        // Ensure the alignment slot was zeroed and first few values match expectations.
        assert_eq!(buffer[0], 0x11);
        assert_eq!(&buffer[1..3], &TEST_U16_ALT2.to_le_bytes());
        assert_eq!(buffer[3], 0);
    }

    #[test]
    fn test_cursor_read_primitives_content() {
        let mut buffer = [0u8; 32];
        {
            let mut writer = CursorMut::new(&mut buffer);
            writer
                .write_u16_le(TEST_U16_ALT3)
                .expect("Write u16 should succeed");
            writer
                .write_u32_le(TEST_U32_ALT2)
                .expect("Write u32 should succeed");
            writer
                .write_u64_le(TEST_U64_ALT)
                .expect("Write u64 should succeed");
            writer.align(4).expect("Align should succeed");
            writer
                .write_bytes(&[0xDE, 0xAD, 0xBE, 0xEF])
                .expect("Write bytes should succeed");
        }

        let mut reader = Cursor::new(&buffer);
        assert_eq!(
            reader.read_u16_le().expect("Read u16 should succeed"),
            TEST_U16_ALT3
        );
        assert_eq!(
            reader.read_u32_le().expect("Read u32 should succeed"),
            TEST_U32_ALT2
        );
        assert_eq!(
            reader.read_u64_le().expect("Read u64 should succeed"),
            TEST_U64_ALT
        );
        reader.align(4).expect("Align should succeed");
        assert_eq!(
            reader.read_bytes(4).expect("Read bytes should succeed"),
            &[0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_cursor_align_noop_for_alignment_one() {
        let mut buffer = [0u8; 8];
        let mut write_cursor = CursorMut::new(&mut buffer);
        write_cursor.write_u8(42).expect("Write u8 should succeed");
        write_cursor.align(1).expect("Align should succeed");
        assert_eq!(write_cursor.offset(), 1);

        let mut read_cursor = Cursor::new(&buffer);
        read_cursor.read_u8().expect("Read u8 should succeed");
        read_cursor.align(1).expect("Align should succeed");
        assert_eq!(read_cursor.offset(), 1);
    }
}

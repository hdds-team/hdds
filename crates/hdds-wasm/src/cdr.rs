// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

// HDDS WASM SDK - CDR2 encode/decode (no-std compatible subset)

use crate::error::WasmError;

/// Minimal CDR2 encoder for WASM.
///
/// Encodes primitive types in little-endian byte order with CDR alignment rules.
pub struct CdrEncoder {
    buf: Vec<u8>,
    pos: usize,
}

impl CdrEncoder {
    /// Create a new encoder.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
        }
    }

    /// Create a new encoder with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
            pos: 0,
        }
    }

    /// Align the write position to the given alignment boundary.
    /// CDR requires alignment to natural boundaries (2 for u16, 4 for u32, 8 for u64).
    pub fn align(&mut self, alignment: usize) {
        if alignment <= 1 {
            return;
        }
        let remainder = self.pos % alignment;
        if remainder != 0 {
            let padding = alignment - remainder;
            for _ in 0..padding {
                self.buf.push(0);
                self.pos += 1;
            }
        }
    }

    /// Encode a bool (1 byte: 0 or 1).
    pub fn encode_bool(&mut self, v: bool) {
        self.buf.push(if v { 1 } else { 0 });
        self.pos += 1;
    }

    /// Encode a u8 (1 byte).
    pub fn encode_u8(&mut self, v: u8) {
        self.buf.push(v);
        self.pos += 1;
    }

    /// Encode an i8 (1 byte).
    pub fn encode_i8(&mut self, v: i8) {
        self.buf.push(v as u8);
        self.pos += 1;
    }

    /// Encode a u16 (2 bytes, LE, aligned to 2).
    pub fn encode_u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 2;
    }

    /// Encode an i16 (2 bytes, LE, aligned to 2).
    pub fn encode_i16(&mut self, v: i16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 2;
    }

    /// Encode a u32 (4 bytes, LE, aligned to 4).
    pub fn encode_u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 4;
    }

    /// Encode an i32 (4 bytes, LE, aligned to 4).
    pub fn encode_i32(&mut self, v: i32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 4;
    }

    /// Encode a u64 (8 bytes, LE, aligned to 8).
    pub fn encode_u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 8;
    }

    /// Encode an i64 (8 bytes, LE, aligned to 8).
    pub fn encode_i64(&mut self, v: i64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 8;
    }

    /// Encode an f32 (4 bytes, LE, aligned to 4).
    pub fn encode_f32(&mut self, v: f32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 4;
    }

    /// Encode an f64 (8 bytes, LE, aligned to 8).
    pub fn encode_f64(&mut self, v: f64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self.pos += 8;
    }

    /// Encode a string (CDR format: u32 length including NUL, then bytes + NUL).
    pub fn encode_string(&mut self, v: &str) {
        let len = v.len() as u32 + 1; // +1 for NUL terminator
        self.encode_u32(len);
        self.buf.extend_from_slice(v.as_bytes());
        self.buf.push(0); // NUL terminator
        self.pos += v.len() + 1;
    }

    /// Encode a byte sequence (u32 length prefix, then bytes).
    pub fn encode_bytes(&mut self, v: &[u8]) {
        let len = v.len() as u32;
        self.encode_u32(len);
        self.buf.extend_from_slice(v);
        self.pos += v.len();
    }

    /// Returns the current write position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Finish encoding and return the buffer.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for CdrEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal CDR2 decoder for WASM.
///
/// Decodes primitive types in little-endian byte order with CDR alignment rules.
pub struct CdrDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CdrDecoder<'a> {
    /// Create a new decoder over the given buffer.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Align the read position to the given alignment boundary.
    pub fn align(&mut self, alignment: usize) -> Result<(), WasmError> {
        if alignment <= 1 {
            return Ok(());
        }
        let remainder = self.pos % alignment;
        if remainder != 0 {
            let padding = alignment - remainder;
            if self.pos + padding > self.buf.len() {
                return Err(WasmError::BufferUnderflow);
            }
            self.pos += padding;
        }
        Ok(())
    }

    /// Check that at least `n` bytes remain.
    fn check_remaining(&self, n: usize) -> Result<(), WasmError> {
        if self.pos + n > self.buf.len() {
            Err(WasmError::BufferUnderflow)
        } else {
            Ok(())
        }
    }

    /// Decode a bool (1 byte).
    pub fn decode_bool(&mut self) -> Result<bool, WasmError> {
        self.check_remaining(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v != 0)
    }

    /// Decode a u8 (1 byte).
    pub fn decode_u8(&mut self) -> Result<u8, WasmError> {
        self.check_remaining(1)?;
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    /// Decode an i8 (1 byte).
    pub fn decode_i8(&mut self) -> Result<i8, WasmError> {
        self.check_remaining(1)?;
        let v = self.buf[self.pos] as i8;
        self.pos += 1;
        Ok(v)
    }

    /// Decode a u16 (2 bytes, LE, aligned to 2).
    pub fn decode_u16(&mut self) -> Result<u16, WasmError> {
        self.align(2)?;
        self.check_remaining(2)?;
        let v = u16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Decode an i16 (2 bytes, LE, aligned to 2).
    pub fn decode_i16(&mut self) -> Result<i16, WasmError> {
        self.align(2)?;
        self.check_remaining(2)?;
        let v = i16::from_le_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    /// Decode a u32 (4 bytes, LE, aligned to 4).
    pub fn decode_u32(&mut self) -> Result<u32, WasmError> {
        self.align(4)?;
        self.check_remaining(4)?;
        let v = u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Decode an i32 (4 bytes, LE, aligned to 4).
    pub fn decode_i32(&mut self) -> Result<i32, WasmError> {
        self.align(4)?;
        self.check_remaining(4)?;
        let v = i32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Decode a u64 (8 bytes, LE, aligned to 8).
    pub fn decode_u64(&mut self) -> Result<u64, WasmError> {
        self.align(8)?;
        self.check_remaining(8)?;
        let v = u64::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
            self.buf[self.pos + 4],
            self.buf[self.pos + 5],
            self.buf[self.pos + 6],
            self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    /// Decode an i64 (8 bytes, LE, aligned to 8).
    pub fn decode_i64(&mut self) -> Result<i64, WasmError> {
        self.align(8)?;
        self.check_remaining(8)?;
        let v = i64::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
            self.buf[self.pos + 4],
            self.buf[self.pos + 5],
            self.buf[self.pos + 6],
            self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    /// Decode an f32 (4 bytes, LE, aligned to 4).
    pub fn decode_f32(&mut self) -> Result<f32, WasmError> {
        self.align(4)?;
        self.check_remaining(4)?;
        let v = f32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    /// Decode an f64 (8 bytes, LE, aligned to 8).
    pub fn decode_f64(&mut self) -> Result<f64, WasmError> {
        self.align(8)?;
        self.check_remaining(8)?;
        let v = f64::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
            self.buf[self.pos + 4],
            self.buf[self.pos + 5],
            self.buf[self.pos + 6],
            self.buf[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    /// Decode a CDR string (u32 length including NUL, then bytes + NUL).
    pub fn decode_string(&mut self) -> Result<String, WasmError> {
        let len = self.decode_u32()? as usize;
        if len == 0 {
            return Ok(String::new());
        }
        self.check_remaining(len)?;
        // len includes NUL terminator
        let str_len = len - 1;
        let s = String::from_utf8_lossy(&self.buf[self.pos..self.pos + str_len]).to_string();
        self.pos += len; // skip past NUL
        Ok(s)
    }

    /// Decode a byte sequence (u32 length prefix, then bytes).
    pub fn decode_bytes(&mut self) -> Result<Vec<u8>, WasmError> {
        let len = self.decode_u32()? as usize;
        self.check_remaining(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    /// Returns the current read position.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Returns remaining bytes count.
    pub fn remaining(&self) -> usize {
        if self.pos >= self.buf.len() {
            0
        } else {
            self.buf.len() - self.pos
        }
    }
}

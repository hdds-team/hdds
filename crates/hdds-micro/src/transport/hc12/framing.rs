// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Packet framing for HC-12 UART transport
//!
//! Since HC-12 is a raw UART bridge, we need framing to detect packet boundaries.
//!
//! ## Frame Format
//!
//! ```text
//! +------+------+------+--------+---------+------+
//! | SYNC | LEN  | SRC  | DATA   |   CRC   | SYNC |
//! +------+------+------+--------+---------+------+
//!   0xAA   1B     1B    0-50B     2B       0x55
//! ```
//!
//! - SYNC_START (0xAA): Frame start marker
//! - LEN: Payload length (0-50)
//! - SRC: Source node ID
//! - DATA: Payload bytes
//! - CRC16: CRC-16-CCITT checksum
//! - SYNC_END (0x55): Frame end marker

use crate::error::{Error, Result};

/// Frame start marker
const SYNC_START: u8 = 0xAA;

/// Frame end marker
const SYNC_END: u8 = 0x55;

/// Maximum payload size per frame
const MAX_PAYLOAD: usize = 50;

/// Frame overhead: start(1) + len(1) + src(1) + crc(2) + end(1) = 6
pub const FRAME_OVERHEAD: usize = 6;

/// Maximum frame size
const MAX_FRAME_SIZE: usize = MAX_PAYLOAD + FRAME_OVERHEAD;

/// Frame encoder for outgoing packets
#[derive(Debug)]
pub struct FrameEncoder {
    // Stateless encoder
}

impl FrameEncoder {
    /// Create a new frame encoder
    pub const fn new() -> Self {
        Self {}
    }

    /// Encode data into a frame
    ///
    /// # Arguments
    ///
    /// * `src_node` - Source node ID
    /// * `data` - Payload data
    /// * `buf` - Output buffer for frame
    ///
    /// # Returns
    ///
    /// Frame length
    pub fn encode(&self, src_node: u8, data: &[u8], buf: &mut [u8]) -> Result<usize> {
        if data.len() > MAX_PAYLOAD {
            return Err(Error::BufferTooSmall);
        }

        let frame_len = data.len() + FRAME_OVERHEAD;
        if buf.len() < frame_len {
            return Err(Error::BufferTooSmall);
        }

        // Build frame
        buf[0] = SYNC_START;
        buf[1] = data.len() as u8;
        buf[2] = src_node;

        // Copy payload
        buf[3..3 + data.len()].copy_from_slice(data);

        // Calculate CRC over len + src + data
        let crc = crc16_ccitt(&buf[1..3 + data.len()]);
        buf[3 + data.len()] = (crc >> 8) as u8;
        buf[4 + data.len()] = (crc & 0xFF) as u8;

        // End marker
        buf[5 + data.len()] = SYNC_END;

        Ok(frame_len)
    }
}

impl Default for FrameEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoder state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecoderState {
    /// Waiting for start sync
    WaitStart,
    /// Got start, waiting for length
    WaitLength,
    /// Got length, waiting for source
    WaitSource,
    /// Receiving payload
    Payload,
    /// Waiting for CRC high byte
    CrcHigh,
    /// Waiting for CRC low byte
    CrcLow,
    /// Waiting for end sync
    WaitEnd,
}

/// Frame decoder for incoming packets
#[derive(Debug)]
pub struct FrameDecoder {
    /// Current state
    state: DecoderState,

    /// Payload buffer
    buf: [u8; MAX_FRAME_SIZE],

    /// Expected payload length
    payload_len: usize,

    /// Source node ID
    src_node: u8,

    /// Current position in buffer
    pos: usize,

    /// Received CRC
    crc: u16,
}

impl FrameDecoder {
    /// Create a new frame decoder
    pub const fn new() -> Self {
        Self {
            state: DecoderState::WaitStart,
            buf: [0u8; MAX_FRAME_SIZE],
            payload_len: 0,
            src_node: 0,
            pos: 0,
            crc: 0,
        }
    }

    /// Reset decoder state
    pub fn reset(&mut self) {
        self.state = DecoderState::WaitStart;
        self.pos = 0;
        self.payload_len = 0;
        self.src_node = 0;
        self.crc = 0;
    }

    /// Feed a byte to the decoder
    ///
    /// # Returns
    ///
    /// `Some((src_node, payload))` when a complete frame is decoded
    pub fn feed(&mut self, byte: u8) -> Result<Option<(u8, &[u8])>> {
        match self.state {
            DecoderState::WaitStart => {
                if byte == SYNC_START {
                    self.state = DecoderState::WaitLength;
                    self.pos = 0;
                }
                Ok(None)
            }

            DecoderState::WaitLength => {
                if byte > MAX_PAYLOAD as u8 {
                    // Invalid length, reset
                    self.reset();
                    return Ok(None);
                }
                self.payload_len = byte as usize;
                self.buf[0] = byte; // Store for CRC
                self.state = DecoderState::WaitSource;
                Ok(None)
            }

            DecoderState::WaitSource => {
                self.src_node = byte;
                self.buf[1] = byte; // Store for CRC
                self.pos = 0;
                if self.payload_len == 0 {
                    self.state = DecoderState::CrcHigh;
                } else {
                    self.state = DecoderState::Payload;
                }
                Ok(None)
            }

            DecoderState::Payload => {
                self.buf[2 + self.pos] = byte;
                self.pos += 1;

                if self.pos >= self.payload_len {
                    self.state = DecoderState::CrcHigh;
                }
                Ok(None)
            }

            DecoderState::CrcHigh => {
                self.crc = (byte as u16) << 8;
                self.state = DecoderState::CrcLow;
                Ok(None)
            }

            DecoderState::CrcLow => {
                self.crc |= byte as u16;
                self.state = DecoderState::WaitEnd;
                Ok(None)
            }

            DecoderState::WaitEnd => {
                if byte == SYNC_END {
                    // Verify CRC
                    let expected_crc = crc16_ccitt(&self.buf[..2 + self.payload_len]);

                    if self.crc == expected_crc {
                        // Valid frame! Reset state but keep data for return
                        self.state = DecoderState::WaitStart;
                        let payload_end = 2 + self.payload_len;
                        self.payload_len = 0; // Reset for next frame
                        self.crc = 0;
                        self.pos = 0;
                        return Ok(Some((self.src_node, &self.buf[2..payload_end])));
                    }
                }

                // Invalid frame, reset
                self.reset();
                Ok(None)
            }
        }
    }

    /// Check if decoder is in middle of receiving a frame
    pub const fn is_receiving(&self) -> bool {
        !matches!(self.state, DecoderState::WaitStart)
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// CRC-16-CCITT calculation (polynomial 0x1021)
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;

    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_basic() {
        let encoder = FrameEncoder::new();
        let mut buf = [0u8; 64];

        let len = encoder.encode(42, b"Hello", &mut buf).unwrap();

        assert_eq!(len, 5 + FRAME_OVERHEAD); // 5 bytes payload + 6 overhead
        assert_eq!(buf[0], SYNC_START);
        assert_eq!(buf[1], 5); // length
        assert_eq!(buf[2], 42); // src_node
        assert_eq!(&buf[3..8], b"Hello");
        assert_eq!(buf[len - 1], SYNC_END);
    }

    #[test]
    fn test_encoder_empty_payload() {
        let encoder = FrameEncoder::new();
        let mut buf = [0u8; 64];

        let len = encoder.encode(1, &[], &mut buf).unwrap();

        assert_eq!(len, FRAME_OVERHEAD);
        assert_eq!(buf[0], SYNC_START);
        assert_eq!(buf[1], 0); // length
        assert_eq!(buf[len - 1], SYNC_END);
    }

    #[test]
    fn test_encoder_buffer_too_small() {
        let encoder = FrameEncoder::new();
        let mut buf = [0u8; 5]; // Too small

        let result = encoder.encode(1, b"Hello", &mut buf);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }

    #[test]
    fn test_encoder_payload_too_large() {
        let encoder = FrameEncoder::new();
        let mut buf = [0u8; 256];
        let data = [0u8; 60]; // Too large

        let result = encoder.encode(1, &data, &mut buf);
        assert_eq!(result, Err(Error::BufferTooSmall));
    }

    #[test]
    fn test_decoder_basic() {
        let encoder = FrameEncoder::new();
        let mut decoder = FrameDecoder::new();
        let mut buf = [0u8; 64];

        // Encode a frame
        let len = encoder.encode(42, b"Test", &mut buf).unwrap();

        // Feed to decoder (all but last byte)
        for &byte in &buf[..len - 1] {
            let result = decoder.feed(byte).unwrap();
            assert!(result.is_none());
        }

        // Last byte should complete the frame
        let result = decoder.feed(buf[len - 1]).unwrap();
        assert!(result.is_some());

        let (src, payload) = result.unwrap();
        assert_eq!(src, 42);
        assert_eq!(payload, b"Test");
    }

    #[test]
    fn test_decoder_empty_payload() {
        let encoder = FrameEncoder::new();
        let mut decoder = FrameDecoder::new();
        let mut buf = [0u8; 64];

        let len = encoder.encode(1, &[], &mut buf).unwrap();

        for &byte in &buf[..len - 1] {
            assert!(decoder.feed(byte).unwrap().is_none());
        }

        let result = decoder.feed(buf[len - 1]).unwrap();
        assert!(result.is_some());

        let (src, payload) = result.unwrap();
        assert_eq!(src, 1);
        assert!(payload.is_empty());
    }

    #[test]
    fn test_decoder_bad_crc() {
        let encoder = FrameEncoder::new();
        let mut decoder = FrameDecoder::new();
        let mut buf = [0u8; 64];

        let len = encoder.encode(42, b"Test", &mut buf).unwrap();

        // Corrupt a byte
        buf[5] ^= 0xFF;

        // Feed to decoder
        for &byte in &buf[..len] {
            let _ = decoder.feed(byte);
        }

        // Should have reset (no valid frame)
        assert!(!decoder.is_receiving());
    }

    #[test]
    fn test_decoder_bad_sync() {
        let mut decoder = FrameDecoder::new();

        // Random bytes without sync
        for b in &[0x12, 0x34, 0x56, 0x78] {
            let result = decoder.feed(*b).unwrap();
            assert!(result.is_none());
        }

        assert!(!decoder.is_receiving());
    }

    #[test]
    fn test_decoder_multiple_frames() {
        let encoder = FrameEncoder::new();
        let mut decoder = FrameDecoder::new();
        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];

        let len1 = encoder.encode(1, b"First", &mut buf1).unwrap();
        let len2 = encoder.encode(2, b"Second", &mut buf2).unwrap();

        // Decode first frame
        for &byte in &buf1[..len1 - 1] {
            assert!(decoder.feed(byte).unwrap().is_none());
        }
        let result = decoder.feed(buf1[len1 - 1]).unwrap();
        let (src, payload) = result.unwrap();
        assert_eq!(src, 1);
        assert_eq!(payload, b"First");

        // Decode second frame
        for &byte in &buf2[..len2 - 1] {
            assert!(decoder.feed(byte).unwrap().is_none());
        }
        let result = decoder.feed(buf2[len2 - 1]).unwrap();
        let (src, payload) = result.unwrap();
        assert_eq!(src, 2);
        assert_eq!(payload, b"Second");
    }

    #[test]
    fn test_crc16_known_values() {
        // Test with known CRC values
        assert_eq!(crc16_ccitt(b""), 0xFFFF);
        assert_eq!(crc16_ccitt(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_roundtrip_various_sizes() {
        let encoder = FrameEncoder::new();
        let mut decoder = FrameDecoder::new();
        let mut frame_buf = [0u8; 64];
        let mut data_buf = [0u8; 50];

        for size in [0usize, 1, 10, 25, 50] {
            // Fill data buffer with sequential values
            for (i, slot) in data_buf[..size].iter_mut().enumerate() {
                *slot = i as u8;
            }
            let data = &data_buf[..size];

            let len = encoder.encode(42, data, &mut frame_buf).unwrap();

            for &byte in &frame_buf[..len - 1] {
                assert!(decoder.feed(byte).unwrap().is_none());
            }

            let result = decoder.feed(frame_buf[len - 1]).unwrap();
            assert!(result.is_some());

            let (src, payload) = result.unwrap();
            assert_eq!(src, 42);
            assert_eq!(payload, data);
        }
    }
}

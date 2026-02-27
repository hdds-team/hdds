// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Length-prefix framing codec for RTPS over TCP.
//!
//! TCP is a stream protocol without message boundaries. This codec adds
//! length-prefix framing to delimit RTPS messages:
//!
//! ```text
//! +----------------+-------------------+
//! | Length (4B BE) | RTPS Message      |
//! +----------------+-------------------+
//! ```
//!
//! The length field is a 32-bit big-endian integer specifying the size
//! of the RTPS message payload (not including the 4-byte header).
//!
//! # Wire Format
//!
//! - **Length**: `u32` big-endian (network byte order)
//! - **Payload**: Raw RTPS message bytes
//!
//! # Example
//!
//! ```
//! use hdds::transport::tcp::FrameCodec;
//!
//! let mut codec = FrameCodec::new(16 * 1024 * 1024);
//!
//! // Encode a message
//! let msg = b"RTPS\x02\x03\x00\x00...";
//! let frame = FrameCodec::encode(msg);
//! assert_eq!(&frame[..4], &(msg.len() as u32).to_be_bytes());
//!
//! // Decode requires a ByteStream (see tests)
//! ```

use std::io::{self, Read};

/// Frame header size (4 bytes for length).
pub const FRAME_HEADER_SIZE: usize = 4;

/// Default maximum message size (16 MB).
pub const DEFAULT_MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Minimum valid RTPS message size (header only).
pub const MIN_RTPS_MESSAGE_SIZE: usize = 20; // RTPS header

/// Length-prefix frame codec for TCP transport.
///
/// Handles framing/deframing of RTPS messages over TCP streams.
/// The codec maintains partial read state to handle TCP's streaming nature.
#[derive(Debug)]
pub struct FrameCodec {
    /// Current read state
    state: ReadState,

    /// Buffer for accumulating bytes
    buffer: Vec<u8>,

    /// Maximum allowed message size (anti-OOM protection)
    max_size: usize,

    /// Statistics: frames decoded
    frames_decoded: u64,

    /// Statistics: bytes decoded
    bytes_decoded: u64,

    /// Statistics: frames too large (rejected)
    frames_rejected: u64,

    /// v233: Accumulation buffer for TLS plaintext data
    /// When using TLS, we read plaintext chunks and accumulate them here
    accumulator: Vec<u8>,

    /// v233: Read position in accumulator
    accumulator_pos: usize,
}

/// Internal state for incremental reading.
#[derive(Debug, Clone, Copy)]
enum ReadState {
    /// Reading the 4-byte length header
    ReadingLength { bytes_read: usize },

    /// Reading the message body
    ReadingBody {
        expected_len: usize,
        bytes_read: usize,
    },
}

impl Default for ReadState {
    fn default() -> Self {
        ReadState::ReadingLength { bytes_read: 0 }
    }
}

impl FrameCodec {
    /// Create a new frame codec with the specified max message size.
    pub fn new(max_size: usize) -> Self {
        Self {
            state: ReadState::default(),
            buffer: vec![0u8; FRAME_HEADER_SIZE], // Start with header buffer
            max_size,
            frames_decoded: 0,
            bytes_decoded: 0,
            frames_rejected: 0,
            accumulator: Vec::with_capacity(16384),
            accumulator_pos: 0,
        }
    }

    /// Create a codec with default max size (16 MB).
    pub fn with_default_max() -> Self {
        Self::new(DEFAULT_MAX_MESSAGE_SIZE)
    }

    /// Get maximum allowed message size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Get number of frames successfully decoded.
    pub fn frames_decoded(&self) -> u64 {
        self.frames_decoded
    }

    /// Get total bytes decoded.
    pub fn bytes_decoded(&self) -> u64 {
        self.bytes_decoded
    }

    /// Get number of frames rejected (too large).
    pub fn frames_rejected(&self) -> u64 {
        self.frames_rejected
    }

    /// Reset the codec state (e.g., after connection reset).
    pub fn reset(&mut self) {
        self.state = ReadState::default();
        self.buffer.resize(FRAME_HEADER_SIZE, 0);
    }

    /// Encode a message into a framed buffer.
    ///
    /// Returns a new Vec containing: `[length: u32 BE][payload]`
    pub fn encode(payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    /// Encode a message into an existing buffer.
    ///
    /// Appends: `[length: u32 BE][payload]` to the buffer.
    pub fn encode_into(payload: &[u8], buf: &mut Vec<u8>) {
        let len = payload.len() as u32;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(payload);
    }

    /// Encode multiple messages into a single buffer.
    ///
    /// More efficient than encoding separately when sending batches.
    pub fn encode_batch(payloads: &[&[u8]]) -> Vec<u8> {
        let total_size: usize = payloads.iter().map(|p| FRAME_HEADER_SIZE + p.len()).sum();
        let mut buf = Vec::with_capacity(total_size);
        for payload in payloads {
            Self::encode_into(payload, &mut buf);
        }
        buf
    }

    /// Try to decode a complete message from the reader.
    ///
    /// Returns:
    /// - `Ok(Some(data))` - A complete message was decoded
    /// - `Ok(None)` - Need more data (WouldBlock)
    /// - `Err(e)` - I/O error or protocol error
    ///
    /// This method is designed for non-blocking I/O. Call repeatedly
    /// when the socket becomes readable until it returns `Ok(None)`.
    pub fn decode<R: Read + ?Sized>(&mut self, reader: &mut R) -> io::Result<Option<Vec<u8>>> {
        loop {
            match self.state {
                ReadState::ReadingLength { bytes_read } => {
                    // Read remaining header bytes
                    match reader.read(&mut self.buffer[bytes_read..FRAME_HEADER_SIZE]) {
                        Ok(0) => {
                            // EOF
                            if bytes_read == 0 {
                                // Clean EOF at message boundary
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "connection closed",
                                ));
                            } else {
                                // Partial header read
                                return Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "incomplete frame header",
                                ));
                            }
                        }
                        Ok(n) => {
                            let total = bytes_read + n;
                            if total < FRAME_HEADER_SIZE {
                                // Still need more header bytes
                                self.state = ReadState::ReadingLength { bytes_read: total };
                                // Continue trying to read
                                continue;
                            }

                            // Header complete - parse length
                            let len = u32::from_be_bytes([
                                self.buffer[0],
                                self.buffer[1],
                                self.buffer[2],
                                self.buffer[3],
                            ]) as usize;

                            // Validate length
                            if len > self.max_size {
                                self.frames_rejected += 1;
                                self.state = ReadState::default();
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "frame too large: {} bytes (max {})",
                                        len, self.max_size
                                    ),
                                ));
                            }

                            if len == 0 {
                                // Empty message - valid but unusual
                                self.frames_decoded += 1;
                                self.state = ReadState::default();
                                return Ok(Some(Vec::new()));
                            }

                            // Prepare body buffer
                            self.buffer.resize(len, 0);
                            self.state = ReadState::ReadingBody {
                                expected_len: len,
                                bytes_read: 0,
                            };
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            self.state = ReadState::ReadingLength { bytes_read };
                            return Ok(None);
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }

                ReadState::ReadingBody {
                    expected_len,
                    bytes_read,
                } => {
                    // Read remaining body bytes
                    match reader.read(&mut self.buffer[bytes_read..expected_len]) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "incomplete frame body",
                            ));
                        }
                        Ok(n) => {
                            let total = bytes_read + n;
                            if total < expected_len {
                                // Still need more body bytes
                                self.state = ReadState::ReadingBody {
                                    expected_len,
                                    bytes_read: total,
                                };
                                continue;
                            }

                            // Message complete
                            let message = self.buffer[..expected_len].to_vec();
                            self.frames_decoded += 1;
                            self.bytes_decoded += expected_len as u64;

                            // Reset for next message
                            self.buffer.resize(FRAME_HEADER_SIZE, 0);
                            self.state = ReadState::default();

                            return Ok(Some(message));
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            self.state = ReadState::ReadingBody {
                                expected_len,
                                bytes_read,
                            };
                            return Ok(None);
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    /// Check if the codec is in the middle of reading a message.
    pub fn is_partial(&self) -> bool {
        match self.state {
            ReadState::ReadingLength { bytes_read } => bytes_read > 0,
            ReadState::ReadingBody { .. } => true,
        }
    }

    /// Get the number of bytes needed to complete the current read.
    pub fn bytes_needed(&self) -> usize {
        match self.state {
            ReadState::ReadingLength { bytes_read } => FRAME_HEADER_SIZE - bytes_read,
            ReadState::ReadingBody {
                expected_len,
                bytes_read,
            } => expected_len - bytes_read,
        }
    }

    /// v233: Feed plaintext data into the accumulator buffer.
    ///
    /// Used when data comes from TLS decryption instead of direct socket reads.
    /// After feeding data, call `decode_buffered()` to extract frames.
    pub fn feed(&mut self, data: &[u8]) {
        // Compact the accumulator if we've consumed a lot
        if self.accumulator_pos > 0 && self.accumulator_pos > self.accumulator.len() / 2 {
            self.accumulator.drain(..self.accumulator_pos);
            self.accumulator_pos = 0;
        }
        self.accumulator.extend_from_slice(data);
    }

    /// v233: Try to decode a complete message from the accumulator buffer.
    ///
    /// Returns:
    /// - `Some(data)` - A complete message was decoded
    /// - `None` - Need more data
    ///
    /// Call repeatedly until it returns `None` to extract all available frames.
    pub fn decode_buffered(&mut self) -> Option<Vec<u8>> {
        loop {
            let available = &self.accumulator[self.accumulator_pos..];

            match self.state {
                ReadState::ReadingLength { bytes_read } => {
                    let needed = FRAME_HEADER_SIZE - bytes_read;
                    if available.len() < needed {
                        // Not enough data for header
                        return None;
                    }

                    // Copy header bytes
                    self.buffer[bytes_read..FRAME_HEADER_SIZE]
                        .copy_from_slice(&available[..needed]);
                    self.accumulator_pos += needed;

                    // Parse length
                    let len = u32::from_be_bytes([
                        self.buffer[0],
                        self.buffer[1],
                        self.buffer[2],
                        self.buffer[3],
                    ]) as usize;

                    // Validate length
                    if len > self.max_size {
                        self.frames_rejected += 1;
                        self.state = ReadState::default();
                        // Skip this frame - in practice this is an error condition
                        // but for buffered mode we just reset
                        continue;
                    }

                    if len == 0 {
                        // Empty message
                        self.frames_decoded += 1;
                        self.state = ReadState::default();
                        return Some(Vec::new());
                    }

                    // Prepare for body
                    self.buffer.resize(len, 0);
                    self.state = ReadState::ReadingBody {
                        expected_len: len,
                        bytes_read: 0,
                    };
                }

                ReadState::ReadingBody {
                    expected_len,
                    bytes_read,
                } => {
                    let needed = expected_len - bytes_read;
                    if available.len() < needed {
                        // Not enough data for body
                        return None;
                    }

                    // Copy body bytes
                    self.buffer[bytes_read..expected_len].copy_from_slice(&available[..needed]);
                    self.accumulator_pos += needed;

                    // Message complete
                    let message = self.buffer[..expected_len].to_vec();
                    self.frames_decoded += 1;
                    self.bytes_decoded += expected_len as u64;

                    // Reset for next message
                    self.buffer.resize(FRAME_HEADER_SIZE, 0);
                    self.state = ReadState::default();

                    return Some(message);
                }
            }
        }
    }

    /// v233: Check if there's buffered data waiting to be decoded.
    pub fn has_buffered_data(&self) -> bool {
        self.accumulator_pos < self.accumulator.len()
    }
}

/// Result of attempting to parse a frame from a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult {
    /// Complete frame found, returns (payload_len, total_frame_len)
    Complete(usize, usize),
    /// Need more bytes to complete
    Incomplete(usize),
    /// Frame length exceeds maximum
    TooLarge(usize),
}

/// Parse frame header from a buffer without consuming.
///
/// Useful for peek-style processing or zero-copy scenarios.
pub fn peek_frame_header(buf: &[u8], max_size: usize) -> ParseResult {
    if buf.len() < FRAME_HEADER_SIZE {
        return ParseResult::Incomplete(FRAME_HEADER_SIZE - buf.len());
    }

    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    if len > max_size {
        return ParseResult::TooLarge(len);
    }

    let total_frame_len = FRAME_HEADER_SIZE + len;
    if buf.len() < total_frame_len {
        return ParseResult::Incomplete(total_frame_len - buf.len());
    }

    ParseResult::Complete(len, total_frame_len)
}

/// Extract a complete frame from a buffer, returning the payload.
///
/// Returns None if the buffer doesn't contain a complete frame.
pub fn extract_frame(buf: &[u8], max_size: usize) -> Option<&[u8]> {
    match peek_frame_header(buf, max_size) {
        ParseResult::Complete(len, _) => Some(&buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + len]),
        _ => None,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_encode_simple() {
        let payload = b"hello";
        let frame = FrameCodec::encode(payload);

        assert_eq!(frame.len(), 4 + 5);
        assert_eq!(&frame[..4], &5u32.to_be_bytes());
        assert_eq!(&frame[4..], b"hello");
    }

    #[test]
    fn test_encode_empty() {
        let frame = FrameCodec::encode(b"");
        assert_eq!(frame.len(), 4);
        assert_eq!(&frame[..4], &0u32.to_be_bytes());
    }

    #[test]
    fn test_encode_into() {
        let mut buf = Vec::new();
        FrameCodec::encode_into(b"hello", &mut buf);
        FrameCodec::encode_into(b"world", &mut buf);

        assert_eq!(buf.len(), 4 + 5 + 4 + 5);
    }

    #[test]
    fn test_encode_batch() {
        let payloads: Vec<&[u8]> = vec![b"hello", b"world", b"!"];
        let buf = FrameCodec::encode_batch(&payloads);

        assert_eq!(buf.len(), (4 + 5) + (4 + 5) + (4 + 1));
    }

    #[test]
    fn test_decode_simple() {
        let mut codec = FrameCodec::new(1024);
        let frame = FrameCodec::encode(b"hello, world!");
        let mut cursor = Cursor::new(frame);

        let result = codec.decode(&mut cursor).unwrap();
        assert_eq!(result, Some(b"hello, world!".to_vec()));
        assert_eq!(codec.frames_decoded(), 1);
    }

    #[test]
    fn test_decode_empty_message() {
        let mut codec = FrameCodec::new(1024);
        let frame = FrameCodec::encode(b"");
        let mut cursor = Cursor::new(frame);

        let result = codec.decode(&mut cursor).unwrap();
        assert_eq!(result, Some(Vec::new()));
    }

    #[test]
    fn test_decode_multiple() {
        let mut codec = FrameCodec::new(1024);
        let mut buf = Vec::new();
        FrameCodec::encode_into(b"first", &mut buf);
        FrameCodec::encode_into(b"second", &mut buf);
        FrameCodec::encode_into(b"third", &mut buf);

        let mut cursor = Cursor::new(buf);

        assert_eq!(codec.decode(&mut cursor).unwrap(), Some(b"first".to_vec()));
        assert_eq!(codec.decode(&mut cursor).unwrap(), Some(b"second".to_vec()));
        assert_eq!(codec.decode(&mut cursor).unwrap(), Some(b"third".to_vec()));
        assert_eq!(codec.frames_decoded(), 3);
    }

    #[test]
    fn test_decode_too_large() {
        let mut codec = FrameCodec::new(10); // Very small max
        let frame = FrameCodec::encode(b"this message is too long for the limit");
        let mut cursor = Cursor::new(frame);

        let result = codec.decode(&mut cursor);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(codec.frames_rejected(), 1);
    }

    #[test]
    fn test_decode_partial_header() {
        let mut codec = FrameCodec::new(1024);
        let frame = FrameCodec::encode(b"hello");

        // Feed only 2 bytes of header
        // With a Cursor, EOF is returned when exhausted (not WouldBlock)
        // In real TCP with non-blocking sockets, we'd get WouldBlock instead
        let mut cursor = Cursor::new(&frame[..2]);
        let result = codec.decode(&mut cursor);

        // Cursor returns EOF when exhausted, which triggers incomplete header error
        // This is expected behavior - partial reads return EOF from Cursor
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_decode_partial_body() {
        let mut codec = FrameCodec::new(1024);
        let frame = FrameCodec::encode(b"hello, world!");

        // Feed header + partial body
        let mut cursor = Cursor::new(&frame[..8]);
        // Will read header, then fail on partial body
        let result = codec.decode(&mut cursor);
        // EOF in middle of body is an error
        assert!(result.is_err());
    }

    #[test]
    fn test_peek_frame_header() {
        let frame = FrameCodec::encode(b"hello");

        // Incomplete header
        assert_eq!(
            peek_frame_header(&frame[..2], 1024),
            ParseResult::Incomplete(2)
        );

        // Complete header but incomplete body
        assert_eq!(
            peek_frame_header(&frame[..4], 1024),
            ParseResult::Incomplete(5)
        );

        // Complete frame
        assert_eq!(peek_frame_header(&frame, 1024), ParseResult::Complete(5, 9));

        // Too large
        assert_eq!(peek_frame_header(&frame, 2), ParseResult::TooLarge(5));
    }

    #[test]
    fn test_extract_frame() {
        let frame = FrameCodec::encode(b"hello");

        // Incomplete
        assert!(extract_frame(&frame[..4], 1024).is_none());

        // Complete
        assert_eq!(extract_frame(&frame, 1024), Some(b"hello".as_slice()));
    }

    #[test]
    fn test_codec_reset() {
        let mut codec = FrameCodec::new(1024);

        // Start reading
        let frame = FrameCodec::encode(b"hello");
        let mut cursor = Cursor::new(&frame[..4]); // Just header
        let _ = codec.decode(&mut cursor); // Partial read

        assert!(codec.is_partial());

        codec.reset();

        assert!(!codec.is_partial());
        assert_eq!(codec.bytes_needed(), FRAME_HEADER_SIZE);
    }

    #[test]
    fn test_bytes_needed() {
        let mut codec = FrameCodec::new(1024);

        // Initial state: need header
        assert_eq!(codec.bytes_needed(), 4);

        // After header read, need body
        // Simulate by manually setting state
        codec.state = ReadState::ReadingBody {
            expected_len: 100,
            bytes_read: 40,
        };
        assert_eq!(codec.bytes_needed(), 60);
    }

    #[test]
    fn test_large_message() {
        let mut codec = FrameCodec::new(1024 * 1024);
        let payload = vec![0x42u8; 100_000];
        let frame = FrameCodec::encode(&payload);
        let mut cursor = Cursor::new(frame);

        let result = codec.decode(&mut cursor).unwrap();
        assert_eq!(result.as_ref().map(|v| v.len()), Some(100_000));
        assert_eq!(codec.bytes_decoded(), 100_000);
    }

    #[test]
    fn test_roundtrip_various_sizes() {
        let sizes = [0, 1, 100, 1000, 10000, 65535, 100000];

        for &size in &sizes {
            let mut codec = FrameCodec::new(1024 * 1024);
            let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let frame = FrameCodec::encode(&payload);
            let mut cursor = Cursor::new(frame);

            let result = codec.decode(&mut cursor).unwrap().unwrap();
            assert_eq!(result.len(), size, "Size mismatch for {}", size);
            assert_eq!(result, payload, "Content mismatch for size {}", size);
        }
    }

    #[test]
    fn test_max_u32_length_rejected() {
        let mut codec = FrameCodec::new(1024);

        // Craft a frame with max u32 length
        let mut frame = vec![0xFF, 0xFF, 0xFF, 0xFF]; // u32::MAX
        frame.push(0); // Some body byte

        let mut cursor = Cursor::new(frame);
        let result = codec.decode(&mut cursor);

        assert!(result.is_err());
        assert_eq!(codec.frames_rejected(), 1);
    }

    #[test]
    fn test_statistics() {
        let mut codec = FrameCodec::new(1024);

        let mut buf = Vec::new();
        FrameCodec::encode_into(b"hello", &mut buf);
        FrameCodec::encode_into(b"world!!", &mut buf);

        let mut cursor = Cursor::new(buf);

        codec.decode(&mut cursor).unwrap();
        assert_eq!(codec.frames_decoded(), 1);
        assert_eq!(codec.bytes_decoded(), 5);

        codec.decode(&mut cursor).unwrap();
        assert_eq!(codec.frames_decoded(), 2);
        assert_eq!(codec.bytes_decoded(), 5 + 7);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Low Bandwidth Transport (LBW) for constrained links.
//!
//! This module provides an optimized HDDS<->HDDS transport for:
//! - **Throughput**: 9.6 kbps -> 2 Mbps
//! - **Latency**: 100 ms -> 2 s RTT
//! - **Loss**: 10-30% packet loss
//! - **Corruption**: End-to-end CRC protection
//!
//! # Design Goals
//!
//! - Minimal overhead vs RTPS (~3-6 bytes per record, ~6-10 bytes per frame)
//! - Selective reliability (P0 = reliable, P2 = best-effort/droppable)
//! - Transparent API (writer.write() unchanged)
//! - Batching + token bucket rate limiting
//! - Delta encoding for telemetry efficiency
//!
//! # Wire Protocol
//!
//! ```text
//! Frame = sync(0xA5) | version | flags | frame_len(varint) | session_id | frame_seq | records* | crc16?
//! Record = stream_id | rflags | msg_seq(varint) | len(varint) | payload
//! ```
//!
//! # Priority Levels
//!
//! - **P0**: Critical/reliable (commands, state sync) - immediate flush, retransmit
//! - **P1**: Important (sensor data) - batched, no retransmit
//! - **P2**: Telemetry (droppable) - batched, dropped on congestion
//!
//! # Modules
//!
//! - `varint` - ULEB128 variable-length integer encoding
//! - `crc` - CRC-16/CCITT-FALSE checksums
//! - `frame` - Frame header encoding/decoding
//! - `record` - Record encoding/decoding
//! - `control` - CONTROL stream messages (HELLO, MAP_*, ACK, etc.)

pub mod compress;
pub mod control;
pub mod crc;
pub mod delta;
pub mod fragment;
pub mod frame;
pub mod link;
pub mod mapping;
pub mod record;
pub mod reliable;
pub mod scheduler;
pub mod session;
pub mod transport;
pub mod varint;

// Re-exports
pub use compress::{
    CompressConfig, CompressError, CompressResult, CompressStats, CompressionAlgo, Compressor,
    Decompressor,
};
pub use crc::{crc16_ccitt, verify_crc16};
pub use delta::{
    DeltaConfig, DeltaDecoder, DeltaDecoderStats, DeltaEncoder, DeltaEncoderStats, DeltaError,
    DeltaRecord, StateAck,
};
pub use fragment::{
    FragError, FragHeader, Fragment, Fragmenter, Reassembler, ReassemblerConfig, ReassemblerStats,
};
pub use link::{LinkStats, LoopbackLink, LowBwLink, SimLink, SimLinkConfig, UdpLink};
pub use mapping::{MapperConfig, MapperStats, RxStreamInfo, StreamMapper, TxStreamInfo};
pub use record::Priority;
pub use reliable::{
    ReliableConfig, ReliableReceiver, ReliableReceiverStats, ReliableSender, ReliableSenderStats,
};
pub use scheduler::{Scheduler, SchedulerConfig, SchedulerStats};
pub use session::{
    NegotiatedParams, Session, SessionConfig, SessionError, SessionState, SessionStats,
};
pub use transport::{
    LowBwConfig, LowBwStats, LowBwTransport, StreamConfig, StreamHandle, TransportError,
};
pub use varint::{decode_varint, encode_varint, varint_len};

#[cfg(test)]
mod fuzz_tests {
    //! Fuzz-lite tests to ensure no panics on random/malformed input.

    use super::control::ControlMessage;
    use super::frame::decode_frame;
    use super::record::decode_record;
    use super::varint::decode_varint;

    /// Simple PRNG for reproducible fuzz testing.
    struct SimpleRng {
        state: u64,
    }

    impl SimpleRng {
        fn new(seed: u64) -> Self {
            Self { state: seed }
        }

        fn next(&mut self) -> u64 {
            // xorshift64
            self.state ^= self.state << 13;
            self.state ^= self.state >> 7;
            self.state ^= self.state << 17;
            self.state
        }

        fn next_u8(&mut self) -> u8 {
            self.next() as u8
        }

        fn fill_bytes(&mut self, buf: &mut [u8]) {
            for byte in buf.iter_mut() {
                *byte = self.next_u8();
            }
        }
    }

    #[test]
    fn test_varint_fuzz_no_panic() {
        let mut rng = SimpleRng::new(12345);
        let mut buf = [0u8; 32];

        for _ in 0..10_000 {
            let len = (rng.next() % 32) as usize + 1;
            rng.fill_bytes(&mut buf[..len]);

            // Should not panic, may return error
            let _ = decode_varint(&buf[..len]);
        }
    }

    #[test]
    fn test_frame_fuzz_no_panic() {
        let mut rng = SimpleRng::new(67890);
        let mut buf = [0u8; 256];

        for _ in 0..10_000 {
            let len = (rng.next() % 256) as usize + 1;
            rng.fill_bytes(&mut buf[..len]);

            // Should not panic, may return error
            let _ = decode_frame(&buf[..len]);
        }
    }

    #[test]
    fn test_record_fuzz_no_panic() {
        let mut rng = SimpleRng::new(11111);
        let mut buf = [0u8; 256];

        for _ in 0..10_000 {
            let len = (rng.next() % 256) as usize + 1;
            rng.fill_bytes(&mut buf[..len]);

            // Should not panic, may return error
            let _ = decode_record(&buf[..len]);
        }
    }

    #[test]
    fn test_control_fuzz_no_panic() {
        let mut rng = SimpleRng::new(22222);
        let mut buf = [0u8; 64];

        for _ in 0..10_000 {
            let len = (rng.next() % 64) as usize + 1;
            rng.fill_bytes(&mut buf[..len]);

            // Should not panic, may return error
            let _ = ControlMessage::decode(&buf[..len]);
        }
    }

    #[test]
    fn test_edge_cases_no_panic() {
        // Empty buffers
        let _ = decode_varint(&[]);
        let _ = decode_frame(&[]);
        let _ = decode_record(&[]);
        let _ = ControlMessage::decode(&[]);

        // Single byte
        let _ = decode_varint(&[0x00]);
        let _ = decode_varint(&[0x80]); // Continuation bit set
        let _ = decode_varint(&[0xFF]);
        let _ = decode_frame(&[0xA5]); // Just sync
        let _ = decode_record(&[0x00]);
        let _ = ControlMessage::decode(&[0x01]); // HELLO type

        // All zeros
        let zeros = [0u8; 100];
        let _ = decode_frame(&zeros);
        let _ = decode_record(&zeros);

        // All ones
        let ones = [0xFFu8; 100];
        let _ = decode_frame(&ones);
        let _ = decode_record(&ones);

        // Extremely long varint (overflow)
        let long_varint = [0x80u8; 20];
        let _ = decode_varint(&long_varint);
    }

    #[test]
    fn test_malformed_frame_headers() {
        use super::frame::FRAME_SYNC;

        // Valid sync, wrong version
        let _ = decode_frame(&[FRAME_SYNC, 0xFF, 0x00, 0x00, 0x00, 0x00]);

        // Valid sync+version, huge frame_len
        let _ = decode_frame(&[FRAME_SYNC, 0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Sync at various positions with garbage before
        let mut buf = [0u8; 100];
        buf[50] = FRAME_SYNC;
        buf[51] = 0x01;
        let _ = decode_frame(&buf);
    }

    #[test]
    fn test_malformed_records() {
        // Record with huge payload length
        let _ = decode_record(&[0x01, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);

        // Record claiming control stream with garbage
        let _ = decode_record(&[0x00, 0xFF, 0x00, 0x00]);

        // Record with fragment flag set
        let _ = decode_record(&[0x01, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00]);
    }
}

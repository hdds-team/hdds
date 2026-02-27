// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Integrated Low Bandwidth Transport for HDDS.
//!
//! This module provides the main entry point for using the LBW transport,
//! combining all components (session, scheduler, reliable, delta, compression,
//! fragmentation) into a unified transport layer.
//!
//! # Architecture
//!
//! ```text
//! Application (writer.write())
//!        |
//!        v
//! +------------------+
//! |  LowBwTransport  |  <-- Unified API
//! +------------------+
//!        |
//!        v
//! +------------------+
//! |   DeltaEncoder   |  <-- FULL/DELTA encoding (P1/P2 telemetry)
//! +------------------+
//!        |
//!        v
//! +------------------+
//! |   Compressor     |  <-- LZ4/Deflate (if beneficial)
//! +------------------+
//!        |
//!        v
//! +------------------+
//! |   Fragmenter     |  <-- Split large payloads
//! +------------------+
//!        |
//!        v
//! +------------------+
//! |   Scheduler      |  <-- Priority queues + token bucket
//! +------------------+
//!        |
//!        v
//! +------------------+
//! |  ReliableSender  |  <-- Retransmit for P0/CONTROL
//! +------------------+
//!        |
//!        v
//! +------------------+
//! |    Session       |  <-- HELLO handshake + mapping
//! +------------------+
//!        |
//!        v
//! +------------------+
//! |   LowBwLink      |  <-- UDP/Serial/Radio
//! +------------------+
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use hdds::transport::lowbw::{LowBwTransport, LowBwConfig, Priority};
//!
//! // Create transport with satellite preset
//! let config = LowBwConfig::satellite();
//! let mut transport = LowBwTransport::new(config, link)?;
//!
//! // Establish session
//! transport.connect()?;
//!
//! // Send data
//! transport.send(topic_id, &data, Priority::P1)?;
//!
//! // Receive data
//! if let Some((topic_id, data)) = transport.recv()? {
//!     // Process received data
//! }
//! ```

use super::compress::{CompressConfig, CompressResult, CompressionAlgo, Compressor, Decompressor};
use super::delta::{DeltaConfig, DeltaDecoder, DeltaEncoder, DeltaRecord};
use super::fragment::{Fragmenter, Reassembler, ReassemblerConfig};
use super::link::LowBwLink;
use super::mapping::{MapperConfig, StreamMapper};
use super::record::Priority;
use super::reliable::{ReliableConfig, ReliableSender};
use super::scheduler::{Scheduler, SchedulerConfig};
use super::session::{Session, SessionConfig, SessionState};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Unified configuration for LBW transport.
#[derive(Debug, Clone)]
pub struct LowBwConfig {
    /// Session configuration.
    pub session: SessionConfig,
    /// Scheduler configuration.
    pub scheduler: SchedulerConfig,
    /// Reliable transport configuration.
    pub reliable: ReliableConfig,
    /// Delta encoding configuration.
    pub delta: DeltaConfig,
    /// Compression configuration.
    pub compress: CompressConfig,
    /// Reassembler configuration.
    pub reassembler: ReassemblerConfig,
    /// Stream mapper configuration.
    pub mapper: MapperConfig,
    /// Enable delta encoding for telemetry streams.
    pub delta_enabled: bool,
    /// Enable compression.
    pub compress_enabled: bool,
}

impl Default for LowBwConfig {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            scheduler: SchedulerConfig::default(),
            reliable: ReliableConfig::default(),
            delta: DeltaConfig::default(),
            compress: CompressConfig::default(),
            reassembler: ReassemblerConfig::default(),
            mapper: MapperConfig::default(),
            delta_enabled: true,
            compress_enabled: true,
        }
    }
}

impl LowBwConfig {
    /// Preset for slow serial links (9600 bps).
    ///
    /// Optimized for very low bandwidth with aggressive batching.
    pub fn slow_serial() -> Self {
        Self {
            session: SessionConfig {
                mtu: 256,
                hello_interval: Duration::from_millis(2000),
                hello_max_retries: 15,
                session_timeout: Duration::from_secs(60),
                ..Default::default()
            },
            scheduler: SchedulerConfig {
                rate_bps: 9600,
                bucket_size: 512,
                batch_window_ms: 200,
                max_frame_size: 256,
                ..Default::default()
            },
            reliable: ReliableConfig {
                window_size: 2,
                timeout_ms: 2000,
                max_retries: 10,
            },
            delta: DeltaConfig {
                keyframe_period: Duration::from_millis(10000),
                keyframe_redundancy: 3,
                redundancy_spacing: Duration::from_millis(500),
                ..Default::default()
            },
            compress: CompressConfig {
                algo: CompressionAlgo::Deflate, // Better ratio for slow links
                threshold: 32,
                ratio_gate: 0.95,
                ..Default::default()
            },
            reassembler: ReassemblerConfig {
                timeout: Duration::from_secs(10),
                max_groups: 8,
                ..Default::default()
            },
            mapper: MapperConfig::default(),
            delta_enabled: true,
            compress_enabled: true,
        }
    }

    /// Preset for satellite links (64-256 kbps, 500ms-2s RTT).
    ///
    /// Balanced for medium bandwidth with high latency.
    pub fn satellite() -> Self {
        Self {
            session: SessionConfig {
                mtu: 512,
                hello_interval: Duration::from_millis(3000),
                hello_max_retries: 10,
                session_timeout: Duration::from_secs(30),
                ..Default::default()
            },
            scheduler: SchedulerConfig {
                rate_bps: 128_000,
                bucket_size: 2048,
                batch_window_ms: 100,
                max_frame_size: 512,
                ..Default::default()
            },
            reliable: ReliableConfig {
                window_size: 4,
                timeout_ms: 3000, // High RTT
                max_retries: 8,
            },
            delta: DeltaConfig {
                keyframe_period: Duration::from_millis(5000),
                keyframe_redundancy: 2,
                redundancy_spacing: Duration::from_millis(300),
                ..Default::default()
            },
            compress: CompressConfig {
                #[cfg(feature = "lowbw-lz4")]
                algo: CompressionAlgo::Lz4,
                #[cfg(not(feature = "lowbw-lz4"))]
                algo: CompressionAlgo::Deflate,
                threshold: 64,
                ratio_gate: 0.9,
                ..Default::default()
            },
            reassembler: ReassemblerConfig {
                timeout: Duration::from_secs(8),
                max_groups: 16,
                ..Default::default()
            },
            mapper: MapperConfig::default(),
            delta_enabled: true,
            compress_enabled: true,
        }
    }

    /// Preset for tactical radio (UHF/VHF, 16-64 kbps, 100-500ms RTT, 10-30% loss).
    ///
    /// Optimized for lossy links with redundancy.
    pub fn tactical_radio() -> Self {
        Self {
            session: SessionConfig {
                mtu: 256,
                hello_interval: Duration::from_millis(1500),
                hello_max_retries: 12,
                session_timeout: Duration::from_secs(20),
                ..Default::default()
            },
            scheduler: SchedulerConfig {
                rate_bps: 32_000,
                bucket_size: 1024,
                batch_window_ms: 50,
                max_frame_size: 256,
                ..Default::default()
            },
            reliable: ReliableConfig {
                window_size: 2,
                timeout_ms: 1000,
                max_retries: 12, // More retries for lossy link
            },
            delta: DeltaConfig {
                keyframe_period: Duration::from_millis(3000),
                keyframe_redundancy: 3, // More redundancy for loss
                redundancy_spacing: Duration::from_millis(200),
                ..Default::default()
            },
            compress: CompressConfig {
                #[cfg(feature = "lowbw-lz4")]
                algo: CompressionAlgo::Lz4,
                #[cfg(not(feature = "lowbw-lz4"))]
                algo: CompressionAlgo::Deflate,
                threshold: 48,
                ratio_gate: 0.85,
                ..Default::default()
            },
            reassembler: ReassemblerConfig {
                timeout: Duration::from_secs(5),
                max_groups: 12,
                ..Default::default()
            },
            mapper: MapperConfig::default(),
            delta_enabled: true,
            compress_enabled: true,
        }
    }

    /// Preset for IoT/LoRa links (< 10 kbps, high latency).
    ///
    /// Minimal overhead, aggressive compression.
    pub fn iot_lora() -> Self {
        Self {
            session: SessionConfig {
                mtu: 128,
                hello_interval: Duration::from_millis(5000),
                hello_max_retries: 20,
                session_timeout: Duration::from_secs(120),
                ..Default::default()
            },
            scheduler: SchedulerConfig {
                rate_bps: 4000,
                bucket_size: 256,
                batch_window_ms: 500,
                max_frame_size: 128,
                ..Default::default()
            },
            reliable: ReliableConfig {
                window_size: 1, // Stop-and-wait
                timeout_ms: 5000,
                max_retries: 15,
            },
            delta: DeltaConfig {
                keyframe_period: Duration::from_millis(30000),
                keyframe_redundancy: 2,
                redundancy_spacing: Duration::from_millis(1000),
                ..Default::default()
            },
            compress: CompressConfig {
                algo: CompressionAlgo::Deflate, // Better ratio
                threshold: 16,
                ratio_gate: 0.98,
                ..Default::default()
            },
            reassembler: ReassemblerConfig {
                timeout: Duration::from_secs(30),
                max_groups: 4,
                ..Default::default()
            },
            mapper: MapperConfig::default(),
            delta_enabled: true,
            compress_enabled: true,
        }
    }

    /// Preset for local testing (fast, no loss simulation).
    pub fn local_test() -> Self {
        Self {
            session: SessionConfig {
                mtu: 1400,
                hello_interval: Duration::from_millis(100),
                hello_max_retries: 5,
                session_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            scheduler: SchedulerConfig {
                rate_bps: 8_000_000, // 8 Mbps
                bucket_size: 65536,
                batch_window_ms: 10,
                max_frame_size: 1400,
                ..Default::default()
            },
            reliable: ReliableConfig {
                window_size: 8,
                timeout_ms: 100,
                max_retries: 3,
            },
            delta: DeltaConfig {
                keyframe_period: Duration::from_millis(1000),
                keyframe_redundancy: 1,
                redundancy_spacing: Duration::from_millis(50),
                ..Default::default()
            },
            compress: CompressConfig {
                algo: CompressionAlgo::None, // No compression for testing
                ..Default::default()
            },
            reassembler: ReassemblerConfig::default(),
            mapper: MapperConfig::default(),
            delta_enabled: false,
            compress_enabled: false,
        }
    }
}

/// Aggregated statistics for the LBW transport.
#[derive(Debug, Clone, Default)]
pub struct LowBwStats {
    /// Session statistics.
    pub session_established: bool,
    pub session_uptime_ms: u64,

    /// Scheduler statistics.
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub p0_records: u64,
    pub p1_records: u64,
    pub p2_records: u64,
    pub records_dropped: u64,

    /// Reliable statistics.
    pub retransmits: u64,
    pub acks_sent: u64,
    pub messages_acked: u64,

    /// Delta statistics.
    pub fulls_sent: u64,
    pub deltas_sent: u64,
    pub resyncs: u64,

    /// Compression statistics.
    pub compress_bytes_saved: u64,

    /// Fragment statistics.
    pub fragments_sent: u64,
    pub fragments_reassembled: u64,
    pub fragments_timeout: u64,

    /// Error counters.
    pub crc_errors: u64,
    pub decode_errors: u64,
    pub mapping_errors: u64,
}

/// Stream handle for sending data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamHandle(pub u8);

/// Stream configuration.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Topic hash for matching.
    pub topic_hash: u64,
    /// Type hash for matching.
    pub type_hash: u64,
    /// Priority level.
    pub priority: Priority,
    /// Enable reliable delivery.
    pub reliable: bool,
    /// Enable delta encoding.
    pub delta_enabled: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            topic_hash: 0,
            type_hash: 0,
            priority: Priority::P1,
            reliable: false,
            delta_enabled: false,
        }
    }
}

/// TX stream state.
struct TxStream {
    #[allow(dead_code)]
    config: StreamConfig,
    delta_encoder: Option<DeltaEncoder>,
    compressor: Option<Compressor>,
    fragmenter: Fragmenter,
    msg_seq: u32,
}

/// RX stream state.
struct RxStream {
    #[allow(dead_code)]
    config: StreamConfig,
    delta_decoder: Option<DeltaDecoder>,
    decompressor: Option<Decompressor>,
    reassembler: Reassembler,
}

/// Main LBW transport instance.
pub struct LowBwTransport {
    config: LowBwConfig,
    link: Arc<dyn LowBwLink>,

    // Core components
    session: Session,
    scheduler: Scheduler,
    #[allow(dead_code)]
    mapper: StreamMapper,
    reliable_sender: ReliableSender,

    // Per-stream state
    tx_streams: HashMap<StreamHandle, TxStream>,
    rx_streams: HashMap<StreamHandle, RxStream>,

    // Frame sequencing
    session_id: u16,
    frame_seq: u32,

    // Timing
    start_time: Instant,

    // Statistics
    stats: LowBwStats,
}

impl LowBwTransport {
    /// Create a new LBW transport with the given configuration and link.
    pub fn new(config: LowBwConfig, link: Arc<dyn LowBwLink>) -> Self {
        let session = Session::new(config.session.clone());
        let scheduler = Scheduler::new(config.scheduler.clone());
        let mapper = StreamMapper::new(config.mapper.clone());
        let reliable_sender = ReliableSender::new(config.reliable.clone());

        Self {
            config,
            link,
            session,
            scheduler,
            mapper,
            reliable_sender,
            tx_streams: HashMap::new(),
            rx_streams: HashMap::new(),
            session_id: 0,
            frame_seq: 0,
            start_time: Instant::now(),
            stats: LowBwStats::default(),
        }
    }

    /// Get the current session state.
    pub fn session_state(&self) -> SessionState {
        self.session.state()
    }

    /// Check if session is established.
    pub fn is_connected(&self) -> bool {
        self.session.state() == SessionState::Established
    }

    /// Register a TX stream.
    pub fn register_tx_stream(
        &mut self,
        handle: StreamHandle,
        config: StreamConfig,
    ) -> Result<(), TransportError> {
        let delta_encoder = if config.delta_enabled && self.config.delta_enabled {
            Some(DeltaEncoder::new(self.config.delta.clone()))
        } else {
            None
        };

        let compressor = if self.config.compress_enabled {
            Some(Compressor::new(self.config.compress.clone()))
        } else {
            None
        };

        // Reserve ~20 bytes for frame/record overhead
        let fragmenter = Fragmenter::new(self.config.session.mtu as usize, 20);

        let stream = TxStream {
            config,
            delta_encoder,
            compressor,
            fragmenter,
            msg_seq: 0,
        };

        self.tx_streams.insert(handle, stream);
        Ok(())
    }

    /// Register an RX stream.
    pub fn register_rx_stream(
        &mut self,
        handle: StreamHandle,
        config: StreamConfig,
    ) -> Result<(), TransportError> {
        let delta_decoder = if config.delta_enabled && self.config.delta_enabled {
            Some(DeltaDecoder::new())
        } else {
            None
        };

        let decompressor = if self.config.compress_enabled {
            Some(Decompressor::new(self.config.compress.algo))
        } else {
            None
        };

        let reassembler = Reassembler::new(self.config.reassembler.clone());

        let stream = RxStream {
            config,
            delta_decoder,
            decompressor,
            reassembler,
        };

        self.rx_streams.insert(handle, stream);
        Ok(())
    }

    /// Send data on a stream.
    pub fn send(
        &mut self,
        handle: StreamHandle,
        data: &[u8],
        priority: Priority,
    ) -> Result<(), TransportError> {
        let stream = self
            .tx_streams
            .get_mut(&handle)
            .ok_or(TransportError::UnknownStream(handle.0))?;

        // Step 1: Delta encoding (if enabled)
        let payload = if let Some(ref mut encoder) = stream.delta_encoder {
            // For delta, we'd need field-level updates
            // For now, treat entire payload as single field
            encoder.update_field(0, data);
            match encoder.poll_record(Instant::now()) {
                DeltaRecord::Full { payload, .. } => {
                    self.stats.fulls_sent += 1;
                    payload
                }
                DeltaRecord::Delta { payload, .. } => {
                    self.stats.deltas_sent += 1;
                    payload
                }
                DeltaRecord::None => return Ok(()), // No change
            }
        } else {
            data.to_vec()
        };

        // Step 2: Compression (if enabled and beneficial)
        let payload = if let Some(ref mut compressor) = stream.compressor {
            match compressor.compress(&payload)? {
                CompressResult::Compressed(compressed) => {
                    self.stats.compress_bytes_saved +=
                        payload.len().saturating_sub(compressed.len()) as u64;
                    compressed
                }
                CompressResult::Skipped => payload,
            }
        } else {
            payload
        };

        // Step 3: Fragmentation (if needed)
        let fragments = stream.fragmenter.fragment(&payload, stream.msg_seq)?;
        stream.msg_seq = stream.msg_seq.wrapping_add(1);

        if fragments.len() > 1 {
            self.stats.fragments_sent += fragments.len() as u64;
        }

        // Step 4: Queue in scheduler
        for frag in fragments {
            let mut record_payload = Vec::with_capacity(32 + frag.data.len());
            let mut header_buf = [0u8; 32];
            let header_len = frag.header.encode(&mut header_buf)?;
            record_payload.extend_from_slice(&header_buf[..header_len]);
            record_payload.extend_from_slice(&frag.data);

            self.scheduler.enqueue(priority, record_payload, handle.0);

            match priority {
                Priority::P0 => self.stats.p0_records += 1,
                Priority::P1 => self.stats.p1_records += 1,
                Priority::P2 => self.stats.p2_records += 1,
            }
        }

        Ok(())
    }

    /// Poll for outgoing frames and send them.
    pub fn poll_send(&mut self) -> Result<usize, TransportError> {
        let mut bytes_sent = 0;

        // Poll scheduler for frames
        while let Some(frame) = self
            .scheduler
            .poll_frame(self.session_id, &mut self.frame_seq)
        {
            self.link.send(&frame)?;
            bytes_sent += frame.len();
            self.stats.frames_sent += 1;
            self.stats.bytes_sent += frame.len() as u64;
        }

        Ok(bytes_sent)
    }

    /// Receive and process incoming data.
    pub fn poll_recv(&mut self) -> Result<Option<(StreamHandle, Vec<u8>)>, TransportError> {
        let mut buf = [0u8; 2048];

        match self.link.recv(&mut buf) {
            Ok(len) if len > 0 => {
                // Process received frame
                self.process_frame(&buf[..len])
            }
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(None),
            Err(e) => Err(TransportError::Io(e)),
        }
    }

    fn process_frame(
        &mut self,
        frame: &[u8],
    ) -> Result<Option<(StreamHandle, Vec<u8>)>, TransportError> {
        use super::frame::decode_frame;
        use super::record::{decode_records, STREAM_CONTROL};

        // Step 1: Decode frame
        let decoded_frame = match decode_frame(frame) {
            Ok(f) => f,
            Err(_) => {
                self.stats.crc_errors += 1;
                return Ok(None);
            }
        };

        // Validate session ID (if session established)
        if self.session.state() == SessionState::Established
            && decoded_frame.header.session_id != self.session_id
        {
            return Ok(None);
        }

        // Step 2: Decode records from frame payload
        let mut records = Vec::new();
        if decode_records(decoded_frame.records, &mut records).is_err() {
            self.stats.decode_errors += 1;
            return Ok(None);
        }

        // Step 3: Process each record
        let mut completed_message: Option<(StreamHandle, Vec<u8>)> = None;

        for record in records {
            if record.header.stream_id == STREAM_CONTROL {
                // Handle CONTROL message
                self.handle_control_record(&record)?;
            } else {
                // Data stream - process through RX pipeline
                if let Some((handle, payload)) = self.process_data_record(&record)? {
                    // Return first completed message; others queued for next poll
                    if completed_message.is_none() {
                        completed_message = Some((handle, payload));
                    }
                }
            }
        }

        Ok(completed_message)
    }

    /// Handle a CONTROL stream record.
    fn handle_control_record(
        &mut self,
        record: &super::record::DecodedRecord<'_>,
    ) -> Result<(), TransportError> {
        use super::control::ControlMessage;

        let (ctrl_msg, _) = match ControlMessage::decode(record.payload) {
            Ok(msg) => msg,
            Err(_) => {
                self.stats.decode_errors += 1;
                return Ok(());
            }
        };

        match ctrl_msg {
            ControlMessage::Hello(hello) => {
                // Session handshake response
                self.session_id = hello.session_id;
                // Session state machine would handle this
            }
            ControlMessage::MapAdd(_map_add) => {
                // Remote is announcing a stream mapping
                // Would update mapper and possibly create RX stream
            }
            ControlMessage::MapAck(_map_ack) => {
                // Remote acknowledged our stream mapping
            }
            ControlMessage::MapReq(_map_req) => {
                // Remote is requesting mapping info for a stream
                // Would respond with MAP_ADD
            }
            ControlMessage::Ack(ack) => {
                // Acknowledgment for reliable delivery
                self.reliable_sender.on_ack(&ack);
                self.stats.acks_sent += 1;
            }
            ControlMessage::StateAck(_state_ack) => {
                // Delta state synchronization ACK
                // Would signal delta encoder to update baseline
            }
            ControlMessage::KeyframeReq(_kf_req) => {
                // Remote is requesting a keyframe
                // Would signal delta encoder to emit full frame
            }
        }

        Ok(())
    }

    /// Process a data stream record through the RX pipeline.
    fn process_data_record(
        &mut self,
        record: &super::record::DecodedRecord<'_>,
    ) -> Result<Option<(StreamHandle, Vec<u8>)>, TransportError> {
        use super::fragment::Fragment;

        let handle = StreamHandle(record.header.stream_id);

        let rx_stream = match self.rx_streams.get_mut(&handle) {
            Some(s) => s,
            None => {
                // Unknown stream - might need to request mapping
                self.stats.mapping_errors += 1;
                return Ok(None);
            }
        };

        // Step 1: Fragment reassembly (if fragmented)
        let payload = if record.header.is_fragment() {
            let (frag, _) = Fragment::decode(record.payload).map_err(|e| {
                self.stats.decode_errors += 1;
                TransportError::Fragment(e)
            })?;

            match rx_stream.reassembler.on_fragment(
                record.header.stream_id,
                &frag.header,
                frag.data,
            ) {
                Ok(Some(complete)) => {
                    self.stats.fragments_reassembled += 1;
                    complete
                }
                Ok(None) => return Ok(None), // Fragment pending
                Err(_) => {
                    self.stats.decode_errors += 1;
                    return Ok(None);
                }
            }
        } else {
            record.payload.to_vec()
        };

        // Step 2: Decompression (if compressed)
        let payload = if record.header.is_compressed() {
            if let Some(ref mut decompressor) = rx_stream.decompressor {
                match decompressor.decompress(&payload) {
                    Ok(decompressed) => decompressed,
                    Err(_) => {
                        self.stats.decode_errors += 1;
                        return Ok(None);
                    }
                }
            } else {
                // Compression flag set but no decompressor configured
                payload
            }
        } else {
            payload
        };

        // Step 3: Delta decoding (if delta)
        // The DeltaDecoder stores field-level state. For now, we handle both
        // FULL and DELTA payloads via on_record, which updates the internal state.
        // Full reconstruction would require a schema to know field layout.
        let payload = if let Some(ref mut delta_decoder) = rx_stream.delta_decoder {
            let is_delta = record.header.is_delta();
            if delta_decoder.on_record(&payload, is_delta).is_err() {
                self.stats.resyncs += 1;
                // Would send KEYFRAME_REQ here
                return Ok(None);
            }
            // For now, pass through the payload as-is
            // Full field reconstruction would require schema knowledge
            payload
        } else {
            payload
        };

        Ok(Some((handle, payload)))
    }

    /// Get current statistics.
    pub fn stats(&self) -> LowBwStats {
        let mut stats = self.stats.clone();
        stats.session_established = self.is_connected();
        stats.session_uptime_ms = self.start_time.elapsed().as_millis() as u64;

        // Aggregate from components
        let scheduler_stats = self.scheduler.stats();
        stats.records_dropped = scheduler_stats.records_dropped;

        let reliable_stats = self.reliable_sender.stats();
        stats.retransmits = reliable_stats.retransmits;
        stats.messages_acked = reliable_stats.messages_acked;

        stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = LowBwStats::default();
        self.scheduler.reset_stats();
        self.reliable_sender.reset_stats();
    }

    /// Get the configuration.
    pub fn config(&self) -> &LowBwConfig {
        &self.config
    }
}

/// Transport error type.
#[derive(Debug)]
pub enum TransportError {
    /// Session not established.
    NotConnected,
    /// Unknown stream handle.
    UnknownStream(u8),
    /// I/O error.
    Io(std::io::Error),
    /// Compression error.
    Compress(super::compress::CompressError),
    /// Fragment error.
    Fragment(super::fragment::FragError),
    /// Session error.
    Session(super::session::SessionError),
    /// Mapping error.
    Mapping(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "session not connected"),
            Self::UnknownStream(id) => write!(f, "unknown stream {}", id),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Compress(e) => write!(f, "compression error: {}", e),
            Self::Fragment(e) => write!(f, "fragment error: {}", e),
            Self::Session(e) => write!(f, "session error: {}", e),
            Self::Mapping(s) => write!(f, "mapping error: {}", s),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<super::compress::CompressError> for TransportError {
    fn from(e: super::compress::CompressError) -> Self {
        Self::Compress(e)
    }
}

impl From<super::fragment::FragError> for TransportError {
    fn from(e: super::fragment::FragError) -> Self {
        Self::Fragment(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::lowbw::link::LoopbackLink;

    #[test]
    fn test_config_presets() {
        let slow = LowBwConfig::slow_serial();
        assert_eq!(slow.session.mtu, 256);
        assert_eq!(slow.scheduler.rate_bps, 9600);

        let sat = LowBwConfig::satellite();
        assert_eq!(sat.session.mtu, 512);
        assert!(sat.reliable.timeout_ms >= 2000);

        let radio = LowBwConfig::tactical_radio();
        assert_eq!(radio.delta.keyframe_redundancy, 3);

        let iot = LowBwConfig::iot_lora();
        assert_eq!(iot.session.mtu, 128);
        assert_eq!(iot.reliable.window_size, 1);

        let local = LowBwConfig::local_test();
        assert!(!local.compress_enabled);
    }

    #[test]
    fn test_transport_create() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let transport = LowBwTransport::new(config, link);

        assert!(!transport.is_connected());
        assert_eq!(transport.session_state(), SessionState::Idle);
    }

    #[test]
    fn test_register_streams() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        // Register TX stream
        let tx_config = StreamConfig {
            topic_hash: 0x1234,
            type_hash: 0x5678,
            priority: Priority::P1,
            reliable: false,
            delta_enabled: false,
        };
        transport
            .register_tx_stream(StreamHandle(1), tx_config.clone())
            .unwrap();

        // Register RX stream
        transport
            .register_rx_stream(StreamHandle(1), tx_config)
            .unwrap();

        assert!(transport.tx_streams.contains_key(&StreamHandle(1)));
        assert!(transport.rx_streams.contains_key(&StreamHandle(1)));
    }

    #[test]
    fn test_send_unknown_stream() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let result = transport.send(StreamHandle(99), b"test", Priority::P1);
        assert!(matches!(result, Err(TransportError::UnknownStream(99))));
    }

    #[test]
    fn test_send_basic() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let stream_config = StreamConfig {
            priority: Priority::P1,
            ..Default::default()
        };
        transport
            .register_tx_stream(StreamHandle(1), stream_config)
            .unwrap();

        // Send data
        transport
            .send(StreamHandle(1), b"hello world", Priority::P1)
            .unwrap();

        assert!(transport.stats.p1_records > 0);
    }

    #[test]
    fn test_send_with_fragmentation() {
        let mut config = LowBwConfig::local_test();
        config.session.mtu = 32; // Force fragmentation

        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let stream_config = StreamConfig::default();
        transport
            .register_tx_stream(StreamHandle(1), stream_config)
            .unwrap();

        // Send large data that requires fragmentation
        let large_data = vec![0xAA; 100];
        transport
            .send(StreamHandle(1), &large_data, Priority::P1)
            .unwrap();

        assert!(transport.stats.fragments_sent > 1);
    }

    #[test]
    fn test_stats() {
        let config = LowBwConfig::local_test();
        let link = Arc::new(LoopbackLink::new());
        let mut transport = LowBwTransport::new(config, link);

        let stream_config = StreamConfig::default();
        transport
            .register_tx_stream(StreamHandle(1), stream_config)
            .unwrap();

        transport
            .send(StreamHandle(1), b"test1", Priority::P0)
            .unwrap();
        transport
            .send(StreamHandle(1), b"test2", Priority::P1)
            .unwrap();
        transport
            .send(StreamHandle(1), b"test3", Priority::P2)
            .unwrap();

        let stats = transport.stats();
        assert_eq!(stats.p0_records, 1);
        assert_eq!(stats.p1_records, 1);
        assert_eq!(stats.p2_records, 1);

        transport.reset_stats();
        let stats = transport.stats();
        assert_eq!(stats.p0_records, 0);
    }

    #[test]
    fn test_config_default() {
        let config = LowBwConfig::default();
        assert!(config.delta_enabled);
        assert!(config.compress_enabled);
    }

    #[test]
    fn test_stream_config_default() {
        let config = StreamConfig::default();
        assert_eq!(config.priority, Priority::P1);
        assert!(!config.reliable);
        assert!(!config.delta_enabled);
    }

    #[test]
    fn test_transport_error_display() {
        let err = TransportError::NotConnected;
        assert_eq!(format!("{}", err), "session not connected");

        let err = TransportError::UnknownStream(5);
        assert_eq!(format!("{}", err), "unknown stream 5");
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LBW Session management.
//!
//! A session represents a bidirectional connection between two LBW nodes.
//! It handles:
//! - HELLO handshake for session establishment
//! - Feature negotiation (intersection of capabilities)
//! - MTU negotiation (min of local and remote)
//! - Session keepalive
//!
//! # State Machine
//!
//! ```text
//!                     +-------------+
//!                     |    Idle     |
//!                     +------+------+
//!                            | start()
//!                            v
//!                     +-------------+
//!          +----------| Connecting  |----------+
//!          |          +------+------+          |
//!          |                 |                 |
//!   HELLO timeout    recv HELLO          max retries
//!   (resend)               |                 |
//!          |               v                 v
//!          |        +-------------+   +-------------+
//!          +------->| Established |   |   Failed    |
//!                   +-------------+   +-------------+
//! ```
//!
//! # Usage
//!
//! ```ignore
//! let config = SessionConfig::default();
//! let mut session = Session::new(config, node_id);
//!
//! // Start handshake
//! session.start();
//!
//! // In event loop:
//! if let Some(frame) = session.poll_send() {
//!     link.send(&frame)?;
//! }
//!
//! // On receive:
//! session.on_receive(&data)?;
//!
//! // Check state:
//! if session.is_established() {
//!     // Can send user data
//! }
//! ```

use std::time::{Duration, Instant};

use super::control::{ctrl_type, features, Hello};
use super::frame::{encode_frame, FrameHeader};
use super::record::{encode_record, RecordHeader, STREAM_CONTROL};

/// Session configuration.
///
/// # Timeout Parameters
///
/// - `hello_interval`: Time between HELLO retransmissions during Connecting
/// - `hello_max_retries`: Max retries before Connecting → Failed
/// - `session_timeout`: Inactivity timeout in Established state
///
/// Total handshake timeout = `hello_interval × hello_max_retries`
/// Default: 500ms × 10 = 5 seconds
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Local node ID (0-255).
    pub node_id: u8,
    /// Supported features bitmap (see `features::*` constants).
    pub features: u8,
    /// Local MTU in bytes. Negotiated MTU = min(local, remote).
    pub mtu: u16,
    /// HELLO resend interval during handshake (default: 500ms).
    pub hello_interval: Duration,
    /// Maximum HELLO retries before declaring failure (default: 10).
    pub hello_max_retries: u32,
    /// Inactivity timeout for established sessions (default: 30s).
    pub session_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            node_id: 0,
            features: features::DELTA | features::COMPRESSION | features::FRAGMENTATION,
            mtu: 256,
            hello_interval: Duration::from_millis(500),
            hello_max_retries: 10,
            session_timeout: Duration::from_secs(30),
        }
    }
}

/// Session state.
///
/// # State Machine Transitions
///
/// ```text
/// Idle ─────┬─── start() ──────────→ Connecting
///           │                              │
///           └─ recv HELLO (passive) ──→ Established ←── recv HELLO ───┘
///                                          │
///                 max retries ←────────────┤
///                     ↓                    │
///                  Failed ←─── session_timeout
///
/// Any state ─── close() ───→ Closed
/// Any state ─── reset() ───→ Idle
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial state, not started. Transitions via start() or passive HELLO.
    Idle,
    /// Sending HELLO, waiting for response. Retries on hello_interval timeout.
    Connecting,
    /// Session established, ready for data. Monitors session_timeout.
    Established,
    /// Session failed (max retries or inactivity timeout). Requires reset().
    Failed,
    /// Session explicitly closed. Requires reset() to reuse.
    Closed,
}

/// Negotiated session parameters.
///
/// Computed during HELLO exchange using conservative negotiation:
/// - `mtu`: min(local, remote) - ensures neither peer overflows
/// - `features`: local & remote (bitmask AND) - only mutually supported features
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedParams {
    /// Negotiated MTU (min of local and remote).
    pub mtu: u16,
    /// Negotiated features (bitwise AND of local and remote feature masks).
    pub features: u8,
    /// Remote node ID.
    pub remote_node_id: u8,
    /// Remote session ID.
    pub remote_session_id: u16,
}

/// Session statistics.
#[derive(Debug, Default, Clone)]
pub struct SessionStats {
    /// HELLO messages sent.
    pub hellos_sent: u32,
    /// HELLO messages received.
    pub hellos_received: u32,
    /// Frames sent.
    pub frames_sent: u64,
    /// Frames received.
    pub frames_received: u64,
    /// Current retry count.
    pub retry_count: u32,
}

/// LBW Session.
pub struct Session {
    /// Configuration.
    config: SessionConfig,
    /// Current state.
    state: SessionState,
    /// Local session ID (random).
    session_id: u16,
    /// Mapping epoch.
    map_epoch: u16,
    /// Frame sequence counter.
    frame_seq: u32,
    /// Last HELLO send time.
    last_hello_sent: Option<Instant>,
    /// HELLO retry count.
    hello_retries: u32,
    /// Last activity time.
    last_activity: Instant,
    /// Negotiated parameters (after establishment).
    negotiated: Option<NegotiatedParams>,
    /// Statistics.
    stats: SessionStats,
    /// Pending outbound frame.
    pending_send: Option<Vec<u8>>,
}

impl Session {
    /// Create a new session.
    pub fn new(config: SessionConfig) -> Self {
        // Generate random session ID
        let session_id = Self::generate_session_id();

        Self {
            config,
            state: SessionState::Idle,
            session_id,
            map_epoch: 0,
            frame_seq: 0,
            last_hello_sent: None,
            hello_retries: 0,
            last_activity: Instant::now(),
            negotiated: None,
            stats: SessionStats::default(),
            pending_send: None,
        }
    }

    /// Generate a random session ID.
    fn generate_session_id() -> u16 {
        // Use a simple hash of current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        ((now.as_nanos() ^ (now.as_nanos() >> 32)) & 0xFFFF) as u16
    }

    /// Get current state.
    #[inline]
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Check if session is established.
    #[inline]
    pub fn is_established(&self) -> bool {
        self.state == SessionState::Established
    }

    /// Check if session is connecting.
    #[inline]
    pub fn is_connecting(&self) -> bool {
        self.state == SessionState::Connecting
    }

    /// Check if session has failed.
    #[inline]
    pub fn is_failed(&self) -> bool {
        self.state == SessionState::Failed
    }

    /// Get local session ID.
    #[inline]
    pub fn session_id(&self) -> u16 {
        self.session_id
    }

    /// Get negotiated parameters (if established).
    pub fn negotiated(&self) -> Option<&NegotiatedParams> {
        self.negotiated.as_ref()
    }

    /// Get effective MTU.
    pub fn effective_mtu(&self) -> u16 {
        self.negotiated
            .as_ref()
            .map(|n| n.mtu)
            .unwrap_or(self.config.mtu)
    }

    /// Get statistics.
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Start the session (begin handshake).
    ///
    /// # State Transition: Idle → Connecting
    ///
    /// Initiates active open by sending first HELLO. The session enters
    /// Connecting state and remains there until either:
    /// - A HELLO response arrives → Established
    /// - Max retries exceeded → Failed
    pub fn start(&mut self) {
        if self.state != SessionState::Idle {
            return;
        }

        self.state = SessionState::Connecting;
        self.hello_retries = 0;
        self.queue_hello();
    }

    /// Close the session.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        self.negotiated = None;
        self.pending_send = None;
    }

    /// Reset the session to idle state.
    pub fn reset(&mut self) {
        self.state = SessionState::Idle;
        self.session_id = Self::generate_session_id();
        self.map_epoch = 0;
        self.frame_seq = 0;
        self.last_hello_sent = None;
        self.hello_retries = 0;
        self.last_activity = Instant::now();
        self.negotiated = None;
        self.pending_send = None;
    }

    /// Queue a HELLO message for sending.
    ///
    /// # HELLO Message Contents
    ///
    /// The HELLO carries all parameters needed for negotiation:
    /// - `proto_ver`: Protocol version (currently 1)
    /// - `features`: Bitmask of supported features (DELTA, COMPRESSION, FRAG)
    /// - `mtu`: Local maximum transmission unit
    /// - `node_id`: Local node identifier
    /// - `session_id`: Random session ID for this connection
    /// - `map_epoch`: Topic mapping epoch (for mapping sync)
    ///
    /// Wire format: HELLO is wrapped as CONTROL record (stream_id=0) inside a frame.
    fn queue_hello(&mut self) {
        let hello = Hello {
            proto_ver: 1,
            features: self.config.features,
            mtu: self.config.mtu,
            node_id: self.config.node_id,
            session_id: self.session_id,
            map_epoch: self.map_epoch,
        };

        // Encode HELLO as CONTROL record (stream_id=0 is reserved for control)
        let mut ctrl_buf = [0u8; 32];
        #[allow(clippy::expect_used)] // buffer is oversized for HELLO, cannot fail
        let ctrl_len = hello.encode(&mut ctrl_buf).expect("HELLO encode");

        let record_header = RecordHeader::control(0);
        let mut record_buf = [0u8; 64];
        #[allow(clippy::expect_used)] // buffer is oversized for control record, cannot fail
        let record_len =
            encode_record(&record_header, &ctrl_buf[..ctrl_len], &mut record_buf).expect("record");

        // Wrap record in frame with incrementing sequence number
        let frame_header = FrameHeader::new(self.session_id, self.frame_seq);
        self.frame_seq = self.frame_seq.wrapping_add(1);

        let mut frame_buf = [0u8; 128];
        #[allow(clippy::expect_used)] // buffer is oversized for frame, cannot fail
        let frame_len =
            encode_frame(&frame_header, &record_buf[..record_len], &mut frame_buf).expect("frame");

        self.pending_send = Some(frame_buf[..frame_len].to_vec());
        self.last_hello_sent = Some(Instant::now());
        self.stats.hellos_sent += 1;
    }

    /// Poll for a frame to send.
    ///
    /// Returns `Some(frame)` if there's a frame ready to send.
    pub fn poll_send(&mut self) -> Option<Vec<u8>> {
        self.pending_send.take()
    }

    /// Tick the session (call periodically).
    ///
    /// Handles:
    /// - HELLO resend during connecting
    /// - Session timeout
    ///
    /// # Timeout/Retry Behavior
    ///
    /// **Connecting state:**
    /// - Timer fires every `hello_interval` (default 500ms)
    /// - Each timeout increments retry counter and resends HELLO
    /// - After `hello_max_retries` (default 10) → transition to Failed
    /// - Total handshake timeout = hello_interval × hello_max_retries (default 5s)
    ///
    /// **Established state:**
    /// - Monitors `last_activity` timestamp
    /// - If no frames received for `session_timeout` (default 30s) → Failed
    /// - Activity is updated on any received frame, not just HELLO
    pub fn tick(&mut self) {
        let now = Instant::now();

        match self.state {
            SessionState::Connecting => {
                // Retry logic: resend HELLO if interval elapsed
                if let Some(last_sent) = self.last_hello_sent {
                    if now.duration_since(last_sent) >= self.config.hello_interval {
                        self.hello_retries += 1;
                        self.stats.retry_count = self.hello_retries;

                        // Connecting → Failed: max retries exceeded
                        if self.hello_retries >= self.config.hello_max_retries {
                            self.state = SessionState::Failed;
                        } else {
                            self.queue_hello();
                        }
                    }
                }
            }
            SessionState::Established => {
                // Established → Failed: inactivity timeout
                if now.duration_since(self.last_activity) >= self.config.session_timeout {
                    self.state = SessionState::Failed;
                }
            }
            _ => {}
        }
    }

    /// Process a received frame.
    ///
    /// # Arguments
    /// * `data` - Raw frame bytes
    ///
    /// # Returns
    /// * `Ok(())` if processed successfully
    /// * `Err` on parse error
    pub fn on_receive(&mut self, data: &[u8]) -> Result<(), SessionError> {
        use super::frame::decode_frame;
        use super::record::decode_record;

        self.last_activity = Instant::now();
        self.stats.frames_received += 1;

        // Decode frame
        let frame = decode_frame(data).map_err(|e| SessionError::FrameError(format!("{}", e)))?;

        // Decode records
        let mut offset = 0;
        while offset < frame.records.len() {
            let record = decode_record(&frame.records[offset..])
                .map_err(|e| SessionError::RecordError(format!("{}", e)))?;

            offset += record.consumed;

            // Handle CONTROL stream
            if record.header.stream_id == STREAM_CONTROL {
                self.handle_control(record.payload)?;
            }
        }

        Ok(())
    }

    /// Handle a CONTROL message.
    fn handle_control(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        if payload.is_empty() {
            return Err(SessionError::EmptyControl);
        }

        let ctrl_type = payload[0];

        match ctrl_type {
            ctrl_type::HELLO => {
                let (hello, _) = Hello::decode(&payload[1..])
                    .map_err(|e| SessionError::ControlError(format!("{}", e)))?;

                self.handle_hello(hello)?;
            }
            // Other control types will be handled by mapping/reliable modules
            _ => {
                // Ignore unknown control types for now
            }
        }

        Ok(())
    }

    /// Handle a received HELLO message.
    ///
    /// # HELLO Handshake State Transitions
    ///
    /// **Connecting → Established (active open completes):**
    /// Received HELLO is the response to our HELLO. Negotiate params and confirm.
    ///
    /// **Idle → Established (passive open):**
    /// Remote initiated connection. Accept by negotiating params and responding.
    /// Skips Connecting state since we have all info needed to establish.
    ///
    /// **Established → Established (keepalive):**
    /// HELLO received on established session acts as keepalive, resets activity timer.
    ///
    /// # Feature Negotiation
    ///
    /// Features use bitmask intersection: `local_features & remote_features`
    /// - Only features supported by BOTH peers are enabled
    /// - Example: local=DELTA|COMPRESSION, remote=DELTA|FRAG → negotiated=DELTA
    /// - See `features::*` constants for available feature bits
    ///
    /// # MTU Selection
    ///
    /// MTU = `min(local_mtu, remote_mtu)`
    /// - Conservative approach ensures neither peer receives oversized frames
    /// - Both peers will use the same negotiated MTU for fragmentation decisions
    fn handle_hello(&mut self, hello: Hello) -> Result<(), SessionError> {
        self.stats.hellos_received += 1;

        match self.state {
            SessionState::Connecting => {
                // Connecting → Established: active open completes
                // Negotiate: MTU=min, features=intersection (bitwise AND)
                let negotiated = NegotiatedParams {
                    mtu: self.config.mtu.min(hello.mtu),
                    features: self.config.features & hello.features,
                    remote_node_id: hello.node_id,
                    remote_session_id: hello.session_id,
                };

                self.negotiated = Some(negotiated);
                self.state = SessionState::Established;

                // Send confirmation HELLO so peer also transitions to Established
                self.queue_hello();

                Ok(())
            }
            SessionState::Established => {
                // Already established - HELLO serves as keepalive
                // Activity timer already updated in on_receive()
                Ok(())
            }
            SessionState::Idle => {
                // Idle → Established: passive open (remote initiated)
                // Negotiate immediately and respond with our HELLO
                let negotiated = NegotiatedParams {
                    mtu: self.config.mtu.min(hello.mtu),
                    features: self.config.features & hello.features,
                    remote_node_id: hello.node_id,
                    remote_session_id: hello.session_id,
                };

                self.negotiated = Some(negotiated);
                self.state = SessionState::Established;
                self.queue_hello();

                Ok(())
            }
            _ => {
                // Failed/Closed: ignore HELLO, session must be reset() first
                Ok(())
            }
        }
    }
}

/// Session error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// Frame decode error.
    FrameError(String),
    /// Record decode error.
    RecordError(String),
    /// Control message error.
    ControlError(String),
    /// Empty control payload.
    EmptyControl,
    /// Session not established.
    NotEstablished,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameError(e) => write!(f, "frame error: {}", e),
            Self::RecordError(e) => write!(f, "record error: {}", e),
            Self::ControlError(e) => write!(f, "control error: {}", e),
            Self::EmptyControl => write!(f, "empty control payload"),
            Self::NotEstablished => write!(f, "session not established"),
        }
    }
}

impl std::error::Error for SessionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::lowbw::link::{LoopbackLink, LowBwLink, SimLink, SimLinkConfig};

    #[test]
    fn test_session_initial_state() {
        let session = Session::new(SessionConfig::default());
        assert_eq!(session.state(), SessionState::Idle);
        assert!(!session.is_established());
    }

    #[test]
    fn test_session_start() {
        let mut session = Session::new(SessionConfig::default());
        session.start();

        assert_eq!(session.state(), SessionState::Connecting);
        assert!(session.poll_send().is_some()); // Should have HELLO queued
    }

    #[test]
    fn test_session_hello_retry() {
        let config = SessionConfig {
            hello_interval: Duration::from_millis(10),
            hello_max_retries: 3,
            ..Default::default()
        };
        let mut session = Session::new(config);
        session.start();

        // Consume initial HELLO
        let _ = session.poll_send();

        // Wait and tick to trigger retry
        std::thread::sleep(Duration::from_millis(15));
        session.tick();

        assert_eq!(session.state(), SessionState::Connecting);
        assert!(session.poll_send().is_some()); // Should have retransmit
        assert_eq!(session.stats.hellos_sent, 2);
    }

    #[test]
    fn test_session_max_retries() {
        let config = SessionConfig {
            hello_interval: Duration::from_millis(5),
            hello_max_retries: 2,
            ..Default::default()
        };
        let mut session = Session::new(config);
        session.start();

        // Exhaust retries
        for _ in 0..5 {
            let _ = session.poll_send();
            std::thread::sleep(Duration::from_millis(10));
            session.tick();
        }

        assert_eq!(session.state(), SessionState::Failed);
    }

    #[test]
    fn test_session_handshake_loopback() {
        let link = LoopbackLink::new();

        let config = SessionConfig::default();
        let mut session_a = Session::new(config.clone());
        let mut session_b = Session::new(SessionConfig {
            node_id: 1,
            ..config
        });

        // A starts
        session_a.start();

        // A sends HELLO
        if let Some(frame) = session_a.poll_send() {
            link.send(&frame).expect("send");
        }

        // B receives HELLO
        let mut buf = [0u8; 256];
        let n = link.recv(&mut buf).expect("recv");
        session_b.on_receive(&buf[..n]).expect("process");

        // B should be established (passive open)
        assert!(session_b.is_established());

        // B sends response HELLO
        if let Some(frame) = session_b.poll_send() {
            link.send(&frame).expect("send");
        }

        // A receives response
        let n = link.recv(&mut buf).expect("recv");
        session_a.on_receive(&buf[..n]).expect("process");

        // A should be established
        assert!(session_a.is_established());

        // Check negotiated params
        let params_a = session_a.negotiated().expect("negotiated");
        let params_b = session_b.negotiated().expect("negotiated");

        assert_eq!(params_a.mtu, params_b.mtu);
        assert_eq!(params_a.remote_node_id, 1);
        assert_eq!(params_b.remote_node_id, 0);
    }

    #[test]
    fn test_session_mtu_negotiation() {
        let link = LoopbackLink::new();

        let mut session_a = Session::new(SessionConfig {
            mtu: 512,
            ..Default::default()
        });
        let mut session_b = Session::new(SessionConfig {
            node_id: 1,
            mtu: 256,
            ..Default::default()
        });

        // Handshake
        session_a.start();

        if let Some(frame) = session_a.poll_send() {
            link.send(&frame).expect("send");
        }

        let mut buf = [0u8; 256];
        let n = link.recv(&mut buf).expect("recv");
        session_b.on_receive(&buf[..n]).expect("process");

        // Negotiated MTU should be min(512, 256) = 256
        assert_eq!(session_b.effective_mtu(), 256);
    }

    #[test]
    fn test_session_feature_negotiation() {
        let link = LoopbackLink::new();

        let mut session_a = Session::new(SessionConfig {
            features: features::DELTA | features::COMPRESSION,
            ..Default::default()
        });
        let mut session_b = Session::new(SessionConfig {
            node_id: 1,
            features: features::DELTA | features::FRAGMENTATION,
            ..Default::default()
        });

        // Handshake
        session_a.start();

        if let Some(frame) = session_a.poll_send() {
            link.send(&frame).expect("send");
        }

        let mut buf = [0u8; 256];
        let n = link.recv(&mut buf).expect("recv");
        session_b.on_receive(&buf[..n]).expect("process");

        // Negotiated features should be intersection (DELTA only)
        let params = session_b.negotiated().expect("negotiated");
        assert_eq!(params.features, features::DELTA);
    }

    #[test]
    fn test_session_reset() {
        let mut session = Session::new(SessionConfig::default());
        session.start();
        let _ = session.poll_send();

        session.reset();

        assert_eq!(session.state(), SessionState::Idle);
        assert!(session.negotiated().is_none());
    }

    #[test]
    fn test_session_close() {
        let mut session = Session::new(SessionConfig::default());
        session.start();

        session.close();

        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_under_loss() {
        // Test that session can establish under packet loss
        // With 30% loss both ways, we need many retries
        let config = SimLinkConfig {
            loss_rate: 0.30, // 30% loss
            ..Default::default()
        };
        let link_a_to_b = SimLink::new(config.clone());
        let link_b_to_a = SimLink::new(config);

        // Use deterministic seeds for reproducibility
        link_a_to_b.set_seed(42424242);
        link_b_to_a.set_seed(12121212);

        let session_config = SessionConfig {
            hello_interval: Duration::from_millis(10), // Fast retries
            hello_max_retries: 50,                     // Many retries to handle 30% loss
            ..Default::default()
        };

        let mut session_a = Session::new(session_config.clone());
        let mut session_b = Session::new(SessionConfig {
            node_id: 1,
            ..session_config
        });

        // B also starts (simultaneous open) for more robust connection
        session_a.start();
        session_b.start();

        let mut buf = [0u8; 256];
        let deadline = Instant::now() + Duration::from_secs(3);

        while Instant::now() < deadline {
            // A tick and maybe send
            session_a.tick();
            if let Some(frame) = session_a.poll_send() {
                let _ = link_a_to_b.send(&frame);
            }

            // B tick and maybe send
            session_b.tick();
            if let Some(frame) = session_b.poll_send() {
                let _ = link_b_to_a.send(&frame);
            }

            // B receive and process all available frames
            while let Ok(n) = link_a_to_b.recv(&mut buf) {
                let _ = session_b.on_receive(&buf[..n]);
            }

            // A receive and process all available frames
            while let Ok(n) = link_b_to_a.recv(&mut buf) {
                let _ = session_a.on_receive(&buf[..n]);
            }

            if session_a.is_established() && session_b.is_established() {
                break;
            }

            std::thread::sleep(Duration::from_millis(2));
        }

        // Both should be established despite loss
        assert!(
            session_a.is_established(),
            "Session A should be established (sent {} HELLOs)",
            session_a.stats.hellos_sent
        );
        assert!(
            session_b.is_established(),
            "Session B should be established (sent {} HELLOs)",
            session_b.stats.hellos_sent
        );

        // Should have needed retries (with 30% loss, expect several attempts)
        let total_hellos = session_a.stats.hellos_sent + session_b.stats.hellos_sent;
        assert!(
            total_hellos > 2,
            "Should have retried HELLOs (total: {})",
            total_hellos
        );
    }
}

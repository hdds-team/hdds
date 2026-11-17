// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TCP connection management with state machine.
//!
//! Provides the [`TcpConnection`] type which wraps a TCP stream with:
//! - Connection state machine (Connecting -> Connected -> Closing -> Closed)
//! - Frame codec for length-prefix framing
//! - Send queue with backpressure handling
//! - Statistics tracking
//!
//! # State Machine
//!
//! ```text
//!      +----------+
//!      |   Idle   |
//!      +----+-----+
//!           | connect() or accept()
//!           v
//!      +----------+
//!      |Connecting|--(timeout)--> Failed
//!      +----+-----+
//!           | connected
//!           v
//!      +----------+
//!      |Connected |--(error/EOF)--> Reconnecting
//!      +----+-----+                      |
//!           | close()                    | (retry)
//!           v                            |
//!      +----------+                      |
//!      | Closing  |<---------------------+
//!      +----+-----+
//!           | closed
//!           v
//!      +----------+
//!      |  Closed  |
//!      +----------+
//! ```

use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::byte_stream::ByteStream;
use super::frame_codec::FrameCodec;
use super::TcpConfig;

// ============================================================================
// Connection State
// ============================================================================

/// Connection state machine states.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// Initial state, no connection attempt made
    #[default]
    Idle,

    /// Connection in progress (non-blocking connect)
    Connecting,

    /// Connection established and operational
    Connected,

    /// Connection lost, attempting to reconnect
    Reconnecting,

    /// Graceful shutdown in progress
    Closing,

    /// Connection terminated
    Closed,

    /// Connection failed (terminal state)
    Failed,
}

impl ConnectionState {
    /// Check if the connection can send/receive data.
    pub fn is_operational(&self) -> bool {
        matches!(self, ConnectionState::Connected)
    }

    /// Check if the connection is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ConnectionState::Closed | ConnectionState::Failed)
    }

    /// Check if the connection is being established.
    pub fn is_connecting(&self) -> bool {
        matches!(
            self,
            ConnectionState::Idle | ConnectionState::Connecting | ConnectionState::Reconnecting
        )
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ConnectionState::Idle => "Idle",
            ConnectionState::Connecting => "Connecting",
            ConnectionState::Connected => "Connected",
            ConnectionState::Reconnecting => "Reconnecting",
            ConnectionState::Closing => "Closing",
            ConnectionState::Closed => "Closed",
            ConnectionState::Failed => "Failed",
        };
        write!(f, "{}", s)
    }
}

// ============================================================================
// Flush Result
// ============================================================================

/// Result of a flush operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushResult {
    /// All queued data was sent
    Complete,

    /// Some data remains in the queue (would block)
    WouldBlock,

    /// Queue is empty, nothing to flush
    Empty,
}

// ============================================================================
// Connection Statistics
// ============================================================================

/// Statistics for a TCP connection.
#[derive(Clone, Debug, Default)]
pub struct TcpConnectionStats {
    /// Messages successfully sent
    pub messages_sent: u64,

    /// Messages successfully received
    pub messages_received: u64,

    /// Total bytes sent (including framing)
    pub bytes_sent: u64,

    /// Total bytes received (including framing)
    pub bytes_received: u64,

    /// Send queue depth (messages waiting)
    pub send_queue_depth: usize,

    /// Send queue bytes (total size waiting)
    pub send_queue_bytes: usize,

    /// Number of partial sends (backpressure events)
    pub partial_sends: u64,

    /// Number of reconnection attempts
    pub reconnect_attempts: u64,

    /// Time of last successful send
    pub last_send_time: Option<Instant>,

    /// Time of last successful receive
    pub last_recv_time: Option<Instant>,
}

// ============================================================================
// TCP Connection
// ============================================================================

/// A TCP connection to a remote participant.
///
/// Wraps a [`ByteStream`] with framing codec, send queue, and state tracking.
pub struct TcpConnection {
    /// Underlying byte stream (TCP or TLS)
    stream: Box<dyn ByteStream>,

    /// Frame codec for length-prefix framing
    codec: FrameCodec,

    /// Remote socket address
    remote_addr: SocketAddr,

    /// Local socket address
    local_addr: SocketAddr,

    /// Whether we initiated this connection
    is_initiator: bool,

    /// Current connection state
    state: ConnectionState,

    /// Send queue (framed messages ready to send)
    send_queue: VecDeque<Vec<u8>>,

    /// Partial send in progress (buffer, offset)
    pending_send: Option<(Vec<u8>, usize)>,

    /// Connection statistics
    stats: TcpConnectionStats,

    /// Time connection was established
    connected_at: Option<Instant>,

    /// Time of last state change
    state_changed_at: Instant,

    /// Connection timeout
    connect_timeout: Duration,

    /// Reconnection attempts counter
    reconnect_count: u32,

    /// Maximum reconnection attempts
    max_reconnect_attempts: u32,
}

impl TcpConnection {
    /// Create a new TCP connection from an established stream.
    ///
    /// # Arguments
    ///
    /// * `stream` - The connected byte stream
    /// * `remote_addr` - Remote peer address
    /// * `is_initiator` - Whether we initiated this connection
    /// * `config` - TCP configuration
    pub fn new(
        stream: Box<dyn ByteStream>,
        remote_addr: SocketAddr,
        is_initiator: bool,
        config: &TcpConfig,
    ) -> io::Result<Self> {
        let local_addr = stream.local_addr()?;

        // Configure stream
        stream.set_nonblocking(true)?;
        if config.nodelay {
            stream.set_nodelay(true)?;
        }

        let codec = FrameCodec::new(config.max_message_size);

        Ok(Self {
            stream,
            codec,
            remote_addr,
            local_addr,
            is_initiator,
            state: ConnectionState::Connected,
            send_queue: VecDeque::new(),
            pending_send: None,
            stats: TcpConnectionStats::default(),
            connected_at: Some(Instant::now()),
            state_changed_at: Instant::now(),
            connect_timeout: config.connect_timeout,
            reconnect_count: 0,
            max_reconnect_attempts: config.max_reconnect_attempts,
        })
    }

    /// Create a connection in Connecting state (for non-blocking connect).
    pub fn connecting(
        stream: Box<dyn ByteStream>,
        remote_addr: SocketAddr,
        config: &TcpConfig,
    ) -> io::Result<Self> {
        let local_addr = stream.local_addr()?;

        stream.set_nonblocking(true)?;
        if config.nodelay {
            let _ = stream.set_nodelay(true);
        }

        let codec = FrameCodec::new(config.max_message_size);

        Ok(Self {
            stream,
            codec,
            remote_addr,
            local_addr,
            is_initiator: true,
            state: ConnectionState::Connecting,
            send_queue: VecDeque::new(),
            pending_send: None,
            stats: TcpConnectionStats::default(),
            connected_at: None,
            state_changed_at: Instant::now(),
            connect_timeout: config.connect_timeout,
            reconnect_count: 0,
            max_reconnect_attempts: config.max_reconnect_attempts,
        })
    }

    // ========================================================================
    // Getters
    // ========================================================================

    /// Get the remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Check if we initiated this connection.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Get the current connection state.
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if the connection is operational (can send/receive).
    pub fn is_connected(&self) -> bool {
        self.state.is_operational()
    }

    /// Get connection statistics.
    pub fn stats(&self) -> &TcpConnectionStats {
        &self.stats
    }

    /// Get mutable reference to statistics (for external updates).
    pub fn stats_mut(&mut self) -> &mut TcpConnectionStats {
        &mut self.stats
    }

    /// Get time since connection was established.
    pub fn uptime(&self) -> Option<Duration> {
        self.connected_at.map(|t| t.elapsed())
    }

    /// Get time since last state change.
    pub fn time_in_state(&self) -> Duration {
        self.state_changed_at.elapsed()
    }

    /// Check if connection has timed out (in Connecting state).
    pub fn is_connect_timeout(&self) -> bool {
        self.state == ConnectionState::Connecting
            && self.state_changed_at.elapsed() > self.connect_timeout
    }

    /// Get number of messages in send queue.
    pub fn send_queue_len(&self) -> usize {
        self.send_queue.len()
    }

    /// Check if send queue is empty.
    pub fn send_queue_is_empty(&self) -> bool {
        self.send_queue.is_empty() && self.pending_send.is_none()
    }

    /// Get the underlying stream (for mio registration).
    pub fn stream(&self) -> &dyn ByteStream {
        &*self.stream
    }

    /// Get mutable reference to the stream.
    pub fn stream_mut(&mut self) -> &mut dyn ByteStream {
        &mut *self.stream
    }

    // ========================================================================
    // State transitions
    // ========================================================================

    /// Transition to a new state.
    fn set_state(&mut self, new_state: ConnectionState) {
        if self.state != new_state {
            self.state = new_state;
            self.state_changed_at = Instant::now();
        }
    }

    /// Mark connection as connected (after non-blocking connect completes).
    pub fn mark_connected(&mut self) {
        self.set_state(ConnectionState::Connected);
        self.connected_at = Some(Instant::now());
    }

    /// Handle connection error and transition to appropriate state.
    pub fn handle_error(&mut self, _error: &io::Error) {
        match self.state {
            ConnectionState::Connecting => {
                if self.reconnect_count < self.max_reconnect_attempts {
                    self.set_state(ConnectionState::Reconnecting);
                    self.reconnect_count += 1;
                    self.stats.reconnect_attempts += 1;
                } else {
                    self.set_state(ConnectionState::Failed);
                }
            }
            ConnectionState::Connected => {
                if self.max_reconnect_attempts > 0
                    && self.reconnect_count < self.max_reconnect_attempts
                {
                    self.set_state(ConnectionState::Reconnecting);
                    self.reconnect_count += 1;
                    self.stats.reconnect_attempts += 1;
                } else {
                    self.set_state(ConnectionState::Failed);
                }
            }
            ConnectionState::Reconnecting => {
                if self.reconnect_count < self.max_reconnect_attempts {
                    self.reconnect_count += 1;
                    self.stats.reconnect_attempts += 1;
                } else {
                    self.set_state(ConnectionState::Failed);
                }
            }
            _ => {
                self.set_state(ConnectionState::Failed);
            }
        }
    }

    /// Initiate graceful close.
    pub fn close(&mut self) {
        if !self.state.is_terminal() {
            self.set_state(ConnectionState::Closing);
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            self.set_state(ConnectionState::Closed);
        }
    }

    // ========================================================================
    // Send operations
    // ========================================================================

    /// Queue a message for sending.
    ///
    /// The message will be framed and added to the send queue.
    /// Call `flush` to actually send queued data.
    pub fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        if !self.state.is_operational() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("connection not ready: {}", self.state),
            ));
        }

        let frame = FrameCodec::encode(payload)?;
        self.stats.send_queue_bytes += frame.len();
        self.send_queue.push_back(frame);
        self.stats.send_queue_depth = self.send_queue.len();

        Ok(())
    }

    /// Flush the send queue, writing data to the socket.
    ///
    /// Returns:
    /// - `Complete` - All data was sent
    /// - `WouldBlock` - Socket buffer full, call again when writable
    /// - `Empty` - No data to send
    pub fn flush(&mut self) -> io::Result<FlushResult> {
        if !self.state.is_operational() {
            return Ok(FlushResult::Empty);
        }

        // Handle partial send from previous flush
        if let Some((ref buf, ref mut offset)) = self.pending_send {
            match self.stream.write(&buf[*offset..]) {
                Ok(0) => {
                    // Connection closed
                    let err = io::Error::new(io::ErrorKind::WriteZero, "connection closed");
                    self.handle_error(&err);
                    return Err(err);
                }
                Ok(n) => {
                    self.stats.bytes_sent += n as u64;
                    *offset += n;

                    if *offset >= buf.len() {
                        // Partial send complete
                        self.pending_send = None;
                        self.stats.messages_sent += 1;
                        self.stats.last_send_time = Some(Instant::now());
                    } else {
                        // Still more to send
                        self.stats.partial_sends += 1;
                        return Ok(FlushResult::WouldBlock);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(FlushResult::WouldBlock);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    // Retry
                    return self.flush();
                }
                Err(e) => {
                    self.handle_error(&e);
                    return Err(e);
                }
            }
        }

        // Send queued messages
        while let Some(frame) = self.send_queue.pop_front() {
            self.stats.send_queue_depth = self.send_queue.len();
            self.stats.send_queue_bytes = self.stats.send_queue_bytes.saturating_sub(frame.len());

            match self.stream.write(&frame) {
                Ok(0) => {
                    let err = io::Error::new(io::ErrorKind::WriteZero, "connection closed");
                    self.handle_error(&err);
                    return Err(err);
                }
                Ok(n) if n == frame.len() => {
                    // Complete send
                    self.stats.bytes_sent += n as u64;
                    self.stats.messages_sent += 1;
                    self.stats.last_send_time = Some(Instant::now());
                }
                Ok(n) => {
                    // Partial send
                    self.stats.bytes_sent += n as u64;
                    self.stats.partial_sends += 1;
                    self.pending_send = Some((frame, n));
                    return Ok(FlushResult::WouldBlock);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Put frame back
                    self.send_queue.push_front(frame);
                    self.stats.send_queue_depth = self.send_queue.len();
                    return Ok(FlushResult::WouldBlock);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    // Put frame back and retry
                    self.send_queue.push_front(frame);
                    return self.flush();
                }
                Err(e) => {
                    self.handle_error(&e);
                    return Err(e);
                }
            }
        }

        // Flush underlying stream
        let _ = self.stream.flush();

        Ok(FlushResult::Complete)
    }

    // ========================================================================
    // Receive operations
    // ========================================================================

    /// Try to receive a message.
    ///
    /// Returns:
    /// - `Ok(Some(data))` - A complete message was received
    /// - `Ok(None)` - No complete message available (would block)
    /// - `Err(e)` - I/O or protocol error
    pub fn recv(&mut self) -> io::Result<Option<Vec<u8>>> {
        if !self.state.is_operational() {
            return Ok(None);
        }

        match self.codec.decode(&mut *self.stream) {
            Ok(Some(data)) => {
                self.stats.messages_received += 1;
                self.stats.bytes_received += (4 + data.len()) as u64; // Include header
                self.stats.last_recv_time = Some(Instant::now());
                Ok(Some(data))
            }
            Ok(None) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Connection closed gracefully
                self.set_state(ConnectionState::Closed);
                Ok(None)
            }
            Err(e) => {
                self.handle_error(&e);
                Err(e)
            }
        }
    }

    /// Receive all available messages (non-blocking).
    ///
    /// Continues reading until WouldBlock or error.
    pub fn recv_all(&mut self) -> io::Result<Vec<Vec<u8>>> {
        let mut messages = Vec::new();

        loop {
            match self.recv() {
                Ok(Some(msg)) => messages.push(msg),
                Ok(None) => break,
                Err(e) => {
                    if messages.is_empty() {
                        return Err(e);
                    }
                    // Return what we have
                    break;
                }
            }
        }

        Ok(messages)
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    /// Reset the frame codec (e.g., after reconnection).
    pub fn reset_codec(&mut self) {
        self.codec.reset();
    }

    /// Clear the send queue.
    pub fn clear_send_queue(&mut self) {
        self.send_queue.clear();
        self.pending_send = None;
        self.stats.send_queue_depth = 0;
        self.stats.send_queue_bytes = 0;
    }

    /// Take a socket error if any.
    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.stream.take_error()
    }

    /// Update stream after reconnection.
    pub fn update_stream(
        &mut self,
        stream: Box<dyn ByteStream>,
        config: &TcpConfig,
    ) -> io::Result<()> {
        self.local_addr = stream.local_addr()?;

        stream.set_nonblocking(true)?;
        if config.nodelay {
            stream.set_nodelay(true)?;
        }

        self.stream = stream;
        self.codec.reset();
        self.mark_connected();

        Ok(())
    }
}

impl std::fmt::Debug for TcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConnection")
            .field("remote_addr", &self.remote_addr)
            .field("local_addr", &self.local_addr)
            .field("state", &self.state)
            .field("is_initiator", &self.is_initiator)
            .field("send_queue_len", &self.send_queue.len())
            .field("messages_sent", &self.stats.messages_sent)
            .field("messages_received", &self.stats.messages_received)
            .finish()
    }
}

// ============================================================================
// Tie-breaker logic
// ============================================================================

/// Determine which connection to keep when both peers connect simultaneously.
///
/// The peer with the "smaller" GUID prefix is the "server" (acceptor).
/// We keep the connection where the smaller GUID is the acceptor.
///
/// # Arguments
///
/// * `local_guid_prefix` - Our GUID prefix bytes
/// * `remote_guid_prefix` - Remote peer's GUID prefix bytes
/// * `is_initiator` - Whether we initiated this connection
///
/// # Returns
///
/// `true` if this connection should be kept, `false` if it should be closed.
pub fn should_keep_connection(
    local_guid_prefix: &[u8; 12],
    remote_guid_prefix: &[u8; 12],
    is_initiator: bool,
) -> bool {
    // Compare GUID prefixes lexicographically
    let local_is_smaller = local_guid_prefix < remote_guid_prefix;

    // Rule: the "smaller" GUID is the server (acceptor)
    // Keep the connection where the smaller GUID accepted
    if local_is_smaller {
        !is_initiator // Keep if we accepted (we're the server)
    } else {
        is_initiator // Keep if we initiated (they're the server)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "connection_test.rs"]
mod tests;

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QUIC connection management.
//!
//! v234: Added event routing, TLS cert pinning, tokio-native async.
//! v234-sprint3: Long-lived send stream per connection (stream pooling).

use super::{QuicError, QuicResult};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[cfg(feature = "quic")]
use tokio::sync::Mutex as TokioMutex;

/// State of a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicConnectionState {
    /// Connection is being established.
    Connecting,
    /// Connection is established and ready.
    Connected,
    /// Connection is draining (graceful close in progress).
    Draining,
    /// Connection is closed.
    Closed,
}

impl std::fmt::Display for QuicConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicConnectionState::Connecting => write!(f, "Connecting"),
            QuicConnectionState::Connected => write!(f, "Connected"),
            QuicConnectionState::Draining => write!(f, "Draining"),
            QuicConnectionState::Closed => write!(f, "Closed"),
        }
    }
}

/// Statistics for a QUIC connection.
#[derive(Debug, Default)]
pub struct QuicConnectionStats {
    /// Total bytes sent.
    pub bytes_sent: AtomicU64,
    /// Total bytes received.
    pub bytes_received: AtomicU64,
    /// Total streams opened.
    pub streams_opened: AtomicU64,
    /// Total streams closed.
    pub streams_closed: AtomicU64,
    /// Number of connection migrations.
    pub migrations: AtomicU64,
    /// Round-trip time estimate (microseconds).
    pub rtt_us: AtomicU64,
    /// Messages sent counter.
    pub messages_sent: AtomicU64,
    /// Messages received counter.
    pub messages_received: AtomicU64,
}

impl QuicConnectionStats {
    /// Create new stats.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record bytes sent.
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record bytes received.
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record stream opened.
    pub fn stream_opened(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
    }

    /// Record stream closed.
    pub fn stream_closed(&self) {
        self.streams_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection migration.
    pub fn migration(&self) {
        self.migrations.fetch_add(1, Ordering::Relaxed);
    }

    /// Update RTT estimate.
    pub fn set_rtt(&self, rtt_us: u64) {
        self.rtt_us.store(rtt_us, Ordering::Relaxed);
    }

    /// Get current RTT in microseconds.
    pub fn get_rtt_us(&self) -> u64 {
        self.rtt_us.load(Ordering::Relaxed)
    }

    /// Record message sent.
    pub fn message_sent(&self) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record message received.
    pub fn message_received(&self) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }
}

/// Maximum RTPS message size over QUIC (16 MB, same as TCP FrameCodec).
pub const MAX_QUIC_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// Wrapper around a QUIC connection.
///
/// v234-sprint3: Uses a long-lived send stream instead of opening a new
/// unidirectional stream per message. The stream is lazily opened on first
/// send and reused for all subsequent messages on this connection.
///
/// Wire format: same as TCP — `[u32 BE length][payload]` per message,
/// concatenated on the same stream. This is identical to the FrameCodec
/// used by the TCP transport, enabling the same framing logic on the
/// receive side.
///
/// ```text
/// Long-lived uni-stream:
/// ┌──────┬─────────┬──────┬─────────┬──────┬─────────┬───
/// │ len1 │ msg1    │ len2 │ msg2    │ len3 │ msg3    │ ...
/// └──────┴─────────┴──────┴─────────┴──────┴─────────┴───
/// ```
pub struct QuicConnection {
    /// Remote peer address.
    remote_addr: SocketAddr,
    /// Connection state.
    state: QuicConnectionState,
    /// Connection statistics.
    stats: Arc<QuicConnectionStats>,
    /// When connection was established.
    connected_at: Option<Instant>,
    /// Underlying quinn connection (when connected).
    #[cfg(feature = "quic")]
    inner: Option<quinn::Connection>,
    /// v234-sprint3: Persistent send stream (lazily opened).
    /// Wrapped in TokioMutex for exclusive write access across tasks.
    #[cfg(feature = "quic")]
    send_stream: Arc<TokioMutex<Option<quinn::SendStream>>>,
}

impl QuicConnection {
    /// Create a new connection in Connecting state.
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            state: QuicConnectionState::Connecting,
            stats: Arc::new(QuicConnectionStats::new()),
            connected_at: None,
            #[cfg(feature = "quic")]
            inner: None,
            #[cfg(feature = "quic")]
            send_stream: Arc::new(TokioMutex::new(None)),
        }
    }

    /// Create a connected connection from quinn::Connection.
    #[cfg(feature = "quic")]
    pub fn from_quinn(conn: quinn::Connection, remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            state: QuicConnectionState::Connected,
            stats: Arc::new(QuicConnectionStats::new()),
            connected_at: Some(Instant::now()),
            inner: Some(conn),
            send_stream: Arc::new(TokioMutex::new(None)),
        }
    }

    /// Get remote address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get connection state.
    pub fn state(&self) -> QuicConnectionState {
        self.state
    }

    /// Check if connection is ready for data transfer.
    pub fn is_connected(&self) -> bool {
        self.state == QuicConnectionState::Connected
    }

    /// Get connection statistics.
    pub fn stats(&self) -> Arc<QuicConnectionStats> {
        Arc::clone(&self.stats)
    }

    /// Get underlying quinn connection.
    #[cfg(feature = "quic")]
    pub fn inner(&self) -> Option<&quinn::Connection> {
        self.inner.as_ref()
    }

    /// v234-sprint3: Send data on the persistent send stream.
    ///
    /// Lazily opens a unidirectional stream on first call, then reuses it
    /// for all subsequent messages. If the stream is broken (peer reset,
    /// connection migration), a new stream is transparently opened.
    ///
    /// Wire format: `[u32 BE length][payload]` — same as TCP FrameCodec.
    #[cfg(feature = "quic")]
    pub async fn send(&self, data: &[u8]) -> QuicResult<()> {
        let conn = self.inner.as_ref().ok_or(QuicError::ConnectionClosed)?;

        let mut stream_guard = self.send_stream.lock().await;

        // Try to send on existing stream, or open a new one
        let result = if let Some(ref mut stream) = *stream_guard {
            Self::write_framed(stream, data).await
        } else {
            Err(QuicError::StreamFailed("No stream".to_string()))
        };

        match result {
            Ok(()) => {
                self.stats.add_bytes_sent((4 + data.len()) as u64);
                self.stats.message_sent();
                Ok(())
            }
            Err(_) => {
                // Stream broken or not yet opened — open a fresh one
                log::debug!("[QUIC] Opening new send stream to {}", self.remote_addr);

                let mut new_stream = conn
                    .open_uni()
                    .await
                    .map_err(|e| QuicError::StreamFailed(e.to_string()))?;

                self.stats.stream_opened();

                // Write on the new stream
                Self::write_framed(&mut new_stream, data).await?;

                self.stats.add_bytes_sent((4 + data.len()) as u64);
                self.stats.message_sent();

                // Store for reuse
                *stream_guard = Some(new_stream);

                Ok(())
            }
        }
    }

    /// Write a length-prefixed message to a stream.
    #[cfg(feature = "quic")]
    async fn write_framed(stream: &mut quinn::SendStream, data: &[u8]) -> QuicResult<()> {
        let len = data.len() as u32;

        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| QuicError::SendFailed(e.to_string()))?;

        stream
            .write_all(data)
            .await
            .map_err(|e| QuicError::SendFailed(e.to_string()))?;

        Ok(())
    }

    /// Close the connection gracefully.
    #[cfg(feature = "quic")]
    pub fn close(&mut self) {
        // The send_stream will be dropped when the mutex guard is released,
        // which triggers a QUIC RESET_STREAM. For graceful close, we'd
        // need to finish() the stream first, but that requires async.
        // The connection close below handles it at the transport level.
        if let Some(ref conn) = self.inner {
            conn.close(0u32.into(), b"bye");
        }
        self.state = QuicConnectionState::Closed;
    }

    /// Update RTT from connection stats.
    #[cfg(feature = "quic")]
    pub fn update_rtt(&self) {
        if let Some(ref conn) = self.inner {
            let rtt = conn.rtt();
            self.stats.set_rtt(rtt.as_micros() as u64);
        }
    }
}

impl std::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnection")
            .field("remote_addr", &self.remote_addr)
            .field("state", &self.state)
            .field("connected_at", &self.connected_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_display() {
        assert_eq!(QuicConnectionState::Connecting.to_string(), "Connecting");
        assert_eq!(QuicConnectionState::Connected.to_string(), "Connected");
        assert_eq!(QuicConnectionState::Draining.to_string(), "Draining");
        assert_eq!(QuicConnectionState::Closed.to_string(), "Closed");
    }

    #[test]
    fn test_connection_stats() {
        let stats = QuicConnectionStats::new();
        stats.add_bytes_sent(100);
        stats.add_bytes_received(200);
        stats.stream_opened();
        stats.stream_opened();
        stats.stream_closed();
        stats.set_rtt(5000);
        stats.message_sent();
        stats.message_received();

        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 100);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 200);
        assert_eq!(stats.streams_opened.load(Ordering::Relaxed), 2);
        assert_eq!(stats.streams_closed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.get_rtt_us(), 5000);
        assert_eq!(stats.messages_sent.load(Ordering::Relaxed), 1);
        assert_eq!(stats.messages_received.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_connection_new() {
        let addr: SocketAddr = "127.0.0.1:7400".parse().unwrap();
        let conn = QuicConnection::new(addr);

        assert_eq!(conn.remote_addr(), addr);
        assert_eq!(conn.state(), QuicConnectionState::Connecting);
        assert!(!conn.is_connected());
    }

    #[test]
    fn test_max_message_size() {
        assert_eq!(MAX_QUIC_MESSAGE_SIZE, 16 * 1024 * 1024);
    }
}

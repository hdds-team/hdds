// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TCP transport metrics.
//!
//! Provides metrics collection for monitoring TCP transport health:
//! - Connection statistics (established, failed, active)
//! - Message throughput (sent, received)
//! - Byte throughput
//! - Error counts
//!
//! # Example
//!
//! ```
//! use hdds::transport::tcp::{TcpTransportMetrics, TcpConnectionMetrics};
//!
//! let metrics = TcpTransportMetrics::new();
//! metrics.record_connection_established();
//! metrics.record_message_sent(1024);
//!
//! let snapshot = metrics.snapshot();
//! assert_eq!(snapshot.connections_established, 1);
//! ```

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

// ============================================================================
// Transport-level metrics
// ============================================================================

/// Metrics for the entire TCP transport.
#[derive(Debug)]
pub struct TcpTransportMetrics {
    // Connection metrics
    /// Number of currently active connections
    active_connections: AtomicUsize,

    /// Total connections successfully established
    connections_established: AtomicU64,

    /// Total connection attempts that failed
    connections_failed: AtomicU64,

    /// Number of reconnection attempts
    reconnections: AtomicU64,

    // Message metrics
    /// Total messages sent
    messages_sent: AtomicU64,

    /// Total messages received
    messages_received: AtomicU64,

    // Byte metrics
    /// Total bytes sent (including framing)
    bytes_sent: AtomicU64,

    /// Total bytes received (including framing)
    bytes_received: AtomicU64,

    // Error metrics
    /// Framing errors (invalid length, oversized, etc.)
    framing_errors: AtomicU64,

    /// Send errors (connection reset, broken pipe, etc.)
    send_errors: AtomicU64,

    /// Receive errors
    recv_errors: AtomicU64,

    // Backpressure metrics
    /// Number of times send would have blocked
    send_blocked_count: AtomicU64,

    /// Total bytes pending in send queues (approximate)
    send_queue_bytes: AtomicU64,

    // Timestamp
    /// When metrics collection started
    start_time: Instant,
}

impl TcpTransportMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            connections_established: AtomicU64::new(0),
            connections_failed: AtomicU64::new(0),
            reconnections: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            framing_errors: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            send_blocked_count: AtomicU64::new(0),
            send_queue_bytes: AtomicU64::new(0),
            start_time: Instant::now(),
        }
    }

    // ========================================================================
    // Connection recording
    // ========================================================================

    /// Record a new connection established.
    pub fn record_connection_established(&self) {
        self.connections_established.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection closed.
    pub fn record_connection_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a connection failure.
    pub fn record_connection_failed(&self) {
        self.connections_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a reconnection attempt.
    pub fn record_reconnection(&self) {
        self.reconnections.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Message recording
    // ========================================================================

    /// Record a message sent.
    pub fn record_message_sent(&self, bytes: usize) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a message received.
    pub fn record_message_received(&self, bytes: usize) {
        self.messages_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record bytes sent (without message count).
    pub fn record_bytes_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record bytes received (without message count).
    pub fn record_bytes_received(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    // ========================================================================
    // Error recording
    // ========================================================================

    /// Record a framing error.
    pub fn record_framing_error(&self) {
        self.framing_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a send error.
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a receive error.
    pub fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Backpressure recording
    // ========================================================================

    /// Record a send blocked event.
    pub fn record_send_blocked(&self) {
        self.send_blocked_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Update send queue bytes (set, not add).
    pub fn set_send_queue_bytes(&self, bytes: u64) {
        self.send_queue_bytes.store(bytes, Ordering::Relaxed);
    }

    // ========================================================================
    // Getters
    // ========================================================================

    /// Get number of active connections.
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get total connections established.
    pub fn connections_established(&self) -> u64 {
        self.connections_established.load(Ordering::Relaxed)
    }

    /// Get total connection failures.
    pub fn connections_failed(&self) -> u64 {
        self.connections_failed.load(Ordering::Relaxed)
    }

    /// Get total messages sent.
    pub fn messages_sent(&self) -> u64 {
        self.messages_sent.load(Ordering::Relaxed)
    }

    /// Get total messages received.
    pub fn messages_received(&self) -> u64 {
        self.messages_received.load(Ordering::Relaxed)
    }

    /// Get uptime (time since metrics collection started).
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    // ========================================================================
    // Snapshot
    // ========================================================================

    /// Take a snapshot of all metrics.
    pub fn snapshot(&self) -> TcpTransportMetricsSnapshot {
        TcpTransportMetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            connections_established: self.connections_established.load(Ordering::Relaxed),
            connections_failed: self.connections_failed.load(Ordering::Relaxed),
            reconnections: self.reconnections.load(Ordering::Relaxed),
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            messages_received: self.messages_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            framing_errors: self.framing_errors.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            send_blocked_count: self.send_blocked_count.load(Ordering::Relaxed),
            send_queue_bytes: self.send_queue_bytes.load(Ordering::Relaxed),
            uptime_secs: self.start_time.elapsed().as_secs_f64(),
        }
    }

    /// Reset all metrics.
    pub fn reset(&self) {
        self.active_connections.store(0, Ordering::Relaxed);
        self.connections_established.store(0, Ordering::Relaxed);
        self.connections_failed.store(0, Ordering::Relaxed);
        self.reconnections.store(0, Ordering::Relaxed);
        self.messages_sent.store(0, Ordering::Relaxed);
        self.messages_received.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.framing_errors.store(0, Ordering::Relaxed);
        self.send_errors.store(0, Ordering::Relaxed);
        self.recv_errors.store(0, Ordering::Relaxed);
        self.send_blocked_count.store(0, Ordering::Relaxed);
        self.send_queue_bytes.store(0, Ordering::Relaxed);
    }
}

impl Default for TcpTransportMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of TCP transport metrics.
#[derive(Clone, Debug, Default)]
pub struct TcpTransportMetricsSnapshot {
    /// Number of active connections
    pub active_connections: usize,

    /// Total connections established
    pub connections_established: u64,

    /// Total connection failures
    pub connections_failed: u64,

    /// Total reconnection attempts
    pub reconnections: u64,

    /// Total messages sent
    pub messages_sent: u64,

    /// Total messages received
    pub messages_received: u64,

    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Framing errors
    pub framing_errors: u64,

    /// Send errors
    pub send_errors: u64,

    /// Receive errors
    pub recv_errors: u64,

    /// Send blocked count
    pub send_blocked_count: u64,

    /// Send queue bytes
    pub send_queue_bytes: u64,

    /// Uptime in seconds
    pub uptime_secs: f64,
}

impl TcpTransportMetricsSnapshot {
    /// Calculate message rate (messages/second).
    pub fn message_rate(&self) -> f64 {
        if self.uptime_secs > 0.0 {
            (self.messages_sent + self.messages_received) as f64 / self.uptime_secs
        } else {
            0.0
        }
    }

    /// Calculate byte rate (bytes/second).
    pub fn byte_rate(&self) -> f64 {
        if self.uptime_secs > 0.0 {
            (self.bytes_sent + self.bytes_received) as f64 / self.uptime_secs
        } else {
            0.0
        }
    }

    /// Calculate connection success rate.
    pub fn connection_success_rate(&self) -> f64 {
        let total = self.connections_established + self.connections_failed;
        if total > 0 {
            self.connections_established as f64 / total as f64
        } else {
            1.0 // No attempts, consider 100%
        }
    }
}

// ============================================================================
// Connection-level metrics
// ============================================================================

/// Metrics for a single TCP connection.
#[derive(Clone, Debug, Default)]
pub struct TcpConnectionMetrics {
    /// Messages sent on this connection
    pub messages_sent: u64,

    /// Messages received on this connection
    pub messages_received: u64,

    /// Bytes sent (including framing)
    pub bytes_sent: u64,

    /// Bytes received (including framing)
    pub bytes_received: u64,

    /// Current send queue depth (messages)
    pub send_queue_depth: usize,

    /// Current send queue size (bytes)
    pub send_queue_bytes: usize,

    /// Number of partial sends (backpressure events)
    pub partial_sends: u64,

    /// Number of reconnection attempts
    pub reconnect_attempts: u64,

    /// Round-trip time estimate (if available)
    pub rtt_estimate_us: Option<u64>,
}

impl TcpConnectionMetrics {
    /// Create new empty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a message sent.
    pub fn record_sent(&mut self, bytes: usize) {
        self.messages_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a message received.
    pub fn record_received(&mut self, bytes: usize) {
        self.messages_received += 1;
        self.bytes_received += bytes as u64;
    }

    /// Update queue stats.
    pub fn update_queue(&mut self, depth: usize, bytes: usize) {
        self.send_queue_depth = depth;
        self.send_queue_bytes = bytes;
    }

    /// Record a partial send.
    pub fn record_partial_send(&mut self) {
        self.partial_sends += 1;
    }

    /// Record a reconnection attempt.
    pub fn record_reconnect(&mut self) {
        self.reconnect_attempts += 1;
    }

    /// Reset metrics.
    pub fn reset(&mut self) {
        self.messages_sent = 0;
        self.messages_received = 0;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.partial_sends = 0;
        // Keep queue stats and reconnect count
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_metrics_new() {
        let metrics = TcpTransportMetrics::new();
        assert_eq!(metrics.active_connections(), 0);
        assert_eq!(metrics.connections_established(), 0);
        assert_eq!(metrics.messages_sent(), 0);
    }

    #[test]
    fn test_transport_metrics_recording() {
        let metrics = TcpTransportMetrics::new();

        metrics.record_connection_established();
        assert_eq!(metrics.active_connections(), 1);
        assert_eq!(metrics.connections_established(), 1);

        metrics.record_connection_established();
        assert_eq!(metrics.active_connections(), 2);

        metrics.record_connection_closed();
        assert_eq!(metrics.active_connections(), 1);

        metrics.record_connection_failed();
        assert_eq!(metrics.connections_failed(), 1);

        metrics.record_message_sent(100);
        metrics.record_message_sent(200);
        assert_eq!(metrics.messages_sent(), 2);

        metrics.record_message_received(150);
        assert_eq!(metrics.messages_received(), 1);
    }

    #[test]
    fn test_transport_metrics_snapshot() {
        let metrics = TcpTransportMetrics::new();

        metrics.record_connection_established();
        metrics.record_message_sent(100);
        metrics.record_message_received(200);
        metrics.record_framing_error();

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(snapshot.connections_established, 1);
        assert_eq!(snapshot.messages_sent, 1);
        assert_eq!(snapshot.messages_received, 1);
        assert_eq!(snapshot.bytes_sent, 100);
        assert_eq!(snapshot.bytes_received, 200);
        assert_eq!(snapshot.framing_errors, 1);
        assert!(snapshot.uptime_secs > 0.0);
    }

    #[test]
    fn test_transport_metrics_reset() {
        let metrics = TcpTransportMetrics::new();

        metrics.record_connection_established();
        metrics.record_message_sent(100);

        metrics.reset();

        assert_eq!(metrics.active_connections(), 0);
        assert_eq!(metrics.connections_established(), 0);
        assert_eq!(metrics.messages_sent(), 0);
    }

    #[test]
    fn test_snapshot_rates() {
        let snapshot = TcpTransportMetricsSnapshot {
            messages_sent: 100,
            messages_received: 100,
            bytes_sent: 10000,
            bytes_received: 10000,
            uptime_secs: 10.0,
            ..Default::default()
        };

        assert_eq!(snapshot.message_rate(), 20.0); // 200 / 10
        assert_eq!(snapshot.byte_rate(), 2000.0); // 20000 / 10
    }

    #[test]
    fn test_snapshot_success_rate() {
        let snapshot = TcpTransportMetricsSnapshot {
            connections_established: 9,
            connections_failed: 1,
            ..Default::default()
        };

        assert!((snapshot.connection_success_rate() - 0.9).abs() < 0.001);

        let perfect = TcpTransportMetricsSnapshot {
            connections_established: 10,
            connections_failed: 0,
            ..Default::default()
        };
        assert_eq!(perfect.connection_success_rate(), 1.0);

        let none = TcpTransportMetricsSnapshot::default();
        assert_eq!(none.connection_success_rate(), 1.0);
    }

    #[test]
    fn test_connection_metrics() {
        let mut metrics = TcpConnectionMetrics::new();

        metrics.record_sent(100);
        metrics.record_sent(200);
        assert_eq!(metrics.messages_sent, 2);
        assert_eq!(metrics.bytes_sent, 300);

        metrics.record_received(150);
        assert_eq!(metrics.messages_received, 1);
        assert_eq!(metrics.bytes_received, 150);

        metrics.update_queue(5, 1000);
        assert_eq!(metrics.send_queue_depth, 5);
        assert_eq!(metrics.send_queue_bytes, 1000);

        metrics.record_partial_send();
        assert_eq!(metrics.partial_sends, 1);

        metrics.record_reconnect();
        assert_eq!(metrics.reconnect_attempts, 1);
    }

    #[test]
    fn test_connection_metrics_reset() {
        let mut metrics = TcpConnectionMetrics::new();

        metrics.record_sent(100);
        metrics.record_received(200);
        metrics.record_partial_send();
        metrics.record_reconnect();
        metrics.update_queue(5, 1000);

        metrics.reset();

        assert_eq!(metrics.messages_sent, 0);
        assert_eq!(metrics.messages_received, 0);
        assert_eq!(metrics.bytes_sent, 0);
        assert_eq!(metrics.bytes_received, 0);
        assert_eq!(metrics.partial_sends, 0);
        // Queue and reconnect count are preserved
        assert_eq!(metrics.send_queue_depth, 5);
        assert_eq!(metrics.reconnect_attempts, 1);
    }

    #[test]
    fn test_error_recording() {
        let metrics = TcpTransportMetrics::new();

        metrics.record_framing_error();
        metrics.record_send_error();
        metrics.record_recv_error();
        metrics.record_send_blocked();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.framing_errors, 1);
        assert_eq!(snapshot.send_errors, 1);
        assert_eq!(snapshot.recv_errors, 1);
        assert_eq!(snapshot.send_blocked_count, 1);
    }

    #[test]
    fn test_send_queue_bytes() {
        let metrics = TcpTransportMetrics::new();

        metrics.set_send_queue_bytes(1000);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.send_queue_bytes, 1000);

        metrics.set_send_queue_bytes(500);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.send_queue_bytes, 500);
    }
}

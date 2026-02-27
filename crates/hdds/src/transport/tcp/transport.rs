// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! High-level TCP transport interface.
//!
//! Provides [`TcpTransport`] which is the main entry point for TCP
//! communication in HDDS. Integrates:
//! - Connection management
//! - I/O thread coordination
//! - Metrics collection
//! - RTPS message routing
//!
//! # Example
//!
//! ```ignore
//! use hdds::transport::tcp::{TcpTransport, TcpConfig};
//!
//! let config = TcpConfig::enabled().with_port(7410);
//! let local_guid = [0x01; 12];
//!
//! let transport = TcpTransport::new(local_guid, config)?;
//!
//! // Connect to a remote participant
//! transport.connect(remote_guid, "192.168.1.100:7410".parse()?)?;
//!
//! // Send a message
//! transport.send(&remote_guid, &rtps_message)?;
//!
//! // Poll for events
//! for event in transport.poll() {
//!     match event {
//!         TcpTransportEvent::MessageReceived { from, payload } => {
//!             // Handle RTPS message
//!         }
//!         _ => {}
//!     }
//! }
//! ```

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::connection_manager::{
    ConnectionEvent, ConnectionInfo, ConnectionManager, ConnectionManagerConfig, GuidPrefix,
};
use super::io_thread::IoThread;
use super::locator::TcpLocator;
use super::metrics::{TcpTransportMetrics, TcpTransportMetricsSnapshot};
use super::TcpConfig;

// ============================================================================
// Transport Events
// ============================================================================

/// Events emitted by the TCP transport.
#[derive(Debug)]
pub enum TcpTransportEvent {
    /// Transport started and ready
    Started {
        /// Local TCP listen address (if listening)
        local_addr: Option<SocketAddr>,
    },

    /// New connection established to a remote participant
    Connected {
        /// Remote participant GUID prefix
        remote_guid: GuidPrefix,
        /// Remote socket address
        remote_addr: SocketAddr,
    },

    /// Connection to a remote participant was lost
    Disconnected {
        /// Remote participant GUID prefix
        remote_guid: GuidPrefix,
        /// Reason for disconnection
        reason: Option<String>,
    },

    /// RTPS message received from a remote participant
    MessageReceived {
        /// Source participant GUID prefix
        from: GuidPrefix,
        /// RTPS message payload
        payload: Vec<u8>,
    },

    /// Connection attempt failed
    ConnectFailed {
        /// Target participant GUID prefix
        remote_guid: GuidPrefix,
        /// Failure reason
        reason: String,
    },

    /// Transport error
    Error {
        /// Error description
        error: String,
    },

    /// Transport stopped
    Stopped,
}

// ============================================================================
// TCP Transport
// ============================================================================

/// High-level TCP transport for RTPS communication.
///
/// Manages TCP connections to remote DDS participants, handling:
/// - Connection lifecycle (connect, accept, reconnect)
/// - Message framing and delivery
/// - Metrics collection
///
/// # Thread Safety
///
/// `TcpTransport` is thread-safe and can be shared via `Arc<TcpTransport>`.
/// All methods take `&self` and use internal synchronization.
pub struct TcpTransport {
    /// Configuration
    config: TcpConfig,

    /// Local GUID prefix
    local_guid: GuidPrefix,

    /// Connection manager (protected by mutex for thread-safe access)
    conn_manager: Mutex<ConnectionManager>,

    /// Metrics
    metrics: Arc<TcpTransportMetrics>,

    /// Local listener address (if listening)
    local_addr: Option<SocketAddr>,

    /// Whether the transport is running (atomic for lock-free reads)
    running: AtomicBool,
}

impl TcpTransport {
    /// Create a new TCP transport.
    ///
    /// Starts the I/O thread and TCP listener (if configured).
    pub fn new(local_guid: GuidPrefix, config: TcpConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let metrics = Arc::new(TcpTransportMetrics::new());

        // Spawn I/O thread
        let io_handle = IoThread::spawn(config.clone(), metrics.clone())?;

        // Wait for started event to get local address
        let local_addr = loop {
            match io_handle.recv_timeout(Duration::from_secs(5)) {
                Some(super::io_thread::TcpEvent::Started { local_addr }) => {
                    break local_addr;
                }
                Some(_) => continue,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "I/O thread failed to start",
                    ));
                }
            }
        };

        let conn_config = ConnectionManagerConfig::from(&config);
        let conn_manager = ConnectionManager::new(local_guid, conn_config, io_handle);

        Ok(Self {
            config,
            local_guid,
            conn_manager: Mutex::new(conn_manager),
            metrics,
            local_addr,
            running: AtomicBool::new(true),
        })
    }

    // ========================================================================
    // Getters
    // ========================================================================

    /// Get the local GUID prefix.
    pub fn local_guid(&self) -> &GuidPrefix {
        &self.local_guid
    }

    /// Get the local listener address.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Get the local TCP locator (for SPDP announcements).
    pub fn local_locator(&self) -> Option<TcpLocator> {
        self.local_addr
            .map(|addr| TcpLocator::from_socket_addr(&addr))
    }

    /// Check if the transport is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
            && self
                .conn_manager
                .lock()
                .map(|cm| cm.is_running())
                .unwrap_or(false)
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.conn_manager
            .lock()
            .map(|cm| cm.connection_count())
            .unwrap_or(0)
    }

    /// Check if we have a connection to a remote participant.
    pub fn has_connection(&self, remote_guid: &GuidPrefix) -> bool {
        self.conn_manager
            .lock()
            .map(|cm| cm.has_connection(remote_guid))
            .unwrap_or(false)
    }

    /// Get connection info for a remote participant.
    pub fn connection_info(&self, remote_guid: &GuidPrefix) -> Option<ConnectionInfo> {
        self.conn_manager
            .lock()
            .ok()
            .and_then(|cm| cm.connection_info(remote_guid))
    }

    /// Get info for all connections.
    pub fn all_connections(&self) -> Vec<ConnectionInfo> {
        self.conn_manager
            .lock()
            .map(|cm| cm.all_connection_info())
            .unwrap_or_default()
    }

    /// Get the configuration.
    pub fn config(&self) -> &TcpConfig {
        &self.config
    }

    // ========================================================================
    // Connection management
    // ========================================================================

    /// Connect to a remote participant.
    ///
    /// If a connection already exists, this is a no-op.
    /// The connection will be established asynchronously; watch for
    /// `TcpTransportEvent::Connected` or `TcpTransportEvent::ConnectFailed`.
    ///
    /// This method is thread-safe and can be called from any thread.
    pub fn connect(&self, remote_guid: GuidPrefix, addr: SocketAddr) -> io::Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport not running",
            ));
        }

        self.conn_manager
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?
            .connect(remote_guid, addr)
    }

    /// Disconnect from a remote participant.
    pub fn disconnect(&self, remote_guid: &GuidPrefix) -> io::Result<()> {
        self.conn_manager
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?
            .disconnect(remote_guid)
    }

    /// Disconnect from all remote participants.
    pub fn disconnect_all(&self) -> io::Result<()> {
        self.conn_manager
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?
            .disconnect_all()
    }

    // ========================================================================
    // Message sending
    // ========================================================================

    /// Send an RTPS message to a remote participant.
    ///
    /// The message will be framed and queued for sending.
    /// This method is thread-safe.
    pub fn send(&self, remote_guid: &GuidPrefix, payload: &[u8]) -> io::Result<()> {
        if !self.running.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "transport not running",
            ));
        }

        self.conn_manager
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?
            .send(remote_guid, payload.to_vec())?;
        self.metrics.record_message_sent(payload.len() + 4); // +4 for frame header

        Ok(())
    }

    /// Send an RTPS message using a TCP locator.
    ///
    /// Requires an existing connection to the locator's address.
    pub fn send_to_locator(
        &self,
        remote_guid: &GuidPrefix,
        _locator: &TcpLocator,
        payload: &[u8],
    ) -> io::Result<()> {
        // The locator is informational; we route by GUID
        self.send(remote_guid, payload)
    }

    // ========================================================================
    // Event polling
    // ========================================================================

    /// Poll for transport events.
    ///
    /// Call this regularly to process I/O events and receive messages.
    /// This method is thread-safe.
    pub fn poll(&self) -> Vec<TcpTransportEvent> {
        if !self.running.load(Ordering::Acquire) {
            return vec![];
        }

        let conn_events = match self.conn_manager.lock() {
            Ok(mut cm) => cm.poll(),
            Err(_) => return vec![],
        };

        let mut events = Vec::with_capacity(conn_events.len());

        for event in conn_events {
            match event {
                ConnectionEvent::Connected {
                    remote_guid,
                    remote_addr,
                } => {
                    events.push(TcpTransportEvent::Connected {
                        remote_guid,
                        remote_addr,
                    });
                }
                ConnectionEvent::Disconnected {
                    remote_guid,
                    reason,
                } => {
                    events.push(TcpTransportEvent::Disconnected {
                        remote_guid,
                        reason,
                    });
                }
                ConnectionEvent::ConnectTimeout { remote_guid } => {
                    events.push(TcpTransportEvent::ConnectFailed {
                        remote_guid,
                        reason: "connection timeout".to_string(),
                    });
                }
                ConnectionEvent::MessageReceived {
                    remote_guid,
                    payload,
                } => {
                    events.push(TcpTransportEvent::MessageReceived {
                        from: remote_guid,
                        payload,
                    });
                }
                ConnectionEvent::Error {
                    remote_guid: _,
                    error,
                } => {
                    events.push(TcpTransportEvent::Error { error });
                }
                ConnectionEvent::IoThreadStopped => {
                    self.running.store(false, Ordering::Release);
                    events.push(TcpTransportEvent::Stopped);
                }
            }
        }

        events
    }

    /// Poll with blocking wait.
    ///
    /// Waits until at least one event is available or timeout expires.
    /// This method is thread-safe.
    pub fn poll_timeout(&self, timeout: Duration) -> Vec<TcpTransportEvent> {
        use std::thread;
        use std::time::Instant;

        let start = Instant::now();
        let poll_interval = Duration::from_millis(10);

        loop {
            let events = self.poll();
            if !events.is_empty() {
                return events;
            }

            if start.elapsed() >= timeout {
                return vec![];
            }

            thread::sleep(poll_interval);
        }
    }

    // ========================================================================
    // GUID association (for pending inbound connections)
    // ========================================================================

    /// Associate a GUID with a connection ID.
    ///
    /// Called when an RTPS message reveals the sender's GUID on an
    /// inbound connection that hasn't been identified yet.
    /// This method is thread-safe.
    pub fn associate_guid(&self, conn_id: u64, remote_guid: GuidPrefix) {
        if let Ok(mut cm) = self.conn_manager.lock() {
            cm.associate_guid(conn_id, remote_guid);
        }
    }

    // ========================================================================
    // Metrics
    // ========================================================================

    /// Get a snapshot of transport metrics.
    pub fn metrics(&self) -> TcpTransportMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get the raw metrics handle.
    pub fn metrics_handle(&self) -> &Arc<TcpTransportMetrics> {
        &self.metrics
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /// Shutdown the transport.
    ///
    /// Closes all connections and stops the I/O thread.
    /// This method is thread-safe.
    pub fn shutdown(&self) -> io::Result<()> {
        if !self.running.swap(false, Ordering::AcqRel) {
            return Ok(());
        }

        self.conn_manager
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?
            .shutdown()
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        // Use the thread-safe shutdown
        let _ = self.shutdown();
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for TcpTransport.
#[derive(Clone, Debug)]
pub struct TcpTransportBuilder {
    config: TcpConfig,
    local_guid: Option<GuidPrefix>,
}

impl TcpTransportBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: TcpConfig::enabled(),
            local_guid: None,
        }
    }

    /// Set the local GUID prefix.
    pub fn local_guid(mut self, guid: GuidPrefix) -> Self {
        self.local_guid = Some(guid);
        self
    }

    /// Set the TCP configuration.
    pub fn config(mut self, config: TcpConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the listen port.
    pub fn port(mut self, port: u16) -> Self {
        self.config.listen_port = port;
        self
    }

    /// Set the TCP role.
    pub fn role(mut self, role: super::TcpRole) -> Self {
        self.config.role = role;
        self
    }

    /// Add initial peers.
    pub fn peers(mut self, peers: Vec<SocketAddr>) -> Self {
        self.config.initial_peers = peers;
        self
    }

    /// Build the transport.
    pub fn build(self) -> io::Result<TcpTransport> {
        let guid = self
            .local_guid
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "local GUID required"))?;

        TcpTransport::new(guid, self.config)
    }
}

impl Default for TcpTransportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_guid(id: u8) -> GuidPrefix {
        [id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn test_transport_event_debug() {
        let guid = make_guid(1);

        let event = TcpTransportEvent::Connected {
            remote_guid: guid,
            remote_addr: "127.0.0.1:8080".parse().unwrap(),
        };
        let _ = format!("{:?}", event);

        let event = TcpTransportEvent::MessageReceived {
            from: guid,
            payload: vec![1, 2, 3],
        };
        let _ = format!("{:?}", event);
    }

    #[test]
    fn test_builder() {
        let builder = TcpTransportBuilder::new()
            .local_guid(make_guid(1))
            .port(7410)
            .role(super::super::TcpRole::ServerOnly);

        assert!(builder.local_guid.is_some());
        assert_eq!(builder.config.listen_port, 7410);
    }

    #[test]
    fn test_builder_missing_guid() {
        let builder = TcpTransportBuilder::new();
        let result = builder.build();
        assert!(result.is_err());
    }

    // Full transport tests require network I/O which is better suited
    // for integration tests. Focus on unit-testable components here.

    #[test]
    fn test_tcp_locator_conversion() {
        let addr: SocketAddr = "192.168.1.100:7410".parse().unwrap();
        let locator = TcpLocator::from_socket_addr(&addr);

        assert!(locator.is_tcp_v4());
        assert_eq!(locator.port(), 7410);
        assert_eq!(locator.to_socket_addr().unwrap(), addr);
    }
}

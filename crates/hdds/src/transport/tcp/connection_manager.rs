// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Connection manager for TCP transport.
//!
//! Manages the pool of TCP connections to remote participants:
//! - Connection lifecycle (connect, accept, close)
//! - GUID-based connection lookup
//! - Tie-breaker for duplicate connections
//! - Reconnection handling
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |                   ConnectionManager                          |
//! |  +-------------------------------------------------------+  |
//! |  |              Active Connections                        |  |
//! |  |         HashMap<GuidPrefix, TcpConnection>            |  |
//! |  +-------------------------------------------------------+  |
//! |  +-------------------------------------------------------+  |
//! |  |              Pending Connections                       |  |
//! |  |       HashMap<SocketAddr, PendingConnection>          |  |
//! |  +-------------------------------------------------------+  |
//! |  +-------------------------------------------------------+  |
//! |  |              Connection ID Mapping                     |  |
//! |  |            HashMap<u64, GuidPrefix>                   |  |
//! |  +-------------------------------------------------------+  |
//! +-------------------------------------------------------------+
//! ```

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::connection::{should_keep_connection, ConnectionState};
use super::io_thread::{IoThreadHandle, TcpEvent};
use super::TcpConfig;

// ============================================================================
// Types
// ============================================================================

/// 12-byte GUID prefix (participant identifier).
pub type GuidPrefix = [u8; 12];

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the connection manager.
#[derive(Clone, Debug)]
pub struct ConnectionManagerConfig {
    /// Maximum number of active connections
    pub max_connections: usize,

    /// Connection timeout
    pub connect_timeout: Duration,

    /// Reconnection delay
    pub reconnect_delay: Duration,

    /// Maximum reconnection attempts
    pub max_reconnect_attempts: u32,

    /// Enable automatic reconnection
    pub auto_reconnect: bool,
}

impl Default for ConnectionManagerConfig {
    fn default() -> Self {
        Self {
            max_connections: 1000,
            connect_timeout: Duration::from_secs(5),
            reconnect_delay: Duration::from_secs(1),
            max_reconnect_attempts: 10,
            auto_reconnect: true,
        }
    }
}

impl From<&TcpConfig> for ConnectionManagerConfig {
    fn from(tcp: &TcpConfig) -> Self {
        Self {
            max_connections: 1000,
            connect_timeout: tcp.connect_timeout,
            reconnect_delay: tcp.reconnect_delay,
            max_reconnect_attempts: tcp.max_reconnect_attempts,
            auto_reconnect: tcp.max_reconnect_attempts > 0,
        }
    }
}

// ============================================================================
// Pending Connection
// ============================================================================

/// A connection that is being established.
#[derive(Debug)]
pub struct PendingConnection {
    /// Target socket address
    pub addr: SocketAddr,

    /// Connection ID from I/O thread
    pub conn_id: u64,

    /// Expected remote GUID prefix (if known)
    pub expected_guid: Option<GuidPrefix>,

    /// Whether we initiated this connection
    pub is_initiator: bool,

    /// Time connection was initiated
    pub started_at: Instant,

    /// Number of connection attempts
    pub attempt_count: u32,
}

impl PendingConnection {
    /// Create a new pending outbound connection.
    pub fn outbound(addr: SocketAddr, conn_id: u64, expected_guid: Option<GuidPrefix>) -> Self {
        Self {
            addr,
            conn_id,
            expected_guid,
            is_initiator: true,
            started_at: Instant::now(),
            attempt_count: 1,
        }
    }

    /// Create a new pending inbound connection.
    pub fn inbound(addr: SocketAddr, conn_id: u64) -> Self {
        Self {
            addr,
            conn_id,
            expected_guid: None,
            is_initiator: false,
            started_at: Instant::now(),
            attempt_count: 1,
        }
    }

    /// Check if the connection attempt has timed out.
    pub fn is_timeout(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout
    }
}

// ============================================================================
// Managed Connection
// ============================================================================

/// A managed connection with additional metadata.
#[derive(Debug)]
struct ManagedConnection {
    /// Connection ID from I/O thread
    conn_id: u64,

    /// Remote socket address
    remote_addr: SocketAddr,

    /// Remote GUID prefix
    remote_guid: GuidPrefix,

    /// Whether we initiated this connection
    is_initiator: bool,

    /// Connection state
    state: ConnectionState,

    /// Time connection was established
    connected_at: Instant,

    /// Number of messages sent
    messages_sent: u64,

    /// Number of messages received
    messages_received: u64,

    /// Last activity time
    last_activity: Instant,
}

// ============================================================================
// Connection Manager
// ============================================================================

/// Manages TCP connections to remote participants.
pub struct ConnectionManager {
    /// Configuration
    config: ConnectionManagerConfig,

    /// Local GUID prefix
    local_guid: GuidPrefix,

    /// Active connections by remote GUID
    connections: HashMap<GuidPrefix, ManagedConnection>,

    /// Connection ID to GUID mapping
    conn_id_to_guid: HashMap<u64, GuidPrefix>,

    /// Pending outbound connections by address
    pending_outbound: HashMap<SocketAddr, PendingConnection>,

    /// Pending inbound connections by conn_id
    pending_inbound: HashMap<u64, PendingConnection>,

    /// I/O thread handle
    io_handle: IoThreadHandle,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(
        local_guid: GuidPrefix,
        config: ConnectionManagerConfig,
        io_handle: IoThreadHandle,
    ) -> Self {
        Self {
            config,
            local_guid,
            connections: HashMap::new(),
            conn_id_to_guid: HashMap::new(),
            pending_outbound: HashMap::new(),
            pending_inbound: HashMap::new(),
            io_handle,
        }
    }

    // ========================================================================
    // Connection lookup
    // ========================================================================

    /// Get a connection by remote GUID.
    pub fn get(&self, remote_guid: &GuidPrefix) -> Option<u64> {
        self.connections.get(remote_guid).map(|c| c.conn_id)
    }

    /// Check if we have a connection to a remote GUID.
    pub fn has_connection(&self, remote_guid: &GuidPrefix) -> bool {
        self.connections.contains_key(remote_guid)
    }

    /// Get the remote GUID for a connection ID.
    pub fn get_guid(&self, conn_id: u64) -> Option<&GuidPrefix> {
        self.conn_id_to_guid.get(&conn_id)
    }

    /// Get the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get all active remote GUIDs.
    pub fn remote_guids(&self) -> impl Iterator<Item = &GuidPrefix> {
        self.connections.keys()
    }

    // ========================================================================
    // Connection management
    // ========================================================================

    /// Connect to a remote participant.
    ///
    /// If a connection already exists, returns Ok immediately.
    /// Otherwise, initiates a new connection.
    pub fn connect(&mut self, remote_guid: GuidPrefix, remote_addr: SocketAddr) -> io::Result<()> {
        // Already connected?
        if self.connections.contains_key(&remote_guid) {
            return Ok(());
        }

        // Already pending?
        if self.pending_outbound.contains_key(&remote_addr) {
            return Ok(());
        }

        // Check connection limit
        if self.connections.len() >= self.config.max_connections {
            return Err(io::Error::other("connection limit reached"));
        }

        // Apply tie-breaker: should we initiate?
        if !should_keep_connection(&self.local_guid, &remote_guid, true) {
            // We should wait for them to connect
            return Ok(());
        }

        // Initiate connection
        let conn_id = self.io_handle.connect(remote_addr)?;

        let pending = PendingConnection::outbound(remote_addr, conn_id, Some(remote_guid));
        self.pending_outbound.insert(remote_addr, pending);

        Ok(())
    }

    /// Send a message to a remote participant.
    pub fn send(&self, remote_guid: &GuidPrefix, payload: Vec<u8>) -> io::Result<()> {
        let conn = self.connections.get(remote_guid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no connection to remote")
        })?;

        if conn.state != ConnectionState::Connected {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("connection not ready: {:?}", conn.state),
            ));
        }

        self.io_handle.send(conn.conn_id, payload)
    }

    /// Close a connection to a remote participant.
    pub fn disconnect(&mut self, remote_guid: &GuidPrefix) -> io::Result<()> {
        if let Some(conn) = self.connections.remove(remote_guid) {
            self.conn_id_to_guid.remove(&conn.conn_id);
            self.io_handle.close(conn.conn_id)?;
        }
        Ok(())
    }

    /// Close all connections.
    pub fn disconnect_all(&mut self) -> io::Result<()> {
        let guids: Vec<GuidPrefix> = self.connections.keys().copied().collect();
        for guid in guids {
            let _ = self.disconnect(&guid);
        }

        // Clear pending
        for (_, pending) in self.pending_outbound.drain() {
            let _ = self.io_handle.close(pending.conn_id);
        }
        for (_, pending) in self.pending_inbound.drain() {
            let _ = self.io_handle.close(pending.conn_id);
        }

        Ok(())
    }

    // ========================================================================
    // Event handling
    // ========================================================================

    /// Process events from the I/O thread.
    ///
    /// Call this regularly to handle connection events.
    /// Returns a list of high-level events for the transport layer.
    pub fn poll(&mut self) -> Vec<ConnectionEvent> {
        let mut events = Vec::new();

        // Process all available I/O events
        // v233: handle_io_event can return multiple events (Connected + MessageReceived)
        while let Some(io_event) = self.io_handle.try_recv() {
            events.extend(self.handle_io_event(io_event));
        }

        // Check for connection timeouts
        self.check_timeouts(&mut events);

        events
    }

    /// Handle a single I/O event.
    /// v233: Returns Vec to support emitting multiple events (e.g., Connected + MessageReceived)
    fn handle_io_event(&mut self, event: TcpEvent) -> Vec<ConnectionEvent> {
        match event {
            TcpEvent::ConnectionAccepted {
                conn_id,
                remote_addr,
            } => {
                // New inbound connection - we don't know the GUID yet
                let pending = PendingConnection::inbound(remote_addr, conn_id);
                self.pending_inbound.insert(conn_id, pending);
                vec![]
            }

            TcpEvent::ConnectionEstablished {
                conn_id,
                remote_addr,
            } => {
                // Outbound connection established
                if let Some(pending) = self.pending_outbound.remove(&remote_addr) {
                    if let Some(guid) = pending.expected_guid {
                        self.promote_connection(conn_id, remote_addr, guid, true);
                        return vec![ConnectionEvent::Connected {
                            remote_guid: guid,
                            remote_addr,
                        }];
                    }
                }
                vec![]
            }

            TcpEvent::ConnectionClosed {
                conn_id,
                remote_addr,
                reason,
            } => {
                // Remove from pending
                self.pending_outbound.remove(&remote_addr);
                self.pending_inbound.remove(&conn_id);

                // Remove from active
                if let Some(guid) = self.conn_id_to_guid.remove(&conn_id) {
                    self.connections.remove(&guid);
                    return vec![ConnectionEvent::Disconnected {
                        remote_guid: guid,
                        reason,
                    }];
                }
                vec![]
            }

            TcpEvent::MessageReceived {
                conn_id,
                remote_addr: _,
                payload,
            } => {
                // Update stats for known connections
                if let Some(guid) = self.conn_id_to_guid.get(&conn_id) {
                    if let Some(conn) = self.connections.get_mut(guid) {
                        conn.messages_received += 1;
                        conn.last_activity = Instant::now();
                    }
                    return vec![ConnectionEvent::MessageReceived {
                        remote_guid: *guid,
                        payload,
                    }];
                }

                // v233: Message from pending inbound connection - extract GUID from RTPS header
                // RTPS header format: "RTPS" (4B) + version (2B) + vendorId (2B) + guidPrefix (12B)
                // Total: 20 bytes minimum for a valid RTPS header
                if self.pending_inbound.contains_key(&conn_id) {
                    if let Some(guid_prefix) = extract_guid_prefix_from_rtps(&payload) {
                        // Promote the pending connection to active using the extracted GUID
                        if let Some(pending) = self.pending_inbound.remove(&conn_id) {
                            let peer_addr = pending.addr;
                            self.promote_connection(conn_id, peer_addr, guid_prefix, false);

                            // Update message stats on the newly promoted connection
                            if let Some(conn) = self.connections.get_mut(&guid_prefix) {
                                conn.messages_received += 1;
                                conn.last_activity = Instant::now();
                            }

                            log::debug!(
                                "[TCP] v233: Inbound connection {} promoted via RTPS GUID {:02x?}",
                                conn_id,
                                guid_prefix
                            );

                            // v233: Emit BOTH Connected and MessageReceived events
                            // This ensures the application knows a new client connected
                            return vec![
                                ConnectionEvent::Connected {
                                    remote_guid: guid_prefix,
                                    remote_addr: peer_addr,
                                },
                                ConnectionEvent::MessageReceived {
                                    remote_guid: guid_prefix,
                                    payload,
                                },
                            ];
                        }
                    } else {
                        log::warn!(
                            "[TCP] v233: Received message on pending inbound conn {} but couldn't extract GUID (payload len={})",
                            conn_id,
                            payload.len()
                        );
                    }
                }

                // Unknown connection - drop message
                vec![]
            }

            TcpEvent::WriteReady { conn_id: _ } => {
                // Backpressure cleared - could notify writer
                vec![]
            }

            TcpEvent::Started { local_addr: _ } => vec![],
            TcpEvent::Stopped => vec![ConnectionEvent::IoThreadStopped],

            TcpEvent::Error { conn_id, error } => {
                if let Some(cid) = conn_id {
                    // Connection-specific error
                    if let Some(guid) = self.conn_id_to_guid.get(&cid) {
                        return vec![ConnectionEvent::Error {
                            remote_guid: Some(*guid),
                            error,
                        }];
                    }
                }
                vec![ConnectionEvent::Error {
                    remote_guid: None,
                    error,
                }]
            }
        }
    }

    /// Promote a pending connection to active.
    fn promote_connection(
        &mut self,
        conn_id: u64,
        remote_addr: SocketAddr,
        remote_guid: GuidPrefix,
        is_initiator: bool,
    ) {
        // Check for duplicate connection
        if let Some(existing) = self.connections.get(&remote_guid) {
            // Apply tie-breaker
            let keep_existing =
                should_keep_connection(&self.local_guid, &remote_guid, existing.is_initiator);

            if keep_existing {
                // Close the new connection
                let _ = self.io_handle.close(conn_id);
                return;
            } else {
                // Close the existing connection
                let _ = self.io_handle.close(existing.conn_id);
                self.conn_id_to_guid.remove(&existing.conn_id);
            }
        }

        let managed = ManagedConnection {
            conn_id,
            remote_addr,
            remote_guid,
            is_initiator,
            state: ConnectionState::Connected,
            connected_at: Instant::now(),
            messages_sent: 0,
            messages_received: 0,
            last_activity: Instant::now(),
        };

        self.connections.insert(remote_guid, managed);
        self.conn_id_to_guid.insert(conn_id, remote_guid);
    }

    /// Associate a GUID with a pending inbound connection.
    ///
    /// Called when RTPS messages reveal the remote GUID.
    pub fn associate_guid(&mut self, conn_id: u64, remote_guid: GuidPrefix) {
        if let Some(pending) = self.pending_inbound.remove(&conn_id) {
            self.promote_connection(conn_id, pending.addr, remote_guid, false);
        }
    }

    /// Check for timed-out pending connections.
    fn check_timeouts(&mut self, events: &mut Vec<ConnectionEvent>) {
        let timeout = self.config.connect_timeout;

        // Check outbound timeouts
        let timed_out: Vec<SocketAddr> = self
            .pending_outbound
            .iter()
            .filter(|(_, p)| p.is_timeout(timeout))
            .map(|(addr, _)| *addr)
            .collect();

        for addr in timed_out {
            if let Some(pending) = self.pending_outbound.remove(&addr) {
                let _ = self.io_handle.close(pending.conn_id);

                if let Some(guid) = pending.expected_guid {
                    events.push(ConnectionEvent::ConnectTimeout { remote_guid: guid });
                }
            }
        }

        // Check inbound timeouts (connections that never identified themselves)
        let timed_out_inbound: Vec<u64> = self
            .pending_inbound
            .iter()
            .filter(|(_, p)| p.is_timeout(timeout * 2)) // Longer timeout for inbound
            .map(|(id, _)| *id)
            .collect();

        for conn_id in timed_out_inbound {
            if let Some(pending) = self.pending_inbound.remove(&conn_id) {
                let _ = self.io_handle.close(pending.conn_id);
            }
        }
    }

    // ========================================================================
    // Utilities
    // ========================================================================

    /// Shutdown the connection manager.
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.disconnect_all()?;
        self.io_handle.shutdown()
    }

    /// Check if the I/O thread is running.
    pub fn is_running(&self) -> bool {
        self.io_handle.is_running()
    }

    /// Get connection info by GUID.
    pub fn connection_info(&self, remote_guid: &GuidPrefix) -> Option<ConnectionInfo> {
        self.connections.get(remote_guid).map(|c| ConnectionInfo {
            conn_id: c.conn_id,
            remote_addr: c.remote_addr,
            remote_guid: c.remote_guid,
            is_initiator: c.is_initiator,
            state: c.state,
            connected_at: c.connected_at,
            messages_sent: c.messages_sent,
            messages_received: c.messages_received,
            last_activity: c.last_activity,
        })
    }

    /// Get all connection infos.
    pub fn all_connection_info(&self) -> Vec<ConnectionInfo> {
        self.connections
            .values()
            .map(|c| ConnectionInfo {
                conn_id: c.conn_id,
                remote_addr: c.remote_addr,
                remote_guid: c.remote_guid,
                is_initiator: c.is_initiator,
                state: c.state,
                connected_at: c.connected_at,
                messages_sent: c.messages_sent,
                messages_received: c.messages_received,
                last_activity: c.last_activity,
            })
            .collect()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract GUID prefix from RTPS message header.
///
/// RTPS header format (20 bytes minimum):
/// - Bytes 0-3: "RTPS" magic
/// - Bytes 4-5: Protocol version (e.g., 0x02, 0x05 for RTPS v2.5)
/// - Bytes 6-7: Vendor ID
/// - Bytes 8-19: GUID Prefix (12 bytes)
///
/// v233: Added for automatic GUID extraction from inbound TCP connections
fn extract_guid_prefix_from_rtps(payload: &[u8]) -> Option<GuidPrefix> {
    // Minimum RTPS header size is 20 bytes
    if payload.len() < 20 {
        return None;
    }

    // Check RTPS magic (optional but good for validation)
    // "RTPS" = 0x52, 0x54, 0x50, 0x53
    if payload[0..4] != [0x52, 0x54, 0x50, 0x53] {
        log::trace!(
            "[TCP] v233: Not a valid RTPS header (magic={:02x?})",
            &payload[0..4]
        );
        return None;
    }

    // Extract GUID prefix (bytes 8-19)
    let mut guid_prefix: GuidPrefix = [0u8; 12];
    guid_prefix.copy_from_slice(&payload[8..20]);

    Some(guid_prefix)
}

// ============================================================================
// Events
// ============================================================================

/// High-level connection events for the transport layer.
#[derive(Debug)]
pub enum ConnectionEvent {
    /// Connection established to a remote participant
    Connected {
        remote_guid: GuidPrefix,
        remote_addr: SocketAddr,
    },

    /// Connection to a remote participant was lost
    Disconnected {
        remote_guid: GuidPrefix,
        reason: Option<String>,
    },

    /// Connection attempt timed out
    ConnectTimeout { remote_guid: GuidPrefix },

    /// Message received from a remote participant
    MessageReceived {
        remote_guid: GuidPrefix,
        payload: Vec<u8>,
    },

    /// Error occurred
    Error {
        remote_guid: Option<GuidPrefix>,
        error: String,
    },

    /// I/O thread stopped
    IoThreadStopped,
}

/// Information about a connection.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    /// Connection ID
    pub conn_id: u64,

    /// Remote socket address
    pub remote_addr: SocketAddr,

    /// Remote GUID prefix
    pub remote_guid: GuidPrefix,

    /// Whether we initiated this connection
    pub is_initiator: bool,

    /// Connection state
    pub state: ConnectionState,

    /// Time connection was established
    pub connected_at: Instant,

    /// Messages sent
    pub messages_sent: u64,

    /// Messages received
    pub messages_received: u64,

    /// Last activity time
    pub last_activity: Instant,
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
    fn test_pending_connection_outbound() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let guid = make_guid(1);
        let pending = PendingConnection::outbound(addr, 1, Some(guid));

        assert!(pending.is_initiator);
        assert_eq!(pending.addr, addr);
        assert_eq!(pending.conn_id, 1);
        assert_eq!(pending.expected_guid, Some(guid));
        assert_eq!(pending.attempt_count, 1);
    }

    #[test]
    fn test_pending_connection_inbound() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let pending = PendingConnection::inbound(addr, 2);

        assert!(!pending.is_initiator);
        assert_eq!(pending.conn_id, 2);
        assert!(pending.expected_guid.is_none());
    }

    #[test]
    fn test_pending_connection_timeout() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let pending = PendingConnection::outbound(addr, 1, None);

        // Not timed out immediately
        assert!(!pending.is_timeout(Duration::from_secs(1)));

        // Would time out with zero duration
        assert!(pending.is_timeout(Duration::ZERO));
    }

    #[test]
    fn test_config_from_tcp_config() {
        let tcp_config = TcpConfig {
            connect_timeout: Duration::from_secs(10),
            reconnect_delay: Duration::from_secs(2),
            max_reconnect_attempts: 5,
            ..Default::default()
        };

        let config: ConnectionManagerConfig = (&tcp_config).into();

        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.reconnect_delay, Duration::from_secs(2));
        assert_eq!(config.max_reconnect_attempts, 5);
        assert!(config.auto_reconnect);
    }

    #[test]
    fn test_connection_event_debug() {
        let guid = make_guid(1);

        let event = ConnectionEvent::Connected {
            remote_guid: guid,
            remote_addr: "127.0.0.1:8080".parse().unwrap(),
        };
        let _ = format!("{:?}", event);

        let event = ConnectionEvent::Disconnected {
            remote_guid: guid,
            reason: Some("test".to_string()),
        };
        let _ = format!("{:?}", event);

        let event = ConnectionEvent::MessageReceived {
            remote_guid: guid,
            payload: vec![1, 2, 3],
        };
        let _ = format!("{:?}", event);
    }

    #[test]
    fn test_connection_info() {
        let info = ConnectionInfo {
            conn_id: 1,
            remote_addr: "127.0.0.1:8080".parse().unwrap(),
            remote_guid: make_guid(2),
            is_initiator: true,
            state: ConnectionState::Connected,
            connected_at: Instant::now(),
            messages_sent: 10,
            messages_received: 20,
            last_activity: Instant::now(),
        };

        assert_eq!(info.conn_id, 1);
        assert!(info.is_initiator);
        assert_eq!(info.messages_sent, 10);
    }

    // Integration tests would require I/O thread setup which is complex
    // for unit tests. Focus on data structure tests here.
}

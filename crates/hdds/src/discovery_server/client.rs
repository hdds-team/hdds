// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server client implementation.
//!
//! Provides async TCP client for connecting to a discovery server.

use super::config::DiscoveryServerConfig;
use super::protocol::{ClientMessage, EntityId, GuidPrefix, ServerMessage};
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

/// Discovery server client for DDS participants.
///
/// Manages connection to a discovery server, handles reconnection,
/// and provides async methods for participant/endpoint announcements.
pub struct DiscoveryServerClient {
    config: DiscoveryServerConfig,
    state: ClientState,
    guid_prefix: GuidPrefix,
    last_heartbeat: Option<Instant>,
}

/// Internal client state.
enum ClientState {
    /// Not connected.
    Disconnected,
    /// Connected to server.
    Connected { stream: std::net::TcpStream },
}

/// Events received from the discovery server.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// Successfully connected to server.
    Connected,

    /// Disconnected from server.
    Disconnected { reason: String },

    /// Server acknowledged our participant registration.
    ParticipantAcknowledged,

    /// New remote participant discovered.
    ParticipantDiscovered {
        guid_prefix: GuidPrefix,
        domain_id: u32,
        name: Option<String>,
        unicast_locators: Vec<SocketAddr>,
        builtin_endpoints: u32,
    },

    /// Remote participant left.
    ParticipantLeft { guid_prefix: GuidPrefix },

    /// New remote endpoint discovered.
    EndpointDiscovered {
        guid_prefix: GuidPrefix,
        entity_id: EntityId,
        topic_name: String,
        type_name: String,
        is_writer: bool,
        reliable: bool,
        durability: u8,
        unicast_locators: Vec<SocketAddr>,
    },

    /// Error from server.
    Error { code: u32, message: String },
}

/// Client error types.
#[derive(Debug)]
pub enum ClientError {
    /// Connection failed.
    ConnectionFailed(String),

    /// Connection closed unexpectedly.
    ConnectionClosed,

    /// I/O error.
    Io(io::Error),

    /// Protocol error.
    Protocol(String),

    /// Server returned an error.
    ServerError { code: u32, message: String },

    /// Configuration error.
    Config(String),

    /// Not connected.
    NotConnected,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            Self::ConnectionClosed => write!(f, "Connection closed"),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Protocol(s) => write!(f, "Protocol error: {}", s),
            Self::ServerError { code, message } => {
                write!(f, "Server error {}: {}", code, message)
            }
            Self::Config(s) => write!(f, "Configuration error: {}", s),
            Self::NotConnected => write!(f, "Not connected to server"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl DiscoveryServerClient {
    /// Create a new client with the given configuration and GUID prefix.
    pub fn new(
        config: DiscoveryServerConfig,
        guid_prefix: GuidPrefix,
    ) -> Result<Self, ClientError> {
        config
            .validate()
            .map_err(|e| ClientError::Config(e.to_string()))?;

        Ok(Self {
            config,
            state: ClientState::Disconnected,
            guid_prefix,
            last_heartbeat: None,
        })
    }

    /// Connect to the discovery server.
    pub fn connect(&mut self) -> Result<(), ClientError> {
        use std::net::TcpStream;

        let stream =
            TcpStream::connect_timeout(&self.config.server_address, self.config.connect_timeout)
                .map_err(|e| ClientError::ConnectionFailed(e.to_string()))?;

        // Set TCP options
        stream.set_nodelay(true).ok();
        stream
            .set_read_timeout(Some(self.config.connect_timeout))
            .ok();

        self.state = ClientState::Connected { stream };
        self.last_heartbeat = Some(Instant::now());

        Ok(())
    }

    /// Check if connected to the server.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ClientState::Connected { .. })
    }

    /// Get the GUID prefix.
    pub fn guid_prefix(&self) -> &GuidPrefix {
        &self.guid_prefix
    }

    /// Announce this participant to the server.
    pub fn announce_participant(
        &mut self,
        domain_id: u32,
        name: Option<String>,
        unicast_locators: Vec<SocketAddr>,
        builtin_endpoints: u32,
    ) -> Result<(), ClientError> {
        let msg = ClientMessage::ParticipantAnnounce {
            guid_prefix: self.guid_prefix,
            domain_id,
            name,
            unicast_locators,
            builtin_endpoints,
        };

        self.send_message(&msg)
    }

    /// Announce an endpoint (writer or reader) to the server.
    #[allow(clippy::too_many_arguments)] // Discovery protocol fields
    pub fn announce_endpoint(
        &mut self,
        entity_id: EntityId,
        topic_name: String,
        type_name: String,
        is_writer: bool,
        reliable: bool,
        durability: u8,
        unicast_locators: Vec<SocketAddr>,
    ) -> Result<(), ClientError> {
        let msg = ClientMessage::EndpointAnnounce {
            guid_prefix: self.guid_prefix,
            entity_id,
            topic_name,
            type_name,
            is_writer,
            reliable,
            durability,
            unicast_locators,
        };

        self.send_message(&msg)
    }

    /// Send a heartbeat to keep the lease alive.
    pub fn send_heartbeat(&mut self) -> Result<(), ClientError> {
        let msg = ClientMessage::Heartbeat {
            guid_prefix: self.guid_prefix,
        };

        self.send_message(&msg)?;
        self.last_heartbeat = Some(Instant::now());
        Ok(())
    }

    /// Announce that this participant is leaving.
    pub fn leave(&mut self) -> Result<(), ClientError> {
        let msg = ClientMessage::ParticipantLeave {
            guid_prefix: self.guid_prefix,
        };

        let result = self.send_message(&msg);
        self.disconnect();
        result
    }

    /// Disconnect from the server.
    pub fn disconnect(&mut self) {
        self.state = ClientState::Disconnected;
        self.last_heartbeat = None;
    }

    /// Read a message from the server (blocking).
    ///
    /// Returns `Ok(None)` if the connection was closed gracefully.
    pub fn read_message(&mut self) -> Result<Option<ClientEvent>, ClientError> {
        use std::io::Read;

        let stream = match &mut self.state {
            ClientState::Connected { stream } => stream,
            ClientState::Disconnected => return Err(ClientError::NotConnected),
        };

        // Read length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.state = ClientState::Disconnected;
                return Ok(None);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Ok(None);
            }
            Err(e) => {
                self.state = ClientState::Disconnected;
                return Err(ClientError::Io(e));
            }
        }

        let len = u32::from_be_bytes(len_buf) as usize;

        // Validate length
        if len == 0 || len > self.config.max_message_size {
            return Err(ClientError::Protocol(format!(
                "Invalid message length: {}",
                len
            )));
        }

        // Read message body
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf)?;

        // Parse message
        let msg = ServerMessage::decode(&buf).map_err(|e| ClientError::Protocol(e.to_string()))?;

        // Convert to event
        Ok(Some(self.message_to_event(msg)))
    }

    /// Send a message to the server.
    fn send_message(&mut self, msg: &ClientMessage) -> Result<(), ClientError> {
        use std::io::Write;

        let stream = match &mut self.state {
            ClientState::Connected { stream } => stream,
            ClientState::Disconnected => return Err(ClientError::NotConnected),
        };

        let encoded = msg
            .encode()
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        stream.write_all(&encoded)?;
        stream.flush()?;

        Ok(())
    }

    /// Convert a server message to a client event.
    fn message_to_event(&self, msg: ServerMessage) -> ClientEvent {
        match msg {
            ServerMessage::ParticipantAck { .. } => ClientEvent::ParticipantAcknowledged,

            ServerMessage::ParticipantAnnounce {
                guid_prefix,
                domain_id,
                name,
                unicast_locators,
                builtin_endpoints,
            } => ClientEvent::ParticipantDiscovered {
                guid_prefix,
                domain_id,
                name,
                unicast_locators,
                builtin_endpoints,
            },

            ServerMessage::ParticipantLeave { guid_prefix } => {
                ClientEvent::ParticipantLeft { guid_prefix }
            }

            ServerMessage::EndpointAnnounce {
                guid_prefix,
                entity_id,
                topic_name,
                type_name,
                is_writer,
                reliable,
                durability,
                unicast_locators,
            } => ClientEvent::EndpointDiscovered {
                guid_prefix,
                entity_id,
                topic_name,
                type_name,
                is_writer,
                reliable,
                durability,
                unicast_locators,
            },

            ServerMessage::Error { code, message } => ClientEvent::Error { code, message },
        }
    }

    /// Check if a heartbeat is due.
    pub fn heartbeat_due(&self) -> bool {
        if let Some(last) = self.last_heartbeat {
            last.elapsed() >= self.config.heartbeat_interval
        } else {
            false
        }
    }

    /// Get the server address.
    pub fn server_address(&self) -> SocketAddr {
        self.config.server_address
    }

    /// Get the configuration.
    pub fn config(&self) -> &DiscoveryServerConfig {
        &self.config
    }
}

/// Builder for creating a discovery server client.
#[allow(dead_code)]
pub struct DiscoveryServerClientBuilder {
    config: DiscoveryServerConfig,
    guid_prefix: Option<GuidPrefix>,
}

#[allow(dead_code)]
impl DiscoveryServerClientBuilder {
    /// Create a new builder with the server address.
    pub fn new(server_address: SocketAddr) -> Self {
        Self {
            config: DiscoveryServerConfig::new(server_address),
            guid_prefix: None,
        }
    }

    /// Set the GUID prefix.
    pub fn guid_prefix(mut self, guid_prefix: GuidPrefix) -> Self {
        self.guid_prefix = Some(guid_prefix);
        self
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set the heartbeat interval.
    pub fn heartbeat_interval(mut self, interval: std::time::Duration) -> Self {
        self.config.heartbeat_interval = interval;
        self
    }

    /// Disable auto-reconnect.
    pub fn without_auto_reconnect(mut self) -> Self {
        self.config.auto_reconnect = false;
        self
    }

    /// Keep multicast discovery enabled (hybrid mode).
    pub fn with_multicast_enabled(mut self) -> Self {
        self.config.disable_multicast = false;
        self
    }

    /// Build the client.
    pub fn build(self) -> Result<DiscoveryServerClient, ClientError> {
        let guid_prefix = self
            .guid_prefix
            .ok_or_else(|| ClientError::Config("GUID prefix is required".into()))?;

        DiscoveryServerClient::new(self.config, guid_prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_client_creation() {
        let guid_prefix = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let config = DiscoveryServerConfig::default();

        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();
        assert!(!client.is_connected());
        assert_eq!(client.guid_prefix(), &guid_prefix);
    }

    #[test]
    fn test_client_builder() {
        let addr: SocketAddr = "192.168.1.100:7400".parse().unwrap();
        let guid_prefix = [0xaa; 12];

        let client = DiscoveryServerClientBuilder::new(addr)
            .guid_prefix(guid_prefix)
            .connect_timeout(Duration::from_secs(10))
            .heartbeat_interval(Duration::from_secs(5))
            .without_auto_reconnect()
            .with_multicast_enabled()
            .build()
            .unwrap();

        assert_eq!(client.server_address(), addr);
        assert_eq!(client.config().connect_timeout, Duration::from_secs(10));
        assert_eq!(client.config().heartbeat_interval, Duration::from_secs(5));
        assert!(!client.config().auto_reconnect);
        assert!(!client.config().disable_multicast);
    }

    #[test]
    fn test_client_builder_requires_guid() {
        let addr: SocketAddr = "192.168.1.100:7400".parse().unwrap();

        let result = DiscoveryServerClientBuilder::new(addr).build();
        assert!(result.is_err());
    }

    #[test]
    fn test_not_connected_error() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let mut client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        // Should fail when not connected
        let result = client.announce_participant(0, None, vec![], 0);
        assert!(matches!(result, Err(ClientError::NotConnected)));
    }

    #[test]
    fn test_heartbeat_due() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig {
            heartbeat_interval: Duration::from_millis(10),
            ..Default::default()
        };

        let mut client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        // Initially no heartbeat is due (not connected)
        assert!(!client.heartbeat_due());

        // Simulate connected state
        client.last_heartbeat = Some(Instant::now() - Duration::from_millis(20));
        assert!(client.heartbeat_due());
    }

    #[test]
    fn test_client_error_display() {
        let err = ClientError::ConnectionFailed("timeout".into());
        assert!(err.to_string().contains("Connection failed"));

        let err = ClientError::NotConnected;
        assert!(err.to_string().contains("Not connected"));

        let err = ClientError::ServerError {
            code: 1,
            message: "Max participants".into(),
        };
        assert!(err.to_string().contains("Server error 1"));
    }

    #[test]
    fn test_message_to_event_participant_ack() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        let msg = ServerMessage::ParticipantAck {
            guid_prefix: [2; 12],
        };
        let event = client.message_to_event(msg);

        assert!(matches!(event, ClientEvent::ParticipantAcknowledged));
    }

    #[test]
    fn test_message_to_event_participant_discovered() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        let msg = ServerMessage::ParticipantAnnounce {
            guid_prefix: [2; 12],
            domain_id: 0,
            name: Some("TestParticipant".into()),
            unicast_locators: vec![],
            builtin_endpoints: 0x3f,
        };
        let event = client.message_to_event(msg);

        match event {
            ClientEvent::ParticipantDiscovered {
                guid_prefix,
                domain_id,
                name,
                builtin_endpoints,
                ..
            } => {
                assert_eq!(guid_prefix, [2; 12]);
                assert_eq!(domain_id, 0);
                assert_eq!(name, Some("TestParticipant".into()));
                assert_eq!(builtin_endpoints, 0x3f);
            }
            other => assert!(
                matches!(other, ClientEvent::ParticipantDiscovered { .. }),
                "Expected ParticipantDiscovered, got {:?}",
                other
            ),
        }
    }

    #[test]
    fn test_message_to_event_error() {
        let guid_prefix = [1; 12];
        let config = DiscoveryServerConfig::default();
        let client = DiscoveryServerClient::new(config, guid_prefix).unwrap();

        let msg = ServerMessage::Error {
            code: 100,
            message: "Test error".into(),
        };
        let event = client.message_to_event(msg);

        match event {
            ClientEvent::Error { code, message } => {
                assert_eq!(code, 100);
                assert_eq!(message, "Test error");
            }
            other => assert!(
                matches!(other, ClientEvent::Error { .. }),
                "Expected Error, got {:?}",
                other
            ),
        }
    }
}

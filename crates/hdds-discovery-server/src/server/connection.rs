// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Client connection handling for discovery server.

use super::protocol::{DiscoveryMessage, ProtocolError};
use super::registry::GuidPrefix;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A connected client.
pub struct ClientConnection {
    stream: TcpStream,
    #[allow(dead_code)]
    peer_addr: SocketAddr,
    max_message_size: usize,
    guid_prefix: Option<GuidPrefix>,
    read_buffer: Vec<u8>,
}

impl ClientConnection {
    /// Create a new client connection.
    pub fn new(stream: TcpStream, peer_addr: SocketAddr, max_message_size: usize) -> Self {
        Self {
            stream,
            peer_addr,
            max_message_size,
            guid_prefix: None,
            read_buffer: Vec::with_capacity(4096),
        }
    }

    /// Get the peer address.
    #[allow(dead_code)]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Get the registered GUID prefix (if any).
    pub fn guid_prefix(&self) -> Option<&GuidPrefix> {
        self.guid_prefix.as_ref()
    }

    /// Set the GUID prefix after participant registration.
    pub fn set_guid_prefix(&mut self, guid_prefix: GuidPrefix) {
        self.guid_prefix = Some(guid_prefix);
    }

    /// Read a message from the client.
    ///
    /// Returns `Ok(None)` if the connection is closed gracefully.
    pub async fn read_message(&mut self) -> Result<Option<DiscoveryMessage>, ConnectionError> {
        // Read length prefix (4 bytes, big-endian)
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None); // Connection closed
            }
            Err(e) => return Err(ConnectionError::Io(e.to_string())),
        }

        let len = u32::from_be_bytes(len_buf) as usize;

        // Validate length
        if len == 0 {
            return Err(ConnectionError::Protocol("Empty message".into()));
        }
        if len > self.max_message_size {
            return Err(ConnectionError::Protocol(format!(
                "Message too large: {} > {}",
                len, self.max_message_size
            )));
        }

        // Read message body
        self.read_buffer.clear();
        self.read_buffer.resize(len, 0);

        self.stream
            .read_exact(&mut self.read_buffer)
            .await
            .map_err(|e| ConnectionError::Io(e.to_string()))?;

        // Parse JSON
        let msg: DiscoveryMessage = serde_json::from_slice(&self.read_buffer)
            .map_err(|e| ConnectionError::Protocol(format!("Invalid JSON: {}", e)))?;

        Ok(Some(msg))
    }

    /// Send a message to the client.
    pub async fn send_message(&mut self, msg: DiscoveryMessage) -> Result<(), ConnectionError> {
        let json = serde_json::to_vec(&msg)
            .map_err(|e| ConnectionError::Protocol(format!("Serialize error: {}", e)))?;

        // Check size
        if json.len() > self.max_message_size {
            return Err(ConnectionError::Protocol(format!(
                "Response too large: {} > {}",
                json.len(),
                self.max_message_size
            )));
        }

        // Write length prefix
        let len = json.len() as u32;
        self.stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| ConnectionError::Io(e.to_string()))?;

        // Write body
        self.stream
            .write_all(&json)
            .await
            .map_err(|e| ConnectionError::Io(e.to_string()))?;

        self.stream
            .flush()
            .await
            .map_err(|e| ConnectionError::Io(e.to_string()))?;

        Ok(())
    }

    /// Shutdown the connection.
    #[allow(dead_code)]
    pub async fn shutdown(&mut self) -> Result<(), ConnectionError> {
        self.stream
            .shutdown()
            .await
            .map_err(|e| ConnectionError::Io(e.to_string()))
    }
}

/// Connection error types.
#[derive(Debug)]
pub enum ConnectionError {
    Io(String),
    Protocol(String),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O error: {}", s),
            Self::Protocol(s) => write!(f, "Protocol error: {}", s),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<ProtocolError> for ConnectionError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e.to_string())
    }
}

impl From<std::io::Error> for ConnectionError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_error_display() {
        let err = ConnectionError::Io("test".into());
        assert!(err.to_string().contains("I/O"));

        let err = ConnectionError::Protocol("invalid".into());
        assert!(err.to_string().contains("Protocol"));
    }
}

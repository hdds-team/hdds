// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Relay mode for NAT traversal.
//!
//! When relay mode is enabled, the discovery server can forward DDS DATA
//! messages between participants that cannot communicate directly due to NAT.
//!
//! # How it works
//!
//! 1. Participant A sends DATA with destination GUID prefix
//! 2. Server looks up destination participant's connection
//! 3. Server forwards DATA to destination participant
//!
//! This enables DDS communication in scenarios where:
//! - Participants are behind different NATs
//! - Firewalls block direct peer-to-peer communication
//! - Cloud-to-edge deployments

use super::protocol::DiscoveryMessage;
use super::registry::GuidPrefix;
use std::collections::HashMap;

/// Relay statistics.
#[derive(Debug, Default, Clone)]
pub struct RelayStats {
    /// Total messages relayed.
    pub messages_relayed: u64,
    /// Total bytes relayed.
    pub bytes_relayed: u64,
    /// Relay errors (destination not found, etc.).
    pub relay_errors: u64,
}

/// Client connections indexed by GUID prefix for relay routing.
pub struct RelayRouter {
    /// Connected clients by GUID prefix.
    connections: HashMap<GuidPrefix, ClientConnectionHandle>,
    /// Statistics.
    stats: RelayStats,
}

/// Handle to a client connection for relay purposes.
///
/// Uses a channel to send messages to the connection handler task.
pub struct ClientConnectionHandle {
    /// Channel to send messages to this client.
    tx: tokio::sync::mpsc::Sender<DiscoveryMessage>,
}

impl RelayRouter {
    /// Create a new relay router.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            stats: RelayStats::default(),
        }
    }

    /// Register a client connection for relay.
    pub fn register(
        &mut self,
        guid_prefix: GuidPrefix,
        tx: tokio::sync::mpsc::Sender<DiscoveryMessage>,
    ) {
        self.connections
            .insert(guid_prefix, ClientConnectionHandle { tx });
    }

    /// Unregister a client connection.
    pub fn unregister(&mut self, guid_prefix: &GuidPrefix) {
        self.connections.remove(guid_prefix);
    }

    /// Relay a DATA message to the destination.
    ///
    /// Returns `Ok(true)` if message was relayed, `Ok(false)` if destination not found.
    pub async fn relay_data(
        &mut self,
        destination: GuidPrefix,
        payload: Vec<u8>,
        _source: GuidPrefix,
    ) -> Result<bool, RelayError> {
        match self.connections.get(&destination) {
            Some(handle) => {
                let msg = DiscoveryMessage::Data {
                    destination: destination.into(),
                    payload: payload.clone(),
                };

                match handle.tx.send(msg).await {
                    Ok(_) => {
                        self.stats.messages_relayed += 1;
                        self.stats.bytes_relayed += payload.len() as u64;
                        Ok(true)
                    }
                    Err(_) => {
                        self.stats.relay_errors += 1;
                        Err(RelayError::SendFailed)
                    }
                }
            }
            None => {
                self.stats.relay_errors += 1;
                Ok(false)
            }
        }
    }

    /// Broadcast a message to all connected clients except the source.
    pub async fn broadcast(&self, msg: DiscoveryMessage, exclude: Option<&GuidPrefix>) -> usize {
        let mut sent = 0;
        for (guid_prefix, handle) in &self.connections {
            if exclude.map(|e| e != guid_prefix).unwrap_or(true)
                && handle.tx.send(msg.clone()).await.is_ok()
            {
                sent += 1;
            }
        }
        sent
    }

    /// Get relay statistics.
    pub fn stats(&self) -> &RelayStats {
        &self.stats
    }

    /// Get number of connected clients.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if a participant is connected.
    #[cfg(test)]
    fn is_connected(&self, guid_prefix: &GuidPrefix) -> bool {
        self.connections.contains_key(guid_prefix)
    }
}

impl Default for RelayRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay error types.
#[derive(Debug)]
#[allow(dead_code)]
pub enum RelayError {
    /// Failed to send message to destination.
    SendFailed,
    /// Destination not found.
    DestinationNotFound,
    /// Invalid destination GUID.
    InvalidDestination,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendFailed => write!(f, "Failed to send message"),
            Self::DestinationNotFound => write!(f, "Destination not found"),
            Self::InvalidDestination => write!(f, "Invalid destination GUID"),
        }
    }
}

impl std::error::Error for RelayError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_relay_router_new() {
        let router = RelayRouter::new();
        assert_eq!(router.connection_count(), 0);
        assert_eq!(router.stats().messages_relayed, 0);
    }

    #[tokio::test]
    async fn test_register_unregister() {
        let mut router = RelayRouter::new();
        let guid = [1u8; 12];
        let (tx, _rx) = mpsc::channel(10);

        router.register(guid, tx);
        assert!(router.is_connected(&guid));
        assert_eq!(router.connection_count(), 1);

        router.unregister(&guid);
        assert!(!router.is_connected(&guid));
        assert_eq!(router.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_relay_data_destination_not_found() {
        let mut router = RelayRouter::new();
        let dest = [1u8; 12];
        let source = [2u8; 12];

        let result = router.relay_data(dest, vec![1, 2, 3], source).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Not relayed
        assert_eq!(router.stats().relay_errors, 1);
    }

    #[tokio::test]
    async fn test_relay_data_success() {
        let mut router = RelayRouter::new();
        let dest = [1u8; 12];
        let source = [2u8; 12];
        let (tx, mut rx) = mpsc::channel(10);

        router.register(dest, tx);

        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let result = router.relay_data(dest, payload.clone(), source).await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Relayed successfully

        // Verify message received
        let msg = rx.recv().await.unwrap();
        match msg {
            DiscoveryMessage::Data {
                destination: _,
                payload: p,
            } => {
                assert_eq!(p, payload);
            }
            _ => panic!("Wrong message type"),
        }

        assert_eq!(router.stats().messages_relayed, 1);
        assert_eq!(router.stats().bytes_relayed, 4);
    }

    #[tokio::test]
    async fn test_broadcast() {
        let mut router = RelayRouter::new();
        let guid1 = [1u8; 12];
        let guid2 = [2u8; 12];
        let guid3 = [3u8; 12];

        let (tx1, mut rx1) = mpsc::channel(10);
        let (tx2, mut rx2) = mpsc::channel(10);
        let (tx3, mut rx3) = mpsc::channel(10);

        router.register(guid1, tx1);
        router.register(guid2, tx2);
        router.register(guid3, tx3);

        // Broadcast excluding guid1
        let msg = DiscoveryMessage::Heartbeat {
            guid_prefix: guid1.into(),
        };
        let sent = router.broadcast(msg, Some(&guid1)).await;
        assert_eq!(sent, 2); // guid2 and guid3

        // Verify guid1 didn't receive
        assert!(rx1.try_recv().is_err());

        // guid2 and guid3 should have received
        assert!(rx2.try_recv().is_ok());
        assert!(rx3.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_relay_stats() {
        let mut router = RelayRouter::new();
        let dest = [1u8; 12];
        let source = [2u8; 12];
        let (tx, _rx) = mpsc::channel(10);

        router.register(dest, tx);

        // Relay several messages
        for i in 0..5 {
            let payload = vec![i as u8; 100];
            router.relay_data(dest, payload, source).await.unwrap();
        }

        assert_eq!(router.stats().messages_relayed, 5);
        assert_eq!(router.stats().bytes_relayed, 500);
    }
}

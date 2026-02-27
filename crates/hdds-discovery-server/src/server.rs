// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery Server core implementation.

use crate::config::ServerConfig;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

pub mod connection;
pub mod protocol;
pub mod registry;
pub mod relay;

pub use connection::ClientConnection;
use protocol::{DiscoveryMessage, ParticipantInfoWire};
pub use registry::{ParticipantInfo, ParticipantRegistry};
pub use relay::{RelayRouter, RelayStats};

/// Discovery Server - centralized discovery for DDS.
#[derive(Clone)]
pub struct DiscoveryServer {
    config: Arc<ServerConfig>,
    registry: Arc<RwLock<ParticipantRegistry>>,
    relay_router: Arc<RwLock<RelayRouter>>,
    shutdown: Arc<tokio::sync::Notify>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl DiscoveryServer {
    /// Create a new discovery server.
    pub async fn new(config: ServerConfig) -> Result<Self, ServerError> {
        config
            .validate()
            .map_err(|e| ServerError::Config(e.to_string()))?;

        Ok(Self {
            config: Arc::new(config),
            registry: Arc::new(RwLock::new(ParticipantRegistry::new())),
            relay_router: Arc::new(RwLock::new(RelayRouter::new())),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Run the discovery server.
    pub async fn run(&self) -> Result<(), ServerError> {
        use std::sync::atomic::Ordering;
        use tokio::net::TcpListener;

        if self.running.swap(true, Ordering::SeqCst) {
            return Err(ServerError::AlreadyRunning);
        }

        let addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| ServerError::Bind(e.to_string()))?;

        info!("Discovery server listening on {}", addr);

        // Spawn lease checker task
        let registry = self.registry.clone();
        let lease_duration = self.config.lease_duration();
        let heartbeat_interval = self.config.heartbeat_interval();
        let shutdown_lease = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(heartbeat_interval) => {
                        let mut reg = registry.write().await;
                        let expired = reg.remove_expired(lease_duration);
                        if !expired.is_empty() {
                            info!("Removed {} expired participants", expired.len());
                            for guid in &expired {
                                debug!("  - {:?}", guid);
                            }
                        }
                    }
                    _ = shutdown_lease.notified() => {
                        debug!("Lease checker shutting down");
                        break;
                    }
                }
            }
        });

        // Accept connections
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            info!("New connection from {}", peer_addr);

                            let registry = self.registry.clone();
                            let relay_router = self.relay_router.clone();
                            let config = self.config.clone();
                            let shutdown = self.shutdown.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    peer_addr,
                                    registry,
                                    relay_router,
                                    config,
                                    shutdown,
                                ).await {
                                    warn!("Connection error from {}: {}", peer_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                        }
                    }
                }
                _ = self.shutdown.notified() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Handle a client connection.
    async fn handle_connection(
        stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
        registry: Arc<RwLock<ParticipantRegistry>>,
        relay_router: Arc<RwLock<RelayRouter>>,
        config: Arc<ServerConfig>,
        shutdown: Arc<tokio::sync::Notify>,
    ) -> Result<(), ServerError> {
        let mut conn = ClientConnection::new(stream, peer_addr, config.max_message_size);

        // Create channel for outbound messages (for relay and broadcast)
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<DiscoveryMessage>(100);

        loop {
            tokio::select! {
                result = conn.read_message() => {
                    match result {
                        Ok(Some(msg)) => {
                            Self::process_message(
                                &mut conn,
                                msg,
                                &registry,
                                &relay_router,
                                &config,
                                outbound_tx.clone(),
                            ).await?;
                        }
                        Ok(None) => {
                            // Connection closed gracefully
                            info!("Connection closed: {}", peer_addr);
                            break;
                        }
                        Err(e) => {
                            warn!("Read error from {}: {}", peer_addr, e);
                            break;
                        }
                    }
                }
                // Handle outbound messages from relay/broadcast
                Some(outbound_msg) = outbound_rx.recv() => {
                    if let Err(e) = conn.send_message(outbound_msg).await {
                        warn!("Failed to send outbound message to {}: {}", peer_addr, e);
                        break;
                    }
                }
                _ = shutdown.notified() => {
                    debug!("Connection handler shutting down: {}", peer_addr);
                    break;
                }
            }
        }

        // Clean up participant if registered
        if let Some(guid_prefix) = conn.guid_prefix() {
            // Unregister from relay router
            {
                let mut router = relay_router.write().await;
                router.unregister(guid_prefix);
            }

            // Remove from registry and broadcast departure
            let mut reg = registry.write().await;
            if reg.remove_participant(guid_prefix).is_some() {
                info!("Removed participant {:?} on disconnect", guid_prefix);

                // Broadcast participant removal to other clients
                if config.relay_enabled {
                    let leave_msg = DiscoveryMessage::ParticipantLeave {
                        guid_prefix: (*guid_prefix).into(),
                    };
                    let router = relay_router.read().await;
                    router.broadcast(leave_msg, Some(guid_prefix)).await;
                }
            }
        }

        Ok(())
    }

    /// Process a received message.
    async fn process_message(
        conn: &mut ClientConnection,
        msg: DiscoveryMessage,
        registry: &Arc<RwLock<ParticipantRegistry>>,
        relay_router: &Arc<RwLock<RelayRouter>>,
        config: &ServerConfig,
        outbound_tx: tokio::sync::mpsc::Sender<DiscoveryMessage>,
    ) -> Result<(), ServerError> {
        use registry::GuidPrefix;

        match msg {
            DiscoveryMessage::ParticipantAnnounce(info_wire) => {
                debug!("Participant announce: {:?}", info_wire.guid_prefix);

                // Convert wire format to internal format
                let info: ParticipantInfo = info_wire
                    .clone()
                    .try_into()
                    .map_err(|e| ServerError::Protocol(format!("{}", e)))?;

                // Check limits
                {
                    let reg = registry.read().await;
                    if reg.participant_count() >= config.max_participants {
                        warn!("Max participants reached, rejecting {:?}", info.guid_prefix);
                        conn.send_message(DiscoveryMessage::Error {
                            code: 1,
                            message: "Max participants reached".into(),
                        })
                        .await?;
                        return Ok(());
                    }
                }

                let guid_prefix = info.guid_prefix;

                // Register participant
                {
                    let mut reg = registry.write().await;
                    reg.add_participant(info.clone());
                }

                // Store guid_prefix in connection for cleanup
                conn.set_guid_prefix(guid_prefix);

                // Register in relay router for broadcast/relay
                {
                    let mut router = relay_router.write().await;
                    router.register(guid_prefix, outbound_tx.clone());
                }

                // Send ACK
                conn.send_message(DiscoveryMessage::ParticipantAck {
                    guid_prefix: guid_prefix.into(),
                })
                .await?;

                // Send current participant list to new participant
                {
                    let reg = registry.read().await;
                    for (_, participant) in reg.participants() {
                        if participant.guid_prefix != guid_prefix {
                            let wire: ParticipantInfoWire = participant.clone().into();
                            conn.send_message(DiscoveryMessage::ParticipantAnnounce(wire))
                                .await?;
                        }
                    }
                }

                // Broadcast new participant to existing participants
                if config.relay_enabled {
                    let announce_wire: ParticipantInfoWire = info.into();
                    let announce_msg = DiscoveryMessage::ParticipantAnnounce(announce_wire);
                    let router = relay_router.read().await;
                    router.broadcast(announce_msg, Some(&guid_prefix)).await;
                }

                info!("Registered participant {:?}", guid_prefix);
            }

            DiscoveryMessage::EndpointAnnounce(endpoint_wire) => {
                debug!("Endpoint announce: {:?}", endpoint_wire);

                let guid_prefix = match conn.guid_prefix() {
                    Some(gp) => *gp,
                    None => {
                        warn!("Endpoint announce before participant registration");
                        conn.send_message(DiscoveryMessage::Error {
                            code: 2,
                            message: "Register participant first".into(),
                        })
                        .await?;
                        return Ok(());
                    }
                };

                // Convert wire format
                let endpoint: registry::EndpointInfo = endpoint_wire
                    .clone()
                    .try_into()
                    .map_err(|e| ServerError::Protocol(format!("{}", e)))?;

                // Register endpoint
                {
                    let mut reg = registry.write().await;
                    reg.add_endpoint(guid_prefix, endpoint);
                }

                // Broadcast endpoint to other participants
                if config.relay_enabled {
                    let endpoint_msg = DiscoveryMessage::EndpointAnnounce(endpoint_wire);
                    let router = relay_router.read().await;
                    router.broadcast(endpoint_msg, Some(&guid_prefix)).await;
                }

                debug!("Registered endpoint for {:?}", guid_prefix);
            }

            DiscoveryMessage::Heartbeat { guid_prefix } => {
                // Update participant lease
                let gp: GuidPrefix = guid_prefix
                    .try_into()
                    .map_err(|e| ServerError::Protocol(format!("{}", e)))?;
                let mut reg = registry.write().await;
                reg.touch_participant(&gp);
            }

            DiscoveryMessage::ParticipantLeave { guid_prefix } => {
                let gp: GuidPrefix = guid_prefix
                    .clone()
                    .try_into()
                    .map_err(|e| ServerError::Protocol(format!("{}", e)))?;
                info!("Participant leave: {:?}", gp);

                // Unregister from relay router
                {
                    let mut router = relay_router.write().await;
                    router.unregister(&gp);
                }

                // Remove from registry
                {
                    let mut reg = registry.write().await;
                    reg.remove_participant(&gp);
                }

                // Broadcast removal to other participants
                if config.relay_enabled {
                    let leave_msg = DiscoveryMessage::ParticipantLeave { guid_prefix };
                    let router = relay_router.read().await;
                    router.broadcast(leave_msg, Some(&gp)).await;
                }
            }

            DiscoveryMessage::Error { code, message } => {
                warn!("Received error from client: {} - {}", code, message);
            }

            DiscoveryMessage::ParticipantAck { .. } => {
                // Server doesn't expect ACKs
                debug!("Unexpected ACK received");
            }

            DiscoveryMessage::Data {
                destination,
                payload,
            } if config.relay_enabled => {
                // Relay mode: forward DATA to destination
                let dest_gp: GuidPrefix = destination
                    .try_into()
                    .map_err(|e| ServerError::Protocol(format!("Invalid destination: {}", e)))?;

                let source_gp = conn.guid_prefix().ok_or_else(|| {
                    ServerError::Protocol("Relay from unregistered participant".into())
                })?;

                let mut router = relay_router.write().await;
                match router.relay_data(dest_gp, payload, *source_gp).await {
                    Ok(true) => {
                        debug!("Relayed DATA from {:?} to {:?}", source_gp, dest_gp);
                    }
                    Ok(false) => {
                        debug!("Relay destination {:?} not found", dest_gp);
                    }
                    Err(e) => {
                        warn!("Relay error: {}", e);
                    }
                }
            }

            DiscoveryMessage::Data { .. } => {
                debug!("DATA received but relay mode disabled");
            }
        }

        Ok(())
    }

    /// Signal the server to shutdown.
    pub async fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    /// Get the current participant count.
    pub async fn participant_count(&self) -> usize {
        self.registry.read().await.participant_count()
    }

    /// Check if server is running.
    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Get relay statistics (if relay mode is enabled).
    pub async fn relay_stats(&self) -> RelayStats {
        self.relay_router.read().await.stats().clone()
    }

    /// Get number of connected clients in the relay router.
    pub async fn relay_connection_count(&self) -> usize {
        self.relay_router.read().await.connection_count()
    }
}

/// Server error types.
#[derive(Debug)]
pub enum ServerError {
    Config(String),
    Bind(String),
    AlreadyRunning,
    Io(String),
    Protocol(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(s) => write!(f, "Configuration error: {}", s),
            Self::Bind(s) => write!(f, "Bind error: {}", s),
            Self::AlreadyRunning => write!(f, "Server already running"),
            Self::Io(s) => write!(f, "I/O error: {}", s),
            Self::Protocol(s) => write!(f, "Protocol error: {}", s),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<connection::ConnectionError> for ServerError {
    fn from(e: connection::ConnectionError) -> Self {
        Self::Io(e.to_string())
    }
}

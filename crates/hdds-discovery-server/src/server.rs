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
use protocol::{DiscoveryMessage, EndpointInfoWire, ParticipantInfoWire};
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
        let relay_router_lease = self.relay_router.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(heartbeat_interval) => {
                        let mut reg = registry.write().await;
                        let expired = reg.remove_expired(lease_duration);
                        let notifications: Vec<_> = expired
                            .iter()
                            .map(|info| {
                                (
                                    info.guid_prefix,
                                    reg.participant_guids_in_domain(info.domain_id),
                                )
                            })
                            .collect();
                        drop(reg);
                        if !expired.is_empty() {
                            info!("Removed {} expired participants", expired.len());
                            let mut router = relay_router_lease.write().await;
                            for info in &expired {
                                router.unregister(&info.guid_prefix);
                                debug!("  - {:?}", info.guid_prefix);
                            }
                            drop(router);

                            for (guid_prefix, recipients) in notifications {
                                RelayRouter::broadcast_to(
                                    &relay_router_lease,
                                    &DiscoveryMessage::ParticipantLeave {
                                        guid_prefix: guid_prefix.into(),
                                    },
                                    &recipients,
                                )
                                .await;
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
        if config.tcp_keepalive {
            let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(
                config.tcp_keepalive_interval_secs,
            ));
            socket2::SockRef::from(&stream)
                .set_tcp_keepalive(&keepalive)
                .map_err(|error| ServerError::Io(error.to_string()))?;
        }
        stream
            .set_nodelay(true)
            .map_err(|error| ServerError::Io(error.to_string()))?;

        let mut conn = ClientConnection::new(stream, peer_addr, config.max_message_size);

        // Create channel for outbound messages (for relay and broadcast),
        // paired with the signal that ends this connection. The router gets
        // both or neither: it must be able to terminate a client it gives up
        // on, otherwise that client stays connected, registered and deaf.
        let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<DiscoveryMessage>(100);
        let link = relay::ClientLink {
            tx: outbound_tx,
            evicted: Arc::new(tokio::sync::Notify::new()),
        };
        let evicted = Arc::clone(&link.evicted);

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
                                link.clone(),
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
                // The router gave up on this client (outbound queue full or
                // closed). Leaving the loop sends it down the ordinary
                // disconnect path below: unregister, remove from the
                // registry, broadcast the departure. Without this arm the
                // task never learns it was evicted and the client is deaf
                // for the rest of its connection.
                _ = evicted.notified() => {
                    warn!("Evicted by the relay router, closing: {}", peer_addr);
                    break;
                }
            }
        }

        // An operator-visible total for a connection that spoke a dialect
        // this build does not implement. Each frame was already counted and
        // the first one warned; this is the one line that says how much of
        // the session was skipped, which is what tells "one stray frame"
        // apart from "this peer and this server are not the same version".
        let ignored = conn.unknown_messages();
        if ignored > 0 {
            info!(
                "Connection from {} ended after {} frame(s) of a type this build does not \
                 implement",
                peer_addr, ignored
            );
        }

        // Clean up participant if registered
        if let Some(guid_prefix) = conn.guid_prefix() {
            // Unregister from relay router
            {
                let mut router = relay_router.write().await;
                router.unregister(guid_prefix);
            }

            // Remove from registry and broadcast departure
            let removed = {
                let mut reg = registry.write().await;
                reg.remove_participant(guid_prefix)
            };
            if let Some(info) = removed {
                info!("Removed participant {:?} on disconnect", guid_prefix);

                let recipients = registry
                    .read()
                    .await
                    .participant_guids_in_domain(info.domain_id);
                let leave_msg = DiscoveryMessage::ParticipantLeave {
                    guid_prefix: (*guid_prefix).into(),
                };
                RelayRouter::broadcast_to(&relay_router, &leave_msg, &recipients).await;
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
        link: relay::ClientLink,
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

                if config.domain_id != 0 && info.domain_id != config.domain_id {
                    conn.send_message(DiscoveryMessage::Error {
                        code: 3,
                        message: format!("Domain {} is not served by this server", info.domain_id),
                    })
                    .await?;
                    return Ok(());
                }

                if let Some(registered_guid) = conn.guid_prefix() {
                    if *registered_guid != info.guid_prefix {
                        conn.send_message(DiscoveryMessage::Error {
                            code: 4,
                            message: "Connection is already registered with another GUID".into(),
                        })
                        .await?;
                        return Ok(());
                    }
                }

                // Check limits
                {
                    let reg = registry.read().await;
                    let already_registered = reg.get_participant(&info.guid_prefix).is_some();
                    if conn.guid_prefix().is_none() && already_registered {
                        conn.send_message(DiscoveryMessage::Error {
                            code: 4,
                            message: "Participant GUID is already connected".into(),
                        })
                        .await?;
                        return Ok(());
                    }
                    if !already_registered && reg.participant_count() >= config.max_participants {
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
                    router.register(guid_prefix, info.domain_id, link.clone());
                }

                // Send ACK
                conn.send_message(DiscoveryMessage::ParticipantAck {
                    guid_prefix: guid_prefix.into(),
                })
                .await?;

                // Send current participant list to new participant
                let (participants, endpoints, recipients) = {
                    let reg = registry.read().await;
                    let participants: Vec<_> = reg
                        .participants()
                        .filter(|(_, participant)| {
                            participant.domain_id == info.domain_id
                                && participant.guid_prefix != guid_prefix
                        })
                        .map(|(_, participant)| participant.clone())
                        .collect();
                    let endpoints: Vec<_> = reg
                        .endpoints()
                        .filter(|(_, endpoint)| {
                            endpoint.guid.prefix != guid_prefix
                                && reg.get_participant(&endpoint.guid.prefix).is_some_and(
                                    |participant| participant.domain_id == info.domain_id,
                                )
                        })
                        .map(|(_, endpoint)| endpoint.clone())
                        .collect();
                    let recipients: Vec<_> = reg
                        .participant_guids_in_domain(info.domain_id)
                        .into_iter()
                        .filter(|recipient| *recipient != guid_prefix)
                        .collect();
                    (participants, endpoints, recipients)
                };

                for participant in participants {
                    let wire: ParticipantInfoWire = participant.into();
                    conn.send_message(DiscoveryMessage::ParticipantAnnounce(wire))
                        .await?;
                }
                for endpoint in endpoints {
                    let wire: EndpointInfoWire = endpoint.into();
                    conn.send_message(DiscoveryMessage::EndpointAnnounce(wire))
                        .await?;
                }

                // Broadcast new participant to existing participants
                let announce_wire: ParticipantInfoWire = info.into();
                let announce_msg = DiscoveryMessage::ParticipantAnnounce(announce_wire);
                RelayRouter::broadcast_to(relay_router, &announce_msg, &recipients).await;

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

                if endpoint.guid.prefix != guid_prefix {
                    conn.send_message(DiscoveryMessage::Error {
                        code: 4,
                        message: "Endpoint GUID does not match the registered participant".into(),
                    })
                    .await?;
                    return Ok(());
                }

                // Register endpoint
                let recipients = {
                    let mut reg = registry.write().await;
                    let Some(participant) = reg.get_participant(&guid_prefix) else {
                        conn.send_message(DiscoveryMessage::Error {
                            code: 2,
                            message: "Register participant first".into(),
                        })
                        .await?;
                        return Ok(());
                    };
                    let domain_id = participant.domain_id;
                    let already_registered = reg.get_endpoint(&endpoint.guid).is_some();
                    if !already_registered
                        && reg.endpoint_count_for_participant(&guid_prefix)
                            >= config.max_endpoints_per_participant
                    {
                        conn.send_message(DiscoveryMessage::Error {
                            code: 5,
                            message: "Max endpoints per participant reached".into(),
                        })
                        .await?;
                        return Ok(());
                    }
                    reg.add_endpoint(guid_prefix, endpoint);
                    reg.participant_guids_in_domain(domain_id)
                        .into_iter()
                        .filter(|recipient| *recipient != guid_prefix)
                        .collect::<Vec<_>>()
                };

                // Broadcast endpoint to other participants
                let endpoint_msg = DiscoveryMessage::EndpointAnnounce(endpoint_wire);
                RelayRouter::broadcast_to(relay_router, &endpoint_msg, &recipients).await;

                debug!("Registered endpoint for {:?}", guid_prefix);
            }

            DiscoveryMessage::Heartbeat { guid_prefix } => {
                // Update participant lease
                let gp: GuidPrefix = guid_prefix
                    .try_into()
                    .map_err(|e| ServerError::Protocol(format!("{}", e)))?;
                if conn.guid_prefix() != Some(&gp) {
                    conn.send_message(DiscoveryMessage::Error {
                        code: 4,
                        message: "Heartbeat GUID does not match the connection".into(),
                    })
                    .await?;
                    return Ok(());
                }
                let mut reg = registry.write().await;
                reg.touch_participant(&gp);
            }

            DiscoveryMessage::ParticipantLeave { guid_prefix } => {
                let gp: GuidPrefix = guid_prefix
                    .clone()
                    .try_into()
                    .map_err(|e| ServerError::Protocol(format!("{}", e)))?;
                if conn.guid_prefix() != Some(&gp) {
                    conn.send_message(DiscoveryMessage::Error {
                        code: 4,
                        message: "Leave GUID does not match the connection".into(),
                    })
                    .await?;
                    return Ok(());
                }
                info!("Participant leave: {:?}", gp);

                // Unregister from relay router
                {
                    let mut router = relay_router.write().await;
                    router.unregister(&gp);
                }

                // Remove from registry
                let removed = {
                    let mut reg = registry.write().await;
                    reg.remove_participant(&gp)
                };

                // Broadcast removal to other participants
                if let Some(info) = removed {
                    let recipients = registry
                        .read()
                        .await
                        .participant_guids_in_domain(info.domain_id);
                    let leave_msg = DiscoveryMessage::ParticipantLeave { guid_prefix };
                    RelayRouter::broadcast_to(relay_router, &leave_msg, &recipients).await;
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

                match RelayRouter::relay_data(relay_router, dest_gp, payload, *source_gp).await {
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

            // Filtered out by `ClientConnection::read_message`, which counts
            // it and logs it with its wire type name, so this arm is never
            // reached. It exists so that adding a variant to
            // `DiscoveryMessage` stays a compile error here rather than
            // becoming a silent drop.
            DiscoveryMessage::Unknown => {}
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
        self.relay_router.read().await.stats()
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

#[cfg(test)]
mod integration_tests {
    use super::*;
    use hdds::api::{DataWriterListener, PublicationMatchedStatus};
    use hdds::discovery_server::{
        ClientEvent, DiscoveryServerClient, DiscoveryServerConfig as ClientConfig,
    };
    use hdds::{Participant, QoS, TransportMode};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[derive(Clone, Debug, PartialEq, hdds::DDS)]
    struct ManagedDiscoverySample {
        value: u32,
    }

    struct MatchObserver(Arc<AtomicBool>);

    impl DataWriterListener<ManagedDiscoverySample> for MatchObserver {
        fn on_publication_matched(&self, status: PublicationMatchedStatus) {
            if status.current_count > 0 {
                self.0.store(true, Ordering::Release);
            }
        }
    }

    fn reserve_local_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve local port")
            .local_addr()
            .expect("read reserved address")
            .port()
    }

    fn connect_with_retry(address: SocketAddr, guid_prefix: [u8; 12]) -> DiscoveryServerClient {
        let config = ClientConfig::new(address)
            .with_connect_timeout(Duration::from_millis(250))
            .without_auto_reconnect();
        let deadline = Instant::now() + Duration::from_secs(3);

        loop {
            let mut client = DiscoveryServerClient::new(config.clone(), guid_prefix)
                .expect("create discovery client");
            match client.connect() {
                Ok(()) => return client,
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("connect to discovery server: {error}"),
            }
        }
    }

    fn read_event(client: &mut DiscoveryServerClient, description: &str) -> ClientEvent {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            // The client's socket is non-blocking, so the wait belongs here
            // rather than inside the read. Without it this loop is a hot spin
            // for however long the server takes to answer.
            client
                .wait_for_io(Duration::from_millis(50))
                .unwrap_or_else(|error| panic!("waiting for {description}: {error}"));
            match client.read_message() {
                Ok(Some(event)) => return event,
                Ok(None) if !client.is_connected() => {
                    panic!("client disconnected while waiting for {description}")
                }
                Ok(None) if Instant::now() < deadline => {}
                Ok(None) => panic!("timed out waiting for {description}"),
                Err(error) => panic!("failed while waiting for {description}: {error}"),
            }
        }
    }

    async fn start_server(
        mut config: ServerConfig,
    ) -> (
        SocketAddr,
        DiscoveryServer,
        tokio::task::JoinHandle<Result<(), ServerError>>,
    ) {
        config.bind_address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        config.port = reserve_local_port();
        let address = SocketAddr::new(config.bind_address, config.port);
        let server = DiscoveryServer::new(config)
            .await
            .expect("create discovery server");
        let server_task = {
            let server = server.clone();
            tokio::spawn(async move { server.run().await })
        };
        (address, server, server_task)
    }

    async fn stop_server(
        server: DiscoveryServer,
        server_task: tokio::task::JoinHandle<Result<(), ServerError>>,
    ) {
        server.shutdown().await;
        tokio::time::timeout(Duration::from_secs(3), server_task)
            .await
            .expect("server shutdown timed out")
            .expect("server task panicked")
            .expect("server run failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hdds_clients_exchange_discovery_events_end_to_end() {
        let (address, server, server_task) = start_server(ServerConfig::default()).await;

        let client_flow = tokio::task::spawn_blocking(move || {
            let guid_a = [0xA1; 12];
            let guid_b = [0xB2; 12];
            let locator_a: SocketAddr = "127.0.0.1:7411".parse().unwrap();
            let locator_b: SocketAddr = "127.0.0.1:7413".parse().unwrap();

            let mut client_a = connect_with_retry(address, guid_a);
            client_a
                .announce_participant(7, Some("participant-a".into()), vec![locator_a], 0x3f)
                .expect("announce participant A");
            assert!(matches!(
                read_event(&mut client_a, "ACK for A"),
                ClientEvent::ParticipantAcknowledged
            ));
            client_a
                .announce_endpoint(
                    [0x00, 0x00, 0x01, 0x02],
                    "Pressure".into(),
                    "PressureType".into(),
                    true,
                    false,
                    0,
                    vec![locator_a],
                )
                .expect("announce endpoint A");

            let mut client_b = connect_with_retry(address, guid_b);
            client_b
                .announce_participant(7, Some("participant-b".into()), vec![locator_b], 0x3f)
                .expect("announce participant B");
            assert!(matches!(
                read_event(&mut client_b, "ACK for B"),
                ClientEvent::ParticipantAcknowledged
            ));
            assert!(matches!(
                read_event(&mut client_b, "B discovers A"),
                ClientEvent::ParticipantDiscovered {
                    guid_prefix,
                    domain_id: 7,
                    ..
                } if guid_prefix == guid_a
            ));
            assert!(matches!(
                read_event(&mut client_b, "B discovers endpoint A"),
                ClientEvent::EndpointDiscovered {
                    guid_prefix,
                    entity_id: [0x00, 0x00, 0x01, 0x02],
                    ref topic_name,
                    ..
                } if guid_prefix == guid_a && topic_name == "Pressure"
            ));
            assert!(matches!(
                read_event(&mut client_a, "A discovers B"),
                ClientEvent::ParticipantDiscovered {
                    guid_prefix,
                    domain_id: 7,
                    ..
                } if guid_prefix == guid_b
            ));

            client_b
                .announce_endpoint(
                    [0x00, 0x00, 0x02, 0x02],
                    "Temperature".into(),
                    "TemperatureType".into(),
                    true,
                    true,
                    0,
                    vec![locator_b],
                )
                .expect("announce endpoint B");
            assert!(matches!(
                read_event(&mut client_a, "A discovers endpoint B"),
                ClientEvent::EndpointDiscovered {
                    guid_prefix,
                    entity_id: [0x00, 0x00, 0x02, 0x02],
                    ref topic_name,
                    ..
                } if guid_prefix == guid_b && topic_name == "Temperature"
            ));

            client_b.leave().expect("participant B leaves");
            assert!(matches!(
                read_event(&mut client_a, "A observes B leave"),
                ClientEvent::ParticipantLeft { guid_prefix } if guid_prefix == guid_b
            ));
        });

        tokio::time::timeout(Duration::from_secs(10), client_flow)
            .await
            .expect("client flow timed out")
            .expect("client flow panicked");

        stop_server(server, server_task).await;
    }

    /// Hex-encode a GUID prefix the way the wire protocol spells it.
    ///
    /// The crate's own `hex` helper is private to `protocol`, and widening
    /// its visibility for a test would be the test dictating the shape of
    /// the production code.
    fn hex12(bytes: [u8; 12]) -> String {
        use std::fmt::Write;

        bytes.iter().fold(String::with_capacity(24), |mut out, b| {
            let _ = write!(out, "{:02x}", b);
            out
        })
    }

    /// A connection that speaks the wire protocol directly, for frames no
    /// `DiscoveryServerClient` can produce.
    struct RawClient(std::net::TcpStream);

    impl RawClient {
        fn connect(address: SocketAddr) -> Self {
            Self(std::net::TcpStream::connect(address).expect("raw connect"))
        }

        fn send(&mut self, json: &str) {
            use std::io::Write;
            let len = u32::try_from(json.len()).expect("frame fits a u32 length");
            self.0.write_all(&len.to_be_bytes()).expect("write prefix");
            self.0.write_all(json.as_bytes()).expect("write body");
            self.0.flush().expect("flush");
        }
    }

    /// RELAY-0, end to end: a frame of a type the server does not implement
    /// must not end the connection it arrived on.
    ///
    /// `serde` reports an unrecognised tag as a deserialisation failure, the
    /// read loop reported a protocol error and the connection loop broke, so
    /// a client one version ahead of its server could not talk to it at all.
    /// The per-side unit tests prove the decoders; this one proves the
    /// connection survives and keeps serving the rest of the fleet.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unimplemented_frame_type_does_not_end_the_connection_end_to_end() {
        let config = ServerConfig {
            relay_enabled: true,
            ..ServerConfig::default()
        };
        let (address, server, server_task) = start_server(config).await;

        let client_flow = tokio::task::spawn_blocking(move || {
            let guid_victim = [0xB2; 12];
            let guid_sender = [0xA1; 12];

            let mut victim = connect_with_retry(address, guid_victim);
            victim
                .announce_participant(7, Some("victim".into()), vec![], 0x3f)
                .expect("announce the victim");
            assert!(matches!(
                read_event(&mut victim, "ACK for the victim"),
                ClientEvent::ParticipantAcknowledged
            ));

            // Raw on purpose: `ClientMessage` has no relay variant, and that
            // is the point - the frame comes from something that is not this
            // build, which is exactly the case the relay creates.
            let mut sender = RawClient::connect(address);
            sender.send(&format!(
                r#"{{"type":"participant_announce","guid_prefix":"{}","domain_id":7,"unicast_locators":[],"builtin_endpoints":63}}"#,
                hex12(guid_sender)
            ));
            assert!(matches!(
                read_event(&mut victim, "the victim discovers the sender"),
                ClientEvent::ParticipantDiscovered { guid_prefix, .. }
                    if guid_prefix == guid_sender
            ));

            // A type from a protocol revision this server does not know.
            sender.send(r#"{"type":"something_newer","whatever":42}"#);

            // The discriminator. A `participant_leave` would NOT prove
            // anything: when the server closes a connection it runs the
            // disconnect teardown, which broadcasts the very same
            // `ParticipantLeave`. An earlier draft of this test asserted on
            // that and passed whether the connection survived or not.
            //
            // An endpoint announcement has no such twin: the victim can only
            // see it if the sender's connection is still open AND still
            // synchronised on its stream.
            sender.send(&format!(
                r#"{{"type":"endpoint_announce","guid_prefix":"{}","entity_id":"000001c2","topic_name":"Pressure","type_name":"PressureType","is_writer":true}}"#,
                hex12(guid_sender)
            ));
            assert!(
                matches!(
                    read_event(&mut victim, "the victim discovers the sender's endpoint"),
                    ClientEvent::EndpointDiscovered {
                        guid_prefix,
                        ref topic_name,
                        ..
                    } if guid_prefix == guid_sender && topic_name == "Pressure"
                ),
                "an unimplemented frame type must not have ended the sender's connection"
            );
            assert!(victim.is_connected(), "the victim's own session must stand");
        });

        tokio::time::timeout(Duration::from_secs(10), client_flow)
            .await
            .expect("client flow timed out")
            .expect("client flow panicked");

        stop_server(server, server_task).await;
    }

    /// The two ends of the relay frame must agree, byte for byte.
    ///
    /// The server encodes the payload with the `base64` crate; the client
    /// lives in the `hdds` core crate, where that dependency is feature-
    /// gated, so it hand-writes the same codec. Each side is tested against
    /// a reference on its own. This is the test that pins them TOGETHER, at
    /// the message level, in both directions - the one that fails if either
    /// side ever changes its mind about the wire.
    #[test]
    fn the_relay_frame_crosses_both_encoders_intact() {
        // Every byte value, so a codec that mangles the high half is caught.
        // Three lengths, one per padding case: 256 % 3 == 1 (two pads),
        // 257 % 3 == 2 (one pad), 258 % 3 == 0 (none).
        let base: Vec<u8> = (0..=255u8).collect();
        let destination = [0xB2u8; 12];

        for extra in 0..=2usize {
            let mut payload = base.clone();
            payload.extend(std::iter::repeat_n(0xAAu8, extra));
            assert_eq!(payload.len() % 3, (1 + extra) % 3, "padding case coverage");
            check_relay_frame_round_trip(destination, payload);
        }
    }

    fn check_relay_frame_round_trip(destination: [u8; 12], payload: Vec<u8>) {
        use hdds::discovery_server::{ClientMessage, ServerMessage};

        // Client -> server.
        let encoded = ClientMessage::Data {
            destination,
            payload: payload.clone(),
        }
        .encode()
        .expect("client encodes a relay frame");
        let decoded: DiscoveryMessage = serde_json::from_slice(&encoded[4..])
            .expect("the server must parse what the client writes");
        match decoded {
            DiscoveryMessage::Data {
                destination: seen_destination,
                payload: seen_payload,
            } => {
                assert_eq!(seen_payload, payload, "payload mangled client -> server");
                assert_eq!(seen_destination.0, hex12(destination));
            }
            other => panic!("expected a relayed frame, got {:?}", other),
        }

        // Server -> client.
        let outbound = serde_json::to_vec(&DiscoveryMessage::Data {
            destination: destination.into(),
            payload: payload.clone(),
        })
        .expect("server encodes a relay frame");
        match ServerMessage::decode(&outbound)
            .expect("the client must parse what the server writes")
        {
            ServerMessage::Data {
                destination: seen_destination,
                payload: seen_payload,
            } => {
                assert_eq!(seen_payload, payload, "payload mangled server -> client");
                assert_eq!(seen_destination, destination);
            }
            other => panic!("expected a relayed frame, got {:?}", other),
        }

        // And the payload is a base64 STRING on the wire, not a JSON array
        // of decimal numbers. This is the property the frame size depends
        // on, so it gets asserted rather than assumed.
        let text = String::from_utf8(outbound).expect("the frame is UTF-8 JSON");
        assert!(
            text.contains(r#""payload":""#),
            "the payload must be a JSON string, got: {}",
            &text[..text.len().min(120)]
        );
    }

    /// The relay carries a datagram from one client to another, end to end,
    /// through the real server and the real client API.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_relayed_datagram_reaches_the_other_client() {
        let config = ServerConfig {
            relay_enabled: true,
            ..ServerConfig::default()
        };
        let (address, server, server_task) = start_server(config).await;

        let client_flow = tokio::task::spawn_blocking(move || {
            let guid_sender = [0xA1; 12];
            let guid_target = [0xB2; 12];

            // Every byte value, so any codec that mangles the high half of
            // the range fails here rather than in a capture six weeks later.
            let mut payload: Vec<u8> = (0..=255u8).collect();
            payload.extend_from_slice(b"RTPS");

            let mut target = connect_with_retry(address, guid_target);
            target
                .announce_participant(7, Some("target".into()), vec![], 0x3f)
                .expect("announce the target");
            assert!(matches!(
                read_event(&mut target, "ACK for the target"),
                ClientEvent::ParticipantAcknowledged
            ));

            let mut sender = connect_with_retry(address, guid_sender);
            sender
                .announce_participant(7, Some("sender".into()), vec![], 0x3f)
                .expect("announce the sender");
            assert!(matches!(
                read_event(&mut sender, "ACK for the sender"),
                ClientEvent::ParticipantAcknowledged
            ));
            assert!(matches!(
                read_event(&mut target, "the target discovers the sender"),
                ClientEvent::ParticipantDiscovered { guid_prefix, .. }
                    if guid_prefix == guid_sender
            ));

            sender
                .send_relay_data(guid_target, payload.clone())
                .expect("relay a datagram to the target");

            match read_event(&mut target, "the relayed datagram") {
                ClientEvent::RelayDataReceived { payload: received } => {
                    assert_eq!(
                        received, payload,
                        "the relayed datagram must arrive byte for byte"
                    );
                }
                other => panic!("expected a relayed datagram, got {:?}", other),
            }
            assert_eq!(
                target.misrouted_relay_frames(),
                0,
                "the frame was addressed to this participant"
            );
        });

        tokio::time::timeout(Duration::from_secs(10), client_flow)
            .await
            .expect("client flow timed out")
            .expect("client flow panicked");

        stop_server(server, server_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discovery_events_are_isolated_by_domain() {
        let (address, server, server_task) = start_server(ServerConfig::default()).await;

        tokio::task::spawn_blocking(move || {
            let mut client_a = connect_with_retry(address, [0xA1; 12]);
            client_a
                .announce_participant(7, None, vec![], 0x3f)
                .expect("announce domain 7 participant");
            assert!(matches!(
                read_event(&mut client_a, "domain 7 ACK"),
                ClientEvent::ParticipantAcknowledged
            ));

            let mut client_b = connect_with_retry(address, [0xB2; 12]);
            client_b
                .announce_participant(8, None, vec![], 0x3f)
                .expect("announce domain 8 participant");
            assert!(matches!(
                read_event(&mut client_b, "domain 8 ACK"),
                ClientEvent::ParticipantAcknowledged
            ));

            assert!(client_a.read_message().unwrap().is_none());
            assert!(client_b.read_message().unwrap().is_none());
        })
        .await
        .expect("domain isolation flow panicked");

        stop_server(server, server_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn configured_domain_and_resource_limits_are_enforced() {
        let (address, server, server_task) = start_server(ServerConfig {
            domain_id: 7,
            max_participants: 1,
            max_endpoints_per_participant: 1,
            ..ServerConfig::default()
        })
        .await;

        let clients = tokio::task::spawn_blocking(move || {
            let mut client_a = connect_with_retry(address, [0xA1; 12]);
            client_a
                .announce_participant(7, None, vec![], 0x3f)
                .expect("announce accepted participant");
            assert!(matches!(
                read_event(&mut client_a, "accepted participant ACK"),
                ClientEvent::ParticipantAcknowledged
            ));

            client_a
                .announce_endpoint(
                    [0, 0, 1, 2],
                    "TopicA".into(),
                    "TypeA".into(),
                    true,
                    false,
                    0,
                    vec![],
                )
                .expect("announce first endpoint");
            client_a
                .announce_endpoint(
                    [0, 0, 2, 2],
                    "TopicB".into(),
                    "TypeB".into(),
                    true,
                    false,
                    0,
                    vec![],
                )
                .expect("send endpoint above limit");
            assert!(matches!(
                read_event(&mut client_a, "endpoint limit error"),
                ClientEvent::Error { code: 5, .. }
            ));

            let mut wrong_domain = connect_with_retry(address, [0xB2; 12]);
            wrong_domain
                .announce_participant(8, None, vec![], 0x3f)
                .expect("send participant in rejected domain");
            assert!(matches!(
                read_event(&mut wrong_domain, "domain rejection"),
                ClientEvent::Error { code: 3, .. }
            ));

            let mut above_limit = connect_with_retry(address, [0xC3; 12]);
            above_limit
                .announce_participant(7, None, vec![], 0x3f)
                .expect("send participant above limit");
            assert!(matches!(
                read_event(&mut above_limit, "participant limit error"),
                ClientEvent::Error { code: 1, .. }
            ));

            // Handed back so the three connections outlive the assertion
            // below. A dropped client closes its socket, the server
            // unregisters the participant behind it, and the count this test
            // is about then races with that teardown: observed twice in five
            // runs of the full suite while the machine was busy, never when
            // the test ran alone. A race that only shows up under load is
            // still a race.
            (client_a, wrong_domain, above_limit)
        })
        .await
        .expect("limit enforcement flow panicked");

        assert_eq!(server.participant_count().await, 1);
        drop(clients);
        stop_server(server, server_task).await;
    }

    /// Reserve 6 loopback UDP ports (3 per managed-participant child) via the
    /// shared `hdds::test_support::ports` helper.
    ///
    /// No retry here: the actual bind happens in a separately spawned child
    /// process (`spawn_managed_child`/`run_managed_children`), so a failure
    /// surfaces as a nonzero exit status plus a panic message in the child's
    /// captured stderr, not as a typed `Result` this process could match on
    /// and retry through `with_reserved_ports`. Reservation is still routed
    /// through the one shared implementation to avoid a second copy of the
    /// bind-read-drop trick.
    fn reserve_udp_ports() -> Vec<u16> {
        hdds::test_support::ports::reserve_udp_ports::<6>().to_vec()
    }

    fn spawn_managed_child(
        role: &str,
        server_address: SocketAddr,
        ports: &[u16],
        timeout_secs: u64,
    ) -> Child {
        let test_exe = std::env::current_exe().expect("locate server test executable");
        Command::new(test_exe)
            .arg("--exact")
            .arg("server::integration_tests::managed_participant_child")
            .arg("--nocapture")
            .env("HDDS_DISCOVERY_CHILD_ROLE", role)
            .env("HDDS_DISCOVERY_SERVER", server_address.to_string())
            .env(
                "HDDS_DISCOVERY_PORTS",
                ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .env("HDDS_DISCOVERY_TIMEOUT_SECS", timeout_secs.to_string())
            .env_remove("HDDS_INTERFACE")
            .env_remove("HDDS_UNICAST_IF")
            .env_remove("HDDS_REUSEPORT")
            .env_remove("HDDS_SPDP_UNICAST_PEERS")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn managed participant child")
    }

    fn run_managed_children(
        server_address: SocketAddr,
        ports: &[u16],
        timeout_secs: u64,
    ) -> (Output, Output) {
        let reader = spawn_managed_child("reader", server_address, &ports[..3], timeout_secs);
        thread::sleep(Duration::from_millis(200));
        let writer = spawn_managed_child("writer", server_address, &ports[3..], timeout_secs);
        let reader_output = reader.wait_with_output().expect("wait for reader child");
        let writer_output = writer.wait_with_output().expect("wait for writer child");
        (reader_output, writer_output)
    }

    fn output_diagnostics(output: &Output) -> String {
        format!(
            "status={}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    #[test]
    fn managed_participant_child() {
        let Ok(role) = std::env::var("HDDS_DISCOVERY_CHILD_ROLE") else {
            return;
        };
        let server_address: SocketAddr = std::env::var("HDDS_DISCOVERY_SERVER")
            .unwrap()
            .parse()
            .unwrap();
        let ports: Vec<u16> = std::env::var("HDDS_DISCOVERY_PORTS")
            .unwrap()
            .split(',')
            .map(|port| port.parse().unwrap())
            .collect();
        assert_eq!(ports.len(), 3);
        let timeout = Duration::from_secs(
            std::env::var("HDDS_DISCOVERY_TIMEOUT_SECS")
                .unwrap()
                .parse()
                .unwrap(),
        );
        let client_config = ClientConfig::new(server_address)
            .with_connect_timeout(Duration::from_millis(200))
            .with_reconnect_delay(Duration::from_millis(50))
            .with_max_reconnect_attempts(20)
            .with_heartbeat_interval(Duration::from_millis(200));
        let participant = Participant::builder(&format!("managed-{role}"))
            .domain_id(73)
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(ports[0], ports[1], ports[2])
            .with_discovery_server(client_config)
            .build()
            .expect("build managed participant");

        match role.as_str() {
            "reader" => {
                let reader = participant
                    .topic::<ManagedDiscoverySample>("ManagedDiscoveryTopic")
                    .unwrap()
                    .reader()
                    .qos(QoS::best_effort())
                    .build()
                    .unwrap();
                let deadline = Instant::now() + timeout;
                while Instant::now() < deadline {
                    if let Ok(Some(sample)) = reader.take() {
                        assert_eq!(sample.value, 0xD15C0);
                        return;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
                panic!("managed reader did not receive a sample before timeout");
            }
            "writer" => {
                let matched = Arc::new(AtomicBool::new(false));
                let writer = participant
                    .topic::<ManagedDiscoverySample>("ManagedDiscoveryTopic")
                    .unwrap()
                    .writer()
                    .qos(QoS::best_effort())
                    .with_listener(Arc::new(MatchObserver(Arc::clone(&matched))))
                    .build()
                    .unwrap();
                thread::sleep(Duration::from_millis(500));
                let deadline = Instant::now() + timeout;
                let mut writes_after_match = 0;
                while Instant::now() < deadline {
                    writer
                        .write(&ManagedDiscoverySample { value: 0xD15C0 })
                        .unwrap();
                    if matched.load(Ordering::Acquire) {
                        writes_after_match += 1;
                        if writes_after_match >= 10 {
                            return;
                        }
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                panic!("managed writer did not observe publication matching before timeout");
            }
            other => panic!("unknown child role: {other}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn managed_participants_require_server_and_exchange_data_without_multicast() {
        let (address, server, server_task) = start_server(ServerConfig::default()).await;
        let positive_ports = reserve_udp_ports();
        let positive =
            tokio::task::spawn_blocking(move || run_managed_children(address, &positive_ports, 8))
                .await
                .expect("positive child flow panicked");
        stop_server(server, server_task).await;

        assert!(
            positive.0.status.success(),
            "reader failed with live server:\n{}",
            output_diagnostics(&positive.0)
        );
        assert!(
            positive.1.status.success(),
            "writer failed with live server:\n{}",
            output_diagnostics(&positive.1)
        );

        let unavailable_address =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), reserve_local_port());
        let negative_ports = reserve_udp_ports();
        let negative = tokio::task::spawn_blocking(move || {
            run_managed_children(unavailable_address, &negative_ports, 3)
        })
        .await
        .expect("negative child flow panicked");

        assert!(
            !negative.0.status.success(),
            "reader discovered without a server; multicast was not isolated:\n{}",
            output_diagnostics(&negative.0)
        );
    }
}

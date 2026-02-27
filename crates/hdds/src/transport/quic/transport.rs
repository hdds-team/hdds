// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QUIC transport implementation.
//!
//! v234 changes:
//! - **FIXED**: Receive path now routes messages via event channel instead of dropping them
//! - **FIXED**: TLS `dangerous_skip_verify` flag now actually controls verification
//! - **FIXED**: Replaced `std::sync::RwLock` with `tokio::sync::RwLock` to prevent
//!   deadlocks in single-threaded tokio runtime
//! - **ADDED**: `trusted_client_config()` for proper cert pinning in HDDS-to-HDDS mode
//! - **ADDED**: Max message size validation on receive path (anti-OOM)
//!
//! v234-sprint3 changes:
//! - **CHANGED**: `read_stream_messages()` now loops to read multiple messages
//!   per stream, supporting both long-lived and single-use streams.

use super::config::QuicConfig;
use super::connection::{QuicConnection, MAX_QUIC_MESSAGE_SIZE};
use super::io_thread::QuicEvent;
use super::{QuicError, QuicResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[cfg(feature = "quic")]
use quinn::{ClientConfig, Endpoint, ServerConfig};
#[cfg(feature = "quic")]
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
#[cfg(feature = "quic")]
use tokio::sync::RwLock;

/// Handle to a running QUIC transport.
///
/// This handle can be cloned and shared across threads.
#[derive(Clone)]
pub struct QuicTransportHandle {
    #[cfg(feature = "quic")]
    inner: Arc<QuicTransportInner>,
}

#[cfg(feature = "quic")]
struct QuicTransportInner {
    endpoint: Endpoint,
    connections: RwLock<HashMap<SocketAddr, QuicConnection>>,
    config: QuicConfig,
    /// Event channel for routing received messages back to the I/O thread.
    event_tx: std::sync::mpsc::Sender<QuicEvent>,
    /// Running flag shared with stream handler tasks.
    running: Arc<AtomicBool>,
}

impl QuicTransportHandle {
    /// Get local address the transport is bound to.
    #[cfg(feature = "quic")]
    pub fn local_addr(&self) -> QuicResult<SocketAddr> {
        self.inner
            .endpoint
            .local_addr()
            .map_err(|e| QuicError::BindFailed(e.to_string()))
    }

    /// Connect to a remote peer.
    #[cfg(feature = "quic")]
    pub async fn connect(&self, remote_addr: SocketAddr) -> QuicResult<()> {
        self.connect_with_name(remote_addr, &self.inner.config.server_name)
            .await
    }

    /// Connect to a remote peer with explicit server name for TLS SNI.
    #[cfg(feature = "quic")]
    pub async fn connect_with_name(
        &self,
        remote_addr: SocketAddr,
        server_name: &str,
    ) -> QuicResult<()> {
        // Check if already connected
        {
            let connections = self.inner.connections.read().await;
            if connections.contains_key(&remote_addr) {
                return Ok(());
            }
        }

        log::debug!(
            "[QUIC] Connecting to {} (SNI: {})",
            remote_addr,
            server_name
        );

        let connection = self
            .inner
            .endpoint
            .connect(remote_addr, server_name)
            .map_err(|e| QuicError::ConnectionFailed(e.to_string()))?
            .await
            .map_err(|e| QuicError::ConnectionFailed(e.to_string()))?;

        log::info!("[QUIC] Connected to {}", remote_addr);

        let quic_conn = QuicConnection::from_quinn(connection.clone(), remote_addr);

        {
            let mut connections = self.inner.connections.write().await;
            connections.insert(remote_addr, quic_conn);
        }

        // Spawn stream handler for this connection's incoming data
        let event_tx = self.inner.event_tx.clone();
        let running = Arc::clone(&self.inner.running);
        tokio::spawn(async move {
            QuicTransport::handle_connection_streams(connection, remote_addr, event_tx, running)
                .await;
        });

        Ok(())
    }

    /// Send data to a specific peer.
    #[cfg(feature = "quic")]
    pub async fn send(&self, data: &[u8], remote_addr: &SocketAddr) -> QuicResult<()> {
        let connections = self.inner.connections.read().await;
        let conn = connections
            .get(remote_addr)
            .ok_or(QuicError::ConnectionFailed(format!(
                "No connection to {}",
                remote_addr
            )))?;

        conn.send(data).await
    }

    /// Send data to all connected peers.
    #[cfg(feature = "quic")]
    pub async fn broadcast(&self, data: &[u8]) -> QuicResult<()> {
        let connections = self.inner.connections.read().await;

        for conn in connections.values() {
            if conn.is_connected() {
                if let Err(e) = conn.send(data).await {
                    log::warn!("[QUIC] Broadcast to {} failed: {}", conn.remote_addr(), e);
                }
            }
        }

        Ok(())
    }

    /// Get list of connected peers.
    #[cfg(feature = "quic")]
    pub async fn connected_peers(&self) -> Vec<SocketAddr> {
        let connections = self.inner.connections.read().await;
        connections
            .values()
            .filter(|c| c.is_connected())
            .map(|c| c.remote_addr())
            .collect()
    }

    /// Close connection to a specific peer.
    #[cfg(feature = "quic")]
    pub async fn disconnect(&self, remote_addr: &SocketAddr) {
        let mut connections = self.inner.connections.write().await;
        if let Some(mut conn) = connections.remove(remote_addr) {
            conn.close();
            log::info!("[QUIC] Disconnected from {}", remote_addr);
        }
    }

    /// Close all connections and shutdown transport.
    #[cfg(feature = "quic")]
    pub async fn shutdown(&self) {
        self.inner.running.store(false, Ordering::Relaxed);
        let mut connections = self.inner.connections.write().await;
        for (_, mut conn) in connections.drain() {
            conn.close();
        }
        self.inner.endpoint.close(0u32.into(), b"shutdown");
        log::info!("[QUIC] Transport shutdown");
    }
}

/// QUIC transport for DDS communication.
pub struct QuicTransport;

impl QuicTransport {
    /// Create a new QUIC transport.
    ///
    /// Takes `event_tx` for routing received messages back to the I/O thread.
    #[cfg(feature = "quic")]
    #[allow(clippy::new_ret_no_self)]
    pub async fn new(
        config: QuicConfig,
        event_tx: std::sync::mpsc::Sender<QuicEvent>,
    ) -> QuicResult<QuicTransportHandle> {
        // Generate or load TLS config
        let (server_config, client_config) = Self::build_tls_configs(&config)?;

        // Create endpoint
        let mut endpoint = Endpoint::server(server_config, config.bind_addr)
            .map_err(|e| QuicError::BindFailed(e.to_string()))?;

        endpoint.set_default_client_config(client_config);

        log::info!(
            "[QUIC] Transport bound to {}",
            endpoint
                .local_addr()
                .map_err(|e| QuicError::BindFailed(e.to_string()))?
        );

        let running = Arc::new(AtomicBool::new(true));

        let inner = Arc::new(QuicTransportInner {
            endpoint,
            connections: RwLock::new(HashMap::new()),
            config,
            event_tx: event_tx.clone(),
            running: Arc::clone(&running),
        });

        // Spawn incoming connection handler
        let inner_clone = Arc::clone(&inner);
        tokio::spawn(async move {
            Self::handle_incoming(inner_clone).await;
        });

        Ok(QuicTransportHandle { inner })
    }

    /// Handle incoming connections.
    #[cfg(feature = "quic")]
    async fn handle_incoming(inner: Arc<QuicTransportInner>) {
        while inner.running.load(Ordering::Relaxed) {
            match inner.endpoint.accept().await {
                Some(incoming) => {
                    let remote_addr = incoming.remote_address();
                    log::debug!("[QUIC] Incoming connection from {}", remote_addr);

                    match incoming.await {
                        Ok(connection) => {
                            log::info!("[QUIC] Accepted connection from {}", remote_addr);

                            let quic_conn =
                                QuicConnection::from_quinn(connection.clone(), remote_addr);

                            {
                                let mut connections = inner.connections.write().await;
                                connections.insert(remote_addr, quic_conn);
                            }

                            // Notify io_thread of new connection
                            let _ = inner.event_tx.send(QuicEvent::Connected { remote_addr });

                            // Spawn stream handler with event routing
                            let event_tx = inner.event_tx.clone();
                            let running = Arc::clone(&inner.running);
                            tokio::spawn(async move {
                                Self::handle_connection_streams(
                                    connection,
                                    remote_addr,
                                    event_tx,
                                    running,
                                )
                                .await;
                            });
                        }
                        Err(e) => {
                            log::warn!(
                                "[QUIC] Failed to accept connection from {}: {}",
                                remote_addr,
                                e
                            );
                        }
                    }
                }
                None => {
                    // Endpoint closed
                    break;
                }
            }
        }
    }

    /// Handle incoming streams on a connection.
    ///
    /// Accepts unidirectional streams and spawns a reader task for each.
    /// Each stream may carry one or many messages (sprint3 compatibility).
    #[cfg(feature = "quic")]
    async fn handle_connection_streams(
        connection: quinn::Connection,
        remote_addr: SocketAddr,
        event_tx: std::sync::mpsc::Sender<QuicEvent>,
        running: Arc<AtomicBool>,
    ) {
        while running.load(Ordering::Relaxed) {
            match connection.accept_uni().await {
                Ok(recv_stream) => {
                    let event_tx = event_tx.clone();
                    let remote = remote_addr;

                    // Spawn a task per stream to read its data
                    tokio::spawn(async move {
                        Self::read_stream_messages(recv_stream, remote, event_tx).await;
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                    log::info!("[QUIC] Connection closed by {}", remote_addr);
                    break;
                }
                Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                    log::info!("[QUIC] Connection to {} closed", remote_addr);
                    break;
                }
                Err(e) => {
                    log::warn!("[QUIC] Stream accept error from {}: {}", remote_addr, e);
                    break;
                }
            }
        }

        // Notify disconnection
        let _ = event_tx.send(QuicEvent::Disconnected {
            remote_addr,
            reason: Some("Connection ended".to_string()),
        });
    }

    /// v234-sprint3: Read length-prefixed messages from a long-lived stream.
    ///
    /// Reads `[u32 BE length][payload]` frames in a loop until the stream
    /// is finished (FIN) or an error occurs. This handles both:
    /// - Long-lived streams (sprint3): multiple messages, loop continues
    /// - Legacy 1-stream-per-message: single message, then FIN breaks loop
    #[cfg(feature = "quic")]
    async fn read_stream_messages(
        mut recv_stream: quinn::RecvStream,
        remote_addr: SocketAddr,
        event_tx: std::sync::mpsc::Sender<QuicEvent>,
    ) {
        let mut len_buf = [0u8; 4];
        let mut msg_count: u64 = 0;

        loop {
            // Read 4-byte length header
            match recv_stream.read_exact(&mut len_buf).await {
                Ok(()) => {}
                Err(quinn::ReadExactError::FinishedEarly(_)) => {
                    // Stream finished (FIN) — clean end
                    log::trace!(
                        "[QUIC] Stream from {} finished after {} messages",
                        remote_addr,
                        msg_count
                    );
                    break;
                }
                Err(e) => {
                    if msg_count > 0 {
                        log::trace!(
                            "[QUIC] Stream from {} ended after {} messages: {}",
                            remote_addr,
                            msg_count,
                            e
                        );
                    }
                    break;
                }
            }

            let len = u32::from_be_bytes(len_buf) as usize;

            // Validate message size (anti-OOM protection)
            if len > MAX_QUIC_MESSAGE_SIZE {
                log::warn!(
                    "[QUIC] Message too large from {}: {} bytes (max {})",
                    remote_addr,
                    len,
                    MAX_QUIC_MESSAGE_SIZE
                );
                break; // Protocol error — abandon stream
            }

            if len == 0 {
                // Empty message — valid but skip routing
                msg_count += 1;
                continue;
            }

            // Read message payload
            let mut data = vec![0u8; len];
            match recv_stream.read_exact(&mut data).await {
                Ok(()) => {}
                Err(e) => {
                    log::warn!(
                        "[QUIC] Incomplete message from {} (expected {} bytes): {}",
                        remote_addr,
                        len,
                        e
                    );
                    break;
                }
            }

            msg_count += 1;
            log::trace!(
                "[QUIC] Received msg #{} ({} bytes) from {}",
                msg_count,
                data.len(),
                remote_addr
            );

            // Route to event channel
            if event_tx
                .send(QuicEvent::MessageReceived {
                    remote_addr,
                    payload: data,
                })
                .is_err()
            {
                // Event channel closed — transport shutting down
                break;
            }
        }
    }

    // ========================================================================
    // TLS Configuration
    // ========================================================================

    /// Build TLS configurations for server and client.
    ///
    /// Correctly respects `dangerous_skip_verify`:
    /// - `false` (default): Uses cert pinning — the generated/provided cert is
    ///   added to the client trust store. Only peers with this cert are trusted.
    /// - `true`: Disables ALL verification (testing only).
    #[cfg(feature = "quic")]
    fn build_tls_configs(config: &QuicConfig) -> QuicResult<(ServerConfig, ClientConfig)> {
        let (cert_chain, private_key) = if let (Some(cert_pem), Some(key_pem)) =
            (&config.certificate_pem, &config.private_key_pem)
        {
            // Load provided certificates
            Self::load_pem_certs(cert_pem, key_pem)?
        } else {
            // Generate self-signed certificate
            Self::generate_self_signed()?
        };

        // Server config
        let private_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(private_key.clone_key());
        let server_config = ServerConfig::with_single_cert(cert_chain.clone(), private_key_der)
            .map_err(|e| QuicError::TlsError(e.to_string()))?;

        // Client config branches correctly on dangerous_skip_verify
        let client_config = if config.dangerous_skip_verify {
            log::warn!("[QUIC] TLS verification DISABLED — dangerous_skip_verify=true");
            Self::insecure_client_config()
        } else {
            // Pin the cert: add our cert chain to the trust store so we only
            // trust peers using the same certificate (HDDS-to-HDDS mutual trust).
            Self::trusted_client_config(&cert_chain)?
        };

        Ok((server_config, client_config))
    }

    /// Load certificates from PEM strings.
    #[cfg(feature = "quic")]
    fn load_pem_certs(
        cert_pem: &str,
        key_pem: &str,
    ) -> QuicResult<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
        use rustls_pemfile::{certs, pkcs8_private_keys};
        use std::io::BufReader;

        let cert_chain: Vec<CertificateDer<'static>> =
            certs(&mut BufReader::new(cert_pem.as_bytes()))
                .filter_map(|r| r.ok())
                .collect();

        if cert_chain.is_empty() {
            return Err(QuicError::TlsError(
                "No certificates found in PEM".to_string(),
            ));
        }

        let mut keys: Vec<PrivatePkcs8KeyDer<'static>> =
            pkcs8_private_keys(&mut BufReader::new(key_pem.as_bytes()))
                .filter_map(|r| r.ok())
                .collect();

        let private_key = keys
            .pop()
            .ok_or_else(|| QuicError::TlsError("No private key found in PEM".to_string()))?;

        Ok((cert_chain, private_key))
    }

    /// Generate a self-signed certificate for HDDS.
    #[cfg(feature = "quic")]
    fn generate_self_signed(
    ) -> QuicResult<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>)> {
        let cert = rcgen::generate_simple_self_signed(vec!["hdds.local".to_string()])
            .map_err(|e| QuicError::TlsError(e.to_string()))?;

        let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());

        Ok((vec![cert_der], key))
    }

    /// Create client config that trusts a specific cert chain (cert pinning).
    ///
    /// For HDDS-to-HDDS communication, both peers use the same self-signed cert.
    /// We add that cert to the trust store so only peers with this cert are accepted.
    #[cfg(feature = "quic")]
    fn trusted_client_config(cert_chain: &[CertificateDer<'static>]) -> QuicResult<ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in cert_chain {
            root_store
                .add(cert.clone())
                .map_err(|e| QuicError::TlsError(format!("Failed to add cert to store: {}", e)))?;
        }

        let crypto = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| QuicError::TlsError(format!("QUIC client config error: {}", e)))?,
        )))
    }

    /// Create insecure client config that skips certificate verification.
    ///
    /// **WARNING**: This disables ALL TLS security. Only for local testing.
    #[cfg(feature = "quic")]
    fn insecure_client_config() -> ClientConfig {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        ClientConfig::new(Arc::new(
            #[allow(clippy::unwrap_used)] // crypto config built from valid rustls ClientConfig
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ))
    }
}

/// Skip server certificate verification (for testing only).
#[cfg(feature = "quic")]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(feature = "quic")]
impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = QuicConfig::default();
        assert_eq!(config.server_name, "hdds.local");
        assert!(config.enable_migration);
        // Default should NOT skip verification
        assert!(!config.dangerous_skip_verify);
    }
}

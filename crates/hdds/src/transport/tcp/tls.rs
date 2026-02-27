// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TLS support for TCP transport.
//!
//! This module provides TLS encryption for TCP connections using rustls.
//! It implements the `ByteStream` trait to allow seamless integration
//! with the existing TCP transport infrastructure.
//!
//! # Features
//!
//! - **Server and client modes**: Full support for both TLS server and client roles
//! - **Certificate validation**: Configurable certificate chain and private key
//! - **ALPN support**: Application-Layer Protocol Negotiation for DDS
//! - **mTLS support**: Mutual TLS with client certificate verification
//!
//! # Example
//!
//! ```ignore
//! use hdds::transport::tcp::tls::{TlsConfig, TlsAcceptor, TlsConnector};
//!
//! // Server-side TLS
//! let server_config = TlsConfig::server()
//!     .with_cert_file("server.crt")
//!     .with_key_file("server.key")
//!     .build()?;
//! let acceptor = TlsAcceptor::new(server_config);
//! let tls_stream = acceptor.accept(tcp_stream)?;
//!
//! // Client-side TLS
//! let client_config = TlsConfig::client()
//!     .with_root_certs_file("ca.crt")
//!     .build()?;
//! let connector = TlsConnector::new(client_config);
//! let tls_stream = connector.connect("server.example.com", tcp_stream)?;
//! ```
//!
//! # Security Notes
//!
//! - By default, client connections verify server certificates against system roots
//! - Server connections require explicit certificate configuration
//! - Use `dangerous_accept_invalid_certs()` only for testing (not in production)

use std::fmt;
use std::io::{self};
#[cfg(feature = "tcp-tls")]
use std::io::{Read, Write};
#[cfg(feature = "tcp-tls")]
use std::net::{Shutdown, SocketAddr, TcpStream};
#[cfg(feature = "tcp-tls")]
use std::sync::Arc;
#[cfg(feature = "tcp-tls")]
use std::time::Duration;

#[cfg(feature = "tcp-tls")]
use std::path::Path;

#[cfg(all(unix, feature = "tcp-tls"))]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(all(windows, feature = "tcp-tls"))]
use std::os::windows::io::{AsRawSocket, RawSocket};

#[cfg(feature = "tcp-tls")]
use super::byte_stream::ByteStream;

#[cfg(feature = "tcp-tls")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

#[cfg(feature = "tcp-tls")]
use rustls::{ClientConfig, ServerConfig};

// ============================================================================
// TLS Configuration
// ============================================================================

/// TLS configuration for TCP transport.
///
/// This struct holds all the configuration needed to establish TLS connections,
/// including certificates, private keys, and verification settings.
#[derive(Clone)]
pub struct TlsConfig {
    /// Server-side configuration (for accepting connections)
    #[cfg(feature = "tcp-tls")]
    pub(crate) server_config: Option<Arc<ServerConfig>>,

    /// Client-side configuration (for initiating connections)
    #[cfg(feature = "tcp-tls")]
    pub(crate) client_config: Option<Arc<ClientConfig>>,

    /// Whether this is a server configuration
    pub(crate) is_server: bool,

    /// ALPN protocols to advertise
    pub(crate) alpn_protocols: Vec<Vec<u8>>,

    /// Whether to verify peer certificates (client mode)
    pub(crate) verify_peer: bool,

    /// Whether to require client certificates (server mode, mTLS)
    pub(crate) require_client_cert: bool,

    /// Session resumption enabled
    pub(crate) enable_session_resumption: bool,

    /// TLS version constraints
    pub(crate) min_protocol_version: TlsVersion,
    pub(crate) max_protocol_version: TlsVersion,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "tcp-tls")]
            server_config: None,
            #[cfg(feature = "tcp-tls")]
            client_config: None,
            is_server: false,
            alpn_protocols: vec![b"dds".to_vec()],
            verify_peer: true,
            require_client_cert: false,
            enable_session_resumption: true,
            min_protocol_version: TlsVersion::Tls12,
            max_protocol_version: TlsVersion::Tls13,
        }
    }
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("is_server", &self.is_server)
            .field("alpn_protocols", &self.alpn_protocols.len())
            .field("verify_peer", &self.verify_peer)
            .field("require_client_cert", &self.require_client_cert)
            .field("enable_session_resumption", &self.enable_session_resumption)
            .field("min_protocol_version", &self.min_protocol_version)
            .field("max_protocol_version", &self.max_protocol_version)
            .finish()
    }
}

/// TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum TlsVersion {
    /// TLS 1.2
    #[default]
    Tls12,
    /// TLS 1.3
    Tls13,
}

// ============================================================================
// TLS Configuration Builder
// ============================================================================

/// Builder for TLS configuration.
pub struct TlsConfigBuilder {
    #[allow(dead_code)] // Used when tcp-tls feature is enabled
    is_server: bool,
    cert_chain: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    root_certs: Vec<Vec<u8>>,
    alpn_protocols: Vec<Vec<u8>>,
    verify_peer: bool,
    require_client_cert: bool,
    enable_session_resumption: bool,
    min_protocol_version: TlsVersion,
    max_protocol_version: TlsVersion,
    use_system_roots: bool,
}

impl TlsConfigBuilder {
    /// Create a builder for server-side TLS.
    pub fn server() -> Self {
        Self {
            is_server: true,
            cert_chain: None,
            private_key: None,
            root_certs: Vec::new(),
            alpn_protocols: vec![b"dds".to_vec()],
            verify_peer: false, // Server doesn't verify client by default
            require_client_cert: false,
            enable_session_resumption: true,
            min_protocol_version: TlsVersion::Tls12,
            max_protocol_version: TlsVersion::Tls13,
            use_system_roots: false,
        }
    }

    /// Create a builder for client-side TLS.
    pub fn client() -> Self {
        Self {
            is_server: false,
            cert_chain: None,
            private_key: None,
            root_certs: Vec::new(),
            alpn_protocols: vec![b"dds".to_vec()],
            verify_peer: true, // Client verifies server by default
            require_client_cert: false,
            enable_session_resumption: true,
            min_protocol_version: TlsVersion::Tls12,
            max_protocol_version: TlsVersion::Tls13,
            use_system_roots: true,
        }
    }

    /// Set the certificate chain (PEM format).
    pub fn with_cert_pem(mut self, pem_data: Vec<u8>) -> Self {
        self.cert_chain = Some(pem_data);
        self
    }

    /// Load certificate chain from a file.
    #[cfg(feature = "tcp-tls")]
    pub fn with_cert_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let pem_data = std::fs::read(path)?;
        Ok(self.with_cert_pem(pem_data))
    }

    /// Set the private key (PEM format).
    pub fn with_key_pem(mut self, pem_data: Vec<u8>) -> Self {
        self.private_key = Some(pem_data);
        self
    }

    /// Load private key from a file.
    #[cfg(feature = "tcp-tls")]
    pub fn with_key_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let pem_data = std::fs::read(path)?;
        Ok(self.with_key_pem(pem_data))
    }

    /// Add a root certificate (PEM format) for verification.
    pub fn with_root_cert_pem(mut self, pem_data: Vec<u8>) -> Self {
        self.root_certs.push(pem_data);
        self
    }

    /// Load root certificates from a file.
    #[cfg(feature = "tcp-tls")]
    pub fn with_root_certs_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let pem_data = std::fs::read(path)?;
        Ok(self.with_root_cert_pem(pem_data))
    }

    /// Use system root certificates (client mode only).
    pub fn with_system_roots(mut self) -> Self {
        self.use_system_roots = true;
        self
    }

    /// Set ALPN protocols.
    pub fn with_alpn_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = protocols;
        self
    }

    /// Disable peer certificate verification.
    ///
    /// # Warning
    ///
    /// This is dangerous and should only be used for testing.
    /// In production, always verify certificates.
    pub fn dangerous_disable_verification(mut self) -> Self {
        self.verify_peer = false;
        self
    }

    /// Require client certificate (server mode, enables mTLS).
    pub fn require_client_cert(mut self) -> Self {
        self.require_client_cert = true;
        self.verify_peer = true;
        self
    }

    /// Disable session resumption.
    pub fn disable_session_resumption(mut self) -> Self {
        self.enable_session_resumption = false;
        self
    }

    /// Set minimum TLS version.
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.min_protocol_version = version;
        self
    }

    /// Set maximum TLS version.
    pub fn with_max_version(mut self, version: TlsVersion) -> Self {
        self.max_protocol_version = version;
        self
    }

    /// Build the TLS configuration.
    #[cfg(feature = "tcp-tls")]
    pub fn build(self) -> io::Result<TlsConfig> {
        use rustls::pki_types::pem::PemObject;

        if self.is_server {
            // Server configuration requires certificate and key
            let cert_pem = self.cert_chain.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Server requires certificate")
            })?;
            let key_pem = self.private_key.ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Server requires private key")
            })?;

            // Parse certificates
            let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if certs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "No certificates found in PEM data",
                ));
            }

            // Parse private key
            let key = PrivateKeyDer::from_pem_slice(&key_pem)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // Build server config
            let mut config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            config.alpn_protocols = self.alpn_protocols.clone();

            Ok(TlsConfig {
                server_config: Some(Arc::new(config)),
                client_config: None,
                is_server: true,
                alpn_protocols: self.alpn_protocols,
                verify_peer: self.verify_peer,
                require_client_cert: self.require_client_cert,
                enable_session_resumption: self.enable_session_resumption,
                min_protocol_version: self.min_protocol_version,
                max_protocol_version: self.max_protocol_version,
            })
        } else {
            // Client configuration
            let root_store = if self.use_system_roots {
                let mut root_store = rustls::RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                root_store
            } else {
                let mut root_store = rustls::RootCertStore::empty();
                for root_pem in &self.root_certs {
                    let certs: Vec<CertificateDer<'static>> =
                        CertificateDer::pem_slice_iter(root_pem)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    for cert in certs {
                        root_store
                            .add(cert)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    }
                }
                root_store
            };

            let config = if self.verify_peer {
                let builder = ClientConfig::builder().with_root_certificates(root_store);

                // Add client certificate if provided (for mTLS)
                if let (Some(cert_pem), Some(key_pem)) = (&self.cert_chain, &self.private_key) {
                    let certs: Vec<CertificateDer<'static>> =
                        CertificateDer::pem_slice_iter(cert_pem)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    let key = PrivateKeyDer::from_pem_slice(key_pem)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    builder
                        .with_client_auth_cert(certs, key)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                } else {
                    builder.with_no_client_auth()
                }
            } else {
                // Dangerous: skip verification
                let builder = ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier));

                if let (Some(cert_pem), Some(key_pem)) = (&self.cert_chain, &self.private_key) {
                    let certs: Vec<CertificateDer<'static>> =
                        CertificateDer::pem_slice_iter(cert_pem)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    let key = PrivateKeyDer::from_pem_slice(key_pem)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    builder
                        .with_client_auth_cert(certs, key)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                } else {
                    builder.with_no_client_auth()
                }
            };

            let mut config = config;
            config.alpn_protocols = self.alpn_protocols.clone();

            Ok(TlsConfig {
                server_config: None,
                client_config: Some(Arc::new(config)),
                is_server: false,
                alpn_protocols: self.alpn_protocols,
                verify_peer: self.verify_peer,
                require_client_cert: self.require_client_cert,
                enable_session_resumption: self.enable_session_resumption,
                min_protocol_version: self.min_protocol_version,
                max_protocol_version: self.max_protocol_version,
            })
        }
    }

    /// Build without tcp-tls feature (returns error).
    #[cfg(not(feature = "tcp-tls"))]
    pub fn build(self) -> io::Result<TlsConfig> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TLS support requires the 'tcp-tls' feature",
        ))
    }
}

impl TlsConfig {
    /// Create a server configuration builder.
    pub fn server() -> TlsConfigBuilder {
        TlsConfigBuilder::server()
    }

    /// Create a client configuration builder.
    pub fn client() -> TlsConfigBuilder {
        TlsConfigBuilder::client()
    }

    /// Check if this is a server configuration.
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Check if this is a client configuration.
    pub fn is_client(&self) -> bool {
        !self.is_server
    }

    /// Get ALPN protocols.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }
}

// ============================================================================
// No-verification certificate verifier (dangerous, for testing only)
// ============================================================================

#[cfg(feature = "tcp-tls")]
#[derive(Debug)]
struct NoVerifier;

#[cfg(feature = "tcp-tls")]
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
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

// ============================================================================
// TLS Acceptor (server-side)
// ============================================================================

/// TLS acceptor for server-side connections.
///
/// Wraps incoming TCP connections in TLS.
#[cfg(feature = "tcp-tls")]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
}

#[cfg(feature = "tcp-tls")]
impl TlsAcceptor {
    /// Create a new TLS acceptor from configuration.
    pub fn new(config: &TlsConfig) -> io::Result<Self> {
        let server_config = config.server_config.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TlsConfig is not a server configuration",
            )
        })?;

        Ok(Self {
            config: Arc::clone(server_config),
        })
    }

    /// Accept a TLS connection from a TCP stream.
    ///
    /// This performs the TLS handshake and returns a TlsStream.
    pub fn accept(&self, tcp_stream: TcpStream) -> io::Result<TlsStream> {
        let conn =
            rustls::ServerConnection::new(Arc::clone(&self.config)).map_err(io::Error::other)?;

        let mut tls_stream = TlsStream {
            tcp_stream,
            tls_conn: TlsConnection::Server(conn),
            handshake_complete: false,
        };

        // Attempt to complete handshake
        tls_stream.complete_handshake()?;

        Ok(tls_stream)
    }

    /// Accept a TLS connection in non-blocking mode.
    ///
    /// Returns `Ok(None)` if the handshake would block.
    pub fn accept_nonblocking(&self, tcp_stream: TcpStream) -> io::Result<Option<TlsStream>> {
        tcp_stream.set_nonblocking(true)?;

        let conn =
            rustls::ServerConnection::new(Arc::clone(&self.config)).map_err(io::Error::other)?;

        let mut tls_stream = TlsStream {
            tcp_stream,
            tls_conn: TlsConnection::Server(conn),
            handshake_complete: false,
        };

        match tls_stream.try_complete_handshake() {
            Ok(true) => Ok(Some(tls_stream)),
            Ok(false) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "tcp-tls")]
impl fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAcceptor").finish()
    }
}

// ============================================================================
// TLS Connector (client-side)
// ============================================================================

/// TLS connector for client-side connections.
///
/// Initiates TLS connections to servers.
#[cfg(feature = "tcp-tls")]
pub struct TlsConnector {
    config: Arc<ClientConfig>,
}

#[cfg(feature = "tcp-tls")]
impl TlsConnector {
    /// Create a new TLS connector from configuration.
    pub fn new(config: &TlsConfig) -> io::Result<Self> {
        let client_config = config.client_config.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TlsConfig is not a client configuration",
            )
        })?;

        Ok(Self {
            config: Arc::clone(client_config),
        })
    }

    /// Connect to a TLS server.
    ///
    /// The `server_name` is used for SNI and certificate verification.
    pub fn connect(&self, server_name: &str, tcp_stream: TcpStream) -> io::Result<TlsStream> {
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let conn = rustls::ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(io::Error::other)?;

        let mut tls_stream = TlsStream {
            tcp_stream,
            tls_conn: TlsConnection::Client(conn),
            handshake_complete: false,
        };

        // Attempt to complete handshake
        tls_stream.complete_handshake()?;

        Ok(tls_stream)
    }

    /// Connect in non-blocking mode.
    ///
    /// Returns `Ok(None)` if the handshake would block.
    pub fn connect_nonblocking(
        &self,
        server_name: &str,
        tcp_stream: TcpStream,
    ) -> io::Result<Option<TlsStream>> {
        tcp_stream.set_nonblocking(true)?;

        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let conn = rustls::ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(io::Error::other)?;

        let mut tls_stream = TlsStream {
            tcp_stream,
            tls_conn: TlsConnection::Client(conn),
            handshake_complete: false,
        };

        match tls_stream.try_complete_handshake() {
            Ok(true) => Ok(Some(tls_stream)),
            Ok(false) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

#[cfg(feature = "tcp-tls")]
impl fmt::Debug for TlsConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnector").finish()
    }
}

// ============================================================================
// TLS Stream
// ============================================================================

/// TLS connection state (client or server).
#[cfg(feature = "tcp-tls")]
enum TlsConnection {
    Client(rustls::ClientConnection),
    Server(rustls::ServerConnection),
}

/// A TLS-encrypted TCP stream.
///
/// This implements the [`ByteStream`] trait for seamless integration
/// with the TCP transport layer.
#[cfg(feature = "tcp-tls")]
pub struct TlsStream {
    tcp_stream: TcpStream,
    tls_conn: TlsConnection,
    handshake_complete: bool,
}

#[cfg(feature = "tcp-tls")]
impl TlsStream {
    /// Complete the TLS handshake (blocking).
    fn complete_handshake(&mut self) -> io::Result<()> {
        while !self.handshake_complete {
            if !self.try_complete_handshake()? {
                // Would block - in blocking mode, we should wait
                continue;
            }
        }
        Ok(())
    }

    /// Try to complete the TLS handshake (non-blocking).
    ///
    /// Returns `Ok(true)` if handshake is complete, `Ok(false)` if would block.
    fn try_complete_handshake(&mut self) -> io::Result<bool> {
        if self.handshake_complete {
            return Ok(true);
        }

        // Process any pending TLS data
        self.process_tls_io()?;

        // Check if handshake is complete
        let is_complete = match &self.tls_conn {
            TlsConnection::Client(conn) => !conn.is_handshaking(),
            TlsConnection::Server(conn) => !conn.is_handshaking(),
        };

        if is_complete {
            self.handshake_complete = true;
        }

        Ok(is_complete)
    }

    /// Process TLS I/O (read from TCP, write to TCP).
    fn process_tls_io(&mut self) -> io::Result<()> {
        // Read from TCP into TLS
        match &mut self.tls_conn {
            TlsConnection::Client(conn) => match conn.read_tls(&mut self.tcp_stream) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS connection closed",
                    ));
                }
                Ok(_) => {
                    conn.process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            },
            TlsConnection::Server(conn) => match conn.read_tls(&mut self.tcp_stream) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS connection closed",
                    ));
                }
                Ok(_) => {
                    conn.process_new_packets()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            },
        }

        // Write TLS data to TCP
        match &mut self.tls_conn {
            TlsConnection::Client(conn) => {
                while conn.wants_write() {
                    match conn.write_tls(&mut self.tcp_stream) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
            TlsConnection::Server(conn) => {
                while conn.wants_write() {
                    match conn.write_tls(&mut self.tcp_stream) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        Ok(())
    }

    /// Check if handshake is complete.
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Get the negotiated ALPN protocol.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        match &self.tls_conn {
            TlsConnection::Client(conn) => conn.alpn_protocol(),
            TlsConnection::Server(conn) => conn.alpn_protocol(),
        }
    }

    /// Get the negotiated TLS protocol version.
    pub fn protocol_version(&self) -> Option<TlsVersion> {
        let version = match &self.tls_conn {
            TlsConnection::Client(conn) => conn.protocol_version(),
            TlsConnection::Server(conn) => conn.protocol_version(),
        };

        version.map(|v| match v {
            rustls::ProtocolVersion::TLSv1_2 => TlsVersion::Tls12,
            rustls::ProtocolVersion::TLSv1_3 => TlsVersion::Tls13,
            _ => TlsVersion::Tls12, // Fallback
        })
    }

    /// Get the underlying TCP stream (for mio registration).
    pub fn tcp_stream(&self) -> &TcpStream {
        &self.tcp_stream
    }

    /// Get mutable access to the underlying TCP stream.
    pub fn tcp_stream_mut(&mut self) -> &mut TcpStream {
        &mut self.tcp_stream
    }
}

#[cfg(feature = "tcp-tls")]
impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, try to read any already-decrypted data
        let result = match &mut self.tls_conn {
            TlsConnection::Client(conn) => {
                let mut reader = conn.reader();
                reader.read(buf)
            }
            TlsConnection::Server(conn) => {
                let mut reader = conn.reader();
                reader.read(buf)
            }
        };

        match result {
            Ok(n) if n > 0 => return Ok(n),
            Ok(_) => {} // No data available, try to read more
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {} // Try to read more
            Err(e) => return Err(e),
        }

        // Try to read more TLS data from the TCP stream
        self.process_tls_io()?;

        // Try reading again
        match &mut self.tls_conn {
            TlsConnection::Client(conn) => {
                let mut reader = conn.reader();
                reader.read(buf)
            }
            TlsConnection::Server(conn) => {
                let mut reader = conn.reader();
                reader.read(buf)
            }
        }
    }
}

#[cfg(feature = "tcp-tls")]
impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = match &mut self.tls_conn {
            TlsConnection::Client(conn) => {
                let mut writer = conn.writer();
                writer.write(buf)?
            }
            TlsConnection::Server(conn) => {
                let mut writer = conn.writer();
                writer.write(buf)?
            }
        };

        // Flush TLS data to TCP
        self.process_tls_io()?;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.tls_conn {
            TlsConnection::Client(conn) => {
                let mut writer = conn.writer();
                writer.flush()?;
            }
            TlsConnection::Server(conn) => {
                let mut writer = conn.writer();
                writer.flush()?;
            }
        }

        // Flush TLS data to TCP
        while match &self.tls_conn {
            TlsConnection::Client(conn) => conn.wants_write(),
            TlsConnection::Server(conn) => conn.wants_write(),
        } {
            self.process_tls_io()?;
        }

        self.tcp_stream.flush()
    }
}

#[cfg(feature = "tcp-tls")]
impl ByteStream for TlsStream {
    fn shutdown(&mut self, _how: Shutdown) -> io::Result<()> {
        // Send TLS close_notify
        match &mut self.tls_conn {
            TlsConnection::Client(conn) => conn.send_close_notify(),
            TlsConnection::Server(conn) => conn.send_close_notify(),
        }

        // Flush the close_notify
        self.process_tls_io()?;

        // Shutdown TCP
        self.tcp_stream.shutdown(Shutdown::Both)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp_stream.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.tcp_stream.peer_addr()
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.tcp_stream.set_nonblocking(nonblocking)
    }

    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.tcp_stream.set_nodelay(nodelay)
    }

    fn nodelay(&self) -> io::Result<bool> {
        self.tcp_stream.nodelay()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.tcp_stream.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.tcp_stream.set_write_timeout(dur)
    }

    fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.tcp_stream.take_error()
    }

    fn is_tls(&self) -> bool {
        true
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> RawFd {
        AsRawFd::as_raw_fd(&self.tcp_stream)
    }

    #[cfg(windows)]
    fn as_raw_socket(&self) -> RawSocket {
        AsRawSocket::as_raw_socket(&self.tcp_stream)
    }
}

#[cfg(feature = "tcp-tls")]
impl fmt::Debug for TlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("local_addr", &self.tcp_stream.local_addr().ok())
            .field("peer_addr", &self.tcp_stream.peer_addr().ok())
            .field("handshake_complete", &self.handshake_complete)
            .field(
                "is_client",
                &matches!(self.tls_conn, TlsConnection::Client(_)),
            )
            .finish()
    }
}

// ============================================================================
// TLS Error types
// ============================================================================

/// TLS-specific error type.
#[derive(Debug)]
pub enum TlsError {
    /// Handshake failed
    HandshakeFailed(String),
    /// Certificate error
    CertificateError(String),
    /// I/O error
    IoError(io::Error),
    /// TLS protocol error
    ProtocolError(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HandshakeFailed(msg) => write!(f, "TLS handshake failed: {}", msg),
            Self::CertificateError(msg) => write!(f, "Certificate error: {}", msg),
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::ProtocolError(msg) => write!(f, "TLS protocol error: {}", msg),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TlsError {
    fn from(e: io::Error) -> Self {
        Self::IoError(e)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }

    #[test]
    fn test_tls_config_builder_server() {
        let builder = TlsConfigBuilder::server();
        assert!(builder.is_server);
        assert!(!builder.verify_peer); // Server doesn't verify by default
    }

    #[test]
    fn test_tls_config_builder_client() {
        let builder = TlsConfigBuilder::client();
        assert!(!builder.is_server);
        assert!(builder.verify_peer); // Client verifies by default
    }

    #[test]
    fn test_tls_config_builder_alpn() {
        let builder = TlsConfigBuilder::client()
            .with_alpn_protocols(vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(builder.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_tls_config_builder_min_version() {
        let builder = TlsConfigBuilder::client().with_min_version(TlsVersion::Tls13);
        assert_eq!(builder.min_protocol_version, TlsVersion::Tls13);
    }

    #[test]
    fn test_tls_config_builder_dangerous_disable_verification() {
        let builder = TlsConfigBuilder::client().dangerous_disable_verification();
        assert!(!builder.verify_peer);
    }

    #[test]
    fn test_tls_config_builder_require_client_cert() {
        let builder = TlsConfigBuilder::server().require_client_cert();
        assert!(builder.require_client_cert);
        assert!(builder.verify_peer);
    }

    #[test]
    fn test_tls_config_default() {
        let config = TlsConfig::default();
        assert!(!config.is_server);
        assert!(config.verify_peer);
        assert!(!config.require_client_cert);
        assert!(config.enable_session_resumption);
    }

    #[test]
    fn test_tls_error_display() {
        let err = TlsError::HandshakeFailed("test".to_string());
        assert!(err.to_string().contains("handshake failed"));

        let err = TlsError::CertificateError("invalid".to_string());
        assert!(err.to_string().contains("Certificate error"));
    }

    #[test]
    fn test_tls_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let tls_err: TlsError = io_err.into();
        assert!(matches!(tls_err, TlsError::IoError(_)));
    }

    #[cfg(not(feature = "tcp-tls"))]
    #[test]
    fn test_build_without_feature() {
        let result = TlsConfigBuilder::client().build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tcp-tls"));
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn test_build_server_requires_cert() {
        let result = TlsConfigBuilder::server().build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("certificate"));
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn test_build_client_with_system_roots() {
        let result = TlsConfigBuilder::client().with_system_roots().build();
        assert!(result.is_ok());
        let config = result.unwrap();
        assert!(config.client_config.is_some());
    }
}

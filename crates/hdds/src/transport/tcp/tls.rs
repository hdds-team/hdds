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
//! - **Server and client modes**: Full support for both TLS server and client roles,
//!   and a combined peer configuration ([`TlsConfig::peer`]) for participants that
//!   both accept and initiate connections (`TcpRole::Auto`).
//! - **Certificate validation**: Configurable certificate chain and private key
//! - **ALPN support**: Application-Layer Protocol Negotiation for DDS
//! - **mTLS support**: Mutual TLS with client certificate verification. When
//!   [`TlsConfigBuilder::require_client_cert`] is set the server verifies every
//!   client certificate against the configured client CA and refuses anonymous
//!   clients and clients issued by any other CA.
//! - **CRL revocation**: Optional certificate revocation lists
//!   ([`TlsConfigBuilder::with_crl_pem`]) checked during client authentication.
//!   OCSP is not supported.
//!
//! # Example
//!
//! ```ignore
//! use hdds::transport::tcp::tls::{TlsConfig, TlsAcceptor, TlsConnector};
//!
//! // Server-side TLS
//! let server_config = TlsConfig::server()
//!     .with_cert_file("server.crt")?
//!     .with_key_file("server.key")?
//!     .build()?;
//! let acceptor = TlsAcceptor::new(&server_config)?;
//! let tls_stream = acceptor.accept(tcp_stream)?;
//!
//! // Server-side mutual TLS: the client CA is mandatory
//! let mtls_config = TlsConfig::server()
//!     .with_cert_file("server.crt")?
//!     .with_key_file("server.key")?
//!     .require_client_cert()
//!     .with_root_certs_file("client-ca.crt")?
//!     .build()?;
//!
//! // Client-side TLS against a private CA
//! let client_config = TlsConfig::client()
//!     .with_root_certs_file("ca.crt")?
//!     .build()?;
//! let connector = TlsConnector::new(&client_config)?;
//! let tls_stream = connector.connect("server.example.com", tcp_stream)?;
//! ```
//!
//! # Fail-closed configuration rules
//!
//! Every ambiguity is a build error ([`TlsBuildError`]) instead of a silently
//! weaker configuration:
//!
//! - `require_client_cert()` without a client CA
//!   (`with_root_cert_pem` / `with_root_certs_file`) refuses to build.
//! - A client CA or CRL on a server that did not call `require_client_cert()`
//!   refuses to build (nothing is silently ignored).
//! - `with_system_roots()` on a server refuses to build: public web roots are
//!   not a client-authentication policy.
//! - `dangerous_disable_verification()` combined with `require_client_cert()`
//!   refuses to build.
//! - A client that verifies the server but has an empty trust store refuses to
//!   build. Explicit root certificates always win over system roots.
//! - Explicit root certificates combined with `dangerous_disable_verification()`
//!   refuse to build; with verification off the configuration reports zero
//!   trust anchors.
//! - A client identity needs both certificate and key; one without the other
//!   refuses to build.
//! - [`TlsConfig::peer`] refuses an mTLS server half combined with a client
//!   half that presents no certificate (such a participant could never pair
//!   with its own kind), and refuses version bounds whose intersection is
//!   empty.
//!
//! # Security Notes
//!
//! - By default, client connections verify server certificates against system roots
//!   unless a private CA is configured, in which case only that CA is trusted
//! - Server connections require explicit certificate configuration
//! - Use `dangerous_disable_verification()` only for testing (not in production)
//! - Under TLS 1.3 the client finishes its side of the handshake before the server
//!   verifies the client certificate: a rejected HDDS client observes `Connected`
//!   followed immediately by `Disconnected`. No application data is ever delivered
//!   on a rejected connection.
//! - The HDDS I/O thread uses the peer IP address as SNI, so HDDS-to-HDDS server
//!   certificates need an IP subject alternative name.
//! - `with_min_version` / `with_max_version` bound the protocol versions offered
//!   to rustls (default TLS 1.2 to TLS 1.3; an inverted range is a build error)
//! - `disable_session_resumption()` removes server session storage and TLS 1.3
//!   tickets on a server and ticket/session reuse on a client, so every
//!   connection runs a full handshake

use std::fmt;
use std::io::{self};
#[cfg(feature = "tcp-tls")]
use std::io::{Read, Write};
#[cfg(feature = "tcp-tls")]
use std::net::{Shutdown, SocketAddr, TcpStream};
#[cfg(feature = "tcp-tls")]
use std::sync::Arc;
#[cfg(feature = "tcp-tls")]
use std::time::{Duration, Instant};

#[cfg(feature = "tcp-tls")]
use std::path::Path;

#[cfg(all(unix, feature = "tcp-tls"))]
use std::os::unix::io::{AsRawFd, RawFd};

#[cfg(all(windows, feature = "tcp-tls"))]
use std::os::windows::io::{AsRawSocket, RawSocket};

#[cfg(feature = "tcp-tls")]
use super::byte_stream::ByteStream;

#[cfg(feature = "tcp-tls")]
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName};

#[cfg(feature = "tcp-tls")]
use rustls::{ClientConfig, RootCertStore, ServerConfig};

// ============================================================================
// TLS build errors (typed)
// ============================================================================

/// Typed error returned by [`TlsConfigBuilder::try_build`] and [`TlsConfig::peer`].
///
/// [`TlsConfigBuilder::build`] wraps the same value in an [`io::Error`]; the
/// typed value is reachable through `io::Error::get_ref` + `downcast_ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsBuildError {
    /// The crate was built without the `tcp-tls` feature.
    FeatureDisabled,
    /// A server configuration needs a certificate chain.
    MissingCertificate,
    /// A server configuration needs a private key.
    MissingPrivateKey,
    /// The certificate PEM contained no certificate.
    NoCertificatesInPem,
    /// The certificate chain PEM could not be parsed.
    InvalidCertificatePem(String),
    /// The private key PEM could not be parsed.
    InvalidPrivateKeyPem(String),
    /// A root certificate PEM could not be parsed or added to the trust store.
    InvalidRootCertificatePem(String),
    /// A certificate revocation list PEM could not be parsed.
    InvalidCrlPem(String),
    /// `require_client_cert()` was set but no client CA was configured.
    RequireClientCertWithoutClientCa,
    /// A client CA was configured on a server that does not require client certificates.
    ClientCaWithoutRequireClientCert,
    /// A CRL was configured on a server that does not require client certificates.
    CrlWithoutRequireClientCert,
    /// `with_system_roots()` was called on a server builder.
    SystemRootsOnServer,
    /// `dangerous_disable_verification()` and `require_client_cert()` were both set.
    VerificationDisabledWithRequireClientCert,
    /// `require_client_cert()` was called on a client builder.
    RequireClientCertOnClient,
    /// A client configured trust material and then disabled verification.
    RootsWithVerificationDisabled,
    /// The client verifies the server but has no trust anchor at all.
    EmptyClientRootStore,
    /// A client identity has a certificate without a key or a key without a certificate.
    ClientIdentityIncomplete,
    /// [`TlsConfig::peer`] was given configurations with the wrong roles.
    PeerRoleMismatch,
    /// [`TlsConfig::peer`] was given configurations with different ALPN lists.
    PeerAlpnMismatch,
    /// [`TlsConfig::peer`] was given an mTLS server half and a client half
    /// that presents no certificate.
    PeerMtlsWithoutClientIdentity,
    /// `with_min_version` is above `with_max_version`.
    InvalidProtocolVersionRange {
        /// Configured minimum.
        min: TlsVersion,
        /// Configured maximum.
        max: TlsVersion,
    },
    /// rustls refused the configuration.
    Rustls(String),
}

impl fmt::Display for TlsBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FeatureDisabled => write!(f, "TLS support requires the 'tcp-tls' feature"),
            Self::MissingCertificate => write!(f, "Server requires certificate"),
            Self::MissingPrivateKey => write!(f, "Server requires private key"),
            Self::NoCertificatesInPem => write!(f, "No certificates found in PEM data"),
            Self::InvalidCertificatePem(e) => write!(f, "invalid certificate PEM: {}", e),
            Self::InvalidPrivateKeyPem(e) => write!(f, "invalid private key PEM: {}", e),
            Self::InvalidRootCertificatePem(e) => {
                write!(f, "invalid root certificate PEM: {}", e)
            }
            Self::InvalidCrlPem(e) => write!(f, "invalid CRL PEM: {}", e),
            Self::RequireClientCertWithoutClientCa => write!(
                f,
                "require_client_cert set but no client CA configured; \
                 use with_root_cert_pem or with_root_certs_file"
            ),
            Self::ClientCaWithoutRequireClientCert => {
                write!(f, "client CA configured but require_client_cert() not set")
            }
            Self::CrlWithoutRequireClientCert => {
                write!(f, "CRL configured but require_client_cert() not set")
            }
            Self::SystemRootsOnServer => write!(
                f,
                "with_system_roots() is not a client-authentication policy; \
                 configure an explicit client CA"
            ),
            Self::VerificationDisabledWithRequireClientCert => write!(
                f,
                "dangerous_disable_verification() cannot be combined with require_client_cert()"
            ),
            Self::RequireClientCertOnClient => {
                write!(
                    f,
                    "require_client_cert() applies to server configurations only"
                )
            }
            Self::RootsWithVerificationDisabled => write!(
                f,
                "root certificates configured but dangerous_disable_verification() \
                 was called: the trust material would be silently ignored"
            ),
            Self::EmptyClientRootStore => write!(
                f,
                "client verifies the server but has no trust anchor; \
                 use with_root_cert_pem, with_root_certs_file or with_system_roots"
            ),
            Self::ClientIdentityIncomplete => write!(
                f,
                "client identity needs both a certificate and a private key"
            ),
            Self::PeerRoleMismatch => write!(
                f,
                "TlsConfig::peer needs a server configuration and a client configuration"
            ),
            Self::PeerAlpnMismatch => write!(
                f,
                "TlsConfig::peer needs identical ALPN lists on both configurations"
            ),
            Self::PeerMtlsWithoutClientIdentity => write!(
                f,
                "TlsConfig::peer with require_client_cert() needs a client half \
                 carrying a client certificate and key"
            ),
            Self::InvalidProtocolVersionRange { min, max } => write!(
                f,
                "TLS minimum version {:?} is above maximum version {:?}",
                min, max
            ),
            Self::Rustls(e) => write!(f, "rustls configuration error: {}", e),
        }
    }
}

impl std::error::Error for TlsBuildError {}

impl From<TlsBuildError> for io::Error {
    fn from(e: TlsBuildError) -> Self {
        let kind = match &e {
            TlsBuildError::FeatureDisabled => io::ErrorKind::Unsupported,
            TlsBuildError::InvalidCertificatePem(_)
            | TlsBuildError::InvalidPrivateKeyPem(_)
            | TlsBuildError::InvalidRootCertificatePem(_)
            | TlsBuildError::InvalidCrlPem(_)
            | TlsBuildError::Rustls(_) => io::ErrorKind::InvalidData,
            _ => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, e)
    }
}

// ============================================================================
// TLS Configuration
// ============================================================================

/// TLS configuration for TCP transport.
///
/// This struct holds all the configuration needed to establish TLS connections,
/// including certificates, private keys, and verification settings.
///
/// A configuration is a server configuration ([`TlsConfig::server`]), a client
/// configuration ([`TlsConfig::client`]) or a peer configuration carrying both
/// ([`TlsConfig::peer`]).
#[derive(Clone)]
pub struct TlsConfig {
    /// Server-side configuration (for accepting connections)
    #[cfg(feature = "tcp-tls")]
    pub(crate) server_config: Option<Arc<ServerConfig>>,

    /// Client-side configuration (for initiating connections)
    #[cfg(feature = "tcp-tls")]
    pub(crate) client_config: Option<Arc<ClientConfig>>,

    /// Whether this configuration can accept connections (server or peer)
    pub(crate) is_server: bool,

    /// Whether this configuration carries both roles ([`TlsConfig::peer`])
    pub(crate) is_peer: bool,

    /// ALPN protocols to advertise
    pub(crate) alpn_protocols: Vec<Vec<u8>>,

    /// Whether to verify peer certificates (client mode)
    pub(crate) verify_peer: bool,

    /// Whether to require client certificates (server mode, mTLS)
    pub(crate) require_client_cert: bool,

    /// Number of trust anchors resolved at build time
    /// (client CA certificates on a server, server roots on a client)
    pub(crate) trust_anchor_count: usize,

    /// Number of certificate revocation lists resolved at build time
    pub(crate) crl_count: usize,

    /// Whether the client half presents a client-authentication certificate
    /// (set on client and peer configurations, always false on a server)
    pub(crate) has_client_identity: bool,

    /// Session resumption enabled (applied to the rustls configuration at build)
    pub(crate) enable_session_resumption: bool,

    /// TLS version bounds (applied to the rustls configuration at build)
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
            is_peer: false,
            alpn_protocols: vec![b"dds".to_vec()],
            verify_peer: true,
            require_client_cert: false,
            trust_anchor_count: 0,
            crl_count: 0,
            has_client_identity: false,
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
            .field("is_peer", &self.is_peer)
            .field("alpn_protocols", &self.alpn_protocols.len())
            .field("verify_peer", &self.verify_peer)
            .field("require_client_cert", &self.require_client_cert)
            .field("trust_anchor_count", &self.trust_anchor_count)
            .field("crl_count", &self.crl_count)
            .field("has_client_identity", &self.has_client_identity)
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

/// The PEM private key buffer: wiped on drop with `tcp-tls`, which provides
/// `zeroize`; a plain vector without it.
#[cfg(feature = "tcp-tls")]
type PrivateKeyPem = zeroize::Zeroizing<Vec<u8>>;
#[cfg(not(feature = "tcp-tls"))]
type PrivateKeyPem = Vec<u8>;

#[cfg(feature = "tcp-tls")]
fn private_key_pem(bytes: Vec<u8>) -> PrivateKeyPem {
    zeroize::Zeroizing::new(bytes)
}

#[cfg(not(feature = "tcp-tls"))]
fn private_key_pem(bytes: Vec<u8>) -> PrivateKeyPem {
    bytes
}

/// Builder for TLS configuration.
pub struct TlsConfigBuilder {
    #[allow(dead_code)] // Used when tcp-tls feature is enabled
    is_server: bool,
    cert_chain: Option<Vec<u8>>,
    /// PEM private key. Wiped when the builder, or the config built from it, drops.
    private_key: Option<PrivateKeyPem>,
    root_certs: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
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
            crls: Vec::new(),
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
            crls: Vec::new(),
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
        self.private_key = Some(private_key_pem(pem_data));
        self
    }

    /// Load private key from a file.
    #[cfg(feature = "tcp-tls")]
    pub fn with_key_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let pem_data = std::fs::read(path)?;
        Ok(self.with_key_pem(pem_data))
    }

    /// Add a root certificate (PEM format) for verification.
    ///
    /// On a client this is the CA that issued the server certificate; explicit
    /// roots take precedence over system roots. On a server this is the client
    /// CA and requires [`require_client_cert`](Self::require_client_cert).
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

    /// Add a certificate revocation list (PEM format) for client authentication.
    ///
    /// Server mode only, requires [`require_client_cert`](Self::require_client_cert).
    /// Every certificate in the client chain (except the trust anchor) must have a
    /// known revocation status; an expired CRL (`nextUpdate` in the past) is an error.
    pub fn with_crl_pem(mut self, pem_data: Vec<u8>) -> Self {
        self.crls.push(pem_data);
        self
    }

    /// Load a certificate revocation list from a file.
    #[cfg(feature = "tcp-tls")]
    pub fn with_crl_file(self, path: impl AsRef<Path>) -> io::Result<Self> {
        let pem_data = std::fs::read(path)?;
        Ok(self.with_crl_pem(pem_data))
    }

    /// Use system root certificates (client mode only).
    ///
    /// Explicit root certificates, when present, take precedence.
    pub fn with_system_roots(mut self) -> Self {
        self.use_system_roots = true;
        self
    }

    /// Do not use system root certificates (client mode).
    ///
    /// Combined with peer verification and no explicit root certificate the
    /// configuration refuses to build ([`TlsBuildError::EmptyClientRootStore`]).
    pub fn without_system_roots(mut self) -> Self {
        self.use_system_roots = false;
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
    /// Combined with [`require_client_cert`](Self::require_client_cert) the
    /// configuration refuses to build.
    pub fn dangerous_disable_verification(mut self) -> Self {
        self.verify_peer = false;
        self
    }

    /// Require client certificate (server mode, enables mTLS).
    ///
    /// The client CA must be configured with
    /// [`with_root_cert_pem`](Self::with_root_cert_pem) or
    /// [`with_root_certs_file`](Self::with_root_certs_file); anonymous clients and
    /// clients issued by any other CA are refused at handshake time.
    pub fn require_client_cert(mut self) -> Self {
        self.require_client_cert = true;
        self.verify_peer = true;
        self
    }

    /// Disable session resumption.
    ///
    /// A server built with this flag stores no sessions and sends no TLS 1.3
    /// tickets; a client built with it never offers a previous session. Every
    /// connection then runs a full handshake.
    pub fn disable_session_resumption(mut self) -> Self {
        self.enable_session_resumption = false;
        self
    }

    /// Set minimum TLS version (default TLS 1.2).
    ///
    /// Applied to the rustls protocol-version list at build time; a minimum
    /// above the maximum is refused by `build()`.
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.min_protocol_version = version;
        self
    }

    /// Set maximum TLS version (default TLS 1.3).
    ///
    /// Applied to the rustls protocol-version list at build time; a maximum
    /// below the minimum is refused by `build()`.
    pub fn with_max_version(mut self, version: TlsVersion) -> Self {
        self.max_protocol_version = version;
        self
    }

    /// Build the TLS configuration.
    ///
    /// Configuration mistakes are reported as [`io::Error`] wrapping a
    /// [`TlsBuildError`]; see [`try_build`](Self::try_build) for the typed form.
    pub fn build(self) -> io::Result<TlsConfig> {
        self.try_build().map_err(io::Error::from)
    }

    /// Build the TLS configuration with a typed error.
    #[cfg(feature = "tcp-tls")]
    pub fn try_build(self) -> Result<TlsConfig, TlsBuildError> {
        if self.is_server {
            self.build_server()
        } else {
            self.build_client()
        }
    }

    /// Build without tcp-tls feature (returns error).
    #[cfg(not(feature = "tcp-tls"))]
    pub fn try_build(self) -> Result<TlsConfig, TlsBuildError> {
        Err(TlsBuildError::FeatureDisabled)
    }

    #[cfg(feature = "tcp-tls")]
    fn build_server(self) -> Result<TlsConfig, TlsBuildError> {
        use rustls::server::WebPkiClientVerifier;

        if self.use_system_roots {
            return Err(TlsBuildError::SystemRootsOnServer);
        }

        // Server configuration requires certificate and key
        let cert_pem = self
            .cert_chain
            .as_ref()
            .ok_or(TlsBuildError::MissingCertificate)?;
        let key_pem = self
            .private_key
            .as_ref()
            .ok_or(TlsBuildError::MissingPrivateKey)?;

        let certs = parse_cert_chain(cert_pem)?;
        let key = parse_private_key(key_pem)?;

        // Resolve the client-authentication policy ONCE, here (cold path).
        let (verifier, trust_anchor_count, crl_count) = if self.require_client_cert {
            if !self.verify_peer {
                return Err(TlsBuildError::VerificationDisabledWithRequireClientCert);
            }
            let roots = parse_root_store(&self.root_certs)?;
            if roots.is_empty() {
                return Err(TlsBuildError::RequireClientCertWithoutClientCa);
            }
            let crls = parse_crls(&self.crls)?;
            let trust_anchor_count = roots.len();
            let crl_count = crls.len();
            let verifier =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto_provider())
                    .with_crls(crls)
                    .enforce_revocation_expiration()
                    .build()
                    .map_err(|e| TlsBuildError::Rustls(e.to_string()))?;
            (verifier, trust_anchor_count, crl_count)
        } else {
            if !self.root_certs.is_empty() {
                return Err(TlsBuildError::ClientCaWithoutRequireClientCert);
            }
            if !self.crls.is_empty() {
                return Err(TlsBuildError::CrlWithoutRequireClientCert);
            }
            (WebPkiClientVerifier::no_client_auth(), 0, 0)
        };

        // Build server config
        let versions = protocol_versions(self.min_protocol_version, self.max_protocol_version)?;
        let mut config = ServerConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(&versions)
            .map_err(|e| TlsBuildError::Rustls(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| TlsBuildError::Rustls(e.to_string()))?;

        config.alpn_protocols = self.alpn_protocols.clone();
        if !self.enable_session_resumption {
            // No stored sessions, no TLS 1.3 tickets: every connection is a
            // full handshake and there is nothing for a client to replay.
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
        }

        Ok(TlsConfig {
            server_config: Some(Arc::new(config)),
            client_config: None,
            is_server: true,
            is_peer: false,
            alpn_protocols: self.alpn_protocols,
            verify_peer: self.verify_peer,
            require_client_cert: self.require_client_cert,
            trust_anchor_count,
            crl_count,
            has_client_identity: false,
            enable_session_resumption: self.enable_session_resumption,
            min_protocol_version: self.min_protocol_version,
            max_protocol_version: self.max_protocol_version,
        })
    }

    #[cfg(feature = "tcp-tls")]
    fn build_client(self) -> Result<TlsConfig, TlsBuildError> {
        if self.require_client_cert {
            return Err(TlsBuildError::RequireClientCertOnClient);
        }

        // Explicit trust material plus disabled verification is an ambiguity,
        // not a weaker configuration: the roots would be dropped on the floor
        // while the config still advertised them. (System roots are the client
        // default, so only explicitly configured roots are a signal here.)
        if !self.verify_peer && !self.root_certs.is_empty() {
            return Err(TlsBuildError::RootsWithVerificationDisabled);
        }

        // Explicit roots win over system roots.
        let root_store = if !self.root_certs.is_empty() {
            parse_root_store(&self.root_certs)?
        } else if self.use_system_roots {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            root_store
        } else {
            RootCertStore::empty()
        };
        // Nothing is trusted when verification is disabled: never report a
        // trust anchor the handshake will not consult.
        let trust_anchor_count = if self.verify_peer {
            root_store.len()
        } else {
            0
        };

        // Client identity (for mTLS): both halves or none.
        let identity = match (&self.cert_chain, &self.private_key) {
            (Some(cert_pem), Some(key_pem)) => {
                Some((parse_cert_chain(cert_pem)?, parse_private_key(key_pem)?))
            }
            (None, None) => None,
            _ => return Err(TlsBuildError::ClientIdentityIncomplete),
        };
        let identity_present = identity.is_some();

        let versions = protocol_versions(self.min_protocol_version, self.max_protocol_version)?;
        let builder = ClientConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(&versions)
            .map_err(|e| TlsBuildError::Rustls(e.to_string()))?;

        let config = if self.verify_peer {
            if root_store.is_empty() {
                return Err(TlsBuildError::EmptyClientRootStore);
            }
            let builder = builder.with_root_certificates(root_store);
            match identity {
                Some((certs, key)) => builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| TlsBuildError::Rustls(e.to_string()))?,
                None => builder.with_no_client_auth(),
            }
        } else {
            // Dangerous: skip verification
            let builder = builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier));
            match identity {
                Some((certs, key)) => builder
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| TlsBuildError::Rustls(e.to_string()))?,
                None => builder.with_no_client_auth(),
            }
        };

        let mut config = config;
        config.alpn_protocols = self.alpn_protocols.clone();
        if !self.enable_session_resumption {
            config.resumption = rustls::client::Resumption::disabled();
        }

        Ok(TlsConfig {
            server_config: None,
            client_config: Some(Arc::new(config)),
            is_server: false,
            is_peer: false,
            alpn_protocols: self.alpn_protocols,
            verify_peer: self.verify_peer,
            require_client_cert: false,
            trust_anchor_count,
            crl_count: 0,
            has_client_identity: identity_present,
            enable_session_resumption: self.enable_session_resumption,
            min_protocol_version: self.min_protocol_version,
            max_protocol_version: self.max_protocol_version,
        })
    }
}

// ============================================================================
// PEM parsing helpers (cold path, build time only)
// ============================================================================

/// Protocol versions offered to rustls for the configured `[min, max]` bounds.
///
/// Cold path (build time). An inverted range is a typed build error instead of
/// an empty version list that rustls would refuse with an opaque message.
#[cfg(feature = "tcp-tls")]
fn protocol_versions(
    min: TlsVersion,
    max: TlsVersion,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, TlsBuildError> {
    if min > max {
        return Err(TlsBuildError::InvalidProtocolVersionRange { min, max });
    }
    let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = Vec::with_capacity(2);
    if min == TlsVersion::Tls12 {
        versions.push(&rustls::version::TLS12);
    }
    if max == TlsVersion::Tls13 {
        versions.push(&rustls::version::TLS13);
    }
    Ok(versions)
}

/// Process-wide rustls crypto provider (ring). Explicit so a second compiled
/// provider can never turn config building into a process-default panic.
#[cfg(feature = "tcp-tls")]
fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    use std::sync::OnceLock;
    static PROVIDER: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    Arc::clone(PROVIDER.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider())))
}

#[cfg(feature = "tcp-tls")]
fn parse_cert_chain(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsBuildError> {
    use rustls::pki_types::pem::PemObject;

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsBuildError::InvalidCertificatePem(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsBuildError::NoCertificatesInPem);
    }
    Ok(certs)
}

#[cfg(feature = "tcp-tls")]
fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsBuildError> {
    use rustls::pki_types::pem::PemObject;

    PrivateKeyDer::from_pem_slice(pem)
        .map_err(|e| TlsBuildError::InvalidPrivateKeyPem(e.to_string()))
}

#[cfg(feature = "tcp-tls")]
fn parse_root_store(pems: &[Vec<u8>]) -> Result<RootCertStore, TlsBuildError> {
    use rustls::pki_types::pem::PemObject;

    let mut root_store = RootCertStore::empty();
    for root_pem in pems {
        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(root_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsBuildError::InvalidRootCertificatePem(e.to_string()))?;
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|e| TlsBuildError::InvalidRootCertificatePem(e.to_string()))?;
        }
    }
    Ok(root_store)
}

#[cfg(feature = "tcp-tls")]
fn parse_crls(
    pems: &[Vec<u8>],
) -> Result<Vec<CertificateRevocationListDer<'static>>, TlsBuildError> {
    use rustls::pki_types::pem::PemObject;

    let mut crls = Vec::new();
    for crl_pem in pems {
        let parsed: Vec<CertificateRevocationListDer<'static>> =
            CertificateRevocationListDer::pem_slice_iter(crl_pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| TlsBuildError::InvalidCrlPem(e.to_string()))?;
        if parsed.is_empty() {
            return Err(TlsBuildError::InvalidCrlPem(
                "no X509 CRL found in PEM data".to_string(),
            ));
        }
        crls.extend(parsed);
    }
    Ok(crls)
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

    /// Combine a server configuration and a client configuration into one peer
    /// configuration that can both accept and initiate TLS connections.
    ///
    /// `TcpRole::Auto` (the default) listens and dials, so a TLS-enabled
    /// participant needs both halves; a single-role configuration on an Auto
    /// participant is refused by `TcpConfig::validate`.
    pub fn peer(server: TlsConfig, client: TlsConfig) -> Result<TlsConfig, TlsBuildError> {
        if !server.is_server || server.is_peer || client.is_server || client.is_peer {
            return Err(TlsBuildError::PeerRoleMismatch);
        }
        if server.alpn_protocols != client.alpn_protocols {
            return Err(TlsBuildError::PeerAlpnMismatch);
        }
        // An mTLS server half paired with an anonymous client half can never
        // pair with its own kind: it demands a client certificate from every
        // peer and presents none itself.
        if server.require_client_cert && !client.has_client_identity {
            return Err(TlsBuildError::PeerMtlsWithoutClientIdentity);
        }
        // The merged bounds must still be a range the builder would accept.
        let min_protocol_version = server.min_protocol_version.max(client.min_protocol_version);
        let max_protocol_version = server.max_protocol_version.min(client.max_protocol_version);
        if min_protocol_version > max_protocol_version {
            return Err(TlsBuildError::InvalidProtocolVersionRange {
                min: min_protocol_version,
                max: max_protocol_version,
            });
        }
        Ok(TlsConfig {
            #[cfg(feature = "tcp-tls")]
            server_config: server.server_config,
            #[cfg(feature = "tcp-tls")]
            client_config: client.client_config,
            is_server: true,
            is_peer: true,
            alpn_protocols: server.alpn_protocols,
            verify_peer: client.verify_peer,
            require_client_cert: server.require_client_cert,
            trust_anchor_count: server.trust_anchor_count,
            crl_count: server.crl_count,
            has_client_identity: client.has_client_identity,
            enable_session_resumption: server.enable_session_resumption
                && client.enable_session_resumption,
            min_protocol_version,
            max_protocol_version,
        })
    }

    /// Check if this configuration can accept connections (server or peer).
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Check if this configuration can initiate connections (client or peer).
    pub fn is_client(&self) -> bool {
        !self.is_server || self.is_peer
    }

    /// Check if this configuration carries both roles ([`TlsConfig::peer`]).
    pub fn is_peer(&self) -> bool {
        self.is_peer
    }

    /// Whether a rustls server configuration is present (accept path usable).
    pub fn can_accept(&self) -> bool {
        #[cfg(feature = "tcp-tls")]
        {
            self.server_config.is_some()
        }
        #[cfg(not(feature = "tcp-tls"))]
        {
            false
        }
    }

    /// Whether a rustls client configuration is present (dial path usable).
    pub fn can_initiate(&self) -> bool {
        #[cfg(feature = "tcp-tls")]
        {
            self.client_config.is_some()
        }
        #[cfg(not(feature = "tcp-tls"))]
        {
            false
        }
    }

    /// Get ALPN protocols.
    pub fn alpn_protocols(&self) -> &[Vec<u8>] {
        &self.alpn_protocols
    }

    /// Whether the server side requires and verifies client certificates (mTLS).
    pub fn require_client_cert(&self) -> bool {
        self.require_client_cert
    }

    /// Number of trust anchors resolved at build time
    /// (client CA certificates on a server, server roots on a client).
    pub fn trust_anchor_count(&self) -> usize {
        self.trust_anchor_count
    }

    /// Number of client CA certificates on a server (0 unless mTLS).
    pub fn client_ca_count(&self) -> usize {
        if self.is_server {
            self.trust_anchor_count
        } else {
            0
        }
    }

    /// Number of certificate revocation lists resolved at build time.
    pub fn crl_count(&self) -> usize {
        self.crl_count
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
// Handshake bounds
// ============================================================================

/// Upper bound on a blocking TLS handshake ([`TlsAcceptor::accept`],
/// [`TlsConnector::connect`]).
///
/// A peer that opens the TCP connection and then goes silent must not hold a
/// thread forever; after this the handshake fails with
/// `io::ErrorKind::TimedOut` and the stream is dropped.
#[cfg(feature = "tcp-tls")]
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Pause between handshake polls when the socket produced nothing. Only used
/// on sockets that return `WouldBlock` (non-blocking, or a read timeout);
/// a plain blocking socket parks inside `read_tls`.
#[cfg(feature = "tcp-tls")]
const HANDSHAKE_POLL_PAUSE: Duration = Duration::from_millis(1);

/// Upper bound on consecutive plaintext-free TLS records a single
/// [`Read::read`] call will step over (TLS 1.3 NewSessionTicket, KeyUpdate,
/// alerts). Past that the call returns `WouldBlock` and the caller decides
/// whether to come back, so a peer streaming control records cannot hold one
/// `read()` open indefinitely.
#[cfg(feature = "tcp-tls")]
const MAX_PLAINTEXT_FREE_RECORDS: usize = 64;

/// The error a blocking handshake returns once its budget is spent.
#[cfg(feature = "tcp-tls")]
fn handshake_timeout(budget: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("TLS handshake did not complete within {budget:?}"),
    )
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
    /// This performs the TLS handshake and returns a TlsStream. The handshake
    /// is bounded by [`DEFAULT_HANDSHAKE_TIMEOUT`]: a peer that connects and
    /// then stops talking yields `io::ErrorKind::TimedOut` instead of pinning
    /// the calling thread forever.
    pub fn accept(&self, tcp_stream: TcpStream) -> io::Result<TlsStream> {
        self.accept_with_timeout(tcp_stream, DEFAULT_HANDSHAKE_TIMEOUT)
    }

    /// Accept a TLS connection with an explicit handshake deadline.
    pub fn accept_with_timeout(
        &self,
        tcp_stream: TcpStream,
        timeout: Duration,
    ) -> io::Result<TlsStream> {
        let conn =
            rustls::ServerConnection::new(Arc::clone(&self.config)).map_err(io::Error::other)?;

        let mut tls_stream = TlsStream {
            tcp_stream,
            tls_conn: TlsConnection::Server(conn),
            handshake_complete: false,
        };

        // Attempt to complete handshake, bounded in time
        tls_stream.complete_handshake(timeout)?;

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
    /// The `server_name` is used for SNI and certificate verification. The
    /// handshake is bounded by [`DEFAULT_HANDSHAKE_TIMEOUT`]: a server that
    /// accepts the TCP connection and then stops talking yields
    /// `io::ErrorKind::TimedOut` instead of pinning the calling thread.
    pub fn connect(&self, server_name: &str, tcp_stream: TcpStream) -> io::Result<TlsStream> {
        self.connect_with_timeout(server_name, tcp_stream, DEFAULT_HANDSHAKE_TIMEOUT)
    }

    /// Connect to a TLS server with an explicit handshake deadline.
    pub fn connect_with_timeout(
        &self,
        server_name: &str,
        tcp_stream: TcpStream,
        timeout: Duration,
    ) -> io::Result<TlsStream> {
        let server_name = ServerName::try_from(server_name.to_string())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let conn = rustls::ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(io::Error::other)?;

        let mut tls_stream = TlsStream {
            tcp_stream,
            tls_conn: TlsConnection::Client(conn),
            handshake_complete: false,
        };

        // Attempt to complete handshake, bounded in time
        tls_stream.complete_handshake(timeout)?;

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
    /// Complete the TLS handshake, bounded by `timeout`.
    ///
    /// A peer that opens the TCP connection and then stops talking (or that
    /// stops mid-flight) must not pin the calling thread: once `timeout` has
    /// elapsed without the handshake completing, the call fails with
    /// `io::ErrorKind::TimedOut` and the caller drops the stream.
    ///
    /// The loop only pauses when the socket produced nothing, so a healthy
    /// handshake still runs at socket speed.
    fn complete_handshake(&mut self, timeout: Duration) -> io::Result<()> {
        // The socket's own read timeout is capped to the remaining budget for
        // the duration of the handshake, so a blocking socket cannot park
        // inside read_tls past the deadline. The caller's setting is restored
        // before returning.
        let caller_timeout = self.tcp_stream.read_timeout().ok().flatten();
        let result = self.complete_handshake_inner(timeout, caller_timeout);
        let _ = self.tcp_stream.set_read_timeout(caller_timeout);
        result
    }

    fn complete_handshake_inner(
        &mut self,
        timeout: Duration,
        caller_timeout: Option<Duration>,
    ) -> io::Result<()> {
        let deadline = Instant::now() + timeout;
        while !self.handshake_complete {
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return Err(handshake_timeout(timeout));
            }
            // Never wait longer than the caller asked for, never longer than
            // what is left of the handshake budget, never zero (which means
            // "block for ever" to the OS).
            let slice = match caller_timeout {
                Some(caller) => remaining.min(caller),
                None => remaining,
            }
            .max(HANDSHAKE_POLL_PAUSE);
            let _ = self.tcp_stream.set_read_timeout(Some(slice));

            let progressed = self.process_tls_io()?;
            if self.refresh_handshake_state() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(handshake_timeout(timeout));
            }
            if !progressed {
                std::thread::sleep(HANDSHAKE_POLL_PAUSE);
            }
        }
        Ok(())
    }

    /// Latch `handshake_complete` from the rustls connection state.
    fn refresh_handshake_state(&mut self) -> bool {
        let is_complete = match &self.tls_conn {
            TlsConnection::Client(conn) => !conn.is_handshaking(),
            TlsConnection::Server(conn) => !conn.is_handshaking(),
        };

        if is_complete {
            self.handshake_complete = true;
        }

        is_complete
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

        Ok(self.refresh_handshake_state())
    }

    /// Process TLS I/O: flush pending TLS records to TCP first, then read
    /// from TCP into TLS if rustls wants more data.
    ///
    /// Returns `Ok(true)` when bytes were consumed from the socket (rustls
    /// reads one record per call once the handshake is done), `Ok(false)` when
    /// the socket had nothing to offer.
    ///
    /// Writing first matters on blocking sockets: a client must send its
    /// ClientHello before it can expect anything from the server.
    fn process_tls_io(&mut self) -> io::Result<bool> {
        self.flush_tls_writes()?;

        let wants_read = match &self.tls_conn {
            TlsConnection::Client(conn) => conn.wants_read(),
            TlsConnection::Server(conn) => conn.wants_read(),
        };
        if !wants_read {
            return Ok(false);
        }

        // Read from TCP into TLS
        let consumed = match &mut self.tls_conn {
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
                    true
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
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
                    true
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => false,
                Err(e) => return Err(e),
            },
        };

        // Processing may have queued a reply (handshake flight, alert).
        self.flush_tls_writes()?;
        Ok(consumed)
    }

    /// Write pending TLS records to TCP without reading.
    fn flush_tls_writes(&mut self) -> io::Result<()> {
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

    /// Whether the handshake resumed a previous session (`None` until the
    /// handshake has progressed far enough to know).
    pub fn is_resumed(&self) -> Option<bool> {
        let kind = match &self.tls_conn {
            TlsConnection::Client(conn) => conn.handshake_kind(),
            TlsConnection::Server(conn) => conn.handshake_kind(),
        };
        kind.map(|k| matches!(k, rustls::HandshakeKind::Resumed))
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
    /// Read decrypted application bytes.
    ///
    /// rustls hands over one TLS record per socket read once the handshake is
    /// done, and some records carry no plaintext at all (TLS 1.3
    /// NewSessionTicket right after the handshake, KeyUpdate, alerts). The loop
    /// keeps pulling records while the socket still yields bytes, so a
    /// plaintext-free record never surfaces as a spurious `WouldBlock` with
    /// application data still queued in the kernel buffer (which would stall an
    /// edge-triggered reader until the peer sends more).
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut plaintext_free_records = 0usize;
        loop {
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

            let mut clean_close = false;
            match result {
                Ok(n) if n > 0 => return Ok(n),
                Ok(_) => clean_close = true, // rustls: peer sent close_notify
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {} // need more records
                Err(e) => return Err(e),
            }

            // Pull the next TLS record from the socket. No progress means the
            // socket is drained (or, on a blocking socket, timed out).
            if !self.process_tls_io()? {
                return if clean_close {
                    Ok(0)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "no TLS application data available",
                    ))
                };
            }

            // Bounded: a peer streaming plaintext-free records cannot hold
            // this call open for ever.
            plaintext_free_records += 1;
            if plaintext_free_records >= MAX_PLAINTEXT_FREE_RECORDS {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "too many consecutive plaintext-free TLS records",
                ));
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

        // Flush TLS data to TCP (write only: never block on a read here)
        self.flush_tls_writes()?;

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
        self.flush_tls_writes()?;

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
        self.flush_tls_writes()?;

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

    #[test]
    fn build_error_is_typed_and_downcastable() {
        let err = io::Error::from(TlsBuildError::RequireClientCertWithoutClientCa);
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let typed = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<TlsBuildError>())
            .expect("io::Error wraps TlsBuildError");
        assert_eq!(*typed, TlsBuildError::RequireClientCertWithoutClientCa);
        assert!(err.to_string().contains("no client CA"));

        let err = io::Error::from(TlsBuildError::InvalidCrlPem("x".to_string()));
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = io::Error::from(TlsBuildError::FeatureDisabled);
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(not(feature = "tcp-tls"))]
    #[test]
    fn test_build_without_feature() {
        let result = TlsConfigBuilder::client().build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("tcp-tls"));
        assert_eq!(
            TlsConfigBuilder::client().try_build().unwrap_err(),
            TlsBuildError::FeatureDisabled
        );
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
        assert!(config.can_initiate());
        assert!(!config.can_accept());
        assert!(config.trust_anchor_count() > 0);
    }

    // ------------------------------------------------------------------
    // mTLS build rules (fail closed) -- use the in-process test PKI
    // ------------------------------------------------------------------

    #[cfg(feature = "tcp-tls")]
    fn pki() -> &'static crate::transport::tcp::tls_test_pki::TestPki {
        crate::transport::tcp::tls_test_pki::TestPki::shared()
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn mtls_server_refuses_to_build_without_client_ca() {
        let pki = pki();
        let err = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .try_build()
            .unwrap_err();
        assert_eq!(err, TlsBuildError::RequireClientCertWithoutClientCa);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn build_refuses_inverted_protocol_version_range() {
        let pki = pki();
        let err = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .with_min_version(TlsVersion::Tls13)
            .with_max_version(TlsVersion::Tls12)
            .try_build()
            .unwrap_err();
        assert_eq!(
            err,
            TlsBuildError::InvalidProtocolVersionRange {
                min: TlsVersion::Tls13,
                max: TlsVersion::Tls12,
            }
        );
        let err = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_min_version(TlsVersion::Tls13)
            .with_max_version(TlsVersion::Tls12)
            .try_build()
            .unwrap_err();
        assert!(matches!(
            err,
            TlsBuildError::InvalidProtocolVersionRange { .. }
        ));
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn mtls_server_refuses_system_roots_as_client_ca() {
        let pki = pki();
        let err = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .with_system_roots()
            .try_build()
            .unwrap_err();
        assert_eq!(err, TlsBuildError::SystemRootsOnServer);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn server_refuses_client_ca_without_require_client_cert() {
        let pki = pki();
        let err = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .try_build()
            .unwrap_err();
        assert_eq!(err, TlsBuildError::ClientCaWithoutRequireClientCert);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn server_refuses_crl_without_require_client_cert() {
        let pki = pki();
        let err = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .with_crl_pem(pki.crl_a_empty.clone())
            .try_build()
            .unwrap_err();
        assert_eq!(err, TlsBuildError::CrlWithoutRequireClientCert);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn mtls_server_refuses_disabled_verification() {
        let pki = pki();
        let err = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .dangerous_disable_verification()
            .try_build()
            .unwrap_err();
        assert_eq!(
            err,
            TlsBuildError::VerificationDisabledWithRequireClientCert
        );
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn mtls_server_build_reports_client_ca_count() {
        let pki = pki();
        let config = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_crl_pem(pki.crl_a_empty.clone())
            .try_build()
            .expect("mTLS server config builds with a client CA");
        assert!(config.require_client_cert());
        assert_eq!(config.client_ca_count(), 1);
        assert_eq!(config.trust_anchor_count(), 1);
        assert_eq!(config.crl_count(), 1);
        assert!(config.can_accept());
        assert!(!config.can_initiate());
        assert!(config.is_server() && !config.is_client() && !config.is_peer());

        // A plain TLS server reports no client CA.
        let plain = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .try_build()
            .expect("plain server config builds");
        assert!(!plain.require_client_cert());
        assert_eq!(plain.client_ca_count(), 0);
        assert_eq!(plain.crl_count(), 0);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn mtls_server_refuses_garbage_crl() {
        let pki = pki();
        let err = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_crl_pem(
                b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
            )
            .try_build()
            .unwrap_err();
        assert!(
            matches!(err, TlsBuildError::InvalidCrlPem(_)),
            "got {err:?}"
        );
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn client_refuses_empty_root_store_with_verification() {
        let err = TlsConfig::client()
            .without_system_roots()
            .try_build()
            .unwrap_err();
        assert_eq!(err, TlsBuildError::EmptyClientRootStore);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn client_refuses_require_client_cert() {
        let err = TlsConfig::client()
            .require_client_cert()
            .try_build()
            .unwrap_err();
        assert_eq!(err, TlsBuildError::RequireClientCertOnClient);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn client_refuses_incomplete_identity() {
        let pki = pki();
        let err = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_cert_pem(pki.client_a_cert.clone())
            .try_build()
            .unwrap_err();
        assert_eq!(err, TlsBuildError::ClientIdentityIncomplete);
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn client_explicit_roots_win_over_system_roots() {
        let pki = pki();
        // client() defaults to system roots; an explicit private CA replaces them.
        let config = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .try_build()
            .expect("client config builds with a private CA");
        assert_eq!(config.trust_anchor_count(), 1);
        assert!(config.is_client() && !config.is_server());
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn peer_config_carries_both_roles() {
        let pki = pki();
        let server = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .try_build()
            .unwrap();
        let client = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_cert_pem(pki.client_a_cert.clone())
            .with_key_pem(pki.client_a_key.clone())
            .try_build()
            .unwrap();
        let peer = TlsConfig::peer(server, client).expect("peer config builds");
        assert!(peer.is_peer());
        assert!(peer.is_server());
        assert!(peer.is_client());
        assert!(peer.can_accept());
        assert!(peer.can_initiate());
        assert!(peer.require_client_cert());
        assert_eq!(peer.client_ca_count(), 1);
        assert!(TlsAcceptor::new(&peer).is_ok());
        assert!(TlsConnector::new(&peer).is_ok());
    }

    #[cfg(feature = "tcp-tls")]
    #[test]
    fn peer_refuses_role_and_alpn_mismatch() {
        let pki = pki();
        let server = || {
            TlsConfig::server()
                .with_cert_pem(pki.server_a_cert.clone())
                .with_key_pem(pki.server_a_key.clone())
                .try_build()
                .unwrap()
        };
        let client = || {
            TlsConfig::client()
                .with_root_cert_pem(pki.ca_a_cert.clone())
                .try_build()
                .unwrap()
        };
        assert_eq!(
            TlsConfig::peer(client(), server()).unwrap_err(),
            TlsBuildError::PeerRoleMismatch
        );
        assert_eq!(
            TlsConfig::peer(server(), server()).unwrap_err(),
            TlsBuildError::PeerRoleMismatch
        );
        let peer = TlsConfig::peer(server(), client()).unwrap();
        assert_eq!(
            TlsConfig::peer(peer, client()).unwrap_err(),
            TlsBuildError::PeerRoleMismatch
        );
        let other_alpn = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_alpn_protocols(vec![b"h2".to_vec()])
            .try_build()
            .unwrap();
        assert_eq!(
            TlsConfig::peer(server(), other_alpn).unwrap_err(),
            TlsBuildError::PeerAlpnMismatch
        );
    }

    /// An mTLS server half plus an anonymous client half is a participant that
    /// demands a certificate from everyone and presents none: refuse it at
    /// build time instead of shipping a peer that can never pair.
    #[cfg(feature = "tcp-tls")]
    #[test]
    fn peer_refuses_mtls_server_with_anonymous_client_half() {
        let pki = pki();
        let mtls_server = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .try_build()
            .unwrap();
        let anonymous_client = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .try_build()
            .unwrap();
        assert!(!anonymous_client.has_client_identity);
        assert_eq!(
            TlsConfig::peer(mtls_server, anonymous_client).unwrap_err(),
            TlsBuildError::PeerMtlsWithoutClientIdentity
        );

        // The same server half with an identified client half is fine.
        let mtls_server = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .require_client_cert()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .try_build()
            .unwrap();
        let identified_client = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_cert_pem(pki.client_a_cert.clone())
            .with_key_pem(pki.client_a_key.clone())
            .try_build()
            .unwrap();
        let peer = TlsConfig::peer(mtls_server, identified_client).expect("peer builds");
        assert!(peer.has_client_identity);
    }

    /// A peer whose halves have disjoint version bounds must not hold a range
    /// its own builder refuses.
    #[cfg(feature = "tcp-tls")]
    #[test]
    fn peer_refuses_inverted_merged_protocol_version_range() {
        let pki = pki();
        let server = TlsConfig::server()
            .with_cert_pem(pki.server_a_cert.clone())
            .with_key_pem(pki.server_a_key.clone())
            .with_min_version(TlsVersion::Tls13)
            .try_build()
            .unwrap();
        let client = TlsConfig::client()
            .with_root_cert_pem(pki.ca_a_cert.clone())
            .with_max_version(TlsVersion::Tls12)
            .try_build()
            .unwrap();
        assert_eq!(
            TlsConfig::peer(server, client).unwrap_err(),
            TlsBuildError::InvalidProtocolVersionRange {
                min: TlsVersion::Tls13,
                max: TlsVersion::Tls12,
            }
        );
    }

    /// Explicit roots plus `dangerous_disable_verification()` is an ambiguity:
    /// the roots would never be consulted. Refuse, and never report a trust
    /// anchor the handshake will not use.
    #[cfg(feature = "tcp-tls")]
    #[test]
    fn client_refuses_roots_with_verification_disabled() {
        let pki = pki();
        assert_eq!(
            TlsConfig::client()
                .with_root_cert_pem(pki.ca_a_cert.clone())
                .dangerous_disable_verification()
                .try_build()
                .unwrap_err(),
            TlsBuildError::RootsWithVerificationDisabled
        );

        // Verification off without explicit roots stays legal (test-only path)
        // but must report zero trust anchors.
        let unverified = TlsConfig::client()
            .dangerous_disable_verification()
            .try_build()
            .expect("unverified client builds");
        assert_eq!(unverified.trust_anchor_count(), 0);
        assert!(!unverified.verify_peer);
    }

    /// The builder holds the TLS private key in a buffer that is wiped on drop.
    /// Pinned by type: a plain `Vec` in that field stops this from compiling.
    #[cfg(feature = "tcp-tls")]
    #[test]
    fn the_builder_holds_its_private_key_in_a_wiping_buffer() {
        let builder = TlsConfig::server().with_key_pem(b"pem".to_vec());
        let held: Option<&zeroize::Zeroizing<Vec<u8>>> = builder.private_key.as_ref();
        assert_eq!(held.map(|key| key.as_slice()), Some(&b"pem"[..]));
    }
}

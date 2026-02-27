// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS Security v1.1 implementation
//!
//! Provides secure DDS communication with:
//! - **Authentication** -- X.509 certificate-based identity verification
//! - **Access Control** -- Permissions XML for topic/partition authorization
//! - **Cryptographic** -- AES-256-GCM encryption for data confidentiality
//! - **Logging** -- Audit trail for security events
//!
//! # Architecture
//!
//! Security is implemented via a plugin architecture with 4 main components:
//!
//! ```text
//! SecurityPluginSuite
//! +-- AuthenticationPlugin  (X.509 certificate validation)
//! +-- AccessControlPlugin   (Permissions XML enforcement)
//! +-- CryptographicPlugin   (AES-256-GCM encryption)
//! +-- LoggingPlugin         (Audit trail + syslog)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use hdds::api::Participant;
//! use hdds::security::SecurityConfig;
//!
//! let security = SecurityConfig::builder()
//!     .identity_certificate("certs/participant1.pem")
//!     .private_key("certs/participant1_key.pem")
//!     .ca_certificates("certs/ca.pem")
//!     .permissions_xml("permissions.xml")
//!     .enable_encryption(true)
//!     .enable_audit_log(true)
//!     .build()?;
//!
//! let participant = Participant::builder("secure_app")
//!     .security(security)
//!     .build()?;
//! ```
//!
//! # References
//!
//! - [OMG DDS Security v1.1](https://www.omg.org/spec/DDS-SECURITY/1.1/)
//! - [RTPS v2.5 Security Extensions](https://www.omg.org/spec/DDSI-RTPS/2.5/)
//! - [X.509 Certificate Profile (RFC 5280)](https://datatracker.ietf.org/doc/html/rfc5280)

/// Access Control plugin (permissions XML, topic allow/deny rules).
#[cfg(feature = "security")]
pub mod access;
/// Audit logging plugin (audit trail, file backend, ANSSI hash-chain).
#[cfg(feature = "security")]
pub mod audit;
/// Authentication plugins (X.509 handshake implementations).
pub mod authentication;
/// Builder and configuration utilities for DDS security.
pub mod config;
/// Cryptographic plugin (AES-256-GCM encryption, ECDH key exchange).
#[cfg(feature = "security")]
pub mod crypto;

pub use config::{SecurityConfig, SecurityConfigBuilder};

use crate::dds::Error;

/// Security plugin suite
///
/// Holds all 4 security plugins (authentication, access control, cryptographic, logging).
///
/// # Lifecycle
///
/// 1. Created via `SecurityConfig::build()`
/// 2. Attached to `Participant` during creation
/// 3. Plugins invoked during discovery, data send/receive
pub struct SecurityPluginSuite {
    /// Authentication plugin (X.509 certificate validation)
    ///
    /// Connected to DiscoveryFsm via SecurityValidatorAdapter for automatic
    /// participant authentication during SPDP discovery. Remote participants
    /// with invalid identity_tokens are rejected per DDS Security v1.1 Sec.8.4.
    pub(crate) authentication: Box<dyn authentication::AuthenticationPlugin>,

    /// Access Control plugin (permissions XML enforcement)
    ///
    /// Optional: Only created if `governance_xml` and `permissions_xml` are both provided.
    #[cfg(feature = "security")]
    pub(crate) access_control: Option<access::AccessControlPlugin>,

    /// Cryptographic plugin (AES-256-GCM encryption, ECDH key exchange)
    ///
    /// Optional: Only created if `enable_encryption` is true.
    #[cfg(feature = "security")]
    pub(crate) cryptographic: Option<crypto::CryptoPlugin>,

    /// Logging plugin (audit trail with ANSSI-compliant hash-chain)
    ///
    /// Optional: Only created if `enable_audit_log` is true.
    /// Wrapped in Mutex for thread-safe concurrent access.
    #[cfg(feature = "security")]
    pub(crate) logging: Option<std::sync::Mutex<audit::LoggingPlugin>>,

    /// Configuration (certificates, permissions, etc.)
    pub(crate) config: SecurityConfig,
}

impl SecurityPluginSuite {
    /// Create a new security plugin suite
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Certificate files cannot be loaded
    /// - Permissions XML is invalid
    /// - Crypto initialization fails
    pub fn new(config: SecurityConfig) -> Result<Self, Error> {
        // Initialize authentication plugin (always required)
        let authentication = authentication::create_authentication_plugin(&config)?;

        // Initialize access control plugin if governance and permissions XML are provided
        #[cfg(feature = "security")]
        let access_control = {
            match (&config.governance_xml, &config.permissions_xml) {
                (Some(governance), Some(permissions)) => {
                    let governance_content =
                        std::fs::read_to_string(governance).map_err(|_| Error::Config)?;
                    let permissions_content =
                        std::fs::read_to_string(permissions).map_err(|_| Error::Config)?;
                    Some(
                        access::AccessControlPlugin::from_xml(
                            &governance_content,
                            &permissions_content,
                        )
                        .map_err(|_| Error::Config)?,
                    )
                }
                _ => None,
            }
        };

        // Initialize cryptographic plugin if encryption is enabled
        #[cfg(feature = "security")]
        let cryptographic = if config.enable_encryption {
            Some(crypto::CryptoPlugin::new())
        } else {
            None
        };

        // Initialize logging plugin if audit log is enabled
        // Wrapped in Mutex for thread-safe concurrent logging
        #[cfg(feature = "security")]
        let logging = if config.enable_audit_log {
            match &config.audit_log_path {
                Some(path) => Some(std::sync::Mutex::new(
                    audit::LoggingPlugin::with_file(path).map_err(|_| Error::Config)?,
                )),
                None => Some(std::sync::Mutex::new(audit::LoggingPlugin::new())),
            }
        } else {
            None
        };

        Ok(Self {
            authentication,
            #[cfg(feature = "security")]
            access_control,
            #[cfg(feature = "security")]
            cryptographic,
            #[cfg(feature = "security")]
            logging,
            config,
        })
    }

    /// Check if security is enabled
    pub fn is_enabled(&self) -> bool {
        true
    }

    /// Check if encryption is enabled
    pub fn is_encryption_enabled(&self) -> bool {
        self.config.enable_encryption
    }

    /// Check if audit logging is enabled
    pub fn is_audit_log_enabled(&self) -> bool {
        self.config.enable_audit_log
    }

    /// Check if access control is enabled
    #[cfg(feature = "security")]
    pub fn is_access_control_enabled(&self) -> bool {
        self.access_control.is_some()
    }

    /// Get reference to access control plugin
    #[cfg(feature = "security")]
    pub fn access_control(&self) -> Option<&access::AccessControlPlugin> {
        self.access_control.as_ref()
    }

    /// Get reference to cryptographic plugin
    #[cfg(feature = "security")]
    pub fn cryptographic(&self) -> Option<&crypto::CryptoPlugin> {
        self.cryptographic.as_ref()
    }

    /// Get mutable reference to cryptographic plugin
    #[cfg(feature = "security")]
    pub fn cryptographic_mut(&mut self) -> Option<&mut crypto::CryptoPlugin> {
        self.cryptographic.as_mut()
    }

    /// Get reference to logging plugin (Mutex-wrapped for thread-safety)
    #[cfg(feature = "security")]
    pub fn logging(&self) -> Option<&std::sync::Mutex<audit::LoggingPlugin>> {
        self.logging.as_ref()
    }

    /// Log a security event (thread-safe)
    ///
    /// Convenience method that acquires the Mutex lock and logs the event.
    /// Returns Ok(()) if logging is disabled or if the event was logged successfully.
    #[cfg(feature = "security")]
    pub fn log_security_event(
        &self,
        event: &audit::SecurityEvent,
    ) -> Result<(), crate::security::SecurityError> {
        if let Some(logging) = &self.logging {
            let mut guard = logging
                .lock()
                .map_err(|_| SecurityError::ConfigError("Logging mutex poisoned".to_string()))?;
            guard.log_event(event)?;
        }
        Ok(())
    }

    /// Get reference to authentication plugin
    pub fn authentication(&self) -> &dyn authentication::AuthenticationPlugin {
        self.authentication.as_ref()
    }

    /// Get reference to configuration
    pub fn config(&self) -> &SecurityConfig {
        &self.config
    }
}

impl std::fmt::Debug for SecurityPluginSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("SecurityPluginSuite");
        debug.field("authentication", &self.authentication);

        #[cfg(feature = "security")]
        {
            debug.field(
                "access_control",
                &self.access_control.as_ref().map(|_| "AccessControlPlugin"),
            );
            debug.field(
                "cryptographic",
                &self.cryptographic.as_ref().map(|_| "CryptoPlugin"),
            );
            debug.field(
                "logging",
                &self.logging.as_ref().map(|_| "Mutex<LoggingPlugin>"),
            );
        }

        debug.field("config", &self.config);
        debug.finish()
    }
}

/// Security error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// Certificate validation failed
    CertificateInvalid(String),

    /// Certificate expired
    CertificateExpired,

    /// Certificate revoked (CRL/OCSP)
    CertificateRevoked,

    /// Authentication handshake failed
    AuthenticationFailed(String),

    /// Permissions denied
    PermissionsDenied(String),

    /// Encryption/decryption failed
    CryptoFailed(String),

    /// Cryptographic operation error (AES-GCM, ECDH, HKDF)
    CryptoError(String),

    /// Configuration error
    ConfigError(String),
}

impl std::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateInvalid(msg) => write!(f, "Certificate invalid: {}", msg),
            Self::CertificateExpired => write!(f, "Certificate expired"),
            Self::CertificateRevoked => write!(f, "Certificate revoked"),
            Self::AuthenticationFailed(msg) => write!(f, "Authentication failed: {}", msg),
            Self::PermissionsDenied(msg) => write!(f, "Permissions denied: {}", msg),
            Self::CryptoFailed(msg) => write!(f, "Crypto operation failed: {}", msg),
            Self::CryptoError(msg) => write!(f, "Cryptographic error: {}", msg),
            Self::ConfigError(msg) => write!(f, "Security configuration error: {}", msg),
        }
    }
}

impl std::error::Error for SecurityError {}

impl From<SecurityError> for Error {
    fn from(_err: SecurityError) -> Self {
        Error::Config
    }
}

// ============================================================================
// Security Validator Adapter (DDS Security v1.1 Sec.8.4)
// ============================================================================
//
// Bridges AuthenticationPlugin to DiscoveryFsm's SecurityValidator trait.
// This enables automatic participant authentication during SPDP discovery.

#[cfg(feature = "security")]
mod validator_adapter {
    use super::SecurityPluginSuite;
    use crate::core::discovery::multicast::SecurityValidator;
    use crate::core::discovery::GUID;
    use std::sync::Arc;

    /// Adapter that bridges AuthenticationPlugin to SecurityValidator.
    ///
    /// Used by DiscoveryFsm to validate incoming participant identity_tokens
    /// during SPDP discovery. Delegates to the AuthenticationPlugin from
    /// SecurityPluginSuite.
    ///
    /// # DDS Security Spec Reference
    ///
    /// Per DDS Security v1.1 Sec.8.4.2.3:
    /// > "The Authentication Plugin shall verify that the identity_token
    /// > presented by a remote DomainParticipant is valid and trusted."
    pub struct SecurityValidatorAdapter {
        security_suite: Arc<SecurityPluginSuite>,
    }

    impl SecurityValidatorAdapter {
        /// Create a new adapter wrapping the security suite.
        pub fn new(security_suite: Arc<SecurityPluginSuite>) -> Self {
            Self { security_suite }
        }
    }

    impl SecurityValidator for SecurityValidatorAdapter {
        /// Validate a remote participant's identity token.
        ///
        /// The identity_token from SPDP is the remote participant's X.509
        /// certificate (PEM-encoded). We delegate to the AuthenticationPlugin
        /// to validate the certificate chain and expiration.
        fn validate_identity(
            &self,
            participant_guid: GUID,
            identity_token: &[u8],
        ) -> Result<(), String> {
            use super::authentication::HandshakeRequestToken;

            // Validate local identity first (ensures our own cert is valid)
            let local_identity = self
                .security_suite
                .authentication()
                .validate_identity()
                .map_err(|e| format!("Local identity validation failed: {}", e))?;

            // Create a handshake request token from the remote identity
            let remote_request = HandshakeRequestToken::new(
                "DDS:Auth:PKI-DH:1.0".to_string(),
                identity_token.to_vec(),
            );

            // Process the handshake to validate the remote certificate
            // The AuthenticationPlugin.process_handshake() validates:
            // 1. Certificate chain (signed by trusted CA)
            // 2. Certificate expiration
            // 3. Signature verification (if present)
            match self
                .security_suite
                .authentication()
                .process_handshake(&local_identity, &remote_request)
            {
                Ok(_) => {
                    log::debug!(
                        "[security] Authenticated participant {:?}",
                        participant_guid
                    );
                    Ok(())
                }
                Err(e) => {
                    log::warn!(
                        "[security] Rejected participant {:?}: {}",
                        participant_guid,
                        e
                    );
                    Err(format!("{}", e))
                }
            }
        }
    }
}

#[cfg(feature = "security")]
pub use validator_adapter::SecurityValidatorAdapter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_error_display() {
        let err = SecurityError::CertificateInvalid("bad format".to_string());
        assert_eq!(err.to_string(), "Certificate invalid: bad format");

        let err = SecurityError::CertificateExpired;
        assert_eq!(err.to_string(), "Certificate expired");

        let err = SecurityError::AuthenticationFailed("challenge mismatch".to_string());
        assert_eq!(err.to_string(), "Authentication failed: challenge mismatch");
    }

    #[test]
    fn test_security_error_into_api_error() {
        let sec_err = SecurityError::CertificateExpired;
        let api_err: Error = sec_err.into();
        assert!(matches!(api_err, Error::Config));
    }
}

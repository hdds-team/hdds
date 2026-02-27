// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Authentication plugin (DDS Security v1.1 Sec.8.3)
//!
//! Provides X.509 certificate-based participant authentication via challenge-response handshake.
//!
//! # Protocol
//!
//! ```text
//! Initiator                      Responder
//!    |                              |
//!    |  1. begin_handshake()        |
//!    |----------------------------->|
//!    |     (identity certificate)   |
//!    |                              |
//!    |  2. process_handshake()      |
//!    |<-----------------------------|
//!    |     (challenge + signature)  |
//!    |                              |
//!    |  3. process_handshake()      |
//!    |----------------------------->|
//!    |     (response + signature)   |
//!    |                              |
//!    |  4. Authentication success   |
//!    |<-----------------------------|
//! ```
//!
//! # References
//!
//! - [DDS Security v1.1 Sec.8.3](https://www.omg.org/spec/DDS-SECURITY/1.1/)
//! - [X.509 RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280)

use std::fmt;

use crate::core::discovery::guid::GUID;
use crate::dds::Error;

use super::config::SecurityConfig;
use super::SecurityError;

/// X.509-based authentication backends and helpers.
pub mod x509;

/// Authentication plugin trait (SPI)
///
/// Defines the interface for participant authentication.
///
/// # Lifecycle
///
/// 1. `validate_identity()` -- Validate local identity certificate
/// 2. `begin_handshake()` -- Initiate authentication with remote participant
/// 3. `process_handshake()` -- Process challenge/response messages
/// 4. Authentication success/failure
pub trait AuthenticationPlugin: fmt::Debug + Send + Sync {
    /// Validate local participant identity
    ///
    /// Verifies that the local identity certificate is valid and trusted.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Certificate is expired
    /// - Certificate chain validation fails
    /// - Private key does not match certificate
    fn validate_identity(&self) -> Result<IdentityHandle, SecurityError>;

    /// Begin authentication handshake
    ///
    /// Initiates authentication with a remote participant.
    ///
    /// # Parameters
    ///
    /// - `local_identity`: Local participant identity handle
    /// - `remote_guid`: Remote participant GUID
    ///
    /// # Returns
    ///
    /// Handshake request token (contains identity certificate)
    fn begin_handshake(
        &self,
        local_identity: &IdentityHandle,
        remote_guid: GUID,
    ) -> Result<HandshakeRequestToken, SecurityError>;

    /// Process handshake message
    ///
    /// Processes a challenge or response from remote participant.
    ///
    /// # Security Validations
    ///
    /// Before accepting the handshake, this method MUST validate the remote certificate:
    ///
    /// 1. **Trust Chain** -- Certificate is signed by a CA in the trust store
    /// 2. **Expiration** -- Certificate is within validity period (notBefore/notAfter)
    /// 3. **KeyUsage** -- Certificate has digitalSignature extension
    /// 4. **Signature** -- Challenge signature is valid for this certificate
    ///
    /// # Parameters
    ///
    /// - `local_identity`: Local participant identity handle
    /// - `request`: Handshake request token from remote
    ///
    /// # Returns
    ///
    /// - `Some(reply)` -- Handshake reply token (challenge or final confirmation)
    /// - `None` -- Authentication complete, no reply needed
    ///
    /// # Errors
    ///
    /// - `SecurityError::CertificateInvalid` -- Remote certificate validation failed
    /// - `SecurityError::CertificateExpired` -- Remote certificate is expired
    /// - `SecurityError::AuthenticationFailed` -- Signature verification failed
    fn process_handshake(
        &self,
        local_identity: &IdentityHandle,
        request: &HandshakeRequestToken,
    ) -> Result<Option<HandshakeReplyToken>, SecurityError>;
}

/// Identity handle
///
/// Opaque handle to a validated participant identity.
///
/// # Contents
///
/// - X.509 certificate (DER encoded)
/// - Private key (for signing challenges)
/// - Subject name (CN=participant.example.com)
#[derive(Debug, Clone)]
pub struct IdentityHandle {
    /// Participant GUID
    pub guid: GUID,

    /// Subject name from certificate (e.g., "CN=participant1.example.com")
    pub subject_name: String,

    /// Certificate expiration timestamp (Unix epoch)
    pub expiration_time: u64,

    /// Internal certificate data (opaque)
    pub(crate) certificate_data: Vec<u8>,
}

impl IdentityHandle {
    /// Create a new identity handle
    pub fn new(
        guid: GUID,
        subject_name: String,
        expiration_time: u64,
        certificate_data: Vec<u8>,
    ) -> Self {
        Self {
            guid,
            subject_name,
            expiration_time,
            certificate_data,
        }
    }

    /// Check if identity is expired
    ///
    /// Returns `true` if the certificate has expired, or if system time is unavailable
    /// (fail-safe: treat time errors as expired).
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0); // Fail-safe: treat time error as epoch 0 (expired)
        now > self.expiration_time
    }
}

/// Handshake request token
///
/// Sent by initiator to begin authentication or by responder as challenge.
///
/// # Wire Format
///
/// ```text
/// +-------------------+
/// | class_id (16 bytes)|  DDS Security token class ID
/// +-------------------+
/// | properties         |  Key-value pairs:
/// |  - "c.id"          |    Identity certificate (PEM)
/// |  - "c.perm"        |    Permissions token (optional)
/// |  - "challenge"     |    Random nonce (32 bytes)
/// +-------------------+
/// | binary_properties  |  Binary data (signatures)
/// +-------------------+
/// ```
#[derive(Debug, Clone)]
pub struct HandshakeRequestToken {
    /// Class ID (DDS Security token identifier)
    pub class_id: String,

    /// Identity certificate (PEM format)
    pub identity_certificate: Vec<u8>,

    /// Challenge nonce (32 bytes, crypto-secure random)
    pub challenge: Option<Vec<u8>>,

    /// Digital signature (RSA/ECDSA)
    pub signature: Option<Vec<u8>>,
}

impl HandshakeRequestToken {
    /// Create a new handshake request token
    pub fn new(class_id: String, identity_certificate: Vec<u8>) -> Self {
        Self {
            class_id,
            identity_certificate,
            challenge: None,
            signature: None,
        }
    }

    /// Set challenge nonce
    pub fn with_challenge(mut self, challenge: Vec<u8>) -> Self {
        self.challenge = Some(challenge);
        self
    }

    /// Set digital signature
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }
}

/// Handshake reply token
///
/// Sent in response to a handshake request.
///
/// # Contents
///
/// - Challenge response (signature of received challenge)
/// - New challenge (if multi-step handshake)
/// - Final confirmation (if authentication complete)
#[derive(Debug, Clone)]
pub struct HandshakeReplyToken {
    /// Challenge response (signature of received challenge)
    pub challenge_response: Vec<u8>,

    /// New challenge for next step (optional)
    pub new_challenge: Option<Vec<u8>>,

    /// Digital signature
    pub signature: Vec<u8>,
}

impl HandshakeReplyToken {
    /// Create a new handshake reply token
    pub fn new(challenge_response: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            challenge_response,
            new_challenge: None,
            signature,
        }
    }

    /// Set new challenge
    pub fn with_new_challenge(mut self, challenge: Vec<u8>) -> Self {
        self.new_challenge = Some(challenge);
        self
    }
}

/// Create authentication plugin
///
/// Factory function to instantiate the appropriate authentication plugin.
///
/// # Current Implementation
///
/// - X.509 certificate-based authentication (PKI-DH)
///
/// # Future
///
/// - Kerberos authentication
/// - Pre-shared keys (PSK)
pub fn create_authentication_plugin(
    config: &SecurityConfig,
) -> Result<Box<dyn AuthenticationPlugin>, Error> {
    // For now, always use X.509 authentication
    let plugin = x509::X509AuthenticationPlugin::new(config)?;
    Ok(Box::new(plugin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_handle_creation() {
        let guid = GUID::zero();
        let handle = IdentityHandle::new(
            guid,
            "CN=test.example.com".to_string(),
            u64::MAX,
            vec![0x30, 0x82], // Mock DER certificate
        );

        assert_eq!(handle.subject_name, "CN=test.example.com");
        assert!(!handle.is_expired());
    }

    #[test]
    fn test_identity_handle_expiration() {
        let guid = GUID::zero();
        let expired_time = 1609459200; // 2021-01-01 (past)
        let handle = IdentityHandle::new(
            guid,
            "CN=expired.example.com".to_string(),
            expired_time,
            vec![],
        );

        assert!(handle.is_expired());
    }

    #[test]
    fn test_handshake_request_token_builder() {
        let token = HandshakeRequestToken::new(
            "DDS:Auth:PKI-DH:1.0".to_string(),
            vec![0x30, 0x82], // Mock certificate
        )
        .with_challenge(vec![0xAA; 32])
        .with_signature(vec![0xBB; 64]);

        assert_eq!(token.class_id, "DDS:Auth:PKI-DH:1.0");
        assert!(token.challenge.is_some());
        assert_eq!(
            token.challenge.expect("Challenge should be present").len(),
            32
        );
        assert!(token.signature.is_some());
        assert_eq!(
            token.signature.expect("Signature should be present").len(),
            64
        );
    }

    #[test]
    fn test_handshake_reply_token_builder() {
        let token = HandshakeReplyToken::new(
            vec![0xCC; 32], // Challenge response
            vec![0xDD; 64], // Signature
        )
        .with_new_challenge(vec![0xEE; 32]);

        assert_eq!(token.challenge_response.len(), 32);
        assert_eq!(token.signature.len(), 64);
        assert!(token.new_challenge.is_some());
        assert_eq!(
            token
                .new_challenge
                .expect("New challenge should be present")
                .len(),
            32
        );
    }
}

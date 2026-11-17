// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use std::fs;

use crate::core::discovery::guid::GUID;
use crate::dds::Error;
use crate::security::config::SecurityConfig;
use crate::security::SecurityError;

use super::super::{
    AuthenticationPlugin, HandshakeReplyToken, HandshakeRequestToken, IdentityHandle,
};
use super::cert::{
    derive_guid_from_certificate, get_expiration_time, parse_subject_name,
    validate_certificate_chain,
};
use super::crypto::{generate_challenge, sign_data, verify_signature};

/// The buffer that holds the identity's PEM private key: wiped on drop when
/// the `security` feature provides `zeroize`, a plain vector otherwise.
#[cfg(feature = "security")]
type KeyPemBuffer = zeroize::Zeroizing<Vec<u8>>;
#[cfg(not(feature = "security"))]
type KeyPemBuffer = Vec<u8>;

#[cfg(feature = "security")]
fn key_pem_buffer(bytes: Vec<u8>) -> KeyPemBuffer {
    zeroize::Zeroizing::new(bytes)
}

#[cfg(not(feature = "security"))]
fn key_pem_buffer(bytes: Vec<u8>) -> KeyPemBuffer {
    bytes
}

/// X.509 authentication plugin implementing the DDS Security PKI-DH flow.
pub struct X509AuthenticationPlugin {
    identity_certificate_pem: Vec<u8>,
    /// The identity's PEM private key, as read from disk. Wiped on drop; never
    /// printed (see the `Debug` impl below).
    private_key_pem: KeyPemBuffer,
    ca_certificates_pem: Vec<u8>,
    check_revocation: bool,
    /// The CRL every certificate this plugin judges is checked against - the
    /// local identity at construction and in `validate_identity`, and each
    /// REMOTE peer's certificate in `process_handshake`. Read once, and only
    /// when `check_revocation` is on: the flag is the single switch, a list
    /// named while it is off is never loaded. Only READ under the `security`
    /// feature, where the CRL parser lives; without it the field is loaded and
    /// never consulted, and the compiler says so.
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    revocation_list: crate::security::revocation::ListInForce,
}

/// Redacted: the identity's private key is printed as a placeholder, so a
/// `{:?}` on the plugin, or on anything holding it, never shows key bytes.
impl std::fmt::Debug for X509AuthenticationPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X509AuthenticationPlugin")
            .field("identity_certificate_pem", &self.identity_certificate_pem)
            .field("private_key_pem", &"<redacted>")
            .field("ca_certificates_pem", &self.ca_certificates_pem)
            .field("check_revocation", &self.check_revocation)
            .finish_non_exhaustive()
    }
}

impl X509AuthenticationPlugin {
    /// Create a new X.509 authentication plugin from the provided security configuration.
    ///
    /// The CRL named by the configuration is read once, here. A participant
    /// shares its list in force with its plugin and reloads it on rotation; a
    /// plugin created with this function outside a participant does not see a
    /// rotated CRL. An embedder that uses it directly must create the plugin
    /// again after every CRL rotation.
    pub fn new(config: &SecurityConfig) -> Result<Self, Error> {
        let revocation_list = Self::read_revocation_list(config)?;
        Self::with_list(
            config,
            std::sync::Arc::new(parking_lot::Mutex::new(revocation_list)),
        )
    }

    /// The revocation list `config` names, read from its file, or `None` when
    /// revocation is not checked.
    pub(crate) fn read_revocation_list(config: &SecurityConfig) -> Result<Option<Vec<u8>>, Error> {
        // The builder refuses "revocation on, no list", but `SecurityConfig`
        // has public fields and can be written by hand, so the same rule is
        // enforced where the list is consumed.
        if config.check_certificate_revocation {
            let Some(path) = &config.certificate_revocation_list else {
                return Err(Error::Config(
                    "check_certificate_revocation is on but no certificate_revocation_list \
                     was given; revocation cannot be checked against a list that does not exist"
                        .to_string(),
                ));
            };
            Ok(Some(std::fs::read(path).map_err(|e| {
                Error::Config(format!(
                    "failed to read certificate revocation list from {}: {}",
                    path.display(),
                    e
                ))
            })?))
        } else {
            Ok(None)
        }
    }

    /// The plugin for `config`, judging against `revocation_list`: the list in
    /// force, shared with the participant's handshake machine. Nothing is read
    /// from the revocation file here.
    pub(crate) fn with_list(
        config: &SecurityConfig,
        revocation_list: crate::security::revocation::ListInForce,
    ) -> Result<Self, Error> {
        let identity_certificate_pem =
            fs::read(&config.identity_certificate).map_err(Error::IoError)?;
        let private_key_pem =
            key_pem_buffer(fs::read(&config.private_key).map_err(Error::IoError)?);
        let ca_certificates_pem = fs::read(&config.ca_certificates).map_err(Error::IoError)?;

        Self::validate_pem_format(&identity_certificate_pem, "identity certificate")?;
        Self::validate_pem_format(&private_key_pem, "private key")?;
        Self::validate_pem_format(&ca_certificates_pem, "CA certificates")?;

        // The local identity is judged with the list from the start: a
        // participant whose own certificate is revoked fails to BUILD, rather
        // than announcing itself and failing at the first handshake.
        let list_now = revocation_list.lock().clone();
        validate_certificate_chain(
            &identity_certificate_pem,
            &ca_certificates_pem,
            list_now.as_deref(),
        )
        .map_err(|e| Error::Config(format!("certificate chain validation failed: {}", e)))?;

        Ok(Self {
            identity_certificate_pem,
            private_key_pem,
            ca_certificates_pem,
            check_revocation: config.check_certificate_revocation,
            revocation_list,
        })
    }

    /// The list every certificate check passes through, or the reason none
    /// can: `Ok(None)` when revocation is off, the list when it is on, and an
    /// error when it is on and cannot be honoured. The one thing this must
    /// never return is `Ok(None)` while the configuration says revocation is
    /// being checked - that is a silent pass, which is the failure this plugin
    /// refused unconditionally for as long as no CRL could reach it.
    fn revocation_list_for_check(&self) -> Result<Option<Vec<u8>>, SecurityError> {
        if !self.check_revocation {
            return Ok(None);
        }
        // The CRL parser and the X.509 crate live behind the `security`
        // feature. This plugin does not: it is compiled under default features
        // too. A build that cannot parse a CRL cannot honour one, and saying so
        // beats a default-features build that silently authenticates.
        #[cfg(not(feature = "security"))]
        {
            Err(SecurityError::AuthenticationFailed(
                "revocation checking is enabled (check_certificate_revocation = true) \
                 but this build has no `security` feature and cannot parse a CRL"
                    .to_string(),
            ))
        }
        #[cfg(feature = "security")]
        {
            let list = self.revocation_list.lock().clone();
            list.map(Some).ok_or_else(|| {
                SecurityError::AuthenticationFailed(
                    "revocation checking is enabled (check_certificate_revocation = true) \
                     but no certificate_revocation_list reached this plugin"
                        .to_string(),
                )
            })
        }
    }

    /// Quick validity check that the provided blob appears to be PEM formatted data.
    pub(super) fn validate_pem_format(data: &[u8], _label: &str) -> Result<(), Error> {
        if data.is_empty() {
            return Err(Error::Config(format!("{} PEM data is empty", _label)));
        }

        if !data.starts_with(b"-----BEGIN") {
            return Err(Error::Config(format!(
                "{} does not start with PEM header",
                _label
            )));
        }

        Ok(())
    }
}

impl AuthenticationPlugin for X509AuthenticationPlugin {
    fn validate_identity(&self) -> Result<IdentityHandle, SecurityError> {
        // Revocation (DDS Security v1.1 Sec.9.3.2.4) is CRL-based only: OCSP
        // needs an outbound HTTP connection that air-gapped deployments do not
        // have. The identity was already judged at construction; it is judged
        // again here because a handle is what the rest of the stack trusts,
        // and the check is cheap next to what a wrongly issued handle costs.
        let list = self.revocation_list_for_check()?;
        validate_certificate_chain(
            &self.identity_certificate_pem,
            &self.ca_certificates_pem,
            list.as_deref(),
        )?;

        let subject_name = parse_subject_name(&self.identity_certificate_pem)?;
        let expiration_time = get_expiration_time(&self.identity_certificate_pem)?;
        let guid = derive_guid_from_certificate(&self.identity_certificate_pem)?;

        let handle = IdentityHandle::new(
            guid,
            subject_name,
            expiration_time,
            self.identity_certificate_pem.clone(),
        );

        if handle.is_expired() {
            return Err(SecurityError::CertificateExpired);
        }

        Ok(handle)
    }

    fn begin_handshake(
        &self,
        local_identity: &IdentityHandle,
        _remote_guid: GUID,
    ) -> Result<HandshakeRequestToken, SecurityError> {
        let token = HandshakeRequestToken::new(
            "DDS:Auth:PKI-DH:1.0".to_string(),
            local_identity.certificate_data.clone(),
        );

        let challenge = generate_challenge()?;
        let signature = sign_data(&challenge, &self.private_key_pem)?;

        Ok(token.with_challenge(challenge).with_signature(signature))
    }

    fn process_handshake(
        &self,
        _local_identity: &IdentityHandle,
        request: &HandshakeRequestToken,
    ) -> Result<Option<HandshakeReplyToken>, SecurityError> {
        if request.identity_certificate.is_empty() {
            return Err(SecurityError::CertificateInvalid(
                "Empty certificate".to_string(),
            ));
        }

        // The REMOTE certificate is judged with the same list as the local
        // one: a revoked peer chained to the CA must not be authenticated
        // while the configuration says revocation is being checked.
        let list = self.revocation_list_for_check()?;
        validate_certificate_chain(
            &request.identity_certificate,
            &self.ca_certificates_pem,
            list.as_deref(),
        )?;
        let _remote_subject = parse_subject_name(&request.identity_certificate)
            .unwrap_or_else(|_| "unknown".to_string());

        if let (Some(challenge), Some(signature)) = (&request.challenge, &request.signature) {
            let valid = verify_signature(challenge, signature, &request.identity_certificate)?;
            if !valid {
                return Err(SecurityError::AuthenticationFailed(
                    "Invalid signature".to_string(),
                ));
            }
        }

        let challenge_response = request.challenge.clone().unwrap_or_else(|| vec![0x00; 32]);
        let signature = sign_data(&challenge_response, &self.private_key_pem)?;
        let reply = HandshakeReplyToken::new(challenge_response, signature);

        Ok(Some(reply))
    }
}

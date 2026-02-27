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

/// X.509 authentication plugin implementing the DDS Security PKI-DH flow.
#[derive(Debug)]
pub struct X509AuthenticationPlugin {
    identity_certificate_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
    ca_certificates_pem: Vec<u8>,
    #[allow(dead_code)]
    check_revocation: bool,
}

impl X509AuthenticationPlugin {
    /// Create a new X.509 authentication plugin from the provided security configuration.
    pub fn new(config: &SecurityConfig) -> Result<Self, Error> {
        let identity_certificate_pem =
            fs::read(&config.identity_certificate).map_err(Error::IoError)?;
        let private_key_pem = fs::read(&config.private_key).map_err(Error::IoError)?;
        let ca_certificates_pem = fs::read(&config.ca_certificates).map_err(Error::IoError)?;

        Self::validate_pem_format(&identity_certificate_pem, "identity certificate")?;
        Self::validate_pem_format(&private_key_pem, "private key")?;
        Self::validate_pem_format(&ca_certificates_pem, "CA certificates")?;

        validate_certificate_chain(&identity_certificate_pem, &ca_certificates_pem)
            .map_err(|_| Error::Config)?;

        Ok(Self {
            identity_certificate_pem,
            private_key_pem,
            ca_certificates_pem,
            check_revocation: config.check_certificate_revocation,
        })
    }

    /// Quick validity check that the provided blob appears to be PEM formatted data.
    pub(super) fn validate_pem_format(data: &[u8], _label: &str) -> Result<(), Error> {
        if data.is_empty() {
            return Err(Error::Config);
        }

        if !data.starts_with(b"-----BEGIN") {
            return Err(Error::Config);
        }

        Ok(())
    }
}

impl AuthenticationPlugin for X509AuthenticationPlugin {
    fn validate_identity(&self) -> Result<IdentityHandle, SecurityError> {
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

        validate_certificate_chain(&request.identity_certificate, &self.ca_certificates_pem)?;
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

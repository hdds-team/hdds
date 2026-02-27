// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Identity Token Wire Format
//!
//! Defines the wire format for embedding identity certificates in SPDP messages.
//!
//! # Wire Format
//!
//! ```text
//! IdentityToken {
//!     u32 cert_length;
//!     u8[] certificate_der;  // X.509 certificate in DER format
//! }
//! ```
//!
//! # OMG DDS Security v1.1 Sec.8.3.4 (Identity Token)

#[cfg(feature = "security")]
use crate::security::SecurityError;
use std::convert::TryFrom;

#[cfg(feature = "security")]
use super::x509::pem_to_der;

/// Identity token for embedding in SPDP DATA(p) messages
///
/// Contains the participant's X.509 identity certificate.
#[cfg(feature = "security")]
#[derive(Debug, Clone, PartialEq)]
pub struct IdentityToken {
    /// DER-encoded X.509 certificate
    certificate_der: Vec<u8>,
}

#[cfg(feature = "security")]
impl IdentityToken {
    /// Create a new identity token from a PEM-encoded certificate
    ///
    /// # Arguments
    ///
    /// * `cert_pem` - PEM-encoded X.509 certificate
    pub fn from_pem(cert_pem: &[u8]) -> Result<Self, SecurityError> {
        // Parse PEM format
        let certificate_der = pem_to_der(cert_pem)?;

        Ok(Self { certificate_der })
    }

    /// Create a new identity token from a DER-encoded certificate
    ///
    /// # Arguments
    ///
    /// * `cert_der` - DER-encoded X.509 certificate
    pub fn from_der(cert_der: Vec<u8>) -> Self {
        Self {
            certificate_der: cert_der,
        }
    }

    /// Get the DER-encoded certificate
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Serialize identity token to wire format
    ///
    /// # Wire Format
    ///
    /// ```text
    /// [u32 length | u8[] certificate_der]
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let cert_len = u32::try_from(self.certificate_der.len())
            .expect("certificate length must fit in u32 for wire encoding");
        let mut buffer = Vec::with_capacity(4 + self.certificate_der.len());

        // Write length (little-endian)
        buffer.extend_from_slice(&cert_len.to_le_bytes());
        // Write certificate
        buffer.extend_from_slice(&self.certificate_der);

        buffer
    }

    /// Deserialize identity token from wire format
    ///
    /// # Arguments
    ///
    /// * `data` - Wire format bytes
    pub fn deserialize(data: &[u8]) -> Result<Self, SecurityError> {
        if data.len() < 4 {
            return Err(SecurityError::AuthenticationFailed(
                "Identity token too short (missing length)".to_string(),
            ));
        }

        // Read length
        let cert_len = usize::try_from(u32::from_le_bytes([
            data[0], data[1], data[2], data[3],
        ]))
        .expect("u32 length should fit in usize");

        if data.len() < 4 + cert_len {
            return Err(SecurityError::AuthenticationFailed(format!(
                "Identity token truncated (expected {} bytes, got {})",
                4 + cert_len,
                data.len()
            )));
        }

        // Read certificate
        let certificate_der = data[4..4 + cert_len].to_vec();

        Ok(Self { certificate_der })
    }

    /// Convert to PEM format (for debugging)
    pub fn to_pem(&self) -> String {
        let pem = pem::Pem::new("CERTIFICATE", self.certificate_der.clone());
        pem::encode(&pem)
    }
}

#[cfg(all(test, feature = "security"))]
mod tests {
    use super::*;

    #[test]
    fn test_identity_token_serialize_deserialize() {
        // Create a dummy DER certificate
        let cert_der = vec![0x30, 0x82, 0x01, 0x00]; // ASN.1 SEQUENCE header

        let token = IdentityToken::from_der(cert_der.clone());

        // Serialize
        let serialized = token.serialize();
        assert_eq!(serialized.len(), 4 + cert_der.len());

        // Deserialize
        let deserialized = IdentityToken::deserialize(&serialized).expect("Deserialize failed");
        assert_eq!(deserialized.certificate_der(), &cert_der[..]);
    }

    #[test]
    fn test_identity_token_deserialize_invalid() {
        // Too short (< 4 bytes)
        let result = IdentityToken::deserialize(&[0x01, 0x02]);
        assert!(result.is_err());

        // Length mismatch
        let invalid = vec![0x10, 0x00, 0x00, 0x00]; // Says length=16, but no data
        let result = IdentityToken::deserialize(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_identity_token_from_pem_invalid() {
        let invalid_pem = b"not a pem file";
        let result = IdentityToken::from_pem(invalid_pem);
        assert!(result.is_err());
    }
}

#[cfg(not(feature = "security"))]
pub struct IdentityToken;

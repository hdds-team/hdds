// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SecuredPayload submessage format for DDS Security v1.1
//!
//! Implements the wire format for encrypted RTPS payloads per
//! DDS Security spec Sec.7.3.7 and RTPS v2.5 Sec.9.6.2.

use crate::security::SecurityError;

/// SecuredPayload submessage (SEC_BODY, submessage kind 0x30)
///
/// # Wire Format
///
/// ```text
/// +-------------------+
/// | session_key_id    |  8 bytes (u64)
/// +-------------------+
/// | nonce             | 12 bytes
/// +-------------------+
/// | ciphertext        |  N bytes (variable)
/// +-------------------+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuredPayload {
    /// Session key ID used for encryption
    pub session_key_id: u64,

    /// 96-bit nonce (IV) for AES-GCM
    pub nonce: [u8; 12],

    /// Encrypted payload + authentication tag
    pub ciphertext: Vec<u8>,
}

impl SecuredPayload {
    /// Encode SecuredPayload to wire format (CDR serialization)
    pub fn encode(&self) -> Result<Vec<u8>, SecurityError> {
        let mut buf = Vec::with_capacity(8 + 12 + self.ciphertext.len());

        // Encode session_key_id (u64, little-endian)
        buf.extend_from_slice(&self.session_key_id.to_le_bytes());

        // Encode nonce (12 bytes)
        buf.extend_from_slice(&self.nonce);

        // Encode ciphertext (variable length)
        buf.extend_from_slice(&self.ciphertext);

        Ok(buf)
    }

    /// Decode SecuredPayload from wire format
    pub fn decode(bytes: &[u8]) -> Result<Self, SecurityError> {
        if bytes.len() < 20 {
            return Err(SecurityError::CryptoError(
                "SecuredPayload too short (min 20 bytes)".to_string(),
            ));
        }

        // Decode session_key_id (u64)
        let mut key_id_bytes = [0u8; 8];
        key_id_bytes.copy_from_slice(&bytes[0..8]);
        let session_key_id = u64::from_le_bytes(key_id_bytes);

        // Decode nonce (12 bytes)
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[8..20]);

        // Decode ciphertext (rest of bytes)
        let ciphertext = bytes[20..].to_vec();

        Ok(Self {
            session_key_id,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = SecuredPayload {
            session_key_id: 42,
            nonce: [0xAA; 12],
            ciphertext: vec![0xBB; 100],
        };

        let encoded = original.encode().unwrap();
        let decoded = SecuredPayload::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_decode_too_short_fails() {
        let bytes = vec![0u8; 10]; // Too short
        assert!(SecuredPayload::decode(&bytes).is_err());
    }

    #[test]
    fn test_encode_length() {
        let payload = SecuredPayload {
            session_key_id: 1,
            nonce: [0; 12],
            ciphertext: vec![0; 50],
        };

        let encoded = payload.encode().unwrap();
        assert_eq!(encoded.len(), 8 + 12 + 50); // key_id + nonce + ciphertext
    }
}

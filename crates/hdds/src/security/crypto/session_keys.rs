// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HKDF session-key derivation for DDS Security v1.1
//!
//! Implements HMAC-based Key Derivation Function (HKDF) per RFC 5869
//! for deriving session encryption keys from ECDH shared secrets. Static
//! functions only: derived keys are owned by their call sites (the handshake
//! machine's per-peer secrets, `data_keys` for the data plane), not parked in
//! a registry here.
//!
//! # Key Derivation Flow
//!
//! ```text
//! ECDH shared secret (32 bytes)
//!   v
//! HKDF-Extract (with salt)
//!   v
//! Pseudorandom Key (PRK)
//!   v
//! HKDF-Expand (with info: "DDS Security v1.1 Session Key")
//!   v
//! Session Key (32 bytes for AES-256)
//! ```
//!
//! # Security Properties
//!
//! - **Key Isolation**: Each session gets unique keys
//! - **Forward Secrecy**: Old keys can't decrypt new sessions
//! - **Domain Separation**: "info" parameter prevents key reuse
//!
//! # Example
//!
//! ```
//! use hdds::security::crypto::{EcdhKeyExchange, KeyAgreementSuite, SessionKeyManager};
//! # use hdds::security::SecurityError;
//!
//! # fn example() -> Result<(), SecurityError> {
//! // Generate ECDH keypairs
//! let (_alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256)?;
//! let (bob_pub, _bob_priv) = EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256)?;
//!
//! // Derive shared secret
//! let shared_secret =
//!     EcdhKeyExchange::derive_shared_secret(KeyAgreementSuite::EcdhP256, alice_priv, &bob_pub)?;
//!
//! // Derive session key from shared secret
//! let salt = b"DDS Security Session";
//! let info = b"AES-256-GCM Key";
//! let session_key = SessionKeyManager::derive_session_key(
//!     &shared_secret,
//!     salt,
//!     info
//! )?;
//! assert_eq!(session_key.len(), 32);
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) -- HKDF Specification
//! - [NIST SP 800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf) -- Key Derivation

use crate::security::crypto::key_exchange::KeyAgreementSuite;
use crate::security::SecurityError;
use ring::hkdf::{Salt, HKDF_SHA256, HKDF_SHA384};
use zeroize::Zeroizing;

/// Namespace for the static HKDF derivation functions.
///
/// Fieldless on purpose: this struct once carried a `key_id -> key` registry
/// (store/get/rotate), but that half had zero production callers -- it
/// belonged to the retired parallel `CryptoPlugin` API -- and a key registry
/// nobody reads is exactly the drift-prone scaffolding the data plane was
/// rebuilt out of. Live key ownership sits with the handshake machine
/// (per-peer secrets) and `data_keys` (data-plane writer keys).
pub struct SessionKeyManager;

impl SessionKeyManager {
    /// Derive session key from ECDH shared secret using HKDF
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - ECDH shared secret (from `EcdhKeyExchange::derive_shared_secret`)
    /// * `salt` - Random salt for HKDF-Extract (use unique salt per session)
    /// * `info` - Context info for HKDF-Expand (e.g., "DDS Security v1.1 Session Key")
    ///
    /// # Returns
    ///
    /// 256-bit (32-byte) session key suitable for AES-256-GCM
    ///
    /// # Security
    ///
    /// **CRITICAL**: Never use the ECDH shared secret directly as an encryption key.
    /// Always derive keys via HKDF to ensure:
    /// - Uniform distribution (even if ECDH output has bias)
    /// - Domain separation (different keys for different purposes)
    /// - Forward secrecy (compromise of one key doesn't reveal others)
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::SessionKeyManager;
    ///
    /// let shared_secret = vec![0x42; 32]; // From ECDH
    /// let salt = b"unique-session-id-12345";
    /// let info = b"DDS Security v1.1 Session Key";
    ///
    /// let session_key = SessionKeyManager::derive_session_key(
    ///     &shared_secret,
    ///     salt,
    ///     info
    /// ).unwrap();
    ///
    /// assert_eq!(session_key.len(), 32); // AES-256 key
    /// ```
    pub fn derive_session_key(
        shared_secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, SecurityError> {
        // HKDF-Extract: shared_secret + salt -> PRK
        let salt = Salt::new(HKDF_SHA256, salt);
        let prk = salt.extract(shared_secret);

        // HKDF-Expand: PRK + info -> session_key. The output is key material:
        // it is wiped when the caller drops it, never copied out by value.
        let mut session_key = Zeroizing::new([0u8; 32]);
        prk.expand(&[info], HKDF_SHA256)
            .map_err(|_| SecurityError::CryptoError("HKDF expand failed".to_string()))?
            .fill(session_key.as_mut_slice())
            .map_err(|_| SecurityError::CryptoError("HKDF fill failed".to_string()))?;

        Ok(session_key)
    }

    /// Derive session key from ECDH shared secret using suite-selected HKDF.
    ///
    /// Selects HKDF-SHA256 (32-byte output) for [`KeyAgreementSuite::EcdhP256`]
    /// and HKDF-SHA384 (48-byte output) for [`KeyAgreementSuite::EcdhP384`].
    ///
    /// # Arguments
    ///
    /// * `suite`         - Key-agreement suite (determines HKDF algorithm and output length)
    /// * `shared_secret` - ECDH shared secret (from `EcdhKeyExchange::derive_shared_secret`)
    /// * `salt`          - Random salt for HKDF-Extract
    /// * `info`          - Context info for HKDF-Expand
    ///
    /// # Returns
    ///
    /// Suite-length key material as a `Vec<u8>` (32 bytes for P-256, 48 for P-384).
    pub fn derive_session_key_with_suite(
        suite: KeyAgreementSuite,
        shared_secret: &[u8],
        salt: &[u8],
        info: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SecurityError> {
        match suite {
            KeyAgreementSuite::EcdhP256 => {
                let s = Salt::new(HKDF_SHA256, salt);
                let prk = s.extract(shared_secret);
                let mut out = Zeroizing::new([0u8; 32]);
                prk.expand(&[info], HKDF_SHA256)
                    .map_err(|_| {
                        SecurityError::CryptoError("HKDF-SHA256 expand failed".to_string())
                    })?
                    .fill(out.as_mut_slice())
                    .map_err(|_| {
                        SecurityError::CryptoError("HKDF-SHA256 fill failed".to_string())
                    })?;
                Ok(Zeroizing::new(out.to_vec()))
            }
            KeyAgreementSuite::EcdhP384 => {
                let s = Salt::new(HKDF_SHA384, salt);
                let prk = s.extract(shared_secret);
                let mut out = Zeroizing::new([0u8; 48]);
                prk.expand(&[info], HKDF_SHA384)
                    .map_err(|_| {
                        SecurityError::CryptoError("HKDF-SHA384 expand failed".to_string())
                    })?
                    .fill(out.as_mut_slice())
                    .map_err(|_| {
                        SecurityError::CryptoError("HKDF-SHA384 fill failed".to_string())
                    })?;
                Ok(Zeroizing::new(out.to_vec()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_key_deterministic() {
        let shared_secret = vec![0x42; 32];
        let salt = b"test-salt";
        let info = b"test-info";

        let key1 = SessionKeyManager::derive_session_key(&shared_secret, salt, info).unwrap();
        let key2 = SessionKeyManager::derive_session_key(&shared_secret, salt, info).unwrap();

        // Same inputs should produce same output
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_session_key_different_salt() {
        let shared_secret = vec![0x42; 32];
        let info = b"test-info";

        let key1 = SessionKeyManager::derive_session_key(&shared_secret, b"salt1", info).unwrap();
        let key2 = SessionKeyManager::derive_session_key(&shared_secret, b"salt2", info).unwrap();

        // Different salts should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_session_key_different_info() {
        let shared_secret = vec![0x42; 32];
        let salt = b"test-salt";

        let key1 = SessionKeyManager::derive_session_key(&shared_secret, salt, b"info1").unwrap();
        let key2 = SessionKeyManager::derive_session_key(&shared_secret, salt, b"info2").unwrap();

        // Different info should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_output_length() {
        let shared_secret = vec![0x42; 32];
        let key = SessionKeyManager::derive_session_key(&shared_secret, b"salt", b"info").unwrap();

        assert_eq!(key.len(), 32); // AES-256 key size
    }

    // --- Suite-aware derivation tests ---

    #[test]
    fn test_derive_with_suite_p256_matches_base() {
        use crate::security::crypto::key_exchange::KeyAgreementSuite;

        let secret = vec![0x42; 32];
        let salt = b"test-salt";
        let info = b"test-info";

        let base = SessionKeyManager::derive_session_key(&secret, salt, info).unwrap();
        let suite_out = SessionKeyManager::derive_session_key_with_suite(
            KeyAgreementSuite::EcdhP256,
            &secret,
            salt,
            info,
        )
        .unwrap();

        // P-256 suite must produce the same bytes as the legacy SHA256 path.
        assert_eq!(base.as_ref(), suite_out.as_slice());
        assert_eq!(suite_out.len(), 32);
    }

    #[test]
    fn test_derive_with_suite_p384_returns_48_bytes() {
        use crate::security::crypto::key_exchange::KeyAgreementSuite;

        let secret = vec![0x5A; 48]; // 48-byte secret as produced by P-384 ECDH
        let out = SessionKeyManager::derive_session_key_with_suite(
            KeyAgreementSuite::EcdhP384,
            &secret,
            b"salt",
            b"info",
        )
        .unwrap();

        assert_eq!(out.len(), 48);
    }

    #[test]
    fn test_derive_with_suite_p384_deterministic() {
        use crate::security::crypto::key_exchange::KeyAgreementSuite;

        let secret = vec![0x5A; 48];
        let a = SessionKeyManager::derive_session_key_with_suite(
            KeyAgreementSuite::EcdhP384,
            &secret,
            b"s",
            b"i",
        )
        .unwrap();
        let b = SessionKeyManager::derive_session_key_with_suite(
            KeyAgreementSuite::EcdhP384,
            &secret,
            b"s",
            b"i",
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_with_suite_p384_differs_from_p256() {
        use crate::security::crypto::key_exchange::KeyAgreementSuite;

        let secret = vec![0x42; 32];
        let p256_out = SessionKeyManager::derive_session_key_with_suite(
            KeyAgreementSuite::EcdhP256,
            &secret,
            b"salt",
            b"info",
        )
        .unwrap();
        let p384_out = SessionKeyManager::derive_session_key_with_suite(
            KeyAgreementSuite::EcdhP384,
            &secret,
            b"salt",
            b"info",
        )
        .unwrap();

        // Different algorithms and output lengths.
        assert_eq!(p256_out.len(), 32);
        assert_eq!(p384_out.len(), 48);
        // First 32 bytes should differ (different HKDF algorithms).
        assert_ne!(p256_out.as_slice(), &p384_out[..32]);
    }
}

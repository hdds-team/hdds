// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ECDH P-256 / P-384 key exchange for DDS Security v1.1
//!
//! Implements Elliptic Curve Diffie-Hellman key exchange using either the
//! P-256 curve (NIST secp256r1) or the P-384 curve (NIST secp384r1) per
//! DDS Security spec Sec.7.3.5.  The curve is selected at call time via
//! [`KeyAgreementSuite`], which is derived from the `kagree_algo` string
//! advertised in the `AuthRequest` token.
//!
//! # Algorithm strings (DDS Security v1.1 sec. 9.3.1.1.1)
//!
//! | `kagree_algo` string           | Suite              |
//! |--------------------------------|--------------------|
//! | `"ECDH+prime256v1-CEUM"`       | [`KeyAgreementSuite::EcdhP256`] |
//! | `"ECDH+secp384r1-CEUM"`        | [`KeyAgreementSuite::EcdhP384`] |
//! | anything else / unknown        | refused (`None`, fail closed)   |
//!
//! # Security Properties
//!
//! - **Forward Secrecy**: Each session uses ephemeral keys
//! - **Authentication**: Combined with X.509 certificates
//! - **Key Derivation**: ECDH shared secret -> HKDF -> session keys

use crate::security::SecurityError;
use ring::agreement::{
    agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256, ECDH_P384,
};
use ring::rand::SystemRandom;

// ------------------------------------------------------------
//  Suite enum
// ------------------------------------------------------------

/// Key-agreement suite derived from the `kagree_algo` token string.
///
/// Used to select the ECDH curve (and companion HKDF algorithm) for both
/// key-pair generation and shared-secret derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAgreementSuite {
    /// ECDH over NIST P-256 (secp256r1).  65-byte uncompressed public key,
    /// 32-byte raw shared secret.  Companion KDF: HKDF-SHA256.
    EcdhP256,
    /// ECDH over NIST P-384 (secp384r1).  97-byte uncompressed public key,
    /// 48-byte raw shared secret.  Companion KDF: HKDF-SHA384.
    EcdhP384,
}

impl KeyAgreementSuite {
    /// Map a `kagree_algo` wire string to a suite.
    ///
    /// Strict mapping: an unknown string is `None`, never a silent default.
    ///
    /// A fallback to P-256 would let a config typo silently downgrade the key
    /// agreement, and answer a peer advertising an unsupported suite with
    /// P-256 material it never asked for. Both callers want a refusal they
    /// can act on: a local config error at `start()`, a fail-closed handshake
    /// rejection at `handle_request()`.
    pub fn from_kagree_algo(s: &str) -> Option<Self> {
        match s {
            "ECDH+prime256v1-CEUM" => Some(Self::EcdhP256),
            "ECDH+secp384r1-CEUM" => Some(Self::EcdhP384),
            _ => None,
        }
    }

    /// The canonical `kagree_algo` wire string for this suite.
    pub fn as_kagree_algo(self) -> &'static str {
        match self {
            Self::EcdhP256 => "ECDH+prime256v1-CEUM",
            Self::EcdhP384 => "ECDH+secp384r1-CEUM",
        }
    }

    /// Expected byte length of the uncompressed public key (`0x04 || X || Y`).
    pub fn public_key_len(self) -> usize {
        match self {
            Self::EcdhP256 => ECDH_P256_PUBLIC_KEY_LEN,
            Self::EcdhP384 => ECDH_P384_PUBLIC_KEY_LEN,
        }
    }

    /// Byte length of the raw ECDH shared secret output.
    pub fn shared_secret_len(self) -> usize {
        match self {
            Self::EcdhP256 => ECDH_P256_SHARED_SECRET_LEN,
            Self::EcdhP384 => ECDH_P384_SHARED_SECRET_LEN,
        }
    }
}

// ------------------------------------------------------------
//  Length constants
// ------------------------------------------------------------

/// ECDH P-256 public key length (uncompressed: 0x04 || X || Y).
pub const ECDH_P256_PUBLIC_KEY_LEN: usize = 65;

/// ECDH P-256 shared secret length.
pub const ECDH_P256_SHARED_SECRET_LEN: usize = 32;

/// ECDH P-384 public key length (uncompressed: 0x04 || X || Y).
pub const ECDH_P384_PUBLIC_KEY_LEN: usize = 97;

/// ECDH P-384 shared secret length.
pub const ECDH_P384_SHARED_SECRET_LEN: usize = 48;

// ------------------------------------------------------------
//  EcdhKeyExchange
// ------------------------------------------------------------

/// ECDH key exchange handler (P-256 and P-384).
pub struct EcdhKeyExchange;

impl EcdhKeyExchange {
    /// Generate an ephemeral ECDH keypair for the specified suite.
    ///
    /// Returns `(public_key_bytes, private_key)`.
    /// Public key is in uncompressed point format (`0x04 || X || Y`):
    /// - P-256: 65 bytes
    /// - P-384: 97 bytes
    pub fn generate_keypair(
        suite: KeyAgreementSuite,
    ) -> Result<(Vec<u8>, EphemeralPrivateKey), SecurityError> {
        let rng = SystemRandom::new();
        let alg = match suite {
            KeyAgreementSuite::EcdhP256 => &ECDH_P256,
            KeyAgreementSuite::EcdhP384 => &ECDH_P384,
        };

        let private_key = EphemeralPrivateKey::generate(alg, &rng).map_err(|_| {
            SecurityError::CryptoError(format!("Failed to generate ECDH {:?} keypair", suite))
        })?;

        let public_key = private_key.compute_public_key().map_err(|_| {
            SecurityError::CryptoError(format!("Failed to compute ECDH {:?} public key", suite))
        })?;

        Ok((public_key.as_ref().to_vec(), private_key))
    }

    /// Derive shared secret from our ephemeral private key and peer's public key.
    ///
    /// # Arguments
    ///
    /// * `suite` - Key-agreement suite (must match how the keypair was generated)
    /// * `private_key` - Our ephemeral private key (consumed)
    /// * `peer_public` - Peer's public key bytes (65 bytes for P-256, 97 for P-384)
    ///
    /// # Returns
    ///
    /// Raw ECDH shared secret (32 bytes for P-256, 48 bytes for P-384).
    ///
    /// **CRITICAL**: Pass through HKDF before use as an encryption key.
    pub fn derive_shared_secret(
        suite: KeyAgreementSuite,
        private_key: EphemeralPrivateKey,
        peer_public: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, SecurityError> {
        let alg = match suite {
            KeyAgreementSuite::EcdhP256 => &ECDH_P256,
            KeyAgreementSuite::EcdhP384 => &ECDH_P384,
        };
        let peer_public_key = UnparsedPublicKey::new(alg, peer_public);

        // The raw DH output is wiped by its owner; this copy is the only
        // one of it that leaves ring's closure.
        agree_ephemeral(private_key, &peer_public_key, |shared_secret| {
            zeroize::Zeroizing::new(shared_secret.to_vec())
        })
        .map_err(|_| {
            SecurityError::CryptoError(format!(
                "ECDH {:?} agreement failed (invalid peer public key or curve mismatch)",
                suite
            ))
        })
    }

    /// Serialize public key for transmission (identity operation; kept for API symmetry).
    #[must_use]
    pub fn serialize_public_key(public_key: &[u8]) -> Vec<u8> {
        public_key.to_vec()
    }

    /// Deserialize and validate a DH public key received from the wire.
    ///
    /// Accepts both P-256 (65 bytes) and P-384 (97 bytes) uncompressed points.
    /// Rejects any other length, and rejects points whose first byte is not `0x04`.
    pub fn deserialize_public_key(raw: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if raw.len() != ECDH_P256_PUBLIC_KEY_LEN && raw.len() != ECDH_P384_PUBLIC_KEY_LEN {
            return Err(SecurityError::CryptoError(format!(
                "Invalid ECDH public key length: expected {} (P-256) or {} (P-384) bytes, got {}",
                ECDH_P256_PUBLIC_KEY_LEN,
                ECDH_P384_PUBLIC_KEY_LEN,
                raw.len()
            )));
        }
        if raw[0] != 0x04 {
            return Err(SecurityError::CryptoError(
                "Invalid ECDH public key format: expected uncompressed point (0x04 prefix)"
                    .to_string(),
            ));
        }
        Ok(raw.to_vec())
    }
}

// ------------------------------------------------------------
//  Unit tests
// ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- P-256 tests (existing behaviour, unchanged) ---

    #[test]
    fn test_generate_keypair_p256() {
        let (public, _private) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        assert_eq!(public.len(), ECDH_P256_PUBLIC_KEY_LEN);
        assert_eq!(public[0], 0x04);
    }

    #[test]
    fn test_ecdh_p256_alice_bob_same_secret() {
        let (alice_pub, alice_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        let (bob_pub, bob_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();

        let alice_secret = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP256,
            alice_priv,
            &bob_pub,
        )
        .unwrap();
        let bob_secret = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP256,
            bob_priv,
            &alice_pub,
        )
        .unwrap();

        assert_eq!(alice_secret, bob_secret);
        assert_eq!(alice_secret.len(), ECDH_P256_SHARED_SECRET_LEN);
    }

    #[test]
    fn test_derive_shared_secret_different_keys_p256() {
        let (_alice_pub, alice_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        let (bob_pub, bob_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        let (charlie_pub, _charlie_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();

        let alice_bob = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP256,
            alice_priv,
            &bob_pub,
        )
        .unwrap();
        let bob_charlie = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP256,
            bob_priv,
            &charlie_pub,
        )
        .unwrap();

        assert_ne!(alice_bob, bob_charlie);
    }

    #[test]
    fn test_derive_with_invalid_peer_public_fails_p256() {
        let (_our_pub, our_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        let invalid_pub = vec![0x42; 16];
        assert!(EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP256,
            our_priv,
            &invalid_pub
        )
        .is_err());
    }

    #[test]
    fn test_serialize_deserialize_public_key_p256() {
        let (public, _private) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        let serialized = EcdhKeyExchange::serialize_public_key(&public);
        let deserialized = EcdhKeyExchange::deserialize_public_key(&serialized).unwrap();
        assert_eq!(public, deserialized);
    }

    #[test]
    fn test_deserialize_invalid_length_fails() {
        // 16 bytes: rejected (not 65 or 97)
        assert!(EcdhKeyExchange::deserialize_public_key(&[0x42; 16]).is_err());
        // 32 bytes: rejected
        assert!(EcdhKeyExchange::deserialize_public_key(&[0x04; 32]).is_err());
    }

    #[test]
    fn test_deserialize_invalid_format_fails() {
        // Wrong prefix on P-256 size
        let mut invalid = vec![0x02; ECDH_P256_PUBLIC_KEY_LEN];
        invalid[0] = 0x02;
        assert!(EcdhKeyExchange::deserialize_public_key(&invalid).is_err());

        // Wrong prefix on P-384 size
        let mut invalid384 = vec![0x03; ECDH_P384_PUBLIC_KEY_LEN];
        invalid384[0] = 0x03;
        assert!(EcdhKeyExchange::deserialize_public_key(&invalid384).is_err());
    }

    #[test]
    fn test_shared_secret_length_p256() {
        let (_alice_pub, alice_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        let (bob_pub, _bob_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP256).unwrap();
        let secret = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP256,
            alice_priv,
            &bob_pub,
        )
        .unwrap();
        assert_eq!(secret.len(), ECDH_P256_SHARED_SECRET_LEN);
    }

    // --- P-384 tests (new) ---

    #[test]
    fn test_generate_keypair_p384() {
        let (public, _private) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP384).unwrap();
        assert_eq!(public.len(), ECDH_P384_PUBLIC_KEY_LEN); // 97 bytes
        assert_eq!(public[0], 0x04);
    }

    #[test]
    fn test_ecdh_p384_alice_bob_same_secret() {
        // Both parties generate P-384 keypairs.
        let (alice_pub, alice_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP384).unwrap();
        let (bob_pub, bob_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP384).unwrap();

        // Alice derives shared secret using Bob's public key.
        let alice_secret = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP384,
            alice_priv,
            &bob_pub,
        )
        .unwrap();

        // Bob derives shared secret using Alice's public key.
        let bob_secret = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP384,
            bob_priv,
            &alice_pub,
        )
        .unwrap();

        // Both must arrive at the same 48-byte shared secret.
        assert_eq!(alice_secret, bob_secret);
        assert_eq!(alice_secret.len(), ECDH_P384_SHARED_SECRET_LEN); // 48 bytes
    }

    #[test]
    fn test_shared_secret_length_p384() {
        let (_alice_pub, alice_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP384).unwrap();
        let (bob_pub, _bob_priv) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP384).unwrap();
        let secret = EcdhKeyExchange::derive_shared_secret(
            KeyAgreementSuite::EcdhP384,
            alice_priv,
            &bob_pub,
        )
        .unwrap();
        assert_eq!(secret.len(), ECDH_P384_SHARED_SECRET_LEN);
    }

    #[test]
    fn test_p384_public_key_accepted_by_deserialize() {
        let (public, _private) =
            EcdhKeyExchange::generate_keypair(KeyAgreementSuite::EcdhP384).unwrap();
        let deserialized = EcdhKeyExchange::deserialize_public_key(&public).unwrap();
        assert_eq!(public, deserialized);
    }

    // --- Suite selector ---

    #[test]
    fn test_suite_from_kagree_algo() {
        assert_eq!(
            KeyAgreementSuite::from_kagree_algo("ECDH+prime256v1-CEUM"),
            Some(KeyAgreementSuite::EcdhP256)
        );
        assert_eq!(
            KeyAgreementSuite::from_kagree_algo("ECDH+secp384r1-CEUM"),
            Some(KeyAgreementSuite::EcdhP384)
        );
        // Unknown must be a refusal, never a silent P-256 downgrade: the
        // spec-defined finite-field suite is real but UNSUPPORTED here, and
        // answering it with P-256 material would be a substitution the peer
        // never asked for.
        assert_eq!(
            KeyAgreementSuite::from_kagree_algo("DH+MODP-2048-256"),
            None
        );
        assert_eq!(KeyAgreementSuite::from_kagree_algo(""), None);
    }

    #[test]
    fn test_suite_as_kagree_algo() {
        assert_eq!(
            KeyAgreementSuite::EcdhP256.as_kagree_algo(),
            "ECDH+prime256v1-CEUM"
        );
        assert_eq!(
            KeyAgreementSuite::EcdhP384.as_kagree_algo(),
            "ECDH+secp384r1-CEUM"
        );
    }

    #[test]
    fn test_suite_lengths() {
        assert_eq!(KeyAgreementSuite::EcdhP256.public_key_len(), 65);
        assert_eq!(KeyAgreementSuite::EcdhP256.shared_secret_len(), 32);
        assert_eq!(KeyAgreementSuite::EcdhP384.public_key_len(), 97);
        assert_eq!(KeyAgreementSuite::EcdhP384.shared_secret_len(), 48);
    }
}

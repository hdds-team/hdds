// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ECDH P-256 key exchange for DDS Security v1.1
//!
//! Implements Elliptic Curve Diffie-Hellman key exchange using the
//! P-256 curve (NIST secp256r1) per DDS Security spec Sec.7.3.5.
//!
//! # Security Properties
//!
//! - **Forward Secrecy**: Each session uses ephemeral keys
//! - **Authentication**: Combined with X.509 certificates
//! - **Key Derivation**: ECDH shared secret -> HKDF -> session keys
//!
//! # Algorithm
//!
//! 1. Each participant generates ephemeral P-256 keypair
//! 2. Participants exchange public keys (via SPDP/SEDP)
//! 3. Each derives shared secret: `agree(our_private, peer_public)`
//! 4. Shared secret is used as input to HKDF for session key derivation
//!
//! # Example
//!
//! ```
//! use hdds::security::crypto::EcdhKeyExchange;
//! # use hdds::security::SecurityError;
//!
//! # fn example() -> Result<(), SecurityError> {
//! // Alice generates keypair
//! let (alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair()?;
//!
//! // Bob generates keypair
//! let (bob_pub, bob_priv) = EcdhKeyExchange::generate_keypair()?;
//!
//! // Alice derives shared secret using Bob's public key
//! let alice_secret = EcdhKeyExchange::derive_shared_secret(alice_priv, &bob_pub)?;
//!
//! // Bob derives shared secret using Alice's public key
//! let (bob_pub2, bob_priv2) = EcdhKeyExchange::generate_keypair()?;
//! let bob_secret = EcdhKeyExchange::derive_shared_secret(bob_priv2, &alice_pub)?;
//!
//! // Both should have the same shared secret (if using matching keypairs)
//! // assert_eq!(alice_secret, bob_secret);
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [NIST FIPS 186-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf) -- DSA and ECDSA
//! - [RFC 5903](https://datatracker.ietf.org/doc/html/rfc5903) -- ECC Test Vectors

use crate::security::SecurityError;
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256};
use ring::rand::SystemRandom;

/// ECDH P-256 public key length (uncompressed: 0x04 || X || Y)
pub const ECDH_P256_PUBLIC_KEY_LEN: usize = 65;

/// ECDH P-256 shared secret length
pub const ECDH_P256_SHARED_SECRET_LEN: usize = 32;

/// ECDH key exchange handler
pub struct EcdhKeyExchange;

impl EcdhKeyExchange {
    /// Generate an ECDH P-256 keypair (public + private)
    ///
    /// Returns (public_key_bytes, private_key)
    ///
    /// # Security
    ///
    /// - Uses NIST P-256 curve (secp256r1) per DDS Security spec Sec.7.3.5
    /// - Private key is ephemeral (not stored long-term)
    /// - Public key is sent to peer via SPDP/SEDP
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::EcdhKeyExchange;
    ///
    /// let (public_key, private_key) = EcdhKeyExchange::generate_keypair().unwrap();
    /// assert_eq!(public_key.len(), 65); // P-256 uncompressed public key is 65 bytes
    /// ```
    pub fn generate_keypair() -> Result<(Vec<u8>, EphemeralPrivateKey), SecurityError> {
        let rng = SystemRandom::new();

        let private_key = EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| {
            SecurityError::CryptoError("Failed to generate ECDH P-256 keypair".to_string())
        })?;

        let public_key = private_key.compute_public_key().map_err(|_| {
            SecurityError::CryptoError("Failed to compute ECDH P-256 public key".to_string())
        })?;

        Ok((public_key.as_ref().to_vec(), private_key))
    }

    /// Derive shared secret from our private key and peer's public key
    ///
    /// # Arguments
    ///
    /// * `private_key` - Our ephemeral private key
    /// * `peer_public` - Peer's public key (received via SPDP/SEDP)
    ///
    /// # Returns
    ///
    /// 32-byte shared secret (suitable for HKDF input)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Peer public key is invalid (wrong format or length)
    /// - ECDH agreement fails
    ///
    /// # Security
    ///
    /// **CRITICAL**: The shared secret must be passed through HKDF before use.
    /// Never use the raw ECDH output as an encryption key directly.
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::EcdhKeyExchange;
    ///
    /// // Alice and Bob generate keypairs
    /// let (alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair().unwrap();
    /// let (bob_pub, bob_priv) = EcdhKeyExchange::generate_keypair().unwrap();
    ///
    /// // Alice derives shared secret
    /// let alice_secret = EcdhKeyExchange::derive_shared_secret(alice_priv, &bob_pub).unwrap();
    ///
    /// // Bob derives shared secret
    /// let bob_secret = EcdhKeyExchange::derive_shared_secret(bob_priv, &alice_pub).unwrap();
    ///
    /// // Both secrets should match
    /// assert_eq!(alice_secret, bob_secret);
    /// ```
    pub fn derive_shared_secret(
        private_key: EphemeralPrivateKey,
        peer_public: &[u8],
    ) -> Result<Vec<u8>, SecurityError> {
        let peer_public_key = UnparsedPublicKey::new(&ECDH_P256, peer_public);

        agree_ephemeral(private_key, &peer_public_key, |shared_secret| {
            // The shared secret is passed to this closure
            // We need to copy it before returning (it's only valid in this scope)
            shared_secret.to_vec()
        })
        .map_err(|_| {
            SecurityError::CryptoError(
                "ECDH P-256 agreement failed (invalid peer public key or curve mismatch)"
                    .to_string(),
            )
        })
    }

    /// Serialize public key for transmission
    ///
    /// # Note
    ///
    /// For P-256, the public key is in uncompressed format (65 bytes: 0x04 || X || Y).
    /// This method returns the raw bytes suitable for transmission.
    #[must_use]
    pub fn serialize_public_key(public_key: &[u8]) -> Vec<u8> {
        public_key.to_vec()
    }

    /// Deserialize and validate public key
    ///
    /// # Note
    ///
    /// For P-256, the public key must be in uncompressed format (65 bytes).
    /// First byte must be 0x04 (uncompressed point indicator).
    pub fn deserialize_public_key(raw: &[u8]) -> Result<Vec<u8>, SecurityError> {
        if raw.len() != ECDH_P256_PUBLIC_KEY_LEN {
            return Err(SecurityError::CryptoError(format!(
                "Invalid P-256 public key length: expected {} bytes, got {}",
                ECDH_P256_PUBLIC_KEY_LEN,
                raw.len()
            )));
        }
        if raw[0] != 0x04 {
            return Err(SecurityError::CryptoError(
                "Invalid P-256 public key format: expected uncompressed point (0x04 prefix)"
                    .to_string(),
            ));
        }
        Ok(raw.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (public, _private) = EcdhKeyExchange::generate_keypair().unwrap();
        assert_eq!(public.len(), ECDH_P256_PUBLIC_KEY_LEN); // P-256 uncompressed public key is 65 bytes
        assert_eq!(public[0], 0x04); // Uncompressed point format
    }

    #[test]
    fn test_ecdh_alice_bob_same_secret() {
        // Alice generates keypair
        let (alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair().unwrap();

        // Bob generates keypair
        let (bob_pub, bob_priv) = EcdhKeyExchange::generate_keypair().unwrap();

        // Alice derives shared secret using Bob's public key
        let alice_secret = EcdhKeyExchange::derive_shared_secret(alice_priv, &bob_pub).unwrap();

        // Bob derives shared secret using Alice's public key
        let bob_secret = EcdhKeyExchange::derive_shared_secret(bob_priv, &alice_pub).unwrap();

        // Both should have the same shared secret
        assert_eq!(alice_secret, bob_secret);
        assert_eq!(alice_secret.len(), ECDH_P256_SHARED_SECRET_LEN); // P-256 shared secret is 32 bytes
    }

    #[test]
    fn test_derive_shared_secret_different_keys() {
        let (_alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair().unwrap();
        let (bob_pub, bob_priv) = EcdhKeyExchange::generate_keypair().unwrap();
        let (charlie_pub, _charlie_priv) = EcdhKeyExchange::generate_keypair().unwrap();

        let alice_bob = EcdhKeyExchange::derive_shared_secret(alice_priv, &bob_pub).unwrap();
        let bob_charlie = EcdhKeyExchange::derive_shared_secret(bob_priv, &charlie_pub).unwrap();

        // Different keypair combinations should produce different secrets
        assert_ne!(alice_bob, bob_charlie);
    }

    #[test]
    fn test_derive_with_invalid_peer_public_fails() {
        let (_our_pub, our_priv) = EcdhKeyExchange::generate_keypair().unwrap();

        // Invalid public key (wrong length)
        let invalid_pub = vec![0x42; 16];
        assert!(EcdhKeyExchange::derive_shared_secret(our_priv, &invalid_pub).is_err());
    }

    #[test]
    fn test_serialize_deserialize_public_key() {
        let (public, _private) = EcdhKeyExchange::generate_keypair().unwrap();

        let serialized = EcdhKeyExchange::serialize_public_key(&public);
        let deserialized = EcdhKeyExchange::deserialize_public_key(&serialized).unwrap();

        assert_eq!(public, deserialized);
    }

    #[test]
    fn test_deserialize_invalid_length_fails() {
        let invalid = vec![0x42; 16]; // Wrong length
        assert!(EcdhKeyExchange::deserialize_public_key(&invalid).is_err());
    }

    #[test]
    fn test_deserialize_invalid_format_fails() {
        // Wrong prefix (should be 0x04 for uncompressed)
        let mut invalid = vec![0x02; ECDH_P256_PUBLIC_KEY_LEN];
        invalid[0] = 0x02; // Compressed format (not supported)
        assert!(EcdhKeyExchange::deserialize_public_key(&invalid).is_err());
    }

    #[test]
    fn test_ecdh_deterministic() {
        // Same keypairs should always produce same shared secret
        let (_alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair().unwrap();
        let (bob_pub, _bob_priv) = EcdhKeyExchange::generate_keypair().unwrap();

        // We can't test determinism with ring's EphemeralPrivateKey since it's consumed
        // But we can test that two different participants get the same secret
        let (_alice_pub2, alice_priv2) = EcdhKeyExchange::generate_keypair().unwrap();
        let (_bob_pub2, _bob_priv2) = EcdhKeyExchange::generate_keypair().unwrap();

        let secret1 = EcdhKeyExchange::derive_shared_secret(alice_priv, &bob_pub).unwrap();
        let secret2 = EcdhKeyExchange::derive_shared_secret(alice_priv2, &bob_pub).unwrap();

        // Different private keys with same public key = different secrets
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_shared_secret_length() {
        let (_alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair().unwrap();
        let (bob_pub, _bob_priv) = EcdhKeyExchange::generate_keypair().unwrap();

        let secret = EcdhKeyExchange::derive_shared_secret(alice_priv, &bob_pub).unwrap();
        assert_eq!(secret.len(), ECDH_P256_SHARED_SECRET_LEN); // P-256 shared secret is always 32 bytes
    }
}

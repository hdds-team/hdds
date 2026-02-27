// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! AES-256-GCM encryption/decryption for DDS Security v1.1
//!
//! Implements authenticated encryption with associated data (AEAD) using
//! AES-256 in Galois/Counter Mode (GCM) per DDS Security spec Sec.7.3.4.
//!
//! # Security Properties
//!
//! - **Confidentiality**: AES-256 encryption
//! - **Integrity**: GCM authentication tag (128-bit)
//! - **Nonce**: 96-bit random nonce (never reused)
//!
//! # Performance
//!
//! - Encryption: ~200ns per 1KB (target)
//! - Hardware acceleration: Uses AES-NI when available (via ring crate)
//!
//! # References
//!
//! - [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) -- GCM Specification
//! - [ring::aead](https://docs.rs/ring/latest/ring/aead/) -- Rust crypto library

use crate::security::SecurityError;
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

/// AES-256-GCM cipher for encrypting/decrypting DDS Security payloads
pub struct AesGcmCipher {
    /// 256-bit encryption key
    key: [u8; 32],
}

impl AesGcmCipher {
    /// Create a new AES-256-GCM cipher with the given key
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit (32-byte) encryption key
    ///
    /// # Errors
    ///
    /// Returns error if key length is not exactly 32 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::AesGcmCipher;
    ///
    /// let key = [0u8; 32]; // In practice, use a properly derived key
    /// let cipher = AesGcmCipher::new(&key).unwrap();
    /// ```
    pub fn new(key: &[u8; 32]) -> Result<Self, SecurityError> {
        Ok(Self { key: *key })
    }

    /// Encrypt plaintext using AES-256-GCM with associated data
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - 96-bit (12-byte) nonce (must be unique per key)
    /// * `aad` - Associated data authenticated but not encrypted (e.g., session key ID)
    ///
    /// # Returns
    ///
    /// Ciphertext + authentication tag (plaintext.len() + 16 bytes)
    ///
    /// # Security
    ///
    /// **CRITICAL**: Never reuse a nonce with the same key. Use `generate_nonce()`
    /// to create a cryptographically random nonce for each encryption.
    /// The AAD binds the ciphertext to its context, preventing cross-session replay.
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::AesGcmCipher;
    ///
    /// let key = [0u8; 32];
    /// let cipher = AesGcmCipher::new(&key).unwrap();
    /// let nonce = AesGcmCipher::generate_nonce().unwrap();
    /// let aad = b"session-context";
    ///
    /// let plaintext = b"secret message";
    /// let ciphertext = cipher.encrypt(plaintext, &nonce, aad).unwrap();
    /// assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for auth tag
    /// ```
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>, SecurityError> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key).map_err(|_| {
            SecurityError::CryptoError("Failed to create AES-256-GCM key".to_string())
        })?;

        let nonce_sequence = FixedNonceSequence::new(*nonce);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_sequence);

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
            .map_err(|_| SecurityError::CryptoError("AES-256-GCM encryption failed".to_string()))?;

        Ok(in_out)
    }

    /// Decrypt ciphertext using AES-256-GCM with associated data
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Encrypted data + auth tag (from `encrypt()`)
    /// * `nonce` - Same 96-bit nonce used during encryption
    /// * `aad` - Same associated data used during encryption
    ///
    /// # Returns
    ///
    /// Decrypted plaintext (ciphertext.len() - 16 bytes)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Authentication tag verification fails (data tampered)
    /// - AAD doesn't match encryption AAD
    /// - Nonce doesn't match encryption nonce
    /// - Key doesn't match encryption key
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::AesGcmCipher;
    ///
    /// let key = [0u8; 32];
    /// let cipher = AesGcmCipher::new(&key).unwrap();
    /// let nonce = AesGcmCipher::generate_nonce().unwrap();
    /// let aad = b"session-context";
    ///
    /// let plaintext = b"secret message";
    /// let ciphertext = cipher.encrypt(plaintext, &nonce, aad).unwrap();
    /// let decrypted = cipher.decrypt(&ciphertext, &nonce, aad).unwrap();
    ///
    /// assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    /// ```
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> Result<Vec<u8>, SecurityError> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key).map_err(|_| {
            SecurityError::CryptoError("Failed to create AES-256-GCM key".to_string())
        })?;

        let nonce_sequence = FixedNonceSequence::new(*nonce);
        let mut opening_key = OpeningKey::new(unbound_key, nonce_sequence);

        let mut in_out = ciphertext.to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::from(aad), &mut in_out)
            .map_err(|_| {
                SecurityError::CryptoError(
                    "AES-256-GCM decryption failed (authentication tag mismatch or wrong key)"
                        .to_string(),
                )
            })?;

        Ok(plaintext.to_vec())
    }

    /// Generate a cryptographically secure 96-bit nonce
    ///
    /// # Returns
    ///
    /// 12-byte random nonce suitable for AES-GCM encryption
    ///
    /// # Errors
    ///
    /// Returns error if the system CSPRNG fails. This is a hard failure --
    /// we refuse to encrypt with a predictable nonce.
    ///
    /// # Security
    ///
    /// Uses `ring::rand::SystemRandom` for cryptographically secure randomness.
    /// Nonces must never be reused with the same key.
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::AesGcmCipher;
    ///
    /// let nonce1 = AesGcmCipher::generate_nonce().unwrap();
    /// let nonce2 = AesGcmCipher::generate_nonce().unwrap();
    ///
    /// // Nonces should be unique (probability of collision: ~2^-96)
    /// assert_ne!(nonce1, nonce2);
    /// ```
    pub fn generate_nonce() -> Result<[u8; 12], SecurityError> {
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 12];

        rng.fill(&mut nonce).map_err(|_| {
            SecurityError::CryptoError(
                "SystemRandom failed to generate nonce - refusing to encrypt with predictable nonce"
                    .to_string(),
            )
        })?;

        Ok(nonce)
    }
}

impl Drop for AesGcmCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Fixed nonce sequence for ring's BoundKey API
///
/// ring requires a NonceSequence trait for nonce management. Since we
/// generate nonces externally (one per message), we use a fixed sequence
/// that returns the same nonce once, then fails on subsequent calls.
struct FixedNonceSequence {
    nonce: Option<[u8; 12]>,
}

impl FixedNonceSequence {
    fn new(nonce: [u8; 12]) -> Self {
        Self { nonce: Some(nonce) }
    }
}

impl NonceSequence for FixedNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let nonce_bytes = self.nonce.take().ok_or(Unspecified)?;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();
        let aad = b"test-context";

        let plaintext = b"Hello, DDS Security!";
        let ciphertext = cipher.encrypt(plaintext, &nonce, aad).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce, aad).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_1kb() {
        let key = [0x42; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();
        let aad = b"1kb-context";

        let plaintext = vec![0xAA; 1024];
        let ciphertext = cipher.encrypt(&plaintext, &nonce, aad).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce, aad).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_eq!(ciphertext.len(), plaintext.len() + 16); // +16 for GCM tag
    }

    #[test]
    fn test_encrypt_decrypt_1mb() {
        let key = [0x55; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();
        let aad = b"1mb-context";

        let plaintext = vec![0xBB; 1024 * 1024];
        let ciphertext = cipher.encrypt(&plaintext, &nonce, aad).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce, aad).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key1 = [0x00; 32];
        let key2 = [0xFF; 32];

        let cipher1 = AesGcmCipher::new(&key1).unwrap();
        let cipher2 = AesGcmCipher::new(&key2).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();
        let aad = b"wrong-key-test";

        let plaintext = b"secret";
        let ciphertext = cipher1.encrypt(plaintext, &nonce, aad).unwrap();

        // Decrypt with wrong key should fail (auth tag mismatch)
        assert!(cipher2.decrypt(&ciphertext, &nonce, aad).is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce_fails() {
        let key = [0x42; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce1 = [0u8; 12];
        let nonce2 = [1u8; 12];
        let aad = b"wrong-nonce-test";

        let plaintext = b"secret";
        let ciphertext = cipher.encrypt(plaintext, &nonce1, aad).unwrap();

        // Decrypt with wrong nonce should fail
        assert!(cipher.decrypt(&ciphertext, &nonce2, aad).is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_aad_fails() {
        let key = [0x42; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();

        let plaintext = b"secret message";
        let ciphertext = cipher.encrypt(plaintext, &nonce, b"correct-aad").unwrap();

        // Decrypt with wrong AAD should fail (GCM auth tag verification)
        assert!(cipher.decrypt(&ciphertext, &nonce, b"wrong-aad").is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = [0x42; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();
        let aad = b"tamper-test";

        let plaintext = b"secret message";
        let mut ciphertext = cipher.encrypt(plaintext, &nonce, aad).unwrap();

        // Tamper with ciphertext
        ciphertext[5] ^= 0x01;

        // Decrypt should fail (GCM auth tag verification)
        assert!(cipher.decrypt(&ciphertext, &nonce, aad).is_err());
    }

    #[test]
    fn test_generate_nonce_unique() {
        let nonce1 = AesGcmCipher::generate_nonce().unwrap();
        let nonce2 = AesGcmCipher::generate_nonce().unwrap();

        // Nonces should be unique (probability of collision: ~2^-96)
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn test_ciphertext_length() {
        let key = [0x42; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();
        let aad = b"length-test";

        let plaintext = b"test";
        let ciphertext = cipher.encrypt(plaintext, &nonce, aad).unwrap();

        // Ciphertext = plaintext + 16-byte GCM auth tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_encrypt_decrypt_empty_aad() {
        let key = [0u8; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();
        let nonce = AesGcmCipher::generate_nonce().unwrap();

        let plaintext = b"test empty aad";
        let ciphertext = cipher.encrypt(plaintext, &nonce, b"").unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &nonce, b"").unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }
}

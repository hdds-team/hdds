// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cryptographic Plugin for DDS Security v1.1
//!
//! Provides data encryption/decryption using AES-256-GCM and key exchange
//! using ECDH P-256 per OMG DDS Security spec Sec.7.3.
//!
//! # Features
//!
//! - AES-256-GCM encryption for confidentiality
//! - ECDH P-256 key exchange for secure session key establishment
//! - HKDF session key derivation
//! - SecuredPayload submessage format (RTPS v2.5 Sec.9.6.2)
//!
//! # Example
//!
//! ```no_run
//! use hdds::security::crypto::CryptoPlugin;
//!
//! let mut plugin = CryptoPlugin::new();
//! let session_key_id = plugin.generate_session_key()?;
//! let encrypted = plugin.encrypt_data(b"secret data", session_key_id)?;
//! let decrypted = plugin.decrypt_data(&encrypted, session_key_id)?;
//! # Ok::<(), hdds::security::SecurityError>(())
//! ```

use crate::security::SecurityError;
use ring::agreement::EphemeralPrivateKey;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

pub mod aes_gcm;
pub mod key_exchange;
pub mod session_keys;
pub mod transform;

// Re-export main types
pub use aes_gcm::AesGcmCipher;
pub use key_exchange::{EcdhKeyExchange, ECDH_P256_PUBLIC_KEY_LEN, ECDH_P256_SHARED_SECRET_LEN};
pub use session_keys::SessionKeyManager;
pub use transform::SecuredPayload;

/// DDS Security v1.1 session key derivation info string
const SESSION_KEY_INFO: &[u8] = b"DDS Security v1.1 Session Key";

/// Cryptographic plugin implementing DDS Security v1.1 Sec.7.3
pub struct CryptoPlugin {
    /// Session key manager for key derivation and rotation
    key_manager: SessionKeyManager,
    /// Our current ECDH keypair (public key bytes, private key)
    /// Regenerated for each new key exchange to ensure forward secrecy
    pending_keypair: Option<(Vec<u8>, EphemeralPrivateKey)>,
}

impl CryptoPlugin {
    /// Create a new crypto plugin
    #[must_use]
    pub fn new() -> Self {
        Self {
            key_manager: SessionKeyManager::new(),
            pending_keypair: None,
        }
    }

    /// Initiate ECDH key exchange by generating our ephemeral keypair
    ///
    /// Returns our public key to send to the peer.
    /// The private key is kept internally for `complete_key_exchange`.
    ///
    /// # Returns
    ///
    /// Our P-256 public key (65 bytes, uncompressed format)
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::CryptoPlugin;
    ///
    /// let mut plugin = CryptoPlugin::new();
    /// let our_public_key = plugin.initiate_key_exchange().unwrap();
    /// assert_eq!(our_public_key.len(), 65); // P-256 uncompressed public key
    /// // Send our_public_key to peer...
    /// ```
    pub fn initiate_key_exchange(&mut self) -> Result<Vec<u8>, SecurityError> {
        let (public_key, private_key) = EcdhKeyExchange::generate_keypair()?;
        let public_key_copy = public_key.clone();
        self.pending_keypair = Some((public_key, private_key));
        Ok(public_key_copy)
    }

    /// Complete ECDH key exchange using peer's public key
    ///
    /// Derives a session key from the ECDH shared secret using HKDF.
    /// Must be called after `initiate_key_exchange`.
    ///
    /// # Arguments
    ///
    /// * `peer_public_key` - Peer's P-256 public key (65 bytes, uncompressed)
    ///
    /// # Returns
    ///
    /// Session key ID for use with `encrypt_data`/`decrypt_data`
    ///
    /// # Example
    ///
    /// ```no_run
    /// use hdds::security::crypto::CryptoPlugin;
    ///
    /// let mut alice = CryptoPlugin::new();
    /// let mut bob = CryptoPlugin::new();
    ///
    /// // Alice initiates
    /// let alice_pub = alice.initiate_key_exchange().unwrap();
    ///
    /// // Bob initiates
    /// let bob_pub = bob.initiate_key_exchange().unwrap();
    ///
    /// // Alice completes with Bob's public key
    /// let alice_key_id = alice.complete_key_exchange(&bob_pub).unwrap();
    ///
    /// // Bob completes with Alice's public key
    /// let bob_key_id = bob.complete_key_exchange(&alice_pub).unwrap();
    ///
    /// // Both now have session keys derived from the same shared secret
    /// ```
    pub fn complete_key_exchange(&mut self, peer_public_key: &[u8]) -> Result<u64, SecurityError> {
        // Take our pending keypair (consumes the private key)
        let (our_public, private_key) = self.pending_keypair.take().ok_or_else(|| {
            SecurityError::CryptoError(
                "No pending key exchange - call initiate_key_exchange first".to_string(),
            )
        })?;

        // Validate peer's public key
        EcdhKeyExchange::deserialize_public_key(peer_public_key)?;

        // Derive ECDH shared secret
        let mut shared_secret =
            EcdhKeyExchange::derive_shared_secret(private_key, peer_public_key)?;

        // Generate unique salt from both public keys (ensures unique session keys)
        // Salt = SHA256(our_public || peer_public) - deterministic for both parties
        let mut salt_input = Vec::with_capacity(our_public.len() + peer_public_key.len());
        // Use consistent ordering: smaller public key first (lexicographic)
        if our_public < peer_public_key.to_vec() {
            salt_input.extend_from_slice(&our_public);
            salt_input.extend_from_slice(peer_public_key);
        } else {
            salt_input.extend_from_slice(peer_public_key);
            salt_input.extend_from_slice(&our_public);
        }

        // Derive session key using HKDF
        let session_key =
            SessionKeyManager::derive_session_key(&shared_secret, &salt_input, SESSION_KEY_INFO)?;

        // Zeroize shared secret immediately after key derivation
        shared_secret.zeroize();

        // Store and return key ID
        Ok(self.key_manager.store_session_key(session_key))
    }

    /// Encrypt data using the specified session key
    ///
    /// Uses the session key ID as AAD (Associated Authenticated Data) to bind
    /// the ciphertext to its session context, preventing cross-session replay.
    pub fn encrypt_data(
        &self,
        plaintext: &[u8],
        session_key_id: u64,
    ) -> Result<Vec<u8>, SecurityError> {
        let key = self
            .key_manager
            .get_session_key(session_key_id)
            .ok_or_else(|| {
                SecurityError::CryptoError(format!("Session key {} not found", session_key_id))
            })?;

        let cipher = AesGcmCipher::new(&key)?;
        let nonce = AesGcmCipher::generate_nonce()?;
        let aad = session_key_id.to_le_bytes();
        let ciphertext = cipher.encrypt(plaintext, &nonce, &aad)?;

        // Build SecuredPayload submessage
        let secured = SecuredPayload {
            session_key_id,
            nonce,
            ciphertext,
        };

        secured.encode()
    }

    /// Decrypt data using the specified session key
    ///
    /// Verifies that the AAD (session key ID) matches, preventing
    /// cross-session ciphertext replay attacks.
    pub fn decrypt_data(
        &self,
        secured_data: &[u8],
        session_key_id: u64,
    ) -> Result<Vec<u8>, SecurityError> {
        let secured = SecuredPayload::decode(secured_data)?;

        if secured.session_key_id != session_key_id {
            return Err(SecurityError::CryptoError(format!(
                "Session key ID mismatch: expected {}, got {}",
                session_key_id, secured.session_key_id
            )));
        }

        let key = self
            .key_manager
            .get_session_key(session_key_id)
            .ok_or_else(|| {
                SecurityError::CryptoError(format!("Session key {} not found", session_key_id))
            })?;

        let cipher = AesGcmCipher::new(&key)?;
        let aad = session_key_id.to_le_bytes();
        cipher.decrypt(&secured.ciphertext, &secured.nonce, &aad)
    }

    /// Generate a random session key (for testing or fallback)
    ///
    /// # Note
    ///
    /// For production use with peer communication, prefer the ECDH-based
    /// `initiate_key_exchange` + `complete_key_exchange` flow which provides
    /// forward secrecy and mutual authentication.
    ///
    /// This method generates a cryptographically random key directly,
    /// suitable for:
    /// - Local encryption (no peer)
    /// - Testing and development
    /// - Fallback when ECDH is not available
    pub fn generate_session_key(&mut self) -> Result<u64, SecurityError> {
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        rng.fill(&mut key).map_err(|_| {
            SecurityError::CryptoError("Failed to generate random session key".to_string())
        })?;

        Ok(self.key_manager.store_session_key(key))
    }

    /// Get access to the session key manager
    #[must_use]
    pub fn key_manager(&self) -> &SessionKeyManager {
        &self.key_manager
    }

    /// Get mutable access to the session key manager
    pub fn key_manager_mut(&mut self) -> &mut SessionKeyManager {
        &mut self.key_manager
    }
}

impl Default for CryptoPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_plugin_roundtrip() {
        let mut plugin = CryptoPlugin::new();
        let key_id = plugin.generate_session_key().unwrap();

        let plaintext = b"Hello, DDS Security!";
        let encrypted = plugin.encrypt_data(plaintext, key_id).unwrap();
        let decrypted = plugin.decrypt_data(&encrypted, key_id).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let mut plugin = CryptoPlugin::new();
        let key1 = plugin.generate_session_key().unwrap();
        let key2 = plugin.generate_session_key().unwrap();

        let plaintext = b"secret";
        let encrypted = plugin.encrypt_data(plaintext, key1).unwrap();

        // Decrypt with wrong key should fail
        assert!(plugin.decrypt_data(&encrypted, key2).is_err());
    }

    #[test]
    fn test_ecdh_key_exchange_roundtrip() {
        let mut alice = CryptoPlugin::new();
        let mut bob = CryptoPlugin::new();

        // Alice and Bob both initiate key exchange
        let alice_pub = alice.initiate_key_exchange().unwrap();
        let bob_pub = bob.initiate_key_exchange().unwrap();

        // Public keys should be P-256 format (65 bytes, 0x04 prefix)
        assert_eq!(alice_pub.len(), ECDH_P256_PUBLIC_KEY_LEN);
        assert_eq!(bob_pub.len(), ECDH_P256_PUBLIC_KEY_LEN);
        assert_eq!(alice_pub[0], 0x04);
        assert_eq!(bob_pub[0], 0x04);

        // Both complete with peer's public key
        let alice_key_id = alice.complete_key_exchange(&bob_pub).unwrap();
        let bob_key_id = bob.complete_key_exchange(&alice_pub).unwrap();

        // Now Alice encrypts a message
        let plaintext = b"Secret message via ECDH!";
        let encrypted = alice.encrypt_data(plaintext, alice_key_id).unwrap();

        // Bob should be able to decrypt it (they derived the same session key)
        // We need to get the actual key bytes to verify they match
        let alice_key = alice.key_manager().get_session_key(alice_key_id).unwrap();
        let bob_key = bob.key_manager().get_session_key(bob_key_id).unwrap();

        // Both parties derived the same session key!
        assert_eq!(alice_key, bob_key);

        // Bob can decrypt Alice's message
        let decrypted = bob.decrypt_data(&encrypted, bob_key_id).unwrap();
        assert_eq!(plaintext.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_complete_key_exchange_without_initiate_fails() {
        let mut plugin = CryptoPlugin::new();
        let fake_peer_pub = vec![0x04; ECDH_P256_PUBLIC_KEY_LEN];

        // Should fail because we didn't call initiate_key_exchange first
        assert!(plugin.complete_key_exchange(&fake_peer_pub).is_err());
    }

    #[test]
    fn test_complete_key_exchange_invalid_peer_key_fails() {
        let mut plugin = CryptoPlugin::new();
        let _our_pub = plugin.initiate_key_exchange().unwrap();

        // Invalid peer key (wrong length)
        let invalid_peer = vec![0x04; 32];
        assert!(plugin.complete_key_exchange(&invalid_peer).is_err());

        // Need to re-initiate after the failed attempt consumed the keypair
        let _our_pub = plugin.initiate_key_exchange().unwrap();

        // Invalid peer key (wrong prefix)
        let mut invalid_peer = vec![0x02; ECDH_P256_PUBLIC_KEY_LEN];
        invalid_peer[0] = 0x02;
        assert!(plugin.complete_key_exchange(&invalid_peer).is_err());
    }

    #[test]
    fn test_initiate_key_exchange_returns_different_keys() {
        let mut plugin = CryptoPlugin::new();

        let pub1 = plugin.initiate_key_exchange().unwrap();
        let pub2 = plugin.initiate_key_exchange().unwrap();

        // Each call should generate a new keypair (forward secrecy)
        assert_ne!(pub1, pub2);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Session key management and HKDF derivation for DDS Security v1.1
//!
//! Implements HMAC-based Key Derivation Function (HKDF) per RFC 5869
//! for deriving session encryption keys from ECDH shared secrets.
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
//! use hdds::security::crypto::{SessionKeyManager, EcdhKeyExchange};
//! # use hdds::security::SecurityError;
//!
//! # fn example() -> Result<(), SecurityError> {
//! let mut manager = SessionKeyManager::new();
//!
//! // Generate ECDH keypairs
//! let (alice_pub, alice_priv) = EcdhKeyExchange::generate_keypair()?;
//! let (bob_pub, _bob_priv) = EcdhKeyExchange::generate_keypair()?;
//!
//! // Derive shared secret
//! let shared_secret = EcdhKeyExchange::derive_shared_secret(alice_priv, &bob_pub)?;
//!
//! // Derive session key from shared secret
//! let salt = b"DDS Security Session";
//! let info = b"AES-256-GCM Key";
//! let session_key = SessionKeyManager::derive_session_key(
//!     &shared_secret,
//!     salt,
//!     info
//! )?;
//!
//! // Store session key
//! let key_id = manager.store_session_key(session_key);
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) -- HKDF Specification
//! - [NIST SP 800-108](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-108.pdf) -- Key Derivation

use crate::security::SecurityError;
use ring::hkdf::{Salt, HKDF_SHA256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroize;

/// Session key manager for storing and rotating encryption keys
pub struct SessionKeyManager {
    /// Key storage (key_id -> 256-bit key)
    keys: HashMap<u64, [u8; 32]>,
    /// Monotonic key ID counter
    next_key_id: AtomicU64,
}

impl SessionKeyManager {
    /// Create a new session key manager
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            next_key_id: AtomicU64::new(1),
        }
    }

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
    ) -> Result<[u8; 32], SecurityError> {
        // HKDF-Extract: shared_secret + salt -> PRK
        let salt = Salt::new(HKDF_SHA256, salt);
        let prk = salt.extract(shared_secret);

        // HKDF-Expand: PRK + info -> session_key
        let mut session_key = [0u8; 32];
        prk.expand(&[info], HKDF_SHA256)
            .map_err(|_| SecurityError::CryptoError("HKDF expand failed".to_string()))?
            .fill(&mut session_key)
            .map_err(|_| SecurityError::CryptoError("HKDF fill failed".to_string()))?;

        Ok(session_key)
    }

    /// Store a session key and return its ID
    ///
    /// # Arguments
    ///
    /// * `key` - 256-bit session key (from `derive_session_key`)
    ///
    /// # Returns
    ///
    /// Unique session key ID (monotonically increasing)
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::SessionKeyManager;
    ///
    /// let mut manager = SessionKeyManager::new();
    /// let key = [0x42; 32];
    ///
    /// let key_id = manager.store_session_key(key);
    /// assert!(key_id > 0);
    /// ```
    pub fn store_session_key(&mut self, key: [u8; 32]) -> u64 {
        let key_id = self.next_key_id.fetch_add(1, Ordering::Relaxed);
        self.keys.insert(key_id, key);
        key_id
    }

    /// Get a session key by ID
    ///
    /// # Arguments
    ///
    /// * `key_id` - Session key ID (from `store_session_key`)
    ///
    /// # Returns
    ///
    /// Session key if found, None if key ID doesn't exist
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::SessionKeyManager;
    ///
    /// let mut manager = SessionKeyManager::new();
    /// let key = [0x42; 32];
    /// let key_id = manager.store_session_key(key);
    ///
    /// assert_eq!(manager.get_session_key(key_id), Some(key));
    /// assert_eq!(manager.get_session_key(999), None);
    /// ```
    pub fn get_session_key(&self, key_id: u64) -> Option<[u8; 32]> {
        self.keys.get(&key_id).copied()
    }

    /// Rotate session key (generate new key from existing key)
    ///
    /// # Arguments
    ///
    /// * `old_key_id` - Existing session key ID
    ///
    /// # Returns
    ///
    /// New session key ID, or error if old key doesn't exist
    ///
    /// # Security
    ///
    /// Key rotation should happen:
    /// - After N messages (e.g., 1 million messages)
    /// - After T time (e.g., 24 hours)
    /// - On security event (e.g., suspected compromise)
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::SessionKeyManager;
    ///
    /// let mut manager = SessionKeyManager::new();
    /// let key1 = [0x42; 32];
    /// let key1_id = manager.store_session_key(key1);
    ///
    /// let key2_id = manager.rotate_session_key(key1_id).unwrap();
    /// assert!(key2_id > key1_id);
    /// ```
    pub fn rotate_session_key(&mut self, old_key_id: u64) -> Result<u64, SecurityError> {
        let mut old_key = self.get_session_key(old_key_id).ok_or_else(|| {
            SecurityError::CryptoError(format!("Session key {} not found", old_key_id))
        })?;

        // Derive new key from old key using HKDF
        // Salt: old_key_id (ensures uniqueness)
        // Info: "DDS Security Key Rotation"
        let salt = old_key_id.to_le_bytes();
        let info = b"DDS Security Key Rotation";

        let new_key = Self::derive_session_key(&old_key, &salt, info)?;
        old_key.zeroize();
        Ok(self.store_session_key(new_key))
    }

    /// Remove expired session keys
    ///
    /// # Arguments
    ///
    /// * `max_key_id` - Remove all keys with ID <= this value
    ///
    /// # Returns
    ///
    /// Number of keys removed
    ///
    /// # Example
    ///
    /// ```
    /// use hdds::security::crypto::SessionKeyManager;
    ///
    /// let mut manager = SessionKeyManager::new();
    /// let _key1 = manager.store_session_key([0x01; 32]);
    /// let _key2 = manager.store_session_key([0x02; 32]);
    /// let key3 = manager.store_session_key([0x03; 32]);
    ///
    /// let removed = manager.remove_old_keys(key3 - 1);
    /// assert_eq!(removed, 2);
    /// ```
    pub fn remove_old_keys(&mut self, max_key_id: u64) -> usize {
        let before = self.keys.len();
        self.keys.retain(|&key_id, value| {
            if key_id <= max_key_id {
                value.zeroize();
                false
            } else {
                true
            }
        });
        before - self.keys.len()
    }
}

impl Drop for SessionKeyManager {
    fn drop(&mut self) {
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl Default for SessionKeyManager {
    fn default() -> Self {
        Self::new()
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
    fn test_store_and_get_key() {
        let mut manager = SessionKeyManager::new();
        let key = [0x42; 32];

        let key_id = manager.store_session_key(key);
        assert_eq!(manager.get_session_key(key_id), Some(key));
    }

    #[test]
    fn test_key_id_increments() {
        let mut manager = SessionKeyManager::new();

        let key1_id = manager.store_session_key([0x00; 32]);
        let key2_id = manager.store_session_key([0xFF; 32]);

        assert!(key2_id > key1_id);
    }

    #[test]
    fn test_get_nonexistent_key_returns_none() {
        let manager = SessionKeyManager::new();
        assert_eq!(manager.get_session_key(999), None);
    }

    #[test]
    fn test_rotate_session_key() {
        let mut manager = SessionKeyManager::new();
        let key1 = [0x42; 32];
        let key1_id = manager.store_session_key(key1);

        let key2_id = manager.rotate_session_key(key1_id).unwrap();

        assert!(key2_id > key1_id);

        let key2 = manager.get_session_key(key2_id).unwrap();
        // Rotated key should be different from original
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_rotate_nonexistent_key_fails() {
        let mut manager = SessionKeyManager::new();
        assert!(manager.rotate_session_key(999).is_err());
    }

    #[test]
    fn test_remove_old_keys() {
        let mut manager = SessionKeyManager::new();
        let key1_id = manager.store_session_key([0x01; 32]);
        let key2_id = manager.store_session_key([0x02; 32]);
        let key3_id = manager.store_session_key([0x03; 32]);

        let removed = manager.remove_old_keys(key2_id);
        assert_eq!(removed, 2); // key1 and key2 removed

        assert_eq!(manager.get_session_key(key1_id), None);
        assert_eq!(manager.get_session_key(key2_id), None);
        assert!(manager.get_session_key(key3_id).is_some());
    }

    #[test]
    fn test_hkdf_output_length() {
        let shared_secret = vec![0x42; 32];
        let key = SessionKeyManager::derive_session_key(&shared_secret, b"salt", b"info").unwrap();

        assert_eq!(key.len(), 32); // AES-256 key size
    }
}

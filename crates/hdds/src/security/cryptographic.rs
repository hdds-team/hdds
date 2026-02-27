// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cryptographic Plugin SPI
//!
//! AES-256-GCM encryption for RTPS submessages.
//!
//! # OMG DDS Security v1.1 Sec.8.5 (Cryptographic)
//!
//! **Phase 1 Prep (Mode Nuit 2025-10-26):** Trait defined only

use super::SecurityError;

/// Cryptographic plugin trait
///
/// Encrypts RTPS DATA submessages using AES-256-GCM.
pub trait CryptographicPlugin: Send + Sync {
    /// Encrypt RTPS DATA payload
    ///
    /// # Arguments
    /// - `plaintext`: Original payload bytes
    /// - `session_key_id`: Identifier for current session key
    ///
    /// # Returns
    /// - `Ok(ciphertext)`: IV + encrypted payload + GMAC tag
    /// - `Err(SecurityError)`: Encryption failed
    fn encrypt_data(&self, plaintext: &[u8], session_key_id: u64)
        -> Result<Vec<u8>, SecurityError>;

    /// Decrypt RTPS DATA payload
    ///
    /// # Arguments
    /// - `ciphertext`: IV + encrypted payload + GMAC tag
    /// - `session_key_id`: Identifier for session key
    ///
    /// # Returns
    /// - `Ok(plaintext)`: Decrypted payload
    /// - `Err(SecurityError)`: Decryption or GMAC verification failed
    fn decrypt_data(
        &self,
        ciphertext: &[u8],
        session_key_id: u64,
    ) -> Result<Vec<u8>, SecurityError>;

    /// Generate new session key (called periodically for key rotation)
    fn generate_session_key(&self) -> Result<u64, SecurityError>;
}

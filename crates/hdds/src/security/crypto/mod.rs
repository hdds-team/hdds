// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cryptographic plumbing for DDS Security v1.1 (OMG spec Sec.7.3).
//!
//! [`CryptoPlugin`] itself is a MARKER, not a cipher: the suite builds one
//! iff `enable_encryption(true)`, and its presence is the "encryption
//! requested" predicate the write path consults before every emission --
//! with a plugin present, a leg that cannot seal REFUSES instead of falling
//! through to cleartext. It holds no key material. An earlier draft carried
//! a parallel ECDH + session-key-registry API on this struct; the data plane
//! that shipped never called it, so it was deleted rather than left as a
//! second key store that would drift from the real one (`data_keys`).
//!
//! The live cryptography is in the submodules:
//!
//! - `aes_gcm` -- the AES-256-GCM cipher primitive
//! - `key_exchange` -- ECDH P-256/P-384 key agreement (driven by `handshake`)
//! - `session_keys` -- static HKDF derivation helpers (RFC 5869)
//! - `secure_sedp` -- symmetric protection of SEDP and ParticipantMessage
//! - `secure_submessage` -- the DDS-Security 1.1 SEC_PREFIX / SEC_BODY /
//!   SEC_POSTFIX codec the spec shape of secure SEDP uses
//! - `peer_keys` -- per-peer key material, derived at handshake completion
//! - `kx_keys` -- Table 67/68 KxKeys for the ParticipantVolatileMessageSecure
//!   channel itself, derived from the authentication SharedSecret
//! - `volatile` -- key distribution over ParticipantVolatileMessageSecure
//! - `crypto_token` -- the builtin DDS:Crypto:AES_GCM_GMAC CryptoToken and
//!   its KeyMaterial_AES_GCM_GMAC payload (Table 66)
//! - `participant_keys` -- this participant's own key material for whole
//!   RTPS message protection and each peer's, exchanged as
//!   ParticipantCryptoTokens (no consumer: encode_rtps_message is not
//!   implemented)
//! - `data_keys` -- the ONE store for data-plane writer keys, local and remote
//! - `user_data` -- sealing of user-data payloads (`user_data::encode_serialized_payload`
//!   is the data plane's entry point)

pub mod aes_gcm;
pub mod key_exchange;
pub mod session_keys;

/// Symmetric encryption helpers for secure SEDP and ParticipantMessage tunnels.
#[cfg(feature = "security")]
pub mod secure_sedp;

/// DDS-Security 1.1 submessage protection (SEC_PREFIX / SEC_BODY /
/// SEC_POSTFIX) by the builtin AES-GCM-GMAC transformation.
#[cfg(feature = "security")]
pub mod secure_submessage;

/// Per-peer key material, derived once at handshake completion.
#[cfg(feature = "security")]
pub mod peer_keys;

/// Table 67/68 KxKeys for the ParticipantVolatileMessageSecure channel.
#[cfg(feature = "security")]
pub mod kx_keys;

/// Key-distribution messages for the ParticipantVolatileMessageSecure channel.
#[cfg(feature = "security")]
pub mod volatile;

/// The builtin DDS:Crypto:AES_GCM_GMAC CryptoToken (Table 66).
#[cfg(feature = "security")]
pub mod crypto_token;

/// This participant's own metatraffic key and each peer's, exchanged as
/// ParticipantCryptoTokens.
#[cfg(feature = "security")]
pub mod participant_keys;

/// Store for data-plane writer keys, local and remote.
#[cfg(feature = "security")]
pub mod data_keys;

/// AES-256-GCM protection of user-data payloads (the data plane itself).
#[cfg(feature = "security")]
pub mod user_data;

// Re-export main types
pub use aes_gcm::AesGcmCipher;
pub use key_exchange::{
    EcdhKeyExchange, KeyAgreementSuite, ECDH_P256_PUBLIC_KEY_LEN, ECDH_P256_SHARED_SECRET_LEN,
    ECDH_P384_PUBLIC_KEY_LEN, ECDH_P384_SHARED_SECRET_LEN,
};
pub use session_keys::SessionKeyManager;

#[cfg(feature = "security")]
pub use secure_sedp::find_data_cdr_bounds;

/// Marker: encryption was requested for this participant.
///
/// Built by `SecurityPluginSuite::new` iff `enable_encryption(true)`. The
/// write path treats `Option<&CryptoPlugin>` presence as its fail-closed
/// switch: encryption requested means every emission is sealed or refused,
/// never cleartext. Key material lives elsewhere on purpose -- per-peer keys
/// in the handshake machine, data-plane writer keys in `data_keys`.
pub struct CryptoPlugin;

impl CryptoPlugin {
    /// Create the encryption-requested marker.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for CryptoPlugin {
    fn default() -> Self {
        Self::new()
    }
}

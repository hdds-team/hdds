// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Store for this participant's own participant key material and each
//! authenticated peer's, exchanged as `ParticipantCryptoTokens` (DDS Security
//! v1.1 Sec.7.4.4.6.1, Sec.8.8.9.1) over the volatile channel.
//!
//! # What this key material protects
//!
//! Whole RTPS messages, and nothing else. Sec.8.8.9.1: the participant key
//! exchange "propagates the key material related to encoding/signing/
//! decoding/verifying the whole RTPS message. In other words the key
//! material needed to support the CryptoTransform operations
//! encode_rtps_message and decode_rtps_message". Table 70
//! (`register_matched_remote_participant`): "The
//! Participant2ParticipantKeyMaterial shall be used to transform and
//! authenticate the RTPS messages", and Table 71
//! (`create_local_participant_crypto_tokens`) puts exactly that material in
//! the token.
//!
//! It does NOT protect secure discovery. The secure builtin endpoints
//! (Sec.7.4.5) - the secure SEDP writers and readers included - get their
//! own key material from `register_local_datawriter` /
//! `register_local_datareader` (Sec.8.8.8.3; Table 59,
//! `is_discovery_encrypted`), exchanged as DatawriterCryptoTokens /
//! DatareaderCryptoTokens (Sec.8.8.9.2).
//!
//! Whole-message protection (`rtps_protection_kind` other than NONE) is not
//! implemented and a governance document asking for it is refused at load
//! (`access::permissions`), so this store is minted, exchanged and installed
//! but has no consumer yet.
//!
//! # One local key, many remote keys
//!
//! Unlike `data_keys` (one map, both directions, because a writer's key and
//! a reader's copy of it share one `(writer_guid, key_id)` lookup), this
//! store is asymmetric by construction: this participant has exactly ONE
//! key material of its own (minted once, here, at construction), and a
//! DIFFERENT one for every authenticated peer (each peer mints its own).
//! Protecting OUR outgoing messages and verifying a PEER's incoming ones are
//! therefore never the same lookup: [`Self::local_key_material`] for the
//! first, [`Self::get_remote`] for the second.

use crate::security::audit::{self, CryptoOutcome, SecurityEvent, SharedAuditLogger};
use crate::security::crypto::data_keys::WriterKey;
use crate::security::SecurityError;
use parking_lot::RwLock;
use std::collections::HashMap;

/// Store for this participant's own participant key material (minted once)
/// and each authenticated peer's (installed on receipt).
pub(crate) struct ParticipantKeyStore {
    /// This participant's own `(key_id, key)`. `None` when encryption is
    /// not enabled: nothing would ever read it, and minting a key nobody
    /// uses is the same unreachable scaffolding this subsystem keeps
    /// getting built out of.
    local: Option<(u32, WriterKey)>,
    /// One entry per authenticated peer, keyed by its 12-byte GUID prefix.
    remote: RwLock<HashMap<[u8; 12], (u32, WriterKey)>>,
    audit: Option<SharedAuditLogger>,
}

impl ParticipantKeyStore {
    /// Mint this participant's own key material when `enable_encryption`
    /// is true; build an otherwise-empty store either way.
    ///
    /// The key id is minted within 32 bits from the start (4 random bytes,
    /// not 8): `KeyMaterial_AES_GCM_GMAC.sender_key_id` is
    /// `CryptoTransformKeyId`, `octet[4]` (Sec.9.5.2.1.1), and widening a
    /// value born within that width is lossless by construction -- the
    /// same lesson `dds::writer::builder`'s data-plane key id already
    /// applies, not relearned here as a narrowing-on-the-wire bug.
    pub(crate) fn new(
        enable_encryption: bool,
        audit: Option<SharedAuditLogger>,
    ) -> Result<Self, SecurityError> {
        let local = if enable_encryption {
            Some(WriterKey::mint().map_err(|e| {
                SecurityError::CryptoError(format!(
                    "cannot mint the local participant key material: {}",
                    e
                ))
            })?)
        } else {
            None
        };
        Ok(Self {
            local,
            remote: RwLock::new(HashMap::new()),
            audit,
        })
    }

    /// This participant's own `(key_id, key)`, to announce to every
    /// authenticated peer. `None` when encryption is not enabled.
    pub(crate) fn local_key_material(&self) -> Option<(u32, WriterKey)> {
        self.local
            .as_ref()
            .map(|(id, material)| (*id, material.duplicate()))
    }

    /// Install (or replace) `peer_prefix`'s announced key material.
    ///
    /// Idempotent on an identical re-announcement (the same tokens written
    /// again after the peer authenticated again, same as
    /// `data_keys::insert`): no audit record, no
    /// log line, for a value that did not change. A DIFFERENT key for a
    /// peer that already had one is a real rekey and is recorded.
    pub(crate) fn install_remote(&self, peer_prefix: [u8; 12], key_id: u32, key: WriterKey) {
        let mut remote = self.remote.write();
        let changed = match remote.get(&peer_prefix) {
            Some((existing_id, existing_key)) => {
                *existing_id != key_id || !existing_key.same_material(&key)
            }
            None => true,
        };
        if changed {
            remote.insert(peer_prefix, (key_id, key));
        }
        drop(remote);

        if changed {
            audit::record_key_change(
                &self.audit,
                &SecurityEvent::Crypto {
                    key_id: u64::from(key_id),
                    operation: "install_participant_crypto_tokens".to_string(),
                    outcome: CryptoOutcome::Success,
                    timestamp: audit::timestamp_ns(),
                },
            );
        }
    }

    /// `peer_prefix`'s announced participant key material, if one was
    /// installed.
    ///
    /// No production call site: its consumer is `decode_rtps_message`,
    /// which is not implemented (module docs).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn get_remote(&self, peer_prefix: &[u8; 12]) -> Option<(u32, WriterKey)> {
        self.remote
            .read()
            .get(peer_prefix)
            .map(|(id, material)| (*id, material.duplicate()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::crypto::peer_keys::SecretKey;

    fn wk(byte: u8) -> WriterKey {
        WriterKey::new(
            SecretKey::from_bytes([byte; 32]),
            SecretKey::from_bytes([byte ^ 0xFF; 32]),
        )
    }

    #[test]
    fn disabled_encryption_mints_no_local_key() {
        let store = ParticipantKeyStore::new(false, None).expect("new");
        assert!(store.local_key_material().is_none());
    }

    #[test]
    fn enabled_encryption_mints_a_nonzero_local_key() {
        let store = ParticipantKeyStore::new(true, None).expect("new");
        let (id, material) = store.local_key_material().expect("minted");
        assert_ne!(id, 0);
        assert_ne!(material.key.as_bytes(), &[0u8; 32]);
        assert_ne!(material.salt.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn install_then_get_returns_the_key() {
        let store = ParticipantKeyStore::new(false, None).expect("new");
        let prefix = [0x11; 12];
        store.install_remote(prefix, 7, wk(0x22));
        let (id, key) = store.get_remote(&prefix).expect("installed");
        assert_eq!(id, 7);
        assert_eq!(key.key.as_bytes(), &[0x22; 32]);
    }

    #[test]
    fn two_different_peers_keep_two_different_keys() {
        let store = ParticipantKeyStore::new(false, None).expect("new");
        store.install_remote([0xAA; 12], 1, wk(0x01));
        store.install_remote([0xBB; 12], 2, wk(0x02));
        assert_eq!(
            store.get_remote(&[0xAA; 12]).unwrap().1.key.as_bytes(),
            &[0x01; 32]
        );
        assert_eq!(
            store.get_remote(&[0xBB; 12]).unwrap().1.key.as_bytes(),
            &[0x02; 32]
        );
    }

    #[test]
    fn a_rekey_replaces_the_old_key() {
        let store = ParticipantKeyStore::new(false, None).expect("new");
        let prefix = [0x33; 12];
        store.install_remote(prefix, 1, wk(0x01));
        store.install_remote(prefix, 2, wk(0x02));
        let (id, key) = store.get_remote(&prefix).expect("installed");
        assert_eq!(id, 2);
        assert_eq!(key.key.as_bytes(), &[0x02; 32]);
    }

    #[test]
    fn an_unknown_peer_has_no_key() {
        let store = ParticipantKeyStore::new(false, None).expect("new");
        assert!(store.get_remote(&[0x99; 12]).is_none());
    }
}

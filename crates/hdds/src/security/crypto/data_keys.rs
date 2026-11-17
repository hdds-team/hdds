// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Process-side store for data-plane writer keys, local and remote.
//!
//! # Why this map exists next to the handshake map
//!
//! `HandshakeMachine`'s map is keyed by remote PARTICIPANT and cannot address
//! an entity. This store has a different key shape -- `(writer GUID, key
//! id)` -- so it is its own map, and it is ONE map for both directions on
//! purpose:
//!
//! - the LOCAL writer registers its own key here at build time, and the
//!   distributor walks these same entries to know what to announce;
//! - REMOTE keys arriving on the volatile channel land here, and readers look
//!   them up at decrypt time.
//!
//! A separate "keys to announce" list and "keys received" list would be two
//! lists that must agree about the same concept -- a drift
//! pattern. Locality is decided by the GUID prefix, not by
//! which list an entry sits in.
//!
//! # Lookup key
//!
//! `(writer GUID, key id)`, never the key id alone: ids are writer-chosen
//! random values with no global-uniqueness contract, so two writers colliding
//! on an id must not overwrite each other.
//!
//! Mutation through `&self` (RwLock), same access shape as the handshake map,
//! because every caller reaches this through `Arc<SecurityPluginSuite>`.

use crate::core::discovery::GUID;
use crate::security::audit::{self, CryptoOutcome, SecurityEvent, SharedAuditLogger};
use crate::security::crypto::peer_keys::SecretKey;
use crate::security::crypto::secure_submessage::{Transformation, WriterKeyMaterial};
use crate::security::SecurityError;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};

/// Bound hostile or corrupt volatile-channel sources to finite audit state.
const MAX_AUDITED_OPEN_FAILURE_SOURCES: usize = 1024;

/// The master half of one writer's `KeyMaterial_AES_GCM_GMAC`
/// (DDS Security v1.1 Sec.9.5.2.1.1): `master_sender_key` and `master_salt`.
///
/// The salt is minted at random with the key (Table 70,
/// `register_local_datawriter`: the operation "shall create a new
/// KeyMaterial_AES_GCM_GMAC object") and travels with it in the writer's
/// CryptoToken, because the session keys of Sec.9.5.3.3.3 are derived from
/// both: `SessionKey := HMAC256(MasterKey, "SessionKey" | MasterSalt |
/// SessionId)`. A receiver that substitutes any other salt derives other
/// session keys and cannot decode a submessage the writer protected.
///
/// The `transformation_kind` travels with them (Table 70: chosen "according
/// to the setting of corresponding Protection Kind"): AES256_GCM for the
/// user-data writers and an encrypting discovery protection, AES256_GMAC for
/// a signing one.
///
/// Both halves clear themselves on drop; `Debug` redacts them.
pub struct WriterKey {
    /// `master_sender_key`.
    pub key: SecretKey,
    /// `master_salt`.
    pub salt: SecretKey,
    /// `transformation_kind`.
    pub transformation: Transformation,
}

impl WriterKey {
    /// `key` and `salt`, transformation AES256_GCM.
    pub(crate) fn new(key: SecretKey, salt: SecretKey) -> Self {
        Self {
            key,
            salt,
            transformation: Transformation::Aes256Gcm,
        }
    }

    /// Remember retired material for equality checks without retaining its
    /// secret bytes. Fixed-width key, salt and transformation make the
    /// SHA-256 input unambiguous; this digest is never a wire key.
    fn retirement_fingerprint(&self) -> [u8; 32] {
        let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
        hash.update(self.key.as_bytes());
        hash.update(self.salt.as_bytes());
        hash.update(&self.transformation.kind());
        let mut out = [0; 32];
        out.copy_from_slice(hash.finish().as_ref());
        out
    }

    /// The same material, announced and applied as `transformation`.
    #[must_use]
    pub(crate) fn with_transformation(mut self, transformation: Transformation) -> Self {
        self.transformation = transformation;
        self
    }

    /// The material `encode_datawriter_submessage` /
    /// `decode_datawriter_submessage` take, under the key id `key_id`
    /// (`CryptoTransformKeyId`, big endian on the wire, Sec.9.5.2.2).
    pub(crate) fn submessage_material(&self, key_id: u32) -> WriterKeyMaterial {
        WriterKeyMaterial::new(
            *self.key.as_bytes(),
            *self.salt.as_bytes(),
            key_id.to_be_bytes(),
        )
        .with_transformation(self.transformation)
    }

    /// A key and a salt drawn from the system RNG, with a key id within
    /// `CryptoTransformKeyId` (`octet[4]`, Sec.9.5.2.1.1) and never 0.
    pub(crate) fn mint() -> Result<(u32, Self), SecurityError> {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut key = [0u8; 32];
        let mut salt = [0u8; 32];
        let mut id = [0u8; 4];
        let failed = |what: &str| {
            SecurityError::CryptoError(format!(
                "cannot mint writer key material: the system RNG failed on the {}",
                what
            ))
        };
        rng.fill(&mut key).map_err(|_| failed("key"))?;
        rng.fill(&mut salt).map_err(|_| failed("salt"))?;
        rng.fill(&mut id).map_err(|_| failed("key id"))?;
        let material = Self::new(SecretKey::from_bytes(key), SecretKey::from_bytes(salt));
        {
            use zeroize::Zeroize;
            key.zeroize();
            salt.zeroize();
        }
        Ok((u32::from_le_bytes(id).max(1), material))
    }

    /// `key` with a fixed announced salt, for deterministic fixtures.
    #[cfg(test)]
    pub(crate) fn for_tests(key: SecretKey) -> Self {
        Self::new(key, SecretKey::from_bytes([0xA5; 32]))
    }

    /// An owned copy, zeroizing like the original.
    pub(crate) fn duplicate(&self) -> Self {
        Self {
            key: self.key.duplicate_for_store(),
            salt: self.salt.duplicate_for_store(),
            transformation: self.transformation,
        }
    }

    /// Whether both halves are the same material (constant time each), under
    /// the same transformation.
    pub(crate) fn same_material(&self, other: &Self) -> bool {
        // Both comparisons always run: `&` on bools, not `&&`.
        self.key.same_material(&other.key)
            & self.salt.same_material(&other.salt)
            & (self.transformation == other.transformation)
    }
}

impl std::fmt::Debug for WriterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterKey")
            .field("key", &self.key)
            .field("salt", &self.salt)
            .field("transformation", &self.transformation)
            .finish()
    }
}

/// Data-plane writer keys, keyed by `(writer GUID, key id)`.
pub struct DataKeyStore {
    keys: RwLock<HashMap<(GUID, u64), WriterKey>>,
    /// One fingerprint per secure builtin writer from the latest retired authentication
    /// generation. Stale token sweeps cannot reinstall it, under any id.
    retired_material: RwLock<HashMap<GUID, [u8; 32]>>,
    audit: Option<SharedAuditLogger>,
    audited_open_failures: Mutex<HashSet<[u8; 12]>>,
}

impl Default for DataKeyStore {
    fn default() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            retired_material: RwLock::new(HashMap::new()),
            audit: None,
            audited_open_failures: Mutex::new(HashSet::new()),
        }
    }
}

impl DataKeyStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty store that records genuine key transitions.
    pub(crate) fn with_audit_logger(audit: Option<SharedAuditLogger>) -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            retired_material: RwLock::new(HashMap::new()),
            audit,
            audited_open_failures: Mutex::new(HashSet::new()),
        }
    }

    /// Install a key. Idempotent by value: re-announcing the same key is
    /// normal traffic on a best-effort channel, so a duplicate insert is not
    /// an event worth logging. A DIFFERENT key under the same pair replaces
    /// the old one (writer restart with a colliding random id -- the fresh
    /// announcement is the truth).
    ///
    /// Fails closed once the audit chain is degraded: material that would be a
    /// NEW or CHANGED key is refused, because its installation could not be
    /// recorded. Re-announcements of material already installed stay a silent
    /// no-op either way. No audit I/O runs under the store lock.
    pub fn insert(
        &self,
        writer_guid: GUID,
        key_id: u64,
        key: WriterKey,
    ) -> Result<(), SecurityError> {
        let slot = (writer_guid, key_id);
        let mut keys = self.keys.write();
        if self
            .retired_material
            .read()
            .get(&writer_guid)
            .is_some_and(|retired| *retired == key.retirement_fingerprint())
        {
            return Err(SecurityError::CryptoError(
                "retired writer key material".into(),
            ));
        }
        let changed = match keys.get(&slot) {
            Some(existing) => !existing.same_material(&key),
            None => true,
        };
        if changed && audit::is_degraded(&self.audit) {
            drop(keys);
            return Err(SecurityError::CryptoError(
                "audit chain degraded (a record was lost): refusing to install a new \
                 data-plane key until this participant is rebuilt"
                    .into(),
            ));
        }
        if changed {
            // No grace period: a token installation replaces the writer's
            // generation atomically (DDS Security v1.1 Sec.8.8.9.2).
            // Operations already holding a copy may finish; new lookups
            // cannot acquire material from the retired generation.
            keys.retain(|(guid, _), _| *guid != writer_guid);
            keys.insert(slot, key);
        }
        drop(keys);

        if changed {
            // A builtin endpoint (entityKind's two high bits set, DDSI-RTPS
            // v2.5 Sec.9.3.1.2) is a secure builtin endpoint's key material,
            // not a data-plane key; its reader/writer half says which
            // CryptoTokens class minted it (DatareaderCryptoTokens vs
            // DatawriterCryptoTokens, `volatile::is_reader_entity_id`).
            let operation = if writer_guid.entity_id[3] & 0xC0 == 0xC0 {
                if crate::security::crypto::volatile::is_reader_entity_id(writer_guid.entity_id) {
                    "install_builtin_reader_key"
                } else {
                    "install_builtin_writer_key"
                }
            } else {
                "install_data_key"
            };
            audit::record_key_change(
                &self.audit,
                &SecurityEvent::Crypto {
                    key_id,
                    operation: operation.to_string(),
                    outcome: CryptoOutcome::Success,
                    timestamp: audit::timestamp_ns(),
                },
            );
        }
        Ok(())
    }

    /// Report the first failed key-envelope open from each authenticated
    /// peer: one operator-facing WARN, and (when an audit chain is
    /// configured) one audit record.
    ///
    /// Invalid packets can be replayed indefinitely, while the synchronous
    /// file backend calls `sync_all()` for every record. One record per source,
    /// with a hard cap, preserves the forensic signal without turning audit
    /// logging into a disk-amplification path. Key id zero means the envelope
    /// could not be opened far enough to recover its real id.
    ///
    /// The WARN fires regardless of whether an audit chain is configured:
    /// a peer whose envelope this participant cannot open is authenticated
    /// (the handshake already filters out anything that is not an HDDS
    /// peer running compatible authentication, 1.4.x included) but derives
    /// different volatile-channel key material or framing -- a mismatched
    /// HDDS build on this specific channel, or a tampered message -- and an
    /// operator should see that, not only a debug line.
    pub(crate) fn audit_open_failure_once(&self, remote_prefix: [u8; 12]) {
        let mut seen = self.audited_open_failures.lock();
        if seen.contains(&remote_prefix) || seen.len() >= MAX_AUDITED_OPEN_FAILURE_SOURCES {
            return;
        }
        seen.insert(remote_prefix);
        drop(seen);

        log::warn!(
            "[security::volatile] could not open a key-distribution envelope from {:02x?}: \
             the peer derives a different volatile-channel key or wire form (a different \
             HDDS build?), or the message was altered",
            remote_prefix
        );

        if self.audit.is_none() {
            return;
        }

        audit::record_committed(
            &self.audit,
            &SecurityEvent::Crypto {
                key_id: 0,
                operation: "open_data_key_announcement".to_string(),
                outcome: CryptoOutcome::Failed,
                timestamp: audit::timestamp_ns(),
            },
        );
    }

    /// The key for `(writer_guid, key_id)`, if one was installed.
    pub fn get(&self, writer_guid: &GUID, key_id: u64) -> Option<SecretKey> {
        self.keys
            .read()
            .get(&(*writer_guid, key_id))
            .map(|material| material.key.duplicate_for_store())
    }

    /// The whole key material (key and salt) for `(writer_guid, key_id)`, if
    /// one was installed.
    pub fn get_material(&self, writer_guid: &GUID, key_id: u64) -> Option<WriterKey> {
        self.keys
            .read()
            .get(&(*writer_guid, key_id))
            .map(WriterKey::duplicate)
    }

    /// Every entry whose writer GUID starts with `prefix` -- i.e. the LOCAL
    /// writers when called with our own prefix. This is what the distributor
    /// announces to authenticated peers.
    pub fn entries_with_prefix(&self, prefix: &[u8; 12]) -> Vec<(GUID, u64, WriterKey)> {
        self.keys
            .read()
            .iter()
            .filter(|((guid, _), _)| &guid.prefix == prefix)
            .map(|((guid, id), material)| (*guid, *id, material.duplicate()))
            .collect()
    }

    /// Whether a writer has installed token material.
    pub(crate) fn has_writer(&self, writer: &GUID) -> bool {
        self.keys.read().keys().any(|(guid, _)| guid == writer)
    }

    /// The whole key material of one LOCAL writer, by GUID alone (as
    /// [`Self::key_for_writer`]).
    pub fn material_for_writer(&self, writer_guid: &GUID) -> Option<(u64, WriterKey)> {
        self.keys
            .read()
            .iter()
            .find(|((guid, _), _)| guid == writer_guid)
            .map(|((_, id), material)| (*id, material.duplicate()))
    }

    /// The key one LOCAL writer encrypts with, by GUID alone.
    ///
    /// The writer does not carry its own key id around; it minted exactly one
    /// entry at build time, and this is how it finds it back at write time. A
    /// writer with several ids would be a bug this lookup makes visible (it
    /// returns the first and the distribution sweep announces all of them).
    pub fn key_for_writer(&self, writer_guid: &GUID) -> Option<(u64, SecretKey)> {
        self.keys
            .read()
            .iter()
            .find(|((guid, _), _)| guid == writer_guid)
            .map(|((_, id), material)| (*id, material.key.duplicate_for_store()))
    }

    /// Retire one authentication generation. Fingerprints survive until
    /// replacement or departure, preventing stale token reinstallation.
    pub(crate) fn retire_participant(&self, prefix: &[u8; 12]) {
        let mut keys = self.keys.write();
        let mut retired = self.retired_material.write();
        for ((guid, _), material) in keys.iter().filter(|((guid, _), _)| &guid.prefix == prefix) {
            if guid.entity_id[3] & 0xc0 == 0xc0 {
                retired.insert(*guid, material.retirement_fingerprint());
            }
        }
        keys.retain(|(guid, _), _| &guid.prefix != prefix);
    }

    /// Release every writer of a departed participant
    /// (DDS Security v1.1 Sec.8.5.1.7.7-8). Local writers are untouched when
    /// called with the remote participant's prefix.
    pub(crate) fn remove_participant(&self, prefix: &[u8; 12]) {
        self.keys
            .write()
            .retain(|(guid, _), _| &guid.prefix != prefix);
        self.retired_material
            .write()
            .retain(|guid, _| &guid.prefix != prefix);
    }

    /// Remove one writer's key (writer teardown). The distributor stops
    /// announcing it on the next cycle; remote copies age out with the peers.
    pub fn remove_writer(&self, writer_guid: &GUID) {
        self.keys.write().retain(|(guid, _), _| guid != writer_guid);
        self.retired_material.write().remove(writer_guid);
    }

    /// Number of installed keys (tests and diagnostics).
    pub fn len(&self) -> usize {
        self.keys.read().len()
    }

    /// True when no key is installed.
    pub fn is_empty(&self) -> bool {
        self.keys.read().is_empty()
    }
}

impl std::fmt::Debug for DataKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never iterate values here: SecretKey redacts itself, but a count
        // is all a log line legitimately needs anyway.
        write!(f, "DataKeyStore({} keys)", self.keys.read().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::audit::{AuditChain, LoggingPlugin};
    use std::fs;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    fn wk(byte: u8) -> WriterKey {
        WriterKey::new(
            SecretKey::from_bytes([byte; 32]),
            SecretKey::from_bytes([byte ^ 0xFF; 32]),
        )
    }

    fn guid(last: u8) -> GUID {
        GUID::new([0xAB; 12], [0, 0, 0, last])
    }

    #[test]
    fn insert_then_get_returns_the_key() {
        let store = DataKeyStore::new();
        store.insert(guid(1), 7, wk(0x11)).expect("install");

        let got = store.get(&guid(1), 7).expect("key must be present");
        assert_eq!(got.as_bytes(), &[0x11; 32]);
    }

    /// Two writers colliding on a key id must not shadow each other: the GUID
    /// is part of the lookup key, not a decoration.
    #[test]
    fn colliding_key_ids_on_different_writers_coexist() {
        let store = DataKeyStore::new();
        store.insert(guid(1), 7, wk(0x11)).expect("install");
        store.insert(guid(2), 7, wk(0x22)).expect("install");

        assert_eq!(store.get(&guid(1), 7).unwrap().as_bytes(), &[0x11; 32]);
        assert_eq!(store.get(&guid(2), 7).unwrap().as_bytes(), &[0x22; 32]);
    }

    #[test]
    fn retired_key_fingerprint_known_answer() {
        // Independently computed with Python hashlib over key || salt || kind.
        assert_eq!(
            wk(0x11).retirement_fingerprint(),
            [
                0xc1, 0xec, 0x78, 0xe0, 0x54, 0x1a, 0x57, 0x62, 0xbc, 0x81, 0x17, 0x1a, 0x81, 0x3c,
                0x0f, 0x5f, 0x4a, 0x00, 0xc4, 0xba, 0x9b, 0xc8, 0x00, 0x8c, 0xa2, 0x55, 0xa0, 0x5c,
                0x88, 0x85, 0x42, 0xe8
            ]
        );
    }

    #[test]
    fn replacement_authentication_refuses_reannounced_retired_material() {
        let store = DataKeyStore::new();
        let writer = GUID::new([0xab; 12], [0xff, 0, 3, 0xc2]);
        store.insert(writer, 7, wk(0x11)).unwrap();
        store.retire_participant(&writer.prefix);
        assert!(store.get(&writer, 7).is_none());
        assert!(store.insert(writer, 7, wk(0x11)).is_err());
        assert!(
            store.insert(writer, 8, wk(0x11)).is_err(),
            "changing the id cannot revive old material"
        );
        store.insert(writer, 8, wk(0x22)).unwrap();
        assert!(store.get(&writer, 7).is_none());
        assert!(store.get(&writer, 8).is_some());
        store.insert(writer, 7, wk(0x33)).unwrap();
        assert_eq!(
            store.get(&writer, 7).unwrap().as_bytes(),
            &[0x33; 32],
            "a 32-bit id collision with fresh material is not an old-key replay"
        );
        // Departure releases the retired-generation resource as well.
        store.remove_participant(&writer.prefix);
        assert!(store.retired_material.read().is_empty());
    }

    /// Rejection of reannounced retired READER material -- the mirror of
    /// `replacement_authentication_refuses_reannounced_retired_material`
    /// above, which only ever used a WRITER entity id (`0xff,0,3,0xc2`).
    /// `retire_participant`/`insert` key on the GUID alone (prefix +
    /// entity id) and gate on the builtin namespace bits
    /// (`entity_id[3] & 0xc0 == 0xc0`), which a builtin READER id
    /// (`0xc4`/`0xc7`) carries exactly as a builtin writer id
    /// (`0xc2`/`0xc3`) does -- so the mechanism was already reader/writer-
    /// agnostic by construction; this covers the reader case explicitly.
    #[test]
    fn replacement_authentication_refuses_reannounced_retired_reader_material() {
        let store = DataKeyStore::new();
        let reader = GUID::new([0xcd; 12], [0xff, 0, 3, 0xc7]);
        store.insert(reader, 9, wk(0x44)).unwrap();
        store.retire_participant(&reader.prefix);
        assert!(store.get(&reader, 9).is_none());
        assert!(
            store.insert(reader, 9, wk(0x44)).is_err(),
            "the same reader key id, reannounced after retirement, must be refused"
        );
        assert!(
            store.insert(reader, 10, wk(0x44)).is_err(),
            "changing the id cannot revive old reader material either"
        );
        store.insert(reader, 10, wk(0x55)).unwrap();
        assert!(store.get(&reader, 9).is_none());
        assert_eq!(store.get(&reader, 10).unwrap().as_bytes(), &[0x55; 32]);
        store.remove_participant(&reader.prefix);
        assert!(store.retired_material.read().is_empty());
    }

    #[test]
    fn a_new_writer_key_id_retires_its_previous_id_only() {
        let store = DataKeyStore::new();
        store.insert(guid(1), 7, wk(0x11)).unwrap();
        store.insert(guid(2), 7, wk(0x22)).unwrap();
        store.insert(guid(1), 8, wk(0x33)).unwrap();
        assert!(store.get(&guid(1), 7).is_none());
        assert_eq!(store.get(&guid(1), 8).unwrap().as_bytes(), &[0x33; 32]);
        assert_eq!(store.get(&guid(2), 7).unwrap().as_bytes(), &[0x22; 32]);
    }

    #[test]
    fn a_fresh_key_under_the_same_pair_replaces_the_old_one() {
        let store = DataKeyStore::new();
        store.insert(guid(1), 7, wk(0x11)).expect("install");
        store.insert(guid(1), 7, wk(0x99)).expect("install");

        assert_eq!(store.get(&guid(1), 7).unwrap().as_bytes(), &[0x99; 32]);
        assert_eq!(store.len(), 1);
    }

    /// The salt is half of the material: the same key under another salt is
    /// a different key material (it derives other session keys), installed
    /// in place of the old one, not ignored as a re-announcement.
    #[test]
    fn the_same_key_under_another_salt_replaces_the_material() {
        let store = DataKeyStore::new();
        store.insert(guid(1), 7, wk(0x11)).expect("install");
        let resalted = WriterKey::new(
            SecretKey::from_bytes([0x11; 32]),
            SecretKey::from_bytes([0x77; 32]),
        );
        store.insert(guid(1), 7, resalted).expect("install");
        let got = store.get_material(&guid(1), 7).expect("present");
        assert_eq!(got.salt.as_bytes(), &[0x77; 32]);
    }

    #[test]
    fn minted_material_has_a_nonzero_id_and_independent_key_and_salt() {
        let (id, material) = WriterKey::mint().expect("mint");
        assert_ne!(id, 0);
        assert_ne!(material.key.as_bytes(), &[0u8; 32]);
        assert_ne!(material.salt.as_bytes(), &[0u8; 32]);
        assert_ne!(material.key.as_bytes(), material.salt.as_bytes());
    }

    #[test]
    fn audit_records_only_new_or_replaced_key_material() {
        let audit_file = NamedTempFile::new().expect("create audit fixture");
        let logger = LoggingPlugin::with_file(audit_file.path()).expect("open audit fixture");
        let store = DataKeyStore::with_audit_logger(Some(Arc::new(AuditChain::new(logger))));

        store.insert(guid(1), 7, wk(0x11)).expect("install");
        store.insert(guid(1), 7, wk(0x11)).expect("install");
        store.insert(guid(1), 7, wk(0x22)).expect("install");

        let records = fs::read_to_string(audit_file.path()).expect("read audit records");
        assert_eq!(
            records.matches("operation: \"install_data_key\"").count(),
            2,
            "the periodic duplicate announcement must not trigger another fsync"
        );
        assert_eq!(records.matches("outcome: Success").count(), 2);
    }

    /// A peer announcing new key material in a loop sets no pace for the
    /// disk: every key is installed, the records written are bounded per
    /// second (`audit::record_key_change`).
    #[test]
    fn a_flood_of_key_changes_writes_bounded_audit_records() {
        let audit_file = NamedTempFile::new().expect("create audit fixture");
        let logger = LoggingPlugin::with_file(audit_file.path()).expect("open audit fixture");
        let store = DataKeyStore::with_audit_logger(Some(Arc::new(AuditChain::new(logger))));

        let started = std::time::Instant::now();
        let flood = 2000u64;
        for i in 1..=flood {
            let mut key = [0x5Au8; 32];
            key[..8].copy_from_slice(&i.to_be_bytes());
            let material = WriterKey::new(
                SecretKey::from_bytes(key),
                SecretKey::from_bytes([0xA5; 32]),
            );
            store.insert(guid(1), i, material).expect("install");
        }
        let windows = started.elapsed().as_secs() + 1;
        assert!(
            store.get(&guid(1), flood).is_some(),
            "the last key is installed"
        );

        let records = fs::read_to_string(audit_file.path()).expect("read audit records");
        let written = records.matches("operation: \"install_data_key\"").count() as u64;
        assert!(
            written <= 64 * windows && written < flood,
            "{} install records for {} key changes over {} window(s)",
            written,
            flood,
            windows
        );
    }

    /// Also the rate-limit for the operator-facing WARN: both share the
    /// same `seen` guard, so a bound on the audit record is a bound on the
    /// WARN too.
    #[test]
    fn open_failure_audit_is_once_per_source() {
        let audit_file = NamedTempFile::new().expect("create audit fixture");
        let logger = LoggingPlugin::with_file(audit_file.path()).expect("open audit fixture");
        let store = DataKeyStore::with_audit_logger(Some(Arc::new(AuditChain::new(logger))));

        store.audit_open_failure_once([0x11; 12]);
        store.audit_open_failure_once([0x11; 12]);
        store.audit_open_failure_once([0x22; 12]);

        let records = fs::read_to_string(audit_file.path()).expect("read audit records");
        assert_eq!(
            records
                .matches("operation: \"open_data_key_announcement\"")
                .count(),
            2
        );
        assert_eq!(records.matches("outcome: Failed").count(), 2);
        assert_eq!(records.matches("key_id: 0").count(), 2);
    }

    /// AUD-1: a lost record closes the store to NEW material. The key whose
    /// record was lost stays installed (the transition had committed), an
    /// identical re-announcement is still a silent no-op, and anything new
    /// or changed is refused with a named error.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_degraded_audit_chain_refuses_new_keys() {
        let sink = std::fs::File::create("/dev/full").expect("/dev/full opens on linux");
        let chain = Arc::new(AuditChain::new(LoggingPlugin::over_file_for_tests(sink)));
        let store = DataKeyStore::with_audit_logger(Some(chain.clone()));

        store
            .insert(guid(1), 7, wk(0x11))
            .expect("the first install commits before its record is attempted");
        assert!(
            chain.is_degraded(),
            "the lost record must degrade the chain"
        );
        assert_eq!(store.len(), 1, "the committed key is not rolled back");

        store
            .insert(guid(1), 7, wk(0x11))
            .expect("re-announcing installed material is not a new key");

        let error = store
            .insert(guid(2), 9, wk(0x22))
            .expect_err("a new key must be refused while the chain is degraded");
        assert!(
            error.to_string().contains("audit chain degraded"),
            "{}",
            error
        );
        let error = store
            .insert(guid(1), 7, wk(0x33))
            .expect_err("changed material is a new key too");
        assert!(
            error.to_string().contains("audit chain degraded"),
            "{}",
            error
        );
        assert_eq!(store.len(), 1);
        assert!(store.get(&guid(2), 9).is_none());
    }

    #[test]
    fn entries_with_prefix_separates_local_from_remote() {
        let store = DataKeyStore::new();
        let local = GUID::new([0x01; 12], [0, 0, 0, 3]);
        let remote = GUID::new([0x02; 12], [0, 0, 0, 3]);
        store.insert(local, 1, wk(0xAA)).expect("install");
        store.insert(remote, 2, wk(0xBB)).expect("install");

        let locals = store.entries_with_prefix(&[0x01; 12]);
        assert_eq!(locals.len(), 1);
        assert_eq!(locals[0].0, local);
        assert_eq!(locals[0].1, 1);
    }

    #[test]
    fn remove_writer_drops_every_key_id_of_that_writer_only() {
        let store = DataKeyStore::new();
        store.insert(guid(1), 7, wk(0x11)).expect("install");
        store.insert(guid(1), 8, wk(0x12)).expect("install");
        store.insert(guid(2), 7, wk(0x22)).expect("install");

        store.remove_writer(&guid(1));

        assert!(store.get(&guid(1), 7).is_none());
        assert!(store.get(&guid(1), 8).is_none());
        assert!(store.get(&guid(2), 7).is_some());
    }

    #[test]
    fn debug_prints_a_count_and_no_key_bytes() {
        let store = DataKeyStore::new();
        store.insert(guid(1), 7, wk(0x5E)).expect("install");
        let rendered = format!("{:?}", store);
        assert_eq!(rendered, "DataKeyStore(1 keys)");
    }
}

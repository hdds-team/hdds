// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Endpoint protection resolved once per document generation.
//!
//! A topic's `data_protection_kind` (DDS-Security v1.1 Table 30) is read out
//! of the governance document by walking its rules against the topic name.
//! The write path needs it to decide whether to seal a sample, mint a
//! KeyHash or refuse a cleartext leg, and the read path to decide whether a
//! payload must be opened: both asked the walk once per sample, which is a
//! rule traversal on every byte that crosses the wire.
//!
//! What the walk reads changes only when a document is replaced. The
//! permissions overlay is the one document that can be reloaded while the
//! participant runs, and every reload moves
//! [`SecurityPluginSuite::local_restriction_generation`](crate::security::SecurityPluginSuite::local_restriction_generation);
//! governance itself is fixed for the participant's lifetime, so its
//! contribution is the constant generation `0` a participant without an
//! overlay always reads. Both caches here are filed under that value and drop
//! everything the moment it moves.
//!
//! The invariant every fill keeps is the one
//! `DiscoveryFsm::admission_epoch` states: **the generation is loaded BEFORE
//! any input of the resolution is read**. A reload landing in between files
//! an answer the new document never gave under a generation the new document
//! has already left, and the next lookup throws it away. Nothing here ever
//! serves a verdict under a generation that is not the one it was resolved
//! at.
//!
//! A resolution that FAILS is never filed: a document that could not be read
//! once is read again on the next sample, rather than its failure outliving
//! the reload that fixes it.

use crate::protocol::discovery::EndpointSecurityInfo;
use std::cell::Cell;

/// The protection of ONE endpoint's topic, resolved once per generation.
///
/// `Cell`: the writer that holds it is `!Sync` by contract, and a lock here
/// would cost every sample an acquisition it can never contend on.
#[derive(Debug, Default)]
pub(crate) struct EndpointProtection {
    /// The last successful fill: the generation it was resolved at, and what
    /// it resolved to.
    entry: Cell<Option<(u64, EndpointSecurityInfo)>>,
    /// Resolutions actually performed, so a test can tell a served answer
    /// from a recomputed one.
    #[cfg(test)]
    resolutions: Cell<u64>,
}

impl EndpointProtection {
    /// The protection `resolve` yields for `generation`, taken from the last
    /// fill when that fill was filed under the same generation.
    ///
    /// # Errors
    ///
    /// Whatever `resolve` returns; the failure is passed through and not
    /// remembered.
    pub(crate) fn get<E>(
        &self,
        generation: u64,
        resolve: impl FnOnce() -> Result<EndpointSecurityInfo, E>,
    ) -> Result<EndpointSecurityInfo, E> {
        if let Some((filed, attributes)) = self.entry.get() {
            if filed == generation {
                return Ok(attributes);
            }
        }
        let attributes = resolve()?;
        self.entry.set(Some((generation, attributes)));
        #[cfg(test)]
        self.resolutions
            .set(self.resolutions.get().saturating_add(1));
        Ok(attributes)
    }

    /// How many resolutions this cache has performed.
    #[cfg(test)]
    pub(crate) fn resolutions(&self) -> u64 {
        self.resolutions.get()
    }

    /// The generation the current entry was filed under, `None` before the
    /// first fill.
    #[cfg(test)]
    pub(crate) fn filed_generation(&self) -> Option<u64> {
        self.entry.get().map(|(generation, _)| generation)
    }
}

/// How many remote writers one reader remembers, as the admission cache is
/// bounded (`DiscoveryFsm::ADMISSION_CACHE_CAP`): at the cap the map starts
/// over, so a hostile domain costs recomputations, never memory. A reader's
/// matched writers are a small set; the cap only bounds an attack.
const WRITER_CAP: usize = 64;

/// What the data plane of ONE reader resolved from the documents: its topic's
/// own protection and each remote writer's announcement, all filed under the
/// same generation.
#[derive(Debug, Default)]
pub(crate) struct ReaderProtection {
    /// The generation every entry below was resolved at.
    generation: u64,
    /// The topic's protection: the outer `None` is "not resolved yet", the
    /// inner one is the answer "no access-control plugin to ask"
    /// (`resolved_payload_protection`), which `decrypt_if_secured` must tell
    /// apart from "resolved to unprotected".
    topic: Option<Option<bool>>,
    /// Per remote writer: its announcement, or `None` when discovery holds
    /// the writer and it announced no `PID_ENDPOINT_SECURITY_INFO`. A writer
    /// discovery does not hold is not filed at all, so a late announcement
    /// still resolves.
    writers: std::collections::HashMap<[u8; 16], Option<EndpointSecurityInfo>>,
    /// Resolutions actually performed, so a test can tell a served answer
    /// from a recomputed one.
    #[cfg(test)]
    resolutions: u64,
}

impl ReaderProtection {
    /// Point the cache at `generation`, dropping everything filed under
    /// another one.
    fn rekey(&mut self, generation: u64) {
        if self.generation != generation {
            self.generation = generation;
            self.topic = None;
            self.writers.clear();
        }
    }

    /// The topic's protection filed under `generation`, resolving it with
    /// `resolve` on a miss.
    pub(crate) fn topic(
        &mut self,
        generation: u64,
        resolve: impl FnOnce() -> Option<bool>,
    ) -> Option<bool> {
        self.rekey(generation);
        if let Some(resolved) = self.topic {
            return resolved;
        }
        let resolved = resolve();
        self.topic = Some(resolved);
        #[cfg(test)]
        {
            self.resolutions += 1;
        }
        resolved
    }

    /// What the cache holds for `writer` under `generation`: the outer
    /// `None` is a miss (nothing filed, or filed under another generation),
    /// the inner one a writer discovery holds without security info.
    pub(crate) fn writer(
        &mut self,
        generation: u64,
        writer: &[u8; 16],
    ) -> Option<Option<EndpointSecurityInfo>> {
        self.rekey(generation);
        self.writers.get(writer).copied()
    }

    /// File `attributes` for `writer` under `generation`.
    pub(crate) fn file_writer(
        &mut self,
        generation: u64,
        writer: [u8; 16],
        attributes: Option<EndpointSecurityInfo>,
    ) {
        self.rekey(generation);
        if self.writers.len() >= WRITER_CAP && !self.writers.contains_key(&writer) {
            self.writers.clear();
        }
        self.writers.insert(writer, attributes);
        #[cfg(test)]
        {
            self.resolutions += 1;
        }
    }

    /// How many resolutions this cache has performed.
    #[cfg(test)]
    pub(crate) fn resolutions(&self) -> u64 {
        self.resolutions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(payload_protected: bool) -> EndpointSecurityInfo {
        EndpointSecurityInfo {
            endpoint_security_attributes: if payload_protected {
                EndpointSecurityInfo::IS_VALID
                    | EndpointSecurityInfo::IS_PAYLOAD_PROTECTED
                    | EndpointSecurityInfo::IS_KEY_PROTECTED
            } else {
                EndpointSecurityInfo::IS_VALID
            },
            plugin_endpoint_security_attributes: 0,
        }
    }

    #[test]
    fn one_endpoint_resolves_once_per_generation() {
        let cache = EndpointProtection::default();
        assert_eq!(cache.get(0, || Ok::<_, ()>(info(true))), Ok(info(true)));
        assert_eq!(cache.get(0, || Ok::<_, ()>(info(false))), Ok(info(true)));
        assert_eq!(cache.resolutions(), 1);
    }

    #[test]
    fn a_generation_move_re_resolves() {
        let cache = EndpointProtection::default();
        assert_eq!(cache.get(0, || Ok::<_, ()>(info(true))), Ok(info(true)));
        assert_eq!(cache.get(1, || Ok::<_, ()>(info(false))), Ok(info(false)));
        assert_eq!(cache.resolutions(), 2);
        assert_eq!(cache.filed_generation(), Some(1));
    }

    #[test]
    fn a_failed_resolution_is_not_filed() {
        let cache = EndpointProtection::default();
        assert!(cache
            .get(0, || Err::<EndpointSecurityInfo, _>("unreadable"))
            .is_err());
        assert_eq!(cache.filed_generation(), None);
        assert_eq!(cache.get(0, || Ok::<_, &str>(info(true))), Ok(info(true)));
        assert_eq!(cache.resolutions(), 1);
    }

    #[test]
    fn a_reader_serves_its_topic_and_writers_until_the_generation_moves() {
        let mut cache = ReaderProtection::default();
        let writer = [0x11; 16];
        assert_eq!(cache.topic(0, || Some(true)), Some(true));
        assert_eq!(cache.topic(0, || Some(false)), Some(true));
        for attributes in [None, Some(info(false))] {
            cache.file_writer(0, writer, attributes);
            assert_eq!(cache.writer(0, &writer), Some(attributes));
        }
        assert_eq!(cache.resolutions(), 3);
        // Another writer is a miss, not "unprotected": a writer discovery
        // has not announced yet must still be looked up again.
        assert_eq!(cache.writer(0, &[0x22; 16]), None);
        // A reload drops both kinds of entry.
        assert_eq!(cache.topic(1, || Some(false)), Some(false));
        assert_eq!(cache.writer(1, &writer), None);
        assert_eq!(cache.resolutions(), 4);
    }

    #[test]
    fn a_reader_bounds_its_writer_map() {
        let mut cache = ReaderProtection::default();
        for i in 0..WRITER_CAP {
            let mut writer = [0u8; 16];
            writer[..8].copy_from_slice(&(i as u64).to_be_bytes());
            cache.file_writer(0, writer, Some(info(true)));
        }
        let mut fresh = [0u8; 16];
        fresh[..8].copy_from_slice(&(WRITER_CAP as u64).to_be_bytes());
        cache.file_writer(0, fresh, Some(info(true)));
        assert_eq!(cache.writers.len(), 1);
        assert_eq!(cache.writer(0, &fresh), Some(Some(info(true))));
    }
}

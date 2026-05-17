// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Middleware-level match notification (DDS spec 2.2.2.4).
//!
//! Bridges discovery events to writer/reader listeners, firing
//! `on_publication_matched` and `on_subscription_matched` callbacks
//! when compatible remote endpoints are discovered.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use crate::core::discovery::multicast::{
    DiscoveryFsm, DiscoveryListener, EndpointInfo, EndpointKind,
};
use crate::core::discovery::Matcher;
use crate::core::discovery::GUID;
use crate::dds::qos::QoS;

/// Type-erased match callback.
/// Args: (total_count, total_count_change, current_count, current_count_change, last_remote_guid)
type MatchCallback = Box<dyn Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync>;

/// Type-erased incompatible QoS callback.
/// Args: (total_count, total_count_change, last_policy_id)
type IncompatibleCallback = Box<dyn Fn(u32, i32, u32) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalKind {
    Writer,
    Reader,
}

struct MatchEntry {
    id: u64,
    topic: String,
    qos: QoS,
    kind: LocalKind,
    /// Type descriptor of the local endpoint, used at match time to evaluate
    /// DataRepresentation constraints per DDS-XTypes v1.3 §7.4.3.4.1 Table 15
    /// (types combining variable-size containers with 8-byte aligned
    /// primitives require native XCDR1 encoding).
    type_descriptor: &'static crate::core::types::TypeDescriptor,
    callback: MatchCallback,
    incompatible_callback: Option<IncompatibleCallback>,
    matched_remotes: Mutex<HashSet<GUID>>,
    /// `(remote endpoint GUID, policy_id)` tuples that have already
    /// triggered an incompatible-QoS notification on this entry. Used
    /// to dedup repeated incompat fires when the split incompat/match
    /// paths (see `on_endpoint_discovered_incompat_only` /
    /// `on_endpoint_discovered`) both see the same endpoint over the
    /// lifetime of the registration. Without this set, an incompat
    /// could fire once when the SEDP arrives (immediate notification,
    /// no participant-confirmation gate) AND a second time when the
    /// gate eventually releases and the same SEDP is replayed through
    /// the match path.
    ///
    /// Keying on `(GUID, policy_id)` rather than `GUID` alone means
    /// that if the remote endpoint later becomes incompatible for a
    /// DIFFERENT policy (post-discovery QoS evolution, or a different
    /// local entry observing a different first-incompatible policy on
    /// the same remote), the new policy id fires its own notification
    /// — matching DDS's `last_policy_id` status semantics. Without
    /// this, a remote that flipped from a Reliability mismatch to an
    /// Ownership mismatch would silently suppress the second event.
    incompat_remotes: Mutex<HashSet<(GUID, u32)>>,
    total_count: AtomicU32,
    incompatible_count: AtomicU32,
    /// For local Readers: when a remote Writer with a finite Lifespan
    /// matches, tighten this atomic to `min(current, writer_lifespan_nanos)`
    /// so the reader filters samples using the writer-announced lifespan
    /// even when the reader did not request a lifespan of its own.
    reader_lifespan_nanos: Option<Arc<AtomicU64>>,
}

/// Token returned when registering a match callback.
/// Unregisters from the registry on drop.
pub(crate) struct MatchToken {
    registry: Weak<MatchNotificationRegistry>,
    id: u64,
}

impl Drop for MatchToken {
    fn drop(&mut self) {
        if let Some(reg) = self.registry.upgrade() {
            reg.unregister(self.id);
        }
    }
}

impl std::fmt::Debug for MatchToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchToken").field("id", &self.id).finish()
    }
}

/// Registry for match notification callbacks.
///
/// Implements `DiscoveryListener` to receive remote endpoint discoveries
/// and fire `on_publication_matched` / `on_subscription_matched` callbacks
/// on local writers/readers with compatible QoS.
pub(crate) struct MatchNotificationRegistry {
    entries: RwLock<Vec<MatchEntry>>,
    discovery_fsm: Weak<DiscoveryFsm>,
    local_guid_prefix: [u8; 12],
    next_id: AtomicU64,
}

impl MatchNotificationRegistry {
    pub fn new(fsm: &Arc<DiscoveryFsm>, local_guid_prefix: [u8; 12]) -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            discovery_fsm: Arc::downgrade(fsm),
            local_guid_prefix,
            next_id: AtomicU64::new(1),
        }
    }

    /// Register a local writer for match notifications without an
    /// INCOMPATIBLE_QoS callback. Convenience wrapper over
    /// [`Self::register_writer_with_incompatible`] for callers that only
    /// want match-success events.
    #[allow(dead_code)]
    pub fn register_writer(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_descriptor: &'static crate::core::types::TypeDescriptor,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
    ) -> MatchToken {
        self.register_writer_with_incompatible(topic, qos, type_descriptor, callback, None)
    }

    /// Register a local writer with both match and incompatible QoS callbacks.
    pub fn register_writer_with_incompatible(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_descriptor: &'static crate::core::types::TypeDescriptor,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        incompatible_callback: Option<IncompatibleCallback>,
    ) -> MatchToken {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = MatchEntry {
            id,
            topic: topic.clone(),
            qos: qos.clone(),
            kind: LocalKind::Writer,
            type_descriptor,
            callback: Box::new(callback),
            incompatible_callback,
            matched_remotes: Mutex::new(HashSet::new()),
            incompat_remotes: Mutex::new(HashSet::new()),
            total_count: AtomicU32::new(0),
            incompatible_count: AtomicU32::new(0),
            reader_lifespan_nanos: None,
        };
        {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            entries.push(entry);
        }
        self.catch_up(id, LocalKind::Writer, &topic, &qos, type_descriptor);
        MatchToken {
            registry: Arc::downgrade(self),
            id,
        }
    }

    /// Register a local reader and additionally hand in an `AtomicU64` that
    /// will be tightened (min) whenever a compatible remote writer announces
    /// a finite Lifespan via SEDP. Used by the DataReader runtime so that
    /// writer-announced lifespans filter samples even when the reader did
    /// not request a lifespan of its own.
    pub fn register_reader_with_lifespan(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_descriptor: &'static crate::core::types::TypeDescriptor,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        incompatible_callback: Option<IncompatibleCallback>,
        reader_lifespan_nanos: Arc<AtomicU64>,
    ) -> MatchToken {
        self.register_reader_full(
            topic,
            qos,
            type_descriptor,
            callback,
            incompatible_callback,
            Some(reader_lifespan_nanos),
        )
    }

    fn register_reader_full(
        self: &Arc<Self>,
        topic: String,
        qos: QoS,
        type_descriptor: &'static crate::core::types::TypeDescriptor,
        callback: impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static,
        incompatible_callback: Option<IncompatibleCallback>,
        reader_lifespan_nanos: Option<Arc<AtomicU64>>,
    ) -> MatchToken {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = MatchEntry {
            id,
            topic: topic.clone(),
            qos: qos.clone(),
            kind: LocalKind::Reader,
            type_descriptor,
            callback: Box::new(callback),
            incompatible_callback,
            matched_remotes: Mutex::new(HashSet::new()),
            incompat_remotes: Mutex::new(HashSet::new()),
            total_count: AtomicU32::new(0),
            incompatible_count: AtomicU32::new(0),
            reader_lifespan_nanos,
        };
        {
            let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
            entries.push(entry);
        }
        self.catch_up(id, LocalKind::Reader, &topic, &qos, type_descriptor);
        MatchToken {
            registry: Arc::downgrade(self),
            id,
        }
    }

    fn unregister(&self, id: u64) {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        entries.retain(|e| e.id != id);
    }

    /// Catch-up: scan existing remote endpoints for matches with a newly registered entry.
    fn catch_up(
        &self,
        entry_id: u64,
        kind: LocalKind,
        topic: &str,
        local_qos: &QoS,
        type_descriptor: &'static crate::core::types::TypeDescriptor,
    ) {
        let fsm = match self.discovery_fsm.upgrade() {
            Some(fsm) => fsm,
            None => return,
        };

        let remote_endpoints = match kind {
            LocalKind::Writer => fsm.find_readers_for_topic(topic),
            LocalKind::Reader => fsm.find_writers_for_topic(topic),
        };

        for remote in &remote_endpoints {
            if remote.endpoint_guid.prefix == self.local_guid_prefix {
                continue;
            }
            // Fill in the remote's empty `data_representation` with the
            // spec default `[XCDR1]` per DDS-XTypes v1.3 §7.6.3.1.2.
            // Same correction as in `evaluate_entries` for the live
            // discovery path — see the long comment there for why we
            // must NOT let `pair_effective_cdr_version` expand the
            // remote's empty list using HDDS's local-default
            // `[XCDR2, XCDR1]`.
            let remote_data_rep: std::borrow::Cow<'_, [u16]> =
                if remote.qos.data_representation.is_empty() {
                    std::borrow::Cow::Owned(vec![0x0000])
                } else {
                    std::borrow::Cow::Borrowed(remote.qos.data_representation.as_slice())
                };
            let compatible_policies = match kind {
                LocalKind::Writer => Matcher::is_compatible(&remote.qos, local_qos),
                LocalKind::Reader => Matcher::is_compatible(local_qos, &remote.qos),
            };
            // DataRepresentation matching per DDS-XTypes v1.3 §7.6.3.1:
            // writer.offered must accept at least one of reader.accepted.
            // Types requiring native XCDR1 (XTypes v1.3 §7.4.3.4.1 Table 15:
            // variable-size containers with 8-byte aligned primitives) are
            // rejected on XCDR1 negotiation until native support lands.
            let cdr_result = match kind {
                LocalKind::Writer => crate::dds::cdr_negotiation::pair_effective_cdr_version(
                    &local_qos.data_representation,
                    remote_data_rep.as_ref(),
                ),
                LocalKind::Reader => crate::dds::cdr_negotiation::pair_effective_cdr_version(
                    remote_data_rep.as_ref(),
                    &local_qos.data_representation,
                ),
            };
            let data_rep_ok = match cdr_result {
                Ok(crate::dds::CdrVersion::Xcdr1)
                    if crate::dds::cdr_negotiation::type_requires_native_xcdr1(type_descriptor) =>
                {
                    false
                }
                Ok(_) => true,
                Err(_) => false,
            };
            let compatible = compatible_policies && data_rep_ok;
            if compatible {
                let writer_lifespan_nanos = if kind == LocalKind::Reader
                    && !remote.qos.lifespan.is_infinite()
                {
                    Some(u64::try_from(remote.qos.lifespan.duration.as_nanos()).unwrap_or(u64::MAX))
                } else {
                    None
                };
                self.notify_entry(entry_id, remote.endpoint_guid, writer_lifespan_nanos);
            } else {
                // Incompatible QoS discovered during catch-up (the remote
                // endpoint was cached BEFORE the local entry registered).
                // Fire on_requested_incompatible_qos / on_offered_incompatible_qos
                // so listeners see the mismatch even in this ordering.
                let policy_id = if !data_rep_ok {
                    crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
                } else {
                    match kind {
                        LocalKind::Writer => {
                            Matcher::first_incompatible_policy(&remote.qos, local_qos)
                        }
                        LocalKind::Reader => {
                            Matcher::first_incompatible_policy(local_qos, &remote.qos)
                        }
                    }
                };
                if policy_id != 0 {
                    log::warn!(
                        "[MATCH] incompatible QoS on topic='{}' policy_id={}",
                        topic,
                        policy_id
                    );
                    self.fire_incompat(entry_id, remote.endpoint_guid, policy_id);
                }
            }
        }
    }

    fn fire_incompat(&self, entry_id: u64, endpoint_guid: GUID, policy_id: u32) {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        for entry in entries.iter() {
            if entry.id == entry_id {
                // Dedup against the same `incompat_remotes` set the
                // split-path `dispatch_incompat` uses. catch_up runs at
                // entry-registration time and may see the same remote that
                // a later `handle_sedp` -> `dispatch_incompat` re-evaluates
                // — without this dedup we'd fire the callback twice.
                let mut already = entry
                    .incompat_remotes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !already.insert((endpoint_guid, policy_id)) {
                    return;
                }
                drop(already);
                if let Some(ref cb) = entry.incompatible_callback {
                    let total = entry.incompatible_count.fetch_add(1, Ordering::Relaxed) + 1;
                    cb(total, 1, policy_id);
                }
                return;
            }
        }
    }

    fn notify_entry(&self, entry_id: u64, remote_guid: GUID, writer_lifespan_nanos: Option<u64>) {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        for entry in entries.iter() {
            if entry.id == entry_id {
                let mut matched = entry
                    .matched_remotes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if matched.insert(remote_guid) {
                    let total = entry.total_count.fetch_add(1, Ordering::Relaxed) + 1;
                    let current = matched.len() as u32;
                    drop(matched);
                    if let (Some(writer_nanos), Some(nanos_cell)) =
                        (writer_lifespan_nanos, entry.reader_lifespan_nanos.as_ref())
                    {
                        let mut cur = nanos_cell.load(Ordering::Relaxed);
                        while writer_nanos < cur {
                            match nanos_cell.compare_exchange_weak(
                                cur,
                                writer_nanos,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            ) {
                                Ok(_) => break,
                                Err(observed) => cur = observed,
                            }
                        }
                    }
                    (entry.callback)(total, 1, current, 1, Some(remote_guid));
                }
                return;
            }
        }
    }
}

/// Per-entry verdict produced by `MatchNotificationRegistry::evaluate`.
/// `policy_id == 0` for `Incompat` would mean "partition or unknown
/// reason" which is silently no-matched per DDS spec; only the `Match`
/// and `Incompat(policy)` variants reach the dispatch layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryVerdict {
    /// Endpoint is a cross-kind match candidate AND QoS is fully
    /// compatible. The match dispatch may update `matched_remotes` and
    /// fire `on_publication_matched` / `on_subscription_matched`.
    Match,
    /// Endpoint is a cross-kind candidate but QoS is incompatible on the
    /// carried policy. The incompat dispatch may fire
    /// `on_offered_incompatible_qos` / `on_requested_incompatible_qos`.
    Incompat(u32),
    /// Endpoint is not a candidate (same-kind, wrong topic, partition
    /// mismatch, etc.). No dispatch.
    Skip,
}

impl MatchNotificationRegistry {
    /// Common helper for the two `DiscoveryListener` hooks
    /// (`on_endpoint_discovered` for the match path,
    /// `on_endpoint_discovered_incompat_only` for the always-on
    /// QoS-incompat path). Returns one verdict per local entry on the
    /// same topic. The split exists so the SEDP confirmation gate in
    /// `discovery::handle_sedp` can publish QoS mismatches immediately
    /// (no gate) while still gating the match-status side against
    /// stale-test SPDP/SEDP contamination.
    fn evaluate_entries(&self, endpoint: &EndpointInfo) -> Vec<(u64, EntryVerdict)> {
        // Build effective QoS for the remote endpoint:
        //
        // 1. When PID_OWNERSHIP is absent, copy local ownership to skip
        //    ownership in the policy-compatibility check (vendors omit
        //    default PIDs). The explicit ownership check is done
        //    separately per-entry below.
        //
        // 2. When PID_DATA_REPRESENTATION is absent, fill in `[XCDR1]`
        //    per DDS-XTypes v1.3 §7.6.3.1.2 ("if the
        //    DataRepresentationQosPolicy.value is empty, the value
        //    defaults to XCDR_DATA_REPRESENTATION"). Without this,
        //    `pair_effective_cdr_version` would expand the remote's
        //    empty list to HDDS's local default `[XCDR2, XCDR1]` (the
        //    HDDS dialect's own offered list when its QoS is empty),
        //    silently turning a real cross-vendor XCDR1↔XCDR2 mismatch
        //    into a "match on XCDR2". That bug let Connext's `-x 1`
        //    publisher (which often emits no PID_DATA_REPRESENTATION,
        //    leaning on the vendor default) appear compatible with an
        //    HDDS `-x 2` subscriber — no `on_requested_incompatible_qos`
        //    fired and the harness recorded `DATA_NOT_RECEIVED` instead
        //    of `INCOMPATIBLE_QOS`. The local default stays as
        //    `[XCDR2, XCDR1]` (applied inside
        //    `pair_effective_cdr_version` when the LOCAL entry's
        //    `data_representation` is empty) so HDDS's own matching
        //    continues to mirror what its SEDP advertises on the wire.
        let remote_qos_for_compat = {
            let mut q = endpoint.qos.clone();
            if !endpoint.has_explicit_ownership {
                q.ownership = crate::dds::qos::Ownership::shared();
            }
            if q.data_representation.is_empty() {
                q.data_representation = vec![0x0000]; // XCDR_DATA_REPRESENTATION (XCDR1) per spec
            }
            q
        };

        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let mut verdicts = Vec::with_capacity(entries.len());
        for entry in entries.iter() {
            if entry.topic != endpoint.topic_name {
                verdicts.push((entry.id, EntryVerdict::Skip));
                continue;
            }
            // DDS matching is strictly cross-kind: writers match readers
            // and vice versa. Same-kind pairs are silently irrelevant.
            let is_match_candidate = matches!(
                (entry.kind, endpoint.kind),
                (LocalKind::Writer, EndpointKind::Reader)
                    | (LocalKind::Reader, EndpointKind::Writer)
            );
            if !is_match_candidate {
                verdicts.push((entry.id, EntryVerdict::Skip));
                continue;
            }

            // `Matcher::is_compatible` takes the (reader_qos, writer_qos)
            // order regardless of which side is local. DataRepresentation
            // matching per DDS-XTypes v1.3 §7.6.3.1: writer.offered must
            // accept at least one of reader.accepted. Types requiring
            // native XCDR1 (XTypes v1.3 §7.4.3.4.1 Table 15: variable-size
            // containers with 8-byte aligned primitives) are rejected on
            // XCDR1 negotiation until native support lands.
            let (compatible_policies, cdr_result) = match entry.kind {
                LocalKind::Writer => (
                    Matcher::is_compatible(&remote_qos_for_compat, &entry.qos),
                    crate::dds::cdr_negotiation::pair_effective_cdr_version(
                        &entry.qos.data_representation,
                        &remote_qos_for_compat.data_representation,
                    ),
                ),
                LocalKind::Reader => (
                    Matcher::is_compatible(&entry.qos, &remote_qos_for_compat),
                    crate::dds::cdr_negotiation::pair_effective_cdr_version(
                        &remote_qos_for_compat.data_representation,
                        &entry.qos.data_representation,
                    ),
                ),
            };
            let data_rep_ok = match cdr_result {
                Ok(crate::dds::CdrVersion::Xcdr1)
                    if crate::dds::cdr_negotiation::type_requires_native_xcdr1(
                        entry.type_descriptor,
                    ) =>
                {
                    false
                }
                Ok(_) => true,
                Err(_) => false,
            };

            // Ownership check: infer ownership kind from SEDP PIDs.
            // PID_OWNERSHIP present → use it directly.
            // PID_OWNERSHIP absent + PID_OWNERSHIP_STRENGTH present → EXCLUSIVE.
            // Both absent → SHARED (DDS default).
            let ownership_ok = if endpoint.has_explicit_ownership {
                endpoint.qos.ownership.kind == entry.qos.ownership.kind
            } else if endpoint.has_ownership_strength {
                crate::qos::ownership::OwnershipKind::Exclusive == entry.qos.ownership.kind
            } else {
                crate::qos::ownership::OwnershipKind::Shared == entry.qos.ownership.kind
            };

            if compatible_policies && data_rep_ok && ownership_ok {
                verdicts.push((entry.id, EntryVerdict::Match));
                continue;
            }

            // Compute the most specific policy id for the incompat fire.
            // Order: ownership > data_representation > generic first
            // incompatible policy. `policy_id == 0` means "no real QoS
            // incompatibility" (e.g. partition mismatch, silently
            // no-matched per DDS spec) and is collapsed to Skip.
            let policy_id = if !ownership_ok {
                5 // OWNERSHIP
            } else if !data_rep_ok {
                crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
            } else {
                // first_incompatible_policy expects (reader_qos, writer_qos)
                match entry.kind {
                    LocalKind::Reader => {
                        Matcher::first_incompatible_policy(&entry.qos, &remote_qos_for_compat)
                    }
                    LocalKind::Writer => {
                        Matcher::first_incompatible_policy(&remote_qos_for_compat, &entry.qos)
                    }
                }
            };
            if policy_id == 0 {
                verdicts.push((entry.id, EntryVerdict::Skip));
            } else {
                verdicts.push((entry.id, EntryVerdict::Incompat(policy_id)));
            }
        }
        verdicts
    }

    /// Dispatch the match outcome for an entry. Updates
    /// `matched_remotes` (dedup against repeat fires) and tightens
    /// the reader's effective lifespan from the writer's announced
    /// value. Idempotent against the same `(entry_id, endpoint_guid)`
    /// pair so the deferred replay path doesn't double-fire.
    fn dispatch_match(&self, endpoint: &EndpointInfo, entry: &MatchEntry) {
        let mut matched = entry
            .matched_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !matched.insert(endpoint.endpoint_guid) {
            return;
        }
        let total = entry.total_count.fetch_add(1, Ordering::Relaxed) + 1;
        let current = matched.len() as u32;
        drop(matched);
        // Lifespan propagation: a local Reader matched with a remote
        // Writer announcing a finite Lifespan — tighten this reader's
        // effective lifespan so samples are filtered even when the
        // reader did not set one itself.
        if entry.kind == LocalKind::Reader {
            if let Some(ref nanos_cell) = entry.reader_lifespan_nanos {
                if !endpoint.qos.lifespan.is_infinite() {
                    let writer_nanos = u64::try_from(endpoint.qos.lifespan.duration.as_nanos())
                        .unwrap_or(u64::MAX);
                    let mut cur = nanos_cell.load(Ordering::Relaxed);
                    while writer_nanos < cur {
                        match nanos_cell.compare_exchange_weak(
                            cur,
                            writer_nanos,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break,
                            Err(observed) => cur = observed,
                        }
                    }
                }
            }
        }
        (entry.callback)(total, 1, current, 1, Some(endpoint.endpoint_guid));
    }

    /// Dispatch the incompat outcome for an entry. Dedups against
    /// `incompat_remotes` so the same `(entry_id, endpoint_guid)` pair
    /// fires the callback at most once over the entry's lifetime —
    /// important because the split incompat / match paths both see
    /// every new SEDP and would otherwise double-count.
    fn dispatch_incompat(&self, endpoint: &EndpointInfo, entry: &MatchEntry, policy_id: u32) {
        let Some(ref incompat_cb) = entry.incompatible_callback else {
            return;
        };
        let mut already = entry
            .incompat_remotes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !already.insert((endpoint.endpoint_guid, policy_id)) {
            return;
        }
        drop(already);
        log::warn!(
            "[MATCH] incompatible QoS on topic='{}' policy_id={}",
            entry.topic,
            policy_id
        );
        if std::env::var("HDDS_INTEROP_DIAGNOSTICS").is_ok() {
            eprintln!(
                "[MATCH-INCOMPAT] topic='{}' policy={} has_expl_own={} has_own_str={} remote_own={:?} local_own={:?}",
                entry.topic,
                policy_id,
                endpoint.has_explicit_ownership,
                endpoint.has_ownership_strength,
                endpoint.qos.ownership.kind,
                entry.qos.ownership.kind,
            );
        }
        let total = entry.incompatible_count.fetch_add(1, Ordering::Relaxed) + 1;
        incompat_cb(total, 1, policy_id);
    }
}

impl DiscoveryListener for MatchNotificationRegistry {
    /// Match path. Called by `discovery::handle_sedp` only AFTER the
    /// SEDP confirmation gate has released (participant is confirmed,
    /// or FSM uptime is past the probation window, or this is a local
    /// endpoint). Fires `on_publication_matched` /
    /// `on_subscription_matched` for compatible pairs. Incompat
    /// notifications are NOT fired here; they go through the
    /// always-on `on_endpoint_discovered_incompat_only` hook below.
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
        if endpoint.endpoint_guid.prefix == self.local_guid_prefix {
            return;
        }
        let verdicts = self.evaluate_entries(&endpoint);
        if verdicts.is_empty() {
            return;
        }
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        for (entry_id, verdict) in verdicts {
            if !matches!(verdict, EntryVerdict::Match) {
                continue;
            }
            if let Some(entry) = entries.iter().find(|e| e.id == entry_id) {
                self.dispatch_match(&endpoint, entry);
            }
        }
    }

    /// Incompat path. Called by `discovery::handle_sedp` IMMEDIATELY,
    /// before the confirmation gate, so QoS mismatches surface to the
    /// application without waiting for SPDP participant confirmation
    /// (which can take up to a steady-state SPDP interval, ~3 s — long
    /// enough to miss the OMG harness 5 s check window). The
    /// `incompat_remotes` dedup makes this idempotent against the
    /// match path: when the gate eventually releases and the same
    /// endpoint is replayed, we don't double-fire.
    fn on_endpoint_discovered_incompat_only(&self, endpoint: EndpointInfo) {
        if endpoint.endpoint_guid.prefix == self.local_guid_prefix {
            return;
        }
        let verdicts = self.evaluate_entries(&endpoint);
        if verdicts.is_empty() {
            return;
        }
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        for (entry_id, verdict) in verdicts {
            let EntryVerdict::Incompat(policy_id) = verdict else {
                continue;
            };
            if let Some(entry) = entries.iter().find(|e| e.id == entry_id) {
                self.dispatch_incompat(&endpoint, entry, policy_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    fn test_qos() -> QoS {
        QoS::best_effort()
    }

    // Simple fixed-size type descriptor (alignment=4, is_variable_size=false):
    // triggers the XCDR1 guard-rail only when alignment>=8 && is_variable_size.
    static SIMPLE_DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
        type_id: 0,
        type_name: "Simple",
        size_bytes: 8,
        alignment: 4,
        is_variable_size: false,
        fields: &[],
    };

    // Container type descriptor (alignment=8 + is_variable_size=true):
    // requires native XCDR1 per §7.4.3.4.1 Table 15. Triggers the guard-rail.
    static CONTAINER_DESC: crate::core::types::TypeDescriptor =
        crate::core::types::TypeDescriptor {
            type_id: 0,
            type_name: "Container",
            size_bytes: 0,
            alignment: 8,
            is_variable_size: true,
            fields: &[],
        };

    // Remote reader with an explicit data_representation sequence. Used to
    // exercise the DDS-XTypes v1.3 §7.6.3.1 match-time gate.
    fn remote_reader(data_rep: Vec<u16>) -> EndpointInfo {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        // GUID with a non-zero prefix so it is not skipped as local.
        let guid = GUID::from_bytes([
            0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x04,
        ]);
        let qos = QoS {
            data_representation: data_rep,
            ..QoS::best_effort()
        };
        EndpointInfo {
            endpoint_guid: guid,
            participant_guid: guid,
            topic_name: "topic".into(),
            type_name: "T".into(),
            qos,
            kind: EndpointKind::Reader,
            type_object: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
        }
    }

    #[test]
    fn data_rep_mismatch_fires_incompat_with_policy_23_and_skips_match() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_policy = Arc::new(AtomicU32::new(0));
        let ip = Arc::clone(&incompat_policy);

        let writer_qos = QoS {
            data_representation: vec![0x0002], // offered XCDR2 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, policy_id| {
                ip.store(policy_id, Ordering::Relaxed);
            })),
        );

        // Reader accepts only XCDR1 -> mismatch.
        // After the split:
        //   - The match path (`on_endpoint_discovered`) MUST NOT fire
        //     either match or incompat for this endpoint;
        //   - The incompat path (`on_endpoint_discovered_incompat_only`)
        //     MUST fire incompat with policy 23.
        let remote = remote_reader(vec![0x0000]);
        reg.on_endpoint_discovered(remote.clone());
        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "match path must not fire match on incompatible pair"
        );
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            0,
            "match path must not fire incompat (that's the other hook's job)"
        );

        reg.on_endpoint_discovered_incompat_only(remote);
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
        );
    }

    #[test]
    fn data_rep_match_proceeds_and_does_not_fire_incompat() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let writer_qos = QoS {
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        // Reader accepts XCDR2 -> intersection non-empty -> match fires.
        reg.on_endpoint_discovered(remote_reader(vec![0x0002]));

        assert_eq!(match_count.load(Ordering::Relaxed), 1);
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn xcdr1_rejected_for_container_type_fires_policy_23() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_policy = Arc::new(AtomicU32::new(0));
        let ip = Arc::clone(&incompat_policy);

        let writer_qos = QoS {
            data_representation: vec![0x0000], // XCDR1 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &CONTAINER_DESC, // alignment=8 + is_variable_size
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, policy_id| {
                ip.store(policy_id, Ordering::Relaxed);
            })),
        );

        // Reader also accepts only XCDR1 -> intersection non-empty,
        // but the container type requires native XCDR1 which is not
        // implemented: the guard-rail fires policy 23 via the incompat
        // path. The match path stays silent on both sides.
        let remote = remote_reader(vec![0x0000]);
        reg.on_endpoint_discovered(remote.clone());
        assert_eq!(match_count.load(Ordering::Relaxed), 0);
        assert_eq!(incompat_policy.load(Ordering::Relaxed), 0);

        reg.on_endpoint_discovered_incompat_only(remote);
        assert_eq!(
            incompat_policy.load(Ordering::Relaxed),
            crate::dds::cdr_negotiation::POLICY_ID_DATA_REPRESENTATION
        );
    }

    #[test]
    fn xcdr2_proceeds_for_container_type() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let writer_qos = QoS {
            data_representation: vec![0x0002], // XCDR2 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &CONTAINER_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        // Reader accepts XCDR2 -> negotiation resolves to XCDR2, which the
        // codegen path supports natively on container types; guard-rail
        // does not fire.
        reg.on_endpoint_discovered(remote_reader(vec![0x0002]));

        assert_eq!(match_count.load(Ordering::Relaxed), 1);
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn xcdr1_accepted_for_simple_type() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let writer_qos = QoS {
            data_representation: vec![0x0000], // XCDR1 only
            ..QoS::best_effort()
        };
        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            writer_qos,
            &SIMPLE_DESC, // alignment=4, is_variable_size=false
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        // Simple type: XCDR1 natively supported (primitive types have
        // identical XCDR1/XCDR2 layout at 4-byte alignment or finer).
        reg.on_endpoint_discovered(remote_reader(vec![0x0000]));

        assert_eq!(match_count.load(Ordering::Relaxed), 1);
        assert_eq!(incompat_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn register_and_unregister() {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let call_count = Arc::new(AtomicU32::new(0));
        let cc = Arc::clone(&call_count);
        let token = reg.register_writer(
            "test".into(),
            test_qos(),
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                cc.fetch_add(1, Ordering::Relaxed);
            },
        );

        // Should have 1 entry
        assert_eq!(
            reg.entries.read().unwrap_or_else(|e| e.into_inner()).len(),
            1
        );

        // Drop token -> unregisters
        drop(token);
        assert_eq!(
            reg.entries.read().unwrap_or_else(|e| e.into_inner()).len(),
            0
        );
    }

    /// Build a remote endpoint of a chosen kind with a default-best-effort QoS.
    /// Used to exercise the same-kind / opposite-kind routing in
    /// `on_endpoint_discovered`.
    fn remote_endpoint(kind: crate::core::discovery::multicast::fsm::EndpointKind) -> EndpointInfo {
        let guid = GUID::from_bytes([
            0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 1, 2, 3, 4, 5, 6, 0, 0, 0, 0x04,
        ]);
        let qos = QoS {
            // Offer XCDR2 so a same-kind pair won't even trip a
            // DataRepresentation difference; the test must rely solely on
            // the same-kind guard, not on any compatibility coincidence.
            data_representation: vec![0x0002],
            ..QoS::best_effort()
        };
        EndpointInfo {
            endpoint_guid: guid,
            participant_guid: guid,
            topic_name: "topic".into(),
            type_name: "T".into(),
            qos,
            kind,
            type_object: None,
            has_explicit_ownership: false,
            has_ownership_strength: false,
        }
    }

    /// Regression: a local Writer that discovers a remote Writer on the same
    /// topic must NOT fire `on_offered_incompatible_qos`. DDS matching is
    /// strictly cross-kind (DDS v1.4 §2.2.3.8 OFFERED_INCOMPATIBLE_QOS is
    /// defined only for Writer↔Reader). Before the same-kind guard, the
    /// `_ => false` arm in the compatibility match labelled Writer-Writer
    /// pairs as INCOMPATIBLE and forced `data_rep_ok` false (because
    /// `cdr_result` defaulted to `None`), firing a false-positive
    /// `INCOMPATIBLE_QOS` event with policy_id = 23 (DataRepresentation).
    /// On the OMG interop suite that single bug accounted for the
    /// dominant share of cross-vendor regressions whenever two publishers
    /// (or two subscribers) co-existed on the same topic.
    #[test]
    fn same_kind_writer_pair_does_not_fire_incompat() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        let _token = reg.register_writer_with_incompatible(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
        );

        reg.on_endpoint_discovered(remote_endpoint(EndpointKind::Writer));

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "Writer-Writer pair must not produce a publication-matched event"
        );
        assert_eq!(
            incompat_count.load(Ordering::Relaxed),
            0,
            "Writer-Writer pair must not fire on_offered_incompatible_qos"
        );
    }

    /// Symmetric regression: a local Reader that discovers a remote Reader
    /// on the same topic must NOT fire `on_requested_incompatible_qos`.
    #[test]
    fn same_kind_reader_pair_does_not_fire_incompat() {
        use crate::core::discovery::multicast::fsm::EndpointKind;
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let reg = Arc::new(MatchNotificationRegistry::new(&fsm, [0; 12]));

        let match_count = Arc::new(AtomicU32::new(0));
        let mc = Arc::clone(&match_count);
        let incompat_count = Arc::new(AtomicU32::new(0));
        let ic = Arc::clone(&incompat_count);

        // `register_reader_with_lifespan` is the only public reader hook;
        // an effectively-infinite lifespan cell makes it equivalent to a
        // plain reader registration for the purpose of this test.
        let lifespan = Arc::new(AtomicU64::new(u64::MAX));
        let _token = reg.register_reader_with_lifespan(
            "topic".into(),
            test_qos(),
            &SIMPLE_DESC,
            move |_, _, _, _, _| {
                mc.fetch_add(1, Ordering::Relaxed);
            },
            Some(Box::new(move |_, _, _| {
                ic.fetch_add(1, Ordering::Relaxed);
            })),
            lifespan,
        );

        reg.on_endpoint_discovered(remote_endpoint(EndpointKind::Reader));

        assert_eq!(
            match_count.load(Ordering::Relaxed),
            0,
            "Reader-Reader pair must not produce a subscription-matched event"
        );
        assert_eq!(
            incompat_count.load(Ordering::Relaxed),
            0,
            "Reader-Reader pair must not fire on_requested_incompatible_qos"
        );
    }
}

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
                    &remote.qos.data_representation,
                ),
                LocalKind::Reader => crate::dds::cdr_negotiation::pair_effective_cdr_version(
                    &remote.qos.data_representation,
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
                    self.fire_incompat(entry_id, policy_id);
                }
            }
        }
    }

    fn fire_incompat(&self, entry_id: u64, policy_id: u32) {
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        for entry in entries.iter() {
            if entry.id == entry_id {
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

impl DiscoveryListener for MatchNotificationRegistry {
    fn on_endpoint_discovered(&self, endpoint: EndpointInfo) {
        // Skip local endpoints — intra-process matching is handled by DomainState
        if endpoint.endpoint_guid.prefix == self.local_guid_prefix {
            return;
        }

        // Build effective QoS: when PID_OWNERSHIP absent, copy local ownership
        // to skip ownership in compatibility check (vendors omit default PIDs).
        // The explicit ownership check is done separately below.
        let remote_qos_for_compat = {
            let mut q = endpoint.qos.clone();
            if !endpoint.has_explicit_ownership {
                // Placeholder: will be set per-entry
                q.ownership = crate::dds::qos::Ownership::shared();
            }
            q
        };

        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        for entry in entries.iter() {
            if entry.topic != endpoint.topic_name {
                continue;
            }
            // DDS matching is strictly cross-kind: writers match readers and
            // vice versa. Same-kind pairs (Writer/Writer, Reader/Reader) are
            // semantically irrelevant and MUST be ignored silently. Falling
            // through to the compatibility check below with `_ => false`
            // labelled the pair "incompatible" rather than "irrelevant",
            // which then fired `on_offered_incompatible_qos` /
            // `on_requested_incompatible_qos` against the local entry — a
            // false positive every time a second publisher (or subscriber)
            // joined the topic. That single false fire is the dominant
            // source of OMG interop regression on multi-pub / multi-sub
            // test cases (Ownership_3-6, OrderedAccess_3-8, Cft_0,
            // Partition_2, etc.).
            let is_match_candidate = matches!(
                (entry.kind, endpoint.kind),
                (LocalKind::Writer, EndpointKind::Reader)
                    | (LocalKind::Reader, EndpointKind::Writer)
            );
            if !is_match_candidate {
                continue;
            }

            // Same-kind pairs are filtered above; `entry.kind` alone is
            // enough to route. `Matcher::is_compatible` takes the
            // (reader_qos, writer_qos) order regardless of which side is
            // local. DataRepresentation matching per DDS-XTypes v1.3
            // §7.6.3.1: writer.offered must accept at least one of
            // reader.accepted. Types requiring native XCDR1 (XTypes v1.3
            // §7.4.3.4.1 Table 15: variable-size containers with 8-byte
            // aligned primitives) are rejected on XCDR1 negotiation until
            // native support lands.
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
            let compatible = compatible_policies && data_rep_ok;

            // Ownership check: infer ownership kind from SEDP PIDs.
            // PID_OWNERSHIP present → use it directly.
            // PID_OWNERSHIP absent + PID_OWNERSHIP_STRENGTH present → EXCLUSIVE.
            // Both absent → UNKNOWN, skip check (assume compatible to avoid false positives).
            let ownership_ok = if endpoint.has_explicit_ownership {
                endpoint.qos.ownership.kind == entry.qos.ownership.kind
            } else if endpoint.has_ownership_strength {
                crate::qos::ownership::OwnershipKind::Exclusive == entry.qos.ownership.kind
            } else {
                // No PID_OWNERSHIP, no PID_OWNERSHIP_STRENGTH → writer is SHARED (DDS default).
                // SHARED is only compatible with SHARED readers/writers.
                crate::qos::ownership::OwnershipKind::Shared == entry.qos.ownership.kind
            };

            if compatible && ownership_ok {
                let mut matched = entry
                    .matched_remotes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if matched.insert(endpoint.endpoint_guid) {
                    let total = entry.total_count.fetch_add(1, Ordering::Relaxed) + 1;
                    let current = matched.len() as u32;
                    drop(matched);
                    // Lifespan propagation: a local Reader matched with a
                    // remote Writer announcing a finite Lifespan — tighten
                    // the reader's effective lifespan so samples are
                    // filtered even when the reader did not set one itself.
                    if entry.kind == LocalKind::Reader {
                        if let Some(ref nanos_cell) = entry.reader_lifespan_nanos {
                            if !endpoint.qos.lifespan.is_infinite() {
                                let writer_nanos =
                                    u64::try_from(endpoint.qos.lifespan.duration.as_nanos())
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
            } else if let Some(ref incompat_cb) = entry.incompatible_callback {
                // Fire on_requested_incompatible_qos / on_offered_incompatible_qos.
                // But NOT for partition mismatches — those are silent no-match (DDS spec).
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
                // policy_id 0 = no real QoS incompatibility found (partition mismatch
                // or unknown). Partition mismatch is not an INCOMPATIBLE_QOS event.
                if policy_id != 0 {
                    log::warn!(
                        "[MATCH] incompatible QoS on topic='{}' policy_id={}",
                        entry.topic,
                        policy_id
                    );
                    if std::env::var("HDDS_INTEROP_DIAGNOSTICS").is_ok() {
                        eprintln!(
                            "[MATCH-INCOMPAT] topic='{}' policy={} own_ok={} has_expl={} has_str={} remote_own={:?} local_own={:?} compat={}",
                            entry.topic, policy_id, ownership_ok,
                            endpoint.has_explicit_ownership, endpoint.has_ownership_strength,
                            endpoint.qos.ownership.kind, entry.qos.ownership.kind, compatible
                        );
                    }
                    let total = entry.incompatible_count.fetch_add(1, Ordering::Relaxed) + 1;
                    incompat_cb(total, 1, policy_id);
                }
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

        // Reader accepts only XCDR1 -> mismatch -> incompat event, no match.
        reg.on_endpoint_discovered(remote_reader(vec![0x0000]));

        assert_eq!(match_count.load(Ordering::Relaxed), 0);
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
        // implemented: the guard-rail fires policy 23.
        reg.on_endpoint_discovered(remote_reader(vec![0x0000]));

        assert_eq!(match_count.load(Ordering::Relaxed), 0);
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

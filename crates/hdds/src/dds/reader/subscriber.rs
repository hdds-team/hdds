// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Internal subscriber implementation for DataReader.
//!
//!
//! Bridges the engine's subscriber trait to the typed DataReader,
//! handling sample deserialization and duplicate detection.

use super::reorder::{PendingPayload, ReorderGate};
use crate::core::rt;
use crate::dds::filter::FilterEvaluator;
use crate::dds::listener::DataReaderListener;
use crate::dds::{GuardCondition, StatusCondition, StatusMask, DDS};
use crate::telemetry;
use crate::telemetry::metrics::current_time_ns;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

use crate::engine::subscriber::DisposeKind;

/// A single sample buffered for the coherent-set runtime (RTPS v2.5
/// §8.7.5). Held in the per-writer staging FIFO until the matching
/// ECS DATA submessage arrives, then drained in writer-sequence order
/// and pushed through the normal admit pipeline. `group_sn` is the
/// Publisher GSN tag from inline QoS (only meaningful when the
/// publisher access_scope is GROUP); under TOPIC/INSTANCE scope it
/// remains `None`. Retained on the struct so future audits / packet
/// captures can correlate a buffered sample with the wire ECS that
/// bounds it even though the current dispatch logic keys on the
/// outer `(publisher_prefix, gsn)` map for GROUP-scope sets.
#[derive(Debug, Clone)]
pub(super) struct BufferedCoherentSample {
    remote_seq: u64,
    data: Vec<u8>,
    version: crate::dds::CdrVersion,
    #[allow(dead_code)]
    group_sn: Option<u64>,
}

/// Composite key for the GROUP-scope coherent aggregation buffer:
/// `(participant_prefix, publisher_entity_id, group_sn)`. Lifted to a
/// `type` alias to keep clippy's `type_complexity` lint happy while
/// preserving the readability of the docstring on the buffer field.
pub(super) type GroupSetKey = ([u8; 12], [u8; 4], u64);

/// Per-(publisher, group_sn) atomic-delivery state for GROUP-scope
/// coherent_access (DDS v1.4 §2.2.3.6 + RTPS v2.5 §8.7.5).
///
/// Aggregates samples from every writer in the same Publisher that
/// tagged its DATA with `PID_GROUP_COHERENT_SET = gsn` and tracks which
/// of those writers have already announced the close of the set via an
/// ECS DATA submessage carrying the same GSN. The set becomes
/// deliverable when every writer with buffered samples has been
/// observed in `closers` (i.e. has sent its ECS), at which point all
/// staged samples whose `remote_seq <= writer_ceiling[writer]` are
/// flushed atomically and the entry is removed. Samples whose
/// `remote_seq` is past the closing writer's `coherent_sn` are
/// publisher-protocol violations and are dropped with a warn log:
/// flushing them with the just-closed set would breach the writer-
/// scoped ECS boundary (RTPS v2.5 §8.7.5).
///
/// `closers` may temporarily contain a writer whose samples have not
/// yet arrived (UDP delivery reorder between samples and the ECS that
/// bounds them); the completion check tolerates this by re-evaluating
/// `per_writer.keys() subseteq closers` on every insertion. A writer
/// that contributes samples but never closes (e.g. dropped mid-set)
/// pins the set until `forget_writer` evicts it.
#[derive(Debug, Default)]
pub(super) struct GroupCoherentSet {
    /// Per-writer staged samples for this (publisher_prefix, group_sn).
    per_writer: HashMap<[u8; 16], Vec<BufferedCoherentSample>>,
    /// Writers that have sent an ECS DATA closing this group_sn.
    closers: HashSet<[u8; 16]>,
    /// Per-writer writer-scoped coherent_sn ceiling, set when the
    /// writer's ECS arrives. At flush time each writer's samples are
    /// partitioned by this ceiling; samples with `remote_seq` past
    /// the ceiling are dropped (publisher protocol violation: the
    /// ECS announced the set ended at `coherent_sn`).
    writer_ceilings: HashMap<[u8; 16], u64>,
}

impl GroupCoherentSet {
    /// Returns true when every writer with buffered samples has sent
    /// its ECS. An empty `per_writer` paired with non-empty `closers`
    /// also returns true (the writers that closed contributed zero
    /// samples) so the entry can be GC'd; the flush is then a no-op.
    fn is_complete(&self) -> bool {
        self.per_writer.keys().all(|w| self.closers.contains(w))
    }

    /// Number of samples currently buffered across all writers.
    fn total_samples(&self) -> usize {
        self.per_writer.values().map(Vec::len).sum()
    }
}

/// Bounded FIFO tombstone for GROUP sets that exceeded the memory
/// cap. Operations are O(1): `insert` pushes a key and evicts the
/// oldest once `MAX_DISCARDED` is reached, `contains` peeks the
/// HashSet, `remove` clears both halves (used when the matching ECS
/// arrives and lifts the tombstone). The bound is large enough that
/// overflow is rare in practice but small enough to keep the GC cost
/// bounded if a buggy publisher drops in storm conditions.
#[derive(Debug, Default)]
pub(super) struct DiscardedGroupSets {
    fifo: std::collections::VecDeque<([u8; 12], [u8; 4], u64)>,
    set: HashSet<([u8; 12], [u8; 4], u64)>,
}

impl DiscardedGroupSets {
    const MAX_DISCARDED: usize = 256;

    fn insert(&mut self, key: ([u8; 12], [u8; 4], u64)) {
        if self.set.contains(&key) {
            return;
        }
        if self.fifo.len() >= Self::MAX_DISCARDED {
            if let Some(oldest) = self.fifo.pop_front() {
                self.set.remove(&oldest);
            }
        }
        self.fifo.push_back(key);
        self.set.insert(key);
    }

    fn contains(&self, key: &([u8; 12], [u8; 4], u64)) -> bool {
        self.set.contains(key)
    }

    fn remove(&mut self, key: &([u8; 12], [u8; 4], u64)) -> bool {
        if !self.set.remove(key) {
            return false;
        }
        if let Some(pos) = self.fifo.iter().position(|k| k == key) {
            self.fifo.remove(pos);
        }
        true
    }
}

/// Configuration captured from the reader's QoS at subscriber
/// construction time so the data path can decide whether to buffer
/// per coherent set or to deliver immediately. Held by-value (the
/// QoS values are immutable for the life of the reader; DDS spec
/// 2.2.3.6 Presentation policy is non-runtime-changeable).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct CoherentConfig {
    /// Whether the reader's Presentation QoS enables coherent_access.
    /// When false the data path bypasses the buffer entirely and the
    /// per-sample coherent-set tags are ignored.
    pub coherent_access: bool,
    /// Whether the reader's Presentation QoS access_scope is GROUP.
    /// When true we wait for the ECS marker carrying
    /// `PID_GROUP_COHERENT_SET` before flushing; when false (TOPIC or
    /// INSTANCE) we flush as soon as we see ECS with `PID_COHERENT_SET`
    /// from the originating writer.
    pub is_group_scope: bool,
}

/// A dispose/unregister lifecycle event received from the network.
///
/// Stored by ReaderSubscriber and drained by DataReader to surface
/// instance state changes to the application.
#[derive(Debug, Clone)]
pub(super) struct DisposeEvent {
    /// 16-byte key hash identifying the instance.
    pub key_hash: [u8; 16],
    /// Dispose, Unregister, or both.
    pub kind: DisposeKind,
    /// RTPS writer sequence number.
    pub seq: u64,
}

/// Sliding window of recently admitted remote sequences.
///
/// Drops duplicates so a writer that resends the same seq (e.g. intra-process
/// loopback collision + UDP delivery, or a late transient retransmit that
/// already reached the reader) doesn't deliver a sample twice.
///
/// RTPS v2.5 §8.3.5.4 says sequence numbers are *per DataWriter*, so callers
/// must scope this window to a single writer GUID — otherwise a second
/// writer's legitimate `seq=N` would be dropped as a duplicate of the first
/// writer's `seq=N`. The writer-tagged data path keeps one `SeenSeqs` per
/// writer in a HashMap; the legacy (no-GUID) path keeps a single global
/// instance, accepting the multi-writer false-positive that pre-dates this
/// module.
#[derive(Debug, Default)]
struct SeenSeqs {
    /// Highest seq admitted so far.
    high: u64,
    /// Recent window of admitted seqs (covers out-of-order retransmits).
    recent: std::collections::VecDeque<u64>,
}

impl SeenSeqs {
    const WINDOW: usize = 4096;

    fn admit(&mut self, seq: u64) -> bool {
        if seq > self.high {
            self.high = seq;
            self.recent.push_back(seq);
            if self.recent.len() > Self::WINDOW {
                self.recent.pop_front();
            }
            return true;
        }
        // seq <= high: may be a duplicate or an out-of-order retransmit.
        // Admit only if not already in the recent window AND within window range.
        let floor = self.high.saturating_sub(Self::WINDOW as u64);
        if seq < floor {
            // Too old — conservatively drop (was already expired from window).
            return false;
        }
        if self.recent.iter().any(|&s| s == seq) {
            return false;
        }
        self.recent.push_back(seq);
        if self.recent.len() > Self::WINDOW {
            self.recent.pop_front();
        }
        true
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SeqWindow {
    /// Base sequence number (first remote sequence observed).
    base: u64,
    /// Optional stride between consecutive remote sequences.
    ///
    /// - `None`  -> dense mode (delta fits in u32, seq++ style).
    /// - `Some`  -> stride mode (remote_seq = base + k * stride).
    stride: Option<u64>,
    /// Whether the window has seen at least one sequence number.
    initialized: bool,
}

impl SeqWindow {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            base: 0,
            stride: None,
            initialized: false,
        }
    }

    /// Map a 64-bit remote sequence number into a local 32-bit sequence.
    ///
    /// Behaviour:
    /// - First sequence initializes the window (base) and returns 0.
    /// - While deltas are small (<= u32::MAX), uses dense mapping `seq = delta`.
    /// - On first large delta, switches to stride mode where
    ///   `local_seq = (remote_seq - base) / stride` if aligned.
    #[allow(dead_code)]
    fn map(&mut self, remote_seq: u64) -> Option<u32> {
        // Note: Duplicate detection is disabled because SeqWindow is per-topic,
        // not per-writer-GUID. Multiple writers can use the same sequence numbers.
        // Fragment-level duplicate detection happens in FragmentBuffer.

        // 1) First sequence: initialize base.
        if !self.initialized {
            self.base = remote_seq;
            self.stride = None;
            self.initialized = true;
            return Some(0);
        }

        // 2) Handle sequences from potentially new writers.
        // If seq < base, this might be a new writer starting fresh.
        // Re-initialize the window for the new writer's sequence space.
        if remote_seq < self.base {
            log::debug!(
                "[reader] Sequence {} < base {}; possible new writer, reinitializing window",
                remote_seq,
                self.base
            );
            self.base = remote_seq;
            self.stride = None;
            return Some(0);
        }

        let delta = remote_seq - self.base;

        // 3) No stride yet: try dense mapping first.
        if self.stride.is_none() {
            if let Ok(value) = u32::try_from(delta) {
                return Some(value);
            }

            // First large delta: treat it as stride.
            // At this point we know remote_seq == base + stride, so index is 1.
            if delta == 0 {
                // Defensive: shouldn't happen here, but keep behaviour sane.
                return Some(0);
            }

            self.stride = Some(delta);
            return Some(1);
        }

        // 4) Stride mode: enforce alignment on stride and map to index.
        let stride = match self.stride {
            Some(s) if s > 0 => s,
            _ => {
                log::debug!(
                    "[reader] Invalid stride (base={}, stride={:?}); dropping seq={}",
                    self.base,
                    self.stride,
                    remote_seq
                );
                return None;
            }
        };

        let idx = delta / stride;
        let rem = delta % stride;

        if rem != 0 {
            log::debug!(
                "[reader] Sequence {} not aligned on stride {} (base={}); dropping UDP packet",
                remote_seq,
                stride,
                self.base
            );
            return None;
        }

        match u32::try_from(idx) {
            Ok(value) => Some(value),
            Err(_) => {
                log::debug!(
                    "[reader] Sequence {} maps to idx {} > u32::MAX (base={}, stride={}); dropping UDP packet",
                    remote_seq,
                    idx,
                    self.base,
                    stride
                );
                None
            }
        }
    }
}

pub(super) struct ReaderSubscriber<T: DDS> {
    pub(super) topic: String,
    pub(super) ring: Arc<rt::IndexRing>,
    pub(super) status_condition: Arc<StatusCondition>,
    pub(super) participant_guard: Option<Arc<GuardCondition>>,
    #[allow(dead_code)]
    seq_window: Mutex<SeqWindow>,
    /// Recently admitted remote sequences for the legacy path that has no
    /// writer GUID. Single window because we cannot tell writers apart on
    /// this path; multi-writer scenarios on intra-process / writer-less
    /// transports are handled by the per-topic engine.
    seen_seqs: Mutex<SeenSeqs>,
    /// Per-writer recently admitted sequences for the network path. RTPS
    /// sequence numbers are scoped per DataWriter (RTPS v2.5 §8.3.5.4) so
    /// the dedup window must be keyed by the writer's 16-byte GUID.
    seen_seqs_by_writer: Mutex<std::collections::HashMap<[u8; 16], SeenSeqs>>,
    /// Optional content filter (for ContentFilteredTopic)
    pub(super) content_filter: Option<FilterEvaluator>,
    /// Optional listener for data callbacks
    pub(super) listener: Option<Arc<dyn DataReaderListener<T>>>,
    /// Shared queue for dispose/unregister events (drained by DataReader).
    pub(super) dispose_events: Arc<Mutex<Vec<DisposeEvent>>>,
    /// Per-writer reorder gate. Sample arrivals push into the gate via
    /// `on_data_with_writer`; the discovery control thread seeds the
    /// per-writer base sequence via `on_writer_heartbeat`.
    pub(super) reorder: Arc<Mutex<ReorderGate>>,
    /// Per-writer instance tracker for the SEDP-W dispose path. When a
    /// remote DataWriter is announced as disposed via SEDP DATA(d) on
    /// `ENTITYID_BUILTIN_PUBLICATIONS_WRITER`, no per-instance K-flag
    /// payload accompanies the announcement; the subscriber must emit one
    /// `on_dispose` per instance it has ever received from the writer.
    /// Storing only the 16-byte key hashes keeps memory bounded: ~24
    /// bytes per writer plus 16 bytes per (writer, instance) tuple. DDS
    /// v1.4 §2.2.4.2.2 mandates the instance-state transition regardless
    /// of whether the application already took the samples, so the
    /// tracker lives next to `dispose_events` (which survives `take()`)
    /// rather than inside the sample cache.
    pub(super) writer_instances:
        Mutex<std::collections::HashMap<[u8; 16], std::collections::HashSet<[u8; 16]>>>,
    /// Per-reader coherent_access configuration captured at build time
    /// (Presentation QoS is immutable per DDS spec 2.2.3.6).
    pub(super) coherent_cfg: CoherentConfig,
    /// Per-writer FIFO of samples buffered while a coherent set is
    /// open (RTPS v2.5 §8.7.5). The publisher tags each sample with
    /// `PID_COHERENT_SET = sample_sn` (writer-scoped) and the ECS
    /// DATA submessage with `PID_COHERENT_SET = last_sn_in_set`. On
    /// ECS arrival we drain every staged sample whose `remote_seq` is
    /// `<= ecs.coherent_sn`, sort them in writer order, and feed them
    /// through the regular admit pipeline so the application sees a
    /// complete in-order set.
    ///
    /// Used for TOPIC and INSTANCE access_scope (each writer's set is
    /// committed independently of other writers in the same Publisher).
    /// GROUP-scope sets are aggregated by `group_coherent_buffer` so the
    /// commit barrier waits for every writer in the publisher group
    /// before flushing.
    pub(super) coherent_buffer: Mutex<HashMap<[u8; 16], Vec<BufferedCoherentSample>>>,
    /// GROUP-scope coherent aggregation buffer, keyed by
    /// `(participant_prefix, publisher_entity_id, group_sn)` per
    /// DDS v1.4 §2.2.3.6 GROUP access_scope + RTPS v2.5 §9.3.2.1.
    /// The first 12 bytes of the writer GUID identify the Participant
    /// and `publisher_entity_id` (extracted from `PID_GROUP_ENTITY_ID`
    /// in inline QoS) identifies the Publisher within that Participant.
    /// Both are required: two Publishers in the same Participant can
    /// legitimately reuse the same GSN, so keying only by the prefix
    /// would alias their sets. When the wire doesn't carry
    /// `PID_GROUP_ENTITY_ID` we fall back to `[0; 4]` as a distinct
    /// "unspecified publisher" sentinel so an emitter that never
    /// advertises the PID doesn't collide with one that does.
    pub(super) group_coherent_buffer: Mutex<HashMap<GroupSetKey, GroupCoherentSet>>,
    /// Tombstone for GROUP sets that exceeded the per-set memory cap.
    /// DDS coherent_access is an all-or-nothing presentation contract
    /// (DDS v1.4 §2.2.3.6), so an overflow MUST drop the entire set
    /// rather than truncate it. While a set is tombstoned, every
    /// subsequent sample tagged with the same key is dropped silently;
    /// the matching ECS arrival lifts the tombstone (no flush). A
    /// bounded FIFO eviction prevents leaks if the closing ECS is
    /// never observed (e.g. the publisher crashed mid-set).
    pub(super) discarded_group_sets: Mutex<DiscardedGroupSets>,
    /// Per-writer delivery serialisation mutex. Released samples from a
    /// given writer GUID are pushed to the ring under this lock — keeps
    /// per-writer FIFO order without holding the reorder gate (which
    /// gates ALL writers and would block on user listener callbacks).
    /// Lookup is constant-time; the outer Mutex is held only briefly to
    /// fetch / insert the per-writer Arc<Mutex<()>>.
    delivery_locks: Mutex<std::collections::HashMap<[u8; 16], Arc<Mutex<()>>>>,
    pub(super) _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> ReaderSubscriber<T> {
    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub fn new(
        topic: String,
        ring: Arc<rt::IndexRing>,
        status_condition: Arc<StatusCondition>,
        participant_guard: Option<Arc<GuardCondition>>,
        content_filter: Option<FilterEvaluator>,
        listener: Option<Arc<dyn DataReaderListener<T>>>,
        dispose_events: Arc<Mutex<Vec<DisposeEvent>>>,
        reorder: Arc<Mutex<ReorderGate>>,
    ) -> Self {
        Self::new_with_coherent(
            topic,
            ring,
            status_condition,
            participant_guard,
            content_filter,
            listener,
            dispose_events,
            reorder,
            CoherentConfig::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_with_coherent(
        topic: String,
        ring: Arc<rt::IndexRing>,
        status_condition: Arc<StatusCondition>,
        participant_guard: Option<Arc<GuardCondition>>,
        content_filter: Option<FilterEvaluator>,
        listener: Option<Arc<dyn DataReaderListener<T>>>,
        dispose_events: Arc<Mutex<Vec<DisposeEvent>>>,
        reorder: Arc<Mutex<ReorderGate>>,
        coherent_cfg: CoherentConfig,
    ) -> Self {
        if participant_guard.is_some() {
            log::debug!(
                "[READER-SUB] participant guard attached for topic='{}'",
                topic
            );
        } else {
            log::debug!("[READER-SUB] no participant guard for topic='{}'", topic);
        }
        if content_filter.is_some() {
            log::debug!("[READER-SUB] content filter attached for topic='{}'", topic);
        }
        if coherent_cfg.coherent_access {
            log::debug!(
                "[READER-SUB] coherent_access enabled topic='{}' group_scope={}",
                topic,
                coherent_cfg.is_group_scope
            );
        }
        Self {
            topic,
            ring,
            status_condition,
            participant_guard,
            seq_window: Mutex::new(SeqWindow::new()),
            seen_seqs: Mutex::new(SeenSeqs::default()),
            seen_seqs_by_writer: Mutex::new(std::collections::HashMap::new()),
            content_filter,
            listener,
            dispose_events,
            reorder,
            writer_instances: Mutex::new(std::collections::HashMap::new()),
            coherent_cfg,
            coherent_buffer: Mutex::new(HashMap::new()),
            group_coherent_buffer: Mutex::new(HashMap::new()),
            discarded_group_sets: Mutex::new(DiscardedGroupSets::default()),
            delivery_locks: Mutex::new(std::collections::HashMap::new()),
            _phantom: core::marker::PhantomData,
        }
    }

    /// Get or create the per-writer delivery lock. Held during
    /// `deliver_released` to preserve per-writer FIFO order on the
    /// ring without serialising across all writers.
    fn writer_delivery_lock(&self, writer_guid: [u8; 16]) -> Arc<Mutex<()>> {
        let mut map = match self.delivery_locks.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        map.entry(writer_guid)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Run the decode -> filter -> listener -> re-encode -> slab -> ring
    /// pipeline for a single sample. Returns silently on any failure (the
    /// path was already best-effort for malformed payloads / pool
    /// exhaustion; preserving that behaviour avoids interop regressions).
    ///
    /// When `writer_guid` is `Some`, the decoded sample's instance key is
    /// recorded in `writer_instances` so the SEDP-W dispose path can later
    /// emit per-instance `on_dispose` events for every instance ever seen
    /// from that writer (DDS v1.4 §2.2.4.2.2).
    fn process_admitted(
        &self,
        writer_guid: Option<[u8; 16]>,
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        let msg = match T::decode(data, version) {
            Ok(m) => m,
            Err(_e) => {
                log::debug!(
                    "[READER-SUB] decode failed topic='{}' seq={} len={}: {:?}",
                    self.topic,
                    remote_seq,
                    data.len(),
                    _e
                );
                return;
            }
        };

        // Apply content filter if present
        if let Some(ref filter) = self.content_filter {
            let fields = T::get_fields(&msg);
            match filter.matches(&fields) {
                Ok(true) => {
                    log::trace!(
                        "[READER-SUB] Sample passed content filter for topic='{}'",
                        self.topic
                    );
                }
                Ok(false) => {
                    log::debug!(
                        "[READER-SUB] Sample rejected by content filter for topic='{}'",
                        self.topic
                    );
                    return;
                }
                Err(e) => {
                    log::debug!(
                        "[READER-SUB] Filter evaluation error for topic='{}': {:?}",
                        self.topic,
                        e
                    );
                    // On error, reject the sample (fail-safe)
                    return;
                }
            }
        }

        // Per-(writer, instance) tracker for the SEDP-W dispose path. Done
        // after the content filter so a sample the reader explicitly
        // rejected does not later resurface as a NOT_ALIVE event on the
        // SEDP-W path. We still do it before the re-encode + slab push so
        // a tracker insert is not coupled to history/lifespan eviction;
        // DDS v1.4 §2.2.4.2.2 says the instance-state transition is
        // independent of whether the application took the samples.
        if let Some(guid) = writer_guid {
            let key_hash = msg.compute_key();
            let mut guard = match self.writer_instances.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.entry(guid).or_default().insert(key_hash);
        }

        if let Some(ref listener) = self.listener {
            listener.on_data_available(&msg);
        }

        // Grow-and-retry re-encoding buffer: start at 64KB (covers typical
        // RTPS DATA payload) and double on BufferTooSmall up to 16MB to
        // support DATA_FRAG reassembled payloads (e.g. 100KB LargeData).
        const MAX_RE_ENCODE_SIZE: usize = 16 * 1024 * 1024;
        let (tmp_buf, serialized_len) = {
            let mut size = 65_536usize;
            loop {
                let mut buf = vec![0u8; size];
                match msg.encode(&mut buf, version) {
                    Ok(len) => break (buf, len),
                    Err(crate::dds::Error::BufferTooSmall) if size < MAX_RE_ENCODE_SIZE => {
                        size = (size * 2).min(MAX_RE_ENCODE_SIZE);
                    }
                    Err(_e) => {
                        log::debug!("[READER-SUB] re-encode failed: {:?}", _e);
                        return;
                    }
                }
            }
        };

        let slab_pool = rt::get_slab_pool();
        let (handle, _metric) = match slab_pool.reserve_and_write(&tmp_buf[..serialized_len]) {
            Some(value) => value,
            None => {
                log::debug!("[READER-SUB] slab_pool exhausted");
                return;
            }
        };

        // Use the raw remote_seq (truncated to u32) directly. Previously
        // we mapped via `SeqWindow::map` which re-initialises its `base` on
        // any arrival with `remote_seq < base` (SeqWindow step 2). When a
        // late-joiner buffered live samples (seq >> 1) before its HEARTBEAT
        // seed and only then drained the retransmits of seq 1..N, the re-init
        // mapped the smaller historical seqs onto the same local slot as the
        // earlier-buffered larger live seq — SampleCache then duplicate-dropped
        // them silently, so sample seq 1 was lost on the application read.
        // Keying on the raw RTPS sequence avoids the slot collision and gives
        // every distinct remote_seq its own cache key. RTPS samples come in
        // far below u32::MAX for any realistic session; on overflow the cache
        // simply wraps and behaves like the old SeqWindow path.
        let seq = remote_seq as u32;

        let len = match u32::try_from(serialized_len) {
            Ok(value) => value,
            Err(_) => {
                slab_pool.release(handle);
                if let Some(m) = telemetry::get_metrics_opt() {
                    m.increment_dropped(1);
                }
                log::debug!(
                    "[reader] Serialized payload too large ({} bytes); dropping UDP packet",
                    serialized_len
                );
                return;
            }
        };

        let entry = rt::IndexEntry {
            seq,
            handle,
            len,
            flags: 0x01,
            cdr_version: version,
            timestamp_ns: current_time_ns(),
            event_data: 0,
        };

        if self.ring.push(entry) {
            log::debug!(
                "[READER-SUB] pushed topic='{}' seq={} len={}",
                self.topic,
                seq,
                len
            );
            self.status_condition
                .set_active_statuses(StatusMask::DATA_AVAILABLE);
            if let Some(guard) = &self.participant_guard {
                log::debug!(
                    "[READER-SUB-SIGNAL] triggering participant guard topic='{}'",
                    self.topic
                );
                guard.set_trigger_value(true);
            }
        } else {
            slab_pool.release(handle);
            log::debug!("Reader ring full - dropping UDP packet");
        }
    }

    /// Push any payloads the reorder gate just released (in writer-seq
    /// order) through the per-sample pipeline. `writer_guid` tags the
    /// originating DataWriter so `process_admitted` can update the
    /// per-(writer, instance) tracker used by SEDP-W dispose detection.
    fn deliver_released(&self, writer_guid: Option<[u8; 16]>, released: Vec<PendingPayload>) {
        for payload in released {
            self.process_admitted(
                writer_guid,
                payload.remote_seq,
                &payload.data,
                payload.version,
            );
        }
    }

    /// Stage a sample into the GROUP-scope aggregation buffer
    /// (DDS v1.4 §2.2.3.6 + RTPS v2.5 §8.7.5). Called from
    /// `on_data_coherent` when the reader's Presentation access_scope
    /// is GROUP and the sample carries `PID_GROUP_COHERENT_SET = gsn`.
    /// Bucketed by `(participant_prefix, publisher_entity_id, gsn)` so
    /// multi-writer GROUP sets commit atomically once every
    /// contributing writer has closed via ECS, and two Publishers in
    /// the same Participant do not alias on the same GSN
    /// (RTPS v2.5 §9.3.2.1).
    fn stage_group_sample(
        &self,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        gsn: u64,
        publisher_entity_id: [u8; 4],
    ) {
        // Hard cap per-(publisher, gsn) staging. DDS coherent_access is
        // an all-or-nothing presentation contract (DDS v1.4 §2.2.3.6);
        // on overflow we MUST drop the entire set and tombstone the
        // key so subsequent samples + the closing ECS for the same set
        // do not produce a truncated atomic delivery.
        const MAX_BUFFERED_PER_GROUP: usize = 8_192;

        let publisher_prefix: [u8; 12] = match writer_guid[..12].try_into() {
            Ok(p) => p,
            Err(_) => return,
        };
        let key = (publisher_prefix, publisher_entity_id, gsn);

        {
            let tomb = match self.discarded_group_sets.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if tomb.contains(&key) {
                log::debug!(
                    "[READER-SUB] GROUP sample dropped (set tombstoned) topic='{}' \
                     writer={:02x?} gsn={} pub_eid={:02x?}",
                    self.topic,
                    &writer_guid[..4],
                    gsn,
                    publisher_entity_id,
                );
                return;
            }
        }

        let mut buf = match self.group_coherent_buffer.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };

        // Overflow check BEFORE inserting the new sample so the cap is
        // a hard bound, not a soft one. If adding this sample would
        // breach the cap, drop the entire set + tombstone + drop the
        // sample (atomic-or-nothing contract preserved per
        // DDS v1.4 §2.2.3.6).
        let projected = buf
            .get(&key)
            .map_or(0, GroupCoherentSet::total_samples)
            .saturating_add(1);
        if projected > MAX_BUFFERED_PER_GROUP {
            let prev = buf.remove(&key);
            log::warn!(
                "[READER-SUB] GROUP coherent buffer overflow topic='{}' gsn={} pub_eid={:02x?} \
                 cap={} discarded entire set ({} samples) — atomic delivery contract preserved",
                self.topic,
                gsn,
                publisher_entity_id,
                MAX_BUFFERED_PER_GROUP,
                prev.as_ref().map_or(0, GroupCoherentSet::total_samples),
            );
            drop(buf);
            let mut tomb = match self.discarded_group_sets.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            tomb.insert(key);
            return;
        }

        let set = buf.entry(key).or_default();
        let entry = set.per_writer.entry(writer_guid).or_default();
        entry.push(BufferedCoherentSample {
            remote_seq: seq,
            data: data.to_vec(),
            version,
            group_sn: Some(gsn),
        });
        log::debug!(
            "[READER-SUB] GROUP coherent buffer topic='{}' writer={:02x?} seq={} gsn={} \
             pub_eid={:02x?} writer_buf={} group_buf={}",
            self.topic,
            &writer_guid[..4],
            seq,
            gsn,
            publisher_entity_id,
            entry.len(),
            set.total_samples(),
        );

        if set.is_complete() {
            // ECS arrived before samples for every member writer; the
            // set is now complete and can flush. Remove the entry,
            // release the lock before dispatching through the gate.
            if let Some(ready) = buf.remove(&key) {
                drop(buf);
                self.flush_group_set(publisher_prefix, publisher_entity_id, gsn, ready);
            }
        }
    }

    /// Mark `writer_guid` as having closed the group set identified by
    /// `(participant_prefix, publisher_entity_id, gsn)` and flush
    /// atomically once every writer with buffered samples has been
    /// observed in `closers`. `coherent_sn` is the writer's own
    /// last-sample SN per the ECS marker; samples whose `remote_seq`
    /// is past this value are dropped at flush time because the ECS
    /// announced the set ended at `coherent_sn` and including them
    /// would breach the writer-scoped ECS boundary
    /// (RTPS v2.5 §8.7.5).
    fn close_group_set(
        &self,
        writer_guid: [u8; 16],
        coherent_sn: u64,
        gsn: u64,
        publisher_entity_id: [u8; 4],
    ) {
        let publisher_prefix: [u8; 12] = match writer_guid[..12].try_into() {
            Ok(p) => p,
            Err(_) => return,
        };
        let key = (publisher_prefix, publisher_entity_id, gsn);

        // Tombstone path: ECS arrived after the set was discarded for
        // overflow. Lift the tombstone (single-use) and swallow the
        // ECS without flushing — atomic-or-nothing means "nothing".
        {
            let mut tomb = match self.discarded_group_sets.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if tomb.remove(&key) {
                log::debug!(
                    "[READER-SUB] GROUP ECS swallowed (set was tombstoned) topic='{}' \
                     writer={:02x?} gsn={} pub_eid={:02x?}",
                    self.topic,
                    &writer_guid[..4],
                    gsn,
                    publisher_entity_id,
                );
                return;
            }
        }

        let ready = {
            let mut buf = match self.group_coherent_buffer.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };

            let set = buf.entry(key).or_default();
            let inserted = set.closers.insert(writer_guid);
            // Record this writer's per-set ceiling so flush_group_set
            // can drop samples past coherent_sn (publisher-protocol
            // violations that must NOT be delivered with the set).
            set.writer_ceilings.insert(writer_guid, coherent_sn);
            log::debug!(
                "[READER-SUB] GROUP ECS topic='{}' writer={:02x?} gsn={} coherent_sn={} \
                 pub_eid={:02x?} first_close={} contributors={} closers={}",
                self.topic,
                &writer_guid[..4],
                gsn,
                coherent_sn,
                publisher_entity_id,
                inserted,
                set.per_writer.len(),
                set.closers.len(),
            );

            if set.is_complete() {
                buf.remove(&key)
            } else {
                None
            }
        };

        if let Some(set) = ready {
            self.flush_group_set(publisher_prefix, publisher_entity_id, gsn, set);
        }
    }

    /// Drain a completed GROUP set through the regular admit pipeline.
    /// Samples are released in `(writer_guid, remote_seq)` order so the
    /// application sees a deterministic interleaving even when UDP
    /// reordered the arrivals; per-writer monotonic seq order is
    /// preserved because the reorder gate is invoked per-writer.
    /// Samples whose `remote_seq` is past the per-writer `coherent_sn`
    /// ceiling are dropped with a warn — they are publisher-protocol
    /// violations and must NOT be included in the atomic batch
    /// (RTPS v2.5 §8.7.5).
    fn flush_group_set(
        &self,
        publisher_prefix: [u8; 12],
        publisher_entity_id: [u8; 4],
        gsn: u64,
        mut set: GroupCoherentSet,
    ) {
        // Stable ordering: sort writer entries by writer_guid so a
        // re-run of the same scenario produces the same interleaving.
        // Within each writer, samples are released in remote_seq order
        // (the reorder gate enforces this; we also sort the buffer to
        // bypass any quirk in the gate's stride-detection heuristics).
        let ceilings = std::mem::take(&mut set.writer_ceilings);
        let mut writers: Vec<_> = set.per_writer.drain().collect();
        writers.sort_by_key(|(guid, _)| *guid);

        let total: usize = writers.iter().map(|(_, v)| v.len()).sum();
        log::debug!(
            "[READER-SUB] GROUP set flush topic='{}' publisher={:02x?} pub_eid={:02x?} gsn={} \
             writers={} samples={}",
            self.topic,
            &publisher_prefix[..4],
            publisher_entity_id,
            gsn,
            writers.len(),
            total,
        );

        for (writer_guid, mut samples) in writers {
            // Apply the writer's ECS ceiling: drop samples beyond it.
            // If the writer had no ECS (set flushed via writer-lost
            // path) treat `u64::MAX` as the ceiling so all buffered
            // samples are released — the writer-lost code already
            // logged the drop intent.
            let ceiling = ceilings.get(&writer_guid).copied().unwrap_or(u64::MAX);
            samples.retain(|s| {
                if s.remote_seq > ceiling {
                    log::warn!(
                        "[READER-SUB] GROUP coherent sample past close — dropped topic='{}' \
                         writer={:02x?} gsn={} sample_seq={} ecs_coherent_sn={}",
                        self.topic,
                        &writer_guid[..4],
                        gsn,
                        s.remote_seq,
                        ceiling,
                    );
                    false
                } else {
                    true
                }
            });
            samples.sort_by_key(|s| s.remote_seq);
            for sample in samples {
                let released = {
                    let mut gate = match self.reorder.lock() {
                        Ok(lock) => lock,
                        Err(e) => e.into_inner(),
                    };
                    let payload = PendingPayload {
                        data: sample.data,
                        version: sample.version,
                        remote_seq: sample.remote_seq,
                    };
                    gate.on_data(writer_guid, sample.remote_seq, payload)
                };
                self.deliver_released(Some(writer_guid), released);
            }
        }
    }

    /// Evict a writer from every GROUP set it participates in. Called
    /// from the writer-dispose / writer-lost path so a publisher
    /// dropping mid-set doesn't pin the buffer forever. The sweep
    /// covers every `publisher_entity_id` for this writer's
    /// participant prefix; a single writer belongs to exactly one
    /// Publisher in DDS but the receiver may have observed a sample
    /// for that writer with `PID_GROUP_ENTITY_ID` missing
    /// (cross-vendor edge case) and bucketed it under the `[0; 4]`
    /// sentinel, so we drop the writer from all such variants.
    fn forget_writer_in_group_sets(&self, writer_guid: [u8; 16]) {
        let publisher_prefix: [u8; 12] = match writer_guid[..12].try_into() {
            Ok(p) => p,
            Err(_) => return,
        };

        type GroupKey = ([u8; 12], [u8; 4], u64);
        let mut to_flush: Vec<(GroupKey, GroupCoherentSet)> = Vec::new();
        {
            let mut buf = match self.group_coherent_buffer.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let keys: Vec<_> = buf
                .keys()
                .copied()
                .filter(|(prefix, _, _)| *prefix == publisher_prefix)
                .collect();
            for key in keys {
                if let Some(set) = buf.get_mut(&key) {
                    let removed = set.per_writer.remove(&writer_guid).map(|v| v.len());
                    let was_closer = set.closers.remove(&writer_guid);
                    set.writer_ceilings.remove(&writer_guid);
                    if let Some(dropped) = removed {
                        if dropped > 0 {
                            log::debug!(
                                "[READER-SUB] GROUP coherent drop on writer dispose topic='{}' \
                                 writer={:02x?} gsn={} pub_eid={:02x?} dropped_samples={} \
                                 was_closer={}",
                                self.topic,
                                &writer_guid[..4],
                                key.2,
                                key.1,
                                dropped,
                                was_closer,
                            );
                        }
                    }
                    if set.per_writer.is_empty() && set.closers.is_empty() {
                        buf.remove(&key);
                    } else if set.is_complete() {
                        if let Some(ready) = buf.remove(&key) {
                            to_flush.push((key, ready));
                        }
                    }
                }
            }
        }

        for ((prefix, pub_eid, gsn), set) in to_flush {
            self.flush_group_set(prefix, pub_eid, gsn, set);
        }
    }
}

impl<T: DDS> crate::engine::Subscriber for ReaderSubscriber<T> {
    fn on_data(&self, topic: &str, remote_seq: u64, data: &[u8]) {
        // Fallback path: wire CDR version unknown at this entry point,
        // default to Xcdr2 to preserve pre-2.5-f behavior.
        self.on_data_with_version(topic, remote_seq, data, crate::dds::CdrVersion::Xcdr2);
    }

    fn on_data_with_version(
        &self,
        _topic: &str,
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        // Drop duplicate remote sequences. Per RTPS v2.5 §8.4.2.2 a DataWriter
        // MUST assign a monotonically increasing sequence number per sample,
        // so repeats are retransmits that were already delivered. Without
        // this guard, a writer that resends a sample under the same seq
        // delivers the payload twice (breaks reliability tests).
        {
            let mut seen = match self.seen_seqs.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            if !seen.admit(remote_seq) {
                log::debug!(
                    "[READER-SUB] dropping duplicate remote_seq={} topic='{}'",
                    remote_seq,
                    self.topic
                );
                return;
            }
        }
        // No writer GUID available on this path — bypass the reorder gate
        // and ship straight through, matching pre-reorder behaviour for
        // intra-process / non-routed paths that never see a writer GUID.
        self.process_admitted(None, remote_seq, data, version);
    }

    fn on_data_with_writer(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        remote_seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
    ) {
        {
            let mut map = match self.seen_seqs_by_writer.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            let seen = map.entry(writer_guid).or_default();
            if !seen.admit(remote_seq) {
                log::debug!(
                    "[READER-SUB] dropping duplicate remote_seq={} writer={:02x?} topic='{}'",
                    remote_seq,
                    &writer_guid[..4],
                    self.topic
                );
                return;
            }
        }

        // Run the sample through the per-writer reorder gate. For Volatile
        // readers the gate is disabled and returns the sample immediately;
        // for TRANSIENT_LOCAL+ readers it holds out-of-order arrivals until
        // the writer-seq prefix is contiguous (DDS v1.4 §2.2.3.4 + RTPS
        // v2.5 §8.4.2.2 reliable-retransmit interleaving).
        let released = {
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            let payload = PendingPayload {
                data: data.to_vec(),
                version,
                remote_seq,
            };
            gate.on_data(writer_guid, remote_seq, payload)
        };
        if !released.is_empty() {
            let lock = self.writer_delivery_lock(writer_guid);
            let _del_guard = match lock.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            self.deliver_released(Some(writer_guid), released);
        }
    }

    fn on_writer_heartbeat(&self, writer_guid: [u8; 16], first_seq: u64) {
        let released = {
            let mut gate = match self.reorder.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            gate.on_heartbeat(writer_guid, first_seq)
        };
        if !released.is_empty() {
            let lock = self.writer_delivery_lock(writer_guid);
            let _del_guard = match lock.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            self.deliver_released(Some(writer_guid), released);
        }
    }

    fn on_data_coherent(
        &self,
        topic: &str,
        writer_guid: [u8; 16],
        seq: u64,
        data: &[u8],
        version: crate::dds::CdrVersion,
        coherent_sn: Option<u64>,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        // If this reader didn't opt in to coherent_access just deliver
        // immediately like a regular DATA sample — the coherent tags
        // are advisory at the wire level.
        if !self.coherent_cfg.coherent_access {
            self.on_data_with_writer(topic, writer_guid, seq, data, version);
            return;
        }

        // No coherent tags at all -> pass through. This happens when
        // the publisher's QoS is non-coherent OR when the publisher
        // hasn't opened a set yet (samples between two
        // begin/end_coherent_changes windows).
        if coherent_sn.is_none() && group_sn.is_none() {
            self.on_data_with_writer(topic, writer_guid, seq, data, version);
            return;
        }

        // De-dup against the per-writer admission window so a coherent
        // sample that arrives twice (retransmit interleaved with the
        // ECS path) is staged only once.
        {
            let mut map = match self.seen_seqs_by_writer.lock() {
                Ok(lock) => lock,
                Err(e) => e.into_inner(),
            };
            let seen = map.entry(writer_guid).or_default();
            if !seen.admit(seq) {
                log::debug!(
                    "[READER-SUB] coherent dup drop topic='{}' writer={:02x?} seq={}",
                    self.topic,
                    &writer_guid[..4],
                    seq
                );
                return;
            }
        }

        // GROUP-scope sets aggregate across all writers in the same
        // Publisher (DDS v1.4 §2.2.3.6). Route the sample into the
        // group buffer keyed by (participant_prefix, publisher_entity_id,
        // group_sn) and bail before touching the per-writer buffer;
        // TOPIC/INSTANCE-scope sets keep using the simpler per-writer
        // buffer below.
        if self.coherent_cfg.is_group_scope {
            if let Some(gsn) = group_sn {
                self.stage_group_sample(
                    writer_guid,
                    seq,
                    data,
                    version,
                    gsn,
                    publisher_entity_id.unwrap_or([0; 4]),
                );
                return;
            }
            // Group-scope reader received a coherent sample without a
            // GSN tag. The publisher is either non-GROUP or the sample
            // arrived before begin_coherent_changes assigned a GSN.
            // Pass through immediately rather than gambling on the
            // writer-only buffer (which doesn't enforce the group
            // barrier).
            self.on_data_with_writer(topic, writer_guid, seq, data, version);
            return;
        }

        // TOPIC / INSTANCE access_scope: each writer's set is committed
        // independently. Stage in the per-writer FIFO and wait for the
        // matching ECS.
        let mut guard = match self.coherent_buffer.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let entry = guard.entry(writer_guid).or_default();

        // Cap per-writer staging at a sane upper bound. A misbehaving
        // publisher (or a lost ECS marker)
        // would otherwise let this Vec grow until the host OOMs. The
        // cap matches the worst-case ResourceLimits a reader would
        // hold for normal traffic; on overrun we drop the OLDEST
        // staged sample (FIFO) since the application contract is that
        // a complete coherent set is committed atomically, and an
        // incomplete prefix is more useful diagnostically than an
        // overflowed tail.
        const MAX_BUFFERED_PER_WRITER: usize = 4_096;
        if entry.len() >= MAX_BUFFERED_PER_WRITER {
            let dropped = entry.remove(0);
            log::warn!(
                "[READER-SUB] coherent buffer overflow topic='{}' writer={:02x?} cap={} \
                 dropped oldest seq={} (likely lost ECS marker or runaway publisher)",
                self.topic,
                &writer_guid[..4],
                MAX_BUFFERED_PER_WRITER,
                dropped.remote_seq
            );
        }

        entry.push(BufferedCoherentSample {
            remote_seq: seq,
            data: data.to_vec(),
            version,
            group_sn,
        });
        log::debug!(
            "[READER-SUB] coherent buffer topic='{}' writer={:02x?} seq={} group_sn={:?} buffered={}",
            self.topic,
            &writer_guid[..4],
            seq,
            group_sn,
            entry.len()
        );
    }

    fn on_ecs(
        &self,
        _topic: &str,
        writer_guid: [u8; 16],
        coherent_sn: u64,
        group_sn: Option<u64>,
        publisher_entity_id: Option<[u8; 4]>,
    ) {
        if !self.coherent_cfg.coherent_access {
            return;
        }

        // RTPS v2.5 §8.7.5 + DDS v1.4 §2.2.3.6: under GROUP-scope
        // coherent_access an ECS marker MUST carry PID_GROUP_COHERENT_SET.
        // An ECS with only PID_COHERENT_SET is a TOPIC/INSTANCE-scope
        // closure and MUST NOT prematurely flush a GROUP-scope buffer
        // (a malformed or adversarial Q-only DATA carrying just
        // PID_COHERENT_SET could otherwise release samples whose group
        // set is still open).
        if self.coherent_cfg.is_group_scope && group_sn.is_none() {
            log::debug!(
                "[READER-SUB] ECS without group_sn ignored under GROUP scope topic='{}' writer={:02x?} coherent_sn={}",
                self.topic,
                &writer_guid[..4],
                coherent_sn
            );
            return;
        }

        // GROUP-scope: route through the publisher-wide barrier. Mark
        // this writer as closed for the given group_sn and atomically
        // flush the set only once every writer with buffered samples in
        // that set has sent its ECS (DDS v1.4 §2.2.3.6).
        if self.coherent_cfg.is_group_scope {
            if let Some(gsn) = group_sn {
                self.close_group_set(
                    writer_guid,
                    coherent_sn,
                    gsn,
                    publisher_entity_id.unwrap_or([0; 4]),
                );
            }
            return;
        }

        // TOPIC / INSTANCE access_scope: per-writer commit. Partition the
        // writer's FIFO into:
        //   * "in-set" samples (remote_seq <= ecs.coherent_sn) -> commit
        //   * "outside-the-set" samples -> leave in the buffer for a
        //     later ECS to close
        let to_commit = {
            let mut guard = match self.coherent_buffer.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let Some(entries) = guard.get_mut(&writer_guid) else {
                return;
            };
            let group_match = |_s: &BufferedCoherentSample| -> bool { true };
            let mut commit = Vec::new();
            let mut keep = Vec::new();
            for s in entries.drain(..) {
                if s.remote_seq <= coherent_sn && group_match(&s) {
                    commit.push(s);
                } else {
                    keep.push(s);
                }
            }
            *entries = keep;
            if entries.is_empty() {
                guard.remove(&writer_guid);
            }
            commit
        };

        if to_commit.is_empty() {
            log::debug!(
                "[READER-SUB] ECS no-op topic='{}' writer={:02x?} coherent_sn={} group_sn={:?} (no buffered samples)",
                self.topic,
                &writer_guid[..4],
                coherent_sn,
                group_sn
            );
            return;
        }

        // Sort by writer-scoped remote_seq so the application sees the
        // set in writer order even if UDP delivery reordered the
        // arrivals (RTPS v2.5 §8.3.5.4 sample ordering within a set).
        let mut samples = to_commit;
        samples.sort_by_key(|s| s.remote_seq);

        log::debug!(
            "[READER-SUB] ECS commit topic='{}' writer={:02x?} coherent_sn={} group_sn={:?} count={}",
            self.topic,
            &writer_guid[..4],
            coherent_sn,
            group_sn,
            samples.len()
        );

        for sample in samples {
            let released = {
                let mut gate = match self.reorder.lock() {
                    Ok(lock) => lock,
                    Err(e) => e.into_inner(),
                };
                let payload = PendingPayload {
                    data: sample.data,
                    version: sample.version,
                    remote_seq: sample.remote_seq,
                };
                gate.on_data(writer_guid, sample.remote_seq, payload)
            };
            self.deliver_released(Some(writer_guid), released);
        }
    }

    fn on_dispose(&self, _topic: &str, seq: u64, key_hash: [u8; 16], kind: DisposeKind) {
        log::debug!(
            "[READER-SUB] on_dispose topic='{}' seq={} kind={:?} key_hash={:02x?}",
            self.topic,
            seq,
            kind,
            &key_hash[..4]
        );

        // Push event to shared queue (DataReader drains it)
        if let Ok(mut events) = self.dispose_events.lock() {
            events.push(DisposeEvent {
                key_hash,
                kind,
                seq,
            });
        }

        // Signal data available so WaitSet wakes up
        self.status_condition
            .set_active_statuses(StatusMask::DATA_AVAILABLE);
        if let Some(guard) = &self.participant_guard {
            guard.set_trigger_value(true);
        }
    }

    fn on_writer_dispose(&self, _topic: &str, writer_guid: [u8; 16], kind: DisposeKind) {
        // Snapshot the instance set under lock, then fire dispose events
        // outside to avoid holding the tracker mutex during status-condition
        // signalling (on_dispose tries to lock dispose_events itself).
        let handles: Vec<[u8; 16]> = {
            let mut guard = match self.writer_instances.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Drain the entry so a future SEDP-W from the same writer GUID
            // (e.g. the writer endpoint is re-created with the same id) does
            // not double-fire on stale instances.
            guard
                .remove(&writer_guid)
                .map(|set| set.into_iter().collect())
                .unwrap_or_default()
        };

        // Drop any coherent-set samples staged for this writer. If the
        // writer disappears before its ECS
        // marker is delivered, the staged set is never going to commit
        // and would otherwise leak memory indefinitely (no other code
        // path drains a stale per-writer buffer).
        {
            let mut buf = match self.coherent_buffer.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(dropped) = buf.remove(&writer_guid) {
                if !dropped.is_empty() {
                    log::debug!(
                        "[READER-SUB] coherent buffer drop on writer dispose topic='{}' \
                         writer={:02x?} dropped_samples={}",
                        self.topic,
                        &writer_guid[..4],
                        dropped.len()
                    );
                }
            }
        }
        // GROUP-scope: also evict the writer from any per-(publisher,
        // gsn) sets it participated in so a dropped writer never pins
        // a set forever. May trigger flushes for sets whose remaining
        // contributors had already closed (atomic commit per DDS
        // v1.4 §2.2.3.6 is preserved across the eviction).
        self.forget_writer_in_group_sets(writer_guid);
        // Same for the per-writer dedup admission window.
        {
            let mut map = match self.seen_seqs_by_writer.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            map.remove(&writer_guid);
        }

        if handles.is_empty() {
            log::debug!(
                "[READER-SUB] on_writer_dispose topic='{}' writer={:02x?} kind={:?} \
                 no instances tracked — no-op",
                self.topic,
                &writer_guid[..4],
                kind
            );
            return;
        }

        log::debug!(
            "[READER-SUB] on_writer_dispose topic='{}' writer={:02x?} kind={:?} \
             firing {} per-instance dispose events",
            self.topic,
            &writer_guid[..4],
            kind,
            handles.len()
        );

        // RTPS sequence number for synthesized events is 0: the SEDP-W
        // packet has its own writer SN tracked elsewhere; for the user-data
        // queue we have no meaningful per-sample seq to attach.
        for key_hash in handles {
            self.on_dispose(&self.topic, 0, key_hash, kind);
        }
    }

    fn topic_name(&self) -> &str {
        &self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::SeqWindow;

    #[test]
    fn seq_window_maps_initial_and_monotonic_increase() {
        let mut window = SeqWindow::new();
        assert_eq!(window.map(100), Some(0));
        assert_eq!(window.map(101), Some(1));
        assert_eq!(window.map(110), Some(10));
    }

    #[test]
    fn seq_window_reinits_for_lower_seq() {
        // When a sequence < base arrives, it might be from a new writer.
        // The window re-initializes to accommodate.
        let mut window = SeqWindow::new();
        assert_eq!(window.map(50), Some(0));
        // Lower seq triggers re-init (possible new writer)
        assert_eq!(window.map(49), Some(0));
    }

    #[test]
    fn seq_window_handles_large_stride() {
        let mut window = SeqWindow::new();
        let base = 1u64 << 32;
        let second = 2 * base;
        let third = 3 * base;

        // First sequence initializes base at 2^32 -> local 0
        assert_eq!(window.map(base), Some(0));
        // Second sequence sets stride = 2^32 -> local 1
        assert_eq!(window.map(second), Some(1));
        // Third sequence uses same stride -> local 2
        assert_eq!(window.map(third), Some(2));
    }

    #[test]
    fn seq_window_rejects_non_aligned_large_seq() {
        let mut window = SeqWindow::new();
        let base = 1u64 << 32;
        let stride = 1u64 << 32;

        // Initialize base
        assert_eq!(window.map(base), Some(0));
        // Establish stride
        assert_eq!(window.map(base + stride), Some(1));
        // Non-aligned sequence should be dropped
        assert_eq!(window.map(base + stride + 1), None);
    }
}

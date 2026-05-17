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
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

use crate::engine::subscriber::DisposeKind;

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
    pub(super) _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> ReaderSubscriber<T> {
    #[allow(clippy::too_many_arguments)]
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
            _phantom: core::marker::PhantomData,
        }
    }

    /// Run the decode -> filter -> listener -> re-encode -> slab -> ring
    /// pipeline for a single sample. Returns silently on any failure (the
    /// path was already best-effort for malformed payloads / pool
    /// exhaustion; preserving that behaviour avoids interop regressions).
    fn process_admitted(&self, remote_seq: u64, data: &[u8], version: crate::dds::CdrVersion) {
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

        let seq = {
            let mut guard = match self.seq_window.lock() {
                Ok(lock) => lock,
                Err(poisoned) => {
                    log::debug!(
                        "[reader] WARNING: seq_window lock poisoned; recovering for topic='{}'",
                        self.topic
                    );
                    poisoned.into_inner()
                }
            };

            match guard.map(remote_seq) {
                Some(value) => value,
                None => {
                    slab_pool.release(handle);
                    if let Some(m) = telemetry::get_metrics_opt() {
                        m.increment_dropped(1);
                    }
                    return;
                }
            }
        };

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
    /// order) through the per-sample pipeline.
    fn deliver_released(&self, released: Vec<PendingPayload>) {
        for payload in released {
            self.process_admitted(payload.remote_seq, &payload.data, payload.version);
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
        self.process_admitted(remote_seq, data, version);
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
        self.deliver_released(released);
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
            self.deliver_released(released);
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

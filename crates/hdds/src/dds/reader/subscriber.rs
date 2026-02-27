// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Internal subscriber implementation for DataReader.
//!
//!
//! Bridges the engine's subscriber trait to the typed DataReader,
//! handling sample deserialization and duplicate detection.

use crate::core::rt;
use crate::dds::filter::FilterEvaluator;
use crate::dds::listener::DataReaderListener;
use crate::dds::{GuardCondition, StatusCondition, StatusMask, DDS};
use crate::telemetry;
use crate::telemetry::metrics::current_time_ns;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

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
    /// Optional content filter (for ContentFilteredTopic)
    pub(super) content_filter: Option<FilterEvaluator>,
    /// Optional listener for data callbacks
    pub(super) listener: Option<Arc<dyn DataReaderListener<T>>>,
    pub(super) _phantom: core::marker::PhantomData<T>,
}

impl<T: DDS> ReaderSubscriber<T> {
    pub fn new(
        topic: String,
        ring: Arc<rt::IndexRing>,
        status_condition: Arc<StatusCondition>,
        participant_guard: Option<Arc<GuardCondition>>,
        content_filter: Option<FilterEvaluator>,
        listener: Option<Arc<dyn DataReaderListener<T>>>,
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
            content_filter,
            listener,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<T: DDS> crate::engine::Subscriber for ReaderSubscriber<T> {
    fn on_data(&self, _topic: &str, remote_seq: u64, data: &[u8]) {
        let msg = match T::decode_cdr2(data) {
            Ok(m) => m,
            Err(_e) => {
                log::debug!(
                    "[READER-SUB] CDR2 decode failed for topic '{}': {:?}",
                    self.topic,
                    _e
                );
                return;
            }
        };

        // Apply content filter if present
        if let Some(ref filter) = self.content_filter {
            // Extract fields from the message for filter evaluation
            // Note: Full filtering requires DDS types to implement get_fields()
            // For now, we use a placeholder that always passes
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

        // Invoke listener callback if present
        if let Some(ref listener) = self.listener {
            listener.on_data_available(&msg);
        }

        // Buffer sized to fit max RTPS DATA submessage payload (~64KB)
        let mut tmp_buf = vec![0u8; 65536];
        let serialized_len = match msg.encode_cdr2(&mut tmp_buf) {
            Ok(len) => len,
            Err(_e) => {
                log::debug!("[READER-SUB] re-encode failed: {:?}", _e);
                return;
            }
        };

        let slab_pool = rt::get_slab_pool();
        let (handle, slab_buf) = match slab_pool.reserve(serialized_len) {
            Some((h, b)) => (h, b),
            None => {
                log::debug!("[READER-SUB] slab_pool exhausted");
                return;
            }
        };

        slab_buf[..serialized_len].copy_from_slice(&tmp_buf[..serialized_len]);
        slab_pool.commit(handle, serialized_len);

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
            timestamp_ns: current_time_ns(),
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

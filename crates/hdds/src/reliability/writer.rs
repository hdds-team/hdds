// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Writer-side reliability protocol handlers
//!
//! Consolidates all TX (transmit) logic for Reliable QoS:
//! - HeartbeatTx: Periodic heartbeat transmission with jitter
//! - GapTx: GAP message generation for lost sequences
//! - InfoTsTx: Timestamp injection for DATA submessages
//! - InfoDstTx: Destination GUID prefix for targeted delivery
//! - WriterRetransmitHandler: NACK processing and retransmission

use std::convert::TryFrom;
use std::time::{Duration, Instant};

use super::messages::{
    EntityId, GapMsg, GuidPrefix, HeartbeatMsg, InfoDstMsg, InfoTsMsg, NackMsg, SequenceNumberSet,
    ENTITYID_UNKNOWN, GUID_PREFIX_LEN,
};
use super::{CachedChange, HistoryCache, ReliableMetrics, RtpsRange};

// ============================================================================
// HEARTBEAT TX
// ============================================================================

/// Default heartbeat period (milliseconds).
pub const DEFAULT_PERIOD_MS: u32 = 100;
/// Default jitter percentage (0-100).
pub const DEFAULT_JITTER_PCT: u8 = 10;

/// Heartbeat transmitter (writer-side).
#[derive(Debug)]
pub struct HeartbeatTx {
    next_deadline: Instant,
    period: Duration,
    jitter_pct: u8,
    count: u32,
}

impl HeartbeatTx {
    /// Create a transmitter with the default period (100 ms +/- 10%).
    #[must_use]
    pub fn new() -> Self {
        Self::with_period_ms(DEFAULT_PERIOD_MS, DEFAULT_JITTER_PCT)
    }

    /// Create a transmitter with custom period and jitter.
    #[must_use]
    pub fn with_period_ms(period_ms: u32, jitter_pct: u8) -> Self {
        let period = Duration::from_millis(period_ms as u64);
        let next_deadline = Instant::now() + Self::apply_jitter(period, jitter_pct);

        Self {
            next_deadline,
            period,
            jitter_pct,
            count: 0,
        }
    }

    /// Next time the heartbeat should be sent.
    #[must_use]
    pub fn next_deadline(&self) -> Instant {
        self.next_deadline
    }

    /// Build a heartbeat message and schedule the next send deadline.
    pub fn build_heartbeat(&mut self, first_seq: u64, last_seq: u64) -> HeartbeatMsg {
        let hb = HeartbeatMsg::new(first_seq, last_seq, self.count);
        self.count = self.count.wrapping_add(1);
        self.next_deadline = Instant::now() + Self::apply_jitter(self.period, self.jitter_pct);
        hb
    }

    /// Monotonic heartbeat counter.
    #[must_use]
    pub fn count(&self) -> u32 {
        self.count
    }

    fn apply_jitter(period: Duration, jitter_pct: u8) -> Duration {
        if jitter_pct == 0 {
            return period;
        }

        let now_ns = Instant::now().elapsed().as_nanos();
        let jitter_seed = u32::try_from(now_ns % 200).unwrap_or(0);
        let jitter_factor = i32::try_from(jitter_seed).unwrap_or(0) - 100; // -100..=100

        let base_ms = i128::try_from(period.as_millis()).unwrap_or(i128::MAX);
        let jitter_ms = base_ms
            .saturating_mul(i128::from(jitter_pct))
            .saturating_mul(i128::from(jitter_factor))
            / 10_000;

        let adjusted_ms = base_ms.saturating_add(jitter_ms).max(1);
        let millis_u128 = u128::try_from(adjusted_ms).unwrap_or(u128::from(u64::MAX));
        let clamped_ms = millis_u128.min(u128::from(u64::MAX));

        Duration::from_millis(clamped_ms as u64)
    }
}

impl Default for HeartbeatTx {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// GAP TX
// ============================================================================

/// GAP transmitter (writer-side).
#[derive(Debug)]
pub struct GapTx {
    gap_count: u64,
    total_lost: u64,
    reader_id: EntityId,
    writer_id: EntityId,
}

impl GapTx {
    /// Create a transmitter whose GAPs name no reader and no writer:
    /// ENTITYID_UNKNOWN on both sides until `set_entity_ids`. A GAP with
    /// readerId ENTITYID_UNKNOWN addresses every reader of the receiving
    /// participant matched with the writer (RTPS 2.5 9.3.1.2).
    #[must_use]
    pub fn new() -> Self {
        Self::with_entity_ids(ENTITYID_UNKNOWN, ENTITYID_UNKNOWN)
    }

    /// Create transmitter with explicit reader/writer entity IDs.
    #[must_use]
    pub fn with_entity_ids(reader_id: EntityId, writer_id: EntityId) -> Self {
        Self {
            gap_count: 0,
            total_lost: 0,
            reader_id,
            writer_id,
        }
    }

    /// Update entity identifiers (fluent builder style).
    pub fn set_entity_ids(&mut self, reader_id: EntityId, writer_id: EntityId) {
        self.reader_id = reader_id;
        self.writer_id = writer_id;
    }

    /// Build GAP messages for the provided range.
    pub fn build_gap(&mut self, range: RtpsRange) -> Vec<GapMsg> {
        if range.start >= range.end {
            return Vec::new();
        }

        let mut messages = Vec::new();
        let mut cursor = range.start;

        while cursor < range.end {
            let chunk_end = (cursor + u64::from(SequenceNumberSet::MAX_BITS) + 1).min(range.end);
            if let Some(msg) = GapMsg::contiguous(
                self.reader_id,
                self.writer_id,
                RtpsRange::new(cursor, chunk_end),
            ) {
                self.gap_count += 1;
                self.total_lost += chunk_end - cursor;
                messages.push(msg);
            }
            cursor = chunk_end;
        }

        messages
    }

    /// Build GAP messages from explicit missing sequence numbers.
    ///
    /// Sequences must be sorted in ascending order.
    pub fn build_gap_from_sequences(&mut self, sequences: &[u64]) -> Vec<GapMsg> {
        if sequences.is_empty() {
            return Vec::new();
        }

        let mut messages = Vec::new();
        let mut idx = 0usize;

        while idx < sequences.len() {
            let gap_start = sequences[idx];
            let base = gap_start.saturating_add(1);
            let base_i64 = match i64::try_from(base) {
                Ok(value) => value,
                Err(_) => {
                    idx = idx.saturating_add(1);
                    continue;
                }
            };

            let max_seq = gap_start.saturating_add(u64::from(SequenceNumberSet::MAX_BITS));
            let mut extras = Vec::new();
            let mut j = idx.saturating_add(1);
            while j < sequences.len() {
                let seq = sequences[j];
                if seq > max_seq {
                    break;
                }
                if seq > gap_start {
                    extras.push(seq);
                }
                j += 1;
            }

            if let Some(gap_list) = SequenceNumberSet::from_sequences(base_i64, &extras) {
                self.gap_count = self.gap_count.saturating_add(1);
                let lost = 1u64.saturating_add(u64::try_from(extras.len()).unwrap_or(0));
                self.total_lost = self.total_lost.saturating_add(lost);
                messages.push(GapMsg::new(
                    self.reader_id,
                    self.writer_id,
                    gap_start,
                    gap_list,
                ));
            }

            idx = j;
        }

        messages
    }

    /// Total GAP messages emitted.
    #[must_use]
    pub fn gap_count(&self) -> u64 {
        self.gap_count
    }

    /// Total sequence numbers marked as lost.
    #[must_use]
    pub fn total_lost(&self) -> u64 {
        self.total_lost
    }
}

impl Default for GapTx {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// INFO_TS TX
// ============================================================================

/// INFO_TS transmitter (writer-side)
#[derive(Debug, Default)]
pub struct InfoTsTx {
    ts_count: u64,
}

impl InfoTsTx {
    pub fn new() -> Self {
        Self { ts_count: 0 }
    }

    pub fn build_timestamp(&mut self) -> InfoTsMsg {
        self.ts_count += 1;
        InfoTsMsg::now()
    }

    pub fn build_timestamp_at(&mut self, nanos: u64) -> InfoTsMsg {
        self.ts_count += 1;
        InfoTsMsg::from_nanos(nanos)
    }

    #[must_use]
    pub fn ts_count(&self) -> u64 {
        self.ts_count
    }
}

// ============================================================================
// INFO_DST TX
// ============================================================================

/// INFO_DST transmitter (writer-side).
#[derive(Debug, Default)]
pub struct InfoDstTx {
    dst_count: u64,
    last_prefix: Option<GuidPrefix>,
}

impl InfoDstTx {
    #[must_use]
    pub fn new() -> Self {
        Self {
            dst_count: 0,
            last_prefix: None,
        }
    }

    /// Build INFO_DST message for specific destination.
    pub fn build_info_dst(&mut self, guid_prefix: GuidPrefix) -> InfoDstMsg {
        self.dst_count += 1;
        self.last_prefix = Some(guid_prefix);
        InfoDstMsg::new(guid_prefix)
    }

    /// Build broadcast INFO_DST (all zeros).
    pub fn build_broadcast(&mut self) -> InfoDstMsg {
        self.dst_count += 1;
        self.last_prefix = Some([0; GUID_PREFIX_LEN]);
        InfoDstMsg::broadcast()
    }

    #[must_use]
    pub fn dst_count(&self) -> u64 {
        self.dst_count
    }

    #[must_use]
    pub fn last_prefix(&self) -> Option<&GuidPrefix> {
        self.last_prefix.as_ref()
    }
}

// ============================================================================
// WRITER RETRANSMIT HANDLER
// ============================================================================

/// Classify a NACK'd, cache-miss sequence number as genuinely evicted
/// (GAP it) or not-yet-written (silently skip it).
///
/// `newest_ever_inserted` is the writer's SN high-water mark
/// (`HistoryCache::highest_inserted()`), kept apart from the entries. It is
/// not `newest_seq()`, the back of the ring: once the entries themselves go
/// (acknowledged changes freed by a VOLATILE writer, a per-instance
/// KEEP_LAST replacing the newest one), the back is older than the highest
/// SN ever written, or absent, and a request for a freed change would read
/// as "not written yet": neither the data nor a GAP, so the reader would
/// ask forever.
///
/// - `seq <= newest_ever_inserted`: the writer's SN space has already
///   passed this sequence number and it is no longer in cache ->
///   genuinely evicted (aged out of the ring buffer, or LIFESPAN-pruned,
///   or simply never produced despite an allocated SN e.g. a dropped
///   write). The reader will never receive it any other way, so GAP it.
/// - `seq > newest_ever_inserted` (including the empty-cache case,
///   `None`): the writer has not assigned this SN yet. A
///   preemptive/speculative NACK (a reader probing a wide bitmap
///   before any HEARTBEAT/first sample) can name sequence numbers ahead
///   of the writer's actual progress. GAPing those would tell the
///   reader they will NEVER exist, which makes it discard the real
///   DATA/DATA_FRAG once the writer actually produces them later.
///   "Not yet written" is not the same as "lost" -- skip it silently;
///   normal delivery (or a later, honest NACK once the SN is truly
///   evicted) handles it.
#[must_use]
fn is_genuinely_evicted(seq: u64, newest_ever_inserted: Option<u64>) -> bool {
    matches!(newest_ever_inserted, Some(newest) if seq <= newest)
}

/// Writer-side retransmission handler.
pub struct WriterRetransmitHandler<'a> {
    cache: &'a HistoryCache,
    gap_tx: &'a mut GapTx,
    metrics: &'a ReliableMetrics,
}

impl<'a> WriterRetransmitHandler<'a> {
    /// Create new writer retransmission handler.
    pub fn new(
        cache: &'a HistoryCache,
        gap_tx: &'a mut GapTx,
        metrics: &'a ReliableMetrics,
    ) -> Self {
        Self {
            cache,
            gap_tx,
            metrics,
        }
    }

    /// Process a NACK message and return both retransmits and GAP notifications.
    ///
    /// # NACK Processing State Machine
    ///
    /// For each sequence number range requested in the NACK:
    /// 1. **Cache Hit** -> Add the [`CachedChange`] (payload + typed
    ///    metadata, snapshotted under ONE cache lookup) to retransmits,
    ///    increment metrics
    /// 2. **Cache Miss** -> Collect into `missing` list for GAP generation
    ///
    /// After processing each range, if any sequences were missing from the cache,
    /// we generate GAP messages to inform the reader those samples are irretrievably
    /// lost (expired from history cache or never existed).
    ///
    /// # Why Both Retransmits AND Gaps?
    ///
    /// A single NACK may request sequences in mixed states:
    /// - Some still available in cache -> retransmit them
    /// - Some already evicted (history depth exceeded) -> send GAP
    ///
    /// The reader needs BOTH responses to maintain correct state:
    /// - Retransmits fill actual data gaps
    /// - GAPs allow the reader to advance its expected sequence number without
    ///   waiting forever for samples that will never arrive
    ///
    /// # Cache Lookup and Range Iteration
    ///
    /// We iterate `range.start..range.end` (exclusive end) to match RTPS sequence
    /// number semantics. Each lookup in `self.cache` is O(1) for the typical
    /// ring-buffer implementation. Missing sequences are batched per-range to
    /// minimize the number of GAP submessages generated.
    ///
    /// # Atomic payload + metadata snapshot
    ///
    /// Each cache hit is materialized via [`HistoryCache::get_change`],
    /// which copies the payload AND its [`super::ChangeMetadata`] under a
    /// single ring-lock acquisition. The packet-building consumer can
    /// therefore never pair a payload with metadata from a different
    /// cache state (e.g. after a concurrent eviction between two
    /// separate lookups).
    pub fn on_nack(&mut self, nack: &NackMsg) -> (Vec<CachedChange>, Vec<GapMsg>) {
        let mut retransmits = Vec::new();
        let mut gaps = Vec::new();

        // Snapshot once: the highest SN the writer has EVER inserted. One
        // snapshot keeps the missing-vs-not-yet-written classification
        // consistent for the whole NACK even if the writer inserts
        // concurrently on another thread mid-call. SNs start at 1, so 0
        // means nothing was ever inserted.
        let newest_ever_inserted = Some(self.cache.highest_inserted()).filter(|&seq| seq > 0);

        // Process each requested sequence range from the NACK
        for range in &nack.ranges {
            let mut missing = Vec::new();

            // Attempt to retrieve each sequence from the writer's history cache
            for seq in range.start..range.end {
                if let Some(change) = self.cache.get_change(seq) {
                    // Cache hit: queue the atomic payload+metadata snapshot
                    // for retransmission
                    retransmits.push(change);
                    self.metrics.increment_retransmit_sent(1);
                } else if is_genuinely_evicted(seq, newest_ever_inserted) {
                    // Cache miss AND the writer's SN space has already
                    // passed this seq: genuinely evicted/lost, unless a
                    // change at or below it is taken and not journaled yet
                    // (`HistoryCache::taking`): then nothing, the reader asks
                    // again. Looked up again once no such change is in
                    // flight: one journaled since the miss is repaired.
                    if self.cache.in_flight_at_or_below(seq) {
                        continue;
                    }
                    if let Some(change) = self.cache.get_change(seq) {
                        retransmits.push(change);
                        self.metrics.increment_retransmit_sent(1);
                    } else {
                        missing.push(seq);
                    }
                }
                // else: not yet written (seq is ahead of the writer's
                // progress, or the cache has never held anything at
                // all) -- silently skip, see `is_genuinely_evicted`.
            }

            // Generate GAP messages for sequences we cannot retransmit
            if !missing.is_empty() {
                let gap_msgs = self.gap_tx.build_gap_from_sequences(&missing);
                for gap in &gap_msgs {
                    let gap_size = 1u64.saturating_add(gap.gap_list().iter().count() as u64);
                    self.metrics.record_gap(gap_size);
                }
                gaps.extend(gap_msgs);
            }
        }

        (retransmits, gaps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rt::slabpool::SlabPool;
    use crate::qos::History;
    use std::sync::Arc;

    // -- is_genuinely_evicted: pure classification decision --

    #[test]
    fn is_genuinely_evicted_empty_cache_never_evicted() {
        // Nothing has ever been inserted: every seq is "not yet
        // written", never "evicted".
        assert!(!is_genuinely_evicted(1, None));
        assert!(!is_genuinely_evicted(u64::MAX, None));
    }

    #[test]
    fn is_genuinely_evicted_seq_at_or_below_newest_is_evicted() {
        assert!(is_genuinely_evicted(5, Some(10)));
        assert!(is_genuinely_evicted(1, Some(10)));
        // Boundary: seq == newest is still classified evicted (a
        // concurrent evict landing between the cache miss and this
        // snapshot is the only realistic way to reach this cell).
        assert!(is_genuinely_evicted(10, Some(10)));
    }

    #[test]
    fn is_genuinely_evicted_seq_ahead_of_newest_is_not_yet_written() {
        assert!(!is_genuinely_evicted(11, Some(10)));
        assert!(!is_genuinely_evicted(1000, Some(10)));
    }

    // -- on_nack: end-to-end coverage --

    fn test_cache() -> HistoryCache {
        let pool = Arc::new(SlabPool::new());
        HistoryCache::new_with_limits(pool, 100, 64 * 1024, History::KeepLast(100))
    }

    #[test]
    fn on_nack_never_gaps_a_range_before_any_sample_was_written() {
        // A reader may send a preemptive/speculative ACKNACK (wide bitmap)
        // before the writer produces its first sample or sends any
        // HEARTBEAT. Answering every requested SN as a cache miss with a GAP
        // would tell the reader the whole range will NEVER exist (RTPS GAP
        // semantics: irrelevant to the reader), so it would discard the real
        // DATA_FRAGs once the writer actually caught up and the subscriber
        // would receive nothing.
        let cache = test_cache();
        let metrics = ReliableMetrics::new();
        let mut gap_tx = GapTx::new();
        let mut handler = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics);

        let nack = NackMsg::from_ranges(std::iter::once(1..51));
        let (retransmits, gaps) = handler.on_nack(&nack);

        assert!(
            retransmits.is_empty(),
            "nothing was ever written, nothing to retransmit"
        );
        assert!(
            gaps.is_empty(),
            "not-yet-written sequence numbers must never be GAPed"
        );
    }

    /// A change the writer no longer holds, once every entry has left the
    /// history, is still one it wrote: GAP it. `newest_seq()` (the back of
    /// the ring) answers `None` there, and the request would read as "not
    /// written yet": no data, no GAP, and the reader would ask forever.
    #[test]
    fn on_nack_gaps_a_change_freed_with_the_whole_history() {
        let cache = test_cache();
        for seq in 1..=3u64 {
            cache.insert(seq, b"payload").expect("cache insert");
        }
        while cache.evict_oldest().is_some() {}
        assert_eq!(cache.newest_seq(), None, "the history is empty");
        let metrics = ReliableMetrics::new();
        let mut gap_tx = GapTx::new();
        let mut handler = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics);

        let (retransmits, gaps) = handler.on_nack(&NackMsg::from_ranges(std::iter::once(2..5)));

        assert!(retransmits.is_empty());
        let gapped: Vec<u64> = gaps.iter().flat_map(|g| g.lost_sequences()).collect();
        assert_eq!(
            gapped,
            vec![2, 3],
            "written and gone: GAP; 4 is not written yet"
        );
    }

    /// A change taken and not journaled yet (`HistoryCache::taking`) while a
    /// later SN is: the reader NACKs it, and gets neither the change nor a
    /// GAP for it, which would tell it the change it is about to receive
    /// does not exist. Once journaled, it is repaired; abandoned, GAPped.
    #[test]
    fn on_nack_does_not_gap_a_change_taken_and_not_journaled_yet() {
        let cache = test_cache();
        cache.insert(1, b"one").expect("cache insert");
        let metrics = ReliableMetrics::new();
        let mut gap_tx = GapTx::new();
        let nack = || NackMsg::from_ranges(std::iter::once(2..4));
        let gapped = |gaps: &[GapMsg]| -> Vec<u64> {
            gaps.iter().flat_map(|g| g.lost_sequences()).collect()
        };

        // The writer takes 2; an end of set takes 3 and is journaled first.
        let writer = cache.taking(super::super::Producer::Writer, 2);
        cache.insert(3, b"end").expect("cache insert");
        let (retransmits, gaps) =
            WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics).on_nack(&nack());
        assert_eq!(
            retransmits.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(gapped(&gaps), Vec::<u64>::new(), "2 is in flight");

        // Journaled: repaired.
        cache.insert(2, b"two").expect("cache insert");
        drop(writer);
        let (retransmits, gaps) =
            WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics).on_nack(&nack());
        assert_eq!(
            retransmits.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(gaps.is_empty());

        // Abandoned (4 taken, 5 journaled, 4 never): GAPped once it is not
        // in flight any more.
        let writer = cache.taking(super::super::Producer::Writer, 4);
        cache.insert(5, b"end").expect("cache insert");
        let nack = NackMsg::from_ranges(std::iter::once(4..5));
        let (_, gaps) = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics).on_nack(&nack);
        assert_eq!(gapped(&gaps), Vec::<u64>::new(), "4 is in flight");
        drop(writer);
        let (_, gaps) = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics).on_nack(&nack);
        assert_eq!(gapped(&gaps), vec![4], "4 abandoned: GAP");
    }

    #[test]
    fn on_nack_still_gaps_a_genuinely_evicted_prefix() {
        // The writer has produced seqs 1..=19 into a KeepLast(5) ring,
        // so only the last 5 (15..=19) remain cached; 1..=14 are
        // genuinely evicted. A NACK for [1, 20) must GAP the evicted
        // prefix (unchanged behavior) while still retransmitting
        // whatever remains cached.
        let pool = Arc::new(SlabPool::new());
        let cache = HistoryCache::new_with_limits(pool, 5, 64 * 1024, History::KeepLast(5));
        let metrics = ReliableMetrics::new();
        let mut gap_tx = GapTx::new();

        for seq in 1..=19u64 {
            cache
                .insert(seq, format!("payload-{seq}").as_bytes())
                .expect("cache insert");
        }

        let mut handler = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics);
        let nack = NackMsg::from_ranges(std::iter::once(1..20));
        let (retransmits, gaps) = handler.on_nack(&nack);

        assert_eq!(
            retransmits.len(),
            5,
            "the 5 still-cached seqs (15..=19) must be retransmitted"
        );
        for (change, expected_seq) in retransmits.iter().zip(15u64..=19) {
            assert_eq!(change.seq, expected_seq);
            assert_eq!(
                change.payload,
                format!("payload-{expected_seq}").into_bytes(),
                "retransmitted CachedChange must carry the original payload"
            );
        }
        let total_gapped: u64 = gaps
            .iter()
            .map(|g| 1 + g.gap_list().iter().count() as u64)
            .sum();
        assert_eq!(
            total_gapped, 14,
            "the 14 genuinely evicted seqs (1..=14) must still be GAPed"
        );
    }

    #[test]
    fn on_nack_skips_only_the_not_yet_written_tail_of_a_mixed_range() {
        // Writer has produced 1..=10 (all still cached, KeepLast(100)).
        // A NACK for [1, 20) mixes a real cache-hit prefix with a
        // not-yet-written tail (11..20): the tail must be silently
        // skipped, never GAPed, while the hits still retransmit.
        let cache = test_cache();
        let metrics = ReliableMetrics::new();
        let mut gap_tx = GapTx::new();

        for seq in 1..=10u64 {
            cache
                .insert(seq, format!("payload-{seq}").as_bytes())
                .expect("cache insert");
        }

        let mut handler = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics);
        let nack = NackMsg::from_ranges(std::iter::once(1..20));
        let (retransmits, gaps) = handler.on_nack(&nack);

        assert_eq!(retransmits.len(), 10, "all 10 written seqs are cache hits");
        for (change, expected_seq) in retransmits.iter().zip(1u64..=10) {
            assert_eq!(change.seq, expected_seq);
            assert_eq!(
                change.payload,
                format!("payload-{expected_seq}").into_bytes(),
                "retransmitted CachedChange must carry the original payload"
            );
        }
        assert!(
            gaps.is_empty(),
            "the not-yet-written tail (11..20) must never be GAPed"
        );
    }

    #[test]
    fn on_nack_preserves_change_metadata_in_retransmit_result() {
        use crate::reliability::{ChangeKind, ChangeMetadata};

        // A NACK hit must return payload AND typed metadata from ONE
        // atomic cache lookup, so the packet-building consumer can
        // rebuild coherent/keyed repairs without a second (divergence-
        // prone) metadata lookup.
        let cache = test_cache();
        let metrics = ReliableMetrics::new();
        let mut gap_tx = GapTx::new();

        let key_hash = [0x5A; 16];
        cache
            .insert_coherent_with_key_hash(
                1,
                b"coherent-sample",
                0,
                Some(7),
                Some(3),
                Some(key_hash),
            )
            .expect("cache insert");
        cache.insert(2, b"plain-sample").expect("cache insert");

        let mut handler = WriterRetransmitHandler::new(&cache, &mut gap_tx, &metrics);
        let nack = NackMsg::from_ranges(std::iter::once(1..3));
        let (retransmits, gaps) = handler.on_nack(&nack);

        assert!(gaps.is_empty(), "both seqs are cache hits, no GAPs");
        assert_eq!(retransmits.len(), 2);

        assert_eq!(retransmits[0].seq, 1);
        assert_eq!(retransmits[0].payload, b"coherent-sample".to_vec());
        assert_eq!(
            retransmits[0].metadata,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(7),
                group_sn: Some(3),
                key_hash: Some(key_hash),
                ..ChangeMetadata::user_data()
            }
        );

        assert_eq!(retransmits[1].seq, 2);
        assert_eq!(retransmits[1].payload, b"plain-sample".to_vec());
        assert_eq!(retransmits[1].metadata, ChangeMetadata::user_data());
    }
}

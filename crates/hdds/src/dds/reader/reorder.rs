// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Per-writer sequence-number reorder buffer for late-joiner ordering.
//!
//! For DDS Durability kinds other than `VOLATILE` (DDS v1.4 sec. 2.2.3.4), a
//! reader that joins after the writer has started must deliver historical
//! samples in writer-sequence order, regardless of the on-wire arrival
//! order produced by the reliable retransmission flow (DDS-RTPS v2.5
//! sec. 8.4.2.2 -- the writer multicasts the current change while servicing
//! ACKNACK-requested retransmits unicast, so the late joiner observes
//! `current, current+1, ..., 1, 2, 3, ..., current-1, current+k` on the
//! wire).
//!
//! This module holds out-of-order samples in a per-writer min-heap keyed
//! on the RTPS writer sequence number and only releases them to the
//! downstream pipeline once a contiguous prefix is available. The expected
//! base sequence (`next_seq`) is seeded from the writer's first HEARTBEAT
//! (RTPS sec. 8.3.8.6: `HeartbeatSubmessage.firstSN`), which advertises the
//! oldest sample still available in the writer's history cache.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};

/// Hard cap on the number of out-of-order samples buffered per writer.
///
/// Reached only when a writer keeps producing new sequences while the
/// reader's expected base is blocked on a missing seq that has not yet
/// arrived (or never will). Hitting the cap triggers a forced drain in
/// seq order, accepting that the still-missing seqs are lost.
const MAX_PENDING_PER_WRITER: usize = 4096;

/// `n` in the running total's width, which holds any `usize` exactly.
fn wide(n: usize) -> u128 {
    u128::try_from(n).unwrap_or(u128::MAX)
}

/// Whether every held sample is below `remote_seq`.
fn state_last_below(pending: &BTreeMap<u64, PendingPayload>, remote_seq: u64) -> bool {
    pending
        .last_key_value()
        .is_none_or(|(&last, _)| last < remote_seq)
}

/// A single buffered sample, opaque to the gate.
pub struct PendingPayload {
    pub(super) order: Option<crate::engine::router::OrderedGroupChange>,
    pub(super) order_token: Option<super::wire_order::OrderToken>,
    /// The representation of the stored sample's bytes, for its ring entry.
    pub version: crate::dds::CdrVersion,
    /// Writer's RTPS sequence number for this sample, preserved so the
    /// downstream pipeline can keep seq-aware bookkeeping (NACK tracking,
    /// SeqWindow mapping) consistent after a delayed release.
    pub remote_seq: u64,
    /// Source timestamp (epoch ns) from the datagram's INFO_TS, captured at
    /// buffering time so a delayed release still expires by the writer's
    /// source time (lifespan). `None` when the datagram carried no INFO_TS
    /// -> the pipeline falls back to reception time.
    pub source_ts_ns: Option<u64>,
    /// The slot this sample holds in its reader's history, taken before it
    /// was acknowledged (`None` for a reader that reserves none, and for a
    /// sample that takes its slot only at the ring push). Wherever the gate
    /// discards the payload, dropping it gives the slot back.
    pub(super) slot: Option<super::admission::HistorySlot>,
    /// The sample decoded and stored for the application before it was
    /// acknowledged: a sample travels through the gate with its storage, and
    /// leaves it as a handle, nothing allocated again. Dropping it releases
    /// its storage.
    pub(super) prepared: super::admission::Prepared,
    /// A coherent set's member's charge on its reader's staging budget
    /// (`staging_budget`), given back when the change leaves the gate
    /// (pushed for the application, or dropped). `None` for any other.
    pub(super) staged: Option<super::staging_budget::StagedCharge>,
}

impl PendingPayload {
    /// Change `remote_seq` received with no sample to deliver: it takes
    /// its turn in the gate and delivers nothing (`Prepared::Discard`, no
    /// place in the history).
    pub(super) fn nothing(remote_seq: u64) -> Self {
        Self {
            order: None,
            order_token: None,
            // Never decoded.
            version: crate::dds::CdrVersion::Xcdr2,
            remote_seq,
            source_ts_ns: None,
            slot: None,
            prepared: super::admission::Prepared::Discard,
            staged: None,
        }
    }

    /// Change `remote_seq`, a dispose or unregister of instance `key` that
    /// is a member of a coherent set: it takes its turn in the gate, and its
    /// transition is applied where the set is delivered
    /// (`admission::Prepared::Lifecycle`).
    pub(super) fn lifecycle(
        remote_seq: u64,
        key: [u8; 16],
        kind: crate::engine::subscriber::DisposeKind,
        source_ts_ns: Option<u64>,
    ) -> Self {
        Self {
            order: None,
            order_token: None,
            version: crate::dds::CdrVersion::Xcdr2,
            remote_seq,
            source_ts_ns,
            slot: None,
            prepared: super::admission::Prepared::Lifecycle { key, kind },
            staged: None,
        }
    }

    /// Tests only: change `remote_seq`, the `T` CDR-encoded in `data`
    /// (XCDR2), stored in the slab pool as the reader stores a sample it
    /// receives (behind a writer GUID prefix).
    #[cfg(test)]
    pub(crate) fn stored_for_test<T: crate::dds::DDS>(remote_seq: u64, data: &[u8]) -> Self {
        let version = crate::dds::CdrVersion::Xcdr2;
        let msg = T::decode(data, version).expect("a T");
        let mut bytes = vec![0u8; 16 + data.len() + 64];
        let len = msg.encode(&mut bytes[16..], version).expect("encode");
        bytes.truncate(16 + len);
        let (handle, _) = crate::core::rt::get_slab_pool_ref()
            .reserve_and_write(&bytes, crate::core::rt::Claim::Reader)
            .expect("slab");
        Self {
            order: None,
            order_token: None,
            version,
            remote_seq,
            source_ts_ns: None,
            slot: None,
            prepared: super::admission::Prepared::Stored(super::admission::StoredSample::new(
                handle,
                u32::try_from(bytes.len()).expect("small"),
                Box::new(msg),
            )),
            staged: None,
        }
    }
}

/// Per-writer ordering state.
#[derive(Default)]
struct WriterState {
    /// Next remote sequence number eligible for delivery.
    ///
    /// `None` until either (a) a HEARTBEAT seeds it, or (b) a writer's
    /// first DATA arrives while the reader is volatile (passthrough, kept
    /// as `None`).
    next_seq: Option<u64>,
    /// Sequences received but not yet delivered, sorted ascending.
    pending: BTreeMap<u64, PendingPayload>,
    /// True once at least one HEARTBEAT has seeded `next_seq`. Used so
    /// that subsequent HEARTBEATs do not rewind progress.
    seeded: bool,
    /// The highest sequence a GAP (or a sample-less DATA) declared above
    /// `next_seq` without the gate recording it: until `next_seq` passes
    /// it, the writer proxy may be ahead of the gate.
    passed_over: u64,
    /// For a gate seeded by the first DATA (VOLATILE, BEST_EFFORT) only:
    /// the lowest sequence this reader takes from the writer, fixed once,
    /// where it joined. The first DATA the gate takes, a GAP that seeds it,
    /// or the first staged DATA observed (`observe`), whichever comes first;
    /// a staged one counts from the start of its coherent set. Below it is
    /// history from before the join. A gate seeded by a HEARTBEAT has no
    /// such history to exclude (the writer's history is owed to the reader)
    /// and no floor.
    join_floor: Option<u64>,
    /// [`ReorderGate::places_owed`] of this state, as last counted into
    /// [`ReorderGate::owed_total`].
    owed: usize,
    /// Sequences the gate crosses when it gets there, as a received change
    /// would be, and never delivers (start -> end, exclusive; disjoint):
    /// those a GAP declared irrelevant (kept before the gate is seeded too),
    /// and those a HEARTBEAT's firstSN passed as never received while the
    /// gate waited below at a staged place (`on_heartbeat`). Either is
    /// final, as a sequence below the base is: a copy arriving later is
    /// dropped (`on_data`) and refused a place (`hold_staged`). A GAP says
    /// the writer will not send the change (RTPS v2.5 Sec.8.3.7.4, 8.4.10.4
    /// `irrelevant_change_set`); a firstSN past it says it is no longer
    /// available, and the reader reports it lost then (DDS v1.4
    /// Sec.2.2.4.1, SAMPLE_LOST, whose total_count is cumulative): delivered
    /// after all, it would have been counted lost and delivered both.
    irrelevant: BTreeMap<u64, u64>,
    /// Sequences a GAP declared filtered for this reader (its filteredCount
    /// covered the whole GAP, RTPS v2.5 Sec.8.3.8.4): changes the writer
    /// still has but that are not relevant to this reader (start -> end,
    /// exclusive; disjoint; at most `MAX_FILTERED_RANGES`, the lowest
    /// dropped first). Not part of the reader's coherent sets
    /// (`misses_for_good`).
    filtered: BTreeMap<u64, u64>,
    /// Below this exclusive bound, pruned filter history is unknown.
    filtered_history_floor: u64,
    /// Sequences at or above the base the reader received, acknowledged and
    /// staged outside the gate, a coherent set's members waiting for their
    /// set to commit (`hold_staged`), until the gate takes them
    /// (`on_staged`). "A change can only be removed when it has been
    /// acknowledged by all readers the change was sent to" (RTPS v2.5
    /// Sec.8.2.10.1): acknowledged, they leave the writer's history, and its
    /// next HEARTBEAT's firstSN lies above them. Purged so, they are not
    /// lost: the gate waits for them in their turn rather than release what
    /// follows first. DDS v1.4 Sec.2.2.3.14: the DataReader "will never see
    /// the value of a data-object change from a newer value to an order
    /// [sic] value"; Sec.2.2.3.6, ordered_access, TOPIC scope: "changes
    /// [...] made by a single DataWriter are made available to subscribers
    /// in the same order they occur".
    staged: std::collections::BTreeSet<u64>,
    /// The latest sequences handed to the gate through `on_staged` (at most
    /// `HANDED_BACK_KEPT`, the lowest dropped first): a staged change comes
    /// back once, and a second hand-back of it (its set's commit and its
    /// rejection both handing it over) delivers nothing. Below the base,
    /// `on_staged` releases a change the gate passed while it was staged;
    /// handed back twice, it was released twice.
    handed_back: std::collections::BTreeSet<u64>,
    /// For a gate seeded by the first DATA (VOLATILE) and not seeded yet:
    /// the lowest sequence of a DATA refused because it could not be
    /// authenticated yet (`ReorderGate::on_refused_unauthenticated`), or
    /// dropped before discovery held its writer
    /// (`ReorderGate::on_dropped_undiscovered`). Not a join floor: anyone
    /// can send such a DATA under the writer's GUID. The gate joins there
    /// only once an admitted change of the writer arrives at or above it
    /// (`confirm_refused`).
    unconfirmed_refused: Option<u64>,
    /// The base a DATA dropped unconfirmed seeded (`confirm_refused`).
    /// While the base stands there, the sequences below a
    /// HEARTBEAT's firstSN above it were never shown to be owed: the gate
    /// moves up to firstSN without counting them lost (`on_heartbeat`).
    hint_floor: Option<u64>,
}

/// The most sequences `WriterState::handed_back` keeps: a defence against a
/// double hand-back in close succession, not a delivery record.
const HANDED_BACK_KEPT: usize = 256;

/// The most filtered ranges `WriterState::filtered` keeps.
const MAX_FILTERED_RANGES: usize = 256;

/// The most writers discovery does not hold yet that a gate keeps a state
/// for on a DATA dropped unconfirmed alone
/// (`ReorderGate::on_dropped_undiscovered`,
/// `ReorderGate::on_refused_unauthenticated`), the oldest forgotten first.
pub(super) const UNDISCOVERED_REFUSALS_KEPT: usize = 256;

/// `[start, end)` merged into `ranges` (start -> end, exclusive, disjoint).
pub(super) fn add_range(ranges: &mut BTreeMap<u64, u64>, start: u64, end: u64) {
    if end <= start {
        return;
    }
    let (mut start, mut end) = (start, end);
    // The ranges it touches or overlaps, from the highest that starts at or
    // below its end down to the first that ends below its start: the
    // ranges are disjoint and sorted, so the walk stops there, whatever
    // lies below.
    while let Some((s, e)) = ranges
        .range(..=end)
        .next_back()
        .map(|(&s, &e)| (s, e))
        .filter(|&(_, e)| e >= start)
    {
        ranges.remove(&s);
        start = start.min(s);
        end = end.max(e);
    }
    ranges.insert(start, end);
}

/// How many sequences of `[lo, hi)` `ranges` covers.
pub(super) fn covered_in(ranges: &BTreeMap<u64, u64>, lo: u64, hi: u64) -> u64 {
    if hi <= lo {
        return 0;
    }
    let first = ranges
        .range(..lo)
        .next_back()
        .map(|(&s, _)| s)
        .unwrap_or(lo);
    ranges
        .range(first..hi)
        .map(|(&s, &e)| e.min(hi).saturating_sub(s.max(lo)))
        .sum()
}

impl WriterState {
    /// An authenticated change of the writer at `remote_seq` is about to
    /// seed this unseeded gate: a DATA refused at or below it before it
    /// could be authenticated (`unconfirmed_refused`) lies in the writer's
    /// stream as far as the gate can tell, and is owed to the reader, as a
    /// DATA refused for want of room is (`ReorderGate::on_refused`). One
    /// above it says nothing, and is forgotten.
    fn confirm_refused(&mut self, remote_seq: u64) {
        let Some(refused) = self.unconfirmed_refused.take() else {
            return;
        };
        if self.next_seq.is_some()
            || refused > remote_seq
            || self.join_floor.is_some_and(|floor| refused < floor)
        {
            return;
        }
        self.next_seq = Some(refused);
        self.seeded = true;
        self.join_floor.get_or_insert(refused);
        self.hint_floor = Some(refused);
    }

    /// Whether the base still stands where a DATA dropped unconfirmed
    /// seeded it (`hint_floor`): nothing has passed it since.
    fn at_hint_floor(&self) -> bool {
        self.hint_floor.is_some() && self.hint_floor == self.next_seq
    }

    /// Whether this state holds nothing but a DATA dropped unconfirmed
    /// (`unconfirmed_refused`): nothing received, staged, seeded or
    /// declared.
    fn holds_only_a_refusal(&self) -> bool {
        self.next_seq.is_none()
            && !self.seeded
            && self.pending.is_empty()
            && self.passed_over == 0
            && self.join_floor.is_none()
            && self.owed == 0
            && self.irrelevant.is_empty()
            && self.filtered.is_empty()
            && self.filtered_history_floor == 0
            && self.staged.is_empty()
            && self.handed_back.is_empty()
    }

    /// Record `[start, end)` as declared irrelevant.
    fn add_irrelevant(&mut self, start: u64, end: u64) {
        add_range(&mut self.irrelevant, start, end);
    }

    /// `seq` received before the gate recorded it as irrelevant after all
    /// (a change staged before a GAP's step that its `keep` missed, handed
    /// back through `on_staged`): no longer recorded so (the range that
    /// holds it, if any, split around it).
    fn received_after_all(&mut self, seq: u64) {
        if self.irrelevant.is_empty() {
            return;
        }
        let Some((start, end)) = self
            .irrelevant
            .range(..=seq)
            .next_back()
            .map(|(&s, &e)| (s, e))
            .filter(|&(_, e)| e > seq)
        else {
            return;
        };
        self.irrelevant.remove(&start);
        if start < seq {
            self.irrelevant.insert(start, seq);
        }
        let after = seq.saturating_add(1);
        if after < end {
            self.irrelevant.insert(after, end);
        }
    }

    /// Record `[start, end)` as declared irrelevant, but `keep`.
    fn add_irrelevant_except(
        &mut self,
        start: u64,
        end: u64,
        keep: &std::collections::BTreeSet<u64>,
    ) {
        let mut at = start;
        for &held in keep.range(start..end) {
            self.add_irrelevant(at, held);
            at = held.saturating_add(1);
        }
        self.add_irrelevant(at, end);
    }

    /// How many sequences of `[lo, hi)` were declared irrelevant.
    fn irrelevant_in(&self, lo: u64, hi: u64) -> u64 {
        covered_in(&self.irrelevant, lo, hi)
    }

    /// How many sequences of `[lo, hi)` were declared irrelevant and not
    /// filtered.
    fn unfiltered_irrelevant_in(&self, lo: u64, hi: u64) -> u64 {
        if hi <= lo || self.irrelevant.is_empty() {
            return 0;
        }
        let first = self
            .irrelevant
            .range(..lo)
            .next_back()
            .map(|(&s, _)| s)
            .unwrap_or(lo);
        self.irrelevant
            .range(first..hi)
            .map(|(&s, &e)| {
                let (s, e) = (s.max(lo), e.min(hi));
                e.saturating_sub(s)
                    .saturating_sub(covered_in(&self.filtered, s, e))
            })
            .sum()
    }

    /// Whether `seq` was declared irrelevant.
    fn is_irrelevant(&self, seq: u64) -> bool {
        !self.irrelevant.is_empty()
            && self
                .irrelevant
                .range(..=seq)
                .next_back()
                .is_some_and(|(_, &e)| e > seq)
    }
}

/// Per-reader gate that performs per-writer in-order delivery for
/// non-volatile durability.
///
/// `enabled` reflects the reader's `Durability` choice -- when `false`
/// (Volatile), all calls fall through immediately and no buffering
/// occurs.
pub struct ReorderGate {
    enabled: bool,
    seed_on_first_data: bool,
    /// A BEST_EFFORT reader's gate: RTPS 2.5 8.4.12.1, see
    /// [`new_best_effort`](Self::new_best_effort).
    best_effort: bool,
    writers: HashMap<[u8; 16], WriterState>,
    /// The sum of every writer's `owed`, kept as each writer's state moves
    /// (see [`settle_owed`](Self::settle_owed)): what
    /// [`places_owed_except`](Self::places_owed_except) asks per admission
    /// is then O(1), not a pass over every writer under the gate's lock.
    /// Wide enough that the sum of `usize` terms never saturates, so taking
    /// one term back out is exact.
    owed_total: u128,
    /// Samples released and not yet delivered, per writer, in the order
    /// they were released. Filled under the gate's lock by the thread that
    /// releases them, emptied under the writer's delivery lock: a thread
    /// that released first may reach the delivery lock last, and delivery
    /// follows the order samples left the gate in, not that one.
    ready: HashMap<[u8; 16], Vec<PendingPayload>>,
    /// Writers discovery did not hold when the gate created their state
    /// for a DATA dropped unconfirmed, oldest first, at most
    /// `UNDISCOVERED_REFUSALS_KEPT`: a GUID nobody announced never departs,
    /// so its state is forgotten here instead (`file_unconfirmed`).
    undiscovered_refusals: std::collections::VecDeque<[u8; 16]>,
}

impl ReorderGate {
    /// Queue `released` for delivery behind what `writer_key`'s gate
    /// released before; the caller then drains the queue (see
    /// `take_ready`).
    pub fn hand_over(&mut self, writer_key: [u8; 16], released: Vec<PendingPayload>) {
        if released.is_empty() {
            return;
        }
        match self.ready.entry(writer_key) {
            Entry::Occupied(mut queued) => queued.get_mut().extend(released),
            Entry::Vacant(empty) => {
                empty.insert(released);
            }
        }
    }

    /// Take what is queued for delivery for `writer_key`, in release order.
    /// Only under the writer's delivery lock (`_delivering`): what one take
    /// returns is delivered before what the next take returns.
    pub fn take_ready(
        &mut self,
        writer_key: &[u8; 16],
        _delivering: &std::sync::MutexGuard<'_, ()>,
    ) -> Vec<PendingPayload> {
        if self.ready.is_empty() {
            return Vec::new();
        }
        self.ready.remove(writer_key).unwrap_or_default()
    }

    /// How many samples wait in `writer_key`'s queue.
    #[cfg(test)]
    pub fn queued(&self, writer_key: &[u8; 16]) -> usize {
        self.ready.get(writer_key).map_or(0, Vec::len)
    }

    /// Tests only: how many writers the gate keeps a state for.
    #[cfg(test)]
    pub fn writer_count(&self) -> usize {
        self.writers.len()
    }

    /// Tests only: how many changes of `writer_key` the gate holds above a
    /// gap.
    #[cfg(test)]
    pub fn held(&self, writer_key: &[u8; 16]) -> usize {
        self.writers.get(writer_key).map_or(0, |w| w.pending.len())
    }

    /// Take out of what the gate holds for `writer_key` above a gap every
    /// change `pick` chooses, each left in its place as a change that
    /// delivers nothing (`PendingPayload::nothing`): the members of a
    /// coherent set rejected after it committed
    /// (`ReaderSubscriber::reject_staged_set`). Returned, to be dropped with
    /// the gate's lock released (their storage, places and charges go
    /// back then).
    pub fn strip_held(
        &mut self,
        writer_key: &[u8; 16],
        mut pick: impl FnMut(&PendingPayload) -> bool,
    ) -> Vec<PendingPayload> {
        let Some(state) = self.writers.get_mut(writer_key) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (&seq, payload) in &mut state.pending {
            if pick(payload) {
                out.push(std::mem::replace(payload, PendingPayload::nothing(seq)));
            }
        }
        out
    }

    /// Current gate position for a writer: the next sequence number the
    /// gate is waiting for, `None` while unseeded (or unknown writer).
    pub fn next_seq(&self, writer_key: &[u8; 16]) -> Option<u64> {
        self.writers.get(writer_key).and_then(|w| w.next_seq)
    }

    /// Whether `on_data` would hold this sample, waiting for an earlier
    /// sequence, rather than release it now or drop it.
    pub fn would_hold(&self, writer_key: &[u8; 16], remote_seq: u64) -> bool {
        if !self.enabled || self.best_effort {
            return false;
        }
        match self.next_seq(writer_key) {
            None => !self.seed_on_first_data,
            Some(next) => remote_seq > next,
        }
    }

    /// Whether an arriving sample was retained above a gap by `on_data`.
    /// A stale or irrelevant change is not kept, even when it was prepared.
    pub fn holds_sample(&self, writer_key: &[u8; 16], remote_seq: u64) -> bool {
        self.writers
            .get(writer_key)
            .is_some_and(|state| state.pending.contains_key(&remote_seq))
    }

    /// Whether the gate is at its bound for this writer and would have to
    /// hold `remote_seq` too: then the sample must be refused before it is
    /// acknowledged, and `on_data` never reaches the forced progress that
    /// gives up the gap below.
    pub fn holds_no_more(&self, writer_key: &[u8; 16], remote_seq: u64) -> bool {
        self.would_hold(writer_key, remote_seq)
            && self
                .writers
                .get(writer_key)
                .is_some_and(|state| state.pending.len() >= MAX_PENDING_PER_WRITER)
    }

    /// Whether the writer proxy may be ahead of the gate for `writer_key`:
    /// the gate holds samples waiting below them, or passed over a GAP or a
    /// sample-less DATA it did not record and has not reached yet.
    pub fn may_trail_proxy(&self, writer_key: &[u8; 16]) -> bool {
        self.writers.get(writer_key).is_some_and(|state| {
            !state.pending.is_empty()
                || state.next_seq.is_some_and(|next| next <= state.passed_over)
        })
    }

    /// The reader's WriterProxy awaits nothing up to `settled`: every
    /// sequence up to it was received, declared irrelevant, or is no longer
    /// available. A gate still waiting below it waits for what will not
    /// come: a GAP or a sample-less DATA above the base, which the gate
    /// does not record. Move the base past `settled`, releasing what it
    /// holds there, in order. The proxy only counts what reached this
    /// reader, so nothing it waits for is skipped.
    pub fn catch_up(&mut self, writer_key: [u8; 16], settled: u64) -> Vec<PendingPayload> {
        let out = self.catch_up_unsettled(writer_key, settled);
        self.settle_owed(&writer_key);
        out
    }

    fn catch_up_unsettled(&mut self, writer_key: [u8; 16], settled: u64) -> Vec<PendingPayload> {
        if !self.enabled || self.best_effort {
            return Vec::new();
        }
        let Some(state) = self.writers.get_mut(&writer_key) else {
            return Vec::new();
        };
        if state.next_seq.is_none_or(|next| next > settled) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let received: Vec<u64> = state.pending.range(..=settled).map(|(k, _)| *k).collect();
        for k in received {
            if let Some(payload) = state.pending.remove(&k) {
                out.push(payload);
            }
        }
        state.next_seq = Some(settled.saturating_add(1));
        out.append(&mut Self::drain_contiguous(state));
        out
    }

    /// How many places in its reader's history a sample must leave free if
    /// the gate is to hold it: one per earlier sequence still awaited (not
    /// released, not held), so that the gap can fill without the held
    /// samples taking its room. `Some(0)` for a sample the gate would not
    /// hold.
    ///
    /// `None` when the gate would hold the sample but cannot tell how large
    /// the gap below it is: before the writer's first HEARTBEAT the base is
    /// unknown. A reader with a bounded history then holds it keeping one
    /// place free, the least the gap needs to fill as the application
    /// takes (see `ReaderSubscriber::deliver_sample`).
    ///
    /// The count grows with the distance to the awaited sequence, which is
    /// not bounded: a gap wider than the history refuses every sample above
    /// it until the gap fills. Counting the held samples below `remote_seq`
    /// is O(log n) when the sample arrives above every held one (a live
    /// stream above a gap), linear in the held samples otherwise.
    pub fn places_to_keep(&self, writer_key: &[u8; 16], remote_seq: u64) -> Option<usize> {
        if !self.would_hold(writer_key, remote_seq) {
            return Some(0);
        }
        let (state, next) = self
            .writers
            .get(writer_key)
            .and_then(|state| Some((state, state.next_seq?)))?;
        let span = remote_seq.saturating_sub(next);
        let held = if state_last_below(&state.pending, remote_seq) {
            state.pending.len()
        } else {
            state.pending.range(next..remote_seq).count()
        };
        let held = u64::try_from(held)
            .unwrap_or(span)
            .saturating_add(state.irrelevant_in(next, remote_seq));
        Some(usize::try_from(span.saturating_sub(held)).unwrap_or(usize::MAX))
    }

    /// The places the samples this gate holds for writers other than
    /// `writer_key` keep free in their reader's history: for each such
    /// writer, the sequences it still awaits below the highest one held.
    /// Those places are the other writers' gaps', whichever writer asks:
    /// a writer that took them would leave a gap unfilled, its held samples
    /// unreleasable, and its stream stopped until the taker's samples are
    /// taken, every time (see `ReaderSubscriber::deliver_sample`).
    ///
    /// O(1): the running total less the asking writer's own term, and
    /// nothing to look up while no writer has a gap.
    pub fn places_owed_except(&self, writer_key: &[u8; 16]) -> usize {
        // No gap open anywhere, the common case: no lookup.
        if self.owed_total == 0 {
            return 0;
        }
        let own = self.writers.get(writer_key).map_or(0, |state| state.owed);
        let others = self.owed_total - wide(own);
        usize::try_from(others).unwrap_or(usize::MAX)
    }

    /// Whether `writer_key`'s gate holds samples above sequences it still
    /// awaits: a gap whose places are owed.
    pub fn has_gap(&self, writer_key: &[u8; 16]) -> bool {
        self.owed_total != 0
            && self
                .writers
                .get(writer_key)
                .is_some_and(|state| state.owed > 0)
    }

    /// Whether `remote_seq` is one of the sequences `writer_key`'s gate
    /// awaits below the highest it holds: one of the places it owes.
    pub fn awaits(&self, writer_key: &[u8; 16], remote_seq: u64) -> bool {
        self.writers.get(writer_key).is_some_and(|state| {
            let (Some(next), Some((&top, _))) = (state.next_seq, state.pending.last_key_value())
            else {
                return false;
            };
            next <= remote_seq
                && remote_seq < top
                && !state.pending.contains_key(&remote_seq)
                && !state.is_irrelevant(remote_seq)
        })
    }

    /// The places every writer's gap needs, for a sample that comes from
    /// none of them.
    pub fn places_owed_by_all(&self) -> usize {
        usize::try_from(self.owed_total).unwrap_or(usize::MAX)
    }

    /// Count `writer_key`'s state, as it is now, into the running total,
    /// in place of what was counted for it before. Called by every method
    /// that moves a writer's state, once it is done (a writer forgotten
    /// counts nothing).
    fn settle_owed(&mut self, writer_key: &[u8; 16]) {
        if let Some(state) = self.writers.get_mut(writer_key) {
            let owed = Self::places_owed(state);
            self.owed_total = self.owed_total - wide(state.owed) + wide(owed);
            state.owed = owed;
        }
    }

    /// The sequences `state` awaits below the highest sample it holds.
    fn places_owed(state: &WriterState) -> usize {
        let (Some(next), Some((&top, _))) = (state.next_seq, state.pending.last_key_value()) else {
            return 0;
        };
        let span = top.saturating_add(1).saturating_sub(next);
        let held = u64::try_from(state.pending.len())
            .unwrap_or(span)
            .saturating_add(state.irrelevant_in(next, top.saturating_add(1)));
        usize::try_from(span.saturating_sub(held)).unwrap_or(usize::MAX)
    }

    /// Create a gate. Pass `enabled = false` for Volatile readers to
    /// keep the gate in passthrough mode.
    pub fn new(enabled: bool, seed_on_first_data: bool) -> Self {
        Self {
            enabled,
            seed_on_first_data,
            best_effort: false,
            writers: HashMap::new(),
            owed_total: 0,
            ready: HashMap::new(),
            undiscovered_refusals: std::collections::VecDeque::new(),
        }
    }

    /// The gate of a BEST_EFFORT reader, whatever its durability. RTPS 2.5
    /// 8.4.12.1 (Best-Effort StatefulReader, transition T2): a change is
    /// accepted when its sequence number is STRICTLY greater than the
    /// highest one received from that writer, the skipped numbers are lost,
    /// and anything older is discarded - "This ensures that there are no
    /// duplicate changes and no out-of-order changes". There is no
    /// HEARTBEAT nor GAP transition: a best-effort reader never waits.
    ///
    /// A best-effort + TRANSIENT_LOCAL reader used to get the reliable
    /// gate, seeded only by a HEARTBEAT: a best-effort writer sends none,
    /// so the reader received NOTHING (measured `[]`); and once seeded it
    /// waited for holes nobody would ever repair. A best-effort + VOLATILE
    /// reader passed everything through, duplicates and out-of-order
    /// changes included.
    pub fn new_best_effort() -> Self {
        Self {
            enabled: true,
            seed_on_first_data: true,
            best_effort: true,
            writers: HashMap::new(),
            owed_total: 0,
            ready: HashMap::new(),
            undiscovered_refusals: std::collections::VecDeque::new(),
        }
    }

    /// Seed (or update) the per-writer expected base from a HEARTBEAT's
    /// `firstSN`, "the first (lowest) sequence number that is available in
    /// the Writer" (RTPS 2.5 8.3.8.6). If that floor has advanced past our
    /// base (the writer purged history), the numbers below it that never
    /// arrived are lost and the gate resumes from the floor - otherwise the
    /// reader would stall waiting for samples that no longer exist.
    ///
    /// What DID arrive below the floor is delivered, in order, not dropped.
    /// The reliable reader's HEARTBEAT transition calls
    /// `lost_changes_update(firstSN)`, which changes only the changes whose
    /// status is MISSING or UNKNOWN (RTPS 2.5 8.4.10.4, T7): a RECEIVED
    /// change stays deliverable. Purging them here would make a hole followed
    /// by a fast-forward lose every sample received behind the hole, for
    /// good.
    ///
    /// Returns any pending samples that are now deliverable as a result
    /// of this update (in ascending seq order).
    pub fn on_heartbeat(&mut self, writer_key: [u8; 16], first_seq: u64) -> Vec<PendingPayload> {
        let out = self.on_heartbeat_unsettled(writer_key, first_seq);
        self.settle_owed(&writer_key);
        out
    }

    fn on_heartbeat_unsettled(
        &mut self,
        writer_key: [u8; 16],
        first_seq: u64,
    ) -> Vec<PendingPayload> {
        if !self.enabled || self.best_effort {
            return Vec::new();
        }
        let seed_on_first_data = self.seed_on_first_data;
        let state = self.writers.entry(writer_key).or_default();
        if !state.seeded {
            if seed_on_first_data {
                // VOLATILE+RELIABLE: the delivery baseline is set by the
                // first DATA observed post-match, never by the writer's
                // advertised history floor. Seeding from `firstSN` here
                // would let a KEEP_ALL writer (firstSN=1) make the reader
                // wait for pre-join history it must not deliver, stalling
                // forever. Defer seeding to the data path. A DATA dropped
                // unconfirmed below firstSN is no longer in the writer's
                // history: the join it may seed moves up to firstSN.
                if let Some(refused) = state.unconfirmed_refused.as_mut() {
                    *refused = (*refused).max(first_seq);
                }
                return Vec::new();
            }
            // TRANSIENT_LOCAL+: request the writer's full available
            // history starting at its oldest retained seq.
            state.next_seq = Some(first_seq);
            state.seeded = true;
        } else if let Some(next) = state.next_seq {
            // History purged -- fast-forward over the gap.
            if first_seq > next {
                log::debug!(
                    "[reorder] writer first_seq={} > expected next={} (history purged); skipping gap",
                    first_seq,
                    next
                );
                // A base a DATA dropped unconfirmed seeded and nothing
                // passed since: the join moves up to firstSN
                // (`WriterState::hint_floor`).
                if state.at_hint_floor() {
                    state.join_floor = Some(first_seq);
                    state.hint_floor = None;
                }
                if state.staged.range(next..first_seq).next().is_none() {
                    state.next_seq = Some(first_seq);
                } else {
                    // Below firstSN are changes this reader received and
                    // staged, acknowledged (`staged`): the writer dropped
                    // them as acknowledged, not as lost. The base stays;
                    // only what never arrived is crossed, as a GAP's
                    // irrelevant changes are (`drain_contiguous`), and what
                    // follows a staged change waits for it.
                    let mut keep: std::collections::BTreeSet<u64> =
                        state.staged.range(next..first_seq).copied().collect();
                    keep.extend(state.pending.range(next..first_seq).map(|(&seq, _)| seq));
                    state.add_irrelevant_except(next, first_seq, &keep);
                }
            }
        }
        // Received below the base: deliverable, oldest first, ahead of what
        // the base itself now releases.
        let mut out = Vec::new();
        if let Some(base) = state.next_seq {
            let received: Vec<u64> = state.pending.range(..base).map(|(k, _)| *k).collect();
            for k in received {
                if let Some(payload) = state.pending.remove(&k) {
                    out.push(payload);
                }
            }
        }
        out.append(&mut Self::drain_contiguous(state));
        // What the gate has passed it no longer holds a place for.
        if let (Some(base), false) = (state.next_seq, state.staged.is_empty()) {
            state.staged = state.staged.split_off(&base);
        }
        out
    }

    /// A DATA of `writer_key` this reliable reader is about to acknowledge
    /// and stage outside the gate (a member of a coherent set, RTPS v2.5
    /// Sec.8.7.5): `false` when the gate passed `remote_seq` already, or
    /// crosses it ahead (`WriterState::irrelevant`): the writer gave it up
    /// (a HEARTBEAT's firstSN, reported lost) or declared it irrelevant (a
    /// GAP), and it is no change to deliver. Otherwise the gate
    /// keeps its place until the change comes back through `on_staged`: a
    /// HEARTBEAT whose firstSN passes it (the writer purged it, acknowledged)
    /// or a GAP that declares it does not move the base over it.
    ///
    /// Recorded under the gate's lock before the change is acknowledged, so
    /// that no HEARTBEAT can answer that acknowledgement before the gate
    /// knows. A gate seeded by the first DATA (VOLATILE) that is not seeded
    /// yet is seeded here, at its join floor (the start of the first set
    /// observed, `observe`): the staged change is the first one it takes
    /// from the writer, and the writer's later DATA waits behind its set
    /// (DDS v1.4 Sec.2.2.3.6 and 2.2.3.14). Left unseeded, the next plain
    /// DATA seeded the gate above the set and reached the application first,
    /// the set after it or never. A gate seeded by a HEARTBEAT keeps no place
    /// while unseeded (no base to pass it), and a writer forgotten
    /// (`forget_writer`) gets no record back. Always `true` for a disabled or
    /// BEST_EFFORT gate, which keeps nothing.
    pub fn hold_staged(&mut self, writer_key: &[u8; 16], remote_seq: u64) -> bool {
        if !self.enabled || self.best_effort {
            return true;
        }
        let seed_on_first_data = self.seed_on_first_data;
        let Some(state) = self.writers.get_mut(writer_key) else {
            return true;
        };
        if seed_on_first_data {
            state.confirm_refused(remote_seq);
        }
        let held = match state.next_seq {
            Some(next) if remote_seq < next => false,
            // Crossed ahead (a GAP declared it, or a HEARTBEAT's firstSN
            // passed it as never received while the gate waited below):
            // final, as below the base (`WriterState::irrelevant`). Its set
            // can never be whole (`misses_for_good`). Kept, its place held
            // with the record left, the gate crossed the place and the
            // places it owes left it out; taken back from the record, a
            // change reported lost was delivered too.
            _ if state.is_irrelevant(remote_seq) => false,
            Some(_) => {
                state.staged.insert(remote_seq);
                true
            }
            None if seed_on_first_data => {
                // Below the floor it is history from before the join,
                // dropped at release (`on_staged`); it seeds nothing.
                let floor = *state.join_floor.get_or_insert(remote_seq);
                if remote_seq >= floor {
                    state.next_seq = Some(floor);
                    state.seeded = true;
                    state.staged.insert(remote_seq);
                }
                true
            }
            None => true,
        };
        self.settle_owed(writer_key);
        held
    }

    /// Give back the places `writer_key`'s staged changes below `below`
    /// hold (`hold_staged`), so that the gate may cross them: the sets that
    /// hold them will never close. Only for the GROUP seam step of a writer
    /// that replays its pre-join sets without their END markers (RTI,
    /// vendor 0x0101, `flush_group_set`); a set of any other writer closes
    /// or is given up, and comes back through `on_staged`. Should such a
    /// set close after all, its changes, below the base, are released as
    /// any staged change the gate passed (`on_staged`). The number of places
    /// given back.
    pub fn give_up_staged_places_below(&mut self, writer_key: &[u8; 16], below: u64) -> usize {
        let Some(state) = self.writers.get_mut(writer_key) else {
            return 0;
        };
        if state.staged.is_empty() {
            return 0;
        }
        let kept = state.staged.split_off(&below);
        let given = state.staged.len();
        state.staged = kept;
        given
    }

    /// A DATA the reader received from `writer_key` and staged outside the
    /// gate (a coherent set waiting for its end, `set_start` its first
    /// sequence, PID_COHERENT_SET, RTPS v2.5 Sec.8.7.5): the gate does not
    /// see it arrive. A gate seeded by the first DATA (VOLATILE,
    /// BEST_EFFORT) takes the start of the first set observed as the
    /// writer's join floor, whichever of its samples arrives first. A
    /// BEST_EFFORT gate also counts it as received (T2, Sec.8.4.12.1, decides
    /// on arrival): a DATA older than it, arriving later, is refused.
    pub fn observe(&mut self, writer_key: [u8; 16], remote_seq: u64, set_start: Option<u64>) {
        if !self.enabled || !self.seed_on_first_data {
            return;
        }
        let best_effort = self.best_effort;
        let state = self.writers.entry(writer_key).or_default();
        // Sequence numbers start at 1 (RTPS v2.5 Sec.8.3.5.4): a set said to
        // start at 0 says nothing about where it starts.
        let start = set_start
            .filter(|&start| start > 0)
            .map_or(remote_seq, |start| start.min(remote_seq));
        if !best_effort {
            state.confirm_refused(start);
        }
        state.join_floor.get_or_insert(start);
        if best_effort && state.next_seq.is_none_or(|next| next <= remote_seq) {
            state.next_seq = Some(remote_seq.saturating_add(1));
            state.seeded = true;
        }
    }

    /// A DATA of `writer_key` this reliable reader received and refused
    /// unacknowledged (no storage, no place in its history, a backlog): the
    /// writer sends it again, and it is owed to the reader. A gate seeded
    /// by the first DATA (VOLATILE) joins the writer at the first one it
    /// receives, refused or not: its base is the refused sequence, which
    /// the samples above it then wait for. Seeded only by a later DATA it
    /// stored, the gate delivered that DATA ahead of the refused ones and
    /// dropped their resends as history from before its join, acknowledged.
    ///
    /// Nothing for a gate seeded by a HEARTBEAT (its base is the writer's
    /// firstSN) nor a BEST_EFFORT one (owed nothing). A sample refused at
    /// staging takes `observe` instead, as a staged sample does.
    pub fn on_refused(&mut self, writer_key: [u8; 16], remote_seq: u64) {
        if let Some(state) = self.writers.get_mut(&writer_key) {
            state.confirm_refused(remote_seq);
        }
        if !self.enabled || self.best_effort || !self.seed_on_first_data {
            return;
        }
        let state = self.writers.entry(writer_key).or_default();
        if state.next_seq.is_some() || state.join_floor.is_some_and(|floor| remote_seq < floor) {
            return;
        }
        state.next_seq = Some(remote_seq);
        state.seeded = true;
        state.join_floor.get_or_insert(remote_seq);
        self.settle_owed(&writer_key);
    }

    /// A DATA of `writer_key` this reliable reader refused unacknowledged
    /// because it cannot authenticate it yet: its writer's security
    /// attributes or the key it names have not arrived (DDS-Security v1.1
    /// Sec.8.5.1.9.6, `preprocess_secure_submsg`: a key id with no matching
    /// material). If its writer sent it, the writer sends it again and it is
    /// owed to the reader, as a DATA refused for want of room is
    /// (`on_refused`); but unauthenticated, it says nothing about where the
    /// writer's stream is, so it seeds no gate. A gate seeded by the first
    /// DATA (VOLATILE) keeps its lowest such sequence (`set_start` for a
    /// coherent set's member, as `observe` reads it) and joins there only
    /// when the first authenticated change of the writer arrives at or above
    /// it (`WriterState::confirm_refused`): a sequence forged far ahead of
    /// the writer cannot make the gate drop the writer's real samples as
    /// history from before its join.
    ///
    /// A real writer's DATA can arrive before discovery holds the writer,
    /// and is owed all the same; but a GUID nobody announced never departs,
    /// and anyone can forge one under an admitted participant. A state the
    /// gate creates for a writer discovery does not hold (`!discovered`)
    /// is therefore counted, and once `UNDISCOVERED_REFUSALS_KEPT` are, the
    /// oldest that still holds nothing but the refusal is forgotten. A
    /// writer discovery holds is never forgotten so (`writer_discovered`).
    #[cfg(feature = "security")]
    pub fn on_refused_unauthenticated(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        set_start: Option<u64>,
        discovered: bool,
    ) {
        self.file_unconfirmed(writer_key, remote_seq, set_start, discovered);
    }

    /// A DATA of `writer_key` (a coherent set's member when `set_start`)
    /// this reliable reader dropped unacknowledged because discovery does
    /// not hold its writer yet. A writer that has discovered this reader
    /// sends it DATA before this reader has discovered the writer
    /// (discovery is asymmetric): the writer sends it again, and it is
    /// owed. The GUID is vouched for by nothing yet, so the DATA is filed
    /// as one refused unauthenticated is (`on_refused_unauthenticated`):
    /// the gate joins there only once a change of the writer it admits
    /// arrives at or above it, and the states of GUIDs discovery does not
    /// hold are bounded (`UNDISCOVERED_REFUSALS_KEPT`).
    pub fn on_dropped_undiscovered(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        set_start: Option<u64>,
    ) {
        self.file_unconfirmed(writer_key, remote_seq, set_start, false);
    }

    /// A change of `writer_key` (a coherent set's member when `set_start`)
    /// this reliable reader dropped unacknowledged because the GROUP context
    /// it needs to order the change (the writer's class and Publisher) is
    /// not known yet: the writer sends it again, and it is owed. Filed as
    /// `on_dropped_undiscovered` files a DATA, counted among the states
    /// forgotten first unless `discovered`.
    pub fn on_dropped_without_group_context(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        set_start: Option<u64>,
        discovered: bool,
    ) {
        self.file_unconfirmed(writer_key, remote_seq, set_start, discovered);
    }

    /// File `remote_seq` (from `set_start` for a coherent set's member) as
    /// `writer_key`'s lowest unconfirmed DATA (`unconfirmed_refused`),
    /// counting the state among those forgotten first unless `discovered`.
    fn file_unconfirmed(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        set_start: Option<u64>,
        discovered: bool,
    ) {
        if !self.enabled || self.best_effort || !self.seed_on_first_data {
            return;
        }
        if discovered {
            self.writer_discovered(&writer_key);
        } else if !self.writers.contains_key(&writer_key)
            && !self.undiscovered_refusals.contains(&writer_key)
        {
            // Counted once: a writer whose state was forgotten (it
            // departed) may still be counted.
            self.undiscovered_refusals.push_back(writer_key);
            while self.undiscovered_refusals.len() > UNDISCOVERED_REFUSALS_KEPT {
                let Some(oldest) = self.undiscovered_refusals.pop_front() else {
                    break;
                };
                if self
                    .writers
                    .get(&oldest)
                    .is_some_and(WriterState::holds_only_a_refusal)
                {
                    self.writers.remove(&oldest);
                }
            }
        }
        let state = self.writers.entry(writer_key).or_default();
        // A gate that joined the writer already keeps its base: moving it
        // back would deliver the writer's changes out of order. Known
        // limitation: the router's drop of a DATA can race the writer's
        // binding (one thread finds no binding, discovery binds the writer,
        // another thread routes a later DATA through the binding and the
        // gate joins there, then the first thread reports the drop): that
        // DATA is then not delivered. The fix belongs in the seeding rule
        // (no join through a binding while a drop before it may still be
        // reported), planned for 1.6.0.
        if state.next_seq.is_some() {
            return;
        }
        let start = set_start
            .filter(|&start| start > 0)
            .map_or(remote_seq, |start| start.min(remote_seq));
        state.unconfirmed_refused = Some(state.unconfirmed_refused.map_or(start, |s| s.min(start)));
    }

    /// Whether `writer_key`'s base still stands where a DATA dropped
    /// unconfirmed seeded it (`WriterState::hint_floor`): a HEARTBEAT's
    /// firstSN above it moves the gate up without the sequences in between
    /// being lost to the reader.
    pub fn at_hint_floor(&self, writer_key: &[u8; 16]) -> bool {
        self.writers
            .get(writer_key)
            .is_some_and(WriterState::at_hint_floor)
    }

    /// Tests only: `writer_key`'s lowest DATA dropped unconfirmed
    /// (`WriterState::unconfirmed_refused`).
    #[cfg(all(test, feature = "security"))]
    pub fn unconfirmed_for_test(&self, writer_key: &[u8; 16]) -> Option<u64> {
        self.writers
            .get(writer_key)
            .and_then(|state| state.unconfirmed_refused)
    }

    /// Discovery holds `writer_key` now: its state is no longer counted
    /// among those `file_unconfirmed` forgets.
    pub fn writer_discovered(&mut self, writer_key: &[u8; 16]) {
        if !self.undiscovered_refusals.is_empty() {
            self.undiscovered_refusals.retain(|key| key != writer_key);
        }
    }

    /// Tests only: how many writers the gate counts among those
    /// `file_unconfirmed` forgets.
    #[cfg(test)]
    pub fn undiscovered_refusal_count(&self) -> usize {
        self.undiscovered_refusals.len()
    }

    /// A directed DATA held until discovery is owed even before admission.
    /// Several such changes may arrive out of order: until anything has
    /// passed the initial floor, keep the lowest observed one. After a
    /// release the floor never moves back (RTPS 2.5 8.4.12.2).
    pub fn on_deferred(&mut self, writer_key: [u8; 16], remote_seq: u64) {
        self.on_refused(writer_key, remote_seq);
        if !self.enabled || self.best_effort || !self.seed_on_first_data {
            return;
        }
        if let Some(state) = self.writers.get_mut(&writer_key) {
            if state.next_seq == state.join_floor
                && state.next_seq.is_some_and(|next| remote_seq < next)
                && !state.is_irrelevant(remote_seq)
            {
                state.next_seq = Some(remote_seq);
                state.join_floor = Some(remote_seq);
            }
        }
        self.settle_owed(&writer_key);
    }

    /// Whether a change of `writer_key` in `[start, end]` that is not in
    /// `have` will never reach this gate: it passed that sequence without
    /// it (the writer GAPped it, or its HEARTBEAT no longer offers it), or a
    /// GAP declared it irrelevant ahead. A coherent set missing one can
    /// never be whole (RTPS v2.5 Sec.8.7.6, lines 7500-7515 of the 2.5
    /// text). Always `false` for a disabled gate, which keeps nothing.
    pub fn misses_for_good(
        &self,
        writer_key: &[u8; 16],
        start: u64,
        end: u64,
        have: &std::collections::BTreeSet<u64>,
    ) -> bool {
        if !self.enabled || end < start {
            return false;
        }
        let Some(state) = self.writers.get(writer_key) else {
            return false;
        };
        if let Some(passed) = state
            .next_seq
            .and_then(|next| next.checked_sub(1))
            .map(|below| below.min(end))
            .filter(|&below| below >= start)
        {
            let held = u64::try_from(have.range(start..=passed).count()).unwrap_or(u64::MAX);
            let filtered = covered_in(&state.filtered, start, passed.saturating_add(1));
            if held.saturating_add(filtered) < passed - start + 1 {
                return true;
            }
        }
        state.unfiltered_irrelevant_in(start, end.saturating_add(1)) > 0
    }

    /// `writer_key`'s sequences a GAP declared filtered for this reader
    /// (`note_filtered`): at most `MAX_FILTERED_RANGES` ranges.
    pub fn filtered_ranges(&self, writer_key: &[u8; 16]) -> BTreeMap<u64, u64> {
        self.writers
            .get(writer_key)
            .map(|state| state.filtered.clone())
            .unwrap_or_default()
    }

    /// How many of `writer_key`'s sequences in `[start, end]` a GAP
    /// declared filtered for this reader (`note_filtered`).
    pub fn filtered_in(&self, writer_key: &[u8; 16], start: u64, end: u64) -> u64 {
        self.writers.get(writer_key).map_or(0, |state| {
            covered_in(&state.filtered, start, end.saturating_add(1))
        })
    }

    /// Filter history is complete only at or above this exclusive bound.
    /// An older absent range is unknown, not proof of an unfiltered loss.
    pub fn filtered_history_floor(&self, writer_key: &[u8; 16]) -> u64 {
        self.writers
            .get(writer_key)
            .map_or(0, |state| state.filtered_history_floor)
    }

    /// A GAP of `writer_key` declared `[gap_start, gap_list_base)` and
    /// `gap_list_seqs` filtered for this reader: changes the writer still
    /// has but that are not relevant to it (RTPS v2.5 Sec.8.3.8.4,
    /// filteredCount). They are not part of the reader's coherent sets
    /// (Sec.8.7.6: the Subscriber-relevant coherent set excludes "changes
    /// that are filtered by content or time"): a set without them is whole.
    /// To be called before the GAP itself (`on_gap`).
    pub fn note_filtered(
        &mut self,
        writer_key: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: &[u64],
    ) {
        if !self.enabled {
            return;
        }
        let state = self.writers.entry(writer_key).or_default();
        if gap_start > 0 {
            add_range(
                &mut state.filtered,
                gap_start,
                gap_list_base.max(gap_start.saturating_add(1)),
            );
        }
        for &seq in gap_list_seqs.iter().filter(|&&seq| seq > 0) {
            add_range(&mut state.filtered, seq, seq.saturating_add(1));
        }
        while state.filtered.len() > MAX_FILTERED_RANGES {
            if let Some((_, end)) = state.filtered.pop_first() {
                state.filtered_history_floor = state.filtered_history_floor.max(end);
            }
        }
    }

    /// Whether a BEST_EFFORT gate took a later change of `writer_key` than
    /// `remote_seq` already: the best-effort reader refuses it (T2, RTPS
    /// v2.5 Sec.8.4.12.1), staged or not. Always `false` for a reliable
    /// gate.
    pub fn is_behind(&self, writer_key: &[u8; 16], remote_seq: u64) -> bool {
        self.enabled
            && self.best_effort
            && self
                .writers
                .get(writer_key)
                .and_then(|state| state.next_seq)
                .is_some_and(|next| remote_seq < next)
    }

    /// Submit a sample the reader received earlier and staged outside the
    /// gate, a member of a coherent set released now that the set is
    /// complete.
    ///
    /// The gate may have moved past it while it was staged: a HEARTBEAT
    /// whose firstSN passed it (a writer drops a change from its history
    /// once every reader acknowledged it, and the reader acknowledged the
    /// staged sample on receipt), or, for a BEST_EFFORT gate, a later DATA
    /// of the writer that was not staged. Neither says the sample was lost:
    /// it was received, and accepted, once, by the duplicate record at
    /// staging (RTPS v2.5 Sec.8.4.12.1, T2, decides on arrival). It is
    /// released as it is instead of being dropped as stale, which delivered
    /// the set without it.
    ///
    /// Below the writer's join floor it is history from before this reader
    /// joined (a VOLATILE reader's repair of an older set) and is dropped,
    /// whether or not the gate is seeded yet. A sample the gate has not
    /// reached takes `on_data`.
    pub fn on_staged(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        payload: PendingPayload,
    ) -> Vec<PendingPayload> {
        if !self.enabled {
            return vec![payload];
        }
        let state = self.writers.entry(writer_key).or_default();
        // Back through the gate: it holds the change itself now (or has
        // passed it), no longer its place.
        if !state.staged.is_empty() {
            state.staged.remove(&remote_seq);
        }
        if state.join_floor.is_some_and(|floor| remote_seq < floor) {
            return Vec::new();
        }
        // Handed back once already: nothing more to deliver.
        if !state.handed_back.insert(remote_seq) {
            return Vec::new();
        }
        if state.handed_back.len() > HANDED_BACK_KEPT {
            state.handed_back.pop_first();
        }
        if state.next_seq.is_some_and(|next| remote_seq < next) {
            return vec![payload];
        }
        // Acknowledged when staged: past the bound, held all the same (the
        // staging is bounded on its own, `MAX_STAGED_PER_WRITER`). Forced
        // progress here gave up the gap below, whose repair the gate then
        // took for history, acknowledged and never delivered. Received
        // before the gate recorded it irrelevant, it is held all the same.
        self.insert(writer_key, remote_seq, payload, false)
    }

    /// Submit an arriving DATA sample.
    ///
    /// Returns the list of payloads ready for delivery, in ascending seq
    /// order. Empty vector means "buffered, deliver later". For Volatile
    /// readers (`enabled == false`) the input is returned verbatim.
    pub fn on_data(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        payload: PendingPayload,
    ) -> Vec<PendingPayload> {
        self.insert(writer_key, remote_seq, payload, true)
    }

    /// [`on_data`](Self::on_data) when `arriving`: the per-writer bound
    /// enforced by forced progress (a sample the reader still refuses
    /// unacknowledged at the bound never reaches it, `holds_no_more`), and a
    /// sequence the gate crosses ahead (`WriterState::irrelevant`) dropped.
    /// Otherwise a change staged earlier, handed back (`on_staged`): held
    /// whatever the bound, and received before the gate recorded it.
    fn insert(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        payload: PendingPayload,
        arriving: bool,
    ) -> Vec<PendingPayload> {
        if !self.enabled {
            return vec![payload];
        }
        let (best_effort, seed_on_first_data) = (self.best_effort, self.seed_on_first_data);
        // One lookup for the step and its settling (see `settle_owed`).
        let state = self.writers.entry(writer_key).or_default();
        if seed_on_first_data && !best_effort {
            state.confirm_refused(remote_seq);
        }
        let out = Self::data_into(
            state,
            best_effort,
            seed_on_first_data,
            remote_seq,
            payload,
            arriving,
        );
        let owed = Self::places_owed(state);
        self.owed_total = self.owed_total - wide(state.owed) + wide(owed);
        state.owed = owed;
        out
    }

    /// [`on_data`](Self::on_data) on `writer_key`'s state, of an enabled
    /// gate.
    fn data_into(
        state: &mut WriterState,
        best_effort: bool,
        seed_on_first_data: bool,
        remote_seq: u64,
        payload: PendingPayload,
        arriving: bool,
    ) -> Vec<PendingPayload> {
        if best_effort {
            // T2: expected = available_changes_max + 1, kept as `next_seq`.
            if state.next_seq.is_some_and(|expected| remote_seq < expected) {
                return Vec::new();
            }
            state.next_seq = Some(remote_seq.saturating_add(1));
            state.seeded = true;
            state.join_floor.get_or_insert(remote_seq);
            return vec![payload];
        }
        match state.next_seq {
            None if seed_on_first_data => {
                // VOLATILE+RELIABLE join: the first DATA observed
                // post-match sets the delivery baseline (low-water mark).
                // Deliver it immediately and advance. A lower seq that
                // arrives later (a delayed/retransmitted pre-join sample)
                // falls into the `remote_seq < next` branch and is
                // dropped; a genuine post-join gap is held by the
                // `remote_seq > next` branch and released in order. Below
                // a join floor a staged DATA set first, it is from before
                // the join too.
                if state.join_floor.is_some_and(|floor| remote_seq < floor) {
                    return Vec::new();
                }
                state.next_seq = Some(remote_seq + 1);
                state.seeded = true;
                state.join_floor.get_or_insert(remote_seq);
                let mut out = Vec::with_capacity(1);
                out.push(payload);
                let mut drained = Self::drain_contiguous(state);
                out.append(&mut drained);
                out
            }
            None => {
                // No HB yet -- hold and wait. While unseeded we cannot
                // drain (the base is unknown), so just bound memory by
                // dropping the oldest buffered entry when the cap is
                // exceeded. Dropping individual entries means a later
                // HEARTBEAT could seed at a value that lies inside the
                // dropped range and cause a permanent stall, so when
                // forced to discard we clear the entire pending buffer:
                // worst case we lose the unseeded prefix entirely (the
                // application sees the seeded history retransmits), but
                // no synthetic gap is left for `drain_contiguous` to
                // block on.
                //
                // A GAP that came first declared it irrelevant: final.
                if Self::crossed_ahead(state, remote_seq, arriving) {
                    return Vec::new();
                }
                state.pending.insert(remote_seq, payload);
                if arriving && state.pending.len() > MAX_PENDING_PER_WRITER {
                    log::warn!(
                        "[reorder] writer pending cap exceeded ({} > {}) while unseeded; \
                         clearing buffer to avoid synthetic gap after HEARTBEAT",
                        state.pending.len(),
                        MAX_PENDING_PER_WRITER,
                    );
                    state.pending.clear();
                }
                Vec::new()
            }
            Some(next) if remote_seq < next => {
                // Already delivered (or stale historical retransmit).
                Vec::new()
            }
            Some(next) if remote_seq == next => {
                // Hot path: in-order arrival.
                state.next_seq = Some(next + 1);
                let mut out = Vec::with_capacity(1);
                out.push(payload);
                let mut drained = Self::drain_contiguous(state);
                out.append(&mut drained);
                out
            }
            Some(_) => {
                // Out-of-order future seq -- buffer, then force progress if
                // we have hit the per-writer pending cap. Forced progress
                // declares the still-missing prefix as lost and releases
                // everything that has piled up starting at the new
                // (raised) base; otherwise an adversarial peer holding the
                // gap could grow `pending` without bound.
                //
                // Crossed ahead (a GAP declared it, or a HEARTBEAT's firstSN
                // passed it as never received while the gate waited below):
                // final, as below the base. Held inside the record, the gate
                // jumped over it (`drain_contiguous`) and released it below
                // the base, after what followed it.
                if Self::crossed_ahead(state, remote_seq, arriving) {
                    return Vec::new();
                }
                state.pending.insert(remote_seq, payload);
                if arriving && state.pending.len() > MAX_PENDING_PER_WRITER {
                    if let Some((&lowest, _)) = state.pending.iter().next() {
                        if let Some(prev) = state.next_seq {
                            if lowest > prev {
                                log::warn!(
                                    "[reorder] writer pending cap exceeded ({} > {}); \
                                     advancing base {} -> {} (treating {} seqs as lost)",
                                    state.pending.len(),
                                    MAX_PENDING_PER_WRITER,
                                    prev,
                                    lowest,
                                    lowest - prev,
                                );
                                state.next_seq = Some(lowest);
                                return Self::drain_contiguous(state);
                            }
                        }
                    }
                }
                Vec::new()
            }
        }
    }

    /// Whether `remote_seq`, about to be held, is one the gate crosses ahead
    /// (`WriterState::irrelevant`): an `arriving` copy is then dropped (the
    /// caller returns nothing; the payload, dropped, gives back what it
    /// holds). A change handed back from staging was received before the
    /// gate recorded it, and leaves the record instead.
    fn crossed_ahead(state: &mut WriterState, remote_seq: u64, arriving: bool) -> bool {
        if !state.is_irrelevant(remote_seq) {
            return false;
        }
        if arriving {
            return true;
        }
        state.received_after_all(remote_seq);
        false
    }

    /// Whether a change of `writer_key` at `remote_seq` that arrives now is
    /// one a seeded gate crosses ahead and is not filtered for this reader:
    /// a sample lost, which `hold_staged` refuses. Reported lost when the
    /// sequence was crossed, unless it was received by then (the reader's
    /// duplicate record, read in that section of the gate's lock): one
    /// admitted before and handed to the gate after is reported when the
    /// gate refuses it. Before the gate is seeded nothing is owed yet, and
    /// a GAP reports nothing then (`ReaderSubscriber::on_writer_gap`).
    pub fn lost_ahead(&self, writer_key: &[u8; 16], remote_seq: u64) -> bool {
        self.enabled
            && !self.best_effort
            && self.writers.get(writer_key).is_some_and(|state| {
                state.next_seq.is_some_and(|next| remote_seq >= next)
                    && state.is_irrelevant(remote_seq)
                    && covered_in(&state.filtered, remote_seq, remote_seq.saturating_add(1)) == 0
            })
    }

    /// Advance past a received writer sequence that carries no application
    /// sample (for example a key-only instance-registration DATA).
    ///
    /// This has the same ordering effect as a one-element GAP, but names the
    /// distinct transport fact: the sequence was received and acknowledged;
    /// it is only absent from the application sample stream.
    ///
    /// Unlike a GAP, it seeds no gate. Where a durable reader's delivery
    /// starts is the writer's history (its HEARTBEAT), and where a volatile
    /// reader's starts is its first sample: a sample-less change arriving
    /// first (a coherent set's END marker overtaking the set on UDP) would
    /// place the base above samples still to come, which the gate would then
    /// drop as delivered. The proxy has the change; the reader follows the
    /// proxy once the gate is seeded (`ReaderSubscriber::follow_proxy`).
    ///
    /// A reliable gate takes it as a received sample that delivers nothing
    /// (`PendingPayload::nothing`): moved over once the gate reaches it,
    /// kept until then; a gate seeded by a HEARTBEAT, before it is seeded
    /// too. A reliable gate its writer's first DATA has not seeded yet
    /// records it as a sequence to cross (`irrelevant`, as a GAP's before
    /// the gate is seeded), seeding nothing: crossed once the gate, seeded
    /// below it, reaches it, forgotten if the gate is seeded above it.
    /// Forgotten before the gate is seeded, the change was acknowledged and
    /// the gate, once seeded, waited for it for good; recorded only as
    /// passed over above the base, it was crossed only by a gate that
    /// follows the writer proxy, which a coherent reader's does not.
    pub fn on_non_data(&mut self, writer_key: [u8; 16], remote_seq: u64) -> Vec<PendingPayload> {
        if self.keeps_non_data(&writer_key) {
            return self.on_data(writer_key, remote_seq, PendingPayload::nothing(remote_seq));
        }
        if self.enabled && self.next_seq(&writer_key).is_none() {
            if !self.best_effort && remote_seq > 0 {
                self.writers
                    .entry(writer_key)
                    .or_default()
                    .add_irrelevant(remote_seq, remote_seq.saturating_add(1));
            }
            return Vec::new();
        }
        self.on_gap(
            writer_key,
            remote_seq,
            remote_seq.saturating_add(1),
            std::iter::empty(),
        )
    }

    /// Whether [`on_non_data`](Self::on_non_data) holds a change without a
    /// sample of `writer_key` until the gate reaches it, where
    /// [`held_after`](Self::held_after) finds it: a reliable gate seeded by
    /// a HEARTBEAT, or one seeded already. A gate not seeded yet by a first
    /// DATA only records it as a sequence to cross, and a best-effort gate
    /// passes it.
    pub fn keeps_non_data(&self, writer_key: &[u8; 16]) -> bool {
        self.enabled
            && !self.best_effort
            && (!self.seed_on_first_data || self.next_seq(writer_key).is_some())
    }

    /// The lowest sequence above `remote_seq` the gate holds for
    /// `writer_key` (a sample, or a change that delivers nothing), if any.
    pub fn held_after(&self, writer_key: &[u8; 16], remote_seq: u64) -> Option<u64> {
        let state = self.writers.get(writer_key)?;
        state
            .pending
            .range(remote_seq.saturating_add(1)..)
            .next()
            .map(|(&seq, _)| seq)
    }

    /// Whether this is a BEST_EFFORT reader's gate.
    pub fn is_best_effort(&self) -> bool {
        self.best_effort
    }

    /// Whether this gate is seeded by the writer's HEARTBEAT (a durable,
    /// reliable reader's), not by its first DATA.
    pub fn seeded_by_heartbeat(&self) -> bool {
        self.enabled && !self.best_effort && !self.seed_on_first_data
    }

    /// Consume a GAP submessage (RTPS v2.5 sec 8.3.8.4).
    ///
    /// A GAP declares two irrelevant sets, unioned together:
    /// - the contiguous range `[gap_start, gap_list_base)`;
    /// - every additional sequence in the SNSet bitmap (`gap_list_seqs`).
    ///
    /// `gap_list_base` is clamped to at least `gap_start + 1` when
    /// `gap_start > 0`, so a caller with no real base (a legacy/local site
    /// that only ever declared a single sequence irrelevant) can pass
    /// `gap_start + 1` and get the old single-sequence behavior, and a
    /// malformed/hostile `gap_list_base <= gap_start` degrades to the same
    /// single-sequence range instead of an empty or negative one.
    ///
    /// The contiguous range is never materialized into a set - membership
    /// is an interval check and `next_seq` crosses it with a single jump -
    /// so a huge range (e.g. `[1, 2^40)`) is O(1), not O(range length).
    ///
    /// The method discards any buffered pending samples that fall inside
    /// the declared-irrelevant union, then advances `next_seq` past the
    /// contiguous leading run that was declared irrelevant, and finally
    /// drains any contiguous prefix that is now unblocked.
    ///
    /// Returns the list of payloads that are now deliverable (in ascending
    /// seq order). Empty when no buffered samples were unblocked.
    ///
    /// # Non-regression guarantee
    ///
    /// If no GAP is ever received for a writer the gate behaves identically
    /// to before: this method is never called for that writer. Existing
    /// `on_heartbeat` / `on_data` logic is unchanged. For any call with
    /// `gap_list_base <= gap_start + 1` the behavior is bit-identical to
    /// the pre-range implementation (the range collapses to the single
    /// sequence `gap_start`, exactly as before).
    pub fn on_gap(
        &mut self,
        writer_key: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: impl IntoIterator<Item = u64>,
    ) -> Vec<PendingPayload> {
        self.on_gap_keeping(
            writer_key,
            gap_start,
            gap_list_base,
            gap_list_seqs,
            &std::collections::BTreeSet::new(),
        )
    }

    /// [`on_gap`](Self::on_gap), but for `keep`: sequences the GAP declares
    /// that the reader received and holds outside the gate (staged in a
    /// coherent set). Received, they are the reader's all the same; the gate
    /// waits for them as for any change still to come, and takes them when
    /// their set commits (`on_staged`). Crossed, the gate released the
    /// writer's later changes before the set that holds them.
    pub fn on_gap_keeping(
        &mut self,
        writer_key: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: impl IntoIterator<Item = u64>,
        keep: &std::collections::BTreeSet<u64>,
    ) -> Vec<PendingPayload> {
        let out = self.on_gap_unsettled(writer_key, gap_start, gap_list_base, gap_list_seqs, keep);
        self.settle_owed(&writer_key);
        out
    }

    fn on_gap_unsettled(
        &mut self,
        writer_key: [u8; 16],
        gap_start: u64,
        gap_list_base: u64,
        gap_list_seqs: impl IntoIterator<Item = u64>,
        keep: &std::collections::BTreeSet<u64>,
    ) -> Vec<PendingPayload> {
        if !self.enabled || self.best_effort {
            return Vec::new();
        }

        // Effective end of the contiguous range (exclusive). Clamped so
        // gap_start alone is always covered, per the doc comment above.
        // Saturating: `gap_start` is a u64 this pub fn does not control, and
        // `u64::MAX + 1` panicked in checked builds. Decoded GAPs can no
        // longer carry one (`parse_gap_body` refuses a sequence number above
        // i64::MAX), but this function should not rely on its callers for
        // not panicking.
        let range_end = if gap_start > 0 {
            gap_list_base.max(gap_start.saturating_add(1))
        } else {
            gap_list_base
        };
        let range_valid = gap_start > 0 && range_end > gap_start;

        // Individual bitmap entries, kept in a bounded set -- never the
        // contiguous range itself, so a hostile/huge range GAP cannot
        // blow up memory.
        let bitmap: std::collections::BTreeSet<u64> =
            gap_list_seqs.into_iter().filter(|&seq| seq > 0).collect();

        if !range_valid && bitmap.is_empty() {
            return Vec::new();
        }

        let seed_on_first_data = self.seed_on_first_data;
        let state = self.writers.entry(writer_key).or_default();
        // Held in the gate or outside it, received: never recorded as
        // irrelevant, so a held change is never counted twice in the places
        // its gap keeps free (`places_to_keep`).
        let mut held_keep = keep.clone();
        // Staged and acknowledged (`hold_staged`): the gate knows it under
        // its own lock, even when `keep`, read before it, does not yet.
        held_keep.extend(state.staged.iter().copied());
        if range_valid {
            held_keep.extend(
                state
                    .pending
                    .range(gap_start..range_end)
                    .map(|(&seq, _)| seq),
            );
        }
        held_keep.extend(bitmap.iter().filter(|seq| state.pending.contains_key(seq)));
        let keep = &held_keep;

        // What the gate holds of the declared sequences was received: the
        // GAP does not take it back (RTPS v2.5 Sec.8.4.10.4,
        // `irrelevant_change_set` marks a change the reader is not to wait
        // for; one in the reader's history cache stays there). A writer
        // that replaced a change after sending it (KEEP_LAST) GAPs it, and
        // the copy the reader holds is delivered in its turn; the gate
        // crosses the declared sequences around it (`drain_contiguous`).
        // Dropped here, a received sample, acknowledged, was lost without a
        // report, and a coherent set it belonged to was delivered in part.

        // A gate seeded by the first DATA (VOLATILE) takes its base from a
        // GAP that comes first, as before: the GAP is where it joins. So does
        // a gate seeded by a HEARTBEAT, from a GAP that starts at the
        // writer's first sequence (1, RTPS v2.5 Sec.8.3.5.4): everything
        // below its end is then accounted for.
        let was_seeded = state.next_seq.is_some();
        if !was_seeded && (seed_on_first_data || (range_valid && gap_start == 1)) {
            let mut base = gap_start;
            if range_valid {
                base = range_end;
            }
            while bitmap.contains(&base) {
                match base.checked_add(1) {
                    Some(next) => base = next,
                    None => break,
                }
            }
            // A sample held below the base (received before the gate was
            // seeded), or one held outside the gate (`keep`), is delivered:
            // the gate starts at the GAP and crosses the declared sequences
            // up to it.
            if range_valid
                && (state.pending.range(..base).next().is_some()
                    || keep.range(..base).next().is_some())
            {
                state.next_seq = Some(gap_start);
                for &seq in bitmap.iter().filter(|seq| !keep.contains(seq)) {
                    state.add_irrelevant(seq, seq.saturating_add(1));
                }
                state.add_irrelevant_except(gap_start, range_end, keep);
            } else {
                state.next_seq = Some(base);
            }
            state.seeded = true;
            if seed_on_first_data {
                state.join_floor.get_or_insert(base);
            }
            return Self::drain_contiguous(state);
        }

        // Otherwise the declared sequences are recorded, never materialized
        // (a range is one entry, however long), and crossed when the gate
        // reaches them (`drain_contiguous`), seeded or not yet. A gate seeded
        // by a HEARTBEAT takes no base from any other GAP: one that came
        // before the first HEARTBEAT seeded it past the samples below the
        // GAP, held or still to come, which were then dropped as delivered,
        // acknowledged.
        if range_valid {
            state.add_irrelevant_except(gap_start, range_end, keep);
        }
        for &seq in bitmap.iter().filter(|seq| !keep.contains(seq)) {
            state.add_irrelevant(seq, seq.saturating_add(1));
        }
        if let Some(base) = state.next_seq {
            let declared = bitmap
                .last()
                .copied()
                .into_iter()
                .chain(range_valid.then(|| range_end - 1))
                .max()
                .unwrap_or(0);
            if declared >= base {
                state.passed_over = state.passed_over.max(declared);
            }
        }

        Self::drain_contiguous(state)
    }

    /// Discard a writer's gate state: the writer left (its SEDP dispose, its
    /// participant's departure, or a re-authentication), and a writer that
    /// comes back under its GUID is a new one, whose sequence numbers start
    /// again. What the gate held is dropped (its slots come back); what it
    /// released (`ready`) is still delivered.
    /// The sequences it held, received and never released, are returned.
    #[cfg(test)]
    pub fn forget_writer(&mut self, writer_key: &[u8; 16]) -> Vec<u64> {
        self.forget_writer_payloads(writer_key)
            .into_iter()
            .map(|payload| payload.remote_seq)
            .collect()
    }

    /// Return owned payloads so a departure can report real losses before
    /// releasing their history and storage reservations.
    pub(super) fn forget_writer_payloads(&mut self, writer_key: &[u8; 16]) -> Vec<PendingPayload> {
        match self.writers.remove(writer_key) {
            Some(state) => {
                self.owed_total -= wide(state.owed);
                state.pending.into_values().collect()
            }
            None => Vec::new(),
        }
    }

    fn drain_contiguous(state: &mut WriterState) -> Vec<PendingPayload> {
        let mut out = Vec::new();
        let Some(mut next) = state.next_seq else {
            return out;
        };
        loop {
            if let Some(entry) = state.pending.remove(&next) {
                out.push(entry);
                next += 1;
                continue;
            }
            // Declared irrelevant: crossed like a received change.
            match state.irrelevant.range(..=next).next_back() {
                Some((_, &end)) if end > next => next = end,
                _ => break,
            }
        }
        state.next_seq = Some(next);
        // What the gate has passed is forgotten.
        let below: Vec<u64> = state
            .irrelevant
            .range(..next)
            .filter(|&(_, &e)| e <= next)
            .map(|(&s, _)| s)
            .collect();
        for start in below {
            state.irrelevant.remove(&start);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::CdrVersion;

    /// A received sample held behind a hole is delivered by the HEARTBEAT
    /// whose firstSN passes it: it was received, and a HEARTBEAT only marks
    /// what was never received as lost (RTPS 2.5 8.4.10.4). Both seeds.
    #[test]
    fn a_held_received_sample_below_first_heartbeat_is_released_in_order() {
        for seed_on_first_data in [true, false] {
            let mut gate = ReorderGate::new(true, seed_on_first_data);
            let key = [7u8; 16];
            if seed_on_first_data {
                assert_eq!(data_tags(&gate.on_data(key, 1, payload(1))), vec![1]);
            } else {
                assert!(gate.on_data(key, 1, payload(1)).is_empty());
                assert!(gate.on_data(key, 2, payload(2)).is_empty());
            }
            // 3 is missing; 4 arrives and is held behind it.
            let held = if seed_on_first_data { 4 } else { 3 };
            assert!(gate.on_data(key, held, payload(held as u8)).is_empty());
            // firstSN 5: 3 was never received, 4 was.
            let released = gate.on_heartbeat(key, 5);
            // Unseeded, 1 and 2 were held too (no baseline yet): all received.
            let expected: Vec<u8> = if seed_on_first_data {
                vec![held as u8]
            } else {
                vec![1, 2, held as u8]
            };
            assert_eq!(
                data_tags(&released),
                expected,
                "seed_on_first_data={seed_on_first_data}: every received sample below firstSN is delivered"
            );
            let out = gate.on_data(key, 5, payload(5));
            assert_eq!(data_tags(&out), vec![5], "the gate continues at firstSN");
        }
    }

    /// A GAP that declares 1..3 irrelevant and a HEARTBEAT with firstSN 5
    /// release the same thing in either order, for a received sample held at 3
    /// (the order the UDP Router and the TCP door apply them in is the arrival
    /// order of one datagram, which may be either). Only a never-received
    /// sequence is crossed, and the result is the same either way.
    #[test]
    fn the_order_of_a_gap_and_a_heartbeat_releases_the_same_samples() {
        let run = |gap_first: bool| {
            let mut gate = ReorderGate::new(true, true);
            let key = [9u8; 16];
            assert_eq!(data_tags(&gate.on_data(key, 1, payload(1))), vec![1]);
            assert!(gate.on_data(key, 3, payload(3)).is_empty());
            let mut released = Vec::new();
            if gap_first {
                released.extend(gate.on_gap(key, 2, 3, std::iter::empty()));
                released.extend(gate.on_heartbeat(key, 5));
            } else {
                released.extend(gate.on_heartbeat(key, 5));
                released.extend(gate.on_gap(key, 2, 3, std::iter::empty()));
            }
            data_tags(&released)
        };
        assert_eq!(run(true), vec![3]);
        assert_eq!(run(false), vec![3]);
    }

    /// A HEARTBEAT whose firstSN is past a sequence never received does not
    /// stall the gate: what it passes is crossed, and what follows is
    /// delivered (both seeds).
    #[test]
    fn a_missing_sample_below_first_heartbeat_does_not_stall_the_gate() {
        for seed_on_first_data in [true, false] {
            let mut gate = ReorderGate::new(true, seed_on_first_data);
            let key = [8u8; 16];
            if seed_on_first_data {
                assert_eq!(data_tags(&gate.on_data(key, 1, payload(1))), vec![1]);
            }
            // Nothing else ever arrives below 9; the writer keeps only 9 on.
            let released = gate.on_heartbeat(key, 9);
            assert!(
                released.is_empty(),
                "seed_on_first_data={seed_on_first_data}: nothing held below firstSN"
            );
            let out = gate.on_data(key, 9, payload(9));
            assert_eq!(
                data_tags(&out),
                vec![9],
                "seed_on_first_data={seed_on_first_data}: the gate does not wait for 2..8"
            );
        }
    }

    fn payload(tag: u8) -> PendingPayload {
        PendingPayload {
            order: None,
            order_token: None,
            version: CdrVersion::Xcdr2,
            remote_seq: tag as u64,
            source_ts_ns: None,
            slot: None,
            prepared: crate::dds::reader::admission::Prepared::Discard,
            staged: None,
        }
    }

    /// The tag of each payload: its sequence (`payload`).
    fn data_tags(out: &[PendingPayload]) -> Vec<u8> {
        out.iter()
            .map(|p| u8::try_from(p.remote_seq).expect("a tag"))
            .collect()
    }

    #[test]
    fn places_to_keep_counts_the_awaited_sequences_below() {
        let mut gate = ReorderGate::new(true, false);
        let key = [2u8; 16];
        assert_eq!(
            gate.places_to_keep(&key, 5),
            None,
            "no HEARTBEAT: gap unknown"
        );
        let _ = gate.on_heartbeat(key, 1);
        assert_eq!(gate.places_to_keep(&key, 1), Some(0), "the awaited one");
        assert_eq!(gate.places_to_keep(&key, 5), Some(4), "1..=4 awaited");
        assert!(gate.on_data(key, 10, payload(10)).is_empty(), "held");
        assert_eq!(
            gate.places_to_keep(&key, 5),
            Some(4),
            "a held sample above does not count"
        );
        assert_eq!(
            gate.places_to_keep(&key, 12),
            Some(10),
            "1..=11 but 10, held already"
        );
    }

    #[test]
    fn a_held_change_gapped_after_is_counted_once() {
        let mut gate = ReorderGate::new(true, false);
        let key = [4u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.on_data(key, 3, payload(3)).is_empty(), "held");
        assert!(gate.on_gap(key, 3, 4, Vec::new()).is_empty(), "1 awaited");
        assert_eq!(
            gate.places_to_keep(&key, 5),
            Some(3),
            "1, 2 and 4 awaited: 3 is held, not also declared"
        );
        assert_eq!(data_tags(&gate.on_data(key, 1, payload(1))), vec![1]);
        assert_eq!(data_tags(&gate.on_data(key, 2, payload(2))), vec![2, 3]);
    }

    #[test]
    fn places_owed_count_the_other_writers_gaps() {
        let mut gate = ReorderGate::new(true, false);
        let (a, b) = ([2u8; 16], [3u8; 16]);
        let _ = gate.on_heartbeat(a, 1);
        let _ = gate.on_heartbeat(b, 1);
        assert_eq!(gate.places_owed_except(&a), 0, "nothing held");
        assert!(gate.on_data(a, 3, payload(3)).is_empty(), "held");
        assert!(gate.on_data(a, 5, payload(5)).is_empty(), "held");
        assert_eq!(gate.places_owed_except(&b), 3, "1, 2 and 4 awaited");
        assert_eq!(gate.places_owed_except(&a), 0, "its own gap is not owed");
        assert!(gate.on_data(b, 2, payload(2)).is_empty(), "held");
        assert_eq!(gate.places_owed_except(&a), 1, "b's 1 awaited");
        assert_eq!(gate.on_data(a, 1, payload(1)).len(), 1, "1 released");
        assert_eq!(gate.places_owed_except(&b), 2, "2 and 4 awaited");
    }

    /// The running total `places_owed_except` reads is the sum, writer by
    /// writer, of what each awaits below its highest held sample, through
    /// every way a writer's state moves.
    #[test]
    fn places_owed_follow_every_move_of_the_gate() {
        fn check(gate: &ReorderGate, step: &str) {
            for asking in [[1u8; 16], [2; 16], [3; 16], [9; 16]] {
                let expected: usize = gate
                    .writers
                    .iter()
                    .filter(|(key, _)| **key != asking)
                    .map(|(_, state)| ReorderGate::places_owed(state))
                    .sum();
                assert_eq!(gate.places_owed_except(&asking), expected, "{step}");
            }
        }
        let mut gate = ReorderGate::new(true, false);
        let (a, b, c) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let _ = gate.on_heartbeat(a, 1);
        let _ = gate.on_heartbeat(b, 1);
        let _ = gate.on_data(a, 4, payload(4));
        let _ = gate.on_data(a, 9, payload(9));
        let _ = gate.on_data(b, 3, payload(3));
        // Held before any HEARTBEAT: no base, nothing owed yet.
        let _ = gate.on_data(c, 7, payload(7));
        check(&gate, "held");
        let _ = gate.on_heartbeat(c, 2);
        check(&gate, "seeded by a heartbeat");
        let _ = gate.on_data(a, 1, payload(1));
        check(&gate, "a repair");
        let _ = gate.on_gap(a, 2, 4, std::iter::empty());
        check(&gate, "a gap");
        let _ = gate.on_non_data(b, 1);
        check(&gate, "a sample-less change");
        let _ = gate.catch_up(b, 2);
        check(&gate, "caught up");
        let _ = gate.on_heartbeat(a, 8);
        check(&gate, "history purged");
        gate.forget_writer(&c);
        check(&gate, "a writer forgotten");
        let _ = gate.on_staged(b, 6, payload(6));
        check(&gate, "a staged sample");
    }

    #[test]
    fn a_gap_is_what_the_gate_awaits_below_what_it_holds() {
        let mut gate = ReorderGate::new(true, false);
        let (a, b) = ([1u8; 16], [2u8; 16]);
        let _ = gate.on_heartbeat(a, 2);
        let _ = gate.on_heartbeat(b, 1);
        assert!(!gate.has_gap(&a), "nothing held");
        assert!(gate.on_data(a, 5, payload(5)).is_empty(), "held");
        assert!(gate.on_data(a, 3, payload(3)).is_empty(), "held");
        assert!(gate.has_gap(&a));
        assert!(!gate.has_gap(&b));
        let awaited: Vec<u64> = (0..8).filter(|&seq| gate.awaits(&a, seq)).collect();
        assert_eq!(
            awaited,
            vec![2, 4],
            "below 2 delivered, 3 and 5 held, above 5 not owed"
        );
        assert!(!gate.awaits(&b, 1), "no gap");
    }

    #[test]
    fn passthrough_when_disabled() {
        let mut gate = ReorderGate::new(false, false);
        let key = [1u8; 16];
        // No heartbeat needed, no buffering, samples flow through.
        let out = gate.on_data(key, 5, payload(0x10));
        assert_eq!(data_tags(&out), vec![0x10]);
        let out = gate.on_data(key, 3, payload(0x20)); // out-of-order ignored
        assert_eq!(data_tags(&out), vec![0x20]);
    }

    #[test]
    fn hb_seeds_then_in_order_passes_immediately() {
        let mut gate = ReorderGate::new(true, false);
        let key = [2u8; 16];
        let drained = gate.on_heartbeat(key, 1);
        assert!(drained.is_empty());
        let out = gate.on_data(key, 1, payload(0xA1));
        assert_eq!(data_tags(&out), vec![0xA1]);
        let out = gate.on_data(key, 2, payload(0xA2));
        assert_eq!(data_tags(&out), vec![0xA2]);
    }

    #[test]
    fn out_of_order_is_buffered_until_gap_fills() {
        let mut gate = ReorderGate::new(true, false);
        let key = [3u8; 16];
        gate.on_heartbeat(key, 1);
        // Seqs arrive 3,4,2,1 -- we should only release once 1 fills.
        assert!(gate.on_data(key, 3, payload(3)).is_empty());
        assert!(gate.on_data(key, 4, payload(4)).is_empty());
        assert!(gate.on_data(key, 2, payload(2)).is_empty());
        let out = gate.on_data(key, 1, payload(1));
        assert_eq!(data_tags(&out), vec![1, 2, 3, 4]);
    }

    #[test]
    fn data_before_hb_is_held_then_released_in_order() {
        let mut gate = ReorderGate::new(true, false);
        let key = [4u8; 16];
        // Late-joiner: live multicast arrives first, history second, HB
        // somewhere along the way.
        assert!(gate.on_data(key, 30, payload(30)).is_empty());
        assert!(gate.on_data(key, 31, payload(31)).is_empty());
        // Now HB arrives announcing first_seq=1; the buffered 30/31 stay
        // pending until seqs 1..29 arrive.
        let drained = gate.on_heartbeat(key, 1);
        assert!(drained.is_empty());
        // History 1..29 trickles in out of order.
        for seq in (1u64..=29).rev() {
            let out = gate.on_data(key, seq, payload((seq & 0xFF) as u8));
            if seq == 1 {
                // Seq 1 unblocks the whole contiguous prefix 1..31. The
                // tag for seq N is `(N & 0xFF) as u8` for 1..=29 and was
                // captured as `30`/`31` for the early arrivals at the top
                // of this test.
                let tags = data_tags(&out);
                assert_eq!(tags.len(), 31);
                assert_eq!(tags[0], 1);
                assert_eq!(tags[28], 29);
                assert_eq!(tags[29], 30);
                assert_eq!(tags[30], 31);
            } else {
                assert!(out.is_empty(), "seq={} should still be buffered", seq);
            }
        }
    }

    #[test]
    fn second_heartbeat_does_not_rewind() {
        let mut gate = ReorderGate::new(true, false);
        let key = [5u8; 16];
        gate.on_heartbeat(key, 10);
        let out = gate.on_data(key, 10, payload(10));
        assert_eq!(data_tags(&out), vec![10]);
        // Another HB with first_seq=5 should NOT cause us to expect seq 5
        // again -- we've already moved past it.
        let drained = gate.on_heartbeat(key, 5);
        assert!(drained.is_empty());
        let out = gate.on_data(key, 11, payload(11));
        assert_eq!(data_tags(&out), vec![11]);
    }

    #[test]
    fn samples_received_before_a_higher_first_heartbeat_are_delivered() {
        // 1 and 2 arrive before any HEARTBEAT; the first one says the
        // writer's history now starts at 100. They were RECEIVED:
        // `lost_changes_update` touches only MISSING/UNKNOWN changes (RTPS
        // 2.5 8.4.10.4), so they are delivered, in order, and the gate then
        // waits at 100. (This test used to assert they were discarded as
        // "a previous incarnation" - the spec has no such rule.)
        let mut gate = ReorderGate::new(true, false);
        let key = [6u8; 16];
        assert!(gate.on_data(key, 1, payload(1)).is_empty());
        assert!(gate.on_data(key, 2, payload(2)).is_empty());
        let drained = gate.on_heartbeat(key, 100);
        assert_eq!(data_tags(&drained), vec![1, 2]);
        let out = gate.on_data(key, 100, payload(100));
        assert_eq!(data_tags(&out), vec![100]);
    }

    #[test]
    fn duplicate_arrival_after_delivery_is_dropped() {
        let mut gate = ReorderGate::new(true, false);
        let key = [7u8; 16];
        gate.on_heartbeat(key, 1);
        let _ = gate.on_data(key, 1, payload(1));
        let _ = gate.on_data(key, 2, payload(2));
        // Retransmit of seq 1 -- already delivered.
        let out = gate.on_data(key, 1, payload(0xFF));
        assert!(out.is_empty());
    }

    #[test]
    fn delivery_frontier_is_exactly_once_for_every_four_sample_arrival_order() {
        const ORDERS: [[u64; 4]; 24] = [
            [1, 2, 3, 4],
            [1, 2, 4, 3],
            [1, 3, 2, 4],
            [1, 3, 4, 2],
            [1, 4, 2, 3],
            [1, 4, 3, 2],
            [2, 1, 3, 4],
            [2, 1, 4, 3],
            [2, 3, 1, 4],
            [2, 3, 4, 1],
            [2, 4, 1, 3],
            [2, 4, 3, 1],
            [3, 1, 2, 4],
            [3, 1, 4, 2],
            [3, 2, 1, 4],
            [3, 2, 4, 1],
            [3, 4, 1, 2],
            [3, 4, 2, 1],
            [4, 1, 2, 3],
            [4, 1, 3, 2],
            [4, 2, 1, 3],
            [4, 2, 3, 1],
            [4, 3, 1, 2],
            [4, 3, 2, 1],
        ];

        for order in ORDERS {
            let mut gate = ReorderGate::new(true, false);
            let key = [0x71; 16];
            gate.on_heartbeat(key, 1);
            let mut delivered = Vec::new();

            for seq in order {
                delivered.extend(gate.on_data(key, seq, payload(seq as u8)));
                // A retransmit may replace the still-buffered copy, but it
                // must never create a second delivery frontier entry.
                delivered.extend(gate.on_data(key, seq, payload(seq as u8)));
            }

            assert_eq!(
                data_tags(&delivered),
                vec![1, 2, 3, 4],
                "arrival order {order:?} did not deliver one contiguous frontier"
            );

            for seq in 1..=4 {
                assert!(
                    gate.on_data(key, seq, payload(seq as u8)).is_empty(),
                    "arrival order {order:?} re-delivered sequence {seq}"
                );
            }
        }
    }

    #[test]
    fn pending_cap_forces_progress_and_shrinks_map() {
        // Fill the gate well past the cap while the base sample never
        // arrives; the cap must drain rather than allow unbounded growth.
        let mut gate = ReorderGate::new(true, false);
        let key = [10u8; 16];
        gate.on_heartbeat(key, 1);
        // Seq 1 never arrives. Push 2..=MAX_PENDING_PER_WRITER + 50 out
        // of order; the cap should kick in.
        for seq in 2u64..=(MAX_PENDING_PER_WRITER as u64 + 50) {
            let _ = gate.on_data(key, seq, payload((seq & 0xFF) as u8));
        }
        let state = gate.writers.get(&key).expect("writer state");
        assert!(
            state.pending.len() <= MAX_PENDING_PER_WRITER,
            "pending should have been drained at the cap, got len={}",
            state.pending.len()
        );
        // After forced progress the base advanced past seq 1, but the
        // exact value depends on when the cap tripped; what matters is
        // that the map is bounded and `next_seq` moved forward.
        assert!(state.next_seq.expect("next seeded") > 1);
    }

    #[test]
    fn hb_advances_base_when_writer_purges_history() {
        // RTPS v2.5 sec. 8.4.2.2.1.2: a writer that has purged sample N from
        // its cache reports the new floor via the next HEARTBEAT's
        // `firstSN`. The reader must skip the gap and resume from the
        // new floor rather than block waiting for purged samples.
        let mut gate = ReorderGate::new(true, false);
        let key = [11u8; 16];
        gate.on_heartbeat(key, 1);
        // Reader gets stuck waiting on seq 1; seqs 2..5 buffer up.
        for s in 2u64..=5 {
            assert!(gate.on_data(key, s, payload(s as u8)).is_empty());
        }
        // Writer purges, advertises first_seq=4 in the next HB. Seq 1 never
        // arrived: lost. Seqs 2 and 3 DID arrive: delivered, ahead of 4 and
        // 5 (RTPS 2.5 8.4.10.4 `lost_changes_update` changes only MISSING
        // or UNKNOWN changes). This test used to expect [4, 5].
        let released = gate.on_heartbeat(key, 4);
        assert_eq!(data_tags(&released), vec![2, 3, 4, 5]);
    }

    #[test]
    fn writers_are_independent() {
        let mut gate = ReorderGate::new(true, false);
        let k1 = [8u8; 16];
        let k2 = [9u8; 16];
        gate.on_heartbeat(k1, 1);
        gate.on_heartbeat(k2, 100);
        let out1 = gate.on_data(k1, 1, payload(1));
        assert_eq!(data_tags(&out1), vec![1]);
        let out2 = gate.on_data(k2, 100, payload(100));
        assert_eq!(data_tags(&out2), vec![100]);
    }

    // -------------------------------------------------------------------------
    // GAP unit tests (RTPS v2.5 sec 8.3.8.4)
    // -------------------------------------------------------------------------

    /// GAP_CONTIGUOUS: writer declares seqs [1,35] irrelevant; live samples
    /// 37,38,39 were buffered before the GAP arrived.  After on_gap, next_seq
    /// must skip to 36 (first seq AFTER the declared-lost run: gap_start=1,
    /// gap_list covers 1..=35 so base advances to 36).  Then seq 36 is not in
    /// pending, so drain stops there -- we cannot release 37+ because 36 has
    /// not arrived yet.  A subsequent on_gap for seq 36 (or on_data(36)) then
    /// drains 37/38/39.
    ///
    /// Concrete late-joiner scenario: HB firstSN=1 lastSN=36; GAP gapStart=1
    /// gapList.base=36 covers [1,35] (all in history purge range); live data
    /// starts at 37.  After GAP next_seq must be 36 so that when seq 36 also
    /// arrives the drain releases 37,38,39 in order.
    #[test]
    fn gap_contiguous_unblocks_buffered_live_samples() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x20u8; 16];

        // HEARTBEAT seeds next_seq = 1.
        gate.on_heartbeat(key, 1);

        // Live samples 37/38/39 arrive before the GAP (out-of-order).
        assert!(gate.on_data(key, 37, payload(37)).is_empty());
        assert!(gate.on_data(key, 38, payload(38)).is_empty());
        assert!(gate.on_data(key, 39, payload(39)).is_empty());

        // GAP: seqs 1..=35 declared irrelevant (gapStart=1, bitmap covers
        // 2..=35). gap_list_base = gap_start + 1 keeps the pre-range
        // semantics: only the bitmap carries the extra sequences.
        let gap_extra: Vec<u64> = (2u64..=35).collect();
        let released = gate.on_gap(key, 1, 2, gap_extra);

        // Nothing drains yet: next_seq is now 36, but 36 is not in pending.
        assert!(
            released.is_empty(),
            "seq 36 not yet received, nothing drains"
        );
        assert_eq!(
            gate.writers.get(&key).and_then(|s| s.next_seq),
            Some(36),
            "next_seq must advance to 36 after GAP covering 1..=35"
        );

        // seq 36 arrives -> drains 36,37,38,39.
        let out = gate.on_data(key, 36, payload(36));
        assert_eq!(
            data_tags(&out),
            vec![36, 37, 38, 39],
            "seq 36 arrival must drain the contiguous prefix"
        );
    }

    /// GAP_NONCONTIGUOUS: GAP covers seqs 1 and 3 (non-contiguous; 2 is NOT
    /// in the gap list).  After on_gap, next_seq must advance past 1 but stop
    /// at 2 (still needed).  Seq 2 arriving then unblocks the drain.
    #[test]
    fn gap_non_contiguous_leaves_uncovered_seqs_gated() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x21u8; 16];

        gate.on_heartbeat(key, 1);

        // Live samples 3,4,5 buffered.
        assert!(gate.on_data(key, 3, payload(3)).is_empty());
        assert!(gate.on_data(key, 4, payload(4)).is_empty());
        assert!(gate.on_data(key, 5, payload(5)).is_empty());

        // GAP: gapStart=1, gapList contains {3} (seq 2 is NOT declared
        // irrelevant). gap_list_base = gap_start + 1 keeps the pre-range
        // semantics: only the bitmap carries the extra sequence.
        let released = gate.on_gap(key, 1, 2, vec![3u64]);

        // Seq 3, declared irrelevant, was received: it stays held.
        // next_seq advances past 1 -> 2 (stops because 2 not in lost set).
        // Pending has {4,5}; drain does not fire (base=2 not in pending).
        assert!(
            released.is_empty(),
            "seq 2 not yet received, gate must hold"
        );
        assert_eq!(
            gate.writers.get(&key).and_then(|s| s.next_seq),
            Some(2),
            "next_seq stops at 2 because it was NOT in the GAP"
        );

        // Seq 2 arrives -> drain: 2, then 3, received before the GAP that
        // declared it, then 4 and 5.
        let out2 = gate.on_data(key, 2, payload(2));
        assert_eq!(data_tags(&out2), vec![2, 3, 4, 5], "3 was received");
        assert!(gate.on_gap(key, 3, 4, vec![]).is_empty(), "nothing left");
    }

    /// GAP_REAL_BASE: late-joiner GAP shape (a writer retiring its whole
    /// pre-join window in one contiguous run). GAP(gapStart=1,
    /// gapList.base=67, no bitmap) declares the WHOLE pre-join window
    /// [1,67) irrelevant in a single contiguous run -- the bug to avoid
    /// is Arm 1 dropping `gap_list_base` and treating only `gap_start`
    /// (seq 1) as irrelevant, which stalls the gate at next_seq=2 forever.
    #[test]
    fn gap_real_base_jumps_next_seq_directly_seeded() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x30u8; 16];

        // HEARTBEAT seeds next_seq = 1.
        gate.on_heartbeat(key, 1);

        let released = gate.on_gap(key, 1, 67, std::iter::empty());
        assert!(released.is_empty(), "nothing buffered yet to release");
        assert_eq!(
            gate.writers.get(&key).and_then(|s| s.next_seq),
            Some(67),
            "next_seq must jump straight to gap_list_base, not gap_start + 1"
        );

        // Seq 67 now delivers immediately, no further stall.
        let out = gate.on_data(key, 67, payload(67));
        assert_eq!(data_tags(&out), vec![67]);
    }

    /// `on_gap` is `pub` and takes u64s it does not control. At the top of
    /// the range `gap_start + 1` overflowed, which panics in checked builds
    /// (tests, debug); the bitmap walk's `base += 1` could too. The decoder
    /// no longer produces such values (it refuses a sequence number above
    /// i64::MAX), and this function must not depend on that to not panic.
    #[test]
    fn on_gap_at_the_top_of_the_range_does_not_panic() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x3Au8; 16];
        let _ = gate.on_gap(key, u64::MAX, u64::MAX, std::iter::once(u64::MAX));
        let _ = gate.on_gap(key, u64::MAX - 1, 5, [u64::MAX - 1, u64::MAX]);
    }

    /// Same GAP shape arriving before any HEARTBEAT: the gate must seed at
    /// `gap_list_base` directly so a late joiner never waits for purged
    /// history the writer already declared gone.
    #[test]
    fn gap_real_base_seeds_unseeded_gate_directly() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x31u8; 16];

        let released = gate.on_gap(key, 1, 67, std::iter::empty());
        assert!(released.is_empty());
        assert_eq!(
            gate.writers.get(&key).and_then(|s| s.next_seq),
            Some(67),
            "unseeded gate must seed directly at gap_list_base"
        );

        let out = gate.on_data(key, 67, payload(67));
        assert_eq!(data_tags(&out), vec![67]);
    }

    /// GAP_UNION_HOLE: range [2,5) covers {2,3,4}; the bitmap {6,8} does
    /// NOT include 5, so the union has a hole at 5 and next_seq must stop
    /// there (walking the range does not "spill over" into an unrelated
    /// bitmap entry).
    #[test]
    fn gap_range_and_bitmap_union_stops_at_hole() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x32u8; 16];

        gate.on_heartbeat(key, 2);
        let released = gate.on_gap(key, 2, 5, vec![6u64, 8u64]);
        assert!(released.is_empty());
        assert_eq!(
            gate.writers.get(&key).and_then(|s| s.next_seq),
            Some(5),
            "union has a hole at 5: not in the range, not in the bitmap"
        );
    }

    /// GAP_UNION_CONTIGUOUS: range [2,5) covers {2,3,4}; the bitmap {5,6}
    /// continues the run contiguously past `gap_list_base`, so next_seq
    /// must walk all the way to 7.
    #[test]
    fn gap_range_and_bitmap_union_extends_past_base() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x33u8; 16];

        gate.on_heartbeat(key, 2);
        let released = gate.on_gap(key, 2, 5, vec![5u64, 6u64]);
        assert!(released.is_empty());
        assert_eq!(
            gate.writers.get(&key).and_then(|s| s.next_seq),
            Some(7),
            "bitmap continues the contiguous run past gap_list_base"
        );
    }

    /// GAP_RANGE_PENDING_DISCARD: pending samples that fall inside the
    /// declared range must be discarded; samples outside it must survive
    /// and drain once the gate reaches them.
    #[test]
    fn gap_range_keeps_what_it_holds_inside_and_outside() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x34u8; 16];

        gate.on_heartbeat(key, 2);
        // Seq 3 falls inside the upcoming [2,5) range; seq 6 falls outside.
        assert!(gate.on_data(key, 3, payload(3)).is_empty());
        assert!(gate.on_data(key, 6, payload(6)).is_empty());

        // 2 is crossed, 3 was received: delivered; 4 crossed; 5 not yet.
        let released = gate.on_gap(key, 2, 5, std::iter::empty());
        assert_eq!(
            data_tags(&released),
            vec![3],
            "a change received before its GAP is delivered, not dropped"
        );

        // Seq 5 arrives -> drains 5, then 6.
        let out = gate.on_data(key, 5, payload(5));
        assert_eq!(data_tags(&out), vec![5, 6]);
    }

    /// GAP_HUGE_RANGE: a hostile/buggy GAP with a huge range must not
    /// materialize the range into a set -- `next_seq` jumps directly to
    /// the base, so this test completes instantly instead of allocating
    /// (or looping over) 2^40 entries.
    #[test]
    fn gap_huge_range_completes_without_materializing() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x35u8; 16];

        gate.on_heartbeat(key, 1);
        let huge_base: u64 = 1u64 << 40;
        let released = gate.on_gap(key, 1, huge_base, std::iter::empty());
        assert!(released.is_empty());
        assert_eq!(
            gate.writers.get(&key).and_then(|s| s.next_seq),
            Some(huge_base),
            "next_seq must jump straight to the huge base, no per-seq walk"
        );
    }

    /// NO_GAP_REGRESSION: a publisher that sends NO GAP (e.g.
    /// HDDS-self) must behave identically to before -- purely
    /// HEARTBEAT + DATA flow, on_gap never called.
    #[test]
    fn no_gap_flow_unchanged() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x22u8; 16];

        gate.on_heartbeat(key, 1);

        // In-order flow: 1,2,3 delivered one by one.
        let out1 = gate.on_data(key, 1, payload(1));
        assert_eq!(data_tags(&out1), vec![1]);
        let out2 = gate.on_data(key, 2, payload(2));
        assert_eq!(data_tags(&out2), vec![2]);
        let out3 = gate.on_data(key, 3, payload(3));
        assert_eq!(data_tags(&out3), vec![3]);

        // Out-of-order: 5,4 arrive; then 4 fills the gap.
        assert!(gate.on_data(key, 5, payload(5)).is_empty());
        let out4 = gate.on_data(key, 4, payload(4));
        assert_eq!(data_tags(&out4), vec![4, 5]);

        // State: next_seq == 6, pending empty, no on_gap ever called.
        let state = gate.writers.get(&key).expect("writer state");
        assert_eq!(state.next_seq, Some(6));
        assert!(state.pending.is_empty());
    }

    #[test]
    fn non_data_sequence_releases_following_application_samples() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x40u8; 16];
        gate.on_heartbeat(key, 1);

        assert!(gate.on_data(key, 2, payload(2)).is_empty());
        assert!(gate.on_data(key, 3, payload(3)).is_empty());

        let released = gate.on_non_data(key, 1);
        assert_eq!(released.len(), 3, "1, which delivers nothing, then 2 and 3");
        assert_eq!(released[0].remote_seq, 1);
        assert_eq!(data_tags(&released[1..]), vec![2, 3]);
        assert_eq!(
            gate.writers.get(&key).and_then(|state| state.next_seq),
            Some(4)
        );
    }

    // =====================================================================
    // VOLATILE + RELIABLE mode (seed_on_first_data = true)
    // =====================================================================

    #[test]
    fn volatile_seeds_at_first_data_and_passes_in_order() {
        let mut gate = ReorderGate::new(true, true);
        let key = [20u8; 16];
        let out = gate.on_data(key, 50, payload(50));
        assert_eq!(data_tags(&out), vec![50]);
        let out = gate.on_data(key, 51, payload(51));
        assert_eq!(data_tags(&out), vec![51]);
        let out = gate.on_data(key, 52, payload(52));
        assert_eq!(data_tags(&out), vec![52]);
    }

    #[test]
    fn volatile_drops_stale_retransmit_below_join_point() {
        let mut gate = ReorderGate::new(true, true);
        let key = [21u8; 16];
        for seq in 50u64..=55 {
            let out = gate.on_data(key, seq, payload(seq as u8));
            assert_eq!(data_tags(&out), vec![seq as u8]);
        }
        let out = gate.on_data(key, 1, payload(0xFF));
        assert!(out.is_empty(), "pre-join retransmit must be dropped");
        let out = gate.on_data(key, 56, payload(56));
        assert_eq!(data_tags(&out), vec![56]);
    }

    #[test]
    fn deferred_observation_cannot_rewind_a_released_stream() {
        let mut gate = ReorderGate::new(true, true);
        let key = [25u8; 16];
        gate.on_deferred(key, 2);
        assert_eq!(data_tags(&gate.on_data(key, 2, payload(2))), vec![2]);
        gate.on_deferred(key, 1);
        assert!(gate.on_data(key, 1, payload(1)).is_empty());
        assert_eq!(data_tags(&gate.on_data(key, 3, payload(3))), vec![3]);
    }

    #[test]
    fn volatile_holds_genuine_post_join_gap_until_filled() {
        let mut gate = ReorderGate::new(true, true);
        let key = [22u8; 16];
        let out = gate.on_data(key, 50, payload(50));
        assert_eq!(data_tags(&out), vec![50]);
        let out = gate.on_data(key, 52, payload(52));
        assert!(out.is_empty(), "gap must hold 52 until 51 arrives");
        let out = gate.on_data(key, 51, payload(51));
        assert_eq!(data_tags(&out), vec![51, 52]);
    }

    #[test]
    fn volatile_ignores_heartbeat_seeding() {
        let mut gate = ReorderGate::new(true, true);
        let key = [23u8; 16];
        let drained = gate.on_heartbeat(key, 1);
        assert!(drained.is_empty());
        let out = gate.on_data(key, 40, payload(40));
        assert_eq!(data_tags(&out), vec![40]);
        let out = gate.on_data(key, 1, payload(0xFF));
        assert!(out.is_empty());
    }

    // RTPS 2.5 8.4.12.1 T2: the best-effort reader's acceptance rule.

    const W1: [u8; 16] = [9u8; 16];

    fn be_payload(seq: u64) -> PendingPayload {
        payload(u8::try_from(seq).expect("test sequence numbers are small"))
    }

    #[test]
    fn a_best_effort_gate_delivers_without_any_heartbeat() {
        let mut gate = ReorderGate::new_best_effort();
        for seq in 1..=3 {
            assert_eq!(gate.on_data(W1, seq, be_payload(seq)).len(), 1, "seq {seq}");
        }
    }

    #[test]
    fn a_best_effort_gate_skips_a_hole_and_discards_what_comes_late() {
        let mut gate = ReorderGate::new_best_effort();
        assert_eq!(gate.on_data(W1, 1, be_payload(1)).len(), 1);
        assert_eq!(
            gate.on_data(W1, 3, be_payload(3)).len(),
            1,
            "2 is lost, not awaited"
        );
        assert!(
            gate.on_data(W1, 2, be_payload(2)).is_empty(),
            "older: discarded"
        );
        assert!(
            gate.on_data(W1, 3, be_payload(3)).is_empty(),
            "duplicate: discarded"
        );
        assert_eq!(gate.on_data(W1, 4, be_payload(4)).len(), 1);
    }

    #[test]
    fn a_best_effort_gate_has_no_heartbeat_nor_gap_transition() {
        let mut gate = ReorderGate::new_best_effort();
        assert_eq!(gate.on_data(W1, 5, be_payload(5)).len(), 1);
        assert!(gate.on_heartbeat(W1, 10).is_empty());
        assert!(gate.on_gap(W1, 6, 9, std::iter::empty()).is_empty());
        assert_eq!(
            gate.on_data(W1, 6, be_payload(6)).len(),
            1,
            "neither the HEARTBEAT nor the GAP moved what it accepts"
        );
    }

    /// a staged sample the gate passed while it waited outside (here a
    /// HEARTBEAT whose firstSN moved beyond it) is released, not dropped; a
    /// staged sample the gate has not reached is held like any other.
    #[test]
    fn a_staged_sample_the_gate_passed_is_released() {
        let mut gate = ReorderGate::new(true, false);
        let key = [3u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        let _ = gate.on_heartbeat(key, 5);
        assert_eq!(data_tags(&gate.on_staged(key, 2, payload(2))), vec![2]);
        assert!(gate.on_staged(key, 6, payload(6)).is_empty(), "held");
        assert_eq!(data_tags(&gate.on_staged(key, 5, payload(5))), vec![5, 6]);
    }

    /// a VOLATILE gate's join floor is where it joined: the start of
    /// the first staged set observed, the first DATA it took, or the GAP that
    /// seeded it. Older history, staged or not, is dropped below it, whether
    /// or not the gate is seeded yet.
    #[test]
    fn a_volatile_gate_drops_history_below_its_join_floor() {
        let mut gate = ReorderGate::new(true, true);
        let key = [5u8; 16];
        gate.observe(key, 6, Some(5));
        gate.observe(key, 5, Some(5));
        // A set start of 0 is no sequence number: the sample's own counts.
        let zero = [12u8; 16];
        gate.observe(zero, 4, Some(0));
        assert!(gate.on_data(zero, 3, payload(3)).is_empty(), "below 4");
        gate.observe(key, 1, Some(1));
        assert!(
            gate.on_staged(key, 1, payload(1)).is_empty(),
            "pre-join, unseeded"
        );
        assert!(gate.on_data(key, 3, payload(3)).is_empty(), "pre-join DATA");
        assert_eq!(data_tags(&gate.on_staged(key, 5, payload(5))), vec![5]);
        assert_eq!(data_tags(&gate.on_staged(key, 6, payload(6))), vec![6]);
        // Seeded by a DATA that was not staged: the floor is that DATA.
        let other = [7u8; 16];
        assert_eq!(data_tags(&gate.on_data(other, 5, payload(5))), vec![5]);
        gate.observe(other, 1, None);
        assert!(gate.on_staged(other, 1, payload(1)).is_empty(), "pre-join");
        // Seeded by a GAP: the floor is where the GAP ends.
        let gapped = [8u8; 16];
        let _ = gate.on_gap(gapped, 1, 4, std::iter::empty());
        gate.observe(gapped, 2, None);
        assert!(gate.on_staged(gapped, 2, payload(2)).is_empty(), "declared");
    }

    /// A VOLATILE gate whose first change taken is a staged one (a set
    /// waiting for its end, or for room) is seeded by it, at the start of
    /// its set: the writer's next plain DATA waits behind the set instead of
    /// seeding the gate above it (DDS v1.4 Sec.2.2.3.6, 2.2.3.14). A
    /// HEARTBEAT before it seeds nothing; one whose firstSN passes the
    /// members never received crosses them, and the gate goes on.
    #[test]
    fn a_volatile_gate_is_seeded_by_its_first_staged_change() {
        for heartbeat_first in [false, true] {
            let mut gate = ReorderGate::new(true, true);
            let key = [13u8; 16];
            if heartbeat_first {
                assert!(gate.on_heartbeat(key, 1).is_empty());
                assert_eq!(gate.next_seq(&key), None, "a HEARTBEAT seeds nothing");
            }
            gate.observe(key, 12, Some(11));
            assert!(gate.hold_staged(&key, 12));
            assert_eq!(gate.next_seq(&key), Some(11), "seeded at the set start");
            gate.observe(key, 11, Some(11));
            assert!(gate.hold_staged(&key, 11));
            // The writer purges the set, acknowledged: its places hold.
            assert!(gate.on_heartbeat(key, 13).is_empty());
            assert_eq!(gate.next_seq(&key), Some(11), "staged places hold");
            assert!(gate.on_data(key, 13, payload(13)).is_empty(), "waits");
            assert!(gate.on_staged(key, 12, payload(12)).is_empty(), "waits");
            assert_eq!(
                data_tags(&gate.on_staged(key, 11, payload(11))),
                vec![11, 12, 13]
            );
        }
        // The seeding change alone holds its place: the writer purges it,
        // acknowledged, and its next plain DATA still waits for it.
        let mut gate = ReorderGate::new(true, true);
        let key = [16u8; 16];
        gate.observe(key, 11, Some(11));
        assert!(gate.hold_staged(&key, 11));
        assert!(gate.on_heartbeat(key, 12).is_empty());
        assert!(
            gate.on_data(key, 12, payload(12)).is_empty(),
            "waits for 11"
        );
        assert_eq!(
            data_tags(&gate.on_staged(key, 11, payload(11))),
            vec![11, 12]
        );
        // Below the floor: history from before the join, seeds nothing.
        let mut gate = ReorderGate::new(true, true);
        let key = [14u8; 16];
        gate.observe(key, 6, Some(5));
        assert!(gate.hold_staged(&key, 4));
        assert_eq!(gate.next_seq(&key), None);
        // Members never received, purged by the writer: crossed.
        let mut gate = ReorderGate::new(true, true);
        let key = [15u8; 16];
        gate.observe(key, 13, Some(11));
        assert!(gate.hold_staged(&key, 13));
        assert!(gate.on_heartbeat(key, 13).is_empty());
        assert_eq!(gate.next_seq(&key), Some(13));
        assert_eq!(data_tags(&gate.on_staged(key, 13, payload(13))), vec![13]);
        // A durable gate is still seeded only by its HEARTBEAT.
        let mut durable = ReorderGate::new(true, false);
        durable.observe(key, 13, Some(11));
        assert!(durable.hold_staged(&key, 13));
        assert_eq!(durable.next_seq(&key), None);
    }

    /// a gate seeded by a HEARTBEAT or a GAP has no join floor: the
    /// writer's history is owed to the reader. A staged sample received
    /// before the gate's first HEARTBEAT (or GAP) set its base above it is
    /// released.
    #[test]
    fn a_heartbeat_or_gap_seeded_gate_keeps_what_was_staged_before() {
        let mut gate = ReorderGate::new(true, false);
        let key = [6u8; 16];
        gate.observe(key, 1, Some(1));
        let _ = gate.on_heartbeat(key, 3);
        assert_eq!(data_tags(&gate.on_staged(key, 1, payload(1))), vec![1]);
        let gapped = [10u8; 16];
        let _ = gate.on_gap(gapped, 1, 4, std::iter::empty());
        assert_eq!(data_tags(&gate.on_staged(gapped, 1, payload(1))), vec![1]);
        // A later set staged first takes no floor either: the history the
        // writer then replays from the first HEARTBEAT's base is delivered.
        let replayed = [11u8; 16];
        gate.observe(replayed, 5, Some(5));
        let _ = gate.on_heartbeat(replayed, 1);
        assert_eq!(data_tags(&gate.on_staged(replayed, 1, payload(1))), vec![1]);
    }

    /// a BEST_EFFORT gate accepts a change on arrival (RTPS v2.5
    /// Sec.8.4.12.1, T2), staged ones included: a staged sample is released
    /// whatever the gate took since, and a DATA older than it, arriving
    /// after it, is refused.
    #[test]
    fn a_best_effort_gate_counts_a_staged_sample_on_arrival() {
        let mut gate = ReorderGate::new_best_effort();
        let key = [4u8; 16];
        gate.observe(key, 3, None);
        assert!(
            gate.on_data(key, 2, payload(2)).is_empty(),
            "older than staged 3"
        );
        assert_eq!(data_tags(&gate.on_data(key, 5, payload(5))), vec![5]);
        assert_eq!(data_tags(&gate.on_staged(key, 3, payload(3))), vec![3]);
        assert!(gate.on_data(key, 4, payload(4)).is_empty(), "T2 on arrival");
        let other = [9u8; 16];
        assert_eq!(data_tags(&gate.on_data(other, 5, payload(5))), vec![5]);
        gate.observe(other, 1, None);
        assert!(gate.on_staged(other, 1, payload(1)).is_empty());
    }
}

#[cfg(test)]
mod gap_before_heartbeat_tests {
    use super::*;

    fn payload(seq: u64) -> PendingPayload {
        PendingPayload {
            order: None,
            order_token: None,
            version: crate::dds::CdrVersion::Xcdr2,
            remote_seq: seq,
            source_ts_ns: None,
            slot: None,
            prepared: crate::dds::reader::admission::Prepared::Discard,
            staged: None,
        }
    }

    fn seqs(out: &[PendingPayload]) -> Vec<u64> {
        out.iter().map(|p| p.remote_seq).collect()
    }

    /// A GAP that does not start at the writer's first sequence, before its
    /// first HEARTBEAT, seeds no durable gate: the samples below it, held or
    /// still to come, are delivered once the HEARTBEAT seeds the gate, and
    /// the GAP's sequences are crossed then. Seeded at the GAP's end, the
    /// gate dropped them as delivered.
    #[test]
    fn a_gap_before_the_first_heartbeat_seeds_no_durable_gate() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x51u8; 16];
        assert!(gate.on_data(key, 2, payload(2)).is_empty(), "held");
        assert!(gate.on_gap(key, 3, 4, std::iter::empty()).is_empty());
        assert!(gate.on_data(key, 4, payload(4)).is_empty(), "held");
        assert_eq!(
            seqs(&gate.on_heartbeat(key, 1)),
            Vec::<u64>::new(),
            "1 awaited"
        );
        assert_eq!(seqs(&gate.on_data(key, 1, payload(1))), vec![1, 2, 4]);
    }

    /// A GAP above the base is crossed when the gate reaches it, however
    /// long, and owes no place.
    #[test]
    fn a_gap_above_the_base_is_crossed_and_owes_nothing() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x52u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.on_gap(key, 3, 1 << 40, std::iter::empty()).is_empty());
        assert!(
            gate.on_data(key, 1 << 40, payload(5)).is_empty(),
            "held above 2"
        );
        assert_eq!(gate.places_owed_except(&[0; 16]), 2, "only 1 and 2 awaited");
        assert!(gate.awaits(&key, 2));
        assert!(!gate.awaits(&key, 3));
        assert_eq!(seqs(&gate.on_data(key, 1, payload(1))), vec![1]);
        assert_eq!(
            seqs(&gate.on_data(key, 2, payload(2))),
            vec![2, 5],
            "the held one"
        );
    }

    /// A set {4..=7} staged and acknowledged, the writer purges it and
    /// announces firstSN 8: the gate stays at 4, and 8 waits for the set.
    /// DDS v1.4 Sec.2.2.3.14: never a newer value before an older one.
    #[test]
    fn a_heartbeat_past_staged_changes_keeps_their_order() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x61u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        for seq in 1..=3u64 {
            assert_eq!(seqs(&gate.on_data(key, seq, payload(seq))), vec![seq]);
        }
        for seq in 4..=7 {
            assert!(gate.hold_staged(&key, seq));
        }
        assert!(gate.on_heartbeat(key, 8).is_empty(), "4..=7 staged");
        assert_eq!(gate.next_seq(&key), Some(4));
        assert!(
            gate.on_data(key, 8, payload(8)).is_empty(),
            "behind the set"
        );
        for seq in 4..=6u64 {
            assert_eq!(seqs(&gate.on_staged(key, seq, payload(seq))), vec![seq]);
        }
        assert_eq!(seqs(&gate.on_staged(key, 7, payload(7))), vec![7, 8]);
    }

    /// What never arrived below firstSN is crossed around a staged change,
    /// and a sample held between them is released in its turn.
    #[test]
    fn a_heartbeat_crosses_the_purged_changes_around_a_staged_one() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x62u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.hold_staged(&key, 3));
        assert!(gate.on_data(key, 5, payload(5)).is_empty());
        // 1, 2, 4 and 6 never arrived; the writer purged up to 6.
        assert!(gate.on_heartbeat(key, 7).is_empty(), "waits at 3");
        assert_eq!(gate.next_seq(&key), Some(3));
        assert_eq!(gate.places_owed_by_all(), 1, "3 owed, 5 held, 4 lost");
        assert!(!gate.awaits(&key, 4), "4 is lost, not awaited");
        assert!(
            gate.misses_for_good(&key, 4, 4, &std::collections::BTreeSet::new()),
            "a set holding 4 can never be whole"
        );
        assert_eq!(seqs(&gate.on_staged(key, 3, payload(3))), vec![3, 5]);
        assert_eq!(gate.next_seq(&key), Some(7));
        assert_eq!(seqs(&gate.on_data(key, 7, payload(7))), vec![7]);
    }

    /// A staged change given up (its set rejected or discarded) comes back
    /// as a change that delivers nothing, and the gate moves on.
    #[test]
    fn a_staged_change_given_up_frees_its_place() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x63u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.hold_staged(&key, 1));
        assert!(gate.hold_staged(&key, 2));
        assert!(gate.on_heartbeat(key, 4).is_empty());
        assert!(gate.on_data(key, 4, payload(4)).is_empty());
        assert_eq!(
            seqs(&gate.on_staged(key, 1, PendingPayload::nothing(1))),
            vec![1]
        );
        assert_eq!(
            seqs(&gate.on_staged(key, 2, PendingPayload::nothing(2))),
            vec![2, 4],
            "nothing for 2, then 4"
        );
        // No place left: a later purge moves the base at once.
        assert!(gate.on_heartbeat(key, 9).is_empty());
        assert_eq!(gate.next_seq(&key), Some(9));
    }

    /// A GAP that declares a staged change the reader's `keep`, read before
    /// the gate's lock, does not name yet still leaves its place.
    #[test]
    fn a_gap_keeps_a_staged_place_its_keep_set_missed() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x64u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.hold_staged(&key, 1));
        assert!(gate.on_gap(key, 1, 3, std::iter::empty()).is_empty());
        assert!(gate.on_data(key, 3, payload(3)).is_empty(), "waits for 1");
        assert_eq!(seqs(&gate.on_staged(key, 1, payload(1))), vec![1, 3]);
    }

    /// A change the gate passed before it was staged is refused its place:
    /// it is no change to deliver. A disabled, BEST_EFFORT or unseeded gate
    /// keeps no place.
    #[test]
    fn only_a_seeded_reliable_gate_holds_a_staged_place() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x65u8; 16];
        assert!(gate.hold_staged(&key, 1), "unknown writer");
        let _ = gate.on_heartbeat(key, 5);
        assert!(!gate.hold_staged(&key, 4), "passed");
        assert!(gate.hold_staged(&key, 5));
        let mut best_effort = ReorderGate::new_best_effort();
        let _ = best_effort.on_data(key, 3, payload(3));
        assert!(best_effort.hold_staged(&key, 1));
        let mut off = ReorderGate::new(false, false);
        assert!(off.hold_staged(&key, 1));
        // Forgotten, the writer keeps no place.
        gate.forget_writer(&key);
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.on_heartbeat(key, 6).is_empty());
        assert_eq!(gate.next_seq(&key), Some(6));
    }

    /// The GROUP seam step of a writer that replays its pre-join sets
    /// without their END markers gives up the places those sets hold, and
    /// the GAP over the hole crosses them; places at or above the floor stay.
    #[test]
    fn places_given_up_below_a_floor_are_crossed() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x67u8; 16];
        let _ = gate.on_heartbeat(key, 2);
        for seq in [2u64, 3, 5, 6] {
            assert!(gate.hold_staged(&key, seq));
        }
        assert!(gate.on_gap(key, 2, 5, std::iter::empty()).is_empty());
        assert_eq!(gate.next_seq(&key), Some(2), "held places stop the GAP");
        assert_eq!(gate.give_up_staged_places_below(&key, 5), 2);
        assert_eq!(gate.give_up_staged_places_below(&key, 5), 0);
        assert!(gate.on_gap(key, 2, 5, std::iter::empty()).is_empty());
        assert_eq!(gate.next_seq(&key), Some(5), "crossed");
        assert!(gate.on_heartbeat(key, 8).is_empty());
        assert_eq!(gate.next_seq(&key), Some(5), "5 and 6 still held");
        assert_eq!(gate.give_up_staged_places_below(&[0x68u8; 16], 9), 0);
    }

    /// A staged change handed back twice (its set's commit and its
    /// rejection) is delivered once, above the base or below it.
    #[test]
    fn a_staged_change_handed_back_twice_is_delivered_once() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x69u8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.hold_staged(&key, 1));
        assert!(gate.hold_staged(&key, 2));
        assert!(gate.on_staged(key, 2, payload(2)).is_empty());
        assert!(gate.on_staged(key, 2, payload(2)).is_empty(), "held once");
        assert_eq!(seqs(&gate.on_staged(key, 1, payload(1))), vec![1, 2]);
        assert!(
            gate.on_staged(key, 1, payload(1)).is_empty(),
            "below the base"
        );
        assert!(
            gate.on_staged(key, 2, payload(2)).is_empty(),
            "below the base"
        );
        // Passed while staged (a purge the gate crossed, no place held):
        // released once, below the base.
        assert!(gate.on_heartbeat(key, 9).is_empty());
        assert_eq!(seqs(&gate.on_staged(key, 5, payload(5))), vec![5]);
        assert!(gate.on_staged(key, 5, payload(5)).is_empty());
    }

    /// A coherent change that arrives after a purge crossed its sequence as
    /// never received (reported lost then) is refused its place, as one
    /// below the base is: final. What follows waits only for the places
    /// still held.
    #[test]
    fn a_change_staged_after_a_purge_crossed_it_is_refused() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x6Au8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.hold_staged(&key, 1));
        // 2 to 5 never arrived; the writer purged up to 5.
        assert!(gate.on_heartbeat(key, 6).is_empty());
        assert_eq!(gate.places_owed_by_all(), 0);
        // 3 arrives late, a set's member: lost, refused.
        assert!(gate.lost_ahead(&key, 3));
        assert!(!gate.hold_staged(&key, 3));
        assert!(
            gate.misses_for_good(&key, 3, 3, &std::collections::BTreeSet::new()),
            "a set holding 3 can never be whole"
        );
        assert!(gate.on_data(key, 6, payload(6)).is_empty());
        assert_eq!(gate.places_owed_by_all(), 1, "1 owed, 2 to 5 lost");
        assert_eq!(seqs(&gate.on_staged(key, 1, payload(1))), vec![1, 6]);
        assert_eq!(gate.next_seq(&key), Some(7));
    }

    /// A DATA that arrives after a purge crossed its sequence as never
    /// received (reported lost then) is dropped, not held: delivered, it
    /// was counted lost and delivered both, after what followed it before
    /// the place rule.
    #[test]
    fn a_data_after_a_purge_crossed_it_is_dropped() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x6Bu8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.hold_staged(&key, 1));
        // 2 to 5 never arrived; the writer purged up to 5.
        assert!(gate.on_heartbeat(key, 6).is_empty());
        // 4 arrives late, of no set; then 6.
        assert!(gate.on_data(key, 4, payload(4)).is_empty());
        assert_eq!(gate.held(&key), 0, "4 dropped");
        assert!(gate.on_data(key, 6, payload(6)).is_empty());
        assert_eq!(gate.places_owed_by_all(), 1, "1 owed, 2 to 5 lost");
        assert_eq!(seqs(&gate.on_staged(key, 1, payload(1))), vec![1, 6]);
        assert!(gate.on_heartbeat(key, 7).is_empty(), "nothing left below");
    }

    /// A GAP declares SN 3 irrelevant: the writer will not send it (RTPS
    /// v2.5 Sec.8.3.7.4; Sec.8.4.10.4, `irrelevant_change_set`). A stray copy
    /// of DATA(3) arriving later (a retransmission queued before the
    /// writer's decision, a reordered duplicate) never reaches the
    /// application.
    #[test]
    fn a_gap_declared_irrelevant_sn_must_not_be_delivered_if_it_arrives_late() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x7Du8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.on_gap(key, 3, 4, std::iter::empty()).is_empty());
        assert!(gate.on_data(key, 3, payload(3)).is_empty(), "dropped");
        assert_eq!(seqs(&gate.on_data(key, 1, payload(1))), vec![1]);
        let out = seqs(&gate.on_data(key, 2, payload(2)));
        assert_eq!(
            out,
            vec![2],
            "RTPS v2.5 Sec.8.3.7.4/8.4.10.4: a GAP declares a SN irrelevant, \
             the writer will never send it; got {out:?}"
        );
        assert!(!gate.hold_staged(&key, 3), "nor a place for a member");
    }

    /// Before the first HEARTBEAT too: a GAP declares 3 to 5, 4 arrives
    /// after it anyway, and is dropped; the gate, once seeded, crosses 3
    /// to 5.
    #[test]
    fn a_data_unseeded_inside_a_gap_is_dropped() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x6Cu8; 16];
        assert!(gate.on_gap(key, 3, 6, std::iter::empty()).is_empty());
        assert!(gate.on_data(key, 4, payload(4)).is_empty(), "dropped");
        assert_eq!(gate.held(&key), 0);
        assert!(!gate.hold_staged(&key, 5), "nor a place for a member");
        let _ = gate.on_heartbeat(key, 1);
        assert_eq!(seqs(&gate.on_data(key, 1, payload(1))), vec![1]);
        assert_eq!(seqs(&gate.on_data(key, 2, payload(2))), vec![2]);
        assert_eq!(gate.next_seq(&key), Some(6));
    }

    /// A change staged before the gate recorded a GAP over it (an unseeded
    /// gate keeps no place, and the GAP's `keep`, read before the gate's
    /// lock, missed it) was received: handed back with its set, it is
    /// delivered in its turn, not dropped as a late copy.
    #[test]
    fn a_change_staged_before_a_gap_recorded_it_is_delivered_in_its_turn() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x6Du8; 16];
        assert!(gate.hold_staged(&key, 4), "unseeded: no place kept");
        assert!(gate.on_gap(key, 3, 6, std::iter::empty()).is_empty());
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.on_staged(key, 4, payload(4)).is_empty(), "held");
        assert_eq!(seqs(&gate.on_data(key, 1, payload(1))), vec![1]);
        assert_eq!(seqs(&gate.on_data(key, 2, payload(2))), vec![2, 4]);
        assert_eq!(gate.next_seq(&key), Some(6));
    }

    /// Only a sequence crossed ahead and not filtered is a sample lost.
    #[test]
    fn lost_ahead_is_crossed_ahead_and_not_filtered() {
        let mut gate = ReorderGate::new(true, false);
        let key = [0x6Eu8; 16];
        let _ = gate.on_heartbeat(key, 1);
        assert!(gate.hold_staged(&key, 1));
        gate.note_filtered(key, 3, 4, &[]);
        assert!(gate.on_gap(key, 3, 4, std::iter::empty()).is_empty());
        assert!(gate.on_heartbeat(key, 6).is_empty());
        assert!(gate.lost_ahead(&key, 2), "purged");
        assert!(!gate.lost_ahead(&key, 3), "filtered");
        assert!(gate.lost_ahead(&key, 5), "purged");
        assert!(!gate.lost_ahead(&key, 1), "held");
        assert!(!gate.lost_ahead(&key, 6), "available");
        assert_eq!(seqs(&gate.on_staged(key, 1, payload(1))), vec![1]);
        assert!(!gate.lost_ahead(&key, 2), "below the base");
        assert!(!ReorderGate::new_best_effort().lost_ahead(&key, 2));
        let mut unseeded = ReorderGate::new(true, false);
        assert!(unseeded.on_gap(key, 3, 6, std::iter::empty()).is_empty());
        assert!(!unseeded.lost_ahead(&key, 4), "nothing owed yet");
    }

    /// A staged change `on_staged` drops (below a VOLATILE gate's join
    /// floor: history from before the join) gives its place back: held, it
    /// stopped the gate at it on the next purge, for good.
    #[test]
    fn a_staged_change_dropped_as_history_frees_its_place() {
        let mut gate = ReorderGate::new(true, true);
        let key = [0x66u8; 16];
        gate.observe(key, 10, Some(10));
        assert!(gate.on_gap(key, 2, 5, std::iter::empty()).is_empty());
        assert_eq!(gate.next_seq(&key), Some(5), "seeded by the GAP");
        assert!(gate.hold_staged(&key, 7));
        assert!(gate.on_staged(key, 7, payload(7)).is_empty(), "pre-join");
        assert!(gate.on_heartbeat(key, 12).is_empty());
        assert_eq!(gate.next_seq(&key), Some(12));
    }
}

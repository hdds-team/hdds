// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Linear sample ownership and exact bounded sequence classification for GROUP.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

// @audit-ok: Per-thread context, restored by GapOrderScope on every exit.
thread_local! {
    static GAP_ORDER: Cell<Option<([u8; 16], u64, u64)>> = const { Cell::new(None) };
}

/// One decoded GAP supplies ordering metadata to each native receipt callback.
pub(crate) struct GapOrderScope(Option<([u8; 16], u64, u64)>);

impl GapOrderScope {
    pub(crate) fn enter(writer: [u8; 16], start: u64, end: u64) -> Self {
        Self(GAP_ORDER.with(|slot| slot.replace(Some((writer, start, end)))))
    }

    pub(crate) fn captured(writer: [u8; 16]) -> Option<(u64, u64)> {
        GAP_ORDER.with(|slot| {
            slot.get()
                .filter(|(id, _, _)| *id == writer)
                .map(|(_, start, end)| (start, end))
        })
    }
}

impl Drop for GapOrderScope {
    fn drop(&mut self) {
        GAP_ORDER.with(|slot| slot.set(self.0.take()));
    }
}

/// A packet pins its original admission identity through preparation.
/// Keep the active byte first so ordinary admission retains its direct load.
#[repr(C)]
#[derive(Debug)]
pub(crate) struct AdmissionFrame {
    active: AtomicBool,
    loss: OnceLock<Arc<GroupLossAuthority>>,
}

impl AdmissionFrame {
    pub(crate) fn new(active: bool) -> Self {
        Self {
            active: AtomicBool::new(active),
            loss: OnceLock::new(),
        }
    }

    #[cold]
    pub(crate) fn loss_authority(&self) -> &Arc<GroupLossAuthority> {
        self.loss
            .get_or_init(|| Arc::new(GroupLossAuthority::default()))
    }

    #[cold]
    pub(crate) fn inherit_loss_authority(&self, authority: Arc<GroupLossAuthority>) -> bool {
        match self.loss.set(authority) {
            Ok(()) => true,
            Err(authority) => self
                .loss
                .get()
                .is_some_and(|old| Arc::ptr_eq(old, &authority)),
        }
    }
}

impl std::ops::Deref for AdmissionFrame {
    type Target = AtomicBool;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.active
    }
}

const OWED: u8 = 0;
const OWNED: u8 = 1;
const DELIVERED: u8 = 2;
const LOST: u8 = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    New,
    Duplicate,
    Full,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Missed {
    All,
    Dropped,
}

#[derive(Debug, Clone)]
struct Sequences {
    high: Option<u64>,
    bits: Box<[u64]>,
    missed: BTreeMap<u64, u64>,
}
impl Default for Sequences {
    fn default() -> Self {
        Self {
            high: None,
            bits: vec![0; 64].into_boxed_slice(),
            missed: BTreeMap::new(),
        }
    }
}
impl Sequences {
    const WINDOW: u64 = 4096;
    const MISSED_RUNS: usize = 4096;
    fn for_each_unreceived(&self, lo: u64, hi: u64, run: &mut impl FnMut(u64, u64)) {
        if hi <= lo {
            return;
        }
        let mut pending: Option<(u64, u64)> = None;
        let mut push = |start: u64, end: u64| {
            if end <= start {
                return;
            }
            match pending.as_mut() {
                Some((_, last)) if *last == start => *last = end,
                _ => {
                    if let Some((s, e)) = pending.replace((start, end)) {
                        run(s, e);
                    }
                }
            }
        };
        match self.high {
            None => push(lo, hi),
            Some(high) => {
                let floor = Self::floor(high);
                // Below the window: the missed runs (inclusive) within
                // [lo, hi).
                if lo <= floor {
                    let below_hi = hi.min(floor.saturating_add(1));
                    let first = self
                        .missed
                        .range(..lo)
                        .next_back()
                        .map(|(&s, _)| s)
                        .unwrap_or(lo);
                    for (&start, &end) in self.missed.range(first..below_hi) {
                        push(start.max(lo), end.saturating_add(1).min(below_hi));
                    }
                }
                // The window: its unmarked bits.
                let win_hi = hi.min(high.saturating_add(1));
                let mut seq = lo.max(floor.saturating_add(1));
                while seq < win_hi {
                    if self.marked(seq) {
                        seq += 1;
                        continue;
                    }
                    let start = seq;
                    while seq < win_hi && !self.marked(seq) {
                        seq += 1;
                    }
                    push(start, seq);
                }
                // Above it: nothing received.
                push(lo.max(high.saturating_add(1)), hi);
            }
        }
        if let Some((s, e)) = pending {
            run(s, e);
        }
    }

    fn terminal_range(&mut self, lo: u64, hi: u64) {
        if hi <= lo {
            return;
        }
        if self.high.is_none_or(|high| hi - 1 > high) {
            self.record(hi - 1, Missed::All);
        }
        let overlapping: Vec<_> = self
            .missed
            .range(..hi)
            .filter(|(_, end)| **end >= lo)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (s, e) in overlapping {
            self.missed.remove(&s);
            if s < lo {
                self.missed.insert(s, lo - 1);
            }
            if e >= hi {
                self.missed.insert(hi, e);
            }
        }
        let high = self.high.unwrap_or(0);
        for seq in lo.max(Self::floor(high).saturating_add(1))..hi.min(high.saturating_add(1)) {
            self.mark(seq, true);
        }
    }

    fn floor(high: u64) -> u64 {
        high.saturating_sub(Self::WINDOW)
    }

    fn slot(seq: u64) -> (usize, u64) {
        let at = seq % Self::WINDOW;
        // `at` < WINDOW, so the word index is below WORDS.
        let word = usize::try_from(at / 64).unwrap_or(0);
        (word, 1 << (at % 64))
    }

    fn marked(&self, seq: u64) -> bool {
        let (word, bit) = Self::slot(seq);
        self.bits[word] & bit != 0
    }

    fn mark(&mut self, seq: u64, on: bool) {
        let (word, bit) = Self::slot(seq);
        if on {
            self.bits[word] |= bit;
        } else {
            self.bits[word] &= !bit;
        }
    }

    fn unmark(&mut self, seq: u64) {
        let Some(high) = self.high else {
            return;
        };
        if seq == 0 || seq > high {
            return;
        }
        if seq > Self::floor(high) {
            self.mark(seq, false);
            return;
        }
        if self.missed_run(seq).is_some() {
            return;
        }
        let (mut start, mut end) = (seq, seq);
        if let Some((s, e)) = self.missed_run(seq.saturating_sub(1)) {
            if e.saturating_add(1) == seq {
                self.missed.remove(&s);
                start = s;
            }
        }
        if let Some(&e) = self.missed.get(&seq.saturating_add(1)) {
            self.missed.remove(&seq.saturating_add(1));
            end = e;
        }
        self.missed.insert(start, end);
    }

    fn missed_run(&self, seq: u64) -> Option<(u64, u64)> {
        self.missed
            .range(..=seq)
            .next_back()
            .filter(|(_, &end)| seq <= end)
            .map(|(&start, &end)| (start, end))
    }

    fn judge(&mut self, seq: u64, missed: Missed, settled: impl FnOnce() -> Option<u64>) -> Seen {
        let Some(high) = self.high else {
            return Seen::New;
        };
        if seq > Self::floor(high) {
            if seq <= high {
                return if self.marked(seq) {
                    Seen::Duplicate
                } else {
                    Seen::New
                };
            }
            // Moving the window up: the runs it leaves behind must fit.
            let runs = self.leaving(Some(high), seq, missed);
            let added = self.added(&runs);
            if added == 0 || self.missed.len() + added <= Self::MISSED_RUNS {
                return Seen::New;
            }
            if let Some(settled) = settled() {
                self.settle(settled);
            }
            let runs = self.leaving(Some(high), seq, missed);
            return if self.missed.len() + self.added(&runs) <= Self::MISSED_RUNS {
                Seen::New
            } else {
                Seen::Full
            };
        }
        if self.missed_run(seq).is_none() {
            return Seen::Duplicate;
        }
        if let Some(settled) = settled() {
            self.settle(settled);
        }
        // Settled or not, the run as it stands now.
        let Some((start, end)) = self.missed_run(seq) else {
            return Seen::Duplicate;
        };
        // Taking it out of the middle of its run splits the run in two.
        if start < seq && seq < end && self.missed.len() >= Self::MISSED_RUNS {
            return Seen::Full;
        }
        Seen::New
    }

    fn record(&mut self, seq: u64, missed: Missed) {
        match self.high {
            Some(high) if seq <= Self::floor(high) => self.take_missed(seq),
            Some(high) if seq <= high => self.mark(seq, true),
            high => {
                for (start, end) in self.leaving(high, seq, missed) {
                    self.add_missed(start, end);
                }
                let top = high.unwrap_or(0);
                if seq - top >= Self::WINDOW {
                    self.bits.fill(0);
                } else {
                    // The sequences entering the window take the slots of
                    // those leaving it.
                    for entering in top + 1..seq {
                        self.mark(entering, false);
                    }
                }
                self.high = Some(seq);
                self.mark(seq, true);
            }
        }
    }

    fn leaving(&self, high: Option<u64>, seq: u64, missed: Missed) -> Vec<(u64, u64)> {
        let mut runs: Vec<(u64, u64)> = Vec::new();
        if missed == Missed::Dropped {
            return runs;
        }
        let top = high.unwrap_or(0);
        let to = Self::floor(seq);
        let mut push = |start: u64, end: u64| match runs.last_mut() {
            Some((_, last)) if *last + 1 == start => *last = end,
            _ => runs.push((start, end)),
        };
        for gone in high.map_or(0, Self::floor) + 1..=to.min(top) {
            if !self.marked(gone) {
                push(gone, gone);
            }
        }
        // Above the old top nothing was admitted.
        if to > top {
            push(top + 1, to);
        }
        runs
    }

    fn added(&self, runs: &[(u64, u64)]) -> usize {
        let extends = runs.first().is_some_and(|&(start, _)| {
            self.missed
                .iter()
                .next_back()
                .is_some_and(|(_, &end)| end + 1 == start)
        });
        runs.len() - usize::from(extends)
    }

    fn add_missed(&mut self, start: u64, end: u64) {
        if let Some((_, last)) = self.missed.iter_mut().next_back() {
            if last.saturating_add(1) == start {
                *last = end;
                return;
            }
        }
        self.missed.insert(start, end);
    }

    fn take_missed(&mut self, seq: u64) {
        let Some((start, end)) = self.missed_run(seq) else {
            return;
        };
        self.missed.remove(&start);
        if start < seq {
            self.missed.insert(start, seq - 1);
        }
        if seq < end {
            self.missed.insert(seq + 1, end);
        }
    }

    fn settle(&mut self, settled: u64) {
        while let Some((&start, &end)) = self.missed.iter().next() {
            if start > settled {
                break;
            }
            self.missed.remove(&start);
            if end > settled {
                self.missed.insert(settled + 1, end);
                break;
            }
        }
    }
}

#[derive(Debug)]
struct Claim {
    ticket: Weak<GroupLossTicket>,
    status: Arc<AtomicU8>,
    reserved: bool,
}

#[derive(Debug, Default)]
struct State {
    sequences: Sequences,
    /// Irrelevance is not proof that a real sample was already counted.
    /// Allocated lazily; its fixed window and sparse-run bound match Sequences.
    irrelevant: Option<Sequences>,
    claims: BTreeMap<u64, Claim>,
    closed: bool,
    terminal_through: u64,
}

impl State {
    fn prune(&mut self) {
        let dead: Vec<_> = self
            .claims
            .iter()
            .filter(|(_, c)| c.ticket.strong_count() == 0 && (c.reserved || self.closed))
            .map(|(&seq, c)| (seq, c.status.load(Ordering::Acquire)))
            .collect();
        for (seq, status) in dead {
            self.claims.remove(&seq);
            if status == OWED || status == OWNED {
                self.sequences.unmark(seq);
            }
        }
    }
}

/// One logical writer namespace, retained on a confirmed lease continuation.
#[derive(Debug, Default)]
pub(crate) struct GroupLossAuthority {
    state: Mutex<State>,
    pending: AtomicU64,
    deferred_gap_through: AtomicU64,
    order_gap_end: AtomicU64,
}

impl GroupLossAuthority {
    pub(crate) fn classify_control(&self, seq: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        if let Some(ticket) = state
            .claims
            .get(&seq)
            .and_then(|claim| claim.ticket.upgrade())
        {
            return ticket.status.load(Ordering::Acquire) != OWED;
        }
        match state.sequences.judge(seq, Missed::All, || None) {
            Seen::Full => false,
            Seen::Duplicate => true,
            Seen::New => {
                state.sequences.record(seq, Missed::All);
                true
            }
        }
    }

    pub(crate) fn claim(
        self: &Arc<Self>,
        writer: [u8; 16],
        seq: u64,
        owned: bool,
        frame: &Arc<AdmissionFrame>,
        _settled: Option<u64>,
        known_terminal: bool,
    ) -> Option<Arc<GroupLossTicket>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        if let Some(ticket) = state
            .claims
            .get(&seq)
            .and_then(|claim| claim.ticket.upgrade())
        {
            if owned && !ticket.take_ownership() {
                return None;
            }
            return Some(ticket);
        }
        let terminal =
            known_terminal || state.sequences.judge(seq, Missed::All, || None) == Seen::Duplicate;
        if !owned && (state.closed || !frame.load(Ordering::Acquire)) {
            return None;
        }
        let mut reserved = true;
        if !terminal {
            if state.sequences.judge(seq, Missed::All, || None) == Seen::Full {
                if !owned || frame.load(Ordering::Acquire) {
                    return None;
                }
                // Already prepared by an invalidated in-flight admission.
                // Retain only its status until the pending close consumes debt.
                reserved = false;
            } else {
                state.sequences.record(seq, Missed::All);
            }
        }
        let ticket = Arc::new(GroupLossTicket {
            authority: self.clone(),
            frame: frame.clone(),
            writer,
            seq,
            status: Arc::new(AtomicU8::new(if terminal {
                DELIVERED
            } else if owned {
                OWNED
            } else {
                OWED
            })),
        });
        state.claims.insert(
            seq,
            Claim {
                ticket: Arc::downgrade(&ticket),
                status: ticket.status.clone(),
                reserved,
            },
        );
        Some(ticket)
    }

    /// Consume only actual proxy debt. Live owned bytes retain their ticket.
    #[cfg(test)]
    pub(crate) fn consume(&self, ranges: &[(u64, u64)], filtered: &BTreeMap<u64, u64>) -> u64 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        Self::consume_locked(&mut state, ranges, filtered)
    }

    fn consume_locked(
        state: &mut State,
        ranges: &[(u64, u64)],
        filtered: &BTreeMap<u64, u64>,
    ) -> u64 {
        let mut count = 0u64;
        for &(lo, hi) in ranges {
            if hi <= lo {
                continue;
            }
            let mut parts = vec![(lo, hi)];
            for (&start, &end) in filtered.range(..hi) {
                if end > lo {
                    subtract(&mut parts, start, end);
                }
            }
            for (&seq, ticket) in state.claims.range(lo..hi) {
                if let Some(ticket) = ticket.ticket.upgrade() {
                    if parts.iter().any(|&(s, e)| s <= seq && seq < e) {
                        if ticket.status.load(Ordering::Acquire) == OWED {
                            count = count.saturating_add(ticket.mark_lost());
                        }
                        subtract(&mut parts, seq, seq.saturating_add(1));
                    }
                } else if !ticket.reserved && ticket.status.load(Ordering::Acquire) == LOST {
                    subtract(&mut parts, seq, seq.saturating_add(1));
                }
            }
            for (lo, hi) in parts {
                let mut part = |lo, hi| {
                    state.sequences.for_each_unreceived(lo, hi, &mut |s, e| {
                        count = count.saturating_add(e - s);
                    });
                };
                if let Some(irrelevant) = &state.irrelevant {
                    irrelevant.for_each_unreceived(lo, hi, &mut part);
                } else {
                    part(lo, hi);
                }
            }
        }
        count
    }

    /// Reserve exact terminal classification before committing native irrelevance.
    pub(crate) fn try_consume(
        &self,
        ranges: &[(u64, u64)],
        filtered: &BTreeMap<u64, u64>,
        prefix: bool,
    ) -> Option<u64> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        let mut next = state.sequences.clone();
        for &(lo, hi) in ranges {
            if let Some(irrelevant) = &state.irrelevant {
                irrelevant.for_each_unreceived(lo, hi, &mut |lo, hi| next.terminal_range(lo, hi));
            } else {
                next.terminal_range(lo, hi);
            }
        }
        let limit = Sequences::MISSED_RUNS + usize::from(prefix);
        if next.missed.len() > limit.max(state.sequences.missed.len()) {
            return None;
        }
        let count = Self::consume_locked(&mut state, ranges, filtered);
        state.sequences = next;
        Some(count)
    }

    /// Classify declared GAPs even while their native receipt waits for order.
    /// Only the previously announced proxy debt contributes to SAMPLE_LOST.
    pub(crate) fn try_consume_gap(
        &self,
        owed: &[(u64, u64)],
        declared: &[(u64, u64)],
        filtered: &BTreeMap<u64, u64>,
    ) -> Option<u64> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        let mut irrelevant = state.irrelevant.clone().unwrap_or_default();
        for &(lo, hi) in declared {
            irrelevant.terminal_range(lo, hi);
            // Check every insertion, including a long bitmap GAP. The temporary
            // candidate has at most MISSED_RUNS + WINDOW / 2 + 2 runs; accepted
            // state never exceeds MISSED_RUNS and never depends on frame length.
            if irrelevant.missed.len() > Sequences::MISSED_RUNS {
                return None;
            }
        }
        let mut next = state.sequences.clone();
        for &(lo, hi) in owed {
            if let Some(known) = &state.irrelevant {
                known.for_each_unreceived(lo, hi, &mut |lo, hi| next.terminal_range(lo, hi));
            } else {
                next.terminal_range(lo, hi);
            }
        }
        if next.missed.len() > Sequences::MISSED_RUNS.max(state.sequences.missed.len()) {
            return None;
        }
        let count = Self::consume_locked(&mut state, owed, filtered);
        state.sequences = next;
        state.irrelevant = Some(irrelevant);
        Some(count)
    }

    pub(crate) fn defer_order_gap(&self, end: u64) {
        self.order_gap_end.fetch_max(end, Ordering::AcqRel);
    }

    pub(crate) fn order_gap_end(&self) -> u64 {
        self.order_gap_end.load(Ordering::Acquire)
    }

    /// A concurrent higher debt must survive completion of an older one.
    pub(crate) fn complete_order_gap(&self, end: u64) {
        let _ = self
            .order_gap_end
            .compare_exchange(end, 0, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn refresh_gap_deferred(&self) {
        let through = self.deferred_gap_through.load(Ordering::Acquire);
        if through != 0 && self.accounted_prefix() >= through.saturating_sub(1) {
            let _ = self.deferred_gap_through.compare_exchange(
                through,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    pub(crate) fn close(&self, through: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        state.terminal_through = state.terminal_through.max(through);
        state.prune();
    }

    pub(crate) fn close_debt(
        &self,
        ranges: &[(u64, u64)],
        filtered: &BTreeMap<u64, u64>,
        through: u64,
    ) -> u64 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        let count = Self::consume_locked(&mut state, ranges, filtered);
        for &(lo, hi) in ranges {
            state.sequences.terminal_range(lo, hi);
        }
        state.closed = true;
        state.terminal_through = state.terminal_through.max(through);
        state.prune();
        count
    }

    pub(crate) fn reopen(&self) -> u64 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = false;
        state.terminal_through
    }

    /// An actual prepared sample was invalidated before publishing its owner.
    pub(crate) fn record_prepared_loss(&self, _writer: [u8; 16], seq: u64) -> u64 {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        if let Some(ticket) = state
            .claims
            .get(&seq)
            .and_then(|claim| claim.ticket.upgrade())
        {
            return ticket.mark_lost();
        }
        if state.sequences.judge(seq, Missed::All, || None) == Seen::Duplicate {
            return 0;
        }
        // This identity is backed by the already allocated in-flight sample.
        state.sequences.terminal_range(seq, seq.saturating_add(1));
        1
    }

    pub(crate) fn unaccounted(&self, lo: u64, hi: u64) -> Vec<(u64, u64)> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.prune();
        let mut ranges = Vec::new();
        state
            .sequences
            .for_each_unreceived(lo, hi, &mut |s, e| ranges.push((s, e)));
        for (&seq, claim) in state.claims.range(lo..hi) {
            if claim.status.load(Ordering::Acquire) == OWED && claim.ticket.strong_count() != 0 {
                ranges.push((seq, seq.saturating_add(1)));
            }
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (s, e) in ranges {
            match merged.last_mut() {
                Some((_, end)) if s <= *end => *end = (*end).max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    }

    pub(crate) fn accounted_prefix(&self) -> u64 {
        let high = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sequences
            .high
            .unwrap_or(0);
        self.unaccounted(1, high.saturating_add(1))
            .first()
            .map_or(high, |(lo, _)| lo.saturating_sub(1))
    }

    pub(crate) fn defer_gap(&self, through: u64) {
        self.deferred_gap_through
            .fetch_max(through, Ordering::AcqRel);
    }
    pub(crate) fn gap_deferred(&self) -> bool {
        self.deferred_gap_through.load(Ordering::Acquire) != 0
    }
    pub(crate) fn heartbeat_prefix(&self, first: u64) {
        if first > 1 {
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .irrelevant
                .get_or_insert_with(Sequences::default)
                .terminal_range(1, first);
        }
        let _ = self.deferred_gap_through.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |through| (through != 0 && first >= through).then_some(0),
        );
    }

    pub(crate) fn take_pending(&self) -> u64 {
        self.pending.swap(0, Ordering::AcqRel)
    }
}

/// A reader's exact right to count one identified sample lost.
#[derive(Debug)]
pub(crate) struct GroupLossTicket {
    authority: Arc<GroupLossAuthority>,
    frame: Arc<AdmissionFrame>,
    writer: [u8; 16],
    seq: u64,
    status: Arc<AtomicU8>,
}
impl GroupLossTicket {
    pub(crate) fn writer(&self) -> [u8; 16] {
        self.writer
    }
    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }
    fn take_ownership(&self) -> bool {
        match self
            .status
            .compare_exchange(OWED, OWNED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(LOST | DELIVERED) => true,
            Err(_) => false,
        }
    }
    pub(crate) fn is_lost(&self) -> bool {
        self.status.load(Ordering::Acquire) == LOST
    }

    pub(crate) fn is_settled(&self) -> bool {
        matches!(self.status.load(Ordering::Acquire), DELIVERED | LOST)
    }

    pub(crate) fn mark_lost(&self) -> u64 {
        self.status
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |s| {
                (s == OWNED || s == OWED).then_some(LOST)
            })
            .is_ok() as u64
    }
    pub(crate) fn mark_delivered(&self) {
        let _ = self
            .status
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |s| {
                (s == OWNED || s == OWED).then_some(DELIVERED)
            });
    }
    pub(crate) fn abort(&self) {
        let state = self
            .authority
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let status = self.status.load(Ordering::Acquire);
        if status == OWNED {
            if state.closed || !self.frame.load(Ordering::Acquire) {
                self.authority
                    .pending
                    .fetch_add(self.mark_lost(), Ordering::AcqRel);
            } else {
                self.status.store(OWED, Ordering::Release);
            }
        }
    }
}

fn subtract(parts: &mut Vec<(u64, u64)>, lo: u64, hi: u64) {
    let old = std::mem::take(parts);
    for (s, e) in old {
        if hi <= s || lo >= e {
            parts.push((s, e));
            continue;
        }
        if s < lo {
            parts.push((s, lo));
        }
        if hi < e {
            parts.push((hi, e));
        }
    }
}

/// The actual intervals a proxy stopped awaiting during a proof transaction.
pub(super) fn consumed(before: &[(u64, u64)], after: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut result = before.to_vec();
    for &(lo, hi) in after {
        subtract(&mut result, lo, hi);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disjoint_owned_losses_do_not_consume_a_later_first_loss_in_an_old_hole() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(true));
        let writer = [1; 16];
        let mut losses = 0;
        for seq in (1..=16385).step_by(32) {
            let ticket = authority
                .claim(writer, seq, true, &frame, None, false)
                .unwrap();
            losses += ticket.mark_lost();
        }
        assert_eq!(losses, 513);
        let first = authority
            .claim(writer, 2, true, &frame, None, false)
            .unwrap();
        losses += first.mark_lost();
        drop(first);
        let duplicate = authority
            .claim(writer, 2, true, &frame, None, false)
            .unwrap();
        losses += duplicate.mark_lost();
        assert_eq!(
            losses, 514,
            "an earlier sparse loss swallowed a new sample identity"
        );
        assert!(authority.state.lock().unwrap().claims.len() <= 1);
    }

    #[test]
    fn an_unrepresentable_sparse_gap_stays_owed_until_a_real_prefix_proof() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(true));
        let writer = [3; 16];
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            [4; 16],
        );
        credit.match_writer(writer);
        let mut refused = false;
        let mut last = 1u64;
        for n in 0..10000u64 {
            let seq = 1 + n * 16384;
            let Some(ticket) = authority.claim(writer, seq, true, &frame, None, false) else {
                refused = true;
                break;
            };
            assert_eq!(ticket.mark_lost(), 1);
            // The owned samples expired before their receipt credit. Keep
            // native debt open while exact loss identities fill their bound.
            last = seq;
        }
        assert!(
            refused,
            "new identities did not respect their terminal metadata reservation"
        );
        let _ = credit.answer_heartbeat(
            &writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: i64::try_from(last).unwrap(),
                count: 1,
                final_flag: false,
            },
        );
        assert_eq!(
            credit.group_gap_loss(&writer, &authority, 10, 11, &[10], &BTreeMap::new()),
            None
        );
        assert!(
            credit.awaits(&writer, 10),
            "unrepresented GAP was credited as received"
        );
        assert!(authority.gap_deferred());
        let prefix = credit.group_heartbeat_loss(&writer, &authority, last + 1, &BTreeMap::new());
        assert!(
            prefix.is_some(),
            "a real contiguous prefix could not compact sparse obligations"
        );
        assert!(!credit.awaits(&writer, 10));
        assert!(!authority.gap_deferred());
        let late = authority
            .claim(writer, 10, true, &frame, None, false)
            .unwrap();
        assert_eq!(
            late.mark_lost(),
            0,
            "the prefix loss was counted again for a late copy"
        );
    }

    #[test]
    fn aborting_a_body_keeps_its_shared_owed_cohort_ticket_live() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(true));
        let owed = authority
            .claim([1; 16], 1, false, &frame, None, false)
            .unwrap();
        let body = authority
            .claim([1; 16], 1, true, &frame, None, false)
            .unwrap();
        body.abort();
        drop(body);
        assert_eq!(
            owed.mark_lost(),
            1,
            "refused repair withdrew an already owed sample"
        );
        assert_eq!(owed.mark_lost(), 0);
    }

    #[test]
    fn dense_controls_do_not_exhaust_sample_loss_metadata() {
        let authority = Arc::new(GroupLossAuthority::default());
        for seq in 1..=20000 {
            assert!(
                authority.classify_control(seq),
                "accepted controls accumulated false sample debt"
            );
        }
        let frame = Arc::new(AdmissionFrame::new(true));
        let data = authority
            .claim([1; 16], 20001, true, &frame, None, false)
            .unwrap();
        assert_eq!(data.mark_lost(), 1);
    }

    #[test]
    fn one_sample_cannot_have_two_simultaneous_owned_body_leases() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(true));
        let body = authority
            .claim([1; 16], 1, true, &frame, None, false)
            .unwrap();
        assert!(authority
            .claim([1; 16], 1, true, &frame, None, false)
            .is_none());
        assert_eq!(authority.consume(&[(1, 2)], &BTreeMap::new()), 0);
        assert_eq!(body.mark_lost(), 1);
    }

    #[test]
    fn closing_a_namespace_preserves_a_never_counted_hole_below_its_native_prefix() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(true));
        for seq in 2..=4200 {
            let ticket = authority
                .claim([1; 16], seq, true, &frame, None, false)
                .unwrap();
            ticket.mark_delivered();
        }
        assert_eq!(authority.close_debt(&[], &BTreeMap::new(), 4200), 0);
        assert_eq!(
            authority.record_prepared_loss([1; 16], 1),
            1,
            "native terminal prefix swallowed an unknown real sample"
        );
        assert_eq!(authority.record_prepared_loss([1; 16], 1), 0);
    }

    #[test]
    fn a_prepared_sample_after_departure_counts_even_without_announced_proxy_debt() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(false));
        authority.close(0);
        let prepared = authority
            .claim([1; 16], 1, true, &frame, None, false)
            .unwrap();
        assert_eq!(prepared.mark_lost(), 1);
        drop(prepared);
        let duplicate = authority
            .claim([1; 16], 1, true, &frame, None, false)
            .unwrap();
        assert_eq!(duplicate.mark_lost(), 0);
    }
}

#[cfg(test)]
mod ordered_gap_debt_tests {
    use super::*;

    #[test]
    fn completion_of_an_earlier_gap_cannot_clear_a_later_order_debt() {
        let authority = GroupLossAuthority::default();
        authority.defer_order_gap(7);
        authority.defer_order_gap(11);
        authority.complete_order_gap(7);
        assert_eq!(authority.order_gap_end(), 11);
        authority.complete_order_gap(11);
        assert_eq!(authority.order_gap_end(), 0);
    }

    #[test]
    fn a_gap_before_heartbeat_classifies_irrelevance_without_inventing_loss() {
        let authority = GroupLossAuthority::default();
        assert_eq!(
            authority.try_consume_gap(&[], &[(2, 6)], &BTreeMap::new()),
            Some(0)
        );
        assert_eq!(
            authority.consume(&[(2, 6)], &BTreeMap::new()),
            0,
            "later heartbeat debt reclassified a previously declared GAP as lost DATA"
        );
        assert_eq!(
            authority.consume(&[(6, 7)], &BTreeMap::new()),
            1,
            "unreceived announced DATA beyond the GAP still counts once"
        );
    }

    #[test]
    fn an_actual_owed_ticket_is_not_hidden_by_earlier_irrelevance() {
        let authority = Arc::new(GroupLossAuthority::default());
        assert_eq!(
            authority.try_consume_gap(&[], &[(2, 6)], &BTreeMap::new()),
            Some(0)
        );
        let frame = Arc::new(AdmissionFrame::new(true));
        let ticket = authority
            .claim([1; 16], 3, false, &frame, None, false)
            .unwrap();
        assert_eq!(
            authority.try_consume_gap(&[(2, 6)], &[(2, 6)], &BTreeMap::new()),
            Some(1)
        );
        assert!(ticket.is_lost());
        assert_eq!(
            authority.try_consume_gap(&[(2, 6)], &[(2, 6)], &BTreeMap::new()),
            Some(0)
        );
    }

    #[test]
    fn sparse_gap_irrelevance_refuses_before_mutating_and_prefix_compacts_it() {
        let authority = GroupLossAuthority::default();
        let mut last = 1;
        let mut refused = false;
        for n in 0..10000u64 {
            let seq = 1 + n * 16384;
            let before = authority.state.lock().unwrap().irrelevant.clone();
            let result = authority.try_consume_gap(&[], &[(seq, seq + 1)], &BTreeMap::new());
            let state = authority.state.lock().unwrap();
            let mask = state.irrelevant.as_ref().unwrap();
            assert_eq!(mask.bits.len(), 64);
            assert!(mask.missed.len() <= Sequences::MISSED_RUNS);
            if result.is_none() {
                let before = before.unwrap();
                assert_eq!(mask.high, before.high);
                assert_eq!(mask.bits, before.bits);
                assert_eq!(mask.missed, before.missed);
                assert!(state.sequences.high.is_none());
                refused = true;
                last = seq;
                break;
            }
        }
        assert!(refused, "sparse irrelevance grew without a fixed bound");
        authority.heartbeat_prefix(last + 1);
        assert_eq!(
            authority.try_consume_gap(&[], &[(last, last + 1)], &BTreeMap::new()),
            Some(0)
        );
        let state = authority.state.lock().unwrap();
        assert!(state.irrelevant.as_ref().unwrap().missed.is_empty());
        assert!(
            state.sequences.high.is_none(),
            "unknown GAP became an accounted real sample"
        );
    }

    #[test]
    fn delayed_ordered_gap_credit_cannot_recreate_an_unmatched_reader() {
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            [4; 16],
        );
        let writer = [3; 16];
        let authority = GroupLossAuthority::default();
        credit.match_writer(writer);
        credit.unmatch_writer(&writer);
        assert!(!credit.credit_ordered_gap(&writer, &authority, 1, 3, &[1, 2]));
        assert!(!credit.is_matched(&writer));
    }

    #[test]
    fn actual_native_ack_prefix_compacts_alternating_gap_data_irrelevance() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(true));
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            [4; 16],
        );
        let writer = [3; 16];
        credit.match_writer(writer);
        authority
            .claim(writer, 1, true, &frame, None, false)
            .unwrap()
            .mark_delivered();
        credit.on_data(writer, 1);
        let _ = credit.answer_heartbeat(
            &writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: 20001,
                count: 1,
                final_flag: false,
            },
        );
        for n in 0..10000i64 {
            let seq = 2 + 2 * n;
            let filtered = BTreeMap::from([(seq as u64, seq as u64 + 1)]);
            assert_eq!(
                credit.group_gap_loss_with_order(
                    &writer,
                    &authority,
                    seq,
                    seq + 1,
                    &[seq as u64],
                    &filtered,
                    false
                ),
                Some(0),
                "native ACK prefix failed to compact alternating irrelevance at {seq}"
            );
            assert!(credit.credit_ordered_gap(&writer, &authority, seq, seq + 1, &[seq as u64]));
            authority
                .claim(writer, (seq + 1) as u64, true, &frame, None, false)
                .unwrap()
                .mark_delivered();
            credit.on_data(writer, seq + 1);
        }
        assert!(!credit.awaits(&writer, 20001));
        let state = authority.state.lock().unwrap();
        assert!(state.irrelevant.as_ref().unwrap().missed.len() <= Sequences::MISSED_RUNS);
    }

    #[test]
    fn nested_gap_event_scopes_restore_the_original_writer_and_interval() {
        let a = [1; 16];
        let b = [2; 16];
        assert_eq!(GapOrderScope::captured(a), None);
        let _outer = GapOrderScope::enter(a, 1, 3);
        assert_eq!(GapOrderScope::captured(a), Some((1, 3)));
        {
            let _inner = GapOrderScope::enter(b, 7, 11);
            assert_eq!(GapOrderScope::captured(a), None);
            assert_eq!(GapOrderScope::captured(b), Some((7, 11)));
        }
        assert_eq!(GapOrderScope::captured(a), Some((1, 3)));
        assert_eq!(GapOrderScope::captured(b), None);
    }
}

#[cfg(test)]
mod combined_gap_debt_tests {
    use super::*;

    #[test]
    fn a_shadow_heartbeat_compacts_exact_budget_without_forgetting_order_repair() {
        let authority = Arc::new(GroupLossAuthority::default());
        let frame = Arc::new(AdmissionFrame::new(true));
        let writer = [3; 16];
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            [4; 16],
        );
        credit.match_writer(writer);
        let mut last = 1;
        let mut refused = false;
        for n in 0..10000u64 {
            let seq = 1 + n * 16384;
            let Some(ticket) = authority.claim(writer, seq, true, &frame, None, false) else {
                refused = true;
                break;
            };
            assert_eq!(ticket.mark_lost(), 1);
            last = seq;
        }
        assert!(refused);
        let _ = credit.answer_heartbeat(
            &writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: last as i64,
                count: 1,
                final_flag: false,
            },
        );
        authority.defer_order_gap(last + 100);
        assert_eq!(
            credit.group_gap_loss_with_order(
                &writer,
                &authority,
                10,
                11,
                &[10],
                &BTreeMap::new(),
                false,
            ),
            None
        );
        assert!(authority.gap_deferred());
        assert!(
            credit
                .group_heartbeat_loss(&writer, &authority, last + 1, &BTreeMap::new())
                .is_some(),
            "order debt prevented shadow prefix compaction of the exact budget"
        );
        assert!(!authority.gap_deferred());
        assert!(
            credit.awaits(&writer, 10),
            "shadow compaction committed native irrelevance"
        );
        assert_eq!(authority.order_gap_end(), last + 100);
        let answer = credit
            .answer_heartbeat(
                &writer,
                &crate::core::reader::HeartbeatSeen {
                    first_seq: last as i64 + 1,
                    last_seq: last as i64 + 1,
                    count: 2,
                    final_flag: false,
                },
            )
            .expect("order proof repair must survive exact-budget compaction");
        assert_eq!(answer.bitmap_base, 1);
        assert!(answer.missing.contains(&10));
        assert_eq!(
            credit.group_gap_loss_with_order(
                &writer,
                &authority,
                10,
                11,
                &[10],
                &BTreeMap::new(),
                false,
            ),
            Some(0),
            "the lower GAP could not be classified after compaction"
        );
        assert!(credit.awaits(&writer, 10));
        assert_eq!(authority.order_gap_end(), last + 100);
        authority.complete_order_gap(last + 100);
        assert!(credit
            .group_heartbeat_loss(&writer, &authority, last + 1, &BTreeMap::new())
            .is_some());
        assert!(!credit.awaits(&writer, 10));
        assert_eq!(
            authority.consume(&[(1, last + 1)], &BTreeMap::new()),
            0,
            "shadow-classified loss was counted twice at completion"
        );
    }
}

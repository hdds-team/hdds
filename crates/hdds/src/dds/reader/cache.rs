// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Sample cache for DataReader with read/take semantics.
//!
//! This module provides a cache that supports both DDS `read()` (non-destructive)
//! and `take()` (destructive) operations on received samples.
//!
//! # Architecture
//!
//! ```text
//! Buffer: [S0][S1][S2][S3][S4][S5]
//!          ^              ^
//!          |              |
//!     take_cursor    write_cursor
//!
//! read()  -> peek from take_cursor, marks sample as READ
//! take()  -> removes sample, advances take_cursor
//! ```

use crate::engine::subscriber::DisposeKind;
use crate::qos::time_based_filter::gate::{now as filter_now, Gate, Stamp};
use crate::qos::time_based_filter::TimeBasedFilter;
use crate::telemetry::metrics::current_time_ns;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Sample state per DDS spec (NOT_READ vs READ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleState {
    /// Sample has not been read yet.
    NotRead,
    /// Sample has been accessed via `read()`.
    Read,
}

/// Per-instance view state (DDS v1.4 Sec.2.2.2.5.5): whether this reader
/// has already accessed a sample of the instance.
///
/// An instance is `New` until the application reads or takes one of its
/// samples through this reader (Sec.2.2.2.5.3.8: "If the sample belongs
/// to the most recent generation of the instance, it will also set the
/// view_state of the instance to NOT_NEW"); it is `NotNew` from then on.
/// Reviving an instance starts a new generation with view state `New`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewState {
    /// No sample of the instance has been read or taken yet.
    New,
    /// The reader has already handed out a sample of the instance.
    NotNew,
}

/// Hasher for 16-byte identifier keys -- an [`InstanceHandle`], or a
/// writer GUID: both are already digests of what they name, so their
/// bytes are as uniformly distributed as any hash a table could compute,
/// and the per-access cost stays at one load and one compare. Also used
/// by the reader's per-writer partition verdicts, whose key is a GUID.
#[derive(Default)]
pub(super) struct HandleHasher(u64);

impl Hasher for HandleHasher {
    fn write(&mut self, bytes: &[u8]) {
        // A `[u8; 16]` hashes through `Hash::hash` for arrays, which
        // writes the length prefix first and then the bytes; fold
        // whatever arrives so both writes contribute.
        for chunk in bytes.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.0 ^= u64::from_le_bytes(word);
        }
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// Where a sample or a transition sits in its writer's stream: the writer
/// (when known) and the sequence number. Used to decide whether a data
/// sample was sent before or after the transition that made its instance
/// NOT_ALIVE (the pump is lazy, so cache arrival order is not wire order).
pub type Origin = (Option<[u8; 16]>, u64);

/// Deterministic ordering key for DESTINATION_ORDER BY_SOURCE_TIMESTAMP
/// (DDS v1.4 Sec.2.2.3.17): a change's source timestamp, with ties broken
/// by writer identity so every reader resolves a tie the same way
/// regardless of arrival order. A local writer with no carried identity
/// (`None`) sorts before every writer whose GUID is known: arbitrary, but
/// fixed, which is all a deterministic tie-break needs.
///
/// Field 3 is the change's position in its own writer's stream: the
/// writer's FULL 64-bit sequence number (RTPS v2.5 Sec.8.3.5.4), never a
/// ring tag nor its low 32 bits, for a DATA sample, a dispose or an
/// unregister alike. A synthesized "writer departed" transition takes
/// `u64::MAX`, after everything that writer ever sent. Two different
/// writers tied on timestamp never reach it (the GUID decides); the same
/// writer can send two changes with one timestamp (a write and a dispose
/// at the same `_w_timestamp`, two writes in one clock tick), and its
/// sequence numbers then accept both, in the order it sent them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceOrderKey(pub u64, pub Option<[u8; 16]>, pub u64);

/// Per-instance bookkeeping relative to this reader: the current
/// instance state (DDS v1.4 Sec.2.2.2.5.1.3) and whether the application
/// has accessed a sample of the instance since it was last (re)born (the
/// view state, Sec.2.2.2.5.1.8).
#[derive(Clone, Copy)]
struct InstanceEntry {
    state: InstanceState,
    viewed: bool,
    /// The transition that made the instance NOT_ALIVE: a later sample of
    /// the same writer, or any sample of another writer, revives it.
    since: Option<Origin>,
    /// How many times this instance has become ALIVE again after having
    /// NO_WRITERS (DDS v1.4 Sec.2.2.2.5.1.5 `no_writers_generation_count`).
    /// Receipt-time SampleInfo snapshots never reset this running count.
    no_writers_generation_count: u32,
    disposed_generation_count: u32,
    /// BY_SOURCE_TIMESTAMP acceptance watermark (DDS v1.4 Sec.2.2.3.17):
    /// the `SourceOrderKey` of the last change (DATA or dispose/unregister
    /// alike) this instance ACCEPTED, or `None` before the first one.
    /// Lives here, beside the instance's ALIVE/NOT_ALIVE state, precisely
    /// so it survives what that state survives: every sample leaving the
    /// cache (take, read, eviction) and every instance-state transition.
    /// It is NOT derived from what the cache happens to buffer right now
    /// -- a change arriving after every newer one for this instance has
    /// already been taken must still lose, which a buffer-derived floor
    /// cannot see once the buffer is empty. Checked only when the
    /// reader's DESTINATION_ORDER is BY_SOURCE_TIMESTAMP
    /// (`InstanceTable::admit_by_source`); always `None` otherwise.
    source_accept: Option<SourceOrderKey>,
}

impl InstanceEntry {
    const ALIVE_UNSEEN: InstanceEntry = InstanceEntry {
        state: InstanceState::Alive,
        viewed: false,
        since: None,
        no_writers_generation_count: 0,
        disposed_generation_count: 0,
        source_accept: None,
    };

    fn generation_counts(&self) -> (u32, u32) {
        (
            self.disposed_generation_count,
            self.no_writers_generation_count,
        )
    }

    /// BY_SOURCE_TIMESTAMP admission (DDS v1.4 Sec.2.2.3.17): `true` and
    /// raises `source_accept` to `key` when `key` is strictly greater
    /// than it (or it is not set yet); `false`, unchanged, when `key` is
    /// older than, or tied-and-loses against, the watermark. The caller
    /// of a `false` must change nothing else.
    fn accept_by_source_order(&mut self, key: SourceOrderKey) -> bool {
        if self.source_accept.is_some_and(|floor| key <= floor) {
            return false;
        }
        self.source_accept = Some(key);
        true
    }

    /// A writer's registration holds this instance again while it is
    /// NOT_ALIVE_NO_WRITERS (DDS v1.4 Sec.2.2.2.5.1.3): revive it. Writer
    /// PRESENCE, not a value: it never touches `source_accept`, and it
    /// never revives NOT_ALIVE_DISPOSED, which only a newer accepted
    /// sample ends. The caller has checked, under the same lock, that a
    /// writer holds the instance right now. Returns whether it revived.
    fn revive_no_writers(&mut self) -> bool {
        if self.state != InstanceState::NotAliveNoWriters {
            return false;
        }
        *self = InstanceEntry {
            state: InstanceState::Alive,
            viewed: false,
            since: None,
            no_writers_generation_count: self.no_writers_generation_count.wrapping_add(1),
            disposed_generation_count: self.disposed_generation_count,
            source_accept: self.source_accept,
        };
        true
    }

    /// BY_SOURCE_TIMESTAMP admission of a data sample (DDS v1.4
    /// Sec.2.2.3.17), the one acceptance point every data sample of such
    /// a reader passes, as ONE operation under the lock the caller holds:
    ///
    /// 1. writer presence first (`held`, asked only while the instance is
    ///    NOT_ALIVE_NO_WRITERS): a sample whose value loses the ordering
    ///    still proves its writer holds the instance;
    /// 2. the ordering: `key` must be strictly greater than the last
    ///    change this instance accepted (`key: None`, a sample with no
    ///    source timestamp of its own, is not ordered);
    /// 3. `filter`, the reader's other per-instance acceptance rule
    ///    (TIME_BASED_FILTER), asked only for a sample the ordering
    ///    admits, so a rejected sample consumes nothing of it;
    /// 4. then, and only then, the watermark moves and the revive rule
    ///    ([`Self::arrive`]) applies.
    ///
    /// Returns `None` when the sample is not accepted (nothing but the
    /// presence revival changed); `Some((disposed, no_writers))`
    /// otherwise, read under this same lock (Sec.2.2.2.5.1.5).
    fn admit_by_source(
        &mut self,
        key: Option<SourceOrderKey>,
        origin: Origin,
        held: impl FnOnce() -> bool,
        filter: impl FnOnce() -> bool,
    ) -> Option<(u32, u32)> {
        if self.state == InstanceState::NotAliveNoWriters && held() {
            self.revive_no_writers();
        }
        if let Some(key) = key {
            if self.source_accept.is_some_and(|floor| key <= floor) {
                return None;
            }
        }
        if !filter() {
            return None;
        }
        if key.is_some() {
            self.source_accept = key;
        }
        self.arrive(origin);
        Some(self.generation_counts())
    }

    /// The BY_SOURCE_TIMESTAMP admission of a dispose or unregister (DDS
    /// v1.4 Sec.2.2.3.17) and its not-alive transition (`state`/`since`),
    /// as ONE operation under the lock the caller holds -- the transition
    /// counterpart of [`Self::admit_by_source`].
    ///
    /// `force` (an unregister that left the instance with no ALIVE
    /// writer): the transition applies even when its key loses the
    /// ordering, since NOT_ALIVE_NO_WRITERS is writer PRESENCE
    /// (Sec.2.2.2.5.1.3), but then without moving the watermark. `held`,
    /// when given, re-checks that presence fact under this lock: a writer
    /// that holds the instance by now makes the unregister change
    /// nothing, exactly as if its caller had seen that writer.
    ///
    /// Returns `None` when nothing applies; otherwise `Some(changed)`,
    /// `changed` false exactly when the "keeps disposed" rule
    /// (NOT_ALIVE_NO_WRITERS over NOT_ALIVE_DISPOSED changes nothing,
    /// [`InstanceTable::mark_not_alive_stamped`]) applied.
    fn accept_and_mark_not_alive(
        &mut self,
        key: Option<SourceOrderKey>,
        state: InstanceState,
        origin: Origin,
        force: bool,
        held: Option<&dyn Fn() -> bool>,
        compound: bool,
    ) -> Option<bool> {
        if force && held.is_some_and(|held| held()) {
            return None;
        }
        let accepted = match key {
            // The lifecycle half of one accepted D=1 DATA follows that
            // same source key. Older keys still lose the ordering.
            Some(key) if compound && self.source_accept == Some(key) => true,
            Some(key) => self.accept_by_source_order(key),
            None => true,
        };
        if !accepted && !force {
            return None;
        }
        let keeps_disposed = self.state == InstanceState::NotAliveDisposed
            && state == InstanceState::NotAliveNoWriters;
        if keeps_disposed {
            return Some(false);
        }
        self.state = state;
        self.since = Some(origin);
        Some(true)
    }

    fn view_state(&self) -> ViewState {
        if self.viewed {
            ViewState::NotNew
        } else {
            ViewState::New
        }
    }

    /// The revive rule (Sec.2.2.2.5.1.3, ALIVE "or else more samples have
    /// been received after it was disposed"): a sample the same writer
    /// sent before its transition does not count as received after it.
    /// Returns whether this revived the instance FROM NOT_ALIVE_NO_WRITERS
    /// specifically; either revival increments only its own counter.
    fn arrive(&mut self, origin: Origin) -> bool {
        if self.state == InstanceState::Alive {
            return false;
        }
        let after = match (self.since, origin) {
            (Some((Some(since_writer), since_seq)), (Some(writer), seq))
                if since_writer == writer =>
            {
                seq > since_seq
            }
            _ => true,
        };
        if !after {
            return false;
        }
        let revived_no_writers = self.state == InstanceState::NotAliveNoWriters;
        let no_writers_generation_count = self
            .no_writers_generation_count
            .wrapping_add(u32::from(revived_no_writers));
        // Reborn: alive again and never seen in this generation. The
        // BY_SOURCE_TIMESTAMP watermark is NOT part of this rebirth: it
        // tracks the instance's changes across every generation, since
        // DDS v1.4 Sec.2.2.3.17's final-value guarantee is about the
        // instance, not about one generation of it.
        *self = InstanceEntry {
            state: InstanceState::Alive,
            viewed: false,
            since: None,
            no_writers_generation_count,
            disposed_generation_count: self
                .disposed_generation_count
                .wrapping_add(u32::from(!revived_no_writers)),
            source_accept: self.source_accept,
        };
        revived_no_writers
    }
}

/// The instance table of one reader: state and view of every instance it
/// has seen. Shared between the cache (which stamps samples with it) and
/// the dispose queue (which records the NOT_ALIVE transitions).
///
/// The nil handle every sample of a keyless topic carries has two flags
/// in front of its entry, so the crown take path pays one Relaxed load
/// and a predictable branch per flag; keyed topics go through a map keyed
/// by the instance digest, one lock per access. The map only grows: the
/// standard tracks instances for the life of the reader as well, and
/// nothing here recycles a handle.
pub struct InstanceTable {
    /// DESTINATION_ORDER (DDS v1.4 Sec.2.2.3.17) resolved ONCE, at reader
    /// creation, into this flag: `true` for BY_SOURCE_TIMESTAMP, `false`
    /// (BY_RECEPTION_TIMESTAMP, the default) for every reader built before
    /// this field existed and for every one that does not request it.
    /// Never written again after construction, which is the point: the
    /// cache's hot push path reads this instead of a QoS policy lookup.
    by_source_timestamp: bool,
    /// Keyless fast path: has the nil instance been accessed?
    nil_seen: AtomicBool,
    /// Keyless fast path: is the nil instance NOT_ALIVE? (rare: a keyless
    /// topic disposed or left by its writers)
    nil_not_alive: AtomicBool,
    nil: Mutex<InstanceEntry>,
    /// Keyless fast path: the nil instance's
    /// generation counts packed as (disposed << 32) | no_writers,
    /// read in one snapshot with no lock while it is
    /// ALIVE (the overwhelmingly common case) - a plain field inside
    /// `nil` would force a lock on every access just to read a count that
    /// is 0 for the life of most readers.
    nil_gen: AtomicU64,
    keyed: Mutex<HashMap<InstanceHandle, InstanceEntry, BuildHasherDefault<HandleHasher>>>,
}

impl Default for InstanceTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InstanceTable {
    pub fn new() -> Self {
        Self::with_destination_order(false)
    }

    /// An instance table for a reader whose DESTINATION_ORDER resolved to
    /// BY_SOURCE_TIMESTAMP when `by_source_timestamp` is `true` (DDS v1.4
    /// Sec.2.2.3.17); to BY_RECEPTION_TIMESTAMP, unchanged from before
    /// this flag existed, when `false`.
    pub fn with_destination_order(by_source_timestamp: bool) -> Self {
        Self {
            by_source_timestamp,
            nil_seen: AtomicBool::new(false),
            nil_not_alive: AtomicBool::new(false),
            nil: Mutex::new(InstanceEntry::ALIVE_UNSEEN),
            nil_gen: AtomicU64::new(0),
            keyed: Mutex::new(HashMap::with_hasher(BuildHasherDefault::default())),
        }
    }

    /// Whether this table's reader resolved DESTINATION_ORDER to
    /// BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17).
    pub fn by_source_timestamp(&self) -> bool {
        self.by_source_timestamp
    }

    /// Whether `key` is older than, or ties and loses against, the last
    /// change `handle` accepted under BY_SOURCE_TIMESTAMP (DDS v1.4
    /// Sec.2.2.3.17), changing nothing. The watermark only rises, so a
    /// `true` here is final: the locked acceptance step refuses the
    /// change too. The network path asks it before a sample takes a place
    /// in the reader's history, so that a sample already decided against
    /// never occupies one.
    pub fn would_reject_by_source_order(
        &self,
        handle: InstanceHandle,
        key: SourceOrderKey,
    ) -> bool {
        let floor = if handle.is_nil() {
            self.nil.lock().source_accept
        } else {
            self.keyed.lock().get(&handle).and_then(|e| e.source_accept)
        };
        floor.is_some_and(|floor| key <= floor)
    }

    /// [`InstanceEntry::admit_by_source`] for `handle`: presence, ordering,
    /// `filter` and the revive rule as ONE operation under ONE lock
    /// acquisition. Only a BY_SOURCE_TIMESTAMP reader calls it; the
    /// default reader keeps the lock-free keyless path of
    /// [`Self::arrive`].
    pub fn admit_by_source(
        &self,
        handle: InstanceHandle,
        key: Option<SourceOrderKey>,
        origin: Origin,
        held: impl FnOnce() -> bool,
        filter: impl FnOnce() -> bool,
    ) -> Option<(u32, u32)> {
        if handle.is_nil() {
            let mut nil = self.nil.lock();
            let was_alive = nil.state == InstanceState::Alive;
            let admitted = nil.admit_by_source(key, origin, held, filter);
            self.sync_nil_after_revival(&nil, was_alive);
            return admitted;
        }
        let mut keyed = self.keyed.lock();
        let entry = keyed.entry(handle).or_insert(InstanceEntry::ALIVE_UNSEEN);
        entry.admit_by_source(key, origin, held, filter)
    }

    /// Writer presence for `handle` on the network path, before any
    /// ordering (DDS v1.4 Sec.2.2.2.5.1.3): revives a NOT_ALIVE_NO_WRITERS
    /// instance when `held`, asked under the instance lock, says a writer
    /// holds it now. A sample refused later for its value still proved
    /// its writer present. Never revives NOT_ALIVE_DISPOSED, never moves
    /// the BY_SOURCE_TIMESTAMP watermark.
    pub fn revive_if_held(&self, handle: InstanceHandle, held: impl FnOnce() -> bool) {
        if handle.is_nil() {
            let mut nil = self.nil.lock();
            if nil.state == InstanceState::NotAliveNoWriters && held() {
                nil.revive_no_writers();
                self.sync_nil_after_revival(&nil, false);
            }
            return;
        }
        let mut keyed = self.keyed.lock();
        if let Some(entry) = keyed.get_mut(&handle) {
            if entry.state == InstanceState::NotAliveNoWriters && held() {
                entry.revive_no_writers();
            }
        }
    }

    /// The keyless fast-path atomics after a locked operation on the nil
    /// instance: the generation count always, and the two flags only when
    /// the instance went from NOT_ALIVE to ALIVE, which starts a new
    /// generation the application has not seen. An ALIVE instance that
    /// stays ALIVE keeps its view state.
    fn sync_nil_after_revival(&self, nil: &InstanceEntry, was_alive: bool) {
        self.nil_gen.store(
            (u64::from(nil.disposed_generation_count) << 32)
                | u64::from(nil.no_writers_generation_count),
            Ordering::Relaxed,
        );
        if !was_alive && nil.state == InstanceState::Alive {
            self.nil_seen.store(false, Ordering::Relaxed);
            self.nil_not_alive.store(false, Ordering::Relaxed);
        }
    }

    /// [`InstanceEntry::accept_and_mark_not_alive`] for `handle`: the
    /// acceptance check and the not-alive transition as ONE operation
    /// under ONE lock acquisition. Returns `None` when nothing applies;
    /// otherwise `Some((changed, (disposed, no_writers)))`, the counts
    /// read under this same lock (Sec.2.2.2.5.1.5).
    pub fn accept_and_mark_not_alive(
        &self,
        handle: InstanceHandle,
        key: Option<SourceOrderKey>,
        state: InstanceState,
        origin: Origin,
        force: bool,
        held: Option<&dyn Fn() -> bool>,
    ) -> Option<(bool, (u32, u32))> {
        self.accept_and_mark_not_alive_ordered(handle, key, state, origin, force, held, false)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn accept_and_mark_not_alive_ordered(
        &self,
        handle: InstanceHandle,
        key: Option<SourceOrderKey>,
        state: InstanceState,
        origin: Origin,
        force: bool,
        held: Option<&dyn Fn() -> bool>,
        compound: bool,
    ) -> Option<(bool, (u32, u32))> {
        if handle.is_nil() {
            let mut nil = self.nil.lock();
            let changed =
                nil.accept_and_mark_not_alive(key, state, origin, force, held, compound)?;
            if changed {
                self.nil_not_alive.store(true, Ordering::Relaxed);
            }
            return Some((changed, nil.generation_counts()));
        }
        let mut keyed = self.keyed.lock();
        let entry = keyed.entry(handle).or_insert(InstanceEntry::ALIVE_UNSEEN);
        let changed = entry.accept_and_mark_not_alive(key, state, origin, force, held, compound)?;
        Some((changed, entry.generation_counts()))
    }

    /// The view and instance state of `handle` right now, changing nothing.
    fn states_of(&self, handle: InstanceHandle) -> (ViewState, InstanceState) {
        if handle.is_nil() {
            let view = if self.nil_seen.load(Ordering::Relaxed) {
                ViewState::NotNew
            } else {
                ViewState::New
            };
            let state = if self.nil_not_alive.load(Ordering::Relaxed) {
                self.nil.lock().state
            } else {
                InstanceState::Alive
            };
            return (view, state);
        }
        match self.keyed.lock().get(&handle) {
            Some(entry) => (entry.view_state(), entry.state),
            None => (ViewState::New, InstanceState::Alive),
        }
    }

    /// Record that a sample of `handle` was handed to the application
    /// (Sec.2.2.2.5.3.8/9) and return the view state that access carried,
    /// i.e. the state BEFORE it (the first access of a generation is
    /// `New`).
    #[inline]
    fn note(&self, handle: InstanceHandle) -> ViewState {
        if handle.is_nil() {
            if self.nil_seen.load(Ordering::Relaxed) {
                return ViewState::NotNew;
            }
            self.nil_seen.store(true, Ordering::Relaxed);
            if self.nil_not_alive.load(Ordering::Relaxed) {
                self.nil.lock().viewed = true;
            }
            return ViewState::New;
        }
        let mut keyed = self.keyed.lock();
        let entry = keyed.entry(handle).or_insert(InstanceEntry::ALIVE_UNSEEN);
        let view = entry.view_state();
        entry.viewed = true;
        view
    }

    /// [`note`](Self::note) that also returns the instance state of the
    /// access, in one lock for a keyed instance: what a single-sample
    /// take or read stamps its sample with.
    #[inline]
    fn access(&self, handle: InstanceHandle) -> (ViewState, InstanceState) {
        if handle.is_nil() {
            let state = if self.nil_not_alive.load(Ordering::Relaxed) {
                self.nil.lock().state
            } else {
                InstanceState::Alive
            };
            return (self.note(handle), state);
        }
        let mut keyed = self.keyed.lock();
        let entry = keyed.entry(handle).or_insert(InstanceEntry::ALIVE_UNSEEN);
        let states = (entry.view_state(), entry.state);
        entry.viewed = true;
        states
    }

    /// A data sample of `handle` reached the cache: revives a NOT_ALIVE
    /// instance when the sample was sent after the transition (see
    /// [`InstanceEntry::arrive`]). One load and a branch on the keyless
    /// path while the nil instance is alive.
    ///
    /// Returns both instance generation counters AFTER this
    /// arrival (DDS v1.4 Sec.2.2.2.5.1.5: a `SampleInfo` reports the count
    /// at the time ITS sample was received - for the sample that itself
    /// revives the instance, that is the just-incremented value). The
    /// caller stamps it onto the `CachedSample` under the same lock this
    /// already takes, so a later revival of a DIFFERENT, still-buffered
    /// sample's instance cannot change what an earlier sample reports.
    #[inline]
    pub(super) fn arrive(&self, handle: InstanceHandle, origin: Origin) -> (u32, u32) {
        if handle.is_nil() {
            if !self.nil_not_alive.load(Ordering::Relaxed) {
                return self.generation_counts(handle);
            }
            let mut nil = self.nil.lock();
            let was_alive = nil.state == InstanceState::Alive;
            nil.arrive(origin);
            self.sync_nil_after_revival(&nil, was_alive);
            return nil.generation_counts();
        }
        let mut keyed = self.keyed.lock();
        match keyed.get_mut(&handle) {
            Some(entry) => {
                entry.arrive(origin);
                entry.generation_counts()
            }
            None => (0, 0),
        }
    }

    /// A transition (dispose or unregister) for `handle` was received: the
    /// instance is `state` from now on, until a sample sent after
    /// `origin` revives it. Called by the dispose queue's producer.
    ///
    /// Losing its writers does not move an instance already disposed: it
    /// stays NOT_ALIVE_DISPOSED, and the transition that disposed it keeps
    /// deciding which sample revives it (DDS v1.4 Sec.2.2.2.5.1.3, and
    /// Sec.2.2.3.22: the last sample of an instance reports DISPOSED or
    /// NO_WRITERS "depending on whether the last writer ... disposed it or
    /// not"). Returns whether the instance state changed.
    #[cfg(test)]
    pub fn mark_not_alive(
        &self,
        handle: InstanceHandle,
        state: InstanceState,
        origin: Origin,
    ) -> bool {
        self.mark_not_alive_stamped(handle, state, origin).0
    }

    /// [`Self::mark_not_alive`], also returning the instance's
    /// generation counters read under the SAME lock that applied
    /// the transition (DDS v1.4 Sec.2.2.2.5.1.5: the count at the time this
    /// transition was received). A separate read after the lock is released
    /// could observe a concurrent sample's revival and stamp its generation
    /// on the transition that preceded it.
    pub fn mark_not_alive_stamped(
        &self,
        handle: InstanceHandle,
        state: InstanceState,
        origin: Origin,
    ) -> (bool, (u32, u32)) {
        let keeps_disposed = |current: InstanceState| {
            current == InstanceState::NotAliveDisposed && state == InstanceState::NotAliveNoWriters
        };
        if handle.is_nil() {
            let mut nil = self.nil.lock();
            // nil_gen only moves under this lock (see `arrive`).
            if self.nil_not_alive.load(Ordering::Relaxed) && keeps_disposed(nil.state) {
                return (false, nil.generation_counts());
            }
            nil.state = state;
            nil.since = Some(origin);
            self.nil_not_alive.store(true, Ordering::Relaxed);
            return (true, nil.generation_counts());
        }
        let mut keyed = self.keyed.lock();
        let entry = keyed.entry(handle).or_insert(InstanceEntry::ALIVE_UNSEEN);
        if keeps_disposed(entry.state) {
            return (false, entry.generation_counts());
        }
        entry.state = state;
        entry.since = Some(origin);
        (true, entry.generation_counts())
    }

    /// How many times `handle`'s instance has become ALIVE again after
    /// having NO_WRITERS (DDS v1.4 Sec.2.2.2.5.1.5
    /// `no_writers_generation_count`). 0 for an instance never seen.
    #[cfg(test)]
    pub fn no_writers_generation_count(&self, handle: InstanceHandle) -> u32 {
        self.generation_counts(handle).1
    }

    /// The transition that last made `handle`'s instance NOT_ALIVE, `None`
    /// while it is alive (or never seen).
    pub(super) fn since_of(&self, handle: InstanceHandle) -> Option<Origin> {
        if handle.is_nil() {
            if !self.nil_not_alive.load(Ordering::Relaxed) {
                return None;
            }
            return self.nil.lock().since;
        }
        self.keyed.lock().get(&handle).and_then(|entry| entry.since)
    }

    /// Both generation counters, from one snapshot (DDS v1.4 Sec.2.2.2.5.1.5).
    pub(super) fn generation_counts(&self, handle: InstanceHandle) -> (u32, u32) {
        if handle.is_nil() {
            let packed = self.nil_gen.load(Ordering::Relaxed);
            let [hi0, hi1, hi2, hi3, lo0, lo1, lo2, lo3] = packed.to_be_bytes();
            return (
                u32::from_be_bytes([hi0, hi1, hi2, hi3]),
                u32::from_be_bytes([lo0, lo1, lo2, lo3]),
            );
        }
        self.keyed
            .lock()
            .get(&handle)
            .map_or((0, 0), InstanceEntry::generation_counts)
    }

    /// `handle`'s current instance state (DDS v1.4 Sec.2.2.2.5.1.3), for
    /// a test that asserts directly on it rather than through a sample's
    /// own `SampleInfo`.
    #[cfg(test)]
    pub fn state_of(&self, handle: InstanceHandle) -> InstanceState {
        self.states_of(handle).1
    }
}

/// The `InstanceState` a queued transition stands for. DDS has three
/// instance states, so "disposed and unregistered" collapses to DISPOSED
/// (`DataReader::get_dispose_events` carries the exact kind).
pub fn transition_state(kind: DisposeKind) -> InstanceState {
    match kind {
        DisposeKind::Disposed | DisposeKind::DisposedUnregistered => {
            InstanceState::NotAliveDisposed
        }
        DisposeKind::Unregistered => InstanceState::NotAliveNoWriters,
    }
}

/// Instance handle for keyed topics (16-byte key hash).
///
/// This is the DDS-standard instance identifier computed from @key fields.
/// For keyless topics, this is all zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct InstanceHandle(pub [u8; 16]);

impl InstanceHandle {
    /// Create a new instance handle from a key hash.
    pub const fn new(key_hash: [u8; 16]) -> Self {
        Self(key_hash)
    }

    /// Create a nil (all zeros) instance handle for keyless topics.
    pub const fn nil() -> Self {
        Self([0u8; 16])
    }

    /// Check if this is a nil handle.
    pub fn is_nil(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Get the raw key hash bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Instance lifecycle state (DDS v1.4 Sec.2.2.2.5.1.3), maintained per
/// instance by the reader's [`InstanceTable`]: a data sample reports the
/// CURRENT state of its instance at the time it is accessed, so the
/// retained samples of a disposed instance report NOT_ALIVE_DISPOSED; a
/// transition sample (`valid_data == false`) reports the state it
/// announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceState {
    /// The instance has a live writer and samples are flowing.
    Alive,
    /// The instance was explicitly disposed by a writer.
    NotAliveDisposed,
    /// Every writer of the instance unregistered or went away.
    NotAliveNoWriters,
}

/// Per-sample metadata returned by `DataReader::take_with_info()`
/// (DDS v1.4 sec. 2.2.2.5.5 SampleInfo, reduced to what the engine
/// actually carries today).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleInfo {
    /// The WRITER's timestamp for the sample: the write-side clock on
    /// the intra-process path, the datagram's INFO_TS on the network
    /// path. `None` when the writer sent no INFO_TS (best-effort
    /// vendors may omit it), in which case only the reception time is
    /// known.
    pub source_timestamp_ns: Option<u64>,
    /// When this reader observed the sample. Exact push-time reception
    /// when no source timestamp is known; otherwise stamped at pop
    /// time (the pump is lazy and runs inside `take`), which can
    /// overstate latency for backlogged samples.
    pub reception_timestamp_ns: u64,
    /// GUID of the originating DataWriter. Network samples and opaque local
    /// captures retain it when known. Typed intra-process samples retain it
    /// under BY_SOURCE_TIMESTAMP; unattributed traffic returns `None`.
    pub writer_guid: Option<[u8; 16]>,
    /// Full writer sequence number when its GUID is known. For anonymous
    /// local deliveries, the ring's per-source dedup tag is stripped.
    pub sequence_number: u64,
    /// Instance handle (key hash for keyed topics, nil otherwise).
    pub instance_handle: InstanceHandle,
    /// The instance's current state at this access (see
    /// [`InstanceState`]); for a transition, the state it announces.
    pub instance_state: InstanceState,
    /// `false` for an instance-state transition, which carries no data.
    pub valid_data: bool,
    /// Whether the sample had already been returned by a `read` before
    /// this access (DDS v1.4 Sec.2.2.2.5.5). A taken sample that was
    /// never read reports [`SampleState::NotRead`].
    pub sample_state: SampleState,
    /// View state of the sample's instance at the time of this access
    /// (see [`ViewState`]): `New` exactly on the first sample of an
    /// instance this reader hands out.
    pub view_state: ViewState,
    /// How many times the instance has become ALIVE again after having
    /// NO_WRITERS, at the time this sample was received (DDS v1.4 Sec.2.2.2.5.1.5
    /// `no_writers_generation_count`): incremented on a write received
    /// after the instance lost its last writer, whether that was an
    /// explicit unregister, a departure, or a LIVELINESS lease expiry
    /// (Sec.2.2.3.23.2).
    pub no_writers_generation_count: u32,
    /// Number of DISPOSED-to-ALIVE transitions at receipt (DDS v1.4 Sec.2.2.2.5.1.5).
    pub disposed_generation_count: u32,
    /// Number of later returned samples of the same instance.
    pub sample_rank: u32,
    /// Generation distance from the newest returned sample of this instance.
    pub generation_rank: u32,
    /// Generation distance from the newest sample received for this instance.
    pub absolute_generation_rank: u32,
}

/// Cached sample with metadata.
#[derive(Debug)]
pub struct CachedSample<T> {
    /// The actual data.
    pub data: T,
    /// Full writer sequence number when `writer_guid` is known. Otherwise
    /// the low 32 bits are the local writer SN and the high bits a ring
    /// tag distinguishing anonymous local writers for deduplication.
    pub seq: u64,
    /// Source timestamp when `has_source_ts`, else reception timestamp
    /// (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Instance handle (key hash for keyed topics).
    pub instance_handle: InstanceHandle,
    /// GUID of the originating writer, when the delivery path knew it.
    pub writer_guid: Option<[u8; 16]>,
    /// Whether `timestamp_ns` is the writer's source timestamp rather
    /// than local reception time.
    pub has_source_ts: bool,
    /// View state of the instance when this sample left the cache. Set
    /// by the cache at pop/read time (`InstanceTable::access`); `New`
    /// while the sample is still cached.
    pub view_state: ViewState,
    /// Instance state at the same access (snapshot per Sec.2.2.2.5.1.3);
    /// `Alive` while the sample is still cached.
    pub instance_state: InstanceState,
    /// The instance's `no_writers_generation_count` (DDS v1.4
    /// Sec.2.2.2.5.1.5) AT THE TIME THIS SAMPLE WAS RECEIVED - unlike
    /// `view_state`/`instance_state` above, the spec fixes this one at
    /// reception, not at access: two samples straddling a revival must
    /// report different counts even when taken together, so it is
    /// stamped once, at push (`InstanceTable::arrive`'s return), and
    /// never touched again.
    pub no_writers_generation_count: u32,
    /// Number of DISPOSED-to-ALIVE transitions at receipt (DDS v1.4 Sec.2.2.2.5.1.5).
    pub disposed_generation_count: u32,
    /// Sample state (NOT_READ vs READ).
    state: AtomicBool, // false = NotRead, true = Read
    /// What the sample holds in its reader's history
    /// (`admission::HistoryRoom`), when it arrived from the network: a
    /// place of a KEEP_ALL history ([`HELD_PLACE`]), and one of the samples
    /// its instance is counted for when the room bounds instances
    /// ([`HELD_INSTANCE`]). Both are counted in the room; the
    /// [`SampleCache`] holding the sample gives them back when the sample
    /// leaves the cache, at every removal site. Flags rather than the place
    /// itself, so that this struct has no drop glue: a field with a
    /// destructor here made every sample on the one-thread take path
    /// slower, even on readers that never hold a place. A clone holds none.
    held: u8,
}

/// [`CachedSample::held`]: a place of a KEEP_ALL history.
pub(super) const HELD_PLACE: u8 = 1;
/// [`CachedSample::held`]: a sample counted for its instance.
pub(super) const HELD_INSTANCE: u8 = 2;
/// Both counters were stamped before this sample entered its network ring.
const RECEIPT_STAMPED: u8 = 4;

// `CachedSample` of a plain-data payload has no drop glue: moving one along
// the take path is a plain copy and nothing runs when one is dropped. A
// field with a destructor (a history place would be one) makes the
// compiler track every move through stack temporaries with drop flags;
// costing about 20 ns per sample on the one-thread
// write-then-take path (blocked store-forwards 4 -> 12 per message), on
// every reader, whether or not it used the field. Keep places, handles and
// buffers out of this struct; give them to the `SampleCache` instead.
const _: () = assert!(!std::mem::needs_drop::<CachedSample<[u8; 16]>>());

// Keep the receipt-time counters inline: metadata survives cache removal
// without allocation or drop glue. The second counter uses existing padding.
const _: () = assert!(std::mem::size_of::<CachedSample<[u8; 16]>>() <= 80);

impl<T: Clone> Clone for CachedSample<T> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            seq: self.seq,
            timestamp_ns: self.timestamp_ns,
            instance_handle: self.instance_handle,
            writer_guid: self.writer_guid,
            has_source_ts: self.has_source_ts,
            view_state: self.view_state,
            instance_state: self.instance_state,
            no_writers_generation_count: self.no_writers_generation_count,
            disposed_generation_count: self.disposed_generation_count,
            state: AtomicBool::new(self.state.load(Ordering::Relaxed)),
            held: self.held & RECEIPT_STAMPED,
        }
    }
}

impl<T> CachedSample<T> {
    /// Record what the sample holds in its reader's history (`HELD_*`
    /// flags), counted by its writer's door before it reached the reader's
    /// local ring; the cache gives it back when the sample leaves.
    #[inline(always)]
    pub(super) fn set_held(&mut self, held: u8) {
        self.held = (self.held & RECEIPT_STAMPED) | held;
    }

    /// Preserve the receipt snapshot through the lazy network pump.
    pub(super) fn stamp_received(&mut self, counts: (u32, u32)) {
        (
            self.disposed_generation_count,
            self.no_writers_generation_count,
        ) = counts;
        self.held |= RECEIPT_STAMPED;
    }

    pub(super) fn receipt_stamped(&self) -> bool {
        self.held & RECEIPT_STAMPED != 0
    }

    /// Whether the sample holds a place in its KEEP_ALL reader's history.
    #[inline(always)]
    fn holds_place(&self) -> bool {
        self.held & HELD_PLACE != 0
    }

    /// Create a new cached sample (keyless topic, nil instance handle).
    #[allow(dead_code)] // DDS API - available for DataReader extensions
    pub fn new(data: T, seq: u64, timestamp_ns: u64) -> Self {
        Self::with_meta(data, seq, timestamp_ns, InstanceHandle::nil(), None, false)
    }

    /// Create a new cached sample with an instance handle (keyed topic).
    #[allow(dead_code)] // DDS API - metadata-free constructor kept for extensions
    pub fn with_instance(
        data: T,
        seq: u64,
        timestamp_ns: u64,
        instance_handle: InstanceHandle,
    ) -> Self {
        Self::with_meta(data, seq, timestamp_ns, instance_handle, None, false)
    }

    /// Create a cached sample carrying the full delivery metadata. The
    /// other constructors delegate here with `None`/`false` so callers
    /// that predate `SampleInfo` keep their exact behaviour.
    pub fn with_meta(
        data: T,
        seq: u64,
        timestamp_ns: u64,
        instance_handle: InstanceHandle,
        writer_guid: Option<[u8; 16]>,
        has_source_ts: bool,
    ) -> Self {
        Self {
            data,
            seq,
            timestamp_ns,
            instance_handle,
            writer_guid,
            has_source_ts,
            view_state: ViewState::New,
            instance_state: InstanceState::Alive,
            // Stamped for real by `SampleCache::push_locked` (and its
            // fused push+take twins) from `InstanceTable::arrive`'s
            // return, before this sample is ever handed back out: 0 here
            // is the pre-push placeholder, never the value `take_with_info`
            // reports.
            no_writers_generation_count: 0,
            disposed_generation_count: 0,
            state: AtomicBool::new(false), // NotRead
            held: 0,
        }
    }

    /// Where this sample sits in its writer's stream (see [`Origin`]).
    fn origin(&self) -> Origin {
        let sn = if self.writer_guid.is_some() {
            self.seq
        } else {
            self.seq & 0xFFFF_FFFF
        };
        (self.writer_guid, sn)
    }

    /// Did this sample's own writer send it at or before `transition`, the
    /// change that made its instance NOT_ALIVE? The negation of the revive
    /// rule's "received after" (`InstanceEntry::arrive`), for the same
    /// writer only: across writers nothing orders two changes.
    fn precedes(&self, transition: Option<Origin>) -> bool {
        match (transition, self.origin()) {
            (Some((Some(writer), since_seq)), (Some(own), seq)) => {
                writer == own && seq <= since_seq
            }
            _ => false,
        }
    }

    /// Get sample state.
    pub fn sample_state(&self) -> SampleState {
        if self.state.load(Ordering::Relaxed) {
            SampleState::Read
        } else {
            SampleState::NotRead
        }
    }

    /// Mark sample as read.
    pub fn mark_read(&self) {
        self.state.store(true, Ordering::Relaxed);
    }

    /// Split the sample into its data and the public [`SampleInfo`].
    ///
    /// Reception semantics: when the source timestamp is known,
    /// `timestamp_ns` holds it and the reception time is stamped HERE
    /// (pop time, see the `SampleInfo` field docs); when it is not,
    /// `timestamp_ns` already IS the push-time reception stamp.
    ///
    /// `no_writers_generation_count`: stamped on this sample at push time
    /// (`SampleCache::push_locked`), the count AT RECEPTION (DDS v1.4
    /// Sec.2.2.2.5.1.5), not whatever the instance table says now - a
    /// later revival of a sample buffered behind this one must not change
    /// what this one reports.
    pub fn into_data_and_info(self) -> (T, SampleInfo) {
        let info = SampleInfo {
            source_timestamp_ns: if self.has_source_ts {
                Some(self.timestamp_ns)
            } else {
                None
            },
            reception_timestamp_ns: if self.has_source_ts {
                current_time_ns()
            } else {
                self.timestamp_ns
            },
            writer_guid: self.writer_guid,
            sequence_number: self.origin().1,
            instance_handle: self.instance_handle,
            instance_state: self.instance_state,
            valid_data: true,
            sample_state: self.sample_state(),
            view_state: self.view_state,
            no_writers_generation_count: self.no_writers_generation_count,
            disposed_generation_count: self.disposed_generation_count,
            sample_rank: 0,
            generation_rank: 0,
            absolute_generation_rank: 0,
        };
        (self.data, info)
    }
}

/// Sample cache with read/take cursor semantics.
///
/// Supports DDS-compliant read (non-destructive) and take (destructive) operations.
pub struct SampleCache<T> {
    /// Ring buffer of cached samples.
    buffer: Mutex<VecDeque<CachedSample<T>>>,
    /// Read cursor position (for read operations).
    /// Samples before this cursor have been read at least once.
    read_cursor: AtomicUsize,
    /// Maximum number of samples to keep per instance (history depth).
    max_samples: usize,
    /// Maximum number of samples to keep across instances, the oldest
    /// discarded first: a BEST_EFFORT KEEP_ALL reader's `max_samples`
    /// ([`with_total`](Self::with_total)); `usize::MAX` otherwise.
    max_total: usize,
    /// `min(max_samples, max_total)`: below this length no bound can be
    /// reached, and the push scans nothing.
    evict_at: usize,
    /// Total samples received (for stats).
    total_received: AtomicUsize,
    /// Samples pushed out of this history before the application read
    /// them (the replacement drop at the bound). The reader's share of
    /// `ReaderStats::drops`, raised at the telemetry drop door.
    dropped: AtomicU64,
    /// The reader's instance table (view and instance state per instance,
    /// DDS v1.4 Sec.2.2.2.5.1.3 and 2.2.2.5.1.8), shared with the dispose
    /// queue that records the NOT_ALIVE transitions.
    instances: Arc<InstanceTable>,
    /// The KEEP_ALL reader's history room, or any reader's whose room
    /// bounds instances; `None` otherwise. What a sample's `held` flags say
    /// it holds is counted there, given back at each site a sample leaves
    /// the buffer (pops, selective and batch takes, the dedup refusal, the
    /// KEEP_LAST replacement, `clear`, and the cache's drop).
    room: Option<Arc<super::admission::HistoryRoom>>,
    /// The reader's TIME_BASED_FILTER at its application boundary (DDS v1.4
    /// Sec.2.2.3.12), `None` for a reader without one or one that orders by
    /// source timestamp (which asks the filter inside its admission).
    tbf: Option<Tbf<T>>,
}

/// A sample parked by the TIME_BASED_FILTER, with the instance's last
/// transition at the moment it was parked: a transition that arrives while
/// it waits makes it stale, and it is dropped rather than shown after it.
struct Parked<T> {
    sample: CachedSample<T>,
    since: Option<Origin>,
    /// The instance's generation counters then: a sample received after the
    /// instance came back to life (a dispose, then a newer sample) moved
    /// them, and the value that waited is from the generation before.
    counts: (u32, u32),
    /// Order of parking across instances, so that samples that fall due
    /// together enter the history in the order they were received.
    order: u64,
    /// The sample's age (ns) when it reached the filter, and the instant it
    /// did: how old it is when it comes out is that age plus the wait.
    age_ns: u64,
    staged: Instant,
}

/// What the TIME_BASED_FILTER stage knows, behind its own lock (taken after
/// the buffer's, never before).
struct TbfGates<T> {
    gates: HashMap<InstanceHandle, Gate<Parked<T>>>,
    /// The instances with a parked sample.
    parked: Vec<InstanceHandle>,
    next_order: u64,
    /// A lower bound of the instant any parked sample's window ends:
    /// an access before it has nothing to promote and scans nothing.
    earliest: Option<Instant>,
}

struct Tbf<T> {
    separation: Duration,
    /// Whether a sample that arrives with the window closed waits for it to
    /// end. A reader whose samples are claimed in a presentation order
    /// (ordered access) cannot let one wait: the order is told its place
    /// when it is pumped, so there it is dropped, as the strict rule does.
    park: bool,
    state: Mutex<TbfGates<T>>,
    /// How many samples are parked: read without a lock before every access
    /// to know whether any could be due.
    parked: Arc<AtomicUsize>,
    /// Told `(instance, instant)` when a sample is parked and the instant it
    /// is due is not one already told (into an empty slot, or replacing a
    /// sample and moving that instant): to wake the application at.
    wake: Option<Arc<dyn Fn(InstanceHandle, Instant) + Send + Sync>>,
    /// The lifespan (ns, `u64::MAX` for none) a sample of the given writer
    /// expires by (DDS v1.4 Sec.2.2.3.16). A sample that waited in the gate
    /// is checked against it when it comes out, as a sample that did not
    /// wait is checked when it is pumped.
    lifespan: Option<Lifespan>,
}

/// See [`Tbf::lifespan`].
pub(super) type Lifespan = Arc<dyn Fn(Option<&[u8; 16]>) -> u64 + Send + Sync>;

impl<T> SampleCache<T> {
    /// This cache's instance table, for a caller outside this module that
    /// needs a read-only BY_SOURCE_TIMESTAMP peek before a side effect of
    /// its own (`InstanceTable::would_reject_by_source_order`) -- the
    /// runtime's decode step, which runs before a sample ever reaches
    /// this cache's own gate.
    pub(super) fn instances(&self) -> &InstanceTable {
        &self.instances
    }

    /// Create a new sample cache with given history depth and its own
    /// instance table.
    #[allow(dead_code)] // cache-level tests build a cache without a reader
    pub fn new(max_samples: usize) -> Self {
        Self::with_instances(max_samples, Arc::new(InstanceTable::new()))
    }

    /// Create a sample cache sharing `instances` with the reader's
    /// dispose queue.
    pub fn with_instances(max_samples: usize, instances: Arc<InstanceTable>) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(max_samples.min(1024))),
            read_cursor: AtomicUsize::new(0),
            max_samples,
            max_total: usize::MAX,
            evict_at: max_samples,
            total_received: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
            instances,
            room: None,
            tbf: None,
        }
    }

    pub(super) fn local_order_keys(&self) -> Vec<super::local_order::CacheKey> {
        self.buffer
            .lock()
            .iter()
            .map(|sample| (sample.writer_guid, sample.seq))
            .collect()
    }

    /// The same cache keeping at most `max_total` samples across its
    /// instances, discarding the oldest one that holds no place in a
    /// KEEP_ALL history (`usize::MAX` for no bound): a BEST_EFFORT KEEP_ALL
    /// reader's RESOURCE_LIMITS `max_samples`, at which "the old values will
    /// be discarded" (DDS v1.4 Sec.2.2.3.18).
    pub(super) fn with_total(mut self, max_total: usize) -> Self {
        self.max_total = max_total;
        self.evict_at = self.max_samples.min(max_total);
        self
    }

    /// The cache of a KEEP_ALL reader whose network arrivals hold places in
    /// `room` (see [`push_holding`](Self::push_holding)).
    pub(super) fn with_room(mut self, room: Option<Arc<super::admission::HistoryRoom>>) -> Self {
        self.room = room;
        self
    }

    /// The same cache showing its samples through the reader's
    /// TIME_BASED_FILTER (DDS v1.4 Sec.2.2.3.12): an instance shows one
    /// sample per `filter.minimum_separation`, measured between the instants
    /// two samples enter this cache (the instants the application can first
    /// see them), not between their arrivals. A sample that comes while the
    /// window is closed is parked; the newest parked sample enters at the
    /// first access at or after the window's end. HISTORY applies to what
    /// enters, as the policy says ("they apply after the TIME_BASED_FILTER
    /// has been applied"). `park`: see [`Tbf::park`]. `wake` is told, with
    /// the instant a parked sample is due, whenever that instant is new (a
    /// sample parked into an empty slot, or one that moved it).
    /// `lifespan`: see [`Tbf::lifespan`].
    pub(super) fn with_time_based_filter(
        mut self,
        filter: TimeBasedFilter,
        park: bool,
        wake: Option<Arc<dyn Fn(InstanceHandle, Instant) + Send + Sync>>,
        lifespan: Option<Lifespan>,
    ) -> Self {
        self.tbf = (!filter.is_disabled() && !self.instances.by_source_timestamp()).then(|| Tbf {
            separation: filter.minimum_separation,
            park,
            state: Mutex::new(TbfGates {
                gates: HashMap::new(),
                parked: Vec::new(),
                next_order: 0,
                earliest: None,
            }),
            parked: Arc::new(AtomicUsize::new(0)),
            wake,
            lifespan,
        });
        self
    }

    /// The buffer, after letting the parked samples whose window has ended
    /// enter it: every access goes through here, so a sample is visible at
    /// the first access at or after its window's end and never before.
    #[inline(always)]
    fn buffer_locked(&self) -> parking_lot::MutexGuard<'_, VecDeque<CachedSample<T>>> {
        let mut buffer = self.buffer.lock();
        if let Some(tbf) = self.tbf.as_ref() {
            if tbf.parked.load(Ordering::Acquire) != 0 {
                self.promote_due(tbf, &mut buffer);
            }
        }
        buffer
    }

    /// How many samples the filter holds parked, readable without a lock:
    /// the wake of a window that ended asks whether anything is left to
    /// announce.
    pub(super) fn parked_probe(&self) -> Option<Arc<AtomicUsize>> {
        self.tbf.as_ref().map(|tbf| Arc::clone(&tbf.parked))
    }

    /// Tests and diagnostics: how many samples the filter holds parked.
    #[cfg(test)]
    pub(super) fn parked_count(&self) -> usize {
        self.tbf
            .as_ref()
            .map_or(0, |tbf| tbf.parked.load(Ordering::Acquire))
    }

    #[cold]
    #[inline(never)]
    fn promote_due(&self, tbf: &Tbf<T>, buffer: &mut VecDeque<CachedSample<T>>) {
        let now = filter_now();
        let mut due: Vec<Parked<T>> = Vec::new();
        let mut stale: Vec<Parked<T>> = Vec::new();
        {
            let mut state = tbf.state.lock();
            if state.earliest.is_some_and(|earliest| now < earliest) {
                return;
            }
            let TbfGates {
                gates,
                parked,
                earliest,
                ..
            } = &mut *state;
            *earliest = None;
            parked.retain(|handle| {
                let Some(gate) = gates.get_mut(handle) else {
                    return false;
                };
                if let Some(old) = self.discard_stale(tbf, gate, now) {
                    stale.push(old);
                    return false;
                }
                match gate.due(tbf.separation, now) {
                    Some(sample) => {
                        due.push(sample);
                        false
                    }
                    None => {
                        if let Some(at) = gate.ready_at(tbf.separation) {
                            *earliest = Some(earliest.map_or(at, |e| e.min(at)));
                        }
                        gate.is_parked()
                    }
                }
            });
        }
        for old in stale {
            tbf.parked.fetch_sub(1, Ordering::AcqRel);
            self.release_place(&old.sample);
        }
        due.sort_by_key(|parked| parked.order);
        for parked in due {
            tbf.parked.fetch_sub(1, Ordering::AcqRel);
            self.push_shown(buffer, parked.sample);
        }
    }

    /// Take out of `gate` the sample it holds parked if it has gone stale at
    /// `now`, so that it neither reaches the history nor closes the window
    /// of the instance (nothing was shown). A sample is stale when:
    /// - its instance went through a transition while it waited (the
    ///   application would see the value after the change that came after
    ///   it), or came back to life (the value is from the generation before);
    /// - its lifespan ran out while it waited (DDS v1.4 Sec.2.2.3.16): the
    ///   age it had when it reached the filter plus the wait.
    fn discard_stale(
        &self,
        tbf: &Tbf<T>,
        gate: &mut Gate<Parked<T>>,
        now: Instant,
    ) -> Option<Parked<T>> {
        let stale = gate.parked_sample().is_some_and(|parked| {
            let handle = parked.sample.instance_handle;
            if self.instances.since_of(handle) != parked.since
                || self.instances.generation_counts(handle) != parked.counts
            {
                return true;
            }
            let waited = now.saturating_duration_since(parked.staged);
            if waited.is_zero() {
                return false;
            }
            let Some(lifespan) = tbf.lifespan.as_ref() else {
                return false;
            };
            let lifespan = lifespan(parked.sample.writer_guid.as_ref());
            let waited = u64::try_from(waited.as_nanos()).unwrap_or(u64::MAX);
            lifespan != u64::MAX && parked.age_ns.saturating_add(waited) > lifespan
        });
        if stale {
            gate.discard()
        } else {
            None
        }
    }

    /// The TIME_BASED_FILTER stage of `push_locked`.
    ///
    /// Known limits of the stage, which is the one place the filter reads the
    /// reader's instance table:
    /// - the instance table (view and instance state, generation counts) is
    ///   updated when a sample is admitted, up to one separation before the
    ///   sample is visible; read conditions see that state;
    /// - a dispose or unregister of a writer is visible as soon as it is
    ///   received: a value of the same writer that is still parked is
    ///   dropped when it comes out (the transition came after it), so the
    ///   application sees the dispose and not the value the writer sent
    ///   before it;
    /// - an arrival raises DATA_AVAILABLE when it is received, also when the
    ///   sample is parked: a wait on it may wake and find nothing to take
    ///   until the window ends;
    /// - a KEEP_ALL history bounded by RESOURCE_LIMITS reserves the place of
    ///   a parked sample until it is replaced or dropped, so a newer sample
    ///   of the instance can be refused for want of a place a parked one
    ///   holds.
    fn stage(&self, tbf: &Tbf<T>, buffer: &mut VecDeque<CachedSample<T>>, sample: CachedSample<T>) {
        let handle = sample.instance_handle;
        let now = filter_now();
        let since = self.instances.since_of(handle);
        let counts = self.instances.generation_counts(handle);
        // A reception time is not the writer's clock: only a source
        // timestamp says when the writer produced the sample.
        let stamp = sample.has_source_ts.then_some(Stamp {
            writer: sample.writer_guid,
            nanos: sample.timestamp_ns,
        });
        let age_ns = current_time_ns().saturating_sub(sample.timestamp_ns);
        let stale: Option<Parked<T>>;
        let mut refused: Option<Parked<T>> = None;
        let (offered, was_parked, is_parked) = {
            let mut state = tbf.state.lock();
            let order = state.next_order;
            state.next_order += 1;
            let TbfGates {
                gates,
                parked,
                earliest,
                ..
            } = &mut *state;
            let gate = gates.entry(handle).or_default();
            let was_parked = gate.is_parked();
            stale = self.discard_stale(tbf, gate, now);
            let staged = Parked {
                sample,
                since,
                counts,
                order,
                age_ns,
                staged: now,
            };
            // A cache that can let a sample wait holds back one that does
            // not show at once (the window, the sample ahead of it, a better
            // pick). One that cannot (ordered or coherent access) keeps the
            // strict rule: it shows what finds the window open, whatever its
            // pick, and drops what finds it closed; a better pick is not
            // worth a sample fewer than one per separation. Both drop a
            // sample its own writer sent before the instance's last
            // transition: it is not shown after it (the revive rule,
            // `InstanceEntry::arrive`, does not count it as received after
            // that transition either).
            let offered = if tbf.park {
                if !gate.shows_at_once(tbf.separation, now, stamp) && staged.sample.precedes(since)
                {
                    refused = Some(staged);
                    None
                } else {
                    Some(gate.offer(tbf.separation, now, stamp, staged))
                }
            } else if !gate.open(tbf.separation, now) || staged.sample.precedes(since) {
                refused = Some(staged);
                None
            } else {
                Some(gate.show_now(now, stamp, staged))
            };
            let is_parked = gate.is_parked();
            if let Some(at) = gate.ready_at(tbf.separation) {
                *earliest = Some(earliest.map_or(at, |e| e.min(at)));
            }
            if is_parked && !was_parked {
                parked.push(handle);
            } else if was_parked && !is_parked {
                parked.retain(|h| *h != handle);
            }
            (offered, was_parked, is_parked)
        };
        match (was_parked, is_parked) {
            (false, true) => {
                tbf.parked.fetch_add(1, Ordering::AcqRel);
            }
            (true, false) => {
                tbf.parked.fetch_sub(1, Ordering::AcqRel);
            }
            _ => {}
        }
        if let Some(old) = stale {
            self.release_place(&old.sample);
        }
        if let Some(refused) = refused {
            self.release_place(&refused.sample);
        }
        let Some(offered) = offered else {
            return;
        };
        if let Some(replaced) = offered.replaced {
            self.release_place(&replaced.sample);
        }
        if let Some(shown) = offered.shown {
            self.push_shown(buffer, shown.sample);
        }
        if let (Some(at), Some(wake)) = (offered.wake_at, tbf.wake.as_ref()) {
            wake(handle, at);
        }
    }

    /// Give back the history places of `count` samples that just left the
    /// buffer holding one. Out of line: no sample on a reader without a room
    /// ever holds a place, so the take path only tests the flag.
    #[cold]
    #[inline(never)]
    fn give_back(&self, count: usize) {
        match self.room.as_ref() {
            Some(room) => room.give_back(count),
            None => debug_assert!(count == 0, "a place held in a cache without a room"),
        }
        // Tests only: a seam right where a room's places (and, through
        // `HistoryRoom::came_back`, any coherent set waiting for one) come
        // back -- late enough in `DataReader`'s teardown (this cache is a
        // field, dropped by Rust's implicit glue, never the reader's own
        // explicit `Drop::drop` body) to see whatever this reader's own
        // strong holds have or have not already released by this point.
        #[cfg(test)]
        if let Some(hook) = AFTER_GIVE_BACK.with(|h| h.borrow_mut().take()) {
            hook();
        }
    }

    /// Give back what one sample leaving the buffer holds.
    #[inline(always)]
    fn release_place(&self, sample: &CachedSample<T>) {
        if sample.held & (HELD_PLACE | HELD_INSTANCE) != 0 {
            self.release_held(sample.held, &sample.instance_handle);
        }
    }

    /// [`release_place`](Self::release_place) for a sample holding
    /// something: out of line, like [`give_back`](Self::give_back).
    #[cold]
    #[inline(never)]
    fn release_held(&self, held: u8, instance: &InstanceHandle) {
        if held & HELD_PLACE != 0 {
            self.give_back(1);
        }
        if held & HELD_INSTANCE != 0 {
            self.release_instance(instance);
        }
    }

    /// Give back one sample counted for `instance`.
    #[cold]
    #[inline(never)]
    fn release_instance(&self, instance: &InstanceHandle) {
        match self.room.as_ref() {
            Some(room) => room.release_instance(instance.as_bytes()),
            None => debug_assert!(false, "an instance counted in a cache without a room"),
        }
    }

    /// Give back what the parked samples hold, counting their places into
    /// `places` as [`release_in_batch`](Self::release_in_batch) does.
    fn release_parked_in_batch(&self, places: &mut usize) {
        let Some(tbf) = self.tbf.as_ref() else {
            return;
        };
        let mut state = tbf.state.lock();
        let TbfGates { gates, parked, .. } = &mut *state;
        for handle in parked.drain(..) {
            if let Some(dropped) = gates.get_mut(&handle).and_then(Gate::discard) {
                self.release_in_batch(&dropped.sample, places);
            }
        }
        tbf.parked.store(0, Ordering::Release);
    }

    /// For the batch removals: count `sample`'s place into `places`, given
    /// back once for the batch, and give back its instance count now.
    #[inline(always)]
    fn release_in_batch(&self, sample: &CachedSample<T>, places: &mut usize) {
        *places += usize::from(sample.held & HELD_PLACE != 0);
        if sample.held & HELD_INSTANCE != 0 {
            self.release_instance(&sample.instance_handle);
        }
    }

    /// The view state an instance has right now (DDS v1.4 Sec.2.2.2.5.1.8),
    /// without changing it. `New` until a sample of the instance has been
    /// read or taken through this cache in its current generation.
    pub fn view_state_of(&self, handle: InstanceHandle) -> ViewState {
        self.instances.states_of(handle).0
    }

    /// Record that the application was handed a sample of `handle`
    /// (a read or a take, Sec.2.2.2.5.3.8/9) and return the view state
    /// that access carried. For an instance-state transition delivered
    /// from outside the cache, so that the instance turns `NotNew` the
    /// way it does for a data sample.
    pub fn note_viewed(&self, handle: InstanceHandle) -> ViewState {
        self.instances.note(handle)
    }

    /// Stamp `sample` with the view and instance state its instance has
    /// at this access and record the access. Runs at every point a
    /// sample leaves the cache or is read in place, one at a time.
    #[inline]
    fn stamp_access(&self, sample: &mut CachedSample<T>) {
        let (view, state) = self.instances.access(sample.instance_handle);
        sample.view_state = view;
        sample.instance_state = state;
    }

    /// True when at least one cached sample satisfies `pred`, which is
    /// given the sample and the CURRENT view and instance state of its
    /// instance. The predicate runs under the cache lock and must not
    /// call back into the reader.
    pub fn any_matching(
        &self,
        mut pred: impl FnMut(&CachedSample<T>, ViewState, InstanceState) -> bool,
    ) -> bool {
        let buffer = self.buffer_locked();
        buffer.iter().any(|sample| {
            let (view, state) = self.instances.states_of(sample.instance_handle);
            pred(sample, view, state)
        })
    }

    /// The pending origins of the samples at index `from` or later
    /// satisfying `pred`, without changing anything: what a conditional take
    /// or read places a queued transition against (see `pending_origins`).
    pub fn pending_matching_origins_from(
        &self,
        from: usize,
        mut pred: impl FnMut(&CachedSample<T>, ViewState, InstanceState) -> bool,
    ) -> Vec<Origin> {
        let buffer = self.buffer_locked();
        earliest_per_writer(buffer.iter().skip(from).filter(|sample| {
            let (view, state) = self.instances.states_of(sample.instance_handle);
            pred(sample, view, state)
        }))
    }

    /// Remove and return the first sample satisfying `pred`, stamped with
    /// the CURRENT view and instance state of its instance. The access is
    /// NOT recorded: a conditional take records every instance it
    /// returned once its whole collection is selected, so the view state
    /// is one snapshot per instance across the collection
    /// (Sec.2.2.2.5.1.8); the caller calls [`note_viewed`](Self::note_viewed)
    /// for each returned sample's instance afterwards.
    pub fn take_first_matching(
        &self,
        pred: impl FnMut(&CachedSample<T>, ViewState, InstanceState) -> bool,
    ) -> Option<CachedSample<T>> {
        never(self.take_first_matching_if(pred, |_| Ok::<(), Infallible>(())))
    }

    /// [`take_first_matching`](Self::take_first_matching), unless `fits`
    /// refuses the data of the sample it would take: then nothing is
    /// removed, the sample stays first in its place, and the refusal is
    /// returned. Under the same lock as the take, so the sample that was
    /// checked is the one removed.
    pub fn take_first_matching_if<E>(
        &self,
        mut pred: impl FnMut(&CachedSample<T>, ViewState, InstanceState) -> bool,
        fits: impl Fn(&T) -> Result<(), E>,
    ) -> Result<Option<CachedSample<T>>, E> {
        let mut buffer = self.buffer_locked();
        let Some((pos, view, state)) = buffer.iter().enumerate().find_map(|(pos, sample)| {
            let (view, state) = self.instances.states_of(sample.instance_handle);
            pred(sample, view, state).then_some((pos, view, state))
        }) else {
            return Ok(None);
        };
        fits(&buffer[pos].data)?;
        let Some(mut sample) = buffer.remove(pos) else {
            return Ok(None);
        };
        self.release_place(&sample);
        sample.view_state = view;
        sample.instance_state = state;
        let cursor = self.read_cursor.load(Ordering::Relaxed);
        if pos < cursor {
            self.read_cursor.store(cursor - 1, Ordering::Relaxed);
        }
        Ok(Some(sample))
    }
}

/// The value of a `Result` whose error type has no values.
#[inline(always)]
pub(crate) fn never<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(impossible) => match impossible {},
    }
}

impl<T: Clone> SampleCache<T> {
    /// Clone the first sample at index `from` or later satisfying `pred`,
    /// mark it READ, and return it with the index the next search starts
    /// from. Same snapshot contract as
    /// [`take_first_matching`](Self::take_first_matching): the access is
    /// recorded by the caller once its collection is complete.
    pub fn read_first_matching_from(
        &self,
        from: usize,
        pred: impl FnMut(&CachedSample<T>, ViewState, InstanceState) -> bool,
    ) -> Option<(usize, CachedSample<T>)> {
        never(self.read_first_matching_from_if(from, pred, |_| Ok::<(), Infallible>(())))
    }

    /// [`read_first_matching_from`](Self::read_first_matching_from), unless
    /// `fits` refuses the data of the sample it would return: then the
    /// sample is neither copied nor marked READ, and the refusal is
    /// returned. A refused read therefore leaves the sample to the next
    /// read, with the same predicate, exactly as if it had not been read.
    pub fn read_first_matching_from_if<E>(
        &self,
        from: usize,
        mut pred: impl FnMut(&CachedSample<T>, ViewState, InstanceState) -> bool,
        fits: impl Fn(&T) -> Result<(), E>,
    ) -> Result<Option<(usize, CachedSample<T>)>, E> {
        let buffer = self.buffer_locked();
        for (pos, sample) in buffer.iter().enumerate().skip(from) {
            let (view, state) = self.instances.states_of(sample.instance_handle);
            if !pred(sample, view, state) {
                continue;
            }
            // The size is checked BEFORE the mark: a refused read leaves the
            // sample unread, so the retry with a bigger buffer reads it again.
            fits(&sample.data)?;
            // The state the application sees is the one BEFORE this
            // read, so the clone is taken before the mark.
            let mut copy = sample.clone();
            sample.mark_read();
            copy.view_state = view;
            copy.instance_state = state;
            return Ok(Some((pos + 1, copy)));
        }
        Ok(None)
    }
}

impl<T> SampleCache<T> {
    /// Push a new sample into the cache.
    ///
    /// History depth is per-instance per DDS v1.4 sec. 2.2.3.18 HistoryQosPolicy:
    /// KEEP_LAST(N) keeps the most recent N samples *for each instance*, not
    /// N samples globally. Without per-instance accounting, a keyed topic
    /// with K instances would only retain N total samples (overwriting older
    /// instances when newer ones arrive), so a reader of several instances
    /// would observe non-contiguous per-instance sequence streams. For keyless
    /// topics every sample shares the nil InstanceHandle so per-instance
    /// and global accounting collapse to the same behaviour.
    pub fn push(&self, sample: CachedSample<T>) {
        let mut buffer = self.buffer_locked();
        self.push_locked(&mut buffer, sample);
    }

    /// [`push`](Self::push) a sample together with its place in the
    /// reader's history (`admission::HistoryRoom`): the place stays counted
    /// while the sample is cached, and the cache gives it back when the
    /// sample leaves (or here, when the push refuses it as a duplicate). A
    /// place of a room other than this cache's, or of a KEEP_LAST history,
    /// whose cache holds none, is given back at once. `counted`: the sample
    /// is counted for its instance in this cache's room, and stays so until
    /// it leaves.
    pub(super) fn push_holding(
        &self,
        mut sample: CachedSample<T>,
        place: Option<super::admission::HistorySlot>,
        counted: bool,
    ) {
        if let Some(room) = self.room.as_ref() {
            if let Some(place) = place.filter(|_| !room.bounds_ring_only()) {
                if place.into_cache(room) {
                    sample.held |= HELD_PLACE;
                }
            }
            if counted {
                sample.held |= HELD_INSTANCE;
            }
        } else {
            debug_assert!(!counted, "an instance counted in a cache without a room");
        }
        self.push(sample);
    }

    /// Dedup + per-instance KeepLast eviction + push_back on an already
    /// locked buffer. Factored out of [`push`](Self::push) so the fused
    /// pump+take path (`push_and_take_front` / `push_all_and_take_front`)
    /// can apply the identical push semantics without re-acquiring the
    /// cache mutex.
    ///
    /// A BY_SOURCE_TIMESTAMP reader's sample arrives here already admitted:
    /// tagged network entries at writer-ordered history acceptance, local
    /// entries through [`Self::admit_by_source`] at decode. That acceptance
    /// applied revival and stamped both counters, so this repeats neither.
    /// Admission only lets a strictly increasing `SourceOrderKey` through
    /// per instance, and the single consumer pushes in admission order, so
    /// a plain `push_back` keeps each instance in source-timestamp order.
    #[inline]
    fn push_locked(&self, buffer: &mut VecDeque<CachedSample<T>>, sample: CachedSample<T>) {
        match self.tbf.as_ref() {
            None => self.push_shown(buffer, sample),
            Some(tbf) => self.stage(tbf, buffer, sample),
        }
    }

    /// [`push_locked`](Self::push_locked) for a sample the application may
    /// see now.
    #[inline]
    fn push_shown(&self, buffer: &mut VecDeque<CachedSample<T>>, mut sample: CachedSample<T>) {
        // Dedup: reject a sample this buffer already holds. A sequence
        // number names a change only within its writer (RTPS v2.5 Sec.8.3.8.2:
        // writerSN identifies the change among those of the writer named by
        // writerGuid), and every remote writer of the reader shares one ring
        // tag, so two writers' changes with the same number are two samples.
        // Local deliveries carry no GUID; their ring tag keeps them apart.
        if buffer
            .iter()
            .any(|s| s.seq == sample.seq && s.writer_guid == sample.writer_guid)
        {
            log::warn!("[CACHE] dedup: dropping duplicate seq={}", sample.seq);
            self.release_place(&sample);
            return;
        }

        // Per-instance KEEP_LAST: count samples for THIS instance only and
        // evict the oldest one for the same instance when at the limit.
        //
        // Fast-path gate: any instance's count is bounded by the total
        // buffer length, so while `len() < max_samples` no instance can
        // be at its limit and the O(len) scan is provably a no-op. This
        // keeps the common not-full case (e.g. KeepLast(1) ping-pong on
        // the intra-process path) scan-free without changing behaviour.
        //
        // A sample holding a place in a KEEP_ALL reader's history is neither
        // counted nor evicted: the history's room already bounds those, and
        // KEEP_ALL keeps a sample until it is taken (DDS v1.4 Sec.2.2.3.18).
        // Evicting one silently dropped a sample its reader had acknowledged.
        //
        // With a bound across instances (`max_total`), a sample that finds
        // the buffer at it discards the oldest sample of any instance.
        if buffer.len() >= self.evict_at {
            let same_instance_count = buffer
                .iter()
                .filter(|s| s.instance_handle == sample.instance_handle && !s.holds_place())
                .count();
            let oldest = if same_instance_count >= self.max_samples {
                buffer
                    .iter()
                    .position(|s| s.instance_handle == sample.instance_handle && !s.holds_place())
            } else if buffer.len() >= self.max_total {
                buffer.iter().position(|s| !s.holds_place())
            } else {
                None
            };
            if let Some(idx) = oldest {
                // Replaced by the newer sample: what it held goes back.
                if let Some(replaced) = buffer.remove(idx) {
                    self.release_place(&replaced);
                    // Pushed out before the application ever looked at it:
                    // the same drop as one the rings count.
                    if replaced.sample_state() == SampleState::NotRead {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        if let Some(m) = crate::telemetry::get_metrics_opt() {
                            m.increment_dropped(1);
                        }
                    }
                }
                let cursor = self.read_cursor.load(Ordering::Relaxed);
                if cursor > idx {
                    self.read_cursor.store(cursor - 1, Ordering::Relaxed);
                }
            }
        }

        // A sample received after the instance went NOT_ALIVE revives it
        // (Sec.2.2.2.5.1.3); alive instances pay a load and a branch.
        // `no_writers_generation_count` (Sec.2.2.2.5.1.5) is stamped here,
        // at reception, from the same call's return - never re-read later.
        // A BY_SOURCE_TIMESTAMP sample was stamped at its admission.
        if !self.instances.by_source_timestamp() && !sample.receipt_stamped() {
            (
                sample.disposed_generation_count,
                sample.no_writers_generation_count,
            ) = self
                .instances
                .arrive(sample.instance_handle, sample.origin());
        }
        buffer.push_back(sample);
        self.count_arrival();
    }

    /// One sample landed in this history: the reader's own count, and the
    /// process telemetry `messages_received`. Every way into the history
    /// (`push_shown`, the empty-buffer pass-through) ends here, so the
    /// figure is the same for `read`, `take`, `take_batch` and the rest,
    /// and for every transport that feeds the reader.
    #[inline(always)]
    fn count_arrival(&self) {
        self.total_received.fetch_add(1, Ordering::Relaxed);
        if let Some(m) = crate::telemetry::get_metrics_opt() {
            m.increment_received(1);
        }
    }

    /// Number of samples currently in cache.
    #[allow(dead_code)] // DDS API - diagnostics
    pub fn len(&self) -> usize {
        self.buffer_locked().len()
    }

    /// Check if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer_locked().is_empty()
    }

    /// Total samples received since creation.
    #[allow(dead_code)] // DDS API - diagnostics
    pub fn total_received(&self) -> usize {
        self.total_received.load(Ordering::Relaxed)
    }

    /// Samples pushed out of this history unread, since creation.
    pub(super) fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// For each writer with samples in the cache, its earliest sequence
    /// number there (local samples, which carry no writer GUID, under
    /// `None`), without removing anything.
    ///
    /// Used only to place an instance-state transition relative to the data
    /// around it: a transition and a sample from the SAME writer are ordered
    /// by the writer's own sequence numbers, which is the one order the wire
    /// actually carries, and that holds for every sample of the writer still
    /// queued, not only the one at the front: a transition placed against
    /// the front alone would overtake its own writer's earlier sample whenever
    /// another writer's sample was in front of it. Empty when the cache is
    /// empty, so the caller reads "no data is competing with the
    /// transition". Scans the cache; asked only while a transition is
    /// queued.
    pub fn pending_origins(&self) -> Vec<Origin> {
        let buffer = self.buffer_locked();
        earliest_per_writer(buffer.iter())
    }

    /// For a BY_SOURCE_TIMESTAMP reader (DDS v1.4 Sec.2.2.3.17,
    /// Sec.2.2.2.5.3.8): per instance with buffered samples carrying a
    /// source timestamp, the oldest of them by source order, at index
    /// `from` or later and satisfying `pred`. What a queued transition of
    /// another writer is placed against: it waits behind an older sample
    /// of its own instance still eligible for the access that asks.
    pub fn pending_source_order_from(
        &self,
        from: usize,
        mut pred: impl FnMut(&CachedSample<T>, ViewState, InstanceState) -> bool,
    ) -> Vec<SourcePending> {
        let buffer = self.buffer_locked();
        oldest_by_source_order(buffer.iter().skip(from).filter(|sample| {
            let (view, state) = self.instances.states_of(sample.instance_handle);
            pred(sample, view, state)
        }))
    }
}

/// One instance and its oldest buffered sample's source order, `(source
/// timestamp, writer)`: the first two fields of a `SourceOrderKey`, which
/// decide between two different writers (`SampleCache::
/// pending_source_order_from`).
pub type SourcePending = (InstanceHandle, (u64, Option<[u8; 16]>));

/// Per instance, the smallest `(source timestamp, writer)` among
/// `samples` that carry a source timestamp.
fn oldest_by_source_order<'a, T: 'a>(
    samples: impl Iterator<Item = &'a CachedSample<T>>,
) -> Vec<SourcePending> {
    let mut oldest: Vec<SourcePending> = Vec::new();
    for sample in samples.filter(|sample| sample.has_source_ts) {
        let order = (sample.timestamp_ns, sample.writer_guid);
        match oldest
            .iter_mut()
            .find(|(handle, _)| *handle == sample.instance_handle)
        {
            Some((_, min)) => *min = (*min).min(order),
            None => oldest.push((sample.instance_handle, order)),
        }
    }
    oldest
}

/// The earliest sequence number of each writer among `samples`.
///
/// Local samples carry no writer GUID, so the samples of every local writer
/// fall under `None`, and their sequence numbers belong to different
/// writers: the minimum across them would hold one local writer's
/// transition behind another local writer's sample. Under `None` this keeps
/// the FIRST local sample in cache order instead: for one local writer that
/// is its earliest, and with several it places a local transition against
/// the next local sample, as the rule did before it looked past the front.
fn earliest_per_writer<'a, T: 'a>(
    samples: impl Iterator<Item = &'a CachedSample<T>>,
) -> Vec<Origin> {
    let mut earliest: Vec<Origin> = Vec::new();
    for (writer, seq) in samples.map(CachedSample::origin) {
        match earliest.iter_mut().find(|(w, _)| *w == writer) {
            Some((_, min)) if writer.is_some() => *min = (*min).min(seq),
            Some(_) => {}
            None => earliest.push((writer, seq)),
        }
    }
    earliest
}

impl<T> SampleCache<T> {
    /// Take a single sample, removing it from cache (DDS take semantics).
    ///
    /// Returns and removes the oldest sample.
    /// Returns `None` if cache is empty.
    #[allow(dead_code)] // DDS API - data-only projection
    pub fn take(&self) -> Option<T> {
        let mut buffer = self.buffer_locked();
        self.pop_front_full_locked(&mut buffer)
            .map(|sample| sample.data)
    }

    /// [`take`](Self::take) keeping the whole [`CachedSample`] (metadata
    /// included) instead of projecting `data`. Sibling used by the
    /// `take_with_info` API; the pop itself is the identical
    /// front-pop + cursor adjust.
    pub fn take_full(&self) -> Option<CachedSample<T>> {
        let mut buffer = self.buffer_locked();
        self.pop_front_full_locked(&mut buffer)
    }

    /// Pop the front sample and adjust the read cursor on an already
    /// locked buffer, returning the full [`CachedSample`]. Factored out
    /// of [`take`](Self::take) so the fused pump+take path can pop under
    /// the same lock that performed the pushes, and so the `_full`
    /// twins can keep the metadata. Byte-identical to the pre-fusion
    /// `take` body (an empty buffer yields `None` via `pop_front`)
    /// modulo the projection point, which moved to the callers.
    #[inline]
    fn pop_front_full_locked(
        &self,
        buffer: &mut VecDeque<CachedSample<T>>,
    ) -> Option<CachedSample<T>> {
        let mut sample = buffer.pop_front()?;
        self.release_place(&sample);

        // Adjust read cursor
        let cursor = self.read_cursor.load(Ordering::Relaxed);
        if cursor > 0 {
            self.read_cursor.store(cursor - 1, Ordering::Relaxed);
        }

        // The take makes the instance NOT_NEW (DDS v1.4 Sec.2.2.2.5.3.9).
        self.stamp_access(&mut sample);
        Some(sample)
    }

    /// Fused pump+take on the crown 1w1r path: push one freshly pumped
    /// sample and pop the front, all under a SINGLE cache-mutex
    /// acquisition.
    ///
    /// Semantically identical to `push(sample)` immediately followed by
    /// `take()` (same dedup, same per-instance KeepLast eviction, same
    /// front-pop and cursor adjust) but halves the lock traffic on the
    /// hot take() path from two acquisitions to one. The single-writer
    /// intra-process roundtrip pumps exactly one sample per `take()`, so
    /// this is the common case; multi-sample drains use
    /// [`push_all_and_take_front`](Self::push_all_and_take_front).
    #[allow(dead_code)] // DDS API - data-only projection of the _full twin
    pub fn push_and_take_front(&self, sample: CachedSample<T>) -> Option<T> {
        let mut buffer = self.buffer_locked();
        if buffer.is_empty() && self.tbf.is_none() {
            self.count_pass_through_locked(&buffer);
            let mut sample = sample;
            self.release_place(&sample);
            if !self.instances.by_source_timestamp() && !sample.receipt_stamped() {
                (
                    sample.disposed_generation_count,
                    sample.no_writers_generation_count,
                ) = self
                    .instances
                    .arrive(sample.instance_handle, sample.origin());
            }
            self.stamp_access(&mut sample);
            return Some(sample.data);
        }
        self.push_locked(&mut buffer, sample);
        self.pop_front_full_locked(&mut buffer)
            .map(|sample| sample.data)
    }

    /// [`push_and_take_front`](Self::push_and_take_front) keeping the
    /// whole [`CachedSample`]. Same single lock acquisition, same push
    /// semantics, same empty-buffer pass-through; only the projection
    /// point differs.
    #[allow(dead_code)] // unconditional twin, used by the cache tests; takes use the _if form
    pub fn push_and_take_front_full(&self, sample: CachedSample<T>) -> Option<CachedSample<T>> {
        let mut buffer = self.buffer_locked();
        if buffer.is_empty() && self.tbf.is_none() {
            return Some(self.pass_through_locked(&buffer, sample));
        }
        self.push_locked(&mut buffer, sample);
        self.pop_front_full_locked(&mut buffer)
    }

    /// The empty-buffer pass-through of the fused push + front-pop: the
    /// sample the round trip through the buffer would have handed out, with
    /// the bookkeeping that round trip leaves (see
    /// `count_pass_through_locked`). Must only be called with the lock held
    /// and the buffer empty.
    #[inline(always)]
    fn pass_through_locked(
        &self,
        buffer: &VecDeque<CachedSample<T>>,
        mut sample: CachedSample<T>,
    ) -> CachedSample<T> {
        self.count_pass_through_locked(buffer);
        self.release_place(&sample);
        if !self.instances.by_source_timestamp() && !sample.receipt_stamped() {
            (
                sample.disposed_generation_count,
                sample.no_writers_generation_count,
            ) = self
                .instances
                .arrive(sample.instance_handle, sample.origin());
        }
        self.stamp_access(&mut sample);
        sample
    }

    /// BY_SOURCE_TIMESTAMP admission (DDS v1.4 Sec.2.2.3.17) of `sample`,
    /// before it is pushed: see [`InstanceTable::admit_by_source`] for
    /// `key`, `held` and `filter`. `origin` is the sample's writer and
    /// that writer's full sequence number, the form a transition's own
    /// origin takes (`DisposeEvent::order_seq`). On `true` the sample
    /// carries its generation count (Sec.2.2.2.5.1.5) and is pushed as
    /// usual; on `false` it must not be pushed, and nothing of its
    /// instance moved but the presence revival.
    pub fn admit_by_source(
        &self,
        sample: &mut CachedSample<T>,
        key: Option<SourceOrderKey>,
        origin: Origin,
        held: impl FnOnce() -> bool,
        filter: impl FnOnce() -> bool,
    ) -> bool {
        match self
            .instances
            .admit_by_source(sample.instance_handle, key, origin, held, filter)
        {
            Some(count) => {
                (
                    sample.disposed_generation_count,
                    sample.no_writers_generation_count,
                ) = count;
                true
            }
            None => false,
        }
    }

    /// Bookkeeping of the empty-buffer pass-through in the fused push +
    /// front-pop: the caller hands the sample straight back without the
    /// VecDeque round trip, and this applies what the round trip would
    /// have left behind.
    ///
    /// On the KeepLast(1) crown path the buffer is empty at push time
    /// on every take (the previous take drained it), so `push_locked`
    /// followed by `pop_front_full_locked` would write the sample into
    /// the heap buffer and read it back out for nothing. Under the lock
    /// the two are provably the same on an empty buffer: the dedup scan
    /// has nothing to match, the per-instance eviction gate is
    /// `0 >= max_samples` and even when it fires (`max_samples == 0`)
    /// finds nothing to remove, the push_back/pop_front pair cancels,
    /// and the read cursor is 0 on an empty buffer (every mutation
    /// keeps `cursor <= len`) so the pop's cursor adjust is a no-op.
    /// The one thing `push_locked` leaves behind, the `total_received`
    /// count, is applied here identically. Must only be called with the
    /// lock held and the buffer empty; the general path runs unchanged
    /// otherwise.
    #[inline(always)]
    fn count_pass_through_locked(&self, buffer: &VecDeque<CachedSample<T>>) {
        debug_assert!(buffer.is_empty());
        debug_assert_eq!(self.read_cursor.load(Ordering::Relaxed), 0);
        self.count_arrival();
    }

    /// Fused pump+take for a multi-sample drain: push `first` then every
    /// sample in `rest` (in order), then pop the front, under a SINGLE
    /// cache-mutex acquisition.
    ///
    /// `rest` is kept separate from `first` so the common single-sample
    /// crown path never has to build a one-element `Vec` (its caller
    /// uses [`push_and_take_front`](Self::push_and_take_front)); the
    /// rare backlog drain passes the additional samples here. Push order
    /// (`first`, then `rest[0..]`) matches the pre-fusion sequential
    /// `push` calls exactly, so dedup / eviction / front ordering are
    /// byte-identical.
    #[allow(dead_code)] // DDS API - data-only projection of the _full twin
    pub fn push_all_and_take_front(
        &self,
        first: CachedSample<T>,
        rest: Vec<CachedSample<T>>,
    ) -> Option<T> {
        let mut buffer = self.buffer_locked();
        self.push_locked(&mut buffer, first);
        for sample in rest {
            self.push_locked(&mut buffer, sample);
        }
        self.pop_front_full_locked(&mut buffer)
            .map(|sample| sample.data)
    }

    /// [`push_all_and_take_front`](Self::push_all_and_take_front)
    /// keeping the whole [`CachedSample`]. Same single lock
    /// acquisition, same push order; only the projection point differs.
    #[allow(dead_code)] // unconditional twin, used by the cache tests; takes use the _if form
    pub fn push_all_and_take_front_full(
        &self,
        first: CachedSample<T>,
        rest: Vec<CachedSample<T>>,
    ) -> Option<CachedSample<T>> {
        let mut buffer = self.buffer_locked();
        self.push_locked(&mut buffer, first);
        for sample in rest {
            self.push_locked(&mut buffer, sample);
        }
        self.pop_front_full_locked(&mut buffer)
    }

    /// [`take_full`](Self::take_full), unless `fits` refuses the data of
    /// the front sample: then it stays in place and the refusal is
    /// returned (the take is all or nothing, under one lock). `project`
    /// turns the taken sample into the result UNDER THE SAME LOCK, as the
    /// data-only take always did: a projection to the data drops the
    /// metadata before the lock is released, and the full sample never
    /// leaves the cache.
    #[inline(always)]
    pub fn take_if_with<O, E>(
        &self,
        fits: impl Fn(&T) -> Result<(), E>,
        project: impl FnOnce(CachedSample<T>) -> O,
    ) -> Result<Option<O>, E> {
        let mut buffer = self.buffer_locked();
        self.pop_front_if_locked(&mut buffer, &fits, project)
    }

    /// The fused push + front-pop of
    /// [`push_and_take_front_full`](Self::push_and_take_front_full), with the
    /// refusal and the projection of [`take_if_with`](Self::take_if_with). A refused sample is
    /// stored as an arrival (it holds its place and its generation counts are
    /// stamped, as any pumped sample is) and left first in the buffer.
    #[inline]
    pub fn push_and_take_if_with<O, E>(
        &self,
        sample: CachedSample<T>,
        fits: impl Fn(&T) -> Result<(), E>,
        project: impl FnOnce(CachedSample<T>) -> O,
    ) -> Result<Option<O>, E> {
        let mut buffer = self.buffer_locked();
        if buffer.is_empty() && self.tbf.is_none() {
            // The pass-through skips the buffer, so its refusal must be
            // decided before it touches anything: a refused sample goes
            // through the buffer and waits there.
            if let Err(refused) = fits(&sample.data) {
                self.push_locked(&mut buffer, sample);
                return Err(refused);
            }
            return Ok(Some(project(self.pass_through_locked(&buffer, sample))));
        }
        self.push_locked(&mut buffer, sample);
        self.pop_front_if_locked(&mut buffer, &fits, project)
    }

    /// The fused push + front-pop of
    /// [`push_all_and_take_front_full`](Self::push_all_and_take_front_full),
    /// with the refusal and the projection of [`take_if_with`](Self::take_if_with).
    #[inline(always)]
    pub fn push_all_and_take_if_with<O, E>(
        &self,
        first: CachedSample<T>,
        rest: Vec<CachedSample<T>>,
        fits: impl Fn(&T) -> Result<(), E>,
        project: impl FnOnce(CachedSample<T>) -> O,
    ) -> Result<Option<O>, E> {
        let mut buffer = self.buffer_locked();
        self.push_locked(&mut buffer, first);
        for sample in rest {
            self.push_locked(&mut buffer, sample);
        }
        self.pop_front_if_locked(&mut buffer, &fits, project)
    }

    /// [`pop_front_full_locked`](Self::pop_front_full_locked) unless `fits`
    /// refuses the data of the front sample (nothing is removed then).
    #[inline(always)]
    fn pop_front_if_locked<O, E>(
        &self,
        buffer: &mut VecDeque<CachedSample<T>>,
        fits: &impl Fn(&T) -> Result<(), E>,
        project: impl FnOnce(CachedSample<T>) -> O,
    ) -> Result<Option<O>, E> {
        if let Some(front) = buffer.front() {
            fits(&front.data)?;
        }
        Ok(self.pop_front_full_locked(buffer).map(project))
    }

    /// Take up to `max` samples, removing them from cache.
    #[allow(dead_code)] // DDS API - batch operations
    pub fn take_batch(&self, max: usize) -> Vec<T> {
        let mut buffer = self.buffer_locked();
        let count = max.min(buffer.len());
        let mut result = Vec::with_capacity(count);

        let mut places = 0;
        for _ in 0..count {
            if let Some(sample) = buffer.pop_front() {
                self.release_in_batch(&sample, &mut places);
                self.instances.note(sample.instance_handle);
                result.push(sample.data);
            }
        }
        self.give_back(places);

        // Reset read cursor (samples removed from front)
        let cursor = self.read_cursor.load(Ordering::Relaxed);
        let new_cursor = cursor.saturating_sub(count);
        self.read_cursor.store(new_cursor, Ordering::Relaxed);

        result
    }

    /// Reset read cursor to beginning (re-read all samples).
    #[allow(dead_code)] // DDS API - cursor management
    pub fn reset_read_cursor(&self) {
        self.read_cursor.store(0, Ordering::Relaxed);
    }

    /// Clear all samples from cache.
    #[allow(dead_code)] // DDS API - cache management
    pub fn clear(&self) {
        let mut buffer = self.buffer_locked();
        let mut places = 0;
        for sample in buffer.iter() {
            self.release_in_batch(sample, &mut places);
        }
        self.release_parked_in_batch(&mut places);
        self.give_back(places);
        buffer.clear();
        self.read_cursor.store(0, Ordering::Relaxed);
    }

    /// Take a single sample for a specific instance, removing it (DDS take_instance).
    ///
    /// Returns and removes the oldest sample matching the given instance handle.
    /// Uses linear scan O(n) - acceptable for v1.0.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    ///
    /// # Returns
    /// * `Some(data)` if a matching sample was found and removed
    /// * `None` if no matching sample exists
    pub fn take_instance(&self, handle: InstanceHandle) -> Option<T> {
        let mut buffer = self.buffer_locked();

        // Linear scan to find first matching instance
        let pos = buffer.iter().position(|s| s.instance_handle == handle)?;

        let sample = buffer.remove(pos)?;
        self.release_place(&sample);
        self.instances.note(sample.instance_handle);

        // Adjust read cursor if we removed a sample before it
        let cursor = self.read_cursor.load(Ordering::Relaxed);
        if pos < cursor {
            self.read_cursor.store(cursor - 1, Ordering::Relaxed);
        }

        Some(sample.data)
    }

    /// Take up to `max` samples for a specific instance, removing them.
    ///
    /// Returns and removes samples matching the given instance handle.
    /// Uses linear scan O(n*max) - acceptable for v1.0.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    /// * `max` - Maximum number of samples to take
    pub fn take_instance_batch(&self, handle: InstanceHandle, max: usize) -> Vec<T> {
        let mut buffer = self.buffer_locked();
        let mut result = Vec::with_capacity(max);
        let mut removed_before_cursor = 0;
        let cursor = self.read_cursor.load(Ordering::Relaxed);

        // Collect indices to remove (in reverse order to not invalidate indices)
        let indices: Vec<usize> = buffer
            .iter()
            .enumerate()
            .filter(|(_, s)| s.instance_handle == handle)
            .take(max)
            .map(|(i, _)| i)
            .collect();

        // Remove in reverse order to maintain valid indices
        let mut places = 0;
        for &idx in indices.iter().rev() {
            if let Some(sample) = buffer.remove(idx) {
                self.release_in_batch(&sample, &mut places);
                self.instances.note(sample.instance_handle);
                result.push(sample.data);
                if idx < cursor {
                    removed_before_cursor += 1;
                }
            }
        }

        self.give_back(places);

        // Adjust read cursor
        if removed_before_cursor > 0 {
            let new_cursor = cursor.saturating_sub(removed_before_cursor);
            self.read_cursor.store(new_cursor, Ordering::Relaxed);
        }

        // Results are in reverse order, fix that
        result.reverse();
        result
    }
}

impl<T> Drop for SampleCache<T> {
    /// The samples still cached when the reader goes leave its history: their
    /// places go back to the room, which the reader's network subscriber may
    /// still be holding.
    fn drop(&mut self) {
        let buffer = std::mem::take(self.buffer.get_mut());
        let mut places = 0;
        for sample in &buffer {
            self.release_in_batch(sample, &mut places);
        }
        self.release_parked_in_batch(&mut places);
        self.give_back(places);
    }
}

#[cfg(test)]
thread_local! {
    /// Tests only: a one-shot hook run synchronously inside `give_back`,
    /// right after it hands a room its places back -- this `Drop` runs as
    /// part of a `DataReader`'s own implicit field-drop glue, strictly
    /// after that reader's explicit `Drop::drop` body has already run, so
    /// a test can observe here exactly what that body did or did not
    /// already release by this point (`a_reader_dropped_...` in
    /// `tests_pump_merge_sample_lost`).
    // @audit-ok: cfg(test) only, one hook per test thread, set and taken
    // by the same thread within one test
    static AFTER_GIVE_BACK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Tests only: run `hook` once, the next time any `SampleCache::give_back`
/// on this thread hands a room its places back.
#[cfg(test)]
pub(super) fn after_give_back_for_test(hook: Box<dyn FnOnce()>) {
    AFTER_GIVE_BACK.with(|h| *h.borrow_mut() = Some(hook));
}

// Read operations require T: Clone (samples are copied, not moved)
impl<T: Clone> SampleCache<T> {
    /// Read a single sample without removing it (DDS read semantics).
    ///
    /// Returns the next unread sample and marks it as READ.
    /// Returns `None` if no unread samples available.
    pub fn read(&self) -> Option<T> {
        let buffer = self.buffer_locked();
        let cursor = self.read_cursor.load(Ordering::Relaxed);

        if cursor >= buffer.len() {
            return None;
        }

        let sample = &buffer[cursor];
        sample.mark_read();
        // A read makes the instance NOT_NEW too (DDS v1.4 Sec.2.2.2.5.3.8).
        self.instances.note(sample.instance_handle);

        // Advance read cursor
        self.read_cursor.store(cursor + 1, Ordering::Relaxed);

        Some(sample.data.clone())
    }

    /// Read up to `max` samples without removing them.
    ///
    /// Returns samples and marks them as READ.
    pub fn read_batch(&self, max: usize) -> Vec<T> {
        let buffer = self.buffer_locked();
        let mut cursor = self.read_cursor.load(Ordering::Relaxed);
        let mut result = Vec::with_capacity(max.min(buffer.len()));

        for _ in 0..max {
            if cursor >= buffer.len() {
                break;
            }

            let sample = &buffer[cursor];
            sample.mark_read();
            self.instances.note(sample.instance_handle);
            result.push(sample.data.clone());
            cursor += 1;
        }

        self.read_cursor.store(cursor, Ordering::Relaxed);
        result
    }

    /// Read a single sample for a specific instance (DDS read_instance).
    ///
    /// Returns the first unread sample matching the given instance handle.
    /// Uses linear scan O(n) - acceptable for v1.0.
    ///
    /// Note: This only reads samples that haven't been read yet. After reading,
    /// the sample is marked as READ and won't be returned again by `read_instance`.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    ///
    /// # Returns
    /// * `Some(data)` if a matching unread sample was found
    /// * `None` if no matching unread sample exists
    pub fn read_instance(&self, handle: InstanceHandle) -> Option<T> {
        let buffer = self.buffer_locked();

        // Linear scan to find first unread matching instance
        for sample in buffer.iter() {
            if sample.instance_handle == handle && sample.sample_state() == SampleState::NotRead {
                sample.mark_read();
                self.instances.note(sample.instance_handle);
                return Some(sample.data.clone());
            }
        }

        None
    }

    /// Read up to `max` samples for a specific instance without removing them.
    ///
    /// Returns clones of unread samples matching the given instance handle.
    /// Uses linear scan O(n) - acceptable for v1.0.
    ///
    /// # Arguments
    /// * `handle` - The instance handle to filter by
    /// * `max` - Maximum number of samples to read
    pub fn read_instance_batch(&self, handle: InstanceHandle, max: usize) -> Vec<T> {
        let buffer = self.buffer_locked();
        let mut result = Vec::with_capacity(max);

        // Linear scan for unread samples matching instance
        for sample in buffer.iter() {
            if result.len() >= max {
                break;
            }

            if sample.instance_handle == handle && sample.sample_state() == SampleState::NotRead {
                sample.mark_read();
                self.instances.note(sample.instance_handle);
                result.push(sample.data.clone());
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[A(read), B(read), C(unread)]`, cursor 2: a selective take of B and
    /// C leaves `[A]` with A already read, so the cursor must become 1 and
    /// an ordinary `read()` must report no unread sample rather than A
    /// again.
    #[test]
    fn selective_take_adjusts_the_read_cursor_by_original_position() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0));
        assert_eq!(cache.read(), Some(1));
        assert_eq!(cache.read(), Some(2));

        let mut taken = Vec::new();
        while let Some(sample) = cache.take_first_matching(|sample, _, _| sample.seq >= 2) {
            taken.push(sample);
        }
        assert_eq!(taken.len(), 2);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.read_cursor.load(Ordering::Relaxed), 1);
        assert_eq!(cache.read(), None, "A was already read");
        assert_eq!(cache.take(), Some(1));
    }

    #[test]
    fn test_push_take() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0));

        assert_eq!(cache.len(), 3);

        assert_eq!(cache.take(), Some(1));
        assert_eq!(cache.take(), Some(2));
        assert_eq!(cache.take(), Some(3));
        assert_eq!(cache.take(), None);
    }

    #[test]
    fn test_push_read() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0));

        // Read doesn't remove
        assert_eq!(cache.read(), Some(1));
        assert_eq!(cache.read(), Some(2));
        assert_eq!(cache.read(), Some(3));
        assert_eq!(cache.read(), None); // No more unread

        // Still 3 samples in cache
        assert_eq!(cache.len(), 3);

        // Reset and read again
        cache.reset_read_cursor();
        assert_eq!(cache.read(), Some(1));
    }

    #[test]
    fn test_read_then_take() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));

        // Read first sample
        assert_eq!(cache.read(), Some(1));

        // Take removes from front
        assert_eq!(cache.take(), Some(1));

        // Read cursor adjusted, next read is sample 2
        assert_eq!(cache.read(), Some(2));
    }

    #[test]
    fn test_take_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        for i in 1..=5 {
            cache.push(CachedSample::new(i, i as u64, 0));
        }

        let batch = cache.take_batch(3);
        assert_eq!(batch, vec![1, 2, 3]);
        assert_eq!(cache.len(), 2);

        let batch = cache.take_batch(10);
        assert_eq!(batch, vec![4, 5]);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_read_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        for i in 1..=5 {
            cache.push(CachedSample::new(i, i as u64, 0));
        }

        let batch = cache.read_batch(3);
        assert_eq!(batch, vec![1, 2, 3]);
        assert_eq!(cache.len(), 5); // Still all there

        let batch = cache.read_batch(10);
        assert_eq!(batch, vec![4, 5]); // Only unread ones

        // All read, no more
        let batch = cache.read_batch(10);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_history_depth() {
        let cache: SampleCache<i32> = SampleCache::new(3);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0));
        assert_eq!(cache.len(), 3);

        // Push 4th, should evict oldest
        cache.push(CachedSample::new(4, 4, 0));
        assert_eq!(cache.len(), 3);

        let all = cache.take_batch(10);
        assert_eq!(all, vec![2, 3, 4]); // 1 was evicted
    }

    #[test]
    fn test_sample_state() {
        let sample = CachedSample::new(42, 1, 0);
        assert_eq!(sample.sample_state(), SampleState::NotRead);

        sample.mark_read();
        assert_eq!(sample.sample_state(), SampleState::Read);
    }

    #[test]
    fn test_total_received() {
        let cache: SampleCache<i32> = SampleCache::new(2);

        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));
        cache.push(CachedSample::new(3, 3, 0)); // Evicts 1

        assert_eq!(cache.total_received(), 3);
        assert_eq!(cache.len(), 2);
    }

    // =========================================================================
    // Instance filtering tests (Phase 2)
    // =========================================================================

    fn make_handle(id: u8) -> InstanceHandle {
        let mut key = [0u8; 16];
        key[0] = id;
        InstanceHandle::new(key)
    }

    #[test]
    fn test_push_dedup_same_seq() {
        let cache: SampleCache<i32> = SampleCache::new(10);

        // Push 3 samples with distinct seqs
        cache.push(CachedSample::new(10, 1, 0));
        cache.push(CachedSample::new(20, 2, 0));
        cache.push(CachedSample::new(30, 3, 0));
        assert_eq!(cache.len(), 3);

        // Push duplicates (same seqs, different data) -- should all be rejected
        cache.push(CachedSample::new(11, 1, 0));
        cache.push(CachedSample::new(21, 2, 0));
        cache.push(CachedSample::new(31, 3, 0));
        assert_eq!(cache.len(), 3, "Duplicates should have been rejected");

        // take() returns original data in order, then None
        assert_eq!(cache.take(), Some(10));
        assert_eq!(cache.take(), Some(20));
        assert_eq!(cache.take(), Some(30));
        assert_eq!(cache.take(), None);
    }

    /// Two remote writers number their changes independently: the same
    /// sequence number from each is two samples, kept in arrival order.
    /// The same number from the same writer is still a duplicate.
    #[test]
    fn the_same_sequence_number_from_two_writers_is_two_samples() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let w1 = Some([1u8; 16]);
        let w2 = Some([2u8; 16]);
        let push = |data: i32, seq: u64, writer: Option<[u8; 16]>| {
            cache.push(CachedSample::with_meta(
                data,
                seq,
                0,
                InstanceHandle::nil(),
                writer,
                false,
            ));
        };
        push(11, 1, w1);
        push(21, 1, w2);
        push(12, 2, w1);
        push(22, 2, w2);
        push(13, 1, w1);
        assert_eq!(
            cache.len(),
            4,
            "only the repeat of writer 1's change 1 is a duplicate"
        );

        let taken: Vec<_> = std::iter::from_fn(|| cache.take_full())
            .map(|s| (s.data, s.writer_guid, s.seq))
            .collect();
        assert_eq!(
            taken,
            vec![(11, w1, 1), (21, w2, 1), (12, w1, 2), (22, w2, 2)],
        );
    }

    /// KEEP_LAST 1 on one instance written by two writers keeps the newer
    /// arrival, whatever the two writers' sequence numbers are.
    #[test]
    fn keep_last_one_keeps_the_newer_of_two_writers_with_the_same_number() {
        let cache: SampleCache<i32> = SampleCache::new(1);
        let handle = make_handle(5);
        cache.push(CachedSample::with_meta(
            10,
            1,
            0,
            handle,
            Some([1u8; 16]),
            false,
        ));
        cache.push(CachedSample::with_meta(
            20,
            1,
            0,
            handle,
            Some([2u8; 16]),
            false,
        ));
        assert_eq!(cache.take(), Some(20));
        assert_eq!(cache.take(), None);
    }

    /// A `SampleCache` whose reader resolved DESTINATION_ORDER to
    /// BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17), for the tests below.
    fn by_source_ts_cache<T>(max_samples: usize) -> SampleCache<T> {
        SampleCache::with_instances(
            max_samples,
            Arc::new(InstanceTable::with_destination_order(true)),
        )
    }

    /// The key the reader's decode step builds for `sample`
    /// (`DataReader::prepare_sample_dropping`): its source timestamp,
    /// writer and writer sequence number.
    fn key_of<T>(sample: &CachedSample<T>) -> Option<SourceOrderKey> {
        sample.has_source_ts.then_some(SourceOrderKey(
            sample.timestamp_ns,
            sample.writer_guid,
            sample.seq,
        ))
    }

    /// What the reader's pump does with a decoded sample of a
    /// BY_SOURCE_TIMESTAMP reader: admit it, then push it if admitted.
    fn push_admitted<T>(cache: &SampleCache<T>, mut sample: CachedSample<T>) -> bool {
        let key = key_of(&sample);
        let origin = sample.origin();
        if !cache.admit_by_source(&mut sample, key, origin, || false, || true) {
            return false;
        }
        cache.push(sample);
        true
    }

    /// `push_admitted` for one of the fused push + take paths.
    fn admitted_then<T, R>(
        cache: &SampleCache<T>,
        push: impl FnOnce(&SampleCache<T>, CachedSample<T>) -> Option<R>,
        mut sample: CachedSample<T>,
    ) -> Option<R> {
        let key = key_of(&sample);
        let origin = sample.origin();
        if !cache.admit_by_source(&mut sample, key, origin, || false, || true) {
            return None;
        }
        push(cache, sample)
    }

    impl<T> SampleCache<T> {
        fn admitted_then_full(&self, sample: CachedSample<T>) -> Option<CachedSample<T>> {
            admitted_then(self, |c, s| c.push_and_take_front_full(s), sample)
        }
    }

    /// DDS v1.4 Sec.2.2.3.17: a change with a source timestamp older than
    /// the last one already accepted for an instance must not overwrite
    /// it. KEEP_LAST(1) on one instance written by two writers must end
    /// up holding the NEWER (by source timestamp) sample WHATEVER ORDER
    /// the two arrived in -- unlike
    /// `keep_last_one_keeps_the_newer_of_two_writers_with_the_same_number`
    /// above, whose BY_RECEPTION_TIMESTAMP rule keeps whichever arrived
    /// last, full stop.
    ///
    /// Mutant: making `InstanceEntry::admit_by_source` skip its ordering
    /// check fails the first half below: the older sample arriving
    /// SECOND would overwrite the newer one, exactly the reception-order
    /// test two names above.
    #[test]
    fn by_source_timestamp_rejects_an_older_sample_whatever_arrival_order() {
        let handle = make_handle(5);
        let w1 = Some([1u8; 16]);
        let w2 = Some([2u8; 16]);

        // Newer (ts=300) arrives first, older (ts=200) second: the older
        // must not overwrite it.
        let cache = by_source_ts_cache::<i32>(1);
        push_admitted(
            &cache,
            CachedSample::with_meta(30, 1, 300, handle, w1, true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(20, 1, 200, handle, w2, true),
        );
        assert_eq!(
            cache.take(),
            Some(30),
            "the older sample must have been rejected on arrival, not kept"
        );
        assert_eq!(cache.take(), None);

        // Same two samples, reception order reversed: the result must be
        // IDENTICAL. The whole point of BY_SOURCE_TIMESTAMP is that every
        // reader ends up with the same final value regardless of arrival
        // order.
        let cache = by_source_ts_cache::<i32>(1);
        push_admitted(
            &cache,
            CachedSample::with_meta(20, 1, 200, handle, w2, true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(30, 1, 300, handle, w1, true),
        );
        assert_eq!(cache.take(), Some(30));
        assert_eq!(cache.take(), None);
    }

    /// DDS v1.4 Sec.2.2.3.17: two DISTINCT changes from the SAME live
    /// writer can legitimately carry the identical application-supplied
    /// source timestamp (an explicit `_w_timestamp` call used twice, or
    /// two calls within one coarse clock tick). A two-field key (timestamp,
    /// writer GUID) would treat the second one as an exact repeat of the
    /// watermark and reject it outright, even though it is a genuinely
    /// later change of the SAME writer -- reference behaviour (Cyclone DDS's equal-timestamp
    /// arbitration) permits a tied live writer to keep advancing. The
    /// writer's own SN, the key's third field, breaks the tie in
    /// writer-local order.
    ///
    /// Mutant: dropping `SourceOrderKey`'s third field (reverting to the
    /// two-field key) makes this fail: the second sample's key would tie
    /// the first's exactly and be rejected as `key <= floor`.
    #[test]
    fn by_source_timestamp_same_writer_same_timestamp_advances_by_sn() {
        let handle = make_handle(50);
        let writer = Some([7u8; 16]);
        let cache = by_source_ts_cache::<i32>(2);
        push_admitted(
            &cache,
            CachedSample::with_meta(10, 1, 500, handle, writer, true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(20, 2, 500, handle, writer, true),
        );
        assert_eq!(cache.take(), Some(10));
        assert_eq!(
            cache.take(),
            Some(20),
            "the second change from the SAME writer, tied on timestamp but \
             with a higher SN, must still be accepted"
        );
    }

    /// DDS v1.4 Sec.2.2.3.17 + Sec.2.2.2.5.1.3: admission and the
    /// instance-state change it implies are ONE operation. Writer A's
    /// DATA@200 is admitted; writer B's dispose@300 is then admitted and
    /// applied (NOT_ALIVE_DISPOSED); A's DATA@200 presented again (a
    /// paused second application) must be refused by the same call that
    /// would revive the instance, so nothing revives it behind the newer
    /// dispose.
    ///
    /// Mutant: making `InstanceEntry::admit_by_source` apply `arrive`
    /// before its ordering check makes the final assertion fail: the
    /// stale re-application would revive the instance.
    #[test]
    fn by_source_timestamp_admission_and_revival_are_one_operation() {
        let table = InstanceTable::with_destination_order(true);
        let handle = make_handle(77);
        let writer_a = Some([0xAAu8; 16]);
        let writer_b = Some([0xBBu8; 16]);
        let key_a = SourceOrderKey(200, writer_a, 1);
        let key_b = SourceOrderKey(300, writer_b, 1);
        let admit =
            |key| table.admit_by_source(handle, Some(key), (writer_a, 1), || false, || true);

        assert!(admit(key_a).is_some(), "A's DATA@200 is the first change");
        assert!(
            table
                .accept_and_mark_not_alive(
                    handle,
                    Some(key_b),
                    InstanceState::NotAliveDisposed,
                    (writer_b, 1),
                    false,
                    None,
                )
                .is_some(),
            "B's dispose@300 is newer: accepted and applied"
        );
        assert!(
            admit(key_a).is_none(),
            "a stale re-application of an admitted key is refused"
        );
        assert_eq!(
            table.state_of(handle),
            InstanceState::NotAliveDisposed,
            "the newest accepted change (the dispose) decides the state"
        );
    }

    /// DDS v1.4 Sec.2.2.3.17: the acceptance watermark is PERSISTENT
    /// instance state, not derived from what the buffer currently holds
    /// -- a stale sample must still be rejected after the sample that
    /// set the watermark has been TAKEN (buffer empty again). This is
    /// the scenario a sorted-insertion-only fix cannot cover: there is
    /// nothing left buffered to insert against.
    ///
    /// Mutant: deriving the floor from `self.buffer` at push time
    /// instead of from the persistent `InstanceEntry::source_accept`
    /// (i.e. reverting to a buffer-scan floor) makes this fail: an empty
    /// buffer would report no floor, and 200 would be accepted.
    #[test]
    fn by_source_timestamp_watermark_survives_the_sample_being_taken() {
        let handle = make_handle(6);
        let cache = by_source_ts_cache::<i32>(1);
        push_admitted(
            &cache,
            CachedSample::with_meta(30, 1, 300, handle, Some([1u8; 16]), true),
        );
        assert_eq!(cache.take(), Some(30), "fixture: 300 taken, buffer empty");
        assert!(cache.is_empty());

        push_admitted(
            &cache,
            CachedSample::with_meta(20, 2, 200, handle, Some([2u8; 16]), true),
        );
        assert_eq!(
            cache.take(),
            None,
            "a sample older than the watermark must be rejected even once \
             nothing of the instance is left buffered to compare it against"
        );
    }

    /// Same persistence, through `read()` instead of `take()`: DDS v1.4
    /// Sec.2.2.3.17 requires read/take to present an instance's changes
    /// in source-timestamp order, so a stale sample must not slip in
    /// behind an already-READ (but not yet taken) newer one either. The
    /// acceptance point must not be keyed off the take cursor -- a
    /// buffer-scan floor that only looked at not-yet-read samples would
    /// miss this.
    #[test]
    fn by_source_timestamp_watermark_survives_a_read_that_does_not_remove_the_sample() {
        let handle = make_handle(10);
        let cache = by_source_ts_cache::<i32>(4);
        push_admitted(
            &cache,
            CachedSample::with_meta(30, 1, 300, handle, Some([1u8; 16]), true),
        );
        assert_eq!(cache.read(), Some(30), "fixture: read, not removed");

        push_admitted(
            &cache,
            CachedSample::with_meta(20, 2, 200, handle, Some([2u8; 16]), true),
        );
        // The stale push must have been rejected: exactly the one
        // (already-read) sample is still there, and it is the one that
        // set the watermark.
        assert_eq!(cache.len(), 1, "the stale sample must not be buffered");
        assert_eq!(cache.take(), Some(30));
        assert_eq!(cache.take(), None);
    }

    /// KEEP_LAST(N>1)/KEEP_ALL: the watermark advances on every accepted
    /// change, not only the one still at the front. A PARTIAL take
    /// (removing the oldest of two buffered samples) must not lower it
    /// back down to what remains buffered.
    #[test]
    fn by_source_timestamp_watermark_advances_past_a_partially_taken_sample() {
        let handle = make_handle(12);
        let cache = by_source_ts_cache::<i32>(4);
        push_admitted(
            &cache,
            CachedSample::with_meta(10, 1, 100, handle, Some([1u8; 16]), true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(20, 2, 200, handle, Some([1u8; 16]), true),
        );
        assert_eq!(cache.take(), Some(10), "fixture: only the older is taken");
        assert_eq!(cache.len(), 1, "fixture: 200 is still buffered");

        push_admitted(
            &cache,
            CachedSample::with_meta(15, 3, 150, handle, Some([2u8; 16]), true),
        );
        assert_eq!(
            cache.len(),
            1,
            "150 is older than the watermark (200), rejected even though \
             the sample that set the watermark (100) is already gone"
        );
        assert_eq!(cache.take(), Some(20));
        assert_eq!(cache.take(), None);
    }

    /// KEEP_ALL/KEEP_LAST(N): several samples of one instance coexist in
    /// the buffer, and read/take hands them out in the order they were
    /// ACCEPTED -- which, because acceptance only ever lets a strictly
    /// increasing `SourceOrderKey` through, is also their source-
    /// timestamp order. No sorted insertion is needed to get this: a
    /// plain `push_back` after the gate is already sorted (see
    /// `push_locked`'s doc).
    #[test]
    fn by_source_timestamp_several_accepted_samples_come_out_in_order() {
        let handle = make_handle(7);
        let cache = by_source_ts_cache::<i32>(8);
        push_admitted(
            &cache,
            CachedSample::with_meta(100, 1, 100, handle, Some([2u8; 16]), true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(200, 2, 200, handle, Some([1u8; 16]), true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(300, 3, 300, handle, Some([1u8; 16]), true),
        );
        // A trailing OLDER arrival is rejected, not inserted "late".
        push_admitted(
            &cache,
            CachedSample::with_meta(250, 4, 250, handle, Some([2u8; 16]), true),
        );

        let taken: Vec<_> = std::iter::from_fn(|| cache.take()).collect();
        assert_eq!(taken, vec![100, 200, 300]);
    }

    /// DDS v1.4 Sec.2.2.3.17: two changes with the SAME source timestamp
    /// are ordered deterministically (here, by writer GUID) so that two
    /// readers which happened to see them in opposite arrival order still
    /// agree on which one survives KEEP_LAST(1).
    ///
    /// Mutant: comparing only `timestamp_ns` in `SourceOrderKey`'s `Ord`
    /// (dropping the writer GUID from the tuple) makes this fail
    /// non-deterministically: whichever of the tied pair arrives second
    /// would always "win" by acceptance order instead of by GUID.
    #[test]
    fn by_source_timestamp_breaks_a_timestamp_tie_by_writer_guid() {
        let handle = make_handle(9);
        let low = Some([1u8; 16]);
        let high = Some([2u8; 16]);

        // Lower-GUID sample arrives first.
        let cache = by_source_ts_cache::<i32>(1);
        push_admitted(
            &cache,
            CachedSample::with_meta(1, 1, 100, handle, low, true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(2, 1, 100, handle, high, true),
        );
        assert_eq!(
            cache.take(),
            Some(2),
            "the higher writer GUID wins an exact timestamp tie"
        );

        // Same tie, arrival order reversed: the winner must not change.
        let cache = by_source_ts_cache::<i32>(1);
        push_admitted(
            &cache,
            CachedSample::with_meta(2, 1, 100, handle, high, true),
        );
        push_admitted(
            &cache,
            CachedSample::with_meta(1, 1, 100, handle, low, true),
        );
        assert_eq!(
            cache.take(),
            Some(2),
            "the tie-break is deterministic, not whichever arrived last"
        );
    }

    /// The empty-buffer fused pump+take path (`push_and_take_front`) is
    /// the common one on the crown KeepLast(1) roundtrip (buffer empty on
    /// every call, since the previous take drained it): exactly where a
    /// persistent watermark matters most, since the buffer never holds a
    /// competing sample. Admission happens before that path and must
    /// still see the taken sample's watermark.
    #[test]
    fn by_source_timestamp_fused_empty_buffer_path_rejects_a_stale_sample() {
        let handle = make_handle(13);
        let cache = by_source_ts_cache::<i32>(1);
        assert_eq!(
            admitted_then(
                &cache,
                |c, s| c.push_and_take_front(s),
                CachedSample::with_meta(30, 1, 300, handle, Some([1u8; 16]), true,)
            ),
            Some(30),
            "fixture: the fused path accepts and returns the first sample"
        );
        assert!(cache.is_empty(), "fixture: fused path never buffers here");

        assert_eq!(
            admitted_then(
                &cache,
                |c, s| c.push_and_take_front(s),
                CachedSample::with_meta(20, 2, 200, handle, Some([2u8; 16]), true,)
            ),
            None,
            "the empty-buffer fused path must not bypass the acceptance gate"
        );
    }

    /// [`by_source_timestamp_fused_empty_buffer_path_rejects_a_stale_sample`]
    /// for the `_full` twin (`push_and_take_front_full`), the one
    /// `take_with_info` actually calls on the crown path.
    #[test]
    fn by_source_timestamp_fused_empty_buffer_path_full_rejects_a_stale_sample() {
        let handle = make_handle(14);
        let cache = by_source_ts_cache::<i32>(1);
        assert!(cache
            .admitted_then_full(CachedSample::with_meta(
                30,
                1,
                300,
                handle,
                Some([1u8; 16]),
                true,
            ))
            .is_some());
        assert!(cache.is_empty());

        assert!(
            cache
                .admitted_then_full(CachedSample::with_meta(
                    20,
                    2,
                    200,
                    handle,
                    Some([2u8; 16]),
                    true,
                ))
                .is_none(),
            "the empty-buffer fused `_full` path must not bypass the gate either"
        );
    }

    #[test]
    fn test_instance_handle() {
        let nil = InstanceHandle::nil();
        assert!(nil.is_nil());
        assert_eq!(nil.as_bytes(), &[0u8; 16]);

        let handle = make_handle(42);
        assert!(!handle.is_nil());
        assert_eq!(handle.as_bytes()[0], 42);
    }

    #[test]
    fn test_take_instance() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        // Push samples with different instance handles
        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));
        cache.push(CachedSample::with_instance(21, 4, 0, h2));

        // Take from instance 1
        assert_eq!(cache.take_instance(h1), Some(10));
        assert_eq!(cache.len(), 3);

        // Take from instance 2
        assert_eq!(cache.take_instance(h2), Some(20));
        assert_eq!(cache.len(), 2);

        // Take remaining from instance 1
        assert_eq!(cache.take_instance(h1), Some(11));
        assert_eq!(cache.len(), 1);

        // No more instance 1 samples
        assert_eq!(cache.take_instance(h1), None);

        // Still one instance 2 sample
        assert_eq!(cache.take_instance(h2), Some(21));
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_take_instance_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        // Push interleaved samples
        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));
        cache.push(CachedSample::with_instance(21, 4, 0, h2));
        cache.push(CachedSample::with_instance(12, 5, 0, h1));

        // Take batch from instance 1 (limit 2)
        let batch = cache.take_instance_batch(h1, 2);
        assert_eq!(batch, vec![10, 11]);
        assert_eq!(cache.len(), 3);

        // Take all remaining from instance 1
        let batch = cache.take_instance_batch(h1, 10);
        assert_eq!(batch, vec![12]);
        assert_eq!(cache.len(), 2);

        // Only instance 2 samples remain
        let batch = cache.take_instance_batch(h2, 10);
        assert_eq!(batch, vec![20, 21]);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn fused_push_take_keeps_every_interleaved_instance_readable() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));

        let taken = cache.push_all_and_take_front(
            CachedSample::with_instance(11, 3, 0, h1),
            vec![
                CachedSample::with_instance(21, 4, 0, h2),
                CachedSample::with_instance(12, 5, 0, h1),
            ],
        );

        assert_eq!(taken, Some(10));
        assert_eq!(cache.take_instance_batch(h1, 10), vec![11, 12]);
        assert_eq!(cache.take_instance_batch(h2, 10), vec![20, 21]);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_read_instance() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));

        // Read from instance 1 (non-destructive)
        assert_eq!(cache.read_instance(h1), Some(10));
        assert_eq!(cache.len(), 3); // Still all there

        // Reading again from instance 1 gets next unread sample
        assert_eq!(cache.read_instance(h1), Some(11));

        // No more unread instance 1 samples
        assert_eq!(cache.read_instance(h1), None);

        // Instance 2 sample still unread
        assert_eq!(cache.read_instance(h2), Some(20));
        assert_eq!(cache.read_instance(h2), None);

        // All samples still in cache
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_read_instance_batch() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(11, 3, 0, h1));
        cache.push(CachedSample::with_instance(12, 4, 0, h1));

        // Read batch from instance 1 (limit 2)
        let batch = cache.read_instance_batch(h1, 2);
        assert_eq!(batch, vec![10, 11]);

        // Read remaining unread from instance 1
        let batch = cache.read_instance_batch(h1, 10);
        assert_eq!(batch, vec![12]);

        // No more unread instance 1 samples
        let batch = cache.read_instance_batch(h1, 10);
        assert!(batch.is_empty());

        // All samples still in cache
        assert_eq!(cache.len(), 4);
    }

    #[test]
    fn test_take_instance_adjusts_read_cursor() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let h1 = make_handle(1);
        let h2 = make_handle(2);

        cache.push(CachedSample::with_instance(10, 1, 0, h1));
        cache.push(CachedSample::with_instance(20, 2, 0, h2));
        cache.push(CachedSample::with_instance(30, 3, 0, h1));

        // Read first two samples (advances cursor to 2)
        assert_eq!(cache.read(), Some(10));
        assert_eq!(cache.read(), Some(20));

        // Take instance 1 sample from front (should adjust cursor)
        assert_eq!(cache.take_instance(h1), Some(10));

        // Next read should be sample at new cursor position
        assert_eq!(cache.read(), Some(30));
    }

    // =========================================================================
    // SampleInfo metadata plumbing (take_with_info support)
    // =========================================================================

    #[test]
    fn test_with_meta_rides_through_take_full() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let guid = [7u8; 16];

        cache.push(CachedSample::with_meta(
            1,
            5,
            111,
            make_handle(3),
            Some(guid),
            true,
        ));

        let sample = cache.take_full().expect("sample present");
        assert_eq!(sample.data, 1);
        assert_eq!(sample.seq, 5);
        assert_eq!(sample.timestamp_ns, 111);
        assert_eq!(sample.instance_handle, make_handle(3));
        assert_eq!(sample.writer_guid, Some(guid));
        assert!(sample.has_source_ts);
        assert!(cache.take_full().is_none());
    }

    #[test]
    fn test_metadata_free_constructors_default_meta() {
        let keyless = CachedSample::new(1, 1, 0);
        assert_eq!(keyless.writer_guid, None);
        assert!(!keyless.has_source_ts);

        let keyed = CachedSample::with_instance(2, 2, 0, make_handle(1));
        assert_eq!(keyed.writer_guid, None);
        assert!(!keyed.has_source_ts);
    }

    #[test]
    fn test_meta_rides_through_fused_twins() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let guid = [9u8; 16];

        // Single-sample fused twin.
        let sample = cache
            .push_and_take_front_full(CachedSample::with_meta(
                10,
                1,
                50,
                InstanceHandle::nil(),
                Some(guid),
                true,
            ))
            .expect("front sample");
        assert_eq!(sample.data, 10);
        assert_eq!(sample.writer_guid, Some(guid));
        assert!(sample.has_source_ts);

        // Multi-sample fused twin: front pop returns the FIRST pushed
        // sample, and the parked rest keeps its own metadata.
        let first = CachedSample::with_meta(20, 2, 60, InstanceHandle::nil(), None, false);
        let rest = vec![CachedSample::with_meta(
            30,
            3,
            70,
            InstanceHandle::nil(),
            Some(guid),
            true,
        )];
        let sample = cache
            .push_all_and_take_front_full(first, rest)
            .expect("front sample");
        assert_eq!(sample.data, 20);
        assert_eq!(sample.writer_guid, None);
        assert!(!sample.has_source_ts);

        let sample = cache.take_full().expect("rest sample");
        assert_eq!(sample.data, 30);
        assert_eq!(sample.writer_guid, Some(guid));
        assert!(sample.has_source_ts);
    }

    #[test]
    fn test_into_data_and_info_source_known() {
        let guid = [3u8; 16];
        // A known writer's full SN survives presentation to the application.
        let seq = (2u64 << 32) | 41;
        let sample = CachedSample::with_meta(7, seq, 123_456_789, make_handle(4), Some(guid), true);

        let (data, info) = sample.into_data_and_info();
        assert_eq!(data, 7);
        assert_eq!(info.source_timestamp_ns, Some(123_456_789));
        // Reception is stamped at pop time when the source is known; any
        // real clock reading dwarfs the tiny synthetic source stamp.
        assert!(info.reception_timestamp_ns > 123_456_789);
        assert_eq!(info.writer_guid, Some(guid));
        assert_eq!(info.sequence_number, seq);
        assert_eq!(info.instance_handle, make_handle(4));
        assert_eq!(info.instance_state, InstanceState::Alive);
        assert!(info.valid_data);
    }

    #[test]
    fn test_into_data_and_info_source_unknown() {
        let sample = CachedSample::with_meta(8, 6, 424_242, InstanceHandle::nil(), None, false);
        let (data, info) = sample.into_data_and_info();
        assert_eq!(data, 8);
        assert_eq!(info.source_timestamp_ns, None);
        // Without a source timestamp, timestamp_ns already IS the
        // push-time reception stamp and must come back verbatim.
        assert_eq!(info.reception_timestamp_ns, 424_242);
        assert_eq!(info.writer_guid, None);
        assert_eq!(info.sequence_number, 6);
        assert!(info.valid_data);
    }

    #[test]
    fn test_instance_handle_nil() {
        let cache: SampleCache<i32> = SampleCache::new(10);
        let nil = InstanceHandle::nil();

        // Keyless samples use nil handle
        cache.push(CachedSample::new(1, 1, 0)); // Uses nil handle
        cache.push(CachedSample::new(2, 2, 0));

        // Can filter by nil handle (all keyless samples)
        assert_eq!(cache.take_instance(nil), Some(1));
        assert_eq!(cache.take_instance(nil), Some(2));
        assert_eq!(cache.take_instance(nil), None);
    }

    /// Observable state the fused push + front-pop leaves behind, so
    /// the pass-through and the general path can be compared exactly.
    fn observe<T>(cache: &SampleCache<T>) -> (usize, usize, usize) {
        (
            cache.len(),
            cache.read_cursor.load(Ordering::Relaxed),
            cache.total_received(),
        )
    }

    /// The empty-buffer pass-through of `push_and_take_front` must be
    /// indistinguishable from push() followed by take(): same sample
    /// out, same length, same read cursor, same total_received. Checked
    /// at KeepLast(1) (the crown depth), at a larger depth, and at depth
    /// 0 where the eviction gate fires on an empty buffer, then through
    /// the `_full` twin, and finally on a NON-empty buffer where the
    /// shortcut must stay out of the way and the front, not the new
    /// sample, comes back.
    #[test]
    fn push_and_take_front_pass_through_matches_push_then_take() {
        for depth in [1usize, 4, 0] {
            let shortcut: SampleCache<i32> = SampleCache::new(depth);
            let general: SampleCache<i32> = SampleCache::new(depth);
            assert_eq!(observe(&shortcut), (0, 0, 0));

            for seq in 1..=3u64 {
                let value = seq as i32 * 10;
                let fused = shortcut.push_and_take_front(CachedSample::new(value, seq, 7));
                general.push(CachedSample::new(value, seq, 7));
                let sequential = general.take();
                assert_eq!(fused, Some(value), "depth {depth} seq {seq}");
                assert_eq!(fused, sequential, "depth {depth} seq {seq}");
                assert_eq!(
                    observe(&shortcut),
                    observe(&general),
                    "depth {depth} seq {seq}"
                );
                assert_eq!(
                    observe(&shortcut),
                    (0, 0, seq as usize),
                    "depth {depth} seq {seq}"
                );
            }
        }

        // The metadata-keeping twin takes the same shortcut.
        let full: SampleCache<i32> = SampleCache::new(1);
        let sample = full
            .push_and_take_front_full(CachedSample::with_meta(
                5,
                9,
                123,
                InstanceHandle::new([3u8; 16]),
                Some([4u8; 16]),
                true,
            ))
            .expect("pass-through returns the sample");
        assert_eq!(sample.data, 5);
        assert_eq!(sample.seq, 9);
        assert_eq!(sample.timestamp_ns, 123);
        assert_eq!(sample.instance_handle, InstanceHandle::new([3u8; 16]));
        assert_eq!(sample.writer_guid, Some([4u8; 16]));
        assert!(sample.has_source_ts);
        assert_eq!(sample.sample_state(), SampleState::NotRead);
        assert_eq!(observe(&full), (0, 0, 1));

        // Non-empty buffer: the general path, front-pop semantics intact.
        let backlog: SampleCache<i32> = SampleCache::new(4);
        backlog.push(CachedSample::new(1, 1, 0));
        assert_eq!(backlog.read(), Some(1));
        assert_eq!(observe(&backlog), (1, 1, 1));
        assert_eq!(
            backlog.push_and_take_front(CachedSample::new(2, 2, 0)),
            Some(1)
        );
        assert_eq!(observe(&backlog), (1, 0, 2));
        assert_eq!(backlog.take(), Some(2));
        assert_eq!(observe(&backlog), (0, 0, 2));
    }

    /// A KEEP_ALL history room of three places, a cache giving places back
    /// to it, and three samples cached holding a place each (sequences 1,
    /// 2, 3; instance `[seq; 16]` for the per-instance takes).
    fn cache_holding_three() -> (
        Arc<crate::dds::reader::admission::HistoryRoom>,
        SampleCache<u32>,
    ) {
        let room = crate::dds::reader::admission::HistoryRoom::new(
            &crate::core::rt::IndexRing::with_capacity(16),
            3,
        );
        let cache = SampleCache::new(8).with_room(Some(Arc::clone(&room)));
        for seq in 1..=3u32 {
            cache.push_holding(
                CachedSample::with_instance(
                    seq,
                    u64::from(seq),
                    0,
                    InstanceHandle::new([u8::try_from(seq).expect("small"); 16]),
                ),
                room.reserve(0),
                false,
            );
        }
        assert_eq!(room.taken(), 3, "three cached samples hold three places");
        assert!(room.reserve(0).is_none(), "the room is full");
        (room, cache)
    }

    /// A sample built to go straight through the fused push + take, holding
    /// a place of `room` the way `push_holding` records one.
    fn held_sample(
        room: &Arc<crate::dds::reader::admission::HistoryRoom>,
        seq: u32,
    ) -> CachedSample<u32> {
        let mut sample = CachedSample::new(seq, u64::from(seq), 0);
        if room.reserve(0).expect("a free place").into_cache(room) {
            sample.held |= HELD_PLACE;
        }
        assert!(sample.holds_place());
        sample
    }

    #[test]
    fn a_front_take_gives_the_place_back() {
        let (room, cache) = cache_holding_three();
        assert_eq!(cache.take(), Some(1));
        assert_eq!(room.taken(), 2, "take");
        assert_eq!(cache.take_full().map(|s| s.data), Some(2));
        assert_eq!(room.taken(), 1, "take_full");
    }

    #[test]
    fn the_fused_push_and_take_gives_the_popped_place_back() {
        let (room, cache) = cache_holding_three();
        // Not empty: the pushed sample queues behind 1, which comes out.
        assert_eq!(
            cache.push_and_take_front(CachedSample::new(9, 9, 0)),
            Some(1)
        );
        assert_eq!(room.taken(), 2, "push_and_take_front");
        let popped = cache.push_and_take_front_full(CachedSample::new(10, 10, 0));
        assert_eq!(popped.map(|s| s.data), Some(2));
        assert_eq!(room.taken(), 1, "push_and_take_front_full");
        assert_eq!(
            cache.push_all_and_take_front(CachedSample::new(11, 11, 0), Vec::new()),
            Some(3)
        );
        assert_eq!(room.taken(), 0, "push_all_and_take_front");
        let (room, cache) = cache_holding_three();
        let popped = cache.push_all_and_take_front_full(CachedSample::new(9, 9, 0), Vec::new());
        assert_eq!(popped.map(|s| s.data), Some(1));
        assert_eq!(room.taken(), 2, "push_all_and_take_front_full");
    }

    #[test]
    fn a_sample_passed_straight_through_an_empty_cache_gives_its_place_back() {
        let (room, cache) = cache_holding_three();
        cache.clear();
        assert_eq!(cache.push_and_take_front(held_sample(&room, 4)), Some(4));
        assert_eq!(room.taken(), 0, "push_and_take_front on an empty cache");
        let passed = cache.push_and_take_front_full(held_sample(&room, 5));
        assert_eq!(passed.map(|s| s.data), Some(5));
        assert_eq!(
            room.taken(),
            0,
            "push_and_take_front_full on an empty cache"
        );
    }

    #[test]
    fn a_selective_take_gives_the_place_back() {
        let (room, cache) = cache_holding_three();
        let taken = cache.take_first_matching(|sample, _, _| sample.seq == 2);
        assert_eq!(taken.map(|s| s.data), Some(2));
        assert_eq!(room.taken(), 2);
    }

    #[test]
    fn a_batch_take_gives_every_place_back() {
        let (room, cache) = cache_holding_three();
        assert_eq!(cache.take_batch(2), vec![1, 2]);
        assert_eq!(room.taken(), 1);
    }

    #[test]
    fn clear_gives_every_place_back() {
        let (room, cache) = cache_holding_three();
        cache.clear();
        assert_eq!(room.taken(), 0);
    }

    #[test]
    fn an_instance_take_gives_the_place_back() {
        let (room, cache) = cache_holding_three();
        assert_eq!(cache.take_instance(InstanceHandle::new([2; 16])), Some(2));
        assert_eq!(room.taken(), 2, "take_instance");
        assert_eq!(
            cache.take_instance_batch(InstanceHandle::new([3; 16]), 4),
            vec![3]
        );
        assert_eq!(room.taken(), 1, "take_instance_batch");
    }

    #[test]
    fn a_duplicate_refused_by_the_cache_gives_its_place_back() {
        let (room, cache) = cache_holding_three();
        assert_eq!(cache.take(), Some(1));
        let place = room.reserve(0).expect("one free place");
        // Same sequence and writer as the cached 2: refused.
        cache.push_holding(CachedSample::new(2, 2, 0), Some(place), false);
        assert_eq!(cache.len(), 2);
        assert_eq!(room.taken(), 2, "the refused duplicate holds nothing");
    }

    #[test]
    fn dropping_the_cache_gives_every_place_back() {
        let (room, cache) = cache_holding_three();
        drop(cache);
        assert_eq!(room.taken(), 0);
    }

    #[test]
    fn a_read_copy_holds_no_place() {
        let (room, cache) = cache_holding_three();
        assert_eq!(cache.read(), Some(1));
        let (_, copy) = cache
            .read_first_matching_from(0, |sample, _, _| sample.seq == 2)
            .expect("2 is cached");
        assert!(!copy.holds_place(), "a clone holds none");
        assert_eq!(room.taken(), 3, "reading takes nothing out of the history");
    }

    #[test]
    fn a_cache_without_a_room_gives_a_pushed_place_back_at_once() {
        let room = crate::dds::reader::admission::HistoryRoom::new(
            &crate::core::rt::IndexRing::with_capacity(16),
            3,
        );
        let cache = SampleCache::new(8);
        cache.push_holding(CachedSample::new(1u32, 1, 0), room.reserve(0), false);
        assert_eq!(room.taken(), 0);
        assert_eq!(cache.take(), Some(1));
    }

    /// `no_writers_generation_count` (DDS v1.4 Sec.2.2.2.5.1.5): 0 until the
    /// instance has had NO_WRITERS and come back ALIVE, then incremented
    /// exactly once per such revival - a revival from NOT_ALIVE_DISPOSED
    /// does not count, and a sample that arrived before the transition
    /// does not revive it at all. Keyed instance: a plain field in the
    /// locked entry.
    #[test]
    fn no_writers_generation_count_counts_only_no_writers_revivals_keyed() {
        let table = InstanceTable::new();
        let handle = make_handle(1);
        let writer = Some([7u8; 16]);
        assert_eq!(table.no_writers_generation_count(handle), 0);

        // NO_WRITERS at seq 5, the same writer's sample sent before it
        // (seq 4) does not revive (the writer is known on both sides, so
        // the seq comparison applies).
        assert!(table.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (writer, 5)));
        table.arrive(handle, (writer, 4));
        assert_eq!(
            table.no_writers_generation_count(handle),
            0,
            "a sample sent before the transition does not revive it"
        );

        // A sample sent after it revives, and counts once.
        table.arrive(handle, (writer, 6));
        assert_eq!(table.no_writers_generation_count(handle), 1);

        // DISPOSED, then revived: does not add to the NO_WRITERS count.
        assert!(table.mark_not_alive(handle, InstanceState::NotAliveDisposed, (writer, 7)));
        table.arrive(handle, (writer, 8));
        assert_eq!(
            table.no_writers_generation_count(handle),
            1,
            "a DISPOSED revival is not a NO_WRITERS revival"
        );

        // NO_WRITERS again: the count keeps counting, it never resets.
        assert!(table.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (writer, 9)));
        table.arrive(handle, (writer, 10));
        assert_eq!(table.no_writers_generation_count(handle), 2);
    }

    /// Same rule, nil (keyless) instance: the fast-path counter
    /// (`InstanceTable::nil_gen`) must track the locked entry exactly.
    #[test]
    fn no_writers_generation_count_counts_only_no_writers_revivals_nil() {
        let table = InstanceTable::new();
        let handle = InstanceHandle::nil();
        assert_eq!(table.no_writers_generation_count(handle), 0);

        assert!(table.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (None, 1)));
        table.arrive(handle, (None, 2));
        assert_eq!(table.no_writers_generation_count(handle), 1);

        assert!(table.mark_not_alive(handle, InstanceState::NotAliveDisposed, (None, 3)));
        table.arrive(handle, (None, 4));
        assert_eq!(
            table.no_writers_generation_count(handle),
            1,
            "a DISPOSED revival is not a NO_WRITERS revival"
        );
    }

    /// A transition reports the generation in effect when it was applied,
    /// read under the lock that applies it, keyed and nil, including a
    /// NO_WRITERS transition that leaves a DISPOSED instance unchanged.
    #[test]
    fn a_transition_is_stamped_with_the_generation_it_was_applied_in() {
        let writer = Some([7u8; 16]);
        let keyed = InstanceHandle::new([3u8; 16]);
        let table = InstanceTable::new();
        assert_eq!(
            table.mark_not_alive_stamped(keyed, InstanceState::NotAliveNoWriters, (writer, 1)),
            (true, (0, 0))
        );
        table.arrive(keyed, (writer, 2));
        assert_eq!(
            table.mark_not_alive_stamped(keyed, InstanceState::NotAliveNoWriters, (writer, 3)),
            (true, (0, 1))
        );
        table.arrive(keyed, (writer, 4));
        assert!(table.mark_not_alive(keyed, InstanceState::NotAliveDisposed, (writer, 5)));
        assert_eq!(
            table.mark_not_alive_stamped(keyed, InstanceState::NotAliveNoWriters, (writer, 6)),
            (false, (0, 2)),
            "losing the writers keeps DISPOSED, and still reports the count"
        );

        let nil = InstanceHandle::nil();
        assert_eq!(
            table.mark_not_alive_stamped(nil, InstanceState::NotAliveNoWriters, (None, 1)),
            (true, (0, 0))
        );
        table.arrive(nil, (None, 2));
        assert_eq!(
            table.mark_not_alive_stamped(nil, InstanceState::NotAliveNoWriters, (None, 3)),
            (true, (0, 1))
        );
    }

    /// DDS v1.4 Sec.2.2.2.5.1.5: a `SampleInfo`'s `no_writers_generation_count`
    /// is the value AT THE TIME its sample was RECEIVED, not whatever the
    /// instance table says when the application finally takes it. Two
    /// samples straddling a second revival, both still buffered when taken,
    /// must report their OWN generation, not the table's latest.
    #[test]
    fn no_writers_generation_count_is_stamped_per_sample_at_receipt_not_at_take() {
        let instances = Arc::new(InstanceTable::new());
        let cache: SampleCache<i32> = SampleCache::with_instances(10, Arc::clone(&instances));
        let handle = make_handle(1);
        let writer = Some([9u8; 16]);

        // NO_WRITERS at seq 1; the sample at seq 2 revives it to generation 1.
        assert!(instances.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (writer, 1)));
        cache.push(CachedSample::with_meta(10, 2, 0, handle, writer, false));

        // NO_WRITERS again at seq 3, while sample 1 is still sitting
        // unread in the cache; the sample at seq 4 revives it to
        // generation 2.
        assert!(instances.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (writer, 3)));
        cache.push(CachedSample::with_meta(20, 4, 0, handle, writer, false));

        // The table is now at generation 2 - taking BOTH samples only
        // now must not retroactively change what the first one reports.
        assert_eq!(instances.no_writers_generation_count(handle), 2);
        let (data1, info1) = cache
            .take_full()
            .expect("first sample")
            .into_data_and_info();
        assert_eq!(data1, 10);
        assert_eq!(
            info1.no_writers_generation_count, 1,
            "stamped at this sample's own receipt, not read fresh at take() time"
        );
        let (data2, info2) = cache
            .take_full()
            .expect("second sample")
            .into_data_and_info();
        assert_eq!(data2, 20);
        assert_eq!(info2.no_writers_generation_count, 2);
    }

    /// Same rule as above, through the fused push+take empty-buffer
    /// pass-through (`push_and_take_front_full`) - the one-writer-one-
    /// reader crown path `latency_benchmark` measures, which stamps the
    /// count on its own, separate code path from `push_locked`.
    #[test]
    fn no_writers_generation_count_is_stamped_on_the_fused_pass_through_too() {
        let instances = Arc::new(InstanceTable::new());
        let cache: SampleCache<i32> = SampleCache::with_instances(10, Arc::clone(&instances));
        let handle = make_handle(1);
        let writer = Some([9u8; 16]);

        assert!(instances.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (writer, 1)));
        let revived = cache
            .push_and_take_front_full(CachedSample::with_meta(10, 2, 0, handle, writer, false))
            .expect("the empty-buffer pass-through hands the sample straight back");
        assert_eq!(
            revived.no_writers_generation_count, 1,
            "the pass-through stamps it too, not only push_locked"
        );
    }
    /// DDS v1.4 Sec.2.2.2.5.1.5: each counter counts only its own
    /// NOT_ALIVE-to-ALIVE transition, including nil and ordered admission.
    #[test]
    fn disposed_generation_counts_are_receipt_snapshots_for_every_instance_path() {
        for by_source in [false, true] {
            for handle in [InstanceHandle::nil(), make_handle(91)] {
                let table = Arc::new(InstanceTable::with_destination_order(by_source));
                let cache = SampleCache::with_instances(16, Arc::clone(&table));
                let writer = Some([7u8; 16]);
                let receive = |seq| {
                    let sample = CachedSample::with_meta(seq, seq, seq * 100, handle, writer, true);
                    if by_source {
                        assert!(push_admitted(&cache, sample));
                    } else {
                        cache.push(sample);
                    }
                };
                receive(1);
                assert_eq!(table.generation_counts(handle), (0, 0));
                table.mark_not_alive(handle, InstanceState::NotAliveDisposed, (writer, 2));
                // Repeating DISPOSED does not count as a revival.
                table.mark_not_alive(handle, InstanceState::NotAliveDisposed, (writer, 3));
                receive(4);
                receive(5);
                assert_eq!(table.generation_counts(handle), (1, 0));
                table.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (writer, 6));
                receive(7);
                assert_eq!(table.generation_counts(handle), (1, 1));
                table.mark_not_alive(handle, InstanceState::NotAliveDisposed, (writer, 8));
                // Losing writers never changes DISPOSED into NO_WRITERS.
                table.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (writer, 9));
                receive(10);
                assert_eq!(table.generation_counts(handle), (2, 1));
                let snapshots: Vec<_> = (0..5)
                    .map(|_| {
                        let (_, info) = cache.take_full().expect("sample").into_data_and_info();
                        (
                            info.disposed_generation_count,
                            info.no_writers_generation_count,
                        )
                    })
                    .collect();
                assert_eq!(snapshots, vec![(0, 0), (1, 0), (1, 0), (1, 1), (2, 1)]);
            }
        }
    }

    /// The direct empty-cache metadata path has the same receipt rule.
    #[test]
    fn disposed_generation_count_survives_fused_empty_cache_take() {
        for handle in [InstanceHandle::nil(), make_handle(92)] {
            let cache = SampleCache::new(4);
            cache
                .instances
                .mark_not_alive(handle, InstanceState::NotAliveDisposed, (None, 1));
            let sample = cache
                .push_and_take_front_full(CachedSample::with_instance(5, 2, 0, handle))
                .expect("reviving sample");
            assert_eq!(sample.disposed_generation_count, 1);
            assert_eq!(sample.no_writers_generation_count, 0);
            assert_eq!(cache.instances.generation_counts(handle), (1, 0));
        }
    }

    /// A value sent before a disposal must not increment either counter.
    #[test]
    fn disposed_generation_count_ignores_a_sample_preceding_the_dispose() {
        for handle in [InstanceHandle::nil(), make_handle(93)] {
            let table = InstanceTable::new();
            let writer = Some([7u8; 16]);
            table.mark_not_alive(handle, InstanceState::NotAliveDisposed, (writer, 5));
            assert_eq!(table.arrive(handle, (writer, 4)), (0, 0));
            assert_eq!(table.state_of(handle), InstanceState::NotAliveDisposed);
            assert_eq!(table.arrive(handle, (writer, 6)), (1, 0));
        }
    }

    /// Writer presence revives NO_WRITERS without erasing earlier
    /// DISPOSED generations, and never revives DISPOSED itself.
    #[test]
    fn writer_presence_preserves_disposed_generation_count() {
        for handle in [InstanceHandle::nil(), make_handle(94)] {
            let table = InstanceTable::with_destination_order(true);
            table.mark_not_alive(handle, InstanceState::NotAliveDisposed, (None, 1));
            table.revive_if_held(handle, || true);
            assert_eq!(table.generation_counts(handle), (0, 0));
            assert_eq!(table.state_of(handle), InstanceState::NotAliveDisposed);
            table.arrive(handle, (None, 2));
            table.mark_not_alive(handle, InstanceState::NotAliveNoWriters, (None, 3));
            table.revive_if_held(handle, || true);
            assert_eq!(table.generation_counts(handle), (1, 1));
            table.revive_if_held(handle, || true);
            assert_eq!(table.generation_counts(handle), (1, 1));
        }
    }
}

#[cfg(test)]
mod gated_take_tests {
    use super::*;

    /// A refused pass-through (empty buffer, no time filter) is stored exactly
    /// like an arrival: the same length and the same received count, and it is
    /// the head that the next accepting take returns.
    #[test]
    fn a_refused_pass_through_is_stored_like_an_arrival() {
        let refused: SampleCache<i32> = SampleCache::new(4);
        let arrival: SampleCache<i32> = SampleCache::new(4);

        let outcome = refused.push_and_take_if_with(
            CachedSample::new(5, 2, 0),
            |_: &i32| Err::<(), usize>(7),
            |sample| sample.data,
        );
        assert_eq!(outcome, Err(7), "refused with its size");
        arrival.push(CachedSample::new(5, 2, 0));
        assert_eq!(refused.len(), arrival.len());
        assert_eq!(refused.total_received(), arrival.total_received());

        let taken = refused.take_if_with(|_: &i32| Ok::<(), usize>(()), |sample| sample.data);
        assert_eq!(taken, Ok(Some(5)), "the refused sample is the head");
        assert_eq!(refused.len(), 0);
    }

    /// The first match of a gated take is the one refused or taken: a refusal
    /// is not skipped for a later match, and nothing is removed by a refusal.
    #[test]
    fn a_refused_first_match_is_not_skipped_for_a_later_one() {
        let cache: SampleCache<i32> = SampleCache::new(8);
        cache.push(CachedSample::new(1, 1, 0));
        cache.push(CachedSample::new(2, 2, 0));

        let refused = cache.take_first_matching_if(
            |_, _, _| true,
            |value: &i32| if *value == 1 { Err(3usize) } else { Ok(()) },
        );
        assert!(matches!(refused, Err(3)), "the first match, refused");
        assert_eq!(cache.len(), 2, "a refusal removes nothing");

        let second = cache.take_first_matching_if(
            |sample, _, _| sample.data == 2,
            |_: &i32| Ok::<(), usize>(()),
        );
        assert!(matches!(second, Ok(Some(ref s)) if s.data == 2));
        assert_eq!(cache.len(), 1);
    }
}

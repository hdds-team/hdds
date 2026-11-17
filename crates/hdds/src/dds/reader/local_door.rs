// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The reader's side of HISTORY and RESOURCE_LIMITS (DDS v1.4 Sec.2.2.3.18,
//! Sec.2.2.3.19) for the samples a DataWriter of the same process delivers:
//! what the writer's merger asks, on the writer's thread, before it pushes
//! into one of the reader's local rings (see [`rt::ReaderDoor`]).
//!
//! A local ring is the part of the reader's history the application has
//! not taken yet; the reader's sample cache, which `take` fills from the
//! ring, is the rest.
//!
//! - A full ring of a KEEP_LAST reader does not refuse the newest sample:
//!   the most recent `depth` values of each instance are kept, so the
//!   samples `depth` newer ones of their instance replace are dropped
//!   first. Every sample in the ring is newer than every sample of the
//!   cache, which drops its own older ones as the ring is taken.
//! - A RELIABLE KEEP_ALL reader's history is bounded by RESOURCE_LIMITS
//!   `max_samples` across its network and local arrivals: a local sample
//!   takes a place in the reader's [`HistoryRoom`] before it is pushed, and
//!   gives it back when the application takes it.
//! - RESOURCE_LIMITS `max_instances` and `max_samples_per_instance` bound
//!   the same history per instance: a local sample of a reader whose room
//!   bounds instances is counted for its instance before it is pushed
//!   ([`HistoryRoom::reserve_instance`]), and the count goes back when the
//!   sample leaves the history.
//! - A RELIABLE reader with no room makes the writer wait
//!   ([`RoomWait`]): nothing repairs a local sample that was not pushed. A
//!   BEST_EFFORT reader drops the sample and reports it as SAMPLE_REJECTED
//!   with the bound it met (Sec.2.2.3.19: "If reliability is BEST_EFFORT
//!   then the Service is allowed to drop samples").

use super::admission::{Bound, HistoryRoom, RoomWait};
use super::cache::InstanceHandle;
use super::registrations::ReaderRegistrations;
use super::runtime::ReaderBindings;
use crate::core::rt;
use crate::dds::listener::{ReaderListenerSlot, SampleRejectedReason, SampleRejectedStatus};
use crate::dds::{StatusCondition, StatusMask, DDS};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

/// Where a local sample the reader drops is reported: the reader's
/// SAMPLE_REJECTED status, condition and listener, the same the network
/// path reports to. Weak: the door lives in the writers' mergers.
pub(super) struct RejectionReport<T: DDS> {
    pub(super) status: Weak<Mutex<SampleRejectedStatus>>,
    pub(super) condition: Weak<StatusCondition>,
    pub(super) listener: Weak<ReaderListenerSlot<T>>,
    /// The reader's `ReaderStats::drops`, shared by every door of the
    /// reader: a sample of this reader's ring the producer pushed out.
    pub(super) dropped: Arc<AtomicU64>,
    /// This path's snapshots for the listener, queued under the status
    /// lock and told in that order with no lock held (`notices::Ordered`),
    /// as the network subscriber's are.
    pub(super) notices: Arc<super::notices::Ordered>,
}

impl<T: DDS> RejectionReport<T> {
    /// Record one rejection, as `ReaderSubscriber::report_sample_rejected`
    /// does for a network sample (DDS v1.4 Sec.2.2.4.2.1: the status is
    /// reset before the listener is called).
    fn report(&self, reason: SampleRejectedReason, instance: Option<InstanceHandle>) {
        // A local reader's history is the only bound a local sample can
        // find full (the slab budget is the writer's: `would_block`), so a
        // ResourceLimit report is a ring-full rejection, counted as the
        // network path counts it.
        if reason == SampleRejectedReason::ResourceLimit {
            if let Some(m) = crate::telemetry::get_metrics_opt() {
                m.increment_samples_rejected_ring_full(1);
            }
        }
        let (Some(status), Some(condition)) = (self.status.upgrade(), self.condition.upgrade())
        else {
            return;
        };
        let installed = self
            .listener
            .upgrade()
            .and_then(|slot| slot.get(StatusMask::SAMPLE_REJECTED));
        let mut own = None;
        {
            let mut status = status.lock().unwrap_or_else(|e| e.into_inner());
            status.total_count = status.total_count.saturating_add(1);
            status.total_count_change = status.total_count_change.saturating_add(1);
            status.last_reason = reason;
            status.last_instance_handle = instance;
            if let Some(listener) = installed.clone() {
                let snapshot = status.clone();
                status.total_count_change = 0;
                condition.clear_active_status(StatusMask::SAMPLE_REJECTED);
                own = self
                    .notices
                    .push(Box::new(move || listener.on_sample_rejected(snapshot)))
                    .err();
            } else {
                condition.raise_active_statuses(StatusMask::SAMPLE_REJECTED);
            }
        }
        // Told with none of the writer's locks held (`notices`); the
        // WaitSet hooks are public trait code too.
        if let Some(own) = own {
            super::notices::notify(own);
        } else if installed.is_some() {
            let notices = Arc::clone(&self.notices);
            super::notices::notify(move || notices.tell());
        } else {
            super::notices::notify(move || {
                condition.notify_waitsets_for(StatusMask::SAMPLE_REJECTED);
            });
        }
    }
}

/// What a reader keeps of its local arrivals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Keep {
    /// KEEP_LAST(`depth`): a newer sample replaces the oldest of its
    /// instance.
    Last(usize),
    /// KEEP_ALL: every sample until it is taken.
    All,
    /// BEST_EFFORT KEEP_ALL: at its RESOURCE_LIMITS "the old values will be
    /// discarded" (DDS v1.4 Sec.2.2.3.18), here its finite
    /// `max_samples_per_instance` of an instance (LENGTH_UNLIMITED for
    /// none), then its oldest samples (the reader's cache keeps
    /// `max_samples` of them).
    AllDiscardingOld(usize),
}

/// The door of a reader of `T` (see the module comment).
pub(super) struct LocalDoor<T: DDS> {
    /// The reader's bindings, for its ring consumer gate. Weak: the door
    /// lives in the writers' mergers, which can outlive the reader.
    bindings: Weak<ReaderBindings>,
    keep: Keep,
    /// RELIABLE: a writer waits for room rather than skip the reader.
    reliable: bool,
    /// The reader's history room, when a local sample takes room in it
    /// before it is pushed: a place (`places`), its instance's count (when
    /// the room bounds instances), or both.
    room: Option<Arc<HistoryRoom>>,
    /// A local sample takes a place in `room` (a RELIABLE KEEP_ALL reader).
    places: bool,
    /// A local sample is counted for its instance in `room`.
    counted: bool,
    /// The reader's writer registrations: an instance a writer still holds
    /// stays managed (Sec.2.2.3.22), asked only when a new instance meets
    /// `max_instances`.
    registrations: Weak<ReaderRegistrations>,
    /// Where the writers wait for room.
    wait: Arc<RoomWait>,
    /// Where a dropped sample is reported.
    report: RejectionReport<T>,
    /// DESTINATION_ORDER (DDS v1.4 Sec.2.2.3.17) resolved once, at reader
    /// creation, same as `InstanceTable::by_source_timestamp`: `true` for
    /// BY_SOURCE_TIMESTAMP, `false` (the default) otherwise. Read by
    /// `drop_replaced` to pick which of two samples of a full KEEP_LAST
    /// ring's instance survives -- the newest by ARRIVAL (unchanged,
    /// BY_RECEPTION_TIMESTAMP) or the newest by SOURCE TIMESTAMP.
    by_source_timestamp: bool,
    ordered: bool,
}

impl<T: DDS> LocalDoor<T> {
    /// The door of a reader keeping `keep`. `room` is the reader's history
    /// room; local samples take places in it when `places`, and are counted
    /// for their instance when it bounds instances. `wait` is where its
    /// writers wait for room.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        bindings: Weak<ReaderBindings>,
        keep: Keep,
        reliable: bool,
        room: Option<Arc<HistoryRoom>>,
        places: bool,
        registrations: Weak<ReaderRegistrations>,
        wait: Arc<RoomWait>,
        report: RejectionReport<T>,
        by_source_timestamp: bool,
        ordered: bool,
    ) -> Self {
        let counted = room.as_ref().is_some_and(|room| room.counts_instances());
        let room = room.filter(|_| places || counted);
        Self {
            bindings,
            keep,
            reliable,
            places: places && room.is_some(),
            counted,
            room,
            registrations,
            wait,
            report,
            by_source_timestamp,
            ordered,
        }
    }

    /// What the reader's cache gives back for each local sample that leaves
    /// it (`cache::HELD_*`): what this door takes for it.
    pub(super) fn hold(&self) -> u8 {
        let mut hold = 0;
        if self.places {
            hold |= super::cache::HELD_PLACE;
        }
        if self.counted {
            hold |= super::cache::HELD_INSTANCE;
        }
        hold
    }

    /// Whether a writer still holds instance `key`.
    fn held_by_a_writer(&self, key: &[u8; 16]) -> bool {
        self.registrations
            .upgrade()
            .is_some_and(|registrations| registrations.is_held(key))
    }

    /// The identity retained for an entry already in a local ring.
    fn entry_instance(&self, entry: &rt::IndexEntry, pool: &rt::SlabPool) -> Option<[u8; 16]> {
        if T::captures_wire_identity() && !entry.has_guid_prefix() {
            return self
                .bindings
                .upgrade()
                .and_then(|bindings| bindings.local_key(entry));
        }
        super::admission::ring_entry_instance::<T>(entry, pool)
    }

    /// The instance of an incoming sample, before its ring publication.
    fn instance_of(&self, entry: &rt::IndexEntry, key: Option<[u8; 16]>) -> [u8; 16] {
        if T::captures_wire_identity() {
            // An incoming replay without key metadata is the nil instance.
            // A recycled slot's previous key belongs only to its old entry.
            return key.unwrap_or([0; 16]);
        }
        if !T::has_key() {
            return [0; 16];
        }
        key.or_else(|| self.entry_instance(entry, rt::get_slab_pool_ref()))
            .unwrap_or([0; 16])
    }

    /// Drop the oldest sample of `ring` (lifecycle changes stay, in their
    /// order). The caller is the ring's producer and holds the reader's
    /// consumer gate. Returns whether a sample was dropped.
    fn drop_oldest(&self, ring: &rt::IndexRing) -> bool {
        let pool = rt::get_slab_pool_ref();
        let mut entries: Vec<rt::IndexEntry> = Vec::with_capacity(ring.len());
        while let Some(entry) = ring.pop() {
            entries.push(entry);
        }
        let oldest = entries.iter().position(|entry| entry.lifecycle_bits() == 0);
        for (i, entry) in entries.into_iter().enumerate() {
            if Some(i) == oldest || !ring.push(entry) {
                self.release_dropped(&entry, pool);
            }
        }
        if oldest.is_some() {
            self.report.dropped.fetch_add(1, Ordering::Relaxed);
            if let Some(m) = crate::telemetry::get_metrics_opt() {
                m.increment_dropped(1);
            }
        }
        oldest.is_some()
    }

    /// What a sample dropped from a ring held goes back: its instance count
    /// (a door that discards takes no place) and its slab reference.
    fn release_dropped(&self, entry: &rt::IndexEntry, pool: &rt::SlabPool) {
        self.release_order(entry);
        if self.counted && entry.lifecycle_bits() == 0 {
            if let (Some(room), Some(key)) = (self.room.as_ref(), self.entry_instance(entry, pool))
            {
                room.release_instance(&key);
            }
        }
        if entry.is_exclusive() {
            pool.release_exclusive(entry.handle);
        } else {
            pool.release(entry.handle);
        }
    }

    fn release_order(&self, entry: &rt::IndexEntry) {
        if !self.ordered {
            return;
        }
        if let Some(bindings) = self.bindings.upgrade() {
            if let Some(order) = bindings.local_read_order() {
                order.decoded(Arc::as_ptr(&bindings) as usize, entry.handle, None);
            }
        }
    }

    /// Drop from `ring`, full, every sample that `depth` newer samples of
    /// its instance replace, counting `incoming`, a sample of that instance
    /// about to be pushed (`None` for an entry that is no sample). What
    /// stays keeps its order; lifecycle changes always stay. Returns how
    /// many were dropped.
    ///
    /// Under BY_RECEPTION_TIMESTAMP (`self.by_source_timestamp` false,
    /// `incoming_ts` unused) "newer" means arrived later. Under
    /// BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17) it means a greater
    /// source timestamp (`kept_by_source_order`): a full ring must not
    /// keep a source-older sample over a source-newer one of its instance
    /// because the older one arrived later. `incoming_ts` is the incoming
    /// entry's source timestamp, `None` when it carries only a reception
    /// time.
    ///
    /// The caller is the ring's producer and holds the reader's consumer
    /// gate: it pops the ring whole and pushes back what the history keeps.
    fn drop_replaced(
        &self,
        ring: &rt::IndexRing,
        depth: usize,
        incoming: Option<[u8; 16]>,
        incoming_ts: Option<u64>,
    ) -> usize {
        let pool = rt::get_slab_pool_ref();
        let mut entries: Vec<(rt::IndexEntry, Option<[u8; 16]>)> = Vec::with_capacity(ring.len());
        while let Some(entry) = ring.pop() {
            let key = if entry.lifecycle_bits() == 0 {
                self.entry_instance(&entry, pool)
            } else {
                None
            };
            entries.push((entry, key));
        }
        // BY_SOURCE_TIMESTAMP: the positions the history keeps, decided up
        // front (`kept_by_source_order`). The default reader counts as it
        // goes, as it always did, with no allocation beyond `from_here`.
        let keep = self
            .by_source_timestamp
            .then(|| Self::kept_by_source_order(&entries, depth, incoming, incoming_ts));
        // For each instance, how many of its samples from here on: the
        // entry under the cursor, every later one, and the incoming one.
        let mut from_here: HashMap<[u8; 16], usize> = HashMap::new();
        if keep.is_none() {
            for key in incoming
                .into_iter()
                .chain(entries.iter().filter_map(|(_, key)| *key))
            {
                *from_here.entry(key).or_default() += 1;
            }
        }
        let mut dropped = 0usize;
        for (pos, (entry, key)) in entries.into_iter().enumerate() {
            let replaced = match &keep {
                Some(keep) => key.is_some() && !keep.contains(&pos),
                None => key
                    .and_then(|key| from_here.get_mut(&key))
                    .is_some_and(|count| {
                        let replaced = *count > depth;
                        *count -= 1;
                        replaced
                    }),
            };
            if replaced || !ring.push(entry) {
                self.release_order(&entry);
                // It leaves the history: what its writer's door took for
                // it goes back (a KEEP_LAST door takes no place).
                if let (Some(room), Some(key)) = (self.room.as_ref(), key) {
                    if self.counted {
                        room.release_instance(&key);
                    }
                }
                if entry.is_exclusive() {
                    pool.release_exclusive(entry.handle);
                } else {
                    pool.release(entry.handle);
                }
                dropped += 1;
            }
        }
        if dropped > 0 {
            self.report
                .dropped
                .fetch_add(dropped as u64, Ordering::Relaxed);
            if let Some(m) = crate::telemetry::get_metrics_opt() {
                m.increment_dropped(dropped as u64);
            }
        }
        dropped
    }
}

impl<T: DDS> LocalDoor<T> {
    /// The ring positions a full KEEP_LAST(`depth`) history keeps under
    /// BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17): per instance, the
    /// `depth` entries with the greatest source timestamp, the incoming
    /// one (`incoming_ts`, position `entries.len()`) included. One local
    /// ring carries one writer, so equal timestamps keep ring order,
    /// which is that writer's sequence order: the same total order the
    /// reader's admission uses. An entry with no source timestamp sorts
    /// as the oldest of its instance.
    fn kept_by_source_order(
        entries: &[(rt::IndexEntry, Option<[u8; 16]>)],
        depth: usize,
        incoming: Option<[u8; 16]>,
        incoming_ts: Option<u64>,
    ) -> std::collections::HashSet<usize> {
        let mut by_instance: HashMap<[u8; 16], Vec<(usize, Option<u64>)>> = HashMap::new();
        for (pos, (entry, key)) in entries.iter().enumerate() {
            if let Some(key) = key {
                let ts = entry.has_source_ts().then_some(entry.timestamp_ns);
                by_instance.entry(*key).or_default().push((pos, ts));
            }
        }
        if let Some(key) = incoming {
            by_instance
                .entry(key)
                .or_default()
                .push((entries.len(), incoming_ts));
        }
        let mut keep = std::collections::HashSet::new();
        for positions in by_instance.values_mut() {
            positions.sort_unstable_by_key(|&(pos, ts)| (ts, pos));
            for &(pos, _) in positions.iter().rev().take(depth) {
                keep.insert(pos);
            }
        }
        keep
    }
}

impl<T: DDS> rt::ReaderDoor for LocalDoor<T> {
    fn is_closed(&self) -> bool {
        self.bindings
            .upgrade()
            .is_none_or(|bindings| bindings.is_closed())
    }

    fn make_room(
        &self,
        ring: &rt::IndexRing,
        incoming: &rt::IndexEntry,
        key: Option<[u8; 16]>,
    ) -> bool {
        let (depth, oldest_too) = match self.keep {
            Keep::Last(depth) => (Some(depth), false),
            Keep::AllDiscardingOld(per_instance) => (
                (per_instance != crate::reliability::LENGTH_UNLIMITED).then_some(per_instance),
                true,
            ),
            // A RELIABLE KEEP_ALL history discards nothing.
            Keep::All => return false,
        };
        let Some(bindings) = self.bindings.upgrade() else {
            return false;
        };
        // The ring's consumer side: the reader pops it under this gate only.
        let _consumer = bindings.consumer_gate().lock();
        if bindings.is_closed() {
            // The reader is being torn down: its rings are drained by it.
            return false;
        }
        if !ring.is_full() {
            // The reader took meanwhile.
            return true;
        }
        // Read from the original entry before `incoming` is shadowed by
        // its own decoded key below.
        let incoming_ts = incoming.has_source_ts().then_some(incoming.timestamp_ns);
        let incoming = if incoming.lifecycle_bits() != 0 {
            None
        } else if T::captures_wire_identity() {
            Some(key.unwrap_or([0; 16]))
        } else if !T::has_key() {
            Some([0; 16])
        } else {
            key.or_else(|| self.entry_instance(incoming, rt::get_slab_pool_ref()))
        };
        let replaced = depth.map_or(0, |depth| {
            self.drop_replaced(ring, depth, incoming, incoming_ts)
        });
        // Nothing replaced and the ring still full: it holds at least
        // `max_samples` samples newer than every cached one (it is sized
        // `max_samples + 1`), so its oldest is one the history discards.
        replaced > 0 || (oldest_too && self.drop_oldest(ring))
    }

    fn make_room_for_set(
        &self,
        ring: &rt::IndexRing,
        members: &[(rt::IndexEntry, [u8; 16])],
        commit: bool,
    ) -> bool {
        let depth = match self.keep {
            Keep::Last(depth) => depth,
            _ => return false,
        };
        if members.len() > ring.usable_capacity() {
            return false;
        }
        let Some(bindings) = self.bindings.upgrade() else {
            return false;
        };
        let _consumer = bindings.consumer_gate().lock();
        if bindings.is_closed() {
            return false;
        }
        let pool = rt::get_slab_pool_ref();
        let mut old = Vec::new();
        while let Some(entry) = ring.pop() {
            old.push(entry);
        }
        let mut per: HashMap<[u8; 16], Vec<(usize, Option<u64>)>> = HashMap::new();
        for (i, entry) in old.iter().enumerate() {
            if entry.lifecycle_bits() == 0 {
                if let Some(key) = self.entry_instance(entry, pool) {
                    per.entry(key)
                        .or_default()
                        .push((i, entry.has_source_ts().then_some(entry.timestamp_ns)));
                }
            }
        }
        for (i, (entry, key)) in members.iter().enumerate() {
            if entry.lifecycle_bits() == 0 {
                per.entry(self.instance_of(entry, Some(*key)))
                    .or_default()
                    .push((
                        old.len() + i,
                        entry.has_source_ts().then_some(entry.timestamp_ns),
                    ));
            }
        }
        let mut replaced = std::collections::HashSet::new();
        for positions in per.values_mut() {
            if self.by_source_timestamp {
                positions.sort_unstable_by_key(|&(i, ts)| (ts, i));
            }
            for &(i, _) in positions.iter().rev().skip(depth) {
                if i < old.len() {
                    replaced.insert(i);
                }
            }
        }
        // Do not change history if even replacing all eligible old samples
        // cannot make the entire incoming set coexist in the ring.
        let fits = old.len() - replaced.len() + members.len() <= ring.usable_capacity();
        for (i, entry) in old.into_iter().enumerate() {
            if commit && fits && replaced.contains(&i) {
                self.release_dropped(&entry, pool);
            } else {
                assert!(ring.push(entry), "producer turn retains old ring positions");
            }
        }
        fits
    }

    fn never_holds_set(&self, members: &[(rt::IndexEntry, [u8; 16])]) -> Option<rt::NoRoom> {
        let room = self.room.as_ref()?;
        let instances: Vec<_> = members
            .iter()
            .filter(|(entry, _)| entry.lifecycle_bits() == 0)
            .map(|(entry, key)| Some(self.instance_of(entry, Some(*key))))
            .collect();
        room.never_holds(&instances).map(|bound| match bound {
            Bound::Instances => rt::NoRoom::Instances,
            Bound::SamplesPerInstance => rt::NoRoom::SamplesPerInstance,
            _ => rt::NoRoom::Samples,
        })
    }

    fn coherent_subscriber(&self) -> Option<usize> {
        self.bindings.upgrade()?.coherent_subscriber()
    }

    fn reserve_order(&self, publisher: u64, gsn: u64) -> Option<u64> {
        let bindings = self.bindings.upgrade()?;
        if bindings.is_closed() {
            return None;
        }
        let order = bindings.local_read_order()?;
        let token = order.reserve(Arc::as_ptr(&bindings) as usize, publisher, gsn);
        if bindings.is_closed() {
            order.cancel(token);
            None
        } else {
            Some(token)
        }
    }

    fn cancel_pending_order(&self, token: u64) {
        if let Some(bindings) = self.bindings.upgrade() {
            if let Some(order) = bindings.local_read_order() {
                order.cancel_pending(token);
            }
        }
    }

    fn record_order(&self, entry: &rt::IndexEntry, publisher: u64, gsn: u64) -> Option<u64> {
        let bindings = self.bindings.upgrade()?;
        if bindings.is_closed() {
            return None;
        }
        let order = bindings.local_read_order()?;
        let token = order.arrival(
            Arc::as_ptr(&bindings) as usize,
            entry.handle,
            publisher,
            gsn,
        );
        // Insertion before teardown is forgotten by it. Insertion after
        // forget_reader acquires its unlock, so this check sees closure.
        if bindings.is_closed() {
            order.cancel(token);
            None
        } else {
            Some(token)
        }
    }

    fn cancel_order(&self, token: u64) {
        if let Some(bindings) = self.bindings.upgrade() {
            if let Some(order) = bindings.local_read_order() {
                order.cancel(token);
            }
        }
    }

    fn counts(&self) -> bool {
        self.room.is_some()
    }

    /// The reader's open access bracket, when it is one of a GROUP-scope
    /// Subscriber (DDS v1.4 Sec.2.2.2.5.2.8): a local coherent set waits for
    /// it in the writer's coordinator (`local_group`).
    fn bracket_depth(&self) -> Option<u32> {
        self.bindings.upgrade()?.coherent_bracket_depth()
    }

    fn needs_instance(&self) -> bool {
        self.counted
    }

    fn reserve(
        &self,
        entry: &rt::IndexEntry,
        key: Option<[u8; 16]>,
    ) -> Result<[u8; 16], rt::NoRoom> {
        let Some(room) = self.room.as_ref() else {
            return Ok([0; 16]);
        };
        let instance = self.counted.then(|| self.instance_of(entry, key));
        let held = |key: &[u8; 16]| self.held_by_a_writer(key);
        let granted = if self.places {
            // The ring entry carries the place and the instance count from
            // here on (as `HistorySlot::into_ring` leaves them); the pump
            // hands them to the cached sample.
            room.reserve_in_ring(instance, held)
        } else {
            match instance {
                Some(instance) => room.reserve_instance(instance, held),
                None => Ok(()),
            }
        };
        match granted {
            Ok(()) => Ok(instance.unwrap_or([0; 16])),
            // A local sample is never held by a reorder gate: no headroom
            // is asked, and `GapHeadroom` does not come back.
            Err(Bound::Samples | Bound::GapHeadroom | Bound::Kept) => Err(rt::NoRoom::Samples),
            Err(Bound::Instances) => Err(rt::NoRoom::Instances),
            Err(Bound::SamplesPerInstance) => Err(rt::NoRoom::SamplesPerInstance),
        }
    }

    fn reserve_ordered(
        &self,
        entry: &rt::IndexEntry,
        key: Option<[u8; 16]>,
        publisher: u64,
        gsn: u64,
    ) -> Result<[u8; 16], rt::NoRoom> {
        let keep = self
            .bindings
            .upgrade()
            .and_then(|bindings| {
                bindings.local_read_order().map(|order| {
                    order.pending_before(Arc::as_ptr(&bindings) as usize, publisher, gsn)
                })
            })
            .unwrap_or(0);
        if keep == 0 {
            return self.reserve(entry, key);
        }
        let Some(room) = &self.room else {
            return Ok([0; 16]);
        };
        let instance = self.counted.then(|| self.instance_of(entry, key));
        let held = |key: &[u8; 16]| self.held_by_a_writer(key);
        let granted = if self.places {
            room.reserve_in_ring_ordered(keep, instance, held)
        } else if let Some(instance) = instance {
            room.reserve_instance_ordered(instance, keep, held)
        } else {
            Ok(())
        };
        match granted {
            Ok(()) => Ok(instance.unwrap_or([0; 16])),
            Err(Bound::Samples | Bound::GapHeadroom | Bound::Kept) => Err(rt::NoRoom::Samples),
            Err(Bound::Instances) => Err(rt::NoRoom::Instances),
            Err(Bound::SamplesPerInstance) => Err(rt::NoRoom::SamplesPerInstance),
        }
    }

    fn has_room_ordered(
        &self,
        entry: &rt::IndexEntry,
        key: Option<[u8; 16]>,
        publisher: u64,
        gsn: u64,
    ) -> bool {
        let keep = self
            .bindings
            .upgrade()
            .and_then(|bindings| {
                bindings.local_read_order().map(|order| {
                    order.pending_before(Arc::as_ptr(&bindings) as usize, publisher, gsn)
                })
            })
            .unwrap_or(0);
        if keep == 0 {
            return self.has_room(entry, key);
        }
        let Some(room) = &self.room else {
            return true;
        };
        (!self.places || room.has_place(keep))
            && (!self.counted
                || room.has_instance_room_ordered(&self.instance_of(entry, key), keep, |key| {
                    self.held_by_a_writer(key)
                }))
    }

    fn cancel(&self, key: [u8; 16]) {
        let Some(room) = self.room.as_ref() else {
            return;
        };
        if self.places {
            room.give_back(1);
        }
        if self.counted {
            room.release_instance(&key);
        }
    }

    fn has_room(&self, entry: &rt::IndexEntry, key: Option<[u8; 16]>) -> bool {
        let Some(room) = self.room.as_ref() else {
            return true;
        };
        if self.places && !room.has_place(0) {
            return false;
        }
        !self.counted
            || room.has_instance_room(&self.instance_of(entry, key), |key| {
                self.held_by_a_writer(key)
            })
    }

    fn waits(&self) -> bool {
        self.reliable
    }

    fn wait_while(&self, deadline: std::time::Instant, blocked: &mut dyn FnMut() -> bool) -> bool {
        self.wait.wait_while(deadline, blocked)
    }

    fn retry_when_room(
        &self,
        retry: Arc<dyn Fn() + Send + Sync>,
        blocked: &mut dyn FnMut() -> bool,
    ) {
        self.wait.retry_when_room(retry, blocked);
    }

    fn rejected(&self, why: rt::NoRoom, key: Option<[u8; 16]>) {
        if let Some(m) = crate::telemetry::get_metrics_opt() {
            m.increment_merge_full(1);
        }
        let reason = match why {
            rt::NoRoom::Samples => SampleRejectedReason::ResourceLimit,
            rt::NoRoom::Instances => SampleRejectedReason::InstanceLimit,
            rt::NoRoom::SamplesPerInstance => SampleRejectedReason::SamplesPerInstanceLimit,
        };
        let instance = key.filter(|_| T::has_key()).map(InstanceHandle::new);
        self.report.report(reason, instance);
    }
}

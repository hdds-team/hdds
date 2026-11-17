// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Whole-set admission for local coherent delivery. No reservation survives
//! a capacity wait, and no application notification runs under a guard.

use super::*;

/// Reader registration and the multi-merger replay snapshot share one cold
/// transition. No delivery or application callback runs while it is held.
pub(crate) fn lock_replay_cohort() -> std::sync::MutexGuard<'static, ()> {
    // @audit-ok: cold registration/replay exclusion token; protects no global data.
    static COHORT: std::sync::Mutex<()> = std::sync::Mutex::new(());
    COHORT.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) struct CoherentMember<'a> {
    pub merger: &'a TopicMerger,
    pub entry: IndexEntry,
    pub key: [u8; 16],
    pub wait: Option<&'a WriteDeadline>,
    pub target: Option<ReaderId>,
    pub gsn: Option<u64>,
    pub publisher: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CoherentResult {
    Delivered,
    Held,
    ReplayPending,
    Rejected,
}

struct Destination {
    reader: MergerReader,
    members: Vec<usize>,
    unit: (bool, usize),
    excluded: bool,
}

#[derive(Default)]
struct Reservations(Vec<(MergerReader, [u8; 16])>);

impl Reservations {
    fn cancel_reader(&mut self, id: ReaderId) {
        self.0.retain(|(reader, key)| {
            if reader.id() == id {
                reader.cancel(*key);
                false
            } else {
                true
            }
        });
    }
}

impl Drop for Reservations {
    fn drop(&mut self) {
        for (reader, key) in self.0.drain(..) {
            reader.cancel(key);
        }
    }
}

impl TopicMerger {
    pub(crate) fn readers_snapshot(&self) -> Vec<MergerReader> {
        let overflow = recover_read(&self.overflow_readers, "coherent snapshot");
        let n = self
            .inline_published
            .load(Ordering::Acquire)
            .min(INLINE_READERS);
        self.inline_readers[..n]
            .iter()
            .filter_map(OnceLock::get)
            .chain(overflow.iter())
            .filter(|r| r.is_active())
            .cloned()
            .collect()
    }

    /// The samples of a set that could not be stored for local delivery
    /// (`local_group::deliver_parts`): none reached a ring. Each reader of the
    /// cohort that formed the set would have taken each of them, and each is
    /// refused as a resource limit, reported, instead of vanishing with only a
    /// log line. `readers` is that cohort, not a fresh snapshot: a reader that
    /// joined after the set was formed never expected it. Content filters and
    /// ownership gates are not evaluated: a deferred sample has no storage to
    /// check them against, so a reader that would have filtered one out counts
    /// it too.
    pub(crate) fn refuse_unstored(readers: &[MergerReader], keys: &[[u8; 16]]) {
        for reader in readers.iter().filter(|reader| reader.is_active()) {
            if let Some(door) = reader.door.as_ref() {
                for key in keys {
                    door.rejected(NoRoom::Samples, Some(*key));
                }
            }
        }
    }

    /// The caller retains each member's slab claim until this returns.
    /// `Held` leaves the whole set queued until an access bracket ends.
    pub(crate) fn deliver_coherent(members: &[CoherentMember<'_>]) -> CoherentResult {
        let mut mergers: Vec<_> = members.iter().map(|m| m.merger).collect();
        mergers.sort_unstable_by_key(|m| *m as *const TopicMerger as usize);
        mergers.dedup_by_key(|m| *m as *const TopicMerger as usize);
        let snapshots: Vec<_> = {
            let _cohort = lock_replay_cohort();
            mergers
                .iter()
                .map(|merger| (*merger, merger.readers_snapshot()))
                .collect()
        };
        Self::deliver_coherent_to(members, snapshots)
    }

    pub(crate) fn deliver_coherent_to(
        members: &[CoherentMember<'_>],
        snapshots: Vec<(&TopicMerger, Vec<MergerReader>)>,
    ) -> CoherentResult {
        Self::deliver_coherent_to_with_completion(members, snapshots, || {})
    }

    pub(crate) fn deliver_coherent_to_with_completion(
        members: &[CoherentMember<'_>],
        snapshots: Vec<(&TopicMerger, Vec<MergerReader>)>,
        completed: impl FnOnce(),
    ) -> CoherentResult {
        if members.is_empty() {
            completed();
            return CoherentResult::Delivered;
        }
        #[cfg(test)]
        for member in members {
            member.merger.before_delivery(member.entry.seq);
        }
        let pool = super::super::get_slab_pool_ref();
        let order_floor = members
            .iter()
            .filter_map(|member| member.gsn.map(|gsn| (member.publisher, gsn)))
            .min_by_key(|(_, gsn)| *gsn);

        let mergers: Vec<_> = snapshots.iter().map(|(merger, _)| *merger).collect();
        // Filters run after the cohort lock and before producer turns.
        let mut destinations: Vec<Destination> = Vec::new();
        for (merger, readers) in snapshots {
            for reader in readers {
                let mut selected = Vec::new();
                for (i, member) in members.iter().enumerate() {
                    if std::ptr::eq(member.merger, merger)
                        && member.target.is_none_or(|id| id == reader.id())
                    {
                        if u64::from(member.entry.seq)
                            < reader.coherent.through.load(Ordering::Acquire)
                        {
                            continue;
                        }
                        if reader.passes_filter(&member.entry, pool) {
                            selected.push(i);
                        } else {
                            reader.acknowledge(member.entry.seq);
                        }
                    }
                }
                if !selected.is_empty() {
                    // Registration can finish after replay collection and
                    // before this live snapshot. Give the coordinator the
                    // live set back until that older history is presented.
                    if reader.coherent.replay_pending.load(Ordering::Acquire) != 0
                        && selected.iter().any(|&i| members[i].target.is_none())
                    {
                        return CoherentResult::ReplayPending;
                    }
                    let unit = reader
                        .door
                        .as_ref()
                        .and_then(|door| door.coherent_subscriber())
                        .map(|subscriber| (true, subscriber))
                        .unwrap_or_else(|| {
                            (
                                false,
                                reader.door.as_ref().map_or(reader.id().0, |door| {
                                    Arc::as_ptr(door) as *const () as usize
                                }),
                            )
                        });
                    destinations.push(Destination {
                        reader,
                        members: selected,
                        unit,
                        excluded: false,
                    });
                }
            }
        }
        loop {
            let attempt_notices = crate::dds::LocalDelivery::enter();
            // Every merger is acquired once, in the same order across
            // Publishers, including when several writers share a reader.
            let producers: Vec<_> = mergers.iter().map(|m| m.producer_turn()).collect();
            let mut reservations = Reservations::default();
            let mut admitted = vec![false; destinations.len()];
            let mut blocked = None;
            let mut impossible = false;
            for (destination_index, destination) in destinations.iter().enumerate() {
                let reader = &destination.reader;
                if destination.excluded || !reader.coherent.active.load(Ordering::Acquire) {
                    continue;
                }
                let entries: Vec<_> = destination
                    .members
                    .iter()
                    .map(|&i| (members[i].entry, members[i].key))
                    .collect();
                let history_entries: Vec<_> = destinations
                    .iter()
                    .filter(
                        |destination| match (&destination.reader.door, &reader.door) {
                            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                            _ => destination.reader.id() == reader.id(),
                        },
                    )
                    .flat_map(|destination| destination.members.iter())
                    .map(|&i| (members[i].entry, members[i].key))
                    .collect();
                if let Some(why) = reader
                    .door
                    .as_ref()
                    .and_then(|d| d.never_holds_set(&history_entries))
                {
                    blocked = Some((
                        reader.clone(),
                        destination.members[0],
                        why,
                        destination.unit,
                    ));
                    impossible = true;
                    break;
                }
                for &i in &destination.members {
                    let member = &members[i];
                    // `counting` is only set together with a door (`with_door`).
                    let counted = reader.counting && member.entry.lifecycle_bits() == 0;
                    debug_assert!(
                        !counted || reader.door.is_some(),
                        "a counting reader registration holds a door"
                    );
                    if let Some(door) = reader.door.as_ref().filter(|_| counted) {
                        let reservation = match order_floor {
                            Some((publisher, floor)) => door.reserve_ordered(
                                &member.entry,
                                Some(member.key),
                                publisher,
                                floor,
                            ),
                            None => door.reserve(&member.entry, Some(member.key)),
                        };
                        match reservation {
                            Ok(key) => reservations.0.push((reader.clone(), key)),
                            Err(why) => {
                                blocked = Some((reader.clone(), i, why, destination.unit));
                                break;
                            }
                        }
                    }
                }
                if blocked.is_some() {
                    break;
                }
                if reader
                    .ring
                    .usable_capacity()
                    .saturating_sub(reader.ring.len())
                    < entries.len()
                    && !reader
                        .door
                        .as_ref()
                        .is_some_and(|d| d.make_room_for_set(&reader.ring, &entries, false))
                {
                    blocked = Some((
                        reader.clone(),
                        destination.members[0],
                        NoRoom::Samples,
                        destination.unit,
                    ));
                    impossible = entries.len() > reader.ring.usable_capacity();
                    break;
                }
                admitted[destination_index] = true;
            }
            if let Some((reader, i, why, unit)) = blocked {
                // Cancel ALL previous members before waiting. Another
                // Publisher can now acquire the entire shared history.
                drop(reservations);
                drop(producers);
                drop(attempt_notices);
                let member = &members[i];
                let wait = member
                    .wait
                    .filter(|_| !impossible)
                    .filter(|_| reader.door.as_ref().is_some_and(|d| d.waits()));
                if let Some(wait) = wait {
                    #[cfg(any(test, feature = "test-support"))]
                    super::run_room_wait_hook();
                    let deadline = wait.instant();
                    let mut key = ResolvedKey::new(&no_key);
                    key.asked = Some(Some(member.key));
                    if std::time::Instant::now() < deadline
                        && reader.door.as_ref().is_some_and(|door| {
                            door.wait_while(deadline, &mut || {
                                reader.still_blocked(&member.entry, &mut key, order_floor)
                            })
                        })
                    {
                        continue;
                    }
                }
                // Refuse this Subscriber's entire set, without discarding
                // another Subscriber's independently admissible set.
                for destination in &mut destinations {
                    if destination.unit != unit {
                        continue;
                    }
                    destination.excluded = true;
                    if destination.reader.id() == reader.id()
                        || match (&destination.reader.door, &reader.door) {
                            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                            _ => false,
                        }
                    {
                        if let Some(door) = &destination.reader.door {
                            for &i in &destination.members {
                                let member = &members[i];
                                if member.entry.lifecycle_bits() == 0 {
                                    door.rejected(why, Some(member.key));
                                }
                            }
                        }
                    }
                }
                if destinations.iter().all(|destination| destination.excluded) {
                    completed();
                    return CoherentResult::Rejected;
                }
                continue;
            }
            let publication = crate::dds::coherent_publication::lock();
            if destinations
                .iter()
                .enumerate()
                .any(|(i, d)| admitted[i] && d.reader.bracket_depth().is_some_and(|n| n > 0))
            {
                return CoherentResult::Held;
            }
            for (i, destination) in destinations.iter().enumerate() {
                let reader = &destination.reader;
                if !admitted[i] {
                    continue;
                }
                if !reader.coherent.active.load(Ordering::Acquire) {
                    admitted[i] = false;
                    reservations.cancel_reader(reader.id());
                    continue;
                }
                if reader
                    .ring
                    .usable_capacity()
                    .saturating_sub(reader.ring.len())
                    < destination.members.len()
                {
                    let entries: Vec<_> = destination
                        .members
                        .iter()
                        .map(|&i| (members[i].entry, members[i].key))
                        .collect();
                    let ready = reader
                        .door
                        .as_ref()
                        .is_some_and(|door| door.make_room_for_set(&reader.ring, &entries, true));
                    if !ready {
                        assert!(
                            !reader.coherent.active.load(Ordering::Acquire)
                                || reader.door.as_ref().is_some_and(|door| door.is_closed()),
                            "planned ring positions remain available"
                        );
                        admitted[i] = false;
                        reservations.cancel_reader(reader.id());
                    }
                }
            }
            // All positions are accounted for while their sole producers
            // are held. Consumer progress can only create more room.
            for (i, member) in members.iter().enumerate() {
                for (d, destination) in destinations.iter().enumerate() {
                    if !admitted[d] || !destination.members.contains(&i) {
                        continue;
                    }
                    let reader = &destination.reader;
                    let reserved = reader.counting && member.entry.lifecycle_bits() == 0;
                    let mut key = ResolvedKey::new(&no_key);
                    key.asked = Some(Some(member.key));
                    let used = if reader.needs_instance {
                        member.key
                    } else {
                        [0; 16]
                    };
                    reader.active.store(
                        reader.coherent.active.load(Ordering::Acquire),
                        Ordering::Relaxed,
                    );
                    let mut order = reader.door.as_ref().and_then(|door| {
                        let token =
                            door.record_order(&member.entry, member.publisher, member.gsn?)?;
                        Some(OrderReservation {
                            door: door.as_ref(),
                            token,
                            committed: false,
                        })
                    });
                    let delivered = Self::deliver_one::<true>(
                        reader,
                        reserved,
                        used,
                        member.entry,
                        pool,
                        &mut key,
                        None,
                    );
                    if let Some(order) = order.as_mut() {
                        order.committed = delivered;
                    }
                    #[cfg(any(test, feature = "test-support"))]
                    crate::dds::writer::run_coherent_visible_hook();
                    if delivered {
                        reader
                            .coherent
                            .through
                            .fetch_max(u64::from(member.entry.seq) + 1, Ordering::Release);
                    }
                }
            }
            // Each reservation is now owned by an entry (or was cancelled
            // by deliver_one if the reader departed or its gate refused).
            reservations.0.clear();
            drop(publication);
            drop(producers);
            completed();
            return CoherentResult::Delivered;
        }
    }
}

/// Set identities and ordinary change GSNs are different numbering spaces.
/// These keys group replay batches; member GSNs determine their delivery order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CoherentReplayIdentity {
    Set(u64),
    Change(u64),
}

/// Snapshot references waiting for the next Subscriber access transition.
pub(crate) struct CoherentReplay {
    pub target: ReaderId,
    pub subscriber: Option<usize>,
    pub identity: CoherentReplayIdentity,
    pub members: Vec<ReplayMember>,
    pending: Arc<CoherentReaderState>,
}

pub(crate) struct ReplayMember {
    pub(super) _pending_order: Option<PendingOrderReservation>,
    pub coherent_replay_valid: Option<Arc<AtomicBool>>,
    pub coherent_replay_admission: Option<Arc<crate::reliability::CoherentReplayAdmission>>,
    pub entry: IndexEntry,
    pub key: [u8; 16],
    pub gsn: Option<u64>,
}

impl CoherentReplay {
    pub(super) fn new(reader: &MergerReader, identity: CoherentReplayIdentity) -> Self {
        reader
            .coherent
            .replay_pending
            .fetch_add(1, Ordering::AcqRel);
        Self {
            target: reader.id(),
            subscriber: reader
                .door
                .as_ref()
                .and_then(|door| door.coherent_subscriber()),
            identity,
            members: Vec::new(),
            pending: Arc::clone(&reader.coherent),
        }
    }
}

impl Drop for CoherentReplay {
    fn drop(&mut self) {
        let _notices = crate::dds::LocalDelivery::enter();
        let pool = super::super::get_slab_pool_ref();
        for member in &self.members {
            pool.release(member.entry.handle);
        }
        self.pending.replay_pending.fetch_sub(1, Ordering::AcqRel);
        // Withdraw every placeholder before any newly eligible reader is
        // notified. Automatic field drops would run after this notice scope.
        self.members.clear();
    }
}

impl TopicMerger {
    pub(crate) fn take_coherent_replay(&self) -> Vec<CoherentReplay> {
        std::mem::take(
            &mut *self
                .coherent_replay
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }

    pub(crate) fn hold_coherent_replay(&self, replay: CoherentReplay) {
        self.coherent_replay
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(replay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_reader_closed_during_capacity_commit_does_not_panic_or_block_its_peer() {
        struct Door {
            closes: bool,
            closed: AtomicBool,
            held: AtomicUsize,
        }
        impl ReaderDoor for Door {
            fn is_closed(&self) -> bool {
                self.closed.load(Ordering::Acquire)
            }
            fn counts(&self) -> bool {
                true
            }
            fn needs_instance(&self) -> bool {
                false
            }
            fn coherent_subscriber(&self) -> Option<usize> {
                Some(77)
            }
            fn make_room(&self, _: &IndexRing, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
                false
            }
            fn make_room_for_set(
                &self,
                _: &IndexRing,
                _: &[(IndexEntry, [u8; 16])],
                commit: bool,
            ) -> bool {
                if commit && self.closes {
                    // A real teardown closes bindings under the consumer gate
                    // before it can retire every merger registration.
                    self.closed.store(true, Ordering::Release);
                    false
                } else {
                    true
                }
            }
            fn reserve(&self, _: &IndexEntry, _: Option<[u8; 16]>) -> Result<[u8; 16], NoRoom> {
                self.held.fetch_add(1, Ordering::AcqRel);
                Ok([0; 16])
            }
            fn cancel(&self, _: [u8; 16]) {
                self.held.fetch_sub(1, Ordering::AcqRel);
            }
            fn has_room(&self, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
                true
            }
            fn rejected(&self, _: NoRoom, _: Option<[u8; 16]>) {}
            fn waits(&self) -> bool {
                false
            }
            fn wait_while(&self, _: std::time::Instant, _: &mut dyn FnMut() -> bool) -> bool {
                false
            }
        }
        let merger = TopicMerger::new();
        merger.enable_coherent_producer();
        let pool = super::super::super::get_slab_pool_ref();
        let retiring = Arc::new(IndexRing::with_capacity(4));
        for i in 0..retiring.usable_capacity() {
            let (handle, _) = pool.reserve_and_write(&[0], Claim::Writer).unwrap();
            assert!(retiring.push(IndexEntry::new(100 + i as u32, handle, 1)));
        }
        let survivor = Arc::new(IndexRing::with_capacity(4));
        let closing = Arc::new(Door {
            closes: true,
            closed: AtomicBool::new(false),
            held: AtomicUsize::new(0),
        });
        let live = Arc::new(Door {
            closes: false,
            closed: AtomicBool::new(false),
            held: AtomicUsize::new(0),
        });
        merger.add_reader(
            MergerReader::new(retiring.clone(), Arc::new(|| {})).with_door(Some(closing.clone())),
        );
        merger.add_reader(
            MergerReader::new(survivor.clone(), Arc::new(|| {})).with_door(Some(live.clone())),
        );
        let entries: Vec<_> = (1..=2)
            .map(|seq| {
                let (handle, _) = pool.reserve_and_write(&[seq as u8], Claim::Writer).unwrap();
                IndexEntry::new(seq, handle, 1)
            })
            .collect();
        let members: Vec<_> = entries
            .iter()
            .map(|&entry| CoherentMember {
                merger: &merger,
                entry,
                key: [0; 16],
                wait: None,
                target: None,
                gsn: None,
                publisher: 0,
            })
            .collect();
        assert_eq!(
            TopicMerger::deliver_coherent(&members),
            CoherentResult::Delivered
        );
        assert_eq!(
            closing.held.load(Ordering::Acquire),
            0,
            "removed reader kept history reservations"
        );
        assert_eq!(live.held.load(Ordering::Acquire), 2);
        let mut received = Vec::new();
        while let Some(entry) = survivor.pop() {
            received.push(entry.seq);
            live.cancel([0; 16]);
            pool.release(entry.handle);
        }
        assert_eq!(
            received,
            [1, 2],
            "a removed peer prevented complete delivery"
        );
        while let Some(entry) = retiring.pop() {
            assert!(entry.seq >= 100, "new data entered a closed reader");
            pool.release(entry.handle);
        }
        for entry in entries {
            pool.release(entry.handle);
        }
    }

    #[test]
    fn a_refused_delivery_cancels_its_exact_order_token() {
        struct Door(std::sync::Mutex<Vec<u64>>);
        impl ReaderDoor for Door {
            fn record_order(&self, _: &IndexEntry, _: u64, _: u64) -> Option<u64> {
                self.0.lock().unwrap().push(42);
                Some(42)
            }
            fn cancel_order(&self, token: u64) {
                assert_eq!(token, 42);
                self.0.lock().unwrap().retain(|&t| t != token);
            }
            fn counts(&self) -> bool {
                false
            }
            fn needs_instance(&self) -> bool {
                false
            }
            fn make_room(&self, _: &IndexRing, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
                false
            }
            fn reserve(&self, _: &IndexEntry, _: Option<[u8; 16]>) -> Result<[u8; 16], NoRoom> {
                Ok([0; 16])
            }
            fn cancel(&self, _: [u8; 16]) {}
            fn has_room(&self, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
                true
            }
            fn rejected(&self, _: NoRoom, _: Option<[u8; 16]>) {}
            fn waits(&self) -> bool {
                false
            }
            fn wait_while(&self, _: std::time::Instant, _: &mut dyn FnMut() -> bool) -> bool {
                false
            }
        }
        let merger = TopicMerger::new();
        let ring = Arc::new(IndexRing::with_capacity(4));
        let door = Arc::new(Door(std::sync::Mutex::new(Vec::new())));
        merger.add_reader(
            MergerReader::new(ring.clone(), Arc::new(|| {}))
                .with_door(Some(door.clone()))
                .gated(Some(Arc::new(|_, _, _| false))),
        );
        let pool = super::super::super::get_slab_pool_ref();
        let (handle, _) = pool.reserve_and_write(&[0; 4], Claim::Writer).unwrap();
        let members = [CoherentMember {
            merger: &merger,
            entry: IndexEntry::new(1, handle, 4),
            key: [0; 16],
            wait: None,
            target: None,
            gsn: Some(1),
            publisher: 1,
        }];
        assert_eq!(
            TopicMerger::deliver_coherent(&members),
            CoherentResult::Delivered
        );
        assert!(ring.is_empty());
        assert!(
            door.0.lock().unwrap().is_empty(),
            "refused member retained an order token"
        );
        pool.release(handle);
    }

    #[test]
    fn an_ordinary_group_observer_runs_after_its_producer_turn() {
        let merger = Arc::new(TopicMerger::new());
        merger.set_local_group_wake(Arc::new(|| {}));
        let weak = Arc::downgrade(&merger);
        let observed = Arc::new(AtomicBool::new(false));
        let result = observed.clone();
        let observer = DeliveryObserver::new(
            Arc::new(AtomicU32::new(1)),
            1,
            Box::new(move |_, _| {
                let merger = weak.upgrade().unwrap();
                let (done, waited) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let _turn = merger.producer_turn();
                    done.send(()).unwrap();
                });
                result.store(
                    waited.recv_timeout(Duration::from_secs(1)).is_ok(),
                    Ordering::SeqCst,
                );
            }),
        )
        .deferring(crate::dds::notify_local);
        let ring = Arc::new(IndexRing::with_capacity(4));
        merger.add_reader(
            MergerReader::new(ring.clone(), Arc::new(|| {})).observed(Some(Arc::new(observer))),
        );
        let pool = super::super::super::get_slab_pool_ref();
        let (handle, _) = pool.reserve_and_write(&[0; 4], Claim::Writer).unwrap();
        let entry = IndexEntry::new(1, handle, 4);
        let admission = merger.admit(&entry, pool, &no_key, None).unwrap();
        assert!(merger.deliver(
            admission,
            entry,
            pool,
            &no_key,
            None,
            PendingOrders::default()
        ));
        assert!(
            observed.load(Ordering::SeqCst),
            "observer retained the producer turn"
        );
        pool.release(ring.pop().unwrap().handle);
    }

    #[test]
    fn coherent_replay_does_not_deliver_the_same_writer_change_twice() {
        let merger = TopicMerger::new();
        merger.enable_coherent_producer();
        let ring = Arc::new(IndexRing::with_capacity(4));
        merger.add_reader(MergerReader::new(ring.clone(), Arc::new(|| {})));
        let pool = super::super::super::get_slab_pool_ref();
        let (handle, _) = pool.reserve_and_write(&[0; 4], Claim::Writer).unwrap();
        let members = [CoherentMember {
            merger: &merger,
            entry: IndexEntry::new(1, handle, 4),
            key: [0; 16],
            wait: None,
            target: None,
            gsn: Some(1),
            publisher: 1,
        }];
        assert_eq!(
            TopicMerger::deliver_coherent(&members),
            CoherentResult::Delivered
        );
        assert_eq!(
            TopicMerger::deliver_coherent(&members),
            CoherentResult::Delivered
        );
        assert_eq!(
            ring.len(),
            1,
            "live and replay share a committed delivery cursor"
        );
        pool.release(handle);
        pool.release(ring.pop().unwrap().handle);
    }

    /// Two Publishers can each fit alone. Force both first reservations
    /// before either second one, then require rollback before either wait.
    #[test]
    fn two_publishers_release_their_entire_reservations_before_waiting() {
        #[derive(Default)]
        struct Held {
            total: usize,
            keys: std::collections::HashMap<[u8; 16], usize>,
            threads: std::collections::HashMap<std::thread::ThreadId, [u8; 16]>,
        }
        struct Door {
            held: std::sync::Mutex<Held>,
            wake: std::sync::Condvar,
            first: std::sync::Barrier,
        }
        impl ReaderDoor for Door {
            fn counts(&self) -> bool {
                true
            }
            fn needs_instance(&self) -> bool {
                true
            }
            fn make_room(&self, _: &IndexRing, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
                false
            }
            fn reserve(&self, _: &IndexEntry, key: Option<[u8; 16]>) -> Result<[u8; 16], NoRoom> {
                let key = key.unwrap();
                let mut held = self.held.lock().unwrap();
                if held.total == 2 {
                    return Err(NoRoom::Samples);
                }
                held.total += 1;
                *held.keys.entry(key).or_default() += 1;
                let first = held
                    .threads
                    .insert(std::thread::current().id(), key)
                    .is_none();
                drop(held);
                if first {
                    self.first.wait();
                }
                Ok(key)
            }
            fn cancel(&self, key: [u8; 16]) {
                let mut held = self.held.lock().unwrap();
                held.total -= 1;
                *held.keys.get_mut(&key).unwrap() -= 1;
                self.wake.notify_all();
            }
            fn has_room(&self, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
                self.held.lock().unwrap().total < 2
            }
            fn rejected(&self, _: NoRoom, _: Option<[u8; 16]>) {}
            fn waits(&self) -> bool {
                true
            }
            fn wait_while(
                &self,
                deadline: std::time::Instant,
                blocked: &mut dyn FnMut() -> bool,
            ) -> bool {
                let held = self.held.lock().unwrap();
                let key = held.threads[&std::thread::current().id()];
                let retained = held.keys[&key];
                drop(held);
                assert_eq!(
                    retained, 0,
                    "a waiting Publisher retained a member reservation"
                );
                // The real RoomWait uses its own wake mutex. Polling is not
                // necessary here: the shared count and wake are checked
                // together; blocked is checked outside that count lock.
                if !blocked() {
                    return true;
                }
                let held = self.held.lock().unwrap();
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                let (held, timeout) = self
                    .wake
                    .wait_timeout_while(held, remaining, |held| held.total == 2)
                    .unwrap();
                !timeout.timed_out() || held.total < 2
            }
        }
        let door = Arc::new(Door {
            held: std::sync::Mutex::new(Held::default()),
            wake: std::sync::Condvar::new(),
            first: std::sync::Barrier::new(2),
        });
        let mut rings = Vec::new();
        let (done, results) = std::sync::mpsc::channel();
        for key in [1u8, 2] {
            let merger = Arc::new(TopicMerger::new());
            merger.set_local_group_wake(Arc::new(|| {}));
            let ring = Arc::new(IndexRing::with_capacity(4));
            merger.add_reader(
                MergerReader::new(ring.clone(), Arc::new(|| {})).with_door(Some(door.clone())),
            );
            rings.push((ring, [key; 16]));
            let done = done.clone();
            std::thread::spawn(move || {
                let pool = super::super::super::get_slab_pool_ref();
                let deadline = WriteDeadline::new(Duration::from_secs(2));
                let entries: Vec<_> = (1..=2)
                    .map(|seq| {
                        let (slab, _) = pool.reserve_and_write(&[key; 4], Claim::Writer).unwrap();
                        IndexEntry::new(seq, slab, 4)
                    })
                    .collect();
                let members: Vec<_> = entries
                    .iter()
                    .map(|&entry| CoherentMember {
                        merger: &merger,
                        entry,
                        key: [key; 16],
                        wait: Some(&deadline),
                        target: None,
                        gsn: None,
                        publisher: u64::from(key),
                    })
                    .collect();
                let result = TopicMerger::deliver_coherent(&members);
                for entry in entries {
                    pool.release(entry.handle);
                }
                done.send((key, result)).unwrap();
            });
        }
        let pool = super::super::super::get_slab_pool_ref();
        for _ in 0..2 {
            let (key, result) = results.recv_timeout(Duration::from_secs(3)).unwrap();
            assert_eq!(result, CoherentResult::Delivered);
            let mut count = 0;
            let ring = &rings[usize::from(key - 1)].0;
            while let Some(entry) = ring.pop() {
                count += 1;
                door.cancel([key; 16]);
                pool.release(entry.handle);
            }
            assert_eq!(count, 2, "one entire Publisher set was delivered");
        }
    }

    /// A door that counts the refusals it is told of.
    struct Refusals(Arc<std::sync::atomic::AtomicUsize>);
    impl ReaderDoor for Refusals {
        fn make_room(&self, _: &IndexRing, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
            false
        }
        fn counts(&self) -> bool {
            false
        }
        fn needs_instance(&self) -> bool {
            false
        }
        fn reserve(&self, _: &IndexEntry, _: Option<[u8; 16]>) -> Result<[u8; 16], NoRoom> {
            Err(NoRoom::Samples)
        }
        fn cancel(&self, _: [u8; 16]) {}
        fn has_room(&self, _: &IndexEntry, _: Option<[u8; 16]>) -> bool {
            false
        }
        fn rejected(&self, _why: NoRoom, _key: Option<[u8; 16]>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn waits(&self) -> bool {
            false
        }
        fn wait_while(&self, _: std::time::Instant, _: &mut dyn FnMut() -> bool) -> bool {
            false
        }
    }

    /// A set that could not be stored is refused by the readers of the cohort
    /// that formed it, and by no reader that joined after.
    #[test]
    fn a_refusal_of_unstored_samples_reaches_only_the_cohort() {
        let merger = TopicMerger::new();
        let cohort_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let late_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cohort_door: Arc<dyn ReaderDoor> = Arc::new(Refusals(Arc::clone(&cohort_count)));
        let late_door: Arc<dyn ReaderDoor> = Arc::new(Refusals(Arc::clone(&late_count)));
        merger.add_reader(
            MergerReader::new(Arc::new(IndexRing::with_capacity(4)), Arc::new(|| {}))
                .with_door(Some(cohort_door)),
        );
        let cohort = merger.readers_snapshot();
        merger.add_reader(
            MergerReader::new(Arc::new(IndexRing::with_capacity(4)), Arc::new(|| {}))
                .with_door(Some(late_door)),
        );
        TopicMerger::refuse_unstored(&cohort, &[[1; 16], [2; 16]]);
        assert_eq!(
            cohort_count.load(Ordering::SeqCst),
            2,
            "the cohort counts both"
        );
        assert_eq!(
            late_count.load(Ordering::SeqCst),
            0,
            "a late reader counts none"
        );
    }
}

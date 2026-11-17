// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Publisher-wide local (intra-process) delivery of coherent sets (DDS v1.4
//! Sec.2.2.2.4.1.10 `end_coherent_changes`, Sec.2.2.3.6 PRESENTATION
//! coherent_access, GROUP access scope; RTPS v2.5 Sec.8.7.5/8.7.6).
//!
//! A coherent set spans every DataWriter of the Publisher: the changes of
//! all of them, made between one `begin_coherent_changes` and its
//! `end_coherent_changes`, are one set. A co-located reader must therefore
//! not be handed writer A's part before writer B's part exists. Each
//! writer's own queue (`intra_coherent`, per writer) only knows its own
//! part: it holds it until its own stamps stage or withdraw, and hands it
//! here.
//!
//! The Publisher's coordinator collects one part per writer of the set and
//! delivers the whole group at once, into the readers' rings, when:
//!
//! * every writer of the set reported (a writer with no change reports an
//!   empty part: the close visits all of them, `Publisher::end`,
//!   RTPS v2.5 Sec.8.7.6 "every writer ends the set"), in set order;
//! * and no reader that would receive it is inside a GROUP access bracket
//!   (`coherent_publication`): a bracketed read sees the set whole or not
//!   at all, and a set that completes during a bracket is delivered when
//!   it ends, before the next bracket's first read.
//!
//! Admission is a whole-set transaction (`TopicMerger::deliver_coherent`).
//! It reserves the relevant members of each Subscriber together, releases
//! every reservation before waiting, and refuses an unadmittable set for
//! that Subscriber without losing another Subscriber's independently
//! admissible set. RELIABLE writers share one bounded deadline; a
//! BEST_EFFORT refusal cannot become a partial set (DDS v1.4 Sec.2.2.3.14,
//! Sec.2.2.3.19; RTPS v2.5 Sec.8.7.6).
//!
//! Listener, observer and WaitSet callbacks are deferred until publication,
//! producer and retry guards have all been released (`notices::Delivering`).
//! A callback can therefore open an access bracket or write again.
//!
//! Nothing here runs for a Publisher of another access scope, nor for a
//! writer without a Publisher: those keep the per-writer delivery of
//! `intra_coherent`.

use super::intra_coherent::StagedIntraSample;
use crate::core::rt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// One writer's share of a coherent set.
pub(super) struct GroupPart {
    pub(super) merger: Arc<rt::TopicMerger>,
    pub(super) members: Vec<StagedIntraSample>,
    /// The writer's `max_blocking_time`, and whether it waits for room.
    pub(super) max_blocking_time: Duration,
    pub(super) reliable: bool,
    pub(super) completion: Option<GroupCompletion>,
}

pub(super) struct GroupCompletion {
    pub(super) stream: Arc<super::intra_coherent::IntraCoherentSets>,
    pub(super) epoch: u64,
}

impl GroupPart {
    /// The slab claims of the members never delivered.
    fn release(self) {
        drop(self.members);
        if let Some(completion) = self.completion {
            completion.stream.finish(completion.epoch);
        }
    }
}

/// The writers of one set that have yet to report, and the parts reported.
struct Expected {
    missing: Vec<u64>,
    parts: Vec<GroupPart>,
}

#[derive(Default)]
struct SetsState {
    /// Sets opened by `begin_coherent_changes`, by set identity, until
    /// every writer of the Publisher reported its part.
    expecting: BTreeMap<u64, Expected>,
    /// Sets every writer reported, by set identity, awaiting delivery.
    ready: BTreeMap<u64, Vec<GroupPart>>,
    delivering: bool,
    retry: bool,
}

/// The coherent sets of one GROUP Publisher, delivered as wholes.
pub(crate) struct LocalGroupSets {
    state: Mutex<SetsState>,
    /// Writer slots handed out (`IntraCoherentSets::slot`): a writer's
    /// identity within its Publisher, for this coordinator only.
    next_slot: AtomicU64,
    identity: u64,
    mergers: Mutex<Vec<std::sync::Weak<rt::TopicMerger>>>,
    streams: Mutex<Vec<Arc<super::intra_coherent::IntraCoherentSets>>>,
    replay_integrity: Arc<crate::reliability::CoherentReplayIntegrity>,
}

struct DeliveryOwner<'a>(&'a LocalGroupSets);

impl Drop for DeliveryOwner<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.lock().delivering = false;
        }
    }
}

impl LocalGroupSets {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self {
            state: Mutex::new(SetsState::default()),
            next_slot: AtomicU64::new(1),
            identity: NEXT.fetch_add(1, Ordering::Relaxed),
            mergers: Mutex::new(Vec::new()),
            streams: Mutex::new(Vec::new()),
            replay_integrity: Arc::new(crate::reliability::CoherentReplayIntegrity::default()),
        }
    }

    pub(crate) fn identity(&self) -> u64 {
        self.identity
    }

    pub(crate) fn replay_integrity(&self) -> Arc<crate::reliability::CoherentReplayIntegrity> {
        Arc::clone(&self.replay_integrity)
    }

    pub(crate) fn register_merger(&self, merger: &Arc<rt::TopicMerger>) {
        self.mergers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::downgrade(merger));
    }

    pub(super) fn update_stream(&self, stream: Arc<super::intra_coherent::IntraCoherentSets>) {
        #[cfg(any(test, feature = "test-support"))]
        super::run_stream_retention_hook();
        // Registry then queue. Enqueuers release the queue before entering
        // here; a stale empty observation cannot remove a newer hold.
        let mut streams = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        let pending = stream.has_queued_changes();
        if pending {
            if !streams.iter().any(|held| Arc::ptr_eq(held, &stream)) {
                streams.push(stream);
            }
        } else {
            streams.retain(|held| !Arc::ptr_eq(held, &stream));
        }
    }

    fn release_streams(&self) {
        let streams = std::mem::take(&mut *self.streams.lock().unwrap_or_else(|e| e.into_inner()));
        for stream in streams {
            stream.deliver_ready();
        }
    }

    fn release_replay(&self) {
        let mergers: Vec<_> = self
            .mergers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect();
        let mut sets: BTreeMap<rt::CoherentReplayIdentity, Vec<(usize, rt::CoherentReplay)>> =
            BTreeMap::new();
        {
            let _cohort = rt::lock_replay_cohort();
            for (i, merger) in mergers.iter().enumerate() {
                for replay in merger.take_coherent_replay() {
                    sets.entry(replay.identity).or_default().push((i, replay));
                }
            }
        }
        // Keep a set whole across writers and readers, then place that
        // batch by its first member's GSN among ordinary changes.
        let mut batches: Vec<_> = sets.into_iter().collect();
        batches.sort_by_key(|(_, replays)| {
            replays
                .iter()
                .flat_map(|(_, replay)| &replay.members)
                .filter_map(|member| member.gsn)
                .min()
        });
        let mut blocked = false;
        for (identity, mut replays) in batches {
            if blocked {
                for (i, replay) in replays {
                    mergers[i].hold_coherent_replay(replay);
                }
                continue;
            }
            // A set still owned by the live collector is delivered by it,
            // with every outstanding stamped write, to these registrations.
            // A history snapshot taken before its last stage may be only a
            // prefix, even when an ECS has already been journaled.
            let live = match identity {
                rt::CoherentReplayIdentity::Set(generation) => {
                    let state = self.lock();
                    state.expecting.contains_key(&generation)
                        || state.ready.contains_key(&generation)
                }
                rt::CoherentReplayIdentity::Change(_) => false,
            };
            if live {
                continue;
            }
            if replays.iter().any(|(_, replay)| {
                replay.members.iter().any(|sample| {
                    sample
                        .coherent_replay_valid
                        .as_ref()
                        .is_some_and(|valid| !valid.load(Ordering::Acquire))
                })
            }) {
                continue;
            }
            // Departure ends future replay admission. Only a Subscriber that
            // already owns every distinct member may publish its composite;
            // another Subscriber's snapshots cannot supply its missing part.
            let mut coverage = std::collections::HashMap::new();
            for (_, replay) in &replays {
                let scope = (
                    replay.subscriber,
                    replay.subscriber.is_none().then_some(replay.target),
                );
                for member in &replay.members {
                    if let Some(admission) = &member.coherent_replay_admission {
                        let key = (scope, Arc::as_ptr(admission) as usize);
                        let (_, members) = coverage.entry(key).or_insert_with(|| {
                            (Arc::clone(admission), std::collections::HashSet::new())
                        });
                        if let Some(gsn) = member.gsn {
                            members.insert(gsn);
                        }
                    }
                }
            }
            let incomplete: std::collections::HashSet<_> = coverage
                .into_iter()
                .filter_map(|((scope, _), (admission, members))| {
                    (!admission.permits_captured(members.len())).then_some(scope)
                })
                .collect();
            replays.retain(|(_, replay)| {
                !incomplete.contains(&(
                    replay.subscriber,
                    replay.subscriber.is_none().then_some(replay.target),
                ))
            });
            let mut members = Vec::new();
            for (i, replay) in &replays {
                for sample in &replay.members {
                    members.push(rt::CoherentMember {
                        merger: &mergers[*i],
                        entry: sample.entry,
                        key: sample.key,
                        wait: None,
                        target: Some(replay.target),
                        gsn: sample.gsn,
                        publisher: self.identity,
                    });
                }
            }
            members.sort_by_key(|member| member.gsn);
            let held = rt::TopicMerger::deliver_coherent(&members) == rt::CoherentResult::Held;
            drop(members);
            if held {
                blocked = true;
                for (i, replay) in replays {
                    mergers[i].hold_coherent_replay(replay);
                }
            }
        }
    }

    /// A fresh writer slot, never reused: a writer built after a set
    /// closed still reports under an identity of its own.
    pub(crate) fn writer_slot(&self) -> u64 {
        self.next_slot.fetch_add(1, Ordering::Relaxed)
    }

    fn lock(&self) -> MutexGuard<'_, SetsState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The Publisher opened set `generation`: `slots` are its writers, and
    /// it is complete once each of them reported a part. Called under the
    /// Publisher's set lock, with the writers it holds for the set.
    pub(crate) fn expect(&self, generation: u64, slots: Vec<u64>) {
        if slots.is_empty() {
            return;
        }
        self.lock().expecting.insert(
            generation,
            Expected {
                missing: slots,
                parts: Vec::new(),
            },
        );
    }

    /// Writer `slot` reported its part of set `generation`: its members,
    /// empty for a writer with no change in the set. A part reported for a
    /// set this Publisher does not expect (a writer of another Publisher,
    /// or one built after the set opened) is given back at once.
    pub(super) fn report(&self, generation: u64, slot: u64, part: GroupPart) {
        let completed = {
            let mut state = self.lock();
            match state.expecting.get_mut(&generation) {
                Some(expected) => {
                    expected.missing.retain(|s| *s != slot);
                    expected.parts.push(part);
                    if expected.missing.is_empty() {
                        // The set was matched above, so `remove` finds it.
                        let removed = state.expecting.remove(&generation);
                        debug_assert!(removed.is_some(), "a matched set is still expected");
                        match removed {
                            Some(expected) => {
                                self.replay_integrity.complete(generation);
                                state.ready.insert(generation, expected.parts);
                                true
                            }
                            None => {
                                log::error!("coherent set {generation} vanished before completion");
                                false
                            }
                        }
                    } else {
                        false
                    }
                }
                None => {
                    // A writer of no set this Publisher opened cannot
                    // happen: a writer cannot join a Publisher while a set
                    // is open (`PublisherCore::add_writer`), and only the
                    // writers it held report. Loud, not silent, in case a
                    // future path breaks that.
                    log::warn!(
                        "[writer-coherent] a writer reported a part for coherent set \
                         {generation}, which its Publisher does not expect; the part \
                         is dropped"
                    );
                    drop(state);
                    part.release();
                    false
                }
            }
        };
        if completed {
            self.release_ready();
        }
    }

    /// Deliver complete sets in Publisher order. A concurrent completion
    /// marks a retry for the current owner instead of waiting under a lock.
    /// A bracket leaves its sets queued until end_access retries them.
    pub(crate) fn release_ready(&self) {
        {
            let mut state = self.lock();
            if state.delivering {
                state.retry = true;
                return;
            }
            state.delivering = true;
        }
        let _owner = DeliveryOwner(self);
        loop {
            self.release_replay();
            self.release_streams();
            #[cfg(any(test, feature = "test-support"))]
            super::run_group_delivery_hook();
            // A set is deliverable when no earlier one is still missing a
            // writer's part: source order is the set identity's order.
            let Some(generation) = ({
                let state = self.lock();
                let earliest = state.expecting.keys().next().copied();
                match state.ready.keys().next().copied() {
                    Some(ready) if earliest.is_none_or(|open| ready < open) => Some(ready),
                    _ => None,
                }
            }) else {
                let mut state = self.lock();
                if std::mem::take(&mut state.retry) {
                    continue;
                }
                state.delivering = false;
                return;
            };
            // Cheap first: a set a reader's access bracket already holds
            // back takes no room in any reader, and waits for none.
            if self.held_by_bracket(generation) {
                let mut state = self.lock();
                if std::mem::take(&mut state.retry) {
                    continue;
                }
                state.delivering = false;
                return;
            }
            let Some(parts) = self.lock().ready.remove(&generation) else {
                continue;
            };
            let (result, parts) = deliver_parts(parts, self.identity);
            if result == rt::CoherentResult::ReplayPending {
                self.lock().ready.insert(generation, parts);
                continue;
            }
            if result == rt::CoherentResult::Held {
                let mut state = self.lock();
                state.ready.insert(generation, parts);
                if std::mem::take(&mut state.retry) {
                    continue;
                }
                state.delivering = false;
                return;
            }
            debug_assert!(parts.is_empty(), "final delivery retired every part");
        }
    }

    /// Whether a reader that would receive set `generation` is inside an
    /// access bracket (`coherent_publication`).
    fn held_by_bracket(&self, generation: u64) -> bool {
        let _publication = crate::dds::coherent_publication::lock();
        let state = self.lock();
        state
            .ready
            .get(&generation)
            .is_some_and(|parts| parts.iter().any(|part| part.merger.coherent_brackets().1))
    }
}

fn release_parts(parts: Vec<GroupPart>) {
    let _notices = crate::dds::LocalDelivery::enter();
    for part in parts {
        part.release();
    }
}

/// One attempt reserves the entire set or returns every reservation before
/// waiting. Both GROUP and per-writer coherent delivery use this transaction.
pub(super) fn deliver_parts(
    parts: Vec<GroupPart>,
    publisher: u64,
) -> (rt::CoherentResult, Vec<GroupPart>) {
    let deadline = rt::WriteDeadline::new(
        parts
            .iter()
            .filter(|p| p.reliable && !p.members.is_empty())
            .map(|p| p.max_blocking_time)
            .min()
            .unwrap_or(Duration::ZERO),
    );
    // Transaction references outlive part retirement, which must precede
    // application callbacks so source slab claims and writer fences are gone.
    let mergers: Vec<_> = parts.iter().map(|part| Arc::clone(&part.merger)).collect();
    let cohort = rt::lock_replay_cohort();
    let mut snapshots: Vec<_> = mergers
        .iter()
        .map(|merger| (merger.as_ref(), merger.readers_snapshot()))
        .collect();
    snapshots.sort_unstable_by_key(|(merger, _)| *merger as *const rt::TopicMerger as usize);
    snapshots.dedup_by_key(|(merger, _)| *merger as *const rt::TopicMerger as usize);
    if snapshots.iter().all(|(_, readers)| readers.is_empty()) {
        drop(cohort);
        release_parts(parts);
        return (rt::CoherentResult::Delivered, Vec::new());
    }
    let mut members = Vec::new();
    let mut complete = true;
    'parts: for (index, part) in parts.iter().enumerate() {
        if snapshots
            .iter()
            .find(|(merger, _)| std::ptr::eq(*merger, part.merger.as_ref()))
            .is_none_or(|(_, readers)| readers.is_empty())
        {
            continue;
        }
        for member in &part.members {
            let Some(entry) = member.local_entry() else {
                complete = false;
                break 'parts;
            };
            members.push(rt::CoherentMember {
                merger: &mergers[index],
                entry,
                key: member.key_hash,
                wait: part.reliable.then_some(&deadline),
                target: None,
                gsn: member.gsn,
                publisher,
            });
        }
    }
    drop(cohort);
    if !complete {
        log::warn!("[writer-coherent] local storage cannot represent the complete set; no local member is published");
        // Nothing reaches a ring: each reader refuses the samples it would have
        // taken, reported, rather than losing them unannounced.
        let _notices = crate::dds::LocalDelivery::enter();
        for part in &parts {
            let keys: Vec<[u8; 16]> = part
                .members
                .iter()
                .filter_map(StagedIntraSample::sample_key)
                .collect();
            if !keys.is_empty() {
                let cohort = snapshots
                    .iter()
                    .find(|(merger, _)| std::ptr::eq(*merger, part.merger.as_ref()))
                    .map_or(&[][..], |(_, readers)| readers.as_slice());
                rt::TopicMerger::refuse_unstored(cohort, &keys);
            }
        }
        release_parts(parts);
        return (rt::CoherentResult::Rejected, Vec::new());
    }
    members.sort_by_key(|member| member.gsn);
    let owned = std::cell::RefCell::new(Some(parts));
    let result = rt::TopicMerger::deliver_coherent_to_with_completion(&members, snapshots, || {
        let parts = owned.borrow_mut().take().unwrap_or_default();
        release_parts(parts);
    });
    (result, owned.into_inner().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use crate::core::rt;
    use crate::{Participant, QoS, TransportMode};
    use std::sync::Arc;

    #[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
    struct Item {
        value: i32,
    }

    /// Fill a private slab pool until it refuses a sample, so that the
    /// deferred members of a set cannot be materialized for local delivery.
    /// Fill the storage a member of this test needs: its 8-byte CDR payload
    /// class, then the large class, until each refuses a sample.
    fn exhaust(pool: &rt::SlabPool) {
        for size in [8usize, 4096] {
            let payload = vec![0u8; size];
            let mut full = false;
            for _ in 0..200_000 {
                if pool
                    .reserve_and_write(&payload, rt::Claim::Writer)
                    .is_none()
                {
                    full = true;
                    break;
                }
            }
            assert!(full, "the private slab pool never ran out at {size} bytes");
        }
        assert!(
            pool.reserve_and_write(&[0u8; 8], rt::Claim::Writer)
                .is_none(),
            "an 8-byte sample still finds room"
        );
    }

    /// A complete GROUP set whose members have no slab room at delivery is
    /// not published locally, and each of its readers counts its refusal:
    /// nothing vanishes unannounced (the remote side received it all).
    #[test]
    fn a_set_with_no_local_storage_is_refused_and_reported() {
        let policy = crate::qos::MemoryPolicy {
            max_heap_bytes: 1024 * 1024,
            reader_reserve_percent: 0,
            ..crate::qos::MemoryPolicy::default()
        };

        let qos = QoS::reliable()
            .transient_local()
            .keep_all()
            .presentation_group_coherent();
        let participant = Participant::builder("unstored-group-set")
            .domain_id(0)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic_a = participant.topic::<Item>("unstored-group-set-a").unwrap();
        let topic_b = participant.topic::<Item>("unstored-group-set-b").unwrap();
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let writer_a = topic_a
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let writer_b = topic_b
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        // The readers come after the writes: a write made with no co-located
        // reader is staged deferred (materialized only at delivery), while one
        // made with a reader is stored at once and needs no room later.
        publisher.begin_coherent_changes().unwrap();
        writer_a.write(&Item { value: 1 }).unwrap();
        writer_b.write(&Item { value: 2 }).unwrap();
        let reader_a = topic_a.reader().qos(qos.clone()).build().unwrap();
        let reader_b = topic_b.reader().qos(qos.clone()).build().unwrap();
        let (pool, guard) = rt::owned_private_slab_pool_for_test(&policy);
        exhaust(pool);
        publisher.end_coherent_changes().unwrap();
        drop(guard);

        for (name, reader) in [("reader a", &reader_a), ("reader b", &reader_b)] {
            let status = reader.get_sample_rejected_status();
            assert_eq!(
                status.total_count, 1,
                "{name} must count the member it was not given: {status:?}"
            );
            assert_eq!(
                status.last_reason,
                crate::dds::SampleRejectedReason::ResourceLimit,
                "{name}"
            );
        }
    }
}

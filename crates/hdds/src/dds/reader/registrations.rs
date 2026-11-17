// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Which remote DataWriters are writing each instance, as one reader sees
//! them.
//!
//! DDS v1.4 Sec.2.2.2.4.2.7 (unregister_instance): "DataReader entities that
//! are reading the instance will eventually receive a sample with a
//! NOT_ALIVE_NO_WRITERS instance state if no other DataWriter entities are
//! writing the instance." Sec.2.2.3.23.3: "Deleting a DataWriter is
//! equivalent to unregistering all the instances it was writing, but is not
//! the same as 'disposing' all the instances." So the question a reader must
//! answer, on an unregister and on a writer's departure, is which writers
//! still hold the instance REGISTERED - not which ever wrote it.
//!
//! A writer registers an instance by writing it (registration "can be done
//! lazily the first time the DataWriter writes the instance", Sec.2.2.3.23.1.2)
//! and gives it up by unregistering it. A dispose does not unregister
//! (Sec.2.2.2.4.2.13, Sec.2.2.3.23.3), so it changes nothing here.
//!
//! Every applied change is placed by its writerSN. The network reorder
//! gate orders samples and lifecycle changes; a delayed change through
//! another path still must not hand an instance back to a writer that let
//! it go. A writer's standing therefore keeps the sequence number of the
//! change that set it, and only a later change moves it. Legacy alias
//! metadata retained before delivery is separate from that standing.
//!
//! Under EXCLUSIVE ownership the same table answers who OWNS each instance
//! (Sec.2.2.3.9.2): "The arbitration is performed by the DataReader"
//! (Sec.2.2.3.10). Ownership lives here, under the lock the registrations
//! already take for every sample, because it ends exactly where a
//! registration does: the owner's unregister relinquishes it
//! (Sec.2.2.3.23.3), and so does its departure, which unregisters every
//! instance it wrote. The instance is named by the key hash the reader
//! computes from the decoded sample, the same one a key-only dispose or
//! unregister carries, so a lifecycle change finds the owner's entry.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use crate::core::rt::TopicMerger;
use crate::engine::subscriber::DisposeKind;
use crate::engine::TopicRegistry;

/// One writer's standing on one instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Standing {
    /// Whether the writer holds the instance registered.
    registered: bool,
    /// The writerSN of the change that set `registered`.
    seq: u64,
}

/// Receipt metadata for a legacy alias, independent of applied standing.
#[derive(Clone, Copy, Debug, Default)]
struct LegacyAlias {
    latest_sample: u64,
    retired_through: u64,
}

/// The writer that owns one instance under EXCLUSIVE ownership.
#[derive(Clone, Copy, Debug)]
struct Owner {
    writer: [u8; 16],
    /// When the owner last modified the instance; kept only when the reader
    /// requested a finite DEADLINE, the contract an owner that stops
    /// writing violates (Sec.2.2.3.23.1.1).
    last_write: Option<Instant>,
}

/// What one EXCLUSIVE arbitration needs besides the table: the instant of
/// the modification and the reader's requested DEADLINE period (both `None`
/// when the reader requested none), and where the writers' strengths are
/// read when a contender meets the owner (`None`: every strength is the
/// default, 0).
pub(super) struct Contest<'a> {
    pub(super) now: Option<Instant>,
    pub(super) deadline: Option<Duration>,
    pub(super) strengths: Option<&'a Weak<TopicRegistry>>,
}

/// A DataWriter of this process an EXCLUSIVE reader is bound to.
struct LocalWriter {
    /// Its OWNERSHIP_STRENGTH (a DataWriter's QoS is fixed once built).
    strength: i32,
    /// Its merger, alive exactly as long as the writer: a dead one means the
    /// writer was deleted (Sec.2.2.3.23.3: "equivalent to unregistering all
    /// the instances it was writing").
    merger: Weak<TopicMerger>,
}

/// The registrations of the writers of one reader, keyed by writer GUID,
/// then by instance key hash. A writer's entry lives until the writer
/// leaves ([`retire`](Self::retire)), with one entry per instance it wrote
/// or unregistered. `owners` and `local_writers` are empty unless the
/// reader is EXCLUSIVE.
#[derive(Default)]
pub(super) struct WriterRegistrations {
    by_writer: HashMap<[u8; 16], HashMap<[u8; 16], Standing>>,
    /// Receipt-time alias metadata for legacy writers only. Retained DATA
    /// may teach its key before ordered delivery registers the instance.
    /// Its unregister frontier must survive a delayed older DATA as well.
    /// Same writer/instance lifetime as the applied table, including
    /// pending-only keys previously inserted there by eager registration.
    legacy_aliases: HashMap<[u8; 16], HashMap<[u8; 16], LegacyAlias>>,
    owners: HashMap<[u8; 16], Owner>,
    local_writers: HashMap<[u8; 16], LocalWriter>,
    /// Writers whose LIVELINESS lease has expired (DDS v1.4 Sec.2.2.3.11,
    /// Sec.2.2.3.23.2): kept apart from `by_writer`, whose standings a
    /// writer keeps across a liveliness loss - it may resume, and its
    /// earlier samples stay recorded for when it does. A writer in here
    /// counts as holding nothing for [`is_held_alive`](Self::is_held_alive)
    /// and as absent for EXCLUSIVE arbitration ([`arbitrate`](Self::arbitrate)).
    not_alive: std::collections::HashSet<[u8; 16]>,
}

impl WriterRegistrations {
    /// A received hint teaches only above the unregister watermark. A
    /// newer sample does not erase that watermark for older delayed DATA.
    fn note_legacy_alias(&mut self, writer: [u8; 16], key: [u8; 16], seq: u64) -> bool {
        let alias = self
            .legacy_aliases
            .entry(writer)
            .or_default()
            .entry(key)
            .or_default();
        alias.latest_sample = alias.latest_sample.max(seq);
        seq > alias.retired_through
    }

    /// Whether this new retirement must erase aliases. Ordered delivery
    /// repeats receipt metadata at the same SN and must not erase twice.
    /// Newer admitted DATA keeps its hint; unregister still fences its SN.
    fn retire_legacy_alias(&mut self, writer: [u8; 16], key: [u8; 16], seq: u64) -> bool {
        let alias = self
            .legacy_aliases
            .entry(writer)
            .or_default()
            .entry(key)
            .or_default();
        let advanced = seq > alias.retired_through;
        alias.retired_through = alias.retired_through.max(seq);
        advanced && alias.latest_sample <= alias.retired_through
    }

    /// `writer` delivered a sample of instance `key` as its change `seq`: the
    /// writer holds the instance, unless it unregistered it in that same
    /// change (a sample carrying the unregister flag) or a later one.
    ///
    /// Returns whether the writer holds the instance after it.
    pub(super) fn note_sample(&mut self, writer: [u8; 16], key: [u8; 16], seq: u64) -> bool {
        match self.by_writer.entry(writer).or_default().entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(Standing {
                    registered: true,
                    seq,
                });
                true
            }
            Entry::Occupied(mut slot) => {
                let standing = slot.get_mut();
                if seq > standing.seq {
                    *standing = Standing {
                        registered: true,
                        seq,
                    };
                }
                standing.registered
            }
        }
    }

    /// `writer` unregistered instance `key` as its change `seq`. A sample the
    /// writer sent after it keeps the instance registered.
    pub(super) fn note_unregister(&mut self, writer: [u8; 16], key: [u8; 16], seq: u64) {
        match self.by_writer.entry(writer).or_default().entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(Standing {
                    registered: false,
                    seq,
                });
            }
            Entry::Occupied(mut slot) => {
                let standing = slot.get_mut();
                if seq >= standing.seq {
                    *standing = Standing {
                        registered: false,
                        seq,
                    };
                }
            }
        }
        // An owner that no longer holds the instance relinquishes it
        // (Sec.2.2.2.4.2.7, Sec.2.2.3.23.3).
        if !self.holds(&writer, &key) {
            self.release(&writer, &key);
        }
    }

    /// Whether `writer` holds instance `key` registered.
    fn holds(&self, writer: &[u8; 16], key: &[u8; 16]) -> bool {
        self.by_writer
            .get(writer)
            .and_then(|instances| instances.get(key))
            .is_some_and(|s| s.registered)
    }

    /// `writer` gives up ownership of instance `key`, if it had it.
    fn release(&mut self, writer: &[u8; 16], key: &[u8; 16]) {
        if self.owners.get(key).is_some_and(|o| o.writer == *writer) {
            self.owners.remove(key);
        }
    }

    /// EXCLUSIVE ownership (DDS v1.4 Sec.2.2.3.9.2): may `writer` modify
    /// instance `key` - is the sample, or the dispose, visible?
    ///
    /// The owner is the strongest writer, ties going to the lower GUID so
    /// every reader picks the same one whichever wrote first. An instance
    /// without an owner goes to the writer that modifies it; a contender
    /// takes it from the owner by outranking it, or once the owner let the
    /// reader's DEADLINE pass without modifying it. Strengths are read at
    /// the contest, so an owner whose strength dropped loses to a writer it
    /// no longer outranks.
    ///
    /// Only a writer that holds the instance registered becomes its owner:
    /// a change it sent before an unregister already recorded here is
    /// arbitrated, but does not hand it back an instance it let go.
    ///
    /// `holds`: whether `writer` holds the instance registered, as the
    /// caller just recorded it.
    fn arbitrate(
        &mut self,
        writer: [u8; 16],
        key: [u8; 16],
        holds: bool,
        contest: Contest<'_>,
    ) -> bool {
        let local_writers = &self.local_writers;
        let strength = |guid: &[u8; 16]| {
            local_writers
                .get(guid)
                .map(|local| local.strength)
                .or_else(|| {
                    contest
                        .strengths
                        .and_then(Weak::upgrade)
                        .and_then(|reg| reg.writer_ownership_strength(guid))
                })
                .unwrap_or(0)
        };
        let Some(owner) = self.owners.get_mut(&key) else {
            if holds {
                self.owners.insert(
                    key,
                    Owner {
                        writer,
                        last_write: contest.now,
                    },
                );
            }
            return true;
        };
        if owner.writer == writer {
            owner.last_write = contest.now;
            return true;
        }
        let lapsed = match (contest.deadline, owner.last_write, contest.now) {
            (Some(period), Some(last), Some(now)) => now.saturating_duration_since(last) > period,
            _ => false,
        };
        // A writer that is not alive (its LIVELINESS lease expired, DDS v1.4
        // Sec.2.2.3.23.1.2: "the DataReader can deduce that the DataWriter
        // ... is no longer alive") can no longer be the owner: the next
        // sample from any ALIVE writer is accepted at once, no DEADLINE
        // wait needed, exactly as if the instance had no owner yet.
        let owner_alive = !self.not_alive.contains(&owner.writer);
        let wins = lapsed || !owner_alive || {
            let (mine, theirs) = (strength(&writer), strength(&owner.writer));
            mine > theirs || (mine == theirs && writer < owner.writer)
        };
        if wins && holds {
            *owner = Owner {
                writer,
                last_write: contest.now,
            };
        }
        wins
    }

    /// A DataWriter of this process, `guid`, with `strength`, bound to this
    /// EXCLUSIVE reader through `merger`.
    pub(super) fn add_local_writer(
        &mut self,
        guid: [u8; 16],
        strength: i32,
        merger: &Arc<TopicMerger>,
    ) {
        self.local_writers.insert(
            guid,
            LocalWriter {
                strength,
                merger: Arc::downgrade(merger),
            },
        );
    }

    /// Retire every local DataWriter that was deleted, and return the
    /// instances one of them held that no writer recorded here holds any
    /// more.
    ///
    /// Its deletion sent an unregister of each instance it had not disposed
    /// (`DataWriter::drop`), which this table recorded when it was pushed;
    /// an instance it disposed it still holds and may own, and an
    /// unregister that never reached the reader (a slab or journal failure,
    /// or a full ring, which skips the reader before its ownership gate
    /// records anything) left one held: nothing else will say it left.
    fn sweep_local_writers(&mut self) -> Vec<[u8; 16]> {
        let gone: Vec<[u8; 16]> = self
            .local_writers
            .iter()
            .filter(|(_, local)| local.merger.strong_count() == 0)
            .map(|(guid, _)| *guid)
            .collect();
        let mut orphaned = Vec::new();
        for guid in gone {
            self.local_writers.remove(&guid);
            orphaned.extend(self.retire(&guid));
        }
        orphaned
    }

    /// `writer` delivered a sample of instance `key` as its change `seq`:
    /// record it, and under EXCLUSIVE ownership (`contest` is `Some`) answer
    /// whether the sample is visible. A sample is always visible under
    /// SHARED ownership.
    pub(super) fn admit_sample(
        &mut self,
        writer: [u8; 16],
        key: [u8; 16],
        seq: u64,
        contest: Option<Contest<'_>>,
    ) -> bool {
        let holds = self.note_sample(writer, key, seq);
        contest.is_none_or(|contest| self.arbitrate(writer, key, holds, contest))
    }

    /// `writer` disposed or unregistered instance `key` as its change `seq`:
    /// record it, and answer whether the reader moves the instance's state.
    ///
    /// A dispose modifies the instance, and a writer modifying an instance
    /// holds it registered: DDS v1.4 Sec.2.2.2.4.2.7, after an unregister a
    /// writer that "wants to modify (write or dispose) the instance ... has
    /// to register it again, or else use the special handle value
    /// HANDLE_NIL", which registers it as a write does (registration "can be
    /// done lazily", Sec.2.2.3.23.1.2). It does not unregister it
    /// (Sec.2.2.3.23.3).
    ///
    /// Under SHARED ownership any writer's dispose applies (Sec.2.2.2.5.1.3).
    /// Under EXCLUSIVE ownership (`contest` is `Some`) the dispose is
    /// arbitrated like a sample: "NOT_ALIVE_DISPOSED only if the DataWriter
    /// that 'owns' the instance explicitly disposes it" (Sec.2.2.2.5.1.3),
    /// and a stronger writer that disposes takes the instance, so the weaker
    /// writer's values stay hidden after it (Sec.2.2.3.23.3). The unregister
    /// half is recorded first, so the owner's dispose-and-unregister
    /// disposes the instance and then relinquishes it; a non-owner's keeps
    /// only its unregister half, which moves nothing while the owner holds
    /// the instance.
    ///
    /// An unregister moves the instance only when no ALIVE writer holds it
    /// any more (Sec.2.2.2.4.2.7, Sec.2.2.3.23.2): a writer whose LIVELINESS
    /// lease expired keeps its registration recorded (`writer_alive`), but
    /// does not keep the instance alive on its own, or this unregister would
    /// stay masked by that stale registration for as long as the dead
    /// writer is not retired - possibly forever.
    pub(super) fn admit_lifecycle(
        &mut self,
        writer: [u8; 16],
        key: [u8; 16],
        seq: u64,
        kind: DisposeKind,
        contest: Option<Contest<'_>>,
    ) -> bool {
        let disposes = kind != DisposeKind::Unregistered;
        if disposes {
            let _ = self.note_sample(writer, key, seq);
        }
        if kind != DisposeKind::Disposed {
            self.note_unregister(writer, key, seq);
        }
        if disposes {
            if let Some(contest) = contest {
                let holds = self.holds(&writer, &key);
                if !self.arbitrate(writer, key, holds, contest) {
                    return false;
                }
            }
        }
        !(kind == DisposeKind::Unregistered && self.is_held_alive(&key))
    }

    /// Whether any writer holds instance `key` registered.
    pub(super) fn is_held(&self, key: &[u8; 16]) -> bool {
        self.by_writer
            .values()
            .any(|instances| instances.get(key).is_some_and(|s| s.registered))
    }

    /// Whether an ALIVE writer holds instance `key` registered (DDS v1.4
    /// Sec.2.2.3.23.2): unlike [`is_held`](Self::is_held), a writer whose
    /// LIVELINESS lease expired does not count, even though its standing
    /// is still recorded.
    fn is_held_alive(&self, key: &[u8; 16]) -> bool {
        self.by_writer.iter().any(|(writer, instances)| {
            !self.not_alive.contains(writer) && instances.get(key).is_some_and(|s| s.registered)
        })
    }

    /// `writer`'s LIVELINESS changed: alive from now, or not (DDS v1.4
    /// Sec.2.2.3.11, Sec.2.2.3.23.2). Its standing is kept either way - a
    /// writer that lost liveliness may resume, and its earlier samples
    /// must still answer for it when it does, exactly as
    /// [`retire`](Self::retire) does NOT apply here.
    ///
    /// Not alive: return the instances `writer` holds registered that no
    /// other ALIVE writer holds, each with the writerSN `writer` last set
    /// it with - the ones this leaves without an alive writer, as a
    /// departure does to the instances a departing writer held, but
    /// without forgetting `writer`. The seq is NOT `u64::MAX` the way a
    /// departure's is: `writer` is still matched and keeps counting from
    /// where it was, so its own later sample must still be "after" this
    /// transition (the instance table's revive rule), which a seq already
    /// past every seq a real writer can reach never would be.
    pub(super) fn writer_alive(&mut self, writer: [u8; 16], alive: bool) -> Vec<([u8; 16], u64)> {
        if alive {
            self.not_alive.remove(&writer);
            return Vec::new();
        }
        self.not_alive.insert(writer);
        let held: Vec<([u8; 16], u64)> = self
            .by_writer
            .get(&writer)
            .map(|instances| {
                instances
                    .iter()
                    .filter(|(_, standing)| standing.registered)
                    .map(|(key, standing)| (*key, standing.seq))
                    .collect()
            })
            .unwrap_or_default();
        held.into_iter()
            .filter(|(key, _)| !self.is_held_alive(key))
            .collect()
    }

    /// The writer holding instance `key`, if exactly one does.
    pub(super) fn sole_holder(&self, key: &[u8; 16]) -> Option<[u8; 16]> {
        let mut found = None;
        for (writer, instances) in &self.by_writer {
            if instances.get(key).is_some_and(|s| s.registered) {
                if found.is_some() {
                    return None;
                }
                found = Some(*writer);
            }
        }
        found
    }

    /// `writer` left: forget it, release every instance it owned, and return
    /// the instances it held that no other ALIVE writer holds - the ones it
    /// leaves with no writers. A not-alive writer's stale registration must
    /// not mask this: it is not retired by losing liveliness
    /// (`writer_alive` keeps it), so it can still be the ONLY writer left
    /// recorded for an instance when the real last alive writer departs.
    pub(super) fn retire(&mut self, writer: &[u8; 16]) -> Vec<[u8; 16]> {
        self.owners.retain(|_, owner| owner.writer != *writer);
        self.not_alive.remove(writer);
        self.legacy_aliases.remove(writer);
        let Some(gone) = self.by_writer.remove(writer) else {
            return Vec::new();
        };
        gone.into_iter()
            .filter(|(key, standing)| standing.registered && !self.is_held_alive(key))
            .map(|(key, _)| key)
            .collect()
    }
}

/// Announces instances left without writers (see
/// [`ReaderRegistrations::on_orphaned`]).
pub(super) type AnnounceOrphaned = Box<dyn Fn(Vec<[u8; 16]>) + Send + Sync>;

/// One reader's [`WriterRegistrations`], shared by the paths that deliver
/// to it: its network subscriber and, under EXCLUSIVE ownership, the
/// ownership gates of its intra-process bindings, which run on the local
/// writers' threads. One table, so a local and a remote writer contend for
/// an instance as two remote writers do.
pub(super) struct ReaderRegistrations {
    table: Mutex<WriterRegistrations>,
    /// Whether the reader requested EXCLUSIVE ownership: only then does it
    /// arbitrate.
    exclusive: bool,
    /// The reader's requested DEADLINE period when it is EXCLUSIVE and the
    /// period is finite (Sec.2.2.3.9.2 (d)).
    deadline: Option<Duration>,
    /// Where remote writers' strengths are read: the participant's topic
    /// registry, set once. Weak: the registry holds the reader's subscriber,
    /// which holds this table.
    strengths: OnceLock<Weak<TopicRegistry>>,
    /// The instances each local DataWriter bound to this reader holds, by
    /// writer identity: a SHARED reader keeps no per-sample record of its
    /// local writers (that would tax the intra-process path), so before it
    /// declares an instance without writers it asks them. Read only on the
    /// lifecycle and departure paths. A dead entry is a deleted writer.
    local_holders: Mutex<Vec<Weak<crate::core::rt::WriterInstances>>>,
    /// `crate::core::rt::mergers_freed()` when the table last retired its
    /// deleted local writers: an unchanged count means none was deleted
    /// since, and admission does not look.
    swept_at: std::sync::atomic::AtomicU64,
    /// Where the instances a deleted local writer leaves without writers are
    /// announced NOT_ALIVE_NO_WRITERS: the reader's transition queue, set
    /// once by the builder.
    orphaned: OnceLock<AnnounceOrphaned>,
}

impl ReaderRegistrations {
    pub(super) fn new(
        exclusive: bool,
        deadline: Option<Duration>,
        strengths: Option<Arc<TopicRegistry>>,
    ) -> Self {
        let cell = OnceLock::new();
        if let Some(registry) = strengths {
            let _ = cell.set(Arc::downgrade(&registry));
        }
        Self {
            table: Mutex::new(WriterRegistrations::default()),
            exclusive,
            deadline: deadline.filter(|_| exclusive),
            strengths: cell,
            local_holders: Mutex::new(Vec::new()),
            swept_at: std::sync::atomic::AtomicU64::new(crate::core::rt::mergers_freed()),
            orphaned: OnceLock::new(),
        }
    }

    /// Announce the instances a deleted local writer leaves without writers
    /// through `announce`. The first call wins.
    pub(super) fn on_orphaned(&self, announce: AnnounceOrphaned) {
        let _ = self.orphaned.set(announce);
    }

    /// Retire the local writers deleted since the last look and announce
    /// the instances they leave without writers as a remote writer's
    /// departure does (`ReaderSubscriber::on_writer_dispose`).
    /// One atomic load when no merger was freed since.
    fn sweep(&self) {
        let freed = crate::core::rt::mergers_freed();
        if self.swept_at.load(std::sync::atomic::Ordering::Relaxed) == freed {
            return;
        }
        self.swept_at
            .store(freed, std::sync::atomic::Ordering::Relaxed);
        // Local writers are in the table only for an EXCLUSIVE reader, whose
        // gate records every one of them: the table alone knows who else
        // holds the instance.
        let orphaned = self.lock().sweep_local_writers();
        if orphaned.is_empty() {
            return;
        }
        if let Some(announce) = self.orphaned.get() {
            announce(orphaned);
        }
    }

    /// A local DataWriter bound to this reader, holding the instances in
    /// `instances`.
    pub(super) fn add_local_holder(&self, instances: Weak<crate::core::rt::WriterInstances>) {
        let mut holders = self.local_holders.lock().unwrap_or_else(|e| e.into_inner());
        holders.retain(|alive| alive.strong_count() > 0);
        holders.push(instances);
    }

    /// Whether a local DataWriter holds instance `key`. A writer that
    /// unregisters an instance, or is deleted, forgets it before the change
    /// reaches any reader (`DataWriter::send_lifecycle_change`, its `Drop`),
    /// so the sender of an unregister never answers for itself.
    pub(super) fn held_locally(&self, key: &[u8; 16]) -> bool {
        let holders = self.local_holders.lock().unwrap_or_else(|e| e.into_inner());
        holders.iter().any(|instances| {
            instances.upgrade().is_some_and(|instances| {
                instances
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains_key(key)
            })
        })
    }

    /// Whether any writer, remote (recorded in the table) or local, holds
    /// instance `key`.
    pub(super) fn is_held(&self, key: &[u8; 16]) -> bool {
        let in_table = self.lock().is_held(key);
        in_table || self.held_locally(key)
    }

    /// Whether any ALIVE writer, remote or local, holds instance `key`
    /// registered (DDS v1.4 Sec.2.2.3.23.2): unlike [`is_held`](Self::is_held),
    /// a remote writer whose LIVELINESS lease expired does not count, even
    /// though its standing is still recorded; a local writer is always
    /// alive (no liveliness watch exists for one), so it counts the same
    /// way `is_held` does.
    pub(super) fn is_held_alive(&self, key: &[u8; 16]) -> bool {
        let in_table = self.lock().is_held_alive(key);
        in_table || self.held_locally(key)
    }

    /// Tests only: read remote writers' strengths from `registry` if none
    /// was named (a reader built without a participant has none).
    #[cfg(test)]
    pub(super) fn read_strengths_from(&self, registry: &Arc<TopicRegistry>) {
        let _ = self.strengths.set(Arc::downgrade(registry));
    }

    /// The table, a poisoned lock recovered.
    pub(super) fn lock(&self) -> MutexGuard<'_, WriterRegistrations> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The time, only when a DEADLINE can transfer ownership, and where
    /// strengths are read; `None` for a SHARED reader.
    fn contest(&self) -> Option<Contest<'_>> {
        self.exclusive.then(|| Contest {
            now: self.deadline.map(|_| Instant::now()),
            deadline: self.deadline,
            strengths: self.strengths.get(),
        })
    }

    /// [`WriterRegistrations::admit_sample`] under the lock.
    pub(super) fn admit_sample(&self, writer: [u8; 16], key: [u8; 16], seq: u64) -> bool {
        self.sweep();
        let contest = self.contest();
        self.lock().admit_sample(writer, key, seq, contest)
    }

    /// Whether `writer`'s change `seq` of instance `key` is visible, decided
    /// ahead of its delivery: the arbitration `admit_sample` makes, made
    /// now, for a sample that must know it before it may replace anything
    /// (`ReaderSubscriber::reserve_place`). Under EXCLUSIVE ownership the
    /// sample is recorded and arbitrated as `admit_sample` does, which the
    /// delivery then repeats with the same outcome; a SHARED reader records
    /// nothing and every sample is visible. No sweep of deleted local
    /// writers: their departures are announced from the delivery, not from
    /// under the reorder gate's lock this is called with.
    pub(super) fn visible_ahead(&self, writer: [u8; 16], key: [u8; 16], seq: u64) -> bool {
        let Some(contest) = self.contest() else {
            return true;
        };
        self.lock().admit_sample(writer, key, seq, Some(contest))
    }

    /// The compatibility registry, only for a writer flagged legacy. Local
    /// and conforming writers allocate no alias frontier records.
    fn legacy_registry(&self, writer: &[u8; 16]) -> Option<Arc<TopicRegistry>> {
        let registry = self.strengths.get()?.upgrade()?;
        registry
            .writer_uses_legacy_key_hash(writer)
            .then_some(registry)
    }

    /// A delivered legacy sample may teach its key only while the newest
    /// admitted alias metadata has not retired it. Applied registration
    /// alone cannot answer this while later changes await ordered delivery.
    pub(super) fn learn_legacy_key_hash(&self, writer: [u8; 16], hash: [u8; 16], key: [u8; 16]) {
        let Some(registry) = self.legacy_registry(&writer) else {
            return;
        };
        let mut table = self.lock();
        let Some(standing) = table
            .by_writer
            .get(&writer)
            .and_then(|instances| instances.get(&key))
            .copied()
            .filter(|standing| standing.registered)
        else {
            return;
        };
        if table.note_legacy_alias(writer, key, standing.seq) {
            registry.note_legacy_key_hash_instance(writer, hash, key);
        }
    }

    /// A stored sample retained above a reorder gap has been admitted.
    /// Learn its alias without registering or arbitrating its instance:
    /// earlier ordered unregisters must still produce NO_WRITERS before
    /// this DATA revives it. Only the alias frontier is placed by writerSN.
    pub(super) fn learn_pending_legacy_key_hash(
        &self,
        writer: [u8; 16],
        hash: [u8; 16],
        key: [u8; 16],
        seq: u64,
    ) {
        let Some(registry) = self.legacy_registry(&writer) else {
            return;
        };
        let mut table = self.lock();
        if table.note_legacy_alias(writer, key, seq) {
            registry.note_legacy_key_hash_instance(writer, hash, key);
        }
    }

    /// A retained lifecycle change names its alias metadata now, while its
    /// registration and instance-state effects await ordered delivery.
    pub(super) fn note_pending_legacy_lifecycle(
        &self,
        writer: [u8; 16],
        key: [u8; 16],
        seq: u64,
        kind: DisposeKind,
    ) {
        if kind == DisposeKind::Disposed {
            return;
        }
        let Some(registry) = self.legacy_registry(&writer) else {
            return;
        };
        let mut table = self.lock();
        if table.retire_legacy_alias(writer, key, seq) {
            registry.forget_legacy_key_hash_instance(writer, key);
        }
    }

    /// [`WriterRegistrations::admit_lifecycle`] under the lock.
    pub(super) fn admit_lifecycle(
        &self,
        writer: [u8; 16],
        key: [u8; 16],
        seq: u64,
        kind: DisposeKind,
    ) -> bool {
        self.sweep();
        let contest = self.contest();
        let legacy = self.legacy_registry(&writer);
        let mut table = self.lock();
        let moves = table.admit_lifecycle(writer, key, seq, kind, contest);
        if let Some(registry) = legacy.as_ref().filter(|_| kind != DisposeKind::Disposed) {
            if table.retire_legacy_alias(writer, key, seq) {
                registry.forget_legacy_key_hash_instance(writer, key);
            }
        }
        drop(table);
        // An unregister moves nothing while a local writer still holds the
        // instance (asked after the table's lock is released).
        moves && !(kind == DisposeKind::Unregistered && self.held_locally(&key))
    }

    /// `writer` left: forget it in the table, and return the instances it
    /// held that no other writer, remote or local, holds.
    pub(super) fn retire(&self, writer: &[u8; 16]) -> Vec<[u8; 16]> {
        let left = self.lock().retire(writer);
        left.into_iter()
            .filter(|key| !self.held_locally(key))
            .collect()
    }

    /// [`WriterRegistrations::writer_alive`] under the lock: `writer`'s
    /// LIVELINESS changed (DDS v1.4 Sec.2.2.3.11). Not alive: return the
    /// instances it leaves without an alive writer, remote or local - a
    /// local writer is always alive, so it covers the instance regardless
    /// of what this table knows. `writer` keeps its standing either way,
    /// for its resumption (unlike [`retire`](Self::retire), never called
    /// here).
    pub(super) fn writer_alive(&self, writer: [u8; 16], alive: bool) -> Vec<([u8; 16], u64)> {
        let left = self.lock().writer_alive(writer, alive);
        if alive {
            return left;
        }
        left.into_iter()
            .filter(|(key, _)| !self.held_locally(key))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Contest, DisposeKind, ReaderRegistrations, WriterRegistrations};

    const A: [u8; 16] = [0xA; 16];
    const B: [u8; 16] = [0xB; 16];
    const X: [u8; 16] = [0x58; 16];

    fn no_contest() -> Contest<'static> {
        Contest {
            now: None,
            deadline: None,
            strengths: None,
        }
    }

    /// Receipt-time aliases identify lifecycle keys without applying DDS
    /// registration or erasing the unregister watermark with a newer hint.
    #[test]
    fn legacy_alias_metadata_is_independent_and_retires_with_its_writer() {
        let registry = std::sync::Arc::new(crate::engine::TopicRegistry::new());
        registry.register_writer_legacy_key_hash(A, true);
        let regs = ReaderRegistrations::new(false, None, Some(registry.clone()));
        let (new_hash, old_hash) = ([0x61; 16], [0x62; 16]);
        regs.learn_pending_legacy_key_hash(A, new_hash, X, 4);
        assert!(!regs.is_held(&X), "an alias is not an applied registration");
        regs.note_pending_legacy_lifecycle(A, X, 3, DisposeKind::Unregistered);
        assert_eq!(
            registry.resolve_legacy_key_hash_instance(&A, &new_hash),
            Some(X)
        );
        regs.learn_pending_legacy_key_hash(A, old_hash, X, 2);
        assert_eq!(
            registry.resolve_legacy_key_hash_instance(&A, &old_hash),
            None
        );

        regs.note_pending_legacy_lifecycle(A, X, 5, DisposeKind::Unregistered);
        assert_eq!(registry.legacy_key_hash_retirement_locks(), 1);
        regs.note_pending_legacy_lifecycle(A, X, 5, DisposeKind::Unregistered);
        assert_eq!(
            registry.legacy_key_hash_retirement_locks(),
            1,
            "receipt and ordered delivery repeat one retirement"
        );
        regs.learn_pending_legacy_key_hash(A, old_hash, X, 5);
        assert_eq!(
            registry.resolve_legacy_key_hash_instance(&A, &new_hash),
            None
        );
        assert_eq!(
            registry.resolve_legacy_key_hash_instance(&A, &old_hash),
            None
        );
        regs.learn_pending_legacy_key_hash(A, new_hash, X, 6);
        assert_eq!(
            registry.resolve_legacy_key_hash_instance(&A, &new_hash),
            Some(X)
        );

        regs.learn_pending_legacy_key_hash(B, old_hash, X, 7);
        regs.note_pending_legacy_lifecycle(B, X, 8, DisposeKind::Unregistered);
        assert!(!regs.lock().legacy_aliases.contains_key(&B));
        assert!(
            regs.retire(&A).is_empty(),
            "pending metadata holds no instance"
        );
        assert!(
            regs.lock().legacy_aliases.is_empty(),
            "retirement drops the frontier"
        );
    }

    #[test]
    fn an_unregister_releases_only_its_writer() {
        let mut regs = WriterRegistrations::default();
        regs.note_sample(A, X, 1);
        regs.note_sample(B, X, 1);
        regs.note_unregister(A, X, 2);
        assert!(regs.is_held(&X), "B still writes X");
        assert_eq!(regs.sole_holder(&X), Some(B));
        regs.note_unregister(B, X, 2);
        assert!(!regs.is_held(&X), "no writer is left");
    }

    #[test]
    fn a_sample_sent_before_the_unregister_does_not_register_again() {
        let mut regs = WriterRegistrations::default();
        regs.note_unregister(A, X, 5);
        regs.note_sample(A, X, 4);
        assert!(!regs.is_held(&X), "sample 4 was sent before unregister 5");
        regs.note_sample(A, X, 5);
        assert!(
            !regs.is_held(&X),
            "change 5 is the sample that carried the unregister"
        );
        regs.note_sample(A, X, 6);
        assert!(regs.is_held(&X), "sample 6 registers the instance again");
    }

    #[test]
    fn an_unregister_older_than_the_last_sample_changes_nothing() {
        let mut regs = WriterRegistrations::default();
        regs.note_sample(A, X, 7);
        regs.note_unregister(A, X, 6);
        assert!(regs.is_held(&X));
        regs.note_unregister(A, X, 7);
        assert!(
            !regs.is_held(&X),
            "an unregister riding sample 7 releases it"
        );
    }

    #[test]
    fn a_departure_leaves_only_the_instances_no_one_else_holds() {
        let mut regs = WriterRegistrations::default();
        regs.note_sample(A, X, 1);
        regs.note_unregister(A, X, 2);
        regs.note_sample(B, X, 3);
        regs.note_sample(B, [0x59; 16], 4);
        regs.note_sample(A, [0x59; 16], 5);
        let mut left = regs.retire(&B);
        left.sort_unstable();
        assert_eq!(left, vec![X], "A released X; A still holds the other");
        assert!(regs.retire(&B).is_empty(), "a writer retires once");
        assert_eq!(
            regs.retire(&A),
            vec![[0x59; 16]],
            "X is not A's to release a second time"
        );
    }

    /// DDS v1.4 Sec.2.2.3.23.2: an instance moves to NOT_ALIVE_NO_WRITERS
    /// only once no ALIVE writer is left writing it - losing one of two
    /// writers keeps it alive, losing the last one does not.
    #[test]
    fn liveliness_loss_orphans_only_an_instance_no_alive_writer_holds() {
        let mut regs = WriterRegistrations::default();
        regs.note_sample(A, X, 1);
        regs.note_sample(B, X, 9);
        assert_eq!(
            regs.writer_alive(A, false),
            Vec::new(),
            "B is still alive and writes X"
        );
        assert_eq!(
            regs.writer_alive(B, false),
            vec![(X, 9)],
            "neither writer of X is alive any more; B's own last seq rides with it, \
             not u64::MAX, so B's own next (bounded) sample still counts as after it"
        );
        assert_eq!(
            regs.writer_alive(A, true),
            Vec::new(),
            "resuming alone revives nothing by itself - A must write again"
        );
    }

    /// A writer that lost liveliness is not retired (DDS v1.4
    /// Sec.2.2.3.23.2 is a temporary "connectivity loss", not a departure,
    /// Sec.2.2.3.23.3): its earlier standing on an instance must still
    /// answer for it once it resumes.
    #[test]
    fn a_not_alive_writer_keeps_its_registration_for_its_return() {
        let mut regs = WriterRegistrations::default();
        regs.note_sample(A, X, 1);
        assert_eq!(
            regs.writer_alive(A, false),
            vec![(X, 1)],
            "A was the only writer: X has no alive writer left"
        );
        assert!(
            regs.is_held(&X),
            "A's registration is kept, not forgotten, while it may resume"
        );
        assert_eq!(regs.sole_holder(&X), Some(A));
    }

    /// DDS v1.4 Sec.2.2.3.23.1.2: ownership transfers off a writer that is
    /// no longer alive to the next ALIVE writer at once, with no DEADLINE
    /// wait - even one `B` that would otherwise lose the tie-break against
    /// an alive `A` (equal default strength, higher GUID).
    #[test]
    fn a_not_alive_owner_loses_arbitration_to_any_alive_contender() {
        let mut regs = WriterRegistrations::default();
        assert!(
            regs.admit_sample(A, X, 1, Some(no_contest())),
            "no owner yet: A takes it"
        );
        assert!(
            !regs.admit_sample(B, X, 2, Some(no_contest())),
            "A is alive: equal strength ties to the lower GUID, A keeps it"
        );
        regs.writer_alive(A, false);
        assert!(
            regs.admit_sample(B, X, 3, Some(no_contest())),
            "A is not alive any more: B wins at once, no DEADLINE wait"
        );
    }

    /// DDS v1.4 Sec.2.2.3.23.3: a departing writer releases any instance
    /// it owned, so the next ALIVE contender is not blocked by a stale
    /// owner forgotten by the table (this already held before liveliness
    /// was consulted here; pinned because nothing else in this file test
    /// it directly).
    #[test]
    fn a_departed_owner_releases_what_it_owned() {
        let mut regs = WriterRegistrations::default();
        assert!(regs.admit_sample(A, X, 1, Some(no_contest())));
        regs.retire(&A);
        assert!(
            regs.admit_sample(B, X, 2, Some(no_contest())),
            "A left: no owner remains to contest B"
        );
    }

    /// DDS v1.4 Sec.2.2.3.23.2: a not-alive writer's stale registration
    /// (`writer_alive` keeps it, unlike `retire`) must not mask the LAST
    /// alive writer's own unregister. Two writers hold X; A loses
    /// liveliness (B still alive: no transition of its own); B, the only
    /// writer left alive, unregisters: no ALIVE writer is left, so the
    /// instance moves, even though A's registration is still on record.
    #[test]
    fn a_not_alive_writers_stale_registration_does_not_mask_the_last_alive_writers_unregister() {
        let mut regs = WriterRegistrations::default();
        regs.note_sample(A, X, 1);
        regs.note_sample(B, X, 1);
        regs.writer_alive(A, false);
        assert!(
            regs.admit_lifecycle(B, X, 2, DisposeKind::Unregistered, None),
            "A is not alive: B's unregister must move the instance to \
             NOT_ALIVE_NO_WRITERS, not be masked by A's stale registration"
        );
    }

    /// Same rule, the departure path: B, the only writer left alive,
    /// leaves - `retire` must not be blind to A's stale registration
    /// either.
    #[test]
    fn a_not_alive_writers_stale_registration_does_not_mask_the_last_alive_writers_departure() {
        let mut regs = WriterRegistrations::default();
        regs.note_sample(A, X, 1);
        regs.note_sample(B, X, 1);
        regs.writer_alive(A, false);
        assert_eq!(
            regs.retire(&B),
            vec![X],
            "A is not alive: B's departure must leave X without writers, \
             not be masked by A's stale registration"
        );
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The storage a coherent DataReader stages its coherent sets in: a budget
//! of its own, derived from its QoS, that no other reader and no writer
//! shares.
//!
//! A reliable reader acknowledges a staged member once it is stored (RTPS
//! v2.5 Sec.8.4.12.2: it is in the reader's keeping), long before its set
//! commits, and only that commit gives the storage back. Staged in the
//! process-wide readers' share of the slab pool, a set would compete with
//! every other reader's sets and held samples, and with co-located writers'
//! histories: sets of several readers, or a set and the writer whose next
//! sample would close it, could wait for each other for good, and breaking
//! such a cycle would mean rejecting a set acknowledged already. A staged
//! member is therefore stored apart (`rt::SlabPool::reserve_staged`: the heap
//! tier, outside its ceiling and gauge) and charged to its reader's budget
//! only.
//!
//! RELIABLE admission retains every accepted member until delivery or a
//! protocol or LIFESPAN loss proof. Its `admit_retaining` applies the same
//! per-set and process bounds but refuses only the incoming member,
//! unacknowledged, when it cannot fit. Neither this reader nor another
//! reader's pressure may reclaim its acknowledged bytes. A set larger than
//! the configured capacity therefore remains incomplete until a genuine
//! loss proof or available capacity resolves it. The whole-set reclamation
//! rules below apply only to BEST_EFFORT staging.
//!
//! # The budget
//!
//! - Every member staged is charged: its storage (bytes, as stored:
//!   re-encoded, after its writer's GUID) and its entry (`ENTRY_COST`), a
//!   dispose or unregister of the set and a sample with no storage their
//!   entry alone.
//! - `N`, the members a set may count, its disposes and unregisters
//!   included: RESOURCE_LIMITS `max_samples` when finite, else
//!   `max_instances` x `max_samples_per_instance` when both are finite,
//!   else `MAX_STAGED_PER_WRITER` (4096; 64 in unit tests); never more than
//!   `MAX_STAGED_PER_WRITER`, which bounds what one writer stages.
//! - `S`, the largest member's charge currently, the arriving one included:
//!   the largest of the sets staged now, not of the reader's lifetime (one
//!   large sample long gone does not widen every later set's limit).
//!   Never more than the largest sample a reader re-encodes
//!   (`encode_scratch::MAX_SERIALIZED_SIZE`, 16 MiB). A set charged
//!   already stays within the `L` it is judged by: its own members are
//!   among those `S` counts.
//! - `L = N x S`: what one set may take. A set that alone would take more
//!   (more than `L` bytes, or more than `N` samples) is rejected whole
//!   (`ReaderSubscriber::reject_staged_set`): its staged members leave the
//!   staging at once, their storage given back, and what is left of the
//!   set is a record of constant size (its first SN, how many members and
//!   samples it had, the instance its reports name). Each member, staged
//!   before or landing since, is acknowledged, steps its writer's reorder
//!   gate delivering nothing, and, a sample, is reported SAMPLE_REJECTED
//!   once. A member landing since takes no storage, no staging entry and
//!   one lookup: the per-writer and per-GROUP staging bounds always hold,
//!   whatever the set's length, and a set that never closes costs nothing
//!   more. Nothing else rejects a set but the process ceiling (below).
//! - A set is IN ORDER once a member of it arrives with nothing of its
//!   writer awaited below the set's first sequence number
//!   (`ReorderGate::places_to_keep` is 0, or the gate has no baseline for
//!   the writer yet and joins at this set): no earlier set of its writer
//!   remains to commit before it. It stays so. Of each writer, one set at a
//!   time is in order: the sets after it await its members.
//! - The budget: `L` for each set in order, and `L` for every other set
//!   together (the sets staged above a gap). The gauge
//!   ([`StagingBudget::used`]) is within `L x (1 + the sets in order)`, so
//!   within `L x (1 + the writers)` under TOPIC and INSTANCE scope. A GROUP
//!   set committed on one writer may still be held by another writer's gate
//!   above a gap, charged and in order, beside the next set in order of the
//!   first writer: the one case past that.
//! - A staged member is charged from the moment it is stored until its
//!   sample leaves the reader's reorder gate for the application (or is
//!   dropped): a set committed while its writer's gate still holds it above
//!   a gap is still charged.
//!
//! # The rule
//!
//! A member that would take its set past `L` rejects the set. Otherwise a
//! member of a set in order is always admitted; a member of another set is
//! admitted while the sets not in order, it included, stay within `L`, and
//! refused UNACKNOWLEDGED otherwise: its writer sends it again (RTPS v2.5
//! Sec.8.4.7.4), and finds the room the commits meanwhile gave back, or
//! its set in order.
//!
//! # Why nothing waits for good on staging
//!
//! - A set in order waits for no storage: its members are admitted up to
//!   `L`, and a set that needs more is rejected. It waits only for its
//!   writer's samples (reliable: resent until acknowledged), for places in
//!   the history (the application's take), and for nothing of its writer
//!   below it. So it commits, and gives its storage back once its samples
//!   leave the gate.
//! - A set refused waits for what is awaited of its writer below it: samples
//!   of no set, stored without this budget (the pool's head of a gap,
//!   `rt::Claim::Head`), and the earlier sets of its writer, the earliest of
//!   which is in order. Each writer's sets commit in its order, and each in
//!   turn is in order. Under GROUP scope a Publisher's later set waits, on
//!   each writer it shares with an earlier set, for that set's part there,
//!   which is in order on that writer once what precedes it is delivered.
//! - A refusal leaves its sample unacknowledged in its writer's history. A
//!   writer co-located with the reader shares the writers' part of the slab
//!   pool with the others: refusals that filled it could keep the writer of
//!   a set from writing the rest of the set, which the refused sets wait
//!   for (with room kept for one set only, the head of the reader's order,
//!   such a cycle can form: four co-located writers, sets of three
//!   samples). A set in order is never refused, so what stays
//!   unacknowledged is only what is staged above a gap, and the gap's
//!   filling, in order, is admitted: its writer resends it from its
//!   history, writing nothing new.
//! - Nothing outside the reader takes from this budget but the process
//!   ceiling below, and this budget takes nothing from the pool's tiers.
//!
//! # The process ceiling
//!
//! The budgets of every reader of the process (of one slab pool) stage
//! together at most `MemoryPolicy::max_staging_bytes` (64 MiB by default;
//! `rt::staging_ceiling`), `C`. A member is charged only if the process
//! stays within `C` with it, atomically (`StagingCeiling::try_charge`).
//! One that would take the process past `C` makes room first, and never
//! waits for it.
//!
//! Each reader that is staging (charges something), the member's own
//! included, is entitled to a fair share of `C`: `C / R`, `R` the readers
//! staging, recomputed whenever room is made (a cold path: only a member
//! that finds the process full makes room). Room is made only in the
//! readers above their share, the member's own reader counted with the
//! member: of the sets not in order there the youngest (by its first
//! member's arrival; a set with nothing charged yet is the youngest of
//! all), with none, the youngest set in order there. That set is rejected
//! whole, and the member is decided again. The member's own set chosen,
//! it gives way: its set is rejected. With nothing left to choose, the
//! member's set is rejected too, in order or not, and so is a set that
//! alone would pass `C`.
//!
//! - The bound: what the process charges never passes `C`, whatever its
//!   threads admit together; what it stores passes it by at most the one
//!   sample each receiving thread stores before its admission.
//! - Fairness: a reader within its share never loses a set, in order or
//!   not, to another reader's member: only the sets of readers above
//!   their share are chosen. A reader flooded by a hostile peer is above
//!   its share as soon as it holds more than `C / R`, and its sets go
//!   first; a well-behaved reader staging less than its share keeps all of
//!   its sets. Should the room not be found above the shares (every
//!   charge there committed already, held by a gate), the member's own
//!   set is rejected: never another reader's within its share.
//! - Every charge can be given back by its set's rejection: staged, at
//!   once; committed and held by its writer's gate above a gap, there too
//!   (`ReorderGate::strip_held`: its members deliver nothing, reported
//!   rejected). Only a GROUP set's part flushed already stays charged
//!   until it leaves its gate: counted against later admissions as any
//!   charge is, its reader above its share by it if it is.
//!
//! A reader that stages a set larger than its share while others stage
//! sees that set rejected once the process is full: its sets are the
//! ones above a share. Alone, its share is `C`.
//!
//! # Why the ceiling makes no wait cycle
//!
//! A wait cycle needs a set that waits for room. The ceiling never makes
//! one: a member it concerns is admitted or its set is rejected, at once,
//! and a rejection is acknowledged (every member of a set rejected is,
//! staged before or landing since) and gives its storage back before the
//! admission that chose it goes on (`ReaderSubscriber::reject_staged_set`
//! frees the staged members under the staging's lock, then steps their
//! gates), so the room it makes is there when the member is decided again.
//! Each round of a member's admission rejects a set that is then never
//! chosen again (marked `doomed`, whether its storage could all be freed
//! or not), so the rounds end, and at most `MAX_EVICTIONS` are run; past
//! them, or with nothing left to reject, the member's set is rejected.
//!
//! Nor does a reader deadlock on itself. The only waits left on staging
//! are the reader's own budget's refusals above a gap, which the section
//! above shows wait only for each writer's set in order, never refused by
//! the budget. The ceiling may reject that set (its reader above its
//! share, or the set alone past it), never make it wait: a rejection takes
//! nothing a set in order waits for (a set's members are its writer's own),
//! and leaves the writer's gate stepped over its members, as received, so
//! the sets above it are in order in their turn. What a refusal waits for
//! is therefore always delivered or stepped over.

use super::subscriber::GroupSetKey;
use crate::core::rt::staging_ceiling::{StagedSets, StagingCeiling};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock, Weak};

/// A coherent set being staged: a writer's, by its first SN, or a GROUP
/// set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum StagedSet {
    Writer([u8; 16], u64),
    Group(GroupSetKey),
}

/// What a set's staged members take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Charge {
    bytes: usize,
    samples: usize,
    /// In order (see the module documentation): never refused, not counted
    /// with the sets above a gap.
    in_order: bool,
    /// When its first member charged was admitted
    /// (`StagingCeiling::next_arrival`): the higher, the younger.
    arrival: u64,
    /// Chosen to be rejected to make room: never chosen again, whether or
    /// not its reader still stages it (a set committed already is charged
    /// until its samples leave the gate, and cannot be rejected).
    doomed: bool,
    /// A loss marker retains this set until its ordered unit retires.
    pinned: bool,
}

#[derive(Debug, Default)]
struct Ledger {
    /// Every set's charge, together.
    total: usize,
    /// The charge of the sets not in order, together.
    others: usize,
    /// What each set with a member charged takes.
    sets: HashMap<StagedSet, Charge>,
    /// The size of every member charged (bytes -> how many): `S` is the
    /// largest.
    sizes: BTreeMap<usize, usize>,
}

impl Ledger {
    /// The youngest set that may be rejected to make room, of the sets in
    /// order when `in_order` (but `except`), of the others otherwise.
    fn youngest(&self, in_order: bool, except: Option<&StagedSet>) -> Option<(StagedSet, u64)> {
        self.sets
            .iter()
            .filter(|(set, charge)| {
                charge.in_order == in_order && !charge.doomed && Some(*set) != except
            })
            .max_by_key(|(_, charge)| charge.arrival)
            .map(|(set, charge)| (*set, charge.arrival))
    }
}

/// What [`StagingBudget::admit`] decides for a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Admission {
    /// Charged: stage it, then acknowledge it.
    Admitted,
    /// The sets above a gap have no room for it now: refuse it
    /// unacknowledged, its writer sends it again.
    Refused,
    /// Its set is rejected whole: alone it would take more than a set may,
    /// or it is the youngest of the sets that give way to the process
    /// ceiling.
    Rejected,
}

/// What the ledger decides, under its lock, for a member.
enum Step {
    Admitted,
    Refused,
    Rejected,
    /// The process ceiling: make room there first, then decide again.
    Ceiling,
}

/// What [`StagingBudget::make_room_in_the_process`] did.
enum Room {
    /// Another set was rejected: decide again.
    Made,
    /// The member's own set is the one to give way.
    GiveWay,
    /// Nothing is left to reject.
    NoneLeft,
}

/// A reader whose sets a budget can reject from outside it: the one whose
/// budget it is.
pub(crate) trait StagedOwner: Send + Sync {
    /// Accepted reliable DATA remains owned until delivery or loss proof.
    fn may_reject(&self) -> bool {
        true
    }

    /// Reject `set` whole now, its storage given back before this returns
    /// (`ReaderSubscriber::reject_staged_set`).
    fn reject_staged(&self, set: StagedSet);
}

/// The most sets one member's admission rejects to make room: past it,
/// what is left decides (`admit`).
const MAX_EVICTIONS: usize = 1024;

/// What every staged member is charged beside its storage: the larger
/// of its staging entry and its gate entry with its map key. An extra
/// 64 bytes cover the container's per-entry slack, rounded up to 64 bytes.
/// A member with no storage (a dispose, unregister, filtered or undecodable
/// sample) is charged this alone, so these members remain bounded too.
pub(crate) const ENTRY_COST: usize = {
    let staged = std::mem::size_of::<super::subscriber::BufferedCoherentSample>();
    let held = std::mem::size_of::<super::reorder::PendingPayload>() + std::mem::size_of::<u64>();
    let largest = if staged > held { staged } else { held };
    (largest + 64 + 63) & !63
};

/// What a member stored in `stored` bytes (none: no storage) is charged.
pub(super) fn cost_of(stored: Option<usize>) -> usize {
    stored.unwrap_or(0).saturating_add(ENTRY_COST)
}

/// A coherent reader's staging budget (see the module documentation).
pub(crate) struct StagingBudget {
    /// `N`.
    samples: usize,
    /// The process-wide ceiling the budgets of the slab pool share
    /// (`MemoryPolicy::max_staging_bytes`).
    ceiling: Arc<StagingCeiling>,
    /// The reader whose budget it is, for another reader's member to reject
    /// one of its sets (set by the builder; none in a test fixture).
    owner: OnceLock<Weak<dyn StagedOwner>>,
    ledger: Mutex<Ledger>,
}

impl std::fmt::Debug for StagingBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagingBudget")
            .field("samples", &self.samples)
            .field("ceiling", &self.ceiling)
            .field("ledger", &*self.ledger.lock())
            .finish_non_exhaustive()
    }
}

impl StagingBudget {
    /// A budget of `samples` samples per set (`N`, capped at
    /// `MAX_STAGED_PER_WRITER`, at least one), within the ceiling of the
    /// slab pool of the calling thread.
    pub(crate) fn new(samples: usize) -> Arc<Self> {
        let ceiling = Arc::clone(crate::core::rt::get_slab_pool_ref().staging_ceiling());
        let budget = Arc::new(Self {
            samples: samples.clamp(1, super::subscriber::MAX_STAGED_PER_WRITER),
            ceiling: Arc::clone(&ceiling),
            owner: OnceLock::new(),
            ledger: Mutex::new(Ledger::default()),
        });
        let weak: Weak<dyn StagedSets> = Arc::downgrade(&budget) as Weak<dyn StagedSets>;
        ceiling.register(weak);
        budget
    }

    /// The reader whose budget it is: another reader's member may reject
    /// its sets to keep the process within its ceiling.
    pub(crate) fn set_owner(&self, owner: Weak<dyn StagedOwner>) {
        let _ = self.owner.set(owner);
    }

    /// `N` for a reader of `qos` (see the module documentation).
    pub(crate) fn samples_for(qos: &crate::dds::QoS) -> usize {
        let limits = &qos.resource_limits;
        let unlimited = crate::reliability::LENGTH_UNLIMITED;
        if limits.max_samples != unlimited {
            limits.max_samples
        } else if limits.max_instances != unlimited && limits.max_samples_per_instance != unlimited
        {
            limits
                .max_instances
                .saturating_mul(limits.max_samples_per_instance)
        } else {
            super::subscriber::MAX_STAGED_PER_WRITER
        }
    }

    /// `S` for a member of `len` bytes: the largest member charged now, it
    /// included, within what the reader can re-encode.
    fn largest(ledger: &Ledger, len: usize) -> usize {
        ledger
            .sizes
            .last_key_value()
            .map_or(0, |(&size, _)| size)
            .max(len)
            .min(crate::dds::encode_scratch::MAX_SERIALIZED_SIZE)
    }

    /// `L`, what one set may take now, in bytes.
    #[cfg(test)]
    pub(crate) fn set_limit(&self) -> usize {
        self.samples
            .saturating_mul(Self::largest(&self.ledger.lock(), 0))
    }

    /// The reader's budget as it stands: `L` for each set in order charged
    /// now, and `L` for the others.
    pub(crate) fn budget(&self) -> usize {
        let ledger = self.ledger.lock();
        let in_order = ledger
            .sets
            .values()
            .filter(|charge| charge.in_order)
            .count();
        self.samples
            .saturating_mul(Self::largest(&ledger, 0))
            .saturating_mul(in_order.saturating_add(1))
    }

    /// Tests only: what the sets not in order take now, in bytes (within
    /// `L`).
    #[cfg(test)]
    pub(crate) fn others(&self) -> usize {
        self.ledger.lock().others
    }

    /// Whether `set` has the `N` samples a set may stage already: its next
    /// member rejects it.
    pub(super) fn set_is_full(&self, set: &StagedSet) -> bool {
        self.ledger
            .lock()
            .sets
            .get(set)
            .is_some_and(|charge| charge.samples >= self.samples)
    }

    /// What the reader's staged members take now, in bytes (the gauge).
    pub(crate) fn used(&self) -> usize {
        self.ledger.lock().total
    }

    /// A member of `set`, stored in `len` bytes, asks to be staged;
    /// `in_order` says whether it arrived in order (see the module
    /// documentation). Charged when admitted, until
    /// [`release`](Self::release). A member above a gap may be refused for
    /// the reader's budget; for the process ceiling, room is made by
    /// rejecting sets whole, the youngest first: this reader's by
    /// `reject_own` (called with no lock of the budget held), another
    /// reader's through its owner. Nothing waits for that ceiling.
    pub(super) fn admit(
        &self,
        set: StagedSet,
        len: usize,
        in_order: bool,
        reject_own: &dyn Fn(StagedSet),
    ) -> Admission {
        let mut evictions = 0usize;
        let mut last_try = false;
        loop {
            match self.step::<false>(set, len, in_order, last_try || evictions >= MAX_EVICTIONS) {
                Step::Admitted => return Admission::Admitted,
                Step::Refused => return Admission::Refused,
                Step::Rejected => return Admission::Rejected,
                Step::Ceiling => {
                    match self.make_room_in_the_process::<false>(set, len, in_order, reject_own) {
                        Room::Made => {}
                        Room::GiveWay => {
                            return if self.ceiling.has_pinned_sets() {
                                Admission::Refused
                            } else {
                                Admission::Rejected
                            };
                        }
                        Room::NoneLeft => last_try = true,
                    }
                }
            }
            evictions = evictions.saturating_add(1);
        }
    }

    /// Admit reliable DATA without evicting bytes already acknowledged.
    /// Pressure refuses only the arriving member, leaving it repairable.
    pub(super) fn admit_retaining(&self, set: StagedSet, len: usize, in_order: bool) -> Admission {
        for attempts in 0..=MAX_EVICTIONS {
            match self.step::<true>(set, len, in_order, attempts == MAX_EVICTIONS) {
                Step::Admitted => return Admission::Admitted,
                Step::Ceiling => {
                    if !matches!(
                        self.make_room_in_the_process::<true>(set, len, in_order, &|_| {}),
                        Room::Made
                    ) {
                        return Admission::Refused;
                    }
                }
                _ => return Admission::Refused,
            }
        }
        Admission::Refused
    }

    /// One decision of [`admit`](Self::admit), under the ledger's lock.
    /// `last_try`: no room is made any more, a member past the ceiling
    /// rejects its set.
    fn step<const RETAIN: bool>(
        &self,
        set: StagedSet,
        len: usize,
        in_order: bool,
        last_try: bool,
    ) -> Step {
        let mut ledger = self.ledger.lock();
        let limit = self.samples.saturating_mul(Self::largest(&ledger, len));
        let own = ledger.sets.get(&set).copied();
        let charge = own.unwrap_or_default();
        if charge.doomed
            || charge.samples >= self.samples
            || charge.bytes.saturating_add(len) > limit
        {
            return if RETAIN {
                Step::Refused
            } else {
                Step::Rejected
            };
        }
        let in_order = in_order || charge.in_order;
        // The sets above a gap share `L`: past it, a member is refused
        // unacknowledged, and sent again (see the module documentation).
        if !in_order && ledger.others.saturating_add(len) > limit {
            return Step::Refused;
        }
        // The process ceiling, held strictly: a member is charged only
        // within it (`StagingCeiling::try_charge`). A set that alone would
        // pass it is rejected; otherwise room is made first, and once none
        // can be, the member's set is rejected, in order or not.
        if charge.bytes.saturating_add(len) > self.ceiling.limit() {
            return if RETAIN {
                Step::Refused
            } else {
                Step::Rejected
            };
        }
        if !self.ceiling.try_charge(len) {
            return if last_try {
                if RETAIN || self.ceiling.has_pinned_sets() {
                    Step::Refused
                } else {
                    Step::Rejected
                }
            } else {
                Step::Ceiling
            };
        }
        // In order from now on: what it took leaves the others' part.
        if in_order && !charge.in_order {
            ledger.others = ledger.others.saturating_sub(charge.bytes);
        }
        if !in_order {
            ledger.others = ledger.others.saturating_add(len);
        }
        ledger.total = ledger.total.saturating_add(len);
        *ledger.sizes.entry(len).or_default() += 1;
        let arrival = match own {
            Some(own) => own.arrival,
            None => self.ceiling.next_arrival(),
        };
        let entry = ledger.sets.entry(set).or_default();
        entry.bytes = entry.bytes.saturating_add(len);
        entry.samples = entry.samples.saturating_add(1);
        entry.in_order = in_order;
        entry.arrival = arrival;
        Step::Admitted
    }

    /// Make room in the process for a member of `set` of `len` bytes (in
    /// order when `in_order`, or when it was found so before), fairly: the
    /// ceiling is split evenly among the readers that stage now, this one
    /// included (`StagingCeiling::share`), and a victim is chosen only
    /// among the readers above their share, this one with the member
    /// counted: of the sets not in order there, the youngest; with none,
    /// the youngest set in order there. The member's own set is among them,
    /// the youngest of all with nothing charged yet: chosen, it gives way.
    /// A reader within its share loses no set to another reader's member.
    fn make_room_in_the_process<const RETAIN: bool>(
        &self,
        set: StagedSet,
        len: usize,
        in_order: bool,
        reject_own: &dyn Fn(StagedSet),
    ) -> Room {
        /// Where the youngest candidate is.
        enum Victim {
            Itself,
            Own(StagedSet),
            Other(Arc<dyn StagedSets>),
        }
        let own_ptr = std::ptr::from_ref(self).cast::<()>();
        let others = self.ceiling.others(own_ptr);
        let used: Vec<usize> = others.iter().map(|b| b.used()).collect();
        let staging = 1 + used.iter().filter(|&&u| u > 0).count();
        let share = self.ceiling.share(staging);
        let (own_used, own_arrival, own_in_order) = {
            let ledger = self.ledger.lock();
            let (arrival, in_order) = ledger.sets.get(&set).map_or((None, in_order), |charge| {
                (Some(charge.arrival), in_order || charge.in_order)
            });
            (ledger.total, arrival, in_order)
        };
        let own_over = !RETAIN && own_used.saturating_add(len) > share;
        for victims_in_order in [false, true] {
            let mut youngest: Option<(u64, Victim)> = None;
            let mut consider = |arrival: u64, victim: Victim| {
                if youngest.as_ref().is_none_or(|(best, _)| arrival > *best) {
                    youngest = Some((arrival, victim));
                }
            };
            if own_over {
                if own_in_order == victims_in_order {
                    // Nothing charged yet: younger than all.
                    consider(own_arrival.unwrap_or(u64::MAX), Victim::Itself);
                }
                if let Some((victim, arrival)) =
                    self.ledger.lock().youngest(victims_in_order, Some(&set))
                {
                    consider(arrival, Victim::Own(victim));
                }
            }
            for (budget, &used) in others.iter().zip(&used) {
                if used > share {
                    if let Some(arrival) = budget.youngest(victims_in_order) {
                        consider(arrival, Victim::Other(Arc::clone(budget)));
                    }
                }
            }
            match youngest {
                Some((_, Victim::Itself)) => return Room::GiveWay,
                Some((_, Victim::Own(victim))) => {
                    if let Some(charge) = self.ledger.lock().sets.get_mut(&victim) {
                        charge.doomed = true;
                    }
                    reject_own(victim);
                    return Room::Made;
                }
                Some((arrival, Victim::Other(budget))) => {
                    // Rejected there, or gone already: not chosen again
                    // either way.
                    let _ = budget.reject(arrival);
                    return Room::Made;
                }
                None => {}
            }
        }
        Room::NoneLeft
    }

    /// A member of `set` admitted for `len` bytes left the reader's
    /// keeping: taken for the application, or dropped.
    pub(super) fn release(&self, set: StagedSet, len: usize) {
        let mut ledger = self.ledger.lock();
        ledger.total = ledger.total.saturating_sub(len);
        self.ceiling.discharge(len);
        if let Some(count) = ledger.sizes.get_mut(&len) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                ledger.sizes.remove(&len);
            }
        }
        let Some(charge) = ledger.sets.get_mut(&set) else {
            return;
        };
        charge.bytes = charge.bytes.saturating_sub(len);
        charge.samples = charge.samples.saturating_sub(1);
        let (in_order, empty, pinned) = (charge.in_order, charge.samples == 0, charge.pinned);
        if empty {
            ledger.sets.remove(&set);
            if pinned {
                self.ceiling.unpin_set();
            }
        }
        if !in_order {
            ledger.others = ledger.others.saturating_sub(len);
        }
    }

    /// Tests only: whether `set` is in order.
    #[cfg(test)]
    pub(super) fn is_in_order(&self, set: &StagedSet) -> bool {
        self.ledger
            .lock()
            .sets
            .get(set)
            .is_some_and(|charge| charge.in_order)
    }
}

impl Drop for StagingBudget {
    fn drop(&mut self) {
        let ledger = self.ledger.get_mut();
        for charge in ledger.sets.values() {
            if charge.pinned {
                self.ceiling.unpin_set();
            }
        }
        self.ceiling.discharge(ledger.total);
    }
}

impl StagedSets for StagingBudget {
    fn used(&self) -> usize {
        self.used()
    }

    fn youngest(&self, in_order: bool) -> Option<u64> {
        // Only a reader that can be reached rejects from outside.
        if !self.owner.get()?.upgrade()?.may_reject() {
            return None;
        }
        self.ledger
            .lock()
            .youngest(in_order, None)
            .map(|(_, arrival)| arrival)
    }

    fn reject(&self, arrival: u64) -> bool {
        let Some(owner) = self.owner.get().and_then(Weak::upgrade) else {
            return false;
        };
        if !owner.may_reject() {
            return false;
        }
        let victim = {
            let mut ledger = self.ledger.lock();
            let Some((set, charge)) = ledger
                .sets
                .iter_mut()
                .find(|(_, charge)| charge.arrival == arrival && !charge.doomed)
            else {
                return false;
            };
            charge.doomed = true;
            *set
        };
        owner.reject_staged(victim);
        true
    }
}

/// A staged member's charge on its reader's budget, given back when it is
/// dropped.
pub(crate) struct StagedCharge {
    budget: Arc<StagingBudget>,
    set: StagedSet,
    len: usize,
}

impl StagedCharge {
    pub(super) fn new(budget: &Arc<StagingBudget>, set: StagedSet, len: usize) -> Self {
        Self {
            budget: Arc::clone(budget),
            set,
            len,
        }
    }

    /// The set whose member it charges.
    pub(super) fn set(&self) -> StagedSet {
        self.set
    }

    /// A lost-generation marker still consumes its original entry budget.
    /// Reclamation cannot release the charge without removing that marker.
    pub(super) fn pin_loss_marker(self) -> Self {
        if let Some(charge) = self.budget.ledger.lock().sets.get_mut(&self.set) {
            charge.doomed = true;
            if !charge.pinned {
                self.budget.ceiling.pin_set();
                charge.pinned = true;
            }
        }
        self
    }
}

impl Drop for StagedCharge {
    fn drop(&mut self) {
        self.budget.release(self.set, self.len);
    }
}

impl std::fmt::Debug for StagedCharge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StagedCharge")
            .field("set", &self.set)
            .field("len", &self.len)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0xA; 16];
    const B: [u8; 16] = [0xB; 16];

    /// What a test's reader stages in a budget: its charges, given back
    /// when one of its sets is rejected.
    #[derive(Default)]
    struct Fixture {
        budget: OnceLock<Arc<StagingBudget>>,
        charges: std::sync::Mutex<Vec<(StagedSet, usize)>>,
        rejected: std::sync::Mutex<Vec<StagedSet>>,
        protected: std::sync::atomic::AtomicBool,
    }

    impl Fixture {
        fn new(samples: usize) -> Arc<Self> {
            let fixture = Arc::new(Self::default());
            let budget = StagingBudget::new(samples);
            let owner: Weak<dyn StagedOwner> = Arc::downgrade(&fixture) as _;
            budget.set_owner(owner);
            let _ = fixture.budget.set(budget);
            fixture
        }

        fn budget(&self) -> &Arc<StagingBudget> {
            self.budget.get().expect("budget")
        }

        /// A member of `set` of `len` bytes asks to be staged.
        fn admit(&self, set: StagedSet, len: usize, in_order: bool) -> Admission {
            let reject = |victim: StagedSet| self.reject_staged(victim);
            let admitted = self.budget().admit(set, len, in_order, &reject);
            if admitted == Admission::Admitted {
                self.charges.lock().expect("charges").push((set, len));
            }
            admitted
        }

        fn rejected(&self) -> Vec<StagedSet> {
            self.rejected.lock().expect("rejected").clone()
        }
    }

    impl StagedOwner for Fixture {
        fn may_reject(&self) -> bool {
            !self.protected.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn reject_staged(&self, set: StagedSet) {
            self.rejected.lock().expect("rejected").push(set);
            let released: Vec<(StagedSet, usize)> = {
                let mut charges = self.charges.lock().expect("charges");
                let (gone, kept) = charges.drain(..).partition(|(s, _)| *s == set);
                *charges = kept;
                gone
            };
            for (set, len) in released {
                self.budget().release(set, len);
            }
        }
    }

    /// A pool of this thread's own, its staging ceiling `ceiling` bytes.
    fn private_ceiling(ceiling: usize) -> crate::core::rt::PrivateSlabPoolGuard {
        let policy = crate::qos::MemoryPolicy {
            max_staging_bytes: ceiling,
            ..crate::qos::MemoryPolicy::default()
        };
        crate::core::rt::owned_private_slab_pool_for_test(&policy).1
    }

    #[test]
    fn a_set_over_its_limit_is_rejected_and_nothing_else_is() {
        let _guard = private_ceiling(1 << 30);
        let reader = Fixture::new(4);
        let a = StagedSet::Writer(A, 1);
        for _ in 0..4 {
            assert_eq!(reader.admit(a, 100, true), Admission::Admitted);
        }
        // Four of the largest sample: a fifth is one too many.
        assert_eq!(reader.admit(a, 100, true), Admission::Rejected);
        assert_eq!(reader.budget().used(), 400);
        // A larger sample raises the limit at once.
        let b = StagedSet::Writer(B, 1);
        assert_eq!(reader.admit(b, 300, false), Admission::Admitted);
        assert_eq!(reader.budget().set_limit(), 1200);
        assert_eq!(reader.budget().budget(), 2400, "L for A, in order, and L");
        assert!(
            reader.rejected().is_empty(),
            "nothing rejected to make room"
        );
    }

    #[test]
    fn pinned_loss_markers_refuse_pressure_without_creating_unbudgeted_units() {
        let _guard = private_ceiling(200);
        let owner = StagingBudget::new(4);
        let incoming = Fixture::new(4);
        let old = StagedSet::Writer(A, 1);
        assert_eq!(owner.admit(old, 100, true, &|_| {}), Admission::Admitted);
        assert_eq!(owner.admit(old, 100, true, &|_| {}), Admission::Admitted);
        let first = StagedCharge::new(&owner, old, 100)
            .pin_loss_marker()
            .pin_loss_marker();
        let second = StagedCharge::new(&owner, old, 100).pin_loss_marker();
        for seq in 1..=1024 {
            assert_eq!(
                incoming.admit(StagedSet::Writer(B, seq), 100, true),
                Admission::Refused,
                "a full pinned budget must not create an uncharged rejection marker"
            );
        }
        assert!(incoming.rejected().is_empty());
        assert_eq!(incoming.budget().used(), 0);
        assert_eq!(owner.ceiling.total(), 200);
        drop(first);
        assert!(
            owner.ceiling.has_pinned_sets(),
            "the same unit still owns a marker"
        );
        drop(second);
        assert!(
            !owner.ceiling.has_pinned_sets(),
            "double pin left a phantom pressure hold"
        );
        assert_eq!(owner.ceiling.total(), 0);
        assert_eq!(
            incoming.admit(StagedSet::Writer(B, 1025), 100, true),
            Admission::Admitted
        );
    }

    #[test]
    fn a_pinned_charge_outlives_its_reader_and_releases_the_shared_ceiling_once() {
        let _guard = private_ceiling(100);
        let owner = StagingBudget::new(4);
        let ceiling = owner.ceiling.clone();
        let set = StagedSet::Writer(A, 1);
        assert_eq!(owner.admit(set, 100, true, &|_| {}), Admission::Admitted);
        let marker = StagedCharge::new(&owner, set, 100).pin_loss_marker();
        drop(owner);
        assert!(ceiling.has_pinned_sets());
        assert_eq!(ceiling.total(), 100);
        drop(marker);
        assert!(!ceiling.has_pinned_sets());
        assert_eq!(ceiling.total(), 0);
    }

    #[test]
    fn reliable_pressure_retains_accepted_charges_within_the_process_ceiling() {
        let _guard = private_ceiling(200);
        let reader = Fixture::new(2);
        let set = StagedSet::Writer(A, 1);
        assert_eq!(
            reader.budget().admit_retaining(set, 100, true),
            Admission::Admitted
        );
        assert_eq!(
            reader.budget().admit_retaining(set, 100, true),
            Admission::Admitted
        );
        assert_eq!(
            reader.budget().admit_retaining(set, 100, true),
            Admission::Refused
        );
        assert_eq!(
            reader
                .budget()
                .admit_retaining(StagedSet::Writer(B, 1), 100, true),
            Admission::Refused
        );
        assert_eq!(reader.budget().used(), 200);
        assert_eq!(reader.budget().ceiling.total(), 200);
        assert!(reader.rejected().is_empty());
        reader.budget().release(set, 100);
        assert_eq!(
            reader.budget().admit_retaining(set, 100, true),
            Admission::Admitted
        );
        reader.budget().release(set, 100);
        reader.budget().release(set, 100);
        assert_eq!(reader.budget().ceiling.total(), 0);
    }

    #[test]
    fn another_readers_pressure_cannot_evict_acknowledged_reliable_bytes() {
        let _guard = private_ceiling(400);
        let reliable = Fixture::new(4);
        reliable
            .protected
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let set = StagedSet::Writer(A, 1);
        for _ in 0..3 {
            assert_eq!(reliable.admit(set, 100, true), Admission::Admitted);
        }
        let best_effort = Fixture::new(4);
        assert_eq!(
            best_effort.admit(StagedSet::Writer(B, 1), 200, true),
            Admission::Rejected
        );
        assert_eq!(
            reliable.budget().used(),
            300,
            "another reader purged acknowledged reliable DATA"
        );
        assert!(reliable.rejected().is_empty());
    }

    #[test]
    fn a_reliable_head_can_reclaim_only_eligible_best_effort_staging() {
        let _guard = private_ceiling(400);
        let best_effort = Fixture::new(4);
        let disposable = StagedSet::Writer(B, 1);
        for _ in 0..3 {
            assert_eq!(
                best_effort.admit(disposable, 100, true),
                Admission::Admitted
            );
        }
        let reliable = Fixture::new(4);
        reliable
            .protected
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let head = StagedSet::Writer(A, 1);
        assert_eq!(
            reliable.budget().admit_retaining(head, 200, true),
            Admission::Admitted,
            "reclaimable BE bytes permanently blocked the reliable head"
        );
        assert_eq!(best_effort.budget().used(), 0);
        assert_eq!(best_effort.rejected(), vec![disposable]);
        assert_eq!(reliable.budget().used(), 200);
        assert!(reliable.rejected().is_empty());
        assert_eq!(reliable.budget().ceiling.total(), 200);
        reliable.budget().release(head, 200);
    }

    #[test]
    fn the_largest_sample_is_that_of_the_sets_staged_now() {
        let _guard = private_ceiling(1 << 30);
        let reader = Fixture::new(4);
        let a = StagedSet::Writer(A, 1);
        let b = StagedSet::Writer(B, 1);
        assert_eq!(reader.admit(a, 1000, true), Admission::Admitted);
        assert_eq!(reader.admit(b, 10, true), Admission::Admitted);
        assert_eq!(reader.budget().set_limit(), 4000);
        // A gone: S is B's largest, no longer the reader's lifetime one.
        reader.reject_staged(a);
        assert_eq!(reader.budget().set_limit(), 40);
        for _ in 0..3 {
            assert_eq!(reader.admit(b, 10, true), Admission::Admitted);
        }
        assert_eq!(reader.admit(b, 10, true), Admission::Rejected);
        // Within what a reader can re-encode.
        let max = crate::dds::encode_scratch::MAX_SERIALIZED_SIZE;
        let c = StagedSet::Writer([0xC; 16], 1);
        assert_eq!(reader.admit(c, 2 * max, true), Admission::Admitted);
        assert_eq!(reader.budget().set_limit(), 4 * max);
    }

    #[test]
    fn a_set_in_order_is_never_refused_the_others_share_one_set_limit() {
        let _guard = private_ceiling(1 << 30);
        let reader = Fixture::new(4);
        let budget = reader.budget();
        let a = StagedSet::Writer(A, 1);
        let b = StagedSet::Writer(B, 10);
        let c = StagedSet::Writer([0xC; 16], 20);
        let d = StagedSet::Writer([0xD; 16], 30);
        // B above a gap takes the others' part whole.
        for _ in 0..4 {
            assert_eq!(reader.admit(b, 100, false), Admission::Admitted);
        }
        assert_eq!(reader.admit(c, 100, false), Admission::Refused);
        // A and D, in order, each find their whole limit.
        for _ in 0..4 {
            assert_eq!(reader.admit(a, 100, true), Admission::Admitted);
            assert_eq!(reader.admit(d, 100, true), Admission::Admitted);
        }
        assert_eq!(budget.used(), 1200);
        assert_eq!(budget.budget(), 1200, "L for each of A and D, and L");
        // A taken: C, still out of order, is still refused.
        for _ in 0..4 {
            budget.release(a, 100);
        }
        assert_eq!(reader.admit(c, 100, false), Admission::Refused);
        assert_eq!(budget.budget(), 800);
        assert!(
            reader.rejected().is_empty(),
            "the reader's budget rejects nothing"
        );
    }

    #[test]
    fn a_set_found_in_order_leaves_the_others_part() {
        let _guard = private_ceiling(1 << 30);
        let reader = Fixture::new(4);
        let budget = reader.budget();
        let b = StagedSet::Writer(B, 10);
        let c = StagedSet::Writer([0xC; 16], 20);
        for _ in 0..3 {
            assert_eq!(reader.admit(b, 100, false), Admission::Admitted);
        }
        assert_eq!(budget.others(), 300);
        // B's gap filled: its next member arrives in order.
        assert_eq!(reader.admit(b, 100, true), Admission::Admitted);
        assert!(budget.is_in_order(&b));
        assert_eq!(budget.others(), 0);
        // In order it stays, whatever a later member is told.
        assert_eq!(reader.admit(c, 100, false), Admission::Admitted);
        budget.release(b, 100);
        assert_eq!(budget.others(), 100, "B's release leaves the others alone");
        assert!(budget.is_in_order(&b));
    }

    #[test]
    fn a_dropped_charge_gives_its_bytes_back() {
        let _guard = private_ceiling(1 << 30);
        let budget = StagingBudget::new(2);
        let a = StagedSet::Writer(A, 1);
        assert_eq!(budget.admit(a, 50, true, &|_| {}), Admission::Admitted);
        let charge = StagedCharge::new(&budget, a, 50);
        assert_eq!(budget.used(), 50);
        assert_eq!(budget.ceiling.total(), 50);
        drop(charge);
        assert_eq!(budget.used(), 0);
        assert_eq!(budget.ceiling.total(), 0);
        let ledger = budget.ledger.lock();
        assert!(ledger.sets.is_empty() && ledger.sizes.is_empty());
    }

    #[test]
    fn samples_follow_the_resource_limits() {
        let mut qos = crate::dds::QoS::reliable().keep_all();
        assert_eq!(
            StagingBudget::samples_for(&qos),
            super::super::subscriber::MAX_STAGED_PER_WRITER
        );
        qos.resource_limits.max_instances = 3;
        qos.resource_limits.max_samples_per_instance = 5;
        assert_eq!(StagingBudget::samples_for(&qos), 15);
        qos.resource_limits.max_samples = 7;
        assert_eq!(StagingBudget::samples_for(&qos), 7);
        assert_eq!(
            StagingBudget::new(1_000_000).samples,
            super::super::subscriber::MAX_STAGED_PER_WRITER
        );
    }

    /// The process ceiling, split in fair shares among the readers that
    /// stage: a reader above its share gives way first, its youngest set
    /// not in order, then its youngest set in order, the member's own if it
    /// is that one; a reader within its share loses nothing to another's
    /// member. Nothing is refused, and the ceiling is never passed.
    #[test]
    fn a_reader_above_its_share_gives_way_first() {
        let _guard = private_ceiling(1000);
        let one = Fixture::new(64);
        let two = Fixture::new(64);
        let x = StagedSet::Writer(A, 1);
        let y = StagedSet::Writer(B, 10);
        let z = StagedSet::Writer([0xC; 16], 20);
        let w = StagedSet::Writer([0xD; 16], 1);
        assert_eq!(one.admit(x, 300, true), Admission::Admitted);
        assert_eq!(one.admit(x, 300, true), Admission::Admitted);
        assert_eq!(two.admit(y, 300, false), Admission::Admitted);
        // Shares of 500: one is above its share. Z, new, of one, not in
        // order, is the youngest there: it gives way.
        assert_eq!(one.admit(z, 200, false), Admission::Rejected);
        // X, in order, one's youngest set in order: it gives way too. Y,
        // of a reader within its share, is not taken.
        assert_eq!(one.admit(x, 300, true), Admission::Rejected);
        assert!(two.rejected().is_empty());
        assert_eq!(one.budget().ceiling.total(), 900);
        // W of two, within its share: one's X gives way for it.
        assert_eq!(two.admit(w, 200, true), Admission::Admitted);
        assert_eq!(one.rejected(), vec![x]);
        assert_eq!(one.budget().ceiling.total(), 500);
        // Two alone stages now: its share is the ceiling, and it makes room
        // in itself, its set not in order (Y) first.
        for _ in 0..2 {
            assert_eq!(two.admit(w, 200, true), Admission::Admitted);
        }
        assert_eq!(two.admit(w, 200, true), Admission::Admitted);
        assert_eq!(two.rejected(), vec![y]);
        assert_eq!(two.admit(w, 200, true), Admission::Admitted);
        assert_eq!(one.budget().ceiling.total(), 1000);
        // A set alone past the ceiling is rejected.
        assert_eq!(two.admit(w, 200, true), Admission::Rejected);
        assert!(one.budget().ceiling.total() <= 1000);
    }

    /// Within the readers above their share, the youngest gives way, and
    /// only as many sets as the room needs; a reader within its share
    /// keeps even its younger sets.
    #[test]
    fn the_youngest_set_above_its_share_gives_way_not_the_oldest() {
        let _guard = private_ceiling(1200);
        let one = Fixture::new(64);
        let two = Fixture::new(64);
        let three = Fixture::new(64);
        let x = StagedSet::Writer(A, 1);
        let (y1, y2, y3) = (
            StagedSet::Writer(B, 10),
            StagedSet::Writer(B, 20),
            StagedSet::Writer(B, 30),
        );
        let z = StagedSet::Writer([0xC; 16], 30);
        // Two stages 800 in three sets; one 100; three, the youngest set
        // of the process, 100.
        assert_eq!(two.admit(y1, 300, false), Admission::Admitted);
        assert_eq!(two.admit(y2, 300, false), Admission::Admitted);
        assert_eq!(two.admit(y3, 200, false), Admission::Admitted);
        assert_eq!(one.admit(x, 100, true), Admission::Admitted);
        assert_eq!(three.admit(z, 100, false), Admission::Admitted);
        // 1000 of 1200, shares of 400: one's member of 300 makes room in
        // two, above its share: its youngest (`y3`), and only it.
        assert_eq!(one.admit(x, 300, true), Admission::Admitted);
        assert_eq!(two.rejected(), vec![y3]);
        assert!(one.rejected().is_empty() && three.rejected().is_empty());
        assert_eq!(one.budget().ceiling.total(), 1100);
    }

    /// Of two readers above their share, the younger set goes, whichever
    /// reader holds it; of one reader's, a new set gives way before an
    /// older one.
    #[test]
    fn the_youngest_above_the_shares_goes_across_readers() {
        let _guard = private_ceiling(1200);
        let one = Fixture::new(64);
        let two = Fixture::new(64);
        let three = Fixture::new(64);
        let (a1, a2) = (StagedSet::Writer(A, 1), StagedSet::Writer(A, 10));
        let b1 = StagedSet::Writer(B, 1);
        let c = StagedSet::Writer([0xC; 16], 1);
        let n = StagedSet::Writer(A, 20);
        assert_eq!(one.admit(a1, 300, false), Admission::Admitted);
        assert_eq!(one.admit(a2, 200, false), Admission::Admitted);
        assert_eq!(two.admit(b1, 500, false), Admission::Admitted);
        assert_eq!(three.admit(c, 100, true), Admission::Admitted);
        // Shares of 400: one and two above theirs; B1 is the younger.
        assert_eq!(three.admit(c, 300, true), Admission::Admitted);
        assert_eq!(two.rejected(), vec![b1]);
        assert!(one.rejected().is_empty());
        // One, above its share: its new set gives way before A2 and A1.
        assert_eq!(one.admit(n, 300, false), Admission::Admitted);
        assert_eq!(one.admit(n, 400, false), Admission::Rejected);
        assert!(one.rejected().is_empty(), "A1 and A2 kept");
    }

    /// `ENTRY_COST` covers what a member without storage takes, staged or
    /// held by its gate: its record there, and the per-entry share of the
    /// map or vector that keeps it (a B-tree node's key and slack).
    #[test]
    fn the_entry_cost_covers_an_entry() {
        let staged = std::mem::size_of::<super::super::subscriber::BufferedCoherentSample>();
        let held = std::mem::size_of::<super::super::reorder::PendingPayload>()
            + std::mem::size_of::<u64>();
        eprintln!("entry: staged {staged} B, held {held} B, charged {ENTRY_COST} B");
        assert!(staged + 64 <= ENTRY_COST, "{staged} B staged");
        assert!(held + 64 <= ENTRY_COST, "{held} B held");
    }
}

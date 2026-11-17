// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Publisher GSN continuity and bracket publication for ordered wire DATA.

use super::coherent_barrier::{MemberId, PublisherKey};
use super::reorder::PendingPayload;
use super::runtime::ReaderBindings;
use crate::core::rt::SlabHandle;
use crate::engine::router::OrderedGroupChange;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Clone)]
pub(super) enum HistoryProof {
    Lifespan {
        owner_token: u64,
    },
    KnownOwed {
        ticket: Arc<crate::core::reader::LossTicket>,
    },
}

#[derive(Clone)]
pub(super) struct LossContext {
    pub writer: [u8; 16],
    pub seq: u64,
    pub reporter: Arc<super::subscriber::LossLedger>,
}
impl Default for LossContext {
    fn default() -> Self {
        Self {
            writer: [0; 16],
            seq: 1,
            reporter: Arc::default(),
        }
    }
}
pub(super) enum LossWatchResult {
    Unmatched,
    Ticket(Arc<crate::core::reader::LossTicket>),
    Full,
}
pub(super) type LossWatch = Arc<dyn Fn([u8; 16], u64) -> LossWatchResult + Send + Sync>;

type HistoryMaintenance = Arc<dyn Fn(HistoryProof) -> bool + Send + Sync>;
pub(super) type Deliver = Arc<dyn Fn([u8; 16], OrderedDelivery) + Send + Sync>;
type RosterView = Vec<([u8; 4], bool)>;
type Epoch = HashMap<MemberId, RosterView>;
type HeartbeatAnnouncement = ([u64; 3], Option<[u8; 4]>);
type ReaderWriter = ([u8; 16], MemberId);
type MissingGsns = super::gap_proofs::GapProofs;
pub(super) type Roster = Arc<dyn Fn(PublisherKey) -> Option<RosterView> + Send + Sync>;
type TerminalCell = Arc<crate::engine::demux::GroupWriterTerminal>;
type TerminalProof = (u64, Vec<TerminalCell>);
pub(super) type DepartureSnapshot =
    Arc<dyn Fn(PublisherKey) -> Option<Vec<([u8; 4], TerminalCell)>> + Send + Sync>;
pub(super) type TerminalWatch =
    Arc<dyn Fn(PublisherKey, [u8; 4]) -> Option<TerminalCell> + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenPhase {
    Pending,
    Arrived,
    Committed,
}

/// A repair belongs to an exact still-owned coherent set, not new history.
#[derive(Clone, Copy)]
pub(super) struct CoherentRepair {
    first: u64,
    owner: u64,
    member: MemberId,
    change: OrderedGroupChange,
}

pub(super) struct OrderToken {
    bindings: Weak<ReaderBindings>,
    token: u64,
    reservation_active: bool,
    loss: Arc<crate::core::reader::LossTicket>,
    handle: Option<SlabHandle>,
    change: OrderedGroupChange,
    phase: TokenPhase,
    barrier: Weak<super::coherent_barrier::CoherentPresentationBarrier>,
}

impl std::fmt::Debug for OrderToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderToken")
            .field("token", &self.token)
            .field("writer", &self.loss.writer())
            .field("sequence", &self.loss.seq())
            .finish_non_exhaustive()
    }
}

impl OrderToken {
    pub(super) fn new(
        bindings: &Weak<ReaderBindings>,
        handle: Option<SlabHandle>,
        change: OrderedGroupChange,
        barrier: &Arc<super::coherent_barrier::CoherentPresentationBarrier>,
        member: MemberId,
        remaining_lifespan: Option<std::time::Duration>,
        loss: LossContext,
    ) -> Option<Self> {
        Self::new_admission(
            bindings,
            handle,
            change,
            barrier,
            member,
            crate::engine::router::route_ordered_group_set_first(change),
            None,
            remaining_lifespan,
            loss,
        )
    }

    // A coherent admission carries both its ordering identity and replay owner.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_coherent(
        bindings: &Weak<ReaderBindings>,
        handle: Option<SlabHandle>,
        change: OrderedGroupChange,
        barrier: &Arc<super::coherent_barrier::CoherentPresentationBarrier>,
        member: MemberId,
        first: u64,
        repair: Option<CoherentRepair>,
        remaining_lifespan: Option<std::time::Duration>,
        loss: LossContext,
    ) -> Option<Self> {
        Self::new_admission(
            bindings,
            handle,
            change,
            barrier,
            member,
            Some(first),
            repair,
            remaining_lifespan,
            loss,
        )
    }

    // Reserve the payload, replay owner and loss right in the same transaction.
    #[allow(clippy::too_many_arguments)]
    fn new_admission(
        bindings: &Weak<ReaderBindings>,
        handle: Option<SlabHandle>,
        change: OrderedGroupChange,
        barrier: &Arc<super::coherent_barrier::CoherentPresentationBarrier>,
        member: MemberId,
        first: Option<u64>,
        repair: Option<CoherentRepair>,
        remaining_lifespan: Option<std::time::Duration>,
        loss: LossContext,
    ) -> Option<Self> {
        let lifespan_at =
            remaining_lifespan.map(|remaining| barrier.wire_lifespan_deadline(remaining));
        let strong = bindings.upgrade()?;
        if strong.is_closed() {
            return None;
        }
        let order = strong.local_read_order()?;
        let loss_ticket = loss.reporter.claim(loss.seq, true)?;
        let token = order.reserve(
            Arc::as_ptr(&strong) as usize,
            super::local_order::PublisherIdentity::Wire(change.publisher),
            change.gsn,
        );
        let reserved = !strong.is_closed()
            && if handle.is_some() {
                barrier.reserve_wire_sample(change, token, member, first, repair, &loss)
            } else if let Some(first) = first {
                barrier.reserve_wire_coherent(change, token, member, first, repair)
            } else {
                barrier.reserve_wire_order(change, token, member)
            };
        if !reserved {
            order.cancel_pending(token);
            loss_ticket.abort();
            return None;
        }
        if handle.is_none() {
            // This real control transition is not a lost DATA obligation.
            loss_ticket.mark_delivered();
        }
        #[cfg(test)]
        barrier.run_wire_reservation_hook_for_test();
        if let Some(at) = lifespan_at {
            barrier.reserve_wire_lifespan(change, token, member, at);
        }
        Some(Self {
            bindings: bindings.clone(),
            token,
            reservation_active: true,
            loss: loss_ticket,
            handle,
            change,
            phase: TokenPhase::Pending,
            barrier: Arc::downgrade(barrier),
        })
    }

    pub(super) fn owner_id(&self) -> u64 {
        self.token
    }

    pub(super) fn loss_count(&self, seq: u64) -> u64 {
        debug_assert_eq!(seq, self.loss.seq());
        self.loss.mark_lost()
    }

    pub(super) fn mark_lost(&self) {
        if let Some(barrier) = self.barrier.upgrade() {
            barrier.wire_owner_lost(self.change, self.owner_id());
        }
    }

    pub(super) fn attach(&mut self) -> bool {
        if self.loss.is_lost() {
            self.mark_lost();
            return false;
        }
        let Some(strong) = self.bindings.upgrade() else {
            return false;
        };
        if strong.is_closed() {
            return false;
        }
        let Some(order) = strong.local_read_order() else {
            return false;
        };
        // Admission already owns its history room. Remove shared headroom
        // before transferring the local placeholder wakes capacity waiters.
        self.release_reservation();
        // A sample-less change still fences the ACK-to-queue handoff. Its
        // unused placeholder is cancelled after the transition is applied.
        let Some(handle) = self.handle else {
            return true;
        };
        self.token = order.arrival(
            Arc::as_ptr(&strong) as usize,
            handle,
            super::local_order::PublisherIdentity::Wire(self.change.publisher),
            self.change.gsn,
        );
        self.phase = TokenPhase::Arrived;
        if strong.is_closed() {
            order.cancel(self.token);
            return false;
        }
        true
    }

    pub(super) fn commit(&mut self) {
        self.loss.mark_delivered();
        // A sample-less transition publishes no slab. Its unused pending
        // owner still rolls back after the transition has been applied.
        if self.phase == TokenPhase::Arrived {
            self.phase = TokenPhase::Committed;
        }
    }

    fn release_reservation(&mut self) {
        if std::mem::replace(&mut self.reservation_active, false) {
            let token = self.token;
            if let Some(barrier) = self.barrier.upgrade() {
                barrier.release_wire_order(self.change, token);
            }
        }
    }
}

impl Drop for OrderToken {
    fn drop(&mut self) {
        let _delivering = super::notices::Delivering::enter();
        self.release_reservation();
        if self.phase != TokenPhase::Committed {
            self.loss.abort();
            if let Some(bindings) = self.bindings.upgrade() {
                if let Some(order) = bindings.local_read_order() {
                    match self.phase {
                        TokenPhase::Pending => order.cancel_pending(self.token),
                        TokenPhase::Arrived => order.cancel(self.token),
                        TokenPhase::Committed => {}
                    }
                }
            }
        }
    }
}

pub(super) enum OrderedDelivery {
    Data(OrderedPayload),
    Lost(OrderedPayload),
}

#[cfg(test)]
impl OrderedDelivery {
    fn data(&self) -> &OrderedPayload {
        match self {
            Self::Data(payload) => payload,
            // @audit-ok: Test-only projection fails when a DATA fixture produces a loss.
            Self::Lost(_) => panic!("expected retained DATA"),
        }
    }
}

pub(super) struct OrderedPayload {
    pub payload: PendingPayload,
    pub token: Option<OrderToken>,
}

#[derive(Clone)]
struct Member {
    deliver: Deliver,
    roster: Roster,
    reliable: bool,
    durable: bool,
    bindings: Weak<ReaderBindings>,
    terminal: Option<TerminalWatch>,
    history: Option<HistoryMaintenance>,
    snapshot: Option<DepartureSnapshot>,
    loss_watch: Option<LossWatch>,
    ready: bool,
}

/// An unresolved historical prefix is an ordering bound, not a sample.
struct PrefixFence {
    bindings: Weak<ReaderBindings>,
    token: u64,
    gsn: u64,
}

impl PrefixFence {
    fn new(
        bindings: &Weak<ReaderBindings>,
        publisher: PublisherKey,
        gsn: u64,
        retired: &mut Vec<Self>,
    ) -> Option<Self> {
        let strong = bindings.upgrade()?;
        if strong.is_closed() {
            return None;
        }
        let order = strong.local_read_order()?;
        let token = order.reserve(
            Arc::as_ptr(&strong) as usize,
            super::local_order::PublisherIdentity::Wire(publisher),
            gsn,
        );
        let fence = Self {
            bindings: bindings.clone(),
            token,
            gsn,
        };
        if strong.is_closed() {
            retired.push(fence);
            None
        } else {
            Some(fence)
        }
    }
}

impl Drop for PrefixFence {
    fn drop(&mut self) {
        let _delivering = super::notices::Delivering::enter();
        if let Some(bindings) = self.bindings.upgrade() {
            if let Some(order) = bindings.local_read_order() {
                order.cancel_pending(self.token);
            }
        }
    }
}

struct Progress {
    next: u64,
    join_cut: u64,
    fence: Option<PrefixFence>,
    joined: Option<Vec<([u8; 4], TerminalCell)>>,
}

impl Progress {
    fn new(next: u64, join_cut: u64) -> Self {
        Self {
            next,
            join_cut,
            fence: None,
            joined: None,
        }
    }
}

struct Change {
    writer: [u8; 16],
    writer_set: [u8; 4],
    payloads: BTreeMap<MemberId, OrderedPayload>,
    members: HashSet<MemberId>,
}

struct LifespanOwner {
    at: u64,
    member: MemberId,
    active: bool,
}

#[derive(Default)]
struct Publisher {
    next: u64,
    source_closed_through: u64,
    participant_departure: Option<TerminalCell>,
    #[cfg(test)]
    retire_proof_hook: Option<Box<dyn FnOnce() + Send>>,
    /// Kind metadata lives only as long as its admitted reservation.
    coherent_owners: HashMap<u64, (u64, [u8; 4])>,
    lifespans: HashMap<u64, LifespanOwner>,
    progress: HashMap<MemberId, Progress>,
    /// Cohorts freeze before receipt credit; durable history joins can add
    /// debt, but a new volatile member never creates pre-join copy debt.
    cohorts: BTreeMap<u64, HashSet<MemberId>>,
    sample_writers: BTreeMap<u64, ([u8; 16], u64)>,
    losses: BTreeMap<u64, HashMap<MemberId, Arc<crate::core::reader::LossTicket>>>,
    settled: HashMap<MemberId, BTreeMap<u64, u64>>,
    pending: BTreeMap<u64, Change>,
    heartbeats: HashMap<[u8; 16], HeartbeatAnnouncement>,
    advanced: HashMap<ReaderWriter, u64>,
    gaps: HashMap<ReaderWriter, MissingGsns>,
    epochs: HashMap<[u8; 4], Epoch>,
    current_epoch: Option<(u64, [u8; 4])>,
    /// Positive global deletion witnesses for a previously validated writerSet.
    /// A missing/expired cell is unknown; local unmatch never creates proof.
    terminal_epochs: HashMap<[u8; 4], TerminalProof>,
    reserved: BTreeMap<u64, HashMap<u64, MemberId>>,
}

fn merge_interval(ranges: &mut BTreeMap<u64, u64>, mut start: u64, mut end: u64) {
    if let Some((&before, &through)) = ranges.range(..=start).next_back() {
        if through >= start {
            start = before;
            end = end.max(through);
            ranges.remove(&before);
        }
    }
    while let Some((&after, &through)) = ranges.range(start..).next() {
        if after > end {
            break;
        }
        end = end.max(through);
        ranges.remove(&after);
    }
    ranges.insert(start, end);
}

fn terminal_proof(
    key: PublisherKey,
    members: &HashMap<MemberId, Member>,
    views: &[(MemberId, RosterView)],
) -> Option<Vec<TerminalCell>> {
    for (id, view) in views {
        let Some(watch) = members.get(id).and_then(|member| member.terminal.as_ref()) else {
            continue;
        };
        if view.is_empty() {
            continue;
        }
        if let Some(cells) = view.iter().map(|(entity, _)| watch(key, *entity)).collect() {
            return Some(cells);
        }
    }
    None
}

impl Publisher {
    fn owns_repair(
        &self,
        member: MemberId,
        change: OrderedGroupChange,
        repair: CoherentRepair,
    ) -> bool {
        self.progress.contains_key(&member)
            && self.coherent_owners.get(&repair.owner)
                == Some(&(repair.first, repair.change.writer_set))
            && repair.change.publisher == change.publisher
            && repair.change.writer_set == change.writer_set
            && repair.first <= change.gsn
            && self.source_closed_through < repair.first
            && self
                .reserved
                .get(&repair.change.gsn)
                .and_then(|owners| owners.get(&repair.owner))
                == Some(&repair.member)
    }

    fn prune_terminal_epochs(&mut self) {
        let pending: HashSet<_> = self
            .pending
            .values()
            .map(|change| change.writer_set)
            .collect();
        self.terminal_epochs.retain(|digest, _| {
            pending.contains(digest)
                || self
                    .current_epoch
                    .is_some_and(|(_, current)| current == *digest)
        });
    }

    fn observe(&mut self, gsn: u64, members: &HashMap<MemberId, Member>) {
        // Existing readers retain their earlier debt. Only a reader attached
        // after this observation starts at the new volatile join boundary.
        let before = self.next.max(1);
        for id in members.keys() {
            self.progress
                .entry(*id)
                .or_insert_with(|| Progress::new(before, before));
        }
        self.next = self.next.max(gsn.saturating_add(1));
    }

    fn source_advanced(&mut self, id: MemberId, writer: [u8; 16], gsn: u64) {
        self.advanced
            .entry((writer, id))
            .and_modify(|through| *through = (*through).max(gsn))
            .or_insert(gsn);
    }

    /// A settled fact can expose the next missing interval even with no
    /// queued DATA. It proves only this boundary, never another reader's copy.
    fn advance_settled_boundary(
        &mut self,
        key: PublisherKey,
        members: &HashMap<MemberId, Member>,
        answers: &[(MemberId, Option<RosterView>)],
    ) -> bool {
        let floor = self.floor();
        let boundary = self
            .settled
            .iter()
            .filter_map(|(&id, ranges)| {
                let next = self.cursor(id);
                ranges
                    .range(next.saturating_add(1)..)
                    .next()
                    .map(|(&start, _)| start)
            })
            .filter(|start| *start > floor)
            .min();
        let Some(boundary) = boundary else {
            return false;
        };
        if self
            .pending
            .first_key_value()
            .is_some_and(|(&gsn, _)| gsn <= boundary)
        {
            return false;
        }
        let current: Option<HashMap<_, _>> = answers
            .iter()
            .filter(|(id, _)| self.cursor(*id) == floor && members.contains_key(id))
            .map(|(id, view)| Some((*id, view.clone()?)))
            .collect();
        let Some(current) = current else { return false };
        let Some(first) = current.values().next() else {
            return false;
        };
        let digest = crate::protocol::group::group_digest(first.iter().map(|(entity, _)| *entity));
        if current.values().any(|view| {
            crate::protocol::group::group_digest(view.iter().map(|(entity, _)| *entity)) != digest
        }) {
            return false;
        }
        let covering = self
            .current_epoch
            .is_some_and(|(gsn, known)| gsn >= boundary && known == digest);
        let explicit = self.heartbeats.iter().any(|(writer, (info, announced))| {
            info[0] >= boundary
                && *announced == Some(digest)
                && first.iter().any(|(entity, _)| writer[12..] == *entity)
        });
        if !covering && !explicit {
            return false;
        }
        let required: Vec<_> = current
            .iter()
            .flat_map(|(&id, view)| {
                view.iter()
                    .filter(move |(_, matched)| *matched && members[&id].reliable)
                    .map(move |(entity, _)| {
                        let mut writer = key;
                        writer[12..].copy_from_slice(entity);
                        (writer, id)
                    })
            })
            .collect();
        if !required.is_empty()
            && !self.heartbeats.iter().any(|(writer, (info, announced))| {
                info[0] >= boundary
                    && announced.is_none_or(|announced| announced == digest)
                    && first.iter().any(|(entity, _)| writer[12..] == *entity)
            })
        {
            return false;
        }
        let mut until = self
            .reserved
            .range(floor..boundary)
            .find(|(_, reserved)| reserved.values().any(|id| self.cursor(*id) == floor))
            .map_or(boundary, |(&reserved, _)| reserved);
        for (writer, id) in required {
            if self
                .advanced
                .get(&(writer, id))
                .is_some_and(|&through| through >= boundary)
            {
                continue;
            }
            if let Some(end) = self
                .gaps
                .get(&(writer, id))
                .and_then(|ranges| ranges.through(floor))
            {
                until = until.min(end);
                continue;
            }
            let Some((info, announced)) = self.heartbeats.get(&writer) else {
                return false;
            };
            if announced.is_some_and(|announced| announced != digest)
                || info[0] <= floor
                || (info[1] <= floor && floor <= info[2])
            {
                return false;
            }
            until = until
                .min(info[0])
                .min(if floor < info[1] { info[1] } else { info[0] });
        }
        if until <= floor {
            return false;
        }
        self.advance(floor, until);
        true
    }

    fn cursor(&self, id: MemberId) -> u64 {
        self.progress
            .get(&id)
            .map_or(self.next.max(1), |progress| progress.next)
    }

    fn floor(&self) -> u64 {
        self.progress
            .values()
            .map(|progress| progress.next)
            .min()
            .unwrap_or(self.next.max(1))
    }

    fn advance(&mut self, floor: u64, until: u64) {
        for progress in self.progress.values_mut() {
            if progress.next == floor {
                progress.next = until;
            }
        }
        self.update_high_water();
    }

    fn update_high_water(&mut self) {
        self.next = self.next.max(
            self.progress
                .values()
                .map(|progress| progress.next)
                .max()
                .unwrap_or(1),
        );
    }

    fn retire_unavailable_copies(
        &mut self,
        members: &HashMap<MemberId, Member>,
        notices: &mut Vec<(HistoryMaintenance, HistoryProof)>,
    ) -> bool {
        let participant = self.participant_departure.clone();
        // A queued provider writer can block a recursive read of its domain.
        // Deduplicate before locking, then reuse each view through the commit.
        let mut domains: Vec<TerminalCell> = Vec::new();
        for cell in participant
            .iter()
            .chain(self.progress.values().flat_map(|progress| {
                progress
                    .joined
                    .iter()
                    .flat_map(|writers| writers.iter().map(|(_, cell)| cell))
            }))
        {
            if !domains.iter().any(|domain| domain.same_proof_domain(cell)) {
                domains.push(cell.clone());
            }
        }
        // Readers sharing more than one registry acquire domains consistently.
        domains.sort_unstable_by_key(|domain| domain.proof_domain_id());
        let proofs: Vec<_> = domains.iter().map(|domain| domain.proof_guard()).collect();
        let participant_departed = participant.as_ref().is_some_and(|cell| {
            proofs
                .iter()
                .any(|proof| proof.is_participant_departed(cell))
        });
        #[cfg(test)]
        if let Some(hook) = self.retire_proof_hook.take() {
            hook();
        }
        let mut changed = false;
        for (&gsn, pending) in &mut self.pending {
            let missing: Vec<_> = pending
                .members
                .iter()
                .copied()
                .filter(|id| {
                    !pending.payloads.contains_key(id)
                        && !self
                            .reserved
                            .get(&gsn)
                            .is_some_and(|owners| owners.values().any(|owner| owner == id))
                })
                .collect();
            for id in missing {
                let cell = self
                    .progress
                    .get(&id)
                    .and_then(|progress| progress.joined.as_ref())
                    .and_then(|writers| {
                        writers
                            .iter()
                            .find(|(entity, _)| *entity == pending.writer[12..])
                    })
                    .map(|(_, cell)| cell.clone());
                let departed = cell
                    .as_ref()
                    .is_some_and(|cell| proofs.iter().any(|proof| proof.is_departed(cell)));
                let unavailable = self
                    .losses
                    .get(&gsn)
                    .and_then(|losses| losses.get(&id))
                    .is_some_and(|ticket| ticket.is_settled())
                    || participant_departed
                    || departed
                    || self
                        .gaps
                        .get(&(pending.writer, id))
                        .and_then(|ranges| ranges.through(gsn))
                        .is_some()
                    || self
                        .heartbeats
                        .get(&pending.writer)
                        .is_some_and(|(info, _)| info[1] > gsn);
                if !unavailable {
                    continue;
                }
                pending.members.remove(&id);
                merge_interval(
                    self.settled.entry(id).or_default(),
                    gsn,
                    gsn.saturating_add(1),
                );
                if let Some(ticket) = self
                    .losses
                    .get_mut(&gsn)
                    .and_then(|losses| losses.remove(&id))
                {
                    if let Some(callback) =
                        members.get(&id).and_then(|member| member.history.clone())
                    {
                        notices.push((callback, HistoryProof::KnownOwed { ticket }));
                    }
                }
                changed = true;
            }
        }
        changed
    }

    /// Resolve an exclusive historical boundary, not an ordinary DATA candidate.
    /// An empty history ending at cut needs currentGSN=cut-1, not a future write.
    fn close_history(
        &mut self,
        key: PublisherKey,
        members: &HashMap<MemberId, Member>,
        answers: &[(MemberId, Option<RosterView>)],
    ) -> bool {
        let mut advanced = false;
        if let Some(cell) = self.participant_departure.clone() {
            if let Some(_terminal) =
                crate::engine::demux::GroupWriterTerminal::all_participant_departed(
                    std::slice::from_ref(&cell),
                )
            {
                let horizon = self.next;
                for (&id, progress) in &mut self.progress {
                    let until = self
                        .pending
                        .range(progress.next..horizon)
                        .filter(|(_, change)| change.payloads.contains_key(&id))
                        .map(|(&gsn, _)| gsn)
                        .chain(
                            self.reserved
                                .range(progress.next..horizon)
                                .filter(|(_, owners)| owners.values().any(|owner| *owner == id))
                                .map(|(&gsn, _)| gsn),
                        )
                        .min()
                        .unwrap_or(horizon);
                    if until > progress.next {
                        progress.next = until;
                        advanced = true;
                    }
                }
            }
        }
        let cuts: Vec<_> = self
            .progress
            .iter()
            .filter_map(|(&id, progress)| {
                let member = members.get(&id)?;
                let cut = progress.join_cut;
                (member.durable && progress.next < cut).then_some((id, progress.next, cut))
            })
            .collect();
        for (id, next, cut) in cuts {
            // Owned payloads and accepted-but-not-deposited samples must finish;
            // a later availability announcement cannot erase their ownership.
            if self
                .pending
                .range(next..cut)
                .any(|(_, change)| change.members.contains(&id))
                || self
                    .reserved
                    .range(next..cut)
                    .any(|(_, reserved)| reserved.values().any(|member| *member == id))
            {
                continue;
            }
            // Association history is local to this reader. Only writers
            // captured before attachment can finish that historical obligation;
            // this does not validate an unknown global writerSet epoch.
            let joined = self
                .progress
                .get(&id)
                .and_then(|progress| progress.joined.as_ref());
            let cells: Vec<_> = joined
                .into_iter()
                .flatten()
                .map(|(_, cell)| cell.clone())
                .collect();
            if let Some(_departed) = crate::engine::demux::GroupWriterTerminal::all_departed(&cells)
            {
                debug_assert!(
                    self.progress.contains_key(&id),
                    "an active member has progress"
                );
                if let Some(progress) = self.progress.get_mut(&id) {
                    progress.next = cut;
                    advanced = true;
                }
                continue;
            }
            // An explicit global departure closes a known historical epoch,
            // including when no live writer remains to send another heartbeat.
            // The writerSet witness must reach the exclusive cut's last change;
            // an old or incomplete discovery view cannot prove that boundary.
            let terminal = self
                .current_epoch
                .and_then(|(_, digest)| self.terminal_epochs.get(&digest))
                .filter(|(gsn, _)| *gsn >= cut - 1);
            if let Some((_, cells)) = terminal {
                if let Some(_terminal) =
                    crate::engine::demux::GroupWriterTerminal::all_departed(cells)
                {
                    // The provider read guard excludes reannouncement and
                    // deletion changes until this historical cursor commits.
                    debug_assert!(
                        self.progress.contains_key(&id),
                        "an active member has progress"
                    );
                    if let Some(progress) = self.progress.get_mut(&id) {
                        progress.next = cut;
                        advanced = true;
                    }
                    continue;
                }
            }
            let Some(view) = answers
                .iter()
                .find(|(member, _)| *member == id)
                .and_then(|(_, view)| view.as_ref())
            else {
                continue;
            };
            let digest =
                crate::protocol::group::group_digest(view.iter().map(|(entity, _)| *entity));
            let known = self.current_epoch.is_some_and(|(_, known)| known == digest)
                || self.epochs.contains_key(&digest)
                || self
                    .heartbeats
                    .values()
                    .any(|(info, announced)| info[0] >= cut - 1 && *announced == Some(digest));
            if !known {
                continue;
            }
            let required: Vec<_> = view
                .iter()
                .filter(|(_, matched)| *matched && members[&id].reliable)
                .map(|(entity, _)| {
                    let mut writer = key;
                    writer[12..].copy_from_slice(entity);
                    writer
                })
                .collect();
            if !required.is_empty()
                && !self.heartbeats.values().any(|(info, announced)| {
                    info[0] >= cut - 1 && announced.is_none_or(|announced| announced == digest)
                })
            {
                continue;
            }
            let complete = required.into_iter().all(|writer| {
                let mut hole = next;
                while hole < cut {
                    if self
                        .advanced
                        .get(&(writer, id))
                        .is_some_and(|advanced| *advanced >= cut - 1)
                    {
                        return true;
                    }
                    if let Some(end) = self
                        .gaps
                        .get(&(writer, id))
                        .and_then(|ranges| ranges.through(hole))
                    {
                        hole = cut.min(end);
                        continue;
                    }
                    let Some((info, announced)) = self.heartbeats.get(&writer) else {
                        return false;
                    };
                    if announced.is_some_and(|announced| announced != digest)
                        || info[0] < cut - 1
                        || (info[1] <= hole && hole <= info[2])
                    {
                        return false;
                    }
                    let until = cut.min(info[0].saturating_add(1)).min(if hole < info[1] {
                        info[1]
                    } else {
                        cut
                    });
                    if until <= hole {
                        return false;
                    }
                    hole = until;
                }
                true
            });
            if complete {
                debug_assert!(
                    self.progress.contains_key(&id),
                    "an active member has progress"
                );
                if let Some(progress) = self.progress.get_mut(&id) {
                    progress.next = cut;
                    advanced = true;
                }
            }
        }
        self.update_high_water();
        advanced
    }

    fn refresh_fences(
        &mut self,
        key: PublisherKey,
        members: &HashMap<MemberId, Member>,
        retired: &mut Vec<PrefixFence>,
    ) {
        for (&id, progress) in &mut self.progress {
            let Some(member) = members.get(&id) else {
                continue;
            };
            // Historical membership is captured only at attachment. Later
            // observations still fence live holes but never turn them into history.
            let limit = progress.join_cut.max(self.next);
            let desired = (member.durable && progress.next < limit).then_some(progress.next);
            if progress.fence.as_ref().map(|fence| fence.gsn) == desired {
                continue;
            }
            let new = desired.and_then(|gsn| PrefixFence::new(&member.bindings, key, gsn, retired));
            if let Some(old) = progress.fence.take() {
                retired.push(old);
            }
            progress.fence = new;
        }
    }
}

#[derive(Default)]
struct State {
    generation: u64,
    members: HashMap<MemberId, Member>,
    publishers: BTreeMap<PublisherKey, Publisher>,
}

#[derive(Default)]
pub(super) struct WireOrder(
    Mutex<State>,
    OnceLock<Arc<dyn crate::dds::liveliness::LivelinessClock>>,
    std::sync::atomic::AtomicBool,
);

pub(super) struct LifespanWake {
    clock: Arc<dyn crate::dds::liveliness::LivelinessClock>,
    at: u64,
}

impl LifespanWake {
    pub fn sleep_for(&self) -> Option<std::time::Duration> {
        self.clock
            .sleep_for(self.at.saturating_sub(self.clock.now()))
    }
}

impl WireOrder {
    pub fn has_members(&self) -> bool {
        self.2.load(std::sync::atomic::Ordering::Acquire)
    }

    fn clock(&self) -> &Arc<dyn crate::dds::liveliness::LivelinessClock> {
        self.1
            .get_or_init(|| Arc::new(crate::dds::liveliness::MonotonicClock::new()))
    }

    #[cfg(test)]
    pub fn diagnostic(&self, key: PublisherKey) -> String {
        let members = self
            .0
            .lock()
            .expect("order test state mutex")
            .members
            .clone();
        let views: Vec<_> = members
            .iter()
            .map(|(id, member)| (*id, member.reliable, (member.roster)(key)))
            .collect();
        let state = self.0.lock().expect("order test state mutex");
        let Some(publisher) = state.publishers.get(&key) else {
            return format!("no publisher; views={views:?}");
        };
        format!("views={views:?}; next={}; cursors={:?}; settled={:?}; advanced={:?}; heartbeats={:?}; pending={:?}; participant={}", publisher.next,
            publisher.progress.iter().map(|(id, progress)| (*id, progress.next, progress.join_cut)).collect::<Vec<_>>(),
            publisher.settled, publisher.advanced, publisher.heartbeats, publisher.pending.iter().map(|(gsn,change)| (*gsn, change.members.clone(),change.payloads.keys().copied().collect::<Vec<_>>())).collect::<Vec<_>>(), publisher.participant_departure.is_some())
            + &format!("; reservations={:?}; coherent={:?}; source_closed={}", publisher.reserved,publisher.coherent_owners,publisher.source_closed_through)
    }

    #[cfg(test)]
    pub fn set_clock(&self, clock: Arc<dyn crate::dds::liveliness::LivelinessClock>) {
        assert!(
            self.1.set(clock).is_ok(),
            "lifespan clock was already initialized"
        );
    }

    pub fn next_lifespan_wake(&self) -> Option<LifespanWake> {
        if !self.has_members() {
            return None;
        }
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let at = state
            .publishers
            .values()
            .flat_map(|publisher| publisher.lifespans.values())
            .filter(|owner| owner.active)
            .map(|owner| owner.at)
            .min()?;
        Some(LifespanWake {
            clock: self.clock().clone(),
            at,
        })
    }

    pub fn attach_history(&self, id: MemberId, maintenance: HistoryMaintenance) {
        if let Some(member) = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .members
            .get_mut(&id)
        {
            member.history = Some(maintenance);
        }
    }

    pub fn attach_snapshot(&self, id: MemberId, snapshot: DepartureSnapshot) {
        let keys = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let Some(member) = state.members.get_mut(&id) else {
                return;
            };
            member.snapshot = Some(snapshot.clone());
            state.publishers.keys().copied().collect::<Vec<_>>()
        };
        let snapshots: Vec<_> = keys.into_iter().map(|key| (key, snapshot(key))).collect();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.members.contains_key(&id) {
            return;
        }
        for (key, cells) in snapshots {
            if let Some(progress) = state
                .publishers
                .get_mut(&key)
                .and_then(|publisher| publisher.progress.get_mut(&id))
            {
                progress.joined = cells;
            }
        }
    }

    pub fn departure(&self, key: PublisherKey, writer: [u8; 16]) {
        let members = {
            let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if !state.publishers.contains_key(&key) {
                return;
            }
            state.members.clone()
        };
        let [.., e0, e1, e2, e3] = writer;
        let entity: [u8; 4] = [e0, e1, e2, e3];
        let cell = members
            .values()
            .filter_map(|member| member.terminal.as_ref())
            .find_map(|watch| watch(key, entity));
        if let Some(cell) = cell {
            if let Some(publisher) = self
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .publishers
                .get_mut(&key)
            {
                publisher.participant_departure = Some(cell);
            }
        }
    }

    pub fn may_stage_unit(
        &self,
        _writer: [u8; 16],
        change: OrderedGroupChange,
        member: MemberId,
        first: u64,
    ) -> bool {
        if first == 0 || first > change.gsn {
            return false;
        }
        loop {
            let (members, generation) = {
                let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                if !state.members.contains_key(&member) {
                    return false;
                }
                if first
                    <= state
                        .publishers
                        .get(&change.publisher)
                        .map_or(1, Publisher::floor)
                {
                    return true;
                }
                (state.members.clone(), state.generation)
            };
            let views: Option<HashMap<_, _>> = members
                .iter()
                .map(|(&id, member)| Some((id, (member.roster)(change.publisher)?)))
                .collect();
            let Some(views) = views else { return false };
            let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.generation != generation {
                continue;
            }
            let Some(publisher) = state.publishers.get(&change.publisher) else {
                return false;
            };
            // Process-wide staging has one ceiling: every relevant reader's
            // earlier unit must be reconstructible before a later one pins it.
            if publisher.reserved.range(..first).any(|(_, owners)| {
                owners
                    .keys()
                    .any(|token| publisher.coherent_owners.contains_key(token))
            }) {
                return false;
            }
            for (&id, member) in &members {
                let view = &views[&id];
                if crate::protocol::group::group_digest(view.iter().map(|(entity, _)| *entity))
                    != change.writer_set
                {
                    return false;
                }
                let mut next = publisher.cursor(id);
                while next < first {
                    if let Some(owners) = publisher.reserved.get(&next) {
                        if owners.iter().any(|(token, owner)| {
                            *owner == id && !publisher.coherent_owners.contains_key(token)
                        }) {
                            next = next.saturating_add(1);
                            continue;
                        }
                    }
                    if let Some(pending) = publisher.pending.get(&next) {
                        let unmatched = view
                            .iter()
                            .any(|(entity, matched)| pending.writer[12..] == *entity && !matched);
                        if unmatched {
                            next = next.saturating_add(1);
                            continue;
                        }
                    }
                    if let Some((_, end)) = publisher
                        .settled
                        .get(&id)
                        .and_then(|ranges| ranges.range(..=next).next_back())
                        .filter(|(_, end)| next < **end)
                    {
                        next = *end;
                        continue;
                    }
                    let required: Vec<_> = view
                        .iter()
                        .filter(|(_, matched)| *matched && member.reliable)
                        .map(|(entity, _)| {
                            let mut writer = change.publisher;
                            writer[12..].copy_from_slice(entity);
                            writer
                        })
                        .collect();
                    if !required.is_empty()
                        && !publisher.heartbeats.values().any(|(info, digest)| {
                            info[0] >= first
                                && digest.is_none_or(|digest| digest == change.writer_set)
                        })
                    {
                        return false;
                    }
                    let mut until = first;
                    for writer in required {
                        if publisher
                            .advanced
                            .get(&(writer, id))
                            .is_some_and(|through| *through >= first.saturating_sub(1))
                        {
                            continue;
                        }
                        if let Some(end) = publisher
                            .gaps
                            .get(&(writer, id))
                            .and_then(|ranges| ranges.through(next))
                        {
                            until = until.min(end);
                            continue;
                        }
                        let Some((info, digest)) = publisher.heartbeats.get(&writer) else {
                            return false;
                        };
                        if digest.is_some_and(|digest| digest != change.writer_set)
                            || info[0] < first.saturating_sub(1)
                            || (info[1] <= next && next <= info[2])
                        {
                            return false;
                        }
                        until = until.min(info[0].saturating_add(1)).min(if next < info[1] {
                            info[1]
                        } else {
                            first
                        });
                    }
                    if until <= next {
                        return false;
                    }
                    next = until;
                }
            }
            return true;
        }
    }

    pub fn lifespan_deadline(&self, remaining: std::time::Duration) -> u64 {
        self.clock()
            .now()
            .saturating_add(u64::try_from(remaining.as_nanos()).unwrap_or(u64::MAX))
    }

    pub fn reserve_lifespan(
        &self,
        change: OrderedGroupChange,
        token: u64,
        member: MemberId,
        at: u64,
    ) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(publisher) = state.publishers.get_mut(&change.publisher) {
            if publisher
                .reserved
                .get(&change.gsn)
                .is_some_and(|owners| owners.get(&token) == Some(&member))
            {
                publisher.lifespans.insert(
                    token,
                    LifespanOwner {
                        at,
                        member,
                        active: false,
                    },
                );
            }
        }
    }

    pub fn activate_lifespan(&self, token: u64) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for publisher in state.publishers.values_mut() {
            if let Some(owner) = publisher.lifespans.get_mut(&token) {
                owner.active = true;
                break;
            }
        }
    }

    pub fn discarded_copy(&self, member: MemberId, change: OrderedGroupChange) {
        let _delivering = super::notices::Delivering::enter();
        let mut retired = Vec::new();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.members.contains_key(&member) {
            return;
        }
        let members = state.members.clone();
        let publisher = state.publishers.entry(change.publisher).or_default();
        // This proof belongs only to an actual received copy of a known
        // unavailable unit. It is neither a GAP nor another reader's receipt.
        if publisher
            .reserved
            .get(&change.gsn)
            .is_some_and(|owners| owners.values().any(|id| *id == member))
            || publisher
                .pending
                .get(&change.gsn)
                .is_some_and(|pending| pending.payloads.contains_key(&member))
        {
            return;
        }
        publisher.observe(change.gsn, &members);
        merge_interval(
            publisher.settled.entry(member).or_default(),
            change.gsn,
            change.gsn.saturating_add(1),
        );
        if let Some(pending) = publisher.pending.get_mut(&change.gsn) {
            pending.members.remove(&member);
        }
        if let Some(cohort) = publisher.cohorts.get_mut(&change.gsn) {
            cohort.remove(&member);
        }
        if let Some(losses) = publisher.losses.get_mut(&change.gsn) {
            losses.remove(&member);
        }
        publisher.refresh_fences(change.publisher, &members, &mut retired);
        drop(state);
        drop(retired);
    }

    pub fn owner_lost(&self, change: OrderedGroupChange, token: u64) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(publisher) = state.publishers.get_mut(&change.publisher) else {
            return;
        };
        let Some(id) = publisher
            .reserved
            .get(&change.gsn)
            .and_then(|owners| owners.get(&token))
            .copied()
        else {
            return;
        };
        // This is one identified received copy, not an unknown GSN interval
        // or a synthetic writer receipt.
        merge_interval(
            publisher.settled.entry(id).or_default(),
            change.gsn,
            change.gsn.saturating_add(1),
        );
        if let Some(pending) = publisher.pending.get_mut(&change.gsn) {
            pending.members.remove(&id);
        }
    }

    /// Only offered LIFESPAN, measured from the sample's source timestamp,
    /// can schedule loss. Missing historical metadata has no time limit.
    pub fn expire_lifespans(&self) -> Vec<(Deliver, [u8; 16], OrderedDelivery)> {
        let _delivering = super::notices::Delivering::enter();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state
            .publishers
            .values()
            .any(|publisher| publisher.lifespans.values().any(|owner| owner.active))
        {
            return Vec::new();
        }
        let now = self.clock().now();
        let members = state.members.clone();
        let mut callbacks = Vec::new();
        let mut deliveries = Vec::new();
        for publisher in state.publishers.values_mut() {
            let due: Vec<_> = publisher
                .lifespans
                .iter()
                .filter(|(_, owner)| owner.active && owner.at <= now)
                .map(|(&token, owner)| (token, owner.member))
                .collect();
            for (token, id) in due {
                if let Some(owner) = publisher.lifespans.get_mut(&token) {
                    owner.active = false;
                }
                let gsn = publisher
                    .reserved
                    .iter()
                    .find_map(|(&gsn, owners)| (owners.get(&token) == Some(&id)).then_some(gsn));
                let Some(gsn) = gsn else { continue };
                if let Some(change) = publisher.pending.get_mut(&gsn) {
                    if let Some(payload) = change.payloads.remove(&id) {
                        publisher.lifespans.remove(&token);
                        change.members.remove(&id);
                        merge_interval(
                            publisher.settled.entry(id).or_default(),
                            gsn,
                            gsn.saturating_add(1),
                        );
                        if let Some(member) = members.get(&id) {
                            deliveries.push((
                                member.deliver.clone(),
                                change.writer,
                                OrderedDelivery::Lost(payload),
                            ));
                        }
                        continue;
                    }
                }
                if let Some(maintenance) =
                    members.get(&id).and_then(|member| member.history.as_ref())
                {
                    callbacks.push((
                        maintenance.clone(),
                        HistoryProof::Lifespan { owner_token: token },
                    ));
                }
            }
        }
        for publisher in state.publishers.values_mut() {
            publisher
                .pending
                .retain(|_, change| !change.payloads.is_empty() || !change.members.is_empty());
        }
        drop(state);
        for (maintenance, proof) in callbacks {
            let HistoryProof::Lifespan { owner_token } = proof else {
                unreachable!("only lifespan deadlines are scheduled")
            };
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| maintenance(proof))) {
                Ok(true) => {
                    let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                    for publisher in state.publishers.values_mut() {
                        publisher.lifespans.remove(&owner_token);
                    }
                }
                Ok(false) => {
                    // A buffer-to-ready handoff still owns this token. Its
                    // destination reactivates the due deadline after deposit.
                }
                Err(_) => log::error!("[PRESENTATION] a lifespan maintenance callback panicked"),
            }
        }
        deliveries
    }

    #[cfg(test)]
    pub fn attach(&self, id: MemberId, deliver: Deliver, roster: Roster, reliable: bool) {
        self.attach_reader(id, deliver, roster, reliable, false, Weak::new());
    }

    #[cfg(test)]
    pub fn attach_reader(
        &self,
        id: MemberId,
        deliver: Deliver,
        roster: Roster,
        reliable: bool,
        durable: bool,
        bindings: Weak<ReaderBindings>,
    ) {
        self.attach_reader_state(id, deliver, roster, reliable, durable, bindings, true);
    }

    pub fn attach_pending_reader(
        &self,
        id: MemberId,
        deliver: Deliver,
        roster: Roster,
        reliable: bool,
        durable: bool,
        bindings: Weak<ReaderBindings>,
    ) {
        self.attach_reader_state(id, deliver, roster, reliable, durable, bindings, false);
    }

    #[allow(clippy::too_many_arguments)]
    fn attach_reader_state(
        &self,
        id: MemberId,
        deliver: Deliver,
        roster: Roster,
        reliable: bool,
        durable: bool,
        bindings: Weak<ReaderBindings>,
        ready: bool,
    ) {
        let _delivering = super::notices::Delivering::enter();
        let mut retired = Vec::new();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.generation = state.generation.wrapping_add(1);
        state.members.insert(
            id,
            Member {
                deliver,
                roster,
                reliable,
                durable,
                bindings: bindings.clone(),
                terminal: None,
                history: None,
                snapshot: None,
                loss_watch: None,
                ready,
            },
        );
        self.2.store(true, std::sync::atomic::Ordering::Release);
        for (key, publisher) in &mut state.publishers {
            let cut = publisher.next.max(1);
            let next = if durable { 1 } else { cut };
            let mut progress = Progress::new(next, cut);
            if next < cut {
                progress.fence = PrefixFence::new(&bindings, *key, next, &mut retired);
            }
            if let Some(mut old) = publisher.progress.insert(id, progress) {
                if let Some(fence) = old.fence.take() {
                    retired.push(fence);
                }
            }
            if durable && ready {
                for pending in publisher.pending.values_mut() {
                    pending.members.insert(id);
                }
                for cohort in publisher.cohorts.values_mut() {
                    cohort.insert(id);
                }
            }
        }
        drop(state);
        drop(retired);
    }

    pub fn attach_terminal(&self, id: MemberId, watch: TerminalWatch) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(member) = state.members.get_mut(&id) {
            member.terminal = Some(watch);
            state.generation = state.generation.wrapping_add(1);
        }
    }

    pub fn forget(&self, id: MemberId) {
        let _delivering = super::notices::Delivering::enter();
        let mut retired = Vec::new();
        let removed = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.members.remove(&id).is_some() {
                state.generation = state.generation.wrapping_add(1);
            }
            self.2.store(
                !state.members.is_empty(),
                std::sync::atomic::Ordering::Release,
            );
            let mut removed = Vec::new();
            for publisher in state.publishers.values_mut() {
                if let Some(mut progress) = publisher.progress.remove(&id) {
                    if let Some(fence) = progress.fence.take() {
                        retired.push(fence);
                    }
                }
                publisher.settled.remove(&id);
                for losses in publisher.losses.values_mut() {
                    losses.remove(&id);
                }
                publisher.lifespans.retain(|_, owner| owner.member != id);
                for cohort in publisher.cohorts.values_mut() {
                    cohort.remove(&id);
                }
                for change in publisher.pending.values_mut() {
                    change.members.remove(&id);
                    if let Some(payload) = change.payloads.remove(&id) {
                        removed.push(payload);
                    }
                }
                publisher.advanced.retain(|(_, member), _| *member != id);
                publisher.gaps.retain(|(_, member), _| *member != id);
                for reserved in publisher.reserved.values_mut() {
                    reserved.retain(|_, member| *member != id);
                }
                publisher
                    .reserved
                    .retain(|_, reserved| !reserved.is_empty());
                let reserved = &publisher.reserved;
                publisher
                    .coherent_owners
                    .retain(|token, _| reserved.values().any(|owners| owners.contains_key(token)));
                publisher
                    .pending
                    .retain(|_, change| !change.members.is_empty() || !change.payloads.is_empty());
                let reserved = &publisher.reserved;
                let pending = &publisher.pending;
                publisher
                    .cohorts
                    .retain(|gsn, _| reserved.contains_key(gsn) || pending.contains_key(gsn));
                publisher
                    .sample_writers
                    .retain(|gsn, _| publisher.cohorts.contains_key(gsn));
                publisher
                    .losses
                    .retain(|gsn, _| publisher.cohorts.contains_key(gsn));
                for epoch in publisher.epochs.values_mut() {
                    epoch.remove(&id);
                }
            }
            if state.members.is_empty() {
                state.publishers.clear();
            }
            removed
        };
        drop(removed);
        drop(retired);
    }

    pub fn reserve_sample(
        &self,
        change: OrderedGroupChange,
        token: u64,
        member: MemberId,
        first: Option<u64>,
        repair: Option<CoherentRepair>,
        sample: &LossContext,
    ) -> bool {
        self.reserve_admission(change, token, member, first, repair, Some(sample))
    }

    pub fn attach_loss_watch(&self, id: MemberId, watch: LossWatch) -> bool {
        loop {
            let (known, generation) = {
                let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                let Some(member) = state.members.get(&id) else {
                    return false;
                };
                let known = state
                    .publishers
                    .iter()
                    .flat_map(|(&key, publisher)| {
                        publisher
                            .sample_writers
                            .iter()
                            .filter(move |(gsn, (writer, _))| {
                                member.durable
                                    && publisher.cursor(id) <= **gsn
                                    && publisher
                                        .heartbeats
                                        .get(writer)
                                        .is_none_or(|(info, _)| info[1] <= **gsn)
                            })
                            .map(move |(&gsn, &(writer, seq))| (key, gsn, writer, seq))
                    })
                    .collect::<Vec<_>>();
                (known, state.generation)
            };
            let mut tickets = Vec::new();
            for (key, gsn, writer, seq) in known {
                match watch(writer, seq) {
                    LossWatchResult::Ticket(ticket) => tickets.push((key, gsn, ticket)),
                    LossWatchResult::Unmatched => {}
                    LossWatchResult::Full => return false,
                }
            }
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.generation != generation {
                continue;
            }
            let Some(member) = state.members.get_mut(&id) else {
                return false;
            };
            member.loss_watch = Some(watch.clone());
            member.ready = true;
            let durable = member.durable;
            state.generation = state.generation.wrapping_add(1);
            for publisher in state.publishers.values_mut() {
                if durable {
                    for (&gsn, cohort) in &mut publisher.cohorts {
                        if publisher
                            .progress
                            .get(&id)
                            .is_some_and(|progress| progress.next <= gsn)
                        {
                            cohort.insert(id);
                            if let Some(pending) = publisher.pending.get_mut(&gsn) {
                                pending.members.insert(id);
                            }
                        }
                    }
                }
            }
            for (key, gsn, ticket) in tickets {
                if let Some(publisher) = state.publishers.get_mut(&key) {
                    if publisher
                        .cohorts
                        .get(&gsn)
                        .is_some_and(|cohort| cohort.contains(&id))
                    {
                        publisher
                            .losses
                            .entry(gsn)
                            .or_default()
                            .entry(id)
                            .or_insert(ticket);
                    }
                }
            }
            return true;
        }
    }

    pub fn reserve(&self, change: OrderedGroupChange, token: u64, member: MemberId) -> bool {
        self.reserve_admission(change, token, member, None, None, None)
    }

    pub fn reserve_coherent(
        &self,
        change: OrderedGroupChange,
        token: u64,
        member: MemberId,
        first: u64,
        repair: Option<CoherentRepair>,
    ) -> bool {
        self.reserve_admission(change, token, member, Some(first), repair, None)
    }

    pub fn repair_context(
        &self,
        change: OrderedGroupChange,
        member: MemberId,
        first: u64,
    ) -> Option<CoherentRepair> {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.members.contains_key(&member) {
            return None;
        }
        let publisher = state.publishers.get(&change.publisher)?;
        for (&gsn, owners) in &publisher.reserved {
            for (&owner, &id) in owners {
                let repair = CoherentRepair {
                    first,
                    owner,
                    member: id,
                    change: OrderedGroupChange { gsn, ..change },
                };
                if publisher.owns_repair(member, change, repair) {
                    return Some(repair);
                }
            }
        }
        None
    }

    fn reserve_admission(
        &self,
        change: OrderedGroupChange,
        token: u64,
        member: MemberId,
        first: Option<u64>,
        repair: Option<CoherentRepair>,
        sample: Option<&LossContext>,
    ) -> bool {
        let _delivering = super::notices::Delivering::enter();
        let mut retired = Vec::new();
        loop {
            let (snapshot, generation, eligible) = {
                let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                let eligible: HashSet<_> = state
                    .members
                    .keys()
                    .copied()
                    .filter(|id| {
                        *id == member
                            || state
                                .publishers
                                .get(&change.publisher)
                                .is_none_or(|publisher| publisher.cursor(*id) <= change.gsn)
                    })
                    .collect();
                (state.members.clone(), state.generation, eligible)
            };
            if snapshot.values().any(|member| !member.ready) {
                return false;
            }
            let mut reporters = HashMap::new();
            if let Some(sample) = sample {
                for (&id, callbacks) in &snapshot {
                    if !eligible.contains(&id) {
                        continue;
                    }
                    let Some(watch) = &callbacks.loss_watch else {
                        continue;
                    };
                    match watch(sample.writer, sample.seq) {
                        LossWatchResult::Ticket(ticket) => {
                            reporters.insert(id, ticket);
                        }
                        LossWatchResult::Unmatched => {}
                        LossWatchResult::Full => return false,
                    }
                }
                let Some(ticket) = sample.reporter.claim(sample.seq, false) else {
                    return false;
                };
                reporters.insert(member, ticket);
            }
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.generation != generation {
                continue;
            }

            if !state.members.contains_key(&member)
                || first.is_some_and(|first| first == 0 || first > change.gsn)
            {
                return false;
            }
            let members = state.members.clone();
            let current: Vec<_> = members.keys().copied().collect();
            let publisher = state.publishers.entry(change.publisher).or_default();
            let start = publisher.next.max(1);
            publisher
                .progress
                .entry(member)
                .or_insert_with(|| Progress::new(start, start));
            let stale = change.gsn < publisher.cursor(member);
            if stale
                && !repair.is_some_and(|repair| {
                    first == Some(repair.first) && publisher.owns_repair(member, change, repair)
                })
            {
                return false;
            }
            let cohort: HashSet<_> = current
                .into_iter()
                .filter(|id| publisher.cursor(*id) <= change.gsn)
                .collect();
            publisher
                .cohorts
                .entry(change.gsn)
                .or_insert(cohort)
                .insert(member);
            publisher
                .reserved
                .entry(change.gsn)
                .or_default()
                .insert(token, member);
            if let Some(sample) = sample {
                publisher
                    .sample_writers
                    .entry(change.gsn)
                    .or_insert((sample.writer, sample.seq));
                let losses = publisher.losses.entry(change.gsn).or_default();
                for (id, reporter) in reporters {
                    if publisher.cohorts[&change.gsn].contains(&id) {
                        losses.entry(id).or_insert(reporter);
                    }
                }
            }
            if let Some(first) = first {
                // Opening a later coherent set proves the earlier source sets
                // ended. A later member of this SAME set proves no such boundary.
                publisher.source_closed_through = publisher.source_closed_through.max(first - 1);
                publisher
                    .coherent_owners
                    .insert(token, (first, change.writer_set));
            } else {
                // A real ordinary header is outside a coherent interval: earlier
                // sets ended at the sender, even while this owner awaits release.
                // This is closure evidence, never a writer receipt or a GAP.
                publisher.source_closed_through = publisher
                    .source_closed_through
                    .max(change.gsn.saturating_sub(1));
            }
            publisher.observe(change.gsn, &members);
            // A received header for a validated writerSet witnesses its boundary
            // even if its coherent payload is later discarded after writer loss.
            // An unknown writerSet cannot extend another roster's terminal proof.
            if let Some((through, _)) = publisher.terminal_epochs.get_mut(&change.writer_set) {
                *through = (*through).max(change.gsn);
            }
            publisher.refresh_fences(change.publisher, &members, &mut retired);
            drop(state);
            drop(retired);
            return true;
        }
    }

    pub fn stale(&self, change: OrderedGroupChange, member: MemberId) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        state.members.contains_key(&member)
            && state
                .publishers
                .get(&change.publisher)
                .is_some_and(|publisher| change.gsn < publisher.cursor(member))
    }

    pub fn release_reservation(&self, change: OrderedGroupChange, token: u64) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(publisher) = state.publishers.get_mut(&change.publisher) {
            publisher.coherent_owners.remove(&token);
            publisher.lifespans.remove(&token);
            if let Some(reserved) = publisher.reserved.get_mut(&change.gsn) {
                reserved.remove(&token);
                if reserved.is_empty() {
                    publisher.reserved.remove(&change.gsn);
                }
            }
            if !publisher.reserved.contains_key(&change.gsn)
                && !publisher.pending.contains_key(&change.gsn)
            {
                publisher.cohorts.remove(&change.gsn);
                publisher.sample_writers.remove(&change.gsn);
                publisher.losses.remove(&change.gsn);
            }
        }
    }

    pub fn deposit(
        &self,
        id: MemberId,
        writer: [u8; 16],
        change: OrderedGroupChange,
        payload: OrderedPayload,
    ) {
        let _delivering = super::notices::Delivering::enter();
        // The lifespan deadline is activated below, in the same critical
        // section that makes the payload pending: a publication running
        // between the two could find a due deadline whose payload is not
        // pending yet and disarm it, so the sample would never expire.
        let owner = payload.token.as_ref().map(|token| token.owner_id());
        // Freeze validated discovery views at acceptance, including while a
        // bracket suppresses publication. Later roster churn cannot strand an
        // already queued change of an older writerSet epoch.
        #[cfg(test)]
        run_deposit_window_hook();
        let members = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .members
            .clone();
        let views: Vec<_> = members
            .iter()
            .filter_map(|(&member, callbacks)| {
                let view = (callbacks.roster)(change.publisher)?;
                (crate::protocol::group::group_digest(view.iter().map(|(entity, _)| *entity))
                    == change.writer_set)
                    .then_some((member, view))
            })
            .collect();
        let terminal = terminal_proof(change.publisher, &members, &views);
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.members.contains_key(&id) {
            return;
        }
        let active: HashSet<_> = state.members.keys().copied().collect();
        let durable: Vec<_> = state
            .members
            .iter()
            .filter_map(|(&id, member)| member.durable.then_some(id))
            .collect();
        let publisher = state.publishers.entry(change.publisher).or_default();
        if change.gsn < publisher.cursor(id) {
            return;
        }
        if !views.is_empty()
            && publisher
                .current_epoch
                .is_none_or(|(gsn, _)| change.gsn >= gsn)
        {
            publisher.current_epoch = Some((change.gsn, change.writer_set));
        }
        if let Some(cells) = terminal {
            let proof = publisher
                .terminal_epochs
                .entry(change.writer_set)
                .or_insert((0, Vec::new()));
            if change.gsn >= proof.0 {
                *proof = (change.gsn, cells);
            }
        }
        let epoch = publisher.epochs.entry(change.writer_set).or_default();
        for (member, view) in views {
            epoch.entry(member).or_insert(view);
        }
        publisher
            .advanced
            .entry((writer, id))
            .and_modify(|gsn| *gsn = (*gsn).max(change.gsn))
            .or_insert(change.gsn);
        let frozen = publisher
            .cohorts
            .get(&change.gsn)
            .cloned()
            .unwrap_or_else(|| members.keys().copied().collect());
        let owed: HashSet<_> = frozen
            .into_iter()
            .chain(durable)
            .filter(|id| active.contains(id) && publisher.cursor(*id) <= change.gsn)
            .collect();
        publisher
            .cohorts
            .entry(change.gsn)
            .or_insert_with(|| owed.clone())
            .extend(owed.iter().copied());
        publisher.prune_terminal_epochs();
        let pending = publisher
            .pending
            .entry(change.gsn)
            .or_insert_with(|| Change {
                writer,
                writer_set: change.writer_set,
                payloads: BTreeMap::new(),
                members: owed,
            });
        pending.members.insert(id);
        // The receive gate already rejects a duplicate writer SN. Keep its
        // first accepted storage if a concurrent discovery flush repeats it.
        if let std::collections::btree_map::Entry::Vacant(entry) = pending.payloads.entry(id) {
            entry.insert(payload);
            if let Some(lifespan) = owner.and_then(|owner| {
                state
                    .publishers
                    .get_mut(&change.publisher)
                    .and_then(|publisher| publisher.lifespans.get_mut(&owner))
            }) {
                lifespan.active = true;
            }
        } else {
            drop(state);
            drop(payload);
        }
    }

    pub fn heartbeat(
        &self,
        publisher: PublisherKey,
        writer: [u8; 16],
        info: [u64; 3],
        digest: Option<[u8; 4]>,
    ) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .publishers
            .entry(publisher)
            .or_default()
            .heartbeats
            .insert(writer, (info, digest));
    }

    pub fn gap(
        &self,
        publisher: PublisherKey,
        writer: [u8; 16],
        start: u64,
        end: u64,
        member: MemberId,
    ) {
        if start >= end {
            return;
        }
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.members.contains_key(&member) {
            return;
        }
        let publisher = state.publishers.entry(publisher).or_default();
        let next = publisher.cursor(member);
        if end <= next {
            return;
        }
        let ranges = publisher.gaps.entry((writer, member)).or_default();
        ranges.prune(next);
        ranges.insert(start.max(next), end);
    }

    /// Native reliability can forget a GROUP proof only after this reader
    /// passed its exclusive end. Another cohort's horizon proves nothing here.
    pub fn gap_consumed(&self, publisher: PublisherKey, member: MemberId, end: u64) -> bool {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(reader) = state.members.get(&member) else {
            // A removed ordering member no longer owns a repair obligation.
            return true;
        };
        reader.ready
            && state
                .publishers
                .get(&publisher)
                .and_then(|publisher| publisher.progress.get(&member))
                .is_some_and(|progress| progress.next >= end)
    }

    /// No-payload controls are proof metadata, bounded independently of samples.
    /// Refusal happens before receipt credit, so RELIABLE can repair the marker
    /// after an older prefix releases its intervals. Current recipients own
    /// the proof immediately, even while an access bracket suppresses release.
    pub fn accounted(&self, member: MemberId, change: OrderedGroupChange) -> bool {
        const MAX_CONTROL_RANGES: usize = 512;
        let members = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .members
            .clone();
        let views: Vec<_> = members
            .iter()
            .filter_map(|(&id, member)| {
                let view = (member.roster)(change.publisher)?;
                (crate::protocol::group::group_digest(view.iter().map(|(entity, _)| *entity))
                    == change.writer_set)
                    .then_some((id, view))
            })
            .collect();
        let terminal = terminal_proof(change.publisher, &members, &views);
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // The requesting source must own a current ordering member before
        // its marker is credited. Otherwise there is nowhere to retain the
        // proof for that reader, and its later DATA repair could stall.
        if !state.members.contains_key(&member) {
            return false;
        }
        let active: Vec<_> = state.members.keys().copied().collect();
        let publisher = state.publishers.entry(change.publisher).or_default();
        for &id in &active {
            let next = publisher.next.max(1);
            publisher
                .progress
                .entry(id)
                .or_insert_with(|| Progress::new(next, next));
        }
        let end = change.gsn.saturating_add(1);
        // Check every recipient before assigning any proof. Adjacent facts
        // merge, so a contiguous stream needs one range regardless of length.
        for &id in &active {
            if change.gsn < publisher.cursor(id) {
                continue;
            }
            if let Some(ranges) = publisher.settled.get(&id) {
                let joins_before = ranges
                    .range(..=change.gsn)
                    .next_back()
                    .is_some_and(|(_, through)| *through >= change.gsn);
                let joins_after = ranges
                    .range(change.gsn..)
                    .next()
                    .is_some_and(|(start, _)| *start <= end);
                if ranges.len() >= MAX_CONTROL_RANGES && !joins_before && !joins_after {
                    return false;
                }
            }
        }
        if !views.is_empty()
            && publisher
                .current_epoch
                .is_none_or(|(gsn, _)| change.gsn >= gsn)
        {
            publisher.current_epoch = Some((change.gsn, change.writer_set));
        }
        if let Some(cells) = terminal {
            let proof = publisher
                .terminal_epochs
                .entry(change.writer_set)
                .or_insert((0, Vec::new()));
            if change.gsn >= proof.0 {
                *proof = (change.gsn, cells);
            }
        }
        publisher.prune_terminal_epochs();
        for id in active {
            if change.gsn >= publisher.cursor(id) {
                merge_interval(publisher.settled.entry(id).or_default(), change.gsn, end);
            }
        }
        true
    }

    pub fn settled(&self, id: MemberId, writer: [u8; 16], change: OrderedGroupChange) {
        let members = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .members
            .clone();
        // A delivered change also classifies its writer. A peer explicitly
        // unmatched with that writer owes no copy; a matching late reader
        // still owes its own retained payload. Discovery runs unlocked.
        let irrelevant: Vec<_> = members
            .iter()
            .filter_map(|(&peer, member)| {
                let view = (member.roster)(change.publisher)?;
                (crate::protocol::group::group_digest(view.iter().map(|(entity, _)| *entity))
                    == change.writer_set
                    && !view
                        .iter()
                        .any(|(entity, matched)| writer[12..] == *entity && *matched))
                .then_some(peer)
            })
            .collect();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.members.contains_key(&id) {
            return;
        }
        let state_members = state.members.clone();
        let active: HashSet<_> = state_members.keys().copied().collect();
        let publisher = state.publishers.entry(change.publisher).or_default();
        publisher.observe(change.gsn, &state_members);
        publisher.source_advanced(id, writer, change.gsn);
        publisher.source_closed_through = publisher.source_closed_through.max(change.gsn);
        for peer in std::iter::once(id)
            .chain(irrelevant)
            .filter(|peer| active.contains(peer))
        {
            if change.gsn < publisher.cursor(peer) {
                continue;
            }
            if peer != id
                && (publisher
                    .reserved
                    .get(&change.gsn)
                    .is_some_and(|reserved| reserved.values().any(|member| *member == peer))
                    || publisher
                        .pending
                        .get(&change.gsn)
                        .is_some_and(|pending| pending.payloads.contains_key(&peer)))
            {
                continue;
            }
            let ranges = publisher.settled.entry(peer).or_default();
            let mut start = change.gsn;
            let mut end = start.saturating_add(1);
            if let Some((&before, &through)) = ranges.range(..=start).next_back() {
                if through >= start {
                    start = before;
                    end = end.max(through);
                    ranges.remove(&before);
                }
            }
            while let Some((&after, &through)) = ranges.range(start..).next() {
                if after > end {
                    break;
                }
                end = end.max(through);
                ranges.remove(&after);
            }
            ranges.insert(start, end);
        }
    }

    /// A no-payload marker reached its reader's contiguous receipt prefix.
    pub fn control_prefix(&self, id: MemberId, writer: [u8; 16], change: OrderedGroupChange) {
        let _delivering = super::notices::Delivering::enter();
        let mut retired = Vec::new();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if !state.members.contains_key(&id) {
            return;
        }
        let members = state.members.clone();
        let publisher = state.publishers.entry(change.publisher).or_default();
        publisher.observe(change.gsn, &members);
        publisher.source_advanced(id, writer, change.gsn);
        publisher.refresh_fences(change.publisher, &members, &mut retired);
        drop(state);
        drop(retired);
    }

    /// A later Publisher change must leave room for its unknown predecessor.
    /// The caller already holds its writer's receive gate and established an
    /// in-order writer prefix, so accepting it advances that writer atomically.
    pub fn needs_predecessor_room(
        &self,
        writer: [u8; 16],
        change: OrderedGroupChange,
        member: MemberId,
    ) -> usize {
        let (members, next, advanced, heartbeats, gaps, epoch) = {
            let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            let Some(publisher) = state.publishers.get(&change.publisher) else {
                return usize::from(
                    change.gsn > 1 && state.members.values().any(|member| member.reliable),
                );
            };
            let pending = publisher
                .reserved
                .range(..change.gsn)
                .flat_map(|(_, reserved)| reserved.values())
                .filter(|&&id| id == member)
                .count();
            if pending > 0 {
                // Staged members do not account for a genuinely missing
                // predecessor that has not reserved its own place yet.
                return pending.saturating_add(1);
            }
            (
                state.members.clone(),
                publisher.cursor(member),
                publisher.advanced.clone(),
                publisher.heartbeats.clone(),
                publisher.gaps.clone(),
                publisher
                    .epochs
                    .get(&change.writer_set)
                    .cloned()
                    .unwrap_or_default(),
            )
        };
        if change.gsn <= next {
            return 0;
        }
        let mut required = HashSet::new();
        let mut proof_digest = None;
        for (id, member) in members.iter().filter(|(id, _)| **id == member) {
            let view = (member.roster)(change.publisher).or_else(|| epoch.get(id).cloned());
            let Some(view) = view else { return 1 };
            let digest =
                crate::protocol::group::group_digest(view.iter().map(|(entity, _)| *entity));
            let explicit = heartbeats
                .values()
                .any(|(info, announced)| info[0] >= change.gsn && *announced == Some(digest));
            if digest != change.writer_set && !explicit && !epoch.contains_key(id) {
                return 1;
            }
            if proof_digest.is_some_and(|before| before != digest) {
                return 1;
            }
            proof_digest = Some(digest);
            if member.reliable {
                for (entity, matched) in view {
                    if matched {
                        let mut guid = change.publisher;
                        guid[12..].copy_from_slice(&entity);
                        required.insert((guid, *id));
                    }
                }
            }
        }
        let Some(digest) = proof_digest else {
            return 1;
        };
        if required.is_empty() {
            return 0;
        }
        if !heartbeats.values().any(|(info, announced)| {
            info[0] >= change.gsn && announced.is_none_or(|announced| announced == digest)
        }) {
            return 1;
        }
        usize::from(required.into_iter().any(|(other, reader)| {
            if (other == writer && reader == member)
                || advanced
                    .get(&(other, reader))
                    .is_some_and(|&gsn| gsn >= change.gsn)
            {
                return false;
            }
            if gaps
                .get(&(other, reader))
                .is_some_and(|ranges| ranges.through(next).is_some_and(|end| end >= change.gsn))
            {
                return false;
            }
            !heartbeats.get(&other).is_some_and(|&(info, announced)| {
                announced.is_none_or(|announced| announced == digest)
                    && info[0] >= change.gsn
                    && (info[1] >= change.gsn || info[2] < next)
            })
        }))
    }

    /// Resolve discovery with no queue lock held, then select a contiguous
    /// prefix. No reader callback runs while either state mutex is held.
    pub fn release(&self) -> Vec<(Deliver, [u8; 16], OrderedDelivery)> {
        loop {
            let (members, keys, generation) = {
                let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
                if state.members.values().any(|member| !member.ready) {
                    return Vec::new();
                }
                (
                    state.members.clone(),
                    state.publishers.keys().copied().collect::<Vec<_>>(),
                    state.generation,
                )
            };
            let mut rosters = HashMap::new();
            for key in keys {
                rosters.insert(
                    key,
                    members
                        .iter()
                        .map(|(&id, member)| (id, (member.roster)(key)))
                        .collect::<Vec<_>>(),
                );
            }
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            if state.generation != generation {
                continue;
            }
            let active: HashSet<_> = state.members.keys().copied().collect();
            let mut deliveries = Vec::new();
            let mut proof_notices = Vec::new();
            let mut discarded = Vec::new();
            let mut retired = Vec::new();
            for (key, publisher) in &mut state.publishers {
                publisher.next = publisher.next.max(1);
                for id in &active {
                    let start = publisher.next;
                    publisher
                        .progress
                        .entry(*id)
                        .or_insert_with(|| Progress::new(start, start));
                }
                loop {
                    publisher.retire_unavailable_copies(&members, &mut proof_notices);
                    let mut advanced = false;
                    for (&id, progress) in &mut publisher.progress {
                        let end = publisher
                            .settled
                            .get(&id)
                            .and_then(|ranges| ranges.range(..=progress.next).next_back())
                            .filter(|(_, end)| progress.next < **end)
                            .map(|(_, end)| *end);
                        if let Some(end) = end {
                            progress.next = end;
                            advanced = true;
                        }
                    }
                    publisher.update_high_water();
                    if advanced {
                        continue;
                    }
                    if let Some(answers) = rosters.get(key) {
                        if publisher.close_history(*key, &members, answers) {
                            continue;
                        }
                    }
                    if let Some(answers) = rosters.get(key) {
                        if publisher.advance_settled_boundary(*key, &members, answers) {
                            continue;
                        }
                    }
                    let floor = publisher.floor();
                    let Some((&gsn, pending)) = publisher.pending.first_key_value() else {
                        break;
                    };
                    let ordinary = !publisher.reserved.get(&gsn).is_some_and(|owners| {
                        owners
                            .keys()
                            .any(|owner| publisher.coherent_owners.contains_key(owner))
                    });
                    let Some(answers) = rosters.get(key) else {
                        break;
                    };
                    let participant = publisher.participant_departure.clone();
                    let participant_guard = participant.as_ref().and_then(|cell| {
                        crate::engine::demux::GroupWriterTerminal::all_participant_departed(
                            std::slice::from_ref(cell),
                        )
                    });
                    if publisher
                        .reserved
                        .range(..=gsn)
                        .any(|(&reserved_gsn, owners)| {
                            owners.values().any(|id| {
                                publisher.cursor(*id) <= reserved_gsn
                                    && (reserved_gsn < gsn || !pending.payloads.contains_key(id))
                            })
                        })
                    {
                        break;
                    }
                    let mut required: HashMap<[u8; 16], HashSet<MemberId>> = HashMap::new();
                    let mut expected = HashSet::new();
                    let mut complete = true;
                    let mut epoch = publisher
                        .epochs
                        .get(&pending.writer_set)
                        .cloned()
                        .unwrap_or_default();
                    for (id, answer) in answers {
                        if !active.contains(id) {
                            continue;
                        }
                        if let Some(answer) = answer {
                            if crate::protocol::group::group_digest(
                                answer.iter().map(|(entity, _)| *entity),
                            ) == pending.writer_set
                            {
                                if publisher
                                    .current_epoch
                                    .is_none_or(|(known, _)| gsn >= known)
                                {
                                    publisher.current_epoch = Some((gsn, pending.writer_set));
                                }
                                epoch.entry(*id).or_insert_with(|| answer.clone());
                                publisher
                                    .epochs
                                    .entry(pending.writer_set)
                                    .or_default()
                                    .entry(*id)
                                    .or_insert_with(|| answer.clone());
                            }
                        }
                    }
                    // A contiguous change already has its predecessor committed;
                    // roster completeness is required only to prove a missing one.
                    if gsn <= floor {
                        for (id, answer) in answers {
                            if let Some(answer) = answer {
                                epoch.entry(*id).or_insert_with(|| answer.clone());
                            }
                        }
                    }
                    if participant_guard.is_some() && gsn <= floor {
                        // Participant departure proves absent writers independently
                        // of an unavailable discovery digest. Real owners remain.
                        epoch = active.iter().map(|id| (*id, Vec::new())).collect();
                    }
                    let proof_members: HashSet<_> = pending
                        .members
                        .iter()
                        .copied()
                        .chain(
                            active
                                .iter()
                                .copied()
                                .filter(|id| gsn > floor && publisher.cursor(*id) == floor),
                        )
                        .collect();
                    if proof_members
                        .iter()
                        .any(|id| active.contains(id) && !epoch.contains_key(id))
                    {
                        // A current PIM heartbeat, or a PSM heartbeat paired
                        // with a validated newer DATA epoch, can establish the
                        // complete roster after an unknown historical epoch left.
                        let current: Option<HashMap<_, _>> = answers
                            .iter()
                            .filter(|(id, _)| active.contains(id) && proof_members.contains(id))
                            .map(|(id, view)| Some((*id, view.clone()?)))
                            .collect();
                        let Some(current) = current else { break };
                        let Some(first) = current.values().next() else {
                            break;
                        };
                        let digest = crate::protocol::group::group_digest(
                            first.iter().map(|(entity, _)| *entity),
                        );
                        let known_current = publisher
                            .current_epoch
                            .is_some_and(|(known_gsn, known)| known_gsn >= gsn && known == digest)
                            && publisher.epochs.get(&digest).is_some_and(|known| {
                                current.keys().all(|id| known.contains_key(id))
                            });
                        if current.values().any(|view| {
                            crate::protocol::group::group_digest(
                                view.iter().map(|(entity, _)| *entity),
                            ) != digest
                        }) || !publisher
                            .heartbeats
                            .iter()
                            .any(|(writer, (info, announced))| {
                                info[0] >= gsn
                                    && (announced == &Some(digest)
                                        || (announced.is_none() && known_current))
                                    && first.iter().any(|(entity, _)| writer[12..] == *entity)
                            })
                        {
                            break;
                        }
                        epoch = current;
                    }
                    let Some(first) = epoch.values().next() else {
                        break;
                    };
                    let proof_digest = crate::protocol::group::group_digest(
                        first.iter().map(|(entity, _)| *entity),
                    );
                    for (&id, view) in epoch.iter() {
                        if !active.contains(&id) || publisher.cursor(id) > gsn {
                            continue;
                        }
                        for &(entity, matched) in view {
                            if !matched {
                                continue;
                            }
                            let mut writer = *key;
                            writer[12..].copy_from_slice(&entity);
                            let still_matched = answers
                                .iter()
                                .find(|(member, _)| *member == id)
                                .and_then(|(_, view)| view.as_ref())
                                .is_none_or(|view| {
                                    view.iter().any(|&(now, matched)| now == entity && matched)
                                });
                            if !still_matched {
                                continue;
                            }
                            if writer == pending.writer
                                && pending.members.contains(&id)
                                && members.get(&id).is_some_and(|member| member.reliable)
                            {
                                expected.insert(id);
                            }
                            if publisher.cursor(id) == floor
                                && members.get(&id).is_some_and(|member| member.reliable)
                            {
                                required.entry(writer).or_default().insert(id);
                            }
                        }
                    }
                    if gsn > floor {
                        // RTPS 2.5 8.7.5 requires one current heartbeat and
                        // complete discovery before absence can advance a hole.
                        if !required.is_empty()
                            && !publisher.heartbeats.values().any(|(info, digest)| {
                                info[0] >= gsn && digest.is_none_or(|digest| digest == proof_digest)
                            })
                        {
                            break;
                        }
                        let mut until = publisher
                            .reserved
                            .range(floor..gsn)
                            .find(|(_, reserved)| {
                                reserved.values().any(|id| publisher.cursor(*id) == floor)
                            })
                            .map_or(gsn, |(&reserved, _)| reserved);
                        if until == floor {
                            break;
                        }
                        for (writer, member) in required
                            .iter()
                            .flat_map(|(writer, members)| {
                                members.iter().map(move |member| (writer, member))
                            })
                            .filter(|(_, member)| publisher.cursor(**member) == floor)
                        {
                            let hole = floor;
                            // Each payload left its writer's reorder gate before
                            // entering this Subscriber history, so it proves that
                            // writer advanced past every earlier GSN.
                            if publisher
                                .advanced
                                .get(&(*writer, *member))
                                .is_some_and(|&advanced| advanced >= gsn)
                            {
                                continue;
                            }
                            if let Some(end) = publisher
                                .gaps
                                .get(&(*writer, *member))
                                .and_then(|ranges| ranges.through(hole))
                            {
                                until = until.min(end);
                                continue;
                            }
                            let Some(&([current, first, last], digest)) =
                                publisher.heartbeats.get(writer)
                            else {
                                complete = false;
                                break;
                            };
                            if digest.is_some_and(|digest| digest != proof_digest)
                                || current <= hole
                                || (first <= hole && hole <= last)
                            {
                                complete = false;
                                break;
                            }
                            until =
                                until
                                    .min(current)
                                    .min(if hole < first { first } else { current });
                        }
                        if !complete || until <= floor {
                            break;
                        }
                        publisher.advance(floor, until);
                        continue;
                    }
                    if expected.iter().any(|id| !pending.payloads.contains_key(id)) {
                        break;
                    }
                    debug_assert!(
                        publisher.pending.contains_key(&gsn),
                        "a checked pending change is still held"
                    );
                    let Some(pending) = publisher.pending.remove(&gsn) else {
                        break;
                    };
                    if ordinary {
                        publisher.source_closed_through = publisher.source_closed_through.max(gsn);
                    }
                    for progress in publisher.progress.values_mut() {
                        if progress.next <= gsn {
                            progress.next = gsn.saturating_add(1);
                        }
                    }
                    publisher.update_high_water();
                    for (id, payload) in pending.payloads {
                        if let Some(member) = members.get(&id).filter(|_| active.contains(&id)) {
                            deliveries.push((
                                member.deliver.clone(),
                                pending.writer,
                                OrderedDelivery::Data(payload),
                            ));
                        } else {
                            discarded.push(payload);
                        }
                    }
                }
                let reserved = &publisher.reserved;
                let pending = &publisher.pending;
                publisher
                    .cohorts
                    .retain(|gsn, _| reserved.contains_key(gsn) || pending.contains_key(gsn));
                publisher
                    .sample_writers
                    .retain(|gsn, _| publisher.cohorts.contains_key(gsn));
                publisher
                    .losses
                    .retain(|gsn, _| publisher.cohorts.contains_key(gsn));
                publisher.refresh_fences(*key, &members, &mut retired);
                for (&id, ranges) in &mut publisher.settled {
                    let next = publisher
                        .progress
                        .get(&id)
                        .map_or(publisher.next, |progress| progress.next);
                    ranges.retain(|_, end| *end > next);
                }
                publisher.settled.retain(|_, ranges| !ranges.is_empty());
                for ((_, id), ranges) in &mut publisher.gaps {
                    let next = publisher
                        .progress
                        .get(id)
                        .map_or(publisher.next, |progress| progress.next);
                    ranges.prune(next);
                }
                publisher.gaps.retain(|_, ranges| !ranges.is_empty());
                let pending_epochs: HashSet<_> = publisher
                    .pending
                    .values()
                    .map(|change| change.writer_set)
                    .collect();
                publisher.epochs.retain(|digest, _| {
                    pending_epochs.contains(digest)
                        || publisher
                            .current_epoch
                            .is_some_and(|(_, current)| current == *digest)
                });
                publisher.terminal_epochs.retain(|digest, _| {
                    pending_epochs.contains(digest)
                        || publisher
                            .current_epoch
                            .is_some_and(|(_, current)| current == *digest)
                });
                if let Some(answers) = rosters.get(key) {
                    if answers.iter().all(|(_, answer)| answer.is_some()) {
                        let known: HashSet<_> = answers
                            .iter()
                            .flat_map(|(_, answer)| answer.as_ref().into_iter().flatten())
                            .map(|(entity, _)| {
                                let mut writer = *key;
                                writer[12..].copy_from_slice(entity);
                                writer
                            })
                            .collect();
                        publisher.advanced.retain(|(writer, member), _| {
                            known.contains(writer) && active.contains(member)
                        });
                        publisher
                            .heartbeats
                            .retain(|writer, _| known.contains(writer));
                        publisher.gaps.retain(|(writer, member), _| {
                            known.contains(writer) && active.contains(member)
                        });
                    }
                }
            }
            drop(state);
            drop(discarded);
            drop(retired);
            for (callback, proof) in proof_notices {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(proof)))
                    .is_err()
                {
                    log::error!("[PRESENTATION] an unavailable-copy notification panicked");
                }
            }
            return deliveries;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn losing_one_copy_does_not_waive_that_readers_unknown_predecessor() {
        let order = WireOrder::default();
        let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
        order.set_clock(clock.clone());
        let key = [0x4c; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = key;
        wa[12..].copy_from_slice(&a);
        let mut wb = key;
        wb[12..].copy_from_slice(&b);
        let change = |gsn| OrderedGroupChange {
            publisher: key,
            gsn,
            writer_set: crate::protocol::group::group_digest([a, b]),
        };
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
        );
        order.attach(
            1,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, false), (b, true)])),
            true,
        );
        for (member, token) in [(0, 20), (1, 21)] {
            assert!(order.reserve(change(2), token, member));
            order.deposit(
                member,
                wb,
                change(2),
                OrderedPayload {
                    payload: PendingPayload::nothing(1),
                    token: None,
                },
            );
        }
        order.reserve_lifespan(
            change(2),
            20,
            0,
            order.lifespan_deadline(std::time::Duration::from_nanos(1)),
        );
        order.activate_lifespan(20);
        clock.advance(std::time::Duration::from_nanos(1));
        assert_eq!(order.expire_lifespans().len(), 1);
        order.release_reservation(change(2), 20);
        order.heartbeat(key, wb, [2, 2, 2], Some(change(2).writer_set));
        order.heartbeat(key, wa, [2, 1, 1], Some(change(2).writer_set));
        assert!(
            order.release().is_empty(),
            "the surviving copy bypassed another reader's retained A1"
        );
        order.deposit(
            0,
            wa,
            change(1),
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        let released = order.release();
        assert_eq!(released.len(), 2);
        assert_eq!(released[0].1, wa);
        assert_eq!(released[1].1, wb);
        order.release_reservation(change(2), 21);
    }

    #[test]
    fn a_full_loss_watch_never_publishes_a_new_copy_obligation() {
        let order = WireOrder::default();
        let key = [0x49; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut writer = key;
        writer[12..].copy_from_slice(&b);
        let change = OrderedGroupChange {
            publisher: key,
            gsn: 2,
            writer_set: crate::protocol::group::group_digest([a, b]),
        };
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
        );
        let context = LossContext {
            writer,
            seq: 1,
            reporter: Arc::default(),
        };
        assert!(order.reserve_sample(change, 90, 0, None, None, &context));
        order.deposit(
            0,
            writer,
            change,
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        order.release_reservation(change, 90);
        order.attach_pending_reader(
            1,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
            true,
            Weak::new(),
        );
        assert!(!order.attach_loss_watch(1, Arc::new(|_, _| LossWatchResult::Full)));
        assert!(
            !order.0.lock().unwrap().publishers[&key].pending[&2]
                .members
                .contains(&1),
            "a failed metadata reservation published copy debt"
        );
        assert!(
            order.release().is_empty(),
            "a provisional reader was visible during construction"
        );
        order.forget(1);
        let mut wa = key;
        wa[12..].copy_from_slice(&a);
        order.heartbeat(key, wa, [2, 2, 2], Some(change.writer_set));
        order.heartbeat(key, writer, [2, 2, 2], Some(change.writer_set));
        assert_eq!(
            order.release().len(),
            1,
            "failed reader construction stranded accepted data"
        );
    }

    #[test]
    fn a_missing_historical_copy_ends_on_its_own_gap_or_heartbeat() {
        for proof in [0, 1, 2, 3] {
            let order = WireOrder::default();
            let key = [0x4b; 16];
            let entity = [0, 0, 1, 2];
            let mut writer = key;
            writer[12..].copy_from_slice(&entity);
            let change = OrderedGroupChange {
                publisher: key,
                gsn: 1,
                writer_set: crate::protocol::group::group_digest([entity]),
            };
            order.attach(
                0,
                Arc::new(|_, _| {}),
                Arc::new(move |_| Some(vec![(entity, true)])),
                true,
            );
            let context = LossContext {
                writer,
                seq: 1,
                reporter: Arc::default(),
            };
            assert!(order.reserve_sample(change, 91, 0, None, None, &context));
            order.deposit(
                0,
                writer,
                change,
                OrderedPayload {
                    payload: PendingPayload::nothing(1),
                    token: None,
                },
            );
            order.release_reservation(change, 91);
            order.attach_pending_reader(
                1,
                Arc::new(|_, _| {}),
                Arc::new(move |_| Some(vec![(entity, true)])),
                true,
                true,
                Weak::new(),
            );
            let ledger = Arc::new(super::super::subscriber::LossLedger::default());
            let reports = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = reports.clone();
            order.attach_history(
                1,
                Arc::new(move |proof| {
                    if let HistoryProof::KnownOwed { ticket } = proof {
                        observed.fetch_add(
                            ticket.mark_lost() as usize,
                            std::sync::atomic::Ordering::SeqCst,
                        );
                    }
                    true
                }),
            );
            let externally_lost = ledger.claim(1, false).unwrap();
            assert!(order.attach_loss_watch(
                1,
                Arc::new(move |_, seq| {
                    ledger
                        .claim(seq, false)
                        .map_or(LossWatchResult::Full, LossWatchResult::Ticket)
                })
            ));
            assert!(
                order.release().is_empty(),
                "missing retained copy was waived without proof"
            );
            match proof {
                0 => order.heartbeat(key, writer, [2, 2, 2], Some(change.writer_set)),
                1 => order.gap(key, writer, 1, 2, 1),
                3 => externally_lost.mark_delivered(),
                _ => {
                    // The real WriterSN heartbeat/GAP path terminalizes this
                    // exact owed ticket even without optional GROUP_INFO.
                    reports.fetch_add(
                        externally_lost.mark_lost() as usize,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                }
            }
            assert_eq!(
                order.release().len(),
                1,
                "unavailable copy blocked a retained real payload"
            );
            assert_eq!(
                reports.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(proof != 3)
            );
            assert!(order.release().is_empty());
            assert_eq!(
                reports.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(proof != 3),
                "the same owed copy was counted twice"
            );
        }
    }

    #[test]
    fn contiguous_future_controls_use_one_range_until_the_predecessor_arrives() {
        let order = WireOrder::default();
        let publisher = [0x65; 16];
        let entity = [0, 0, 1, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&entity);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(entity, true)])),
            true,
        );
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: crate::protocol::group::group_digest([entity]),
        };
        for gsn in 2..=10_000 {
            order.accounted(0, change(gsn));
        }
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher]
                .settled
                .values()
                .map(BTreeMap::len)
                .sum::<usize>(),
            1
        );
        assert!(order.release().is_empty());
        assert_eq!(
            {
                let state = order.0.lock().unwrap();
                let publisher = &state.publishers[&publisher];
                publisher.settled.values().map(BTreeMap::len).sum::<usize>()
            },
            1
        );
        order.deposit(
            0,
            writer,
            change(1),
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        assert_eq!(order.release().len(), 1);
        let state = order.0.lock().unwrap();
        assert_eq!(state.publishers[&publisher].next, 10_001);
        assert!(state.publishers[&publisher].settled.is_empty());
    }

    #[test]
    fn a_future_gap_does_not_skip_an_unsettled_earlier_prefix() {
        let order = WireOrder::default();
        let publisher = [0x66; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = publisher;
        wa[12..].copy_from_slice(&a);
        let mut wb = publisher;
        wb[12..].copy_from_slice(&b);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
        );
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: crate::protocol::group::group_digest([a, b]),
        };
        order.deposit(
            0,
            wb,
            change(5),
            OrderedPayload {
                payload: PendingPayload::nothing(5),
                token: None,
            },
        );
        order.heartbeat(publisher, wa, [5, 1, 4], None);
        order.heartbeat(publisher, wb, [5, 5, 5], None);
        order.gap(publisher, wa, 3, 4, 0);
        assert!(order.release().is_empty());
        for gsn in [1, 2] {
            order.deposit(
                0,
                wa,
                change(gsn),
                OrderedPayload {
                    payload: PendingPayload::nothing(gsn),
                    token: None,
                },
            );
            let delivered = order.release();
            assert_eq!(delivered.len(), 1);
            assert_eq!(delivered[0].2.data().payload.remote_seq, gsn);
        }
        order.deposit(
            0,
            wa,
            change(4),
            OrderedPayload {
                payload: PendingPayload::nothing(4),
                token: None,
            },
        );
        assert_eq!(
            order
                .release()
                .iter()
                .map(|(_, _, payload)| payload.data().payload.remote_seq)
                .collect::<Vec<_>>(),
            [4, 5]
        );
    }

    #[test]
    fn a_lost_best_effort_copy_does_not_hold_a_reliable_reader() {
        let order = WireOrder::default();
        let publisher = [0x67; 16];
        let entity = [0, 0, 1, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&entity);
        for (id, reliable) in [(0, true), (1, false)] {
            order.attach(
                id,
                Arc::new(|_, _| {}),
                Arc::new(move |_| Some(vec![(entity, true)])),
                reliable,
            );
        }
        let change = OrderedGroupChange {
            publisher,
            gsn: 1,
            writer_set: crate::protocol::group::group_digest([entity]),
        };
        order.deposit(
            0,
            writer,
            change,
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        assert_eq!(order.release().len(), 1);
    }

    #[test]
    fn best_effort_arrivals_still_wait_for_a_matching_reliable_predecessor() {
        let order = WireOrder::default();
        let publisher = [0x68; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = publisher;
        wa[12..].copy_from_slice(&a);
        let mut wb = publisher;
        wb[12..].copy_from_slice(&b);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, false), (b, true)])),
            false,
        );
        order.attach(
            1,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, false)])),
            true,
        );
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: crate::protocol::group::group_digest([a, b]),
        };
        order.deposit(
            0,
            wb,
            change(2),
            OrderedPayload {
                payload: PendingPayload::nothing(2),
                token: None,
            },
        );
        assert!(order.release().is_empty());
        order.deposit(
            1,
            wa,
            change(1),
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        assert_eq!(
            order
                .release()
                .iter()
                .map(|(_, _, payload)| payload.data().payload.remote_seq)
                .collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn staged_members_leave_room_for_an_additional_unknown_member() {
        let order = WireOrder::default();
        let publisher = [0x64; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&b);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
        );
        let digest = crate::protocol::group::group_digest([a, b]);
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: digest,
        };
        assert!(order.reserve(change(1), 10, 0));
        assert!(order.reserve(change(3), 11, 0));
        let ring = crate::core::rt::IndexRing::with_capacity(8);
        let room = super::super::admission::HistoryRoom::new(&ring, 3);
        let keep = order.needs_predecessor_room(writer, change(5), 0);
        assert!(
            room.reserve(keep).is_none(),
            "a future value consumed the unknown member's place"
        );
        let earlier: Vec<_> = (0..3)
            .map(|_| room.reserve(0).expect("earlier coherent member"))
            .collect();
        drop(earlier);
    }

    #[test]
    fn an_admitted_predecessor_fences_absence_until_its_owner_finishes() {
        let order = WireOrder::default();
        let publisher = [0x62; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = publisher;
        wa[12..].copy_from_slice(&a);
        let mut wb = publisher;
        wb[12..].copy_from_slice(&b);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
        );
        let digest = crate::protocol::group::group_digest([a, b]);
        let earlier = OrderedGroupChange {
            publisher,
            gsn: 1,
            writer_set: digest,
        };
        assert!(order.reserve(earlier, 10, 0));
        let later = OrderedGroupChange { gsn: 2, ..earlier };
        order.deposit(
            0,
            wb,
            later,
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        order.heartbeat(publisher, wa, [2, 2, 1], None);
        order.heartbeat(publisher, wb, [2, 2, 2], None);
        assert!(
            order.release().is_empty(),
            "absence skipped admitted storage awaiting handoff"
        );
        order.release_reservation(earlier, 10);
        assert_eq!(order.release().len(), 1);
        assert!(
            !order.reserve(earlier, 11, 0),
            "post-proof stale admission went backwards"
        );
        order.deposit(
            0,
            wa,
            earlier,
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        assert!(order.release().is_empty());
    }

    #[test]
    fn progress_for_one_reader_cannot_skip_another_readers_copy() {
        let order = WireOrder::default();
        let publisher = [0x63; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = publisher;
        wa[12..].copy_from_slice(&a);
        let mut wb = publisher;
        wb[12..].copy_from_slice(&b);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
        );
        order.attach(
            1,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, false)])),
            true,
        );
        let digest = crate::protocol::group::group_digest([a, b]);
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: digest,
        };
        order.deposit(
            0,
            wa,
            change(3),
            OrderedPayload {
                payload: PendingPayload::nothing(2),
                token: None,
            },
        );
        order.deposit(
            0,
            wb,
            change(2),
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        order.heartbeat(publisher, wa, [3, 1, 3], None);
        order.heartbeat(publisher, wb, [3, 2, 2], None);
        assert!(
            order.release().is_empty(),
            "one reader's DATA progress skipped a sibling copy"
        );
        order.gap(publisher, wa, 1, 2, 0);
        assert!(
            order.release().is_empty(),
            "a targeted GAP advanced another reader"
        );
        order.gap(publisher, wa, 1, 2, 1);
        assert_eq!(order.release().len(), 1);
    }

    #[test]
    fn consumed_roster_epochs_and_departed_writers_do_not_accumulate() {
        let order = WireOrder::default();
        let mut publisher = [0x61; 16];
        publisher[12..].copy_from_slice(&[0, 0, 1, 8]);
        let entity = [0, 0, 2, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&entity);
        let roster = Arc::new(Mutex::new(vec![(entity, true)]));
        let source = roster.clone();
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(source.lock().unwrap().clone())),
            true,
        );
        for gsn in 1..=128 {
            let extra = [0, 1, u8::try_from(gsn).unwrap(), 2];
            *roster.lock().unwrap() = vec![(entity, true), (extra, false)];
            let digest = crate::protocol::group::group_digest([entity, extra]);
            let mut departed = publisher;
            departed[12..].copy_from_slice(&extra);
            order.heartbeat(publisher, departed, [gsn, gsn, gsn], None);
            order.gap(publisher, departed, 1, gsn + 1, 0);
            let change = OrderedGroupChange {
                publisher,
                gsn,
                writer_set: digest,
            };
            order.deposit(
                0,
                writer,
                change,
                OrderedPayload {
                    payload: PendingPayload::nothing(gsn),
                    token: None,
                },
            );
            assert_eq!(order.release().len(), 1);
            let state = order.0.lock().unwrap();
            let state = &state.publishers[&publisher];
            assert!(state.pending.is_empty());
            assert!(state.epochs.len() <= 1);
            assert!(state.heartbeats.len() <= 1);
            assert!(state.gaps.len() <= 1);
            assert!(state.advanced.len() <= 1);
        }
    }
    #[test]
    fn irrelevant_data_and_ecs_keep_one_bounded_recipient_union() {
        let order = WireOrder::default();
        let publisher = [0x68; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = publisher;
        wa[12..].copy_from_slice(&a);
        let mut wb = publisher;
        wb[12..].copy_from_slice(&b);
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: crate::protocol::group::group_digest([a, b]),
        };
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, false), (b, true)])),
            true,
        );
        order.heartbeat(publisher, wb, [2, 2, 2], None);
        order.deposit(
            0,
            wb,
            change(2),
            OrderedPayload {
                payload: PendingPayload::nothing(2),
                token: None,
            },
        );
        assert_eq!(order.release().len(), 1);
        order.attach_reader(
            1,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, false)])),
            true,
            true,
            Weak::new(),
        );
        for index in 1..=128 {
            let data = index * 2 + 1;
            order.settled(0, wb, change(data));
            assert!(order.accounted(0, change(data + 1)));
            // No release: an application may keep its access bracket open.

            let state = order.0.lock().unwrap();
            let publisher = &state.publishers[&publisher];
            assert_eq!(publisher.cursor(1), 1, "later B changes erased missing A1");
            let ranges = publisher.settled.get(&1).map_or(0, BTreeMap::len);
            assert!(
                ranges <= 2,
                "proof ranges grew with later coherent sets: {ranges}"
            );
        }
        order.heartbeat(publisher, wa, [258, 1, 1], None);
        order.deposit(
            1,
            wa,
            change(1),
            OrderedPayload {
                payload: PendingPayload::nothing(1),
                token: None,
            },
        );
        assert_eq!(order.release().len(), 1);
        let state = order.0.lock().unwrap();
        let publisher = &state.publishers[&publisher];
        assert_eq!(publisher.cursor(1), 259);
        assert!(publisher.settled.is_empty());
        assert!(publisher.cohorts.is_empty());
    }

    #[test]
    fn a_later_joiner_inherits_neither_data_nor_folded_control_credit() {
        let order = WireOrder::default();
        let publisher = [0x69; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = publisher;
        wa[12..].copy_from_slice(&a);
        let mut wb = publisher;
        wb[12..].copy_from_slice(&b);
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: crate::protocol::group::group_digest([a, b]),
        };
        let payload = |seq| OrderedPayload {
            payload: PendingPayload::nothing(seq),
            token: None,
        };
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, false), (b, true)])),
            true,
        );
        order.heartbeat(publisher, wb, [2, 2, 2], None);
        order.deposit(0, wb, change(2), payload(2));
        assert_eq!(order.release().len(), 1);
        order.attach_reader(
            1,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, false)])),
            true,
            true,
            Weak::new(),
        );
        order.settled(0, wb, change(3));
        order.accounted(0, change(4));
        assert!(order.release().is_empty());
        order.attach_reader(
            2,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, false), (b, true)])),
            true,
            true,
            Weak::new(),
        );
        order.heartbeat(publisher, wa, [4, 1, 1], None);
        order.heartbeat(publisher, wb, [4, 2, 4], None);
        order.deposit(2, wb, change(2), payload(2));
        order.deposit(1, wa, change(1), payload(1));
        assert_eq!(order.release().len(), 2);
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher].cursor(2),
            3,
            "new reader inherited another member's DATA credit"
        );
        order.deposit(2, wb, change(3), payload(3));
        assert_eq!(order.release().len(), 1);
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher].cursor(2),
            4,
            "new reader inherited a control it never learned"
        );
        order.accounted(0, change(4));
        assert!(order.release().is_empty());
        assert_eq!(order.0.lock().unwrap().publishers[&publisher].cursor(2), 5);
    }
    #[test]
    fn sparse_control_proofs_refuse_before_growing_and_repair_after_prefix_progress() {
        let order = WireOrder::default();
        let publisher = [0x70; 16];
        let entity = [0, 0, 1, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&entity);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(entity, true)])),
            true,
        );
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: crate::protocol::group::group_digest([entity]),
        };
        for gsn in (2..=1024).step_by(2) {
            assert!(order.accounted(0, change(gsn)));
        }
        assert!(
            !order.accounted(0, change(1026)),
            "unbounded sparse control metadata"
        );
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher].settled[&0].len(),
            512
        );
        // No release occurred above: access can stay open for the whole burst.
        for gsn in (1..=1025).step_by(2) {
            order.deposit(
                0,
                writer,
                change(gsn),
                OrderedPayload {
                    payload: PendingPayload::nothing(gsn),
                    token: None,
                },
            );
            assert_eq!(order.release().len(), 1);
        }
        assert!(
            order.accounted(0, change(1026)),
            "refused marker did not remain repairable"
        );
        assert!(order.release().is_empty());
        let state = order.0.lock().unwrap();
        let publisher = &state.publishers[&publisher];
        assert_eq!(publisher.cursor(0), 1027);
        assert!(publisher.settled.is_empty());
    }
    #[test]
    fn control_epoch_witnesses_are_reclaimed_without_a_release() {
        let order = WireOrder::default();
        let mut publisher = [0x71; 16];
        publisher[12..].copy_from_slice(&[0, 0, 1, 8]);
        let a = [0, 0, 1, 2];
        let roster = Arc::new(Mutex::new(vec![(a, true)]));
        let source = roster.clone();
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(source.lock().unwrap().clone())),
            true,
        );
        let registry = Arc::new(crate::engine::demux::TopicRegistry::new());
        let weak = Arc::downgrade(&registry);
        order.attach_terminal(
            0,
            Arc::new(move |publisher, entity| {
                let mut writer = publisher;
                writer[12..].copy_from_slice(&entity);
                weak.upgrade()?
                    .group_writer_terminal(&writer, publisher[12..].try_into().ok()?)
            }),
        );
        let group = publisher[12..].try_into().unwrap();
        let mut writer = publisher;
        writer[12..].copy_from_slice(&a);
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(group),
        );
        for gsn in 1..=128 {
            let b = [0, 1, u8::try_from(gsn).unwrap(), 2];
            let mut writer = publisher;
            writer[12..].copy_from_slice(&b);
            registry.record_writer_group_dialect(
                writer,
                crate::protocol::group::GroupDialect::Spec,
                Some(group),
            );
            *roster.lock().unwrap() = vec![(a, true), (b, false)];
            assert!(order.accounted(
                0,
                OrderedGroupChange {
                    publisher,
                    gsn,
                    writer_set: crate::protocol::group::group_digest([a, b]),
                }
            ));
            let state = order.0.lock().unwrap();
            let publisher = &state.publishers[&publisher];
            assert_eq!(
                publisher.terminal_epochs.len(),
                1,
                "an open access bracket retained obsolete terminal witnesses"
            );
            assert_eq!(publisher.settled[&0].len(), 1);
        }
    }
    #[test]
    fn a_control_only_prefix_reclaims_proof_room_from_heartbeat_absence() {
        let order = WireOrder::default();
        let mut publisher = [0x74; 16];
        publisher[12..].copy_from_slice(&[0, 0, 1, 8]);
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&b);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, false), (b, true)])),
            true,
        );
        let digest = crate::protocol::group::group_digest([a, b]);
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: digest,
        };
        // Every set has A's DATA at the odd GSN and B's empty-part marker
        // at the even GSN. Only B is matched with this volatile reader.
        for gsn in (2..=1024).step_by(2) {
            assert!(order.accounted(0, change(gsn)));
        }
        assert!(!order.accounted(0, change(1026)));
        // B ACKed/truncated the earlier markers; its next marker is all
        // that remains available. No older DATA repair is owed here.
        order.heartbeat(publisher, writer, [1026, 1026, 1026], Some(digest));
        assert!(order.release().is_empty());
        assert!(
            order.accounted(0, change(1026)),
            "positive control-prefix absence did not reclaim proof room"
        );
        assert!(order.release().is_empty());
        let state = order.0.lock().unwrap();
        let publisher = &state.publishers[&publisher];
        assert_eq!(publisher.cursor(0), 1027);
        assert!(publisher.settled.is_empty());
    }
    #[test]
    fn a_settled_boundary_keeps_an_accepted_earlier_reservation() {
        let order = WireOrder::default();
        let publisher = [0x75; 16];
        let entity = [0, 0, 1, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&entity);
        let digest = crate::protocol::group::group_digest([entity]);
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: digest,
        };
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(entity, true)])),
            true,
        );
        assert!(order.reserve(change(1), 11, 0));
        assert!(order.accounted(0, change(2)));
        order.heartbeat(publisher, writer, [2, 2, 2], Some(digest));
        assert!(order.release().is_empty());
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher].cursor(0),
            1,
            "a no-payload boundary erased an accepted predecessor"
        );
        order.release_reservation(change(1), 11);
        assert!(order.release().is_empty());
        assert_eq!(order.0.lock().unwrap().publishers[&publisher].cursor(0), 3);
    }

    #[test]
    fn a_settled_boundary_does_not_inherit_a_stale_roster_witness() {
        let order = WireOrder::default();
        let publisher = [0x76; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let c = [0, 0, 3, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&b);
        let old = crate::protocol::group::group_digest([a, b]);
        let new = crate::protocol::group::group_digest([a, b, c]);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, false), (b, true)])),
            true,
        );
        assert!(order.accounted(
            0,
            OrderedGroupChange {
                publisher,
                gsn: 1,
                writer_set: old
            }
        ));
        assert!(order.release().is_empty());
        // C was created and wrote GSN2 before the new empty set at3. Its
        // discovery is still pending, so the old AB witness cannot omit it.
        assert!(order.accounted(
            0,
            OrderedGroupChange {
                publisher,
                gsn: 3,
                writer_set: new
            }
        ));
        order.heartbeat(publisher, writer, [3, 3, 3], None);
        assert!(order.release().is_empty());
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher].cursor(0),
            2,
            "an older roster witness skipped a newly possible writer"
        );
    }

    #[test]
    fn observing_a_high_gsn_preserves_existing_members_lower_copies() {
        let order = WireOrder::default();
        let publisher = [0x77; 16];
        let entity = [0, 0, 1, 2];
        let digest = crate::protocol::group::group_digest([entity]);
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: digest,
        };
        for id in [0, 1] {
            order.attach(
                id,
                Arc::new(|_, _| {}),
                Arc::new(move |_| Some(vec![(entity, true)])),
                true,
            );
        }
        assert!(order.reserve(change(3), 33, 0));
        assert!(
            order.reserve(change(1), 11, 1),
            "a new horizon silently staled an existing reader's lower copy"
        );
    }

    #[test]
    fn a_settled_boundary_needs_each_readers_own_source_prefix() {
        let order = WireOrder::default();
        let publisher = [0x78; 16];
        let entity = [0, 0, 1, 2];
        let mut writer = publisher;
        writer[12..].copy_from_slice(&entity);
        let digest = crate::protocol::group::group_digest([entity]);
        let change = OrderedGroupChange {
            publisher,
            gsn: 2,
            writer_set: digest,
        };
        for id in [0, 1] {
            order.attach(
                id,
                Arc::new(|_, _| {}),
                Arc::new(move |_| Some(vec![(entity, true)])),
                true,
            );
        }
        assert!(order.accounted(0, change));
        order.heartbeat(publisher, writer, [2, 1, 2], Some(digest));
        order.control_prefix(0, writer, change);
        assert!(order.release().is_empty());
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher].cursor(1),
            1,
            "one reader's receipt prefix erased another reader's missing copy"
        );
        order.control_prefix(1, writer, change);
        assert!(order.release().is_empty());
        assert_eq!(order.0.lock().unwrap().publishers[&publisher].cursor(1), 3);
    }
    #[test]
    fn group_gap_proofs_merge_and_deduplicate_before_any_publication() {
        let order = WireOrder::default();
        let publisher = [0x81; 16];
        let writer = [0x82; 16];
        order.attach(0, Arc::new(|_, _| {}), Arc::new(|_| None), true);
        for _ in 0..4096 {
            order.gap(publisher, writer, 2, 5, 0);
        }
        order.gap(publisher, writer, 5, 7, 0);
        order.gap(publisher, writer, 1, 3, 0);
        order.gap(publisher, writer, 4, 6, 0);
        let state = order.0.lock().unwrap();
        let proofs = &state.publishers[&publisher].gaps[&(writer, 0)];
        assert_eq!(proofs.descriptor_count(), 1);
        assert_eq!(proofs.through(1), Some(7));
        assert_eq!(proofs.through(7), None);
    }

    #[test]
    fn sparse_group_gap_proofs_keep_a_finite_conservative_budget() {
        let order = WireOrder::default();
        let publisher = [0x83; 16];
        let writer = [0x84; 16];
        order.attach(0, Arc::new(|_, _| {}), Arc::new(|_| None), true);
        let mut start = 1;
        for width in 1..=600 {
            order.gap(publisher, writer, start, start + width, 0);
            start += width + 1;
        }
        {
            let state = order.0.lock().unwrap();
            let proofs = &state.publishers[&publisher].gaps[&(writer, 0)];
            assert_eq!(proofs.descriptor_count(), 512);
            assert!(proofs.overflowed());
            assert_eq!(proofs.through(1), Some(2));
            assert_eq!(proofs.through(2), None);
            assert_eq!(proofs.through(start - 2), None);
        }
        order.gap(publisher, writer, 2, start, 0);
        let state = order.0.lock().unwrap();
        let proofs = &state.publishers[&publisher].gaps[&(writer, 0)];
        assert_eq!(proofs.descriptor_count(), 1);
        assert_eq!(proofs.through(1), Some(start));
    }

    #[test]
    fn saturated_group_gap_trace_keeps_every_proven_prefix() {
        // Publication is withheld exactly as during begin_access. All GAPs
        // precede release, including the 513th sparse interval. A current
        // heartbeat may arrive before or after those proofs and payloads.
        for heartbeat_first in [true, false] {
            for gaps_first in [true, false] {
                let order = WireOrder::default();
                let publisher = [0x85; 16];
                let a = [0, 0, 1, 2];
                let b = [0, 0, 2, 2];
                let mut wa = publisher;
                wa[12..].copy_from_slice(&a);
                let mut wb = publisher;
                wb[12..].copy_from_slice(&b);
                let digest = crate::protocol::group::group_digest([a, b]);
                order.attach(
                    0,
                    Arc::new(|_, _| {}),
                    Arc::new(move |_| Some(vec![(a, true), (b, true)])),
                    true,
                );
                if heartbeat_first {
                    order.heartbeat(publisher, wb, [1026, 2, 1026], Some(digest));
                }
                for gap_phase in [gaps_first, !gaps_first] {
                    if gap_phase {
                        for start in (1..1026).step_by(2) {
                            order.gap(publisher, wa, start, start + 1, 0);
                        }
                    } else {
                        for gsn in (2..=1026).step_by(2) {
                            order.deposit(
                                0,
                                wb,
                                OrderedGroupChange {
                                    publisher,
                                    gsn,
                                    writer_set: digest,
                                },
                                OrderedPayload {
                                    payload: PendingPayload::nothing(gsn),
                                    token: None,
                                },
                            );
                        }
                    }
                }
                if !heartbeat_first {
                    order.heartbeat(publisher, wb, [1026, 2, 1026], Some(digest));
                }
                let ready = order.release();
                let observed: Vec<_> = ready
                    .into_iter()
                    .map(|(_, _, payload)| payload.data().payload.remote_seq)
                    .collect();
                assert_eq!(observed, (2..=1026).step_by(2).collect::<Vec<_>>(),
                    "a saturated proof cache lost a known prefix (heartbeat_first={heartbeat_first}, gaps_first={gaps_first})");
            }
        }
    }
    #[test]
    fn uncompressible_gap_overflow_waits_for_actual_heartbeat_proof() {
        let order = WireOrder::default();
        let publisher = [0x86; 16];
        let a = [0, 0, 1, 2];
        let b = [0, 0, 2, 2];
        let mut wa = publisher;
        wa[12..].copy_from_slice(&a);
        let mut wb = publisher;
        wb[12..].copy_from_slice(&b);
        let digest = crate::protocol::group::group_digest([a, b]);
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(a, true), (b, true)])),
            true,
        );
        let mut start = 1;
        for width in 1..=600 {
            order.gap(publisher, wa, start, start + width, 0);
            start += width + 1;
        }
        let gsn = start;
        order.deposit(
            0,
            wb,
            OrderedGroupChange {
                publisher,
                gsn,
                writer_set: digest,
            },
            OrderedPayload {
                payload: PendingPayload::nothing(gsn),
                token: None,
            },
        );
        order.heartbeat(publisher, wb, [gsn, gsn, gsn], Some(digest));
        assert!(
            order.release().is_empty(),
            "unknown GSNs became fabricated absence at saturation"
        );
        order.heartbeat(publisher, wa, [gsn + 1, gsn + 1, gsn], Some(digest));
        let ready = order.release();
        assert_eq!(
            ready.len(),
            1,
            "a real firstSN proof failed to release overflow debt"
        );
        assert_eq!(ready[0].2.data().payload.remote_seq, gsn);
    }
    #[test]
    fn one_lifespan_maintenance_panic_does_not_skip_another_expired_owner() {
        let order = WireOrder::default();
        let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
        order.set_clock(clock.clone());
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for id in [0, 1] {
            order.attach(id, Arc::new(|_, _| {}), Arc::new(|_| None), true);
        }
        for id in [0, 1] {
            let change = OrderedGroupChange {
                publisher: [0x91; 16],
                gsn: 3,
                writer_set: [0; 4],
            };
            let token = id as u64 + 100;
            assert!(order.reserve_coherent(change, token, id, 1, None));
            order.reserve_lifespan(
                change,
                token,
                id,
                order.lifespan_deadline(std::time::Duration::from_secs(1)),
            );
            order.activate_lifespan(token);
            let calls = calls.clone();
            order.attach_history(
                id,
                Arc::new(move |_| {
                    assert_ne!(
                        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        0,
                        "the first callback deliberately fails"
                    );
                    true
                }),
            );
        }
        clock.advance(std::time::Duration::from_secs(1));
        assert!(order.expire_lifespans().is_empty());
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one maintenance panic erased another expired owner's callback"
        );
    }
    #[test]
    fn owned_repairs_are_scoped_and_coherent_metadata_leaves_with_its_owner() {
        let order = WireOrder::default();
        let publisher = [0x94; 16];
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: [1; 4],
        };
        order.attach(0, Arc::new(|_, _| {}), Arc::new(|_| None), true);
        for token in 1..=1024 {
            assert!(order.reserve_coherent(change(4), token, 0, 3, None));
            assert!(order.repair_context(change(3), 0, 3).is_some());
            order.release_reservation(change(4), token);
            assert!(
                order.0.lock().unwrap().publishers[&publisher]
                    .coherent_owners
                    .is_empty(),
                "completed/rolled-back coherent metadata accumulated"
            );
        }
        assert!(order.reserve_coherent(change(4), 2000, 0, 3, None));
        let repair = order.repair_context(change(3), 0, 3).unwrap();
        {
            let state = order.0.lock().unwrap();
            let publisher = &state.publishers[&publisher];
            assert!(publisher.owns_repair(0, change(3), repair));
            assert!(
                !publisher.owns_repair(
                    0,
                    OrderedGroupChange {
                        writer_set: [2; 4],
                        ..change(3)
                    },
                    repair
                ),
                "a different writerSet used an unrelated retained owner"
            );
            assert!(
                !publisher.owns_repair(0, change(2), CoherentRepair { first: 2, ..repair }),
                "another coherent set used the owner's identity"
            );
        }
        assert!(order.reserve(change(6), 2005, 0));
        assert!(
            order.repair_context(change(3), 0, 3).is_none(),
            "a superseded source set remained repair-authorized"
        );
        order.forget(0);
        assert!(
            order.0.lock().unwrap().publishers.is_empty(),
            "departed reader retained coherent-kind metadata"
        );
    }
    #[test]
    fn only_a_new_set_first_closes_older_source_sets_and_invalid_tags_close_nothing() {
        let order = WireOrder::default();
        let publisher = [0x95; 16];
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: [1; 4],
        };
        order.attach(0, Arc::new(|_, _| {}), Arc::new(|_| None), true);
        assert!(order.reserve_coherent(change(1), 1, 0, 1, None));
        assert!(order.reserve_coherent(change(3), 3, 0, 3, None));
        assert!(
            order.repair_context(change(1), 0, 1).is_none(),
            "a new source set failed to supersede an older incomplete unit"
        );
        assert!(order.reserve_coherent(change(5), 5, 0, 5, None));
        assert!(order.repair_context(change(3), 0, 3).is_none());
        assert!(order.reserve_coherent(change(17), 17, 0, 5, None));
        assert!(
            order.repair_context(change(6), 0, 5).is_some(),
            "a later member falsely closed its own still-open source set"
        );
        assert!(!order.reserve_coherent(change(18), 18, 0, 0, None));
        assert!(!order.reserve_coherent(change(18), 19, 0, u64::MAX, None));
        assert!(
            order.repair_context(change(6), 0, 5).is_some(),
            "malformed SetFirst fabricated a source closure boundary"
        );
    }
    #[test]
    fn only_prejoin_announcements_belong_to_the_historical_cut() {
        let order = WireOrder::default();
        let publisher = [0x96; 16];
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: [1; 4],
        };
        order.attach_reader(
            0,
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
            true,
            true,
            Weak::new(),
        );
        assert!(order.reserve(change(3), 3, 0));
        assert_eq!(
            order.0.lock().unwrap().publishers[&publisher].progress[&0].join_cut,
            1,
            "a reader present before first traffic classified a live hole as history"
        );
        order.attach_reader(
            1,
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
            true,
            true,
            Weak::new(),
        );
        for gsn in 5..=9 {
            assert!(order.reserve(change(gsn), gsn, 0));
        }
        let state = order.0.lock().unwrap();
        assert_eq!(
            state.publishers[&publisher].progress[&1].join_cut, 4,
            "later live headers changed the join snapshot"
        );
        assert_eq!(state.publishers[&publisher].progress[&0].join_cut, 1);
    }
    #[test]
    fn unrelated_departures_neither_allocate_publishers_nor_watch_cells() {
        let order = WireOrder::default();
        order.attach(0, Arc::new(|_, _| {}), Arc::new(|_| None), true);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let watched = calls.clone();
        order.attach_terminal(
            0,
            Arc::new(move |_, _| {
                watched.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            }),
        );
        for n in 1u64..=512 {
            let mut key = [0; 16];
            key[..8].copy_from_slice(&n.to_le_bytes());
            order.departure(key, [0x45; 16]);
        }
        assert!(
            order.0.lock().unwrap().publishers.is_empty(),
            "unrelated departure allocated a Publisher tombstone"
        );
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "unrelated departure captured terminal cells"
        );
        let change = OrderedGroupChange {
            publisher: [1; 16],
            gsn: 1,
            writer_set: [2; 4],
        };
        assert!(order.reserve(change, 1, 0));
        order.departure(change.publisher, [0x45; 16]);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        order.forget(0);
        assert!(
            order.0.lock().unwrap().publishers.is_empty(),
            "last reader retained Publisher proof cells"
        );
    }

    #[test]
    fn a_due_owner_handoff_retries_expiry_after_its_real_ready_deposit() {
        let barrier = Arc::new(super::super::coherent_barrier::CoherentPresentationBarrier::new());
        let member = barrier.reserve("lifespan-handoff".into(), false);
        barrier.attach_wire_order(
            member,
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
            true,
            true,
            Weak::new(),
        );
        let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
        barrier.set_wire_clock_for_test(clock.clone());
        let change = OrderedGroupChange {
            publisher: [0x59; 16],
            gsn: 1,
            writer_set: [0x32; 4],
        };
        assert!(barrier.reserve_wire_coherent(change, 1, member, 1, None));
        barrier.reserve_wire_lifespan(
            change,
            1,
            member,
            barrier.wire_lifespan_deadline(std::time::Duration::from_secs(1)),
        );
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let weak = Arc::downgrade(&barrier);
        barrier.attach_wire_history(
            member,
            Arc::new(move |proof| {
                let HistoryProof::Lifespan { owner_token } = proof else {
                    unreachable!()
                };
                let seen = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if seen == 0 {
                    false
                } else {
                    weak.upgrade()
                        .unwrap()
                        .retire_wire_owner(member, owner_token)
                }
            }),
        );
        clock.advance(std::time::Duration::from_secs(1));
        barrier.pump_wire_history_for_test();
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "expiry ran before the payload ownership handoff was activated"
        );
        barrier.activate_wire_lifespan(1);
        barrier.pump_wire_history_for_test();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        let mut payload = PendingPayload::nothing(1);
        payload.order = Some(change);
        payload.order_token = Some(OrderToken {
            bindings: Weak::new(),
            token: 1,
            reservation_active: true,
            loss: super::super::subscriber::LossLedger::default()
                .claim(1, true)
                .unwrap(),
            handle: None,
            change,
            phase: TokenPhase::Pending,
            barrier: Arc::downgrade(&barrier),
        });
        barrier.deposit(
            member,
            change.publisher,
            super::super::coherent_barrier::CoherentSet::spec_part(
                vec![([0x62; 16], vec![payload])],
                1,
                false,
            ),
        );
        barrier.pump_wire_history_for_test();
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "buffer-to-ready handoff lost its already-due LIFESPAN"
        );
    }

    #[test]
    fn incarnation_loss_ownership_does_not_grow_the_inline_order_ticket() {
        #[allow(dead_code)]
        struct EarlierTicket {
            bindings: Weak<ReaderBindings>,
            token: u64,
            reservation: Option<u64>,
            handle: Option<SlabHandle>,
            change: OrderedGroupChange,
            phase: TokenPhase,
            barrier: Weak<super::super::coherent_barrier::CoherentPresentationBarrier>,
        }
        assert!(
            std::mem::size_of::<OrderToken>() <= std::mem::size_of::<EarlierTicket>(),
            "incarnation loss ownership enlarged the inline ticket"
        );
        assert!(
            std::mem::size_of::<Option<OrderToken>>()
                <= std::mem::size_of::<Option<EarlierTicket>>()
        );
    }

    #[test]
    fn a_queued_provider_writer_does_not_reenter_an_owed_copy_proof() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};
        let registry = Arc::new(crate::engine::demux::TopicRegistry::new());
        let key = [0x42; 16];
        let entity = [0, 0, 1, 2];
        let publisher_entity = key[12..].try_into().unwrap();
        let mut writer = key;
        writer[12..].copy_from_slice(&entity);
        registry.register_writer_guid(writer, "queued-proof-writer".to_string());
        registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Spec,
            Some(publisher_entity),
        );
        let cell = registry
            .group_writer_terminal(&writer, publisher_entity)
            .unwrap();
        registry.notify_participant_departed(&key[..12].try_into().unwrap());
        assert!(
            crate::engine::demux::GroupWriterTerminal::all_participant_departed(
                std::slice::from_ref(&cell),
            )
            .is_some()
        );
        let mut publisher = Publisher {
            participant_departure: Some(cell.clone()),
            ..Publisher::default()
        };
        let mut progress = Progress::new(1, 2);
        progress.joined = Some(vec![(entity, cell.clone())]);
        publisher.progress.insert(0, progress);
        publisher.pending.insert(
            1,
            Change {
                writer,
                writer_set: [0; 4],
                payloads: BTreeMap::new(),
                members: HashSet::from([0]),
            },
        );
        let (holding, held) = mpsc::channel();
        let (resume, resumed) = mpsc::channel();
        publisher.retire_proof_hook = Some(Box::new(move || {
            holding.send(()).unwrap();
            resumed.recv().unwrap();
        }));
        let (complete, completed) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            let changed = publisher.retire_unavailable_copies(&HashMap::new(), &mut Vec::new());
            complete
                .send((changed, publisher.pending[&1].members.is_empty()))
                .unwrap();
        });
        held.recv_timeout(Duration::from_secs(2))
            .expect("the first proof read was not held");
        let returning = registry.clone();
        let announced = std::thread::spawn(move || {
            returning.record_writer_group_dialect(
                writer,
                crate::protocol::group::GroupDialect::Spec,
                Some(publisher_entity),
            );
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while cell.proof_read_available_for_test() {
            assert!(
                Instant::now() < deadline,
                "the provider writer did not queue"
            );
            std::thread::yield_now();
        }
        resume.send(()).unwrap();
        assert_eq!(
            completed.recv_timeout(Duration::from_secs(2)).ok(),
            Some((true, true)),
            "owed-copy retirement recursively read a proof domain behind its queued writer"
        );
        owner.join().unwrap();
        announced.join().unwrap();
        assert!(
            !cell.is_departed(),
            "the queued announcement did not revoke the proof"
        );
    }

    #[test]
    fn a_group_gap_is_consumed_by_its_reader_not_another_cohorts_horizon() {
        let order = WireOrder::default();
        let publisher = [0x62; 16];
        let entity = [0, 0, 1, 2];
        let change = |gsn| OrderedGroupChange {
            publisher,
            gsn,
            writer_set: crate::protocol::group::group_digest([entity]),
        };
        order.attach(
            0,
            Arc::new(|_, _| {}),
            Arc::new(move |_| Some(vec![(entity, true)])),
            true,
        );
        assert!(
            !order.gap_consumed(publisher, 0, 1),
            "unknown Publisher was consumed"
        );
        for gsn in 1..=5 {
            assert!(order.accounted(0, change(gsn)));
        }
        assert!(
            !order.gap_consumed(publisher, 0, 6),
            "an admitted horizon was credited before its prefix was consumed"
        );
        assert!(order.release().is_empty());
        assert!(order.gap_consumed(publisher, 0, 6));
        order.attach_reader(
            1,
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
            true,
            true,
            Weak::new(),
        );
        assert!(
            order.gap_consumed(publisher, 0, 6),
            "a late reader blocked a proof already consumed by the original reader"
        );
        assert!(
            !order.gap_consumed(publisher, 1, 6),
            "another reader's high-water erased a historical cohort's proof debt"
        );
        order.attach_pending_reader(
            2,
            Arc::new(|_, _| {}),
            Arc::new(|_| None),
            true,
            false,
            Weak::new(),
        );
        assert!(
            !order.gap_consumed(publisher, 2, 6),
            "a provisional reader credited before its ownership was published"
        );
        assert!(order.attach_loss_watch(2, Arc::new(|_, _| LossWatchResult::Unmatched)));
        assert!(order.gap_consumed(publisher, 2, 6));
        order.forget(1);
        assert!(
            order.gap_consumed(publisher, 1, 6),
            "a retired member kept a stale native repair obligation"
        );
    }
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs once, on the depositing thread, at the start of
    /// `deposit`, before the payload is pending.
    // @audit-ok: cfg(test) only, thread-local one-shot hook, never in a product build
    static DEPOSIT_WINDOW_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_deposit_window_hook(hook: Box<dyn FnOnce()>) {
    DEPOSIT_WINDOW_HOOK.with(|h| *h.borrow_mut() = Some(hook));
}

#[cfg(test)]
fn run_deposit_window_hook() {
    if let Some(hook) = DEPOSIT_WINDOW_HOOK.with(|h| h.borrow_mut().take()) {
        hook();
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The history of a participant's two SEDP built-in writers.
//!
//! RTPS v2.5 Sec.8.5.4.4, Tables 8.82 and 8.83: the history of the
//! SEDPbuiltinPublicationsWriter (SEDPbuiltinSubscriptionsWriter) holds one
//! data-object per DataWriter (DataReader) of the participant, inserted
//! each time one is created and deleted each time one is deleted.
//!
//! Sequence numbers are positional: the Nth change of a kind carries SN N,
//! for every peer and every round, so a replay, a retransmission and the
//! announcement itself never disagree about which number names which
//! endpoint (receivers deduplicate SEDP by sequence number). Deleting an
//! endpoint therefore removes nothing from the list. Its announcement is
//! kept as a `Superseded` change, sent as a GAP from then on (Sec.8.3.8.4:
//! that number is irrelevant to the reader), and a `Disposed` change is
//! appended under the next number, sent as the dispose of the endpoint's
//! instance (`build_sedp_dispose_packet`). An endpoint announced again
//! (`reannounce`) is a new change of the same instance the same way: the
//! previous announcement is superseded and the new one takes the next
//! number. Every number a writer emits names exactly one change.
//!
//! A HEARTBEAT advertises as firstSN the first change that is not
//! superseded (`first_available`). RTPS v2.5 Sec.8.3.8.6, Table 8.44:
//! firstSN is the first sequence number still available in the writer, and
//! a superseded change is no longer available (a NACK of it gets a GAP).

use crate::core::discovery::GUID;
use crate::protocol::dialect::Dialect;
use crate::protocol::discovery::{EndpointSecurityInfo, ParseError, SedpData};

use super::rtps_packet::{
    build_sedp_dispose_packet, build_sedp_rtps_packet_secured, bump_publications_high_water,
    bump_subscriptions_high_water, sedp_entity_ids, SedpEndpointKind, TypeObjectPid,
};

/// What one change of the history says about its endpoint.
#[derive(Debug, Clone)]
enum ChangeState {
    /// The endpoint's announcement, while the endpoint exists.
    Alive(Box<SedpData>),
    /// The announcement of an endpoint since deleted: irrelevant to every
    /// reader, sent as a GAP.
    Superseded,
    /// The dispose of a deleted endpoint's instance.
    Disposed,
}

#[derive(Debug, Clone)]
struct Change {
    kind: SedpEndpointKind,
    endpoint: GUID,
    state: ChangeState,
    /// The endpoint's `EndpointSecurityInfo` (DDS-Security v1.1 Sec.7.2.8)
    /// when its participant runs a governance document; `None` otherwise.
    /// Its discovery-protected bit decides on which SEDP topic the change
    /// goes (Table 29); every change of the endpoint carries the same.
    security: Option<EndpointSecurityInfo>,
}

/// The changes of both SEDP writers of one participant, in creation order.
///
/// Once `close`d (the participant is going away and is about to say so with
/// its SPDP dispose, which retires every endpoint at once), no endpoint is
/// retired any more: nothing goes out on SEDP after the participant's
/// farewell.
#[derive(Debug, Default)]
pub struct SedpHistory {
    changes: Vec<Change>,
    closed: bool,
    /// The per-peer SEDP retry threads sending this history, stopped and
    /// joined when the participant goes (`RetryRounds`).
    retry_rounds: std::sync::Arc<RetryRounds>,
}

/// The threads that send a participant's SEDP history again to one peer
/// (the per-peer retry rounds of the SPDP handler), and the signal that
/// ends them.
///
/// They are joined, never detached: a participant dropped with one in
/// flight must not return while the thread still sleeps (up to its 50 ms
/// slice) holding the transport, nor let its retry guard re-enter the
/// process-wide dedup maps after `forget_local_participant` has cleared
/// them. `close` wakes them at once, and the participant joins them
/// (`join_all`) before it forgets its dedup entries.
#[derive(Debug, Default)]
pub struct RetryRounds {
    stopped: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
    threads: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl RetryRounds {
    /// Keep `handle` to be joined; the threads that already ended are
    /// joined now, so the list holds only live ones.
    pub fn track(&self, handle: std::thread::JoinHandle<()>) {
        let mut threads = self.threads.lock().unwrap_or_else(|e| e.into_inner());
        let (ended, live): (Vec<_>, Vec<_>) = std::mem::take(&mut *threads)
            .into_iter()
            .partition(|h| h.is_finished());
        *threads = live;
        threads.push(handle);
        drop(threads);
        for handle in ended {
            let _ = handle.join();
        }
    }

    /// Wait `period` unless stopped meanwhile; whether still running.
    pub fn wait_while_running(&self, period: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + period;
        let mut stopped = self.stopped.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if *stopped {
                return false;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return true;
            }
            stopped = self
                .wake
                .wait_timeout(stopped, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Whether `stop` was called.
    pub fn is_stopped(&self) -> bool {
        *self.stopped.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn stop(&self) {
        *self.stopped.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.wake.notify_all();
    }

    /// Join every thread tracked. Called once the history is closed, with
    /// no lock of the history held (the threads take its read lock).
    pub fn join_all(&self) {
        let threads = std::mem::take(&mut *self.threads.lock().unwrap_or_else(|e| e.into_inner()));
        for handle in threads {
            // Never the calling thread; bounded.
            crate::core::rt::shutdown::join_bounded(handle, "SEDP retry round");
        }
    }

    /// How many threads are tracked. Test-only.
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.threads.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// One message a replay or a retransmission sends for the history, in
/// sequence-number order (`SedpHistory::sends`).
#[derive(Debug, Clone)]
pub struct SedpSend {
    /// The SEDP writer it belongs to.
    pub kind: SedpEndpointKind,
    /// Its sequence number; the first of the range for a GAP.
    pub seq: u64,
    /// The writer's first available sequence number when the history was
    /// read (`SedpHistory::first_available`): the firstSN of a HEARTBEAT
    /// sent with this message.
    pub first_available: u64,
    body: SendBody,
    /// The security info of the endpoint the change is about (`Change`).
    security: Option<EndpointSecurityInfo>,
}

#[derive(Debug, Clone)]
enum SendBody {
    Alive(Box<SedpData>),
    /// `seq..=last` are irrelevant: consecutive superseded changes.
    Gap {
        last: u64,
    },
    Dispose(GUID),
}

impl SedpSend {
    /// The highest sequence number this message covers.
    pub fn last_seq(&self) -> u64 {
        match self.body {
            SendBody::Gap { last } => last,
            _ => self.seq,
        }
    }

    /// Whether this is a GAP (sent in the clear even to a peer whose SEDP
    /// is protected: it carries no endpoint data, and the receiver reads it
    /// against the plaintext writer, `retire_refused_secure_sedp_sequence`).
    pub fn is_gap(&self) -> bool {
        matches!(self.body, SendBody::Gap { .. })
    }

    /// Whether the change goes on the secure SEDP topics (DDS-Security v1.1
    /// Table 29, `is_discovery_protected`): `None` when the participant runs
    /// no governance document and the decision is the participant's, not the
    /// endpoint's.
    pub fn discovery_protected(&self) -> Option<bool> {
        self.security
            .map(|security| security.is_discovery_protected())
    }

    /// The `EndpointSecurityInfo` of the endpoint the change is about.
    pub fn security(&self) -> Option<EndpointSecurityInfo> {
        self.security
    }

    /// The announcement this message carries, if it is one.
    pub fn announcement(&self) -> Option<&SedpData> {
        match &self.body {
            SendBody::Alive(data) => Some(data),
            _ => None,
        }
    }

    /// Tests only: the RTPS message, from `our_prefix`, addressed to
    /// `peer_prefix` (INFO_DST) when given, PID_TYPE_OBJECT following the
    /// destination's vendor bytes (`TypeObjectPid::of_destination`). The send
    /// paths use `build_for`, with the recipient's class.
    #[cfg(test)]
    pub(crate) fn build(
        &self,
        our_prefix: &[u8; 12],
        peer_prefix: Option<&[u8; 12]>,
        dialect: Dialect,
    ) -> Result<Vec<u8>, ParseError> {
        self.build_for(
            our_prefix,
            peer_prefix,
            dialect,
            TypeObjectPid::of_destination(peer_prefix),
        )
    }

    /// The RTPS message, from `our_prefix`, addressed to `peer_prefix`
    /// (INFO_DST) when given, PID_TYPE_OBJECT decided by the recipient's
    /// class (`DiscoveryFsm::type_object_pid_for`).
    pub fn build_for(
        &self,
        our_prefix: &[u8; 12],
        peer_prefix: Option<&[u8; 12]>,
        dialect: Dialect,
        type_object: TypeObjectPid,
    ) -> Result<Vec<u8>, ParseError> {
        match &self.body {
            SendBody::Alive(data) => build_sedp_rtps_packet_secured(
                data,
                self.kind,
                our_prefix,
                peer_prefix,
                self.seq,
                dialect,
                type_object,
                self.security,
            ),
            SendBody::Gap { last } => sedp_gap(self.kind, self.seq, *last, our_prefix),
            SendBody::Dispose(endpoint) => Ok(build_sedp_dispose_packet(
                endpoint,
                self.kind,
                our_prefix,
                peer_prefix,
                self.seq,
                dialect,
            )),
        }
    }
}

/// A GAP of the regular SEDP writer of `kind`, from `our_prefix`, retiring
/// exactly `first..=last` (gapStart = first, gapList based at last + 1 with
/// no bits, RTPS v2.5 Sec.8.3.7.4).
pub fn sedp_gap(
    kind: SedpEndpointKind,
    first: u64,
    last: u64,
    our_prefix: &[u8; 12],
) -> Result<Vec<u8>, ParseError> {
    let (reader_id, writer_id) = sedp_entity_ids(kind);
    let gap = crate::protocol::builder::build_gap_packet_from_parts(
        &reader_id,
        &writer_id,
        first,
        last.saturating_add(1),
        &[],
        *our_prefix,
    );
    if gap.is_empty() {
        return Err(ParseError::EncodingError);
    }
    Ok(gap)
}

impl SedpSend {
    /// This message's numbers as a GAP of the regular writer: what a
    /// participant that is not to receive the change gets instead
    /// (`DiscoveryFsm::sedp_for_peer`).
    pub fn build_gap(&self, our_prefix: &[u8; 12]) -> Result<Vec<u8>, ParseError> {
        sedp_gap(self.kind, self.seq, self.last_seq(), our_prefix)
    }
}

impl SedpHistory {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the history holds no change at all.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Insert the announcement of a new endpoint; returns its sequence
    /// number. No security info: see [`Self::announce_with`].
    pub fn announce(&mut self, data: SedpData, kind: SedpEndpointKind) -> u64 {
        self.announce_with(data, kind, None)
    }

    /// Insert the announcement of a new endpoint whose security info is
    /// `security` (`Change::security`); returns its sequence number.
    pub fn announce_with(
        &mut self,
        data: SedpData,
        kind: SedpEndpointKind,
        security: Option<EndpointSecurityInfo>,
    ) -> u64 {
        let endpoint = data.endpoint_guid;
        self.changes.push(Change {
            kind,
            endpoint,
            state: ChangeState::Alive(Box::new(data)),
            security,
        });
        let seq = self.last_seq(kind);
        bump_high_water(kind, seq);
        seq
    }

    /// Announce an existing endpoint again, as a new change: its current
    /// announcement is superseded (a GAP from then on) and the same data is
    /// appended under the next number. Returns that number and the data;
    /// `None` when the history is closed or holds no live announcement of
    /// the endpoint.
    ///
    /// For a receiver that takes a change it has already seen as a
    /// duplicate whatever it says (a change is identified by writer GUID and
    /// sequence number, not by content), a
    /// fresh number is the only way to be heard again, and the number must
    /// come from this history: one drawn from anywhere else is a number the
    /// history hands out again to the next endpoint or dispose, which that
    /// receiver then drops.
    pub fn reannounce(
        &mut self,
        endpoint: &GUID,
        kind: SedpEndpointKind,
    ) -> Option<(u64, SedpData)> {
        if self.closed {
            return None;
        }
        let change = self.changes.iter_mut().find(|c| {
            c.kind == kind && c.endpoint == *endpoint && matches!(c.state, ChangeState::Alive(_))
        })?;
        let ChangeState::Alive(data) =
            std::mem::replace(&mut change.state, ChangeState::Superseded)
        else {
            return None;
        };
        let announced = (*data).clone();
        let security = change.security;
        self.changes.push(Change {
            kind,
            endpoint: *endpoint,
            state: ChangeState::Alive(data),
            security,
        });
        let seq = self.last_seq(kind);
        bump_high_water(kind, seq);
        Some((seq, announced))
    }

    /// The first sequence number of the writer of `kind` that is still
    /// available: the position of its first change that is not superseded,
    /// 1 when it has written nothing (RTPS v2.5 Sec.8.3.8.6, Example 1).
    /// The last change of a writer is never superseded (superseding one
    /// appends another), so this never exceeds `last_seq(kind)` once the
    /// writer has written anything.
    pub fn first_available(&self, kind: SedpEndpointKind) -> u64 {
        let superseded_prefix = self
            .changes
            .iter()
            .filter(|c| c.kind == kind)
            .take_while(|c| matches!(c.state, ChangeState::Superseded))
            .count() as u64;
        superseded_prefix + 1
    }

    /// The sequence number of `endpoint`'s announcement, while it exists.
    pub fn seq_of(&self, endpoint: &GUID, kind: SedpEndpointKind) -> Option<u64> {
        let mut seq = 0u64;
        for change in self.changes.iter().filter(|c| c.kind == kind) {
            seq += 1;
            if change.endpoint == *endpoint && matches!(change.state, ChangeState::Alive(_)) {
                return Some(seq);
            }
        }
        None
    }

    /// The endpoint was deleted: its announcement becomes irrelevant and the
    /// dispose of its instance is appended. Returns the dispose's sequence
    /// number; `None` when the history is closed or holds no live
    /// announcement of that endpoint (already retired, or never announced).
    pub fn retire(&mut self, endpoint: &GUID, kind: SedpEndpointKind) -> Option<u64> {
        if self.closed {
            return None;
        }
        let change = self.changes.iter_mut().find(|c| {
            c.kind == kind && c.endpoint == *endpoint && matches!(c.state, ChangeState::Alive(_))
        })?;
        change.state = ChangeState::Superseded;
        let security = change.security;
        self.changes.push(Change {
            kind,
            endpoint: *endpoint,
            state: ChangeState::Disposed,
            security,
        });
        let seq = self.last_seq(kind);
        bump_high_water(kind, seq);
        Some(seq)
    }

    /// The security info of the change of the writer of `kind` numbered
    /// `seq`, when it has one.
    pub fn security_at(&self, kind: SedpEndpointKind, seq: u64) -> Option<EndpointSecurityInfo> {
        let index = usize::try_from(seq.checked_sub(1)?).ok()?;
        self.changes
            .iter()
            .filter(|c| c.kind == kind)
            .nth(index)
            .and_then(|c| c.security)
    }

    /// No endpoint is retired from now on (see the type's documentation).
    /// Its retry rounds are told to stop (`retry_rounds`).
    pub fn close(&mut self) {
        self.closed = true;
        self.retry_rounds.stop();
    }

    /// The retry threads sending this history.
    pub fn retry_rounds(&self) -> std::sync::Arc<RetryRounds> {
        std::sync::Arc::clone(&self.retry_rounds)
    }

    /// Whether `close` was called.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The highest sequence number of the writer of `kind`, 0 when it has
    /// written nothing.
    pub fn last_seq(&self, kind: SedpEndpointKind) -> u64 {
        self.changes.iter().filter(|c| c.kind == kind).count() as u64
    }

    /// The announcements of the endpoints that exist.
    pub fn alive(&self) -> impl Iterator<Item = (&SedpData, SedpEndpointKind)> {
        self.changes.iter().filter_map(|c| match &c.state {
            ChangeState::Alive(data) => Some((data.as_ref(), c.kind)),
            _ => None,
        })
    }

    /// Every message that brings a reader up to date with the writer of
    /// `kind` (both writers when `None`), in sequence-number order:
    /// announcements, GAPs for consecutive superseded changes, disposes.
    ///
    /// None once the history is closed: the participant is saying its
    /// farewell, and nothing goes out on SEDP after it, neither a replay to
    /// a peer nor a retransmission a peer asked for.
    pub fn sends(&self, kind: Option<SedpEndpointKind>) -> Vec<SedpSend> {
        if self.closed {
            return Vec::new();
        }
        let mut out: Vec<SedpSend> = Vec::with_capacity(self.changes.len());
        let pub_first = self.first_available(SedpEndpointKind::Writer);
        let sub_first = self.first_available(SedpEndpointKind::Reader);
        let mut pub_seq = 0u64;
        let mut sub_seq = 0u64;
        for change in &self.changes {
            let seq = match change.kind {
                SedpEndpointKind::Writer => {
                    pub_seq += 1;
                    pub_seq
                }
                SedpEndpointKind::Reader => {
                    sub_seq += 1;
                    sub_seq
                }
            };
            if kind.is_some_and(|k| k != change.kind) {
                continue;
            }
            let body = match &change.state {
                ChangeState::Alive(data) => SendBody::Alive(data.clone()),
                ChangeState::Disposed => SendBody::Dispose(change.endpoint),
                ChangeState::Superseded => {
                    // Extend the GAP this writer's previous message opened,
                    // when it ends right before this change.
                    if let Some(open) = out.iter_mut().rev().find(|s| s.kind == change.kind) {
                        if let SendBody::Gap { last } = &mut open.body {
                            if *last + 1 == seq {
                                *last = seq;
                                continue;
                            }
                        }
                    }
                    SendBody::Gap { last: seq }
                }
            };
            let first_available = match change.kind {
                SedpEndpointKind::Writer => pub_first,
                SedpEndpointKind::Reader => sub_first,
            };
            out.push(SedpSend {
                kind: change.kind,
                seq,
                first_available,
                body,
                security: change.security,
            });
        }
        bump_high_water(SedpEndpointKind::Writer, pub_seq);
        bump_high_water(SedpEndpointKind::Reader, sub_seq);
        out
    }
}

/// Keep the process-wide SEDP counters (`get_*_last_seq`, read by the
/// dialect handshakes for their HEARTBEAT lastSN) at or above the numbers
/// this history has handed out. No SEDP message draws its number from those
/// counters any more: every number comes from the history.
fn bump_high_water(kind: SedpEndpointKind, seq: u64) {
    match kind {
        SedpEndpointKind::Writer => bump_publications_high_water(seq),
        SedpEndpointKind::Reader => bump_subscriptions_high_water(seq),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: [u8; 12] = [0x01, 0x1a, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9];

    fn endpoint(entity: [u8; 4]) -> GUID {
        GUID::new(OURS, entity)
    }

    fn data(endpoint: GUID) -> SedpData {
        SedpData {
            topic_name: "T".to_string(),
            type_name: "Ty".to_string(),
            participant_guid: GUID::new(OURS, [0, 0, 1, 0xc1]),
            endpoint_guid: endpoint,
            qos_hash: 0,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// (kind, seq, last, what) of each send, for comparisons.
    fn shape(sends: &[SedpSend]) -> Vec<(SedpEndpointKind, u64, u64, &'static str)> {
        sends
            .iter()
            .map(|s| {
                let what = match s.body {
                    SendBody::Alive(_) => "alive",
                    SendBody::Gap { .. } => "gap",
                    SendBody::Dispose(_) => "dispose",
                };
                (s.kind, s.seq, s.last_seq(), what)
            })
            .collect()
    }

    use SedpEndpointKind::{Reader, Writer};

    /// Sequence numbers stay dense through a deletion: the dispose takes
    /// N+1 and the next endpoint N+2; the deleted endpoint's number is a
    /// GAP from then on, never its announcement again.
    #[test]
    fn a_deletion_keeps_the_numbers_dense() {
        let mut history = SedpHistory::new();
        let w1 = endpoint([0, 0, 1, 2]);
        let w2 = endpoint([0, 0, 2, 2]);
        let r1 = endpoint([0, 0, 3, 7]);
        assert_eq!(history.announce(data(w1), Writer), 1);
        assert_eq!(history.announce(data(r1), Reader), 1);
        assert_eq!(history.announce(data(w2), Writer), 2);
        assert_eq!(history.retire(&w1, Writer), Some(3), "the dispose is N+1");
        assert_eq!(history.seq_of(&w1, Writer), None, "no longer announced");
        assert_eq!(
            history.seq_of(&w2, Writer),
            Some(2),
            "a sibling keeps its number"
        );
        let w3 = endpoint([0, 0, 4, 2]);
        assert_eq!(history.announce(data(w3), Writer), 4, "the next one N+2");
        assert_eq!(history.last_seq(Writer), 4);
        assert_eq!(history.last_seq(Reader), 1, "the other writer is untouched");
        assert_eq!(
            shape(&history.sends(Some(Writer))),
            vec![
                (Writer, 1, 1, "gap"),
                (Writer, 2, 2, "alive"),
                (Writer, 3, 3, "dispose"),
                (Writer, 4, 4, "alive"),
            ]
        );
        assert_eq!(
            history
                .alive()
                .map(|(d, _)| d.endpoint_guid)
                .collect::<Vec<_>>(),
            vec![r1, w2, w3]
        );
    }

    /// Consecutive superseded changes of one writer go out as one GAP; the
    /// other writer's changes in between do not break the run.
    #[test]
    fn consecutive_superseded_changes_are_one_gap() {
        let mut history = SedpHistory::new();
        let w1 = endpoint([0, 0, 1, 2]);
        let w2 = endpoint([0, 0, 2, 2]);
        let r1 = endpoint([0, 0, 3, 7]);
        history.announce(data(w1), Writer);
        history.announce(data(r1), Reader);
        history.announce(data(w2), Writer);
        history.retire(&w1, Writer);
        history.retire(&w2, Writer);
        assert_eq!(
            shape(&history.sends(None)),
            vec![
                (Writer, 1, 2, "gap"),
                (Reader, 1, 1, "alive"),
                (Writer, 3, 3, "dispose"),
                (Writer, 4, 4, "dispose"),
            ]
        );
    }

    /// A retirement happens once, and never after the history is closed.
    #[test]
    fn a_retirement_happens_once_and_never_after_close() {
        let mut history = SedpHistory::new();
        let w1 = endpoint([0, 0, 1, 2]);
        let w2 = endpoint([0, 0, 2, 2]);
        history.announce(data(w1), Writer);
        history.announce(data(w2), Writer);
        assert_eq!(history.retire(&w1, Writer), Some(3));
        assert_eq!(history.retire(&w1, Writer), None, "already retired");
        assert_eq!(history.retire(&w1, Reader), None, "wrong writer");
        history.close();
        assert!(history.is_closed());
        assert_eq!(history.retire(&w2, Writer), None, "closed");
        assert_eq!(history.seq_of(&w2, Writer), Some(2), "and left as it was");
        assert_eq!(history.last_seq(Writer), 3);
    }

    /// A closed history has nothing to send: the participant is saying its
    /// farewell, and no replay or retransmission goes out after it.
    #[test]
    fn a_closed_history_has_nothing_to_send() {
        let mut history = SedpHistory::new();
        history.announce(data(endpoint([0, 0, 1, 2])), Writer);
        history.announce(data(endpoint([0, 0, 2, 7])), Reader);
        assert_eq!(history.sends(None).len(), 2, "fixture");
        history.close();
        assert_eq!(history.sends(None).len(), 0);
        assert_eq!(history.sends(Some(Writer)).len(), 0);
        assert_eq!(history.sends(Some(Reader)).len(), 0);
    }

    /// An endpoint announced again is a new change under the next number;
    /// its previous announcement is superseded. Every later change takes
    /// the numbers after it, and a closed history announces nothing again.
    /// The security info an endpoint was announced with follows every
    /// change about it - its re-announcement and its dispose - so each goes
    /// on the SEDP topic its governance names (DDS-Security v1.1 Table 29).
    #[test]
    fn every_change_of_an_endpoint_carries_its_security_info() {
        let secure = EndpointSecurityInfo {
            endpoint_security_attributes: EndpointSecurityInfo::IS_VALID
                | EndpointSecurityInfo::IS_DISCOVERY_PROTECTED,
            plugin_endpoint_security_attributes: EndpointSecurityInfo::IS_VALID,
        };
        let open = EndpointSecurityInfo {
            endpoint_security_attributes: EndpointSecurityInfo::IS_VALID,
            plugin_endpoint_security_attributes: EndpointSecurityInfo::IS_VALID,
        };
        let mut history = SedpHistory::new();
        let w1 = endpoint([0, 0, 1, 2]);
        let w2 = endpoint([0, 0, 2, 2]);
        let w3 = endpoint([0, 0, 3, 2]);
        assert_eq!(history.announce_with(data(w1), Writer, Some(secure)), 1);
        assert_eq!(history.announce_with(data(w2), Writer, Some(open)), 2);
        assert_eq!(history.announce(data(w3), Writer), 3);
        assert_eq!(history.reannounce(&w1, Writer).map(|(seq, _)| seq), Some(4));
        assert_eq!(history.retire(&w2, Writer), Some(5));
        assert_eq!(
            history.security_at(Writer, 4),
            Some(secure),
            "re-announcement"
        );
        assert_eq!(history.security_at(Writer, 5), Some(open), "dispose");
        assert_eq!(history.security_at(Writer, 3), None);
        assert_eq!(history.security_at(Writer, 0), None);
        assert_eq!(history.security_at(Writer, 6), None);
        let protected: Vec<_> = history
            .sends(Some(Writer))
            .iter()
            .filter(|s| !s.is_gap())
            .map(|s| (s.seq, s.discovery_protected()))
            .collect();
        assert_eq!(
            protected,
            vec![(3, None), (4, Some(true)), (5, Some(false))],
            "1 and 2 are superseded: GAPs"
        );
        assert!(
            !EndpointSecurityInfo {
                endpoint_security_attributes: EndpointSecurityInfo::IS_DISCOVERY_PROTECTED,
                plugin_endpoint_security_attributes: 0,
            }
            .is_discovery_protected(),
            "a mask without is_valid says nothing"
        );
    }

    /// What the history sends for an endpoint announced with security info
    /// carries it in PID_ENDPOINT_SECURITY_INFO (DDS-Security v1.1
    /// Sec.7.4.1.5); without, it does not.
    #[test]
    fn the_history_announces_the_endpoint_security_info() {
        let info = EndpointSecurityInfo {
            endpoint_security_attributes: 0x8000_0007,
            plugin_endpoint_security_attributes: 0x8000_0000,
        };
        let parameter = [
            0x04, 0x10, 0x08, 0x00, 0x07, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80,
        ];
        let carries = |packet: &[u8]| packet.windows(12).any(|w| w == parameter);
        let mut history = SedpHistory::new();
        history.announce_with(data(endpoint([0, 0, 1, 2])), Writer, Some(info));
        history.announce(data(endpoint([0, 0, 2, 2])), Writer);
        let sends = history.sends(Some(Writer));
        let built = |i: usize| {
            sends[i]
                .build(&OURS, Some(&[7; 12]), Dialect::Hdds)
                .expect("build")
        };
        assert!(carries(&built(0)));
        assert!(!carries(&built(1)));
    }

    #[test]
    fn a_reannouncement_is_a_new_change_under_the_next_number() {
        let mut history = SedpHistory::new();
        let r1 = endpoint([0, 0, 1, 7]);
        let r2 = endpoint([0, 0, 2, 7]);
        let w1 = endpoint([0, 0, 3, 2]);
        assert_eq!(history.announce(data(r1), Reader), 1);
        assert_eq!(history.announce(data(w1), Writer), 1);
        let (seq, again) = history.reannounce(&r1, Reader).expect("alive");
        assert_eq!(seq, 2);
        assert_eq!(again.endpoint_guid, r1);
        assert_eq!(history.seq_of(&r1, Reader), Some(2));
        assert!(history.reannounce(&w1, Reader).is_none(), "wrong writer");
        assert_eq!(history.announce(data(r2), Reader), 3);
        assert_eq!(history.retire(&r1, Reader), Some(4));
        assert!(history.reannounce(&r1, Reader).is_none(), "retired");
        assert_eq!(history.last_seq(Writer), 1, "the other writer is untouched");
        assert_eq!(
            shape(&history.sends(Some(Reader))),
            vec![
                (Reader, 1, 2, "gap"),
                (Reader, 3, 3, "alive"),
                (Reader, 4, 4, "dispose"),
            ]
        );
        history.close();
        assert!(history.reannounce(&r2, Reader).is_none(), "closed");
        assert_eq!(history.seq_of(&r2, Reader), Some(3));
    }

    /// The first available number is the first change of the writer that is
    /// not superseded: a superseded change after it does not move it, the
    /// other writer's changes do not count, and a writer that has written
    /// nothing has 1. Each send carries its writer's.
    #[test]
    fn the_first_available_number_skips_the_superseded_prefix_only() {
        let mut history = SedpHistory::new();
        assert_eq!(history.first_available(Writer), 1, "nothing written");
        let w1 = endpoint([0, 0, 1, 2]);
        let w2 = endpoint([0, 0, 2, 2]);
        let w3 = endpoint([0, 0, 3, 2]);
        let r1 = endpoint([0, 0, 4, 7]);
        history.announce(data(r1), Reader);
        history.announce(data(w1), Writer);
        history.announce(data(w2), Writer);
        history.announce(data(w3), Writer);
        history.retire(&w2, Writer);
        assert_eq!(history.first_available(Writer), 1, "1 is still alive");
        history.retire(&w1, Writer);
        assert_eq!(history.first_available(Writer), 3, "1 and 2 superseded");
        assert_eq!(history.first_available(Reader), 1);
        history.retire(&r1, Reader);
        assert_eq!(history.first_available(Reader), 2);
        let firsts: Vec<_> = history
            .sends(None)
            .iter()
            .map(|s| (s.kind, s.seq, s.first_available))
            .collect();
        assert_eq!(
            firsts,
            vec![
                (Reader, 1, 2),
                (Writer, 1, 3),
                (Writer, 3, 3),
                (Writer, 4, 3),
                (Writer, 5, 3),
                (Reader, 2, 2),
            ]
        );
    }

    /// The GAP a superseded change is sent as names the SEDP writer of its
    /// kind and retires exactly its range.
    #[test]
    fn a_superseded_change_is_sent_as_a_gap_of_its_range() {
        let mut history = SedpHistory::new();
        let r1 = endpoint([0, 0, 3, 7]);
        history.announce(data(r1), Reader);
        history.retire(&r1, Reader);
        let sends = history.sends(None);
        assert!(sends[0].is_gap());
        let pkt = sends[0].build(&OURS, None, Dialect::Hdds).expect("gap");
        assert_eq!(&pkt[8..20], &OURS, "under our prefix");
        // GAP submessage right after the header: id 0x08, then readerId,
        // writerId, gapStart, gapList.base, numBits.
        assert_eq!(pkt[20], 0x08, "a GAP");
        let le = pkt[21] & 1 != 0;
        assert!(le);
        assert_eq!(&pkt[24..28], &[0, 0, 4, 0xc7]);
        assert_eq!(&pkt[28..32], &[0, 0, 4, 0xc2]);
        let sn = |at: usize| {
            let high = u32::from_le_bytes(pkt[at..at + 4].try_into().expect("4"));
            let low = u32::from_le_bytes(pkt[at + 4..at + 8].try_into().expect("4"));
            (u64::from(high) << 32) | u64::from(low)
        };
        assert_eq!(sn(32), 1, "gapStart");
        assert_eq!(sn(40), 2, "gapList.base");
        assert_eq!(
            u32::from_le_bytes(pkt[48..52].try_into().expect("4")),
            0,
            "no bits"
        );
    }
}

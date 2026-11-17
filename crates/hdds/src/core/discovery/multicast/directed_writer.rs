// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

//! Reliability state of the four TypeLookup builtin endpoints
//! (DDS-XTypes 1.3 7.6.3.3.3: RELIABLE, KEEP_ALL, VOLATILE):
//!
//! - the request writer (0x000300C3) and the reply writer (0x000301C3),
//!   whose every sample is addressed to ONE remote participant
//!   ([`DirectedWriter`]);
//! - the request reader (0x000300C4) and the reply reader (0x000301C4), as
//!   far as answering a peer writer's HEARTBEAT and dropping a resent sample
//!   needs ([`ReceivedStreams`]).
//!
//! Writer rules, and nowhere else:
//!
//! 1. Each writer numbers its own changes from 1 (RTPS 2.5 8.3.5.4 "Sequence
//!    numbers begin at 1"; 8.3.8.2 writerSN "Each RTPS Writer maintains is own
//!    sequence number"; 8.4.7.1 `new_change`). A number is taken only once its
//!    datagram exists.
//! 2. A sample goes to one participant, so a number the writer used for
//!    another participant is irrelevant to this one: each DATA is preceded, in
//!    the same datagram, by a GAP (RTPS 2.5 8.3.8.4) for every number since
//!    the last one this participant was sent that it was never sent.
//! 3. The samples sent to a participant and not yet acknowledged by it are
//!    kept, up to [`HISTORY_PER_PEER`]; they are announced by a periodic
//!    HEARTBEAT (8.4.2.2.3) and repaired when NACKed. A NACKed number never
//!    sent to that participant is GAPped. A number sent to it but no longer
//!    kept lies below the HEARTBEAT's firstSN, which tells the reader it is
//!    no longer available (8.3.8.6, 8.4.15.4): the bound on KEEP_ALL is that
//!    window, stated on the wire, never a silent GAP of a sample it was sent.

use crate::core::rtps_constants::{
    HDDS_VENDOR_ID, RTPS_ENTITYID_TYPELOOKUP_REPLY_READER, RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
    RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER, RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
    RTPS_VERSION_MAJOR, RTPS_VERSION_MINOR,
};
use crate::protocol::rtps::encode_gap;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ops::Range;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Peers a writer keeps a record of; the least recently written is
/// forgotten first. A forgotten peer loses its unacknowledged samples: its
/// next sample is preceded by a GAP from 1 and its reader learns the rest
/// from the next HEARTBEAT.
pub const MAX_TRACKED_PEERS: usize = 256;

/// Unacknowledged samples kept per peer, oldest dropped first.
pub const HISTORY_PER_PEER: usize = 16;

/// GAP submessages one ACKNACK answer may carry.
pub const MAX_GAP_RUNS: usize = 8;

/// Numbers handed out without a destination participant (HTLK), never
/// GAPped to anyone, remembered up to this many.
const MAX_BROADCAST: usize = 64;

/// Minimum interval between two answers to one peer's ACKNACKs.
const ANSWER_INTERVAL: Duration = Duration::from_millis(5);

/// Missing numbers one ACKNACK of ours may name (RTPS 2.5 8.3.5.5: a
/// SequenceNumberSet holds at most 256).
const MAX_NACKED: u64 = 256;

struct PeerRecord {
    /// Last number sent to this peer.
    last_sn: u64,
    /// Sent, not yet acknowledged, ascending.
    history: VecDeque<(u64, Vec<u8>)>,
    last_acknack_count: Option<u32>,
    last_answer: Option<Instant>,
    touched: u64,
}

#[derive(Default)]
struct Inner {
    last_sn: u64,
    clock: u64,
    heartbeat_count: u32,
    peers: HashMap<[u8; 12], PeerRecord>,
    broadcast: VecDeque<u64>,
}

impl Inner {
    /// `range` minus the numbers sent without a destination, as runs.
    fn irrelevant_runs(&self, range: Range<u64>, out: &mut Vec<Range<u64>>) {
        let mut start = range.start;
        for sn in range.clone() {
            if self.broadcast.contains(&sn) {
                if start < sn {
                    out.push(start..sn);
                }
                start = sn + 1;
            }
        }
        if start < range.end {
            out.push(start..range.end);
        }
    }

    fn record(&mut self, peer: [u8; 12], sn: u64, datagram: Option<Vec<u8>>) {
        self.clock += 1;
        let touched = self.clock;
        if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_TRACKED_PEERS {
            let oldest = self
                .peers
                .iter()
                .min_by_key(|(_, rec)| rec.touched)
                .map(|(key, _)| *key);
            if let Some(oldest) = oldest {
                self.peers.remove(&oldest);
            }
        }
        let rec = self.peers.entry(peer).or_insert(PeerRecord {
            last_sn: 0,
            history: VecDeque::new(),
            last_acknack_count: None,
            last_answer: None,
            touched,
        });
        rec.last_sn = sn;
        rec.touched = touched;
        if let Some(datagram) = datagram {
            if rec.history.len() >= HISTORY_PER_PEER {
                rec.history.pop_front();
            }
            rec.history.push_back((sn, datagram));
        }
    }
}

/// One builtin writer that addresses each sample to one participant.
pub struct DirectedWriter {
    writer_id: [u8; 4],
    reader_id: [u8; 4],
    inner: Mutex<Inner>,
}

impl DirectedWriter {
    /// A writer that has numbered nothing yet.
    pub fn new(writer_id: [u8; 4], reader_id: [u8; 4]) -> Self {
        Self {
            writer_id,
            reader_id,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The writer's entity id.
    pub fn writer_id(&self) -> [u8; 4] {
        self.writer_id
    }

    /// The last sequence number this writer handed out (0 before the first).
    pub fn last_sn(&self) -> u64 {
        self.lock().last_sn
    }

    /// Peers this writer keeps a record of.
    pub fn tracked_peers(&self) -> usize {
        self.lock().peers.len()
    }

    /// The numbers held for `peer`, unacknowledged, ascending.
    pub fn held_for(&self, peer: &[u8; 12]) -> Vec<u64> {
        self.lock()
            .peers
            .get(peer)
            .map(|rec| rec.history.iter().map(|(sn, _)| *sn).collect())
            .unwrap_or_default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Number and build the next sample for `peer`.
    ///
    /// `build(sn, gap)` returns the datagram carrying the sample as `sn`; it
    /// must place `gap` (possibly empty: GAP submessages) after the INFO_DST
    /// naming `peer` and before the DATA. `None` from `build` takes no
    /// number. The datagram is kept for repair until `peer` acknowledges it,
    /// so a send that fails after this returns is repaired when the peer
    /// NACKs it, as for any datagram lost on the wire.
    pub fn write_to<F>(&self, peer: [u8; 12], build: F) -> Option<(u64, Vec<u8>)>
    where
        F: FnOnce(u64, &[u8]) -> Option<Vec<u8>>,
    {
        let mut inner = self.lock();
        let sn = inner.last_sn + 1;
        let prev = inner.peers.get(&peer).map_or(0, |p| p.last_sn);
        let mut runs = Vec::new();
        inner.irrelevant_runs(prev + 1..sn, &mut runs);
        let mut gap = Vec::new();
        for run in runs {
            gap.extend_from_slice(
                &encode_gap(&self.reader_id, &self.writer_id, run.start, run.end, 0, &[]).ok()?,
            );
        }
        let datagram = build(sn, &gap)?;
        inner.last_sn = sn;
        inner.record(peer, sn, Some(datagram.clone()));
        Some((sn, datagram))
    }

    /// Number a sample the caller builds without a GAP slot (HTLK). With a
    /// destination, the number is that peer's like any other (kept for
    /// repair); without one, it is never GAPped to anyone.
    pub fn write_undirected<F>(
        &self,
        destination: Option<[u8; 12]>,
        build: F,
    ) -> Option<(u64, Vec<u8>)>
    where
        F: FnOnce(u64) -> Option<Vec<u8>>,
    {
        let mut inner = self.lock();
        let sn = inner.last_sn + 1;
        let datagram = build(sn)?;
        inner.last_sn = sn;
        match destination {
            Some(peer) => inner.record(peer, sn, Some(datagram.clone())),
            None => {
                if inner.broadcast.len() >= MAX_BROADCAST {
                    inner.broadcast.pop_front();
                }
                inner.broadcast.push_back(sn);
            }
        }
        Some((sn, datagram))
    }

    /// Forget everything about `peer` (it left the domain).
    pub fn forget_peer(&self, peer: &[u8; 12]) {
        self.lock().peers.remove(peer);
    }

    /// The peers this writer keeps a record of.
    pub fn peers(&self) -> Vec<[u8; 12]> {
        self.lock().peers.keys().copied().collect()
    }

    /// Answer an ACKNACK from `peer`: `count` its Count_t, `base` its
    /// readerSNState.bitmapBase, `missing` the numbers it names
    /// (end-exclusive ranges, as `AckNackInfo::missing_ranges`).
    ///
    /// Everything below `base` is acknowledged and released. An ACKNACK from
    /// a peer this writer never wrote to, a repeated or older count, or one
    /// arriving within [`ANSWER_INTERVAL`] of the last answer gets no
    /// answer. Otherwise the answer is, in order: one datagram carrying the
    /// GAPs (numbers never sent to `peer`) and a HEARTBEAT, then each NACKed
    /// sample still held, as it was sent.
    pub fn answer_acknack(
        &self,
        our_guid_prefix: &[u8; 12],
        peer: &[u8; 12],
        count: u32,
        base: u64,
        missing: &[Range<u64>],
        now: Instant,
    ) -> Vec<Vec<u8>> {
        let mut inner = self.lock();
        let Some(rec) = inner.peers.get_mut(peer) else {
            return Vec::new();
        };
        if rec.last_acknack_count.is_some_and(|last| count <= last) {
            return Vec::new();
        }
        rec.last_acknack_count = Some(count);
        while rec.history.front().is_some_and(|(sn, _)| *sn < base) {
            rec.history.pop_front();
        }
        if missing.is_empty() {
            return Vec::new();
        }
        if rec
            .last_answer
            .is_some_and(|at| now.saturating_duration_since(at) < ANSWER_INTERVAL)
        {
            return Vec::new();
        }
        rec.last_answer = Some(now);
        let peer_last = rec.last_sn;
        let first = rec.history.front().map_or(peer_last + 1, |(sn, _)| *sn);
        let mut repairs = Vec::new();
        let mut never_sent = Vec::new();
        for range in missing {
            // gapStart 0 is invalid (RTPS 2.5 8.3.7.4.3); numbers below
            // `first` are announced unavailable by the HEARTBEAT.
            let start = range.start.max(first).max(1);
            let end = range.end.min(peer_last + 1);
            if start >= end {
                continue;
            }
            let mut run_start = start;
            for (sn, datagram) in rec.history.iter() {
                if *sn >= start && *sn < end {
                    if run_start < *sn {
                        never_sent.push(run_start..*sn);
                    }
                    repairs.push(datagram.clone());
                    run_start = sn + 1;
                }
            }
            if run_start < end {
                never_sent.push(run_start..end);
            }
        }
        let mut runs = Vec::new();
        for range in never_sent {
            inner.irrelevant_runs(range, &mut runs);
        }
        runs.truncate(MAX_GAP_RUNS);
        inner.heartbeat_count = inner.heartbeat_count.wrapping_add(1);
        let mut pkt = rtps_header(our_guid_prefix);
        push_info_dst(&mut pkt, peer);
        for run in &runs {
            match encode_gap(&self.reader_id, &self.writer_id, run.start, run.end, 0, &[]) {
                Ok(gap) => pkt.extend_from_slice(&gap),
                Err(_) => return Vec::new(),
            }
        }
        push_heartbeat(
            &mut pkt,
            &self.reader_id,
            &self.writer_id,
            first,
            peer_last,
            inner.heartbeat_count,
        );
        let mut out = vec![pkt];
        out.extend(repairs);
        out
    }

    /// One HEARTBEAT per peer that holds unacknowledged samples (RTPS 2.5
    /// 8.4.2.2.3): firstSN the oldest held, lastSN the last sent to it.
    pub fn heartbeats(&self, our_guid_prefix: &[u8; 12]) -> Vec<([u8; 12], Vec<u8>)> {
        let mut inner = self.lock();
        let due: Vec<([u8; 12], u64, u64)> = inner
            .peers
            .iter()
            .filter_map(|(peer, rec)| {
                rec.history
                    .front()
                    .map(|(first, _)| (*peer, *first, rec.last_sn))
            })
            .collect();
        let mut out = Vec::with_capacity(due.len());
        for (peer, first, last) in due {
            inner.heartbeat_count = inner.heartbeat_count.wrapping_add(1);
            let mut pkt = rtps_header(our_guid_prefix);
            push_info_dst(&mut pkt, &peer);
            push_heartbeat(
                &mut pkt,
                &self.reader_id,
                &self.writer_id,
                first,
                last,
                inner.heartbeat_count,
            );
            out.push((peer, pkt));
        }
        out
    }
}

/// What this participant received from each peer TypeLookup writer, as far
/// as answering its HEARTBEAT and dropping a resent sample needs.
#[derive(Default)]
pub struct ReceivedStreams {
    inner: Mutex<ReceivedMap>,
}

/// (peer prefix, peer writer entity id) -> what was received from it.
type ReceivedMap = HashMap<([u8; 12], [u8; 4]), Received>;

#[derive(Default)]
struct Received {
    /// Every number below is received or no longer available.
    base: u64,
    /// Received at or above `base`.
    above: BTreeSet<u64>,
    last_heartbeat_count: Option<u32>,
}

impl Received {
    fn advance(&mut self) {
        while self.above.remove(&self.base) {
            self.base += 1;
        }
        self.above.retain(|sn| *sn >= self.base);
    }
}

/// The ACKNACK one of our TypeLookup readers owes a peer writer.
#[derive(Debug, PartialEq, Eq)]
pub struct AckNackDue {
    /// readerSNState.bitmapBase.
    pub base: u64,
    /// Numbers in `[base, lastSN]` not received.
    pub missing: Vec<u64>,
}

impl ReceivedStreams {
    fn lock(&self) -> std::sync::MutexGuard<'_, ReceivedMap> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record DATA `sn` from `peer`'s writer `writer_id`. `false` when it was
    /// already received: the caller must not process it again.
    pub fn on_data(&self, peer: [u8; 12], writer_id: [u8; 4], sn: u64) -> bool {
        let mut map = self.lock();
        if !map.contains_key(&(peer, writer_id)) && map.len() >= 4 * MAX_TRACKED_PEERS {
            return true;
        }
        let rx = map.entry((peer, writer_id)).or_insert_with(|| Received {
            base: 1,
            ..Received::default()
        });
        if sn < rx.base || !rx.above.insert(sn) {
            return false;
        }
        if rx.above.len() > MAX_NACKED as usize {
            // Never wait on more than one ACKNACK can name.
            if let Some(&lowest) = rx.above.iter().next() {
                rx.base = lowest;
            }
        }
        rx.advance();
        true
    }

    /// Record a GAP: `[start, end)` will never be sent to us.
    pub fn on_gap(&self, peer: [u8; 12], writer_id: [u8; 4], start: u64, end: u64) {
        let mut map = self.lock();
        let Some(rx) = map.get_mut(&(peer, writer_id)) else {
            return;
        };
        if start <= rx.base {
            rx.base = rx.base.max(end);
        } else {
            for sn in start..end.min(start + MAX_NACKED) {
                rx.above.insert(sn);
            }
        }
        rx.advance();
    }

    /// The ACKNACK owed for a HEARTBEAT `[first, last]` with `count`, or
    /// `None` for a repeated or older count (RTPS 2.5 8.4.15.5).
    pub fn on_heartbeat(
        &self,
        peer: [u8; 12],
        writer_id: [u8; 4],
        first: u64,
        last: u64,
        count: u32,
    ) -> Option<AckNackDue> {
        let mut map = self.lock();
        if !map.contains_key(&(peer, writer_id)) && map.len() >= 4 * MAX_TRACKED_PEERS {
            return None;
        }
        let rx = map.entry((peer, writer_id)).or_insert_with(|| Received {
            base: 1,
            ..Received::default()
        });
        if rx.last_heartbeat_count.is_some_and(|c| count <= c) {
            return None;
        }
        rx.last_heartbeat_count = Some(count);
        // Below firstSN: no longer available, not waited for (8.4.15.4).
        rx.base = rx.base.max(first.max(1));
        rx.advance();
        let top = last.min(rx.base.saturating_add(MAX_NACKED - 1));
        let missing = (rx.base..=top)
            .filter(|sn| !rx.above.contains(sn))
            .collect();
        Some(AckNackDue {
            base: rx.base,
            missing,
        })
    }

    /// Forget everything received from `peer`.
    pub fn forget_peer(&self, peer: &[u8; 12]) {
        self.lock().retain(|(p, _), _| p != peer);
    }
}

/// The four TypeLookup endpoints of one participant.
pub struct TypeLookupWriters {
    /// TypeLookup request writer, 0x000300C3, to the request reader 0x000300C4.
    pub request: DirectedWriter,
    /// TypeLookup reply writer, 0x000301C3, to the reply reader 0x000301C4.
    pub reply: DirectedWriter,
    /// What our request and reply readers received from each peer.
    pub received: ReceivedStreams,
}

impl TypeLookupWriters {
    /// Both writers, nothing numbered yet.
    pub fn new() -> Self {
        Self {
            request: DirectedWriter::new(
                RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER,
                RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER,
            ),
            reply: DirectedWriter::new(
                RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER,
                RTPS_ENTITYID_TYPELOOKUP_REPLY_READER,
            ),
            received: ReceivedStreams::default(),
        }
    }

    /// The writer an ACKNACK naming `writer_id` is addressed to, if one of
    /// these two.
    pub fn for_writer(&self, writer_id: &[u8; 4]) -> Option<&DirectedWriter> {
        if *writer_id == self.request.writer_id {
            Some(&self.request)
        } else if *writer_id == self.reply.writer_id {
            Some(&self.reply)
        } else {
            None
        }
    }

    /// Our reader matching a peer's TypeLookup writer `writer_id`.
    pub fn reader_for(writer_id: &[u8; 4]) -> Option<[u8; 4]> {
        if *writer_id == RTPS_ENTITYID_TYPELOOKUP_REQUEST_WRITER {
            Some(RTPS_ENTITYID_TYPELOOKUP_REQUEST_READER)
        } else if *writer_id == RTPS_ENTITYID_TYPELOOKUP_REPLY_WRITER {
            Some(RTPS_ENTITYID_TYPELOOKUP_REPLY_READER)
        } else {
            None
        }
    }

    /// Forget `peer` in all four endpoints.
    pub fn forget_peer(&self, peer: &[u8; 12]) {
        self.request.forget_peer(peer);
        self.reply.forget_peer(peer);
        self.received.forget_peer(peer);
    }
}

impl Default for TypeLookupWriters {
    fn default() -> Self {
        Self::new()
    }
}

fn rtps_header(our_guid_prefix: &[u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(20 + 16 + 4 * 32);
    pkt.extend_from_slice(b"RTPS");
    pkt.push(RTPS_VERSION_MAJOR);
    pkt.push(RTPS_VERSION_MINOR);
    pkt.extend_from_slice(&HDDS_VENDOR_ID);
    pkt.extend_from_slice(our_guid_prefix);
    pkt
}

fn push_info_dst(pkt: &mut Vec<u8>, peer: &[u8; 12]) {
    pkt.push(0x0e);
    pkt.push(0x01); // flags: LE
    pkt.extend_from_slice(&12u16.to_le_bytes());
    pkt.extend_from_slice(peer);
}

/// HEARTBEAT (RTPS 2.5 8.3.8.6, 9.4.5.7), little-endian, F and L clear: the
/// reader answers it.
fn push_heartbeat(
    pkt: &mut Vec<u8>,
    reader_id: &[u8; 4],
    writer_id: &[u8; 4],
    first: u64,
    last: u64,
    count: u32,
) {
    let sn = |v: u64| {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&u32::try_from(v >> 32).unwrap_or(0).to_le_bytes());
        b[4..].copy_from_slice(&u32::try_from(v & 0xFFFF_FFFF).unwrap_or(0).to_le_bytes());
        b
    };
    pkt.push(0x07);
    pkt.push(0x01);
    pkt.extend_from_slice(&28u16.to_le_bytes());
    pkt.extend_from_slice(reader_id);
    pkt.extend_from_slice(writer_id);
    pkt.extend_from_slice(&sn(first));
    pkt.extend_from_slice(&sn(last));
    pkt.extend_from_slice(&count.to_le_bytes());
}

#[cfg(test)]
mod tests;

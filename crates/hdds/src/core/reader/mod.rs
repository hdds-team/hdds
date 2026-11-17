// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reliable Reader State Machine -- RTPS Sec.8.4.12.2
//!
//! This module provides state tracking for reliable data reception.
//! It implements the WriterProxy concept from RTPS, allowing a Reader
//! to correctly respond to HEARTBEATs with proper ACKNACK messages.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  ReaderProxyRegistry (thread-safe, shared)                 |
//! |  +---------------------------------------------------------+|
//! |  |  DashMap<WriterGUID, { reader GUID -> proxy }>         ||
//! |  +---------------------------------------------------------+|
//! |                                                             |
//! |  Used by:                                                   |
//! |  - Control thread: answer_heartbeat() -> one ACKNACK/reader |
//! |  - Reader subscribers: on_data() -> update sequence tracking|
//! +-------------------------------------------------------------+
//! ```
//!
//! RTPS 2.5 8.4.12: every reliable reader keeps its OWN WriterProxy for
//! each writer it is matched with, and answers that writer's HEARTBEAT
//! with its own ACKNACK, under its own readerId. Two local readers of one
//! topic received what they each received and acknowledge it separately;
//! a writer frees a change only once every one of them has.
//!
//! The public, reader-less methods (`on_heartbeat`, `on_data`, ...) keep
//! their historical meaning: one proxy per writer for the whole registry,
//! which is what the SEDP built-in readers use.
//!
//! # Thread Safety
//!
//! Uses DashMap for lock-free concurrent access from multiple threads.

mod group_loss;
pub(crate) use group_loss::{
    AdmissionFrame, GapOrderScope, GroupLossAuthority, GroupLossTicket as LossTicket,
};
mod proxy;

pub use proxy::{AcknackDecision, ReliableReaderProxy};

use dashmap::DashMap;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use super::discovery::multicast::control_types::ENTITYID_UNKNOWN;

/// Reader key of the proxy behind the reader-less public methods.
const UNNAMED_READER: [u8; 16] = [0; 16];

/// What the registry knows about one remote writer.
#[derive(Debug, Clone)]
struct WriterEntry {
    writer_guid: [u8; 16],
    /// One WriterProxy per local reader tracking this writer.
    readers: HashMap<[u8; 16], ReliableReaderProxy>,
}

impl WriterEntry {
    fn new(writer_guid: [u8; 16]) -> Self {
        Self {
            writer_guid,
            readers: HashMap::new(),
        }
    }

    /// The proxy `reader` keeps for this writer.
    fn reader(&mut self, reader: [u8; 16]) -> &mut ReliableReaderProxy {
        let writer_guid = self.writer_guid;
        self.readers
            .entry(reader)
            .or_insert_with(|| ReliableReaderProxy::new(writer_guid))
    }
}

/// One local reader's answer to a writer's HEARTBEAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeartbeatAnswer {
    /// The answering reader's GUID; its entity id is the ACKNACK readerId.
    pub(crate) reader: [u8; 16],
    /// The first sequence the reader still needs (`readerSNState.bitmapBase`).
    pub(crate) bitmap_base: u64,
    /// The sequences it requests, each at or above `bitmap_base`.
    pub(crate) missing: Vec<u64>,
    /// True when the reader holds everything announced (no response needed).
    pub(crate) final_flag: bool,
    /// The ACKNACK count, one sequence per (reader, writer) pair whichever
    /// door answers (RTPS 2.5 8.3.8.1: the writer uses it to discard
    /// duplicates).
    pub(crate) count: u32,
}

/// Thread-safe registry of ReliableReaderProxy instances
///
/// Sequences received before the match, per reader GUID.
type ReceiptsByReader = HashMap<[u8; 16], BTreeSet<i64>>;

/// Shared between the control thread (HEARTBEAT handling) and the reader
/// subscribers (DATA reception tracking).
#[derive(Debug, Clone)]
pub struct ReaderProxyRegistry {
    /// Map from writer GUID to the proxies kept for it
    proxies: Arc<DashMap<[u8; 16], WriterEntry>>,
    /// Sequences a reader received from a writer it was not yet matched
    /// with, per writer then reader: handed to the reader's proxy when the
    /// match comes (`match_writer`), dropped when it does not.
    unmatched_receipts: Arc<DashMap<[u8; 16], ReceiptsByReader>>,
}

/// Sequences kept at most per (writer, reader) pair before their match, the
/// bound the proxy itself keeps above its floor. A receipt past it is not
/// recorded: the matched proxy then requests that sequence like any other it
/// never heard of.
const MAX_UNMATCHED_RECEIPTS: usize = 4096;

impl Default for ReaderProxyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaderProxyRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            proxies: Arc::new(DashMap::new()),
            unmatched_receipts: Arc::new(DashMap::new()),
        }
    }

    /// Process a HEARTBEAT from a remote writer
    ///
    /// Creates proxy if not exists, then delegates to proxy.on_heartbeat().
    ///
    /// # Arguments
    /// - `writer_guid`: 16-byte GUID (guid_prefix + entity_id)
    /// - `first_seq`: firstAvailableSeqNumber from HEARTBEAT
    /// - `last_seq`: lastSeqNumber from HEARTBEAT
    /// - `count`: HEARTBEAT count
    /// - `final_flag`: FinalFlag from HEARTBEAT
    ///
    /// # Returns
    /// Decision on whether/how to send ACKNACK
    pub fn on_heartbeat(
        &self,
        writer_guid: [u8; 16],
        first_seq: i64,
        last_seq: i64,
        count: u32,
        final_flag: bool,
    ) -> AcknackDecision {
        self.proxies
            .entry(writer_guid)
            .or_insert_with(|| WriterEntry::new(writer_guid))
            .reader(UNNAMED_READER)
            .on_heartbeat(first_seq, last_seq, count, final_flag)
    }

    /// Record that DATA was received from a remote writer
    ///
    /// Creates proxy if not exists, then updates highest_received_seq.
    ///
    /// # Arguments
    /// - `writer_guid`: 16-byte GUID (guid_prefix + entity_id)
    /// - `seq`: Sequence number from DATA submessage
    pub fn on_data(&self, writer_guid: [u8; 16], seq: i64) {
        self.proxies
            .entry(writer_guid)
            .or_insert_with(|| WriterEntry::new(writer_guid))
            .reader(UNNAMED_READER)
            .on_data(seq);
    }

    /// Record a writer-declared GAP so the ACKNACK base advances past purged
    /// sequences: only the contiguous range [gap_start, gap_list_base - 1],
    /// `on_gap_listed` with no listed sequence. A GAP as received is
    /// `on_gap_listed`'s.
    ///
    /// Both arguments are `i64` to match the wire representation (RTPS SequenceNumber_t
    /// is a signed 64-bit value; values are always >= 1 on a well-formed stream).
    pub fn on_gap(&self, writer_guid: [u8; 16], gap_start: i64, gap_list_base: i64) {
        self.on_gap_listed(writer_guid, gap_start, gap_list_base, &[]);
    }

    /// Record a writer-declared GAP (RTPS v2.5 Sec.8.3.8.4, Table 8.43) so the
    /// ACKNACK stops requesting any number it names.
    ///
    /// Routes to the registry-wide proxy of the writer, creating it if it does
    /// not yet exist (mirrors the `on_data` get-or-create pattern), and
    /// records the GAP as `note_gap_for` does for a named reader: `note_gap`
    /// moves the floor over the contiguous range [gap_start, gap_list_base -
    /// 1] when it starts at the floor, and every sequence of `gap_list_seqs`
    /// (the parser lists there the bitmap and the contiguous range) is
    /// recorded like a received one, so a number retired by the bitmap
    /// alone, or a range above a hole, is not requested again.
    pub(crate) fn on_gap_listed(
        &self,
        writer_guid: [u8; 16],
        gap_start: i64,
        gap_list_base: i64,
        gap_list_seqs: &[u64],
    ) {
        let mut entry = self
            .proxies
            .entry(writer_guid)
            .or_insert_with(|| WriterEntry::new(writer_guid));
        let proxy = entry.reader(UNNAMED_READER);
        proxy.note_gap(gap_start, gap_list_base);
        for &seq in gap_list_seqs {
            if let Ok(seq) = i64::try_from(seq) {
                proxy.on_data(seq);
            }
        }
    }

    /// Compute the missing-sequence holes for a writer's contiguous prefix in
    /// the window [low_mark+1 ..= last_seq], capped to the RTPS 256-bit bitmap.
    ///
    /// Returns an empty vec if the writer is unknown (treated as "nothing
    /// received, nothing announced yet" -- the caller falls back to its base).
    /// Drives the ACKNACK readerSNState bitmap from the ACTUAL holes rather
    /// than a single base sequence (RTPS v2.5 Sec.8.4.12.2).
    pub fn missing_holes(&self, writer_guid: &[u8; 16], last_seq: i64) -> Vec<i64> {
        self.proxies
            .get(writer_guid)
            .and_then(|entry| {
                entry
                    .readers
                    .get(&UNNAMED_READER)
                    .map(|p| p.missing_holes(last_seq))
            })
            .unwrap_or_default()
    }

    /// Mark that ACKNACK was sent for a writer (for rate limiting)
    pub fn mark_acknack_sent(&self, writer_guid: &[u8; 16]) {
        if let Some(mut entry) = self.proxies.get_mut(writer_guid) {
            if let Some(proxy) = entry.readers.get_mut(&UNNAMED_READER) {
                proxy.mark_acknack_sent();
            }
        }
    }

    /// Get proxy for a writer (for inspection/debugging)
    pub fn get_proxy(&self, writer_guid: &[u8; 16]) -> Option<ReliableReaderProxy> {
        self.proxies
            .get(writer_guid)
            .and_then(|entry| entry.readers.get(&UNNAMED_READER).cloned())
    }

    /// Number of tracked writers
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Remove a writer and every proxy kept for it (e.g., when peer disconnects)
    pub fn remove(&self, writer_guid: &[u8; 16]) -> Option<ReliableReaderProxy> {
        self.unmatched_receipts.remove(writer_guid);
        self.proxies
            .remove(writer_guid)
            .and_then(|(_, mut entry)| entry.readers.remove(&UNNAMED_READER))
    }

    /// Clear all proxies
    pub fn clear(&self) {
        self.proxies.clear();
        self.unmatched_receipts.clear();
    }

    /// `reader` was told by `writer_guid`'s GAP (RTPS 2.5 8.3.8.4) that the
    /// contiguous range [gap_start, gap_list_base) and the sequences of its
    /// bitmap are irrelevant: they no longer need requesting. Only a reader
    /// tracking the writer takes it (ENTITYID_UNKNOWN addresses the readers
    /// matched when the GAP arrives, not the ones matched later).
    ///
    /// Every sequence the GAP lists is recorded like a received one (RTPS
    /// 2.5 8.4.12: the reader marks each irrelevant change), so none is
    /// requested again and the floor never moves over a hole below them.
    /// The parser lists the bitmap (at most 256, RTPS 2.5 9.4.2.6) and the
    /// contiguous range (capped at 65 536); the proxy caps what it holds
    /// above its floor. `note_gap` moves the floor in one step when the
    /// range starts at it.
    pub(crate) fn note_gap_for(
        &self,
        writer_guid: &[u8; 16],
        reader: &[u8; 16],
        gap_start: i64,
        gap_list_base: i64,
        gap_list_seqs: &[u64],
    ) {
        let Some(mut entry) = self.proxies.get_mut(writer_guid) else {
            return;
        };
        let Some(proxy) = entry.readers.get_mut(reader) else {
            return;
        };
        proxy.note_gap(gap_start, gap_list_base);
        for &seq in gap_list_seqs {
            if let Ok(seq) = i64::try_from(seq) {
                proxy.on_data(seq);
            }
        }
    }

    /// `reader` starts tracking `writer_guid`: the two are matched (RTPS 2.5
    /// 8.4.12, `matched_writer_add`). Idempotent. This is the only way a
    /// named reader's proxy comes to exist.
    ///
    /// What the reader already received from the writer before the match
    /// (`on_data_for`) is received: the new proxy records it (RTPS 2.5
    /// 8.4.10.4, a WriterProxy's changes are RECEIVED once the reader has
    /// them), so the reader's first ACKNACK does not request again changes
    /// it holds, and a writer that answers such a request for a fragmented
    /// change with part of its fragments is not left owing the rest.
    pub(crate) fn match_writer(&self, writer_guid: [u8; 16], reader: [u8; 16]) {
        let received = self
            .unmatched_receipts
            .get_mut(&writer_guid)
            .and_then(|mut by_reader| by_reader.remove(&reader));
        self.unmatched_receipts
            .remove_if(&writer_guid, |_, by_reader| by_reader.is_empty());
        let mut entry = self
            .proxies
            .entry(writer_guid)
            .or_insert_with(|| WriterEntry::new(writer_guid));
        let proxy = entry.reader(reader);
        for seq in received.into_iter().flatten() {
            proxy.on_data(seq);
        }
    }

    /// `reader` stops tracking `writer_guid` (`matched_writer_remove`).
    pub(crate) fn unmatch_writer(&self, writer_guid: &[u8; 16], reader: &[u8; 16]) {
        self.forget_unmatched_receipts(writer_guid, reader);
        self.proxies.remove_if_mut(writer_guid, |_, entry| {
            entry.readers.remove(reader);
            entry.readers.is_empty()
        });
    }

    /// `reader` is gone: drop every proxy it kept.
    pub(crate) fn forget_reader(&self, reader: &[u8; 16]) {
        self.unmatched_receipts.retain(|_, by_reader| {
            by_reader.remove(reader);
            !by_reader.is_empty()
        });
        self.proxies.retain(|_, entry| {
            !(entry.readers.remove(reader).is_some() && entry.readers.is_empty())
        });
    }

    /// Record that `reader` received DATA `seq` from `writer_guid`. A DATA
    /// from a writer the reader is not matched with creates no proxy: no
    /// HEARTBEAT of that writer is answered and no fragment of it is
    /// requested in the reader's name. It is kept, bounded, for the proxy the
    /// match creates (`match_writer`), and dropped if the pair unmatches or
    /// the reader goes first.
    pub(crate) fn on_data_for(&self, writer_guid: &[u8; 16], reader: &[u8; 16], seq: i64) {
        if let Some(mut entry) = self.proxies.get_mut(writer_guid) {
            if let Some(proxy) = entry.readers.get_mut(reader) {
                proxy.on_data(seq);
                return;
            }
        }
        let mut by_reader = self.unmatched_receipts.entry(*writer_guid).or_default();
        let received = by_reader.entry(*reader).or_default();
        if received.len() < MAX_UNMATCHED_RECEIPTS {
            received.insert(seq);
        }
    }

    /// Drop what `reader` received from `writer_guid` before a match.
    fn forget_unmatched_receipts(&self, writer_guid: &[u8; 16], reader: &[u8; 16]) {
        if let Some(mut by_reader) = self.unmatched_receipts.get_mut(writer_guid) {
            by_reader.remove(reader);
        }
        self.unmatched_receipts
            .remove_if(writer_guid, |_, by_reader| by_reader.is_empty());
    }

    /// Whether `other` is this registry (a clone of it), not a copy.
    #[cfg(test)]
    pub(crate) fn shares_state_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.proxies, &other.proxies)
    }

    /// Whether `reader`'s proxy of `writer_guid` still awaits `seq`: neither
    /// received nor declared irrelevant to it. False without a proxy.
    pub(crate) fn awaits(&self, writer_guid: &[u8; 16], reader: &[u8; 16], seq: u64) -> bool {
        let Ok(seq) = i64::try_from(seq) else {
            return false;
        };
        self.proxies
            .get(writer_guid)
            .and_then(|entry| entry.readers.get(reader).map(|proxy| proxy.awaits(seq)))
            .unwrap_or(false)
    }

    /// The readers tracking `writer_guid`, sorted: the local reliable
    /// readers matched with it. The router requests missing fragments in
    /// their names (a NACK_FRAG is a reader's request, RTPS 2.5 8.3.8.12).
    pub(crate) fn readers_of(&self, writer_guid: &[u8; 16]) -> Vec<[u8; 16]> {
        let mut readers: Vec<_> = self
            .proxies
            .get(writer_guid)
            .map(|entry| {
                entry
                    .readers
                    .keys()
                    .filter(|reader| **reader != UNNAMED_READER)
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        readers.sort_unstable();
        readers
    }

    /// The proxy `reader` keeps for `writer_guid`.
    #[cfg(test)]
    pub(crate) fn pair(
        &self,
        writer_guid: &[u8; 16],
        reader: &[u8; 16],
    ) -> Option<ReliableReaderProxy> {
        self.proxies
            .get(writer_guid)
            .and_then(|entry| entry.readers.get(reader).cloned())
    }

    /// Answer a writer's HEARTBEAT once per local reader tracking it, each
    /// from its own proxy (RTPS 2.5 8.4.12). A writer no local reader
    /// tracks gets no answer. The unnamed proxy is not a reader and never
    /// answers here. The caller reports each answer it managed to send
    /// with `mark_acknack_sent_for`.
    ///
    /// A HEARTBEAT whose readerId names one reader is that reader's alone:
    /// the others neither answer it nor take its state (RTPS 2.5 8.3.8.6;
    /// ENTITYID_UNKNOWN addresses them all).
    pub(crate) fn answer_heartbeat(
        &self,
        writer_guid: &[u8; 16],
        addressees: Addressees,
        heartbeat: &HeartbeatSeen,
    ) -> Vec<HeartbeatAnswer> {
        let Some(mut entry) = self.proxies.get_mut(writer_guid) else {
            return Vec::new();
        };
        entry
            .readers
            .iter_mut()
            .filter(|(reader, _)| **reader != UNNAMED_READER)
            .filter(|(reader, _)| addressees.includes(reader))
            .filter_map(|(reader, proxy)| answer_from(*reader, proxy, heartbeat))
            .collect()
    }

    /// Answer a writer's HEARTBEAT for one reader only, from the same proxy
    /// the other doors use. `None` when the reader does not track the writer
    /// or has nothing to send now.
    pub(crate) fn answer_heartbeat_for(
        &self,
        writer_guid: &[u8; 16],
        reader: &[u8; 16],
        heartbeat: &HeartbeatSeen,
    ) -> Option<HeartbeatAnswer> {
        let mut entry = self.proxies.get_mut(writer_guid)?;
        let proxy = entry.readers.get_mut(reader)?;
        answer_from(*reader, proxy, heartbeat)
    }

    /// `reader`'s answer to `writer_guid` left: its rate-limit window runs.
    pub(crate) fn mark_acknack_sent_for(&self, writer_guid: &[u8; 16], reader: &[u8; 16]) {
        if let Some(mut entry) = self.proxies.get_mut(writer_guid) {
            if let Some(proxy) = entry.readers.get_mut(reader) {
                proxy.mark_acknack_sent();
            }
        }
    }
}

/// The local readers a HEARTBEAT is answered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Addressees {
    /// readerId ENTITYID_UNKNOWN: every reader tracking the writer.
    All,
    /// The one reader the readerId names.
    One([u8; 4]),
}

impl Addressees {
    /// The addressees of a HEARTBEAT with this readerId (RTPS 2.5 8.3.8.6).
    pub(crate) fn of(reader_entity_id: [u8; 4]) -> Self {
        if reader_entity_id == ENTITYID_UNKNOWN {
            Self::All
        } else {
            Self::One(reader_entity_id)
        }
    }

    fn includes(&self, reader: &[u8; 16]) -> bool {
        let [.., e0, e1, e2, e3] = *reader;
        let entity_id = [e0, e1, e2, e3];
        match self {
            Self::All => true,
            Self::One(named) => *named == entity_id,
        }
    }
}

/// A HEARTBEAT as the proxies read it (RTPS 2.5 8.3.8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HeartbeatSeen {
    pub(crate) first_seq: i64,
    pub(crate) last_seq: i64,
    pub(crate) count: u32,
    pub(crate) final_flag: bool,
}

/// One reader's answer to a HEARTBEAT, from its own proxy.
fn answer_from(
    reader: [u8; 16],
    proxy: &mut ReliableReaderProxy,
    heartbeat: &HeartbeatSeen,
) -> Option<HeartbeatAnswer> {
    let decision = proxy.on_heartbeat(
        heartbeat.first_seq,
        heartbeat.last_seq,
        heartbeat.count,
        heartbeat.final_flag,
    );
    let (bitmap_base, missing, final_flag) = match decision {
        AcknackDecision::Ignore | AcknackDecision::RateLimited => return None,
        AcknackDecision::Synchronized { bitmap_base } => {
            (bitmap_base.max(1).unsigned_abs(), Vec::new(), true)
        }
        AcknackDecision::NeedData { bitmap_base } => {
            // Drive the bitmap from the ACTUAL holes in the contiguous-prefix
            // state (RTPS v2.5 Sec.8.4.12): a reader that received {1,3} NACKs
            // {2}, not the whole range. An empty bitmap here let a durable
            // writer that answers only set bits skip its historical replay, so fall
            // back to the base bit when no finer hole is recorded.
            let base = bitmap_base.max(1).unsigned_abs();
            let holes = proxy.missing_holes(heartbeat.last_seq);
            let missing = if holes.is_empty() {
                vec![base]
            } else {
                holes.into_iter().map(|h| h.max(1).unsigned_abs()).collect()
            };
            (base, missing, false)
        }
    };
    Some(HeartbeatAnswer {
        reader,
        bitmap_base,
        missing,
        final_flag,
        count: proxy.next_acknack_count(),
    })
}

/// One local reliable reader's handle on the registry: it credits what THIS
/// reader received, matches the writers THIS reader is matched with, and
/// answers their HEARTBEATs from THIS reader's proxies.
#[derive(Debug, Clone)]
pub(crate) struct ReaderAckCredit {
    registry: ReaderProxyRegistry,
    reader: [u8; 16],
    /// Tests only: the next thread through `pass` waits until the sender
    /// `hold_next` returned is dropped.
    #[cfg(test)]
    paused: std::sync::Arc<std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>>,
}

impl ReaderAckCredit {
    pub(crate) fn new(registry: ReaderProxyRegistry, reader: [u8; 16]) -> Self {
        Self {
            registry,
            reader,
            #[cfg(test)]
            paused: std::sync::Arc::default(),
        }
    }

    /// This reader received DATA `seq` from `writer_guid` (a duplicate
    /// included: it was received all the same).
    pub(crate) fn on_data(&self, writer_guid: [u8; 16], seq: i64) {
        self.registry.on_data_for(&writer_guid, &self.reader, seq);
    }

    /// The highest sequence of `writer_guid` below which this reader awaits
    /// nothing: every sequence up to it was received, or declared irrelevant
    /// or no longer available. `None` when this reader keeps no record of
    /// the writer.
    pub(crate) fn settled(&self, writer_guid: &[u8; 16]) -> Option<u64> {
        self.registry
            .proxies
            .get(writer_guid)
            .and_then(|entry| {
                entry
                    .readers
                    .get(&self.reader)
                    .map(|proxy| proxy.low_mark())
            })
            .map(|low_mark| u64::try_from(low_mark).unwrap_or(0))
    }

    /// Snapshot what this reader was actually owed before unmatching.
    pub(crate) fn unreceived_ranges(&self, writer_guid: &[u8; 16]) -> Vec<(u64, u64)> {
        self.registry
            .proxies
            .get(writer_guid)
            .and_then(|entry| {
                entry
                    .readers
                    .get(&self.reader)
                    .map(|proxy| proxy.unreceived_ranges())
            })
            .unwrap_or_default()
    }

    /// Reserve an owned sample or a known cohort obligation on the GROUP path.
    pub(crate) fn claim_group_sample(
        &self,
        writer: &[u8; 16],
        authority: &Arc<GroupLossAuthority>,
        seq: u64,
        owned: bool,
        frame: &Arc<AdmissionFrame>,
    ) -> Option<Arc<LossTicket>> {
        let entry = self.registry.proxies.get(writer);
        let proxy = entry.as_ref().and_then(|e| e.readers.get(&self.reader));
        let _ = proxy;
        authority.claim(*writer, seq, owned, frame, None, false)
    }

    /// Apply an authenticated GROUP GAP after its filtered intervals are known.
    pub(crate) fn group_gap_loss(
        &self,
        writer: &[u8; 16],
        authority: &GroupLossAuthority,
        start: i64,
        base: i64,
        listed: &[u64],
        filtered: &std::collections::BTreeMap<u64, u64>,
    ) -> Option<u64> {
        self.group_gap_loss_with_order(writer, authority, start, base, listed, filtered, true)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn group_gap_loss_with_order(
        &self,
        writer: &[u8; 16],
        authority: &GroupLossAuthority,
        start: i64,
        base: i64,
        listed: &[u64],
        filtered: &std::collections::BTreeMap<u64, u64>,
        credit: bool,
    ) -> Option<u64> {
        let Some(mut entry) = self.registry.proxies.get_mut(writer) else {
            return Some(0);
        };
        let Some(proxy) = entry.readers.get_mut(&self.reader) else {
            return Some(0);
        };
        authority.heartbeat_prefix(proxy.next_needed().max(1) as u64);
        let before = proxy.unreceived_ranges();
        let mut proposed = proxy.clone();
        proposed.note_gap(start, base);
        for &seq in listed {
            if let Ok(seq) = i64::try_from(seq) {
                proposed.on_data(seq);
            }
        }
        let after = proposed.unreceived_ranges();
        let consumed = group_loss::consumed(&before, &after);
        let count = if credit {
            authority.try_consume(&consumed, filtered, false)
        } else {
            let mut declared = Vec::with_capacity(listed.len().saturating_add(1));
            if base > start && start > 0 {
                declared.push((start as u64, base as u64));
            }
            for &seq in listed {
                if seq > 0 && !(start.max(0) as u64..base.max(0) as u64).contains(&seq) {
                    declared.push((seq, seq.saturating_add(1)));
                }
            }
            authority.try_consume_gap(&consumed, &declared, filtered)
        };
        proposed.set_group_order_pending(authority.order_gap_end() != 0);
        proxy.set_group_order_pending(authority.order_gap_end() != 0);
        let Some(count) = count else {
            let through = (base.max(0) as u64)
                .max(listed.iter().copied().max().unwrap_or(0).saturating_add(1));
            authority.defer_gap(through);
            return None;
        };
        if credit {
            *proxy = proposed;
            authority.heartbeat_prefix(proxy.next_needed().max(1) as u64);
        } else {
            authority.refresh_gap_deferred();
        }
        Some(count)
    }

    /// Source receives the heartbeat before its batched ACKNACK is built.
    pub(crate) fn group_heartbeat_loss(
        &self,
        writer: &[u8; 16],
        authority: &GroupLossAuthority,
        first: u64,
        filtered: &std::collections::BTreeMap<u64, u64>,
    ) -> Option<u64> {
        let Ok(first) = i64::try_from(first) else {
            return Some(0);
        };
        let Some(mut entry) = self.registry.proxies.get_mut(writer) else {
            return Some(0);
        };
        let Some(proxy) = entry.readers.get_mut(&self.reader) else {
            return Some(0);
        };
        let order_pending = authority.order_gap_end() != 0;
        authority.heartbeat_prefix(proxy.next_needed().max(1) as u64);
        proxy.set_group_order_pending(order_pending);
        let before = proxy.unreceived_ranges();
        let mut proposed = proxy.clone();
        proposed.note_gap(proxy.next_needed(), first);
        let after = proposed.unreceived_ranges();
        let Some(count) =
            authority.try_consume(&group_loss::consumed(&before, &after), filtered, true)
        else {
            proxy.set_group_heartbeat_blocked(true);
            authority.defer_gap(first.max(1) as u64);
            return None;
        };
        proposed.set_group_heartbeat_blocked(false);
        if !order_pending {
            *proxy = proposed;
        } else {
            proxy.set_group_heartbeat_blocked(false);
        }
        authority.heartbeat_prefix(first.max(0) as u64);
        Some(count)
    }

    /// Close this namespace's actual debt before its proxy is removed.
    pub(crate) fn close_group_loss(
        &self,
        writer: &[u8; 16],
        authority: &GroupLossAuthority,
        filtered: &std::collections::BTreeMap<u64, u64>,
    ) -> u64 {
        let Some(entry) = self.registry.proxies.get(writer) else {
            authority.close(0);
            return 0;
        };
        let Some(proxy) = entry.readers.get(&self.reader) else {
            authority.close(0);
            return 0;
        };
        authority.close_debt(
            &proxy.unreceived_ranges(),
            filtered,
            proxy.announced_through(),
        )
    }

    /// Resume only the already terminal prefix of a confirmed continuation.
    pub(crate) fn resume_group_loss(&self, writer: &[u8; 16], authority: &GroupLossAuthority) {
        let through = authority.reopen();
        if let Some(mut entry) = self.registry.proxies.get_mut(writer) {
            if let Some(proxy) = entry.readers.get_mut(&self.reader) {
                proxy.note_gap(
                    1,
                    i64::try_from(through).unwrap_or(i64::MAX).saturating_add(1),
                );
            }
        }
    }

    /// `writer_guid`'s GAP reached this reader (see `note_gap_for`).
    pub(crate) fn note_gap(
        &self,
        writer_guid: &[u8; 16],
        gap_start: i64,
        gap_list_base: i64,
        gap_list_seqs: &[u64],
    ) {
        self.registry.note_gap_for(
            writer_guid,
            &self.reader,
            gap_start,
            gap_list_base,
            gap_list_seqs,
        );
    }

    pub(crate) fn set_group_order_pending(&self, writer: &[u8; 16], pending: bool) {
        if let Some(mut entry) = self.registry.proxies.get_mut(writer) {
            if let Some(proxy) = entry.readers.get_mut(&self.reader) {
                proxy.set_group_order_pending(pending);
            }
        }
    }

    pub(crate) fn credit_ordered_gap(
        &self,
        writer: &[u8; 16],
        authority: &GroupLossAuthority,
        start: i64,
        base: i64,
        listed: &[u64],
    ) -> bool {
        let Some(mut entry) = self.registry.proxies.get_mut(writer) else {
            return false;
        };
        let Some(proxy) = entry.readers.get_mut(&self.reader) else {
            return false;
        };
        proxy.note_gap(start, base);
        for &seq in listed {
            if let Ok(seq) = i64::try_from(seq) {
                proxy.on_data(seq);
            }
        }
        authority.heartbeat_prefix(proxy.next_needed().max(1) as u64);
        true
    }

    /// This reader matched a writer.
    pub(crate) fn match_writer(&self, writer_guid: [u8; 16]) {
        self.registry.match_writer(writer_guid, self.reader);
    }

    /// This reader no longer matches `writer_guid`.
    pub(crate) fn unmatch_writer(&self, writer_guid: &[u8; 16]) {
        self.registry.unmatch_writer(writer_guid, &self.reader);
    }

    /// This reader's GUID, the one SEDP announces.
    pub(crate) fn reader(&self) -> [u8; 16] {
        self.reader
    }

    /// The next thread through `pass` waits until the returned sender is
    /// dropped (at most ten seconds, so a failing test cannot hang); the
    /// others go through.
    #[cfg(test)]
    pub(crate) fn hold_next(&self) -> std::sync::mpsc::Sender<()> {
        let (resume, paused) = std::sync::mpsc::channel();
        *self.paused.lock().unwrap_or_else(|e| e.into_inner()) = Some(paused);
        resume
    }

    /// Whether a thread is yet to take the pause `hold_next` set.
    #[cfg(test)]
    pub(crate) fn holding(&self) -> bool {
        self.paused
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    /// Whether this reader still awaits `seq` of `writer_guid`: neither
    /// received nor declared irrelevant.
    #[cfg(test)]
    pub(crate) fn awaits(&self, writer_guid: &[u8; 16], seq: u64) -> bool {
        self.registry.awaits(writer_guid, &self.reader, seq)
    }

    /// A pause point for tests; see `hold_next`.
    #[cfg(test)]
    pub(crate) fn pass(&self) {
        let paused = self.paused.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(paused) = paused {
            let _ = paused.recv_timeout(std::time::Duration::from_secs(10));
        }
    }

    /// Whether this reader is matched with `writer_guid`.
    pub(crate) fn is_matched(&self, writer_guid: &[u8; 16]) -> bool {
        self.registry
            .proxies
            .get(writer_guid)
            .is_some_and(|entry| entry.readers.contains_key(&self.reader))
    }

    /// Whether this reader's rate-limit window for `writer_guid` runs.
    #[cfg(test)]
    pub(crate) fn acknack_sent(&self, writer_guid: &[u8; 16]) -> bool {
        self.registry
            .pair(writer_guid, &self.reader)
            .is_some_and(|proxy| proxy.acknack_sent())
    }

    /// This reader's answer to `writer_guid`'s HEARTBEAT, if it tracks it.
    pub(crate) fn answer_heartbeat(
        &self,
        writer_guid: &[u8; 16],
        heartbeat: &HeartbeatSeen,
    ) -> Option<HeartbeatAnswer> {
        self.registry
            .answer_heartbeat_for(writer_guid, &self.reader, heartbeat)
    }

    /// This reader's answer to `writer_guid` left.
    pub(crate) fn mark_acknack_sent(&self, writer_guid: &[u8; 16]) {
        self.registry
            .mark_acknack_sent_for(writer_guid, &self.reader);
    }

    /// The lease whose drop retires this reader from the registry.
    pub(crate) fn lease(&self) -> ReaderProxyLease {
        ReaderProxyLease(self.clone())
    }
}

/// Retires a reader from the registry when dropped (held by the DataReader).
///
/// Nothing creates a proxy for a reader except its match callback, and the
/// DataReader drops its match registration first: `MatchToken::drop` takes
/// the registry's entry list for writing, which waits out a callback that
/// runs under that list's read lock. So once this lease drops, no proxy of
/// the reader can come back. A DATA credited afterwards only updates a
/// proxy that exists.
#[derive(Debug)]
pub(crate) struct ReaderProxyLease(ReaderAckCredit);

impl Drop for ReaderProxyLease {
    fn drop(&mut self) {
        self.0.registry.forget_reader(&self.0.reader);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_guid(id: u8) -> [u8; 16] {
        let mut guid = [0u8; 16];
        guid[0] = id;
        guid
    }

    #[test]
    fn test_registry_creates_proxy_on_heartbeat() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(1);

        assert!(registry.is_empty());

        let decision = registry.on_heartbeat(guid, 1, 1, 1, false);

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(matches!(
            decision,
            AcknackDecision::NeedData { bitmap_base: 1 }
        ));
    }

    #[test]
    fn test_registry_data_updates_state() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(1);

        // First: HEARTBEAT creates proxy
        let _ = registry.on_heartbeat(guid, 1, 1, 1, false);

        // Receive DATA
        registry.on_data(guid, 1);

        // Next HEARTBEAT should show synchronized
        let decision = registry.on_heartbeat(guid, 1, 1, 2, false);
        assert!(matches!(
            decision,
            AcknackDecision::Synchronized { bitmap_base: 2 }
        ));
    }

    #[test]
    fn test_registry_multiple_writers() {
        let registry = ReaderProxyRegistry::new();
        let guid1 = make_guid(1);
        let guid2 = make_guid(2);

        registry.on_heartbeat(guid1, 1, 1, 1, false);
        registry.on_heartbeat(guid2, 1, 5, 1, false);

        assert_eq!(registry.len(), 2);

        // Update only guid1
        registry.on_data(guid1, 1);

        // guid1 synchronized, guid2 still needs data
        let d1 = registry.on_heartbeat(guid1, 1, 1, 2, false);
        let d2 = registry.on_heartbeat(guid2, 1, 5, 2, false);

        assert!(matches!(d1, AcknackDecision::Synchronized { .. }));
        assert!(matches!(d2, AcknackDecision::NeedData { bitmap_base: 1 }));
    }

    fn guid(prefix: u8, id: u8) -> [u8; 16] {
        let mut guid = [prefix; 16];
        guid[15] = id;
        guid
    }

    fn hb(first_seq: i64, last_seq: i64, count: u32) -> HeartbeatSeen {
        HeartbeatSeen {
            first_seq,
            last_seq,
            count,
            final_flag: false,
        }
    }

    fn readers_answering(answers: &[HeartbeatAnswer]) -> Vec<[u8; 16]> {
        let mut readers: Vec<_> = answers.iter().map(|a| a.reader).collect();
        readers.sort_unstable();
        readers
    }

    /// RTPS 2.5 8.4.10.4 / 8.4.12.2: a change the reader received is
    /// RECEIVED in the WriterProxy the match creates, also when it arrived
    /// before the match; the first ACKNACK requests only what the reader
    /// does not hold. The sequence numbers are those of a captured exchange:
    /// a writer that started at 36 and announced 36..=95 in the HEARTBEAT
    /// that followed the match, the reader holding 36..=91.
    #[test]
    fn what_a_reader_received_before_the_match_is_not_requested_again() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let reader = guid(0xA0, 7);
        for seq in 36..=91 {
            registry.on_data_for(&writer, &reader, seq);
        }
        assert!(
            registry
                .answer_heartbeat(&writer, Addressees::All, &hb(36, 95, 1))
                .is_empty(),
            "no proxy before the match: the writer's HEARTBEAT is not answered"
        );
        assert!(registry.readers_of(&writer).is_empty());

        registry.match_writer(writer, reader);
        assert_eq!(
            registry.answer_heartbeat(&writer, Addressees::All, &hb(36, 95, 2)),
            vec![HeartbeatAnswer {
                reader,
                bitmap_base: 92,
                missing: vec![92, 93, 94, 95],
                final_flag: false,
                count: 1,
            }]
        );
        assert!(!registry.awaits(&writer, &reader, 38));
        assert!(registry.awaits(&writer, &reader, 92));
    }

    /// What a reader received before a match belongs to that (writer,
    /// reader) pair only, and goes when the pair unmatches or the reader
    /// does: another reader, or a later match, starts from what it received.
    #[test]
    fn receipts_before_the_match_belong_to_their_pair() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let (first, second, gone) = (guid(0xA0, 7), guid(0xA0, 8), guid(0xA0, 9));
        for seq in 1..=3 {
            registry.on_data_for(&writer, &first, seq);
            registry.on_data_for(&writer, &gone, seq);
        }
        registry.match_writer(writer, second);
        assert_eq!(
            registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 3, 1))[0].missing,
            vec![1, 2, 3],
            "the first reader's receipts are not the second's"
        );

        registry.unmatch_writer(&writer, &first);
        registry.forget_reader(&gone);
        registry.match_writer(writer, first);
        registry.match_writer(writer, gone);
        let mut answers = registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 3, 2));
        answers.sort_by_key(|a| a.reader);
        assert_eq!(
            answers
                .iter()
                .map(|a| a.missing.clone())
                .collect::<Vec<_>>(),
            vec![vec![1, 2, 3], vec![1, 2, 3], vec![1, 2, 3]],
            "an unmatch and the reader's end drop what was received before"
        );
    }

    /// RTPS 2.5 8.4.12: each reader keeps its own WriterProxy. What one
    /// reader received says nothing about what the other did.
    #[test]
    fn each_reader_answers_from_what_it_received() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let (holder, newcomer) = (guid(0xA0, 7), guid(0xA0, 8));
        registry.match_writer(writer, holder);
        registry.match_writer(writer, newcomer);
        for seq in 1..=5 {
            registry.on_data_for(&writer, &holder, seq);
        }

        let mut answers = registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 5, 1));
        answers.sort_by_key(|a| a.reader);
        assert_eq!(
            answers,
            vec![
                HeartbeatAnswer {
                    reader: holder,
                    bitmap_base: 6,
                    missing: vec![],
                    final_flag: true,
                    count: 1,
                },
                HeartbeatAnswer {
                    reader: newcomer,
                    bitmap_base: 1,
                    missing: vec![1, 2, 3, 4, 5],
                    final_flag: false,
                    count: 1,
                },
            ]
        );
    }

    /// RTPS 2.5 8.3.8.1: the ACKNACK count increases with each ACKNACK a
    /// reader sends to a writer; each pair keeps its own, and the door that
    /// answers does not matter.
    #[test]
    fn each_pair_counts_its_own_acknacks_whichever_door_answers() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let (first, second) = (guid(0xA0, 7), guid(0xA0, 8));
        registry.match_writer(writer, first);
        let credit = ReaderAckCredit::new(registry.clone(), second);
        credit.match_writer(writer);

        let counts = |answers: Vec<HeartbeatAnswer>| -> Vec<([u8; 16], u32)> {
            let mut counts: Vec<_> = answers.iter().map(|a| (a.reader, a.count)).collect();
            counts.sort_unstable();
            counts
        };
        assert_eq!(
            counts(registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 5, 1))),
            vec![(first, 1), (second, 1)]
        );
        // The other door, for the second reader only.
        let answer = credit
            .answer_heartbeat(&writer, &hb(1, 5, 2))
            .expect("matched");
        assert_eq!((answer.reader, answer.count), (second, 2));
        assert_eq!(
            counts(registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 5, 3))),
            vec![(first, 2), (second, 3)]
        );
    }

    /// A reader's rate-limit window opens when its answer actually left,
    /// and only for that reader.
    #[test]
    fn the_rate_limit_window_opens_when_an_answer_leaves() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let (sent, failed) = (guid(0xA0, 7), guid(0xA0, 8));
        registry.match_writer(writer, sent);
        registry.match_writer(writer, failed);
        assert_eq!(
            registry
                .answer_heartbeat(&writer, Addressees::All, &hb(1, 5, 1))
                .len(),
            2
        );
        registry.mark_acknack_sent_for(&writer, &sent);

        assert!(registry
            .pair(&writer, &sent)
            .expect("matched")
            .acknack_sent());
        assert!(!registry
            .pair(&writer, &failed)
            .expect("matched")
            .acknack_sent());
    }

    /// A writer no local reader is matched with gets no answer, and the
    /// reader-less proxy of the public API is not a reader.
    #[test]
    fn only_matched_readers_answer() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        assert!(registry
            .answer_heartbeat(&writer, Addressees::All, &hb(1, 3, 1))
            .is_empty());

        registry.on_data(writer, 1);
        assert!(registry
            .answer_heartbeat(&writer, Addressees::All, &hb(1, 3, 2))
            .is_empty());

        let reader = guid(0xA0, 7);
        registry.match_writer(writer, reader);
        assert_eq!(
            readers_answering(&registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 3, 3))),
            vec![reader]
        );
    }

    /// Only a match creates a reader's proxy. A DATA from a writer the
    /// reader is not matched with (arriving before the match, or after the
    /// unmatch) creates nothing, so nothing answers for it.
    #[test]
    fn a_data_never_creates_a_proxy() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let reader = guid(0xA0, 7);
        registry.on_data_for(&writer, &reader, 1);
        assert!(registry.is_empty());

        registry.match_writer(writer, reader);
        registry.on_data_for(&writer, &reader, 1);
        registry.unmatch_writer(&writer, &reader);
        registry.on_data_for(&writer, &reader, 2);
        assert!(registry.is_empty());
        assert!(registry
            .answer_heartbeat(&writer, Addressees::All, &hb(1, 2, 1))
            .is_empty());
    }

    /// A reader behind by one sample NACKs exactly that sample, with the
    /// Final flag clear (it needs an answer).
    #[test]
    fn a_reader_behind_by_one_nacks_exactly_that_sample() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let reader = guid(0xA0, 7);
        registry.match_writer(writer, reader);
        for seq in 1..=3 {
            registry.on_data_for(&writer, &reader, seq);
        }
        let answers = registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 4, 1));
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].bitmap_base, 4);
        assert_eq!(answers[0].missing, vec![4]);
        assert!(!answers[0].final_flag);
    }

    /// A GAP (RTPS 2.5 8.3.8.4) reaches the proxy of the reader it is
    /// noted for, and no other: not a reader matched afterwards (the GAP
    /// addressed the readers matched when it arrived), not a neighbour.
    #[test]
    fn a_gap_reaches_the_proxy_it_is_noted_for_alone() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let (noted, neighbour, later) = (guid(0xA0, 7), guid(0xA0, 8), guid(0xA0, 9));
        registry.match_writer(writer, noted);
        registry.match_writer(writer, neighbour);
        registry.note_gap_for(&writer, &noted, 1, 36, &[]);
        registry.note_gap_for(&writer, &later, 1, 36, &[]);
        registry.match_writer(writer, later);

        let mut bases: Vec<_> = registry
            .answer_heartbeat(&writer, Addressees::All, &hb(1, 36, 1))
            .into_iter()
            .map(|a| (a.reader, a.bitmap_base))
            .collect();
        bases.sort_unstable();
        assert_eq!(bases, vec![(noted, 36), (neighbour, 1), (later, 1)]);
    }

    /// The sequences of a GAP's bitmap are irrelevant too: never requested
    /// again, without moving the floor over the hole below them.
    #[test]
    fn a_gaps_bitmap_sequences_are_not_requested_again() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let reader = guid(0xA0, 7);
        registry.match_writer(writer, reader);
        // gapStart 1, gapList.base 2, bitmap {4}; the parser also lists the
        // contiguous range, here {1}.
        registry.note_gap_for(&writer, &reader, 1, 2, &[1, 4]);

        let answers = registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 5, 1));
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].bitmap_base, 2);
        assert_eq!(answers[0].missing, vec![2, 3, 5]);
    }

    /// A GAP whose range starts above the floor (the reader still misses
    /// 1..=2) marks 3..=4 irrelevant without moving the floor over 1..=2.
    #[test]
    fn a_gap_above_a_hole_marks_its_sequences_without_crossing_the_hole() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let reader = guid(0xA0, 7);
        registry.match_writer(writer, reader);
        registry.note_gap_for(&writer, &reader, 3, 5, &[3, 4]);

        let answers = registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 5, 1));
        assert_eq!(answers[0].bitmap_base, 1);
        assert_eq!(answers[0].missing, vec![1, 2, 5]);
    }

    /// A HEARTBEAT addressed to one reader (RTPS 2.5 8.3.8.6) is answered
    /// by that reader alone, and leaves the other's state untouched: the
    /// other's next answer still carries its first count.
    #[test]
    fn an_addressed_heartbeat_is_one_readers_alone() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let (addressed, other) = (guid(0xA0, 7), guid(0xA0, 8));
        registry.match_writer(writer, addressed);
        registry.match_writer(writer, other);

        let answers = registry.answer_heartbeat(
            &writer,
            Addressees::One([0xA0, 0xA0, 0xA0, 7]),
            &hb(1, 3, 1),
        );
        assert_eq!(readers_answering(&answers), vec![addressed]);

        let answers = registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 3, 2));
        let counts: Vec<_> = {
            let mut c: Vec<_> = answers.iter().map(|a| (a.reader, a.count)).collect();
            c.sort_unstable();
            c
        };
        assert_eq!(counts, vec![(addressed, 2), (other, 1)]);
    }

    /// The public `on_gap` keeps its meaning: the registry-wide proxy of
    /// that writer exists afterwards and carries the GAP.
    #[test]
    fn the_public_gap_still_creates_the_writers_proxy() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        registry.on_gap(writer, 1, 36);
        let proxy = registry.get_proxy(&writer).expect("created by on_gap");
        assert_eq!(proxy.low_mark(), 35);
    }

    /// `matched_writer_remove`: an unmatched reader stops answering, and a
    /// writer left with no reader is forgotten.
    #[test]
    fn unmatching_and_forgetting_readers_remove_their_proxies() {
        let registry = ReaderProxyRegistry::new();
        let (writer, other_writer) = (guid(0xB0, 2), guid(0xB0, 3));
        let (first, second) = (guid(0xA0, 7), guid(0xA0, 8));
        registry.match_writer(writer, first);
        registry.match_writer(writer, second);
        registry.on_gap(other_writer, 1, 5);

        registry.unmatch_writer(&writer, &first);
        assert_eq!(registry.readers_of(&writer), vec![second]);
        assert_eq!(registry.len(), 2, "the writer still has a reader");
        assert_eq!(
            readers_answering(&registry.answer_heartbeat(&writer, Addressees::All, &hb(1, 1, 1))),
            vec![second]
        );

        registry.forget_reader(&second);
        assert!(registry.readers_of(&writer).is_empty());
        assert!(registry
            .answer_heartbeat(&writer, Addressees::All, &hb(1, 1, 2))
            .is_empty());
        // The writer is gone; the other writer's entry is not the
        // forgotten reader's to take away.
        assert_eq!(registry.len(), 1);

        // Unmatching a writer's last reader forgets the writer as well.
        let third = guid(0xA0, 9);
        registry.match_writer(writer, third);
        assert_eq!(registry.len(), 2);
        registry.unmatch_writer(&writer, &third);
        assert_eq!(registry.len(), 1);

        registry.match_writer(other_writer, first);
        assert_eq!(registry.readers_of(&other_writer), vec![first]);
    }

    /// A dropped reader's lease retires every proxy it kept, and a DATA
    /// credited afterwards brings none back.
    #[test]
    fn a_retired_reader_leaves_no_proxy_behind() {
        let registry = ReaderProxyRegistry::new();
        let writer = guid(0xB0, 2);
        let credit = ReaderAckCredit::new(registry.clone(), guid(0xA0, 7));
        credit.match_writer(writer);
        credit.on_data(writer, 1);
        assert!(credit.is_matched(&writer));

        drop(credit.lease());
        assert!(registry.is_empty());

        credit.on_data(writer, 2);
        assert!(registry.is_empty());
    }

    #[test]
    fn test_registry_remove() {
        let registry = ReaderProxyRegistry::new();
        let guid = make_guid(1);

        registry.on_heartbeat(guid, 1, 1, 1, false);
        assert_eq!(registry.len(), 1);

        registry.remove(&guid);
        assert!(registry.is_empty());
    }
}

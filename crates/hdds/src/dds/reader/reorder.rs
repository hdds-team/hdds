// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Per-writer sequence-number reorder buffer for late-joiner ordering.
//!
//! For DDS Durability kinds other than `VOLATILE` (DDS v1.4 §2.2.3.4), a
//! reader that joins after the writer has started must deliver historical
//! samples in writer-sequence order, regardless of the on-wire arrival
//! order produced by the reliable retransmission flow (DDS-RTPS v2.5
//! §8.4.2.2 — the writer multicasts the current change while servicing
//! ACKNACK-requested retransmits unicast, so the late joiner observes
//! `current, current+1, ..., 1, 2, 3, ..., current-1, current+k` on the
//! wire).
//!
//! This module holds out-of-order samples in a per-writer min-heap keyed
//! on the RTPS writer sequence number and only releases them to the
//! downstream pipeline once a contiguous prefix is available. The expected
//! base sequence (`next_seq`) is seeded from the writer's first HEARTBEAT
//! (RTPS §8.3.7.5: `HeartbeatSubmessage.firstSN`), which advertises the
//! oldest sample still available in the writer's history cache.

use crate::core::reader::ReaderProxyRegistry;
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, HashMap};

/// Hard cap on the number of out-of-order samples buffered per writer.
///
/// Reached only when a writer keeps producing new sequences while the
/// reader's expected base is blocked on a missing seq that has not yet
/// arrived (or never will). Hitting the cap triggers a forced drain in
/// seq order, accepting that the still-missing seqs are lost.
const MAX_PENDING_PER_WRITER: usize = 4096;

/// A single buffered sample, opaque to the gate.
pub struct PendingPayload {
    /// Raw CDR-encoded bytes, post encapsulation strip (as seen by the
    /// subscriber's `on_data_with_version`).
    pub data: Vec<u8>,
    pub version: crate::dds::CdrVersion,
    /// Writer's RTPS sequence number for this sample, preserved so the
    /// downstream pipeline can keep seq-aware bookkeeping (NACK tracking,
    /// SeqWindow mapping) consistent after a delayed release.
    pub remote_seq: u64,
}

/// Per-writer ordering state.
#[derive(Default)]
struct WriterState {
    /// Next remote sequence number eligible for delivery.
    ///
    /// `None` until either (a) a HEARTBEAT seeds it, or (b) a writer's
    /// first DATA arrives while the reader is volatile (passthrough, kept
    /// as `None`).
    next_seq: Option<u64>,
    /// Sequences received but not yet delivered, sorted ascending.
    pending: BTreeMap<u64, PendingPayload>,
    /// True once at least one HEARTBEAT has seeded `next_seq`. Used so
    /// that subsequent HEARTBEATs do not rewind progress.
    seeded: bool,
    /// Set while the base is still its floored seed and nothing has been
    /// delivered in order: a DATA below the base is then in hand but
    /// undelivered, so it is released rather than dropped (the floor marks
    /// sequences unobtainable, not delivered). Holds the highest sequence
    /// released that way so releases stay strictly ascending; cleared by the
    /// first in-order delivery, and `None` for unfloored writers.
    floor_release: Option<u64>,
}

/// Per-reader gate that performs per-writer in-order delivery for
/// non-volatile durability.
///
/// `enabled` reflects the reader's `Durability` choice — when `false`
/// (Volatile), all calls fall through immediately and no buffering
/// occurs.
pub struct ReorderGate {
    enabled: bool,
    writers: HashMap<[u8; 16], WriterState>,
    /// Participant reception state, consulted once per writer on first contact.
    /// See [`Self::with_delivery_floors`].
    floors: Option<ReaderProxyRegistry>,
}

/// How this reader first hears from a writer, which decides the floored base.
#[derive(Copy, Clone)]
enum FirstContact {
    /// A DATA arrival: the floor stands, and `on_data` releases the sample in
    /// hand even when it sits below the floor.
    Data,
    /// A HEARTBEAT: its `firstSN` (RTPS v2.5 Sec.8.3.7.5) may still advertise the
    /// retired prefix, so the floor wins, but a purged history raises the base.
    Heartbeat(u64),
}

impl ReorderGate {
    /// Create a gate that floors each writer's base at the participant's
    /// acknowledged low mark (`ReaderProxyRegistry::delivery_floor`).
    ///
    /// hdds ACKNACKs carry participant-scoped `readerSNState` under every local
    /// reader entity id, so a reader created on a live topic falsely
    /// acknowledges the prefix its predecessors consumed (RTPS v2.5
    /// Sec.8.3.7.1); the writer then legitimately retires those changes
    /// (Sec.8.4.2.3.3) and never retransmits them. Without the floor the gate
    /// seeds from `HeartbeatSubmessage.firstSN` and blocks every later sample
    /// behind a hole that can never be filled.
    ///
    /// The floor is read per writer at first contact, never snapshotted at
    /// reader construction: the low mark is raised by the router before delivery
    /// and independently of which subscribers are registered, so any snapshot
    /// taken before this reader is registered races reception and can be stale
    /// (too low) by exactly the sequences that stall the gate. At first contact
    /// the pending buffer is empty and the sample in hand is released even if it
    /// sits below the floor, so no sample this reader received can be skipped.
    pub fn with_delivery_floors(enabled: bool, floors: Option<ReaderProxyRegistry>) -> Self {
        Self {
            enabled,
            writers: HashMap::new(),
            floors,
        }
    }

    /// Per-writer state, created on first contact with its base floored at the
    /// acknowledged low mark and marked seeded (so a HEARTBEAT still advertising
    /// the retired prefix cannot rewind into it). A floored base also arms
    /// `floor_release`, which lets `on_data` release samples still in flight
    /// below that base instead of dropping them as already-delivered.
    fn writer_state(&mut self, writer_key: [u8; 16], contact: FirstContact) -> &mut WriterState {
        let floors = self.floors.as_ref();
        match self.writers.entry(writer_key) {
            Entry::Occupied(existing) => existing.into_mut(),
            Entry::Vacant(slot) => {
                let base = floors
                    .and_then(|proxies| proxies.delivery_floor(&writer_key))
                    .map(|floor| match contact {
                        FirstContact::Data => floor,
                        FirstContact::Heartbeat(first_seq) => floor.max(first_seq),
                    });
                if let Some(base) = base {
                    log::debug!(
                        "[reorder] writer {:02x?} base seeded from acknowledged floor {}",
                        &writer_key[12..],
                        base
                    );
                }
                slot.insert(WriterState {
                    next_seq: base,
                    pending: BTreeMap::new(),
                    seeded: base.is_some(),
                    floor_release: base.map(|_| 0),
                })
            }
        }
    }

    /// Seed (or update) the per-writer expected base from a HEARTBEAT's
    /// `firstSN`. Per RTPS v2.5 §8.4.2.2.1.2 the writer's HEARTBEAT
    /// advertises the oldest sample still in its history cache; if that
    /// floor has advanced past our pending base (writer purged history),
    /// we must skip the gap, drop now-stale buffered entries, and
    /// resume from the new floor — otherwise the reader stalls waiting
    /// for samples that no longer exist on the wire.
    ///
    /// Returns any pending samples that are now deliverable as a result
    /// of this update (in ascending seq order).
    pub fn on_heartbeat(&mut self, writer_key: [u8; 16], first_seq: u64) -> Vec<PendingPayload> {
        if !self.enabled {
            return Vec::new();
        }
        let state = self.writer_state(writer_key, FirstContact::Heartbeat(first_seq));
        if !state.seeded {
            state.next_seq = Some(first_seq);
            state.seeded = true;
        } else if let Some(next) = state.next_seq {
            // History purged — fast-forward over the gap.
            if first_seq > next {
                log::debug!(
                    "[reorder] writer first_seq={} > expected next={} (history purged); skipping gap",
                    first_seq,
                    next
                );
                state.next_seq = Some(first_seq);
            }
        }
        // Drop any pending entries that pre-date the writer's first
        // available seq — they cannot belong to this writer's current
        // history per RTPS §8.3.7.5.
        if let Some(base) = state.next_seq {
            let stale_keys: Vec<u64> = state.pending.range(..base).map(|(k, _)| *k).collect();
            for k in stale_keys {
                state.pending.remove(&k);
            }
        }
        Self::drain_contiguous(state)
    }

    /// Submit an arriving DATA sample.
    ///
    /// Returns the list of payloads ready for delivery, in ascending seq
    /// order. Empty vector means "buffered, deliver later". For Volatile
    /// readers (`enabled == false`) the input is returned verbatim.
    pub fn on_data(
        &mut self,
        writer_key: [u8; 16],
        remote_seq: u64,
        payload: PendingPayload,
    ) -> Vec<PendingPayload> {
        if !self.enabled {
            return vec![payload];
        }
        let state = self.writer_state(writer_key, FirstContact::Data);
        match state.next_seq {
            None => {
                // No HB yet — hold and wait. While unseeded we cannot
                // drain (the base is unknown), so just bound memory by
                // dropping the oldest buffered entry when the cap is
                // exceeded. Dropping individual entries means a later
                // HEARTBEAT could seed at a value that lies inside the
                // dropped range and cause a permanent stall, so when
                // forced to discard we clear the entire pending buffer:
                // worst case we lose the unseeded prefix entirely (the
                // application sees the seeded history retransmits), but
                // no synthetic gap is left for `drain_contiguous` to
                // block on.
                state.pending.insert(remote_seq, payload);
                if state.pending.len() > MAX_PENDING_PER_WRITER {
                    log::warn!(
                        "[reorder] writer pending cap exceeded ({} > {}) while unseeded; \
                         clearing buffer to avoid synthetic gap after HEARTBEAT",
                        state.pending.len(),
                        MAX_PENDING_PER_WRITER,
                    );
                    state.pending.clear();
                }
                Vec::new()
            }
            Some(next) if remote_seq < next => {
                // Below a floored base that has delivered nothing yet: these are
                // the samples that were in flight when the floor was read, so
                // release them (strictly ascending) instead of dropping them —
                // the floor marks sequences unobtainable, not delivered.
                if let Some(released_high) = state.floor_release {
                    if remote_seq > released_high {
                        state.floor_release = Some(remote_seq);
                        return vec![payload];
                    }
                }
                // Already delivered (or stale historical retransmit).
                Vec::new()
            }
            Some(next) if remote_seq == next => {
                // Hot path: in-order arrival. In-order delivery closes the
                // below-floor release window for good.
                state.floor_release = None;
                state.next_seq = Some(next + 1);
                let mut out = Vec::with_capacity(1);
                out.push(payload);
                let mut drained = Self::drain_contiguous(state);
                out.append(&mut drained);
                out
            }
            Some(_) => {
                // Out-of-order future seq — buffer, then force progress if
                // we have hit the per-writer pending cap. Forced progress
                // declares the still-missing prefix as lost and releases
                // everything that has piled up starting at the new
                // (raised) base; otherwise an adversarial peer holding the
                // gap could grow `pending` without bound.
                state.pending.insert(remote_seq, payload);
                if state.pending.len() > MAX_PENDING_PER_WRITER {
                    if let Some((&lowest, _)) = state.pending.iter().next() {
                        if let Some(prev) = state.next_seq {
                            if lowest > prev {
                                log::warn!(
                                    "[reorder] writer pending cap exceeded ({} > {}); \
                                     advancing base {} -> {} (treating {} seqs as lost)",
                                    state.pending.len(),
                                    MAX_PENDING_PER_WRITER,
                                    prev,
                                    lowest,
                                    lowest - prev,
                                );
                                state.next_seq = Some(lowest);
                                return Self::drain_contiguous(state);
                            }
                        }
                    }
                }
                Vec::new()
            }
        }
    }

    /// Discard a writer's gate state on liveliness/unmatch. The next contact
    /// re-derives the floor from live reception state, so no stale creation-time
    /// floor can survive the reset — but it also re-arms `floor_release`, so a
    /// production caller must keep the reader's per-writer dedup window covering
    /// this writer or an already-delivered retransmit could be handed up twice.
    #[allow(dead_code)]
    pub fn forget_writer(&mut self, writer_key: &[u8; 16]) {
        self.writers.remove(writer_key);
    }

    fn drain_contiguous(state: &mut WriterState) -> Vec<PendingPayload> {
        let mut out = Vec::new();
        let Some(mut next) = state.next_seq else {
            return out;
        };
        while let Some(entry) = state.pending.remove(&next) {
            out.push(entry);
            next += 1;
        }
        state.next_seq = Some(next);
        if !out.is_empty() {
            // In-order delivery: nothing below the base may be released after it.
            state.floor_release = None;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dds::CdrVersion;

    fn payload(tag: u8) -> PendingPayload {
        PendingPayload {
            data: vec![tag],
            version: CdrVersion::Xcdr2,
            remote_seq: tag as u64,
        }
    }

    fn data_tags(out: &[PendingPayload]) -> Vec<u8> {
        out.iter().map(|p| p.data[0]).collect()
    }

    /// A gate with no floor source: the base comes only from
    /// `HeartbeatSubmessage.firstSN`.
    fn gate(enabled: bool) -> ReorderGate {
        ReorderGate::with_delivery_floors(enabled, None)
    }

    #[test]
    fn passthrough_when_disabled() {
        let mut gate = gate(false);
        let key = [1u8; 16];
        // No heartbeat needed, no buffering, samples flow through.
        let out = gate.on_data(key, 5, payload(0x10));
        assert_eq!(data_tags(&out), vec![0x10]);
        let out = gate.on_data(key, 3, payload(0x20)); // out-of-order ignored
        assert_eq!(data_tags(&out), vec![0x20]);
    }

    #[test]
    fn hb_seeds_then_in_order_passes_immediately() {
        let mut gate = gate(true);
        let key = [2u8; 16];
        let drained = gate.on_heartbeat(key, 1);
        assert!(drained.is_empty());
        let out = gate.on_data(key, 1, payload(0xA1));
        assert_eq!(data_tags(&out), vec![0xA1]);
        let out = gate.on_data(key, 2, payload(0xA2));
        assert_eq!(data_tags(&out), vec![0xA2]);
    }

    #[test]
    fn out_of_order_is_buffered_until_gap_fills() {
        let mut gate = gate(true);
        let key = [3u8; 16];
        gate.on_heartbeat(key, 1);
        // Seqs arrive 3,4,2,1 — we should only release once 1 fills.
        assert!(gate.on_data(key, 3, payload(3)).is_empty());
        assert!(gate.on_data(key, 4, payload(4)).is_empty());
        assert!(gate.on_data(key, 2, payload(2)).is_empty());
        let out = gate.on_data(key, 1, payload(1));
        assert_eq!(data_tags(&out), vec![1, 2, 3, 4]);
    }

    #[test]
    fn data_before_hb_is_held_then_released_in_order() {
        let mut gate = gate(true);
        let key = [4u8; 16];
        // Late-joiner: live multicast arrives first, history second, HB
        // somewhere along the way.
        assert!(gate.on_data(key, 30, payload(30)).is_empty());
        assert!(gate.on_data(key, 31, payload(31)).is_empty());
        // Now HB arrives announcing first_seq=1; the buffered 30/31 stay
        // pending until seqs 1..29 arrive.
        let drained = gate.on_heartbeat(key, 1);
        assert!(drained.is_empty());
        // History 1..29 trickles in out of order.
        for seq in (1u64..=29).rev() {
            let out = gate.on_data(key, seq, payload((seq & 0xFF) as u8));
            if seq == 1 {
                // Seq 1 unblocks the whole contiguous prefix 1..31. The
                // tag for seq N is `(N & 0xFF) as u8` for 1..=29 and was
                // captured as `30`/`31` for the early arrivals at the top
                // of this test.
                let tags = data_tags(&out);
                assert_eq!(tags.len(), 31);
                assert_eq!(tags[0], 1);
                assert_eq!(tags[28], 29);
                assert_eq!(tags[29], 30);
                assert_eq!(tags[30], 31);
            } else {
                assert!(out.is_empty(), "seq={} should still be buffered", seq);
            }
        }
    }

    #[test]
    fn second_heartbeat_does_not_rewind() {
        let mut gate = gate(true);
        let key = [5u8; 16];
        gate.on_heartbeat(key, 10);
        let out = gate.on_data(key, 10, payload(10));
        assert_eq!(data_tags(&out), vec![10]);
        // Another HB with first_seq=5 should NOT cause us to expect seq 5
        // again — we've already moved past it.
        let drained = gate.on_heartbeat(key, 5);
        assert!(drained.is_empty());
        let out = gate.on_data(key, 11, payload(11));
        assert_eq!(data_tags(&out), vec![11]);
    }

    #[test]
    fn stale_pending_dropped_when_hb_seeds_higher_base() {
        let mut gate = gate(true);
        let key = [6u8; 16];
        // Seqs from a previous incarnation arrive (we don't know yet).
        assert!(gate.on_data(key, 1, payload(1)).is_empty());
        assert!(gate.on_data(key, 2, payload(2)).is_empty());
        // HB announces first_seq=100 — the buffered 1/2 cannot belong to
        // this writer's current history and must be discarded.
        let drained = gate.on_heartbeat(key, 100);
        assert!(drained.is_empty());
        let out = gate.on_data(key, 100, payload(100));
        assert_eq!(data_tags(&out), vec![100]);
    }

    #[test]
    fn duplicate_arrival_after_delivery_is_dropped() {
        let mut gate = gate(true);
        let key = [7u8; 16];
        gate.on_heartbeat(key, 1);
        let _ = gate.on_data(key, 1, payload(1));
        let _ = gate.on_data(key, 2, payload(2));
        // Retransmit of seq 1 — already delivered.
        let out = gate.on_data(key, 1, payload(0xFF));
        assert!(out.is_empty());
    }

    #[test]
    fn pending_cap_forces_progress_and_shrinks_map() {
        // Fill the gate well past the cap while the base sample never
        // arrives; the cap must drain rather than allow unbounded growth.
        let mut gate = gate(true);
        let key = [10u8; 16];
        gate.on_heartbeat(key, 1);
        // Seq 1 never arrives. Push 2..=MAX_PENDING_PER_WRITER + 50 out
        // of order; the cap should kick in.
        for seq in 2u64..=(MAX_PENDING_PER_WRITER as u64 + 50) {
            let _ = gate.on_data(key, seq, payload((seq & 0xFF) as u8));
        }
        let state = gate.writers.get(&key).expect("writer state");
        assert!(
            state.pending.len() <= MAX_PENDING_PER_WRITER,
            "pending should have been drained at the cap, got len={}",
            state.pending.len()
        );
        // After forced progress the base advanced past seq 1, but the
        // exact value depends on when the cap tripped; what matters is
        // that the map is bounded and `next_seq` moved forward.
        assert!(state.next_seq.expect("next seeded") > 1);
    }

    #[test]
    fn hb_advances_base_when_writer_purges_history() {
        // RTPS v2.5 §8.4.2.2.1.2: a writer that has purged sample N from
        // its cache reports the new floor via the next HEARTBEAT's
        // `firstSN`. The reader must skip the gap and resume from the
        // new floor rather than block waiting for purged samples.
        let mut gate = gate(true);
        let key = [11u8; 16];
        gate.on_heartbeat(key, 1);
        // Reader gets stuck waiting on seq 1; seqs 2..5 buffer up.
        for s in 2u64..=5 {
            assert!(gate.on_data(key, s, payload(s as u8)).is_empty());
        }
        // Writer purges, advertises first_seq=4 in the next HB.
        let released = gate.on_heartbeat(key, 4);
        assert_eq!(data_tags(&released), vec![4, 5]);
    }

    /// Participant reception state with `seqs` recorded for `key`, exactly as
    /// the router records them (`TopicRegistry::note_user_sample_received`).
    fn acked(key: [u8; 16], seqs: &[i64]) -> ReaderProxyRegistry {
        let proxies = ReaderProxyRegistry::new();
        for &seq in seqs {
            proxies.on_data(key, seq);
        }
        proxies
    }

    /// A reader recreated on a live topic must resume at the participant's
    /// acknowledged low mark: hdds acknowledges 1..2 under this reader's entity
    /// id (RTPS v2.5 §8.3.7.1) and the writer retires them (§8.4.2.3.3), so
    /// waiting for them stalls the reader forever.
    #[test]
    fn floor_resumes_at_acknowledged_base_instead_of_stalling() {
        let key = [12u8; 16];
        let mut gate = ReorderGate::with_delivery_floors(true, Some(acked(key, &[1, 2])));

        // Next live sample flows through immediately, no HEARTBEAT needed.
        let out = gate.on_data(key, 3, payload(3));
        assert_eq!(data_tags(&out), vec![3]);
        let out = gate.on_data(key, 4, payload(4));
        assert_eq!(data_tags(&out), vec![4]);

        // Retransmits below the floor are stale, not a reason to rewind.
        assert!(gate.on_data(key, 1, payload(1)).is_empty());
    }

    /// The writer's `firstSN` may still advertise the retired prefix; the floor
    /// must win so the gate does not fall back into the unfillable hole.
    #[test]
    fn floor_survives_heartbeat_advertising_retired_prefix() {
        let key = [13u8; 16];
        let mut gate = ReorderGate::with_delivery_floors(true, Some(acked(key, &[1, 2])));

        assert!(gate.on_heartbeat(key, 1).is_empty());
        let out = gate.on_data(key, 3, payload(3));
        assert_eq!(data_tags(&out), vec![3]);
    }

    /// A `firstSN` *above* the floor means the writer purged history (RTPS v2.5
    /// §8.4.2.2.1.2); the fast-forward must still win over the floor.
    #[test]
    fn heartbeat_above_floor_still_fast_forwards() {
        let key = [17u8; 16];
        let mut gate = ReorderGate::with_delivery_floors(true, Some(acked(key, &[1, 2])));

        // First contact: floor 3 wins over the retired firstSN=1.
        assert!(gate.on_heartbeat(key, 1).is_empty());
        // Seq 3 never arrives; 4 and 5 buffer behind it.
        assert!(gate.on_data(key, 4, payload(4)).is_empty());
        assert!(gate.on_data(key, 5, payload(5)).is_empty());
        // Writer purges up to 4 — the gap must be skipped, not held by the floor.
        let released = gate.on_heartbeat(key, 4);
        assert_eq!(data_tags(&released), vec![4, 5]);
    }

    /// Writers with no acknowledged samples keep the late-joiner path: the base
    /// still comes from `HeartbeatSubmessage.firstSN` (RTPS v2.5 §8.3.7.5).
    #[test]
    fn writers_without_floor_keep_heartbeat_seeding() {
        let key = [14u8; 16];
        let mut gate = ReorderGate::with_delivery_floors(true, Some(acked([15u8; 16], &[1, 99])));

        assert!(
            gate.on_data(key, 5, payload(5)).is_empty(),
            "unseeded: hold"
        );
        let released = gate.on_heartbeat(key, 5);
        assert_eq!(data_tags(&released), vec![5]);
    }

    /// The floor is read at first contact, not at construction: reception is
    /// recorded before delivery and independently of subscriber registration, so
    /// a construction-time snapshot would still stall on samples acknowledged
    /// while the reader was being wired up.
    #[test]
    fn floor_is_read_at_first_contact_not_at_construction() {
        let key = [16u8; 16];
        let proxies = ReaderProxyRegistry::new();
        let mut gate = ReorderGate::with_delivery_floors(true, Some(proxies.clone()));

        // Seqs 1..2 land after the gate exists but before this reader is
        // registered: acknowledged, never delivered here, never retransmitted.
        proxies.on_data(key, 1);
        proxies.on_data(key, 2);

        // First sample this reader actually sees; the router recorded it first.
        proxies.on_data(key, 3);
        let out = gate.on_data(key, 3, payload(3));
        assert_eq!(data_tags(&out), vec![3]);
    }

    /// A first sample below the floor (concurrent reception raced the floor read,
    /// or a retransmit arrived first) is in hand and must be released — while the
    /// base stays at the floor so the reader does not then wait for the retired
    /// sequences between them.
    #[test]
    fn floor_releases_the_first_sample_in_hand_and_keeps_the_base() {
        let key = [18u8; 16];
        let mut gate = ReorderGate::with_delivery_floors(true, Some(acked(key, &[1, 2, 3, 4, 5])));

        // Floor is 6; 4 is what we hold.
        assert_eq!(data_tags(&gate.on_data(key, 4, payload(4))), vec![4]);
        // The base did not rewind to 5: the live edge flows straight through.
        assert_eq!(data_tags(&gate.on_data(key, 6, payload(6))), vec![6]);
        // A later retransmit below the floor is stale, not a first contact.
        assert!(gate.on_data(key, 5, payload(5)).is_empty());
    }

    /// A HEARTBEAT is the common first contact (the control thread seeds gates),
    /// and it consumes the state creation. A DATA the router had already recorded
    /// — raising the floor above it — must still be released when it lands.
    #[test]
    fn floor_releases_below_floor_data_after_heartbeat_first_contact() {
        let key = [20u8; 16];
        let proxies = ReaderProxyRegistry::new();
        let mut gate = ReorderGate::with_delivery_floors(true, Some(proxies.clone()));
        proxies.on_data(key, 1);
        proxies.on_data(key, 2);

        // Router records seq 3, then the control thread's HEARTBEAT wins the race
        // and seeds this gate at floor 4 while seq 3 is still in flight to it.
        proxies.on_data(key, 3);
        assert!(gate.on_heartbeat(key, 1).is_empty());

        assert_eq!(data_tags(&gate.on_data(key, 3, payload(3))), vec![3]);
        assert_eq!(data_tags(&gate.on_data(key, 4, payload(4))), vec![4]);
    }

    /// Below-floor releases must stay strictly ascending, never duplicate, and
    /// stop for good once an in-order delivery has happened.
    #[test]
    fn below_floor_releases_stay_ascending_and_never_duplicate() {
        let key = [21u8; 16];
        let mut gate = ReorderGate::with_delivery_floors(true, Some(acked(key, &[1, 2, 3, 4, 5])));

        // Floor 6; seqs 3 and 4 were in flight when the reader was wired in.
        assert_eq!(data_tags(&gate.on_data(key, 3, payload(3))), vec![3]);
        assert_eq!(data_tags(&gate.on_data(key, 4, payload(4))), vec![4]);
        // Retransmit of a released seq, and an older straggler: both dropped.
        assert!(gate.on_data(key, 4, payload(0xFF)).is_empty());
        assert!(gate.on_data(key, 2, payload(2)).is_empty());
        // First in-order delivery closes the window.
        assert_eq!(data_tags(&gate.on_data(key, 6, payload(6))), vec![6]);
        assert!(gate.on_data(key, 5, payload(5)).is_empty());
    }

    /// The release is scoped to floored writers: an unfloored gate keeps dropping
    /// everything below a base seeded from `firstSN` (RTPS v2.5 §8.3.7.5).
    #[test]
    fn unfloored_gate_still_drops_below_a_heartbeat_seeded_base() {
        let key = [22u8; 16];
        let mut gate = gate(true);

        assert!(gate.on_heartbeat(key, 10).is_empty());
        assert!(gate.on_data(key, 5, payload(5)).is_empty());
        assert_eq!(data_tags(&gate.on_data(key, 10, payload(10))), vec![10]);
    }

    /// After `forget_writer` the base is re-derived from live reception state, so
    /// no stale creation-time floor can strand the reader below the live edge.
    #[test]
    fn forget_writer_refloors_from_live_reception_state() {
        let key = [19u8; 16];
        let proxies = ReaderProxyRegistry::new();
        let mut gate = ReorderGate::with_delivery_floors(true, Some(proxies.clone()));
        proxies.on_data(key, 1);
        proxies.on_data(key, 2);

        proxies.on_data(key, 3);
        assert_eq!(data_tags(&gate.on_data(key, 3, payload(3))), vec![3]);

        // Writer unmatches; meanwhile the participant acknowledges 4..10.
        gate.forget_writer(&key);
        for seq in 4..=10 {
            proxies.on_data(key, seq);
        }

        proxies.on_data(key, 11);
        let out = gate.on_data(key, 11, payload(11));
        assert_eq!(data_tags(&out), vec![11], "must resume at the live edge");
    }

    #[test]
    fn writers_are_independent() {
        let mut gate = gate(true);
        let k1 = [8u8; 16];
        let k2 = [9u8; 16];
        gate.on_heartbeat(k1, 1);
        gate.on_heartbeat(k2, 100);
        let out1 = gate.on_data(k1, 1, payload(1));
        assert_eq!(data_tags(&out1), vec![1]);
        let out2 = gate.on_data(k2, 100, payload(100));
        assert_eq!(data_tags(&out2), vec![100]);
    }
}

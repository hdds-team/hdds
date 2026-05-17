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
}

impl ReorderGate {
    /// Create a gate. Pass `enabled = false` for Volatile readers to
    /// keep the gate in passthrough mode.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            writers: HashMap::new(),
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
        let state = self.writers.entry(writer_key).or_default();
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
        let state = self.writers.entry(writer_key).or_default();
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
                // Already delivered (or stale historical retransmit).
                Vec::new()
            }
            Some(next) if remote_seq == next => {
                // Hot path: in-order arrival.
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

    /// Discard a writer's gate state on liveliness/unmatch.
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

    #[test]
    fn passthrough_when_disabled() {
        let mut gate = ReorderGate::new(false);
        let key = [1u8; 16];
        // No heartbeat needed, no buffering, samples flow through.
        let out = gate.on_data(key, 5, payload(0x10));
        assert_eq!(data_tags(&out), vec![0x10]);
        let out = gate.on_data(key, 3, payload(0x20)); // out-of-order ignored
        assert_eq!(data_tags(&out), vec![0x20]);
    }

    #[test]
    fn hb_seeds_then_in_order_passes_immediately() {
        let mut gate = ReorderGate::new(true);
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
        let mut gate = ReorderGate::new(true);
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
        let mut gate = ReorderGate::new(true);
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
        let mut gate = ReorderGate::new(true);
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
        let mut gate = ReorderGate::new(true);
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
        let mut gate = ReorderGate::new(true);
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
        let mut gate = ReorderGate::new(true);
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
        let mut gate = ReorderGate::new(true);
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

    #[test]
    fn writers_are_independent() {
        let mut gate = ReorderGate::new(true);
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

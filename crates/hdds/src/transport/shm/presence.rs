// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Positive proof that a remote participant is attached to a writer's ring.
//!
//! # Why this exists
//!
//! The shared-memory leg replaces the UDP leg for a peer, so the writer must
//! know that the peer can actually read the ring before it stops sending that
//! peer UDP. Inferring it does not work: the writer's own push into its own
//! ring succeeds whether or not anyone is on the other side, and BEST_EFFORT
//! has no acknowledgement to reveal the mistake. A reader that selected shared
//! memory at pairing and then cannot open the segment -- a stale co-location
//! verdict, a different `/dev/shm`, a restarted peer -- would lose every
//! sample, permanently, with both sides reporting success.
//!
//! So attachment is PROVEN, not assumed. A reader that has opened the segment
//! and is about to start draining claims an entry in this table, keyed by its
//! own participant GUID. The writer serves the shared-memory leg to a peer
//! only while that peer holds an entry, and sends UDP to every peer that does
//! not.
//!
//! # Why this cannot lose or duplicate a sample
//!
//! A claim carries the reader's **start cursor**: the ring sequence it will
//! begin reading from. That number is what makes the handover exact, and
//! leaving it out would lose or duplicate samples (see below).
//!
//! The writer pushes a packet once per packet, at the first peer it decides to
//! serve, and that push lands at a known ring sequence. A peer is then credited
//! with the shared-memory leg for that packet if and only if
//! `peer_start_cursor <= pushed_sequence`. Anything else is guesswork:
//!
//! * The writer cannot infer a peer's cursor from the fact that the peer is
//!   present. Presence only says "attached at some earlier instant".
//! * Crediting a peer whose cursor is already PAST the packet loses it on both
//!   legs at once: no ring read, no UDP copy, no acknowledgement on BEST_EFFORT
//!   to reveal it. This is exactly what happened when the writer memoised the
//!   push at the first attached peer and then sampled a later peer's presence
//!   AFTER that push.
//! * Refusing to credit a peer whose cursor is at or BEFORE the packet would
//!   duplicate it: the peer reads the ring slot and receives the UDP copy too.
//!
//! With the cursor in hand both mistakes are unreachable, and every sample
//! crosses exactly one leg. Sending both and relying on the reader to discard
//! the copy was the other option and was rejected: on BEST_EFFORT the only
//! duplicate filter is "a sample with this sequence number is still in the
//! cache", which stops holding as soon as the application has taken it.
//!
//! # What this does NOT protect against, stated plainly
//!
//! A claim is 24 bytes of plain atomics in a segment that every legitimate
//! co-located peer maps `O_RDWR`, so **any process that can open the segment
//! can write any participant's key into a free entry.** The segment is created
//! mode 0600, so that process must run as the same uid as the writer; that uid
//! boundary is the real boundary here, and a same-uid process can already do
//! worse things to the writer than forge 24 bytes. What is NOT true is that
//! only the peer itself can claim: another co-located DDS peer, buggy or
//! compromised, can write a third participant's key.
//!
//! Nothing short of DDS-Security fixes that, because the material a forger
//! would need to be denied - the victim's participant GUID prefix - is
//! broadcast in the clear in every SPDP announcement. So this module does not
//! pretend to authenticate a claim. What it does instead is make a claim
//! **perishable**: the cursor has to keep moving, and a writer stops crediting
//! an entry whose cursor has fallen more than a ring behind
//! (`shm_peer_cursor_stale` counts it). A forged or abandoned claim therefore
//! decays into "this peer takes the UDP leg" on its own, rather than
//! blackholing the victim for the life of the pairing. An attacker who keeps
//! advancing a forged cursor sustains the attack, and is out of scope.
//!
//! # Granularity
//!
//! Per participant, not per reader, because that is the granularity at which
//! draining happens: one poller per participant attaches a given writer's ring
//! once, however many of its readers matched the topic.

use std::sync::atomic::{AtomicU64, Ordering};

/// Participants one writer's segment can serve at once.
///
/// A claim beyond this fails, and a peer whose claim fails simply keeps the
/// UDP leg: the table filling up costs bandwidth, never delivery.
pub const PRESENCE_SLOTS: usize = 64;

/// One participant's claim. Cache-line aligned so two participants claiming
/// concurrently do not contend on the same line.
///
/// The contents are read under a SEQLOCK (`seq`), not field by field. Reading
/// the two key halves with separate loads was a real defect: a release plus a
/// re-claim by a different participant landing between them yields a composite
/// key - high half from one generation, low half from the next - that matches a
/// participant who never claimed anything. The halves are also very unequal in
/// discriminating power (the high half is close to a host-wide constant,
/// because a participant GUID prefix begins with the vendor id and the host
/// address), so a composite is not a remote possibility.
#[repr(C, align(64))]
struct PresenceEntry {
    /// Slot acquisition. `0` = free; CAS to `1` takes it. Separate from the
    /// key so that acquiring a slot and publishing its contents are two
    /// different things.
    lock: AtomicU64,
    /// Seqlock counter, EVEN when the contents are stable and ODD while they
    /// are being written. Monotonic and never reset, so a release followed by
    /// a re-claim always changes it - an epoch that went back to the same
    /// value would make the re-check below blind to exactly the case it exists
    /// for.
    seq: AtomicU64,
    /// High 8 bytes of the claiming participant's GUID prefix.
    key_hi: AtomicU64,
    /// Low 8 bytes of the claiming participant's GUID prefix.
    key_lo: AtomicU64,
    /// The ring sequence this reader is reading from. Set at claim time and
    /// REFRESHED as the reader drains, which is what lets the writer tell a
    /// live peer from a dead one without a timer (see the module docs).
    cursor: AtomicU64,
    _pad: [u8; 24],
}

impl PresenceEntry {
    /// Read the whole entry, or `None` if it is free or was being modified.
    ///
    /// Fails SAFE by design: a torn or in-flight entry reads as absent, and a
    /// peer that reads as absent keeps its UDP leg. The opposite bias would
    /// drop a live peer's UDP leg on a half-written claim.
    fn read(&self) -> Option<(u64, u64, u64)> {
        let s1 = self.seq.load(Ordering::Acquire);
        if s1 & 1 != 0 {
            return None; // a writer is inside the entry right now
        }
        let hi = self.key_hi.load(Ordering::Relaxed);
        let lo = self.key_lo.load(Ordering::Relaxed);
        let cursor = self.cursor.load(Ordering::Relaxed);
        // The load-load half of the seqlock pair. An Acquire LOAD on the
        // re-check would be the wrong direction: it constrains what comes
        // after it, not the three loads above, which the compiler and the CPU
        // could otherwise sink past the check meant to catch them.
        std::sync::atomic::fence(Ordering::Acquire);
        if self.seq.load(Ordering::Relaxed) != s1 {
            return None; // changed under us: this read is not a snapshot
        }
        if hi == 0 && lo == 0 {
            return None; // free
        }
        Some((hi, lo, cursor))
    }

    /// Publish `hi`/`lo`/`cursor` under the seqlock.
    fn publish(&self, hi: u64, lo: u64, cursor: u64) {
        self.seq.fetch_add(1, Ordering::AcqRel); // -> odd
                                                 // The store-store half of the pair: without it the three stores below
                                                 // may be hoisted above the odd marker and be read as a stable entry.
        std::sync::atomic::fence(Ordering::Release);
        self.key_hi.store(hi, Ordering::Relaxed);
        self.key_lo.store(lo, Ordering::Relaxed);
        self.cursor.store(cursor, Ordering::Relaxed);
        self.seq.fetch_add(1, Ordering::Release); // -> even, and a NEW value
    }
}

/// Table of claims, mapped in the segment between the control block and the
/// slots.
#[repr(C, align(64))]
pub struct ShmPresence {
    entries: [PresenceEntry; PRESENCE_SLOTS],
}

impl ShmPresence {
    /// Claim the entry for `key`, or refresh it if this participant already
    /// holds one. Returns false only when the table is full.
    ///
    /// Idempotent: a poller that re-attaches after a transient failure finds
    /// its own entry and keeps it rather than consuming a second one.
    /// `cursor` is the ring sequence this reader will start from; see the
    /// module docs for why the writer cannot do without it.
    pub fn claim(&self, key: [u8; 16], cursor: u64) -> bool {
        let (hi, lo) = split(key);
        // Already ours? A poller that re-attaches after a transient failure
        // must find its own entry and update it rather than consume a second.
        for entry in &self.entries {
            if let Some((ehi, elo, _)) = entry.read() {
                if ehi == hi && elo == lo {
                    entry.publish(hi, lo, cursor);
                    return true;
                }
            }
        }
        for entry in &self.entries {
            if entry
                .lock
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                entry.publish(hi, lo, cursor);
                return true;
            }
        }
        false
    }

    /// Move this participant's published cursor forward as it drains.
    ///
    /// This is the liveness signal, and it is the reason the writer needs no
    /// timer, no reaper thread and no heartbeat of its own: a peer that is
    /// really consuming the ring moves this number, and one that is dead,
    /// gone, or never existed does not. Cheap enough to call once per drain
    /// sweep - it is one seqlock publish, not one per sample.
    ///
    /// A no-op when this participant holds no entry.
    pub fn refresh_cursor(&self, key: [u8; 16], cursor: u64) {
        let (hi, lo) = split(key);
        for entry in &self.entries {
            if let Some((ehi, elo, ecur)) = entry.read() {
                if ehi == hi && elo == lo {
                    if ecur != cursor {
                        entry.publish(hi, lo, cursor);
                    }
                    return;
                }
            }
        }
    }

    /// Release the entry for `key`, if this participant holds one.
    ///
    /// Called when a poller detaches. A peer that dies without reaching this
    /// leaves a stale claim, which is NOT harmless and is why the cursor above
    /// exists: the stale claim's cursor never moves again, so the writer stops
    /// crediting it on its own.
    pub fn release(&self, key: [u8; 16]) {
        let (hi, lo) = split(key);
        for entry in &self.entries {
            if let Some((ehi, elo, _)) = entry.read() {
                if ehi == hi && elo == lo {
                    entry.publish(0, 0, 0);
                    entry.lock.store(0, Ordering::Release);
                    return;
                }
            }
        }
    }

    /// The ring sequence `key` is reading from, or `None` when it holds no
    /// claim. This is the writer's gate: it may drop a peer's UDP leg for a
    /// packet only when that packet's sequence is at or after this value AND
    /// no further behind it than the ring can hold.
    pub fn cursor_of(&self, key: [u8; 16]) -> Option<u64> {
        let (hi, lo) = split(key);
        for entry in &self.entries {
            if let Some((ehi, elo, cursor)) = entry.read() {
                if ehi == hi && elo == lo {
                    return Some(cursor);
                }
            }
        }
        None
    }

    /// Whether `key` holds a claim at all. Kept for the tests and for logging;
    /// the delivery decision goes through [`cursor_of`](Self::cursor_of),
    /// because presence alone is not enough to decide it.
    pub fn is_present(&self, key: [u8; 16]) -> bool {
        self.cursor_of(key).is_some()
    }
}

/// Normalise a participant GUID to the 12-byte RTPS prefix, zero-filled.
///
/// The two sides reach this table from different places and do NOT agree on
/// the entity-id tail: a participant's own GUID carries the participant entity
/// id, while the copy the writer holds for a remote reader's participant
/// carries zeros. Keying on the raw 16 bytes would therefore have the reader
/// claim one key and the writer test another, and the writer would conclude
/// "not attached" forever -- which fails safe (UDP stays on) but makes the
/// shared-memory leg dead code. The prefix is the part that actually
/// identifies the participant.
fn normalize(key: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..12].copy_from_slice(&key[..12]);
    out
}

fn split(key: [u8; 16]) -> (u64, u64) {
    let key = normalize(key);
    let mut hi = [0u8; 8];
    let mut lo = [0u8; 8];
    hi.copy_from_slice(&key[..8]);
    lo.copy_from_slice(&key[8..]);
    (u64::from_le_bytes(hi), u64::from_le_bytes(lo))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a zeroed table the way the segment presents one: the mapping is
    /// zero-filled by the kernel, which is what makes "key_hi == 0 means free"
    /// correct without an explicit init pass.
    fn table() -> Box<ShmPresence> {
        // SAFETY: every field is an integer type for which the all-zero bit
        // pattern is a valid value, which is exactly the state a freshly
        // mapped shared-memory segment is in.
        unsafe { Box::new(std::mem::zeroed()) }
    }

    fn key(n: u8) -> [u8; 16] {
        let mut k = [0u8; 16];
        k[0] = n;
        k[15] = n;
        k
    }

    #[test]
    fn a_participant_is_absent_until_it_claims() {
        let t = table();
        assert!(!t.is_present(key(1)));
        assert!(t.claim(key(1), 0));
        assert!(t.is_present(key(1)));
    }

    #[test]
    fn one_participants_claim_says_nothing_about_another() {
        // The defect this whole table exists to prevent: a writer must not
        // conclude from one attached peer that a second peer is attached too,
        // because it would then drop that second peer's UDP leg and lose
        // every sample for it.
        let t = table();
        assert!(t.claim(key(1), 0));
        assert!(t.is_present(key(1)));
        assert!(!t.is_present(key(2)));
    }

    #[test]
    fn claiming_twice_does_not_consume_two_entries() {
        let t = table();
        for _ in 0..PRESENCE_SLOTS * 2 {
            assert!(t.claim(key(7), 0));
        }
        // Every other participant must still fit.
        for n in 0..(PRESENCE_SLOTS - 1) as u8 {
            assert!(t.claim(key(100 + n), 0), "slot {n} should still be free");
        }
    }

    #[test]
    fn a_released_entry_is_absent_and_reusable() {
        let t = table();
        assert!(t.claim(key(1), 0));
        t.release(key(1));
        assert!(!t.is_present(key(1)));
        assert!(t.claim(key(2), 0));
        assert!(t.is_present(key(2)));
    }

    #[test]
    fn a_full_table_refuses_rather_than_evicting_someone() {
        // Refusing costs the newcomer its shared-memory leg, which is a
        // bandwidth cost. Evicting an existing claim would cost the evicted
        // peer its delivery, which is not survivable.
        let t = table();
        for n in 0..PRESENCE_SLOTS as u8 {
            assert!(t.claim(key(n + 1), 0));
        }
        assert!(!t.claim(key(200), 0));
        for n in 0..PRESENCE_SLOTS as u8 {
            assert!(t.is_present(key(n + 1)));
        }
    }
    #[test]
    fn a_claim_carries_the_cursor_the_writer_needs_to_decide() {
        // The writer may only drop a peer's UDP leg for a packet the peer can
        // still read. Presence alone does not say that; the cursor does.
        let t = table();
        assert_eq!(t.cursor_of(key(1)), None);
        assert!(t.claim(key(1), 42));
        assert_eq!(t.cursor_of(key(1)), Some(42));

        // A re-attach starts somewhere else, and the writer must see the NEW
        // cursor rather than the one from the previous attach.
        assert!(t.claim(key(1), 100));
        assert_eq!(t.cursor_of(key(1)), Some(100));

        // Releasing takes the cursor with it: a stale cursor left behind would
        // credit a peer that is gone.
        t.release(key(1));
        assert_eq!(t.cursor_of(key(1)), None);
    }

    #[test]
    fn one_peers_cursor_is_never_read_for_another() {
        let t = table();
        assert!(t.claim(key(1), 10));
        assert!(t.claim(key(2), 999));
        assert_eq!(t.cursor_of(key(1)), Some(10));
        assert_eq!(t.cursor_of(key(2)), Some(999));
    }

    #[test]
    fn a_claim_whose_cursor_stops_moving_is_visible_as_such() {
        // The liveness signal. A live reader refreshes this every drain sweep;
        // a killed one, a recycled pid rebuilding the same GUID, or an entry
        // written by something that is not the peer at all, never does. The
        // writer reads the difference without any timer of its own.
        let t = table();
        assert!(t.claim(key(1), 10));
        assert_eq!(t.cursor_of(key(1)), Some(10));

        t.refresh_cursor(key(1), 250);
        assert_eq!(t.cursor_of(key(1)), Some(250));

        // Refreshing a key that holds nothing must not invent an entry.
        t.refresh_cursor(key(9), 777);
        assert_eq!(t.cursor_of(key(9)), None);
    }

    #[test]
    fn a_released_slot_changes_the_seqlock_counter() {
        // The reason the counter is monotonic instead of a flag: a release
        // followed by a re-claim must be DETECTABLE by a reader that sampled
        // the entry before it. A counter that went back to the same value
        // would be blind to exactly the case the re-check exists for.
        let t = table();
        assert!(t.claim(key(1), 1));
        let first = t.entries[0].seq.load(Ordering::Relaxed);
        t.release(key(1));
        assert!(t.claim(key(2), 2));
        let second = t.entries[0].seq.load(Ordering::Relaxed);
        assert!(
            second > first,
            "the seqlock counter must move across a release and re-claim: {first} -> {second}"
        );
        assert_eq!(t.cursor_of(key(1)), None, "the old holder must be gone");
        assert_eq!(t.cursor_of(key(2)), Some(2));
    }

    #[test]
    fn an_entry_being_written_reads_as_absent_not_as_a_composite() {
        // Fails SAFE: a peer that reads as absent keeps its UDP leg, whereas
        // a half-read entry that matched would drop a live peer's UDP leg on
        // a key nobody holds.
        let t = table();
        assert!(t.claim(key(1), 5));
        // Force the odd (in-transition) state the way `publish` does.
        t.entries[0].seq.fetch_add(1, Ordering::AcqRel);
        assert_eq!(
            t.cursor_of(key(1)),
            None,
            "an entry mid-write must not be matched"
        );
        t.entries[0].seq.fetch_add(1, Ordering::AcqRel);
        assert_eq!(t.cursor_of(key(1)), Some(5), "and must reappear after it");
    }
}

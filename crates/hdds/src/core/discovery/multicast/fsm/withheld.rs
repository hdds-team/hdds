// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The late-joiner history replays withheld from remote readers the
//! security plugins did not admit when they were discovered
//! (`DiscoveryFsm::withhold_replay`), kept until their participant
//! authenticates.
//!
//! Bounded per participant prefix and overall, in entries and in bytes (a
//! reader's topic and type names are the peer's strings): one participant
//! announcing readers by the thousand evicts only its own oldest, and never
//! what is withheld from another. Past the overall bound a new entry is
//! refused, unless its participant holds a handshake session (the one case
//! the store is for: a reader whose handshake is pending), which then
//! evicts the oldest entry of a participant that holds none. Every bound
//! fails safe: an entry forgotten or refused is a reader that gets no
//! history, never one that gets a history it is not admitted to.

#![cfg(feature = "security")]

use crate::core::discovery::GUID;
use std::collections::{HashMap, VecDeque};

/// A history replay withheld from a late-joining reader.
pub(super) struct WithheldReplay {
    pub(super) topic: String,
    pub(super) type_name: String,
    pub(super) dest: std::net::SocketAddr,
}

impl WithheldReplay {
    /// What the entry costs the store: its two strings and a fixed part.
    fn cost(&self) -> usize {
        ENTRY_OVERHEAD
            .saturating_add(self.topic.len())
            .saturating_add(self.type_name.len())
    }
}

/// The fixed part of an entry's cost.
const ENTRY_OVERHEAD: usize = std::mem::size_of::<GUID>() + std::mem::size_of::<WithheldReplay>();

/// At most this many replays are withheld for one participant; past it its
/// own oldest goes.
pub(super) const PER_PEER_ENTRIES: usize = 256;

/// At most this many bytes (`WithheldReplay::cost`) are withheld for one
/// participant; past it its own oldest goes, and an entry larger than this
/// alone is refused.
pub(super) const PER_PEER_BYTES: usize = 64 * 1024;

/// At most this many replays are withheld overall.
pub(super) const TOTAL_ENTRIES: usize = 4096;

/// At most this many bytes are withheld overall.
pub(super) const TOTAL_BYTES: usize = 1024 * 1024;

/// One participant's withheld replays, oldest first.
#[derive(Default)]
struct PeerReplays {
    replays: VecDeque<(GUID, WithheldReplay)>,
    bytes: usize,
    /// Whether the participant held a handshake session at its last
    /// insertion.
    holds_session: bool,
}

/// The withheld replays, by participant prefix.
#[derive(Default)]
pub(super) struct WithheldReplays {
    peers: HashMap<[u8; 12], PeerReplays>,
    entries: usize,
    bytes: usize,
}

impl WithheldReplays {
    /// Withhold `replay` for `reader`, replacing any held for it; its
    /// participant holds a handshake session when `holds_session`. `false`
    /// when it was refused (`WithheldReplays` doc).
    pub(super) fn insert(
        &mut self,
        reader: GUID,
        replay: WithheldReplay,
        holds_session: bool,
    ) -> bool {
        let cost = replay.cost();
        let _ = self.take(&reader);
        if cost > PER_PEER_BYTES {
            return false;
        }
        let prefix = reader.prefix;
        // The participant's own oldest first.
        if let Some(peer) = self.peers.get_mut(&prefix) {
            while !peer.replays.is_empty()
                && (peer.replays.len() >= PER_PEER_ENTRIES
                    || peer.bytes.saturating_add(cost) > PER_PEER_BYTES)
            {
                if let Some((_, old)) = peer.replays.pop_front() {
                    let old_cost = old.cost();
                    peer.bytes -= old_cost;
                    self.entries -= 1;
                    self.bytes -= old_cost;
                }
            }
        }
        // Then the overall bound: room is never taken from a participant
        // whose handshake may still complete.
        while self.entries >= TOTAL_ENTRIES || self.bytes.saturating_add(cost) > TOTAL_BYTES {
            if !holds_session || !self.evict_one_sessionless(&prefix) {
                self.drop_if_empty(&prefix);
                return false;
            }
        }
        let peer = self.peers.entry(prefix).or_default();
        peer.holds_session = holds_session;
        peer.bytes += cost;
        peer.replays.push_back((reader, replay));
        self.entries += 1;
        self.bytes += cost;
        true
    }

    /// Evict the oldest entry of a participant other than `except` that
    /// held no handshake session; `false` when there is none.
    fn evict_one_sessionless(&mut self, except: &[u8; 12]) -> bool {
        let Some(prefix) = self
            .peers
            .iter()
            .find(|(prefix, peer)| *prefix != except && !peer.holds_session)
            .map(|(prefix, _)| *prefix)
        else {
            return false;
        };
        if let Some(peer) = self.peers.get_mut(&prefix) {
            if let Some((_, old)) = peer.replays.pop_front() {
                let old_cost = old.cost();
                peer.bytes -= old_cost;
                self.entries -= 1;
                self.bytes -= old_cost;
            }
        }
        self.drop_if_empty(&prefix);
        true
    }

    fn drop_if_empty(&mut self, prefix: &[u8; 12]) {
        if self
            .peers
            .get(prefix)
            .is_some_and(|peer| peer.replays.is_empty())
        {
            self.peers.remove(prefix);
        }
    }

    /// Take out the replay withheld for `reader`, if any.
    pub(super) fn take(&mut self, reader: &GUID) -> Option<WithheldReplay> {
        let peer = self.peers.get_mut(&reader.prefix)?;
        let at = peer.replays.iter().position(|(guid, _)| guid == reader)?;
        let (_, replay) = peer.replays.remove(at)?;
        let cost = replay.cost();
        peer.bytes -= cost;
        self.entries -= 1;
        self.bytes -= cost;
        self.drop_if_empty(&reader.prefix);
        Some(replay)
    }

    /// Take out every replay withheld for the readers of `prefix`.
    pub(super) fn take_peer(&mut self, prefix: &[u8; 12]) -> Vec<(GUID, WithheldReplay)> {
        let Some(peer) = self.peers.remove(prefix) else {
            return Vec::new();
        };
        self.entries -= peer.replays.len();
        self.bytes -= peer.bytes;
        peer.replays.into_iter().collect()
    }

    /// How many replays are withheld, overall.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries
    }

    /// How many replays are withheld for `prefix`.
    #[cfg(test)]
    pub(super) fn len_of(&self, prefix: &[u8; 12]) -> usize {
        self.peers.get(prefix).map_or(0, |peer| peer.replays.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(prefix: u8, entity: u16) -> GUID {
        let [hi, lo] = entity.to_be_bytes();
        GUID::new([prefix; 12], [hi, lo, 0x00, 0x07])
    }

    fn replay(topic_len: usize) -> WithheldReplay {
        WithheldReplay {
            topic: "t".repeat(topic_len),
            type_name: "T".to_string(),
            dest: "127.0.0.1:7400".parse().expect("addr"),
        }
    }

    #[test]
    fn a_participant_past_its_entry_bound_loses_its_own_oldest_only() {
        let mut store = WithheldReplays::default();
        assert!(store.insert(reader(1, 0), replay(1), true));
        for entity in 0..PER_PEER_ENTRIES as u16 {
            assert!(store.insert(reader(2, entity), replay(1), false));
        }
        assert_eq!(store.len_of(&[2; 12]), PER_PEER_ENTRIES, "at the bound");
        assert!(
            store.take(&reader(2, 0)).is_some(),
            "the oldest kept at the bound"
        );
        assert!(store.insert(reader(2, 0), replay(1), false));
        assert!(store.insert(reader(2, 999), replay(1), false));
        assert_eq!(
            store.len_of(&[2; 12]),
            PER_PEER_ENTRIES,
            "one past: one evicted"
        );
        assert!(store.take(&reader(2, 1)).is_none(), "its own oldest went");
        assert_eq!(store.len_of(&[1; 12]), 1, "another participant's stays");
    }

    #[test]
    fn a_participant_past_its_byte_bound_loses_its_own_oldest_only() {
        let mut store = WithheldReplays::default();
        assert!(store.insert(reader(1, 0), replay(1), true));
        let big = PER_PEER_BYTES / 2 - ENTRY_OVERHEAD - 1;
        assert!(store.insert(reader(2, 1), replay(big), false));
        assert!(store.insert(reader(2, 2), replay(big), false));
        assert_eq!(store.len_of(&[2; 12]), 2, "two halves fit");
        assert!(store.insert(reader(2, 3), replay(big), false));
        assert_eq!(store.len_of(&[2; 12]), 2, "the third evicts the first");
        assert!(store.take(&reader(2, 1)).is_none());
        assert_eq!(store.len_of(&[1; 12]), 1);
    }

    #[test]
    fn an_entry_larger_than_a_participants_bound_is_refused() {
        let mut store = WithheldReplays::default();
        let fits = PER_PEER_BYTES - ENTRY_OVERHEAD - 1;
        assert!(
            store.insert(reader(2, 1), replay(fits), false),
            "at the bound"
        );
        assert!(
            !store.insert(reader(2, 2), replay(fits + 1), false),
            "one byte past"
        );
        assert_eq!(store.len(), 1);
    }

    /// Strangers (no session) filling the store overall: a new stranger's
    /// entry is refused at the bound, a pending peer's entry stays, and a
    /// pending peer arriving after them still finds room.
    #[test]
    fn strangers_at_the_overall_bound_never_evict_a_pending_peer() {
        let mut store = WithheldReplays::default();
        assert!(
            store.insert(reader(1, 0), replay(1), true),
            "pending peer first"
        );
        let mut stored = 1;
        'fill: for prefix in 0x40..=0xFFu8 {
            for entity in 0..PER_PEER_ENTRIES as u16 {
                if stored == TOTAL_ENTRIES {
                    break 'fill;
                }
                assert!(store.insert(reader(prefix, entity), replay(1), false));
                stored += 1;
            }
        }
        assert_eq!(store.len(), TOTAL_ENTRIES, "at the bound");
        assert!(
            !store.insert(reader(0x3F, 0), replay(1), false),
            "a stranger one past the bound is refused"
        );
        assert_eq!(store.len_of(&[1; 12]), 1, "the pending peer's stays");
        assert!(
            store.insert(reader(3, 0), replay(1), true),
            "a pending peer arriving last takes a stranger's room"
        );
        assert_eq!(store.len(), TOTAL_ENTRIES);
        assert_eq!(store.take_peer(&[1; 12]).len(), 1);
        assert_eq!(store.take_peer(&[3; 12]).len(), 1);
    }

    /// At the overall bound, a pending peer takes room from participants
    /// without a session only, never from another pending peer.
    #[test]
    fn a_pending_peer_at_the_overall_bound_evicts_only_the_sessionless() {
        let mut store = WithheldReplays::default();
        let holders = TOTAL_ENTRIES / PER_PEER_ENTRIES - 1;
        for prefix in 0..holders as u8 {
            for entity in 0..PER_PEER_ENTRIES as u16 {
                assert!(store.insert(reader(prefix, entity), replay(1), true));
            }
        }
        for entity in 0..PER_PEER_ENTRIES as u16 {
            assert!(store.insert(reader(0xEE, entity), replay(1), false));
        }
        assert_eq!(store.len(), TOTAL_ENTRIES, "fixture: at the bound");
        for entity in 0..PER_PEER_ENTRIES as u16 {
            assert!(store.insert(reader(0xDD, entity), replay(1), true));
        }
        assert_eq!(
            store.len_of(&[0xEE; 12]),
            0,
            "the sessionless one made the room"
        );
        for prefix in 0..holders as u8 {
            assert_eq!(store.len_of(&[prefix; 12]), PER_PEER_ENTRIES, "{prefix}");
        }
        assert!(
            !store.insert(reader(0xCC, 0), replay(1), true),
            "no sessionless room left: refused"
        );
    }

    #[test]
    fn the_overall_byte_bound_holds() {
        let mut store = WithheldReplays::default();
        let big = PER_PEER_BYTES - ENTRY_OVERHEAD - 1;
        let fit = TOTAL_BYTES / PER_PEER_BYTES;
        for prefix in 0..fit as u8 {
            assert!(store.insert(reader(prefix, 0), replay(big), false));
        }
        assert!(
            !store.insert(reader(0xF0, 0), replay(big), false),
            "past the overall byte bound"
        );
        assert_eq!(store.len(), fit);
    }

    #[test]
    fn a_reinsert_replaces_and_take_peer_empties() {
        let mut store = WithheldReplays::default();
        assert!(store.insert(reader(1, 0), replay(1), true));
        assert!(store.insert(reader(1, 0), replay(5), true));
        assert_eq!(store.len(), 1);
        assert_eq!(store.take_peer(&[1; 12]).len(), 1);
        assert_eq!(store.len(), 0);
        assert_eq!(store.bytes, 0);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Synthetic addresses standing in for a peer reachable only through a relay.
//!
//! Two participants behind different NATs can both reach a Discovery Server
//! on the WAN and still be unable to reach each other: everything they
//! announce is private, and a private address is not an identity. The
//! Discovery Server can forward their datagrams for them, but the send path
//! does not speak GUIDs -- it takes a [`SocketAddr`](std::net::SocketAddr)
//! and hands it to a socket, at 43 call sites.
//!
//! Rather than thread a "this one goes through the relay" flag through all of
//! them, such a peer is given an address that cannot be anything else. The
//! send path keeps taking a `SocketAddr`; the transport recognises the range
//! and diverts the datagram instead of writing it to a socket.
//!
//! # Why 240.0.0.0/8
//!
//! 240.0.0.0/4 is reserved by RFC 1112 s4 and is not routed on the public
//! Internet. This module only uses the first /8 of it, so anything outside
//! `240.x.y.z` stays untouched and an operator reading a log can tell our
//! synthetic addresses from everything else at a glance.
//!
//! The range is already refused everywhere it could otherwise appear:
//! [`ExternalLocator::new`](super::external_locator::ExternalLocator::new)
//! rejects it as "reserved and not routed", and `is_globally_routable` in the
//! discovery FSM excludes it, so a synthetic locator can never win the
//! "globally routable" pass of `select_best_locator`. A collision with a real
//! configured address is therefore impossible, not merely unlikely.
//!
//! What is NOT impossible is a FOREIGN peer announcing such an address:
//! `usable_unicast_locator` accepts anything IPv4, unicast, with a non-zero
//! port. An address in the range that this table does not know is a peer we
//! have no relay entry for, and the send path must refuse it rather than
//! guess -- see [`RelayLocators::peer_of`].
//!
//! # What this table does NOT do
//!
//! It does not decide WHICH peers deserve a synthetic locator (that belongs
//! to the receiver, next to `select_best_locator`, which is the only place
//! that knows whether a peer is directly reachable), it does not talk to the
//! Discovery Server, and it does not carry ports: an address identifies a
//! peer, and the relay addresses that peer by GUID prefix, so the port a
//! caller supplies alongside a synthetic address is ignored.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// The RTPS GUID prefix of a participant, 12 bytes per RTPS v2.5 s8.2.4.2.
///
/// Spelled out rather than imported: `transport` must not depend on
/// `discovery_server`, and the three `GuidPrefix` aliases in this crate all
/// resolve to this same array.
type GuidPrefix = [u8; 12];

/// The first octet of the range synthetic locators are carved from.
const RELAY_PREFIX_OCTET: u8 = 240;

/// The `240.0.0.0/8` network in host order, to be OR-ed with an index.
const RELAY_NETWORK: u32 = (RELAY_PREFIX_OCTET as u32) << 24;

/// The largest index the range can carry: `240.255.255.255`.
const MAX_INDEX: u32 = 0x00FF_FFFF;

/// The first index handed out.
///
/// Index 0 would produce `240.0.0.0`, which reads as a network address and is
/// ambiguous in a log. Starting at 1 costs one address out of 16 777 215.
const FIRST_INDEX: u32 = 1;

/// Does this address belong to the synthetic relay range?
///
/// This is the whole cost the relay imposes on participants that never use
/// one: a single comparison on the first octet, before any lock is taken and
/// before any map is consulted, on every unicast send.
#[inline]
#[must_use]
pub(crate) fn is_relay_address(address: Ipv4Addr) -> bool {
    address.octets()[0] == RELAY_PREFIX_OCTET
}

/// The address an index maps to, or `None` once the range is exhausted.
fn address_of_index(index: u32) -> Option<Ipv4Addr> {
    if !(FIRST_INDEX..=MAX_INDEX).contains(&index) {
        return None;
    }
    Some(Ipv4Addr::from(RELAY_NETWORK | index))
}

/// The peers currently addressed through the relay, in both directions.
///
/// Reads dominate by orders of magnitude -- every relayed datagram performs
/// one, every discovery event at most one write -- hence an `RwLock` rather
/// than a `Mutex`.
pub(crate) struct RelayLocators {
    state: RwLock<State>,
}

struct State {
    by_prefix: HashMap<GuidPrefix, Ipv4Addr>,
    by_address: HashMap<Ipv4Addr, GuidPrefix>,
    /// The next index to hand out. Only ever increases.
    next_index: u32,
}

impl RelayLocators {
    /// An empty table, handing out addresses from the start of the range.
    pub(crate) fn new() -> Self {
        Self::starting_at(FIRST_INDEX)
    }

    /// An empty table whose first address is `first_index`.
    ///
    /// Exists so the exhaustion behaviour can be tested against the real
    /// `assign` rather than against a reimplementation of its arithmetic:
    /// walking to the end of the range one `assign` at a time would be
    /// sixteen million insertions.
    pub(crate) fn starting_at(first_index: u32) -> Self {
        Self {
            state: RwLock::new(State {
                by_prefix: HashMap::new(),
                by_address: HashMap::new(),
                next_index: first_index,
            }),
        }
    }

    /// The address standing in for `prefix`, allocating one on first sight.
    ///
    /// Idempotent: a peer keeps the same address for as long as it is
    /// registered, so a locator already announced to the rest of the stack
    /// stays valid. Returns `None` only when the range is exhausted, which
    /// after 16 777 215 distinct peers in one process means something is
    /// leaking rather than that the range is too small.
    pub(crate) fn assign(&self, prefix: GuidPrefix) -> Option<Ipv4Addr> {
        // The common case is a peer already in the table, so try under a read
        // guard first and take the write guard only to insert.
        if let Some(address) = self.address_of(&prefix) {
            return Some(address);
        }

        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        // Re-check: another thread may have inserted between the two guards.
        if let Some(address) = state.by_prefix.get(&prefix) {
            return Some(*address);
        }

        let address = address_of_index(state.next_index)?;
        state.next_index += 1;
        state.by_prefix.insert(prefix, address);
        state.by_address.insert(address, prefix);
        Some(address)
    }

    /// The peer a synthetic address stands for, if it is still registered.
    ///
    /// `None` has exactly one meaning: this address names no peer we relay
    /// to. It covers both a peer that has left while a datagram was in flight
    /// and a foreign participant that announced a reserved address on the
    /// wire. Both must end in a refusal rather than a real datagram sent into
    /// a range that does not route, so the caller reports it instead of
    /// falling back to the socket.
    pub(crate) fn peer_of(&self, address: Ipv4Addr) -> Option<GuidPrefix> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state.by_address.get(&address).copied()
    }

    /// The address currently standing in for `prefix`, without allocating.
    pub(crate) fn address_of(&self, prefix: &GuidPrefix) -> Option<Ipv4Addr> {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state.by_prefix.get(prefix).copied()
    }

    /// Forget a peer, returning the address it held.
    ///
    /// The index is NOT recycled. Handing a departed peer's address to a new
    /// one would deliver any datagram still in flight to the wrong
    /// participant -- and it would look like it worked, because both ends are
    /// live HDDS participants that will happily parse what arrives. A
    /// released address resolving to nothing is a refusal we can see; a
    /// released address resolving to somebody else is a mis-delivery nobody
    /// can.
    pub(crate) fn release(&self, prefix: &GuidPrefix) -> Option<Ipv4Addr> {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        let address = state.by_prefix.remove(prefix)?;
        state.by_address.remove(&address);
        Some(address)
    }

    /// How many peers are currently addressed through the relay.
    pub(crate) fn len(&self) -> usize {
        let state = self.state.read().unwrap_or_else(|e| e.into_inner());
        state.by_prefix.len()
    }
}

impl Default for RelayLocators {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(tag: u8) -> GuidPrefix {
        [tag; 12]
    }

    #[test]
    fn the_range_predicate_matches_exactly_the_first_reserved_slash_8() {
        assert!(is_relay_address(Ipv4Addr::new(240, 0, 0, 1)));
        assert!(is_relay_address(Ipv4Addr::new(240, 255, 255, 255)));

        // Neighbours on both sides, and the addresses a real deployment uses.
        for address in [
            Ipv4Addr::new(239, 255, 255, 255),
            Ipv4Addr::new(241, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
            Ipv4Addr::new(192, 168, 1, 50),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
        ] {
            assert!(
                !is_relay_address(address),
                "{address} must not be taken for a relay locator"
            );
        }
    }

    #[test]
    fn an_assigned_address_is_stable_and_resolves_back_to_its_peer() {
        let table = RelayLocators::new();
        let peer = prefix(0xAA);

        let first = table.assign(peer).expect("the range cannot be exhausted");
        let second = table.assign(peer).expect("the range cannot be exhausted");

        assert_eq!(first, second, "a peer must keep one address");
        assert!(is_relay_address(first));
        assert_eq!(table.peer_of(first), Some(peer));
        assert_eq!(table.address_of(&peer), Some(first));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn distinct_peers_get_distinct_addresses() {
        let table = RelayLocators::new();
        let mut seen = std::collections::HashSet::new();

        for tag in 0..64u8 {
            let address = table.assign(prefix(tag)).expect("range not exhausted");
            assert!(seen.insert(address), "{address} handed out twice");
            assert_eq!(table.peer_of(address), Some(prefix(tag)));
        }
        assert_eq!(table.len(), 64);
    }

    #[test]
    fn a_released_address_resolves_to_nothing_and_is_never_handed_out_again() {
        let table = RelayLocators::new();
        let departed = prefix(0x01);

        let address = table.assign(departed).expect("range not exhausted");
        assert_eq!(table.release(&departed), Some(address));

        // The refusal, not a stale mapping.
        assert_eq!(table.peer_of(address), None);
        assert_eq!(table.address_of(&departed), None);
        assert_eq!(table.len(), 0);

        // And the address does not come back: a datagram still in flight for
        // the departed peer must never land on the newcomer.
        let newcomer = prefix(0x02);
        let reassigned = table.assign(newcomer).expect("range not exhausted");
        assert_ne!(
            reassigned, address,
            "a released address was recycled: an in-flight datagram would be mis-delivered"
        );

        // Releasing twice is not an error, and releasing an unknown peer is
        // not either -- a peer can leave before it was ever relayed to.
        assert_eq!(table.release(&departed), None);
        assert_eq!(table.release(&prefix(0xFF)), None);
    }

    #[test]
    fn the_last_address_of_the_range_is_usable_and_the_next_request_is_refused() {
        let table = RelayLocators::starting_at(MAX_INDEX);

        let last = table
            .assign(prefix(0x01))
            .expect("MAX_INDEX must be usable");
        assert_eq!(last, Ipv4Addr::new(240, 255, 255, 255));

        // Exhausted: refused, not wrapped around onto an address in use.
        assert_eq!(table.assign(prefix(0x02)), None);

        // A peer already in the table is still served: `assign` is a lookup
        // first, and exhaustion must not disconnect the peers already relayed.
        assert_eq!(table.assign(prefix(0x01)), Some(last));

        // And the exhaustion is not permanent if room is freed -- though the
        // freed INDEX stays burnt, so the table is simply full for good here.
        table.release(&prefix(0x01));
        assert_eq!(table.assign(prefix(0x03)), None);
    }

    #[test]
    fn indices_map_onto_the_range_without_touching_its_edges() {
        assert_eq!(address_of_index(0), None, "240.0.0.0 is not handed out");
        assert_eq!(
            address_of_index(FIRST_INDEX),
            Some(Ipv4Addr::new(240, 0, 0, 1))
        );
        assert_eq!(address_of_index(256), Some(Ipv4Addr::new(240, 0, 1, 0)));
        assert_eq!(
            address_of_index(MAX_INDEX),
            Some(Ipv4Addr::new(240, 255, 255, 255))
        );
        assert_eq!(address_of_index(MAX_INDEX + 1), None, "stays inside 240/8");
        assert_eq!(address_of_index(u32::MAX), None);

        // Every index in the range produces an address the predicate accepts,
        // which is what makes the send-path comparison sufficient.
        for index in [FIRST_INDEX, 2, 255, 65_535, 1_000_000, MAX_INDEX] {
            let address = address_of_index(index).expect("inside the range");
            assert!(is_relay_address(address), "{address} for index {index}");
        }
    }

    #[test]
    fn concurrent_assignment_of_the_same_peer_yields_one_address() {
        use std::sync::Arc;

        let table = Arc::new(RelayLocators::new());
        let peer = prefix(0x7E);

        // The read-then-write sequence in `assign` has a window between the
        // two guards; the re-check inside the write guard is what closes it.
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let table = Arc::clone(&table);
                std::thread::spawn(move || table.assign(peer).expect("range not exhausted"))
            })
            .collect();

        let addresses: Vec<_> = threads
            .into_iter()
            .map(|handle| handle.join().expect("assign must not panic"))
            .collect();

        let first = addresses[0];
        assert!(
            addresses.iter().all(|address| *address == first),
            "one peer received several addresses: {addresses:?}"
        );
        assert_eq!(table.len(), 1, "one peer must occupy one entry");
    }
}

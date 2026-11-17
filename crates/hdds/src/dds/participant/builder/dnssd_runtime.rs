// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-side wiring of DNS-SD discovery into SPDP.
//!
//! A DNS zone is a COLD-PATH peer source: the resolved `SRV` targets only
//! mutate the `Cloud` origin of the participant's `SpdpPeerSet`, the
//! announcer keeps reading `snapshot()` once per announcement period, and
//! normal SPDP/SEDP takes over as soon as one unicast `DATA(p)` reaches
//! the peer. The RTPS data path is untouched.
//!
//! # Why the Cloud origin
//!
//! DNS-SD and a cloud registry answer the same question ("who else is in
//! this deployment?") and produce the same thing (leased unicast SPDP
//! destinations), so they share the one leased origin the cloud wiring
//! built. That has one consequence, enforced in `bootstrap.rs`: a
//! participant configures EITHER a cloud registry OR DNS-SD, never both,
//! because each origin owner replaces the whole origin on every poll and
//! two owners would delete each other's peers on alternate ticks.
//!
//! # Synthetic keys
//!
//! The origin is keyed by GUID prefix; an `SRV` record carries a host and
//! a port, never a GUID. Each resolved `ip:port` therefore gets a stable
//! synthetic prefix (the first 12 bytes of `MD5("hdds-dnssd:<addr>")`),
//! so a record that disappears from the zone removes exactly its own
//! peer and nothing else. The prefix never reaches the wire: SPDP learns
//! the peer's real GUID from its first `DATA(p)`, and the announcer only
//! ever uses these entries as destination addresses.
//!
//! # Keeping this participant out of its own peer set
//!
//! Self-exclusion here is an ADDRESS match against the transport's
//! advertised unicast locators, not a GUID match: an `SRV` record carries
//! no GUID, so the cloud poller's `own_prefix` test has no equivalent. A
//! zone that advertises this participant under an address the transport
//! does not list (a VIP, a NAT address, an interface the filter dropped)
//! therefore makes it announce to itself once per period. The discovery
//! FSM discards its own GUID on arrival, so the cost is one wasted
//! datagram, not a phantom peer.
//!
//! # Contract followed
//!
//! Like the Discovery Server and cloud registry paths, and unlike
//! `discovery/k8s.rs`, this feeds the peer set ONLY: no synthetic GUID is
//! registered in the discovery FSM (`register_static_peer`), because the
//! GUID here is a hash of an address, not a participant identity.

use crate::core::discovery::{usable_unicast_locator, PeerOrigin, SpdpPeerSet};
use crate::discovery::dnssd::{Answer, DnsSdPeerSink};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Lease multiplier: a DNS-SD peer survives this many missed lookups of a
/// stalled or dead resolver thread before the announcer stops unicasting
/// to it. Same rule and same floor as the cloud registry lease
/// (`cloud_discovery_runtime::cloud_lease`), because both feed the same
/// leased origin and a peer must not expire faster from one source than
/// from the other.
const LEASE_LOOKUPS: u32 = 3;
const LEASE_FLOOR: Duration = Duration::from_secs(1);

/// How many consecutive INCOMPLETE answers a peer survives without being
/// re-confirmed before it is retired anyway.
///
/// An incomplete answer (a listed `SRV` target with no address record)
/// says nothing about the peers it fails to mention, so retiring them on
/// the spot would drop a live peer over one lost `A` question. Carrying
/// them for the same number of polls the lease grants an unanswered
/// lookup bounds the other side of it: a target whose address record is
/// gone for good stops holding its peer open after three polls.
const CARRY_POLLS: u32 = LEASE_LOOKUPS;

/// Lease attached to every DNS-SD peer: three poll intervals, one second
/// at least.
pub(super) fn dnssd_lease(poll_interval: Duration) -> Duration {
    poll_interval.saturating_mul(LEASE_LOOKUPS).max(LEASE_FLOOR)
}

/// Stable per-address key for the leased peer origin.
///
/// MD5 is used as a fixed-width hash of an address string, never as a
/// security primitive: the value is process-local, never transmitted, and
/// an attacker who could choose it would only be choosing which of their
/// own two addresses replaces the other.
pub(super) fn synthetic_prefix(addr: &SocketAddr) -> [u8; 12] {
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(b"hdds-dnssd:");
    hasher.update(addr.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&digest[..12]);
    prefix
}

/// Feeds resolved DNS-SD peers into the `Cloud` origin of the SPDP peer set.
pub(super) struct SpdpDnsSdSink {
    peer_set: Arc<SpdpPeerSet>,
    own_locators: HashSet<SocketAddr>,
    lease: Duration,
    /// The view last written to the origin, so an incomplete answer can
    /// carry forward the peers it does not mention.
    last_view: HashMap<[u8; 12], HashSet<SocketAddr>>,
    /// Consecutive incomplete answers each carried peer has survived.
    carried: HashMap<[u8; 12], u32>,
    /// Addresses the last answer dropped as unusable, for a log line that
    /// fires on change instead of on every poll.
    dropped: Vec<SocketAddr>,
}

impl SpdpDnsSdSink {
    pub(super) fn new(
        peer_set: Arc<SpdpPeerSet>,
        own_locators: impl IntoIterator<Item = SocketAddr>,
        lease: Duration,
    ) -> Self {
        Self {
            peer_set,
            own_locators: own_locators.into_iter().collect(),
            lease,
            last_view: HashMap::new(),
            carried: HashMap::new(),
            dropped: Vec::new(),
        }
    }

    /// The peer view an answered lookup produces: routable IPv4 unicast
    /// destinations that are not this participant's own metatraffic
    /// locators, keyed by their synthetic prefix.
    ///
    /// IPv6 targets are dropped by `usable_unicast_locator`, the single
    /// predicate every runtime peer source shares: the UDP transport binds
    /// IPv4 sockets, so an IPv6 destination would fail silently on every
    /// announcement. The resolver still reports `AAAA` records; this is
    /// where they stop.
    fn peer_view(
        &self,
        peers: &[SocketAddr],
    ) -> (HashMap<[u8; 12], HashSet<SocketAddr>>, Vec<SocketAddr>) {
        let mut view: HashMap<[u8; 12], HashSet<SocketAddr>> = HashMap::new();
        let mut dropped = Vec::new();
        for peer in peers {
            if self.own_locators.contains(peer) {
                continue;
            }
            if !usable_unicast_locator(peer) {
                if !dropped.contains(peer) {
                    dropped.push(*peer);
                }
                continue;
            }
            view.entry(synthetic_prefix(peer))
                .or_default()
                .insert(*peer);
        }
        (view, dropped)
    }

    /// Peers an INCOMPLETE answer did not mention, kept for at most
    /// [`CARRY_POLLS`] consecutive incomplete answers.
    fn carry_forward(&mut self, view: &mut HashMap<[u8; 12], HashSet<SocketAddr>>) {
        let mut still_carried: HashMap<[u8; 12], u32> = HashMap::new();
        for (prefix, locators) in &self.last_view {
            if view.contains_key(prefix) {
                continue;
            }
            let polls = self.carried.get(prefix).copied().unwrap_or(0) + 1;
            if polls > CARRY_POLLS {
                log::warn!(
                    "[DNS-SD] Retiring {:?} after {} incomplete answers in a row",
                    locators,
                    CARRY_POLLS
                );
                continue;
            }
            still_carried.insert(*prefix, polls);
            view.insert(*prefix, locators.clone());
        }
        self.carried = still_carried;
    }
}

impl DnsSdPeerSink for SpdpDnsSdSink {
    fn on_peers(&mut self, peers: &[SocketAddr], answer: Answer) {
        let (mut view, dropped) = self.peer_view(peers);
        if dropped != self.dropped {
            if !dropped.is_empty() {
                // Silence here is how a participant ends up with a healthy
                // status and zero SPDP destinations: the zone published
                // addresses this transport cannot send to.
                log::warn!(
                    "[DNS-SD] {} resolved address(es) are not usable SPDP destinations and were                      dropped (IPv6, unspecified, multicast or port 0): {:?}",
                    dropped.len(),
                    dropped
                );
            }
            self.dropped = dropped;
        }
        match answer {
            Answer::Complete => self.carried.clear(),
            Answer::Partial => self.carry_forward(&mut view),
        }
        self.last_view = view.clone();
        if self.peer_set.sync_cloud(view, self.lease) {
            log::debug!(
                "[DNS-SD] SPDP peers updated: {} locators",
                self.peer_set.counts().cloud_peers
            );
        }
    }

    fn on_stopped(&mut self) {
        self.last_view.clear();
        self.carried.clear();
        self.peer_set.clear(PeerOrigin::Cloud);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("a literal socket address")
    }

    #[test]
    fn resolved_peers_reach_the_cloud_origin_and_vanish_with_their_record() {
        let peer_set = Arc::new(SpdpPeerSet::new());
        let mut sink = SpdpDnsSdSink::new(
            Arc::clone(&peer_set),
            [addr("192.0.2.9:7410")],
            Duration::from_secs(5),
        );

        sink.on_peers(
            &[addr("192.0.2.1:7410"), addr("192.0.2.2:7412")],
            Answer::Complete,
        );
        let mut snapshot = peer_set.snapshot();
        snapshot.sort();
        assert_eq!(
            snapshot,
            vec![addr("192.0.2.1:7410"), addr("192.0.2.2:7412")]
        );
        assert_eq!(peer_set.counts().cloud_peers, 2);

        // One record vanished from the zone: only that peer goes.
        sink.on_peers(&[addr("192.0.2.1:7410")], Answer::Complete);
        assert_eq!(peer_set.snapshot(), vec![addr("192.0.2.1:7410")]);

        // The zone answered with nothing at all: the origin empties.
        sink.on_peers(&[], Answer::Complete);
        assert!(peer_set.snapshot().is_empty());
    }

    #[test]
    fn own_locators_and_unusable_addresses_are_excluded() {
        let peer_set = Arc::new(SpdpPeerSet::new());
        let own = [addr("192.0.2.9:7410"), addr("127.0.0.1:7420")];
        let mut sink = SpdpDnsSdSink::new(Arc::clone(&peer_set), own, Duration::from_secs(5));

        sink.on_peers(
            &[
                addr("192.0.2.9:7410"),     // own: excluded
                addr("127.0.0.1:7420"),     // own: excluded
                addr("[2001:db8::1]:7410"), // IPv6: the transport cannot send to it
                addr("0.0.0.0:7410"),       // unspecified
                addr("239.255.0.1:7400"),   // multicast
                addr("192.0.2.1:0"),        // port 0
                addr("192.0.2.1:7410"),     // the only real peer
            ],
            Answer::Complete,
        );
        assert_eq!(peer_set.snapshot(), vec![addr("192.0.2.1:7410")]);
    }

    /// An answer that could not resolve every target it listed is NOT the
    /// membership: the peers it fails to mention keep their place for a
    /// bounded number of polls instead of being retired on the spot.
    #[test]
    fn an_incomplete_answer_keeps_the_peers_it_could_not_reconfirm() {
        let peer_set = Arc::new(SpdpPeerSet::new());
        let mut sink = SpdpDnsSdSink::new(Arc::clone(&peer_set), [], Duration::from_secs(30));
        let a = addr("192.0.2.1:7410");
        let b = addr("192.0.2.2:7412");

        sink.on_peers(&[a, b], Answer::Complete);
        assert_eq!(peer_set.counts().cloud_peers, 2);

        // B's target lost its A record: the answer is incomplete, so B is
        // carried, not retired.
        for poll in 1..=CARRY_POLLS {
            sink.on_peers(&[a], Answer::Partial);
            let mut snapshot = peer_set.snapshot();
            snapshot.sort();
            assert_eq!(
                snapshot,
                vec![a, b],
                "an incomplete answer retired a peer it never mentioned (poll {})",
                poll
            );
        }

        // Past the budget it goes anyway: an unresolvable target must not
        // hold a peer open for ever.
        sink.on_peers(&[a], Answer::Partial);
        assert_eq!(peer_set.snapshot(), vec![a]);

        // A COMPLETE answer is authoritative from the first poll.
        sink.on_peers(&[a, b], Answer::Complete);
        assert_eq!(peer_set.counts().cloud_peers, 2);
        sink.on_peers(&[a], Answer::Complete);
        assert_eq!(peer_set.snapshot(), vec![a]);
    }

    /// The DNS-SD origin must not disturb the peers other sources own.
    #[test]
    fn stopping_clears_only_the_cloud_origin() {
        let peer_set = Arc::new(SpdpPeerSet::new());
        let static_peer = addr("192.0.2.50:7410");
        peer_set.add_static(static_peer);
        peer_set.replace_server([7u8; 12], [addr("192.0.2.60:7410")]);
        let mut sink = SpdpDnsSdSink::new(Arc::clone(&peer_set), [], Duration::from_secs(5));

        sink.on_peers(&[addr("192.0.2.1:7410")], Answer::Complete);
        assert_eq!(peer_set.counts().cloud_peers, 1);

        sink.on_stopped();
        assert_eq!(peer_set.counts().cloud_peers, 0);
        let mut snapshot = peer_set.snapshot();
        snapshot.sort();
        assert_eq!(snapshot, vec![static_peer, addr("192.0.2.60:7410")]);
    }

    #[test]
    fn synthetic_prefixes_are_stable_and_address_specific() {
        let a = synthetic_prefix(&addr("192.0.2.1:7410"));
        assert_eq!(a, synthetic_prefix(&addr("192.0.2.1:7410")));
        assert_ne!(a, synthetic_prefix(&addr("192.0.2.1:7411")));
        assert_ne!(a, synthetic_prefix(&addr("192.0.2.2:7410")));
    }

    #[test]
    fn the_lease_is_three_lookups_with_a_floor() {
        assert_eq!(dnssd_lease(Duration::from_secs(5)), Duration::from_secs(15));
        assert_eq!(
            dnssd_lease(Duration::from_millis(100)),
            Duration::from_secs(1)
        );
    }
}

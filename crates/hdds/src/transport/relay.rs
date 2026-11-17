// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The transport's end of the Discovery Server relay.
//!
//! [`super::relay_locator`] gives a peer reachable only through the relay an
//! address in `240.0.0.0/8`. This module is what happens when a datagram is
//! sent to one: the address is translated back to the peer's GUID prefix and
//! the datagram is handed to a [`RelaySink`] instead of a socket.
//!
//! # Why a trait
//!
//! The sink is the Discovery Server session, which lives in
//! `dds::participant` and owns a TCP connection. `transport` must not depend
//! on `discovery_server` - it is the layer underneath - so the dependency is
//! inverted: the transport declares what it needs from a sink and the
//! participant installs one. It also means the whole diversion can be tested
//! with a sink that answers on command, without a server, a socket or a
//! thread.
//!
//! # What the sink must guarantee
//!
//! [`RelaySink::offer`] is called from whatever thread is sending, and on the
//! user-data path that is the DDS writer thread. It must not block: refusing
//! a datagram is always better than delaying one, because RTPS reliability
//! above it treats a refusal exactly as it treats any other packet loss,
//! while a stalled writer has no such recovery.

use super::relay_locator::{is_relay_address, RelayLocators};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// The RTPS GUID prefix of a participant, 12 bytes per RTPS v2.5 s8.2.4.2.
type GuidPrefix = [u8; 12];

/// Somewhere a datagram can be handed to for forwarding by the server.
pub(crate) trait RelaySink: Send + Sync {
    /// Take one datagram addressed to `peer`, or refuse it.
    ///
    /// `true` means it was taken for forwarding - not that it arrived, which
    /// no one on this side can know. `false` means it was refused and is
    /// gone; the caller counts it and carries on.
    ///
    /// Must not block, and must not log: `offer` runs under the periodic
    /// HEARTBEAT path's send gate too (`UdpTransport::
    /// transmit_best_effort_resolved`'s `Relayed` branch), where a
    /// synchronous logging call is exactly the kind of wait that gate
    /// must never be able to make (an application logging consumer that
    /// stalls is reachable the same way any other lock holder is, see
    /// `ClassicPairing`'s doc). See `take_pending_diagnostics`.
    fn offer(&self, peer: GuidPrefix, datagram: &[u8]) -> bool;

    /// Diagnostics `offer` collected but could not log itself, taken and
    /// cleared so the caller can log them once it is no longer somewhere
    /// logging cannot wait. Default: nothing to report (a sink with no
    /// such diagnostics, e.g. a test double, never needs to override
    /// this).
    fn take_pending_diagnostics(&self) -> RelayPendingDiagnostics {
        RelayPendingDiagnostics::default()
    }
}

/// Diagnostics a [`RelaySink::offer`] call collected but deferred,
/// because logging them inline could itself have blocked a caller that
/// is not allowed to wait (the periodic HEARTBEAT path's send gate).
#[derive(Default)]
pub(crate) struct RelayPendingDiagnostics {
    /// The length of the first oversized datagram `offer` ever refused,
    /// if that happened since the last `take_pending_diagnostics` call.
    pub(crate) oversized_len: Option<usize>,
    /// Whether `offer` queued a datagram but failed to wake the session
    /// for the first time since the last `take_pending_diagnostics` call.
    pub(crate) wake_failed: bool,
}

/// What the relay's send path could not deliver, and why.
///
/// Shared rather than owned by [`RelayEgress`] because the thread that can
/// say anything useful about these numbers is the Discovery Server session,
/// and it never holds the transport. A counter whose only reader would be a
/// debugger is not a counter.
///
/// It holds ONLY what the sink cannot see for itself. A refusal is counted
/// by the sink, which knows why it refused; counting it here as well would
/// make one lost datagram show up as two.
#[derive(Default)]
pub(crate) struct RelayStats {
    /// Datagrams whose destination named no peer we relay to.
    unknown_destination: AtomicU64,
}

impl RelayStats {
    /// Datagrams refused because their destination named no relayed peer.
    pub(crate) fn unknown_destination(&self) -> u64 {
        self.unknown_destination.load(Ordering::Relaxed)
    }
}

/// The relay as the transport sees it: a table and somewhere to hand bytes.
pub(crate) struct RelayEgress {
    locators: Arc<RelayLocators>,
    sink: Arc<dyn RelaySink>,
    stats: Arc<RelayStats>,
}

impl RelayEgress {
    /// Pair a locator table with the sink that forwards for it.
    pub(crate) fn new(
        locators: Arc<RelayLocators>,
        sink: Arc<dyn RelaySink>,
        stats: Arc<RelayStats>,
    ) -> Self {
        Self {
            locators,
            sink,
            stats,
        }
    }

    /// Send one datagram to the peer a synthetic address stands for.
    ///
    /// Returns the byte count on the same terms as `UdpSocket::send_to`: the
    /// datagram was handed over, not that it was delivered. A refusal by the
    /// sink is reported the same way for the same reason - a datagram dropped
    /// for want of room is a lost packet, which is what the socket path would
    /// also report as success, and what RTPS reliability is there to notice.
    /// The sink counts the loss, with the reason it refused; turning it into
    /// an `Err` would only make 43 call sites log a failure none of them can
    /// act on.
    ///
    /// An address that names NO peer is different in kind and is an error: it
    /// is a routing or configuration fault (a peer released while a datagram
    /// was in flight, or a foreign participant announcing a reserved address,
    /// which `usable_unicast_locator` does not filter out). Sending it to a
    /// socket instead would put a datagram on the wire addressed to a range
    /// that does not route.
    pub(crate) fn send(&self, datagram: &[u8], address: Ipv4Addr) -> std::io::Result<usize> {
        let Some(peer) = self.resolve_peer(address, datagram.len()) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{address} names no relayed peer"),
            ));
        };
        self.offer_resolved(peer, datagram)
    }

    /// The one potentially-blocking step in this whole path
    /// (`RelayLocators::peer_of`'s `RwLock` read): resolve `address` to
    /// the peer it names, without sending anything. `None` means the
    /// address is in the relay range but names no peer this participant
    /// relays to -- logged here, once, so the periodic HEARTBEAT path
    /// can call this during its prepare phase (no gate held) and never
    /// repeat the lookup, or its diagnostic, later under
    /// `HeartbeatSchedulerState::send_gate`.
    pub(crate) fn resolve_peer(
        &self,
        address: Ipv4Addr,
        datagram_len: usize,
    ) -> Option<GuidPrefix> {
        let peer = self.locators.peer_of(address);
        if peer.is_none() {
            let total = self
                .stats
                .unknown_destination
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            if total == 1 {
                log::warn!(
                    "[relay] {} is in the relay range but names no peer this participant \
                     relays to; refusing to send {} bytes. Further occurrences are counted, \
                     not logged.",
                    address,
                    datagram_len
                );
            }
        }
        peer
    }

    /// Hand an already-resolved datagram straight to the sink: no
    /// lookup, no logging, just `RelaySink::offer`'s own non-blocking
    /// call -- safe to run inside a gate.
    pub(crate) fn offer_resolved(
        &self,
        peer: GuidPrefix,
        datagram: &[u8],
    ) -> std::io::Result<usize> {
        // A refusal is a lost packet and is reported as a send, for the
        // same reason a socket does: RTPS reliability above is what
        // notices. The sink counts it, with the reason it refused.
        let _taken = self.sink.offer(peer, datagram);
        Ok(datagram.len())
    }

    /// Take and clear whatever `offer` could not log itself. Call this
    /// AFTER releasing any gate the caller's own transmit ran under --
    /// never from inside it.
    pub(crate) fn drain_pending_diagnostics(&self) -> RelayPendingDiagnostics {
        self.sink.take_pending_diagnostics()
    }
}

/// Is this destination one the relay must handle rather than a socket?
///
/// The whole cost borne by a participant with no relay at all: one variant
/// check and one comparison on the first octet, ahead of every unicast send.
/// An IPv6 destination is never relayed - the relay range is IPv4 and the
/// transport binds IPv4 sockets.
#[inline]
pub(crate) fn destination_is_relayed(endpoint: &SocketAddr) -> Option<Ipv4Addr> {
    match endpoint {
        SocketAddr::V4(v4) if is_relay_address(*v4.ip()) => Some(*v4.ip()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A sink that records what it was offered and answers as instructed.
    struct ScriptedSink {
        accept: bool,
        offered: Mutex<Vec<(GuidPrefix, Vec<u8>)>>,
    }

    impl ScriptedSink {
        fn new(accept: bool) -> Arc<Self> {
            Arc::new(Self {
                accept,
                offered: Mutex::new(Vec::new()),
            })
        }
    }

    impl RelaySink for ScriptedSink {
        fn offer(&self, peer: GuidPrefix, datagram: &[u8]) -> bool {
            self.offered.lock().unwrap().push((peer, datagram.to_vec()));
            self.accept
        }
    }

    fn peer(tag: u8) -> GuidPrefix {
        [tag; 12]
    }

    #[test]
    fn only_the_relay_range_is_diverted() {
        let relayed: SocketAddr = "240.0.0.7:7410".parse().unwrap();
        assert_eq!(
            destination_is_relayed(&relayed),
            Some(Ipv4Addr::new(240, 0, 0, 7))
        );

        // Everything a real deployment sends to keeps going to its socket.
        for endpoint in [
            "192.168.1.50:7410",
            "10.0.0.1:7411",
            "127.0.0.1:7400",
            "239.255.0.1:7400",
            "241.0.0.1:7410",
            "[::1]:7410",
        ] {
            let endpoint: SocketAddr = endpoint.parse().unwrap();
            assert_eq!(
                destination_is_relayed(&endpoint),
                None,
                "{endpoint} must not be diverted"
            );
        }
    }

    #[test]
    fn a_datagram_for_a_known_peer_reaches_the_sink_whole() {
        let locators = Arc::new(RelayLocators::new());
        let address = locators.assign(peer(0xAB)).expect("range not exhausted");
        let sink = ScriptedSink::new(true);
        let stats = Arc::new(RelayStats::default());
        let egress = RelayEgress::new(
            Arc::clone(&locators),
            Arc::clone(&sink) as Arc<dyn RelaySink>,
            Arc::clone(&stats),
        );

        // A real RTPS header, so a reader of this test sees what travels.
        let datagram = b"RTPS\x02\x05\x01\x1a............\x15\x01\x18\x00".to_vec();
        let sent = egress.send(&datagram, address).expect("a known peer");

        assert_eq!(sent, datagram.len(), "the byte count is the datagram's");
        let offered = sink.offered.lock().unwrap();
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].0, peer(0xAB), "addressed by GUID prefix");
        assert_eq!(offered[0].1, datagram, "the datagram is not altered");
        assert_eq!(stats.unknown_destination(), 0);
    }

    #[test]
    fn an_address_naming_no_peer_is_an_error_not_a_send() {
        let locators = Arc::new(RelayLocators::new());
        let sink = ScriptedSink::new(true);
        let stats = Arc::new(RelayStats::default());
        let egress = RelayEgress::new(
            locators,
            Arc::clone(&sink) as Arc<dyn RelaySink>,
            Arc::clone(&stats),
        );

        // Nothing was ever assigned, so this is the shape of both a departed
        // peer and a foreign participant announcing a reserved address.
        let error = egress
            .send(b"RTPS", Ipv4Addr::new(240, 0, 0, 1))
            .expect_err("an unknown relay address cannot be sent to");

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(
            sink.offered.lock().unwrap().is_empty(),
            "nothing may be handed over for a peer we cannot name"
        );
        assert_eq!(stats.unknown_destination(), 1);
    }

    #[test]
    fn a_refused_datagram_is_counted_and_reported_as_sent() {
        let locators = Arc::new(RelayLocators::new());
        let address = locators.assign(peer(0x01)).expect("range not exhausted");
        let sink = ScriptedSink::new(false);
        let stats = Arc::new(RelayStats::default());
        let egress = RelayEgress::new(
            locators,
            Arc::clone(&sink) as Arc<dyn RelaySink>,
            Arc::clone(&stats),
        );

        // Reported as sent on purpose: a datagram dropped for want of room is
        // a lost packet, and that is what a socket send reports too.
        let sent = egress.send(b"RTPS-payload", address).expect("not an error");
        assert_eq!(sent, "RTPS-payload".len());
        assert_eq!(stats.unknown_destination(), 0, "the peer WAS known");

        // And the loss stays counted rather than turning into log volume.
        for _ in 0..99 {
            egress.send(b"RTPS-payload", address).expect("not an error");
        }
    }

    #[test]
    fn a_released_peer_stops_being_sent_to() {
        let locators = Arc::new(RelayLocators::new());
        let address = locators.assign(peer(0x02)).expect("range not exhausted");
        let sink = ScriptedSink::new(true);
        let stats = Arc::new(RelayStats::default());
        let egress = RelayEgress::new(
            Arc::clone(&locators),
            Arc::clone(&sink) as Arc<dyn RelaySink>,
            Arc::clone(&stats),
        );

        egress.send(b"first", address).expect("still registered");
        locators.release(&peer(0x02));

        egress
            .send(b"second", address)
            .expect_err("a departed peer is not a destination");
        assert_eq!(
            sink.offered.lock().unwrap().len(),
            1,
            "only the datagram sent while the peer was registered"
        );
    }
}

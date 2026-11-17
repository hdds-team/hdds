// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The queue between the threads that send and the session that forwards.
//!
//! `transport` diverts a datagram addressed to a synthetic locator into a
//! [`RelaySink`]; the Discovery Server session thread is what actually writes
//! it. They are different threads, and the sending one is a DDS writer
//! delivering a sample - it must not wait for a TCP socket. So the sink is a
//! bounded queue plus a nudge: the datagram is copied in, the session thread
//! is woken, and the writer carries on.
//!
//! This module is also where the two layers meet without depending on each
//! other: `transport` declares the trait, `discovery_server` provides the
//! waker, and neither names the other.

use crate::discovery_server::SessionWaker;
use crate::transport::relay::{RelayPendingDiagnostics, RelaySink};
use crossbeam::queue::ArrayQueue;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

/// The RTPS GUID prefix of a participant, 12 bytes per RTPS v2.5 s8.2.4.2.
type GuidPrefix = [u8; 12];

/// Datagrams the queue holds before the session thread gets to them.
///
/// At the ceiling below this is at most 4 MiB of payload held between the
/// two threads. It is deliberately larger than the session's own outbox can
/// take at once: a burst that outruns the WAN link should pile up here,
/// where refusing is cheap and counted, rather than at the socket.
const QUEUE_CAPACITY: usize = 64;

/// The largest datagram the relay will carry.
///
/// A UDP payload cannot exceed this, so nothing the transport hands us is
/// larger. Checking it anyway is what turns [`MAX_RELAY_FRAME_BYTES`] from an
/// assumption into a fact.
const MAX_RELAYED_DATAGRAM: usize = 65_507;

/// The largest frame one relayed datagram can turn into.
///
/// Base64 of [`MAX_RELAYED_DATAGRAM`] bytes is `ceil(65507 / 3) * 4` = 87 344,
/// plus the JSON envelope (a type tag, a 24-character destination, quotes and
/// braces) and the 4-byte length prefix. 96 KiB covers that with room to
/// spare, and the session uses it to decide whether to take a datagram off
/// the queue AT ALL: popping one the outbox cannot then hold would drop it
/// halfway down, where nothing counts it and nothing can put it back.
pub(in crate::dds::participant) const MAX_RELAY_FRAME_BYTES: usize = 96 * 1024;

/// One datagram waiting for the session thread.
pub(in crate::dds::participant) struct Relayed {
    /// Who the server must forward it to.
    pub peer: GuidPrefix,
    /// The datagram itself, exactly as the transport would have sent it.
    pub datagram: Vec<u8>,
}

/// The sink the transport hands relayed datagrams to.
pub(in crate::dds::participant) struct RelayChannel {
    queue: ArrayQueue<Relayed>,
    waker: SessionWaker,
    /// Datagrams the queue had no room for.
    refused: AtomicU64,
    /// Datagrams larger than a UDP payload can be.
    oversized: AtomicU64,
    /// Whether a failed wake has already been reported.
    wake_failed: AtomicBool,
    /// The first oversized datagram's length, waiting to be logged by a
    /// caller that is not blocked itself (`offer` runs under the
    /// periodic HEARTBEAT path's send gate too, where logging is not
    /// allowed -- see `take_pending_diagnostics`). `None` once taken;
    /// later oversized datagrams are still counted by `oversized`, just
    /// never logged again, same as before this split.
    pending_oversized_len: Mutex<Option<usize>>,
    /// Set alongside `wake_failed` on the first failed wake, cleared by
    /// `take_pending_diagnostics` once its caller has logged it.
    wake_failed_pending: AtomicBool,
}

impl RelayChannel {
    /// A channel that nudges `waker` whenever it takes a datagram.
    pub(in crate::dds::participant) fn new(waker: SessionWaker) -> Self {
        Self {
            queue: ArrayQueue::new(QUEUE_CAPACITY),
            waker,
            refused: AtomicU64::new(0),
            oversized: AtomicU64::new(0),
            wake_failed: AtomicBool::new(false),
            pending_oversized_len: Mutex::new(None),
            wake_failed_pending: AtomicBool::new(false),
        }
    }

    /// Take the oldest waiting datagram, if there is one.
    pub(in crate::dds::participant) fn pop(&self) -> Option<Relayed> {
        self.queue.pop()
    }

    /// Datagrams lost because the session thread was too far behind.
    pub(in crate::dds::participant) fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Datagrams refused for being larger than a UDP payload can be.
    pub(in crate::dds::participant) fn oversized(&self) -> u64 {
        self.oversized.load(Ordering::Relaxed)
    }
}

impl RelaySink for RelayChannel {
    fn offer(&self, peer: GuidPrefix, datagram: &[u8]) -> bool {
        if datagram.len() > MAX_RELAYED_DATAGRAM {
            // Unreachable through a UDP socket, which is exactly why it is
            // worth saying out loud: reaching it means something upstream
            // built a datagram no network could have carried. Never
            // logged HERE: `offer` runs under the periodic HEARTBEAT
            // path's send gate too (see `take_pending_diagnostics`),
            // where a synchronous logging call is exactly the kind of
            // wait that gate must never be able to make.
            let total = self.oversized.fetch_add(1, Ordering::Relaxed) + 1;
            if total == 1 {
                *self
                    .pending_oversized_len
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(datagram.len());
            }
            return false;
        }

        let queued = Relayed {
            peer,
            datagram: datagram.to_vec(),
        };
        if self.queue.push(queued).is_err() {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        if self.waker.wake().is_err() && !self.wake_failed.swap(true, Ordering::Relaxed) {
            // The datagram IS queued; only the nudge failed, and the session
            // thread's own poll timeout will still find it. Worth one line,
            // because a broken registry means every relayed datagram from now
            // on waits for a timeout it should not have needed -- logged by
            // `take_pending_diagnostics`'s caller, never here.
            self.wake_failed_pending.store(true, Ordering::Relaxed);
        }
        true
    }

    fn take_pending_diagnostics(&self) -> RelayPendingDiagnostics {
        RelayPendingDiagnostics {
            oversized_len: self
                .pending_oversized_len
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(),
            wake_failed: self.wake_failed_pending.swap(false, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery_server::{DiscoveryServerClient, DiscoveryServerConfig};
    use std::time::{Duration, Instant};

    fn peer(tag: u8) -> GuidPrefix {
        [tag; 12]
    }

    /// A client that never connects: all this needs is its readiness registry.
    fn idle_client() -> DiscoveryServerClient {
        DiscoveryServerClient::new(DiscoveryServerConfig::default(), [1; 12]).expect("client")
    }

    #[test]
    fn a_datagram_is_queued_whole_and_wakes_the_session() {
        let mut client = idle_client();
        let channel = RelayChannel::new(client.waker());

        assert!(channel.offer(peer(0xAB), b"RTPS\x02\x05\x01\x1a"));

        // The nudge is the point: without it the session sleeps out its whole
        // poll timeout before it discovers the datagram.
        let start = Instant::now();
        client.wait_for_io(Duration::from_secs(5)).expect("poll");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "offering must wake the session thread"
        );

        let taken = channel.pop().expect("one datagram was offered");
        assert_eq!(taken.peer, peer(0xAB), "addressed by GUID prefix");
        assert_eq!(taken.datagram, b"RTPS\x02\x05\x01\x1a", "not altered");
        assert!(channel.pop().is_none(), "and only one");
    }

    #[test]
    fn datagrams_come_back_out_in_the_order_they_went_in() {
        let client = idle_client();
        let channel = RelayChannel::new(client.waker());

        for tag in 0..8u8 {
            assert!(channel.offer(peer(tag), &[tag; 16]));
        }
        for tag in 0..8u8 {
            let taken = channel.pop().expect("eight were offered");
            assert_eq!(
                taken.peer,
                peer(tag),
                "RTPS ordering is not ours to shuffle"
            );
        }
    }

    #[test]
    fn a_full_queue_refuses_and_counts_rather_than_growing() {
        let client = idle_client();
        let channel = RelayChannel::new(client.waker());

        for _ in 0..QUEUE_CAPACITY {
            assert!(channel.offer(peer(1), b"payload"), "there was room");
        }
        assert!(
            !channel.offer(peer(1), b"payload"),
            "a full queue must refuse, not grow"
        );

        assert_eq!(channel.refused(), 1, "the loss is visible in the count");
        // A refusal is a lost packet, which RTPS reliability is there to
        // notice; what must never happen is the queue absorbing it silently.
        for _ in 0..9 {
            assert!(!channel.offer(peer(1), b"payload"));
        }
        assert_eq!(channel.refused(), 10);
    }

    #[test]
    fn a_datagram_no_network_could_carry_is_refused() {
        let client = idle_client();
        let channel = RelayChannel::new(client.waker());

        assert!(
            !channel.offer(peer(2), &vec![0u8; MAX_RELAYED_DATAGRAM + 1]),
            "nothing larger than a UDP payload may enter the queue"
        );
        assert_eq!(channel.oversized(), 1);
        assert!(channel.pop().is_none(), "and nothing was queued");

        // The ceiling itself is accepted, because that is what makes
        // MAX_RELAY_FRAME_BYTES a fact about every datagram that can be here.
        assert!(channel.offer(peer(2), &vec![0u8; MAX_RELAYED_DATAGRAM]));
    }
}

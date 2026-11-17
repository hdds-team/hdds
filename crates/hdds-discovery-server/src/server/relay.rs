// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Fan-out and relay of discovery messages to connected clients.
//!
//! Every message the server pushes to a client (a discovery broadcast, or a
//! relayed DATA when relay mode is enabled) goes through this router. It owns
//! one bounded queue per connected client, keyed by GUID prefix.
//!
//! # The rule this module exists to enforce
//!
//! **Nothing is ever sent while the router's lock is held.** A send can block
//! for as long as the slowest client takes to drain its queue, and a client
//! that stopped reading its socket never drains it at all. Holding the lock
//! across such a send stops every other participant from registering: the
//! whole server's discovery freezes because of one unrelated peer.
//!
//! That is why [`RelayRouter::broadcast_to`] and [`RelayRouter::relay_data`]
//! take the shared `Arc<RwLock<..>>` instead of `&self`. They acquire the
//! guard themselves, copy out the queue handles, drop the guard, and only
//! then deliver. A caller cannot hold the lock across a send because it never
//! holds the lock at all.
//!
//! Delivery uses `try_send`, never `send`. A client whose bounded queue is
//! full is behind beyond recovery, so it is evicted rather than waited for:
//! on reconnect the server replays the full participant and endpoint list for
//! its domain (`server.rs`, `ParticipantAnnounce` handling), so an eviction
//! costs a reconnect, while a silent drop would cost that client a permanently
//! incomplete view of the domain with nothing to signal it.

use super::protocol::DiscoveryMessage;
use super::registry::GuidPrefix;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Notify, RwLock};

/// Relay statistics, as read by an observer.
#[derive(Debug, Default, Clone)]
pub struct RelayStats {
    /// Total messages relayed.
    pub messages_relayed: u64,
    /// Total bytes relayed.
    pub bytes_relayed: u64,
    /// Relay errors (destination not found, cross-domain, evicted client).
    pub relay_errors: u64,
}

/// The live counters behind [`RelayStats`].
///
/// Atomic on purpose: reporting a delivered message must never need the
/// router's WRITE guard. Taking a write guard on the data path is what made a
/// single slow client able to freeze the server.
#[derive(Debug, Default)]
struct LiveStats {
    messages_relayed: AtomicU64,
    bytes_relayed: AtomicU64,
    relay_errors: AtomicU64,
}

impl LiveStats {
    fn snapshot(&self) -> RelayStats {
        RelayStats {
            messages_relayed: self.messages_relayed.load(Ordering::Relaxed),
            bytes_relayed: self.bytes_relayed.load(Ordering::Relaxed),
            relay_errors: self.relay_errors.load(Ordering::Relaxed),
        }
    }
}

/// What a fan-out actually achieved.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Delivery {
    /// Recipients the message was handed to.
    pub delivered: usize,
    /// Recipients dropped from the router because their queue was full or
    /// closed. Each one has been SIGNALLED to terminate ([`ClientLink`]);
    /// its task then takes the ordinary disconnect path, which unregisters
    /// it, removes it from the participant registry and broadcasts its
    /// departure. They resynchronise fully when they reconnect.
    pub evicted: Vec<GuidPrefix>,
}

/// Client connections indexed by GUID prefix for fan-out and relay routing.
pub struct RelayRouter {
    /// Connected clients by GUID prefix.
    connections: HashMap<GuidPrefix, ClientConnectionHandle>,
    /// Statistics.
    stats: LiveStats,
}

/// Everything the router needs to reach a client connection, and to END it.
///
/// The two travel together on purpose. A router that can queue to a client
/// but cannot terminate it can only produce a DEAF client: dropping the
/// router's handle does not close the channel, because the connection task
/// holds its own `Sender`, so the task keeps reading, keeps answering
/// heartbeats and keeps its entry in the participant registry while
/// receiving nothing ever again. The whole fleet then believes it is alive
/// and reachable. Making the link inseparable is what stops that being
/// expressible.
#[derive(Clone)]
pub struct ClientLink {
    /// Bounded outbound queue drained by the connection task.
    pub tx: Sender<DiscoveryMessage>,
    /// Notified when the router gives up on this client. The connection task
    /// selects on it and leaves its loop, so an eviction takes exactly the
    /// SAME teardown path as a disconnect - one teardown, not two.
    pub evicted: Arc<Notify>,
}

/// Handle to a client connection.
struct ClientConnectionHandle {
    /// How to reach this client, and how to end it.
    link: ClientLink,
    /// The domain this client registered for.
    ///
    /// Held here so that the relay cannot cross domains. The rest of the
    /// server partitions everything by domain
    /// (`registry::participant_guids_in_domain`), and a relay that ignored it
    /// would let a client in domain 0 hand arbitrary bytes to a participant in
    /// domain 42 - an isolation break nothing downstream could detect.
    domain_id: u32,
}

impl RelayRouter {
    /// Create a new relay router.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            stats: LiveStats::default(),
        }
    }

    /// Register a client connection, in the domain it registered for.
    pub fn register(&mut self, guid_prefix: GuidPrefix, domain_id: u32, link: ClientLink) {
        self.connections
            .insert(guid_prefix, ClientConnectionHandle { link, domain_id });
    }

    /// Unregister a client connection.
    pub fn unregister(&mut self, guid_prefix: &GuidPrefix) {
        self.connections.remove(guid_prefix);
    }

    /// Queue handles for the recipients that are currently connected.
    ///
    /// Cloning a `Sender` is cheap and keeps the channel alive independently
    /// of the router, which is what lets the caller drop the guard before
    /// sending anything.
    fn handles_for(
        &self,
        recipients: &[GuidPrefix],
    ) -> Vec<(GuidPrefix, Sender<DiscoveryMessage>)> {
        recipients
            .iter()
            .filter_map(|gp| {
                self.connections
                    .get(gp)
                    .map(|handle| (*gp, handle.link.tx.clone()))
            })
            .collect()
    }

    /// Drop the clients that could not be delivered to, and count them.
    async fn evict(router: &Arc<RwLock<Self>>, evicted: &[GuidPrefix]) {
        if evicted.is_empty() {
            return;
        }
        let mut guard = router.write().await;
        for guid_prefix in evicted {
            // Signal BEFORE dropping the handle: the notify lives in the
            // handle, and a client removed without being told would stay
            // connected, registered and deaf.
            if let Some(handle) = guard.connections.remove(guid_prefix) {
                handle.link.evicted.notify_one();
            }
            tracing::warn!(
                "[relay] evicted {:?}: its outbound queue was full or closed. Its \
                 connection is being terminated, so it unregisters and its departure \
                 is broadcast; it resynchronises fully on reconnect. Waiting for it \
                 would have stalled every other participant.",
                guid_prefix
            );
        }
        guard
            .stats
            .relay_errors
            .fetch_add(evicted.len() as u64, Ordering::Relaxed);
    }

    /// Send a discovery message to a specific set of connected participants.
    ///
    /// Takes the shared router rather than `&self` so the read guard is
    /// released before any delivery - see the module header.
    pub async fn broadcast_to(
        router: &Arc<RwLock<Self>>,
        msg: &DiscoveryMessage,
        recipients: &[GuidPrefix],
    ) -> Delivery {
        let handles = {
            let guard = router.read().await;
            guard.handles_for(recipients)
        };

        let mut outcome = Delivery::default();
        for (guid_prefix, tx) in handles {
            if tx.try_send(msg.clone()).is_ok() {
                outcome.delivered += 1;
            } else {
                outcome.evicted.push(guid_prefix);
            }
        }

        Self::evict(router, &outcome.evicted).await;
        outcome
    }

    /// Relay a DATA message to the destination.
    ///
    /// Returns `Ok(true)` if the message was handed to the destination,
    /// `Ok(false)` if the destination is not connected.
    pub async fn relay_data(
        router: &Arc<RwLock<Self>>,
        destination: GuidPrefix,
        payload: Vec<u8>,
        source: GuidPrefix,
    ) -> Result<bool, RelayError> {
        let payload_len = payload.len() as u64;

        // Resolve the destination and check it under ONE short read guard.
        let resolved = {
            let guard = router.read().await;
            let Some(target) = guard.connections.get(&destination) else {
                guard.stats.relay_errors.fetch_add(1, Ordering::Relaxed);
                return Ok(false);
            };

            // A client relaying to itself would hand a message to the very
            // queue its own task is failing to drain.
            if source == destination {
                guard.stats.relay_errors.fetch_add(1, Ordering::Relaxed);
                return Err(RelayError::InvalidDestination);
            }

            // Domain isolation, enforced here because this is the one door
            // every relayed byte goes through.
            let Some(origin) = guard.connections.get(&source) else {
                guard.stats.relay_errors.fetch_add(1, Ordering::Relaxed);
                return Err(RelayError::InvalidDestination);
            };
            if origin.domain_id != target.domain_id {
                guard.stats.relay_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    "[relay] refused a relay from {:?} (domain {}) to {:?} (domain {}): \
                     the relay does not cross domains.",
                    source,
                    origin.domain_id,
                    destination,
                    target.domain_id
                );
                return Err(RelayError::CrossDomain);
            }

            target.link.tx.clone()
        };

        // Guard released: deliver.
        let msg = DiscoveryMessage::Data {
            destination: destination.into(),
            payload,
        };
        match resolved.try_send(msg) {
            Ok(()) => {
                let router_guard = router.read().await;
                router_guard
                    .stats
                    .messages_relayed
                    .fetch_add(1, Ordering::Relaxed);
                router_guard
                    .stats
                    .bytes_relayed
                    .fetch_add(payload_len, Ordering::Relaxed);
                Ok(true)
            }
            Err(_) => {
                Self::evict(router, &[destination]).await;
                Err(RelayError::SendFailed)
            }
        }
    }

    /// Get a snapshot of the relay statistics.
    pub fn stats(&self) -> RelayStats {
        self.stats.snapshot()
    }

    /// Get number of connected clients.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if a participant is connected.
    #[cfg(test)]
    fn is_connected(&self, guid_prefix: &GuidPrefix) -> bool {
        self.connections.contains_key(guid_prefix)
    }
}

impl Default for RelayRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Relay error types.
#[derive(Debug)]
#[allow(dead_code)]
pub enum RelayError {
    /// Failed to send message to destination.
    SendFailed,
    /// Destination not found.
    DestinationNotFound,
    /// Invalid destination GUID, or a client relaying to itself.
    InvalidDestination,
    /// Source and destination are registered in different DDS domains.
    ///
    /// Refused rather than delivered: the rest of the server partitions
    /// every announcement by domain, and a relay that crossed domains would
    /// be an isolation break nothing downstream could detect.
    CrossDomain,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendFailed => write!(f, "Failed to send message"),
            Self::DestinationNotFound => write!(f, "Destination not found"),
            Self::InvalidDestination => write!(f, "Invalid destination GUID"),
            Self::CrossDomain => write!(
                f,
                "Relay refused: source and destination are in different domains"
            ),
        }
    }
}

impl std::error::Error for RelayError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc;

    fn shared() -> Arc<RwLock<RelayRouter>> {
        Arc::new(RwLock::new(RelayRouter::new()))
    }

    /// A link as the connection task builds one: a bounded queue plus the
    /// signal that ends the connection. Returns the receiving end and the
    /// signal, so a test can assert on BOTH what the client received and
    /// whether its connection was told to close.
    fn link(capacity: usize) -> (ClientLink, mpsc::Receiver<DiscoveryMessage>, Arc<Notify>) {
        let (tx, rx) = mpsc::channel(capacity);
        let evicted = Arc::new(Notify::new());
        (
            ClientLink {
                tx,
                evicted: Arc::clone(&evicted),
            },
            rx,
            evicted,
        )
    }

    fn ping(guid_prefix: GuidPrefix) -> DiscoveryMessage {
        DiscoveryMessage::Heartbeat {
            guid_prefix: guid_prefix.into(),
        }
    }

    #[tokio::test]
    async fn test_relay_router_new() {
        let router = RelayRouter::new();
        assert_eq!(router.connection_count(), 0);
        assert_eq!(router.stats().messages_relayed, 0);
    }

    #[tokio::test]
    async fn test_register_unregister() {
        let mut router = RelayRouter::new();
        let guid = [1u8; 12];
        let (link, _rx, _evicted) = link(10);

        router.register(guid, 0, link);
        assert!(router.is_connected(&guid));
        assert_eq!(router.connection_count(), 1);

        router.unregister(&guid);
        assert!(!router.is_connected(&guid));
        assert_eq!(router.connection_count(), 0);
    }

    #[tokio::test]
    async fn test_relay_data_destination_not_found() {
        let router = shared();
        let dest = [1u8; 12];
        let source = [2u8; 12];

        let result = RelayRouter::relay_data(&router, dest, vec![1, 2, 3], source).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Not relayed
        assert_eq!(router.read().await.stats().relay_errors, 1);
    }

    #[tokio::test]
    async fn test_relay_data_success() {
        let router = shared();
        let dest = [1u8; 12];
        let source = [2u8; 12];
        let (dest_link, mut rx, _dest_evicted) = link(10);
        let (src_link, _src_rx, _src_evicted) = link(10);

        router.write().await.register(dest, 0, dest_link);
        router.write().await.register(source, 0, src_link);

        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let result = RelayRouter::relay_data(&router, dest, payload.clone(), source).await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Relayed successfully

        // Verify message received
        let msg = rx.recv().await.unwrap();
        match msg {
            DiscoveryMessage::Data {
                destination: _,
                payload: p,
            } => {
                assert_eq!(p, payload);
            }
            _ => panic!("Wrong message type"),
        }

        let stats = router.read().await.stats();
        assert_eq!(stats.messages_relayed, 1);
        assert_eq!(stats.bytes_relayed, 4);
    }

    /// DS-4: the relay must not cross DDS domains.
    ///
    /// Everything else in the server partitions announcements by domain. A
    /// relay that ignored it would let a client in one domain hand arbitrary
    /// bytes to a participant in another, which nothing downstream could
    /// detect - the fleet's domain table rests on this boundary.
    #[tokio::test]
    async fn relay_refuses_to_cross_domains() {
        let router = shared();
        let source = [0x11; 12];
        let dest = [0x22; 12];
        let (src_link, _src_rx, _src_evicted) = link(10);
        let (dst_link, mut dst_rx, _dst_evicted) = link(10);

        router.write().await.register(source, 0, src_link);
        router.write().await.register(dest, 42, dst_link);

        let result = RelayRouter::relay_data(&router, dest, vec![9; 8], source).await;

        assert!(
            matches!(result, Err(RelayError::CrossDomain)),
            "a relay from domain 0 to domain 42 must be refused, got {result:?}"
        );
        assert!(
            dst_rx.try_recv().is_err(),
            "nothing may reach a participant in another domain"
        );
        assert_eq!(router.read().await.stats().messages_relayed, 0);
    }

    /// A client relaying to itself would hand a message to the very queue its
    /// own task is failing to drain.
    #[tokio::test]
    async fn relay_refuses_a_client_relaying_to_itself() {
        let router = shared();
        let guid = [0x33; 12];
        let (guid_link, _rx, _evicted) = link(10);
        router.write().await.register(guid, 0, guid_link);

        let result = RelayRouter::relay_data(&router, guid, vec![1, 2, 3], guid).await;

        assert!(
            matches!(result, Err(RelayError::InvalidDestination)),
            "a self-relay must be refused, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_broadcast_to() {
        let router = shared();
        let guid1 = [1u8; 12];
        let guid2 = [2u8; 12];
        let guid3 = [3u8; 12];

        let (link1, mut rx1, _ev1) = link(10);
        let (link2, mut rx2, _ev2) = link(10);
        let (link3, mut rx3, _ev3) = link(10);

        {
            let mut guard = router.write().await;
            guard.register(guid1, 0, link1);
            guard.register(guid2, 0, link2);
            guard.register(guid3, 0, link3);
        }

        // Broadcast only to guid2 and guid3
        let outcome = RelayRouter::broadcast_to(&router, &ping(guid1), &[guid2, guid3]).await;
        assert_eq!(outcome.delivered, 2); // guid2 and guid3
        assert!(outcome.evicted.is_empty());

        // Verify guid1 didn't receive
        assert!(rx1.try_recv().is_err());

        // guid2 and guid3 should have received
        assert!(rx2.try_recv().is_ok());
        assert!(rx3.try_recv().is_ok());
    }

    #[tokio::test]
    async fn test_relay_stats() {
        let router = shared();
        let dest = [1u8; 12];
        let source = [2u8; 12];
        let (dest_link, _rx, _dest_evicted) = link(10);
        let (src_link, _src_rx, _src_evicted) = link(10);

        router.write().await.register(dest, 0, dest_link);
        router.write().await.register(source, 0, src_link);

        // Relay several messages
        for i in 0..5 {
            let payload = vec![i as u8; 100];
            RelayRouter::relay_data(&router, dest, payload, source)
                .await
                .unwrap();
        }

        let stats = router.read().await.stats();
        assert_eq!(stats.messages_relayed, 5);
        assert_eq!(stats.bytes_relayed, 500);
    }

    /// A broadcast to ONE saturated client must not stop every other
    /// participant from registering.
    ///
    /// If `broadcast_to` took `&self`, its caller would hold the router's READ
    /// guard for the whole call and, inside it, await `tx.send(..)` on a
    /// bounded channel. A client that stopped reading its socket leaves its
    /// task parked in `write_all` (no write timeout), its queue fills, and the
    /// send parks too - still holding the read guard. The next registration
    /// wants the WRITE guard, and tokio's RwLock is fair, so every later
    /// reader queues behind it as well: the whole server's discovery stops
    /// because of one unrelated slow peer. This test times out on such a
    /// design.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_saturated_client_must_not_block_other_registrations() {
        let router = shared();
        let slow = [0xdd; 12];

        // The slow client: a one-slot queue nobody ever drains. `_rx` is kept
        // alive on purpose - dropping it would close the channel and make the
        // send fail fast, which is the opposite of the situation under test.
        let (slow_link, _rx, _slow_evicted) = link(1);
        router.write().await.register(slow, 0, slow_link);

        // First broadcast takes the only free slot.
        let first = RelayRouter::broadcast_to(&router, &ping(slow), &[slow]).await;
        assert_eq!(first.delivered, 1);

        // Second broadcast finds the queue full. It must not park: the client
        // is evicted and everyone else carries on.
        let second = tokio::time::timeout(
            Duration::from_secs(2),
            RelayRouter::broadcast_to(&router, &ping(slow), &[slow]),
        )
        .await
        .expect("a broadcast to a saturated client must not park");

        assert_eq!(second.delivered, 0);
        assert_eq!(second.evicted, vec![slow]);

        // A brand new participant registers. It shares nothing with the slow
        // client but the router itself.
        let registration = tokio::time::timeout(Duration::from_secs(2), router.write()).await;

        assert!(
            registration.is_ok(),
            "a registration could not acquire the router while a broadcast to one \
             saturated client was in flight: the server's discovery is frozen by a \
             single slow peer"
        );

        // The saturated client is gone, so the next fan-out reaches nobody
        // rather than stalling again.
        assert!(!registration.unwrap().is_connected(&slow));
    }

    #[tokio::test]
    async fn an_evicted_client_is_told_to_close_its_connection() {
        // Dropping the router's handle does NOT close the channel: the
        // connection task holds its own `Sender`. Without an explicit signal
        // the evicted client keeps reading, keeps answering heartbeats and
        // keeps its entry in the participant registry, while receiving
        // nothing ever again - and the rest of the fleet still believes it
        // alive and reachable, because the departure broadcast only happens
        // on the task's disconnect path.
        let router = shared();
        let slow = [9u8; 12];
        let (slow_link, _rx, evicted) = link(1);
        router.write().await.register(slow, 0, slow_link);

        assert_eq!(
            RelayRouter::broadcast_to(&router, &ping(slow), &[slow])
                .await
                .delivered,
            1,
            "the one free slot must be taken first"
        );
        assert_eq!(
            RelayRouter::broadcast_to(&router, &ping(slow), &[slow])
                .await
                .evicted,
            vec![slow]
        );

        // `notify_one` stores a permit, so this completes even though the
        // connection task was not awaiting at the moment of eviction - which
        // is the realistic case: it was busy writing to a slow socket.
        tokio::time::timeout(Duration::from_secs(2), evicted.notified())
            .await
            .expect(
                "an evicted client was never told to close: its task will keep running, \
                 deaf and still registered",
            );
        assert!(!router.read().await.is_connected(&slow));
    }
}

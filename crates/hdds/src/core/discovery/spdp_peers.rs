// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Shared SPDP unicast destinations.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

type GuidPrefix = [u8; 12];

/// A discovered peer's locator set and lease expiry.
struct DiscoveredPeer {
    locators: HashSet<SocketAddr>,
    deadline: Instant,
}

#[derive(Default)]
struct PeerState {
    static_peers: HashSet<SocketAddr>,
    server_peers: HashMap<GuidPrefix, HashSet<SocketAddr>>,
    discovered_peers: HashMap<GuidPrefix, DiscoveredPeer>,
    cloud_peers: HashMap<GuidPrefix, DiscoveredPeer>,
    generation: u64,
}

/// Distinct-locator counts per peer origin, for configuration dumps.
pub(crate) struct PeerCounts {
    pub static_peers: usize,
    pub server_peers: usize,
    pub discovered_peers: usize,
    pub cloud_peers: usize,
}

/// A peer origin that can be cleared as a unit.
///
/// Static peers are deliberately absent: they are configuration, not a
/// runtime source that reconnects or stops, so nothing ever clears them.
/// Peers discovered over SPDP expire per entry through their lease and
/// have no bulk clear either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerOrigin {
    /// Discovery Server locators (`replace_server`/`remove_server`).
    Server,
    /// Peers learned from a cloud registry poller (`sync_cloud`).
    #[cfg_attr(not(feature = "cloud-discovery"), allow(dead_code))]
    Cloud,
}

/// A locator the IPv4 UDP transport can actually send to.
///
/// IPv6 addresses are rejected here, not at send time: the transport binds
/// IPv4 sockets, so an IPv6 rendezvous peer would silently fail on every
/// unicast SPDP. Shared by every runtime peer source (Discovery Server,
/// cloud registries) so they cannot disagree on what is routable.
pub(crate) fn usable_unicast_locator(locator: &SocketAddr) -> bool {
    matches!(locator, SocketAddr::V4(v4)
        if v4.port() != 0 && !v4.ip().is_unspecified() && !v4.ip().is_multicast())
}

/// Runtime-mutable SPDP unicast destinations.
///
/// Peers come from four separate origins, tracked independently so a
/// change or expiry in one origin can never remove an unrelated peer that
/// happens to use the same locator:
/// - static destinations (`add_static`), which never expire;
/// - Discovery Server destinations (`replace_server`/`remove_server`/
///   `clear(PeerOrigin::Server)`), keyed by remote GUID prefix, which never
///   expire;
/// - discovered destinations (`refresh_discovered`/`remove_discovered`),
///   keyed by remote GUID prefix, each with a lease deadline;
/// - cloud registry destinations (`sync_cloud`/`remove_cloud`), keyed by
///   remote GUID prefix, each with a lease deadline so a poller that stalls
///   or dies cannot pin a vanished peer forever.
///
/// An entry whose lease deadline has passed is treated as absent: it is
/// excluded from `snapshot()` and `counts()`, and dropped from the map at
/// that point (pruning does not bump `generation` and does not notify
/// waiters, since it is a passive consequence of time passing rather than
/// a peer-set change to react to).
#[derive(Default)]
pub(crate) struct SpdpPeerSet {
    state: Mutex<PeerState>,
    changed: Condvar,
}

impl SpdpPeerSet {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn add_static(&self, locator: SocketAddr) -> bool {
        let mut state = self.lock();
        let inserted = state.static_peers.insert(locator);
        if inserted {
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        inserted
    }

    pub(crate) fn replace_server(
        &self,
        guid_prefix: GuidPrefix,
        locators: impl IntoIterator<Item = SocketAddr>,
    ) -> bool {
        let replacement: HashSet<_> = locators.into_iter().collect();
        let mut state = self.lock();
        let changed = state.server_peers.get(&guid_prefix) != Some(&replacement);

        if changed {
            if replacement.is_empty() {
                state.server_peers.remove(&guid_prefix);
            } else {
                state.server_peers.insert(guid_prefix, replacement);
            }
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        changed
    }

    pub(crate) fn remove_server(&self, guid_prefix: &GuidPrefix) -> bool {
        let mut state = self.lock();
        let removed = state.server_peers.remove(guid_prefix).is_some();
        if removed {
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        removed
    }

    /// Forget every peer of one origin. Static peers are never touched.
    ///
    /// A Discovery Server reconnect clears `Server` and must not wipe a
    /// cloud registry's peers (or the reverse); a stopped cloud poller clears
    /// `Cloud` only.
    pub(crate) fn clear(&self, origin: PeerOrigin) -> bool {
        let mut state = self.lock();
        let changed = match origin {
            PeerOrigin::Server => {
                let changed = !state.server_peers.is_empty();
                state.server_peers.clear();
                changed
            }
            PeerOrigin::Cloud => {
                let changed = !state.cloud_peers.is_empty();
                state.cloud_peers.clear();
                changed
            }
        };
        if changed {
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        changed
    }

    /// Record or refresh a discovered peer's locator set with a lease.
    ///
    /// Returns `true` and bumps `generation` (waking waiters) only when the
    /// locator SET for this prefix actually changed: a new prefix, or a
    /// different set of locators for an existing prefix. Refreshing with an
    /// identical set only extends the deadline and leaves `generation`
    /// untouched, since this is called on every received SPDP announcement
    /// and must not wake the announcer on every packet. An empty locator set
    /// means "remove" and behaves like `remove_discovered`.
    pub(crate) fn refresh_discovered(
        &self,
        guid_prefix: GuidPrefix,
        locators: impl IntoIterator<Item = SocketAddr>,
        lease: Duration,
    ) -> bool {
        let incoming: HashSet<_> = locators.into_iter().collect();
        let deadline = Instant::now() + lease;
        let mut state = self.lock();
        let changed =
            Self::refresh_leased(&mut state.discovered_peers, guid_prefix, incoming, deadline);
        if changed {
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        changed
    }

    /// Replace the cloud origin with the registry's current view.
    ///
    /// `peers` is the full set a successful registry poll returned (the
    /// caller has already dropped its own prefix and foreign domains). Every
    /// listed prefix is refreshed with `lease` under the same rules as
    /// `refresh_discovered` (identical set = deadline only, no wake); every
    /// cloud peer NOT listed is removed. Callers must not call this on a
    /// failed poll: a registry that answers with an error has said nothing
    /// about who is gone, and the lease bounds how long a stale entry can
    /// survive a silent registry anyway.
    ///
    /// Returns `true` when the cloud origin's locator sets changed.
    #[cfg_attr(not(feature = "cloud-discovery"), allow(dead_code))]
    pub(crate) fn sync_cloud(
        &self,
        peers: impl IntoIterator<Item = (GuidPrefix, HashSet<SocketAddr>)>,
        lease: Duration,
    ) -> bool {
        let deadline = Instant::now() + lease;
        let mut state = self.lock();
        let mut listed: HashSet<GuidPrefix> = HashSet::new();
        let mut changed = false;
        for (guid_prefix, locators) in peers {
            if !locators.is_empty() {
                listed.insert(guid_prefix);
            }
            changed |=
                Self::refresh_leased(&mut state.cloud_peers, guid_prefix, locators, deadline);
        }
        let before = state.cloud_peers.len();
        state
            .cloud_peers
            .retain(|prefix, _| listed.contains(prefix));
        changed |= state.cloud_peers.len() != before;
        if changed {
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        changed
    }

    #[cfg_attr(not(feature = "cloud-discovery"), allow(dead_code))]
    pub(crate) fn remove_cloud(&self, guid_prefix: &GuidPrefix) -> bool {
        let mut state = self.lock();
        let removed = state.cloud_peers.remove(guid_prefix).is_some();
        if removed {
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        removed
    }

    /// Insert, replace or refresh one leased entry. Returns `true` only when
    /// the locator SET for this prefix changed (new prefix, different set,
    /// or removal through an empty set); a refresh with an identical set
    /// only extends the deadline.
    fn refresh_leased(
        map: &mut HashMap<GuidPrefix, DiscoveredPeer>,
        guid_prefix: GuidPrefix,
        incoming: HashSet<SocketAddr>,
        deadline: Instant,
    ) -> bool {
        if incoming.is_empty() {
            return map.remove(&guid_prefix).is_some();
        }
        match map.get_mut(&guid_prefix) {
            Some(existing) if existing.locators == incoming => {
                existing.deadline = deadline;
                false
            }
            Some(existing) => {
                existing.locators = incoming;
                existing.deadline = deadline;
                true
            }
            None => {
                map.insert(
                    guid_prefix,
                    DiscoveredPeer {
                        locators: incoming,
                        deadline,
                    },
                );
                true
            }
        }
    }

    pub(crate) fn remove_discovered(&self, guid_prefix: &GuidPrefix) -> bool {
        let mut state = self.lock();
        let removed = state.discovered_peers.remove(guid_prefix).is_some();
        if removed {
            Self::mark_changed(&mut state);
            self.changed.notify_all();
        }
        removed
    }

    /// Drop discovered peers whose lease has expired.
    ///
    /// Pruning is a passive consequence of time passing, not a peer-set
    /// change to react to: it does not bump `generation` and does not
    /// notify waiters. Returns how many entries were dropped.
    #[allow(dead_code)] // Staged: wired into the announcer's periodic tick by a follow-up commit.
    pub(crate) fn prune_expired(&self) -> usize {
        let mut state = self.lock();
        Self::prune_expired_locked(&mut state)
    }

    fn prune_expired_locked(state: &mut PeerState) -> usize {
        let now = Instant::now();
        let before = state.discovered_peers.len() + state.cloud_peers.len();
        state.discovered_peers.retain(|_, peer| peer.deadline > now);
        state.cloud_peers.retain(|_, peer| peer.deadline > now);
        before - state.discovered_peers.len() - state.cloud_peers.len()
    }

    /// Distinct-locator counts per origin, for a configuration dump.
    /// Leased (discovered, cloud) locators are counted after pruning
    /// expired entries.
    pub(crate) fn counts(&self) -> PeerCounts {
        let mut state = self.lock();
        Self::prune_expired_locked(&mut state);

        let mut server_locators: HashSet<SocketAddr> = HashSet::new();
        for locators in state.server_peers.values() {
            server_locators.extend(locators);
        }
        let mut discovered_locators: HashSet<SocketAddr> = HashSet::new();
        for peer in state.discovered_peers.values() {
            discovered_locators.extend(&peer.locators);
        }
        let mut cloud_locators: HashSet<SocketAddr> = HashSet::new();
        for peer in state.cloud_peers.values() {
            cloud_locators.extend(&peer.locators);
        }

        PeerCounts {
            static_peers: state.static_peers.len(),
            server_peers: server_locators.len(),
            discovered_peers: discovered_locators.len(),
            cloud_peers: cloud_locators.len(),
        }
    }

    pub(crate) fn snapshot(&self) -> Vec<SocketAddr> {
        let mut state = self.lock();
        Self::prune_expired_locked(&mut state);

        let mut peers = state.static_peers.clone();
        for server_locators in state.server_peers.values() {
            peers.extend(server_locators);
        }
        for discovered in state.discovered_peers.values() {
            peers.extend(&discovered.locators);
        }
        for cloud in state.cloud_peers.values() {
            peers.extend(&cloud.locators);
        }
        let mut peers: Vec<_> = peers.into_iter().collect();
        peers.sort_unstable();
        peers
    }

    pub(crate) fn generation(&self) -> u64 {
        self.lock().generation
    }

    pub(crate) fn wait_for_change(
        &self,
        observed_generation: u64,
        timeout: Duration,
        shutdown: &AtomicBool,
    ) -> u64 {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();

        while state.generation == observed_generation && !shutdown.load(Ordering::Relaxed) {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            let wait_result = self.changed.wait_timeout(state, remaining);
            let (next_state, _) = match wait_result {
                Ok(result) => result,
                Err(poisoned) => poisoned.into_inner(),
            };
            state = next_state;
        }

        state.generation
    }

    /// Wake a waiter without changing the set (shutdown path).
    ///
    /// The notification is issued while holding the state mutex: a waiter
    /// evaluates `shutdown` under that mutex and enters the condvar wait
    /// atomically, so a wake issued outside the lock could slip between the
    /// check and the wait and be lost for a full announcement period.
    pub(crate) fn wake(&self) {
        let _state = self.lock();
        self.changed.notify_all();
    }

    fn lock(&self) -> MutexGuard<'_, PeerState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn mark_changed(state: &mut PeerState) {
        state.generation = state.generation.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn server_removal_preserves_static_locator() {
        let peers = SpdpPeerSet::new();
        let locator: SocketAddr = "127.0.0.1:7410".parse().unwrap();

        assert!(peers.add_static(locator));
        assert!(peers.replace_server([1; 12], [locator]));
        assert!(peers.remove_server(&[1; 12]));
        assert_eq!(peers.snapshot(), vec![locator]);
    }

    #[test]
    fn replacing_server_locator_removes_stale_address() {
        let peers = SpdpPeerSet::new();
        let old: SocketAddr = "192.0.2.1:7410".parse().unwrap();
        let new: SocketAddr = "192.0.2.2:7410".parse().unwrap();

        assert!(peers.replace_server([2; 12], [old]));
        assert!(peers.replace_server([2; 12], [new]));
        assert_eq!(peers.snapshot(), vec![new]);
    }

    #[test]
    fn shutdown_wake_is_not_lost() {
        // A waiter with a long timeout must return promptly once shutdown is
        // stored and wake() is called, whatever the interleaving.
        for _ in 0..50 {
            let peers = Arc::new(SpdpPeerSet::new());
            let generation = peers.generation();
            let shutdown = Arc::new(AtomicBool::new(false));
            let waiter_peers = Arc::clone(&peers);
            let waiter_shutdown = Arc::clone(&shutdown);
            let waiter = thread::spawn(move || {
                let started = Instant::now();
                waiter_peers.wait_for_change(
                    generation,
                    Duration::from_secs(30),
                    waiter_shutdown.as_ref(),
                );
                started.elapsed()
            });
            shutdown.store(true, Ordering::Relaxed);
            peers.wake();
            let waited = waiter.join().unwrap();
            assert!(
                waited < Duration::from_secs(5),
                "waiter blocked for {:?}",
                waited
            );
        }
    }

    #[test]
    fn mutation_wakes_waiter() {
        let peers = Arc::new(SpdpPeerSet::new());
        let generation = peers.generation();
        let waiter_peers = Arc::clone(&peers);
        let shutdown = Arc::new(AtomicBool::new(false));
        let waiter_shutdown = Arc::clone(&shutdown);

        let waiter = thread::spawn(move || {
            waiter_peers.wait_for_change(
                generation,
                Duration::from_secs(1),
                waiter_shutdown.as_ref(),
            )
        });
        thread::sleep(Duration::from_millis(20));
        peers.add_static("127.0.0.1:7410".parse().unwrap());

        assert_ne!(waiter.join().unwrap(), generation);
    }

    #[test]
    fn refresh_discovered_same_locators_is_noop_for_generation() {
        let peers = SpdpPeerSet::new();
        let locator: SocketAddr = "203.0.113.1:7410".parse().unwrap();

        assert!(peers.refresh_discovered([3; 12], [locator], Duration::from_secs(5)));
        let generation = peers.generation();
        assert!(!peers.refresh_discovered([3; 12], [locator], Duration::from_secs(5)));
        assert_eq!(peers.generation(), generation);
    }

    #[test]
    fn refresh_discovered_new_peer_wakes_waiter() {
        let peers = Arc::new(SpdpPeerSet::new());
        let generation = peers.generation();
        let waiter_peers = Arc::clone(&peers);
        let shutdown = Arc::new(AtomicBool::new(false));
        let waiter_shutdown = Arc::clone(&shutdown);

        let waiter = thread::spawn(move || {
            waiter_peers.wait_for_change(
                generation,
                Duration::from_secs(1),
                waiter_shutdown.as_ref(),
            )
        });
        thread::sleep(Duration::from_millis(20));
        let locator: SocketAddr = "203.0.113.2:7410".parse().unwrap();
        assert!(peers.refresh_discovered([4; 12], [locator], Duration::from_secs(5)));

        assert_ne!(waiter.join().unwrap(), generation);
    }

    #[test]
    fn discovered_peer_expires_after_lease() {
        let peers = SpdpPeerSet::new();
        let locator: SocketAddr = "198.51.100.1:7410".parse().unwrap();

        assert!(peers.refresh_discovered([9; 12], [locator], Duration::from_millis(30)));
        thread::sleep(Duration::from_millis(60));

        assert!(!peers.snapshot().contains(&locator));
        // snapshot() already pruned the expired entry, so nothing is left to prune.
        assert_eq!(peers.prune_expired(), 0);
    }

    #[test]
    fn remove_discovered_preserves_static_locator() {
        let peers = SpdpPeerSet::new();
        let locator: SocketAddr = "203.0.113.3:7410".parse().unwrap();

        assert!(peers.add_static(locator));
        assert!(peers.refresh_discovered([5; 12], [locator], Duration::from_secs(5)));
        assert!(peers.remove_discovered(&[5; 12]));
        assert_eq!(peers.snapshot(), vec![locator]);
    }

    #[test]
    fn refresh_discovered_empty_locators_removes_peer() {
        let peers = SpdpPeerSet::new();
        let locator: SocketAddr = "203.0.113.4:7410".parse().unwrap();

        assert!(peers.refresh_discovered([6; 12], [locator], Duration::from_secs(5)));
        assert!(peers.refresh_discovered([6; 12], [], Duration::from_secs(5)));
        assert!(peers.snapshot().is_empty());
    }

    #[test]
    fn counts_reflects_three_origins() {
        let peers = SpdpPeerSet::new();
        let static_locator: SocketAddr = "203.0.113.5:7410".parse().unwrap();
        let server_locator: SocketAddr = "203.0.113.6:7410".parse().unwrap();
        let discovered_locator: SocketAddr = "203.0.113.7:7410".parse().unwrap();

        assert!(peers.add_static(static_locator));
        assert!(peers.replace_server([7; 12], [server_locator]));
        assert!(peers.refresh_discovered([8; 12], [discovered_locator], Duration::from_secs(5)));

        let counts = peers.counts();
        assert_eq!(counts.static_peers, 1);
        assert_eq!(counts.server_peers, 1);
        assert_eq!(counts.discovered_peers, 1);
        assert_eq!(counts.cloud_peers, 0);
    }

    fn set(addrs: &[&str]) -> HashSet<SocketAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn cloud_origin_is_independent_of_server_and_static() {
        let peers = SpdpPeerSet::new();
        let shared: SocketAddr = "203.0.113.10:7410".parse().unwrap();
        let cloud_only: SocketAddr = "203.0.113.11:7410".parse().unwrap();

        assert!(peers.add_static(shared));
        assert!(peers.replace_server([1; 12], [shared]));
        assert!(peers.sync_cloud(
            [([2; 12], set(&["203.0.113.10:7410", "203.0.113.11:7410"]))],
            Duration::from_secs(5)
        ));
        assert_eq!(peers.counts().cloud_peers, 2);

        // A Discovery Server reconnect clears its own origin only.
        assert!(peers.clear(PeerOrigin::Server));
        assert_eq!(peers.snapshot(), vec![shared, cloud_only]);
        assert_eq!(peers.counts().cloud_peers, 2);

        // Clearing the cloud origin leaves the static locator in place.
        assert!(peers.clear(PeerOrigin::Cloud));
        assert!(!peers.clear(PeerOrigin::Cloud));
        assert_eq!(peers.snapshot(), vec![shared]);
    }

    #[test]
    fn sync_cloud_removes_absent_refreshes_present_and_reports_change() {
        let peers = SpdpPeerSet::new();
        let a: SocketAddr = "203.0.113.20:7410".parse().unwrap();
        let b: SocketAddr = "203.0.113.21:7410".parse().unwrap();
        let lease = Duration::from_secs(5);

        assert!(peers.sync_cloud(
            [
                ([1; 12], set(&["203.0.113.20:7410"])),
                ([2; 12], set(&["203.0.113.21:7410"]))
            ],
            lease
        ));
        assert_eq!(peers.snapshot(), vec![a, b]);
        let generation = peers.generation();

        // Same view again: deadlines refreshed, nothing changed, no wake.
        assert!(!peers.sync_cloud(
            [
                ([1; 12], set(&["203.0.113.20:7410"])),
                ([2; 12], set(&["203.0.113.21:7410"]))
            ],
            lease
        ));
        assert_eq!(peers.generation(), generation);

        // Peer 2 vanished from the registry: removed, generation bumped.
        assert!(peers.sync_cloud([([1; 12], set(&["203.0.113.20:7410"]))], lease));
        assert_eq!(peers.snapshot(), vec![a]);
        assert_ne!(peers.generation(), generation);

        // An empty locator set counts as absent.
        assert!(peers.sync_cloud([([1; 12], HashSet::new())], lease));
        assert!(peers.snapshot().is_empty());
        assert!(!peers.remove_cloud(&[1; 12]));
    }

    #[test]
    fn cloud_peer_expires_after_lease_without_a_poll() {
        let peers = SpdpPeerSet::new();
        let locator: SocketAddr = "198.51.100.9:7410".parse().unwrap();

        assert!(peers.sync_cloud(
            [([3; 12], set(&["198.51.100.9:7410"]))],
            Duration::from_millis(30)
        ));
        assert_eq!(peers.snapshot(), vec![locator]);
        thread::sleep(Duration::from_millis(60));

        assert!(peers.snapshot().is_empty());
        assert_eq!(peers.counts().cloud_peers, 0);
        assert_eq!(peers.prune_expired(), 0);
    }

    #[test]
    fn usable_unicast_locator_rejects_v6_unspecified_multicast_and_port0() {
        assert!(!usable_unicast_locator(&"0.0.0.0:7410".parse().unwrap()));
        assert!(!usable_unicast_locator(
            &"239.255.0.1:7410".parse().unwrap()
        ));
        assert!(!usable_unicast_locator(&"127.0.0.1:0".parse().unwrap()));
        assert!(!usable_unicast_locator(&"[::1]:7410".parse().unwrap()));
        assert!(!usable_unicast_locator(
            &"[2001:db8::1]:7410".parse().unwrap()
        ));
        assert!(usable_unicast_locator(&"127.0.0.1:7410".parse().unwrap()));
        assert!(usable_unicast_locator(&"192.0.2.1:7410".parse().unwrap()));
    }
}

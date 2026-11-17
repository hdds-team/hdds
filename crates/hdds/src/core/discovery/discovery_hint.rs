// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A once-only hint for a participant that discovers nobody.
//!
//! Discovery that cannot work fails silently: the participant announces,
//! nobody answers, and the application simply sees no match. The usual
//! causes are local (multicast leaving through the wrong interface, a VPN
//! that claims all multicast, a network that does not route multicast at
//! all), and every one of them has a remedy the user can apply. This module
//! says so ONCE, about two announcement periods after start, and only when
//! there is nothing else that could still discover a peer: no remote
//! participant, no static peer, no Discovery Server, no cloud discovery.
//!
//! Cost: the SPDP announcer polls it once per announcement. Before the
//! deadline that is one comparison; after the single evaluation it is one
//! boolean. The evaluation itself (a participant count and a peer-set count)
//! happens once per participant lifetime. Nothing on the data path.

use std::time::Duration;

/// The documentation page the hint points to.
pub(crate) const NETWORK_PREREQUISITES_URL: &str =
    "https://docs.hdds.io/getting-started/network-prerequisites";

/// What the hint looks at when its deadline passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiscoveryState {
    /// Remote participants currently known to discovery.
    pub remote_participants: usize,
    /// A static peer, a Discovery Server or cloud discovery is configured:
    /// discovery does not depend on multicast alone, so silence is not a
    /// sign of a local network problem.
    pub peers_configured: bool,
    /// The transport's multicast send probe on the primary interface was
    /// refused at start-up (see `UdpTransport::multicast_if_blocked`).
    pub multicast_blocked: bool,
}

/// The once-only discovery hint, owned by the SPDP announcer thread.
pub(crate) struct DiscoveryHint {
    after: Duration,
    state: Box<dyn Fn() -> DiscoveryState + Send>,
    done: bool,
}

impl DiscoveryHint {
    /// A hint evaluated once, two announcement periods after start.
    ///
    /// `state` is called at most once, when the deadline has passed.
    pub(crate) fn new(
        announcement_period: Duration,
        state: impl Fn() -> DiscoveryState + Send + 'static,
    ) -> Self {
        Self {
            after: announcement_period.saturating_mul(2),
            state: Box::new(state),
            done: false,
        }
    }

    /// True once the single evaluation has happened.
    pub(crate) fn is_done(&self) -> bool {
        self.done
    }

    /// Called by the announcer with the time elapsed since start; returns
    /// the line to log, at most once over the hint's lifetime.
    ///
    /// The first call at or past the deadline settles the matter either way:
    /// a participant that had discovered someone by then is never told later
    /// that it has not.
    pub(crate) fn poll(&mut self, elapsed: Duration) -> Option<(log::Level, String)> {
        if self.done || elapsed < self.after {
            return None;
        }
        self.done = true;
        hint_for((self.state)(), self.after)
    }
}

/// The hint for `state`, or `None` when there is nothing to say.
///
/// INFO when nothing was found: a participant alone on its network is a
/// legitimate state, and the line only says where to look if it is not
/// meant to be alone. WARN when the multicast probe was refused as well: a
/// measured local cause then explains the silence.
pub(crate) fn hint_for(state: DiscoveryState, after: Duration) -> Option<(log::Level, String)> {
    if state.remote_participants > 0 || state.peers_configured {
        return None;
    }
    let cause = if state.multicast_blocked {
        " Multicast sends on the primary interface were refused at start-up \
         (a VPN that claims all multicast is the usual cause), so multicast \
         discovery is unlikely to reach this network."
    } else {
        ""
    };
    let level = if state.multicast_blocked {
        log::Level::Warn
    } else {
        log::Level::Info
    };
    Some((
        level,
        format!(
            "[hdds] No remote participant discovered after {:?}, and discovery relies on \
             multicast alone (no static peer, Discovery Server or cloud discovery \
             configured).{cause} If peers are expected, check: HDDS_INTERFACE (the interface \
             discovery uses), unicast peers (HDDS_SPDP_UNICAST_PEERS or \
             ParticipantBuilder::add_static_peer), or a Discovery Server. \
             See {NETWORK_PREREQUISITES_URL}",
            after
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const PERIOD: Duration = Duration::from_secs(3);

    fn alone(multicast_blocked: bool) -> DiscoveryState {
        DiscoveryState {
            remote_participants: 0,
            peers_configured: false,
            multicast_blocked,
        }
    }

    /// A hint over a fixed state that counts how often the state is read.
    fn counted(state: DiscoveryState) -> (DiscoveryHint, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&reads);
        let hint = DiscoveryHint::new(PERIOD, move || {
            seen.fetch_add(1, Ordering::Relaxed);
            state
        });
        (hint, reads)
    }

    #[test]
    fn silent_before_two_periods_then_info_once() {
        let (mut hint, reads) = counted(alone(false));
        // Polled at every announcement of the startup burst and beyond.
        assert_eq!(hint.poll(Duration::ZERO), None);
        assert_eq!(hint.poll(Duration::from_millis(5_999)), None);
        assert_eq!(reads.load(Ordering::Relaxed), 0, "nothing read early");

        let (level, line) = hint.poll(Duration::from_secs(6)).expect("the hint");
        assert_eq!(level, log::Level::Info);
        for needle in [
            "HDDS_INTERFACE",
            "HDDS_SPDP_UNICAST_PEERS",
            "Discovery Server",
            NETWORK_PREREQUISITES_URL,
        ] {
            assert!(line.contains(needle), "{needle} missing from: {line}");
        }

        // Once only, whatever happens next.
        for secs in [9, 12, 600, 86_400] {
            assert_eq!(hint.poll(Duration::from_secs(secs)), None);
        }
        assert_eq!(reads.load(Ordering::Relaxed), 1, "state read exactly once");
    }

    #[test]
    fn warn_when_the_vpn_multicast_probe_fired() {
        let (mut hint, _) = counted(alone(true));
        let (level, line) = hint.poll(Duration::from_secs(6)).expect("the hint");
        assert_eq!(level, log::Level::Warn);
        assert!(line.contains("VPN"), "{line}");
        assert!(line.contains(NETWORK_PREREQUISITES_URL), "{line}");
    }

    #[test]
    fn nothing_when_a_participant_was_discovered() {
        let state = DiscoveryState {
            remote_participants: 1,
            ..alone(true)
        };
        let (mut hint, reads) = counted(state);
        assert_eq!(hint.poll(Duration::from_secs(6)), None);
        // Settled: no second evaluation later.
        assert_eq!(hint.poll(Duration::from_secs(60)), None);
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn nothing_when_peers_are_configured() {
        let state = DiscoveryState {
            peers_configured: true,
            ..alone(true)
        };
        assert_eq!(hint_for(state, PERIOD * 2), None);
    }

    #[test]
    fn the_deadline_follows_the_configured_period() {
        let mut hint = DiscoveryHint::new(Duration::from_millis(100), || alone(false));
        assert_eq!(hint.poll(Duration::from_millis(199)), None);
        assert!(hint.poll(Duration::from_millis(200)).is_some());
    }
}

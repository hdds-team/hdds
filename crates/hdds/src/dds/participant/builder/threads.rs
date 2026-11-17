// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Background thread spawning for participant services.
//!
//! This module contains logic for spawning background threads that support
//! participant operation:
//! - SPDP announcer (participant discovery)
//! - Lease tracker (participant liveliness monitoring)

use super::telemetry_setup::TelemetryThread;
use crate::config::RuntimeConfig;
use crate::core::discovery::{
    multicast::DiscoveryFsm, DiscoveryHint, DiscoveryState, SpdpPeerSet, GUID,
};
use crate::telemetry::MetricsCollector;
use crate::transport::UdpTransport;
use std::sync::Arc;

/// Spawned threads and shutdown coordination for a participant.
pub(super) struct ParticipantThreads {
    pub telemetry: TelemetryThread,
    pub spdp_announcer: Option<crate::core::discovery::SpdpAnnouncer>,
    pub lease_tracker: Option<crate::core::discovery::multicast::LeaseTracker>,
}

/// Spawn background threads for participant operation (excluding telemetry).
///
/// Telemetry thread is spawned separately in telemetry_setup module.
///
/// # Arguments
/// - `guid`: Participant GUID for SPDP announcements
/// - `_metrics`: Metrics registry (unused, kept for API compatibility)
/// - `transport`: UDP transport (if UDP mode enabled)
/// - `discovery_fsm`: Discovery FSM for lease tracking
/// - `telemetry`: Telemetry thread components from telemetry_setup
/// - `config`: Runtime configuration (for custom port mapping)
/// - `identity_token`: Optional serialized PID_IDENTITY_TOKEN payload
///   (DDS Security v1.1 sec. 7.4.1.4) attached to outgoing SPDP announcements.
/// - `permissions_token`: Optional serialized PID_PERMISSIONS_TOKEN payload
///   (DDS Security v1.1 sec. 7.4.1.4) attached to outgoing SPDP announcements.
/// - `security_attributes_mask`: Optional 8-byte
///   PID_PARTICIPANT_SECURITY_INFO payload (DDS Security v1.1 sec. 7.4.1.5)
///   advertising the local participant's security posture.
/// - `participant_lease_duration_ms` / `spdp_announcement_period`: SPDP
///   timing from the validated discovery timing options.
/// - `spdp_peer_set`: live SPDP unicast destinations (static peers plus
///   Discovery Server locators); the announcer wakes on every change.
/// - `discovery_services_configured`: a Discovery Server or cloud discovery
///   is configured, so the "discovered nobody" hint stays silent.
///
/// # Returns
/// Struct containing thread handles and shutdown coordination
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_participant_threads(
    guid: GUID,
    _metrics: Arc<MetricsCollector>,
    transport: Option<Arc<UdpTransport>>,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    telemetry: TelemetryThread,
    config: Arc<RuntimeConfig>,
    identity_token: Option<Vec<u8>>,
    permissions_token: Option<Vec<u8>>,
    security_attributes_mask: Option<[u8; 8]>,
    participant_lease_duration_ms: u64,
    spdp_announcement_period: std::time::Duration,
    spdp_peer_set: Arc<SpdpPeerSet>,
    discovery_services_configured: bool,
    spdp_sequence: Arc<std::sync::atomic::AtomicU64>,
) -> ParticipantThreads {
    // Spawn SPDP announcer (periodic participant discovery)
    let spdp_announcer = if let Some(ref transport_arc) = transport {
        log::debug!("[hdds] Spawning SPDP announcer (GUID={:?})", guid);
        let hint = discovery_hint(
            spdp_announcement_period,
            discovery_fsm.clone(),
            Arc::clone(&spdp_peer_set),
            transport_arc.multicast_if_blocked(),
            discovery_services_configured,
        );
        let capabilities = discovery_fsm
            .as_ref()
            .map_or(crate::protocol::group::LOCAL_CAPABILITIES, |fsm| {
                fsm.local_capabilities()
            });
        Some(
            crate::core::discovery::SpdpAnnouncer::spawn_with_security_and_peers(
                guid,
                transport_arc.clone(),
                participant_lease_duration_ms,
                spdp_announcement_period,
                config.clone(),
                identity_token,
                permissions_token,
                security_attributes_mask,
                spdp_peer_set,
                Some(hint),
                capabilities,
                spdp_sequence,
            ),
        )
    } else {
        None
    };

    // Phase 1.4: Start LeaseTracker to remove expired participants
    let lease_tracker = if let Some(ref fsm) = discovery_fsm {
        log::debug!("[hdds] Starting LeaseTracker (1 Hz check rate)");
        match crate::core::discovery::multicast::LeaseTracker::start_with_fsm(Arc::clone(fsm)) {
            Ok(tracker) => Some(tracker),
            Err(e) => {
                log::debug!("[hdds] WARNING: LeaseTracker failed to start: {}", e);
                None
            }
        }
    } else {
        None
    };

    ParticipantThreads {
        telemetry,
        spdp_announcer,
        lease_tracker,
    }
}

/// The once-only "discovered nobody" hint for this participant.
///
/// Peers configured = any static, Discovery Server or cloud peer in the SPDP
/// peer set when the deadline passes (the env-configured peers included,
/// seeded when the announcer starts), or a Discovery Server / cloud
/// discovery configured at all, even one that has not answered yet.
/// `multicast_blocked` is fixed when the transport is built.
fn discovery_hint(
    announcement_period: std::time::Duration,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    peer_set: Arc<SpdpPeerSet>,
    multicast_blocked: bool,
    discovery_services_configured: bool,
) -> DiscoveryHint {
    DiscoveryHint::new(announcement_period, move || {
        let counts = peer_set.counts();
        DiscoveryState {
            remote_participants: discovery_fsm
                .as_ref()
                .map_or(0, |fsm| fsm.participant_count()),
            peers_configured: discovery_services_configured
                || counts.static_peers + counts.server_peers + counts.cloud_peers > 0,
            multicast_blocked,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PERIOD: Duration = Duration::from_millis(10);
    const DEADLINE: Duration = Duration::from_millis(20);

    fn level(hint: &mut DiscoveryHint) -> Option<log::Level> {
        hint.poll(DEADLINE).map(|(level, _)| level)
    }

    #[test]
    fn a_lone_multicast_only_participant_gets_the_hint() {
        let peers = Arc::new(SpdpPeerSet::new());
        let mut info = discovery_hint(PERIOD, None, Arc::clone(&peers), false, false);
        assert_eq!(level(&mut info), Some(log::Level::Info));
        let mut warn = discovery_hint(PERIOD, None, peers, true, false);
        assert_eq!(level(&mut warn), Some(log::Level::Warn));
    }

    #[test]
    fn any_configured_peer_source_silences_it() {
        let configured = Arc::new(SpdpPeerSet::new());
        let mut hint = discovery_hint(PERIOD, None, configured, true, true);
        assert_eq!(
            level(&mut hint),
            None,
            "Discovery Server / cloud configured"
        );

        let static_peer = Arc::new(SpdpPeerSet::new());
        assert!(static_peer.add_static("203.0.113.5:7410".parse().expect("addr")));
        let mut hint = discovery_hint(PERIOD, None, static_peer, true, false);
        assert_eq!(level(&mut hint), None, "static peer");

        let server_peer = Arc::new(SpdpPeerSet::new());
        assert!(server_peer.replace_server([7; 12], ["203.0.113.6:7410".parse().expect("addr")]));
        let mut hint = discovery_hint(PERIOD, None, server_peer, true, false);
        assert_eq!(level(&mut hint), None, "Discovery Server peer");
    }

    #[test]
    fn a_static_peer_added_after_start_still_counts() {
        // The env peers are seeded when the announcer starts, after the hint
        // is built: the peer set is read at the deadline, not at build time.
        let peers = Arc::new(SpdpPeerSet::new());
        let mut hint = discovery_hint(PERIOD, None, Arc::clone(&peers), false, false);
        assert!(peers.add_static("203.0.113.5:7410".parse().expect("addr")));
        assert_eq!(level(&mut hint), None);
    }
}

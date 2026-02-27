// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Background thread spawning for participant services.
//!
//! This module contains logic for spawning background threads that support
//! participant operation:
//! - SPDP announcer (participant discovery)
//! - Lease tracker (participant liveliness monitoring)

use super::telemetry_setup::TelemetryThread;
use crate::config::{RuntimeConfig, PARTICIPANT_LEASE_DURATION_MS};
use crate::core::discovery::{multicast::DiscoveryFsm, GUID};
use crate::telemetry::MetricsCollector;
use crate::transport::UdpTransport;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Spawned threads and shutdown coordination for a participant.
pub(super) struct ParticipantThreads {
    pub telemetry_shutdown: Arc<AtomicBool>,
    pub telemetry_handle: Option<std::thread::JoinHandle<()>>,
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
///
/// # Returns
/// Struct containing thread handles and shutdown coordination
pub(super) fn spawn_participant_threads(
    guid: GUID,
    _metrics: Arc<MetricsCollector>,
    transport: Option<Arc<UdpTransport>>,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    telemetry: TelemetryThread,
    config: Arc<RuntimeConfig>,
) -> ParticipantThreads {
    // Spawn SPDP announcer (periodic participant discovery)
    let spdp_announcer = if let Some(ref transport_arc) = transport {
        log::debug!("[hdds] Spawning SPDP announcer (GUID={:?})", guid);
        Some(crate::core::discovery::SpdpAnnouncer::spawn(
            guid,
            transport_arc.clone(),
            PARTICIPANT_LEASE_DURATION_MS,
            config.clone(),
        ))
    } else {
        None
    };

    // Phase 1.4: Start LeaseTracker to remove expired participants
    let lease_tracker = if let Some(ref fsm) = discovery_fsm {
        log::debug!("[hdds] Starting LeaseTracker (1 Hz check rate)");
        match crate::core::discovery::multicast::LeaseTracker::start(fsm.db()) {
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
        telemetry_shutdown: telemetry.shutdown,
        telemetry_handle: Some(telemetry.handle),
        spdp_announcer,
        lease_tracker,
    }
}

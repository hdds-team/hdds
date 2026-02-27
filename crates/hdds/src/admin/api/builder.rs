// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Snapshot builders for Admin API responses.
//!
//! Produces mesh, topics, endpoints, and metrics snapshots from internal state.

use super::super::snapshot::{
    snapshot_participants, snapshot_with_epoch, EndpointView, EndpointsSnapshot, MeshSnapshot,
    MetricsSnapshot, ParticipantDB, TopicView, TopicsSnapshot,
};
use super::locks::recover_write;
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::multicast::EndpointInfo;
use crate::dds::qos::{Durability, History, Reliability};
use crate::telemetry::{extract_metrics_from_collector, MetricsCollector};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

/// Produce a mesh snapshot either from the multicast FSM (if available)
/// or by cloning the participant database with epoch consistency.
pub(crate) fn mesh_snapshot(
    epoch: &Arc<AtomicU64>,
    db: &Arc<RwLock<ParticipantDB>>,
    fsm: Option<&Arc<DiscoveryFsm>>,
) -> MeshSnapshot {
    let epoch_val = epoch.load(Ordering::SeqCst);

    let participants = if let Some(fsm) = fsm {
        snapshot_participants(fsm)
    } else {
        snapshot_with_epoch(epoch, db, |db| db.participants())
    };

    MeshSnapshot {
        epoch: epoch_val,
        participants,
    }
}

/// Mark the local participant in the DB and bump the epoch.
pub(crate) fn set_local_participant(
    db: &Arc<RwLock<ParticipantDB>>,
    epoch: &AtomicU64,
    name: String,
) {
    let mut guard = recover_write(Arc::as_ref(db), "AdminApi::set_local_participant");
    guard.set_local(name);
    epoch.fetch_add(1, Ordering::SeqCst);
}

/// Topics snapshot built from DiscoveryFsm when available.
pub(crate) fn topics_snapshot(
    epoch: &Arc<AtomicU64>,
    fsm: Option<&Arc<DiscoveryFsm>>,
) -> TopicsSnapshot {
    let epoch_val = epoch.load(Ordering::SeqCst);

    let topics = if let Some(fsm) = fsm {
        let mut views = Vec::new();
        for (topic_name, (writers, readers)) in fsm.get_all_topics() {
            if topic_name.starts_with("DCPS") {
                continue;
            }
            let type_name = writers
                .first()
                .or_else(|| readers.first())
                .map(|e| e.type_name.clone())
                .unwrap_or_default();
            views.push(TopicView {
                name: topic_name,
                type_name,
                writers_count: writers.len(),
                readers_count: readers.len(),
            });
        }
        views
    } else {
        Vec::new()
    };

    TopicsSnapshot {
        epoch: epoch_val,
        topics,
    }
}

pub(crate) fn writers_snapshot(
    epoch: &Arc<AtomicU64>,
    fsm: Option<&Arc<DiscoveryFsm>>,
) -> EndpointsSnapshot {
    endpoints_snapshot(epoch, fsm, true)
}

pub(crate) fn readers_snapshot(
    epoch: &Arc<AtomicU64>,
    fsm: Option<&Arc<DiscoveryFsm>>,
) -> EndpointsSnapshot {
    endpoints_snapshot(epoch, fsm, false)
}

/// Metrics snapshot built from the shared collector reference.
pub(crate) fn metrics_snapshot(
    epoch: &Arc<AtomicU64>,
    metrics: &Arc<Mutex<Option<Arc<MetricsCollector>>>>,
) -> MetricsSnapshot {
    let epoch_val = epoch.load(Ordering::SeqCst);
    extract_metrics_from_collector(epoch_val, metrics)
}

fn endpoints_snapshot(
    epoch: &Arc<AtomicU64>,
    fsm: Option<&Arc<DiscoveryFsm>>,
    writers: bool,
) -> EndpointsSnapshot {
    let epoch_val = epoch.load(Ordering::SeqCst);

    let endpoints = if let Some(fsm) = fsm {
        let mut views = Vec::new();
        for (_topic, (writers_list, readers_list)) in fsm.get_all_topics() {
            let list = if writers { writers_list } else { readers_list };
            for endpoint in list {
                views.push(endpoint_view(&endpoint));
            }
        }
        views
    } else {
        Vec::new()
    };

    EndpointsSnapshot {
        epoch: epoch_val,
        endpoints,
    }
}

fn endpoint_view(endpoint: &EndpointInfo) -> EndpointView {
    let reliability = match endpoint.qos.reliability {
        Reliability::BestEffort => "BEST_EFFORT",
        Reliability::Reliable => "RELIABLE",
    };
    let durability = match endpoint.qos.durability {
        Durability::Volatile => "VOLATILE",
        Durability::TransientLocal => "TRANSIENT_LOCAL",
        Durability::Persistent => "PERSISTENT",
    };
    let history = match endpoint.qos.history {
        History::KeepLast(depth) => format!("KEEP_LAST({})", depth),
        History::KeepAll => "KEEP_ALL".to_string(),
    };

    EndpointView {
        guid: endpoint.endpoint_guid.to_string(),
        participant_guid: endpoint.participant_guid.to_string(),
        topic_name: endpoint.topic_name.clone(),
        type_name: endpoint.type_name.clone(),
        reliability: reliability.to_string(),
        durability: durability.to_string(),
        history,
    }
}

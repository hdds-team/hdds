// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Admin API for Web Debugger.
//!
//! Provides epoch-based snapshots of mesh state (participants, topics, metrics)
//! over a binary protocol on TCP port 4243 (default).
//!
//! # Architecture
//!
//! - **Epoch-based snapshots**: AtomicU64 epoch counter incremented on mutations
//! - **Lock-free reads**: Clone Arc-wrapped structures, retry if epoch changed
//! - **Binary protocol**: Simple `[cmd_id][len][payload]` format
//! - **Zero data-plane impact**: No locks held during write/read operations

/// Admin API for Web Debugger
///
/// Provides epoch-based snapshots of mesh state (participants, topics, metrics)
/// over a binary protocol on TCP port 4243 (default).
///
/// # Architecture
///
/// - **Epoch-based snapshots**: AtomicU64 epoch counter incremented on mutations
/// - **Lock-free reads**: Clone Arc-wrapped structures, retry if epoch changed
/// - **Binary protocol**: Simple `[cmd_id][len][payload]` format
/// - **Zero data-plane impact**: No locks held during write/read operations
pub mod api;
/// Snapshot helpers used by the admin API for mesh/metrics reporting.
pub mod snapshot;

pub use api::AdminApi;
pub use snapshot::{
    snapshot_participants, EndpointView, EndpointsSnapshot, MeshSnapshot, MetricsSnapshot,
    ParticipantView, TopicsSnapshot,
};

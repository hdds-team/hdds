// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery finite state machine (FSM) for SPDP/SEDP protocol handling.
//!
//! Processes incoming discovery packets from the multicast listener and
//! maintains participant/endpoint state in `ParticipantDB`.

mod discovery;
mod endpoint;
mod metrics;
mod registry;

pub use discovery::{DiscoveryFsm, DiscoveryListener, ParticipantDB, SecurityValidator};
pub use endpoint::{EndpointInfo, EndpointKind};
pub use metrics::DiscoveryMetrics;
pub use registry::TopicRegistry;

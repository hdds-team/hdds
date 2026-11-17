// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovery finite state machine (FSM) for SPDP/SEDP protocol handling.
//!
//! Processes incoming discovery packets from the multicast listener and
//! maintains participant/endpoint state in `ParticipantDB`.

mod discovery;
mod endpoint;
mod metrics;
#[cfg(all(test, feature = "security"))]
mod participant_status_tests;
mod registry;
mod withheld;

/// `discovery` is private, so the relay reaches the reachability rule here
/// rather than keeping a second copy of it.
pub(crate) use discovery::has_direct_route;
#[cfg(all(test, feature = "security"))]
pub(crate) use discovery::mint_sedp_writer_keys_for_tests;
#[cfg(all(test, feature = "security"))]
pub(crate) use discovery::sealed_departure_datagram;
pub use discovery::{DiscoveryFsm, DiscoveryListener, ParticipantDB, SecurityValidator};
pub(crate) use discovery::{SedpChangeAdmission, SedpChannel, SpdpVerdict};
pub use endpoint::{EndpointInfo, EndpointKind};
pub use metrics::DiscoveryMetrics;
pub use registry::TopicRegistry;

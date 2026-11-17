// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # DDS Participant
//!
//! The [`Participant`] is the entry point to the HDDS middleware. It represents
//! a single DDS domain participant and acts as a factory for all DDS entities.
//!
//! ## Overview
//!
//! A participant:
//! - Joins a DDS domain (isolated communication space)
//! - Discovers other participants via SPDP/SEDP protocols
//! - Creates publishers, subscribers, topics, readers, and writers
//! - Manages the lifecycle of all child entities
//!
//! ## Example
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS, TransportMode, Result};
//!
//! fn main() -> Result<()> {
//!     // Create a participant with UDP multicast discovery
//!     let participant = Participant::builder("my_robot")
//!         .domain_id(0)
//!         .with_transport(TransportMode::UdpMulticast)
//!         .build()?;
//!
//!     // Create a typed writer
//!     let writer = participant.create_writer::<SensorData>(
//!         "sensors/lidar",
//!         QoS::reliable(),
//!     )?;
//!
//!     // Create a typed reader
//!     let reader = participant.create_reader::<Command>(
//!         "commands",
//!         QoS::reliable(),
//!     )?;
//!
//!     Ok(())
//! }
//! # #[derive(hdds::DDS)] struct SensorData { value: f64 }
//! # #[derive(hdds::DDS)] struct Command { id: u32 }
//! ```
//!
//! ## Transport Modes
//!
//! | Mode | Use Case |
//! |------|----------|
//! | [`TransportMode::IntraProcess`] | Same process, zero-copy (default) |
//! | [`TransportMode::UdpMulticast`] | Network communication with auto-discovery |
//!
//! ## Architecture
//!
//! ```text
//! +-----------------------------------------------------+
//! |                    Participant                      |
//! |  +-------------+  +-------------+  +-------------+ |
//! |  |  Publisher  |  | Subscriber  |  |   Topic     | |
//! |  |  +-------+  |  |  +-------+  |  |  Registry   | |
//! |  |  |Writer |  |  |  |Reader |  |  |             | |
//! |  |  +-------+  |  |  +-------+  |  |             | |
//! |  +-------------+  +-------------+  +-------------+ |
//! +-----------------------------------------------------+
//! |  Discovery FSM | Transport | Router | Type Cache   |
//! +-----------------------------------------------------+
//! ```
//!
//! ## See Also
//!
//! - [`ParticipantBuilder`] - Builder pattern for configuration
//! - [`DataWriter`](crate::DataWriter) - Publish data samples
//! - [`DataReader`](crate::DataReader) - Subscribe to data samples
//! - [`QoS`](crate::QoS) - Quality of Service policies

mod adopt;
mod announce;
mod builder;
#[cfg(test)]
mod false_departure_tests;
#[cfg(test)]
mod group_wire_tests;
mod live_capture;
#[cfg(test)]
mod publisher_identity_tests;
mod runtime;
#[cfg(test)]
mod sedp_retirement_tests;
mod telemetry;
#[cfg(all(test, feature = "xtypes"))]
mod type_verdict_tests;
#[cfg(feature = "xtypes")]
mod xtypes;

pub use adopt::{ADOPT_WAIT_ENV, PLACEHOLDER_TYPE_NAME};
pub(crate) use announce::SedpRetirement;
pub use builder::ParticipantBuilder;
pub use live_capture::{
    DiscoveredEndpointInfo, DiscoveredEndpointKind, DiscoveredTopicInfo, RawDataReader,
    RawDataWriter, RawRelayWriter, RawSample,
};
#[cfg(feature = "security")]
pub(crate) use runtime::EndpointKeyHooks;
pub use runtime::{Participant, TransportMode};

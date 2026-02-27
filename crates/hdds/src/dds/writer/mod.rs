// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # DDS DataWriter
//!
//! The [`DataWriter`] publishes typed data samples to a DDS topic.
//!
//! ## Overview
//!
//! A DataWriter:
//! - Serializes and publishes typed data samples
//! - Supports QoS policies (reliability, history, durability)
//! - Handles both intra-process and network delivery
//! - Maintains a history cache for late-joining readers (transient-local)
//!
//! ## Example
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS, Result};
//!
//! fn main() -> Result<()> {
//!     let participant = Participant::builder("publisher")
//!         .domain_id(0)
//!         .build()?;
//!
//!     let writer = participant.create_writer::<SensorData>(
//!         "sensors/temperature",
//!         QoS::reliable(),
//!     )?;
//!
//!     // Publish a sample
//!     writer.write(&SensorData { value: 23.5 })?;
//!
//!     Ok(())
//! }
//! # #[derive(hdds::DDS)] struct SensorData { value: f64 }
//! ```
//!
//! ## Reliability
//!
//! With `QoS::reliable()`, the writer:
//! - Assigns monotonic sequence numbers to each sample
//! - Sends periodic HEARTBEAT messages
//! - Responds to ACKNACK by retransmitting missed samples
//! - Maintains a history cache for retransmission
//!
//! ## Delivery Path
//!
//! ```text
//! write() -+-> Intra-process (TopicMerger) -> Local readers
//!          |
//!          +-> UDP transport -+-> Unicast to discovered endpoints
//!                             +-> Multicast fallback
//! ```
//!
//! ## See Also
//!
//! - [`DataReader`](crate::DataReader) - The subscribing counterpart
//! - [`QoS`](crate::QoS) - Quality of Service configuration
//! - [DDS Spec Sec.2.2.2.4](https://www.omg.org/spec/DDS/1.4/) - DataWriter

mod builder;
mod heartbeat_scheduler;
mod nack;
mod runtime;
#[cfg(test)]
mod tests;

pub use builder::WriterBuilder;
#[allow(unused_imports)]
pub use runtime::{DataWriter, WriterStats};

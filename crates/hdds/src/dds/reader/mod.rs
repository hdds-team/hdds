// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # DDS DataReader
//!
//! The [`DataReader`] subscribes to data samples published on a DDS topic.
//!
//! ## Overview
//!
//! A DataReader:
//! - Receives typed data samples from matching DataWriters
//! - Supports QoS policies (reliability, history, durability)
//! - Provides both blocking and non-blocking read APIs
//! - Tracks sample metadata (sequence numbers, timestamps)
//!
//! ## Example
//!
//! ```rust,no_run
//! use hdds::{Participant, QoS, Result};
//!
//! fn main() -> Result<()> {
//!     let participant = Participant::builder("subscriber")
//!         .domain_id(0)
//!         .build()?;
//!
//!     let reader = participant.create_reader::<SensorData>(
//!         "sensors/temperature",
//!         QoS::reliable(),
//!     )?;
//!
//!     // Non-blocking read
//!     if let Some(sample) = reader.try_take()? {
//!         println!("Received: {:?}", sample);
//!     }
//!
//!     // Batch read
//!     let samples = reader.take_batch(10)?;
//!     println!("Got {} samples", samples.len());
//!
//!     Ok(())
//! }
//! # #[derive(hdds::DDS, Debug)] struct SensorData { value: f64 }
//! ```
//!
//! ## Reliability
//!
//! With `QoS::reliable()`, the reader:
//! - Tracks sequence numbers to detect gaps
//! - Sends ACKNACK messages to request retransmission
//! - Buffers out-of-order samples until gaps are filled
//!
//! ## See Also
//!
//! - [`DataWriter`](crate::DataWriter) - The publishing counterpart
//! - [`QoS`](crate::QoS) - Quality of Service configuration
//! - [DDS Spec Sec.2.2.2.5](https://www.omg.org/spec/DDS/1.4/) - DataReader

mod admission;
pub(crate) use admission::{retries as local_retries, Retry as LocalRetry};
mod builder;
mod cache;
pub(crate) mod coherent_barrier;
mod conditions;
mod consumer_gate;
mod filter_wake;
mod gap_proofs;
mod heartbeat;
mod local_door;
mod local_order;
pub(crate) mod notices;
mod registrations;
mod reorder;
mod runtime;
mod staging_budget;
mod subscriber;
pub(crate) use subscriber::GroupArrivalScope;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_barrier_empty_generation;
#[cfg(test)]
mod tests_best_effort_lost;
#[cfg(test)]
mod tests_coherent_staging;
#[cfg(test)]
mod tests_conditions;
#[cfg(test)]
mod tests_consumer_gate;
#[cfg(test)]
mod tests_cyclone_wire_fixture;
#[cfg(test)]
mod tests_dispose_gap_order;
#[cfg(test)]
mod tests_exclusive_ownership;
#[cfg(test)]
mod tests_foreign_key_hash;
#[cfg(test)]
mod tests_group_sibling;
#[cfg(test)]
mod tests_group_spec;
#[cfg(test)]
mod tests_held_storage;
#[cfg(test)]
mod tests_history_limits;
#[cfg(test)]
mod tests_local_history;
#[cfg(test)]
mod tests_memory_model;
#[cfg(test)]
mod tests_model;
#[cfg(test)]
mod tests_ownership;
#[cfg(test)]
mod tests_pair_gate;
#[cfg(test)]
mod tests_pump_merge_sample_lost;
#[cfg(test)]
mod tests_refusal_join;
#[cfg(test)]
mod tests_registrations;
#[cfg(test)]
mod tests_route_cost;
#[cfg(test)]
mod tests_sampleless_set_end;
#[cfg(test)]
mod tests_time_filter;
#[cfg(test)]
mod tests_topic_gate;
#[cfg(test)]
mod tests_verify_barrier2;
#[cfg(test)]
mod tests_verify_barrier3;
#[cfg(test)]
mod tests_verify_bf;
#[cfg(test)]
mod tests_verify_membudget;
#[cfg(test)]
mod tests_verify_membudget3;
#[cfg(test)]
mod tests_verify_membudget3_model;
#[cfg(test)]
mod tests_verify_membudget4;
#[cfg(test)]
mod tests_verify_membudget4_base;
#[cfg(test)]
mod tests_verify_notices;
#[cfg(test)]
mod tests_verify_reorder_ff;
mod wire_order;

pub use builder::ReaderBuilder;
// InstanceHandle export also fixes a pre-existing wart: take_instance's
// parameter type was public API with no public path to name it.
pub use cache::{InstanceHandle, InstanceState, SampleInfo, SampleState, ViewState};
pub use conditions::FieldExtractor;
#[allow(unused_imports)]
pub use runtime::{DataReader, InstanceDisposeEvent, ReaderStats};

use super::condition::HasStatusCondition;
use super::DDS;
use std::sync::Arc;

impl<T: DDS> HasStatusCondition for DataReader<T> {
    fn get_status_condition(&self) -> Arc<super::StatusCondition> {
        self.get_status_condition()
    }
}

#[cfg(test)]
mod tests_wire_group_order;

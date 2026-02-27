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

mod builder;
mod cache;
mod heartbeat;
mod runtime;
mod subscriber;
#[cfg(test)]
mod tests;

pub use builder::ReaderBuilder;
#[allow(unused_imports)]
pub use runtime::{DataReader, ReaderStats};

use super::condition::HasStatusCondition;
use super::DDS;
use std::sync::Arc;

impl<T: DDS> HasStatusCondition for DataReader<T> {
    fn get_status_condition(&self) -> Arc<super::StatusCondition> {
        self.get_status_condition()
    }
}

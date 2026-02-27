// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Prelude module for convenient imports.
//!
//! This module re-exports the most commonly used types from the DDS API.
//!
//! # Example
//!
//! ```rust,no_run
//! use hdds::dds::prelude::*;
//!
//! let participant = Participant::builder("my_app").build()?;
//! # Ok::<(), hdds::Error>(())
//! ```

pub use super::{
    Condition, ContentFilteredTopic, DataReader, DataWriter, DiscoveredTopicInfo, Error,
    FieldValue, FilterError, GuardCondition, HasStatusCondition, Participant, QoS, RawDataReader,
    RawDataWriter, RawSample, Result, StatusCondition, StatusMask, Topic, TransportMode, WaitSet,
    DDS,
};

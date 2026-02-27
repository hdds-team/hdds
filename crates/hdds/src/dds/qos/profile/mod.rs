// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! QoS profile aggregation and builder pattern.
//!
//! Combines all 22 DDS QoS policies into a single `QoS` struct
//! with fluent builder methods.

mod builders_behavior;
mod builders_factory;
mod builders_reliability;
mod builders_timing;
mod structs;

pub use structs::QoS;

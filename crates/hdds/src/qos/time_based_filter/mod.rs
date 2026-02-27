// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TIME_BASED_FILTER QoS policy (DDS v1.4 Sec.2.2.3.14).
//!
//! Controls the minimum separation between samples delivered to a
//! `DataReader`. Samples arriving faster than the minimum separation
//! are discarded client-side.

mod checker;
mod policy;

pub use checker::TimeBasedFilterChecker;
pub use policy::TimeBasedFilter;

#[cfg(test)]
mod tests;

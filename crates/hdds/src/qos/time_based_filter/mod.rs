// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TIME_BASED_FILTER QoS policy (DDS v1.4 Sec.2.2.3.14).
//!
//! Controls the minimum separation between the samples of an instance that a
//! `DataReader` shows its application. The separation is measured between the
//! instants two samples become visible, not between their arrivals: a sample
//! that arrives while the previous one's window is still open waits and is
//! shown when the window ends, a newer sample of the same window replacing it.
//! A reader's listener learns of it through `on_data_available_notification`.

mod checker;
pub(crate) mod gate;
mod policy;

pub use checker::TimeBasedFilterChecker;
pub use policy::TimeBasedFilter;

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Waitset implementation for condition variable notification.
//!
//! Provides `WaitsetDriver` for efficient multi-slot event waiting.
//! Used by `StatusCondition` and readers to implement `wait_for_data()`.

mod bitmap;
mod driver;

pub use driver::{
    WaitsetDriver, WaitsetRegistration, WaitsetSignal, WaitsetWaitError, WAITSET_DEFAULT_MAX_SLOTS,
};

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! PARTITION QoS policy API re-exports.
//!
//! This module re-exports the core partition implementation from `crate::qos::partition`.
//! See the core module for full documentation, compatibility rules, and use cases.

// Re-export all types from core partition module
pub use crate::qos::partition::Partition;

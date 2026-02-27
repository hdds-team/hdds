// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LIVELINESS QoS policy API re-exports.
//!
//! This module re-exports the core liveliness implementation from `crate::qos::liveliness`.
//! See the core module for full documentation and implementation details.
//!
//! Note: The core implementation uses `std::time::Duration` for lease duration.
//! Convenience constructors (automatic_millis, manual_participant_secs, etc.) are
//! available directly on the `Liveliness` type.

// Re-export all types from core liveliness module
pub use crate::qos::liveliness::{Liveliness, LivelinessKind};

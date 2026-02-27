// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! OWNERSHIP QoS policy API re-exports.
//!
//! This module re-exports the core ownership implementation from `crate::qos::ownership`.
//! See the core module for full documentation and implementation details.

// Re-export all types from core ownership module
pub use crate::qos::ownership::{Ownership, OwnershipKind, OwnershipStrength};

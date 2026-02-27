// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS Discovery Protocol Implementation
//!
//! This module contains parsers and builders for:
//! - SPDP (Simple Participant Discovery Protocol)
//! - SEDP (Simple Endpoint Discovery Protocol)
//!
//! Organized for clarity and maintainability.

pub mod constants;
pub mod hash;
pub mod sedp;
pub mod spdp;
pub mod topic;
pub mod types;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod xcdr_interop_test;

// Re-export commonly used items
// Note: constants module contains internal PIDs, not re-exported (use via constants::PID_*)
pub use sedp::{build_sedp, parse_sedp};
pub use spdp::{build_spdp, parse_spdp, parse_spdp_partial, SpdpData};
pub use topic::parse_topic_name;
pub use types::*;

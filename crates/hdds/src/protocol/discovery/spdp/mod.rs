// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SPDP (Simple Participant Discovery Protocol) Module
//!
//! This module implements the parsing and building of SPDP messages according to
//! DDS-RTPS v2.3 Sec.8.5.4 specification. SPDP is used for participant discovery in DDS,
//! where participants announce their presence and capabilities on the network.
//!
//! # Module Structure
//!
//! - `types`: Core data structures (SpdpData) and constants
//! - `parse`: SPDP message parsing functions (parse_spdp, parse_spdp_partial)
//! - `build`: SPDP message building functions (build_spdp)
//!
//! # Features
//!
//! - Multi-format CDR support (CDR_LE, CDR_BE, CDR2_LE, CDR2_BE, vendor variants)
//! - RTI Connext compatibility (non-standard padding, fragmented messages)
//! - FastDDS compatibility (vendor-specific encapsulation)
//! - Complete parameter list handling (20+ PIDs)
//! - Fragmented message support via parse_spdp_partial()

pub mod build;
pub mod parse;
pub mod types;

// Public exports
pub use build::build_spdp;
pub use parse::{parse_spdp, parse_spdp_partial};
pub use types::SpdpData;

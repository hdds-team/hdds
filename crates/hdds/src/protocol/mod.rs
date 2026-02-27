// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! RTPS protocol implementation
//!
//! This module contains the core RTPS protocol components:
//! - Constants: PIDs, entity IDs, vendor IDs
//! - CDR encoding/decoding
//! - Packet builders for RTPS messages
//! - Discovery protocol parsers (SPDP/SEDP)
//! - Dialect encoders for vendor-specific interoperability
//! - RTPS standard submessage encoders (vendor-neutral)

pub mod builder;
pub mod cdr;
pub mod constants;
pub mod dialect;
pub mod discovery;
pub mod rtps;

// Re-export commonly used items
pub use constants::*;

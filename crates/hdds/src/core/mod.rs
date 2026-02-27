// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # Core Runtime Components
//!
//! Low-level infrastructure shared across the HDDS stack.
//!
//! ## Overview
//!
//! This module contains performance-critical primitives and protocol
//! implementations used by higher-level DDS APIs.
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | `discovery` | SPDP/SEDP endpoint discovery, GUID management |
//! | `reader` | RTPS ReaderProxy state machine (Sec.8.4.9) |
//! | `writer` | RTPS WriterProxy state machine (Sec.8.4.7) |
//! | `rt` | Runtime primitives (slab pools, waitsets, hubs) |
//! | `ser` | CDR2 serialization helpers |
//! | `types` | XTypes metadata structures |
//!
//! ## Architecture
//!
//! ```text
//! +-----------------------------------------------------+
//! |                    DDS Layer                        |
//! |        (Participant, DataWriter, DataReader)        |
//! +-----------------------------------------------------+
//! |                    Core Layer                       |
//! |  +----------+ +----------+ +----------+ +-------+ |
//! |  |Discovery | | Reader   | | Writer   | |  RT   | |
//! |  | SPDP/SEDP| | Proxy    | | Proxy    | |Waitset| |
//! |  +----------+ +----------+ +----------+ +-------+ |
//! +-----------------------------------------------------+
//! ```
//!
//! ## Note
//!
//! Most users should use the high-level [`crate::dds`] API instead of
//! interacting with core modules directly.

/// Endpoint discovery helpers and SPDP parsing utilities.
pub mod discovery;
/// Reliable Reader state machine (RTPS Sec.8.4.9 WriterProxy tracking).
pub mod reader;
/// Runtime primitives (slab pools, waitsets, hub) shared across transports.
pub mod rt;
/// RTPS constants dedicated to the core routing/interop engine.
pub mod rtps_constants;
/// Serialization helpers (CDR2 encoding/decoding).
pub mod ser;
/// Helper routines used by hot-path formatting utilities.
pub mod string_utils;
pub mod types;
/// Reliable Writer state machine (RTPS Sec.8.4.7 ReaderProxy tracking).
pub mod writer;

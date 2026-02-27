// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP (Simple Endpoint Discovery Protocol) - Endpoint discovery parser and builder
//!
//! This module handles parsing and building SEDP discovery announcements for DDS endpoints.
//! SEDP is part of the RTPS discovery protocol (RTPS v2.3 Sec.8.5) and is used to announce
//! DataReaders and DataWriters after participant discovery (SPDP) completes.

pub mod build;
pub mod parse;

pub use build::build_sedp;
pub use parse::parse_sedp;

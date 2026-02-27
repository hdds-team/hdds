// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Reliable Writer State Machine -- RTPS Sec.8.4.7
//!
//! This module provides state tracking for reliable data transmission.
//! It implements the ReaderProxy concept from RTPS, allowing a Writer
//! to correctly handle ACKNACKs and schedule HEARTBEATs per reader.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  MatchedReadersRegistry (thread-safe, shared)              |
//! |  +---------------------------------------------------------+|
//! |  |  DashMap<ReaderGUID, ReliableWriterProxy>              ||
//! |  +---------------------------------------------------------+|
//! |                                                             |
//! |  Used by:                                                   |
//! |  - Control thread: on_acknack() -> repair sequences         |
//! |  - Data thread: get_all_addrs() -> unicast fan-out          |
//! |  - HEARTBEAT scheduler: get_needing_heartbeat()            |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Thread Safety
//!
//! Uses DashMap for lock-free concurrent access from multiple threads.

mod matched_readers;
mod proxy;

pub use matched_readers::MatchedReadersRegistry;
pub use proxy::ReliableWriterProxy;

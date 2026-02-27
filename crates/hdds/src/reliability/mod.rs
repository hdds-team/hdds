// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # RTPS Reliable QoS Protocol
//!
//! Implementation of the RTPS reliability protocol for guaranteed delivery
//! in DDS communications.
//!
//! ## Overview
//!
//! When using `QoS::reliable()`, HDDS ensures all published samples are
//! delivered to all matched readers, even in the presence of packet loss.
//!
//! ## Protocol Flow
//!
//! ```text
//! Writer                                    Reader
//!   |                                          |
//!   |--- DATA (seq=1) ------------------------>|
//!   |--- DATA (seq=2) ----------X (lost)       |
//!   |--- DATA (seq=3) ------------------------>|
//!   |                                          |
//!   |--- HEARTBEAT (first=1, last=3) -------->|
//!   |                                          | (detects gap: seq=2 missing)
//!   |<-- ACKNACK (missing: [2]) --------------|
//!   |                                          |
//!   |--- DATA (seq=2) [retransmit] ---------->|
//!   |                                          | (gap filled!)
//! ```
//!
//! ## Components
//!
//! | Component | Role |
//! |-----------|------|
//! | `HeartbeatTx` | Writer sends periodic heartbeats announcing available samples |
//! | `HeartbeatRx` | Reader processes heartbeats, triggers NACKs for gaps |
//! | `NackScheduler` | Reader schedules NACK messages for missing samples |
//! | `GapTracker` | Reader tracks sequence number gaps |
//! | `HistoryCache` | Writer stores samples for retransmission |
//! | `ReliableMetrics` | Observability counters (heartbeats, NACKs, retransmits) |
//!
//! ## Configuration
//!
//! Reliability behavior is controlled via QoS:
//!
//! ```rust,ignore
//! use hdds::QoS;
//!
//! // Reliable with history depth
//! let qos = QoS::reliable()
//!     .history_keep_last(100);  // Keep 100 samples for retransmission
//!
//! // Best-effort (no reliability)
//! let qos = QoS::best_effort();
//! ```
//!
//! ## See Also
//!
//! - [`QoS`](crate::QoS) - Quality of Service configuration
//! - [RTPS v2.5 Sec.8.4](https://www.omg.org/spec/DDSI-RTPS/2.5/) - Reliability Protocol

// Core types
mod gap_tracker;
mod metrics;
mod rtps_range;
mod seq;

// Protocol messages
mod messages;

// Protocol handlers
mod reader;
mod writer;

// History cache
mod history_cache;

// ============================================================================
// Public re-exports: Core types
// ============================================================================

pub use gap_tracker::GapTracker;
pub use metrics::{
    ReliableMetrics, TAG_GAPS_DETECTED, TAG_HEARTBEATS_SENT, TAG_MAX_GAP_SIZE, TAG_NACKS_SENT,
    TAG_OUT_OF_ORDER, TAG_RETRANSMIT_RECEIVED, TAG_RETRANSMIT_SENT,
};
pub use rtps_range::RtpsRange;
pub use seq::SeqNumGenerator;

// ============================================================================
// Public re-exports: Messages
// ============================================================================

pub use messages::{
    // Supporting types
    EntityId,
    // Message types
    GapMsg,
    GuidPrefix,
    HeartbeatMsg,
    InfoDstMsg,
    InfoTsMsg,
    NackMsg,
    SequenceNumberIter,
    SequenceNumberSet,
    // Constants
    ENTITYID_UNKNOWN_READER,
    ENTITYID_UNKNOWN_WRITER,
    GUID_PREFIX_LEN,
    MAX_BITMAP_BITS,
    RTPS_FRACTION_HALF_SECOND,
};

// ============================================================================
// Public re-exports: Writer-side (TX)
// ============================================================================

pub use writer::{
    // Transmitters
    GapTx,
    HeartbeatTx,
    InfoDstTx,
    InfoTsTx,
    // Retransmission handler
    WriterRetransmitHandler,
    // Constants
    DEFAULT_JITTER_PCT,
    DEFAULT_PERIOD_MS,
};

// ============================================================================
// Public re-exports: Reader-side (RX)
// ============================================================================

pub use reader::{
    // Receivers
    GapRx,
    HeartbeatRx,
    InfoDstRx,
    InfoTsRx,
    // NACK scheduler
    NackScheduler,
    // Retransmission handler
    ReaderRetransmitHandler,
};

// ============================================================================
// Public re-exports: History cache
// ============================================================================

pub use history_cache::{CacheEntry, HistoryCache, LENGTH_UNLIMITED};

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
//! | `HeartbeatRx` | Reader processes heartbeats and derives missing ranges; feeds the fallback ACKNACK path in `dds::reader::heartbeat` (no `control_tx`) |
//! | `NackScheduler` | Standalone single-sequence-space gap/backoff bookkeeping utility (see `examples/reliable_demo.rs`); not wired to a live DataReader |
//! | `GapTracker` | Standalone sequence-number gap tracker underlying `NackScheduler`; same utility status, not wired to a live DataReader |
//! | `HistoryCache` | Writer stores samples for retransmission |
//! | `ReliableMetrics` | Observability counters (heartbeats, NACKs, retransmits) |
//!
//! The DataReader's actual repair path in production is the per-writer
//! `ReaderProxyRegistry` (`core::reader`), credited on every admitted
//! sample, and the control-plane ACKNACK built from it
//! (`core::discovery::multicast::control`). `NackScheduler` and
//! `GapTracker` above are honest, standalone bookkeeping types; they are
//! not consulted when building a live ACKNACK.
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
pub(crate) mod local_ack;

// ============================================================================
// Public re-exports: Core types
// ============================================================================

pub use gap_tracker::GapTracker;
pub use metrics::{
    ReliableMetrics, TAG_CONTROLS_REFUSED, TAG_GAPS_DETECTED, TAG_HEARTBEATS_SENT,
    TAG_MAX_GAP_SIZE, TAG_NACKS_SENT, TAG_OUT_OF_ORDER, TAG_RETRANSMIT_RECEIVED,
    TAG_RETRANSMIT_SENT,
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
    ENTITYID_UNKNOWN,
    GUID_PREFIX_LEN,
    MAX_BITMAP_BITS,
    RTPS_FRACTION_HALF_SECOND,
};

/// ENTITYID_UNKNOWN under a reader-side name.
///
/// RTPS defines a single ENTITYID_UNKNOWN; there is no reader-side
/// variant. Up to 1.4 this constant was `00 00 00 C7`, which a receiver
/// reads as the entity `00 00 00` of kind "built-in reader with key": a
/// reader no participant has, so a GAP carrying it reached nobody.
#[deprecated(
    since = "1.5.0",
    note = "RTPS has one ENTITYID_UNKNOWN; use `ENTITYID_UNKNOWN` (this constant was 00 00 00 C7 up to 1.4)"
)]
pub const ENTITYID_UNKNOWN_READER: EntityId = ENTITYID_UNKNOWN;

/// ENTITYID_UNKNOWN under a writer-side name.
///
/// RTPS defines a single ENTITYID_UNKNOWN; there is no writer-side
/// variant. Up to 1.4 this constant was `00 00 00 C2`, the entity
/// `00 00 00` of kind "built-in writer with key", which is no writer.
#[deprecated(
    since = "1.5.0",
    note = "RTPS has one ENTITYID_UNKNOWN; use `ENTITYID_UNKNOWN` (this constant was 00 00 00 C2 up to 1.4)"
)]
pub const ENTITYID_UNKNOWN_WRITER: EntityId = ENTITYID_UNKNOWN;

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

pub use history_cache::{
    CacheEntry, CachedChange, ChangeKind, ChangeMetadata, GroupWindow, HistoryCache,
    LENGTH_UNLIMITED,
};
pub(crate) use history_cache::{
    CoherentReplayAdmission, CoherentReplayIntegrity, GroupRetention, InFlight, Producer,
};

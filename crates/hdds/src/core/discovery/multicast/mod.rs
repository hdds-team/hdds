// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Multicast discovery implementation (SPDP/SEDP).
//!
//! Implements RTPS-compatible participant and endpoint discovery via UDP multicast.
//! Designed for zero-allocation hot-path with lock-free buffer pooling.
//!
//! # Architecture
//!
//! ```text
//! MulticastListener (thread)
//!     v UDP recv_from()
//! RxPool (lock-free buffer acquire)
//!     v classify_packet()
//! RxRing (SPSC queue)
//!     v poll()
//! DiscoveryFsm (state machine)
//!     v parse_spdp/parse_sedp
//! ParticipantDB (hash map + topic index)
//! ```
//!
//! # Modules
//!
//! - [`meta`]: Packet metadata and classification types
//! - [`pool`]: Lock-free buffer pool for zero-allocation RX
//! - [`tiny_vec`]: Small-vector optimization for topic index
//! - [`dialect_detector`]: Auto-detect vendor implementation
//! - [`probe_metrics`]: Telemetry for dialect detection
//! - [`overlapped_sockets`]: Zero-loss hot-reconfiguration
//!
//! # Performance Targets
//!
//! - Latency p99 < 10 us (listener -> FSM processed)
//! - Throughput: 0 packet loss on 1000-packet burst
//! - Memory: < 200 KB total (pool + ring + DB)
pub mod classifier;
pub mod control;
pub mod control_builder;
pub mod control_metrics;
pub mod control_parser;
pub mod control_types;
pub mod dialect_detector;
pub mod fsm;
pub mod lease;
pub mod listener;
pub mod meta;
pub mod overlapped_sockets;
pub mod pool;
pub mod probe_metrics;
pub mod rtps_packet;
pub mod spdp;
pub mod tiny_vec;

pub use classifier::classify_rtps;
pub use control::ControlHandler;
pub use control_metrics::{ControlMetrics, ControlMetricsSnapshot};
pub use control_parser::{parse_heartbeat_submessage, parse_nack_frag_submessage};
pub use control_types::{ControlMessage, ControlMessageKind, HeartbeatInfo, NackFragInfo};
pub use fsm::{
    DiscoveryFsm, DiscoveryListener, DiscoveryMetrics, EndpointInfo, EndpointKind, ParticipantDB,
    SecurityValidator, TopicRegistry,
};
pub use lease::LeaseTracker;
pub use listener::{DiscoveryCallback, ListenerMetrics, MulticastListener};

// Re-export config constants for backward compatibility
pub use crate::config::{MULTICAST_GROUP, SPDP_MULTICAST_PORT_DOMAIN0 as MULTICAST_PORT};
pub use meta::{FragmentMetadata, PacketKind, RtpsContext, RxMeta};
// MIGRATION: parse_*, build_*, ParseError, SedpData, SpdpData -> use protocol::discovery directly
pub use dialect_detector::should_skip_spdp_barrier_for_packet;
pub use pool::RxPool;
pub use rtps_packet::{
    build_heartbeat_submessage, build_heartbeat_submessage_final, build_sedp_rtps_packet,
    build_spdp_rtps_packet, get_publications_last_seq, get_subscriptions_last_seq,
    next_publications_seq, next_subscriptions_seq, SedpEndpointKind,
};
pub use spdp::{FsmState, ParticipantInfo};
pub use tiny_vec::TinyVec;

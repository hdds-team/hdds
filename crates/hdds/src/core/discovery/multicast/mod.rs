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
pub mod directed_writer;
pub mod fsm;
pub mod lease;
pub mod listener;
pub mod meta;
pub mod overlapped_sockets;
pub mod pool;
pub mod probe_metrics;
pub mod rtps_packet;
pub mod sedp_history;
pub mod spdp;
pub mod tiny_vec;

pub use classifier::classify_rtps;
// Not public: "every DATA of this datagram" is how the listener feeds
// discovery, not something a user of the crate composes with.
pub(crate) use classifier::for_each_data_submessage;
pub(crate) use classifier::{scan_all_addressed_data_frags_with_qos, FragInlineQos};
pub use classifier::{scan_all_data_frags, ScannedFrag};
pub use control::ControlHandler;
pub use control_metrics::{ControlMetrics, ControlMetricsSnapshot};
pub use control_types::{ControlMessage, ControlMessageKind, HeartbeatInfo, NackFragInfo};
pub use fsm::{
    DiscoveryFsm, DiscoveryListener, DiscoveryMetrics, EndpointInfo, EndpointKind, ParticipantDB,
    SecurityValidator, TopicRegistry,
};
pub(crate) use fsm::{SedpChannel, SpdpVerdict};
pub use lease::LeaseTracker;
pub use listener::{DiscoveryCallback, ListenerMetrics, MulticastListener};
// Not public: a routing target is plumbing, and the only caller outside
// the listener is the participant's own Discovery Server session.
pub(crate) use listener::PacketDispatch;

// Re-export config constants for backward compatibility
pub use crate::config::{MULTICAST_GROUP, SPDP_MULTICAST_PORT_DOMAIN0 as MULTICAST_PORT};
pub use meta::{FragmentGeometry, FragmentMetadata, Origin, PacketKind, RtpsContext, RxMeta};
// MIGRATION: parse_*, build_*, ParseError, SedpData, SpdpData -> use protocol::discovery directly
pub use dialect_detector::should_skip_spdp_barrier_for_packet;
pub use pool::RxPool;
#[cfg(test)]
pub(crate) use rtps_packet::build_sedp_rtps_packet;
pub use rtps_packet::{
    build_heartbeat_submessage, build_heartbeat_submessage_final, build_sedp_dispose_packet,
    build_sedp_rtps_packet_for, build_sedp_rtps_packet_secured, build_spdp_dispose_packet,
    build_spdp_rtps_packet, get_publications_last_seq, get_subscriptions_last_seq,
    next_publications_seq, next_subscriptions_seq, SedpEndpointKind, TypeObjectPid,
};
pub use sedp_history::{sedp_gap, SedpHistory, SedpSend};
pub use spdp::{FsmState, ParticipantInfo};
pub use tiny_vec::TinyVec;

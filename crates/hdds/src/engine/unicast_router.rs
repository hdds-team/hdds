// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Standalone RTPS message router for unicast transports (TCP, QUIC).
//!
//! v234-sprint6: This module provides a transport-agnostic function that takes
//! a raw RTPS message (header + submessages) and routes it through the existing
//! `TopicRegistry` / demux infrastructure.
//!
//! Unlike the multicast `router_loop` which consumes from an `ArrayQueue<(RxMeta, u8)>`,
//! this function is called directly by TCP/QUIC event handlers — no ring buffer,
//! no dedicated thread. The caller owns the dispatch loop.
//!
//! # Data flow
//! ```text
//! TCP poll()  ──→ MessageReceived { payload } ──→ route_raw_rtps_message()
//! QUIC event  ──→ MessageReceived { payload } ──→ route_raw_rtps_message()
//!                                                   ├── classify_rtps(payload)
//!                                                   ├── Data      → route_data_packet()
//!                                                   ├── DataFrag  → route_data_frag_packet()
//!                                                   ├── Heartbeat → registry.deliver_heartbeat()
//!                                                   ├── AckNack   → registry.deliver_nack()
//!                                                   └── other     → dropped/ignored (logged)
//! ```

use std::sync::atomic::Ordering;
use std::sync::Mutex;

use crate::core::discovery::multicast::{classify_rtps, PacketKind};
use crate::core::discovery::FragmentBuffer;
use crate::engine::demux::TopicRegistry;
use crate::engine::router::{
    route_data_frag_packet, route_data_packet, RouteStatus, RouterMetrics,
};

// ============================================================================
// Result type
// ============================================================================

/// Outcome of routing a raw RTPS message from a unicast transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicastRouteOutcome {
    /// Successfully delivered to at least one subscriber.
    Delivered,
    /// Packet was valid but no subscriber matched (orphaned).
    Orphaned,
    /// Packet was dropped (parse error, invalid submessage, etc.).
    Dropped,
    /// Packet type not handled by unicast router (SPDP, SEDP, NackFrag, etc.).
    Ignored,
}

// ============================================================================
// Main entry point
// ============================================================================

/// Route a raw RTPS message through the demux/topic registry.
///
/// This is the **single entry point** for TCP and QUIC transports to feed
/// received data into the HDDS routing engine.
///
/// # Arguments
/// * `payload`         — Complete RTPS message (header at offset 0 + submessages)
/// * `registry`        — Shared topic registry (thread-safe)
/// * `metrics`         — Shared router metrics (atomic counters)
/// * `fragment_buffer` — Optional fragment reassembly buffer for DATA_FRAG.
///   Pass `None` if fragmentation is not expected on this transport.
///
/// # Thread safety
/// All arguments are designed for concurrent access. This function can be called
/// from any thread or async task without external synchronisation.
///
/// # v234-sprint6
pub fn route_raw_rtps_message(
    payload: &[u8],
    registry: &TopicRegistry,
    metrics: &RouterMetrics,
    fragment_buffer: Option<&Mutex<FragmentBuffer>>,
) -> UnicastRouteOutcome {
    // Step 1: Classify the RTPS message
    let (kind, data_offset, frag_meta, _rtps_ctx) = classify_rtps(payload);

    let len = payload.len();

    // Step 2: Dispatch based on submessage type
    match kind {
        PacketKind::Data => {
            let status = route_data_packet(payload, len, data_offset, registry, metrics);
            match status {
                RouteStatus::Delivered => UnicastRouteOutcome::Delivered,
                RouteStatus::Orphaned => UnicastRouteOutcome::Orphaned,
                RouteStatus::Dropped => UnicastRouteOutcome::Dropped,
            }
        }

        PacketKind::DataFrag => {
            let fb = match fragment_buffer {
                Some(fb) => fb,
                None => {
                    log::warn!(
                        "[unicast-router] DATA_FRAG received but no fragment buffer configured"
                    );
                    metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
                    return UnicastRouteOutcome::Dropped;
                }
            };
            let status = route_data_frag_packet(
                payload,
                len,
                data_offset,
                frag_meta.as_ref(),
                fb,
                registry,
                metrics,
            );
            match status {
                RouteStatus::Delivered => UnicastRouteOutcome::Delivered,
                RouteStatus::Orphaned => UnicastRouteOutcome::Orphaned,
                RouteStatus::Dropped => UnicastRouteOutcome::Dropped,
            }
        }

        PacketKind::Heartbeat => {
            let errors = registry.deliver_heartbeat(payload);
            if errors > 0 {
                metrics
                    .delivery_errors
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }
            UnicastRouteOutcome::Delivered
        }

        PacketKind::AckNack => {
            let errors = registry.deliver_nack(payload);
            if errors > 0 {
                metrics
                    .delivery_errors
                    .fetch_add(errors as u64, Ordering::Relaxed);
            }
            UnicastRouteOutcome::Delivered
        }

        // NackFrag and HeartbeatFrag require response generation (sending NACK_FRAG back)
        // which needs transport handle + our_guid_prefix. Deferred to Sprint 6b.
        PacketKind::NackFrag | PacketKind::HeartbeatFrag => {
            log::debug!(
                "[unicast-router] {:?} ({} bytes) — deferred (needs transport for response)",
                kind,
                len
            );
            UnicastRouteOutcome::Ignored
        }

        // Discovery packets (SPDP, SEDP) should be handled by discovery FSM, not user router
        PacketKind::SPDP | PacketKind::SEDP | PacketKind::TypeLookup => {
            log::trace!(
                "[unicast-router] {:?} packet ({} bytes) — ignored (discovery layer)",
                kind,
                len
            );
            UnicastRouteOutcome::Ignored
        }

        // INFO submessages are context-setting, not routable
        PacketKind::InfoTs | PacketKind::InfoSrc | PacketKind::InfoDst | PacketKind::InfoReply => {
            log::trace!("[unicast-router] {:?} — context submessage, ignored", kind);
            UnicastRouteOutcome::Ignored
        }

        PacketKind::Invalid => {
            log::debug!(
                "[unicast-router] Invalid RTPS packet ({} bytes), dropping",
                len
            );
            metrics.delivery_errors.fetch_add(1, Ordering::Relaxed);
            UnicastRouteOutcome::Dropped
        }

        other => {
            log::debug!(
                "[unicast-router] Unhandled {:?} ({} bytes), dropping",
                other,
                len
            );
            UnicastRouteOutcome::Dropped
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_metrics() -> RouterMetrics {
        RouterMetrics::new()
    }

    #[test]
    fn test_invalid_packet_returns_dropped() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Too short to be valid RTPS
        let result = route_raw_rtps_message(&[0u8; 4], &registry, &metrics, None);
        assert_eq!(result, UnicastRouteOutcome::Dropped);
    }

    #[test]
    fn test_empty_payload_returns_dropped() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        let result = route_raw_rtps_message(&[], &registry, &metrics, None);
        assert_eq!(result, UnicastRouteOutcome::Dropped);
    }

    #[test]
    fn test_valid_rtps_no_submessage() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Valid RTPS header but no submessages
        let mut pkt = vec![0u8; 20];
        pkt[0..4].copy_from_slice(b"RTPS");
        pkt[4] = 0x02; // version major
        pkt[5] = 0x03; // version minor

        let result = route_raw_rtps_message(&pkt, &registry, &metrics, None);
        // classify_rtps returns Unknown for header-only → Dropped
        assert!(
            result == UnicastRouteOutcome::Dropped || result == UnicastRouteOutcome::Ignored,
            "Expected Dropped or Ignored for header-only RTPS, got {:?}",
            result
        );
    }

    #[test]
    fn test_data_packet_no_subscribers() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Minimal RTPS DATA packet:
        // 20-byte header + 4-byte submessage header (DATA=0x15) + 20-byte DATA fields
        let mut pkt = vec![0u8; 44];
        pkt[0..4].copy_from_slice(b"RTPS");
        pkt[4] = 0x02;
        pkt[5] = 0x03;
        // Submessage at offset 20: DATA (0x15)
        pkt[20] = 0x15;
        pkt[21] = 0x01; // flags: little-endian
                        // octetsToNextHeader = 20 (enough for DATA submessage fields)
        pkt[22] = 20;
        pkt[23] = 0;

        let result = route_raw_rtps_message(&pkt, &registry, &metrics, None);
        // No topic registered, so should be Dropped or Orphaned
        assert!(
            result == UnicastRouteOutcome::Dropped || result == UnicastRouteOutcome::Orphaned,
            "Expected Dropped or Orphaned, got {:?}",
            result
        );
    }

    #[test]
    fn test_outcome_enum_completeness() {
        let outcomes = [
            UnicastRouteOutcome::Delivered,
            UnicastRouteOutcome::Orphaned,
            UnicastRouteOutcome::Dropped,
            UnicastRouteOutcome::Ignored,
        ];
        for o in &outcomes {
            let _ = format!("{:?}", o);
        }
    }

    #[test]
    fn test_data_frag_without_buffer_is_dropped() {
        let registry = TopicRegistry::new();
        let metrics = make_metrics();

        // Build a minimal DATA_FRAG packet (0x16)
        let mut pkt = vec![0u8; 60];
        pkt[0..4].copy_from_slice(b"RTPS");
        pkt[4] = 0x02;
        pkt[5] = 0x03;
        pkt[20] = 0x16; // DATA_FRAG submessage ID
        pkt[21] = 0x01;
        pkt[22] = 36; // octetsToNextHeader
        pkt[23] = 0;

        let result = route_raw_rtps_message(&pkt, &registry, &metrics, None);
        assert_eq!(result, UnicastRouteOutcome::Dropped);
        assert!(metrics.delivery_errors.load(Ordering::Relaxed) > 0);
    }
}

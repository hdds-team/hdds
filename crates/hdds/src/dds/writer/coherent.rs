// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Coherent-set bridge between a `DataWriter` and its parent `Publisher`.
//!
//! Implements the type-erased `CoherentWriter` trait the publisher uses to
//! drive the per-set End-of-Coherent-Set DATA submessage protocol per
//! RTPS v2.5 §8.7.5. Carries the minimum state needed to:
//!
//! 1. Read (and reset) the writer-scoped sequence number of the last
//!    sample the writer wrote into the active set; and
//! 2. Build + send the matching ECS DATA submessage on the writer's
//!    transport with a freshly-reserved writer SN, then refresh the
//!    HEARTBEAT scheduler so the new SN becomes visible to readers.

use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::EndpointRegistry;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::dds::publisher::CoherentWriter;
use crate::protocol::builder;
use crate::protocol::builder::RtpsEndpointContext;
use crate::reliability::HistoryCache;
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::heartbeat_scheduler::HeartbeatSchedulerState;

/// Shared coherent-set state. Held both by the `DataWriter` (which
/// publishes into it on every coherent write) and by the publisher's
/// registry (which drains it at `end_coherent_changes`).
///
/// All fields are clones / Arcs of state already on the writer; the
/// bridge does not own anything the writer doesn't, it just exposes
/// the minimum surface area to the publisher without leaking the
/// writer's generic `T` parameter.
pub(super) struct WriterCoherentBridge {
    topic: String,
    /// Shared `next_seq` counter — the bridge bumps this when emitting
    /// the ECS DATA so the writer's normal write() path keeps a
    /// monotonic SN space (RTPS v2.5 §8.3.5.4).
    next_seq: Arc<AtomicU64>,
    /// Writer-scoped SN of the last sample stamped into the active
    /// coherent set. Set by the writer's `coherent_context`, drained
    /// (swapped back to 0) by `take_last_sn_in_active_set` so a writer
    /// that wrote nothing between two `end_coherent_changes` calls is
    /// skipped (no useless ECS emission).
    last_sn_in_active_set: Arc<AtomicU64>,
    transport: Option<Arc<UdpTransport>>,
    rtps_endpoint: Option<RtpsEndpointContext>,
    history_cache: Option<Arc<HistoryCache>>,
    endpoint_registry: Option<EndpointRegistry>,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    heartbeat_scheduler_state: Option<Arc<HeartbeatSchedulerState>>,
}

impl WriterCoherentBridge {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        topic: String,
        next_seq: Arc<AtomicU64>,
        last_sn_in_active_set: Arc<AtomicU64>,
        transport: Option<Arc<UdpTransport>>,
        rtps_endpoint: Option<RtpsEndpointContext>,
        history_cache: Option<Arc<HistoryCache>>,
        endpoint_registry: Option<EndpointRegistry>,
        discovery_fsm: Option<Arc<DiscoveryFsm>>,
        heartbeat_scheduler_state: Option<Arc<HeartbeatSchedulerState>>,
    ) -> Self {
        Self {
            topic,
            next_seq,
            last_sn_in_active_set,
            transport,
            rtps_endpoint,
            history_cache,
            endpoint_registry,
            discovery_fsm,
            heartbeat_scheduler_state,
        }
    }

    /// Send the ECS DATA submessage to every discovered remote reader
    /// for the writer's topic. Mirrors the unicast-per-reader strategy
    /// used by `DataWriter::send_packet_to_endpoints` minus the
    /// partition / ownership filters (an ECS marker carries no user
    /// data; readers either match the writer or they don't).
    fn dispatch_ecs(&self, packet: &[u8]) {
        let Some(ref transport) = self.transport else {
            return;
        };
        let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);

        // Per-reader routing: prefer FSM-discovered reader locators so
        // the ECS reaches the same endpoints as the regular DATA path.
        let mut delivered = false;
        if let (Some(ref fsm), Some(ref reg)) = (&self.discovery_fsm, &self.endpoint_registry) {
            let readers = fsm.find_readers_for_topic(&self.topic);
            for reader in &readers {
                if let Some(local_pfx) = local_prefix {
                    if reader.participant_guid.as_bytes()[..12] == local_pfx {
                        continue;
                    }
                }
                let mut pguid_bytes = [0u8; 16];
                pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
                pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
                let participant_key = GUID::from_bytes(pguid_bytes);
                let dest = reg
                    .get_reader_locator(&reader.endpoint_guid)
                    .or_else(|| reg.get(&participant_key));
                if let Some(endpoint) = dest {
                    let mut patched = packet.to_vec();
                    if patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
                        patched[builder::READER_ENTITY_ID_OFFSET
                            ..builder::READER_ENTITY_ID_OFFSET + 4]
                            .copy_from_slice(&reader.endpoint_guid.entity_id);
                    }
                    if transport
                        .send_user_data_unicast(&patched, &endpoint)
                        .is_ok()
                    {
                        delivered = true;
                    }
                }
            }
        }

        if !delivered {
            // No discovered readers (or none reachable): broadcast on
            // user-data multicast as a fallback. The receiver-side
            // ECS recogniser ignores markers it doesn't have a
            // matching writer for, so the multicast fallback is safe.
            let _ = transport.send_user_data_multicast(packet);
        }
    }
}

impl CoherentWriter for WriterCoherentBridge {
    fn take_last_sn_in_active_set(&self) -> Option<u64> {
        let sn = self.last_sn_in_active_set.swap(0, Ordering::AcqRel);
        if sn == 0 {
            None
        } else {
            Some(sn)
        }
    }

    fn emit_ecs_data(&self, coherent_sn: u64, group_sn: Option<u64>) {
        let Some(ctx) = self.rtps_endpoint else {
            log::debug!(
                "[writer-coherent] ECS skipped (no RTPS endpoint context) topic='{}'",
                self.topic
            );
            return;
        };

        // Reserve a fresh writer SN. RTPS v2.5 §8.3.5.4 requires every
        // submessage to use a unique monotonic SN; the ECS shares the
        // writer's SN space because the receiver's late-arrival /
        // retransmit logic keys on `writerSN`.
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);

        // Publisher EntityId tag for inline-QoS PID_GROUP_ENTITY_ID. HDDS
        // pins entityKey=0x000001 with kind 0x08 (USER_DEFINED_PUBLISHER_GROUP)
        // since the current builder topology hosts a single Publisher per
        // Participant; the receiver uses it to cluster writers in the same
        // Publisher for GROUP-scope coherent_access (RTPS v2.5 §9.3.2.1 +
        // DDS v1.4 §2.2.3.6).
        let publisher_entity_id = Some([0x00, 0x00, 0x01, 0x08]);

        let packet = builder::build_ecs_data_submessage(
            &ctx,
            &self.topic,
            seq,
            coherent_sn,
            group_sn,
            publisher_entity_id,
        );
        if packet.is_empty() {
            log::debug!(
                "[writer-coherent] ECS build returned empty packet topic='{}' seq={}",
                self.topic,
                seq
            );
            return;
        }

        self.dispatch_ecs(&packet);

        // Insert an empty payload into history cache so a NACK on the
        // ECS slot retransmits the inline-QoS-only marker correctly
        // (the receiver re-recognises ECS by its flags + PIDs, not
        // by the payload).
        if let Some(ref cache) = self.history_cache {
            if let Err(e) = cache.insert(seq, &[]) {
                log::debug!(
                    "[writer-coherent] ECS cache insert failed topic='{}' seq={}: {}",
                    self.topic,
                    seq,
                    e
                );
            }
        }

        // Refresh the periodic HEARTBEAT scheduler so it advertises
        // the ECS in its `lastSN` field. Without this nudge a reader
        // that misses the unicast ECS packet would only learn about
        // it at the next HB tick, which delays the per-set commit.
        if let Some(ref state) = self.heartbeat_scheduler_state {
            state.update_seq(seq);
        }

        log::debug!(
            "[writer-coherent] ECS emitted topic='{}' seq={} coherent_sn={} group_sn={:?}",
            self.topic,
            seq,
            coherent_sn,
            group_sn
        );
    }
}

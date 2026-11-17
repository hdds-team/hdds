// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Coherent-set bridge between a `DataWriter` and its parent `Publisher`.
//!
//! Implements the type-erased `CoherentWriter` trait the publisher uses to
//! drive the per-set End-of-Coherent-Set DATA submessage protocol per
//! RTPS v2.5 sec. 8.7.5. Carries the minimum state needed to:
//!
//! 1. Read (and reset) the writer-scoped sequence number of the last
//!    sample the writer wrote into the active set; and
//! 2. Build + send the matching ECS DATA submessage on the writer's
//!    transport with a freshly-reserved writer SN, then refresh the
//!    HEARTBEAT scheduler so the new SN becomes visible to readers.

use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::EndpointRegistry;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::{
    HDDS_VENDOR_ID_U16, INTERCOM_VENDOR_ID_U16, RTPS_ENTITYID_PARTICIPANT,
};
use crate::dds::publisher::CoherentWriter;
use crate::protocol::builder;
use crate::protocol::builder::RtpsEndpointContext;
use crate::reliability::HistoryCache;
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::heartbeat_scheduler::HeartbeatSchedulerState;
use super::intra_coherent::IntraCoherentSets;

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
    /// Shared `next_seq` counter -- the bridge bumps this when emitting
    /// the ECS DATA so the writer's normal write() path keeps a
    /// monotonic SN space (RTPS v2.5 sec. 8.3.5.4).
    next_seq: Arc<AtomicU64>,
    /// Writer-scoped SN of the last sample stamped into the active
    /// coherent set. Set by the writer's `coherent_context`, drained
    /// (swapped back to 0) by `take_last_sn_in_active_set` so a writer
    /// that wrote nothing between two `end_coherent_changes` calls is
    /// skipped (no useless ECS emission).
    last_sn_in_active_set: Arc<AtomicU64>,
    /// The writer's first SN in its active coherent set (the writer's
    /// `coherent_set_first_sn`): the `PID_COHERENT_SET` of its end of set in
    /// the spec GROUP form (Table 9.23).
    first_sn_in_active_set: Arc<AtomicU64>,
    wire_windows: Arc<crate::protocol::dialect::sequence_window::WriterWindows>,
    transport: Option<Arc<UdpTransport>>,
    rtps_endpoint: Option<RtpsEndpointContext>,
    history_cache: Option<Arc<HistoryCache>>,
    endpoint_registry: Option<EndpointRegistry>,
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    /// The participant-level routing a DATA change takes when discovery knows
    /// no reader of its topic yet (`DataWriter`): an end of set takes the same
    /// route. Off for a partitioned writer, whose DATA fallback is filtered by
    /// partition, which this bridge does not hold.
    participant_fallback: bool,
    heartbeat_scheduler_state: Option<Arc<HeartbeatSchedulerState>>,
    /// Boundary SN of the previous set-close marker sent to an intercom
    /// (0x0105) reader, not yet retired by GAP, per reader. HDDS defers the
    /// marker's retirement GAP by one set-close (~one set period): GAP(N)
    /// is sent immediately before marker(N+stride). Retiring the marker in
    /// the same burst instead amounts to never sending a marker at all (the
    /// GAP retracts the SN the reader just received, so the reader never
    /// sees the set-close event DDSI-RTPS 2.5 8.7.6 defines). The repair of
    /// a NACK on a pending boundary leaves it alone
    /// (`protocol::dialect::close_gap`). Lives in the history cache, which
    /// the NACK handler shares; this one is used when the writer has none.
    fallback_deferred: crate::protocol::dialect::close_gap::DeferredCloseGaps,
    /// This writer's coherent sets awaiting local (merger) delivery, shared
    /// with the `DataWriter`: `end_coherent_changes` closes its part of the
    /// set under `set_lock` (`close_intra_set`) and delivers what is
    /// complete once the lock is released (`deliver_intra_sets`), whatever
    /// the writer's transport -- RTPS v2.5 Sec.8.7.6 and DDS v1.4
    /// Sec.2.2.3.6 are not RTPS-only guarantees.
    intra_sets: Arc<IntraCoherentSets>,
    /// What the writer's own `wait_for_acknowledgments` reads, shared with
    /// the `DataWriter` so the Publisher's wait is the same wait: whether
    /// the writer is RELIABLE, and its per-reader acknowledgment watermarks.
    /// Without them (`None`) there is nothing to wait for.
    ack_wait: Option<AckWait>,
}

/// See [`WriterCoherentBridge::ack_wait`].
struct AckWait {
    reliable: bool,
    ack_track: super::nack::AckTrack,
}

impl WriterCoherentBridge {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        topic: String,
        next_seq: Arc<AtomicU64>,
        last_sn_in_active_set: Arc<AtomicU64>,
        first_sn_in_active_set: Arc<AtomicU64>,
        wire_windows: Arc<crate::protocol::dialect::sequence_window::WriterWindows>,
        transport: Option<Arc<UdpTransport>>,
        rtps_endpoint: Option<RtpsEndpointContext>,
        history_cache: Option<Arc<HistoryCache>>,
        endpoint_registry: Option<EndpointRegistry>,
        discovery_fsm: Option<Arc<DiscoveryFsm>>,
        heartbeat_scheduler_state: Option<Arc<HeartbeatSchedulerState>>,
        intra_sets: Arc<IntraCoherentSets>,
    ) -> Self {
        Self {
            topic,
            next_seq,
            last_sn_in_active_set,
            first_sn_in_active_set,
            wire_windows,
            transport,
            rtps_endpoint,
            history_cache,
            endpoint_registry,
            discovery_fsm,
            participant_fallback: false,
            heartbeat_scheduler_state,
            fallback_deferred: Default::default(),
            intra_sets,
            ack_wait: None,
        }
    }

    /// Let the Publisher wait for this writer's acknowledgments
    /// (`CoherentWriter::wait_for_acknowledgments_until`).
    /// Route an end of set to the participants a DATA change reaches while
    /// discovery knows no reader of the topic (see `participant_fallback`).
    pub(super) fn with_participant_fallback(mut self, on: bool) -> Self {
        self.participant_fallback = on;
        self
    }

    pub(super) fn with_acknowledgments(
        mut self,
        reliable: bool,
        ack_track: super::nack::AckTrack,
    ) -> Self {
        self.ack_wait = Some(AckWait {
            reliable,
            ack_track,
        });
        self
    }

    /// The end of set to each participant the DATA fallback reaches, with the
    /// same admission, group-window and form rules (`DataWriter`'s
    /// participant routing). Returns whether one datagram left.
    fn dispatch_ecs_to_participants(
        &self,
        transport: &UdpTransport,
        packet: &[u8],
        spec_packet: Option<&[u8]>,
        seq: u64,
    ) -> bool {
        let Some(ref registry) = self.endpoint_registry else {
            return false;
        };
        let local_guid = self
            .rtps_endpoint
            .map(|ctx| GUID::new(ctx.guid_prefix, RTPS_ENTITYID_PARTICIPANT));
        let fsm = self.discovery_fsm.as_deref();
        let mut delivered = false;
        for (guid, endpoint) in registry.entries() {
            if Some(guid) == local_guid {
                continue;
            }
            if self.wire_windows.is_group()
                && fsm.is_some_and(|fsm| fsm.requires_group_window(&guid.prefix))
            {
                continue;
            }
            if !super::runtime::fallback_admits(fsm, &guid, &self.topic) {
                continue;
            }
            // The native end of set is the form of an HDDS peer (or a peer
            // speaking the spec group form). A classic peer whose vendor is not
            // resolved would read it as the start of a new set; its repair
            // sends the form its vendor takes once known.
            // A plain participant (D18, plain) takes no end-of-set marker: the
            // close SN is retired with a GAP, its readers not being known here.
            if self.wire_windows.is_group()
                && fsm.is_some_and(|fsm| fsm.speaks_plain_group(&guid.prefix))
            {
                let Some(ctx) = self.rtps_endpoint else {
                    continue;
                };
                // ENTITYID_UNKNOWN: the GAP names no particular reader.
                let gap = super::nack::plain_close_gap(&ctx, [0u8; 4], seq);
                if !gap.is_empty()
                    && self
                        .wire_windows
                        .send(transport, &gap, &endpoint, Some(guid))
                        .is_ok()
                {
                    delivered = true;
                }
                continue;
            }
            let native_peer = fsm.is_some_and(|fsm| {
                fsm.vendor_id_for_participant(&guid) == Some(HDDS_VENDOR_ID_U16)
                    || fsm.speaks_spec_group(&guid.prefix)
            });
            if !native_peer {
                continue;
            }
            let form = match (spec_packet, fsm) {
                (Some(spec), Some(fsm)) if fsm.speaks_spec_group(&guid.prefix) => spec,
                _ => packet,
            };
            if self
                .wire_windows
                .send(transport, form, &endpoint, Some(guid))
                .is_ok()
            {
                delivered = true;
            }
        }
        delivered
    }

    /// Where the end of a set reaches `reader`: its unicast destination
    /// and whether it is reached through a classic GROUP window, or `None`
    /// when the reader is skipped (a classic reader outside the window, a
    /// reader of this participant, no locator known).
    fn reader_route(
        &self,
        fsm: &DiscoveryFsm,
        reg: &EndpointRegistry,
        reader: &crate::core::discovery::multicast::EndpointInfo,
        local_prefix: Option<[u8; 12]>,
    ) -> Option<(std::net::SocketAddr, bool)> {
        let classic_window =
            self.wire_windows.is_group() && fsm.requires_group_window(&reader.endpoint_guid.prefix);
        if classic_window && !self.wire_windows.contains(reader.endpoint_guid) {
            return None;
        }
        if let Some(local_pfx) = local_prefix {
            if reader.participant_guid.as_bytes()[..12] == local_pfx {
                return None;
            }
        }
        let mut pguid_bytes = [0u8; 16];
        pguid_bytes[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
        pguid_bytes[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let participant_key = GUID::from_bytes(pguid_bytes);
        reg.get_reader_locator(&reader.endpoint_guid)
            .or_else(|| reg.get(&participant_key))
            .map(|endpoint| (endpoint, classic_window))
    }

    /// The pending retirement GAP of an InterCOM set boundary, sent now to
    /// every InterCOM reader of the topic. Called for EVERY writer of the
    /// Publisher before any of them emits its end of set, so the readers
    /// of all the topics release the set they withheld within one burst of
    /// GAPs, not interleaved with the markers: a read cycle that lands
    /// between two topics' releases returns a part of the set.
    fn release_deferred_boundaries(&self) {
        let (Some(transport), Some(fsm), Some(reg), Some(ctx)) = (
            self.transport.as_ref(),
            self.discovery_fsm.as_ref(),
            self.endpoint_registry.as_ref(),
            self.rtps_endpoint,
        ) else {
            return;
        };
        // A writer with nothing in the set emits no end of set, and keeps
        // its boundary pending until it does.
        if self.last_sn_in_active_set.load(Ordering::Acquire) == 0 {
            return;
        }
        let deferred = self
            .history_cache
            .as_deref()
            .map_or(&self.fallback_deferred, |cache| &cache.deferred_close_gaps);
        for reader in &fsm.find_readers_for_topic(&self.topic) {
            if fsm.vendor_id_for_participant(&reader.participant_guid)
                != Some(INTERCOM_VENDOR_ID_U16)
            {
                continue;
            }
            let Some((endpoint, classic_window)) =
                self.reader_route(fsm, reg, reader, Some(ctx.guid_prefix))
            else {
                continue;
            };
            let Some(prev) = deferred.take(reader.endpoint_guid.as_bytes()) else {
                continue;
            };
            let gap = builder::build_gap_packet_from_parts(
                &reader.endpoint_guid.entity_id,
                &ctx.writer_entity_id,
                prev,
                prev + 1,
                &[],
                ctx.guid_prefix,
            );
            if !gap.is_empty() {
                let _ = self.wire_windows.send_classed(
                    transport,
                    &gap,
                    &endpoint,
                    reader.endpoint_guid,
                    classic_window,
                );
            }
        }
    }

    /// Send the ECS DATA submessage to every discovered remote reader
    /// for the writer's topic. Mirrors the unicast-per-reader strategy
    /// used by `DataWriter::send_packet_to_endpoints` minus the
    /// partition / ownership filters (an ECS marker carries no user
    /// data; readers either match the writer or they don't).
    /// `spec_packet`: the end of set in the spec GROUP form, for readers of
    /// the spec class (D18); every other reader gets the form it gets today.
    fn dispatch_ecs(&self, packet: &[u8], spec_packet: Option<&[u8]>, seq: u64) {
        let Some(ref transport) = self.transport else {
            return;
        };
        let no_fsm_readers = self
            .discovery_fsm
            .as_ref()
            .is_none_or(|fsm| fsm.find_readers_for_topic(&self.topic).is_empty());
        let local_prefix = self.rtps_endpoint.map(|ctx| ctx.guid_prefix);

        // Per-reader routing: prefer FSM-discovered reader locators so
        // the ECS reaches the same endpoints as the regular DATA path.
        let mut delivered = false;
        if let (Some(ref fsm), Some(ref reg)) = (&self.discovery_fsm, &self.endpoint_registry) {
            let readers = fsm.find_readers_for_topic(&self.topic);
            for reader in &readers {
                if let Some((endpoint, classic_window)) =
                    self.reader_route(fsm, reg, reader, local_prefix)
                {
                    // Per-reader dialect close form (this loop is UNICAST per
                    // reader; each vendor gets its own datagram):
                    //
                    // * vendor 0x0105 (InterCOM dialect): bare D=0 close
                    //   marker occupying the boundary SN in-burst, then a
                    //   single-SN GAP (gapStart = prev, base = prev + 1,
                    //   empty bitmap, RTPS v2.5 SS8.3.8.4) retiring the
                    //   PREVIOUS boundary SN, deferred by one set-close.
                    //   Every set close is a real empty DATA at the boundary
                    //   SN (no reliable hole; per DDSI-RTPS 2.5 8.7.6 a DATA
                    //   without a coherent-set inline QoS ends the open
                    //   set), and its retirement GAP rides ~one set period
                    //   later, immediately before the next marker. GAPing
                    //   the boundary SN in the same burst as (or instead
                    //   of) the marker retracts the close event before the
                    //   reader can act on it, so the reader never sees the
                    //   set end. Both datagrams are unicast to that reader
                    //   ONLY -- never multicast, which would retire the SN
                    //   for vendors that need the native ECS DATA.
                    // * Other classic-model subscribers (vendorId != HDDS):
                    //   they close a coherent set on a sample carrying no
                    //   PID_COHERENT_SET (8.7.6), so they get a bare D=0
                    //   close marker instead of the HDDS ECS DATA -- whose
                    //   distinct PID_COHERENT_SET they would read as the
                    //   start of a new, one-sample set.
                    // * HDDS readers (and peers whose vendor is not yet
                    //   resolved) get the real ECS DATA they need for on_ecs.
                    let reader_vendor = fsm.vendor_id_for_participant(&reader.participant_guid);
                    let is_classic_vendor =
                        matches!(reader_vendor, Some(v) if v != HDDS_VENDOR_ID_U16);
                    let spec_reader = spec_packet.is_some()
                        && fsm.speaks_spec_group(&reader.participant_guid.prefix);
                    // A plain reader (D18, plain) takes no end-of-set marker:
                    // the close SN is retired with a unicast GAP to it.
                    let plain_reader = self.wire_windows.is_group()
                        && fsm.speaks_plain_group(&reader.participant_guid.prefix);
                    let datagram = if plain_reader {
                        let Some(ctx) = self.rtps_endpoint else {
                            continue;
                        };
                        let gap =
                            super::nack::plain_close_gap(&ctx, reader.endpoint_guid.entity_id, seq);
                        if gap.is_empty() {
                            continue;
                        }
                        gap
                    } else if let (true, Some(spec)) = (spec_reader, spec_packet) {
                        let mut patched = spec.to_vec();
                        if patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
                            patched[builder::READER_ENTITY_ID_OFFSET
                                ..builder::READER_ENTITY_ID_OFFSET + 4]
                                .copy_from_slice(&reader.endpoint_guid.entity_id);
                        }
                        patched
                    } else if is_classic_vendor {
                        let Some(ctx) = self.rtps_endpoint else {
                            continue;
                        };
                        if reader_vendor == Some(INTERCOM_VENDOR_ID_U16) {
                            // Classic-model set close for intercom: an
                            // UNTAGGED empty DATA occupies the boundary
                            // SN in-burst (a sample with no
                            // PID_COHERENT_SET ends the open set), and
                            // the PREVIOUS boundary SN is retired by GAP
                            // one set-close later - never in the same
                            // burst as its own marker, which would
                            // retract the close event it just delivered.
                            // The marker delivers the close event; the
                            // deferred GAP then retires the boundary SN so
                            // repair traffic does not re-request it.
                            let deferred = self
                                .history_cache
                                .as_deref()
                                .map_or(&self.fallback_deferred, |cache| {
                                    &cache.deferred_close_gaps
                                });
                            if let Some(prev) = deferred.defer(
                                reader.endpoint_guid.as_bytes(),
                                seq,
                                std::time::Instant::now(),
                            ) {
                                let gap = builder::build_gap_packet_from_parts(
                                    &reader.endpoint_guid.entity_id,
                                    &ctx.writer_entity_id,
                                    prev,
                                    prev + 1,
                                    &[],
                                    ctx.guid_prefix,
                                );
                                if !gap.is_empty() {
                                    let _ = self.wire_windows.send_classed(
                                        transport,
                                        &gap,
                                        &endpoint,
                                        reader.endpoint_guid,
                                        classic_window,
                                    );
                                }
                            }
                        }
                        // Marker form, shared with `WriterReplayState::
                        // replay_to`'s late-joiner ECS close replay via
                        // `ecs_close_form_for` (see that function's doc):
                        // both agree InterCOM gets the bare close MARKER,
                        // never the on_nack-only single-SN GAP form.
                        match ecs_close_form_for(
                            reader_vendor,
                            Some(&ctx),
                            reader.endpoint_guid.entity_id,
                            seq,
                            builder::now_rtps_timestamp(),
                            packet,
                        ) {
                            Some(d) => d,
                            None => continue,
                        }
                    } else {
                        // Native ECS form: patches the already-built,
                        // already-timestamped `packet`, so the source_ts
                        // argument is inert here (see `ecs_close_form_for`).
                        match ecs_close_form_for(
                            reader_vendor,
                            self.rtps_endpoint.as_ref(),
                            reader.endpoint_guid.entity_id,
                            seq,
                            (0, 0),
                            packet,
                        ) {
                            Some(d) => d,
                            None => continue,
                        }
                    };
                    if self
                        .wire_windows
                        .send_classed(
                            transport,
                            &datagram,
                            &endpoint,
                            reader.endpoint_guid,
                            classic_window,
                        )
                        .is_ok()
                    {
                        delivered = true;
                    }
                }
            }
        }

        if !delivered && no_fsm_readers && self.participant_fallback {
            delivered = self.dispatch_ecs_to_participants(transport, packet, spec_packet, seq);
        }
        if !delivered && !self.wire_windows.is_group() {
            // A non-GROUP close can use the ordinary multicast fallback.
            let _ = super::runtime::send_multicast_unless_group(
                transport,
                packet,
                spec_packet,
                self.discovery_fsm.as_deref(),
                &self.topic,
            );
        }
    }
}

/// Decide, and build, the ECS close-slot wire form for ONE specific
/// reader given its resolved RTPS vendor id. Shared by the live path
/// (`WriterCoherentBridge::dispatch_ecs`, above) and TRANSIENT_LOCAL /
/// TRANSIENT / PERSISTENT late-joiner replay
/// (`dds::writer::runtime::WriterReplayState::replay_to`'s `EcsClose`
/// branch), so both agree on which vendors get the bare close MARKER vs.
/// the native ECS DATA.
///
/// Every classic-model vendor (`vendorId != HDDS`, InterCOM 0x0105
/// INCLUDED) gets the bare D=0 close marker
/// (`builder::build_ecs_close_marker_ts`). This differs from
/// `nack::build_ecs_repair_packet`'s on_nack-ONLY single-SN GAP form for
/// InterCOM: that GAP retires a SPECIFIC already-NACKed SN, a repair
/// concept that does not apply here -- both a fresh live close and a
/// late joiner's FIRST view of the close need the actual close EVENT on
/// the wire (DDSI-RTPS 2.5 8.7.6: the set ends on the arrival of a DATA
/// without a coherent-set inline QoS; see the deferred-GAP comment in
/// `dispatch_ecs` -- a GAP instead of the marker retracts that event, so
/// the reader never observes the end of the set). The
/// GAP form stays reserved to `nack::build_ecs_repair_packet`; this
/// function never builds one.
///
/// HDDS peers, and peers whose vendor is not yet resolved (`None`), get
/// the native ECS DATA: `native_packet` is the ALREADY-BUILT submessage
/// for this close (from `build_ecs_data_submessage_ts`); only its
/// readerEntityId is patched in-place, matching `dispatch_ecs`'s
/// existing per-reader patch-and-reuse strategy. Callers that must NOT
/// guess an unresolved vendor (late-joiner replay: see
/// `replay_to`'s doc) filter `reader_vendor.is_some()` themselves
/// BEFORE calling this function; it makes no such distinction on its
/// own, so it stays a drop-in replacement for `dispatch_ecs`'s existing
/// (deliberately lenient) `is_classic_vendor` split.
///
/// Returns `None` only when the vendor is classic but no RTPS endpoint
/// context is available to build the marker (`ctx = None`) -- the
/// caller's existing "skip this reader" behavior.
pub(super) fn ecs_close_form_for(
    reader_vendor: Option<u16>,
    ctx: Option<&RtpsEndpointContext>,
    reader_entity_id: [u8; 4],
    seq: u64,
    source_ts: (u32, u32),
    native_packet: &[u8],
) -> Option<Vec<u8>> {
    let is_classic_vendor = matches!(reader_vendor, Some(v) if v != HDDS_VENDOR_ID_U16);
    if is_classic_vendor {
        let ctx = ctx?;
        Some(builder::build_ecs_close_marker_ts(
            ctx,
            &reader_entity_id,
            seq,
            source_ts,
        ))
    } else {
        let mut patched = native_packet.to_vec();
        if patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
            patched[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
                .copy_from_slice(&reader_entity_id);
        }
        Some(patched)
    }
}

impl WriterCoherentBridge {
    /// An end of set is about to take the writer's next SN; it journals it
    /// once made (`HistoryCache::taking`).
    fn taking_end_of_set(&self) -> Option<crate::reliability::InFlight<'_>> {
        self.history_cache.as_deref().map(|cache| {
            cache.taking(
                crate::reliability::Producer::EndOfSet,
                self.next_seq.load(Ordering::Acquire),
            )
        })
    }

    /// Journal `seq` as this writer's ECS close slot (`ChangeKind::EcsClose`),
    /// whatever its transport: shared tail of `emit_ecs_data`'s wire and
    /// no-transport branches, so both describe the set's close with the
    /// EXACT same `ChangeMetadata` shape
    /// `HistoryCache::snapshot_for_local_replay` and the NACK repair path
    /// read it with (one representation of "is this set closed", not a
    /// transport-gated one and a transport-less one that could drift
    /// apart).
    fn journal_ecs_close(
        &self,
        seq: u64,
        coherent_sn: u64,
        group_sn: Option<u64>,
        ecs: Option<crate::protocol::group::GroupTag>,
        source_ts: (u32, u32),
    ) {
        if let Some(ref cache) = self.history_cache {
            if let Err(e) = cache.insert_grouped_until(
                seq,
                &[],
                0,
                crate::reliability::ChangeMetadata {
                    kind: crate::reliability::ChangeKind::EcsClose,
                    coherent_sn: Some(coherent_sn),
                    group_sn,
                    key_hash: None,
                    source_ts,
                    source_ts_known: true,
                    ..crate::reliability::ChangeMetadata::user_data()
                },
                ecs,
                None,
            ) {
                log::debug!(
                    "[writer-coherent] ECS cache insert failed topic='{}' seq={}: {}",
                    self.topic,
                    seq,
                    e
                );
            }
        }
        self.intra_sets.acknowledge_control(seq);
    }

    /// Send the end of set `spec_packet` (SN `seq`) of a writer that wrote
    /// nothing in the set to every reader of the spec class, and a filtered
    /// GAP of `seq` to every other reader (D6/D18: they never receive an end
    /// of a set from a writer that had no part in it).
    fn dispatch_idle_ecs(&self, spec_packet: &[u8], seq: u64) {
        let (Some(transport), Some(fsm), Some(reg), Some(ctx)) = (
            self.transport.as_ref(),
            self.discovery_fsm.as_ref(),
            self.endpoint_registry.as_ref(),
            self.rtps_endpoint,
        ) else {
            return;
        };
        for reader in fsm.find_readers_for_topic(&self.topic) {
            let classic_window = self.wire_windows.is_group()
                && fsm.requires_group_window(&reader.endpoint_guid.prefix);
            if classic_window && !self.wire_windows.contains(reader.endpoint_guid) {
                continue;
            }
            if reader.participant_guid.prefix == ctx.guid_prefix {
                continue;
            }
            let mut pguid = [0u8; 16];
            pguid[..12].copy_from_slice(&reader.participant_guid.as_bytes()[..12]);
            pguid[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
            let Some(dest) = reg
                .get_reader_locator(&reader.endpoint_guid)
                .or_else(|| reg.get(&GUID::from_bytes(pguid)))
            else {
                continue;
            };
            let datagram = if fsm.speaks_spec_group(&reader.participant_guid.prefix) {
                let mut patched = spec_packet.to_vec();
                if patched.len() >= builder::READER_ENTITY_ID_OFFSET + 4 {
                    patched[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
                        .copy_from_slice(&reader.endpoint_guid.entity_id);
                }
                patched
            } else if fsm.speaks_plain_group(&reader.participant_guid.prefix) {
                // A plain reader: the plain GAP, with no GROUP extension.
                super::nack::plain_close_gap(&ctx, reader.endpoint_guid.entity_id, seq)
            } else {
                // No change for this reader: filtered, not lost.
                builder::build_gap_packet_filtered(
                    &reader.endpoint_guid.entity_id,
                    &ctx.writer_entity_id,
                    seq,
                    ctx.guid_prefix,
                )
            };
            if !datagram.is_empty() {
                let _ = self.wire_windows.send_classed(
                    transport,
                    &datagram,
                    &dest,
                    reader.endpoint_guid,
                    classic_window,
                );
            }
        }
        if self.participant_fallback && fsm.find_readers_for_topic(&self.topic).is_empty() {
            self.dispatch_ecs_to_participants(transport, spec_packet, Some(spec_packet), seq);
        }
    }
}

impl CoherentWriter for WriterCoherentBridge {
    fn wait_for_acknowledgments_until(
        &self,
        deadline: std::time::Instant,
    ) -> crate::dds::Result<()> {
        let Some(ref wait) = self.ack_wait else {
            return Ok(());
        };
        super::runtime::wait_acked_until(
            wait.reliable,
            &self.next_seq,
            &wait.ack_track,
            self.history_cache.as_deref(),
            deadline,
        )
    }

    fn close_intra_set(&self, generation: Option<u64>) {
        self.intra_sets.close_open_set(generation);
    }

    fn deliver_intra_sets(&self) {
        self.intra_sets.deliver_ready();
    }

    fn intra_slot(&self) -> Option<u64> {
        self.intra_sets.group_slot()
    }

    fn emit_idle_ecs(&self, ecs: crate::protocol::group::GroupTag) {
        let Some(ctx) = self.rtps_endpoint else {
            // No wire leg: the end of set still goes into this writer's own
            // history, like `emit_ecs_data`'s no-endpoint branch. Taken now,
            // journaled below (`HistoryCache::taking`).
            let _in_flight = self.taking_end_of_set();
            let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
            self.wire_windows.record_unretained(seq);
            let source_ts = builder::now_rtps_timestamp();
            let tag = crate::protocol::group::GroupTag {
                part_first_sn: Some(seq),
                ..ecs
            };
            // Same journal shape as the with-endpoint idle branch below
            // (no PID_COHERENT_SET: this writer wrote nothing in the
            // set), just without the wire packet this writer has no
            // transport to send.
            if let Some(ref cache) = self.history_cache {
                let _ = cache.insert_grouped_until(
                    seq,
                    &[],
                    0,
                    crate::reliability::ChangeMetadata {
                        kind: crate::reliability::ChangeKind::EcsClose,
                        source_ts,
                        source_ts_known: true,
                        ..crate::reliability::ChangeMetadata::user_data()
                    },
                    Some(tag),
                    None,
                );
            }
            self.intra_sets.acknowledge_control(seq);
            if let Some(ref state) = self.heartbeat_scheduler_state {
                state.record_end_of_set(seq);
            }
            log::debug!(
                "[writer-coherent] idle ECS closed (no transport) topic='{}' seq={}",
                self.topic,
                seq
            );
            return;
        };
        // Taken now, journaled below (`HistoryCache::taking`).
        let _in_flight = self.taking_end_of_set();
        let source_ts = builder::now_rtps_timestamp();
        // Built before the number is taken: a refused build takes none
        // (`take_sequence_number_for`), so no hole a RELIABLE reader would
        // NACK forever.
        let Some((seq, packet)) = super::runtime::take_sequence_number_for(&self.next_seq, |seq| {
            let tag = crate::protocol::group::GroupTag {
                part_first_sn: Some(seq),
                ..ecs
            };
            builder::build_ecs_spec_ts(&ctx, &self.topic, seq, &tag, source_ts)
        }) else {
            return;
        };
        let tag = crate::protocol::group::GroupTag {
            part_first_sn: Some(seq),
            ..ecs
        };
        if self.history_cache.is_none() {
            self.wire_windows.record_unretained(seq);
        }
        self.dispatch_idle_ecs(&packet, seq);
        // Journaled as an end of set with no PID_COHERENT_SET of today's
        // form: a repair to a reader of the spec class rebuilds the spec
        // form, any other reader's repair is a GAP (nack.rs).
        if let Some(ref cache) = self.history_cache {
            let _ = cache.insert_grouped_until(
                seq,
                &[],
                0,
                crate::reliability::ChangeMetadata {
                    kind: crate::reliability::ChangeKind::EcsClose,
                    source_ts,
                    source_ts_known: true,
                    ..crate::reliability::ChangeMetadata::user_data()
                },
                Some(tag),
                None,
            );
        }
        self.intra_sets.acknowledge_control(seq);
        if let Some(ref state) = self.heartbeat_scheduler_state {
            state.record_end_of_set(seq);
        }
    }

    fn release_deferred_boundaries(&self) {
        WriterCoherentBridge::release_deferred_boundaries(self);
    }

    fn take_last_sn_in_active_set(&self) -> Option<u64> {
        let sn = self.last_sn_in_active_set.swap(0, Ordering::AcqRel);
        if sn == 0 {
            None
        } else {
            Some(sn)
        }
    }

    fn emit_ecs_data(
        &self,
        coherent_sn: u64,
        group_sn: Option<u64>,
        ecs: Option<crate::protocol::group::GroupTag>,
    ) {
        let _in_flight = self.taking_end_of_set();

        // The spec GROUP form for readers of the spec class (D18): its
        // PID_COHERENT_SET is the writer's FIRST SN in the set (Table 9.23).
        // Computed whether or not there is a wire leg: `insert_grouped_until`
        // consults it for GROUP retention regardless (`HistoryCache::
        // set_group_retention`), and a wire leg additionally builds its
        // spec packet from it below.
        let ecs = ecs.map(|tag| crate::protocol::group::GroupTag {
            part_first_sn: Some(self.first_sn_in_active_set.load(Ordering::Acquire)),
            ..tag
        });

        let Some(ctx) = self.rtps_endpoint else {
            // No wire leg: nothing to put on a transport this writer does
            // not have, but the set still closes in this writer's own
            // history (late joiners, DDS v1.4 SS2.2.2.4.1.10/11) -- RTPS
            // v2.5 SS8.7.6 and the DDS coherent-access contract are not
            // RTPS-only guarantees. (Live co-located readers get the set
            // through `close_intra_set` / `deliver_intra_sets`.) The SN is taken by a plain `fetch_add`: there is
            // no packet build to refuse and retry on a concurrent taker.
            let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
            self.wire_windows.record_unretained(seq);
            let source_ts = builder::now_rtps_timestamp();
            self.journal_ecs_close(seq, coherent_sn, group_sn, ecs, source_ts);
            if let Some(ref state) = self.heartbeat_scheduler_state {
                state.record_end_of_set(seq);
            }
            log::debug!(
                "[writer-coherent] ECS closed (no transport) topic='{}' seq={} coherent_sn={} group_sn={:?}",
                self.topic,
                seq,
                coherent_sn,
                group_sn
            );
            return;
        };

        // Publisher EntityId tag for inline-QoS PID_GROUP_ENTITY_ID: the
        // writer's own Publisher (`RtpsEndpointContext::publisher_entity_id`),
        // which the receiver uses to cluster writers of one Publisher for
        // GROUP-scope coherent_access (RTPS v2.5 sec. 9.3.2.1 + DDS v1.4
        // sec. 2.2.3.6).
        let publisher_entity_id = Some(ctx.publisher_entity_id);

        // Captured ONCE and threaded into both the live packet build AND
        // the history-cache journal below, so a NACK-triggered ECS repair
        // (nack.rs::build_ecs_repair_packet, HDDS-native leg) can replay
        // this exact timestamp instead of stamping a fresh one -- same
        // pattern as DataWriter::write()'s small-DATA branch.
        let source_ts = builder::now_rtps_timestamp();
        let Some((seq, packet)) = super::runtime::take_sequence_number_for(&self.next_seq, |seq| {
            builder::build_ecs_data_submessage_ts(
                &ctx,
                &self.topic,
                seq,
                coherent_sn,
                group_sn,
                publisher_entity_id,
                source_ts,
            )
        }) else {
            log::debug!(
                "[writer-coherent] ECS build returned empty packet topic='{}': no sequence number taken",
                self.topic
            );
            return;
        };
        let spec_packet = ecs
            .as_ref()
            .map(|tag| builder::build_ecs_spec_ts(&ctx, &self.topic, seq, tag, source_ts))
            .filter(|p| !p.is_empty());

        if self.history_cache.is_none() {
            self.wire_windows.record_unretained(seq);
        }
        self.dispatch_ecs(&packet, spec_packet.as_deref(), seq);

        // Cache the ECS close slot AS an ECS close (ChangeKind::EcsClose,
        // empty payload, wire coherent markers), NOT as an ordinary empty
        // user change. A NACK on this slot must be repaired with the
        // dialect-correct close form for the requesting reader (bare close
        // marker for classic vendors, native ECS DATA for HDDS peers); the
        // old ordinary-DATA repair of this slot emitted a payload-less user
        // DATA that a classic-model reader may materialize as an extra sample
        // (one more sample than the writer wrote). The journal keeps the
        // original Publisher identity; destination windows never alter it.
        self.journal_ecs_close(seq, coherent_sn, group_sn, ecs, source_ts);

        // Refresh the periodic HEARTBEAT scheduler so it advertises
        // the ECS in its `lastSN` field. Without this nudge a reader
        // that misses the unicast ECS packet would only learn about
        // it at the next HB tick, which delays the per-set commit.
        if let Some(ref state) = self.heartbeat_scheduler_state {
            state.record_end_of_set(seq);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::discovery::{SedpData, SpdpData};
    use crate::test_support::domains::unique_domain;
    use crate::transport::PortMapping;
    use std::net::SocketAddr;
    use std::time::Duration;

    const WRITER_EID: [u8; 4] = [0x00, 0x00, 0x10, 0x02];
    const OUR_PREFIX: [u8; 12] = [7u8; 12];

    fn writer_ctx() -> RtpsEndpointContext {
        RtpsEndpointContext {
            guid_prefix: OUR_PREFIX,
            reader_entity_id: [0u8; 4],
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0007,
            // Not the key-1 Publisher: the end of set must name the
            // writer's own Publisher.
            publisher_entity_id: [0x00, 0x00, 0x21, 0x08],
        }
    }

    /// Zero the 8-byte INFO_TS timestamp (offsets 24..32 after the RTPS
    /// header + INFO_TS id) so two builds at different instants can be
    /// byte-compared. Only valid for DATA-form packets (marker / ECS).
    fn with_masked_timestamp(mut pkt: Vec<u8>) -> Vec<u8> {
        assert!(pkt.len() >= 32, "packet too short for header + INFO_TS");
        assert_eq!(pkt[20], 0x09, "INFO_TS submessage expected at offset 20");
        for b in &mut pkt[24..32] {
            *b = 0;
        }
        pkt
    }

    /// Register one discovered remote reader on `topic` with the given
    /// GUID prefix byte, vendor id and unicast locator: SPDP (participant +
    /// vendor) then SEDP (reader endpoint), plus the locator table entry
    /// dispatch_ecs resolves. Returns the reader endpoint GUID.
    /// A reader whose prefix byte is 0xD0 or above announces the spec GROUP
    /// capability (D18).
    fn register_reader(
        fsm: &DiscoveryFsm,
        reg: &EndpointRegistry,
        topic: &str,
        prefix_byte: u8,
        vendor_id: u16,
        dest: SocketAddr,
    ) -> GUID {
        let mut pguid = [prefix_byte; 16];
        pguid[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let participant_guid = GUID::from_bytes(pguid);
        fsm.handle_spdp(SpdpData {
            participant_guid,
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: Some(vendor_id),
            hdds_capabilities: (prefix_byte >= 0xD0)
                .then_some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
            builtin_endpoint_set: None,
        });

        let mut rguid = [prefix_byte; 16];
        rguid[12..16].copy_from_slice(&[0x00, 0x00, 0x10, 0x04]); // reader entity kind
        let endpoint_guid = GUID::from_bytes(rguid);
        fsm.handle_sedp(SedpData {
            topic_name: topic.to_string(),
            type_name: "ShapeType".to_string(),
            participant_guid,
            endpoint_guid,
            qos_hash: 0,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![dest],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        reg.register_reader_locator(endpoint_guid, dest);
        endpoint_guid
    }

    fn bind_listener() -> (std::net::UdpSocket, SocketAddr) {
        let sock = crate::test_support::ports::bind_capture_socket();
        sock.set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let addr = sock.local_addr().expect("listener addr");
        (sock, addr)
    }

    fn recv_one(sock: &std::net::UdpSocket, what: &str) -> Vec<u8> {
        let mut buf = [0u8; 2048];
        let (n, _) = sock
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("{what} must arrive: {e}"));
        buf[..n].to_vec()
    }

    /// Mixed audience at set close: on ONE topic, a vendor 0x0105 reader, a
    /// classic-model reader and an HDDS reader each receive their own
    /// per-reader unicast close form -- for 0x0105 the bare D=0 close
    /// marker on the first close and, on every later close, a single-SN
    /// GAP retiring the PREVIOUS boundary SN immediately before the new
    /// marker; the bare D=0 close marker for other classic vendors
    /// (byte-identical to the live builder); and the native ECS DATA for
    /// HDDS peers -- and the multicast stream
    /// carries NO close datagram at all (a multicast GAP would retire
    /// the SN for vendors that need the marker).
    #[test]
    fn ecs_close_mixed_audience_forms_and_no_multicast_gap() {
        let topic = "MixedCloseTopic";
        // Declared first so it drops last, after the observer socket and
        // the transport below have released the domain's multicast port.
        let domain = unique_domain();
        let domain_id = domain.id();

        // Multicast observer on the user-data group of a dedicated
        // domain, fenced by control datagrams (see the nack.rs tests).
        let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");
        let mc_port = mapping.metatraffic_multicast + 1;
        let observer = std::net::UdpSocket::bind(("0.0.0.0", mc_port)).expect("bind observer");
        crate::transport::multicast::join_multicast_group(&observer).expect("join group");
        observer
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");

        let (intercom_l, intercom_dest) = bind_listener();
        let (classic_l, classic_dest) = bind_listener();
        let (hdds_l, hdds_dest) = bind_listener();

        let mut local = [0u8; 16];
        local[..12].copy_from_slice(&OUR_PREFIX);
        local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
        fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
        let reg = EndpointRegistry::new();

        let intercom_guid = register_reader(
            &fsm,
            &reg,
            topic,
            0xA1,
            INTERCOM_VENDOR_ID_U16,
            intercom_dest,
        );
        let classic_guid = register_reader(&fsm, &reg, topic, 0xB1, 0x0101, classic_dest);
        let hdds_guid = register_reader(&fsm, &reg, topic, 0xC1, HDDS_VENDOR_ID_U16, hdds_dest);

        let transport = Arc::new(UdpTransport::new(domain_id, 0, mapping).expect("test transport"));

        // Positive control A: prove multicast loopback is observable so
        // the no-multicast assertion below is not vacuous.
        transport
            .send_user_data_multicast(b"HDDS_ECS_CTRL_A")
            .expect("control send");
        let mut buf = [0u8; 2048];
        let mut control_seen = false;
        for _ in 0..3 {
            match observer.recv_from(&mut buf) {
                Ok((n, _)) if &buf[..n] == b"HDDS_ECS_CTRL_A" => {
                    control_seen = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        let bridge = WriterCoherentBridge::new(
            topic.to_string(),
            Arc::new(AtomicU64::new(30)), // next writer SN -> close slot = 30
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::default(),
            Some(transport.clone()),
            Some(writer_ctx()),
            None, // history cache: slot bookkeeping covered by nack.rs tests
            Some(reg),
            Some(fsm),
            None,
            test_intra_sets(),
        );

        bridge.emit_ecs_data(29, Some(3), None);

        // intercom reader, first close: bare D=0 close marker occupying
        // the close-slot SN (classic-model close event), byte-identical
        // to the live builder. No GAP yet: there is no previous boundary
        // to retire, and GAPing the marker's own SN in the same burst
        // would retract the close event it just delivered.
        let ic_marker = recv_one(&intercom_l, "intercom close marker");
        assert_eq!(&ic_marker[0..4], b"RTPS");
        assert_eq!(ic_marker[32], 0x15, "DATA submessage");
        assert_eq!(ic_marker[33], 0x01, "flags LE only: bare close marker");
        assert_eq!(
            u32::from_le_bytes([ic_marker[52], ic_marker[53], ic_marker[54], ic_marker[55]]),
            30,
            "marker rides the close-slot SN"
        );
        let live_ic_marker =
            builder::build_ecs_close_marker(&writer_ctx(), &intercom_guid.entity_id, 30);
        assert_eq!(
            with_masked_timestamp(ic_marker),
            with_masked_timestamp(live_ic_marker),
            "intercom close marker byte-identical to the live builder"
        );
        assert!(
            intercom_l.recv_from(&mut buf).is_err(),
            "intercom gets the marker ONLY on first close -- no GAP yet"
        );

        // classic-model reader: bare D=0 close marker, byte-identical to
        // the live builder output for this reader.
        let marker = recv_one(&classic_l, "classic close marker");
        assert_eq!(marker[32], 0x15, "DATA submessage");
        assert_eq!(marker[33], 0x01, "flags LE only: bare close marker");
        assert_eq!(
            u32::from_le_bytes([marker[52], marker[53], marker[54], marker[55]]),
            30,
            "marker rides the close-slot SN"
        );
        let live_marker =
            builder::build_ecs_close_marker(&writer_ctx(), &classic_guid.entity_id, 30);
        assert_eq!(
            with_masked_timestamp(marker),
            with_masked_timestamp(live_marker),
            "classic close marker byte-identical to the live builder"
        );
        assert!(
            classic_l.recv_from(&mut buf).is_err(),
            "classic reader gets the marker ONLY"
        );

        // HDDS reader: native ECS DATA with the coherent PIDs, patched to
        // the reader entity id, byte-identical to the live builder.
        let ecs = recv_one(&hdds_l, "HDDS native ECS DATA");
        assert_eq!(ecs[33], 0x03, "flags LE + Q=1: native ECS marker");
        assert_eq!(
            &ecs[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4],
            &hdds_guid.entity_id,
            "patched to the HDDS reader entity id"
        );
        assert_eq!(
            builder::extract_ecs_marker(&ecs),
            Some((29, Some(3))),
            "PID_COHERENT_SET / group GSN as emitted"
        );
        let mut live_ecs = builder::build_ecs_data_submessage(
            &writer_ctx(),
            topic,
            30,
            29,
            Some(3),
            Some([0x00, 0x00, 0x21, 0x08]),
        );
        live_ecs[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
            .copy_from_slice(&hdds_guid.entity_id);
        assert_eq!(
            with_masked_timestamp(ecs),
            with_masked_timestamp(live_ecs),
            "HDDS ECS DATA byte-identical to the live builder"
        );
        assert!(
            hdds_l.recv_from(&mut buf).is_err(),
            "HDDS reader gets the ECS DATA ONLY"
        );

        // Multicast stream: NO close datagram of any form (all three
        // readers resolved unicast, so the fallback must not fire; a
        // multicast GAP would retire the SN for everyone).
        if control_seen {
            transport
                .send_user_data_multicast(b"HDDS_ECS_CTRL_B")
                .expect("control send");
            let mut fence_seen = false;
            for _ in 0..10 {
                match observer.recv_from(&mut buf) {
                    Ok((n, _)) => {
                        let dgram = &buf[..n];
                        if dgram == b"HDDS_ECS_CTRL_B" {
                            fence_seen = true;
                            break;
                        }
                        if dgram == b"HDDS_ECS_CTRL_A" {
                            continue;
                        }
                        assert!(
                            !dgram.starts_with(b"RTPS"),
                            "close datagram LEAKED to multicast: {:02x?}",
                            &dgram[..dgram.len().min(24)]
                        );
                    }
                    Err(_) => break,
                }
            }
            assert!(fence_seen, "control fence B must arrive on the observer");
        } else {
            eprintln!(
                "SKIP multicast observation: control datagram not looped back on domain {}",
                domain_id
            );
        }

        // Second close: the PREVIOUS boundary SN (30) is retired by a
        // single-SN GAP sent immediately before the new marker (31) --
        // the deferred-by-one-set retirement dance.
        bridge.emit_ecs_data(30, Some(4), None);
        let gap = recv_one(&intercom_l, "intercom deferred GAP");
        assert_eq!(&gap[0..4], b"RTPS");
        assert_eq!(&gap[8..20], &OUR_PREFIX, "GAP attribution prefix");
        assert_eq!(gap[20], 0x08, "GAP submessage id");
        assert_eq!(
            u16::from_le_bytes([gap[22], gap[23]]),
            28,
            "single-SN GAP body: no bitmap"
        );
        assert_eq!(
            &gap[24..28],
            &intercom_guid.entity_id,
            "addressed to the intercom reader"
        );
        assert_eq!(&gap[28..32], &WRITER_EID, "attributed to this writer");
        assert_eq!(
            u32::from_le_bytes([gap[36], gap[37], gap[38], gap[39]]),
            30,
            "gapStart = the PREVIOUS close-slot SN"
        );
        assert_eq!(
            u32::from_le_bytes([gap[44], gap[45], gap[46], gap[47]]),
            31,
            "gapList.base = previous + 1"
        );
        assert_eq!(
            u32::from_le_bytes([gap[48], gap[49], gap[50], gap[51]]),
            0,
            "numBits = 0"
        );
        assert_eq!(gap.len(), 52, "nothing after the GAP submessage");
        let ic_marker2 = recv_one(&intercom_l, "intercom second close marker");
        assert_eq!(ic_marker2[32], 0x15, "DATA submessage");
        assert_eq!(ic_marker2[33], 0x01, "flags LE only: bare close marker");
        assert_eq!(
            u32::from_le_bytes([
                ic_marker2[52],
                ic_marker2[53],
                ic_marker2[54],
                ic_marker2[55]
            ]),
            31,
            "second marker rides the new close-slot SN"
        );
        assert!(
            intercom_l.recv_from(&mut buf).is_err(),
            "intercom gets GAP + marker on later closes -- nothing else"
        );
    }

    /// Two InterCOM readers of one topic: at the second close EACH of them
    /// gets the retirement GAP of the first boundary right before the second
    /// marker. The deferred retirement is per reader; a single per-writer
    /// slot handed it to the first reader of the loop only.
    #[test]
    fn deferred_boundary_gap_goes_to_every_intercom_reader() {
        let topic = "TwoIntercomTopic";
        let domain = unique_domain();
        let domain_id = domain.id();
        let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");

        let (first_l, first_dest) = bind_listener();
        let (second_l, second_dest) = bind_listener();

        let mut local = [0u8; 16];
        local[..12].copy_from_slice(&OUR_PREFIX);
        local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
        let reg = EndpointRegistry::new();
        register_reader(&fsm, &reg, topic, 0xA1, INTERCOM_VENDOR_ID_U16, first_dest);
        register_reader(&fsm, &reg, topic, 0xA2, INTERCOM_VENDOR_ID_U16, second_dest);

        let transport = Arc::new(UdpTransport::new(domain_id, 0, mapping).expect("test transport"));
        let bridge = WriterCoherentBridge::new(
            topic.to_string(),
            Arc::new(AtomicU64::new(30)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::default(),
            Some(transport),
            Some(writer_ctx()),
            None,
            Some(reg),
            Some(fsm),
            None,
            test_intra_sets(),
        );

        bridge.emit_ecs_data(29, None, None);
        for (l, name) in [(&first_l, "first"), (&second_l, "second")] {
            let marker = recv_one(l, name);
            assert_eq!(marker[33], 0x01, "{name}: bare close marker");
        }

        bridge.emit_ecs_data(30, None, None);
        for (l, name) in [(&first_l, "first"), (&second_l, "second")] {
            let gap = recv_one(l, &format!("{name} deferred GAP"));
            assert_eq!(gap[20], 0x08, "{name}: GAP before the second marker");
            assert_eq!(
                u32::from_le_bytes([gap[36], gap[37], gap[38], gap[39]]),
                30,
                "{name}: the GAP retires the FIRST boundary"
            );
            let marker = recv_one(l, &format!("{name} second marker"));
            assert_eq!(marker[33], 0x01, "{name}: bare close marker");
            assert_eq!(
                u32::from_le_bytes([marker[52], marker[53], marker[54], marker[55]]),
                31,
                "{name}: the second marker rides the next SN"
            );
        }
    }

    /// The Publisher releases the deferred boundaries of ALL its writers
    /// before any of them emits its end of set: `release_deferred_boundaries`
    /// sends the pending GAP, once, and only for a writer that has a change
    /// in the set; the end of set that follows sends the marker alone.
    #[test]
    fn release_deferred_boundaries_sends_the_gap_before_the_marker() {
        let topic = "ReleaseTopic";
        let domain = unique_domain();
        let domain_id = domain.id();
        let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");

        let (l, dest) = bind_listener();
        let mut local = [0u8; 16];
        local[..12].copy_from_slice(&OUR_PREFIX);
        local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
        let reg = EndpointRegistry::new();
        register_reader(&fsm, &reg, topic, 0xA1, INTERCOM_VENDOR_ID_U16, dest);

        let transport = Arc::new(UdpTransport::new(domain_id, 0, mapping).expect("test transport"));
        let last_sn = Arc::new(AtomicU64::new(0));
        let bridge = WriterCoherentBridge::new(
            topic.to_string(),
            Arc::new(AtomicU64::new(30)),
            Arc::clone(&last_sn),
            Arc::new(AtomicU64::new(0)),
            Arc::default(),
            Some(transport),
            Some(writer_ctx()),
            None,
            Some(reg),
            Some(fsm),
            None,
            test_intra_sets(),
        );
        let mut buf = [0u8; 2048];

        // First close: marker 30, nothing pending before it.
        bridge.emit_ecs_data(29, None, None);
        assert_eq!(recv_one(&l, "first marker")[33], 0x01);

        // No change in the next set: the boundary stays pending.
        bridge.release_deferred_boundaries();
        assert!(
            l.recv_from(&mut buf).is_err(),
            "a writer with nothing in the set keeps its boundary pending"
        );

        // A change in the set: the GAP of boundary 30 goes out ahead of the
        // end of set.
        last_sn.store(40, Ordering::Release);
        bridge.release_deferred_boundaries();
        let gap = recv_one(&l, "released GAP");
        assert_eq!(gap[20], 0x08, "single-SN GAP");
        assert_eq!(
            u32::from_le_bytes([gap[36], gap[37], gap[38], gap[39]]),
            30,
            "it retires the pending boundary"
        );
        assert!(l.recv_from(&mut buf).is_err(), "and nothing else");

        // The end of set carries the marker alone, and a second release finds
        // nothing but the new boundary, which the next set retires.
        bridge.emit_ecs_data(40, None, None);
        let marker = recv_one(&l, "second marker");
        assert_eq!(marker[33], 0x01, "bare close marker, no GAP before it");
        assert_eq!(
            u32::from_le_bytes([marker[52], marker[53], marker[54], marker[55]]),
            31
        );
        assert!(l.recv_from(&mut buf).is_err(), "no second GAP");
    }

    /// The end of a GROUP set facing a reader of the spec class and a legacy
    /// HDDS reader (D18), decoded by hand: the spec reader's carries the
    /// writer's FIRST SN in the set in PID_COHERENT_SET, the set's first GSN
    /// in 0x0063, the end of set's own GSN (last + 1, D2) in 0x0064 and the
    /// writerSet in 0x0065 (RTPS v2.5 Table 9.23), and no 0x0053 (G11); the
    /// legacy reader's is today's: PID_COHERENT_SET the writer's LAST SN,
    /// the set id in 0x8030, 0x0053.
    #[test]
    fn ecs_spec_and_legacy_readers_each_get_their_form() {
        let topic = "SpecEcsTopic";
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 1).expect("port mapping");
        let transport = Arc::new(UdpTransport::new(domain.id(), 1, mapping).expect("transport"));
        let (spec_l, spec_dest) = bind_listener();
        let (legacy_l, legacy_dest) = bind_listener();
        let mut local = [0u8; 16];
        local[..12].copy_from_slice(&OUR_PREFIX);
        local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
        fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
        let reg = EndpointRegistry::new();
        register_reader(&fsm, &reg, topic, 0xD1, HDDS_VENDOR_ID_U16, spec_dest);
        register_reader(&fsm, &reg, topic, 0xC1, HDDS_VENDOR_ID_U16, legacy_dest);
        let bridge = WriterCoherentBridge::new(
            topic.to_string(),
            Arc::new(AtomicU64::new(30)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(27)), // the writer's first SN in the set
            Arc::default(),
            Some(transport),
            Some(writer_ctx()),
            None,
            Some(reg),
            Some(fsm),
            None,
            test_intra_sets(),
        );
        let writer_set = [0xAB, 0xCD, 0xEF, 0x01];
        bridge.emit_ecs_data(
            29,
            Some(3),
            Some(crate::protocol::group::GroupTag {
                gsn: 5,
                writer_set,
                set_first_gsn: Some(3),
                part_first_sn: None,
            }),
        );
        let parameters = |pkt: &[u8]| {
            // RTPS header 20, INFO_TS 12, DATA header 4 + 20, inline QoS.
            let mut at = 56;
            let mut out = std::collections::BTreeMap::new();
            while at + 4 <= pkt.len() {
                let pid = u16::from_le_bytes([pkt[at], pkt[at + 1]]);
                let len = usize::from(u16::from_le_bytes([pkt[at + 2], pkt[at + 3]]));
                if pid == 1 {
                    break;
                }
                out.insert(pid, pkt[at + 4..at + 4 + len].to_vec());
                at += 4 + len;
            }
            out
        };
        let sn = |v: &Vec<u8>| {
            (u64::from(u32::from_le_bytes(v[0..4].try_into().unwrap())) << 32)
                | u64::from(u32::from_le_bytes(v[4..8].try_into().unwrap()))
        };
        let spec = parameters(&recv_one(&spec_l, "spec end of set"));
        assert_eq!(sn(&spec[&0x0056]), 27, "the writer's first SN in the set");
        assert_eq!(sn(&spec[&0x0063]), 3, "the set's first GSN");
        assert_eq!(sn(&spec[&0x0064]), 5, "the end of set's GSN");
        assert_eq!(spec[&0x0065], writer_set.to_vec());
        assert!(!spec.contains_key(&0x8030));
        assert!(
            !spec.contains_key(&0x0053),
            "no PID_GROUP_ENTITY_ID: an SEDP parameter (G11)"
        );
        let legacy = parameters(&recv_one(&legacy_l, "legacy end of set"));
        assert_eq!(sn(&legacy[&0x0056]), 29, "the writer's last SN");
        assert!(legacy.contains_key(&0x0053), "today's PID_GROUP_ENTITY_ID");
        assert_eq!(sn(&legacy[&0x8030]), 3, "the set id");
        for pid in [0x0063u16, 0x0064, 0x0065] {
            assert!(!legacy.contains_key(&pid), "{pid:#06x}");
        }
    }

    /// A writer that wrote nothing in a GROUP set ends it all the same (W3):
    /// a reader of the spec class receives its end of set, PID_COHERENT_SET
    /// its own SN (D6); a legacy reader receives a filtered GAP of that SN.
    #[test]
    fn an_idle_end_of_set_reaches_spec_readers_and_gaps_the_others() {
        let topic = "IdleEcsTopic";
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 2).expect("port mapping");
        let transport = Arc::new(UdpTransport::new(domain.id(), 2, mapping).expect("transport"));
        let (spec_l, spec_dest) = bind_listener();
        let (legacy_l, legacy_dest) = bind_listener();
        let mut local = [0u8; 16];
        local[..12].copy_from_slice(&OUR_PREFIX);
        local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
        fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
        let reg = EndpointRegistry::new();
        register_reader(&fsm, &reg, topic, 0xD2, HDDS_VENDOR_ID_U16, spec_dest);
        register_reader(&fsm, &reg, topic, 0xC2, HDDS_VENDOR_ID_U16, legacy_dest);
        let bridge = WriterCoherentBridge::new(
            topic.to_string(),
            Arc::new(AtomicU64::new(12)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::default(),
            Some(transport),
            Some(writer_ctx()),
            None,
            Some(reg),
            Some(fsm),
            None,
            test_intra_sets(),
        );
        bridge.emit_idle_ecs(crate::protocol::group::GroupTag {
            gsn: 5,
            writer_set: [9, 9, 9, 9],
            set_first_gsn: Some(3),
            part_first_sn: None,
        });
        let spec = recv_one(&spec_l, "spec end of set");
        assert_eq!(spec[32], 0x15, "a DATA");
        let at = spec
            .windows(4)
            .position(|w| w == [0x56, 0x00, 0x08, 0x00])
            .expect("PID_COHERENT_SET");
        assert_eq!(
            u32::from_le_bytes(spec[at + 8..at + 12].try_into().unwrap()),
            12,
            "its own SN"
        );
        let gap = recv_one(&legacy_l, "legacy GAP");
        assert_eq!(gap[20], 0x08, "a GAP");
        assert_eq!(u32::from_le_bytes([gap[36], gap[37], gap[38], gap[39]]), 12);
        // No change for that reader: filtered, never a sample lost (RTPS
        // v2.5 Sec.8.4.9.2, Sec.9.4.5.6): the F flag, and a filteredCount
        // of 1 after the empty gapList.
        assert_eq!(gap[21], 0x01 | 0x04, "flags E|F");
        assert_eq!(u16::from_le_bytes([gap[22], gap[23]]), 36);
        assert_eq!(&gap[52..60], &[0, 0, 0, 0, 1, 0, 0, 0], "filteredCount 1");
        assert_eq!(gap.len(), 60, "nothing after it");
    }

    /// An end of set reaches a participant the DATA fallback reaches, when
    /// discovery knows no reader of the topic yet: the same participant route
    /// as a DATA change (`DataWriter`), not a snapshot of the readers.
    #[test]
    fn an_end_of_set_takes_the_participant_route_while_no_reader_is_known() {
        let topic = "FallbackEcsTopic";
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 2).expect("port mapping");
        let transport = Arc::new(UdpTransport::new(domain.id(), 2, mapping).expect("transport"));
        let (participant_l, participant_dest) = bind_listener();
        let mut local = [0u8; 16];
        local[..12].copy_from_slice(&OUR_PREFIX);
        local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
        let reg = EndpointRegistry::new();
        let mut remote = [0xD4u8; 16];
        remote[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        reg.register(GUID::from_bytes(remote), participant_dest);
        // A classic peer of the same topic: its end of set is not the native form.
        let (classic_l, classic_dest) = bind_listener();
        let mut classic = [0xC4u8; 16];
        classic[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        reg.register(GUID::from_bytes(classic), classic_dest);
        for (prefix, vendor) in [
            (0xD4u8, HDDS_VENDOR_ID_U16),
            (0xC4u8, INTERCOM_VENDOR_ID_U16),
        ] {
            let mut pguid = [prefix; 16];
            pguid[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
            fsm.handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::from_bytes(pguid),
                lease_duration_ms: 100_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: Some(vendor),
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            });
        }
        let build = |on: bool| {
            WriterCoherentBridge::new(
                topic.to_string(),
                Arc::new(AtomicU64::new(12)),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
                Arc::default(),
                Some(Arc::clone(&transport)),
                Some(writer_ctx()),
                None,
                Some(reg.clone()),
                Some(Arc::clone(&fsm)),
                None,
                test_intra_sets(),
            )
            .with_participant_fallback(on)
        };
        build(true).emit_idle_ecs(crate::protocol::group::GroupTag {
            gsn: 5,
            writer_set: [9, 9, 9, 9],
            set_first_gsn: Some(3),
            part_first_sn: None,
        });
        let end = recv_one(&participant_l, "end of set on the participant route");
        assert_eq!(end[32], 0x15, "a DATA");
        assert!(
            end.windows(8).any(|w| w == [0, 0, 0, 0, 12, 0, 0, 0]),
            "carries its own SN 12"
        );
        classic_l
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .expect("set timeout");
        let mut buf = [0u8; 2048];
        assert!(
            classic_l.recv_from(&mut buf).is_err(),
            "a classic peer of unresolved native form gets no end of set"
        );
    }

    /// An end of set whose packet cannot be built (a topic name past what a
    /// ParameterList length can carry) takes no sequence number: a number
    /// taken and never sent nor journaled is a hole every RELIABLE reader
    /// NACKs forever (RTPS v2.5 Sec.8.2.3, each change has its own SN).
    #[test]
    fn an_end_of_set_that_cannot_be_built_takes_no_sequence_number() {
        let topic = "t".repeat(70_000);
        let next_seq = Arc::new(AtomicU64::new(12));
        let bridge = WriterCoherentBridge::new(
            topic,
            Arc::clone(&next_seq),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::default(),
            None,
            Some(writer_ctx()),
            None,
            None,
            None,
            None,
            test_intra_sets(),
        );
        bridge.emit_idle_ecs(crate::protocol::group::GroupTag {
            gsn: 5,
            writer_set: [9, 9, 9, 9],
            set_first_gsn: Some(3),
            part_first_sn: None,
        });
        assert_eq!(
            next_seq.load(Ordering::Acquire),
            12,
            "an idle end of set that was not built took a number"
        );
        bridge.emit_ecs_data(11, None, None);
        assert_eq!(
            next_seq.load(Ordering::Acquire),
            12,
            "an end of set that was not built took a number"
        );
    }

    /// DDS Security v1.1 Sec.8.8.2.2, 8.8.7.1: the end of a coherent set
    /// of a protected topic does not fall back to the multicast group
    /// (anyone may listen there) when no reader is reached; of an
    /// unprotected topic it does, which proves the observer hears the group.
    /// The ECS DATA fallback must not reach the group whatever the topic.
    #[cfg(feature = "security")]
    #[test]
    fn a_protected_topics_end_of_set_does_not_fall_back_to_multicast() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let observer = std::net::UdpSocket::bind(("0.0.0.0", mapping.metatraffic_multicast + 1))
            .expect("bind observer");
        crate::transport::multicast::join_multicast_group(&observer).expect("join group");
        observer
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let mut buf = [0u8; 4096];
        transport
            .send_user_data_multicast(b"HDDS_ECS_GATE_CTRL")
            .expect("control");
        if !matches!(observer.recv(&mut buf), Ok(n) if &buf[..n] == b"HDDS_ECS_GATE_CTRL") {
            eprintln!("SKIP: multicast loopback not observable on this host");
            return;
        }
        let rule = |expression: &str, protected: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: protected,
            enable_write_access_control: protected,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        let mut local = [0u8; 16];
        local[..12].copy_from_slice(&OUR_PREFIX);
        local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
        let mut fsm = DiscoveryFsm::new(GUID::from_bytes(local), 100_000);
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: false,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![rule("Protected*", true), rule("*", false)],
        })));
        let fsm = Arc::new(fsm);
        // The RTPS datagrams the group carries after the end of a set of
        // `topic`, up to the fence.
        let mut heard = |topic: &str| -> usize {
            let bridge = WriterCoherentBridge::new(
                topic.to_string(),
                Arc::new(AtomicU64::new(30)),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
                Arc::default(),
                Some(transport.clone()),
                Some(writer_ctx()),
                None,
                Some(EndpointRegistry::new()),
                Some(Arc::clone(&fsm)),
                None,
                test_intra_sets(),
            );
            bridge.emit_ecs_data(29, None, None);
            transport
                .send_user_data_multicast(b"HDDS_ECS_GATE_FENCE")
                .expect("fence");
            let mut rtps = 0;
            loop {
                let n = observer.recv(&mut buf).expect("the fence arrives");
                if &buf[..n] == b"HDDS_ECS_GATE_FENCE" {
                    return rtps;
                }
                if buf[..n].starts_with(b"RTPS") {
                    rtps += 1;
                }
            }
        };
        assert!(
            heard("OpenSetTopic") > 0,
            "fixture: an unprotected topic's end of set falls back to the group"
        );
        assert_eq!(
            heard("ProtectedSetTopic"),
            0,
            "a protected topic's end of set reached the multicast group"
        );
    }

    /// A writer built with no RTPS endpoint context (e.g. one never given a
    /// participant) still owes its close to its own history:
    /// `emit_ecs_data` must not early-return before journaling the
    /// `EcsClose` marker just because it has nothing to put on a transport
    /// it does not have (DDS v1.4 Sec.2.2.3.6, RTPS v2.5 Sec.8.7.6 are not
    /// RTPS-only guarantees).
    #[test]
    fn emit_ecs_data_with_no_rtps_endpoint_still_journals() {
        use crate::core::rt::slabpool::SlabPool;
        use crate::reliability::{ChangeKind, HistoryCache};

        let cache = Arc::new(HistoryCache::new_with_limits(
            Arc::new(SlabPool::new()),
            16,
            64 * 1024,
            crate::dds::qos::History::KeepAll,
        ));
        // Journal the member itself too, as the write path does: the close
        // below must find it and treat SN 1 as closed.
        cache
            .insert_coherent(1, b"member", 0, Some(1), None)
            .expect("member journaled");

        let bridge = WriterCoherentBridge::new(
            "no-endpoint-topic".to_string(),
            Arc::new(AtomicU64::new(2)),
            Arc::new(AtomicU64::new(1)),
            Arc::new(AtomicU64::new(1)),
            Arc::default(),
            None, // no transport
            None, // no RTPS endpoint context: the branch under test
            Some(Arc::clone(&cache)),
            None,
            None,
            None,
            test_intra_sets(),
        );

        bridge.emit_ecs_data(1, None, None);

        let close = cache
            .get_change(2)
            .expect("the end of set must be journaled even with no RTPS endpoint context");
        assert_eq!(close.metadata.kind, ChangeKind::EcsClose);
        assert_eq!(close.metadata.coherent_sn, Some(1));
    }

    /// The local-delivery state of a bridge whose test does not look at it.
    fn test_intra_sets() -> Arc<IntraCoherentSets> {
        Arc::new(IntraCoherentSets::new(
            "coherent-bridge-test".to_string(),
            Arc::new(crate::core::rt::TopicMerger::new()),
            Duration::from_secs(5),
            true,
            None,
        ))
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ACKNACK processing for DataWriter.
//!
//! Handles incoming RTPS ACKNACK messages from readers and triggers
//! retransmission of missing samples from the history cache.
//!
//! ## RTPS Reliable Protocol Flow
//!
//! ```text
//! Writer                              Reader
//!   |--DATA(1,2,3,4,5)----------------->  (3 lost)
//!   |--HEARTBEAT(first=1,last=5)------->
//!   |                                   |
//!   <----------ACKNACK(missing={3})-----|
//!   |                                   |
//!   |--DATA(3) retransmit-------------->  <- This module handles this
//! ```
//!
//! ## Dual-format ACKNACK parsing
//!
//! Two callers feed `deliver_nack()` with different formats:
//!   1. `router.rs` / `unicast_router.rs` -- raw RTPS packet (starts with "RTPS" magic)
//!   2. `control.rs` -- CDR2-encoded `NackMsg` (missing-range list only)
//!
//! `on_nack()` tries RTPS parsing first, then falls back to NackMsg CDR2.
//!
//! ## Unicast retransmit routing
//!
//! When the NACKing reader's GUID is known (passed via `reader_guid` parameter,
//! or extracted from the raw RTPS header bytes 8..20 + ACKNACK submessage),
//! retransmits are sent UNICAST to the reader's discovered user-data locator
//! (from `EndpointRegistry`).  If no locator is available the packet falls
//! back to the existing multicast send so no regression occurs.
//!
//! EXCEPTION: ECS close-slot repairs (`ChangeKind::EcsClose`) are UNICAST
//! ONLY and are dropped when the reader cannot be fully resolved -- see
//! `WriterNackHandler::repair_ecs_close` for the rationale.

use super::runtime::{finalize_for_reader, ReaderWireProfile};
use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::{EndpointRegistry, GUID};
use crate::core::rtps_constants::{HDDS_VENDOR_ID_U16, INTERCOM_VENDOR_ID_U16};
use crate::engine::{NackFragHandler, NackHandler};
use crate::protocol::builder;
use crate::reliability::{
    CachedChange, ChangeKind, GapTx, HistoryCache, NackMsg, ReliableMetrics,
    WriterRetransmitHandler, ENTITYID_UNKNOWN,
};
use crate::transport::UdpTransport;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug)]
struct ReaderDestination {
    endpoint: SocketAddr,
    reader: GUID,
    classic_window: bool,
}

impl ReaderDestination {
    fn send(
        self,
        windows: &crate::protocol::dialect::sequence_window::WriterWindows,
        transport: &UdpTransport,
        packet: &[u8],
    ) -> std::io::Result<usize> {
        windows.send_classed(
            transport,
            packet,
            &self.endpoint,
            self.reader,
            self.classic_window,
        )
    }
}

pub(super) fn requires_classic_window(
    cache: &HistoryCache,
    fsm: Option<&DiscoveryFsm>,
    reader: Option<[u8; 16]>,
) -> bool {
    cache.wire_windows.is_group()
        && reader.is_some_and(|reader| {
            fsm.is_some_and(|fsm| fsm.requires_group_window(&GUID::from_bytes(reader).prefix))
        })
}

impl std::fmt::Display for ReaderDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.endpoint.fmt(f)
    }
}

/// Shared per-reader cumulative acknowledgment watermark table
/// (reader GUID -> highest SN acknowledged, i.e. ACKNACK bitmapBase - 1).
pub use crate::reliability::local_ack::AckTrack;

/// The highest sequence number every matched reliable reader has
/// acknowledged: the minimum over the per-reader watermarks, `u64::MAX`
/// when no reliable reader is matched (every change is then acknowledged by
/// all of them, vacuously - RTPS 2.5 8.4.7.4 `is_acked_by_all` iterates over
/// `matched_readers`).
///
/// Entries are added when a reliable reader matches and removed when it
/// unmatches (`dds::writer::builder`); ACKNACKs only move existing ones.
pub(super) fn acked_floor(track: &std::collections::HashMap<[u8; 16], u64>) -> u64 {
    track.values().copied().min().unwrap_or(u64::MAX)
}

/// The wire form of a cached instance lifecycle change: the key-only DATA
/// (K flag, PID_STATUS_INFO, the serialized @key fields as payload, plus
/// the coherent-set PIDs when the live emission carried them -- see
/// `ChangeMetadata::coherent_sn` / `group_sn`) it was when emitted live.
/// `None` when the change is not a lifecycle change; an empty packet when
/// it cannot be rebuilt (no endpoint context, no key hash).
///
/// One builder for both consumers of the history - NACK repair and the
/// late-joiner replay - so the two cannot send a dispose in two forms.
///
/// `spec`: the reader is of the spec GROUP class, which receives the
/// change's group sequence information (`CachedChange::group`) in the spec
/// form; every other reader receives today's form.
#[cfg(test)]
pub(super) fn lifecycle_change_packet(
    ctx: Option<builder::RtpsEndpointContext>,
    topic: &str,
    change: &CachedChange,
    spec: bool,
) -> Option<Vec<u8>> {
    lifecycle_change_packet_form(ctx, topic, change, GroupForm::of_spec(spec))
}

/// `lifecycle_change_packet` for a reader of `form` (plain included).
pub(super) fn lifecycle_change_packet_form(
    ctx: Option<builder::RtpsEndpointContext>,
    topic: &str,
    change: &CachedChange,
    form: GroupForm,
) -> Option<Vec<u8>> {
    let (coherent_sn, group_sn, group_tag) =
        member_group_args(form.for_change(change.group.is_some()), change);
    let status = change.metadata.status_info?;
    // The journaled INFO_TS, as for a sample; now() only for a change that
    // never captured one (see `ChangeMetadata::source_ts_known`).
    let source_ts = if change.metadata.source_ts_known {
        change.metadata.source_ts
    } else {
        builder::now_rtps_timestamp()
    };
    Some(match (ctx, change.metadata.key_hash) {
        (Some(ctx), Some(key_hash)) => builder::build_dispose_packet_with_context_coherent_ts(
            &ctx,
            topic,
            change.seq,
            &key_hash,
            &change.payload,
            status,
            change.metadata.cdr_version,
            source_ts,
            coherent_sn,
            group_sn,
            group_tag,
            // `change.payload` is already sealed when the live emission
            // was (see `ChangeMetadata::key_epoch`'s doc): never re-sniff
            // the cached bytes for a cryptographic header.
            change.metadata.key_epoch != 0,
        ),
        _ => Vec::new(),
    })
}

/// The small (unfragmented) DATA of cached user change `change`, as it was
/// emitted live: the journaled INFO_TS, CDR version, PID_KEY_HASH and
/// coherent-set markers (`ChangeMetadata::coherent_sn` / `group_sn`, the
/// set the sample was written in, whatever the writer's durability). An
/// empty packet when it cannot be built. `spec`: as for
/// [`lifecycle_change_packet`].
#[cfg(test)]
pub(super) fn user_data_change_packet(
    ctx: builder::RtpsEndpointContext,
    topic: &str,
    change: &CachedChange,
    source_ts: (u32, u32),
    spec: bool,
) -> Vec<u8> {
    user_data_change_packet_form(ctx, topic, change, source_ts, GroupForm::of_spec(spec))
}

/// `user_data_change_packet` for a reader of `form` (plain included).
pub(super) fn user_data_change_packet_form(
    ctx: builder::RtpsEndpointContext,
    topic: &str,
    change: &CachedChange,
    source_ts: (u32, u32),
    form: GroupForm,
) -> Vec<u8> {
    let (coherent_sn, group_sn, group_tag) =
        member_group_args(form.for_change(change.group.is_some()), change);
    builder::build_data_packet_grouped_ts(
        &ctx,
        topic,
        change.seq,
        &change.payload,
        change.metadata.cdr_version,
        source_ts,
        coherent_sn,
        group_sn,
        group_tag,
        change.metadata.key_hash.as_ref(),
        // As in `lifecycle_change_packet`: the cache already carries
        // whatever the live write sealed; read it, don't re-detect it.
        change.metadata.key_epoch != 0,
    )
}

/// The DATA_FRAGs repairing or replaying change `seq` (`payload`, with
/// its journaled `metadata` and `group` tag), fragmented as it was written
/// (`fragment_size`, its INFO_TS `source_ts`): the first carrying the
/// inline QoS of its coherent set and GROUP tags in the form a reader of
/// class `spec` received live. Empty when they cannot be built.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) fn change_frag_packets(
    ctx: &crate::protocol::builder::RtpsEndpointContext,
    topic: &str,
    seq: u64,
    payload: &[u8],
    metadata: &crate::reliability::ChangeMetadata,
    group: Option<&crate::protocol::group::GroupTag>,
    fragment_size: usize,
    source_ts: (u32, u32),
    spec: bool,
) -> Vec<Vec<u8>> {
    change_frag_packets_form(
        ctx,
        topic,
        seq,
        payload,
        metadata,
        group,
        fragment_size,
        source_ts,
        GroupForm::of_spec(spec),
    )
}

/// `change_frag_packets` for a reader of `form` (plain included).
#[allow(clippy::too_many_arguments)]
pub(super) fn change_frag_packets_form(
    ctx: &crate::protocol::builder::RtpsEndpointContext,
    topic: &str,
    seq: u64,
    payload: &[u8],
    metadata: &crate::reliability::ChangeMetadata,
    group: Option<&crate::protocol::group::GroupTag>,
    fragment_size: usize,
    source_ts: (u32, u32),
    form: GroupForm,
) -> Vec<Vec<u8>> {
    let (coherent_sn, group_sn, group_tag) = match form.for_change(group.is_some()) {
        GroupForm::Legacy => (metadata.coherent_sn, metadata.group_sn, None),
        GroupForm::Spec => (metadata.coherent_sn, metadata.group_sn, group),
        GroupForm::Plain => (None, None, None),
    };
    let mut packets = builder::build_data_frag_packets_ts(
        ctx,
        seq,
        payload,
        fragment_size,
        metadata.cdr_version,
        source_ts,
        metadata.key_epoch != 0,
    );
    let inline_qos = builder::data_frag_inline_qos(
        ctx,
        topic,
        coherent_sn,
        group_sn,
        group_tag,
        metadata.key_hash.as_ref(),
    );
    if !inline_qos.is_empty()
        && !packets.is_empty()
        && !builder::put_inline_qos_in_first_fragment(&mut packets, &inline_qos)
    {
        return Vec::new();
    }
    packets
}

/// Whether the participant of reader `reader_guid` is of the spec GROUP
/// class (`GroupDialect::Spec`, decided at its pairing).
pub(super) fn reader_is_spec(fsm: Option<&DiscoveryFsm>, reader_guid: Option<[u8; 16]>) -> bool {
    match (fsm, reader_guid) {
        (Some(fsm), Some(guid)) => {
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(&guid[..12]);
            fsm.speaks_spec_group(&prefix)
        }
        _ => false,
    }
}

/// The wire form of a GROUP change for one reader.
///
/// `Legacy` is today's form (per-writer PID_COHERENT_SET, HDDS 0x8030 and
/// 0x0053). `Spec` is the RTPS v2.5 GROUP form, for a reader of the spec
/// class. `Plain` is plain DATA with no coherent-set PIDs and no end-of-set
/// marker, for a reader that reads per-writer sets only and takes plain DATA
/// from a GROUP Publisher (`GroupDialect::SpecReceive`, vendor 0x0114). Its
/// close SN is retired with a GAP (`plain_close_gap`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GroupForm {
    Legacy,
    Spec,
    Plain,
}

impl GroupForm {
    /// The form of a bool-keyed entry point: spec or not, never plain.
    #[cfg(test)]
    pub(super) fn of_spec(spec: bool) -> Self {
        if spec {
            Self::Spec
        } else {
            Self::Legacy
        }
    }

    /// The form a change of a `group` (GROUP Publisher) scope is sent in.
    /// Plain is for GROUP changes only: any other change keeps today's form.
    pub(super) fn for_change(self, group: bool) -> Self {
        match self {
            Self::Plain if !group => Self::Legacy,
            form => form,
        }
    }
}

/// The wire form of a GROUP change for reader `reader_guid`, from the
/// participant's pairing verdicts (`speaks_plain_group`, then `speaks_spec_group`).
pub(super) fn reader_form(fsm: Option<&DiscoveryFsm>, reader_guid: Option<[u8; 16]>) -> GroupForm {
    match (fsm, reader_guid) {
        (Some(fsm), Some(guid)) => {
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(&guid[..12]);
            if fsm.speaks_plain_group(&prefix) {
                GroupForm::Plain
            } else if fsm.speaks_spec_group(&prefix) {
                GroupForm::Spec
            } else {
                GroupForm::Legacy
            }
        }
        _ => GroupForm::Legacy,
    }
}

/// The GAP that retires the close SN `seq` for a plain reader: the
/// single-SN form of the InterCOM retirement GAP (gapStart = seq, gap list
/// based at seq + 1, empty bitmap). Empty when `seq` cannot be retired.
pub(super) fn plain_close_gap(
    ctx: &builder::RtpsEndpointContext,
    reader_entity_id: [u8; 4],
    seq: u64,
) -> Vec<u8> {
    let Some(next) = seq.checked_add(1) else {
        return Vec::new();
    };
    builder::build_gap_packet_from_parts(
        &reader_entity_id,
        &ctx.writer_entity_id,
        seq,
        next,
        &[],
        ctx.guid_prefix,
    )
}

/// The coherent-set PIDs and GROUP tag a member (or dispose) of `change`
/// carries in `form`. Plain carries none of them.
fn member_group_args(
    form: GroupForm,
    change: &CachedChange,
) -> (
    Option<u64>,
    Option<u64>,
    Option<&crate::protocol::group::GroupTag>,
) {
    match form {
        GroupForm::Legacy => (change.metadata.coherent_sn, change.metadata.group_sn, None),
        GroupForm::Spec => (
            change.metadata.coherent_sn,
            change.metadata.group_sn,
            change.group.as_ref(),
        ),
        GroupForm::Plain => (None, None, None),
    }
}

/// Keep one acknowledgement watermark per matched RELIABLE reader (RTPS 2.5
/// 8.4.7.4 `matched_reader_add` / `matched_reader_remove`) and tell the
/// history the new floor.
///
/// A new reader's watermark starts where the writer's debt to it starts:
/// at the last change already written when either side is VOLATILE (the
/// reader is owed only what comes next), at 0 when both are durable (it is
/// owed the history). A durable writer keeps its history for late joiners
/// that ASK for it: DURABILITY controls "whether the Service will actually
/// make data available to late-joining readers" (DDS 1.4 2.2.3.4), and a
/// VOLATILE reader asked for none.
/// A best-effort reader acknowledges nothing and never holds the history
/// back. The floor is published under the table's lock, so two changes
/// racing cannot publish it out of order.
///
/// Returns the watermark of a ReaderProxy this call created, `None` when it
/// created none (a reader already tracked, a best-effort one, a departure).
pub(super) fn track_reader_proxy(
    track: &AckTrack,
    cache: &HistoryCache,
    writer_volatile: bool,
    change: crate::dds::match_notification::PeerChange,
) -> Option<u64> {
    use crate::dds::match_notification::PeerChange;
    let mut map = match track.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let created = match change {
        PeerChange::Matched {
            guid,
            reliable: true,
            volatile: reader_volatile,
        } => {
            // The last change actually written, not the sequence counter:
            // a number reserved and then given back by a failed write
            // is reused by a write made after this match, which
            // this reader is owed.
            //
            // A VOLATILE reader is owed nothing written before its match,
            // except the end of set still retained: that marker is not
            // acknowledged by this reader, and an acknowledgement that
            // skipped it would let the writer discard it (RTPS v2.5
            // Sec.8.7.6, Sec.8.4.2.2.3). Left unowed, the reader's part of
            // the set never closes, and the heartbeat firstSN passes it.
            let owed_after = if writer_volatile || reader_volatile {
                let last = cache.highest_inserted();
                cache
                    .lowest_retained_end_of_set()
                    .map_or(last, |marker| last.min(marker.saturating_sub(1)))
            } else {
                0
            };
            match map.entry(guid.as_bytes()) {
                std::collections::hash_map::Entry::Occupied(_) => None,
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(owed_after);
                    Some(owed_after)
                }
            }
        }
        PeerChange::Matched {
            reliable: false, ..
        } => return None,
        PeerChange::Unmatched { guid } => {
            // A reader this writer never tracked changes nothing.
            map.remove(&guid.as_bytes())?;
            None
        }
    };
    cache.set_acked_floor(acked_floor(&map));
    created
}

/// Shared encoding and routing parameters for nack handlers.
///
/// Grouping these three fields keeps each handler constructor within the
/// 7-argument clippy limit while adding the new `endpoint_registry`.
pub(super) struct RetransmitCfg {
    /// RTPS endpoint context (GUID prefix, entity IDs, encapsulation kind).
    pub rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    /// Per-reader unicast locator table (from SEDP discovery).
    /// When populated, retransmits are sent directly to the NACKing reader
    /// instead of to the multicast group.
    pub endpoint_registry: Option<EndpointRegistry>,
    /// Writer's canonical (XCDR2) encapsulation kind, derived from the
    /// type's extensibility (@final 0x0007 / @appendable 0x0009 /
    /// @mutable 0x000B). Used by the no-context retransmit fallback so
    /// re-fragmented payloads keep the same wire encapsulation as the
    /// original DATA_FRAGs.
    pub canonical_encapsulation_kind: u16,
    /// Per-reader cumulative acknowledgment watermark, shared with the
    /// owning DataWriter (reader GUID -> highest SN acknowledged, i.e.
    /// ACKNACK bitmapBase - 1). Fed here because the nack handler is the
    /// only component that sees every reader ACKNACK; consumed by
    /// `DataWriter::fully_acked()`. `None` on handlers that must not feed
    /// it (fragment-level).
    pub ack_track: Option<AckTrack>,
    /// Shared large-payload route (fragment size + optional multicast
    /// destination). MUST be the same instance as the live write path's:
    /// retransmits that fragment with a different size corrupt the
    /// reader's reassembly (fragment numbering diverges).
    pub frag_route: Arc<super::frag_route::FragRouteProfile>,
    /// Discovery FSM used to resolve a NACKing reader's RTPS vendor id
    /// (`DiscoveryFsm::vendor_id_for_participant`). Required by the ECS
    /// close-slot repair path to regenerate the dialect-correct close
    /// form; when `None` (or the vendor is unresolved) ECS repairs are
    /// dropped, never guessed. Unused by the fragment-level handler.
    pub discovery_fsm: Option<Arc<DiscoveryFsm>>,
}

/// Participant GUID (12-byte prefix + `RTPS_ENTITYID_PARTICIPANT`) of an
/// endpoint GUID, for `DiscoveryFsm::vendor_id_for_participant` lookups.
pub(super) fn participant_guid_of(endpoint_guid: [u8; 16]) -> GUID {
    let mut bytes = endpoint_guid;
    bytes[12..16].copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
    GUID::from_bytes(bytes)
}

/// Split the ranges a reader requested into those it is owed and the
/// sequence numbers at or below `not_owed_through`, which it is not.
///
/// The requested ranges come from one ACKNACK's bitmap, at most 256
/// sequence numbers (RTPS 2.5 9.4.2.6), so listing the second part is
/// bounded.
pub(super) fn split_at_watermark(
    ranges: Vec<std::ops::Range<u64>>,
    not_owed_through: Option<u64>,
) -> (Vec<std::ops::Range<u64>>, Vec<u64>) {
    let Some(through) = not_owed_through else {
        return (ranges, Vec::new());
    };
    let owed_from = through.saturating_add(1);
    let mut owed = Vec::with_capacity(ranges.len());
    let mut not_owed = Vec::new();
    for range in ranges {
        not_owed.extend(range.start..range.end.min(owed_from));
        if range.end > owed_from {
            owed.push(range.start.max(owed_from)..range.end);
        }
    }
    (owed, not_owed)
}

/// Whether this writer leaves the ACKNACK (or NACK_FRAG) of `reader_guid`
/// unanswered: no repair, no GAP, no acknowledgment recorded.
///
/// 1. A reader the security plugins do not admit on `topic`
///    (`DiscoveryFsm::admits_remote_endpoint`: its participant not
///    authenticated where the governance requires it, its handshake not
///    complete, its permissions not granting the topic in its partitions),
///    whether discovery announced it or not, paired or not. DDS Security
///    v1.1 Sec.8.8.7.1, 9.4.3: such a reader is not matched, and answering
///    it would repair the topic's data, and for a TRANSIENT_LOCAL writer its
///    history, to a reader refused the topic.
/// 2. A reader discovery announced on `topic` that this writer has not
///    paired: its proxy is created when discovery pairs the two
///    (`MatchNotificationRegistry::pair_at_discovery`, ahead of the
///    deferred match), so an announced reader without one is a pairing the
///    writer does not make (incompatible QoS, refused by
///    `ShmPolicy::Require`, best-effort). RTPS 2.5 8.4.9.2 describes the
///    writer's behaviour "with respect to each matched Reader"; answering
///    such a reader would repair, for a VOLATILE one, the history it is not
///    owed. Judged from every reader discovery holds
///    (`registered_readers_for_topic`): the list our writers send to leaves
///    a refused reader out, and a reader missing from it would read as "a
///    GUID discovery never announced" and be served. A GUID discovery never
///    announced is judged by `unpaired_reader_unanswered`: its SEDP may not
///    have reached this writer yet. A request naming no entity is served.
pub(super) fn discovered_but_unpaired(
    track: Option<&AckTrack>,
    fsm: Option<&DiscoveryFsm>,
    topic: &str,
    reader_guid: [u8; 16],
) -> bool {
    let Some(fsm) = fsm else {
        return false;
    };
    #[cfg(feature = "security")]
    if !fsm.admits_remote_endpoint(
        topic,
        &crate::core::discovery::GUID::from_bytes(reader_guid),
        false,
    ) {
        return true;
    }
    let Some(track) = track else {
        return false;
    };
    let paired = match track.lock() {
        Ok(map) => map.contains_key(&reader_guid),
        Err(poisoned) => poisoned.into_inner().contains_key(&reader_guid),
    };
    !paired
        && fsm
            .registered_readers_for_topic(topic)
            .iter()
            .any(|reader| reader.endpoint_guid.as_bytes() == reader_guid)
}

/// Whether a request naming `reader_guid` is left unanswered because the
/// reader has no ReaderProxy with this writer yet (RTPS 2.5 Table 8.66: the
/// acknowledgement transitions belong to a matched proxy, T1 adds it, T16
/// removes it). Besides an announced reader that is not paired
/// (`discovered_but_unpaired`), this covers a reader discovery has not
/// announced: its SEDP can reach the writer after its first ACKNACK, and
/// that ACKNACK would otherwise repair the history it is not owed (DDS 1.4
/// 2.2.3.4). It asks again at the next HEARTBEAT, once paired. A request
/// naming no entity (ENTITYID_UNKNOWN) names no reader to judge, and stays
/// as it was.
pub(super) fn unpaired_reader_unanswered(
    track: Option<&AckTrack>,
    fsm: Option<&DiscoveryFsm>,
    topic: &str,
    reader_guid: [u8; 16],
) -> bool {
    if discovered_but_unpaired(track, fsm, topic, reader_guid) {
        return true;
    }
    let (Some(track), Some(_)) = (track, fsm) else {
        return false;
    };
    let named = reader_guid[12..16] != [0u8; 4];
    let paired = match track.lock() {
        Ok(map) => map.contains_key(&reader_guid),
        Err(poisoned) => poisoned.into_inner().contains_key(&reader_guid),
    };
    named && !paired
}

/// Whether a NACK that names no reader (the CDR2 control path of a caller
/// that passes no GUID, a NACK_FRAG without its sender) is left unanswered:
/// under the security plugins nothing shows it comes from a reader they
/// admit (`discovered_but_unpaired` judges a named one), and with no reader
/// to address, its repair would go to the multicast group (DDS Security
/// v1.1 Sec.8.8.7.1, 9.4.3). False without the security feature or without
/// the plugins: served as before.
pub(super) fn unattributed_nack_refused(fsm: Option<&DiscoveryFsm>) -> bool {
    #[cfg(feature = "security")]
    {
        fsm.is_some_and(DiscoveryFsm::admission_gate_active)
    }
    #[cfg(not(feature = "security"))]
    {
        let _ = fsm;
        false
    }
}

/// Reader entityId: the trailing 4 bytes of a 16-byte endpoint GUID.
pub(super) fn reader_entity_id_of(reader_guid: [u8; 16]) -> [u8; 4] {
    [
        reader_guid[12],
        reader_guid[13],
        reader_guid[14],
        reader_guid[15],
    ]
}

/// The end of set `change` in the spec GROUP form for one reader of the
/// spec class, from the group sequence information journaled with it;
/// `None` when it has none (a set of no GROUP Publisher).
pub(super) fn spec_ecs_packet(
    ctx: &crate::protocol::builder::RtpsEndpointContext,
    topic: &str,
    change: &CachedChange,
    reader_entity_id: [u8; 4],
) -> Option<Vec<u8>> {
    let tag = change.group?;
    let source_ts = if change.metadata.source_ts_known {
        change.metadata.source_ts
    } else {
        builder::now_rtps_timestamp()
    };
    let mut patched = *ctx;
    patched.reader_entity_id = reader_entity_id;
    let packet = builder::build_ecs_spec_ts(&patched, topic, change.seq, &tag, source_ts);
    (!packet.is_empty()).then_some(packet)
}

/// Build the dialect-correct repair packet for one NACKed ECS close slot,
/// or `None` when the repair must be DROPPED.
///
/// Regenerates the SAME wire form the live close path produced for this
/// reader's dialect (`WriterCoherentBridge::dispatch_ecs`, same builders):
///
/// * `Some(INTERCOM_VENDOR_ID_U16)` (0x0105): single-SN GAP retiring the
///   close slot (`gapStart = seq`, `gapList.base = seq + 1`, empty
///   bitmap), per RTPS v2.5 SS8.3.8.4 ("the SN is not relevant to this
///   reader"). For this dialect HDDS does not re-send the bare flags-0x01
///   close marker on repair: a reader that NACKs the close slot keeps its
///   ACKNACK bitmapBase pinned there, and re-sending the same marker
///   would leave it pinned. Retiring the SN with a GAP is the RTPS
///   mechanism that lets the reader's reliable state advance past the
///   slot; the live close path has already delivered the close event.
/// * Other `Some(v)` with `v != HDDS_VENDOR_ID_U16` (classic vendor):
///   bare close marker via
///   `build_ecs_close_marker` -- a real DATA on the writer SN with
///   `D=0 K=0 Q=0`, no inline QoS, no payload. Classic collators read a
///   sample with no coherent tag as "current set closed"; anything else
///   (an ordinary payload-less user DATA, or the HDDS ECS with its
///   distinct PID_COHERENT_SET) is materialized as an extra sample
///   (one sample more than the writer wrote).
/// * `Some(HDDS_VENDOR_ID_U16)`: native ECS DATA via
///   `build_ecs_data_submessage` (`D=0 K=0 Q=1`, PID_COHERENT_SET
///   [+ PID_GROUP_COHERENT_SET_HDDS], publisher entity id tag), patched
///   to the requesting reader's entity id -- what an HDDS peer needs to
///   commit the set via `on_ecs`. Requires the cached `coherent_sn`
///   marker; an EcsClose entry without one cannot be regenerated.
/// * `None` (vendor unresolved): DROP. Never guess a close dialect and
///   never send the native ECS form to a reader that may be classic.
pub(super) fn build_ecs_repair_packet(
    ctx: &crate::protocol::builder::RtpsEndpointContext,
    topic: &str,
    change: &CachedChange,
    reader_entity_id: [u8; 4],
    reader_vendor: Option<u16>,
) -> Option<Vec<u8>> {
    build_ecs_repair_packet_form(
        ctx,
        topic,
        change,
        reader_entity_id,
        reader_vendor,
        GroupForm::Legacy,
    )
}

/// `build_ecs_repair_packet` for a reader of `form`: a plain reader gets the
/// GAP that retires the close SN instead of any end-of-set marker.
pub(super) fn build_ecs_repair_packet_form(
    ctx: &crate::protocol::builder::RtpsEndpointContext,
    topic: &str,
    change: &CachedChange,
    reader_entity_id: [u8; 4],
    reader_vendor: Option<u16>,
    form: GroupForm,
) -> Option<Vec<u8>> {
    if form == GroupForm::Plain && change.group.is_some() {
        let gap = plain_close_gap(ctx, reader_entity_id, change.seq);
        return (!gap.is_empty()).then_some(gap);
    }
    // Replay the journaled wire timestamp (source_ts) so every branch
    // below reproduces the live ECS/close-marker bytes exactly; fall back
    // to now() only for an entry whose source_ts was never captured
    // (see ChangeMetadata::source_ts doc). Hoisted above the vendor match so
    // the classic close-marker branch and the native-ECS branch share it.
    let source_ts = if !change.metadata.source_ts_known {
        builder::now_rtps_timestamp()
    } else {
        change.metadata.source_ts
    };
    match reader_vendor {
        Some(INTERCOM_VENDOR_ID_U16) => {
            // Single-SN GAP: gapStart = seq, gapList = empty set based at
            // seq + 1, no bitmap. Built from explicit parts so the SNs go
            // straight to the wire encoder; the header carries our real
            // participant prefix so the reader can attribute the GAP to
            // this writer proxy (same framing as the evicted-SN GAP path).
            let packet = builder::build_gap_packet_from_parts(
                &reader_entity_id,
                &ctx.writer_entity_id,
                change.seq,
                change.seq + 1,
                &[],
                ctx.guid_prefix,
            );
            if packet.is_empty() {
                None
            } else {
                Some(packet)
            }
        }
        Some(v) if v != HDDS_VENDOR_ID_U16 => Some(builder::build_ecs_close_marker_ts(
            ctx,
            &reader_entity_id,
            change.seq,
            source_ts,
        )),
        Some(_) => {
            let coherent_sn = change.metadata.coherent_sn?;
            let mut patched_ctx = *ctx;
            patched_ctx.reader_entity_id = reader_entity_id;
            // Same publisher entity id tag as the live ECS emission
            // (WriterCoherentBridge::emit_ecs_data).
            let packet = builder::build_ecs_data_submessage_ts(
                &patched_ctx,
                topic,
                change.seq,
                coherent_sn,
                change.metadata.group_sn,
                Some(ctx.publisher_entity_id),
                source_ts,
            );
            if packet.is_empty() {
                None
            } else {
                Some(packet)
            }
        }
        None => None,
    }
}

pub(super) struct WriterNackHandler {
    topic: String,
    cache: Arc<HistoryCache>,
    transport: Arc<UdpTransport>,
    metrics: Arc<ReliableMetrics>,
    gap_tx: Mutex<GapTx>,
    rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    /// Per-reader unicast locator table (from SEDP discovery).
    /// When populated, retransmits are sent directly to the NACKing reader
    /// instead of to the multicast group.
    endpoint_registry: Option<EndpointRegistry>,
    /// See `RetransmitCfg::ack_track`.
    ack_track: Option<AckTrack>,
    /// See `RetransmitCfg::frag_route`.
    frag_route: Arc<super::frag_route::FragRouteProfile>,
    /// See `RetransmitCfg::discovery_fsm` (ECS close repair only).
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    #[cfg(test)]
    before_ack_apply: Option<Box<dyn Fn() + Send + Sync>>,
}

impl WriterNackHandler {
    pub fn new(
        topic: String,
        cache: Arc<HistoryCache>,
        transport: Arc<UdpTransport>,
        metrics: Arc<ReliableMetrics>,
        cfg: RetransmitCfg,
    ) -> Self {
        Self {
            topic,
            cache,
            transport,
            metrics,
            gap_tx: Mutex::new(GapTx::new()),
            rtps_endpoint: cfg.rtps_endpoint,
            endpoint_registry: cfg.endpoint_registry,
            ack_track: cfg.ack_track,
            frag_route: cfg.frag_route,
            discovery_fsm: cfg.discovery_fsm,
            #[cfg(test)]
            before_ack_apply: None,
        }
    }

    /// Resolve the unicast SocketAddr for a reader given its 16-byte GUID.
    ///
    /// Checks the SEDP reader-locator table first (per-reader unicast port),
    /// then falls back to the participant SPDP default_unicast_locator.
    /// Returns `None` when neither is known (multicast fallback required).
    fn resolve_unicast(&self, reader_guid: [u8; 16]) -> Option<ReaderDestination> {
        let reg = self.endpoint_registry.as_ref()?;
        let guid = GUID::from_bytes(reader_guid);
        reg.get_reader_locator(&guid)
            .or_else(|| {
                // Fall back to the reader's participant default_unicast locator
                // (SPDP PID_DEFAULT_UNICAST_LOCATOR) when the reader announced no
                // per-reader SEDP locator -- mirrors the live/HEARTBEAT routing in
                // runtime.rs. Without this a NACKing reader whose per-reader locator
                // is unknown gets retransmits only via multicast, which some readers
                // (INSTANCE-scope TRANSIENT_LOCAL) do not receive.
                let mut pbytes = reader_guid;
                pbytes[12..16]
                    .copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
                reg.get(&GUID::from_bytes(pbytes))
            })
            .map(|endpoint| ReaderDestination {
                endpoint,
                reader: guid,
                classic_window: requires_classic_window(
                    &self.cache,
                    self.discovery_fsm.as_deref(),
                    Some(reader_guid),
                ),
            })
    }

    /// Send a single DATA (or DATA_FRAG) packet, preferring unicast to
    /// `dest` when available, falling back to multicast otherwise.
    ///
    /// The multicast fallback MUST use the user-data multicast group
    /// (`send_user_data_multicast`, port 7401 for domain 0), NOT the bare
    /// `transport.send()` which targets the metatraffic/SPDP discovery
    /// multicast (port 7400). A retransmit sent to the discovery port is
    /// received by peers' SPDP readers and dropped -- the durable reader
    /// never gets the sample, never advances its reliable ACK base, and
    /// the writer loops re-sending the whole history to the wrong group
    /// (for durable coherent or ordered-access writers the result is a
    /// full-history retransmit storm that delivers nothing).
    ///
    /// A packet in the spec GROUP form (`group`) does not fall back to the
    /// multicast group while a participant of the spec class is known
    /// (`runtime::multicasts`): the group's audience is of no one class.
    fn send_unicast_or_multicast(
        &self,
        packet: &[u8],
        dest: Option<ReaderDestination>,
        group: bool,
    ) {
        if let Some(addr) = dest {
            if let Err(e) = addr.send(&self.cache.wire_windows, &self.transport, packet) {
                log::debug!(
                    "[writer] Retransmit unicast to {} failed ({}), falling back to multicast",
                    addr,
                    e
                );
                self.multicast_unless_group(packet, group);
            }
        } else {
            self.multicast_unless_group(packet, group);
        }
    }

    /// Multicast `packet`, but not one of a GROUP change (`group`) while a
    /// participant of the spec class is known: the multicast group's
    /// readers are of no one class, and a reader of the spec class given
    /// the 1.4.x form of a change keys its set apart. A reliable reader
    /// asks again once it is known.
    fn multicast_unless_group(&self, packet: &[u8], group: bool) {
        if self.multicast_open(group) {
            let _ = self.transport.send_user_data_multicast(packet);
        } else {
            log::debug!(
                "[writer] repair on topic '{}': no multicast to an audience of unknown class \
                 or of a protected topic",
                self.topic
            );
        }
    }

    /// Whether a repair (`group`: of a GROUP change) may reach a multicast
    /// group, the user-data one or the large-payload route's: not a GROUP
    /// change while a participant of the spec class is known, and
    /// nothing of a topic whose multicast fallback is closed - our
    /// governance refuses an unauthenticated participant on it, and anyone
    /// may listen on a group (`runtime::multicast_fallback_closed`, DDS
    /// Security v1.1 Sec.8.8.2.2, 8.8.7.1).
    fn multicast_open(&self, group: bool) -> bool {
        !self.cache.wire_windows.is_group()
            && super::runtime::multicasts(group, self.discovery_fsm.as_deref())
            && !self.multicast_closed()
    }

    /// Whether this writer's topic keeps off every multicast group
    /// (`runtime::multicast_fallback_closed`).
    fn multicast_closed(&self) -> bool {
        super::runtime::multicast_fallback_closed(self.discovery_fsm.as_deref(), &self.topic)
    }

    /// Send a per-reader retransmit that must be finalized for exactly one
    /// reader (readerEntityId patch and, when `fragmented == false`, the
    /// zzdds/InterCOM vendor transforms -- see `finalize_for_reader`), and
    /// that must NEVER reach the multicast group in finalized form.
    ///
    /// `canonical` is the un-finalized packet. `profile` and `unicast_dest`
    /// come from two INDEPENDENT lookups (`ReaderWireProfile` resolution
    /// vs. `resolve_unicast`) and can disagree: a reader GUID can resolve
    /// a wire profile while `resolve_unicast` finds no locator for it (no
    /// SEDP entry yet, or no SPDP default_unicast_locator either). Folding
    /// finalize-then-send into one call keeps that disagreement from ever
    /// producing a finalized packet with nowhere to go but multicast:
    /// * `dest = Some(addr)`: finalize and send unicast.
    /// * A reader whose identity resolved (`profile` is `Some`) is never
    ///   served by multicast: the canonical packet carries ENTITYID_UNKNOWN,
    ///   so every reader of every participant on the group would take the
    ///   repair, a VOLATILE one owed nothing of it included (DDS 1.4
    ///   2.2.3.4). With no locator, or a failed send, it is dropped; the
    ///   reader asks again.
    /// * An unresolved requester keeps the multicast of the CANONICAL packet,
    ///   never finalized.
    ///
    /// `group`: the change is one of a GROUP Publisher's writer: its
    /// canonical packet does not reach the multicast group while a
    /// participant of the spec class is known (`multicast_unless_group`).
    fn send_finalized_or_multicast(
        &self,
        canonical: &[u8],
        profile: Option<ReaderWireProfile>,
        fragmented: bool,
        dest: Option<ReaderDestination>,
        group: bool,
    ) {
        match dest {
            Some(addr) => {
                let to_send = match profile {
                    Some(p) => finalize_for_reader(canonical.to_vec(), p, fragmented),
                    None => canonical.to_vec(),
                };
                if let Err(e) = addr.send(&self.cache.wire_windows, &self.transport, &to_send) {
                    if profile.is_some() {
                        log::debug!(
                            "[writer] Retransmit unicast to {} failed ({}); dropped, the \
                             reader asks again",
                            addr,
                            e
                        );
                    } else {
                        log::debug!(
                            "[writer] Retransmit unicast to {} failed ({}), falling back to \
                             multicast with the canonical (un-finalized) packet",
                            addr,
                            e
                        );
                        self.multicast_unless_group(canonical, group);
                    }
                }
            }
            None if profile.is_some() => {
                log::debug!("[writer] Retransmit for a reader with no locator: dropped");
            }
            None => self.multicast_unless_group(canonical, group),
        }
    }

    /// Repair a NACKed ECS close slot with the dialect-correct close
    /// form, UNICAST ONLY. Returns `true` when a repair was sent.
    ///
    /// An ECS close slot is NEVER repaired as ordinary user DATA: its
    /// cached payload is empty, so the ordinary repair path would emit a
    /// payload-less user DATA that a classic receiver may
    /// materialize as an extra sample (one sample more than the writer
    /// wrote, under loss). Instead the repair
    /// regenerates the SAME wire form the live close path produced for
    /// this reader's dialect, or -- for the vendor 0x0105 dialect --
    /// retires the SN with a
    /// single-SN GAP per RTPS v2.5 SS8.3.8.4 (see
    /// `build_ecs_repair_packet` for the per-vendor forms).
    ///
    /// CORE RULE: the repair requires ALL of (resolved reader
    /// GUID, unicast destination, RTPS endpoint context, vendor resolved
    /// via `DiscoveryFsm::vendor_id_for_participant`). If ANY is missing,
    /// or the unicast send fails, the repair is DROPPED with a debug log.
    /// NEVER fall back to multicast: a close form is per-reader-dialect,
    /// and a multicast repair reaches readers that have not matched yet (a
    /// not-yet-matched classic collator can fold the broadcast marker into
    /// its collation and stall, on VOLATILE coherent topics). NEVER
    /// send the native ECS form to a non-HDDS or unresolved reader (its
    /// PID_COHERENT_SET reads as a phantom singleton set to classic
    /// collators). A dropped repair is safe: the reader keeps NACKing and
    /// is served once its GUID / locator / vendor resolve.
    fn repair_ecs_close(
        &self,
        change: &CachedChange,
        resolved_guid: Option<[u8; 16]>,
        unicast_dest: Option<ReaderDestination>,
    ) -> bool {
        let (Some(reader_guid), Some(dest), Some(ctx)) =
            (resolved_guid, unicast_dest, self.rtps_endpoint)
        else {
            log::debug!(
                "[writer] ECS repair DROPPED for seq {} topic={}: reader GUID / unicast \
                 locator / RTPS context unresolved (ECS repairs are never multicast)",
                change.seq,
                self.topic
            );
            return false;
        };
        let vendor = self
            .discovery_fsm
            .as_deref()
            .and_then(|fsm| fsm.vendor_id_for_participant(&participant_guid_of(reader_guid)));
        // An InterCOM reader NACKs the boundary of a set on every HEARTBEAT it
        // answers. While that boundary's retirement is deferred to the close
        // of the set that follows, the GAP is not sent from here: it would
        // release the next set at an arbitrary phase of its transmission.
        // The reader keeps NACKing; the deferred GAP answers it.
        if vendor == Some(INTERCOM_VENDOR_ID_U16)
            && self.cache.deferred_close_gaps.holds(
                &reader_guid,
                change.seq,
                std::time::Instant::now(),
            )
        {
            log::debug!(
                "[writer] ECS repair HELD for seq {} topic={}: boundary retirement deferred \
                 to the close of the next set",
                change.seq,
                self.topic
            );
            return false;
        }
        let form = reader_form(self.discovery_fsm.as_deref(), Some(reader_guid))
            .for_change(change.group.is_some());
        let spec = form == GroupForm::Spec;
        let spec_packet = spec
            .then(|| spec_ecs_packet(&ctx, &self.topic, change, reader_entity_id_of(reader_guid)))
            .flatten();
        // The end of a set its writer had no part in is for readers of the
        // spec class only; any other reader is told its SN is not for it.
        // A plain reader is told with the plain GAP (no GROUP extension).
        let idle = change
            .group
            .is_some_and(|tag| tag.part_first_sn == Some(change.seq));
        let idle_gap = (idle && !spec && form != GroupForm::Plain).then(|| {
            builder::build_gap_packet_filtered(
                &reader_entity_id_of(reader_guid),
                &ctx.writer_entity_id,
                change.seq,
                ctx.guid_prefix,
            )
        });
        let Some(packet) = idle_gap.or(spec_packet).or_else(|| {
            build_ecs_repair_packet_form(
                &ctx,
                &self.topic,
                change,
                reader_entity_id_of(reader_guid),
                vendor,
                form,
            )
        }) else {
            log::debug!(
                "[writer] ECS repair DROPPED for seq {} topic={}: reader vendor unresolved \
                 (vendor={:?}) or ECS metadata incomplete (never guess a close dialect)",
                change.seq,
                self.topic,
                vendor
            );
            return false;
        };
        match dest.send(&self.cache.wire_windows, &self.transport, &packet) {
            Ok(_) => {
                log::debug!(
                    "[writer] ECS repair sent unicast to {} for seq {} topic={} vendor={:?}",
                    dest,
                    change.seq,
                    self.topic,
                    vendor
                );
                true
            }
            Err(e) => {
                // Unicast send error: DROP, no multicast fallback (see above).
                log::debug!(
                    "[writer] ECS repair DROPPED for seq {} topic={}: unicast to {} failed ({})",
                    change.seq,
                    self.topic,
                    dest,
                    e
                );
                false
            }
        }
    }

    /// The changes `gap` declares that a GROUP Publisher's writer took and
    /// never made (`HistoryCache::record_group_hole`), as (SN, GSN).
    fn group_holes_of(&self, gap: &crate::reliability::GapMsg) -> Vec<(u64, u64)> {
        let declared = gap.lost_sequences();
        let (Some(&first), Some(&last)) = (declared.first(), declared.last()) else {
            return Vec::new();
        };
        let mut holes = self.cache.group_holes_in(first, last);
        holes.retain(|(seq, _)| declared.binary_search(seq).is_ok());
        holes
    }

    /// `gap` to a reader of the spec class, `holes` among what it
    /// declares: first a GAP of each hole with the GroupInfoFlag naming its
    /// GSN (RTPS v2.5 Sec.8.3.8.4, Sec.9.4.5.6), which the reader takes
    /// for a change in no history, so in no coherent set; then the rest of
    /// what `gap` declares, by contiguous ranges, without the holes. The
    /// reader learns a hole from its GROUP GAP alone: told first by a plain
    /// GAP, it took the hole for a change lost, and lost its set with it.
    fn send_gap_around_holes(
        &self,
        gap: &crate::reliability::GapMsg,
        holes: &[(u64, u64)],
        gap_prefix: [u8; 12],
        unicast_dest: Option<ReaderDestination>,
    ) {
        for &(seq, gsn) in holes {
            let packet = builder::build_gap_packet_group(
                &gap.reader_id(),
                &gap.writer_id(),
                seq,
                gsn,
                gsn,
                gap_prefix,
            );
            if !packet.is_empty() {
                // The GroupInfoFlag form: a reader of the spec class's.
                self.send_unicast_or_multicast(&packet, unicast_dest, true);
            }
        }
        let mut cuts: Vec<u64> = holes.iter().map(|(seq, _)| *seq).collect();
        cuts.sort_unstable();
        for range in gap.lost_ranges() {
            let mut start = range.start;
            for &cut in cuts.iter().filter(|&&cut| range.contains(&cut)) {
                if start < cut {
                    self.send_range_gap(gap, start, cut, gap_prefix, unicast_dest);
                }
                start = cut + 1;
            }
            if start < range.end {
                self.send_range_gap(gap, start, range.end, gap_prefix, unicast_dest);
            }
        }
    }

    /// A GAP of `gap`'s reader and writer declaring `start..end`.
    fn send_range_gap(
        &self,
        gap: &crate::reliability::GapMsg,
        start: u64,
        end: u64,
        gap_prefix: [u8; 12],
        unicast_dest: Option<ReaderDestination>,
    ) {
        let packet = builder::build_gap_packet_from_parts(
            &gap.reader_id(),
            &gap.writer_id(),
            start,
            end,
            &[],
            gap_prefix,
        );
        if !packet.is_empty() {
            self.send_unicast_or_multicast(&packet, unicast_dest, false);
        }
    }

    /// Whether an ACKNACK naming `an_writer_id` is this writer's to service
    /// (RTPS v2.5 8.3.8.1: writerId "identifies the Writer entity that is
    /// the target of the AckNack message"). Unlike readerId on a HEARTBEAT
    /// or GAP (8.3.7.5 / 8.3.8.4), the spec gives writerId no
    /// ENTITYID_UNKNOWN broadcast form: Table 8.40 lists no such case, and
    /// a sweep of 1,387,238 real ACKNACKs across every vendor in the OMG
    /// matrix found none with writerId UNKNOWN. An ACKNACK that carries it
    /// anyway names no writer, so it is refused like any other mismatch,
    /// never treated as "every writer of the participant repairs on it".
    fn claims_acknack(&self, an_writer_id: [u8; 4]) -> bool {
        let Some(ctx) = self.rtps_endpoint else {
            return true;
        };
        if an_writer_id != ctx.writer_entity_id {
            log::debug!(
                "[writer] ACKNACK refused: writerId does not name this writer \
                 (got {:02x?}, want {:02x?})",
                an_writer_id,
                ctx.writer_entity_id
            );
            return false;
        }
        true
    }

    /// Everything ONE ACKNACK asks of this writer: record its cumulative
    /// acknowledgment watermark, resolve the NACKing reader once, then
    /// retransmit the samples it named and GAP the ones the cache no longer
    /// holds.
    ///
    /// Extracted from `on_nack` when it learned to read every ACKNACK of a
    /// datagram: the whole body is per-ACKNACK work, and a rule buried in a
    /// 300-line method cannot be tested on its own.
    ///
    /// `acknack_entity_ids` and `acknack_base` are `None` on the CDR2
    /// control path, which carries a range list and nothing else.
    fn service_nack_request(
        &self,
        missing_ranges: Vec<std::ops::Range<u64>>,
        resolved_guid: Option<[u8; 16]>,
        acknack_entity_ids: Option<([u8; 4], [u8; 4])>,
        acknack_base: Option<u64>,
    ) {
        let classic_window =
            requires_classic_window(&self.cache, self.discovery_fsm.as_deref(), resolved_guid);
        let Some(window) = self
            .cache
            .wire_windows
            .inbound_window(resolved_guid, classic_window)
        else {
            self.metrics.refuse_control();
            return;
        };
        let offset = window.offset;
        let classic_window = classic_window || window.is_classic();
        let highest = self.cache.highest_inserted();
        let inverse = |sn| crate::protocol::dialect::sequence_window::to_original(sn, offset);
        let acknack_base = match acknack_base {
            Some(sn) => {
                let Some(sn) = inverse(sn) else {
                    self.metrics.refuse_control();
                    return;
                };
                if classic_window && !window.valid_base(sn, highest) {
                    self.metrics.refuse_control();
                    return;
                }
                Some(sn)
            }
            None => None,
        };
        let mut translated_ranges = Vec::with_capacity(missing_ranges.len());
        for range in missing_ranges {
            let Some(range) =
                crate::protocol::dialect::sequence_window::range_to_original(range, offset)
            else {
                self.metrics.refuse_control();
                return;
            };
            if classic_window && !window.valid_range(&range, highest) {
                self.metrics.refuse_control();
                return;
            }
            translated_ranges.push(range);
        }
        let missing_ranges = translated_ranges;
        // Record the reader's cumulative acknowledgment watermark (bitmapBase
        // minus one covers everything below it, including pure ACKs, which
        // return early right after this), then tell the history what every
        // reader now holds (RTPS 2.5 8.4.7.4 `is_acked_by_all`).
        //
        // Only a reader matched as RELIABLE has an entry, created at pairing
        // (see `acked_floor`): an ACKNACK from anyone else moves nothing, and
        // creates no entry. Were it to create one, a reader matched but not
        // yet heard from would be invisible to the minimum, and one that went
        // away would pin it for good.
        //
        // The watermark this leaves is also what the reader is NOT owed:
        // what it acknowledged, or, for a reader matched as VOLATILE, what
        // was written before it matched (see `track_reader_proxy`).
        if resolved_guid.is_none() && unattributed_nack_refused(self.discovery_fsm.as_deref()) {
            log::debug!(
                "[writer] ACKNACK naming no reader on topic={} under the security plugins: \
                 ignored",
                self.topic
            );
            return;
        }
        if let Some(guid) = resolved_guid.filter(|guid| {
            unpaired_reader_unanswered(
                self.ack_track.as_ref(),
                self.discovery_fsm.as_deref(),
                &self.topic,
                *guid,
            )
        }) {
            log::debug!(
                "[writer] ACKNACK from reader {:02x?} not paired yet on topic={}: ignored",
                &guid[12..],
                self.topic
            );
            return;
        }
        let mut not_owed_through: Option<u64> = None;
        #[cfg(test)]
        if let Some(hook) = &self.before_ack_apply {
            hook();
        }
        let current = self.cache.wire_windows.apply_if_current(window, || {
            if let (Some(track), Some(guid)) = (self.ack_track.as_ref(), resolved_guid) {
                let mut map = match track.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if let Some(entry) = map.get_mut(&guid) {
                    if let Some(acked) = acknack_base.map(|base| base.saturating_sub(1)) {
                        if acked > *entry {
                            *entry = acked;
                            self.cache.set_acked_floor(acked_floor(&map));
                        }
                    }
                }
                not_owed_through = map.get(&guid).copied();
            }
        });
        if !current {
            self.metrics.refuse_control();
            return;
        }

        // Resolve the unicast destination once for all retransmits in this NACK.
        let unicast_dest = resolved_guid
            .and_then(|g| self.resolve_unicast(g))
            .map(|mut dest| {
                dest.classic_window |= classic_window;
                dest
            });
        if unicast_dest.is_some() {
            log::debug!(
                "[writer] Retransmitting unicast to {:?} for topic={}",
                unicast_dest,
                self.topic
            );
        }

        // Resolve the NACKing reader's wire profile (entity id, RTPS vendor
        // id) ONCE for every retransmit in this NACK, exactly like
        // `build_ecs_repair_packet`'s vendor lookup. `None` when the reader
        // GUID never resolved (falls back to sending the canonical packet
        // as-is, today's behavior).
        let reader_profile = resolved_guid.map(|g| ReaderWireProfile {
            entity_id: reader_entity_id_of(g),
            vendor: self
                .discovery_fsm
                .as_deref()
                .and_then(|fsm| fsm.vendor_id_for_participant(&participant_guid_of(g))),
        });

        // Skip if no missing ranges (pure ACK - reader is caught up)
        if missing_ranges.is_empty() {
            log::debug!("[writer] ACKNACK is pure ACK (no gaps) - reader is synchronized");
            return;
        }

        // A change the reader is not owed is answered with a GAP, never
        // repaired: it is irrelevant to that reader (RTPS 2.5 8.3.8.4). A
        // VOLATILE reader requests the history below the writer's firstSN
        // like any reliable reader; repairing it is how one received every
        // sample written before it matched (DDS 1.4 2.2.3.4 makes history
        // available only to a late joiner that asked for durability).
        let (owed_ranges, not_owed) = split_at_watermark(missing_ranges, not_owed_through);
        let nack = NackMsg::new(owed_ranges);

        let (retransmits, gaps, not_owed_gaps) = {
            let mut gap_tx = match self.gap_tx.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    log::debug!("[writer] WARNING: GAP transmitter lock poisoned, recovering");
                    poisoned.into_inner()
                }
            };

            // Stamp the GAP with the real endpoint identities. The ACKNACK's
            // writerEntityId is authoritative (it names US); the readerEntityId
            // names the NACKing reader. A GAP answers the reader that asked:
            // with no ACKNACK ids (the re-encoded path), its id comes from the
            // resolved GUID. Only a request from no known reader is answered
            // with ENTITYID_UNKNOWN; it then has no watermark, so its GAPs
            // cover only changes gone from the cache, irrelevant to every
            // reader. The transmitter is shared by every request: both ids
            // are set on each one, so a GAP never carries the previous
            // reader's.
            let (reader_id, writer_id) = match (acknack_entity_ids, self.rtps_endpoint) {
                (Some(ids), _) => ids,
                (None, Some(ctx)) => (
                    resolved_guid.map_or(ENTITYID_UNKNOWN, reader_entity_id_of),
                    ctx.writer_entity_id,
                ),
                (None, None) => (ENTITYID_UNKNOWN, ENTITYID_UNKNOWN),
            };
            gap_tx.set_entity_ids(reader_id, writer_id);

            let not_owed_gaps = gap_tx.build_gap_from_sequences(&not_owed);
            let mut handler = WriterRetransmitHandler::new(&self.cache, &mut gap_tx, &self.metrics);
            let (retransmits, gaps) = handler.on_nack(&nack);
            (retransmits, gaps, not_owed_gaps)
        };

        log::debug!(
            "[writer] Retransmitting {} samples, {} gaps for topic={}",
            retransmits.len(),
            gaps.len(),
            self.topic
        );

        for change in retransmits {
            let seq = change.seq;
            // ECS close slots BYPASS ordinary DATA repair entirely:
            // dialect-correct close regeneration or nothing, unicast only
            // (see repair_ecs_close for the full rationale).
            if change.metadata.kind == ChangeKind::EcsClose {
                let _ = self.repair_ecs_close(&change, resolved_guid, unicast_dest);
                continue;
            }
            // A dispose or unregister is repaired as itself, not answered
            // with a GAP: it is a change of the history like a sample.
            let form = reader_form(self.discovery_fsm.as_deref(), resolved_guid);
            if let Some(packet) =
                lifecycle_change_packet_form(self.rtps_endpoint, &self.topic, &change, form)
            {
                if packet.is_empty() {
                    log::debug!(
                        "[writer] lifecycle repair for seq {} could not be built",
                        seq
                    );
                } else {
                    self.send_finalized_or_multicast(
                        &packet,
                        reader_profile,
                        false,
                        unicast_dest,
                        change.group.is_some(),
                    );
                }
                continue;
            }
            let payload = &change.payload;
            // Replay the journaled wire INFO_TS (falls back to now() only
            // for a legacy entry that never captured one -- see
            // ChangeMetadata::source_ts_known). Same resolution runtime.rs's
            // replay_to uses, so NACK repair and TRANSIENT_LOCAL replay
            // agree with each other AND with the original live send.
            let source_ts = if !change.metadata.source_ts_known {
                builder::now_rtps_timestamp()
            } else {
                change.metadata.source_ts
            };
            // Check if payload needs fragmentation (same threshold as write())
            if builder::should_fragment(payload.len()) {
                // Large payload: retransmit as DATA_FRAG packets, the
                // first carrying the change's coherent-set and GROUP inline
                // QoS in the form this reader received live
                // (`change_frag_packets`).
                //
                // source_ts / cdr_version below replay the journaled value:
                // the live write() path itself captures ONE timestamp and
                // stamps every fragment's INFO_TS with it
                // (build_data_frag_packets_ts, RTPS v2.5 SS8.3.8.11 -- one
                // source timestamp PER SAMPLE), so this retransmit
                // reproduces the live INFO_TS exactly, the same guarantee
                // the small-payload branch above has. The
                // readerEntityId patch is applied below via
                // `finalize_for_reader(.., fragmented: true)`, which
                // withholds the zzdds/InterCOM vendor transforms on every
                // fragmented leg (matching the live DATA_FRAG leg -- see
                // that function's doc).
                if let Some(ctx) = self.rtps_endpoint {
                    // Reuse the live write()'s journaled fragment size when
                    // known: it is what the reader's reassembly was set up
                    // against, and can differ from the CURRENT
                    // frag_route.fragment_size() if the dialect-gated
                    // large-payload route (see frag_route module docs)
                    // changed between the original write and this NACK.
                    let fragment_size = usize::from(if change.metadata.frag_size != 0 {
                        change.metadata.frag_size
                    } else {
                        self.frag_route.fragment_size()
                    });
                    let frag_packets = change_frag_packets_form(
                        &ctx,
                        &self.topic,
                        seq,
                        payload,
                        &change.metadata,
                        change.group.as_ref(),
                        fragment_size,
                        source_ts,
                        form,
                    );
                    log::debug!(
                        "[writer] Retransmitting seq {} as {} DATA_FRAG packets ({} bytes)",
                        seq,
                        frag_packets.len(),
                        payload.len()
                    );
                    // Not to a group anyone may listen on, for a protected
                    // topic: the per-reader leg below instead.
                    let mcast_dest = self.frag_route.multicast_dest().filter(|_| {
                        !self.multicast_closed() && !self.cache.wire_windows.is_group()
                    });
                    for packet in frag_packets {
                        // Dialect-gated large-payload route: DATA_FRAG
                        // retransmits follow the same destination as the
                        // live emission (see frag_route module docs). The
                        // multicast route keeps readerEntityId=UNKNOWN (no
                        // per-reader profile applies to a group send).
                        if let Some(mdest) = mcast_dest {
                            let _ = self.transport.send_user_data_multicast_to(&packet, &mdest);
                        } else {
                            // `fragmented = true`: entity id patch only,
                            // see `finalize_for_reader`'s doc. A packet
                            // finalized for one reader must NEVER reach
                            // the multicast group -- `unicast_dest` may be
                            // `None` even when `reader_profile` resolved
                            // (independent lookups), so the finalize/send
                            // decision is made together, not separately.
                            self.send_finalized_or_multicast(
                                &packet,
                                reader_profile,
                                true,
                                unicast_dest,
                                change.group.is_some(),
                            );
                        }
                    }
                } else {
                    log::debug!(
                        "[writer] Cannot retransmit large payload: no RTPS endpoint context"
                    );
                }
            } else {
                // Small payload: retransmit as single DATA packet
                let rtps_packet = if let Some(ctx) = self.rtps_endpoint {
                    // Reproduce the live emission's coherent-set inline QoS
                    // (PID_COHERENT_SET / PID_GROUP_COHERENT_SET_HDDS) on
                    // retransmit -- without it a reader cannot associate the
                    // retransmitted sample with its coherent set and keeps
                    // NACKing it. The markers come from the SAME atomic
                    // cache lookup as the payload (CachedChange, see
                    // WriterRetransmitHandler::on_nack), so they can never
                    // pair a payload with markers from a different cache
                    // state. `None`/`None` for non-coherent samples matches
                    // today's behavior exactly. Only UserData changes reach
                    // this branch (EcsClose slots were bypassed above); the
                    // key_hash metadata is forwarded too, so a keyed
                    // repair carries the same PID_KEY_HASH as the original
                    // live send (RTPS v2.5 SS9.6.4.8; a receiver may gate
                    // per-instance delivery on it).
                    user_data_change_packet_form(ctx, &self.topic, &change, source_ts, form)
                } else {
                    builder::build_data_packet(&self.topic, seq, payload)
                };
                if rtps_packet.is_empty() {
                    log::debug!(
                        "[writer] Skipping retransmit: failed to build DATA packet for seq {}",
                        seq
                    );
                    continue;
                }

                // Same per-reader wire transforms the live path applies
                // (readerEntityId patch, zzdds encap downgrade, InterCOM
                // HEADER_EXTENSION); see `finalize_for_reader`. Unresolved
                // reader (profile = None) keeps sending the canonical
                // packet as-is. A packet
                // finalized for one reader must NEVER reach the multicast
                // group, so the finalize and the unicast-vs-multicast
                // decision are made together (`send_finalized_or_multicast`),
                // not separately -- `unicast_dest` may be `None` even when
                // `reader_profile` resolved (independent lookups).
                self.send_finalized_or_multicast(
                    &rtps_packet,
                    reader_profile,
                    false,
                    unicast_dest,
                    change.group.is_some(),
                );
            }
        }

        let spec = reader_is_spec(self.discovery_fsm.as_deref(), resolved_guid);
        for gap in gaps {
            // Real participant prefix in the header (see build_gap_packet).
            let gap_prefix = self
                .rtps_endpoint
                .map(|ctx| ctx.guid_prefix)
                .unwrap_or([0u8; 12]);
            let packet = builder::build_gap_packet(&gap.encode_cdr2_le(), gap_prefix);
            if packet.is_empty() {
                log::debug!(
                    "[writer] Skipping GAP transmit: payload too large (start={}, base={})",
                    gap.gap_start(),
                    gap.gap_list().base()
                );
                continue;
            }
            let holes = if spec {
                self.group_holes_of(&gap)
            } else {
                Vec::new()
            };
            if holes.is_empty() {
                // GAP messages go to the same destination as the retransmit DATA.
                self.send_unicast_or_multicast(&packet, unicast_dest, false);
                continue;
            }
            self.send_gap_around_holes(&gap, &holes, gap_prefix, unicast_dest);
        }

        // A GAP naming one reader never goes to the multicast group: it
        // carries no INFO_DST, so a reader of another participant with the
        // same entity id, matched with this writer, would take it for its
        // own. With no unicast locator it is not sent; the reader asks again.
        let gap_prefix = self
            .rtps_endpoint
            .map(|ctx| ctx.guid_prefix)
            .unwrap_or([0u8; 12]);
        for gap in not_owed_gaps {
            let packet = builder::build_gap_packet(&gap.encode_cdr2_le(), gap_prefix);
            match unicast_dest {
                Some(addr) if !packet.is_empty() => {
                    match addr.send(&self.cache.wire_windows, &self.transport, &packet) {
                        Ok(_) => {
                            let listed =
                                u64::try_from(gap.gap_list().iter().count()).unwrap_or(u64::MAX);
                            self.metrics.record_gap(listed.saturating_add(1));
                        }
                        Err(e) => log::debug!("[writer] not-owed GAP to {} failed: {}", addr, e),
                    }
                }
                _ => log::debug!("[writer] not-owed GAP not sent: no unicast locator"),
            }
        }
    }
}

impl NackHandler for WriterNackHandler {
    /// The UDP control path's parsed ACKNACK. Kept only when it names this
    /// writer: RTPS addresses an ACKNACK to one writer (8.3.8.1 writerId),
    /// and the demux hands every one to every handler. Serviced with its
    /// base, so the acknowledgement reaches the reader's proxy.
    ///
    /// The ACKNACK must reach here with its writerId and base: re-encoded
    /// without them, every writer of the participant would service every
    /// NACK, and on UDP no writer would ever learn what a reader had
    /// acknowledged (pure ACKs would not even be forwarded).
    fn on_acknack(
        &self,
        reader_guid: [u8; 16],
        acknack: &crate::core::discovery::multicast::control_types::AckNackInfo,
    ) {
        if !self.claims_acknack(acknack.writer_entity_id) {
            return;
        }
        self.service_nack_request(
            acknack.missing_ranges.clone(),
            Some(reader_guid),
            Some((acknack.reader_entity_id, acknack.writer_entity_id)),
            Some(acknack.bitmap_base),
        );
    }

    fn on_nack(&self, nack_bytes: &[u8], reader_guid: Option<[u8; 16]>) {
        log::debug!(
            "[writer] on_nack called for topic={} with {} bytes",
            self.topic,
            nack_bytes.len()
        );

        // Two formats arrive here:
        // 1. Full RTPS packet (from router.rs / unicast_router.rs -- raw UDP)
        // 2. NackMsg CDR2 (from control.rs which re-encodes parsed AckNackInfo)
        //
        // For path 1 we can also extract the reader GUID prefix from bytes 8..20
        // even when the caller passed reader_guid=None.
        //
        // A datagram carries as many ACKNACKs as the reader chose to batch --
        // one per writer it is talking to, submessages being independently
        // valid (RTPS v2.5 Sec.8.3.3) -- and the demux hands the SAME bytes to
        // every nack handler of the topic transport. Reading the first ACKNACK
        // only meant a writer whose request rode second saw its neighbour's
        // entity id, failed `claims_acknack` and retransmitted nothing at all.
        let acknacks = parse_all_acknack_submessages(nack_bytes);
        if !acknacks.is_empty() {
            // A handler with no endpoint context claims every ACKNACK (it
            // cannot tell which one names it), so servicing them all would
            // multiply exactly the spurious repair rounds `claims_acknack`
            // exists to stop. That case answers a single ACKNACK.
            // Production always carries a context (see
            // dds::writer::builder, which builds one per DataWriter).
            let readable = if self.rtps_endpoint.is_some() {
                acknacks.len()
            } else {
                1
            };
            for info in acknacks.into_iter().take(readable) {
                if !self.claims_acknack(info.writer_entity_id) {
                    continue;
                }
                log::debug!(
                    "[writer] Parsed RTPS ACKNACK for writer={:02x?} with {} missing ranges",
                    info.writer_entity_id,
                    info.missing_ranges.len()
                );
                // Prefer the explicitly-passed GUID; derive from the RTPS header as a
                // fallback when the caller left it as None (e.g. router.rs path).
                let guid = reader_guid.or_else(|| {
                    if nack_bytes.len() >= 20 {
                        let mut g = [0u8; 16];
                        g[..12].copy_from_slice(&nack_bytes[8..20]);
                        g[12..16].copy_from_slice(&info.reader_entity_id);
                        Some(g)
                    } else {
                        None
                    }
                });
                self.service_nack_request(
                    info.missing_ranges,
                    guid,
                    Some((info.reader_entity_id, info.writer_entity_id)),
                    Some(info.bitmap_base),
                );
            }
            return;
        }

        if let Some(nack_msg) = NackMsg::decode_cdr2_le(nack_bytes) {
            log::debug!(
                "[writer] Parsed NackMsg CDR2 with {} missing ranges (control.rs path)",
                nack_msg.ranges.len()
            );
            // CDR2 path: the caller-supplied GUID (may be None for old paths)
            // and no entity ids, so nothing is filtered (fan-out to every
            // handler).
            self.service_nack_request(nack_msg.ranges, reader_guid, None, None);
            return;
        }

        log::debug!(
            "[writer] Failed to parse ACKNACK: neither RTPS nor CDR2 (len={})",
            nack_bytes.len()
        );
    }
}

/// Handler for NACK_FRAG messages - fragment-level retransmission.
///
/// When a reader detects missing fragments in a DATA_FRAG sequence,
/// it sends NACK_FRAG requesting specific fragments. This handler
/// re-fragments the original message and sends only the missing fragments.
pub(super) struct WriterNackFragHandler {
    topic: String,
    cache: Arc<HistoryCache>,
    transport: Arc<UdpTransport>,
    metrics: Arc<ReliableMetrics>,
    rtps_endpoint: Option<crate::protocol::builder::RtpsEndpointContext>,
    writer_entity_id: [u8; 4],
    /// Per-reader unicast locator table (from SEDP discovery).
    endpoint_registry: Option<EndpointRegistry>,
    /// Writer's canonical encapsulation kind for the no-context fallback;
    /// see [`RetransmitCfg::canonical_encapsulation_kind`].
    canonical_encapsulation_kind: u16,
    /// See `RetransmitCfg::frag_route`.
    frag_route: Arc<super::frag_route::FragRouteProfile>,
    /// Discovery FSM used to build the NACKing reader's `ReaderWireProfile`
    /// (see `WriterNackHandler::discovery_fsm`). Threaded through here so
    /// this handler resolves its reader profile the same way the
    /// DATA-level handler does, even though `finalize_for_reader`'s
    /// `fragmented = true` call from this handler currently uses only the
    /// entity id half of the profile (vendor transforms are withheld on
    /// every fragmented leg, see `finalize_for_reader`'s doc).
    discovery_fsm: Option<Arc<DiscoveryFsm>>,
    /// The DATA-level handler's acknowledgement watermarks, READ here only:
    /// a NACK_FRAG carries no sample watermark to record, but a reader asks
    /// through it for fragments of a change it may not be owed (see
    /// `split_at_watermark`).
    ack_track: Option<AckTrack>,
}

impl WriterNackFragHandler {
    /// As `WriterNackHandler::multicast_open`.
    fn multicast_open(&self, group: bool) -> bool {
        !self.cache.wire_windows.is_group()
            && super::runtime::multicasts(group, self.discovery_fsm.as_deref())
            && !self.multicast_closed()
    }

    /// As `WriterNackHandler::multicast_closed`.
    fn multicast_closed(&self) -> bool {
        super::runtime::multicast_fallback_closed(self.discovery_fsm.as_deref(), &self.topic)
    }

    pub fn new(
        topic: String,
        cache: Arc<HistoryCache>,
        transport: Arc<UdpTransport>,
        metrics: Arc<ReliableMetrics>,
        writer_entity_id: [u8; 4],
        cfg: RetransmitCfg,
    ) -> Self {
        Self {
            topic,
            cache,
            transport,
            metrics,
            rtps_endpoint: cfg.rtps_endpoint,
            writer_entity_id,
            endpoint_registry: cfg.endpoint_registry,
            canonical_encapsulation_kind: cfg.canonical_encapsulation_kind,
            frag_route: cfg.frag_route,
            discovery_fsm: cfg.discovery_fsm,
            ack_track: cfg.ack_track,
        }
    }

    fn resolve_unicast(&self, reader_guid: [u8; 16]) -> Option<ReaderDestination> {
        let reg = self.endpoint_registry.as_ref()?;
        let guid = GUID::from_bytes(reader_guid);
        reg.get_reader_locator(&guid)
            .or_else(|| {
                // Fall back to the reader's participant default_unicast locator
                // (SPDP PID_DEFAULT_UNICAST_LOCATOR) when the reader announced no
                // per-reader SEDP locator -- mirrors the live/HEARTBEAT routing in
                // runtime.rs. Without this a NACKing reader whose per-reader locator
                // is unknown gets retransmits only via multicast, which some readers
                // (INSTANCE-scope TRANSIENT_LOCAL) do not receive.
                let mut pbytes = reader_guid;
                pbytes[12..16]
                    .copy_from_slice(&crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT);
                reg.get(&GUID::from_bytes(pbytes))
            })
            .map(|endpoint| ReaderDestination {
                endpoint,
                reader: guid,
                classic_window: requires_classic_window(
                    &self.cache,
                    self.discovery_fsm.as_deref(),
                    Some(reader_guid),
                ),
            })
    }

    /// Whether `reader_guid` is owed change `writer_sn` at all: false at or
    /// below its watermark (`split_at_watermark` says why), true for a
    /// reader with no proxy here.
    pub(super) fn owes(&self, reader_guid: [u8; 16], writer_sn: u64) -> bool {
        let Some(track) = self.ack_track.as_ref() else {
            return true;
        };
        let map = match track.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(&reader_guid)
            .is_none_or(|through| writer_sn > *through)
    }
}

impl NackFragHandler for WriterNackFragHandler {
    fn on_nack_frag(
        &self,
        writer_entity_id: &[u8; 4],
        writer_sn: u64,
        missing_fragments: &[u32],
        reader_guid: Option<[u8; 16]>,
    ) {
        // The demux broadcasts controls to all handlers. A different writer
        // must not renew retired origins or affect refusal accounting.
        if writer_entity_id != &self.writer_entity_id {
            log::debug!(
                "[writer] NACK_FRAG ignored: entity_id mismatch (got {:02x?}, want {:02x?})",
                writer_entity_id,
                self.writer_entity_id
            );
            return;
        }

        let classic_window =
            requires_classic_window(&self.cache, self.discovery_fsm.as_deref(), reader_guid);
        let Some(window) = self
            .cache
            .wire_windows
            .inbound_window(reader_guid, classic_window)
        else {
            self.metrics.refuse_control();
            return;
        };
        let Some(writer_sn) =
            crate::protocol::dialect::sequence_window::to_original(writer_sn, window.offset)
        else {
            self.metrics.refuse_control();
            return;
        };
        let classic_window = classic_window || window.is_classic();
        if classic_window
            && (!window.valid_range(&(writer_sn..writer_sn + 1), self.cache.highest_inserted())
                || !self.cache.wire_windows.apply_if_current(window, || {}))
        {
            self.metrics.refuse_control();
            return;
        }
        // Resolve unicast destination for the NACKing reader.
        let unicast_dest = reader_guid
            .and_then(|g| self.resolve_unicast(g))
            .map(|mut dest| {
                dest.classic_window |= classic_window;
                dest
            });

        // A reader not paired yet is not answered (see
        // `discovered_but_unpaired`), nor one not named under the security
        // plugins (`unattributed_nack_refused`); a change the reader is not
        // owed is answered with a GAP, as on the DATA-level door, never with
        // its fragments.
        if reader_guid.is_none() && unattributed_nack_refused(self.discovery_fsm.as_deref()) {
            log::debug!(
                "[writer] NACK_FRAG for seq {} naming no reader under the security plugins: \
                 ignored",
                writer_sn
            );
            return;
        }
        if reader_guid.is_some_and(|guid| {
            unpaired_reader_unanswered(
                self.ack_track.as_ref(),
                self.discovery_fsm.as_deref(),
                &self.topic,
                guid,
            )
        }) {
            log::debug!(
                "[writer] NACK_FRAG for seq {} from a reader not paired yet: ignored",
                writer_sn
            );
            return;
        }
        if let Some(guid) = reader_guid.filter(|g| !self.owes(*g, writer_sn)) {
            let prefix = self
                .rtps_endpoint
                .map(|ctx| ctx.guid_prefix)
                .unwrap_or([0u8; 12]);
            let gap = builder::build_gap_packet_from_parts(
                &reader_entity_id_of(guid),
                &self.writer_entity_id,
                writer_sn,
                writer_sn.saturating_add(1),
                &[],
                prefix,
            );
            log::debug!(
                "[writer] NACK_FRAG for seq {} from a reader not owed it: GAP",
                writer_sn
            );
            // Unicast only, as on the ACKNACK door: this GAP names one reader.
            if let (false, Some(addr)) = (gap.is_empty(), unicast_dest) {
                self.metrics.record_gap(1);
                if let Err(e) = addr.send(&self.cache.wire_windows, &self.transport, &gap) {
                    log::debug!("[writer] NACK_FRAG GAP send failed: {}", e);
                }
            }
            return;
        }

        // Resolve the NACKing reader's wire profile the same way `on_nack`
        // does (independent lookup from `unicast_dest`, see
        // `finalize_for_reader`'s doc): entity id patch
        // only is applied below (`fragmented = true`).
        let reader_profile = reader_guid.map(|g| ReaderWireProfile {
            entity_id: reader_entity_id_of(g),
            vendor: self
                .discovery_fsm
                .as_deref()
                .and_then(|fsm| fsm.vendor_id_for_participant(&participant_guid_of(g))),
        });

        log::debug!(
            "[writer] NACK_FRAG for topic={} seq={} missing_frags={:?} unicast_dest={:?}",
            self.topic,
            writer_sn,
            missing_fragments,
            unicast_dest
        );

        // Get the original sample (with its journaled emission metadata)
        // from cache.
        let change = match self.cache.get_change(writer_sn) {
            Some(c) => c,
            None => {
                log::debug!(
                    "[writer] NACK_FRAG: seq {} not in cache (expired or never existed)",
                    writer_sn
                );
                return;
            }
        };
        let payload = &change.payload;

        // Reuse the live write()'s journaled fragment size when known: it
        // is what the reader's reassembly was set up against, and can
        // differ from the CURRENT frag_route.fragment_size() if the
        // dialect-gated large-payload route changed since the original
        // write.
        let fragment_size = usize::from(if change.metadata.frag_size != 0 {
            change.metadata.frag_size
        } else {
            self.frag_route.fragment_size()
        });
        // Replay the journaled wire INFO_TS -- same resolution as
        // on_nack's and replay_to's -- and the journaled CDR version
        // (a repair must derive the wire encapsulation from the version
        // the cached body was ACTUALLY encoded with, not a writer-level
        // default).
        let source_ts = if !change.metadata.source_ts_known {
            builder::now_rtps_timestamp()
        } else {
            change.metadata.source_ts
        };
        let frag_packets = if let Some(ctx) = self.rtps_endpoint {
            change_frag_packets_form(
                &ctx,
                &self.topic,
                writer_sn,
                payload,
                &change.metadata,
                change.group.as_ref(),
                fragment_size,
                source_ts,
                reader_form(self.discovery_fsm.as_deref(), reader_guid),
            )
        } else {
            // Build without endpoint context (fallback). Use the writer's
            // canonical encapsulation kind (derived from the type's
            // extensibility at build time) so appendable/mutable payloads
            // keep their D_CDR2/PL_CDR2 wire encap on retransmit; see
            // `encap_kind_for_version`.
            let ctx = builder::RtpsEndpointContext {
                guid_prefix: [0; 12],
                reader_entity_id: [0; 4],
                writer_entity_id: self.writer_entity_id,
                encapsulation_kind: self.canonical_encapsulation_kind,
                // A DATA_FRAG names no group (no inline QoS here).
                publisher_entity_id: [0; 4],
            };
            builder::build_data_frag_packets_ts(
                &ctx,
                writer_sn,
                payload,
                fragment_size,
                change.metadata.cdr_version,
                source_ts,
                change.metadata.key_epoch != 0,
            )
        };

        if frag_packets.is_empty() {
            log::debug!(
                "[writer] NACK_FRAG: failed to build DATA_FRAG packets for seq {}",
                writer_sn
            );
            return;
        }

        // Send only the missing fragments, unicast when destination is known.
        // Fragment numbers are 1-based FragmentNumber_t (u32) in RTPS, so the
        // packets are numbered by a u32 counter rather than a narrowed index.
        // A GROUP change's fragments do not reach the multicast group while
        // a participant of the spec class is known.
        let group = change.group.is_some();
        let multicast_unless_group = |packet: &Vec<u8>| {
            self.multicast_open(group) && self.transport.send_user_data_multicast(packet).is_ok()
        };
        // The large-payload route's group, not for a protected topic.
        let route_multicast = self
            .frag_route
            .multicast_dest()
            .filter(|_| !self.multicast_closed() && !self.cache.wire_windows.is_group());
        let mut sent_count = 0;
        for (frag_num_1based, packet) in (1u32..).zip(frag_packets.iter()) {
            if missing_fragments.contains(&frag_num_1based) {
                let ok = if let Some(mdest) = route_multicast {
                    // Dialect-gated large-payload route: retransmitted
                    // fragments follow the live emission's destination.
                    self.transport
                        .send_user_data_multicast_to(packet, &mdest)
                        .is_ok()
                } else if let Some(addr) = unicast_dest {
                    // Entity id patch only (`fragmented = true`, see
                    // `finalize_for_reader`'s doc). A packet finalized for
                    // one reader must NEVER reach the multicast group, so
                    // the fallback below resends the CANONICAL `packet`,
                    // not the finalized copy.
                    let to_send = match reader_profile {
                        Some(profile) => finalize_for_reader(packet.clone(), profile, true),
                        None => packet.clone(),
                    };
                    match addr.send(&self.cache.wire_windows, &self.transport, &to_send) {
                        Ok(_) => true,
                        // A resolved reader is never served by multicast
                        // (see `WriterNackHandler::send_finalized_or_multicast`).
                        Err(e) if reader_profile.is_some() => {
                            log::debug!(
                                "[writer] NACK_FRAG unicast to {} failed ({}); dropped",
                                addr,
                                e
                            );
                            false
                        }
                        Err(e) => {
                            log::debug!(
                                "[writer] NACK_FRAG unicast to {} failed ({}), falling back to multicast",
                                addr,
                                e
                            );
                            multicast_unless_group(packet)
                        }
                    }
                } else if reader_profile.is_some() {
                    false
                } else {
                    multicast_unless_group(packet)
                };

                if ok {
                    sent_count += 1;
                } else {
                    log::debug!(
                        "[writer] NACK_FRAG retransmit failed: seq={} frag={}",
                        writer_sn,
                        frag_num_1based
                    );
                }
            }
        }

        // One retransmission of a change, however many of its fragments it
        // took: the unit the DATA-level path counts in
        // (`WriterRetransmitHandler`).
        if sent_count > 0 {
            self.metrics.increment_retransmit_sent(1);
        }
        log::debug!(
            "[writer] NACK_FRAG: retransmitted {}/{} fragments for seq={}",
            sent_count,
            missing_fragments.len(),
            writer_sn
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rt::slabpool::SlabPool;
    use crate::protocol::builder::RtpsEndpointContext;
    use crate::qos::History;
    use crate::test_support::domains::unique_domain;
    use crate::transport::PortMapping;
    use std::time::Duration;

    const WRITER_EID: [u8; 4] = [0x00, 0x00, 0x10, 0x02];
    const OUR_PREFIX: [u8; 12] = [7u8; 12];

    fn reader_guid() -> [u8; 16] {
        let mut g = [0xAAu8; 16];
        g[12..16].copy_from_slice(&[0x00, 0x00, 0x10, 0x07]);
        g
    }

    fn test_cache(max_samples: u32) -> Arc<HistoryCache> {
        let pool = Arc::new(SlabPool::new());
        Arc::new(HistoryCache::new_with_limits(
            pool,
            max_samples as usize,
            256 * 1024,
            History::KeepLast(max_samples),
        ))
    }

    fn repair_ctx() -> RtpsEndpointContext {
        RtpsEndpointContext {
            guid_prefix: OUR_PREFIX,
            reader_entity_id: [0x00, 0x00, 0x10, 0x07],
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0x00, 0x00, 0x21, 0x08],
        }
    }

    // ------------------------------------------------------------------
    // ECS close repair: dialect-correct close regeneration, UNICAST ONLY
    // (decode the built bytes -- house rule for wire fixes)
    // ------------------------------------------------------------------

    /// Vendor id of a classic-model peer (0x0101) for the tests.
    const CLASSIC_VENDOR: u16 = 0x0101;

    fn ecs_change(seq: u64, coherent_sn: Option<u64>, group_sn: Option<u64>) -> CachedChange {
        CachedChange {
            seq,
            payload: Vec::new(),
            metadata: crate::reliability::ChangeMetadata {
                kind: ChangeKind::EcsClose,
                coherent_sn,
                group_sn,
                key_hash: None,
                ..crate::reliability::ChangeMetadata::user_data()
            },
            group: None,
        }
    }

    /// Zero the 8-byte INFO_TS timestamp so two builds at different
    /// instants can be byte-compared. Both ECS builders emit RTPS
    /// header (20 bytes) + INFO_TS (id 0x09 at offset 20, timestamp at
    /// 24..32) before the DATA submessage.
    fn with_masked_timestamp(mut pkt: Vec<u8>) -> Vec<u8> {
        assert!(pkt.len() >= 32, "packet too short for header + INFO_TS");
        assert_eq!(pkt[20], 0x09, "INFO_TS submessage expected at offset 20");
        for b in &mut pkt[24..32] {
            *b = 0;
        }
        pkt
    }

    /// DiscoveryFsm that has discovered the reader's participant with the
    /// given (optional) vendor id, via the real SPDP ingestion path.
    fn fsm_with_vendor(reader_guid: [u8; 16], vendor_id: Option<u16>) -> Arc<DiscoveryFsm> {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: participant_guid_of(reader_guid),
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        Arc::new(fsm)
    }

    /// `fsm_with_vendor` for an HDDS reader announcing `capabilities`.
    fn fsm_with_capabilities(
        reader_guid: [u8; 16],
        capabilities: Option<u32>,
    ) -> Arc<DiscoveryFsm> {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        // This participant speaks the spec GROUP dialect.
        fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: participant_guid_of(reader_guid),
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: Some(HDDS_VENDOR_ID_U16),
            hdds_capabilities: capabilities,
            builtin_endpoint_set: None,
        });
        Arc::new(fsm)
    }

    /// DATA-level nack handler with a real transport; domain/participant
    /// must be unique per test so parallel tests never share a socket.
    fn data_handler(
        domain_id: u32,
        participant_id: u8,
        cache: Arc<HistoryCache>,
        metrics: Arc<ReliableMetrics>,
        endpoint_registry: Option<EndpointRegistry>,
        discovery_fsm: Option<Arc<DiscoveryFsm>>,
    ) -> (WriterNackHandler, Arc<UdpTransport>) {
        let mapping = PortMapping::calculate(domain_id, participant_id).expect("port mapping");
        let transport = Arc::new(
            UdpTransport::new(domain_id, participant_id, mapping).expect("test transport"),
        );
        let handler = WriterNackHandler::new(
            "EcsRepairTestTopic".to_string(),
            cache,
            transport.clone(),
            metrics,
            RetransmitCfg {
                rtps_endpoint: Some(repair_ctx()),
                endpoint_registry,
                canonical_encapsulation_kind: 0x0007,
                ack_track: None,
                frag_route: Arc::new(super::super::frag_route::FragRouteProfile::new(
                    u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
                        .expect("DEFAULT_FRAGMENT_SIZE fits the u16 fragmentSize field"),
                )),
                discovery_fsm,
            },
        );
        (handler, transport)
    }

    /// Raw RTPS ACKNACK from the test reader NACKing `missing`.
    fn acknack_from_reader(base: u64, missing: &[u64]) -> Vec<u8> {
        let mut reader_prefix = [0u8; 12];
        reader_prefix.copy_from_slice(&reader_guid()[..12]);
        builder::build_acknack_packet(
            reader_prefix,
            OUR_PREFIX,
            [0x00, 0x00, 0x10, 0x07],
            WRITER_EID,
            base,
            missing,
            1,
        )
    }

    /// Wire-level ACKNACK and NACK_FRAG requests name the reader's origin,
    /// while the history, cumulative acknowledgements and fragment journal
    /// remain in the writer's original sequence space (RTPS 2.5 8.4.7.4).
    #[test]
    fn classic_wire_requests_repair_and_acknowledge_the_original_history() {
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), addr);
        let cache = test_cache(8);
        cache
            .insert_with_metadata(
                101,
                &[0x55; 20_000],
                0,
                crate::reliability::ChangeMetadata {
                    coherent_sn: Some(101),
                    group_sn: Some(57),
                    frag_size: 1024,
                    ..crate::reliability::ChangeMetadata::user_data()
                },
            )
            .unwrap();
        cache.wire_windows.configure(true);
        let metrics = Arc::new(ReliableMetrics::new());
        let (mut handler, transport) = data_handler(
            domain.id(),
            8,
            cache.clone(),
            metrics.clone(),
            Some(reg.clone()),
            Some(fsm_with_vendor(reader_guid(), Some(0x0101))),
        );
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::from([(
            reader_guid(),
            100,
        )])));
        handler.ack_track = Some(track.clone());
        handler.on_nack(&acknack_from_reader(102, &[]), Some(reader_guid()));
        assert_eq!(
            *track.lock().unwrap().get(&reader_guid()).unwrap(),
            100,
            "an uninitialized classic window cannot advance its ReaderProxy"
        );
        handler.on_nack(&acknack_from_reader(1, &[1]), Some(reader_guid()));
        listener.set_nonblocking(true).unwrap();
        let mut before_pair = [0u8; 128];
        assert_eq!(
            listener.recv(&mut before_pair).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "no raw GAP or repair during window initialization"
        );
        listener.set_nonblocking(false).unwrap();
        handler
            .cache
            .wire_windows
            .pair(GUID::from_bytes(reader_guid()), Some(addr), 100, false);
        handler.on_nack(&acknack_from_reader(1, &[1]), Some(reader_guid()));
        let mut bytes = [0u8; 8192];
        let n = listener.recv(&mut bytes).unwrap();
        let mut at = 20;
        while bytes[at] != 0x15 && bytes[at] != 0x16 {
            at += 4 + usize::from(u16::from_le_bytes(
                bytes[at + 2..at + 4].try_into().unwrap(),
            ));
            assert!(at < n);
        }
        assert_eq!(
            u32::from_le_bytes(bytes[at + 20..at + 24].try_into().unwrap()),
            1
        );
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 100);
        // Drain any remaining DATA_FRAGs from the full-sample repair first.
        listener.set_nonblocking(true).unwrap();
        while listener.recv(&mut bytes).is_ok() {}
        listener.set_nonblocking(false).unwrap();
        let fragment_handler = WriterNackFragHandler::new(
            "EcsRepairTestTopic".into(),
            cache,
            transport,
            metrics,
            WRITER_EID,
            RetransmitCfg {
                rtps_endpoint: Some(repair_ctx()),
                endpoint_registry: Some(reg),
                canonical_encapsulation_kind: 7,
                ack_track: None,
                frag_route: handler.frag_route.clone(),
                discovery_fsm: handler.discovery_fsm.clone(),
            },
        );
        let raw = builder::build_nack_frag_packet(
            reader_guid()[..12].try_into().unwrap(),
            OUR_PREFIX,
            reader_entity_id_of(reader_guid()),
            WRITER_EID,
            1,
            &[2],
            1,
        );
        let parsed =
            crate::core::discovery::multicast::control_parser::parse_all_nack_frag_submessages(
                &raw,
            );
        assert_eq!(parsed.len(), 1);
        let request = &parsed[0];
        fragment_handler.on_nack_frag(
            &request.writer_entity_id,
            request.writer_sn,
            &request.missing_fragments,
            Some(reader_guid()),
        );
        let n = listener.recv(&mut bytes).unwrap();
        let mut at = 20;
        while bytes[at] != 0x16 {
            at += 4 + usize::from(u16::from_le_bytes(
                bytes[at + 2..at + 4].try_into().unwrap(),
            ));
            assert!(at < n);
        }
        assert_eq!(
            u32::from_le_bytes(bytes[at + 20..at + 24].try_into().unwrap()),
            1
        );
        assert_eq!(
            u32::from_le_bytes(bytes[at + 24..at + 28].try_into().unwrap()),
            2,
            "fragment numbers are not translated"
        );
        handler.on_nack(&acknack_from_reader(2, &[]), Some(reader_guid()));
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 101);
    }

    /// Classic-vendor ECS repair == the LIVE bare close marker shape:
    /// D=0 K=0 Q=0, octetsToNextHeader=20, no inline QoS, no payload --
    /// byte-identical to `build_ecs_close_marker` (the builder the live
    /// `dispatch_ecs` uses), modulo the INFO_TS timestamp.
    #[test]
    fn ecs_close_repair_for_classic_is_bare_close_shape() {
        let reader_eid = [0x00, 0x00, 0x10, 0x07];
        let change = ecs_change(29, Some(25), Some(3));

        let pkt = build_ecs_repair_packet(
            &repair_ctx(),
            "EcsRepairTopic",
            &change,
            reader_eid,
            Some(CLASSIC_VENDOR),
        )
        .expect("classic ECS repair must build");

        // Decode the built bytes: RTPS header + INFO_TS + ONE bare DATA.
        assert_eq!(&pkt[0..4], b"RTPS");
        assert_eq!(&pkt[8..20], &OUR_PREFIX);
        assert_eq!(pkt[32], 0x15, "DATA submessage");
        assert_eq!(
            pkt[33], 0x01,
            "flags LE only: D=0 K=0 Q=0 (bare close, no inline QoS)"
        );
        assert_eq!(
            u16::from_le_bytes([pkt[34], pkt[35]]),
            20,
            "bare close body is exactly 20 octets (no inline QoS, no payload)"
        );
        assert_eq!(&pkt[40..44], &reader_eid, "addressed to the NACKing reader");
        assert_eq!(&pkt[44..48], &WRITER_EID);
        assert_eq!(i32::from_le_bytes([pkt[48], pkt[49], pkt[50], pkt[51]]), 0);
        assert_eq!(
            u32::from_le_bytes([pkt[52], pkt[53], pkt[54], pkt[55]]),
            29,
            "close marker rides the NACKed writer SN"
        );
        assert_eq!(pkt.len(), 56, "nothing after the bare DATA body");

        // A bare close is NOT a native ECS marker (Q=0, no PIDs).
        assert_eq!(builder::extract_ecs_marker(&pkt), None);

        // Byte comparison against the LIVE close-marker builder output
        // for the same ctx/reader/seq.
        let live = builder::build_ecs_close_marker(&repair_ctx(), &reader_eid, 29);
        assert_eq!(
            with_masked_timestamp(pkt),
            with_masked_timestamp(live),
            "repair must be byte-identical to the live close marker"
        );
    }

    /// HDDS-vendor ECS repair == the LIVE native ECS DATA shape
    /// (D=0 K=0 Q=1 + PID_COHERENT_SET [+ group PID]), patched to the
    /// reader entity id, and round-trips through the SAME extractor the
    /// engine router uses to recognise a live ECS marker.
    #[test]
    fn ecs_close_repair_for_hdds_is_native_ecs() {
        let reader_eid = [0x00, 0x00, 0x10, 0x07];
        let change = ecs_change(29, Some(25), Some(3));

        let pkt = build_ecs_repair_packet(
            &repair_ctx(),
            "EcsRepairTopic",
            &change,
            reader_eid,
            Some(HDDS_VENDOR_ID_U16),
        )
        .expect("native ECS repair must build");

        let off = crate::protocol::builder::helpers::find_data_submsg_offset(&pkt)
            .expect("native ECS repair must contain a DATA submessage");
        assert_eq!(pkt[off + 1], 0x03, "flags LE + Q=1, D=0 K=0 (ECS marker)");
        assert_eq!(
            &pkt[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4],
            &reader_eid,
            "patched to the NACKing reader entity id"
        );

        let (coherent_sn, group_sn) =
            builder::extract_ecs_marker(&pkt).expect("native ECS repair must round-trip");
        assert_eq!(coherent_sn, 25, "cached PID_COHERENT_SET value");
        assert_eq!(group_sn, Some(3), "cached wire group SN");

        // Byte comparison against the LIVE native emission: emit_ecs_data
        // builds with ENTITYID_UNKNOWN and dispatch_ecs patches the
        // reader entity id at READER_ENTITY_ID_OFFSET.
        let live_ctx = RtpsEndpointContext {
            guid_prefix: OUR_PREFIX,
            reader_entity_id: [0u8; 4],
            writer_entity_id: WRITER_EID,
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0x00, 0x00, 0x21, 0x08],
        };
        let mut live = builder::build_ecs_data_submessage(
            &live_ctx,
            "EcsRepairTopic",
            29,
            25,
            Some(3),
            Some([0x00, 0x00, 0x21, 0x08]),
        );
        live[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
            .copy_from_slice(&reader_eid);
        assert_eq!(
            with_masked_timestamp(pkt),
            with_masked_timestamp(live),
            "repair must be byte-identical to the live patched ECS DATA"
        );
    }

    /// Vendor 0x0105 ECS repair == a single-SN GAP retiring the close
    /// slot: gapStart = seq, gapList base = seq + 1, numBits = 0, our
    /// participant prefix in the header -- NOT a close marker (for this
    /// dialect a NACKed close slot is retired, RTPS v2.5 SS8.3.8.4, so the
    /// reader's reliable state can advance past it). Other classic vendors
    /// and HDDS peers keep their forms (asserted here against the 0x0105
    /// output, and byte-frozen by their own tests).
    #[test]
    fn ecs_close_repair_for_intercom_is_single_sn_gap() {
        let reader_eid = [0x00, 0x00, 0x10, 0x07];
        let change = ecs_change(29, Some(25), Some(3));

        let pkt = build_ecs_repair_packet(
            &repair_ctx(),
            "EcsRepairTopic",
            &change,
            reader_eid,
            Some(INTERCOM_VENDOR_ID_U16),
        )
        .expect("intercom ECS repair must build");

        // Decode the built bytes: RTPS header + ONE bare GAP submessage.
        assert_eq!(&pkt[0..4], b"RTPS");
        assert_eq!(
            &pkt[8..20],
            &OUR_PREFIX,
            "header carries OUR participant prefix (GAP attribution)"
        );
        assert_eq!(pkt[20], 0x08, "GAP submessage id");
        assert_eq!(pkt[21], 0x01, "GAP flags LE");
        assert_eq!(
            u16::from_le_bytes([pkt[22], pkt[23]]),
            28,
            "GAP body: ids(8) + gapStart(8) + gapListBase(8) + numBits(4), no bitmap"
        );
        assert_eq!(&pkt[24..28], &reader_eid, "addressed to the NACKing reader");
        assert_eq!(&pkt[28..32], &WRITER_EID, "attributed to this writer");
        assert_eq!(
            i32::from_le_bytes([pkt[32], pkt[33], pkt[34], pkt[35]]),
            0,
            "gapStart high"
        );
        assert_eq!(
            u32::from_le_bytes([pkt[36], pkt[37], pkt[38], pkt[39]]),
            29,
            "gapStart = the NACKed close-slot SN"
        );
        assert_eq!(
            i32::from_le_bytes([pkt[40], pkt[41], pkt[42], pkt[43]]),
            0,
            "gapListBase high"
        );
        assert_eq!(
            u32::from_le_bytes([pkt[44], pkt[45], pkt[46], pkt[47]]),
            30,
            "gapList.base = seq + 1 (single-SN retire, nothing beyond)"
        );
        assert_eq!(
            u32::from_le_bytes([pkt[48], pkt[49], pkt[50], pkt[51]]),
            0,
            "numBits = 0: no bitmap, only gapStart is retired"
        );
        assert_eq!(pkt.len(), 52, "nothing after the GAP submessage");

        // It is a GAP, not any DATA form: no DATA submessage anywhere.
        assert_eq!(
            crate::protocol::builder::helpers::find_data_submsg_offset(&pkt),
            None,
            "intercom repair must not carry any DATA submessage"
        );

        // The intercom gate is EXACT: a neighboring classic vendor id
        // still gets the bare close marker, byte-identical to the live
        // builder output (classic-model path untouched).
        let classic = build_ecs_repair_packet(
            &repair_ctx(),
            "EcsRepairTopic",
            &change,
            reader_eid,
            Some(CLASSIC_VENDOR),
        )
        .expect("classic ECS repair must build");
        let live = builder::build_ecs_close_marker(&repair_ctx(), &reader_eid, 29);
        assert_eq!(
            with_masked_timestamp(classic),
            with_masked_timestamp(live),
            "non-intercom classic vendors keep the marker-form repair"
        );

        // And the HDDS-peer form is likewise unaffected by the gate.
        let native = build_ecs_repair_packet(
            &repair_ctx(),
            "EcsRepairTopic",
            &change,
            reader_eid,
            Some(HDDS_VENDOR_ID_U16),
        )
        .expect("native ECS repair must build");
        assert_eq!(
            builder::extract_ecs_marker(&native),
            Some((25, Some(3))),
            "HDDS peers keep the native ECS DATA repair"
        );
    }

    /// A NACK for a dispose's number is repaired WITH the dispose, as the
    /// key-only DATA it was live - decoded here: K set, D clear, the
    /// NACKed number, PID_STATUS_INFO disposed. Were it absent from the
    /// history, the NACK would be answered with a GAP and a reader that lost
    /// the dispose would never learn the instance was gone.
    #[test]
    fn a_nacked_dispose_is_repaired_as_a_dispose() {
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");
        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);

        let cache = test_cache(8);
        cache
            .insert_with_metadata(
                5,
                &[0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
                0,
                crate::reliability::ChangeMetadata {
                    key_hash: Some([0x42; 16]),
                    source_ts: (0x0A0B_0C0D, 0x0102_0304),
                    source_ts_known: true,
                    status_info: Some(crate::protocol::builder::StatusInfoKind::Disposed),
                    ..crate::reliability::ChangeMetadata::user_data()
                },
            )
            .expect("journal the dispose");
        let metrics = Arc::new(ReliableMetrics::new());
        let (handler, _transport) = data_handler(domain.id(), 7, cache, metrics, Some(reg), None);

        handler.on_nack(&acknack_from_reader(5, &[5]), Some(reader_guid()));

        let mut buf = [0u8; 2048];
        let (n, _) = listener
            .recv_from(&mut buf)
            .expect("the repair must arrive");
        let pkt = &buf[..n];
        let off = crate::protocol::builder::helpers::find_data_submsg_offset(pkt)
            .expect("the repair is a DATA, not a GAP");
        let flags = pkt[off + 1];
        assert_ne!(flags & 0x08, 0, "K flag: a key-only DATA");
        assert_eq!(flags & 0x04, 0, "no D flag: no sample payload");
        assert_eq!(
            u32::from_le_bytes([pkt[off + 20], pkt[off + 21], pkt[off + 22], pkt[off + 23]]),
            5,
            "the NACKed number"
        );
        let (inline_qos, le) =
            crate::protocol::builder::extract_inline_qos(pkt).expect("inline QoS");
        assert_eq!(
            crate::protocol::builder::extract_status_info(inline_qos, le),
            Some(1),
            "PID_STATUS_INFO: disposed"
        );
        assert_eq!(pkt[20], 0x09, "INFO_TS precedes the DATA");
        assert_eq!(
            (
                u32::from_le_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]),
                u32::from_le_bytes([pkt[28], pkt[29], pkt[30], pkt[31]])
            ),
            (0x0A0B_0C0D, 0x0102_0304),
            "the repair carries the journaled source timestamp"
        );
    }

    /// A reader matched after its set's end of set was journaled is repaired
    /// with that marker when it NACKs it: the marker is retained for it
    /// (RTPS v2.5 Sec.8.4.2.2.3, Sec.8.7.6), and the repair is the end of set
    /// itself, not a GAP.
    #[test]
    fn a_reader_matched_after_an_end_of_set_is_repaired_with_it() {
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");
        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);
        let cache = test_cache(8);
        cache.set_release_policy(true, false);
        cache.insert(1, &[0x55; 32]).unwrap();
        cache.insert(2, &[0x55; 32]).unwrap();
        cache
            .insert_grouped_until(
                3,
                &[],
                0,
                crate::reliability::ChangeMetadata {
                    kind: ChangeKind::EcsClose,
                    source_ts_known: true,
                    ..crate::reliability::ChangeMetadata::user_data()
                },
                Some(crate::protocol::group::GroupTag {
                    gsn: 9,
                    writer_set: [1, 2, 3, 4],
                    set_first_gsn: Some(1),
                    part_first_sn: Some(1),
                }),
                None,
            )
            .expect("insert end of set");
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        track_reader_proxy(
            &track,
            &cache,
            true,
            crate::dds::match_notification::PeerChange::Matched {
                guid: GUID::from_bytes(reader_guid()),
                reliable: true,
                volatile: true,
            },
        );
        assert_eq!(cache.lowest_retained_end_of_set(), Some(3));
        let metrics = Arc::new(ReliableMetrics::new());
        let fsm = fsm_with_capabilities(
            reader_guid(),
            Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
        );
        let (handler, _transport) =
            data_handler(domain.id(), 7, cache, metrics, Some(reg), Some(fsm));
        handler.on_nack(&acknack_from_reader(3, &[3]), Some(reader_guid()));
        let mut buf = [0u8; 2048];
        let (n, _) = listener
            .recv_from(&mut buf)
            .expect("the marker is repaired");
        let pkt = &buf[..n];
        assert_eq!(pkt[32], 0x15, "a DATA, the end of set itself");
        assert!(
            pkt.windows(8).any(|w| w == [0, 0, 0, 0, 3, 0, 0, 0]),
            "carries its own SN 3"
        );
    }

    /// The end of a set its writer had no part in, NACKed: a
    /// reader of the spec class is repaired with it in the spec form (its
    /// PID_COHERENT_SET its own SN); a legacy HDDS reader is told by a
    /// filtered GAP that the SN is not for it, never sent an end of a set.
    #[test]
    fn an_idle_writers_end_of_set_is_repaired_per_class() {
        for (capabilities, expect_gap) in [
            (Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT), false),
            (None, true),
        ] {
            let domain = unique_domain();
            let listener = crate::test_support::ports::bind_capture_socket();
            listener
                .set_read_timeout(Some(Duration::from_millis(400)))
                .expect("set timeout");
            let dest = listener.local_addr().expect("listener addr");
            let reg = EndpointRegistry::new();
            reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);
            let cache = test_cache(8);
            cache
                .insert_grouped_until(
                    6,
                    &[],
                    0,
                    crate::reliability::ChangeMetadata {
                        kind: ChangeKind::EcsClose,
                        source_ts_known: true,
                        ..crate::reliability::ChangeMetadata::user_data()
                    },
                    Some(crate::protocol::group::GroupTag {
                        gsn: 9,
                        writer_set: [1, 2, 3, 4],
                        set_first_gsn: Some(7),
                        part_first_sn: Some(6),
                    }),
                    None,
                )
                .expect("insert idle end of set");
            let metrics = Arc::new(ReliableMetrics::new());
            let fsm = fsm_with_capabilities(reader_guid(), capabilities);
            let (handler, _transport) =
                data_handler(domain.id(), 7, cache, metrics, Some(reg), Some(fsm));
            handler.on_nack(&acknack_from_reader(6, &[6]), Some(reader_guid()));
            let mut buf = [0u8; 2048];
            let (n, _) = listener.recv_from(&mut buf).expect("a repair");
            let pkt = &buf[..n];
            if expect_gap {
                assert_eq!(pkt[20], 0x08, "a GAP");
                assert_eq!(u32::from_le_bytes([pkt[36], pkt[37], pkt[38], pkt[39]]), 6);
                // No change for that reader: filtered, never a sample lost
                // (RTPS v2.5 Sec.8.4.9.2, Sec.9.4.5.6): the F flag, and a
                // filteredCount of 1 after the empty gapList.
                assert_eq!(pkt[21], 0x01 | 0x04, "flags E|F");
                assert_eq!(u16::from_le_bytes([pkt[22], pkt[23]]), 36);
                assert_eq!(&pkt[52..60], &[0, 0, 0, 0, 1, 0, 0, 0], "filteredCount 1");
                assert_eq!(n, 60, "nothing after it");
            } else {
                let off = crate::protocol::builder::helpers::find_data_submsg_offset(pkt)
                    .expect("a DATA");
                assert_eq!(pkt[off + 1] & 0x04, 0, "no payload");
                // PID_COHERENT_SET first, after PID_TOPIC_NAME: its own SN.
                let at = pkt
                    .windows(4)
                    .position(|w| w == [0x56, 0x00, 0x08, 0x00])
                    .expect("PID_COHERENT_SET");
                assert_eq!(
                    u32::from_le_bytes(pkt[at + 8..at + 12].try_into().unwrap()),
                    6
                );
                assert!(
                    pkt.windows(4).any(|w| w == [0x64, 0x00, 0x08, 0x00]),
                    "0x0064"
                );
            }
        }
    }

    /// A change of a GROUP Publisher's writer taken and never made, whose
    /// SN and GSN could not be given back: to a reader of the spec
    /// class it is GAPped alone with the GroupInfoFlag naming its GSN
    /// (RTPS v2.5 Sec.9.4.5.6), decoded from the bytes, BEFORE the rest of
    /// the repair's GAP, which does not declare it; any other reader gets
    /// the plain GAP.
    #[test]
    fn a_hole_in_a_group_writers_numbering_is_gapped_with_its_gsn() {
        for (capabilities, spec) in [
            (Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT), true),
            (None, false),
        ] {
            let domain = unique_domain();
            let listener = crate::test_support::ports::bind_capture_socket();
            listener
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("set timeout");
            let dest = listener.local_addr().expect("listener addr");
            let reg = EndpointRegistry::new();
            reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);
            let cache = test_cache(8);
            for seq in [1u64, 2, 4, 6] {
                cache
                    .insert_with_metadata(
                        seq,
                        &[0xAB],
                        0,
                        crate::reliability::ChangeMetadata::user_data(),
                    )
                    .expect("insert");
            }
            // 3 a hole, 5 gone from the history.
            cache.record_group_hole(3, 0x1_0000_0007);
            let metrics = Arc::new(ReliableMetrics::new());
            let fsm = fsm_with_capabilities(reader_guid(), capabilities);
            let (handler, _transport) =
                data_handler(domain.id(), 8, cache, metrics, Some(reg), Some(fsm));
            handler.on_nack(&acknack_from_reader(3, &[3, 5]), Some(reader_guid()));
            let mut gaps = Vec::new();
            let mut buf = [0u8; 2048];
            while let Ok((n, _)) = listener.recv_from(&mut buf) {
                if n > 24 && buf[20] == 0x08 {
                    gaps.push(buf[20..n].to_vec());
                }
            }
            // (G flag, gapStart, every SN declared)
            let read = |g: &Vec<u8>| {
                let sn =
                    |at: usize| u64::from(u32::from_le_bytes(g[at..at + 4].try_into().unwrap()));
                let start = sn(16);
                let base = sn(24);
                let bits = u32::from_le_bytes(g[28..32].try_into().unwrap());
                let mut declared: Vec<u64> = (start..base).collect();
                for i in 0..bits {
                    let word = u32::from_le_bytes(
                        g[32 + 4 * (i as usize / 32)..36 + 4 * (i as usize / 32)]
                            .try_into()
                            .unwrap(),
                    );
                    if word & (1 << (31 - i % 32)) != 0 {
                        declared.push(base + u64::from(i));
                    }
                }
                (g[1] & 0x02 != 0, declared)
            };
            let decoded: Vec<(bool, Vec<u64>)> = gaps.iter().map(read).collect();
            if !spec {
                assert_eq!(
                    decoded,
                    vec![(false, vec![3]), (false, vec![5])],
                    "today's GAPs"
                );
                continue;
            }
            assert_eq!(
                decoded,
                vec![(true, vec![3]), (false, vec![5])],
                "the hole first, alone, then the rest"
            );
            let expected: Vec<u8> = [
                &[0x08, 0x01 | 0x02, 44, 0][..],
                &reader_entity_id_of(reader_guid()),
                &repair_ctx().writer_entity_id,
                // gapStart 3, gapList.bitmapBase 4, numBits 0
                &[0, 0, 0, 0, 3, 0, 0, 0],
                &[0, 0, 0, 0, 4, 0, 0, 0],
                &[0, 0, 0, 0],
                // gapStartGSN = gapEndGSN = 0x1_0000_0007
                &[1, 0, 0, 0, 7, 0, 0, 0],
                &[1, 0, 0, 0, 7, 0, 0, 0],
            ]
            .concat();
            assert_eq!(gaps[0].as_slice(), expected.as_slice());
        }
    }

    /// The DATA_FRAGs repairing or replaying a fragmented change of a GROUP
    /// set: the first carries the set's tags in the form the reader's class
    /// received live, decoded from the bytes; a change of no set
    /// carries none.
    #[test]
    fn a_fragmented_change_is_repaired_with_its_sets_tags_per_class() {
        let ctx = repair_ctx();
        let payload = vec![0x44u8; 20_000];
        let tag = crate::protocol::group::GroupTag {
            gsn: 9,
            writer_set: [1, 2, 3, 4],
            set_first_gsn: Some(8),
            part_first_sn: None,
        };
        let member = crate::reliability::ChangeMetadata {
            coherent_sn: Some(3),
            group_sn: Some(2),
            source_ts_known: true,
            ..crate::reliability::ChangeMetadata::user_data()
        };
        let pids = |packets: &[Vec<u8>]| -> Option<Vec<u16>> {
            let first = packets.first()?;
            if first[33] & 0x02 == 0 {
                return None;
            }
            let mut at = 68;
            let mut out = Vec::new();
            loop {
                let pid = u16::from_le_bytes([first[at], first[at + 1]]);
                let len = usize::from(u16::from_le_bytes([first[at + 2], first[at + 3]]));
                if pid == 1 {
                    return Some(out);
                }
                out.push(pid);
                at += 4 + len;
            }
        };
        let frags = |metadata: &crate::reliability::ChangeMetadata, spec: bool| {
            change_frag_packets(
                &ctx,
                "FragRepair",
                5,
                &payload,
                metadata,
                Some(&tag),
                1024,
                (0, 0),
                spec,
            )
        };
        let spec = pids(&frags(&member, true)).expect("Q on the spec form");
        for pid in [0x0056u16, 0x0063, 0x0064, 0x0065] {
            assert!(spec.contains(&pid), "spec form has {pid:#06x}: {spec:x?}");
        }
        assert!(!spec.contains(&0x8030) && !spec.contains(&0x0053));
        let legacy = pids(&frags(&member, false)).expect("Q on today's form");
        for pid in [0x0056u16, 0x8030, 0x0053] {
            assert!(
                legacy.contains(&pid),
                "today's form has {pid:#06x}: {legacy:x?}"
            );
        }
        assert!(!legacy.contains(&0x0064));
        let plain = crate::reliability::ChangeMetadata::user_data();
        let none = change_frag_packets(
            &ctx,
            "FragRepair",
            5,
            &payload,
            &plain,
            None,
            1024,
            (0, 0),
            false,
        );
        assert!(!none.is_empty());
        assert_eq!(
            pids(&none),
            None,
            "a change of no set carries no inline QoS"
        );
    }

    /// Full wiring proof for the intercom gate: a NACK covering a user
    /// DATA slot and an ECS close slot from a discovered intercom reader
    /// yields exactly TWO unicast packets -- the ordinary DATA repair and
    /// the single-SN GAP retiring the close slot -- and no marker form.
    #[test]
    fn ecs_close_repair_for_intercom_sends_gap_through_on_nack() {
        // Declared first so it drops last, after the transport built by
        // data_handler() below has released the domain's RTPS sockets.
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");

        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);

        let cache = test_cache(8);
        cache.insert(5, &[0xAB; 8]).expect("insert user data");
        cache
            .insert_ecs_close(6, Some(5), None)
            .expect("insert ECS close");
        let metrics = Arc::new(ReliableMetrics::new());
        let fsm = fsm_with_vendor(reader_guid(), Some(INTERCOM_VENDOR_ID_U16));
        let (handler, _transport) =
            data_handler(domain.id(), 6, cache, metrics, Some(reg), Some(fsm));

        handler.on_nack(&acknack_from_reader(5, &[5, 6]), Some(reader_guid()));

        // Exactly two unicast packets: the seq-5 DATA repair and the
        // seq-6 GAP. Delivery order is the retransmit-loop order but we
        // classify defensively.
        let mut got_data5 = false;
        let mut got_gap6 = false;
        let mut buf = [0u8; 2048];
        for _ in 0..2 {
            let (n, _) = listener.recv_from(&mut buf).expect("repair must arrive");
            let pkt = &buf[..n];
            assert_eq!(&pkt[0..4], b"RTPS");
            if pkt[20] == 0x08 {
                assert_eq!(
                    u32::from_le_bytes([pkt[36], pkt[37], pkt[38], pkt[39]]),
                    6,
                    "GAP retires the ECS close slot SN"
                );
                assert_eq!(
                    u32::from_le_bytes([pkt[44], pkt[45], pkt[46], pkt[47]]),
                    7,
                    "GAP list base = seq + 1"
                );
                got_gap6 = true;
            } else {
                let off = crate::protocol::builder::helpers::find_data_submsg_offset(pkt)
                    .expect("non-GAP repair must be the seq-5 DATA");
                assert_eq!(
                    u32::from_le_bytes([
                        pkt[off + 20],
                        pkt[off + 21],
                        pkt[off + 22],
                        pkt[off + 23]
                    ]),
                    5,
                    "ordinary repair is the user DATA slot"
                );
                got_data5 = true;
            }
        }
        assert!(got_data5, "user DATA repair for seq 5 must arrive");
        assert!(got_gap6, "single-SN GAP for the ECS slot must arrive");

        // Nothing else: no marker form, no duplicate.
        assert!(
            listener.recv_from(&mut buf).is_err(),
            "exactly two repairs: DATA(5) + GAP(6), nothing more"
        );
    }

    /// An InterCOM reader NACKs the boundary of a set on every HEARTBEAT it
    /// answers. While the boundary's retirement is deferred to the close of
    /// the next set (`protocol::dialect::close_gap`), the repair of that NACK
    /// sends NOTHING: a GAP from here would release the next set at an
    /// arbitrary phase of its transmission. Once the deferred retirement has
    /// moved on to a later boundary (or the hold has run out) the NACK is
    /// answered with the single-SN GAP.
    #[test]
    fn ecs_close_repair_for_intercom_leaves_a_deferred_boundary_alone() {
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");

        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);

        let cache = test_cache(8);
        cache.insert(5, &[0xAB; 8]).expect("insert user data");
        cache
            .insert_ecs_close(6, Some(5), None)
            .expect("insert ECS close");
        let metrics = Arc::new(ReliableMetrics::new());
        let fsm = fsm_with_vendor(reader_guid(), Some(INTERCOM_VENDOR_ID_U16));
        let (handler, _transport) = data_handler(
            domain.id(),
            8,
            Arc::clone(&cache),
            metrics,
            Some(reg),
            Some(fsm),
        );
        let mut buf = [0u8; 2048];

        // The boundary 6 is the reader's pending one: the NACK is held.
        cache
            .deferred_close_gaps
            .defer(reader_guid(), 6, std::time::Instant::now());
        handler.on_nack(&acknack_from_reader(6, &[6]), Some(reader_guid()));
        assert!(
            listener.recv_from(&mut buf).is_err(),
            "a deferred boundary is not retired by the repair of a NACK"
        );

        // The next set's close moved the pending boundary on: 6 is retired
        // by the deferred GAP, and a NACK that still names it is answered.
        cache
            .deferred_close_gaps
            .defer(reader_guid(), 13, std::time::Instant::now());
        handler.on_nack(&acknack_from_reader(6, &[6]), Some(reader_guid()));
        let (n, _) = listener
            .recv_from(&mut buf)
            .expect("a boundary that is not pending is retired by the repair");
        assert_eq!(buf[20], 0x08, "single-SN GAP");
        assert_eq!(
            u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
            6,
            "the GAP retires the NACKed boundary"
        );
        assert!(n > 40);
    }

    /// Gate enforcement through the REAL on_nack wiring: an ECS close
    /// slot whose reader vendor cannot resolve is DROPPED -- never
    /// re-emitted as ordinary user DATA (which a classic reader would
    /// count as an extra sample),
    /// never multicast -- while the UserData slot in the same ACKNACK is
    /// still repaired unicast (positive control).
    #[test]
    fn ecs_close_repair_without_resolved_reader_drops() {
        // Declared first so it drops last, after the transport built by
        // data_handler() below has released the domain's RTPS sockets.
        let domain = unique_domain();
        // Real unicast listener plays the NACKing reader's locator.
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");

        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);

        let cache = test_cache(8);
        cache.insert(5, &[0xAB; 8]).expect("insert user data");
        cache
            .insert_ecs_close(6, Some(5), None)
            .expect("insert ECS close");
        let metrics = Arc::new(ReliableMetrics::new());
        // discovery_fsm: None -> the reader's vendor can NEVER resolve.
        let (handler, _transport) = data_handler(domain.id(), 4, cache, metrics, Some(reg), None);

        // ACKNACK NACKing both slots (5 = user DATA, 6 = ECS close).
        handler.on_nack(&acknack_from_reader(5, &[5, 6]), Some(reader_guid()));

        // Exactly ONE unicast repair arrives: the ordinary DATA for seq 5.
        let mut buf = [0u8; 2048];
        let (n, _) = listener
            .recv_from(&mut buf)
            .expect("user DATA repair for seq 5 must arrive unicast");
        let pkt = &buf[..n];
        assert_eq!(&pkt[0..4], b"RTPS");
        let off = crate::protocol::builder::helpers::find_data_submsg_offset(pkt)
            .expect("seq-5 repair must be a DATA packet");
        assert_ne!(
            pkt[off + 1] & 0x04,
            0,
            "seq-5 repair is ordinary user DATA (D=1)"
        );
        assert_eq!(
            u32::from_le_bytes([pkt[off + 20], pkt[off + 21], pkt[off + 22], pkt[off + 23]]),
            5,
            "the one repair on the wire is seq 5, not the ECS slot"
        );

        // And NOTHING else: the ECS close slot (seq 6) is dropped.
        assert!(
            listener.recv_from(&mut buf).is_err(),
            "ECS close repair must be DROPPED when the reader vendor is unresolved"
        );

        // Direct gate checks: each missing prerequisite drops.
        let change = ecs_change(6, Some(5), None);
        assert!(
            !handler.repair_ecs_close(
                &change,
                None,
                Some(ReaderDestination {
                    endpoint: dest,
                    reader: GUID::from_bytes(reader_guid()),
                    classic_window: false,
                })
            ),
            "no resolved reader GUID -> drop"
        );
        assert!(
            !handler.repair_ecs_close(&change, Some(reader_guid()), None),
            "no unicast locator -> drop"
        );

        // Pure-builder gates: unresolved vendor never yields a packet,
        // and a native ECS cannot regenerate without its coherent_sn.
        assert_eq!(
            build_ecs_repair_packet(&repair_ctx(), "T", &change, [0, 0, 0x10, 0x07], None),
            None,
            "unresolved vendor -> no packet, ever"
        );
        assert_eq!(
            build_ecs_repair_packet(
                &repair_ctx(),
                "T",
                &ecs_change(6, None, None),
                [0, 0, 0x10, 0x07],
                Some(HDDS_VENDOR_ID_U16)
            ),
            None,
            "native ECS without cached coherent_sn -> no packet"
        );
    }

    /// A unicast send failure on an ECS close repair DROPS the repair --
    /// NEVER falls back to multicast (a multicast close form reaches
    /// not-yet-matched classic collators and can stall them). Observed on the actual
    /// user-data multicast group of a dedicated domain, fenced between
    /// two control datagrams.
    #[test]
    fn ecs_close_repair_unicast_failure_does_not_multicast() {
        // Dedicated domain so the multicast observer only ever sees this
        // test's traffic (user-data multicast port is domain-scoped).
        // Declared first so it drops last, after the observer socket and
        // the transport below have released the domain.
        let domain = unique_domain();
        let domain_id = domain.id();
        let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");
        let mc_port = mapping.metatraffic_multicast + 1;

        // Observer joined to the user-data multicast group. The transport
        // never binds this port itself (it only sends to it).
        let observer = std::net::UdpSocket::bind(("0.0.0.0", mc_port)).expect("bind observer");
        crate::transport::multicast::join_multicast_group(&observer).expect("join group");
        observer
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");

        // Reader locator with an IPv6 address: the user-data socket is
        // AF_INET, so send_to fails deterministically on every platform
        // (EAFNOSUPPORT on Linux, WSAEAFNOSUPPORT on Windows). A port-0
        // destination only fails on Linux; the Windows target accepts it.
        let bad_dest: SocketAddr = "[::1]:7411".parse().expect("addr");
        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), bad_dest);

        let cache = test_cache(8);
        cache
            .insert_ecs_close(6, Some(5), None)
            .expect("insert ECS close");
        let metrics = Arc::new(ReliableMetrics::new());
        let fsm = fsm_with_vendor(reader_guid(), Some(CLASSIC_VENDOR));
        let (handler, transport) = data_handler(domain_id, 0, cache, metrics, Some(reg), Some(fsm));

        // Positive control A: prove the observer sees this transport's
        // user-data multicast at all; without it the negative assertion
        // below would be vacuous.
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

        // Failing repair through the REAL on_nack wiring: reader + vendor
        // resolved, unicast dest present but the send errors (IPv6 dest on
        // an IPv4 socket).
        handler.on_nack(&acknack_from_reader(6, &[6]), Some(reader_guid()));

        // Direct call confirms the drop is reported.
        assert!(
            !handler.repair_ecs_close(
                &ecs_change(6, Some(5), None),
                Some(reader_guid()),
                Some(ReaderDestination {
                    endpoint: bad_dest,
                    reader: GUID::from_bytes(reader_guid()),
                    classic_window: false,
                })
            ),
            "unicast send failure must report a dropped ECS repair"
        );

        if control_seen {
            // Ordering fence: send control B. Every datagram the observer
            // sees between A and B must be a control -- an RTPS packet in
            // between would be the ECS repair leaking to multicast.
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
                            "ECS repair LEAKED to multicast: {:02x?}",
                            &dgram[..dgram.len().min(24)]
                        );
                    }
                    Err(_) => break,
                }
            }
            assert!(fence_seen, "control fence B must arrive on the observer");
        } else {
            // Multicast loopback not observable in this environment: the
            // direct-drop assertion above still holds; only the wire-level
            // observation is skipped.
            eprintln!(
                "SKIP multicast observation: control datagram not looped back on domain {}",
                domain_id
            );
        }
    }

    /// `reader_profile` and `unicast_dest` are
    /// two INDEPENDENT lookups and can disagree (a reader GUID resolves a
    /// wire profile while no unicast locator is known for it). A packet
    /// finalized for one reader must NEVER reach the multicast group; and
    /// a repair for a resolved reader does not reach it at all,
    /// not even canonical: its ENTITYID_UNKNOWN would hand every reader on
    /// the group a change owed to one. Only an unresolved requester keeps
    /// the canonical multicast.
    #[test]
    fn send_finalized_or_multicast_never_leaks_finalized_bytes_to_multicast() {
        // Declared first so it drops last, after the observer socket and
        // the transport below have released the domain.
        let domain = unique_domain();
        let domain_id = domain.id();
        let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");
        let mc_port = mapping.metatraffic_multicast + 1;

        let observer = std::net::UdpSocket::bind(("0.0.0.0", mc_port)).expect("bind observer");
        crate::transport::multicast::join_multicast_group(&observer).expect("join group");
        observer
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");

        let cache = test_cache(4);
        let metrics = Arc::new(ReliableMetrics::new());
        let (handler, transport) = data_handler(domain_id, 0, cache, metrics, None, None);

        // Positive control: prove the observer sees this transport's
        // user-data multicast at all before trusting any negative result.
        transport
            .send_user_data_multicast(b"HDDS_FIN_CTRL_A")
            .expect("control send");
        let mut buf = [0u8; 2048];
        let mut control_seen = false;
        for _ in 0..3 {
            match observer.recv_from(&mut buf) {
                Ok((n, _)) if &buf[..n] == b"HDDS_FIN_CTRL_A" => {
                    control_seen = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        if !control_seen {
            eprintln!(
                "SKIP multicast observation: control datagram not looped back on domain {}",
                domain_id
            );
            return;
        }

        // Canonical packet long enough to carry the readerEntityId field;
        // a distinct sentinel at that offset lets a leaked finalize show
        // up as a byte difference instead of a coincidental match.
        let mut canonical = vec![0xEEu8; builder::READER_ENTITY_ID_OFFSET + 4];
        canonical[builder::READER_ENTITY_ID_OFFSET..builder::READER_ENTITY_ID_OFFSET + 4]
            .copy_from_slice(&[0, 0, 0, 0]);
        let profile = ReaderWireProfile {
            entity_id: [0x11, 0x22, 0x33, 0x44],
            vendor: None,
        };

        // A resolved reader with no locator, then one whose unicast send
        // fails (an IPv6 destination on the AF_INET user-data socket fails on
        // every platform): nothing reaches the group. A fence datagram sent
        // afterwards must be the next thing the observer sees.
        let bad_dest: SocketAddr = "[::1]:7411".parse().expect("addr");
        handler.send_finalized_or_multicast(&canonical, Some(profile), false, None, false);
        handler.send_finalized_or_multicast(
            &canonical,
            Some(profile),
            false,
            Some(ReaderDestination {
                endpoint: bad_dest,
                reader: GUID::from_bytes(reader_guid()),
                classic_window: false,
            }),
            false,
        );
        transport
            .send_user_data_multicast(b"HDDS_FIN_CTRL_B")
            .expect("fence send");
        let (n, _) = observer.recv_from(&mut buf).expect("the fence");
        assert_eq!(
            &buf[..n],
            b"HDDS_FIN_CTRL_B",
            "a repair for a resolved reader reached the multicast group"
        );

        // An unresolved requester: the CANONICAL bytes, never a finalized
        // copy, on both paths.
        handler.send_finalized_or_multicast(&canonical, None, false, None, false);
        let (n, _) = observer
            .recv_from(&mut buf)
            .expect("canonical packet must reach multicast when dest is None");
        assert_eq!(&buf[..n], &canonical[..]);
        handler.send_finalized_or_multicast(
            &canonical,
            None,
            false,
            Some(ReaderDestination {
                endpoint: bad_dest,
                reader: GUID::from_bytes(reader_guid()),
                classic_window: false,
            }),
            false,
        );
        let (n2, _) = observer
            .recv_from(&mut buf)
            .expect("canonical packet must reach multicast on unicast failure");
        assert_eq!(&buf[..n2], &canonical[..]);
    }

    /// A repair of a GROUP change for an unresolved requester does not fall
    /// back to the multicast group while a participant of the spec class is
    /// known: its audience is of no one class. Any other change does,
    /// as it did.
    #[test]
    fn a_group_repair_does_not_multicast_to_an_audience_of_unknown_class() {
        let domain = unique_domain();
        let domain_id = domain.id();
        let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");
        let observer = std::net::UdpSocket::bind(("0.0.0.0", mapping.metatraffic_multicast + 1))
            .expect("bind observer");
        crate::transport::multicast::join_multicast_group(&observer).expect("join group");
        observer
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let fsm = fsm_with_capabilities(
            reader_guid(),
            Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
        );
        let (handler, transport) = data_handler(
            domain_id,
            0,
            test_cache(4),
            Arc::new(ReliableMetrics::new()),
            None,
            Some(fsm),
        );
        let canonical = vec![0xEEu8; builder::READER_ENTITY_ID_OFFSET + 4];
        let mut buf = [0u8; 2048];
        transport
            .send_user_data_multicast(b"HDDS_GRP_CTRL_A")
            .expect("control send");
        match observer.recv_from(&mut buf) {
            Ok((n, _)) if &buf[..n] == b"HDDS_GRP_CTRL_A" => {}
            _ => {
                eprintln!("SKIP multicast observation: no loopback on domain {domain_id}");
                return;
            }
        }
        handler.send_finalized_or_multicast(&canonical, None, false, None, true);
        handler.send_unicast_or_multicast(&canonical, None, true);
        transport
            .send_user_data_multicast(b"HDDS_GRP_CTRL_B")
            .expect("fence send");
        let (n, _) = observer.recv_from(&mut buf).expect("the fence");
        assert_eq!(
            &buf[..n],
            b"HDDS_GRP_CTRL_B",
            "a GROUP repair reached the group"
        );
        handler.send_finalized_or_multicast(&canonical, None, false, None, false);
        let (n, _) = observer.recv_from(&mut buf).expect("a plain repair");
        assert_eq!(&buf[..n], &canonical[..], "any other change still does");
    }

    // ------------------------------------------------------------------
    // Batched ACKNACKs: a datagram carries one ACKNACK per writer the
    // reader is talking to (RTPS v2.5 Sec.8.3.3), and the demux hands the
    // SAME bytes to every nack handler registered on the topic transport.
    // ------------------------------------------------------------------

    /// Entity id of ANOTHER writer of the same participant.
    const OTHER_WRITER_EID: [u8; 4] = [0x00, 0x00, 0x20, 0x02];

    /// Raw RTPS ACKNACK from the test reader, addressed to `writer_eid`.
    fn acknack_for_writer(writer_eid: [u8; 4], base: u64, missing: &[u64]) -> Vec<u8> {
        let mut reader_prefix = [0u8; 12];
        reader_prefix.copy_from_slice(&reader_guid()[..12]);
        builder::build_acknack_packet(
            reader_prefix,
            OUR_PREFIX,
            [0x00, 0x00, 0x10, 0x07],
            writer_eid,
            base,
            missing,
            1,
        )
    }

    /// The ACKNACK submessage of a packet built by `build_acknack_packet`,
    /// RTPS header and INFO_DST stripped. Asserts the wire invariants it
    /// relies on, so a builder change cannot silently turn the batched
    /// fixture below into something the walk reads as one submessage.
    fn acknack_submessage_of(packet: &[u8]) -> &[u8] {
        let mut off = 20;
        while off + 4 <= packet.len() {
            assert_eq!(
                packet[off + 1] & 0x01,
                0x01,
                "fixture builder emits little-endian submessages"
            );
            let len = usize::from(u16::from_le_bytes([packet[off + 2], packet[off + 3]]));
            if packet[off] == 0x06 {
                assert_eq!(
                    off + 4 + len,
                    packet.len(),
                    "ACKNACK must declare its real length, not run to the end of the datagram"
                );
                return &packet[off..];
            }
            off += 4 + len;
        }
        panic!("no ACKNACK submessage in the built packet");
    }

    /// One datagram carrying every packet's ACKNACK submessage, in order,
    /// behind the first packet's RTPS header.
    fn batched_acknacks(packets: &[Vec<u8>]) -> Vec<u8> {
        let mut out = packets[0].clone();
        for p in &packets[1..] {
            out.extend_from_slice(acknack_submessage_of(p));
        }
        // A fixture the walk cannot read proves nothing about a walk.
        assert_eq!(
            crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages(&out)
                .len(),
            packets.len(),
            "batched fixture must carry one readable ACKNACK per packet"
        );
        out
    }

    /// Sequence numbers of the repair DATA packets that reach `listener`,
    /// until it stops delivering.
    fn repaired_seqs(listener: &std::net::UdpSocket) -> Vec<u32> {
        let mut seqs = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok((n, _)) = listener.recv_from(&mut buf) {
            let pkt = &buf[..n];
            assert_eq!(&pkt[0..4], b"RTPS");
            let off = crate::protocol::builder::helpers::find_data_submsg_offset(pkt)
                .expect("every repair here is a DATA packet");
            seqs.push(u32::from_le_bytes([
                pkt[off + 20],
                pkt[off + 21],
                pkt[off + 22],
                pkt[off + 23],
            ]));
        }
        seqs.sort_unstable();
        seqs
    }

    /// Two writers of one participant, one datagram: OUR ACKNACK rides
    /// SECOND. `on_nack` must not read the first ACKNACK only: it would see
    /// the neighbour's entity id, fail the addressed-to-us filter and
    /// return, dropping the reader's request with no counter and no log
    /// naming it.
    #[test]
    fn an_acknack_riding_behind_another_writers_is_still_serviced() {
        // Declared first so it drops last, after the transport built by
        // data_handler() below has released the domain's RTPS sockets.
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");

        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);

        let cache = test_cache(8);
        cache.insert(5, &[0x55; 8]).expect("insert seq 5");
        cache.insert(7, &[0x77; 8]).expect("insert seq 7");
        let metrics = Arc::new(ReliableMetrics::new());
        let (handler, _transport) = data_handler(domain.id(), 7, cache, metrics, Some(reg), None);

        handler.on_nack(
            &batched_acknacks(&[
                acknack_for_writer(OTHER_WRITER_EID, 5, &[5]),
                acknack_for_writer(WRITER_EID, 7, &[7]),
            ]),
            Some(reader_guid()),
        );

        assert_eq!(
            repaired_seqs(&listener),
            vec![7],
            "our ACKNACK is serviced, and the other writer's is not ours to service"
        );
    }

    /// writerId ENTITYID_UNKNOWN names no writer: unlike readerId on a
    /// HEARTBEAT or GAP (RTPS v2.5 Sec.8.3.7.5 / 8.3.8.4), Table 8.40 gives
    /// ACKNACK's writerId no ENTITYID_UNKNOWN broadcast form, and real
    /// ACKNACKs from every tested vendor never carry it. A datagram with one
    /// ACKNACK naming no writer and one naming us owes exactly one repair,
    /// never two: every writer of the participant repairing on an unnamed
    /// ACKNACK would be a defect, not a feature.
    #[test]
    fn an_acknack_naming_no_writer_is_refused_not_broadcast() {
        // Declared first so it drops last, after the transport built by
        // data_handler() below has released the domain's RTPS sockets.
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");

        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);

        let cache = test_cache(8);
        cache.insert(5, &[0x55; 8]).expect("insert seq 5");
        cache.insert(7, &[0x77; 8]).expect("insert seq 7");
        let metrics = Arc::new(ReliableMetrics::new());
        let (handler, _transport) = data_handler(domain.id(), 8, cache, metrics, Some(reg), None);

        handler.on_nack(
            &batched_acknacks(&[
                acknack_for_writer([0u8; 4], 5, &[5]),
                acknack_for_writer(WRITER_EID, 7, &[7]),
            ]),
            Some(reader_guid()),
        );

        assert_eq!(
            repaired_seqs(&listener),
            vec![7],
            "writerId UNKNOWN is refused; only the ACKNACK naming us is serviced"
        );
    }

    /// `claims_acknack` itself, directly: the entity id this writer was
    /// built with is claimed, a mismatched one is refused, and so is
    /// ENTITYID_UNKNOWN -- the three cases Table 8.40 distinguishes,
    /// pinned without a socket round-trip.
    #[test]
    fn claims_acknack_refuses_unknown_and_mismatch_alike() {
        let cache = test_cache(4);
        let metrics = Arc::new(ReliableMetrics::new());
        let (handler, _transport) =
            data_handler(unique_domain().id(), 9, cache, metrics, None, None);

        assert!(
            handler.claims_acknack(WRITER_EID),
            "the writer's own entity id is claimed"
        );
        assert!(
            !handler.claims_acknack(OTHER_WRITER_EID),
            "another writer's entity id is refused"
        );
        assert!(
            !handler.claims_acknack([0u8; 4]),
            "ENTITYID_UNKNOWN names no writer and is refused, not broadcast"
        );
    }

    /// Perimeter of the batched read: a handler built with NO RTPS
    /// endpoint context does not know its own entity id, so it claims
    /// every ACKNACK of the datagram. Answering them all would multiply
    /// the spurious repair rounds `claims_acknack` exists to stop, so it
    /// answers exactly one.
    ///
    /// The ACKNACK it answers here is the OTHER writer's, and that is not
    /// a correct answer -- there is no correct answer without an entity
    /// id. What this pins is that the wrong answer is not multiplied.
    ///
    /// This configuration is test-only: `Topic::create_writer` is the one
    /// non-test path that builds a writer and it always supplies a
    /// participant, so `rtps_endpoint` is always `Some` in production.
    /// It has to be identified by its PAYLOAD rather than its sequence
    /// number, because the contextless `build_data_packet` emits no
    /// INFO_TS and therefore violates the `READER_ENTITY_ID_OFFSET`
    /// invariant its own doc states: the per-reader entity id patch lands
    /// on the low word of writerSN and the repair goes out claiming a
    /// sequence it does not carry. Latent (unreachable from the public
    /// API today).
    #[test]
    fn without_an_endpoint_context_exactly_one_acknack_is_answered() {
        // Declared first so it drops last, after the transport built
        // below has released the domain's RTPS sockets.
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let dest = listener.local_addr().expect("listener addr");

        let reg = EndpointRegistry::new();
        reg.register_reader_locator(GUID::from_bytes(reader_guid()), dest);

        let cache = test_cache(8);
        cache.insert(5, &[0x55; 8]).expect("insert seq 5");
        cache.insert(7, &[0x77; 8]).expect("insert seq 7");

        let mapping = PortMapping::calculate(domain.id(), 9).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 9, mapping).expect("test transport"));
        let handler = WriterNackHandler::new(
            "EcsRepairTestTopic".to_string(),
            cache,
            transport.clone(),
            Arc::new(ReliableMetrics::new()),
            RetransmitCfg {
                rtps_endpoint: None,
                endpoint_registry: Some(reg),
                canonical_encapsulation_kind: 0x0007,
                ack_track: None,
                frag_route: Arc::new(super::super::frag_route::FragRouteProfile::new(
                    u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
                        .expect("DEFAULT_FRAGMENT_SIZE fits the u16 fragmentSize field"),
                )),
                discovery_fsm: None,
            },
        );

        handler.on_nack(
            &batched_acknacks(&[
                acknack_for_writer(OTHER_WRITER_EID, 5, &[5]),
                acknack_for_writer(WRITER_EID, 7, &[7]),
            ]),
            Some(reader_guid()),
        );

        let mut buf = [0u8; 2048];
        let (n, _) = listener
            .recv_from(&mut buf)
            .expect("one repair must arrive");
        assert!(
            buf[..n].ends_with(&[0x55; 8]),
            "the answer is the datagram's FIRST ACKNACK, carrying the seq-5 payload"
        );
        assert!(
            listener.recv_from(&mut buf).is_err(),
            "one answer, never one per ACKNACK"
        );
    }

    /// The GAP transmitter is shared by every request of a writer. A
    /// request that carries no entity ids (the re-encoded path) must not
    /// send its GAP under the ids the previous ACKNACK left behind: that
    /// GAP would name a reader that did not ask.
    #[test]
    fn a_gap_never_carries_the_ids_of_the_previous_request() {
        let domain = unique_domain();
        let listener = crate::test_support::ports::bind_capture_socket();
        listener
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        let reg = EndpointRegistry::new();
        reg.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            listener.local_addr().expect("listener addr"),
        );
        let cache = test_cache(8);
        cache.insert(5, &[0x55; 8]).expect("insert seq 5");
        let mapping = PortMapping::calculate(domain.id(), 9).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 9, mapping).expect("test transport"));
        let handler = WriterNackHandler::new(
            "GapIdsTestTopic".to_string(),
            cache,
            transport.clone(),
            Arc::new(ReliableMetrics::new()),
            RetransmitCfg {
                rtps_endpoint: None,
                endpoint_registry: Some(reg),
                canonical_encapsulation_kind: 0x0007,
                ack_track: None,
                frag_route: Arc::new(super::super::frag_route::FragRouteProfile::new(
                    u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
                        .expect("DEFAULT_FRAGMENT_SIZE fits the u16 fragmentSize field"),
                )),
                discovery_fsm: None,
            },
        );
        let reader_a = [0x00, 0x00, 0x10, 0x07];
        let mut buf = [0u8; 2048];
        // GAP submessage body right after the 20-byte RTPS header and its
        // own 4-byte submessage header: readerId, then writerId.
        let mut gap_ids = || {
            let n = listener.recv(&mut buf).expect("a GAP must arrive");
            assert_eq!(buf[20], 0x08, "a GAP submessage");
            assert!(n >= 32);
            (
                <[u8; 4]>::try_from(&buf[24..28]).expect("readerId"),
                <[u8; 4]>::try_from(&buf[28..32]).expect("writerId"),
            )
        };

        // Seq 3 is not in the cache: answered with a GAP.
        handler.on_acknack(
            reader_guid(),
            &crate::core::discovery::multicast::control_types::AckNackInfo {
                reader_entity_id: reader_a,
                writer_entity_id: WRITER_EID,
                missing_ranges: vec![std::ops::Range { start: 3, end: 4 }],
                bitmap_base: 3,
                count: None,
            },
        );
        assert_eq!(gap_ids(), (reader_a, WRITER_EID), "the ACKNACK's ids");

        handler.on_nack(
            &NackMsg::new(vec![std::ops::Range { start: 3, end: 4 }]).encode_cdr2_le(),
            Some(reader_guid()),
        );
        assert_eq!(
            gap_ids(),
            (ENTITYID_UNKNOWN, ENTITYID_UNKNOWN),
            "no ids known: ENTITYID_UNKNOWN, never the previous request's"
        );
    }

    // ------------------------------------------------------------------
    // The doors of the "owed" rule, on the ACKNACK and NACK_FRAG paths.
    // ------------------------------------------------------------------

    const DOOR_TOPIC: &str = "OwedDoorTopic";

    /// A discovery database that has announced the test reader on
    /// `DOOR_TOPIC` (its participant announced once, past the startup
    /// probation), without the writer having paired it.
    fn discovered_test_reader() -> Arc<DiscoveryFsm> {
        use crate::protocol::discovery::{SedpData, SpdpData};
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&reader_guid()[..12]);
        std::thread::sleep(Duration::from_millis(300));
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        fsm.handle_sedp(SedpData {
            topic_name: DOOR_TOPIC.to_string(),
            type_name: "Probe".to_string(),
            participant_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]),
            endpoint_guid: GUID::from_bytes(reader_guid()),
            qos_hash: 1,
            qos: Some(crate::dds::QoS::reliable()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert!(
            fsm.find_readers_for_topic(DOOR_TOPIC)
                .iter()
                .any(|r| r.endpoint_guid.as_bytes() == reader_guid()),
            "the fixture must announce the reader"
        );
        fsm
    }

    fn door_cfg(
        track: &AckTrack,
        fsm: Arc<DiscoveryFsm>,
        endpoint_registry: Option<EndpointRegistry>,
    ) -> RetransmitCfg {
        RetransmitCfg {
            rtps_endpoint: Some(repair_ctx()),
            endpoint_registry,
            canonical_encapsulation_kind: 0x0007,
            ack_track: Some(Arc::clone(track)),
            frag_route: Arc::new(super::super::frag_route::FragRouteProfile::new(
                u16::try_from(crate::protocol::builder::DEFAULT_FRAGMENT_SIZE)
                    .expect("DEFAULT_FRAGMENT_SIZE fits the u16 fragmentSize field"),
            )),
            discovery_fsm: Some(fsm),
        }
    }

    /// The submessages of a datagram, as (id, readerId).
    fn submessages(datagram: &[u8]) -> Vec<(u8, [u8; 4])> {
        use crate::core::discovery::multicast::classifier::walk;
        let mut found = Vec::new();
        walk::for_each_submessage(datagram, |sub| {
            if matches!(sub.id, 0x08 | 0x15 | 0x16) {
                let at = sub.offset + if sub.id == 0x08 { 4 } else { 8 };
                if let Ok(reader) = <[u8; 4]>::try_from(&datagram[at..at + 4]) {
                    found.push((sub.id, reader));
                }
            }
            walk::Step::Continue
        });
        found
    }

    /// An observer on the user-data multicast group and a fence: the fence
    /// is the next thing it sees when nothing else reached the group.
    struct Group {
        observer: std::net::UdpSocket,
        transport: Arc<UdpTransport>,
    }

    impl Group {
        fn join(domain_id: u32, transport: Arc<UdpTransport>) -> Self {
            let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");
            let observer =
                std::net::UdpSocket::bind(("0.0.0.0", mapping.metatraffic_multicast + 1))
                    .expect("bind observer");
            crate::transport::multicast::join_multicast_group(&observer).expect("join group");
            observer
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("timeout");
            Self {
                observer,
                transport,
            }
        }

        /// Whether nothing but the fence reached the group (true when the
        /// loopback is not observable here: nothing to contradict).
        fn quiet(&self) -> bool {
            self.transport
                .send_user_data_multicast(b"HDDS_DOOR_FENCE")
                .expect("fence");
            let mut buf = [0u8; 4096];
            match self.observer.recv(&mut buf) {
                Ok(n) => &buf[..n] == b"HDDS_DOOR_FENCE",
                Err(_) => true,
            }
        }
    }

    fn reader_socket() -> std::net::UdpSocket {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("reader socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("timeout");
        socket
    }

    fn next_datagram(socket: &std::net::UdpSocket) -> Option<Vec<(u8, [u8; 4])>> {
        let mut buf = [0u8; 4096];
        socket.recv(&mut buf).ok().map(|n| submessages(&buf[..n]))
    }

    #[test]
    fn the_acknack_door_ignores_the_unpaired_and_gaps_what_is_not_owed() {
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let group = Group::join(domain.id(), Arc::clone(&transport));
        let reader = reader_socket();
        let cache = test_cache(8);
        for seq in 1..=3 {
            cache.insert(seq, &[0x11; 8]).expect("insert");
        }
        let metrics = Arc::new(ReliableMetrics::new());
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let registry = EndpointRegistry::new();
        let handler = WriterNackHandler::new(
            DOOR_TOPIC.to_string(),
            Arc::clone(&cache),
            Arc::clone(&transport),
            Arc::clone(&metrics),
            door_cfg(&track, discovered_test_reader(), Some(registry.clone())),
        );
        let nack = || crate::core::discovery::multicast::control_types::AckNackInfo {
            reader_entity_id: [0x00, 0x00, 0x10, 0x07],
            writer_entity_id: WRITER_EID,
            missing_ranges: vec![std::ops::Range { start: 1, end: 4 }],
            bitmap_base: 1,
            count: None,
        };

        // Discovered, not paired yet: ignored.
        handler.on_acknack(reader_guid(), &nack());
        assert_eq!(metrics.retransmit_sent(), 0, "not paired yet: ignored");

        // Paired after the three writes (a VOLATILE reader): not owed. With
        // no locator, its GAP does not go to the group.
        track.lock().expect("track").insert(reader_guid(), 3);
        handler.on_acknack(reader_guid(), &nack());
        assert_eq!(metrics.retransmit_sent(), 0);
        assert!(group.quiet(), "a GAP naming one reader reached the group");

        // With its locator: a GAP, to that reader, naming it.
        registry.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            reader.local_addr().expect("addr"),
        );
        handler.on_acknack(reader_guid(), &nack());
        assert_eq!(
            next_datagram(&reader),
            Some(vec![(0x08, [0x00, 0x00, 0x10, 0x07])])
        );
        assert_eq!(metrics.retransmit_sent(), 0);

        // Owed (paired before the writes): repaired.
        track.lock().expect("track").insert(reader_guid(), 0);
        handler.on_acknack(reader_guid(), &nack());
        assert_eq!(metrics.retransmit_sent(), 3, "paired and owed: repaired");
    }

    /// A discovery that has not announced the reader on `DOOR_TOPIC`.
    fn undiscovered_test_reader() -> Arc<DiscoveryFsm> {
        Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000))
    }

    /// A request naming an entity is judged on its reader's pairing; one
    /// naming no entity (ENTITYID_UNKNOWN) names no reader to judge and is
    /// not left unanswered by this rule. Without discovery there is no rule.
    #[test]
    fn unpaired_reader_unanswered_judges_only_named_readers() {
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let fsm = undiscovered_test_reader();
        let mut unnamed = reader_guid();
        unnamed[12..16].copy_from_slice(&[0u8; 4]);
        assert!(unpaired_reader_unanswered(
            Some(&track),
            Some(&fsm),
            DOOR_TOPIC,
            reader_guid()
        ));
        assert!(!unpaired_reader_unanswered(
            Some(&track),
            Some(&fsm),
            DOOR_TOPIC,
            unnamed
        ));
        assert!(!unpaired_reader_unanswered(
            Some(&track),
            None,
            DOOR_TOPIC,
            reader_guid()
        ));
        track.lock().expect("track").insert(reader_guid(), 0);
        assert!(!unpaired_reader_unanswered(
            Some(&track),
            Some(&fsm),
            DOOR_TOPIC,
            reader_guid()
        ));
    }

    /// RTPS 2.5 Table 8.66: the writer's acknowledgement transitions exist
    /// for a matched ReaderProxy only (T1 adds it, T16 removes it). A reader
    /// whose SEDP has not reached this writer yet can already be heard: its
    /// first ACKNACK, for the history a VOLATILE reader is not owed (DDS 1.4
    /// 2.2.3.4), is ignored, not repaired, and the reader asks again at the
    /// next HEARTBEAT.
    #[test]
    fn an_acknack_from_a_reader_discovery_has_not_announced_is_ignored() {
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let reader = reader_socket();
        let cache = test_cache(8);
        for seq in 1..=3 {
            cache.insert(seq, &[0x11; 8]).expect("insert");
        }
        let metrics = Arc::new(ReliableMetrics::new());
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let registry = EndpointRegistry::new();
        registry.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            reader.local_addr().expect("addr"),
        );
        let handler = WriterNackHandler::new(
            DOOR_TOPIC.to_string(),
            Arc::clone(&cache),
            Arc::clone(&transport),
            Arc::clone(&metrics),
            door_cfg(&track, undiscovered_test_reader(), Some(registry.clone())),
        );
        let nack =
            |start: u64, end: u64| crate::core::discovery::multicast::control_types::AckNackInfo {
                reader_entity_id: [0x00, 0x00, 0x10, 0x07],
                writer_entity_id: WRITER_EID,
                missing_ranges: vec![std::ops::Range { start, end }],
                bitmap_base: start,
                count: None,
            };

        handler.on_acknack(reader_guid(), &nack(1, 4));
        assert_eq!(metrics.retransmit_sent(), 0, "not announced: ignored");
        assert!(
            next_datagram(&reader).is_none(),
            "not announced: nothing sent to the reader"
        );
        assert!(track.lock().expect("track").is_empty());

        // Announced and matched as VOLATILE after the three writes: owed
        // nothing before its match.
        track_reader_proxy(
            &track,
            &cache,
            true,
            crate::dds::match_notification::PeerChange::Matched {
                guid: GUID::from_bytes(reader_guid()),
                reliable: true,
                volatile: true,
            },
        );
        handler.on_acknack(reader_guid(), &nack(1, 4));
        assert_eq!(
            metrics.retransmit_sent(),
            0,
            "matched as VOLATILE: the writes before the match are not repaired"
        );

        // Written after the match: owed, and repaired.
        cache.insert(4, &[0x11; 8]).expect("insert");
        handler.on_acknack(reader_guid(), &nack(4, 5));
        assert_eq!(
            metrics.retransmit_sent(),
            1,
            "written after the match: owed"
        );
    }

    /// VERIFY-SECENF2: an ADMITTED (authenticated) reader of a protected
    /// topic NACKs; the writer knows no unicast locator for it (none
    /// announced, no endpoint registry), so `send_unicast_or_multicast`
    /// repairs to the user-data MULTICAST group, where unauthenticated
    /// participants listen. The live path closes that fallback
    /// (`multicast_fallback_closed`); the repair path does not.
    #[cfg(feature = "security")]
    #[test]
    fn recheck_repair_of_protected_topic_does_not_fall_back_to_multicast() {
        use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
        const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let cache = test_cache(8);
        for seq in 1..=3 {
            cache.insert(seq, &[0x11; 8]).expect("insert");
        }
        let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.set_handshake_machine(
            crate::security::test_pki::local_machine_with_completed_peer(LOCAL, PEER, None),
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
            crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![TopicRule {
                topic_expression: "*".to_string(),
                enable_discovery_protection: false,
                enable_liveliness_protection: false,
                enable_read_access_control: true,
                enable_write_access_control: true,
                metadata_protection_kind: ProtectionKind::None,
                data_protection_kind: BasicProtectionKind::None,
            }],
        })));
        std::thread::sleep(Duration::from_millis(300));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: Some(crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec()),
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let reader = GUID::new(PEER, [0, 0, 0x12, 0x07]);
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            topic_name: DOOR_TOPIC.to_string(),
            type_name: "Probe".to_string(),
            participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(crate::dds::QoS::reliable()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert!(
            fsm.admits_remote_endpoint(DOOR_TOPIC, &reader, false),
            "fixture: the authenticated reader is admitted"
        );
        assert!(
            fsm.unauthenticated_gate_applies(DOOR_TOPIC),
            "fixture: protected"
        );
        let fsm = Arc::new(fsm);
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let _ = track_reader_proxy(
            &track,
            &cache,
            false,
            crate::dds::match_notification::PeerChange::Matched {
                guid: reader,
                reliable: true,
                volatile: false,
            },
        );
        let metrics = Arc::new(ReliableMetrics::new());
        let handler = WriterNackHandler::new(
            DOOR_TOPIC.to_string(),
            Arc::clone(&cache),
            Arc::clone(&transport),
            Arc::clone(&metrics),
            door_cfg(&track, Arc::clone(&fsm), None),
        );
        let nack = NackMsg::new(vec![std::ops::Range { start: 1, end: 4 }]).encode_cdr2_le();
        let mc_port = mapping.metatraffic_multicast + 1;
        let observer = std::net::UdpSocket::bind(("0.0.0.0", mc_port)).expect("bind observer");
        crate::transport::multicast::join_multicast_group(&observer).expect("join group");
        observer
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("set timeout");
        transport
            .send_user_data_multicast(b"VERIFY2_CTRL")
            .expect("control send");
        let mut buf = [0u8; 4096];
        let mut control_seen = false;
        for _ in 0..3 {
            if let Ok((n, _)) = observer.recv_from(&mut buf) {
                if &buf[..n] == b"VERIFY2_CTRL" {
                    control_seen = true;
                    break;
                }
            }
        }
        handler.on_nack(&nack, Some(reader.as_bytes()));
        let mut mc_rtps = 0;
        while let Ok((n, _)) = observer.recv_from(&mut buf) {
            if n >= 4 && &buf[..4] == b"RTPS" {
                mc_rtps += 1;
            }
        }
        eprintln!(
            "[verify2] control_seen={} multicast RTPS datagrams after the NACK={} retransmit_sent={}",
            control_seen, mc_rtps, metrics.retransmit_sent()
        );
        assert!(
            control_seen,
            "fixture: the observer hears the user-data multicast group"
        );
        // REFUTED hypothesis guard: the DATA repair to a named reader with no
        // locator is dropped (`send_finalized_or_multicast`, profile Some),
        // never multicast. retransmit_sent counts it all the same.
        assert_eq!(
            mc_rtps, 0,
            "the protected topic's data was repaired to the multicast group"
        );
    }

    /// Under the security plugins a NACK that names no reader is not
    /// answered: its repair, with no reader to address, went to the
    /// multicast group, whoever listens on it (DDS Security v1.1
    /// Sec.8.8.7.1, 9.4.3). Without them it is served as before.
    #[cfg(feature = "security")]
    #[test]
    fn a_nack_naming_no_reader_is_not_answered_under_the_security_plugins() {
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let cache = test_cache(8);
        for seq in 1..=3 {
            cache.insert(seq, &[0x11; 8]).expect("insert");
        }
        let mut governed = DiscoveryFsm::new(GUID::zero(), 30_000);
        governed.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![TopicRule {
                topic_expression: "*".to_string(),
                enable_discovery_protection: false,
                enable_liveliness_protection: false,
                enable_read_access_control: true,
                enable_write_access_control: true,
                metadata_protection_kind: ProtectionKind::None,
                data_protection_kind: BasicProtectionKind::None,
            }],
        })));
        let nack = NackMsg::new(vec![std::ops::Range { start: 1, end: 4 }]).encode_cdr2_le();
        for (fsm, served) in [
            (Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)), 3),
            (Arc::new(governed), 0),
        ] {
            let metrics = Arc::new(ReliableMetrics::new());
            let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
            let handler = WriterNackHandler::new(
                DOOR_TOPIC.to_string(),
                Arc::clone(&cache),
                Arc::clone(&transport),
                Arc::clone(&metrics),
                door_cfg(&track, fsm, None),
            );
            handler.on_nack(&nack, None);
            assert_eq!(metrics.retransmit_sent(), served);
        }
        // The fragment-level door, on a sample past the unfragmented
        // ceiling.
        let large = test_cache(8);
        large.insert(5, &[0x22; 10_000]).expect("insert");
        let mut governed_frag = DiscoveryFsm::new(GUID::zero(), 30_000);
        governed_frag.set_handshake_machine(
            Arc::new(crate::security::handshake::HandshakeMachine::new()),
            Vec::new(),
            Vec::new(),
        );
        for (fsm, served) in [
            (Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000)), true),
            (Arc::new(governed_frag), false),
        ] {
            let metrics = Arc::new(ReliableMetrics::new());
            let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
            let handler = WriterNackFragHandler::new(
                DOOR_TOPIC.to_string(),
                Arc::clone(&large),
                Arc::clone(&transport),
                Arc::clone(&metrics),
                WRITER_EID,
                door_cfg(&track, fsm, None),
            );
            handler.on_nack_frag(&WRITER_EID, 5, &[1], None);
            assert_eq!(metrics.retransmit_sent() > 0, served);
        }
    }

    #[test]
    fn the_nack_frag_door_ignores_the_unpaired_and_gaps_what_is_not_owed() {
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let group = Group::join(domain.id(), Arc::clone(&transport));
        let reader = reader_socket();
        let cache = test_cache(8);
        // Past the unfragmented ceiling, so it goes out in fragments.
        cache.insert(5, &[0x22; 10_000]).expect("insert");
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let registry = EndpointRegistry::new();
        registry.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            reader.local_addr().expect("addr"),
        );
        let metrics = Arc::new(ReliableMetrics::new());
        let handler = WriterNackFragHandler::new(
            DOOR_TOPIC.to_string(),
            Arc::clone(&cache),
            Arc::clone(&transport),
            Arc::clone(&metrics),
            WRITER_EID,
            door_cfg(&track, discovered_test_reader(), Some(registry.clone())),
        );
        let request = || handler.on_nack_frag(&WRITER_EID, 5, &[1], Some(reader_guid()));

        // Discovered, not paired yet: nothing.
        request();
        assert_eq!(next_datagram(&reader), None);

        // Paired after seq 5 was written: a GAP naming it, no fragment.
        track.lock().expect("track").insert(reader_guid(), 5);
        request();
        assert_eq!(
            next_datagram(&reader),
            Some(vec![(0x08, [0x00, 0x00, 0x10, 0x07])])
        );

        // Owed, and its only locator fails: nothing, not the group either.
        track.lock().expect("track").insert(reader_guid(), 0);
        registry.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            "[::1]:7411".parse().expect("addr"),
        );
        request();
        assert!(
            group.quiet(),
            "a repair for a resolved reader reached the group"
        );
        assert_eq!(metrics.retransmit_sent(), 0, "nothing was retransmitted");

        // Owed, with its locator: the fragment, naming it.
        registry.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            reader.local_addr().expect("addr"),
        );
        request();
        assert_eq!(
            next_datagram(&reader),
            Some(vec![(0x16, [0x00, 0x00, 0x10, 0x07])])
        );
        assert_eq!(metrics.retransmit_sent(), 1, "one change retransmitted");
    }

    /// RTPS 2.5 8.4.9.2 (T8) / 8.4.7.5: a reliable StatefulWriter answers
    /// an ACKNACK through the ReaderProxy of the reader that sent it, at the
    /// reader's DISCOVERED locator. An INFO_REPLY ahead of the ACKNACK
    /// naming another address (8.3.8.9) is the Receiver's reply locator,
    /// read only by a Reliable StatelessWriter (8.4.8.2.6): it must not aim
    /// the repair -- here a sample of 1000 octets for an ACKNACK of a few
    /// dozen -- at a third party. Driven end to end from the control
    /// thread, the door the UDP ACKNACK takes in production.
    #[test]
    fn an_info_reply_never_redirects_a_repair() {
        use crate::core::discovery::multicast::control::ControlHandler;
        use crate::core::discovery::multicast::control_types::{AckNackInfo, ControlMessage};
        use crate::core::discovery::multicast::sedp_history::SedpHistory;
        use crate::core::discovery::multicast::Origin;
        use crate::core::reader::ReaderProxyRegistry;
        use crate::engine::TopicRegistry;

        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let recorded = reader_socket();
        let named = reader_socket();
        let source = reader_socket();
        let std::net::SocketAddr::V4(named_v4) = named.local_addr().expect("addr") else {
            panic!("bound on IPv4");
        };
        let cache = test_cache(8);
        cache.insert(1, &[0x11; 1000]).expect("insert");
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        track.lock().expect("track").insert(reader_guid(), 0);
        let registry = EndpointRegistry::new();
        registry.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            recorded.local_addr().expect("addr"),
        );
        let fsm = discovered_test_reader();
        let topics = Arc::new(TopicRegistry::new());
        topics.register_nack_handler(Arc::new(WriterNackHandler::new(
            DOOR_TOPIC.to_string(),
            Arc::clone(&cache),
            Arc::clone(&transport),
            Arc::new(ReliableMetrics::new()),
            door_cfg(&track, Arc::clone(&fsm), Some(registry)),
        )));
        let control = ControlHandler::spawn_with_topic_registry(
            Arc::clone(&transport),
            OUR_PREFIX,
            7400,
            ReaderProxyRegistry::new(),
            ReaderProxyRegistry::new(),
            topics,
            fsm,
            Arc::new(std::sync::RwLock::new(SedpHistory::new())),
        );

        let mut reader_prefix = [0u8; 12];
        reader_prefix.copy_from_slice(&reader_guid()[..12]);
        let acknack = ControlMessage::acknack(
            Origin::direct(source.local_addr().expect("addr")).replying_to(Some(named_v4)),
            reader_prefix,
            AckNackInfo {
                reader_entity_id: [0x00, 0x00, 0x10, 0x07],
                writer_entity_id: WRITER_EID,
                missing_ranges: vec![std::ops::Range { start: 1, end: 2 }],
                bitmap_base: 1,
                count: Some(1),
            },
            &[],
        )
        .expect("control message");
        assert!(control.try_send(acknack));

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut repaired = None;
        while repaired.is_none() && std::time::Instant::now() < deadline {
            repaired = next_datagram(&recorded);
        }
        control.shutdown();
        assert_eq!(
            repaired,
            Some(vec![(0x15, [0x00, 0x00, 0x10, 0x07])]),
            "the repair reaches the reader's discovered locator"
        );
        assert_eq!(next_datagram(&named), None, "never the INFO_REPLY locator");
        assert_eq!(next_datagram(&source), None, "nor the source");
    }

    #[test]
    fn a_gap_on_the_re_encoded_path_names_the_reader_that_asked() {
        let domain = unique_domain();
        let reader = reader_socket();
        let registry = EndpointRegistry::new();
        registry.register_reader_locator(
            GUID::from_bytes(reader_guid()),
            reader.local_addr().expect("addr"),
        );
        let cache = test_cache(1);
        cache.insert(1, &[1; 8]).expect("insert");
        cache.insert(2, &[2; 8]).expect("insert"); // 1 leaves the history
        let (handler, _transport) = data_handler(
            domain.id(),
            0,
            cache,
            Arc::new(ReliableMetrics::new()),
            Some(registry),
            None,
        );
        let nack = NackMsg::new(vec![std::ops::Range { start: 1, end: 2 }]);
        handler.on_nack(&nack.encode_cdr2_le(), Some(reader_guid()));
        assert_eq!(
            next_datagram(&reader),
            Some(vec![(0x08, [0x00, 0x00, 0x10, 0x07])])
        );
    }

    /// The two multicast groups a repair could reach, observed on one
    /// socket: the user-data group of `domain_id` and the large-payload
    /// route's group (`frag_route::OPENDDS_DEFAULT_USER_MULTICAST_GROUP`) on
    /// the same port. `None` when the loopback of either is not observable
    /// here.
    #[cfg(feature = "security")]
    fn observe_both_groups(
        domain_id: u32,
        transport: &UdpTransport,
    ) -> Option<(std::net::UdpSocket, SocketAddr)> {
        let mapping = PortMapping::calculate(domain_id, 0).expect("port mapping");
        let port = mapping.metatraffic_multicast + 1;
        let observer = std::net::UdpSocket::bind(("0.0.0.0", port)).expect("bind observer");
        // Joins 239.255.0.1 and 239.255.0.2, the route's group among them.
        crate::transport::multicast::join_multicast_group(&observer).expect("join");
        let route_group = super::super::frag_route::OPENDDS_DEFAULT_USER_MULTICAST_GROUP;
        observer
            .set_read_timeout(Some(Duration::from_millis(400)))
            .expect("timeout");
        let route = SocketAddr::new(std::net::IpAddr::V4(route_group), port);
        let mut buf = [0u8; 2048];
        for (control, send) in [
            (
                &b"HDDS_MC_CTRL_USER"[..],
                transport.send_user_data_multicast(b"HDDS_MC_CTRL_USER"),
            ),
            (
                &b"HDDS_MC_CTRL_ROUTE"[..],
                transport.send_user_data_multicast_to(b"HDDS_MC_CTRL_ROUTE", &route),
            ),
        ] {
            send.ok()?;
            match observer.recv(&mut buf) {
                Ok(n) if &buf[..n] == control => {}
                _ => return None,
            }
        }
        Some((observer, route))
    }

    /// DDS Security v1.1 Sec.8.8.2.2, 8.8.7.1: nothing of a protected
    /// topic goes to a multicast group, where anyone may listen - an
    /// unauthenticated participant included. The writer of a topic our
    /// governance protects repairs an admitted reader whose locator is not
    /// known: its small change is dropped (the reader asks again), and its
    /// large one, like the fragments a NACK_FRAG asks for, is not repaired
    /// as DATA_FRAG to the large-payload route's group
    /// (`frag_route.multicast_dest()`); nor is a repair for an unresolved
    /// requester sent to the user-data group. The large-payload route and
    /// the unresolved fallback must not reach the groups (the live send path
    /// keeps off them too).
    #[cfg(feature = "security")]
    #[test]
    fn a_protected_topics_repairs_reach_no_multicast_group() {
        use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
        use crate::security::access::{
            BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
        };
        const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
        const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
        let domain = unique_domain();
        let mapping = PortMapping::calculate(domain.id(), 0).expect("port mapping");
        let transport =
            Arc::new(UdpTransport::new(domain.id(), 0, mapping).expect("test transport"));
        let Some((observer, route)) = observe_both_groups(domain.id(), &transport) else {
            eprintln!("SKIP: multicast loopback not observable on this host");
            return;
        };
        let cache = test_cache(8);
        cache.insert(1, &[0x11; 8]).expect("insert");
        cache
            .insert(
                2,
                &vec![0x22; crate::protocol::builder::DEFAULT_MAX_UNFRAGMENTED_SIZE + 1000],
            )
            .expect("insert");
        let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 30_000);
        fsm.set_handshake_machine(
            crate::security::test_pki::local_machine_with_completed_peer(LOCAL, PEER, None),
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
            crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::None,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![TopicRule {
                topic_expression: "*".to_string(),
                enable_discovery_protection: false,
                enable_liveliness_protection: false,
                enable_read_access_control: true,
                enable_write_access_control: true,
                metadata_protection_kind: ProtectionKind::None,
                data_protection_kind: BasicProtectionKind::None,
            }],
        })));
        std::thread::sleep(Duration::from_millis(300));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: Some(crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec()),
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
        let reader = GUID::new(PEER, [0, 0, 0x12, 0x07]);
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            topic_name: DOOR_TOPIC.to_string(),
            type_name: "Probe".to_string(),
            participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: reader,
            qos_hash: 1,
            qos: Some(crate::dds::QoS::reliable()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        });
        assert!(
            fsm.admits_remote_endpoint(DOOR_TOPIC, &reader, false),
            "fixture: the authenticated reader is admitted"
        );
        assert!(
            fsm.unauthenticated_gate_applies(DOOR_TOPIC),
            "fixture: protected"
        );
        let fsm = Arc::new(fsm);
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let _ = track_reader_proxy(
            &track,
            &cache,
            false,
            crate::dds::match_notification::PeerChange::Matched {
                guid: reader,
                reliable: true,
                volatile: false,
            },
        );
        let routed = |track: &AckTrack| {
            let cfg = door_cfg(track, Arc::clone(&fsm), None);
            cfg.frag_route.set_opendds(route.port());
            assert_eq!(cfg.frag_route.multicast_dest(), Some(route), "fixture");
            cfg
        };
        let metrics = Arc::new(ReliableMetrics::new());
        let handler = WriterNackHandler::new(
            DOOR_TOPIC.to_string(),
            Arc::clone(&cache),
            Arc::clone(&transport),
            Arc::clone(&metrics),
            routed(&track),
        );
        let frag_handler = WriterNackFragHandler::new(
            DOOR_TOPIC.to_string(),
            Arc::clone(&cache),
            Arc::clone(&transport),
            Arc::clone(&metrics),
            WRITER_EID,
            routed(&track),
        );

        let nack = NackMsg::new(vec![std::ops::Range { start: 1, end: 3 }]).encode_cdr2_le();
        handler.on_nack(&nack, Some(reader.as_bytes()));
        frag_handler.on_nack_frag(&WRITER_EID, 2, &[1, 2], Some(reader.as_bytes()));
        let canonical = vec![0xEEu8; builder::READER_ENTITY_ID_OFFSET + 4];
        handler.send_finalized_or_multicast(&canonical, None, false, None, false);
        handler.send_unicast_or_multicast(&canonical, None, false);
        assert!(
            metrics.retransmit_sent() > 0,
            "fixture: the repairs were reached"
        );

        transport
            .send_user_data_multicast(b"HDDS_MC_FENCE")
            .expect("fence");
        let mut buf = [0u8; 70_000];
        let mut leaked = Vec::new();
        loop {
            let (n, to) = observer.recv_from(&mut buf).expect("the fence arrives");
            if &buf[..n] == b"HDDS_MC_FENCE" {
                break;
            }
            leaked.push((n, to));
        }
        assert!(
            leaked.is_empty(),
            "a protected topic's repair reached a multicast group: {} datagram(s) {:?}",
            leaked.len(),
            leaked
        );
    }
    #[test]
    fn independent_a_delayed_pre_rematch_ack_cannot_acknowledge_future_changes() {
        let domain = unique_domain();
        let cache = test_cache(8);
        cache.insert(101, &[0x55; 32]).unwrap();
        cache.wire_windows.configure(true);
        let metrics = Arc::new(ReliableMetrics::new());
        let (mut handler, _transport) = data_handler(
            domain.id(),
            8,
            cache.clone(),
            metrics.clone(),
            None,
            Some(fsm_with_vendor(reader_guid(), Some(0x0101))),
        );
        let reader = GUID::from_bytes(reader_guid());
        cache.wire_windows.pair(reader, None, 0, false);
        // This ACK was emitted while wire 4 meant original 4, before an
        // unmatch/rematch changed the window. It can be reordered in UDP.
        let old_ack = acknack_from_reader(5, &[]);
        cache.wire_windows.unpair(reader);
        cache.wire_windows.pair(reader, None, 100, false);
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::from([(
            reader_guid(),
            100,
        )])));
        handler.ack_track = Some(track.clone());
        handler.on_nack(&old_ack, Some(reader_guid()));
        let acked = *track.lock().unwrap().get(&reader_guid()).unwrap();
        assert_eq!(metrics.controls_refused(), 1);
        assert_eq!(acked, 100);
        // Once enough new samples exist, the old ACK would pass an upper
        // bound check if rematching had reused the wire sequence space.
        cache.insert(105, &[0x66; 32]).unwrap();
        handler.on_nack(&old_ack, Some(reader_guid()));
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 100);
        assert_eq!(metrics.controls_refused(), 2);
        assert!(
            acked <= cache.highest_inserted(),
            "acknowledged original {} beyond highest committed {}",
            acked,
            cache.highest_inserted()
        );
    }
    #[test]
    fn unknown_group_readers_acknowledge_native_history_without_a_window() {
        let domain = unique_domain();
        let cache = test_cache(8);
        cache.insert(1, &[0x55; 32]).unwrap();
        cache.wire_windows.configure(true);
        let metrics = Arc::new(ReliableMetrics::new());
        let (mut handler, _transport) = data_handler(
            domain.id(),
            8,
            cache.clone(),
            metrics.clone(),
            None,
            Some(fsm_with_vendor(reader_guid(), None)),
        );
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        track_reader_proxy(
            &track,
            &cache,
            true,
            crate::dds::match_notification::PeerChange::Matched {
                guid: GUID::from_bytes(reader_guid()),
                reliable: true,
                volatile: true,
            },
        );
        handler.ack_track = Some(track.clone());
        cache.insert(2, &[0x66; 32]).unwrap();
        handler.on_nack(&acknack_from_reader(3, &[]), Some(reader_guid()));
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 2);
        assert_eq!(cache.acked_floor(), 2);
        assert_eq!(metrics.controls_refused(), 0);
        assert!(!cache.wire_windows.contains(GUID::from_bytes(reader_guid())));
    }

    fn end_of_set_metadata() -> crate::reliability::ChangeMetadata {
        crate::reliability::ChangeMetadata {
            kind: crate::reliability::ChangeKind::EcsClose,
            ..crate::reliability::ChangeMetadata::user_data()
        }
    }

    /// A VOLATILE reader matched after an end of set was journaled is owed
    /// that marker: it stays retained until the reader acknowledges it, and
    /// the HEARTBEAT firstSN does not pass it (RTPS v2.5 Sec.8.7.6).
    #[test]
    fn a_reader_matched_after_an_end_of_set_is_owed_it() {
        use crate::dds::writer::heartbeat_scheduler::advertised_first_seq;
        let cache = test_cache(8);
        cache.set_release_policy(true, false);
        cache.insert(1, &[0x55; 32]).unwrap();
        cache.insert(2, &[0x55; 32]).unwrap();
        cache
            .insert_grouped_until(3, &[], 0, end_of_set_metadata(), None, None)
            .unwrap();
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        track_reader_proxy(
            &track,
            &cache,
            true,
            crate::dds::match_notification::PeerChange::Matched {
                guid: GUID::from_bytes(reader_guid()),
                reliable: true,
                volatile: true,
            },
        );
        assert_eq!(cache.lowest_retained_end_of_set(), Some(3));
        let first = advertised_first_seq(cache.oldest_seq(), 3);
        assert!(
            first <= 3,
            "heartbeat firstSN {first} passes the unacked marker 3"
        );
        cache.set_acked_floor(2);
        assert_eq!(cache.lowest_retained_end_of_set(), Some(3));
        cache.set_acked_floor(3);
        assert_eq!(cache.lowest_retained_end_of_set(), None);
    }

    /// Without a retained end of set, a VOLATILE reader matched now is owed
    /// nothing written before its match (DDS 1.4 Sec.2.2.3.4).
    #[test]
    fn a_volatile_reader_without_a_retained_end_of_set_is_owed_nothing_before_it() {
        let cache = test_cache(8);
        cache.set_release_policy(true, false);
        cache.insert(1, &[0x55; 32]).unwrap();
        cache.insert(2, &[0x55; 32]).unwrap();
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::new()));
        track_reader_proxy(
            &track,
            &cache,
            true,
            crate::dds::match_notification::PeerChange::Matched {
                guid: GUID::from_bytes(reader_guid()),
                reliable: true,
                volatile: true,
            },
        );
        assert_eq!(cache.oldest_seq(), None);
    }

    #[test]
    fn classic_controls_validate_the_entire_committed_range_before_accounting() {
        let domain = unique_domain();
        let cache = test_cache(8);
        cache.insert(101, &[0x55; 32]).unwrap();
        cache.wire_windows.configure(true);
        cache
            .wire_windows
            .pair(GUID::from_bytes(reader_guid()), None, 100, false);
        let metrics = Arc::new(ReliableMetrics::new());
        let (mut handler, transport) = data_handler(
            domain.id(),
            8,
            cache.clone(),
            metrics.clone(),
            None,
            Some(fsm_with_vendor(reader_guid(), Some(0x0101))),
        );
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::from([(
            reader_guid(),
            100,
        )])));
        handler.ack_track = Some(track.clone());
        // highest + 1 is the cumulative boundary; nothing above it is published.
        handler.on_nack(&acknack_from_reader(3, &[]), Some(reader_guid()));
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 100);
        assert_eq!(metrics.controls_refused(), 1);
        // Even a valid cumulative boundary cannot smuggle a future NACK bit.
        handler.on_nack(&acknack_from_reader(2, &[2]), Some(reader_guid()));
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 100);
        assert_eq!(metrics.controls_refused(), 2);
        handler.on_nack(&acknack_from_reader(2, &[]), Some(reader_guid()));
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 101);
        assert_eq!(metrics.controls_refused(), 2);
        let frag = WriterNackFragHandler::new(
            "test".to_owned(),
            cache.clone(),
            transport,
            metrics.clone(),
            WRITER_EID,
            RetransmitCfg {
                rtps_endpoint: handler.rtps_endpoint,
                endpoint_registry: None,
                canonical_encapsulation_kind: 0x0007,
                ack_track: Some(track.clone()),
                frag_route: handler.frag_route.clone(),
                discovery_fsm: handler.discovery_fsm.clone(),
            },
        );
        frag.on_nack_frag(&WRITER_EID, 2, &[1], Some(reader_guid()));
        assert_eq!(
            metrics.controls_refused(),
            3,
            "future NACK_FRAG refused before dispatch"
        );
        cache.wire_windows.unpair(GUID::from_bytes(reader_guid()));
        cache
            .wire_windows
            .pair(GUID::from_bytes(reader_guid()), None, 101, false);
        frag.on_nack_frag(&WRITER_EID, 1, &[1], Some(reader_guid()));
        assert_eq!(
            metrics.controls_refused(),
            4,
            "previous pairing's fragment SN refused"
        );
        assert_eq!(metrics.retransmit_sent(), 0);
        let frame = metrics.snapshot(0);
        assert_eq!(
            frame
                .fields
                .iter()
                .find(|f| f.tag == crate::reliability::TAG_CONTROLS_REFUSED)
                .unwrap()
                .value_u64,
            4
        );
    }
    #[test]
    fn unrelated_fragment_controls_do_not_renew_retired_pairings() {
        use crate::dds::liveliness::ManualClock;
        use std::time::Duration;
        let domain = unique_domain();
        let cache = test_cache(8);
        cache.wire_windows.configure(true);
        let clock = Arc::new(ManualClock::new(0));
        cache.wire_windows.set_retirement_clock(clock.clone());
        let reader = GUID::from_bytes(reader_guid());
        cache.wire_windows.pair(reader, None, 10, false);
        cache.wire_windows.unpair(reader);
        let metrics = Arc::new(ReliableMetrics::new());
        let (handler, transport) = data_handler(
            domain.id(),
            8,
            cache.clone(),
            metrics.clone(),
            None,
            Some(fsm_with_vendor(reader_guid(), Some(0x0101))),
        );
        let frag = WriterNackFragHandler::new(
            "test".to_owned(),
            cache.clone(),
            transport,
            metrics.clone(),
            WRITER_EID,
            RetransmitCfg {
                rtps_endpoint: handler.rtps_endpoint,
                endpoint_registry: None,
                canonical_encapsulation_kind: 0x0007,
                ack_track: None,
                frag_route: handler.frag_route.clone(),
                discovery_fsm: handler.discovery_fsm.clone(),
            },
        );
        clock.advance(Duration::from_secs(119));
        let other_writer = [0x99, 0, 1, 3];
        assert_ne!(other_writer, WRITER_EID);
        frag.on_nack_frag(&other_writer, 1, &[1], Some(reader.as_bytes()));
        clock.advance(Duration::from_secs(1));
        cache.wire_windows.pair(reader, None, 50, false);
        assert_eq!(
            cache
                .wire_windows
                .inbound_offset(Some(reader.as_bytes()), true),
            Some(50),
            "another writer's NACK_FRAG cannot retain an expired origin"
        );
        assert_eq!(metrics.controls_refused(), 0);
        assert_eq!(metrics.retransmit_sent(), 0);
    }

    #[test]
    fn a_decoded_control_cannot_acknowledge_a_replacement_reader_proxy() {
        let domain = unique_domain();
        let cache = test_cache(8);
        cache.insert(101, &[0x55; 32]).unwrap();
        cache.wire_windows.configure(true);
        let reader = GUID::from_bytes(reader_guid());
        cache.wire_windows.pair(reader, None, 100, false);
        let metrics = Arc::new(ReliableMetrics::new());
        let (mut handler, _transport) = data_handler(
            domain.id(),
            8,
            cache.clone(),
            metrics.clone(),
            None,
            Some(fsm_with_vendor(reader_guid(), Some(0x0101))),
        );
        let track: AckTrack = Arc::new(Mutex::new(std::collections::HashMap::from([(
            reader_guid(),
            100,
        )])));
        handler.ack_track = Some(track.clone());
        let decoded = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        let (reached, release) = (decoded.clone(), resume.clone());
        handler.before_ack_apply = Some(Box::new(move || {
            reached.wait();
            release.wait();
        }));
        let worker = std::thread::spawn(move || {
            handler.on_nack(&acknack_from_reader(2, &[]), Some(reader_guid()));
        });
        decoded.wait();
        cache.wire_windows.unpair(reader);
        // The replacement has the same numeric bounds but a different identity.
        cache.wire_windows.pair(reader, None, 100, false);
        track.lock().unwrap().insert(reader_guid(), 100);
        resume.wait();
        worker.join().unwrap();
        assert_eq!(*track.lock().unwrap().get(&reader_guid()).unwrap(), 100);
        assert_eq!(metrics.controls_refused(), 1);
    }
}

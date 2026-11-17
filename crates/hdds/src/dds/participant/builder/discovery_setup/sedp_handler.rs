// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP packet handler.
//!
//!
//! Handles SEDP (Subscription/Endpoint Discovery Protocol) packets including:
//! - SEDP parsing
//! - Endpoint discovery (Writer/Reader)
//! - TopicRegistry updates (writer GUID -> topic mapping)
//! - FSM state updates
//! - Reader proxy notification for ACKNACK state machine

use super::type_lookup_handler::{
    maybe_request_omg_type_object, maybe_request_type_object, TypeLookupHandle,
};
use crate::core::discovery::multicast::classifier::for_each_data_submessage;
use crate::core::discovery::multicast::{
    build_heartbeat_submessage_final, build_sedp_rtps_packet_secured,
    rtps_packet::{next_sedp_heartbeat_count, sedp_entity_ids},
    DiscoveryFsm, EndpointKind, Origin, SedpChannel, SedpEndpointKind, TypeObjectPid,
};
use crate::core::discovery::GUID;
use crate::core::reader::ReaderProxyRegistry;
use crate::core::rtps_constants::{
    RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER, RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER,
};
use crate::engine::TopicRegistry;
use crate::protocol::builder::{
    extract_endpoint_guid_from_serialized_key, extract_inline_qos_at, extract_key_hash,
    extract_serialized_key_at, extract_status_info,
};
use crate::protocol::builder::{read_u16, read_u32};
use crate::protocol::dialect::{get_encoder, Dialect};
use crate::protocol::discovery::{parse_sedp, parse_sedp_with_vendor};
use std::sync::Arc;

/// Detect a SEDP endpoint dispose/unregister.
///
/// A vendor signals "this DataWriter / DataReader is going away" with a SEDP
/// DATA submessage on the built-in topic that announced it:
/// `ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER` (`0x000003c2`) for a writer,
/// `ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER` (`0x000004c2`) for a reader.
/// The DATA carries:
///   - submessage flags with Q (inline QoS present) and no data payload
///     (D=0); the serialized key (K=1) may be there or not
///   - `PID_STATUS_INFO` (0x0071) with D and/or U bits set
///     (DDS-RTPS v2.5 Sec.9.6.4.9)
///   - the 16-byte GUID of the disposed endpoint, its instance key: in
///     `PID_KEY_HASH` (0x0070, Sec.9.6.4.8), or else as PID_ENDPOINT_GUID in
///     the key-only payload (Sec.9.6.3.2)
///
/// An endpoint is deleted only by its own participant: the SEDP writer that
/// sent the DATA holds the data-objects of its own participant's endpoints
/// and of no other (Sec.8.5.4.4, Tables 8.82, 8.83), so the endpoint must
/// belong to the participant whose prefix the message carries (the RTPS
/// header, or the INFO_SRC the walk split it on, `split_by_receiver_state`). A
/// dispose naming an endpoint of another participant is refused.
///
/// Returns `Some((kind, disposed_endpoint_guid, status_info_low_byte))` when
/// the SEDP packet is an endpoint dispose, `kind` being named by the
/// built-in topic (its writerEntityId), not guessed from the GUID. Returns
/// `None` for any SEDP DATA that carries an actual SEDP record (D=1), that
/// lacks the expected inline QoS fields, that names another participant's
/// endpoint, or that comes from any other writer.
///
/// It reads the DATA submessage `cdr_offset` names (`data_submessage_at`),
/// the one this call is handling: a datagram carries several, and the
/// handler runs once per DATA. Reading the FIRST one every time would miss a
/// dispose that is not first and apply one that is first once per DATA of
/// its datagram. It reuses the
/// `extract_inline_qos` + `extract_status_info` + `extract_key_hash`
/// helpers (their `_at` forms) so the spec-compliant LE-octet-3 layout fix
/// lives in one place.
fn detect_sedp_endpoint_dispose(
    payload: &[u8],
    cdr_offset: usize,
) -> Option<(EndpointKind, [u8; 16], u8)> {
    let data_off = data_submessage_at(payload, cdr_offset)?;

    // Reads the fixed DATA fields against the submessage itself, which also
    // grants the flags octet read below.
    let (writer_entity_id, _) = data_writer_and_seq(payload, data_off)?;
    let kind = match writer_entity_id {
        RTPS_ENTITYID_SEDP_PUBLICATIONS_WRITER => EndpointKind::Writer,
        RTPS_ENTITYID_SEDP_SUBSCRIPTIONS_WRITER => EndpointKind::Reader,
        _ => return None,
    };

    let flags = payload[data_off + 1];
    let has_inline_qos = flags & 0x02 != 0;
    let has_payload = flags & 0x04 != 0;

    // Dispose signature: Q=1, D=0 (no full DCPSPublication/DCPSSubscription
    // announcement payload). The disposed endpoint's BuiltinTopicKey may be
    // carried two ways (RTPS v2.5 Sec.9.6.4.8, 9.6.3.2):
    //   - K=0, inline PID_KEY_HASH only, or
    //   - K=1, serialized key (PL_CDR PID_ENDPOINT_GUID), with or without an
    //     inline PID_KEY_HASH.
    // Both forms carry PID_STATUS_INFO in inline QoS, and the key is read
    // below from either place, so we accept either K value here and only
    // reject a D=1 announce. Refusing K=1 would leave the instances of a
    // remote writer deleted with a K=1 dispose ALIVE instead of
    // NOT_ALIVE_NO_WRITERS.
    if !has_inline_qos || has_payload {
        return None;
    }

    // `extract_inline_qos` returns the QoS slice paired with the E flag
    // that drives ParameterList PID/length decoding per RTPS v2.5 sec. 9.4.5.3.3.
    // Using that single source removes any chance of a second-scan
    // disagreement (e.g. `unwrap_or(true)` fallback masking a parse failure).
    let (inline_qos, is_le) = extract_inline_qos_at(payload, data_off)?;
    let status_info = extract_status_info(inline_qos, is_le)?;
    let status_lo = (status_info & 0x03) as u8;
    if status_lo == 0 {
        return None;
    }

    // Endpoint identity: inline PID_KEY_HASH or, when absent, the
    // PID_ENDPOINT_GUID inside the K-flag serialized key.
    let endpoint_guid = extract_key_hash(inline_qos, is_le).or_else(|| {
        extract_serialized_key_at(payload, data_off)
            .and_then(extract_endpoint_guid_from_serialized_key)
    })?;
    let sender_prefix = payload.get(8..20)?;
    if endpoint_guid[..12] != *sender_prefix {
        log::debug!(
            "[sedp] dispose of endpoint {:02x?} sent under {:02x?}: not that participant's, \
             ignored",
            &endpoint_guid[..],
            sender_prefix
        );
        return None;
    }
    Some((kind, endpoint_guid, status_lo))
}

/// Apply a SEDP endpoint dispose/unregister, if `payload` carries one.
///
/// Returns whether `payload` was an endpoint dispose.
///
/// Writer endpoint (DCPSPublication): a remote writer's deletion may arrive
/// only as this SEDP DATA(w) with D=0, Q=1 + PID_STATUS_INFO + its key,
/// without per-instance K-flag DATA on the user topic. Without the
/// user-instance branch HDDS sub never transitions instances to
/// NOT_ALIVE_* when a remote writer exits cleanly.
///
/// The PID_STATUS_INFO bits on a SEDP DCPSPublication packet describe the
/// lifecycle of the *BuiltinTopic instance* (the writer endpoint), not the
/// lifecycle of the user-topic instances the writer was producing. Per DDS
/// v1.4 Sec.2.2.4.2.2, "When all DataWriters that were writing the instance
/// have unregistered" the instance transitions to NOT_ALIVE_NO_WRITERS --
/// we therefore always synthesize `Unregistered` kind on the user-data side
/// regardless of the SEDP-side bits.
///
/// Both kinds: the endpoint also leaves discovery, so every local endpoint
/// it was matched with sees its matched count drop (the departure of the
/// whole participant is not the only way a remote endpoint is unmatched).
///
/// On the plain topic, the dispose of an endpoint a participant that
/// authenticated with us announced is ignored: anyone can send one, and
/// that participant sends its own on the secure topic
/// (`DiscoveryFsm::ignores_plain_sedp_about`, DDS Security v1.1
/// Sec.7.4.1.7, 7.4.1.8).
fn apply_sedp_endpoint_dispose(
    payload: &[u8],
    cdr_offset: usize,
    fsm: &DiscoveryFsm,
    registry: &TopicRegistry,
    channel: SedpChannel,
    change_sn: Option<i64>,
) -> bool {
    let Some((kind, endpoint_guid, _status_lo)) = detect_sedp_endpoint_dispose(payload, cdr_offset)
    else {
        return false;
    };
    if channel == SedpChannel::Plain
        && fsm.ignores_plain_sedp_about(&GUID::from_bytes(endpoint_guid))
    {
        return true;
    }
    // Not older than what was applied about that endpoint
    // (`DiscoveryFsm::admits_sedp_change`).
    if change_sn
        .is_some_and(|sn| !fsm.admits_sedp_change(channel, &GUID::from_bytes(endpoint_guid), sn))
    {
        return true;
    }

    if kind == EndpointKind::Writer {
        let dispose_kind = crate::engine::subscriber::DisposeKind::Unregistered;
        log::debug!(
            "[sedp] writer-endpoint dispose: writer={:02x?} -> NOT_ALIVE_NO_WRITERS",
            &endpoint_guid[..]
        );
        // The writer was deleted: its strength goes with it. Not on a
        // participant departure, which also follows a lease expiry or a
        // probation purge after which the peer may come back without
        // announcing the writer again.
        registry.forget_writer_ownership_strength(&endpoint_guid);
        // Told to the readers behind the writer's data still queued
        // (`engine::departures`).
        registry.post_departure(crate::engine::departures::Departure::Writer {
            guid: endpoint_guid,
            kind: dispose_kind,
            cause: crate::engine::WriterDeparture::Deleted,
        });
    }

    if !fsm.remove_remote_endpoint(GUID::from_bytes(endpoint_guid)) {
        log::debug!(
            "[sedp] {:?}-endpoint dispose for unknown endpoint {:02x?} - no-op",
            kind,
            &endpoint_guid[..]
        );
    }
    true
}

/// Record a remote writer's OWNERSHIP and PARTITION from SEDP, returning
/// its OWNERSHIP kind.
///
/// The kind is `OwnershipKind::announced`. The strength is the announced
/// PID_OWNERSHIP_STRENGTH, or the default 0 when it is absent, so a
/// re-announcement without it does not leave a stale value behind. It is
/// recorded BEFORE the kind: a reader resolves the writer through the kind,
/// and must then find its strength (DDS v1.4 Sec.2.2.3.10).
///
/// Durable like `register_writer_guid`: it survives the discovery FSM's
/// unconfirmed-participant purge (a slow-announcing vendor never re-sends
/// its ACKed SEDP, so the FSM registry may stay empty of this writer
/// forever). The strength leaves with the writer's own SEDP dispose
/// (`apply_sedp_endpoint_dispose`).
fn record_writer_qos(
    registry: &TopicRegistry,
    writer: [u8; 16],
    sedp_data: &crate::protocol::discovery::SedpData,
) -> crate::qos::ownership::OwnershipKind {
    let kind = crate::qos::ownership::OwnershipKind::announced(
        sedp_data.has_explicit_ownership.then(|| {
            sedp_data
                .qos
                .as_ref()
                .map_or(crate::qos::ownership::OwnershipKind::Shared, |q| {
                    q.ownership.kind
                })
        }),
        sedp_data.has_ownership_strength,
    );
    let strength = if sedp_data.has_ownership_strength {
        sedp_data
            .qos
            .as_ref()
            .map_or(0, |q| q.ownership_strength.value)
    } else {
        0
    };
    registry.register_writer_ownership_strength(writer, strength);
    registry.register_writer_ownership_kind(writer, kind);
    registry.register_writer_partition(
        writer,
        sedp_data
            .qos
            .as_ref()
            .map_or_else(Default::default, |q| q.partition.clone()),
    );
    kind
}

/// Flag remote writer `writer` as legacy (vendor HDDS, its participant NOT
/// announcing `CAP_CONFORMANT_KEY_HASH`: a 1.4.x peer, or an unreleased
/// pre-bit 1.5.0 snapshot) for `TopicRegistry::writer_uses_legacy_key_hash`
/// -- see that method's doc and record 385. Both looked up from the
/// participant's own SPDP announcement (`DiscoveryFsm::legacy_key_hash_known`),
/// the same source `record_writer_group_dialect` reads its dialect from, so
/// this needs no SEDP-specific vendor byte and is called identically from both
/// SEDP entry points (classifier and reassembled-fragments). A participant not
/// known yet is not flagged here; `settle_writer_decisions` decides it once it is.
fn record_writer_vendor(registry: &TopicRegistry, fsm: &DiscoveryFsm, writer: [u8; 16]) {
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&writer[..12]);
    let legacy = fsm.legacy_key_hash_known(&prefix).unwrap_or(false);
    registry.register_writer_legacy_key_hash(writer, legacy);
}

/// Record the GROUP class of remote writer `writer` (D18), decided once
/// here from its participant's announced dialect: the router reads it at
/// each of its ends of set.
fn record_writer_group_dialect(
    registry: &TopicRegistry,
    fsm: &DiscoveryFsm,
    writer: [u8; 16],
    publisher: Option<[u8; 4]>,
) {
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&writer[..12]);
    match fsm.group_dialect_known(&prefix) {
        Some(dialect) => registry.record_writer_group_dialect(writer, dialect, publisher),
        // A late SEDP (a repair) of a participant discovery forgot meanwhile
        // (its SPDP dispose, read on another thread): the class decided
        // while it was known stands. Its writers' ends of set still queued
        // behind their data are read in that form until their departure
        // reaches the readers (`engine::departures`).
        None if registry.writer_spec_group(&writer).is_some() => {}
        None => registry.record_writer_group_dialect(
            writer,
            crate::protocol::group::GroupDialect::Classic,
            publisher,
        ),
    }
}

/// Decide again, for remote writer `writer`, what `record_writer_group_dialect`
/// and `record_writer_vendor` decided of it at its announcement, now that its
/// participant may be known: its GROUP class (every dialect, `publisher` as
/// announced) and its legacy key-hash flag. Both are read from the participant
/// as discovery knows it now, the reads those two functions make; a
/// participant still unknown decides nothing new. The registry is written only
/// where what it holds differs (`TopicRegistry::settle_writer_group_dialect`,
/// `settle_writer_legacy_key_hash`).
///
/// The cause is an SPDP read on another thread that had not registered the
/// participant when the writer was announced: the writer was then recorded
/// for good as the classic class and without the legacy flag (its members
/// staged under no Publisher, its bare end of set read as nothing, no set of
/// it ever closing, for a Dust writer). Called on discovery events only: once
/// `handle_sedp` has taken the announcement here, and when the participant is
/// discovered (`WriterDepartures`, `replay_pending_sedp`), never per sample.
fn settle_writer_decisions(
    registry: &TopicRegistry,
    fsm: &DiscoveryFsm,
    writer: [u8; 16],
    publisher: Option<[u8; 4]>,
) {
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&writer[..12]);
    if let Some(dialect) = fsm.group_dialect_known(&prefix) {
        registry.settle_writer_group_dialect(writer, dialect, publisher);
    }
    if let Some(legacy) = fsm.legacy_key_hash_known(&prefix) {
        registry.settle_writer_legacy_key_hash(writer, legacy);
    }
}

/// The writers of a remote participant that left (`on_participant_departed`:
/// its SPDP dispose, or its lease expired) are gone with it. Its SEDP never
/// says so endpoint by endpoint, so the instances they wrote move to
/// NOT_ALIVE_NO_WRITERS here, by the same path an endpoint dispose takes
/// (`TopicRegistry::notify_participant_departed`, DDS v1.4 Sec.2.2.2.5.1.3).
pub(crate) struct WriterDepartures(std::sync::Weak<TopicRegistry>);

impl WriterDepartures {
    pub(crate) fn new(registry: &Arc<TopicRegistry>) -> Self {
        Self(Arc::downgrade(registry))
    }
}

impl crate::core::discovery::multicast::DiscoveryListener for WriterDepartures {
    fn on_endpoint_discovered(&self, endpoint: crate::core::discovery::multicast::EndpointInfo) {
        drop(endpoint);
    }

    fn on_participant_dialect_changed(
        &self,
        dialect: crate::protocol::group::GroupDialect,
        writers: &[([u8; 16], Option<[u8; 4]>)],
    ) {
        // The class of the participant's writers, decided at their
        // discovery (`record_writer_group_dialect`), decided again.
        if let Some(registry) = self.0.upgrade() {
            for (writer, publisher) in writers {
                registry.settle_writer_group_dialect(*writer, dialect, *publisher);
            }
        }
    }

    fn on_participant_key_hash_decided(&self, legacy_key_hash: bool, writers: &[[u8; 16]]) {
        // The legacy key-hash flag of the participant's writers, decided at
        // their discovery (`record_writer_vendor`), decided again.
        if let Some(registry) = self.0.upgrade() {
            for writer in writers {
                registry.settle_writer_legacy_key_hash(*writer, legacy_key_hash);
            }
        }
    }

    fn on_participant_left(&self, participant: GUID, announced: bool) {
        if let Some(registry) = self.0.upgrade() {
            let cause = if announced {
                crate::engine::WriterDeparture::Deleted
            } else {
                crate::engine::WriterDeparture::Unheard
            };
            // Told to the readers behind the participant's data still queued
            // (`engine::departures`).
            registry.post_departure(crate::engine::departures::Departure::Participant {
                prefix: participant.prefix,
                cause,
            });
        }
    }
}

/// Handle SEDP packet.
///
/// # Arguments
/// - `payload`: Full RTPS packet (including headers)
/// - `cdr_offset`: CDR payload offset within the packet (computed by classifier)
/// - `fsm`: Discovery FSM for state updates
/// - `registry`: Topic registry for writer GUID -> topic mapping
/// - `reader_registry`: Reader proxy registry for ACKNACK state tracking
/// - `transport`: UDP transport for sending responses
/// - `sedp_cache`: SEDP announcements cache for reader re-announcement
/// - `our_guid_prefix`: Our participant GUID prefix
/// - `type_lookup`: Optional TypeLookup handler for missing TypeObjects
/// - `origin`: where the datagram came from, and where a reply may go
///   (RTPS 2.5 8.3.4, 8.3.8.10: `None` behind an INFO_SRC)
/// - `channel`: the builtin topic the announcement arrived on; a plain
///   announcement or dispose of an endpoint an authenticated participant
///   already announced is ignored before anything is registered or removed
///   from it (`DiscoveryFsm::ignores_plain_sedp_about`)
#[allow(clippy::too_many_arguments)]
pub(super) fn handle_sedp_packet(
    payload: &[u8],
    cdr_offset: usize,
    fsm: Arc<DiscoveryFsm>,
    registry: Arc<TopicRegistry>,
    reader_registry: ReaderProxyRegistry,
    transport: Arc<crate::transport::UdpTransport>,
    sedp_cache: super::super::entity_registry::SedpAnnouncementsCache,
    our_guid_prefix: [u8; 12],
    type_lookup: TypeLookupHandle,
    origin: Origin,
    channel: SedpChannel,
) {
    log::debug!(
        "[callback-builder] Received SEDP packet, len={}, cdr_offset={}",
        payload.len(),
        cdr_offset
    );

    // Extract writer GUID and sequence number from RTPS DATA header
    // to notify the reader proxy registry that we received this DATA.
    //
    // RTPS DATA format (after RTPS header at offset 20):
    // - Submessage header: 4 bytes (ID=0x15, flags, length)
    // - extraFlags: 2 bytes
    // - octetsToInlineQos: 2 bytes
    // - readerEntityId: 4 bytes
    // - writerEntityId: 4 bytes
    // - writerSeqNum: 8 bytes (high: i32, low: u32)
    //
    // Writer GUID = RTPS header guid_prefix (bytes 8-20) + writerEntityId (offset 20+12)
    let change = extract_data_writer_info(payload, cdr_offset);
    // A resource refusal must remain missing to the reliable reader. Only
    // acknowledge a change after its tracking admission succeeds.
    let acknowledge = || {
        if let Some((writer_guid, seq)) = change {
            log::debug!(
                "[sedp] Notifying reader registry: writer={:02x?}, seq={}",
                writer_guid,
                seq
            );
            reader_registry.on_data(writer_guid, seq);

            // Send the confirmation ACKNACK if the peer's dialect encoder builds one
            // (`build_sedp_data_confirmation`; the `OpenDds` dialect, vendor 0x0103, does).
            //
            // Note: We extract dialect from RTPS header vendor ID directly since FSM may not
            // have the dialect locked yet when we receive the first SEDP DATA(w).
            let dialect = fsm
                .get_locked_dialect()
                .or_else(|| extract_vendor_dialect(payload));
            if let Some(dialect) = dialect {
                let encoder = get_encoder(dialect);
                // Extract peer GUID prefix (first 12 bytes) and writer entity ID (last 4 bytes)
                let mut peer_guid_prefix = [0u8; 12];
                peer_guid_prefix.copy_from_slice(&writer_guid[..12]);
                let mut writer_entity_id = [0u8; 4];
                writer_entity_id.copy_from_slice(&writer_guid[12..16]);

                if let Some(confirmation_packet) = encoder.build_sedp_data_confirmation(
                    &our_guid_prefix,
                    &peer_guid_prefix,
                    &writer_entity_id,
                    seq,
                ) {
                    // RTPS 2.5 8.3.4 / 8.3.8.10: direct is byte-for-byte what
                    // this was before -- send straight to the reply address.
                    // Relayed has none: resolve the peer's metatraffic locator
                    // from the FSM by GUID prefix instead of the forwarder's
                    // address, and drop the confirmation if the peer is not yet
                    // known (never invent a destination for it).
                    let dest = origin
                        .reply()
                        .or_else(|| fsm.first_metatraffic_locator(&peer_guid_prefix));
                    match dest {
                        Some(dest) => {
                            log::debug!(
                            "[sedp] Sending SEDP DATA confirmation ACKNACK to {:?}, dialect={:?}",
                            dest,
                            dialect
                        );
                            if let Err(e) = transport.send_to_endpoint(&confirmation_packet, &dest)
                            {
                                log::debug!("[sedp] Failed to send confirmation ACKNACK: {}", e);
                            }
                        }
                        None => log::debug!(
                            "[sedp] relayed origin and peer {:02x?} unknown to the FSM: no \
                         reply address, dropping confirmation ACKNACK",
                            peer_guid_prefix
                        ),
                    }
                }
            }
        }
    };

    let admit = |endpoint: &GUID| {
        use crate::core::discovery::multicast::fsm::SedpChangeAdmission;
        match change.map(|(_, sn)| fsm.admit_sedp_change(channel, endpoint, sn)) {
            Some(SedpChangeAdmission::Stale) => {
                acknowledge();
                false
            }
            Some(SedpChangeAdmission::Refused) => false,
            Some(SedpChangeAdmission::Apply) | None => true,
        }
    };

    if let Some((_, endpoint, _)) = detect_sedp_endpoint_dispose(payload, cdr_offset) {
        let endpoint = GUID::from_bytes(endpoint);
        if channel == SedpChannel::Plain && fsm.ignores_plain_sedp_about(&endpoint) {
            return;
        }
        if !admit(&endpoint) {
            return;
        }
        acknowledge();
        apply_sedp_endpoint_dispose(payload, cdr_offset, &fsm, &registry, channel, None);
        return;
    }

    // Extract CDR payload using offset from classifier
    let cdr_payload = if cdr_offset < payload.len() {
        log::debug!("[sedp] Extracting CDR payload at offset {}", cdr_offset);
        // Debug: dump first bytes at offset
        if cdr_offset + 2 <= payload.len() {
            let first_bytes = [payload[cdr_offset], payload[cdr_offset + 1]];
            log::debug!(
                "[sedp] DEBUG: First 2 bytes at offset {}: 0x{:02x}{:02x}",
                cdr_offset,
                first_bytes[0],
                first_bytes[1]
            );
        }
        &payload[cdr_offset..]
    } else {
        log::debug!("[sedp] Invalid offset {}, using full payload", cdr_offset);
        payload
    };

    let peer_guid_prefix = extract_peer_guid_prefix(payload);
    // Pass the source vendorId (RTPS header bytes 6-7) so vendor-specific QoS
    // wire quirks (e.g. the Duration_t nanosecond handling of the `OpenDds`
    // dialect, vendor 0x0103) decode right.
    let vendor = if payload.len() >= 8 && &payload[0..4] == b"RTPS" {
        Some([payload[6], payload[7]])
    } else {
        None
    };
    match parse_sedp_with_vendor(cdr_payload, vendor) {
        Ok(mut sedp_data) => {
            // Before anything below registers from it: the topic mapping,
            // ownership and lifespan records, the writer gate.
            if channel == SedpChannel::Plain
                && (fsm.ignores_plain_sedp_about(&sedp_data.endpoint_guid)
                    || fsm.refuses_plain_announcement_of(
                        &sedp_data.endpoint_guid,
                        &sedp_data.topic_name,
                    ))
            {
                return;
            }
            // The builtin writer announces only its own participant's
            // endpoints (DDSI-RTPS v2.5 Sec.8.5.4.4).
            if payload.get(8..20) != Some(&sedp_data.endpoint_guid.prefix[..]) {
                return;
            }
            // Nor older than what was applied about that endpoint: a delayed
            // or replayed announcement brings back nothing its later dispose
            // removed (`DiscoveryFsm::admits_sedp_change`).
            if !admit(&sedp_data.endpoint_guid) {
                return;
            }
            #[cfg(feature = "security")]
            if channel == SedpChannel::Secure && !fsm.track_secure_endpoint(sedp_data.endpoint_guid)
            {
                return;
            }
            acknowledge();
            let endpoint_guid_bytes = sedp_data.endpoint_guid.as_bytes();
            let endpoint_kind = EndpointKind::from_guid(&sedp_data.endpoint_guid);

            log::debug!(
                "[callback] [OK] SEDP parsed (via classifier): topic={:?}, endpoint=GUID({:?}), kind={:?}",
                sedp_data.topic_name, sedp_data.endpoint_guid, endpoint_kind
            );

            // Register writer GUID -> topic mapping (interop fix)
            if matches!(endpoint_kind, EndpointKind::Writer) {
                log::debug!(
                    "[callback] [*] Writer endpoint detected! Registering writer GUID {:02x?} -> topic '{}'",
                    &endpoint_guid_bytes[..],
                    sedp_data.topic_name
                );
                registry.register_writer_guid(endpoint_guid_bytes, sedp_data.topic_name.clone());

                // A writer without PID_RELIABILITY is RELIABLE (DDS v1.4
                // Sec.2.2.3.14), but the raw parsed QoS has BestEffort (the
                // Rust struct default): the default is applied here, before
                // discovery records the announcement and judges each
                // (writer, local reader) pair on it
                // (`MatchNotificationRegistry::judge_remote_writer_qos`).
                if !sedp_data.has_explicit_reliability {
                    if let Some(ref mut qos) = sedp_data.qos {
                        if qos.reliability == crate::dds::qos::Reliability::BestEffort {
                            qos.reliability = crate::dds::qos::Reliability::Reliable;
                        }
                    }
                }
                // The OWNERSHIP kind the announcement implies (PID_OWNERSHIP,
                // else EXCLUSIVE when it carries PID_OWNERSHIP_STRENGTH, else
                // SHARED), recorded for the readers' OWNERSHIP gate.
                record_writer_qos(&registry, endpoint_guid_bytes, &sedp_data);
                record_writer_group_dialect(
                    &registry,
                    &fsm,
                    endpoint_guid_bytes,
                    sedp_data.group_entity_id,
                );
                record_writer_vendor(&registry, &fsm, endpoint_guid_bytes);
                if let Some(ref qos) = sedp_data.qos {
                    // Publish this writer's finite Lifespan so a local reader can
                    // tighten its effective lifespan on first data, before the
                    // async match-notification fires (startup catch-up race).
                    if !qos.lifespan.is_infinite() {
                        if let Ok(ns) = u64::try_from(qos.lifespan.duration.as_nanos()) {
                            registry.register_writer_lifespan_of(
                                &sedp_data.topic_name,
                                endpoint_guid_bytes,
                                ns,
                            );
                        }
                    }
                }

                // Re-announce our Reader endpoints for the same topic if the peer's
                // dialect requires it (`requires_sedp_reader_confirmation`; the `OpenDds`
                // dialect, vendor 0x0103, does): a DATA(r) under a NEW sequence number,
                // sent after the peer's DATA(w). A retransmission under the same number
                // would be dropped as a duplicate.
                let dialect = fsm
                    .get_locked_dialect()
                    .or_else(|| extract_vendor_dialect(payload));
                if let Some(dialect) = dialect {
                    let encoder = get_encoder(dialect);
                    if encoder.requires_sedp_reader_confirmation() {
                        // Extract peer's GUID prefix from RTPS header for INFO_DST
                        let peer_guid_prefix: Option<[u8; 12]> = if payload.len() >= 20 {
                            let mut prefix = [0u8; 12];
                            prefix.copy_from_slice(&payload[8..20]);
                            Some(prefix)
                        } else {
                            None
                        };

                        // RTPS 2.5 8.3.4 / 8.3.8.10: direct is byte-for-byte
                        // what this was before; relayed resolves the peer
                        // from the FSM by GUID prefix instead of aiming the
                        // re-announcement at the forwarder, and skips it
                        // entirely for a peer the FSM does not know.
                        let dest = origin.reply().or_else(|| {
                            peer_guid_prefix
                                .and_then(|prefix| fsm.first_metatraffic_locator(&prefix))
                        });
                        match dest {
                            Some(dest) => send_reader_reannouncement_for_topic(
                                &fsm,
                                &sedp_data.topic_name,
                                &sedp_cache,
                                &our_guid_prefix,
                                peer_guid_prefix.as_ref(),
                                &transport,
                                &dest,
                                dialect,
                                peer_guid_prefix
                                    .and_then(|prefix| fsm.type_object_pid_for(&prefix))
                                    .unwrap_or(TypeObjectPid::Withhold),
                            ),
                            None => log::debug!(
                                "[sedp] relayed origin and peer unknown to the FSM: no \
                                 reply address, not re-announcing readers for topic '{}'",
                                sedp_data.topic_name
                            ),
                        }
                    }
                }
            } else {
                log::debug!("[callback] >>  Reader endpoint - not registering writer mapping");
            }

            // The type to ask for, read before `handle_sedp` takes the
            // announcement: the request goes out after the endpoint is in the
            // registry, because a request the TypeLookup cache answers
            // resolves the endpoint at once, and an endpoint not registered
            // yet cannot be resolved (it stayed typeless for good).
            let type_to_request = (sedp_data.type_object.is_none()
                && endpoint_guid_bytes[..12] != our_guid_prefix)
                .then(|| {
                    (
                        sedp_data.type_name.clone(),
                        sedp_data.type_information.clone(),
                    )
                });

            let group_entity_id = sedp_data.group_entity_id;
            fsm.handle_sedp_on(sedp_data, channel);
            if matches!(endpoint_kind, EndpointKind::Writer) {
                settle_writer_decisions(&registry, &fsm, endpoint_guid_bytes, group_entity_id);
            }

            if let Some((type_name, type_information)) = type_to_request {
                maybe_request_type_object(&type_lookup, &type_name, origin, peer_guid_prefix);
                // OMG getTypes: the peer told us the TypeIdentifier in
                // PID_TYPE_INFORMATION but sent no TypeObject, so ask for
                // it. Complements the HTLK call above rather than racing
                // it -- HTLK is name-keyed and inert in interop mode,
                // getTypes is hash-keyed and cross-vendor.
                maybe_request_omg_type_object(
                    &type_lookup,
                    &type_name,
                    type_information.as_ref(),
                    origin,
                    peer_guid_prefix,
                );
            }

            // The writer's endpoint is now in the FSM registry, so per-writer
            // QoS is resolvable (resolve_writer_ownership & co read exactly
            // that registry). Kick subscribers that deferred samples while
            // this writer was unresolved (a data burst racing its own SEDP,
            // e.g. a TRANSIENT_LOCAL history push) so the held samples are
            // flushed or discarded NOW instead of waiting for the writer's
            // next live sample -- a one-shot durable burst may never send one.
            if matches!(endpoint_kind, EndpointKind::Writer) {
                let _ = registry.notify_writer_qos_resolved(endpoint_guid_bytes);
            }
        }
        Err(e) => {
            log::debug!("[callback] SEDP parse failed (via classifier): {:?}", e);
        }
    }
}

fn extract_peer_guid_prefix(packet: &[u8]) -> Option<[u8; 12]> {
    if packet.len() < 20 || &packet[0..4] != b"RTPS" {
        return None;
    }
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&packet[8..20]);
    Some(prefix)
}

/// Extract writer GUID and sequence number from RTPS DATA packet.
///
/// # Returns
/// Describe the SEDP DATA submessage whose serialized payload starts at
/// `cdr_offset`: its writer GUID (RTPS header prefix + writerEntityId) and
/// its writerSN.
///
/// **`cdr_offset` is not decoration.** The listener delivers EVERY DATA of a
/// datagram to the discovery callback, so this handler is called
/// once per announcement, each time with the WHOLE datagram and that
/// announcement's own payload offset. Ignoring the offset and re-walking to
/// the FIRST DATA would, for a datagram bundling several SEDP
/// announcements - which RTPS v2.5 Sec.8.3.3 allows -
/// have announcement 1 acknowledged as many times as there are
/// submessages and announcements 2..N never acknowledged at all.
///
/// It walks with `for_each_data_submessage`, the SAME walk that produced the
/// offset it is handed. That is the point: the producer and the consumer of
/// an offset disagreeing about where the submessages are IS the defect. It
/// also retires one of the private RTPS walks, and with it a body read
/// against the datagram rather than against its own submessage.
///
/// Falls back to the first DATA when no submessage claims `cdr_offset`, which
/// is what every caller got before, so an unexpected offset is no worse than
/// it was.
fn extract_data_writer_info(packet: &[u8], cdr_offset: usize) -> Option<([u8; 16], i64)> {
    // RTPS header (20) + DATA submessage header (4) + the 20 fixed octets
    // this reads.
    if packet.len() < 44 || &packet[0..4] != b"RTPS" {
        return None;
    }

    let mut guid_prefix = [0u8; 12];
    guid_prefix.copy_from_slice(&packet[8..20]);

    // A DATA that claims `cdr_offset` but is malformed answers None: handing
    // the caller a DIFFERENT announcement is the very defect this function
    // was rewritten to remove. Only "no DATA claims it" falls back.
    let (writer_entity_id, seq) =
        data_writer_and_seq(packet, data_submessage_at(packet, cdr_offset)?)?;
    let mut writer_guid = [0u8; 16];
    writer_guid[..12].copy_from_slice(&guid_prefix);
    writer_guid[12..16].copy_from_slice(&writer_entity_id);
    Some((writer_guid, seq))
}

/// The DATA submessage of `packet` that `cdr_offset` names (its serialized
/// payload starts there), as a submessage offset; the FIRST DATA when none
/// claims that offset, which is what every caller read before it could be
/// told which. One walk for every consumer that must answer for the DATA it
/// was handed: the announcement fields and the dispose detection.
pub(super) fn data_submessage_at(packet: &[u8], cdr_offset: usize) -> Option<usize> {
    let mut addressed = None;
    let mut first = None;
    for_each_data_submessage(packet, |data| {
        if first.is_none() {
            first = Some(data.offset);
        }
        if addressed.is_none() && data.payload_offset == cdr_offset {
            addressed = Some(data.offset);
        }
    });
    addressed.or(first)
}

/// writerEntityId and writerSN of the DATA submessage at `submsg_offset`.
///
/// Body layout (RTPS v2.5 Sec.8.3.8.2): extraFlags 2, octetsToInlineQos 2,
/// readerEntityId 4, writerEntityId 4, writerSN 8. Read against the
/// SUBMESSAGE, never against the datagram: a DATA that declares fewer octets
/// than it needs is refused here rather than served with the bytes of
/// whatever follows it.
pub(super) fn data_writer_and_seq(packet: &[u8], submsg_offset: usize) -> Option<([u8; 4], i64)> {
    let flags = *packet.get(submsg_offset + 1)?;
    let is_le = flags & 0x01 != 0;
    let octets_to_next = read_u16(packet, submsg_offset + 2, is_le) as usize;
    let body = submsg_offset + 4;
    // Sec.8.3.3.3: a zero octetsToNextHeader means this submessage runs to
    // the end of the message.
    let body_end = if octets_to_next == 0 {
        packet.len()
    } else {
        (body + octets_to_next).min(packet.len())
    };
    if body + 20 > body_end {
        return None;
    }

    // 4-octet EntityId, positional, no endianness conversion (Sec.9.3.2.1).
    let mut writer_entity_id = [0u8; 4];
    writer_entity_id.copy_from_slice(&packet[body + 8..body + 12]);

    // writerSN: SequenceNumber_t, both halves following this submessage's E
    // flag (Sec.9.4.5.3.1). The high half is a signed i32 (Sec.9.3.2.4), so
    // SEQUENCENUMBER_UNKNOWN = {-1, 0} stays a negative i64 for callers that
    // compare against the sentinel.
    let high = i32::from_ne_bytes(read_u32(packet, body + 12, is_le).to_ne_bytes());
    let low = read_u32(packet, body + 16, is_le);
    Some((writer_entity_id, ((high as i64) << 32) | (low as i64)))
}

/// Extract dialect from RTPS header vendor ID.
///
/// RTPS header format:
/// - bytes 0-4: "RTPS" magic
/// - bytes 4-6: protocol version (major, minor)
/// - bytes 6-8: vendor ID (e.g., 0x0103 = OpenDDS)
///
/// # Returns
/// Some(Dialect) if vendor ID maps to a known dialect, None otherwise.
fn extract_vendor_dialect(packet: &[u8]) -> Option<Dialect> {
    // Need at least 8 bytes for vendor ID
    if packet.len() < 8 || &packet[0..4] != b"RTPS" {
        return None;
    }

    let vendor_id = [packet[6], packet[7]];
    match vendor_id {
        [0x01, 0x03] => Some(Dialect::OpenDds),
        [0x01, 0x01] => Some(Dialect::Rti),
        [0x01, 0x0f] => Some(Dialect::FastDds),
        [0x01, 0x10] => Some(Dialect::CycloneDds),
        _ => None,
    }
}

/// Handle SEDP from reassembled fragments.
///
/// # Arguments
/// - `complete_payload`: Complete reassembled SEDP payload
/// - `fsm`: Discovery FSM for state updates
/// - `registry`: Topic registry for writer GUID -> topic mapping
pub(super) fn handle_sedp_from_fragments(
    complete_payload: &[u8],
    sn: u64,
    fsm: Arc<DiscoveryFsm>,
    registry: Arc<TopicRegistry>,
) {
    match parse_sedp(complete_payload) {
        Ok(sedp_data) => {
            // A reassembled announcement is a plain one: same refusals, same
            // place (`handle_sedp_packet`).
            if fsm.ignores_plain_sedp_about(&sedp_data.endpoint_guid)
                || fsm
                    .refuses_plain_announcement_of(&sedp_data.endpoint_guid, &sedp_data.topic_name)
            {
                return;
            }
            if !fsm.admits_sedp_change(
                SedpChannel::Plain,
                &sedp_data.endpoint_guid,
                i64::try_from(sn).unwrap_or(-1),
            ) {
                return;
            }
            let endpoint_guid_bytes = sedp_data.endpoint_guid.as_bytes();
            let endpoint_kind = EndpointKind::from_guid(&sedp_data.endpoint_guid);

            log::debug!(
                "[callback] [OK] SEDP parsed from reassembled fragments: topic={:?}, endpoint=GUID({:?}), kind={:?}",
                sedp_data.topic_name,
                sedp_data.endpoint_guid,
                endpoint_kind
            );

            // Register writer GUID -> topic mapping (interop fix)
            // Only register Writers (entity_id 0x02, 0x03, 0xC2, etc.)
            if matches!(endpoint_kind, EndpointKind::Writer) {
                log::debug!(
                    "[callback] [*] Writer endpoint detected! Registering writer GUID {:02x?} -> topic '{}'",
                    &endpoint_guid_bytes[..],
                    sedp_data.topic_name
                );
                registry.register_writer_guid(endpoint_guid_bytes, sedp_data.topic_name.clone());
                // Durable OWNERSHIP record for the reader-side gate and the
                // arbitration (same rationale as the classifier path).
                record_writer_qos(&registry, endpoint_guid_bytes, &sedp_data);
                record_writer_group_dialect(
                    &registry,
                    &fsm,
                    endpoint_guid_bytes,
                    sedp_data.group_entity_id,
                );
                record_writer_vendor(&registry, &fsm, endpoint_guid_bytes);
                // The writer's finite Lifespan, as the classifier path
                // records it: a reader expires this writer's samples by it.
                if let Some(ref qos) = sedp_data.qos {
                    if !qos.lifespan.is_infinite() {
                        if let Ok(ns) = u64::try_from(qos.lifespan.duration.as_nanos()) {
                            registry.register_writer_lifespan_of(
                                &sedp_data.topic_name,
                                endpoint_guid_bytes,
                                ns,
                            );
                        }
                    }
                }
            } else {
                log::debug!("[callback] >>  Reader endpoint - not registering writer mapping");
            }

            let group_entity_id = sedp_data.group_entity_id;
            fsm.handle_sedp(sedp_data);
            if matches!(endpoint_kind, EndpointKind::Writer) {
                settle_writer_decisions(&registry, &fsm, endpoint_guid_bytes, group_entity_id);
            }

            // Same as the classifier path: the writer is now resolvable in
            // the FSM registry, so kick subscribers holding samples deferred
            // for this writer (see notify_writer_qos_resolved).
            if matches!(endpoint_kind, EndpointKind::Writer) {
                let _ = registry.notify_writer_qos_resolved(endpoint_guid_bytes);
            }
        }
        Err(e) => {
            log::debug!(
                "[callback] SEDP parse failed on reassembled payload: {:?}",
                e
            );
        }
    }
}

/// Re-announce our Reader endpoints for a specific topic.
///
/// This is called when a Writer announcement arrives from a peer whose dialect
/// requires reader confirmation (the `OpenDds` dialect, vendor 0x0103), to send
/// our Reader endpoints under NEW sequence numbers: a DATA(r) under a number the
/// peer has already received is a duplicate to it, so a standard RTPS
/// retransmission does not serve.
///
/// Each re-announcement is a new change of the SEDP subscriptions writer
/// (`SedpHistory::reannounce`): the reader's previous announcement is
/// superseded and the new one takes the history's next number, so no number
/// is ever emitted twice. A number from the process-wide counter would be
/// one the history hands out again to the next reader or dispose, and the
/// peer would drop that one as a duplicate. The history stays
/// write-locked until the messages are sent, as `SedpRetirement::retire`
/// does: a dispose of the reader cannot take its number in between and go
/// out before the announcement it supersedes.
///
/// Each goes where any other change of the reader goes
/// (`DiscoveryFsm::sedp_for_peer`): on the secure SEDP topic for a reader
/// announced there, and as a GAP to a participant that is not to receive it.
///
/// # Arguments
/// - `fsm`: discovery, which decides where each change goes
/// - `topic_name`: Topic to find matching Reader endpoints for
/// - `sedp_cache`: SEDP history holding our endpoints
/// - `our_guid_prefix`: Our participant GUID prefix
/// - `peer_guid_prefix`: Peer's GUID prefix for INFO_DST (if dialect requires it)
/// - `transport`: UDP transport for sending packets
/// - `dest_addr`: Destination address (peer's metatraffic unicast)
/// - `dialect`: Encoding dialect to use
/// - `type_object`: whether the announcements carry PID_TYPE_OBJECT, the
///   class discovery decided for the peer (`DiscoveryFsm::type_object_pid_for`),
///   whether or not the message names it in an INFO_DST
#[allow(clippy::too_many_arguments)]
fn send_reader_reannouncement_for_topic(
    fsm: &DiscoveryFsm,
    topic_name: &str,
    sedp_cache: &super::super::entity_registry::SedpAnnouncementsCache,
    our_guid_prefix: &[u8; 12],
    peer_guid_prefix: Option<&[u8; 12]>,
    transport: &Arc<crate::transport::UdpTransport>,
    dest_addr: &std::net::SocketAddr,
    dialect: Dialect,
    type_object: TypeObjectPid,
) {
    let mut history = match sedp_cache.write() {
        Ok(guard) => guard,
        Err(e) => {
            log::debug!("[sedp] Failed to lock SEDP history: {}", e);
            return;
        }
    };

    // The Reader endpoints of this topic that exist, never the
    // announcement of a reader since deleted (RTPS v2.5 Sec.8.5.4.4).
    let readers: Vec<GUID> = history
        .alive()
        .filter(|(sd, kind)| {
            matches!(kind, SedpEndpointKind::Reader) && sd.topic_name == topic_name
        })
        .map(|(sd, _)| sd.endpoint_guid)
        .collect();

    if readers.is_empty() {
        log::debug!(
            "[sedp] No Reader endpoints found for topic '{}'",
            topic_name
        );
        return;
    }

    log::debug!(
        "[sedp] Found {} Reader endpoint(s) for topic '{}', re-announcing with new seq",
        readers.len(),
        topic_name
    );

    // Check if dialect requires INFO_DST for re-announcements
    let encoder = get_encoder(dialect);
    let destination_prefix = if encoder.requires_info_dst_for_reannouncement() {
        peer_guid_prefix
    } else {
        None
    };

    for reader in readers {
        let Some((new_seq, sd)) = history.reannounce(&reader, SedpEndpointKind::Reader) else {
            // The history is closed: the participant is saying farewell.
            return;
        };
        let first_seq = history.first_available(SedpEndpointKind::Reader);

        log::debug!(
            "[sedp] Re-announcing Reader endpoint for topic '{}' with new seq={}, info_dst={}",
            topic_name,
            new_seq,
            destination_prefix.is_some()
        );

        let security = history.security_at(SedpEndpointKind::Reader, new_seq);
        match build_sedp_rtps_packet_secured(
            &sd,
            SedpEndpointKind::Reader,
            our_guid_prefix,
            destination_prefix,
            new_seq,
            dialect,
            type_object,
            security,
        ) {
            Ok(packet) => {
                let discovery_protected =
                    security.map(|security| security.is_discovery_protected());
                let routed = match peer_guid_prefix {
                    Some(prefix) => fsm.sedp_for_peer(prefix, packet, discovery_protected),
                    // No participant to decide for: only what anybody may
                    // read goes out.
                    None if discovery_protected != Some(true) => Some(packet),
                    None => None,
                };
                let Some(mut packet) = routed.or_else(|| {
                    crate::core::discovery::multicast::sedp_gap(
                        SedpEndpointKind::Reader,
                        new_seq,
                        new_seq,
                        our_guid_prefix,
                    )
                    .ok()
                }) else {
                    continue;
                };
                // Append a HEARTBEAT to the DATA(r): it tells the peer which sequence
                // numbers are available, so that it answers with an ACKNACK (RTPS v2.5
                // Sec.8.3.8.6) and the reliable exchange completes.
                // This matches what spdp_handler.rs does for initial SEDP announcements.
                let (reader_id, writer_id) = sedp_entity_ids(SedpEndpointKind::Reader);
                let count = next_sedp_heartbeat_count();
                let hb = build_heartbeat_submessage_final(
                    &reader_id, &writer_id, first_seq, new_seq, count,
                );
                packet.extend_from_slice(&hb);

                if let Err(e) = transport.send_to_endpoint(&packet, dest_addr) {
                    log::debug!(
                        "[sedp] Failed to send Reader re-announcement to {}: {}",
                        dest_addr,
                        e
                    );
                } else {
                    log::debug!(
                        "[sedp] [OK] Sent Reader re-announcement to {} (seq={}, +HB count={})",
                        dest_addr,
                        new_seq,
                        count
                    );
                }
            }
            Err(e) => {
                log::debug!("[sedp] Failed to build SEDP packet: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEDP_PUBLICATIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x03, 0xC2];
    const SEDP_SUBSCRIPTIONS_WRITER: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];

    /// Appends one SEDP DATA submessage (id 0x15, little-endian, D flag set).
    /// Body per RTPS v2.5 Sec.8.3.8.2: extraFlags 2, octetsToInlineQos 2,
    /// readerEntityId 4, writerEntityId 4, writerSN 8, then the payload.
    /// The declared length is computed from the bytes actually written --
    /// four fixture builders in this repo have been caught over-declaring it.
    fn push_sedp_data(packet: &mut Vec<u8>, writer_id: [u8; 4], sn: u32, payload: &[u8]) {
        packet.push(0x15);
        packet.push(0x05); // E (little-endian) + D (serialized payload present)
        let declared = packet.len();
        packet.extend_from_slice(&0u16.to_le_bytes()); // placeholder
        let body_start = packet.len();
        packet.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        packet.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        packet.extend_from_slice(&[0x00, 0x00, 0x03, 0xC7]); // readerEntityId
        packet.extend_from_slice(&writer_id);
        packet.extend_from_slice(&0i32.to_le_bytes()); // writerSN.high
        packet.extend_from_slice(&sn.to_le_bytes()); // writerSN.low
        packet.extend_from_slice(payload);
        // Sec.9.4.1: submessage headers are aligned on 4 octets, so a
        // writer pads its body up to the next boundary. Without this the
        // shared walk realigns past the start of whatever follows and reads
        // two octets into it.
        while !(packet.len() - body_start).is_multiple_of(4) {
            packet.push(0x00);
        }
        let body = packet.len() - body_start;
        assert!(
            body.is_multiple_of(4),
            "a padded DATA body is a whole number of words"
        );
        assert!(
            body >= 20 + payload.len(),
            "a DATA body is 20 fixed octets plus its serialized payload, padded"
        );
        packet[declared..declared + 2].copy_from_slice(
            &u16::try_from(body)
                .expect("the fixture's DATA body fits octetsToNextHeader")
                .to_le_bytes(),
        );
    }

    const PREFIX: [u8; 12] = [0x0A; 12];

    /// One datagram bundling the two SEDP announcements, as RTPS v2.5
    /// Sec.8.3.3 allows.
    fn two_announcements() -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&[0x02, 0x04, 0x01, 0x1a]);
        p.extend_from_slice(&PREFIX);
        push_sedp_data(
            &mut p,
            SEDP_PUBLICATIONS_WRITER,
            1,
            &[0x00, 0x03, 0x00, 0x00, 0xAA, 0xBB],
        );
        push_sedp_data(
            &mut p,
            SEDP_SUBSCRIPTIONS_WRITER,
            2,
            &[0x00, 0x03, 0x00, 0x00, 0x11, 0x22],
        );
        p
    }

    fn guid_of(writer: [u8; 4]) -> [u8; 16] {
        let mut g = [0u8; 16];
        g[..12].copy_from_slice(&PREFIX);
        g[12..16].copy_from_slice(&writer);
        g
    }

    /// Each delivered announcement is described by ITS OWN submessage.
    ///
    /// The offsets are not written by hand: they come from
    /// `for_each_data_submessage`, the very walk the listener uses to decide
    /// what to deliver and at which offset. A test that invented its own
    /// offsets would prove nothing about the pair that has to agree.
    ///
    /// Answering (publications writer, seq 1) for BOTH offsets would notify
    /// the reader proxy registry twice about announcement 1 and send the
    /// confirmation ACKNACK twice for it, while announcement 2 would never be
    /// acknowledged -- and a peer that waits for that acknowledgment
    /// retransmits it forever.
    #[test]
    fn each_delivered_announcement_is_described_by_its_own_submessage() {
        let packet = two_announcements();

        let mut delivered = Vec::new();
        for_each_data_submessage(&packet, |data| delivered.push(data.payload_offset));
        assert_eq!(
            delivered.len(),
            2,
            "the fixture must carry two announcements the listener would deliver"
        );

        let answers: Vec<_> = delivered
            .iter()
            .map(|off| extract_data_writer_info(&packet, *off).expect("each DATA describes itself"))
            .collect();
        assert_eq!(
            answers,
            vec![
                (guid_of(SEDP_PUBLICATIONS_WRITER), 1i64),
                (guid_of(SEDP_SUBSCRIPTIONS_WRITER), 2i64),
            ],
            "each delivery names its own writer and its own sequence number"
        );
    }

    /// An offset no submessage claims falls back to the first DATA, which is
    /// what every caller got before the offset was honoured at all.
    #[test]
    fn an_unclaimed_offset_falls_back_to_the_first_announcement() {
        let packet = two_announcements();
        assert_eq!(
            extract_data_writer_info(&packet, 9999),
            Some((guid_of(SEDP_PUBLICATIONS_WRITER), 1)),
            "an offset naming no submessage is no worse off than before"
        );
    }

    /// A DATA that declares fewer octets than its own fixed fields need is
    /// refused rather than served with the bytes of whatever follows it
    /// (RTPS v2.5 Sec.8.3.3: submessages are independently valid, and a body
    /// is read against its submessage, not against the datagram).
    #[test]
    fn a_data_shorter_than_its_fixed_fields_describes_nothing() {
        let mut p = Vec::new();
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&[0x02, 0x04, 0x01, 0x1a]);
        p.extend_from_slice(&PREFIX);
        // Declares 16 octets where the fixed fields alone are 20.
        p.push(0x15);
        p.push(0x05);
        p.extend_from_slice(&16u16.to_le_bytes());
        let short_at = p.len();
        p.extend_from_slice(&[0xEE; 16]);
        assert_eq!(
            p.len() - short_at,
            16,
            "the short DATA carries what it declares"
        );
        push_sedp_data(
            &mut p,
            SEDP_SUBSCRIPTIONS_WRITER,
            2,
            &[0x00, 0x03, 0x00, 0x00, 0x11, 0x22],
        );

        // The walk refuses a DATA declaring 16 octets - its fixed fields
        // need 20 - so it never reaches here through that door and only the
        // conforming announcement is delivered.
        let mut delivered = Vec::new();
        for_each_data_submessage(&p, |data| delivered.push(data.payload_offset));
        assert_eq!(
            delivered.len(),
            1,
            "the walk no longer admits a DATA declaring 16 octets"
        );
        assert_eq!(
            extract_data_writer_info(&p, delivered[0]),
            Some((guid_of(SEDP_SUBSCRIPTIONS_WRITER), 2)),
            "and the conforming announcement behind it is still described"
        );

        // The guard this test exists for is `data_writer_and_seq`'s, and the
        // walk moving in front of it is exactly how a proof goes vacuous:
        // asked through `delivered`, it would be asked about the announcement
        // instead. So it is asked at its own door, on the short DATA's own
        // submessage - which is where any caller that is not this walk would
        // reach it.
        assert_eq!(
            data_writer_and_seq(&p, short_at - 4),
            None,
            "a DATA declaring fewer octets than its fixed fields describes nothing; \
             bounding against the datagram instead would serve it the next \
             submessage's header as a writerEntityId"
        );
    }

    // ---- Endpoint dispose: a deleted remote endpoint leaves the match ----

    const REMOTE_PREFIX: [u8; 12] = [0x5A; 12];
    const TOPIC: &str = "Square";
    const TYPE_NAME: &str = "ShapeType";
    static SHAPE_DESC: crate::core::types::TypeDescriptor =
        crate::core::types::TypeDescriptor::new(0, TYPE_NAME, 8, 4, false, &[]);

    /// A (total, total_change, current, current_change, remote) match event.
    type MatchEvent = (u32, i32, u32, i32, Option<GUID>);
    type EventLog = Arc<std::sync::Mutex<Vec<MatchEvent>>>;

    fn remote(entity_id: [u8; 4]) -> GUID {
        GUID::new(REMOTE_PREFIX, entity_id)
    }

    /// One datagram carrying the dispose/unregister of `endpoint`'s instance
    /// of the SEDP built-in topic written by `sedp_writer`: DATA with E+Q,
    /// D=0, K=0, inline QoS PID_KEY_HASH(endpoint GUID) + PID_STATUS_INFO,
    /// no payload: the K=0 form of an endpoint dispose.
    fn endpoint_dispose(sedp_writer: [u8; 4], endpoint: GUID, status: u8) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&[0x02, 0x04, 0x01, 0x01]);
        p.extend_from_slice(&REMOTE_PREFIX);
        let data_at = p.len();
        p.push(0x15);
        p.push(0x03); // E (little-endian) + Q (inline QoS); D and K clear
        let declared = p.len();
        p.extend_from_slice(&0u16.to_le_bytes()); // placeholder
        let body_start = p.len();
        p.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        p.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        let mut sedp_reader = sedp_writer;
        sedp_reader[3] = 0xC7;
        p.extend_from_slice(&sedp_reader);
        p.extend_from_slice(&sedp_writer);
        p.extend_from_slice(&0i32.to_le_bytes()); // writerSN.high
        p.extend_from_slice(&7u32.to_le_bytes()); // writerSN.low
        let qos_start = p.len();
        p.extend_from_slice(&0x0070u16.to_le_bytes()); // PID_KEY_HASH
        p.extend_from_slice(&16u16.to_le_bytes());
        p.extend_from_slice(&endpoint.as_bytes());
        p.extend_from_slice(&0x0071u16.to_le_bytes()); // PID_STATUS_INFO
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, status]); // flags in octet 3
        p.extend_from_slice(&0x0001u16.to_le_bytes()); // PID_SENTINEL
        p.extend_from_slice(&0u16.to_le_bytes());
        let body = p.len() - body_start;
        p[declared..declared + 2].copy_from_slice(
            &u16::try_from(body)
                .expect("the fixture's DATA body fits octetsToNextHeader")
                .to_le_bytes(),
        );

        // The fixture's own wire invariants, so a malformed fixture cannot
        // pass by being skipped or misread.
        assert!(
            body.is_multiple_of(4),
            "a DATA body is a whole number of words (RTPS 2.5 9.4.1)"
        );
        assert_eq!(
            body,
            20 + (p.len() - qos_start),
            "the body is the 20 fixed octets plus the inline QoS, no payload"
        );
        assert_eq!(
            declared + 2 + body,
            p.len(),
            "the declared length reaches exactly the end of the datagram"
        );
        let mut walked = Vec::new();
        for_each_data_submessage(&p, |data| walked.push(data.offset));
        assert_eq!(
            walked,
            vec![data_at],
            "the walk admits the dispose as the one DATA of the datagram"
        );
        let (inline_qos, is_le) =
            crate::protocol::builder::extract_inline_qos(&p).expect("the inline QoS is found");
        assert!(is_le, "the E flag reads back little-endian");
        assert_eq!(
            inline_qos,
            &p[qos_start..],
            "the parameter list read back is the whole list, sentinel included"
        );
        p
    }

    /// Two endpoint disposes in ONE datagram: the handler runs once per
    /// DATA, and each call must answer for the DATA it is handed. The
    /// detection must not read the first DATA every time (the second
    /// endpoint's dispose would never be seen, the first one seen twice).
    #[test]
    fn each_dispose_of_a_datagram_is_read_from_its_own_data() {
        let first = remote([0x00, 0x00, 0x01, 0x04]);
        let second = remote([0x00, 0x00, 0x02, 0x04]);
        let mut p = endpoint_dispose(SEDP_SUBSCRIPTIONS_WRITER, first, 0x03);
        let tail = endpoint_dispose(SEDP_SUBSCRIPTIONS_WRITER, second, 0x03);
        p.extend_from_slice(&tail[20..]);
        let mut payloads = Vec::new();
        for_each_data_submessage(&p, |data| payloads.push(data.payload_offset));
        assert_eq!(payloads.len(), 2, "fixture: the walk sees two DATA");
        let endpoint_at =
            |offset| detect_sedp_endpoint_dispose(&p, offset).map(|(_, guid, _)| guid);
        assert_eq!(endpoint_at(payloads[0]), Some(first.as_bytes()));
        assert_eq!(endpoint_at(payloads[1]), Some(second.as_bytes()));
    }

    fn remote_participant() -> crate::protocol::discovery::SpdpData {
        crate::protocol::discovery::SpdpData {
            participant_guid: remote(crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT),
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
        }
    }

    fn announcement(endpoint: GUID) -> crate::protocol::discovery::SedpData {
        crate::protocol::discovery::SedpData {
            topic_name: TOPIC.to_string(),
            type_name: TYPE_NAME.to_string(),
            participant_guid: remote(crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT),
            endpoint_guid: endpoint,
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// A discovery FSM past its startup probation, with the match registry
    /// listening and the remote participant confirmed alive, so an SEDP
    /// announcement matches through the real `handle_sedp` path rather than
    /// through a hand-made call.
    fn live_discovery() -> (
        Arc<DiscoveryFsm>,
        Arc<crate::dds::match_notification::MatchNotificationRegistry>,
    ) {
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        let reg =
            Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0; 12]));
        fsm.register_listener(reg.clone());
        // The FSM's startup probation is 250 ms of uptime, and a refresh
        // counts toward confirmation only 100 ms after the participant's
        // entry was created. Both are asserted below, not assumed.
        std::thread::sleep(std::time::Duration::from_millis(300));
        fsm.handle_spdp(remote_participant());
        std::thread::sleep(std::time::Duration::from_millis(150));
        fsm.handle_spdp(remote_participant());
        assert!(fsm.is_probation_done(), "the probation window is over");
        assert!(
            fsm.is_participant_confirmed(&REMOTE_PREFIX),
            "two SPDP announcements confirm the remote participant"
        );
        (fsm, reg)
    }

    /// A match callback that appends every event it receives to `events`.
    fn recorder(
        events: &EventLog,
    ) -> impl Fn(u32, i32, u32, i32, Option<GUID>) + Send + Sync + 'static {
        let captured = Arc::clone(events);
        move |total, total_change, current, current_change, guid| {
            captured.lock().unwrap_or_else(|e| e.into_inner()).push((
                total,
                total_change,
                current,
                current_change,
                guid,
            ));
        }
    }

    fn unmatch_events(events: &std::sync::Mutex<Vec<MatchEvent>>) -> Vec<MatchEvent> {
        events
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|event| event.3 < 0)
            .copied()
            .collect()
    }

    /// A remote DataReader deleted while its participant lives on publishes
    /// a dispose of its DCPSSubscription instance. The local writer's
    /// `publication_matched.current_count` must go down, once.
    ///
    /// A DCPSSubscription dispose must be read: an endpoint must not leave
    /// the match only with its whole participant, or the count would stay at
    /// 1 for as long as the remote participant lives.
    #[test]
    fn a_remote_reader_endpoint_dispose_unmatches_the_local_writer() {
        let (fsm, reg) = live_discovery();
        let events = EventLog::default();
        let callback = recorder(&events);
        let token = reg.register_writer(
            TOPIC.to_string(),
            crate::dds::qos::QoS::best_effort(),
            &SHAPE_DESC,
            callback,
        );
        let reader = remote([0x00, 0x00, 0x01, 0x04]);
        fsm.handle_sedp(announcement(reader));
        assert_eq!(
            token.current_match_count(),
            1,
            "the remote reader matched through discovery"
        );

        let dispose = endpoint_dispose(SEDP_SUBSCRIPTIONS_WRITER, reader, 0x03);
        let topics = TopicRegistry::new();
        assert!(apply_sedp_endpoint_dispose(
            &dispose,
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None
        ));
        // A retransmission of the same dispose, or the handler being called
        // again for the same datagram, must not unmatch twice.
        assert!(apply_sedp_endpoint_dispose(
            &dispose,
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None
        ));

        assert_eq!(
            token.current_match_count(),
            0,
            "the deleted reader is no longer matched"
        );
        assert_eq!(
            unmatch_events(&events),
            vec![(1, 0, 0, -1, Some(reader))],
            "the unmatch callback fires exactly once, for that reader"
        );
        assert!(
            fsm.find_readers_for_topic(TOPIC).is_empty(),
            "the reader left the discovery database"
        );
        assert_eq!(fsm.get_participants().len(), 1, "its participant stays");
    }

    /// Same rule on the reader side: a remote DataWriter's DCPSPublication
    /// dispose makes the local reader's `subscription_matched.current_count`
    /// go down, once, in addition to the user-instance NOT_ALIVE_NO_WRITERS
    /// transition that path already drove.
    #[test]
    fn a_remote_writer_endpoint_dispose_unmatches_the_local_reader() {
        let (fsm, reg) = live_discovery();
        let events = EventLog::default();
        let callback = recorder(&events);
        let token = reg.register_reader_with_lifespan(
            TOPIC.to_string(),
            crate::dds::qos::QoS::best_effort(),
            &SHAPE_DESC,
            None,
            callback,
            None,
            None,
            None,
            Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            crate::transport::shm::ShmPolicy::default(),
        );
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        fsm.handle_sedp(announcement(writer));
        assert_eq!(
            token.current_match_count(),
            1,
            "the remote writer matched through discovery"
        );

        let dispose = endpoint_dispose(SEDP_PUBLICATIONS_WRITER, writer, 0x02);
        let topics = TopicRegistry::new();
        assert!(apply_sedp_endpoint_dispose(
            &dispose,
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None
        ));
        assert!(apply_sedp_endpoint_dispose(
            &dispose,
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None
        ));

        assert_eq!(
            token.current_match_count(),
            0,
            "the deleted writer is no longer matched"
        );
        assert_eq!(
            unmatch_events(&events),
            vec![(1, 0, 0, -1, Some(writer))],
            "the unmatch callback fires exactly once, for that writer"
        );
        assert!(
            fsm.find_writers_for_topic(TOPIC).is_empty(),
            "the writer left the discovery database"
        );
    }

    /// A writer's SEDP dispose, and its participant's announced departure,
    /// reach the reader as a deletion; a participant removed without a word
    /// does not.
    #[test]
    fn an_announced_departure_reaches_the_reader_as_a_deletion() {
        use crate::engine::{DisposeKind, Subscriber, WriterDeparture};
        struct Causes(std::sync::Mutex<Vec<WriterDeparture>>);
        impl Subscriber for Causes {
            fn on_data(&self, _topic: &str, _seq: u64, _data: &[u8]) {}
            fn on_writer_departure(
                &self,
                _topic: &str,
                _writer_guid: [u8; 16],
                _kind: DisposeKind,
                cause: WriterDeparture,
            ) {
                self.0.lock().unwrap_or_else(|e| e.into_inner()).push(cause);
            }
            fn topic_name(&self) -> &str {
                TOPIC
            }
        }
        let (fsm, _reg) = live_discovery();
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        fsm.handle_sedp(announcement(writer));
        let topics = Arc::new(TopicRegistry::new());
        let causes = Arc::new(Causes(std::sync::Mutex::new(Vec::new())));
        topics
            .register_subscriber(causes.clone())
            .expect("register subscriber");
        topics.register_writer_guid(writer.as_bytes(), TOPIC.to_string());
        assert!(apply_sedp_endpoint_dispose(
            &endpoint_dispose(SEDP_PUBLICATIONS_WRITER, writer, 0x02),
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None
        ));
        let departures = WriterDepartures::new(&topics);
        use crate::core::discovery::multicast::DiscoveryListener;
        let participant = GUID::new(
            writer.prefix,
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        );
        departures.on_participant_left(participant, true);
        departures.on_participant_left(participant, false);
        assert_eq!(
            causes.0.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            vec![
                WriterDeparture::Deleted,
                WriterDeparture::Deleted,
                WriterDeparture::Unheard
            ]
        );
    }

    /// A dispose naming an endpoint discovery never saw changes nothing -
    /// not even for a sibling endpoint of the same participant - and an
    /// endpoint that was removed and then announced again matches again.
    #[test]
    fn an_unknown_endpoint_dispose_is_a_no_op_and_a_reannounced_endpoint_matches_again() {
        let (fsm, reg) = live_discovery();
        let events = EventLog::default();
        let callback = recorder(&events);
        let token = reg.register_writer(
            TOPIC.to_string(),
            crate::dds::qos::QoS::best_effort(),
            &SHAPE_DESC,
            callback,
        );
        let reader = remote([0x00, 0x00, 0x01, 0x04]);
        fsm.handle_sedp(announcement(reader));
        assert_eq!(token.current_match_count(), 1);
        let generation = fsm.topic_registry_generation();

        // Same participant, an entity id nobody announced.
        let stranger = remote([0x00, 0x00, 0x02, 0x04]);
        let topics = TopicRegistry::new();
        assert!(apply_sedp_endpoint_dispose(
            &endpoint_dispose(SEDP_SUBSCRIPTIONS_WRITER, stranger, 0x03),
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None,
        ));
        assert_eq!(
            token.current_match_count(),
            1,
            "an unknown endpoint's dispose leaves the match alone"
        );
        assert!(unmatch_events(&events).is_empty(), "and fires no callback");
        assert_eq!(
            fsm.find_readers_for_topic(TOPIC).len(),
            1,
            "and removes nothing from discovery"
        );
        assert_eq!(
            fsm.topic_registry_generation(),
            generation,
            "and invalidates no cache"
        );

        assert!(apply_sedp_endpoint_dispose(
            &endpoint_dispose(SEDP_SUBSCRIPTIONS_WRITER, reader, 0x03),
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None,
        ));
        assert_eq!(token.current_match_count(), 0);

        fsm.handle_sedp(announcement(reader));
        assert_eq!(
            token.current_match_count(),
            1,
            "the same GUID announced again is matched again"
        );
        assert_eq!(
            fsm.find_readers_for_topic(TOPIC).len(),
            1,
            "and is back in discovery"
        );
    }

    #[cfg(feature = "security")]
    #[test]
    fn a_secure_endpoint_dispose_releases_its_secure_membership() {
        use crate::security::access::{DiscoveryGovernance, DomainRule, ProtectionKind};
        let machine = crate::security::test_pki::local_machine_with_completed_peer(
            crate::security::test_pki::bound_test_prefix([0x11; 6]),
            crate::security::test_pki::bound_test_prefix([0x21; 6]),
            None,
        );
        let our_prefix = crate::security::test_pki::bound_test_prefix([0x11; 6]);
        let peer_prefix = crate::security::test_pki::bound_test_prefix([0x21; 6]);
        let mut fsm = DiscoveryFsm::new(GUID::new(our_prefix, [0, 0, 1, 0xc1]), 30_000);
        fsm.set_handshake_machine(
            machine,
            crate::security::test_pki::TEST_IDENTITY_CERT_PEM.to_vec(),
            crate::security::test_pki::TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: false,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![],
        })));
        let endpoint = GUID::new(peer_prefix, [0, 0, 0x12, 2]);
        let topics = TopicRegistry::new();
        for status in [1, 2, 3] {
            assert!(fsm.track_secure_endpoint(endpoint));
            assert!(fsm.ignores_plain_sedp_about(&endpoint));
            let mut packet = endpoint_dispose(SEDP_PUBLICATIONS_WRITER, endpoint, status);
            packet[8..20].copy_from_slice(&peer_prefix);
            assert!(apply_sedp_endpoint_dispose(
                &packet,
                0,
                &fsm,
                &topics,
                SedpChannel::Secure,
                Some(7)
            ));
            assert!(
                !fsm.is_secure_endpoint_member(&endpoint),
                "status={status}: the live membership is released"
            );
            assert!(
                fsm.ignores_plain_sedp_about(&endpoint),
                "status={status}: its tombstone still refuses a plain change"
            );
        }
    }

    #[test]
    fn a_stale_sedp_change_is_acknowledged_without_recreating_its_endpoint() {
        let h = Harness::new();
        let prefix = super::super::wire_fixtures::SENDER_PREFIX;
        let endpoint = GUID::new(prefix, [0, 0, 0x12, 2]);
        assert!(h
            .dispatch
            .fsm
            .admits_sedp_change(SedpChannel::Plain, &endpoint, 2));
        let mut packet = b"RTPS\x02\x05\x01\x12".to_vec();
        packet.extend_from_slice(&prefix);
        push_sedp_data(
            &mut packet,
            SEDP_PUBLICATIONS_WRITER,
            1,
            &publication_with(endpoint, &[]),
        );
        h.feed(PacketKind::SEDP, &packet, 44, None);
        let writer = GUID::new(prefix, SEDP_PUBLICATIONS_WRITER).as_bytes();
        assert!(h.dispatch.sedp_reader_registry.get_proxy(&writer).is_some());
        assert!(h
            .dispatch
            .registry
            .get_topic_by_guid(&endpoint.as_bytes())
            .is_none());
        assert_eq!(
            h.dispatch
                .fsm
                .metrics
                .sedp_tracking_refused
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn an_sedp_announcement_of_another_participants_endpoint_is_not_recorded() {
        let h = Harness::new();
        let prefix = super::super::wire_fixtures::SENDER_PREFIX;
        let endpoint = GUID::new([0xee; 12], [0, 0, 0x12, 2]);
        let mut packet = b"RTPS\x02\x05\x01\x12".to_vec();
        packet.extend_from_slice(&prefix);
        push_sedp_data(
            &mut packet,
            SEDP_PUBLICATIONS_WRITER,
            7,
            &publication_with(endpoint, &[]),
        );
        h.feed(PacketKind::SEDP, &packet, 44, None);
        let writer = GUID::new(prefix, SEDP_PUBLICATIONS_WRITER).as_bytes();
        assert!(h.dispatch.sedp_reader_registry.get_proxy(&writer).is_none());
        assert!(h
            .dispatch
            .registry
            .get_topic_by_guid(&endpoint.as_bytes())
            .is_none());
        assert!(
            h.dispatch
                .fsm
                .admits_sedp_change(SedpChannel::Plain, &endpoint, 1),
            "the foreign endpoint was not tracked at 7"
        );
    }

    #[test]
    fn a_sedp_tracking_refusal_is_not_acknowledged_or_registered() {
        let h = Harness::new();
        let prefix = super::super::wire_fixtures::SENDER_PREFIX;
        let mut refused = None;
        for n in 0u32..u16::MAX.into() {
            let n_bytes = n.to_be_bytes();
            let endpoint = GUID::new(prefix, [n_bytes[1], n_bytes[2], n_bytes[3], 2]);
            if !h
                .dispatch
                .fsm
                .admits_sedp_change(SedpChannel::Plain, &endpoint, 1)
            {
                refused = Some(endpoint);
                break;
            }
        }
        let endpoint = refused.expect("the tracking table must have a finite bound");
        let before = h
            .dispatch
            .fsm
            .metrics
            .sedp_tracking_refused
            .load(std::sync::atomic::Ordering::Relaxed);
        let mut packet = b"RTPS\x02\x05\x01\x12".to_vec();
        packet.extend_from_slice(&prefix);
        push_sedp_data(
            &mut packet,
            SEDP_PUBLICATIONS_WRITER,
            1,
            &publication_with(endpoint, &[]),
        );
        h.feed(PacketKind::SEDP, &packet, 44, None);
        let writer = GUID::new(prefix, SEDP_PUBLICATIONS_WRITER).as_bytes();
        assert!(h.dispatch.sedp_reader_registry.get_proxy(&writer).is_none());
        assert!(h
            .dispatch
            .registry
            .get_topic_by_guid(&endpoint.as_bytes())
            .is_none());
        assert_eq!(
            h.dispatch
                .fsm
                .metrics
                .sedp_tracking_refused
                .load(std::sync::atomic::Ordering::Relaxed),
            before + 1
        );
    }

    // ------------------------------------------------------------------
    // RTPS 2.5 8.3.4 / 8.3.8.10: a relayed origin (behind an INFO_SRC) has
    // no reply locator, and neither the confirmation ACKNACK nor the
    // reader re-announcement may be aimed at the forwarder that only
    // relayed the SEDP DATA.
    // ------------------------------------------------------------------

    use super::super::wire_fixtures::Harness;
    use crate::core::discovery::multicast::PacketKind;
    use crate::protocol::discovery::SedpData;

    /// A minimal, parseable `SedpData` for `topic`, named `participant`'s
    /// `endpoint` -- everything else is the type's own zero value.
    fn minimal_sedp_data(topic: &str, participant: GUID, endpoint: GUID) -> SedpData {
        SedpData {
            topic_name: topic.to_string(),
            type_name: "Y11bType".to_string(),
            participant_guid: participant,
            endpoint_guid: endpoint,
            qos_hash: 0,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            type_information: None,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        }
    }

    /// An OpenDDS-dialect SEDP DATA(w) datagram, as if `peer_prefix`'s
    /// participant sent it: `build_sedp_rtps_packet` writes OUR OWN vendor
    /// id in the RTPS header (it is always the SENDER's own stamp, whoever
    /// the encoding targets), so the two vendor-id octets are patched to
    /// 0x0103, the vendor id the `OpenDds` dialect handles, afterward -- the
    /// octets `extract_vendor_dialect` reads.
    fn opendds_sedp_writer_datagram(peer_prefix: [u8; 12], topic: &str, seq: u64) -> Vec<u8> {
        let participant = GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let endpoint = GUID::new(peer_prefix, [0x00, 0x00, 0x01, 0x02]); // WRITER_WITH_KEY
        let data = minimal_sedp_data(topic, participant, endpoint);
        let mut packet = crate::core::discovery::multicast::build_sedp_rtps_packet(
            &data,
            SedpEndpointKind::Writer,
            &peer_prefix,
            None,
            seq,
            Dialect::OpenDds,
        )
        .expect("a minimal writer announcement must encode");
        packet[6..8].copy_from_slice(&[0x01, 0x03]);
        packet
    }

    /// A DATA(r) announcement for `topic`, to seed the SEDP cache so
    /// `send_reader_reannouncement_for_topic` (E2) finds a Reader to
    /// re-announce. Never put on the wire; only ever read back out of the
    /// cache.
    fn reader_announcement(our_prefix: [u8; 12], topic: &str) -> SedpData {
        let participant = GUID::new(our_prefix, [0x00, 0x00, 0x01, 0xC1]);
        let endpoint = GUID::new(our_prefix, [0x00, 0x00, 0x01, 0x04]); // READER_WITH_KEY
        minimal_sedp_data(topic, participant, endpoint)
    }

    /// The payload offset of the one DATA submessage a fixture built above
    /// carries -- read by the same walk the listener itself uses, never
    /// invented.
    fn one_data_offset(packet: &[u8]) -> usize {
        let mut offset = None;
        for_each_data_submessage(packet, |data| offset = Some(data.payload_offset));
        offset.expect("fixture carries exactly one DATA submessage")
    }

    /// E1: the confirmation ACKNACK. Relayed and unknown to the FSM:
    /// nothing reaches the forwarder.
    #[test]
    fn a_relayed_sedp_confirmation_never_reaches_the_forwarder() {
        const PEER: [u8; 12] = [0x0B; 12];
        let packet = opendds_sedp_writer_datagram(PEER, "Y11bE1Unknown", 1);
        let offset = one_data_offset(&packet);

        let forwarder = std::net::UdpSocket::bind("127.0.0.1:0").expect("forwarder socket");
        forwarder
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("set timeout");
        let forwarder_addr = forwarder.local_addr().expect("forwarder address");

        let h = Harness::new();
        h.feed_relayed_from(PacketKind::SEDP, &packet, offset, None, forwarder_addr);

        let mut buf = [0u8; 512];
        assert!(
            forwarder.recv_from(&mut buf).is_err(),
            "peer unknown to the FSM: no confirmation ACKNACK may reach the forwarder"
        );
    }

    /// E1, the other half: relayed but the peer IS known to the FSM (from
    /// SPDP) -- the confirmation reaches its recorded metatraffic locator,
    /// never the forwarder.
    #[test]
    fn a_relayed_sedp_confirmation_from_a_known_peer_reaches_its_fsm_address() {
        const PEER: [u8; 12] = [0x0C; 12];
        let packet = opendds_sedp_writer_datagram(PEER, "Y11bE1Known", 1);
        let offset = one_data_offset(&packet);

        let peer_metatraffic = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
        peer_metatraffic
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set timeout");
        let peer_addr = peer_metatraffic.local_addr().expect("peer address");
        let forwarder: std::net::SocketAddr = "203.0.113.7:9999".parse().expect("valid address");

        let h = Harness::new();
        h.dispatch
            .fsm
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(PEER, [0x00, 0x00, 0x01, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![peer_addr],
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

        h.feed_relayed_from(PacketKind::SEDP, &packet, offset, None, forwarder);

        let mut buf = [0u8; 512];
        let (len, _from) = peer_metatraffic
            .recv_from(&mut buf)
            .expect("the confirmation ACKNACK reaches the peer's recorded FSM address");
        assert!(len > 0);
    }

    /// E2: the reader re-announcement. Relayed and unknown to the FSM:
    /// nothing reaches the forwarder, even with a matching Reader in the
    /// SEDP cache.
    #[test]
    fn a_relayed_reader_reannouncement_never_reaches_the_forwarder() {
        const PEER: [u8; 12] = [0x0D; 12];
        const OURS: [u8; 12] = [0x11; 12];
        const TOPIC: &str = "Y11bE2Unknown";
        let packet = opendds_sedp_writer_datagram(PEER, TOPIC, 1);
        let offset = one_data_offset(&packet);

        let forwarder = std::net::UdpSocket::bind("127.0.0.1:0").expect("forwarder socket");
        forwarder
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("set timeout");
        let forwarder_addr = forwarder.local_addr().expect("forwarder address");

        let h = Harness::new();
        h.dispatch
            .sedp_cache
            .write()
            .expect("sedp cache lock")
            .announce(reader_announcement(OURS, TOPIC), SedpEndpointKind::Reader);

        h.feed_relayed_from(PacketKind::SEDP, &packet, offset, None, forwarder_addr);

        let mut buf = [0u8; 512];
        assert!(
            forwarder.recv_from(&mut buf).is_err(),
            "peer unknown to the FSM: no reader re-announcement may reach the forwarder"
        );
    }

    /// E2, the other half: relayed but the peer IS known -- the
    /// re-announcement reaches its recorded metatraffic locator.
    #[test]
    fn a_relayed_reader_reannouncement_from_a_known_peer_reaches_its_fsm_address() {
        const PEER: [u8; 12] = [0x0E; 12];
        const OURS: [u8; 12] = [0x12; 12];
        const TOPIC: &str = "Y11bE2Known";
        let packet = opendds_sedp_writer_datagram(PEER, TOPIC, 1);
        let offset = one_data_offset(&packet);

        let peer_metatraffic = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
        peer_metatraffic
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set timeout");
        let peer_addr = peer_metatraffic.local_addr().expect("peer address");
        let forwarder: std::net::SocketAddr = "203.0.113.8:9999".parse().expect("valid address");

        let h = Harness::new();
        h.dispatch
            .sedp_cache
            .write()
            .expect("sedp cache lock")
            .announce(reader_announcement(OURS, TOPIC), SedpEndpointKind::Reader);
        h.dispatch
            .fsm
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(PEER, [0x00, 0x00, 0x01, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![peer_addr],
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

        h.feed_relayed_from(PacketKind::SEDP, &packet, offset, None, forwarder);

        // The confirmation ACKNACK (unrelated to this test, and
        // resolved the same way) reaches this very socket too: the `OpenDds`
        // dialect's confirmation fires for any writer announcement, direct or
        // relayed. So the reannouncement is identified by its SHAPE (it
        // carries a DATA submessage, 0x15; a pure ACKNACK never does), not
        // merely by "something arrived" -- reading only the first datagram
        // would pass on the confirmation alone and prove nothing about the
        // reannouncement this test exists to pin.
        let mut buf = [0u8; 1024];
        let mut saw_data_submessage = false;
        for _ in 0..3 {
            let Ok((len, _from)) = peer_metatraffic.recv_from(&mut buf) else {
                break;
            };
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                &buf[..len],
                |sub| {
                    if sub.id == 0x15 {
                        saw_data_submessage = true;
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        assert!(
            saw_data_submessage,
            "the reader re-announcement (a DATA submessage) must reach the peer's \
             recorded FSM address"
        );
    }

    // ------------------------------------------------------------------
    // Endpoint deletion, read in the forms RTPS allows and from our own
    // encoder (RTPS v2.5 Sec.8.5.4.4).
    // ------------------------------------------------------------------

    /// What a submessage around the dispose DATA is, in a synthetic
    /// endpoint-dispose datagram.
    #[derive(Clone, Copy)]
    enum Around {
        /// Nothing.
        Nothing,
        /// A submessage with the unassigned id 0x00 (RTPS v2.5 Table 8.13):
        /// the receiver skips it by its octetsToNextHeader (Sec.8.3.4.1).
        UnknownId,
        /// A submessage in the vendor-specific id range 0x80-0xff (Table
        /// 8.13), skipped the same way.
        VendorSpecific,
        /// The HEARTBEAT of the SEDP publications writer (Sec.8.3.8.6).
        Heartbeat,
    }

    /// The layout of one synthetic SEDP endpoint dispose: each field is a
    /// variation the dispose detection must read through.
    struct DisposeForm {
        name: &'static str,
        /// RTPS header protocolVersion (Sec.8.3.3.1).
        version: [u8; 2],
        /// The sending participant; the deleted writer is one of its own.
        prefix: [u8; 12],
        /// The deleted writer's entityId.
        writer_entity: [u8; 4],
        writer_sn: u32,
        before: Around,
        /// An INFO_DST addressed to the receiving participant (Sec.8.3.8.8).
        info_dst: bool,
        /// readerEntityId ENTITYID_UNKNOWN instead of the SEDP publications
        /// reader (Sec.8.3.8.2).
        reader_unknown: bool,
        /// PID_STATUS_INFO before PID_KEY_HASH in the inline QoS: a
        /// ParameterList is unordered (Sec.9.4.2.11).
        status_first: bool,
        /// The StatusInfo flags (Sec.9.6.4.9): 0x01 DISPOSED, 0x02
        /// UNREGISTERED.
        status: u8,
        /// K=1 and the serialized key after the inline QoS (Sec.9.6.3.2),
        /// beside the PID_KEY_HASH; K=0 and no payload otherwise.
        key_payload: bool,
        /// octetsToNextHeader 0 on the DATA, the last submessage: it runs to
        /// the end of the message (Sec.9.4.5.1.3).
        runs_to_end: bool,
        after: Around,
    }

    /// The four forms read by
    /// `the_four_synthetic_endpoint_disposes_retire_their_writer`. Between
    /// them: K=0 and K=1; StatusInfo DISPOSED|UNREGISTERED and DISPOSED
    /// alone; PID_KEY_HASH before and after PID_STATUS_INFO; the DATA after
    /// an INFO_DST, after an unknown submessage, and as the last submessage
    /// with octetsToNextHeader 0; a submessage after it, vendor-specific or
    /// HEARTBEAT; readerId known and unknown.
    const DISPOSE_FORMS: [DisposeForm; 4] = [
        DisposeForm {
            name: "K=0, key hash only, status first",
            version: [0x02, 0x02],
            prefix: [
                0x01, 0x1a, 0x51, 0x0e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21,
            ],
            writer_entity: [0x00, 0x00, 0x11, 0x02],
            writer_sn: 5,
            before: Around::Nothing,
            info_dst: true,
            reader_unknown: false,
            status_first: true,
            status: 0x03,
            key_payload: false,
            runs_to_end: false,
            after: Around::VendorSpecific,
        },
        DisposeForm {
            name: "K=1 after an unknown submessage",
            version: [0x02, 0x05],
            prefix: [
                0x01, 0x1a, 0x51, 0x0e, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22,
            ],
            writer_entity: [0x00, 0x00, 0x12, 0x02],
            writer_sn: 11,
            before: Around::UnknownId,
            info_dst: false,
            reader_unknown: false,
            status_first: false,
            status: 0x03,
            key_payload: true,
            runs_to_end: false,
            after: Around::Heartbeat,
        },
        DisposeForm {
            name: "K=1, readerId unknown, runs to the end",
            version: [0x02, 0x04],
            prefix: [
                0x01, 0x1a, 0x51, 0x0e, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23,
            ],
            writer_entity: [0x00, 0x00, 0x13, 0x02],
            writer_sn: 17,
            before: Around::Nothing,
            info_dst: false,
            reader_unknown: true,
            status_first: false,
            status: 0x03,
            key_payload: true,
            runs_to_end: true,
            after: Around::Nothing,
        },
        DisposeForm {
            name: "K=1, DISPOSED alone",
            version: [0x02, 0x05],
            prefix: [
                0x01, 0x1a, 0x51, 0x0e, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24,
            ],
            writer_entity: [0x00, 0x00, 0x14, 0x02],
            writer_sn: 23,
            before: Around::Nothing,
            info_dst: true,
            reader_unknown: false,
            status_first: false,
            status: 0x01,
            key_payload: true,
            runs_to_end: false,
            after: Around::Nothing,
        },
    ];

    /// A submessage header (Sec.9.4.5.1.1): id, flags with E=1, then
    /// octetsToNextHeader little-endian.
    fn submessage(p: &mut Vec<u8>, id: u8, flags: u8, body: &[u8]) {
        p.push(id);
        p.push(flags);
        p.extend_from_slice(
            &u16::try_from(body.len())
                .expect("a test submessage fits octetsToNextHeader")
                .to_le_bytes(),
        );
        p.extend_from_slice(body);
    }

    fn around(p: &mut Vec<u8>, what: Around, writer_sn: u32) {
        match what {
            Around::Nothing => {}
            // Flags other than E carry no meaning for an id the receiver
            // does not know; set here so that nothing relies on them.
            Around::UnknownId => submessage(p, 0x00, 0x03, &[0x5d, 0x0c, 0x00, 0x00]),
            Around::VendorSpecific => submessage(p, 0x80, 0x01, &[0xa5; 12]),
            Around::Heartbeat => {
                let mut hb = Vec::new();
                hb.extend_from_slice(&[0x00, 0x00, 0x03, 0xc7]); // readerId
                hb.extend_from_slice(&SEDP_PUBLICATIONS_WRITER); // writerId
                hb.extend_from_slice(&0i32.to_le_bytes()); // firstSN.high
                hb.extend_from_slice(&1u32.to_le_bytes()); // firstSN.low
                hb.extend_from_slice(&0i32.to_le_bytes()); // lastSN.high
                hb.extend_from_slice(&writer_sn.to_le_bytes()); // lastSN.low
                hb.extend_from_slice(&3u32.to_le_bytes()); // count
                submessage(p, 0x07, 0x01, &hb);
            }
        }
    }

    /// One endpoint-dispose datagram of the SEDP publications writer, built
    /// for the test from RTPS v2.5, laid out as `form` says; returns it with
    /// the writer it deletes. The vendorId is HDDS's: nothing on the
    /// dispose path branches on it.
    fn synthetic_endpoint_dispose(form: &DisposeForm) -> (Vec<u8>, GUID) {
        let endpoint = GUID::new(form.prefix, form.writer_entity);
        let mut p = Vec::new();
        // RTPS header (Sec.8.3.3.1): protocol, version, vendorId, prefix.
        p.extend_from_slice(b"RTPS");
        p.extend_from_slice(&form.version);
        p.extend_from_slice(&crate::core::rtps_constants::HDDS_VENDOR_ID);
        p.extend_from_slice(&form.prefix);
        around(&mut p, form.before, form.writer_sn);
        if form.info_dst {
            submessage(&mut p, 0x0e, 0x01, &super::super::wire_fixtures::OUR_PREFIX);
        }
        // INFO_TS (Sec.8.3.8.11): Time_t seconds, fraction.
        let mut ts = 1_790_000_000u32.to_le_bytes().to_vec();
        ts.extend_from_slice(&0x4000_0000u32.to_le_bytes());
        submessage(&mut p, 0x09, 0x01, &ts);

        // DATA (Sec.8.3.8.2): extraFlags, octetsToInlineQos 16, readerId,
        // writerId, writerSN; then the inline QoS and, with K, the key.
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_le_bytes()); // extraFlags
        body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
        if form.reader_unknown {
            body.extend_from_slice(&[0x00; 4]); // ENTITYID_UNKNOWN
        } else {
            body.extend_from_slice(&[0x00, 0x00, 0x03, 0xc7]); // SEDP pub. reader
        }
        body.extend_from_slice(&SEDP_PUBLICATIONS_WRITER);
        body.extend_from_slice(&0i32.to_le_bytes()); // writerSN.high
        body.extend_from_slice(&form.writer_sn.to_le_bytes()); // writerSN.low
                                                               // PID_KEY_HASH (Sec.9.6.4.8): the deleted endpoint's GUID.
        let mut key_hash = vec![0x70, 0x00, 0x10, 0x00];
        key_hash.extend_from_slice(&endpoint.as_bytes());
        // PID_STATUS_INFO (Sec.9.6.4.9): the flags in the last octet.
        let status = [0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, form.status];
        if form.status_first {
            body.extend_from_slice(&status);
            body.extend_from_slice(&key_hash);
        } else {
            body.extend_from_slice(&key_hash);
            body.extend_from_slice(&status);
        }
        body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL
        if form.key_payload {
            // Serialized key (Sec.9.6.3.2): PL_CDR_LE encapsulation (Sec.10.3),
            // PID_ENDPOINT_GUID, PID_SENTINEL.
            body.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
            body.extend_from_slice(&[0x5a, 0x00, 0x10, 0x00]);
            body.extend_from_slice(&endpoint.as_bytes());
            body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        }
        // E, Q, and K when the key follows; D clear.
        let flags = 0x01 | 0x02 | if form.key_payload { 0x08 } else { 0x00 };
        let data_at = p.len();
        submessage(&mut p, 0x15, flags, &body);
        if form.runs_to_end {
            assert!(
                matches!(form.after, Around::Nothing),
                "only the last submessage may run to the end"
            );
            p[data_at + 2..data_at + 4].copy_from_slice(&0u16.to_le_bytes());
        }
        around(&mut p, form.after, form.writer_sn);

        // The fixture's own invariants: the walk the listener uses finds
        // this DATA, and only it.
        let mut walked = Vec::new();
        for_each_data_submessage(&p, |data| walked.push(data.offset));
        assert_eq!(
            walked,
            vec![data_at],
            "{}: one DATA, the dispose",
            form.name
        );
        (p, endpoint)
    }

    fn participant_of(prefix: [u8; 12]) -> crate::protocol::discovery::SpdpData {
        crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(
                prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            ..remote_participant()
        }
    }

    fn announcement_of(endpoint: GUID) -> SedpData {
        SedpData {
            participant_guid: GUID::new(
                endpoint.prefix,
                crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
            ),
            ..announcement(endpoint)
        }
    }

    /// Records the writer-departure calls its topic receives.
    struct Departures(std::sync::Mutex<Vec<([u8; 16], crate::engine::subscriber::DisposeKind)>>);

    impl crate::engine::Subscriber for Departures {
        fn on_data(&self, _: &str, _: u64, _: &[u8]) {}
        fn topic_name(&self) -> &str {
            TOPIC
        }
        fn on_writer_dispose(
            &self,
            _: &str,
            writer_guid: [u8; 16],
            kind: crate::engine::subscriber::DisposeKind,
        ) {
            self.0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((writer_guid, kind));
        }
    }

    /// The dispatch, past its probation, with the match registry listening,
    /// a recording subscriber on TOPIC, and each of `prefixes` a confirmed
    /// remote participant.
    fn live_harness(
        prefixes: &[[u8; 12]],
    ) -> (
        Harness,
        Arc<crate::dds::match_notification::MatchNotificationRegistry>,
        Arc<Departures>,
    ) {
        let h = Harness::new();
        let fsm = &h.dispatch.fsm;
        let reg = Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(
                fsm,
                super::super::wire_fixtures::OUR_PREFIX,
            ),
        );
        fsm.register_listener(reg.clone());
        let departures = Arc::new(Departures(std::sync::Mutex::new(Vec::new())));
        h.dispatch
            .registry
            .register_subscriber(departures.clone())
            .expect("subscriber");
        // Probation 250 ms of uptime; a refresh confirms 100 ms after the
        // entry was created. Both asserted, not assumed.
        std::thread::sleep(std::time::Duration::from_millis(300));
        for prefix in prefixes {
            fsm.handle_spdp(participant_of(*prefix));
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
        for prefix in prefixes {
            fsm.handle_spdp(participant_of(*prefix));
            assert!(fsm.is_participant_confirmed(prefix), "confirmed");
        }
        assert!(fsm.is_probation_done());
        (h, reg, departures)
    }

    fn local_reader(
        reg: &Arc<crate::dds::match_notification::MatchNotificationRegistry>,
    ) -> crate::dds::match_notification::MatchToken {
        reg.register_reader_with_lifespan(
            TOPIC.to_string(),
            crate::dds::qos::QoS::best_effort(),
            &SHAPE_DESC,
            None,
            |_, _, _, _, _| {},
            None,
            None,
            None,
            Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            crate::transport::shm::ShmPolicy::default(),
        )
    }

    /// Every form of `DISPOSE_FORMS` is read, through the real door (the
    /// dispatch, at the offset the classifier hands it): the writer leaves
    /// discovery, the local reader's match count drops, and the readers of
    /// its topic are told it left (its instances go NOT_ALIVE_NO_WRITERS).
    #[test]
    fn the_four_synthetic_endpoint_disposes_retire_their_writer() {
        let built: Vec<(Vec<u8>, GUID)> = DISPOSE_FORMS
            .iter()
            .map(synthetic_endpoint_dispose)
            .collect();
        let endpoints: Vec<GUID> = built.iter().map(|(_, guid)| *guid).collect();
        let prefixes: Vec<[u8; 12]> = endpoints.iter().map(|g| g.prefix).collect();
        let (h, reg, departures) = live_harness(&prefixes);
        let token = local_reader(&reg);
        for endpoint in &endpoints {
            h.dispatch.fsm.handle_sedp(announcement_of(*endpoint));
            h.dispatch
                .registry
                .register_writer_guid(endpoint.as_bytes(), TOPIC.to_string());
        }
        assert_eq!(token.current_match_count(), 4, "the four writers matched");

        for (form, (packet, endpoint)) in DISPOSE_FORMS.iter().zip(&built) {
            let name = form.name;
            let at = one_data_offset(packet);
            assert_eq!(
                detect_sedp_endpoint_dispose(packet, at).map(|(kind, guid, _)| (kind, guid)),
                Some((EndpointKind::Writer, endpoint.as_bytes())),
                "{name}: read as the dispose of its writer"
            );
            h.feed(PacketKind::SEDP, packet, at, None);
            assert!(
                !h.dispatch
                    .fsm
                    .find_writers_for_topic(TOPIC)
                    .iter()
                    .any(|w| w.endpoint_guid == *endpoint),
                "{name}: the writer left discovery"
            );
        }
        assert_eq!(token.current_match_count(), 0, "all four unmatched");
        let told: Vec<_> = departures
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(
            told,
            endpoints
                .iter()
                .map(|e| (
                    e.as_bytes(),
                    crate::engine::subscriber::DisposeKind::Unregistered
                ))
                .collect::<Vec<_>>(),
            "each writer's readers are told it left, once"
        );
        assert_eq!(
            h.dispatch.fsm.get_participants().len(),
            4,
            "their participants stay"
        );
    }

    /// HDDS <-> HDDS: the dispose our own encoder emits for a deleted
    /// DataWriter and for a deleted DataReader is read by another HDDS
    /// participant, through the same door, and unmatches.
    #[test]
    fn our_own_endpoint_disposes_unmatch_at_another_hdds_participant() {
        const THEIRS: [u8; 12] = [0x01, 0x1a, 7, 7, 7, 7, 7, 7, 7, 7, 0, 3];
        let writer = GUID::new(THEIRS, [0x00, 0x00, 0x01, 0x02]);
        let reader = GUID::new(THEIRS, [0x00, 0x00, 0x02, 0x07]);
        let (h, reg, departures) = live_harness(&[THEIRS]);
        let local_r = local_reader(&reg);
        let local_w = reg.register_writer(
            TOPIC.to_string(),
            crate::dds::qos::QoS::best_effort(),
            &SHAPE_DESC,
            |_, _, _, _, _| {},
        );
        h.dispatch.fsm.handle_sedp(announcement_of(writer));
        h.dispatch.fsm.handle_sedp(announcement_of(reader));
        h.dispatch
            .registry
            .register_writer_guid(writer.as_bytes(), TOPIC.to_string());
        assert_eq!(local_r.current_match_count(), 1);
        assert_eq!(local_w.current_match_count(), 1);

        for (endpoint, kind, seq) in [
            (writer, SedpEndpointKind::Writer, 2),
            (reader, SedpEndpointKind::Reader, 2),
        ] {
            let packet = crate::core::discovery::multicast::build_sedp_dispose_packet(
                &endpoint,
                kind,
                &THEIRS,
                Some(&super::super::wire_fixtures::OUR_PREFIX),
                seq,
                Dialect::Hdds,
            );
            h.feed(PacketKind::SEDP, &packet, one_data_offset(&packet), None);
        }
        assert_eq!(
            local_r.current_match_count(),
            0,
            "the deleted writer unmatched"
        );
        assert_eq!(
            local_w.current_match_count(),
            0,
            "the deleted reader unmatched"
        );
        assert_eq!(
            departures
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_slice(),
            &[(
                writer.as_bytes(),
                crate::engine::subscriber::DisposeKind::Unregistered
            )]
        );
    }

    /// Whether an HDDS receiver keeps the first of two copies of one SEDP
    /// sequence number: the same announcement under the same SN, first
    /// without PID_TYPE_OBJECT, then with it, through the real door. The
    /// second copy is read, and its TypeObject recorded: HDDS does not
    /// deduplicate SEDP by sequence number. Pins the premise the
    /// PID_TYPE_OBJECT class rests on (`TypeObjectPid`).
    #[cfg(feature = "xtypes")]
    #[test]
    fn a_second_copy_of_an_sedp_number_with_the_type_object_is_read() {
        use crate::core::discovery::multicast::{build_sedp_rtps_packet_for, TypeObjectPid};
        const THEIRS: [u8; 12] = [0x01, 0x1a, 7, 7, 7, 7, 7, 7, 7, 7, 0, 4];
        let writer = GUID::new(THEIRS, [0x00, 0x00, 0x01, 0x02]);
        let (h, _reg, _departures) = live_harness(&[THEIRS]);
        let mut sd = announcement_of(writer);
        sd.type_object = Some(crate::xtypes::CompleteTypeObject::Struct(
            crate::xtypes::CompleteStructType {
                struct_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
                header: crate::xtypes::CompleteStructHeader {
                    base_type: None,
                    detail: crate::xtypes::CompleteTypeDetail::new(TYPE_NAME),
                },
                member_seq: vec![crate::xtypes::CompleteStructMember {
                    common: crate::xtypes::CommonStructMember {
                        member_id: 0,
                        member_flags: crate::xtypes::MemberFlag::TRY_CONSTRUCT1,
                        member_type_id: crate::xtypes::TypeIdentifier::TK_INT32,
                    },
                    detail: crate::xtypes::CompleteMemberDetail::new("x"),
                }],
            },
        ));
        let copy = |class| {
            build_sedp_rtps_packet_for(
                &sd,
                SedpEndpointKind::Writer,
                &THEIRS,
                Some(&super::super::wire_fixtures::OUR_PREFIX),
                1,
                Dialect::Hdds,
                class,
            )
            .expect("packet")
        };
        let recorded = || {
            h.dispatch
                .fsm
                .find_writers_for_topic(TOPIC)
                .into_iter()
                .find(|w| w.endpoint_guid == writer)
                .map(|w| w.type_object.is_some())
        };
        let first = copy(TypeObjectPid::Withhold);
        h.feed(PacketKind::SEDP, &first, one_data_offset(&first), None);
        assert_eq!(recorded(), Some(false), "first copy: known, no TypeObject");
        let second = copy(TypeObjectPid::Emit);
        h.feed(PacketKind::SEDP, &second, one_data_offset(&second), None);
        assert_eq!(
            recorded(),
            Some(true),
            "second copy, same SN: TypeObject recorded"
        );
    }

    /// An endpoint is deleted only by its own participant: a dispose naming
    /// another participant's endpoint is refused, whether the sender is
    /// named by the RTPS header or by an INFO_SRC before the DATA.
    #[test]
    fn a_dispose_of_another_participants_endpoint_is_refused() {
        const SENDER: [u8; 12] = [0x77; 12];
        let victim = remote([0x00, 0x00, 0x01, 0x04]); // REMOTE_PREFIX's
        let mut spoofed = endpoint_dispose(SEDP_SUBSCRIPTIONS_WRITER, victim, 0x03);
        spoofed[8..20].copy_from_slice(&SENDER);
        assert_eq!(detect_sedp_endpoint_dispose(&spoofed, 0), None, "header");

        // Same in our own K form, under a foreign header.
        let k_form = crate::core::discovery::multicast::build_sedp_dispose_packet(
            &victim,
            SedpEndpointKind::Reader,
            &SENDER,
            None,
            2,
            Dialect::Hdds,
        );
        assert_eq!(
            detect_sedp_endpoint_dispose(&k_form, one_data_offset(&k_form)),
            None,
            "key-only form"
        );

        // A datagram from REMOTE_PREFIX that relays, behind an INFO_SRC
        // naming SENDER, a dispose of REMOTE_PREFIX's endpoint: once split,
        // its sender is SENDER, and it is refused.
        let honest = endpoint_dispose(SEDP_SUBSCRIPTIONS_WRITER, victim, 0x03);
        assert!(
            detect_sedp_endpoint_dispose(&honest, 0).is_some(),
            "fixture"
        );
        let relayed = |source: [u8; 12]| {
            let mut p = honest[..20].to_vec();
            p.extend_from_slice(&[0x0c, 0x01, 20, 0]); // INFO_SRC, E, 20 octets
            p.extend_from_slice(&[0, 0, 0, 0, 0x02, 0x05, 0x01, 0x01]);
            p.extend_from_slice(&source);
            p.extend_from_slice(&honest[20..]);
            p
        };
        let parts = |datagram: &[u8]| -> Vec<Vec<u8>> {
            match crate::core::discovery::multicast::classifier::walk::split_by_receiver_state(
                datagram,
            ) {
                crate::core::discovery::multicast::classifier::walk::Sources::Split(parts) => {
                    parts.into_iter().map(|part| part.message).collect()
                }
                crate::core::discovery::multicast::classifier::walk::Sources::One(_) => {
                    panic!("an INFO_SRC splits the datagram")
                }
            }
        };
        let spoofed_parts = parts(&relayed(SENDER));
        assert_eq!(spoofed_parts.len(), 1, "one part, behind the INFO_SRC");
        assert_eq!(
            detect_sedp_endpoint_dispose(&spoofed_parts[0], one_data_offset(&spoofed_parts[0])),
            None,
            "the INFO_SRC names the sender, and it is not the endpoint's participant"
        );
        // The endpoint's own participant relayed by someone else is read.
        let mut forwarded = relayed(REMOTE_PREFIX);
        forwarded[8..20].copy_from_slice(&SENDER);
        let own_parts = parts(&forwarded);
        assert_eq!(
            detect_sedp_endpoint_dispose(&own_parts[0], one_data_offset(&own_parts[0]))
                .map(|(_, guid, _)| guid),
            Some(victim.as_bytes())
        );
    }

    /// The re-announcement of our readers for the `OpenDds` dialect
    /// sends the readers
    /// that exist: a reader deleted since is never announced again.
    #[test]
    fn the_opendds_reannouncement_skips_a_deleted_reader() {
        const PEER: [u8; 12] = [0x0F; 12];
        const OURS: [u8; 12] = [0x13; 12];
        const TOPIC: &str = "Y22OpenDdsDeleted";
        let packet = opendds_sedp_writer_datagram(PEER, TOPIC, 1);
        let offset = one_data_offset(&packet);

        let peer_metatraffic = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
        peer_metatraffic
            .set_read_timeout(Some(std::time::Duration::from_millis(400)))
            .expect("set timeout");
        let peer_addr = peer_metatraffic.local_addr().expect("peer address");

        let h = Harness::new();
        let deleted = reader_announcement(OURS, TOPIC);
        let deleted_guid = deleted.endpoint_guid;
        {
            let mut history = h.dispatch.sedp_cache.write().expect("sedp cache lock");
            history.announce(deleted, SedpEndpointKind::Reader);
            assert_eq!(
                history.retire(&deleted_guid, SedpEndpointKind::Reader),
                Some(2)
            );
        }
        h.dispatch
            .fsm
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(
                    PEER,
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                ),
                metatraffic_unicast_locators: vec![peer_addr],
                ..remote_participant()
            });

        h.feed_from(PacketKind::SEDP, &packet, offset, None, peer_addr);

        // The confirmation ACKNACK arrives (proof the door ran); a DATA
        // never does.
        let mut buf = [0u8; 1024];
        let mut datagrams = 0;
        let mut data_submessages = 0;
        while let Ok((len, _)) = peer_metatraffic.recv_from(&mut buf) {
            datagrams += 1;
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                &buf[..len],
                |sub| {
                    if sub.id == 0x15 {
                        data_submessages += 1;
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        assert!(datagrams > 0, "the confirmation ACKNACK reached the peer");
        assert_eq!(
            data_submessages, 0,
            "the deleted reader is not re-announced"
        );
    }

    /// The re-announcement of a reader for the `OpenDds` dialect is a change
    /// of the SEDP
    /// subscriptions writer's history, under the history's next number: the
    /// reader created after it and the dispose after that take the numbers
    /// after it, never the one it went out under. Read from the bytes the
    /// peer received and the bytes the history builds.
    ///
    /// One reader (1); a DATA(w) of its topic arrives under vendor 0x0103:
    /// the reader
    /// goes out again under 2, its HEARTBEAT 2..2 (1 is superseded); a second
    /// reader takes 3; the first one's dispose 4. The re-announcement must not
    /// take its number from a process-wide counter while the history goes
    /// on handing out its own: the second reader could go out under the
    /// re-announcement's number, which the peer drops as a duplicate.
    #[test]
    fn the_opendds_reannouncement_takes_a_number_no_other_change_takes() {
        const PEER: [u8; 12] = [0x14; 12];
        const OURS: [u8; 12] = [0x15; 12];
        const TOPIC: &str = "OpenDdsNumber";
        const SEDP_SUBSCRIPTIONS: [u8; 4] = [0x00, 0x00, 0x04, 0xC2];
        let packet = opendds_sedp_writer_datagram(PEER, TOPIC, 1);
        let offset = one_data_offset(&packet);

        let peer_metatraffic = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer socket");
        peer_metatraffic
            .set_read_timeout(Some(std::time::Duration::from_millis(400)))
            .expect("set timeout");
        let peer_addr = peer_metatraffic.local_addr().expect("peer address");

        let h = Harness::new();
        let first = reader_announcement(OURS, TOPIC);
        let first_guid = first.endpoint_guid;
        assert_eq!(
            h.dispatch
                .sedp_cache
                .write()
                .expect("sedp cache lock")
                .announce(first, SedpEndpointKind::Reader),
            1
        );
        h.dispatch
            .fsm
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(
                    PEER,
                    crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
                ),
                metatraffic_unicast_locators: vec![peer_addr],
                ..remote_participant()
            });

        h.feed_from(PacketKind::SEDP, &packet, offset, None, peer_addr);

        let sn = |bytes: &[u8], at: usize| {
            let high = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four octets"));
            let low = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().expect("four octets"));
            (u64::from(high) << 32) | u64::from(low)
        };
        // (writerSN of each DATA of the subscriptions writer, (firstSN,
        // lastSN) of each of its HEARTBEATs), from what the peer received.
        let mut data_sns = Vec::new();
        let mut heartbeats = Vec::new();
        let mut buf = [0u8; 2048];
        while let Ok((len, _)) = peer_metatraffic.recv_from(&mut buf) {
            let dgram = &buf[..len];
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                dgram,
                |sub| {
                    let body = sub.offset + 4;
                    match sub.id {
                        0x15 if dgram[body + 8..body + 12] == SEDP_SUBSCRIPTIONS => {
                            assert_eq!(sub.flags & 0x01, 0x01, "little-endian");
                            data_sns.push(sn(dgram, body + 12));
                        }
                        0x07 if dgram[body + 4..body + 8] == SEDP_SUBSCRIPTIONS => {
                            heartbeats.push((sn(dgram, body + 8), sn(dgram, body + 16)));
                        }
                        _ => {}
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        assert_eq!(
            data_sns,
            vec![2],
            "re-announced under the history's next number"
        );
        assert_eq!(heartbeats, vec![(2, 2)], "1 is superseded, 2 is the last");

        let second = minimal_sedp_data(
            TOPIC,
            GUID::new(OURS, [0x00, 0x00, 0x01, 0xC1]),
            GUID::new(OURS, [0x00, 0x00, 0x02, 0x04]),
        );
        let second_guid = second.endpoint_guid;
        let mut history = h.dispatch.sedp_cache.write().expect("sedp cache lock");
        assert_eq!(
            history.announce(second, SedpEndpointKind::Reader),
            3,
            "the next reader takes the number after the re-announcement"
        );
        assert_eq!(
            history.retire(&first_guid, SedpEndpointKind::Reader),
            Some(4),
            "and the dispose the one after that"
        );
        // Every number the history sends now, read from the bytes it builds:
        // (submessage id, writerSN or gapStart, D/K flags or gapList.base).
        let mut sent = Vec::new();
        for send in history.sends(Some(SedpEndpointKind::Reader)) {
            let bytes = send
                .build(&OURS, Some(&PEER), Dialect::OpenDds)
                .expect("built");
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                &bytes,
                |sub| {
                    let body = sub.offset + 4;
                    match sub.id {
                        0x15 => {
                            sent.push((sub.id, sn(&bytes, body + 12), u64::from(sub.flags & 0x0c)))
                        }
                        0x08 => sent.push((sub.id, sn(&bytes, body + 8), sn(&bytes, body + 16))),
                        _ => {}
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        assert_eq!(
            sent,
            vec![(0x08, 1, 3), (0x15, 3, 0x04), (0x15, 4, 0x08)],
            "GAP over 1..2 (the first reader's two announcements), the second reader (D) at \
             3, the first one's dispose (K) at 4"
        );
        assert_eq!(
            history.seq_of(&second_guid, SedpEndpointKind::Reader),
            Some(3)
        );
        assert_eq!(history.seq_of(&first_guid, SedpEndpointKind::Reader), None);
    }

    /// The GROUP class of a remote participant's writers follows its
    /// participant's dialect when an SPDP changes it after the writers were
    /// discovered: one that announced no capability, then the spec GROUP
    /// one, has its writers' ends of set read in the spec form, and back.
    #[test]
    fn a_writers_group_class_follows_its_participants_capabilities() {
        const PUBLISHER: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
        let topics = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
        fsm.register_listener(Arc::new(WriterDepartures::new(&topics)));
        let spdp = |caps: Option<u32>| crate::protocol::discovery::SpdpData {
            vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            hdds_capabilities: caps,
            ..remote_participant()
        };
        fsm.handle_spdp(spdp(None));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            group_entity_id: Some(PUBLISHER),
            ..announcement(writer)
        });
        record_writer_group_dialect(&topics, &fsm, writer.as_bytes(), Some(PUBLISHER));
        assert_eq!(topics.writer_spec_group(&writer.as_bytes()), None, "1.4.x");

        fsm.handle_spdp(spdp(Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT)));
        assert_eq!(
            topics.writer_spec_group(&writer.as_bytes()),
            Some(PUBLISHER),
            "the spec class, its capability announced"
        );

        fsm.handle_spdp(spdp(Some(0)));
        assert_eq!(
            topics.writer_spec_group(&writer.as_bytes()),
            None,
            "1.4.x again, its capability withdrawn"
        );
    }

    /// A writer's SEDP read again after discovery forgot its participant
    /// (its SPDP dispose, read on another thread: a reliable SEDP repair
    /// crossing it) leaves the writer's GROUP class as decided while the
    /// participant was known. Recorded again from a participant discovery no
    /// longer knew, the class fell to the classic one, and the router read
    /// the writer's last end of set, still queued behind its data, in the
    /// wrong form: under no Publisher, its part ending at its first SN. The
    /// set never closed and the departure discarded it.
    #[test]
    fn a_late_sedp_of_a_forgotten_participant_keeps_its_writers_group_class() {
        const PUBLISHER: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
        let topics = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            hdds_capabilities: Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
            ..remote_participant()
        });
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        record_writer_group_dialect(&topics, &fsm, writer.as_bytes(), Some(PUBLISHER));
        assert_eq!(
            topics.writer_spec_group(&writer.as_bytes()),
            Some(PUBLISHER),
            "fixture: the spec class"
        );
        fsm.remove_participant(remote(
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        ));
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&writer.as_bytes()[..12]);
        assert!(!fsm.is_participant_known(&prefix), "fixture: forgotten");
        record_writer_group_dialect(&topics, &fsm, writer.as_bytes(), Some(PUBLISHER));
        assert_eq!(
            topics.writer_spec_group(&writer.as_bytes()),
            Some(PUBLISHER),
            "the class decided while its participant was known"
        );
    }

    /// A Dust DDS writer (vendor 0x0114, `GroupDialect::SpecReceive`) whose
    /// SEDP reaches the handler before its participant's SPDP is registered
    /// (the two are read on different threads): the handler records its GROUP
    /// class from a participant discovery does not know yet, the classic one,
    /// and discovery holds the announcement until the SPDP arrives and replays
    /// it without going back through the handler. The writer kept the classic
    /// class for good: its members were staged under no Publisher, its bare end
    /// of set was read as nothing, and a GROUP reader never closed a set of it
    /// (the intermittent dust-h Test_CoherentSets_21 / _12 stall).
    #[test]
    fn a_dust_writer_announced_before_its_participant_keeps_the_dust_group_class() {
        const PUBLISHER: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
        let topics = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        fsm.register_listener(Arc::new(WriterDepartures::new(&topics)));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        // The handler's steps for the writer's SEDP, its SPDP not read yet.
        record_writer_group_dialect(&topics, &fsm, writer.as_bytes(), Some(PUBLISHER));
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            group_entity_id: Some(PUBLISHER),
            ..announcement(writer)
        });
        assert!(
            !topics.writer_is_spec_receive(&writer.as_bytes()),
            "fixture: recorded while its participant was unknown"
        );
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            vendor_id: Some(0x0114),
            ..remote_participant()
        });
        assert_eq!(
            topics.writer_spec_group(&writer.as_bytes()),
            Some(PUBLISHER),
            "the writer's Publisher, once its participant is known"
        );
        assert!(
            topics.writer_is_spec_receive(&writer.as_bytes()),
            "a Dust writer announced before its participant"
        );
    }

    /// The same order for a participant of no GROUP dialect: nothing is
    /// recorded again, the class stays the classic one as decided.
    #[test]
    fn a_classic_writer_announced_before_its_participant_is_left_as_recorded() {
        const PUBLISHER: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
        let topics = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        fsm.register_listener(Arc::new(WriterDepartures::new(&topics)));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        record_writer_group_dialect(&topics, &fsm, writer.as_bytes(), Some(PUBLISHER));
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            group_entity_id: Some(PUBLISHER),
            ..announcement(writer)
        });
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            vendor_id: Some(0x0101),
            ..remote_participant()
        });
        assert_eq!(topics.writer_spec_group(&writer.as_bytes()), None);
        assert!(!topics.writer_is_spec_receive(&writer.as_bytes()));
    }

    /// A Dust writer whose participant is registered between the handler
    /// reading its dialect and discovery taking its announcement: the
    /// announcement is not held, nothing replays it, and the class recorded
    /// from the unknown participant is decided again once discovery has it
    /// (`settle_writer_decisions`).
    #[test]
    fn a_dust_writer_whose_participant_appears_during_its_announcement_is_settled() {
        const PUBLISHER: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
        let topics = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        record_writer_group_dialect(&topics, &fsm, writer.as_bytes(), Some(PUBLISHER));
        fsm.handle_spdp(crate::protocol::discovery::SpdpData {
            vendor_id: Some(0x0114),
            ..remote_participant()
        });
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            group_entity_id: Some(PUBLISHER),
            ..announcement(writer)
        });
        assert!(
            !topics.writer_is_spec_receive(&writer.as_bytes()),
            "fixture: the window the handler's first read leaves"
        );
        settle_writer_decisions(&topics, &fsm, writer.as_bytes(), Some(PUBLISHER));
        assert_eq!(
            topics.writer_spec_group(&writer.as_bytes()),
            Some(PUBLISHER)
        );
        assert!(topics.writer_is_spec_receive(&writer.as_bytes()));
    }

    /// A writer's SEDP taken by the handler's fragments entry point, the
    /// reassembled form of an announcement: its class and vendor are recorded
    /// from the participant as it is then, and the announcement is settled
    /// after `handle_sedp` as the classifier path settles it.
    fn take_writer_announcement(
        topics: &Arc<TopicRegistry>,
        fsm: &Arc<DiscoveryFsm>,
        writer: GUID,
        publisher: [u8; 4],
    ) {
        let mut bytes = vec![0u8; 2048];
        let len = crate::protocol::discovery::build_sedp(
            &crate::protocol::discovery::SedpData {
                group_entity_id: Some(publisher),
                ..announcement(writer)
            },
            &mut bytes,
        )
        .expect("fixture: the announcement builds");
        handle_sedp_from_fragments(&bytes[..len], 1, Arc::clone(fsm), Arc::clone(topics));
    }

    /// What the registry holds for a writer: its Publisher when it is of the
    /// spec GROUP class, its SpecReceive flag, its legacy key-hash flag.
    type ClassState = (Option<[u8; 4]>, bool, bool);

    /// What the registry holds for `writer`, as a `ClassState`.
    fn recorded_class_state(topics: &TopicRegistry, writer: GUID) -> ClassState {
        (
            topics.writer_spec_group(&writer.as_bytes()),
            topics.writer_is_spec_receive(&writer.as_bytes()),
            topics.writer_uses_legacy_key_hash(&writer.as_bytes()),
        )
    }

    /// The state recorded for `writer` after its SEDP and its participant's
    /// SPDP `spdp`, in both orders: (SPDP first, SEDP first).
    fn class_state_in_both_orders(
        spdp: &crate::protocol::discovery::SpdpData,
        writer: GUID,
        publisher: [u8; 4],
    ) -> (ClassState, ClassState) {
        let spdp_first = {
            let topics = Arc::new(TopicRegistry::new());
            let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
            fsm.register_listener(Arc::new(WriterDepartures::new(&topics)));
            fsm.handle_spdp(spdp.clone());
            take_writer_announcement(&topics, &fsm, writer, publisher);
            recorded_class_state(&topics, writer)
        };
        let sedp_first = {
            let topics = Arc::new(TopicRegistry::new());
            let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
            fsm.register_listener(Arc::new(WriterDepartures::new(&topics)));
            take_writer_announcement(&topics, &fsm, writer, publisher);
            fsm.handle_spdp(spdp.clone());
            recorded_class_state(&topics, writer)
        };
        (spdp_first, sedp_first)
    }

    /// An HDDS peer announcing the spec GROUP capability (`GroupDialect::Spec`)
    /// whose writer is announced before its participant's SPDP: the registry
    /// ends in the state the SPDP-first order gives (the writer in the spec
    /// class under its Publisher, not legacy).
    #[test]
    fn an_hdds_spec_writer_announced_before_its_participant_settles_as_spdp_first() {
        const PUBLISHER: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        let spdp = crate::protocol::discovery::SpdpData {
            vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            hdds_capabilities: Some(crate::protocol::group::LOCAL_CAPABILITIES),
            ..remote_participant()
        };
        let (spdp_first, sedp_first) = class_state_in_both_orders(&spdp, writer, PUBLISHER);
        assert_eq!(
            spdp_first,
            (Some(PUBLISHER), false, false),
            "fixture: the spec class under its Publisher, not legacy"
        );
        assert_eq!(
            sedp_first, spdp_first,
            "announced before its participant: the state of the SPDP-first order"
        );
    }

    /// An HDDS 1.4.x peer (no PID_HDDS_CAPABILITIES) whose writer is announced
    /// before its participant's SPDP: the writer keeps the legacy key-hash
    /// flag its participant's vendor and capabilities give, as in the
    /// SPDP-first order.
    #[test]
    fn a_legacy_key_hash_writer_announced_before_its_participant_settles_as_spdp_first() {
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        let spdp = crate::protocol::discovery::SpdpData {
            vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
            hdds_capabilities: None,
            ..remote_participant()
        };
        let (spdp_first, sedp_first) = class_state_in_both_orders(&spdp, writer, [0x00; 4]);
        assert_eq!(
            spdp_first,
            (None, false, true),
            "fixture: a 1.4.x HDDS writer, legacy key hash, no GROUP class"
        );
        assert_eq!(
            sedp_first, spdp_first,
            "announced before its participant: the state of the SPDP-first order"
        );
    }

    /// The listener path of the legacy key-hash decision: a writer announced
    /// while its participant was not known has no flag, and
    /// `on_participant_key_hash_decided` (what discovery sends once the
    /// participant is known) sets it, and clears it again on a later `false`.
    #[test]
    fn the_listener_settles_the_legacy_key_hash_flag_of_the_writers_it_names() {
        use crate::core::discovery::multicast::DiscoveryListener as _;
        const PUBLISHER: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
        let topics = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        take_writer_announcement(&topics, &fsm, writer, PUBLISHER);
        assert!(
            !topics.writer_uses_legacy_key_hash(&writer.as_bytes()),
            "fixture: announced while its participant was not known"
        );
        WriterDepartures::new(&topics).on_participant_key_hash_decided(true, &[writer.as_bytes()]);
        assert!(topics.writer_uses_legacy_key_hash(&writer.as_bytes()));
        WriterDepartures::new(&topics).on_participant_key_hash_decided(false, &[writer.as_bytes()]);
        assert!(!topics.writer_uses_legacy_key_hash(&writer.as_bytes()));
    }

    /// A participant's writers are gone with it however it was removed: when
    /// it said so, when its lease expired, and when the probation purged it
    /// (it may have delivered samples before it fell silent). Each removal
    /// takes that participant's writers, and only its own.
    #[test]
    fn a_removed_participant_takes_its_own_writers_with_it_whatever_removed_it() {
        const STALE: [u8; 12] = [0x5b; 12];
        let topics = Arc::new(TopicRegistry::new());
        let departures = Arc::new(Departures(std::sync::Mutex::new(Vec::new())));
        topics
            .register_subscriber(departures.clone())
            .expect("subscriber");
        let stale_writer = GUID::new(STALE, [0x00, 0x00, 0x01, 0x02]);
        let leaving_writer = remote([0x00, 0x00, 0x01, 0x02]);
        for writer in [stale_writer, leaving_writer] {
            topics.register_writer_guid(writer.as_bytes(), TOPIC.to_string());
        }
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        fsm.register_listener(Arc::new(WriterDepartures::new(&topics)));
        let departed = || {
            departures
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        };

        // STALE is heard once during the probation and never again: it is
        // judged at its own age (250 ms, `PROBATION_SPAN_MS`) and purged
        // then, by this call or by the probation timer.
        fsm.handle_spdp(participant_of(STALE));
        assert!(
            fsm.uptime() < std::time::Duration::from_millis(250),
            "fixture: STALE is first heard during the probation"
        );
        std::thread::sleep(std::time::Duration::from_millis(300));
        fsm.purge_unconfirmed_participants();
        assert!(!fsm.is_participant_known(&STALE), "fixture: purged");
        assert_eq!(
            departed(),
            vec![(
                stale_writer.as_bytes(),
                crate::engine::subscriber::DisposeKind::Unregistered
            )],
            "the purged participant took its writer, and only its own"
        );

        fsm.handle_spdp(remote_participant());
        fsm.remove_participant(remote(
            crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT,
        ));
        assert_eq!(
            departed(),
            vec![
                (
                    stale_writer.as_bytes(),
                    crate::engine::subscriber::DisposeKind::Unregistered
                ),
                (
                    leaving_writer.as_bytes(),
                    crate::engine::subscriber::DisposeKind::Unregistered
                )
            ],
            "the participant that left took its writer, and only its own"
        );
    }

    /// A DCPSPublication parameter list (PL_CDR_LE) for `writer` on TOPIC,
    /// with `extra` parameters before the sentinel.
    fn publication_with(writer: GUID, extra: &[(u16, Vec<u8>)]) -> Vec<u8> {
        fn string(s: &str) -> Vec<u8> {
            let mut v = u32::try_from(s.len() + 1)
                .expect("fits")
                .to_le_bytes()
                .to_vec();
            v.extend_from_slice(s.as_bytes());
            v.push(0);
            v.resize(v.len().next_multiple_of(4), 0);
            v
        }
        let mut params: Vec<(u16, Vec<u8>)> = vec![
            (0x005a, writer.as_bytes().to_vec()),
            (0x0005, string(TOPIC)),
            (0x0007, string(TYPE_NAME)),
        ];
        params.extend_from_slice(extra);
        let mut p = vec![0x00, 0x03, 0x00, 0x00];
        for (pid, value) in params {
            p.extend_from_slice(&pid.to_le_bytes());
            p.extend_from_slice(&u16::try_from(value.len()).expect("fits").to_le_bytes());
            p.extend_from_slice(&value);
        }
        p.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        p
    }

    /// A reassembled announcement older than the last one applied about its
    /// endpoint is not applied (`DiscoveryFsm::admits_sedp_change`): here
    /// the EXCLUSIVE announcement at 5 stays, the older SHARED one at 4 is
    /// refused, and the next, 6, applies.
    #[test]
    fn a_reassembled_announcement_older_than_the_last_applied_is_refused() {
        let registry = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        let exclusive = publication_with(writer, &[(0x0006, 7i32.to_le_bytes().to_vec())]);
        let shared = publication_with(writer, &[]);
        let kind = || registry.writer_ownership_kind(&writer.as_bytes());
        handle_sedp_from_fragments(&exclusive, 5, Arc::clone(&fsm), Arc::clone(&registry));
        assert_eq!(
            kind(),
            Some(crate::qos::ownership::OwnershipKind::Exclusive)
        );
        handle_sedp_from_fragments(&shared, 4, Arc::clone(&fsm), Arc::clone(&registry));
        assert_eq!(
            kind(),
            Some(crate::qos::ownership::OwnershipKind::Exclusive)
        );
        handle_sedp_from_fragments(&shared, 6, Arc::clone(&fsm), Arc::clone(&registry));
        assert_eq!(kind(), Some(crate::qos::ownership::OwnershipKind::Shared));
    }

    /// DDS 1.4 Sec.2.2.3.13: SEDP PARTITION metadata is retained for
    /// controls arriving after the discovery endpoint has been purged.
    /// An omitted PID on a later announcement restores the default.
    #[test]
    fn a_reassembled_writer_partition_is_recorded_and_defaulted() {
        let registry = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        // PID_PARTITION (0x0029): one CDR string, "a", padded to four bytes.
        let partition = vec![1, 0, 0, 0, 2, 0, 0, 0, b'a', 0, 0, 0];
        handle_sedp_from_fragments(
            &publication_with(writer, &[(0x0029, partition)]),
            1,
            Arc::clone(&fsm),
            Arc::clone(&registry),
        );
        assert_eq!(
            registry.writer_partition(&writer.as_bytes()),
            Some(crate::qos::partition::Partition::single("a")),
        );
        handle_sedp_from_fragments(
            &publication_with(writer, &[]),
            2,
            Arc::clone(&fsm),
            Arc::clone(&registry),
        );
        assert_eq!(
            registry.writer_partition(&writer.as_bytes()),
            Some(Default::default())
        );
    }

    /// A writer that announces PID_OWNERSHIP_STRENGTH without PID_OWNERSHIP
    /// is read as EXCLUSIVE, and its strength is recorded with it: the
    /// arbitration of its instances needs both (DDS v1.4 Sec.2.2.3.10).
    /// Recording the strength only when the PARSED kind is EXCLUSIVE (which
    /// it never is without PID_OWNERSHIP) would arbitrate such a writer at
    /// strength 0.
    #[test]
    fn a_strength_announced_alone_is_recorded_with_its_exclusive_kind() {
        let registry = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        handle_sedp_from_fragments(
            &publication_with(writer, &[(0x0006, 7i32.to_le_bytes().to_vec())]),
            1,
            Arc::clone(&fsm),
            Arc::clone(&registry),
        );
        assert_eq!(
            registry.writer_ownership_kind(&writer.as_bytes()),
            Some(crate::qos::ownership::OwnershipKind::Exclusive)
        );
        assert_eq!(
            registry.writer_ownership_strength(&writer.as_bytes()),
            Some(7)
        );

        // Announced again without the PID: back to the default, 0.
        handle_sedp_from_fragments(
            &publication_with(writer, &[]),
            2,
            Arc::clone(&fsm),
            Arc::clone(&registry),
        );
        assert_eq!(
            registry.writer_ownership_kind(&writer.as_bytes()),
            Some(crate::qos::ownership::OwnershipKind::Shared)
        );
        assert_eq!(
            registry.writer_ownership_strength(&writer.as_bytes()),
            Some(0)
        );
    }

    /// A deleted writer's strength leaves the registry with it.
    #[test]
    fn a_deleted_writers_strength_leaves_the_registry() {
        let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
        let topics = TopicRegistry::new();
        let writer = remote([0x00, 0x00, 0x01, 0x02]);
        topics.register_writer_guid(writer.as_bytes(), TOPIC.to_string());
        topics.register_writer_ownership_strength(writer.as_bytes(), 9);
        assert_eq!(topics.writer_ownership_strength_count(), 1);

        let dispose = endpoint_dispose(SEDP_PUBLICATIONS_WRITER, writer, 0x03);
        assert!(apply_sedp_endpoint_dispose(
            &dispose,
            0,
            &fsm,
            &topics,
            SedpChannel::Plain,
            None
        ));
        assert_eq!(topics.writer_ownership_strength_count(), 0);
    }

    /// A writer's finite Lifespan reaches the registry, per writer, from an
    /// announcement reassembled from fragments as from a whole one: a reader
    /// expires that writer's samples by it, and no other writer's.
    #[test]
    fn a_reassembled_writer_announcement_records_its_lifespan_per_writer() {
        use crate::protocol::dialect::{
            build_sedp_for_dialect, Dialect, Guid, QosProfile, SedpEndpointData,
        };
        let prefix = [0x61; 12];
        let qos = QosProfile {
            lifespan_sec: 2,
            lifespan_nsec: 0,
            ..Default::default()
        };
        let sample = build_sedp_for_dialect(
            Dialect::Hdds,
            &SedpEndpointData {
                endpoint_guid: Guid {
                    prefix,
                    entity_id: [0x00, 0x00, 0x12, 0x02],
                },
                participant_guid: Guid {
                    prefix,
                    entity_id: [0x00, 0x00, 0x01, 0xc1],
                },
                topic_name: "Lifespans",
                type_name: "ShapeType",
                unicast_locators: &[],
                multicast_locators: &[],
                qos: Some(&qos),
                type_object: None,
                user_data: None,
                hdds_shm_capability: None,
                hdds_peer_destination: false,
                group_entity_id: None,
                type_consistency: None,
                #[cfg(feature = "xtypes-structural-assignability")]
                type_information: None,
                emit_type_object_pid: true,
            },
        )
        .expect("build");
        let registry = Arc::new(TopicRegistry::new());
        let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 30_000));
        handle_sedp_from_fragments(&sample, 1, fsm, Arc::clone(&registry));
        let writer = GUID::new(prefix, [0x00, 0x00, 0x12, 0x02]).as_bytes();
        assert_eq!(
            registry.writer_lifespan(&writer),
            Some(2_000_000_000),
            "the writer's lifespan, under its own GUID"
        );
        assert_eq!(registry.writer_lifespan(&[0x62; 16]), None);
    }

    /// The one QoS verdict (`match_notification::rxo_verdict`) on
    /// DATA_REPRESENTATION, with the writer read as a remote announcement
    /// (no list = `[XCDR]`, DDS-XTypes v1.3 Sec.7.6.3.1.1) and each local
    /// reader as it announces itself (no list = `[XCDR, XCDR2]`,
    /// `announced_data_representation`): what each (writer, reader) pair's
    /// data-plane gate records.
    #[test]
    fn rxo_verdict_reads_data_representation_as_each_end_announces_it() {
        use crate::core::discovery::multicast::EndpointInfo;
        use crate::core::discovery::GUID;
        use crate::dds::match_notification::{
            local_reader_qos_for_verdict, remote_announcement_for_verdict, rxo_verdict,
        };
        use crate::dds::qos::QoS;

        const XCDR1: u16 = 0x0000;
        const XCDR2: u16 = 0x0002;

        fn local_reader(qos: QoS) -> EndpointInfo {
            let guid = GUID::from_bytes([0; 16]);
            EndpointInfo {
                endpoint_guid: guid,
                participant_guid: guid,
                topic_name: String::new(),
                type_name: String::new(),
                qos,
                kind: EndpointKind::Reader,
                type_object: None,
                type_object_legacy_v1: false,
                type_information: None,
                has_explicit_ownership: true,
                has_ownership_strength: false,
                shm_capability: None,
                incarnation: 0,
                group_entity_id: None,
                endpoint_security_info: None,
            }
        }
        let announced = |data_representation: Vec<u16>| QoS {
            data_representation,
            ..QoS::best_effort()
        };
        // What `QoS::best_effort()` / `reliable()` leave it at, which is
        // what `Participant::create_reader` records when the application
        // sets no DATA_REPRESENTATION.
        let default_reader = local_reader(QoS::best_effort());
        assert!(default_reader.qos.data_representation.is_empty());
        let xcdr1_reader = local_reader(QoS::best_effort().data_representation_xcdr1());
        let xcdr2_reader = local_reader(QoS::best_effort().data_representation_xcdr2());

        for (writer, reader, blocked, why) in [
            (
                announced(vec![XCDR2]),
                &xcdr1_reader,
                true,
                "XCDR2 writer, XCDR-only reader: the offer is not requested",
            ),
            (
                announced(vec![XCDR2]),
                &xcdr2_reader,
                false,
                "XCDR2 writer, XCDR2 reader",
            ),
            (
                announced(vec![XCDR2]),
                &default_reader,
                false,
                "XCDR2 writer (an HDDS writer that set XCDR2, or a vendor's), \
                 reader that set none: it requests both",
            ),
            (
                announced(vec![XCDR1, XCDR2]),
                &default_reader,
                false,
                "a writer announcing [XCDR, XCDR2] (an HDDS 1.4 writer that set none, \
                 which encoded XCDR2 meanwhile), reader that set none",
            ),
            (
                announced(vec![]),
                &default_reader,
                false,
                "a writer that announced no list (XCDR), reader that set none",
            ),
            (
                announced(vec![]),
                &xcdr2_reader,
                true,
                "a writer that announced no list is XCDR, not XCDR2",
            ),
            (
                announced(vec![]),
                &xcdr1_reader,
                false,
                "a writer that announced no list, XCDR-only reader",
            ),
        ] {
            let writer = remote_announcement_for_verdict(&writer, false, false);
            assert_eq!(
                rxo_verdict(
                    &writer,
                    &local_reader_qos_for_verdict(&reader.qos),
                    crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                    None,
                    false,
                )
                .is_err(),
                blocked,
                "rxo_verdict: {why}"
            );
        }
    }
}

/// The (writer, reader) pair gate where it is set: a SEDP announcement fed
/// to the discovery dispatch, judged against the readers this participant
/// has registered.
#[cfg(test)]
mod pair_gate_at_the_handler {
    use super::super::wire_fixtures::{
        announcement_from, data_datagram, pid_offset, Harness, OUR_PREFIX, SAMPLE_AT,
        SEDP_PUBLICATIONS, SENDER_PREFIX, SPDP,
    };
    use crate::core::discovery::multicast::PacketKind;
    use crate::core::discovery::GUID;
    use crate::dds::qos::QoS;

    const WRITER_ENTITY: [u8; 4] = [0x00, 0x00, 0x12, 0x02];

    /// A writer announcement of `SENDER_PREFIX` on topic "Square", carrying
    /// PID_DATA_REPRESENTATION `representation`, or none at all when
    /// `None` (the PID is cut out of the parameter list: a peer that
    /// announces no list, XCDR by DDS-XTypes v1.3 Sec.7.6.3.1.1).
    fn writer_sample(representation: Option<Vec<u16>>) -> Vec<u8> {
        writer_sample_from(SENDER_PREFIX, representation)
    }

    /// `writer_sample`, announced by the participant `prefix`.
    fn writer_sample_from(prefix: [u8; 12], representation: Option<Vec<u16>>) -> Vec<u8> {
        use crate::protocol::dialect::{
            build_sedp_for_dialect, Dialect, Guid, QosProfile, SedpEndpointData,
        };
        let locators: Vec<std::net::SocketAddr> = vec!["192.0.2.7:7411".parse().expect("addr")];
        let qos = QosProfile {
            data_representation: representation.clone().unwrap_or_else(|| vec![0x0000]),
            ..Default::default()
        };
        let mut cdr = build_sedp_for_dialect(
            Dialect::Hdds,
            &SedpEndpointData {
                endpoint_guid: Guid {
                    prefix,
                    entity_id: WRITER_ENTITY,
                },
                participant_guid: Guid {
                    prefix,
                    entity_id: [0x00, 0x00, 0x01, 0xc1],
                },
                topic_name: "Square",
                type_name: "ShapeType",
                unicast_locators: &locators,
                multicast_locators: &[],
                qos: Some(&qos),
                type_object: None,
                user_data: None,
                hdds_shm_capability: None,
                hdds_peer_destination: false,
                group_entity_id: None,
                type_consistency: None,
                #[cfg(feature = "xtypes-structural-assignability")]
                type_information: None,
                emit_type_object_pid: true,
            },
        )
        .expect("build the announcement");
        if representation.is_none() {
            let at = pid_offset(&cdr, 0x0073).expect("the builder writes PID_DATA_REPRESENTATION");
            let length = usize::from(u16::from_le_bytes([cdr[at + 2], cdr[at + 3]]));
            cdr.drain(at..at + 4 + length);
            assert_eq!(pid_offset(&cdr, 0x0073), None, "fixture: the PID is gone");
        }
        cdr
    }

    /// A reader of this participant on "Square", of QoS `reader`, as the
    /// match registry holds it, and whether that registry refuses `writer`
    /// to it.
    fn reader_of(h: &Harness, reader: QoS) -> impl Fn(GUID) -> bool {
        let reg = std::sync::Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(
                &h.dispatch.fsm,
                OUR_PREFIX,
            ),
        );
        h.dispatch.fsm.set_match_registry(reg.clone());
        // The reader announces the type the writers of "Square" announce.
        let token = reg.register_reader_with_lifespan(
            "Square".into(),
            reader,
            crate::dds::match_notification::LocalType::new(
                crate::dds::cdr_negotiation::Xcdr1Encoding::native(),
                "ShapeType",
            ),
            None,
            |_, _, _, _, _| {},
            None,
            None,
            None,
            std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
            crate::transport::shm::ShmPolicy::default(),
        );
        move |writer: GUID| reg.is_writer_refused_by(&writer.as_bytes(), token.id())
    }

    /// Whether the writer is refused to a reader of this participant of QoS
    /// `reader` on "Square", once the writer announced `representation`.
    fn blocked(reader: QoS, representation: Option<Vec<u16>>) -> bool {
        let h = Harness::new();
        let (_, spdp) = announcement_from(SENDER_PREFIX);
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &spdp),
            SAMPLE_AT,
            None,
        );
        let refused = reader_of(&h, reader);
        let datagram = data_datagram(
            SENDER_PREFIX,
            &SEDP_PUBLICATIONS,
            &writer_sample(representation),
        );
        let (kind, at, meta, _) =
            crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
        h.feed(kind, &datagram, at.unwrap_or(SAMPLE_AT), meta);
        let writer = GUID::new(SENDER_PREFIX, WRITER_ENTITY);
        assert!(
            h.dispatch.fsm.current_endpoint("Square", &writer).is_some(),
            "fixture: the writer is admitted"
        );
        refused(writer)
    }

    /// The ordinary SEDP DATA path retains the same PARTITION as the
    /// reassembled path (DDS 1.4 Sec.2.2.3.13, RTPS 2.5 Sec.9.6.2.1).
    #[test]
    fn whole_writer_announcement_records_partition_metadata() {
        let h = Harness::new();
        let (_, spdp) = announcement_from(SENDER_PREFIX);
        h.feed(
            PacketKind::SPDP,
            &data_datagram(SENDER_PREFIX, &SPDP, &spdp),
            SAMPLE_AT,
            None,
        );
        let mut sample = writer_sample(None);
        let partition_at = pid_offset(&sample, 0x0029).expect("default PARTITION");
        assert_eq!(
            &sample[partition_at..partition_at + 8],
            &[0x29, 0, 4, 0, 0, 0, 0, 0]
        );
        assert_eq!(&sample[sample.len() - 4..], &[1, 0, 0, 0]);
        // PID_PARTITION: one CDR string, "a", padded to a four-byte boundary.
        let parameter = [0x29, 0, 12, 0, 1, 0, 0, 0, 2, 0, 0, 0, b'a', 0, 0, 0];
        sample.splice(partition_at..partition_at + 8, parameter);
        let datagram = data_datagram(SENDER_PREFIX, &SEDP_PUBLICATIONS, &sample);
        let (kind, at, meta, _) =
            crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
        h.feed(kind, &datagram, at.expect("SEDP DATA"), meta);
        let writer = GUID::new(SENDER_PREFIX, WRITER_ENTITY).as_bytes();
        assert_eq!(
            h.dispatch.registry.writer_partition(&writer),
            Some(crate::qos::partition::Partition::single("a"))
        );
    }

    /// An announcement of one of OUR writers that loops back (multicast
    /// loopback) never arms the pair gate, even when that writer and our
    /// only reader are incompatible: the pair is judged by the in-process
    /// binding and the discovery match. The gate must not read it as a
    /// remote writer, or the router would drop its samples.
    #[test]
    fn our_own_writer_looped_back_is_never_blocked() {
        let h = Harness::new();
        let refused = reader_of(&h, QoS::best_effort().data_representation_xcdr1());
        let datagram = data_datagram(
            OUR_PREFIX,
            &SEDP_PUBLICATIONS,
            &writer_sample_from(OUR_PREFIX, Some(vec![0x0002])),
        );
        let (kind, at, meta, _) =
            crate::core::discovery::multicast::classifier::classify_rtps(&datagram);
        h.feed(kind, &datagram, at.unwrap_or(SAMPLE_AT), meta);
        let writer = GUID::new(OUR_PREFIX, WRITER_ENTITY);
        assert!(!refused(writer));
        // The same announcement from a peer is refused: the fixture reaches
        // the gate.
        assert!(blocked(
            QoS::best_effort().data_representation_xcdr1(),
            Some(vec![0x0002])
        ));
    }

    #[test]
    fn the_gate_reads_the_writer_as_announced_and_our_reader_as_it_announces_itself() {
        assert!(blocked(
            QoS::best_effort().data_representation_xcdr2(),
            None
        ));
        assert!(!blocked(
            QoS::best_effort().data_representation_xcdr1(),
            None
        ));
        assert!(!blocked(QoS::best_effort(), None));
        assert!(!blocked(QoS::best_effort(), Some(vec![0x0002])));
        assert!(blocked(
            QoS::best_effort().data_representation_xcdr1(),
            Some(vec![0x0002])
        ));
    }
}

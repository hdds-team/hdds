// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP endpoint announcement for Participant.
//!
//!
//! Builds and publishes SEDP messages to announce local DataWriter
//! and DataReader endpoints to discovered remote participants.

use super::runtime::Participant;
use crate::core::discovery::multicast::SedpEndpointKind;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::{
    ENTITY_KIND_USER_READER_NO_KEY, ENTITY_KIND_USER_READER_WITH_KEY,
    ENTITY_KIND_USER_WRITER_NO_KEY, ENTITY_KIND_USER_WRITER_WITH_KEY,
};
#[cfg(target_os = "linux")]
use crate::dds::qos::Reliability;
use crate::dds::Result;
use crate::protocol::discovery::{EndpointSecurityInfo, SedpData};
use crate::xtypes::CompleteTypeObject;

use crate::core::discovery::multicast::rtps_packet::{
    build_heartbeat_submessage, build_heartbeat_submessage_final, build_sedp_dispose_packet,
    build_sedp_rtps_packet_secured, next_sedp_heartbeat_count, sedp_entity_ids,
};
use crate::core::discovery::multicast::{DiscoveryFsm, SedpHistory};
use crate::protocol::dialect::{get_encoder, Dialect};
use crate::protocol::discovery::ParseError;
use crate::transport::UdpTransport;
use std::sync::{Arc, RwLock, Weak};

#[cfg(target_os = "linux")]
use crate::transport::shm::format_shm_user_data;

impl Participant {
    /// Announce a writer of `topic` in the participant's implicit Publisher
    /// (`Participant::implicit_publisher_entity_id`).
    #[cfg(test)]
    pub(crate) fn announce_writer_endpoint<T: crate::dds::DDS>(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
    ) -> Result<SedpRetirement> {
        self.announce_writer_endpoint_in::<T>(topic, qos, self.implicit_publisher_entity_id())
    }

    /// Announce a writer of `topic` in the Publisher `publisher_entity_id`
    /// (PID_GROUP_GUID / PID_GROUP_ENTITY_ID of its SEDP announcement).
    pub(crate) fn announce_writer_endpoint_in<T: crate::dds::DDS>(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        publisher_entity_id: [u8; 4],
    ) -> Result<SedpRetirement> {
        let (type_name, type_object) = self.resolve_type_info::<T>(topic, None, None, false);
        self.announce_writer_endpoint_with_resolved(
            topic,
            qos,
            type_name,
            type_object,
            T::has_key(),
            publisher_entity_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn announce_writer_endpoint_with_type<T: crate::dds::DDS>(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        type_name: &str,
        type_object: Option<CompleteTypeObject>,
        type_name_only: bool,
        serialized_keys: bool,
        publisher_entity_id: [u8; 4],
    ) -> Result<SedpRetirement> {
        let (type_name, type_object) =
            self.resolve_type_info::<T>(topic, Some(type_name), type_object, type_name_only);
        self.announce_writer_endpoint_with_resolved(
            topic,
            qos,
            type_name,
            type_object,
            T::has_key() || serialized_keys,
            publisher_entity_id,
        )
    }

    fn announce_writer_endpoint_with_resolved(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        type_name: String,
        type_object: Option<CompleteTypeObject>,
        has_key: bool,
        publisher_entity_id: [u8; 4],
    ) -> Result<SedpRetirement> {
        // NOTE: TypeObject handling is delegated to the dialect encoder.
        // FastDdsEncoder ignores type_object (requires_type_object() = false)
        // RtiEncoder ignores it too (it writes no TypeObject PID)
        // No need to drop it here - the encoder decides based on detected dialect.

        // Raw-typed endpoints (e.g. DataWriter<RawBytes>) report T::has_key() =
        // false, but the caller-supplied TypeObject override can describe a
        // keyed type (IS_KEY member flags). RTPS conveys topic keyed-ness via
        // the endpoint GUID entityKind (WITH_KEY vs NO_KEY, RTPS v2.5 Table
        // 9.1), and a peer may validate it at SEDP time (on_inconsistent_topic on
        // mismatch), so derive the effective keyed-ness from the resolved
        // TypeObject as well.
        let has_key = has_key || type_object.as_ref().is_some_and(type_object_has_key);

        let entity_kind = if has_key {
            ENTITY_KIND_USER_WRITER_WITH_KEY
        } else {
            ENTITY_KIND_USER_WRITER_NO_KEY
        };
        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&self.guid.as_bytes()[..12]);
        let entity_id = self.next_user_entity_id(entity_kind);
        endpoint_guid_bytes[12..16].copy_from_slice(&entity_id);
        log::debug!(
            "[SEDP-ANNOUNCE] Writer entity_id={:02x?} has_key={}",
            entity_id,
            has_key
        );
        let endpoint_guid = GUID::from_bytes(endpoint_guid_bytes);

        let qos_hash = compute_qos_hash(topic, qos);

        // Get user data locators for SEDP announcement. If no transport is
        // available (e.g. IntraProcess mode), this stays empty and discovery
        // will remain local-only.
        let unicast_locators = if let Some(ref port_map) = self.port_mapping {
            if let Some(ref transport) = self.transport {
                transport.get_user_unicast_locators(port_map.user_unicast)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        // PID_USER_DATA (0x002c) carries the APPLICATION's UserDataQosPolicy
        // (DDS-RTPS Sec.9.6.2.2.1) verbatim. Never squat this for an internal
        // capability hint -- see `shm_capability` below, which uses the HDDS
        // vendor-specific PID_HDDS_SHM_CAPABILITY (0x8031) instead.
        let user_data = if qos.user_data.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&qos.user_data.value).into_owned())
        };

        // HDDS vendor-specific SHM capability hint (Linux only, BestEffort
        // only, and only when the participant's ShmPolicy has not disabled
        // SHM). SHM transport only works for BestEffort QoS - Reliable
        // requires UDP for retransmission.
        #[cfg(target_os = "linux")]
        let shm_capability = if self.shm_policy() != crate::transport::shm::ShmPolicy::Disable
            && matches!(qos.reliability, Reliability::BestEffort)
        {
            Some(format_shm_user_data())
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let shm_capability: Option<String> = None;

        // Propagate the TypeConsistencyEnforcement from the QoS into SedpData
        // so the SEDP builder emits PID_TYPE_CONSISTENCY_ENFORCEMENT (0x0074)
        // with the caller-supplied values rather than the hardcoded default.
        let type_consistency = qos.type_consistency.clone();

        // Feature `xtypes-structural-assignability`: pre-compute TypeInformation
        // with real dep hashes from the participant's type store. The build_sedp
        // path in build/mod.rs will emit these dep hashes in PID_TYPE_INFORMATION
        // (0x0075) instead of the zero-dep sentinel, letting cross-vendor readers
        // resolve the full type graph before matching.
        // Feature OFF: None -- build_sedp falls back to the zero-dep sentinel.
        #[cfg(feature = "xtypes-structural-assignability")]
        let type_information = type_object
            .as_ref()
            .and_then(|to| self.announced_type_information(&type_name, to));
        #[cfg(not(feature = "xtypes-structural-assignability"))]
        let type_information: Option<crate::protocol::discovery::types::TypeInformation> = None;

        let sedp_data = SedpData {
            topic_name: topic.to_string(),
            type_name,
            participant_guid: self.guid, // Add participant GUID for PID_PARTICIPANT_GUID (FastDDS interop)
            endpoint_guid,
            qos_hash,
            qos: Some(qos.clone()), // Pass actual QoS to use in build_sedp() instead of hardcoding!
            type_object,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators,
            user_data,
            shm_capability,
            // Our own QoS, known whole: the record discovery keeps of this
            // endpoint (`handle_sedp`, `EndpointInfo::from_sedp`) is judged
            // against our other endpoints, and must not be completed as a
            // remote announcement missing its PIDs would be (an absent
            // RELIABILITY read as a writer's RELIABLE default, an absent
            // OWNERSHIP as SHARED). Not read by the wire encoder.
            has_explicit_reliability: true,
            has_explicit_ownership: true,
            has_ownership_strength: matches!(
                qos.ownership.kind,
                crate::qos::ownership::OwnershipKind::Exclusive
            ),
            type_information,
            type_consistency,
            group_entity_id: Some(publisher_entity_id),
            // Not read by the wire encoder: the outgoing
            // PID_ENDPOINT_SECURITY_INFO is computed straight from the
            // governance by `Participant::endpoint_security_info` and
            // inserted into the serialized ParameterList
            // (`insert_endpoint_security_info`), never through this field.
            // This struct's copy of the field exists for the RECEIVE side.
            endpoint_security_info: None,
        };

        // Cache announcement for unicast replay / re-announces driven by SPDP
        // handler. No network send is performed here; spdp_handler will flush
        // cached SEDP once remote participants are known via SPDP.
        let security = self.endpoint_security_info(topic);
        let seq_num = self
            .sedp_announcements
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .announce_with(sedp_data.clone(), SedpEndpointKind::Writer, security);

        // Phase 1.4: Also add local endpoint to local registry for automatic matching
        if let Some(ref discovery_fsm) = self.discovery_fsm {
            discovery_fsm.handle_sedp(sedp_data.clone());
        }

        // Immediately announce this endpoint to all known peers.
        // Bypasses the SPDP barrier race: if the participant was discovered
        // before this writer was created, the SPDP handler would have sent
        // SEDP with an empty cache. This ensures late-created endpoints are
        // announced without waiting for the next SPDP round-trip.
        self.flush_sedp_to_known_peers(&sedp_data, SedpEndpointKind::Writer, seq_num, security);

        // Register writer GUID->topic mapping for DATA_FRAG routing.
        // DATA_FRAG packets are reassembled and routed via GUID lookup,
        // so we need this mapping even for local writers.
        if let Some(ref registry) = self.registry {
            registry.register_writer_guid(endpoint_guid_bytes, topic.to_string());
            log::debug!(
                "[SEDP-ANNOUNCE] Registered writer GUID {:02x?} -> topic '{}'",
                &endpoint_guid_bytes[..],
                topic
            );
        }

        self.graph_guard.set_trigger_value(true);

        Ok(self.sedp_retirement(endpoint_guid, SedpEndpointKind::Writer))
    }

    /// Allocate a reader endpoint's entity id ahead of its announcement.
    ///
    /// A reliable reader answers HEARTBEATs under this id (RTPS 2.5 8.4.12),
    /// so the parts built before the announcement (its HEARTBEAT handler,
    /// its proxies) must already carry the id SEDP will announce.
    pub(crate) fn reserve_reader_endpoint<T: crate::dds::DDS>(
        &self,
        topic: &str,
        type_name_override: Option<&str>,
        type_object_override: Option<CompleteTypeObject>,
        type_name_only: bool,
    ) -> ReaderReservation {
        // NOTE: TypeObject handling is delegated to the dialect encoder.
        // FastDdsEncoder ignores type_object (requires_type_object() = false)
        // RtiEncoder ignores it too (it writes no TypeObject PID)
        // No need to drop it here - the encoder decides based on detected dialect.
        let (type_name, type_object) = self.resolve_type_info::<T>(
            topic,
            type_name_override,
            type_object_override,
            type_name_only,
        );

        // Same effective keyed-ness derivation as the writer path: honor an
        // IS_KEY-carrying TypeObject override for raw-typed readers so the
        // announced entityKind matches the actual topic kind (WITH_KEY 0x07 vs
        // NO_KEY 0x04). See announce_writer_endpoint_with_resolved above.
        //
        // A wire-identity capture type (the raw reader's CapturedBytes) keeps
        // every sample keyed internally so the writer's PID_KEY_HASH survives,
        // but that says nothing about the topic: its announced kind comes from
        // the TypeObject alone, as for RawBytes. A keyless topic announced
        // WITH_KEY is refused by peers as an inconsistent topic.
        let has_key = if T::captures_wire_identity() {
            type_object.as_ref().is_some_and(type_object_has_key)
        } else {
            T::has_key() || type_object.as_ref().is_some_and(type_object_has_key)
        };

        let entity_kind = if has_key {
            ENTITY_KIND_USER_READER_WITH_KEY
        } else {
            ENTITY_KIND_USER_READER_NO_KEY
        };
        let entity_id = self.next_user_entity_id(entity_kind);
        log::debug!(
            "[SEDP-ANNOUNCE] Reader entity_id={:02x?} has_key={}",
            entity_id,
            has_key
        );
        ReaderReservation {
            entity_id,
            type_name,
            type_object,
        }
    }

    /// Announce a reader endpoint under the entity id it reserved.
    pub(crate) fn announce_reserved_reader(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        reservation: ReaderReservation,
    ) -> Result<SedpRetirement> {
        let ReaderReservation {
            entity_id,
            type_name,
            type_object,
        } = reservation;
        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&self.guid.as_bytes()[..12]);
        endpoint_guid_bytes[12..16].copy_from_slice(&entity_id);
        let endpoint_guid = GUID::from_bytes(endpoint_guid_bytes);

        let qos_hash = compute_qos_hash(topic, qos);

        // Get user data locators for SEDP announcement. If no transport is
        // available (e.g. IntraProcess mode), this stays empty and discovery
        // will remain local-only.
        let unicast_locators = if let Some(ref port_map) = self.port_mapping {
            if let Some(ref transport) = self.transport {
                transport.get_user_unicast_locators(port_map.user_unicast)
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        // PID_USER_DATA (0x002c) carries the APPLICATION's UserDataQosPolicy
        // (DDS-RTPS Sec.9.6.2.2.1) verbatim. Never squat this for an internal
        // capability hint -- see `shm_capability` below, which uses the HDDS
        // vendor-specific PID_HDDS_SHM_CAPABILITY (0x8031) instead.
        let user_data = if qos.user_data.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&qos.user_data.value).into_owned())
        };

        // HDDS vendor-specific SHM capability hint (Linux only, BestEffort
        // only, and only when the participant's ShmPolicy has not disabled
        // SHM).
        #[cfg(target_os = "linux")]
        let shm_capability = if self.shm_policy() != crate::transport::shm::ShmPolicy::Disable
            && matches!(qos.reliability, Reliability::BestEffort)
        {
            Some(format_shm_user_data())
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let shm_capability: Option<String> = None;

        // Propagate the TypeConsistencyEnforcement from the QoS into SedpData.
        let type_consistency = qos.type_consistency.clone();

        // Feature `xtypes-structural-assignability`: pre-compute TypeInformation
        // with real dep hashes (same logic as the writer path above).
        #[cfg(feature = "xtypes-structural-assignability")]
        let type_information = type_object
            .as_ref()
            .and_then(|to| self.announced_type_information(&type_name, to));
        #[cfg(not(feature = "xtypes-structural-assignability"))]
        let type_information: Option<crate::protocol::discovery::types::TypeInformation> = None;

        let sedp_data = SedpData {
            topic_name: topic.to_string(),
            type_name,
            participant_guid: self.guid, // Add participant GUID for PID_PARTICIPANT_GUID (FastDDS interop)
            endpoint_guid,
            qos_hash,
            qos: Some(qos.clone()), // Pass actual QoS to use in build_sedp() instead of hardcoding!
            type_object,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators,
            user_data,
            shm_capability,
            // Our own QoS, known whole (see the writer's announcement).
            has_explicit_reliability: true,
            has_explicit_ownership: true,
            has_ownership_strength: false,
            type_information,
            type_consistency,
            group_entity_id: None,
            // See the writer's announcement above: the outgoing
            // PID_ENDPOINT_SECURITY_INFO never goes through this field.
            endpoint_security_info: None,
        };

        // Cache announcement for unicast replay to discovered peers
        let security = self.endpoint_security_info(topic);
        let seq_num = self
            .sedp_announcements
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .announce_with(sedp_data.clone(), SedpEndpointKind::Reader, security);

        // Phase 1.4: Also add local endpoint to local registry for automatic matching
        if let Some(ref discovery_fsm) = self.discovery_fsm {
            discovery_fsm.handle_sedp(sedp_data.clone());
        }

        // Immediately announce this endpoint to all known peers.
        self.flush_sedp_to_known_peers(&sedp_data, SedpEndpointKind::Reader, seq_num, security);

        self.graph_guard.set_trigger_value(true);

        Ok(self.sedp_retirement(endpoint_guid, SedpEndpointKind::Reader))
    }

    /// The retirement of an endpoint this participant just announced, for
    /// the DataWriter or DataReader to hold (`SedpRetirement`).
    fn sedp_retirement(&self, endpoint: GUID, kind: SedpEndpointKind) -> SedpRetirement {
        SedpRetirement {
            endpoint,
            kind,
            history: Arc::downgrade(&self.sedp_announcements),
            fsm: self.discovery_fsm.as_ref().map(Arc::downgrade),
            transport: self.transport.as_ref().map(Arc::downgrade),
            #[cfg(test)]
            on_dispose_sent: None,
        }
    }
}

/// The deletion of a local DataWriter or DataReader, as SEDP announces it
/// (RTPS v2.5 Sec.8.5.4.4, Tables 8.82 and 8.83: the endpoint's data-object
/// leaves the history of the SEDP writer each time the endpoint is
/// deleted).
///
/// Created when the endpoint is announced and owned by the endpoint; when
/// dropped it retires the endpoint from the participant's `SedpHistory`
/// (its announcement becomes a GAP, the dispose of its instance is
/// appended) and sends the dispose, followed by a HEARTBEAT, to every peer
/// already known, so they unmatch it now rather than when the whole
/// participant leaves. A peer discovered later gets the dispose with the
/// replay. The endpoint also leaves this participant's own discovery,
/// where it entered at its announcement.
///
/// It holds only weak handles: it does nothing once the participant is
/// gone, and sends nothing once the participant has closed its history on
/// its way out, because the participant's SPDP dispose retires every
/// endpoint at once and nothing goes out on SEDP after it (`Drop for
/// Participant`).
#[must_use = "dropping the token retires the endpoint it announced"]
pub(crate) struct SedpRetirement {
    endpoint: GUID,
    kind: SedpEndpointKind,
    history: Weak<RwLock<SedpHistory>>,
    fsm: Option<Weak<DiscoveryFsm>>,
    transport: Option<Weak<UdpTransport>>,
    /// Run once the dispose has been handed to the known peers, for a test
    /// that pins what must precede it.
    #[cfg(test)]
    on_dispose_sent: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl SedpRetirement {
    /// The entity id of the endpoint announced.
    pub(crate) fn entity_id(&self) -> [u8; 4] {
        self.endpoint.entity_id
    }

    /// Run `hook` once the dispose has been handed to the known peers.
    #[cfg(test)]
    pub(crate) fn on_dispose_sent(&mut self, hook: Box<dyn FnOnce() + Send + Sync>) {
        self.on_dispose_sent = Some(hook);
    }

    /// Retire the endpoint now (see the type's documentation). Once.
    ///
    /// It also leaves this participant's own discovery, where it entered at
    /// its announcement (`DiscoveryFsm::remove_local_endpoint`), whether or
    /// not its dispose still goes out.
    fn retire(&mut self) {
        self.announce_retirement();
        if let Some(fsm) = self.fsm.as_ref().and_then(Weak::upgrade) {
            fsm.remove_local_endpoint(self.endpoint);
        }
    }

    /// The SEDP side of `retire`: the dispose, to every peer already known.
    fn announce_retirement(&mut self) {
        let Some(history) = self.history.upgrade() else {
            return;
        };
        // Held across the sends: the participant closes the history under
        // this lock before it says farewell, so a dispose that got its number
        // here is on the wire before the farewell is.
        let mut history = history.write().unwrap_or_else(|e| e.into_inner());
        let Some(seq_num) = history.retire(&self.endpoint, self.kind) else {
            return;
        };
        let first_seq = history.first_available(self.kind);
        let discovery_protected = history
            .security_at(self.kind, seq_num)
            .map(|security| security.is_discovery_protected());
        let fsm = self.fsm.as_ref().and_then(Weak::upgrade);
        let transport = self.transport.as_ref().and_then(Weak::upgrade);
        let (Some(fsm), Some(transport)) = (fsm, transport) else {
            return;
        };
        let our_prefix = self.endpoint.prefix;
        let (reader_id, writer_id) = sedp_entity_ids(self.kind);
        let change = SedpChange {
            kind: self.kind,
            seq: seq_num,
            our_prefix,
            discovery_protected,
        };
        send_to_known_peers(&fsm, &transport, &change, |peer, dialect| {
            let packet = build_sedp_dispose_packet(
                &self.endpoint,
                self.kind,
                &our_prefix,
                Some(&peer.guid.prefix),
                seq_num,
                dialect,
            );
            // The writer's range now ends at the dispose, so a reader that
            // missed it asks for it; it starts at the first change not
            // superseded (RTPS v2.5 Sec.8.3.8.6), so a reader that never got
            // the retired prefix does not ask for it.
            let count = next_sedp_heartbeat_count();
            let heartbeat = if get_encoder(dialect).sedp_heartbeat_final(&writer_id) {
                build_heartbeat_submessage_final(&reader_id, &writer_id, first_seq, seq_num, count)
            } else {
                build_heartbeat_submessage(&reader_id, &writer_id, first_seq, seq_num, count)
            };
            Ok((packet, heartbeat))
        });
        #[cfg(test)]
        if let Some(hook) = self.on_dispose_sent.take() {
            hook();
        }
        drop(history);
        log::debug!(
            "[SEDP-RETIRE] {:?} {:?} retired under seq={}",
            self.kind,
            self.endpoint,
            seq_num
        );
    }
}

impl Drop for SedpRetirement {
    fn drop(&mut self) {
        self.retire();
    }
}

/// A reader endpoint whose entity id is allocated but not yet announced
/// (`Participant::reserve_reader_endpoint`).
pub(crate) struct ReaderReservation {
    entity_id: [u8; 4],
    type_name: String,
    type_object: Option<CompleteTypeObject>,
}

impl ReaderReservation {
    /// The entity id the reader will be announced under.
    pub(crate) fn entity_id(&self) -> [u8; 4] {
        self.entity_id
    }
}

impl Participant {
    /// The name and TypeObject an endpoint announces.
    ///
    /// The builders have already settled a registered or adopted name into
    /// `type_name_override` (`Participant::settle_type`), so the name announced
    /// here is the one the intra-process match key is built from.
    /// `type_name_only`: the override is a name alone (adopted or the
    /// placeholder), so no TypeObject registered under it is attached.
    fn resolve_type_info<T: crate::dds::DDS>(
        &self,
        topic: &str,
        type_name_override: Option<&str>,
        type_object_override: Option<CompleteTypeObject>,
        type_name_only: bool,
    ) -> (String, Option<CompleteTypeObject>) {
        let _ = topic;
        let type_descriptor = T::type_descriptor();

        #[cfg(feature = "xtypes")]
        {
            if std::env::var("HDDS_DISABLE_TYPE_OBJECT").is_ok() {
                if let Some(type_name) = type_name_override {
                    return (type_name.to_string(), None);
                }
                return (type_descriptor.type_name.to_string(), None);
            }

            if let Some(type_name) = type_name_override {
                let mut type_object = type_object_override;
                if type_object.is_none() && !type_name_only {
                    type_object = self
                        .registered_type(type_name)
                        .map(|handle| handle.complete.clone());
                }
                return (type_name.to_string(), type_object);
            }

            let type_object = type_object_override.or_else(|| {
                T::get_type_object().or_else(|| {
                    self.registered_type(type_descriptor.type_name)
                        .map(|handle| handle.complete.clone())
                })
            });

            (type_descriptor.type_name.to_string(), type_object)
        }

        #[cfg(not(feature = "xtypes"))]
        {
            let _ = type_name_only;
            let type_name = type_name_override
                .map(|name| name.to_string())
                .unwrap_or_else(|| type_descriptor.type_name.to_string());
            let type_object = type_object_override.or_else(T::get_type_object);
            (type_name, type_object)
        }
    }
}

impl Participant {
    /// The `EndpointSecurityInfo` of an endpoint of `topic` (DDS-Security
    /// v1.1 Sec.7.2.8): the masks of the attributes the governance gives it
    /// (Sec.9.4.1.2.6), or the explicit payload encryption configuration
    /// when no governance document is installed.
    ///
    /// The endpoint was admitted by `check_create_endpoint`, which refuses a
    /// topic no rule matches (Sec.9.4.1.2.7), so the attributes exist. Were
    /// they missing anyway, the endpoint is announced as discovery
    /// protected: kept from participants that have not authenticated rather
    /// than shown to them.
    pub(crate) fn endpoint_security_info(&self, topic: &str) -> Option<EndpointSecurityInfo> {
        #[cfg(feature = "security")]
        {
            let suite = self.security.as_ref()?;
            Some(
                match crate::security::crypto::user_data::endpoint_security_info(suite, topic) {
                    Ok(attributes) => attributes,
                    Err(e) => {
                        log::error!(
                            "[security] no governance attributes for topic '{}' ({}): its \
                         endpoint is announced as discovery protected",
                            topic,
                            e
                        );
                        EndpointSecurityInfo {
                            endpoint_security_attributes: EndpointSecurityInfo::IS_VALID
                                | EndpointSecurityInfo::IS_DISCOVERY_PROTECTED,
                            plugin_endpoint_security_attributes: EndpointSecurityInfo::IS_VALID,
                        }
                    }
                },
            )
        }
        #[cfg(not(feature = "security"))]
        {
            let _ = topic;
            None
        }
    }

    /// Send a single SEDP announcement to all already-discovered peers.
    ///
    /// This is called immediately when a new writer/reader is created, so that
    /// peers that were discovered before this endpoint existed learn about it
    /// without waiting for the next SPDP round-trip (which could be 5+ seconds).
    ///
    /// `seq_num` is the endpoint's STABLE positional sequence number,
    /// the one `SedpHistory::announce` gave it and every replay
    /// (preallocate_sedp_sequence_numbers) and re-transmit
    /// (retransmit_sedp_data) uses, never a number from the global atomic
    /// counter: the same endpoint under different numbers, or two endpoints
    /// under the same one, makes receivers that dedup SEDP by sequence number
    /// (HDDS itself among them) drop an announcement, and
    /// that reader/writer never matches.
    fn flush_sedp_to_known_peers(
        &self,
        sedp_data: &SedpData,
        kind: SedpEndpointKind,
        seq_num: u64,
        security: Option<EndpointSecurityInfo>,
    ) {
        let (Some(ref discovery_fsm), Some(ref transport)) = (&self.discovery_fsm, &self.transport)
        else {
            return;
        };
        flush_sedp_to(
            discovery_fsm,
            transport,
            &self.guid.prefix,
            sedp_data,
            kind,
            seq_num,
            security,
        );
        log::debug!(
            "[SEDP-FLUSH] Announced {:?} '{}' (seq={}) to known peers",
            kind,
            sedp_data.topic_name,
            seq_num
        );
    }
}

/// One SEDP announcement, from `our_prefix`, to every participant already
/// discovered, each built with the PID_TYPE_OBJECT class discovery keeps for
/// it (`ParticipantInfo::type_object_pid`).
fn flush_sedp_to(
    discovery_fsm: &DiscoveryFsm,
    transport: &UdpTransport,
    our_prefix: &[u8; 12],
    sedp_data: &SedpData,
    kind: SedpEndpointKind,
    seq_num: u64,
    security: Option<EndpointSecurityInfo>,
) {
    let change = SedpChange {
        kind,
        seq: seq_num,
        our_prefix: *our_prefix,
        discovery_protected: security.map(|security| security.is_discovery_protected()),
    };
    send_to_known_peers(discovery_fsm, transport, &change, |peer, dialect| {
        build_sedp_rtps_packet_secured(
            sedp_data,
            kind,
            our_prefix,
            Some(&peer.guid.prefix),
            seq_num,
            dialect,
            peer.type_object_pid(),
            security,
        )
        .map(|packet| (packet, Vec::new()))
    });
}

/// The SEDP change a send is for: its writer and number, and whether its
/// endpoint is announced on the secure topics (`SedpSend::discovery_protected`).
struct SedpChange {
    kind: SedpEndpointKind,
    seq: u64,
    our_prefix: [u8; 12],
    discovery_protected: Option<bool>,
}

/// Send what `build` makes for each participant already discovered, to each
/// of its locators, encoded in the locked dialect (Hybrid until one is).
///
/// `build` returns the SEDP DATA datagram and what follows it (a HEARTBEAT,
/// or nothing). Where the DATA goes is `DiscoveryFsm::sedp_for_peer`'s
/// decision: on the secure SEDP topic for an endpoint announced there (DDS
/// Security v1.1 Sec.7.4.1.7, 7.4.1.8, Table 29), where it alone can be taken
/// as a change to what it announced before; on the regular topic otherwise.
/// A participant that is not to receive the change gets its number as a GAP
/// of the regular writer, followed by the same trailer.
fn send_to_known_peers(
    discovery_fsm: &DiscoveryFsm,
    transport: &UdpTransport,
    change: &SedpChange,
    build: impl Fn(
        &crate::core::discovery::multicast::ParticipantInfo,
        Dialect,
    ) -> std::result::Result<(Vec<u8>, Vec<u8>), ParseError>,
) {
    let dialect = discovery_fsm
        .get_locked_dialect()
        .unwrap_or(Dialect::Hybrid);
    for peer in discovery_fsm.get_participants() {
        if peer.endpoints.is_empty() {
            continue;
        }
        let built = build(&peer, dialect).map(|(data, trailer)| {
            let mut pkt = discovery_fsm
                .sedp_for_peer(&peer.guid.prefix, data, change.discovery_protected)
                .or_else(|| {
                    crate::core::discovery::multicast::sedp_gap(
                        change.kind,
                        change.seq,
                        change.seq,
                        &change.our_prefix,
                    )
                    .ok()
                })?;
            pkt.extend_from_slice(&trailer);
            Some(pkt)
        });
        match built {
            Ok(None) => continue,
            Ok(Some(pkt)) => {
                for ep in &peer.endpoints {
                    match transport.send_to_endpoint(&pkt, ep) {
                        Ok(_) => log::debug!("[SEDP-FLUSH] Sent to {}", ep),
                        Err(e) => log::debug!("[SEDP-FLUSH] Failed to send to {}: {}", ep, e),
                    }
                }
            }
            Err(e) => log::debug!("[SEDP-FLUSH] Failed to build SEDP packet: {:?}", e),
        }
    }
}

/// Returns true when a TypeObject describes a keyed topic type.
///
/// Per DDS-XTypes v1.3 a topic type is keyed when the type itself declares
/// key members:
/// - a Struct with at least one member carrying `MemberFlag::IS_KEY`
///   (0x0020, its own bit - distinct from the TRY_CONSTRUCT bits 0x0001 /
///   0x0002, so a plain bit test is exact);
/// - a Union whose discriminator is `@key` (IS_KEY in the header's
///   `discriminator_flags`) or whose members mirror IS_KEY (HDDS keeps the
///   discriminator key flag mirrored onto members internally, see
///   `xtypes/cdr2/unions.rs`).
///
/// Keyed-ness is a TOP-LEVEL property: a member typed as a keyed struct only
/// makes the enclosing type keyed when that member itself carries IS_KEY
/// (e.g. struct_key_struct_1). Nested key content never changes the
/// top-level topic kind, so no recursion is needed. All other kinds (enum,
/// bitmask, alias, collections, ...) are never keyed topic types here.
pub(crate) fn type_object_has_key(type_object: &CompleteTypeObject) -> bool {
    use crate::xtypes::MemberFlag;
    match type_object {
        CompleteTypeObject::Struct(st) => st
            .member_seq
            .iter()
            .any(|m| m.common.member_flags.contains(MemberFlag::IS_KEY)),
        CompleteTypeObject::Union(ut) => {
            ut.header.discriminator_flags.contains(MemberFlag::IS_KEY)
                || ut
                    .member_seq
                    .iter()
                    .any(|m| m.common.member_flags.contains(MemberFlag::IS_KEY))
        }
        _ => false,
    }
}

fn compute_qos_hash(topic: &str, qos: &crate::dds::QoS) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = FNV_OFFSET;

    for byte in topic.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    let reliability_byte = match qos.reliability {
        crate::dds::qos::Reliability::BestEffort => 0u8,
        crate::dds::qos::Reliability::Reliable => 1u8,
    };
    hash ^= u64::from(reliability_byte);
    hash = hash.wrapping_mul(FNV_PRIME);

    let durability_byte = match qos.durability {
        crate::dds::qos::Durability::Volatile => 0u8,
        crate::dds::qos::Durability::TransientLocal => 1u8,
        crate::dds::qos::Durability::Transient => 2u8,
        crate::dds::qos::Durability::Persistent => 3u8,
    };
    hash ^= u64::from(durability_byte);
    hash = hash.wrapping_mul(FNV_PRIME);

    hash
}

#[cfg(test)]
mod tests {
    use super::super::live_capture::RawBytes;
    use super::type_object_has_key;
    use crate::core::discovery::multicast::SedpEndpointKind;
    use crate::core::rtps_constants::{
        ENTITY_KIND_USER_READER_NO_KEY, ENTITY_KIND_USER_READER_WITH_KEY,
        ENTITY_KIND_USER_WRITER_NO_KEY, ENTITY_KIND_USER_WRITER_WITH_KEY,
    };
    use crate::dds::{Participant, QoS, TransportMode};
    use crate::protocol::discovery::SedpData;
    use crate::test_support::domains::unique_domain;
    use crate::xtypes::{
        CommonStructMember, CommonUnionMember, CompleteMemberDetail, CompleteStructHeader,
        CompleteStructMember, CompleteStructType, CompleteTypeDetail, CompleteTypeObject,
        CompleteUnionHeader, CompleteUnionMember, CompleteUnionType, EquivalenceHash, MemberFlag,
        StructTypeFlag, TypeIdentifier, UnionTypeFlag,
    };

    fn struct_member(
        id: u32,
        name: &str,
        flags: MemberFlag,
        type_id: TypeIdentifier,
    ) -> CompleteStructMember {
        CompleteStructMember {
            common: CommonStructMember {
                member_id: id,
                member_flags: flags,
                member_type_id: type_id,
            },
            detail: CompleteMemberDetail::new(name),
        }
    }

    fn struct_type_object(name: &str, members: Vec<CompleteStructMember>) -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_APPENDABLE,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new(name),
            },
            member_seq: members,
        })
    }

    fn keyed_struct_type_object() -> CompleteTypeObject {
        struct_type_object(
            "KeyedShape",
            vec![
                struct_member(
                    0,
                    "color",
                    MemberFlag(MemberFlag::IS_KEY.0 | MemberFlag::TRY_CONSTRUCT1.0),
                    TypeIdentifier::TK_INT32,
                ),
                struct_member(1, "x", MemberFlag::TRY_CONSTRUCT1, TypeIdentifier::TK_INT32),
            ],
        )
    }

    fn unkeyed_struct_type_object() -> CompleteTypeObject {
        struct_type_object(
            "PlainShape",
            vec![
                struct_member(0, "x", MemberFlag::TRY_CONSTRUCT1, TypeIdentifier::TK_INT32),
                struct_member(1, "y", MemberFlag::TRY_CONSTRUCT1, TypeIdentifier::TK_INT32),
            ],
        )
    }

    fn union_type_object(
        discriminator_flags: MemberFlag,
        member_flags: MemberFlag,
    ) -> CompleteTypeObject {
        CompleteTypeObject::Union(CompleteUnionType {
            union_flags: UnionTypeFlag::IS_APPENDABLE,
            header: CompleteUnionHeader {
                discriminator: TypeIdentifier::TK_INT32,
                discriminator_flags,
                detail: CompleteTypeDetail::new("SwitchType"),
            },
            member_seq: vec![CompleteUnionMember {
                common: CommonUnionMember {
                    member_id: 1,
                    member_flags,
                    member_type_id: TypeIdentifier::TK_INT32,
                    label_seq: vec![0],
                },
                detail: CompleteMemberDetail::new("case_a"),
            }],
        })
    }

    #[test]
    fn type_object_has_key_keyed_struct() {
        assert!(type_object_has_key(&keyed_struct_type_object()));
    }

    #[test]
    fn type_object_has_key_unkeyed_struct() {
        // TRY_CONSTRUCT1 (0x0001) must not be mistaken for IS_KEY (0x0020).
        assert!(!type_object_has_key(&unkeyed_struct_type_object()));
    }

    #[test]
    fn type_object_has_key_union_key_discriminator() {
        // @key discriminator: IS_KEY carried in the header discriminator_flags.
        let flags = MemberFlag(
            MemberFlag::IS_KEY.0 | MemberFlag::TRY_CONSTRUCT1.0 | MemberFlag::IS_MUST_UNDERSTAND.0,
        );
        assert!(type_object_has_key(&union_type_object(
            flags,
            MemberFlag::TRY_CONSTRUCT1
        )));
    }

    #[test]
    fn type_object_has_key_union_mirrored_member_key() {
        // HDDS mirrors a @key discriminator onto members internally
        // (xtypes/cdr2/unions.rs); either representation must count.
        let member_flags = MemberFlag(MemberFlag::IS_KEY.0 | MemberFlag::TRY_CONSTRUCT1.0);
        assert!(type_object_has_key(&union_type_object(
            MemberFlag::empty(),
            member_flags
        )));
    }

    #[test]
    fn type_object_has_key_unkeyed_union() {
        assert!(!type_object_has_key(&union_type_object(
            MemberFlag::TRY_CONSTRUCT1,
            MemberFlag::TRY_CONSTRUCT1
        )));
    }

    #[test]
    fn type_object_has_key_nested_keyed_type_without_top_level_key() {
        // A member typed as a (keyed) nested struct, referenced by hash, but
        // WITHOUT IS_KEY on the member itself: the top-level type is NOT
        // keyed. Only the type's own member flags decide topic keyed-ness.
        let nested_ref = TypeIdentifier::Minimal(EquivalenceHash::from_bytes([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
        ]));
        let to = struct_type_object(
            "Outer",
            vec![struct_member(
                0,
                "inner",
                MemberFlag::TRY_CONSTRUCT1,
                nested_ref,
            )],
        );
        assert!(!type_object_has_key(&to));
    }

    /// `domain` comes from a `DomainLease` the CALLER holds: the participant
    /// returned here outlives this function, so the reservation has to
    /// outlive it in turn.
    ///
    /// `TransportMode::IntraProcess` binds no socket, so the leased id is not
    /// about RTPS ports. It is about `DomainRegistry::global()`, which is a
    /// process-wide map keyed by domain id alone: on a fixed domain every
    /// test of the lib binary naming it would share one `DomainState`, kept
    /// apart only by disjoint topic names.
    fn test_participant(name: &str, domain: u32) -> std::sync::Arc<Participant> {
        Participant::builder(name)
            .with_transport(TransportMode::IntraProcess)
            .domain_id(domain)
            .build()
            .expect("intra-process participant")
    }

    #[cfg(target_os = "linux")]
    fn test_participant_with_shm_policy(
        name: &str,
        policy: crate::transport::shm::ShmPolicy,
    ) -> std::sync::Arc<Participant> {
        Participant::builder(name)
            .with_transport(TransportMode::IntraProcess)
            .domain_id(39)
            .shm_policy(policy)
            .build()
            .expect("intra-process participant")
    }

    /// Look up the cached `SedpData` for a topic name announced as a writer.
    #[cfg(target_os = "linux")]
    fn sedp_data_for_writer_topic(p: &Participant, topic: &str) -> Option<SedpData> {
        let guard = p
            .sedp_announcements
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let found = guard
            .alive()
            .find(|(sd, kind)| sd.topic_name == topic && *kind == SedpEndpointKind::Writer)
            .map(|(sd, _)| sd.clone());
        found
    }

    /// (c): `ShmPolicy::Disable` must not put the SHM capability hint into
    /// the `SedpData` this participant builds. A hint gated only on
    /// QoS/platform (never on ShmPolicy) would let a participant configured
    /// with `Disable` still build a SedpData carrying `shm=1;...` (it would
    /// not reach the wire, since the SEDP encoder drops the field -- see the
    /// round-trip tests in `dialect::hdds`). Only Linux + BestEffort ever
    /// sets this field.
    #[cfg(target_os = "linux")]
    #[test]
    fn shm_disable_does_not_set_sedp_shm_capability() {
        let p = test_participant_with_shm_policy(
            "announce_shm_disable",
            crate::transport::shm::ShmPolicy::Disable,
        );
        let qos = QoS::best_effort();
        let _writer = p
            .announce_writer_endpoint::<RawBytes>("announce_shm_disable_topic", &qos)
            .expect("announce writer under ShmPolicy::Disable");

        let sd = sedp_data_for_writer_topic(&p, "announce_shm_disable_topic")
            .expect("writer announcement must be cached");
        assert!(
            sd.shm_capability.is_none(),
            "ShmPolicy::Disable must not advertise SHM capability, got {:?}",
            sd.shm_capability
        );
    }

    /// (c) control: `ShmPolicy::Prefer` (default) keeps the pre-existing
    /// behavior -- BestEffort + Linux still sets the SHM hint, and it lands
    /// in `shm_capability`, never in `user_data`.
    #[cfg(target_os = "linux")]
    #[test]
    fn shm_prefer_still_sets_sedp_shm_capability() {
        let p = test_participant_with_shm_policy(
            "announce_shm_prefer",
            crate::transport::shm::ShmPolicy::Prefer,
        );
        let qos = QoS::best_effort();
        let _writer = p
            .announce_writer_endpoint::<RawBytes>("announce_shm_prefer_topic", &qos)
            .expect("announce writer under ShmPolicy::Prefer");

        let sd = sedp_data_for_writer_topic(&p, "announce_shm_prefer_topic")
            .expect("writer announcement must be cached");
        assert!(
            sd.shm_capability
                .as_deref()
                .is_some_and(|s| s.starts_with("shm=1;")),
            "ShmPolicy::Prefer must still advertise SHM capability, got {:?}",
            sd.shm_capability
        );
        assert!(
            sd.user_data.is_none(),
            "no application user_data was set on this QoS, so SedpData::user_data \
             must stay None (the SHM hint must never appear there), got {:?}",
            sd.user_data
        );
    }

    /// An application that sets `QoS::user_data` must see ITS bytes in
    /// `SedpData::user_data`, completely independent of `shm_capability`,
    /// under every `ShmPolicy`: `SedpData::user_data` must not be
    /// overwritten with the SHM hint (or None) while the application's own
    /// UserDataQosPolicy goes unread.
    #[cfg(target_os = "linux")]
    #[test]
    fn application_user_data_propagates_independently_of_shm_policy() {
        for policy in [
            crate::transport::shm::ShmPolicy::Prefer,
            crate::transport::shm::ShmPolicy::Disable,
        ] {
            let p = test_participant_with_shm_policy(
                &format!("announce_app_user_data_{policy:?}"),
                policy,
            );
            let mut qos = QoS::best_effort();
            qos.user_data = crate::qos::metadata::UserData::new(b"app-metadata=v1".to_vec());
            let topic = format!("announce_app_user_data_topic_{policy:?}");
            let _writer = p
                .announce_writer_endpoint::<RawBytes>(&topic, &qos)
                .expect("announce writer with application user_data");

            let sd = sedp_data_for_writer_topic(&p, &topic).expect("writer announcement cached");
            assert_eq!(
                sd.user_data.as_deref(),
                Some("app-metadata=v1"),
                "ShmPolicy::{policy:?}: SedpData::user_data must carry the application's \
                 own UserDataQosPolicy, got {:?}",
                sd.user_data
            );
        }
    }

    #[test]
    fn announce_writer_kind_honors_type_object_key_override() {
        // RawBytes::has_key() == false; the keyed TypeObject override alone
        // must select the WITH_KEY writer entity kind (0x02).
        let domain = unique_domain();
        let p = test_participant("announce_writer_kind_keyed", domain.id());
        let qos = QoS::best_effort();

        let keyed_id = p
            .announce_writer_endpoint_with_type::<RawBytes>(
                "announce_kind_keyed_w",
                &qos,
                "KeyedShape",
                Some(keyed_struct_type_object()),
                false,
                false,
                p.implicit_publisher_entity_id(),
            )
            .expect("announce keyed writer");
        assert_eq!(keyed_id.entity_id()[3], ENTITY_KIND_USER_WRITER_WITH_KEY);

        // Unkeyed control: no key in the TypeObject keeps NO_KEY (0x03).
        let unkeyed_id = p
            .announce_writer_endpoint_with_type::<RawBytes>(
                "announce_kind_unkeyed_w",
                &qos,
                "PlainShape",
                Some(unkeyed_struct_type_object()),
                false,
                false,
                p.implicit_publisher_entity_id(),
            )
            .expect("announce unkeyed writer");
        assert_eq!(unkeyed_id.entity_id()[3], ENTITY_KIND_USER_WRITER_NO_KEY);
    }

    /// The raw reader keeps every sample keyed internally (CapturedBytes) to
    /// preserve the writer's PID_KEY_HASH; its announced entityKind must still
    /// follow the topic's TypeObject, never that internal choice.
    #[test]
    fn captured_raw_reader_kind_follows_the_type_object() {
        use super::super::live_capture::CapturedBytes;
        let domain = unique_domain();
        let p = test_participant("announce_captured_kind", domain.id());
        let qos = QoS::best_effort();

        let mut held = Vec::new();
        for (topic, name, to) in [
            (
                "captured_kind_unkeyed_r",
                "PlainShape",
                Some(unkeyed_struct_type_object()),
            ),
            (
                "captured_kind_keyed_r",
                "KeyedShape",
                Some(keyed_struct_type_object()),
            ),
            ("captured_kind_untyped_r", "Opaque", None),
        ] {
            let reservation =
                p.reserve_reader_endpoint::<CapturedBytes>(topic, Some(name), to, false);
            held.push(
                p.announce_reserved_reader(topic, &qos, reservation)
                    .expect("announce captured reader"),
            );
        }

        let guard = p
            .sedp_announcements
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let kind_of = |topic: &str| -> u8 {
            guard
                .alive()
                .find(|(sd, _)| sd.topic_name == topic)
                .map(|(sd, _)| sd.endpoint_guid.as_bytes()[15])
                .expect("announced reader present in SEDP cache")
        };
        assert_eq!(
            kind_of("captured_kind_unkeyed_r"),
            ENTITY_KIND_USER_READER_NO_KEY
        );
        assert_eq!(
            kind_of("captured_kind_keyed_r"),
            ENTITY_KIND_USER_READER_WITH_KEY
        );
        assert_eq!(
            kind_of("captured_kind_untyped_r"),
            ENTITY_KIND_USER_READER_NO_KEY
        );
    }

    #[test]
    fn announce_reader_kind_honors_type_object_key_override() {
        let domain = unique_domain();
        let p = test_participant("announce_reader_kind_keyed", domain.id());
        let qos = QoS::best_effort();

        let reservation = p.reserve_reader_endpoint::<RawBytes>(
            "announce_kind_keyed_r",
            Some("KeyedShape"),
            Some(keyed_struct_type_object()),
            false,
        );
        let _keyed = p
            .announce_reserved_reader("announce_kind_keyed_r", &qos, reservation)
            .expect("announce keyed reader");

        let reservation = p.reserve_reader_endpoint::<RawBytes>(
            "announce_kind_unkeyed_r",
            Some("PlainShape"),
            Some(unkeyed_struct_type_object()),
            false,
        );
        let _unkeyed = p
            .announce_reserved_reader("announce_kind_unkeyed_r", &qos, reservation)
            .expect("announce unkeyed reader");

        let guard = p
            .sedp_announcements
            .read()
            .unwrap_or_else(|e| e.into_inner());
        let kind_of = |topic: &str| -> u8 {
            guard
                .alive()
                .find(|(sd, _)| sd.topic_name == topic)
                .map(|(sd, _)| sd.endpoint_guid.as_bytes()[15])
                .expect("announced reader present in SEDP cache")
        };
        assert_eq!(
            kind_of("announce_kind_keyed_r"),
            ENTITY_KIND_USER_READER_WITH_KEY
        );
        assert_eq!(
            kind_of("announce_kind_unkeyed_r"),
            ENTITY_KIND_USER_READER_NO_KEY
        );
    }

    /// The router requests missing fragments in the names of this
    /// participant's reliable readers: it must hold their writer proxies,
    /// not a registry of its own that no reader ever joins.
    #[test]
    fn the_router_requests_fragments_from_the_readers_own_proxies() {
        let domain = unique_domain();
        let participant = Participant::builder("router_proxies")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant");
        let router = participant
            .router
            .as_ref()
            .expect("a UDP participant has a router");
        assert!(router
            .reader_proxies()
            .shares_state_with(&participant.user_data_registry));
    }

    /// Every receive leg of a participant knows whose it is, so a
    /// submessage an INFO_DST destines to another participant is not applied
    /// here (RTPS 2.5 8.3.8.8).
    #[test]
    fn every_receive_leg_knows_its_participant() {
        let domain = unique_domain();
        let participant = Participant::builder("receive_legs")
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant");
        let ours = Some(participant.guid().prefix);
        assert!(!participant._listeners.is_empty());
        for listener in &participant._listeners {
            assert_eq!(listener.local_prefix(), ours);
        }
        let relay = participant
            .relay_ingress
            .as_ref()
            .expect("a UDP participant builds the relay's receive leg");
        assert_eq!(relay.local_prefix(), ours);
    }

    /// The flush of a new endpoint to the participants already discovered
    /// carries PID_TYPE_OBJECT by the class discovery keeps for each: not to
    /// an HDDS 1.4.x participant, to one announcing
    /// CAP_TYPE_OBJECT_SPEC_STRINGS; PID_TYPE_INFORMATION to both. Read
    /// from the datagrams each receives.
    #[test]
    fn the_flush_carries_the_type_object_by_each_peers_class() {
        use crate::core::discovery::multicast::DiscoveryFsm;
        use crate::core::discovery::GUID;
        use crate::protocol::discovery::SpdpData;
        use std::net::UdpSocket;
        use std::time::Duration;

        const OURS: [u8; 12] = [0x01, 0x1a, 0x5f, 0x5f, 0, 0, 0, 0, 0, 0, 0, 1];
        let fsm = DiscoveryFsm::new(GUID::new(OURS, [0, 0, 1, 0xC1]), 30_000);
        let peer = |prefix: [u8; 12], caps: Option<u32>| {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
            sock.set_read_timeout(Some(Duration::from_millis(300)))
                .expect("timeout");
            fsm.handle_spdp(SpdpData {
                participant_guid: GUID::new(prefix, [0, 0, 1, 0xC1]),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![sock.local_addr().expect("addr")],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                identity_token: None,
                permissions_token: None,
                participant_security_info: None,
                vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
                hdds_capabilities: caps,
                builtin_endpoint_set: None,
            });
            sock
        };
        let old = peer([0x01, 0x1a, 0x14, 0x08, 0, 0, 0, 0, 0, 0, 0, 2], None);
        let new = peer(
            [0x01, 0x1a, 0x15, 0x00, 0, 0, 0, 0, 0, 0, 0, 3],
            Some(crate::protocol::group::LOCAL_CAPABILITIES),
        );
        let lease = unique_domain();
        let mapping =
            crate::transport::PortMapping::calculate(lease.id(), 3).expect("port mapping");
        let transport =
            crate::transport::UdpTransport::new(lease.id(), 3, mapping).expect("test transport");
        let sedp = SedpData {
            topic_name: "FlushTopic".to_string(),
            type_name: "FlushT".to_string(),
            participant_guid: GUID::new(OURS, [0, 0, 1, 0xC1]),
            endpoint_guid: GUID::new(OURS, [0x00, 0x00, 0x01, 0x02]),
            qos_hash: 0,
            qos: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            type_object: Some(struct_type_object(
                "FlushT",
                vec![struct_member(
                    0,
                    "color",
                    MemberFlag::TRY_CONSTRUCT1,
                    TypeIdentifier::string(128),
                )],
            )),
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
        };
        super::flush_sedp_to(
            &fsm,
            &transport,
            &OURS,
            &sedp,
            SedpEndpointKind::Writer,
            1,
            None,
        );

        let pids = |sock: &UdpSocket| -> Vec<u16> {
            let mut buf = [0u8; 8192];
            let len = sock.recv(&mut buf).expect("the flush");
            let dgram = &buf[..len];
            let mut out = Vec::new();
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                dgram,
                |sub| {
                    if sub.id == 0x15 {
                        let body = sub.offset + 4;
                        let to_inline =
                            usize::from(u16::from_le_bytes([dgram[body + 2], dgram[body + 3]]));
                        let mut p = body + 4 + to_inline + 4;
                        while p + 4 <= sub.body_end {
                            let pid = u16::from_le_bytes([dgram[p], dgram[p + 1]]);
                            let len = usize::from(u16::from_le_bytes([dgram[p + 2], dgram[p + 3]]));
                            if pid == 0x0001 {
                                break;
                            }
                            out.push(pid);
                            p += 4 + len;
                        }
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
            out
        };
        let to_old = pids(&old);
        assert!(
            to_old.contains(&0x0075) && !to_old.contains(&0x0072),
            "{to_old:04x?}"
        );
        let to_new = pids(&new);
        assert!(
            to_new.contains(&0x0075) && to_new.contains(&0x0072),
            "{to_new:04x?}"
        );
    }
}

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
use crate::core::rtps_constants::{ENTITY_KIND_USER_READER, ENTITY_KIND_USER_WRITER};
use crate::dds::qos::Reliability;
use crate::dds::Result;
use crate::protocol::discovery::SedpData;
use crate::xtypes::CompleteTypeObject;

use crate::core::discovery::multicast::rtps_packet::{
    build_sedp_rtps_packet, next_publications_seq, next_subscriptions_seq,
};
use crate::protocol::dialect::Dialect;

#[cfg(target_os = "linux")]
use crate::transport::shm::format_shm_user_data;

impl Participant {
    pub(crate) fn announce_writer_endpoint<T: crate::dds::DDS>(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
    ) -> Result<[u8; 4]> {
        let (type_name, type_object) = self.resolve_type_info::<T>(topic, None, None);
        self.announce_writer_endpoint_with_resolved(topic, qos, type_name, type_object)
    }

    pub(crate) fn announce_writer_endpoint_with_type<T: crate::dds::DDS>(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        type_name: &str,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<[u8; 4]> {
        let (type_name, type_object) =
            self.resolve_type_info::<T>(topic, Some(type_name), type_object);
        self.announce_writer_endpoint_with_resolved(topic, qos, type_name, type_object)
    }

    fn announce_writer_endpoint_with_resolved(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        type_name: String,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<[u8; 4]> {
        // NOTE: TypeObject handling is now delegated to the dialect encoder.
        // FastDdsEncoder ignores type_object (requires_type_object() = false)
        // RtiEncoder would encode it if present (requires_type_object() = true)
        // No need to drop it here - the encoder decides based on detected dialect.

        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&self.guid.as_bytes()[..12]);
        let entity_id = self.next_user_entity_id(ENTITY_KIND_USER_WRITER);
        endpoint_guid_bytes[12..16].copy_from_slice(&entity_id);
        log::debug!(
            "[SEDP-ANNOUNCE] Writer entity_id={:02x?} guid={:02x?}",
            entity_id,
            &endpoint_guid_bytes[12..16]
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

        // Generate user_data with SHM capability (Linux only, BestEffort only)
        // SHM transport only works for BestEffort QoS - Reliable requires UDP for retransmission
        #[cfg(target_os = "linux")]
        let user_data = if matches!(qos.reliability, Reliability::BestEffort) {
            Some(format_shm_user_data())
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let user_data: Option<String> = None;

        let sedp_data = SedpData {
            topic_name: topic.to_string(),
            type_name,
            participant_guid: self.guid, // v110: Add participant GUID for PID_PARTICIPANT_GUID (FastDDS interop)
            endpoint_guid,
            qos_hash,
            qos: Some(qos.clone()), // v60: Pass actual QoS to use in build_sedp() instead of hardcoding!
            type_object,
            unicast_locators,
            user_data,
        };

        // Cache announcement for unicast replay / re-announces driven by SPDP
        // handler. No network send is performed here; spdp_handler will flush
        // cached SEDP once remote participants are known via SPDP.
        {
            let mut guard = self
                .sedp_announcements
                .write()
                .unwrap_or_else(|e| e.into_inner());
            guard.push((sedp_data.clone(), SedpEndpointKind::Writer));
        }

        // Phase 1.4: Also add local endpoint to local registry for automatic matching
        if let Some(ref discovery_fsm) = self.discovery_fsm {
            discovery_fsm.handle_sedp(sedp_data.clone());
        }

        // v234: Immediately announce this endpoint to all known peers.
        // Bypasses the SPDP barrier race: if the participant was discovered
        // before this writer was created, the SPDP handler would have sent
        // SEDP with an empty cache. This ensures late-created endpoints are
        // announced without waiting for the next SPDP round-trip.
        self.flush_sedp_to_known_peers(&sedp_data, SedpEndpointKind::Writer);

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

        Ok(entity_id)
    }

    pub(crate) fn announce_reader_endpoint<T: crate::dds::DDS>(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
    ) -> Result<()> {
        log::debug!(
            "[SEDP-ANNOUNCE] announce_reader_endpoint called for topic '{}'",
            topic
        );
        let (type_name, type_object) = self.resolve_type_info::<T>(topic, None, None);
        self.announce_reader_endpoint_with_resolved(topic, qos, type_name, type_object)
    }

    pub(crate) fn announce_reader_endpoint_with_type<T: crate::dds::DDS>(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        type_name: &str,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<()> {
        let (type_name, type_object) =
            self.resolve_type_info::<T>(topic, Some(type_name), type_object);
        self.announce_reader_endpoint_with_resolved(topic, qos, type_name, type_object)
    }

    fn announce_reader_endpoint_with_resolved(
        &self,
        topic: &str,
        qos: &crate::dds::QoS,
        type_name: String,
        type_object: Option<CompleteTypeObject>,
    ) -> Result<()> {
        // NOTE: TypeObject handling is now delegated to the dialect encoder.
        // FastDdsEncoder ignores type_object (requires_type_object() = false)
        // RtiEncoder would encode it if present (requires_type_object() = true)
        // No need to drop it here - the encoder decides based on detected dialect.

        let mut endpoint_guid_bytes = [0u8; 16];
        endpoint_guid_bytes[..12].copy_from_slice(&self.guid.as_bytes()[..12]);
        let entity_id = self.next_user_entity_id(ENTITY_KIND_USER_READER);
        endpoint_guid_bytes[12..16].copy_from_slice(&entity_id);
        log::debug!(
            "[SEDP-ANNOUNCE] Reader entity_id={:02x?} guid={:02x?}",
            entity_id,
            &endpoint_guid_bytes[12..16]
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

        // Generate user_data with SHM capability (Linux only, BestEffort only)
        #[cfg(target_os = "linux")]
        let user_data = if matches!(qos.reliability, Reliability::BestEffort) {
            Some(format_shm_user_data())
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let user_data: Option<String> = None;

        let sedp_data = SedpData {
            topic_name: topic.to_string(),
            type_name,
            participant_guid: self.guid, // v110: Add participant GUID for PID_PARTICIPANT_GUID (FastDDS interop)
            endpoint_guid,
            qos_hash,
            qos: Some(qos.clone()), // v60: Pass actual QoS to use in build_sedp() instead of hardcoding!
            type_object,
            unicast_locators,
            user_data,
        };

        // Cache announcement for unicast replay to discovered peers
        {
            let mut guard = self
                .sedp_announcements
                .write()
                .unwrap_or_else(|e| e.into_inner());
            guard.push((sedp_data.clone(), SedpEndpointKind::Reader));
        }

        // Phase 1.4: Also add local endpoint to local registry for automatic matching
        if let Some(ref discovery_fsm) = self.discovery_fsm {
            discovery_fsm.handle_sedp(sedp_data.clone());
        }

        // v234: Immediately announce this endpoint to all known peers.
        self.flush_sedp_to_known_peers(&sedp_data, SedpEndpointKind::Reader);

        self.graph_guard.set_trigger_value(true);

        Ok(())
    }
}

impl Participant {
    fn resolve_type_info<T: crate::dds::DDS>(
        &self,
        topic: &str,
        type_name_override: Option<&str>,
        type_object_override: Option<CompleteTypeObject>,
    ) -> (String, Option<CompleteTypeObject>) {
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
                if type_object.is_none() {
                    type_object = self
                        .registered_type(type_name)
                        .map(|handle| handle.complete.clone());
                }
                return (type_name.to_string(), type_object);
            }

            if let Some(handle) = self.topic_type_handle(topic) {
                return (
                    handle.fqn.as_ref().to_string(),
                    Some(handle.complete.clone()),
                );
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
            let type_name = type_name_override
                .map(|name| name.to_string())
                .unwrap_or_else(|| type_descriptor.type_name.to_string());
            let type_object = type_object_override.or_else(T::get_type_object);
            (type_name, type_object)
        }
    }
}

impl Participant {
    /// v234: Send a single SEDP announcement to all already-discovered peers.
    ///
    /// This is called immediately when a new writer/reader is created, so that
    /// peers that were discovered before this endpoint existed learn about it
    /// without waiting for the next SPDP round-trip (which could be 5+ seconds).
    fn flush_sedp_to_known_peers(&self, sedp_data: &SedpData, kind: SedpEndpointKind) {
        let (Some(ref discovery_fsm), Some(ref transport)) = (&self.discovery_fsm, &self.transport)
        else {
            return;
        };

        let peers = discovery_fsm.get_participants();
        if peers.is_empty() {
            return;
        }

        let dialect = discovery_fsm
            .get_locked_dialect()
            .unwrap_or(Dialect::Hybrid);

        let our_guid_prefix: [u8; 12] = {
            let bytes = self.guid.as_bytes();
            let mut prefix = [0u8; 12];
            prefix.copy_from_slice(&bytes[..12]);
            prefix
        };

        let seq_num = match kind {
            SedpEndpointKind::Writer => next_publications_seq(),
            SedpEndpointKind::Reader => next_subscriptions_seq(),
        };

        for peer in &peers {
            if peer.endpoints.is_empty() {
                continue;
            }

            let peer_guid_prefix: [u8; 12] = {
                let bytes = peer.guid.as_bytes();
                let mut prefix = [0u8; 12];
                prefix.copy_from_slice(&bytes[..12]);
                prefix
            };

            match build_sedp_rtps_packet(
                sedp_data,
                kind,
                &our_guid_prefix,
                Some(&peer_guid_prefix),
                seq_num,
                dialect,
            ) {
                Ok(pkt) => {
                    for ep in &peer.endpoints {
                        match transport.send_to_endpoint(&pkt, ep) {
                            Ok(_) => log::debug!(
                                "[SEDP-FLUSH] Sent {:?} for '{}' to {} (on endpoint create)",
                                kind,
                                sedp_data.topic_name,
                                ep
                            ),
                            Err(e) => log::debug!("[SEDP-FLUSH] Failed to send to {}: {}", ep, e),
                        }
                    }
                }
                Err(e) => {
                    log::debug!(
                        "[SEDP-FLUSH] Failed to build SEDP packet for '{}': {:?}",
                        sedp_data.topic_name,
                        e
                    );
                }
            }
        }

        log::debug!(
            "[SEDP-FLUSH] v234: Announced {:?} '{}' to {} known peers",
            kind,
            sedp_data.topic_name,
            peers.len()
        );
    }
}

fn compute_qos_hash(topic: &str, qos: &crate::dds::QoS) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

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
        crate::dds::qos::Durability::Persistent => 3u8,
    };
    hash ^= u64::from(durability_byte);
    hash = hash.wrapping_mul(FNV_PRIME);

    hash
}

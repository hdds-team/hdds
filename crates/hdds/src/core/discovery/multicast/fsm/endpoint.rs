// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Discovered endpoint metadata and kind classification.
//!
//! Defines `EndpointInfo` for storing discovered DataWriter/DataReader metadata
//! and `EndpointKind` for distinguishing writers from readers via RTPS entity ID.

use crate::core::discovery::GUID;
use crate::protocol::dialect::{get_encoder, Dialect};
use crate::protocol::discovery::SedpData;
use crate::xtypes::CompleteTypeObject;

/// Endpoint kind (Writer or Reader).
///
/// Derived from RTPS GUID entity_id (last 4 bytes).
/// Used to distinguish DataWriters from DataReaders in discovery.
///
/// # RTPS Spec (9.3.1)
/// - Writer entity_id\[3\]: 0x02-0x03 (user-defined), 0xC2 (built-in SEDP publications)
/// - Reader entity_id\[3\]: 0x04-0x07 (user-defined), 0xC7 (built-in SEDP subscriptions)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// DataWriter endpoint.
    Writer,
    /// DataReader endpoint.
    Reader,
}

impl EndpointKind {
    /// Derive endpoint kind from RTPS GUID.
    ///
    /// Uses entity_id\[3\] (last byte of GUID) to determine Writer vs Reader.
    ///
    /// # RTPS Logic
    /// - 0x02, 0x03, 0xC2 -> Writer
    /// - 0x04, 0x07, 0xC7 -> Reader
    /// - Default: Writer (conservative assumption)
    ///
    /// # Arguments
    /// - `guid`: RTPS GUID (16 bytes)
    ///
    /// # Examples
    /// ```
    /// use hdds::core::discovery::GUID;
    /// use hdds::core::discovery::multicast::EndpointKind;
    ///
    /// // Writer GUID (entity_id[3] = 0x02)
    /// let writer_guid = GUID::from_bytes([
    ///     1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ///     0, 0, 0, 0x02
    /// ]);
    /// assert_eq!(EndpointKind::from_guid(&writer_guid), EndpointKind::Writer);
    ///
    /// // Reader GUID (entity_id[3] = 0x04)
    /// let reader_guid = GUID::from_bytes([
    ///     1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ///     0, 0, 0, 0x04
    /// ]);
    /// assert_eq!(EndpointKind::from_guid(&reader_guid), EndpointKind::Reader);
    /// ```
    #[must_use]
    pub fn from_guid(guid: &GUID) -> Self {
        crate::trace_fn!("EndpointKind::from_guid");
        let entity_id_byte = guid.as_bytes()[15]; // Last byte of GUID

        match entity_id_byte {
            // Writer kinds (RTPS spec 9.3.1.1)
            0x02 | 0x03 | 0xC2 => EndpointKind::Writer,
            // Reader kinds (RTPS spec 9.3.1.2)
            0x04 | 0x07 | 0xC7 => EndpointKind::Reader,
            // Unknown: default to Writer (conservative)
            _ => EndpointKind::Writer,
        }
    }
}

/// Endpoint metadata from SEDP discovery.
///
/// Represents a discovered DataWriter or DataReader from a remote participant.
#[derive(Debug, Clone)]
pub struct EndpointInfo {
    /// Endpoint GUID (16 bytes).
    pub endpoint_guid: GUID,
    /// Participant GUID (derived from endpoint_guid prefix).
    pub participant_guid: GUID,
    /// Topic name (e.g., "sensor/temperature").
    pub topic_name: String,
    /// Type name (e.g., "Temperature").
    pub type_name: String,
    /// QoS policies for this endpoint.
    ///
    /// Changed from qos_hash to actual QoS object for proper compatibility checking.
    /// Enables:
    /// - Runtime QoS compatibility verification (Reliability, Durability, History matching)
    /// - Vendor-specific QoS defaults when not explicitly announced
    /// - Correct endpoint matching per DDS spec Sec.2.2.3
    pub qos: crate::dds::qos::QoS,
    /// Endpoint kind (Writer or Reader).
    pub kind: EndpointKind,
    /// TypeObject (XTypes v1.3 type information).
    ///
    /// Optional field containing the complete type definition for this endpoint.
    /// When present, enables:
    /// - Runtime type compatibility checking
    /// - Structural type equivalence verification
    /// - Dynamic type evolution support
    ///
    /// # Usage
    /// - Check compatibility: compare TypeObject equivalence hashes
    /// - Validate types: ensure compatible QoS + type structure
    /// - Support late joiners: cache TypeObject for TransientLocal endpoints
    ///
    /// # None Cases
    /// - Legacy endpoints (pre-XTypes)
    /// - Primitive types (no complex structure)
    /// - Endpoints that opt out of type discovery
    pub type_object: Option<CompleteTypeObject>,
    /// Announced `PID_TYPE_INFORMATION` (equivalence hashes), retained even
    /// when `type_object` is `None`.
    ///
    /// Cross-vendor peers announce only hashes; if the local type store is
    /// still empty when the SEDP arrives (remote-before-local ordering),
    /// arrival-time resolution misses and `type_object` stays `None`.
    /// Retaining the raw TypeInformation lets the late-side compatibility
    /// checks re-run resolution once the local endpoint has registered its
    /// TypeObject, making INCONSISTENT_TOPIC detection order-independent.
    pub type_information: Option<crate::protocol::discovery::types::TypeInformation>,
    /// True when `type_object` was decoded from a lossy legacy TypeObject
    /// v1 payload and could not be substituted with a same-named local
    /// type at arrival time (see `SedpData::type_object_legacy_v1`). The
    /// late-side compatibility checks re-attempt the name-based local
    /// substitution when this is set, mirroring the lazy TypeInformation
    /// re-resolution used for hash-announcing peers.
    pub type_object_legacy_v1: bool,
    /// Whether PID_OWNERSHIP was explicitly present in SEDP.
    pub has_explicit_ownership: bool,
    /// Whether PID_OWNERSHIP_STRENGTH was present (implies EXCLUSIVE).
    pub has_ownership_strength: bool,
    /// HDDS vendor-specific SHM transport capability hint, parsed from
    /// `PID_HDDS_SHM_CAPABILITY` (0x8031) via `SedpData::shm_capability`.
    /// Format: "shm=1;host_id=XXXXXXXX;v=1".
    ///
    /// Deliberately NOT `user_data`. PID_USER_DATA is `UserDataQosPolicy`
    /// and belongs to the application; carrying a proprietary capability
    /// hint there would silently overwrite whatever an application set on
    /// its own endpoints. A vendor PID is also the only carrier a foreign
    /// vendor is required to ignore, which matters because `Dialect::Hdds`
    /// is the DEFAULT encoding dialect before a peer's vendor is resolved.
    ///
    /// Consumed exactly ONCE at SEDP match time by
    /// `MatchNotificationRegistry::resolve_transport`, which feeds it to
    /// `select_transport` as the `remote_user_data` argument and stores the
    /// verdict beside the GUID in `matched_remotes`. North Star pillar 2:
    /// a peer capability is resolved once on the cold path and read O(1)
    /// afterwards, never re-parsed per message.
    ///
    /// `None` when the peer sent no such parameter, which is every peer
    /// running a build older than this one.
    pub shm_capability: Option<String>,
    /// Which record of the endpoint this is, under its GUID: assigned by the
    /// discovery's topic registry when the endpoint enters it (1, 2, ... in
    /// the order records enter), kept by an update of the same record, new
    /// for an endpoint removed and announced again under the same GUID. 0 for
    /// a record that never went through the registry.
    ///
    /// Every copy of a record carries it, so a notification in flight names
    /// the record it was decided on: a match decided on a record that has
    /// since been replaced is undone, and the removal of a record ends no
    /// match made on a newer one (`MatchNotificationRegistry`).
    pub incarnation: u64,
    /// The endpoint's group, its Publisher or Subscriber
    /// (`SedpData::group_entity_id`): the writers of one remote Publisher
    /// share it (`DiscoveryFsm::publisher_roster`). `None` when the
    /// announcement named none.
    pub group_entity_id: Option<[u8; 4]>,
    /// Parsed `PID_ENDPOINT_SECURITY_INFO` (`SedpData::endpoint_security_info`):
    /// the protections this endpoint announced for itself (DDS-Security v1.1
    /// Sec.7.2.8). `None` when the peer sent no such PID, read by
    /// [`crate::protocol::discovery::EndpointSecurityInfo::matches`] the same
    /// as a mask with every bit clear.
    ///
    /// Consumed at admission time by `DiscoveryFsm::judge_endpoint`, which
    /// compares it against the LOCAL topic's own attributes before the
    /// endpoint is surfaced.
    pub endpoint_security_info: Option<crate::protocol::discovery::EndpointSecurityInfo>,
}

impl EndpointInfo {
    /// The COMPLETE EquivalenceHash this endpoint announced in its
    /// `PID_TYPE_INFORMATION`, if it announced one. This is the key a
    /// TypeLookup request is made on (`update_type_object_for_hash`
    /// resolves exactly the endpoints that named it): a type announced by
    /// hash with no TypeObject yet is a reply still to come.
    #[must_use]
    pub(crate) fn announced_complete_hash(&self) -> Option<crate::xtypes::EquivalenceHash> {
        self.type_information
            .as_ref()
            .and_then(|ti| ti.complete.as_ref())
            .map(|complete| complete.hash)
    }

    /// Create new EndpointInfo from SEDP data.
    ///
    /// # Arguments
    /// - `sedp_data`: Parsed SEDP announcement
    ///
    /// # Returns
    /// EndpointInfo with endpoint kind auto-detected and QoS defaults applied if needed.
    ///
    /// # QoS Defaults
    /// When `sedp_data.qos` is None (no QoS PIDs in SEDP), the dialect encoder's
    /// `default_qos()` method provides vendor-specific defaults.
    ///
    /// # Arguments
    /// - `sedp_data`: Parsed SEDP data
    /// - `dialect`: Optional detected dialect for vendor-specific QoS defaults
    ///
    /// # Examples
    /// ```no_run
    /// use hdds::core::discovery::GUID;
    /// use hdds::core::discovery::multicast::EndpointInfo;
    /// use hdds::protocol::discovery::SedpData;
    /// use hdds::protocol::dialect::Dialect;
    ///
    /// let sedp_data = SedpData {
    ///     topic_name: "sensor/temp".to_string(),
    ///     type_name: "Temperature".to_string(),
    ///     participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0]),
    ///     endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0x02]),
    ///     qos_hash: 12345,
    ///     qos: None,
    ///     type_object: None,
    ///     type_object_legacy_v1: false,
    ///     dependents: Vec::new(),
    ///     type_information: None,
    ///     unicast_locators: vec![],
    ///     user_data: None,
    ///     shm_capability: None,
    ///     has_explicit_reliability: false,
    ///     has_explicit_ownership: false,
    ///     has_ownership_strength: false,
    ///     type_consistency: None,
    ///     group_entity_id: None,
    ///     endpoint_security_info: None,
    /// };
    ///
    /// let endpoint = EndpointInfo::from_sedp(sedp_data, Some(Dialect::Rti));
    /// assert_eq!(endpoint.topic_name, "sensor/temp");
    /// ```
    #[must_use]
    pub fn from_sedp(sedp_data: SedpData, dialect: Option<Dialect>) -> Self {
        crate::trace_fn!("EndpointInfo::from_sedp");
        // Destructure upfront to avoid partial-move issues.
        let SedpData {
            endpoint_guid,
            topic_name,
            type_name,
            qos: sedp_qos,
            type_object,
            type_object_legacy_v1,
            has_explicit_reliability,
            has_explicit_ownership,
            has_ownership_strength,
            type_consistency: sedp_type_consistency,
            group_entity_id,
            type_information,
            shm_capability,
            endpoint_security_info,
            // fields not used for EndpointInfo construction
            participant_guid: _,
            qos_hash: _,
            unicast_locators: _,
            // The application's UserDataQosPolicy. Announced and parsed, but
            // no matching decision reads it, so it is deliberately not
            // carried into EndpointInfo. Named explicitly rather than swept
            // up by `..` so that adding a field to SedpData keeps failing
            // this destructure until somebody decides where it belongs.
            user_data: _,
            // Drained into the participant type store by
            // DiscoveryFsm::handle_sedp before this call (see the
            // `dependents` registration block there); nothing left to do
            // with it here.
            dependents: _,
        } = sedp_data;

        let kind = EndpointKind::from_guid(&endpoint_guid);

        // Derive participant GUID (first 12 bytes of endpoint GUID)
        let mut participant_bytes = [0u8; 16];
        participant_bytes[..12].copy_from_slice(&endpoint_guid.as_bytes()[..12]);
        let participant_guid = GUID::from_bytes(participant_bytes);

        // Apply QoS: use explicit PIDs if present, otherwise get dialect-specific defaults.
        // DDS spec: DataWriter defaults to RELIABLE, DataReader defaults to BEST_EFFORT.
        // If the SEDP QoS is present but PID_RELIABILITY was not explicitly set,
        // the reliability field is at its Rust default (BestEffort), which is wrong
        // for writers. Apply the spec default based on endpoint kind.
        let qos = if let Some(mut qos) = sedp_qos {
            // If reliability is still at default and this is a writer,
            // apply the DDS spec default (RELIABLE for writers).
            if qos.reliability == crate::dds::qos::Reliability::BestEffort
                && kind == EndpointKind::Writer
                && !has_explicit_reliability
            {
                qos.reliability = crate::dds::qos::Reliability::Reliable;
            }
            // PID_TYPE_CONSISTENCY_ENFORCEMENT is parsed separately from the main
            // QoS PID block and stored in SedpData.type_consistency. Merge it into
            // the endpoint QoS so that discovery can read it via
            // endpoint.qos.type_consistency when evaluating structural compatibility.
            // XTypes v1.3 sec. 7.6.3.4: TypeConsistencyEnforcement is a reader-side QoS;
            // the peer's policy controls whether bound mismatches trigger INCONSISTENT_TOPIC.
            // NOTE: when the PID is absent, type_consistency intentionally stays
            // as carried by the QoS struct (None for wire-parsed QoS). The
            // ABSENT-PID spec-default materialization for REMOTE readers happens
            // in DiscoveryFsm::handle_sedp, which knows endpoint locality;
            // from_sedp also serves LOCALLY-built SedpData (announce path) whose
            // unset policy must keep the permissive local semantics.
            if sedp_type_consistency.is_some() {
                qos.type_consistency = sedp_type_consistency;
            }
            log::debug!("[ENDPOINT] Using QoS from SEDP PIDs: reliability={:?}, durability={:?}, history={:?}",
                      qos.reliability, qos.durability, qos.history);
            qos
        } else {
            // Get dialect-specific defaults (or DDS spec defaults if no dialect)
            let dialect = dialect.unwrap_or(Dialect::Hybrid);
            let encoder = get_encoder(dialect);
            let mut default_qos = encoder.default_qos();
            // DDS spec: DataWriter defaults to RELIABLE (Sec.2.2.3.12).
            // When no QoS PIDs are present, apply spec defaults based on kind.
            if kind == EndpointKind::Writer {
                default_qos.reliability = crate::dds::qos::Reliability::Reliable;
            }
            // Merge PID_TYPE_CONSISTENCY_ENFORCEMENT into the default QoS.
            // Absent PID: stays None here; see the NOTE in the explicit-QoS
            // branch above (remote-reader materialization lives in handle_sedp).
            if sedp_type_consistency.is_some() {
                default_qos.type_consistency = sedp_type_consistency;
            }
            log::debug!("[ENDPOINT] No QoS PIDs in SEDP - applying {} defaults (reliability={:?}, durability={:?}, history={:?})",
                      encoder.name(), default_qos.reliability, default_qos.durability, default_qos.history);
            default_qos
        };

        Self {
            endpoint_guid,
            participant_guid,
            topic_name,
            type_name,
            qos,
            kind,
            type_object,
            type_object_legacy_v1,
            type_information,
            has_explicit_ownership,
            has_ownership_strength,
            shm_capability,
            incarnation: 0,
            group_entity_id,
            endpoint_security_info,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;

    #[test]
    fn test_endpoint_kind_writer() {
        let writer_guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0x02]);
        assert_eq!(EndpointKind::from_guid(&writer_guid), EndpointKind::Writer);

        let builtin_writer =
            GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0xC2]);
        assert_eq!(
            EndpointKind::from_guid(&builtin_writer),
            EndpointKind::Writer
        );
    }

    #[test]
    fn test_endpoint_kind_reader() {
        let reader_guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0x04]);
        assert_eq!(EndpointKind::from_guid(&reader_guid), EndpointKind::Reader);

        let builtin_reader =
            GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0xC7]);
        assert_eq!(
            EndpointKind::from_guid(&builtin_reader),
            EndpointKind::Reader
        );
    }

    #[test]
    fn test_endpoint_kind_unknown_defaults_to_writer() {
        let unknown_guid = GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 0xFF]);
        assert_eq!(EndpointKind::from_guid(&unknown_guid), EndpointKind::Writer);
    }

    fn sedp_data_for(entity_kind_byte: u8) -> crate::protocol::discovery::SedpData {
        crate::protocol::discovery::SedpData {
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            topic_name: "t".to_string(),
            type_name: "T".to_string(),
            participant_guid: GUID::from_bytes([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xC1,
            ]),
            endpoint_guid: GUID::from_bytes([
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                0,
                0,
                0,
                entity_kind_byte,
            ]),
            qos_hash: 0,
            qos: None,
            type_object: None,
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

    /// from_sedp is locality-agnostic and must stay PURE on the absent PID:
    /// it must NOT synthesize a TypeConsistencyEnforcement (the ABSENT-PID
    /// spec default for REMOTE readers is materialized in
    /// DiscoveryFsm::handle_sedp, which knows endpoint locality; locally-built
    /// SedpData from the announce path also flows through from_sedp and its
    /// unset policy must keep the permissive local semantics). An explicitly
    /// received policy is preserved verbatim.
    #[test]
    fn test_from_sedp_absent_type_consistency_stays_none() {
        use crate::protocol::discovery::types::TypeConsistencyEnforcement;

        // Reader (0x04), absent PID -> stays None (materialization is NOT here).
        let reader_ep = EndpointInfo::from_sedp(sedp_data_for(0x04), None);
        assert!(
            reader_ep.qos.type_consistency.is_none(),
            "from_sedp must not synthesize a policy for an absent PID"
        );

        // Writer (0x02), absent PID -> stays None (TCE is reader-side QoS).
        let writer_ep = EndpointInfo::from_sedp(sedp_data_for(0x02), None);
        assert!(writer_ep.qos.type_consistency.is_none());

        // Reader with EXPLICIT policy -> preserved verbatim (not overwritten).
        let mut sd = sedp_data_for(0x04);
        let explicit = TypeConsistencyEnforcement {
            kind: 1,
            ignore_sequence_bounds: false,
            ignore_string_bounds: false,
            ignore_member_names: true,
            prevent_type_widening: true,
            force_type_validation: true,
        };
        sd.type_consistency = Some(explicit.clone());
        let explicit_ep = EndpointInfo::from_sedp(sd, None);
        assert_eq!(
            explicit_ep.qos.type_consistency,
            Some(explicit),
            "explicit wire policy must be preserved verbatim"
        );
    }
}

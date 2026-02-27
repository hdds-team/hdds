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
    /// v61: Changed from qos_hash to actual QoS object for proper compatibility checking.
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
}

impl EndpointInfo {
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
    ///     unicast_locators: vec![],
    ///     user_data: None,
    /// };
    ///
    /// let endpoint = EndpointInfo::from_sedp(sedp_data, Some(Dialect::Rti));
    /// assert_eq!(endpoint.topic_name, "sensor/temp");
    /// ```
    #[must_use]
    pub fn from_sedp(sedp_data: SedpData, dialect: Option<Dialect>) -> Self {
        crate::trace_fn!("EndpointInfo::from_sedp");
        let endpoint_guid = sedp_data.endpoint_guid;
        let kind = EndpointKind::from_guid(&endpoint_guid);

        // Derive participant GUID (first 12 bytes of endpoint GUID)
        let mut participant_bytes = [0u8; 16];
        participant_bytes[..12].copy_from_slice(&endpoint_guid.as_bytes()[..12]);
        let participant_guid = GUID::from_bytes(participant_bytes);

        // Apply QoS: use explicit PIDs if present, otherwise get dialect-specific defaults
        let qos = if let Some(qos) = sedp_data.qos {
            log::debug!("[ENDPOINT] Using QoS from SEDP PIDs: reliability={:?}, durability={:?}, history={:?}",
                      qos.reliability, qos.durability, qos.history);
            qos
        } else {
            // Get dialect-specific defaults (or DDS spec defaults if no dialect)
            let dialect = dialect.unwrap_or(Dialect::Hybrid);
            let encoder = get_encoder(dialect);
            let default_qos = encoder.default_qos();
            log::debug!("[ENDPOINT] No QoS PIDs in SEDP - applying {} defaults (reliability={:?}, durability={:?}, history={:?})",
                      encoder.name(), default_qos.reliability, default_qos.durability, default_qos.history);
            default_qos
        };

        Self {
            endpoint_guid,
            participant_guid,
            topic_name: sedp_data.topic_name,
            type_name: sedp_data.type_name,
            qos,
            kind,
            type_object: sedp_data.type_object,
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
}

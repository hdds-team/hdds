// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SEDP Builder - CDR encoding of SEDP endpoint discovery messages
//!
//! Handles building SEDP discovery announcement packets with:
//! - Endpoint metadata (topic, type, GUID)
//! - QoS policies (reliability, durability, history)
//! - Type information (TypeObject CDR2 payload)
//! - Locator announcements
//! - Vendor-specific PIDs (0x8000+), HDDS-owned only
//!
//! # Module Organization
//! - `metadata` - Endpoint identification PIDs (GUID, topic, type, versions)
//! - `qos` - QoS policy PIDs (reliability, durability, history, etc.)
//! - `locators` - Network locator PIDs (unicast, multicast)

mod locators;
mod metadata;
pub(crate) use metadata::default_group_entity_id;
/// QoS PID serialization for SEDP endpoint discovery.
pub mod qos;
mod type_information;

// Re-export the with-deps variant so callers outside this module (e.g.
// announce.rs) can use it without naming the private `type_information`
// submodule.
#[cfg(feature = "xtypes-structural-assignability")]
pub(crate) use type_information::derive_announced_type_graph;
#[cfg(all(test, feature = "xtypes-structural-assignability"))]
pub(crate) use type_information::derive_type_information_with_deps;
// The TypeInformation every dialect announces for an endpoint's type, and
// its one parameter writer: a dialect encoder that carries
// PID_TYPE_INFORMATION takes both from here rather than building its own.
#[cfg(feature = "xtypes")]
pub(crate) use type_information::{announced_type_information, encode_type_information_parameter};

use crate::protocol::discovery::constants::{PID_SENTINEL, PID_TYPE_OBJECT};
use crate::protocol::discovery::types::{ParseError, SedpData};
use crate::xtypes::CompleteTypeObject;
use crate::Cdr2Encode;
use std::convert::TryFrom;

/// Build SEDP discovery announcement packet.
///
/// # Arguments
/// - `sedp_data`: Endpoint metadata to encode (topic name, type name, endpoint GUID, optional TypeObject).
/// - `buf`: Destination buffer that receives the encoded parameter list.
///
/// # Returns
/// Number of bytes copied into `buf`.
///
/// # Errors
/// - `ParseError::BufferTooSmall` if the provided buffer cannot hold the encoding.
/// - `ParseError::EncodingError` when the TypeObject CDR2 encoding fails.
/// - `ParseError::InvalidFormat` for values that exceed RTPS size limits.
///
/// # PID Write Order
/// The order of PID writes is CRITICAL for cross-vendor interop. Do not reorder without
/// running the interoperability tests. HDDS writes this sequence:
///
/// 1. CDR encapsulation header (0x0003 = PL_CDR_LE)
/// 2. PID_ENDPOINT_GUID - first, for endpoint identification
/// 3. PID_TOPIC_NAME, PID_TYPE_NAME - String parameters, then PID_USER_DATA
///    (0x002c, application UserDataQosPolicy) when `sedp_data.user_data` is
///    `Some`, then PID_HDDS_SHM_CAPABILITY (0x8031, HDDS vendor PID) when
///    `sedp_data.shm_capability` is `Some` (HDDS dialect path only)
/// 4. PID_PROTOCOL_VERSION, PID_VENDOR_ID, PID_PRODUCT_VERSION - Version metadata
/// 5. PID_DATA_REPRESENTATION, PID_RECV_QUEUE_SIZE - Data format info
/// 6. PID_GROUP_ENTITY_ID - Publisher/Subscriber ownership
/// 7. PID_ENTITY_VIRTUAL_GUID, PID_EXPECTS_VIRTUAL_HB - vendor 0x0101 PIDs (unsent)
/// 8. PID_ENDPOINT_PROPERTY_CHANGE_EPOCH - vendor 0x0101 PID (currently unsent)
/// 9. PID_UNICAST_LOCATOR - Network locators
/// 10. QoS PIDs - RELIABILITY, DURABILITY, HISTORY, DEADLINE, OWNERSHIP, LIVELINESS, etc.
/// 11. PID_TYPE_OBJECT - TypeObject CDR2 (if present)
/// 12. PID_TYPE_INFORMATION - DDS-XTypes v1.3 sec. 7.6.3.2 (if TypeObject present)
/// 13. PID_TYPE_CONSISTENCY_ENFORCEMENT - DDS-XTypes v1.3 sec. 7.6.3.3.3 (if TypeObject present)
/// 14. PID_SENTINEL - Terminator
pub fn build_sedp(sedp_data: &SedpData, buf: &mut [u8]) -> Result<usize, ParseError> {
    build_sedp_with_options(sedp_data, buf, true)
}

/// Build SEDP discovery announcement packet with emission options.
///
/// `emit_type_object_pid` controls PID_TYPE_OBJECT (0x0072) emission. HDDS
/// encodes this PID with its INTERNAL `CompleteTypeObject` CDR2 layout (the
/// Rust-struct encoding consumed by sedp/parse.rs), which is NOT the standard
/// XTypes TypeObject CDR (DDS-XTypes 1.3 Sec.7.6.3.2), so a foreign reader
/// that decodes it as a spec TypeObject would fail and could report
/// INCONSISTENT_TOPIC without running assignability. Callers pass `false`
/// for announcements targeting non-HDDS peers; PID_TYPE_INFORMATION (0x0075)
/// and PID_TYPE_CONSISTENCY_ENFORCEMENT (0x0074) emission is unaffected.
pub fn build_sedp_with_options(
    sedp_data: &SedpData,
    buf: &mut [u8],
    emit_type_object_pid: bool,
) -> Result<usize, ParseError> {
    let mut offset = 0;
    // NOTE: This legacy builder is only used by tests now. Production code uses
    // build_sedp_for_dialect() with dialect-specific encoders.
    // interop_minimal mode is not needed - dialect encoders handle this.
    let interop_minimal = false;

    // CDR encapsulation header (ALWAYS big-endian per CDR spec)
    // 0x0003 = PL_CDR_LE (Parameter List, Little-Endian data)
    if buf.len() < 4 {
        return Err(ParseError::BufferTooSmall);
    }
    buf[0..4].copy_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    offset += 4;

    // ===== METADATA SECTION =====
    // PID_ENDPOINT_GUID is written before PID_PARTICIPANT_GUID, so a
    // receiver that keys the announcement on the endpoint GUID meets it
    // first; HDDS keeps this order stable.
    metadata::write_endpoint_guid(&sedp_data.endpoint_guid, buf, &mut offset)?;
    metadata::write_participant_guid(&sedp_data.participant_guid, buf, &mut offset)?;
    if !interop_minimal {
        metadata::write_key_hash(&sedp_data.endpoint_guid, buf, &mut offset)?;
    }

    // String parameters
    metadata::write_topic_name(&sedp_data.topic_name, buf, &mut offset)?;
    metadata::write_type_name(&sedp_data.type_name, buf, &mut offset)?;

    // PID_USER_DATA (0x002c): the application's UserDataQosPolicy, propagated
    // for every dialect that routes through this shared builder (whichever
    // dialect populated sedp_data.user_data from the local endpoint's QoS).
    if let Some(ref user_data) = sedp_data.user_data {
        metadata::write_user_data(user_data, buf, &mut offset)?;
    }

    // PID_HDDS_SHM_CAPABILITY (0x8031): only ever Some() on the HDDS dialect
    // path (see SedpEndpointData::hdds_shm_capability /
    // HddsEncoder::build_sedp); every other dialect's LegacySedpData carries
    // shm_capability: None, so this is a no-op for every foreign-dialect
    // frame. Never PID_USER_DATA -- see PID_HDDS_SHM_CAPABILITY doc.
    if let Some(ref hint) = sedp_data.shm_capability {
        metadata::write_hdds_shm_capability(hint, buf, &mut offset)?;
    }

    // Version metadata (standard PIDs only)
    metadata::write_protocol_version(buf, &mut offset)?;
    metadata::write_vendor_id(buf, &mut offset)?;
    // NOTE: Removed PID_PRODUCT_VERSION (0x8000) - vendor-range PID owned by vendor 0x0101
    // (DDSI-RTPS 2.5 Sec.9.4.2.11); HDDS never emits another vendor's PIDs
    // metadata::write_product_version(buf, &mut offset)?;

    // PID_DATA_REPRESENTATION: what the endpoint offers (a writer, its one
    // representation) or requests (a reader), the one announcement source
    // the wire builder of every dialect uses too
    // (`cdr_negotiation::announced_data_representation`). An endpoint built
    // with no QoS is announced as one that set no list.
    let announces_writer = matches!(sedp_data.endpoint_guid.as_bytes()[15], 0x02 | 0x03);
    let announced = crate::dds::cdr_negotiation::announced_data_representation(
        if announces_writer {
            crate::core::discovery::multicast::fsm::EndpointKind::Writer
        } else {
            crate::core::discovery::multicast::fsm::EndpointKind::Reader
        },
        sedp_data
            .qos
            .as_ref()
            .map_or(&[][..], |qos| qos.data_representation.as_slice()),
    );
    metadata::write_data_representation_list(announced, buf, &mut offset)?;

    // Additional metadata (commented out for minimal profile)
    // NOTE: Removed vendor PIDs (0x8002, 0x8009) - vendor 0x0101 PIDs, never emitted by HDDS
    // PID_GROUP_GUID (0x0052) + PID_GROUP_ENTITY_ID (0x0053) emitted
    // unconditionally per RTPS v2.5 sec. 9.3.2.1 so peers can associate
    // endpoint-level PIDs (PID_COHERENT_SET, PID_PARTITION) with the
    // announcing publisher / subscriber group. GROUP-presentation delivery
    // keys on this group identity.
    let is_writer = matches!(sedp_data.endpoint_guid.as_bytes()[15], 0x02 | 0x03);
    let group = sedp_data
        .group_entity_id
        .unwrap_or_else(|| metadata::default_group_entity_id(is_writer));
    metadata::write_group_guid(&sedp_data.endpoint_guid.as_bytes(), group, buf, &mut offset)?;
    metadata::write_group_entity_id(group, buf, &mut offset)?;
    // if !interop_minimal {
    //     metadata::write_recv_queue_size(buf, &mut offset)?;
    //     metadata::write_expects_inline_qos(false, buf, &mut offset)?;
    //     metadata::write_entity_virtual_guid(&sedp_data.endpoint_guid, buf, &mut offset)?;  // 0x8002
    //     metadata::write_expects_virtual_hb(buf, &mut offset)?;  // 0x8009
    // }

    // PID_TYPE_CONSISTENCY_ENFORCEMENT (0x0074) ships from the TYPE OBJECT /
    // TYPE INFORMATION SECTION below, gated on `sedp_data.type_object` being
    // present (XTypes-capable endpoints only). For non-XTypes endpoints we
    // keep the historic "do not advertise a QoS we don't validate" stance
    // so a receiver does not report a type mismatch when no type
    // information is available to enforce against.
    // PID_ENDPOINT_PROPERTY_CHANGE_EPOCH (0x8015) is a vendor 0x0101 PID and
    // remains unsent.

    // ===== LOCATORS SECTION =====
    locators::write_unicast_locators(&sedp_data.unicast_locators, buf, &mut offset)?;

    // ===== QOS SECTION =====
    // Core QoS policies (order kept stable for interop)
    qos::write_reliability(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_durability(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_durability_service(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_history(sedp_data.qos.as_ref(), buf, &mut offset)?;

    // Additional QoS policies
    qos::write_deadline(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_lifespan(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_ownership(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_ownership_strength(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_liveliness(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_latency_budget(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_destination_order(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_time_based_filter(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_partition(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_resource_limits(sedp_data.qos.as_ref(), buf, &mut offset)?;
    qos::write_presentation(sedp_data.qos.as_ref(), buf, &mut offset)?;

    // ===== TYPE OBJECT / TYPE INFORMATION SECTION =====
    // PID_TYPE_OBJECT (0x0072) - CDR2-encoded CompleteTypeObject
    let tc_policy = sedp_data.type_consistency.as_ref().or_else(|| {
        sedp_data
            .qos
            .as_ref()
            .and_then(|q| q.type_consistency.as_ref())
    });
    if let Some(ref type_obj) = sedp_data.type_object {
        if emit_type_object_pid {
            write_type_object(type_obj, buf, &mut offset)?;
        }
        // PID_TYPE_INFORMATION (0x0075) per DDS-XTypes v1.3 sec. 7.6.3.2.
        // A cross-vendor reader may consult this PID for type-identifier
        // matching alongside PID_TYPE_OBJECT.
        // Soft-skip when the type cannot derive a `MinimalTypeObject`
        // (non-Struct variants today) so the rest of the SEDP packet still
        // serialises cleanly. See the `type_information` module docstring.
        //
        // Feature `xtypes-structural-assignability`: use a pre-computed
        // `TypeInformation` carried in `sedp_data.type_information` when
        // present (built by announce.rs with real dep hashes from the local
        // type store). Fall back to a freshly-derived empty-dep sentinel only
        // when none is pre-computed. Feature OFF: always derive fresh (empty
        // deps / sentinel), preserving byte-identical behaviour vs today.
        #[cfg(feature = "xtypes-structural-assignability")]
        let precomputed = sedp_data.type_information.as_ref();
        #[cfg(not(feature = "xtypes-structural-assignability"))]
        let precomputed = None;
        let ti_opt = type_information::announced_type_information(type_obj, precomputed);
        if let Some(info) = ti_opt {
            let _ = type_information::write_type_information(&info, buf, &mut offset)?;
        }
        // PID_TYPE_CONSISTENCY_ENFORCEMENT (0x0074) per DDS-XTypes v1.3
        // sec. 7.6.3.3.3. Emitted alongside PID_TYPE_INFORMATION so that
        // a cross-vendor reader knows which assignability rules to apply;
        // a reader that assumes a stricter policy when it is absent can
        // reject otherwise-compatible types at the matching layer.
        qos::write_type_consistency_enforcement(tc_policy, buf, &mut offset)?;
    } else if let Some(tc) = tc_policy {
        // When no TypeObject is available but an explicit TypeConsistency policy
        // deviates from the default (e.g. force_type_validation=true), emit the
        // PID so the remote endpoint can apply the correct policy.
        // DDS-XTypes v1.3 sec. 7.6.3.3.3: the PID is not tied to TypeObject presence.
        if tc.force_type_validation
            || !tc.ignore_member_names
            || tc.prevent_type_widening
            || tc.kind != 1
        {
            qos::write_type_consistency_enforcement(Some(tc), buf, &mut offset)?;
        }
    }

    // ===== SENTINEL =====
    if offset + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }
    buf[offset..offset + 2].copy_from_slice(&PID_SENTINEL.to_le_bytes());
    buf[offset + 2..offset + 4].copy_from_slice(&0u16.to_le_bytes());
    offset += 4;

    Ok(offset)
}

/// Write PID_TYPE_OBJECT (0x0072) with CDR2-encoded TypeObject payload.
fn write_type_object(
    type_obj: &CompleteTypeObject,
    buf: &mut [u8],
    offset: &mut usize,
) -> Result<(), ParseError> {
    let mut type_obj_buf = vec![0u8; type_obj.max_cdr2_size()];
    let type_obj_len = type_obj
        .encode_cdr2_le(&mut type_obj_buf)
        .map_err(|_| ParseError::EncodingError)?;

    let aligned_len = (type_obj_len + 3) & !3;
    if aligned_len > u16::MAX as usize {
        return Err(ParseError::InvalidFormat);
    }
    if *offset + 4 + aligned_len > buf.len() {
        return Err(ParseError::BufferTooSmall);
    }

    // Write PID header
    buf[*offset..*offset + 2].copy_from_slice(&PID_TYPE_OBJECT.to_le_bytes());
    let payload_len = u16::try_from(aligned_len).map_err(|_| ParseError::InvalidFormat)?;
    buf[*offset + 2..*offset + 4].copy_from_slice(&payload_len.to_le_bytes());
    *offset += 4;

    // Write CDR2 payload
    buf[*offset..*offset + type_obj_len].copy_from_slice(&type_obj_buf[..type_obj_len]);
    *offset += type_obj_len;

    // Align to 4-byte boundary
    let padding = aligned_len - type_obj_len;
    if padding > 0 {
        buf[*offset..*offset + padding].fill(0);
        *offset += padding;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: verify that build_sedp uses pre-computed TypeInformation (feature-on)
// and falls back to the sentinel (feature-off / no pre-computed value).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::types::{SedpData, TypeInformation};
    use crate::xtypes::{
        CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
        CompleteStructType, CompleteTypeDetail, MemberFlag, StructTypeFlag, TypeIdentifier,
        TypeKind,
    };

    /// PID_TYPE_INFORMATION identifier.
    const PID_TI: u16 = 0x0075;

    fn zero_guid() -> GUID {
        GUID::from_bytes([0u8; 16])
    }

    /// Build a minimal `SedpData` for testing with just a type_object and
    /// optionally a pre-computed `type_information`.
    fn sedp_with_type(
        type_object: Option<CompleteTypeObject>,
        type_information: Option<TypeInformation>,
    ) -> SedpData {
        SedpData {
            topic_name: "TestTopic".to_string(),
            type_name: "TestType".to_string(),
            participant_guid: zero_guid(),
            endpoint_guid: zero_guid(),
            qos_hash: 0,
            qos: None,
            type_object,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            type_information,
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

    /// Find the byte offset of `PID_TYPE_INFORMATION` (0x0075) in a buffer.
    fn find_pid_ti(buf: &[u8]) -> Option<usize> {
        let target = PID_TI.to_le_bytes();
        buf.windows(2).position(|w| w == target)
    }

    /// A simple struct with no deps -- used to assert the spec zero-dep
    /// format is emitted when no `type_information` is pre-computed.
    fn temperature_complete() -> CompleteTypeObject {
        CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("Temperature"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::primitive(TypeKind::TK_FLOAT32),
                },
                detail: CompleteMemberDetail::new("value"),
            }],
        })
    }

    /// The parameter ids of a built SEDP payload, in order, walked as a
    /// parameter list (never searched as bytes).
    fn pids_of(buf: &[u8]) -> Vec<u16> {
        let mut pids = Vec::new();
        let mut at = 4;
        while at + 4 <= buf.len() {
            let pid = u16::from_le_bytes([buf[at], buf[at + 1]]);
            let len = usize::from(u16::from_le_bytes([buf[at + 2], buf[at + 3]]));
            if pid == 0x0001 {
                break;
            }
            pids.push(pid);
            at += 4 + len;
        }
        pids
    }

    /// The value bytes of parameter `pid` in a built SEDP payload.
    fn value_of(buf: &[u8], pid: u16) -> Option<Vec<u8>> {
        let mut at = 4;
        while at + 4 <= buf.len() {
            let this = u16::from_le_bytes([buf[at], buf[at + 1]]);
            let len = usize::from(u16::from_le_bytes([buf[at + 2], buf[at + 3]]));
            if this == pid {
                return Some(buf[at + 4..at + 4 + len].to_vec());
            }
            if this == 0x0001 {
                return None;
            }
            at += 4 + len;
        }
        None
    }

    fn built(qos: crate::dds::QoS) -> Vec<u8> {
        let mut sd = sedp_with_type(None, None);
        sd.qos = Some(qos);
        let mut buf = vec![0u8; 8192];
        let len = build_sedp(&sd, &mut buf).expect("build_sedp must succeed");
        buf.truncate(len);
        buf
    }

    /// DEADLINE, LIFESPAN and LIVELINESS at their defaults (INFINITE,
    /// INFINITE, AUTOMATIC with an INFINITE lease) are not announced: a
    /// receiver takes the default for an absent parameter (RTPS 2.5
    /// Sec.8.5.4.4), and leaving them out removes any chance of a receiver
    /// decoding the explicit INFINITE Duration_t as a finite value.
    /// Parsed back, the defaults are what the receiver sees.
    #[test]
    fn default_duration_policies_are_not_announced() {
        let buf = built(crate::dds::QoS::default());
        let pids = pids_of(&buf);
        for (pid, name) in [
            (0x0023, "DEADLINE"),
            (0x002b, "LIFESPAN"),
            (0x001b, "LIVELINESS"),
        ] {
            assert!(
                !pids.contains(&pid),
                "{name} announced at its default: {pids:04x?}"
            );
        }
        assert!(
            pids.contains(&0x001a),
            "RELIABILITY still announced: {pids:04x?}"
        );
        let parsed = crate::protocol::discovery::sedp::parse::parse_sedp(&buf).expect("parses");
        let qos = parsed.qos.expect("QoS parameters present");
        assert!(qos.deadline.is_infinite());
        assert!(qos.lifespan.is_infinite());
    }

    /// a DEADLINE, a LIFESPAN and a LIVELINESS that are set are
    /// announced, with the endpoint's own values (the LIVELINESS kind and
    /// lease included, not a fixed AUTOMATIC/INFINITE whatever
    /// the endpoint's policy), and a DEADLINE and a LIFESPAN parse back.
    #[test]
    fn set_duration_policies_are_announced_with_their_values() {
        let mut qos = crate::dds::QoS::default();
        qos.deadline = crate::dds::qos::Deadline::new(std::time::Duration::from_millis(1500));
        qos.lifespan = crate::dds::qos::Lifespan::new(std::time::Duration::from_millis(250));
        qos.liveliness =
            crate::dds::qos::Liveliness::manual_by_topic(std::time::Duration::from_millis(2500));
        let buf = built(qos);
        // 1.5 s: seconds 1, fraction 2^31.
        assert_eq!(
            value_of(&buf, 0x0023),
            Some(vec![1, 0, 0, 0, 0, 0, 0, 0x80]),
            "DEADLINE"
        );
        // MANUAL_BY_TOPIC (2), 2.5 s.
        assert_eq!(
            value_of(&buf, 0x001b),
            Some(vec![2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0x80]),
            "LIVELINESS"
        );
        let parsed = crate::protocol::discovery::sedp::parse::parse_sedp(&buf).expect("parses");
        let parsed = parsed.qos.expect("QoS parameters present");
        assert_eq!(
            parsed.deadline.period,
            std::time::Duration::from_millis(1500)
        );
        assert_eq!(
            parsed.lifespan.duration,
            std::time::Duration::from_millis(250)
        );
    }

    /// an AUTOMATIC liveliness with a finite lease is not the default:
    /// announced, kind 0.
    #[test]
    fn a_finite_automatic_lease_is_announced() {
        let mut qos = crate::dds::QoS::default();
        qos.liveliness = crate::dds::qos::Liveliness::automatic(std::time::Duration::from_secs(3));
        let buf = built(qos);
        assert_eq!(
            value_of(&buf, 0x001b),
            Some(vec![0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]),
            "LIVELINESS"
        );
    }

    /// a MANUAL liveliness with an INFINITE lease is not the default
    /// either: announced, with its kind and the INFINITE Duration_t
    /// (seconds 0x7FFFFFFF, fraction 0xFFFFFFFF, RTPS v2.5 Sec.9.3.2).
    #[test]
    fn a_manual_infinite_lease_is_announced() {
        let mut qos = crate::dds::QoS::default();
        qos.liveliness = crate::dds::qos::Liveliness::manual_by_participant(
            std::time::Duration::from_secs(u64::MAX),
        );
        let buf = built(qos);
        assert_eq!(
            value_of(&buf, 0x001b),
            Some(vec![
                1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff
            ]),
            "LIVELINESS"
        );
    }

    /// Feature-OFF and feature-ON (no pre-computed value): build_sedp emits
    /// PID_TYPE_INFORMATION in the spec zero-dep @appendable format
    /// (DHEADER_tiwd present, dep_count = 0, delimited empty sequence).
    #[test]
    fn build_sedp_emits_spec_zero_dep_when_no_type_information_precomputed() {
        let sd = sedp_with_type(Some(temperature_complete()), None);
        let mut buf = vec![0u8; 8192];
        let len = build_sedp(&sd, &mut buf).expect("build_sedp must succeed");
        buf.truncate(len);

        let pid_off = find_pid_ti(&buf).expect("PID_TYPE_INFORMATION must be present");
        // PID layout from pid_off:
        //   [0..4]  PID header (PID + payload_len)
        //   [4..8]  DHEADER outer (96)
        //   [8..12] EMHEADER1 minimal
        //   [12..16] NEXTINT (40 for 0 deps)
        //   [16..20] DHEADER_tiwd (36)
        //   [20..24] DHEADER_tiws (20)
        //   [24]    disc
        //   [25..39] hash (14 bytes)
        //   [39]    pad
        //   [40..44] typeobject_serialized_size
        //   [44..48] dep_count (0)
        //   [48..52] seq_DHEADER (4)
        //   [52..56] seq_count (0)
        let nextint = u32::from_le_bytes(buf[pid_off + 12..pid_off + 16].try_into().unwrap());
        assert_eq!(nextint, 40, "zero-dep NEXTINT must be 40");
        let dheader_tiwd = u32::from_le_bytes(buf[pid_off + 16..pid_off + 20].try_into().unwrap());
        assert_eq!(
            dheader_tiwd, 36,
            "DHEADER_tiwd must be present and equal 36"
        );
        let dep_count = u32::from_le_bytes(buf[pid_off + 44..pid_off + 48].try_into().unwrap());
        assert_eq!(dep_count, 0, "dependent_typeid_count must be 0");
    }

    /// PID_DATA_REPRESENTATION, decoded from the bytes by walking the
    /// parameter list; `None` when absent.
    fn data_representation_pid(buf: &[u8]) -> Option<Vec<u16>> {
        let mut at = 4; // PL_CDR_LE encapsulation header
        while at + 4 <= buf.len() {
            let pid = u16::from_le_bytes([buf[at], buf[at + 1]]);
            let len = usize::from(u16::from_le_bytes([buf[at + 2], buf[at + 3]]));
            let value = &buf[at + 4..at + 4 + len];
            if pid == 0x0001 {
                return None;
            }
            if pid == 0x0073 {
                let n = u32::from_le_bytes(value[..4].try_into().expect("count")) as usize;
                return Some(
                    (0..n)
                        .map(|k| u16::from_le_bytes([value[4 + 2 * k], value[5 + 2 * k]]))
                        .collect(),
                );
            }
            at += 4 + len;
        }
        None
    }

    /// The legacy builder announces DATA_REPRESENTATION as the wire builder
    /// of every dialect does (`announced_data_representation`): a writer its
    /// one representation (`[XCDR]` for an empty list, the first element of
    /// a list), a reader its list (`[XCDR, XCDR2]` for an empty one), the
    /// kind read from the endpoint's entity kind. Before: `[XCDR2]` for any
    /// empty list and every element of a writer's list.
    #[test]
    fn build_sedp_announces_data_representation_by_endpoint_kind() {
        let mut xcdr2_first = crate::dds::QoS::reliable();
        xcdr2_first.data_representation = vec![0x0002, 0x0000];
        for (entity_kind, qos, expected) in [
            (0x02u8, None, vec![0x0000]),
            (0x02, Some(crate::dds::QoS::reliable()), vec![0x0000]),
            (0x02, Some(xcdr2_first.clone()), vec![0x0002]),
            (0x03, Some(crate::dds::QoS::reliable()), vec![0x0000]),
            (0x07, None, vec![0x0000, 0x0002]),
            (
                0x04,
                Some(crate::dds::QoS::reliable()),
                vec![0x0000, 0x0002],
            ),
            (0x07, Some(xcdr2_first.clone()), vec![0x0002, 0x0000]),
        ] {
            let mut guid = [0u8; 16];
            guid[15] = entity_kind;
            let sd = SedpData {
                endpoint_guid: GUID::from_bytes(guid),
                qos,
                ..sedp_with_type(None, None)
            };
            let mut buf = vec![0u8; 4096];
            let n = build_sedp(&sd, &mut buf).expect("build");
            assert_eq!(
                data_representation_pid(&buf[..n]),
                Some(expected),
                "entity kind {entity_kind:#04x}"
            );
        }
    }

    /// `build_sedp_with_options(.., false)` must omit
    /// ONLY PID_TYPE_OBJECT (0x0072) while keeping PID_TYPE_INFORMATION
    /// (0x0075). Rationale: 0x0072 carries HDDS' internal CompleteTypeObject
    /// encoding, not the spec TypeObject a foreign reader would decode (a
    /// failed decode could yield INCONSISTENT_TOPIC), so non-HDDS-bound
    /// SEDP copies drop it; the HDDS self path keeps it byte-identical.
    #[test]
    fn build_sedp_with_options_suppresses_only_type_object_pid() {
        let sd = sedp_with_type(Some(temperature_complete()), None);

        let mut buf_on = vec![0u8; 8192];
        let n_on = build_sedp_with_options(&sd, &mut buf_on, true)
            .expect("build with type object must succeed");
        buf_on.truncate(n_on);

        let mut buf_off = vec![0u8; 8192];
        let n_off = build_sedp_with_options(&sd, &mut buf_off, false)
            .expect("build without type object PID must succeed");
        buf_off.truncate(n_off);

        // Default `build_sedp` must stay byte-identical to the emit=true path
        // (self path unchanged).
        let mut buf_default = vec![0u8; 8192];
        let n_default = build_sedp(&sd, &mut buf_default).expect("default build must succeed");
        buf_default.truncate(n_default);
        assert_eq!(
            buf_on, buf_default,
            "build_sedp must equal build_sedp_with_options(.., true)"
        );

        // Parse both back: type_object present only on the emit=true copy,
        // TypeInformation present on BOTH.
        let parsed_on = crate::protocol::discovery::sedp::parse::parse_sedp(&buf_on)
            .expect("emit=true payload must parse");
        let parsed_off = crate::protocol::discovery::sedp::parse::parse_sedp(&buf_off)
            .expect("emit=false payload must parse");
        assert!(
            parsed_on.type_object.is_some(),
            "emit=true copy must carry PID_TYPE_OBJECT"
        );
        assert!(
            parsed_off.type_object.is_none(),
            "emit=false copy must NOT carry PID_TYPE_OBJECT"
        );
        assert!(
            find_pid_ti(&buf_on).is_some(),
            "PID_TYPE_INFORMATION must stay on the emit=true copy"
        );
        assert!(
            find_pid_ti(&buf_off).is_some(),
            "PID_TYPE_INFORMATION must stay on the emit=false copy"
        );
    }

    /// Feature-ON: when `sedp_data.type_information` is pre-computed with 1 dep,
    /// `build_sedp` must emit PID_TYPE_INFORMATION with dep_count=1 (NOT the
    /// sentinel format). Confirms the wiring from announce.rs through build_sedp.
    #[cfg(feature = "xtypes-structural-assignability")]
    #[test]
    fn build_sedp_uses_precomputed_type_information_with_dep() {
        use crate::xtypes::{
            CommonEnumeratedLiteral, CompleteEnumeratedHeader, CompleteEnumeratedLiteral,
            CompleteEnumeratedType, EnumeratedLiteralFlag,
        };

        // Build E2 enum type.
        let enum_obj = CompleteTypeObject::Enumerated(CompleteEnumeratedType {
            enum_flags: crate::xtypes::StructTypeFlag::IS_APPENDABLE,
            header: CompleteEnumeratedHeader {
                bit_bound: 32,
                detail: CompleteTypeDetail::new("E2"),
            },
            literal_seq: vec![
                CompleteEnumeratedLiteral {
                    common: CommonEnumeratedLiteral {
                        value: 0,
                        flags: EnumeratedLiteralFlag::empty(),
                    },
                    detail: CompleteMemberDetail::new("VAL0"),
                },
                CompleteEnumeratedLiteral {
                    common: CommonEnumeratedLiteral {
                        value: 1,
                        flags: EnumeratedLiteralFlag::empty(),
                    },
                    detail: CompleteMemberDetail::new("VAL1"),
                },
            ],
        });

        // Compute minimal hash of E2 (the store key).
        let min_hash_e2 = crate::dynamic::complete_to_minimal_type_object(&enum_obj)
            .expect("enum must convert to minimal")
            .compute_equivalence_hash()
            .expect("hash must succeed");

        // Build struct `enum2 { E2 x1 }` referencing E2 via minimal hash.
        let struct_obj = CompleteTypeObject::Struct(CompleteStructType {
            struct_flags: StructTypeFlag::IS_FINAL,
            header: CompleteStructHeader {
                base_type: None,
                detail: CompleteTypeDetail::new("enum2"),
            },
            member_seq: vec![CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::minimal(min_hash_e2),
                },
                detail: CompleteMemberDetail::new("x1"),
            }],
        });

        // Build store with E2.
        let mut store = std::collections::HashMap::new();
        store.insert(min_hash_e2, enum_obj);

        // Pre-compute TypeInformation with deps (the path announce.rs takes).
        let type_info = derive_type_information_with_deps(&struct_obj, &store)
            .expect("must derive TypeInformation with deps");

        // Verify the pre-computed info has 1 dep.
        assert_eq!(
            type_info.minimal.as_ref().unwrap().dependent_typeids.len(),
            1,
            "pre-computed TypeInformation must carry 1 dep"
        );

        // Wire it through build_sedp via sedp_data.type_information.
        let sd = sedp_with_type(Some(struct_obj), Some(type_info));
        let mut buf = vec![0u8; 8192];
        let len = build_sedp(&sd, &mut buf).expect("build_sedp must succeed");
        buf.truncate(len);

        // Find PID_TYPE_INFORMATION.
        let pid_off = find_pid_ti(&buf).expect("PID_TYPE_INFORMATION must be present");

        // With 1 dep the minimal member NEXTINT is 64 (at pid_off + 4 + 4 + 4 = pid_off + 12).
        // Layout: PID_header(4) + DHEADER(4) + EMHEADER(4) + NEXTINT(4) = 16 bytes offset to NEXTINT.
        let nextint_bytes = &buf[pid_off + 12..pid_off + 16];
        let nextint = u32::from_le_bytes(nextint_bytes.try_into().unwrap());
        assert_eq!(
            nextint, 64,
            "NEXTINT for 1-dep minimal member must be 64 (not 36 sentinel)"
        );

        // dep_count is at pid_off + 4 (PID hdr) + 4 (DHEADER) + 4 (EMHEADER) + 4 (NEXTINT) +
        // 4 (DHEADER_tiwdeps) + 4 (DHEADER_tiws) + 1 (disc) + 14 (hash) + 1 (pad) + 4 (size) = 44
        let dep_count_bytes = &buf[pid_off + 44..pid_off + 48];
        let dep_count = u32::from_le_bytes(dep_count_bytes.try_into().unwrap());
        assert_eq!(
            dep_count, 1,
            "dep_count must be 1 (pre-computed TypeInformation with dep wired through)"
        );
    }
}

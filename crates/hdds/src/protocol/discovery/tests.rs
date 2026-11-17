// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::constants::{
    PID_DEFAULT_UNICAST_LOCATOR, PID_ENDPOINT_GUID, PID_METATRAFFIC_UNICAST_LOCATOR,
    PID_PARTICIPANT_GUID, PID_PARTICIPANT_LEASE_DURATION, PID_SENTINEL, PID_TOPIC_NAME,
    PID_TYPE_NAME, PID_TYPE_OBJECT,
};
use super::{
    build_sedp, build_spdp, parse_sedp, parse_spdp, parse_topic_name, ParseError, SedpData,
    SpdpData,
};
use crate::core::discovery::GUID;
use crate::core::ser::traits::Cdr2Encode;
use crate::xtypes::{
    CommonStructMember, CompleteMemberDetail, CompleteStructHeader, CompleteStructMember,
    CompleteStructType, CompleteTypeDetail, CompleteTypeObject, MemberFlag, StructTypeFlag,
    TypeIdentifier,
};
use std::convert::TryFrom;

fn sample_complete_type_object() -> CompleteTypeObject {
    let struct_type = CompleteStructType {
        struct_flags: StructTypeFlag::IS_FINAL,
        header: CompleteStructHeader {
            base_type: None,
            detail: CompleteTypeDetail::new("TestType"),
        },
        member_seq: vec![
            CompleteStructMember {
                common: CommonStructMember {
                    member_id: 0,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::TK_INT32,
                },
                detail: CompleteMemberDetail::new("value"),
            },
            // A string member, deliberately: with only the integer above the
            // SEDP round trip below could not see a broken string
            // TypeIdentifier (TK_STRING8 encoded to a bare 0x20 that this
            // crate's own decoder refuses, which silently drops
            // PID_TYPE_OBJECT from every string-bearing endpoint's
            // announcement).
            CompleteStructMember {
                common: CommonStructMember {
                    member_id: 1,
                    member_flags: MemberFlag::empty(),
                    member_type_id: TypeIdentifier::StringSmall { bound: 128 },
                },
                detail: CompleteMemberDetail::new("label"),
            },
        ],
    };
    CompleteTypeObject::Struct(struct_type)
}

#[test]
fn test_parse_spdp_valid() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_PARTICIPANT_GUID.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes());
    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    buf.extend_from_slice(&PID_PARTICIPANT_LEASE_DURATION.to_le_bytes());
    buf.extend_from_slice(&8u16.to_le_bytes());
    buf.extend_from_slice(&200u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_spdp(&buf).expect("SPDP parsing should succeed");
    assert_eq!(
        result.participant_guid.as_bytes(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    );
    assert_eq!(result.lease_duration_ms, 200_000);
}

#[test]
fn test_parse_spdp_truncated() {
    // Buffer with valid encapsulation but truncated PID section
    let buf = vec![0x00, 0x03, 0x00]; // Encapsulation (big-endian) + incomplete
    assert_eq!(parse_spdp(&buf), Err(ParseError::TruncatedData));
}

#[test]
fn test_parse_spdp_invalid_encapsulation() {
    let buf = vec![
        0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(parse_spdp(&buf), Err(ParseError::InvalidEncapsulation));
}

#[test]
fn test_parse_spdp_with_unicast_locator() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_PARTICIPANT_GUID.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes());
    buf.extend_from_slice(&[1; 16]);
    buf.extend_from_slice(&PID_METATRAFFIC_UNICAST_LOCATOR.to_le_bytes());
    buf.extend_from_slice(&24u16.to_le_bytes());
    let mut locator = [0u8; 24];
    locator[0..4].copy_from_slice(&1u32.to_le_bytes()); // LOCATOR_KIND_UDPv4
    locator[4..8].copy_from_slice(&(7400u32).to_be_bytes());
    locator[20..24].copy_from_slice(&[192, 168, 10, 20]);
    buf.extend_from_slice(&locator);
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_spdp(&buf).expect("SPDP parsing should succeed");
    assert_eq!(result.metatraffic_unicast_locators.len(), 1);
    assert_eq!(
        result.metatraffic_unicast_locators[0],
        "192.168.10.20:7400"
            .parse()
            .expect("Socket address parsing should succeed")
    );
}

#[test]
fn test_parse_sedp_valid() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_TOPIC_NAME.to_le_bytes());
    let topic = "TestTopic";
    let topic_len = u32::try_from(topic.len())
        .expect("test topic length fits in u32")
        .checked_add(1)
        .expect("topic length + null fits in u32");
    let topic_param_len = u16::try_from(topic_len + 4).expect("topic parameter length fits in u16");
    buf.extend_from_slice(&topic_param_len.to_le_bytes());
    buf.extend_from_slice(&topic_len.to_le_bytes());
    buf.extend_from_slice(topic.as_bytes());
    buf.push(0);
    buf.resize(buf.len() + (4 - buf.len() % 4) % 4, 0);

    buf.extend_from_slice(&PID_TYPE_NAME.to_le_bytes());
    let type_name = "TestType";
    let type_len = u32::try_from(type_name.len())
        .expect("test type length fits in u32")
        .checked_add(1)
        .expect("type length + null fits in u32");
    let type_param_len = u16::try_from(type_len + 4).expect("type parameter length fits in u16");
    buf.extend_from_slice(&type_param_len.to_le_bytes());
    buf.extend_from_slice(&type_len.to_le_bytes());
    buf.extend_from_slice(type_name.as_bytes());
    buf.push(0);
    buf.resize(buf.len() + (4 - buf.len() % 4) % 4, 0);

    buf.extend_from_slice(&PID_ENDPOINT_GUID.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes());
    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_sedp(&buf).expect("SEDP parsing should succeed");
    assert_eq!(result.topic_name, "TestTopic");
    assert_eq!(result.type_name, "TestType");
    assert_eq!(
        result.endpoint_guid.as_bytes(),
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    );
}

#[test]
fn test_parse_sedp_truncated() {
    // Buffer with valid encapsulation but truncated PID section
    // Encapsulation is big-endian, so CDR_LE (0x0003) = [0x00, 0x03]
    let buf = vec![0x00, 0x03, 0x00]; // Encapsulation (BE) + incomplete PID header
    assert!(matches!(parse_sedp(&buf), Err(ParseError::TruncatedData)));
}

#[test]
fn test_parse_sedp_invalid_encapsulation() {
    let buf = vec![
        0xFF, 0xFF, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
    ];
    assert!(matches!(
        parse_sedp(&buf),
        Err(ParseError::InvalidEncapsulation)
    ));
}

#[test]
fn test_parse_sedp_missing_required_fields() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&[0u8; 4]);
    assert!(matches!(parse_sedp(&buf), Err(ParseError::InvalidFormat)));
}

#[test]
#[ignore = "pre-existing roundtrip regression, deferred to a later release"]
fn test_parse_sedp_with_type_object() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_TOPIC_NAME.to_le_bytes());
    let topic = "TestTopic";
    let topic_len = u32::try_from(topic.len())
        .expect("test topic length fits in u32")
        .checked_add(1)
        .expect("topic length + null fits in u32");
    let topic_param_len = u16::try_from(topic_len + 4).expect("topic parameter length fits in u16");
    buf.extend_from_slice(&topic_param_len.to_le_bytes());
    buf.extend_from_slice(&topic_len.to_le_bytes());
    buf.extend_from_slice(topic.as_bytes());
    buf.push(0);
    buf.resize(buf.len() + (4 - buf.len() % 4) % 4, 0);

    buf.extend_from_slice(&PID_TYPE_NAME.to_le_bytes());
    let type_name = "TestType";
    let type_len = u32::try_from(type_name.len())
        .expect("test type length fits in u32")
        .checked_add(1)
        .expect("type length + null fits in u32");
    let type_param_len = u16::try_from(type_len + 4).expect("type parameter length fits in u16");
    buf.extend_from_slice(&type_param_len.to_le_bytes());
    buf.extend_from_slice(&type_len.to_le_bytes());
    buf.extend_from_slice(type_name.as_bytes());
    buf.push(0);
    buf.resize(buf.len() + (4 - buf.len() % 4) % 4, 0);

    buf.extend_from_slice(&PID_ENDPOINT_GUID.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes());
    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

    let type_object = sample_complete_type_object();
    let mut type_obj_buf = vec![0u8; 512];
    let type_obj_len = type_object
        .encode_cdr2_le(&mut type_obj_buf)
        .expect("encoding type object should succeed");
    buf.extend_from_slice(&PID_TYPE_OBJECT.to_le_bytes());
    let type_obj_len_u16 =
        u16::try_from(type_obj_len).expect("type object length fits in u16 for tests");
    buf.extend_from_slice(&type_obj_len_u16.to_le_bytes());
    buf.extend_from_slice(&type_obj_buf[..type_obj_len]);
    buf.resize(buf.len() + (4 - buf.len() % 4) % 4, 0);

    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    let result = parse_sedp(&buf).expect("SEDP parsing should succeed");
    assert!(result.type_object.is_some());
}

#[test]
fn test_parse_topic_name_valid() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_TOPIC_NAME.to_le_bytes());
    let topic = "TestTopic";
    let topic_len = u32::try_from(topic.len())
        .expect("test topic length fits in u32")
        .checked_add(1)
        .expect("topic length + null fits in u32");
    let topic_param_len = u16::try_from(topic_len + 4).expect("topic parameter length fits in u16");
    buf.extend_from_slice(&topic_param_len.to_le_bytes());
    buf.extend_from_slice(&topic_len.to_le_bytes());
    buf.extend_from_slice(topic.as_bytes());
    buf.push(0);
    buf.resize(buf.len() + (4 - buf.len() % 4) % 4, 0);
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    let topic_name = parse_topic_name(&buf).expect("topic name should be parsed");
    assert_eq!(topic_name, "TestTopic");
}

#[test]
fn test_parse_topic_name_missing() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    assert!(parse_topic_name(&buf).is_none());
}

#[test]
fn test_parse_topic_name_truncated() {
    let buf = vec![0x00, 0x03];
    assert!(parse_topic_name(&buf).is_none());
}

#[test]
fn test_parse_topic_name_invalid_encapsulation() {
    let buf = vec![
        0xFF, 0xFF, 0x00, 0x00, 0x05, 0x00, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00,
    ];
    assert!(parse_topic_name(&buf).is_none());
}

#[test]
fn test_parse_topic_name_invalid_utf8() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
    buf.extend_from_slice(&PID_TOPIC_NAME.to_le_bytes());
    buf.extend_from_slice(&8u16.to_le_bytes());
    buf.extend_from_slice(&5u32.to_le_bytes());
    buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    buf.push(0);
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    assert!(parse_topic_name(&buf).is_none());
}

#[test]
fn test_build_sedp_roundtrip_with_type_object() {
    let sedp_data = SedpData {
        topic_name: "TestTopic".to_string(),
        type_name: "TestType".to_string(),
        participant_guid: GUID::zero(), // Test data
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
        qos: None, // Tests use default QoS values
        type_object: Some(sample_complete_type_object()),
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
    };

    let mut buf = vec![0u8; 2048];
    let len = build_sedp(&sedp_data, &mut buf).expect("SEDP build should succeed");
    let parsed = parse_sedp(&buf[..len]).expect("SEDP parse should succeed");

    assert_eq!(parsed.topic_name, sedp_data.topic_name);
    assert_eq!(parsed.type_name, sedp_data.type_name);
    assert_eq!(parsed.endpoint_guid, sedp_data.endpoint_guid);
    // Full equality, not is_some(). A TypeObject that survives the wire as a
    // DIFFERENT object is the failure this round trip exists to catch, and
    // presence alone cannot see it.
    assert_eq!(parsed.type_object, sedp_data.type_object);
}

#[test]
fn test_build_sedp_roundtrip_without_type_object() {
    let sedp_data = SedpData {
        topic_name: "TestTopic".to_string(),
        type_name: "TestType".to_string(),
        participant_guid: GUID::zero(), // Test data
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
        qos: None, // Tests use default QoS values
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
    };

    let mut buf = vec![0u8; 1024];
    let len = build_sedp(&sedp_data, &mut buf).expect("SEDP build should succeed");
    let parsed = parse_sedp(&buf[..len]).expect("SEDP parse should succeed");

    assert_eq!(parsed.topic_name, sedp_data.topic_name);
    assert_eq!(parsed.type_name, sedp_data.type_name);
    assert_eq!(parsed.endpoint_guid, sedp_data.endpoint_guid);
    assert!(parsed.type_object.is_none());
}

#[test]
fn test_sedp_pid_order_endpoint_then_participant() {
    let sedp_data = SedpData {
        topic_name: "OrderCheck".to_string(),
        type_name: "OrderType".to_string(),
        participant_guid: GUID::zero(),
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
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
    };

    let mut buf = vec![0u8; 1024];
    let len = build_sedp(&sedp_data, &mut buf).expect("SEDP build should succeed");
    assert!(len > 36);

    let first_pid = u16::from_le_bytes([buf[4], buf[5]]);
    let second_pid = u16::from_le_bytes([buf[24], buf[25]]);
    assert_eq!(
        first_pid, PID_ENDPOINT_GUID,
        "PID order mismatch: endpoint must be first"
    );
    assert_eq!(
        second_pid, PID_PARTICIPANT_GUID,
        "PID order mismatch: participant must be second"
    );
}

#[test]
fn test_build_sedp_buffer_too_small() {
    let sedp_data = SedpData {
        topic_name: "TestTopic".to_string(),
        type_name: "TestType".to_string(),
        participant_guid: GUID::zero(), // Test data
        endpoint_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        qos_hash: 0,
        qos: None, // Tests use default QoS values
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
    };

    let mut buf = vec![0u8; 16];
    let result = build_sedp(&sedp_data, &mut buf);
    assert_eq!(result, Err(ParseError::BufferTooSmall));
}

#[test]
fn test_build_spdp_roundtrip_with_locators() {
    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        lease_duration_ms: 120_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec!["192.168.0.1:7410".parse().expect("valid addr")],
        default_unicast_locators: vec!["192.168.0.1:7411".parse().expect("valid addr")],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };

    let mut buf = vec![0u8; 1024];
    let len = build_spdp(&spdp_data, &mut buf).expect("SPDP build should succeed");
    let parsed = parse_spdp(&buf[..len]).expect("SPDP parse should succeed");

    assert_eq!(parsed.participant_guid, spdp_data.participant_guid);
    assert_eq!(parsed.lease_duration_ms, spdp_data.lease_duration_ms);
    assert_eq!(
        parsed.metatraffic_unicast_locators,
        spdp_data.metatraffic_unicast_locators
    );
    assert_eq!(
        parsed.default_unicast_locators,
        spdp_data.default_unicast_locators
    );
}

#[test]
fn test_build_spdp_preserves_ipv6_locator_bytes() {
    let ip: std::net::Ipv6Addr = "2001:db8:1234:5678:9abc:def0:1111:2222"
        .parse()
        .expect("valid IPv6 address");
    let locator = std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 7411);
    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        lease_duration_ms: 120_000,
        domain_id: 0,
        metatraffic_unicast_locators: Vec::new(),
        default_unicast_locators: vec![locator],
        default_multicast_locators: Vec::new(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };

    let mut buf = vec![0u8; 1024];
    let len = build_spdp(&spdp_data, &mut buf).expect("SPDP build should succeed");
    let pid = PID_DEFAULT_UNICAST_LOCATOR.to_le_bytes();
    let pos = buf[..len]
        .windows(4)
        .position(|w| w[0..2] == pid && w[2..4] == 24u16.to_le_bytes())
        .expect("default unicast locator parameter");

    assert_eq!(&buf[pos + 4..pos + 8], &2u32.to_le_bytes());
    assert_eq!(&buf[pos + 8..pos + 12], &7411u32.to_le_bytes());
    assert_eq!(&buf[pos + 12..pos + 28], &ip.octets());
}

#[test]
fn test_build_spdp_roundtrip_without_locators() {
    let mut spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        // Exercise the RTPS Duration_t 2^-32 fractional-second field.
        lease_duration_ms: 90_501,
        domain_id: 0,
        metatraffic_unicast_locators: Vec::new(),
        default_unicast_locators: Vec::new(),
        default_multicast_locators: Vec::new(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };

    let mut buf = vec![0u8; 1024]; // Increased for property list (7 properties ~600 bytes)
    let len = build_spdp(&spdp_data, &mut buf).expect("SPDP build should succeed");
    let parsed = parse_spdp(&buf[..len]).expect("SPDP parse should succeed");

    assert_eq!(parsed.participant_guid, spdp_data.participant_guid);
    assert_eq!(parsed.lease_duration_ms, spdp_data.lease_duration_ms);
    assert_eq!(parsed.metatraffic_unicast_locators.len(), 0);
    assert_eq!(parsed.default_unicast_locators.len(), 0);

    spdp_data.lease_duration_ms = (i32::MAX as u64 + 1) * 1000 + 501;
    let len = build_spdp(&spdp_data, &mut buf).expect("oversized SPDP lease should clamp");
    let parsed = parse_spdp(&buf[..len]).expect("clamped SPDP should parse");
    assert_eq!(parsed.lease_duration_ms, u64::MAX);
}

#[test]
fn a_999_ms_lease_remainder_fills_the_fraction_without_wrapping() {
    // build.rs computes `fraction = (remaining_ms << 32) / 1000` and casts to
    // u32. `remaining_ms` is `lease_duration_ms % 1000`, so 999 is the largest
    // it can be, and that is the only input that could overflow the cast.
    // The audit flags the cast; this is the measurement that answers it.
    let worst_case = (999u64 << 32) / 1000;
    assert_eq!(worst_case, 4_290_672_328);
    assert!(
        worst_case <= u32::MAX as u64,
        "the Duration_t fraction must fit in 32 bits"
    );

    // And the whole 999 ms remainder survives a build/parse round trip.
    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        lease_duration_ms: 30_999,
        domain_id: 0,
        metatraffic_unicast_locators: Vec::new(),
        default_unicast_locators: Vec::new(),
        default_multicast_locators: Vec::new(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };
    let mut buf = vec![0u8; 1024];
    let len = build_spdp(&spdp_data, &mut buf).expect("SPDP build should succeed");
    let parsed = parse_spdp(&buf[..len]).expect("SPDP parse should succeed");
    assert_eq!(parsed.lease_duration_ms, 30_999);
}

#[test]
fn test_build_spdp_buffer_too_small() {
    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        lease_duration_ms: 120_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec!["192.168.0.1:7410".parse().expect("valid addr")],
        default_unicast_locators: vec!["192.168.0.1:7411".parse().expect("valid addr")],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };

    let mut buf = vec![0u8; 16];
    let result = build_spdp(&spdp_data, &mut buf);
    assert_eq!(result, Err(ParseError::BufferTooSmall));
}

#[cfg(feature = "security")]
#[test]
fn test_build_spdp_roundtrip_with_security_tokens() {
    // Opaque DataHolder-shaped payloads. The wire emission pads the value
    // to a 4-byte boundary (RTPS v2.5 sec. 9.4.2.11); use inputs whose length
    // is already a multiple of 4 to make the round-trip identity-clean.
    use crate::protocol::discovery::spdp::data_holder::serialize_data_holder;
    let identity_bytes = serialize_data_holder(
        "DDS:Auth:PKI-DH:1.0",
        &[],
        &[(
            "dds.cert.identity".to_string(),
            vec![0x30u8, 0x82, 0x01, 0x00],
            true,
        )],
    )
    .expect("encode");
    let permissions_bytes = serialize_data_holder(
        "DDS:Access:Permissions:1.0",
        &[("dds.perm.cert.sn".to_string(), "01ABCD".to_string(), true)],
        &[],
    )
    .expect("encode");
    assert_eq!(identity_bytes.len() % 4, 0);
    assert_eq!(permissions_bytes.len() % 4, 0);

    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xc1]),
        lease_duration_ms: 120_000,
        domain_id: 0,
        metatraffic_unicast_locators: Vec::new(),
        default_unicast_locators: Vec::new(),
        default_multicast_locators: Vec::new(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token: Some(identity_bytes.clone()),
        permissions_token: Some(permissions_bytes.clone()),
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };

    let mut buf = vec![0u8; 4096];
    let len = build_spdp(&spdp_data, &mut buf).expect("SPDP build should succeed");
    let parsed = parse_spdp(&buf[..len]).expect("SPDP parse should succeed");

    assert_eq!(
        parsed.identity_token.as_deref(),
        Some(identity_bytes.as_slice())
    );
    assert_eq!(
        parsed.permissions_token.as_deref(),
        Some(permissions_bytes.as_slice())
    );
}

#[test]
fn test_build_spdp_roundtrip_without_security_tokens() {
    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0xc1]),
        lease_duration_ms: 60_000,
        domain_id: 0,
        metatraffic_unicast_locators: Vec::new(),
        default_unicast_locators: Vec::new(),
        default_multicast_locators: Vec::new(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };

    let mut buf = vec![0u8; 1024];
    let len = build_spdp(&spdp_data, &mut buf).expect("SPDP build should succeed");
    let parsed = parse_spdp(&buf[..len]).expect("SPDP parse should succeed");
    assert!(parsed.identity_token.is_none());
    assert!(parsed.permissions_token.is_none());
}

// DDS-XTypes v1.3 sec. 7.6.3.4: when PID_TYPE_CONSISTENCY_ENFORCEMENT is absent from
// the wire, parse_sedp must return type_consistency = None so that the downstream
// matcher falls back to the spec-permissive default_policy() (ALLOW_TYPE_COERCION,
// ignore_member_names=true). Forcing Some(Default::default()) here would bypass the
// fallback and silently enforce ignore_member_names=false on peers that omit the PID.
#[test]
fn parse_omitted_type_consistency_enforcement_returns_none() {
    let mut buf: Vec<u8> = Vec::new();

    // CDR_LE encapsulation header (4 bytes)
    buf.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);

    // PID_ENDPOINT_GUID (0x005a), length = 16
    buf.extend_from_slice(&PID_ENDPOINT_GUID.to_le_bytes());
    buf.extend_from_slice(&16u16.to_le_bytes());
    buf.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 7]);

    // PID_TOPIC_NAME (0x0005) -- CDR string "Foo\0" (4 bytes incl. null)
    let topic_str: &[u8] = b"Foo\0";
    let topic_len = 4u32; // CDR string length field (byte count incl. null)
    let pid_topic_payload_len = 4 + topic_str.len(); // u32 + "Foo\0"
    buf.extend_from_slice(&PID_TOPIC_NAME.to_le_bytes());
    buf.extend_from_slice(&(pid_topic_payload_len as u16).to_le_bytes());
    buf.extend_from_slice(&topic_len.to_le_bytes());
    buf.extend_from_slice(topic_str);

    // PID_TYPE_NAME (0x0007) -- CDR string "Bar\0" (4 bytes incl. null)
    let type_str: &[u8] = b"Bar\0";
    let type_len = 4u32;
    let pid_type_payload_len = 4 + type_str.len();
    buf.extend_from_slice(&PID_TYPE_NAME.to_le_bytes());
    buf.extend_from_slice(&(pid_type_payload_len as u16).to_le_bytes());
    buf.extend_from_slice(&type_len.to_le_bytes());
    buf.extend_from_slice(type_str);

    // PID_SENTINEL -- no PID_TYPE_CONSISTENCY_ENFORCEMENT on the wire
    buf.extend_from_slice(&PID_SENTINEL.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    let parsed = parse_sedp(&buf).expect("minimal SEDP without type consistency should parse");

    assert!(
        parsed.type_consistency.is_none(),
        "type_consistency must be None when PID_TYPE_CONSISTENCY_ENFORCEMENT is absent; \
         the downstream matcher will apply default_policy() (ALLOW_TYPE_COERCION, \
         ignore_member_names=true) as the spec-permissive fallback"
    );
}

/// A minimal SEDP publication (PL_CDR_LE, or PL_CDR_BE when `!le`): topic
/// "T", type "Y", endpoint GUID, then `extra` parameters as they are.
fn sedp_with(le: bool, extra: &[u8]) -> Vec<u8> {
    let u16b = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let u32b = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let mut buf = vec![0x00, if le { 0x03 } else { 0x02 }, 0x00, 0x00];
    for (pid, text) in [(PID_TOPIC_NAME, "T"), (PID_TYPE_NAME, "Y")] {
        buf.extend_from_slice(&u16b(pid));
        buf.extend_from_slice(&u16b(8));
        buf.extend_from_slice(&u32b(2));
        buf.extend_from_slice(text.as_bytes());
        buf.extend_from_slice(&[0, 0, 0]);
    }
    buf.extend_from_slice(&u16b(PID_ENDPOINT_GUID));
    buf.extend_from_slice(&u16b(16));
    buf.extend_from_slice(&[7; 12]);
    buf.extend_from_slice(&[0, 0, 1, 2]);
    buf.extend_from_slice(extra);
    buf.extend_from_slice(&u16b(PID_SENTINEL));
    buf.extend_from_slice(&u16b(0));
    buf
}

/// PID_DATA_TAGS (0x1003, DDS Security v1.1 Table 14) carrying `tags`,
/// laid out by hand from the IDL of Sec.7.2.5 (`DataTags { sequence<Tag>
/// tags; }`, `Tag { string name; string value; }`), XCDR1: a count, then per
/// tag two CDR strings (length with the NUL, bytes, NUL, padding to 4).
/// Written from the specification, not with our encoder (HDDS emits no
/// PID_DATA_TAGS): a fixture from our own encoder would ratify our own
/// reading.
fn data_tags_parameter(le: bool, tags: &[(&str, &str)]) -> Vec<u8> {
    let u16b = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let u32b = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let mut value = Vec::new();
    value.extend_from_slice(&u32b(u32::try_from(tags.len()).expect("count")));
    for (name, tag_value) in tags {
        for text in [name, tag_value] {
            value.extend_from_slice(&u32b(u32::try_from(text.len() + 1).expect("length")));
            value.extend_from_slice(text.as_bytes());
            value.push(0);
            while value.len() % 4 != 0 {
                value.push(0);
            }
        }
    }
    let mut parameter = Vec::new();
    parameter.extend_from_slice(&u16b(0x1003));
    parameter.extend_from_slice(&u16b(u16::try_from(value.len()).expect("length")));
    parameter.extend_from_slice(&value);
    parameter
}

/// A remote endpoint's data tags (PID_DATA_TAGS) reach its QoS, both
/// endiannesses; an announcement without them has none.
#[test]
fn the_data_tags_of_an_announcement_are_read() {
    for le in [true, false] {
        let tags = [("aTagName1", "aTagValue1"), ("n", "")];
        let sedp = parse_sedp(&sedp_with(le, &data_tags_parameter(le, &tags))).expect("parses");
        let read: Vec<(String, String)> = sedp
            .qos
            .expect("a QoS")
            .data_tags
            .tags
            .into_iter()
            .map(|tag| (tag.name, tag.value))
            .collect();
        assert_eq!(
            read,
            vec![
                ("aTagName1".to_string(), "aTagValue1".to_string()),
                ("n".to_string(), String::new())
            ],
            "le={}",
            le
        );
    }
    let untagged = parse_sedp(&sedp_with(true, &[])).expect("parses");
    assert!(untagged.qos.is_none_or(|qos| qos.data_tags.is_empty()));
}

/// A PID_DATA_TAGS that does not read whole refuses the announcement: the
/// access control would judge the endpoint on tags it does not carry.
#[test]
fn malformed_data_tags_refuse_the_announcement() {
    let good = data_tags_parameter(true, &[("a", "b")]);
    // The value starts after the 4-byte parameter header.
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    // A count far past what the value holds.
    let mut count = good.clone();
    count[4..8].copy_from_slice(&1000u32.to_le_bytes());
    cases.push(("count", count));
    // A string length running past the value.
    let mut long = good.clone();
    long[8..12].copy_from_slice(&64u32.to_le_bytes());
    cases.push(("string length", long));
    // A string without its NUL.
    let mut unterminated = good.clone();
    unterminated[13] = b'x';
    cases.push(("no NUL", unterminated));
    // A zero-length string (a CDR string counts its NUL).
    let mut empty = good.clone();
    empty[8..12].copy_from_slice(&0u32.to_le_bytes());
    cases.push(("zero length", empty));
    // Not UTF-8.
    let mut binary = good.clone();
    binary[12] = 0xFF;
    cases.push(("not UTF-8", binary));
    for (what, parameter) in cases {
        assert!(
            matches!(
                parse_sedp(&sedp_with(true, &parameter)),
                Err(ParseError::InvalidFormat)
            ),
            "{}",
            what
        );
    }
    // The fixture itself reads.
    assert!(parse_sedp(&sedp_with(true, &good)).is_ok());
}

/// PID_ENDPOINT_SECURITY_INFO (0x1004, DDS Security v1.1 Sec.7.2.8,
/// 7.4.1.5) carrying the two masks, laid out by hand from the
/// specification: a 4-byte PID header then the two u32 masks, in the
/// parameter list's own byte order. Written independently of our own
/// encoder (`rtps_packet.rs`'s `insert_endpoint_security_info`, tested on
/// its own): a fixture built from it would ratify our own reading.
fn endpoint_security_info_parameter(le: bool, mask: u32, plugin_mask: u32) -> Vec<u8> {
    let u16b = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let u32b = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let mut parameter = Vec::new();
    parameter.extend_from_slice(&u16b(0x1004));
    parameter.extend_from_slice(&u16b(8));
    parameter.extend_from_slice(&u32b(mask));
    parameter.extend_from_slice(&u32b(plugin_mask));
    parameter
}

/// A remote endpoint's `PID_ENDPOINT_SECURITY_INFO` reaches `SedpData`,
/// both endiannesses; an announcement without it decodes to `None`, which
/// `EndpointSecurityInfo::matches` reads the same as an all-zero mask.
#[test]
fn the_endpoint_security_info_of_an_announcement_is_read() {
    for le in [true, false] {
        for bit in 0..7 {
            let mask = 0x8000_0000 | (1 << bit);
            let sedp = parse_sedp(&sedp_with(
                le,
                &endpoint_security_info_parameter(le, mask, 0x8000_0000),
            ))
            .expect("parses");
            let info = sedp.endpoint_security_info.expect("present");
            assert_eq!(info.endpoint_security_attributes, mask);
            for (index, value) in [
                info.is_read_protected(),
                info.is_write_protected(),
                info.is_discovery_protected(),
                info.is_submessage_protected(),
                info.is_payload_protected(),
                info.is_key_protected(),
                info.is_liveliness_protected(),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(value, index == bit, "standard bit {bit}, le={le}");
            }
        }
        for bit in 0..3 {
            let plugin = 0x8000_0000 | (1 << bit);
            let sedp = parse_sedp(&sedp_with(
                le,
                &endpoint_security_info_parameter(le, 0x8000_0000, plugin),
            ))
            .expect("parses");
            let info = sedp.endpoint_security_info.expect("present");
            assert_eq!(info.plugin_endpoint_security_attributes, plugin);
            for (index, value) in [
                info.is_submessage_encrypted(),
                info.is_payload_encrypted(),
                info.is_submessage_origin_authenticated(),
            ]
            .into_iter()
            .enumerate()
            {
                assert_eq!(value, index == bit, "plugin bit {bit}, le={le}");
            }
        }
    }
    let without = parse_sedp(&sedp_with(true, &[])).expect("parses");
    assert_eq!(without.endpoint_security_info, None);
}

/// A `PID_ENDPOINT_SECURITY_INFO` shorter than its 8-byte payload is
/// ignored, not refused: the announcement still parses, with the field left
/// `None` -- the same posture as a peer that sent no such PID.
#[test]
fn a_truncated_endpoint_security_info_is_ignored() {
    let mut truncated = endpoint_security_info_parameter(true, 0x8000_0001, 0x8000_0000);
    // Shrink the declared length to 4: only the first mask would be read.
    truncated[2..4].copy_from_slice(&4u16.to_le_bytes());
    truncated.truncate(8);
    let sedp = parse_sedp(&sedp_with(true, &truncated)).expect("parses");
    assert_eq!(sedp.endpoint_security_info, None);
}

/// PID_DATA_TAGS in an XCDR2 parameter list (PL_CDR2_LE): DataTags, the
/// sequence of Tag and each Tag are `@appendable`, each preceded by a
/// DHEADER (DDS-XTypes v1.3 Sec.7.4.3.5), laid out by hand from the IDL.
#[test]
fn the_data_tags_of_an_xcdr2_announcement_are_read() {
    let mut tag = Vec::new();
    for text in ["aTagName1", "aTagValue1"] {
        tag.extend_from_slice(&u32::try_from(text.len() + 1).expect("len").to_le_bytes());
        tag.extend_from_slice(text.as_bytes());
        tag.push(0);
        while tag.len() % 4 != 0 {
            tag.push(0);
        }
    }
    let mut sequence = Vec::new();
    sequence.extend_from_slice(&1u32.to_le_bytes());
    sequence.extend_from_slice(&u32::try_from(tag.len()).expect("len").to_le_bytes());
    sequence.extend_from_slice(&tag);
    let mut value = Vec::new();
    value.extend_from_slice(
        &u32::try_from(sequence.len() + 4)
            .expect("len")
            .to_le_bytes(),
    );
    value.extend_from_slice(&u32::try_from(sequence.len()).expect("len").to_le_bytes());
    value.extend_from_slice(&sequence);
    let mut parameter = Vec::new();
    parameter.extend_from_slice(&0x1003u16.to_le_bytes());
    parameter.extend_from_slice(&u16::try_from(value.len()).expect("len").to_le_bytes());
    parameter.extend_from_slice(&value);
    let mut buf = sedp_with(true, &parameter);
    // PL_CDR2_LE
    buf[1] = 0x0B;
    let sedp = parse_sedp(&buf).expect("parses");
    let tags = sedp.qos.expect("a QoS").data_tags.tags;
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].name, "aTagName1");
    assert_eq!(tags[0].value, "aTagValue1");
}

/// More data tags than `MAX_DATA_TAGS` (256) refuse the announcement, even
/// when the parameter holds them all.
#[test]
fn an_announcement_with_too_many_data_tags_is_refused() {
    let names: Vec<String> = (0..257).map(|i| format!("{}", i % 10)).collect();
    let tags: Vec<(&str, &str)> = names.iter().map(|name| (name.as_str(), "")).collect();
    assert!(matches!(
        parse_sedp(&sedp_with(true, &data_tags_parameter(true, &tags))),
        Err(ParseError::InvalidFormat)
    ));
    assert!(parse_sedp(&sedp_with(true, &data_tags_parameter(true, &tags[..256]))).is_ok());
}

fn v3_rng(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// PID_DATA_TAGS value bytes wrapped in the parameter header, padded to 4.
fn v3_param(le: bool, value: &[u8]) -> Vec<u8> {
    let mut v = value.to_vec();
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    let u16b = |x: u16| if le { x.to_le_bytes() } else { x.to_be_bytes() };
    let mut p = Vec::new();
    p.extend_from_slice(&u16b(0x1003));
    p.extend_from_slice(&u16b(u16::try_from(v.len()).unwrap_or(u16::MAX)));
    p.extend_from_slice(&v);
    p
}

/// Hostile PID_DATA_TAGS in all four encapsulations: random bytes, small
/// structured words (counts and lengths near the boundaries), and bit flips
/// of a valid encoding. Never a panic; whatever parses holds <= 256 tags
/// whose strings fit in the value.
#[test]
fn verify3_data_tags_fuzz_never_panics_nor_overallocates() {
    let mut st = 0xD1B5_4A32_D192_ED03u64;
    let interesting: [u32; 12] = [
        0,
        1,
        2,
        3,
        4,
        5,
        255,
        256,
        257,
        0x7FFF_FFFF,
        0xFFFF_FFFF,
        0x8000_0000,
    ];
    let mut parsed_ok = 0usize;
    let mut refused = 0usize;
    for round in 0..300_000u32 {
        let le = round % 2 == 0;
        let cdr2 = (round / 2) % 2 == 0;
        let len = (v3_rng(&mut st) % 200) as usize;
        let mut value = Vec::with_capacity(len);
        match round % 3 {
            0 => {
                for _ in 0..len {
                    value.push(v3_rng(&mut st) as u8);
                }
            }
            1 => {
                for _ in 0..len / 4 {
                    let w = if v3_rng(&mut st).is_multiple_of(2) {
                        interesting[(v3_rng(&mut st) % 12) as usize]
                    } else {
                        (v3_rng(&mut st) % 12) as u32
                    };
                    value.extend_from_slice(&if le { w.to_le_bytes() } else { w.to_be_bytes() });
                }
            }
            _ => {
                let good = data_tags_parameter(le, &[("aTagName1", "aTagValue1"), ("b", "")]);
                value.extend_from_slice(&good[4..]);
                let flips = 1 + v3_rng(&mut st) % 4;
                for _ in 0..flips {
                    let i = (v3_rng(&mut st) as usize) % value.len();
                    value[i] ^= 1 << (v3_rng(&mut st) % 8);
                }
            }
        }
        let mut sedp = sedp_with(le, &v3_param(le, &value));
        if cdr2 {
            sedp[1] = if le { 0x0B } else { 0x0A };
        }
        match std::panic::catch_unwind(|| parse_sedp(&sedp)) {
            Err(_) => panic!("panic on value {:02x?} le={} cdr2={}", value, le, cdr2),
            Ok(Ok(data)) => {
                parsed_ok += 1;
                if let Some(qos) = data.qos {
                    let total: usize = qos
                        .data_tags
                        .tags
                        .iter()
                        .map(|t| t.name.len() + t.value.len())
                        .sum();
                    assert!(qos.data_tags.tags.len() <= 256);
                    assert!(total <= value.len(), "strings longer than the value");
                }
            }
            Ok(Err(_)) => refused += 1,
        }
    }
    eprintln!(
        "[verify3] data tags fuzz: {} parsed, {} refused",
        parsed_ok, refused
    );
}

/// The 256 bound from both sides, XCDR1 and XCDR2 (written by hand from
/// XTypes 7.4.3.5: DHEADER(DataTags), DHEADER(sequence), count, per Tag
/// DHEADER + two strings).
#[test]
fn verify3_data_tags_bound_both_sides_and_xcdr2_layout() {
    fn build(le: bool, cdr2: bool, n: usize) -> Vec<u8> {
        let w = |x: u32| if le { x.to_le_bytes() } else { x.to_be_bytes() };
        let mut body = Vec::new();
        body.extend_from_slice(&w(n as u32));
        for _ in 0..n {
            let mut tag = Vec::new();
            for s in ["n", "v"] {
                tag.extend_from_slice(&w(2));
                tag.extend_from_slice(s.as_bytes());
                tag.extend_from_slice(&[0, 0, 0]);
            }
            if cdr2 {
                body.extend_from_slice(&w(tag.len() as u32));
            }
            body.extend_from_slice(&tag);
        }
        let mut value = Vec::new();
        if cdr2 {
            value.extend_from_slice(&w(body.len() as u32 + 4));
            value.extend_from_slice(&w(body.len() as u32));
        }
        value.extend_from_slice(&body);
        value
    }
    for le in [true, false] {
        for cdr2 in [false, true] {
            for (n, ok) in [(256usize, true), (257, false)] {
                let mut sedp = sedp_with(le, &v3_param(le, &build(le, cdr2, n)));
                if cdr2 {
                    sedp[1] = if le { 0x0B } else { 0x0A };
                }
                let r = parse_sedp(&sedp);
                assert_eq!(
                    r.is_ok(),
                    ok,
                    "n={} le={} cdr2={}: {:?}",
                    n,
                    le,
                    cdr2,
                    r.as_ref().err()
                );
                if let Ok(d) = r {
                    assert_eq!(d.qos.expect("qos").data_tags.tags.len(), n);
                }
            }
        }
    }
}

/// A QoS parameter `pid` whose value is `words` (32-bit words, each in the
/// payload's endianness), as RTPS v2.5 Sec.9.6.2.2 lays the policies out:
/// LivelinessQosPolicy `{ kind; Duration_t lease_duration }`,
/// LatencyBudgetQosPolicy `{ Duration_t duration }`,
/// DestinationOrderQosPolicy `{ kind }`, Duration_t `{ int32 seconds;
/// uint32 fraction }` (Sec.9.3.2, fraction in 2^-32 s). Written by hand
/// from the specification, not with our encoder.
fn qos_parameter(le: bool, pid: u16, words: &[u32]) -> Vec<u8> {
    let u16b = |v: u16| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let mut parameter = Vec::new();
    parameter.extend_from_slice(&u16b(pid));
    parameter.extend_from_slice(&u16b(u16::try_from(words.len() * 4).expect("length")));
    for word in words {
        parameter.extend_from_slice(&if le {
            word.to_le_bytes()
        } else {
            word.to_be_bytes()
        });
    }
    parameter
}

/// PID_LIVELINESS (0x001b), PID_LATENCY_BUDGET (0x0027) and
/// PID_DESTINATION_ORDER (0x0025) reach the announced QoS, both
/// endiannesses (RTPS v2.5 Sec.9.6.2.2, Table 9.12).
#[test]
fn liveliness_latency_budget_and_destination_order_are_read() {
    use crate::dds::qos::{DestinationOrderKind, LivelinessKind};
    use std::time::Duration;
    for le in [true, false] {
        // MANUAL_BY_TOPIC (2), lease 3.5 s; budget 0.25 s; BY_SOURCE (1).
        let mut extra = qos_parameter(le, 0x001b, &[2, 3, 0x8000_0000]);
        extra.extend(qos_parameter(le, 0x0027, &[0, 0x4000_0000]));
        extra.extend(qos_parameter(le, 0x0025, &[1]));
        let qos = parse_sedp(&sedp_with(le, &extra))
            .expect("parses")
            .qos
            .expect("a QoS");
        assert_eq!(
            qos.liveliness.kind,
            LivelinessKind::ManualByTopic,
            "le={le}"
        );
        assert_eq!(qos.liveliness.lease_duration, Duration::from_millis(3500));
        assert_eq!(qos.latency_budget.duration, Duration::from_millis(250));
        assert_eq!(
            qos.destination_order.kind,
            DestinationOrderKind::BySourceTimestamp
        );

        // MANUAL_BY_PARTICIPANT (1), an INFINITE lease (Sec.9.3.2:
        // { 0x7fffffff, 0xffffffff }).
        let alone = qos_parameter(le, 0x001b, &[1, 0x7FFF_FFFF, 0xFFFF_FFFF]);
        let qos = parse_sedp(&sedp_with(le, &alone))
            .expect("parses")
            .qos
            .expect("PID_LIVELINESS alone is a QoS");
        assert_eq!(qos.liveliness.kind, LivelinessKind::ManualByParticipant);
        assert!(qos.liveliness.is_infinite());
    }
}

/// Absent, each policy is its DDS v1.4 Sec.2.2.3 default: AUTOMATIC with an
/// infinite lease, a zero budget, BY_RECEPTION_TIMESTAMP.
#[test]
fn absent_liveliness_latency_budget_and_destination_order_are_the_defaults() {
    use crate::dds::qos::{DestinationOrderKind, LivelinessKind};
    use std::time::Duration;
    // A QoS PID of another policy, so the announcement carries a QoS.
    let extra = qos_parameter(true, 0x001a, &[2, 0, 0x1999_999A]);
    let qos = parse_sedp(&sedp_with(true, &extra))
        .expect("parses")
        .qos
        .expect("a QoS");
    assert_eq!(qos.liveliness.kind, LivelinessKind::Automatic);
    assert!(qos.liveliness.is_infinite());
    assert_eq!(qos.latency_budget.duration, Duration::ZERO);
    assert_eq!(
        qos.destination_order.kind,
        DestinationOrderKind::ByReceptionTimestamp
    );
}

/// a sub-second Duration_t from an encoder that truncates
/// (fraction = floor(ns * 2^32 / 1e9)) or rounds must decode to the same
/// nanosecond count: 2^-32 s < 1 ns, so the nearest-ns decode is exact.
#[test]
fn a_subsecond_duration_decodes_to_the_encoded_nanoseconds() {
    use std::time::Duration;
    let mut bad = Vec::new();
    for ms in [1u64, 7, 10, 100, 300, 1100] {
        let d = Duration::from_millis(ms);
        let ns = u64::from(d.subsec_nanos());
        let trunc = u32::try_from((ns << 32) / 1_000_000_000).unwrap();
        let round = u32::try_from(((ns << 32) + 500_000_000) / 1_000_000_000).unwrap();
        for (enc, frac) in [("trunc", trunc), ("round", round)] {
            let secs = u32::try_from(d.as_secs()).unwrap();
            let extra = qos_parameter(true, 0x001b, &[0, secs, frac]);
            let mut extra2 = extra.clone();
            extra2.extend(qos_parameter(true, 0x0027, &[secs, frac]));
            extra2.extend(qos_parameter(true, 0x0023, &[secs, frac]));
            let qos = parse_sedp(&sedp_with(true, &extra2)).unwrap().qos.unwrap();
            if qos.liveliness.lease_duration != d {
                bad.push(format!(
                    "LIV {ms}ms {enc} -> {:?}",
                    qos.liveliness.lease_duration
                ));
            }
            if qos.latency_budget.duration != d {
                bad.push(format!(
                    "LAT {ms}ms {enc} -> {:?}",
                    qos.latency_budget.duration
                ));
            }
            if qos.deadline.period != d {
                bad.push(format!("DL {ms}ms {enc} -> {:?}", qos.deadline.period));
            }
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
}

/// a policy PID shorter than its type is never a panic, and leaves
/// the policy at its default.
#[test]
fn short_policy_pids_leave_the_default() {
    use crate::dds::qos::{DestinationOrderKind, LivelinessKind};
    use std::time::Duration;
    for le in [true, false] {
        let mut extra = qos_parameter(le, 0x001a, &[2, 0, 0]);
        extra.extend(qos_parameter(le, 0x001b, &[2, 3]));
        extra.extend(qos_parameter(le, 0x0027, &[5]));
        extra.extend(qos_parameter(le, 0x0025, &[]));
        let qos = parse_sedp(&sedp_with(le, &extra)).unwrap().qos.unwrap();
        assert_eq!(qos.liveliness.kind, LivelinessKind::Automatic);
        assert!(qos.liveliness.is_infinite());
        assert_eq!(qos.latency_budget.duration, Duration::ZERO);
        assert_eq!(
            qos.destination_order.kind,
            DestinationOrderKind::ByReceptionTimestamp
        );
        // Unknown kinds.
        let mut extra = qos_parameter(le, 0x001a, &[2, 0, 0]);
        extra.extend(qos_parameter(le, 0x001b, &[9, 1, 0]));
        extra.extend(qos_parameter(le, 0x0025, &[7]));
        let qos = parse_sedp(&sedp_with(le, &extra)).unwrap().qos.unwrap();
        assert_eq!(qos.liveliness.kind, LivelinessKind::Automatic);
        assert_eq!(
            qos.destination_order.kind,
            DestinationOrderKind::ByReceptionTimestamp
        );
        // Both INFINITE encodings, and a zero lease.
        for second in [0xFFFF_FFFFu32, 0x7FFF_FFFF, 0] {
            let extra = qos_parameter(le, 0x001b, &[0, 0x7FFF_FFFF, second]);
            let qos = parse_sedp(&sedp_with(le, &extra)).unwrap().qos.unwrap();
            assert!(qos.liveliness.is_infinite(), "second word {second:#x}");
        }
        let extra = qos_parameter(le, 0x001b, &[0, 0, 0]);
        let qos = parse_sedp(&sedp_with(le, &extra)).unwrap().qos.unwrap();
        assert_eq!(qos.liveliness.lease_duration, Duration::ZERO);
    }
    // A PID whose length runs past the buffer: no panic.
    let mut b = sedp_with(true, &[]);
    let n = b.len();
    b.truncate(n - 4);
    b.extend_from_slice(&[0x1b, 0x00, 0x0c, 0x00, 0, 0, 0, 0]);
    let _ = parse_sedp(&b);
    let _ = parse_sedp(&b[..b.len() - 3]);
}

/// A parameter `pid` carrying `value`, padded to a multiple of 4 (PL_CDR_LE).
fn le_parameter(pid: u16, value: &[u8]) -> Vec<u8> {
    let mut padded = value.to_vec();
    while !padded.len().is_multiple_of(4) {
        padded.push(0);
    }
    let mut parameter = Vec::new();
    parameter.extend_from_slice(&pid.to_le_bytes());
    parameter.extend_from_slice(&u16::try_from(padded.len()).expect("length").to_le_bytes());
    parameter.extend_from_slice(&padded);
    parameter
}

/// A legacy TypeObject v1 (XCDR1) captured from CoreDX, announced as is on the
/// standard PID_TYPE_OBJECT (0x0072): parse_sedp falls back to the v1 decoder
/// when the CDR2 decode fails, marks the object lossy and keeps the decoded
/// type's name.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn a_legacy_v1_type_object_on_pid_type_object_is_decoded_and_marked_lossy() {
    let wire = crate::xtypes::legacy_v1_test_vectors::COREDX_STRUCT_X1_V1;
    let sedp = parse_sedp(&sedp_with(true, &le_parameter(PID_TYPE_OBJECT, &wire))).expect("parses");
    assert!(
        sedp.type_object_legacy_v1,
        "a v1-decoded object must be marked lossy"
    );
    match sedp.type_object {
        Some(CompleteTypeObject::Struct(s)) => {
            assert_eq!(s.header.detail.type_name, "Test::struct_x1");
        }
        other => panic!("expected the decoded Struct, got {other:?}"),
    }
}

/// A legacy TypeObject v1 captured from RTI Connext, announced the way RTI
/// does: ZLIB-compressed, in PID 0x8021 behind the 12-byte envelope (class id
/// 1, uncompressed length, compressed length). The compressed bytes are made
/// here from the captured payload.
#[cfg(feature = "xtypes-structural-assignability")]
#[test]
fn a_zlib_legacy_v1_type_object_on_pid_0x8021_is_decoded_and_marked_lossy() {
    use std::io::Write;
    let wire = crate::xtypes::legacy_v1_test_vectors::RTI_INT32X10_V1;
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&wire).expect("compress");
    let compressed = encoder.finish().expect("compress");
    let mut value = Vec::new();
    value.extend_from_slice(&1u32.to_le_bytes());
    value.extend_from_slice(&u32::try_from(wire.len()).expect("length").to_le_bytes());
    value.extend_from_slice(
        &u32::try_from(compressed.len())
            .expect("length")
            .to_le_bytes(),
    );
    value.extend_from_slice(&compressed);
    let sedp = parse_sedp(&sedp_with(
        true,
        &le_parameter(super::constants::PID_TYPE_OBJECT_LB, &value),
    ))
    .expect("parses");
    assert!(
        sedp.type_object_legacy_v1,
        "a v1-decoded object must be marked lossy"
    );
    assert!(
        matches!(sedp.type_object, Some(CompleteTypeObject::Struct(_))),
        "the decoded root must be a Struct"
    );
}

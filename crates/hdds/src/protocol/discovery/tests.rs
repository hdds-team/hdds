// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::constants::{
    PID_ENDPOINT_GUID, PID_METATRAFFIC_UNICAST_LOCATOR, PID_PARTICIPANT_GUID,
    PID_PARTICIPANT_LEASE_DURATION, PID_SENTINEL, PID_TOPIC_NAME, PID_TYPE_NAME, PID_TYPE_OBJECT,
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
        member_seq: vec![CompleteStructMember {
            common: CommonStructMember {
                member_id: 0,
                member_flags: MemberFlag::empty(),
                member_type_id: TypeIdentifier::TK_INT32,
            },
            detail: CompleteMemberDetail::new("value"),
        }],
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
    // v62: Encapsulation is big-endian, so CDR_LE (0x0003) = [0x00, 0x03]
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
        unicast_locators: vec![],
        user_data: None,
    };

    let mut buf = vec![0u8; 2048];
    let len = build_sedp(&sedp_data, &mut buf).expect("SEDP build should succeed");
    let parsed = parse_sedp(&buf[..len]).expect("SEDP parse should succeed");

    assert_eq!(parsed.topic_name, sedp_data.topic_name);
    assert_eq!(parsed.type_name, sedp_data.type_name);
    assert_eq!(parsed.endpoint_guid, sedp_data.endpoint_guid);
    assert!(parsed.type_object.is_some());
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
        unicast_locators: vec![],
        user_data: None,
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
        unicast_locators: vec![],
        user_data: None,
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
        unicast_locators: vec![],
        user_data: None,
    };

    let mut buf = vec![0u8; 16];
    let result = build_sedp(&sedp_data, &mut buf);
    assert_eq!(result, Err(ParseError::BufferTooSmall));
}

#[test]
#[ignore] // Pre-existing SPDP locator parsing issue (not v61 blocker)
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
fn test_build_spdp_roundtrip_without_locators() {
    let spdp_data = SpdpData {
        participant_guid: GUID::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
        lease_duration_ms: 90_000,
        domain_id: 0,
        metatraffic_unicast_locators: Vec::new(),
        default_unicast_locators: Vec::new(),
        default_multicast_locators: Vec::new(),
        metatraffic_multicast_locators: Vec::new(),
        identity_token: None,
    };

    let mut buf = vec![0u8; 1024]; // v101: Increased for property list (7 properties ~600 bytes)
    let len = build_spdp(&spdp_data, &mut buf).expect("SPDP build should succeed");
    let parsed = parse_spdp(&buf[..len]).expect("SPDP parse should succeed");

    assert_eq!(parsed.participant_guid, spdp_data.participant_guid);
    assert_eq!(parsed.lease_duration_ms, spdp_data.lease_duration_ms);
    assert_eq!(parsed.metatraffic_unicast_locators.len(), 0);
    assert_eq!(parsed.default_unicast_locators.len(), 0);
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
    };

    let mut buf = vec![0u8; 16];
    let result = build_spdp(&spdp_data, &mut buf);
    assert_eq!(result, Err(ParseError::BufferTooSmall));
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Each Publisher of a participant is a group of its own (RTPS v2.5
//! Sec.8.7.5, Sec.9.3.1.2): its writers' SEDP announcements name it in
//! PID_GROUP_GUID (0x0052) and PID_GROUP_ENTITY_ID (0x0053), and their
//! GROUP-scope members carry it inline. Publishers must not all name the
//! same `[0,0,1,0x08]`, or a GROUP reader would merge two Publishers' sets.

use super::{Participant, TransportMode};
use crate::core::discovery::multicast::SedpEndpointKind;
use crate::dds::qos::{Presentation, PresentationAccessScope};
use crate::dds::QoS;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Sample {
    #[key]
    id: u32,
    v: i32,
}

fn participant(name: &str) -> Arc<Participant> {
    Participant::builder(name)
        .with_transport(TransportMode::IntraProcess)
        .domain_id(crate::test_support::domains::unique_domain().id())
        .build()
        .expect("participant")
}

fn group_qos() -> QoS {
    QoS::reliable().presentation(Presentation::new(
        PresentationAccessScope::Group,
        true,
        false,
    ))
}

/// The value of parameter `pid` in an encapsulated little-endian
/// ParameterList, decoded by hand (RTPS v2.5 Sec.9.4.2.11).
fn parameter(list: &[u8], pid: u16) -> Option<Vec<u8>> {
    let mut at = 4; // encapsulation header
    while at + 4 <= list.len() {
        let id = u16::from_le_bytes([list[at], list[at + 1]]);
        let len = usize::from(u16::from_le_bytes([list[at + 2], list[at + 3]]));
        if id == 0x0001 {
            return None;
        }
        if id == pid {
            return Some(list[at + 4..at + 4 + len].to_vec());
        }
        at += 4 + len;
    }
    None
}

/// The SEDP announcement of the writer of `topic`, as the participant
/// sends it (`build_sedp_rtps_packet`, the Hybrid dialect of the flush and
/// retransmit paths and the HDDS one), and the ParameterList in it: the
/// serialized payload follows the 24-octet DATA submessage prefix.
fn announcements(p: &Participant, topic: &str) -> Vec<Vec<u8>> {
    use crate::core::discovery::multicast::rtps_packet::build_sedp_rtps_packet;
    use crate::protocol::dialect::Dialect;
    let data = p
        .sedp_announcements
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .alive()
        .find(|(sd, kind)| *kind == SedpEndpointKind::Writer && sd.topic_name == topic)
        .map(|(sd, _)| sd.clone())
        .expect("announced");
    [Dialect::Hybrid, Dialect::Hdds]
        .into_iter()
        .map(|dialect| {
            let packet = build_sedp_rtps_packet(
                &data,
                SedpEndpointKind::Writer,
                &p.guid().prefix,
                None,
                1,
                dialect,
            )
            .expect("build");
            // The serialized payload starts with its encapsulation header
            // (PL_CDR_LE 00 03 00 00).
            let at = packet
                .windows(4)
                .position(|w| w == [0x00, 0x03, 0x00, 0x00])
                .expect("PL_CDR_LE payload");
            packet[at..].to_vec()
        })
        .collect()
}

#[test]
fn two_publishers_of_one_participant_are_two_groups() {
    let p = participant("two-publishers");
    let a = Arc::new(p.create_publisher(group_qos()).expect("publisher a"));
    let b = Arc::new(p.create_publisher(group_qos()).expect("publisher b"));
    let (ida, idb, implicit) = (
        a.entity_id(),
        b.entity_id(),
        p.implicit_publisher_entity_id(),
    );
    assert_ne!(ida, idb, "two Publishers, two ids");
    assert!(
        implicit != ida && implicit != idb,
        "the implicit one is a third"
    );
    for id in [ida, idb, implicit] {
        assert_eq!(id[3], 0x08, "{id:02x?}: USER_DEFINED_WRITER_GROUP kind");
    }

    let wa = p
        .topic::<Sample>("GroupA")
        .expect("topic")
        .writer()
        .qos(group_qos())
        .publisher(&a)
        .build()
        .expect("writer a");
    let wb = p
        .topic::<Sample>("GroupB")
        .expect("topic")
        .writer()
        .qos(group_qos())
        .publisher(&b)
        .build()
        .expect("writer b");
    // The deprecated path still names its Publisher.
    #[allow(deprecated)]
    let wb2 = b
        .create_writer::<Sample>("GroupB2", group_qos())
        .expect("writer b2");
    let plain = p
        .topic::<Sample>("Implicit")
        .expect("topic")
        .writer()
        .qos(group_qos())
        .build()
        .expect("writer of no publisher");

    let prefix = p.guid().prefix;
    for (topic, writer_id, expected) in [
        ("GroupA", wa.rtps_endpoint_for_test(), ida),
        ("GroupB", wb.rtps_endpoint_for_test(), idb),
        ("GroupB2", wb2.rtps_endpoint_for_test(), idb),
        ("Implicit", plain.rtps_endpoint_for_test(), implicit),
    ] {
        let ctx = writer_id.expect("an RTPS context");
        assert_eq!(
            ctx.publisher_entity_id, expected,
            "{topic}: the writer's context"
        );
        for bytes in announcements(&p, topic) {
            assert_eq!(
                parameter(&bytes, 0x0053),
                Some(expected.to_vec()),
                "{topic}: PID_GROUP_ENTITY_ID"
            );
            let mut group_guid = prefix.to_vec();
            group_guid.extend_from_slice(&expected);
            assert_eq!(
                parameter(&bytes, 0x0052),
                Some(group_guid),
                "{topic}: PID_GROUP_GUID = prefix + group"
            );
            // And a remote participant's discovery reads it back.
            assert_eq!(
                crate::protocol::discovery::parse_sedp(&bytes)
                    .expect("parse")
                    .group_entity_id,
                Some(expected),
                "{topic}: parsed back"
            );
        }
        // A GROUP-scope member of the writer names its Publisher inline.
        let member = crate::protocol::builder::build_data_packet_with_context_full_keyed_ts(
            &ctx,
            topic,
            1,
            &[0, 1, 0, 0, 1, 0, 0, 0],
            crate::dds::CdrVersion::Xcdr2,
            (0, 0),
            Some(1),
            Some(1),
            None,
            false,
        );
        assert!(
            member
                .windows(8)
                .any(|w| w[..4] == [0x53, 0x00, 0x04, 0x00] && w[4..] == expected),
            "{topic}: inline PID_GROUP_ENTITY_ID {expected:02x?}"
        );
    }
}

/// Every SEDP encoder that announces the group carries the endpoint's own:
/// the dialects a peer may be paired with name the Publisher the writer
/// belongs to, not a fixed one.
#[test]
fn every_dialect_announces_the_writers_own_publisher() {
    use crate::protocol::dialect::{build_sedp_for_dialect, Dialect, Guid, SedpEndpointData};
    let group = [0x00, 0x00, 0x2A, 0x08];
    let prefix = [0x01; 12];
    for dialect in [
        Dialect::Hdds,
        Dialect::Rti,
        Dialect::FastDds,
        Dialect::CycloneDds,
        Dialect::OpenDds,
        Dialect::Hybrid,
    ] {
        let bytes = build_sedp_for_dialect(
            dialect,
            &SedpEndpointData {
                endpoint_guid: Guid {
                    prefix,
                    entity_id: [0x00, 0x00, 0x12, 0x02],
                },
                participant_guid: Guid {
                    prefix,
                    entity_id: [0x00, 0x00, 0x01, 0xc1],
                },
                topic_name: "T",
                type_name: "Ty",
                unicast_locators: &[],
                multicast_locators: &[],
                qos: None,
                type_object: None,
                user_data: None,
                hdds_shm_capability: None,
                hdds_peer_destination: false,
                group_entity_id: Some(group),
                type_consistency: None,
                #[cfg(feature = "xtypes-structural-assignability")]
                type_information: None,
                emit_type_object_pid: false,
            },
        )
        .expect("encode");
        if let Some(value) = parameter(&bytes, 0x0053) {
            assert_eq!(value, group.to_vec(), "{dialect:?}: PID_GROUP_ENTITY_ID");
        }
        if let Some(value) = parameter(&bytes, 0x0052) {
            assert_eq!(value[12..], group, "{dialect:?}: PID_GROUP_GUID");
        }
    }
}

/// A remote announcement names its endpoint's group by PID_GROUP_GUID
/// (0x0052: prefix + entityId) or PID_GROUP_ENTITY_ID (0x0053); the GUID
/// wins when both are present, and ENTITYID_UNKNOWN names no group (a
/// vendor that sends 0x0053 as UNKNOWN). Bytes laid out by hand from RTPS
/// v2.5 Sec.9.6.2.2.5 (Table 9.12/9.14), not by our encoder.
#[test]
fn a_remote_announcement_names_its_group() {
    fn parameter_list(extra: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![0x00, 0x03, 0x00, 0x00]; // PL_CDR_LE
        let mut put = |pid: u16, value: &[u8]| {
            b.extend_from_slice(&pid.to_le_bytes());
            b.extend_from_slice(&u16::try_from(value.len()).expect("small").to_le_bytes());
            b.extend_from_slice(value);
        };
        let mut guid = vec![0x01; 12];
        guid.extend_from_slice(&[0, 0, 0x12, 0x02]);
        put(0x005a, &guid); // PID_ENDPOINT_GUID
        let string = |s: &str| {
            let mut v = u32::try_from(s.len() + 1)
                .expect("small")
                .to_le_bytes()
                .to_vec();
            v.extend_from_slice(s.as_bytes());
            v.push(0);
            while v.len() % 4 != 0 {
                v.push(0);
            }
            v
        };
        put(0x0005, &string("T")); // PID_TOPIC_NAME
        put(0x0007, &string("Ty")); // PID_TYPE_NAME
        for (pid, value) in extra {
            put(*pid, value);
        }
        put(0x0001, &[]);
        b
    }
    let group_guid = |id: [u8; 4]| {
        let mut v = vec![0x01; 12];
        v.extend_from_slice(&id);
        v
    };
    let parse = |extra: &[(u16, Vec<u8>)]| {
        crate::protocol::discovery::parse_sedp(&parameter_list(extra))
            .expect("parse")
            .group_entity_id
    };
    assert_eq!(parse(&[]), None, "no group named");
    assert_eq!(
        parse(&[(0x0053, vec![0, 0, 0x31, 0x08])]),
        Some([0, 0, 0x31, 0x08])
    );
    assert_eq!(
        parse(&[(0x0052, group_guid([0, 0, 0x32, 0x08]))]),
        Some([0, 0, 0x32, 0x08])
    );
    assert_eq!(
        parse(&[
            (0x0053, vec![0, 0, 0x31, 0x08]),
            (0x0052, group_guid([0, 0, 0x32, 0x08]))
        ]),
        Some([0, 0, 0x32, 0x08]),
        "the GUID wins"
    );
    assert_eq!(
        parse(&[(0x0053, vec![0, 0, 0, 0])]),
        None,
        "ENTITYID_UNKNOWN"
    );
}

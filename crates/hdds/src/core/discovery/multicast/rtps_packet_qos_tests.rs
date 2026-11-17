// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The QoS an SEDP announcement carries, decoded from the bytes each
//! dialect encoder puts on the wire (RTPS v2.5 Sec.9.6.2.2, Table 9.12),
//! never with our own decoder.

use super::*;
use crate::core::discovery::GUID;
use crate::dds::qos::QoS;

fn writer_data(qos: QoS) -> SedpData {
    let guid = GUID::from_bytes([0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 1, 0x02]);
    SedpData {
        topic_name: "qos_topic".to_string(),
        type_name: "QosT".to_string(),
        participant_guid: guid,
        endpoint_guid: guid,
        qos_hash: 0,
        qos: Some(qos),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        type_information: None,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: true,
        has_ownership_strength: false,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    }
}

/// The parameters of the PL_CDR_LE ParameterList in `packet`, as
/// `(pid, value)`, in wire order: the list found where a walk from an
/// encapsulation header reaches PID_SENTINEL and holds PID_TOPIC_NAME.
fn parameters(packet: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let encap = [0x00u8, 0x03, 0x00, 0x00];
    'start: for start in 0..packet.len().saturating_sub(4) {
        if packet[start..start + 4] != encap {
            continue;
        }
        let mut at = start + 4;
        let mut list = Vec::new();
        while at + 4 <= packet.len() {
            let pid = u16::from_le_bytes([packet[at], packet[at + 1]]);
            let len = usize::from(u16::from_le_bytes([packet[at + 2], packet[at + 3]]));
            if pid == 0x0001 {
                if list.iter().any(|(p, _)| *p == 0x0005) {
                    return list;
                }
                continue 'start;
            }
            let Some(value) = packet.get(at + 4..at + 4 + len) else {
                continue 'start;
            };
            list.push((pid, value.to_vec()));
            at += 4 + len;
        }
    }
    panic!("no ParameterList in the packet")
}

fn announced(qos: &QoS, dialect: Dialect) -> Vec<(u16, Vec<u8>)> {
    let packet = build_sedp_rtps_packet(
        &writer_data(qos.clone()),
        SedpEndpointKind::Writer,
        &[0x01, 0x1A, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        None,
        1,
        dialect,
    )
    .unwrap_or_else(|e| panic!("{dialect:?}: {e:?}"));
    parameters(&packet)
}

fn value_of(list: &[(u16, Vec<u8>)], pid: u16) -> Option<&[u8]> {
    list.iter()
        .find(|(p, _)| *p == pid)
        .map(|(_, v)| v.as_slice())
}

fn words(value: &[u8]) -> Vec<u32> {
    value
        .chunks_exact(4)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
        .collect()
}

/// PID_PRESENTATION (0x0021), PID_LIFESPAN (0x002b),
/// PID_OWNERSHIP_STRENGTH (0x0006) and PID_TIME_BASED_FILTER (0x0004)
/// carry the endpoint's policies in every dialect built with the generic
/// SEDP builder. They must all read the announced profile through one shared
/// conversion: a per-dialect copy can drop a policy (PRESENTATION, LIFESPAN,
/// TIME_BASED_FILTER in the CycloneDDS dialect, PRESENTATION and LIFESPAN in
/// FastDDS's, the OWNERSHIP strength and TIME_BASED_FILTER in Hybrid's, the
/// flush and retransmit dialect).
#[test]
fn generic_builder_dialects_announce_the_endpoints_policies() {
    let qos = QoS::reliable()
        .presentation_topic_coherent()
        .lifespan_millis(1500)
        .ownership_exclusive()
        .ownership_strength(7)
        .time_based_filter_millis(250);
    for dialect in [
        Dialect::Hdds,
        Dialect::CycloneDds,
        Dialect::FastDds,
        Dialect::Hybrid,
    ] {
        let list = announced(&qos, dialect);
        let presentation = value_of(&list, 0x0021).expect("PID_PRESENTATION");
        assert_eq!(
            presentation[..6],
            [1, 0, 0, 0, 1, 0],
            "{dialect:?}: TOPIC, coherent"
        );
        let lifespan = words(value_of(&list, 0x002b).expect("PID_LIFESPAN"));
        assert_eq!(lifespan, [1, 0x8000_0000], "{dialect:?}: 1.5 s");
        let strength = words(value_of(&list, 0x0006).expect("PID_OWNERSHIP_STRENGTH"));
        assert_eq!(strength, [7], "{dialect:?}");
        let filter = words(value_of(&list, 0x0004).expect("PID_TIME_BASED_FILTER"));
        assert_eq!(filter, [0, 0x4000_0000], "{dialect:?}: 0.25 s");
    }
}

/// Every dialect whose encoder builds an SEDP announcement
/// (`dialect::is_dialect_implemented`).
const DIALECTS: [Dialect; 6] = [
    Dialect::Hdds,
    Dialect::Hybrid,
    Dialect::Rti,
    Dialect::FastDds,
    Dialect::CycloneDds,
    Dialect::OpenDds,
];

/// PID_LIVELINESS (0x001b: kind, Duration_t lease_duration),
/// PID_LATENCY_BUDGET (0x0027: Duration_t duration) and
/// PID_DESTINATION_ORDER (0x0025: kind) carry the endpoint's policies in
/// every dialect: a remote reader judges our writer on them (DDS v1.4
/// Sec.2.2.3.11, 2.2.3.8, 2.2.3.17).
#[test]
fn every_dialect_announces_liveliness_latency_budget_and_destination_order() {
    use crate::dds::qos::{DestinationOrder, LatencyBudget, Liveliness};
    use std::time::Duration;
    let mut qos = QoS::reliable();
    qos.liveliness = Liveliness::manual_by_topic(Duration::from_millis(2500));
    qos.latency_budget = LatencyBudget::new(Duration::from_millis(250));
    qos.destination_order = DestinationOrder::by_source_timestamp();
    for dialect in DIALECTS {
        let list = announced(&qos, dialect);
        let liveliness =
            value_of(&list, 0x001b).unwrap_or_else(|| panic!("{dialect:?}: PID_LIVELINESS"));
        // MANUAL_BY_TOPIC 2; 2 s + 2^31 * 2^-32 s.
        assert_eq!(words(liveliness), [2, 2, 0x8000_0000], "{dialect:?}");
        let budget =
            value_of(&list, 0x0027).unwrap_or_else(|| panic!("{dialect:?}: PID_LATENCY_BUDGET"));
        assert_eq!(words(budget), [0, 0x4000_0000], "{dialect:?}");
        let order =
            value_of(&list, 0x0025).unwrap_or_else(|| panic!("{dialect:?}: PID_DESTINATION_ORDER"));
        assert_eq!(words(order), [1], "{dialect:?}: BY_SOURCE_TIMESTAMP");
    }
}

/// An endpoint on the defaults announces them, or nothing (a receiver takes
/// an absent PID as its default, RTPS v2.5 Sec.9.6.2.2): AUTOMATIC with an
/// INFINITE lease ({0x7fffffff, 0xffffffff}, Sec.9.3.2), a zero budget,
/// BY_RECEPTION_TIMESTAMP.
#[test]
fn default_liveliness_latency_budget_and_destination_order_are_announced_as_defaults() {
    for dialect in DIALECTS {
        let list = announced(&QoS::reliable(), dialect);
        for (pid, default) in [
            (0x001b, vec![0, 0x7FFF_FFFF, 0xFFFF_FFFF]),
            (0x0027, vec![0, 0]),
            (0x0025, vec![0]),
        ] {
            if let Some(value) = value_of(&list, pid) {
                assert_eq!(words(value), default, "{dialect:?} PID 0x{pid:04x}");
            }
        }
    }
}

/// PID_PRESENTATION (0x0021: access_scope, coherent_access, ordered_access)
/// carries the endpoint's policy in every dialect (DDS v1.4 Sec.2.2.3.6,
/// an RxO policy); an endpoint on the default, INSTANCE without coherent nor
/// ordered access, announces it or nothing.
#[test]
fn every_dialect_announces_presentation() {
    let group = QoS::reliable().presentation_group_coherent_ordered();
    for dialect in DIALECTS {
        let list = announced(&group, dialect);
        let value =
            value_of(&list, 0x0021).unwrap_or_else(|| panic!("{dialect:?}: PID_PRESENTATION"));
        assert_eq!(value[..6], [2, 0, 0, 0, 1, 1], "{dialect:?}: GROUP");
        let list = announced(&QoS::reliable(), dialect);
        if let Some(value) = value_of(&list, 0x0021) {
            assert_eq!(value[..6], [0; 6], "{dialect:?}: default");
        }
    }
}

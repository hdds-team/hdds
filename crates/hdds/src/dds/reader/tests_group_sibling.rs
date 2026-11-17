// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A GROUP-scope reader's sets are the sets of the writers it is matched
//! with (DDS v1.4 Sec.2.2.3.6, PRESENTATION GROUP): a writer of the same
//! Publisher that this reader refuses (its QoS, its partition) or that the
//! security plugins do not admit (DDS Security v1.1 Sec.8.8.7.1) moves
//! nothing of them. Its changes, its HEARTBEATs' GroupInfo and its GSNs are
//! ignored, it is not waited for, and the admitted sibling's sets are
//! delivered whole.
//!
//! Each test has its control: the admitted writer's set is delivered, and
//! what the other writer sent leaves no trace.

use super::subscriber::DiscoveryRoster;
use super::tests_history_limits::{encoded, Keyed, NetworkReader};
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::dds::match_notification::MatchNotificationRegistry;
use crate::dds::QoS;
use crate::engine::Subscriber as _;
use crate::protocol::discovery::{SedpData, SpdpData};
use std::sync::Arc;

const PUBLISHER: [u8; 4] = [0, 0, 0x31, 0x08];
/// The writer the reader is matched with.
const A: [u8; 4] = [0, 0, 0x01, 0x02];
/// Its sibling in the same Publisher, refused or not admitted.
const B: [u8; 4] = [0, 0, 0x02, 0x02];

fn guid(prefix: [u8; 12], id: [u8; 4]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&prefix);
    g[12..].copy_from_slice(&id);
    g
}

/// The announcement of the Publisher's writer `id` of `topic`.
fn announcement(prefix: [u8; 12], id: [u8; 4], topic: &str, qos: QoS) -> SedpData {
    SedpData {
        topic_name: topic.to_string(),
        type_name: "Keyed".to_string(),
        participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
        endpoint_guid: GUID::new(prefix, id),
        qos_hash: 0,
        qos: Some(qos),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: Some(PUBLISHER),
        endpoint_security_info: None,
    }
}

fn spdp(prefix: [u8; 12], identity_token: Option<Vec<u8>>) -> SpdpData {
    SpdpData {
        participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
        hdds_capabilities: Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
        builtin_endpoint_set: None,
    }
}

/// The GROUP reader of `topic` (reliable, KEEP_ALL, in `partition`), judged
/// by `fsm`'s match registry and deciding its sets against `fsm`'s writers
/// of the Publisher, as a participant wires it; registered, then told the
/// first HEARTBEAT of `A` and `B` of `prefix`.
fn reader(
    fsm: Arc<DiscoveryFsm>,
    local: [u8; 12],
    prefix: [u8; 12],
    topic: &str,
    partition: &[&str],
) -> NetworkReader<Keyed> {
    let registry = Arc::new(MatchNotificationRegistry::new(&fsm, local));
    fsm.set_match_registry(Arc::clone(&registry));
    fsm.register_listener(registry.clone());
    let partition = crate::qos::partition::Partition::new(
        partition.iter().map(|name| (*name).to_string()).collect(),
    );
    let qos = QoS::reliable().keep_all().partition(partition.clone());
    let net = NetworkReader::<Keyed>::with_parts_judged(
        topic,
        qos.clone(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
        Some(Arc::clone(&registry)),
        partition,
    );
    net.subscriber.register_match_entry_for_test(qos);
    let roster = DiscoveryRoster {
        fsm,
        registry,
        entry: Arc::clone(&net.subscriber.match_entry),
    };
    let _ = net.subscriber.group_roster.set(Arc::new(roster));
    for id in [A, B] {
        net.credit.match_writer(guid(prefix, id));
        net.subscriber.on_writer_heartbeat(guid(prefix, id), 1);
    }
    net
}

/// The Publisher's writer set, as discovery knows it: both writers.
fn writer_set() -> [u8; 4] {
    crate::protocol::group::group_digest([A, B])
}

fn group_change(
    net: &NetworkReader<Keyed>,
    writer: [u8; 16],
    seq: u64,
    set: u64,
    named: [u8; 4],
    gsn: Option<u64>,
    part_first_sn: Option<u64>,
) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_group_change(
        writer,
        crate::engine::GroupChange {
            seq,
            group_sn: set,
            publisher_entity_id: PUBLISHER,
            writer_set: named,
            gsn,
            part_first_sn,
        },
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

/// Change `seq` of `writer`, a member of the set whose first GSN is `set`,
/// its part starting at `start`.
fn member(net: &NetworkReader<Keyed>, writer: [u8; 16], seq: u64, start: u64, set: u64, v: i32) {
    group_change(net, writer, seq, set, writer_set(), None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        writer,
        seq,
        &encoded(&Keyed { id: v, value: v }),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        Some(set),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

/// `writer`'s end `seq` of the set `set`, its part from `part_first`.
fn end(net: &NetworkReader<Keyed>, writer: [u8; 16], seq: u64, part_first: u64, set: u64) {
    group_change(net, writer, seq, set, writer_set(), None, Some(part_first));
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber
        .on_ecs(&net.topic, writer, seq, seq - 1, Some(set), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

fn values(net: &NetworkReader<Keyed>) -> Vec<i32> {
    net.take_all().iter().map(|s| s.value).collect()
}

/// What the other writer `other` sends to break the sets of its Publisher,
/// before and around the matched writer's set 1: a change of set 1 naming
/// another writer set (two writer sets: never whole), a change whose GSN is
/// below the set's first (GSNs that contradict the spec), an end of a set
/// 50 the Publisher never writes (a phantom set, waiting for `A`'s end for
/// good and holding `A`'s later changes behind it), a HEARTBEAT whose
/// GroupInfo announces every GSN of the sets absent, an end of a set 60
/// with no change naming it, and a standalone end marker of a set 70.
fn sibling_attacks(net: &NetworkReader<Keyed>, other: [u8; 16]) {
    group_change(net, other, 1, 1, [0xEE; 4], None, None);
    group_change(net, other, 2, 1, writer_set(), Some(0), None);
    group_change(net, other, 3, 50, writer_set(), Some(51), Some(3));
    net.subscriber
        .on_writer_group_heartbeat(other, 1_000, 900, 950);
    // An end of a set 60 the Publisher never writes, without its change.
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber
        .on_ecs(&net.topic, other, 4, 3, Some(60), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    // A standalone end marker of a set 70, as a vendor-0x0101 writer ends
    // a GROUP set.
    crate::engine::router::set_route_writer_is_connext_for_test(true);
    net.subscriber
        .on_coherent_end_marker(&net.topic, other, Some(70), Some(PUBLISHER), 5, None, 6);
    crate::engine::router::set_route_writer_is_connext_for_test(false);
}

/// The matched writer's set 1 ({1, 2}, its end 3), then its change 4 of no
/// set, are delivered, in that order, nothing lost.
fn the_matched_writers_set_is_delivered(net: &NetworkReader<Keyed>, prefix: [u8; 12]) {
    let a = guid(prefix, A);
    member(net, a, 1, 1, 1, 11);
    member(net, a, 2, 1, 1, 12);
    end(net, a, 3, 1, 1);
    assert_eq!(values(net), vec![11, 12], "the matched writer's set");
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_with_writer(
        &net.topic,
        a,
        4,
        &encoded(&Keyed { id: 4, value: 4 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(values(net), vec![4], "its next change is held by nothing");
    assert_eq!(net.lost(), 0);
}

/// Nothing of `other` is recorded: no GSN, no GroupInfo, no set of its own.
/// Called once the matched writer's set is delivered: what is left staged
/// is the other writer's.
fn leaves_no_trace(net: &NetworkReader<Keyed>, other: [u8; 16]) {
    assert!(
        !net.subscriber
            .writer_gsns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&other),
        "its GSNs or its GroupInfo were recorded"
    );
    let buf = net
        .subscriber
        .group_coherent_buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert!(
        buf.keys().all(|key| ![50, 60, 70].contains(&key.2)),
        "a phantom set of it was opened: {:?}",
        buf.keys().map(|key| key.2).collect::<Vec<_>>()
    );
}

/// Discovery of the peer `PREFIX`, its writers `A` (RELIABLE) and `B`
/// (`b_qos`), of `topic`.
mod qos {
    use super::*;

    const LOCAL: [u8; 12] = [0x01; 12];
    const PREFIX: [u8; 12] = [0x5C; 12];

    fn discovery(topic: &str, a_qos: QoS, b_qos: QoS) -> Arc<DiscoveryFsm> {
        let fsm = Arc::new(DiscoveryFsm::new(
            GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT),
            100_000,
        ));
        fsm.handle_spdp(spdp(PREFIX, None));
        fsm.handle_sedp(announcement(PREFIX, A, topic, a_qos));
        fsm.handle_sedp(announcement(PREFIX, B, topic, b_qos));
        fsm
    }

    /// DDS v1.4 Sec.2.2.3: B, BEST_EFFORT, is refused by the RELIABLE reader
    /// (`writer_refused`); A is matched. B's changes, GSNs and GroupInfo
    /// break nothing of A's set and open nothing.
    #[test]
    fn a_refused_sibling_cannot_break_the_matched_writers_group_set() {
        let topic = "group-sibling-qos";
        let fsm = discovery(topic, QoS::reliable(), QoS::best_effort());
        let net = reader(fsm, LOCAL, PREFIX, topic, &[]);
        let b = guid(PREFIX, B);
        assert!(
            net.subscriber.writer_refused_for_test(&b),
            "fixture: B refused"
        );
        assert!(
            !net.subscriber.writer_refused_for_test(&guid(PREFIX, A)),
            "fixture: A matched"
        );
        sibling_attacks(&net, b);
        the_matched_writers_set_is_delivered(&net, PREFIX);
        leaves_no_trace(&net, b);
    }

    /// A set NOT decided yet when B's verdict flips: A's member staged and
    /// the set's writers decided ([A], B refused), then B re-announces
    /// RELIABLE and is matched before A ends the set. B is one of the set's
    /// writer set from the start (the Publisher's digest), so the set now
    /// waits for B's end too, and is delivered whole with B's part (RTPS
    /// v2.5 Sec.8.7.6: every writer of the Publisher matched here ends the
    /// set). Decided without B, A's end flushed it alone, and B's part,
    /// coming next, was lost.
    #[test]
    fn a_sibling_matched_before_the_set_is_decided_is_waited_for() {
        let topic = "group-sibling-flip-open";
        let fsm = discovery(topic, QoS::reliable(), QoS::best_effort());
        let net = reader(Arc::clone(&fsm), LOCAL, PREFIX, topic, &[]);
        let (a, b) = (guid(PREFIX, A), guid(PREFIX, B));
        member(&net, a, 1, 1, 1, 11);
        let required = || {
            net.subscriber
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .next()
                .and_then(|set| set.required_for_test())
        };
        assert_eq!(required(), Some(vec![a]), "fixture: decided without B");
        fsm.handle_sedp(announcement(PREFIX, B, topic, QoS::reliable()));
        assert!(!net.subscriber.writer_refused_for_test(&b), "fixture");
        net.subscriber.on_writer_heartbeat_range(b, 1, 2);
        end(&net, a, 2, 1, 1);
        assert_eq!(values(&net), Vec::<i32>::new(), "B's end is owed now");
        member(&net, b, 1, 1, 1, 21);
        end(&net, b, 2, 1, 1);
        let mut got = values(&net);
        got.sort_unstable();
        assert_eq!(got, vec![11, 21], "whole, with B's part");
        assert_eq!(net.lost(), 0);
    }

    /// The control of the one above: a writer added to the Publisher after
    /// the set's writer set was named is no writer of that set, matched or
    /// not (`a_decided_set_survives_a_writer_added_to_the_publisher`): the
    /// roster grows back only with the set's own writers.
    #[test]
    fn a_writer_new_to_the_publisher_is_not_waited_for() {
        const C: [u8; 4] = [0, 0, 0x03, 0x02];
        let topic = "group-sibling-new-writer";
        let fsm = discovery(topic, QoS::reliable(), QoS::best_effort());
        let net = reader(Arc::clone(&fsm), LOCAL, PREFIX, topic, &[]);
        let a = guid(PREFIX, A);
        member(&net, a, 1, 1, 1, 11);
        fsm.handle_sedp(announcement(PREFIX, C, topic, QoS::reliable()));
        net.credit.match_writer(guid(PREFIX, C));
        net.subscriber
            .on_writer_heartbeat_range(guid(PREFIX, C), 1, 1);
        end(&net, a, 2, 1, 1);
        assert_eq!(values(&net), vec![11]);
    }

    /// DDS v1.4 Sec.2.2.3.13: B announces partition X, the reader reads P,
    /// as A does. B is no writer of this reader (its pair verdict refuses
    /// it, PARTITION being a policy of the verdict), and breaks nothing.
    #[test]
    fn a_sibling_of_another_partition_cannot_break_the_matched_writers_group_set() {
        let topic = "group-sibling-partition";
        let in_partition = |name: &str| {
            QoS::reliable().partition(crate::qos::partition::Partition::new(
                vec![name.to_string()],
            ))
        };
        let fsm = discovery(topic, in_partition("P"), in_partition("X"));
        let net = reader(fsm, LOCAL, PREFIX, topic, &["P"]);
        let b = guid(PREFIX, B);
        sibling_attacks(&net, b);
        the_matched_writers_set_is_delivered(&net, PREFIX);
        leaves_no_trace(&net, b);
    }

    /// The control: B matched too, its change naming another writer set
    /// breaks set 1 (it is one of the set's writers), and the set waits for
    /// B's end.
    #[test]
    fn a_matched_siblings_contradiction_breaks_the_set() {
        let topic = "group-sibling-control";
        let fsm = discovery(topic, QoS::reliable(), QoS::reliable());
        let net = reader(fsm, LOCAL, PREFIX, topic, &[]);
        let (a, b) = (guid(PREFIX, A), guid(PREFIX, B));
        member(&net, a, 1, 1, 1, 11);
        end(&net, a, 2, 1, 1);
        assert_eq!(values(&net), Vec::<i32>::new(), "B's end is owed");
        group_change(&net, b, 1, 1, [0xEE; 4], None, Some(1));
        net.subscriber
            .on_ecs(&net.topic, b, 1, 0, Some(1), Some(PUBLISHER));
        assert_eq!(values(&net), Vec::<i32>::new(), "never whole");
        assert_eq!(net.lost(), 1, "A's member, lost with its set");
    }

    /// A late-reliable sibling case: B starts BEST_EFFORT (refused,
    /// `writer_shut_out`), so A's set 1 is decided and flushed without it.
    /// B then re-announces RELIABLE: its pair verdict flips, and B's own
    /// part of the SAME set 1 arrives (a reliable retransmit of what it sent
    /// while shut out). A decided set is final: delivering B's part now
    /// delivers set 1 in two parts (DDS v1.4 Sec.2.2.3.6), and staging it
    /// opened a set A never ends again, B's samples held for good, neither
    /// delivered nor reported. It is discarded at once and reported lost
    /// (SAMPLE_LOST, Sec.2.2.4.1: never made available to the reader, as
    /// for any GROUP set discarded whole), each sample once, nothing staged,
    /// and B's later changes go through.
    #[test]
    fn a_late_part_of_a_decided_group_set_is_discarded_and_reported() {
        let topic = "group-sibling-verdict-flip";
        let fsm = discovery(topic, QoS::reliable(), QoS::best_effort());
        let net = reader(Arc::clone(&fsm), LOCAL, PREFIX, topic, &[]);
        let (a, b) = (guid(PREFIX, A), guid(PREFIX, B));
        assert!(
            net.subscriber.writer_refused_for_test(&b),
            "fixture: B refused (best-effort vs reliable reader)"
        );

        // A's set 1, member + end, decided and flushed while B is shut out.
        member(&net, a, 1, 1, 1, 11);
        end(&net, a, 2, 1, 1);
        assert_eq!(
            values(&net),
            vec![11],
            "A's set flushed alone while B was shut out"
        );

        // B re-announces RELIABLE: the pair verdict flips.
        fsm.handle_sedp(announcement(PREFIX, B, topic, QoS::reliable()));
        assert!(
            !net.subscriber.writer_refused_for_test(&b),
            "fixture: B now matched (verdict flipped)"
        );
        // Its first HEARTBEAT heard (the one before was B's while refused).
        net.subscriber.on_writer_heartbeat_range(b, 1, 2);

        // A's repair of its member of set 1: a duplicate, not a loss.
        member(&net, a, 1, 1, 1, 11);
        assert_eq!(values(&net), Vec::<i32>::new());
        assert_eq!(net.lost(), 0, "a repair of a delivered member is no loss");

        // B's own part of the SAME group set 1, twice (a repair), and its end.
        member(&net, b, 1, 1, 1, 21);
        member(&net, b, 1, 1, 1, 21);
        end(&net, b, 2, 1, 1);
        assert_eq!(values(&net), Vec::<i32>::new(), "set 1 never in two parts");
        assert_eq!(net.lost(), 1, "B's sample of set 1, reported once");
        assert!(
            net.subscriber
                .group_coherent_buffer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "nothing of set 1 staged again"
        );
        // B's next change, of no set, is held by nothing.
        crate::engine::router::set_route_writer_is_hdds_for_test(true);
        net.subscriber.on_data_with_writer(
            &net.topic,
            b,
            3,
            &encoded(&Keyed { id: 3, value: 3 }),
            crate::dds::CdrVersion::Xcdr2,
        );
        crate::engine::router::set_route_writer_is_hdds_for_test(false);
        assert_eq!(values(&net), vec![3]);
        assert_eq!(net.lost(), 1);
    }
}

/// DDS Security v1.1 Sec.8.8.7.1, 9.4.3: the peer, authenticated, is granted
/// the topic for the data tag (level, public): its writer A announcing that
/// tag is admitted, its writer B announcing (level, secret) is not, both of
/// one Publisher.
#[cfg(feature = "security")]
mod security {
    use super::*;
    use crate::security::access::{RemoteAccessControl, RemoteAccessInputs};
    use crate::security::cms::PermissionsCa;
    use crate::security::test_pki::{
        bound_test_prefix, local_machine_with_completed_peer, FIXTURE_NOW_UNIX, PERM_CA_EC_PEM,
        TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
    };

    const DOMAIN: u32 = 229;
    const TOPIC: &str = "sensor/group";
    const LOCAL: [u8; 12] = bound_test_prefix([0x01; 6]);
    const PREFIX: [u8; 12] = bound_test_prefix([0xFF; 6]);

    fn access_control() -> Arc<RemoteAccessControl> {
        let governance = format!(
            r#"<?xml version="1.0"?>
<governance>
  <domain_rule>
    <domains>{DOMAIN}</domains>
    <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
    <enable_join_access_control>true</enable_join_access_control>
    <discovery_protection_kind>NONE</discovery_protection_kind>
    <data_protection_kind>NONE</data_protection_kind>
  </domain_rule>
</governance>"#
        );
        let ca = PermissionsCa::from_pem(PERM_CA_EC_PEM).expect("fixture permissions CA parses");
        Arc::new(
            RemoteAccessControl::new(
                RemoteAccessInputs {
                    governance_xml: governance,
                    permissions_ca: Some(ca),
                    accept_unsigned_for_tests: true,
                    legacy_partition_matching: false,
                },
                DOMAIN,
            )
            .with_fixed_now(FIXTURE_NOW_UNIX),
        )
    }

    /// The peer's permissions: publish `sensor/*` for the tag (level,
    /// public), default DENY.
    fn peer_document() -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\"?><dds><permissions><grant name=\"peer\">\
             <subject_name>CN=DDS Test Identity, O=HDDS Test</subject_name><validity>\
             <not_before>2020-01-01T00:00:00</not_before>\
             <not_after>2036-01-01T00:00:00</not_after></validity>\
             <allow_rule><domains><id>{DOMAIN}</id></domains><publish><topics>\
             <topic>sensor/*</topic></topics><data_tags><tag><name>level</name>\
             <value>public</value></tag></data_tags></publish></allow_rule>\
             <default>DENY</default></grant></permissions></dds>"
        )
        .into_bytes()
    }

    fn tagged(level: &str) -> QoS {
        let mut qos = QoS::reliable();
        qos.data_tags.tags = vec![crate::qos::data_tags::DataTag {
            name: "level".to_string(),
            value: level.to_string(),
        }];
        qos
    }

    fn discovery() -> Arc<DiscoveryFsm> {
        let mut fsm = DiscoveryFsm::new(GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT), 100_000);
        fsm.set_handshake_machine(
            local_machine_with_completed_peer(LOCAL, PREFIX, Some(peer_document())),
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_remote_access_control(Some(access_control()));
        fsm.handle_spdp(spdp(PREFIX, Some(TEST_IDENTITY_CERT_PEM.to_vec())));
        for (id, level) in [(A, "public"), (B, "secret")] {
            fsm.handle_sedp_on(
                announcement(PREFIX, id, TOPIC, tagged(level)),
                crate::core::discovery::multicast::SedpChannel::Secure,
            );
        }
        let fsm = Arc::new(fsm);
        assert!(fsm.admits_remote_endpoint(TOPIC, &GUID::new(PREFIX, A), true));
        assert!(!fsm.admits_remote_endpoint(TOPIC, &GUID::new(PREFIX, B), true));
        fsm
    }

    /// B, not admitted, sends what would break A's set: nothing of it is
    /// taken, and A's set is delivered.
    #[test]
    fn a_sibling_not_admitted_cannot_break_the_admitted_writers_group_set() {
        let net = reader(discovery(), LOCAL, PREFIX, TOPIC, &[]);
        let b = guid(PREFIX, B);
        sibling_attacks(&net, b);
        the_matched_writers_set_is_delivered(&net, PREFIX);
        leaves_no_trace(&net, b);
    }

    /// B, not admitted, is no writer of this reader: its ends are refused
    /// (`on_ecs`), so it is not waited for either. Waited for, it parked
    /// every set of its Publisher for good.
    #[test]
    fn a_sibling_not_admitted_is_not_waited_for() {
        let net = reader(discovery(), LOCAL, PREFIX, TOPIC, &[]);
        let b = guid(PREFIX, B);
        // B ends the set as an HDDS writer does, idle in it: refused.
        end(&net, b, 1, 1, 1);
        the_matched_writers_set_is_delivered(&net, PREFIX);
    }
}

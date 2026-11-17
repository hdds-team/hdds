// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The deletion of a local endpoint, as SEDP announces it (RTPS v2.5
//! Sec.8.5.4.4, Tables 8.82, 8.83), and the departure of a remote writer, as
//! a reader of this participant sees it (DDS v1.4 Sec.2.2.2.5.1.3), on a
//! participant with a real UDP transport. The bytes asserted are the bytes
//! a peer socket received.

use super::live_capture::RawBytes;
use super::{Participant, TransportMode};
use crate::core::discovery::multicast::classifier::walk::{for_each_submessage, Step};
use crate::core::discovery::multicast::{DiscoveryFsm, SedpEndpointKind};
use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::dds::{InstanceState, QoS, DDS};
use crate::engine::subscriber::DisposeKind;
use crate::protocol::discovery::{SedpData, SpdpData};
use crate::test_support::domains::{unique_domain, DomainLease};
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::Duration;

/// The remote participant the peer socket stands for.
const PEER: [u8; 12] = [0x01, 0x1a, 0x5e, 0x5e, 0x5e, 0x5e, 0, 0, 0x22, 0x22, 0, 9];

fn participant(name: &str, domain: &DomainLease) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

fn fsm(p: &Participant) -> &Arc<DiscoveryFsm> {
    p.discovery_fsm
        .as_ref()
        .expect("a UDP participant runs discovery")
}

fn peer_announcement(locator: std::net::SocketAddr, lease_duration_ms: u64) -> SpdpData {
    SpdpData {
        participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
        lease_duration_ms,
        domain_id: 0,
        metatraffic_unicast_locators: vec![locator],
        default_unicast_locators: vec![locator],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    }
}

/// Uptime of a participant's discovery past which a participant it first
/// hears is trusted from that announcement: its startup probation is 250 ms
/// (`PROBATION_SPAN_MS`), with a margin.
const PAST_PROBATION: Duration = Duration::from_millis(300);

/// A socket the participant knows as the PEER participant's metatraffic and
/// default unicast locator.
///
/// PEER is announced once, after the participant's startup probation: a
/// participant first heard during it and never heard again is purged as a
/// stale packet of a dead process once 250 ms old, and the endpoint
/// disposes these tests read would then have no addressee. One first heard
/// after the probation lives by its lease.
fn known_peer(p: &Participant) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("peer socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .expect("read timeout");
    let locator = socket.local_addr().expect("peer address");
    if let Some(rest) = PAST_PROBATION.checked_sub(fsm(p).uptime()) {
        std::thread::sleep(rest);
    }
    fsm(p).handle_spdp(peer_announcement(locator, 30_000));
    socket
}

/// PEER is still a participant the discovery knows: a capture with no
/// dispose then says nothing was sent to it, not that it had no addressee.
fn assert_peer_known(p: &Participant) {
    assert!(
        fsm(p).is_participant_known(&PEER),
        "fixture: PEER is still known to the participant"
    );
}

/// Every datagram until the socket has been quiet for its read timeout.
fn drain(socket: &UdpSocket) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 65_536];
    while let Ok(len) = socket.recv(&mut buf) {
        out.push(buf[..len].to_vec());
    }
    out
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes[..4].try_into().expect("four octets"))
}

fn le_sn(bytes: &[u8]) -> u64 {
    (u64::from(le_u32(&bytes[..4])) << 32) | u64::from(le_u32(&bytes[4..8]))
}

/// An SEDP endpoint dispose, every field read from the datagram.
#[derive(Debug, PartialEq, Eq)]
struct WireDispose {
    header_prefix: [u8; 12],
    reader_id: [u8; 4],
    writer_id: [u8; 4],
    sn: u64,
    key_hash: [u8; 16],
    status_info: [u8; 4],
    serialized_guid: [u8; 16],
    /// (firstSN, lastSN) of the HEARTBEAT that follows it.
    heartbeat: Option<(u64, u64)>,
}

/// The SEDP endpoint disposes `datagrams` carry: DATA of an SEDP writer
/// with the K flag. The layout the wire must have is asserted octet by
/// octet: E|Q|K, octetsToInlineQos 16, inline QoS PID_KEY_HASH,
/// PID_STATUS_INFO, PID_SENTINEL, then the PL_CDR_LE key-only payload
/// (PID_ENDPOINT_GUID, PID_SENTINEL), 80 octets in all.
fn sedp_disposes(datagrams: &[Vec<u8>]) -> Vec<WireDispose> {
    let mut out = Vec::new();
    for dgram in datagrams {
        let mut found: Option<WireDispose> = None;
        for_each_submessage(dgram, |sub| {
            let body = sub.offset + 4;
            match sub.id {
                0x15 if matches!(
                    dgram[body + 8..body + 12],
                    [0x00, 0x00, 0x03, 0xC2] | [0x00, 0x00, 0x04, 0xC2]
                ) && sub.flags & 0x08 != 0 =>
                {
                    assert_eq!(sub.flags, 0x0b, "E|Q|K");
                    assert_eq!(sub.octets_to_next, 80, "the DATA body");
                    assert_eq!(&dgram[body..body + 2], &[0, 0], "extraFlags");
                    assert_eq!(&dgram[body + 2..body + 4], &[16, 0], "octetsToInlineQos");
                    let qos = body + 20;
                    assert_eq!(&dgram[qos..qos + 4], &[0x70, 0x00, 0x10, 0x00], "KEY_HASH");
                    assert_eq!(
                        &dgram[qos + 20..qos + 24],
                        &[0x71, 0x00, 0x04, 0x00],
                        "STATUS_INFO"
                    );
                    assert_eq!(&dgram[qos + 28..qos + 32], &[0x01, 0, 0, 0], "sentinel");
                    let key = qos + 32;
                    assert_eq!(&dgram[key..key + 4], &[0x00, 0x03, 0x00, 0x00], "PL_CDR_LE");
                    assert_eq!(
                        &dgram[key + 4..key + 8],
                        &[0x5a, 0x00, 0x10, 0x00],
                        "PID_ENDPOINT_GUID"
                    );
                    assert_eq!(&dgram[key + 24..key + 28], &[0x01, 0, 0, 0], "sentinel");
                    assert_eq!(key + 28, body + 80, "nothing else in the DATA");
                    found = Some(WireDispose {
                        header_prefix: dgram[8..20].try_into().expect("prefix"),
                        reader_id: dgram[body + 4..body + 8].try_into().expect("id"),
                        writer_id: dgram[body + 8..body + 12].try_into().expect("id"),
                        sn: le_sn(&dgram[body + 12..]),
                        key_hash: dgram[qos + 4..qos + 20].try_into().expect("key"),
                        status_info: dgram[qos + 24..qos + 28].try_into().expect("status"),
                        serialized_guid: dgram[key + 8..key + 24].try_into().expect("guid"),
                        heartbeat: None,
                    });
                }
                0x07 => {
                    if let Some(ref mut dispose) = found {
                        assert_eq!(&dgram[body + 4..body + 8], &dispose.writer_id);
                        assert_eq!(&dgram[body..body + 4], &dispose.reader_id);
                        dispose.heartbeat =
                            Some((le_sn(&dgram[body + 8..]), le_sn(&dgram[body + 16..])));
                    }
                }
                _ => {}
            }
            Step::Continue
        });
        out.extend(found);
    }
    out
}

/// A deleted DataWriter's dispose, decoded from what the peer received:
/// the publications writer to the publications reader, N+1, its GUID as
/// the key hash and as the serialized key, DISPOSED|UNREGISTERED, followed
/// by a HEARTBEAT whose range ends at the dispose and starts at 2: the
/// deleted writer's announcement, 1, is superseded (RTPS v2.5 Sec.8.3.8.6:
/// firstSN is the first change still available).
#[test]
fn a_deleted_writer_sends_the_dispose_of_its_sedp_instance() {
    let domain = unique_domain();
    let p = participant("y22_wire_writer", &domain);
    let peer = known_peer(&p);
    let qos = QoS::best_effort();
    let first = p
        .announce_writer_endpoint::<RawBytes>("Y22WireA", &qos)
        .expect("first writer");
    let _second = p
        .announce_writer_endpoint::<RawBytes>("Y22WireB", &qos)
        .expect("second writer");
    let endpoint = GUID::new(p.guid().prefix, first.entity_id());
    assert!(
        sedp_disposes(&drain(&peer)).is_empty(),
        "the announcements are no dispose"
    );

    drop(first);
    assert_eq!(
        sedp_disposes(&drain(&peer)),
        vec![WireDispose {
            header_prefix: p.guid().prefix,
            reader_id: [0x00, 0x00, 0x03, 0xC7],
            writer_id: [0x00, 0x00, 0x03, 0xC2],
            sn: 3,
            key_hash: endpoint.as_bytes(),
            status_info: [0, 0, 0, 0x03],
            serialized_guid: endpoint.as_bytes(),
            heartbeat: Some((2, 3)),
        }]
    );
}

/// Same for a DataReader, on the subscriptions writer.
#[test]
fn a_deleted_reader_sends_the_dispose_of_its_sedp_instance() {
    let domain = unique_domain();
    let p = participant("y22_wire_reader", &domain);
    let peer = known_peer(&p);
    let qos = QoS::best_effort();
    let announce = |topic: &str| {
        let reservation = p.reserve_reader_endpoint::<RawBytes>(topic, None, None, false);
        p.announce_reserved_reader(topic, &qos, reservation)
            .expect("reader")
    };
    let first = announce("Y22WireR1");
    let _second = announce("Y22WireR2");
    let endpoint = GUID::new(p.guid().prefix, first.entity_id());
    drain(&peer);

    drop(first);
    assert_eq!(
        sedp_disposes(&drain(&peer)),
        vec![WireDispose {
            header_prefix: p.guid().prefix,
            reader_id: [0x00, 0x00, 0x04, 0xC7],
            writer_id: [0x00, 0x00, 0x04, 0xC2],
            sn: 3,
            key_hash: endpoint.as_bytes(),
            status_info: [0, 0, 0, 0x03],
            serialized_guid: endpoint.as_bytes(),
            heartbeat: Some((2, 3)),
        }]
    );
}

/// The numbers stay dense across a deletion and a creation: the endpoint
/// created after a deletion takes N+2, and the replay a newly discovered
/// peer gets sends a GAP for the deleted one's announcement and the dispose
/// at N+1, never the announcement.
#[test]
fn a_new_endpoint_after_a_deletion_takes_the_next_number() {
    let domain = unique_domain();
    let p = participant("y22_dense", &domain);
    let qos = QoS::best_effort();
    let deleted = p
        .announce_writer_endpoint::<RawBytes>("Y22DenseA", &qos)
        .expect("writer");
    let deleted_guid = GUID::new(p.guid().prefix, deleted.entity_id());
    drop(deleted);
    let next = p
        .announce_writer_endpoint::<RawBytes>("Y22DenseB", &qos)
        .expect("writer");
    let next_guid = GUID::new(p.guid().prefix, next.entity_id());
    let history = p
        .sedp_announcements
        .read()
        .unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        history.seq_of(&next_guid, SedpEndpointKind::Writer),
        Some(3)
    );
    assert_eq!(
        history.seq_of(&deleted_guid, SedpEndpointKind::Writer),
        None
    );
    let replay: Vec<(u64, u64, bool, Option<GUID>)> = history
        .sends(Some(SedpEndpointKind::Writer))
        .iter()
        .map(|s| {
            (
                s.seq,
                s.last_seq(),
                s.is_gap(),
                s.announcement().map(|a| a.endpoint_guid),
            )
        })
        .collect();
    assert_eq!(
        replay,
        vec![
            (1, 1, true, None),
            (2, 2, false, None),
            (3, 3, false, Some(next_guid)),
        ]
    );
    let dispose = history.sends(Some(SedpEndpointKind::Writer))[1]
        .build(
            &p.guid().prefix,
            Some(&PEER),
            crate::protocol::dialect::Dialect::Hdds,
        )
        .expect("dispose");
    let decoded = sedp_disposes(&[dispose]);
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].sn, 2);
    assert_eq!(decoded[0].key_hash, deleted_guid.as_bytes());
}

/// The participant's SPDP dispose retires every endpoint at once, and no
/// SEDP dispose follows it: dropping the participant closes its SEDP
/// history, and an endpoint dropped after that retires nothing.
#[test]
fn an_endpoint_outliving_its_participant_sends_no_sedp_dispose() {
    let domain = unique_domain();
    let p = participant("y22_participant_first", &domain);
    let peer = known_peer(&p);
    let token = p
        .announce_writer_endpoint::<RawBytes>("Y22ParticipantFirst", &QoS::best_effort())
        .expect("writer");
    let history = Arc::clone(&p.sedp_announcements);
    drain(&peer);
    assert_peer_known(&p);

    drop(p);
    assert!(
        history
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .is_closed(),
        "the participant closed its SEDP history on its way out"
    );
    drop(token);
    assert!(sedp_disposes(&drain(&peer)).is_empty());
    assert_eq!(
        history
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .last_seq(SedpEndpointKind::Writer),
        1,
        "and appended nothing"
    );
}

/// The farewell check itself, with the participant, its discovery and its
/// transport all still there: a closed history retires nothing and sends
/// nothing.
#[test]
fn a_closed_history_retires_nothing() {
    let domain = unique_domain();
    let p = participant("y22_closed", &domain);
    let peer = known_peer(&p);
    let token = p
        .announce_writer_endpoint::<RawBytes>("Y22Closed", &QoS::best_effort())
        .expect("writer");
    drain(&peer);
    p.sedp_announcements
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .close();
    assert_peer_known(&p);
    drop(token);
    assert!(sedp_disposes(&drain(&peer)).is_empty());
}

// ---------------------------------------------------------------------------
// A keyed type for the DataWriter / DataReader tests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct KeyedWire {
    key: i64,
    value: i64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Keyed {
    key: i64,
    value: i64,
}

impl DDS for Keyed {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        KeyedWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        KeyedWire {
            key: self.key,
            value: self.value,
        }
        .encode(buf, version)
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        let wire = KeyedWire::decode(buf, version)?;
        Ok(Self {
            key: wire.key,
            value: wire.value,
        })
    }

    fn has_key() -> bool {
        true
    }

    fn compute_key(&self) -> [u8; 16] {
        let mut hash = [0u8; 16];
        hash[..8].copy_from_slice(&self.key.to_le_bytes());
        hash[8..].copy_from_slice(&(!self.key).to_le_bytes());
        hash
    }
}

fn encoded(sample: Keyed) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    let len = sample
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf.truncate(len);
    buf
}

/// The participant's discovery, past its probation, with PEER confirmed.
fn confirm_peer(p: &Participant, locator: std::net::SocketAddr, lease_duration_ms: u64) {
    std::thread::sleep(Duration::from_millis(300));
    fsm(p).handle_spdp(peer_announcement(locator, lease_duration_ms));
    std::thread::sleep(Duration::from_millis(150));
    fsm(p).handle_spdp(peer_announcement(locator, lease_duration_ms));
    assert!(fsm(p).is_participant_confirmed(&PEER));
}

/// Complete the writer discovery that must precede admitted test DATA.
/// Routing and OWNERSHIP metadata alone are not a pair QoS/type verdict.
fn discover_keyed_writer(p: &Participant, topic: &str, writer: GUID, qos: QoS) {
    // The payloads injected below use XCDR2.
    let qos = qos.data_representation_xcdr2();
    let registry = p.registry.as_ref().expect("registry");
    registry.register_writer_guid(writer.as_bytes(), topic.to_string());
    registry.register_writer_ownership_kind(
        writer.as_bytes(),
        crate::qos::ownership::OwnershipKind::Shared,
    );
    fsm(p).handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: Keyed::type_descriptor().type_name.to_string(),
        participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
        endpoint_guid: writer,
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
        group_entity_id: None,
        endpoint_security_info: None,
    });
    let _ = registry.notify_writer_qos_resolved(writer.as_bytes());
}

/// A reader built AFTER a short-lived writer of its topic is known (the
/// common order) still expires only that writer's samples. The match
/// registry's catch-up runs inside the reader's construction and tightens
/// the reader-wide lifespan cell to the writer's 1 ns; the reader's own
/// lifespan was read from that cell, so every writer's samples expired by
/// it. A sample of another writer, which announced no lifespan, must be
/// delivered; the short-lived writer's own expires.
#[test]
fn a_reader_built_after_a_short_lived_writer_expires_only_its_samples() {
    const TOPIC: &str = "LifespanPerWriterOrder";
    let domain = unique_domain();
    let p = participant("lifespan_order", &domain);
    confirm_peer(&p, "127.0.0.1:9".parse().expect("address"), 30_000);
    let short_lived = GUID::new(PEER, [0x00, 0x00, 0x03, 0x02]);
    let long_lived = GUID::new(PEER, [0x00, 0x00, 0x04, 0x02]);
    let one_ns = QoS::best_effort().lifespan(crate::qos::lifespan::Lifespan {
        duration: Duration::from_nanos(1),
    });
    discover_keyed_writer(&p, TOPIC, short_lived, one_ns);
    let registry = p.registry.as_ref().expect("registry");
    registry.register_writer_lifespan_of(TOPIC, short_lived.as_bytes(), 1);

    let reader = p
        .topic::<Keyed>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_last(8))
        .build()
        .expect("reader");
    discover_keyed_writer(&p, TOPIC, long_lived, QoS::best_effort());
    let route = registry.get_topic(TOPIC).expect("the reader's topic");
    route.deliver_with_writer(
        short_lived.as_bytes(),
        1,
        &encoded(Keyed { key: 1, value: 1 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    route.deliver_with_writer(
        long_lived.as_bytes(),
        1,
        &encoded(Keyed { key: 2, value: 2 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        reader.take().expect("take"),
        Some(Keyed { key: 2, value: 2 }),
        "the long-lived writer's sample expired by the other writer's lifespan"
    );
    assert_eq!(reader.take().expect("take"), None);
}

/// A sample still in the reader when its writer leaves expires by that
/// writer's lifespan all the same (DDS v1.4 Sec.2.2.3.16): the writer's
/// record leaves the participant with the writer, and the sample, judged
/// when the application reads it, was delivered as if it had none.
#[test]
fn a_departed_writers_samples_still_expire_by_its_lifespan() {
    const TOPIC: &str = "LifespanAfterDeparture";
    let domain = unique_domain();
    let p = participant("lifespan_departed", &domain);
    confirm_peer(&p, "127.0.0.1:9".parse().expect("address"), 30_000);
    let short_lived = GUID::new(PEER, [0x00, 0x00, 0x05, 0x02]);
    let registry = p.registry.as_ref().expect("registry");
    let reader = p
        .topic::<Keyed>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_last(8))
        .build()
        .expect("reader");
    discover_keyed_writer(
        &p,
        TOPIC,
        short_lived,
        QoS::best_effort().lifespan(crate::qos::lifespan::Lifespan {
            duration: Duration::from_nanos(1),
        }),
    );
    registry.register_writer_lifespan_of(TOPIC, short_lived.as_bytes(), 1); // 1 ns
    let route = registry.get_topic(TOPIC).expect("the reader's topic");
    route.deliver_with_writer(
        short_lived.as_bytes(),
        1,
        &encoded(Keyed { key: 1, value: 1 }),
        crate::dds::CdrVersion::Xcdr2,
    );

    // The writer leaves before the application reads.
    assert!(registry.notify_writer_dispose(short_lived.as_bytes(), DisposeKind::Unregistered));
    let _ = fsm(&p).remove_remote_endpoint(short_lived);
    assert_eq!(registry.writer_lifespan(&short_lived.as_bytes()), None);
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        reader.take().expect("take"),
        None,
        "the departed writer's sample expired by its 1 ns lifespan"
    );
    // Its DATA sent before its departure overtook by its dispose (the
    // DATA on the router thread, the dispose on the control thread) lands
    // now, into a ring the take just saw empty: it expires by the departed
    // writer's lifespan all the same.
    route.deliver_with_writer(
        short_lived.as_bytes(),
        2,
        &encoded(Keyed { key: 1, value: 2 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        reader.take().expect("take"),
        None,
        "a late sample of the departed writer expired by its 1 ns lifespan"
    );
    // Announced again, the writer is judged by its new record: here none.
    discover_keyed_writer(&p, TOPIC, short_lived, QoS::best_effort());
    assert_eq!(reader.departed_lifespan_of(&short_lived.as_bytes()), None);
}

/// A writer of `p` on `topic` matched with a best-effort reader of the raw
/// `peer`, with the entity id it is announced under.
fn writer_matched_with_peer(
    p: &Arc<Participant>,
    topic: &str,
    qos: QoS,
) -> (crate::dds::DataWriter<Keyed>, UdpSocket, [u8; 4]) {
    let peer = known_peer(p);
    let locator = peer.local_addr().expect("peer address");
    confirm_peer(p, locator, 30_000);
    fsm(p).handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: Keyed::type_descriptor().type_name.to_string(),
        participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
        endpoint_guid: GUID::new(PEER, [0x00, 0x00, 0x01, 0x07]),
        qos_hash: 0,
        qos: Some(QoS::best_effort()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![locator],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
    let writer = p
        .topic::<Keyed>(topic)
        .expect("topic")
        .writer()
        .qos(qos)
        .build()
        .expect("writer");
    let user_writer = p
        .sedp_announcements
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .alive()
        .find(|(sd, kind)| *kind == SedpEndpointKind::Writer && sd.topic_name == topic)
        .map(|(sd, _)| sd.endpoint_guid.entity_id)
        .expect("the writer is announced");
    (writer, peer, user_writer)
}

/// The PID_STATUS_INFO value of every DATA of `writer_id` carrying inline
/// QoS in `datagrams`, read by walking the parameter list.
fn lifecycle_status_infos(datagrams: &[Vec<u8>], writer_id: [u8; 4]) -> Vec<[u8; 4]> {
    let mut out = Vec::new();
    for dgram in datagrams {
        for_each_submessage(dgram, |sub| {
            let body = sub.offset + 4;
            if sub.id == 0x15 && sub.flags & 0x02 != 0 && dgram[body + 8..body + 12] == writer_id {
                assert_ne!(sub.flags & 0x01, 0, "a little-endian DATA");
                let to_qos = usize::from(u16::from_le_bytes([dgram[body + 2], dgram[body + 3]]));
                let mut at = body + 4 + to_qos;
                loop {
                    let pid = u16::from_le_bytes([dgram[at], dgram[at + 1]]);
                    let len = usize::from(u16::from_le_bytes([dgram[at + 2], dgram[at + 3]]));
                    if pid == 0x0001 {
                        break;
                    }
                    if pid == 0x0071 {
                        assert_eq!(len, 4, "StatusInfo_t is four octets");
                        out.push(dgram[at + 4..at + 8].try_into().expect("status"));
                    }
                    at += 4 + len;
                }
            }
            Step::Continue
        });
    }
    out
}

/// What deleting a writer of `qos` puts on the wire for the one instance it
/// wrote (and disposed first when `dispose_first`): the PID_STATUS_INFO of
/// each lifecycle DATA the peer receives after the drop.
fn status_infos_sent_by_the_deletion(topic: &str, qos: QoS, dispose_first: bool) -> Vec<[u8; 4]> {
    let domain = unique_domain();
    let p = participant(topic, &domain);
    let (writer, peer, user_writer) = writer_matched_with_peer(&p, topic, qos);
    writer.write(&Keyed { key: 1, value: 1 }).expect("write");
    if dispose_first {
        writer
            .dispose(&Keyed { key: 1, value: 1 })
            .expect("dispose");
    }
    drain(&peer);
    drop(writer);
    lifecycle_status_infos(&drain(&peer), user_writer)
}

/// DDS v1.4 Sec.2.2.2.4.1.6 and Sec.2.2.3.21: the deletion unregisters the
/// instance, and with autodispose_unregistered_instances TRUE (the default)
/// it disposes it too - DISPOSED|UNREGISTERED (RTPS v2.5 Sec.9.6.4.9).
#[test]
fn a_deleted_writer_disposes_and_unregisters_its_instances_by_default() {
    assert_eq!(
        status_infos_sent_by_the_deletion("WdlWireAuto", QoS::best_effort(), false),
        [[0, 0, 0, 0x03]]
    );
}

/// With autodispose_unregistered_instances FALSE the deletion unregisters
/// only: UNREGISTERED alone.
#[test]
fn a_deleted_writer_without_autodispose_only_unregisters_its_instances() {
    assert_eq!(
        status_infos_sent_by_the_deletion(
            "WdlWireManual",
            QoS::best_effort().writer_data_lifecycle_manual_dispose(),
            false
        ),
        [[0, 0, 0, 0x02]]
    );
}

/// An instance the application disposed is left alone by the deletion,
/// whatever the policy: nothing more goes out for it.
#[test]
fn a_deleted_writer_sends_nothing_more_for_an_instance_it_disposed() {
    for (topic, qos) in [
        ("WdlWireDisposedAuto", QoS::best_effort()),
        (
            "WdlWireDisposedManual",
            QoS::best_effort().writer_data_lifecycle_manual_dispose(),
        ),
    ] {
        assert_eq!(
            status_infos_sent_by_the_deletion(topic, qos, true),
            Vec::<[u8; 4]>::new(),
            "{topic}"
        );
    }
}

/// DDS v1.4 Sec.2.2.2.4.1.6: deleting a DataWriter unregisters its
/// instances, and the remote reader must hear that from a writer it still
/// knows. The unregister reaches the peer BEFORE the SEDP dispose that
/// unmatches the writer.
#[test]
fn a_deleted_writer_unregisters_its_instances_before_its_sedp_dispose() {
    const TOPIC: &str = "Y22UnregisterFirst";
    let domain = unique_domain();
    let p = participant("y22_order", &domain);
    let (writer, peer, user_writer) = writer_matched_with_peer(&p, TOPIC, QoS::best_effort());
    writer.write(&Keyed { key: 1, value: 1 }).expect("write");
    drain(&peer);

    drop(writer);
    let datagrams = drain(&peer);
    // Index of the first datagram carrying a DATA of the user writer with
    // inline QoS (the unregister), and of the first SEDP dispose.
    let position = |wanted: &dyn Fn(
        &[u8],
        &crate::core::discovery::multicast::classifier::walk::Submessage,
    ) -> bool| {
        datagrams.iter().position(|dgram| {
            let mut hit = false;
            for_each_submessage(dgram, |sub| {
                hit |= wanted(dgram, sub);
                Step::Continue
            });
            hit
        })
    };
    let unregister = position(&|dgram, sub| {
        sub.id == 0x15
            && sub.flags & 0x02 != 0
            && dgram[sub.offset + 12..sub.offset + 16] == user_writer
    })
    .expect("the unregister reached the peer");
    let dispose = position(&|dgram, sub| {
        sub.id == 0x15
            && sub.flags & 0x08 != 0
            && dgram[sub.offset + 12..sub.offset + 16] == [0x00, 0x00, 0x03, 0xC2]
    })
    .expect("the SEDP dispose reached the peer");
    assert!(
        unregister < dispose,
        "the unregister ({unregister}) precedes the SEDP dispose ({dispose})"
    );
}

// ---------------------------------------------------------------------------
// The departure of a remote writer, on a reader of this participant
// ---------------------------------------------------------------------------

/// How a remote writer leaves.
#[derive(Clone, Copy, Debug)]
enum Departure {
    /// Its participant disposes its SPDP instance (`remove_participant`,
    /// what `apply_participant_departure` calls).
    SpdpDispose,
    /// Its participant's lease expires (`remove_expired_participant`, what
    /// the lease tracker calls).
    LeaseExpiry,
    /// It disposes its own SEDP instance (`notify_writer_dispose`, what
    /// `apply_sedp_endpoint_dispose` calls).
    SedpDispose,
}

/// A reader of this participant received from the remote writer W: data
/// for instances 1 and 2, then the dispose of instance 1. W leaves before
/// the application reads anything. Nothing received is lost, instance 1
/// stays NOT_ALIVE_DISPOSED, instance 2 (alive when W left) goes
/// NOT_ALIVE_NO_WRITERS (DDS v1.4 Sec.2.2.2.5.1.3, Sec.2.2.3.22).
fn a_departure_keeps_what_was_received(how: Departure) {
    let topic = format!("Y22Departure{how:?}");
    let domain = unique_domain();
    let p = participant(&format!("y22_departure_{how:?}"), &domain);
    let lease_ms = match how {
        Departure::LeaseExpiry => 200,
        _ => 30_000,
    };
    confirm_peer(&p, "127.0.0.1:9".parse().expect("address"), lease_ms);
    let reader = p
        .topic::<Keyed>(&topic)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_last(8))
        .build()
        .expect("reader");
    let writer = GUID::new(PEER, [0x00, 0x00, 0x03, 0x02]);
    let registry = p.registry.as_ref().expect("registry");
    discover_keyed_writer(&p, &topic, writer, QoS::best_effort());
    let route = registry.get_topic(&topic).expect("the reader's topic");
    let one = Keyed { key: 1, value: 10 };
    let two = Keyed { key: 2, value: 20 };
    route.deliver_with_writer(
        writer.as_bytes(),
        1,
        &encoded(one),
        crate::dds::CdrVersion::Xcdr2,
    );
    route.deliver_with_writer(
        writer.as_bytes(),
        2,
        &encoded(two),
        crate::dds::CdrVersion::Xcdr2,
    );
    route.deliver_dispose(3, one.compute_key(), DisposeKind::Disposed);

    match how {
        Departure::SpdpDispose => {
            fsm(&p).remove_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT))
        }
        Departure::LeaseExpiry => {
            std::thread::sleep(Duration::from_millis(lease_ms + 100));
            fsm(&p).remove_expired_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT));
        }
        Departure::SedpDispose => {
            assert!(registry.notify_writer_dispose(writer.as_bytes(), DisposeKind::Unregistered));
        }
    }
    // The departure reaches the reader behind the data queued before it,
    // on the Router (`engine::departures`).
    registry.settle_departures();
    assert!(
        !fsm(&p).is_participant_known(&PEER) || matches!(how, Departure::SedpDispose),
        "{how:?}: the participant left"
    );

    let mut taken = Vec::new();
    while let Some((data, info)) = reader.take_with_info().expect("take") {
        taken.push((
            data,
            info.instance_handle.0,
            info.instance_state,
            info.valid_data,
        ));
    }
    let of = |key: [u8; 16]| -> Vec<(Option<Keyed>, InstanceState, bool)> {
        taken
            .iter()
            .filter(|(_, handle, _, _)| *handle == key)
            .map(|(data, _, state, valid)| (*data, *state, *valid))
            .collect()
    };
    assert_eq!(
        of(one.compute_key()),
        vec![
            (Some(one), InstanceState::NotAliveDisposed, true),
            (None, InstanceState::NotAliveDisposed, false),
        ],
        "{how:?}: the data and the dispose of instance 1, DISPOSED: {taken:?}"
    );
    assert_eq!(
        of(two.compute_key()),
        vec![
            (Some(two), InstanceState::NotAliveNoWriters, true),
            (None, InstanceState::NotAliveNoWriters, false),
        ],
        "{how:?}: the data of instance 2, then NO_WRITERS: {taken:?}"
    );
}

#[test]
fn a_participants_spdp_dispose_keeps_what_was_received_and_disposed() {
    a_departure_keeps_what_was_received(Departure::SpdpDispose);
}

#[test]
fn a_participants_lease_expiry_keeps_what_was_received_and_disposed() {
    a_departure_keeps_what_was_received(Departure::LeaseExpiry);
}

#[test]
fn a_writers_sedp_dispose_keeps_what_was_received_and_disposed() {
    a_departure_keeps_what_was_received(Departure::SedpDispose);
}

/// DDS v1.4 Sec.2.2.2.4.2.7: an instance moves to NOT_ALIVE_NO_WRITERS only
/// when no other DataWriter is writing it. Two remote writers write one
/// instance; one leaves, the instance stays ALIVE; the second leaves, it
/// goes NO_WRITERS.
#[test]
fn an_instance_another_writer_still_writes_stays_alive() {
    const TOPIC: &str = "Y22TwoWriters";
    let domain = unique_domain();
    let p = participant("y22_two_writers", &domain);
    let reader = p
        .topic::<Keyed>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_last(8))
        .build()
        .expect("reader");
    let first = GUID::new(PEER, [0x00, 0x00, 0x03, 0x02]);
    let second = GUID::new(PEER, [0x00, 0x00, 0x04, 0x02]);
    let registry = p.registry.as_ref().expect("registry");
    let route = registry.get_topic(TOPIC).expect("the reader's topic");
    for (seq, value, writer) in [(1, 70, first), (2, 71, second)] {
        let sample = Keyed { key: 7, value };
        discover_keyed_writer(&p, TOPIC, writer, QoS::best_effort());
        route.deliver_with_writer(
            writer.as_bytes(),
            seq,
            &encoded(sample),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert!(registry.notify_writer_dispose(first.as_bytes(), DisposeKind::Unregistered));
    let mut states = Vec::new();
    while let Some((data, info)) = reader.take_with_info().expect("take") {
        states.push((data.is_some(), info.instance_state));
    }
    assert_eq!(
        states,
        vec![(true, InstanceState::Alive), (true, InstanceState::Alive)],
        "one writer left, the other still writes the instance"
    );

    assert!(registry.notify_writer_dispose(second.as_bytes(), DisposeKind::Unregistered));
    let (data, info) = reader
        .take_with_info()
        .expect("take")
        .expect("the last writer left");
    assert!(data.is_none());
    assert_eq!(info.instance_state, InstanceState::NotAliveNoWriters);
}

/// A departure after the application already took an instance's dispose
/// changes nothing for that instance: it stays NOT_ALIVE_DISPOSED, and no
/// NOT_ALIVE_NO_WRITERS notification appears for it.
#[test]
fn a_departure_after_the_dispose_was_read_adds_nothing() {
    const TOPIC: &str = "Y22DisposeRead";
    let domain = unique_domain();
    let p = participant("y22_dispose_read", &domain);
    confirm_peer(&p, "127.0.0.1:9".parse().expect("address"), 30_000);
    let reader = p
        .topic::<Keyed>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_last(8))
        .build()
        .expect("reader");
    let writer = GUID::new(PEER, [0x00, 0x00, 0x05, 0x02]);
    let registry = p.registry.as_ref().expect("registry");
    discover_keyed_writer(&p, TOPIC, writer, QoS::best_effort());
    let route = registry.get_topic(TOPIC).expect("the reader's topic");
    let sample = Keyed { key: 3, value: 30 };
    route.deliver_with_writer(
        writer.as_bytes(),
        1,
        &encoded(sample),
        crate::dds::CdrVersion::Xcdr2,
    );
    route.deliver_dispose(2, sample.compute_key(), DisposeKind::Disposed);
    let mut read = Vec::new();
    while let Some((data, info)) = reader.take_with_info().expect("take") {
        read.push((data.is_some(), info.instance_state));
    }
    assert_eq!(
        read,
        vec![
            (true, InstanceState::NotAliveDisposed),
            (false, InstanceState::NotAliveDisposed)
        ]
    );

    fsm(&p).remove_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT));
    assert!(!fsm(&p).is_participant_known(&PEER), "the participant left");
    assert!(
        reader.take_with_info().expect("take").is_none(),
        "no NO_WRITERS notification for an instance already disposed"
    );
}

/// A reader built on a participant keeps its announcement for as long as it
/// lives, and its drop sends the dispose of it.
#[test]
fn a_built_reader_is_retired_when_dropped_not_before() {
    const TOPIC: &str = "Y22BuiltReader";
    let domain = unique_domain();
    let p = participant("y22_built_reader", &domain);
    let peer = known_peer(&p);
    let reader = p
        .topic::<Keyed>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader");
    let guid = p
        .sedp_announcements
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .alive()
        .find(|(sd, kind)| *kind == SedpEndpointKind::Reader && sd.topic_name == TOPIC)
        .map(|(sd, _)| sd.endpoint_guid)
        .expect("the built reader is announced, and stays so");
    assert!(sedp_disposes(&drain(&peer)).is_empty(), "not retired yet");

    drop(reader);
    let disposes = sedp_disposes(&drain(&peer));
    assert_eq!(disposes.len(), 1);
    assert_eq!(disposes[0].key_hash, guid.as_bytes());
    assert_eq!(disposes[0].writer_id, [0x00, 0x00, 0x04, 0xC2]);
}

// ---------------------------------------------------------------------------
// A deleted local endpoint leaves its own participant's discovery
// ---------------------------------------------------------------------------

/// The GUIDs of the `kind` endpoints of `topic` this participant's discovery
/// knows, its own included.
fn known_endpoints(p: &Participant, topic: &str, kind: SedpEndpointKind) -> Vec<GUID> {
    let endpoints = match kind {
        SedpEndpointKind::Writer => fsm(p).find_writers_for_topic(topic),
        SedpEndpointKind::Reader => fsm(p).find_readers_for_topic(topic),
    };
    endpoints.iter().map(|e| e.endpoint_guid).collect()
}

/// The GUID this participant announced for its live `kind` endpoint of
/// `topic`.
fn announced(p: &Participant, topic: &str, kind: SedpEndpointKind) -> GUID {
    p.sedp_announcements
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .alive()
        .find(|(sd, k)| *k == kind && sd.topic_name == topic)
        .map(|(sd, _)| sd.endpoint_guid)
        .expect("the endpoint is announced")
}

/// A local endpoint enters its own participant's discovery when it is
/// announced, where every local and remote decision about its topic reads
/// it. A deleted DataWriter left SEDP for its peers but stayed there for
/// the life of the participant: a reader of the same participant, built
/// before or after the deletion, still saw it among the writers of its
/// topic. It leaves with its deletion; the reader beside it stays.
#[test]
fn a_deleted_local_writer_leaves_its_own_participants_discovery() {
    const TOPIC: &str = "DeletedLocalWriter";
    let domain = unique_domain();
    let p = participant("deleted_local_writer", &domain);
    let topic = p.topic::<Keyed>(TOPIC).expect("topic");
    let _reader = topic
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader");
    let writer = topic
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let writer_guid = announced(&p, TOPIC, SedpEndpointKind::Writer);
    let reader_guid = announced(&p, TOPIC, SedpEndpointKind::Reader);
    assert_eq!(
        known_endpoints(&p, TOPIC, SedpEndpointKind::Writer),
        vec![writer_guid],
        "fixture: the live writer is known to its own participant"
    );

    drop(writer);
    assert_eq!(
        known_endpoints(&p, TOPIC, SedpEndpointKind::Writer),
        Vec::<GUID>::new(),
        "the deleted writer left its own participant's discovery"
    );
    let _later = topic
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("a reader built after the deletion");
    assert_eq!(
        known_endpoints(&p, TOPIC, SedpEndpointKind::Writer),
        Vec::<GUID>::new(),
        "and a reader built after it finds no writer"
    );
    assert!(
        known_endpoints(&p, TOPIC, SedpEndpointKind::Reader).contains(&reader_guid),
        "the reader beside it stays"
    );
}

/// The mirror: a deleted DataReader leaves its own participant's discovery,
/// and the writer beside it stays.
#[test]
fn a_deleted_local_reader_leaves_its_own_participants_discovery() {
    const TOPIC: &str = "DeletedLocalReader";
    let domain = unique_domain();
    let p = participant("deleted_local_reader", &domain);
    let topic = p.topic::<Keyed>(TOPIC).expect("topic");
    let _writer = topic
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let reader = topic
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader");
    let writer_guid = announced(&p, TOPIC, SedpEndpointKind::Writer);
    let reader_guid = announced(&p, TOPIC, SedpEndpointKind::Reader);
    assert_eq!(
        known_endpoints(&p, TOPIC, SedpEndpointKind::Reader),
        vec![reader_guid],
        "fixture: the live reader is known to its own participant"
    );

    drop(reader);
    assert_eq!(
        known_endpoints(&p, TOPIC, SedpEndpointKind::Reader),
        Vec::<GUID>::new(),
        "the deleted reader left its own participant's discovery"
    );
    assert_eq!(
        known_endpoints(&p, TOPIC, SedpEndpointKind::Writer),
        vec![writer_guid],
        "the writer beside it stays"
    );
}

/// A deleted reader must not decide anything. A remote writer is refused at
/// the router when it is incompatible with every reader this participant has
/// on its topic; if that were read from a discovery record that outlives the
/// reader, a deleted EXCLUSIVE reader would still count among them and a
/// SHARED reader built afterwards would never receive a sample of a SHARED
/// remote writer. Each pair is judged by the match registry, which a deleted
/// reader leaves.
#[test]
fn a_deleted_local_reader_does_not_refuse_a_remote_writer() {
    use crate::core::discovery::multicast::build_sedp_rtps_packet;
    const TOPIC: &str = "DeletedReaderRefusal";
    let domain = unique_domain();
    let p = participant("deleted_reader_refusal", &domain);
    let peer = UdpSocket::bind("127.0.0.1:0").expect("peer socket");
    let locator = peer.local_addr().expect("peer address");
    confirm_peer(&p, locator, 30_000);
    let topic = p.topic::<Keyed>(TOPIC).expect("topic");
    let exclusive = topic
        .reader()
        .qos(QoS::best_effort().ownership_exclusive())
        .build()
        .expect("exclusive reader");
    drop(exclusive);

    let writer = GUID::new(PEER, [0x00, 0x00, 0x05, 0x02]);
    let sedp = SedpData {
        topic_name: TOPIC.to_string(),
        type_name: Keyed::type_descriptor().type_name.to_string(),
        participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
        endpoint_guid: writer,
        qos_hash: 0,
        qos: Some(QoS::best_effort()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![locator],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    };
    let packet = build_sedp_rtps_packet(
        &sedp,
        SedpEndpointKind::Writer,
        &PEER,
        Some(&p.guid().prefix),
        1,
        crate::protocol::dialect::Dialect::Hdds,
    )
    .expect("SEDP datagram");
    let mapping = p.port_mapping().expect("port mapping");
    let dest = std::net::SocketAddr::from(([127, 0, 0, 1], mapping.metatraffic_unicast));
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    while !known_endpoints(&p, TOPIC, SedpEndpointKind::Writer).contains(&writer) {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture: the remote writer's SEDP was received within 4 s"
        );
        peer.send_to(&packet, dest).expect("send SEDP");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Each (writer, local reader) pair is judged when the announcement
    // reaches discovery: a reader that was deleted judges nothing.
    assert_eq!(
        p.match_registry
            .as_ref()
            .expect("match registry")
            .refused_pair_counts(),
        (0, 0),
        "a reader that was deleted refuses nothing"
    );
}

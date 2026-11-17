// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The plain form of a GROUP change for a reader that reads per-writer sets
//! only (vendor 0x0114, `GroupDialect::SpecReceive`): its members carry no
//! coherent-set PIDs (0x0056, 0x8030, 0x0053, 0x0061, 0x0063-0x0065), no
//! end-of-set marker is sent to it, and the close SN is retired with a GAP.
//! An HDDS reader in the same audience keeps the close marker and today's
//! member form.
//!
//! The wire is decoded BY HAND (submessage walk, inline QoS walk), not with
//! our own extractors. The production entry points drive the sends: the live
//! publisher close, ACKNACK repair, NACK_FRAG repair and the TRANSIENT_LOCAL
//! replay to a late joiner.

use super::coherent_dispose_tests::{
    bind_capture, build_pair, drain, writer_ctx, CoherentDisposeSample,
};
use super::frag_route::FragRouteProfile;
use super::nack::{GroupForm, RetransmitCfg, WriterNackFragHandler, WriterNackHandler};
use super::runtime::{multicasts, LazyForm, WriterReplayState};
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::{EndpointRegistry, GUID};
use crate::core::rt::slabpool::SlabPool;
use crate::core::rtps_constants::HDDS_VENDOR_ID_U16;
use crate::dds::qos::{Presentation, PresentationAccessScope, QoS};
use crate::engine::{NackFragHandler, NackHandler};
use crate::protocol::builder;
use crate::protocol::discovery::{SedpData, SpdpData};
use crate::protocol::group::GroupTag;
use crate::qos::History;
use crate::reliability::{ChangeKind, ChangeMetadata, HistoryCache, ReliableMetrics};
use crate::transport::{PortMapping, UdpTransport};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Vendor id of Dust DDS (S2E Software Systems B.V.).
const DUST_VENDOR_ID: u16 = 0x0114;
/// The entity id of the Dust reader the registration helpers create.
const DUST_READER_EID: [u8; 4] = [0x00, 0x00, 0x20, 0x04];
/// The coherent-set and GROUP PIDs a plain member must not carry.
const SET_PIDS: [u16; 7] = [0x0056, 0x8030, 0x0053, 0x0061, 0x0063, 0x0064, 0x0065];

/// The submessages of one captured RTPS packet, as (id, flags, body), the
/// body being the bytes after the 4-byte submessage header.
fn submessages(pkt: &[u8]) -> Vec<(u8, u8, &[u8])> {
    let mut out = Vec::new();
    let mut at = 20;
    while at + 4 <= pkt.len() {
        let (id, flags) = (pkt[at], pkt[at + 1]);
        let len = if flags & 0x01 != 0 {
            usize::from(u16::from_le_bytes([pkt[at + 2], pkt[at + 3]]))
        } else {
            usize::from(u16::from_be_bytes([pkt[at + 2], pkt[at + 3]]))
        };
        let end = (at + 4 + len).min(pkt.len());
        out.push((id, flags, &pkt[at + 4..end]));
        at = end;
    }
    out
}

/// Every submessage of every packet, in order.
fn all_submessages(packets: &[Vec<u8>]) -> Vec<(u8, u8, Vec<u8>)> {
    packets
        .iter()
        .flat_map(|p| submessages(p))
        .map(|(id, flags, body)| (id, flags, body.to_vec()))
        .collect()
}

/// The inline QoS of a little-endian DATA or DATA_FRAG body: PID -> value,
/// walked from octetsToInlineQos (the body's bytes 2..4).
fn inline_pids(body: &[u8]) -> BTreeMap<u16, Vec<u8>> {
    let oti = usize::from(u16::from_le_bytes([body[2], body[3]]));
    let mut pids = BTreeMap::new();
    let mut at = 4 + oti;
    loop {
        let pid = u16::from_le_bytes([body[at], body[at + 1]]);
        let len = usize::from(u16::from_le_bytes([body[at + 2], body[at + 3]]));
        if pid == 0x0001 {
            break;
        }
        pids.insert(pid, body[at + 4..at + 4 + len].to_vec());
        at += 4 + len;
    }
    pids
}

/// A little-endian SequenceNumber_t at the start of `b` (high word first).
fn seq_at(b: &[u8]) -> u64 {
    (u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) << 32)
        | u64::from(u32::from_le_bytes([b[4], b[5], b[6], b[7]]))
}

/// The hex text of `bytes`, the form the golden constants are written in.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// FNV-1a 64 of `bytes`: a compact fingerprint for the golden fragment set.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Checks that every DATA carrying a payload in `subs` is a plain member: its
/// inline QoS has PID_TOPIC_NAME and none of the set PIDs. Returns the
/// writer SNs of those members.
fn assert_plain_members(subs: &[(u8, u8, Vec<u8>)]) -> Vec<u64> {
    let mut sns = Vec::new();
    for (id, flags, body) in subs.iter().filter(|s| s.0 == 0x15) {
        assert_ne!(
            flags & 0x04,
            0,
            "{id:#04x}: a DATA with no payload is a marker"
        );
        assert_ne!(flags & 0x02, 0, "a plain member carries inline QoS");
        let pids = inline_pids(body);
        assert!(pids.contains_key(&0x0005), "PID_TOPIC_NAME");
        for pid in SET_PIDS {
            assert!(
                !pids.contains_key(&pid),
                "plain member carries no {pid:#06x}"
            );
        }
        sns.push(seq_at(&body[12..20]));
    }
    sns
}

/// The GAP submessages of `subs`, as (gapStart, gapListBase, numBits, readerId).
fn gaps_of(subs: &[(u8, u8, Vec<u8>)]) -> Vec<(u64, u64, u32, [u8; 4])> {
    subs.iter()
        .filter(|s| s.0 == 0x08)
        .map(|(_, flags, body)| {
            assert_eq!(flags & 0x01, 1, "little-endian GAP");
            (
                seq_at(&body[8..16]),
                seq_at(&body[16..24]),
                u32::from_le_bytes([body[24], body[25], body[26], body[27]]),
                [body[0], body[1], body[2], body[3]],
            )
        })
        .collect()
}

fn spdp(prefix: u8, vendor_id: u16, caps: Option<u32>) -> SpdpData {
    SpdpData {
        participant_guid: GUID::new([prefix; 12], [0, 0, 1, 0xC1]),
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(vendor_id),
        hdds_capabilities: caps,
        builtin_endpoint_set: None,
    }
}

/// Registers a reader of `topic` at `dest` for the participant `prefix_byte`
/// announcing `vendor_id` with `caps`: a confirmed participant (two SPDPs),
/// one reader `DUST_READER_EID` (or the HDDS equivalent: the same entity id)
/// at `dest`, in both the FSM and the endpoint registry.
fn register_reader_of(
    fsm: &DiscoveryFsm,
    reg: &EndpointRegistry,
    topic: &str,
    prefix_byte: u8,
    dest: SocketAddr,
    vendor_id: u16,
    caps: Option<u32>,
) -> GUID {
    let participant_guid = GUID::new([prefix_byte; 12], [0, 0, 1, 0xC1]);
    fsm.handle_spdp(spdp(prefix_byte, vendor_id, caps));
    std::thread::sleep(Duration::from_millis(120));
    fsm.handle_spdp(spdp(prefix_byte, vendor_id, caps));
    let endpoint_guid = GUID::new([prefix_byte; 12], DUST_READER_EID);
    fsm.handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: "CoherentDisposeSample".to_string(),
        participant_guid,
        endpoint_guid,
        qos_hash: 0,
        qos: None,
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![dest],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: false,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
    reg.register_reader_locator(endpoint_guid, dest);
    reg.register(participant_guid, dest);
    endpoint_guid
}

fn register_dust_reader(
    fsm: &DiscoveryFsm,
    reg: &EndpointRegistry,
    topic: &str,
    prefix_byte: u8,
    dest: SocketAddr,
) -> GUID {
    register_reader_of(fsm, reg, topic, prefix_byte, dest, DUST_VENDOR_ID, None)
}

fn register_hdds_reader(
    fsm: &DiscoveryFsm,
    reg: &EndpointRegistry,
    topic: &str,
    prefix_byte: u8,
    dest: SocketAddr,
) -> GUID {
    register_reader_of(fsm, reg, topic, prefix_byte, dest, HDDS_VENDOR_ID_U16, None)
}

/// A discovery state knowing one Dust participant (SPDP only): enough for
/// the send paths' per-reader form, the repair entry points read the same.
fn dust_fsm(prefix_byte: u8) -> Arc<DiscoveryFsm> {
    let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
    fsm.handle_spdp(spdp(prefix_byte, DUST_VENDOR_ID, None));
    Arc::new(fsm)
}

fn tag(gsn: u64, set_first: u64) -> GroupTag {
    GroupTag {
        gsn,
        writer_set: [1, 2, 3, 4],
        set_first_gsn: Some(set_first),
        part_first_sn: None,
    }
}

/// The history of one GROUP coherent set, as the repair and replay paths
/// read it: two members (SN 1, 2) and the close (SN 3). The members carry the
/// set's coherent and GROUP PIDs in today's form.
fn group_set_cache() -> Arc<HistoryCache> {
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::new(SlabPool::new()),
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache.wire_windows.configure(true);
    let source = (100, 200);
    for (seq, value) in [(1u64, 0x61u64), (2, 0x62)] {
        cache
            .insert_grouped_until(
                seq,
                &[0, 0, 0, 0, 1, 2, 3, 4],
                value,
                ChangeMetadata {
                    kind: ChangeKind::UserData,
                    coherent_sn: Some(2),
                    group_sn: Some(seq),
                    key_hash: Some([0x9a; 16]),
                    source_ts: source,
                    source_ts_known: true,
                    ..ChangeMetadata::user_data()
                },
                Some(tag(seq, 1)),
                None,
            )
            .unwrap();
    }
    cache
        .insert_grouped_until(
            3,
            &[],
            0,
            ChangeMetadata {
                kind: ChangeKind::EcsClose,
                coherent_sn: Some(2),
                group_sn: Some(3),
                source_ts: source,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
            Some(tag(3, 1)),
            None,
        )
        .unwrap();
    cache
}

/// The history of one large GROUP member (SN 1, 20000 bytes, fragmented at
/// 4096), for the NACK_FRAG repair.
fn group_frag_cache() -> Arc<HistoryCache> {
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::new(SlabPool::new()),
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    cache.wire_windows.configure(true);
    cache
        .insert_grouped_until(
            1,
            &vec![0x5a; 20_000],
            0x71,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(1),
                group_sn: Some(1),
                frag_size: 4096,
                key_hash: Some([0x9a; 16]),
                source_ts: (100, 200),
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
            Some(tag(1, 1)),
            None,
        )
        .unwrap();
    cache
}

/// A DataWriter-free fixture transport on `domain_id`, port 40.
fn transport_on(domain_id: u32, participant: u8) -> Arc<UdpTransport> {
    let mapping = PortMapping::calculate(domain_id, participant).expect("port mapping");
    Arc::new(UdpTransport::new(domain_id, participant, mapping).expect("transport"))
}

/// The decision is taken once per participant, at its SPDP: a Dust peer is a
/// plain peer, an HDDS spec peer is not, and a GROUP change is kept off the
/// multicast fallback while a plain peer is known.
#[test]
fn the_plain_form_is_decided_per_participant_at_pairing() {
    let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
    fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
    fsm.handle_spdp(spdp(0x4b, DUST_VENDOR_ID, None));
    fsm.handle_spdp(spdp(
        0x4c,
        HDDS_VENDOR_ID_U16,
        Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
    ));
    assert!(
        fsm.speaks_plain_group(&[0x4b; 12]),
        "Dust reads per-writer sets: plain"
    );
    assert!(
        !fsm.speaks_spec_group(&[0x4b; 12]),
        "Dust is not a spec peer"
    );
    assert!(fsm.speaks_spec_group(&[0x4c; 12]), "the HDDS spec peer");
    assert!(
        !fsm.speaks_plain_group(&[0x4c; 12]),
        "an HDDS spec peer is not plain"
    );
    assert!(fsm.any_plain_group_peer());
    assert!(
        !multicasts(true, Some(&fsm)),
        "a GROUP change stays off multicast"
    );
    assert!(
        multicasts(false, Some(&fsm)),
        "a non-GROUP change is unaffected"
    );
}

/// Live path, through a real Participant publisher (so the bridge is wired to
/// the writer's endpoint and transport when it is built). One GROUP coherent
/// set of two members, then its end, with a Dust reader and an HDDS reader in
/// the same audience. The Dust reader gets plain members and one GAP covering
/// exactly the close SN, and no end-of-set DATA. The HDDS reader gets today's
/// member form and its close marker, and no GAP.
#[test]
fn a_group_publisher_closes_its_set_toward_a_dust_reader_with_a_gap_and_an_hdds_reader_with_its_marker(
) {
    let topic = "test/plain_live_close";
    let lease = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("plain-live-close")
        .domain_id(lease.id())
        .build()
        .expect("participant");
    let qos = QoS::reliable()
        .keep_all()
        .transient_local()
        .presentation(Presentation::group_coherent());
    let publisher = Arc::new(
        participant
            .create_publisher(qos.clone())
            .expect("publisher"),
    );
    let writer = participant
        .topic::<CoherentDisposeSample>(topic)
        .expect("topic")
        .writer()
        .qos(qos)
        .publisher(&publisher)
        .build()
        .expect("writer");
    let fsm = Arc::clone(writer.discovery_fsm.as_ref().expect("discovery"));
    let registry = writer.endpoint_registry.clone().expect("registry");
    let (dust, dust_addr) = bind_capture();
    register_dust_reader(&fsm, &registry, topic, 0x50, dust_addr);
    let (hdds, hdds_addr) = bind_capture();
    register_hdds_reader(&fsm, &registry, topic, 0x51, hdds_addr);

    publisher.begin_coherent_changes().expect("begin");
    writer
        .write(&CoherentDisposeSample { id: 3, v: 4 })
        .expect("write a");
    writer
        .write(&CoherentDisposeSample { id: 5, v: 6 })
        .expect("write b");
    publisher.end_coherent_changes().expect("end");

    let dust_subs = all_submessages(&drain(&dust));
    let members = assert_plain_members(&dust_subs);
    assert_eq!(members.len(), 2, "two plain members, no end-of-set DATA");
    let close = *members.iter().max().expect("members") + 1;
    let gaps = gaps_of(&dust_subs);
    assert_eq!(gaps.len(), 1, "one GAP, and only one");
    let (gap_start, gap_base, num_bits, reader) = gaps[0];
    assert_eq!(gap_start, close, "the GAP starts at the close SN");
    assert_eq!(gap_base, close + 1, "its list is based at close + 1");
    assert_eq!(num_bits, 0, "empty bitmap: the close SN alone");
    assert_eq!(reader, DUST_READER_EID, "addressed to the Dust reader");

    let hdds_subs = all_submessages(&drain(&hdds));
    let hdds_members: Vec<_> = hdds_subs
        .iter()
        .filter(|s| s.0 == 0x15 && s.1 & 0x04 != 0)
        .collect();
    assert_eq!(hdds_members.len(), 2, "the HDDS reader gets both members");
    for (_, _, body) in &hdds_members {
        let pids = inline_pids(body);
        for pid in [0x0056u16, 0x8030, 0x0053] {
            assert!(pids.contains_key(&pid), "HDDS member keeps {pid:#06x}");
        }
    }
    let markers: Vec<_> = hdds_subs
        .iter()
        .filter(|s| s.0 == 0x15 && s.1 & 0x04 == 0)
        .collect();
    assert_eq!(markers.len(), 1, "the HDDS reader gets its close marker");
    assert!(
        inline_pids(&markers[0].2).contains_key(&0x0056),
        "the close marker is the native ECS DATA"
    );
    assert!(
        gaps_of(&hdds_subs).iter().all(|g| g.0 != close),
        "no GAP for the close SN toward the HDDS reader"
    );
}

/// The send path of one write, against a plain peer learned after the plain
/// form was prepared: the form is built lazily by the first plain reader, so
/// the Dust reader still gets the plain form, the HDDS reader the legacy one,
/// and the builder runs exactly once.
#[test]
fn a_plain_peer_learned_after_the_form_was_prepared_still_gets_the_plain_form() {
    let topic = "test/plain_late_peer";
    let (_publisher, writer, hdds, registry, fsm, domain) =
        build_pair(topic, 54, PresentationAccessScope::Group, |qos| {
            qos.transient_local()
        });
    let transport = transport_on(domain.id(), 59);
    let ctx = writer_ctx();
    let version = ChangeMetadata::user_data().cdr_version;
    let payload = [0u8, 0, 0, 0, 1, 2, 3, 4];
    let legacy = builder::build_data_packet_grouped_ts(
        &ctx,
        topic,
        77,
        &payload,
        version,
        (100, 200),
        Some(5),
        Some(3),
        None,
        None,
        false,
    );
    let calls = std::cell::Cell::new(0u32);
    let build = || {
        calls.set(calls.get() + 1);
        builder::build_data_packet_grouped_ts(
            &ctx,
            topic,
            77,
            &payload,
            version,
            (100, 200),
            None,
            None,
            None,
            None,
            false,
        )
    };
    // The plain form is prepared here, with no plain peer known yet.
    let plain = LazyForm::new(&build);
    // The plain peer is learned only now, after the form was prepared.
    let (dust, dust_addr) = bind_capture();
    register_dust_reader(&fsm, &registry, topic, 0x52, dust_addr);
    writer
        .send_packet_to_endpoints_classed(&transport, &legacy, None, Some(&plain))
        .expect("send");

    assert_eq!(
        calls.get(),
        1,
        "the plain form is built once, by its reader"
    );
    let dust_subs = all_submessages(&drain(&dust));
    let dust_members = assert_plain_members(&dust_subs);
    assert_eq!(
        dust_members,
        vec![77],
        "the Dust reader got the plain member"
    );
    let hdds_subs = all_submessages(&drain(&hdds));
    let hdds_member = hdds_subs
        .iter()
        .find(|s| s.0 == 0x15)
        .expect("the HDDS reader got the legacy member");
    assert!(
        inline_pids(&hdds_member.2).contains_key(&0x0056),
        "the HDDS reader keeps the legacy 0x0056"
    );
}

/// The live close, through the bridge a GROUP writer's publisher ends its set
/// with, driven directly: a set of no member is closed toward a Dust reader by
/// one GAP that retires the close SN (the bridge's next SN), and no
/// end-of-set DATA.
#[test]
fn a_group_bridge_closes_a_set_toward_a_dust_reader_with_a_gap() {
    use super::coherent::WriterCoherentBridge;
    use crate::dds::publisher::CoherentWriter;
    use crate::dds::writer::intra_coherent::IntraCoherentSets;
    use crate::protocol::dialect::sequence_window::WriterWindows;
    use std::sync::atomic::AtomicU64;

    let topic = "test/plain_bridge";
    let lease = crate::test_support::domains::unique_domain();
    let transport = transport_on(lease.id(), 51);
    let (dust, dust_addr) = bind_capture();
    let mut local = [0u8; 16];
    local[..12].copy_from_slice(&super::coherent_dispose_tests::OUR_PREFIX);
    local[12..16].copy_from_slice(&[0, 0, 1, 0xC1]);
    let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
    fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
    let reg = EndpointRegistry::new();
    register_dust_reader(&fsm, &reg, topic, 0x4d, dust_addr);

    let windows = Arc::new(WriterWindows::default());
    windows.configure(true);
    let intra = Arc::new(IntraCoherentSets::new(
        "plain-bridge-test".to_string(),
        Arc::new(crate::core::rt::TopicMerger::new()),
        Duration::from_secs(5),
        true,
        None,
    ));
    let bridge = WriterCoherentBridge::new(
        topic.to_string(),
        Arc::new(AtomicU64::new(30)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        windows,
        Some(transport.clone()),
        Some(writer_ctx()),
        None,
        Some(reg),
        Some(fsm),
        None,
        intra,
    );
    bridge.emit_ecs_data(29, Some(3), None);

    let subs = all_submessages(&drain(&dust));
    assert!(
        subs.iter().all(|s| !(s.0 == 0x15 && s.1 & 0x04 == 0)),
        "no end-of-set DATA toward the Dust reader"
    );
    let gaps = gaps_of(&subs);
    assert_eq!(
        gaps,
        vec![(30, 31, 0, DUST_READER_EID)],
        "one GAP for the close SN"
    );
}

/// ACKNACK repair (`WriterNackHandler::on_nack`) of a GROUP set to a Dust
/// reader: the two members go out in the plain form and the close is a GAP.
#[test]
fn an_acknack_repair_to_a_dust_reader_is_the_plain_form() {
    let topic = "test/plain_acknack";
    let domain = crate::test_support::domains::unique_domain();
    let transport = transport_on(domain.id(), 55);
    let (dust, dust_addr) = bind_capture();
    let reader = GUID::new([0x55; 12], DUST_READER_EID);
    let fsm = dust_fsm(0x55);
    let reg = EndpointRegistry::new();
    reg.register_reader_locator(reader, dust_addr);
    reg.register(GUID::new([0x55; 12], [0, 0, 1, 0xC1]), dust_addr);
    let cache = group_set_cache();
    let handler = WriterNackHandler::new(
        topic.to_string(),
        cache,
        transport,
        Arc::new(ReliableMetrics::new()),
        RetransmitCfg {
            rtps_endpoint: Some(writer_ctx()),
            endpoint_registry: Some(reg),
            canonical_encapsulation_kind: 0x0007,
            ack_track: None,
            frag_route: Arc::new(FragRouteProfile::new(
                u16::try_from(builder::DEFAULT_FRAGMENT_SIZE).expect("fits u16"),
            )),
            discovery_fsm: Some(fsm),
        },
    );
    let mut reader_prefix = [0u8; 12];
    reader_prefix.copy_from_slice(&reader.as_bytes()[..12]);
    let acknack = builder::build_acknack_packet(
        reader_prefix,
        super::coherent_dispose_tests::OUR_PREFIX,
        DUST_READER_EID,
        super::coherent_dispose_tests::WRITER_EID,
        1,
        &[1, 2, 3],
        1,
    );
    handler.on_nack(&acknack, Some(reader.as_bytes()));

    let subs = all_submessages(&drain(&dust));
    let sns = assert_plain_members(&subs);
    assert!(
        sns.contains(&1) && sns.contains(&2),
        "both members repaired: {sns:?}"
    );
    assert_eq!(
        gaps_of(&subs).iter().map(|g| g.0).collect::<Vec<_>>(),
        vec![3],
        "the close is repaired as a GAP"
    );
}

/// NACK_FRAG repair (`WriterNackFragHandler::on_nack_frag`) of a fragmented
/// GROUP member to a Dust reader: the first fragment, which carries the inline
/// QoS, is in the plain form.
#[test]
fn a_nack_frag_repair_to_a_dust_reader_is_the_plain_form() {
    let topic = "test/plain_nack_frag";
    let domain = crate::test_support::domains::unique_domain();
    let transport = transport_on(domain.id(), 56);
    let (dust, dust_addr) = bind_capture();
    let reader = GUID::new([0x56; 12], DUST_READER_EID);
    let reg = EndpointRegistry::new();
    reg.register_reader_locator(reader, dust_addr);
    reg.register(GUID::new([0x56; 12], [0, 0, 1, 0xC1]), dust_addr);
    let handler = WriterNackFragHandler::new(
        topic.to_string(),
        group_frag_cache(),
        transport,
        Arc::new(ReliableMetrics::new()),
        super::coherent_dispose_tests::WRITER_EID,
        RetransmitCfg {
            rtps_endpoint: Some(writer_ctx()),
            endpoint_registry: Some(reg),
            canonical_encapsulation_kind: 0x0007,
            ack_track: None,
            frag_route: Arc::new(FragRouteProfile::new(
                u16::try_from(builder::DEFAULT_FRAGMENT_SIZE).expect("fits u16"),
            )),
            discovery_fsm: Some(dust_fsm(0x56)),
        },
    );
    handler.on_nack_frag(
        &super::coherent_dispose_tests::WRITER_EID,
        1,
        &[1],
        Some(reader.as_bytes()),
    );

    let subs = all_submessages(&drain(&dust));
    let frags: Vec<_> = subs.iter().filter(|s| s.0 == 0x16).collect();
    assert!(!frags.is_empty(), "the requested fragment was sent");
    let (_, flags, body) = frags[0];
    assert_ne!(flags & 0x02, 0, "the first fragment carries inline QoS");
    let pids = inline_pids(body);
    assert!(pids.contains_key(&0x0005), "PID_TOPIC_NAME kept");
    for pid in SET_PIDS {
        assert!(
            !pids.contains_key(&pid),
            "plain fragment carries no {pid:#06x}"
        );
    }
}

/// TRANSIENT_LOCAL replay (`WriterReplayState::replay_to`) of a GROUP set to a
/// late-joining Dust reader: the members go out in the plain form and the
/// close is a GAP.
#[test]
fn a_late_joining_dust_reader_replays_the_plain_form_and_a_gap_for_the_close() {
    let topic = "test/plain_replay";
    let domain = crate::test_support::domains::unique_domain();
    let transport = transport_on(domain.id(), 57);
    let (dust, dust_addr) = bind_capture();
    let reader = GUID::new([0x57; 12], DUST_READER_EID);
    let state = WriterReplayState::new(
        topic.to_string(),
        Some(writer_ctx()),
        transport,
        group_set_cache(),
        Some(dust_fsm(0x57)),
    );
    state.replay_to(dust_addr, Some(reader.as_bytes()));

    let subs = all_submessages(&drain(&dust));
    let sns = assert_plain_members(&subs);
    assert!(
        sns.contains(&1) && sns.contains(&2),
        "both members replayed: {sns:?}"
    );
    assert_eq!(
        gaps_of(&subs).iter().map(|g| g.0).collect::<Vec<_>>(),
        vec![3],
        "the close is replayed as a GAP"
    );
}

/// Fixed fixture for the golden checks, identical in the parent commit, where
/// the golden bytes were captured: a member, a dispose, a close and a
/// fragmented member, all in today's (legacy) form, with fixed source times.
fn golden_fixture() -> (builder::RtpsEndpointContext, Arc<HistoryCache>) {
    let ctx = builder::RtpsEndpointContext {
        guid_prefix: [0x44; 12],
        reader_entity_id: [0; 4],
        writer_entity_id: [0x00, 0x00, 0x20, 0x03],
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let cache = Arc::new(HistoryCache::new_with_limits(
        Arc::new(SlabPool::new()),
        16,
        256 * 1024,
        History::KeepLast(16),
    ));
    let source = (100, 200);
    cache
        .insert_grouped_until(
            7,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            0x55,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(5),
                group_sn: Some(3),
                key_hash: Some([0x9a; 16]),
                source_ts: source,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
            Some(tag(3, 2)),
            None,
        )
        .unwrap();
    cache
        .insert_grouped_until(
            8,
            &[9, 9, 9, 9],
            0x55,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                status_info: Some(builder::StatusInfoKind::Disposed),
                coherent_sn: Some(5),
                group_sn: Some(4),
                key_hash: Some([0x9a; 16]),
                source_ts: source,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
            Some(tag(4, 2)),
            None,
        )
        .unwrap();
    cache
        .insert_grouped_until(
            9,
            &[],
            0,
            ChangeMetadata {
                kind: ChangeKind::EcsClose,
                coherent_sn: Some(8),
                group_sn: Some(5),
                source_ts: source,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
            Some(tag(5, 2)),
            None,
        )
        .unwrap();
    cache
        .insert_grouped_until(
            10,
            &vec![0xab; 9000],
            0x66,
            ChangeMetadata {
                kind: ChangeKind::UserData,
                coherent_sn: Some(5),
                group_sn: Some(6),
                frag_size: 4096,
                key_hash: Some([0x9a; 16]),
                source_ts: source,
                source_ts_known: true,
                ..ChangeMetadata::user_data()
            },
            Some(tag(6, 2)),
            None,
        )
        .unwrap();
    (ctx, cache)
}

/// The legacy forms are byte-identical to what the legacy builders produced
/// before the plain-group emission existed: the golden bytes below were
/// generated from the same fixture by those builders, not by this code path.
#[test]
fn legacy_forms_are_byte_identical_to_the_golden_bytes() {
    let (ctx, cache) = golden_fixture();
    let topic = "golden/legacy";
    let member = cache.get_change(7).expect("member");
    let dispose = cache.get_change(8).expect("dispose");
    let close = cache.get_change(9).expect("close");
    let big = cache.get_change(10).expect("big");
    let reader = [0x00, 0x00, 0x20, 0x04];
    let legacy = GroupForm::Legacy;
    assert_eq!(
        hex(&super::nack::user_data_change_packet_form(
            ctx,
            topic,
            &member,
            (100, 200),
            legacy
        )),
        GOLDEN_USER_LEGACY,
        "member, legacy"
    );
    assert_eq!(
        hex(&super::nack::user_data_change_packet_form(
            ctx,
            topic,
            &member,
            (100, 200),
            GroupForm::Spec
        )),
        GOLDEN_USER_SPEC,
        "member, spec"
    );
    assert_eq!(
        hex(
            &super::nack::lifecycle_change_packet_form(Some(ctx), topic, &dispose, legacy)
                .expect("dispose")
        ),
        GOLDEN_LIFECYCLE_LEGACY,
        "dispose, legacy"
    );
    assert_eq!(
        hex(&super::nack::build_ecs_repair_packet_form(
            &ctx,
            topic,
            &close,
            reader,
            Some(HDDS_VENDOR_ID_U16),
            legacy
        )
        .expect("native close")),
        GOLDEN_ECS_NATIVE,
        "close, HDDS native"
    );
    assert_eq!(
        hex(&super::nack::build_ecs_repair_packet_form(
            &ctx,
            topic,
            &close,
            reader,
            Some(DUST_VENDOR_ID),
            legacy
        )
        .expect("classic close")),
        GOLDEN_ECS_CLASSIC,
        "close, classic bare marker"
    );
    let frags = super::nack::change_frag_packets_form(
        &ctx,
        topic,
        10,
        &big.payload,
        &big.metadata,
        big.group.as_ref(),
        4096,
        (100, 200),
        legacy,
    );
    let joined: Vec<u8> = frags.concat();
    assert_eq!(
        format!(
            "count={} len={} fnv={:016x}",
            frags.len(),
            joined.len(),
            fnv1a(&joined)
        ),
        GOLDEN_FRAGS_LEGACY,
        "fragmented member, legacy"
    );
}

// Golden bytes, generated by the legacy builders from `golden_fixture` (see `legacy_forms_are_byte_identical_to_the_golden_bytes`).
const GOLDEN_USER_LEGACY: &str = "525450530204011a4444444444444444444444440901080064000000c8000000150770000000100000000000000020030000000007000000050014000e000000676f6c64656e2f6c65676163790000005600080000000000050000003080080000000000030000005300040000000108700010009a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a01000000000700000102030405060708";
const GOLDEN_USER_SPEC: &str = "525450530204011a4444444444444444444444440901080064000000c800000015077c000000100000000000000020030000000007000000050014000e000000676f6c64656e2f6c65676163790000005600080000000000050000006300080000000000020000006400080000000000030000006500040001020304700010009a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a01000000000700000102030405060708";
const GOLDEN_LIFECYCLE_LEGACY: &str = "525450530204011a4444444444444444444444440901080064000000c8000000150b74000000100000000000000020030000000008000000050014000e000000676f6c64656e2f6c65676163790000005600080000000000050000003080080000000000040000005300040000000108700010009a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a7100040000000001010000000007000009090909";
const GOLDEN_ECS_NATIVE: &str = "525450530204011a4444444444444444444444440901080064000000c8000000150350000000100000002004000020030000000009000000050014000e000000676f6c64656e2f6c6567616379000000560008000000000008000000308008000000000005000000530004000000010801000000";
const GOLDEN_ECS_CLASSIC: &str = "525450530204011a4444444444444444444444440901080064000000c8000000150114000000100000002004000020030000000009000000";
const GOLDEN_FRAGS_LEGACY: &str = "count=3 len=9288 fnv=a3e3d460ce5d482f";

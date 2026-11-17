// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A dispose / unregister emitted while the writer's publisher has an open
//! coherent set must carry the same coherent-set PIDs a member sample
//! carries (RTPS v2.5 SS8.7.5/SS8.7.6, DDS v1.4 SS2.2.2.4.1.10/SS2.2.3.6): a
//! dispose is a CacheChange of the writer like any other (RTPS v2.5
//! SS8.2.3), and "a Data Submessage from this Writer that does not contain
//! a coherent set in-line QoS parameter" ends the set for a spec-strict
//! reader.
//!
//! These drive the REAL `DataWriter`/`Publisher` live path end to end
//! (`begin_coherent_changes` -> `write` -> `dispose` -> `end_coherent_changes`)
//! and decode the captured wire bytes BY HAND (not via our own extractor),
//! so a regression in either the writer or the inline-QoS layout fails a
//! test that does not share the bug.

use super::WriterBuilder;
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::{EndpointRegistry, GUID};
use crate::dds::qos::{Presentation, PresentationAccessScope};
use crate::dds::{Publisher, QoS};
use crate::protocol::builder::RtpsEndpointContext;
use crate::transport::{PortMapping, UdpTransport};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// `@final struct { @key id: u32; v: i32; }` -- a minimal keyed type, same
/// shape as `key_payload_tests::Keyed`.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
pub(super) struct CoherentDisposeSample {
    #[key]
    pub(super) id: u32,
    pub(super) v: i32,
}

pub(super) const OUR_PREFIX: [u8; 12] = [0x44; 12];
pub(super) const WRITER_EID: [u8; 4] = [0x00, 0x00, 0x20, 0x03];
const RTPS_ENTITYID_PARTICIPANT: [u8; 4] = [0x00, 0x00, 0x01, 0xC1];

/// Offset of the DATA submessage inside a captured packet: RTPS header
/// (20) + INFO_TS (12).
pub(super) const DATA_SUBMSG_OFFSET: usize = 32;

pub(super) fn writer_ctx() -> RtpsEndpointContext {
    RtpsEndpointContext {
        guid_prefix: OUR_PREFIX,
        reader_entity_id: [0; 4],
        writer_entity_id: WRITER_EID,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    }
}

pub(super) fn bind_capture() -> (std::net::UdpSocket, SocketAddr) {
    let sock = crate::test_support::ports::bind_capture_socket();
    sock.set_read_timeout(Some(Duration::from_millis(400)))
        .expect("set timeout");
    let addr = sock.local_addr().expect("capture addr");
    (sock, addr)
}

/// Drain every datagram currently queued on `sock` (short read timeout, so
/// this returns once nothing more arrives within it).
pub(super) fn drain(sock: &std::net::UdpSocket) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok((n, _)) = sock.recv_from(&mut buf) {
        packets.push(buf[..n].to_vec());
    }
    packets
}

/// Decode one DATA submessage's flags byte and its inline-QoS ParameterList,
/// walking the PIDs BY HAND -- not through `extract_inline_qos` or any other
/// of our own decoders, so a bug shared between the writer and our
/// extractor cannot hide from this test.
///
/// Layout (RTPS v2.5 SS9.4.2.11 / SS9.4.5.3.3), relative to `pkt`:
/// * `[0..20)` RTPS header, `[20..32)` INFO_TS (this test's packets always
///   carry one, matching `send_packet_to_endpoints`'s convention);
/// * `[32]` submessageId (0x15 for DATA), `[33]` flags, `[34..36)`
///   octetsToNextHeader;
/// * `[36..38)` extraFlags, `[38..40)` octetsToInlineQos;
/// * `[40..48)` reader+writer EntityId, `[48..56)` writerSN;
/// * inline QoS starts at `40 + octetsToInlineQos` (normally 16, so 56),
///   each parameter is `pid:u16 LE, len:u16 LE, value[len]`, terminated by
///   PID_SENTINEL (0x0001).
pub(super) fn decode_data_submsg(pkt: &[u8]) -> (u8, BTreeMap<u16, Vec<u8>>) {
    assert!(
        pkt.len() > DATA_SUBMSG_OFFSET + 4,
        "packet too short for a DATA submessage"
    );
    assert_eq!(
        pkt[DATA_SUBMSG_OFFSET], 0x15,
        "expected DATA submessage id 0x15"
    );
    let flags = pkt[DATA_SUBMSG_OFFSET + 1];
    let fixed_body = DATA_SUBMSG_OFFSET + 4; // past the 4-byte submsg header
    let oti = usize::from(u16::from_le_bytes([
        pkt[fixed_body + 2],
        pkt[fixed_body + 3],
    ]));
    let mut at = fixed_body + 4 + oti;
    let mut pids = BTreeMap::new();
    loop {
        let pid = u16::from_le_bytes([pkt[at], pkt[at + 1]]);
        let len = usize::from(u16::from_le_bytes([pkt[at + 2], pkt[at + 3]]));
        if pid == 0x0001 {
            break;
        }
        pids.insert(pid, pkt[at + 4..at + 4 + len].to_vec());
        at += 4 + len;
        assert!(at <= pkt.len(), "parameter list ran past the packet");
    }
    (flags, pids)
}

/// First captured packet whose DATA submessage has exactly `flags`.
fn find_by_flags(packets: &[Vec<u8>], flags: u8, what: &str) -> Vec<u8> {
    packets
        .iter()
        .find(|pkt| {
            pkt.len() > DATA_SUBMSG_OFFSET + 1
                && pkt[DATA_SUBMSG_OFFSET] == 0x15
                && pkt[DATA_SUBMSG_OFFSET + 1] == flags
        })
        .unwrap_or_else(|| {
            panic!(
                "no DATA submessage with flags {flags:#04x} ({what}) among {} captured packets",
                packets.len()
            )
        })
        .clone()
}

/// Build a Publisher + matched DataWriter<CoherentDisposeSample> pair with a
/// capture socket as the sole matched reader. `access_scope` selects
/// TOPIC vs GROUP; `durability` is passed through (Volatile needs the extra
/// confirmed-reader dance in `register_confirmed_reader`, done by the
/// caller before writing).
pub(super) fn build_pair(
    topic: &str,
    participant_id: u8,
    access_scope: PresentationAccessScope,
    qos_extra: impl FnOnce(QoS) -> QoS,
) -> (
    Arc<Publisher>,
    super::DataWriter<CoherentDisposeSample>,
    std::net::UdpSocket,
    EndpointRegistry,
    Arc<DiscoveryFsm>,
    // Held by the caller for as long as the transport lives.
    crate::test_support::domains::DomainLease,
) {
    build_pair_of::<CoherentDisposeSample>(topic, participant_id, access_scope, qos_extra)
}

type Pair<T> = (
    Arc<Publisher>,
    super::DataWriter<T>,
    std::net::UdpSocket,
    EndpointRegistry,
    Arc<DiscoveryFsm>,
    crate::test_support::domains::DomainLease,
);

/// `build_pair` for a writer of type `T`.
fn build_pair_of<T: crate::dds::DDS>(
    topic: &str,
    participant_id: u8,
    access_scope: PresentationAccessScope,
    qos_extra: impl FnOnce(QoS) -> QoS,
) -> Pair<T> {
    build_pair_with_confirmation(topic, participant_id, access_scope, qos_extra, true)
}

fn build_pair_with_confirmation<T: crate::dds::DDS>(
    topic: &str,
    participant_id: u8,
    access_scope: PresentationAccessScope,
    qos_extra: impl FnOnce(QoS) -> QoS,
    confirmed: bool,
) -> Pair<T> {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), participant_id).expect("port mapping");
    let transport =
        Arc::new(UdpTransport::new(lease.id(), participant_id, mapping).expect("transport"));

    let presentation = Presentation::new(access_scope, true, false);
    let publisher = Arc::new(Publisher::new(
        QoS {
            presentation,
            ..QoS::default()
        },
        None,
        None,
        None,
    ));

    let (capture, capture_addr) = bind_capture();
    let registry = EndpointRegistry::new();

    let mut local = [0u8; 16];
    local[..12].copy_from_slice(&OUR_PREFIX);
    local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
    let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
    // This participant speaks the spec GROUP dialect.
    fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);

    let base_qos =
        QoS::reliable()
            .keep_all()
            .presentation(Presentation::new(access_scope, true, false));
    let qos = qos_extra(base_qos);

    let mut writer = WriterBuilder::<T>::new(topic.to_string())
        .qos(qos)
        .with_transport(transport)
        .with_endpoint_registry(registry.clone())
        .with_discovery_fsm(Arc::clone(&fsm))
        .publisher(&publisher)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(writer_ctx());

    // DATA and ECS resolve the same discovered reader and user-data locator.
    register_reader(&fsm, &registry, topic, 0x46, capture_addr, None, confirmed);

    (publisher, writer, capture, registry, fsm, lease)
}

/// `build_pair_of` with no reader registered: a writer whose discovery
/// knows no reader of its topic.
#[allow(clippy::type_complexity)]
fn build_writer_of<T: crate::dds::DDS>(
    topic: &str,
    participant_id: u8,
    access_scope: PresentationAccessScope,
) -> (
    Arc<Publisher>,
    super::DataWriter<T>,
    EndpointRegistry,
    Arc<DiscoveryFsm>,
    crate::test_support::domains::DomainLease,
) {
    let lease = crate::test_support::domains::unique_domain();
    let mapping = PortMapping::calculate(lease.id(), participant_id).expect("port mapping");
    let transport =
        Arc::new(UdpTransport::new(lease.id(), participant_id, mapping).expect("transport"));
    let presentation = Presentation::new(access_scope, true, false);
    let publisher = Arc::new(Publisher::new(
        QoS {
            presentation,
            ..QoS::default()
        },
        None,
        None,
        None,
    ));
    let registry = EndpointRegistry::new();
    let mut local = [0u8; 16];
    local[..12].copy_from_slice(&OUR_PREFIX);
    local[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
    let fsm = Arc::new(DiscoveryFsm::new(GUID::from_bytes(local), 100_000));
    fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
    let qos = QoS::reliable()
        .keep_all()
        .transient_local()
        .presentation(presentation);
    let mut writer = WriterBuilder::<T>::new(topic.to_string())
        .qos(qos)
        .with_transport(transport)
        .with_endpoint_registry(registry.clone())
        .with_discovery_fsm(Arc::clone(&fsm))
        .publisher(&publisher)
        .build()
        .expect("writer build");
    writer.rtps_endpoint = Some(writer_ctx());
    (publisher, writer, registry, fsm, lease)
}

/// A participant `prefix_byte` discovered (SPDP), announcing `caps`, its
/// default locator `dest`, none of its readers known yet.
fn register_participant(
    fsm: &DiscoveryFsm,
    reg: &EndpointRegistry,
    prefix_byte: u8,
    dest: SocketAddr,
    caps: Option<u32>,
) {
    let mut pguid = [prefix_byte; 16];
    pguid[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
    let participant_guid = GUID::from_bytes(pguid);
    fsm.handle_spdp(crate::protocol::discovery::SpdpData {
        participant_guid,
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
        hdds_capabilities: caps,
        builtin_endpoint_set: None,
    });
    reg.register(participant_guid, dest);
}

/// Register a discovered reader with a confirmed participant and a user-data
/// locator. Returns the reader's endpoint GUID.
fn register_confirmed_reader(
    fsm: &DiscoveryFsm,
    reg: &EndpointRegistry,
    topic: &str,
    prefix_byte: u8,
    dest: SocketAddr,
    hdds_capabilities: Option<u32>,
) -> GUID {
    register_reader(fsm, reg, topic, prefix_byte, dest, hdds_capabilities, true)
}

fn register_reader(
    fsm: &DiscoveryFsm,
    reg: &EndpointRegistry,
    topic: &str,
    prefix_byte: u8,
    dest: SocketAddr,
    hdds_capabilities: Option<u32>,
    confirmed: bool,
) -> GUID {
    let mut pguid = [prefix_byte; 16];
    pguid[12..16].copy_from_slice(&RTPS_ENTITYID_PARTICIPANT);
    let participant_guid = GUID::from_bytes(pguid);
    let spdp = || crate::protocol::discovery::SpdpData {
        participant_guid,
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
        hdds_capabilities,
        builtin_endpoint_set: None,
    };
    // Two counted SPDPs confirm the participant alive -- but `refresh()`
    // only counts a second SPDP at least `PROBATION_WINDOW_MS` (100 ms)
    // after the entry was created (`ParticipantInfo::is_confirmed_alive`
    // doc), so a back-to-back pair within that window is a "stale burst"
    // and does NOT confirm it.
    fsm.handle_spdp(spdp());
    if confirmed {
        std::thread::sleep(Duration::from_millis(120));
        fsm.handle_spdp(spdp());
    }

    let mut rguid = [prefix_byte; 16];
    rguid[12..16].copy_from_slice(&[0x00, 0x00, 0x20, 0x04]);
    let endpoint_guid = GUID::from_bytes(rguid);
    fsm.handle_sedp(crate::protocol::discovery::SedpData {
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
    // `send_packet_to_endpoints` short-circuits to multicast when
    // `registry.is_empty()`, which tracks ONLY the participant-level map
    // populated by `register()` (the production SPDP handler populates
    // this too, outside this unit test's scope) -- `register_reader_locator`
    // alone leaves it looking empty.
    reg.register(participant_guid, dest);
    assert_eq!(
        fsm.is_endpoint_participant_confirmed(&endpoint_guid),
        confirmed,
        "test setup: the participant confirmation must match the requested state"
    );
    endpoint_guid
}

// PIDs decoded by hand against the spec, not imported from our own builder
// or extractor constants.
const PID_TOPIC_NAME: u16 = 0x0005;
const PID_COHERENT_SET: u16 = 0x0056;
const PID_GROUP_COHERENT_SET_HDDS: u16 = 0x8030;
const PID_GROUP_ENTITY_ID: u16 = 0x0053;
const PID_KEY_HASH: u16 = 0x0070;
pub(super) const PID_STATUS_INFO: u16 = 0x0071;

/// A dispose/unregister written inside a TOPIC-scope coherent set must
/// carry PID_COHERENT_SET = the set's first SN (the sample's SN, since the
/// sample opens the set).
///
/// Also proves the set-close-after-dispose requirement at the state level:
/// `DataWriter::last_sn_in_active_set` is the exact `Arc<AtomicU64>` the
/// coherent-set bridge drains (`take_last_sn_in_active_set`, swap-to-0) at
/// `Publisher::end_coherent_changes` to build the ECS close marker's
/// `PID_COHERENT_SET`; reading it right after `dispose()` (before `end`
/// drains it) is the authoritative value the wire close marker would carry
/// -- RTPS v2.5 SS8.7.5 defines the marker's PID_COHERENT_SET as the
/// writer's LAST sample SN in the set, so a set whose last change is a
/// dispose must close with the DISPOSE's SN, not the sample's. (The actual
/// wire send of the ECS marker goes through `WriterCoherentBridge`, whose
/// `rtps_endpoint` is captured once at `WriterBuilder::build()` time from a
/// real `Participant`; this test's writer has none, so the marker itself
/// cannot reach the capture socket here -- the direct DATA/dispose sends
/// below read `self.rtps_endpoint` live and are unaffected.)
#[test]
fn dispose_inside_topic_scope_coherent_set_carries_coherent_set_tag() {
    let topic = "test/coherent_dispose_topic";
    let (publisher, writer, capture, _reg, _fsm, _domain) = build_pair(
        topic,
        40,
        PresentationAccessScope::Topic,
        |qos| qos.transient_local(), // non-VOLATILE: never pre-confirmation-suppressed
    );

    publisher.begin_coherent_changes().expect("begin");
    let sample = CoherentDisposeSample { id: 1, v: 2 };
    let sample_seq = writer.next_seq.load(std::sync::atomic::Ordering::Relaxed);
    writer.write(&sample).expect("write");
    let dispose_seq = writer.next_seq.load(std::sync::atomic::Ordering::Relaxed);
    writer.dispose(&sample).expect("dispose");
    assert_eq!(dispose_seq, sample_seq + 1, "dispose takes the next SN");
    assert_eq!(
        writer
            .last_sn_in_active_set
            .load(std::sync::atomic::Ordering::Acquire),
        dispose_seq,
        "the set's last-SN bookkeeping must be the DISPOSE's SN, not the \
         sample's: the ECS close marker built from this value must close \
         the set AFTER the dispose"
    );
    publisher.end_coherent_changes().expect("end");

    let packets = drain(&capture);

    // The member sample (D=1): PID_COHERENT_SET = its own SN (it opened
    // the set).
    let data_pkt = find_by_flags(&packets, 0x07, "member DATA");
    let (_, data_pids) = decode_data_submsg(&data_pkt);
    assert!(data_pids.contains_key(&PID_TOPIC_NAME));
    let coherent_set_on_sample = data_pids
        .get(&PID_COHERENT_SET)
        .expect("member sample must carry PID_COHERENT_SET");
    assert_eq!(
        u64::from(u32::from_le_bytes(
            coherent_set_on_sample[4..8].try_into().unwrap()
        )),
        sample_seq,
        "PID_COHERENT_SET on the opening sample must be its own SN"
    );

    // The dispose (K=1): PID_COHERENT_SET = the SAME first SN (the sample's,
    // NOT the dispose's own) -- RTPS v2.5 SS8.7.5/SS8.7.6, this is the
    // conformance defect this change fixes.
    let dispose_pkt = find_by_flags(&packets, 0x0B, "dispose");
    let (_, dispose_pids) = decode_data_submsg(&dispose_pkt);
    assert!(
        dispose_pids.contains_key(&PID_TOPIC_NAME),
        "dispose must carry PID_TOPIC_NAME"
    );
    assert!(
        !dispose_pids.contains_key(&PID_GROUP_COHERENT_SET_HDDS),
        "TOPIC scope must not carry the GROUP PID"
    );
    assert!(
        !dispose_pids.contains_key(&PID_GROUP_ENTITY_ID),
        "TOPIC scope must not carry PID_GROUP_ENTITY_ID"
    );
    let coherent_set_on_dispose = dispose_pids
        .get(&PID_COHERENT_SET)
        .expect("dispose inside a coherent set must carry PID_COHERENT_SET");
    assert_eq!(
        u64::from(u32::from_le_bytes(
            coherent_set_on_dispose[4..8].try_into().unwrap()
        )),
        sample_seq,
        "PID_COHERENT_SET on the dispose must be the SET'S FIRST SN, same as the sample"
    );
    let key_hash = dispose_pids
        .get(&PID_KEY_HASH)
        .expect("dispose must carry PID_KEY_HASH");
    assert_eq!(key_hash.len(), 16);
    let status = dispose_pids
        .get(&PID_STATUS_INFO)
        .expect("dispose must carry PID_STATUS_INFO");
    assert_eq!(
        status[3], 0x01,
        "StatusInfo_t octet 3 must report Disposed (big-endian layout)"
    );
}

/// GROUP-scope variant: the dispose must ALSO carry PID_GROUP_COHERENT_SET_HDDS
/// (0x8030) and PID_GROUP_ENTITY_ID (0x0053), exactly as a GROUP-scope
/// member sample does.
#[test]
fn dispose_inside_group_scope_coherent_set_carries_group_tags() {
    let topic = "test/coherent_dispose_group";
    let (publisher, writer, capture, _reg, _fsm, _domain) =
        build_pair(topic, 41, PresentationAccessScope::Group, |qos| {
            qos.transient_local()
        });

    publisher.begin_coherent_changes().expect("begin");
    let sample = CoherentDisposeSample { id: 1, v: 2 };
    writer.write(&sample).expect("write");
    writer.dispose(&sample).expect("dispose");
    publisher.end_coherent_changes().expect("end");

    let packets = drain(&capture);
    let dispose_pkt = find_by_flags(&packets, 0x0B, "dispose");
    let (_, dispose_pids) = decode_data_submsg(&dispose_pkt);

    assert!(
        dispose_pids.contains_key(&PID_COHERENT_SET),
        "GROUP-scope dispose must still carry PID_COHERENT_SET"
    );
    let group_set = dispose_pids
        .get(&PID_GROUP_COHERENT_SET_HDDS)
        .expect("GROUP-scope dispose must carry PID_GROUP_COHERENT_SET_HDDS (0x8030)");
    assert_eq!(group_set.len(), 8, "SequenceNumber_t value is 8 octets");
    let group_entity_id = dispose_pids
        .get(&PID_GROUP_ENTITY_ID)
        .expect("GROUP-scope dispose must carry PID_GROUP_ENTITY_ID (0x0053)");
    assert_eq!(
        group_entity_id,
        &vec![0x00, 0x00, 0x01, 0x08],
        "PID_GROUP_ENTITY_ID payload must be the pinned Publisher Group EntityId"
    );
}

/// A dispose with NO open coherent set (no `begin_coherent_changes` call)
/// must carry no coherent PID at all -- the pre-existing, untagged form is
/// unchanged.
#[test]
fn dispose_outside_any_coherent_set_carries_no_coherent_pid() {
    let topic = "test/coherent_dispose_none";
    let (_publisher, writer, capture, _reg, _fsm, _domain) =
        build_pair(topic, 42, PresentationAccessScope::Topic, |qos| {
            qos.transient_local()
        });

    let sample = CoherentDisposeSample { id: 1, v: 2 };
    writer.write(&sample).expect("write");
    writer.dispose(&sample).expect("dispose");

    let packets = drain(&capture);
    let dispose_pkt = find_by_flags(&packets, 0x0B, "dispose");
    let (_, dispose_pids) = decode_data_submsg(&dispose_pkt);
    assert!(
        !dispose_pids.contains_key(&PID_COHERENT_SET),
        "a dispose outside any coherent set must carry no PID_COHERENT_SET"
    );
    assert!(!dispose_pids.contains_key(&PID_GROUP_COHERENT_SET_HDDS));
    assert!(!dispose_pids.contains_key(&PID_GROUP_ENTITY_ID));
}

/// A VOLATILE coherent writer's dispose is persisted in the history with
/// its coherent markers; a NACK repair of it
/// (`nack::lifecycle_change_packet`) must reproduce the live bytes exactly,
/// INFO_TS included (the journaled `source_ts` is replayed, not
/// re-stamped).
#[test]
fn nack_repair_of_a_volatile_coherent_dispose_reproduces_the_live_bytes() {
    let topic = "test/coherent_dispose_volatile_repair";
    let (publisher, writer, capture, _reg, _fsm, _domain) =
        build_pair(topic, 43, PresentationAccessScope::Topic, |qos| {
            qos.volatile()
        });

    publisher.begin_coherent_changes().expect("begin");
    let sample = CoherentDisposeSample { id: 7, v: 9 };
    writer.write(&sample).expect("write");
    let dispose_seq = writer.next_seq.load(std::sync::atomic::Ordering::Relaxed);
    writer.dispose(&sample).expect("dispose");
    // Simulate the matched reader's ACKNACK up through the sample (the
    // dispose itself, SN `dispose_seq`, stays un-acknowledged): without
    // this, `acked_floor` sits at its build-time `u64::MAX` ("no reliable
    // reader has acknowledged anything yet") for the rest of the test, and
    // `HistoryCache::admit`'s VOLATILE policy ("owes nothing every reader
    // already holds", RTPS v2.5 Sec.8.4.1 step 22) discards EVERY entry at
    // or below that floor before each insert -- which also runs for
    // `end_coherent_changes`'s own ECS-close insert below. A real matched
    // reader would have acknowledged the sample long before disposing it.
    writer
        .history_cache
        .as_ref()
        .expect("RELIABLE writer keeps a history cache")
        .set_acked_floor(dispose_seq.saturating_sub(1));
    publisher.end_coherent_changes().expect("end");

    let packets = drain(&capture);
    let live_dispose = find_by_flags(&packets, 0x0B, "VOLATILE coherent dispose");
    let (_, live_pids) = decode_data_submsg(&live_dispose);
    assert!(
        live_pids.contains_key(&PID_COHERENT_SET),
        "the confirmed-reader dance must have let the coherent dispose reach the wire"
    );

    let cache = writer
        .history_cache
        .clone()
        .expect("RELIABLE writer keeps a history cache");
    let change = cache
        .get_change(dispose_seq)
        .expect("the dispose must be journaled");
    assert!(
        change.metadata.coherent_sn.is_some(),
        "a VOLATILE writer must persist the coherent marker on its cached lifecycle change"
    );

    let repaired = super::nack::lifecycle_change_packet(Some(writer_ctx()), topic, &change, false)
        .expect("a lifecycle change rebuilds to a packet");

    // Compare DATA submessages (strip the leading RTPS header + INFO_TS,
    // both derived from the SAME journaled source_ts, so they must match
    // too) with the readerEntityId field masked on both: the live leg had
    // `send_packet_to_endpoints`'s per-reader patch applied (writer_ctx()'s
    // placeholder [0,0,0,0] rewritten to the confirmed reader's entity id)
    // -- the SAME patch a real NACK retransmit of `repaired` would also get
    // before hitting the wire, and orthogonal to what this test is
    // checking: that the coherent-tagged inline QoS and K-payload the repair
    // builder produces are byte-identical to the live emission.
    let mut repaired_masked = repaired[DATA_SUBMSG_OFFSET..].to_vec();
    let mut live_masked = live_dispose[DATA_SUBMSG_OFFSET..].to_vec();
    const READER_EID_REL_OFFSET: usize = 8; // relative to the DATA submsg start
    for buf in [&mut repaired_masked, &mut live_masked] {
        buf[READER_EID_REL_OFFSET..READER_EID_REL_OFFSET + 4].copy_from_slice(&[0, 0, 0, 0]);
    }
    assert_eq!(
        repaired_masked, live_masked,
        "a NACK repair of a tagged VOLATILE coherent dispose must reproduce \
         the live wire bytes exactly (modulo the per-reader readerEntityId patch)"
    );
}

/// The SequenceNumber_t value of a PID, decoded by hand: high (i32) then
/// low (u32), little-endian (the DATA's E flag is set).
fn seq_of(value: &[u8]) -> u64 {
    let high = u32::from_le_bytes(value[0..4].try_into().expect("high"));
    let low = u32::from_le_bytes(value[4..8].try_into().expect("low"));
    (u64::from(high) << 32) | u64::from(low)
}

/// A durable (TRANSIENT_LOCAL) writer's coherent set, repaired to a live
/// reader that NACKed it: each repaired member, sample or dispose, carries
/// the set it was written in (PID_COHERENT_SET = the set's first SN), as
/// its live emission did, byte for byte but the per-reader readerEntityId.
/// Untagged, the repaired member ended the set at a spec reader (DDSI-RTPS
/// 2.5 8.7.6) and the set's later members started nothing.
#[test]
fn nack_repair_of_a_durable_coherent_member_carries_its_set() {
    let topic = "test/coherent_durable_repair";
    let (publisher, writer, capture, _reg, _fsm, _domain) =
        build_pair(topic, 44, PresentationAccessScope::Topic, |qos| {
            qos.transient_local()
        });
    let first = writer.next_seq.load(std::sync::atomic::Ordering::Relaxed);
    publisher.begin_coherent_changes().expect("begin");
    let a = CoherentDisposeSample { id: 1, v: 2 };
    let b = CoherentDisposeSample { id: 2, v: 3 };
    writer.write(&a).expect("write a");
    writer.write(&b).expect("write b");
    writer.dispose(&a).expect("dispose a");
    publisher.end_coherent_changes().expect("end");
    let packets = drain(&capture);
    let cache = writer
        .history_cache
        .clone()
        .expect("RELIABLE writer keeps a history cache");
    let live_of = |seq: u64| {
        packets
            .iter()
            .find(|pkt| {
                pkt.len() > DATA_SUBMSG_OFFSET + 24
                    && pkt[DATA_SUBMSG_OFFSET] == 0x15
                    && seq_of(&pkt[DATA_SUBMSG_OFFSET + 16..DATA_SUBMSG_OFFSET + 24]) == seq
            })
            .unwrap_or_else(|| panic!("live DATA of seq {seq}"))
            .clone()
    };
    for seq in first..first + 3 {
        let change = cache.get_change(seq).expect("journaled");
        let source_ts = change.metadata.source_ts;
        let repaired =
            match super::nack::lifecycle_change_packet(Some(writer_ctx()), topic, &change, false) {
                Some(packet) => packet,
                None => super::nack::user_data_change_packet(
                    writer_ctx(),
                    topic,
                    &change,
                    source_ts,
                    false,
                ),
            };
        let (_, pids) = decode_data_submsg(&repaired);
        let set = pids
            .get(&PID_COHERENT_SET)
            .unwrap_or_else(|| panic!("repaired seq {seq} must carry PID_COHERENT_SET"));
        assert_eq!(seq_of(set), first, "seq {seq}: the set's first SN");
        let live = live_of(seq);
        let mut repaired_masked = repaired[DATA_SUBMSG_OFFSET..].to_vec();
        let mut live_masked = live[DATA_SUBMSG_OFFSET..].to_vec();
        for buf in [&mut repaired_masked, &mut live_masked] {
            buf[8..12].copy_from_slice(&[0, 0, 0, 0]);
        }
        assert_eq!(
            repaired_masked, live_masked,
            "seq {seq}: repair = live emission"
        );
    }
}

/// GROUP scope: a repaired member of a durable writer's group set carries
/// the group set PID (0x8030) and the Publisher's group entity id, as live.
#[test]
fn nack_repair_of_a_durable_group_member_carries_its_group_set() {
    let topic = "test/coherent_durable_group_repair";
    let (publisher, writer, _capture, _reg, _fsm, _domain) =
        build_pair(topic, 45, PresentationAccessScope::Group, |qos| {
            qos.transient_local()
        });
    let first = writer.next_seq.load(std::sync::atomic::Ordering::Relaxed);
    publisher.begin_coherent_changes().expect("begin");
    let a = CoherentDisposeSample { id: 1, v: 2 };
    writer.write(&a).expect("write");
    writer.dispose(&a).expect("dispose");
    publisher.end_coherent_changes().expect("end");
    let cache = writer.history_cache.clone().expect("history");
    let sample = cache.get_change(first).expect("sample journaled");
    let dispose = cache.get_change(first + 1).expect("dispose journaled");
    let repaired = [
        super::nack::user_data_change_packet(
            writer_ctx(),
            topic,
            &sample,
            sample.metadata.source_ts,
            false,
        ),
        super::nack::lifecycle_change_packet(Some(writer_ctx()), topic, &dispose, false)
            .expect("a lifecycle change"),
    ];
    for packet in &repaired {
        let (_, pids) = decode_data_submsg(packet);
        assert_eq!(seq_of(&pids[&PID_COHERENT_SET]), first);
        assert_eq!(pids[&PID_GROUP_COHERENT_SET_HDDS].len(), 8);
        assert_eq!(pids[&PID_GROUP_ENTITY_ID], vec![0x00, 0x00, 0x01, 0x08]);
    }
}

/// A change written outside any set journals no coherent marker: its repair
/// is the plain one, whatever the durability.
#[test]
fn nack_repair_of_a_change_outside_any_set_carries_no_coherent_pid() {
    let topic = "test/coherent_durable_plain_repair";
    let (_publisher, writer, _capture, _reg, _fsm, _domain) =
        build_pair(topic, 46, PresentationAccessScope::Topic, |qos| {
            qos.transient_local()
        });
    let first = writer.next_seq.load(std::sync::atomic::Ordering::Relaxed);
    let a = CoherentDisposeSample { id: 1, v: 2 };
    writer.write(&a).expect("write");
    writer.dispose(&a).expect("dispose");
    let cache = writer.history_cache.clone().expect("history");
    for seq in first..first + 2 {
        let change = cache.get_change(seq).expect("journaled");
        assert_eq!(change.metadata.coherent_sn, None);
        assert_eq!(change.metadata.group_sn, None);
    }
}

/// A GROUP Publisher's writer facing a reader of the spec class and a
/// legacy HDDS reader: each decodes its own form, one DATA each per
/// change. The spec reader's carries the change's GSN, the writerSet and
/// the set's first GSN in the standard PIDs (0x0064, 0x0065, 0x0063, RTPS
/// v2.5 Sec.9.6.4.3-5) and no vendor 0x8030; the legacy reader's is today's
/// form, 0x8030 and none of the standard group PIDs. Decoded by hand.
#[test]
fn a_group_writer_sends_each_reader_class_its_own_form() {
    let topic = "test/group_classes_live";
    let (publisher, writer, legacy, registry, fsm, _domain) =
        build_pair(topic, 47, PresentationAccessScope::Group, |qos| {
            qos.transient_local()
        });
    let (spec, spec_addr) = bind_capture();
    register_confirmed_reader(
        &fsm,
        &registry,
        topic,
        0x47,
        spec_addr,
        Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
    );
    publisher.begin_coherent_changes().expect("begin");
    let sample = CoherentDisposeSample { id: 3, v: 4 };
    writer.write(&sample).expect("write");
    writer.dispose(&sample).expect("dispose");
    publisher.end_coherent_changes().expect("end");
    let (spec_packets, legacy_packets) = (drain(&spec), drain(&legacy));
    // The writer joined its Publisher before its RTPS context was set by
    // this harness: its roster entry is the unknown id.
    let writer_set = crate::protocol::group::group_digest([[0u8; 4]]);
    let sn = |value: &[u8]| {
        (u64::from(u32::from_le_bytes(value[0..4].try_into().unwrap())) << 32)
            | u64::from(u32::from_le_bytes(value[4..8].try_into().unwrap()))
    };
    for (flags, gsn) in [(0x07, 1u64), (0x0B, 2u64)] {
        let pkt = find_by_flags(&spec_packets, flags, "spec form");
        let (_, pids) = decode_data_submsg(&pkt);
        assert_eq!(sn(&pids[&0x0064]), gsn, "PID_GROUP_SEQ_NUM");
        assert_eq!(pids.get(&0x0065), Some(&writer_set.to_vec()), "writerSet");
        assert_eq!(
            sn(&pids[&0x0063]),
            1,
            "PID_GROUP_COHERENT_SET: the set's first GSN"
        );
        assert!(
            !pids.contains_key(&PID_GROUP_COHERENT_SET_HDDS),
            "no vendor 0x8030"
        );
        assert!(
            !pids.contains_key(&0x0053),
            "no PID_GROUP_ENTITY_ID: an SEDP parameter (G11)"
        );
        let pkt = find_by_flags(&legacy_packets, flags, "legacy form");
        let (_, pids) = decode_data_submsg(&pkt);
        assert!(
            pids.contains_key(&PID_GROUP_COHERENT_SET_HDDS),
            "today's 0x8030"
        );
        assert!(pids.contains_key(&0x0053), "today's PID_GROUP_ENTITY_ID");
        for pid in [0x0063u16, 0x0064, 0x0065] {
            assert!(
                !pids.contains_key(&pid),
                "legacy form carries no {pid:#06x}"
            );
        }
    }
    for packets in [&spec_packets, &legacy_packets] {
        let data = packets
            .iter()
            .filter(|p| p.len() > DATA_SUBMSG_OFFSET && p[DATA_SUBMSG_OFFSET] == 0x15)
            .count();
        assert_eq!(data, 2, "one DATA per change for each reader");
    }
}

/// A uniform audience of legacy readers gets today's bytes, exactly.
#[test]
fn a_group_writers_legacy_audience_gets_todays_form() {
    let topic = "test/group_classes_legacy";
    let (_publisher, writer, legacy, _registry, _fsm, _domain) =
        build_pair(topic, 48, PresentationAccessScope::Group, |qos| {
            qos.transient_local()
        });
    let sample = CoherentDisposeSample { id: 3, v: 4 };
    writer.write(&sample).expect("write");
    let packets = drain(&legacy);
    let pkt = find_by_flags(&packets, 0x07, "today's form");
    let (_, pids) = decode_data_submsg(&pkt);
    for pid in [0x0063u16, 0x0064, 0x0065] {
        assert!(!pids.contains_key(&pid), "no {pid:#06x}");
    }
}

/// The HEARTBEATs `packets` carry, as (flags, body).
pub(super) fn heartbeats_of(packets: &[Vec<u8>]) -> Vec<(u8, Vec<u8>)> {
    packets
        .iter()
        .filter(|p| p.len() > 24 && p[20] == 0x07)
        .map(|p| (p[21], p[24..].to_vec()))
        .collect()
}

/// A GROUP Publisher's writer's HEARTBEAT carries its GroupInfo, with the
/// G flag (RTPS v2.5 Sec.9.4.5.7), to readers of the spec class only: the
/// legacy reader gets today's 28-octet body.
#[test]
fn a_group_writers_heartbeat_carries_its_group_info_to_spec_readers_only() {
    let topic = "test/group_heartbeat_classes";
    let (_publisher, writer, legacy, registry, fsm, _domain) =
        build_pair(topic, 49, PresentationAccessScope::Group, |qos| {
            qos.transient_local()
        });
    let (spec, spec_addr) = bind_capture();
    register_confirmed_reader(
        &fsm,
        &registry,
        topic,
        0x49,
        spec_addr,
        Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
    );
    writer
        .write(&CoherentDisposeSample { id: 1, v: 1 })
        .expect("write");
    let spec_hbs = heartbeats_of(&drain(&spec));
    let legacy_hbs = heartbeats_of(&drain(&legacy));
    assert!(!spec_hbs.is_empty(), "the write sends a HEARTBEAT");
    for (flags, body) in &spec_hbs {
        assert_eq!(flags & 0x08, 0x08, "G for the spec reader");
        assert_eq!(body.len(), 28 + 24);
        let sn_at = |at: usize| {
            (u64::from(u32::from_le_bytes(body[at..at + 4].try_into().unwrap())) << 32)
                | u64::from(u32::from_le_bytes(body[at + 4..at + 8].try_into().unwrap()))
        };
        assert_eq!((sn_at(8), sn_at(16)), (1, 1), "firstSN, lastSN");
        assert_eq!(
            (sn_at(28), sn_at(36), sn_at(44)),
            (1, 1, 1),
            "currentGSN, firstGSN, lastGSN of the one change"
        );
    }
    assert_eq!(legacy_hbs.len(), spec_hbs.len(), "one HEARTBEAT each");
    for (flags, body) in &legacy_hbs {
        assert_eq!(flags & 0x08, 0, "no G for the legacy reader");
        assert_eq!(body.len(), 28);
    }
}

/// A writer outside GROUP access_scope sends no GroupInfo, even to a
/// reader of the spec class.
#[test]
fn a_topic_writers_heartbeat_has_no_group_info() {
    let topic = "test/topic_heartbeat_plain";
    let (_publisher, writer, _legacy, registry, fsm, _domain) =
        build_pair(topic, 50, PresentationAccessScope::Topic, |qos| {
            qos.transient_local()
        });
    let (spec, spec_addr) = bind_capture();
    register_confirmed_reader(
        &fsm,
        &registry,
        topic,
        0x50,
        spec_addr,
        Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
    );
    writer
        .write(&CoherentDisposeSample { id: 1, v: 1 })
        .expect("write");
    let hbs = heartbeats_of(&drain(&spec));
    assert!(!hbs.is_empty(), "the write sends a HEARTBEAT");
    for (flags, body) in &hbs {
        assert_eq!(flags & 0x08, 0);
        assert_eq!(body.len(), 28);
    }
}

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct LargeSample {
    data: Vec<u8>,
}

/// A large change of a GROUP set goes out as DATA_FRAGs whose first one
/// carries the set's tags in the form of each reader's class, read
/// by hand from the bytes: the spec reader's has 0x0063, 0x0064 and 0x0065
/// and neither 0x8030 nor 0x0053; the legacy reader's has 0x8030 and
/// 0x0053 and no 0x0064. The other fragments carry none.
#[test]
fn a_fragmented_group_change_reaches_each_reader_class_in_its_form() {
    let topic = "test/group_frag_classes";
    let (publisher, writer, legacy, registry, fsm, _domain) =
        build_pair_of::<LargeSample>(topic, 51, PresentationAccessScope::Group, |qos| {
            qos.transient_local()
        });
    let (spec, spec_addr) = bind_capture();
    register_confirmed_reader(
        &fsm,
        &registry,
        topic,
        0x51,
        spec_addr,
        Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
    );
    publisher.begin_coherent_changes().expect("begin");
    writer
        .write(&LargeSample {
            data: vec![7u8; 20_000],
        })
        .expect("write");
    publisher.end_coherent_changes().expect("end");
    // (Q flag, inline QoS PIDs) of each DATA_FRAG received.
    let frags = |packets: Vec<Vec<u8>>| -> Vec<(bool, Vec<u16>)> {
        packets
            .into_iter()
            .filter(|p| p.len() > 68 && p[32] == 0x16)
            .map(|p| {
                let q = p[33] & 0x02 != 0;
                let mut pids = Vec::new();
                if q {
                    let mut at = 68;
                    loop {
                        let pid = u16::from_le_bytes([p[at], p[at + 1]]);
                        let len = usize::from(u16::from_le_bytes([p[at + 2], p[at + 3]]));
                        if pid == 1 {
                            break;
                        }
                        pids.push(pid);
                        at += 4 + len;
                    }
                }
                (q, pids)
            })
            .collect()
    };
    let (spec_frags, legacy_frags) = (frags(drain(&spec)), frags(drain(&legacy)));
    for (frags, class) in [(&spec_frags, "spec"), (&legacy_frags, "legacy")] {
        assert!(frags.len() > 1, "{class}: fragmented");
        assert_eq!(
            frags.iter().filter(|(q, _)| *q).count(),
            1,
            "{class}: one fragment carries the inline QoS"
        );
    }
    let first = |frags: &[(bool, Vec<u16>)]| frags.iter().find(|(q, _)| *q).expect("Q").1.clone();
    let spec_pids = first(&spec_frags);
    for pid in [0x0056u16, 0x0063, 0x0064, 0x0065] {
        assert!(
            spec_pids.contains(&pid),
            "spec: {pid:#06x} in {spec_pids:x?}"
        );
    }
    assert!(!spec_pids.contains(&0x8030) && !spec_pids.contains(&0x0053));
    let legacy_pids = first(&legacy_frags);
    for pid in [0x0056u16, 0x8030, 0x0053] {
        assert!(
            legacy_pids.contains(&pid),
            "legacy: {pid:#06x} in {legacy_pids:x?}"
        );
    }
    assert!(!legacy_pids.contains(&0x0064));
}

/// RTPS 2.5 Sec.8.7.5: fragmented GROUP changes are allocated and
/// journaled even before participant confirmation, like small changes.
#[test]
fn a_fragmented_group_change_is_journaled_without_confirmation() {
    let topic = "test/group_frag_unconditional";
    let (publisher, writer, capture, _registry, fsm, _domain) =
        build_pair_with_confirmation::<LargeSample>(
            topic,
            52,
            PresentationAccessScope::Group,
            |qos| qos,
            false,
        );
    let reader = fsm
        .find_readers_for_topic(topic)
        .first()
        .expect("discovered reader")
        .endpoint_guid;
    assert!(!fsm.is_endpoint_participant_confirmed(&reader));
    publisher.begin_coherent_changes().expect("begin");
    writer
        .write(&LargeSample {
            data: vec![9u8; 20_000],
        })
        .expect("write");
    assert!(drain(&capture)
        .iter()
        .any(|p| p.len() > 32 && p[32] == 0x16));
    let changes = writer
        .history_cache
        .as_ref()
        .expect("history")
        .snapshot_changes();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].seq, 1);
    assert_eq!(changes[0].metadata.coherent_sn, Some(1));
    publisher.end_coherent_changes().expect("end");
}

/// Before any reader of the topic is known, a GROUP change goes to each
/// discovered participant in the form of the participant's class:
/// the class is the participant's, known from its SPDP.
#[test]
fn a_group_change_before_its_readers_are_known_goes_in_each_participants_form() {
    let topic = "test/group_participant_fallback";
    let (_publisher, writer, registry, fsm, _domain) =
        build_writer_of::<CoherentDisposeSample>(topic, 53, PresentationAccessScope::Group);
    let (spec, spec_addr) = bind_capture();
    let (legacy, legacy_addr) = bind_capture();
    register_participant(
        &fsm,
        &registry,
        0x53,
        spec_addr,
        Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
    );
    register_participant(&fsm, &registry, 0x54, legacy_addr, None);
    writer
        .write(&CoherentDisposeSample { id: 1, v: 1 })
        .expect("write");
    let data = |packets: Vec<Vec<u8>>| {
        packets
            .into_iter()
            .find(|p| p.len() > DATA_SUBMSG_OFFSET && p[DATA_SUBMSG_OFFSET] == 0x15)
            .expect("a DATA")
    };
    let (_, spec_pids) = decode_data_submsg(&data(drain(&spec)));
    assert!(spec_pids.contains_key(&0x0064), "spec form: {spec_pids:x?}");
    let (_, legacy_pids) = decode_data_submsg(&data(drain(&legacy)));
    assert!(
        !legacy_pids.contains_key(&0x0064),
        "1.4.x form: {legacy_pids:x?}"
    );
}

/// DDS 1.4 Sec.2.2.3.6 and RTPS 2.5 Sec.8.7.6: a reader of T1 is
/// relevant to T1 even when T2 has no reader. Every writer still allocates
/// and journals its changes, including before any classic peer is ready.
#[test]
fn a_native_t1_reader_gets_every_set_with_an_unmatched_sibling_and_a_late_classic_peer() {
    let topic = "test/native_t1_unconditional";
    let (publisher, writer, capture, _registry, _fsm, _domain) =
        build_pair(topic, 54, PresentationAccessScope::Group, |qos| qos);
    let sibling = WriterBuilder::<CoherentDisposeSample>::new(format!("{topic}_sibling"))
        .qos(
            QoS::reliable()
                .keep_all()
                .presentation(Presentation::group_coherent()),
        )
        .publisher(&publisher)
        .build()
        .expect("unmatched sibling");
    let native_qos = QoS::reliable()
        .keep_all()
        .presentation(Presentation::group_coherent());
    let subscriber = crate::dds::Subscriber::new(native_qos.clone(), None, None, None);
    let native = crate::dds::reader::ReaderBuilder::<CoherentDisposeSample>::new(topic.to_string())
        .qos(native_qos)
        .subscriber(&subscriber)
        .build()
        .expect("native T1 reader");
    native.bind_to_writer(writer.merger());
    for set in 0..3 {
        if set == 1 {
            writer
                .wire_windows
                .pair(GUID::new([0x91; 12], [0, 0, 3, 7]), None, 2, true);
        }
        publisher.begin_coherent_changes().expect("begin");
        writer
            .write(&CoherentDisposeSample { id: 1, v: set })
            .expect("T1");
        sibling
            .write(&CoherentDisposeSample { id: 1, v: set })
            .expect("T2");
        publisher.end_coherent_changes().expect("end");
        subscriber.begin_access().expect("access");
        assert_eq!(
            native
                .take_all()
                .expect("take")
                .iter()
                .map(|s| s.v)
                .collect::<Vec<_>>(),
            [set]
        );
        subscriber.end_access().expect("end access");
        assert_eq!(native.get_sample_lost_status().total_count, 0);
    }
    let mut seqs = Vec::new();
    for packet in drain(&capture) {
        crate::core::discovery::multicast::classifier::walk::for_each_submessage(&packet, |sub| {
            if sub.id == 0x15 {
                let at = sub.offset;
                seqs.push(u32::from_le_bytes(
                    packet[at + 20..at + 24].try_into().unwrap(),
                ));
            }
            crate::core::discovery::multicast::classifier::walk::Step::Continue
        });
    }
    assert_eq!(
        seqs,
        [1, 3, 5],
        "native DATA has no suppression or translation"
    );
    for cache in [
        writer.history_cache.as_ref().unwrap(),
        sibling.history_cache.as_ref().unwrap(),
    ] {
        assert_eq!(
            cache.highest_inserted(),
            6,
            "all members and closes were journaled"
        );
    }
    assert_eq!(
        writer.next_seq.load(std::sync::atomic::Ordering::Acquire),
        7
    );
    assert_eq!(
        sibling.next_seq.load(std::sync::atomic::Ordering::Acquire),
        7
    );
}

#[test]
fn independent_late_vendor_resolution_initializes_an_already_paired_reader() {
    for (sedp_first, vendor) in [
        (false, 0x0101),
        (true, 0x0101),
        (false, 0x010a),
        (true, 0x010a),
    ] {
        let lease = crate::test_support::domains::unique_domain();
        let participant = crate::Participant::builder("independent-late-vendor")
            .domain_id(lease.id())
            .build()
            .unwrap();
        let qos = QoS::reliable()
            .keep_all()
            .presentation(Presentation::group_coherent());
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let topic = "independent-late-vendor";
        let writer = participant
            .topic::<CoherentDisposeSample>(topic)
            .unwrap()
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let fsm = writer.discovery_fsm.as_ref().unwrap();
        let (capture, addr) = bind_capture();
        let participant_guid = GUID::new([0xa5; 12], RTPS_ENTITYID_PARTICIPANT);
        let reader = GUID::new([0xa5; 12], [0, 0, 0x10, 0x07]);
        let announcement = |vendor_id| crate::protocol::discovery::SpdpData {
            participant_guid,
            lease_duration_ms: 100_000,
            domain_id: lease.id(),
            metatraffic_unicast_locators: vec![addr],
            default_unicast_locators: vec![addr],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        // The partial-SPDP compatibility path can know the GUID before vendorId.
        let sedp = crate::protocol::discovery::SedpData {
            topic_name: topic.to_owned(),
            type_name: "CoherentDisposeSample".to_owned(),
            participant_guid,
            endpoint_guid: reader,
            qos_hash: 0,
            qos: Some(qos),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![addr],
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
        if sedp_first {
            fsm.handle_sedp(sedp.clone());
            assert_eq!(writer.get_publication_matched_status().current_count, 0);
        }
        fsm.handle_spdp(announcement(None));
        fsm.confirm_participant_for_test(participant_guid);
        fsm.handle_sedp(sedp.clone());
        assert_eq!(
            writer.get_publication_matched_status().current_count,
            1,
            "the reader must actually be paired before resolving its vendor"
        );
        assert!(!writer.wire_windows.contains(reader));
        writer
            .write(&CoherentDisposeSample { id: 1, v: 1 })
            .unwrap();
        publisher.begin_coherent_changes().unwrap();
        writer
            .write(&CoherentDisposeSample { id: 1, v: 2 })
            .unwrap();
        // RTPS 8.3.8.2: absence of vendor metadata cannot suppress DATA.
        // These original SNs must keep their meaning after classification.
        capture.set_nonblocking(true).unwrap();
        let mut before = [0u8; 4096];
        let writer_id = writer.rtps_endpoint.unwrap().writer_entity_id;
        let mut native_sns = Vec::new();
        while let Ok(n) = capture.recv(&mut before) {
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                &before[..n],
                |sub| {
                    let at = sub.offset;
                    if sub.id == 0x15
                        && before[at + 1] & 4 != 0
                        && before.get(at + 12..at + 16) == Some(writer_id.as_slice())
                    {
                        native_sns.push(u32::from_le_bytes(
                            before[at + 20..at + 24].try_into().unwrap(),
                        ));
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
        }
        assert_eq!(native_sns, vec![1, 2]);
        capture.set_nonblocking(false).unwrap();
        fsm.handle_spdp(announcement(Some(vendor)));
        fsm.handle_sedp(sedp);
        assert!(fsm.needs_classic_sequence_window(&reader.prefix));
        assert!(
            writer.wire_windows.contains(reader),
            "resolved classic reader is now permanently refused by every send path"
        );
        let status = writer.get_publication_matched_status();
        assert_eq!((status.total_count, status.current_count), (1, 1));
        // Resolution during a part cannot expose its suffix as a complete set.
        writer
            .write(&CoherentDisposeSample { id: 1, v: 3 })
            .unwrap();
        publisher.end_coherent_changes().unwrap();
        publisher.begin_coherent_changes().unwrap();
        writer
            .write(&CoherentDisposeSample { id: 1, v: 4 })
            .unwrap();
        publisher.end_coherent_changes().unwrap();
        let writer_id = writer.rtps_endpoint.unwrap().writer_entity_id;
        let mut first = None;
        let mut buf = [0u8; 4096];
        for _ in 0..64 {
            let Ok(n) = capture.recv(&mut buf) else {
                break;
            };
            let packet = &buf[..n];
            if packet.get(24..36) != Some(&reader.prefix) {
                continue;
            }
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                packet,
                |sub| {
                    let at = sub.offset;
                    if sub.id == 0x15
                        && packet[at + 1] & 4 != 0
                        && packet.get(at + 12..at + 16) == Some(&writer_id)
                    {
                        first = Some(u32::from_le_bytes(
                            packet[at + 20..at + 24].try_into().unwrap(),
                        ));
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
            if first.is_some() {
                break;
            }
        }
        assert_eq!(
            first,
            Some(5),
            "classification preserves native SN identity and skips the partial part"
        );
    }
}

#[test]
fn late_vendor_classification_replays_best_effort_durable_history_and_close() {
    for (reliable_writer, confirmed) in [(false, false), (false, true), (true, false), (true, true)]
    {
        let lease = crate::test_support::domains::unique_domain();
        let participant = crate::Participant::builder("late-durable-classification")
            .domain_id(lease.id())
            .build()
            .unwrap();
        let base = if reliable_writer {
            QoS::reliable()
        } else {
            QoS::best_effort()
        };
        let qos = base
            .keep_all()
            .transient_local()
            .presentation(Presentation::group_coherent());
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let topic = "late-durable-classification";
        let writer = participant
            .topic::<CoherentDisposeSample>(topic)
            .unwrap()
            .writer()
            .qos(qos)
            .publisher(&publisher)
            .build()
            .unwrap();
        publisher.begin_coherent_changes().unwrap();
        for value in [1, 2] {
            writer
                .write(&CoherentDisposeSample { id: 1, v: value })
                .unwrap();
        }
        publisher.end_coherent_changes().unwrap();
        let fsm = writer.discovery_fsm.as_ref().unwrap();
        let (capture, addr) = bind_capture();
        let participant_guid = GUID::new([0xa6; 12], RTPS_ENTITYID_PARTICIPANT);
        let reader = GUID::new(participant_guid.prefix, [0, 0, 0x10, 0x07]);
        let announcement = |vendor_id| crate::protocol::discovery::SpdpData {
            participant_guid,
            lease_duration_ms: 100_000,
            domain_id: lease.id(),
            metatraffic_unicast_locators: vec![addr],
            default_unicast_locators: vec![addr],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        fsm.handle_spdp(announcement(None));
        if confirmed {
            fsm.confirm_participant_for_test(participant_guid);
        }
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            topic_name: topic.to_owned(),
            type_name: "CoherentDisposeSample".to_owned(),
            participant_guid,
            endpoint_guid: reader,
            qos_hash: 0,
            qos: Some(
                QoS::best_effort()
                    .keep_all()
                    .transient_local()
                    .presentation(Presentation::group_coherent()),
            ),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![addr],
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
        assert_eq!(
            writer.get_publication_matched_status().current_count,
            u32::from(confirmed)
        );
        // Unknown vendors already receive native DATA, but the vendor-specific
        // coherent close cannot be encoded until the SPDP is classified.
        capture.set_nonblocking(true).unwrap();
        let writer_id = writer.rtps_endpoint.unwrap().writer_entity_id;
        let collect = || {
            let mut sns = Vec::new();
            let mut buf = [0; 4096];
            while let Ok(n) = capture.recv(&mut buf) {
                crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                    &buf[..n],
                    |sub| {
                        let at = sub.offset;
                        if sub.id == 0x15 && buf.get(at + 12..at + 16) == Some(writer_id.as_slice())
                        {
                            sns.push((
                                u32::from_le_bytes(buf[at + 20..at + 24].try_into().unwrap()),
                                buf[at + 1] & 4 != 0,
                            ));
                        }
                        crate::core::discovery::multicast::classifier::walk::Step::Continue
                    },
                );
            }
            sns
        };
        assert_eq!(collect(), vec![(1, true), (2, true)]);
        fsm.handle_spdp(announcement(Some(0x0101)));
        assert!(writer.wire_windows.contains(reader));
        assert_eq!(
            collect(),
            vec![(1, true), (2, true), (3, false)],
            "classification must replay complete retained history without waiting for an ACKNACK"
        );
        fsm.confirm_participant_for_test(participant_guid);
        let status = writer.get_publication_matched_status();
        assert_eq!((status.total_count, status.current_count), (1, 1));
        fsm.handle_spdp(announcement(Some(0x0101)));
        assert!(
            collect().is_empty(),
            "an unchanged SPDP must not repeat replay"
        );
    }
}

#[test]
fn independent_local_only_ordered_group_writes_advance_the_late_match_watermark() {
    let mut observed = Vec::new();
    for (tag, base) in [
        ("reliable", QoS::reliable()),
        ("best_effort", QoS::best_effort()),
    ] {
        let lease = crate::test_support::domains::unique_domain();
        let participant = crate::Participant::builder("independent-local-watermark")
            .domain_id(lease.id())
            .build()
            .unwrap();
        let presentation = Presentation::new(PresentationAccessScope::Group, false, true);
        let publisher = Arc::new(
            participant
                .create_publisher(base.clone().presentation(presentation))
                .unwrap(),
        );
        let topic = format!("independent-local-watermark-{tag}");
        let writer = participant
            .topic::<CoherentDisposeSample>(&topic)
            .unwrap()
            .writer()
            .qos(base.keep_all().presentation(presentation))
            .publisher(&publisher)
            .build()
            .unwrap();
        let native = crate::dds::reader::ReaderBuilder::<CoherentDisposeSample>::new(topic.clone())
            .qos(QoS::best_effort().keep_all())
            .build()
            .unwrap();
        native.bind_to_writer(writer.merger());
        for v in 1..=3 {
            writer.write(&CoherentDisposeSample { id: 1, v }).unwrap();
        }
        assert_eq!(native.take_all().unwrap().len(), 3);
        assert_eq!(
            writer.next_seq.load(std::sync::atomic::Ordering::Acquire),
            4
        );
        let watermark = writer.history_cache.as_ref().map_or_else(
            || writer.wire_windows.highest_unretained(),
            |cache| cache.highest_inserted(),
        );
        let fsm = writer.discovery_fsm.as_ref().unwrap();
        let (capture, addr) = bind_capture();
        let participant_guid = GUID::new([0xa6; 12], RTPS_ENTITYID_PARTICIPANT);
        let reader = GUID::new([0xa6; 12], [0, 0, 0x10, 0x07]);
        let spdp = || crate::protocol::discovery::SpdpData {
            participant_guid,
            lease_duration_ms: 100_000,
            domain_id: lease.id(),
            metatraffic_unicast_locators: vec![addr],
            default_unicast_locators: vec![addr],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: Some(0x0101),
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        };
        fsm.handle_spdp(spdp());
        fsm.confirm_participant_for_test(participant_guid);
        fsm.handle_sedp(crate::protocol::discovery::SedpData {
            topic_name: topic,
            type_name: "CoherentDisposeSample".to_owned(),
            participant_guid,
            endpoint_guid: reader,
            qos_hash: 0,
            qos: Some(QoS::best_effort().keep_all().presentation(presentation)),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![addr],
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
        assert!(
            writer.wire_windows.contains(reader),
            "production pairing must install the window"
        );
        writer
            .write(&CoherentDisposeSample { id: 1, v: 4 })
            .unwrap();
        capture
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let mut wire_sns = Vec::new();
        let mut buf = [0u8; 4096];
        let writer_id = writer.rtps_endpoint.unwrap().writer_entity_id;
        // The capture receives periodic heartbeats and SEDP too. Stop
        // after this writer's DATA rather than waiting for a silent socket.
        for _ in 0..64 {
            let Ok(n) = capture.recv(&mut buf) else {
                break;
            };
            let packet = &buf[..n];
            crate::core::discovery::multicast::classifier::walk::for_each_submessage(
                packet,
                |sub| {
                    let at = sub.offset;
                    if sub.id == 0x15 && packet.get(at + 12..at + 16) == Some(&writer_id) {
                        wire_sns.push(u32::from_le_bytes(
                            packet[at + 20..at + 24].try_into().unwrap(),
                        ));
                    }
                    crate::core::discovery::multicast::classifier::walk::Step::Continue
                },
            );
            if !wire_sns.is_empty() {
                break;
            }
        }
        assert_eq!(wire_sns.len(), 1, "one addressed user DATA after matching");
        observed.push((tag, watermark, wire_sns[0]));
    }
    assert_eq!(observed, [("reliable", 3, 1), ("best_effort", 3, 1)],
        "successful local writes are missing from the watermark and the first classic DATA starts at SN 4");
}

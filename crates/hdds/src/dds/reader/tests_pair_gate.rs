// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The reader's half of the (writer, reader) pair gate (`writer_refused`):
//! every door a remote writer's change takes into a reader is shut to a
//! writer that reader's QoS verdict refuses, and open to one it accepts.
//! DDS v1.4 Sec.2.2.3: "for the Subscriber to receive data the DataReader's
//! requested value must be compatible with the DataWriter's offered value".
//!
//! Each test has its control: the same change from a writer the reader
//! accepts goes through the same door.

use super::tests::{encoded_point, Point};
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::GUID;
use crate::core::rt;
use crate::dds::match_notification::{MatchNotificationRegistry, PeerChange};
use crate::dds::QoS;
use crate::engine::subscriber::DisposeKind;
use crate::engine::Subscriber;
use crate::protocol::discovery::{SedpData, SpdpData};
use std::sync::{Arc, Mutex};

const TOPIC: &str = "pair_gate";
const LOCAL: [u8; 12] = [0x01; 12];
const PEER: [u8; 12] = [0x0E; 12];
/// A best-effort writer: a RELIABLE reader refuses it (RELIABILITY).
const REFUSED: [u8; 16] = [
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0, 0, 1, 0x02,
];
/// A reliable writer: the RELIABLE reader accepts it.
const ACCEPTED: [u8; 16] = [
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0, 0, 2, 0x02,
];

/// Discovery with its match registry, as a participant builds them, the
/// peer known and both its writers announced.
fn discovery() -> (Arc<DiscoveryFsm>, Arc<MatchNotificationRegistry>) {
    let (fsm, reg) = discovery_where(true);
    for (writer, qos) in [(REFUSED, QoS::best_effort()), (ACCEPTED, QoS::reliable())] {
        fsm.handle_sedp(announcement(writer, qos));
    }
    (fsm, reg)
}

/// Discovery with its match registry, as a participant builds them, the
/// peer known when `peer_known`, no writer announced.
fn discovery_where(peer_known: bool) -> (Arc<DiscoveryFsm>, Arc<MatchNotificationRegistry>) {
    let fsm = Arc::new(DiscoveryFsm::new(
        GUID::new(LOCAL, [0, 0, 1, 0xC1]),
        100_000,
    ));
    let reg = Arc::new(MatchNotificationRegistry::new(&fsm, LOCAL));
    fsm.set_match_registry(reg.clone());
    fsm.register_listener(reg.clone());
    if peer_known {
        fsm.handle_spdp(SpdpData {
            participant_guid: GUID::new(PEER, [0, 0, 1, 0xC1]),
            lease_duration_ms: 100_000,
            domain_id: 0,
            metatraffic_unicast_locators: vec![],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        });
    }
    (fsm, reg)
}

/// `writer`'s announcement of `TOPIC` with `qos`.
fn announcement(writer: [u8; 16], qos: QoS) -> SedpData {
    SedpData {
        topic_name: TOPIC.to_string(),
        type_name: "Point".to_string(),
        participant_guid: GUID::new(PEER, [0, 0, 1, 0xC1]),
        endpoint_guid: GUID::from_bytes(writer),
        qos_hash: 1,
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
    }
}

/// The router's record of `writers`, as the SEDP handler makes it on each
/// announcement, held or not, and keeps across discovery's purges: their
/// topic and their OWNERSHIP (SHARED), through which a reader resolves a
/// writer discovery no longer holds (`ownership_gate`).
fn routed(writers: &[[u8; 16]]) -> Arc<crate::engine::TopicRegistry> {
    let topics = Arc::new(crate::engine::TopicRegistry::new());
    for writer in writers {
        topics.register_writer_guid(*writer, TOPIC.to_string());
        topics
            .register_writer_ownership_kind(*writer, crate::qos::ownership::OwnershipKind::Shared);
    }
    topics
}

/// A RELIABLE reader of `TOPIC`, judged by `reg`, TOPIC-scope coherent when
/// `coherent`; registered with the registry when `registered`.
fn reader(
    reg: &Arc<MatchNotificationRegistry>,
    coherent: bool,
    registered: bool,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    reader_with(reg, coherent, registered, None, None)
}

/// `reader`, resolving OWNERSHIP through the router's record `topics` when
/// given, and acknowledging through `credit` (a reliable reader's
/// WriterProxies, behind a reliable reorder gate) when given.
fn reader_with(
    reg: &Arc<MatchNotificationRegistry>,
    coherent: bool,
    registered: bool,
    topics: Option<Arc<crate::engine::TopicRegistry>>,
    credit: Option<crate::core::reader::ReaderAckCredit>,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    let _ = rt::init_slab_pool();
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let gate = if credit.is_some() {
        super::reorder::ReorderGate::new(true, true)
    } else {
        super::reorder::ReorderGate::new(false, false)
    };
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        TOPIC.to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(gate)),
        super::subscriber::CoherentConfig {
            coherent_access: coherent,
            is_group_scope: false,
        },
        Some(reg.clone()),
        credit,
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        topics,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    if registered {
        sub.register_match_entry_for_test(QoS::reliable());
    }
    (ring, sub)
}

fn sample(sub: &super::subscriber::ReaderSubscriber<Point>, writer: [u8; 16], seq: u64) {
    let value = i32::try_from(seq).expect("small");
    sub.on_data_with_writer(
        TOPIC,
        writer,
        seq,
        &encoded_point(value, value),
        crate::dds::CdrVersion::Xcdr2,
    );
}

fn taken(ring: &rt::IndexRing) -> usize {
    let pool = rt::get_slab_pool();
    let mut n = 0;
    while let Some(entry) = ring.pop() {
        pool.release(entry.handle);
        n += 1;
    }
    n
}

/// A sample: the refused writer's is dropped, the accepted writer's
/// delivered.
#[test]
fn a_refused_writers_sample_is_dropped() {
    let (_fsm, reg) = discovery();
    let (ring, sub) = reader(&reg, false, true);
    sample(&sub, REFUSED, 1);
    assert_eq!(taken(&ring), 0, "refused");
    sample(&sub, ACCEPTED, 1);
    assert_eq!(taken(&ring), 1, "the control is delivered");
}

/// A reader whose entry is not registered yet is matched with nothing: it
/// takes nothing, not even from a writer it would accept; registered, it
/// takes the accepted writer's samples.
#[test]
fn a_reader_not_registered_yet_takes_nothing() {
    let (_fsm, reg) = discovery();
    let (ring, sub) = reader(&reg, false, false);
    sample(&sub, ACCEPTED, 1);
    assert_eq!(taken(&ring), 0, "matched with nothing yet");
    sub.register_match_entry_for_test(QoS::reliable());
    sample(&sub, ACCEPTED, 2);
    assert_eq!(taken(&ring), 1, "registered: the accepted writer's");
}

/// A dispose: the refused writer's moves no instance, the accepted
/// writer's does.
#[test]
fn a_refused_writers_dispose_moves_nothing() {
    let (_fsm, reg) = discovery();
    let (_ring, sub) = reader(&reg, false, true);
    let key = [0x42; 16];
    sub.on_dispose_from_writer(TOPIC, REFUSED, 1, key, DisposeKind::Disposed);
    assert!(sub.dispose_events.pop_one().is_none(), "refused");
    sub.on_dispose_from_writer(TOPIC, ACCEPTED, 1, key, DisposeKind::Disposed);
    assert!(
        sub.dispose_events.pop_one().is_some(),
        "the control moves the instance"
    );
}

/// DDS v1.4 Sec.2.2.2.5.5 / Sec.2.2.2.4.2.13 `dispose_w_timestamp`,
/// Sec.2.2.2.4.2.8 `unregister_instance_w_timestamp`: the datagram's INFO_TS
/// (`route_source_ts_ns`, set by the router for the datagram currently
/// being routed -- the same thread-local a DATA sample's lifespan already
/// reads) must reach the queued transition's `DisposeEvent`, which carries
/// it to the NOT_ALIVE sample's `SampleInfo` (`transition_info`).
#[test]
fn a_dispose_carries_its_datagrams_source_timestamp() {
    let (_fsm, reg) = discovery();
    let (_ring, sub) = reader(&reg, false, true);
    crate::engine::router::set_route_source_ts_ns(Some(123_456_789));
    sub.on_dispose_from_writer(TOPIC, ACCEPTED, 1, [0x43; 16], DisposeKind::Disposed);
    crate::engine::router::set_route_source_ts_ns(None);
    let event = sub.dispose_events.pop_one().expect("the control moves it");
    assert_eq!(
        event.source_timestamp_ns,
        Some(123_456_789),
        "the datagram's source timestamp must reach the transition"
    );
}

/// The control: a transition with no INFO_TS (`route_source_ts_ns` unset,
/// e.g. a best-effort vendor that omits it) reports none -- never a stale
/// carry-over from an earlier call that did set it.
#[test]
fn a_dispose_with_no_info_ts_reports_no_source_timestamp() {
    let (_fsm, reg) = discovery();
    let (_ring, sub) = reader(&reg, false, true);
    crate::engine::router::set_route_source_ts_ns(Some(999));
    crate::engine::router::set_route_source_ts_ns(None);
    sub.on_dispose_from_writer(TOPIC, ACCEPTED, 1, [0x44; 16], DisposeKind::Disposed);
    let event = sub.dispose_events.pop_one().expect("the control moves it");
    assert_eq!(event.source_timestamp_ns, None);
}

/// Two transitions of the same instance coalesce into one queued event
/// (at most one notification per instance): an unregister at timestamp
/// 100 followed by a dispose at timestamp 200 must keep 200, the
/// timestamp of the LATER change (DDS v1.4 Sec.2.2.2.5.5 -- the
/// SampleInfo reports the instant of the change the application is
/// actually told about), the same rule already used to decide which
/// change's `order_seq`/`writer_guid` the merged event keeps.
#[test]
fn a_coalesced_transition_keeps_the_later_timestamp() {
    let (_fsm, reg) = discovery();
    let (_ring, sub) = reader(&reg, false, true);
    for (seq, ts, kind) in [
        (1, 100, DisposeKind::Unregistered),
        (2, 200, DisposeKind::Disposed),
    ] {
        crate::engine::router::set_route_source_ts_ns(Some(ts));
        sub.on_dispose_from_writer(TOPIC, ACCEPTED, seq, [0x62; 16], kind);
    }
    crate::engine::router::set_route_source_ts_ns(None);
    let event = sub.dispose_events.pop_one().expect("coalesced into one");
    assert_eq!(event.seq, 2, "fixture: the later change's seq");
    assert_eq!(
        event.source_timestamp_ns,
        Some(200),
        "the coalesced event must report the later change's timestamp"
    );
}

/// A coherent set: the refused writer's sample is never staged, so its
/// END_COHERENT_SET commits nothing; the accepted writer's set commits.
#[test]
fn a_refused_writers_coherent_set_is_never_staged() {
    let (_fsm, reg) = discovery();
    let (ring, sub) = reader(&reg, true, true);
    for writer in [REFUSED, ACCEPTED] {
        sub.on_data_coherent(
            TOPIC,
            writer,
            1,
            &encoded_point(1, 1),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
        sub.on_ecs(TOPIC, writer, 2, 1, None, None);
    }
    assert_eq!(taken(&ring), 1, "the accepted writer's set only");
}

/// Independent of DESTINATION_ORDER BY_SOURCE_TIMESTAMP: `SampleInfo
/// ::source_timestamp_ns` for a coherently-staged sample must carry the
/// datagram's INFO_TS, not `source_ts_ns: None` as hardcoded in
/// `BufferedCoherentSample::into_payload`. The real value is available at
/// staging time (`router::route_source_ts_ns`, set from the same
/// datagram's INFO_TS this `on_data_coherent` call is routing) and is
/// captured then, not thrown away.
///
/// This reader is not coherent-access on this topic's Subscriber in a
/// way `taken()` can see the metadata of, so this test pops the ring
/// entry itself and reads `IndexEntry::timestamp_ns`/`has_source_ts`
/// directly -- the same fields `SampleInfo::source_timestamp_ns` is
/// built from (`DataReader::into_data_and_info`).
///
/// Mutant: reverting `into_payload`'s data branch to hardcode
/// `source_ts_ns: None` makes this fail: the delivered entry would
/// report `has_source_ts() == false`.
#[test]
fn a_coherent_samples_source_timestamp_reaches_the_delivered_entry() {
    let (_fsm, reg) = discovery();
    let (ring, sub) = reader(&reg, true, true);

    crate::engine::router::set_route_source_ts_ns(Some(123_456_789));
    sub.on_data_coherent(
        TOPIC,
        ACCEPTED,
        1,
        &encoded_point(1, 1),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        None,
        None,
    );
    // A later, unrelated datagram's INFO_TS: the staged sample's own
    // value must already have been captured, not read lazily from this
    // thread-local at commit time.
    crate::engine::router::set_route_source_ts_ns(Some(999_999_999));
    sub.on_ecs(TOPIC, ACCEPTED, 2, 1, None, None);
    crate::engine::router::set_route_source_ts_ns(None);

    let pool = rt::get_slab_pool();
    let entry = ring.pop().expect("the committed sample");
    assert!(
        entry.has_source_ts(),
        "a coherently-staged sample must carry a real source timestamp"
    );
    assert_eq!(entry.timestamp_ns, 123_456_789);
    pool.release(entry.handle);
}

/// A writer this participant has never discovered via SEDP at all: no
/// announcement, unlike `REFUSED`, whose announcement the reader's QoS
/// verdict judges and refuses. It has no matched writer proxy (RTPS v2.5
/// Sec.8.4.15), so it is no writer of this reader on any axis, PARTITION
/// included.
const UNDISCOVERED: [u8; 16] = [
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0, 0, 9, 0x02,
];

/// A coherent set from a writer never discovered via SEDP commits nothing,
/// even on a default-partition reader: `writer_partition_incompatible`
/// bypasses its own gate for a default partition, and `is_writer_refused_by`
/// answers false for a writer it never judged at all (unknown, not
/// "refused") -- the one combination that reached `stage_coherent_change`
/// with no gate at all before `writer_undiscovered` closed it. The control:
/// the accepted (discovered, matched) writer's set still commits.
#[test]
fn an_undiscovered_writers_coherent_set_is_never_staged() {
    let (_fsm, reg) = discovery();
    let (ring, sub) = reader(&reg, true, true);
    sub.on_data_coherent(
        TOPIC,
        UNDISCOVERED,
        1,
        &encoded_point(1, 1),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        None,
        None,
    );
    sub.on_ecs(TOPIC, UNDISCOVERED, 2, 1, None, None);
    assert_eq!(
        taken(&ring),
        0,
        "a writer never discovered via SEDP has no matched writer proxy"
    );
    sub.on_data_coherent(
        TOPIC,
        ACCEPTED,
        1,
        &encoded_point(1, 1),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        None,
        None,
    );
    sub.on_ecs(TOPIC, ACCEPTED, 2, 1, None, None);
    assert_eq!(taken(&ring), 1, "the control is delivered");
}

/// A plain (non-coherent) DISPOSE/UNREGISTER from a writer this
/// participant has never discovered via SEDP: `writer_refused` answers
/// false for it (unjudged, not "refused"), same gap as the coherent
/// staging door, but on the independent lifecycle path a D=1/Q=1 DATA
/// with inline KeyHash and StatusInfo reaches regardless of what the
/// deferred OWNERSHIP verdict does with the sample value (RTPS v2.5
/// Sec.8.4.15: no matched writer proxy, no standing to move instance
/// state).
#[test]
fn an_undiscovered_writers_dispose_moves_nothing() {
    let (_fsm, reg) = discovery();
    let (_ring, sub) = reader(&reg, false, true);
    sub.on_dispose_from_writer(TOPIC, UNDISCOVERED, 1, [0x99; 16], DisposeKind::Disposed);
    assert!(
        sub.dispose_events.pop_one().is_none(),
        "a writer never discovered via SEDP must not move instance state"
    );
    sub.on_dispose_from_writer(TOPIC, ACCEPTED, 1, [0x99; 16], DisposeKind::Disposed);
    assert!(
        sub.dispose_events.pop_one().is_some(),
        "the control (a matched writer) moves it"
    );
}

/// Samples deferred for OWNERSHIP before the writer was known: once its
/// announcement makes it known and refused, they are discarded, never
/// flushed to the reader.
#[test]
fn samples_deferred_before_the_writer_was_known_are_discarded_once_refused() {
    let (fsm, reg) = discovery();
    let (ring, sub) = reader(&reg, false, true);
    let late: [u8; 16] = [
        0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0, 0, 3, 0x02,
    ];
    sample(&sub, late, 1);
    sample(&sub, late, 2);
    assert_eq!(taken(&ring), 0, "fixture: deferred, its OWNERSHIP unknown");
    fsm.handle_sedp(announcement(late, QoS::best_effort()));
    sub.on_writer_qos_resolved(late);
    assert_eq!(
        taken(&ring),
        0,
        "refused: the deferred samples are discarded"
    );
    sample(&sub, late, 3);
    assert_eq!(taken(&ring), 0);
}

/// A reader created after the refused writer's participant fell silent:
/// discovery forgot the writer, the router still routes its samples and the
/// reader resolves its OWNERSHIP through the router's record. The reader
/// drops them; the accepted writer's, gone silent the same way, are
/// delivered (the control: the same doors are open to it).
#[test]
fn a_reader_created_after_a_silent_departure_drops_the_refused_writers_samples() {
    let (fsm, reg) = discovery();
    fsm.remove_participant(GUID::new(PEER, [0, 0, 1, 0xC1]));
    assert!(
        fsm.current_endpoint(TOPIC, &GUID::from_bytes(REFUSED))
            .is_none(),
        "fixture: discovery forgot the writer"
    );
    let (ring, sub) = reader_with(&reg, false, true, Some(routed(&[REFUSED, ACCEPTED])), None);
    sample(&sub, REFUSED, 1);
    assert_eq!(taken(&ring), 0, "refused");
    sample(&sub, ACCEPTED, 1);
    assert_eq!(taken(&ring), 1, "the control is delivered");
}

/// A reader created while the refused writer's announcement is held for
/// its participant (SEDP before SPDP): the router routes its samples by the
/// topic it announced from then on, and the reader drops them before the
/// replay; the accepted writer's, held the same way, are delivered.
#[test]
fn a_reader_created_while_a_writer_is_held_drops_its_samples() {
    let (fsm, reg) = discovery_where(false);
    for (writer, qos) in [(REFUSED, QoS::best_effort()), (ACCEPTED, QoS::reliable())] {
        fsm.handle_sedp(announcement(writer, qos));
    }
    assert!(
        fsm.current_endpoint(TOPIC, &GUID::from_bytes(REFUSED))
            .is_none(),
        "fixture: the announcement is held"
    );
    let (ring, sub) = reader_with(&reg, false, true, Some(routed(&[REFUSED, ACCEPTED])), None);
    sample(&sub, REFUSED, 1);
    assert_eq!(taken(&ring), 0, "refused");
    sample(&sub, ACCEPTED, 1);
    assert_eq!(taken(&ring), 1, "the control is delivered");
}

/// A writer the reader accepted, then refuses: announced again with a QoS
/// the reader does not match. Its sample 1 was delivered.
const FLIPPED: [u8; 16] = [
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0, 0, 4, 0x02,
];

/// A reliable reader that delivered sample 1 of `FLIPPED` and of
/// `ACCEPTED`, `FLIPPED` refused since, TOPIC-scope coherent when
/// `coherent`; with its discovery, its ring and its acknowledgement state.
struct Flipped {
    fsm: Arc<DiscoveryFsm>,
    reg: Arc<MatchNotificationRegistry>,
    ring: Arc<rt::IndexRing>,
    sub: super::subscriber::ReaderSubscriber<Point>,
    credit: crate::core::reader::ReaderAckCredit,
}

fn after_a_flip(coherent: bool) -> Flipped {
    after_a_flip_with(coherent, |_| {})
}

/// `after_a_flip`, `before` run on the reader before the flip.
fn after_a_flip_with(
    coherent: bool,
    before: impl FnOnce(&super::subscriber::ReaderSubscriber<Point>),
) -> Flipped {
    let (fsm, reg) = discovery();
    fsm.handle_sedp(announcement(FLIPPED, QoS::reliable()));
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    credit.match_writer(FLIPPED);
    credit.match_writer(ACCEPTED);
    let (ring, sub) = reader_with(&reg, coherent, true, None, Some(credit.clone()));
    sample(&sub, FLIPPED, 1);
    sample(&sub, ACCEPTED, 1);
    assert_eq!(taken(&ring), 2, "fixture: both accepted");
    before(&sub);
    fsm.handle_sedp(announcement(FLIPPED, QoS::best_effort()));
    let entry = *sub.match_entry.get().expect("registered");
    assert!(
        reg.is_writer_refused_by(&FLIPPED, entry),
        "fixture: refused now"
    );
    assert!(!reg.is_writer_refused_by(&ACCEPTED, entry));
    Flipped {
        fsm,
        reg,
        ring,
        sub,
        credit,
    }
}

fn lost(sub: &super::subscriber::ReaderSubscriber<Point>) -> u32 {
    sub.sample_lost
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .total_count
}

/// Whether the reader acknowledged `writer`'s change 2 (its answer to a
/// HEARTBEAT announcing 1..=2).
fn acknowledged_2(credit: &crate::core::reader::ReaderAckCredit, writer: &[u8; 16]) -> bool {
    let answer = credit
        .answer_heartbeat(
            writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: 2,
                count: 1,
                final_flag: false,
            },
        )
        .expect("matched");
    answer.bitmap_base > 2 && !answer.missing.contains(&2)
}

/// A HEARTBEAT: the refused writer's moves no gate and loses no sample; the
/// accepted writer's reports the changes it no longer holds lost.
#[test]
fn a_refused_writers_heartbeat_moves_nothing() {
    let Flipped { sub, .. } = after_a_flip(false);
    sub.on_writer_heartbeat(FLIPPED, 5);
    assert_eq!(lost(&sub), 0, "refused");
    sub.on_writer_heartbeat(ACCEPTED, 5);
    assert_eq!(lost(&sub), 3, "the control: 2, 3 and 4 lost");
}

/// A GAP: the refused writer's moves no gate and loses no sample; the
/// accepted writer's reports the changes it declares lost.
#[test]
fn a_refused_writers_gap_moves_nothing() {
    let Flipped { sub, .. } = after_a_flip(false);
    sub.on_writer_gap(FLIPPED, 2, 5, vec![]);
    sub.on_writer_gap_filtered(FLIPPED, 5, 6, vec![], 0);
    assert_eq!(lost(&sub), 0, "refused");
    sub.on_writer_gap(ACCEPTED, 2, 5, vec![]);
    assert_eq!(lost(&sub), 3, "the control: 2, 3 and 4 lost");
}

/// A change without a sample: the refused writer's is not received; the
/// accepted writer's is acknowledged.
#[test]
fn a_refused_writers_sample_less_change_is_not_received() {
    let Flipped { sub, credit, .. } = after_a_flip(false);
    sub.on_writer_non_data(FLIPPED, 2);
    assert!(!acknowledged_2(&credit, &FLIPPED), "refused");
    sub.on_writer_non_data(ACCEPTED, 2);
    assert!(acknowledged_2(&credit, &ACCEPTED), "the control");
}

/// An END_COHERENT_SET marker, to a reader that reads coherent sets and to
/// one that does not: the refused writer's is not received; the accepted
/// writer's is acknowledged.
#[test]
fn a_refused_writers_end_coherent_set_is_not_received() {
    for coherent in [true, false] {
        // `fsm` must outlive `sub`: its match registry holds only a `Weak`
        // reference to it, and the accepted writer must stay resolvable
        // (`writer_undiscovered`) for the control to commit.
        let Flipped {
            fsm: _fsm,
            sub,
            credit,
            ..
        } = after_a_flip(coherent);
        sub.on_ecs(TOPIC, FLIPPED, 2, 1, None, None);
        assert!(!acknowledged_2(&credit, &FLIPPED), "refused ({coherent})");
        sub.on_ecs(TOPIC, ACCEPTED, 2, 1, None, None);
        assert!(
            acknowledged_2(&credit, &ACCEPTED),
            "the control ({coherent})"
        );
    }
}

/// A standalone end-of-set marker (PID_END_COHERENT_SET), to a reader that
/// reads coherent sets and to one that does not: the refused writer's is
/// not received; the accepted writer's is acknowledged.
#[test]
fn a_refused_writers_coherent_end_marker_is_not_received() {
    for coherent in [true, false] {
        // `fsm` must outlive `sub` (see the sibling end-coherent-set test).
        let Flipped {
            fsm: _fsm,
            sub,
            credit,
            ..
        } = after_a_flip(coherent);
        sub.on_coherent_end_marker(TOPIC, FLIPPED, None, None, 1, None, 2);
        assert!(!acknowledged_2(&credit, &FLIPPED), "refused ({coherent})");
        sub.on_coherent_end_marker(TOPIC, ACCEPTED, None, None, 1, None, 2);
        assert!(
            acknowledged_2(&credit, &ACCEPTED),
            "the control ({coherent})"
        );
    }
}

/// What a participant's discovery saw of its own readers of a topic as each
/// was announced: how many reader entries of the topic the match registry
/// held then.
struct AnnouncedWith {
    topic: String,
    registry: Arc<MatchNotificationRegistry>,
    seen: Mutex<Vec<usize>>,
}

impl crate::core::discovery::multicast::DiscoveryListener for AnnouncedWith {
    fn on_endpoint_discovered(&self, endpoint: crate::core::discovery::multicast::EndpointInfo) {
        if endpoint.topic_name == self.topic
            && endpoint.kind == crate::core::discovery::multicast::EndpointKind::Reader
        {
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(self.registry.reader_entries_of(&self.topic));
        }
    }
}

/// A reader is announced only once it is registered with its match
/// registry: from its announcement on a peer's writer may send to it, and
/// an unregistered reader is matched with nothing and drops everything
/// (`writer_refused`), so a best-effort sample sent in that window would be lost.
#[test]
fn a_reader_is_announced_only_once_registered() {
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::dds::Participant::builder("pair_gate_announce")
        .domain_id(domain.id())
        .with_transport(crate::dds::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let fsm = participant
        .discovery()
        .expect("a UDP participant runs discovery");
    let registry = participant
        .match_registry
        .clone()
        .expect("a UDP participant judges its pairings");
    let topic = "pair_gate_announce";
    let observer = Arc::new(AnnouncedWith {
        topic: topic.to_string(),
        registry,
        seen: Mutex::new(Vec::new()),
    });
    fsm.register_listener(observer.clone());
    let _reader = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader");
    assert_eq!(
        *observer.seen.lock().unwrap_or_else(|e| e.into_inner()),
        vec![1],
        "announced once, its entry registered"
    );
}

/// A GAP that says its changes are filtered: the refused writer's records
/// nothing as filtered. Accepted again, its changes 2 to 4, never received,
/// are samples lost when its HEARTBEAT says they left its history.
#[test]
fn a_refused_writers_filtered_gap_records_nothing() {
    let Flipped { fsm, reg, sub, .. } = after_a_flip(false);
    sub.on_writer_gap_filtered(FLIPPED, 2, 5, vec![], 3);
    fsm.handle_sedp(announcement(FLIPPED, QoS::reliable()));
    let entry = *sub.match_entry.get().expect("registered");
    assert!(
        !reg.is_writer_refused_by(&FLIPPED, entry),
        "fixture: accepted again"
    );
    sub.on_writer_heartbeat(FLIPPED, 5);
    assert_eq!(lost(&sub), 3, "2, 3 and 4 lost, none filtered");
}

/// The end of a set its writer staged before it was refused
/// (PID_END_COHERENT_SET on a sample of the set, no marker of its own):
/// the refused writer's commits nothing; the accepted writer's commits its
/// set.
#[test]
fn a_refused_writers_coherent_end_commits_nothing() {
    // `fsm` must outlive `sub` (see `a_refused_writers_end_coherent_set_is_not_received`).
    let Flipped {
        fsm: _fsm,
        ring,
        sub,
        ..
    } = after_a_flip_with(true, |sub| {
        for writer in [FLIPPED, ACCEPTED] {
            sub.on_data_coherent(
                TOPIC,
                writer,
                2,
                &encoded_point(2, 2),
                crate::dds::CdrVersion::Xcdr2,
                Some(2),
                None,
                None,
            );
        }
    });
    assert_eq!(taken(&ring), 0, "fixture: both sets staged");
    sub.on_coherent_end(TOPIC, FLIPPED, None, None, Some(2), None);
    assert_eq!(taken(&ring), 0, "refused");
    sub.on_coherent_end(TOPIC, ACCEPTED, None, None, Some(2), None);
    assert_eq!(taken(&ring), 1, "the control commits its set");
}

/// A writer never discovered via SEDP at all, on a reader whose PARTITION is non-default ("a").
///
/// Two mechanisms could refuse it, and neither is `writer_shut_out`'s own
/// `writer_refused`: `is_writer_refused_by` answers `false` for a writer
/// it never judged (unknown, not "refused" -- the same fact
/// `an_undiscovered_writers_coherent_set_is_never_staged` above pins for
/// the DATA path). A DISCOVERED writer whose announced PARTITION
/// genuinely does not intersect this reader's IS caught, but indirectly:
/// `rxo_verdict` folds PARTITION into its QoS verdict
/// (`matcher::qos::first_incompatible`), and `record_pair_qos` records
/// ANY `rxo_verdict` error as `Refusal::QOS` -- including the
/// `policy_id == 0` ("partition or unknown") case -- so `writer_refused`
/// already returns `true` for a judged-and-mismatched writer. It is only
/// the UNDISCOVERED case that slips through `writer_refused`, and
/// `writer_partition_incompatible` is the gate DDS v1.4 sec. 2.2.3.13 names
/// for exactly it ("a partitioned reader is not matched to an
/// undiscovered writer... drop the sample until its SEDP confirms a
/// compatible partition") -- a gate `writer_shut_out` must consult.
const UNDISCOVERED_GROUP: [u8; 16] = [
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0, 0, 0x0A, 0x02,
];
/// The control: discovered, PARTITION `"a"`, matches the reader below.
const DISCOVERED_SAME_PARTITION: [u8; 16] = [
    0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0x0E, 0, 0, 0x0B, 0x02,
];

/// A GROUP-scope coherent reader whose PARTITION is `"a"`, registered
/// against discovery where `DISCOVERED_SAME_PARTITION` (also `"a"`) is
/// announced and `UNDISCOVERED_GROUP` is not announced at all.
fn reader_group_scope_partitioned() -> (
    Arc<DiscoveryFsm>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    let (fsm, reg) = discovery_where(true);
    fsm.handle_sedp(announcement(
        DISCOVERED_SAME_PARTITION,
        QoS::reliable().partition(crate::qos::partition::Partition::single("a")),
    ));
    let sub = group_partition_reader(&reg, crate::qos::partition::Partition::single("a"), None);
    (fsm, sub)
}

fn group_partition_reader(
    reg: &Arc<MatchNotificationRegistry>,
    partition: crate::qos::partition::Partition,
    topics: Option<Arc<crate::engine::TopicRegistry>>,
) -> super::subscriber::ReaderSubscriber<Point> {
    let _ = rt::init_slab_pool();
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        TOPIC.to_string(),
        ring,
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
        Some(reg.clone()),
        None,
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        partition.clone(),
        crate::qos::ownership::OwnershipKind::default(),
        topics,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    sub.register_match_entry_for_test(QoS::reliable().partition(partition));
    sub
}

/// Isolated to the case `writer_refused` genuinely cannot see (see the const
/// doc above): an UNDISCOVERED writer must not move this reader's GROUP state
/// through `on_writer_group_heartbeat` (nor through the same gate's 4
/// siblings: `on_group_change`, `on_ecs`, `on_coherent_end`,
/// `on_coherent_end_marker`), so each of them must consult
/// `writer_partition_incompatible`, the one gate DDS v1.4 sec. 2.2.3.13
/// gives a partitioned reader against an undiscovered writer.
///
/// Mutant: dropping the `writer_partition_incompatible` call from
/// `writer_shut_out` (leaving `writer_refused` plus the security check
/// alone) makes this fail: `UNDISCOVERED_GROUP` would be recorded in
/// `writer_gsns` exactly like the control.
#[test]
fn an_undiscovered_writers_group_heartbeat_moves_no_state_on_a_partitioned_reader() {
    let (_fsm, sub) = reader_group_scope_partitioned();

    sub.on_writer_group_heartbeat(UNDISCOVERED_GROUP, 5, 1, 5);
    assert!(
        !sub.writer_gsns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&UNDISCOVERED_GROUP),
        "an undiscovered writer is no writer of this reader's GROUP sets, \
         PARTITION included"
    );

    // Control: the discovered, same-partition writer's heartbeat IS
    // recorded.
    sub.on_writer_group_heartbeat(DISCOVERED_SAME_PARTITION, 5, 1, 5);
    assert!(
        sub.writer_gsns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&DISCOVERED_SAME_PARTITION),
        "the control writer's GroupInfo must still be recorded"
    );
}
/// DDS 1.4 Sec.2.2.3.6 and Sec.2.2.3.13: only a matched writer may
/// supply a GROUP writer set, heartbeat or end. The default partition
/// carries the same discovery requirement as a named partition.
#[test]
fn group_controls_from_undiscovered_default_partition_writer_move_nothing() {
    let (_fsm, reg) = discovery_where(true);
    let sub = group_partition_reader(&reg, Default::default(), None);
    group_controls(&sub, UNDISCOVERED_GROUP);
    assert!(sub.writer_gsns.lock().expect("GSNs").is_empty());
    assert!(sub.group_coherent_buffer.lock().expect("sets").is_empty());
}

fn group_controls(sub: &super::subscriber::ReaderSubscriber<Point>, writer: [u8; 16]) {
    let publisher = [0, 0, 3, 0x09];
    sub.on_writer_group_heartbeat(writer, 5, 1, 5);
    sub.on_group_change(
        writer,
        crate::engine::subscriber::GroupChange {
            seq: 1,
            group_sn: 5,
            publisher_entity_id: publisher,
            writer_set: [1; 4],
            gsn: Some(5),
            part_first_sn: None,
        },
    );
    sub.on_ecs(TOPIC, writer, 2, 1, Some(6), Some(publisher));
    sub.on_coherent_end(TOPIC, writer, Some(7), Some(publisher), Some(1), None);
    sub.on_coherent_end_marker(TOPIC, writer, Some(8), Some(publisher), 1, None, 3);
}

/// DDS 1.4 Sec.2.2.3.13: named and default readers both exclude a
/// discovered writer whose partitions have no common name. Test the
/// standalone partition gate without a discovery pair-refusal record.
#[test]
fn group_controls_require_matching_partition_including_default_reader() {
    use crate::qos::partition::Partition;
    for partition in [Partition::default(), Partition::single("a")] {
        let (_fsm, reg) = discovery_where(true);
        let topics = routed(&[REFUSED, ACCEPTED]);
        topics.register_writer_partition(REFUSED, Partition::single("b"));
        topics.register_writer_partition(ACCEPTED, partition.clone());
        let sub = group_partition_reader(&reg, partition, Some(topics));
        group_controls(&sub, REFUSED);
        assert!(sub.writer_gsns.lock().expect("GSNs").is_empty());
        assert!(sub.group_coherent_buffer.lock().expect("sets").is_empty());
        sub.on_writer_group_heartbeat(ACCEPTED, 5, 1, 5);
        assert!(sub
            .writer_gsns
            .lock()
            .expect("GSNs")
            .contains_key(&ACCEPTED));
    }
}

/// DDS 1.4 Sec.2.2.3.13: PARTITION is mutable, so a new announcement
/// replaces a previous refusal as well as a previous acceptance.
#[test]
fn group_partition_verdict_tracks_reannounced_partition() {
    use crate::qos::partition::Partition;
    for partition in [Partition::default(), Partition::single("a")] {
        let (_fsm, reg) = discovery_where(true);
        let topics = routed(&[ACCEPTED]);
        topics.register_writer_partition(ACCEPTED, Partition::single("b"));
        let sub = group_partition_reader(&reg, partition.clone(), Some(topics.clone()));
        sub.on_writer_group_heartbeat(ACCEPTED, 5, 1, 5);
        assert!(sub.writer_gsns.lock().expect("GSNs").is_empty());

        topics.register_writer_partition(ACCEPTED, partition);
        sub.on_writer_qos_resolved(ACCEPTED);
        sub.on_writer_group_heartbeat(ACCEPTED, 5, 1, 5);
        assert!(sub
            .writer_gsns
            .lock()
            .expect("GSNs")
            .contains_key(&ACCEPTED));

        topics.register_writer_partition(ACCEPTED, Partition::single("b"));
        sub.on_writer_qos_resolved(ACCEPTED);
        sub.writer_gsns.lock().expect("GSNs").clear();
        group_controls(&sub, ACCEPTED);
        assert!(sub.writer_gsns.lock().expect("GSNs").is_empty());
        assert!(sub.group_coherent_buffer.lock().expect("sets").is_empty());
    }
}

/// DDS 1.4 Sec.2.2.3.6: a known writer's last coherent set remains
/// admissible after discovery removed its participant, including when no
/// partition verdict was cached before that removal.
#[test]
fn group_partition_verdict_resolves_cold_from_durable_metadata_after_departure() {
    use crate::qos::partition::Partition;
    for partition in [Partition::default(), Partition::single("a")] {
        let (fsm, reg) = discovery_where(true);
        let topics = routed(&[REFUSED, ACCEPTED]);
        for (writer, offered) in [
            (REFUSED, Partition::single("b")),
            (ACCEPTED, partition.clone()),
        ] {
            topics.register_writer_partition(writer, offered.clone());
            fsm.handle_sedp(announcement(writer, QoS::reliable().partition(offered)));
        }
        let sub = group_partition_reader(&reg, partition, Some(topics.clone()));
        assert!(sub.writer_gsns.lock().expect("GSNs").is_empty());
        fsm.remove_participant(GUID::new(PEER, [0, 0, 1, 0xC1]));
        assert!(reg.resolve_writer_partition(TOPIC, &ACCEPTED).is_none());
        assert!(topics.get_topic_by_guid(&ACCEPTED).is_some());
        group_controls(&sub, REFUSED);
        assert!(sub.writer_gsns.lock().expect("GSNs").is_empty());
        assert!(sub.group_coherent_buffer.lock().expect("sets").is_empty());
        sub.on_data_coherent(
            TOPIC,
            ACCEPTED,
            1,
            &encoded_point(1, 1),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(5),
            None,
        );
        sub.on_ecs(TOPIC, ACCEPTED, 2, 1, Some(5), None);
        assert_eq!(taken(&sub.ring), 1, "the final compatible set commits");
        sub.on_writer_group_heartbeat(ACCEPTED, 5, 1, 5);
        assert!(sub
            .writer_gsns
            .lock()
            .expect("GSNs")
            .contains_key(&ACCEPTED));
    }
}

/// DATA without inline QoS (RTPS 2.5 8.3.8.2). The addressed reader is
/// already known locally even when the writer's SEDP is still in flight.
fn directed_early_packet(reader: [u8; 4], seq: u32) -> Vec<u8> {
    directed_early_packet_tagged(reader, seq, seq as i32)
}

/// As `directed_early_packet`, with `tag` as the payload's `x`: a taken
/// sample then names the writer incarnation that sent it.
fn directed_early_packet_tagged(reader: [u8; 4], seq: u32, tag: i32) -> Vec<u8> {
    let data = encoded_point(tag, seq as i32);
    let mut packet = b"RTPS\x02\x05\x01\x1a".to_vec();
    packet.extend_from_slice(&PEER);
    packet.extend_from_slice(&[0x15, 0x05]);
    packet.extend_from_slice(
        &u16::try_from(24 + data.len())
            .expect("small DATA")
            .to_le_bytes(),
    );
    packet.extend_from_slice(&[0, 0, 16, 0]);
    packet.extend_from_slice(&reader);
    packet.extend_from_slice(&ACCEPTED[12..]);
    packet.extend_from_slice(&0u32.to_le_bytes());
    packet.extend_from_slice(&seq.to_le_bytes());
    packet.extend_from_slice(&[0, 9, 0, 0]);
    packet.extend_from_slice(&data);
    packet
}

#[derive(Clone)]
struct EarlyDirected {
    /// Unregisters `sub` from `topics` once the last clone drops (the
    /// subscriber holds the registry and the registry the subscriber).
    _registration: Arc<crate::engine::SubscriberToken>,
    fsm: Arc<DiscoveryFsm>,
    topics: Arc<crate::engine::TopicRegistry>,
    credit: crate::core::reader::ReaderAckCredit,
    ring: Arc<rt::IndexRing>,
    sub: Arc<super::subscriber::ReaderSubscriber<Point>>,
}

impl EarlyDirected {
    const READER: [u8; 4] = [0, 0, 7, 7];

    fn new() -> Self {
        Self::with_qos(QoS::reliable())
    }

    fn with_qos(qos: QoS) -> Self {
        Self::configured(qos, |_| {})
    }

    fn configured(
        qos: QoS,
        configure: impl FnOnce(&mut super::subscriber::ReaderSubscriber<Point>),
    ) -> Self {
        let qos = qos.data_representation_xcdr2();
        let reliable = qos.reliability == crate::dds::qos::Reliability::Reliable;
        let (fsm, reg) = discovery_where(true);
        let topics = routed(&[]);
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            GUID::new(LOCAL, Self::READER).as_bytes(),
        );
        let (_, mut sub) = reader_with(
            &reg,
            false,
            false,
            Some(topics.clone()),
            reliable.then(|| credit.clone()),
        );
        if !reliable {
            sub.reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new_best_effort()));
        }
        // Register the real peer hook: discovery creates a proxy only for
        // a compatible pair, as in ReaderBuilder, including inside probation.
        let callback_credit = credit.clone();
        let peer = reliable.then(|| {
            Box::new(move |change: PeerChange| match change {
                PeerChange::Matched { guid, .. } => callback_credit.match_writer(guid.as_bytes()),
                PeerChange::Unmatched { guid } => callback_credit.unmatch_writer(&guid.as_bytes()),
            }) as crate::dds::match_notification::PeerCallback
        });
        sub.register_match_entry_with_peer_for_test(qos, peer);
        let ring = Arc::new(rt::IndexRing::with_capacity(256));
        sub.ring = ring.clone();
        sub.reader_entity_id = Some(Self::READER);
        configure(&mut sub);
        let sub = Arc::new(sub);
        let registration = topics
            .register_subscriber_scoped(sub.clone())
            .expect("reader");
        Self {
            _registration: Arc::new(registration),
            fsm,
            topics,
            credit,
            ring,
            sub,
        }
    }

    fn route(&self, reader: [u8; 4], seq: u32) -> crate::engine::router::RouteStatus {
        self.route_tagged(reader, seq, seq as i32)
    }

    fn route_tagged(
        &self,
        reader: [u8; 4],
        seq: u32,
        tag: i32,
    ) -> crate::engine::router::RouteStatus {
        let packet = directed_early_packet_tagged(reader, seq, tag);
        crate::engine::router::route_data_packet(
            &packet,
            packet.len(),
            None,
            &self.topics,
            &crate::engine::router::RouterMetrics::new(),
        )
    }

    fn publish(&self, qos: QoS) {
        self.topics
            .register_writer_guid(ACCEPTED, TOPIC.to_string());
        self.topics
            .register_writer_ownership_kind(ACCEPTED, crate::qos::ownership::OwnershipKind::Shared);
        self.fsm
            .handle_sedp(announcement(ACCEPTED, qos.data_representation_xcdr2()));
    }

    fn resolve(&self, qos: QoS) {
        self.publish(qos);
        // The SEDP handler wakes the deferred subscriber after discovery
        // has judged the pair and run its peer callback.
        assert!(self.topics.notify_writer_qos_resolved(ACCEPTED));
    }

    fn sequences(&self) -> Vec<u32> {
        let pool = rt::get_slab_pool();
        let mut result = Vec::new();
        while let Some(entry) = self.ring.pop() {
            result.push(entry.seq);
            pool.release(entry.handle);
        }
        result
    }

    /// Taken samples as (seq, stored payload): what the application reads.
    fn delivered(&self) -> Vec<(u32, Vec<u8>)> {
        let pool = rt::get_slab_pool();
        let mut result = Vec::new();
        while let Some(entry) = self.ring.pop() {
            let bytes = pool.get_buffer(entry.handle);
            result.push((entry.seq, bytes[16..entry.len as usize].to_vec()));
            drop(bytes);
            pool.release(entry.handle);
        }
        result
    }
}

/// A directed DATA has already missed writer routing when SEDP publishes
/// its topic and OWNERSHIP, but has not judged the pair yet. DDS v1.4
/// Sec.2.2.3 requires the pair verdict before any application delivery.
fn directed_data_during_sedp_metadata(reader_qos: QoS, qos: QoS, expected: Vec<u32>) {
    let reader = EarlyDirected::with_qos(reader_qos);
    let (data_paused, data_ready) = std::sync::mpsc::channel();
    let (data_resume, data_wait) = std::sync::mpsc::channel();
    *reader.sub.pair_gate_hook.lock().expect("hook") = Some(Box::new(move || {
        data_paused.send(()).expect("DATA paused");
        data_wait.recv().expect("resume DATA");
    }));
    let receiving = reader.clone();
    let data = std::thread::spawn(move || receiving.route(EarlyDirected::READER, 1));
    let timeout = std::time::Duration::from_secs(10);
    data_ready
        .recv_timeout(timeout)
        .expect("DATA reached reader");

    let (sedp_paused, sedp_ready) = std::sync::mpsc::channel();
    let (sedp_resume, sedp_wait) = std::sync::mpsc::channel();
    // resolve() publishes the router's metadata before entering the FSM.
    // Its admission hook stops before the type and QoS pair judgments.
    let sedp_wait = Mutex::new(sedp_wait);
    reader.fsm.set_sedp_admitted_hook(Box::new(move || {
        sedp_paused.send(()).expect("SEDP paused");
        sedp_wait
            .lock()
            .expect("resume lock")
            .recv()
            .expect("resume SEDP");
    }));
    let discovering = reader.clone();
    let sedp = std::thread::spawn(move || discovering.resolve(qos));
    sedp_ready
        .recv_timeout(timeout)
        .expect("SEDP published metadata");
    data_resume.send(()).expect("resume DATA");
    data.join().expect("DATA thread");
    let premature = reader.sequences();
    let premature_credit = reader.credit.settled(&ACCEPTED);
    sedp_resume.send(()).expect("resume SEDP");
    sedp.join().expect("SEDP thread");

    assert!(premature.is_empty(), "metadata is not a pair verdict");
    assert_eq!(
        premature_credit, None,
        "unjudged DATA receives no ACK credit"
    );
    assert_eq!(reader.sequences(), expected);
    // A repeated discovery notification must not deliver the sample again.
    assert!(reader.topics.notify_writer_qos_resolved(ACCEPTED));
    assert!(reader.sequences().is_empty());
}

#[test]
fn directed_data_during_sedp_metadata_waits_for_acceptance() {
    directed_data_during_sedp_metadata(QoS::reliable(), QoS::reliable(), vec![1]);
}

#[test]
fn directed_data_during_sedp_metadata_waits_for_refusal() {
    directed_data_during_sedp_metadata(QoS::reliable(), QoS::best_effort(), vec![]);
}

fn type_validating_reader_qos() -> QoS {
    QoS {
        type_consistency: Some(
            crate::protocol::discovery::types::TypeConsistencyEnforcement {
                force_type_validation: true,
                ..Default::default()
            },
        ),
        ..QoS::reliable()
    }
}

/// DDS-XTypes v1.3 Sec.7.6.3.4.2: a reader forcing type validation must
/// refuse an unknown type even when all offered QoS values are compatible.
#[test]
fn directed_data_during_sedp_metadata_waits_for_type_refusal() {
    directed_data_during_sedp_metadata(type_validating_reader_qos(), QoS::reliable(), vec![]);
}

/// A SEDP held for an unknown participant has its QoS judged at once, but
/// that alone is not a type verdict (DDS-XTypes v1.3 Sec.7.6.3.4.2).
#[test]
fn directed_data_with_held_sedp_requires_a_type_verdict() {
    let reader = EarlyDirected::with_qos(type_validating_reader_qos());
    reader
        .fsm
        .remove_participant(GUID::new(PEER, [0, 0, 1, 0xC1]));
    reader.route(EarlyDirected::READER, 1);
    assert!(reader.sequences().is_empty());
    reader.resolve(QoS::reliable());
    assert!(
        reader.sequences().is_empty(),
        "QoS alone cannot admit an unvalidated type"
    );
    assert_eq!(reader.credit.settled(&ACCEPTED), None);
}

/// DDS 1.4 2.2.3.4: VOLATILE does not discard writes made after the
/// writer knew this reader. Asymmetric discovery is not a second join.
#[test]
fn directed_data_before_sedp_waits_for_the_matching_writer() {
    let reader = EarlyDirected::new();
    for seq in 1..=32 {
        assert_eq!(
            reader.route(EarlyDirected::READER, seq),
            crate::engine::router::RouteStatus::Delivered
        );
    }
    assert!(
        reader.sequences().is_empty(),
        "not admitted before discovery"
    );
    assert!(!reader.credit.is_matched(&ACCEPTED), "no early ACK credit");
    assert!(
        reader.topics.get_topic_by_guid(&ACCEPTED).is_none(),
        "no guessed writer binding"
    );
    reader.resolve(QoS::reliable());
    assert_eq!(reader.sequences(), (1..=32).collect::<Vec<_>>());
    reader.route(EarlyDirected::READER, 33);
    reader.route(EarlyDirected::READER, 1);
    assert_eq!(
        reader.sequences(),
        vec![33],
        "repair is not a duplicate delivery"
    );
    assert_eq!(reader.credit.settled(&ACCEPTED), Some(33));
}

/// RTPS 2.5 Sec.8.4.12.1 T2: once discovery admits a writer, each
/// received increasing sequence reaches the history without waiting for
/// another DATA. The addressed burst precedes the writer's SEDP.
#[test]
fn best_effort_directed_burst_before_sedp_reaches_history_in_order() {
    let reader = EarlyDirected::with_qos(QoS::best_effort().keep_last(100));
    for seq in 1..=32 {
        reader.route(EarlyDirected::READER, seq);
    }
    assert!(reader.sequences().is_empty());
    reader.resolve(QoS::best_effort().transient_local());
    assert_eq!(reader.sequences(), (1..=32).collect::<Vec<_>>());
    for seq in 33..=100 {
        reader.route(EarlyDirected::READER, seq);
        assert_eq!(reader.sequences(), vec![seq]);
    }
}

/// RTPS 2.5 Sec.8.4.12.1 T2: discovery releasing received DATA cannot
/// make a later live DATA discard the tail of that same received burst.
#[test]
fn best_effort_live_data_cannot_overtake_a_deferred_burst() {
    let reader = EarlyDirected::with_qos(QoS::best_effort().keep_last(100));
    for seq in 1..=32 {
        reader.route(EarlyDirected::READER, seq);
    }
    let (paused, ready) = std::sync::mpsc::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    let wait = Arc::new(Mutex::new(wait));
    *reader.sub.delivered_hook.lock().expect("hook") = Some(Arc::new(move |seq| {
        if seq == 10 {
            paused.send(()).expect("delivery paused");
            wait.lock()
                .expect("resume lock")
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("resume delivery");
        }
    }));
    let flushing = reader.clone();
    let worker = std::thread::spawn(move || {
        flushing.resolve(QoS::best_effort().transient_local());
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("ten deferred samples reached history");
    let first = reader.sequences();
    let live = reader.clone();
    let (finished, done) = std::sync::mpsc::channel();
    let arriving = std::thread::spawn(move || {
        live.route(EarlyDirected::READER, 33);
        finished.send(()).expect("live DATA finished");
    });
    // A valid implementation may let live DATA help the drain or wait
    // for it. Release the delivery pause in either case, without requiring
    // that route() return while delivery is paused.
    let _ = done.recv_timeout(std::time::Duration::from_millis(100));
    resume.send(()).expect("resume flush");
    arriving.join().expect("live DATA thread");
    worker.join().expect("flush thread");
    assert_eq!(first, (1..=10).collect::<Vec<_>>());
    let mut received = first;
    received.extend(reader.sequences());
    for seq in 34..=100 {
        reader.route(EarlyDirected::READER, seq);
        received.extend(reader.sequences());
    }
    assert_eq!(received, (1..=100).collect::<Vec<_>>());
}

/// RTPS 2.5 Sec.8.4.12.1 T2: DATA that starts admission of a
/// received burst must not evict its first sample from pre-match storage.
#[test]
fn best_effort_live_data_preserves_a_full_discovery_backlog() {
    let reader = EarlyDirected::with_qos(QoS::best_effort().keep_last(100));
    for seq in 1..=64 {
        reader.route(EarlyDirected::READER, seq);
    }
    // Publish a compatible verdict before the subscriber's wake callback,
    // just as the SEDP handler does. The next DATA starts the drain.
    reader
        .topics
        .register_writer_guid(ACCEPTED, TOPIC.to_string());
    reader
        .topics
        .register_writer_ownership_kind(ACCEPTED, crate::qos::ownership::OwnershipKind::Shared);
    reader.fsm.handle_sedp(announcement(
        ACCEPTED,
        QoS::best_effort().data_representation_xcdr2(),
    ));
    reader.route(EarlyDirected::READER, 65);
    assert_eq!(reader.sequences(), (1..=65).collect::<Vec<_>>());
}

/// RTPS 2.5 Sec.8.4.12.1 T2: an application panic on one received
/// change does not discard later received changes of the same writer.
#[test]
fn best_effort_discovery_drain_finishes_after_a_preparation_panic() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (paused, ready) = std::sync::mpsc::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    let wait = Mutex::new(wait);
    let calls = AtomicUsize::new(0);
    let reader = EarlyDirected::configured(QoS::best_effort().keep_last(100), |sub| {
        sub.content_filter = Some(
            crate::dds::filter::ContentFilter::new("x > 0")
                .expect("filter")
                .evaluator(),
        );
        sub.field_extractor = Some(Arc::new(move |_: &Point| {
            if calls.fetch_add(1, Ordering::Relaxed) == 9 {
                paused.send(()).expect("preparation paused");
                wait.lock()
                    .expect("resume lock")
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .expect("resume preparation");
                panic!("field extraction failed");
            }
            Some(std::collections::HashMap::from([(
                "x".to_string(),
                crate::dds::filter::FieldValue::Integer(1),
            )]))
        }));
    });
    for seq in 1..=32 {
        reader.route(EarlyDirected::READER, seq);
    }
    let discovering = reader.clone();
    let worker = std::thread::spawn(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            discovering.publish(QoS::best_effort());
            discovering.sub.on_writer_qos_resolved(ACCEPTED);
        }))
    });
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("tenth sample reached preparation");
    // This arrival hands its DATA to the paused drain and returns. No
    // later DATA or SEDP notification may be needed to finish that work.
    reader.route(EarlyDirected::READER, 33);
    resume.send(()).expect("resume preparation");
    assert!(
        worker.join().expect("discovery thread").is_err(),
        "panic is propagated"
    );
    let expected = (1..=33).filter(|seq| *seq != 10).collect::<Vec<_>>();
    assert_eq!(reader.sequences(), expected);
    reader.route(EarlyDirected::READER, 34);
    assert_eq!(reader.sequences(), vec![34]);
}

/// RTPS 2.5 Sec.8.4.12.1 T1/T3: removing a writer removes its reader
/// state. A successor with the same GUID cannot inherit old received DATA.
#[test]
fn discovery_drain_does_not_admit_a_departed_writers_extracted_tail() {
    let reader = EarlyDirected::with_qos(QoS::best_effort().keep_last(100));
    for seq in 1..=32 {
        reader.route(EarlyDirected::READER, seq);
    }
    let (paused, ready) = std::sync::mpsc::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    let wait = Mutex::new(wait);
    *reader.sub.delivered_hook.lock().expect("hook") = Some(Arc::new(move |seq| {
        if seq == 10 {
            paused.send(()).expect("delivery paused");
            wait.lock()
                .expect("resume lock")
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("resume delivery");
        }
    }));
    let discovering = reader.clone();
    let worker = std::thread::spawn(move || discovering.resolve(QoS::best_effort()));
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("tenth sample reached history");
    assert_eq!(reader.sequences(), (1..=10).collect::<Vec<_>>());
    // Include DATA entrusted to the old drainer, as well as its local tail.
    reader.route(EarlyDirected::READER, 33);
    reader.sub.on_writer_departure(
        TOPIC,
        ACCEPTED,
        DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    reader.resolve(QoS::best_effort());
    reader.route(EarlyDirected::READER, 1);
    resume.send(()).expect("resume old drain");
    worker.join().expect("discovery thread");
    assert_eq!(reader.sequences(), vec![1], "only the successor's sample");
    reader.route(EarlyDirected::READER, 2);
    assert_eq!(
        reader.sequences(),
        vec![2],
        "old DATA cannot advance its watermark"
    );
}

/// The incarnation check is at admission, after application decoding and
/// extraction. A departure of a different writer does not invalidate it.
#[test]
fn discovery_drain_checks_the_writers_incarnation_at_admission() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for departing in [ACCEPTED, REFUSED] {
        let (paused, ready) = std::sync::mpsc::channel();
        let (resume, wait) = std::sync::mpsc::channel();
        let wait = Mutex::new(wait);
        let calls = AtomicUsize::new(0);
        let reader = EarlyDirected::configured(QoS::best_effort().keep_last(100), |sub| {
            sub.content_filter = Some(
                crate::dds::filter::ContentFilter::new("x > 0")
                    .expect("filter")
                    .evaluator(),
            );
            sub.field_extractor = Some(Arc::new(move |_: &Point| {
                if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    paused.send(()).expect("preparation paused");
                    wait.lock()
                        .expect("resume lock")
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .expect("resume preparation");
                }
                Some(std::collections::HashMap::from([(
                    "x".to_string(),
                    crate::dds::filter::FieldValue::Integer(1),
                )]))
            }));
        });
        for seq in 20..=22 {
            reader.route(EarlyDirected::READER, seq);
        }
        let discovering = reader.clone();
        let worker = std::thread::spawn(move || discovering.resolve(QoS::best_effort()));
        ready
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("sample reached preparation");
        reader.sub.on_writer_departure(
            TOPIC,
            departing,
            DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
        if departing == ACCEPTED {
            reader.resolve(QoS::best_effort());
            reader.route(EarlyDirected::READER, 1);
        }
        resume.send(()).expect("resume old sample");
        worker.join().expect("discovery thread");
        let expected = if departing == ACCEPTED {
            vec![1]
        } else {
            vec![20, 21, 22]
        };
        assert_eq!(reader.sequences(), expected);
    }
}

/// RTPS 2.5 Sec.8.4.10.3, 8.4.12.1: a removed WriterProxy's sequence
/// state cannot be inherited by a new writer under the same GUID.
#[test]
fn direct_data_checks_the_writers_incarnation_at_admission() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for departing in [ACCEPTED, REFUSED] {
        let (paused, ready) = std::sync::mpsc::channel();
        let (resume, wait) = std::sync::mpsc::channel();
        let wait = Mutex::new(wait);
        let calls = AtomicUsize::new(0);
        let reader = EarlyDirected::configured(QoS::best_effort().keep_last(100), |sub| {
            sub.content_filter = Some(
                crate::dds::filter::ContentFilter::new("x > 0")
                    .expect("filter")
                    .evaluator(),
            );
            sub.field_extractor = Some(Arc::new(move |_: &Point| {
                if calls.fetch_add(1, Ordering::Relaxed) == 0 {
                    paused.send(()).expect("preparation paused");
                    wait.lock()
                        .expect("resume lock")
                        .recv_timeout(std::time::Duration::from_secs(10))
                        .expect("resume preparation");
                }
                Some(std::collections::HashMap::from([(
                    "x".to_string(),
                    crate::dds::filter::FieldValue::Integer(1),
                )]))
            }));
        });
        reader.resolve(QoS::best_effort());
        let receiving = reader.clone();
        let worker = std::thread::spawn(move || receiving.route(EarlyDirected::READER, 20));
        ready
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("direct DATA reached preparation");
        reader.sub.on_writer_departure(
            TOPIC,
            departing,
            DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
        if departing == ACCEPTED {
            reader.resolve(QoS::best_effort());
            reader.route(EarlyDirected::READER, 1);
        }
        resume.send(()).expect("resume old DATA");
        worker.join().expect("receive thread");
        let expected = if departing == ACCEPTED {
            vec![1]
        } else {
            vec![20]
        };
        assert_eq!(reader.sequences(), expected, "departing={departing:02x?}");
        let next = if departing == ACCEPTED { 2 } else { 21 };
        reader.route(EarlyDirected::READER, next);
        assert_eq!(reader.sequences(), vec![next], "fresh DATA is admissible");
    }
}

/// Old-incarnation DATA that passed the door before its writer left, and
/// is still ahead of the OWNERSHIP gate when the writer comes back under
/// the same GUID (its re-announcement lifts `has_left`), must neither be
/// delivered nor hold the successor's sequence slot. Checked by take():
/// the successor's seq 1..=25 arrive once each, in order, carrying its own
/// payload; the old seq 20 (payload tag 900) never appears.
#[test]
fn old_incarnation_data_before_the_ownership_gate_is_not_admitted_to_successor() {
    const OLD: i32 = 900;
    const NEW: i32 = 1;
    let reader = EarlyDirected::new();
    reader.resolve(QoS::reliable());
    let (paused, ready) = std::sync::mpsc::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    *reader.sub.pair_gate_hook.lock().expect("hook") = Some(Box::new(move || {
        paused.send(()).expect("old DATA paused");
        wait.recv().expect("resume old DATA");
    }));
    let receiving = reader.clone();
    let worker = std::thread::spawn(move || receiving.route_tagged(EarlyDirected::READER, 20, OLD));
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("old DATA reached the door");
    reader.sub.on_writer_departure(
        TOPIC,
        ACCEPTED,
        DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    // The same GUID comes back: its announcement lifts the door.
    reader.resolve(QoS::reliable());
    reader.route_tagged(EarlyDirected::READER, 1, NEW);
    resume.send(()).expect("resume old DATA");
    worker.join().expect("receive thread");
    for seq in 2..=25 {
        reader.route_tagged(EarlyDirected::READER, seq, NEW);
    }
    let taken = reader.delivered();
    let expected: Vec<(u32, Vec<u8>)> = (1..=25)
        .map(|seq| (seq, encoded_point(NEW, seq as i32)))
        .collect();
    assert_eq!(
        taken, expected,
        "successor's seq 1..=25 once each in order; no stale old-incarnation sample"
    );
}

/// Same setup as the test above, but the successor first delivers seq
/// 1..=19, so the stale seq 20 is in order when the paused DATA resumes.
/// Admitted there, it is taken as seq 20 with the old payload, and the
/// successor's own seq 20 is deduplicated away.
#[test]
fn stale_data_released_in_order_after_the_successor_is_not_admitted() {
    const OLD: i32 = 900;
    const NEW: i32 = 1;
    let reader = EarlyDirected::new();
    reader.resolve(QoS::reliable());
    let (paused, ready) = std::sync::mpsc::channel();
    let (resume, wait) = std::sync::mpsc::channel();
    *reader.sub.pair_gate_hook.lock().expect("hook") = Some(Box::new(move || {
        paused.send(()).expect("old DATA paused");
        wait.recv().expect("resume old DATA");
    }));
    let receiving = reader.clone();
    let worker = std::thread::spawn(move || receiving.route_tagged(EarlyDirected::READER, 20, OLD));
    ready
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("old DATA reached the door");
    reader.sub.on_writer_departure(
        TOPIC,
        ACCEPTED,
        DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    // The same GUID comes back: its announcement lifts the door.
    reader.resolve(QoS::reliable());
    for seq in 1..=19 {
        reader.route_tagged(EarlyDirected::READER, seq, NEW);
    }
    resume.send(()).expect("resume old DATA");
    worker.join().expect("receive thread");
    for seq in 20..=25 {
        reader.route_tagged(EarlyDirected::READER, seq, NEW);
    }
    let taken = reader.delivered();
    let expected: Vec<(u32, Vec<u8>)> = (1..=25)
        .map(|seq| (seq, encoded_point(NEW, seq as i32)))
        .collect();
    assert_eq!(
        taken, expected,
        "successor's seq 1..=25 once each in order; no stale old-incarnation sample"
    );
}

/// RTPS 2.5 8.4.10.4/8.4.12.2: a bounded pre-match holding area may
/// evict DATA, but must leave it unacknowledged and deliver its repair
/// before the later changes it kept.
#[test]
fn directed_data_evicted_before_sedp_is_requested_and_delivered_in_order() {
    let reader = EarlyDirected::new();
    reader.route(EarlyDirected::READER, 2);
    reader.route(EarlyDirected::READER, 1);
    for seq in 3..=70 {
        reader.route(EarlyDirected::READER, seq);
    }
    reader.resolve(QoS::reliable());
    assert!(
        reader.sequences().is_empty(),
        "waiting for the evicted prefix"
    );
    let answer = reader
        .credit
        .answer_heartbeat(
            &ACCEPTED,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: 70,
                count: 1,
                final_flag: false,
            },
        )
        .expect("matched reader answers");
    assert_eq!(answer.bitmap_base, 1);
    assert_eq!(answer.missing, (1..=6).collect::<Vec<_>>());
    assert!(!answer.final_flag);
    for seq in answer.missing {
        reader.route(EarlyDirected::READER, seq as u32);
    }
    assert_eq!(reader.sequences(), (1..=70).collect::<Vec<_>>());
    assert_eq!(reader.credit.settled(&ACCEPTED), Some(70));
}

/// Discovery still judges the pair: an addressed reader is no permission
/// to deliver a best-effort writer to a reliable reader (DDS 1.4 2.2.3.14).
#[test]
fn directed_data_before_sedp_is_discarded_when_the_pair_is_refused() {
    let reader = EarlyDirected::new();
    reader.route(EarlyDirected::READER, 1);
    reader.resolve(QoS::best_effort());
    assert!(reader.sequences().is_empty());
    assert_eq!(reader.credit.settled(&ACCEPTED), None);
    assert!(!reader.credit.is_matched(&ACCEPTED));
}

/// RTPS 2.5 8.3.8.2: ENTITYID_UNKNOWN names no particular topic. A DATA
/// naming another reader cannot be assigned to this one either.
#[test]
fn an_unannounced_writer_cannot_guess_a_topic_from_an_unknown_reader() {
    let reader = EarlyDirected::new();
    for id in [[0; 4], [0, 0, 8, 7]] {
        assert_eq!(
            reader.route(id, 1),
            crate::engine::router::RouteStatus::Dropped
        );
    }
    reader.resolve(QoS::reliable());
    assert!(reader.sequences().is_empty());
}

/// RTPS 2.5 8.7.7: deferring discovery cannot change the source time used
/// for lifespan. A SEDP callback has no DATA timestamp of its own.
#[test]
fn directed_data_deferred_before_sedp_keeps_each_source_timestamp() {
    let reader = EarlyDirected::new();
    for (seq, seconds) in [(1, Some(10u32)), (2, Some(20u32)), (3, None)] {
        let mut packet = directed_early_packet(EarlyDirected::READER, seq);
        if let Some(seconds) = seconds {
            let mut timestamp = vec![0x09, 0x01, 8, 0];
            timestamp.extend_from_slice(&seconds.to_le_bytes());
            timestamp.extend_from_slice(&0u32.to_le_bytes());
            packet.splice(20..20, timestamp);
        }
        crate::engine::router::route_data_packet(
            &packet,
            packet.len(),
            None,
            &reader.topics,
            &crate::engine::router::RouterMetrics::new(),
        );
    }
    assert!(reader.sequences().is_empty());
    crate::engine::router::set_route_source_ts_ns(Some(999));
    reader.resolve(QoS::reliable());
    let restored = crate::engine::router::route_source_ts_ns();
    crate::engine::router::set_route_source_ts_ns(None);
    assert_eq!(restored, Some(999), "the flushing caller keeps its context");
    let pool = rt::get_slab_pool();
    for (seq, source) in [
        (1, Some(10_000_000_000)),
        (2, Some(20_000_000_000)),
        (3, None),
    ] {
        let entry = reader.ring.pop().expect("deferred sample");
        pool.release(entry.handle);
        assert_eq!(entry.seq, seq);
        assert_eq!(entry.has_source_ts(), source.is_some());
        if let Some(timestamp) = source {
            assert_eq!(entry.timestamp_ns, timestamp);
        }
    }
    assert!(reader.ring.pop().is_none());
}

/// RTPS 2.5 8.4.12.2: a live change cannot become available ahead of the
/// earlier changes another thread is releasing after endpoint discovery.
#[test]
fn directed_data_cannot_overtake_a_deferred_flush_after_sedp() {
    let reader = EarlyDirected::new();
    for seq in 1..=32 {
        reader.route(EarlyDirected::READER, seq);
    }
    let resume = reader.credit.hold_next();
    let flushing = reader.clone();
    let worker = std::thread::spawn(move || flushing.resolve(QoS::reliable()));
    // `pass` takes the channel just after the queue is removed, before it
    // is admitted. No wall-clock delay establishes this ordering.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while reader.credit.holding() {
        assert!(
            std::time::Instant::now() < deadline,
            "flush reached its pause"
        );
        std::thread::yield_now();
    }
    reader.route(EarlyDirected::READER, 33);
    let overtaking = reader.sequences();
    drop(resume);
    worker.join().expect("flush thread");
    assert!(
        overtaking.is_empty(),
        "live DATA waited for the deferred prefix"
    );
    assert_eq!(reader.sequences(), (1..=33).collect::<Vec<_>>());
}

/// A one-shot write racing discovery must be released even when the
/// discovery callback runs just before the sample enters its queue.
#[test]
fn directed_data_enqueued_after_the_sedp_flush_needs_no_later_sample() {
    let reader = EarlyDirected::new();
    let resume = reader.credit.hold_next();
    let receiving = reader.clone();
    let worker = std::thread::spawn(move || receiving.route(EarlyDirected::READER, 1));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while reader.credit.holding() {
        assert!(
            std::time::Instant::now() < deadline,
            "DATA reached deferral"
        );
        std::thread::yield_now();
    }
    reader.resolve(QoS::reliable());
    assert!(reader.sequences().is_empty(), "not queued yet");
    drop(resume);
    worker.join().expect("receiving thread");
    assert_eq!(reader.sequences(), vec![1]);
    assert_eq!(reader.credit.settled(&ACCEPTED), Some(1));
}

/// Best-effort reception has the same discovery handoff. It needs no ACK
/// proxy to release an already received, now-compatible one-shot sample.
#[test]
fn directed_data_best_effort_enqueued_after_sedp_needs_no_later_sample() {
    let reader = EarlyDirected::with_qos(QoS::best_effort());
    let pause = reader.credit.clone();
    let resume = pause.hold_next();
    *reader.sub.pending_hook.lock().expect("hook") = Some(Box::new(move || pause.pass()));
    let receiving = reader.clone();
    let worker = std::thread::spawn(move || receiving.route(EarlyDirected::READER, 1));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while reader.credit.holding() {
        assert!(
            std::time::Instant::now() < deadline,
            "DATA reached deferral"
        );
        std::thread::yield_now();
    }
    reader.resolve(QoS::best_effort());
    assert!(reader.sequences().is_empty());
    drop(resume);
    worker.join().expect("receiving thread");
    assert_eq!(reader.sequences(), vec![1]);
    assert!(
        !reader.credit.is_matched(&ACCEPTED),
        "best-effort never acknowledges"
    );
}

/// The explicit destination cannot override the writer's discovered topic.
#[test]
fn directed_data_waiting_for_sedp_cannot_enter_another_topic() {
    let reader = EarlyDirected::new();
    reader.route(EarlyDirected::READER, 1);
    let mut other = announcement(ACCEPTED, QoS::reliable().data_representation_xcdr2());
    other.topic_name = "another_topic".to_string();
    reader
        .topics
        .register_writer_guid(ACCEPTED, other.topic_name.clone());
    reader
        .topics
        .register_writer_ownership_kind(ACCEPTED, crate::qos::ownership::OwnershipKind::Shared);
    reader.fsm.handle_sedp(other);
    reader.topics.notify_writer_qos_resolved(ACCEPTED);
    assert!(reader.sequences().is_empty());
    assert!(!reader.credit.is_matched(&ACCEPTED));
    // Even a stale callback handed to this subscriber cannot admit a
    // writer now known to publish another topic.
    reader.sub.on_writer_qos_resolved(ACCEPTED);
    assert!(reader.sequences().is_empty());
}

/// RTPS 2.5 8.4.12.2: a reliable reader makes received changes available
/// in sequence order, including DATA that overtook SEDP out of order.
#[test]
fn directed_data_before_sedp_is_released_in_sequence_order() {
    let reader = EarlyDirected::new();
    reader.route(EarlyDirected::READER, 2);
    reader.route(EarlyDirected::READER, 1);
    reader.resolve(QoS::reliable());
    assert_eq!(reader.sequences(), vec![1, 2]);
    assert_eq!(reader.credit.settled(&ACCEPTED), Some(2));
}

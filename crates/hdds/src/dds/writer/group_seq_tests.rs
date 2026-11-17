// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Group sequence numbers of a GROUP Publisher's writers (RTPS v2.5
//! Sec.8.7.5): every change of every writer of the Publisher takes the
//! Publisher's next GSN, with the writer's SN, and carries it with the
//! Publisher's writerSet (`PID_GROUP_SEQ_NUM` 0x0064, `PID_WRITER_GROUP_INFO`
//! 0x0065) on the wire and in the history a repair is built from.

use crate::dds::publisher::Publisher;
use crate::dds::qos::{Presentation, PresentationAccessScope};
use crate::dds::{Participant, QoS, TransportMode};
use crate::protocol::group::{group_digest, GroupTag};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Sample {
    #[key]
    id: u32,
    v: i32,
}

fn participant(name: &str) -> Arc<Participant> {
    // In-process only: no socket, nothing to reserve the domain against.
    Participant::builder(name)
        .with_transport(TransportMode::IntraProcess)
        .domain_id(crate::test_support::domains::unique_domain().id())
        .build()
        .expect("participant")
}

/// A participant on `transport`, with the lease that reserves its domain:
/// bind it first (`let (_domain, p) = ...`) so the participant is dropped
/// before the domain goes back to the pool. Dropped at once, the lease handed
/// the domain to another test while this one's sockets were still bound.
fn participant_on(
    name: &str,
    transport: TransportMode,
) -> (crate::test_support::domains::DomainLease, Arc<Participant>) {
    let domain = crate::test_support::domains::unique_domain();
    let participant = Participant::builder(name)
        .with_transport(transport)
        .domain_id(domain.id())
        .build()
        .expect("participant");
    (domain, participant)
}

fn qos(scope: PresentationAccessScope, coherent: bool) -> QoS {
    QoS::reliable()
        .transient_local()
        .presentation(Presentation::new(scope, coherent, false))
}

fn writer(
    p: &Arc<Participant>,
    publisher: &Arc<Publisher>,
    topic: &str,
    q: QoS,
) -> super::DataWriter<Sample> {
    p.topic::<Sample>(topic)
        .expect("topic")
        .writer()
        .qos(q)
        .publisher(publisher)
        .build()
        .expect("writer")
}

fn tags(w: &super::DataWriter<Sample>) -> Vec<(u64, Option<GroupTag>, Option<u64>)> {
    let cache = w.history_cache.clone().expect("a history");
    cache
        .snapshot_changes()
        .into_iter()
        .map(|c| (c.seq, c.group, c.metadata.coherent_sn))
        .collect()
}

/// The value of inline QoS parameter `pid` in a DATA packet, decoded by
/// hand: RTPS header 20, INFO_TS 12, DATA header 4 + 20, then the list.
fn inline(packet: &[u8], pid: u16) -> Option<Vec<u8>> {
    let mut at = 20 + 12 + 4 + 20;
    while at + 4 <= packet.len() {
        let id = u16::from_le_bytes([packet[at], packet[at + 1]]);
        let len = usize::from(u16::from_le_bytes([packet[at + 2], packet[at + 3]]));
        if id == 0x0001 {
            return None;
        }
        if id == pid {
            return Some(packet[at + 4..at + 4 + len].to_vec());
        }
        at += 4 + len;
    }
    None
}

#[test]
fn every_change_of_a_group_publisher_takes_its_next_gsn() {
    let p = participant("group-gsn");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, false))
            .expect("publisher"),
    );
    let a = writer(
        &p,
        &publisher,
        "GsnA",
        qos(PresentationAccessScope::Group, false),
    );
    let b = writer(
        &p,
        &publisher,
        "GsnB",
        qos(PresentationAccessScope::Group, false),
    );
    let ids = [a.rtps_endpoint_for_test(), b.rtps_endpoint_for_test()]
        .map(|ctx| ctx.expect("context").writer_entity_id);
    let digest = group_digest(ids);
    a.write(&Sample { id: 1, v: 1 }).expect("a1");
    b.write(&Sample { id: 2, v: 2 }).expect("b1");
    a.dispose(&Sample { id: 1, v: 1 }).expect("a dispose");
    b.write(&Sample { id: 2, v: 3 }).expect("b2");
    let tag = |gsn| {
        Some(GroupTag {
            gsn,
            writer_set: digest,
            set_first_gsn: None,
            part_first_sn: None,
        })
    };
    assert_eq!(tags(&a), vec![(1, tag(1), None), (2, tag(3), None)]);
    assert_eq!(tags(&b), vec![(1, tag(2), None), (2, tag(4), None)]);

    // A repair of a change carries them, decoded by hand.
    let change = a
        .history_cache
        .clone()
        .expect("history")
        .get_change(1)
        .expect("1");
    let packet = super::nack::user_data_change_packet(
        a.rtps_endpoint_for_test().expect("context"),
        "GsnA",
        &change,
        (0, 0),
        true,
    );
    assert_eq!(
        inline(&packet, 0x0064),
        Some(vec![0, 0, 0, 0, 1, 0, 0, 0]),
        "GSN 1"
    );
    assert_eq!(inline(&packet, 0x0065), Some(digest.to_vec()), "writerSet");
    let dispose = a
        .history_cache
        .clone()
        .expect("history")
        .get_change(2)
        .expect("2");
    let packet =
        super::nack::lifecycle_change_packet(a.rtps_endpoint_for_test(), "GsnA", &dispose, true)
            .expect("a lifecycle change");
    assert_eq!(
        inline(&packet, 0x0064),
        Some(vec![0, 0, 0, 0, 3, 0, 0, 0]),
        "GSN 3"
    );
    assert_eq!(inline(&packet, 0x0065), Some(digest.to_vec()));
}

/// A writer of a TOPIC-scope Publisher, or of none, takes no GSN.
#[test]
fn a_writer_of_no_group_takes_no_gsn() {
    let p = participant("no-group-gsn");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Topic, true))
            .expect("publisher"),
    );
    let w = writer(
        &p,
        &publisher,
        "NoGsn",
        qos(PresentationAccessScope::Topic, true),
    );
    w.write(&Sample { id: 1, v: 1 }).expect("write");
    assert_eq!(tags(&w), vec![(1, None, None)]);
    let plain = p
        .topic::<Sample>("NoGsn2")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().transient_local())
        .build()
        .expect("writer");
    plain.write(&Sample { id: 1, v: 1 }).expect("write");
    assert_eq!(tags(&plain), vec![(1, None, None)]);
}

/// A writer made by the deprecated `Publisher::create_writer` belongs to
/// the Publisher (D17): it takes the Publisher's GSNs and its sets' tags.
#[test]
#[allow(deprecated)]
fn a_writer_created_by_the_publisher_joins_its_group() {
    // On the wire: the set's tags are taken where the DATA is built.
    let domain = crate::test_support::domains::unique_domain();
    let p = Participant::builder("create-writer-gsn")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(domain.id())
        .build()
        .expect("participant");
    let publisher = p
        .create_publisher(qos(PresentationAccessScope::Group, true))
        .expect("publisher");
    let w = publisher
        .create_writer::<Sample>("Created", qos(PresentationAccessScope::Group, true))
        .expect("writer");
    publisher.begin_coherent_changes().expect("begin");
    w.write(&Sample { id: 1, v: 1 }).expect("write");
    publisher.end_coherent_changes().expect("end");
    let id = w
        .rtps_endpoint_for_test()
        .expect("context")
        .writer_entity_id;
    let changes = tags(&w);
    assert_eq!(
        changes[0],
        (
            1,
            Some(GroupTag {
                gsn: 1,
                writer_set: group_digest([id]),
                set_first_gsn: Some(1),
                part_first_sn: None,
            }),
            Some(1)
        ),
        "a GSN and the set's first SN"
    );
}

/// A writer cannot join a Publisher while a coherent set is open (D11,
/// RTPS v2.5 Sec.8.7.6): PRECONDITION_NOT_MET.
#[test]
fn a_writer_cannot_join_during_an_open_set() {
    let p = participant("join-in-set");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, true))
            .expect("publisher"),
    );
    let _a = writer(
        &p,
        &publisher,
        "JoinA",
        qos(PresentationAccessScope::Group, true),
    );
    publisher.begin_coherent_changes().expect("begin");
    let refused = p
        .topic::<Sample>("JoinB")
        .expect("topic")
        .writer()
        .qos(qos(PresentationAccessScope::Group, true))
        .publisher(&publisher)
        .build();
    assert!(matches!(refused, Err(crate::dds::Error::InvalidState(_))));
    publisher.end_coherent_changes().expect("end");
    let _b = writer(
        &p,
        &publisher,
        "JoinB",
        qos(PresentationAccessScope::Group, true),
    );
}

/// SN and GSN are given back together when both are the last handed out,
/// and neither when another change took a later one (D16).
#[test]
fn a_change_not_made_gives_back_its_sn_and_gsn_together() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let p = participant("give-back");
    let publisher = p
        .create_publisher(qos(PresentationAccessScope::Group, false))
        .expect("publisher");
    let core = &publisher.core;
    let (a, b) = (AtomicU64::new(1), AtomicU64::new(1));
    let (sn, gsn) = {
        let (sn, tag) = core.take_sn_and_gsn(&a, None);
        (sn, tag.gsn)
    };
    assert_eq!((sn, gsn), (1, 1));
    assert_eq!(
        core.give_back_sn_and_gsn(&a, sn, gsn),
        crate::dds::publisher::GiveBack::Both,
        "both last: given back"
    );
    assert_eq!(a.load(Ordering::Acquire), 1);
    assert_eq!(core.current_gsn(), 0, "currentGSN given back too");
    let (sn, gsn) = {
        let (sn, tag) = core.take_sn_and_gsn(&a, None);
        (sn, tag.gsn)
    };
    assert_eq!((sn, gsn), (1, 1), "taken again");
    let later = core.take_sn_and_gsn(&b, None).1.gsn;
    assert_eq!(later, 2);
    assert_eq!(
        core.give_back_sn_and_gsn(&a, sn, gsn),
        crate::dds::publisher::GiveBack::SnOnly,
        "a later GSN was taken: the SN alone"
    );
    assert_eq!(
        a.load(Ordering::Acquire),
        1,
        "the SN is given back all the same"
    );
    assert_eq!(core.current_gsn(), 2, "the GSN stays taken: a hole");
    // A later change of the same writer took an SN: neither.
    let (sn, tag) = core.take_sn_and_gsn(&a, None);
    core.take_sn_and_gsn(&a, None);
    assert_eq!(
        core.give_back_sn_and_gsn(&a, sn, tag.gsn),
        crate::dds::publisher::GiveBack::Neither
    );
    assert_eq!(a.load(Ordering::Acquire), 3, "both SNs stay taken");
}

/// A repair carries the spec GROUP form only for a reader of the spec
/// class (D18); any other reader's repair is today's form.
#[test]
fn a_repair_takes_the_form_of_its_readers_class() {
    let p = participant("repair-class");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, false))
            .expect("publisher"),
    );
    let w = writer(
        &p,
        &publisher,
        "RepairClass",
        qos(PresentationAccessScope::Group, false),
    );
    w.write(&Sample { id: 1, v: 1 }).expect("write");
    let change = w
        .history_cache
        .clone()
        .expect("history")
        .get_change(1)
        .expect("1");
    let ctx = w.rtps_endpoint_for_test().expect("context");
    let legacy = super::nack::user_data_change_packet(ctx, "RepairClass", &change, (0, 0), false);
    assert_eq!(inline(&legacy, 0x0064), None);
    assert_eq!(inline(&legacy, 0x0065), None);
    let spec = super::nack::user_data_change_packet(ctx, "RepairClass", &change, (0, 0), true);
    assert_eq!(inline(&spec, 0x0064), Some(vec![0, 0, 0, 0, 1, 0, 0, 0]));
}

/// The shared-memory ring carries one form (D18): the first reader it
/// serves sets it, a reader of the other class is not served by it.
#[test]
fn the_shared_memory_ring_serves_one_class() {
    use super::runtime::shm_serves;
    assert!(
        shm_serves(None, true) && shm_serves(None, false),
        "nothing pushed yet"
    );
    assert!(shm_serves(Some(true), true));
    assert!(
        !shm_serves(Some(true), false),
        "a legacy reader goes by UDP"
    );
    assert!(!shm_serves(Some(false), true), "a spec reader goes by UDP");
}

/// Every end of a GROUP set takes one GSN, the set's last plus one (RTPS
/// v2.5 Sec.8.7.6, D2): the next change takes the one after; an empty set
/// takes one too.
#[test]
fn the_end_of_a_group_set_takes_one_gsn() {
    let p = participant("end-gsn");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, true))
            .expect("publisher"),
    );
    let w = writer(
        &p,
        &publisher,
        "EndGsn",
        qos(PresentationAccessScope::Group, true),
    );
    publisher.begin_coherent_changes().expect("begin");
    w.write(&Sample { id: 1, v: 1 }).expect("1");
    publisher.end_coherent_changes().expect("end: GSN 2");
    assert_eq!(publisher.core.current_gsn(), 2, "currentGSN: the end's");
    publisher.begin_coherent_changes().expect("begin");
    publisher
        .end_coherent_changes()
        .expect("an empty set: GSN 3");
    assert_eq!(publisher.core.current_gsn(), 3);
    w.write(&Sample { id: 1, v: 2 }).expect("4");
    let gsns: Vec<u64> = w
        .history_cache
        .clone()
        .expect("history")
        .snapshot_changes()
        .into_iter()
        .filter(|c| c.metadata.kind == crate::reliability::ChangeKind::UserData)
        .filter_map(|c| c.group.map(|t| t.gsn))
        .collect();
    assert_eq!(gsns, vec![1, 4], "the samples' GSNs around two ends of set");
}

/// Every writer of a GROUP Publisher ends a set, the writers that wrote
/// nothing in it too (RTPS v2.5 Sec.8.7.6, W3): their end of set is
/// journaled with its own SN as PID_COHERENT_SET (D6) and the set's GSNs.
#[test]
fn an_idle_writer_ends_the_group_set_too() {
    let p = participant("idle-end");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, true))
            .expect("publisher"),
    );
    let a = writer(
        &p,
        &publisher,
        "IdleA",
        qos(PresentationAccessScope::Group, true),
    );
    let b = writer(
        &p,
        &publisher,
        "IdleB",
        qos(PresentationAccessScope::Group, true),
    );
    publisher.begin_coherent_changes().expect("begin");
    a.write(&Sample { id: 1, v: 1 }).expect("a");
    publisher.end_coherent_changes().expect("end");
    let ends = |w: &super::DataWriter<Sample>| -> Vec<(u64, Option<GroupTag>)> {
        w.history_cache
            .clone()
            .expect("history")
            .snapshot_changes()
            .into_iter()
            .filter(|c| c.metadata.kind == crate::reliability::ChangeKind::EcsClose)
            .map(|c| (c.seq, c.group))
            .collect()
    };
    let digest = a
        .history_cache
        .clone()
        .expect("h")
        .get_change(1)
        .expect("1")
        .group
        .expect("tag")
        .writer_set;
    assert_eq!(
        ends(&b),
        vec![(
            1,
            Some(GroupTag {
                gsn: 2,
                writer_set: digest,
                set_first_gsn: Some(1),
                part_first_sn: Some(1),
            })
        )],
        "the idle writer's end of set: its own SN, the set's GSNs"
    );
    assert_eq!(ends(&a).len(), 1, "the writer that wrote ends it too");
    assert_eq!(ends(&a)[0].1.map(|t| t.gsn), Some(2), "one GSN for both");
}

/// The GroupInfo rules of a GROUP writer's HEARTBEAT (RTPS v2.5
/// Sec.8.3.8.6, Sec.8.7.5, D3, D15).
#[test]
fn a_group_heartbeat_announces_no_gsn_of_its_writer_as_absent_wrongly() {
    use super::heartbeat_scheduler::group_heartbeat_info as info;
    use crate::reliability::GroupWindow;
    let window = |first: u64, last: u64, unannounced: Option<u64>| GroupWindow {
        first_gsn: Some(first),
        last_gsn: Some(last),
        unannounced_gsn: unannounced,
    };
    assert_eq!(
        info(9, 0, window(3, 7, None)),
        Some([9, 3, 7]),
        "the Publisher's last GSN, past this writer's last (D3)"
    );
    assert_eq!(
        info(9, 8, window(3, 7, None)),
        Some([8, 3, 7]),
        "a pending GSN"
    );
    assert_eq!(
        info(9, 0, window(3, 7, Some(8))),
        Some([8, 3, 7]),
        "a change made above lastSN"
    );
    assert_eq!(
        info(5, 0, window(3, 7, None)),
        Some([7, 3, 7]),
        "never below lastGSN"
    );
    let empty = GroupWindow::default();
    assert_eq!(info(4, 0, empty), Some([4, 4, 3]), "an empty interval");
    assert_eq!(info(4, 2, empty), Some([2, 2, 1]));
    assert_eq!(info(0, 0, empty), None, "currentGSN must be positive");
}

/// A GSN a writer took and has not made is not announced as one it does
/// not have, however far its Publisher's other writers go; nor is one it
/// made above the HEARTBEAT's lastSN.
#[test]
fn a_group_heartbeat_holds_back_a_gsn_taken_and_not_made() {
    use super::heartbeat_scheduler::group_heartbeat_info_of as info_of;
    use crate::core::rt::slabpool::SlabPool;
    use crate::reliability::{ChangeMetadata, HistoryCache};
    use std::sync::atomic::{AtomicU64, Ordering};
    let p = participant("hb-pending");
    let publisher = p
        .create_publisher(qos(PresentationAccessScope::Group, false))
        .expect("publisher");
    let core = &publisher.core;
    let cache = HistoryCache::new_with_limits(
        Arc::new(SlabPool::new()),
        16,
        64 * 1024,
        crate::dds::qos::History::KeepAll,
    );
    let (mine, other) = (AtomicU64::new(1), AtomicU64::new(1));
    let pending = AtomicU64::new(0);
    let make = |seq: u64, tag: GroupTag| {
        cache
            .insert_grouped_until(seq, &[1], 0, ChangeMetadata::user_data(), Some(tag), None)
            .expect("insert");
    };
    let (seq, tag) = core.take_sn_and_gsn(&mine, Some(&pending));
    make(seq, tag);
    pending.store(0, Ordering::Release);
    // Taken, not made; then another writer takes the next GSN.
    let (seq, tag) = core.take_sn_and_gsn(&mine, Some(&pending));
    assert_eq!((seq, tag.gsn), (2, 2));
    assert_eq!(pending.load(Ordering::Acquire), 2);
    core.take_sn_and_gsn(&other, None);
    assert_eq!(core.current_gsn(), 3);
    assert_eq!(
        info_of(core, Some(&pending), &cache, 1, 1),
        Some([2, 1, 1]),
        "GSN 2 is pending: currentGSN stops there"
    );
    make(seq, tag);
    pending.store(0, Ordering::Release);
    assert_eq!(
        info_of(core, Some(&pending), &cache, 1, 1),
        Some([2, 1, 1]),
        "GSN 2 is made but above lastSN"
    );
    assert_eq!(info_of(core, Some(&pending), &cache, 1, 2), Some([3, 1, 2]));
}

/// A change abandoned after a later change of its own writer cannot give
/// its SN back: its history records the hole, for the GAP that will name
/// the GSN (D16). One abandoned after another writer's change only gives
/// its SN back, leaving no SN hole.
#[test]
fn a_change_abandoned_past_another_records_its_hole() {
    use std::sync::atomic::AtomicU64;
    let p = participant("hole");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, false))
            .expect("publisher"),
    );
    let a = writer(
        &p,
        &publisher,
        "HoleA",
        qos(PresentationAccessScope::Group, false),
    );
    a.write(&Sample { id: 1, v: 1 }).expect("a1");
    let other = AtomicU64::new(1);
    let (taken, holes) = a.abandon_past_another_change_for_test(&other, true);
    assert_eq!(taken, (2, 2));
    assert_eq!(holes, vec![(2, 2)], "an SN hole, GAPped with its GSN");
    // Past another writer's GSN only: the SN is given back, no SN hole.
    let (taken, holes) = a.abandon_past_another_change_for_test(&other, false);
    assert_eq!(taken.0, 4, "after the hole and the change taken past it");
    assert!(holes.is_empty(), "no SN hole: {holes:?}");
}

/// A write leaves no pending GSN behind, made or refused: the HEARTBEAT
/// thread would otherwise hold its currentGSN back for good.
#[test]
fn a_write_leaves_no_pending_gsn() {
    use std::sync::atomic::Ordering;
    let (_domain, p) = participant_on("pending", TransportMode::UdpMulticast);
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, false))
            .expect("publisher"),
    );
    let a = writer(
        &p,
        &publisher,
        "PendingA",
        qos(PresentationAccessScope::Group, false),
    );
    let state = a
        ._heartbeat_scheduler
        .as_ref()
        .expect("a reliable writer on the wire has a HEARTBEAT thread")
        .state()
        .clone();
    a.write(&Sample { id: 1, v: 1 }).expect("a1");
    assert_eq!(
        state.pending_gsn.load(Ordering::Acquire),
        0,
        "after a write"
    );
    a.dispose(&Sample { id: 1, v: 1 }).expect("dispose");
    assert_eq!(
        state.pending_gsn.load(Ordering::Acquire),
        0,
        "after a dispose"
    );
    let other = std::sync::atomic::AtomicU64::new(1);
    a.abandon_past_another_change_for_test(&other, false);
    assert_ne!(
        state.pending_gsn.load(Ordering::Acquire),
        0,
        "the slot is the one a take sets (the hook takes without clearing)"
    );
}

/// A write racing its Publisher's begin and end: the change's GSN tag (its
/// set) and its coherent context (PID_COHERENT_SET, the end of set's last
/// SN) agree on whether it is a member of a set, whatever the interleaving
/// (both decided in one critical section of the Publisher's lock).
#[test]
fn a_changes_group_tag_and_coherent_set_agree_under_a_racing_begin_and_end() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_domain, p) = participant_on("group-race", TransportMode::UdpMulticast);
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, true))
            .expect("publisher"),
    );
    let w = writer(
        &p,
        &publisher,
        "GroupRace",
        qos(PresentationAccessScope::Group, true),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let cycles = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let toggler = {
        let publisher = Arc::clone(&publisher);
        let stop = Arc::clone(&stop);
        let cycles = Arc::clone(&cycles);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                // Each phase lasts long enough for writes to land in it: with
                // a bare yield a set stays open for only about 1% of the
                // writes, and none under ASan.
                publisher.begin_coherent_changes().expect("begin");
                std::thread::sleep(std::time::Duration::from_micros(100));
                publisher.end_coherent_changes().expect("end");
                cycles.fetch_add(1, Ordering::Release);
                std::thread::sleep(std::time::Duration::from_micros(100));
            }
        })
    };
    // The writes must overlap the toggling: start once it has toggled, and
    // keep writing until it has toggled often, within a bound.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while cycles.load(Ordering::Acquire) == 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    let mut i = 0u32;
    while i < 3_000
        || (cycles.load(Ordering::Acquire) < 200 && std::time::Instant::now() < deadline)
    {
        w.write(&Sample { id: i, v: 0 }).expect("write");
        i += 1;
    }
    stop.store(true, Ordering::Release);
    toggler.join().expect("toggler");
    let mut in_set = 0;
    let mut disagree = Vec::new();
    for c in w.history_cache.clone().expect("history").snapshot_changes() {
        let Some(tag) = c.group else { continue };
        if tag.part_first_sn.is_some()
            || c.metadata.kind != crate::reliability::ChangeKind::UserData
        {
            continue;
        }
        if tag.set_first_gsn.is_some() {
            in_set += 1;
        }
        if tag.set_first_gsn.is_some() != c.metadata.coherent_sn.is_some() {
            disagree.push((c.seq, tag.set_first_gsn, c.metadata.coherent_sn));
        }
    }
    assert!(in_set > 0, "some changes landed in sets");
    assert!(
        disagree.is_empty(),
        "{} changes disagree, first {:?}",
        disagree.len(),
        &disagree[..disagree.len().min(5)]
    );
}

/// A writer whose QoS has no coherent access writes no member of its
/// Publisher's open set: no PID_COHERENT_SET, and no set in its GSN tag
/// either (0x0063), the two always agreeing.
#[test]
fn a_writer_without_coherent_access_tags_no_set() {
    let p = participant("no-coherent-access");
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, true))
            .expect("publisher"),
    );
    let w = writer(
        &p,
        &publisher,
        "NoCoherentAccess",
        qos(PresentationAccessScope::Group, false),
    );
    publisher.begin_coherent_changes().expect("begin");
    w.write(&Sample { id: 1, v: 1 }).expect("write");
    publisher.end_coherent_changes().expect("end");
    let tags = tags(&w);
    let (_, tag, coherent_sn) = tags
        .iter()
        .find(|(_, tag, _)| tag.is_some_and(|t| t.part_first_sn.is_none()))
        .copied()
        .expect("the change");
    assert_eq!(coherent_sn, None);
    assert_eq!(
        tag.and_then(|t| t.set_first_gsn),
        None,
        "no set in the GSN tag"
    );
}

/// A shared-memory ring is drained by every reader attached to it: it
/// carries a GROUP change only when those readers are all of one class
/// (D18).
#[test]
fn a_ring_of_a_mixed_audience_carries_no_group_change() {
    use super::runtime::shm_audience_is_one_class as one;
    assert!(one(&mut std::iter::empty()));
    assert!(one(&mut [true, true].into_iter()));
    assert!(one(&mut [false, false, false].into_iter()));
    assert!(!one(&mut [true, false].into_iter()));
    assert!(!one(&mut [false, false, true].into_iter()));
}

/// The multicast fallback (an audience of unknown class) carries no GROUP
/// change while a participant of the spec class is known (D18), any other
/// change, and a GROUP change when only 1.4.x or foreign participants are.
#[test]
fn the_multicast_fallback_carries_no_group_change_to_a_spec_audience() {
    use super::runtime::multicasts;
    use crate::core::discovery::multicast::DiscoveryFsm;
    use crate::core::discovery::GUID;
    let fsm = DiscoveryFsm::new(GUID::zero(), 100_000);
    fsm.set_local_capabilities(crate::protocol::group::CAP_SPEC_GROUP_COHERENT);
    let spdp = |prefix: u8, caps: Option<u32>| crate::protocol::discovery::SpdpData {
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
        vendor_id: Some(crate::core::rtps_constants::HDDS_VENDOR_ID_U16),
        hdds_capabilities: caps,
        builtin_endpoint_set: None,
    };
    fsm.handle_spdp(spdp(0x61, None));
    assert!(multicasts(true, Some(&fsm)), "only a 1.4.x peer");
    assert!(multicasts(true, None), "no discovery");
    fsm.handle_spdp(spdp(
        0x62,
        Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
    ));
    assert!(!multicasts(true, Some(&fsm)), "a spec peer known");
    assert!(multicasts(false, Some(&fsm)), "not a GROUP change");
}

/// A writes s1 in a set, then a write of A abandoned
/// after another writer took the next GSN (SnOnly: SN given back), then
/// the set ends. A's end of set must not claim a member it never made:
/// its "last SN" (PID_COHERENT_SET of the 1.4.x form) must be s1, not the
/// given-back SN, which the end itself now occupies.
#[test]
fn an_end_of_set_after_an_sn_given_back_claims_no_phantom_member() {
    let (_domain, p) = participant_on("vgroup-giveback", TransportMode::UdpMulticast);
    let q = || qos(PresentationAccessScope::Group, true);
    let publisher = Arc::new(p.create_publisher(q()).expect("publisher"));
    let a = writer(&p, &publisher, "VGiveA", q());
    publisher.begin_coherent_changes().expect("begin");
    a.write(&Sample { id: 1, v: 1 }).expect("a1");
    let other = std::sync::atomic::AtomicU64::new(1);
    let (abandoned_sn, _gsn) = a.abandon_in_set_for_test(&other);
    publisher.end_coherent_changes().expect("end");
    let snap = a.history_cache.clone().expect("h").snapshot_changes();
    let ecs = snap
        .iter()
        .find(|c| c.metadata.kind == crate::reliability::ChangeKind::EcsClose)
        .expect("A's end of set");
    let members: Vec<u64> = snap
        .iter()
        .filter(|c| c.metadata.kind != crate::reliability::ChangeKind::EcsClose)
        .map(|c| c.seq)
        .collect();
    assert_eq!(members, vec![1]);
    assert_eq!(abandoned_sn, 2);
    assert_eq!(
        ecs.metadata.coherent_sn,
        Some(1),
        "end of set SN {} claims last member {:?}; the only member is 1",
        ecs.seq,
        ecs.metadata.coherent_sn
    );
}

/// KEEP_ALL writer (nothing evicted), writes racing the ends of set taken
/// on another thread: the history holds every member before its set's
/// end (ring order == SN order), as `orphan_markers` reads it.
#[test]
fn an_end_of_set_is_never_journaled_before_its_member() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_domain, p) = participant_on("group-journal-order", TransportMode::UdpMulticast);
    let q = || qos(PresentationAccessScope::Group, true).keep_all();
    let publisher = Arc::new(p.create_publisher(q()).expect("publisher"));
    let a = writer(&p, &publisher, "OrderA", q());
    let stop = Arc::new(AtomicBool::new(false));
    let toggler = {
        let publisher = Arc::clone(&publisher);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                publisher.begin_coherent_changes().expect("begin");
                std::thread::yield_now();
                publisher.end_coherent_changes().expect("end");
                std::thread::yield_now();
            }
        })
    };
    for i in 0..3_000u32 {
        a.write(&Sample { id: i, v: 0 }).expect("write");
    }
    stop.store(true, Ordering::Release);
    toggler.join().expect("toggler");
    let snap = a.history_cache.clone().expect("h").snapshot_changes();
    let inv: Vec<(u64, u64)> = snap
        .windows(2)
        .filter(|w| w[0].seq > w[1].seq)
        .map(|w| (w[0].seq, w[1].seq))
        .collect();
    assert!(
        inv.is_empty(),
        "{} ECS-before-member inversions in the history ring, first {:?}",
        inv.len(),
        &inv[..inv.len().min(8)]
    );
}

/// An idle writer B's end of set 1 stays in B's history while A's member of
/// set 1 stays in A's (KEEP_LAST, distinct keys): an end of set "can only
/// be removed from the RTPS Writer cache when all data samples belonging to
/// the coherent set are removed" (RTPS v2.5 Sec.8.7.6), and under GROUP
/// scope the set's samples are every writer's. Given up, one lost datagram
/// of B's end was the set lost (its HEARTBEAT announces the end GSN absent).
#[test]
fn an_idle_writers_end_outlives_the_sets_samples() {
    let (_domain, p) = participant_on("group-idle-end-kept", TransportMode::UdpMulticast);
    let q = || qos(PresentationAccessScope::Group, true).keep_last(2);
    let publisher = Arc::new(p.create_publisher(q()).expect("publisher"));
    let a = writer(&p, &publisher, "IdleA", q());
    let b = writer(&p, &publisher, "IdleB", q());
    publisher.begin_coherent_changes().expect("begin1");
    a.write(&Sample { id: 1, v: 1 }).expect("a1");
    publisher.end_coherent_changes().expect("end1");
    for k in 2..6u32 {
        publisher.begin_coherent_changes().expect("begin2");
        a.write(&Sample { id: k, v: 2 }).expect("a2");
        publisher.end_coherent_changes().expect("end2");
    }
    let set1 = 1u64;
    let a_has_member = a
        .history_cache
        .clone()
        .expect("h")
        .snapshot_changes()
        .iter()
        .any(|c| {
            c.metadata.kind != crate::reliability::ChangeKind::EcsClose
                && c.group.and_then(|t| t.set_first_gsn) == Some(set1)
        });
    let b_snap = b.history_cache.clone().expect("h").snapshot_changes();
    let b_has_end = b_snap.iter().any(|c| {
        c.metadata.kind == crate::reliability::ChangeKind::EcsClose
            && c.group.and_then(|t| t.set_first_gsn) == Some(set1)
    });
    assert!(a_has_member, "A keeps its member of set 1");
    assert!(
        b_has_end,
        "B's end of set 1 evicted while set 1 still has a sample"
    );
    // A's member of set 1 replaced (KEEP_LAST 2 of key 1), and the members
    // of the next two sets after it: three of B's ends name a set with no
    // member left, one more than the depth keeps, and the oldest, set 1's,
    // goes (`release_orphan_markers`).
    for _ in 0..4 {
        publisher.begin_coherent_changes().expect("begin3");
        a.write(&Sample { id: 1, v: 3 }).expect("a3");
        publisher.end_coherent_changes().expect("end3");
    }
    let b_ends: Vec<Option<u64>> = b
        .history_cache
        .clone()
        .expect("h")
        .snapshot_changes()
        .iter()
        .map(|c| c.group.and_then(|t| t.set_first_gsn))
        .collect();
    assert!(
        !b_ends.contains(&Some(set1)),
        "set 1 has no member left: its end is released, {b_ends:?}"
    );
    // A deleted: its history retains nothing. B's ends of A's sets go with
    // B's next ends, but for the depth B keeps.
    drop(a);
    for _ in 0..3 {
        publisher.begin_coherent_changes().expect("begin4");
        publisher.end_coherent_changes().expect("end4");
    }
    let b_len = b.history_cache.clone().expect("h").snapshot_changes().len();
    assert_eq!(
        b_len, 2,
        "B keeps the depth of its ends of sets with no member"
    );
}

/// Two writers on two threads, writes and disposes, racing a third thread
/// opening and ending sets (nested ones too). Every set's invariants, read
/// from the histories: members inside [first GSN, end GSN), ends agreeing,
/// PID_COHERENT_SET the part's first SN, the end's last SN its writer's
/// highest member, no change with a GSN inside a set's range left out of it.
#[test]
fn racing_writers_sets_are_consistent() {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_domain, p) = participant_on("group-race-sets", TransportMode::UdpMulticast);
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, true))
            .expect("publisher"),
    );
    let a = writer(
        &p,
        &publisher,
        "RaceA",
        qos(PresentationAccessScope::Group, true),
    );
    let b = writer(
        &p,
        &publisher,
        "RaceB",
        qos(PresentationAccessScope::Group, true),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let toggler = {
        let publisher = Arc::clone(&publisher);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut n = 0u32;
            while !stop.load(Ordering::Acquire) {
                publisher.begin_coherent_changes().expect("begin");
                if n.is_multiple_of(3) {
                    // nested
                    publisher.begin_coherent_changes().expect("begin2");
                    std::thread::yield_now();
                    publisher.end_coherent_changes().expect("end2");
                }
                std::thread::yield_now();
                publisher.end_coherent_changes().expect("end");
                std::thread::yield_now();
                n += 1;
            }
        })
    };
    let spawn = |w: super::DataWriter<Sample>, base: u32| {
        std::thread::spawn(move || {
            for i in 0..2_000u32 {
                let s = Sample { id: base + i, v: 0 };
                w.write(&s).expect("write");
                if i % 7 == 0 {
                    w.dispose(&s).expect("dispose");
                }
            }
            w
        })
    };
    let ta = spawn(a, 0);
    let tb = spawn(b, 1_000_000);
    let a = ta.join().expect("a");
    let b = tb.join().expect("b");
    stop.store(true, Ordering::Release);
    toggler.join().expect("toggler");

    let snaps: Vec<(char, Vec<crate::reliability::CachedChange>)> = vec![
        ('A', a.history_cache.clone().expect("h").snapshot_changes()),
        ('B', b.history_cache.clone().expect("h").snapshot_changes()),
    ];
    // set key -> end gsn (all ECS must agree)
    let mut ends: HashMap<u64, u64> = HashMap::new();
    let mut errs: Vec<String> = Vec::new();
    let mut n_sets = 0usize;
    let mut n_members = 0usize;
    for (name, snap) in &snaps {
        for c in snap {
            if c.metadata.kind == crate::reliability::ChangeKind::EcsClose {
                let Some(tag) = c.group else {
                    errs.push(format!("{name}: ECS sn {} without group tag", c.seq));
                    continue;
                };
                let key = tag.set_first_gsn.expect("ECS names its set");
                if let Some(e) = ends.insert(key, tag.gsn) {
                    if e != tag.gsn {
                        errs.push(format!("set {key}: two end GSNs {e} vs {}", tag.gsn));
                    }
                }
            }
        }
    }
    for (name, snap) in &snaps {
        let by_seq: BTreeMap<u64, &crate::reliability::CachedChange> =
            snap.iter().map(|c| (c.seq, c)).collect();
        // ECS of this writer by set key
        let mut ecs_of: HashMap<u64, &crate::reliability::CachedChange> = HashMap::new();
        for c in snap {
            if c.metadata.kind == crate::reliability::ChangeKind::EcsClose {
                ecs_of.insert(c.group.unwrap().set_first_gsn.unwrap(), c);
            }
        }
        n_sets += ecs_of.len();
        for c in snap {
            if c.metadata.kind == crate::reliability::ChangeKind::EcsClose {
                continue;
            }
            let Some(tag) = c.group else {
                errs.push(format!("{name}: change sn {} without GSN", c.seq));
                continue;
            };
            // Containment: GSN inside some set's range => must be its member.
            for (key, e) in &ends {
                if tag.gsn >= *key && tag.gsn < *e && tag.set_first_gsn != Some(*key) {
                    errs.push(format!(
                        "{name}: sn {} gsn {} inside set [{key},{e}) but tagged {:?} coherent_sn {:?}",
                        c.seq, tag.gsn, tag.set_first_gsn, c.metadata.coherent_sn
                    ));
                }
            }
            if tag.set_first_gsn.is_some() != c.metadata.coherent_sn.is_some() {
                errs.push(format!(
                    "{name}: sn {} set {:?} vs coherent_sn {:?}",
                    c.seq, tag.set_first_gsn, c.metadata.coherent_sn
                ));
            }
            let Some(key) = tag.set_first_gsn else {
                continue;
            };
            n_members += 1;
            let Some(e) = ends.get(&key) else {
                errs.push(format!(
                    "{name}: member sn {} of set {key} with no end",
                    c.seq
                ));
                continue;
            };
            if tag.gsn < key || tag.gsn >= *e {
                errs.push(format!(
                    "{name}: member sn {} gsn {} outside [{key},{e})",
                    c.seq, tag.gsn
                ));
            }
            let Some(ecs) = ecs_of.get(&key) else {
                errs.push(format!(
                    "{name}: member sn {} of set {key}, no ECS of its writer",
                    c.seq
                ));
                continue;
            };
            let part_first = ecs.group.unwrap().part_first_sn.unwrap();
            if c.seq >= ecs.seq || c.seq < part_first {
                errs.push(format!(
                    "{name}: member sn {} outside part [{part_first},{}) of set {key}",
                    c.seq, ecs.seq
                ));
            }
            if c.metadata.coherent_sn != Some(part_first) {
                errs.push(format!(
                    "{name}: member sn {} PID_COHERENT_SET {:?} != part first {part_first}",
                    c.seq, c.metadata.coherent_sn
                ));
            }
        }
        // ECS last SN == max member SN of that writer in the set
        for (key, ecs) in &ecs_of {
            let max_member = by_seq
                .values()
                .filter(|c| {
                    c.metadata.kind != crate::reliability::ChangeKind::EcsClose
                        && c.group.and_then(|t| t.set_first_gsn) == Some(*key)
                })
                .map(|c| c.seq)
                .max();
            if ecs.metadata.coherent_sn.is_some() && ecs.metadata.coherent_sn != max_member {
                errs.push(format!(
                    "{name}: ECS sn {} of set {key} says last {:?}, members max {:?}",
                    ecs.seq, ecs.metadata.coherent_sn, max_member
                ));
            }
        }
    }
    assert!(
        n_members > 0 && n_sets > 0,
        "sets {n_sets} members {n_members}"
    );
    assert!(
        errs.is_empty(),
        "{} violations (sets {n_sets}, members {n_members}), first: {:#?}",
        errs.len(),
        &errs[..errs.len().min(12)]
    );
}

/// The writer SNs of the DATA submessages of an RTPS datagram.
fn data_writer_sns(datagram: &[u8]) -> Vec<u64> {
    let mut sns = Vec::new();
    let mut at = 20;
    while at + 4 <= datagram.len() {
        let (id, flags) = (datagram[at], datagram[at + 1]);
        let le = flags & 1 == 1;
        let word = |b: &[u8]| {
            let b: [u8; 4] = b.try_into().expect("4 bytes");
            if le {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        let len = if le {
            u16::from_le_bytes([datagram[at + 2], datagram[at + 3]])
        } else {
            u16::from_be_bytes([datagram[at + 2], datagram[at + 3]])
        } as usize;
        if id == 0x15 && at + 24 <= datagram.len() {
            let high = u64::from(word(&datagram[at + 16..at + 20]));
            let low = u64::from(word(&datagram[at + 20..at + 24]));
            sns.push((high << 32) | low);
        }
        if len == 0 {
            break;
        }
        at += 4 + len;
    }
    sns
}

/// A socket joined to the user-data multicast group of `p`'s domain on the
/// loopback interface.
fn user_multicast_capture(p: &Participant) -> std::net::UdpSocket {
    let port = p.transport().expect("transport").data_multicast_port();
    let group: std::net::Ipv4Addr = crate::config::MULTICAST_GROUP.parse().expect("group");
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("socket");
    socket.set_reuse_address(true).expect("reuse");
    socket
        .bind(&std::net::SocketAddr::from(([0, 0, 0, 0], port)).into())
        .expect("bind");
    socket
        .join_multicast_v4(&group, &std::net::Ipv4Addr::LOCALHOST)
        .expect("join");
    let socket: std::net::UdpSocket = socket.into();
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(300)))
        .expect("timeout");
    socket
}

/// The writer SNs of the DATA `capture` receives for one second.
fn multicast_data_sns(capture: &std::net::UdpSocket) -> Vec<u64> {
    let mut buf = [0u8; 65_536];
    let mut sns = Vec::new();
    let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
    while std::time::Instant::now() < until {
        if let Ok(n) = capture.recv(&mut buf) {
            sns.extend(data_writer_sns(&buf[..n]));
        }
    }
    sns
}

/// A GROUP end of set with no known reader is not broadcast into an
/// unknown sequence space. Matched native readers can still use their
/// multicast locator, scoped by INFO_DST to their own participant.
#[test]
fn an_end_of_set_with_no_known_reader_never_reaches_an_unknown_multicast_audience() {
    use crate::core::discovery::GUID;
    for (name, caps, multicast) in [
        ("group-ecs-mcast-old", None, false),
        (
            "group-ecs-mcast-spec",
            Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
            false,
        ),
    ] {
        let (_domain, p) = participant_on(name, TransportMode::UdpMulticast);
        let publisher = Arc::new(
            p.create_publisher(qos(PresentationAccessScope::Group, true))
                .expect("publisher"),
        );
        let a = writer(
            &p,
            &publisher,
            "EcsMcast",
            qos(PresentationAccessScope::Group, true),
        );
        p.discovery()
            .expect("discovery")
            .handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new([0x61; 12], [0, 0, 1, 0xC1]),
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
        let capture = user_multicast_capture(&p);
        publisher.begin_coherent_changes().expect("begin");
        a.write(&Sample { id: 1, v: 1 }).expect("write");
        publisher.end_coherent_changes().expect("end");
        let sns = multicast_data_sns(&capture);
        assert_eq!(
            sns.contains(&2),
            multicast,
            "{name}: the end of set (SN 2) on multicast: {sns:?}"
        );
    }
}

/// A change is marked in flight (`HistoryCache::taking`) only by a writer
/// with another producer of its SNs, a Publisher's ends of set: a writer of
/// no Publisher takes and journals its changes in order on its one thread,
/// and pays nothing on its write path.
#[test]
fn only_a_writer_of_a_publisher_marks_its_changes_in_flight() {
    let (_domain, p) = participant_on("in-flight-guard", TransportMode::UdpMulticast);
    let publisher = Arc::new(
        p.create_publisher(qos(PresentationAccessScope::Group, true))
            .expect("publisher"),
    );
    let grouped = writer(
        &p,
        &publisher,
        "Guarded",
        qos(PresentationAccessScope::Group, true),
    );
    let plain = p
        .topic::<Sample>("Unguarded")
        .expect("topic")
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("writer");
    assert!(plain.history_cache.is_some(), "fixture: a reliable history");
    assert!(
        plain.taking_change().is_none(),
        "no other producer: no guard"
    );
    assert!(grouped.taking_change().is_some(), "ends of set: guarded");
}

/// The TOPIC-scope form of `an_end_of_set_after_an_sn_given_back_claims_no_phantom_member`:
/// a write abandoned inside a set gives its SN back, and the end of set,
/// which takes that SN, names the set's real last member, not itself.
#[test]
fn a_topic_end_of_set_after_an_sn_given_back_claims_no_phantom_member() {
    let (_domain, p) = participant_on("topic-giveback", TransportMode::UdpMulticast);
    let q = || qos(PresentationAccessScope::Topic, true);
    let publisher = Arc::new(p.create_publisher(q()).expect("publisher"));
    let a = writer(&p, &publisher, "TopicGiveA", q());
    publisher.begin_coherent_changes().expect("begin");
    a.write(&Sample { id: 1, v: 1 }).expect("a1");
    assert_eq!(a.abandon_topic_change_for_test(), 2);
    publisher.end_coherent_changes().expect("end");
    let snap = a.history_cache.clone().expect("h").snapshot_changes();
    let ecs = snap
        .iter()
        .find(|c| c.metadata.kind == crate::reliability::ChangeKind::EcsClose)
        .expect("A's end of set");
    assert_eq!(ecs.seq, 2, "the end takes the SN given back");
    assert_eq!(ecs.metadata.coherent_sn, Some(1), "its last member is 1");
}

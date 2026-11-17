// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A GROUP-scope reader receiving the coherent sets of a Publisher whose
//! writers speak the spec GROUP dialect (RTPS v2.5 Sec.8.7.5, Sec.8.7.6):
//! each change of a set names the set's writer set (PID_WRITER_GROUP_INFO),
//! every writer of the Publisher ends every set, an idle one with an end of
//! its own SN, and the reader decides a set against discovery's writers of
//! the Publisher.

use super::subscriber::GroupRoster;
use super::tests_history_limits::{encoded, Keyed, NetworkReader};
use crate::dds::QoS;
use crate::engine::Subscriber as _;
use std::sync::{Arc, Mutex};

const PREFIX: [u8; 12] = [0x5B; 12];
const PUBLISHER: [u8; 4] = [0, 0, 0x31, 0x08];
const A: [u8; 4] = [0, 0, 0x01, 0x02];
const B: [u8; 4] = [0, 0, 0x02, 0x02];

fn guid(id: [u8; 4]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&PREFIX);
    g[12..].copy_from_slice(&id);
    g
}

/// Discovery's writers of the Publisher, all on the reader's topic.
struct Roster(Mutex<Vec<[u8; 4]>>, std::sync::atomic::AtomicU64);

impl GroupRoster for Roster {
    fn writers_of(
        &self,
        prefix: &[u8; 12],
        publisher: [u8; 4],
        _topic: &str,
    ) -> Vec<([u8; 4], bool)> {
        if *prefix != PREFIX || publisher != PUBLISHER {
            return Vec::new();
        }
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|id| (*id, true))
            .collect()
    }

    /// Moves when a test says discovery's answer changed.
    fn generation(&self) -> u64 {
        self.1.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A reliable KEEP_ALL GROUP reader matched with writers `A` and `B` of the
/// Publisher, discovery knowing `known` of its writers.
fn reader(topic: &str, known: &[[u8; 4]]) -> (NetworkReader<Keyed>, Arc<Roster>) {
    reader_with(topic, known, QoS::reliable().keep_all())
}

fn reader_with(topic: &str, known: &[[u8; 4]], qos: QoS) -> (NetworkReader<Keyed>, Arc<Roster>) {
    let net = NetworkReader::<Keyed>::with_parts(
        topic,
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    let roster = Arc::new(Roster(
        Mutex::new(known.to_vec()),
        std::sync::atomic::AtomicU64::new(0),
    ));
    let _ = net
        .subscriber
        .group_roster
        .set(Arc::clone(&roster) as Arc<dyn GroupRoster>);
    for id in [A, B] {
        net.credit.match_writer(guid(id));
        net.subscriber.on_writer_heartbeat(guid(id), 1);
    }
    (net, roster)
}

fn writer_set() -> [u8; 4] {
    crate::protocol::group::group_digest([A, B])
}

/// Change `seq` of writer `id`, a member of the set whose first GSN is
/// `set`, its part starting at `start`.
fn member(net: &NetworkReader<Keyed>, id: [u8; 4], seq: u64, start: u64, set: u64, value: i32) {
    member_naming(net, id, seq, start, set, value, writer_set());
}

fn member_naming(
    net: &NetworkReader<Keyed>,
    id: [u8; 4],
    seq: u64,
    start: u64,
    set: u64,
    value: i32,
    named: [u8; 4],
) {
    member_gsn_naming(net, id, seq, start, set, value, named, None);
}

/// `member_naming`, the change carrying PID_GROUP_SEQ_NUM `gsn`.
#[allow(clippy::too_many_arguments)]
fn member_gsn_naming(
    net: &NetworkReader<Keyed>,
    id: [u8; 4],
    seq: u64,
    start: u64,
    set: u64,
    value: i32,
    named: [u8; 4],
    gsn: Option<u64>,
) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_group_change(
        guid(id),
        crate::engine::GroupChange {
            seq,
            group_sn: set,
            publisher_entity_id: PUBLISHER,
            writer_set: named,
            gsn,
            part_first_sn: None,
        },
    );
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(id),
        seq,
        &encoded(&Keyed { id: value, value }),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        Some(set),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

/// Writer `id`'s end `seq` of the set `set`, its part from `part_first`
/// (its own SN when it wrote nothing in the set).
fn end(net: &NetworkReader<Keyed>, id: [u8; 4], seq: u64, part_first: u64, set: u64) {
    end_gsn(net, id, seq, part_first, set, None);
}

/// `end`, carrying PID_GROUP_SEQ_NUM `gsn` (the set's end GSN).
fn end_gsn(
    net: &NetworkReader<Keyed>,
    id: [u8; 4],
    seq: u64,
    part_first: u64,
    set: u64,
    gsn: Option<u64>,
) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_group_change(
        guid(id),
        crate::engine::GroupChange {
            seq,
            group_sn: set,
            publisher_entity_id: PUBLISHER,
            writer_set: writer_set(),
            gsn,
            part_first_sn: Some(part_first),
        },
    );
    net.subscriber.on_ecs(
        &net.topic,
        guid(id),
        seq,
        seq - 1,
        Some(set),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

fn values(net: &NetworkReader<Keyed>) -> Vec<i32> {
    net.take_all().iter().map(|s| s.value).collect()
}

/// A set only A wrote in waits for B's end too: B is a writer of the
/// Publisher matched here, and every writer ends every set (D6). Delivered
/// whole once it lands.
#[test]
fn a_spec_group_set_waits_for_the_end_of_every_writer_of_its_publisher() {
    let (net, _) = reader("spec-group-every-end", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    member(&net, A, 2, 1, 1, 12);
    end(&net, A, 3, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B has not ended the set");
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), vec![11, 12]);
    assert_eq!(net.lost(), 0);
}

/// A writer that ends a set with a part none of whose changes landed: the
/// set waits for them, and is whole with them.
#[test]
fn a_spec_group_set_waits_for_a_part_its_end_overtook() {
    let (net, _) = reader("spec-group-overtaken", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B's change 1 is owed");
    member(&net, B, 1, 1, 1, 21);
    let mut got = values(&net);
    got.sort_unstable();
    assert_eq!(got, vec![11, 21]);
}

/// The part of B whose only change was GAPped as lost (not filtered): the
/// set is never whole, and is reported lost, never delivered in part.
#[test]
fn a_spec_group_set_with_a_part_gapped_is_lost_whole() {
    let (net, _) = reader("spec-group-gapped-part", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    net.subscriber.on_writer_gap(guid(B), 1, 2, Vec::new());
    end(&net, B, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new());
    assert_eq!(
        net.lost(),
        2,
        "B's, lost to the GAP, and A's, discarded with its set"
    );
}

/// A set is not delivered while one of its writers still owes a change
/// before its part: fed into that writer's gate, its part was held there
/// and the other parts delivered.
#[test]
fn a_spec_group_set_waits_for_its_writers_earlier_changes() {
    let (net, _) = reader("spec-group-earlier", &[A, B]);
    member(&net, A, 2, 2, 1, 12);
    end(&net, A, 3, 2, 1);
    member(&net, B, 1, 1, 1, 21);
    end(&net, B, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "A's change 1 is owed");
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_with_writer(
        &net.topic,
        guid(A),
        1,
        &encoded(&Keyed { id: 1, value: 1 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let got = values(&net);
    assert_eq!(got.first(), Some(&1), "A's earlier change first: {got:?}");
    let mut set: Vec<i32> = got[1..].to_vec();
    set.sort_unstable();
    assert_eq!(set, vec![12, 21]);
}

/// Discovery does not know B, which the set's writer set names: the set
/// waits for it (SEDP lags), and once known, is decided as any other.
#[test]
fn a_spec_group_set_waits_for_discovery_to_know_its_writers() {
    let (net, roster) = reader("spec-group-roster-lag", &[A]);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B is not known yet");
    roster.0.lock().unwrap_or_else(|e| e.into_inner()).push(B);
    // Any event of the reader decides it again: a HEARTBEAT.
    net.subscriber.on_writer_heartbeat(guid(A), 1);
    assert_eq!(values(&net), vec![11]);
    assert_eq!(net.lost(), 0);
}

/// Discovery forgets a Publisher (its participant's SPDP dispose, read on
/// the discovery thread) while ends of its last set are still queued
/// behind the data: the set is decided against the writers the reader
/// knew until their departures reach it, in the data's order
/// (`engine::departures`). Decided again against discovery's empty answer,
/// the set waited for no writer, and A's part was delivered alone, B's
/// after it: a torn GROUP set.
#[test]
fn a_spec_group_set_ended_after_discovery_forgot_its_publisher_is_whole() {
    let (net, roster) = reader("spec-group-roster-forgotten", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), vec![11], "fixture: a first set decided");
    member(&net, A, 3, 3, 4, 13);
    end(&net, A, 4, 3, 4);
    roster.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
    roster.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    // Any event of the reader decides the set again: a HEARTBEAT.
    net.subscriber.on_writer_heartbeat(guid(A), 4);
    assert_eq!(values(&net), Vec::<i32>::new(), "B's end is still queued");
    member(&net, B, 2, 2, 4, 22);
    end(&net, B, 3, 2, 4);
    let mut got = values(&net);
    got.sort_unstable();
    assert_eq!(got, vec![13, 22], "the last set, whole");
    assert_eq!(net.lost(), 0);
    // Their departures reached the reader: it knows them no more.
    for id in [A, B] {
        net.subscriber.on_writer_dispose(
            &net.topic,
            guid(id),
            crate::engine::DisposeKind::Unregistered,
        );
    }
    assert!(
        net.subscriber
            .roster_seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "forgotten with their departures"
    );
}

/// ... but not for ever: past the wait the set is discarded and reported
/// lost, never delivered for the writers discovery knows (D7).
#[test]
fn a_spec_group_set_whose_writers_stay_unknown_is_discarded() {
    let (net, _) = reader("spec-group-roster-never", &[A]);
    net.subscriber
        .group_roster_wait_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new());
    assert_eq!(net.lost(), 1);
}

/// Two changes of one set naming two writer sets: a writer joined or left
/// the Publisher inside the set, refused at its API (D11): the set is
/// never whole.
#[test]
fn a_spec_group_set_naming_two_writer_sets_is_discarded() {
    let (net, _) = reader("spec-group-two-sets", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    member_naming(
        &net,
        B,
        1,
        1,
        1,
        21,
        crate::protocol::group::group_digest([A]),
    );
    end(&net, A, 2, 1, 1);
    end(&net, B, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new());
    assert_eq!(net.lost(), 2);
}

/// A writer that leaves before ending a set it is a writer of: the set is
/// never whole (Sec.8.7.6), discarded and reported lost.
#[test]
fn a_spec_group_set_a_writer_leaves_before_ending_is_lost() {
    let (net, roster) = reader("spec-group-departure", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    // Discovery forgets B and the reader hears it left.
    roster
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|id| *id != B);
    net.subscriber.on_writer_dispose(
        &net.topic,
        guid(B),
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    assert_eq!(values(&net), Vec::<i32>::new());
    assert_eq!(net.lost(), 1);
}

/// A departed writer's GSN record (`writer_gsns`) is forgotten with it: a
/// writer re-created under the same GUID announces its GSNs again from its
/// own start (RTPS v2.5 Sec.8.7.5, "strictly monotonically increasing" per
/// writer, not across an old and a new incarnation). A sibling's record,
/// for a set of its own still open, is untouched.
#[test]
fn a_departed_writers_gsns_are_forgotten_a_sibling_mid_set_keeps_its_own() {
    let (net, roster) = reader("spec-group-gsn-departure", &[A, B]);
    // B's GSN record: a HEARTBEAT's GroupInfo.
    net.subscriber.on_writer_group_heartbeat(guid(B), 5, 1, 5);
    // A's GSN record, and a set of its own still open (not yet ended).
    net.subscriber.on_writer_group_heartbeat(guid(A), 3, 1, 3);
    member(&net, A, 1, 1, 1, 11);
    assert!(
        net.subscriber
            .writer_gsns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&guid(B)),
        "B's GSN record exists before it departs"
    );
    // Discovery forgets B and the reader hears it left.
    roster
        .0
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|id| *id != B);
    net.subscriber.on_writer_departure(
        &net.topic,
        guid(B),
        crate::engine::subscriber::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    let gsns = net
        .subscriber
        .writer_gsns
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    assert!(!gsns.contains_key(&guid(B)), "B's GSN record is forgotten");
    assert!(
        gsns.contains_key(&guid(A)),
        "A's GSN record, of a set still in flight, is not disturbed"
    );
}

/// A writer that only fell silent (`WriterDeparture::Unheard`: a lease
/// expiry, a probation purge) may come back as the same writer, its GSNs
/// going on: its record is kept, so a GSN that goes backward across the
/// silence still breaks the set (RTPS v2.5 Sec.8.7.5, "strictly
/// monotonically increasing").
#[test]
fn a_silent_writers_gsn_record_survives_its_return() {
    let (net, _) = reader("gsn-unheard-flicker", &[A, B]);
    member_gsn_naming(&net, A, 1, 1, 1, 11, writer_set(), Some(100));
    end_gsn(&net, A, 2, 1, 1, Some(101));
    member(&net, B, 1, 1, 1, 21);
    end(&net, B, 2, 1, 1);
    let mut first = values(&net);
    first.sort_unstable();
    assert_eq!(first, vec![11, 21], "fixture: the first set, whole");
    assert_eq!(net.lost(), 0);

    net.subscriber.on_writer_dispose(
        &net.topic,
        guid(A),
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    assert!(
        net.subscriber
            .writer_gsns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&guid(A)),
        "a silent writer's GSN record is kept"
    );
    // Back, its first HEARTBEAT naming the same highest SN: the same writer.
    net.credit.match_writer(guid(A));
    net.subscriber.on_writer_heartbeat_range(guid(A), 1, 2);
    // GSN 50 after 101 from the same SN stream.
    member_gsn_naming(&net, A, 3, 3, 4, 13, writer_set(), Some(50));
    end_gsn(&net, A, 4, 3, 4, Some(51));
    member(&net, B, 3, 3, 4, 23);
    end(&net, B, 4, 3, 4);
    assert_eq!(
        values(&net),
        Vec::<i32>::new(),
        "a GSN gone backward across the silence breaks the set"
    );
}

/// The same backward GSN with no departure in between: the set is broken.
#[test]
fn a_backward_gsn_breaks_the_set() {
    let (net, _) = reader("gsn-no-flicker-control", &[A, B]);
    member_gsn_naming(&net, A, 1, 1, 1, 11, writer_set(), Some(100));
    end_gsn(&net, A, 2, 1, 1, Some(101));
    member(&net, B, 1, 1, 1, 21);
    end(&net, B, 2, 1, 1);
    let mut first = values(&net);
    first.sort_unstable();
    assert_eq!(first, vec![11, 21], "fixture: the first set, whole");
    assert_eq!(net.lost(), 0);

    member_gsn_naming(&net, A, 3, 3, 4, 13, writer_set(), Some(50));
    end_gsn(&net, A, 4, 3, 4, Some(51));
    member(&net, B, 3, 3, 4, 23);
    end(&net, B, 4, 3, 4);
    assert_eq!(values(&net), Vec::<i32>::new());
}

/// A silent writer that never comes back: its GSN record goes when its
/// departure is forgotten (`DEPARTED_KEEP`), not before.
#[test]
fn a_silent_writers_gsn_record_goes_with_its_forgotten_departure() {
    let (net, _) = reader("gsn-unheard-forgotten", &[A, B]);
    member_gsn_naming(&net, A, 1, 1, 1, 11, writer_set(), Some(100));
    end_gsn(&net, A, 2, 1, 1, Some(101));
    member(&net, B, 1, 1, 1, 21);
    end(&net, B, 2, 1, 1);
    net.subscriber.on_writer_dispose(
        &net.topic,
        guid(A),
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    let has_a = || {
        net.subscriber
            .writer_gsns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&guid(A))
    };
    // Any traffic runs the departure check; the departure is still kept.
    member(&net, B, 3, 3, 4, 23);
    assert!(has_a(), "kept while its departure is");
    net.subscriber
        .set_departed_keep_for_test(std::time::Duration::from_millis(1));
    // A lower bound on elapsed time, not a wait for an event.
    std::thread::sleep(std::time::Duration::from_millis(5));
    end(&net, B, 4, 3, 4);
    assert!(!has_a(), "forgotten with its departure");
}

/// An empty set (no writer wrote in it): every writer's end lands, nothing
/// is delivered, nothing lost, and the next set is decided as usual.
#[test]
fn an_empty_spec_group_set_delivers_nothing_and_holds_nothing() {
    let (net, _) = reader("spec-group-empty", &[A, B]);
    end(&net, A, 1, 1, 1);
    end(&net, B, 1, 1, 1);
    member(&net, A, 2, 2, 2, 12);
    end(&net, A, 3, 2, 2);
    end(&net, B, 2, 2, 2);
    assert_eq!(values(&net), vec![12]);
    assert_eq!(net.lost(), 0);
    assert!(
        net.subscriber
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "both sets decided"
    );
}

/// A set whose every member the writer filtered for this reader (a GAP
/// with filteredCount): whole without them, nothing to deliver.
#[test]
fn a_fully_filtered_spec_group_set_is_whole_and_empty() {
    let (net, _) = reader("spec-group-filtered", &[A, B]);
    net.subscriber
        .on_writer_gap_filtered(guid(A), 1, 3, Vec::new(), 2);
    end(&net, A, 3, 1, 1);
    end(&net, B, 1, 1, 1);
    member(&net, A, 4, 4, 2, 14);
    end(&net, A, 5, 4, 2);
    end(&net, B, 2, 2, 2);
    assert_eq!(values(&net), vec![14]);
    assert_eq!(net.lost(), 0);
}

/// Two sets complete at once, the later one waiting on the earlier one's
/// parts in its writers' gates: both delivered, in order, with no further
/// event.
#[test]
fn two_spec_group_sets_completed_together_are_delivered_in_order() {
    let (net, _) = reader("spec-group-two-in-a-row", &[A, B]);
    // Set 2 lands whole first; set 1 is completed last.
    member(&net, A, 3, 3, 2, 13);
    end(&net, A, 4, 3, 2);
    member(&net, B, 3, 3, 2, 23);
    end(&net, B, 4, 3, 2);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B's change 1 is owed");
    member(&net, B, 1, 1, 1, 21);
    let got = values(&net);
    let mut first: Vec<i32> = got.iter().copied().take(2).collect();
    let mut second: Vec<i32> = got.iter().copied().skip(2).collect();
    first.sort_unstable();
    second.sort_unstable();
    assert_eq!((first, second), (vec![11, 21], vec![13, 23]), "{got:?}");
}

/// A change of A after its part of a set still open, held by A's gate
/// (its part is staged, not through the gate): it takes no place. Held
/// with one, it kept a place the set needed once B's part landed, and the
/// set waited for it while it waited for the set. Refused, unacknowledged,
/// it is sent again and delivered after the set.
#[test]
fn a_change_held_above_an_open_spec_group_set_takes_no_place() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 3;
    let (net, _) = reader_with("spec-group-held-above", &[A, B], qos);
    member(&net, A, 1, 1, 1, 11);
    member(&net, A, 2, 1, 1, 12);
    end(&net, A, 3, 1, 1);
    let plain = |net: &NetworkReader<Keyed>| {
        crate::engine::router::set_route_writer_is_hdds_for_test(true);
        net.subscriber.on_data_with_writer(
            &net.topic,
            guid(A),
            4,
            &encoded(&Keyed { id: 4, value: 4 }),
            crate::dds::CdrVersion::Xcdr2,
        );
        crate::engine::router::set_route_writer_is_hdds_for_test(false);
    };
    plain(&net);
    member(&net, B, 1, 1, 1, 21);
    end(&net, B, 2, 1, 1);
    let mut set = values(&net);
    set.sort_unstable();
    assert_eq!(set, vec![11, 12, 21], "the set has its three places");
    plain(&net);
    assert_eq!(values(&net), vec![4], "sent again, delivered after it");
    assert_eq!(net.lost(), 0);
}

/// A write abandoned inside a set (its SN and GSN not given back, D16):
/// its writer GAPs it naming its GSN, which reaches the reader as a
/// change filtered for it (`release_reorder_gate`). The set is whole
/// without it, nothing lost.
#[test]
fn a_spec_group_set_with_an_abandoned_write_is_whole_without_it() {
    let (net, _) = reader("spec-group-abandoned", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    net.subscriber
        .on_writer_gap_filtered(guid(A), 2, 3, Vec::new(), 1);
    member(&net, A, 3, 1, 1, 13);
    end(&net, A, 4, 1, 1);
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), vec![11, 13]);
    assert_eq!(net.lost(), 0);
}

/// An end of a set delivered already, landing again (a repair the writer
/// sent twice): stepped over, opening no set that would never close.
#[test]
fn a_spec_group_sets_end_landing_again_opens_nothing() {
    let (net, _) = reader("spec-group-end-again", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), vec![11]);
    let staged = |net: &NetworkReader<Keyed>| {
        net.subscriber
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    };
    end(&net, B, 1, 1, 1);
    assert_eq!(staged(&net), 0, "after B's end again");
    member(&net, A, 1, 1, 1, 11);
    assert_eq!(staged(&net), 0, "after A's change again");
    end(&net, A, 2, 1, 1);
    assert!(
        net.subscriber
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "nothing staged for a set delivered"
    );
    assert_eq!(values(&net), Vec::<i32>::new());
}

/// A reader that joins late: the writer's HEARTBEAT announces its history
/// from SN 3, but its part of the set began at SN 1 (its end says so): the
/// part can never be whole, the set is lost, never delivered in part
/// (RTPS v2.5 Sec.8.7.6, S5).
#[test]
fn a_spec_group_set_begun_before_a_late_joiner_is_lost() {
    let net = NetworkReader::<Keyed>::with_parts(
        "spec-group-late-joiner",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    let roster = Arc::new(Roster(
        Mutex::new(vec![A, B]),
        std::sync::atomic::AtomicU64::new(0),
    ));
    let _ = net
        .subscriber
        .group_roster
        .set(roster as Arc<dyn GroupRoster>);
    net.credit.match_writer(guid(A));
    net.credit.match_writer(guid(B));
    net.subscriber.on_writer_heartbeat(guid(A), 3);
    net.subscriber.on_writer_heartbeat(guid(B), 1);
    member(&net, A, 3, 1, 1, 13);
    end(&net, A, 4, 1, 1);
    member(&net, B, 1, 1, 1, 21);
    end(&net, B, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new());
    assert!(net.lost() >= 2, "both parts' samples: {}", net.lost());
}

/// The bound on a set whose writers discovery does not know (D7) expires
/// by itself: with no further event from the Publisher, the set is
/// discarded and reported lost once the wait is over (a retry the reader
/// schedules on its own lane), never parked for good.
#[test]
fn a_spec_group_roster_wait_expires_with_no_traffic() {
    let (net, _) = reader("spec-group-roster-timer", &[A]);
    net.subscriber
        .group_roster_wait_ms
        .store(30, std::sync::atomic::Ordering::Relaxed);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B unknown yet");
    let staged = || {
        net.subscriber
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    // The set leaves the buffer, then its loss is reported: wait for both.
    while (staged() != 0 || net.lost() == 0) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(staged(), 0, "discarded with no event");
    assert_eq!(net.lost(), 1, "reported lost");
    assert_eq!(values(&net), Vec::<i32>::new());
}

/// The writers of a Publisher a reader is matched with are the ones the
/// match registry pairs it with (`pairs_with`), whatever refuses the pair:
/// RELIABILITY (B), another topic (C), OWNERSHIP kind (D: EXCLUSIVE for a
/// SHARED reader), DataRepresentation (E: XCDR1 only for an XCDR2 reader).
/// A writer the reader is not matched with sends it nothing, its end of
/// set either: waited for, it parked every set of its Publisher.
#[test]
fn a_writer_the_reader_cannot_match_is_not_waited_for() {
    use crate::core::discovery::multicast::DiscoveryFsm;
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::{SedpData, SpdpData};
    let fsm = Arc::new(DiscoveryFsm::new(GUID::zero(), 100_000));
    fsm.handle_spdp(SpdpData {
        participant_guid: GUID::new(PREFIX, [0, 0, 1, 0xC1]),
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
        hdds_capabilities: Some(crate::protocol::group::CAP_SPEC_GROUP_COHERENT),
        builtin_endpoint_set: None,
    });
    // Every writer offers XCDR2 (an absent offer is XCDR1, DDS-XTypes v1.3
    // Sec.7.6.3.1.2) but E.
    let xcdr2 = |mut qos: QoS| {
        qos.data_representation = vec![0x0002];
        qos
    };
    let mut exclusive = xcdr2(QoS::reliable());
    exclusive.ownership.kind = crate::qos::ownership::OwnershipKind::Exclusive;
    let mut xcdr1_only = QoS::reliable();
    xcdr1_only.data_representation = vec![0x0000];
    const C: [u8; 4] = [0, 0, 0x03, 0x02];
    const D: [u8; 4] = [0, 0, 0x04, 0x02];
    const E: [u8; 4] = [0, 0, 0x05, 0x02];
    for (id, topic, qos, explicit_ownership) in [
        (A, "Matched", xcdr2(QoS::reliable()), false),
        (B, "Matched", xcdr2(QoS::best_effort()), false),
        (C, "Other", xcdr2(QoS::reliable()), false),
        (D, "Matched", exclusive, true),
        (E, "Matched", xcdr1_only, false),
    ] {
        fsm.handle_sedp(SedpData {
            topic_name: topic.to_string(),
            type_name: "Keyed".to_string(),
            participant_guid: GUID::new(PREFIX, [0, 0, 1, 0xC1]),
            endpoint_guid: GUID::new(PREFIX, id),
            qos_hash: 0,
            qos: Some(qos),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: true,
            has_explicit_ownership: explicit_ownership,
            has_ownership_strength: explicit_ownership,
            type_information: None,
            type_consistency: None,
            group_entity_id: Some(PUBLISHER),
            endpoint_security_info: None,
        });
    }
    let registry =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x77; 12]));
    let mut reader_qos = QoS::reliable();
    reader_qos.data_representation = vec![0x0002];
    let token = registry.register_reader_with_lifespan(
        "Matched".to_string(),
        reader_qos,
        crate::dds::match_notification::LocalType::new(
            crate::dds::cdr_negotiation::Xcdr1Encoding::of::<Keyed>(),
            "Keyed",
        ),
        None,
        |_, _, _, _, _| (),
        None,
        None,
        None,
        Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX)),
        crate::transport::shm::ShmPolicy::Disable,
    );
    let entry = Arc::new(std::sync::OnceLock::new());
    let roster = super::subscriber::DiscoveryRoster {
        fsm,
        registry: Arc::clone(&registry),
        entry: Arc::clone(&entry),
    };
    let mut writers = roster.writers_of(&PREFIX, PUBLISHER, "Matched");
    writers.sort_unstable();
    assert_eq!(
        writers,
        vec![(A, true), (B, true), (C, false), (D, true), (E, true)],
        "before the reader's entry is registered, every writer of its topic is waited for"
    );
    assert!(!roster.ready(), "no set decided before the entry exists");
    let _ = entry.set(token.id());
    assert!(roster.ready());
    let mut writers = roster.writers_of(&PREFIX, PUBLISHER, "Matched");
    writers.sort_unstable();
    assert_eq!(
        writers,
        vec![(A, true), (B, false), (C, false), (D, false), (E, false)],
        "all five in the writer set, only A matched"
    );
}

fn member_gsn(net: &NetworkReader<Keyed>, id: [u8; 4], seq: u64, start: u64, set: u64, gsn: u64) {
    member_gsn_naming(
        net,
        id,
        seq,
        start,
        set,
        i32::try_from(gsn).expect("small"),
        writer_set(),
        Some(gsn),
    );
}

/// A set whose GSNs agree with the spec (RTPS v2.5 Sec.8.7.6): its members
/// from its first GSN up, each writer's increasing with its SNs, every end
/// carrying the same end GSN, the last GSN plus one. Delivered.
#[test]
fn a_spec_group_set_whose_gsns_agree_is_delivered() {
    let (net, _) = reader("spec-group-gsn-ok", &[A, B]);
    member_gsn(&net, A, 1, 1, 10, 10);
    member_gsn(&net, B, 1, 1, 10, 11);
    member_gsn(&net, A, 2, 1, 10, 12);
    end_gsn(&net, A, 3, 1, 10, Some(13));
    end_gsn(&net, B, 2, 1, 10, Some(13));
    let mut got = values(&net);
    got.sort_unstable();
    assert_eq!(got, vec![10, 11, 12]);
    assert_eq!(net.lost(), 0);
}

/// Each way a set's GSNs can contradict the spec makes it never whole:
/// discarded, reported lost, never delivered.
#[test]
fn a_spec_group_set_whose_gsns_contradict_the_spec_is_lost() {
    // (name, A's member GSNs, B's member GSN, A's end GSN, B's end GSN)
    for (name, a_gsns, b_gsn, a_end, b_end) in [
        ("member at the end GSN", [10, 11], 13, 13, 13),
        ("member below the set's first GSN", [9, 11], 12, 13, 13),
        ("two end GSNs", [10, 11], 12, 13, 14),
        ("a writer's GSNs decreasing", [12, 11], 10, 13, 13),
        ("end below the set's first GSN", [10, 11], 12, 9, 9),
    ] {
        let (net, _) = reader(&format!("spec-group-gsn-{}", name.len()), &[A, B]);
        member_gsn(&net, A, 1, 1, 10, a_gsns[0]);
        member_gsn(&net, A, 2, 1, 10, a_gsns[1]);
        member_gsn(&net, B, 1, 1, 10, b_gsn);
        end_gsn(&net, A, 3, 1, 10, Some(a_end));
        end_gsn(&net, B, 2, 1, 10, Some(b_end));
        assert_eq!(values(&net), Vec::<i32>::new(), "{name}: nothing delivered");
        assert_eq!(net.lost(), 3, "{name}: reported lost");
    }
}

/// A writer announces it does not have the change of GSN `g` (RTPS v2.5
/// Sec.8.7.5): its HEARTBEAT's currentGSN is past `g` and `g` is outside
/// its [firstGSN, lastGSN].
#[test]
fn a_heartbeat_announces_a_gsn_absent() {
    use super::subscriber::gsn_announced_absent as absent;
    assert!(absent(13, [20, 14, 18]), "below its first");
    assert!(absent(13, [20, 1, 5]), "above its last, current past it");
    assert!(!absent(13, [20, 10, 18]), "inside its range");
    assert!(!absent(13, [13, 1, 5]), "current not past it");
    assert!(absent(13, [14, 14, 13]), "an empty range past it");
    assert!(!absent(13, [13, 13, 12]), "an empty range at it");
}

/// A set one of whose writers announced (HEARTBEAT GroupInfo) that it no
/// longer has the set's end GSN, its end not received: the end never comes
/// (evicted before this reader joined, say), the set is never whole:
/// discarded and reported lost at once, not parked.
#[test]
fn a_spec_group_set_whose_writer_no_longer_has_its_end_is_lost() {
    let (net, _) = reader("spec-group-end-gone", &[A, B]);
    member_gsn(&net, A, 1, 1, 10, 10);
    end_gsn(&net, A, 2, 1, 10, Some(12));
    assert_eq!(values(&net), Vec::<i32>::new(), "B's end awaited");
    assert_eq!(net.lost(), 0);
    // B's history now holds GSNs 14 to 20 only.
    net.subscriber
        .on_writer_group_heartbeat(guid(B), 20, 14, 20);
    assert_eq!(values(&net), Vec::<i32>::new());
    assert_eq!(net.lost(), 1, "discarded, A's sample reported lost");
    assert!(net
        .subscriber
        .group_coherent_buffer
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_empty());
}

/// The same HEARTBEAT holding the end GSN in its range leaves the set
/// waiting: the end may still come (a repair).
#[test]
fn a_spec_group_set_whose_writer_still_has_its_end_waits() {
    let (net, _) = reader("spec-group-end-held", &[A, B]);
    member_gsn(&net, A, 1, 1, 10, 10);
    end_gsn(&net, A, 2, 1, 10, Some(12));
    net.subscriber
        .on_writer_group_heartbeat(guid(B), 20, 11, 20);
    assert_eq!(net.lost(), 0);
    end_gsn(&net, B, 1, 1, 10, Some(12));
    assert_eq!(values(&net), vec![10]);
}

/// A set whose ends all landed is not delivered while one of its writers
/// has not advanced past its last GSN in its SN order (Sec.8.7.5): here
/// the end of writer B landed before B's earlier change, which is owed.
#[test]
fn a_spec_group_set_waits_for_its_writers_to_reach_its_end_gsn() {
    let (net, _) = reader("spec-group-gsn-order", &[A, B]);
    member_gsn(&net, A, 1, 1, 10, 10);
    end_gsn(&net, A, 2, 1, 10, Some(12));
    // B's end, SN 3, before B's member SN 2 (and SN 1, of no set).
    end_gsn(&net, B, 3, 2, 10, Some(12));
    assert_eq!(values(&net), Vec::<i32>::new(), "B's changes are owed");
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_with_writer(
        &net.topic,
        guid(B),
        1,
        &encoded(&Keyed { id: 1, value: 1 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    member_gsn(&net, B, 2, 2, 10, 11);
    let got = values(&net);
    assert_eq!(got.first(), Some(&1), "B's earlier change first: {got:?}");
    let mut set: Vec<i32> = got[1..].to_vec();
    set.sort_unstable();
    assert_eq!(set, vec![10, 11]);
}

/// A member whose GSN is not below its set's end GSN, landing after the
/// end: the set is never whole.
#[test]
fn a_spec_group_member_at_or_past_the_end_gsn_breaks_its_set() {
    let (net, _) = reader("spec-group-gsn-late-member", &[A, B]);
    member_gsn(&net, A, 1, 1, 10, 10);
    end_gsn(&net, A, 2, 1, 10, Some(12));
    // B's member, its end not landed yet: the member alone contradicts
    // the end GSN A's end gave.
    member_gsn(&net, B, 1, 1, 10, 12);
    assert_eq!(values(&net), Vec::<i32>::new());
    assert_eq!(net.lost(), 2);
}

/// The 1.4.x-form end of set an HDDS writer
/// sends after an in-set write was abandoned and its SN given back: the end
/// occupies the given-back SN and names it as the set's last SN. An HDDS
/// GROUP reader of the 1.4.x dialect (no GROUP tag) must still deliver the
/// set (member SN 1 is the only member).
#[test]
fn a_legacy_end_naming_itself_as_last_still_delivers() {
    let net = NetworkReader::<Keyed>::with_parts(
        "vlegacy-phantom-last",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    net.credit.match_writer(guid(A));
    net.subscriber.on_writer_heartbeat(guid(A), 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(A),
        1,
        &encoded(&Keyed { id: 1, value: 1 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        Some(1),
        Some(PUBLISHER),
    );
    // End of set at SN 2 naming last SN 2 (itself), as the writer emits it.
    net.subscriber
        .on_ecs(&net.topic, guid(A), 2, 2, Some(1), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    // Next HEARTBEAT, nothing else owed.
    net.subscriber.on_writer_heartbeat(guid(A), 1);
    let first = values(&net);
    // A's next, plain change SN 3 and a later set: do they still flow?
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_with_writer(
        &net.topic,
        guid(A),
        3,
        &encoded(&Keyed { id: 3, value: 3 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(A),
        4,
        &encoded(&Keyed { id: 4, value: 4 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(4),
        Some(2),
        Some(PUBLISHER),
    );
    net.subscriber
        .on_ecs(&net.topic, guid(A), 5, 4, Some(2), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    net.subscriber.on_writer_heartbeat(guid(A), 1);
    let later = values(&net);
    assert_eq!(first, vec![1], "the set: lost {}", net.lost());
    assert_eq!(later, vec![3, 4], "the changes after it");
    assert_eq!(net.lost(), 0);
}

/// The same set as `a_legacy_end_naming_itself_as_last_still_delivers`,
/// its end naming last SN 1, its member.
#[test]
fn a_legacy_end_naming_its_member_delivers() {
    let net = NetworkReader::<Keyed>::with_parts(
        "vlegacy-control",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    net.credit.match_writer(guid(A));
    net.subscriber.on_writer_heartbeat(guid(A), 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(A),
        1,
        &encoded(&Keyed { id: 1, value: 1 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        Some(1),
        Some(PUBLISHER),
    );
    net.subscriber
        .on_ecs(&net.topic, guid(A), 2, 1, Some(1), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    net.subscriber.on_writer_heartbeat(guid(A), 1);
    assert_eq!(values(&net), vec![1], "lost {}", net.lost());
}

/// A reliable KEEP_ALL GROUP reader of writers `A` and `B` of the 1.4.x
/// dialect (no writer set, an end of set only from the writers that
/// wrote, naming the last SN of the writer's part).
fn legacy_reader(topic: &str) -> NetworkReader<Keyed> {
    let net = NetworkReader::<Keyed>::with_parts(
        topic,
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    for id in [A, B] {
        net.credit.match_writer(guid(id));
        net.subscriber.on_writer_heartbeat(guid(id), 1);
    }
    net
}

/// Change `seq` of writer `id` in the 1.4.x dialect, a member of set `set`,
/// its part starting at `start`.
fn legacy_member(
    net: &NetworkReader<Keyed>,
    id: [u8; 4],
    seq: u64,
    start: u64,
    set: u64,
    value: i32,
) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(id),
        seq,
        &encoded(&Keyed { id: value, value }),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        Some(set),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

/// Writer `id`'s end `seq` of set `set` in the 1.4.x dialect, naming
/// `last`, the last SN of its part.
fn legacy_end(net: &NetworkReader<Keyed>, id: [u8; 4], seq: u64, last: u64, set: u64) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber
        .on_ecs(&net.topic, guid(id), seq, last, Some(set), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

/// The end of a set `A` wrote nothing in is not sent to a reader of the
/// 1.4.x dialect: `A` declares its SN by a GAP, filtered (RTPS v2.5
/// Sec.9.4.5.6, `build_gap_packet_filtered`), read from the wire bytes as
/// the receiver reads them. The SN carried no change for this reader, so
/// no sample is lost (Sec.8.4.9.2, T4; DDS v1.4 Sec.2.2.4.1), and A's
/// next set is delivered.
#[test]
fn an_idle_end_of_set_gapped_to_a_legacy_reader_loses_no_sample() {
    let net = legacy_reader("vlegacy-idle-end-gap");
    let mut bytes = crate::protocol::builder::build_gap_packet_filtered(&[0; 4], &A, 1, PREFIX);
    // The walk reads a datagram of at least 52 octets.
    bytes.extend_from_slice(&[0x01, 0x01, 0x00, 0x00].repeat(4));
    let gap =
        crate::core::discovery::multicast::control_parser::scan_all_embedded_control_submessages(
            &bytes,
        )
        .0
        .pop()
        .expect("a GAP");
    let (info, filtered) = (gap.info, gap.filtered_count);
    match filtered {
        Some(count) => net.subscriber.on_writer_gap_filtered(
            guid(A),
            info.gap_start,
            info.gap_list_base,
            info.gap_list_seqs,
            count,
        ),
        None => net.subscriber.on_writer_gap(
            guid(A),
            info.gap_start,
            info.gap_list_base,
            info.gap_list_seqs,
        ),
    }
    legacy_member(&net, A, 2, 2, 2, 12);
    legacy_end(&net, A, 3, 2, 2);
    assert_eq!(values(&net), vec![12], "A's next set");
    assert_eq!(net.lost(), 0, "an SN with no change for this reader");
}

/// A set of the 1.4.x dialect written by `A` and `B`, every change of it
/// received and both ends with it, while `A`'s change 1, before its part,
/// is still owed: nothing of the set is delivered until `settle` resolves
/// change 1, then the set is, whole, in one take (DDS v1.4 Sec.2.2.3.6).
/// What the reader took before and after.
fn legacy_set_behind_an_owed_change(
    topic: &str,
    settle: impl FnOnce(&NetworkReader<Keyed>),
) -> (Vec<i32>, Vec<i32>, u32) {
    let net = legacy_reader(topic);
    legacy_member(&net, B, 1, 1, 1, 21);
    legacy_member(&net, A, 2, 2, 1, 12);
    legacy_end(&net, B, 2, 1, 1);
    legacy_end(&net, A, 3, 2, 1);
    let before = values(&net);
    settle(&net);
    let mut after = values(&net);
    after.sort_unstable();
    (before, after, net.lost())
}

/// The order the 1.4.x wire gives under load: `A`'s change 1 is an end of
/// a set `A` wrote nothing in, which that wire does not send; its GAP
/// (RTPS v2.5 Sec.8.3.8.4, filtered for this reader) lands after the next
/// set. Fed into `A`'s gate still waiting at 1, `A`'s part was held there
/// while `B`'s went to the application, and released later on its own:
/// the set in two parts, and across a Subscriber's readers `B`'s part
/// waited for a generation `A`'s reader never deposited.
#[test]
fn a_legacy_group_set_waits_for_a_gap_of_its_writers_earlier_change() {
    let (before, after, lost) = legacy_set_behind_an_owed_change("vlegacy-owed-gap", |net| {
        net.subscriber
            .on_writer_gap_filtered(guid(A), 1, 2, vec![], 1);
    });
    assert_eq!(before, Vec::<i32>::new(), "A's change 1 is owed");
    assert_eq!(after, vec![12, 21], "the set, whole, once the GAP lands");
    assert_eq!(lost, 0, "a filtered change is no sample lost");
}

/// The same set, `A`'s change 1 a plain change repaired late: delivered
/// first, then the set, whole.
#[test]
fn a_legacy_group_set_waits_for_a_repair_of_its_writers_earlier_change() {
    let (before, after, lost) = legacy_set_behind_an_owed_change("vlegacy-owed-data", |net| {
        crate::engine::router::set_route_writer_is_hdds_for_test(true);
        net.subscriber.on_data_with_writer(
            &net.topic,
            guid(A),
            1,
            &encoded(&Keyed { id: 1, value: 1 }),
            crate::dds::CdrVersion::Xcdr2,
        );
        crate::engine::router::set_route_writer_is_hdds_for_test(false);
    });
    assert_eq!(before, Vec::<i32>::new(), "A's change 1 is owed");
    assert_eq!(after, vec![1, 12, 21], "A's change, then the set");
    assert_eq!(lost, 0);
}

/// The same set, `A`'s change 1 never received and gone from `A`'s history
/// (a HEARTBEAT's firstSN past it, RTPS v2.5 Sec.8.4.12.2, T7): one sample
/// lost, the set whole all the same, every change of it received.
#[test]
fn a_legacy_group_set_waits_for_a_heartbeat_past_its_writers_earlier_change() {
    let (before, after, lost) = legacy_set_behind_an_owed_change("vlegacy-owed-hb", |net| {
        net.subscriber.on_writer_heartbeat(guid(A), 2);
    });
    assert_eq!(before, Vec::<i32>::new(), "A's change 1 is owed");
    assert_eq!(after, vec![12, 21], "the set, whole");
    assert_eq!(lost, 1, "A's change 1, never received");
}

/// Discovery learning a set's writers on one thread while another times the
/// set out: the refresh that times it out asked discovery first (outside
/// the reader's locks), the one that learnt the writers decided the set
/// meanwhile. Played on one thread: the stale query re-enters the reader
/// (`retry_waiting_sets`), which learns the writers, before it answers.
struct RacingRoster {
    known: Mutex<Vec<[u8; 4]>>,
    /// When set, the next query first lets the reader learn `[A, B]`.
    race: Mutex<Option<std::sync::Weak<super::subscriber::ReaderSubscriber<Keyed>>>>,
}

impl GroupRoster for RacingRoster {
    fn writers_of(
        &self,
        _prefix: &[u8; 12],
        _publisher: [u8; 4],
        _topic: &str,
    ) -> Vec<([u8; 4], bool)> {
        let stale: Vec<([u8; 4], bool)> = self
            .known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|id| (*id, true))
            .collect();
        let racing = self.race.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(subscriber) = racing.and_then(|weak| weak.upgrade()) {
            *self.known.lock().unwrap_or_else(|e| e.into_inner()) = vec![A, B];
            subscriber.retry_waiting_sets();
        }
        stale
    }
}

/// A set timed out waiting for its writers is discarded only if they are
/// still unknown when it is: discovery may have brought them, and the set
/// been decided, between the refresh that timed it out and its discard.
#[test]
fn a_set_decided_while_it_timed_out_is_not_discarded() {
    let net = NetworkReader::<Keyed>::with_parts(
        "spec-group-roster-race",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    let roster = Arc::new(RacingRoster {
        known: Mutex::new(vec![A]),
        race: Mutex::new(None),
    });
    let _ = net
        .subscriber
        .group_roster
        .set(Arc::clone(&roster) as Arc<dyn GroupRoster>);
    for id in [A, B] {
        net.credit.match_writer(guid(id));
        net.subscriber.on_writer_heartbeat(guid(id), 1);
    }
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    // The wait over; the next refresh's query is stale by the time it
    // answers.
    net.subscriber
        .group_roster_wait_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    *roster.race.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(&net.subscriber));
    net.subscriber.retry_waiting_sets();
    assert_eq!(net.lost(), 0, "decided meanwhile: not discarded");
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), vec![11]);
    assert_eq!(net.lost(), 0);
}

/// The reader dropped while its roster timer is
/// pending: nothing runs against a dropped reader, no panic, and the
/// lane's thread does not keep the subscriber alive.
#[test]
fn a_reader_dropped_with_a_roster_timer_pending_is_freed() {
    let (net, _) = reader("spec-timer-drop", &[A]);
    net.subscriber
        .group_roster_wait_ms
        .store(150, std::sync::atomic::Ordering::Relaxed);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 1, 1, 1);
    let weak = Arc::downgrade(&net.subscriber);
    drop(net);
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(
        weak.upgrade().is_none(),
        "subscriber kept alive by its timer"
    );
}

/// GSN holes inside a set (another writer's abandoned writes, their GSN
/// not given back), GSNs starting mid-stream (1000), and the idle
/// writer's HEARTBEAT landing before its end: delivered, nothing lost.
#[test]
fn gsn_holes_and_a_mid_stream_start_deliver() {
    let (net, _) = reader("spec-gsn-holes", &[A, B]);
    member_gsn(&net, A, 1, 1, 1000, 1000);
    member_gsn(&net, B, 1, 1, 1000, 1002);
    member_gsn(&net, A, 2, 1, 1000, 1004);
    end_gsn(&net, A, 3, 1, 1000, Some(1006));
    net.subscriber
        .on_writer_group_heartbeat(guid(B), 1007, 1002, 1006);
    end_gsn(&net, B, 2, 1, 1000, Some(1006));
    let mut got = values(&net);
    got.sort_unstable();
    assert_eq!(got, vec![1000, 1002, 1004], "lost {}", net.lost());
    assert_eq!(net.lost(), 0);
}

/// A roster that can be not ready yet, and whose answer changes.
struct GatedRoster {
    known: Mutex<Vec<([u8; 4], bool)>>,
    ready: std::sync::atomic::AtomicBool,
    generation: std::sync::atomic::AtomicU64,
}

impl GroupRoster for GatedRoster {
    fn writers_of(
        &self,
        _prefix: &[u8; 12],
        _publisher: [u8; 4],
        _topic: &str,
    ) -> Vec<([u8; 4], bool)> {
        self.known.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn ready(&self) -> bool {
        self.ready.load(std::sync::atomic::Ordering::Acquire)
    }

    fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }
}

fn gated_reader(topic: &str, ready: bool) -> (NetworkReader<Keyed>, Arc<GatedRoster>) {
    let net = NetworkReader::<Keyed>::with_parts(
        topic,
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    let roster = Arc::new(GatedRoster {
        known: Mutex::new(vec![(A, true), (B, true)]),
        ready: std::sync::atomic::AtomicBool::new(ready),
        generation: std::sync::atomic::AtomicU64::new(1),
    });
    let _ = net
        .subscriber
        .group_roster
        .set(Arc::clone(&roster) as Arc<dyn GroupRoster>);
    for id in [A, B] {
        net.credit.match_writer(guid(id));
        net.subscriber.on_writer_heartbeat(guid(id), 1);
    }
    (net, roster)
}

/// A set is not decided against a roster that cannot tell yet which
/// writers the reader is matched with (its match entry not registered):
/// decided then, it required a writer the reader may never pair with, for
/// good. It is decided once the roster is ready.
#[test]
fn a_set_is_not_decided_before_the_roster_is_ready() {
    let (net, roster) = gated_reader("spec-roster-not-ready", false);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "not decided yet");
    roster
        .ready
        .store(true, std::sync::atomic::Ordering::Release);
    net.subscriber.retry_waiting_sets();
    assert_eq!(values(&net), vec![11]);
    assert_eq!(net.lost(), 0);
}

/// A set decided against the roster is decided again when the roster
/// changes: a writer it required that the reader no longer matches (B)
/// sends it nothing more, its end either; still required, the set waited
/// for it for good.
#[test]
fn a_set_is_decided_again_when_the_roster_changes() {
    let (net, roster) = gated_reader("spec-roster-changes", true);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B's end awaited");
    *roster.known.lock().unwrap_or_else(|e| e.into_inner()) = vec![(A, true), (B, false)];
    roster
        .generation
        .store(2, std::sync::atomic::Ordering::Release);
    net.subscriber.retry_waiting_sets();
    assert_eq!(values(&net), vec![11]);
    assert_eq!(net.lost(), 0);
}

/// The GROUP dialect of a writer decided again in the middle of a set
/// (its participant's SPDP changed its capabilities): the set
/// staged in the 1.4.x form is never closed in that form. It is lost,
/// reported, not parked in front of the writer's later sets.
#[test]
fn a_set_staged_in_one_dialect_and_continued_in_the_other_is_lost_not_parked() {
    let (net, _) = reader("spec-dialect-switch", &[A, B]);
    // 1.4.x form: no GROUP sequence information, the set named by 7.
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(A),
        1,
        &encoded(&Keyed { id: 1, value: 1 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        Some(7),
        Some(PUBLISHER),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    // The spec form from here: the next set, and both writers' ends.
    member(&net, A, 2, 2, 10, 22);
    end(&net, A, 3, 2, 10);
    end(&net, B, 1, 1, 10);
    assert_eq!(values(&net), vec![22], "lost {}", net.lost());
    assert_eq!(net.lost(), 1, "the set staged in the 1.4.x form");
}

/// The converse of `a_set_staged_in_one_dialect_and_continued_in_the_other_is_lost_not_parked`:
/// a set staged in the spec form, the writer continuing in the 1.4.x form.
#[test]
fn a_set_staged_in_the_spec_dialect_and_continued_in_the_old_is_lost_not_parked() {
    let (net, _) = reader("spec-dialect-switch-back", &[A, B]);
    member(&net, A, 1, 1, 10, 11);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(A),
        2,
        &encoded(&Keyed { id: 2, value: 22 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(2),
        Some(7),
        Some(PUBLISHER),
    );
    net.subscriber
        .on_ecs(&net.topic, guid(A), 3, 2, Some(7), Some(PUBLISHER));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    net.subscriber.on_writer_heartbeat(guid(A), 1);
    assert_eq!(values(&net), vec![22], "lost {}", net.lost());
    assert_eq!(net.lost(), 1, "the set staged in the spec form");
}

/// A set decided against the roster survives a writer the Publisher gains
/// after it began (the digest changes): that writer is no writer of the set,
/// named when it began. Decided again, the set went back to undecided, and
/// the roster wait discarded it.
#[test]
fn a_decided_set_survives_a_writer_added_to_the_publisher() {
    const C: [u8; 4] = [0, 0, 0x03, 0x02];
    for wait_ms in [0, 5_000] {
        let (net, roster) = gated_reader("spec-roster-added", true);
        net.subscriber
            .group_roster_wait_ms
            .store(wait_ms, std::sync::atomic::Ordering::Relaxed);
        member(&net, A, 1, 1, 1, 11);
        end(&net, A, 2, 1, 1);
        assert_eq!(values(&net), Vec::<i32>::new(), "B's end awaited");
        *roster.known.lock().unwrap_or_else(|e| e.into_inner()) =
            vec![(A, true), (B, true), (C, true)];
        roster
            .generation
            .store(2, std::sync::atomic::Ordering::Release);
        net.subscriber.retry_waiting_sets();
        end(&net, B, 1, 1, 1);
        assert_eq!(
            values(&net),
            vec![11],
            "wait {wait_ms}: lost {}",
            net.lost()
        );
        assert_eq!(net.lost(), 0);
    }
}

/// A refresh that read an older roster does not undo what a newer one
/// decided: B, still matched at the newer generation, is still awaited.
#[test]
fn an_older_roster_does_not_undo_a_newer_decision() {
    let (net, roster) = gated_reader("spec-roster-older", true);
    roster
        .generation
        .store(2, std::sync::atomic::Ordering::Release);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    // An answer from before: B not matched, at generation 1.
    *roster.known.lock().unwrap_or_else(|e| e.into_inner()) = vec![(A, true), (B, false)];
    roster
        .generation
        .store(1, std::sync::atomic::Ordering::Release);
    net.subscriber.retry_waiting_sets();
    assert_eq!(values(&net), Vec::<i32>::new(), "B's end still awaited");
    end(&net, B, 1, 1, 1);
    assert_eq!(values(&net), vec![11]);
}

/// In the spec dialect, a set spanning A and B,
/// B's change 2 lost on the wire, B's end received, then B's HEARTBEAT
/// firstSN past it (purged once acknowledged by its other readers): the
/// set is lost whole, nothing of A's part delivered, and A's next change is
/// held by nothing (DDS v1.4 Sec.2.2.3.6, coherent_access).
#[test]
fn a_spec_group_set_spanning_two_writers_one_part_purged_is_lost_whole() {
    let (net, _) = reader("spec-group-part-purged", &[A, B]);
    member(&net, A, 1, 1, 1, 11);
    member(&net, A, 2, 1, 1, 12);
    member(&net, B, 1, 1, 1, 21);
    end(&net, A, 3, 1, 1);
    end(&net, B, 3, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B's change 2 is owed");
    net.subscriber.on_writer_heartbeat_range(guid(B), 4, 4);
    assert_eq!(values(&net), Vec::<i32>::new(), "never in part");
    // A's two, B's staged one, B's purged one at least; B's end marker 3,
    // crossed by the HEARTBEAT, is counted too (an open over-count of
    // SAMPLE_LOST: an end of a GROUP set is not recorded as received).
    assert!(net.lost() >= 4, "lost {}", net.lost());
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_with_writer(
        &net.topic,
        guid(A),
        4,
        &encoded(&Keyed { id: 4, value: 4 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(values(&net), vec![4]);
}

/// Same, B's end landing first and A's last: A's end completes nothing
/// while B's part is short.
#[test]
fn a_spec_group_set_closed_last_by_the_whole_writer_waits_for_the_other_part() {
    let (net, _) = reader("spec-group-part-purged-late", &[A, B]);
    member(&net, B, 1, 1, 1, 21);
    end(&net, B, 3, 1, 1);
    member(&net, A, 1, 1, 1, 11);
    end(&net, A, 2, 1, 1);
    assert_eq!(values(&net), Vec::<i32>::new(), "B's change 2 is owed");
    net.subscriber.on_writer_heartbeat_range(guid(B), 4, 4);
    assert_eq!(values(&net), Vec::<i32>::new(), "never in part");
    assert!(net.lost() >= 3, "lost {}", net.lost());
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_with_writer(
        &net.topic,
        guid(A),
        3,
        &encoded(&Keyed { id: 3, value: 3 }),
        crate::dds::CdrVersion::Xcdr2,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(values(&net), vec![3], "A's next change is held by nothing");
}

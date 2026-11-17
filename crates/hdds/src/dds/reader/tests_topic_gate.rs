// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A coherent set of TOPIC access scope (DDS v1.4 Sec.2.2.3.6) is one
//! writer's, and goes to the application whole, through its Subscriber's
//! presentation barrier (`coherent_barrier`), with the sets of the other
//! readers of the Subscriber. A set whose writer still owes an earlier
//! change is not committed while its writer's gate would hold it
//! (`ReorderGate::would_hold`): committed, its samples were held in the
//! gate, released later on their own outside the set, and never reached
//! the barrier, where the other readers' sets waited for it.

use super::coherent_barrier::{CoherentPresentationBarrier, MemberId};
use super::tests_history_limits::{encoded, Keyed, NetworkReader};
use crate::dds::QoS;
use crate::engine::Subscriber as _;
use std::sync::Arc;

const PREFIX: [u8; 12] = [0x6C; 12];
/// The writer of topic A, which owes its change 1.
const WA: u8 = 0x02;
/// The writer of topic B, of the same remote participant.
const WB: u8 = 0x03;

fn guid(entity: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[..12].copy_from_slice(&PREFIX);
    g[15] = entity;
    g
}

/// Two reliable KEEP_ALL readers of TOPIC-scope coherent sets, of topics
/// A and B, members of one Subscriber's barrier, each matched with its
/// writer, seeded by the writer's first HEARTBEAT.
struct Pair {
    barrier: Arc<CoherentPresentationBarrier>,
    a: NetworkReader<Keyed>,
    b: NetworkReader<Keyed>,
    ma: MemberId,
    mb: MemberId,
}

fn pair(topic: &str) -> Pair {
    let barrier = Arc::new(CoherentPresentationBarrier::new());
    let reader = |name: String, writer: u8| {
        let member = barrier.reserve(name.clone(), true);
        let net = NetworkReader::<Keyed>::with_barrier(
            &name,
            QoS::reliable().keep_all(),
            super::reorder::ReorderGate::new(true, false),
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: false,
            },
            Arc::clone(&barrier),
            member,
        );
        net.credit.match_writer(guid(writer));
        barrier.register_matched_writer(member, guid(writer));
        net.subscriber.on_writer_heartbeat(guid(writer), 1);
        (net, member)
    };
    let (a, ma) = reader(format!("{topic}A"), WA);
    let (b, mb) = reader(format!("{topic}B"), WB);
    Pair {
        barrier,
        a,
        b,
        ma,
        mb,
    }
}

/// Change `seq` of `writer`, a member of the set that starts at `start`.
fn member(net: &NetworkReader<Keyed>, writer: u8, seq: u64, start: u64, value: i32) {
    net.subscriber.on_data_coherent(
        &net.topic,
        guid(writer),
        seq,
        &encoded(&Keyed { id: value, value }),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        None,
        None,
    );
}

/// `writer`'s end of set at `seq`, naming `last`, the set's last SN.
fn end(net: &NetworkReader<Keyed>, writer: u8, seq: u64, last: u64) {
    net.subscriber
        .on_ecs(&net.topic, guid(writer), seq, last, None, None);
}

fn values(net: &NetworkReader<Keyed>) -> Vec<i32> {
    let mut v: Vec<i32> = net.take_all().iter().map(|s| s.value).collect();
    v.sort_unstable();
    v
}

/// What each reader took: B's set `{21, 22}` and A's set `{12, 13}`,
/// every change of both received and both ended, A's change 1 still owed
/// until `settle` resolves it. Before: what a read cycle of the
/// Subscriber released for each reader, and what each took. After: the
/// same, and the samples A lost.
struct Outcome {
    released_before: (bool, bool),
    before: (Vec<i32>, Vec<i32>),
    released_after: (bool, bool),
    after: (Vec<i32>, Vec<i32>),
    lost: u32,
}

fn topic_sets_behind_an_owed_change(
    topic: &str,
    settle: impl FnOnce(&NetworkReader<Keyed>),
) -> Outcome {
    let p = pair(topic);
    member(&p.b, WB, 1, 1, 21);
    member(&p.b, WB, 2, 1, 22);
    end(&p.b, WB, 3, 2);
    member(&p.a, WA, 2, 2, 12);
    member(&p.a, WA, 3, 2, 13);
    end(&p.a, WA, 4, 3);
    let released_before = (
        p.barrier.take_one_aligned(p.ma),
        p.barrier.take_one_aligned(p.mb),
    );
    let before = (values(&p.a), values(&p.b));
    settle(&p.a);
    let released_after = (
        p.barrier.take_one_aligned(p.ma),
        p.barrier.take_one_aligned(p.mb),
    );
    let after = (values(&p.a), values(&p.b));
    Outcome {
        released_before,
        before,
        released_after,
        after,
        lost: p.a.lost(),
    }
}

fn assert_held_then_released(o: &Outcome, a_after: &[i32]) {
    assert_eq!(o.released_before, (false, false), "A's change 1 is owed");
    assert_eq!(o.before, (vec![], vec![]), "nothing taken before");
    assert_eq!(
        o.released_after,
        (true, true),
        "both sets through the barrier, together"
    );
    assert_eq!(o.after.0, a_after, "A");
    assert_eq!(o.after.1, vec![21, 22], "B's set");
}

/// A's change 1 a change filtered for this reader, its GAP (RTPS v2.5
/// Sec.8.3.8.4) landing after A's set.
#[test]
fn a_topic_set_waits_for_a_gap_of_its_writers_earlier_change() {
    let o = topic_sets_behind_an_owed_change("TopicOwedGap", |a| {
        a.subscriber
            .on_writer_gap_filtered(guid(WA), 1, 2, vec![], 1);
    });
    assert_held_then_released(&o, &[12, 13]);
    assert_eq!(o.lost, 0, "a filtered change is no sample lost");
}

/// A's change 1 a plain change repaired late: delivered, then the set.
#[test]
fn a_topic_set_waits_for_a_repair_of_its_writers_earlier_change() {
    let o = topic_sets_behind_an_owed_change("TopicOwedData", |a| {
        a.subscriber.on_data_with_writer(
            &a.topic,
            guid(WA),
            1,
            &encoded(&Keyed { id: 1, value: 1 }),
            crate::dds::CdrVersion::Xcdr2,
        );
    });
    assert_held_then_released(&o, &[1, 12, 13]);
    assert_eq!(o.lost, 0);
}

/// A's change 1 never received and gone from A's history (a HEARTBEAT's
/// firstSN past it, RTPS v2.5 Sec.8.4.12.2, T7): one sample lost, A's set
/// whole all the same.
#[test]
fn a_topic_set_waits_for_a_heartbeat_past_its_writers_earlier_change() {
    let o = topic_sets_behind_an_owed_change("TopicOwedHb", |a| {
        a.subscriber.on_writer_heartbeat(guid(WA), 2);
    });
    assert_held_then_released(&o, &[12, 13]);
    assert_eq!(o.lost, 1, "A's change 1, never received");
}

/// A writer whose set waits for its gate, gone before the gate moves: its
/// staged set goes (`on_writer_departure`), and so does the record that
/// its set waits, which nothing else would ever remove.
#[test]
fn a_departed_writers_wait_on_its_gate_is_forgotten() {
    let p = pair("TopicOwedGone");
    member(&p.a, WA, 2, 2, 12);
    end(&p.a, WA, 3, 2);
    let waits = |net: &NetworkReader<Keyed>| {
        net.subscriber
            .writer_sets_await_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&guid(WA))
    };
    assert!(waits(&p.a), "A's set waits for A's change 1");
    p.a.subscriber.on_writer_departure(
        &p.a.topic,
        guid(WA),
        crate::engine::subscriber::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    assert!(!waits(&p.a), "the gone writer's wait is forgotten");
    assert!(
        p.a.subscriber
            .writer_sets_await_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "nothing waits"
    );
}

/// Sets chained behind one owed change: A stages as many one-change sets
/// as a writer may stage (`MAX_STAGED_PER_WRITER`), each waiting for the
/// one before it, then the GAP of A's change 1 lets the first through and
/// each decided set the next. Decided on a thread with a small stack, as
/// an embedded target has: one pass per set, never one call frame per
/// set. Every set is delivered, in order, through the barrier.
#[test]
fn sets_chained_behind_an_owed_change_are_decided_in_constant_stack() {
    let p = pair("TopicOwedChain");
    // A alone in the barrier: B's reader is gone.
    p.barrier.forget_member(p.mb);
    let sets = u64::try_from(super::subscriber::MAX_STAGED_PER_WRITER).unwrap() - 4;
    for k in 0..sets {
        let seq = 2 + 2 * k;
        member(&p.a, WA, seq, seq, i32::try_from(seq).unwrap());
        end(&p.a, WA, seq + 1, seq);
    }
    assert!(!p.barrier.take_one_aligned(p.ma), "A's change 1 is owed");
    let subscriber = Arc::clone(&p.a.subscriber);
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || subscriber.on_writer_gap_filtered(guid(WA), 1, 2, vec![], 1))
        .expect("spawn")
        .join()
        .expect("decided on a small stack");
    while p.barrier.take_one_aligned(p.ma) {}
    let expected: Vec<i32> = (0..sets)
        .map(|k| i32::try_from(2 + 2 * k).unwrap())
        .collect();
    assert_eq!(values(&p.a), expected, "every set, in order");
    assert_eq!(p.a.lost(), 0);
}

/// A KEEP_LAST(1) reader (DDS v1.4 Sec.2.2.3.18: the most recent sample
/// of each instance is kept), its set `{instance 1 = 12, instance 2 = 13}`
/// waiting behind A's owed change 1, and a later plain change of instance
/// 1 (`15`) landing while it waits. Once change 1 is settled the changes
/// reach the reader in A's order (Sec.2.2.3.6: the set whole, then the
/// change after it), so instance 1 holds `15`, never the set's `12` laid
/// over it, nor anything twice; nothing waits any more.
fn keep_last_overwrite(settle: impl FnOnce(&NetworkReader<Keyed>)) -> (Vec<(i32, i32)>, u32) {
    let barrier = Arc::new(CoherentPresentationBarrier::new());
    let member_id = barrier.reserve("TopicKeepLast".into(), true);
    let net = NetworkReader::<Keyed>::with_barrier(
        "TopicKeepLast",
        QoS::reliable().keep_last(1),
        super::reorder::ReorderGate::new(true, false),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
        Arc::clone(&barrier),
        member_id,
    );
    net.credit.match_writer(guid(WA));
    barrier.register_matched_writer(member_id, guid(WA));
    net.subscriber.on_writer_heartbeat(guid(WA), 1);
    let keyed = |id: i32, value: i32| encoded(&Keyed { id, value });
    let coherent = |seq: u64, id: i32, value: i32| {
        net.subscriber.on_data_coherent(
            &net.topic,
            guid(WA),
            seq,
            &keyed(id, value),
            crate::dds::CdrVersion::Xcdr2,
            Some(2),
            None,
            None,
        );
    };
    coherent(2, 1, 12);
    coherent(3, 2, 13);
    end(&net, WA, 4, 3);
    net.subscriber.on_data_with_writer(
        &net.topic,
        guid(WA),
        5,
        &keyed(1, 15),
        crate::dds::CdrVersion::Xcdr2,
    );
    settle(&net);
    while barrier.take_one_aligned(member_id) {}
    let mut got: Vec<(i32, i32)> = net.take_all().iter().map(|s| (s.id, s.value)).collect();
    got.sort_unstable();
    assert!(
        net.subscriber
            .writer_sets_await_gate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "nothing waits"
    );
    (got, net.lost())
}

#[test]
fn a_keep_last_overwrite_behind_a_waiting_set_keeps_the_writers_order() {
    let gap = keep_last_overwrite(|net| {
        net.subscriber
            .on_writer_gap_filtered(guid(WA), 1, 2, vec![], 1);
    });
    assert_eq!(gap, (vec![(1, 15), (2, 13)], 0), "settled by a GAP");
    let repaired = keep_last_overwrite(|net| {
        net.subscriber.on_data_with_writer(
            &net.topic,
            guid(WA),
            1,
            &encoded(&Keyed { id: 1, value: 1 }),
            crate::dds::CdrVersion::Xcdr2,
        );
    });
    assert_eq!(repaired, (vec![(1, 15), (2, 13)], 0), "settled by a repair");
}

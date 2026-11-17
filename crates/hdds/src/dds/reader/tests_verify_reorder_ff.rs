// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Adversarial tests of the reorder gate's staged places (`hold_staged`).

use crate::core::rt;
use crate::engine::Subscriber;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Small {
    id: i32,
    body: Vec<u8>,
}

const A: [u8; 16] = [0x7A; 16];
const B: [u8; 16] = [0x7B; 16];
/// Two writers of one participant, hence possibly of one Publisher: `A`
/// and `B` are of two participants, whose GROUP sets are never one set
/// (`GroupSetKey`).
const A_OF_P: [u8; 16] = [
    0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0, 0, 1, 0x02,
];
const B_OF_P: [u8; 16] = [
    0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0x7A, 0, 0, 2, 0x02,
];

fn encoded(seq: u64) -> Vec<u8> {
    let s = Small {
        id: i32::try_from(seq).expect("small"),
        body: vec![1; 32],
    };
    let mut b = vec![0u8; 256];
    let n = crate::dds::DDS::encode(&s, &mut b, crate::dds::CdrVersion::Xcdr2).expect("enc");
    b.truncate(n);
    b
}

type Sub = super::subscriber::ReaderSubscriber<Small>;

fn sub_with3(
    volatile: bool,
    group: bool,
    writers: &[[u8; 16]],
) -> (
    Arc<rt::IndexRing>,
    Sub,
    crate::core::reader::ReaderAckCredit,
) {
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA1; 16],
    );
    for w in writers {
        credit.match_writer(*w);
    }
    let ring = Arc::new(rt::IndexRing::with_capacity(4096));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut s = Sub::new_with_coherent(
        "t".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, volatile))),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: group,
        },
        None,
        Some(credit.clone()),
        Arc::default(),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    s.room = Some(super::admission::HistoryRoom::new(
        &ring,
        crate::reliability::LENGTH_UNLIMITED,
    ));
    s.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
    (ring, s, credit)
}

fn sub_with(volatile: bool, group: bool, writers: &[[u8; 16]]) -> (Arc<rt::IndexRing>, Sub) {
    let (r, s, _) = sub_with3(volatile, group, writers);
    (r, s)
}

fn take(ring: &rt::IndexRing, s: &Sub) -> Vec<u64> {
    let mut v = Vec::new();
    while let Some(e) = ring.pop() {
        v.push(u64::from(e.seq));
        rt::get_slab_pool_ref().release(e.handle);
        drop(s.room.as_ref().map(super::admission::HistoryRoom::adopt));
    }
    v
}

fn member(s: &Sub, w: [u8; 16], seq: u64, start: u64) {
    s.on_data_coherent(
        "t",
        w,
        seq,
        &encoded(seq),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        None,
        None,
    );
}

fn plain(s: &Sub, w: [u8; 16], seq: u64) {
    s.on_data_with_writer("t", w, seq, &encoded(seq), crate::dds::CdrVersion::Xcdr2);
}

fn in_order(taken: &[u64]) -> bool {
    taken.windows(2).all(|p| p[0] < p[1])
}

/// Durable (HEARTBEAT-seeded) gate, members staged BEFORE the first
/// HEARTBEAT (a late joiner's history arriving ahead of the HB). First HB
/// firstSN 1 seeds the gate; the writer then purges the acknowledged set and
/// announces firstSN 4; 4 arrives. The set must not come after 4.
#[test]
fn vr_durable_set_staged_before_first_heartbeat_then_purged() {
    let (ring, s) = sub_with(false, false, &[A]);
    member(&s, A, 1, 1);
    member(&s, A, 2, 1);
    s.on_writer_heartbeat_range(A, 1, 2);
    let mut taken = take(&ring, &s);
    s.on_writer_heartbeat_range(A, 3, 3);
    plain(&s, A, 3);
    taken.extend(take(&ring, &s));
    plain(&s, A, 4);
    taken.extend(take(&ring, &s));
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!("vr durable pre-HB: taken {taken:?} lost {lost}");
    assert_eq!(taken, vec![1, 2, 3, 4], "lost {lost}");
}

/// Same, VOLATILE gate: the members are the first DATA observed; no HB
/// seeds a VOLATILE gate; the writer purges (HB firstSN 4) and 4 arrives.
#[test]
fn vr_volatile_set_staged_first_then_purged() {
    let (ring, s) = sub_with(true, false, &[A]);
    member(&s, A, 1, 1);
    member(&s, A, 2, 1);
    s.on_writer_heartbeat_range(A, 1, 2);
    let mut taken = take(&ring, &s);
    s.on_writer_heartbeat_range(A, 3, 3);
    plain(&s, A, 3);
    taken.extend(take(&ring, &s));
    plain(&s, A, 4);
    taken.extend(take(&ring, &s));
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!("vr volatile first: taken {taken:?} lost {lost}");
    assert_eq!(taken, vec![1, 2, 3, 4], "lost {lost}");
}

/// VOLATILE gate, no purge at all: a set staged as the first DATA, then a
/// plain DATA closes it.
#[test]
fn vr_volatile_set_staged_first_then_plain() {
    let (ring, s) = sub_with(true, false, &[A]);
    member(&s, A, 1, 1);
    member(&s, A, 2, 1);
    plain(&s, A, 3);
    let mut taken = take(&ring, &s);
    plain(&s, A, 4);
    taken.extend(take(&ring, &s));
    eprintln!("vr volatile plain: taken {taken:?}");
    assert!(in_order(&taken), "out of order: {taken:?}");
    assert_eq!(taken, vec![1, 2, 3, 4]);
}

/// A staged set whose writer leaves (SEDP dispose, Unheard) with the set
/// open, then comes back (same writer, false departure) and goes on: no
/// held place blocks it.
#[test]
fn vr_writer_leaves_with_an_open_set_and_comes_back() {
    let (ring, s, credit) = sub_with3(false, false, &[A]);
    s.on_writer_heartbeat_range(A, 1, 1);
    plain(&s, A, 1);
    let mut taken = take(&ring, &s);
    member(&s, A, 2, 2);
    member(&s, A, 3, 2);
    s.on_writer_dispose("t", A, crate::engine::DisposeKind::Unregistered);
    // A re-created writer under the GUID starts again at 1.
    s.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
    credit.match_writer(A);
    s.on_writer_heartbeat_range(A, 1, 3);
    for seq in 1..=3 {
        plain(&s, A, seq);
    }
    s.on_writer_heartbeat_range(A, 4, 6);
    for seq in 4..=6 {
        plain(&s, A, seq);
    }
    taken.extend(take(&ring, &s));
    eprintln!("vr leaves: taken {taken:?}");
    assert!(
        taken.ends_with(&[4, 5, 6]),
        "stalled after a departure: {taken:?}"
    );
}

/// `A` and `B` are writers
/// of two participants, so of two Publishers, and their sets tagged GSN 1
/// are two GROUP sets (`GroupSetKey` holds the participant prefix): A's is
/// whole and delivered, B's, short of 103 for good once B purges past it,
/// is lost whole. Neither is delivered in part. The same scenario within one
/// Publisher is `vr_group_set_spanning_writers_one_part_lost_known_writers`
/// below (and `a_spec_group_set_spanning_two_writers_one_part_purged_is_lost_whole`
/// in the spec dialect); with A's end landing before anything of B, the
/// HDDS 1.4.x dialect cannot know B's part is coming
/// (`a_group_set_is_flushed_before_another_writers_part_lands`).
#[test]
fn vr_group_sets_of_two_publishers_one_part_lost() {
    const P: [u8; 4] = [0, 0, 1, 8];
    let (ring, s) = sub_with(false, true, &[A, B]);
    s.on_writer_heartbeat_range(A, 1, 1);
    s.on_writer_heartbeat_range(B, 101, 101);
    plain(&s, A, 1);
    plain(&s, B, 101);
    let mut taken = take(&ring, &s);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let g = |w, seq, start| {
        s.on_data_coherent(
            "t",
            w,
            seq,
            &encoded(seq),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            Some(1),
            Some(P),
        );
    };
    g(A, 2, 2);
    g(A, 3, 2);
    s.on_ecs("t", A, 4, 3, Some(1), Some(P));
    g(B, 102, 102);
    // B's 103 never arrives; its ECS 104 does.
    s.on_ecs("t", B, 104, 103, Some(1), Some(P));
    taken.extend(take(&ring, &s));
    assert_eq!(taken, vec![1, 101, 2, 3], "A's set, whole; B's waits");
    s.on_writer_heartbeat_range(A, 5, 5);
    s.on_writer_heartbeat_range(B, 105, 105);
    plain(&s, A, 5);
    plain(&s, B, 105);
    taken.extend(take(&ring, &s));
    plain(&s, A, 6);
    taken.extend(take(&ring, &s));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!("vr group: taken {taken:?} lost {lost}");
    assert_eq!(
        taken,
        vec![1, 101, 2, 3, 5, 105, 6],
        "B's set lost whole, nothing held behind it"
    );
    assert!(lost >= 2, "102 and 103, lost {lost}");
}

/// The same set in the HDDS 1.4.x dialect, B's part seen before A's end:
/// the reader knows B is one of the set's writers, so A's end completes
/// nothing, and B's part, short of 103 for good once B purges past it,
/// makes the set lost whole. A's later changes follow, in order.
#[test]
fn vr_group_set_spanning_writers_one_part_lost_known_writers() {
    const P: [u8; 4] = [0, 0, 1, 8];
    const A: [u8; 16] = A_OF_P;
    const B: [u8; 16] = B_OF_P;
    let (ring, s) = sub_with(false, true, &[A, B]);
    s.on_writer_heartbeat_range(A, 1, 1);
    s.on_writer_heartbeat_range(B, 101, 101);
    plain(&s, A, 1);
    plain(&s, B, 101);
    let mut taken = take(&ring, &s);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let g = |w, seq, start| {
        s.on_data_coherent(
            "t",
            w,
            seq,
            &encoded(seq),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            Some(1),
            Some(P),
        );
    };
    g(A, 2, 2);
    g(B, 102, 102);
    g(A, 3, 2);
    // B's 103 never arrives; its ECS 104 does.
    s.on_ecs("t", B, 104, 103, Some(1), Some(P));
    s.on_ecs("t", A, 4, 3, Some(1), Some(P));
    taken.extend(take(&ring, &s));
    assert_eq!(taken, vec![1, 101], "nothing of set 1 while 103 is owed");
    s.on_writer_heartbeat_range(A, 5, 5);
    s.on_writer_heartbeat_range(B, 105, 105);
    plain(&s, A, 5);
    plain(&s, B, 105);
    plain(&s, A, 6);
    taken.extend(take(&ring, &s));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    eprintln!("vr group known writers: taken {taken:?} lost {}", lost(&s));
    assert_eq!(taken, vec![1, 101, 5, 105, 6], "set 1 lost whole");
    // Exactly 2, 3, 102 and 103: the set's four DATA samples. The two end
    // markers (4, 104), crossed by the HEARTBEATs same as the samples, are
    // not: a coherent-set marker is not a sample (DDS v1.4 Sec.2.2.4.1).
    assert_eq!(lost(&s), 4, "lost {}", lost(&s));
}

/// A single writer's GROUP set that can never complete (its DATA sample 3
/// never arrives, only the ECS marker at 4 that names it): once a HEARTBEAT
/// purges 3 for good, DDS v1.4 Sec.2.2.4.1 SAMPLE_LOST must count only the
/// two DATA samples of the discarded set -- 2 (staged, but never delivered:
/// its set never closed whole) and 3 (never received) -- never the ECS
/// marker at 4: a coherent-set end marker is a change of its own (RTPS v2.5
/// Sec.8.7.5) but carries no application sample.
#[test]
fn vr_group_end_marker_not_counted_as_sample_lost() {
    const P: [u8; 4] = [0, 0, 1, 8];
    const A: [u8; 16] = A_OF_P;
    let (ring, s) = sub_with(false, true, &[A]);
    s.on_writer_heartbeat_range(A, 1, 1);
    plain(&s, A, 1);
    let mut taken = take(&ring, &s);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    s.on_data_coherent(
        "t",
        A,
        2,
        &encoded(2),
        crate::dds::CdrVersion::Xcdr2,
        Some(2),
        Some(1),
        Some(P),
    );
    // A's 3 never arrives; its ECS marker 4 (naming coherent_sn 3) does.
    s.on_ecs("t", A, 4, 3, Some(1), Some(P));
    // The set can never complete: a HEARTBEAT purges 3 (and the marker 4)
    // for good.
    s.on_writer_heartbeat_range(A, 5, 5);
    plain(&s, A, 5);
    taken.extend(take(&ring, &s));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    eprintln!(
        "vr group single-writer marker: taken {taken:?} lost {}",
        lost(&s)
    );
    assert_eq!(
        taken,
        vec![1, 5],
        "set 1 lost whole, held nothing behind it"
    );
    // 2 and 3: the set's two DATA samples, discarded whole. The ECS marker
    // at 4 must not add a third.
    assert_eq!(
        lost(&s),
        2,
        "samples 2 and 3 are lost; the ECS marker at 4 must not be counted \
         too, lost {}",
        lost(&s)
    );
}

/// Stress: thread W writes sets of 3 members, each closed by a plain DATA;
/// thread H sends HEARTBEATs whose firstSN is one past the highest sequence
/// already handed to the reader (legitimately purged once acknowledged);
/// thread R takes. Every sample delivered once, in order.
fn stress(volatile: bool, rounds: u64) {
    let (ring, s) = sub_with(volatile, false, &[A]);
    let s = Arc::new(s);
    s.on_writer_heartbeat_range(A, 1, 1);
    let sent = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let h = {
        let (s, sent, done) = (Arc::clone(&s), Arc::clone(&sent), Arc::clone(&done));
        std::thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let top = sent.load(Ordering::Acquire);
                if top > 0 {
                    s.on_writer_heartbeat_range(A, top + 1, top);
                }
                std::thread::yield_now();
            }
        })
    };
    let r = {
        let (s, ring, done) = (Arc::clone(&s), Arc::clone(&ring), Arc::clone(&done));
        std::thread::spawn(move || {
            let mut v = Vec::new();
            loop {
                let d = done.load(Ordering::Acquire);
                v.extend(take(&ring, &s));
                if d {
                    v.extend(take(&ring, &s));
                    return v;
                }
                std::thread::yield_now();
            }
        })
    };
    let mut seq = 1u64;
    for _ in 0..rounds {
        let start = seq;
        for _ in 0..3 {
            member(&s, A, seq, start);
            sent.store(seq, Ordering::Release);
            seq += 1;
        }
        plain(&s, A, seq);
        sent.store(seq, Ordering::Release);
        seq += 1;
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    done.store(true, Ordering::Release);
    h.join().expect("h");
    let mut taken = r.join().expect("r");
    taken.extend(take(&ring, &s));
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!(
        "vr stress volatile={volatile}: taken {} of {} lost {lost}",
        taken.len(),
        seq - 1
    );
    let bad: Vec<_> = taken.windows(2).filter(|p| p[0] >= p[1]).take(5).collect();
    assert!(bad.is_empty(), "out of order or twice: {bad:?}");
    assert_eq!(
        taken.len() as u64,
        seq - 1,
        "missing samples, lost={lost}, last {:?}",
        taken.last()
    );
}

#[test]
fn vr_stress_durable() {
    for _ in 0..20 {
        stress(false, 300);
    }
}

#[test]
fn vr_stress_volatile() {
    for _ in 0..20 {
        stress(true, 300);
    }
}

/// Gate level: commit and rejection both hand the same staged change back
/// (on_staged twice): delivered twice?
#[test]
fn vr_gate_on_staged_twice_delivers_once() {
    use super::reorder::{PendingPayload, ReorderGate};
    let mut gate = ReorderGate::new(true, false);
    let _ = gate.on_heartbeat(A, 1);
    assert!(gate.hold_staged(&A, 1));
    assert!(gate.hold_staged(&A, 2));
    let mut out = Vec::new();
    out.extend(gate.on_staged(A, 2, PendingPayload::nothing(2)));
    out.extend(gate.on_staged(A, 2, PendingPayload::nothing(2)));
    out.extend(gate.on_staged(A, 1, PendingPayload::nothing(1)));
    out.extend(gate.on_staged(A, 1, PendingPayload::nothing(1)));
    let seqs: Vec<u64> = out.iter().map(|p| p.remote_seq).collect();
    eprintln!("vr twice: {seqs:?}");
    assert_eq!(seqs, vec![1, 2], "a second hand-back delivered again");
}

/// Durable gate, the late joiner's history burst lands before the first
/// HEARTBEAT: 1..=3 plain (held, gate unseeded), set {4..=7} staged (no
/// place recorded: unseeded), 8 plain. History of 6 places, 1..=3 not
/// taken: the set waits for places. The first HEARTBEAT seeds at 1; then
/// the writer, every change acknowledged, purges and announces firstSN 8.
/// The set must reach the application before 8.
#[test]
fn vr_durable_unseeded_set_waiting_for_places_then_purged() {
    let (ring, mut s, _credit) = sub_with3(false, false, &[A]);
    s.room = Some(super::admission::HistoryRoom::new(&ring, 6));
    for seq in 1..=3 {
        plain(&s, A, seq);
    }
    for seq in 4..=7 {
        member(&s, A, seq, 4);
    }
    plain(&s, A, 8);
    s.on_writer_heartbeat_range(A, 1, 8);
    s.on_writer_heartbeat_range(A, 8, 8);
    let mut taken = Vec::new();
    for _ in 0..4 {
        taken.extend(take(&ring, &s));
        s.on_writer_heartbeat_range(A, 8, 9);
        plain(&s, A, 8);
        plain(&s, A, 9);
    }
    taken.extend(take(&ring, &s));
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!("vr durable unseeded places: taken {taken:?} lost {lost}");
    assert!(in_order(&taken), "out of order: {taken:?}");
    assert!(
        taken.contains(&7),
        "set never delivered: {taken:?} lost {lost}"
    );
}

/// VOLATILE gate, the set {11..=14} is the first DATA observed and waits
/// for places (another writer's samples hold 3 of 6); A's next plain DATA
/// arrives, refused while the set holds the gate, and is sent again with the
/// writer's later ones. No purge at all. `heartbeat_first`: A's HEARTBEAT
/// (firstSN 1, a KEEP_ALL writer) arrives before the set, and seeds no
/// VOLATILE gate. Every change of A reaches the application, in A's order
/// (DDS v1.4 Sec.2.2.3.6 and 2.2.3.14).
fn volatile_first_set_waiting_for_places_then_plain(heartbeat_first: bool) -> Vec<u64> {
    let (ring, mut s, _credit) = sub_with3(true, false, &[A, B]);
    s.room = Some(super::admission::HistoryRoom::new(&ring, 6));
    s.on_writer_heartbeat_range(B, 1, 1);
    if heartbeat_first {
        s.on_writer_heartbeat_range(A, 1, 10);
    }
    for seq in 1..=3 {
        plain(&s, B, seq);
    }
    for seq in 11..=14 {
        member(&s, A, seq, 11);
    }
    plain(&s, A, 15);
    let mut taken = Vec::new();
    for _ in 0..4 {
        taken.extend(take(&ring, &s));
        s.on_writer_heartbeat_range(A, 11, 16);
        plain(&s, A, 15);
        plain(&s, A, 16);
    }
    taken.extend(take(&ring, &s));
    let a: Vec<u64> = taken.iter().copied().filter(|&x| x > 10).collect();
    eprintln!("vr volatile first places hb={heartbeat_first}: taken {taken:?} A {a:?}");
    a
}

#[test]
fn vr_volatile_first_set_waiting_for_places_then_plain() {
    let a = volatile_first_set_waiting_for_places_then_plain(false);
    assert_eq!(a, vec![11, 12, 13, 14, 15, 16], "A out of order or lost");
}

#[test]
fn vr_volatile_heartbeat_then_first_set_waiting_for_places_then_plain() {
    let a = volatile_first_set_waiting_for_places_then_plain(true);
    assert_eq!(a, vec![11, 12, 13, 14, 15, 16], "A out of order or lost");
}

/// Same, durable gate seeded by a HEARTBEAT before the set: the HEARTBEAT
/// purge past the acknowledged set (the branch's own fix).
#[test]
fn vr_durable_seeded_set_waiting_for_places_two_writers_purge() {
    let (ring, mut s, _credit) = sub_with3(false, false, &[A, B]);
    s.room = Some(super::admission::HistoryRoom::new(&ring, 6));
    s.on_writer_heartbeat_range(B, 1, 1);
    s.on_writer_heartbeat_range(A, 11, 11);
    for seq in 1..=3 {
        plain(&s, B, seq);
    }
    for seq in 11..=14 {
        member(&s, A, seq, 11);
    }
    plain(&s, A, 15);
    s.on_writer_heartbeat_range(A, 15, 15);
    let mut taken = Vec::new();
    for _ in 0..4 {
        taken.extend(take(&ring, &s));
        s.on_writer_heartbeat_range(A, 15, 16);
        plain(&s, A, 15);
        plain(&s, A, 16);
    }
    taken.extend(take(&ring, &s));
    let a: Vec<u64> = taken.iter().copied().filter(|&x| x > 10).collect();
    eprintln!("vr durable seeded places 2w: taken {taken:?} A {a:?}");
    assert!(in_order(&a), "A out of order: {a:?}");
    assert!(a.contains(&14), "set never delivered: {a:?}");
}

/// Durable gate: set {11..=14} lands before A's first HEARTBEAT (no place
/// recorded: the gate is unseeded); the first HEARTBEAT seeds at 11; the
/// set waits for places (B holds 3 of 6); A's 15 is held; A's writer, the
/// set acknowledged, purges and announces firstSN 15.
#[test]
fn vr_durable_unseeded_then_seeded_set_waiting_for_places_purge() {
    let (ring, mut s, _credit) = sub_with3(false, false, &[A, B]);
    s.room = Some(super::admission::HistoryRoom::new(&ring, 6));
    s.on_writer_heartbeat_range(B, 1, 1);
    for seq in 1..=3 {
        plain(&s, B, seq);
    }
    for seq in 11..=14 {
        member(&s, A, seq, 11);
    }
    s.on_writer_heartbeat_range(A, 11, 14);
    plain(&s, A, 15);
    s.on_writer_heartbeat_range(A, 15, 15);
    let mut taken = Vec::new();
    for _ in 0..4 {
        taken.extend(take(&ring, &s));
        s.on_writer_heartbeat_range(A, 15, 16);
        plain(&s, A, 15);
        plain(&s, A, 16);
    }
    taken.extend(take(&ring, &s));
    let a: Vec<u64> = taken.iter().copied().filter(|&x| x > 10).collect();
    eprintln!("vr durable unseeded->seeded places: taken {taken:?} A {a:?}");
    assert!(in_order(&a), "A out of order: {a:?}");
    assert!(a.contains(&14), "set never delivered: {a:?}");
}

/// VOLATILE gate, unlimited history, packet loss at the join: the set
/// {11..=14} is the first DATA observed, 12 is lost on the wire, 15 (no
/// set) arrives, then 12 is repaired. No purge, no tight history.
#[test]
fn vr_volatile_first_set_missing_member_then_plain() {
    let (ring, s, _credit) = sub_with3(true, false, &[A]);
    member(&s, A, 11, 11);
    member(&s, A, 13, 11);
    member(&s, A, 14, 11);
    plain(&s, A, 15);
    let mut taken = take(&ring, &s);
    s.on_writer_heartbeat_range(A, 11, 15);
    member(&s, A, 12, 11);
    taken.extend(take(&ring, &s));
    plain(&s, A, 16);
    taken.extend(take(&ring, &s));
    eprintln!("vr volatile join loss: taken {taken:?}");
    assert_eq!(
        taken,
        vec![11, 12, 13, 14, 15, 16],
        "the set passed by 15, or lost"
    );
}

/// Connext-style GROUP durable replay (vendor 0x0101): a pre-join GROUP set
/// {2,3} (gsn 1) whose END marker SN 4 is never re-emitted nor GAPped, so it
/// never closes; the live set {5,6} (gsn 2) closes with its ECS 7. The
/// flush steps the gate over the seam hole [next, 5) (`flush_group_set`).
#[test]
fn vr_connext_group_replay_seam_hole() {
    const P: [u8; 4] = [0, 0, 1, 8];
    let (ring, s, _credit) = sub_with3(false, true, &[A]);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    crate::engine::router::set_route_writer_is_connext_for_test(true);
    let g = |seq, start, gsn| {
        s.on_data_coherent(
            "t",
            A,
            seq,
            &encoded(seq),
            crate::dds::CdrVersion::Xcdr2,
            Some(start),
            Some(gsn),
            Some(P),
        );
    };
    s.on_writer_heartbeat_range(A, 2, 7);
    g(2, 2, 1);
    g(3, 2, 1);
    g(5, 5, 2);
    g(6, 5, 2);
    s.on_ecs("t", A, 7, 6, Some(2), Some(P));
    let mut taken = take(&ring, &s);
    s.on_writer_heartbeat_range(A, 2, 7);
    taken.extend(take(&ring, &s));
    s.on_writer_heartbeat_range(A, 8, 8);
    plain(&s, A, 8);
    taken.extend(take(&ring, &s));
    crate::engine::router::set_route_writer_is_connext_for_test(false);
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!("vr connext seam: taken {taken:?} lost {lost}");
    assert_eq!(
        taken,
        vec![5, 6, 8],
        "live GROUP set starved behind a never-closing replayed set"
    );
}

fn lost(s: &Sub) -> u32 {
    s.sample_lost.lock().expect("lost").total_count
}

/// A HEARTBEAT's firstSN passes 2 and 3, never received, while the gate
/// waits at a staged place (1): reported lost then (DDS v1.4 Sec.2.2.4.1,
/// SAMPLE_LOST, total_count cumulative). A late copy of 3, of no set, is
/// dropped, never delivered and never counted again: every sequence is
/// delivered or counted lost, once.
#[test]
fn sl_a_late_sample_of_no_set_after_a_purge_is_dropped_counted_once() {
    let (ring, s) = sub_with(false, false, &[A]);
    s.on_writer_heartbeat_range(A, 1, 1);
    member(&s, A, 1, 1);
    s.on_writer_heartbeat_range(A, 4, 4);
    assert_eq!(lost(&s), 2, "2 and 3");
    // 3 ends set 1 at 2 (2 may be its own: it can never be whole, RTPS
    // v2.5 Sec.8.7.6), discarded, its member lost; 3 is not counted again.
    plain(&s, A, 3);
    assert_eq!(lost(&s), 3, "1, 2 and 3, each once");
    assert_eq!(take(&ring, &s), Vec::<u64>::new(), "3 dropped, 4 awaited");
    plain(&s, A, 4);
    assert_eq!(take(&ring, &s), vec![4], "3 never delivered");
    assert_eq!(lost(&s), 3);
}

/// Same, the late copy a coherent set's member (a set starting at 3):
/// refused its place, counted once; where its set starts is known, which
/// ends the set at 1, and the writer's next sample is delivered.
#[test]
fn sl_a_late_member_after_a_purge_is_refused_counted_once() {
    let (ring, s) = sub_with(false, false, &[A]);
    s.on_writer_heartbeat_range(A, 1, 1);
    member(&s, A, 1, 1);
    s.on_writer_heartbeat_range(A, 4, 4);
    assert_eq!(lost(&s), 2, "2 and 3");
    member(&s, A, 3, 3);
    assert_eq!(lost(&s), 3, "set 1 ends at 2, discarded: 1 lost; 3 once");
    plain(&s, A, 4);
    member(&s, A, 5, 5);
    plain(&s, A, 6);
    assert_eq!(take(&ring, &s), vec![4, 5, 6]);
    assert_eq!(lost(&s), 3);
}

/// A member whose set closes whole before the hole: the late member of the
/// set after it is refused, and the set before it delivered.
#[test]
fn sl_a_late_member_after_a_purge_lets_the_set_before_it_through() {
    let (ring, s) = sub_with(false, false, &[A]);
    s.on_writer_heartbeat_range(A, 1, 1);
    member(&s, A, 1, 1);
    // 2 to 4 never arrived; the writer purged up to 4.
    s.on_writer_heartbeat_range(A, 5, 5);
    assert_eq!(lost(&s), 3, "2, 3 and 4");
    // 3, of the set starting at 2, arrives late: set 1 ends at 1.
    member(&s, A, 3, 2);
    plain(&s, A, 5);
    assert_eq!(take(&ring, &s), vec![1, 5]);
    assert_eq!(lost(&s), 3, "3 counted once");
}

/// A member admitted before the purge's step and handed to the gate after
/// it: the step read it as received and did not count it; the gate, which
/// crossed it, refuses it, and it is counted then, once.
#[test]
fn sl_a_member_admitted_before_a_purge_and_refused_after_is_reported() {
    let (ring, s) = sub_with(false, false, &[A]);
    let s = Arc::new(s);
    s.on_writer_heartbeat_range(A, 1, 1);
    member(&s, A, 1, 1);
    let purger = Arc::clone(&s);
    *s.hold_hook.lock().expect("hook") = Some(Box::new(move || {
        purger.on_writer_heartbeat_range(A, 4, 4);
    }));
    member(&s, A, 3, 3);
    assert_eq!(lost(&s), 3, "2, then 3 refused, then set 1 discarded");
    plain(&s, A, 4);
    assert_eq!(take(&ring, &s), vec![4]);
    assert_eq!(lost(&s), 3, "1, 2 and 3, each once");
}

/// "Taken empty" with a HEARTBEAT
/// purged hole between two sets of one writer. Not a stall: the HEARTBEAT
/// (firstSN 4, lastSN 4) says 4 is available, the harness never sent it,
/// and the gate waits for it; once 4 arrives, everything after it follows.
#[test]
fn a_purged_hole_between_two_sets_waits_only_for_what_is_available() {
    let (ring, s) = sub_with(false, false, &[A]);
    s.on_writer_heartbeat_range(A, 1, 1);
    member(&s, A, 1, 1);
    s.on_writer_heartbeat_range(A, 4, 4);
    member(&s, A, 3, 3);
    plain(&s, A, 5);
    assert_eq!(take(&ring, &s), Vec::<u64>::new(), "4 awaited");
    plain(&s, A, 4);
    assert_eq!(take(&ring, &s), vec![4, 5]);
    assert_eq!(lost(&s), 3, "1, 2 and 3");
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The reorder gate's HEARTBEAT fast-forward must not pass staged members
//! (minimal form).

use crate::core::rt;
use crate::engine::Subscriber;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Small {
    id: i32,
    body: Vec<u8>,
}

const A: [u8; 16] = [0x6A; 16];

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

fn sub() -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Small>,
    crate::core::reader::ReaderAckCredit,
) {
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    credit.match_writer(A);
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut s = super::subscriber::ReaderSubscriber::<Small>::new_with_coherent(
        "t".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, true))),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
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

fn take(ring: &rt::IndexRing, s: &super::subscriber::ReaderSubscriber<Small>) -> Vec<u64> {
    let mut v = Vec::new();
    while let Some(e) = ring.pop() {
        v.push(u64::from(e.seq));
        rt::get_slab_pool_ref().release(e.handle);
        drop(s.room.as_ref().map(super::admission::HistoryRoom::adopt));
    }
    v
}

fn member(s: &super::subscriber::ReaderSubscriber<Small>, seq: u64, start: u64) {
    s.on_data_coherent(
        "t",
        A,
        seq,
        &encoded(seq),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        None,
        None,
    );
}

fn plain(s: &super::subscriber::ReaderSubscriber<Small>, seq: u64) {
    s.on_data_with_writer("t", A, seq, &encoded(seq), crate::dds::CdrVersion::Xcdr2);
}

/// Set {2, 3} staged and acknowledged, its end (4) not received; the
/// KEEP_LAST writer purges 2..=4 (HEARTBEAT firstSN 5); 5 arrives. The set,
/// received before 5, must not reach the application after it.
#[test]
fn v4_base_heartbeat_fast_forward_passes_a_staged_set() {
    let (ring, s, _credit) = sub();
    s.on_writer_heartbeat_range(A, 1, 1);
    plain(&s, 1);
    let mut taken = take(&ring, &s);
    member(&s, 2, 2);
    member(&s, 3, 2);
    s.on_writer_heartbeat_range(A, 5, 5);
    plain(&s, 5);
    taken.extend(take(&ring, &s));
    plain(&s, 6);
    taken.extend(take(&ring, &s));
    eprintln!("v4 base fast-forward: taken {taken:?}");
    let pos = |x: u64| taken.iter().position(|&t| t == x);
    if let (Some(p3), Some(p5)) = (pos(3), pos(5)) {
        assert!(p3 < p5, "set {{2,3}} delivered after 5: {taken:?}");
    }
}

/// Seed-6 shape (KEEP_ALL writer, tight history): history of 4 places,
/// 1..=3 not taken; set {4, 5}, closed by 6, waits for places; 6 is held
/// above it; every sample acknowledged, the writer purges and announces
/// firstSN 7. The set must still reach the application before 6.
#[test]
fn v4_base_fast_forward_releases_a_later_sample_ahead_of_a_set_waiting_for_places() {
    let (ring, mut s, credit) = sub();
    s.room = Some(super::admission::HistoryRoom::new(&ring, 4));
    s.on_writer_heartbeat_range(A, 1, 1);
    for seq in 1..=3 {
        plain(&s, seq);
    }
    member(&s, 4, 4);
    member(&s, 5, 4);
    plain(&s, 6);
    let ack = credit
        .answer_heartbeat(
            &A,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: 6,
                count: 1,
                final_flag: false,
            },
        )
        .expect("matched");
    eprintln!(
        "v4 base places: before purge ack base {} missing {:?}",
        ack.bitmap_base, ack.missing
    );
    let acked_6 = ack.bitmap_base > 6;
    s.on_writer_heartbeat_range(A, 7, 7);
    let mut taken = Vec::new();
    for _ in 0..4 {
        taken.extend(take(&ring, &s));
        plain(&s, 7);
        s.on_writer_heartbeat_range(A, 7, 7);
    }
    taken.extend(take(&ring, &s));
    eprintln!("v4 base places: taken {taken:?}");
    let pos = |x: u64| taken.iter().position(|&t| t == x);
    if let (Some(p5), Some(p6)) = (pos(5), pos(6)) {
        assert!(p5 < p6, "set {{4,5}} delivered after 6: {taken:?}");
    }
    assert!(pos(5).is_some(), "set {{4,5}} delivered: {taken:?}");
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!("v4 base places: acked_6={acked_6} lost={lost}");
    assert!(
        !(acked_6 && pos(6).is_none() && lost == 0),
        "6 acknowledged, never delivered, not reported lost: {taken:?}"
    );
}

/// Seed-6 shape, second form: history of 6 places, 1..=3 not taken; set
/// {4..=7} staged and acknowledged, waits for 4 places (3 free); 8 (no set)
/// closes it. The KEEP_ALL writer purges 4..=7 (acknowledged by its only
/// reader) and announces firstSN 8; 8 is resent. The set must reach the
/// application before 8.
#[test]
fn v4_base_fast_forward_over_an_acknowledged_set_waiting_for_places() {
    let (ring, mut s, credit) = sub();
    s.room = Some(super::admission::HistoryRoom::new(&ring, 6));
    s.on_writer_heartbeat_range(A, 1, 1);
    for seq in 1..=3 {
        plain(&s, seq);
    }
    for seq in 4..=7 {
        member(&s, seq, 4);
    }
    plain(&s, 8);
    let ack = credit
        .answer_heartbeat(
            &A,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq: 8,
                count: 1,
                final_flag: false,
            },
        )
        .expect("matched");
    eprintln!(
        "v4 base acked-set: ack base {} missing {:?}",
        ack.bitmap_base, ack.missing
    );
    // Legitimate purge only if 4..=7 are acknowledged.
    assert!(ack.bitmap_base > 7, "fixture: 4..=7 acknowledged");
    s.on_writer_heartbeat_range(A, 8, 8);
    plain(&s, 8);
    let mut taken = Vec::new();
    for _ in 0..4 {
        taken.extend(take(&ring, &s));
        s.on_writer_heartbeat_range(A, 8, 9);
        plain(&s, 8);
        plain(&s, 9);
    }
    taken.extend(take(&ring, &s));
    let lost = s.sample_lost.lock().expect("lost").total_count;
    eprintln!("v4 base acked-set: taken {taken:?} lost {lost}");
    let pos = |x: u64| taken.iter().position(|&t| t == x);
    assert!(
        pos(7).is_some(),
        "set {{4..=7}} acknowledged, never delivered: {taken:?} lost {lost}"
    );
    if let (Some(p7), Some(p8)) = (pos(7), pos(8)) {
        assert!(p7 < p8, "set {{4..=7}} delivered after 8: {taken:?}");
    }
}

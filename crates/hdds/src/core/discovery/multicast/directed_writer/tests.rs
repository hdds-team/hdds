// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 naskel.com

use super::*;

const US: [u8; 12] = [0xAA; 12];
const PEER_A: [u8; 12] = [0x0A; 12];
const PEER_B: [u8; 12] = [0x0B; 12];
const W: [u8; 4] = [0, 3, 1, 0xC3];
const R: [u8; 4] = [0, 3, 1, 0xC4];

/// A stand-in datagram: the number, then the GAP bytes it was handed.
fn fake(sn: u64, gap: &[u8]) -> Option<Vec<u8>> {
    let mut v = sn.to_le_bytes().to_vec();
    v.extend_from_slice(gap);
    Some(v)
}

fn sn_at(bytes: &[u8], o: usize) -> u64 {
    let high = u64::from(u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()));
    let low = u64::from(u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap()));
    (high << 32) | low
}

/// Submessages after the 20-byte header: (id, body offset).
fn submessages(d: &[u8]) -> Vec<(u8, usize)> {
    let mut out = Vec::new();
    let mut off = 20;
    while off + 4 <= d.len() {
        let len = usize::from(u16::from_le_bytes([d[off + 2], d[off + 3]]));
        out.push((d[off], off + 4));
        off += 4 + len;
    }
    out
}

/// [(gapStart, gapList.base)] of every GAP in an answer datagram.
fn gaps(d: &[u8]) -> Vec<(u64, u64)> {
    submessages(d)
        .into_iter()
        .filter(|(id, _)| *id == 0x08)
        .map(|(_, b)| (sn_at(d, b + 8), sn_at(d, b + 16)))
        .collect()
}

/// (firstSN, lastSN) of the HEARTBEAT in a datagram.
fn heartbeat(d: &[u8]) -> (u64, u64) {
    let (_, b) = submessages(d)
        .into_iter()
        .find(|(id, _)| *id == 0x07)
        .expect("a HEARTBEAT");
    (sn_at(d, b + 8), sn_at(d, b + 16))
}

fn at(ms: u64) -> Instant {
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *BASE.get_or_init(Instant::now) + Duration::from_millis(ms)
}

#[test]
fn the_first_sample_is_one_and_carries_no_gap() {
    let w = DirectedWriter::new(W, R);
    let (sn, d) = w.write_to(PEER_A, fake).unwrap();
    assert_eq!(sn, 1);
    assert_eq!(d.len(), 8, "no GAP before the first sample");
}

#[test]
fn two_writers_number_independently() {
    let w = TypeLookupWriters::new();
    for _ in 0..5 {
        w.request.write_to(PEER_A, fake).unwrap();
    }
    let (sn, d) = w.reply.write_to(PEER_A, fake).unwrap();
    assert_eq!(
        sn, 1,
        "the reply writer does not see the request writer's numbers"
    );
    assert_eq!(d.len(), 8);
    assert_eq!(w.request.last_sn(), 5);
}

#[test]
fn a_failed_build_takes_no_number() {
    let w = DirectedWriter::new(W, R);
    assert!(w.write_to(PEER_A, |_, _| None).is_none());
    assert_eq!(w.write_to(PEER_A, fake).unwrap().0, 1);
    assert!(w.write_undirected(None, |_| None).is_none());
    assert_eq!(w.write_undirected(None, |sn| fake(sn, &[])).unwrap().0, 2);
}

#[test]
fn numbers_used_for_another_peer_are_gapped_before_the_data() {
    let w = DirectedWriter::new(W, R);
    w.write_to(PEER_A, fake).unwrap(); // 1 -> A
    w.write_to(PEER_A, fake).unwrap(); // 2 -> A
    let (sn, d) = w.write_to(PEER_B, fake).unwrap(); // 3 -> B
    assert_eq!(sn, 3);
    assert_eq!(d[8], 0x08);
    assert_eq!(
        (sn_at(&d, 8 + 12), sn_at(&d, 8 + 20)),
        (1, 3),
        "B: 1..=2 irrelevant"
    );
    assert_eq!(&d[12..16], &R, "GAP readerId");
    assert_eq!(&d[16..20], &W, "GAP writerId");
    let (_, d) = w.write_to(PEER_A, fake).unwrap(); // 4 -> A
    assert_eq!(
        (sn_at(&d, 8 + 12), sn_at(&d, 8 + 20)),
        (3, 4),
        "A: 3 irrelevant"
    );
    let (_, d) = w.write_to(PEER_A, fake).unwrap(); // 5 -> A
    assert_eq!(d.len(), 8, "no GAP when nothing went elsewhere");
}

/// A number handed out with no destination (HTLK) may have reached any
/// peer: it is never declared irrelevant to one.
#[test]
fn a_number_sent_without_destination_is_never_gapped() {
    let w = DirectedWriter::new(W, R);
    w.write_to(PEER_B, fake).unwrap(); // 1 -> B
    w.write_undirected(None, |sn| fake(sn, &[])).unwrap(); // 2 -> anyone
    w.write_to(PEER_B, fake).unwrap(); // 3 -> B
    let (sn, d) = w.write_to(PEER_A, fake).unwrap(); // 4 -> A
    assert_eq!(sn, 4);
    // GAP [1,1] and GAP [3,3]: 2 is not among them.
    assert_eq!((sn_at(&d, 8 + 12), sn_at(&d, 8 + 20)), (1, 2));
    assert_eq!((sn_at(&d, 40 + 12), sn_at(&d, 40 + 20)), (3, 4));
    // With a destination, an HTLK number is that peer's: not GAPped to it.
    let w = DirectedWriter::new(W, R);
    w.write_undirected(Some(PEER_A), |sn| fake(sn, &[]))
        .unwrap(); // 1 -> A
    let (_, d) = w.write_to(PEER_A, fake).unwrap(); // 2 -> A
    assert_eq!(d.len(), 8);
}

/// Every unacknowledged sample a peer was sent is repaired, not only the
/// last (KEEP_ALL); a number it was never sent is GAPped; a number below
/// the oldest held is not GAPped but announced unavailable by the
/// HEARTBEAT's firstSN.
#[test]
fn every_held_sample_is_repaired_and_only_numbers_never_sent_are_gapped() {
    let w = DirectedWriter::new(W, R);
    let (_, one) = w.write_to(PEER_A, fake).unwrap(); // 1 -> A
    w.write_to(PEER_B, fake).unwrap(); // 2 -> B
    let (_, three) = w.write_to(PEER_A, fake).unwrap(); // 3 -> A
    let out = w.answer_acknack(&US, &PEER_A, 1, 1, &[Range { start: 1, end: 4 }], at(0));
    assert_eq!(out.len(), 3, "answer datagram, then repairs of 1 and 3");
    assert_eq!(&out[0][24..36], &PEER_A, "INFO_DST names the NACKing peer");
    assert_eq!(gaps(&out[0]), vec![(2, 3)], "only 2, sent to B, is GAPped");
    assert_eq!(heartbeat(&out[0]), (1, 3));
    assert_eq!(out[1], one);
    assert_eq!(out[2], three);
}

/// gapStart is never 0 (RTPS 2.5 8.3.7.4.3): a NACK range from 0 is
/// answered from 1.
#[test]
fn a_gap_never_starts_at_zero() {
    let w = DirectedWriter::new(W, R);
    w.write_to(PEER_B, fake).unwrap(); // 1 -> B
    w.write_to(PEER_B, fake).unwrap(); // 2 -> B
    w.write_undirected(Some(PEER_A), |sn| fake(sn, &[]))
        .unwrap(); // 3 -> A
    w.answer_acknack(&US, &PEER_A, 1, 4, &[], at(0)); // A acks 3
    let out = w.answer_acknack(&US, &PEER_A, 2, 0, &[Range { start: 0, end: 3 }], at(100));
    // Nothing held: first = 4, so 0..3 is below firstSN, said by HEARTBEAT.
    assert_eq!(gaps(&out[0]), Vec::<(u64, u64)>::new());
    assert_eq!(heartbeat(&out[0]), (4, 3));
    // A peer with a held sample, NACKing from 0: GAP from 1.
    let w = DirectedWriter::new(W, R);
    w.write_to(PEER_B, fake).unwrap(); // 1 -> B
    w.write_to(PEER_A, fake).unwrap(); // 2 -> A
    let held = w.held_for(&PEER_A);
    assert_eq!(held, vec![2]);
    // Force a range below the held sample by acking nothing and NACKing 0..2:
    // 1 lies below firstSN 2, so no GAP at all; a range from 0 that reaches
    // a never-sent number above firstSN starts its GAP at firstSN, never 0.
    let out = w.answer_acknack(&US, &PEER_A, 1, 0, &[Range { start: 0, end: 2 }], at(0));
    for (start, _) in gaps(&out[0]) {
        assert!(start >= 1, "gapStart 0");
    }
    // Unit check of the clamp itself, where firstSN is 1.
    let w = DirectedWriter::new(W, R);
    w.write_undirected(Some(PEER_A), |sn| fake(sn, &[]))
        .unwrap(); // 1 -> A, held
    w.write_to(PEER_B, fake).unwrap(); // 2 -> B
    w.write_to(PEER_A, fake).unwrap(); // 3 -> A
    let out = w.answer_acknack(&US, &PEER_A, 1, 0, &[Range { start: 0, end: 3 }], at(0));
    assert_eq!(gaps(&out[0]), vec![(2, 3)]);
    assert_eq!(out.len(), 2, "1 repaired");
}

#[test]
fn an_answer_carries_at_most_max_gap_runs() {
    let w = DirectedWriter::new(W, R);
    for _ in 0..20 {
        w.write_to(PEER_B, fake).unwrap(); // odd numbers to B
        w.write_to(PEER_A, fake).unwrap(); // even numbers to A
    }
    // A acks everything, then NACKs 1..40: 20 disjoint never-sent runs.
    w.answer_acknack(&US, &PEER_A, 1, 1, &[], at(0));
    let out = w.answer_acknack(&US, &PEER_A, 2, 1, &[Range { start: 1, end: 41 }], at(100));
    assert_eq!(gaps(&out[0]).len(), MAX_GAP_RUNS);
}

/// A NACK range that stops before the held sample does not resend it.
#[test]
fn a_held_sample_outside_the_nacked_range_is_not_resent() {
    let w = DirectedWriter::new(W, R);
    w.write_to(PEER_B, fake).unwrap(); // 1 -> B
    w.write_to(PEER_B, fake).unwrap(); // 2 -> B
    w.write_undirected(Some(PEER_A), |sn| fake(sn, &[]))
        .unwrap(); // 3 -> A
    w.write_to(PEER_B, fake).unwrap(); // 4 -> B
    w.write_to(PEER_A, fake).unwrap(); // 5 -> A
    let out = w.answer_acknack(&US, &PEER_A, 1, 3, &[Range { start: 4, end: 5 }], at(0));
    assert_eq!(out.len(), 1, "4 GAPped, 5 not resent: it was not NACKed");
    assert_eq!(gaps(&out[0]), vec![(4, 5)]);
}

#[test]
fn an_acknack_is_answered_once_per_count_and_rate_limited() {
    let w = DirectedWriter::new(W, R);
    w.write_to(PEER_A, fake).unwrap();
    let nack = [Range { start: 1, end: 2 }];
    assert_eq!(w.answer_acknack(&US, &PEER_A, 5, 1, &nack, at(0)).len(), 2);
    assert!(
        w.answer_acknack(&US, &PEER_A, 6, 1, &nack, at(1))
            .is_empty(),
        "too soon"
    );
    assert_eq!(
        w.answer_acknack(&US, &PEER_A, 7, 1, &nack, at(100)).len(),
        2
    );
    assert!(
        w.answer_acknack(&US, &PEER_A, 7, 1, &nack, at(200))
            .is_empty(),
        "same count"
    );
    assert!(
        w.answer_acknack(&US, &PEER_A, 6, 1, &nack, at(300))
            .is_empty(),
        "older count"
    );
    assert!(
        w.answer_acknack(&US, &PEER_B, 1, 1, &nack, at(400))
            .is_empty(),
        "a peer never written to gets nothing"
    );
}

#[test]
fn an_acknowledged_sample_is_released_and_no_longer_heartbeated() {
    let w = DirectedWriter::new(W, R);
    w.write_to(PEER_A, fake).unwrap();
    w.write_to(PEER_A, fake).unwrap();
    let hbs = w.heartbeats(&US);
    assert_eq!(hbs.len(), 1);
    assert_eq!(hbs[0].0, PEER_A);
    assert_eq!(heartbeat(&hbs[0].1), (1, 2));
    w.answer_acknack(&US, &PEER_A, 1, 2, &[], at(0));
    assert_eq!(w.held_for(&PEER_A), vec![2]);
    assert_eq!(heartbeat(&w.heartbeats(&US)[0].1), (2, 2));
    w.answer_acknack(&US, &PEER_A, 2, 3, &[], at(100));
    assert!(w.heartbeats(&US).is_empty(), "nothing unacknowledged");
}

#[test]
fn history_per_peer_is_bounded_oldest_first() {
    let w = DirectedWriter::new(W, R);
    for _ in 0..HISTORY_PER_PEER + 3 {
        w.write_to(PEER_A, fake).unwrap();
    }
    let held = w.held_for(&PEER_A);
    assert_eq!(held.len(), HISTORY_PER_PEER);
    assert_eq!(held[0], 4);
}

#[test]
fn the_least_recently_written_peer_is_forgotten_first() {
    let w = DirectedWriter::new(W, R);
    let peer = |i: usize| {
        let mut p = [0u8; 12];
        p[..8].copy_from_slice(&(i as u64).to_le_bytes());
        p
    };
    for i in 0..MAX_TRACKED_PEERS {
        w.write_to(peer(i), fake).unwrap();
    }
    // Peer 0 written again: it is now the most recent.
    w.write_to(peer(0), fake).unwrap();
    w.write_to(peer(MAX_TRACKED_PEERS), fake).unwrap();
    assert_eq!(w.tracked_peers(), MAX_TRACKED_PEERS, "bounded");
    assert!(
        w.held_for(&peer(1)).is_empty(),
        "peer 1, the oldest, forgotten"
    );
    assert!(!w.held_for(&peer(0)).is_empty());
    assert!(!w.held_for(&peer(2)).is_empty());
    assert!(
        !w.held_for(&peer(MAX_TRACKED_PEERS)).is_empty(),
        "the newest kept"
    );
    w.forget_peer(&peer(0));
    assert!(w.held_for(&peer(0)).is_empty());
}

#[test]
fn a_reader_answers_a_heartbeat_with_what_it_misses() {
    let rx = ReceivedStreams::default();
    assert!(rx.on_data(PEER_A, W, 2));
    assert!(!rx.on_data(PEER_A, W, 2), "a resent sample is a duplicate");
    assert_eq!(
        rx.on_heartbeat(PEER_A, W, 1, 3, 1),
        Some(AckNackDue {
            base: 1,
            missing: vec![1, 3]
        })
    );
    assert_eq!(rx.on_heartbeat(PEER_A, W, 1, 3, 1), None, "same count");
    assert!(rx.on_data(PEER_A, W, 1));
    rx.on_gap(PEER_A, W, 3, 4);
    assert_eq!(
        rx.on_heartbeat(PEER_A, W, 1, 3, 2),
        Some(AckNackDue {
            base: 4,
            missing: vec![]
        })
    );
    // firstSN above what we have: the rest is not waited for.
    assert_eq!(
        rx.on_heartbeat(PEER_A, W, 9, 9, 3),
        Some(AckNackDue {
            base: 9,
            missing: vec![9]
        })
    );
    assert!(!rx.on_data(PEER_A, W, 5), "below base");
    rx.forget_peer(&PEER_A);
    assert!(rx.on_data(PEER_A, W, 5));
}

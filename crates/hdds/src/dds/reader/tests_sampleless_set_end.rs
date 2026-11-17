// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A writer may end its open coherent set with a DATA that carries neither
//! payload nor key nor inline QoS (`D=0 K=0 Q=0`): a change with no
//! PID_COHERENT_SET, so no member of the set, which ends it (RTPS v2.5
//! Sec.8.7.6). The set is then whole and is delivered, and the change,
//! received, is acknowledged (Sec.8.4.12.2).
//!
//! The bytes below are a foreign publisher's UDP payloads, verbatim: a
//! one-sample set (writerSN 1, PID_COHERENT_SET 1, PID_KEY_HASH, a
//! `ShapeType` sample in D_CDR2_LE) addressed to reader 0x00000107, then the
//! bare DATA of writerSN 2.

use crate::core::discovery::fragment_buffer::FragmentBuffer;
use crate::core::rt;
use crate::engine::{
    route_data_packet, route_raw_rtps_message, RouterMetrics, Subscriber, TopicRegistry,
};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct ShapeType {
    #[key]
    color: String,
    x: i32,
    y: i32,
    shapesize: i32,
}

/// INFO_TS, then DATA writerSN 1 (E|Q|D), PID_KEY_HASH and PID_COHERENT_SET 1.
#[rustfmt::skip]
const SET_MEMBER: [u8; 144] = [
    0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x1b, 0x01, 0x1b, 0xf6, 0xcf, 0x19, 0x92, 0x9a, 0xfc,
    0x38, 0x94, 0xfe, 0xa2, 0x0e, 0x01, 0x0c, 0x00, 0x01, 0x1a, 0xac, 0x19, 0x00, 0x02, 0x24, 0xc5,
    0x3e, 0x07, 0x6e, 0x10, 0x09, 0x01, 0x08, 0x00, 0xcf, 0x9c, 0xe5, 0x6a, 0x21, 0xfe, 0xa8, 0xa3,
    0x15, 0x07, 0x5c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x07, 0x00, 0x00, 0x01, 0x02,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x70, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x42, 0x4c, 0x55, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
    0x1c, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x42, 0x4c, 0x55, 0x45, 0x00, 0x00, 0x00, 0x00,
    0x1f, 0x00, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// DATA writerSN 2, flags E only: no inline QoS, no payload.
#[rustfmt::skip]
const SET_END: [u8; 60] = [
    0x52, 0x54, 0x50, 0x53, 0x02, 0x05, 0x01, 0x1b, 0x01, 0x1b, 0xf6, 0xcf, 0x19, 0x92, 0x9a, 0xfc,
    0x38, 0x94, 0xfe, 0xa2, 0x0e, 0x01, 0x0c, 0x00, 0x01, 0x1a, 0xac, 0x19, 0x00, 0x02, 0x24, 0xc5,
    0x3e, 0x07, 0x6e, 0x10, 0x15, 0x01, 0x14, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x07,
    0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
];

const READER: [u8; 4] = [0x00, 0x00, 0x01, 0x07];

/// Where `SET_MEMBER` holds its writerSN (low word) and its
/// PID_COHERENT_SET (low word), its inline QoS and its serializedPayload.
const MEMBER_SN: usize = 68;
const MEMBER_SET: usize = 100;
const MEMBER_QOS: std::ops::Range<usize> = 72..108;
const MEMBER_PAYLOAD: std::ops::Range<usize> = 108..144;
/// Where `SET_END` holds its writerSN (low word).
const END_SN: usize = 56;

/// The captured member, as writerSN `seq` of the set that starts at
/// `set_start`.
fn member(seq: u32, set_start: u32) -> Vec<u8> {
    let mut packet = SET_MEMBER.to_vec();
    packet[MEMBER_SN..MEMBER_SN + 4].copy_from_slice(&seq.to_le_bytes());
    packet[MEMBER_SET..MEMBER_SET + 4].copy_from_slice(&set_start.to_le_bytes());
    packet
}

/// The captured bare DATA, as writerSN `seq`.
fn bare(seq: u32) -> Vec<u8> {
    let mut packet = SET_END.to_vec();
    packet[END_SN..END_SN + 4].copy_from_slice(&seq.to_le_bytes());
    packet
}

/// The captured member, writerSN `seq` of the set starting at `seq`, sent
/// as two DATA_FRAG of 20 octets (RTPS v2.5 Sec.8.3.8.3, Sec.9.4.5.5):
/// fragment `number` (1 or 2), the inline QoS on the first only.
fn member_fragment(seq: u32, number: u32) -> Vec<u8> {
    const FRAGMENT_SIZE: usize = 20;
    let sample = &SET_MEMBER[MEMBER_PAYLOAD];
    let at = (number as usize - 1) * FRAGMENT_SIZE;
    let data = &sample[at..(at + FRAGMENT_SIZE).min(sample.len())];
    let first = number == 1;
    let mut body = Vec::new();
    body.extend_from_slice(&[0x00, 0x00, 28, 0x00]);
    body.extend_from_slice(&READER);
    body.extend_from_slice(&[0x00, 0x00, 0x01, 0x02]);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&seq.to_le_bytes());
    body.extend_from_slice(&number.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&(FRAGMENT_SIZE as u16).to_le_bytes());
    body.extend_from_slice(&(sample.len() as u32).to_le_bytes());
    if first {
        let mut qos = SET_MEMBER[MEMBER_QOS].to_vec();
        let set = MEMBER_SET - MEMBER_QOS.start;
        qos[set..set + 4].copy_from_slice(&seq.to_le_bytes());
        body.extend_from_slice(&qos);
    }
    body.extend_from_slice(data);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    let mut packet = SET_MEMBER[..48].to_vec();
    packet.extend_from_slice(&[0x16, if first { 0x03 } else { 0x01 }]);
    packet.extend_from_slice(&(body.len() as u16).to_le_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn writer() -> [u8; 16] {
    let mut guid = [0u8; 16];
    guid[..12].copy_from_slice(&SET_MEMBER[8..20]);
    guid[12..].copy_from_slice(&[0x00, 0x00, 0x01, 0x02]);
    guid
}

struct Fixture {
    /// Unregisters `sub` from `registry` when the fixture drops (the
    /// subscriber holds the registry and the registry the subscriber).
    _registration: crate::engine::SubscriberToken,
    ring: Arc<rt::IndexRing>,
    sub: Arc<super::subscriber::ReaderSubscriber<ShapeType>>,
    credit: crate::core::reader::ReaderAckCredit,
    registry: Arc<TopicRegistry>,
    fragments: Mutex<FragmentBuffer>,
    pool: &'static Arc<rt::SlabPool>,
    _guard: rt::PrivateSlabPoolGuard,
}

impl Fixture {
    /// A reliable KEEP_ALL VOLATILE coherent reader (TOPIC scope) named
    /// `READER`, matched with the captured writer, whose first HEARTBEAT
    /// announced nothing yet (first 1, last 0).
    fn new() -> Self {
        Self::with_gate(super::reorder::ReorderGate::new(true, true), (1, 0))
    }

    /// [`Fixture::new`], with `gate` and a first HEARTBEAT announcing
    /// `first..=last`.
    fn with_gate(gate: super::reorder::ReorderGate, (first, last): (u64, u64)) -> Self {
        let (pool, guard) =
            rt::owned_private_slab_pool_for_test(&crate::qos::MemoryPolicy::default());
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            [0xA0; 16],
        );
        credit.match_writer(writer());
        let ring = Arc::new(rt::IndexRing::with_capacity(64));
        let status = Arc::new(crate::dds::StatusCondition::new());
        let registry = Arc::new(TopicRegistry::new());
        let mut sub = super::subscriber::ReaderSubscriber::<ShapeType>::new_with_coherent(
            "Square".to_string(),
            Arc::clone(&ring),
            Arc::clone(&status),
            None,
            None,
            None,
            Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
            Arc::new(Mutex::new(gate)),
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: false,
            },
            None,
            Some(credit.clone()),
            Arc::default(),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::Shared,
            Some(Arc::clone(&registry)),
            None,
            None,
            #[cfg(feature = "security")]
            None,
        );
        sub.room = Some(super::admission::HistoryRoom::new(
            &ring,
            crate::reliability::LENGTH_UNLIMITED,
        ));
        sub.reader_entity_id = Some(READER);
        sub.register_match_entry_for_test(crate::dds::QoS::reliable().keep_all());
        let sub = Arc::new(sub);
        let registration = registry
            .register_subscriber_scoped(Arc::clone(&sub) as Arc<dyn Subscriber>)
            .expect("register subscriber");
        registry.register_writer_guid(writer(), "Square".to_string());
        registry
            .register_writer_ownership_kind(writer(), crate::qos::ownership::OwnershipKind::Shared);
        sub.on_writer_heartbeat_range(writer(), first, last);
        Self {
            _registration: registration,
            ring,
            sub,
            credit,
            registry,
            fragments: Mutex::new(FragmentBuffer::new(8, 60_000)),
            pool,
            _guard: guard,
        }
    }

    /// Route a captured RTPS message as the live router does on receipt.
    fn route(&self, packet: &[u8]) {
        let (_, offset, _, _) = crate::core::discovery::multicast::classify_rtps(packet);
        let _ = route_data_packet(
            packet,
            packet.len(),
            offset,
            &self.registry,
            &RouterMetrics::new(),
        );
    }

    /// Route a message through the receive door that reassembles DATA_FRAG.
    fn route_door(&self, packet: &[u8]) {
        let _ = route_raw_rtps_message(
            packet,
            &self.registry,
            &RouterMetrics::new(),
            Some(&self.fragments),
        );
    }

    /// How many samples the application can take.
    fn take_all(&self) -> usize {
        let mut taken = 0;
        while let Some(entry) = self.ring.pop() {
            taken += 1;
            self.pool.release(entry.handle);
            drop(
                self.sub
                    .room
                    .as_ref()
                    .map(super::admission::HistoryRoom::adopt),
            );
        }
        taken
    }

    /// What the reader answers a HEARTBEAT announcing `first..=last`:
    /// (bitmapBase, missing).
    fn acknowledged(&self, first: i64, last: i64) -> (u64, Vec<u64>) {
        let answer = self
            .credit
            .answer_heartbeat(
                &writer(),
                &crate::core::reader::HeartbeatSeen {
                    first_seq: first,
                    last_seq: last,
                    count: 2,
                    final_flag: false,
                },
            )
            .expect("matched");
        (answer.bitmap_base, answer.missing)
    }
}

#[test]
fn a_bare_data_ends_the_coherent_set_staged_before_it() {
    let f = Fixture::new();
    f.route(&SET_MEMBER);
    assert_eq!(f.take_all(), 0, "a set is not delivered before its end");

    f.route(&SET_END);

    assert_eq!(f.take_all(), 1, "the set ended by the bare DATA is whole");
    assert_eq!(
        f.acknowledged(1, 2),
        (3, Vec::new()),
        "the bare DATA, received, is acknowledged"
    );
}

/// A volatile reader's gate is seeded by its writer's first DATA, and does
/// not keep a change without a sample before that. The end of a set that
/// overtook the set's first member is a change all the same, received and
/// acknowledged: where the set ends is known from it, and the set is
/// delivered once its member arrives (RTPS v2.5 Sec.8.7.6). So is the set
/// after it.
#[test]
fn an_end_of_set_received_before_its_first_member_ends_the_set() {
    let f = Fixture::new();
    f.route(&bare(2));
    assert_eq!(f.take_all(), 0, "an end alone delivers nothing");

    f.route(&member(1, 1));

    assert_eq!(f.take_all(), 1, "the set its end overtook is whole");
    f.route(&member(3, 3));
    f.route(&bare(4));
    assert_eq!(f.take_all(), 1, "the next set is delivered too");
    assert_eq!(f.acknowledged(1, 4), (5, Vec::new()));
}

/// The same overtaking, with the member sent as DATA_FRAG: the end arrives
/// while the member is being reassembled, and the set is delivered once
/// the member is whole.
#[test]
fn an_end_of_set_received_while_its_member_is_reassembled_ends_the_set() {
    let f = Fixture::new();
    f.route_door(&member_fragment(1, 1));
    f.route_door(&bare(2));
    assert_eq!(f.take_all(), 0, "a member in reassembly is no member yet");

    f.route_door(&member_fragment(1, 2));

    assert_eq!(f.take_all(), 1, "the reassembled member's set is whole");
    assert_eq!(f.acknowledged(1, 2), (3, Vec::new()));
}

/// A whole set waits for its writer's gate to reach it (a change before
/// it not received yet). When that change is a change without a sample,
/// its arrival moves the gate up to the set, and the set is delivered.
#[test]
fn a_change_without_a_sample_the_gate_waited_for_releases_the_set_after_it() {
    // A durable gate, seeded by the HEARTBEAT at 1.
    let f = Fixture::with_gate(super::reorder::ReorderGate::new(true, false), (1, 3));
    f.route(&member(2, 2));
    f.route(&bare(3));
    assert_eq!(f.take_all(), 0, "the set waits for writerSN 1");

    f.route(&bare(1));

    assert_eq!(
        f.take_all(),
        1,
        "the gate passed writerSN 1: the set is next"
    );
    assert_eq!(f.acknowledged(1, 3), (4, Vec::new()));
}

/// A repair of a member received already, sent as a change without a
/// sample, is a duplicate (RTPS v2.5 Sec.8.4.12.2): it is no change after
/// the set and closes nothing. The set stays whole and open until its
/// writer ends it.
#[test]
fn a_repair_of_a_staged_member_without_its_sample_closes_nothing() {
    let f = Fixture::new();
    f.route(&member(1, 1));
    f.route(&member(2, 1));

    f.route(&bare(2));

    assert_eq!(f.take_all(), 0, "a duplicate of a member closed its set");
    f.route(&bare(3));
    assert_eq!(f.take_all(), 2, "the set its writer ended is whole");
}

/// A writer this participant never discovered has no matched writer proxy
/// (RTPS v2.5 Sec.8.4.15): its change without a sample, routed to the
/// reader by its readerId, leaves nothing of the reader's coherent state.
#[test]
fn an_undiscovered_writers_change_without_a_sample_leaves_no_set_end() {
    let f = Fixture::new();
    let mut stranger = bare(1);
    // writerId 0x00000202, a writer no SEDP announced.
    stranger[50] = 0x02;
    let mut guid = writer();
    guid[14] = 0x02;

    f.route(&stranger);

    assert!(
        !f.sub
            .pending_coherent_end
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&guid),
        "an undiscovered writer's change was kept as a set end"
    );
}

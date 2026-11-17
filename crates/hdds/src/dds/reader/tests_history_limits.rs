// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HISTORY and RESOURCE_LIMITS on the reader side (DDS v1.4 Sec.2.2.3.18,
//! Sec.2.2.3.19), as the application sees them: through `take()` and the
//! SAMPLE_REJECTED status, never through the reader's internal rings.

use super::ReaderBuilder;
use crate::core::rt;
use crate::dds::listener::{SampleRejectedReason, SampleRejectedStatus};
use crate::dds::{QoS, DDS};
use crate::engine::Subscriber as _;
use std::sync::{Arc, Mutex};

/// A keyless sample: one instance.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
pub(super) struct Point {
    x: i32,
    y: i32,
}

/// A keyed sample: `id` names the instance.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
pub(super) struct Keyed {
    #[key]
    pub(super) id: i32,
    pub(super) value: i32,
}

pub(super) fn encoded<T: DDS>(sample: &T) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let len = sample
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf.truncate(len);
    buf
}

/// A reader built with a network ring, and the subscriber the network
/// delivers it through, wired as the builder wires them: the same ring,
/// the same history room, the same SAMPLE_REJECTED status.
pub(super) struct NetworkReader<T: DDS> {
    pub(super) reader: Arc<super::DataReader<T>>,
    pub(super) subscriber: Arc<super::subscriber::ReaderSubscriber<T>>,
    pub(super) topic: String,
    /// The reliable acknowledgement state of the subscriber, matched with
    /// `WRITER`.
    pub(super) credit: crate::core::reader::ReaderAckCredit,
}

/// The remote writer every test here receives from.
pub(super) const WRITER: [u8; 16] = [0x7A; 16];

/// A second remote writer.
pub(super) const WRITER_B: [u8; 16] = [0x7B; 16];

impl<T: DDS> NetworkReader<T> {
    pub(super) fn new(topic: &str, qos: QoS) -> Self {
        Self::with_gate(topic, qos, super::reorder::ReorderGate::new(false, false))
    }

    /// A reader whose subscriber orders each writer's samples through
    /// `gate`.
    fn with_gate(topic: &str, qos: QoS, gate: super::reorder::ReorderGate) -> Self {
        Self::with_parts(
            topic,
            qos,
            gate,
            crate::qos::ownership::OwnershipKind::default(),
            super::subscriber::CoherentConfig::default(),
        )
    }

    /// A reader whose subscriber orders each writer's samples through
    /// `gate` and arbitrates its instances with `ownership`.
    pub(super) fn with_parts(
        topic: &str,
        qos: QoS,
        gate: super::reorder::ReorderGate,
        ownership: crate::qos::ownership::OwnershipKind,
        coherent: super::subscriber::CoherentConfig,
    ) -> Self {
        Self::with_parts_judged(
            topic,
            qos,
            gate,
            ownership,
            coherent,
            None,
            crate::qos::partition::Partition::default(),
        )
    }

    /// `with_parts`, the subscriber judged by the match registry `registry`
    /// (its pair verdicts and, with the security plugins, its admission),
    /// as a participant wires it, the reader in `partition`. The reader's
    /// entry is not registered.
    pub(super) fn with_parts_judged(
        topic: &str,
        qos: QoS,
        gate: super::reorder::ReorderGate,
        ownership: crate::qos::ownership::OwnershipKind,
        coherent: super::subscriber::CoherentConfig,
        registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
        partition: crate::qos::partition::Partition,
    ) -> Self {
        Self::assembled(
            topic, qos, gate, ownership, coherent, registry, partition, None,
        )
    }

    /// `with_parts`, the reader a member `member` of a Subscriber's
    /// presentation barrier `barrier`, as a Subscriber's coherent reader
    /// is (`ReaderBuilder`).
    pub(super) fn with_barrier(
        topic: &str,
        qos: QoS,
        gate: super::reorder::ReorderGate,
        coherent: super::subscriber::CoherentConfig,
        barrier: Arc<super::coherent_barrier::CoherentPresentationBarrier>,
        member: super::coherent_barrier::MemberId,
    ) -> Self {
        Self::assembled(
            topic,
            qos,
            gate,
            crate::qos::ownership::OwnershipKind::default(),
            coherent,
            None,
            crate::qos::partition::Partition::default(),
            Some((barrier, member)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assembled(
        topic: &str,
        qos: QoS,
        gate: super::reorder::ReorderGate,
        ownership: crate::qos::ownership::OwnershipKind,
        coherent: super::subscriber::CoherentConfig,
        registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
        partition: crate::qos::partition::Partition,
        barrier: Option<(
            Arc<super::coherent_barrier::CoherentPresentationBarrier>,
            super::coherent_barrier::MemberId,
        )>,
    ) -> Self {
        let (barrier, member) = barrier.map_or((None, None), |(b, m)| (Some(b), Some(m)));
        // The reader's QoS says what its subscriber is told: a coherent
        // reader's PRESENTATION has `coherent_access`, which its history
        // reads too (`HistoryRoom::discards_old_values`).
        let mut qos = qos;
        qos.presentation.coherent_access |= coherent.coherent_access;
        let reliable = !matches!(qos.reliability, crate::dds::qos::Reliability::BestEffort);
        let credit = crate::core::reader::ReaderAckCredit::new(
            crate::core::reader::ReaderProxyRegistry::new(),
            [0xA0; 16],
        );
        credit.match_writer(WRITER);
        credit.match_writer(WRITER_B);
        let _ = rt::init_slab_pool();
        let time_based_filter = qos.time_based_filter;
        let reader = ReaderBuilder::<T>::new(topic.to_string())
            .qos(qos)
            .network_ring_for_test()
            .build()
            .expect("reader with a test network ring should build");
        let network_ring = Arc::clone(reader.network_ring_for_test().expect("network ring"));
        let status = reader.get_status_condition();
        // The reader's own queue of instance transitions, as the builder
        // wires it: what the subscriber queues, the reader reads.
        let dispose = Arc::clone(reader.dispose_events());
        let reorder = Arc::new(Mutex::new(gate));
        let subscriber = super::subscriber::ReaderSubscriber::<T>::new_with_coherent(
            topic.to_string(),
            network_ring,
            status,
            None,
            None,
            None,
            dispose,
            reorder,
            coherent,
            registry,
            // A BEST_EFFORT reader acknowledges nothing.
            reliable.then(|| credit.clone()),
            reader.sample_rejected_for_test(),
            Vec::new(),
            partition,
            ownership,
            None,
            barrier,
            member,
            #[cfg(feature = "security")]
            None,
        )
        .with_room(reader.network_room_for_test().cloned());
        let mut subscriber = subscriber;
        subscriber.time_based_filter = time_based_filter;
        subscriber.time_filter_checkers = Arc::clone(&reader.time_filter_checkers);
        subscriber.sample_lost = reader.sample_lost_for_test();
        let subscriber = Arc::new(subscriber);
        if member.is_some() {
            subscriber.attach_barrier_delivery();
        }
        // As the builder wires it: a take that gives places back tries
        // the coherent sets that wait for them again.
        if let Some(room) = reader.network_room_for_test() {
            let weak = Arc::downgrade(&subscriber);
            room.on_room(Box::new(move || {
                if let Some(subscriber) = weak.upgrade() {
                    subscriber.retry_waiting_sets();
                }
            }));
        }
        Self {
            reader: Arc::new(reader),
            subscriber,
            topic: topic.to_string(),
            credit,
        }
    }

    /// What the reader answers `WRITER` after a HEARTBEAT announcing
    /// 1..=`last_seq`: its acknowledgement base and what it asks again.
    fn acknowledged(&self, last_seq: i64, count: u32) -> (u64, Vec<u64>) {
        let answer = self
            .credit
            .answer_heartbeat(
                &WRITER,
                &crate::core::reader::HeartbeatSeen {
                    first_seq: 1,
                    last_seq,
                    count,
                    final_flag: false,
                },
            )
            .expect("matched");
        (answer.bitmap_base, answer.missing)
    }

    /// `WRITER` unregisters instance `id` as its change `seq`.
    fn unregister(&self, seq: u64, key: [u8; 16]) {
        self.subscriber.on_dispose_from_writer(
            &self.topic,
            WRITER,
            seq,
            key,
            crate::engine::subscriber::DisposeKind::Unregistered,
        );
    }

    pub(super) fn deliver(&self, writer: [u8; 16], seq: u64, sample: &T) {
        self.subscriber.on_data_with_writer(
            &self.topic,
            writer,
            seq,
            &encoded(sample),
            crate::dds::CdrVersion::Xcdr2,
        );
    }

    /// `writer`'s change `seq`, a member of the coherent set that starts
    /// at `set_start` (PID_COHERENT_SET, the classic model: the set closes
    /// when a later one starts).
    pub(super) fn deliver_coherent(&self, writer: [u8; 16], seq: u64, set_start: u64, sample: &T) {
        self.subscriber.on_data_coherent(
            &self.topic,
            writer,
            seq,
            &encoded(sample),
            crate::dds::CdrVersion::Xcdr2,
            Some(set_start),
            None,
            None,
        );
    }

    pub(super) fn take_all(&self) -> Vec<T> {
        let mut out = Vec::new();
        while let Some(sample) = self.reader.take().expect("take") {
            out.push(sample);
        }
        out
    }

    /// The samples reported lost (SAMPLE_LOST) so far.
    pub(super) fn lost(&self) -> u32 {
        self.reader.get_sample_lost_status().total_count
    }

    pub(super) fn rejected(&self) -> SampleRejectedStatus {
        self.reader.get_sample_rejected_status()
    }
}

/// KEEP_LAST keeps the newest `depth` samples, whatever the reader took or
/// did not take before: a reader that fell behind by more than its network
/// ring holds still sees the newest values, and nothing is rejected.
#[test]
fn keep_last_reader_that_does_not_take_keeps_the_newest_samples() {
    let net = NetworkReader::<Point>::new("hist-keep-last-newest", QoS::reliable().keep_last(10));
    let writer = [0x71u8; 16];
    let total: i32 = 2000;
    for i in 1..=total {
        net.deliver(
            writer,
            u64::try_from(i).expect("positive"),
            &Point { x: i, y: i },
        );
    }
    let taken: Vec<i32> = net.take_all().iter().map(|p| p.x).collect();
    assert_eq!(
        taken,
        ((total - 9)..=total).collect::<Vec<_>>(),
        "KEEP_LAST(10) delivers the ten newest samples"
    );
    let status = net.rejected();
    assert_eq!(
        status.total_count, 0,
        "KEEP_LAST replaces, it never rejects"
    );
}

/// KEEP_LAST is per instance: an instance written once, long ago, keeps its
/// value while another instance floods the reader.
#[test]
fn keep_last_keeps_a_quiet_instance_while_another_floods() {
    let net = NetworkReader::<Keyed>::new("hist-keep-last-quiet", QoS::reliable().keep_last(2));
    let writer = [0x72u8; 16];
    net.deliver(writer, 1, &Keyed { id: 1, value: 1 });
    let total: i32 = 3000;
    for i in 2..=total {
        net.deliver(
            writer,
            u64::try_from(i).expect("positive"),
            &Keyed { id: 2, value: i },
        );
    }
    let taken = net.take_all();
    assert_eq!(
        taken,
        vec![
            Keyed { id: 1, value: 1 },
            Keyed {
                id: 2,
                value: total - 1
            },
            Keyed {
                id: 2,
                value: total
            },
        ],
        "the quiet instance's only sample and the flooding instance's two newest"
    );
    assert_eq!(net.rejected().total_count, 0);
}

/// Fill a KEEP_LAST(`depth`) reader with `total` samples of one instance,
/// without taking, then take: the `depth` newest come out, and nothing was
/// rejected.
fn keep_last_keeps_the_newest(topic: &str, depth: u32, total: i32) {
    let net = NetworkReader::<Point>::new(topic, QoS::reliable().keep_last(depth));
    let writer = [0x73u8; 16];
    for i in 1..=total {
        net.deliver(
            writer,
            u64::try_from(i).expect("positive"),
            &Point { x: i, y: i },
        );
    }
    let taken: Vec<i32> = net.take_all().iter().map(|p| p.x).collect();
    let first = total - i32::try_from(depth).expect("small") + 1;
    assert_eq!(taken, (first..=total).collect::<Vec<_>>(), "depth {depth}");
    assert_eq!(net.rejected().total_count, 0, "depth {depth}");
}

/// A depth as large as the ring's usable capacity: the full ring holds
/// exactly `depth` samples the history keeps, and the newer sample replaces
/// the oldest of them.
#[test]
fn keep_last_as_deep_as_its_ring_replaces_the_oldest() {
    let depth = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() - 1;
    let depth = u32::try_from(depth).expect("small");
    keep_last_keeps_the_newest("hist-keep-last-ring-deep", depth, 1100);
}

/// A depth one above the default ring's usable capacity: the ring is sized
/// to hold `depth` samples of one instance.
#[test]
fn keep_last_deeper_than_the_default_ring_keeps_its_depth() {
    let depth = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two();
    let depth = u32::try_from(depth).expect("small");
    keep_last_keeps_the_newest("hist-keep-last-ring-deeper", depth, 2 * 1024 + 100);
}
/// The deprecated `try_take` keeps the newest `depth` samples of EACH
/// instance, like every other accessor.
#[test]
#[allow(deprecated)]
fn try_take_keeps_last_per_instance() {
    let _ = rt::init_slab_pool();
    let writer = crate::dds::writer::WriterBuilder::<Keyed>::new("hist-try-take".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let reader = ReaderBuilder::<Keyed>::new("hist-try-take".to_string())
        .qos(QoS::best_effort().keep_last(1))
        .build()
        .expect("reader");
    reader.bind_to_writer(writer.merger());
    for id in 1..=3 {
        writer.write(&Keyed { id, value: 10 }).expect("write");
        writer.write(&Keyed { id, value: 20 }).expect("write");
    }
    let mut taken = Vec::new();
    while let Some(sample) = reader.try_take().expect("try_take") {
        taken.push(sample);
    }
    taken.sort_by_key(|k| k.id);
    assert_eq!(
        taken,
        vec![
            Keyed { id: 1, value: 20 },
            Keyed { id: 2, value: 20 },
            Keyed { id: 3, value: 20 },
        ],
        "KEEP_LAST(1) keeps the newest sample of each of the three instances"
    );
}

fn keyed(id: i32, value: i32) -> Keyed {
    Keyed { id, value }
}

fn handle_of(id: i32) -> crate::dds::InstanceHandle {
    crate::dds::InstanceHandle::new(keyed(id, 0).compute_key())
}

/// DDS v1.4 Sec.2.2.3.19, max_instances, KEEP_ALL RELIABLE: a sample of an
/// instance beyond the limit is rejected as REJECTED_BY_INSTANCES_LIMIT and
/// not acknowledged, so that the writer sends it again. An instance stays
/// managed while a writer holds it or the history holds a sample of it
/// (Sec.2.2.3.22): taking its samples is not enough, its writer letting go
/// of it is what makes room.
#[test]
fn keep_all_rejects_an_instance_beyond_max_instances_unacknowledged() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_instances = 2;
    let net = NetworkReader::<Keyed>::new("limits-keep-all-instances", qos);
    net.deliver(WRITER, 1, &keyed(1, 1));
    net.deliver(WRITER, 2, &keyed(2, 2));
    net.deliver(WRITER, 3, &keyed(3, 3));

    let status = net.rejected();
    assert_eq!(status.total_count, 1);
    assert_eq!(status.last_reason, SampleRejectedReason::InstanceLimit);
    assert_eq!(status.last_instance_handle, Some(handle_of(3)));
    assert_eq!(net.acknowledged(3, 1), (3, vec![3]), "3 is asked again");
    assert_eq!(net.take_all(), vec![keyed(1, 1), keyed(2, 2)]);

    // Taken, but still written by WRITER: both instances are still managed.
    net.deliver(WRITER, 3, &keyed(3, 3));
    assert_eq!(net.rejected().total_count, 2, "still two instances managed");
    assert_eq!(net.take_all(), vec![]);

    // WRITER lets instance 1 go: its resources can be reclaimed.
    net.unregister(4, keyed(1, 0).compute_key());
    net.deliver(WRITER, 3, &keyed(3, 3));
    assert_eq!(net.take_all(), vec![keyed(3, 3)]);
    assert_eq!(net.rejected().total_count, 2, "accepted this time");
    assert_eq!(net.acknowledged(3, 2), (4, vec![]));
}

/// max_samples_per_instance, KEEP_ALL RELIABLE: the sample beyond the limit
/// is rejected as REJECTED_BY_SAMPLES_PER_INSTANCE_LIMIT, unacknowledged,
/// while other instances are still accepted; taking the instance's samples
/// makes room for it again.
#[test]
fn keep_all_rejects_beyond_max_samples_per_instance_unacknowledged() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples_per_instance = 2;
    let net = NetworkReader::<Keyed>::new("limits-keep-all-per-instance", qos);
    net.deliver(WRITER, 1, &keyed(1, 1));
    net.deliver(WRITER, 2, &keyed(1, 2));
    net.deliver(WRITER, 3, &keyed(1, 3));
    net.deliver(WRITER, 4, &keyed(2, 4));

    let status = net.rejected();
    assert_eq!(status.total_count, 1);
    assert_eq!(
        status.last_reason,
        SampleRejectedReason::SamplesPerInstanceLimit
    );
    assert_eq!(status.last_instance_handle, Some(handle_of(1)));
    assert_eq!(net.acknowledged(4, 1), (3, vec![3]), "3 is asked again");
    assert_eq!(net.take_all(), vec![keyed(1, 1), keyed(1, 2), keyed(2, 4)]);

    net.deliver(WRITER, 3, &keyed(1, 3));
    assert_eq!(net.take_all(), vec![keyed(1, 3)]);
    assert_eq!(net.rejected().total_count, 1);
    assert_eq!(net.acknowledged(4, 2), (5, vec![]));
}

/// KEEP_LAST: a newer sample replaces the oldest of its instance, so
/// max_samples_per_instance (which must be at least the depth) never
/// rejects; max_instances still rejects a sample of an instance beyond it,
/// which has no older sample to replace.
#[test]
fn keep_last_replaces_within_an_instance_and_rejects_beyond_max_instances() {
    let mut qos = QoS::reliable().keep_last(1);
    qos.resource_limits.max_instances = 2;
    qos.resource_limits.max_samples_per_instance = 1;
    let net = NetworkReader::<Keyed>::new("limits-keep-last", qos);
    for seq in 1..=5u64 {
        let value = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(1, value));
    }
    net.deliver(WRITER, 6, &keyed(2, 6));
    assert_eq!(net.rejected().total_count, 0, "KEEP_LAST replaces");

    net.deliver(WRITER, 7, &keyed(3, 7));
    let status = net.rejected();
    assert_eq!(status.total_count, 1);
    assert_eq!(status.last_reason, SampleRejectedReason::InstanceLimit);
    assert_eq!(status.last_instance_handle, Some(handle_of(3)));
    assert_eq!(net.acknowledged(7, 1), (7, vec![7]), "7 is asked again");

    net.deliver(WRITER, 8, &keyed(1, 8));
    assert_eq!(net.take_all(), vec![keyed(2, 6), keyed(1, 8)]);
    assert_eq!(net.rejected().total_count, 1);

    // Every sample replaced or taken, and WRITER lets both instances go:
    // nothing of them is left to manage, so two new instances have their
    // room. Instance 1's four replaced samples are not counted.
    net.unregister(9, keyed(1, 0).compute_key());
    net.unregister(10, keyed(2, 0).compute_key());
    net.deliver(WRITER, 7, &keyed(3, 7));
    net.deliver(WRITER, 11, &keyed(4, 11));
    assert_eq!(net.take_all(), vec![keyed(3, 7), keyed(4, 11)]);
    assert_eq!(net.rejected().total_count, 1, "both accepted");
}

/// The samples a full KEEP_LAST ring drops for newer ones of their instance
/// are no longer counted for it: once its writer lets it go and the newest
/// is taken, the instance leaves room for another.
#[test]
fn samples_a_full_keep_last_ring_replaces_leave_their_instance() {
    let mut qos = QoS::reliable().keep_last(1);
    qos.resource_limits.max_instances = 1;
    let net = NetworkReader::<Keyed>::new("limits-keep-last-ring", qos);
    let total: u64 = 3000;
    for seq in 1..=total {
        let value = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(1, value));
    }
    let last = i32::try_from(total).expect("small");
    assert_eq!(net.take_all(), vec![keyed(1, last)]);
    net.unregister(total + 1, keyed(1, 0).compute_key());
    net.deliver(WRITER, total + 2, &keyed(2, 1));
    assert_eq!(net.take_all(), vec![keyed(2, 1)]);
    assert_eq!(net.rejected().total_count, 0);
}

/// A sample the reader drops when it pumps it (its LIFESPAN expired) is no
/// longer counted for its instance.
#[test]
fn a_sample_dropped_on_its_way_to_the_application_leaves_its_instance() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_instances = 1;
    qos.lifespan = crate::qos::lifespan::Lifespan::new(std::time::Duration::from_nanos(1));
    let net = NetworkReader::<Keyed>::new("limits-lifespan", qos);
    net.deliver(WRITER, 1, &keyed(1, 1));
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert_eq!(net.take_all(), vec![], "expired");
    net.unregister(2, keyed(1, 0).compute_key());
    net.deliver(WRITER, 3, &keyed(2, 3));
    assert_eq!(net.rejected().total_count, 0, "instance 1 left the history");
}

/// One history for every writer of a reader, and places for each writer's
/// gap: a writer whose gate holds samples above a lost one keeps the places
/// that lost sample needs, and another writer's in-order stream does not
/// take them. Without that, the second writer filled the history while the
/// first waited for its repair, and the repair was refused for want of a
/// place, again at each retransmission while the stream went on: the first
/// writer starved.
#[test]
fn a_writer_s_in_order_stream_leaves_the_places_another_writer_s_gap_needs() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    // A RELIABLE TRANSIENT_LOCAL reader's gate: it orders each writer's
    // samples once that writer's first HEARTBEAT tells where they start.
    let net = NetworkReader::<Point>::with_gate(
        "limits-fair-room",
        qos,
        super::reorder::ReorderGate::new(true, false),
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    let a = |x: i32| Point { x, y: 1 };
    let b = |x: i32| Point { x, y: 2 };

    // WRITER's 1 is lost on the way: 2 and 3 wait for it.
    net.deliver(WRITER, 2, &a(2));
    net.deliver(WRITER, 3, &a(3));
    // WRITER_B streams in order.
    for seq in 1..=3u64 {
        net.deliver(WRITER_B, seq, &b(i32::try_from(seq).expect("small")));
    }
    // WRITER's 1 arrives again: it has its place.
    net.deliver(WRITER, 1, &a(1));

    let taken = net.take_all();
    let from_a: Vec<i32> = taken.iter().filter(|p| p.y == 1).map(|p| p.x).collect();
    assert_eq!(from_a, vec![1, 2, 3], "the repair found its place");
    let from_b: Vec<i32> = taken.iter().filter(|p| p.y == 2).map(|p| p.x).collect();
    assert_eq!(from_b, vec![1], "WRITER_B took the one place nobody owed");
}

/// Two writers with a gap each never wait for a place the other holds: a
/// held sample is admitted only if the free places still cover every open
/// gap, so each repair finds its place.
#[test]
fn two_writers_with_gaps_both_get_their_repairs_in() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = NetworkReader::<Point>::with_gate(
        "limits-fair-two-gaps",
        qos,
        super::reorder::ReorderGate::new(true, false),
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    let a = |x: i32| Point { x, y: 1 };
    let b = |x: i32| Point { x, y: 2 };

    // Both lose their 1; WRITER's 2 and 3, then WRITER_B's 2, arrive.
    net.deliver(WRITER, 2, &a(2));
    net.deliver(WRITER, 3, &a(3));
    net.deliver(WRITER_B, 2, &b(2));
    // The repairs, then WRITER_B's 2 again.
    net.deliver(WRITER, 1, &a(1));
    net.deliver(WRITER_B, 1, &b(1));
    let mut taken = net.take_all();
    net.deliver(WRITER_B, 2, &b(2));
    taken.extend(net.take_all());

    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(from(1), vec![1, 2, 3]);
    assert_eq!(from(2), vec![1, 2]);
}

/// The usable capacity of a reader's default network ring.
fn ring_capacity() -> u64 {
    u64::try_from(crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() - 1).expect("small")
}

/// A sample sent again that the reader already holds is a duplicate: a full
/// KEEP_LAST ring that makes room before the duplicate is recognised must
/// not count it as the newest sample of its instance and drop the one it
/// duplicates, which was acknowledged and is never sent again.
#[test]
fn a_duplicate_does_not_replace_the_sample_it_duplicates() {
    let net = NetworkReader::<Point>::new("hist-keep-last-dup", QoS::reliable().keep_last(1));
    let last = ring_capacity();
    for seq in 1..=last {
        let x = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &Point { x, y: 0 });
    }
    let x = i32::try_from(last).expect("small");
    net.deliver(WRITER, last, &Point { x, y: 0 });
    assert_eq!(net.take_all(), vec![Point { x, y: 0 }]);
    assert_eq!(net.rejected().total_count, 0);
}

/// EXCLUSIVE ownership, KEEP_LAST(1), a ring full of the owner's newest
/// values, one per instance: a sample of a writer that does not own its
/// instance is not visible, so it replaces nothing. Making room for it
/// before the arbitration dropped the owner's value of that instance for
/// good.
#[test]
fn a_sample_its_writer_does_not_own_replaces_nothing() {
    let net = NetworkReader::<Keyed>::with_parts(
        "hist-keep-last-exclusive",
        QoS::reliable().keep_last(1),
        super::reorder::ReorderGate::new(false, false),
        crate::qos::ownership::OwnershipKind::Exclusive,
        super::subscriber::CoherentConfig::default(),
    );
    let count = ring_capacity();
    for seq in 1..=count {
        let id = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(id, id));
    }
    // WRITER_B ties WRITER's strength and has the higher GUID: it does not
    // own instance 1.
    net.deliver(WRITER_B, 1, &keyed(1, -1));
    let taken = net.take_all();
    assert_eq!(taken.len(), usize::try_from(count).expect("small"));
    assert_eq!(taken.first(), Some(&keyed(1, 1)), "the owner's value stays");
    assert!(!taken.contains(&keyed(1, -1)));
    assert_eq!(net.rejected().total_count, 0);
}

/// A full-ring compaction pops the whole ring and pushes back what the
/// history keeps: a take that runs in between finds every ring empty and
/// clears DATA_AVAILABLE. What came back must raise it again, or a reader
/// waiting on its status sleeps with the newest sample unread.
#[test]
fn what_a_compaction_puts_back_is_announced() {
    let net = NetworkReader::<Point>::new("hist-keep-last-wake", QoS::reliable().keep_last(1));
    let status = net.reader.get_status_condition();
    status.set_enabled_statuses(crate::dds::StatusMask::DATA_AVAILABLE);
    let last = ring_capacity();
    for seq in 1..=last {
        let x = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &Point { x, y: 0 });
    }
    let reader = Arc::clone(&net.reader);
    net.subscriber.on_next_compaction(Box::new(move || {
        assert_eq!(reader.take().expect("take"), None, "the ring is popped");
    }));
    // A copy of the newest sample: the compaction it triggers keeps that
    // sample, and the copy itself is a duplicate, which pushes nothing.
    let x = i32::try_from(last).expect("small");
    net.deliver(WRITER, last, &Point { x, y: 0 });
    use crate::dds::Condition as _;
    assert!(
        status.get_trigger_value(),
        "the sample put back raised DATA_AVAILABLE"
    );
    assert_eq!(net.take_all(), vec![Point { x, y: 0 }]);
}

/// A RELIABLE TRANSIENT_LOCAL reader whose gate orders `WRITER`'s samples
/// from sequence 1, with `qos`.
fn ordered_reader<T: DDS>(topic: &str, qos: QoS) -> NetworkReader<T> {
    let net =
        NetworkReader::<T>::with_gate(topic, qos, super::reorder::ReorderGate::new(true, false));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net
}

/// max_samples_per_instance, KEEP_ALL: samples the gate holds above a lost
/// one count for their instance, and cannot leave before the lost one
/// comes. Held, they must leave their instance room for the gap below
/// them: two held samples of an instance limited to two refused the repair
/// of the first for good. The sample that would take that room is refused
/// unacknowledged instead, and not reported: it comes again once in order.
#[test]
fn held_samples_leave_their_instance_room_for_the_gap_below() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples_per_instance = 2;
    let net = ordered_reader::<Keyed>("limits-held-per-instance", qos);
    net.deliver(WRITER, 2, &keyed(1, 2));
    net.deliver(WRITER, 3, &keyed(1, 3));
    net.deliver(WRITER, 1, &keyed(1, 1));
    assert_eq!(net.take_all(), vec![keyed(1, 1), keyed(1, 2)]);
    assert_eq!(net.acknowledged(3, 1), (3, vec![3]), "3 is asked again");
    net.deliver(WRITER, 3, &keyed(1, 3));
    assert_eq!(net.take_all(), vec![keyed(1, 3)]);
    assert_eq!(net.rejected().total_count, 0, "nothing beyond a limit");
    assert_eq!(net.acknowledged(3, 2), (4, vec![]));
}

/// max_instances, KEEP_ALL: a held sample of a new instance takes an
/// instance slot it keeps until the gap below it fills. Held samples of two
/// new instances took both slots, and the repair, of a third, was refused
/// as beyond max_instances for good.
#[test]
fn held_samples_leave_instance_slots_for_the_gap_below() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_instances = 2;
    let net = ordered_reader::<Keyed>("limits-held-instances", qos);
    net.deliver(WRITER, 2, &keyed(2, 2));
    net.deliver(WRITER, 3, &keyed(3, 3));
    net.deliver(WRITER, 1, &keyed(1, 1));
    assert_eq!(net.take_all(), vec![keyed(1, 1), keyed(2, 2)]);
    assert_eq!(net.rejected().total_count, 0, "the held 3 was not reported");
    assert_eq!(net.acknowledged(3, 1), (3, vec![3]), "3 is asked again");
    // In order now, 3 meets the limit itself: instances 1 and 2 are still
    // written by WRITER.
    net.deliver(WRITER, 3, &keyed(3, 3));
    let status = net.rejected();
    assert_eq!(status.total_count, 1);
    assert_eq!(status.last_reason, SampleRejectedReason::InstanceLimit);
    net.unregister(4, keyed(1, 0).compute_key());
    net.deliver(WRITER, 3, &keyed(3, 3));
    assert_eq!(net.take_all(), vec![keyed(3, 3)]);
}

/// KEEP_LAST, max_instances: a sample the gate holds is acknowledged on
/// arrival, so it must count for its instance then. Counted only at its
/// release, a held sample of an instance beyond the limit would be rejected
/// after its acknowledgement: lost, never sent again. It is refused on
/// arrival instead, unacknowledged.
#[test]
fn keep_last_counts_a_held_sample_for_its_instance_before_acknowledging_it() {
    let mut qos = QoS::reliable().keep_last(1);
    qos.resource_limits.max_instances = 1;
    let net = ordered_reader::<Keyed>("limits-keep-last-held-instance", qos);
    net.deliver(WRITER, 1, &keyed(1, 1));
    net.deliver(WRITER, 3, &keyed(2, 3));
    net.deliver(WRITER, 2, &keyed(1, 2));
    assert_eq!(net.acknowledged(3, 1), (3, vec![3]), "3 is asked again");
    assert_eq!(net.take_all(), vec![keyed(1, 2)]);
    net.unregister(4, keyed(1, 0).compute_key());
    net.deliver(WRITER, 3, &keyed(2, 3));
    assert_eq!(net.take_all(), vec![keyed(2, 3)]);
    assert_eq!(net.acknowledged(3, 2), (4, vec![]));
}

/// KEEP_LAST: a sample the gate holds is acknowledged on arrival, so it
/// must hold its place in the ring then. Taking it only at its release, a
/// held sample found the ring full of the newest values of other instances,
/// none to replace, and was rejected after its acknowledgement: lost.
#[test]
fn keep_last_holds_a_ring_place_for_a_held_sample_before_acknowledging_it() {
    let net = ordered_reader::<Keyed>("limits-keep-last-held-place", QoS::reliable().keep_last(1));
    let capacity = ring_capacity();
    // One instance per sequence, the ring one short of full.
    for seq in 1..capacity {
        let id = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(id, id));
    }
    let held = capacity + 1;
    let held_id = i32::try_from(held).expect("small");
    net.deliver(WRITER, held, &keyed(held_id, held_id));
    let last_id = i32::try_from(capacity).expect("small");
    net.deliver(WRITER, capacity, &keyed(last_id, last_id));
    assert_eq!(
        net.acknowledged(i64::try_from(held).expect("small"), 1),
        (held, vec![held]),
        "the held sample found no place: asked again"
    );
    assert_eq!(
        net.rejected().total_count,
        0,
        "not reported: it comes again in order"
    );
    assert_eq!(
        net.take_all().len(),
        usize::try_from(capacity).expect("small")
    );
    net.deliver(WRITER, held, &keyed(held_id, held_id));
    assert_eq!(net.take_all(), vec![keyed(held_id, held_id)]);
}

/// KEEP_LAST: a sample the gate holds replaces nothing in a full ring.
/// Whether it is visible is known only at its release, in order; dropping
/// the value of its instance for it would leave the application without
/// that value if it is not, and without any value until the gap fills if it
/// is. It is refused, unacknowledged, and comes again in order.
#[test]
fn keep_last_a_held_sample_replaces_nothing() {
    // A finite max_instances: the held sample's instance is known on
    // arrival.
    let mut qos = QoS::reliable().keep_last(1);
    qos.resource_limits.max_instances = 4096;
    let net = ordered_reader::<Keyed>("limits-keep-last-held-replace", qos);
    let capacity = ring_capacity();
    for seq in 1..=capacity {
        let id = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(id, id));
    }
    // Sequence capacity + 1 is lost; capacity + 2 is a newer value of 1.
    net.deliver(WRITER, capacity + 2, &keyed(1, -1));
    let taken = net.take_all();
    assert_eq!(taken.len(), usize::try_from(capacity).expect("small"));
    assert_eq!(
        taken.first(),
        Some(&keyed(1, 1)),
        "instance 1 kept its value"
    );
    assert_eq!(net.rejected().total_count, 0);
}

/// One history for every writer, a coherent stream included: a coherent
/// set's samples, acknowledged when staged, take their places when the set
/// commits, where they cannot be refused. While another writer's gap is
/// open, a coherent sample is staged only if the history has room for it
/// and the samples already staged beyond the places that gap needs;
/// otherwise it is refused unacknowledged and comes again. Without that,
/// the committed set took the places the gap needed, the repair was refused
/// for want of one, and the set's last sample was rejected after its
/// acknowledgement.
#[test]
fn a_coherent_stream_leaves_the_places_another_writer_s_gap_needs() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = NetworkReader::<Point>::with_parts(
        "limits-fair-coherent",
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    let a = |x: i32| Point { x, y: 1 };
    let b = |x: i32| Point { x, y: 2 };

    // WRITER's 1 is lost on the way: 2 and 3 wait for it.
    net.deliver(WRITER, 2, &a(2));
    net.deliver(WRITER, 3, &a(3));
    // WRITER_B's set 1..=3, closed by the start of set 4.
    for seq in 1..=3u64 {
        net.deliver_coherent(WRITER_B, seq, 1, &b(i32::try_from(seq).expect("small")));
    }
    net.deliver_coherent(WRITER_B, 4, 4, &b(4));
    // WRITER's 1 arrives again: it has its place.
    net.deliver(WRITER, 1, &a(1));
    let mut taken = net.take_all();
    // WRITER_B sends again what was refused, and the next set closes its
    // first.
    for seq in 1..=3u64 {
        net.deliver_coherent(WRITER_B, seq, 1, &b(i32::try_from(seq).expect("small")));
    }
    net.deliver_coherent(WRITER_B, 4, 4, &b(4));
    taken.extend(net.take_all());

    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(from(1), vec![1, 2, 3], "the repair found its place");
    assert_eq!(from(2), vec![1, 2, 3], "the whole set, nothing rejected");
    assert_eq!(net.rejected().total_count, 0);
}

/// A sample that names no writer is acknowledged to nobody, so it can be
/// refused for want of a place without being lost to a writer that will
/// not send it again: while a writer's gap is open, it leaves that gap its
/// places as every writer does.
#[test]
fn a_sample_with_no_writer_leaves_the_places_a_gap_needs() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = ordered_reader::<Point>("limits-fair-no-writer", qos);
    let a = |x: i32| Point { x, y: 1 };
    net.deliver(WRITER, 2, &a(2));
    net.deliver(WRITER, 3, &a(3));
    for x in 1..=2 {
        net.subscriber.on_data_with_version(
            &net.topic,
            u64::try_from(x).expect("small"),
            &encoded(&Point { x, y: 0 }),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    net.deliver(WRITER, 1, &a(1));
    let from_a: Vec<i32> = net
        .take_all()
        .iter()
        .filter(|p| p.y == 1)
        .map(|p| p.x)
        .collect();
    assert_eq!(from_a, vec![1, 2, 3], "the repair found its place");
}

/// A full KEEP_LAST ring is compacted before the gate's lock and again
/// under it; the instance of each entry is decoded once per arrival, not
/// once per pass: the pass under the lock, which every writer of the
/// reader waits for, reuses what the first learned while the ring did not
/// change.
#[test]
fn a_full_ring_is_decoded_once_per_arrival() {
    let capacity = ring_capacity();
    let depth = u32::try_from(capacity).expect("small");
    let net =
        NetworkReader::<Keyed>::new("hist-keep-last-decodes", QoS::reliable().keep_last(depth));
    for seq in 1..=capacity {
        let value = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(1, value));
    }
    assert_eq!(net.subscriber.compaction_decodes(), 0, "the ring had room");
    for seq in capacity + 1..=capacity + 3 {
        let value = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(1, value));
    }
    assert!(
        net.subscriber.compaction_decodes() <= usize::try_from(3 * capacity).expect("small"),
        "decoded {} entries for 3 arrivals at a ring of {capacity}",
        net.subscriber.compaction_decodes()
    );
    let taken = net.take_all();
    assert_eq!(taken.len(), usize::try_from(capacity).expect("small"));
    assert_eq!(
        taken.last(),
        Some(&keyed(1, i32::try_from(capacity + 3).expect("small")))
    );
}

/// What a compaction learned of the ring's instances is reused only while
/// nothing was pushed since: a sample taken and another pushed leave the
/// ring as long as it was, with other instances in it.
#[test]
fn a_compaction_reuses_no_keys_a_push_made_stale() {
    let net =
        NetworkReader::<Keyed>::new("hist-keep-last-stale-keys", QoS::reliable().keep_last(1));
    let capacity = ring_capacity();
    for seq in 1..=capacity {
        let id = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(id, id));
    }
    // A copy of the last sample: the full ring is compacted (nothing to
    // drop) and learned, and the copy is a duplicate.
    let last = i32::try_from(capacity).expect("small");
    net.deliver(WRITER, capacity, &keyed(last, last));
    // The application takes instance 1's sample out of the ring.
    let ring = Arc::clone(net.reader.network_ring_for_test().expect("network ring"));
    let room = Arc::clone(net.reader.network_room_for_test().expect("room"));
    let entry = ring.pop().expect("instance 1");
    drop(room.adopt());
    rt::get_slab_pool().release(entry.handle);
    // A new instance fills the ring again, then a newer value of 1 comes:
    // there is no older sample of 1 in the ring to replace.
    let fresh = i32::try_from(capacity + 1).expect("small");
    net.deliver(WRITER, capacity + 1, &keyed(fresh, fresh));
    net.deliver(WRITER, capacity + 2, &keyed(1, -1));
    let taken = net.take_all();
    assert_eq!(
        taken.first(),
        Some(&keyed(2, 2)),
        "instance 2 kept its value"
    );
    assert_eq!(taken.len(), usize::try_from(capacity).expect("small"));
    assert!(!taken.contains(&keyed(1, -1)), "refused: no place");
}

/// A RELIABLE TRANSIENT_LOCAL reader with TOPIC-scope coherent access,
/// its gate seeded at 1 for `WRITER` and `WRITER_B`.
fn coherent_reader(topic: &str, qos: QoS) -> NetworkReader<Point> {
    let net = NetworkReader::<Point>::with_parts(
        topic,
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    net
}

/// A classic coherent set (PID_COHERENT_SET on each DATA) is committed
/// past the reorder gate. The gate must still step over the set's
/// sequences: otherwise it waits for them for good, and the plain DATA
/// that follows the set, acknowledged on arrival, is held for good. Here
/// the set is closed by the start of the next one.
#[test]
fn a_classic_coherent_set_closed_by_the_next_lets_the_gate_go_on() {
    let net = coherent_reader("coherent-classic-next-set", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.deliver(WRITER, 3, &p(3));
    net.deliver_coherent(WRITER, 4, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(1), p(2), p(3)]);
}

/// The same, the set closed by its explicit end (vendor 0x0101 dialect).
#[test]
fn a_classic_coherent_set_closed_by_its_end_lets_the_gate_go_on() {
    let net = coherent_reader("coherent-classic-end", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.deliver(WRITER, 3, &p(3));
    net.subscriber
        .on_coherent_end(&net.topic, WRITER, None, None, Some(1), None);
    assert_eq!(net.take_all(), vec![p(1), p(2), p(3)]);
}

/// Two classic-model coherent writers, each with a plain DATA held by the
/// gate above sequences its own coherent sets fill, every coherent sample
/// sent again each round. A staged sample that fills a gap is already
/// counted among the places that gap owes: counted again as staged, each
/// writer's set-closing sample was refused for the other's gap at every
/// resend, no set committed, and nothing was ever delivered.
#[test]
fn two_coherent_writers_gaps_do_not_deadlock_each_other() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 6;
    let net = coherent_reader("coherent-two-gaps", qos);
    let a = |x: i32| Point { x, y: 1 };
    let b = |x: i32| Point { x, y: 2 };
    net.deliver(WRITER, 3, &a(3));
    net.deliver(WRITER_B, 3, &b(3));
    let mut taken = Vec::new();
    for _round in 0..5 {
        net.deliver_coherent(WRITER, 1, 1, &a(1));
        net.deliver_coherent(WRITER_B, 1, 1, &b(1));
        net.deliver_coherent(WRITER, 2, 2, &a(2));
        net.deliver_coherent(WRITER_B, 2, 2, &b(2));
        net.deliver_coherent(WRITER, 4, 4, &a(4));
        net.deliver_coherent(WRITER_B, 4, 4, &b(4));
        taken.extend(net.take_all());
    }
    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(
        from(1),
        vec![1, 2, 3],
        "writer A's sets, then what they held"
    );
    assert_eq!(
        from(2),
        vec![1, 2, 3],
        "writer B's sets, then what they held"
    );
}

/// Two HDDS writers with end-of-set markers, TOPIC or GROUP scope (one
/// publisher each), each with a plain DATA held by the gate above the
/// coherent set that fills its gap, every sample sent again each round:
/// both sets commit and release what their gates held.
fn two_marker_writers_with_gaps_both_deliver(topic: &str, group: bool) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 8;
    let net = NetworkReader::<Point>::with_parts(
        topic,
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: group,
        },
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    let group_sn = group.then_some(1u64);
    let publisher = group.then_some([0, 0, 0, 0xC8]);
    let point = |writer: [u8; 16], x: i32| Point {
        x,
        y: i32::from(writer == WRITER_B) + 1,
    };
    // The set is 1..=2, its end marker 3, a plain DATA 4.
    for writer in [WRITER, WRITER_B] {
        net.deliver(writer, 4, &point(writer, 4));
    }
    let mut taken = Vec::new();
    for _round in 0..5 {
        for seq in 1..=2u64 {
            for writer in [WRITER, WRITER_B] {
                let x = i32::try_from(seq).expect("small");
                net.subscriber.on_data_coherent(
                    &net.topic,
                    writer,
                    seq,
                    &encoded(&point(writer, x)),
                    crate::dds::CdrVersion::Xcdr2,
                    Some(1),
                    group_sn,
                    publisher,
                );
            }
        }
        for writer in [WRITER, WRITER_B] {
            net.subscriber
                .on_ecs(&net.topic, writer, 3, 2, group_sn, publisher);
        }
        taken.extend(net.take_all());
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(from(1), vec![1, 2, 4], "writer A's set, then what it held");
    assert_eq!(from(2), vec![1, 2, 4], "writer B's set, then what it held");
}

#[test]
fn two_marker_writers_with_gaps_both_deliver_topic_scope() {
    two_marker_writers_with_gaps_both_deliver("coherent-two-gaps-ecs", false);
}

#[test]
fn two_marker_writers_with_gaps_both_deliver_group_scope() {
    two_marker_writers_with_gaps_both_deliver("coherent-two-gaps-group", true);
}

/// A third writer's coherent set, staged and still open, counts against
/// what the others may stage. Two writers with a gap their own sets fill
/// must still stage the sample that closes their set: refused for the
/// other's gap and the open set, neither set committed, the third set's
/// closer was refused for both gaps, the places were all held by samples
/// the gate holds, and the application had nothing to take.
#[test]
fn a_writer_s_set_that_fills_its_gap_is_never_refused_for_another_s() {
    let writer_c = [0x7C; 16];
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 6;
    let net = coherent_reader("coherent-three-writers", qos);
    net.credit.match_writer(writer_c);
    net.subscriber.on_writer_heartbeat(writer_c, 1);
    let point = |y: i32, x: i32| Point { x, y };
    // WRITER_C opens a set and stages two samples of it.
    net.deliver_coherent(writer_c, 1, 1, &point(3, 1));
    net.deliver_coherent(writer_c, 2, 1, &point(3, 2));
    // WRITER and WRITER_B: a plain DATA above the set that fills their gap.
    net.deliver(WRITER, 3, &point(1, 3));
    net.deliver(WRITER_B, 3, &point(2, 3));
    let mut taken = Vec::new();
    for _round in 0..5 {
        for (writer, y) in [(WRITER, 1), (WRITER_B, 2)] {
            net.deliver_coherent(writer, 1, 1, &point(y, 1));
            net.deliver_coherent(writer, 2, 1, &point(y, 2));
        }
        net.deliver_coherent(WRITER, 4, 4, &point(1, 4));
        net.deliver_coherent(WRITER_B, 4, 4, &point(2, 4));
        taken.extend(net.take_all());
        net.deliver_coherent(writer_c, 3, 3, &point(3, 3));
        taken.extend(net.take_all());
    }
    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(from(1), vec![1, 2, 3]);
    assert_eq!(from(2), vec![1, 2, 3]);
    assert_eq!(from(3), vec![1, 2]);
}

/// A staged sample that fills its writer's gap is counted once, among the
/// places that gap owes, not again as staged: another writer's coherent
/// sample that leaves the gap its places is staged, not refused.
#[test]
fn a_staged_sample_that_fills_a_gap_is_counted_once() {
    let writer_c = [0x7C; 16];
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 5;
    let net = coherent_reader("coherent-counted-once", qos);
    net.credit.match_writer(writer_c);
    net.subscriber.on_writer_heartbeat(writer_c, 1);
    let point = |y: i32, x: i32| Point { x, y };
    // WRITER: a plain DATA above its set 1..=2, which fills its gap.
    net.deliver(WRITER, 3, &point(1, 3));
    net.deliver_coherent(WRITER, 1, 1, &point(1, 1));
    net.deliver_coherent(WRITER, 2, 1, &point(1, 2));
    // WRITER_C's set 1, closed by the start of set 2, each sent once.
    net.deliver_coherent(writer_c, 1, 1, &point(3, 1));
    net.deliver_coherent(writer_c, 2, 2, &point(3, 2));
    net.deliver_coherent(WRITER, 4, 4, &point(1, 4));
    let taken = net.take_all();
    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(from(3), vec![1], "staged at its first arrival");
    assert_eq!(from(1), vec![1, 2, 3]);
    assert_eq!(net.rejected().total_count, 0);
}

/// A KEEP_LAST reader whose gate waits for the writer's first HEARTBEAT,
/// the DATA before it (RTPS v2.5 Sec.8.4.15.4 piggybacks the HEARTBEAT
/// after the DATA): held with its place and acknowledged, delivered as
/// soon as the HEARTBEAT seeds the gate, with no resend.
#[test]
fn keep_last_data_before_the_first_heartbeat_is_delivered_at_the_heartbeat() {
    let net = NetworkReader::<Point>::with_gate(
        "keep-last-pre-heartbeat",
        QoS::reliable().keep_last(1),
        super::reorder::ReorderGate::new(true, false),
    );
    net.deliver(WRITER, 1, &Point { x: 1, y: 1 });
    assert!(net.take_all().is_empty(), "nothing before the heartbeat");
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    assert_eq!(net.acknowledged(1, 1), (2, vec![]), "held, so acknowledged");
    assert_eq!(net.take_all(), vec![Point { x: 1, y: 1 }]);
    assert_eq!(net.rejected().total_count, 0);
}

/// A full KEEP_LAST ring replacing the oldest sample of the incoming
/// sample's instance hands that sample's place to the incoming one: the
/// replacement takes no place another writer's gap is owed. Dropping it
/// and asking for a place again refused the incoming sample whenever the
/// gaps were owed more than the one place freed, after its instance's
/// newest value had been dropped: the application had no value of it.
#[test]
fn keep_last_a_replacement_takes_the_place_of_what_it_replaces() {
    let net = ordered_reader::<Keyed>("limits-keep-last-transfer", QoS::reliable().keep_last(1));
    // WRITER_B's 10 is held before its HEARTBEAT, with its place.
    net.deliver(WRITER_B, 10, &keyed(5000, 10));
    // WRITER fills the rest of the ring, one instance per sample.
    let capacity = ring_capacity();
    for seq in 1..capacity {
        let id = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(id, id));
    }
    // WRITER_B's HEARTBEAT: its gap, 1..=9, is owed nine places.
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    // A newer value of instance 1.
    net.deliver(WRITER, capacity, &keyed(1, -1));
    let taken = net.take_all();
    assert!(
        taken.contains(&keyed(1, -1)),
        "the newer value replaced the older"
    );
    assert!(!taken.contains(&keyed(1, 1)));
    assert_eq!(taken.len(), usize::try_from(capacity - 1).expect("small"));
}

/// A coherent set closed by a standalone end marker, a change of its own
/// with its own sequence number (RTPS v2.5 Sec.8.7.5): acknowledged, never
/// delivered, it must be stepped over by the reorder gate like the set's
/// samples, or the plain DATA after it is acknowledged and held for good.
#[test]
fn a_standalone_end_marker_lets_the_gate_go_on() {
    let net = coherent_reader("coherent-end-marker", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, None, 3);
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(1), p(2), p(4)]);
}

/// The same, the marker overtaking a sample of its set (it names the set's
/// count): the set commits when its last sample comes, and the gate steps
/// over the set, then the marker.
#[test]
fn a_standalone_end_marker_that_overtakes_its_set_lets_the_gate_go_on() {
    let net = coherent_reader("coherent-end-marker-early", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, Some(2), 3);
    net.deliver(WRITER, 4, &p(4));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    assert_eq!(net.take_all(), vec![p(1), p(2), p(4)]);
}

/// A GROUP-scope reader ignores an end marker that names no group set,
/// but the marker is still a change it acknowledged: the gate steps over
/// it, and the plain DATA after it is delivered.
#[test]
fn a_group_reader_steps_over_an_end_marker_it_ignores() {
    let net = NetworkReader::<Point>::with_parts(
        "coherent-group-end-marker",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    let p = |x: i32| Point { x, y: 0 };
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, None, 1);
    net.deliver(WRITER, 2, &p(2));
    assert_eq!(net.take_all(), vec![p(2)]);
}

/// EXCLUSIVE ownership, a full KEEP_LAST ring with nothing of the incoming
/// sample's instance to replace: the sample is refused, unacknowledged, and
/// its writer is not made the owner of an instance it showed nothing of.
/// Arbitrated before being refused, it would keep the instance from a writer
/// that later writes it and would otherwise own it.
#[test]
fn a_refused_sample_takes_no_ownership() {
    let writer_c = [0x7C; 16];
    let net = NetworkReader::<Keyed>::with_parts(
        "hist-keep-last-refused-owner",
        QoS::reliable().keep_last(1),
        super::reorder::ReorderGate::new(false, false),
        crate::qos::ownership::OwnershipKind::Exclusive,
        super::subscriber::CoherentConfig::default(),
    );
    net.credit.match_writer(writer_c);
    let capacity = ring_capacity();
    for seq in 1..=capacity {
        let id = i32::try_from(seq).expect("small");
        net.deliver(WRITER, seq, &keyed(id, id));
    }
    // WRITER_B, a new instance: no place, nothing to replace.
    let fresh = i32::try_from(capacity + 1).expect("small");
    net.deliver(WRITER_B, 1, &keyed(fresh, -1));
    assert_eq!(
        net.take_all().len(),
        usize::try_from(capacity).expect("small")
    );
    // writer_c (it would lose a tie to WRITER_B) writes that instance first.
    net.deliver(writer_c, 1, &keyed(fresh, -2));
    assert_eq!(net.take_all(), vec![keyed(fresh, -2)], "writer_c owns it");
}

/// A change with no sample (an end-of-set marker a reader without coherent
/// access takes as such) that arrives before the writer's first HEARTBEAT
/// is acknowledged; the gate, not seeded yet, must keep it, or once the
/// HEARTBEAT seeds it the gate waits for it for good, and what follows it,
/// acknowledged, is never delivered.
#[test]
fn a_sample_less_change_before_the_first_heartbeat_is_kept() {
    let net = NetworkReader::<Point>::with_gate(
        "non-data-pre-heartbeat",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, None, 2);
    net.deliver(WRITER, 3, &p(3));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    assert_eq!(net.take_all(), vec![p(1), p(3)]);
    assert_eq!(net.acknowledged(3, 1), (4, vec![]));
}

/// The same with an HDDS end-of-set DATA on a coherent reader: before the
/// first HEARTBEAT it must not seed the gate past itself: what came before
/// it, the set it closes included, would be dropped as delivered.
#[test]
fn an_end_of_set_data_before_the_first_heartbeat_seeds_no_gate() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net = NetworkReader::<Point>::with_parts(
        "ecs-pre-heartbeat",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 2, &p(2));
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    net.deliver(WRITER, 4, &p(4));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    // A coherent reader refuses a plain DATA its gate would hold before the
    // gap is known: what was refused is sent again.
    let (_, missing) = net.acknowledged(4, 1);
    for seq in missing {
        net.deliver(WRITER, seq, &p(i32::try_from(seq).expect("small")));
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![p(1), p(2), p(4)]);
}

/// Two writers, each with DATA held before its first HEARTBEAT. Each
/// held sample keeps ONE place free, but an unseeded gate owes nothing to
/// the others (`places_owed` is 0 without `next_seq`), so both writers keep
/// the SAME free place. Once both HEARTBEATs arrive each gap owes a place,
/// and each writer's in-order repair must leave the other's owed place
/// free: free 1 <= owed 1 for both, every resend refused, the held samples
/// acknowledged and never released. Every sample is sent again each round
/// and the application takes all it can.
#[test]
fn verify_two_writers_held_before_heartbeat_do_not_deadlock_keep_all() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = NetworkReader::<Point>::with_gate(
        "verify-pre-hb-two-writers",
        qos,
        super::reorder::ReorderGate::new(true, false),
    );
    let pt = |y: i32, x: i32| Point { x, y };
    net.deliver(WRITER, 2, &pt(1, 2));
    net.deliver(WRITER, 3, &pt(1, 3));
    net.deliver(WRITER_B, 2, &pt(2, 2));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    let mut taken = Vec::new();
    for _round in 0..6 {
        for seq in 1..=3u64 {
            let x = i32::try_from(seq).expect("small");
            net.deliver(WRITER, seq, &pt(1, x));
            net.deliver(WRITER_B, seq, &pt(2, x));
        }
        taken.extend(net.take_all());
    }
    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(from(1), vec![1, 2, 3], "writer A");
    assert_eq!(from(2), vec![1, 2, 3], "writer B");
}

/// V1b. The same with KEEP_LAST: the held samples are in the gate, not the
/// ring, so a full room has nothing to replace and refuses the repair.
#[test]
fn verify_two_writers_held_before_heartbeat_do_not_deadlock_keep_last() {
    let net = NetworkReader::<Keyed>::with_gate(
        "verify-pre-hb-two-writers-kl",
        QoS::reliable().keep_last(1),
        super::reorder::ReorderGate::new(true, false),
    );
    let cap = ring_capacity();
    // One instance per (writer, seq): nothing replaces anything.
    let k = |w: i32, seq: u64| keyed(w * 100_000 + i32::try_from(seq).expect("small"), w);
    // A holds 2..=cap-1 (cap-2 samples), B holds 2: cap-1 places taken.
    for seq in 2..cap {
        net.deliver(WRITER, seq, &k(1, seq));
    }
    net.deliver(WRITER_B, 2, &k(2, 2));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    let mut taken = Vec::new();
    // Every unacknowledged sample is sent again each round.
    for _round in 0..4 {
        for seq in 1..cap {
            net.deliver(WRITER, seq, &k(1, seq));
        }
        for seq in 1..=2 {
            net.deliver(WRITER_B, seq, &k(2, seq));
        }
        taken.extend(net.take_all());
    }
    assert!(taken.contains(&k(1, 1)), "writer A's repair delivered");
    assert!(taken.contains(&k(2, 2)), "writer B's held sample delivered");
}

/// max_instances: a sample the gate holds keeps its instance managed until
/// it is released, whatever its writer says, so it must leave an instance
/// slot for the gap below it even when its own instance is managed already.
/// Held, it kept the only slot after its writer let the instance go, and
/// the gap's sample, of another instance, was refused for good.
#[test]
fn a_held_sample_leaves_an_instance_slot_even_for_a_known_instance() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_instances = 1;
    let net = ordered_reader::<Keyed>("limits-held-pins-slot", qos);
    net.deliver(WRITER, 1, &keyed(1, 1));
    let mut taken = net.take_all();
    net.deliver(WRITER, 3, &keyed(1, 3));
    // WRITER lets both instances go.
    net.unregister(10, keyed(1, 0).compute_key());
    net.unregister(10, keyed(2, 0).compute_key());
    for _round in 0..4 {
        net.deliver(WRITER, 2, &keyed(2, 2));
        net.deliver(WRITER, 3, &keyed(1, 3));
        taken.extend(net.take_all());
    }
    assert_eq!(taken, vec![keyed(1, 1), keyed(2, 2), keyed(1, 3)]);
    assert_eq!(net.acknowledged(3, 9), (4, vec![]));
}

/// RTPS v2.5 Sec.8.7.6: "The end of a Writer's coherent set is defined
/// by the arrival of ... A Data Submessage from this Writer that does not
/// contain a coherent set in-line QoS parameter". A classic writer's set
/// followed by a plain DATA, then silence: the set is closed by that DATA.
/// The reader commits nothing (only a NEXT set's first sample commits), so
/// the gate is never stepped over 1..=2 and the plain DATA, acknowledged,
/// is held with the set until a next set that may never come.
#[test]
fn verify_a_plain_data_ends_a_classic_coherent_set() {
    let net = coherent_reader("verify-plain-ends-set", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.deliver(WRITER, 3, &p(3));
    assert_eq!(net.take_all(), vec![p(1), p(2), p(3)]);
}

/// The staging check refuses a coherent sample in the MIDDLE of a set
/// (a writer with no gap of its own, another writer's gap open): the
/// samples before it are staged and acknowledged, the refused one is not.
/// An end marker that names no sample count then commits what is staged:
/// a partial set reaches the application (DDS v1.4 Sec.2.2.3.6, RTPS v2.5
/// Sec.8.7.6 "Incomplete coherent sets shall not be added"), and the
/// refused sample, sent again, is staged into a set that never closes.
#[test]
fn verify_a_refused_sample_never_splits_its_coherent_set() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 6;
    let net = coherent_reader("verify-split-set", qos);
    let pt = |y: i32, x: i32| Point { x, y };
    // B: plain 3 held above 1..=2, owed 2.
    net.deliver(WRITER_B, 3, &pt(2, 3));
    // A, no gap: set 1..=4.
    for seq in 1..=4u64 {
        net.deliver_coherent(WRITER, seq, 1, &pt(1, i32::try_from(seq).expect("small")));
    }
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, None, 5);
    let first = net.take_all();
    let a_first: Vec<i32> = first.iter().filter(|p| p.y == 1).map(|p| p.x).collect();
    assert!(
        a_first.is_empty() || a_first == vec![1, 2, 3, 4],
        "a coherent set is delivered whole or not at all, got {a_first:?}"
    );
}

/// A GROUP-scope reader, `WRITER` an HDDS writer of its own publisher.
fn group_reader(topic: &str) -> NetworkReader<Point> {
    let net = NetworkReader::<Point>::with_parts(
        topic,
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net
}

/// `WRITER`'s sample `seq` of the group set `gsn` starting at `start`.
fn stage_in_group(net: &NetworkReader<Point>, seq: u64, start: u64, gsn: u64) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let x = i32::try_from(seq).expect("small");
    net.subscriber.on_data_coherent(
        &net.topic,
        WRITER,
        seq,
        &encoded(&Point { x, y: 0 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        Some(gsn),
        Some([0, 0, 1, 8]),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

/// `WRITER`'s end-of-set DATA `seq` closing group set `gsn` at `last`.
fn end_group(net: &NetworkReader<Point>, seq: u64, last: u64, gsn: u64) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber
        .on_ecs(&net.topic, WRITER, seq, last, Some(gsn), Some([0, 0, 1, 8]));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

/// A GROUP set's end that overtakes one of its samples waits for it: the
/// set was flushed in part, and the late sample, acknowledged, was staged
/// under a set that never closed again.
#[test]
fn a_group_set_waits_for_a_sample_its_end_overtook() {
    let net = group_reader("group-end-overtakes");
    let p = |x: i32| Point { x, y: 0 };
    stage_in_group(&net, 1, 1, 1);
    end_group(&net, 3, 2, 1);
    assert_eq!(net.take_all(), vec![], "not whole yet");
    stage_in_group(&net, 2, 1, 1);
    assert_eq!(net.take_all(), vec![p(1), p(2)]);
}

/// A GROUP set flushed while the gate still waits below it (a sample of an
/// earlier set lost on the way) waits for that sample: the gate must not be
/// stepped over the hole, or the repair, acknowledged, would be dropped as
/// delivered.
#[test]
fn a_group_set_flushed_above_a_hole_does_not_drop_the_hole() {
    let net = group_reader("group-hole");
    let p = |x: i32| Point { x, y: 0 };
    // Set 1 is 1..=2, its end 3; set 2 is 4..=5, its end 6. 1 is lost.
    stage_in_group(&net, 2, 1, 1);
    end_group(&net, 3, 2, 1);
    stage_in_group(&net, 4, 4, 2);
    stage_in_group(&net, 5, 4, 2);
    end_group(&net, 6, 5, 2);
    assert_eq!(net.take_all(), vec![], "set 2 waits behind set 1");
    stage_in_group(&net, 1, 1, 1);
    assert_eq!(net.take_all(), vec![p(1), p(2), p(4), p(5)]);
    assert_eq!(net.acknowledged(6, 1), (7, vec![]));
}
/// A reader never refuses a coherent sample of a writer whose own gate
/// has a gap, whether or not the sample fills that gap. A set ABOVE the gap
/// is then staged (acknowledged) with no regard for the places another
/// writer's gap is owed, and its commit finds the history full: samples
/// acknowledged at staging are dropped (SAMPLE_REJECTED), never sent again.
/// (The set starts at 3: starting at 4 would leave the writer's sequence 3
/// neither sent nor declared irrelevant.) Every sample is sent again each
/// round.
#[test]
fn verify_a_gapped_writer_s_set_above_its_gap_is_not_lost_at_commit() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 6;
    let net = coherent_reader("verify-gapped-set-above", qos);
    let pt = |y: i32, x: i32| Point { x, y };
    // A: plain 2 held above 1 (owed 1). B: plain 3 held above 1..=2 (owed 2).
    net.deliver(WRITER, 2, &pt(1, 2));
    net.deliver(WRITER_B, 3, &pt(2, 3));
    let mut taken = Vec::new();
    for _round in 0..6 {
        // A's coherent set 3..=6, above its gap.
        for seq in 3..=6u64 {
            net.deliver_coherent(WRITER, seq, 3, &pt(1, i32::try_from(seq).expect("small")));
        }
        // A's gap fills, then set 4's end marker commits it.
        net.deliver(WRITER, 1, &pt(1, 1));
        // Set 3 closed by its standalone end marker, SN 7 (no staging
        // check on that path).
        net.subscriber
            .on_coherent_end_marker(&net.topic, WRITER, None, None, 3, None, 7);
        net.deliver(WRITER_B, 1, &pt(2, 1));
        net.deliver(WRITER_B, 2, &pt(2, 2));
        taken.extend(net.take_all());
    }
    let from = |y: i32| -> Vec<i32> { taken.iter().filter(|p| p.y == y).map(|p| p.x).collect() };
    assert_eq!(
        from(1),
        vec![1, 2, 3, 4, 5, 6],
        "writer A: nothing acknowledged dropped"
    );
    assert_eq!(from(2), vec![1, 2, 3], "writer B");
}

/// While another writer's gap is open, a coherent sample of a writer with a
/// gap of its own is staged regardless of the places only if it fills that
/// gap: one above it is a stream like any other, refused unacknowledged
/// when it would take what the other gap is owed.
#[test]
fn a_gapped_writer_s_sample_above_its_gap_leaves_another_gap_its_places() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 6;
    let net = coherent_reader("coherent-above-own-gap", qos);
    let pt = |y: i32, x: i32| Point { x, y };
    // WRITER: 2 held above 1. WRITER_B: 3 held above 1..=2, owed 2.
    net.deliver(WRITER, 2, &pt(1, 2));
    net.deliver(WRITER_B, 3, &pt(2, 3));
    // WRITER's set 4..=6, above its own gap (3 is WRITER's too: the set
    // starts after it).
    for seq in 4..=6u64 {
        net.deliver_coherent(WRITER, seq, 4, &pt(1, i32::try_from(seq).expect("small")));
    }
    let (_, missing) = net.acknowledged(6, 1);
    assert!(missing.contains(&6), "6 refused: missing {missing:?}");
    assert!(!missing.contains(&4), "4 staged: missing {missing:?}");
}

/// A writer's coherent samples staged at the bound of what one writer may
/// stage: the next one is refused, unacknowledged. Dropping the oldest
/// staged sample instead lost it, acknowledged, and its set could never be
/// whole again. (Sets of two that each lost their first member: staged,
/// none of them can commit.)
#[test]
fn a_full_staging_buffer_refuses_rather_than_drops() {
    let net = coherent_reader("coherent-staging-bound", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    let bound = u64::try_from(super::subscriber::MAX_STAGED_PER_WRITER).expect("small");
    for start in (1..=2 * bound + 1).step_by(2) {
        net.deliver_coherent(
            WRITER,
            start + 1,
            start,
            &p(i32::try_from(start).expect("small")),
        );
    }
    let last = 2 * bound + 2;
    let (base, missing) = net.acknowledged(i64::try_from(last).expect("small"), 1);
    assert_eq!(base, 1, "every first member lost");
    assert_eq!(
        missing,
        (1..=last)
            .filter(|s| s % 2 == 1 || *s == last)
            .collect::<Vec<_>>(),
        "every second member staged but the one beyond the bound, refused"
    );
}

/// A set that alone has more samples than a set may stage (the reader's
/// staging budget, `MAX_STAGED_PER_WRITER` samples by default) is rejected
/// whole: every sample acknowledged, none refused for good, each reported
/// once the set is closed. The writer's staging bound must not refuse the
/// sample that would reject the set, nor every sample after it (all counted
/// at the bound with the set's staged or rejected samples): refusing them
/// would be for good.
#[test]
fn a_set_past_what_a_set_may_stage_is_rejected_whole() {
    let net = coherent_reader("coherent-set-bound", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    let bound = u64::try_from(super::subscriber::MAX_STAGED_PER_WRITER).expect("small");
    // Ten past the bound: the first rejects the set, the others are of a
    // set rejected already.
    let size = bound + 10;
    for seq in 1..=size {
        net.deliver_coherent(WRITER, seq, 1, &p(i32::try_from(seq).expect("small")));
    }
    net.deliver(WRITER, size + 1, &p(0));
    let last = i64::try_from(size + 1).expect("small");
    assert_eq!(net.acknowledged(last, 1), (size + 2, vec![]));
    assert_eq!(
        net.take_all(),
        vec![p(0)],
        "the set rejected, what follows delivered"
    );
    assert_eq!(
        u64::from(net.rejected().total_count),
        size,
        "each sample of the set reported"
    );
}

/// A GROUP set likewise: past what a set may stage, it is rejected whole,
/// every sample acknowledged and reported. It is not discarded whole (its
/// samples acknowledged and never reported), nor refused for good at its
/// bound.
#[test]
fn a_group_set_past_what_a_set_may_stage_is_rejected_whole() {
    let net = group_reader("group-staging-bound");
    let bound = u64::try_from(super::subscriber::MAX_STAGED_PER_WRITER).expect("small");
    for seq in 1..=bound + 1 {
        stage_in_group(&net, seq, 1, 1);
    }
    end_group(&net, bound + 2, bound + 1, 1);
    let last = i64::try_from(bound + 2).expect("small");
    let (base, missing) = net.acknowledged(last, 1);
    assert_eq!(base, bound + 3, "every sample acknowledged");
    assert!(missing.is_empty());
    assert_eq!(
        u64::from(net.rejected().total_count),
        bound + 1,
        "each sample of the set reported"
    );
}

/// A coherent set that waits for places is committed by the take that gives
/// them back: its writer may have nothing more to send, its samples all
/// acknowledged, and no HEARTBEAT would come to try it again.
#[test]
fn a_take_commits_a_set_that_waited_for_places() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = coherent_reader("coherent-waits-for-take", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    net.deliver_coherent(WRITER, 3, 3, &p(3));
    net.deliver_coherent(WRITER, 4, 3, &p(4));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 3, None, 5);
    assert_eq!(net.acknowledged(5, 1), (6, vec![]), "all acknowledged");
    // The take gives the places back; the set commits then, off the taking
    // thread.
    let mut taken = net.take_all();
    assert!(taken.starts_with(&[p(1), p(2)]), "{taken:?}");
    taken.extend(take_until(&net, 2));
    assert_eq!(taken, vec![p(1), p(2), p(3), p(4)]);
}

// ---------------------------------------------------------------------
// Probes of coherent-set edge cases. Each states the spec-expected outcome.
// ---------------------------------------------------------------------

/// TOPIC scope, HDDS end-of-set DATA: the writer GAPs a member of a closed
/// set (its history dropped it, RTPS 2.5 8.3.8.4). The set can never be
/// whole: it is not delivered (RTPS 2.5 8.7.6), and the writer's later
/// changes still are.
#[test]
fn vx_gap_inside_a_closed_ecs_set_does_not_stall_the_writer() {
    let net = coherent_reader("vx-gap-ecs", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    // set {1,2,3}, ECS 4; 1 is GAPped by the writer.
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.deliver_coherent(WRITER, 3, 1, &p(3));
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    net.subscriber.on_writer_gap(WRITER, 1, 2, Vec::new());
    net.deliver(WRITER, 5, &p(5));
    net.deliver(WRITER, 6, &p(6));
    let got = net.take_all();
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(got, vec![p(5), p(6)], "places taken {}", room.taken());
}

/// The same with the classic model: set {1,2} closed by plain DATA 3.
#[test]
fn vx_gap_inside_a_classic_set_does_not_stall_the_writer() {
    let net = coherent_reader("vx-gap-classic", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.subscriber.on_writer_gap(WRITER, 1, 2, Vec::new());
    net.deliver(WRITER, 3, &p(3));
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(3), p(4)]);
}

/// A GAP that arrives before the member's set is closed.
#[test]
fn vx_gap_before_the_set_closes() {
    let net = coherent_reader("vx-gap-early-in-set", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.subscriber.on_writer_gap(WRITER, 1, 2, Vec::new());
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(4)]);
}

/// A GAP over a member of the second writer's set must not block the first
/// writer for good through the places the stuck stream holds.
#[test]
fn vx_gap_in_one_writers_set_does_not_starve_another_writer() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 3;
    let net = coherent_reader("vx-gap-starve", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER_B, 2, 1, &p(1002));
    net.subscriber
        .on_ecs(&net.topic, WRITER_B, 3, 2, None, None);
    net.subscriber.on_writer_gap(WRITER_B, 1, 2, Vec::new());
    for sn in 4..=8 {
        net.deliver(WRITER_B, sn, &p(1000 + i32::try_from(sn).unwrap()));
    }
    let mut got = Vec::new();
    // Adapted: what the reader refused, unacknowledged, is sent again the
    // next round (the probe sent each sample once, and the reader refuses
    // A's 1 while B's samples fill the history).
    for _round in 0..2 {
        for sn in 1..=4 {
            net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
            got.extend(net.take_all());
        }
    }
    let a: Vec<i32> = got.iter().filter(|s| s.x < 1000).map(|s| s.x).collect();
    assert_eq!(a, vec![1, 2, 3, 4], "writer A starved; all {got:?}");
}

fn same_publisher(byte: u8) -> [u8; 16] {
    let mut g = [0x5A; 16];
    g[12] = 0;
    g[13] = 0;
    g[14] = byte;
    g[15] = 0x02;
    g
}

fn group_stage(net: &NetworkReader<Point>, w: [u8; 16], seq: u64, start: u64, gsn: u64, x: i32) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        w,
        seq,
        &encoded(&Point { x, y: 0 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(start),
        Some(gsn),
        Some([0, 0, 1, 8]),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

fn group_end(net: &NetworkReader<Point>, w: [u8; 16], seq: u64, last: u64, gsn: u64) {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber
        .on_ecs(&net.topic, w, seq, last, Some(gsn), Some([0, 0, 1, 8]));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
}

fn two_writer_group_reader(topic: &str, qos: QoS) -> (NetworkReader<Point>, [u8; 16], [u8; 16]) {
    let net = NetworkReader::<Point>::with_parts(
        topic,
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    let a = same_publisher(1);
    let b = same_publisher(2);
    net.credit.match_writer(a);
    net.credit.match_writer(b);
    net.subscriber.on_writer_heartbeat(a, 1);
    net.subscriber.on_writer_heartbeat(b, 1);
    (net, a, b)
}

/// GROUP scope, two writers of one publisher in set gsn 1. Writer B leaves
/// before its end of set: the group set can never be whole, and is not
/// delivered (DDS 1.4 2.2.3.6, RTPS 2.5 8.7.6).
#[test]
fn vx_group_writer_departure_mid_set_delivers_no_partial_set() {
    let (net, a, b) = two_writer_group_reader("vx-group-depart", QoS::reliable().keep_all());
    group_stage(&net, a, 1, 1, 1, 11);
    group_stage(&net, b, 1, 1, 1, 21);
    group_end(&net, a, 2, 1, 1);
    net.subscriber.on_writer_dispose(
        &net.topic,
        b,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert!(got.is_empty(), "partial GROUP set delivered: {got:?}");
}

/// The same, writer A's own part not whole yet (its sample 2 still in
/// repair) when B leaves: A's part must not be flushed without it, and the
/// repair must not be lost.
#[test]
fn vx_group_departure_flush_skips_completeness_and_places() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 1;
    let (net, a, b) = two_writer_group_reader("vx-group-depart-incomplete", qos);
    group_stage(&net, a, 1, 1, 1, 11);
    // a's sample 2 lost on the way; its end names 2.
    group_end(&net, a, 3, 2, 1);
    group_stage(&net, b, 1, 1, 1, 21);
    net.subscriber.on_writer_dispose(
        &net.topic,
        b,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    let first: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    group_stage(&net, a, 2, 1, 1, 12);
    let later: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert!(
        first.is_empty(),
        "A's part flushed without its sample 2 (then {later:?})"
    );
}

/// A writer leaves while its closed, complete set waits for places: the
/// set goes with it, its places are not held, and the other writer goes on.
#[test]
fn vx_departure_of_a_writer_whose_set_waits_for_places() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = coherent_reader("vx-depart-waiting", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    net.deliver_coherent(WRITER_B, 1, 1, &p(101));
    net.deliver_coherent(WRITER_B, 2, 1, &p(102));
    net.subscriber
        .on_ecs(&net.topic, WRITER_B, 3, 2, None, None);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER_B,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    assert_eq!(net.take_all(), vec![p(1), p(2)]);
    net.deliver(WRITER, 3, &p(3));
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(3), p(4)]);
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(room.taken(), 0);
}

/// KEEP_LAST(1): a coherent set of instance X whose ring is full of other
/// instances' samples: a non-coherent sample of X would replace X's oldest;
/// a set waits until the application takes. Checks whether the writer's
/// stream is blocked (KEEP_LAST never blocks a reliable writer, DDS 1.4
/// 2.2.3.18/2.2.3.14).
#[test]
fn vx_keep_last_full_ring_coherent_set_never_waits() {
    let cap = ring_capacity();
    let net = NetworkReader::<Keyed>::with_parts(
        "vx-kl-full",
        QoS::reliable().keep_last(1),
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    for sn in 1..=cap {
        net.deliver(WRITER, sn, &keyed(i32::try_from(sn).unwrap(), 0));
    }
    // WRITER_B: a set with a new value of instance 1, then plain DATA of 2.
    net.deliver_coherent(WRITER_B, 1, 1, &keyed(1, 7));
    net.subscriber
        .on_ecs(&net.topic, WRITER_B, 2, 1, None, None);
    net.deliver(WRITER_B, 3, &keyed(2, 7));
    let (base, _) = {
        let answer = net
            .credit
            .answer_heartbeat(
                &WRITER_B,
                &crate::core::reader::HeartbeatSeen {
                    first_seq: 1,
                    last_seq: 3,
                    count: 1,
                    final_flag: false,
                },
            )
            .expect("matched");
        (answer.bitmap_base, answer.missing)
    };
    assert_eq!(base, 4, "writer B's stream held behind its waiting set");
}

/// A set that waits for places is tried again by the next take (round 4):
/// here the application takes with `DataReader::take_all` (or
/// take_instance, a TakeCondition), which gives the places back too. No
/// HEARTBEAT follows (the writer has everything acknowledged).
#[test]
fn vx_take_all_retries_a_waiting_set() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = coherent_reader("vx-take-all-retry", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    net.deliver_coherent(WRITER_B, 1, 1, &p(101));
    net.deliver_coherent(WRITER_B, 2, 1, &p(102));
    net.subscriber
        .on_ecs(&net.topic, WRITER_B, 3, 2, None, None);
    let first = net.reader.take_all().expect("take_all");
    assert_eq!(first, vec![p(1), p(2)]);
    // The set commits off the taking thread (the room given back schedules
    // it): taken once it has.
    let second = take_until(&net, 2);
    assert_eq!(second, vec![p(101), p(102)]);
}

/// BEST_EFFORT reader with coherent access (TOPIC). Losses are final on a
/// best-effort path: a set that lost a sample is never whole. Its staged
/// remnants must not pile up until the staging bound refuses every later
/// set of the writer.
#[test]
fn vx_best_effort_coherent_reader_survives_lost_set_members() {
    let net = NetworkReader::<Point>::with_parts(
        "vx-be-coherent",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let p = |x: i32| Point { x, y: 0 };
    let mut sn = 0u64;
    for _ in 0..100 {
        let first = sn + 1;
        // first member lost on the way, second arrives, then the ECS.
        net.deliver_coherent(WRITER, first + 1, first, &p(-1));
        net.subscriber
            .on_ecs(&net.topic, WRITER, first + 2, first + 1, None, None);
        sn += 3;
        let _ = net.take_all();
    }
    let first = sn + 1;
    net.deliver_coherent(WRITER, first, first, &p(7));
    net.deliver_coherent(WRITER, first + 1, first, &p(8));
    net.subscriber
        .on_ecs(&net.topic, WRITER, first + 2, first + 1, None, None);
    let got = net.take_all();
    assert_eq!(got, vec![p(7), p(8)]);
}

#[test]
fn vx_best_effort_coherent_ten_losses() {
    let net = NetworkReader::<Point>::with_parts(
        "vx-be-coherent-10",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let p = |x: i32| Point { x, y: 0 };
    let mut sn = 0u64;
    for _ in 0..10 {
        let first = sn + 1;
        // first member lost on the way, second arrives, then the ECS.
        net.deliver_coherent(WRITER, first + 1, first, &p(-1));
        net.subscriber
            .on_ecs(&net.topic, WRITER, first + 2, first + 1, None, None);
        sn += 3;
        let _ = net.take_all();
    }
    let first = sn + 1;
    net.deliver_coherent(WRITER, first, first, &p(7));
    net.deliver_coherent(WRITER, first + 1, first, &p(8));
    net.subscriber
        .on_ecs(&net.topic, WRITER, first + 2, first + 1, None, None);
    let got = net.take_all();
    assert_eq!(got, vec![p(7), p(8)]);
}

/// A DATA the writer sent before it left lands after its departure
/// (on_writer_dispose forgot its gate): it must not hold a history place
/// for good (no HEARTBEAT of that writer ever comes again).
#[test]
fn vx_late_data_after_departure_holds_no_place() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = NetworkReader::<Point>::with_parts(
        "vx-late-after-depart",
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig::default(),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.deliver(WRITER, 1, &p(1));
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.deliver(WRITER, 3, &p(3));
    let _ = net.take_all();
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(
        room.taken(),
        0,
        "a departed writer's late DATA holds a place"
    );
}

struct TakingListener {
    reader: std::sync::Mutex<Option<Arc<super::DataReader<Point>>>>,
    taken: std::sync::atomic::AtomicUsize,
}

impl crate::dds::listener::DataReaderListener<Point> for TakingListener {
    fn on_data_available(&self, _sample: &Point) {
        let reader = self.reader.lock().unwrap().clone();
        if let Some(reader) = reader {
            while let Ok(Some(_)) = reader.take() {
                self.taken
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// An on_data_available listener that takes (the common pattern) while a
/// coherent set waits for places: the take's retry runs on the delivering
/// thread, which holds the commit lock. Must not deadlock.
#[test]
fn vx_listener_take_while_a_set_waits_does_not_deadlock() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut qos = QoS::reliable().keep_all();
        qos.resource_limits.max_samples = 2;
        let net = coherent_reader("vx-listener-retry", qos);
        let listener = Arc::new(TakingListener {
            reader: std::sync::Mutex::new(Some(Arc::clone(&net.reader))),
            taken: std::sync::atomic::AtomicUsize::new(0),
        });
        let p = |x: i32| Point { x, y: 0 };
        net.deliver(WRITER, 1, &p(1));
        // B: set 3..=4 (end 5) arrives before set 1..=1 (end 2): it needs
        // the places of 1 and 2 below it too, and waits.
        net.deliver_coherent(WRITER_B, 3, 3, &p(103));
        net.deliver_coherent(WRITER_B, 4, 3, &p(104));
        net.subscriber
            .on_ecs(&net.topic, WRITER_B, 5, 4, None, None);
        // Now the listener is installed; the next commit pushes and the
        // listener takes.
        net.subscriber.listener.set(
            Some(listener.clone() as Arc<dyn crate::dds::listener::DataReaderListener<Point>>),
            crate::dds::StatusMask::DATA_AVAILABLE,
        );
        net.deliver_coherent(WRITER_B, 1, 1, &p(101));
        net.subscriber
            .on_ecs(&net.topic, WRITER_B, 2, 1, None, None);
        *listener.reader.lock().unwrap() = None;
        let _ = tx.send(listener.taken.load(std::sync::atomic::Ordering::Relaxed));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(n) => eprintln!("listener took {n}"),
        Err(_) => panic!("deadlock: the listener's take re-entered the commit lock"),
    }
}

#[test]
fn vx_listener_take_control_no_waiting_set() {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut qos = QoS::reliable().keep_all();
        qos.resource_limits.max_samples = 2;
        let net = coherent_reader("vx-listener-control", qos);
        let listener = Arc::new(TakingListener {
            reader: std::sync::Mutex::new(Some(Arc::clone(&net.reader))),
            taken: std::sync::atomic::AtomicUsize::new(0),
        });
        let p = |x: i32| Point { x, y: 0 };
        net.deliver(WRITER, 1, &p(1));
        // B: set 3..=4 (end 5) arrives before set 1..=1 (end 2): it needs
        // the places of 1 and 2 below it too, and waits.
        // Now the listener is installed; the next commit pushes and the
        // listener takes.
        net.subscriber.listener.set(
            Some(listener.clone() as Arc<dyn crate::dds::listener::DataReaderListener<Point>>),
            crate::dds::StatusMask::DATA_AVAILABLE,
        );
        net.deliver_coherent(WRITER_B, 1, 1, &p(101));
        net.subscriber
            .on_ecs(&net.topic, WRITER_B, 2, 1, None, None);
        *listener.reader.lock().unwrap() = None;
        let _ = tx.send(listener.taken.load(std::sync::atomic::Ordering::Relaxed));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(n) => eprintln!("listener took {n}"),
        Err(_) => panic!("deadlock: the listener's take re-entered the commit lock"),
    }
}

/// Take until `count` samples came (the coherent set a room given back
/// commits, off the taking thread), for at most five seconds.
fn take_until<T: DDS>(net: &NetworkReader<T>, count: usize) -> Vec<T> {
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while got.len() < count && std::time::Instant::now() < deadline {
        got.extend(net.take_all());
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    got
}

/// A listener that, from inside its first on_data_available, has another
/// thread commit another writer's set and waits for it (an application
/// that hands work to a thread and joins it).
struct JoiningListener {
    net: std::sync::Mutex<Option<Arc<NetworkReader<Point>>>>,
    joined: std::sync::Mutex<Option<bool>>,
}

impl crate::dds::listener::DataReaderListener<Point> for JoiningListener {
    fn on_data_available(&self, _sample: &Point) {
        let Some(net) = self.net.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            crate::engine::router::set_route_writer_is_hdds_for_test(true);
            net.deliver_coherent(WRITER_B, 1, 1, &Point { x: 2, y: 0 });
            net.subscriber
                .on_ecs(&net.topic, WRITER_B, 2, 1, None, None);
            let _ = tx.send(());
        });
        let joined = rx.recv_timeout(std::time::Duration::from_secs(3)).is_ok();
        *self.joined.lock().unwrap_or_else(|e| e.into_inner()) = Some(joined);
    }
}

/// No listener runs while the reader holds its commit state: another
/// thread's commit, which the listener waits for, goes through.
#[test]
fn a_listener_runs_with_no_commit_held() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net = Arc::new(coherent_reader(
        "coherent-listener-joins",
        QoS::reliable().keep_all(),
    ));
    let listener = Arc::new(JoiningListener {
        net: std::sync::Mutex::new(Some(Arc::clone(&net))),
        joined: std::sync::Mutex::new(None),
    });
    net.subscriber.listener.set(
        Some(listener.clone() as Arc<dyn crate::dds::listener::DataReaderListener<Point>>),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );
    net.deliver_coherent(WRITER, 1, 1, &Point { x: 1, y: 0 });
    net.subscriber.on_ecs(&net.topic, WRITER, 2, 1, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(
        *listener.joined.lock().unwrap_or_else(|e| e.into_inner()),
        Some(true),
        "the other writer's commit waited for the listener"
    );
}

/// The room a set waits for, given back between the set's refusal and the
/// mark that it waits (the take there sees no set waiting, schedules
/// nothing): the set asks once more after the mark, and commits.
#[test]
fn room_given_back_while_a_set_is_refused_is_not_missed() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = coherent_reader("coherent-refused-race", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    let reader = Arc::clone(&net.reader);
    let taken = Arc::new(std::sync::Mutex::new(Vec::new()));
    let in_hook = Arc::clone(&taken);
    net.subscriber.on_next_refused_room(Box::new(move || {
        let got = reader.take_all().expect("take_all");
        in_hook
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(got);
    }));
    net.deliver_coherent(WRITER_B, 1, 1, &p(101));
    net.deliver_coherent(WRITER_B, 2, 1, &p(102));
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber
        .on_ecs(&net.topic, WRITER_B, 3, 2, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(
        *taken.lock().unwrap_or_else(|e| e.into_inner()),
        vec![p(1), p(2)]
    );
    assert_eq!(take_until(&net, 2), vec![p(101), p(102)]);
}

/// A best-effort reader discards a closed set a member of which was lost,
/// and reports its samples as lost (SAMPLE_LOST).
#[test]
fn a_best_effort_reader_reports_an_incomplete_set_lost() {
    let net = NetworkReader::<Point>::with_parts(
        "be-coherent-lost",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let p = |x: i32| Point { x, y: 0 };
    // Set 1..=2, 1 lost; its end at 3; then a plain DATA 4.
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(4)]);
    assert_eq!(net.lost(), 2, "the set's two samples");
}

/// A GROUP set one of whose samples its writer GAPped can never be whole:
/// it is discarded, reported lost, and the writer's later changes are
/// delivered.
#[test]
fn a_group_set_with_a_gapped_sample_is_discarded() {
    let net = group_reader("group-gapped-member");
    let p = |x: i32| Point { x, y: 0 };
    stage_in_group(&net, 2, 1, 1);
    end_group(&net, 3, 2, 1);
    net.subscriber.on_writer_gap(WRITER, 1, 2, Vec::new());
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(4)]);
    assert_eq!(net.lost(), 2);
}

/// The same for a writer's set: discarded, its two samples reported lost.
#[test]
fn a_set_with_a_gapped_sample_is_reported_lost() {
    let net = coherent_reader("coherent-gapped-lost", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.subscriber.on_writer_gap(WRITER, 1, 2, Vec::new());
    net.deliver(WRITER, 3, &p(3));
    assert_eq!(net.take_all(), vec![p(3)]);
    assert_eq!(net.lost(), 2);
}

/// A sample of a set discarded already (a sample of it GAPped) that
/// arrives after the discard is of a set that no longer exists: stepped
/// over, never staged under it again. Staged, it reopened the set, which
/// the sequences the discard had stepped over made look closed and whole:
/// the set reached the application in part.
#[test]
fn a_late_sample_of_a_discarded_set_is_not_delivered() {
    let net = coherent_reader("coherent-late-of-discarded", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 3, 1, &p(3));
    net.subscriber.on_writer_gap(WRITER, 2, 3, Vec::new());
    net.deliver(WRITER, 4, &p(4));
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver(WRITER, 5, &p(5));
    assert_eq!(net.take_all(), vec![p(4), p(5)]);
    assert_eq!(net.lost(), 3);
}

/// A GAP that lands while an earlier set is still staged, for a sample of
/// a set that has not started yet, still discards that set once it comes:
/// what was GAPped outlives the commits that empty the staging.
#[test]
fn a_gap_ahead_of_its_set_outlives_the_sets_before() {
    let net = coherent_reader("coherent-gap-ahead", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.subscriber.on_writer_gap(WRITER, 5, 6, Vec::new());
    net.deliver(WRITER, 2, &p(2));
    net.deliver_coherent(WRITER, 3, 3, &p(3));
    net.deliver_coherent(WRITER, 4, 3, &p(4));
    net.deliver(WRITER, 6, &p(6));
    assert_eq!(net.take_all(), vec![p(1), p(2), p(6)]);
    assert_eq!(net.lost(), 3);
}

/// Sets commit out of order: a later set, closed and complete, commits
/// while an earlier one waits for a sample. What is known of the earlier
/// one (a GAPped sample of it) is not forgotten with the later one's
/// commit: the earlier set is discarded when it closes, reported lost, and
/// the later one is delivered. Forgotten, the earlier set waited for good
/// for the GAPped sample, and the later one behind it.
#[test]
fn an_earlier_set_is_judged_after_a_later_set_commits_first() {
    let net = coherent_reader("coherent-out-of-order-commit", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.subscriber.on_writer_gap(WRITER, 1, 2, Vec::new());
    net.deliver_coherent(WRITER, 3, 3, &p(3));
    net.deliver_coherent(WRITER, 4, 3, &p(4));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 3, Some(2), 5);
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    assert_eq!(net.take_all(), vec![p(3), p(4)]);
    assert_eq!(net.lost(), 2);
}

/// A sample of a coherent set its writer filtered for this reader (a GAP
/// whose filteredCount covers it, RTPS v2.5 Sec.8.3.8.4) is not part of the
/// reader's coherent set (Sec.8.7.6: the Subscriber-relevant coherent set
/// excludes "changes that are filtered by content or time"): the set is
/// whole without it, delivered, and nothing is reported lost ("Filtered
/// changes should not be treated as samples lost", Sec.8.3.8.4). Without
/// the count, the same GAP still discards the set.
#[test]
fn a_set_with_a_filtered_sample_is_whole_without_it() {
    let p = |x: i32| Point { x, y: 0 };
    let run = |filtered: Option<u64>| {
        let net = coherent_reader("coherent-filtered", QoS::reliable().keep_all());
        net.deliver_coherent(WRITER, 1, 1, &p(1));
        match filtered {
            Some(count) => net
                .subscriber
                .on_writer_gap_filtered(WRITER, 2, 3, Vec::new(), count),
            None => net.subscriber.on_writer_gap(WRITER, 2, 3, Vec::new()),
        }
        net.deliver_coherent(WRITER, 3, 1, &p(3));
        net.deliver(WRITER, 4, &p(4));
        (net.take_all(), net.lost())
    };
    assert_eq!(run(Some(1)), (vec![p(1), p(3), p(4)], 0), "filtered");
    assert_eq!(run(Some(0)).0, vec![p(4)], "not filtered: discarded");
    assert_eq!(run(None).0, vec![p(4)], "no count: discarded");
}

/// A filtered sequence the gate already passed does not make a set that
/// still waits for a member look broken: the set waits for it, and is
/// delivered whole when it lands.
#[test]
fn a_filtered_sequence_passed_by_the_gate_breaks_no_set() {
    let p = |x: i32| Point { x, y: 0 };
    let net = coherent_reader("coherent-filtered-passed", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    net.subscriber
        .on_writer_gap_filtered(WRITER, 2, 3, Vec::new(), 1);
    net.deliver_coherent(WRITER, 4, 2, &p(4));
    net.deliver(WRITER, 5, &p(5));
    net.deliver_coherent(WRITER, 3, 2, &p(3));
    assert_eq!(net.take_all(), vec![p(1), p(3), p(4), p(5)]);
    assert_eq!(net.lost(), 0);
}

/// The same for a GROUP set's part.
#[test]
fn a_group_set_with_a_filtered_sample_is_whole_without_it() {
    let net = group_reader("group-filtered");
    stage_in_group(&net, 1, 1, 1);
    net.subscriber
        .on_writer_gap_filtered(WRITER, 2, 3, Vec::new(), 1);
    stage_in_group(&net, 3, 1, 1);
    end_group(&net, 4, 3, 1);
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, vec![1, 3]);
    assert_eq!(net.lost(), 0);
}

/// SAMPLE_LOST counts samples (DDS v1.4 Sec.2.2.4.1: "A sample has been
/// lost (never received)"): a discarded set loses its staged members and
/// the members never received, not a change filtered for the reader (RTPS
/// v2.5 Sec.8.3.8.4), here 2, and each once (3, GAPped, is reported by its
/// GAP, not again by its set). The count is not the set's whole sequence
/// range.
#[test]
fn a_discarded_set_reports_the_samples_it_loses() {
    let net = coherent_reader("coherent-lost-count", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.subscriber
        .on_writer_gap_filtered(WRITER, 2, 3, Vec::new(), 1);
    net.deliver_coherent(WRITER, 4, 1, &p(4));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 4, None, 5);
    net.subscriber.on_writer_gap(WRITER, 3, 4, Vec::new());
    net.deliver(WRITER, 6, &p(6));
    assert_eq!(net.take_all(), vec![p(6)]);
    assert_eq!(net.lost(), 3, "1 and 4, staged, and 3, never received");
}

/// A GAP that declares a change this reliable reader is owed and never
/// received reports it lost (DDS v1.4 Sec.2.2.4.1), outside any set too;
/// but not a change filtered for the reader (RTPS v2.5 Sec.8.3.8.4:
/// "Filtered changes should not be treated as samples lost"), nor one it
/// received, nor one below where its gate is (not owed), nor any before
/// its gate knows where it joined.
#[test]
fn a_gapped_change_never_received_is_reported_lost() {
    let p = |x: i32| Point { x, y: 0 };
    let net = ordered_reader::<Point>("gap-lost", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    net.subscriber.on_writer_gap(WRITER, 2, 3, Vec::new());
    assert_eq!(net.lost(), 1, "2: owed, never received");
    net.subscriber
        .on_writer_gap_filtered(WRITER, 3, 4, Vec::new(), 1);
    assert_eq!(net.lost(), 1, "3: filtered");
    net.deliver(WRITER, 5, &p(5));
    net.subscriber.on_writer_gap(WRITER, 4, 5, vec![5]);
    assert_eq!(net.lost(), 2, "4: lost; 5: received");
    net.subscriber.on_writer_gap(WRITER, 1, 3, Vec::new());
    assert_eq!(net.lost(), 2, "below the gate, reported already");
    net.deliver(WRITER, 6, &p(6));
    assert_eq!(
        net.take_all(),
        vec![p(1), p(5), p(6)],
        "5, received before its GAP, is delivered"
    );
    let unseeded = NetworkReader::<Point>::with_gate(
        "gap-lost-unseeded",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
    );
    unseeded.subscriber.on_writer_gap(WRITER, 1, 5, Vec::new());
    assert_eq!(unseeded.lost(), 0, "before the gate knows its join point");
    let joined = NetworkReader::<Point>::with_gate(
        "gap-lost-joined",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, true),
    );
    joined.deliver(WRITER, 5, &p(5));
    joined.subscriber.on_writer_gap(WRITER, 1, 5, Vec::new());
    assert_eq!(joined.lost(), 0, "written before a VOLATILE reader joined");
}

/// A GAP's set is `[gapStart, gapList.base - 1]` and what gapList lists
/// (RTPS v2.5 Sec.8.3.8.4): with gapList.base at gapStart it is the listed
/// sequences alone, one here, not two.
#[test]
fn a_gap_with_its_base_at_its_start_declares_only_its_list() {
    let p = |x: i32| Point { x, y: 0 };
    let net = ordered_reader::<Point>("gap-base-at-start", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    net.subscriber.on_writer_gap(WRITER, 3, 3, vec![4]);
    assert_eq!(net.lost(), 1);
}

/// A GROUP set a writer leaves before its end is discarded whole and its
/// staged samples reported lost; the remaining writer goes on.
#[test]
fn a_group_set_its_writer_leaves_is_reported_lost() {
    let (net, a, b) = two_writer_group_reader("group-depart-lost", QoS::reliable().keep_all());
    group_stage(&net, a, 1, 1, 1, 11);
    group_stage(&net, b, 1, 1, 1, 21);
    group_end(&net, a, 2, 1, 1);
    net.subscriber.on_writer_dispose(
        &net.topic,
        b,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    assert_eq!(net.lost(), 2);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        a,
        3,
        &encoded(&Point { x: 13, y: 0 }),
        crate::dds::CdrVersion::Xcdr2,
        None,
        None,
        None,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![Point { x: 13, y: 0 }]);
}

/// A GROUP set discarded because a writer left: a sample of the remaining
/// writer's part that arrives afterwards is stepped over, not staged as a
/// set of its own that nothing would ever close, holding that writer's
/// later samples behind it.
#[test]
fn a_late_sample_of_a_group_set_discarded_on_departure_is_stepped_over() {
    let (net, a, b) = two_writer_group_reader("group-depart-late", QoS::reliable().keep_all());
    group_stage(&net, a, 1, 1, 1, 11);
    group_stage(&net, b, 1, 1, 1, 21);
    group_end(&net, a, 3, 2, 1);
    net.subscriber.on_writer_dispose(
        &net.topic,
        b,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    // A's 1 and B's 1, staged, and A's 2, never received.
    assert_eq!(net.lost(), 3);
    group_stage(&net, a, 2, 1, 1, 12);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        a,
        4,
        &encoded(&Point { x: 14, y: 0 }),
        crate::dds::CdrVersion::Xcdr2,
        None,
        None,
        None,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![Point { x: 14, y: 0 }]);
}

/// A best-effort GROUP reader, one writer (`same_publisher(1)`).
fn best_effort_group_reader(topic: &str) -> (NetworkReader<Point>, [u8; 16]) {
    best_effort_group_reader_with(topic, QoS::best_effort().keep_all())
}

/// [`best_effort_group_reader`] with `qos`.
fn best_effort_group_reader_with(topic: &str, qos: QoS) -> (NetworkReader<Point>, [u8; 16]) {
    let net = NetworkReader::<Point>::with_parts(
        topic,
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    (net, same_publisher(1))
}

/// A best-effort GROUP reader: a later change of the writer is delivered
/// at once (the best-effort gate never waits), so a GROUP set still staged
/// with an older sample of it is discarded, reported lost. Flushed when its
/// end came, it delivered the older sample after the newer one.
#[test]
fn a_best_effort_group_set_behind_a_delivered_change_is_discarded() {
    let (net, a) = best_effort_group_reader("be-group-behind");
    let p = |x: i32| Point { x, y: 0 };
    group_stage(&net, a, 1, 1, 1, 11);
    net.deliver(a, 3, &p(13));
    group_end(&net, a, 2, 1, 1);
    assert_eq!(net.take_all(), vec![p(13)]);
    assert_eq!(
        net.lost(),
        2,
        "the passed marker SN and the discarded staged sample"
    );
}

/// The same when the later change is of a later GROUP set that flushes
/// first.
#[test]
fn a_best_effort_group_set_behind_a_flushed_set_is_discarded() {
    let (net, a) = best_effort_group_reader("be-group-behind-set");
    let p = |x: i32| Point { x, y: 0 };
    group_stage(&net, a, 1, 1, 1, 11);
    group_stage(&net, a, 3, 3, 2, 13);
    group_end(&net, a, 4, 3, 2);
    group_end(&net, a, 2, 1, 1);
    assert_eq!(net.take_all(), vec![p(13)]);
    assert_eq!(
        net.lost(),
        2,
        "the passed marker SN and the discarded staged sample"
    );
}

/// The same when the later change is an HDDS writer's coherent sample
/// with no GROUP sequence number, passed straight through.
#[test]
fn a_best_effort_group_set_behind_a_passed_through_change_is_discarded() {
    let (net, a) = best_effort_group_reader("be-group-behind-passed");
    group_stage(&net, a, 1, 1, 1, 11);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_data_coherent(
        &net.topic,
        a,
        3,
        &encoded(&Point { x: 13, y: 0 }),
        crate::dds::CdrVersion::Xcdr2,
        Some(3),
        None,
        None,
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    group_end(&net, a, 2, 1, 1);
    assert_eq!(net.take_all(), vec![Point { x: 13, y: 0 }]);
    assert_eq!(
        net.lost(),
        2,
        "the passed marker SN and the discarded staged sample"
    );
}

/// A best-effort writer repairs nothing: a GROUP set closed with a member
/// missing is never whole, and is discarded at its end, reported lost, as
/// a writer's set is (`a_best_effort_reader_reports_an_incomplete_set_lost`).
#[test]
fn a_best_effort_group_set_closed_incomplete_is_reported_lost() {
    let (net, a) = best_effort_group_reader("be-group-incomplete");
    group_stage(&net, a, 2, 1, 1, 12);
    group_end(&net, a, 3, 2, 1);
    assert_eq!(net.lost(), 2);
    assert_eq!(net.take_all(), vec![]);
}

/// A best-effort reader never waits for room: a set that does not fit when
/// it closes is rejected whole, reported, as a single sample that finds no
/// place is. Waiting for a take, it reached the application behind the
/// change that closed it, which the best-effort gate passed at once.
#[test]
fn a_best_effort_set_that_does_not_fit_is_rejected_whole() {
    let mut qos = QoS::best_effort().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = NetworkReader::<Point>::with_parts(
        "be-set-no-room",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 2, &p(2));
    net.deliver_coherent(WRITER, 3, 2, &p(3));
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(1), p(4)]);
    assert_eq!(net.take_all(), vec![]);
    assert_eq!(net.rejected().total_count, 2);
}

/// A best-effort reader refuses a coherent sample older than a change of
/// its writer it already passed (T2, RTPS v2.5 Sec.8.4.12.1), as it
/// refuses a DATA it does not stage. Staged, its set reached the
/// application behind that later change.
#[test]
fn a_best_effort_reader_refuses_a_set_member_behind_a_passed_change() {
    let net = NetworkReader::<Point>::with_parts(
        "be-member-behind",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    // The set 2..=2 ends (an end-of-set marker, at 3); the change after it
    // is passed at once; the set's sample lands after that change.
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 2, Some(1), 3);
    net.deliver(WRITER, 4, &p(4));
    net.deliver_coherent(WRITER, 2, 2, &p(2));
    assert_eq!(net.take_all(), vec![p(1), p(4)]);
}

/// The same for a GROUP set.
#[test]
fn a_best_effort_group_set_that_does_not_fit_is_rejected_whole() {
    let mut qos = QoS::best_effort().keep_all();
    qos.resource_limits.max_samples = 2;
    let (net, a) = best_effort_group_reader_with("be-group-no-room", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(a, 1, &p(1));
    group_stage(&net, a, 2, 2, 1, 2);
    group_stage(&net, a, 3, 2, 1, 3);
    group_end(&net, a, 4, 3, 1);
    net.deliver(a, 5, &p(5));
    assert_eq!(net.take_all(), vec![p(1), p(5)]);
    assert_eq!(net.take_all(), vec![]);
    assert_eq!(net.rejected().total_count, 2);
}

/// A GROUP set discarded when a writer left, before the remaining
/// writer's end: that writer's later sample and end of the set are of a
/// set that no longer exists. Staged, they would start the set again with
/// that writer alone, and its end would flush that part of the set.
#[test]
fn a_group_set_discarded_is_not_started_again_by_its_late_parts() {
    let (net, a, b) = two_writer_group_reader("group-discarded-key", QoS::reliable().keep_all());
    group_stage(&net, a, 1, 1, 1, 11);
    group_stage(&net, b, 1, 1, 1, 21);
    net.subscriber.on_writer_dispose(
        &net.topic,
        b,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    assert_eq!(net.lost(), 2);
    group_stage(&net, a, 2, 1, 1, 12);
    group_end(&net, a, 3, 2, 1);
    group_stage(&net, a, 4, 4, 2, 14);
    group_end(&net, a, 5, 4, 2);
    assert_eq!(net.take_all(), vec![Point { x: 14, y: 0 }]);
}

/// A best-effort reader: a DATA its writer sent before it left that lands
/// after the departure is dropped, holding nothing. The departure forgot
/// the writer's state, so the late DATA, a copy of one delivered already,
/// was delivered again, older than the newest the writer sent.
#[test]
fn a_best_effort_reader_drops_what_lands_from_a_writer_that_left() {
    let net = NetworkReader::<Point>::with_parts(
        "be-departed-late",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig::default(),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1), p(2)]);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)], "announced again: a new writer");
}

/// A writer judged departed while it is in fact alive (a participant lease
/// expiry over a network outage, a probation purge: both reach
/// `on_writer_dispose`) keeps writing. Until it is matched again what lands
/// from it is dropped, holding nothing and unacknowledged. It comes back
/// the RTPS way: its participant is discovered again, its announcement is
/// received again, and the reader matches it again (a reliable reader's
/// writer proxy, `match_writer`; any reader's `on_writer_qos_resolved`).
/// Its first HEARTBEAT then shows its sequence numbers going on: it is the
/// same writer, and what it sends again (its history, to a durable reader
/// whose new proxy asks for it) is not delivered twice; what it wrote
/// meanwhile is delivered. The door neither stays shut for good nor (with a
/// time window) lets a durable reader re-deliver its history.
fn a_falsely_departed_writer_comes_back_matched_again(
    qos: QoS,
    gate: super::reorder::ReorderGate,
    durable: bool,
) {
    let reliable = !matches!(qos.reliability, crate::dds::qos::Reliability::BestEffort);
    let net = NetworkReader::<Point>::with_parts(
        "false-departure",
        qos,
        gate,
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig::default(),
    );
    let p = |x: i32| Point { x, y: 0 };
    if durable {
        net.subscriber.on_writer_heartbeat_range(WRITER, 1, 0);
    }
    for sn in 1..=10 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all().len(), 10);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    // Still writing, not matched again: dropped, holding nothing.
    net.deliver(WRITER, 11, &p(11));
    net.deliver(WRITER, 3, &p(3));
    assert_eq!(net.take_all(), vec![]);
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(room.taken(), 0);
    // Discovered again: matched again.
    if reliable {
        net.credit.match_writer(WRITER);
    }
    net.subscriber.on_writer_qos_resolved(WRITER);
    if reliable {
        // Matched again, before its first HEARTBEAT: a copy of a change
        // delivered already, then the writer's HEARTBEAT.
        net.deliver(WRITER, 3, &p(3));
        net.subscriber.on_writer_heartbeat_range(WRITER, 1, 20);
    }
    // A durable reader's new proxy asks for the history: sent again.
    let resent = if durable { 1..=20 } else { 11..=20 };
    for sn in resent {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(
        got,
        (11..=20).collect::<Vec<i32>>(),
        "everything new, nothing twice"
    );
}

#[test]
fn a_falsely_departed_writer_comes_back_to_a_durable_reader() {
    a_falsely_departed_writer_comes_back_matched_again(
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, false),
        true,
    );
}

#[test]
fn a_falsely_departed_writer_comes_back_to_a_volatile_reader() {
    a_falsely_departed_writer_comes_back_matched_again(
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, true),
        false,
    );
}

#[test]
fn a_falsely_departed_writer_comes_back_to_a_best_effort_reader() {
    a_falsely_departed_writer_comes_back_matched_again(
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        false,
    );
}

/// A writer re-created under the GUID of one that left starts its
/// sequence numbers again at 1 (RTPS v2.5 Sec.8.3.5.4): its first HEARTBEAT
/// shows a lastSN below what was received from the old one, and its
/// samples are delivered from 1, none taken for a copy of the old writer's.
#[test]
fn a_writer_back_with_a_lower_last_sequence_is_a_new_writer() {
    let net = ordered_reader::<Point>("recreated-verdict", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    for sn in 1..=10 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all().len(), 10);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 3);
    for sn in 1..=3 {
        net.deliver(WRITER, sn, &p(100 + i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all(), vec![p(101), p(102), p(103)]);
}

/// A listener that blocks while it runs on a retry thread.
struct BlockOnRetryThread {
    hold: std::time::Duration,
    blocked: std::sync::atomic::AtomicBool,
}

impl crate::dds::listener::DataReaderListener<Point> for BlockOnRetryThread {
    fn on_data_available(&self, _sample: &Point) {
        if std::thread::current().name() == Some("hdds-coherent-retry")
            && !self.blocked.swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            std::thread::sleep(self.hold);
        }
    }
}

/// A reader whose history is full (two samples of `WRITER`) and whose set
/// of `WRITER_B` (two samples, closed) waits for room.
fn reader_with_a_waiting_set(topic: &str) -> NetworkReader<Point> {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = coherent_reader(topic, qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    net.deliver_coherent(WRITER_B, 1, 1, &p(101));
    net.deliver_coherent(WRITER_B, 2, 1, &p(102));
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber
        .on_ecs(&net.topic, WRITER_B, 3, 2, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    net
}

/// Two unrelated readers, each with a set waiting for room. Reader 1's
/// listener blocks when its set is committed by its retry. Reader 2's set,
/// given room by its own application, is committed meanwhile: the retries
/// of one reader run on a thread of its own. On one thread for the whole
/// process, reader 2's set waited behind reader 1's listener.
#[test]
fn a_blocking_listener_does_not_hold_another_readers_waiting_sets() {
    let r1 = reader_with_a_waiting_set("retry-lane-1");
    let listener = Arc::new(BlockOnRetryThread {
        hold: std::time::Duration::from_millis(1500),
        blocked: std::sync::atomic::AtomicBool::new(false),
    });
    r1.subscriber.listener.set(
        Some(listener as Arc<dyn crate::dds::listener::DataReaderListener<Point>>),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );
    let r2 = reader_with_a_waiting_set("retry-lane-2");
    assert_eq!(r1.take_all().len(), 2);
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert_eq!(r2.take_all().len(), 2);
    let t0 = std::time::Instant::now();
    let mut got = Vec::new();
    while got.len() < 2 && t0.elapsed() < std::time::Duration::from_secs(3) {
        got.extend(r2.take_all());
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    let waited = t0.elapsed();
    assert_eq!(got.len(), 2, "reader 2's set is delivered");
    assert!(
        waited < std::time::Duration::from_millis(700),
        "reader 2's set waited {waited:?} behind reader 1's listener"
    );
}

/// A writer that left and is announced again (the same GUID, a new
/// writer) is a writer of the reader once more: its DATA is delivered.
#[test]
fn a_writer_announced_again_after_leaving_is_heard() {
    let net = ordered_reader::<Point>("departed-announced-again", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![], "dropped: it left");
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)]);
}

/// A best-effort coherent reader: a plain DATA closes the set before it,
/// and the set reaches the application before that DATA. A best-effort
/// gate passes the DATA at once: the set committed after it was delivered
/// behind it.
#[test]
fn a_best_effort_set_is_delivered_before_the_data_that_closes_it() {
    let net = NetworkReader::<Point>::with_parts(
        "be-set-before-closer",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.deliver(WRITER, 3, &p(3));
    assert_eq!(net.take_all(), vec![p(1), p(2), p(3)]);
}

// Known defects, each pinned by a test named for it and ignored until it
// is fixed.

fn probe_topic_reader<T: DDS>(topic: &str, qos: QoS, best_effort: bool) -> NetworkReader<T> {
    let gate = if best_effort {
        super::reorder::ReorderGate::new_best_effort()
    } else {
        super::reorder::ReorderGate::new(true, false)
    };
    let net = NetworkReader::<T>::with_parts(
        topic,
        qos,
        gate,
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    if !best_effort {
        net.subscriber.on_writer_heartbeat(WRITER, 1);
        net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    }
    net
}

/// A dispose written inside a coherent set is a member of it (RTPS v2.5
/// Sec.8.7.6: the Publisher coherent set is every change of its writers
/// between begin and end_coherent_changes; DDS v1.4 Sec.2.2.2.4.1.10): it
/// carries the set's PID_COHERENT_SET (`on_lifecycle_coherent`), is staged
/// with the set, and the instance's transition is applied when the set is
/// delivered, with it, not before. Taken as a change of no set, it ended
/// the set in its middle: the set was delivered in part (1.4.x: stalled).
fn a_dispose_inside_a_set_is_a_member_of_it(qos: QoS, best_effort: bool, closer: &str) {
    crate::engine::router::set_route_writer_is_hdds_for_test(closer == "ecs");
    let net = probe_topic_reader::<Keyed>("dispose-in-set", qos, best_effort);
    let key = keyed(1, 0).compute_key();
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.subscriber.on_lifecycle_coherent(
        &net.topic,
        WRITER,
        2,
        key,
        crate::engine::subscriber::DisposeKind::Disposed,
        Some(1),
        None,
        None,
    );
    net.deliver_coherent(WRITER, 3, 1, &keyed(3, 3));
    #[allow(deprecated)]
    let early = net.reader.get_dispose_events();
    assert!(
        early.is_empty(),
        "the transition waits for its set: {early:?}"
    );
    match closer {
        "ecs" => net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None),
        _ => net.deliver_coherent(WRITER, 4, 4, &keyed(4, 4)),
    }
    net.deliver(WRITER, 5, &keyed(5, 5));
    if !best_effort {
        net.subscriber.on_writer_heartbeat(WRITER, 1);
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    #[allow(deprecated)]
    let events = net.reader.get_dispose_events();
    assert_eq!(events.len(), 1, "the dispose applied with its set");
    assert_eq!((events[0].key_hash, events[0].seq), (key, 2));
    let got = net.take_all();
    let mut want = vec![keyed(1, 1), keyed(3, 3)];
    if closer != "ecs" {
        want.push(keyed(4, 4));
    }
    want.push(keyed(5, 5));
    assert_eq!((got, net.lost()), (want, 0), "the set whole, nothing lost");
}

#[test]
fn a_dispose_inside_a_coherent_set_is_a_member_of_it_reliable() {
    a_dispose_inside_a_set_is_a_member_of_it(QoS::reliable().keep_all(), false, "ecs");
}

#[test]
fn a_dispose_inside_a_classic_coherent_set_is_a_member_of_it() {
    a_dispose_inside_a_set_is_a_member_of_it(QoS::reliable().keep_all(), false, "next set");
}

/// A dispose of a set takes no place in the history: a set of two samples
/// and a dispose fits in a history of two. Taking one, the set did not fit,
/// and waited for a room that never came.
#[test]
fn a_dispose_inside_a_coherent_set_takes_no_place() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = probe_topic_reader::<Keyed>("dispose-no-place", qos, false);
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.subscriber.on_lifecycle_coherent(
        &net.topic,
        WRITER,
        2,
        keyed(1, 0).compute_key(),
        crate::engine::subscriber::DisposeKind::Disposed,
        Some(1),
        None,
        None,
    );
    net.deliver_coherent(WRITER, 3, 1, &keyed(3, 3));
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![keyed(1, 1), keyed(3, 3)]);
}

#[test]
fn a_dispose_inside_a_coherent_set_is_a_member_of_it_best_effort() {
    a_dispose_inside_a_set_is_a_member_of_it(QoS::best_effort().keep_all(), true, "ecs");
}

/// Multi-writer GROUP set (one publisher, writers A and B), A's part complete
/// and closed, B's sample still in flight: the reader only knows a writer is
/// part of a GROUP set once something of it lands, so A's part looks like
/// the whole set. Atomicity across the publisher's writers.
#[test]
#[ignore = "HDDS 1.4.x GROUP dialect: an idle writer sends no end and no change names the \
            writer set, so the reader cannot know another writer's part is coming; the spec \
            dialect decides it (tests_group_spec)"]
fn a_group_set_is_flushed_before_another_writers_part_lands() {
    let (net, a, b) =
        two_writer_group_reader("probe-group-early-flush", QoS::reliable().keep_all());
    group_stage(&net, a, 1, 1, 1, 11);
    group_end(&net, a, 2, 1, 1);
    let first: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    group_stage(&net, b, 1, 1, 1, 21);
    group_end(&net, b, 2, 1, 1);
    let second: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert!(
        first.is_empty() || first.len() == 2,
        "GROUP set delivered in two parts: {first:?} then {second:?}"
    );
}

/// The same race, decided: a GROUP set flushed is final. B's part of it,
/// landing after the flush, is never delivered as a second part of the set
/// (DDS v1.4 Sec.2.2.3.6) and never staged as a set no end of A closes
/// again: discarded at once, reported lost (SAMPLE_LOST, Sec.2.2.4.1, as
/// for any GROUP set discarded), once, and B's next change goes through.
#[test]
fn a_late_part_of_a_flushed_group_set_is_lost_never_a_second_part() {
    let (net, a, b) = two_writer_group_reader("probe-group-late-part", QoS::reliable().keep_all());
    group_stage(&net, a, 1, 1, 1, 11);
    group_end(&net, a, 2, 1, 1);
    let first: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(first, vec![11], "fixture: flushed on A's end alone");
    group_stage(&net, b, 1, 1, 1, 21);
    group_stage(&net, b, 1, 1, 1, 21);
    group_end(&net, b, 2, 1, 1);
    assert!(net.take_all().is_empty(), "set 1 delivered in two parts");
    assert_eq!(net.lost(), 1, "B's member, reported once");
    assert!(
        net.subscriber
            .group_coherent_buffer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "staged as a set that never closes"
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.deliver(b, 3, &Point { x: 3, y: 0 });
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let next: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(next, vec![3]);
    // A repair of A's member, delivered already: a duplicate, no loss.
    group_stage(&net, a, 1, 1, 1, 11);
    assert!(net.take_all().is_empty());
    assert_eq!(net.lost(), 1);
}

/// GROUP, best-effort reader, two writers of one publisher. Writer A's
/// set gsn 1 closes and is flushed; writer B then delivers a plain change
/// (no gsn) with a sequence number higher than a set of B staged under gsn 2:
/// discard_group_sets_behind must only discard sets with an OLDER B sample.
#[test]
fn a_best_effort_group_of_two_writers_delivers_its_sets() {
    let mut qos = QoS::best_effort().keep_all();
    qos.reliability = crate::dds::qos::Reliability::BestEffort;
    let net = NetworkReader::<Point>::with_parts(
        "probe-be-group-two",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    let a = same_publisher(1);
    let b = same_publisher(2);
    // gsn 1: a:1, b:1 ; gsn 2: a:3, b:3
    group_stage(&net, a, 1, 1, 1, 11);
    group_stage(&net, b, 1, 1, 1, 21);
    group_end(&net, a, 2, 1, 1);
    group_end(&net, b, 2, 1, 1);
    group_stage(&net, a, 3, 3, 2, 13);
    group_stage(&net, b, 3, 3, 2, 23);
    group_end(&net, a, 4, 3, 2);
    group_end(&net, b, 4, 3, 2);
    let mut got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    got.sort_unstable();
    assert_eq!(got, vec![11, 13, 21, 23], "lost {}", net.lost());
}

/// A set member received and staged, then GAPped by its writer (a KEEP_LAST
/// writer that replaced it after sending it, answering an older NACK or a
/// reordered datagram): the set is whole by what the reader holds, and
/// delivered whole. A GAP marks what the reader is not to wait for (RTPS
/// v2.5 Sec.8.4.10.4, `irrelevant_change_set`); it takes back nothing the
/// reader received.
#[test]
fn a_staged_member_then_gapped_never_leaves_its_set_partial() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net = probe_topic_reader::<Keyed>(
        "probe-staged-then-gapped",
        QoS::reliable().keep_all(),
        false,
    );
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.deliver_coherent(WRITER, 2, 1, &keyed(2, 2));
    net.subscriber.on_writer_gap(WRITER, 2, 3, Vec::new());
    net.deliver_coherent(WRITER, 3, 1, &keyed(3, 3));
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    net.deliver(WRITER, 5, &keyed(5, 5));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let got = net.take_all();
    let lost = net.lost();
    assert_eq!(
        got,
        vec![keyed(1, 1), keyed(2, 2), keyed(3, 3), keyed(5, 5)],
        "lost {lost}"
    );
    assert_eq!(lost, 0, "nothing owed was missed");
}

/// A staged member GAPped while the set waits for a change below it: the
/// gate waits for the member as for any change still to come, so the change
/// after the set is not delivered before it.
#[test]
fn a_staged_member_gapped_keeps_its_place_in_the_writers_order() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net = probe_topic_reader::<Keyed>(
        "probe-staged-gapped-order",
        QoS::reliable().keep_all(),
        false,
    );
    // Staged before the writer's first HEARTBEAT, 3 not received: two sets
    // wait for the gate, outside it.
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.deliver_coherent(WRITER, 2, 1, &keyed(2, 2));
    net.deliver_coherent(WRITER, 4, 4, &keyed(4, 4));
    net.deliver_coherent(WRITER, 5, 4, &keyed(5, 5));
    net.deliver_coherent(WRITER, 6, 6, &keyed(6, 6));
    net.subscriber.on_writer_gap(WRITER, 6, 7, Vec::new());
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    // 7, after the GAPped member's set, lands before 3, below it.
    net.deliver(WRITER, 7, &keyed(7, 7));
    net.deliver(WRITER, 3, &keyed(3, 3));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let got: Vec<i32> = net.take_all().iter().map(|s| s.id).collect();
    assert_eq!(got, vec![1, 2, 3, 4, 5, 6, 7], "lost {}", net.lost());
    assert_eq!(net.lost(), 0);
}

/// Same, the GAP lands after the set's end, while the set waits for a
/// change below it: the member it declares, received, is delivered with
/// its set; only the change never received is lost.
#[test]
fn a_member_gapped_after_its_sets_end_is_delivered_with_its_set() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net = probe_topic_reader::<Keyed>(
        "probe-staged-gapped-late",
        QoS::reliable().keep_all(),
        false,
    );
    // seq 1 lost on the way: the set cannot commit before it.
    net.deliver_coherent(WRITER, 2, 2, &keyed(2, 2));
    net.deliver_coherent(WRITER, 3, 2, &keyed(3, 3));
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    // The writer GAPs 1..=2 (1 never sent again, 2 replaced since).
    net.subscriber.on_writer_gap(WRITER, 1, 3, Vec::new());
    net.deliver(WRITER, 5, &keyed(5, 5));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let got = net.take_all();
    let lost = net.lost();
    assert_eq!(
        got,
        vec![keyed(2, 2), keyed(3, 3), keyed(5, 5)],
        "lost {lost}"
    );
    assert_eq!(lost, 1, "1, never received");
}

/// Same, the writer's HEARTBEAT not offering 1..=2 any more (firstSN 3).
#[test]
fn a_staged_member_below_the_heartbeat_first_never_leaves_its_set_partial() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net =
        probe_topic_reader::<Keyed>("probe-staged-below-hb", QoS::reliable().keep_all(), false);
    net.deliver_coherent(WRITER, 2, 2, &keyed(2, 2));
    net.deliver_coherent(WRITER, 3, 2, &keyed(3, 3));
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    net.subscriber.on_writer_heartbeat(WRITER, 3);
    net.deliver(WRITER, 5, &keyed(5, 5));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let got = net.take_all();
    let lost = net.lost();
    let ok = got == vec![keyed(2, 2), keyed(3, 3), keyed(5, 5)]
        || (got == vec![keyed(5, 5)] && lost == 2);
    assert!(ok, "got {got:?} lost {lost}");
}

/// A GAP that declares 70000 owed changes never received reports them
/// all lost, counted by ranges: a scan bound would report none of a GAP
/// longer than 65536.
#[test]
fn a_large_gap_reports_every_lost_change() {
    let p = |x: i32| Point { x, y: 0 };
    let net = ordered_reader::<Point>("big-gap-lost", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    net.subscriber
        .on_writer_gap(WRITER, 2, 2 + 70_000, Vec::new());
    assert_eq!(net.lost(), 70_000, "70000 owed, never received");
}

/// Cost probe (release build): a GAP of 65000 owed changes on the receive
/// path, then GAPs of one change each, interleaved with DATA and takes.
#[test]
#[ignore = "cost probe: run in release, compare against a base build"]
fn gap_cost_probe() {
    let p = |x: i32| Point { x, y: 0 };
    let net = ordered_reader::<Point>("gap-cost", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    let t0 = std::time::Instant::now();
    net.subscriber
        .on_writer_gap(WRITER, 2, 2 + 65_000, Vec::new());
    let e = t0.elapsed();
    eprintln!("GAP of 65000: {e:?}, lost={}", net.lost());
    // and a single-seq GAP, many times
    let t1 = std::time::Instant::now();
    for k in 0..10_000u64 {
        let s = 65_002 + 2 * k;
        net.subscriber.on_writer_gap(WRITER, s, s + 1, Vec::new());
        net.deliver(WRITER, s + 1, &p(1));
        let _ = net.take_all();
    }
    eprintln!("10000 x (GAP of 1 + DATA + take): {:?}", t1.elapsed());
}

/// A change is reported lost once, through its GAP or its set, past the
/// bound of the record of what was reported too (more than 256 disjoint
/// ranges here): dropping the lowest range reported its changes again.
#[test]
fn a_change_is_reported_lost_once_past_the_record_bound() {
    let net = coherent_reader("lost-record-bound", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    // A set 1..=600 staged with every odd member, the even ones GAPped
    // (never received, not filtered), > 256 disjoint lost ranges.
    let mut seq = 1;
    while seq <= 600 {
        net.deliver_coherent(WRITER, seq, 1, &p(1));
        seq += 2;
    }
    let mut lost_by_gaps = 0;
    for even in (2..=600).step_by(2) {
        net.subscriber
            .on_writer_gap(WRITER, even, even + 1, Vec::new());
        lost_by_gaps += 1;
    }
    let before = net.lost();
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, None, 601);
    let _ = net.take_all();
    let after = net.lost();
    assert!(before <= lost_by_gaps);
    // The set, past what a set may stage (`staging_budget`), was rejected
    // whole at its 65th member: its 300 members received are reported
    // rejected, the 300 never received lost, each once.
    assert_eq!(after, 300, "each once");
    assert_eq!(net.rejected().total_count, 300, "each once");
}

/// Cost probe (release build): a retry scheduled and run to completion,
/// back to back, on one lane.
#[test]
#[ignore = "cost probe: run in release"]
fn lane_cost_probe() {
    use super::admission::retries;
    let lane = Arc::new(retries::Lane::default());
    let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = Arc::clone(&runs);
    let retry: super::admission::Retry = Arc::new(move || {
        counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    let n = 2000;
    let t0 = std::time::Instant::now();
    for i in 0..n {
        retries::schedule(&lane, Arc::clone(&retry));
        while runs.load(std::sync::atomic::Ordering::SeqCst) <= i {
            std::hint::spin_loop();
        }
    }
    let e = t0.elapsed();
    eprintln!(
        "lane: {n} schedules each to completion: {e:?} ({:?} each)",
        e / n as u32
    );
    let t1 = std::time::Instant::now();
    for _ in 0..n {
        retries::schedule(&lane, Arc::clone(&retry));
    }
    eprintln!(
        "lane: {n} schedules back to back, caller side: {:?}",
        t1.elapsed()
    );
}

/// A departed writer's DATA landing late, on a durable reliable reader
/// (gate seeded by HEARTBEAT), with a hole below it: dropped, holding no
/// place, however late it lands, until the writer is matched again.
#[test]
fn late_data_of_a_departed_writer_holds_no_place_durable() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = NetworkReader::<Point>::with_parts(
        "departed-late-durable",
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig::default(),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)]);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.deliver(WRITER, 3, &p(3));
    let _ = net.take_all();
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(
        room.taken(),
        0,
        "a departed writer's late DATA holds a place"
    );
}

/// Same, a late member of a set: not staged under a set nothing will ever
/// close.
#[test]
fn a_late_set_member_of_a_departed_writer_holds_no_place() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = coherent_reader("departed-late-member", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)]);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.deliver_coherent(WRITER, 2, 2, &p(2));
    let _ = net.take_all();
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(
        room.taken(),
        0,
        "a departed writer's late set member holds a place"
    );
}

/// A volatile reliable reader: a retransmitted copy of a change delivered
/// already, landing late after its writer's departure, is not delivered
/// twice.
#[test]
fn a_late_copy_from_a_departed_writer_is_not_delivered_twice() {
    let net = NetworkReader::<Point>::with_gate(
        "departed-late-copy",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, true),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    assert_eq!(net.take_all(), vec![p(1), p(2)]);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![], "a late copy delivered again");
}

/// `WRITER` leaves, then comes back: matched again, announced again, its
/// first HEARTBEAT announcing 1..=`last`.
fn depart_and_come_back(net: &NetworkReader<Point>, last: u64) {
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, last);
}

/// Samples the gate held above a hole at the departure were received, never
/// delivered: the departure throws them away and takes them back from the
/// record it keeps. The same writer comes back and sends the hole and them
/// again: they are delivered. Kept as received, they were dropped as
/// duplicates, acknowledged, lost without a report.
#[test]
fn samples_held_at_a_departure_are_delivered_when_the_writer_returns() {
    let net = ordered_reader::<Point>("returned-held", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 3, &p(3));
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(1)]);
    depart_and_come_back(&net, 4);
    for sn in 1..=4 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, vec![2, 3, 4], "held samples silently lost");
}

/// Same, volatile reliable reader.
#[test]
fn samples_held_at_a_departure_are_delivered_when_the_writer_returns_volatile() {
    let net = NetworkReader::<Point>::with_gate(
        "returned-held-volatile",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, true),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 3, &p(3));
    net.deliver(WRITER, 4, &p(4));
    let first: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    depart_and_come_back(&net, 4);
    for sn in 2..=4 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    let mut all = first;
    all.extend(got);
    assert_eq!(all, vec![1, 2, 3, 4], "held samples silently lost");
}

/// A coherent set staged (open) at the departure is thrown away with it, and
/// taken back from the record it keeps: the same writer comes back, sends
/// the set again and closes it, and it is delivered. Kept as received, the
/// set's samples were dropped as duplicates, acknowledged, and the reader
/// delivered nothing more, its gate holding the writer's later samples.
#[test]
fn a_set_staged_at_a_departure_is_delivered_when_the_writer_returns() {
    let net = coherent_reader("returned-staged", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    assert_eq!(net.take_all(), vec![]);
    depart_and_come_back(&net, 2);
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, None, 3);
    net.deliver(WRITER, 4, &p(4));
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, vec![1, 2, 4], "staged set silently lost");
}

/// Residual limit, FOREIGN peers only: a new writer under the GUID of one
/// that left, which wrote past the old one's highest sequence before its
/// first HEARTBEAT reaches the reader, is taken for the same writer
/// (`heartbeat_verdict`): its samples numbered like those the old one
/// delivered are taken for copies. RTPS gives the reader nothing else to
/// tell them apart by, and RTPS v2.5 Sec.8.2.4.1 forbids the reuse: a
/// GUID uniquely identifies its entity. An HDDS peer never reuses one
/// (`entity_registry::generate_guid`, and
/// `a_recreated_hdds_writer_is_a_new_writer` below); a stack that derives
/// its prefix deterministically (host + PID, say) still can.
#[test]
#[ignore = "residual limit, foreign stacks reusing a GUID: a new writer past the old one's highest is taken for it"]
fn a_new_writer_past_the_old_ones_highest_is_taken_for_it() {
    let net = ordered_reader::<Point>("recreated-past-high", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    for sn in 1..=3 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all().len(), 3);
    depart_and_come_back(&net, 5);
    for sn in 1..=5u64 {
        net.deliver(WRITER, sn, &p(100 + i32::try_from(sn).unwrap()));
    }
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, vec![101, 102, 103, 104, 105]);
}

/// The same scenario from an HDDS peer: the writer recreated in the
/// recreated participant carries a NEW GUID prefix (the entity id, counted
/// from zero again, is the same), so the reader meets a new writer and
/// delivers every sample it sends, those numbered like the old writer's
/// included.
#[test]
fn a_recreated_hdds_writer_is_a_new_writer() {
    let net = ordered_reader::<Point>("recreated-new-guid", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    let mut recreated = WRITER;
    recreated[6..12].copy_from_slice(&[0x5E; 6]);
    for sn in 1..=3 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all().len(), 3);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.credit.match_writer(recreated);
    net.subscriber.on_writer_qos_resolved(recreated);
    net.subscriber.on_writer_heartbeat_range(recreated, 1, 5);
    for sn in 1..=5u64 {
        net.deliver(recreated, sn, &p(100 + i32::try_from(sn).unwrap()));
    }
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, vec![101, 102, 103, 104, 105]);
}

/// Cost probe (release): DATA of a live writer while another writer has
/// departed (never announced again), within `DEPARTED_KEEP` and after it.
#[test]
#[ignore = "cost probe: release"]
fn departed_writer_cost_probe() {
    let p = |x: i32| Point { x, y: 0 };
    let n: u64 = 200_000;
    for mode in ["none", "kept", "forgotten"] {
        let net = NetworkReader::<Point>::with_gate(
            "departed-cost",
            QoS::best_effort().keep_last(1),
            super::reorder::ReorderGate::new_best_effort(),
        );
        if mode != "none" {
            if mode == "forgotten" {
                net.subscriber
                    .set_departed_keep_for_test(std::time::Duration::from_millis(1));
            }
            net.subscriber.on_writer_dispose(
                &net.topic,
                WRITER_B,
                crate::engine::subscriber::DisposeKind::Unregistered,
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let bytes = encoded(&p(1));
        let t0 = std::time::Instant::now();
        for sn in 1..=n {
            net.subscriber.on_data_with_writer(
                &net.topic,
                WRITER,
                sn,
                &bytes,
                crate::dds::CdrVersion::Xcdr2,
            );
        }
        let e = t0.elapsed();
        let _ = net.take_all();
        eprintln!(
            "departed writer {mode}: {:?}/sample",
            e / u32::try_from(n).unwrap()
        );
    }
}

/// The same writer back steps its new gate over what it delivered before
/// it left (the history still holds it, untaken): the copies it sends
/// again are duplicates, and its gate does not wait for them. Waiting, it
/// held the writer's later samples above them, and with the history full
/// refused them for good.
#[test]
fn a_returned_writers_gate_steps_over_what_it_delivered() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let net = ordered_reader::<Point>("returned-steps", qos);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 2, &p(2));
    depart_and_come_back(&net, 4);
    for sn in 1..=4 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all(), vec![p(1), p(2)]);
    for sn in 3..=4 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all(), vec![p(3), p(4)]);
}

/// A VOLATILE reliable reader: the same writer back, its new gate is
/// stepped over what it delivered before the door opens, so the first DATA
/// landing once it is open (here 16, at the moment it opens) does not
/// become where the reader joined: what the writer wrote while taken for
/// departed (11..=15) is still owed, and delivered. Stepped after, the
/// gate took 16 for the join point and dropped 11..=15 as history from
/// before it.
#[test]
fn a_returned_writers_changes_written_meanwhile_reach_a_volatile_reader() {
    let net = NetworkReader::<Point>::with_gate(
        "returned-volatile-meanwhile",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, true),
    );
    let p = |x: i32| Point { x, y: 0 };
    for sn in 1..=10 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all().len(), 10);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    let subscriber = Arc::clone(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .opened_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        use crate::engine::Subscriber;
        subscriber.on_data_with_writer(
            &topic,
            WRITER,
            16,
            &encoded(&Point { x: 16, y: 0 }),
            crate::dds::CdrVersion::Xcdr2,
        );
    }));
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 16);
    for sn in 11..=15 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, (11..=16).collect::<Vec<i32>>());
}

/// A GROUP set its writer's departure discarded (reported lost: its staged
/// sample 1) stays discarded when the writer comes back: what lands of it
/// then is stepped over, and reported lost if its discard did not report
/// it (2, in flight at the departure), but not twice (1, sent again). The
/// writer's later changes are delivered. Stepped over silently, 2 was lost
/// without a report.
#[test]
fn a_discarded_group_sets_late_parts_are_reported_lost_once() {
    let net = group_reader("returned-group");
    stage_in_group(&net, 1, 1, 1);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    assert_eq!(net.lost(), 1);
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 4);
    stage_in_group(&net, 1, 1, 1);
    stage_in_group(&net, 2, 1, 1);
    end_group(&net, 3, 2, 1);
    assert_eq!(net.lost(), 2, "2 reported, 1 not twice");
    stage_in_group(&net, 4, 4, 2);
    end_group(&net, 5, 4, 2);
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, vec![4]);
}

/// The same, followed further: the writer's later samples are delivered,
/// nothing holds a place, nothing is reported lost, the acknowledgement
/// names only what the reader has.
#[test]
fn a_writer_back_after_its_set_was_staged_goes_on() {
    let net = coherent_reader("returned-staged-goes-on", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    assert_eq!(net.take_all(), vec![]);
    depart_and_come_back(&net, 2);
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    net.subscriber
        .on_coherent_end_marker(&net.topic, WRITER, None, None, 1, None, 3);
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(1), p(2), p(4)]);
    for sn in 5..=8 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 8);
    assert_eq!(net.take_all(), vec![p(5), p(6), p(7), p(8)]);
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(room.taken(), 0);
    assert_eq!(net.lost(), 0);
    assert_eq!(net.acknowledged(8, 8), (9, Vec::new()));
}

/// A departure is forgotten after `DEPARTED_KEEP` (shortened here): the
/// door's fast path comes back (no departure left), and what lands from
/// the writer that left for good still holds no place: a reliable reader
/// holds a sample only for a writer it is matched with, so it refuses it,
/// unacknowledged, rather than hold a place for a HEARTBEAT that never
/// comes. Kept for good, one writer that left put every DATA of every
/// writer on the door's slow path.
#[test]
fn a_departure_is_forgotten_and_a_late_data_still_holds_no_place() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = NetworkReader::<Point>::with_parts(
        "departure-forgotten",
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig::default(),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.subscriber
        .set_departed_keep_for_test(std::time::Duration::from_millis(20));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    net.subscriber.on_writer_heartbeat(WRITER_B, 1);
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)]);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    assert_eq!(net.subscriber.departed_count_for_test(), 1);
    std::thread::sleep(std::time::Duration::from_millis(40));
    // Another writer's DATA: the expired departure goes.
    net.deliver(WRITER_B, 1, &p(21));
    assert_eq!(
        net.subscriber.departed_count_for_test(),
        0,
        "the fast path is back"
    );
    net.deliver(WRITER, 3, &p(3));
    assert_eq!(net.take_all(), vec![p(21)]);
    let room = net.reader.network_room_for_test().expect("room");
    assert_eq!(
        room.taken(),
        0,
        "a late DATA of a forgotten writer holds a place"
    );
}

/// The record of a writer back after a false departure goes back before
/// the door opens: a DATA landing in between (here a copy of a change
/// delivered already, at the pause) is dropped at the door. Opened first,
/// the copy was admitted into a fresh record, delivered again, and the
/// record put back after it forgot the admission.
#[test]
fn a_copy_landing_while_a_writer_comes_back_is_not_delivered_twice() {
    let net = ordered_reader::<Point>("verdict-order", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    for sn in 1..=3 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all().len(), 3);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.credit.match_writer(WRITER);
    let subscriber = Arc::clone(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .verdict_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        use crate::engine::Subscriber;
        subscriber.on_data_with_writer(
            &topic,
            WRITER,
            2,
            &encoded(&Point { x: 2, y: 0 }),
            crate::dds::CdrVersion::Xcdr2,
        );
    }));
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 4);
    for sn in 1..=4 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all(), vec![p(4)], "nothing twice");
}

/// A DATA that passed the door before its writer left, and takes the gate
/// after the departure (here at the pause), is dropped, unacknowledged: the
/// departure took the writer's record and gate in a section of the gate's
/// lock, and the DATA finds the door shut under it. Admitted, it opened a
/// fresh record the departure never saw, reached the application after its
/// writer's departure, and once the same writer came back (its record put
/// back over the fresh one) was delivered again.
#[test]
fn a_data_in_flight_at_a_departure_is_delivered_once() {
    // VOLATILE: a fresh gate passes its first DATA straight on.
    let net = NetworkReader::<Point>::with_gate(
        "departure-in-flight",
        QoS::reliable().keep_all(),
        super::reorder::ReorderGate::new(true, true),
    );
    let p = |x: i32| Point { x, y: 0 };
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)]);
    let subscriber = Arc::clone(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .admission_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        use crate::engine::Subscriber;
        subscriber.on_writer_dispose(
            &topic,
            WRITER,
            crate::engine::subscriber::DisposeKind::Unregistered,
        );
    }));
    net.deliver(WRITER, 2, &p(2));
    assert_eq!(net.take_all(), vec![], "after its writer left");
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 2);
    for sn in 1..=2 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all(), vec![p(2)], "once, after it came back");
}

/// Same, a coherent change in flight, its writer deleted: admitted after
/// the departure, it would be staged under a fresh record the departure
/// never saw, and the new writer under the GUID would have its own change
/// of that sequence number dropped as a duplicate, the old writer's sample
/// delivered in its place.
#[test]
fn a_coherent_change_in_flight_at_a_departure_is_not_the_new_writers() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net = probe_topic_reader::<Keyed>(
        "departure-in-flight-coherent",
        QoS::reliable().keep_all(),
        false,
    );
    let subscriber = Arc::clone(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .admission_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        use crate::engine::Subscriber;
        subscriber.on_writer_departure(
            &topic,
            WRITER,
            crate::engine::subscriber::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
    }));
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    // A new writer under the GUID.
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 2);
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 100));
    net.subscriber.on_ecs(&net.topic, WRITER, 2, 1, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![keyed(1, 100)], "lost {}", net.lost());
}

/// Two HEARTBEATs of a writer back after a false departure, on two
/// threads: the second, landing while the first puts the record back (at
/// the pause), is dropped and opens nothing. Opening the door before the
/// record is back would admit a copy landing then (2, delivered already)
/// into a fresh record, deliver it again, and the record put back after
/// would forget the admission.
#[test]
fn a_second_heartbeat_does_not_open_the_door_before_the_record_is_back() {
    let net = ordered_reader::<Point>("verdict-two-heartbeats", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    for sn in 1..=3 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all().len(), 3);
    net.subscriber.on_writer_dispose(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
    );
    net.credit.match_writer(WRITER);
    let subscriber = Arc::clone(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .verdict_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        use crate::engine::Subscriber;
        subscriber.on_writer_heartbeat_range(WRITER, 1, 4);
        subscriber.on_data_with_writer(
            &topic,
            WRITER,
            2,
            &encoded(&Point { x: 2, y: 0 }),
            crate::dds::CdrVersion::Xcdr2,
        );
    }));
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 4);
    for sn in 1..=4 {
        net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all(), vec![p(4)], "nothing twice");
}

/// A writer that said it left (its SEDP dispose, its participant's) is
/// deleted: a writer seen again under its GUID is a new one, and every
/// change it sends is delivered, whatever its first HEARTBEAT says. Its
/// record must not be kept as for a writer that fell silent: a new writer
/// whose first HEARTBEAT reached the old one's highest would have its
/// changes up to it dropped as delivered, acknowledged, lost without a
/// report.
#[test]
fn a_writer_that_announced_its_departure_is_new_when_seen_again() {
    let p = |x: i32| Point { x, y: 0 };
    for (cause, expected) in [
        (
            crate::engine::WriterDeparture::Deleted,
            vec![p(11), p(12), p(13), p(14)],
        ),
        (crate::engine::WriterDeparture::Unheard, vec![p(14)]),
    ] {
        let net = ordered_reader::<Point>("announced-departure", QoS::reliable().keep_all());
        for sn in 1..=3 {
            net.deliver(WRITER, sn, &p(i32::try_from(sn).unwrap()));
        }
        assert_eq!(net.take_all().len(), 3);
        net.subscriber.on_writer_departure(
            &net.topic,
            WRITER,
            crate::engine::subscriber::DisposeKind::Unregistered,
            cause,
        );
        net.credit.match_writer(WRITER);
        net.subscriber.on_writer_qos_resolved(WRITER);
        net.subscriber.on_writer_heartbeat_range(WRITER, 1, 4);
        for sn in 1..=4 {
            net.deliver(WRITER, sn, &p(10 + i32::try_from(sn).unwrap()));
        }
        assert_eq!(net.take_all(), expected, "{cause:?}");
    }
}

/// DDS v1.4 Sec.2.2.3.19, max_samples, KEEP_LAST: the history keeps at most
/// `max_samples` samples across its instances. A newer sample of an
/// instance holding `depth` replaces its oldest and grows nothing; a sample
/// that would grow the history past `max_samples` is rejected as
/// REJECTED_BY_SAMPLES_LIMIT and, RELIABLE, not acknowledged. Taking makes
/// room again. The bound applies on KEEP_LAST too.
#[test]
fn keep_last_bounds_its_samples_across_instances() {
    let mut qos = QoS::reliable().keep_last(2);
    qos.resource_limits.max_samples = 3;
    let net = NetworkReader::<Keyed>::new("limits-keep-last-max-samples", qos);
    net.deliver(WRITER, 1, &keyed(1, 1));
    net.deliver(WRITER, 2, &keyed(1, 2));
    net.deliver(WRITER, 3, &keyed(2, 1));
    assert_eq!(net.rejected().total_count, 0, "three kept");
    net.deliver(WRITER, 4, &keyed(2, 2));
    let status = net.rejected();
    assert_eq!(status.total_count, 1, "a fourth would grow the history");
    assert_eq!(status.last_reason, SampleRejectedReason::ResourceLimit);
    assert_eq!(status.last_instance_handle, Some(handle_of(2)));
    assert_eq!(net.acknowledged(4, 1), (4, vec![4]), "4 is asked again");
    net.deliver(WRITER, 5, &keyed(1, 3));
    assert_eq!(net.rejected().total_count, 1, "a replacing sample has room");
    assert_eq!(
        net.take_all(),
        vec![keyed(1, 2), keyed(2, 1), keyed(1, 3)],
        "instance 1 keeps its two newest, instance 2 its one"
    );
    net.deliver(WRITER, 4, &keyed(2, 2));
    assert_eq!(net.rejected().total_count, 1, "taken: room again");
    assert_eq!(net.take_all(), vec![keyed(2, 2)]);
}

/// DDS v1.4 Sec.2.2.3.18, KEEP_ALL: "If the limit is reached, then the
/// behavior of the Service will depend on the RELIABILITY QoS. If the
/// reliability kind is BEST_EFFORT, then the old values will be
/// discarded." A BEST_EFFORT KEEP_ALL reader at `max_samples` keeps the
/// newest samples and rejects none (it does not reject the newest).
#[test]
fn best_effort_keep_all_discards_the_old_values_at_max_samples() {
    let mut qos = QoS::best_effort().keep_all();
    qos.resource_limits.max_samples = 3;
    let net = NetworkReader::<Keyed>::new("limits-be-keep-all-old", qos);
    for value in 1..=5 {
        net.deliver(
            WRITER,
            u64::try_from(value).expect("positive"),
            &keyed(1, value),
        );
    }
    assert_eq!(net.take_all(), vec![keyed(1, 3), keyed(1, 4), keyed(1, 5)]);
    assert_eq!(net.rejected().total_count, 0);
}

/// The same per instance (`max_samples_per_instance`), and past the
/// reader's network ring: the old values go, the newest stay.
#[test]
fn best_effort_keep_all_discards_the_old_values_of_an_instance_and_past_its_ring() {
    let mut qos = QoS::best_effort().keep_all();
    qos.resource_limits.max_samples = 5;
    qos.resource_limits.max_samples_per_instance = 2;
    let net = NetworkReader::<Keyed>::new("limits-be-keep-all-ring", qos);
    let mut seq = 0u64;
    let mut deliver = |id: i32, value: i32| {
        seq += 1;
        net.deliver(WRITER, seq, &keyed(id, value));
    };
    deliver(2, 1);
    for value in 1..=3000 {
        deliver(1, value);
    }
    assert_eq!(
        net.take_all(),
        vec![keyed(2, 1), keyed(1, 2999), keyed(1, 3000)],
        "instance 2 keeps its only value, instance 1 its two newest"
    );
    assert_eq!(net.rejected().total_count, 0);
}

/// Past its network ring with no per-instance bound: nothing is replaced,
/// the oldest samples are discarded, the newest `max_samples` stay.
#[test]
fn best_effort_keep_all_discards_its_oldest_past_its_ring() {
    let mut qos = QoS::best_effort().keep_all();
    qos.resource_limits.max_samples = 5;
    let net = NetworkReader::<Keyed>::new("limits-be-keep-all-oldest", qos);
    for value in 1..=3000 {
        net.deliver(
            WRITER,
            u64::try_from(value).expect("positive"),
            &keyed(value % 7, value),
        );
    }
    let taken: Vec<i32> = net.take_all().iter().map(|k| k.value).collect();
    assert_eq!(taken, (2996..=3000).collect::<Vec<_>>());
    assert_eq!(net.rejected().total_count, 0);
}

/// A set member of a writer that said it left, stepped over after its
/// departure (a late part of a discarded set): no gate and no record are
/// opened again for the old writer. Opened, the new writer under the GUID
/// would find the old one's step in its gate and its report in its record:
/// its own change 2 would be taken for the old one's, never delivered.
#[test]
fn a_late_step_of_a_deleted_writer_leaves_nothing_for_the_new_one() {
    let p = |x: i32| Point { x, y: 0 };
    let net = ordered_reader::<Point>("late-step-deleted", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)]);
    net.subscriber.on_writer_departure(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    net.subscriber.step_gate_over_staged_for_test(WRITER, 2);
    net.subscriber.note_reported_for_test(WRITER, 3);
    let lost = net.lost();
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 3);
    for sn in 1..=3 {
        net.deliver(WRITER, sn, &p(10 + i32::try_from(sn).unwrap()));
    }
    assert_eq!(net.take_all(), vec![p(11), p(12), p(13)]);
    assert_eq!(net.lost(), lost, "nothing of the new writer lost");
}

/// Same, the new writer losing the changes the old one's late step and
/// report named: both are reported lost. A record opened for the old
/// writer would take them for reported already.
#[test]
fn a_late_report_of_a_deleted_writer_hides_no_loss_of_the_new_one() {
    let p = |x: i32| Point { x, y: 0 };
    let net = ordered_reader::<Point>("late-report-deleted", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    assert_eq!(net.take_all(), vec![p(1)]);
    net.subscriber.on_writer_departure(
        &net.topic,
        WRITER,
        crate::engine::subscriber::DisposeKind::Unregistered,
        crate::engine::WriterDeparture::Deleted,
    );
    net.subscriber.note_reported_for_test(WRITER, 2);
    net.subscriber.step_gate_over_staged_for_test(WRITER, 3);
    let lost = net.lost();
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 4);
    net.deliver(WRITER, 1, &p(11));
    net.subscriber.on_writer_gap(WRITER, 2, 4, Vec::new());
    net.deliver(WRITER, 4, &p(14));
    assert_eq!(net.take_all(), vec![p(11), p(14)]);
    assert_eq!(net.lost(), lost + 2, "2 and 3 of the new writer lost");
}

/// Same as a classic set rejected whole, under GROUP scope: the group set
/// reports its samples rejected, not its dispose.
#[test]
fn a_rejected_group_set_does_not_report_its_dispose_as_a_sample() {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 1;
    let net = NetworkReader::<Point>::with_parts(
        "group-rejected-dispose",
        qos,
        super::reorder::ReorderGate::new(true, false),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
    );
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    stage_in_group(&net, 1, 1, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    net.subscriber.on_lifecycle_coherent(
        &net.topic,
        WRITER,
        2,
        [0x11; 16],
        crate::engine::subscriber::DisposeKind::Disposed,
        Some(1),
        Some(1),
        Some([0, 0, 1, 8]),
    );
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    stage_in_group(&net, 3, 1, 1);
    end_group(&net, 4, 3, 1);
    assert_eq!(net.take_all(), vec![]);
    assert_eq!(
        net.rejected().total_count,
        2,
        "two samples rejected, not three"
    );
}

/// Two departures, the first expiring first: the door forgets it when it
/// is due, and the second when that one is, each once, without looking at
/// the others on every DATA in between. The fast path is back after the
/// second.
#[test]
fn departures_are_forgotten_each_when_due() {
    let net = ordered_reader::<Point>("departures-due", QoS::reliable().keep_all());
    let p = |x: i32| Point { x, y: 0 };
    let third = [0x7C; 16];
    net.subscriber
        .set_departed_keep_for_test(std::time::Duration::from_millis(300));
    let depart = |writer: [u8; 16]| {
        net.subscriber.on_writer_dispose(
            &net.topic,
            writer,
            crate::engine::subscriber::DisposeKind::Unregistered,
        );
    };
    depart(WRITER);
    std::thread::sleep(std::time::Duration::from_millis(200));
    depart(WRITER_B);
    assert_eq!(net.subscriber.departed_count_for_test(), 2);
    std::thread::sleep(std::time::Duration::from_millis(150));
    // A third writer's DATA: the first departure is due, not the second.
    net.subscriber.on_writer_heartbeat(third, 1);
    net.deliver(third, 1, &p(1));
    assert_eq!(
        net.subscriber.departed_count_for_test(),
        1,
        "the first went"
    );
    std::thread::sleep(std::time::Duration::from_millis(200));
    net.deliver(third, 2, &p(2));
    assert_eq!(
        net.subscriber.departed_count_for_test(),
        0,
        "the second went"
    );
    assert_eq!(net.take_all(), vec![p(1), p(2)]);
}

/// A coherent set rejected whole (it can never fit) reports each of its
/// SAMPLES rejected; its dispose is not a sample and takes no place.
#[test]
fn a_rejected_set_does_not_report_its_dispose_as_a_sample() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 1;
    let net = probe_topic_reader::<Keyed>("probe-rejected-dispose", qos, false);
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.subscriber.on_lifecycle_coherent(
        &net.topic,
        WRITER,
        2,
        keyed(1, 0).compute_key(),
        crate::engine::subscriber::DisposeKind::Disposed,
        Some(1),
        None,
        None,
    );
    net.deliver_coherent(WRITER, 3, 1, &keyed(3, 3));
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![]);
    assert_eq!(
        net.rejected().total_count,
        2,
        "two samples rejected, not three"
    );
}

/// A coherent change admitted before its writer said it left, and pushed
/// into the staging after the departure drained it (at the pause): never
/// staged. A new writer under the GUID then sends its own change 1, which
/// is delivered; had it been staged, the old writer's sample would be
/// delivered in its place.
#[test]
fn a_change_staged_after_a_deleted_writers_departure_is_not_the_new_writers() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net =
        probe_topic_reader::<Keyed>("probe-window-deleted", QoS::reliable().keep_all(), false);
    let subscriber = Arc::clone(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .staging_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        use crate::engine::Subscriber;
        subscriber.on_writer_departure(
            &topic,
            WRITER,
            crate::engine::subscriber::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
    }));
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 2);
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 100));
    net.subscriber.on_ecs(&net.topic, WRITER, 2, 1, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![keyed(1, 100)], "lost {}", net.lost());
}

/// Same, the writer unheard (it comes back as the same writer): its parked
/// record says 1 was received, and the staged copy is the one delivered.
#[test]
fn a_change_staged_after_an_unheard_writers_departure_is_delivered_on_return() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net =
        probe_topic_reader::<Keyed>("probe-window-unheard", QoS::reliable().keep_all(), false);
    let subscriber = Arc::clone(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .staging_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Box::new(move || {
        use crate::engine::Subscriber;
        subscriber.on_writer_departure(
            &topic,
            WRITER,
            crate::engine::subscriber::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Unheard,
        );
    }));
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.credit.match_writer(WRITER);
    net.subscriber.on_writer_qos_resolved(WRITER);
    net.subscriber.on_writer_heartbeat_range(WRITER, 1, 3);
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.deliver_coherent(WRITER, 2, 1, &keyed(2, 2));
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    net.deliver(WRITER, 4, &keyed(4, 4));
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(
        net.take_all(),
        vec![keyed(1, 1), keyed(2, 2), keyed(4, 4)],
        "lost {}",
        net.lost()
    );
}

/// A staged member kept by a GAP whose set is then broken by the same GAP
/// (a member never received): the set is discarded, the gate steps over
/// the kept member, and the writer's next change is delivered (no stall).
#[test]
fn a_kept_member_of_a_broken_set_does_not_stall_the_gate() {
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    let net = probe_topic_reader::<Keyed>("probe-kept-broken", QoS::reliable().keep_all(), false);
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.deliver_coherent(WRITER, 2, 1, &keyed(2, 2));
    net.subscriber.on_writer_gap(WRITER, 2, 4, Vec::new());
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    net.deliver(WRITER, 5, &keyed(5, 5));
    net.subscriber.on_writer_heartbeat(WRITER, 1);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(net.take_all(), vec![keyed(5, 5)], "lost {}", net.lost());
}

/// Best-effort: a set holding a dispose, a member lost: the set is
/// discarded with its dispose; the instance never moves.
#[test]
fn a_best_effort_discarded_set_discards_its_dispose() {
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let net = probe_topic_reader::<Keyed>(
        "probe-be-discard-dispose",
        QoS::best_effort().keep_all(),
        true,
    );
    let key = keyed(1, 0).compute_key();
    net.deliver_coherent(WRITER, 1, 1, &keyed(1, 1));
    net.subscriber.on_lifecycle_coherent(
        &net.topic,
        WRITER,
        2,
        key,
        crate::engine::subscriber::DisposeKind::Disposed,
        Some(1),
        None,
        None,
    );
    // 3 lost; the next set starts at 4 and closes set 1.
    net.deliver_coherent(WRITER, 4, 4, &keyed(4, 4));
    net.deliver(WRITER, 5, &keyed(5, 5));
    #[allow(deprecated)]
    let events = net.reader.get_dispose_events();
    assert!(
        events.is_empty(),
        "dispose of a discarded set applied: {events:?}"
    );
    assert_eq!(
        net.take_all(),
        vec![keyed(4, 4), keyed(5, 5)],
        "lost {}",
        net.lost()
    );
}

/// A best-effort coherent reader (`group` scope or not).
fn best_effort_coherent_reader(topic: &str, group: bool) -> NetworkReader<Point> {
    NetworkReader::<Point>::with_parts(
        topic,
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: group,
        },
    )
}

/// RTPS v2.5 Sec.8.4.12.1 T2 applies to the sample-less END DATA
/// (Sec.8.7.6). Its missing older member is permanently passed; the
/// incomplete set is discarded and a late member cannot repair it.
#[test]
fn a_best_effort_set_is_lost_when_its_end_passes_a_member() {
    let net = best_effort_coherent_reader("be-end-overtakes", false);
    let p = |x: i32| Point { x, y: 0 };
    net.deliver_coherent(WRITER, 1, 1, &p(1));
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    assert!(
        net.take_all().is_empty(),
        "the set cannot be delivered in part"
    );
    assert_eq!(net.lost(), 2, "one missing and one staged member");
    net.deliver_coherent(WRITER, 2, 1, &p(2));
    assert!(
        net.take_all().is_empty(),
        "late DATA cannot repair BEST_EFFORT"
    );
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    net.subscriber.on_writer_gap(WRITER, 1, 4, Vec::new());
    net.subscriber.retry_waiting_sets();
    assert_eq!(
        net.lost(),
        2,
        "duplicate END, GAP and retry count neither SN again"
    );
}

/// An END that passes every member of a later set reports those missing
/// changes once, without affecting the complete earlier set.
#[test]
fn a_best_effort_set_is_lost_when_its_end_passes_every_member() {
    let net = best_effort_coherent_reader("be-end-overtakes-all", false);
    let p = |x: i32| Point { x, y: 0 };
    for seq in 1..=3 {
        net.deliver_coherent(WRITER, seq, 1, &p(i32::try_from(seq).expect("small")));
    }
    net.subscriber.on_ecs(&net.topic, WRITER, 4, 3, None, None);
    assert_eq!(net.take_all(), vec![p(1), p(2), p(3)], "the first set");
    net.subscriber.on_ecs(&net.topic, WRITER, 8, 7, None, None);
    assert!(net.take_all().is_empty());
    assert_eq!(net.lost(), 3, "the absent SN5 through SN7");
    for seq in 5..=7 {
        net.deliver_coherent(WRITER, seq, 5, &p(i32::try_from(seq).expect("small")));
    }
    assert!(net.take_all().is_empty());
    assert_eq!(
        net.lost(),
        3,
        "late members never subtract or repeat losses"
    );
}

/// The same T2 and coherent completeness rules apply to a GROUP set.
#[test]
fn a_best_effort_group_set_is_lost_when_its_end_passes_a_member() {
    let net = best_effort_coherent_reader("be-group-end-overtakes", true);
    stage_in_group(&net, 1, 1, 1);
    end_group(&net, 3, 2, 1);
    assert!(net.take_all().is_empty());
    assert_eq!(net.lost(), 2, "one missing and one staged member");
    stage_in_group(&net, 2, 1, 1);
    assert!(net.take_all().is_empty());
    end_group(&net, 3, 2, 1);
    net.subscriber.on_writer_gap(WRITER, 1, 4, Vec::new());
    net.subscriber.retry_waiting_sets();
    assert_eq!(
        net.lost(),
        2,
        "duplicate END, GAP and retry count neither SN again"
    );
}

/// A reliable END does not apply BEST_EFFORT T2: a delayed member remains
/// repairable, and the complete set is delivered together once it lands.
#[test]
fn a_reliable_set_waits_for_a_member_its_end_overtook() {
    for group in [false, true] {
        let net = NetworkReader::<Point>::with_parts(
            "reliable-end-overtakes",
            QoS::reliable().keep_all(),
            super::reorder::ReorderGate::new(true, false),
            crate::qos::ownership::OwnershipKind::default(),
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: group,
            },
        );
        net.subscriber.on_writer_heartbeat(WRITER, 1);
        let p = |x: i32| Point { x, y: 0 };
        if group {
            stage_in_group(&net, 1, 1, 1);
            end_group(&net, 3, 2, 1);
        } else {
            net.deliver_coherent(WRITER, 1, 1, &p(1));
            net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
        }
        assert!(net.take_all().is_empty());
        assert_eq!(net.lost(), 0);
        if group {
            stage_in_group(&net, 2, 1, 1);
        } else {
            net.deliver_coherent(WRITER, 2, 1, &p(2));
        }
        assert_eq!(net.take_all(), vec![p(1), p(2)]);
        assert_eq!(net.lost(), 0);
    }
}

/// A member a best-effort reader has passed for good (a later change of
/// the writer arrived) is lost: the set is lost whole, as before, once the
/// gate is past it, by its end or by any later change.
#[test]
fn a_best_effort_set_whose_member_was_passed_is_lost() {
    let net = best_effort_coherent_reader("be-member-passed", true);
    let p = |x: i32| Point { x, y: 0 };
    stage_in_group(&net, 1, 1, 1);
    end_group(&net, 3, 2, 1);
    net.deliver(WRITER, 4, &p(4));
    assert_eq!(net.take_all(), vec![p(4)]);
    assert_eq!(net.lost(), 2, "the set's two samples");
}

/// Once END advances T2, no timer or later traffic is required to
/// discard an incomplete BEST_EFFORT coherent set and report its members.
#[test]
fn a_best_effort_set_whose_end_passes_a_member_is_lost_without_a_timer() {
    for group in [false, true] {
        let net = best_effort_coherent_reader("be-member-never-comes", group);
        net.subscriber
            .best_effort_wait_ms
            .store(60_000, std::sync::atomic::Ordering::Relaxed);
        if group {
            stage_in_group(&net, 1, 1, 1);
            end_group(&net, 3, 2, 1);
        } else {
            net.deliver_coherent(WRITER, 1, 1, &Point { x: 1, y: 0 });
            net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
        }
        assert_eq!(
            net.lost(),
            2,
            "group {group}: the set is already incomplete"
        );
        net.subscriber.retry_waiting_sets();
        assert_eq!(net.lost(), 2, "the retry never repeats the loss");
        assert!(net.take_all().is_empty());
    }
}

/// A best-effort set waiting for a member is lost when its writer leaves,
/// reported: the reader never gets it back.
#[test]
fn a_best_effort_set_waiting_when_its_writer_leaves_is_reported_lost() {
    for group in [false, true] {
        let net = best_effort_coherent_reader("be-waiting-departure", group);
        net.subscriber
            .best_effort_wait_ms
            .store(60_000, std::sync::atomic::Ordering::Relaxed);
        let p = |x: i32| Point { x, y: 0 };
        if group {
            stage_in_group(&net, 1, 1, 1);
            end_group(&net, 3, 2, 1);
        } else {
            net.deliver_coherent(WRITER, 1, 1, &p(1));
            net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
        }
        net.subscriber.on_writer_departure(
            &net.topic,
            WRITER,
            crate::engine::subscriber::DisposeKind::Unregistered,
            crate::engine::WriterDeparture::Deleted,
        );
        assert_eq!(net.take_all(), vec![]);
        assert_eq!(net.lost(), 2, "group {group}: the set's two samples");
    }
}

/// A best-effort set waiting for a member blocks no other writer.
#[test]
fn a_best_effort_set_waiting_blocks_no_other_writer() {
    let mut qos = QoS::best_effort().keep_last(1);
    qos.resource_limits.max_samples = 2;
    let net = NetworkReader::<Point>::with_parts(
        "be-waiting-other-writer",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::default(),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    net.subscriber
        .best_effort_wait_ms
        .store(60_000, std::sync::atomic::Ordering::Relaxed);
    let p = |x: i32, y: i32| Point { x, y };
    net.deliver_coherent(WRITER, 1, 1, &p(1, 0));
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    for sn in 1..=5 {
        net.deliver(WRITER_B, sn, &p(i32::try_from(sn).expect("small"), 1));
    }
    assert!(!net.take_all().is_empty(), "the other writer's samples");
    net.deliver(WRITER, 4, &p(4, 0));
    assert_eq!(
        net.lost(),
        2,
        "a later change of the writer decides the set"
    );
}

/// A reliable reader told by a HEARTBEAT that its writer's history starts
/// above what it received (firstSN past its gate) reports the changes it
/// never received in between as samples lost (RTPS v2.5 Sec.8.4.12.2,
/// transition T7: `lost_changes_update(firstSN, true)`; DDS v1.4
/// Sec.2.2.4.1, SAMPLE_LOST "never received"), each once, whatever reports
/// the same changes again (a second HEARTBEAT, a GAP), and not those a GAP
/// declared filtered for it (RTPS v2.5 Sec.8.3.8.4). They were stepped
/// over silently.
#[test]
fn a_heartbeat_past_what_was_received_reports_the_samples_lost() {
    let p = |x: i32| Point { x, y: 0 };
    let net = ordered_reader::<Point>("lost-to-heartbeat", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    net.deliver(WRITER, 3, &p(3));
    net.subscriber.on_writer_heartbeat_range(WRITER, 6, 7);
    assert_eq!(net.lost(), 3, "2, 4 and 5 were never received");
    net.subscriber.on_writer_heartbeat_range(WRITER, 6, 7);
    net.subscriber.on_writer_gap(WRITER, 2, 6, Vec::new());
    assert_eq!(net.lost(), 3, "each once");
    net.deliver(WRITER, 6, &p(6));
    net.deliver(WRITER, 7, &p(7));
    let got: Vec<i32> = net.take_all().iter().map(|s| s.x).collect();
    assert_eq!(got, vec![1, 3, 6, 7]);

    // Changes a GAP declared filtered for this reader are not lost.
    let net = ordered_reader::<Point>("lost-to-heartbeat-filtered", QoS::reliable().keep_all());
    net.deliver(WRITER, 1, &p(1));
    net.subscriber
        .on_writer_gap_filtered(WRITER, 3, 5, Vec::new(), 2);
    assert_eq!(net.lost(), 0, "fixture: filtered, not lost");
    net.subscriber.on_writer_heartbeat_range(WRITER, 6, 6);
    assert_eq!(net.lost(), 2, "only 2 and 5: 3 and 4 were filtered");

    // A best-effort reader takes no HEARTBEAT: nothing reported there.
    let net = NetworkReader::<Point>::with_gate(
        "lost-to-heartbeat-best-effort",
        QoS::best_effort().keep_all(),
        super::reorder::ReorderGate::new_best_effort(),
    );
    net.deliver(WRITER, 1, &p(1));
    net.subscriber.on_writer_heartbeat_range(WRITER, 5, 6);
    assert_eq!(net.lost(), 0);
}

/// KEEP_LAST compaction keeps the greatest source-order keys, rather
/// than the latest arrival positions (DDS 1.4 Sec.2.2.3.17-18). Preload
/// history directly so this contract is checked independently of the
/// receipt gate, which rejects stale noise before it fills a ring.
/// Source values 100 and 200 must survive noise at timestamp 1.
///
/// Mutant: using Self::replaced for BY_SOURCE compaction drops both.
#[test]
fn by_source_timestamp_keep_last_ring_compacts_by_source_order_not_arrival_position() {
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-ring-compaction",
        QoS::reliable()
            .keep_last(2)
            .destination_order(crate::dds::qos::DestinationOrder::by_source_timestamp()),
    );
    let writer = [0x75u8; 16];
    let ring = net.reader.network_ring_for_test().expect("ring");
    // Exercise history compaction independently of the receipt gate,
    // which refuses stale noise before it can fill this ring.
    for seq in 1..=ring.usable_capacity() as u64 {
        let (value, ts) = match seq {
            1 => (100, 100),
            2 => (200, 200),
            _ => (1, 1),
        };
        preload_source_history(&net, writer, seq, value, ts);
    }
    net.subscriber.compact_history_for_test(2);
    assert!(net.subscriber.compaction_decodes() > 0);

    let taken: Vec<i32> = net.take_all().iter().map(|k| k.value).collect();
    assert_eq!(
        taken,
        vec![100, 200],
        "the ring must retain the two greatest source timestamps (100, 200), \
         not the samples that happened to arrive last"
    );
    assert_eq!(
        net.rejected().total_count,
        0,
        "compaction evicts from the ring, it does not report SAMPLE_REJECTED"
    );
}

/// Compaction's tie-break is the same total source order as admission:
/// `(timestamp, writer GUID, writer SN)` (DDS 1.4 Sec.2.2.3.17). Preload
/// one higher-GUID value and later lower-GUID history entries at the same
/// source timestamp. The compactor must preserve the higher-GUID winner,
/// independently of receipt rejection that normally filters this noise.
///
/// Mutant: arrival-position replacement makes 999 disappear.
#[test]
fn by_source_timestamp_ring_compaction_keeps_the_guid_winner_on_an_exact_tie() {
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-compaction-guid-tie",
        QoS::reliable()
            .keep_last(2)
            .destination_order(crate::dds::qos::DestinationOrder::by_source_timestamp()),
    );
    let higher_guid = [0xFFu8; 16]; // lexicographically the greatest: the true winner
    let lower_guid = [0x01u8; 16]; // lexicographically the least
    let tied_ts: u64 = 5_000_000_000;

    let ring = net.reader.network_ring_for_test().expect("ring");
    preload_source_history(&net, higher_guid, 1, 999, tied_ts);
    for seq in 1..ring.usable_capacity() as u64 {
        preload_source_history(&net, lower_guid, seq, 1, tied_ts);
    }
    net.subscriber.compact_history_for_test(2);
    assert!(net.subscriber.compaction_decodes() > 0);

    let taken: Vec<i32> = net.take_all().iter().map(|k| k.value).collect();
    assert_eq!(
        taken,
        vec![999],
        "the higher-GUID writer's sample wins the tie on every reader"
    );
}

/// DDS v1.4 Sec.2.2.3.17: "all readers belonging to the same application
/// end up with the same final value" for the instance under
/// BY_SOURCE_TIMESTAMP, including the tie-break when two writers' samples
/// carry the exact same source timestamp. The K>1 merge path
/// (`pump_merge_locked`) and the dispose/unregister construction every
/// pump shares (`admit_lifecycle_entry`) must decode a LOCAL writer's
/// sample with its real writer GUID: with `writer_guid: None`, two local
/// writers tied on source timestamp would compare as equal keys, and
/// whichever one the merge happened to drain first -- a
/// ring-registration-order detail, never a property of the data -- would
/// win. This binds the SAME two writers
/// to two independent readers in OPPOSITE order (forcing the opposite
/// drain order on the tie) alongside one remote sample routed through
/// the network ring, and checks that both readers land on the same
/// value.
#[test]
fn by_source_timestamp_two_local_writers_tied_plus_one_remote_agree_on_the_winner() {
    let qos = || {
        QoS::best_effort()
            .keep_last(1)
            .destination_order(crate::dds::qos::DestinationOrder::by_source_timestamp())
    };
    let writer_a = crate::dds::writer::WriterBuilder::<Keyed>::new("hist-bysrc-tie".to_string())
        .qos(qos())
        .build()
        .expect("writer a");
    let writer_b = crate::dds::writer::WriterBuilder::<Keyed>::new("hist-bysrc-tie".to_string())
        .qos(qos())
        .build()
        .expect("writer b");
    let remote_writer = [0x76u8; 16];
    // Lower than the tied pair: present only to exercise the network
    // ring alongside the two local rings in the same merge; must always
    // lose the tie on its own timestamp, nothing to do with identity.
    let remote_ts: u64 = 1_000_000_000;
    // The tie: both local writers write the SAME instance at the SAME
    // exact-second source timestamp (avoids the lossy RTPS Time_t
    // 32-bit-fraction round trip, same convention as the other
    // `_w_timestamp` tests).
    let tied_ts: u64 = 2_000_000_000;

    let winner = |a_binds_first: bool| -> i32 {
        let net = NetworkReader::<Keyed>::new("hist-bysrc-tie", qos());
        crate::engine::router::set_route_source_ts_ns(Some(remote_ts));
        net.deliver(remote_writer, 1, &Keyed { id: 1, value: 999 });
        crate::engine::router::set_route_source_ts_ns(None);
        if a_binds_first {
            net.reader.bind_to_writer(writer_a.merger());
            net.reader.bind_to_writer(writer_b.merger());
        } else {
            net.reader.bind_to_writer(writer_b.merger());
            net.reader.bind_to_writer(writer_a.merger());
        }
        writer_a
            .write_w_timestamp(&Keyed { id: 1, value: 111 }, tied_ts)
            .expect("writer a write");
        writer_b
            .write_w_timestamp(&Keyed { id: 1, value: 222 }, tied_ts)
            .expect("writer b write");
        let taken = net.take_all();
        assert_eq!(taken.len(), 1, "KEEP_LAST(1): exactly one survivor");
        taken[0].value
    };

    let a_first = winner(true);
    let b_first = winner(false);
    assert_ne!(
        a_first, 999,
        "the remote sample's lower timestamp must lose the tie"
    );
    assert_eq!(
        a_first, b_first,
        "the same two writers, tied on source timestamp, must resolve to the \
         same winner whichever one this reader's merge happens to drain first"
    );
}

/// DDS v1.4 Sec.2.2.3.17: the tie-break identity above must not depend on
/// the writer still being alive at drain time. `ReaderBindings` must not
/// re-derive a local writer's GUID by upgrading a `Weak<TopicMerger>`
/// every pump; once the writer is dropped (a perfectly normal
/// `DataWriter` lifetime -- it may be destroyed the instant after its
/// last write), the upgrade would fail and the identity silently become
/// `None` for every ring entry it already queued, even though those
/// entries are real, already-admitted changes. Two readers of the SAME two writers, bound in opposite
/// order, BOTH writers dropped before EITHER reader drains: the GUID
/// persisted in the binding at bind time must still break the tie the
/// same way on both.
#[test]
fn by_source_timestamp_tie_break_survives_the_writer_being_dropped() {
    let qos = || {
        QoS::best_effort()
            .keep_last(1)
            .destination_order(crate::dds::qos::DestinationOrder::by_source_timestamp())
    };
    let writer_a =
        crate::dds::writer::WriterBuilder::<Keyed>::new("hist-bysrc-tie-drop".to_string())
            .qos(qos())
            .build()
            .expect("writer a");
    let writer_b =
        crate::dds::writer::WriterBuilder::<Keyed>::new("hist-bysrc-tie-drop".to_string())
            .qos(qos())
            .build()
            .expect("writer b");
    let tied_ts: u64 = 3_000_000_000;

    let net_a_first = NetworkReader::<Keyed>::new("hist-bysrc-tie-drop", qos());
    net_a_first.reader.bind_to_writer(writer_a.merger());
    net_a_first.reader.bind_to_writer(writer_b.merger());
    let net_b_first = NetworkReader::<Keyed>::new("hist-bysrc-tie-drop", qos());
    net_b_first.reader.bind_to_writer(writer_b.merger());
    net_b_first.reader.bind_to_writer(writer_a.merger());

    writer_a
        .write_w_timestamp(&Keyed { id: 1, value: 111 }, tied_ts)
        .expect("writer a write");
    writer_b
        .write_w_timestamp(&Keyed { id: 1, value: 222 }, tied_ts)
        .expect("writer b write");

    // Both writers are gone before either reader drains: their identity
    // must already be persisted in the binding at bind time, not
    // re-derived later by upgrading a `Weak<TopicMerger>` that no
    // longer resolves.
    drop(writer_a);
    drop(writer_b);

    let a_first = net_a_first.take_all();
    let b_first = net_b_first.take_all();
    assert_eq!(a_first.len(), 1, "KEEP_LAST(1): exactly one survivor");
    assert_eq!(b_first.len(), 1, "KEEP_LAST(1): exactly one survivor");
    assert_eq!(
        a_first[0].value, b_first[0].value,
        "two readers of the same two (now-dropped) writers, tied on \
         source timestamp, must still agree on the same survivor"
    );
}

/// Same guarantee (DDS v1.4 Sec.2.2.3.17) for the OTHER site that must not
/// hardcode `writer_guid: None` for a local writer: `admit_lifecycle_entry`'s
/// construction of a local DISPOSE's `DisposeEvent`, narrowed to TWO LOCAL
/// DISPOSES (both go through `admit_lifecycle_entry`). A DATA-vs-DISPOSE
/// tie could not expose a missing identity, since `None` always loses to a
/// DATA sample's real local identity regardless of which drains first;
/// two disposes tied on both sides can. Writer A's dispose is its SECOND change (an earlier, lower-
/// timestamp dispose first advances its own sequence number); writer B's
/// is its first. Both final disposes tie on source timestamp: the
/// `SampleInfo::sequence_number` that survives says which writer's
/// dispose the gate actually kept, and it must be the same one whichever
/// writer's ring this reader's merge happens to drain first.
#[test]
fn by_source_timestamp_two_local_disposes_tied_agree_on_which_one_survives() {
    let qos = || {
        QoS::best_effort()
            .keep_last(1)
            .destination_order(crate::dds::qos::DestinationOrder::by_source_timestamp())
    };
    let writer_a = crate::dds::writer::WriterBuilder::<Keyed>::new("hist-bysrc-tie-dd".to_string())
        .qos(qos())
        .build()
        .expect("writer a");
    let writer_b = crate::dds::writer::WriterBuilder::<Keyed>::new("hist-bysrc-tie-dd".to_string())
        .qos(qos())
        .build()
        .expect("writer b");
    let a_early_ts: u64 = 1_000_000_000;
    let b_early_ts_1: u64 = 1_500_000_000;
    let b_early_ts_2: u64 = 2_000_000_000;
    let tied_ts: u64 = 4_000_000_000;

    // Two readers of the SAME pair of writers, bound in opposite order,
    // so each writer's dispose fans out to both at once: every dispose
    // below happens exactly ONCE (never replayed across reader
    // instances), so each writer's own sequence number is deterministic
    // and the same input reaches both readers.
    let net_a_first = NetworkReader::<Keyed>::new("hist-bysrc-tie-dd", qos());
    net_a_first.reader.bind_to_writer(writer_a.merger());
    net_a_first.reader.bind_to_writer(writer_b.merger());
    let net_b_first = NetworkReader::<Keyed>::new("hist-bysrc-tie-dd", qos());
    net_b_first.reader.bind_to_writer(writer_b.merger());
    net_b_first.reader.bind_to_writer(writer_a.merger());

    // A's own sequence number reaches the tie at 2, B's at 3 (one and
    // two earlier, non-tied, strictly increasing disposes): the two
    // ties' events are then distinguishable by `sequence_number` alone
    // (2 vs 3, never colliding), whichever the gate keeps -- on EITHER
    // reader, since both just got the same writer bindings, only in
    // opposite order.
    writer_a
        .dispose_w_timestamp(&Keyed { id: 1, value: 0 }, a_early_ts)
        .expect("writer a early dispose");
    writer_b
        .dispose_w_timestamp(&Keyed { id: 1, value: 0 }, b_early_ts_1)
        .expect("writer b early dispose 1");
    writer_b
        .dispose_w_timestamp(&Keyed { id: 1, value: 0 }, b_early_ts_2)
        .expect("writer b early dispose 2");
    writer_a
        .dispose_w_timestamp(&Keyed { id: 1, value: 0 }, tied_ts)
        .expect("writer a tied dispose");
    writer_b
        .dispose_w_timestamp(&Keyed { id: 1, value: 0 }, tied_ts)
        .expect("writer b tied dispose");

    let survivor_seq = |net: &NetworkReader<Keyed>| -> u64 {
        let mut last_seq = None;
        while let Ok(Some((_, info))) = net.reader.take_with_info() {
            last_seq = Some(info.sequence_number);
        }
        last_seq.expect("the tie's winner must surface exactly one event")
    };

    let a_first = survivor_seq(&net_a_first);
    let b_first = survivor_seq(&net_b_first);
    assert_eq!(
        a_first, b_first,
        "two local writers' disposes, tied on source timestamp, must resolve to the \
         same survivor whichever one this reader's merge happens to drain first"
    );
}

// ---------------------------------------------------------------------
// DESTINATION_ORDER BY_SOURCE_TIMESTAMP (DDS v1.4 Sec.2.2.3.17): where its
// one acceptance point sits relative to the history, the listener, the
// presentation order, writer presence and the reader's other filters;
// and the default reader it must leave as it was.
// ---------------------------------------------------------------------

fn by_source(qos: QoS) -> QoS {
    qos.destination_order(crate::dds::qos::DestinationOrder::by_source_timestamp())
}

pub(super) fn key1() -> [u8; 16] {
    Keyed { id: 1, value: 0 }.compute_key()
}

impl NetworkReader<Keyed> {
    /// `writer`'s change `seq` of instance 1, value `value`, under the
    /// datagram INFO_TS `ts_ns`.
    pub(super) fn deliver_at(&self, writer: [u8; 16], seq: u64, value: i32, ts_ns: u64) {
        crate::engine::router::set_route_source_ts_ns(Some(ts_ns));
        self.deliver(writer, seq, &Keyed { id: 1, value });
        crate::engine::router::set_route_source_ts_ns(None);
    }

    /// `writer`'s lifecycle change `seq` of instance 1 under INFO_TS
    /// `ts_ns`.
    fn lifecycle_at(
        &self,
        writer: [u8; 16],
        seq: u64,
        kind: crate::engine::subscriber::DisposeKind,
        ts_ns: u64,
    ) {
        crate::engine::router::set_route_source_ts_ns(Some(ts_ns));
        self.subscriber
            .on_dispose_from_writer(&self.topic, writer, seq, key1(), kind);
        crate::engine::router::set_route_source_ts_ns(None);
    }

    fn values(&self) -> Vec<i32> {
        self.take_all().iter().map(|k| k.value).collect()
    }

    fn state_of_1(&self) -> super::InstanceState {
        self.reader
            .cache()
            .instances()
            .state_of(super::InstanceHandle::new(key1()))
    }
}

/// Counts every `on_data_available` call, payload included.
#[derive(Default)]
struct CountingListener {
    calls: std::sync::atomic::AtomicUsize,
}

impl CountingListener {
    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl<T: DDS> crate::dds::listener::DataReaderListener<T> for CountingListener {
    fn on_data_available(&self, _sample: &T) {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A sample its instance's admission has already decided against (older
/// than the last change it accepted, Sec.2.2.3.17) is refused before it
/// takes a place in a bounded RELIABLE KEEP_ALL history: four of them, as
/// many as the history holds, leave room for the next valid sample, with
/// nothing taken in between.
///
/// Mutant: removing the reception-time refusal in
/// `ReaderSubscriber::process_admitted` makes this fail: the four stale
/// samples fill the history, DATA@400 is refused for room (SAMPLE_REJECTED)
/// and the take finds nothing once admission discards the four.
#[test]
fn by_source_timestamp_a_stale_sample_takes_no_place_in_a_keep_all_history() {
    let mut qos = by_source(QoS::reliable().keep_all());
    qos.resource_limits.max_samples = 4;
    let net = NetworkReader::<Keyed>::new("hist-bysrc-stale-no-place", qos);
    net.deliver_at(WRITER, 1, 300, 300);
    assert_eq!(net.values(), vec![300], "fixture: DATA@300 accepted, taken");
    for seq in 2..=5 {
        net.deliver_at(WRITER, seq, 200, 200);
    }
    net.deliver_at(WRITER, 6, 400, 400);
    assert_eq!(
        net.values(),
        vec![400],
        "the stale samples held no place: DATA@400 found one"
    );
    assert_eq!(
        net.rejected().total_count,
        0,
        "nothing was refused for room"
    );
}

/// A BY_SOURCE_TIMESTAMP reader's listener remains notification-only.
/// DATA@200 is accepted before another writer's dispose@300 arrives at
/// its notification hook. The accepted value remains in history, while
/// access reports the instance's current disposed state. Both the value
/// and transition remain available through accessors.
#[test]
fn by_source_timestamp_the_network_listener_carries_no_payload() {
    use crate::dds::Condition as _;
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-no-payload",
        by_source(QoS::reliable().keep_last(4)),
    );
    let listener = Arc::new(CountingListener::default());
    net.subscriber.listener.set(
        Some(listener.clone() as Arc<dyn crate::dds::listener::DataReaderListener<Keyed>>),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );

    // No race: woken, read, never handed to the listener.
    net.deliver_at(WRITER, 1, 100, 100);
    assert!(
        net.reader.get_status_condition().get_trigger_value(),
        "the wake-up goes out without the payload"
    );
    assert_eq!(net.values(), vec![100]);

    // The race, paused at the notification point of WRITER's seq 2.
    let sub = Arc::downgrade(&net.subscriber);
    let topic = net.topic.clone();
    *net.subscriber
        .pushed_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |seq| {
        if seq != 2 {
            return;
        }
        if let Some(sub) = sub.upgrade() {
            crate::engine::router::set_route_source_ts_ns(Some(300));
            sub.on_dispose_from_writer(
                &topic,
                WRITER_B,
                1,
                key1(),
                crate::engine::subscriber::DisposeKind::Disposed,
            );
        }
    }));
    net.deliver_at(WRITER, 2, 200, 200);
    *net.subscriber
        .pushed_hook
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = None;
    crate::engine::router::set_route_source_ts_ns(None);

    assert_eq!(listener.calls(), 0, "no payload ever reached the listener");
    let mut got = Vec::new();
    while let Some((data, info)) = net.reader.take_with_info().expect("take_with_info") {
        assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
        got.push(data.map(|sample| sample.value));
    }
    assert!(
        got.contains(&Some(200)),
        "DATA accepted before dispose remains retained"
    );
    assert!(got.contains(&None), "the later dispose is reported too");
}

/// The same for a coherent set's members, announced together once the set
/// is whole (`announce`): the reader is woken for the set, its listener is
/// handed none of the members' values, and the set is read.
///
/// The payload-less notification is tested separately by draining complete
/// sets from the callback itself.
#[test]
fn by_source_timestamp_a_coherent_set_wakes_without_payloads() {
    use crate::dds::Condition as _;
    let net = coherent_reader(
        "hist-bysrc-coherent-no-payload",
        by_source(QoS::reliable().keep_all()),
    );
    let listener = Arc::new(CountingListener::default());
    net.subscriber.listener.set(
        Some(listener.clone() as Arc<dyn crate::dds::listener::DataReaderListener<Point>>),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );
    net.deliver_coherent(WRITER_B, 1, 1, &Point { x: 1, y: 0 });
    net.deliver_coherent(WRITER_B, 2, 1, &Point { x: 2, y: 0 });
    net.subscriber
        .on_ecs(&net.topic, WRITER_B, 3, 2, None, None);
    assert!(net.reader.get_status_condition().get_trigger_value());
    assert_eq!(listener.calls(), 0);
    assert_eq!(net.take_all().len(), 2, "the whole set is read");
}

/// The order key's third field is the writer's FULL sequence number, the
/// same 64 bits for its DATA as for its dispose (RTPS v2.5 Sec.8.3.5.4).
/// One writer past 2^32 changes sends, at one source timestamp T, DATA
/// SN=2^32+1, a dispose SN=2^32+2 and DATA SN=2^32+3: the last DATA is
/// the newest change and must be accepted, reviving the instance. With
/// the ring's 32-bit `seq` in the key, DATA SN=2^32+3 compared as 3, below
/// the dispose's 2^32+2, and was refused.
///
/// Mutant: keying admission on `u64::from(entry.seq)` instead of the
/// prefix's `writer_sn` (`DataReader::admit_by_source`) makes this fail:
/// nothing is taken and the instance stays disposed.
#[test]
fn by_source_timestamp_orders_one_writer_by_its_full_sequence_number() {
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-full-sn",
        by_source(QoS::best_effort().keep_last(8)),
    );
    let base = 1u64 << 32;
    let t = 5_000_000_000;
    net.deliver_at(WRITER, base + 1, 1, t);
    net.lifecycle_at(
        WRITER,
        base + 2,
        crate::engine::subscriber::DisposeKind::Disposed,
        t,
    );
    net.deliver_at(WRITER, base + 3, 3, t);
    assert_eq!(
        net.values(),
        vec![1, 3],
        "both DATA were accepted at receipt; the later DATA revives after disposal"
    );
    assert_eq!(
        net.state_of_1(),
        super::InstanceState::Alive,
        "the later DATA revives the instance its writer disposed"
    );
}

/// Ring compaction keeps the same order: one writer, one timestamp, its
/// sequence numbers crossing 2^32 (from 2^32-2 on), delivered untaken
/// until the full network ring compacts once. KEEP_LAST(2) then keeps the
/// two greatest sequence numbers. Compared on the ring's 32 bits, 2^32-2
/// and 2^32-1 outranked every later change and were the ones kept.
///
/// Mutant: ordering ring entries by `u64::from(entry.seq)` in
/// `ReaderSubscriber::compact` instead of the prefix's sequence number
/// makes this fail: value 1 (SN 2^32-1) is taken.
#[test]
fn by_source_timestamp_ring_compaction_orders_by_the_full_sequence_number() {
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-compaction-full-sn",
        by_source(QoS::reliable().keep_last(2)),
    );
    let t = 6_000_000_000;
    let first = (1u64 << 32) - 2;
    let mut last = 0;
    while net.subscriber.compaction_decodes() == 0 {
        assert!(last < 100_000, "the ring never compacted");
        net.deliver_at(
            WRITER,
            first + u64::try_from(last).expect("positive"),
            last,
            t,
        );
        last += 1;
    }
    let last = last - 1;
    assert!(last > 2, "fixture: compaction ran once the ring was full");
    assert_eq!(
        net.values(),
        vec![last - 1, last],
        "the two newest changes are kept"
    );
}

/// TIME_BASED_FILTER (Sec.2.2.3.12) is asked inside the admission, after
/// the ordering: a sample the ordering refuses consumes no interval.
/// DATA@200 is in the ring when another writer's dispose@300 is
/// accepted; at the take, DATA@200 loses and DATA@400, inside what would
/// have been DATA@200's interval, is the first sample the filter passes.
///
/// Mutant: asking `filter` before the ordering check in
/// `InstanceEntry::admit_by_source` makes this fail: DATA@200 consumes
/// the interval and DATA@400 is filtered out.
#[test]
fn by_source_timestamp_a_refused_sample_consumes_no_filter_interval() {
    let qos = by_source(QoS::best_effort().keep_last(4)).time_based_filter(
        crate::dds::qos::TimeBasedFilter::new(std::time::Duration::from_secs(3600)),
    );
    let net = NetworkReader::<Keyed>::new("hist-bysrc-tbf", qos);
    net.lifecycle_at(
        WRITER_B,
        1,
        crate::engine::subscriber::DisposeKind::Disposed,
        300,
    );
    net.deliver_at(WRITER, 1, 200, 200);
    net.deliver_at(WRITER, 2, 400, 400);
    assert_eq!(net.values(), vec![400]);
}

/// Presentation (Sec.2.2.2.5.3.8): an instance's changes come out in
/// source order whatever their writers. Writer A's DATA@200 is admitted
/// (read, so pumped into the cache); writer B's dispose@300 follows. The
/// dispose waits behind the older DATA, for the ordinary take and for a
/// condition's take and read alike.
///
/// Mutant: dropping `waits_for_older_source_data` from
/// `DisposeQueue::goes_before` makes all three fail: the dispose comes
/// out first. Passing an empty `by_source` in `take_w_condition` /
/// `read_w_condition` fails the two conditional parts only.
#[test]
fn by_source_timestamp_a_transition_waits_behind_older_data_of_another_writer() {
    use crate::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};
    let setup = |topic: &str| {
        let net = NetworkReader::<Keyed>::new(topic, by_source(QoS::reliable().keep_last(4)));
        net.deliver_at(WRITER, 1, 200, 200);
        // `read` pumps DATA@200 into the cache, admitted.
        assert_eq!(net.reader.read().expect("read").map(|k| k.value), Some(200));
        net.lifecycle_at(
            WRITER_B,
            1,
            crate::engine::subscriber::DisposeKind::Disposed,
            300,
        );
        net
    };
    let order = |out: &[(Option<Keyed>, super::SampleInfo)]| -> Vec<bool> {
        out.iter().map(|(data, _)| data.is_some()).collect()
    };

    let net = setup("hist-bysrc-present-take");
    let mut out = Vec::new();
    while let Some(next) = net.reader.take_with_info().expect("take_with_info") {
        out.push(next);
    }
    assert_eq!(
        order(&out),
        vec![true, false],
        "take: DATA@200, then dispose@300"
    );

    let net = setup("hist-bysrc-present-take-cond");
    let any = net
        .reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let out = net
        .reader
        .take_w_condition(&any, usize::MAX)
        .expect("take_w_condition");
    assert_eq!(order(&out), vec![true, false], "take_w_condition");

    let net = setup("hist-bysrc-present-read-cond");
    let any = net
        .reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let out = net
        .reader
        .read_w_condition(&any, usize::MAX)
        .expect("read_w_condition");
    assert_eq!(order(&out), vec![true, false], "read_w_condition");
}

/// What a read has walked past holds no transition back: the second
/// `read_w_condition` of a NOT_READ condition finds DATA@200 already READ
/// (not matched), so the dispose comes out. No persistent floor.
///
/// Mutant: computing the conditional `by_source` from index 0 with an
/// always-true predicate makes this fail: the second read returns
/// nothing, the dispose waiting for a sample it cannot return.
#[test]
fn by_source_timestamp_a_sample_already_read_holds_no_transition_back() {
    use crate::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-present-cursor",
        by_source(QoS::reliable().keep_last(4)),
    );
    net.deliver_at(WRITER, 1, 200, 200);
    let not_read = net
        .reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let first = net
        .reader
        .read_w_condition(&not_read, usize::MAX)
        .expect("read");
    assert_eq!(first.len(), 1, "fixture: DATA@200 read");
    net.lifecycle_at(
        WRITER_B,
        1,
        crate::engine::subscriber::DisposeKind::Disposed,
        300,
    );
    let second = net
        .reader
        .read_w_condition(&not_read, usize::MAX)
        .expect("read");
    assert_eq!(second.len(), 1, "the dispose, past the already-read DATA");
    assert!(second[0].0.is_none());
}

/// Writer presence never revives NOT_ALIVE_DISPOSED (Sec.2.2.2.5.1.3):
/// writer A disposes-and-unregisters at 300; writer B's DATA@200, refused
/// for its value, registers B but leaves the instance disposed.
///
/// Mutant: letting `InstanceTable::revive_if_held` and
/// `InstanceEntry::revive_no_writers` revive any NOT_ALIVE state makes
/// this fail: the instance becomes ALIVE with no accepted value.
#[test]
fn by_source_timestamp_writer_presence_never_revives_a_disposed_instance() {
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-presence-disposed",
        by_source(QoS::reliable().keep_last(4)),
    );
    net.deliver_at(WRITER, 1, 100, 100);
    assert_eq!(net.values(), vec![100]);
    net.lifecycle_at(
        WRITER,
        2,
        crate::engine::subscriber::DisposeKind::DisposedUnregistered,
        300,
    );
    net.deliver_at(WRITER_B, 1, 200, 200);
    assert_eq!(net.state_of_1(), super::InstanceState::NotAliveDisposed);
    assert_eq!(net.values(), Vec::<i32>::new(), "DATA@200 is refused");
}

/// An unregister applied "because no writer holds the instance" asks that
/// presence fact again under the instance lock: a writer that registered
/// the instance in between (here, in the reader's table before the
/// queued unregister is applied) keeps it ALIVE.
///
/// Mutant: dropping the `held` check from
/// `InstanceEntry::accept_and_mark_not_alive` makes this fail: the
/// instance becomes NOT_ALIVE_NO_WRITERS while writer B holds it.
#[test]
fn by_source_timestamp_an_unregister_asks_writer_presence_again() {
    let net = NetworkReader::<Keyed>::new(
        "hist-bysrc-presence-revalidated",
        by_source(QoS::reliable().keep_last(4)),
    );
    assert!(net
        .reader
        .registrations_for_test()
        .admit_sample(WRITER_B, key1(), 1));
    net.reader
        .dispose_queue_for_test()
        .push(super::subscriber::DisposeEvent {
            key_hash: key1(),
            kind: crate::engine::subscriber::DisposeKind::Unregistered,
            seq: 1,
            writer_guid: Some(WRITER),
            order_seq: 1,
            announced: false,
            read: false,
            from_local_writer: false,
            disposed_generation_count: 0,
            no_writers_generation_count: 0,
            source_timestamp_ns: Some(300),
        });
    assert_eq!(net.state_of_1(), super::InstanceState::Alive);
}

/// A local writer's presence (Sec.2.2.2.5.1.3) on the intra-process path:
/// writer 1 writes at 300, then unregisters at 200 (no autodispose), which
/// leaves the instance NOT_ALIVE_NO_WRITERS though its ordering loses; a
/// new local writer 2 then writes at 200. Its value is refused (older than
/// 300), but writer 2 holds the instance, which is ALIVE again.
///
/// Mutant: dropping the presence step from
/// `InstanceEntry::admit_by_source` makes this fail: the instance stays
/// NOT_ALIVE_NO_WRITERS with a live writer.
#[test]
fn by_source_timestamp_a_local_writer_revives_a_writerless_instance() {
    let qos = by_source(QoS::best_effort().keep_last(4));
    let topic = "hist-bysrc-local-presence";
    let writer = |q: QoS| {
        crate::dds::writer::WriterBuilder::<Keyed>::new(topic.to_string())
            .qos(q.writer_data_lifecycle_manual_dispose())
            .build()
            .expect("writer")
    };
    let writer_1 = writer(qos.clone());
    let writer_2 = writer(qos.clone());
    let net = NetworkReader::<Keyed>::new(topic, qos);
    net.reader.bind_to_writer(writer_1.merger());
    net.reader.bind_to_writer(writer_2.merger());

    writer_1
        .write_w_timestamp(&Keyed { id: 1, value: 1 }, 300)
        .expect("write");
    assert_eq!(net.values(), vec![1]);
    writer_1
        .unregister_instance_w_timestamp(&Keyed { id: 1, value: 0 }, 200)
        .expect("unregister");
    let (_, info) = net
        .reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the transition");
    assert_eq!(info.instance_state, super::InstanceState::NotAliveNoWriters);

    writer_2
        .write_w_timestamp(&Keyed { id: 1, value: 2 }, 200)
        .expect("write");
    assert_eq!(net.values(), Vec::<i32>::new(), "its value is refused");
    assert_eq!(net.state_of_1(), super::InstanceState::Alive);
}

/// A local dispose ends the instance's DEADLINE watch only once the
/// reader admits it (Sec.2.2.3.7, Sec.2.2.3.17): the local writer writes
/// at 300, then disposes at 200, a dispose its ordering refuses. The
/// instance stays ALIVE, and watched.
///
/// Mutant: letting the local ownership gate remove the watch whatever
/// the policy (dropping `.filter(|_| !self.by_source_timestamp)` in
/// `LocalOwnership::gate_for`) makes this fail.
#[test]
fn by_source_timestamp_a_refused_local_dispose_keeps_the_deadline_watch() {
    let qos = by_source(QoS::best_effort().keep_last(4)).deadline(
        crate::qos::deadline::Deadline::new(std::time::Duration::from_secs(3600)),
    );
    let topic = "hist-bysrc-local-deadline";
    let writer = crate::dds::writer::WriterBuilder::<Keyed>::new(topic.to_string())
        .qos(qos.clone())
        .build()
        .expect("writer");
    let net = NetworkReader::<Keyed>::new(topic, qos);
    net.reader.bind_to_writer(writer.merger());
    writer
        .write_w_timestamp(&Keyed { id: 1, value: 1 }, 300)
        .expect("write");
    assert_eq!(net.values(), vec![1]);
    writer
        .dispose_w_timestamp(&Keyed { id: 1, value: 0 }, 200)
        .expect("dispose");
    assert!(
        net.reader
            .take_with_info()
            .expect("take_with_info")
            .is_none(),
        "the stale dispose is refused"
    );
    assert_eq!(net.state_of_1(), super::InstanceState::Alive);
    assert!(
        net.reader
            .deadlines_for_test()
            .expect("a finite deadline")
            .watches(super::InstanceHandle::new(key1())),
        "the refused dispose ended nothing"
    );
}

/// BY_RECEPTION_TIMESTAMP (the default) merges a reader's local writers
/// by when they wrote, not by the source timestamp an application gives
/// `write_w_timestamp`: writer A writes with a timestamp an hour ahead,
/// then writer B writes plainly; a KEEP_LAST(1) reader keeps B's sample,
/// the later write, as it did before local samples carried overrides.
///
/// Mutant: making `DataReader::merge_key` return `timestamp_ns` whatever
/// the policy makes this fail: A's future timestamp sorts last and A's
/// value is kept.
#[test]
fn by_reception_timestamp_a_future_source_timestamp_does_not_win_the_merge() {
    let qos = QoS::best_effort().keep_last(1);
    let topic = "hist-reception-merge-override";
    let writer = || {
        crate::dds::writer::WriterBuilder::<Keyed>::new(topic.to_string())
            .qos(qos.clone())
            .build()
            .expect("writer")
    };
    let writer_a = writer();
    let writer_b = writer();
    let net = NetworkReader::<Keyed>::new(topic, qos.clone());
    net.reader.bind_to_writer(writer_a.merger());
    net.reader.bind_to_writer(writer_b.merger());
    let an_hour_ahead = crate::telemetry::metrics::current_time_ns() + 3_600_000_000_000;
    writer_a
        .write_w_timestamp(&Keyed { id: 1, value: 1 }, an_hour_ahead)
        .expect("write a");
    writer_b.write(&Keyed { id: 1, value: 2 }).expect("write b");
    assert_eq!(net.values(), vec![2], "the later write is kept");
}

/// DDS v1.4 Sec.2.2.4.3.2: DATA_AVAILABLE lets a listener-only application
/// drain its reader. Bounded RELIABLE KEEP_ALL history must make progress
/// through repeated notifications, without exposing arrival payloads.
struct DrainingNotification<T: DDS> {
    reader: std::sync::Weak<super::DataReader<T>>,
    samples: Mutex<Vec<T>>,
    payloads: std::sync::atomic::AtomicUsize,
}

impl<T: DDS> crate::dds::listener::DataReaderListener<T> for DrainingNotification<T> {
    fn on_data_available(&self, _sample: &T) {
        self.payloads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn on_data_available_notification(&self) {
        let reader = self.reader.upgrade().expect("reader alive");
        while let Some(sample) = reader.take().expect("listener take") {
            self.samples.lock().unwrap().push(sample);
        }
    }
}

fn install_draining_notification<T: DDS>(net: &NetworkReader<T>) -> Arc<DrainingNotification<T>> {
    let listener = Arc::new(DrainingNotification {
        reader: Arc::downgrade(&net.reader),
        samples: Mutex::new(Vec::new()),
        payloads: std::sync::atomic::AtomicUsize::new(0),
    });
    net.subscriber.listener.set(
        Some(listener.clone() as Arc<dyn crate::dds::listener::DataReaderListener<T>>),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );
    listener
}

#[test]
fn by_source_notification_drains_bounded_network_history() {
    let mut qos = by_source(QoS::reliable().keep_all());
    qos.resource_limits.max_samples = 2;
    let net = NetworkReader::<Keyed>::new("hist-bysrc-notification-drain", qos);
    let listener = install_draining_notification(&net);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for seq in 1..=8 {
            net.deliver_at(WRITER, seq, i32::try_from(seq).unwrap(), seq * 100);
        }
        tx.send(net.rejected().total_count).unwrap();
    });
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("callback drains outside delivery locks"),
        0
    );
    assert_eq!(
        listener
            .samples
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.value)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(
        listener.payloads.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn by_source_notification_drains_complete_coherent_sets() {
    let mut qos = by_source(QoS::reliable().keep_all());
    qos.resource_limits.max_samples = 2;
    let net = coherent_reader("hist-bysrc-notification-coherent", qos);
    let listener = install_draining_notification(&net);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for start in [1, 4, 7] {
            net.deliver_coherent(
                WRITER_B,
                start,
                start,
                &Point {
                    x: i32::try_from(start).unwrap(),
                    y: 0,
                },
            );
            net.deliver_coherent(
                WRITER_B,
                start + 1,
                start,
                &Point {
                    x: i32::try_from(start + 1).unwrap(),
                    y: 0,
                },
            );
            net.subscriber
                .on_ecs(&net.topic, WRITER_B, start + 2, 2, None, None);
        }
        tx.send(net.rejected().total_count).unwrap();
    });
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("coherent callback drains outside delivery locks"),
        0
    );
    assert_eq!(
        listener
            .samples
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.x)
            .collect::<Vec<_>>(),
        vec![1, 2, 4, 5, 7, 8]
    );
    assert_eq!(
        listener.payloads.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// DDS v1.4 Sec.2.2.2.5.3.8: a writer's transition before DATA is
/// presented before that DATA, including after its SN exceeds 32 bits.
/// The source timestamp barrier alone cannot order these: DATA@400 is
/// newer than dispose@300. Ordinary and conditional accesses share the
/// same full-width writer ordering under both destination policies.
#[test]
fn by_source_and_reception_presentation_preserves_full_writer_sequence_numbers() {
    use crate::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};
    for source in [false, true] {
        for access in 0..3 {
            let qos = QoS::best_effort().keep_last(4);
            let qos = if source { by_source(qos) } else { qos };
            let net = NetworkReader::<Keyed>::new("hist-presentation-full-sn", qos);
            let base = 1u64 << 32;
            net.lifecycle_at(
                WRITER,
                base + 2,
                crate::engine::subscriber::DisposeKind::Disposed,
                300,
            );
            net.deliver_at(WRITER, base + 3, 400, 400);
            let condition = net
                .reader
                .create_readcondition(
                    SampleStateMask::ANY,
                    ViewStateMask::ANY,
                    InstanceStateMask::ANY,
                )
                .expect("condition");
            let samples = match access {
                0 => net
                    .reader
                    .take_with_info()
                    .unwrap()
                    .into_iter()
                    .chain(net.reader.take_with_info().unwrap())
                    .collect::<Vec<_>>(),
                1 => net.reader.take_w_condition(&condition, 2).unwrap(),
                _ => net.reader.read_w_condition(&condition, 2).unwrap(),
            };
            assert_eq!(samples.len(), 2, "source={source}, access={access}");
            assert!(
                samples[0].0.is_none(),
                "dispose must precede DATA: source={source}, access={access}"
            );
            assert_eq!(samples[0].1.sequence_number, base + 2);
            assert_eq!(samples[1].0.as_ref().map(|s| s.value), Some(400));
            assert_eq!(samples[1].1.sequence_number, base + 3);
        }
    }
}

/// A DATA accepted at receipt keeps its TIME_BASED_FILTER interval even
/// when a later dispose is delivered before the application first pumps.
/// BY_SOURCE_TIMESTAMP never retroactively rejects the earlier DATA.
#[test]
fn by_source_timestamp_receipt_keeps_an_accepted_samples_filter_interval() {
    let qos = by_source(QoS::best_effort().keep_last(4)).time_based_filter(
        crate::dds::qos::TimeBasedFilter::new(std::time::Duration::from_secs(3600)),
    );
    let net = NetworkReader::<Keyed>::new("hist-bysrc-receipt-tbf", qos);
    net.deliver_at(WRITER, 1, 200, 200);
    net.lifecycle_at(
        WRITER_B,
        1,
        crate::engine::subscriber::DisposeKind::Disposed,
        300,
    );
    net.deliver_at(WRITER, 2, 400, 400);
    assert_eq!(net.values(), vec![200]);
    assert_eq!(
        net.reader
            .cache()
            .instances()
            .generation_counts(handle_of(1)),
        (0, 0)
    );
    assert_eq!(
        net.reader.cache().instances().state_of(handle_of(1)),
        crate::dds::InstanceState::NotAliveDisposed
    );
}

/// Populate the compactor's input directly so its ordering rule remains
/// tested independently of receipt admission (which rejects stale input).
fn preload_source_history(
    net: &NetworkReader<Keyed>,
    writer: [u8; 16],
    seq: u64,
    value: i32,
    ts: u64,
) {
    let mut bytes = writer.to_vec();
    bytes.extend_from_slice(&seq.to_le_bytes());
    bytes.extend_from_slice(&encoded(&Keyed { id: 1, value }));
    let (handle, _) = rt::get_slab_pool_ref()
        .reserve_and_write(&bytes, rt::Claim::Reader)
        .expect("fixture storage");
    let mut entry = rt::IndexEntry {
        seq: seq as u32,
        handle,
        len: u32::try_from(bytes.len()).expect("small"),
        flags: 1,
        cdr_version: crate::dds::CdrVersion::Xcdr2,
        timestamp_ns: ts,
    };
    entry.mark_guid_prefix();
    entry.mark_writer_sn_prefix();
    entry.mark_source_ts();
    net.reader
        .network_room_for_test()
        .expect("room")
        .reserve_in_ring(Some(key1()), |_| false)
        .expect("fixture history place");
    assert!(net
        .reader
        .network_ring_for_test()
        .expect("ring")
        .push(entry));
}

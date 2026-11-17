// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HISTORY and RESOURCE_LIMITS of a reader fed by a DataWriter of the same
//! process (DDS v1.4 Sec.2.2.3.18, Sec.2.2.3.19), as the application sees
//! them: the writer's `write()` result, what `take()` returns per instance,
//! and the reader's SAMPLE_REJECTED status. The samples travel through the
//! writer's merger and the reader's local rings, never through a network
//! subscriber.

use crate::dds::{QoS, DDS};
use crate::test_support::domains::unique_domain;
use crate::{DataReader, DataWriter, Participant, TransportMode};
use std::collections::BTreeMap;
use std::sync::Arc;

/// A keyed sample: `id` names the instance.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
pub(super) struct Keyed {
    #[key]
    pub(super) id: i32,
    pub(super) value: i32,
}

/// One process, one domain of its own, no network: every writer and reader
/// of these tests is matched through the domain registry only.
pub(super) fn local_participant(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant")
}

pub(super) fn writer_of<T: DDS>(
    participant: &Arc<Participant>,
    topic: &str,
    qos: QoS,
) -> DataWriter<T> {
    participant
        .topic::<T>(topic)
        .expect("topic")
        .writer()
        .qos(qos)
        .build()
        .expect("writer")
}

pub(super) fn reader_of<T: DDS>(
    participant: &Arc<Participant>,
    topic: &str,
    qos: QoS,
) -> DataReader<T> {
    participant
        .topic::<T>(topic)
        .expect("topic")
        .reader()
        .qos(qos)
        .build()
        .expect("reader")
}

/// Everything the reader holds, per instance, in the order `take()` gives it.
pub(super) fn take_all_by_instance(reader: &DataReader<Keyed>) -> BTreeMap<i32, Vec<i32>> {
    let mut by_instance: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
    while let Some(sample) = reader.take().expect("take") {
        by_instance.entry(sample.id).or_default().push(sample.value);
    }
    by_instance
}

/// More than a reader's local ring holds (1023 entries for any depth up to
/// `READER_HISTORY_RING_SIZE`).
const BURST: i32 = 1500;

/// A KEEP_LAST(2) reader that does not take while a local writer writes
/// three instances 1500 times each keeps the last two values of each
/// instance. Its local ring holds 1023 samples: a full ring dropped the
/// newest one, and the application was left with values written long ago.
fn a_full_local_keep_last_reader_keeps_the_newest(reader_qos: QoS, topic: &str) {
    let domain = unique_domain();
    let participant = local_participant("full_local_keep_last", domain.id());
    let reader = reader_of::<Keyed>(&participant, topic, reader_qos.keep_last(2));
    let writer = writer_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(2));

    for value in 1..=BURST {
        for id in 0..3 {
            writer.write(&Keyed { id, value }).expect("write");
        }
    }

    let held = take_all_by_instance(&reader);
    let expected: BTreeMap<i32, Vec<i32>> = (0..3).map(|id| (id, vec![BURST - 1, BURST])).collect();
    assert_eq!(
        held, expected,
        "DDS v1.4 Sec.2.2.3.18: KEEP_LAST keeps the latest `depth` values of each instance"
    );
    assert_eq!(reader.get_sample_rejected_status().total_count, 0);
}

#[test]
fn a_full_local_best_effort_keep_last_reader_keeps_the_newest() {
    a_full_local_keep_last_reader_keeps_the_newest(QoS::best_effort(), "FullLocalKeepLastBE");
}

#[test]
fn a_full_local_reliable_keep_last_reader_keeps_the_newest() {
    a_full_local_keep_last_reader_keeps_the_newest(QoS::reliable(), "FullLocalKeepLastRel");
}

/// A full ring drops only what newer samples of the same instance replace:
/// 500 instances written once each stay, while one busy instance written
/// 2000 times keeps its newest value. Dropping anything else from a full
/// ring loses the only value an instance has.
#[test]
fn a_full_local_keep_last_ring_keeps_what_nothing_replaces() {
    let domain = unique_domain();
    let participant = local_participant("full_local_keep_others", domain.id());
    let topic = "FullLocalKeepOthers";
    let reader = reader_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(1));
    let writer = writer_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(1));

    for id in 0..500 {
        writer.write(&Keyed { id, value: 0 }).expect("write");
    }
    for value in 1..=2000 {
        writer.write(&Keyed { id: 1000, value }).expect("write");
    }

    let held = take_all_by_instance(&reader);
    let mut expected: BTreeMap<i32, Vec<i32>> = (0..500).map(|id| (id, vec![0])).collect();
    expected.insert(1000, vec![2000]);
    assert_eq!(held, expected);
}

/// The same with two readers on the writer (its fan-out path): each keeps
/// the newest `depth` values of each instance of its own.
#[test]
fn every_full_local_keep_last_reader_of_a_writer_keeps_the_newest() {
    let domain = unique_domain();
    let participant = local_participant("full_local_fan_out", domain.id());
    let topic = "FullLocalFanOut";
    let one = reader_of::<Keyed>(&participant, topic, QoS::best_effort().keep_last(1));
    let three = reader_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(3));
    let writer = writer_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(1));

    for value in 1..=BURST {
        for id in 0..2 {
            writer.write(&Keyed { id, value }).expect("write");
        }
    }

    let newest = |depth: i32| -> BTreeMap<i32, Vec<i32>> {
        (0..2)
            .map(|id| (id, (BURST - depth + 1..=BURST).collect()))
            .collect()
    };
    assert_eq!(take_all_by_instance(&one), newest(1));
    assert_eq!(take_all_by_instance(&three), newest(3));
}

/// A writer making room in a full ring while the application takes on
/// another thread: the two pop the ring one at a time (the reader's
/// consumer gate), so no sample is taken twice, none out of its order,
/// and the last value of each instance arrives.
#[test]
fn making_room_in_a_full_ring_while_the_reader_takes() {
    let domain = unique_domain();
    let participant = local_participant("full_local_concurrent", domain.id());
    let topic = "FullLocalConcurrent";
    let reader = Arc::new(reader_of::<Keyed>(
        &participant,
        topic,
        QoS::reliable().keep_last(4),
    ));
    let writer = writer_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(1));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let taker = {
        let reader = Arc::clone(&reader);
        let done = Arc::clone(&done);
        std::thread::spawn(move || {
            let mut last: BTreeMap<i32, i32> = BTreeMap::new();
            loop {
                let finished = done.load(std::sync::atomic::Ordering::Acquire);
                while let Some(sample) = reader.take().expect("take") {
                    let previous = last.insert(sample.id, sample.value);
                    assert!(
                        previous.is_none_or(|previous| previous < sample.value),
                        "instance {} went from {:?} to {}",
                        sample.id,
                        previous,
                        sample.value
                    );
                }
                if finished {
                    return last;
                }
                std::thread::yield_now();
            }
        })
    };
    for value in 1..=20_000 {
        for id in 0..3 {
            writer.write(&Keyed { id, value }).expect("write");
        }
    }
    done.store(true, std::sync::atomic::Ordering::Release);
    let last = taker.join().expect("taker");
    let expected: BTreeMap<i32, i32> = (0..3).map(|id| (id, 20_000)).collect();
    assert_eq!(last, expected);
}

/// A RELIABLE KEEP_ALL reader's QoS with RESOURCE_LIMITS `max_samples`.
pub(super) fn keep_all_reliable(max_samples: usize) -> QoS {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = max_samples;
    qos
}

/// A RELIABLE writer whose `write` waits `wait` for room.
pub(super) fn waiting_writer(
    participant: &Arc<Participant>,
    topic: &str,
    wait: std::time::Duration,
) -> DataWriter<Keyed> {
    writer_of::<Keyed>(
        participant,
        topic,
        QoS::reliable().keep_all().max_blocking_time(wait),
    )
}

fn values(reader: &DataReader<Keyed>) -> Vec<i32> {
    let mut values = Vec::new();
    while let Some(sample) = reader.take().expect("take") {
        values.push(sample.value);
    }
    values
}

fn is_timeout(result: crate::Result<()>) -> bool {
    matches!(result, Err(crate::Error::WriteTimeout))
}

/// A RELIABLE KEEP_ALL reader holding `max_samples` untaken samples has no
/// room for one more: the local writer's `write` waits its
/// `max_blocking_time` and returns TIMEOUT (DDS v1.4 Sec.2.2.3.14,
/// Sec.2.2.3.18 "the Service will block the DataWriter"), and the sample
/// reaches the reader neither then nor later. Once the application takes,
/// the next write goes through. The reader never takes a fifth sample past
/// `max_samples`, and a full ring never drops samples while `write` returns Ok.
#[test]
fn a_full_reliable_keep_all_local_reader_times_the_writer_out() {
    let domain = unique_domain();
    let participant = local_participant("keep_all_timeout", domain.id());
    let topic = "KeepAllTimeout";
    let reader = reader_of::<Keyed>(&participant, topic, keep_all_reliable(4));
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));

    for value in 1..=4 {
        writer
            .write(&Keyed { id: 0, value })
            .expect("room for four");
    }
    let started = std::time::Instant::now();
    assert!(
        is_timeout(writer.write(&Keyed { id: 0, value: 5 })),
        "a fifth sample has no room"
    );
    assert!(started.elapsed() >= std::time::Duration::from_millis(50));
    assert_eq!(
        values(&reader),
        vec![1, 2, 3, 4],
        "the timed-out sample is not delivered"
    );
    writer
        .write(&Keyed { id: 0, value: 6 })
        .expect("the take made room");
    assert_eq!(values(&reader), vec![6]);
    assert_eq!(reader.get_sample_rejected_status().total_count, 0);
}

/// A write waiting for room returns as soon as the application takes on
/// another thread, with the sample delivered after the ones taken.
#[test]
fn a_blocked_write_is_released_by_a_take_on_another_thread() {
    let domain = unique_domain();
    let participant = local_participant("keep_all_released", domain.id());
    let topic = "KeepAllReleased";
    let reader = reader_of::<Keyed>(&participant, topic, keep_all_reliable(2));
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_secs(30));
    writer.write(&Keyed { id: 0, value: 1 }).expect("write");
    writer.write(&Keyed { id: 0, value: 2 }).expect("write");

    let blocked = std::thread::spawn(move || writer.write(&Keyed { id: 0, value: 3 }));
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(!blocked.is_finished(), "the third write waits for room");
    assert_eq!(
        reader.take().expect("take"),
        Some(Keyed { id: 0, value: 1 })
    );
    let taken = std::time::Instant::now();
    blocked
        .join()
        .expect("writer thread")
        .expect("released by the take");
    assert!(
        taken.elapsed() < std::time::Duration::from_secs(10),
        "woken by the take, not by its 30 s running out"
    );
    assert_eq!(values(&reader), vec![2, 3]);
}

/// A writer and a reader at full speed on two threads, the reader's history
/// holding eight samples: the writer waits again and again, the reader's
/// take runs while it waits, and neither deadlocks. Every sample arrives,
/// once, in order.
#[test]
fn a_waiting_writer_and_a_taking_reader_do_not_deadlock() {
    const SAMPLES: i32 = 5000;
    let domain = unique_domain();
    let participant = local_participant("keep_all_no_deadlock", domain.id());
    let topic = "KeepAllNoDeadlock";
    let reader = Arc::new(reader_of::<Keyed>(
        &participant,
        topic,
        keep_all_reliable(8),
    ));
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_secs(30));

    let taker = {
        let reader = Arc::clone(&reader);
        std::thread::spawn(move || {
            let mut got = Vec::with_capacity(SAMPLES as usize);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            while got.len() < SAMPLES as usize && std::time::Instant::now() < deadline {
                match reader.take().expect("take") {
                    Some(sample) => got.push(sample.value),
                    None => std::thread::yield_now(),
                }
            }
            got
        })
    };
    for value in 1..=SAMPLES {
        writer
            .write(&Keyed { id: 0, value })
            .expect("the reader keeps taking");
    }
    let got = taker.join().expect("taker");
    assert_eq!(got, (1..=SAMPLES).collect::<Vec<_>>());
}

/// Two RELIABLE readers, one full: the write waits for it and times out,
/// and the other reader does not get the sample either (a write that
/// returns TIMEOUT wrote nothing), nor keeps the room it was given for it.
/// Once the full one takes, the sample goes to both.
#[test]
fn a_full_reader_holds_the_sample_back_from_every_reader() {
    let domain = unique_domain();
    let participant = local_participant("keep_all_fan_out", domain.id());
    let topic = "KeepAllFanOut";
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));
    // Bound in this order: the roomy reader takes room for the third sample
    // before the full one blocks it.
    let roomy = reader_of::<Keyed>(&participant, topic, keep_all_reliable(3));
    let full = reader_of::<Keyed>(&participant, topic, keep_all_reliable(2));

    writer.write(&Keyed { id: 0, value: 1 }).expect("write");
    writer.write(&Keyed { id: 0, value: 2 }).expect("write");
    assert!(is_timeout(writer.write(&Keyed { id: 0, value: 3 })));
    assert_eq!(values(&full), vec![1, 2]);
    writer
        .write(&Keyed { id: 0, value: 3 })
        .expect("room in both: the timed-out write gave back what it took");
    assert_eq!(
        values(&roomy),
        vec![1, 2, 3],
        "no reader got the timed-out sample"
    );
    assert_eq!(values(&full), vec![3]);
}

/// The same release for a writer waiting on a RELIABLE KEEP_LAST reader's
/// full ring: the take that empties the ring wakes it.
#[test]
fn a_write_blocked_on_a_full_ring_is_released_by_a_take() {
    let domain = unique_domain();
    let participant = local_participant("keep_last_ring_released", domain.id());
    let topic = "KeepLastRingReleased";
    let reader = reader_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(1));
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_secs(30));
    let ring = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() as i32 - 1;
    for id in 0..ring {
        writer
            .write(&Keyed { id, value: 1 })
            .expect("room in the ring");
    }

    let blocked = std::thread::spawn(move || writer.write(&Keyed { id: ring, value: 1 }));
    std::thread::sleep(std::time::Duration::from_millis(100));
    assert!(!blocked.is_finished(), "the write waits for the ring");
    assert!(reader.take().expect("take").is_some());
    let taken = std::time::Instant::now();
    blocked
        .join()
        .expect("writer thread")
        .expect("released by the take");
    assert!(
        taken.elapsed() < std::time::Duration::from_secs(10),
        "woken by the take, not by its 30 s running out"
    );
    assert_eq!(take_all_by_instance(&reader).get(&ring), Some(&vec![1]));
}

/// A RELIABLE KEEP_LAST(1) reader whose local ring is full of the newest
/// value of 1023 instances: nothing in it is replaced by a sample of a new
/// instance, so the writer waits and times out rather than drop it, and
/// once the application takes, the write goes through.
#[test]
fn a_reliable_keep_last_ring_full_of_kept_samples_times_the_writer_out() {
    let domain = unique_domain();
    let participant = local_participant("keep_last_ring_full", domain.id());
    let topic = "KeepLastRingFull";
    let reader = reader_of::<Keyed>(&participant, topic, QoS::reliable().keep_last(1));
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));

    let ring = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() as i32 - 1;
    for id in 0..ring {
        writer
            .write(&Keyed { id, value: 1 })
            .expect("room in the ring");
    }
    assert!(is_timeout(writer.write(&Keyed { id: ring, value: 1 })));
    assert_eq!(reader.take().expect("take").map(|s| s.id), Some(0));
    writer
        .write(&Keyed { id: ring, value: 1 })
        .expect("the take emptied the ring");
    let held = take_all_by_instance(&reader);
    assert_eq!(held.len(), ring as usize, "instances 1..={ring}");
    assert_eq!(held.get(&ring), Some(&vec![1]));
}

/// The mixed leg: the writer has a reader in its own participant and a
/// remote one over UDP. Its local reader has no room for a third sample:
/// the write times out before the sample is sent anywhere, so the remote
/// reader never gets it either, and the next write after a take reaches
/// both.
#[test]
fn a_full_local_reader_times_out_a_write_that_also_goes_on_the_wire() {
    let domain = unique_domain();
    let udp = |name: &str| {
        Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant")
    };
    let topic = "MixedLegTimeout";
    let participant = udp("mixed_leg_local");
    let local = reader_of::<Keyed>(&participant, topic, keep_all_reliable(2));
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));
    let remote_participant = udp("mixed_leg_remote");
    let remote = reader_of::<Keyed>(&remote_participant, topic, QoS::reliable().keep_all());
    // Discovery, until the writer reaches the remote reader over UDP.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut probe = 1;
    loop {
        writer
            .write(&Keyed {
                id: 1,
                value: probe,
            })
            .expect("probe");
        let got = take_all_by_instance(&remote);
        let _ = take_all_by_instance(&local);
        if got.contains_key(&1) {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "no discovery");
        std::thread::sleep(std::time::Duration::from_millis(100));
        probe += 1;
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    let _ = take_all_by_instance(&remote);

    writer.write(&Keyed { id: 0, value: 1 }).expect("write");
    writer.write(&Keyed { id: 0, value: 2 }).expect("write");
    assert!(is_timeout(writer.write(&Keyed { id: 0, value: 3 })));
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(values(&local), vec![1, 2]);
    assert_eq!(
        take_all_by_instance(&remote).get(&0),
        Some(&vec![1, 2]),
        "the timed-out sample went nowhere"
    );
    writer
        .write(&Keyed { id: 0, value: 3 })
        .expect("room again");
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(values(&local), vec![3]);
    assert_eq!(take_all_by_instance(&remote).get(&0), Some(&vec![3]));
}

/// `qos` with RESOURCE_LIMITS `max_instances` and `max_samples_per_instance`.
fn bounded(mut qos: QoS, max_instances: usize, max_samples_per_instance: usize) -> QoS {
    qos.resource_limits.max_instances = max_instances;
    qos.resource_limits.max_samples_per_instance = max_samples_per_instance;
    qos
}

const UNLIMITED: usize = crate::reliability::LENGTH_UNLIMITED;

/// A RELIABLE reader managing `max_instances` instances has no room for a
/// sample of a new one (DDS v1.4 Sec.2.2.3.19): the local writer times out.
/// An instance stays managed while a writer holds it (Sec.2.2.3.22); once
/// the writer unregisters it and the application took its samples, the new
/// instance takes its room. Local writers do not bypass the bound.
#[test]
fn a_reliable_local_reader_bounds_its_instances() {
    let domain = unique_domain();
    let participant = local_participant("local_max_instances", domain.id());
    let topic = "LocalMaxInstances";
    let reader = reader_of::<Keyed>(
        &participant,
        topic,
        bounded(QoS::reliable().keep_all(), 2, UNLIMITED),
    );
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));

    writer
        .write(&Keyed { id: 0, value: 1 })
        .expect("first instance");
    writer
        .write(&Keyed { id: 1, value: 1 })
        .expect("second instance");
    writer
        .write(&Keyed { id: 1, value: 2 })
        .expect("a managed instance");
    assert!(is_timeout(writer.write(&Keyed { id: 2, value: 1 })));
    let held = take_all_by_instance(&reader);
    assert_eq!(held.keys().copied().collect::<Vec<_>>(), vec![0, 1]);
    assert!(
        is_timeout(writer.write(&Keyed { id: 2, value: 1 })),
        "taken, but the writer still holds both instances"
    );
    writer
        .unregister_instance(&Keyed { id: 0, value: 0 })
        .expect("unregister");
    while reader.take().expect("take").is_some() {}
    writer
        .write(&Keyed { id: 2, value: 1 })
        .expect("instance 0 is no longer managed");
    assert_eq!(values(&reader), vec![1]);
}

/// A RELIABLE KEEP_ALL reader holding `max_samples_per_instance` samples of
/// an instance has no room for one more of it, and room for another
/// instance.
#[test]
fn a_reliable_local_reader_bounds_the_samples_of_an_instance() {
    let domain = unique_domain();
    let participant = local_participant("local_per_instance", domain.id());
    let topic = "LocalPerInstance";
    let reader = reader_of::<Keyed>(
        &participant,
        topic,
        bounded(QoS::reliable().keep_all(), UNLIMITED, 2),
    );
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));

    writer.write(&Keyed { id: 0, value: 1 }).expect("write");
    writer.write(&Keyed { id: 0, value: 2 }).expect("write");
    assert!(is_timeout(writer.write(&Keyed { id: 0, value: 3 })));
    writer
        .write(&Keyed { id: 1, value: 1 })
        .expect("another instance");
    let held = take_all_by_instance(&reader);
    assert_eq!(held.get(&0), Some(&vec![1, 2]));
    assert_eq!(held.get(&1), Some(&vec![1]));
    writer
        .write(&Keyed { id: 0, value: 3 })
        .expect("the take made room");
}

/// A BEST_EFFORT reader drops the sample of a new instance beyond
/// `max_instances` and reports it: SAMPLE_REJECTED, reason
/// REJECTED_BY_INSTANCES_LIMIT, with the instance (Sec.2.2.3.19, "If
/// reliability is BEST_EFFORT then the Service is allowed to drop
/// samples"). The writer is not held up.
#[test]
fn a_best_effort_local_reader_rejects_an_instance_beyond_its_bound() {
    use crate::dds::listener::SampleRejectedReason;
    let domain = unique_domain();
    let participant = local_participant("local_rejects_instance", domain.id());
    let topic = "LocalRejectsInstance";
    for qos in [
        QoS::best_effort().keep_last(1),
        QoS::best_effort().keep_all(),
    ] {
        let reader = reader_of::<Keyed>(&participant, topic, bounded(qos, 2, UNLIMITED));
        let writer = waiting_writer(&participant, topic, std::time::Duration::from_secs(30));
        writer.write(&Keyed { id: 0, value: 1 }).expect("write");
        writer.write(&Keyed { id: 1, value: 1 }).expect("write");
        writer
            .write(&Keyed { id: 2, value: 1 })
            .expect("a best-effort reader holds no writer up");
        let held = take_all_by_instance(&reader);
        assert_eq!(held.keys().copied().collect::<Vec<_>>(), vec![0, 1]);
        let rejected = reader.get_sample_rejected_status();
        assert_eq!(rejected.total_count, 1);
        assert_eq!(rejected.last_reason, SampleRejectedReason::InstanceLimit);
        assert_eq!(
            rejected.last_instance_handle,
            Some(super::InstanceHandle::new(
                Keyed { id: 2, value: 1 }.compute_key()
            ))
        );
        drop(writer);
    }
}

/// A RELIABLE KEEP_LAST reader bounds its instances too: a newer sample of
/// a managed instance replaces the oldest, a new instance beyond
/// `max_instances` has nothing to replace and waits.
#[test]
fn a_reliable_keep_last_local_reader_bounds_its_instances() {
    let domain = unique_domain();
    let participant = local_participant("local_keep_last_instances", domain.id());
    let topic = "LocalKeepLastInstances";
    let reader = reader_of::<Keyed>(
        &participant,
        topic,
        bounded(QoS::reliable().keep_last(1), 2, UNLIMITED),
    );
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));
    for value in 1..=5 {
        writer.write(&Keyed { id: 0, value }).expect("write");
        writer.write(&Keyed { id: 1, value }).expect("write");
    }
    assert!(is_timeout(writer.write(&Keyed { id: 2, value: 1 })));
    let held = take_all_by_instance(&reader);
    let expected: BTreeMap<i32, Vec<i32>> = [(0, vec![5]), (1, vec![5])].into_iter().collect();
    assert_eq!(held, expected);
}

/// Samples a full ring drops because newer ones of their instance replace
/// them leave the history: their instance no longer counts them, and is
/// reclaimed once its writer let it go and the application took the rest.
#[test]
fn samples_replaced_in_a_full_ring_leave_their_instance() {
    let domain = unique_domain();
    let participant = local_participant("local_replaced_leave", domain.id());
    let topic = "LocalReplacedLeave";
    let reader = reader_of::<Keyed>(
        &participant,
        topic,
        bounded(QoS::reliable().keep_last(1), 2, UNLIMITED),
    );
    let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));
    for value in 1..=3000 {
        writer.write(&Keyed { id: 0, value }).expect("write");
    }
    writer.write(&Keyed { id: 1, value: 1 }).expect("write");
    let held = take_all_by_instance(&reader);
    assert_eq!(held.get(&0), Some(&vec![3000]));
    writer
        .unregister_instance(&Keyed { id: 0, value: 0 })
        .expect("unregister");
    while reader.take().expect("take").is_some() {}
    writer
        .write(&Keyed { id: 2, value: 1 })
        .expect("instance 0 holds nothing and no writer holds it");
}

/// DDS v1.4 Sec.2.2.3.19 `max_samples` on a KEEP_LAST reader fed by a local
/// writer: at most `max_samples` samples across its instances. A newer
/// sample of an instance holding `depth` replaces its oldest; one that would
/// grow the history beyond the bound waits (RELIABLE) or is dropped and
/// reported (BEST_EFFORT). The bound applies to local writers.
#[test]
fn a_local_keep_last_reader_bounds_its_samples_across_instances() {
    use crate::dds::listener::SampleRejectedReason;
    let domain = unique_domain();
    let participant = local_participant("local_keep_last_max_samples", domain.id());
    for (reliable, topic) in [(true, "LocalKeepLastMaxRel"), (false, "LocalKeepLastMaxBe")] {
        let mut qos = if reliable {
            QoS::reliable()
        } else {
            QoS::best_effort()
        }
        .keep_last(2);
        qos.resource_limits.max_samples = 3;
        let reader = reader_of::<Keyed>(&participant, topic, qos);
        let writer = waiting_writer(&participant, topic, std::time::Duration::from_millis(50));
        writer.write(&Keyed { id: 0, value: 1 }).expect("write");
        writer.write(&Keyed { id: 0, value: 2 }).expect("write");
        writer
            .write(&Keyed { id: 1, value: 1 })
            .expect("third kept");
        let fourth = writer.write(&Keyed { id: 1, value: 2 });
        if reliable {
            assert!(is_timeout(fourth), "a fourth would grow the history");
            assert_eq!(reader.get_sample_rejected_status().total_count, 0);
        } else {
            fourth.expect("a best-effort reader holds no writer up");
            let rejected = reader.get_sample_rejected_status();
            assert_eq!(rejected.total_count, 1);
            assert_eq!(rejected.last_reason, SampleRejectedReason::ResourceLimit);
        }
        writer
            .write(&Keyed { id: 0, value: 3 })
            .expect("a replacing sample has room");
        let held = take_all_by_instance(&reader);
        let expected: BTreeMap<i32, Vec<i32>> =
            [(0, vec![2, 3]), (1, vec![1])].into_iter().collect();
        assert_eq!(held, expected, "reliable: {reliable}");
        writer
            .write(&Keyed { id: 1, value: 2 })
            .expect("taken: room again");
        assert_eq!(take_all_by_instance(&reader).get(&1), Some(&vec![2]));
        drop(writer);
    }
}

/// DDS v1.4 Sec.2.2.3.18, KEEP_ALL, BEST_EFFORT: at the RESOURCE_LIMITS
/// "the old values will be discarded". A BEST_EFFORT KEEP_ALL reader fed by
/// a local writer keeps the newest `max_samples` samples, the newest
/// `max_samples_per_instance` of each instance, past its ring too, and
/// rejects nothing. Local writers do not bypass either bound.
#[test]
fn a_best_effort_keep_all_local_reader_discards_the_old_values() {
    let domain = unique_domain();
    let participant = local_participant("local_be_keep_all_old", domain.id());

    let topic = "LocalBeKeepAllTotal";
    let reader = reader_of::<Keyed>(&participant, topic, {
        let mut qos = QoS::best_effort().keep_all();
        qos.resource_limits.max_samples = 3;
        qos
    });
    let writer = writer_of::<Keyed>(&participant, topic, QoS::best_effort().keep_all());
    for value in 1..=5 {
        writer.write(&Keyed { id: 0, value }).expect("write");
    }
    assert_eq!(values(&reader), vec![3, 4, 5]);
    assert_eq!(reader.get_sample_rejected_status().total_count, 0);

    let topic = "LocalBeKeepAllRing";
    let reader = reader_of::<Keyed>(&participant, topic, {
        let mut qos = QoS::best_effort().keep_all();
        qos.resource_limits.max_samples = 5;
        qos.resource_limits.max_samples_per_instance = 2;
        qos
    });
    let writer = writer_of::<Keyed>(&participant, topic, QoS::best_effort().keep_all());
    writer.write(&Keyed { id: 2, value: 1 }).expect("write");
    for value in 1..=3000 {
        writer.write(&Keyed { id: 1, value }).expect("write");
    }
    let held = take_all_by_instance(&reader);
    let expected: BTreeMap<i32, Vec<i32>> =
        [(1, vec![2999, 3000]), (2, vec![1])].into_iter().collect();
    assert_eq!(held, expected);
    assert_eq!(reader.get_sample_rejected_status().total_count, 0);

    let topic = "LocalBeKeepAllBurst";
    let reader = reader_of::<Keyed>(&participant, topic, {
        let mut qos = QoS::best_effort().keep_all();
        qos.resource_limits.max_samples = 5;
        qos
    });
    let writer = writer_of::<Keyed>(&participant, topic, QoS::best_effort().keep_all());
    for value in 1..=3000 {
        writer
            .write(&Keyed {
                id: value % 7,
                value,
            })
            .expect("write");
    }
    assert_eq!(values(&reader), (2996..=3000).collect::<Vec<_>>());
    assert_eq!(reader.get_sample_rejected_status().total_count, 0);
}

/// RELIABILITY `max_blocking_time` is the writer's QoS (DDS v1.4
/// Sec.2.2.3.14): a write blocked on a full RELIABLE reader returns TIMEOUT
/// once that much time passed, not after a fixed 100 ms.
#[test]
fn a_write_waits_its_qos_max_blocking_time() {
    let domain = unique_domain();
    let participant = local_participant("qos_max_blocking", domain.id());
    for (topic, wait) in [
        ("QosMaxBlockingShort", std::time::Duration::from_millis(20)),
        ("QosMaxBlockingLong", std::time::Duration::from_millis(400)),
    ] {
        let _reader = reader_of::<Keyed>(&participant, topic, keep_all_reliable(1));
        let writer = waiting_writer(&participant, topic, wait);
        writer
            .write(&Keyed { id: 0, value: 1 })
            .expect("room for one");
        let started = std::time::Instant::now();
        assert!(is_timeout(writer.write(&Keyed { id: 0, value: 2 })));
        let waited = started.elapsed();
        assert!(waited >= wait, "{wait:?}: returned after {waited:?}");
        assert!(
            waited < wait + std::time::Duration::from_millis(70),
            "{wait:?}: returned after {waited:?}"
        );
    }
}

/// DDS v1.4 Sec.2.2.3.17 and Sec.2.2.3.4: local late-joiner replay
/// preserves source ordering, rather than replacing the newest instance
/// value with a later-written but older-timestamped value.
#[test]
fn by_source_local_replay_keeps_the_newest_source_value() {
    let domain = unique_domain();
    let participant = local_participant("source_replay", domain.id());
    let topic = "local_source_replay";
    let writer = writer_of::<Keyed>(
        &participant,
        topic,
        QoS::reliable()
            .transient_local()
            .keep_all()
            .destination_order_by_source(),
    );
    writer
        .write_w_timestamp(&Keyed { id: 1, value: 300 }, 300_000_000_000)
        .expect("DATA@300");
    writer
        .write_w_timestamp(&Keyed { id: 1, value: 200 }, 200_000_000_000)
        .expect("DATA@200");
    let reader = reader_of::<Keyed>(
        &participant,
        topic,
        QoS::reliable()
            .transient_local()
            .keep_last(1)
            .destination_order_by_source(),
    );
    let (data, info) = reader
        .take_with_info()
        .expect("take")
        .expect("retained value");
    assert_eq!(data.map(|s| s.value), Some(300));
    assert_eq!(info.source_timestamp_ns, Some(300_000_000_000));
    assert!(reader.take_with_info().expect("empty").is_none());
}

/// DDS v1.4 Sec.2.2.3.17: replaying genuine source timestamps must not
/// reorder a BY_RECEPTION reader. Historical entries used the same zero
/// reception key; binding A then B therefore presents A before B even
/// when A's application timestamp is greater.
#[test]
fn by_reception_local_replay_ignores_application_source_timestamps() {
    let _ = crate::core::rt::init_slab_pool();
    let topic = "reception_local_replay_source_override";
    let writer = || {
        crate::dds::writer::WriterBuilder::<Keyed>::new(topic.to_string())
            .qos(
                QoS::reliable()
                    .transient_local()
                    .keep_all()
                    .destination_order_by_source(),
            )
            .build()
            .expect("writer")
    };
    let a = writer();
    let b = writer();
    a.write_w_timestamp(&Keyed { id: 1, value: 300 }, 300_000_000_000)
        .expect("A");
    b.write_w_timestamp(&Keyed { id: 1, value: 200 }, 200_000_000_000)
        .expect("B");
    let reader = super::ReaderBuilder::<Keyed>::new(topic.to_string())
        .qos(QoS::reliable().transient_local().keep_last(1))
        .build()
        .expect("reader");
    reader.bind_to_writer(a.merger());
    reader.bind_to_writer(b.merger());
    assert_eq!(reader.take().expect("take").map(|s| s.value), Some(200));
}

/// DDS v1.4 Sec.2.2.2.5.1.3 and Sec.2.2.3.17: a replayed dispose
/// affects its own instance and reports the original source timestamp.
#[test]
fn by_source_local_replay_lifecycle_keeps_its_instance_key() {
    let domain = unique_domain();
    let participant = local_participant("source_replay_lifecycle", domain.id());
    let topic = "local_source_replay_lifecycle";
    let qos = QoS::reliable()
        .transient_local()
        .keep_all()
        .destination_order_by_source();
    let writer = writer_of::<Keyed>(&participant, topic, qos.clone());
    let value = Keyed { id: 1, value: 200 };
    writer
        .write_w_timestamp(&value, 200_000_000_000)
        .expect("DATA");
    writer
        .dispose_w_timestamp(&value, 300_000_000_000)
        .expect("dispose");
    let reader = reader_of::<Keyed>(&participant, topic, qos);
    let (data, _) = reader.take_with_info().expect("take data").expect("DATA");
    assert_eq!(data, Some(value));
    let (data, info) = reader
        .take_with_info()
        .expect("take dispose")
        .expect("dispose");
    assert!(data.is_none());
    assert_eq!(
        info.instance_handle,
        super::InstanceHandle::new(value.compute_key())
    );
    assert_eq!(info.source_timestamp_ns, Some(300_000_000_000));
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
    assert!(reader.take_with_info().expect("empty").is_none());
}

/// DDS v1.4 Sec.2.2.4.3.2: one arrival batch can be announced once,
/// outside binding locks, so a listener can drain the accepted values.
#[test]
fn by_source_local_replay_notifies_once_after_the_batch() {
    use crate::dds::{DataReaderListener, StatusMask};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, Weak,
    };

    struct Listener {
        reader: Weak<DataReader<Keyed>>,
        calls: AtomicUsize,
        payloads: AtomicUsize,
        values: Mutex<Vec<Keyed>>,
    }
    impl DataReaderListener<Keyed> for Listener {
        fn on_data_available(&self, _: &Keyed) {
            self.payloads.fetch_add(1, Ordering::SeqCst);
        }
        fn on_data_available_notification(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let reader = self.reader.upgrade().unwrap();
            if let Some(watch) = reader.deadlines_for_test() {
                for id in [1, 2] {
                    assert!(
                        watch.watches(super::InstanceHandle::new(
                            Keyed { id, value: 0 }.compute_key(),
                        )),
                        "deadline watches precede the batch notification"
                    );
                }
            }
            while let Some(sample) = reader.take().expect("reentrant take") {
                self.values.lock().unwrap().push(sample);
            }
        }
    }

    let _ = crate::core::rt::init_slab_pool();
    for deadline in [false, true] {
        let topic = "source_replay_batch_notification";
        let mut qos = QoS::reliable()
            .transient_local()
            .keep_all()
            .destination_order_by_source();
        if deadline {
            qos = qos.deadline(crate::qos::deadline::Deadline::new(
                std::time::Duration::from_secs(3600),
            ));
        }
        let writer = crate::dds::writer::WriterBuilder::<Keyed>::new(topic.to_string())
            .qos(qos.clone())
            .build()
            .unwrap();
        for sample in [
            Keyed { id: 1, value: 300 },
            Keyed { id: 1, value: 200 },
            Keyed { id: 2, value: 400 },
        ] {
            writer
                .write_w_timestamp(&sample, sample.value as u64)
                .unwrap();
        }
        let reader = Arc::new(
            super::ReaderBuilder::<Keyed>::new(topic.to_string())
                .qos(qos)
                .build()
                .unwrap(),
        );
        let listener = Arc::new(Listener {
            reader: Arc::downgrade(&reader),
            calls: AtomicUsize::new(0),
            payloads: AtomicUsize::new(0),
            values: Mutex::new(Vec::new()),
        });
        reader.set_listener(Some(listener.clone()), StatusMask::DATA_AVAILABLE);
        let (tx, rx) = std::sync::mpsc::channel();
        let bound = Arc::clone(&reader);
        let merger = writer.merger();
        let thread = std::thread::spawn(move || {
            bound.bind_to_writer(merger);
            tx.send(()).unwrap();
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("replay callback runs after binding locks are released");
        thread.join().unwrap();
        assert_eq!(
            listener.calls.load(Ordering::SeqCst),
            1,
            "one notice for the replay batch"
        );
        assert_eq!(listener.payloads.load(Ordering::SeqCst), 0);
        assert_eq!(
            *listener.values.lock().unwrap(),
            vec![Keyed { id: 1, value: 300 }, Keyed { id: 2, value: 400 }]
        );
        if deadline {
            for id in [1, 2] {
                assert!(
                    reader
                        .deadlines_for_test()
                        .unwrap()
                        .watches(super::InstanceHandle::new(
                            Keyed { id, value: 0 }.compute_key()
                        ),),
                    "every replayed instance retains its deadline watch"
                );
            }
        }
        // A repeated binding queues no new data and owes no new notice.
        reader.bind_to_writer(writer.merger());
        assert_eq!(listener.calls.load(Ordering::SeqCst), 1);
        // Masking the listener suppresses a replay's notification.
        reader.set_listener(Some(listener.clone()), StatusMask::NONE);
        let mut other_qos = QoS::reliable()
            .transient_local()
            .keep_all()
            .destination_order_by_source();
        if deadline {
            other_qos = other_qos.deadline(crate::qos::deadline::Deadline::new(
                std::time::Duration::from_secs(3600),
            ));
        }
        let other = crate::dds::writer::WriterBuilder::<Keyed>::new(topic.to_string())
            .qos(other_qos)
            .build()
            .unwrap();
        other
            .write_w_timestamp(&Keyed { id: 3, value: 500 }, 500)
            .unwrap();
        reader.bind_to_writer(other.merger());
        assert_eq!(listener.calls.load(Ordering::SeqCst), 1);
        assert_eq!(reader.take().unwrap(), Some(Keyed { id: 3, value: 500 }));
    }
}

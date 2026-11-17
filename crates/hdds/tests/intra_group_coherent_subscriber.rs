// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! GROUP-scope coherent presentation read through a Subscriber's access
//! brackets, across several DataWriters of one Publisher, over the
//! intra-process delivery path (DDS v1.4 SS2.2.2.4.1.10
//! `begin_coherent_changes`, SS2.2.2.5.2.8 `begin_access`, SS2.2.3.6
//! PRESENTATION; RTPS v2.5 SS8.7.5, SS8.7.6).
//!
//! The set is every change of every DataWriter of the Publisher between
//! `begin_coherent_changes` and `end_coherent_changes`. A Subscriber of the
//! same access scope reads it whole, across all of its DataReaders, and
//! only inside `begin_access`/`end_access`: a bracket that is open when the
//! set completes sees nothing of it until it ends.
//!
//! Each test names the one rule it holds; the collection below is
//! `coherent_publication` (the bracket against the coordinator's decision),
//! `local_group` (the Publisher-wide collector) and the barrier's local
//! retry.

use hdds::dds::{DataReaderListener, SampleRejectedReason, Subscriber, Topic};
use hdds::qos::ResourceLimits;
use hdds::{Participant, QoS, TransportMode};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, hdds::DDS)]
struct Item {
    value: i32,
}

fn group_qos(ordered: bool) -> QoS {
    let qos = QoS::reliable().transient_local().keep_all();
    if ordered {
        qos.presentation_group_coherent_ordered()
    } else {
        qos.presentation_group_coherent()
    }
}

/// A Publisher, a Subscriber and their writers/readers, all in one process
/// and all on the same access scope. Writer `i` owns topic `i`; reader `i`
/// reads topic `i` (the first `readers` topics).
struct Group {
    _participant: Arc<Participant>,
    _topics: Vec<Topic<Item>>,
    publisher: Arc<hdds::dds::Publisher>,
    subscriber: Arc<Subscriber>,
    writers: Vec<hdds::DataWriter<Item>>,
    readers: Vec<hdds::DataReader<Item>>,
}

fn group(name: &str, writers: usize, readers: usize, ordered: bool) -> Group {
    group_with_qos(name, writers, readers, group_qos(ordered))
}

fn group_with_qos(name: &str, writers: usize, readers: usize, qos: QoS) -> Group {
    let participant = Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let mut topics = Vec::new();
    let mut data_writers = Vec::new();
    let mut data_readers = Vec::new();
    for index in 0..writers {
        let topic = participant
            .topic::<Item>(&format!("{name}-t{index}"))
            .unwrap();
        data_writers.push(
            topic
                .writer()
                .qos(qos.clone())
                .publisher(&publisher)
                .build()
                .unwrap(),
        );
        if index < readers {
            data_readers.push(
                topic
                    .reader()
                    .qos(qos.clone())
                    .subscriber(&subscriber)
                    .build()
                    .unwrap(),
            );
        }
        topics.push(topic);
    }
    Group {
        _participant: participant,
        _topics: topics,
        publisher,
        subscriber,
        writers: data_writers,
        readers: data_readers,
    }
}

/// Everything `reader` holds, taken inside one access bracket: a reader of
/// a GROUP-scope Subscriber refuses a take outside one (DDS v1.4
/// Sec.2.2.2.5.2.8).
fn take_in_bracket(subscriber: &Subscriber, reader: &hdds::DataReader<Item>) -> Vec<i32> {
    subscriber.begin_access().unwrap();
    let mut values = Vec::new();
    while let Some(sample) = reader.take().unwrap() {
        values.push(sample.value);
    }
    subscriber.end_access().unwrap();
    values
}

/// [`take_in_bracket`] until `expected` values are collected or `timeout`
/// elapses: a set that completed while an access bracket was open is
/// delivered when that bracket closes, and that delivery can run on the
/// Subscriber's publishing thread.
fn take_eventually(
    subscriber: &Subscriber,
    reader: &hdds::DataReader<Item>,
    expected: usize,
    timeout: Duration,
) -> Vec<i32> {
    let deadline = Instant::now() + timeout;
    let mut values = Vec::new();
    loop {
        values.extend(take_in_bracket(subscriber, reader));
        if values.len() >= expected || Instant::now() >= deadline {
            return values;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// One coherent set spanning every writer of one Publisher, read by two
/// readers of one Subscriber: each reader sees its own writer's members,
/// whole, in its writer's order and once, and nothing while the set is
/// open. A writer with no reader of its own still has to end the set.
fn a_group_set_spans_every_writer_of_its_publisher(writer_count: usize, ordered: bool) {
    let name = format!("intra-group-{writer_count}-{ordered}");
    let g = group(&name, writer_count, 2, ordered);

    g.publisher.begin_coherent_changes().unwrap();
    for (index, writer) in g.writers.iter().enumerate() {
        let base = 10 * (index as i32 + 1);
        writer.write(&Item { value: base }).unwrap();
        writer.write(&Item { value: base + 1 }).unwrap();
    }
    // A bracket opened while the set is open publishes every COMPLETE
    // generation (DDS v1.4 Sec.2.2.2.5.2.8) and nothing of this one.
    for reader in &g.readers {
        assert_eq!(
            take_in_bracket(&g.subscriber, reader),
            Vec::<i32>::new(),
            "an open coherent set reached a reader"
        );
    }

    g.publisher.end_coherent_changes().unwrap();

    for (index, reader) in g.readers.iter().enumerate() {
        let base = 10 * (index as i32 + 1);
        assert_eq!(
            take_in_bracket(&g.subscriber, reader),
            vec![base, base + 1],
            "reader {index} must see its writer's part of the set, in order"
        );
    }
    for reader in &g.readers {
        assert_eq!(
            take_in_bracket(&g.subscriber, reader),
            Vec::<i32>::new(),
            "one set is delivered once"
        );
    }
}

#[test]
fn a_group_set_of_two_writers_is_read_whole() {
    a_group_set_spans_every_writer_of_its_publisher(2, false);
}

#[test]
fn a_group_set_of_two_writers_is_read_whole_ordered() {
    a_group_set_spans_every_writer_of_its_publisher(2, true);
}

#[test]
fn a_group_set_of_three_writers_is_read_whole() {
    a_group_set_spans_every_writer_of_its_publisher(3, false);
}

#[test]
fn a_group_set_of_three_writers_is_read_whole_ordered() {
    a_group_set_spans_every_writer_of_its_publisher(3, true);
}

/// A polling condition may drain a ring before publication notifications.
/// Its decoded member must already belong to the shared Publisher order.
#[test]
fn a_condition_pump_never_observes_an_untracked_group_member() {
    use hdds::dds::{Condition, InstanceStateMask, SampleStateMask, ViewStateMask};
    let mut g = group("intra-group-condition-order", 2, 2, true);
    let first = Arc::new(g.readers.remove(0));
    let condition = first
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .unwrap();
    // Leave an earlier arrival raised, so the condition pumps even before
    // the coherent transaction sends its own deferred notifications.
    g.writers[0].write(&Item { value: 0 }).unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    hdds::test_support::coherent_race::after_next_push(move || {
        assert!(condition.get_trigger_value());
    });
    g.publisher.end_coherent_changes().unwrap();
    g.subscriber.begin_access().unwrap();
    assert_eq!(first.take().unwrap().unwrap().value, 0);
    assert_eq!(first.take().unwrap().unwrap().value, 1);
    assert_eq!(g.readers[0].take().unwrap().unwrap().value, 2);
    g.subscriber.end_access().unwrap();
}

/// Writer sequence order applies across the boundary of a coherent set.
#[test]
fn an_ordinary_write_cannot_overtake_its_writers_retained_set() {
    let g = group("intra-group-ordinary-tail", 2, 2, false);
    g.subscriber.begin_access().unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    let mut inside = Vec::new();
    while let Some(sample) = g.readers[0].take().unwrap() {
        inside.push(sample.value);
    }
    g.subscriber.end_access().unwrap();
    let after = take_in_bracket(&g.subscriber, &g.readers[0]);
    assert!(
        inside.is_empty(),
        "ordinary tail overtook its retained coherent prefix: {inside:?}"
    );
    assert_eq!(after, vec![1, 3]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);
}

#[test]
fn durable_replay_keeps_ordinary_samples_after_their_coherent_prefix() {
    let mut g = group("intra-group-replay-tail", 2, 0, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    for topic in &g._topics {
        g.readers.push(
            topic
                .reader()
                .qos(group_qos(false))
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
    }
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 3]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);
}

#[test]
fn a_live_ordinary_write_waits_for_older_durable_replay() {
    let mut g = group("intra-group-replay-live-tail", 2, 0, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    for topic in &g._topics {
        g.readers.push(
            topic
                .reader()
                .qos(group_qos(false))
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
    }
    g.writers[0].write(&Item { value: 3 }).unwrap();
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 3]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);
}

#[test]
fn an_ordinary_tail_cannot_bypass_its_writers_blocked_ordered_member() {
    let g = group("intra-group-ordered-ordinary-tail", 2, 2, true);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[1].write(&Item { value: 1 }).unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    g.subscriber.begin_access().unwrap();
    let blocked = g.readers[0].take().unwrap();
    assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 1 }));
    let first = g.readers[0].take().unwrap();
    let second = g.readers[0].take().unwrap();
    g.subscriber.end_access().unwrap();
    assert_eq!(
        blocked, None,
        "ordinary tail bypassed an earlier change of its writer"
    );
    assert_eq!(
        (first, second),
        (Some(Item { value: 2 }), Some(Item { value: 3 }))
    );
}

#[test]
fn a_condition_reconciles_a_replaced_coherent_prefix_before_matching_its_tail() {
    use hdds::dds::{Condition, InstanceStateMask, SampleStateMask, ViewStateMask};
    let g = group("intra-group-condition-replaced-prefix", 1, 0, true);
    let reader = Arc::new(
        g._topics[0]
            .reader()
            .qos(group_qos(true).keep_last(1))
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    let condition = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    assert!(
        condition.get_trigger_value(),
        "an evicted coherent token cannot hide its ordinary replacement"
    );
    assert_eq!(take_in_bracket(&g.subscriber, &reader), vec![2]);
}

#[test]
fn a_condition_cannot_take_unregister_before_its_writers_ordered_data() {
    use hdds::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};
    let mut g = group("intra-group-condition-unregister-tail", 2, 2, true);
    let first_reader = Arc::new(g.readers.remove(0));
    let condition = first_reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[1].write(&Item { value: 1 }).unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.writers[0]
        .unregister_instance(&Item { value: 2 })
        .unwrap();
    g.subscriber.begin_access().unwrap();
    let blocked = first_reader.take_w_condition(&condition, 2).unwrap();
    assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 1 }));
    let after = first_reader.take_w_condition(&condition, 2).unwrap();
    g.subscriber.end_access().unwrap();
    assert!(
        blocked.is_empty(),
        "lifecycle tail bypassed its writer's earlier ordered data"
    );
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].0, Some(Item { value: 2 }));
    assert!(after[1].0.is_none() && !after[1].1.valid_data);
}

#[test]
fn held_replay_fences_later_history_targeting_another_subscriber() {
    let mut g = group("intra-group-replay-subscriber-fence", 1, 0, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.subscriber.begin_access().unwrap();
    g.readers.push(
        g._topics[0]
            .reader()
            .qos(group_qos(false))
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    g.writers[0].write(&Item { value: 2 }).unwrap();
    let other = Arc::new(g._participant.create_subscriber(group_qos(false)).unwrap());
    let late = g._topics[0]
        .reader()
        .qos(group_qos(false))
        .subscriber(&other)
        .build()
        .unwrap();
    other.begin_access().unwrap();
    let inside = late.take().unwrap();
    other.end_access().unwrap();
    g.subscriber.end_access().unwrap();
    assert!(
        inside.is_none(),
        "later ordinary replay overtook a held coherent set"
    );
    assert_eq!(take_in_bracket(&other, &late), vec![1, 2]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 2]);
}

#[derive(Debug, Clone, Copy, PartialEq, hdds::DDS)]
struct KeyedItem {
    #[key]
    key: i32,
    value: i32,
}

struct KeyedGroup {
    _participant: Arc<Participant>,
    topic: Topic<KeyedItem>,
    qos: QoS,
    publisher: Arc<hdds::dds::Publisher>,
    subscriber: Arc<Subscriber>,
    writer: Option<hdds::DataWriter<KeyedItem>>,
    reader: Option<hdds::DataReader<KeyedItem>>,
}

fn keyed_group(name: &str, durable: bool, reader: bool) -> KeyedGroup {
    keyed_group_with_reliability(name, durable, reader, true)
}

fn keyed_group_with_reliability(
    name: &str,
    durable: bool,
    reader: bool,
    reliable: bool,
) -> KeyedGroup {
    let mut qos = group_qos(false);
    if !reliable {
        qos.reliability = hdds::dds::qos::Reliability::BestEffort;
    }
    if !durable {
        qos.durability = hdds::dds::qos::Durability::Volatile;
    }
    let participant = Participant::builder(name)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let topic = participant.topic::<KeyedItem>(name).unwrap();
    let writer = Some(
        topic
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap(),
    );
    let reader = reader.then(|| {
        topic
            .reader()
            .qos(qos.clone())
            .subscriber(&subscriber)
            .build()
            .unwrap()
    });
    KeyedGroup {
        _participant: participant,
        topic,
        qos,
        publisher,
        subscriber,
        writer,
        reader,
    }
}

fn unregister_tail_after_a_retained_set(deleting: bool) {
    let mut g = keyed_group(
        if deleting {
            "intra-group-drop-tail"
        } else {
            "intra-group-unregister-tail"
        },
        false,
        true,
    );
    let value = KeyedItem { key: 1, value: 1 };
    g.subscriber.begin_access().unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writer.as_ref().unwrap().write(&value).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    if deleting {
        drop(g.writer.take());
    } else {
        g.writer
            .as_ref()
            .unwrap()
            .unregister_instance(&value)
            .unwrap();
    }
    let reader = g.reader.as_ref().unwrap();
    let inside = reader.take_with_info().unwrap();
    g.subscriber.end_access().unwrap();
    g.subscriber.begin_access().unwrap();
    let first = reader.take_with_info().unwrap();
    let second = reader.take_with_info().unwrap();
    g.subscriber.end_access().unwrap();
    assert!(
        inside.is_none(),
        "unregister overtook a retained coherent member"
    );
    let (data, info) = first.expect("coherent data before unregister");
    assert_eq!(data, Some(value));
    assert!(info.valid_data);
    let (data, info) = second.expect("unregister after coherent data");
    assert!(data.is_none() && !info.valid_data);
}

#[test]
fn unregister_cannot_overtake_its_writers_retained_set() {
    unregister_tail_after_a_retained_set(false);
}

#[test]
fn deleting_a_writer_keeps_its_unregister_after_its_retained_set() {
    unregister_tail_after_a_retained_set(true);
}

#[test]
fn deleting_a_writer_keeps_ordinary_tails_waiting_behind_replay_alive() {
    let mut g = keyed_group("intra-group-drop-replay-tail", true, false);
    let first = KeyedItem { key: 1, value: 1 };
    let second = KeyedItem { key: 1, value: 2 };
    g.publisher.begin_coherent_changes().unwrap();
    g.writer.as_ref().unwrap().write(&first).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.reader = Some(
        g.topic
            .reader()
            .qos(g.qos.clone())
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    g.writer.as_ref().unwrap().write(&second).unwrap();
    drop(g.writer.take());
    g.subscriber.begin_access().unwrap();
    let reader = g.reader.as_ref().unwrap();
    let a = reader.take_with_info().unwrap();
    let b = reader.take_with_info().unwrap();
    let c = reader.take_with_info().unwrap();
    g.subscriber.end_access().unwrap();
    assert_eq!(a.expect("older replay").0, Some(first));
    assert_eq!(b.expect("retained ordinary tail").0, Some(second));
    let (sample, info) = c.expect("retained unregister");
    assert!(sample.is_none() && !info.valid_data);
}

#[test]
fn a_deferred_ordinary_tail_keeps_its_original_volatile_destinations() {
    let g = keyed_group("intra-group-volatile-tail-cut", false, true);
    let first = KeyedItem { key: 1, value: 1 };
    let second = KeyedItem { key: 1, value: 2 };
    g.subscriber.begin_access().unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writer.as_ref().unwrap().write(&first).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.writer.as_ref().unwrap().write(&second).unwrap();
    let late = g
        .topic
        .reader()
        .qos(g.qos.clone())
        .subscriber(&g.subscriber)
        .build()
        .unwrap();
    g.subscriber.end_access().unwrap();
    g.subscriber.begin_access().unwrap();
    let original = g.reader.as_ref().unwrap();
    let a = original.take().unwrap();
    let b = original.take().unwrap();
    let c = late.take().unwrap();
    let d = late.take().unwrap();
    g.subscriber.end_access().unwrap();
    assert_eq!((a, b), (Some(first), Some(second)));
    assert_eq!(
        (c, d),
        (Some(first), None),
        "a volatile late join does not inherit an older ordinary write"
    );
}

#[test]
fn an_empty_drain_cannot_remove_a_newly_queued_stream_hold() {
    let mut g = keyed_group("intra-group-retention-handoff", true, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writer
        .as_ref()
        .unwrap()
        .write(&KeyedItem { key: 1, value: 1 })
        .unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.reader = Some(
        g.topic
            .reader()
            .qos(g.qos.clone())
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    g.writer
        .as_ref()
        .unwrap()
        .write(&KeyedItem { key: 1, value: 2 })
        .unwrap();
    let (observed, empty) = std::sync::mpsc::channel();
    let (resume, resumed) = std::sync::mpsc::channel();
    let subscriber = g.subscriber.clone();
    let drain = std::thread::spawn(move || {
        hdds::test_support::coherent_race::before_next_stream_retention(move || {
            observed.send(()).unwrap();
            resumed
                .recv_timeout(Duration::from_secs(10))
                .expect("resume retention update");
        });
        subscriber.begin_access().unwrap();
        subscriber.end_access().unwrap();
    });
    empty
        .recv_timeout(Duration::from_secs(10))
        .expect("empty drain reached retention update");
    let other = Arc::new(g._participant.create_subscriber(g.qos.clone()).unwrap());
    let late = g
        .topic
        .reader()
        .qos(g.qos.clone())
        .subscriber(&other)
        .build()
        .unwrap();
    g.writer
        .as_ref()
        .unwrap()
        .write(&KeyedItem { key: 1, value: 3 })
        .unwrap();
    drop(g.writer.take());
    resume.send(()).unwrap();
    drain.join().unwrap();
    other.begin_access().unwrap();
    let mut values = Vec::new();
    let mut unregister = false;
    while let Some((data, info)) = late.take_with_info().unwrap() {
        if let Some(data) = data {
            values.push(data.value);
        } else {
            unregister |= !info.valid_data;
        }
    }
    other.end_access().unwrap();
    assert_eq!(
        values,
        vec![1, 2, 3],
        "a stale empty retirement lost newly queued changes"
    );
    assert!(
        unregister,
        "writer deletion must keep its queued unregister alive"
    );
}

#[test]
fn an_interrupted_delivery_releases_the_publication_owner() {
    let g = group("intra-group-interrupted-owner", 2, 2, false);
    hdds::test_support::coherent_race::before_next_group_delivery(|| {
        panic!("interrupted publication");
    });
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g
        .publisher
        .end_coherent_changes()))
    .is_err());
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    g.writers[1].write(&Item { value: 4 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 3]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2, 4]);
}

fn lifecycle_before_a_late_reader(dispose: bool, durable: bool, reliable: bool) {
    let mut g = keyed_group_with_reliability(
        &format!("intra-group-late-lifecycle-{dispose}-{durable}-{reliable}"),
        durable,
        false,
        reliable,
    );
    let value = KeyedItem { key: 1, value: 1 };
    g.publisher.begin_coherent_changes().unwrap();
    let writer = g.writer.as_ref().unwrap();
    writer.write(&value).unwrap();
    if dispose {
        writer.dispose(&value).unwrap();
    } else {
        writer.unregister_instance(&value).unwrap();
    }
    g.reader = Some(
        g.topic
            .reader()
            .qos(g.qos.clone())
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    g.publisher.end_coherent_changes().unwrap();
    g.subscriber.begin_access().unwrap();
    let reader = g.reader.as_ref().unwrap();
    let data = reader.take_with_info().unwrap();
    let lifecycle = reader.take_with_info().unwrap();
    g.subscriber.end_access().unwrap();
    assert_eq!(data.expect("earlier data").0, Some(value));
    let (sample, info) =
        lifecycle.expect("earlier lifecycle member must survive without a local reader");
    assert!(sample.is_none() && !info.valid_data);
}

#[test]
fn a_late_reader_gets_the_dispose_written_before_it_existed() {
    for durable in [false, true] {
        for reliable in [false, true] {
            lifecycle_before_a_late_reader(true, durable, reliable);
        }
    }
}

#[test]
fn a_late_reader_gets_the_unregister_written_before_it_existed() {
    for durable in [false, true] {
        for reliable in [false, true] {
            lifecycle_before_a_late_reader(false, durable, reliable);
        }
    }
}

/// The readers are told once, when the whole group is in (RTPS v2.5
/// Sec.8.7.6): a reader already blocked on a WaitSet is woken by the set,
/// rather than left to its own timeout.
#[test]
fn a_group_set_wakes_a_waitset_reader_blocked_on_it() {
    let g = group("intra-group-waitset", 2, 2, false);
    let waitset = Arc::new(hdds::WaitSet::new());
    waitset.attach(&g.readers[1]).unwrap();
    let (armed, ready) = std::sync::mpsc::channel();
    hdds::test_support::coherent_race::before_next_wait(&waitset, move || {
        armed.send(()).unwrap();
    });
    let waiter = {
        let waitset = Arc::clone(&waitset);
        std::thread::spawn(move || waitset.wait(Some(Duration::from_secs(5))))
    };
    // The false initial scan has finished. Publication now has to signal
    // the driver, whether it reaches the OS wait before or after the signal.
    ready
        .recv_timeout(Duration::from_secs(2))
        .expect("waiter armed");

    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();

    assert!(
        waiter.join().unwrap().is_ok(),
        "the group set must wake the reader waiting on it"
    );
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);
}

/// Durable history is available before the application's first bracket.
/// Waiting for DATA_AVAILABLE must not require begin_access to cause it.
#[test]
fn durable_group_replay_raises_data_available_before_begin_access() {
    let mut g = group("intra-group-replay-waitset", 2, 0, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    for topic in &g._topics {
        g.readers.push(
            topic
                .reader()
                .qos(group_qos(false))
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
    }
    let waitset = hdds::WaitSet::new();
    waitset.attach(&g.readers[1]).unwrap();
    assert!(
        waitset.wait(Some(Duration::from_millis(100))).is_ok(),
        "retained replay must announce DATA_AVAILABLE without new traffic or an access transition"
    );
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);
}

/// The bracket that matters: it is open when `end_coherent_changes`
/// completes the set. Nothing may reach the readers before it ends, however
/// long the delivery thread has; the set is delivered at the outermost
/// `end_access`, whole, to every reader.
#[test]
fn a_set_completed_inside_an_access_bracket_waits_for_its_end() {
    let g = group("intra-group-bracket", 2, 2, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();

    g.subscriber.begin_access().unwrap();
    g.publisher.end_coherent_changes().unwrap();
    let mut inside_a = Vec::new();
    while let Some(sample) = g.readers[0].take().unwrap() {
        inside_a.push(sample.value);
    }
    let mut inside_b = Vec::new();
    while let Some(sample) = g.readers[1].take().unwrap() {
        inside_b.push(sample.value);
    }
    assert!(
        inside_a.is_empty() && inside_b.is_empty(),
        "a set completed inside an open bracket reached the rings: \
         {inside_a:?} {inside_b:?}"
    );
    g.subscriber.end_access().unwrap();

    assert_eq!(
        take_eventually(&g.subscriber, &g.readers[0], 1, Duration::from_secs(5)),
        vec![1]
    );
    assert_eq!(
        take_eventually(&g.subscriber, &g.readers[1], 1, Duration::from_secs(5)),
        vec![2]
    );
}

/// The readers' listeners are told only once the WHOLE group is in every
/// ring: a listener told of writer A's part, opening the Subscriber's
/// bracket and reading writer B's reader, finds B's part there.
#[test]
fn a_listener_of_one_part_finds_the_other_parts_in_place() {
    struct Peek {
        subscriber: Arc<Subscriber>,
        other: Arc<hdds::DataReader<Item>>,
        seen: Arc<std::sync::Mutex<Vec<i32>>>,
    }

    impl DataReaderListener<Item> for Peek {
        fn on_data_available(&self, _sample: &Item) {
            self.subscriber.begin_access().unwrap();
            let mut values = Vec::new();
            while let Some(sample) = self.other.take().unwrap() {
                values.push(sample.value);
            }
            self.subscriber.end_access().unwrap();
            *self.seen.lock().unwrap() = values;
        }
    }

    let qos = group_qos(false);
    let participant = Participant::builder("intra-group-listener")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic_a = participant.topic::<Item>("intra-group-listener-a").unwrap();
    let topic_b = participant.topic::<Item>("intra-group-listener-b").unwrap();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let writer_a = topic_a
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic_b
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let reader_b = Arc::new(
        topic_b
            .reader()
            .qos(qos.clone())
            .subscriber(&subscriber)
            .build()
            .unwrap(),
    );
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = Arc::new(Peek {
        subscriber: Arc::clone(&subscriber),
        other: Arc::clone(&reader_b),
        seen: Arc::clone(&seen),
    });
    let reader_a = topic_a
        .reader()
        .qos(qos.clone())
        .subscriber(&subscriber)
        .with_listener(Arc::clone(&listener) as Arc<dyn DataReaderListener<Item>>)
        .build()
        .unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 1 }).unwrap();
    writer_b.write(&Item { value: 2 }).unwrap();
    publisher.end_coherent_changes().unwrap();

    assert_eq!(
        *seen.lock().unwrap(),
        vec![2],
        "the listener of writer A's part read writer B's reader torn"
    );
    assert_eq!(take_in_bracket(&subscriber, &reader_a), vec![1]);
}

/// A writer whose handle the application deletes mid-set: the Publisher
/// holds its writers until the set ends (RTPS v2.5 Sec.8.7.6), so the part
/// it already staged still closes with the set and reaches its reader.
#[test]
fn a_writer_dropped_mid_set_still_completes_the_group() {
    let mut g = group("intra-group-drop", 2, 2, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    let deleted = g.writers.pop().expect("writer B");
    drop(deleted);
    g.publisher.end_coherent_changes().unwrap();

    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1]);
    assert_eq!(
        take_in_bracket(&g.subscriber, &g.readers[1]),
        vec![2],
        "the deleted writer's part of the set must still reach its reader"
    );
}

/// Every writer of the set owes a part, the ones with no change included
/// (RTPS v2.5 Sec.8.7.6: every writer of the Publisher ends the set): the
/// set is delivered although only one writer changed anything, and the next
/// set is not left waiting for the part the idle writer still owed.
#[test]
fn a_writer_with_no_change_still_closes_the_set() {
    let g = group("intra-group-idle", 2, 2, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();

    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1]);
    assert_eq!(
        take_in_bracket(&g.subscriber, &g.readers[1]),
        Vec::<i32>::new(),
        "the idle writer's reader gets nothing of the set"
    );

    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![2]);
}

/// A late joiner's replay keeps the set boundaries: the closed GROUP set is
/// replayed whole, nothing of the still-open one (DDS v1.4
/// Sec.2.2.2.4.1.10/11, RTPS v2.5 Sec.8.7.6).
#[test]
fn a_late_joiner_replays_a_closed_group_set_whole_and_holds_the_open_one() {
    let qos = group_qos(false);
    let participant = Participant::builder("intra-group-late")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic_a = participant.topic::<Item>("intra-group-late-a").unwrap();
    let topic_b = participant.topic::<Item>("intra-group-late-b").unwrap();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let writer_a = topic_a
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic_b
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 1 }).unwrap();
    writer_a.write(&Item { value: 2 }).unwrap();
    writer_b.write(&Item { value: 3 }).unwrap();
    publisher.end_coherent_changes().unwrap();
    // A second set, left open: neither writer's history may hand any part
    // of it to a late joiner.
    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 99 }).unwrap();

    let late_a = topic_a
        .reader()
        .qos(qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let late_b = topic_b
        .reader()
        .qos(qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();

    assert_eq!(
        take_in_bracket(&subscriber, &late_a),
        vec![1, 2],
        "writer A's late joiner: its share of the closed set, nothing of the open one"
    );
    assert_eq!(
        take_in_bracket(&subscriber, &late_b),
        vec![3],
        "writer B's late joiner"
    );
    assert_eq!(take_in_bracket(&subscriber, &late_a), Vec::<i32>::new());
}

/// A set larger than a reader's RESOURCE_LIMITS reaches NO reader of the
/// Subscriber: the local counterpart of the wire leg declaring an
/// incomplete set lost (RTPS v2.5 Sec.8.7.6, "Incomplete coherent sets
/// shall not be added"). The reader that lacks the room reports every
/// member it will not get (DDS v1.4 Sec.2.2.3.19, SAMPLE_REJECTED).
#[test]
fn a_group_set_that_does_not_fit_reaches_no_local_reader() {
    let mut qos = group_qos(false);
    qos.reliability_max_blocking_time = Duration::from_millis(20);
    let mut small = qos.clone();
    small.resource_limits = ResourceLimits {
        max_samples: 1,
        ..ResourceLimits::default()
    };

    let participant = Participant::builder("intra-group-limits")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic_a = participant.topic::<Item>("intra-group-limits-a").unwrap();
    let topic_b = participant.topic::<Item>("intra-group-limits-b").unwrap();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let writer_a = topic_a
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = topic_b
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let reader_a = topic_a
        .reader()
        .qos(small)
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let reader_b = topic_b
        .reader()
        .qos(qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();

    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Item { value: 1 }).unwrap();
    writer_a.write(&Item { value: 2 }).unwrap();
    writer_b.write(&Item { value: 3 }).unwrap();
    publisher.end_coherent_changes().unwrap();

    assert_eq!(
        take_in_bracket(&subscriber, &reader_a),
        Vec::<i32>::new(),
        "a reader with room for one sample got a two-sample set"
    );
    assert_eq!(
        take_in_bracket(&subscriber, &reader_b),
        Vec::<i32>::new(),
        "a set that reaches no reader of the group reaches none of them"
    );
    let status = reader_a.get_sample_rejected_status();
    assert_eq!(
        status.total_count, 2,
        "both members of writer A's part were refused: {status:?}"
    );
    assert_eq!(status.last_reason, SampleRejectedReason::ResourceLimit);
}

// A blocked worker must fail this test instead of hanging the test process.
fn bounded(test: impl FnOnce() + Send + 'static) {
    let (done, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
        let _ = done.send(outcome);
    });
    match result
        .recv_timeout(Duration::from_secs(5))
        .expect("delivery or callback deadlocked")
    {
        Ok(()) => (),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// DDS 2.2.2.5.2.8: a listener released by end_access can open and close
/// another bracket and inspect every reader without retaining retry locks.
#[test]
fn end_access_listener_can_reenter_the_same_subscriber() {
    bounded(|| {
        struct Reenter(Arc<Subscriber>, Arc<hdds::DataReader<Item>>);
        impl DataReaderListener<Item> for Reenter {
            fn on_data_available(&self, _: &Item) {
                self.0.begin_access().unwrap();
                assert_eq!(self.1.take().unwrap(), Some(Item { value: 2 }));
                self.0.end_access().unwrap();
            }
        }
        let mut g = group("retry-listener", 2, 2, false);
        let other = Arc::new(g.readers.pop().unwrap());
        g.readers[0].set_listener(
            Some(Arc::new(Reenter(g.subscriber.clone(), other))),
            hdds::dds::StatusMask::DATA_AVAILABLE,
        );
        g.publisher.begin_coherent_changes().unwrap();
        g.writers[0].write(&Item { value: 1 }).unwrap();
        g.writers[1].write(&Item { value: 2 }).unwrap();
        g.subscriber.begin_access().unwrap();
        g.publisher.end_coherent_changes().unwrap();
        g.subscriber.end_access().unwrap();
    });
}

/// WaitsetSignal is public application code, just like a listener. A hook
/// must be able to enter a bracket after the entire set is published.
#[test]
fn a_waitset_hook_can_open_a_bracket_during_group_delivery() {
    bounded(|| {
        use hdds::dds::Condition;
        struct Hook(Arc<Subscriber>, Arc<std::sync::atomic::AtomicUsize>);
        impl hdds::core::rt::waitset::WaitsetSignal for Hook {
            fn id(&self) -> u64 {
                1
            }
            fn signal(&self) {
                self.0.begin_access().unwrap();
                self.0.end_access().unwrap();
                self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let g = group("hook-bracket", 2, 2, false);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hook: Arc<dyn hdds::core::rt::waitset::WaitsetSignal> =
            Arc::new(Hook(g.subscriber.clone(), calls.clone()));
        g.readers[0]
            .get_status_condition()
            .add_waitset_signal(hook.clone());
        g.publisher.begin_coherent_changes().unwrap();
        g.writers[0].write(&Item { value: 1 }).unwrap();
        g.writers[1].write(&Item { value: 2 }).unwrap();
        g.publisher.end_coherent_changes().unwrap();
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1]);
    });
}

/// DDS 2.2.3.6 and RTPS 8.7.6: a BEST_EFFORT capacity skip cannot count
/// as a successful admission of one member of a coherent set.
#[test]
fn a_small_best_effort_reader_never_receives_a_prefix_of_a_group() {
    bounded(|| {
        let mut g = group("mixed-limits", 2, 0, false);
        let mut small = group_qos(false);
        small.reliability = hdds::dds::qos::Reliability::BestEffort;
        small.resource_limits.max_samples = 1;
        g.readers.push(
            g._topics[0]
                .reader()
                .qos(small)
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
        g.readers.push(
            g._topics[1]
                .reader()
                .qos(group_qos(false))
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
        g.publisher.begin_coherent_changes().unwrap();
        g.writers[0].write(&Item { value: 1 }).unwrap();
        g.writers[0].write(&Item { value: 2 }).unwrap();
        g.writers[1].write(&Item { value: 3 }).unwrap();
        g.publisher.end_coherent_changes().unwrap();
        assert!(take_in_bracket(&g.subscriber, &g.readers[0]).is_empty());
        assert!(take_in_bracket(&g.subscriber, &g.readers[1]).is_empty());
    });
}

/// DDS 2.2.3.18: reserve two incoming ring positions, replacing old
/// KEEP_LAST values, even when only one physical position was free.
#[test]
fn keep_last_makes_room_for_all_members_before_publishing_a_group() {
    bounded(|| {
        let mut g = group("ring-set-room", 2, 0, false);
        let qos = group_qos(false).keep_last(2);
        g.readers.push(
            g._topics[0]
                .reader()
                .qos(qos.clone())
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
        g.readers.push(
            g._topics[1]
                .reader()
                .qos(qos)
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
        let capacity =
            hdds::core::rt::IndexRing::with_capacity(hdds::config::READER_HISTORY_RING_SIZE)
                .usable_capacity();
        for _ in 0..capacity - 1 {
            g.writers[0].write(&Item { value: 0 }).unwrap();
        }
        g.publisher.begin_coherent_changes().unwrap();
        g.writers[0].write(&Item { value: 1 }).unwrap();
        g.writers[0].write(&Item { value: 2 }).unwrap();
        g.writers[1].write(&Item { value: 3 }).unwrap();
        g.publisher.end_coherent_changes().unwrap();
        assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 2]);
        assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![3]);
    });
}

#[test]
fn a_reader_joining_mid_set_receives_earlier_members_at_close() {
    let mut g = group("join-open-set", 2, 0, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    for topic in &g._topics {
        g.readers.push(
            topic
                .reader()
                .qos(group_qos(false))
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
    }
    g.writers[0].write(&Item { value: 3 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 3]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);
}

#[test]
fn durable_replay_with_a_small_reader_rejects_the_whole_group() {
    let mut g = group("replay-set-limit", 2, 0, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    g.writers[1].write(&Item { value: 3 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    let mut small = group_qos(false);
    small.resource_limits.max_samples = 1;
    g.readers.push(
        g._topics[0]
            .reader()
            .qos(small)
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    g.readers.push(
        g._topics[1]
            .reader()
            .qos(group_qos(false))
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    assert!(take_in_bracket(&g.subscriber, &g.readers[0]).is_empty());
    assert!(take_in_bracket(&g.subscriber, &g.readers[1]).is_empty());
}

fn coherent_scope_timeout_does_not_publish_the_admitted_prefix(instance: bool) {
    let name = format!("coherent-timeout-{instance}");
    let participant = Participant::builder(&name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable().keep_all().presentation_topic_coherent();
    if instance {
        qos.presentation.access_scope = hdds::dds::qos::PresentationAccessScope::Instance;
    }
    qos.reliability_max_blocking_time = Duration::from_millis(20);
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let topic = participant.topic::<Item>(&name).unwrap();
    let writer = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    qos.resource_limits.max_samples = 2;
    let reader = topic.reader().qos(qos).build().unwrap();
    writer.write(&Item { value: 0 }).unwrap();
    publisher.begin_coherent_changes().unwrap();
    writer.write(&Item { value: 1 }).unwrap();
    writer.write(&Item { value: 2 }).unwrap();
    publisher.end_coherent_changes().unwrap();
    assert_eq!(reader.take_all().unwrap(), vec![Item { value: 0 }]);
}

/// DDS 2.2.3.6 GROUP ordered_access spans all readers of the Subscriber,
/// using each member's Publisher GSN, rather than per-writer FIFO alone.
#[test]
fn ordered_access_reads_alternating_writers_in_one_global_order() {
    let g = group("global-order", 2, 2, true);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    g.writers[1].write(&Item { value: 4 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.subscriber.begin_access().unwrap();
    assert_eq!(
        g.readers[1].take().unwrap(),
        None,
        "the later reader cannot pass GSN 1"
    );
    assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 1 }));
    assert_eq!(
        g.readers[0].take().unwrap(),
        None,
        "GSN 3 waits for GSN 2 on the other reader"
    );
    assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 2 }));
    assert_eq!(g.readers[0].read().unwrap(), Some(Item { value: 3 }));
    assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 4 }));
    assert_eq!(
        g.readers[0].take().unwrap(),
        Some(Item { value: 3 }),
        "taking an already READ sample remains possible"
    );
    g.subscriber.end_access().unwrap();
}

#[test]
fn a_replay_bound_during_an_open_bracket_waits_until_its_end() {
    let mut g = group("replay-bracket", 2, 0, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.subscriber.begin_access().unwrap();
    for topic in &g._topics {
        g.readers.push(
            topic
                .reader()
                .qos(group_qos(false))
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
    }
    assert_eq!(g.readers[0].take().unwrap(), None);
    assert_eq!(g.readers[1].take().unwrap(), None);
    g.subscriber.end_access().unwrap();
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);
}

#[test]
fn replay_of_a_pending_live_set_does_not_use_its_room_twice() {
    let mut g = group("replay-live-cohort", 2, 2, false);
    g.subscriber.begin_access().unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    g.writers[1].write(&Item { value: 3 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    let mut small = group_qos(false);
    small.resource_limits.max_samples = 2;
    g.readers.push(
        g._topics[0]
            .reader()
            .qos(small)
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    g.subscriber.end_access().unwrap();
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 2]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![3]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[2]), vec![1, 2]);
    assert_eq!(g.readers[2].get_sample_rejected_status().total_count, 0);
}

#[test]
fn a_full_subscriber_does_not_discard_another_subscribers_group() {
    let g = group("independent-subscribers", 2, 2, false);
    let small_subscriber = g._participant.create_subscriber(group_qos(false)).unwrap();
    let mut small = group_qos(false);
    small.reliability = hdds::dds::qos::Reliability::BestEffort;
    small.resource_limits.max_samples = 1;
    let limited = g._topics[0]
        .reader()
        .qos(small)
        .subscriber(&small_subscriber)
        .build()
        .unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    g.writers[1].write(&Item { value: 3 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    assert!(take_in_bracket(&small_subscriber, &limited).is_empty());
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1, 2]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![3]);
}

#[test]
fn topic_scope_timeout_does_not_publish_the_admitted_prefix() {
    coherent_scope_timeout_does_not_publish_the_admitted_prefix(false);
}

#[test]
fn instance_scope_timeout_does_not_publish_the_admitted_prefix() {
    coherent_scope_timeout_does_not_publish_the_admitted_prefix(true);
}

#[cfg(feature = "test-support")]
#[test]
fn replay_waits_for_a_closed_sets_outstanding_stamped_member() {
    bounded(|| {
        let mut g = group("replay-outstanding", 2, 2, false);
        g.publisher.begin_coherent_changes().unwrap();
        g.writers[0].write(&Item { value: 1 }).unwrap();
        g.writers[1].write(&Item { value: 3 }).unwrap();
        let writer = g.writers.remove(0);
        let (stamped, ready) = std::sync::mpsc::channel();
        let (release, proceed) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            hdds::test_support::coherent_race::before_next_stage(move || {
                stamped.send(()).unwrap();
                proceed.recv_timeout(Duration::from_secs(3)).unwrap();
            });
            writer.write(&Item { value: 2 }).unwrap();
            writer
        });
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        g.publisher.end_coherent_changes().unwrap();
        for topic in &g._topics {
            g.readers.push(
                topic
                    .reader()
                    .qos(group_qos(false))
                    .subscriber(&g.subscriber)
                    .build()
                    .unwrap(),
            );
        }
        g.subscriber.begin_access().unwrap();
        for reader in &g.readers {
            assert_eq!(
                reader.take().unwrap(),
                None,
                "replay exposed a closed but incomplete live set"
            );
        }
        g.subscriber.end_access().unwrap();
        release.send(()).unwrap();
        let _writer = worker.join().unwrap();
        for (index, reader) in g.readers.iter().enumerate() {
            assert_eq!(
                take_in_bracket(&g.subscriber, reader),
                if index % 2 == 0 { vec![1, 2] } else { vec![3] }
            );
        }
    });
}

#[test]
fn ordered_replay_uses_the_publishers_member_sequence() {
    let mut g = group("ordered-replay", 2, 0, true);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    for topic in &g._topics {
        g.readers.push(
            topic
                .reader()
                .qos(group_qos(true))
                .subscriber(&g.subscriber)
                .build()
                .unwrap(),
        );
    }
    g.subscriber.begin_access().unwrap();
    assert_eq!(g.readers[1].take().unwrap(), None);
    assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 1 }));
    assert_eq!(g.readers[0].take().unwrap(), None);
    assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 2 }));
    assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 3 }));
    g.subscriber.end_access().unwrap();
}

#[test]
fn ordered_take_with_info_still_reports_instance_lifecycle() {
    let g = group("ordered-lifecycle", 1, 1, true);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[0].dispose(&Item { value: 1 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.subscriber.begin_access().unwrap();
    let (sample, info) = g.readers[0].take_with_info().unwrap().unwrap();
    assert_eq!(sample, Some(Item { value: 1 }));
    assert!(info.valid_data);
    let (sample, info) = g.readers[0].take_with_info().unwrap().unwrap();
    assert_eq!(sample, None);
    assert!(!info.valid_data);
    assert_eq!(
        info.instance_state,
        hdds::dds::InstanceState::NotAliveDisposed
    );
    g.subscriber.end_access().unwrap();
}

#[cfg(feature = "test-support")]
#[test]
fn a_reader_registered_between_replay_and_live_gets_its_history_first() {
    let g = group("replay-before-live", 2, 2, false);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![1]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![2]);

    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    g.writers[1].write(&Item { value: 4 }).unwrap();
    let late = Arc::new(std::sync::Mutex::new(Vec::new()));
    let participant = g._participant.clone();
    let subscriber = g.subscriber.clone();
    let readers = late.clone();
    hdds::test_support::coherent_race::before_next_group_delivery(move || {
        for index in 0..2 {
            let topic = participant
                .topic::<Item>(&format!("replay-before-live-t{index}"))
                .unwrap();
            let mut qos = group_qos(false);
            qos.resource_limits.max_samples = 2;
            readers.lock().unwrap().push(
                topic
                    .reader()
                    .qos(qos)
                    .subscriber(&subscriber)
                    .build()
                    .unwrap(),
            );
        }
    });
    g.publisher.end_coherent_changes().unwrap();
    let readers = std::mem::take(&mut *late.lock().unwrap());
    assert_eq!(take_in_bracket(&g.subscriber, &readers[0]), vec![1, 3]);
    assert_eq!(take_in_bracket(&g.subscriber, &readers[1]), vec![2, 4]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[0]), vec![3]);
    assert_eq!(take_in_bracket(&g.subscriber, &g.readers[1]), vec![4]);
}

/// RELIABLE KEEP_ALL retains every accepted value until the application
/// takes it, even when an access bracket deferred its first delivery.
#[test]
fn accepted_ordinary_tails_retry_after_the_reader_returns_room() {
    struct Arrival(std::sync::mpsc::Sender<i32>);
    impl DataReaderListener<Item> for Arrival {
        fn on_data_available(&self, sample: &Item) {
            self.0.send(sample.value).unwrap();
        }
    }
    let mut qos = group_qos(false);
    qos.reliability_max_blocking_time = Duration::ZERO;
    let participant = Participant::builder("intra-group-tail-room")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Item>("intra-group-tail-room-t")
        .unwrap();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let writer = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    qos.resource_limits.max_samples = 1;
    let reader = topic
        .reader()
        .qos(qos)
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    reader.set_listener(
        Some(Arc::new(Arrival(tx))),
        hdds::dds::StatusMask::DATA_AVAILABLE,
    );
    subscriber.begin_access().unwrap();
    publisher.begin_coherent_changes().unwrap();
    writer.write(&Item { value: 1 }).unwrap();
    publisher.end_coherent_changes().unwrap();
    writer.write(&Item { value: 2 }).unwrap();
    writer.write(&Item { value: 3 }).unwrap();
    // The queue owns committed changes after the writer goes away.
    drop(writer);
    subscriber.end_access().unwrap();
    for expected in [1, 2, 3] {
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), expected);
        subscriber.begin_access().unwrap();
        assert_eq!(reader.take().unwrap().unwrap().value, expected);
        subscriber.end_access().unwrap();
    }
}

/// A committed unregister is part of the writer's reliable history even
/// when its coherent prefix occupies every local ring position.
#[test]
fn accepted_unregister_retries_after_a_full_coherent_prefix() {
    use hdds::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};
    let g = keyed_group("intra-group-full-unregister-tail", false, false);
    let writer = g.writer.as_ref().unwrap();
    let capacity = hdds::core::rt::IndexRing::with_capacity(hdds::config::READER_HISTORY_RING_SIZE)
        .usable_capacity();
    let mut reader_qos = g.qos.clone();
    // KEEP_ALL with unlimited max_samples uses a larger ring. This bound
    // makes the actual ring exactly READER_HISTORY_RING_SIZE positions.
    reader_qos.resource_limits.max_samples = capacity;
    let reader = Arc::new(
        g.topic
            .reader()
            .qos(reader_qos)
            .subscriber(&g.subscriber)
            .build()
            .unwrap(),
    );
    g.subscriber.begin_access().unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    for value in 0..capacity {
        writer
            .write(&KeyedItem {
                key: 1,
                value: value as i32,
            })
            .unwrap();
    }
    g.publisher.end_coherent_changes().unwrap();
    writer
        .unregister_instance(&KeyedItem { key: 1, value: 0 })
        .unwrap();
    // No observer may pump the ring before the queued tail attempts it.
    g.subscriber.end_access().unwrap();
    let condition = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_DISPOSED,
        )
        .unwrap();
    let waitset = hdds::WaitSet::new();
    waitset.attach_condition(condition).unwrap();
    g.subscriber.begin_access().unwrap();
    for value in 0..capacity {
        assert_eq!(reader.take().unwrap().unwrap().value, value as i32);
    }
    assert!(
        waitset.wait(Some(Duration::from_secs(5))).is_ok(),
        "accepted unregister was lost behind a full ring"
    );
    assert!(!reader.take_with_info().unwrap().unwrap().1.valid_data);
    g.subscriber.end_access().unwrap();
}

/// Deleting one reader retires its ordered member; the remaining readers
/// must still access the rest of the completed Publisher set.
#[test]
fn deleting_a_reader_during_order_registration_does_not_stall_survivors() {
    use hdds::dds::{InstanceStateMask, SampleStateMask, ViewStateMask};
    let mut g = group("intra-group-order-reader-deletion", 2, 2, true);
    let departing = Arc::new(g.readers.remove(0));
    let survivor = Arc::new(g.readers.remove(0));
    let condition = survivor
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .unwrap();
    let waitset = hdds::WaitSet::new();
    waitset.attach_condition(condition).unwrap();
    let (forgotten, forget) = std::sync::mpsc::channel();
    let (resume, continuing) = std::sync::mpsc::channel();
    let (deleted, deletion) = std::sync::mpsc::channel();
    hdds::test_support::coherent_race::after_next_order_forget(&departing, move || {
        let _ = forgotten.send(());
        let _ = continuing.recv_timeout(Duration::from_secs(5));
    });
    let last_owner = departing.clone();
    hdds::test_support::coherent_race::before_next_order_registration(&departing, move || {
        std::thread::spawn(move || {
            drop(last_owner);
            let _ = deleted.send(());
        });
        forget
            .recv_timeout(Duration::from_secs(5))
            .expect("reader forgot its order before registration");
    });
    drop(departing);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.writers[1].write(&Item { value: 2 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    resume.send(()).unwrap();
    deletion
        .recv_timeout(Duration::from_secs(5))
        .expect("reader deleted before registration");
    g.subscriber.begin_access().unwrap();
    assert!(
        waitset.wait(Some(Duration::from_secs(1))).is_ok(),
        "a departed reader left an order token blocking its surviving reader"
    );
    assert_eq!(survivor.take().unwrap(), Some(Item { value: 2 }));
    g.subscriber.end_access().unwrap();
}

/// A durable writer's ordinary change stays between the coherent sets
/// preceding and following it, including when GROUP ordering is disabled.
fn replay_with_an_ordinary_change_between_sets(ordered: bool) {
    let g = group(&format!("replay-between-sets-{ordered}"), 1, 0, ordered);
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 1 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 2 }).unwrap();
    g.publisher.begin_coherent_changes().unwrap();
    g.writers[0].write(&Item { value: 3 }).unwrap();
    g.publisher.end_coherent_changes().unwrap();

    // Binding inside the bracket queues the whole snapshot before any
    // replay can publish; no background retry can alter that interleaving.
    g.subscriber.begin_access().unwrap();
    let reader = g._topics[0]
        .reader()
        .qos(group_qos(ordered))
        .subscriber(&g.subscriber)
        .build()
        .unwrap();
    assert_eq!(reader.take().unwrap(), None);
    g.subscriber.end_access().unwrap();

    let expected = [1, 2, 3];
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut values = Vec::new();
    loop {
        values.extend(take_in_bracket(&g.subscriber, &reader));
        assert!(
            expected.starts_with(&values),
            "durable replay overtook an earlier writer change: {values:?}"
        );
        if values.len() == expected.len() || Instant::now() >= deadline {
            break;
        }
        // A publishing thread may own the retry. Each closed bracket
        // allows it to finish, without a sleep selecting the outcome.
        std::thread::yield_now();
    }
    assert_eq!(values, expected, "durable replay lost a retained change");
}

#[test]
fn durable_replay_keeps_an_ordinary_change_between_sets_unordered() {
    replay_with_an_ordinary_change_between_sets(false);
}

#[test]
fn durable_replay_keeps_an_ordinary_change_between_sets_ordered() {
    replay_with_an_ordinary_change_between_sets(true);
}

/// DDS v1.4 Sec.2.2.3.6 requires Publisher order across DataReaders for
/// ordinary changes too, whether or not coherent access is also requested.
fn ordinary_group_order(coherent: bool, durable: bool) {
    let mut qos = group_qos(true);
    qos.presentation.coherent_access = coherent;
    let mut g = group_with_qos(
        &format!("ordinary-group-order-{coherent}-{durable}"),
        2,
        if durable { 0 } else { 2 },
        qos.clone(),
    );
    // The order is Publisher order, not the application's source timestamps.
    g.writers[0]
        .write_w_timestamp(&Item { value: 1 }, 400)
        .unwrap();
    g.writers[1]
        .write_w_timestamp(&Item { value: 2 }, 300)
        .unwrap();
    g.writers[0]
        .write_w_timestamp(&Item { value: 3 }, 200)
        .unwrap();
    g.writers[1]
        .write_w_timestamp(&Item { value: 4 }, 100)
        .unwrap();
    if durable {
        g.subscriber.begin_access().unwrap();
        for topic in &g._topics {
            g.readers.push(
                topic
                    .reader()
                    .qos(qos.clone())
                    .subscriber(&g.subscriber)
                    .build()
                    .unwrap(),
            );
        }
        g.subscriber.end_access().unwrap();
    }
    g.subscriber.begin_access().unwrap();
    assert_eq!(
        g.readers[1].take().unwrap(),
        None,
        "GSN 2 must wait for GSN 1"
    );
    assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 1 }));
    assert_eq!(
        g.readers[0].take().unwrap(),
        None,
        "GSN 3 must wait for GSN 2"
    );
    assert_eq!(g.readers[1].read().unwrap(), Some(Item { value: 2 }));
    assert_eq!(
        g.readers[1].read().unwrap(),
        None,
        "GSN 4 must wait for GSN 3"
    );
    assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 3 }));
    assert_eq!(g.readers[1].read().unwrap(), Some(Item { value: 4 }));
    assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 2 }));
    assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 4 }));
    g.subscriber.end_access().unwrap();
}

#[test]
fn ordinary_group_changes_obey_publisher_order_without_coherent_access() {
    ordinary_group_order(false, false);
}

#[test]
fn ordinary_group_changes_obey_publisher_order_with_coherent_access() {
    ordinary_group_order(true, false);
}

#[test]
fn ordinary_group_replay_obeys_publisher_order_without_coherent_access() {
    ordinary_group_order(false, true);
}

#[test]
fn ordinary_group_replay_obeys_publisher_order_with_coherent_access() {
    ordinary_group_order(true, true);
}

/// A lower GSN keeps its position even while another writer finishes first.
#[test]
fn an_ordinary_group_write_keeps_its_order_while_its_admission_is_pending() {
    let mut qos = group_qos(true);
    qos.presentation.coherent_access = false;
    let g = group_with_qos("ordinary-pending-order", 2, 2, qos);
    let (waiting, pending) = std::sync::mpsc::channel();
    let (resume, continued) = std::sync::mpsc::channel();
    let (finished, complete) = std::sync::mpsc::channel();
    let mut writers = g.writers;
    let first = writers.remove(0);
    let thread = std::thread::spawn(move || {
        hdds::test_support::coherent_race::before_next_ordered_write(move || {
            waiting.send(()).unwrap();
            continued
                .recv_timeout(Duration::from_secs(5))
                .expect("pending writer resumed");
        });
        let result = first.write(&Item { value: 1 });
        finished.send(result).unwrap();
        first
    });
    pending
        .recv_timeout(Duration::from_secs(5))
        .expect("first GSN reserved");
    writers[0].write(&Item { value: 2 }).unwrap();
    g.subscriber.begin_access().unwrap();
    let later = g.readers[1].take().unwrap();
    g.subscriber.end_access().unwrap();
    // Always release the thread before asserting, including on a mutant failure.
    resume.send(()).unwrap();
    complete
        .recv_timeout(Duration::from_secs(5))
        .expect("first writer finished")
        .unwrap();
    let first = thread.join().unwrap();
    assert_eq!(
        later, None,
        "a completed later write passed an earlier pending GSN"
    );
    g.subscriber.begin_access().unwrap();
    assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 1 }));
    assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 2 }));
    g.subscriber.end_access().unwrap();
    drop(first);
}

/// GROUP + ordered_access, two writers of one Publisher: ordinary changes
/// outside a coherent set and the members of one set are read through two
/// readers of one Subscriber in the Publisher's GSN order (DDS v1.4
/// Sec.2.2.3.6), not per writer.
#[test]
fn ordinary_and_coherent_group_changes_are_read_in_one_global_order() {
    bounded(|| {
        let g = group("mixed-global-order", 2, 2, true);
        g.writers[0].write(&Item { value: 1 }).unwrap();
        g.publisher.begin_coherent_changes().unwrap();
        g.writers[0].write(&Item { value: 2 }).unwrap();
        g.writers[1].write(&Item { value: 3 }).unwrap();
        g.publisher.end_coherent_changes().unwrap();
        g.writers[1].write(&Item { value: 4 }).unwrap();
        g.writers[0].write(&Item { value: 5 }).unwrap();

        g.subscriber.begin_access().unwrap();
        assert_eq!(
            g.readers[1].take().unwrap(),
            None,
            "GSN 3 waits for GSN 1 on the other reader"
        );
        assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 1 }));
        assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 2 }));
        assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 3 }));
        assert_eq!(g.readers[1].take().unwrap(), Some(Item { value: 4 }));
        assert_eq!(g.readers[0].take().unwrap(), Some(Item { value: 5 }));
        assert_eq!(g.readers[0].take().unwrap(), None);
        g.subscriber.end_access().unwrap();
    });
}

/// RESOURCE_LIMITS at delivery, not at admission: a change of reader A's
/// history the application has not taken fills its only place when a set
/// of the Publisher completes. The set reaches no reader of the Subscriber
/// (one refusal, one unit), the held change is still there, the refusal is
/// reported on reader A, and the next set is delivered whole once the
/// application has taken.
#[test]
fn a_set_meeting_a_full_reader_at_delivery_reaches_no_reader_and_keeps_what_it_holds() {
    bounded(|| {
        let mut qos = group_qos(false);
        qos.reliability_max_blocking_time = Duration::from_millis(20);
        let mut small = qos.clone();
        small.resource_limits = ResourceLimits {
            max_samples: 1,
            ..ResourceLimits::default()
        };
        let participant = Participant::builder("group-full-at-delivery")
            .domain_id(0)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic_a = participant
            .topic::<Item>("group-full-at-delivery-a")
            .unwrap();
        let topic_b = participant
            .topic::<Item>("group-full-at-delivery-b")
            .unwrap();
        let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
        let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
        let writer_a = topic_a
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let writer_b = topic_b
            .writer()
            .qos(qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let reader_a = topic_a
            .reader()
            .qos(small)
            .subscriber(&subscriber)
            .build()
            .unwrap();
        let reader_b = topic_b
            .reader()
            .qos(qos.clone())
            .subscriber(&subscriber)
            .build()
            .unwrap();

        writer_a.write(&Item { value: 10 }).unwrap();
        publisher.begin_coherent_changes().unwrap();
        writer_a.write(&Item { value: 1 }).unwrap();
        writer_b.write(&Item { value: 2 }).unwrap();
        publisher.end_coherent_changes().unwrap();

        assert_eq!(
            take_in_bracket(&subscriber, &reader_a),
            vec![10],
            "the change reader A held must survive a refused set"
        );
        assert_eq!(
            take_in_bracket(&subscriber, &reader_b),
            Vec::<i32>::new(),
            "a set refused by one reader of the Subscriber reaches none of them"
        );
        let status = reader_a.get_sample_rejected_status();
        assert_eq!(status.total_count, 1, "{status:?}");
        assert_eq!(status.last_reason, SampleRejectedReason::ResourceLimit);

        publisher.begin_coherent_changes().unwrap();
        writer_a.write(&Item { value: 3 }).unwrap();
        writer_b.write(&Item { value: 4 }).unwrap();
        publisher.end_coherent_changes().unwrap();
        assert_eq!(
            take_eventually(&subscriber, &reader_a, 1, Duration::from_secs(2)),
            vec![3]
        );
        assert_eq!(
            take_eventually(&subscriber, &reader_b, 1, Duration::from_secs(2)),
            vec![4]
        );
    });
}

/// A TOPIC-scope set read through a GROUP-scope Subscriber, completed while
/// the reader's access bracket is open: the set is held back, and it must
/// reach the reader once the bracket closes.
#[test]
fn topic_set_completed_inside_a_group_bracket_reaches_the_reader_after_it() {
    bounded(|| {
        let topic_qos = QoS::reliable()
            .transient_local()
            .keep_all()
            .presentation_topic_coherent();
        let participant = Participant::builder("topic-set-held-in-bracket")
            .domain_id(0)
            .with_transport(TransportMode::IntraProcess)
            .build()
            .unwrap();
        let topic = participant
            .topic::<Item>("topic-set-held-in-bracket")
            .unwrap();
        let publisher = Arc::new(participant.create_publisher(topic_qos.clone()).unwrap());
        let writer = topic
            .writer()
            .qos(topic_qos.clone())
            .publisher(&publisher)
            .build()
            .unwrap();
        let subscriber = Arc::new(participant.create_subscriber(group_qos(false)).unwrap());
        let reader = topic
            .reader()
            .qos(topic_qos)
            .subscriber(&subscriber)
            .build()
            .unwrap();

        subscriber.begin_access().unwrap();
        publisher.begin_coherent_changes().unwrap();
        writer.write(&Item { value: 1 }).unwrap();
        writer.write(&Item { value: 2 }).unwrap();
        publisher.end_coherent_changes().unwrap();
        let mut inside = Vec::new();
        while let Some(sample) = reader.take().unwrap() {
            inside.push(sample.value);
        }
        assert_eq!(inside, Vec::<i32>::new(), "the open set is held back");
        subscriber.end_access().unwrap();

        assert_eq!(
            take_eventually(&subscriber, &reader, 2, Duration::from_secs(2)),
            vec![1, 2],
            "the set held by the bracket was lost"
        );
    });
}

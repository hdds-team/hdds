// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A reader pairing during an uncommitted GROUP change inherits its place
//! before another writer can publish a later GSN to that reader.

use hdds::{Participant, QoS, TransportMode};
use std::sync::{mpsc, Arc};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Value {
    value: i32,
}

fn joining_reader(durable: bool) {
    let name = if durable {
        "group-late-durable"
    } else {
        "group-late-volatile"
    };
    let participant = Participant::builder(name)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.presentation.coherent_access = false;
    if durable {
        qos.durability = hdds::dds::qos::Durability::TransientLocal;
    }
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let old_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let new_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let topic = participant.topic::<Value>(name).unwrap();
    let a = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    // Its Subscriber owns a different order queue, so this reader cannot
    // accidentally supply the new Subscriber's missing GSN 1 placeholder.
    let _old = topic
        .reader()
        .qos(qos.clone())
        .subscriber(&old_subscriber)
        .build()
        .unwrap();
    let (reserved, first_reserved) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let first = std::thread::spawn(move || {
        hdds::test_support::coherent_race::before_next_ordered_write(move || {
            reserved.send(()).unwrap();
            resumed.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        a.write(&Value { value: 1 })
    });
    first_reserved
        .recv_timeout(Duration::from_secs(2))
        .expect("GSN 1 reserved");
    let new = topic
        .reader()
        .qos(qos)
        .subscriber(&new_subscriber)
        .build()
        .unwrap();
    let second = b.write(&Value { value: 2 });
    new_subscriber.begin_access().unwrap();
    let before = new.take().unwrap();
    new_subscriber.end_access().unwrap();
    // Always release the paused producer before asserting the mutant result.
    resume.send(()).unwrap();
    first.join().unwrap().unwrap();
    second.unwrap();
    assert_eq!(
        before, None,
        "the new Subscriber read GSN 2 before its owed GSN 1"
    );
    new_subscriber.begin_access().unwrap();
    assert_eq!(new.take().unwrap(), Some(Value { value: 1 }));
    assert_eq!(new.take().unwrap(), Some(Value { value: 2 }));
    new_subscriber.end_access().unwrap();
}

#[test]
fn a_volatile_reader_inherits_an_uncommitted_group_position() {
    joining_reader(false);
}

#[test]
fn a_durable_reader_inherits_an_uncommitted_group_position() {
    joining_reader(true);
}

#[test]
fn queued_durable_replay_reserves_its_cross_writer_position_before_access() {
    let participant = Participant::builder("group-late-replay")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.presentation.coherent_access = false;
    qos.durability = hdds::dds::qos::Durability::TransientLocal;
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let old_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let new_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let topic = participant.topic::<Value>("group-late-replay").unwrap();
    let a = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let _old = topic
        .reader()
        .qos(qos.clone())
        .subscriber(&old_subscriber)
        .build()
        .unwrap();
    a.write(&Value { value: 1 }).unwrap();
    new_subscriber.begin_access().unwrap();
    let new = topic
        .reader()
        .qos(qos)
        .subscriber(&new_subscriber)
        .build()
        .unwrap();
    b.write(&Value { value: 2 }).unwrap();
    assert_eq!(
        new.take().unwrap(),
        None,
        "live GSN bypassed queued historical replay"
    );
    new_subscriber.end_access().unwrap();
    new_subscriber.begin_access().unwrap();
    assert_eq!(new.take().unwrap(), Some(Value { value: 1 }));
    assert_eq!(new.take().unwrap(), Some(Value { value: 2 }));
    new_subscriber.end_access().unwrap();
}

#[test]
fn a_committed_coherent_lease_survives_a_late_reader_and_replay_withdrawal() {
    let participant = Participant::builder("group-late-coherent")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.durability = hdds::dds::qos::Durability::TransientLocal;
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let old_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let new_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let topic = participant.topic::<Value>("group-late-coherent").unwrap();
    let a = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let _old = topic
        .reader()
        .qos(qos.clone())
        .subscriber(&old_subscriber)
        .build()
        .unwrap();
    publisher.begin_coherent_changes().unwrap();
    a.write(&Value { value: 1 }).unwrap();
    let (paused, pausing) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let (withdrawn, withdrawing) = mpsc::channel();
    let (finish, finishing) = mpsc::channel();
    let closing = publisher.clone();
    let closer = std::thread::spawn(move || {
        hdds::test_support::coherent_race::before_next_group_delivery(move || {
            paused.send(()).unwrap();
            resumed.recv_timeout(Duration::from_secs(5)).unwrap();
            hdds::test_support::coherent_race::before_next_group_delivery(move || {
                withdrawn.send(()).unwrap();
                finishing.recv_timeout(Duration::from_secs(5)).unwrap();
            });
        });
        closing.end_coherent_changes()
    });
    pausing
        .recv_timeout(Duration::from_secs(2))
        .expect("closed set awaiting destination snapshot");
    let new = topic
        .reader()
        .qos(qos)
        .subscriber(&new_subscriber)
        .build()
        .unwrap();
    let second = b.write(&Value { value: 2 });
    new_subscriber.begin_access().unwrap();
    let before = new.take().unwrap();
    new_subscriber.end_access().unwrap();
    resume.send(()).unwrap();
    withdrawing
        .recv_timeout(Duration::from_secs(2))
        .expect("live replay withdrawn before publication");
    new_subscriber.begin_access().unwrap();
    let after_withdrawal = new.take().unwrap();
    new_subscriber.end_access().unwrap();
    finish.send(()).unwrap();
    closer.join().unwrap().unwrap();
    second.unwrap();
    assert_eq!(
        after_withdrawal, None,
        "withdrawing replay removed the live coherent lease"
    );
    assert_eq!(
        before, None,
        "ordinary tail bypassed retained coherent history"
    );
    new_subscriber.begin_access().unwrap();
    assert_eq!(new.take().unwrap(), Some(Value { value: 1 }));
    assert_eq!(new.take().unwrap(), Some(Value { value: 2 }));
    new_subscriber.end_access().unwrap();
}

#[test]
fn a_volatile_reader_does_not_inherit_an_already_committed_ordinary_change() {
    let participant = Participant::builder("group-late-committed")
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.presentation.coherent_access = false;
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let old_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let new_subscriber = participant.create_subscriber(qos.clone()).unwrap();
    let topic = participant.topic::<Value>("group-late-committed").unwrap();
    let a = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let b = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let old = topic
        .reader()
        .qos(qos.clone())
        .subscriber(&old_subscriber)
        .build()
        .unwrap();
    let (paused, pausing) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    hdds::test_support::coherent_race::before_next_order_registration(&old, move || {
        paused.send(()).unwrap();
        resumed.recv_timeout(Duration::from_secs(5)).unwrap();
    });
    let first = std::thread::spawn(move || a.write(&Value { value: 1 }));
    pausing
        .recv_timeout(Duration::from_secs(2))
        .expect("committed change before ring publication");
    let new = topic
        .reader()
        .qos(qos)
        .subscriber(&new_subscriber)
        .build()
        .unwrap();
    let second = b.write(&Value { value: 2 });
    new_subscriber.begin_access().unwrap();
    let before = new.take().unwrap();
    new_subscriber.end_access().unwrap();
    resume.send(()).unwrap();
    first.join().unwrap().unwrap();
    second.unwrap();
    assert_eq!(
        before,
        Some(Value { value: 2 }),
        "volatile reader waited for a change it never owed"
    );
    new_subscriber.begin_access().unwrap();
    assert_eq!(new.take().unwrap(), None);
    new_subscriber.end_access().unwrap();
}

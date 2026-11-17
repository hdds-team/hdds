// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Durable HISTORY replacement cannot present an incomplete coherent set
//! (DDS 1.4 2.2.3.6/2.2.3.18, RTPS 2.5 8.7.6).

use hdds::{Participant, QoS, TransportMode};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Value {
    value: i32,
}

#[test]
fn durable_keep_last_replay_drops_all_writers_of_a_truncated_group_set() {
    let participant = Participant::builder("durable-group-integrity")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(1)
        .presentation_group_coherent();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let a = participant
        .topic::<Value>("durable-group-integrity-a")
        .unwrap();
    let b = participant
        .topic::<Value>("durable-group-integrity-b")
        .unwrap();
    let writer_a = a
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = b
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    // Live delivery still gets every staged member, independent of which
    // samples the durable writer histories later retain for a late joiner.
    let live_qos = QoS::reliable()
        .transient_local()
        .keep_all()
        .presentation_group_coherent();
    let live_a = a
        .reader()
        .qos(live_qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let live_b = b
        .reader()
        .qos(live_qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Value { value: 1 }).unwrap();
    writer_a.write(&Value { value: 2 }).unwrap();
    writer_b.write(&Value { value: 3 }).unwrap();
    publisher.end_coherent_changes().unwrap();
    subscriber.begin_access().unwrap();
    assert_eq!(
        live_a.take_all().unwrap(),
        vec![Value { value: 1 }, Value { value: 2 }]
    );
    assert_eq!(live_b.take_all().unwrap(), vec![Value { value: 3 }]);
    subscriber.end_access().unwrap();
    let late_a = a
        .reader()
        .qos(live_qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let late_b = b
        .reader()
        .qos(live_qos)
        .subscriber(&subscriber)
        .build()
        .unwrap();
    subscriber.begin_access().unwrap();
    assert!(
        late_a.take_all().unwrap().is_empty(),
        "A's surviving suffix is incomplete"
    );
    assert!(
        late_b.take_all().unwrap().is_empty(),
        "B cannot expose the other half"
    );
    subscriber.end_access().unwrap();
    // A later intact set is still replayable; suppressing one damaged set
    // must not suppress every older or newer retained group generation.
    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Value { value: 4 }).unwrap();
    writer_b.write(&Value { value: 5 }).unwrap();
    publisher.end_coherent_changes().unwrap();
    let later_a = a
        .reader()
        .qos(qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let later_b = b.reader().qos(qos).subscriber(&subscriber).build().unwrap();
    subscriber.begin_access().unwrap();
    assert_eq!(later_a.take_all().unwrap(), vec![Value { value: 4 }]);
    assert_eq!(later_b.take_all().unwrap(), vec![Value { value: 5 }]);
    subscriber.end_access().unwrap();
}

#[test]
fn captured_group_replay_is_suppressed_if_a_member_is_evicted_before_access() {
    let participant = Participant::builder("captured-group-integrity")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(1)
        .presentation_group_coherent();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let a = participant
        .topic::<Value>("captured-group-integrity-a")
        .unwrap();
    let b = participant
        .topic::<Value>("captured-group-integrity-b")
        .unwrap();
    let writer_a = a
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    let writer_b = b
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    publisher.begin_coherent_changes().unwrap();
    writer_a.write(&Value { value: 1 }).unwrap();
    writer_b.write(&Value { value: 2 }).unwrap();
    publisher.end_coherent_changes().unwrap();
    subscriber.begin_access().unwrap();
    let reader_a = a
        .reader()
        .qos(qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let reader_b = b.reader().qos(qos).subscriber(&subscriber).build().unwrap();
    // Both snapshots own references already, but their coherent set is still
    // held outside the readers' visible histories by this access bracket.
    writer_a.write(&Value { value: 3 }).unwrap();
    assert!(reader_a.take_all().unwrap().is_empty());
    assert!(reader_b.take_all().unwrap().is_empty());
    subscriber.end_access().unwrap();
    subscriber.begin_access().unwrap();
    assert_eq!(reader_a.take_all().unwrap(), vec![Value { value: 3 }]);
    assert!(
        reader_b.take_all().unwrap().is_empty(),
        "captured B cannot expose an evicted set's other half"
    );
    subscriber.end_access().unwrap();
}

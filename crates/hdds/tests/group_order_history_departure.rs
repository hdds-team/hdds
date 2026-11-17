// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HISTORY replacement and writer departure must not expose fragments or
//! retain order debt for samples no longer in a reader's history.

use hdds::{Participant, QoS, TransportMode};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Value {
    value: u32,
}

fn replacement_keeps_order(coherent: bool) {
    let name = format!("ordered-history-replacement-{coherent}");
    let participant = Participant::builder(&name)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_last(1)
        .presentation_group_coherent_ordered();
    qos.presentation.coherent_access = coherent;
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let a = participant.topic::<Value>(&format!("{name}-a")).unwrap();
    let b = participant.topic::<Value>(&format!("{name}-b")).unwrap();
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
    let reader_a = a
        .reader()
        .qos(qos.clone())
        .subscriber(&subscriber)
        .build()
        .unwrap();
    let reader_b = b.reader().qos(qos).subscriber(&subscriber).build().unwrap();
    // Fill the unread transport history and force KEEP_LAST to replace its
    // old values. No read decodes an evicted entry or reconciles its order.
    let count = u32::try_from(hdds::config::READER_HISTORY_RING_SIZE).unwrap();
    for value in 0..count {
        writer_a.write(&Value { value }).unwrap();
    }
    writer_b.write(&Value { value: count }).unwrap();
    subscriber.begin_access().unwrap();
    assert_eq!(
        reader_a.take().unwrap(),
        Some(Value { value: count - 1 }),
        "evicted values kept the surviving KEEP_LAST sample inaccessible"
    );
    assert_eq!(reader_a.take().unwrap(), None);
    assert_eq!(
        reader_b.take().unwrap(),
        Some(Value { value: count }),
        "evicted order debt blocked another reader of the Subscriber"
    );
    subscriber.end_access().unwrap();
}

#[test]
fn ordinary_order_survives_unread_keep_last_replacement() {
    replacement_keeps_order(false);
}

#[test]
fn ordinary_order_with_coherent_access_survives_unread_keep_last_replacement() {
    replacement_keeps_order(true);
}

fn departed_replay(capture_b: bool, split_subscribers: bool) {
    let name = format!("departed-group-replay-{capture_b}-{split_subscribers}");
    let participant = Participant::builder(&name)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let qos = QoS::reliable()
        .transient_local()
        .keep_last(2)
        .presentation_group_coherent();
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let first = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let second = if split_subscribers {
        Arc::new(participant.create_subscriber(qos.clone()).unwrap())
    } else {
        first.clone()
    };
    let a = participant.topic::<Value>(&format!("{name}-a")).unwrap();
    let b = participant.topic::<Value>(&format!("{name}-b")).unwrap();
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
    first.begin_access().unwrap();
    if split_subscribers {
        second.begin_access().unwrap();
    }
    let reader_a = a
        .reader()
        .qos(qos.clone())
        .subscriber(&first)
        .build()
        .unwrap();
    let captured_b = capture_b.then(|| {
        b.reader()
            .qos(qos.clone())
            .subscriber(&second)
            .build()
            .unwrap()
    });
    // This ordinary tail keeps A's replay stream alive after deletion. Its
    // independent progress also proves suppression did not stall the stream.
    writer_a.write(&Value { value: 3 }).unwrap();
    // A's replay owns its references before this exact teardown. B's is
    // either already captured or must now be suppressed as a fragment.
    drop(writer_a);
    let reader_b =
        captured_b.unwrap_or_else(|| b.reader().qos(qos).subscriber(&second).build().unwrap());
    first.end_access().unwrap();
    if split_subscribers {
        second.end_access().unwrap();
    }
    first.begin_access().unwrap();
    if split_subscribers {
        second.begin_access().unwrap();
    }
    if capture_b && !split_subscribers {
        assert_eq!(
            reader_a.take_all().unwrap(),
            vec![Value { value: 1 }, Value { value: 3 }]
        );
        assert_eq!(reader_b.take_all().unwrap(), vec![Value { value: 2 }]);
    } else {
        assert_eq!(
            reader_a.take_all().unwrap(),
            vec![Value { value: 3 }],
            "a partial captured composite was presented after departure"
        );
        assert!(
            reader_b.take_all().unwrap().is_empty(),
            "another Subscriber or future snapshot supplied missing coverage"
        );
    }
    first.end_access().unwrap();
    if split_subscribers {
        second.end_access().unwrap();
    }
}

#[test]
fn mixed_capture_across_writer_departure_cannot_present_a_partial_set() {
    departed_replay(false, false);
}

#[test]
fn fully_captured_composite_survives_writer_departure() {
    departed_replay(true, false);
}

#[test]
fn different_subscribers_cannot_pool_captured_set_coverage() {
    departed_replay(true, true);
}

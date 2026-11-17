// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A capacity wait must let already pending reader notifications make progress
//! (DDS v1.4 Sec.2.2.3.14, Sec.2.2.4.2.1).

use crate::{Participant, QoS, TransportMode};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Value {
    value: i32,
}

#[test]
fn an_ordered_write_flushes_prior_reader_notifications_before_waiting_for_room() {
    let participant = Participant::builder("ordered-notice-room")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let mut qos = QoS::reliable()
        .keep_all()
        .presentation_group_coherent_ordered();
    qos.presentation.coherent_access = false;
    qos.reliability_max_blocking_time = Duration::from_millis(200);
    let publisher = Arc::new(participant.create_publisher(qos.clone()).unwrap());
    let subscriber = Arc::new(participant.create_subscriber(qos.clone()).unwrap());
    let topic = participant.topic::<Value>("ordered-notice-room").unwrap();
    let writer = topic
        .writer()
        .qos(qos.clone())
        .publisher(&publisher)
        .build()
        .unwrap();
    qos.resource_limits.max_samples = 1;
    let reader = Arc::new(
        topic
            .reader()
            .qos(qos)
            .subscriber(&subscriber)
            .build()
            .unwrap(),
    );
    writer.write(&Value { value: 1 }).unwrap();
    let read = Arc::new(Mutex::new(None));
    let observed = read.clone();
    let consumer = reader.clone();
    let access = subscriber.clone();
    crate::test_support::coherent_race::before_next_room_wait(move || {
        // A failed reservation can release earlier work on this same thread.
        // Select its notification-before-wait schedule without a timing sleep.
        crate::dds::notify_local(move || {
            access.begin_access().unwrap();
            *observed.lock().unwrap() = consumer.take().unwrap();
            access.end_access().unwrap();
        });
    });
    let written = writer.write(&Value { value: 2 });
    assert_eq!(*read.lock().unwrap(), Some(Value { value: 1 }));
    assert!(
        written.is_ok(),
        "a retained notification forced an avoidable timeout: {written:?}"
    );
    subscriber.begin_access().unwrap();
    assert_eq!(reader.take().unwrap(), Some(Value { value: 2 }));
    subscriber.end_access().unwrap();
}

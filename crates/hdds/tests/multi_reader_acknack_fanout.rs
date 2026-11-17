// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Pending: per-pair ACKNACK fan-out for N>1 local readers on the same topic
//! via UDP (RTPS v2.5 Sec.8.4.12).
//!
//! Per the spec, each `(local_reader, remote_writer)` pair owns its own
//! ACKNACK stream and bitmap. When several local readers subscribe to the
//! same topic over UDP discovery, the publisher's `ControlHandler` must
//! emit one ACKNACK per pair (matched local reader). The current
//! implementation collapses the pairs into a single `ReliableReaderProxy`
//! keyed by `writer_guid` and emits one ACKNACK with an arbitrary matched
//! local reader's `entity_id`, which is correct for the N=1 case
//! (single-reader topics, e.g. the OMG interoperability tests) but ambiguous and
//! non-conformant for N>1.

use hdds::api::{Participant, QoS};
use hdds::test_support::domains::unique_domain;
use std::thread;
use std::time::Duration;

#[test]
#[ignore = "needs per-pair ACKNACK fan-out per RTPS v2.5 Sec.8.4.12; current ControlHandler emits one ACKNACK with an arbitrary matched-local-reader entity_id when N>1 local readers subscribe to the same topic over UDP discovery"]
fn multi_local_readers_same_topic_via_udp_acknack_fanout() {
    use hdds::generated::temperature::Temperature;

    // ONE leased domain for both: the publisher and the subscriber have to
    // discover each other over UDP for the ACKNACK fan-out to exist at all.
    // Without it both defaulted to domain 0, sharing RTPS ports with every
    // other test binary. Declared first so it drops after both participants.
    let domain = unique_domain();

    // Publisher participant (UDP, default transport).
    let publisher = Participant::builder("multi_reader_udp_publisher")
        .domain_id(domain.id())
        .build()
        .expect("publisher participant");

    // Subscriber participant with two local readers on the same topic and
    // distinct QoS so they are independent matching entities.
    let subscriber = Participant::builder("multi_reader_udp_subscriber")
        .domain_id(domain.id())
        .build()
        .expect("subscriber participant");

    let writer = publisher
        .topic::<Temperature>("MultiReaderAcknackFanoutTopic")
        .expect("topic")
        .writer()
        .qos(QoS::reliable())
        .build()
        .expect("writer");

    let reader_a = subscriber
        .topic::<Temperature>("MultiReaderAcknackFanoutTopic")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().latency_budget_millis(5))
        .build()
        .expect("reader_a");

    let reader_b = subscriber
        .topic::<Temperature>("MultiReaderAcknackFanoutTopic")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().latency_budget_millis(500))
        .build()
        .expect("reader_b");

    thread::sleep(Duration::from_millis(300));

    for i in 0..5 {
        writer
            .write(&Temperature {
                value: 20.0 + i as f32,
                timestamp: (i + 1) * 100,
            })
            .expect("write");
    }

    thread::sleep(Duration::from_millis(500));

    let mut count_a = 0;
    while let Ok(Some(_)) = reader_a.take() {
        count_a += 1;
    }
    let mut count_b = 0;
    while let Ok(Some(_)) = reader_b.take() {
        count_b += 1;
    }

    // End-to-end delivery sanity: both readers must observe samples.
    assert!(count_a > 0, "reader_a should receive samples");
    assert!(count_b > 0, "reader_b should receive samples");

    // The strict spec assertion (RTPS v2.5 Sec.8.4.12) requires observing
    // one ACKNACK per (local_reader, remote_writer) pair. Surfacing the
    // ControlHandler ACKNACK counter (or sniffing the wire) is part of the
    // activation work for this test alongside the per-pair fan-out itself.
    todo!("activate alongside per-pair ACKNACK fan-out (RTPS v2.5 Sec.8.4.12)");
}

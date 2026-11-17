// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A DataWriter uses ONE data representation: the first element of its
//! DataRepresentationQosPolicy. DDS-XTypes 1.3 7.6.3.1.1: "Writers offer a
//! single representation. A writer will use its offered policy to
//! communicate with its matched readers", the elements after the first carry
//! no meaning, and "If a writer's offered representation is contained within
//! a reader's sequence, the offer satisfies the request and the policies are
//! compatible. Otherwise, they are incompatible."
//!
//! So with readers requesting only XCDR and only XCDR2 on the same topic,
//! exactly the one that requests the writer's first representation is
//! matched and receives every sample; the other is not matched, and both
//! sides report INCOMPATIBLE_QOS with the DATA_REPRESENTATION policy id
//! (DDS 1.4 2.2.3, policy id 23).

use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus,
    RequestedIncompatibleQosStatus, SubscriptionMatchedStatus,
};
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const XCDR: u16 = 0x0000;
const XCDR2: u16 = 0x0002;
const DATA_REPRESENTATION_POLICY_ID: u32 = 23;
const WRITES: u32 = 50;

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Reading {
    value: u32,
    label: String,
    total: f64,
}

#[derive(Default)]
struct ReaderStatus {
    matched: AtomicU32,
    incompatible_policy: AtomicU32,
}

impl DataReaderListener<Reading> for ReaderStatus {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.matched.store(status.current_count, Ordering::SeqCst);
    }

    fn on_requested_incompatible_qos(&self, status: RequestedIncompatibleQosStatus) {
        self.incompatible_policy
            .store(status.last_policy_id, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct WriterStatus {
    matched: AtomicU32,
    incompatible_policy: AtomicU32,
}

impl DataWriterListener<Reading> for WriterStatus {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.matched.store(status.current_count, Ordering::SeqCst);
    }

    fn on_offered_incompatible_qos(&self, policy_id: u32, _policy_name: &str) {
        self.incompatible_policy.store(policy_id, Ordering::SeqCst);
    }
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done()
}

fn qos_with(representations: &[u16]) -> QoS {
    let mut qos = QoS::reliable().keep_all();
    qos.data_representation = representations.to_vec();
    qos
}

/// Writer offering `offered`; one reader requesting XCDR only, one
/// requesting XCDR2 only. `served` is the representation the writer uses,
/// which must be `offered[0]`.
fn run(offered: &[u16], served: u16, ids: (u8, u8)) {
    let domain = unique_domain();
    let publisher = Participant::builder("datarep_first_pub")
        .domain_id(domain.id())
        .participant_id(Some(ids.0))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher");
    let subscriber = Participant::builder("datarep_first_sub")
        .domain_id(domain.id())
        .participant_id(Some(ids.1))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("subscriber");

    let topic_name = "DataRepFirst";
    let xcdr_status = Arc::new(ReaderStatus::default());
    let xcdr_reader = subscriber
        .topic::<Reading>(topic_name)
        .expect("topic")
        .reader()
        .qos(qos_with(&[XCDR]))
        .with_listener(Arc::clone(&xcdr_status) as Arc<dyn DataReaderListener<Reading>>)
        .build()
        .expect("XCDR reader");
    let xcdr2_status = Arc::new(ReaderStatus::default());
    let xcdr2_reader = subscriber
        .topic::<Reading>(topic_name)
        .expect("topic")
        .reader()
        .qos(qos_with(&[XCDR2]))
        .with_listener(Arc::clone(&xcdr2_status) as Arc<dyn DataReaderListener<Reading>>)
        .build()
        .expect("XCDR2 reader");
    let writer_status = Arc::new(WriterStatus::default());
    let writer = publisher
        .topic::<Reading>(topic_name)
        .expect("topic")
        .writer()
        .qos(qos_with(offered))
        .with_listener(Arc::clone(&writer_status) as Arc<dyn DataWriterListener<Reading>>)
        .build()
        .expect("writer");

    let (served_status, refused_status) = if served == XCDR {
        (&xcdr_status, &xcdr2_status)
    } else {
        (&xcdr2_status, &xcdr_status)
    };
    let (served_reader, refused_reader) = if served == XCDR {
        (&xcdr_reader, &xcdr2_reader)
    } else {
        (&xcdr2_reader, &xcdr_reader)
    };

    assert!(
        wait_for(Duration::from_secs(10), || {
            served_status.matched.load(Ordering::SeqCst) == 1
                && writer_status.matched.load(Ordering::SeqCst) == 1
                && refused_status.incompatible_policy.load(Ordering::SeqCst) != 0
                && writer_status.incompatible_policy.load(Ordering::SeqCst) != 0
        }),
        "discovery did not settle: served reader matched={}, writer matched={}, \
         refused reader policy={}, writer policy={}",
        served_status.matched.load(Ordering::SeqCst),
        writer_status.matched.load(Ordering::SeqCst),
        refused_status.incompatible_policy.load(Ordering::SeqCst),
        writer_status.incompatible_policy.load(Ordering::SeqCst),
    );
    assert_eq!(
        refused_status.incompatible_policy.load(Ordering::SeqCst),
        DATA_REPRESENTATION_POLICY_ID,
        "the reader that does not request {served:#06x} must report DATA_REPRESENTATION"
    );
    assert_eq!(
        writer_status.incompatible_policy.load(Ordering::SeqCst),
        DATA_REPRESENTATION_POLICY_ID,
        "the writer must report DATA_REPRESENTATION for the reader it cannot serve"
    );

    for value in 1..=WRITES {
        writer
            .write(&Reading {
                value,
                label: format!("sample-{value}"),
                total: f64::from(value) * 0.5,
            })
            .expect("write");
    }

    let mut got = Vec::new();
    wait_for(Duration::from_secs(10), || {
        while let Ok(Some(sample)) = served_reader.take() {
            assert_eq!(sample.label, format!("sample-{}", sample.value));
            assert_eq!(sample.total, f64::from(sample.value) * 0.5);
            got.push(sample.value);
        }
        got.len() >= WRITES as usize
    });
    assert_eq!(
        got,
        (1..=WRITES).collect::<Vec<_>>(),
        "the matched reader must receive every sample, in the writer's representation"
    );

    // Give stray traffic time to land, then check the refused reader.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        refused_status.matched.load(Ordering::SeqCst),
        0,
        "the reader that does not request the writer's representation must not match"
    );
    assert!(
        matches!(refused_reader.take(), Ok(None)),
        "the unmatched reader must receive nothing"
    );
}

#[test]
fn a_writer_offering_xcdr_then_xcdr2_serves_only_the_xcdr_reader() {
    run(&[XCDR, XCDR2], XCDR, (90, 91));
}

#[test]
fn a_writer_offering_xcdr2_then_xcdr_serves_only_the_xcdr2_reader() {
    run(&[XCDR2, XCDR], XCDR2, (92, 93));
}

#[test]
fn a_writer_offering_xcdr2_serves_only_the_xcdr2_reader() {
    run(&[XCDR2], XCDR2, (94, 95));
}

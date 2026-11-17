// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A remote writer whose QoS is incompatible with every reader this
//! participant has on its topic is blocked: the router drops its samples.
//! That verdict is about the readers that exist when the writer is
//! discovered. A reader created later that IS compatible with the writer
//! is matched with it, and must receive its samples (DDS v1.4 Sec.2.2.3:
//! communication is established between compatible entities).

use hdds::dds::{DataReaderListener, RequestedIncompatibleQosStatus, SubscriptionMatchedStatus};
use hdds::{Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
}

#[derive(Default)]
struct Seen {
    current: AtomicI32,
    incompat: AtomicU32,
}

impl DataReaderListener<Probe> for Seen {
    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_requested_incompatible_qos(&self, _status: RequestedIncompatibleQosStatus) {
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}

/// A writer of `writer_qos` in one participant; in another, a reader of
/// `first_reader_qos` (incompatible with the writer), then, once that reader
/// was told of the incompatibility, a reader of `later_reader_qos`
/// (compatible). The later reader receives what the writer writes; the
/// first does not.
fn a_compatible_reader_created_later_receives(
    name: &str,
    writer_qos: QoS,
    first_reader_qos: QoS,
    later_reader_qos: QoS,
) {
    let build = |suffix: &str| {
        Participant::builder(&format!("{name}_{suffix}"))
            .domain_id(0)
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .unwrap()
    };
    let subscriber = build("sub");
    let publisher = build("pub");
    let topic = format!("{name}_topic");

    let first_seen = Arc::new(Seen::default());
    let first = subscriber
        .topic::<Probe>(&topic)
        .unwrap()
        .reader()
        .qos(first_reader_qos)
        .with_listener(Arc::clone(&first_seen) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();
    let writer = publisher
        .topic::<Probe>(&topic)
        .unwrap()
        .writer()
        .qos(writer_qos)
        .build()
        .unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || first_seen
            .incompat
            .load(Ordering::SeqCst)
            > 0),
        "{name}: the first reader is told the writer is incompatible"
    );

    let later_seen = Arc::new(Seen::default());
    let later = subscriber
        .topic::<Probe>(&topic)
        .unwrap()
        .reader()
        .qos(later_reader_qos)
        .with_listener(Arc::clone(&later_seen) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || later_seen
            .current
            .load(Ordering::SeqCst)
            == 1),
        "{name}: the later reader is matched with the writer"
    );

    let mut received = Vec::new();
    let mut value = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while received.is_empty() && Instant::now() < deadline {
        value += 1;
        writer.write(&Probe { value }).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        while let Some(sample) = later.take().unwrap() {
            received.push(sample.value);
        }
    }
    assert!(
        !received.is_empty(),
        "{name}: the later, compatible reader receives the writer's samples"
    );
    let mut first_received = Vec::new();
    while let Some(sample) = first.take().unwrap() {
        first_received.push(sample.value);
    }
    assert!(
        first_received.is_empty(),
        "{name}: the first, incompatible reader receives nothing, got {first_received:?}"
    );
    assert_eq!(first_seen.current.load(Ordering::SeqCst), 0, "{name}");
}

#[test]
fn ownership_a_shared_reader_created_after_an_exclusive_one_receives() {
    a_compatible_reader_created_later_receives(
        "block_release_ownership",
        QoS::reliable(),
        QoS::reliable().ownership_exclusive(),
        QoS::reliable(),
    );
}

/// The gate reads DATA_REPRESENTATION (DDS-XTypes v1.3 Sec.7.6.3.1.1): an
/// XCDR2 writer is blocked for an XCDR-only reader, and released by a
/// reader that set no list (it requests `[XCDR, XCDR2]`, as it announces).
#[test]
fn data_representation_a_default_reader_created_after_an_xcdr1_one_receives() {
    a_compatible_reader_created_later_receives(
        "block_release_datarep",
        QoS::reliable().data_representation_xcdr2(),
        QoS::reliable().data_representation_xcdr1(),
        QoS::reliable(),
    );
}

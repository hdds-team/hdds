// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Each telemetry counter counts its event at the one door every path of
//! that kind goes through, whichever transport or accessor the application
//! uses. These tests drive the public API (a write on one participant, an
//! access on another) and assert the EXACT counter deltas.
//!
//! The collector is process-wide, so every test of this file holds
//! `ONE_AT_A_TIME` and reads deltas between two snapshots; the only
//! writers in the process are the ones the test itself created.

use hdds::dds::{Error, SampleRejectedReason};
use hdds::telemetry::{get_metrics, MetricsCollector};
use hdds::test_support::domains::unique_domain;
use hdds::{DataReader, DataWriter, Participant, QoS, TransportMode};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct Blob {
    value: i64,
    pad: Vec<u8>,
}

#[derive(hdds::DDS, Debug, Clone, PartialEq)]
struct Keyed {
    #[key]
    id: u32,
    value: i64,
}

static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A leased domain in the 200..=230 band (the band these tests
/// are allowed to use); leases the pool hands out below it are held only
/// until one in the band comes up.
fn domain() -> hdds::test_support::domains::DomainLease {
    let mut other = Vec::new();
    loop {
        let lease = unique_domain();
        if (200..=230).contains(&lease.id()) {
            return lease;
        }
        other.push(lease);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counts {
    sent: u64,
    bytes: u64,
    received: u64,
    dropped: u64,
    merge_full: u64,
    would_block: u64,
    ring_full: u64,
    slab: u64,
    transport_errors: u64,
}

impl Counts {
    fn now() -> Self {
        let m: Arc<MetricsCollector> = get_metrics();
        Self {
            sent: m.messages_sent(),
            bytes: m.bytes_sent(),
            received: m.messages_received(),
            dropped: m.messages_dropped(),
            merge_full: m.merge_full(),
            would_block: m.would_block(),
            ring_full: m.samples_rejected_ring_full(),
            slab: m.samples_rejected_slab_exhausted(),
            transport_errors: m.transport_errors(),
        }
    }

    fn since(self, before: Self) -> Self {
        Self {
            sent: self.sent - before.sent,
            bytes: self.bytes - before.bytes,
            received: self.received - before.received,
            dropped: self.dropped - before.dropped,
            merge_full: self.merge_full - before.merge_full,
            would_block: self.would_block - before.would_block,
            ring_full: self.ring_full - before.ring_full,
            slab: self.slab - before.slab,
            transport_errors: self.transport_errors - before.transport_errors,
        }
    }
}

fn intra(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant")
}

fn udp(name: &str, domain: u32, shm: bool) -> Arc<Participant> {
    let builder = Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast);
    let builder = if shm {
        builder.shm_policy(hdds::ShmPolicy::Prefer)
    } else {
        builder.shm_disable()
    };
    builder.build().expect("participant")
}

fn pair<T: hdds::api::DDS + 'static>(
    writer_side: &Arc<Participant>,
    reader_side: &Arc<Participant>,
    topic: &str,
    qos: QoS,
) -> (DataWriter<T>, DataReader<T>) {
    let reader = reader_side
        .topic::<T>(topic)
        .expect("reader topic")
        .reader()
        .qos(qos.clone())
        .build()
        .expect("reader");
    let writer = writer_side
        .topic::<T>(topic)
        .expect("writer topic")
        .writer()
        .qos(qos)
        .build()
        .expect("writer");
    (writer, reader)
}

/// Write `blob` until the reader takes it (a pairing is resolved
/// asynchronously on the wire), returning the sample taken. The writes
/// before the pairing are not asserted on: callers snapshot the counters
/// AFTER this warm-up.
fn warm_up(writer: &DataWriter<Blob>, reader: &DataReader<Blob>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let _ = writer.write(&Blob {
            value: -1,
            pad: vec![],
        });
        std::thread::sleep(Duration::from_millis(30));
        if reader.take().expect("warm-up take").is_some() {
            // Let any copy of the warm-up sample still in flight (a second
            // leg, a repair) land and be drained before the baseline.
            std::thread::sleep(Duration::from_millis(400));
            while reader.take().expect("drain").is_some() {}
            return;
        }
    }
    panic!("the pair never matched");
}

fn wait_taken(reader: &DataReader<Blob>, expected: i64) -> Blob {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(sample) = reader.take().expect("take") {
            assert_eq!(sample.value, expected, "samples arrive in order");
            return sample;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("sample {expected} never arrived");
}

/// Two different payload sizes: the bytes counter must move by exactly the
/// serialized-size difference, whatever the fixed header is.
fn bytes_for(writer: &DataWriter<Blob>, pad: usize) -> u64 {
    let before = get_metrics().bytes_sent();
    writer
        .write(&Blob {
            value: 0,
            pad: vec![7; pad],
        })
        .expect("write");
    get_metrics().bytes_sent() - before
}

#[test]
fn intra_process_counts_each_write_and_each_sample_once_for_every_accessor() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = domain();
    let publisher = intra("tc_intra_pub", domain.id());
    let subscriber = intra("tc_intra_sub", domain.id());
    let (writer, reader) = pair::<Blob>(
        &publisher,
        &subscriber,
        "tc_intra_roundtrip",
        QoS::reliable().keep_last(64),
    );

    // bytes_sent: the serialized payload, so +100 pad bytes is +100 bytes.
    let small = bytes_for(&writer, 10);
    let large = bytes_for(&writer, 110);
    assert_eq!(large - small, 100, "bytes_sent is the serialized size");
    assert!(small > 10, "the fixed part of the sample is counted too");
    while reader.take().expect("drain").is_some() {}

    // Six writes, then each accessor family on its own share of them.
    let before = Counts::now();
    for value in 0..6 {
        writer
            .write(&Blob {
                value,
                pad: vec![1; 10],
            })
            .expect("write");
    }
    let after_writes = Counts::now().since(before);
    assert_eq!(after_writes.sent, 6, "one messages_sent per write");
    assert_eq!(after_writes.bytes, 6 * small, "bytes_sent per write");

    // read(): does not consume, still the first arrival of each.
    assert!(reader.read().expect("read").is_some());
    // take_batch / take_with_info / take_next_sample / take / read_batch
    // after that must not add a second count for the same samples.
    let batch = reader.take_batch(2).expect("take_batch");
    assert_eq!(batch.len(), 2);
    assert!(reader.take_with_info().expect("take_with_info").is_some());
    assert!(reader.take().expect("take").is_some());
    #[allow(deprecated)]
    let legacy = reader.try_take().expect("try_take");
    assert!(legacy.is_some());
    let rest = reader.take_all().expect("take_all");
    assert_eq!(
        batch.len() + 3 + rest.len(),
        6,
        "read() consumes nothing: the other accessors take all six"
    );

    let delta = Counts::now().since(before);
    assert_eq!(
        delta.received, 6,
        "6 samples reached the reader: counted once each, whatever the accessor"
    );
    assert_eq!(delta.sent, 6);
    assert_eq!(delta.dropped, 0);
}

#[test]
fn the_other_write_variants_count_through_the_same_door() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = domain();
    let p = intra("tc_variants", domain.id());
    let (writer, reader) = pair::<Keyed>(&p, &p, "tc_variants_keyed", QoS::reliable().keep_all());

    let before = Counts::now();
    writer.write(&Keyed { id: 1, value: 1 }).expect("write");
    writer.write(&Keyed { id: 2, value: 2 }).expect("write");
    writer
        .write_w_timestamp(&Keyed { id: 3, value: 3 }, 1_700_000_000_000_000_000)
        .expect("write_w_timestamp");
    // A lifecycle change is not a message.
    writer.dispose(&Keyed { id: 1, value: 1 }).expect("dispose");
    let delta = Counts::now().since(before);
    assert_eq!(
        delta.sent, 3,
        "keyed write, write_w_timestamp: one each; dispose none"
    );
    assert!(delta.bytes > 0);
    let mut got = 0;
    while reader.take().expect("take").is_some() {
        got += 1;
    }
    assert_eq!(got, 3);
    assert_eq!(Counts::now().since(before).received, 3);
}

#[test]
fn a_udp_loopback_pair_counts_a_write_once_and_a_reception_once() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("HDDS_INTERFACE_ALLOW", "lo");
    let domain = domain();
    let publisher = udp("tc_udp_pub", domain.id(), false);
    let subscriber = udp("tc_udp_sub", domain.id(), false);
    let (writer, reader) = pair::<Blob>(
        &publisher,
        &subscriber,
        "tc_udp",
        QoS::reliable().keep_last(64),
    );
    warm_up(&writer, &reader);

    let small = bytes_for(&writer, 10);
    assert!(small > 10, "bytes_sent counted the payload");
    wait_taken(&reader, 0);
    let before = Counts::now();
    for value in 1..=5 {
        writer
            .write(&Blob {
                value,
                pad: vec![1; 10],
            })
            .expect("write");
        wait_taken(&reader, value);
    }
    std::thread::sleep(Duration::from_millis(300));
    let delta = Counts::now().since(before);
    assert_eq!(
        delta.sent, 5,
        "one messages_sent per write, not per datagram"
    );
    assert_eq!(delta.bytes, 5 * small);
    assert_eq!(
        delta.received, 5,
        "each sample is a reception once, over the wire"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_shared_memory_pair_counts_a_write_once_and_a_reception_once() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("HDDS_INTERFACE_ALLOW", "lo");
    let domain = domain();
    let publisher = udp("tc_shm_pub", domain.id(), true);
    let subscriber = udp("tc_shm_sub", domain.id(), true);
    let (writer, reader) = pair::<Blob>(
        &publisher,
        &subscriber,
        "tc_shm",
        QoS::best_effort().keep_last(64),
    );
    warm_up(&writer, &reader);

    let shm_before = hdds::transport::shm_global_metrics().writes();
    let small = bytes_for(&writer, 10);
    assert!(small > 10, "bytes_sent counted the payload");
    wait_taken(&reader, 0);
    let before = Counts::now();
    for value in 1..=5 {
        writer
            .write(&Blob {
                value,
                pad: vec![1; 10],
            })
            .expect("write");
        wait_taken(&reader, value);
    }
    std::thread::sleep(Duration::from_millis(300));
    let delta = Counts::now().since(before);
    assert!(
        hdds::transport::shm_global_metrics().writes() > shm_before,
        "fixture: the samples went over shared memory"
    );
    assert_eq!(delta.sent, 5);
    assert_eq!(delta.bytes, 5 * small);
    assert_eq!(
        delta.received, 5,
        "SHM and UDP legs are one reception per sample"
    );
}

#[test]
fn a_sample_pushed_out_of_a_keep_last_history_unread_is_a_drop() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = domain();
    let p = intra("tc_keeplast", domain.id());
    let (writer, reader) =
        pair::<Blob>(&p, &p, "tc_keeplast_drop", QoS::best_effort().keep_last(1));

    let before = Counts::now();
    for value in 0..5 {
        writer.write(&Blob { value, pad: vec![] }).expect("write");
    }
    let kept = reader.take_all().expect("take_all");
    assert_eq!(kept.len(), 1, "KEEP_LAST(1) keeps the newest");
    assert_eq!(kept[0].value, 4);
    let delta = Counts::now().since(before);
    assert_eq!(delta.dropped, 4, "the 4 samples replaced before being read");
    assert_eq!(delta.received, 5, "all 5 were deposited in the history");
}

#[test]
fn every_resource_limit_rejection_is_counted_in_exactly_one_rejection_counter() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = domain();
    let p = intra("tc_reject", domain.id());
    // A BEST_EFFORT KEEP_LAST(2) reader bounded to 3 samples across its
    // instances: a third instance's sample past the bound is dropped and
    // reported as REJECTED_BY_SAMPLES_LIMIT.
    let mut qos = QoS::best_effort().keep_last(2);
    qos.resource_limits.max_samples = 3;
    let (writer, reader) = pair::<Keyed>(&p, &p, "tc_reject_limit", qos);

    let before = Counts::now();
    for (id, value) in [(0, 1), (0, 2), (1, 1), (1, 2), (1, 3), (2, 1)] {
        let _ = writer.write(&Keyed { id, value });
    }
    let status = reader.get_sample_rejected_status();
    let delta = Counts::now().since(before);
    assert!(
        status.total_count > 0,
        "fixture: the reader rejected samples"
    );
    assert_eq!(status.last_reason, SampleRejectedReason::ResourceLimit);
    assert_eq!(
        delta.ring_full + delta.slab,
        u64::from(status.total_count),
        "every ResourceLimit report is one rejection counter increment"
    );
    assert_eq!(delta.ring_full, u64::from(status.total_count));
    assert_eq!(delta.slab, 0);
}

#[test]
fn a_write_refused_for_memory_is_a_would_block() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = domain();
    let p = intra("tc_wouldblock", domain.id());
    // BEST_EFFORT KEEP_ALL: the reader keeps what it is given, nothing is
    // taken, so the shared pool fills and a write comes back WouldBlock.
    let (writer, reader) =
        pair::<Blob>(&p, &p, "tc_wouldblock_fill", QoS::best_effort().keep_all());
    let before = Counts::now();
    let mut refused = 0u64;
    for value in 0..6000 {
        match writer.write(&Blob {
            value,
            pad: vec![1; 6000],
        }) {
            Ok(()) => {}
            Err(Error::WouldBlock) => {
                refused += 1;
                if refused >= 3 {
                    break;
                }
            }
            Err(other) => panic!("unexpected write error {other:?}"),
        }
    }
    let delta = Counts::now().since(before);
    assert!(refused > 0, "fixture: the pool filled up");
    assert_eq!(
        delta.would_block, refused,
        "one would_block per refused write"
    );
    drop(reader);
}

#[test]
fn a_failed_udp_send_is_a_transport_error_for_a_write_and_for_a_dispose() {
    use hdds::{MulticastMode, TransportOptions};

    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = domain();
    // Multicast emission off and no peer to unicast to: every send of the
    // writer's packet fails with `Unsupported`.
    let p = Participant::builder("tc_transport")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .shm_disable()
        .with_transport_options(TransportOptions::default().with_multicast(MulticastMode::Disabled))
        .build()
        .expect("participant");
    let writer = p
        .topic::<Keyed>("tc_transport_errors")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");

    let before = Counts::now();
    writer.write(&Keyed { id: 1, value: 1 }).expect("write");
    writer.write(&Keyed { id: 1, value: 2 }).expect("write");
    let after_writes = Counts::now().since(before);
    assert_eq!(after_writes.sent, 2, "the writes were accepted");
    assert_eq!(after_writes.transport_errors, 2, "each failed send, once");

    let disposed = writer.dispose(&Keyed { id: 1, value: 2 });
    assert!(
        matches!(disposed, Err(Error::TransportError)),
        "{disposed:?}"
    );
    let delta = Counts::now().since(before);
    assert_eq!(
        delta.transport_errors, 3,
        "a dispose whose send failed is counted like a write's"
    );
    assert_eq!(delta.sent, 2, "a dispose is not a message");
}

#[test]
fn a_wire_reader_whose_history_is_full_counts_its_rejections_as_ring_full() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("HDDS_INTERFACE_ALLOW", "lo");
    let domain = domain();
    let publisher = udp("tc_wire_full_pub", domain.id(), false);
    let subscriber = udp("tc_wire_full_sub", domain.id(), false);
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 2;
    let (writer, reader) = pair::<Blob>(&publisher, &subscriber, "tc_wire_full", qos);
    // The pair is matched once a sample crosses; that sample is one of the
    // two the reader keeps, and nothing is taken from here on.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && reader.read().expect("read").is_none() {
        let _ = writer.write(&Blob {
            value: -1,
            pad: vec![],
        });
        std::thread::sleep(Duration::from_millis(30));
    }
    std::thread::sleep(Duration::from_millis(300));

    let before = Counts::now();
    let status_before = reader.get_sample_rejected_status().total_count;
    for value in 0..10 {
        // A reliable writer may time out waiting for the reader's room:
        // the refusals are what is being counted, not the write result.
        let _ = writer.write(&Blob { value, pad: vec![] });
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(500));
    let delta = Counts::now().since(before);
    let reported = reader.get_sample_rejected_status().total_count - status_before;
    assert!(reported > 0, "fixture: the full history rejected samples");
    assert_eq!(delta.slab, 0);
    assert_eq!(
        delta.ring_full,
        u64::from(reported),
        "every ResourceLimit report of the wire reader is a ring-full count"
    );
}

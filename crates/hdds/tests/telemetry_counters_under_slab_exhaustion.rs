// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The counters of a process out of slab memory: a reader that cannot store
//! what it receives counts a `samples_rejected_slab_exhausted` for every
//! SAMPLE_REJECTED it reports, and a writer whose history cannot store a
//! change counts a `would_block` and a `cache_insert_errors`.
//!
//! The slab pool is one per process; the tests of this file take turns.

use hdds::core::rt::{get_slab_pool, SlabHandle};
use hdds::dds::Error;
use hdds::telemetry::get_metrics;
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Seq {
    value: u32,
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

/// Every byte the pool can give, largest requests first, the smallest class
/// included.
fn exhaust_everything() -> Vec<SlabHandle> {
    let pool = get_slab_pool();
    let mut held = Vec::new();
    for size in [1usize << 20, 1 << 16, 1 << 12, 1 << 8, 16, 1] {
        let payload = vec![0u8; size];
        while let Some(handle) = pool.bench_reserve_and_write(&payload) {
            held.push(handle);
        }
    }
    held.extend(pool.bench_reserve_and_write_head(&[0u8; 1]));
    held
}

fn release(held: Vec<SlabHandle>) {
    let pool = get_slab_pool();
    for handle in held {
        pool.release(handle);
    }
}

fn udp(name: &str, domain: u32, participant_id: u8) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .participant_id(Some(participant_id))
        .with_transport(TransportMode::UdpMulticast)
        .shm_disable()
        .build()
        .expect("participant")
}

/// Write one sample of a writer built with `qos` while the pool is empty:
/// `(result, would_block, cache_insert_errors, messages_sent)` deltas.
fn write_out_of_memory(
    name: &str,
    participant_id: u8,
    qos: QoS,
) -> (Result<(), Error>, u64, u64, u64) {
    let domain = domain();
    let p = udp(name, domain.id(), participant_id);
    let writer = p
        .topic::<Seq>(name)
        .expect("topic")
        .writer()
        .qos(qos)
        .build()
        .expect("writer");
    let held = exhaust_everything();
    assert!(!held.is_empty(), "the slab pool gave nothing");
    let m = get_metrics();
    let (wb, ci, sent) = (m.would_block(), m.cache_insert_errors(), m.messages_sent());
    let result = writer.write(&Seq { value: 1 });
    let deltas = (
        m.would_block() - wb,
        m.cache_insert_errors() - ci,
        m.messages_sent() - sent,
    );
    release(held);
    (result, deltas.0, deltas.1, deltas.2)
}

/// A RELIABLE writer waits for memory up to `max_blocking_time`: the
/// refusal is a TIMEOUT, not a WouldBlock, but the history still refused.
#[test]
fn a_reliable_write_the_history_cannot_store_is_a_cache_insert_error() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let (result, would_block, insert_errors, sent) = write_out_of_memory(
        "tc_slab_reliable",
        90,
        QoS::reliable()
            .keep_all()
            .max_blocking_time(Duration::from_millis(50)),
    );
    assert!(matches!(result, Err(Error::WriteTimeout)), "{result:?}");
    assert_eq!(insert_errors, 1, "the history refused the change once");
    assert_eq!(would_block, 0, "a timeout is not a would-block");
    assert_eq!(sent, 0, "a refused write is no message");
}

/// A BEST_EFFORT writer that keeps a history for late joiners does not wait:
/// out of memory its write comes back WouldBlock at once.
#[test]
fn a_best_effort_write_the_history_cannot_store_is_a_would_block() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let (result, would_block, insert_errors, sent) = write_out_of_memory(
        "tc_slab_best_effort",
        93,
        QoS::best_effort().transient_local().keep_last(8),
    );
    assert!(matches!(result, Err(Error::WouldBlock)), "{result:?}");
    assert_eq!(would_block, 1, "one WouldBlock returned, one counted");
    assert_eq!(insert_errors, 1);
    assert_eq!(sent, 0);
}

#[test]
fn a_reader_out_of_storage_counts_every_slab_rejection_it_reports() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = domain();
    let publisher = udp("tc_slab_pub", domain.id(), 91);
    let subscriber = udp("tc_slab_sub", domain.id(), 92);
    let reader = subscriber
        .topic::<Seq>("tc_slab_reader")
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_all())
        .build()
        .expect("reader");
    let writer = publisher
        .topic::<Seq>("tc_slab_reader")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().keep_all())
        .build()
        .expect("writer");
    std::thread::sleep(Duration::from_millis(1500));

    let m = get_metrics();
    let (slab, ring) = (
        m.samples_rejected_slab_exhausted(),
        m.samples_rejected_ring_full(),
    );
    // The writer is best-effort with no history: it needs no slab memory to
    // send; the reader needs it to store.
    let held = exhaust_everything();
    for value in 1..=10 {
        let _ = writer.write(&Seq { value });
    }
    std::thread::sleep(Duration::from_secs(1));
    let status = reader.get_sample_rejected_status();
    let (slab, ring) = (
        m.samples_rejected_slab_exhausted() - slab,
        m.samples_rejected_ring_full() - ring,
    );
    release(held);

    assert!(
        status.total_count >= 1,
        "fixture: the reader rejected: {status:?}"
    );
    assert_eq!(
        slab + ring,
        u64::from(status.total_count),
        "every ResourceLimit report is exactly one rejection counter increment"
    );
    assert_eq!(
        slab,
        u64::from(status.total_count),
        "all of them for the slab"
    );
    assert_eq!(ring, 0);
}

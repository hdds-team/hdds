// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A reader whose sample storage (the process-wide slab pool) is exhausted
//! refuses what it receives BEFORE acknowledging it. DDS 1.4 2.2.3.19: "If
//! the reliability is RELIABLE, the Service will block the DataWriter or
//! discard the sample at the DataReader in order not to lose existing
//! samples", footnote 28: "So that the sample can be re-sent at a later
//! time." A RELIABLE reader that acknowledged the sample first lost it for
//! good: the writer never sends an acknowledged change again (RTPS 2.5
//! 8.4.12.2, T8: `add_change`, then `received_change_set`).
//!
//! The slab pool is one per process: exhausting it in this test binary,
//! which holds this one test, disturbs nothing else.

use hdds::core::rt::{get_slab_pool, SlabHandle, SlabRef};
use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Seq {
    value: u32,
}

const TOPIC: &str = "OutOfStorage";
const REFUSED: u32 = 20;

/// Reserve every byte the slab pool can give, largest requests first, and
/// the one sample the next sample in order may take past the heap tier's
/// ceiling, then give back the slots of its smallest class (16 bytes). The writer keeps
/// its history in the same pool, and a `Seq` change (encapsulation and one
/// `u32`) fits there; the reader stores a sample behind its writer's
/// 16-byte GUID, which does not, and a reservation never falls back to a
/// smaller class.
fn exhaust_the_slab_pool_for_the_reader() -> Vec<SlabHandle> {
    let pool = get_slab_pool();
    let mut held = Vec::new();
    for size in [1usize << 20, 1 << 16, 1 << 12, 1 << 8, 16, 1] {
        let payload = vec![0u8; size];
        while let Some(handle) = pool.bench_reserve_and_write(&payload) {
            held.push(handle);
        }
    }
    held.extend(pool.bench_reserve_and_write_head(&[0u8; 1]));
    held.retain(|handle| {
        let smallest = matches!(handle.unpack(), SlabRef::Primary { pool_id: 0, .. });
        if smallest {
            pool.release(*handle);
        }
        !smallest
    });
    held
}

fn udp_participant(name: &str, domain_id: u32, participant_id: u8) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .participant_id(Some(participant_id))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

#[test]
fn a_reader_out_of_storage_refuses_before_acknowledging() {
    let domain = unique_domain();
    let publisher = udp_participant("out_of_storage_pub", domain.id(), 82);
    // Each reader in a participant of its own: a repair the writer sends to
    // the reliable reader never reaches the best-effort one.
    let reliable_sub = udp_participant("out_of_storage_reliable", domain.id(), 83);
    let best_effort_sub = udp_participant("out_of_storage_best_effort", domain.id(), 84);

    let reliable = reliable_sub
        .topic::<Seq>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reliable reader");
    let best_effort = best_effort_sub
        .topic::<Seq>(TOPIC)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort().keep_all())
        .build()
        .expect("best-effort reader");
    let writer = publisher
        .topic::<Seq>(TOPIC)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    std::thread::sleep(Duration::from_millis(1500));

    let held = exhaust_the_slab_pool_for_the_reader();
    assert!(!held.is_empty(), "the slab pool gave nothing");
    for value in 1..=REFUSED {
        writer.write(&Seq { value }).expect("write");
    }
    // Every sample arrives, and every HEARTBEAT that asks for it again.
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        reliable.take().expect("take"),
        None,
        "nothing stored, nothing to take"
    );
    assert_eq!(best_effort.take().expect("take"), None);
    let rejected = reliable.get_sample_rejected_status();
    assert!(
        rejected.total_count >= 1,
        "a refusal for want of storage is a SAMPLE_REJECTED: {rejected:?}"
    );
    let rejected = best_effort.get_sample_rejected_status();
    assert!(
        rejected.total_count >= 1,
        "a best-effort reader drops, and says so: {rejected:?}"
    );

    let pool = get_slab_pool();
    for handle in held {
        pool.release(handle);
    }

    // The reliable reader acknowledged none of them: the writer sends them
    // again, and they arrive once each, in order.
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while got.len() < REFUSED as usize && Instant::now() < deadline {
        while let Ok(Some(sample)) = reliable.take() {
            got.push(sample.value);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        got,
        (1..=REFUSED).collect::<Vec<_>>(),
        "the reliable reader lost what it refused"
    );

    // The best-effort reader is owed nothing: it lives on with what comes
    // next.
    writer.write(&Seq { value: REFUSED + 1 }).expect("write");
    let mut after = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !after.contains(&(REFUSED + 1)) && Instant::now() < deadline {
        while let Ok(Some(sample)) = best_effort.take() {
            after.push(sample.value);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        after,
        vec![REFUSED + 1],
        "a best-effort reader is not repaired"
    );
}

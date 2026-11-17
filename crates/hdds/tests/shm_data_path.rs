// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! End-to-end proof that a DDS sample crosses between two participants over
//! SHARED MEMORY, not merely that it arrives.
//!
//! # Why arrival proves nothing
//!
//! Both participants sit on the same host on the same domain. UDP would
//! deliver the sample perfectly well; so would the intra-process merger. A
//! test that only asserts `reader.take() == Some(sample)` passes identically
//! whether the shared-memory leg ran or silently fell back to UDP, which is
//! exactly the failure this whole slice exists to make impossible.
//!
//! # What is asserted instead
//!
//! The shared-memory ring's OWN counters, sampled before and after the
//! writes:
//!
//! * `writes` is incremented only by `ShmWriterLeg::push`, i.e. only when a
//!   framed RTPS packet was actually accepted into a shared-memory slot.
//! * `reads` is incremented only by the participant's SHM poller, and only
//!   after it has popped a packet out of the ring AND handed it to the
//!   Router through the participant's receive ring.
//!
//! **If the SHM leg silently fell back to UDP, both deltas would be zero**
//! (a UDP send touches neither counter, and with nothing in the ring the
//! poller has nothing to pop), the assertions below would fail, and they
//! would fail even though the sample still arrived over UDP. That is the
//! point: the arrival assertion and the transport assertion are independent,
//! and only the second one can tell the two transports apart.
//!
//! Linux only: `transport::shm` is a stub everywhere else, so there is
//! nothing to prove on other platforms.

#![cfg(target_os = "linux")]

use hdds::test_support::domains::unique_domain;
use hdds::transport::shm_global_metrics;
use hdds::{Participant, QoS, ShmPolicy, TransportMode};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct ShmProbe {
    value: u32,
}

/// One BEST_EFFORT writer and one BEST_EFFORT reader, in two participants on
/// one host, with the default `ShmPolicy::Prefer`.
#[test]
fn best_effort_sample_crosses_over_shared_memory() {
    let domain = unique_domain();
    let domain_id = domain.id();

    let publisher = match Participant::builder("shm_data_path_pub")
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .shm_policy(ShmPolicy::Prefer)
        .build()
    {
        Ok(participant) => participant,
        Err(error) => {
            eprintln!("SKIP shm_data_path: publisher participant failed to build: {error:?}");
            return;
        }
    };
    let subscriber = match Participant::builder("shm_data_path_sub")
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .shm_policy(ShmPolicy::Prefer)
        .build()
    {
        Ok(participant) => participant,
        Err(error) => {
            eprintln!("SKIP shm_data_path: subscriber participant failed to build: {error:?}");
            return;
        }
    };

    let writer = publisher
        .topic::<ShmProbe>("ShmDataPathProbe")
        .expect("writer topic")
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let reader = subscriber
        .topic::<ShmProbe>("ShmDataPathProbe")
        .expect("reader topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader");

    // Snapshot AFTER both endpoints exist but BEFORE any write, so the
    // deltas below can only come from this test's own samples.
    let before_writes = shm_global_metrics().writes();
    let before_reads = shm_global_metrics().reads();

    // BEST_EFFORT drops anything written before the pairing is resolved, and
    // the SHM verdict is resolved at pairing, so writing on a loop until the
    // sample lands is required (the same shape every BEST_EFFORT test in
    // this suite uses).
    let sample = ShmProbe { value: 0x0057_4D30 };
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut received = None;
    while Instant::now() < deadline {
        let _ = writer.write(&sample);
        if let Ok(Some(got)) = reader.take() {
            received = Some(got);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    assert_eq!(
        received,
        Some(sample.clone()),
        "the reader never received the sample at all"
    );

    // The counters can lag the take() above by one poller sweep, because the
    // sample could have reached the reader over the UDP leg first. Give the
    // shared-memory leg a bounded window to show itself.
    let counter_deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < counter_deadline {
        if shm_global_metrics().writes() > before_writes
            && shm_global_metrics().reads() > before_reads
        {
            break;
        }
        let _ = writer.write(&sample);
        let _ = reader.take();
        std::thread::sleep(Duration::from_millis(20));
    }

    let pushed = shm_global_metrics().writes() - before_writes;
    let popped = shm_global_metrics().reads() - before_reads;

    assert!(
        pushed > 0,
        "no framed RTPS packet was ever accepted into a shared-memory slot \
         ({} writes before, {} after): the writer took the UDP leg for every \
         sample, so the SHM data path is NOT wired even though the sample arrived",
        before_writes,
        shm_global_metrics().writes()
    );
    assert!(
        popped > 0,
        "the writer pushed {} packet(s) into shared memory but the subscriber's \
         SHM poller never popped one and handed it to the Router ({} reads before, \
         {} after): the receive half of the data path is dead and delivery came \
         from UDP",
        pushed,
        before_reads,
        shm_global_metrics().reads()
    );
}

/// `ShmPolicy::Require` is still refused at build time, and the error names
/// the part of the wired leg that does not cover it. If this ever starts
/// succeeding without the DATA_FRAG leg being wired, a large sample would
/// fall back to UDP under a policy whose entire point is that it never does.
#[test]
fn require_is_still_refused_with_a_reason() {
    let domain = unique_domain();
    let outcome = Participant::builder("shm_require_refused")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .shm_policy(ShmPolicy::Require)
        .build();
    let message = match outcome {
        Ok(_) => panic!("ShmPolicy::Require must be refused while the leg can fall back to UDP"),
        Err(error) => format!("{error:?}"),
    };
    assert!(
        message.contains("fragment"),
        "the refusal must name the fragmented-sample leg that still uses UDP, got: {message}"
    );
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Late-joiner reliability with VOLATILE durability over UDP.
//!
//! Reproduces several bugs that surfaced in late-joiner reliability and
//! history scenarios (as exercised by the OMG interoperability tests):
//!   1. Same-process intra-process binding delivers samples via TWO paths
//!      (TopicMerger + UDP loopback) leading to duplicates.
//!   2. SeqWindow returns 0 for the first remote sample, scrambling the
//!      cache's seq-based dedup.
//!   3. Historical samples written before a VOLATILE reader matched are
//!      delivered after match.
//!
//! It was `#[ignore]`d from v1.1.2 for the same-process duplication; it
//! passed on every run once that was gone, and its durability check only
//! asked that the first sample not be 1, which a replay of 2..25 satisfies.
//! It now asks that no sample written before the match arrives. The
//! repair-path case (a late VOLATILE reader receiving history through NACK
//! repair) is pinned separately in `data_reaches_the_reader_it_names.rs`.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Counter {
    value: u32,
}

#[test]
fn test_volatile_late_joiner_no_historical_samples() {
    const PRE_WRITE: u32 = 25;
    const POST_WRITE: u32 = 30;

    // Publisher and late-joining subscriber MUST share one domain -- the
    // late joiner has to discover the writer that has already been running.
    // Leased first so the lease outlives both participants.
    let domain = unique_domain();

    let pub_part = Participant::builder("late_pub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");

    let writer = pub_part
        .topic::<Counter>("LateJoinerTopic")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");

    // Wait a moment, then publish PRE_WRITE samples BEFORE any reader exists.
    thread::sleep(Duration::from_millis(200));
    for i in 1..=PRE_WRITE {
        writer.write(&Counter { value: i }).expect("pre-write");
        thread::sleep(Duration::from_millis(20));
    }
    // Long pause so any in-flight UDP buffer has time to drain before the
    // late joiner shows up. Helps distinguish "stale buffered packet" from
    // "history replay".
    thread::sleep(Duration::from_secs(2));

    // Late-joining reader.
    let sub_part = Participant::builder("late_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("subscriber participant");
    let reader = sub_part
        .topic::<Counter>("LateJoinerTopic")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // Background drain on the reader to capture every sample as it arrives.
    let received: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let received_clone = Arc::clone(&received);
    let drain = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            while let Ok(Some(sample)) = reader.take() {
                received_clone.lock().unwrap().push(sample.value);
            }
            thread::sleep(Duration::from_millis(10));
        }
    });

    // Wait for SEDP match, then keep publishing.
    thread::sleep(Duration::from_millis(400));
    for i in (PRE_WRITE + 1)..=(PRE_WRITE + POST_WRITE) {
        writer.write(&Counter { value: i }).expect("post-write");
        thread::sleep(Duration::from_millis(20));
    }

    drain.join().expect("drain join");

    let samples = received.lock().unwrap().clone();
    assert!(!samples.is_empty(), "subscriber received nothing");

    // Strict monotonic invariant per DDS spec for VOLATILE: every received
    // sample's value must be greater than or equal to the previous one.
    // Out-of-order or duplicated retransmits would break this.
    let mut prev = 0u32;
    for &v in &samples {
        assert!(
            v > prev,
            "non-monotonic stream: prev={} cur={} full={:?}",
            prev,
            v,
            samples
        );
        prev = v;
    }

    // VOLATILE durability (DDS 1.4 2.2.3.4): nothing written before the
    // reader matched. With the stream monotonic, the first sample decides.
    assert!(
        samples[0] > PRE_WRITE,
        "VOLATILE late joiner received historical sample {} (full stream={:?})",
        samples[0],
        samples
    );
}

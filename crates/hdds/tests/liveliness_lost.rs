// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! LIVELINESS_LOST (DDS v1.4 Sec.2.2.4.1): a MANUAL_BY_PARTICIPANT or
//! MANUAL_BY_TOPIC writer that stops asserting within its offered lease
//! raises it, read-and-reset; AUTOMATIC never does (the participant keeps
//! it alive on its own); any writer of a participant with
//! MANUAL_BY_PARTICIPANT liveliness keeps its siblings of that kind alive
//! too.
//!
//! One participant, no peer: the writer watches its OWN lease, so there is
//! nothing to kill and nothing to match. Real small leases polled with
//! `until`, like `liveliness_changed.rs` -- the writer's own scheduler
//! thread runs on the real clock, not an injectable one (that is exercised
//! at the unit level, `dds::liveliness::tests_writer`).

use hdds::api::{Liveliness, Participant, QoS};
use hdds::test_support::domains::unique_domain;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct Beat {
    n: u32,
}

const LEASE_MS: u64 = 100;

fn participant(name: &str, domain: u32) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(hdds::TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

/// Poll `read` until it returns `want`, for at most `within`.
fn until<T: PartialEq + std::fmt::Debug>(within: Duration, want: T, read: impl Fn() -> T) -> T {
    let deadline = Instant::now() + within;
    loop {
        let got = read();
        if got == want || Instant::now() >= deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_manual_by_topic_writer_silent_past_its_lease_raises_liveliness_lost() {
    let domain = unique_domain();
    let p = participant("liveliness_lost_by_topic", domain.id());
    let writer = p
        .topic::<Beat>("LivelinessLostByTopic")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness(Liveliness::manual_topic_millis(LEASE_MS)))
        .build()
        .expect("writer");
    let total = until(Duration::from_secs(5), 1, || {
        writer.get_liveliness_lost_status().total_count
    });
    assert_eq!(total, 1, "the writer never asserted after being built");
    // Read-and-reset (DDS v1.4 Sec.2.2.4.2.1): total survives the read,
    // the change does not.
    let again = writer.get_liveliness_lost_status();
    assert_eq!(again.total_count, 1);
    assert_eq!(again.total_count_change, 0);
}

#[test]
fn asserting_within_the_lease_keeps_a_manual_by_topic_writer_alive() {
    let domain = unique_domain();
    let p = participant("liveliness_kept_by_topic", domain.id());
    let writer = p
        .topic::<Beat>("LivelinessKeptByTopic")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness(Liveliness::manual_topic_millis(LEASE_MS)))
        .build()
        .expect("writer");
    let deadline = Instant::now() + Duration::from_millis(LEASE_MS * 6);
    while Instant::now() < deadline {
        writer.assert_liveliness().expect("assert_liveliness");
        std::thread::sleep(Duration::from_millis(LEASE_MS / 4));
    }
    assert_eq!(writer.get_liveliness_lost_status().total_count, 0);
}

#[test]
fn an_automatic_writer_never_raises_liveliness_lost() {
    let domain = unique_domain();
    let p = participant("liveliness_automatic_never_lost", domain.id());
    let writer = p
        .topic::<Beat>("LivelinessAutomaticNeverLost")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness_automatic_millis(LEASE_MS))
        .build()
        .expect("writer");
    std::thread::sleep(Duration::from_millis(LEASE_MS * 5));
    assert_eq!(
        writer.get_liveliness_lost_status().total_count,
        0,
        "AUTOMATIC: the participant asserts it, never the application's to miss"
    );
}

/// RTPS v2.5 Sec.8.4.13.5 R9: a MANUAL_BY_PARTICIPANT writer's own
/// LIVELINESS_LOST is renewed by ANY writer of that kind on the same
/// participant, not only its own write()/assert_liveliness().
#[test]
fn a_manual_by_participant_writer_is_kept_alive_by_a_sibling_writer() {
    let domain = unique_domain();
    let p = participant("liveliness_shared_by_participant", domain.id());
    let kept_silent = p
        .topic::<Beat>("LivelinessSharedSilent")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness_manual_participant_millis(LEASE_MS))
        .build()
        .expect("writer");
    let sibling = p
        .topic::<Beat>("LivelinessSharedSibling")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness_manual_participant_millis(LEASE_MS))
        .build()
        .expect("writer");
    let deadline = Instant::now() + Duration::from_millis(LEASE_MS * 6);
    while Instant::now() < deadline {
        sibling.write(&Beat { n: 1 }).expect("write");
        std::thread::sleep(Duration::from_millis(LEASE_MS / 4));
    }
    assert_eq!(
        kept_silent.get_liveliness_lost_status().total_count,
        0,
        "a sibling MANUAL_BY_PARTICIPANT writer's write() counts for it too"
    );
}

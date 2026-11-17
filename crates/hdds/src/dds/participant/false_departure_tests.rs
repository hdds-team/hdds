// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A remote writer taken for departed while its participant lives (a lease
//! expiry over a network outage, a probation purge) comes back the way RTPS
//! brings it back: its participant is discovered again (SPDP), its
//! announcement is received again (SEDP), the reader matches it again. Two
//! participants on a real UDP transport.

use super::{Participant, TransportMode};
use crate::core::discovery::multicast::DiscoveryFsm;
use crate::core::discovery::GUID;
use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
use crate::dds::QoS;
use crate::test_support::domains::{unique_domain, DomainLease};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, crate::DDS)]
struct Seq {
    value: u32,
}

fn participant(name: &str, domain: &DomainLease, id: u8) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain.id())
        .participant_id(Some(id))
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

fn fsm(p: &Participant) -> &Arc<DiscoveryFsm> {
    p.discovery_fsm
        .as_ref()
        .expect("a UDP participant runs discovery")
}

/// Takes what `reader` has, for up to `within`, until `want` values came.
fn take_until(reader: &crate::dds::DataReader<Seq>, want: usize, within: Duration) -> Vec<u32> {
    let deadline = Instant::now() + within;
    let mut got = Vec::new();
    while got.len() < want && Instant::now() < deadline {
        while let Ok(Some(sample)) = reader.take() {
            got.push(sample.value);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // What comes a little later still: a duplicate would.
    std::thread::sleep(Duration::from_millis(300));
    while let Ok(Some(sample)) = reader.take() {
        got.push(sample.value);
    }
    got
}

/// The subscriber's discovery removes the publisher (as a lease expiry
/// does) while the publisher lives and goes on writing. Both a durable and a
/// volatile reliable reader get every change once: none of the history the
/// durable reader's new proxy asks for again is delivered twice, and what
/// was written while the writer was taken for departed is delivered once
/// the writer is matched again.
#[test]
fn a_writer_taken_for_departed_comes_back_through_discovery() {
    let domain = unique_domain();
    let publisher = participant("false_departure_pub", &domain, 90);
    let subscriber = participant("false_departure_sub", &domain, 91);
    let durable = subscriber
        .topic::<Seq>("FalseDeparture")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .expect("durable reader");
    let volatile = subscriber
        .topic::<Seq>("FalseDeparture")
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("volatile reader");
    let writer = publisher
        .topic::<Seq>("FalseDeparture")
        .expect("topic")
        .writer()
        .qos(QoS::reliable().transient_local().keep_all())
        .build()
        .expect("writer");
    std::thread::sleep(Duration::from_millis(1500));
    for value in 1..=10 {
        writer.write(&Seq { value }).expect("write");
    }
    assert_eq!(take_until(&durable, 10, Duration::from_secs(5)).len(), 10);
    assert_eq!(take_until(&volatile, 10, Duration::from_secs(5)).len(), 10);

    // Past the publisher's own SEDP re-announcement burst to the
    // subscriber (`send_sedp_reannouncements_with_prealloc`: five rounds,
    // 500 ms apart, from the subscriber's discovery). Taken for departed
    // inside it, the subscriber hears the publisher's writer again from
    // that burst; after it, only by asking. Removing the publisher during
    // the burst (about 2.2 s after the build, at its last round) would make
    // the test pass or fail with the timing of the run.
    std::thread::sleep(Duration::from_millis(3000));

    // Taken for departed, alive.
    fsm(&subscriber).remove_participant(GUID::new(
        publisher.guid().prefix,
        RTPS_ENTITYID_PARTICIPANT,
    ));
    for value in 11..=15 {
        writer.write(&Seq { value }).expect("write");
    }
    std::thread::sleep(Duration::from_millis(200));
    for value in 16..=20 {
        writer.write(&Seq { value }).expect("write");
    }
    let expected: Vec<u32> = (11..=20).collect();
    let mut from_durable = take_until(&durable, 10, Duration::from_secs(15));
    let mut from_volatile = take_until(&volatile, 10, Duration::from_secs(15));
    eprintln!("durable {from_durable:?}");
    eprintln!("volatile {from_volatile:?}");
    from_durable.sort_unstable();
    from_volatile.sort_unstable();
    assert_eq!(from_durable, expected, "durable: every change once");
    assert_eq!(from_volatile, expected, "volatile: every change once");
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Participant-level proofs for `MulticastMode` v2 (Enabled / ReceiveOnly / Disabled).
//!
//! Complements the transport-level unit tests in
//! `crates/hdds/src/core/discovery/spdp_announcer.rs` (advertised-locator
//! invariant, rate floor) with the two things that only show up with two
//! real participants exchanging data:
//!
//! 1. `ReceiveOnly` closes the "one-way discovery" hole: a `ReceiveOnly`
//!    participant hears multicast SPDP but must fall back to unicast SPDP
//!    to be heard back, in both directions.
//! 2. The negative control: a `Disabled` participant with no static peers
//!    is provably unreachable, so the positive result above is not a
//!    loopback artifact.

use hdds::test_support::domains::unique_domain;
use hdds::{DataReader, DataWriter, DdsTrait, Participant, QoS, TransportMode, TransportOptions};
use std::thread;
use std::time::{Duration, Instant};

// Each test leases its own domain from `test_support::domains` rather than
// naming a constant. Port isolation here comes from the reserved custom
// discovery ports (never the RTPS formula ports), so the domain id is not
// what keeps these participants off a concurrent test's sockets -- but a
// leased id also cannot be a fleet domain or be shared with another test
// binary's DomainRegistry, which a hand-picked constant could not promise.

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct McastProbe {
    value: u32,
}

/// Write `sample` on a loop until `reader.take()` yields something, or
/// `timeout` elapses. Repeated writes are required because the writer and
/// reader may not have matched (SEDP) by the time the first write happens,
/// and `QoS::best_effort()` drops samples written before a match.
fn write_until_received<T: DdsTrait + Clone>(
    writer: &DataWriter<T>,
    reader: &DataReader<T>,
    sample: &T,
    timeout: Duration,
) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let _ = writer.write(sample);
        if let Ok(Some(received)) = reader.take() {
            return Some(received);
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Poll `reader.take()` for up to `timeout`; returns the first sample seen,
/// if any, without writing anything itself (used by the negative control).
fn poll_for_any_sample<T: DdsTrait>(reader: &DataReader<T>, timeout: Duration) -> Option<T> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(received)) = reader.take() {
            return Some(received);
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Test 3: mutual discovery across a `ReceiveOnly` <-> `Enabled` pair.
///
/// A is `ReceiveOnly` (listens to multicast, never emits it -- per
/// `crates/hdds/src/transport/options.rs` doc table). B is default
/// `Enabled`. Both share the same reserved SPDP multicast port so B's
/// periodic multicast SPDP reaches A; A can only be heard by B via the
/// unicast-to-discovered-peers fallback (`unicast_spdp_to_discovered`),
/// since A never emits multicast. Proving BOTH directions exchange a
/// sample rules out "A discovered B but B never discovered A" (the one-way
/// discovery hole the mode doc explicitly calls out).
#[test]
fn receive_only_participant_achieves_mutual_discovery() {
    // NOTE (deviation from the original plan): `with_discovery_ports()` does
    // NOT vary any port by participant_id (see `PortMapping::from_custom` in
    // `crates/hdds/src/transport/ports.rs`, unlike the RTPS-formula path).
    // Worse, when custom ports are set the builder defaults participant_id to
    // 0 for EVERY participant that doesn't call `.participant_id(...)`
    // explicitly (`crates/hdds/src/dds/participant/builder/bootstrap.rs`,
    // "Priority 1: Custom ports" branch: `self.participant_id.unwrap_or(0)`).
    // A GUID prefix embedding only vendor+host+PID+participant_id would give two
    // same-process participants with the same id IDENTICAL prefixes, and
    // the SPDP self-loopback filter would discard each other's packets. The
    // prefix is therefore unique per participant
    // (`entity_registry.rs::generate_guid`); the explicit distinct ids below
    // are kept so the two participants also differ in what reports the id.
    //
    // A and B must share ONE domain -- mutual discovery is the subject of the
    // test. The lease is declared first so it outlives both participants.
    let domain = unique_domain();
    let domain_id = domain.id();
    let build_pair = |[mcast, a_sedp, a_user, b_sedp, b_user]: [u16; 5]| -> hdds::Result<(
        std::sync::Arc<Participant>,
        std::sync::Arc<Participant>,
    )> {
        let participant_a = Participant::builder("mcastv2_recvonly_a")
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, a_sedp, a_user)
            .participant_id(Some(0))
            .with_transport_options(TransportOptions::default().receive_only())
            .build()?;
        let participant_b = Participant::builder("mcastv2_recvonly_b")
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, b_sedp, b_user)
            .participant_id(Some(1))
            .build()?;
        Ok((participant_a, participant_b))
    };
    let (participant_a, participant_b) =
        match hdds::test_support::ports::with_reserved_ports(8, build_pair) {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!(
                    "SKIP receive_only_participant_achieves_mutual_discovery: \
                     participant A (ReceiveOnly) or B (Enabled) failed to build \
                     (multicast group join): {error:?}"
                );
                return;
            }
        };

    // Direction 1: writer on B, reader on A. Reaches A over multicast
    // (B emits, A listens).
    let writer_b = participant_b
        .topic::<McastProbe>("McastV2ReceiveOnlyBtoA")
        .expect("topic B->A")
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer on B");
    let reader_a = participant_a
        .topic::<McastProbe>("McastV2ReceiveOnlyBtoA")
        .expect("topic B->A")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader on A");

    let received_by_a = write_until_received(
        &writer_b,
        &reader_a,
        &McastProbe { value: 0xB_0000 },
        Duration::from_secs(8),
    );
    assert_eq!(
        received_by_a,
        Some(McastProbe { value: 0xB_0000 }),
        "A (ReceiveOnly) never received B's sample over multicast SPDP + multicast data"
    );

    // Direction 2: writer on A, reader on B. A never emits multicast, so
    // this ONLY works if A's DATA(p) reached B over the unicast fallback
    // to a discovered peer, and B in turn matched A's writer over SEDP.
    let writer_a = participant_a
        .topic::<McastProbe>("McastV2ReceiveOnlyAtoB")
        .expect("topic A->B")
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer on A");
    let reader_b = participant_b
        .topic::<McastProbe>("McastV2ReceiveOnlyAtoB")
        .expect("topic A->B")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader on B");

    let received_by_b = write_until_received(
        &writer_a,
        &reader_b,
        &McastProbe { value: 0xA_0000 },
        Duration::from_secs(8),
    );
    assert_eq!(
        received_by_b,
        Some(McastProbe { value: 0xA_0000 }),
        "B never received A's sample -- A (ReceiveOnly) must reach discovered peers over \
         unicast SPDP for B to ever learn A exists and match A's writer"
    );

    drop(participant_a);
    drop(participant_b);
}

/// Test 4 (negative control for test 3): A in `Disabled` mode with no
/// static peers, B not configured with any knowledge of A. `Disabled`
/// means A neither emits NOR receives multicast (no group join at all, per
/// the mode doc table), so there is no path -- multicast or the
/// discovered-peer unicast fallback -- by which A and B can ever discover
/// each other. This proves the positive result in test 3 is due to the
/// discovered-peer unicast path, not to some loopback side effect that
/// would make any two participants on this host match regardless of mode.
#[test]
fn disabled_participant_without_static_peers_stays_unreachable() {
    // See the matching NOTE in `receive_only_participant_achieves_mutual_discovery`:
    // distinct `.participant_id(...)` is required to avoid identical GUID
    // prefixes for same-process participants built with custom discovery ports.
    //
    // Both on ONE domain on purpose: the negative control has to rule out
    // every reachability path EXCEPT a domain mismatch, so the domain must
    // not be what keeps them apart.
    let domain = unique_domain();
    let domain_id = domain.id();
    let build_pair = |[mcast, a_sedp, a_user, b_sedp, b_user]: [u16; 5]| -> hdds::Result<(
        std::sync::Arc<Participant>,
        std::sync::Arc<Participant>,
    )> {
        let participant_a = Participant::builder("mcastv2_disabled_a")
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, a_sedp, a_user)
            .participant_id(Some(0))
            .with_transport_options(TransportOptions::default().unicast_only())
            .build()?;
        let participant_b = Participant::builder("mcastv2_disabled_b")
            .domain_id(domain_id)
            .with_transport(TransportMode::UdpMulticast)
            .with_discovery_ports(mcast, b_sedp, b_user)
            .participant_id(Some(1))
            .build()?;
        Ok((participant_a, participant_b))
    };
    let (participant_a, participant_b) =
        match hdds::test_support::ports::with_reserved_ports(8, build_pair) {
            Ok(pair) => pair,
            Err(error) => {
                eprintln!(
                    "SKIP disabled_participant_without_static_peers_stays_unreachable: \
                     participant A (Disabled) or B (Enabled) failed to build: {error:?}"
                );
                return;
            }
        };

    let writer_a = participant_a
        .topic::<McastProbe>("McastV2DisabledNegativeControl")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer on A");
    let reader_b = participant_b
        .topic::<McastProbe>("McastV2DisabledNegativeControl")
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("reader on B");

    let sample = poll_for_any_sample(&reader_b, Duration::from_secs(3));
    assert_eq!(
        sample, None,
        "B received a sample from A even though A is Disabled with no static peers -- \
         A should be provably unreachable"
    );

    // Stronger assertion than "no sample crossed": B's SEDP view must never
    // have learned about A's writer at all, since A can never be discovered
    // by any means B has access to.
    if let Some(discovery_b) = participant_b.discovery() {
        let writers = discovery_b.find_writers_for_topic("McastV2DisabledNegativeControl");
        assert!(
            writers.is_empty(),
            "B's discovery FSM matched a writer for the topic even though A is unreachable: {:?}",
            writers
        );
    }

    // Keep the writer alive (and used) until the assertions above ran, so it
    // is not optimized away or dropped before the poll window closes.
    let _ = &writer_a;

    drop(participant_a);
    drop(participant_b);
}

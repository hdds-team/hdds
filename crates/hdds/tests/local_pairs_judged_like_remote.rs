// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A writer and a reader of the SAME participant are judged by the one QoS
//! verdict that judges them across participants, and communicate exactly
//! when it matches them.
//!
//! DDS v1.4 Sec.2.2.3: "If the two policies are not compatible, the Service
//! will not establish communications between the two Entity objects and
//! will record this fact by means of the OFFERED_INCOMPATIBLE_QOS on the
//! publisher end and REQUESTED_INCOMPATIBLE_QOS on the subscriber end".
//!
//! Two defects this pins. The record discovery kept of our own endpoints
//! was completed as a remote announcement missing its PIDs: a best-effort
//! writer read as RELIABLE, an EXCLUSIVE endpoint as SHARED, so the two ends
//! of one pair contradicted each other. And the in-process binding judged a
//! pair on three policies only: a VOLATILE writer fed a TRANSIENT_LOCAL
//! reader both ends reported incompatible.

use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus,
    RequestedIncompatibleQosStatus, SubscriptionMatchedStatus,
};
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

impl DataWriterListener<Probe> for Seen {
    fn on_publication_matched(&self, status: PublicationMatchedStatus) {
        self.current
            .store(status.current_count as i32, Ordering::SeqCst);
    }
    fn on_offered_incompatible_qos(&self, _policy_id: u32, _policy_name: &str) {
        self.incompat.fetch_add(1, Ordering::SeqCst);
    }
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

/// What one pairing reports and delivers.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    writer_matched: i32,
    reader_matched: i32,
    writer_incompatible: bool,
    reader_incompatible: bool,
    delivered: Vec<i64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    Match,
    /// Not matched, both ends told of the incompatibility.
    Incompatible,
    /// Not matched, told nothing (a PARTITION mismatch).
    Silent,
}

fn pairing(
    name: &str,
    mode: TransportMode,
    local: bool,
    writer_qos: QoS,
    reader_qos: QoS,
    expect: Expect,
) -> Outcome {
    // Only UDP opens real sockets; IntraProcess never touches a domain's
    // ports, so it keeps the harmless literal 0 instead of spending a lease.
    let lease = matches!(mode, TransportMode::UdpMulticast)
        .then(hdds::test_support::domains::unique_domain);
    let domain = lease.as_ref().map_or(0, |l| l.id());
    let build = |suffix: &str| {
        Participant::builder(&format!("{name}_{suffix}"))
            .domain_id(domain)
            .with_transport(mode)
            .build()
            .unwrap()
    };
    let publisher = build("pub");
    let subscriber = if local {
        Arc::clone(&publisher)
    } else {
        build("sub")
    };
    let topic = format!("{name}_{}", if local { "local" } else { "remote" });
    let writer_seen = Arc::new(Seen::default());
    let reader_seen = Arc::new(Seen::default());
    let writer = publisher
        .topic::<Probe>(&topic)
        .unwrap()
        .writer()
        .qos(writer_qos)
        .with_listener(Arc::clone(&writer_seen) as Arc<dyn DataWriterListener<Probe>>)
        .build()
        .unwrap();
    let reader = subscriber
        .topic::<Probe>(&topic)
        .unwrap()
        .reader()
        .qos(reader_qos)
        .with_listener(Arc::clone(&reader_seen) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();
    // IntraProcess participants have no `discovery_fsm`, hence no
    // `MatchNotificationRegistry` to report through SEDP -- but
    // domain_registry.rs's own `LocalMatchStatus` now reports exactly the
    // same status from the same verdict (`qos_verdict`/`scope_allows`), so
    // the wait below applies to both modes alike.
    let decided = || match expect {
        Expect::Match => {
            writer_seen.current.load(Ordering::SeqCst) == 1
                && reader_seen.current.load(Ordering::SeqCst) == 1
        }
        Expect::Incompatible => {
            writer_seen.incompat.load(Ordering::SeqCst) > 0
                && reader_seen.incompat.load(Ordering::SeqCst) > 0
        }
        Expect::Silent => false,
    };
    let window = if expect == Expect::Silent {
        1_500
    } else {
        5_000
    };
    wait_for(Duration::from_millis(window), decided);
    // Leave room for a late, contradicting report.
    std::thread::sleep(Duration::from_millis(300));
    writer.write(&Probe { value: 7 }).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let mut delivered = Vec::new();
    while let Some(sample) = reader.take().unwrap() {
        delivered.push(sample.value);
    }
    Outcome {
        writer_matched: writer_seen.current.load(Ordering::SeqCst),
        reader_matched: reader_seen.current.load(Ordering::SeqCst),
        writer_incompatible: writer_seen.incompat.load(Ordering::SeqCst) > 0,
        reader_incompatible: reader_seen.incompat.load(Ordering::SeqCst) > 0,
        delivered,
    }
}

fn expected(expect: Expect) -> Outcome {
    let matched = expect == Expect::Match;
    let incompatible = expect == Expect::Incompatible;
    Outcome {
        writer_matched: i32::from(matched),
        reader_matched: i32::from(matched),
        writer_incompatible: incompatible,
        reader_incompatible: incompatible,
        delivered: if matched { vec![7] } else { Vec::new() },
    }
}

/// The pairing within one participant, across two, and within one
/// IntraProcess participant: the same verdict, the same status, the same
/// delivery -- an IntraProcess participant has no `discovery_fsm`/
/// `MatchNotificationRegistry` of its own, but domain_registry.rs's
/// `LocalMatchStatus` reports PUBLICATION_MATCHED/SUBSCRIPTION_MATCHED and
/// OFFERED/REQUESTED_INCOMPATIBLE_QOS from the exact same verdict.
fn judged_alike(name: &str, writer_qos: QoS, reader_qos: QoS, expect: Expect) {
    let local = pairing(
        name,
        TransportMode::UdpMulticast,
        true,
        writer_qos.clone(),
        reader_qos.clone(),
        expect,
    );
    let remote = pairing(
        name,
        TransportMode::UdpMulticast,
        false,
        writer_qos.clone(),
        reader_qos.clone(),
        expect,
    );
    let intra = pairing(
        &format!("{name}_intra"),
        TransportMode::IntraProcess,
        true,
        writer_qos,
        reader_qos,
        expect,
    );
    assert_eq!(remote, expected(expect), "{name}: across two participants");
    assert_eq!(local, expected(expect), "{name}: within one participant");
    assert_eq!(
        intra,
        expected(expect),
        "{name}: within one IntraProcess participant"
    );
}

#[test]
fn exclusive_writer_exclusive_reader_match() {
    judged_alike(
        "pair_excl_excl",
        QoS::reliable().ownership_exclusive().ownership_strength(5),
        QoS::reliable().ownership_exclusive(),
        Expect::Match,
    );
}

#[test]
fn shared_writer_exclusive_reader_are_incompatible() {
    judged_alike(
        "pair_shared_excl",
        QoS::reliable(),
        QoS::reliable().ownership_exclusive(),
        Expect::Incompatible,
    );
}

#[test]
fn exclusive_writer_shared_reader_are_incompatible() {
    judged_alike(
        "pair_excl_shared",
        QoS::reliable().ownership_exclusive().ownership_strength(5),
        QoS::reliable(),
        Expect::Incompatible,
    );
}

#[test]
fn best_effort_writer_reliable_reader_are_incompatible() {
    judged_alike(
        "pair_be_rel",
        QoS::best_effort(),
        QoS::reliable(),
        Expect::Incompatible,
    );
}

#[test]
fn reliable_writer_best_effort_reader_match() {
    judged_alike(
        "pair_rel_be",
        QoS::reliable(),
        QoS::best_effort(),
        Expect::Match,
    );
}

#[test]
fn volatile_writer_transient_local_reader_are_incompatible() {
    judged_alike(
        "pair_vol_tl",
        QoS::reliable(),
        QoS::reliable().transient_local(),
        Expect::Incompatible,
    );
}

#[test]
fn transient_local_writer_volatile_reader_match() {
    judged_alike(
        "pair_tl_vol",
        QoS::reliable().transient_local(),
        QoS::reliable(),
        Expect::Match,
    );
}

#[test]
fn a_writer_deadline_longer_than_the_reader_deadline_is_incompatible() {
    judged_alike(
        "pair_deadline",
        QoS::reliable().deadline_millis(200),
        QoS::reliable().deadline_millis(100),
        Expect::Incompatible,
    );
}

#[test]
fn disjoint_partitions_do_not_match_and_report_nothing() {
    judged_alike(
        "pair_partition",
        QoS::reliable().partition_single("A"),
        QoS::reliable().partition_single("B"),
        Expect::Silent,
    );
}

#[test]
fn an_xcdr1_writer_and_an_xcdr2_reader_are_incompatible() {
    judged_alike(
        "pair_datarep",
        QoS::reliable().data_representation_xcdr1(),
        QoS::reliable().data_representation_xcdr2(),
        Expect::Incompatible,
    );
}

/// A reader that sets no DATA_REPRESENTATION announces `[XCDR, XCDR2]`
/// (`build_sedp_rtps_packet_secured`, every dialect): it requests both
/// (DDS-XTypes v1.3 Sec.7.6.3.1.1, a reader "shall request XCDR2" and may
/// also request XCDR). Our own verdict reads it the same way: an XCDR2
/// writer matches it, at both ends, wherever the writer lives.
#[test]
fn an_xcdr2_writer_and_a_default_reader_match() {
    judged_alike(
        "pair_x2_default",
        QoS::reliable().data_representation_xcdr2(),
        QoS::reliable(),
        Expect::Match,
    );
}

/// The same reader requests XCDR as well: an XCDR writer matches it.
#[test]
fn an_xcdr1_writer_and_a_default_reader_match() {
    judged_alike(
        "pair_x1_default",
        QoS::reliable().data_representation_xcdr1(),
        QoS::reliable(),
        Expect::Match,
    );
}

/// Two endpoints that set no DATA_REPRESENTATION match.
#[test]
fn a_default_writer_and_a_default_reader_match() {
    judged_alike(
        "pair_default_default",
        QoS::reliable(),
        QoS::reliable(),
        Expect::Match,
    );
}

/// A writer that sets no DATA_REPRESENTATION offers XCDR alone: DDS-XTypes
/// v1.3 Sec.7.6.3.1.1, "The default value of the DataRepresentationQosPolicy
/// shall be an empty list of preferences. An empty list of preferences shall
/// be taken to be equivalent to a list containing the single element XCDR",
/// and "Writers offer a single representation". A reader that requests XCDR2
/// alone is incompatible with it ("If a writer's offered representation is
/// contained within a reader's sequence, the offer satisfies the request and
/// the policies are compatible. Otherwise, they are incompatible"), at both
/// ends, wherever the reader lives, and receives nothing. Before: across two
/// participants the writer reported a match and the reader an
/// incompatibility; within one participant and in-process the pair matched
/// and the writer encoded XCDR2 for it.
#[test]
fn a_default_writer_and_an_xcdr2_reader_are_incompatible() {
    judged_alike(
        "pair_default_x2",
        QoS::reliable(),
        QoS::reliable().data_representation_xcdr2(),
        Expect::Incompatible,
    );
}

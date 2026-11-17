// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The data-plane gate of each (remote writer, local reader) pair on QoS
//! (`MatchNotificationRegistry::refused_pairs`, `Refusal::QOS`): judged by
//! the one QoS verdict (`rxo_verdict`) on every event that can change it,
//! and forgotten exactly when what it was about is gone.
//!
//! DDS v1.4 Sec.2.2.3: "for the Subscriber to receive data the DataReader's
//! requested value must be compatible with the DataWriter's offered value".

use super::*;
use crate::protocol::discovery::{SedpData, SpdpData};
use std::sync::atomic::AtomicI32;

const TOPIC: &str = "pair_topic";
const OUR_PREFIX: [u8; 12] = [0x01; 12];
const REMOTE_PREFIX: [u8; 12] = [0x0E; 12];
const OTHER_PREFIX: [u8; 12] = [0x0F; 12];

static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
    type_id: 0,
    type_name: "Simple",
    size_bytes: 8,
    alignment: 4,
    is_variable_size: false,
    fields: &[],
};

fn participant_guid(prefix: [u8; 12]) -> GUID {
    GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1])
}

fn writer_guid(prefix: [u8; 12], key: u8) -> GUID {
    GUID::new(prefix, [0x00, 0x00, key, 0x02])
}

fn spdp(prefix: [u8; 12]) -> SpdpData {
    SpdpData {
        participant_guid: participant_guid(prefix),
        lease_duration_ms: 100_000,
        domain_id: 0,
        metatraffic_unicast_locators: vec![],
        default_unicast_locators: vec![],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    }
}

fn announcement(writer: GUID, qos: QoS) -> SedpData {
    SedpData {
        topic_name: TOPIC.to_string(),
        type_name: DESC.type_name.to_string(),
        participant_guid: participant_guid(writer.prefix),
        endpoint_guid: writer,
        qos_hash: 1,
        qos: Some(qos),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    }
}

/// A discovery FSM and its match registry, as a participant builds them,
/// with `peers` known (and, when `confirmed`, past the probation and
/// confirmed, so that their matches surface).
fn discovery(
    peers: &[[u8; 12]],
    confirmed: bool,
) -> (Arc<DiscoveryFsm>, Arc<MatchNotificationRegistry>) {
    let fsm = Arc::new(DiscoveryFsm::new(participant_guid(OUR_PREFIX), 100_000));
    let reg = Arc::new(MatchNotificationRegistry::new(&fsm, OUR_PREFIX));
    fsm.set_match_registry(reg.clone());
    fsm.register_listener(reg.clone());
    if confirmed {
        // The FSM's probation is 250 ms of uptime, and a refresh counts
        // toward confirmation only 100 ms after the participant's entry was
        // created.
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    for prefix in peers {
        fsm.handle_spdp(spdp(*prefix));
    }
    if confirmed {
        std::thread::sleep(std::time::Duration::from_millis(150));
        for prefix in peers {
            fsm.handle_spdp(spdp(*prefix));
        }
        for prefix in peers {
            assert!(
                fsm.participant_may_surface_matches(prefix),
                "fixture: the peer's matches surface"
            );
        }
    }
    (fsm, reg)
}

/// What a reader entry was told.
#[derive(Default)]
struct Told {
    current: AtomicI32,
    incompat: AtomicU32,
    last_policy: AtomicU32,
}

fn reader(reg: &Arc<MatchNotificationRegistry>, qos: QoS) -> (MatchToken, Arc<Told>) {
    let told = Arc::new(Told::default());
    let (m, i) = (told.clone(), told.clone());
    let token = reg.register_reader_with_lifespan(
        TOPIC.into(),
        qos,
        &DESC,
        None,
        move |_, _, current, _, _| {
            m.current
                .store(i32::try_from(current).unwrap_or(i32::MAX), Ordering::SeqCst);
        },
        None,
        Some(Box::new(move |_, _, policy| {
            i.incompat.fetch_add(1, Ordering::SeqCst);
            i.last_policy.store(policy, Ordering::SeqCst);
        })),
        None,
        Arc::new(AtomicU64::new(u64::MAX)),
        ShmPolicy::default(),
    );
    (token, told)
}

fn refused(reg: &MatchNotificationRegistry, writer: GUID, token: &MatchToken) -> bool {
    reg.is_writer_refused_by(&writer.as_bytes(), token.id())
}

/// Two readers of one topic, one compatible with a remote writer and one
/// not, on every per-reader RxO policy of the verdict: the writer is
/// refused by the incompatible one only, whichever registered first.
#[test]
fn each_reader_is_judged_on_its_own_qos() {
    let cases: [(&str, QoS, QoS, QoS); 7] = [
        (
            "RELIABILITY",
            QoS::best_effort(),
            QoS::best_effort(),
            QoS::reliable(),
        ),
        (
            "DURABILITY",
            QoS::reliable(),
            QoS::reliable(),
            QoS::reliable().transient_local(),
        ),
        (
            "DEADLINE",
            QoS::reliable().deadline_millis(200),
            QoS::reliable().deadline_millis(500),
            QoS::reliable().deadline_millis(100),
        ),
        (
            "LIVELINESS",
            QoS::reliable(),
            QoS::reliable(),
            QoS::reliable().liveliness_manual_participant_secs(10),
        ),
        (
            "PRESENTATION",
            QoS::reliable(),
            QoS::reliable(),
            QoS::reliable().presentation_topic_coherent(),
        ),
        (
            "OWNERSHIP",
            QoS::reliable().ownership_exclusive(),
            QoS::reliable().ownership_exclusive(),
            QoS::reliable(),
        ),
        (
            "PARTITION",
            QoS::reliable().partition_single("A"),
            QoS::reliable().partition_single("A"),
            QoS::reliable().partition_single("B"),
        ),
    ];
    for (policy, writer_qos, compatible_qos, incompatible_qos) in cases {
        for readers_first in [true, false] {
            let (fsm, reg) = discovery(&[REMOTE_PREFIX], false);
            let writer = writer_guid(REMOTE_PREFIX, 1);
            let mut announce = announcement(writer, writer_qos.clone());
            announce.has_explicit_ownership = true;
            if !readers_first {
                fsm.handle_sedp(announce.clone());
            }
            let (compatible, _) = reader(&reg, compatible_qos.clone());
            let (incompatible, _) = reader(&reg, incompatible_qos.clone());
            if readers_first {
                fsm.handle_sedp(announce);
            }
            assert!(
                !refused(&reg, writer, &compatible),
                "{policy} (readers first: {readers_first}): the compatible reader is open"
            );
            assert!(
                refused(&reg, writer, &incompatible),
                "{policy} (readers first: {readers_first}): the incompatible reader is closed"
            );
        }
    }
}

/// A reader that leaves takes its verdicts with it; its sibling's stay.
#[test]
fn a_reader_leaving_takes_its_verdicts_with_it() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX], false);
    let writer = writer_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(writer, QoS::best_effort()));
    let (first, _) = reader(&reg, QoS::reliable());
    let (second, _) = reader(&reg, QoS::reliable());
    assert_eq!(reg.refused_pair_counts(), (1, 2));
    drop(first);
    assert_eq!(reg.refused_pair_counts(), (1, 1));
    assert!(refused(&reg, writer, &second));
    drop(second);
    assert_eq!(reg.refused_pair_counts(), (0, 0));
}

/// A writer's announcement held until its participant is known is judged
/// at once: its samples are routed by the topic it names from its arrival.
#[test]
fn an_announcement_held_for_its_participant_is_judged_at_once() {
    let (fsm, reg) = discovery(&[], false);
    let (open, _) = reader(&reg, QoS::best_effort());
    let (closed, _) = reader(&reg, QoS::reliable());
    let writer = writer_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(writer, QoS::best_effort()));
    assert!(
        fsm.current_endpoint(TOPIC, &writer).is_none(),
        "fixture: the announcement is held"
    );
    assert!(refused(&reg, writer, &closed));
    assert!(!refused(&reg, writer, &open));
}

/// A writer announced before its participant's match registry is installed
/// is judged at the installation, as one announced after it would have
/// been: the threads that receive announcements run before the registry is
/// set, and a peer does not repeat an announcement it saw accepted.
#[test]
fn a_writer_announced_before_the_registry_is_installed_is_judged_at_install() {
    let fsm = Arc::new(DiscoveryFsm::new(participant_guid(OUR_PREFIX), 100_000));
    fsm.handle_spdp(spdp(REMOTE_PREFIX));
    let writer = writer_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(writer, QoS::best_effort()));
    let reg = Arc::new(MatchNotificationRegistry::new(&fsm, OUR_PREFIX));
    fsm.set_match_registry(reg.clone());
    fsm.register_listener(reg.clone());
    let (closed, _) = reader(&reg, QoS::reliable());
    let (open, _) = reader(&reg, QoS::best_effort());
    assert_eq!(
        reg.writer_pair_verdict(&writer.as_bytes(), closed.id(), TOPIC),
        Some(false),
        "a reliable reader is refused by a best-effort writer"
    );
    assert_eq!(
        reg.writer_pair_verdict(&writer.as_bytes(), open.id(), TOPIC),
        Some(true),
        "a best-effort reader is compatible with a best-effort writer"
    );
}

/// A reader announced before the match registry is installed is judged at
/// the installation, as one announced after it would have been: its next
/// announcement is compared with the QoS it first announced, so a change that
/// flips its verdict against a local writer is acted on.
#[test]
fn a_reader_announced_before_the_registry_is_installed_is_judged_at_install() {
    let fsm = Arc::new(DiscoveryFsm::new(participant_guid(OUR_PREFIX), 100_000));
    fsm.handle_spdp(spdp(REMOTE_PREFIX));
    let remote_reader = reader_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(remote_reader, QoS::best_effort()));
    let reg = Arc::new(MatchNotificationRegistry::new(&fsm, OUR_PREFIX));
    fsm.set_match_registry(reg.clone());
    fsm.register_listener(reg.clone());
    let (_local, told) = writer(&reg, QoS::best_effort());
    assert_eq!(
        told.incompat.load(Ordering::SeqCst),
        0,
        "fixture: a best-effort reader is compatible with a best-effort writer"
    );
    fsm.handle_sedp(announcement(remote_reader, QoS::reliable()));
    assert_eq!(
        told.incompat.load(Ordering::SeqCst),
        1,
        "a reliable re-announcement of the reader is refused by the best-effort writer"
    );
}

/// A writer that said it is gone takes its verdicts with it: its SEDP
/// dispose, or its participant's announced departure. One whose
/// participant fell silent keeps them: it may come back as the same
/// writer without announcing it again, and the reader that refuses it
/// must still drop its samples. A writer of another participant is
/// untouched by all of it.
#[test]
fn a_writer_verdict_is_forgotten_when_it_says_it_left() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX, OTHER_PREFIX], false);
    let disposed = writer_guid(REMOTE_PREFIX, 1);
    let silent = writer_guid(REMOTE_PREFIX, 2);
    let other = writer_guid(OTHER_PREFIX, 1);
    let (closed, _) = reader(&reg, QoS::reliable());
    for writer in [disposed, silent, other] {
        fsm.handle_sedp(announcement(writer, QoS::best_effort()));
        assert!(refused(&reg, writer, &closed), "fixture: refused");
    }
    assert!(fsm.remove_remote_endpoint(disposed));
    assert!(!refused(&reg, disposed, &closed), "its SEDP dispose");
    assert!(refused(&reg, silent, &closed));

    fsm.remove_participant(participant_guid(REMOTE_PREFIX));
    assert!(
        refused(&reg, silent, &closed),
        "a participant that fell silent keeps its writers refused"
    );
    fsm.handle_spdp(spdp(REMOTE_PREFIX));
    fsm.remove_departed_participant(participant_guid(REMOTE_PREFIX));
    assert!(!refused(&reg, silent, &closed), "its announced departure");
    assert!(
        refused(&reg, other, &closed),
        "another participant's writer"
    );
    assert_eq!(reg.refused_pair_counts(), (1, 1));
}

/// A writer announced again with a new QoS is judged again: a pair it no
/// longer matches is refused, unmatched and reported incompatible; a pair
/// it matches again is opened and matched again. The statuses follow the
/// verdict the data plane applies.
#[test]
fn a_writer_announced_again_with_a_new_qos_is_judged_again() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX], true);
    let writer = writer_guid(REMOTE_PREFIX, 1);
    let (open, open_told) = reader(&reg, QoS::reliable().deadline_millis(1_000));
    let (tight, tight_told) = reader(&reg, QoS::reliable().deadline_millis(200));
    fsm.handle_sedp(announcement(writer, QoS::reliable().deadline_millis(100)));
    assert!(!refused(&reg, writer, &open));
    assert!(!refused(&reg, writer, &tight));
    assert_eq!(open_told.current.load(Ordering::SeqCst), 1);
    assert_eq!(tight_told.current.load(Ordering::SeqCst), 1);

    // DEADLINE is changeable (DDS v1.4 Sec.2.2.3.7): now slower than the
    // tight reader requests.
    fsm.handle_sedp(announcement(writer, QoS::reliable().deadline_millis(500)));
    assert!(
        !refused(&reg, writer, &open),
        "still within the open reader's"
    );
    assert!(
        refused(&reg, writer, &tight),
        "slower than the tight reader's"
    );
    assert_eq!(open_told.current.load(Ordering::SeqCst), 1);
    assert_eq!(tight_told.current.load(Ordering::SeqCst), 0, "unmatched");
    assert_eq!(tight_told.incompat.load(Ordering::SeqCst), 1);
    assert_eq!(
        tight_told.last_policy.load(Ordering::SeqCst),
        crate::dds::qos::policy_id::DEADLINE,
        "DEADLINE"
    );
    assert_eq!(open_told.incompat.load(Ordering::SeqCst), 0);

    // The same announcement again changes nothing.
    fsm.handle_sedp(announcement(writer, QoS::reliable().deadline_millis(500)));
    assert_eq!(tight_told.incompat.load(Ordering::SeqCst), 1);
    assert_eq!(tight_told.current.load(Ordering::SeqCst), 0);

    // Back within it: opened and matched again.
    fsm.handle_sedp(announcement(writer, QoS::reliable().deadline_millis(100)));
    assert!(!refused(&reg, writer, &tight));
    assert_eq!(
        tight_told.current.load(Ordering::SeqCst),
        1,
        "matched again"
    );
    assert_eq!(open_told.current.load(Ordering::SeqCst), 1);
}

/// A reader created while an incompatible writer's announcement is held
/// for its participant is judged against it at once: the writer's samples
/// are routed by the topic it names from the announcement's arrival, before
/// the replay. A compatible reader created at the same time is open.
#[test]
fn a_reader_created_while_a_writer_is_held_is_judged_against_it() {
    let (fsm, reg) = discovery(&[], false);
    let writer = writer_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(writer, QoS::best_effort()));
    assert!(
        fsm.current_endpoint(TOPIC, &writer).is_none(),
        "fixture: the announcement is held"
    );
    let (closed, _) = reader(&reg, QoS::reliable());
    let (open, _) = reader(&reg, QoS::best_effort());
    assert!(
        refused(&reg, writer, &closed),
        "a reader created while the writer is held is closed to it"
    );
    assert!(!refused(&reg, writer, &open));
}

/// A writer whose participant fell silent keeps its verdicts, and a reader
/// created after that is judged against it too: the router still routes
/// its samples by the topic it announced. A compatible reader created then
/// is open to it.
#[test]
fn a_reader_created_after_a_silent_departure_is_judged_against_its_writers() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX], false);
    let writer = writer_guid(REMOTE_PREFIX, 1);
    let (old, _) = reader(&reg, QoS::reliable());
    fsm.handle_sedp(announcement(writer, QoS::best_effort()));
    fsm.remove_participant(participant_guid(REMOTE_PREFIX));
    assert!(
        fsm.current_endpoint(TOPIC, &writer).is_none(),
        "fixture: discovery forgot the writer"
    );
    assert!(
        refused(&reg, writer, &old),
        "fixture: kept for the old reader"
    );
    let (new, _) = reader(&reg, QoS::reliable());
    let (open, _) = reader(&reg, QoS::best_effort());
    assert!(
        refused(&reg, writer, &new),
        "a reader created after the silence is closed to it too"
    );
    assert!(!refused(&reg, writer, &open));
}

/// A writer forgotten because it said it left is no longer judged: a
/// reader created after its participant's announced departure records
/// nothing about it.
#[test]
fn a_writer_that_said_it_left_is_not_judged_for_later_readers() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX], false);
    let writer = writer_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(writer, QoS::best_effort()));
    fsm.remove_departed_participant(participant_guid(REMOTE_PREFIX));
    let (later, _) = reader(&reg, QoS::reliable());
    assert!(!refused(&reg, writer, &later));
    assert_eq!(reg.refused_pair_counts(), (0, 0));
}

/// A held writer's SEDP dispose takes its verdicts with it, for the readers
/// that existed and for those created after.
#[test]
fn a_held_writers_dispose_takes_its_verdicts_with_it() {
    let (fsm, reg) = discovery(&[], false);
    let (closed, _) = reader(&reg, QoS::reliable());
    let writer = writer_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(writer, QoS::best_effort()));
    assert!(refused(&reg, writer, &closed), "fixture: held and refused");
    assert!(
        !fsm.remove_remote_endpoint(writer),
        "fixture: discovery did not hold it as known"
    );
    assert!(!refused(&reg, writer, &closed), "its dispose");
    let (later, _) = reader(&reg, QoS::reliable());
    assert!(
        !refused(&reg, writer, &later),
        "nor judged for a later reader"
    );
    assert_eq!(reg.refused_pair_counts(), (0, 0));
}

/// Announcements held for participants that never appear are judged only
/// when held: one the full buffer drops arms nothing, so the gate never
/// holds more held writers than the buffer does.
#[test]
fn an_announcement_the_full_buffer_drops_arms_nothing() {
    let (fsm, reg) = discovery(&[], false);
    let (closed, _) = reader(&reg, QoS::reliable());
    let mut writers = Vec::new();
    for i in 0..300u16 {
        let mut prefix = [0x77u8; 12];
        prefix[..2].copy_from_slice(&i.to_le_bytes());
        let writer = writer_guid(prefix, 1);
        fsm.handle_sedp(announcement(writer, QoS::best_effort()));
        writers.push(writer);
    }
    assert_eq!(
        reg.refused_pair_counts(),
        (64, 64),
        "as many as the held buffer keeps"
    );
    assert!(refused(&reg, writers[63], &closed), "the last one held");
    assert!(
        !refused(&reg, writers[64], &closed),
        "the first one dropped"
    );
    let (later, _) = reader(&reg, QoS::reliable());
    assert!(refused(&reg, writers[0], &later));
    assert!(
        !refused(&reg, writers[299], &later),
        "a dropped one is not judged for a later reader either"
    );
}

fn reader_guid(prefix: [u8; 12], key: u8) -> GUID {
    GUID::new(prefix, [0x00, 0x00, key, 0x07])
}

/// What a writer entry was told: its match count, its incompatible-QoS
/// reports, and whether discovery holds a proxy of the remote reader
/// (`PeerChange`, 1 or 0).
#[derive(Default)]
struct WriterTold {
    current: AtomicI32,
    incompat: AtomicU32,
    last_policy: AtomicU32,
    proxies: AtomicI32,
}

fn writer(reg: &Arc<MatchNotificationRegistry>, qos: QoS) -> (MatchToken, Arc<WriterTold>) {
    let told = Arc::new(WriterTold::default());
    let (m, i, p) = (told.clone(), told.clone(), told.clone());
    let token = reg.register_writer_with_peers(
        TOPIC.into(),
        qos,
        &DESC,
        None,
        move |_, _, current, _, _| {
            m.current
                .store(i32::try_from(current).unwrap_or(i32::MAX), Ordering::SeqCst);
        },
        Some(Box::new(move |change| match change {
            // A repeated `Matched` is a no-op for the hook (one proxy per
            // GUID): what is held is whether the proxy exists.
            PeerChange::Matched { .. } => p.proxies.store(1, Ordering::SeqCst),
            PeerChange::Unmatched { .. } => p.proxies.store(0, Ordering::SeqCst),
        })),
        Some(Box::new(move |_, _, policy| {
            i.incompat.fetch_add(1, Ordering::SeqCst);
            i.last_policy.store(policy, Ordering::SeqCst);
        })),
        None,
        ShmPolicy::default(),
        None,
    );
    (token, told)
}

/// A remote READER announced again with a new QoS is judged again by our
/// writers, as a remote writer is by our readers: a pair it no longer
/// matches is unmatched (its proxy released) and reported incompatible
/// with the policy's QosPolicyId_t; a pair it matches again is matched
/// again. DEADLINE and LATENCY_BUDGET are changeable (DDS v1.4 Sec.2.2.3)
/// and RxO ("offered deadline period <= requested", "offered duration <=
/// requested duration").
#[test]
fn a_reader_announced_again_with_a_new_qos_is_judged_again() {
    let cases = [
        (
            "DEADLINE",
            crate::dds::qos::policy_id::DEADLINE,
            QoS::reliable().deadline_millis(100),
            QoS::reliable().deadline_millis(1_000),
            QoS::reliable().deadline_millis(50),
        ),
        (
            "LATENCY_BUDGET",
            crate::dds::qos::policy_id::LATENCY_BUDGET,
            QoS::reliable().latency_budget_millis(10),
            QoS::reliable().latency_budget_millis(100),
            QoS::reliable().latency_budget_millis(5),
        ),
    ];
    for (policy, id, writer_qos, open_qos, tight_qos) in cases {
        let (fsm, reg) = discovery(&[REMOTE_PREFIX], true);
        let reader = reader_guid(REMOTE_PREFIX, 1);
        let (_token, told) = writer(&reg, writer_qos);
        fsm.handle_sedp(announcement(reader, open_qos.clone()));
        assert_eq!(told.current.load(Ordering::SeqCst), 1, "{policy}: matched");
        assert_eq!(told.proxies.load(Ordering::SeqCst), 1, "{policy}: a proxy");

        fsm.handle_sedp(announcement(reader, tight_qos.clone()));
        assert_eq!(
            told.current.load(Ordering::SeqCst),
            0,
            "{policy}: unmatched"
        );
        assert_eq!(told.proxies.load(Ordering::SeqCst), 0, "{policy}: released");
        assert_eq!(told.incompat.load(Ordering::SeqCst), 1, "{policy}");
        assert_eq!(told.last_policy.load(Ordering::SeqCst), id, "{policy}");

        // The same announcement again changes nothing.
        fsm.handle_sedp(announcement(reader, tight_qos));
        assert_eq!(told.incompat.load(Ordering::SeqCst), 1, "{policy}");
        assert_eq!(told.current.load(Ordering::SeqCst), 0, "{policy}");

        // Back within it: matched again.
        fsm.handle_sedp(announcement(reader, open_qos));
        assert_eq!(told.current.load(Ordering::SeqCst), 1, "{policy}: again");
        assert_eq!(told.proxies.load(Ordering::SeqCst), 1, "{policy}: again");
    }
}

/// A local endpoint is found by its GUID (`MatchToken::bind_local_guid`),
/// with the remote endpoints it is matched with, for as long as it exists:
/// what the CryptoTokens of DDS Security v1.1 Sec.7.4.4.6.2-3 are
/// addressed by and checked against. Through the FSM too, which is where
/// the security plugins read it.
///
/// Mutant: `unregister` leaving the GUID behind keeps a name for an
/// entry that is gone, one more for every endpoint ever deleted (the last
/// assertion).
#[test]
fn a_local_endpoint_is_found_by_its_guid_with_its_matches_until_deleted() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX], true);
    let local = reader_guid(OUR_PREFIX, 9);
    let (token, _) = reader(&reg, QoS::reliable());
    assert_eq!(reg.local_endpoint_matches(&local), None, "not named yet");
    token.bind_local_guid(local);
    assert_eq!(reg.local_endpoint_matches(&local), Some(vec![]));

    let writer = writer_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(writer, QoS::reliable()));
    assert_eq!(reg.local_endpoint_matches(&local), Some(vec![writer]));
    assert_eq!(fsm.local_endpoint_matches(&local), Some(vec![writer]));
    assert_eq!(
        reg.local_endpoint_matches(&reader_guid(OUR_PREFIX, 10)),
        None,
        "another GUID is no endpoint here"
    );

    drop(token);
    assert_eq!(reg.local_endpoint_matches(&local), None, "deleted");
    assert_eq!(reg.named_local_endpoints(), 0, "its name leaves with it");
}

/// The install's catch-up does not judge a writer a live announcement has
/// judged: its verdict is the live one, and the next announcement is compared
/// with it.
#[test]
fn a_catch_up_leaves_a_writer_judged_live_alone() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX], true);
    let writer = writer_guid(REMOTE_PREFIX, 1);
    let (tight, told) = reader(&reg, QoS::reliable().deadline_millis(200));
    fsm.handle_sedp(announcement(writer, QoS::reliable().deadline_millis(100)));
    assert_eq!(
        told.current.load(Ordering::SeqCst),
        1,
        "fixture: matched live"
    );

    let catch_up = EndpointInfo::from_sedp(
        announcement(writer, QoS::reliable().deadline_millis(100)),
        None,
    );
    assert!(
        !reg.judge_unrecorded_remote_writer(&catch_up),
        "a writer with a verdict on record is not judged again"
    );

    fsm.handle_sedp(announcement(writer, QoS::reliable().deadline_millis(500)));
    assert!(
        refused(&reg, writer, &tight),
        "the live verdict is the baseline of the next announcement"
    );
    assert_eq!(
        told.current.load(Ordering::SeqCst),
        0,
        "unmatched by the change"
    );
}

/// The install's catch-up records nothing for a writer discovery does not hold:
/// it would be a verdict for a writer that is gone.
#[test]
fn a_catch_up_does_not_judge_a_writer_discovery_does_not_hold() {
    let (_fsm, reg) = discovery(&[REMOTE_PREFIX], true);
    let writer = writer_guid(REMOTE_PREFIX, 1);
    let (open, _) = reader(&reg, QoS::best_effort());
    let catch_up = EndpointInfo::from_sedp(announcement(writer, QoS::best_effort()), None);
    assert!(
        !reg.judge_unrecorded_remote_writer(&catch_up),
        "not held by discovery: not recorded"
    );
    assert_eq!(
        reg.writer_pair_verdict(&writer.as_bytes(), open.id(), TOPIC),
        None,
        "no verdict on record for the writer"
    );
}

/// The install's catch-up leaves a remote reader's baseline alone when a live
/// announcement has recorded it.
#[test]
fn a_catch_up_leaves_a_reader_judged_live_alone() {
    let (fsm, reg) = discovery(&[REMOTE_PREFIX], true);
    let remote_reader = reader_guid(REMOTE_PREFIX, 1);
    fsm.handle_sedp(announcement(remote_reader, QoS::best_effort()));
    let catch_up = EndpointInfo::from_sedp(announcement(remote_reader, QoS::best_effort()), None);
    assert!(
        !reg.judge_unrecorded_remote_reader(&catch_up),
        "a reader with a baseline on record is not judged again"
    );
}

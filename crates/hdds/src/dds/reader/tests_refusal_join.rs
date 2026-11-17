// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A VOLATILE reliable reader joins each writer at the first DATA it
//! receives (its reorder gate is seeded by the first DATA): older history is
//! from before the join, and is dropped. A DATA the reader receives and
//! drops without acknowledging it, so that the writer sends it again, is
//! received all the same: the join point is at it, wherever it was dropped.
//! Joined at the first DATA it KEPT instead, the reader delivered the later
//! ones first and then dropped the repair of the earlier one as history
//! from before the join, acknowledged: lost for good.
//!
//! One test per door that drops a DATA unacknowledged before the gate sees
//! it: the duplicate record full, coherent staging refusing, the staged
//! duplicate record full, an OWNERSHIP-deferred sample evicted, and (with
//! `security`) a sample whose data key has not arrived yet.

use super::tests::{encoded_point, Point};
use crate::core::rt;
use crate::engine::Subscriber;
use std::sync::{Arc, Mutex};

const WRITER: [u8; 16] = [0x5A; 16];
const OTHER: [u8; 16] = [0x5B; 16];

/// A reliable network subscriber behind a VOLATILE gate, crediting
/// `credit`, delivering into a ring of `usable` entries whose room it
/// reserves; TOPIC-scope coherent access when `coherent`.
fn volatile_subscriber(
    topic: &str,
    credit: &crate::core::reader::ReaderAckCredit,
    usable: usize,
    coherent: bool,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    volatile_subscriber_matching(topic, credit, usable, coherent, None)
}

/// `volatile_subscriber`, its pairings judged by `registry`.
fn volatile_subscriber_matching(
    topic: &str,
    credit: &crate::core::reader::ReaderAckCredit,
    usable: usize,
    coherent: bool,
    registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    volatile_subscriber_in(
        topic,
        credit,
        usable,
        coherent,
        registry,
        crate::qos::partition::Partition::default(),
    )
}

/// `volatile_subscriber_matching`, the reader in `partition`.
fn volatile_subscriber_in(
    topic: &str,
    credit: &crate::core::reader::ReaderAckCredit,
    usable: usize,
    coherent: bool,
    registry: Option<Arc<crate::dds::match_notification::MatchNotificationRegistry>>,
    partition: crate::qos::partition::Partition,
) -> (
    Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    let _ = rt::init_slab_pool();
    let ring = Arc::new(rt::IndexRing::with_capacity(usable + 1));
    assert_eq!(ring.usable_capacity(), usable, "a power of two minus one");
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        topic.to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, true))),
        super::subscriber::CoherentConfig {
            coherent_access: coherent,
            is_group_scope: false,
        },
        registry,
        Some(credit.clone()),
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        partition.clone(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    sub.room = Some(super::admission::HistoryRoom::new(
        &ring,
        crate::reliability::LENGTH_UNLIMITED,
    ));
    // Registered with its match registry, as the builder registers it: an
    // unregistered reader is matched with nothing and refuses every writer.
    sub.register_match_entry_for_test(crate::dds::QoS::reliable().partition(partition));
    (ring, sub)
}

fn credit_for(writers: &[[u8; 16]]) -> crate::core::reader::ReaderAckCredit {
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    for writer in writers {
        credit.match_writer(*writer);
    }
    credit
}

/// What the reader answers `writer`'s HEARTBEAT `first..=last`: its
/// acknowledgement base and what it asks again.
fn answer(
    credit: &crate::core::reader::ReaderAckCredit,
    writer: &[u8; 16],
    first: i64,
    last: i64,
    count: u32,
) -> (u64, Vec<u64>) {
    let answer = credit
        .answer_heartbeat(
            writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: first,
                last_seq: last,
                count,
                final_flag: false,
            },
        )
        .expect("matched");
    (answer.bitmap_base, answer.missing)
}

fn data(seq: u64) -> Vec<u8> {
    let value = i32::try_from(seq % 1_000_000).expect("small");
    encoded_point(value, value)
}

fn plain(sub: &super::subscriber::ReaderSubscriber<Point>, writer: [u8; 16], seq: u64) {
    sub.on_data_with_writer("t", writer, seq, &data(seq), crate::dds::CdrVersion::Xcdr2);
}

fn coherent(
    sub: &super::subscriber::ReaderSubscriber<Point>,
    writer: [u8; 16],
    seq: u64,
    set_start: u64,
) {
    sub.on_data_coherent(
        "t",
        writer,
        seq,
        &data(seq),
        crate::dds::CdrVersion::Xcdr2,
        Some(set_start),
        None,
        None,
    );
}

/// The sequences in `ring`, in ring order, every entry given back.
fn drain(ring: &rt::IndexRing, sub: &super::subscriber::ReaderSubscriber<Point>) -> Vec<u64> {
    let pool = rt::get_slab_pool();
    let mut seqs = Vec::new();
    while let Some(entry) = ring.pop() {
        seqs.push(u64::from(entry.seq));
        pool.release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
    }
    seqs
}

/// Fill `writer`'s duplicate record: sample-less changes (they do not seed
/// a VOLATILE gate) far enough apart that each leaves a run of sequences
/// never received behind the record's window, until it holds all the runs
/// it can. Returns the next sequence, which the record cannot take.
fn fill_the_duplicate_record(
    sub: &super::subscriber::ReaderSubscriber<Point>,
    writer: [u8; 16],
) -> u64 {
    const STEP: u64 = 2 * 4096;
    let mut seq = 1;
    for _ in 0..=4096 {
        sub.on_writer_non_data(writer, seq);
        seq += STEP;
    }
    seq
}

/// The duplicate record full (`Seen::Full`): a DATA refused unacknowledged
/// before the gate. The reader joins at it: once the writer's HEARTBEAT has
/// settled the record, the DATA after it waits for its repair.
#[test]
fn a_volatile_reader_joins_at_a_sample_its_full_duplicate_record_refuses() {
    let credit = credit_for(&[WRITER]);
    let (ring, sub) = volatile_subscriber("t", &credit, 7, false);
    let x = fill_the_duplicate_record(&sub, WRITER);
    plain(&sub, WRITER, x);
    assert!(ring.is_empty(), "refused");
    let last = i64::try_from(x + 1).expect("small");
    let first = i64::try_from(x).expect("small");
    assert_eq!(
        answer(&credit, &WRITER, first, last, 1),
        (x, vec![x, x + 1]),
        "x is requested again, not acknowledged"
    );
    sub.on_writer_heartbeat(WRITER, x);
    plain(&sub, WRITER, x + 1);
    assert!(ring.is_empty(), "x + 1 waits for x");
    plain(&sub, WRITER, x);
    assert_eq!(drain(&ring, &sub), vec![x, x + 1], "the repair, in order");
    assert_eq!(answer(&credit, &WRITER, first, last, 2), (x + 2, vec![]));
}

/// Coherent staging refusing a sample (it would take the place another
/// writer's gap is owed): the reader joins at it, from the start of its set
/// (`observe`, as for a sample it stages). Its repair, staged once there is
/// room, is delivered with its set; joined at the plain DATA that followed
/// it instead, the reader dropped the repaired set as older history.
#[test]
fn a_volatile_reader_joins_at_a_sample_coherent_staging_refuses() {
    let credit = credit_for(&[WRITER, OTHER]);
    let (ring, sub) = volatile_subscriber("t", &credit, 3, true);
    // OTHER: 1 delivered, 3 held above 2, which is owed a place.
    plain(&sub, OTHER, 1);
    plain(&sub, OTHER, 3);
    // WRITER's set {1}: staged, it would take the place owed.
    coherent(&sub, WRITER, 1, 1);
    let (_, missing) = answer(&credit, &WRITER, 1, 1, 1);
    assert_eq!(missing, vec![1], "refused, unacknowledged");
    // OTHER's gap fills; the application takes.
    plain(&sub, OTHER, 2);
    assert_eq!(drain(&ring, &sub), vec![1, 2, 3], "OTHER's");
    // WRITER's plain 2 closes its set {1}; then the repair of 1.
    plain(&sub, WRITER, 2);
    coherent(&sub, WRITER, 1, 1);
    let mut seqs = drain(&ring, &sub);
    seqs.sort_unstable();
    assert_eq!(seqs, vec![1, 2], "the repaired set is delivered");
}

/// The staged duplicate record full: the coherent sample is refused
/// unrecorded, and the reader joins at its set as at a staged one.
#[test]
fn a_volatile_reader_joins_at_a_coherent_sample_its_full_record_refuses() {
    let credit = credit_for(&[WRITER]);
    let (ring, sub) = volatile_subscriber("t", &credit, 7, true);
    let x = fill_the_duplicate_record(&sub, WRITER);
    coherent(&sub, WRITER, x, x);
    assert!(ring.is_empty(), "refused");
    let first = i64::try_from(x).expect("small");
    let last = i64::try_from(x + 1).expect("small");
    let (_, missing) = answer(&credit, &WRITER, first, last, 1);
    assert!(missing.contains(&x), "x unacknowledged: {missing:?}");
    sub.on_writer_heartbeat(WRITER, x);
    // The plain DATA after the set closes it; then the repair.
    plain(&sub, WRITER, x + 1);
    coherent(&sub, WRITER, x, x);
    let mut seqs = drain(&ring, &sub);
    seqs.sort_unstable();
    assert_eq!(seqs, vec![x, x + 1], "the repaired set is delivered");
}

/// An OWNERSHIP-deferred sample evicted from the bounded deferral buffer
/// was never credited: the writer sends it again. The reader joins at the
/// first evicted, and the samples flushed once the writer resolves wait for
/// the repair.
#[test]
fn a_volatile_reader_joins_at_a_sample_evicted_while_its_writer_was_unresolved() {
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::zero(),
        100_000,
    ));
    let _ = rt::init_slab_pool();
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let sub = super::tests_ownership::make_ownership_sub_with_gate(
        "Square",
        Arc::clone(&ring),
        &fsm,
        super::reorder::ReorderGate::new(true, true),
    );
    let w = super::tests_ownership::ownership_writer_guid(0xBC);
    let send = |seqs: std::ops::RangeInclusive<u64>| {
        for seq in seqs {
            sub.on_data_with_writer("Square", w, seq, &data(seq), crate::dds::CdrVersion::Xcdr2);
        }
    };
    // 70 deferred, the per-writer cap is 64: 1..=6 evicted.
    send(1..=70);
    assert!(ring.is_empty());
    super::tests_ownership::announce_writer(&fsm, "Square", w, None, false);
    sub.on_writer_qos_resolved(w);
    assert!(ring.is_empty(), "7..=70 wait for 1..=6");
    send(1..=6);
    let pool = rt::get_slab_pool();
    let mut seqs = Vec::new();
    while let Some(entry) = ring.pop() {
        seqs.push(entry.seq);
        pool.release(entry.handle);
    }
    assert_eq!(seqs, (1..=70).collect::<Vec<_>>(), "all, in order");
}

/// A discovery FSM and its match registry, for a reader that judges its
/// writers by what discovery holds.
fn discovery() -> (
    Arc<crate::core::discovery::multicast::DiscoveryFsm>,
    Arc<crate::dds::match_notification::MatchNotificationRegistry>,
) {
    let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
        crate::core::discovery::GUID::from_bytes([0x31; 16]),
        30_000,
    ));
    let registry =
        Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x31; 12]));
    (fsm, registry)
}

/// Discovery is asymmetric: a writer that has discovered this reader sends
/// it DATA before this reader has discovered the writer. A coherent change
/// from a writer discovery does not hold is dropped unacknowledged, and the
/// writer sends it again. The reader joins at it: the DATA that follows
/// discovery waits for the repaired set, and nothing is acknowledged
/// undelivered.
#[test]
fn a_volatile_coherent_reader_joins_at_a_member_dropped_before_its_writer_was_discovered() {
    let (fsm, registry) = discovery();
    let credit = credit_for(&[WRITER]);
    let (ring, sub) = volatile_subscriber_matching("t", &credit, 7, true, Some(registry));
    coherent(&sub, WRITER, 1, 1);
    coherent(&sub, WRITER, 2, 1);
    assert!(ring.is_empty(), "dropped: writer not discovered");
    super::tests_ownership::announce_writer(&fsm, "t", WRITER, None, false);
    sub.on_writer_qos_resolved(WRITER);
    assert_eq!(answer(&credit, &WRITER, 1, 2, 1), (1, vec![1, 2]));
    // The plain DATA after the set closes it; then the repair.
    plain(&sub, WRITER, 3);
    coherent(&sub, WRITER, 1, 1);
    coherent(&sub, WRITER, 2, 1);
    let mut seqs = drain(&ring, &sub);
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        vec![1, 2, 3],
        "the set dropped before discovery was dropped again as history"
    );
    assert_eq!(answer(&credit, &WRITER, 1, 3, 2), (4, vec![]));
}

/// The same on the plain path of a reader outside the default partition:
/// the DATA of a writer discovery does not hold yet is dropped there
/// unacknowledged (its partition is unknown), and the reader joins at it.
#[test]
fn a_volatile_partitioned_reader_joins_at_a_sample_dropped_before_its_writer_was_discovered() {
    let (fsm, registry) = discovery();
    let credit = credit_for(&[WRITER]);
    let partition = crate::qos::partition::Partition::single("a");
    let (ring, sub) =
        volatile_subscriber_in("t", &credit, 7, false, Some(registry), partition.clone());
    for seq in 1..=3 {
        plain(&sub, WRITER, seq);
    }
    assert!(ring.is_empty(), "dropped: writer not discovered");
    super::tests_ownership::announce_writer(
        &fsm,
        "t",
        WRITER,
        Some(crate::dds::QoS::reliable().partition(partition)),
        false,
    );
    sub.on_writer_qos_resolved(WRITER);
    assert_eq!(answer(&credit, &WRITER, 1, 3, 1), (1, vec![1, 2, 3]));
    for seq in 4..=5 {
        plain(&sub, WRITER, seq);
    }
    assert!(ring.is_empty(), "4 and 5 wait for 1..=3");
    for seq in 1..=3 {
        plain(&sub, WRITER, seq);
    }
    assert_eq!(
        drain(&ring, &sub),
        vec![1, 2, 3, 4, 5],
        "the samples dropped before discovery were dropped again as history"
    );
    assert_eq!(answer(&credit, &WRITER, 1, 5, 2), (6, vec![]));
}

/// DATA from writer GUIDs discovery never announced, on the coherent path
/// and on the plain path of a partitioned reader, is dropped and filed as
/// owed; such a GUID never departs, so the reader keeps a state for a
/// bounded number of them only, however many are forged. A writer
/// discovery holds keeps its join point through the flood, filed before
/// its discovery.
#[test]
fn undiscovered_writers_dropped_before_discovery_allocate_bounded_reader_state() {
    const KEPT: usize = super::reorder::UNDISCOVERED_REFUSALS_KEPT;
    let (fsm, registry) = discovery();
    let credit = credit_for(&[WRITER]);
    let partition = crate::qos::partition::Partition::single("a");
    let (ring, sub) =
        volatile_subscriber_in("t", &credit, 7, true, Some(registry), partition.clone());
    let tracked = |sub: &super::subscriber::ReaderSubscriber<Point>| {
        let gate = sub.reorder.lock().unwrap_or_else(|e| e.into_inner());
        (gate.writer_count(), gate.undiscovered_refusal_count())
    };
    coherent(&sub, WRITER, 1, 1);
    coherent(&sub, WRITER, 2, 1);
    assert_eq!(tracked(&sub), (1, 1));
    super::tests_ownership::announce_writer(
        &fsm,
        "t",
        WRITER,
        Some(crate::dds::QoS::reliable().partition(partition)),
        false,
    );
    sub.on_writer_qos_resolved(WRITER);
    assert_eq!(tracked(&sub), (1, 0), "discovered: no longer counted");
    for n in 0..1000u32 {
        let mut forged = WRITER;
        forged[12..15].copy_from_slice(&(n + 0x100).to_be_bytes()[1..]);
        if n % 2 == 0 {
            coherent(&sub, forged, 1, 1);
        } else {
            plain(&sub, forged, 1);
        }
    }
    let (writers, counted) = tracked(&sub);
    assert!(
        counted <= KEPT && writers <= KEPT + 1,
        "undiscovered writers allocated reader state: {writers} writers, {counted} counted"
    );
    assert!(ring.is_empty());
    // The discovered writer's join point survived: 3 waits for its set.
    plain(&sub, WRITER, 3);
    assert!(ring.is_empty(), "3 waits for the set {{1, 2}}");
    coherent(&sub, WRITER, 1, 1);
    coherent(&sub, WRITER, 2, 1);
    let mut seqs = drain(&ring, &sub);
    seqs.sort_unstable();
    assert_eq!(seqs, vec![1, 2, 3], "the join point survived");
}

/// A writer forgotten (it departed) and filed again while discovery does not
/// hold it is counted once among the states forgotten first.
#[test]
fn a_writer_filed_again_after_it_departed_is_counted_once() {
    let mut gate = super::reorder::ReorderGate::new(true, true);
    gate.on_dropped_undiscovered(OTHER, 1, None);
    assert_eq!(gate.undiscovered_refusal_count(), 1);
    gate.forget_writer(&OTHER);
    gate.on_dropped_undiscovered(OTHER, 1, None);
    assert_eq!(gate.undiscovered_refusal_count(), 1, "counted twice");
}

#[cfg(feature = "security")]
mod secured {
    use super::*;

    /// Nothing authenticates a DATA the router dropped before its writer was
    /// bound: a secured reader files none of it (its own refusals of DATA it
    /// cannot authenticate yet owe what is owed).
    #[test]
    fn a_secured_reader_takes_no_drop_the_router_reports() {
        let credit = credit_for(&[WRITER]);
        let (_ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        sub.security = Some(suite());
        let (_open_ring, open) = volatile_subscriber("t", &credit, 7, false);
        let dropped_at = crate::engine::subscriber::join_clock_tick();
        sub.on_dropped_before_discovery(WRITER, 1, dropped_at);
        open.on_dropped_before_discovery(WRITER, 1, dropped_at);
        let filed = |sub: &super::super::subscriber::ReaderSubscriber<Point>| {
            sub.reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .unconfirmed_for_test(&WRITER)
        };
        assert_eq!(filed(&open), Some(1), "the control");
        assert_eq!(filed(&sub), None, "a secured reader filed a router drop");
    }

    const KEY_ID: u64 = 9;

    fn key() -> crate::security::crypto::peer_keys::SecretKey {
        crate::security::crypto::peer_keys::SecretKey::from_bytes([0x5C; 32])
    }

    fn suite() -> Arc<crate::security::SecurityPluginSuite> {
        use crate::security::test_pki::{
            TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
        };
        use std::io::Write as _;
        let write_pem = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp PEM file");
            f.write_all(contents).expect("write PEM");
            f.flush().expect("flush PEM");
            f
        };
        let cert = write_pem(TEST_IDENTITY_CERT_PEM);
        let private = write_pem(TEST_IDENTITY_KEY_PEM);
        let ca = write_pem(TEST_CA_CERT_PEM);
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(private.path())
            .ca_certificates(ca.path())
            .enable_encryption(true)
            .build()
            .expect("config");
        Arc::new(crate::security::SecurityPluginSuite::new(config, 0).expect("suite"))
    }

    /// [`suite`] plus a permissions overlay: the one document whose
    /// generation moves under a running participant. Encryption stays off so
    /// the data plane consults the TOPIC's own protection as well as the
    /// writer's announcement -- both cached, both re-read after a reload.
    fn overlay_suite(overlay: &std::path::Path) -> Arc<crate::security::SecurityPluginSuite> {
        use crate::security::test_pki::{
            TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
        };
        use std::io::Write as _;
        let write_pem = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp PEM file");
            f.write_all(contents).expect("write PEM");
            f.flush().expect("flush PEM");
            f
        };
        let cert = write_pem(TEST_IDENTITY_CERT_PEM);
        let private = write_pem(TEST_IDENTITY_KEY_PEM);
        let ca = write_pem(TEST_CA_CERT_PEM);
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(private.path())
            .ca_certificates(ca.path())
            .permissions_overlay(overlay)
            .build()
            .expect("config");
        Arc::new(crate::security::SecurityPluginSuite::new(config, 0).expect("suite"))
    }

    /// The data plane reads the topic's protection and each writer's
    /// announcement ONCE per document generation, and a reload drops both: a
    /// sample after it must not be judged by an answer resolved under the
    /// document it replaced.
    #[test]
    fn the_protection_answers_are_read_once_and_again_after_a_document_reload() {
        use super::super::subscriber::SecuredIngest;
        use std::io::Write as _;

        let mut overlay = tempfile::NamedTempFile::new().expect("overlay file");
        overlay
            .write_all(b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\n")
            .expect("write overlay");
        overlay.flush().expect("flush overlay");
        let suite = overlay_suite(overlay.path());

        let credit = credit_for(&[WRITER]);
        let (_ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        sub.security = Some(Arc::clone(&suite));

        for seq in [1, 2] {
            assert_eq!(
                sub.decrypt_if_secured_for_test(&WRITER, seq, &data(seq)),
                SecuredIngest::Plain,
                "nothing announces protection here"
            );
        }
        assert_eq!(
            sub.protection_resolutions(),
            2,
            "one answer for the writer's announcement and one for the topic, served twice"
        );

        let before = suite.local_restriction_generation();
        // A reload that finds the same document changes nothing, so a reload
        // that MOVES the generation is one that found a new one.
        std::fs::write(
            overlay.path(),
            b"[subject: CN=DDS Test Identity, O=HDDS Test]\ndefault: allow\n\
              deny publish: nothing/*\n",
        )
        .expect("rewrite the overlay");
        suite
            .reload_permissions_overlay()
            .expect("the overlay reloads")
            .expect("an overlay is configured");
        assert_ne!(
            suite.local_restriction_generation(),
            before,
            "a reload moves the generation the cache is filed under"
        );
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 3, &data(3)),
            SecuredIngest::Plain
        );
        assert_eq!(
            sub.protection_resolutions(),
            4,
            "the sample after a reload must read the documents again"
        );
    }

    fn sealed(seq: u64) -> Vec<u8> {
        crate::security::crypto::user_data::encode_serialized_payload(
            KEY_ID,
            &crate::security::crypto::data_keys::WriterKey::for_tests(key()),
            &[&[0, 7, 0, 0][..], &data(seq)].concat(),
        )
        .expect("seal")
    }

    fn install_key(suite: &crate::security::SecurityPluginSuite) {
        suite
            .data_keys
            .insert(
                crate::core::discovery::GUID::from_bytes(WRITER),
                KEY_ID,
                crate::security::crypto::data_keys::WriterKey::for_tests(key()),
            )
            .expect("key");
    }

    /// Samples that arrive before their data key are dropped
    /// unacknowledged, for the writer to send again. The reader joins at the
    /// first: those decrypted once the key is in wait for its repair.
    #[test]
    fn a_volatile_secure_reader_joins_at_a_sample_that_came_before_its_key() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        let suite = suite();
        sub.security = Some(Arc::clone(&suite));
        let send = |sub: &super::super::subscriber::ReaderSubscriber<Point>,
                    seqs: std::ops::RangeInclusive<u64>| {
            for seq in seqs {
                sub.on_data_with_writer(
                    "t",
                    WRITER,
                    seq,
                    &sealed(seq),
                    crate::dds::CdrVersion::Xcdr2,
                );
            }
        };
        send(&sub, 1..=3);
        assert_eq!(answer(&credit, &WRITER, 1, 3, 1), (1, vec![1, 2, 3]));
        install_key(&suite);
        send(&sub, 4..=5);
        assert!(ring.is_empty(), "4 and 5 wait for 1..=3");
        send(&sub, 1..=3);
        assert_eq!(drain(&ring, &sub), vec![1, 2, 3, 4, 5]);
        assert_eq!(answer(&credit, &WRITER, 1, 5, 2), (6, vec![]));
    }

    /// The same on the coherent path: a set member that came before its
    /// key fixes the join point at its set, as a staged sample does.
    #[test]
    fn a_volatile_secure_coherent_reader_joins_at_a_member_that_came_before_its_key() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, true);
        let suite = suite();
        sub.security = Some(Arc::clone(&suite));
        let member = |sub: &super::super::subscriber::ReaderSubscriber<Point>, seq: u64| {
            sub.on_data_coherent(
                "t",
                WRITER,
                seq,
                &sealed(seq),
                crate::dds::CdrVersion::Xcdr2,
                Some(1),
                None,
                None,
            );
        };
        member(&sub, 1);
        assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (1, vec![1]));
        install_key(&suite);
        sub.on_data_with_writer("t", WRITER, 2, &sealed(2), crate::dds::CdrVersion::Xcdr2);
        member(&sub, 1);
        let mut seqs = drain(&ring, &sub);
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2], "the repaired set is delivered");
    }
    /// A DATA under the writer's GUID naming a key id nothing is held for
    /// cannot be authenticated: whoever sent it, it says nothing about where
    /// the writer's stream is. One forged far ahead of the writer, before
    /// the writer's first sample, does not make a VOLATILE reader drop the
    /// writer's real samples as history from before its join.
    #[test]
    fn a_forged_sample_naming_an_unknown_key_moves_no_join_floor() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        let suite = suite();
        install_key(&suite);
        sub.security = Some(Arc::clone(&suite));
        let forged = crate::security::crypto::user_data::encode_serialized_payload(
            KEY_ID + 1,
            &crate::security::crypto::data_keys::WriterKey::for_tests(
                crate::security::crypto::peer_keys::SecretKey::from_bytes([0xA5; 32]),
            ),
            &[&[0, 7, 0, 0][..], &data(1 << 62)].concat(),
        )
        .expect("seal");
        sub.on_data_with_writer("t", WRITER, 1 << 62, &forged, crate::dds::CdrVersion::Xcdr2);
        for seq in 1..=3 {
            sub.on_data_with_writer(
                "t",
                WRITER,
                seq,
                &sealed(seq),
                crate::dds::CdrVersion::Xcdr2,
            );
        }
        assert_eq!(
            drain(&ring, &sub),
            vec![1, 2, 3],
            "the writer's samples were dropped below a forged join floor"
        );
    }

    /// The same forgery on the coherent path: a member naming an unknown
    /// key moves no join floor either.
    #[test]
    fn a_forged_coherent_member_naming_an_unknown_key_moves_no_join_floor() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, true);
        let suite = suite();
        install_key(&suite);
        sub.security = Some(Arc::clone(&suite));
        let forged = crate::security::crypto::user_data::encode_serialized_payload(
            KEY_ID + 1,
            &crate::security::crypto::data_keys::WriterKey::for_tests(
                crate::security::crypto::peer_keys::SecretKey::from_bytes([0xA5; 32]),
            ),
            &[&[0, 7, 0, 0][..], &data(1 << 62)].concat(),
        )
        .expect("seal");
        sub.on_data_coherent(
            "t",
            WRITER,
            1 << 62,
            &forged,
            crate::dds::CdrVersion::Xcdr2,
            Some(1 << 62),
            None,
            None,
        );
        for seq in 1..=3 {
            sub.on_data_with_writer(
                "t",
                WRITER,
                seq,
                &sealed(seq),
                crate::dds::CdrVersion::Xcdr2,
            );
        }
        assert_eq!(
            drain(&ring, &sub),
            vec![1, 2, 3],
            "the writer's samples were dropped below a forged join floor"
        );
    }

    #[test]
    fn protected_xcdr1_uses_the_authenticated_representation_at_ingest() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        let suite = suite();
        install_key(&suite);
        sub.security = Some(suite);
        let plain = [0, 1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
        let protected = crate::security::crypto::user_data::encode_serialized_payload(
            KEY_ID,
            &crate::security::crypto::data_keys::WriterKey::for_tests(key()),
            &plain,
        )
        .unwrap();
        sub.on_data_with_writer("t", WRITER, 1, &protected, crate::dds::CdrVersion::Xcdr2);
        let entry = ring.pop().expect("decrypted sample");
        assert_eq!(entry.cdr_version, crate::dds::CdrVersion::Xcdr1);
        rt::get_slab_pool().release(entry.handle);
        drop(
            sub.room
                .as_ref()
                .map(super::super::admission::HistoryRoom::adopt),
        );
    }

    #[test]
    fn encryption_without_governance_requires_a_writer_on_ingest() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        sub.security = Some(suite());
        sub.on_data_with_version("t", 1, &data(1), crate::dds::CdrVersion::Xcdr2);
        assert!(ring.is_empty());
        assert_eq!(sub.cleartext_refused(), 1);
    }

    #[test]
    fn protected_coherent_samples_to_noncoherent_readers_are_opened_once() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        let suite = suite();
        install_key(&suite);
        sub.security = Some(suite);
        sub.on_data_coherent(
            "t",
            WRITER,
            1,
            &sealed(1),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
        assert_eq!(drain(&ring, &sub), vec![1]);
        assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (2, vec![]));
    }

    #[test]
    fn the_remote_writer_attributes_select_protection_even_without_local_governance() {
        use super::super::subscriber::SecuredIngest;
        use crate::protocol::discovery::EndpointSecurityInfo as Info;
        let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
            crate::core::discovery::GUID::from_bytes([0x31; 16]),
            30_000,
        ));
        let registry = Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x31; 12]),
        );
        let credit = credit_for(&[WRITER]);
        let (_ring, mut sub) = volatile_subscriber_matching("t", &credit, 7, false, Some(registry));
        let suite = suite();
        install_key(&suite);
        sub.security = Some(suite);
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &sealed(1)),
            SecuredIngest::KeyUnknown
        );
        super::super::tests_ownership::announce_writer(&fsm, "t", WRITER, None, false);
        let mut announcement = crate::protocol::discovery::SedpData {
            topic_name: "t".into(),
            type_name: "Point".into(),
            participant_guid: crate::core::discovery::GUID::new(
                WRITER[..12].try_into().unwrap(),
                [0, 0, 1, 0xc1],
            ),
            endpoint_guid: crate::core::discovery::GUID::from_bytes(WRITER),
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: None,
        };
        announcement.endpoint_security_info = Some(Info {
            endpoint_security_attributes: Info::IS_VALID,
            plugin_endpoint_security_attributes: Info::IS_VALID,
        });
        fsm.handle_sedp(announcement.clone());
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &sealed(1)),
            SecuredIngest::Plain
        );
        announcement.endpoint_security_info = Some(Info {
            endpoint_security_attributes: Info::IS_VALID
                | Info::IS_PAYLOAD_PROTECTED
                | Info::IS_KEY_PROTECTED,
            plugin_endpoint_security_attributes: Info::IS_VALID | Info::PLUGIN_IS_PAYLOAD_ENCRYPTED,
        });
        fsm.handle_sedp(announcement);
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &sealed(1)),
            SecuredIngest::Decrypted(data(1), crate::dds::CdrVersion::Xcdr2)
        );
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &data(1)),
            SecuredIngest::Drop
        );
        sub.security = None;
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &sealed(1)),
            SecuredIngest::Drop
        );
    }

    /// A SEDP announcement of `WRITER` on topic "t" carrying payload
    /// protection.
    fn protected_announcement() -> crate::protocol::discovery::SedpData {
        protected_announcement_of(WRITER)
    }

    /// A SEDP announcement of `writer` on topic "t" carrying payload
    /// protection.
    fn protected_announcement_of(writer: [u8; 16]) -> crate::protocol::discovery::SedpData {
        use crate::protocol::discovery::EndpointSecurityInfo as Info;
        crate::protocol::discovery::SedpData {
            topic_name: "t".into(),
            type_name: "Point".into(),
            participant_guid: crate::core::discovery::GUID::new(
                writer[..12].try_into().unwrap(),
                [0, 0, 1, 0xc1],
            ),
            endpoint_guid: crate::core::discovery::GUID::from_bytes(writer),
            qos_hash: 1,
            qos: None,
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![],
            user_data: None,
            shm_capability: None,
            has_explicit_reliability: false,
            has_explicit_ownership: false,
            has_ownership_strength: false,
            type_information: None,
            type_consistency: None,
            group_entity_id: None,
            endpoint_security_info: Some(Info {
                endpoint_security_attributes: Info::IS_VALID
                    | Info::IS_PAYLOAD_PROTECTED
                    | Info::IS_KEY_PROTECTED,
                plugin_endpoint_security_attributes: Info::IS_VALID
                    | Info::PLUGIN_IS_PAYLOAD_ENCRYPTED,
            }),
        }
    }

    /// The samples in `ring` as the reader's take decodes them (the stored
    /// payload past its prefix, under the stored CDR version), every entry
    /// given back.
    fn taken_points(
        ring: &rt::IndexRing,
        sub: &super::super::subscriber::ReaderSubscriber<Point>,
    ) -> Vec<(u64, Point)> {
        use crate::dds::DDS as _;
        let pool = rt::get_slab_pool();
        let mut taken = Vec::new();
        while let Some(entry) = ring.pop() {
            let buf = pool.get_buffer(entry.handle);
            let len = (entry.len as usize).min(buf.len());
            let point = Point::decode(&buf[entry.payload_offset()..len], entry.cdr_version)
                .expect("a Point");
            drop(buf);
            taken.push((u64::from(entry.seq), point));
            pool.release(entry.handle);
            drop(
                sub.room
                    .as_ref()
                    .map(super::super::admission::HistoryRoom::adopt),
            );
        }
        taken
    }

    /// The protection of a received sample is decided ONCE, at the router,
    /// and travels with the sample. Here the writer is not resolved when the
    /// router frames its first DATA (bytes kept whole for crypto), and its
    /// plain announcement lands before the reader reads the sample. Read
    /// again by the reader, the sample was delivered with its CDR
    /// encapsulation header decoded as the first field. Key-unknown instead:
    /// dropped, not acknowledged, and the writer's repair is delivered intact.
    #[test]
    fn a_writer_resolved_after_the_router_framed_its_sample_is_never_read_as_plain() {
        a_writer_resolved_plain_after_the_router_framed_its_sample(false);
    }

    /// The other direction of the same race: the router resolved the writer
    /// as payload-protected and kept the bytes whole, then discovery says
    /// plain before the reader reads. The reader's own reading is Plain, but
    /// bytes the router kept whole are never delivered as a plain sample:
    /// dropped, not acknowledged, and the repair (framed Clear now) is
    /// delivered intact.
    #[test]
    fn a_writer_turning_plain_after_the_router_sealed_its_sample_is_dropped() {
        a_writer_resolved_plain_after_the_router_framed_its_sample(true);
    }

    fn a_writer_resolved_plain_after_the_router_framed_its_sample(router_sees_protected: bool) {
        use crate::dds::DDS as _;
        use crate::protocol::builder;
        let value = encoded_point(9, 7);
        let expected = Point::decode(&value, crate::dds::CdrVersion::Xcdr2).expect("a Point");
        let wire = [&[0, 7, 0, 0][..], &value].concat();
        for fragmented in [false, true] {
            let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
                crate::core::discovery::GUID::from_bytes([0x31; 16]),
                30_000,
            ));
            let matching = Arc::new(
                crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x31; 12]),
            );
            let credit = credit_for(&[WRITER]);
            let (ring, mut sub) =
                volatile_subscriber_matching("t", &credit, 7, false, Some(matching));
            sub.security = Some(suite());
            if router_sees_protected {
                // Known and payload-protected when the router decides.
                super::super::tests_ownership::announce_writer(&fsm, "t", WRITER, None, false);
                fsm.handle_sedp(protected_announcement());
            }
            // Discovery resolves the writer as plain right after the router
            // decided, before the reader reads the sample: the race, forced.
            let announcing = Arc::clone(&fsm);
            *sub.framing_hook.lock().expect("hook") = Some(Box::new(move || {
                super::super::tests_ownership::announce_writer(
                    &announcing,
                    "t",
                    WRITER,
                    None,
                    false,
                );
            }));
            let sub = Arc::new(sub);
            let registry = crate::engine::TopicRegistry::new();
            registry.register_subscriber(sub.clone()).unwrap();
            registry.register_writer_guid(WRITER, "t".into());
            let ctx = builder::RtpsEndpointContext {
                guid_prefix: WRITER[..12].try_into().unwrap(),
                reader_entity_id: [0; 4],
                writer_entity_id: WRITER[12..].try_into().unwrap(),
                encapsulation_kind: 0x0007,
                publisher_entity_id: [0, 0, 1, 8],
            };
            let metrics = crate::engine::router::RouterMetrics::new();
            let buffer =
                std::sync::Mutex::new(crate::core::discovery::FragmentBuffer::new(8, 5000));
            let route = || {
                let packets = if fragmented {
                    let encoder = crate::protocol::dialect::get_encoder(
                        crate::protocol::dialect::Dialect::Hybrid,
                    );
                    wire.chunks(4)
                        .enumerate()
                        .map(|(i, chunk)| {
                            let mut packet = b"RTPS\x02\x05\x01\xaa".to_vec();
                            packet.extend_from_slice(&ctx.guid_prefix);
                            packet.extend_from_slice(
                                &encoder
                                    .build_data_frag(
                                        &ctx.reader_entity_id,
                                        &ctx.writer_entity_id,
                                        1,
                                        i as u32 + 1,
                                        1,
                                        wire.len() as u32,
                                        4,
                                        chunk,
                                    )
                                    .unwrap(),
                            );
                            packet
                        })
                        .collect::<Vec<_>>()
                } else {
                    vec![builder::build_data_packet_with_context_full_keyed_ts(
                        &ctx,
                        "t",
                        1,
                        &wire,
                        crate::dds::CdrVersion::Xcdr2,
                        (1, 2),
                        None,
                        None,
                        None,
                        true,
                    )]
                };
                if fragmented {
                    assert!(packets.len() > 1);
                }
                for packet in &packets {
                    let (_, offset, frag, _) =
                        crate::core::discovery::multicast::classifier::classify_rtps(packet);
                    if fragmented {
                        crate::engine::router::route_data_frag_packet(
                            packet,
                            packet.len(),
                            offset,
                            frag.as_ref(),
                            &buffer,
                            &registry,
                            &metrics,
                        );
                    } else {
                        crate::engine::router::route_data_packet(
                            packet,
                            packet.len(),
                            offset,
                            &registry,
                            &metrics,
                        );
                    }
                }
            };

            route();
            assert!(
                sub.framing_hook.lock().expect("hook").is_none(),
                "the router framed the sample (fragmented={fragmented})"
            );
            assert_eq!(
                taken_points(&ring, &sub),
                vec![],
                "a sample framed for an unresolved writer was delivered \
                 (fragmented={fragmented})"
            );
            assert_eq!(
                answer(&credit, &WRITER, 1, 1, 1),
                (1, vec![1]),
                "the dropped sample was acknowledged (fragmented={fragmented})"
            );

            // The repair, now that the writer is resolved: delivered intact.
            route();
            assert_eq!(
                taken_points(&ring, &sub),
                vec![(1, expected)],
                "fragmented={fragmented}"
            );
            assert_eq!(answer(&credit, &WRITER, 1, 1, 2), (2, vec![]));
        }
    }

    #[test]
    fn protected_routing_refuses_an_outer_cdr_header_before_crypto_elements() {
        use crate::protocol::builder;
        for fragmented in [false, true] {
            let credit = credit_for(&[WRITER]);
            let (ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
            let suite = suite();
            install_key(&suite);
            sub.security = Some(suite);
            let sub = Arc::new(sub);
            let registry = crate::engine::TopicRegistry::new();
            registry.register_subscriber(sub.clone()).unwrap();
            registry.register_writer_guid(WRITER, "t".into());
            let ctx = builder::RtpsEndpointContext {
                guid_prefix: WRITER[..12].try_into().unwrap(),
                reader_entity_id: [0; 4],
                writer_entity_id: WRITER[12..].try_into().unwrap(),
                encapsulation_kind: 0x0007,
                publisher_entity_id: [0, 0, 1, 8],
            };
            let protected = sealed(1);
            let outer_cdr = [&[0, 7, 0, 0][..], &protected].concat();
            let metrics = crate::engine::router::RouterMetrics::new();
            let buffer =
                std::sync::Mutex::new(crate::core::discovery::FragmentBuffer::new(8, 5000));
            for (bytes, valid) in [(&outer_cdr, false), (&protected, true)] {
                let packets = if fragmented {
                    // Force a small fragmented sample: the automatic packet
                    // builder only fragments samples above its MTU threshold.
                    let encoder = crate::protocol::dialect::get_encoder(
                        crate::protocol::dialect::Dialect::Hybrid,
                    );
                    bytes
                        .chunks(16)
                        .enumerate()
                        .map(|(i, chunk)| {
                            let mut packet = b"RTPS\x02\x05\x01\xaa".to_vec();
                            packet.extend_from_slice(&ctx.guid_prefix);
                            packet.extend_from_slice(
                                &encoder
                                    .build_data_frag(
                                        &ctx.reader_entity_id,
                                        &ctx.writer_entity_id,
                                        1,
                                        i as u32 + 1,
                                        1,
                                        bytes.len() as u32,
                                        16,
                                        chunk,
                                    )
                                    .unwrap(),
                            );
                            packet
                        })
                        .collect::<Vec<_>>()
                } else {
                    vec![builder::build_data_packet_with_context_full_keyed_ts(
                        &ctx,
                        "t",
                        1,
                        bytes,
                        crate::dds::CdrVersion::Xcdr2,
                        (1, 2),
                        None,
                        None,
                        None,
                        true,
                    )]
                };
                if fragmented {
                    assert!(packets.len() > 1);
                }
                for packet in &packets {
                    let (_, offset, frag, _) =
                        crate::core::discovery::multicast::classifier::classify_rtps(packet);
                    let status = if fragmented {
                        crate::engine::router::route_data_frag_packet(
                            packet,
                            packet.len(),
                            offset,
                            frag.as_ref(),
                            &buffer,
                            &registry,
                            &metrics,
                        )
                    } else {
                        crate::engine::router::route_data_packet(
                            packet,
                            packet.len(),
                            offset,
                            &registry,
                            &metrics,
                        )
                    };
                    assert_ne!(status, crate::engine::RouteStatus::Dropped);
                }
                if valid {
                    assert_eq!(drain(&ring, &sub), vec![1]);
                    assert_eq!(answer(&credit, &WRITER, 1, 1, 2), (2, vec![]));
                } else {
                    assert!(drain(&ring, &sub).is_empty(), "fragmented={fragmented}");
                    assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (1, vec![1]));
                }
            }
        }
    }

    #[test]
    fn a_lifecycle_key_hash_cannot_credit_an_unauthenticated_payload() {
        use crate::protocol::builder;
        use crate::security::crypto::data_keys::WriterKey;
        let credit = credit_for(&[WRITER]);
        let (_ring, mut sub) = volatile_subscriber("t", &credit, 7, false);
        let suite = suite();
        install_key(&suite);
        sub.security = Some(suite);
        let sub = Arc::new(sub);
        let registry = crate::engine::TopicRegistry::new();
        registry.register_subscriber(sub.clone()).unwrap();
        registry.register_writer_guid(WRITER, "t".into());
        let ctx = builder::RtpsEndpointContext {
            guid_prefix: WRITER[..12].try_into().unwrap(),
            reader_entity_id: [0; 4],
            writer_entity_id: WRITER[12..].try_into().unwrap(),
            encapsulation_kind: 0x0007,
            publisher_entity_id: [0, 0, 1, 8],
        };
        let protected = crate::security::crypto::user_data::encode_serialized_payload(
            KEY_ID,
            &WriterKey::for_tests(key()),
            &[0, 7, 0, 0],
        )
        .unwrap();
        let packet = builder::build_dispose_packet_with_context_coherent_ts(
            &ctx,
            "t",
            1,
            &[0x55; 16],
            &protected,
            builder::StatusInfoKind::Disposed,
            crate::dds::CdrVersion::Xcdr2,
            (1, 2),
            None,
            None,
            None,
            true,
        );
        assert_eq!(builder::extract_writer_guid(&packet), Some(WRITER));
        assert_eq!(
            sub.resolve_lifecycle_key(Some(WRITER), 1, Some(&protected), Some([0x55; 16])),
            Some([0; 16])
        );
        let mut corrupted = packet.clone();
        let n = corrupted.len();
        corrupted[n - 5] ^= 1;
        let metrics = crate::engine::router::RouterMetrics::new();
        for bytes in [&corrupted, &packet] {
            let (_, offset, _, _) =
                crate::core::discovery::multicast::classifier::classify_rtps(bytes);
            let status = crate::engine::router::route_data_packet(
                bytes,
                bytes.len(),
                offset,
                &registry,
                &metrics,
            );
            assert_eq!(
                status,
                crate::engine::RouteStatus::Delivered,
                "routing: {:?}",
                metrics.snapshot()
            );
            if std::ptr::eq(bytes, &corrupted) {
                assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (1, vec![1]));
            }
        }
        assert_eq!(answer(&credit, &WRITER, 1, 1, 2), (2, vec![]));
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LifecycleWire {
        KeyOnly,
        InlineData,
        FragmentedData,
    }

    /// DDS-Security 1.1 Sec.8.5.1.9.4 / 9.5.3.3: a payload that cannot
    /// authenticate is discarded without acknowledging or applying its
    /// lifecycle. A repair with the same writerSN must still be accepted.
    fn check_lifecycle_authentication(wire: LifecycleWire) {
        use crate::engine::router;
        use crate::protocol::builder;
        for coherent in [false, true] {
            for tagged in [false, true] {
                let credit = credit_for(&[WRITER]);
                let (ring, mut sub) = volatile_subscriber("t", &credit, 7, coherent);
                let suite = suite();
                sub.security = Some(Arc::clone(&suite));
                let sub = Arc::new(sub);
                let registry = crate::engine::TopicRegistry::new();
                registry.register_subscriber(sub.clone()).unwrap();
                registry.register_writer_guid(WRITER, "t".into());
                let ctx = builder::RtpsEndpointContext {
                    guid_prefix: WRITER[..12].try_into().unwrap(),
                    reader_entity_id: [0; 4],
                    writer_entity_id: WRITER[12..].try_into().unwrap(),
                    encapsulation_kind: 0x0007,
                    publisher_entity_id: [0, 0, 1, 8],
                };
                let metrics = router::RouterMetrics::new();
                let fragments = Mutex::new(crate::core::discovery::FragmentBuffer::new(8, 5000));
                let route = |payload: &[u8]| {
                    let mut packet = builder::build_dispose_packet_with_context_coherent_ts(
                        &ctx,
                        "t",
                        1,
                        &[0x55; 16],
                        payload,
                        builder::StatusInfoKind::Disposed,
                        crate::dds::CdrVersion::Xcdr2,
                        (1, 2),
                        tagged.then_some(1),
                        None,
                        None,
                        true,
                    );
                    let packets = if wire == LifecycleWire::FragmentedData {
                        let (qos, _) = builder::extract_inline_qos(&packet).unwrap();
                        let encoder = crate::protocol::dialect::get_encoder(
                            crate::protocol::dialect::Dialect::Hybrid,
                        );
                        payload
                            .chunks(16)
                            .enumerate()
                            .map(|(i, chunk)| {
                                let mut frag = encoder
                                    .build_data_frag(
                                        &ctx.reader_entity_id,
                                        &ctx.writer_entity_id,
                                        1,
                                        i as u32 + 1,
                                        1,
                                        payload.len() as u32,
                                        16,
                                        chunk,
                                    )
                                    .unwrap();
                                // RTPS 2.5 Sec.9.4.5.5: inline QoS follows
                                // the DATA_FRAG's 32-octet fixed fields.
                                frag[1] |= 0x02;
                                frag.splice(36..36, qos.iter().copied());
                                let len = u16::try_from(frag.len() - 4).unwrap();
                                frag[2..4].copy_from_slice(&len.to_le_bytes());
                                let mut packet = b"RTPS\x02\x05\x01\xaa".to_vec();
                                packet.extend_from_slice(&ctx.guid_prefix);
                                packet.extend_from_slice(&frag);
                                packet
                            })
                            .collect::<Vec<_>>()
                    } else {
                        if wire == LifecycleWire::InlineData {
                            // The builder prepends a 12-octet INFO_TS to
                            // DATA. D=1 replaces K=1, retaining StatusInfo.
                            assert_eq!(packet[32], 0x15);
                            packet[33] = 0x07;
                        }
                        vec![packet]
                    };
                    for packet in packets {
                        let (_, offset, frag, _) =
                            crate::core::discovery::multicast::classifier::classify_rtps(&packet);
                        let result = if wire == LifecycleWire::FragmentedData {
                            router::route_data_frag_packet(
                                &packet,
                                packet.len(),
                                offset,
                                frag.as_ref(),
                                &fragments,
                                &registry,
                                &metrics,
                            )
                        } else {
                            router::route_data_packet(
                                &packet,
                                packet.len(),
                                offset,
                                &registry,
                                &metrics,
                            )
                        };
                        assert_ne!(result, crate::engine::RouteStatus::Dropped);
                    }
                };
                let valid = sealed(1);
                let mut corrupted = valid.clone();
                let last = corrupted.len() - 1;
                corrupted[last] ^= 1;
                // No key yet, then a failed authentication with a known
                // key: neither is a received, acknowledgeable change.
                route(&valid);
                assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (1, vec![1]));
                install_key(&suite);
                route(&corrupted);
                assert_eq!(answer(&credit, &WRITER, 1, 1, 2), (1, vec![1]));
                assert!(ring.is_empty());
                assert!(sub.dispose_events.drain().is_empty());

                route(&valid);
                if coherent && tagged {
                    assert!(ring.is_empty());
                    assert!(sub.dispose_events.drain().is_empty());
                    sub.on_ecs("t", WRITER, 2, 1, None, None);
                }
                assert!(
                    !credit.awaits(&WRITER, 1),
                    "{wire:?}, coherent={coherent}, tagged={tagged}"
                );
                let events = sub.dispose_events.drain();
                assert_eq!(
                    events.len(),
                    1,
                    "{wire:?}, coherent={coherent}, tagged={tagged}"
                );
                assert_eq!(events[0].key_hash, [0; 16]);
                assert_eq!(
                    drain(&ring, &sub),
                    if wire == LifecycleWire::KeyOnly {
                        vec![]
                    } else {
                        vec![1]
                    }
                );
            }
        }
    }

    #[test]
    fn protected_key_only_lifecycle_requires_authentication_before_credit() {
        check_lifecycle_authentication(LifecycleWire::KeyOnly);
    }

    #[test]
    fn protected_inline_lifecycle_requires_authentication_before_credit() {
        check_lifecycle_authentication(LifecycleWire::InlineData);
    }

    #[test]
    fn protected_fragmented_lifecycle_requires_authentication_before_credit() {
        check_lifecycle_authentication(LifecycleWire::FragmentedData);
    }

    /// DATA under an admitted participant prefix from writer entity ids
    /// discovery never announced cannot be authenticated, and such a writer
    /// never departs: the reader keeps a state for a bounded number of them
    /// only, on the plain and the coherent path, however many are forged. A
    /// writer discovery holds keeps its join point through the flood,
    /// whether it filed it once discovered or before.
    #[test]
    fn forged_undiscovered_writers_allocate_bounded_reader_state() {
        const KEPT: usize = super::super::reorder::UNDISCOVERED_REFUSALS_KEPT;
        let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
            crate::core::discovery::GUID::from_bytes([0x31; 16]),
            30_000,
        ));
        let registry = Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x31; 12]),
        );
        let mut late = WRITER;
        late[15] = 0x03;
        let credit = credit_for(&[WRITER, late]);
        let (ring, mut sub) = volatile_subscriber_matching("t", &credit, 7, true, Some(registry));
        let suite = suite();
        sub.security = Some(Arc::clone(&suite));
        let tracked = |sub: &super::super::subscriber::ReaderSubscriber<Point>| {
            let gate = sub.reorder.lock().unwrap_or_else(|e| e.into_inner());
            (gate.writer_count(), gate.undiscovered_refusal_count())
        };
        // `late` files its join point before it is discovered, WRITER after.
        sub.on_data_with_writer("t", late, 1, &sealed(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(tracked(&sub), (1, 1));
        super::super::tests_ownership::announce_writer(&fsm, "t", WRITER, None, false);
        fsm.handle_sedp(protected_announcement());
        fsm.handle_sedp(protected_announcement_of(late));
        sub.on_writer_qos_resolved(WRITER);
        sub.on_writer_qos_resolved(late);
        sub.on_data_with_writer("t", WRITER, 1, &sealed(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(tracked(&sub), (2, 0), "discovered: no longer counted");
        for n in 0..1000u32 {
            let mut forged = WRITER;
            forged[12..15].copy_from_slice(&(n + 0x100).to_be_bytes()[1..]);
            forged[15] = 0x02;
            let seq = u64::from(n) + 1;
            if n % 2 == 0 {
                sub.on_data_with_writer(
                    "t",
                    forged,
                    seq,
                    &sealed(seq),
                    crate::dds::CdrVersion::Xcdr2,
                );
            } else {
                sub.on_data_coherent(
                    "t",
                    forged,
                    seq,
                    &sealed(seq),
                    crate::dds::CdrVersion::Xcdr2,
                    Some(seq),
                    None,
                    None,
                );
            }
        }
        let (writers, counted) = tracked(&sub);
        assert!(
            counted <= KEPT && writers <= KEPT + 2,
            "forged undiscovered writers allocated reader state: {writers} writers, \
             {counted} counted"
        );
        assert!(ring.is_empty());
        // Both discovered writers' join points survived: 2 waits for 1.
        install_key(&suite);
        suite
            .data_keys
            .insert(
                crate::core::discovery::GUID::from_bytes(late),
                KEY_ID,
                crate::security::crypto::data_keys::WriterKey::for_tests(key()),
            )
            .expect("key");
        for writer in [WRITER, late] {
            sub.on_data_with_writer("t", writer, 2, &sealed(2), crate::dds::CdrVersion::Xcdr2);
            assert!(ring.is_empty(), "2 waits for 1");
            sub.on_data_with_writer("t", writer, 1, &sealed(1), crate::dds::CdrVersion::Xcdr2);
            assert_eq!(drain(&ring, &sub), vec![1, 2], "the join point survived");
        }
    }

    /// A real writer's sealed samples can reach the reader before the
    /// reader has discovered the writer and before its data key arrives:
    /// dropped unacknowledged, sent again. Once the writer is discovered
    /// and its key is in, the samples decrypted first wait for the repair
    /// of those refused before discovery, and none is acknowledged
    /// undelivered.
    #[test]
    fn a_volatile_secure_reader_joins_at_a_sample_refused_before_its_writer_was_discovered() {
        let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
            crate::core::discovery::GUID::from_bytes([0x31; 16]),
            30_000,
        ));
        let registry = Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x31; 12]),
        );
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber_matching("t", &credit, 7, false, Some(registry));
        let suite = suite();
        sub.security = Some(Arc::clone(&suite));
        let send = |sub: &super::super::subscriber::ReaderSubscriber<Point>,
                    seqs: std::ops::RangeInclusive<u64>| {
            for seq in seqs {
                sub.on_data_with_writer(
                    "t",
                    WRITER,
                    seq,
                    &sealed(seq),
                    crate::dds::CdrVersion::Xcdr2,
                );
            }
        };
        send(&sub, 1..=3);
        assert!(ring.is_empty(), "refused: no key, writer not discovered");
        super::super::tests_ownership::announce_writer(&fsm, "t", WRITER, None, false);
        fsm.handle_sedp(protected_announcement());
        sub.on_writer_qos_resolved(WRITER);
        install_key(&suite);
        assert_eq!(answer(&credit, &WRITER, 1, 3, 1), (1, vec![1, 2, 3]));
        send(&sub, 4..=5);
        assert!(ring.is_empty(), "4 and 5 wait for 1..=3");
        send(&sub, 1..=3);
        assert_eq!(
            drain(&ring, &sub),
            vec![1, 2, 3, 4, 5],
            "the samples refused before discovery were dropped as history"
        );
        assert_eq!(answer(&credit, &WRITER, 1, 5, 2), (6, vec![]));
    }

    /// The same on the coherent path: a set member refused before its
    /// writer was discovered fixes the join point at its set.
    #[test]
    fn a_volatile_secure_coherent_reader_joins_at_a_member_refused_before_its_writer_was_discovered(
    ) {
        let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
            crate::core::discovery::GUID::from_bytes([0x31; 16]),
            30_000,
        ));
        let registry = Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x31; 12]),
        );
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber_matching("t", &credit, 7, true, Some(registry));
        let suite = suite();
        sub.security = Some(Arc::clone(&suite));
        let member = |sub: &super::super::subscriber::ReaderSubscriber<Point>, seq: u64| {
            sub.on_data_coherent(
                "t",
                WRITER,
                seq,
                &sealed(seq),
                crate::dds::CdrVersion::Xcdr2,
                Some(1),
                None,
                None,
            );
        };
        member(&sub, 1);
        super::super::tests_ownership::announce_writer(&fsm, "t", WRITER, None, false);
        fsm.handle_sedp(protected_announcement());
        sub.on_writer_qos_resolved(WRITER);
        install_key(&suite);
        assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (1, vec![1]));
        sub.on_data_with_writer("t", WRITER, 2, &sealed(2), crate::dds::CdrVersion::Xcdr2);
        member(&sub, 1);
        let mut seqs = drain(&ring, &sub);
        seqs.sort_unstable();
        assert_eq!(seqs, vec![1, 2], "the repaired set is delivered");
    }
}

/// DDS-Security v1.1 Sec.9.4.1.2.6.7 / Table 30: `data_protection_kind`
/// other than NONE makes the topic's payload protected, transformed by
/// `encode_serialized_payload` (Sec.9.5.3.3.4.4). A reader whose governance
/// protects the payload of its topic does not deliver a payload that was not
/// transformed: the DATA submessage itself is not authenticated
/// (`metadata_protection_kind` NONE), so a cleartext payload under the
/// writer's GUID is a forgery anybody can send.
#[cfg(all(feature = "security", feature = "qos-loaders"))]
mod payload_protection {
    use super::*;

    /// A suite whose governance gives topic `t` `data_protection_kind`
    /// `data` and every other topic NONE.
    fn governed_suite(data: &str) -> Arc<crate::security::SecurityPluginSuite> {
        use crate::security::test_pki::{
            TEST_CA_CERT_PEM, TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM,
        };
        use std::io::Write as _;
        let file = |contents: &[u8]| {
            let mut f = tempfile::NamedTempFile::new().expect("temp");
            f.write_all(contents).expect("write");
            f.flush().expect("flush");
            f
        };
        let topic_rule = |expression: &str, data: &str| {
            format!(
                "<topic_rule><topic_expression>{}</topic_expression>\
                 <enable_discovery_protection>true</enable_discovery_protection>\
                 <enable_liveliness_protection>false</enable_liveliness_protection>\
                 <enable_read_access_control>true</enable_read_access_control>\
                 <enable_write_access_control>true</enable_write_access_control>\
                 <metadata_protection_kind>NONE</metadata_protection_kind>\
                 <data_protection_kind>{}</data_protection_kind></topic_rule>",
                expression, data
            )
        };
        let cert = file(TEST_IDENTITY_CERT_PEM);
        let private = file(TEST_IDENTITY_KEY_PEM);
        let ca = file(TEST_CA_CERT_PEM);
        let governance = file(
            format!(
                "<dds><domain_access_rules><domain_rule><domains><id>0</id></domains>\
                 <allow_unauthenticated_participants>false</allow_unauthenticated_participants>\
                 <enable_join_access_control>true</enable_join_access_control>\
                 <discovery_protection_kind>ENCRYPT</discovery_protection_kind>\
                 <liveliness_protection_kind>NONE</liveliness_protection_kind>\
                 <rtps_protection_kind>NONE</rtps_protection_kind>\
                 <topic_access_rules>{}{}</topic_access_rules></domain_rule>\
                 </domain_access_rules></dds>",
                topic_rule("t", data),
                topic_rule("*", "NONE")
            )
            .as_bytes(),
        );
        let permissions = file(
            b"<dds><permissions><grant name=\"g\"><subject_name>CN=DDS Test Identity, \
              O=HDDS Test</subject_name><validity><not_before>2020-01-01T00:00:00</not_before>\
              <not_after>2036-01-01T00:00:00</not_after></validity><allow_rule><domains>\
              <id>0</id></domains><publish><topics><topic>*</topic></topics></publish>\
              <subscribe><topics><topic>*</topic></topics></subscribe>\
              </allow_rule><default>DENY</default></grant></permissions></dds>",
        );
        let config = crate::security::SecurityConfig::builder()
            .identity_certificate(cert.path())
            .private_key(private.path())
            .ca_certificates(ca.path())
            .governance_xml(governance.path())
            .permissions_xml(permissions.path())
            .insecure_allow_unsigned_documents(true)
            .enable_encryption(true)
            .build()
            .expect("config");
        let suite = crate::security::SecurityPluginSuite::new(config, 0).expect("suite");
        suite
            .data_keys
            .insert(
                crate::core::discovery::GUID::from_bytes(WRITER),
                9,
                crate::security::crypto::data_keys::WriterKey::for_tests(
                    crate::security::crypto::peer_keys::SecretKey::from_bytes([0x5C; 32]),
                ),
            )
            .expect("key");
        Arc::new(suite)
    }

    fn sealed(seq: u64) -> Vec<u8> {
        crate::security::crypto::user_data::encode_serialized_payload(
            9,
            &crate::security::crypto::data_keys::WriterKey::for_tests(
                crate::security::crypto::peer_keys::SecretKey::from_bytes([0x5C; 32]),
            ),
            &[&[0, 7, 0, 0][..], &data(seq)].concat(),
        )
        .expect("seal")
    }

    fn reader_on(
        topic: &str,
        data_protection: &str,
    ) -> (
        Arc<rt::IndexRing>,
        super::super::subscriber::ReaderSubscriber<Point>,
        crate::core::reader::ReaderAckCredit,
    ) {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber(topic, &credit, 7, false);
        sub.security = Some(governed_suite(data_protection));
        (ring, sub, credit)
    }

    #[test]
    fn a_cleartext_sample_on_a_payload_protected_topic_is_not_delivered() {
        let (ring, sub, credit) = reader_on("t", "ENCRYPT");
        // A forger's DATA under the writer's GUID, payload in clear.
        plain(&sub, WRITER, 1);
        assert!(
            drain(&ring, &sub).is_empty(),
            "a cleartext sample was delivered on a payload-protected topic"
        );
        assert_eq!(sub.cleartext_refused(), 1, "the refusal is counted");
        // Not credited: it says nothing about the writer's stream.
        assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (1, vec![1]));
        // The sealed form still opens and is delivered.
        sub.on_data_with_writer("t", WRITER, 1, &sealed(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(
            drain(&ring, &sub),
            vec![1],
            "the sealed sample is delivered"
        );
    }

    /// The coherent path stages the payload, and refuses the same way: the
    /// cleartext member is not staged, so the set it opened, closed by the
    /// writer's next sample, does not deliver it.
    #[test]
    fn a_cleartext_coherent_member_on_a_payload_protected_topic_is_not_staged() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, true);
        sub.security = Some(governed_suite("ENCRYPT"));
        coherent(&sub, WRITER, 1, 1);
        assert_eq!(sub.cleartext_refused(), 1);
        assert_eq!(
            answer(&credit, &WRITER, 1, 1, 1),
            (1, vec![1]),
            "not credited"
        );
        sub.on_data_with_writer("t", WRITER, 2, &sealed(2), crate::dds::CdrVersion::Xcdr2);
        assert!(
            !drain(&ring, &sub).contains(&1),
            "the cleartext member is never delivered"
        );
    }

    /// The writer-less ingest path (`on_data`) takes no cleartext on a
    /// payload-protected topic either.
    #[test]
    fn a_cleartext_sample_on_the_writer_less_path_is_refused() {
        let (ring, sub, _credit) = reader_on("t", "ENCRYPT");
        sub.on_data("t", 1, &data(1));
        assert!(
            drain(&ring, &sub).is_empty(),
            "cleartext delivered on a payload-protected topic via the writer-less path"
        );
    }

    /// The writer-less ingest path (`on_data`) refuses a cleartext sample
    /// on a payload-protected topic, as the per-writer path does.
    #[test]
    fn a_cleartext_sample_on_the_writerless_path_is_not_delivered() {
        let (ring, sub, _credit) = reader_on("t", "ENCRYPT");
        sub.on_data("t", 1, &data(1));
        assert!(
            drain(&ring, &sub).is_empty(),
            "cleartext delivered on a payload-protected topic via the writer-less path"
        );
    }

    /// VERIFY-SECENF: the writer-less ingest path (`on_data`).
    #[test]
    fn verify_cleartext_on_writerless_path_is_not_delivered() {
        let (ring, sub, _credit) = reader_on("t", "ENCRYPT");
        sub.on_data("t", 1, &data(1));
        assert!(
            drain(&ring, &sub).is_empty(),
            "cleartext delivered on a payload-protected topic via the writer-less path"
        );
    }

    /// VERIFY-SECENF2: the writer-less ingest path (`on_data`).
    #[test]
    fn verify2_cleartext_on_writerless_path_is_not_delivered() {
        let (ring, sub, _credit) = reader_on("t", "ENCRYPT");
        sub.on_data("t", 1, &data(1));
        assert!(
            drain(&ring, &sub).is_empty(),
            "cleartext delivered on a payload-protected topic via the writer-less path"
        );
    }

    /// A DATA with neither payload nor key under a matched writer's GUID,
    /// on a topic whose payload is protected: it carries nothing the
    /// writer's key authenticates (DDS-Security v1.1 Sec.8.5.1.9.4,
    /// Sec.9.5.3.3), so it is no change of the writer's - not credited, and
    /// it ends no set (a forger's would deliver the set in part, its later
    /// member then dropped as a duplicate). The same change on a topic left
    /// unprotected, the control, does both.
    #[test]
    fn a_change_without_a_sample_on_a_payload_protected_topic_moves_nothing() {
        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("t", &credit, 7, true);
        sub.security = Some(governed_suite("ENCRYPT"));
        sub.on_writer_heartbeat_range(WRITER, 1, 0);
        sub.on_data_coherent(
            "t",
            WRITER,
            1,
            &sealed(1),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );

        sub.on_change_without_sample(WRITER, 2);

        assert_eq!(
            answer(&credit, &WRITER, 1, 2, 1),
            (2, vec![2]),
            "the unauthenticated change was credited"
        );
        assert!(drain(&ring, &sub).is_empty(), "it ended the staged set");

        let credit = credit_for(&[WRITER]);
        let (ring, mut sub) = volatile_subscriber("other", &credit, 7, true);
        sub.security = Some(governed_suite("ENCRYPT"));
        sub.on_writer_heartbeat_range(WRITER, 1, 0);
        sub.on_data_coherent(
            "other",
            WRITER,
            1,
            &data(1),
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
        sub.on_change_without_sample(WRITER, 2);
        assert_eq!(answer(&credit, &WRITER, 1, 2, 1), (3, vec![]), "control");
        assert_eq!(drain(&ring, &sub), vec![1], "control");
    }

    /// A topic the governance leaves unprotected takes cleartext as before.
    #[test]
    fn an_unprotected_key_only_change_is_credited_with_a_crypto_suite() {
        let (_ring, sub, credit) = reader_on("other", "ENCRYPT");
        sub.on_key_only(WRITER, 1, None);
        assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (2, vec![]));
    }

    #[test]
    fn a_cleartext_sample_on_an_unprotected_topic_is_delivered() {
        let (ring, sub, _credit) = reader_on("other", "ENCRYPT");
        sub.on_data_with_writer("other", WRITER, 1, &data(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(drain(&ring, &sub), vec![1]);
        assert_eq!(sub.cleartext_refused(), 0);
    }

    /// The protected/unprotected decision is the endpoint's RESOLVED
    /// attribute, never a sniff of the leading bytes: a plain payload whose
    /// first bytes happen to equal the CryptoHeader prefix, on a topic governance
    /// EXPLICITLY resolves as unprotected, is classified `Plain`, not
    /// mistaken for ciphertext. Before this was fixed, sniffing first on
    /// such a topic meant such a payload was handed to a key lookup that
    /// could never succeed and dropped forever, or (with no security suite
    /// at all) dropped outright -- real application data lost for a
    /// coincidence of its first four bytes.
    ///
    /// Goes through `decrypt_if_secured_for_test` directly rather than the
    /// full `on_data_with_writer` pipeline: downstream delivery decodes the
    /// payload as `Point`, whose non-`final` wire shape puts a DHEADER in
    /// those same first four bytes, which can never spell a crypto header for any
    /// payload small enough to be real -- a constraint of THAT type's
    /// encoding, not of this gate, which this test must not need to work
    /// around. Mutant: swap the order back (sniff before the attribute
    /// check) and this returns `KeyUnknown` instead of `Plain`.
    #[test]
    fn a_plain_payload_colliding_with_the_crypto_header_is_classified_plain_on_an_unprotected_topic(
    ) {
        let (_ring, sub, _credit) = reader_on("other", "ENCRYPT");
        let mut colliding = vec![0, 0, 0, 4];
        colliding.extend_from_slice(&[0xAA; 8]);
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &colliding),
            super::super::subscriber::SecuredIngest::Plain,
            "a coincidental crypto-header-prefixed plain payload must be classified Plain on a topic \
             governance explicitly resolves as unprotected, not mistaken for ciphertext"
        );
        assert_eq!(
            sub.cleartext_refused(),
            0,
            "an unprotected topic never counts a cleartext refusal"
        );
    }

    /// DDS Security v1.1 Sec.8.8.10.1 (`decode_datawriter_submessage`:
    /// "If an error occurs, this method shall return false") together with
    /// DDSI-RTPS v2.5's reliable protocol (a sequence number the reader
    /// never acknowledges is repaired by the writer, not redelivered as a
    /// decode failure): a sample whose data key has not arrived yet over
    /// the volatile channel must be reported as a DISTINCT outcome from
    /// "never decryptable" (`SecuredIngest::KeyUnknown`, not `Drop`), must
    /// not be delivered while it is missing, must still show as
    /// unacknowledged in the reader's own ack-credit bookkeeping (so a
    /// repair is not refused as a duplicate), and must decrypt to the
    /// exact original plaintext and be delivered once the key catches up.
    ///
    /// Mutant: have `decrypt_if_secured` return `SecuredIngest::Drop`
    /// instead of `KeyUnknown` when the key lookup misses (the one-line
    /// diff this gate would need to turn "owed, repairable" into
    /// "permanently lost" for every secured topic) -- the first assertion
    /// below catches it directly.
    #[test]
    fn a_sample_whose_key_has_not_arrived_is_owed_not_lost() {
        let (ring, sub, credit) = reader_on("t", "ENCRYPT");

        // key_id 99 is NOT the one `governed_suite` pre-installs (9): the
        // volatile channel has not delivered it yet.
        let late_key_id = 99;
        let late_key = crate::security::crypto::peer_keys::SecretKey::from_bytes([0xAB; 32]);
        let late_sealed = crate::security::crypto::user_data::encode_serialized_payload(
            late_key_id,
            &crate::security::crypto::data_keys::WriterKey::for_tests(
                late_key.duplicate_for_store(),
            ),
            &[&[0, 7, 0, 0][..], &data(5)].concat(),
        )
        .expect("seal");

        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 5, &late_sealed),
            super::super::subscriber::SecuredIngest::KeyUnknown,
            "a sample whose key has not arrived must report KeyUnknown, not Decrypted or Drop"
        );
        sub.on_data_with_writer("t", WRITER, 5, &late_sealed, crate::dds::CdrVersion::Xcdr2);
        assert!(
            drain(&ring, &sub).is_empty(),
            "a sample whose key has not arrived must not be delivered"
        );
        assert_eq!(
            answer(&credit, &WRITER, 5, 5, 1),
            (5, vec![5]),
            "a sample refused for want of its key must still show as unacknowledged \
             in the reader's own ack-credit bookkeeping, or a later repair risks \
             being judged a duplicate and refused"
        );

        // The key arrives (the volatile channel's own delivery is out of
        // scope here, proven separately by
        // `participant_crypto_tokens_reach_both_sides_of_an_authenticated_pair`
        // and `a_writers_data_key_reaches_an_authenticated_subscriber`):
        // the exact same bytes now decrypt, and the repaired sample (the
        // same seq, redelivered) is finally delivered.
        sub.security
            .as_ref()
            .expect("security suite")
            .data_keys
            .insert(
                crate::core::discovery::GUID::from_bytes(WRITER),
                late_key_id,
                crate::security::crypto::data_keys::WriterKey::for_tests(late_key),
            )
            .expect("install the late key");
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 5, &late_sealed),
            super::super::subscriber::SecuredIngest::Decrypted(
                data(5),
                crate::dds::CdrVersion::Xcdr2
            ),
            "the exact same ciphertext must decrypt once its key has arrived"
        );
        sub.on_data_with_writer("t", WRITER, 5, &late_sealed, crate::dds::CdrVersion::Xcdr2);
        assert_eq!(
            drain(&ring, &sub),
            vec![5],
            "the repaired sample must be delivered once its key has arrived"
        );
    }

    /// A reader that holds a suite, its pairings judged by a real discovery
    /// registry: `topic` names the topic the writer is announced on.
    fn matched_reader(
        topic: &str,
    ) -> (
        Arc<crate::core::discovery::multicast::DiscoveryFsm>,
        super::super::subscriber::ReaderSubscriber<Point>,
    ) {
        let fsm = Arc::new(crate::core::discovery::multicast::DiscoveryFsm::new(
            crate::core::discovery::GUID::from_bytes([0x31; 16]),
            30_000,
        ));
        let registry = Arc::new(
            crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, [0x31; 12]),
        );
        let credit = credit_for(&[WRITER]);
        let (_ring, mut sub) =
            volatile_subscriber_matching(topic, &credit, 7, false, Some(registry));
        sub.security = Some(governed_suite("ENCRYPT"));
        (fsm, sub)
    }

    /// A writer known to discovery that announced no
    /// `PID_ENDPOINT_SECURITY_INFO` speaks in the clear: on a topic the
    /// governance does not protect its samples are read, not held back for a
    /// key that will never come. Collapsing that settled answer into
    /// "nothing resolved this writer yet" made such a reader answer
    /// `KeyUnknown` to every sample, and a RELIABLE writer repair it for
    /// ever.
    ///
    /// Mutant: return `None` from `writer_payload_security` when discovery
    /// answers `Some(None)` -- this asserts `Plain`, the mutant answers
    /// `KeyUnknown`.
    #[test]
    fn a_writer_known_without_security_attributes_is_read_in_the_clear() {
        use super::super::subscriber::SecuredIngest;
        let (fsm, sub) = matched_reader("free");
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &data(1)),
            SecuredIngest::KeyUnknown,
            "nothing resolved this writer yet: with a suite the sample is owed"
        );
        super::super::tests_ownership::announce_writer(&fsm, "free", WRITER, None, false);
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &data(1)),
            SecuredIngest::Plain,
            "a writer that announced no security attributes is settled, not unresolved"
        );
    }

    /// The same settled answer on a topic the governance protects is a
    /// cleartext payload under the writer's GUID -- a forgery anybody can
    /// send (the DATA submessage itself is not authenticated) -- so it is
    /// dropped, not delivered and not owed.
    ///
    /// Mutant: as above; this asserts `Drop`, the mutant answers
    /// `KeyUnknown`.
    #[test]
    fn a_writer_known_without_security_attributes_is_refused_on_a_protected_topic() {
        use super::super::subscriber::SecuredIngest;
        let (fsm, sub) = matched_reader("t");
        super::super::tests_ownership::announce_writer(&fsm, "t", WRITER, None, false);
        assert_eq!(
            sub.decrypt_if_secured_for_test(&WRITER, 1, &data(1)),
            SecuredIngest::Drop,
            "a plain writer on a payload-protected topic is a forgery, not a wait"
        );
    }
}

/// DDS Security v1.1 Sec.8.8.7.1: the match of a writer of an
/// "Unauthenticated" participant on a read or write protected topic is
/// refused at discovery, but user data is routed to a reader by topic name,
/// matched or not. The reader refuses that writer's data too.
#[cfg(feature = "security")]
mod unauthenticated_writers {
    use super::*;
    use crate::core::discovery::GUID;
    use crate::core::rtps_constants::RTPS_ENTITYID_PARTICIPANT;
    use crate::security::access::{
        BasicProtectionKind, DiscoveryGovernance, DomainRule, ProtectionKind, TopicRule,
    };

    const LOCAL: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x11; 6]);
    const PEER: [u8; 12] = crate::security::test_pki::bound_test_prefix([0x21; 6]);
    const STRANGER: [u8; 12] = [0x33; 12];
    const UNKNOWN: [u8; 12] = [0x44; 12];

    /// The writer of `prefix` on `topic`.
    fn writer_of(prefix: [u8; 12], topic: &str) -> [u8; 16] {
        let key = if topic == "OpenData" { 0x12 } else { 0x13 };
        GUID::new(prefix, [0, 0, key, 0x02]).as_bytes()
    }

    /// Discovery authenticated with PEER, knowing STRANGER (no identity
    /// token, admitted: the governance allows unauthenticated participants),
    /// `Open*` read and write protected, `Free*` not.
    fn discovery() -> Arc<crate::core::discovery::multicast::DiscoveryFsm> {
        use crate::security::test_pki::{TEST_IDENTITY_CERT_PEM, TEST_IDENTITY_KEY_PEM};
        let topic = |expression: &str, access: bool| TopicRule {
            topic_expression: expression.to_string(),
            enable_discovery_protection: false,
            enable_liveliness_protection: false,
            enable_read_access_control: access,
            enable_write_access_control: access,
            metadata_protection_kind: ProtectionKind::None,
            data_protection_kind: BasicProtectionKind::None,
        };
        let machine =
            crate::security::test_pki::local_machine_with_completed_peer(LOCAL, PEER, None);
        let mut fsm = crate::core::discovery::multicast::DiscoveryFsm::new(
            GUID::new(LOCAL, RTPS_ENTITYID_PARTICIPANT),
            30_000,
        );
        fsm.set_handshake_machine(
            machine,
            TEST_IDENTITY_CERT_PEM.to_vec(),
            TEST_IDENTITY_KEY_PEM.to_vec(),
        );
        fsm.set_discovery_governance(Some(DiscoveryGovernance::new(DomainRule {
            domains: vec![0],
            domain_ranges: vec![],
            allow_unauthenticated: true,
            enable_join_access_control: true,
            discovery_protection_kind: ProtectionKind::Encrypt,
            liveliness_protection_kind: ProtectionKind::None,
            rtps_protection_kind: ProtectionKind::None,
            topic_rules: vec![topic("Open*", true), topic("Free*", false)],
        })));
        for (prefix, token) in [
            (PEER, Some(TEST_IDENTITY_CERT_PEM.to_vec())),
            (STRANGER, None),
        ] {
            fsm.handle_spdp(crate::protocol::discovery::SpdpData {
                participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
                lease_duration_ms: 30_000,
                domain_id: 0,
                metatraffic_unicast_locators: vec![],
                default_unicast_locators: vec![],
                default_multicast_locators: vec![],
                metatraffic_multicast_locators: vec![],
                // PEER presents an identity token, so Sec.9.4.2.4 is
                // checked for it (`admit_spdp`): it must announce the
                // same ParticipantSecurityInfo our governance does
                // (discovery Encrypt). STRANGER, with none, is outside
                // that check entirely.
                participant_security_info: token.as_ref().map(|_| {
                    crate::security::access::ParticipantSecurityAttributes::from_kinds(
                        true,
                        true,
                        ProtectionKind::Encrypt,
                        ProtectionKind::None,
                        ProtectionKind::None,
                    )
                    .security_info_le()
                }),
                identity_token: token,
                permissions_token: None,
                vendor_id: None,
                hdds_capabilities: None,
                builtin_endpoint_set: None,
            });
            assert!(fsm.is_participant_known(&prefix), "fixture: known");
            // Its writer of each topic, as its SEDP announces it: the
            // reader's other gates resolve the writer through discovery.
            for topic in ["OpenData", "FreeData"] {
                fsm.handle_sedp_on(
                    crate::protocol::discovery::SedpData {
                        topic_name: topic.to_string(),
                        type_name: "Point".to_string(),
                        participant_guid: GUID::new(prefix, RTPS_ENTITYID_PARTICIPANT),
                        endpoint_guid: GUID::from_bytes(writer_of(prefix, topic)),
                        qos_hash: 0,
                        qos: None,
                        type_object: None,
                        dependents: Vec::new(),
                        type_object_legacy_v1: false,
                        unicast_locators: vec![],
                        user_data: None,
                        shm_capability: None,
                        has_explicit_reliability: false,
                        has_explicit_ownership: false,
                        has_ownership_strength: false,
                        type_information: None,
                        type_consistency: None,
                        group_entity_id: None,
                        endpoint_security_info: None,
                    },
                    crate::core::discovery::multicast::SedpChannel::Plain,
                );
            }
        }
        Arc::new(fsm)
    }

    /// A reader of `topic`, and the discovery it is judged by (the registry
    /// holds it weakly: the caller keeps it alive).
    fn reader_of(
        topic: &str,
    ) -> (
        Arc<rt::IndexRing>,
        super::super::subscriber::ReaderSubscriber<Point>,
        Arc<crate::core::discovery::multicast::DiscoveryFsm>,
    ) {
        let fsm = discovery();
        let registry =
            Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, LOCAL));
        let credit = credit_for(&[
            writer_of(PEER, topic),
            writer_of(STRANGER, topic),
            writer_of(UNKNOWN, topic),
        ]);
        let (ring, sub) = volatile_subscriber_matching(topic, &credit, 7, false, Some(registry));
        (ring, sub, fsm)
    }

    #[test]
    fn a_reader_of_a_protected_topic_refuses_an_unauthenticated_writers_data() {
        let (ring, sub, _discovery) = reader_of("OpenData");
        sub.on_data_with_writer(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            &data(1),
            crate::dds::CdrVersion::Xcdr2,
        );
        assert!(
            drain(&ring, &sub).is_empty(),
            "unauthenticated writer: refused"
        );
        sub.on_data_with_writer(
            "OpenData",
            writer_of(UNKNOWN, "OpenData"),
            1,
            &data(1),
            crate::dds::CdrVersion::Xcdr2,
        );
        assert!(
            drain(&ring, &sub).is_empty(),
            "unknown participant: refused"
        );
        sub.on_data_coherent(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            2,
            &data(2),
            crate::dds::CdrVersion::Xcdr2,
            Some(2),
            None,
            None,
        );
        sub.on_data_with_writer(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            3,
            &data(3),
            crate::dds::CdrVersion::Xcdr2,
        );
        assert!(drain(&ring, &sub).is_empty(), "nor on the coherent path");
        sub.on_data_with_writer(
            "OpenData",
            writer_of(PEER, "OpenData"),
            1,
            &data(1),
            crate::dds::CdrVersion::Xcdr2,
        );
        assert_eq!(
            drain(&ring, &sub),
            vec![1],
            "the authenticated writer is delivered"
        );
    }

    /// Sec.8.8.7.1, 9.4.3: an unauthenticated writer's GAP and HEARTBEAT on
    /// a protected topic move nothing of the reader - neither its
    /// WriterProxy (what it acknowledges and asks again) nor its gate -
    /// while the authenticated writer's, the control, move its own.
    #[test]
    fn an_unauthenticated_writers_gap_and_heartbeat_move_nothing() {
        let fsm = discovery();
        let registry =
            Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, LOCAL));
        let stranger = writer_of(STRANGER, "OpenData");
        let peer = writer_of(PEER, "OpenData");
        let credit = credit_for(&[peer, stranger]);
        let (_ring, sub) =
            volatile_subscriber_matching("OpenData", &credit, 7, false, Some(registry));
        // A durable reader's gate: a HEARTBEAT seeds it.
        *sub.reorder.lock().unwrap_or_else(|e| e.into_inner()) =
            super::super::reorder::ReorderGate::new(true, false);
        let next = |writer: &[u8; 16]| {
            sub.reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .next_seq(writer)
        };
        let (stranger_before, peer_before) = (next(&stranger), next(&peer));
        for writer in [stranger, peer] {
            sub.on_writer_heartbeat_range(writer, 8, 9);
            sub.on_writer_gap(writer, 1, 6, vec![]);
            sub.on_writer_gap_filtered(writer, 10, 11, vec![], 1);
        }
        assert_ne!(
            next(&peer),
            peer_before,
            "control: the admitted writer's moved its gate"
        );
        assert_eq!(
            answer(&credit, &peer, 1, 12, 1).0,
            6,
            "control: the admitted writer's GAPs moved its WriterProxy"
        );
        let filtered = |writer: &[u8; 16]| {
            sub.reorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .filtered_ranges(writer)
        };
        assert!(
            !filtered(&peer).is_empty(),
            "control: its filtered GAP noted"
        );
        assert_eq!(next(&stranger), stranger_before, "the gate moved");
        assert!(filtered(&stranger).is_empty(), "the filtered GAP was noted");
        assert_eq!(
            answer(&credit, &stranger, 1, 12, 1),
            (1, (1..=12).collect()),
            "the WriterProxy took the unauthenticated writer's GAP"
        );
    }

    /// Sec.8.8.7.1, 9.4.3: an unauthenticated writer's change without a
    /// sample on a protected topic is no change of the reader's: not
    /// credited. The authenticated writer's, the control, is.
    #[test]
    fn an_unauthenticated_writers_change_without_a_sample_is_not_credited() {
        let fsm = discovery();
        let registry =
            Arc::new(crate::dds::match_notification::MatchNotificationRegistry::new(&fsm, LOCAL));
        let stranger = writer_of(STRANGER, "OpenData");
        let peer = writer_of(PEER, "OpenData");
        let credit = credit_for(&[peer, stranger]);
        let (_ring, sub) =
            volatile_subscriber_matching("OpenData", &credit, 7, false, Some(registry));

        for writer in [stranger, peer] {
            sub.on_change_without_sample(writer, 1);
        }

        assert_eq!(answer(&credit, &peer, 1, 1, 1), (2, vec![]), "control");
        assert_eq!(
            answer(&credit, &stranger, 1, 1, 1),
            (1, vec![1]),
            "the unauthenticated writer's change was credited"
        );
    }

    #[test]
    fn a_reader_of_an_unprotected_topic_takes_an_unauthenticated_writers_data() {
        let (ring, sub, _discovery) = reader_of("FreeData");
        sub.on_data_with_writer(
            "FreeData",
            writer_of(STRANGER, "FreeData"),
            1,
            &data(1),
            crate::dds::CdrVersion::Xcdr2,
        );
        assert_eq!(drain(&ring, &sub), vec![1]);
    }

    /// Sec.8.8.7.1: a dispose / unregister sent by an unauthenticated
    /// participant's writer on a protected topic must not move an instance
    /// of our reader (the data is refused; the lifecycle change is data too).
    #[test]
    fn verify_unauthenticated_writers_dispose_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        let key = [0x77u8; 16];
        sub.on_dispose_from_writer(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            key,
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "an unauthenticated writer's DISPOSE reached the reader of a protected topic"
        );
    }

    #[test]
    fn verify_unauthenticated_writers_unregister_via_lifecycle_coherent_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_lifecycle_coherent(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            [0x78u8; 16],
            crate::engine::subscriber::DisposeKind::DisposedUnregistered,
            None,
            None,
            None,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "an unauthenticated writer's lifecycle change reached the reader"
        );
    }

    /// The writer-less dispose path (`on_dispose`, router without a GUID).
    #[test]
    fn verify_unknown_writer_dispose_without_guid_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_dispose(
            "OpenData",
            1,
            [0x79u8; 16],
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "a dispose with no writer GUID reached the reader of a protected topic"
        );
    }

    /// The per-writer verdict cache: PEER authenticated (cached `false`),
    /// then PEER's participant leaves and the prefix comes back without an
    /// identity token (admitted: allow_unauthenticated TRUE). Discovery now
    /// says refuse; the reader keeps the stale verdict.
    #[test]
    fn verify_stale_verdict_after_prefix_reannounced_unauthenticated() {
        let (ring, sub, discovery) = reader_of("OpenData");
        let w = writer_of(PEER, "OpenData");
        sub.on_data_with_writer("OpenData", w, 1, &data(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(
            drain(&ring, &sub),
            vec![1],
            "fixture: authenticated delivered"
        );
        discovery.remove_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT));
        discovery.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
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
        });
        assert!(
            discovery.is_participant_known(&PEER),
            "fixture: re-admitted"
        );
        assert_eq!(
            Some(discovery.refuses_unauthenticated(&PEER, "OpenData")),
            Some(true),
            "fixture: discovery now refuses the prefix"
        );
        sub.on_data_with_writer("OpenData", w, 2, &data(2), crate::dds::CdrVersion::Xcdr2);
        assert!(
            drain(&ring, &sub).is_empty(),
            "the reader delivered on a stale per-writer verdict"
        );
    }

    /// Sec.8.8.7.1: a dispose / unregister sent by an unauthenticated
    /// participant's writer on a protected topic must not move an instance
    /// of our reader (the data is refused; the lifecycle change is data too).
    #[test]
    fn an_unauthenticated_writers_dispose_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        let key = [0x77u8; 16];
        sub.on_dispose_from_writer(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            key,
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "an unauthenticated writer's DISPOSE reached the reader of a protected topic"
        );
    }

    #[test]
    fn an_unauthenticated_writers_unregister_on_the_lifecycle_path_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_lifecycle_coherent(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            [0x78u8; 16],
            crate::engine::subscriber::DisposeKind::DisposedUnregistered,
            None,
            None,
            None,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "an unauthenticated writer's lifecycle change reached the reader"
        );
    }

    /// The writer-less dispose path (`on_dispose`, router without a GUID):
    /// nothing can be attributed to an admitted writer.
    #[test]
    fn a_dispose_naming_no_writer_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_dispose(
            "OpenData",
            1,
            [0x79u8; 16],
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "a dispose with no writer GUID reached the reader of a protected topic"
        );
    }

    /// The admission verdict is not kept past what it was reached from: PEER
    /// authenticated (admitted), then PEER's participant leaves and the
    /// prefix comes back without an identity token (admitted:
    /// allow_unauthenticated TRUE). Discovery now refuses it, and so does the
    /// reader. The per-writer cache the reader had kept its first verdict.
    #[test]
    fn a_verdict_does_not_outlive_the_participant_it_was_reached_for() {
        let (ring, sub, discovery) = reader_of("OpenData");
        let w = writer_of(PEER, "OpenData");
        sub.on_data_with_writer("OpenData", w, 1, &data(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(
            drain(&ring, &sub),
            vec![1],
            "fixture: authenticated delivered"
        );
        discovery.remove_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT));
        discovery.handle_spdp(crate::protocol::discovery::SpdpData {
            participant_guid: GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT),
            lease_duration_ms: 30_000,
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
        });
        assert!(
            discovery.is_participant_known(&PEER),
            "fixture: re-admitted"
        );
        assert!(
            !discovery.admits_remote_endpoint("OpenData", &GUID::from_bytes(w), true),
            "fixture: discovery now refuses the prefix"
        );
        sub.on_data_with_writer("OpenData", w, 2, &data(2), crate::dds::CdrVersion::Xcdr2);
        assert!(
            drain(&ring, &sub).is_empty(),
            "the reader delivered on a stale per-writer verdict"
        );
    }

    #[test]
    fn verify2_unauthenticated_writers_dispose_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_dispose_from_writer(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            [0x77u8; 16],
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "unauthenticated DISPOSE reached the reader"
        );
    }

    #[test]
    fn verify2_unauthenticated_writers_unregister_via_lifecycle_coherent_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_lifecycle_coherent(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            [0x78u8; 16],
            crate::engine::subscriber::DisposeKind::DisposedUnregistered,
            None,
            None,
            None,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "unauthenticated lifecycle reached the reader"
        );
    }

    #[test]
    fn verify2_unknown_writer_dispose_without_guid_is_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_dispose(
            "OpenData",
            1,
            [0x79u8; 16],
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "GUID-less dispose reached the reader"
        );
    }

    /// PEER authenticated -> leaves -> its prefix returns with an identity
    /// token but its OLD session is dropped and a new one is pending: the
    /// reader must refuse until the new handshake completes.
    #[test]
    fn verify2_returning_prefix_with_pending_handshake_is_refused() {
        let (ring, sub, discovery) = reader_of("OpenData");
        let w = writer_of(PEER, "OpenData");
        sub.on_data_with_writer("OpenData", w, 1, &data(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(drain(&ring, &sub), vec![1], "fixture");
        discovery.remove_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT));
        sub.on_data_with_writer("OpenData", w, 2, &data(2), crate::dds::CdrVersion::Xcdr2);
        let after_leave = drain(&ring, &sub);
        eprintln!(
            "[verify2] delivered after the participant left: {:?}",
            after_leave
        );
        assert!(
            after_leave.is_empty() || after_leave == vec![2],
            "unexpected"
        );
        // Unknown prefix now (no session): Open* is protected, so refused.
        assert!(
            !discovery.admits_remote_endpoint("OpenData", &GUID::from_bytes(w), true),
            "a departed participant's writer still admitted (stale)"
        );
    }

    /// An unauthenticated writer's dispose, its unregister through the coherent
    /// lifecycle path, and a dispose that names no writer reach no reader of
    /// a protected topic.
    #[test]
    fn an_unauthenticated_writers_lifecycle_changes_are_refused() {
        let (_ring, sub, _discovery) = reader_of("OpenData");
        sub.on_dispose_from_writer(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            [0x77u8; 16],
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "unauthenticated DISPOSE reached the reader"
        );
        sub.on_lifecycle_coherent(
            "OpenData",
            writer_of(STRANGER, "OpenData"),
            1,
            [0x78u8; 16],
            crate::engine::subscriber::DisposeKind::DisposedUnregistered,
            None,
            None,
            None,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "unauthenticated lifecycle change reached the reader"
        );
        sub.on_dispose(
            "OpenData",
            1,
            [0x79u8; 16],
            crate::engine::subscriber::DisposeKind::Disposed,
        );
        assert!(
            sub.dispose_events.is_empty(),
            "a dispose naming no writer reached the reader"
        );
    }

    /// An authenticated participant that leaves takes its admission with
    /// it: its writer's prefix, no longer known, is judged as an
    /// unauthenticated participant's, refused on a protected topic.
    #[test]
    fn a_departed_participants_writer_is_no_longer_admitted() {
        let (ring, sub, discovery) = reader_of("OpenData");
        let w = writer_of(PEER, "OpenData");
        sub.on_data_with_writer("OpenData", w, 1, &data(1), crate::dds::CdrVersion::Xcdr2);
        assert_eq!(drain(&ring, &sub), vec![1], "fixture");
        discovery.remove_participant(GUID::new(PEER, RTPS_ENTITYID_PARTICIPANT));
        assert!(
            !discovery.admits_remote_endpoint("OpenData", &GUID::from_bytes(w), true),
            "a departed participant's writer still admitted (stale)"
        );
        sub.on_data_with_writer("OpenData", w, 2, &data(2), crate::dds::CdrVersion::Xcdr2);
        assert!(
            drain(&ring, &sub).is_empty(),
            "a departed participant's sample delivered"
        );
    }
}

/// A coherent reader's gate at its bound (4096 samples held above a gap)
/// refuses the next sample before acknowledging it, as every other
/// reader's does. Its gate used to make "forced progress" instead: the
/// missing sample was declared lost and the held ones delivered past it,
/// and its repair, requested all the same, was then dropped as history
/// and acknowledged: a RELIABLE reader skipped a sample for good (DDS v1.4
/// Sec.2.2.3.14).
#[test]
fn a_coherent_reader_at_its_gate_bound_refuses_before_acknowledging() {
    let credit = credit_for(&[WRITER]);
    let (ring, sub) = volatile_subscriber("t", &credit, 8191, true);
    plain(&sub, WRITER, 1);
    // 2 is lost on the way; 3..=4098 are held above it: the bound.
    for seq in 3..=4098 {
        plain(&sub, WRITER, seq);
    }
    plain(&sub, WRITER, 4099);
    // The repair of 2 releases what the gate held: 4099 is still owed.
    plain(&sub, WRITER, 2);
    assert_eq!(
        answer(&credit, &WRITER, 1, 4099, 1),
        (4099, vec![4099]),
        "past the bound, refused unacknowledged; nothing given up below"
    );
    plain(&sub, WRITER, 4099);
    let delivered = drain(&ring, &sub);
    assert!(
        delivered.iter().copied().eq(1..=4099),
        "every sample, in order: {} delivered, first missing {:?}",
        delivered.len(),
        (1..=4099u64).find(|s| !delivered.contains(s))
    );
}

/// Nor does a coherent set committed above a gate at its bound give the
/// gap up: its samples were acknowledged when staged, and the gate takes
/// them past its bound (the staging is bounded on its own) rather than make
/// forced progress over the gap.
#[test]
fn a_set_committed_above_a_gate_at_its_bound_gives_no_gap_up() {
    let credit = credit_for(&[WRITER]);
    let (ring, sub) = volatile_subscriber("t", &credit, 8191, true);
    plain(&sub, WRITER, 1);
    for seq in 3..=4098 {
        plain(&sub, WRITER, seq);
    }
    // The set 4099..=4100, closed by the start of the next set at 4101.
    coherent(&sub, WRITER, 4099, 4099);
    coherent(&sub, WRITER, 4100, 4099);
    coherent(&sub, WRITER, 4101, 4101);
    plain(&sub, WRITER, 2);
    let delivered = drain(&ring, &sub);
    assert!(
        delivered.iter().copied().eq(1..=4100),
        "every sample, in order: {} delivered, first missing {:?}",
        delivered.len(),
        (1..=4100u64).find(|s| !delivered.contains(s))
    );
}

/// A valid unprotected lifecycle consumes its writer sequence even when
/// this reader has no instance identity to apply (RTPS 2.5 8.3.8.2).
#[test]
fn an_unprotected_unresolved_lifecycle_still_consumes_its_sequence() {
    let credit = credit_for(&[WRITER]);
    let (_ring, sub) = volatile_subscriber("t", &credit, 7, false);
    let registry = crate::engine::TopicRegistry::new();
    registry.register_subscriber(Arc::new(sub)).unwrap();
    let topic = registry.get_topic("t").unwrap();
    let key = crate::engine::subscriber::LifecycleKey {
        serialized_key: Some(&[0, 7, 0, 0]),
        ..Default::default()
    };
    assert_eq!(
        topic.deliver_lifecycle_counted(Some(WRITER), 1, key, crate::engine::DisposeKind::Disposed),
        (0, 1)
    );
    assert_eq!(answer(&credit, &WRITER, 1, 1, 1), (2, vec![]));
}

/// The writer `WRITER`'s DATA `seq` as it leaves the wire, addressed to
/// every reader of topic "t" (readerId ENTITYID_UNKNOWN, as on multicast).
fn multicast_data(seq: u64) -> Vec<u8> {
    wire_data(WRITER, [0; 4], seq)
}

/// `writer`'s DATA `seq` as it leaves the wire, addressed to `reader`.
fn wire_data(writer: [u8; 16], reader: [u8; 4], seq: u64) -> Vec<u8> {
    let mut prefix = [0u8; 12];
    prefix.copy_from_slice(&writer[..12]);
    let mut entity = [0u8; 4];
    entity.copy_from_slice(&writer[12..]);
    let context = crate::protocol::builder::RtpsEndpointContext {
        guid_prefix: prefix,
        reader_entity_id: reader,
        writer_entity_id: entity,
        encapsulation_kind: 0x0007,
        publisher_entity_id: [0, 0, 0x01, 0x08],
    };
    crate::protocol::builder::build_data_packet_with_context(
        &context,
        "t",
        seq,
        &data(seq),
        crate::dds::CdrVersion::Xcdr2,
    )
}

/// A VOLATILE reliable reader of topic "t" behind a router, its writers
/// judged by discovery: the reader's ring, its credit, the router's
/// registry, the reader, and discovery.
fn routed_volatile_reader() -> (
    Arc<rt::IndexRing>,
    crate::core::reader::ReaderAckCredit,
    crate::engine::demux::TopicRegistry,
    Arc<super::subscriber::ReaderSubscriber<Point>>,
    Arc<crate::core::discovery::multicast::DiscoveryFsm>,
) {
    let (fsm, matching) = discovery();
    let credit = credit_for(&[WRITER]);
    let (ring, sub) = volatile_subscriber_matching("t", &credit, 7, false, Some(matching));
    let sub = Arc::new(sub);
    let registry = crate::engine::demux::TopicRegistry::new();
    registry
        .register_subscriber(Arc::clone(&sub) as Arc<dyn crate::engine::Subscriber>)
        .expect("registered");
    (ring, credit, registry, sub, fsm)
}

/// Discovery of `WRITER` on topic "t", as the participant's SEDP handler
/// takes it: the discovery record, the router's writer-to-topic binding,
/// then the readers told the writer is resolvable.
fn discover_writer(
    fsm: &crate::core::discovery::multicast::DiscoveryFsm,
    registry: &crate::engine::demux::TopicRegistry,
) {
    super::tests_ownership::announce_writer(fsm, "t", WRITER, None, false);
    registry.register_writer_guid(WRITER, "t".to_string());
    assert!(registry.notify_writer_qos_resolved(WRITER));
}

/// Control for the test below: the writer discovered first, its multicast
/// DATA all reach the reader and are acknowledged.
#[test]
fn a_routed_volatile_reader_receives_a_discovered_writers_multicast_data() {
    use crate::engine::router::{route_data_packet, RouteStatus, RouterMetrics};
    let (ring, credit, registry, sub, fsm) = routed_volatile_reader();
    let metrics = RouterMetrics::new();
    discover_writer(&fsm, &registry);
    for seq in 1..=4 {
        let packet = multicast_data(seq);
        assert_eq!(
            route_data_packet(&packet, packet.len(), None, &registry, &metrics),
            RouteStatus::Delivered
        );
    }
    assert_eq!(drain(&ring, &sub), vec![1, 2, 3, 4]);
    assert_eq!(answer(&credit, &WRITER, 1, 4, 1), (5, vec![]));
}

/// Discovery is asymmetric: a writer that has discovered this reader sends
/// its multicast DATA (readerId ENTITYID_UNKNOWN) before this participant
/// has discovered the writer, and the router, which cannot tell its topic
/// yet, drops them unacknowledged. The writer sends them again; the first
/// DATA after discovery must not make the reader judge them history.
#[test]
fn a_routed_volatile_reader_receives_multicast_data_dropped_before_its_writer_was_discovered() {
    use crate::engine::router::{route_data_packet, RouteStatus, RouterMetrics};
    let (ring, credit, registry, sub, fsm) = routed_volatile_reader();
    let metrics = RouterMetrics::new();
    let route = |seq: u64| {
        let packet = multicast_data(seq);
        route_data_packet(&packet, packet.len(), None, &registry, &metrics)
    };
    for seq in 1..=3 {
        assert_eq!(route(seq), RouteStatus::Dropped, "writer not discovered");
    }
    assert!(ring.is_empty());
    discover_writer(&fsm, &registry);
    assert_eq!(route(4), RouteStatus::Delivered);
    let (base, missing) = answer(&credit, &WRITER, 1, 4, 1);
    assert_eq!(
        (base, missing.clone()),
        (1, vec![1, 2, 3]),
        "1..=3 acknowledged without being delivered"
    );
    for seq in 1..=3 {
        route(seq);
    }
    let mut seqs = drain(&ring, &sub);
    seqs.sort_unstable();
    assert_eq!(
        seqs,
        vec![1, 2, 3, 4],
        "the samples dropped before discovery were dropped again as history"
    );
    assert_eq!(answer(&credit, &WRITER, 1, 4, 2), (5, vec![]));
}

/// A drop the router records after the binding arrived (the router looked
/// before it) is handed to the readers at once, not left behind; a DATA
/// addressed to a reader that is not here is owed to nobody here; and
/// writer GUIDs nobody announces keep a bounded record only.
#[test]
fn router_records_of_drops_before_discovery_are_handed_over_and_bounded() {
    const KEPT: usize = crate::engine::demux::DROPPED_BEFORE_DISCOVERY_KEPT;
    let (ring, credit, registry, sub, fsm) = routed_volatile_reader();
    discover_writer(&fsm, &registry);
    registry.note_dropped_before_discovery(WRITER, 1);
    assert_eq!(registry.dropped_before_discovery_count(), 0, "handed over");
    let metrics = crate::engine::router::RouterMetrics::new();
    let packet = multicast_data(2);
    crate::engine::router::route_data_packet(&packet, packet.len(), None, &registry, &metrics);
    assert!(ring.is_empty(), "2 waits for 1");
    assert_eq!(answer(&credit, &WRITER, 1, 2, 1), (1, vec![1]));

    let stranger = [0x5C; 16];
    let directed = wire_data(stranger, [0, 0, 9, 7], 1);
    crate::engine::router::route_data_packet(&directed, directed.len(), None, &registry, &metrics);
    assert_eq!(
        registry.dropped_before_discovery_count(),
        0,
        "addressed to a reader that is not here"
    );
    let multicast = wire_data(stranger, [0; 4], 1);
    crate::engine::router::route_data_packet(
        &multicast,
        multicast.len(),
        None,
        &registry,
        &metrics,
    );
    assert_eq!(registry.dropped_before_discovery_count(), 1, "the control");
    registry.register_writer_guid(stranger, "elsewhere".to_string());
    assert_eq!(registry.dropped_before_discovery_count(), 0, "bound");

    for n in 0..1000u32 {
        let mut forged = WRITER;
        forged[12..15].copy_from_slice(&(n + 0x100).to_be_bytes()[1..]);
        registry.note_dropped_before_discovery(forged, 1);
    }
    assert_eq!(registry.dropped_before_discovery_count(), KEPT);
    drop(sub);
}

/// A drop is owed to the readers that existed when it was dropped: a reader
/// created after it joins the writer at the first DATA routed to it, and a
/// resend of the dropped DATA is history to it.
#[test]
fn a_drop_before_discovery_is_owed_only_to_readers_that_existed_then() {
    use crate::engine::router::{route_data_packet, RouteStatus, RouterMetrics};
    let (ring, _credit, registry, sub, fsm) = routed_volatile_reader();
    let metrics = RouterMetrics::new();
    let route = |seq: u64| {
        let packet = multicast_data(seq);
        route_data_packet(&packet, packet.len(), None, &registry, &metrics)
    };
    assert_eq!(route(1), RouteStatus::Dropped, "writer not discovered");
    let (late_fsm, late_matching) = discovery();
    let late_credit = credit_for(&[WRITER]);
    let (late_ring, late) =
        volatile_subscriber_matching("t", &late_credit, 7, false, Some(late_matching));
    let late = Arc::new(late);
    registry
        .register_subscriber(Arc::clone(&late) as Arc<dyn crate::engine::Subscriber>)
        .expect("registered");
    super::tests_ownership::announce_writer(&late_fsm, "t", WRITER, None, false);
    discover_writer(&fsm, &registry);
    assert_eq!(route(2), RouteStatus::Delivered);
    assert!(ring.is_empty(), "2 waits for 1");
    assert_eq!(
        drain(&late_ring, &late),
        vec![2],
        "owed a drop from before it"
    );
    route(1);
    assert_eq!(drain(&ring, &sub), vec![1, 2]);
    assert!(drain(&late_ring, &late).is_empty(), "history delivered");
}

/// A forged DATA (or one the writer purged since) dropped before discovery
/// seeds the reader's join below the writer's history: the writer's
/// HEARTBEAT, whose firstSN is above it, moves the join up to firstSN
/// without reporting the sequences in between lost.
#[test]
fn a_heartbeat_above_a_drop_before_discovery_moves_the_join_without_a_loss() {
    use crate::engine::router::{route_data_packet, RouteStatus, RouterMetrics};
    let (ring, _credit, registry, sub, fsm) = routed_volatile_reader();
    let metrics = RouterMetrics::new();
    let route = |seq: u64| {
        let packet = multicast_data(seq);
        route_data_packet(&packet, packet.len(), None, &registry, &metrics)
    };
    assert_eq!(route(1), RouteStatus::Dropped, "writer not discovered");
    discover_writer(&fsm, &registry);
    assert_eq!(route(11), RouteStatus::Delivered);
    assert!(ring.is_empty(), "11 waits for 1");
    sub.on_writer_heartbeat_range(WRITER, 11, 11);
    assert_eq!(drain(&ring, &sub), vec![11]);
    assert_eq!(
        sub.sample_lost.lock().expect("lost").total_count,
        0,
        "1..=10 were never shown owed"
    );
}

/// A HEARTBEAT taken before the writer's first DATA moves a join a drop
/// before discovery left below firstSN up to it: the DATA at firstSN is
/// delivered at once instead of waiting for history the writer no longer
/// has.
#[test]
fn a_heartbeat_before_any_data_moves_a_drop_before_discovery_up_to_first_sn() {
    use crate::engine::router::{route_data_packet, RouteStatus, RouterMetrics};
    let (ring, _credit, registry, sub, fsm) = routed_volatile_reader();
    let metrics = RouterMetrics::new();
    let route = |seq: u64| {
        let packet = multicast_data(seq);
        route_data_packet(&packet, packet.len(), None, &registry, &metrics)
    };
    assert_eq!(route(1), RouteStatus::Dropped, "writer not discovered");
    discover_writer(&fsm, &registry);
    sub.on_writer_heartbeat_range(WRITER, 11, 11);
    assert_eq!(route(11), RouteStatus::Delivered);
    assert_eq!(drain(&ring, &sub), vec![11], "11 waited for 1");
    assert_eq!(sub.sample_lost.lock().expect("lost").total_count, 0);
}

/// The router's drop can race the writer's binding: one thread finds no
/// binding for DATA 10, discovery binds the writer, another thread routes
/// DATA 11 through the binding and the reader joins there, and only then
/// does the first thread record 10. The reader keeps the writer's changes
/// in order: 11 is delivered, and 10, reported after the join, is not
/// delivered after it (a known limitation, see `file_unconfirmed`).
#[test]
fn a_drop_recorded_after_the_reader_joined_through_the_binding_moves_nothing_back() {
    use crate::engine::router::{route_data_packet, RouteStatus, RouterMetrics};
    let (ring, _credit, registry, sub, fsm) = routed_volatile_reader();
    let metrics = RouterMetrics::new();
    let route = |seq: u64| {
        let packet = multicast_data(seq);
        route_data_packet(&packet, packet.len(), None, &registry, &metrics)
    };
    discover_writer(&fsm, &registry);
    assert_eq!(route(11), RouteStatus::Delivered);
    assert_eq!(drain(&ring, &sub), vec![11]);
    registry.note_dropped_before_discovery(WRITER, 10);
    for seq in [10, 11, 12] {
        route(seq);
    }
    assert_eq!(drain(&ring, &sub), vec![12], "delivered out of order");
}

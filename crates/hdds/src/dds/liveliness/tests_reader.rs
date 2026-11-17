// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A reader's leases of the writers it matches: what renews each kind, on
//! a clock the tests move; then two real participants.

use std::sync::Arc;
use std::time::{Duration, Instant};

use std::sync::Mutex;

use super::clock::ManualClock;
use super::reader::ReaderLiveliness;
use super::scheduler::{Scheduler, Shared};
use crate::core::discovery::GUID;
use crate::dds::listener::LivelinessChangedStatus;
use crate::dds::qos::Liveliness;
use crate::dds::reader::notices::Notice;
use crate::dds::{StatusCondition, StatusMask};

const LEASE: Duration = Duration::from_millis(100);

fn writer(prefix: u8, key: u8) -> GUID {
    GUID::new([prefix; 12], [0, 0, key, 0x02])
}

/// A listener call: the status it was given and the thread it ran on.
type Call = (LivelinessChangedStatus, Option<String>);

struct Rig {
    clock: Arc<ManualClock>,
    _scheduler: Scheduler,
    shared: Arc<Shared>,
    reader: Arc<ReaderLiveliness>,
    condition: Arc<StatusCondition>,
    calls: Arc<Mutex<Vec<Call>>>,
    /// Every (guid, alive) the `on_writer_alive` hook was told, in order.
    alive_transitions: Arc<Mutex<Vec<(GUID, bool)>>>,
}

impl Rig {
    fn new() -> Self {
        Self::with_listener(false)
    }

    /// `listener`: a listener covers LIVELINESS_CHANGED, and records each
    /// call.
    fn with_listener(listener: bool) -> Self {
        let clock = Arc::new(ManualClock::new(0));
        let shared = Shared::new(Arc::clone(&clock) as Arc<dyn super::LivelinessClock>);
        let scheduler = Scheduler::start(Arc::clone(&shared), Box::new(|| {}), Box::new(|| {}))
            .expect("thread");
        let condition = Arc::new(StatusCondition::new());
        let calls: Arc<Mutex<Vec<Call>>> = Arc::default();
        let recorded = Arc::clone(&calls);
        let alive_transitions: Arc<Mutex<Vec<(GUID, bool)>>> = Arc::default();
        let transitions = Arc::clone(&alive_transitions);
        let reader = ReaderLiveliness::new(
            Arc::clone(&shared),
            Arc::clone(&condition),
            Box::new(move |status| {
                if !listener {
                    return None;
                }
                let recorded = Arc::clone(&recorded);
                Some(Box::new(move || {
                    let thread = std::thread::current().name().map(str::to_string);
                    recorded.lock().unwrap().push((status, thread));
                }) as Notice)
            }),
            Box::new(move |guid, alive| {
                transitions.lock().unwrap().push((guid, alive));
            }),
        );
        Self {
            clock,
            _scheduler: scheduler,
            shared,
            reader,
            condition,
            calls,
            alive_transitions,
        }
    }

    /// The listener calls made so far, once `n` are made.
    fn calls(&self, n: usize) -> Vec<Call> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.calls.lock().unwrap().len() < n && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.calls.lock().unwrap().clone()
    }

    fn step(&self, by: Duration) {
        self.clock.advance(by);
        self.shared.settle();
    }
}

#[test]
fn any_traffic_of_its_participant_keeps_an_automatic_writer_alive() {
    let rig = Rig::new();
    let w = writer(1, 1);
    rig.reader.matched(w, Liveliness::automatic(LEASE), false);
    for _ in 0..10 {
        rig.step(Duration::from_millis(60));
        rig.shared.heard_from(&[1; 12]);
        rig.shared.manual_from(&[9; 12]);
    }
    rig.shared.settle();
    assert_eq!(rig.reader.is_alive(&w), Some(true));
    // Another participant's traffic does not.
    for _ in 0..3 {
        rig.step(Duration::from_millis(60));
        rig.shared.heard_from(&[2; 12]);
    }
    assert_eq!(rig.reader.is_alive(&w), Some(false));
    rig.shared.heard_from(&[1; 12]);
    rig.shared.settle();
    assert_eq!(rig.reader.is_alive(&w), Some(true), "alive again");
}

#[test]
fn a_manual_by_participant_writer_is_renewed_by_manual_assertions_and_data() {
    let rig = Rig::new();
    let w = writer(1, 1);
    rig.reader
        .matched(w, Liveliness::manual_by_participant(LEASE), false);
    // Traffic alone does not renew it.
    for _ in 0..3 {
        rig.step(Duration::from_millis(60));
        rig.shared.heard_from(&[1; 12]);
    }
    assert_eq!(rig.reader.is_alive(&w), Some(false));
    rig.shared.manual_from(&[1; 12]);
    rig.shared.settle();
    assert_eq!(rig.reader.is_alive(&w), Some(true), "a manual assertion");
    for _ in 0..5 {
        rig.step(Duration::from_millis(60));
        rig.reader.on_data(&w.as_bytes());
    }
    rig.shared.settle();
    assert_eq!(rig.reader.is_alive(&w), Some(true), "its data");
}

#[test]
fn a_manual_by_topic_writer_is_renewed_by_its_own_data_only() {
    let rig = Rig::new();
    let w = writer(1, 1);
    let sibling = writer(1, 2);
    rig.reader
        .matched(w, Liveliness::manual_by_topic(LEASE), false);
    rig.reader
        .matched(sibling, Liveliness::manual_by_topic(LEASE), false);
    for _ in 0..5 {
        rig.step(Duration::from_millis(60));
        rig.shared.heard_from(&[1; 12]);
        rig.shared.manual_from(&[1; 12]);
        rig.reader.on_data(&sibling.as_bytes());
    }
    assert_eq!(rig.reader.is_alive(&w), Some(false));
    assert_eq!(rig.reader.is_alive(&sibling), Some(true));
    rig.reader.on_data(&w.as_bytes());
    rig.shared.settle();
    assert_eq!(rig.reader.is_alive(&w), Some(true));
}

/// RTPS v2.5 Sec.8.3.7.5: a HEARTBEAT's Liveliness flag renews a
/// MANUAL_BY_TOPIC writer's lease, but NEVER a MANUAL_BY_PARTICIPANT
/// writer's -- that kind renews only on its participant's
/// ParticipantMessage, ordinary traffic and HEARTBEATs included.
/// Mutant: dropping the `t.kind == LivelinessKind::ManualByTopic` filter
/// in `on_heartbeat_liveliness` makes the MANUAL_BY_PARTICIPANT half of
/// this test fail (it would stay alive).
#[test]
fn a_heartbeat_liveliness_flag_renews_manual_by_topic_only() {
    let rig = Rig::new();
    let by_topic = writer(1, 1);
    let by_participant = writer(1, 2);
    rig.reader
        .matched(by_topic, Liveliness::manual_by_topic(LEASE), false);
    rig.reader.matched(
        by_participant,
        Liveliness::manual_by_participant(LEASE),
        false,
    );
    for _ in 0..5 {
        rig.step(Duration::from_millis(60));
        rig.reader.on_heartbeat_liveliness(&by_topic.as_bytes());
        rig.reader
            .on_heartbeat_liveliness(&by_participant.as_bytes());
    }
    rig.shared.settle();
    assert_eq!(
        rig.reader.is_alive(&by_topic),
        Some(true),
        "L flag renews it"
    );
    assert_eq!(
        rig.reader.is_alive(&by_participant),
        Some(false),
        "L flag never renews MANUAL_BY_PARTICIPANT"
    );
}

#[test]
fn a_local_or_infinite_writer_has_no_lease() {
    let rig = Rig::new();
    let local = writer(1, 1);
    let infinite = writer(2, 1);
    rig.reader
        .matched(local, Liveliness::automatic(LEASE), true);
    rig.reader.matched(infinite, Liveliness::infinite(), false);
    assert_eq!(rig.shared.tracked_for_test(), 0, "nothing to renew");
    rig.step(Duration::from_secs(10));
    assert_eq!(rig.reader.is_alive(&local), Some(true));
    assert_eq!(rig.reader.is_alive(&infinite), Some(true));
}

#[test]
fn an_unmatched_writer_releases_its_participant() {
    let rig = Rig::new();
    let (a, b) = (writer(1, 1), writer(1, 2));
    rig.reader.matched(a, Liveliness::automatic(LEASE), false);
    rig.reader.matched(b, Liveliness::automatic(LEASE), false);
    assert_eq!(rig.shared.tracked_for_test(), 1);
    rig.reader.unmatched(a);
    assert_eq!(rig.shared.tracked_for_test(), 1, "b still holds it");
    assert_eq!(rig.reader.is_alive(&a), None);
    rig.reader.close();
    assert_eq!(rig.shared.tracked_for_test(), 0);
    rig.step(Duration::from_secs(1));
    assert_eq!(rig.reader.is_alive(&b), None, "closed: nothing watched");
}

/// `on_writer_alive` (what drives NOT_ALIVE_NO_WRITERS and EXCLUSIVE
/// ownership transfer, DDS v1.4 Sec.2.2.3.23.2, Sec.2.2.3.23.1.2) is told
/// every transition the scheduler decides, in order, and nothing else: a
/// local or infinite writer never has a lease to lose.
#[test]
fn on_writer_alive_is_told_every_lease_transition_in_order() {
    let rig = Rig::new();
    let w = writer(1, 1);
    rig.reader.matched(w, Liveliness::automatic(LEASE), false);
    assert_eq!(
        rig.alive_transitions.lock().unwrap().as_slice(),
        &[],
        "matched alive: nothing lost yet"
    );
    for _ in 0..3 {
        rig.step(Duration::from_millis(60));
        rig.shared.heard_from(&[2; 12]); // a different participant
    }
    assert_eq!(rig.reader.is_alive(&w), Some(false));
    rig.shared.heard_from(&[1; 12]);
    rig.shared.settle();
    assert_eq!(rig.reader.is_alive(&w), Some(true));
    assert_eq!(
        rig.alive_transitions.lock().unwrap().as_slice(),
        &[(w, false), (w, true)],
        "lost, then resumed, in that order"
    );
}

fn counts(s: &LivelinessChangedStatus) -> (u32, u32, i32, i32) {
    (
        s.alive_count,
        s.not_alive_count,
        s.alive_count_change,
        s.not_alive_count_change,
    )
}

/// The status as a getter reads it: counts, changes since the last read,
/// the bit on the condition.
#[test]
fn the_status_counts_alive_and_not_alive_writers() {
    let rig = Rig::new();
    let (a, b) = (writer(1, 1), writer(2, 1));
    rig.reader.matched(a, Liveliness::automatic(LEASE), false);
    rig.reader.matched(b, Liveliness::automatic(LEASE), false);
    assert!(rig
        .condition
        .get_active_statuses()
        .contains(StatusMask::LIVELINESS_CHANGED));
    let s = rig.reader.status();
    assert_eq!(counts(&s), (2, 0, 2, 0));
    assert_eq!(s.last_publication_handle, Some(b));
    assert!(!rig
        .condition
        .get_active_statuses()
        .contains(StatusMask::LIVELINESS_CHANGED));
    assert_eq!(counts(&rig.reader.status()), (2, 0, 0, 0), "read: reset");
    // b's participant goes silent.
    for _ in 0..3 {
        rig.step(Duration::from_millis(60));
        rig.shared.heard_from(&[1; 12]);
    }
    let s = rig.reader.status();
    assert_eq!(counts(&s), (1, 1, -1, 1));
    assert_eq!(s.last_publication_handle, Some(b));
    rig.reader.unmatched(b);
    assert_eq!(
        counts(&rig.reader.status()),
        (1, 0, 0, -1),
        "not alive, gone"
    );
    rig.reader.unmatched(a);
    assert_eq!(counts(&rig.reader.status()), (0, 0, -1, 0), "alive, gone");
}

/// A writer whose lease ended, renewed before the scheduler ran: the
/// listener is told it was not alive, then alive again, in that order,
/// never on the scheduler's thread.
#[test]
fn an_expiry_the_scheduler_did_not_see_reaches_the_listener() {
    let rig = Rig::with_listener(true);
    let w = writer(1, 1);
    rig.reader.matched(w, Liveliness::automatic(LEASE), false);
    assert_eq!(counts(&rig.calls(1)[0].0), (1, 0, 1, 0), "matched");
    rig.shared.settle();
    // Past the lease and renewed, in one step.
    rig.clock.advance(Duration::from_millis(150));
    rig.shared.heard_from(&[1; 12]);
    rig.shared.settle();
    let calls = rig.calls(3);
    assert_eq!(calls.len(), 3, "{calls:?}");
    assert_eq!(counts(&calls[1].0), (0, 1, -1, 1), "not alive, recorded");
    assert_eq!(counts(&calls[2].0), (1, 0, 1, -1), "then alive");
    for (_, thread) in &calls[1..] {
        assert_ne!(thread.as_deref(), Some("hdds-liveliness"));
    }
    assert_eq!(counts(&rig.reader.status()), (1, 0, 0, 0), "told: reset");
    // Renewed in time from then on: nothing more.
    for _ in 0..5 {
        rig.step(Duration::from_millis(60));
        rig.shared.heard_from(&[1; 12]);
    }
    assert_eq!(rig.calls(3).len(), 3);
}

/// With no listener, the same flap raises the condition: a WaitSet sees
/// that the status changed even though the counts came back.
#[test]
fn an_unseen_expiry_raises_the_condition() {
    let rig = Rig::new();
    let w = writer(1, 1);
    rig.reader.matched(w, Liveliness::automatic(LEASE), false);
    let _ = rig.reader.status();
    rig.clock.advance(Duration::from_millis(150));
    rig.shared.heard_from(&[1; 12]);
    rig.shared.settle();
    assert!(rig
        .condition
        .get_active_statuses()
        .contains(StatusMask::LIVELINESS_CHANGED));
}

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Pulse {
    n: u32,
}

/// Two participants: a writer that never writes stays alive on the
/// reader's side through its participant's assertions.
#[test]
fn a_silent_automatic_writer_of_another_participant_stays_alive() {
    use crate::{Participant, QoS, TransportMode};
    let domain = crate::test_support::domains::unique_domain();
    let build = |name: &str| {
        Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant")
    };
    let (a, b) = (
        build("liveliness_writer_side"),
        build("liveliness_reader_side"),
    );
    let qos = QoS::best_effort().liveliness_automatic_millis(400);
    let w = a
        .topic::<Pulse>("LivelinessReaderSide")
        .expect("topic")
        .writer()
        .qos(qos.clone())
        .build()
        .expect("writer");
    let r = b
        .topic::<Pulse>("LivelinessReaderSide")
        .expect("topic")
        .reader()
        .qos(qos)
        .build()
        .expect("reader");
    let guid = w.endpoint_guid_for_test().expect("a wire writer");
    let liveliness = r.liveliness_for_test().expect("reader liveliness");
    let deadline = Instant::now() + Duration::from_secs(10);
    while liveliness.is_alive(&guid).is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(liveliness.is_alive(&guid), Some(true), "matched");
    // Nothing written, for 20 leases: past the first 5 s, when the writer's
    // participant announces itself every 200 ms (`spdp_announcer`), only
    // its assertions are as frequent as the lease.
    for _ in 0..80 {
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(liveliness.is_alive(&guid), Some(true));
    }
}

/// Two participants: a MANUAL_BY_TOPIC writer is alive while it writes,
/// whatever else its participant sends, and not alive a lease after it
/// stops.
#[test]
fn a_manual_by_topic_writer_of_another_participant_lives_by_its_writes() {
    use crate::{Participant, QoS, TransportMode};
    let domain = crate::test_support::domains::unique_domain();
    let build = |name: &str| {
        Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .expect("participant")
    };
    let (a, b) = (
        build("liveliness_topic_writer"),
        build("liveliness_topic_reader"),
    );
    let mut qos = QoS::best_effort();
    qos.liveliness = Liveliness::manual_by_topic(Duration::from_millis(300));
    let w = a
        .topic::<Pulse>("LivelinessByTopic")
        .expect("topic")
        .writer()
        .qos(qos.clone())
        .build()
        .expect("writer");
    let r = b
        .topic::<Pulse>("LivelinessByTopic")
        .expect("topic")
        .reader()
        .qos(qos)
        .build()
        .expect("reader");
    let guid = w.endpoint_guid_for_test().expect("a wire writer");
    let liveliness = r.liveliness_for_test().expect("reader liveliness");
    let deadline = Instant::now() + Duration::from_secs(10);
    while liveliness.is_alive(&guid).is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(liveliness.is_alive(&guid), Some(true), "matched");
    for n in 0..30 {
        w.write(&Pulse { n }).expect("write");
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            liveliness.is_alive(&guid),
            Some(true),
            "written every 50 ms"
        );
    }
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(
        liveliness.is_alive(&guid),
        Some(false),
        "silent past its lease"
    );
    w.write(&Pulse { n: 99 }).expect("write");
    let deadline = Instant::now() + Duration::from_secs(2);
    while liveliness.is_alive(&guid) != Some(true) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(liveliness.is_alive(&guid), Some(true), "a write revives it");
}

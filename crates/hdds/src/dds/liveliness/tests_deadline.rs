// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DEADLINE (DDS v1.4 Sec.2.2.3.7, Sec.2.2.4.1) on the scheduler thread,
//! on a clock the tests move. `Core`-level mutant tests (the shared
//! evaluation function, the per-entry heap arithmetic) live in
//! `leases.rs`'s own test module; this file exercises the participant's
//! scheduler end to end, through `ReaderDeadlines`/`WriterDeadlines`, the
//! way `tests_scheduler.rs` does for LIVELINESS.

use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use super::clock::ManualClock;
use super::deadline::{ReaderDeadlines, WriterDeadlines};
use super::scheduler::{Scheduler, Shared};
use crate::dds::listener::{OfferedDeadlineMissedStatus, RequestedDeadlineMissedStatus};
use crate::dds::reader::InstanceHandle;
use crate::dds::{StatusCondition, StatusMask};

fn started(clock: &Arc<ManualClock>) -> Scheduler {
    let shared = Shared::new(Arc::clone(clock) as Arc<dyn super::LivelinessClock>);
    Scheduler::start(shared, Box::new(|| {}), Box::new(|| {})).expect("thread")
}

fn handle_of(byte: u8) -> InstanceHandle {
    let mut bytes = [0u8; 16];
    bytes[0] = byte;
    InstanceHandle::new(bytes)
}

fn reader_deadlines_no_listener(
    shared: &Arc<Shared>,
    period: Duration,
) -> (Arc<ReaderDeadlines>, Arc<StatusCondition>) {
    let condition = Arc::new(StatusCondition::new());
    let d = ReaderDeadlines::new(
        Arc::clone(shared),
        period,
        Arc::clone(&condition),
        Box::new(|_| None),
    );
    (d, condition)
}

type ReaderTold = (RequestedDeadlineMissedStatus, Option<String>);

fn reader_deadlines_with_listener(
    shared: &Arc<Shared>,
    period: Duration,
) -> (Arc<ReaderDeadlines>, mpsc::Receiver<ReaderTold>) {
    let condition = Arc::new(StatusCondition::new());
    let (tx, rx) = mpsc::channel();
    let d = ReaderDeadlines::new(
        Arc::clone(shared),
        period,
        condition,
        Box::new(move |status| {
            let tx = tx.clone();
            Some(Box::new(move || {
                let name = std::thread::current().name().map(str::to_string);
                let _ = tx.send((status, name));
            }))
        }),
    );
    (d, rx)
}

fn writer_deadlines_no_listener(
    shared: &Arc<Shared>,
    period: Duration,
) -> (Arc<WriterDeadlines>, Arc<StatusCondition>) {
    let condition = Arc::new(StatusCondition::new());
    let d = WriterDeadlines::new(
        Arc::clone(shared),
        period,
        Arc::clone(&condition),
        Box::new(|_| None),
        false,
    );
    (d, condition)
}

/// A reader instance that gets a sample, then nothing: REQUESTED_DEADLINE_MISSED
/// is raised with no `take()`/`read()` call at all -- the missing asynchronous notification (DDS v1.4 Sec.2.2.3.7).
#[test]
fn a_reader_instance_is_missed_without_any_take() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, condition) = reader_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(99));
    shared.settle();
    assert!(
        !condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_DEADLINE_MISSED),
        "not due yet"
    );
    clock.advance(Duration::from_millis(1));
    shared.settle();
    assert!(
        condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_DEADLINE_MISSED),
        "a WaitSet blocked on the condition, with no listener and no take(), must still see this"
    );
    let status = deadlines.status();
    assert_eq!(status.total_count, 1);
    assert_eq!(status.last_instance_handle, Some(handle_of(1)));
}

/// The listener is told on a thread of its own, never the scheduler's
/// (same rule as LIVELINESS, `tests_scheduler.rs`'s
/// `a_silent_writer_is_declared_not_alive_when_its_lease_passes`).
#[test]
fn the_listener_is_never_called_on_the_scheduler_thread() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, rx) = reader_deadlines_with_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let (status, thread) = rx.recv_timeout(Duration::from_secs(5)).expect("told");
    assert_eq!(status.total_count, 1);
    assert_ne!(
        thread.as_deref(),
        Some("hdds-liveliness"),
        "a listener never runs on the scheduler thread"
    );
}

/// Sustained silence reports one event per elapsed period (DDS v1.4
/// Sec.2.2.4.1), end to end through `ReaderDeadlines` and the scheduler
/// thread -- not one event ever.
#[test]
fn the_listener_is_called_once_per_elapsed_period() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, rx) = reader_deadlines_with_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let (first, _) = rx.recv_timeout(Duration::from_secs(5)).expect("first miss");
    assert_eq!(first.total_count, 1);
    clock.advance(Duration::from_millis(100));
    shared.settle();
    let (second, _) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("second miss");
    assert_eq!(
        second.total_count, 2,
        "a second whole silent period, a second miss"
    );
}

/// A sample that arrives after the deadline has already elapsed, but
/// before the scheduler thread ran, is still recorded as a miss first
/// (the deadline truly passed), then the instance is alive again --
/// the DEADLINE counterpart of LIVELINESS's "expired then resumed before
/// the timer ran" (`tests_scheduler.rs`): the scheduler, woken by the
/// new watch's own timer only once the clock moves past it, must not
/// lose the already-elapsed period just because a touch raced it.
#[test]
fn a_late_sample_does_not_erase_the_period_it_arrived_after() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, rx) = reader_deadlines_with_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    // The clock jumps straight past the deadline; the touch happens
    // before the scheduler thread gets to run at all.
    clock.advance(Duration::from_millis(150));
    deadlines.on_sample(handle_of(1));
    shared.settle();
    let (status, _) = rx.recv_timeout(Duration::from_secs(5)).expect("told");
    assert_eq!(
        status.total_count, 1,
        "the period that elapsed before the touch is still a miss"
    );
    // Quiet again for a full period from the touch (at 150ms): no new
    // miss until 250ms.
    clock.advance(Duration::from_millis(99));
    shared.settle();
    assert!(
        rx.try_recv().is_err(),
        "not due yet from the touch at 150ms"
    );
}

/// Two instances on the same reader: only the silent one is reported.
#[test]
fn two_instances_one_missing() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, rx) = reader_deadlines_with_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    deadlines.on_sample(handle_of(2));
    clock.advance(Duration::from_millis(90));
    deadlines.on_sample(handle_of(2));
    clock.advance(Duration::from_millis(10));
    shared.settle();
    let (status, _) = rx.recv_timeout(Duration::from_secs(5)).expect("told");
    assert_eq!(status.last_instance_handle, Some(handle_of(1)));
    assert!(
        rx.try_recv().is_err(),
        "instance 2 was fed at 90ms, not due until 190ms"
    );
}

/// `remove_instance` (the reader's dispose queue, on a dispose or
/// NOT_ALIVE_NO_WRITERS transition -- see the module doc) stops the
/// watch: no further misses for that instance.
#[test]
fn remove_instance_stops_the_watch() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, condition) = reader_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    deadlines.remove_instance(handle_of(1));
    clock.advance(Duration::from_millis(500));
    shared.settle();
    assert!(
        !condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_DEADLINE_MISSED),
        "disposed before its deadline: never missed"
    );
}

/// A revived instance (a new sample after `remove_instance`) restarts
/// its own period from the revival, independent of the watch it
/// replaced.
#[test]
fn a_revived_instance_restarts_its_own_period() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, rx) = reader_deadlines_with_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    deadlines.remove_instance(handle_of(1));
    clock.advance(Duration::from_millis(60));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(99));
    shared.settle();
    assert!(
        rx.try_recv().is_err(),
        "the revival at 60ms moves the boundary to 160ms"
    );
    clock.advance(Duration::from_millis(1));
    shared.settle();
    let (status, _) = rx.recv_timeout(Duration::from_secs(5)).expect("told");
    assert_eq!(status.total_count, 1);
}

/// The lazy check (`ReaderDeadlines::check_now`, what
/// `DataReader::check_requested_deadline` calls) and the scheduler agree:
/// calling it right at the boundary reports the miss once, and the
/// scheduler then finds nothing left to report for the same period.
#[test]
fn the_lazy_check_and_the_scheduler_do_not_double_count() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, rx) = reader_deadlines_with_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(100));
    // The lazy path runs first, synchronously, before the scheduler
    // thread wakes.
    deadlines.check_now();
    let (status, _) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("told once, by the lazy path");
    assert_eq!(status.total_count, 1);
    shared.settle();
    assert!(
        rx.try_recv().is_err(),
        "the scheduler's own pass for the same period reports nothing more"
    );
}

/// The writer side (DDS v1.4 Sec.2.2.3.7, OFFERED_DEADLINE_MISSED,
/// Sec.2.2.4.1): symmetric with the reader, through `WriterDeadlines`.
#[test]
fn a_writer_instance_is_missed_without_any_write() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, condition) = writer_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_write(handle_of(3));
    clock.advance(Duration::from_millis(100));
    shared.settle();
    assert!(condition
        .get_active_statuses()
        .contains(StatusMask::OFFERED_DEADLINE_MISSED));
    let status = deadlines.status();
    assert_eq!(status.total_count, 1);
    assert_eq!(status.last_instance_handle, Some(handle_of(3)));
}

/// `OfferedDeadlineMissedStatus` reads and resets its change exactly like
/// `RequestedDeadlineMissedStatus` (DDS v1.4 Sec.2.2.4.2.1).
#[test]
fn offered_deadline_missed_status_resets_its_change_on_read() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = Arc::clone(scheduler.shared());
    let (deadlines, _condition) = writer_deadlines_no_listener(&shared, Duration::from_millis(50));
    deadlines.on_write(handle_of(9));
    clock.advance(Duration::from_millis(50));
    shared.settle();
    let first: OfferedDeadlineMissedStatus = deadlines.status();
    assert_eq!((first.total_count, first.total_count_change), (1, 1));
    let second = deadlines.status();
    assert_eq!(
        (second.total_count, second.total_count_change),
        (1, 0),
        "the change resets, the total does not"
    );
}

/// DDS v1.4 Sec.2.2.3.7 measures the interval between updates, even if
/// the scheduler has not yet inspected any of the intervening updates.
#[test]
fn timely_updates_before_a_scheduler_pass_do_not_miss() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(clock.clone());
    let (deadlines, _) = reader_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(50));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(60));
    deadlines.on_sample(handle_of(1));
    deadlines.check_now();
    assert_eq!(
        deadlines.status().total_count,
        0,
        "every interval was below 100ms"
    );
}

/// DDS v1.4 Sec.2.2.4.1 counts every elapsed period, including the
/// periods preceding a resumption while the scheduler was delayed.
#[test]
fn a_resumption_preserves_all_elapsed_periods() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(clock.clone());
    let (deadlines, _) = reader_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(350));
    deadlines.on_sample(handle_of(1));
    deadlines.check_now();
    assert_eq!(deadlines.status().total_count, 3);
    clock.advance(Duration::from_millis(99));
    deadlines.check_now();
    assert_eq!(deadlines.status().total_count, 3);
    clock.advance(Duration::from_millis(1));
    deadlines.check_now();
    assert_eq!(deadlines.status().total_count, 4);
}

/// The writer's lazy path must report the same elapsed periods as the
/// scheduler (DDS v1.4 Sec.2.2.4.1), even without a scheduler thread.
#[test]
fn the_lazy_writer_check_counts_all_elapsed_periods() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(clock.clone());
    let (deadlines, _) = writer_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_write(handle_of(1));
    clock.advance(Duration::from_millis(350));
    deadlines.check_instance(handle_of(1));
    assert_eq!(deadlines.status().total_count, 3);
    deadlines.check_instance(handle_of(1));
    assert_eq!(deadlines.status().total_count, 3, "already consumed");
}

#[derive(Clone, Debug, crate::DDS)]
struct DeadlineWire {
    id: u32,
    value: u32,
}

#[derive(Clone, Debug)]
struct DeadlineValue {
    id: u32,
    value: u32,
}

impl crate::dds::DDS for DeadlineValue {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        <DeadlineWire as crate::dds::DDS>::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        crate::dds::DDS::encode(
            &DeadlineWire {
                id: self.id,
                value: self.value,
            },
            buf,
            version,
        )
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        let wire = <DeadlineWire as crate::dds::DDS>::decode(buf, version)?;
        Ok(Self {
            id: wire.id,
            value: wire.value,
        })
    }

    fn has_key() -> bool {
        true
    }

    fn compute_key(&self) -> [u8; 16] {
        let mut key = [0; 16];
        key[..4].copy_from_slice(&self.id.to_be_bytes());
        key
    }
}

fn endpoint_participant(clock: &Arc<ManualClock>, name: &str) -> Arc<crate::Participant> {
    let mut builder = crate::Participant::builder(name)
        .domain_id(160)
        .with_transport(crate::TransportMode::IntraProcess);
    builder.liveliness_clock = Some(clock.clone());
    builder.build().expect("participant")
}

fn finite_qos() -> crate::QoS {
    let mut qos = crate::QoS::best_effort().keep_last(4);
    qos.deadline = crate::qos::deadline::Deadline::new(Duration::from_millis(100));
    qos.writer_data_lifecycle.autodispose_unregistered_instances = false;
    qos
}

/// DDS v1.4 Sec.2.2.3.7 and Sec.2.2.4.4: the real local delivery path
/// must start the reader's per-instance timers without any read/take.
#[test]
fn local_reader_deadline_wakes_a_waitset_without_any_take() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-local-waitset");
    let topic = participant
        .topic::<DeadlineValue>("deadline-local-waitset")
        .unwrap();
    let reader = topic.reader().qos(finite_qos()).build().unwrap();
    let writer = topic.writer().qos(finite_qos()).build().unwrap();
    let condition = reader.get_status_condition();
    condition.set_enabled_statuses(StatusMask::REQUESTED_DEADLINE_MISSED);
    let waitset = crate::dds::WaitSet::new();
    waitset.attach_condition(condition).unwrap();
    writer.write(&DeadlineValue { id: 1, value: 0 }).unwrap();
    writer.write(&DeadlineValue { id: 2, value: 0 }).unwrap();
    clock.advance(Duration::from_millis(90));
    writer.write(&DeadlineValue { id: 2, value: 1 }).unwrap();
    clock.advance(Duration::from_millis(10));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert!(!waitset
        .wait(Some(Duration::from_secs(1)))
        .unwrap()
        .is_empty());
    let status = reader.get_requested_deadline_missed_status();
    assert_eq!(status.total_count, 1, "only instance 1 is silent");
    let key = writer
        .register_instance(&DeadlineValue { id: 1, value: 0 })
        .unwrap();
    assert_eq!(status.last_instance_handle, Some(key));
    let offered = writer.get_offered_deadline_missed_status();
    assert_eq!(offered.total_count, 1);
    assert_eq!(offered.last_instance_handle, Some(key));
}

/// A cached sample cannot renew DEADLINE when the application finally
/// takes it (DDS v1.4 Sec.2.2.3.7 concerns reception, not consumption).
#[test]
fn taking_an_old_sample_does_not_restart_the_reader_period() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-old-take");
    let topic = participant
        .topic::<DeadlineValue>("deadline-old-take")
        .unwrap();
    let reader = topic.reader().qos(finite_qos()).build().unwrap();
    let writer = topic.writer().qos(finite_qos()).build().unwrap();
    writer.write(&DeadlineValue { id: 1, value: 0 }).unwrap();
    clock.advance(Duration::from_millis(90));
    assert!(reader.take().unwrap().is_some());
    clock.advance(Duration::from_millis(10));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 1);
}

/// Drive the same subscriber that handles RTPS DATA, without socket or
/// discovery timing. Reception must arm DEADLINE before any take/read.
#[test]
fn network_reader_deadline_starts_at_admission_without_any_take() {
    use crate::dds::DDS;
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-network");
    let registry = Arc::new(crate::engine::TopicRegistry::new());
    let name = "deadline-network";
    let reader = crate::dds::reader::ReaderBuilder::<DeadlineValue>::new(name.into())
        .with_participant(participant.clone())
        .with_registry(registry.clone())
        .qos(finite_qos())
        .build()
        .unwrap();
    let mut bytes = [0; 64];
    let value = DeadlineValue { id: 1, value: 7 };
    let len = value
        .encode(&mut bytes, crate::dds::CdrVersion::Xcdr2)
        .unwrap();
    registry.register_writer_guid([0x42; 16], name.into());
    registry
        .register_writer_ownership_kind([0x42; 16], crate::qos::ownership::OwnershipKind::Shared);
    let topic = registry.get_topic(name).unwrap();
    assert_eq!(
        topic.deliver_with_writer([0x42; 16], 1, &bytes[..len], crate::dds::CdrVersion::Xcdr2),
        0
    );
    clock.advance(Duration::from_millis(100));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 1);
    assert_eq!(
        topic.deliver_dispose_from_writer(
            [0x42; 16],
            2,
            value.compute_key(),
            crate::engine::subscriber::DisposeKind::Disposed
        ),
        0
    );
    clock.advance(Duration::from_millis(200));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(
        reader.get_requested_deadline_missed_status().total_count,
        1,
        "network disposal stops the timer without any take"
    );
}

/// DDS v1.4 Sec.2.2.3.23.3: disposal ends the instance's existence;
/// consuming its old data must not revive its update contract.
#[test]
fn local_disposal_stops_both_timers_before_any_take() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-dispose");
    let topic = participant
        .topic::<DeadlineValue>("deadline-dispose")
        .unwrap();
    let reader = topic.reader().qos(finite_qos()).build().unwrap();
    let writer = topic.writer().qos(finite_qos()).build().unwrap();
    let value = DeadlineValue { id: 1, value: 0 };
    writer.write(&value).unwrap();
    writer.dispose(&value).unwrap();
    clock.advance(Duration::from_millis(150));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 0);
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 0);
    let _ = reader.take();
    writer.write(&value).unwrap();
    clock.advance(Duration::from_millis(100));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 1);
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 1);
}

/// Unregistration ends only that writer's responsibility. The reader
/// retains its periodic contract after the final writer leaves
/// (DDS v1.4 Sec.2.2.3.23.2).
#[test]
fn unregistering_one_local_writer_keeps_the_reader_timer() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-unregister");
    let topic = participant
        .topic::<DeadlineValue>("deadline-unregister")
        .unwrap();
    let reader = topic.reader().qos(finite_qos()).build().unwrap();
    let first = topic.writer().qos(finite_qos()).build().unwrap();
    let second = topic.writer().qos(finite_qos()).build().unwrap();
    let value = DeadlineValue { id: 1, value: 0 };
    first.write(&value).unwrap();
    second.write(&value).unwrap();
    first.unregister_instance(&value).unwrap();
    clock.advance(Duration::from_millis(100));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 1);
    second.unregister_instance(&value).unwrap();
    clock.advance(Duration::from_millis(200));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 3);
}

#[test]
fn a_closed_deadline_owner_cannot_register_again() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(clock.clone());
    let (reader, _) = reader_deadlines_no_listener(&shared, Duration::from_millis(100));
    let (writer, _) = writer_deadlines_no_listener(&shared, Duration::from_millis(100));
    reader.close();
    writer.close();
    reader.on_sample(handle_of(1));
    writer.on_write(handle_of(1));
    clock.advance(Duration::from_millis(100));
    reader.check_now();
    writer.check_instance(handle_of(1));
    assert_eq!(reader.status().total_count, 0);
    assert_eq!(writer.status().total_count, 0);
}

#[test]
fn infinite_deadlines_create_no_instance_watches() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-infinite");
    let topic = participant
        .topic::<DeadlineValue>("deadline-infinite")
        .unwrap();
    let reader = topic
        .reader()
        .qos(crate::QoS::best_effort())
        .build()
        .unwrap();
    let writer = topic
        .writer()
        .qos(crate::QoS::best_effort())
        .build()
        .unwrap();
    writer.write(&DeadlineValue { id: 1, value: 0 }).unwrap();
    assert!(reader.take().unwrap().is_some());
    let shared = participant.liveliness.as_ref().unwrap().shared();
    assert_eq!(shared.deadline_watch_count_for_test(), 0);
}

struct OfferedRecorder(mpsc::Sender<(OfferedDeadlineMissedStatus, Option<String>)>);

impl crate::dds::listener::DataWriterListener<DeadlineValue> for OfferedRecorder {
    fn on_offered_deadline_missed(&self, status: OfferedDeadlineMissedStatus) {
        let _ = self
            .0
            .send((status, std::thread::current().name().map(str::to_string)));
    }
}

#[test]
fn writer_listener_reports_each_period_once_through_the_real_writer() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-writer-listener");
    let topic = participant
        .topic::<DeadlineValue>("deadline-writer-listener")
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let writer = topic
        .writer()
        .qos(finite_qos())
        .with_listener(Arc::new(OfferedRecorder(tx)))
        .build()
        .unwrap();
    let value = DeadlineValue { id: 1, value: 0 };
    writer.write(&value).unwrap();
    let shared = participant.liveliness.as_ref().unwrap().shared();
    for total in 1..=2 {
        clock.advance(Duration::from_millis(100));
        shared.settle();
        let (status, thread) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(status.total_count, total);
        assert_eq!(status.total_count_change, 1);
        assert_ne!(thread.as_deref(), Some("hdds-liveliness"));
        assert_eq!(
            writer
                .get_offered_deadline_missed_status()
                .total_count_change,
            0
        );
        // The write's lazy check must not count the scheduler's miss again.
        writer.write(&value).unwrap();
        assert_eq!(
            writer.get_offered_deadline_missed_status().total_count,
            total
        );
    }
    drop(writer);
    assert_eq!(shared.deadline_watch_count_for_test(), 0);
}

/// An unsupported zero-period contract must fail explicitly at creation,
/// rather than monopolizing the participant's scheduler on first data.
#[test]
fn zero_deadline_is_rejected_before_a_timer_can_be_armed() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-zero");
    let topic = participant.topic::<DeadlineValue>("deadline-zero").unwrap();
    let mut qos = finite_qos();
    qos.deadline.period = Duration::ZERO;
    assert!(matches!(
        topic.reader().qos(qos.clone()).build(),
        Err(crate::dds::Error::InvalidQos(_))
    ));
    assert!(matches!(
        topic.writer().qos(qos).build(),
        Err(crate::dds::Error::InvalidQos(_))
    ));
}

/// DDS v1.4 Sec.2.2.4.1 identifies the actual missed instance. Keys with
/// identical first eight bytes must still be distinguishable.
#[test]
fn last_instance_handle_distinguishes_keys_with_the_same_prefix() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(clock.clone());
    let (deadlines, _) = reader_deadlines_no_listener(&shared, Duration::from_millis(100));
    let mut key = [0x42; 16];
    key[15] = 1;
    let first = InstanceHandle::new(key);
    key[15] = 2;
    let second = InstanceHandle::new(key);
    deadlines.on_sample(first);
    deadlines.on_sample(second);
    clock.advance(Duration::from_millis(90));
    deadlines.on_sample(second);
    clock.advance(Duration::from_millis(10));
    deadlines.check_now();
    let first_status = deadlines.status();
    clock.advance(Duration::from_millis(90));
    deadlines.check_now();
    let second_status = deadlines.status();
    assert_eq!(first_status.last_instance_handle, Some(first));
    assert_eq!(second_status.last_instance_handle, Some(second));
}

/// DDS v1.4 Sec.2.2.4.1 counts periods that elapsed while the instance
/// still existed, even when disposal arrives before the scheduler runs.
#[test]
fn retiring_a_reader_instance_preserves_elapsed_periods() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(clock.clone());
    let (deadlines, _) = reader_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_sample(handle_of(1));
    clock.advance(Duration::from_millis(350));
    deadlines.remove_instance(handle_of(1));
    assert_eq!(deadlines.status().total_count, 3);
    clock.advance(Duration::from_millis(200));
    deadlines.check_now();
    assert_eq!(
        deadlines.status().total_count,
        3,
        "no periods after retirement"
    );
}

#[test]
fn retiring_a_writer_instance_preserves_elapsed_periods() {
    let clock = Arc::new(ManualClock::new(0));
    let shared = Shared::new(clock.clone());
    let (deadlines, _) = writer_deadlines_no_listener(&shared, Duration::from_millis(100));
    deadlines.on_write(handle_of(1));
    clock.advance(Duration::from_millis(350));
    deadlines.remove_instance(handle_of(1));
    assert_eq!(deadlines.status().total_count, 3);
    clock.advance(Duration::from_millis(200));
    deadlines.check_instance(handle_of(1));
    assert_eq!(
        deadlines.status().total_count,
        3,
        "no periods after retirement"
    );
}

/// Preserve the real status predicate and signal hooks, but pause one
/// false scan so expiration is guaranteed to follow the waiter's scan.
struct ScannedCondition {
    inner: Arc<StatusCondition>,
    scan: std::sync::Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl crate::dds::Condition for ScannedCondition {
    fn get_trigger_value(&self) -> bool {
        let value = crate::dds::Condition::get_trigger_value(self.inner.as_ref());
        let hook = self.scan.lock().unwrap().take();
        if let Some((entered, resume)) = hook {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
        }
        value
    }

    fn condition_id(&self) -> u64 {
        crate::dds::Condition::condition_id(self.inner.as_ref())
    }

    fn add_waitset_signal(&self, signal: Arc<dyn crate::core::rt::waitset::WaitsetSignal>) {
        crate::dds::Condition::add_waitset_signal(self.inner.as_ref(), signal);
    }

    fn remove_waitset_signal(&self, signal_id: u64) {
        crate::dds::Condition::remove_waitset_signal(self.inner.as_ref(), signal_id);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// DDS v1.4 Sec.2.2.4.4: a deadline must signal a waiter that has already
/// observed a false predicate, without another application data access.
#[test]
fn a_waiting_waitset_is_signalled_without_any_take() {
    let clock = Arc::new(ManualClock::new(0));
    let scheduler = started(&clock);
    let shared = scheduler.shared();
    let (deadlines, condition) = reader_deadlines_no_listener(shared, Duration::from_millis(100));
    condition.set_enabled_statuses(StatusMask::REQUESTED_DEADLINE_MISSED);
    deadlines.on_sample(handle_of(1));
    let scanned = Arc::new(ScannedCondition {
        inner: condition,
        scan: std::sync::Mutex::new(None),
    });
    let waitset = crate::dds::WaitSet::new();
    waitset.attach_condition(scanned.clone()).unwrap();
    let (entered, entry) = mpsc::channel();
    let (resume, resumption) = mpsc::channel();
    *scanned.scan.lock().unwrap() = Some((entered, resumption));
    let waiter = std::thread::spawn(move || waitset.wait(Some(Duration::from_secs(5))));
    entry.recv_timeout(Duration::from_secs(5)).unwrap();
    clock.advance(Duration::from_millis(100));
    shared.settle();
    resume.send(()).unwrap();
    assert_eq!(waiter.join().unwrap().unwrap().len(), 1);
}

#[test]
fn no_writers_does_not_end_reader_instance_existence() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-no-writers");
    let topic = participant
        .topic::<DeadlineValue>("deadline-no-writers")
        .unwrap();
    let reader = topic.reader().qos(finite_qos()).build().unwrap();
    let writer = topic.writer().qos(finite_qos()).build().unwrap();
    let value = DeadlineValue { id: 1, value: 0 };
    writer.write(&value).unwrap();
    clock.advance(Duration::from_millis(10));
    writer.unregister_instance(&value).unwrap();
    clock.advance(Duration::from_millis(340));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 3);
}

/// Drive the same subscriber that handles RTPS DATA, without socket or
/// discovery timing. Reception must arm DEADLINE before any take/read.
#[test]
fn network_no_writers_retains_the_reader_deadline() {
    use crate::dds::DDS;
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-no-writers-network");
    let registry = Arc::new(crate::engine::TopicRegistry::new());
    let name = "deadline-no-writers-network";
    let reader = crate::dds::reader::ReaderBuilder::<DeadlineValue>::new(name.into())
        .with_participant(participant.clone())
        .with_registry(registry.clone())
        .qos(finite_qos())
        .build()
        .unwrap();
    let mut bytes = [0; 64];
    let value = DeadlineValue { id: 1, value: 7 };
    let len = value
        .encode(&mut bytes, crate::dds::CdrVersion::Xcdr2)
        .unwrap();
    registry.register_writer_guid([0x42; 16], name.into());
    registry
        .register_writer_ownership_kind([0x42; 16], crate::qos::ownership::OwnershipKind::Shared);
    let topic = registry.get_topic(name).unwrap();
    assert_eq!(
        topic.deliver_with_writer([0x42; 16], 1, &bytes[..len], crate::dds::CdrVersion::Xcdr2),
        0
    );
    clock.advance(Duration::from_millis(100));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.get_requested_deadline_missed_status().total_count, 1);
    assert_eq!(
        topic.deliver_dispose_from_writer(
            [0x42; 16],
            2,
            value.compute_key(),
            crate::engine::subscriber::DisposeKind::Unregistered
        ),
        0
    );
    clock.advance(Duration::from_millis(200));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(
        reader.get_requested_deadline_missed_status().total_count,
        3,
        "NO_WRITERS retains periodic connectivity monitoring"
    );
}

#[test]
fn finite_writer_lazy_check_visits_only_the_written_instance() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Clock(AtomicUsize);
    impl super::LivelinessClock for Clock {
        fn now(&self) -> u64 {
            self.0.fetch_add(1, Ordering::SeqCst);
            0
        }
        fn sleep_for(&self, _: u64) -> Option<Duration> {
            None
        }
    }
    let clock = Arc::new(Clock(AtomicUsize::new(0)));
    let shared = Shared::new(clock.clone());
    let (writer, _) = writer_deadlines_no_listener(&shared, Duration::from_secs(60));
    for id in 0u32..4096 {
        let mut key = [0; 16];
        key[..4].copy_from_slice(&id.to_be_bytes());
        writer.on_write(InstanceHandle::new(key));
    }
    clock.0.store(0, Ordering::SeqCst);
    writer.check_instance(InstanceHandle::new([0; 16]));
    let reads = clock.0.load(Ordering::SeqCst);
    eprintln!("one lazy writer check with 4096 instances reads the clock {reads} times");
    assert_eq!(reads, 1);
}

#[test]
fn cancelled_deadline_storage_is_bounded() {
    struct Sink;
    impl super::deadline::DeadlineSink for Sink {
        fn missed(&self, _: InstanceHandle) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
            None
        }
    }
    let sink: Arc<dyn super::deadline::DeadlineSink> = Arc::new(Sink);
    let mut core = super::leases::Core::default();
    for key in 2..10_002 {
        core.watch_deadline(
            key,
            super::deadline::InstanceDeadline::new(0),
            handle_of(1),
            86_400_000_000_000,
            Arc::downgrade(&sink),
            0,
        );
        core.unwatch_deadline(key);
    }
    eprintln!(
        "active={} heap={}",
        core.deadline_watch_count_for_test(),
        core.heap_len_for_test()
    );
    assert_eq!(core.deadline_watch_count_for_test(), 0);
    assert!(core.heap_len_for_test() <= 64);
    assert!(core.heap_capacity_for_test() <= 128);
    // Reclaim the allocation after a burst of simultaneously live watches.
    for key in 20_000..30_000 {
        core.watch_deadline(
            key,
            super::deadline::InstanceDeadline::new(0),
            handle_of(1),
            86_400_000_000_000,
            Arc::downgrade(&sink),
            0,
        );
    }
    for key in 20_000..30_000 {
        core.unwatch_deadline(key);
    }
    assert_eq!(core.deadline_watch_count_for_test(), 0);
    assert!(core.heap_len_for_test() <= 64);
    assert!(core.heap_capacity_for_test() <= 128);
}

#[test]
fn cancellation_compaction_preserves_live_timers() {
    use super::deadline::{DeadlineSink, InstanceDeadline};
    use super::leases::{Core, LivelinessSink, Outcome, Renewal};
    struct Sink;
    impl DeadlineSink for Sink {
        fn missed(&self, _: InstanceHandle) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
            None
        }
    }
    impl LivelinessSink for Sink {
        fn transition(&self, _: u64, _: bool) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
            None
        }
    }
    let sink = Arc::new(Sink);
    let deadline_sink: Arc<dyn DeadlineSink> = sink.clone();
    let liveliness_sink: Arc<dyn LivelinessSink> = sink;
    let renewal = Arc::new(Renewal::new(1, 0));
    let mut core = Core::default();
    core.watch(2, renewal, 100, Arc::downgrade(&liveliness_sink), 0);
    core.watch_deadline(
        3,
        InstanceDeadline::new(0),
        handle_of(1),
        100,
        Arc::downgrade(&deadline_sink),
        0,
    );
    core.set_local_lease(4, 300, 0);
    let manual = Arc::new(Renewal::new(5, 0));
    core.set_local_lease_manual(5, 300, 0, manual.clone());
    let _ = manual.renew(1);
    for key in 100..10_100 {
        core.watch_deadline(
            key,
            InstanceDeadline::new(0),
            handle_of(2),
            86_400_000_000_000,
            Arc::downgrade(&deadline_sink),
            0,
        );
        core.unwatch_deadline(key);
    }
    assert!(core.heap_len_for_test() <= 72);
    let mut out = Vec::new();
    core.advance(100, &mut out);
    assert_eq!(
        out.iter()
            .filter(|event| matches!(event, Outcome::DeadlineMissed { .. }))
            .count(),
        1
    );
    assert_eq!(
        out.iter()
            .filter(|event| matches!(event, Outcome::Transition { alive: false, .. }))
            .count(),
        1
    );
    assert_eq!(
        out.iter()
            .filter(|event| matches!(event, Outcome::Send))
            .count(),
        1
    );
    assert_eq!(
        out.iter()
            .filter(|event| matches!(event, Outcome::SendManual))
            .count(),
        1
    );
}

#[test]
fn lazy_rearming_without_a_scheduler_keeps_heap_storage_bounded() {
    struct Sink;
    impl super::deadline::DeadlineSink for Sink {
        fn missed(&self, _: InstanceHandle) -> Option<Arc<crate::dds::reader::notices::Ordered>> {
            None
        }
    }
    let sink: Arc<dyn super::deadline::DeadlineSink> = Arc::new(Sink);
    let mut core = super::leases::Core::default();
    core.watch_deadline(
        2,
        super::deadline::InstanceDeadline::new(0),
        handle_of(1),
        100,
        Arc::downgrade(&sink),
        0,
    );
    for period in 1..=10_000 {
        let mut out = Vec::new();
        core.touch_deadline(2, period * 100, &mut out);
        assert_eq!(out.len(), 1, "one elapsed period per late write");
        assert!(core.heap_len_for_test() <= 68);
        assert!(core.heap_capacity_for_test() <= 128);
    }
}

#[test]
fn registered_writer_is_managed_before_first_write() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-register");
    let topic = participant
        .topic::<DeadlineValue>("deadline-register")
        .unwrap();
    let writer = topic.writer().qos(finite_qos()).build().unwrap();
    writer
        .register_instance(&DeadlineValue { id: 1, value: 0 })
        .unwrap();
    clock.advance(Duration::from_millis(350));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 3);
}

/// DDS v1.4 Sec.2.2.2.4.2.5: repeated registration returns the same
/// instance; only writing it meets the periodic update contract.
#[test]
fn repeated_registration_does_not_restart_the_writer_period() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-repeat-register");
    let topic = participant
        .topic::<DeadlineValue>("deadline-repeat-register")
        .unwrap();
    let writer = topic.writer().qos(finite_qos()).build().unwrap();
    let value = DeadlineValue { id: 1, value: 0 };
    let handle = writer.register_instance(&value).unwrap();
    clock.advance(Duration::from_millis(90));
    assert_eq!(
        writer.register_instance_w_timestamp(&value, 123).unwrap(),
        handle
    );
    clock.advance(Duration::from_millis(10));
    participant.liveliness.as_ref().unwrap().shared().settle();
    let status = writer.get_offered_deadline_missed_status();
    assert_eq!(status.total_count, 1);
    assert_eq!(status.last_instance_handle, Some(handle));
    writer.unregister_instance(&value).unwrap();
    clock.advance(Duration::from_millis(100));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 1);
}

/// DDS v1.4 Sec.2.2.2.4.2.5: disposal does not unregister an instance,
/// so looking up its existing handle must not restart periodic updates.
#[test]
fn registering_a_disposed_instance_does_not_restart_its_timer() {
    let clock = Arc::new(ManualClock::new(0));
    let participant = endpoint_participant(&clock, "deadline-disposed-register");
    let topic = participant
        .topic::<DeadlineValue>("deadline-disposed-register")
        .unwrap();
    let writer = topic.writer().qos(finite_qos()).build().unwrap();
    let value = DeadlineValue { id: 1, value: 0 };
    let handle = writer.register_instance(&value).unwrap();
    clock.advance(Duration::from_millis(10));
    writer.dispose(&value).unwrap();
    clock.advance(Duration::from_millis(10));
    assert_eq!(
        writer.register_instance_w_timestamp(&value, 456).unwrap(),
        handle
    );
    clock.advance(Duration::from_millis(330));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 0);
    writer.unregister_instance(&value).unwrap();
    assert_eq!(writer.register_instance(&value).unwrap(), handle);
    clock.advance(Duration::from_millis(100));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 1);
}

thread_local! {
    // DataWriter is not Sync. These callbacks reenter only on write's
    // application thread, so retain its reference on that thread.
    static CALLBACK_WRITER: std::cell::RefCell<Option<std::rc::Rc<crate::DataWriter<DeadlineValue>>>> = const { std::cell::RefCell::new(None) };
}

struct CallbackWriterScope;

impl Drop for CallbackWriterScope {
    fn drop(&mut self) {
        CALLBACK_WRITER.with(|slot| slot.borrow_mut().take());
    }
}

struct RetireOnWrite {
    unregister: bool,
    calls: std::sync::atomic::AtomicUsize,
}

impl RetireOnWrite {
    fn retire(&self, sample: &DeadlineValue) {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let writer = CALLBACK_WRITER.with(|slot| slot.borrow().as_ref().unwrap().clone());
        if self.unregister {
            writer.unregister_instance(sample).unwrap();
        } else {
            writer.dispose(sample).unwrap();
        }
    }
}

impl crate::dds::listener::DataWriterListener<DeadlineValue> for RetireOnWrite {
    fn on_sample_written(&self, sample: &DeadlineValue, _: u64) {
        self.retire(sample);
    }
}

impl crate::dds::listener::DataReaderListener<DeadlineValue> for RetireOnWrite {
    fn on_data_available(&self, sample: &DeadlineValue) {
        self.retire(sample);
    }
}

// DDS v1.4 Sec.2.2.3.7 and Sec.2.2.3.23.3: a later disposal or
// unregistration ends the obligation established by an earlier write,
// including when the application performs it inside a synchronous callback.
fn callback_retirement_stops_deadline(
    local: bool,
    unregister: bool,
    reader_callback: bool,
    durable: bool,
) {
    let clock = Arc::new(ManualClock::new(0));
    let name = format!("deadline-callback-{local}-{unregister}-{reader_callback}-{durable}");
    let participant = endpoint_participant(&clock, &name);
    let topic = participant.topic::<DeadlineValue>(&name).unwrap();
    let reader = local.then(|| topic.reader().qos(finite_qos()).build().unwrap());
    let qos = if durable {
        finite_qos().transient_local()
    } else {
        finite_qos()
    };
    let writer = std::rc::Rc::new(topic.writer().qos(qos).build().unwrap());
    CALLBACK_WRITER.with(|slot| *slot.borrow_mut() = Some(writer.clone()));
    let _scope = CallbackWriterScope;
    let listener = Arc::new(RetireOnWrite {
        unregister,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    if reader_callback {
        reader
            .as_ref()
            .unwrap()
            .set_listener(Some(listener.clone()), StatusMask::DATA_AVAILABLE);
    } else {
        writer.set_listener(Some(listener.clone()), StatusMask::ALL);
    }
    let value = DeadlineValue { id: 1, value: 0 };
    writer.write(&value).unwrap();
    assert_eq!(listener.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    clock.advance(Duration::from_millis(350));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 0);
    assert!(!writer
        .get_status_condition()
        .get_active_statuses()
        .contains(StatusMask::OFFERED_DEADLINE_MISSED));
    writer.set_listener(None, StatusMask::ALL);
    if let Some(reader) = reader {
        reader.set_listener(None, StatusMask::ALL);
    }
    writer.write(&value).unwrap();
    clock.advance(Duration::from_millis(100));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(
        writer.get_offered_deadline_missed_status().total_count,
        1,
        "a later write revives its own deadline"
    );
}

#[test]
fn general_write_callback_disposal_stops_deadline() {
    callback_retirement_stops_deadline(false, false, false, false);
}

#[test]
fn general_write_callback_unregistration_stops_deadline() {
    callback_retirement_stops_deadline(false, true, false, false);
}

#[test]
fn local_write_callback_disposal_stops_deadline() {
    callback_retirement_stops_deadline(true, false, false, false);
}

#[test]
fn local_write_callback_unregistration_stops_deadline() {
    callback_retirement_stops_deadline(true, true, false, false);
}

#[test]
fn local_reader_callback_disposal_stops_deadline() {
    callback_retirement_stops_deadline(true, false, true, false);
}

#[test]
fn local_reader_callback_unregistration_stops_deadline() {
    callback_retirement_stops_deadline(true, true, true, false);
}

#[test]
fn durable_local_reader_callback_disposal_stops_deadline() {
    callback_retirement_stops_deadline(true, false, true, true);
}

#[test]
fn durable_local_reader_callback_unregistration_stops_deadline() {
    callback_retirement_stops_deadline(true, true, true, true);
}

/// DDS v1.4 Sec.2.2.3.7 and Sec.2.2.4.1 apply to each instance,
/// including silent instances of a writer with no participant scheduler.
#[test]
fn standalone_writer_reports_silent_instances_on_the_lazy_path() {
    use crate::dds::DDS;
    let clock = Arc::new(ManualClock::new(0));
    let mut builder = crate::dds::writer::WriterBuilder::<DeadlineValue>::new(
        "deadline-standalone-silent".to_string(),
    );
    builder.deadline_clock = Some(clock.clone());
    let writer = builder.qos(finite_qos()).build().unwrap();
    let a = DeadlineValue { id: 1, value: 0 };
    let b = DeadlineValue { id: 2, value: 0 };
    writer.write(&a).unwrap();
    writer.write(&b).unwrap();
    for (elapsed, expected) in [(90, 0), (90, 1), (90, 2), (80, 3)] {
        clock.advance(Duration::from_millis(elapsed));
        writer.write(&a).unwrap();
        let condition = writer.get_status_condition();
        assert_eq!(
            condition
                .get_active_statuses()
                .contains(StatusMask::OFFERED_DEADLINE_MISSED),
            expected != 0
        );
        let status = writer.get_offered_deadline_missed_status();
        assert_eq!(status.total_count, expected);
        if expected != 0 {
            assert_eq!(status.total_count_change, 1);
            assert_eq!(
                status.last_instance_handle,
                Some(InstanceHandle::new(b.compute_key()))
            );
        }
    }
    // Another lazy check at the same instant must not count B twice.
    writer.write(&a).unwrap();
    let status = writer.get_offered_deadline_missed_status();
    assert_eq!((status.total_count, status.total_count_change), (3, 0));
    writer.dispose(&b).unwrap();
    clock.advance(Duration::from_millis(80));
    writer.write(&a).unwrap();
    assert_eq!(writer.get_offered_deadline_missed_status().total_count, 3);
}

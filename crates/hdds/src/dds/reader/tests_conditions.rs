// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! ReadCondition / QueryCondition through the public reader API (DDS v1.4
//! Sec.2.2.2.5.3.5-7, 2.2.2.5.3.10-11, 2.2.4.5), on the intra-process
//! ring/merger fixture the other reader tests use.

use super::subscriber::DisposeEvent;
use super::ReaderBuilder;
use crate::core::rt;
use crate::dds::writer::WriterBuilder;
use crate::dds::{
    Condition, DataReader, DataWriter, Error, InstanceState, InstanceStateMask, QoS, SampleState,
    SampleStateMask, StatusMask, ViewState, ViewStateMask, WaitSet, DDS,
};
use crate::engine::subscriber::DisposeKind;
use crate::qos::deadline::Deadline;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Reading {
    id: i32,
    value: i32,
}

/// Wire twin of [`Instance`]: the derive has no key handling, so the keyed
/// type delegates its codec here and hand-writes the key (same split as
/// `Keyed`/`KeyedWire` in `tests.rs`).
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct InstanceWire {
    key: i64,
    value: i64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Instance {
    key: i64,
    value: i64,
}

impl DDS for Instance {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        InstanceWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        InstanceWire {
            key: self.key,
            value: self.value,
        }
        .encode(buf, version)
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        let wire = InstanceWire::decode(buf, version)?;
        Ok(Self {
            key: wire.key,
            value: wire.value,
        })
    }

    fn has_key() -> bool {
        true
    }

    fn compute_key(&self) -> [u8; 16] {
        let mut hash = [0u8; 16];
        hash[..8].copy_from_slice(&self.key.to_le_bytes());
        hash[8..].copy_from_slice(&(self.key ^ 0x5A5A_5A5A_5A5A_5A5A_i64).to_le_bytes());
        hash
    }
}

fn pair<T: DDS>(topic: &str) -> (DataWriter<T>, Arc<DataReader<T>>) {
    pair_with_depth(topic, 16)
}

fn pair_with_depth<T: DDS>(topic: &str, depth: u32) -> (DataWriter<T>, Arc<DataReader<T>>) {
    let _ = rt::init_slab_pool();
    let writer = WriterBuilder::<T>::new(topic.to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");
    let reader = ReaderBuilder::<T>::new(topic.to_string())
        .qos(QoS::best_effort().keep_last(depth))
        .build()
        .expect("reader build should succeed");
    reader.bind_to_writer(writer.merger());
    (writer, Arc::new(reader))
}

fn reading(id: i32, value: i32) -> Reading {
    Reading { id, value }
}

// ---------------------------------------------------------------------------
// Sample state masks
// ---------------------------------------------------------------------------

/// NOT_READ / ANY / ALIVE: the common "new data" condition. False on an
/// empty reader, true once a sample arrived, false again once it is taken
/// (Sec.2.2.4.5, the worked example).
#[test]
fn not_read_condition_follows_arrival_and_take() {
    let (writer, reader) = pair::<Reading>("cond-not-read");
    let cond = reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ALIVE,
        )
        .expect("create_readcondition");

    assert!(!cond.get_trigger_value(), "no sample, no trigger");

    writer.write(&reading(1, 10)).expect("write");
    assert!(cond.get_trigger_value(), "an unread sample is present");

    let taken = reader.take_w_condition(&cond, usize::MAX).expect("take");
    assert_eq!(taken.len(), 1);
    let (data, info) = &taken[0];
    assert_eq!(data.as_ref(), Some(&reading(1, 10)));
    assert_eq!(info.sample_state, SampleState::NotRead);
    assert_eq!(info.view_state, ViewState::New);
    assert_eq!(info.instance_state, InstanceState::Alive);
    assert!(info.valid_data);

    assert!(!cond.get_trigger_value(), "all samples taken");
    assert!(reader
        .take_w_condition(&cond, usize::MAX)
        .expect("take")
        .is_empty());
}

/// The second half of the Sec.2.2.4.5 example: with mask {NOT_READ} a
/// read is enough to lower the trigger; with {READ, NOT_READ} only a take
/// is.
#[test]
fn read_lowers_a_not_read_condition_but_not_an_any_condition() {
    let (writer, reader) = pair::<Reading>("cond-read-vs-any");
    let not_read = reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    let any = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    let read_only = reader
        .create_readcondition(
            SampleStateMask::READ,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");

    writer.write(&reading(1, 1)).expect("write");
    assert!(not_read.get_trigger_value());
    assert!(any.get_trigger_value());
    assert!(!read_only.get_trigger_value(), "nothing has been read yet");

    let read = reader
        .read_w_condition(&not_read, usize::MAX)
        .expect("read");
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].0, Some(reading(1, 1)));
    assert_eq!(
        read[0].1.sample_state,
        SampleState::NotRead,
        "the info reports the state before this read"
    );

    assert!(!not_read.get_trigger_value(), "the only sample is READ now");
    assert!(any.get_trigger_value(), "still managed by the reader");
    assert!(read_only.get_trigger_value(), "and READ matches this one");

    // read_w_condition on the READ mask returns it again: read is not
    // destructive (Sec.2.2.2.5.3.8).
    let again = reader
        .read_w_condition(&read_only, usize::MAX)
        .expect("read");
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].1.sample_state, SampleState::Read);

    let taken = reader.take_w_condition(&any, usize::MAX).expect("take");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].1.sample_state, SampleState::Read);
    assert!(!any.get_trigger_value());
    assert!(!read_only.get_trigger_value());
}

/// A plain `take()` recomputes the conditions too: "a single take
/// operation can potentially change the trigger_value of several
/// ReadCondition" (Sec.2.2.4.5).
#[test]
fn plain_take_lowers_every_condition_on_the_reader() {
    let (writer, reader) = pair::<Reading>("cond-plain-take");
    let a = reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    let b = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");

    writer.write(&reading(7, 7)).expect("write");
    assert!(a.get_trigger_value());
    assert!(b.get_trigger_value());

    assert_eq!(reader.take().expect("take"), Some(reading(7, 7)));
    assert!(!a.get_trigger_value());
    assert!(!b.get_trigger_value());
}

// ---------------------------------------------------------------------------
// View state masks
// ---------------------------------------------------------------------------

/// NEW only: true for an instance the reader never handed out, false for
/// a later sample of that instance, true again for another instance
/// (Sec.2.2.2.5.3.9: taking sets the instance's view_state to NOT_NEW).
#[test]
fn new_view_condition_tracks_instances_seen_by_the_application() {
    let (writer, reader) = pair::<Instance>("cond-view-new");
    let new_only = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");
    let not_new_only = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NOT_NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");

    writer
        .write(&Instance { key: 1, value: 10 })
        .expect("write");
    assert!(new_only.get_trigger_value(), "instance 1 never seen");
    assert!(!not_new_only.get_trigger_value());

    let taken = reader
        .take_w_condition(&new_only, usize::MAX)
        .expect("take");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].1.view_state, ViewState::New);
    assert!(!new_only.get_trigger_value());

    writer
        .write(&Instance { key: 1, value: 11 })
        .expect("write");
    assert!(
        !new_only.get_trigger_value(),
        "instance 1 has been seen: its samples are NOT_NEW"
    );
    assert!(not_new_only.get_trigger_value());

    writer
        .write(&Instance { key: 2, value: 20 })
        .expect("write");
    assert!(new_only.get_trigger_value(), "instance 2 is new");

    // take_w_condition honours the view mask: only instance 2 leaves.
    let taken = reader
        .take_w_condition(&new_only, usize::MAX)
        .expect("take");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].0, Some(Instance { key: 2, value: 20 }));
    assert_eq!(taken[0].1.view_state, ViewState::New);

    let rest = reader
        .take_w_condition(&not_new_only, usize::MAX)
        .expect("take");
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].0, Some(Instance { key: 1, value: 11 }));
    assert_eq!(rest[0].1.view_state, ViewState::NotNew);
}

/// A read (not only a take) makes the instance NOT_NEW (Sec.2.2.2.5.3.8).
#[test]
fn read_makes_the_instance_not_new() {
    let (writer, reader) = pair::<Reading>("cond-view-read");
    let new_only = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");
    writer.write(&reading(1, 1)).expect("write");
    assert!(new_only.get_trigger_value());
    assert_eq!(reader.read().expect("read"), Some(reading(1, 1)));
    assert!(
        !new_only.get_trigger_value(),
        "read marked the instance seen"
    );
    // The sample is still there for an ANY-view condition.
    let any = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    assert!(any.get_trigger_value());
}

// ---------------------------------------------------------------------------
// Instance state masks
// ---------------------------------------------------------------------------

fn disposed_event(key: u8, kind: DisposeKind) -> DisposeEvent {
    let mut key_hash = [0u8; 16];
    key_hash[0] = key;
    DisposeEvent {
        key_hash,
        kind,
        seq: 5,
        writer_guid: None,
        order_seq: 5,
        announced: false,
        read: false,
        from_local_writer: false,
        disposed_generation_count: 0,
        no_writers_generation_count: 0,
        source_timestamp_ns: None,
    }
}

/// An instance-state transition is a sample the Service manages
/// (Sec.2.2.4.5): a NOT_ALIVE_DISPOSED condition triggers on a queued
/// dispose and `take_w_condition` returns it as `(None, info)`; an
/// ALIVE-only condition ignores it.
#[test]
fn not_alive_disposed_condition_sees_the_queued_transition() {
    let (_writer, reader) = pair::<Instance>("cond-instance-disposed");
    let disposed = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_DISPOSED,
        )
        .expect("create");
    let no_writers = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_NO_WRITERS,
        )
        .expect("create");
    let alive = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ALIVE,
        )
        .expect("create");

    assert!(!disposed.get_trigger_value());
    reader
        .dispose_queue_for_test()
        .push(disposed_event(1, DisposeKind::Disposed));

    assert!(disposed.get_trigger_value());
    assert!(
        !no_writers.get_trigger_value(),
        "a dispose is not NO_WRITERS"
    );
    assert!(!alive.get_trigger_value(), "no data sample");

    assert!(
        reader
            .take_w_condition(&alive, usize::MAX)
            .expect("take")
            .is_empty(),
        "an ALIVE condition does not carry transitions"
    );
    assert!(disposed.get_trigger_value(), "still queued");

    let taken = reader
        .take_w_condition(&disposed, usize::MAX)
        .expect("take");
    assert_eq!(taken.len(), 1);
    assert!(taken[0].0.is_none());
    assert!(!taken[0].1.valid_data);
    assert_eq!(taken[0].1.instance_state, InstanceState::NotAliveDisposed);
    assert_eq!(taken[0].1.sample_state, SampleState::NotRead);
    assert_eq!(taken[0].1.view_state, ViewState::New);
    assert!(!disposed.get_trigger_value(), "transition consumed");

    // An unregister is NO_WRITERS.
    reader
        .dispose_queue_for_test()
        .push(disposed_event(2, DisposeKind::Unregistered));
    assert!(!disposed.get_trigger_value());
    assert!(no_writers.get_trigger_value());
    let taken = reader
        .take_w_condition(&no_writers, usize::MAX)
        .expect("take");
    assert_eq!(taken[0].1.instance_state, InstanceState::NotAliveNoWriters);
}

// ---------------------------------------------------------------------------
// QueryCondition
// ---------------------------------------------------------------------------

/// The query decides: a sample that fails it neither triggers nor is
/// taken; changing the parameters changes the verdict on the samples the
/// reader still holds (Sec.2.2.2.5.9.3).
#[test]
fn query_condition_filters_on_content_and_follows_parameter_changes() {
    let (writer, reader) = pair::<Reading>("cond-query");
    let hot = reader
        .create_querycondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
            "value > %0",
            vec!["10".to_string()],
        )
        .expect("create_querycondition");

    writer.write(&reading(1, 5)).expect("write");
    assert!(!hot.get_trigger_value(), "5 > 10 is false");

    writer.write(&reading(2, 20)).expect("write");
    assert!(hot.get_trigger_value(), "20 > 10");

    let taken = reader.take_w_condition(&hot, usize::MAX).expect("take");
    assert_eq!(taken.len(), 1, "only the matching sample leaves");
    assert_eq!(taken[0].0, Some(reading(2, 20)));
    assert!(!hot.get_trigger_value());

    hot.try_set_query_parameters(vec!["1".to_string()])
        .expect("one parameter fits");
    assert!(hot.get_trigger_value(), "5 > 1 with the new parameter");
    let taken = reader.take_w_condition(&hot, usize::MAX).expect("take");
    assert_eq!(taken[0].0, Some(reading(1, 5)));

    // A parameter list that does not fit is refused and changes nothing.
    assert!(hot.try_set_query_parameters(vec![]).is_err());
    assert_eq!(hot.get_query_parameters(), vec!["1"]);
    assert_eq!(hot.get_query_expression(), "value > %0");
}

/// A QueryCondition never matches an instance-state transition: there is
/// no data to evaluate the query on.
#[test]
fn query_condition_ignores_transitions() {
    let (_writer, reader) = pair::<Instance>("cond-query-transition");
    let query = reader
        .create_querycondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
            "value > 0",
            vec![],
        )
        .expect("create");
    reader
        .dispose_queue_for_test()
        .push(disposed_event(3, DisposeKind::Disposed));
    assert!(!query.get_trigger_value());
    assert!(reader
        .take_w_condition(&query, usize::MAX)
        .expect("take")
        .is_empty());
    // The transition is still there for a plain condition.
    let plain = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    assert!(plain.get_trigger_value());
}

/// An expression that does not parse, or parameters that do not fit,
/// yield no condition (Sec.2.2.2.5.3.6, "nil").
#[test]
fn invalid_query_is_refused_at_creation() {
    let (_writer, reader) = pair::<Reading>("cond-query-invalid");
    assert!(matches!(
        reader.create_querycondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
            "value >>> 1",
            vec![],
        ),
        Err(Error::Config(_))
    ));
    assert!(matches!(
        reader.create_querycondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
            "value > %0",
            vec![],
        ),
        Err(Error::Config(_))
    ));
}

/// `max_samples` bounds the result and `read_w_condition` marks what it
/// returns.
#[test]
fn max_samples_bounds_read_and_take() {
    let (writer, reader) = pair::<Reading>("cond-max-samples");
    let cond = reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    for i in 0..5 {
        writer.write(&reading(i, i)).expect("write");
    }
    let first_two = reader.read_w_condition(&cond, 2).expect("read");
    assert_eq!(
        first_two
            .iter()
            .map(|(d, _)| d.as_ref().map(|d| d.id))
            .collect::<Vec<_>>(),
        vec![Some(0), Some(1)]
    );
    // Those two are READ now; the NOT_READ condition still has three.
    let taken = reader.take_w_condition(&cond, 2).expect("take");
    assert_eq!(
        taken
            .iter()
            .map(|(d, _)| d.as_ref().map(|d| d.id))
            .collect::<Vec<_>>(),
        vec![Some(2), Some(3)]
    );
    assert!(cond.get_trigger_value(), "id 4 is still unread");
    let taken = reader.take_w_condition(&cond, usize::MAX).expect("take");
    assert_eq!(taken.len(), 1);
    assert!(!cond.get_trigger_value());
    // The two READ samples are still in the reader.
    assert_eq!(reader.take_all().expect("take_all").len(), 2);
}

// ---------------------------------------------------------------------------
// Attachment preconditions (Sec.2.2.2.5.3.7, 2.2.2.5.3.10, 2.2.2.5.3.11)
// ---------------------------------------------------------------------------

#[test]
fn conditions_of_another_reader_and_deleted_conditions_are_refused() {
    let (writer_a, reader_a) = pair::<Reading>("cond-owner-a");
    let (_writer_b, reader_b) = pair::<Reading>("cond-owner-b");
    let cond_a = reader_a
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");

    assert!(matches!(
        reader_b.take_w_condition(&cond_a, usize::MAX),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        reader_b.read_w_condition(&cond_a, usize::MAX),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        reader_b.delete_readcondition(&cond_a),
        Err(Error::InvalidState(_))
    ));

    writer_a.write(&reading(1, 1)).expect("write");
    assert!(cond_a.get_trigger_value());
    assert!(cond_a.is_attached());

    reader_a.delete_readcondition(&cond_a).expect("delete");
    assert!(!cond_a.is_attached());
    assert!(!cond_a.get_trigger_value(), "a deleted condition is silent");
    assert!(matches!(
        reader_a.take_w_condition(&cond_a, usize::MAX),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        reader_a.delete_readcondition(&cond_a),
        Err(Error::InvalidState(_))
    ));
    // The sample is untouched.
    assert_eq!(reader_a.take().expect("take"), Some(reading(1, 1)));

    // A standalone condition was never attached to anything.
    #[allow(deprecated)]
    let loose = crate::dds::ReadCondition::new(
        SampleStateMask::ANY,
        ViewStateMask::ANY,
        InstanceStateMask::ANY,
    );
    assert!(matches!(
        reader_a.take_w_condition(&loose, usize::MAX),
        Err(Error::InvalidState(_))
    ));
}

/// The condition outlives the reader: its trigger is false and it does not
/// dangle.
#[test]
fn condition_survives_its_reader() {
    let (writer, reader) = pair::<Reading>("cond-outlives");
    let cond = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    writer.write(&reading(1, 1)).expect("write");
    assert!(cond.get_trigger_value());
    drop(reader);
    assert!(!cond.get_trigger_value());
}

// ---------------------------------------------------------------------------
// WaitSet wake path
// ---------------------------------------------------------------------------

const WAKE_TIMEOUT: Duration = Duration::from_secs(3);

/// A WaitSet blocked on a ReadCondition wakes when a matching sample
/// arrives, and returns that condition (Sec.2.2.4.4, 2.2.4.5).
#[test]
fn waitset_wakes_on_arrival_for_a_read_condition() {
    let (writer, reader) = pair::<Reading>("cond-waitset-read");
    let cond = reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ALIVE,
        )
        .expect("create");
    let waitset = WaitSet::new();
    waitset
        .attach_condition(cond.clone())
        .expect("attach_condition");

    // Nothing yet: a short wait times out.
    assert!(matches!(
        waitset.wait(Some(Duration::from_millis(50))),
        Err(Error::WouldBlock)
    ));

    let writer_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        writer.write(&reading(1, 1)).expect("write");
        writer
    });
    let start = Instant::now();
    let triggered = waitset
        .wait(Some(WAKE_TIMEOUT))
        .expect("the arrival must wake the WaitSet");
    assert!(
        start.elapsed() >= Duration::from_millis(50),
        "returned before the write could have happened"
    );
    assert_eq!(triggered.len(), 1);
    assert_eq!(triggered[0].condition_id(), cond.condition_id());
    let writer = writer_thread.join().expect("writer thread");

    let taken = reader.take_w_condition(&cond, usize::MAX).expect("take");
    assert_eq!(taken.len(), 1);

    // Taken: the WaitSet blocks again until the next arrival.
    assert!(matches!(
        waitset.wait(Some(Duration::from_millis(50))),
        Err(Error::WouldBlock)
    ));

    // A condition attached while already triggered returns at once.
    writer.write(&reading(2, 2)).expect("write");
    let triggered = waitset
        .wait(Some(WAKE_TIMEOUT))
        .expect("triggered condition is returned at once");
    assert_eq!(triggered[0].condition_id(), cond.condition_id());

    waitset.detach_condition(cond.clone()).expect("detach");
}

/// The "only then" half: a sample that does not satisfy the query wakes
/// the WaitSet internally but does not return to the application; the
/// matching one does.
#[test]
fn waitset_on_a_query_condition_returns_only_for_a_matching_sample() {
    let (writer, reader) = pair::<Reading>("cond-waitset-query");
    let hot = reader
        .create_querycondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ALIVE,
            "value > %0",
            vec!["100".to_string()],
        )
        .expect("create");
    let waitset = WaitSet::new();
    waitset
        .attach_condition(hot.clone())
        .expect("attach_condition");

    let writer_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        writer.write(&reading(1, 10)).expect("write cold");
        std::thread::sleep(Duration::from_millis(300));
        writer.write(&reading(2, 200)).expect("write hot");
        writer
    });

    let start = Instant::now();
    let triggered = waitset
        .wait(Some(WAKE_TIMEOUT))
        .expect("the hot sample must wake the WaitSet");
    let elapsed = start.elapsed();
    assert_eq!(triggered.len(), 1);
    assert_eq!(triggered[0].condition_id(), hot.condition_id());
    assert!(
        elapsed >= Duration::from_millis(300),
        "returned after {elapsed:?}: the cold sample must not end the wait"
    );
    let _writer = writer_thread.join().expect("writer thread");

    let taken = reader.take_w_condition(&hot, usize::MAX).expect("take");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].0, Some(reading(2, 200)));
    // The cold sample is still in the reader for a plain take.
    assert_eq!(reader.take().expect("take"), Some(reading(1, 10)));
}

/// A queued instance-state transition wakes a WaitSet on a NOT_ALIVE
/// condition through the same path (the dispose wake word).
#[test]
fn waitset_wakes_on_a_transition_for_a_not_alive_condition() {
    let (_writer, reader) = pair::<Instance>("cond-waitset-dispose");
    let disposed = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_DISPOSED,
        )
        .expect("create");
    let waitset = WaitSet::new();
    waitset
        .attach_condition(disposed.clone())
        .expect("attach_condition");

    let queue = Arc::clone(reader.dispose_queue_for_test());
    let pusher = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        queue.push(disposed_event(9, DisposeKind::Disposed));
    });
    let triggered = waitset
        .wait(Some(WAKE_TIMEOUT))
        .expect("the transition must wake the WaitSet");
    assert_eq!(triggered[0].condition_id(), disposed.condition_id());
    pusher.join().expect("pusher thread");

    let taken = reader
        .take_w_condition(&disposed, usize::MAX)
        .expect("take");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].1.instance_state, InstanceState::NotAliveDisposed);
}

/// Deleting a condition stops its wake-ups: a later arrival does not end
/// a wait on it.
#[test]
fn deleted_condition_no_longer_wakes_its_waitset() {
    let (writer, reader) = pair::<Reading>("cond-waitset-deleted");
    let cond = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    let waitset = WaitSet::new();
    waitset
        .attach_condition(cond.clone())
        .expect("attach_condition");
    reader.delete_readcondition(&cond).expect("delete");

    let writer_thread = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        writer.write(&reading(1, 1)).expect("write");
        writer
    });
    assert!(matches!(
        waitset.wait(Some(Duration::from_millis(300))),
        Err(Error::WouldBlock)
    ));
    let _writer = writer_thread.join().expect("writer thread");
    assert_eq!(reader.take().expect("take"), Some(reading(1, 1)));
}

// ---------------------------------------------------------------------------
// Registration versus concurrent destruction
// ---------------------------------------------------------------------------

/// Registering a second condition prunes the reader's arrival hooks under
/// their mutex. Pruning must not create a strong reference to another
/// condition: if that reference is the last one (the application dropped
/// its own on another thread meanwhile) the condition's drop runs
/// `detach`, which takes the same mutex on the same thread. The seam
/// parks the prune with the reference alive while a helper thread drops
/// the application's; a registration that survives is the pass, one that
/// never returns is the deadlock.
#[test]
fn registering_a_condition_survives_another_condition_dying_during_the_prune() {
    use std::sync::mpsc;

    let (_writer, reader) = pair::<Reading>("cond-prune-race");
    let first = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");

    let (drop_tx, drop_rx) = mpsc::channel::<Arc<crate::dds::ReadCondition>>();
    let (dropped_tx, dropped_rx) = mpsc::channel::<()>();
    let helper = std::thread::spawn(move || {
        if let Ok(condition) = drop_rx.recv() {
            drop(condition);
            let _ = dropped_tx.send(());
        }
    });
    reader
        .get_status_condition()
        .set_arrival_prune_hook(Box::new(move || {
            let _ = drop_tx.send(first);
            // With the defect the helper's drop is not the last reference
            // (the prune holds one) and returns at once; with the fix the
            // helper blocks on the mutex this thread holds until the
            // registration is done, and this bounded wait lets it.
            let _ = dropped_rx.recv_timeout(Duration::from_millis(300));
        }));

    let (done_tx, done_rx) = mpsc::channel();
    let registrar = {
        let reader = Arc::clone(&reader);
        std::thread::spawn(move || {
            let second = reader
                .create_readcondition(
                    SampleStateMask::ANY,
                    ViewStateMask::ANY,
                    InstanceStateMask::ANY,
                )
                .expect("create");
            let _ = done_tx.send(second.is_attached());
        })
    };
    let attached = done_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("registering a condition deadlocked while another one died in the prune");
    assert!(attached);
    registrar.join().expect("registrar thread");
    helper.join().expect("helper thread");
}

// ---------------------------------------------------------------------------
// Several WaitSets on one reader (Sec.2.2.4.5 contemplates them)
// ---------------------------------------------------------------------------

/// Two WaitSets on two threads each evaluate a condition of the same
/// reader and take through it. The evaluation pumps the reader's rings,
/// and the ring is single-consumer: without serialization two evaluations
/// pop it concurrently, and samples are duplicated or lost. Every written
/// sample must come out exactly once across both threads.
#[test]
fn two_waitsets_on_one_reader_take_every_sample_exactly_once() {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    const SAMPLES: i32 = 4000;

    // Deep history: the point is the consumers, not KEEP_LAST eviction
    // during a burst the consumers have not drained yet.
    let (writer, reader) = pair_with_depth::<Reading>("cond-two-waitsets", 8192);
    let stop = Arc::new(AtomicBool::new(false));

    let consumer = |name: &'static str| {
        let reader = Arc::clone(&reader);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let cond = reader
                .create_readcondition(
                    SampleStateMask::NOT_READ,
                    ViewStateMask::ANY,
                    InstanceStateMask::ALIVE,
                )
                .expect("create");
            let waitset = WaitSet::new();
            waitset
                .attach_condition(cond.clone())
                .expect("attach_condition");
            let mut seen: Vec<i32> = Vec::new();
            loop {
                match waitset.wait(Some(Duration::from_millis(20))) {
                    Ok(_) | Err(Error::WouldBlock) => {}
                    Err(err) => panic!("{name}: wait failed: {err:?}"),
                }
                for (data, _) in reader
                    .take_w_condition(&cond, usize::MAX)
                    .expect("take_w_condition")
                {
                    seen.push(data.expect("data sample").id);
                }
                if stop.load(Ordering::Acquire) {
                    // One last drain after the writer is done.
                    for (data, _) in reader
                        .take_w_condition(&cond, usize::MAX)
                        .expect("take_w_condition")
                    {
                        seen.push(data.expect("data sample").id);
                    }
                    return seen;
                }
            }
        })
    };
    let a = consumer("a");
    let b = consumer("b");

    for i in 0..SAMPLES {
        writer.write(&reading(i, i)).expect("write");
        if i % 64 == 0 {
            std::thread::yield_now();
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Release);

    let mut counts: BTreeMap<i32, usize> = BTreeMap::new();
    for id in a
        .join()
        .expect("consumer a")
        .into_iter()
        .chain(b.join().expect("consumer b"))
    {
        *counts.entry(id).or_default() += 1;
    }
    let duplicated: Vec<i32> = counts
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(id, _)| *id)
        .collect();
    let lost: Vec<i32> = (0..SAMPLES).filter(|id| !counts.contains_key(id)).collect();
    assert!(
        duplicated.is_empty() && lost.is_empty(),
        "duplicated {} sample(s) {:?}, lost {} sample(s) {:?}",
        duplicated.len(),
        &duplicated[..duplicated.len().min(8)],
        lost.len(),
        &lost[..lost.len().min(8)]
    );
}

/// One thread waits on a WaitSet holding a ReadCondition of the reader
/// while another thread drains the reader with the ordinary `take()`:
/// the usual "one thread blocks, one thread consumes" DDS pattern. The
/// condition's evaluation pumps the reader's single-consumer rings; the
/// ordinary take pops the same rings. Unless the two pops are mutually
/// exclusive they are two consumers of one SPSC ring and samples are
/// duplicated or lost. Every written sample must come out of `take()`
/// exactly once.
#[test]
fn a_waitset_evaluating_a_condition_and_a_thread_calling_take_share_one_consumer() {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};

    const SAMPLES: i32 = 4000;

    // Deep history: the point is the consumers, not KEEP_LAST eviction
    // during a burst the consumer has not drained yet.
    let (writer, reader) = pair_with_depth::<Reading>("cond-waiter-and-taker", 8192);
    let stop = Arc::new(AtomicBool::new(false));

    let waiter = {
        let reader = Arc::clone(&reader);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let cond = reader
                .create_readcondition(
                    SampleStateMask::NOT_READ,
                    ViewStateMask::ANY,
                    InstanceStateMask::ALIVE,
                )
                .expect("create");
            let waitset = WaitSet::new();
            waitset
                .attach_condition(cond.clone())
                .expect("attach_condition");
            let mut wakeups: usize = 0;
            while !stop.load(Ordering::Acquire) {
                // Each wait re-evaluates the trigger (pumping the rings);
                // this thread never takes, it only observes.
                match waitset.wait(Some(Duration::from_millis(1))) {
                    Ok(_) => wakeups += 1,
                    Err(Error::WouldBlock) => {}
                    Err(err) => panic!("waiter: wait failed: {err:?}"),
                }
                let _ = cond.get_trigger_value();
            }
            wakeups
        })
    };
    let taker = {
        let reader = Arc::clone(&reader);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut seen: Vec<i32> = Vec::new();
            loop {
                while let Some(sample) = reader.take().expect("take") {
                    seen.push(sample.id);
                }
                if stop.load(Ordering::Acquire) {
                    while let Some(sample) = reader.take().expect("take") {
                        seen.push(sample.id);
                    }
                    return seen;
                }
                std::thread::yield_now();
            }
        })
    };

    for i in 0..SAMPLES {
        writer.write(&reading(i, i)).expect("write");
        if i % 64 == 0 {
            std::thread::yield_now();
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Release);
    let _wakeups = waiter.join().expect("waiter");

    let mut counts: BTreeMap<i32, usize> = BTreeMap::new();
    for id in taker.join().expect("taker") {
        *counts.entry(id).or_default() += 1;
    }
    let duplicated: Vec<i32> = counts
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(id, _)| *id)
        .collect();
    let lost: Vec<i32> = (0..SAMPLES).filter(|id| !counts.contains_key(id)).collect();
    assert!(
        duplicated.is_empty() && lost.is_empty(),
        "duplicated {} sample(s) {:?}, lost {} sample(s) {:?}",
        duplicated.len(),
        &duplicated[..duplicated.len().min(8)],
        lost.len(),
        &lost[..lost.len().min(8)]
    );
}

// ---------------------------------------------------------------------------
// Parameter changes wake a blocked WaitSet
// ---------------------------------------------------------------------------

/// A sample the query rejects is in the reader and a WaitSet is blocked
/// on the QueryCondition. Changing the parameters so the sample now
/// satisfies the query changes the trigger (Sec.2.2.4.5), so the blocked
/// wait must return without another arrival.
#[test]
fn changing_query_parameters_wakes_a_blocked_waitset() {
    let (writer, reader) = pair::<Reading>("cond-params-wake");
    let hot = reader
        .create_querycondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
            "value > %0",
            vec!["10".to_string()],
        )
        .expect("create");
    let waitset = WaitSet::new();
    waitset
        .attach_condition(hot.clone())
        .expect("attach_condition");

    writer.write(&reading(1, 5)).expect("write");
    assert!(!hot.get_trigger_value(), "5 > 10 is false");
    assert!(matches!(
        waitset.wait(Some(Duration::from_millis(50))),
        Err(Error::WouldBlock)
    ));

    let setter = {
        let hot = Arc::clone(&hot);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            hot.try_set_query_parameters(vec!["0".to_string()])
                .expect("one parameter fits");
        })
    };
    let start = Instant::now();
    let triggered = waitset
        .wait(Some(WAKE_TIMEOUT))
        .expect("the parameter change must wake the WaitSet");
    assert!(start.elapsed() >= Duration::from_millis(50));
    assert_eq!(triggered.len(), 1);
    assert_eq!(triggered[0].condition_id(), hot.condition_id());
    setter.join().expect("setter thread");
    let taken = reader.take_w_condition(&hot, usize::MAX).expect("take");
    assert_eq!(taken.len(), 1);
}

// ---------------------------------------------------------------------------
// View state is one snapshot per instance within a call (Sec.2.2.2.5.1.8)
// ---------------------------------------------------------------------------

/// Two unread samples of an instance the reader never handed out, taken
/// with a NEW-only condition and max 2: both belong to the collection and
/// both report NEW. The instance turns NOT_NEW after the call, not after
/// the first sample of it. Same for read_w_condition.
#[test]
fn a_batch_reports_one_view_state_per_instance() {
    let (writer, reader) = pair::<Instance>("cond-view-snapshot");
    let new_only = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");
    writer
        .write(&Instance { key: 1, value: 10 })
        .expect("write");
    writer
        .write(&Instance { key: 1, value: 11 })
        .expect("write");

    let read = reader.read_w_condition(&new_only, 2).expect("read");
    assert_eq!(read.len(), 2, "both samples of the NEW instance are read");
    assert!(read
        .iter()
        .all(|(_, info)| info.view_state == ViewState::New));
    assert!(
        !new_only.get_trigger_value(),
        "after the call the instance is NOT_NEW"
    );

    writer
        .write(&Instance { key: 2, value: 20 })
        .expect("write");
    writer
        .write(&Instance { key: 2, value: 21 })
        .expect("write");
    let taken = reader.take_w_condition(&new_only, 2).expect("take");
    assert_eq!(taken.len(), 2, "both samples of the NEW instance are taken");
    assert!(taken
        .iter()
        .all(|(_, info)| info.view_state == ViewState::New));
    assert!(!new_only.get_trigger_value());
}

// ---------------------------------------------------------------------------
// Instance state is the CURRENT state of the instance (Sec.2.2.2.5.1.3)
// ---------------------------------------------------------------------------

fn key_hash_of(key: i64) -> [u8; 16] {
    Instance { key, value: 0 }.compute_key()
}

fn transition_for(key: i64, kind: DisposeKind, writer: Option<[u8; 16]>, seq: u64) -> DisposeEvent {
    DisposeEvent {
        key_hash: key_hash_of(key),
        kind,
        seq,
        writer_guid: writer,
        order_seq: seq,
        announced: false,
        read: false,
        from_local_writer: false,
        disposed_generation_count: 0,
        no_writers_generation_count: 0,
        source_timestamp_ns: None,
    }
}

/// After a dispose, the retained data samples of the instance report
/// NOT_ALIVE_DISPOSED, match a NOT_ALIVE_DISPOSED condition and no longer
/// match an ALIVE one.
#[test]
fn disposed_instance_reports_not_alive_on_its_retained_samples() {
    let (writer, reader) = pair::<Instance>("cond-instance-state-disposed");
    let alive = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ALIVE,
        )
        .expect("create");
    let disposed = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_DISPOSED,
        )
        .expect("create");

    writer
        .write(&Instance { key: 1, value: 10 })
        .expect("write");
    assert!(alive.get_trigger_value());
    reader
        .dispose_queue_for_test()
        .push(transition_for(1, DisposeKind::Disposed, None, 7));

    assert!(
        !alive.get_trigger_value(),
        "the instance is not ALIVE any more"
    );
    assert!(
        reader
            .take_w_condition(&alive, usize::MAX)
            .expect("take")
            .is_empty(),
        "an ALIVE condition must not take a sample of a disposed instance"
    );
    assert!(disposed.get_trigger_value());
    let taken = reader
        .take_w_condition(&disposed, usize::MAX)
        .expect("take");
    assert_eq!(taken.len(), 2, "the retained sample and the transition");
    assert!(taken
        .iter()
        .all(|(_, info)| info.instance_state == InstanceState::NotAliveDisposed));
    assert!(taken
        .iter()
        .any(|(data, info)| data.is_some() && info.valid_data));
    assert!(taken
        .iter()
        .any(|(data, info)| data.is_none() && !info.valid_data));
}

/// Same for an unregister: NOT_ALIVE_NO_WRITERS.
#[test]
fn unregistered_instance_reports_no_writers_on_its_retained_samples() {
    let (writer, reader) = pair::<Instance>("cond-instance-state-nowriters");
    let no_writers = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_NO_WRITERS,
        )
        .expect("create");
    writer
        .write(&Instance { key: 3, value: 30 })
        .expect("write");
    assert!(!no_writers.get_trigger_value());
    reader
        .dispose_queue_for_test()
        .push(transition_for(3, DisposeKind::Unregistered, None, 2));
    assert!(no_writers.get_trigger_value());
    let taken = reader
        .take_w_condition(&no_writers, usize::MAX)
        .expect("take");
    assert_eq!(taken.len(), 2);
    assert!(taken
        .iter()
        .all(|(_, info)| info.instance_state == InstanceState::NotAliveNoWriters));
    // take_with_info reports the same current state on a data sample.
    writer
        .write(&Instance { key: 4, value: 40 })
        .expect("write");
    reader
        .dispose_queue_for_test()
        .push(transition_for(4, DisposeKind::Unregistered, None, 3));
    let (_, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("a sample");
    assert_eq!(info.instance_state, InstanceState::NotAliveNoWriters);
}

/// A sample received after the instance went NOT_ALIVE makes it ALIVE
/// again and the instance is NEW again (Sec.2.2.2.5.1.8: reborn). A
/// sample the same writer sent BEFORE its dispose does not revive it.
#[test]
fn a_sample_after_not_alive_revives_the_instance_as_new() {
    use super::cache::CachedSample;

    let (writer, reader) = pair::<Instance>("cond-instance-reborn");
    let new_only = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");

    writer
        .write(&Instance { key: 5, value: 50 })
        .expect("write");
    let (_, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("a sample");
    assert_eq!(info.view_state, ViewState::New);
    writer
        .write(&Instance { key: 5, value: 51 })
        .expect("write");
    let (_, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("a sample");
    assert_eq!(info.view_state, ViewState::NotNew);
    assert!(!new_only.get_trigger_value());

    let writer_guid = [0x11u8; 16];
    reader.dispose_queue_for_test().push(transition_for(
        5,
        DisposeKind::Disposed,
        Some(writer_guid),
        10,
    ));
    // Consume the transition.
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the transition");
    assert!(data.is_none());
    assert_eq!(info.instance_state, InstanceState::NotAliveDisposed);

    // A sample of the same writer that precedes the dispose in its
    // sequence does not revive the instance.
    reader.cache().push(CachedSample::with_meta(
        Instance { key: 5, value: 52 },
        5,
        1,
        crate::dds::InstanceHandle::new(key_hash_of(5)),
        Some(writer_guid),
        false,
    ));
    let (_, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the stale sample");
    assert_eq!(
        info.instance_state,
        InstanceState::NotAliveDisposed,
        "sent before the dispose: the instance stays disposed"
    );
    assert_eq!(info.view_state, ViewState::NotNew);

    // A later sample revives it: ALIVE and NEW again.
    writer
        .write(&Instance { key: 5, value: 53 })
        .expect("write");
    assert!(new_only.get_trigger_value(), "reborn instance is NEW");
    let (_, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the reborn sample");
    assert_eq!(info.instance_state, InstanceState::Alive);
    assert_eq!(info.view_state, ViewState::New);
    assert!(!new_only.get_trigger_value());
}

// ---------------------------------------------------------------------------
// What triggers is readable (Sec.2.2.2.5.3.10)
// ---------------------------------------------------------------------------

/// A NOT_ALIVE condition triggers on a queued transition, so
/// read_w_condition must return that transition, as `(None, info)` with
/// `valid_data == false`, without consuming it: a NOT_READ-only condition
/// stops matching it once read, a READ-admitting one returns it again,
/// and take_w_condition still takes it afterwards.
#[test]
fn read_w_condition_reads_a_transition_in_place() {
    let (_writer, reader) = pair::<Instance>("cond-read-transition");
    let unread_disposed = reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_DISPOSED,
        )
        .expect("create");
    let any_disposed = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::NOT_ALIVE_DISPOSED,
        )
        .expect("create");
    reader
        .dispose_queue_for_test()
        .push(transition_for(8, DisposeKind::Disposed, None, 4));
    assert!(unread_disposed.get_trigger_value());

    let read = reader
        .read_w_condition(&unread_disposed, usize::MAX)
        .expect("read");
    assert_eq!(read.len(), 1, "what triggers is readable");
    let (data, info) = &read[0];
    assert!(data.is_none());
    assert!(!info.valid_data);
    assert_eq!(info.instance_state, InstanceState::NotAliveDisposed);
    assert_eq!(info.sample_state, SampleState::NotRead);

    assert!(
        !unread_disposed.get_trigger_value(),
        "read in place: the transition is READ now"
    );
    assert!(any_disposed.get_trigger_value(), "and still there");
    let again = reader
        .read_w_condition(&any_disposed, usize::MAX)
        .expect("read");
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].1.sample_state, SampleState::Read);

    let taken = reader
        .take_w_condition(&any_disposed, usize::MAX)
        .expect("take");
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].1.sample_state, SampleState::Read);
    assert!(!any_disposed.get_trigger_value());
}

// ---------------------------------------------------------------------------
// Conditional take merges data and transitions by origin (Sec.2.2.2.5.3.11)
// ---------------------------------------------------------------------------

/// A transition and the data around it come out in the order their
/// writer sent them, exactly as `take_with_info` orders them: a dispose
/// queued before a later write of the same writer precedes that write and
/// follows the earlier one; facing data of another (or an unknown)
/// writer, the transition goes first. A bounded take honours the same
/// order, so a transition is never starved behind data.
#[test]
fn conditional_take_orders_transitions_among_the_data() {
    use super::cache::CachedSample;
    use crate::dds::InstanceHandle;

    let (writer, reader) = pair::<Instance>("cond-take-order");
    let any = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");

    // Data of an unknown writer, then a transition: the transition is not
    // held back by it, and a take bounded to one sample returns it first.
    writer
        .write(&Instance { key: 20, value: 1 })
        .expect("write");
    reader
        .dispose_queue_for_test()
        .push(transition_for(21, DisposeKind::Disposed, None, 9));
    let first = reader.take_w_condition(&any, 1).expect("take");
    assert_eq!(first.len(), 1);
    assert!(
        first[0].0.is_none(),
        "the transition comes first, a bounded take does not starve it"
    );
    let rest = reader.take_w_condition(&any, usize::MAX).expect("take");
    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].0, Some(Instance { key: 20, value: 1 }));

    // Same writer: sequence order decides. Dispose at 5, samples at 3
    // (before) and 7 (after, which revives the instance).
    let guid = [0x22u8; 16];
    let handle = InstanceHandle::new(key_hash_of(22));
    reader
        .dispose_queue_for_test()
        .push(transition_for(22, DisposeKind::Disposed, Some(guid), 5));
    for (seq, value) in [(3u64, 3i64), (7, 7)] {
        reader.cache().push(CachedSample::with_meta(
            Instance { key: 22, value },
            seq,
            seq,
            handle,
            Some(guid),
            false,
        ));
    }
    let taken = reader.take_w_condition(&any, usize::MAX).expect("take");
    let order: Vec<Option<i64>> = taken.iter().map(|(d, _)| d.map(|d| d.value)).collect();
    assert_eq!(
        order,
        vec![Some(3), None, Some(7)],
        "the writer's sequence order: 3, dispose, 7"
    );
    // One view-state snapshot for the instance across the collection.
    assert!(taken
        .iter()
        .all(|(_, info)| info.view_state == ViewState::New));
}

// ---------------------------------------------------------------------------
// The deprecated try_take is an access too (Sec.2.2.2.5.3.9)
// ---------------------------------------------------------------------------

/// Taking the first sample of an instance through the legacy `try_take`
/// makes the instance NOT_NEW like every other accessor: the next sample
/// of it must not trigger a NEW-only condition.
#[test]
#[allow(deprecated)]
fn try_take_records_the_instance_as_viewed() {
    let (writer, reader) = pair::<Instance>("cond-try-take-view");
    let new_only = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");
    writer
        .write(&Instance { key: 30, value: 1 })
        .expect("write");
    assert_eq!(
        reader.try_take().expect("try_take"),
        Some(Instance { key: 30, value: 1 })
    );
    writer
        .write(&Instance { key: 30, value: 2 })
        .expect("write");
    assert!(
        !new_only.get_trigger_value(),
        "instance 30 was handed out by try_take: NOT_NEW"
    );
}

// ---------------------------------------------------------------------------
// A key-only dispose off the wire keeps its writerSN (RTPS v2.5 Sec.8.3.8.2)
// ---------------------------------------------------------------------------

/// A remote writer disposes an instance with a key-only DATA (K flag), then
/// repairs a sample it sent BEFORE that dispose. The repair arrives after the
/// dispose was processed; it was sent before it, so it does not revive the
/// instance (DDS v1.4 Sec.2.2.2.5.1.3: ALIVE again only when samples are
/// received that were written after the dispose). The reader can tell only
/// if the dispose reaches it under its own sequence number: delivered as 0,
/// it sat before every sample of the writer and the repair revived it.
#[test]
fn a_repair_sent_before_a_k_flag_dispose_does_not_revive_the_instance() {
    use crate::engine::{route_data_packet, RouteStatus, RouterMetrics, Subscriber, TopicRegistry};

    const TOPIC: &str = "cond-k-dispose-repair";
    let writer_guid: [u8; 16] = [
        0x01, 0x03, 0x4b, 0x7d, 0x04, 0xd6, 0x00, 0x0e, 0x5c, 0x5d, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x02,
    ];
    let _ = rt::init_slab_pool();
    let reader = Arc::new(
        ReaderBuilder::<Instance>::new(TOPIC.to_string())
            .qos(QoS::reliable().keep_last(16))
            .network_ring_for_test()
            .build()
            .expect("reader build should succeed"),
    );
    let network_ring = Arc::clone(reader.network_ring_for_test().expect("network ring"));
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Instance>::new(
            TOPIC.to_string(),
            network_ring,
            reader.get_status_condition(),
            None,
            None,
            None,
            Arc::clone(reader.dispose_queue_for_test()),
            Arc::new(std::sync::Mutex::new(super::reorder::ReorderGate::new(
                false, false,
            ))),
        )
        .with_room(reader.network_room_for_test().cloned()),
    );
    let encoded = |value: i64| {
        let mut buf = vec![0u8; 64];
        let len = Instance { key: 5, value }
            .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
            .expect("encode");
        buf.truncate(len);
        buf
    };

    // Sample 9 of the writer: the instance is alive and the reader knows
    // which writer delivers it.
    sub.on_data_with_writer(
        TOPIC,
        writer_guid,
        9,
        &encoded(9),
        crate::dds::CdrVersion::Xcdr2,
    );
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("sample 9");
    assert_eq!(data, Some(Instance { key: 5, value: 9 }));
    assert_eq!(info.instance_state, InstanceState::Alive);

    // Change 11: a key-only dispose (RTPS v2.5 Sec.9.4.5.3, D=0 K=1 Q=1)
    // with StatusInfo D (Sec.9.6.4.9), the KeyHash (Sec.9.6.4.8) and the
    // serialized key, little-endian.
    let key_hash = key_hash_of(5);
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]); // extraFlags
    body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    body.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
    body.extend_from_slice(&writer_guid[12..]);
    body.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
    body.extend_from_slice(&11u32.to_le_bytes()); // writerSN low
    body.extend_from_slice(&[0x71, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01]);
    body.extend_from_slice(&[0x70, 0x00, 0x10, 0x00]);
    body.extend_from_slice(&key_hash);
    body.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // PID_SENTINEL
    body.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // CDR_LE
    body.extend_from_slice(&5i64.to_le_bytes());
    let mut packet = Vec::new();
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 5, 0x01, 0x03]);
    packet.extend_from_slice(&writer_guid[..12]);
    packet.extend_from_slice(&[0x15, 0x0b]);
    packet.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_le_bytes());
    packet.extend_from_slice(&body);
    assert_eq!(
        crate::protocol::builder::extract_sequence_number(&packet),
        Some(11)
    );

    let registry = TopicRegistry::new();
    registry
        .register_subscriber(Arc::clone(&sub) as Arc<dyn Subscriber>)
        .expect("register subscriber");
    registry.register_writer_guid(writer_guid, TOPIC.to_string());
    assert_eq!(
        route_data_packet(
            &packet,
            packet.len(),
            None,
            &registry,
            &RouterMetrics::new()
        ),
        RouteStatus::Delivered
    );

    // The repair of sample 10 arrives after the dispose was processed.
    sub.on_data_with_writer(
        TOPIC,
        writer_guid,
        10,
        &encoded(10),
        crate::dds::CdrVersion::Xcdr2,
    );

    let mut transition = None;
    let mut repair = None;
    while let Some((data, info)) = reader.take_with_info().expect("take_with_info") {
        match data {
            None => transition = Some(info),
            Some(sample) => {
                assert_eq!(sample, Instance { key: 5, value: 10 });
                repair = Some(info);
            }
        }
    }
    let repair = repair.expect("the repaired sample is delivered");
    assert_eq!(
        repair.instance_state,
        InstanceState::NotAliveDisposed,
        "sample 10 was sent before dispose 11: the instance stays disposed"
    );
    let transition = transition.expect("the dispose is delivered");
    assert_eq!(transition.sequence_number, 11, "the dispose is change 11");
    assert_eq!(
        reader.take_with_info().expect("take_with_info"),
        None,
        "nothing revived it behind the repair"
    );
}

fn deadline_participant(
    name: &str,
) -> (
    Arc<crate::Participant>,
    Arc<crate::dds::liveliness::ManualClock>,
) {
    let clock = Arc::new(crate::dds::liveliness::ManualClock::new(0));
    let mut builder = crate::Participant::builder(name)
        .domain_id(160)
        .with_transport(crate::TransportMode::IntraProcess);
    builder.liveliness_clock = Some(clock.clone());
    (builder.build().expect("participant"), clock)
}

/// REQUESTED_DEADLINE_MISSED (DDS v1.4 Sec.2.2.2.5.3.22): a reader with a
/// finite deadline and no further samples reports every elapsed period
/// (Sec.2.2.4.1), read-and-reset like `get_sample_rejected_status`
/// (Sec.2.2.4.2.1), and raises/clears `StatusMask::REQUESTED_DEADLINE_MISSED`
/// on its StatusCondition because no listener is installed.
#[test]
fn requested_deadline_missed_status_reads_and_resets_and_raises_condition() {
    let (participant, clock) = deadline_participant("requested_deadline_missed");
    let topic = participant
        .topic::<Reading>("requested_deadline_missed")
        .expect("topic");
    let qos = QoS::best_effort()
        .keep_last(4)
        .deadline(Deadline::from_millis(20));
    let writer = topic.writer().qos(qos.clone()).build().expect("writer");
    let reader = topic.reader().qos(qos).build().expect("reader");

    // DDS v1.4 Sec.2.2.3.7: reception starts the instance's period.
    writer.write(&reading(1, 1)).expect("write");
    assert_eq!(reader.take().expect("take"), Some(reading(1, 1)));
    let first = reader.get_requested_deadline_missed_status();
    assert_eq!(
        first.total_count, 0,
        "a sample just arrived: nothing missed"
    );
    let condition = reader.get_status_condition();
    condition.set_enabled_statuses(StatusMask::REQUESTED_DEADLINE_MISSED);
    assert!(
        !condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_DEADLINE_MISSED),
        "nothing to raise yet"
    );

    clock.advance(Duration::from_millis(60));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert_eq!(reader.take().expect("take"), None, "still nothing received");
    assert!(
        condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_DEADLINE_MISSED),
        "no listener is installed: the miss must raise the condition"
    );

    let status = reader.get_requested_deadline_missed_status();
    assert_eq!(status.total_count, 3, "three deadline periods elapsed");
    assert_eq!(status.total_count_change, 3);
    assert!(
        !condition
            .get_active_statuses()
            .contains(StatusMask::REQUESTED_DEADLINE_MISSED),
        "the getter must clear the condition it just read"
    );

    let second = reader.get_requested_deadline_missed_status();
    assert_eq!(
        second.total_count, 3,
        "total_count is cumulative, unaffected by the read"
    );
    assert_eq!(
        second.total_count_change, 0,
        "the change resets to 0 on read, DDS v1.4 Sec.2.2.4.2.1"
    );
}

/// OFFERED_DEADLINE_MISSED (DDS v1.4 Sec.2.2.2.4.2.17): writer-side mirror of
/// `requested_deadline_missed_status_reads_and_resets_and_raises_condition`.
#[test]
fn offered_deadline_missed_status_reads_and_resets_and_raises_condition() {
    let (participant, clock) = deadline_participant("offered_deadline_missed");
    let topic = participant
        .topic::<Reading>("offered_deadline_missed")
        .expect("topic");
    let writer = topic
        .writer()
        .qos(QoS::best_effort().deadline(Deadline::from_millis(20)))
        .build()
        .expect("writer");

    // First write(): no "last" instant yet, so no miss is possible.
    writer.write(&reading(1, 1)).expect("write");
    let first = writer.get_offered_deadline_missed_status();
    assert_eq!(first.total_count, 0);
    let condition = writer.get_status_condition();
    condition.set_enabled_statuses(StatusMask::OFFERED_DEADLINE_MISSED);

    clock.advance(Duration::from_millis(60));
    participant.liveliness.as_ref().unwrap().shared().settle();
    assert!(
        condition
            .get_active_statuses()
            .contains(StatusMask::OFFERED_DEADLINE_MISSED),
        "no listener is installed: the miss must raise the condition"
    );

    let status = writer.get_offered_deadline_missed_status();
    assert_eq!(status.total_count, 3);
    assert_eq!(status.total_count_change, 3);
    assert!(
        !condition
            .get_active_statuses()
            .contains(StatusMask::OFFERED_DEADLINE_MISSED),
        "the getter must clear the condition it just read"
    );

    let second = writer.get_offered_deadline_missed_status();
    assert_eq!(second.total_count, 3);
    assert_eq!(second.total_count_change, 0);
}

/// DDS v1.4 Sec.2.2.2.5.1.5-6: ranks combine both receipt counters,
/// are per instance, and distinguish the returned subset from the full
/// received history. Read and take use the same rule.
#[test]
fn generation_ranks_use_both_counters_and_the_returned_collection() {
    use super::cache::{CachedSample, InstanceHandle};
    for take in [false, true] {
        let reader = Arc::new(
            ReaderBuilder::<Instance>::new(format!("generation-ranks-{take}"))
                .qos(QoS::best_effort().keep_last(16))
                .build()
                .expect("reader"),
        );
        let handle = InstanceHandle::new(key_hash_of(1));
        let other = InstanceHandle::new(key_hash_of(2));
        let cache = reader.cache();
        let push = |value, seq, handle| {
            cache.push(CachedSample::with_instance(
                Instance {
                    key: if handle == other { 2 } else { 1 },
                    value,
                },
                seq,
                0,
                handle,
            ))
        };
        push(10, 1, handle);
        push(20, 2, other);
        cache
            .instances()
            .mark_not_alive(handle, InstanceState::NotAliveDisposed, (None, 3));
        push(11, 4, handle);
        cache
            .instances()
            .mark_not_alive(handle, InstanceState::NotAliveNoWriters, (None, 5));
        push(12, 6, handle);
        let condition = reader
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("condition");
        let samples = if take {
            reader.take_w_condition(&condition, 3)
        } else {
            reader.read_w_condition(&condition, 3)
        }
        .expect("access");
        assert_eq!(samples.len(), 3);
        let ranks: Vec<_> = samples
            .iter()
            .map(|(_, info)| {
                (
                    info.sample_rank,
                    info.generation_rank,
                    info.absolute_generation_rank,
                )
            })
            .collect();
        assert_eq!(ranks, vec![(1, 1, 2), (0, 0, 0), (0, 0, 1)]);
        assert_eq!(samples[2].1.disposed_generation_count, 1);
        assert_eq!(samples[2].1.no_writers_generation_count, 0);
        let full = reader
            .read_w_condition(&condition, usize::MAX)
            .expect("full read");
        if !take {
            let ranks: Vec<_> = full
                .iter()
                .map(|(_, info)| {
                    (
                        info.sample_rank,
                        info.generation_rank,
                        info.absolute_generation_rank,
                    )
                })
                .collect();
            assert_eq!(ranks, vec![(2, 2, 2), (0, 0, 0), (1, 1, 1), (0, 0, 0)]);
        }
    }
}

/// Single-sample take has zero collection ranks, but its absolute rank
/// still observes newer received generations of the same instance.
#[test]
fn single_sample_absolute_generation_rank_uses_both_counters() {
    use super::cache::{CachedSample, InstanceHandle};
    let reader = ReaderBuilder::<Reading>::new("single-generation-rank".into())
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .expect("reader");
    let cache = reader.cache();
    let handle = InstanceHandle::nil();
    cache.push(CachedSample::new(reading(1, 10), 1, 0));
    cache
        .instances()
        .mark_not_alive(handle, InstanceState::NotAliveDisposed, (None, 2));
    cache.push(CachedSample::new(reading(1, 11), 3, 0));
    cache
        .instances()
        .mark_not_alive(handle, InstanceState::NotAliveNoWriters, (None, 4));
    cache.push(CachedSample::new(reading(1, 12), 5, 0));
    let (_, info) = reader.take_with_info().expect("take").expect("sample");
    assert_eq!(
        (
            info.disposed_generation_count,
            info.no_writers_generation_count
        ),
        (0, 0)
    );
    assert_eq!(
        (
            info.sample_rank,
            info.generation_rank,
            info.absolute_generation_rank
        ),
        (0, 0, 2)
    );
}

/// Lifecycle notifications retain the generation they announced even
/// when the instance was revived before the application accessed them.
#[test]
fn a_transitions_disposed_generation_count_is_stamped_at_its_own_receipt() {
    use super::cache::{CachedSample, InstanceHandle};
    let reader = ReaderBuilder::<Instance>::new("transition-disposed-generation".into())
        .qos(QoS::best_effort().keep_last(16))
        .build()
        .expect("reader");
    let cache = reader.cache();
    let handle = InstanceHandle::new(key_hash_of(1));
    reader
        .dispose_queue_for_test()
        .push(transition_for(1, DisposeKind::Disposed, None, 1));
    cache.push(CachedSample::with_instance(
        Instance { key: 1, value: 1 },
        2,
        0,
        handle,
    ));
    let first = reader
        .dispose_queue_for_test()
        .pop_one()
        .expect("first event");
    assert_eq!(first.disposed_generation_count, 0);
    reader
        .dispose_queue_for_test()
        .push(transition_for(1, DisposeKind::Disposed, None, 3));
    cache.push(CachedSample::with_instance(
        Instance { key: 1, value: 2 },
        4,
        0,
        handle,
    ));
    let second = reader
        .dispose_queue_for_test()
        .pop_one()
        .expect("second event");
    let info = reader.instance_notification_info(&second);
    assert_eq!(info.disposed_generation_count, 1);
    assert_eq!(info.no_writers_generation_count, 0);
    assert_eq!(info.absolute_generation_rank, 1);
}

/// PRESENTATION does not require collection order to be reception order.
/// MRSIC means the newest received generation in the returned subset,
/// even when a newer lifecycle sample is returned ahead of older data.
#[test]
fn generation_rank_uses_newest_returned_generation_in_an_unordered_collection() {
    use super::cache::{CachedSample, InstanceHandle};
    let reader = Arc::new(
        ReaderBuilder::<Instance>::new("unordered-generation-rank".into())
            .qos(QoS::best_effort().keep_last(16))
            .build()
            .expect("reader"),
    );
    let cache = reader.cache();
    let handle = InstanceHandle::new(key_hash_of(1));
    cache.push(CachedSample::with_instance(
        Instance { key: 1, value: 10 },
        1,
        0,
        handle,
    ));
    cache
        .instances()
        .mark_not_alive(handle, InstanceState::NotAliveDisposed, (None, 2));
    cache.push(CachedSample::with_instance(
        Instance { key: 1, value: 11 },
        3,
        0,
        handle,
    ));
    reader
        .dispose_queue_for_test()
        .push(transition_for(1, DisposeKind::Disposed, None, 4));
    let condition = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let samples = reader.take_w_condition(&condition, 2).expect("take");
    assert_eq!(samples.len(), 2);
    assert!(
        samples[0].0.is_none(),
        "the unattributed transition is returned first"
    );
    assert_eq!(samples[1].0.as_ref().map(|v| v.value), Some(10));
    let ranks: Vec<_> = samples
        .iter()
        .map(|(_, info)| {
            (
                info.sample_rank,
                info.generation_rank,
                info.absolute_generation_rank,
            )
        })
        .collect();
    assert_eq!(ranks, vec![(1, 0, 0), (0, 1, 1)]);
}

fn receipt_at<R>(timestamp: u64, f: impl FnOnce() -> R) -> R {
    struct ClearTimestamp;
    impl Drop for ClearTimestamp {
        fn drop(&mut self) {
            crate::engine::router::set_route_source_ts_ns(None);
        }
    }
    crate::engine::router::set_route_source_ts_ns(Some(timestamp));
    let _clear = ClearTimestamp;
    f()
}

/// Each admitted DATA is a receipt even when the application has not
/// pumped its ring. Repeated generations must not collapse into the last
/// lifecycle transition, and the individual data snapshots remain distinct.
fn assert_network_generation_receipts<T: DDS>(topic: &str, sample: T, by_source: bool) {
    use crate::engine::Subscriber as _;
    let _ = rt::init_slab_pool();
    let mut qos = QoS::best_effort().keep_last(16);
    if by_source {
        qos = qos.destination_order_by_source();
    }
    let reader = Arc::new(
        ReaderBuilder::<T>::new(topic.into())
            .qos(qos)
            .network_ring_for_test()
            .build()
            .expect("reader"),
    );
    let subscriber = reader
        .subscriber_weak_for_test()
        .upgrade()
        .expect("subscriber");
    let writer = [0x7B; 16];
    let key = sample.compute_key();
    let mut bytes = vec![0; 256];
    let len = sample
        .encode(&mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    for seq in 1..=11 {
        receipt_at(seq * 100, || {
            if seq % 2 == 1 {
                subscriber.on_data_with_writer(
                    topic,
                    writer,
                    seq,
                    &bytes,
                    crate::dds::CdrVersion::Xcdr2,
                );
            } else {
                let kind = if seq == 6 || seq == 8 {
                    DisposeKind::Unregistered
                } else {
                    DisposeKind::Disposed
                };
                subscriber.on_dispose_from_writer(topic, writer, seq, key, kind);
                subscriber.on_writer_non_data(writer, seq);
            }
        });
    }
    assert!(
        reader.cache().is_empty(),
        "no application pull has occurred"
    );
    let handle = crate::dds::InstanceHandle::new(key);
    assert_eq!(
        reader.cache().instances().generation_counts(handle),
        (3, 2),
        "receipt transitions must already be counted before the first pull"
    );
    let condition = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let samples = reader
        .take_w_condition(&condition, usize::MAX)
        .expect("take");
    let data: Vec<_> = samples
        .iter()
        .filter(|(_, info)| info.valid_data)
        .map(|(_, info)| {
            (
                info.sequence_number,
                info.disposed_generation_count,
                info.no_writers_generation_count,
                info.generation_rank,
                info.absolute_generation_rank,
            )
        })
        .collect();
    assert_eq!(
        data,
        vec![
            (1, 0, 0, 5, 5),
            (3, 1, 0, 4, 4),
            (5, 2, 0, 3, 3),
            (7, 2, 1, 2, 2),
            (9, 2, 2, 1, 1),
            (11, 3, 2, 0, 0)
        ]
    );
    let notifications: Vec<_> = samples
        .iter()
        .filter(|(_, info)| !info.valid_data)
        .map(|(_, info)| {
            (
                info.disposed_generation_count,
                info.no_writers_generation_count,
            )
        })
        .collect();
    assert_eq!(
        notifications,
        vec![(2, 2)],
        "the coalesced transition carries its latest receipt snapshot"
    );
    assert_eq!(
        reader.cache().instances().generation_counts(handle),
        (3, 2),
        "pumping stamped entries never applies their arrivals again"
    );
}

#[test]
fn network_generation_receipts_survive_multiple_cycles_before_any_pull() {
    for by_source in [false, true] {
        assert_network_generation_receipts(
            &format!("generation-receipts-keyed-{by_source}"),
            Instance { key: 1, value: 10 },
            by_source,
        );
        assert_network_generation_receipts(
            &format!("generation-receipts-nil-{by_source}"),
            reading(1, 10),
            by_source,
        );
    }
}

/// A source-ordered value that predates the disposal cannot revive the
/// disposed instance or consume a generation, even before the first pump.
#[test]
fn network_generation_receipts_reject_stale_source_data_without_revival() {
    use crate::engine::Subscriber as _;
    let _ = rt::init_slab_pool();
    let topic = "generation-receipts-stale-source";
    let reader = Arc::new(
        ReaderBuilder::<Reading>::new(topic.into())
            .qos(
                QoS::best_effort()
                    .keep_last(16)
                    .destination_order_by_source(),
            )
            .network_ring_for_test()
            .build()
            .expect("reader"),
    );
    let sub = reader
        .subscriber_weak_for_test()
        .upgrade()
        .expect("subscriber");
    let writer = [0x7C; 16];
    let mut data = vec![0; 64];
    let len = reading(1, 10)
        .encode(&mut data, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    data.truncate(len);
    receipt_at(100, || {
        sub.on_data_with_writer(topic, writer, 1, &data, crate::dds::CdrVersion::Xcdr2)
    });
    receipt_at(300, || {
        sub.on_dispose_from_writer(topic, writer, 2, [0; 16], DisposeKind::Disposed)
    });
    sub.on_writer_non_data(writer, 2);
    receipt_at(200, || {
        sub.on_data_with_writer(topic, writer, 3, &data, crate::dds::CdrVersion::Xcdr2)
    });
    let handle = crate::dds::InstanceHandle::nil();
    assert_eq!(reader.cache().instances().generation_counts(handle), (0, 0));
    assert_eq!(
        reader.cache().instances().state_of(handle),
        InstanceState::NotAliveDisposed
    );
    receipt_at(400, || {
        sub.on_data_with_writer(topic, writer, 4, &data, crate::dds::CdrVersion::Xcdr2)
    });
    assert_eq!(reader.cache().instances().generation_counts(handle), (1, 0));
    let condition = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let samples = reader
        .take_w_condition(&condition, usize::MAX)
        .expect("take");
    let counts: Vec<_> = samples
        .iter()
        .filter(|(_, info)| info.valid_data)
        .map(|(_, info)| (info.sequence_number, info.disposed_generation_count))
        .collect();
    assert_eq!(counts, vec![(1, 0), (4, 1)]);
}

/// A coherent set publishes its DATA and lifecycle changes together, in
/// writer order. Uncommitted changes affect neither instance state nor
/// generations; all receipt transitions are counted at ordered commit.
#[test]
fn network_generation_receipts_preserve_cycles_in_a_coherent_commit() {
    use super::tests_history_limits::NetworkReader;
    use crate::engine::Subscriber as _;
    for by_source in [false, true] {
        let mut qos = QoS::best_effort().keep_last(16);
        if by_source {
            qos = qos.destination_order_by_source();
        }
        let net = NetworkReader::<Reading>::with_parts(
            "generation-receipts-coherent",
            qos,
            super::reorder::ReorderGate::new_best_effort(),
            crate::qos::ownership::OwnershipKind::Shared,
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: false,
            },
        );
        let writer = [0x7D; 16];
        let mut bytes = vec![0; 64];
        let len = reading(1, 10)
            .encode(&mut bytes, crate::dds::CdrVersion::Xcdr2)
            .expect("encode");
        bytes.truncate(len);
        for seq in 1..=5 {
            receipt_at(seq * 100, || {
                if seq % 2 == 1 {
                    net.subscriber.on_data_coherent(
                        &net.topic,
                        writer,
                        seq,
                        &bytes,
                        crate::dds::CdrVersion::Xcdr2,
                        Some(1),
                        None,
                        None,
                    );
                } else {
                    net.subscriber.on_lifecycle_coherent(
                        &net.topic,
                        writer,
                        seq,
                        [0; 16],
                        DisposeKind::Disposed,
                        Some(1),
                        None,
                        None,
                    );
                }
            });
        }
        let handle = crate::dds::InstanceHandle::nil();
        assert_eq!(
            net.reader.cache().instances().generation_counts(handle),
            (0, 0)
        );
        assert!(net.reader.cache().is_empty());
        assert!(net.reader.network_ring_for_test().expect("ring").is_empty());
        net.subscriber.on_ecs(&net.topic, writer, 6, 5, None, None);
        assert_eq!(
            net.reader.cache().instances().generation_counts(handle),
            (2, 0)
        );
        let condition = net
            .reader
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("condition");
        let samples = net
            .reader
            .take_w_condition(&condition, usize::MAX)
            .expect("take");
        let counts: Vec<_> = samples
            .iter()
            .filter(|(_, info)| info.valid_data)
            .map(|(_, info)| (info.sequence_number, info.disposed_generation_count))
            .collect();
        assert_eq!(counts, vec![(1, 0), (3, 1), (5, 2)]);
    }
}

/// KEEP_LAST replacement cannot erase a generation that happened at receipt.
/// The overwritten DATA need not survive until the application first pulls.
#[test]
fn network_generation_receipts_survive_keep_last_replacement_before_any_pull() {
    use crate::engine::Subscriber as _;
    let _ = rt::init_slab_pool();
    let topic = "generation-receipts-keep-last";
    let reader = Arc::new(
        ReaderBuilder::<Reading>::new(topic.into())
            .qos(QoS::best_effort().keep_last(1))
            .network_ring_for_test()
            .build()
            .expect("reader"),
    );
    let sub = reader
        .subscriber_weak_for_test()
        .upgrade()
        .expect("subscriber");
    let writer = [0x7E; 16];
    let mut bytes = vec![0; 64];
    let len = reading(1, 10)
        .encode(&mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);
    sub.on_dispose_from_writer(topic, writer, 1, [0; 16], DisposeKind::Disposed);
    sub.on_writer_non_data(writer, 1);
    let last = u64::try_from(
        reader
            .network_ring_for_test()
            .expect("ring")
            .usable_capacity(),
    )
    .expect("ring capacity fits")
        + 4;
    for seq in 2..=last {
        sub.on_data_with_writer(topic, writer, seq, &bytes, crate::dds::CdrVersion::Xcdr2);
    }
    assert!(
        sub.compaction_decodes() > 0,
        "the full ring evicted older DATA"
    );
    sub.on_dispose_from_writer(topic, writer, last + 1, [0; 16], DisposeKind::Disposed);
    sub.on_writer_non_data(writer, last + 1);
    sub.on_data_with_writer(
        topic,
        writer,
        last + 2,
        &bytes,
        crate::dds::CdrVersion::Xcdr2,
    );
    assert!(reader.cache().is_empty(), "no application pump");
    let handle = crate::dds::InstanceHandle::nil();
    assert_eq!(reader.cache().instances().generation_counts(handle), (2, 0));
    let condition = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let taken = reader
        .take_w_condition(&condition, usize::MAX)
        .expect("take");
    let data: Vec<_> = taken.iter().filter(|(_, info)| info.valid_data).collect();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].1.sequence_number, last + 2);
    assert_eq!(data[0].1.disposed_generation_count, 2);
}

/// Key-only lifecycle changes wait behind a reliable gap with their DATA,
/// so repairing the prefix preserves each disposed-to-alive generation.
#[test]
fn network_generation_receipts_order_routed_lifecycle_across_a_repaired_gap() {
    use super::tests_history_limits::NetworkReader;
    use crate::engine::{Subscriber, TopicRegistry};
    for (by_source, inline, fragmented, status) in [
        (false, false, false, 1),
        (true, false, false, 1),
        (false, true, false, 1),
        (true, true, false, 1),
        (false, true, true, 1),
        (true, true, true, 1),
        (false, false, false, 2),
        (true, false, false, 2),
        (false, true, false, 2),
        (true, true, false, 2),
        (false, true, true, 2),
        (true, true, true, 2),
    ] {
        let mut qos = QoS::reliable().keep_last(16);
        if by_source {
            qos = qos.destination_order_by_source();
        }
        let net = NetworkReader::<Reading>::with_parts(
            "generation-receipts-repaired-gap",
            qos,
            super::reorder::ReorderGate::new(true, true),
            crate::qos::ownership::OwnershipKind::Shared,
            super::subscriber::CoherentConfig::default(),
        );
        let writer = [0x7A; 16];
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(Arc::clone(&net.subscriber) as Arc<dyn Subscriber>)
            .expect("subscriber");
        registry.register_writer_guid(writer, net.topic.clone());
        net.subscriber.on_writer_heartbeat(writer, 1);
        let route = |seq, status, has_data| {
            if fragmented && has_data {
                route_generation_reassembled(&registry, writer, seq, status);
            } else {
                route_generation_change(&registry, writer, seq, status, has_data);
            }
        };
        for (seq, disposed) in [(1, false), (3, false), (4, true), (5, false), (6, true)] {
            route(seq, disposed.then_some(status), !disposed || inline);
        }
        let handle = crate::dds::InstanceHandle::nil();
        let counts = |generation| {
            if status == 1 {
                (generation, 0)
            } else {
                (0, generation)
            }
        };
        let not_alive = if status == 1 {
            InstanceState::NotAliveDisposed
        } else {
            InstanceState::NotAliveNoWriters
        };
        assert_eq!(
            net.reader.cache().instances().generation_counts(handle),
            (0, 0)
        );
        assert_eq!(
            net.reader.cache().instances().state_of(handle),
            InstanceState::Alive
        );
        assert!(net.credit.awaits(&writer, 2));
        for seq in [1, 3, 4, 5, 6] {
            assert!(
                !net.credit.awaits(&writer, seq),
                "retained change {seq} was credited"
            );
        }
        route(2, None, true);
        assert_eq!(
            net.reader.cache().instances().generation_counts(handle),
            counts(1)
        );
        assert_eq!(net.reader.cache().instances().state_of(handle), not_alive);
        route(7, None, true);
        // A repaired duplicate carries neither a second transition nor DATA.
        route(4, Some(status), inline);
        assert_eq!(
            net.reader.cache().instances().generation_counts(handle),
            counts(2)
        );
        let condition = net
            .reader
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("condition");
        let samples = net
            .reader
            .take_w_condition(&condition, usize::MAX)
            .expect("take");
        let values: Vec<_> = samples
            .iter()
            .filter(|(_, i)| i.valid_data)
            .map(|(_, i)| {
                (
                    i.sequence_number,
                    i.disposed_generation_count + i.no_writers_generation_count,
                )
            })
            .collect();
        assert_eq!(
            values,
            if inline {
                vec![(1, 0), (2, 0), (3, 0), (4, 0), (5, 1), (6, 1), (7, 2)]
            } else {
                vec![(1, 0), (2, 0), (3, 0), (5, 1), (7, 2)]
            }
        );
        let transitions: Vec<_> = samples
            .iter()
            .filter(|(_, i)| !i.valid_data)
            .map(|(_, i)| {
                (
                    i.sequence_number,
                    i.disposed_generation_count + i.no_writers_generation_count,
                )
            })
            .collect();
        assert_eq!(transitions, vec![(6, 1)]);
    }
}

/// A lifecycle refused by the duplicate bound must remain unacknowledged;
/// the router cannot credit it again as a separate sample-less DATA.
#[test]
fn network_generation_receipts_retry_a_routed_lifecycle_refused_at_the_bound() {
    use super::tests_history_limits::NetworkReader;
    use crate::engine::{Subscriber, TopicRegistry};
    let net = NetworkReader::<Reading>::with_parts(
        "generation-receipts-lifecycle-retry",
        QoS::reliable().keep_last(16),
        super::reorder::ReorderGate::new(true, true),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig::default(),
    );
    let writer = [0x7A; 16];
    let registry = TopicRegistry::new();
    registry
        .register_subscriber(Arc::clone(&net.subscriber) as Arc<dyn Subscriber>)
        .expect("subscriber");
    registry.register_writer_guid(writer, net.topic.clone());
    net.subscriber.on_writer_heartbeat(writer, 1);
    route_generation_change(&registry, writer, 1, None, true);
    let seq = net.subscriber.fill_missed_runs(writer, 4);
    route_generation_change(&registry, writer, seq, Some(1), false);
    assert!(
        net.credit.awaits(&writer, seq),
        "refusal must not credit receipt"
    );
    assert_eq!(
        net.reader
            .cache()
            .instances()
            .state_of(crate::dds::InstanceHandle::nil()),
        InstanceState::Alive
    );
    net.subscriber.on_writer_gap(writer, 2, seq, Vec::new());
    route_generation_change(&registry, writer, seq, Some(1), false);
    assert!(
        !net.credit.awaits(&writer, seq),
        "repair is retained and credited"
    );
    assert_eq!(
        net.reader
            .cache()
            .instances()
            .state_of(crate::dds::InstanceHandle::nil()),
        InstanceState::NotAliveDisposed
    );
}

/// One actual routed RTPS DATA, optionally a combined D=1 lifecycle change.
fn route_generation_change(
    registry: &crate::engine::TopicRegistry,
    writer: [u8; 16],
    seq: u64,
    status: Option<u8>,
    has_data: bool,
) {
    let bytes = has_data.then(|| super::tests_history_limits::encoded(&reading(seq as i32, 10)));
    route_generation_bytes(registry, writer, seq, status, [0; 16], bytes.as_deref());
}

fn route_generation_bytes(
    registry: &crate::engine::TopicRegistry,
    writer: [u8; 16],
    seq: u64,
    status: Option<u8>,
    key: [u8; 16],
    data: Option<&[u8]>,
) {
    route_generation_bytes_tagged(registry, writer, seq, status, key, data, None);
}

#[allow(clippy::too_many_arguments)]
fn route_generation_bytes_tagged(
    registry: &crate::engine::TopicRegistry,
    writer: [u8; 16],
    seq: u64,
    status: Option<u8>,
    key: [u8; 16],
    data: Option<&[u8]>,
    coherent: Option<u64>,
) {
    use crate::core::discovery::multicast::{classify_rtps, PacketKind};
    let mut body = vec![0, 0, 16, 0];
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&writer[12..]);
    body.extend_from_slice(&((seq >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(seq as u32).to_le_bytes());
    if let Some(status) = status {
        body.extend_from_slice(&[0x71, 0, 4, 0, 0, 0, 0, status]);
        body.extend_from_slice(&[0x70, 0, 16, 0]);
        body.extend_from_slice(&key);
        if let Some(coherent) = coherent {
            body.extend_from_slice(&[0x56, 0, 8, 0]);
            body.extend_from_slice(&((coherent >> 32) as u32).to_le_bytes());
            body.extend_from_slice(&(coherent as u32).to_le_bytes());
        }
        body.extend_from_slice(&[1, 0, 0, 0]);
    }
    if let Some(data) = data {
        body.extend_from_slice(&[0, 7, 0, 0]);
        body.extend_from_slice(data);
    }
    let mut packet = b"RTPS".to_vec();
    packet.extend_from_slice(&[2, 5, 1, 15]);
    packet.extend_from_slice(&writer[..12]);
    // INFO_TS uses writer-order timestamps even when repair arrives late.
    packet.extend_from_slice(&[0x09, 0x01, 8, 0]);
    packet.extend_from_slice(&(seq as i32).to_le_bytes());
    packet.extend_from_slice(&0u32.to_le_bytes());
    let flags = 1 | if data.is_some() { 4 } else { 8 } | if status.is_some() { 2 } else { 0 };
    packet.extend_from_slice(&[0x15, flags]);
    packet.extend_from_slice(
        &u16::try_from(body.len())
            .expect("small packet")
            .to_le_bytes(),
    );
    packet.extend_from_slice(&body);
    let (kind, offset, _, _) = classify_rtps(&packet);
    assert_eq!(kind, PacketKind::Data);
    let metrics = crate::engine::RouterMetrics::new();
    crate::engine::route_data_packet(&packet, packet.len(), offset, registry, &metrics);
    assert_eq!(
        metrics
            .delivery_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

/// Filtering the value of a D=1 change does not filter its lifecycle half.
/// Its source key is shared with the DATA, so an equal compound key is valid.
#[test]
fn network_generation_receipts_keep_inline_lifecycle_when_the_value_is_filtered() {
    use super::tests_history_limits::NetworkReader;
    use crate::engine::{Subscriber, TopicRegistry};
    for by_source in [false, true] {
        let mut qos = QoS::best_effort().keep_last(16).time_based_filter(
            crate::dds::qos::TimeBasedFilter::new(std::time::Duration::from_secs(3600)),
        );
        if by_source {
            qos = qos.destination_order_by_source();
        }
        let net = NetworkReader::<Reading>::with_parts(
            "generation-receipts-inline-filter",
            qos,
            super::reorder::ReorderGate::new_best_effort(),
            crate::qos::ownership::OwnershipKind::Shared,
            super::subscriber::CoherentConfig::default(),
        );
        let writer = [0x7A; 16];
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(Arc::clone(&net.subscriber) as Arc<dyn Subscriber>)
            .expect("subscriber");
        registry.register_writer_guid(writer, net.topic.clone());
        route_generation_change(&registry, writer, 1, None, true);
        route_generation_change(&registry, writer, 2, Some(1), true);
        let handle = crate::dds::InstanceHandle::nil();
        assert_eq!(
            net.reader.cache().instances().state_of(handle),
            InstanceState::NotAliveDisposed
        );
        assert_eq!(
            net.reader.cache().instances().generation_counts(handle),
            (0, 0)
        );
        let condition = net
            .reader
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("condition");
        let samples = net
            .reader
            .take_w_condition(&condition, usize::MAX)
            .expect("take");
        assert_eq!(samples.iter().filter(|(_, i)| i.valid_data).count(), 1);
        assert!(samples
            .iter()
            .any(|(_, i)| !i.valid_data && i.sequence_number == 2));
    }
}

/// A BEST_EFFORT full history rejects only the value of a compound DATA;
/// its lifecycle still applies and rejected DATA starts no generation.
#[test]
fn network_generation_receipts_keep_inline_lifecycle_when_history_refuses_data() {
    use super::tests_history_limits::NetworkReader;
    use crate::engine::{Subscriber, TopicRegistry};
    for (by_source, coherent) in [
        (false, None),
        (true, None),
        (false, Some(2)),
        (true, Some(2)),
    ] {
        let mut qos = QoS::best_effort().keep_last(1);
        qos.resource_limits.max_instances = 1;
        if by_source {
            qos = qos.destination_order_by_source();
        }
        let net = NetworkReader::<Instance>::with_parts(
            "generation-receipts-inline-full",
            qos,
            super::reorder::ReorderGate::new_best_effort(),
            crate::qos::ownership::OwnershipKind::Shared,
            super::subscriber::CoherentConfig::default(),
        );
        let writer = [0x7A; 16];
        let registry = TopicRegistry::new();
        registry
            .register_subscriber(Arc::clone(&net.subscriber) as Arc<dyn Subscriber>)
            .expect("subscriber");
        registry.register_writer_guid(writer, net.topic.clone());
        let first = Instance { key: 1, value: 10 };
        let refused = Instance { key: 2, value: 20 };
        route_generation_bytes(
            &registry,
            writer,
            1,
            None,
            first.compute_key(),
            Some(&super::tests_history_limits::encoded(&first)),
        );
        let key = refused.compute_key();
        let handle = crate::dds::InstanceHandle::new(key);
        net.subscriber
            .on_dispose_from_writer(&net.topic, writer, 1, key, DisposeKind::Disposed);
        route_generation_bytes_tagged(
            &registry,
            writer,
            2,
            Some(1),
            key,
            Some(&super::tests_history_limits::encoded(&refused)),
            coherent,
        );
        assert_eq!(net.rejected().total_count, 1);
        assert_eq!(
            net.reader.cache().instances().state_of(handle),
            InstanceState::NotAliveDisposed
        );
        assert_eq!(
            net.reader.cache().instances().generation_counts(handle),
            (0, 0)
        );
        let condition = net
            .reader
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("condition");
        let samples = net
            .reader
            .take_w_condition(&condition, usize::MAX)
            .expect("take");
        assert_eq!(samples.iter().filter(|(_, i)| i.valid_data).count(), 1);
        assert!(samples
            .iter()
            .any(|(_, i)| !i.valid_data && i.sequence_number == 2));
    }
}

fn route_generation_reassembled(
    registry: &crate::engine::TopicRegistry,
    writer: [u8; 16],
    seq: u64,
    status: Option<u8>,
) {
    let mut payload = vec![0, 7, 0, 0];
    payload.extend_from_slice(&super::tests_history_limits::encoded(&reading(
        seq as i32, 10,
    )));
    let mut qos = Vec::new();
    if let Some(status) = status {
        qos.extend_from_slice(&[0x71, 0, 4, 0, 0, 0, 0, status]);
        qos.extend_from_slice(&[0x70, 0, 16, 0]);
        qos.extend_from_slice(&[0; 16]);
        qos.extend_from_slice(&[1, 0, 0, 0]);
    }
    let metrics = crate::engine::RouterMetrics::new();
    crate::engine::router::route_reassembled_data_for_test(
        writer,
        seq,
        &payload,
        status.map(|_| qos.as_slice()),
        Some(seq * 1_000_000_000),
        registry,
        &metrics,
    );
    assert_eq!(
        metrics
            .delivery_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

/// A rejected compound's receipt and lifecycle share the original DATA gate.
/// Concurrent newer DATA follows the lifecycle and does not count it lost.
#[test]
fn network_generation_receipts_order_a_refused_inline_lifecycle_before_concurrent_data() {
    use super::tests_history_limits::NetworkReader;
    use crate::engine::{Subscriber, TopicRegistry};
    let mut qos = QoS::best_effort().keep_last(1);
    qos.resource_limits.max_instances = 1;
    let net = NetworkReader::<Instance>::with_parts(
        "generation-receipts-inline-overtaken",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig::default(),
    );
    let writer = [0x7A; 16];
    let registry = Arc::new(TopicRegistry::new());
    registry
        .register_subscriber(Arc::clone(&net.subscriber) as Arc<dyn Subscriber>)
        .expect("subscriber");
    registry.register_writer_guid(writer, net.topic.clone());
    let first = Instance { key: 1, value: 10 };
    let next = Instance { key: 2, value: 20 };
    let key = next.compute_key();
    // The first writer change unregisters its instance after DATA. Its
    // unread value still occupies the sole instance place until drained.
    route_generation_bytes(
        &registry,
        writer,
        1,
        Some(2),
        first.compute_key(),
        Some(&super::tests_history_limits::encoded(&first)),
    );
    let (paused_tx, paused_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    *net.subscriber.refusal_hook.lock().expect("hook") = Some(Box::new(move || {
        paused_tx.send(()).expect("pause");
        resume_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("resume");
    }));
    let worker_registry = Arc::clone(&registry);
    let worker = std::thread::spawn(move || {
        route_generation_bytes(
            &worker_registry,
            writer,
            2,
            Some(1),
            key,
            Some(&super::tests_history_limits::encoded(&next)),
        );
    });
    paused_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("paused refusal");
    assert_eq!(net.take_all(), vec![first], "drain the released instance");
    // The value-only accessor announces an invalid sample but cannot
    // remove it. Explicitly settle just the setup's unregister event.
    let setup_events = net.reader.dispose_events().drain();
    assert_eq!(
        setup_events
            .iter()
            .map(|event| event.seq)
            .collect::<Vec<_>>(),
        vec![1]
    );
    let (enter_tx, enter_rx) = std::sync::mpsc::sync_channel(0);
    *net.subscriber.admission_hook.lock().expect("hook") = Some(Box::new(move || {
        enter_tx.send(()).expect("newer DATA at gate");
    }));
    let newer_registry = Arc::clone(&registry);
    let newer = std::thread::spawn(move || {
        route_generation_bytes(
            &newer_registry,
            writer,
            3,
            None,
            key,
            Some(&super::tests_history_limits::encoded(&next)),
        );
    });
    enter_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("newer DATA");
    resume_tx.send(()).expect("resume");
    worker.join().expect("worker");
    newer.join().expect("newer DATA");
    assert_eq!(
        net.rejected().total_count,
        1,
        "newer DATA has room after the old instance is taken"
    );
    let handle = crate::dds::InstanceHandle::new(key);
    assert_eq!(
        net.reader.cache().instances().state_of(handle),
        InstanceState::Alive
    );
    assert_eq!(
        net.reader.cache().instances().generation_counts(handle),
        (1, 0)
    );
    assert_eq!(net.lost(), 0, "the rejected DATA was received");
    let condition = net
        .reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let samples = net
        .reader
        .take_w_condition(&condition, usize::MAX)
        .expect("take");
    let infos: Vec<_> = samples
        .iter()
        .map(|(_, info)| {
            (
                info.sequence_number,
                info.valid_data,
                info.disposed_generation_count,
            )
        })
        .collect();
    assert_eq!(infos, vec![(2, false, 0), (3, true, 1)]);
}

/// Deterministically drive a newer arrival into a refused DATA's section
/// when an implementation releases it before recording receipt. The oracle
/// is loss and instance history, independent of the scheduling mechanism.
#[test]
fn network_generation_receipts_make_refusal_bookkeeping_atomic_with_admission() {
    use super::tests_history_limits::NetworkReader;
    use crate::engine::{Subscriber, TopicRegistry};
    let mut qos = QoS::best_effort().keep_last(1);
    qos.resource_limits.max_instances = 1;
    let net = NetworkReader::<Instance>::with_parts(
        "generation-receipts-refusal-atomic",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig::default(),
    );
    let writer = [0x7A; 16];
    let registry = Arc::new(TopicRegistry::new());
    registry
        .register_subscriber(Arc::clone(&net.subscriber) as Arc<dyn Subscriber>)
        .expect("subscriber");
    registry.register_writer_guid(writer, net.topic.clone());
    let first = Instance { key: 1, value: 10 };
    let next = Instance { key: 2, value: 20 };
    let key = next.compute_key();
    // The first writer change unregisters its instance after DATA. Its
    // unread value still occupies the sole instance place until drained.
    route_generation_bytes(
        &registry,
        writer,
        1,
        Some(2),
        first.compute_key(),
        Some(&super::tests_history_limits::encoded(&first)),
    );
    let injected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let injected_hook = Arc::clone(&injected);
    let reader = Arc::clone(&net.reader);
    let gate = Arc::clone(&net.subscriber.reorder);
    let nested_registry = Arc::clone(&registry);
    *net.subscriber.refusal_entry_hook.lock().expect("hook") = Some(Box::new(move || {
        while reader.take().expect("free old instance").is_some() {}
        let setup_events = reader.dispose_events().drain();
        assert_eq!(
            setup_events
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![1]
        );
        let open = match gate.try_lock() {
            Ok(guard) => {
                drop(guard);
                true
            }
            Err(std::sync::TryLockError::WouldBlock) => false,
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("gate poisoned"),
        };
        if open {
            injected_hook.store(true, std::sync::atomic::Ordering::Relaxed);
            route_generation_bytes(
                &nested_registry,
                writer,
                3,
                None,
                key,
                Some(&super::tests_history_limits::encoded(&next)),
            );
        }
    }));
    route_generation_bytes(
        &registry,
        writer,
        2,
        Some(1),
        key,
        Some(&super::tests_history_limits::encoded(&next)),
    );
    if !injected.load(std::sync::atomic::Ordering::Relaxed) {
        route_generation_bytes(
            &registry,
            writer,
            3,
            None,
            key,
            Some(&super::tests_history_limits::encoded(&next)),
        );
    }
    assert_eq!(net.lost(), 0, "rejected DATA is received, not lost");
    let handle = crate::dds::InstanceHandle::new(key);
    assert_eq!(
        net.reader.cache().instances().state_of(handle),
        InstanceState::Alive
    );
    assert_eq!(
        net.reader.cache().instances().generation_counts(handle),
        (1, 0)
    );
    let condition = net
        .reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("condition");
    let samples = net
        .reader
        .take_w_condition(&condition, usize::MAX)
        .expect("take");
    let infos: Vec<_> = samples
        .iter()
        .map(|(_, i)| (i.sequence_number, i.valid_data, i.disposed_generation_count))
        .collect();
    assert_eq!(infos, vec![(2, false, 0), (3, true, 1)]);
}

/// A refusal after a transition in the same call does not skip the common
/// tail: the transition was accessed, which makes its instance NOT_NEW, so
/// the sample of that instance that is refused right after it stays in the
/// reader NOT_NEW.
#[test]
fn a_refusal_after_a_transition_keeps_the_tail_of_the_call() {
    let (writer, reader) = pair::<Instance>("cond-refusal-tail");
    let any = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("create");
    let new_only = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::NEW,
            InstanceStateMask::ANY,
        )
        .expect("create");

    reader
        .dispose_queue_for_test()
        .push(transition_for(2, DisposeKind::Disposed, None, 7));
    writer
        .write(&Instance { key: 2, value: 20 })
        .expect("write");
    assert!(new_only.get_trigger_value(), "the sample of key 2 is NEW");

    let refuse_key_2 = |sample: &Instance| {
        if sample.key == 2 {
            Err::<(), ()>(())
        } else {
            Ok(())
        }
    };
    let taken = reader
        .take_w_condition_if(&any, 2, refuse_key_2)
        .expect("take")
        .expect("the transition comes first: taken, then the sample refused");
    assert_eq!(taken.len(), 1);
    assert!(
        taken[0].0.is_none() && !taken[0].1.valid_data,
        "the transition"
    );
    assert!(
        !new_only.get_trigger_value(),
        "the transition accessed the instance: its retained sample is NOT_NEW"
    );
    assert!(
        reader
            .take_w_condition_if(&any, 1, refuse_key_2)
            .expect("take")
            .is_err(),
        "the sample of key 2 is still refused"
    );
}

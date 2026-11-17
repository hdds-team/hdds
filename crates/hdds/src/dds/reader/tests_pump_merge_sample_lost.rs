// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `pump_merge_locked` (the K>1 ring merge path, two or more writers bound
//! to one reader) picks the parked head with the smallest timestamp across
//! every bound ring on each pass. When the entry it picks fails to decode,
//! every OTHER ring's already-popped head is still parked in `heads[]`:
//! admitted (out of its ring) and, for a RELIABLE reader, already
//! acknowledged (RTPS v2.5 Sec.8.4.12 credits a change once it leaves the
//! ring, not once the application sees it). DDS v1.4 Sec.2.2.3.19 footnote
//! 28 / RTPS v2.5 Sec.8.4.12.2.8: a change already added to reader history
//! is kept, or its writer is allowed to retransmit it -- an ACK does not
//! license discarding it. Each parked sibling is delivered through the
//! ordinary path rather than discarded; DDS v1.4 Sec.2.2.4.1 SAMPLE_LOST
//! counts only a sibling that ALSO, independently, fails to decode here --
//! the one case nothing can keep.

use crate::dds::listener::SampleLostStatus;
use crate::dds::{CdrVersion, DataReaderListener, DataWriter, QoS, StatusMask};
use crate::{DataReader, Result};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Decodes to `Err` for the one sentinel value, otherwise round-trips like
/// any plain `i32` payload: a controlled stand-in for bytes that fail to
/// decode, without reaching into slab memory to corrupt it by hand.
const POISON: i32 = i32::MIN;

#[derive(Debug, Clone, Copy, PartialEq)]
struct Poisoned(i32);

impl crate::dds::DDS for Poisoned {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0x7E21_1003,
            type_name: "ReaderPumpMergeTestsPoisoned",
            size_bytes: 4,
            alignment: 4,
            is_variable_size: false,
            fields: &[],
        };
        &DESC
    }

    fn encode(&self, buf: &mut [u8], _version: CdrVersion) -> Result<usize> {
        buf[..4].copy_from_slice(&self.0.to_le_bytes());
        Ok(4)
    }

    fn decode(buf: &[u8], _version: CdrVersion) -> Result<Self> {
        let v = i32::from_le_bytes(buf[..4].try_into().unwrap());
        if v == POISON {
            Err(crate::dds::Error::SerializationError)
        } else {
            Ok(Self(v))
        }
    }
}

/// Two writers bound to one reader on `topic` (the K>1 merge path): neither
/// is "the" binding, so the reader pumps through `pump_merge` on every take.
fn two_writers_one_reader(
    topic: &str,
    qos: QoS,
) -> (
    DataWriter<Poisoned>,
    DataWriter<Poisoned>,
    Arc<DataReader<Poisoned>>,
) {
    let _ = crate::core::rt::init_slab_pool();
    let a = crate::dds::writer::WriterBuilder::<Poisoned>::new(topic.to_string())
        .qos(qos.clone())
        .build()
        .expect("writer A build should succeed");
    let b = crate::dds::writer::WriterBuilder::<Poisoned>::new(topic.to_string())
        .qos(qos.clone())
        .build()
        .expect("writer B build should succeed");
    let reader = Arc::new(
        super::ReaderBuilder::<Poisoned>::new(topic.to_string())
            .qos(qos)
            .build()
            .expect("reader build should succeed"),
    );
    reader.bind_to_writer(a.merger());
    reader.bind_to_writer(b.merger());
    (a, b, reader)
}

/// THE RULE (DDS v1.4 Sec.2.2.3.19 footnote 28 / RTPS v2.5 Sec.8.4.12.2.8):
/// writer A's poisoned change fails to decode mid-merge; writer B's
/// perfectly good, already-admitted change -- parked in the other ring's
/// head at that exact moment -- must still reach the application. An ACK
/// does not license discarding a change already in reader history, and
/// nothing here truly cannot be kept, so SAMPLE_LOST must stay at 0.
#[test]
fn a_mid_merge_decode_failure_keeps_the_other_rings_good_sample() {
    let (a, b, reader) =
        two_writers_one_reader("pump-merge-sample-lost", QoS::best_effort().keep_last(4));
    // Written first: the smaller timestamp, so the merge picks it first.
    a.write(&Poisoned(POISON)).expect("write A (poison)");
    // Written second: parked in its own ring's head while A's entry is
    // being processed and fails.
    b.write(&Poisoned(7)).expect("write B (good)");

    let err = reader
        .take()
        .expect_err("A's poisoned entry fails to decode");
    let _ = err;
    assert_eq!(
        reader.get_sample_lost_status().total_count,
        0,
        "B's good change must be kept, not counted as lost"
    );
    assert_eq!(
        reader.take().expect("B's change was kept, not discarded"),
        Some(Poisoned(7)),
        "B's already-admitted change must reach the application"
    );
}

/// The same rule under RELIABLE KEEP_ALL, where the obligation is
/// explicit: a RELIABLE reader's history keeps every change it has
/// admitted until the application takes it (DDS v1.4 Sec.2.2.3.18/.19).
#[test]
fn a_reliable_keep_all_reader_does_not_lose_a_good_sibling_to_a_decode_failure() {
    let (a, b, reader) = two_writers_one_reader(
        "pump-merge-sample-lost-reliable",
        QoS::reliable().keep_all(),
    );
    a.write(&Poisoned(POISON)).expect("write A (poison)");
    b.write(&Poisoned(7)).expect("write B (good)");
    assert!(reader.take().is_err(), "fixture: A's entry fails to decode");
    assert_eq!(
        reader.take().expect("B's change was kept"),
        Some(Poisoned(7)),
        "a RELIABLE reader's already-admitted change must survive a sibling's decode failure"
    );
}

/// The control: one writer, one poisoned change, no sibling ring with a
/// parked head at all -- SAMPLE_LOST stays at 0. Isolates the count from
/// `report_parked_heads_lost`'s own no-op-for-zero guard.
#[test]
fn a_decode_failure_with_no_sibling_parked_head_reports_no_sample_lost() {
    let (a, _b, reader) = two_writers_one_reader(
        "pump-merge-sample-lost-solo",
        QoS::best_effort().keep_last(4),
    );
    a.write(&Poisoned(POISON)).expect("write A (poison)");
    let _ = reader
        .take()
        .expect_err("the poisoned entry fails to decode");
    assert_eq!(
        reader.get_sample_lost_status().total_count,
        0,
        "nothing else was parked: nothing to count"
    );
}

/// What truly cannot be kept: BOTH parked heads fail to decode (not one
/// sibling's good change lost to another's failure, but its own,
/// independent one). Only THIS is what DDS v1.4 Sec.2.2.4.1 SAMPLE_LOST
/// counts, and it must reach an installed listener and the status alike
/// -- the one door `ReaderSubscriber::report_sample_lost` already is, not
/// a second, listener-less copy of it.
struct Lost(AtomicU32);
impl DataReaderListener<Poisoned> for Lost {
    fn on_sample_lost(&self, status: SampleLostStatus) {
        self.0
            .fetch_add(status.total_count_change.max(0) as u32, Ordering::SeqCst);
    }
}

#[test]
fn a_sibling_that_also_fails_to_decode_is_the_one_thing_sample_lost_counts() {
    let (a, b, reader) = two_writers_one_reader(
        "pump-merge-sample-lost-both-poisoned",
        QoS::best_effort().keep_last(4),
    );
    let listener = Arc::new(Lost(AtomicU32::new(0)));
    reader.set_listener(Some(listener.clone()), StatusMask::SAMPLE_LOST);
    a.write(&Poisoned(POISON)).expect("write A (poison)");
    b.write(&Poisoned(POISON)).expect("write B (also poison)");
    assert!(reader.take().is_err(), "fixture: A's entry fails to decode");
    assert_eq!(
        reader.get_sample_lost_status().total_count,
        1,
        "B's own, independent decode failure truly cannot be kept"
    );
    assert_eq!(
        listener.0.load(Ordering::SeqCst),
        1,
        "an installed SAMPLE_LOST listener must be told, not just the status"
    );
}

/// DDS v1.4 Sec.2.2.2.4.2.13 `dispose_w_timestamp`, a LOCAL (intra-process)
/// writer: the application's explicit source timestamp must reach the
/// co-located reader's NOT_ALIVE `SampleInfo`, not the current clock at
/// the moment the writer happened to build the ring entry
/// (`DataWriter::build_lifecycle_entry` must use what `stamp_source_ts()`
/// computed, never `current_time_ns()`).
#[test]
fn a_local_writers_dispose_w_timestamp_reaches_the_reader() {
    let (a, _b, reader) = two_writers_one_reader(
        "pump-merge-local-lifecycle-ts",
        QoS::best_effort().keep_last(4),
    );
    a.write(&Poisoned(7)).expect("write");
    assert_eq!(reader.take().expect("take"), Some(Poisoned(7)));
    a.dispose_w_timestamp(&Poisoned(7), 2_000_000_000)
        .expect("dispose_w_timestamp");
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the dispose transition");
    assert!(data.is_none());
    assert_eq!(
        info.source_timestamp_ns,
        Some(2_000_000_000),
        "the local writer's explicit source timestamp must reach the reader"
    );
}

/// A SAMPLE_LOST listener runs application code; nothing in `notices`'
/// contract lets an application listener assume it is NOT called
/// re-entrantly (DDS v1.4 Sec.2.2.4.1 names no such restriction). The
/// mid-merge report (a sibling that also fails to decode, same fixture as
/// `a_sibling_that_also_fails_to_decode_is_the_one_thing_sample_lost_counts`)
/// must not run the listener inline while `take()`'s consumer gate (and,
/// for K>1, the bindings mutex and the network consumer guard) are still
/// held: a listener that calls `take()` of its own would deadlock on that
/// same, non-reentrant gate forever. `notices::Delivering`, entered before
/// the gate and dropped after, defers the listener's call to once every lock
/// this `take()` took has released -- the same discipline every other
/// delivery path in this reader follows.
///
/// Run on its own thread with a bounded wait: if the deferral is lost, the
/// listener's reentrant `take()` call hangs that thread forever, and this
/// test must fail (not hang the whole suite) by timing out instead.
#[test]
fn a_reentrant_sample_lost_listener_does_not_deadlock_the_consumer_gate() {
    struct ReentrantListener {
        reader: Arc<DataReader<Poisoned>>,
        called: std::sync::atomic::AtomicBool,
    }
    impl DataReaderListener<Poisoned> for ReentrantListener {
        fn on_sample_lost(&self, _status: SampleLostStatus) {
            self.called.store(true, Ordering::SeqCst);
            // The reentrant call under test: must find the consumer gate
            // free, not deadlock on itself.
            let _ = self.reader.take();
        }
    }

    let (a, b, reader) = two_writers_one_reader(
        "pump-merge-reentrant-listener",
        QoS::best_effort().keep_last(4),
    );
    let listener = Arc::new(ReentrantListener {
        reader: Arc::clone(&reader),
        called: std::sync::atomic::AtomicBool::new(false),
    });
    reader.set_listener(Some(listener.clone()), StatusMask::SAMPLE_LOST);
    a.write(&Poisoned(POISON)).expect("write A (poison)");
    b.write(&Poisoned(POISON)).expect("write B (also poison)");

    let (tx, rx) = std::sync::mpsc::channel();
    let taking = Arc::clone(&reader);
    std::thread::spawn(move || {
        let _ = taking.take();
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(),
        "a SAMPLE_LOST listener that re-enters take() must not deadlock \
         the consumer gate"
    );
    assert!(
        listener.called.load(Ordering::SeqCst),
        "fixture: the listener must have been told"
    );
}

/// DDS v1.4 Sec.2.2.3.16: a sample expires by ITS OWN writer's lifespan,
/// never a departed one's. `probe_writer_lifespan`'s epoch check must keep
/// running once a writer's short, finite lifespan is cached (not only while
/// the cached lifespan is still `u64::MAX`), so a topic minimum the registry
/// raises (or removes) on that writer's departure reaches this reader.
#[test]
fn a_departed_writers_short_lifespan_does_not_stick_once_cached() {
    use crate::engine::{DisposeKind, TopicRegistry, WriterDeparture};

    let topic = "pump-merge-lifespan-probe";
    let registry = Arc::new(TopicRegistry::new());
    let writer = crate::dds::writer::WriterBuilder::<Poisoned>::new(topic.to_string())
        .qos(QoS::best_effort().keep_last(4))
        .build()
        .expect("writer build should succeed");
    let reader = Arc::new(
        super::ReaderBuilder::<Poisoned>::new(topic.to_string())
            .qos(QoS::best_effort().keep_last(4))
            .with_registry(Arc::clone(&registry))
            .build()
            .expect("reader build should succeed"),
    );
    reader.bind_to_writer(writer.merger());

    let w = [0x55u8; 16];
    registry.register_writer_guid(w, topic.to_string());
    registry.register_writer_lifespan_of(topic, w, 1);
    let _ = reader.take();
    assert_eq!(
        reader.lifespan_nanos_for_test(),
        1,
        "fixture: the reader cached the short lifespan"
    );

    registry.notify_writer_departure(w, DisposeKind::Unregistered, WriterDeparture::Deleted);
    let _ = reader.take();
    assert_eq!(
        reader.lifespan_nanos_for_test(),
        u64::MAX,
        "the departed writer's short lifespan must not stick once no writer of \
         this topic has one"
    );
}

/// A KEEP_ALL cache's samples hold a place of the reader's history room
/// (`SampleCache::with_room`) until taken or until the cache itself is
/// dropped (`SampleCache::drop`, cache.rs:1407). Giving that place back is
/// the one door (`HistoryRoom::came_back`) that schedules a retry of any
/// coherent set still waiting for room, through a `Weak` to this reader's
/// own subscriber. `DataReader::drop`'s explicit body must clear this
/// reader's own strong hold on that subscriber (`subscriber_for_sample_lost`)
/// itself, alongside `_subscriber_token`, before any of that teardown runs:
/// Rust's *implicit* field-drop glue only reaches it strictly after `cache`'s
/// own `Drop::drop`, so that retry's `Weak::upgrade` could still succeed at
/// the exact point this test observes, delivering into a ring the explicit
/// body had already drained.
#[test]
fn a_reader_dropped_with_a_cached_place_tells_its_dead_subscriber_nothing() {
    use std::sync::mpsc;

    let topic = "pump-merge-teardown-subscriber-hold";
    let writer = crate::dds::writer::WriterBuilder::<Poisoned>::new(topic.to_string())
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer build should succeed");
    let reader = Arc::new(
        super::ReaderBuilder::<Poisoned>::new(topic.to_string())
            .qos(QoS::reliable().keep_all())
            .build()
            .expect("reader build should succeed"),
    );
    reader.bind_to_writer(writer.merger());

    writer.write(&Poisoned(1)).expect("write");
    // `read()`, not `take()`: the sample stays cached, still holding its
    // room place, exactly as `SampleCache::drop` will find it below.
    assert_eq!(
        reader.read().expect("read should succeed"),
        Some(Poisoned(1)),
        "fixture: the sample reached the cache"
    );

    let weak = reader.subscriber_weak_for_test();
    assert!(
        weak.upgrade().is_some(),
        "fixture: the subscriber is alive before the reader drops"
    );

    let (tx, rx) = mpsc::channel();
    super::cache::after_give_back_for_test(Box::new(move || {
        let _ = tx.send(weak.upgrade().is_some());
    }));

    drop(reader);

    assert_eq!(
        rx.try_recv(),
        Ok(false),
        "the subscriber must already be unreachable by the time the \
         dropped reader's cache gives its cached sample's room place back"
    );
}

/// A parked sibling must not be deposited
/// out of timestamp order against an entry still queued, unpopped, behind
/// the one that just failed to decode. Writer A's queue: a poisoned
/// change, then a good one; writer B's queue: one good change, written
/// after both of A's -- all three queued before either writer's change is
/// popped. The merge picks A's poisoned change first (smallest
/// timestamp); it fails. A's own next change (older than B's) and B's
/// already-parked one must still be merged in THEIR OWN timestamp order --
/// A's good change before B's -- exactly as a fully successful drain
/// would have ordered them, never with B's deposited first just because
/// it happened to be parked at the moment A's failed: that would let
/// KEEP_LAST(1) keep the OLDER of the two good changes instead of the
/// newer one.
#[test]
fn a_parked_sibling_does_not_jump_ahead_of_a_still_queued_earlier_change() {
    let (a, b, reader) = two_writers_one_reader(
        "pump-merge-parked-head-order",
        QoS::best_effort().keep_last(1),
    );
    a.write(&Poisoned(POISON)).expect("write A (poison)");
    a.write(&Poisoned(150)).expect("write A (good, second)");
    b.write(&Poisoned(200))
        .expect("write B (good, after both of A's)");

    let err = reader
        .take()
        .expect_err("A's poisoned entry fails to decode");
    let _ = err;

    assert_eq!(
        reader.take().expect("the merge drained in order"),
        Some(Poisoned(200)),
        "B's change, the newer of the two good ones, must be what \
         KEEP_LAST(1) keeps: the merge must process A's own good change, \
         older than B's, before B's, not after"
    );
}

/// Two writers' sequence numbers are
/// independent streams (DDS v1.4 Sec.2.2.3.19 names no cross-writer
/// order), so comparing them directly to pick which transition's
/// timestamp a coalesced dispose/unregister notification keeps is
/// comparing numbers that mean nothing against each other. Writer A does
/// TWO writes before its unregister (`order_seq` 3) and queues it first,
/// at `source_timestamp_ns` 1s; writer B does only ONE write before its
/// dispose (`order_seq` 2, numerically SMALLER than A's) and queues it
/// second, chronologically later, at `source_timestamp_ns` 2s. `B's
/// order_seq(2) >= A's order_seq(3)` is false, so comparing the raw
/// numbers kept the earlier (A's) timestamp: the representative event
/// must be chosen across different writers by arrival order, not by
/// comparing their sequence numbers.
#[test]
fn a_coalesced_transition_from_a_different_writer_keeps_its_own_timestamp() {
    let (a, b, reader) = two_writers_one_reader(
        "pump-merge-dispose-coalesce-cross-writer",
        QoS::best_effort().keep_last(4),
    );
    a.write(&Poisoned(1)).expect("write A, first");
    assert_eq!(reader.take().expect("take A's write"), Some(Poisoned(1)));
    a.write(&Poisoned(2)).expect("write A, second");
    assert_eq!(reader.take().expect("take A's write"), Some(Poisoned(2)));
    b.write(&Poisoned(1)).expect("write B, only one");
    assert_eq!(reader.take().expect("take B's write"), Some(Poisoned(1)));

    // A's unregister is its THIRD operation (order_seq 3), queued first.
    a.unregister_instance_w_timestamp(&Poisoned(2), 1_000_000_000)
        .expect("A unregisters at ts=1s");
    // B's dispose is only its SECOND operation (order_seq 2, a smaller
    // raw number than A's unregister above), queued second, after A's,
    // while this reader has not drained either yet -- the two
    // transitions coalesce into one.
    b.dispose_w_timestamp(&Poisoned(1), 2_000_000_000)
        .expect("B disposes at ts=2s, after A's unregister was queued");

    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the coalesced transition");
    assert!(data.is_none());
    assert_eq!(
        info.source_timestamp_ns,
        Some(2_000_000_000),
        "B's dispose, queued after A's unregister, must be the \
         transition whose timestamp the coalesced notification reports, \
         whatever either writer's own raw sequence number happens to be"
    );
}

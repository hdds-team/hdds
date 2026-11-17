// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::ReaderBuilder;
use crate::core::rt::{self, IndexEntry};
use crate::dds::QoS;
use crate::dds::DDS;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
pub(super) struct Point {
    x: i32,
    y: i32,
}

/// A hand-written type that says nothing about `encodes_xcdr1_natively`
/// (the `DDS` trait default: `false`), for the `data_repr_incompatible`
/// real-capability backstop test below. `#[derive(DDS)]` always answers
/// `true` (its encoder aligns every 8-byte member by the requested
/// version), so `Point` cannot stand in for a refusing type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct RefusesXcdr1Tag(i32);

impl DDS for RefusesXcdr1Tag {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        static DESC: crate::core::types::TypeDescriptor = crate::core::types::TypeDescriptor {
            type_id: 0x7E21_1001,
            type_name: "ReaderTestsRefusesXcdr1Tag",
            size_bytes: 4,
            alignment: 4,
            is_variable_size: false,
            fields: &[],
        };
        &DESC
    }
    fn encode(
        &self,
        buf: &mut [u8],
        _version: crate::dds::CdrVersion,
    ) -> crate::dds::Result<usize> {
        buf[..4].copy_from_slice(&self.0.to_le_bytes());
        Ok(4)
    }
    fn decode(buf: &[u8], _version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        Ok(Self(i32::from_le_bytes(buf[..4].try_into().unwrap())))
    }
}

// ---------------------------------------------------------------------------
// Cross-reader coherent presentation barrier: end-to-end through the real
// ReaderSubscriber commit path (on_data_coherent -> on_ecs -> emit), plus
// the Subscriber attach API.
// ---------------------------------------------------------------------------

/// Build a coherent-access ReaderSubscriber wired to `barrier` as `member`,
/// sharing `ring` with a would-be DataReader. Mirrors what ReaderBuilder
/// does for a coherent reader attached to a Subscriber (VOLATILE
/// reorder-off, TOPIC/INSTANCE scope).
fn make_coherent_sub(
    topic: &str,
    ring: std::sync::Arc<rt::IndexRing>,
    barrier: std::sync::Arc<super::coherent_barrier::CoherentPresentationBarrier>,
    member: super::coherent_barrier::MemberId,
) -> std::sync::Arc<super::subscriber::ReaderSubscriber<Point>> {
    use std::sync::{Arc, Mutex};
    let status = Arc::new(crate::dds::StatusCondition::new());
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let cfg = super::subscriber::CoherentConfig {
        coherent_access: true,
        is_group_scope: false,
    };
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            topic.to_string(),
            ring,
            status,
            None,
            None,
            None,
            dispose,
            reorder,
            cfg,
            None,
            None,
            Arc::new(Mutex::new(
                crate::dds::listener::SampleRejectedStatus::default(),
            )),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            Some(barrier),
            Some(member),
            #[cfg(feature = "security")]
            None,
        ),
    );
    sub.attach_barrier_delivery();
    sub
}

pub(super) fn encoded_point(x: i32, y: i32) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let len = Point { x, y }
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf.truncate(len);
    buf
}

/// A writer GUID under publisher prefix `[p; 12]` with a distinct entity id.
fn coherent_writer_guid(p: u8, entity: u8) -> [u8; 16] {
    let mut g = [p; 16];
    g[12] = 0;
    g[13] = 0;
    g[14] = 0;
    g[15] = entity;
    g
}

/// Stage a full coherent set (`count` samples) for one writer then close it
/// with its ECS marker. Mirrors the HDDS-self wire path: each DATA carries
/// PID_COHERENT_SET = set first SN, the ECS carries the set's last SN and
/// burns the following writer SN (RTPS v2.5 8.7.5).
fn commit_set<S: crate::engine::Subscriber>(
    sub: &S,
    topic: &str,
    writer: [u8; 16],
    first_sn: u64,
    count: u64,
) {
    let data = encoded_point(7, 9);
    for i in 0..count {
        let seq = first_sn + i;
        sub.on_data_coherent(
            topic,
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(first_sn),
            None,
            None,
        );
    }
    sub.on_ecs(
        topic,
        writer,
        first_sn + count,
        first_sn + count - 1,
        None,
        None,
    );
}

/// Build a coherent-access ReaderSubscriber wired to `barrier` as `member`,
/// under GROUP access_scope. Same construction as `make_coherent_sub`
/// except `is_group_scope: true`, which routes `on_data_coherent` /
/// `on_ecs` through `stage_group_sample` / `close_group_set` instead of the
/// per-writer TOPIC/INSTANCE buffer.
fn make_group_coherent_sub(
    topic: &str,
    ring: std::sync::Arc<rt::IndexRing>,
    barrier: std::sync::Arc<super::coherent_barrier::CoherentPresentationBarrier>,
    member: super::coherent_barrier::MemberId,
) -> std::sync::Arc<super::subscriber::ReaderSubscriber<Point>> {
    use std::sync::{Arc, Mutex};
    let status = Arc::new(crate::dds::StatusCondition::new());
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let cfg = super::subscriber::CoherentConfig {
        coherent_access: true,
        is_group_scope: true,
    };
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            topic.to_string(),
            ring,
            status,
            None,
            None,
            None,
            dispose,
            reorder,
            cfg,
            None,
            None,
            Arc::new(Mutex::new(
                crate::dds::listener::SampleRejectedStatus::default(),
            )),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            Some(barrier),
            Some(member),
            #[cfg(feature = "security")]
            None,
        ),
    );
    sub.attach_barrier_delivery();
    sub
}

/// Stage a full GROUP-scope coherent set (`count` samples) for one writer
/// then close it via its ECS marker carrying `gsn` and
/// `publisher_entity_id`. Mirrors `commit_set` for the GROUP wire shape:
/// each DATA also carries PID_GROUP_COHERENT_SET = gsn and
/// PID_GROUP_ENTITY_ID = the owning Publisher, so the sample routes into
/// `stage_group_sample` and the close routes into `close_group_set`
/// (RTPS v2.5 8.7.5, DDS v1.4 2.2.3.6).
fn commit_group_set<S: crate::engine::Subscriber>(
    sub: &S,
    topic: &str,
    writer: [u8; 16],
    first_sn: u64,
    count: u64,
    gsn: u64,
    publisher_entity_id: [u8; 4],
) {
    let data = encoded_point(7, 9);
    for i in 0..count {
        let seq = first_sn + i;
        sub.on_data_coherent(
            topic,
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(first_sn),
            Some(gsn),
            Some(publisher_entity_id),
        );
    }
    sub.on_ecs(
        topic,
        writer,
        first_sn + count,
        first_sn + count - 1,
        Some(gsn),
        Some(publisher_entity_id),
    );
}

/// THE END-TO-END REPRO (cross-topic desync): a per-topic coherent set
/// committed while a peer topic of the same remote publisher is still in
/// flight must expose NOTHING to any reader's ring. Without the barrier,
/// `on_ecs` pushes topic-0's 12 samples straight to ring-0 (this assertion
/// would fail); with it, the set is held until every matched topic has
/// produced its generation.
#[test]
fn coherent_barrier_holds_partial_cross_topic_group() {
    let _ = rt::init_slab_pool();
    use std::sync::Arc;

    let barrier = Arc::new(super::coherent_barrier::CoherentPresentationBarrier::new());
    let ring0 = Arc::new(rt::IndexRing::with_capacity(256));
    let ring1 = Arc::new(rt::IndexRing::with_capacity(256));
    let m0 = barrier.reserve("Square".into(), true);
    let m1 = barrier.reserve("Square1".into(), true);
    let sub0 = make_coherent_sub("Square", Arc::clone(&ring0), Arc::clone(&barrier), m0);
    let sub1 = make_coherent_sub("Square1", Arc::clone(&ring1), Arc::clone(&barrier), m1);

    // Both writers belong to the same remote publisher (shared GUID
    // prefix); membership is registered as the SEDP match hook would.
    let w0 = coherent_writer_guid(0xA0, 1);
    let w1 = coherent_writer_guid(0xA0, 2);
    barrier.register_matched_writer(m0, w0);
    barrier.register_matched_writer(m1, w1);

    // Topic 0 completes its set; topic 1 has not produced anything yet.
    commit_set(&*sub0, "Square", w0, 1, 12);

    // A subscriber read cycle drains both readers: NOTHING may surface,
    // because the cross-topic group is incomplete.
    assert!(
        !barrier.take_one_aligned(m0),
        "partial group must not release"
    );
    assert!(!barrier.take_one_aligned(m1));
    assert_eq!(ring0.len(), 0, "topic 0 leaked a partial set to its ring");
    assert_eq!(ring1.len(), 0);

    // Topic 1 now completes its set -> the group is aligned.
    commit_set(&*sub1, "Square1", w1, 1, 12);

    // Read cycle: each reader delivers exactly its 12-sample set.
    assert!(barrier.take_one_aligned(m0));
    assert!(barrier.take_one_aligned(m1));
    assert_eq!(ring0.len(), 12, "topic 0 should deliver its aligned set");
    assert_eq!(ring1.len(), 12, "topic 1 should deliver its aligned set");

    // Next cycle: nothing new -> empty (no second generation exists).
    assert!(!barrier.take_one_aligned(m0));
    assert!(!barrier.take_one_aligned(m1));
}

/// A single-topic coherent reader keeps pass-through behaviour: each
/// committed set is delivered on the next read.
#[test]
fn coherent_barrier_single_topic_passthrough() {
    let _ = rt::init_slab_pool();
    use std::sync::Arc;

    let barrier = Arc::new(super::coherent_barrier::CoherentPresentationBarrier::new());
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let m = barrier.reserve("Square".into(), true);
    let sub = make_coherent_sub("Square", Arc::clone(&ring), Arc::clone(&barrier), m);

    let w = coherent_writer_guid(0xC0, 1);
    barrier.register_matched_writer(m, w);
    commit_set(&*sub, "Square", w, 1, 12);
    assert!(
        barrier.take_one_aligned(m),
        "single member releases immediately"
    );
    assert_eq!(ring.len(), 12);
}

/// A coherent set's closing ECS re-received on an already-committed set
/// must be a pure no-op -- no duplicate delivery, no new barrier
/// generation, no panic. Mirrors the wire scenario of a duplicate/replayed
/// ECS DATA (retransmit, best-effort duplicate, or a reflected repair).
#[test]
fn close_redelivery_is_noop_on_committed_set() {
    let _ = rt::init_slab_pool();
    use crate::engine::Subscriber;
    use std::sync::Arc;

    let barrier = Arc::new(super::coherent_barrier::CoherentPresentationBarrier::new());
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let m = barrier.reserve("Square".into(), true);
    let sub = make_coherent_sub("Square", Arc::clone(&ring), Arc::clone(&barrier), m);

    let w = coherent_writer_guid(0xE0, 1);
    barrier.register_matched_writer(m, w);

    // First close: stage the set's samples then close it. Single member ->
    // the barrier releases immediately.
    commit_set(&*sub, "Square", w, 1, 12);
    assert!(
        barrier.take_one_aligned(m),
        "single member releases the first generation immediately"
    );
    assert_eq!(ring.len(), 12, "the set's 12 samples land exactly once");

    // Re-receive the SAME closing ECS a second time (identical args: same
    // writer, same ecs_seq = first_sn + count, same coherent_sn = last SN
    // of the set). The writer's coherent_buffer entry for `w` was already
    // fully drained by the first close, so this must be a clean no-op:
    // no new barrier generation, no duplicate ring delivery, no panic.
    sub.on_ecs("Square", w, 1 + 12, 1 + 12 - 1, None, None);

    assert!(
        !barrier.take_one_aligned(m),
        "re-received close must not manufacture a second generation"
    );
    assert_eq!(
        ring.len(),
        12,
        "re-received close must not duplicate the already-delivered set"
    );
}

/// GROUP-scope equivalent of `close_redelivery_is_noop_on_committed_set`: a
/// coherent-set CLOSE re-received for a GROUP-scope set the reader has
/// already flushed must be a pure no-op -- no duplicate sample delivery, no
/// second barrier generation, no panic. Mirrors the wire scenario of a
/// duplicate/replayed GROUP ECS DATA (retransmit, best-effort duplicate, or
/// a reflected repair) under the publisher-wide `close_group_set` path
/// (subscriber.rs) rather than the per-writer TOPIC/INSTANCE path.
#[test]
fn group_close_redelivery_is_noop_on_flushed_set() {
    let _ = rt::init_slab_pool();
    use crate::engine::Subscriber;
    use std::sync::Arc;

    let barrier = Arc::new(super::coherent_barrier::CoherentPresentationBarrier::new());
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let m = barrier.reserve("SquareGroup".into(), true);
    let sub = make_group_coherent_sub("SquareGroup", Arc::clone(&ring), Arc::clone(&barrier), m);

    let w = coherent_writer_guid(0xE1, 1);
    let pub_eid: [u8; 4] = [0x00, 0x00, 0x01, 0x08];
    barrier.register_matched_writer(m, w);

    // First close: stage the set's samples then close it via the GROUP ECS
    // (group_sn + publisher_entity_id present). Single member -> the
    // barrier releases immediately.
    commit_group_set(&*sub, "SquareGroup", w, 1, 12, 7, pub_eid);
    assert!(
        barrier.take_one_aligned(m),
        "single member releases the first generation immediately"
    );
    assert_eq!(
        ring.len(),
        12,
        "the group set's 12 samples land exactly once"
    );

    // Re-receive the SAME closing GROUP ECS a second time (identical args:
    // same writer, same gsn, same ecs_seq = first_sn + count, same
    // coherent_sn = last SN of the set). The group_coherent_buffer entry
    // for this (publisher_prefix, publisher_entity_id, gsn) key was already
    // removed by the first close's flush, so this must be a clean no-op: no
    // new barrier generation, no duplicate ring delivery, no panic.
    sub.on_ecs("SquareGroup", w, 1 + 12, 1 + 12 - 1, Some(7), Some(pub_eid));

    assert!(
        !barrier.take_one_aligned(m),
        "re-received GROUP close must not manufacture a second generation"
    );
    assert_eq!(
        ring.len(),
        12,
        "re-received GROUP close must not duplicate the already-delivered set"
    );
}

/// The Subscriber attach API: a coherent reader built through
/// `ReaderBuilder::subscriber` reserves a member in the Subscriber's
/// barrier, wires its delivery closure, and `take_all` pulls aligned sets
/// from it.
#[test]
fn subscriber_attached_coherent_reader_takes_from_barrier() {
    let _ = rt::init_slab_pool();
    use super::coherent_barrier::CoherentSet;
    use crate::dds::qos::Presentation;
    use std::sync::Arc;

    let sub_entity = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    // A registry keeps the internal ReaderSubscriber (the barrier's
    // delivery target) registered, exactly as in a networked build; without
    // one it would drop at the end of build() and its Drop safety valve
    // would deactivate the freshly reserved member.
    let registry = Arc::new(crate::engine::TopicRegistry::new());
    let reader = ReaderBuilder::<Point>::new("BarrierAttach".to_string())
        .qos(QoS::best_effort().presentation(Presentation::topic_coherent()))
        .with_registry(Arc::clone(&registry))
        .subscriber(&sub_entity)
        .build()
        .expect("reader build should succeed");

    let barrier = sub_entity.coherent_barrier();
    assert_eq!(barrier.member_count(), 1, "coherent reader reserves a slot");

    // Stand in for the RX commit path: deposit one complete set for the
    // reader's member (id 0) under its matched publisher key.
    let w = coherent_writer_guid(0xD0, 1);
    barrier.register_matched_writer(0, w);
    let payloads: Vec<_> = (1..=12u64)
        .map(|seq| {
            super::reorder::PendingPayload::stored_for_test::<Point>(seq, &encoded_point(3, 4))
        })
        .collect();
    barrier.deposit(
        0,
        super::coherent_barrier::publisher_key([0xD0; 12], [0; 4]),
        CoherentSet::single(w, payloads),
    );

    // The outermost bracket publishes what is complete, on this thread.
    sub_entity.begin_access().expect("begin access");
    let batch = reader.take_all().expect("take_all should not error");
    assert_eq!(batch.len(), 12, "the aligned set, published");
    let batch = reader.take_all().expect("take_all should not error");
    assert!(batch.is_empty(), "no second generation exists");
    sub_entity.end_access().expect("end access");
}

/// A coherent reader attached to a Subscriber, and its barrier, with one
/// complete set of `n` samples deposited for it, nothing released yet.
fn barrier_reader_with_a_set(
    topic: &str,
    n: u64,
) -> (
    std::sync::Arc<super::DataReader<Point>>,
    crate::dds::Subscriber,
    std::sync::Arc<crate::engine::TopicRegistry>,
) {
    let _ = rt::init_slab_pool();
    use super::coherent_barrier::CoherentSet;
    use crate::dds::qos::Presentation;
    let sub_entity = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    let registry = std::sync::Arc::new(crate::engine::TopicRegistry::new());
    let reader = std::sync::Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(
                QoS::best_effort()
                    .keep_all()
                    .presentation(Presentation::topic_coherent()),
            )
            .with_registry(std::sync::Arc::clone(&registry))
            .subscriber(&sub_entity)
            .build()
            .expect("reader build should succeed"),
    );
    let barrier = sub_entity.coherent_barrier();
    let w = coherent_writer_guid(0xD1, 1);
    barrier.register_matched_writer(0, w);
    let payloads: Vec<_> = (1..=n)
        .map(|seq| {
            super::reorder::PendingPayload::stored_for_test::<Point>(
                seq,
                &encoded_point(i32::try_from(seq).expect("small"), 0),
            )
        })
        .collect();
    barrier.deposit(
        0,
        super::coherent_barrier::publisher_key([0xD1; 12], [0; 4]),
        CoherentSet::single(w, payloads),
    );
    (reader, sub_entity, registry)
}

/// Every accessor of a reader attached to a Subscriber sees a generation
/// its barrier published, as `take_all` does: the barrier publishes into
/// the reader's ring (here at the outermost `begin_access`), which every
/// accessor reads. Only `take_all` pulled it; `take()` and every other
/// accessor saw nothing.
#[test]
fn every_accessor_of_a_subscriber_reader_takes_from_its_barrier() {
    use crate::dds::{InstanceHandle, InstanceStateMask, SampleStateMask, ViewStateMask};
    type Accessor = fn(&std::sync::Arc<super::DataReader<Point>>) -> usize;
    let accessors: Vec<(&str, Accessor)> = vec![
        ("take", |r| usize::from(r.take().expect("take").is_some())),
        ("take_with_info", |r| {
            usize::from(r.take_with_info().expect("take_with_info").is_some())
        }),
        ("take_next_sample", |r| {
            usize::from(r.take_next_sample().expect("take_next_sample").is_some())
        }),
        ("take_batch", |r| {
            r.take_batch(16).expect("take_batch").len()
        }),
        ("take_all", |r| r.take_all().expect("take_all").len()),
        ("take_instance", |r| {
            usize::from(
                r.take_instance(InstanceHandle::nil())
                    .expect("take_instance")
                    .is_some(),
            )
        }),
        ("take_instance_batch", |r| {
            r.take_instance_batch(InstanceHandle::nil(), 16)
                .expect("take_instance_batch")
                .len()
        }),
        ("read", |r| usize::from(r.read().expect("read").is_some())),
        ("read_batch", |r| {
            r.read_batch(16).expect("read_batch").len()
        }),
        ("read_next_sample", |r| {
            usize::from(r.read_next_sample().expect("read_next_sample").is_some())
        }),
        ("read_instance", |r| {
            usize::from(
                r.read_instance(InstanceHandle::nil())
                    .expect("read_instance")
                    .is_some(),
            )
        }),
        ("read_instance_batch", |r| {
            r.read_instance_batch(InstanceHandle::nil(), 16)
                .expect("read_instance_batch")
                .len()
        }),
        ("take_w_condition", |r| {
            let cond = r
                .create_readcondition(
                    SampleStateMask::ANY,
                    ViewStateMask::ANY,
                    InstanceStateMask::ANY,
                )
                .expect("readcondition");
            r.take_w_condition(&cond, 16)
                .expect("take_w_condition")
                .len()
        }),
        ("read_w_condition", |r| {
            let cond = r
                .create_readcondition(
                    SampleStateMask::ANY,
                    ViewStateMask::ANY,
                    InstanceStateMask::ANY,
                )
                .expect("readcondition");
            r.read_w_condition(&cond, 16)
                .expect("read_w_condition")
                .len()
        }),
        ("readcondition trigger", |r| {
            let cond = r
                .create_readcondition(
                    SampleStateMask::ANY,
                    ViewStateMask::ANY,
                    InstanceStateMask::ANY,
                )
                .expect("readcondition");
            usize::from(crate::dds::Condition::get_trigger_value(&*cond))
        }),
    ];
    for (name, accessor) in accessors {
        let (reader, subscriber, _registry) = barrier_reader_with_a_set(&format!("Door-{name}"), 3);
        subscriber.begin_access().expect("begin access");
        assert!(
            accessor(&reader) > 0,
            "{name}: the generation its barrier holds"
        );
        subscriber.end_access().expect("end access");
    }
}

/// A WaitSet blocked on a ReadCondition of a Subscriber's reader wakes when
/// the barrier holds a whole generation for it.
#[test]
fn a_waitset_wakes_for_a_generation_its_barrier_holds() {
    use crate::dds::{InstanceStateMask, SampleStateMask, ViewStateMask, WaitSet};
    let _ = rt::init_slab_pool();
    use super::coherent_barrier::CoherentSet;
    use crate::dds::qos::Presentation;
    let sub_entity = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    let registry = std::sync::Arc::new(crate::engine::TopicRegistry::new());
    let reader = std::sync::Arc::new(
        ReaderBuilder::<Point>::new("DoorWaitSet".to_string())
            .qos(
                QoS::best_effort()
                    .keep_all()
                    .presentation(Presentation::topic_coherent()),
            )
            .with_registry(std::sync::Arc::clone(&registry))
            .subscriber(&sub_entity)
            .build()
            .expect("reader build should succeed"),
    );
    let cond = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ANY,
        )
        .expect("readcondition");
    let waitset = WaitSet::new();
    waitset.attach_condition(cond.clone()).expect("attach");
    let barrier = std::sync::Arc::clone(sub_entity.coherent_barrier());
    let w = coherent_writer_guid(0xD2, 1);
    barrier.register_matched_writer(0, w);
    let depositor = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let payloads = vec![super::reorder::PendingPayload::stored_for_test::<Point>(
            1,
            &encoded_point(1, 0),
        )];
        barrier.deposit(
            0,
            super::coherent_barrier::publisher_key([0xD2; 12], [0; 4]),
            CoherentSet::single(w, payloads),
        );
    });
    let woke = waitset.wait(Some(std::time::Duration::from_secs(3)));
    depositor.join().expect("depositor");
    assert!(woke.is_ok(), "the WaitSet woke");
    assert_eq!(reader.take_w_condition(&cond, 16).expect("take").len(), 1);
}

/// A NON-coherent reader attached to a Subscriber must not reserve a
/// barrier slot: the attach API is inert unless the reader's Presentation
/// QoS enables coherent_access.
#[test]
fn subscriber_attached_non_coherent_reader_reserves_nothing() {
    let sub_entity = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    let _reader = ReaderBuilder::<Point>::new("BarrierInert".to_string())
        .qos(QoS::best_effort())
        .subscriber(&sub_entity)
        .build()
        .expect("reader build should succeed");
    assert_eq!(sub_entity.coherent_barrier().member_count(), 0);
}

/// A coherent reader NOT attached to any Subscriber keeps today's direct
/// ring delivery: no barrier, take_all drains the ring.
#[test]
fn unattached_coherent_reader_keeps_direct_delivery() {
    let _ = rt::init_slab_pool();
    use crate::dds::qos::Presentation;

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("NoBarrier".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");
    let reader = ReaderBuilder::<Point>::new("NoBarrier".to_string())
        .qos(QoS::best_effort().presentation(Presentation::topic_coherent()))
        .build()
        .expect("reader build should succeed");
    reader.bind_to_writer(writer.merger());

    writer.write(&Point { x: 11, y: 22 }).expect("write");
    let batch = reader.take_all().expect("take_all should not error");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch[0], Point { x: 11, y: 22 });
}

#[test]
fn reader_returns_none_when_ring_empty() {
    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    let result = reader.take().expect("take should not error");
    assert!(result.is_none(), "Should return None when ring empty");
}

#[test]
fn reader_reads_written_sample() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    let msg = Point { x: 42, y: 123 };
    writer.write(&msg).expect("write should succeed");

    let received = reader
        .take()
        .expect("take should not error")
        .expect("should receive message");
    assert_eq!(received.x, 42);
    assert_eq!(received.y, 123);
}

#[test]
fn keep_last_drops_oldest_samples() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort().keep_last(3))
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    for i in 0_i32..5 {
        let msg = Point { x: i, y: i * 2 };
        writer.write(&msg).expect("write should succeed");
    }

    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg.x);
    }

    assert_eq!(received.len(), 3, "Should keep only the configured depth");
    assert_eq!(received, vec![2, 3, 4], "Should contain the newest samples");
}

#[test]
fn batch_read_limits_number_of_samples() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    for i in 0_i32..10 {
        writer
            .write(&Point { x: i, y: i })
            .expect("write should succeed");
    }

    let batch = reader.take_batch(5).expect("batch read should succeed");
    assert_eq!(
        batch.len(),
        5,
        "Should read the requested number of samples"
    );

    for (expected, msg) in (0_i32..).zip(batch.iter()) {
        assert_eq!(msg.x, expected);
    }
}

/// Listener that records every `on_sample_rejected` call, and counts
/// `on_data_available` calls, for the SAMPLE_REJECTED tests below (the
/// count proves a rejected sample never reaches `on_data_available`,
/// see `rejected_sample_fires_on_sample_rejected_not_on_data_available`).
struct RejectionRecorder<T: DDS> {
    calls: std::sync::Mutex<Vec<crate::dds::listener::SampleRejectedStatus>>,
    data_available_count: std::sync::atomic::AtomicUsize,
    _marker: std::marker::PhantomData<fn(&T)>,
}

impl<T: DDS> RejectionRecorder<T> {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            calls: std::sync::Mutex::new(Vec::new()),
            data_available_count: std::sync::atomic::AtomicUsize::new(0),
            _marker: std::marker::PhantomData,
        })
    }

    fn calls(&self) -> Vec<crate::dds::listener::SampleRejectedStatus> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn data_available_count(&self) -> usize {
        self.data_available_count
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl<T: DDS> crate::dds::listener::DataReaderListener<T> for RejectionRecorder<T> {
    fn on_data_available(&self, _sample: &T) {
        self.data_available_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn on_sample_rejected(&self, status: crate::dds::listener::SampleRejectedStatus) {
        self.calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(status);
    }
}

/// A RELIABLE KEEP_ALL QoS whose history holds at most `max_samples`
/// samples (RESOURCE_LIMITS): the history that rejects what it has no room
/// for.
fn keep_all_up_to(max_samples: usize) -> QoS {
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = max_samples;
    qos.resource_limits.max_samples_per_instance = max_samples;
    qos
}

/// A full reader ring under RELIABLE is a rejected sample, not a wire gap:
/// the sample WAS received (dedup + control-plane credit already happened
/// upstream of `process_admitted`), so the writer is never asked to resend
/// it. Drives the same production admission path the removed NACK-gap
/// tests used (`crate::engine::Subscriber::on_data_with_writer` on a
/// standalone `ReaderSubscriber` sharing the built reader's network ring,
/// see `network_ring_for_test`), admits more samples than the ring holds
/// WITHOUT ever taking, and checks every observable the rejection must
/// produce.
///
/// The reader is KEEP_ALL with RESOURCE_LIMITS `max_samples` at
/// `admitted_capacity` (`keep_all_up_to`): a KEEP_LAST reader replaces its
/// oldest samples rather than reject the newest (DDS v1.4 Sec.2.2.3.18), so
/// only a KEEP_ALL history at its limit rejects.
#[test]
fn ring_full_rejection_raises_sample_rejected_status() {
    use crate::dds::listener::{DataReaderListener, SampleRejectedReason};
    use crate::dds::StatusMask;
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    // The process-wide collector counts every concurrent test's rejections
    // too: this thread's own one counts exactly this reader's.
    let (metrics, _metrics_guard) = crate::telemetry::private_metrics_for_test();

    let admitted_capacity: usize = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() - 1;
    let extra: usize = 10;
    let total: usize = admitted_capacity + extra;

    let topic = "test_sample_rejected_ring_full";
    let reader = Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(keep_all_up_to(admitted_capacity))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let recorder = RejectionRecorder::<Point>::new();
    let subscriber = super::subscriber::ReaderSubscriber::<Point>::new(
        topic.to_string(),
        network_ring,
        status,
        None,
        None,
        Some(Arc::clone(&recorder) as Arc<dyn DataReaderListener<Point>>),
        dispose,
        reorder,
    )
    .with_room(reader.network_room_for_test().cloned());

    let writer_guid = [0x60u8; 16];
    for seq_1based in 1..=total {
        let seq = u64::try_from(seq_1based).expect("seq fits in u64 for this test size");
        let value = i32::try_from(seq_1based).expect("seq fits in i32 for this test size");
        let bytes = encoded_point(value, value);
        subscriber.on_data_with_writer(
            topic,
            writer_guid,
            seq,
            &bytes,
            crate::dds::CdrVersion::Xcdr2,
        );
    }

    let calls = recorder.calls();
    assert_eq!(
        calls.len(),
        extra,
        "one on_sample_rejected call per rejected sample"
    );
    for call in &calls {
        assert_eq!(call.last_reason, SampleRejectedReason::ResourceLimit);
        assert_eq!(
            call.total_count_change, 1,
            "per-event delivery: each delivered change is exactly the one new rejection"
        );
    }
    assert_eq!(
        calls.last().expect("at least one rejection").total_count,
        u32::try_from(extra).expect("extra fits in u32"),
        "cumulative total_count after the last delivered rejection"
    );

    // DDS v1.4 Sec.2.2.4.2.1: the status is reset PRIOR TO calling the
    // listener. A listener was attached for every one of these
    // rejections, so each delivery cleared the bit again immediately;
    // it must NOT still read as raised now. See
    // `waitset_style_sample_rejected_getter_clears_bit_and_delta` below for
    // the no-listener case, where the bit is expected to stay raised.
    assert!(
        !reader
            .get_status_condition()
            .get_active_statuses()
            .contains(StatusMask::SAMPLE_REJECTED),
        "SAMPLE_REJECTED must already be cleared: every rejection here was delivered to a listener"
    );

    assert_eq!(
        metrics.samples_rejected_ring_full(),
        u64::try_from(extra).expect("extra fits in u64"),
        "the ring-full telemetry counter must move by the number of rejections"
    );

    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg);
    }
    assert_eq!(
        received.len(),
        admitted_capacity,
        "every sample that fit in the ring must still be taken intact"
    );
    for (i, msg) in received.iter().enumerate() {
        let expected = i32::try_from(i + 1).expect("index fits in i32 for this test size");
        assert_eq!(
            *msg,
            Point {
                x: expected,
                y: expected
            }
        );
    }
}

/// `process_admitted`'s pipeline is documented as "decode -> filter ->
/// re-encode -> slab -> ring -> listener": `on_data_available` must fire
/// only after a successful ring push, never before it (a sample that
/// re-encodes and reserves a slab slot but then finds the ring full must
/// reach the application as a rejection, never as available data). Fills
/// a ring exactly to capacity (every one of those admitted and expected
/// to fire `on_data_available`), then sends one more that must be
/// rejected, and checks `on_data_available`'s count does not move.
#[test]
fn rejected_sample_fires_on_sample_rejected_not_on_data_available() {
    use crate::dds::listener::{DataReaderListener, SampleRejectedReason};
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();

    let admitted_capacity: usize = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() - 1;

    let topic = "test_sample_rejected_not_on_data_available";
    let reader = Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(keep_all_up_to(admitted_capacity))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let recorder = RejectionRecorder::<Point>::new();
    let subscriber = super::subscriber::ReaderSubscriber::<Point>::new(
        topic.to_string(),
        network_ring,
        status,
        None,
        None,
        Some(Arc::clone(&recorder) as Arc<dyn DataReaderListener<Point>>),
        dispose,
        reorder,
    )
    .with_room(reader.network_room_for_test().cloned());

    let writer_guid = [0x65u8; 16];
    // Fill the ring exactly to capacity: every one of these is admitted
    // and must fire on_data_available.
    for seq_1based in 1..=admitted_capacity {
        let seq = u64::try_from(seq_1based).expect("seq fits in u64 for this test size");
        let value = i32::try_from(seq_1based).expect("seq fits in i32 for this test size");
        subscriber.on_data_with_writer(
            topic,
            writer_guid,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert_eq!(
        recorder.data_available_count(),
        admitted_capacity,
        "every admitted sample must fire on_data_available exactly once"
    );
    assert_eq!(recorder.calls().len(), 0, "nothing has been rejected yet");

    // One more: the ring is now full, so this one must be rejected.
    let overflow_seq = u64::try_from(admitted_capacity + 1).expect("fits in u64");
    subscriber.on_data_with_writer(
        topic,
        writer_guid,
        overflow_seq,
        &encoded_point(999, 999),
        crate::dds::CdrVersion::Xcdr2,
    );

    assert_eq!(
        recorder.calls().len(),
        1,
        "the overflowing sample must be reported as rejected"
    );
    assert_eq!(
        recorder.calls()[0].last_reason,
        SampleRejectedReason::ResourceLimit
    );
    assert_eq!(
        recorder.data_available_count(),
        admitted_capacity,
        "the rejected sample must NOT have fired on_data_available: the count \
         must still be exactly what the admitted samples produced, unmoved by \
         the rejection"
    );
}

/// WaitSet-style consumption: no listener attached, so per DDS v1.4
/// Sec.2.2.4.2.1 SAMPLE_REJECTED stays raised (nothing has "accessed" the
/// status yet) until `DataReader::get_sample_rejected_status` reads it,
/// which must then clear both the bit and `total_count_change` -- a
/// second read with no new rejection in between must report a change of
/// 0. The subscriber shares the reader's own `sample_rejected` Arc (test
/// seam `sample_rejected_for_test`, the same sharing `ReaderBuilder::build`
/// wires up for real) so the getter observes this subscriber's writes.
#[test]
fn waitset_style_sample_rejected_getter_clears_bit_and_delta() {
    use crate::dds::StatusMask;
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();

    let admitted_capacity: usize = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() - 1;
    let extra: usize = 3;
    let total: usize = admitted_capacity + extra;

    let topic = "test_sample_rejected_waitset_style";
    let reader = Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(keep_all_up_to(admitted_capacity))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let sample_rejected = reader.sample_rejected_for_test();
    let subscriber = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        topic.to_string(),
        network_ring,
        status,
        None,
        None,
        None,
        dispose,
        reorder,
        super::subscriber::CoherentConfig::default(),
        None,
        None,
        sample_rejected,
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    )
    .with_room(reader.network_room_for_test().cloned());

    let writer_guid = [0x62u8; 16];
    for seq_1based in 1..=total {
        let seq = u64::try_from(seq_1based).expect("seq fits in u64 for this test size");
        let value = i32::try_from(seq_1based).expect("seq fits in i32 for this test size");
        let bytes = encoded_point(value, value);
        subscriber.on_data_with_writer(
            topic,
            writer_guid,
            seq,
            &bytes,
            crate::dds::CdrVersion::Xcdr2,
        );
    }

    assert!(
        reader
            .get_status_condition()
            .get_active_statuses()
            .contains(StatusMask::SAMPLE_REJECTED),
        "no listener consumed these rejections: the bit must stay raised"
    );

    let status1 = reader.get_sample_rejected_status();
    assert_eq!(
        status1.total_count,
        u32::try_from(extra).expect("extra fits in u32")
    );
    assert_eq!(
        status1.total_count_change,
        i32::try_from(extra).expect("extra fits in i32"),
        "the read must report every rejection accumulated since the reader was built"
    );

    assert!(
        !reader
            .get_status_condition()
            .get_active_statuses()
            .contains(StatusMask::SAMPLE_REJECTED),
        "reading the status must clear SAMPLE_REJECTED, DDS v1.4 Sec.2.2.4.2.1"
    );

    let status2 = reader.get_sample_rejected_status();
    assert_eq!(
        status2.total_count, status1.total_count,
        "total_count is cumulative and a mere read must not change it"
    );
    assert_eq!(
        status2.total_count_change, 0,
        "a second read with no new rejection in between must report a change of 0"
    );
}

/// The two admission callers `process_admitted` documents (ring-full and
/// slab-exhausted) can run on different threads (router vs. application,
/// or two routed packets on a thread pool) and both call
/// `report_sample_rejected` concurrently. This drives that shape directly
/// (the test seam, bypassing the two real admission races) with several
/// threads hammering one subscriber: the delivered `total_count_change`
/// sequence must be gap-free (nothing lost, nothing double-delivered), so
/// the sum of every delivered delta equals the final cumulative
/// `total_count` exactly.
#[test]
fn concurrent_rejections_deliver_a_gap_free_total_count_change_sequence() {
    use crate::dds::listener::{DataReaderListener, SampleRejectedReason};
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let _ = rt::init_slab_pool();

    let topic = "test_sample_rejected_concurrent";
    let status = Arc::new(crate::dds::StatusCondition::new());
    let ring = Arc::new(rt::IndexRing::with_capacity(256));
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let recorder = RejectionRecorder::<Point>::new();
    let subscriber = Arc::new(super::subscriber::ReaderSubscriber::<Point>::new(
        topic.to_string(),
        ring,
        status,
        None,
        None,
        Some(Arc::clone(&recorder) as Arc<dyn DataReaderListener<Point>>),
        dispose,
        reorder,
    ));

    const THREADS: usize = 4;
    const PER_THREAD: usize = 250;
    let barrier = Arc::new(Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let sub = Arc::clone(&subscriber);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                for _ in 0..PER_THREAD {
                    sub.report_sample_rejected_for_test(SampleRejectedReason::ResourceLimit, None);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("producer thread must not panic");
    }
    // What a producer queued while another told is told by the hand-off
    // thread (`notices::Ordered`): it may still be telling.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while recorder.calls().len() < THREADS * PER_THREAD && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let calls = recorder.calls();
    assert_eq!(
        calls.len(),
        THREADS * PER_THREAD,
        "every rejection must be delivered exactly once"
    );
    let sum: i64 = calls.iter().map(|c| i64::from(c.total_count_change)).sum();
    let final_total = calls
        .iter()
        .map(|c| c.total_count)
        .max()
        .expect("at least one call was recorded");
    assert_eq!(
        sum,
        i64::from(final_total),
        "the sum of delivered deltas must equal the final cumulative total_count: \
         no delta lost, none double-delivered"
    );
    assert_eq!(
        final_total,
        u32::try_from(THREADS * PER_THREAD).expect("count fits in u32")
    );
}

#[derive(Debug, Clone, PartialEq, crate::DDS)]
pub(super) struct BigBlob {
    id: i32,
    data: Vec<u8>,
}

/// The slab-exhausted admission exit (`process_admitted`'s OTHER resource
/// limit besides ring-full) reports the same `SampleRejectedStatus` /
/// telemetry / listener contract, forced independently of the ring: fill
/// the slab pool's heap-fallback tier directly
/// (`SlabPool::reserve_and_write`, `pub(crate)`, called the same way
/// `process_admitted` calls it), then admit one sample whose re-encoded
/// size is bigger than the largest primary size class (128 KiB) so it
/// routes straight past primary and the empty default Large tier to the
/// (now full) heap tier -- see `SlabPool::try_reserve_primary_and_copy` /
/// `try_reserve_large_and_copy`.
///
/// The pool and the telemetry collector are this thread's own
/// (`rt::private_slab_pool_for_test`, `telemetry::private_metrics_for_test`):
/// the process-wide pool is one budget for every test running at once, and
/// holding it full refused other tests' samples and local writes (they
/// failed, and their refusals moved this test's counter by dozens).
#[test]
fn slab_exhausted_rejection_raises_sample_rejected_status() {
    use crate::dds::listener::{DataReaderListener, SampleRejectedReason};
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    // A pool of this thread's own: the default tiers (no Large tier) with a
    // heap ceiling of a few filler chunks, leaked because the accessor hands
    // out `&'static`.
    const FILLER_CHUNK: usize = 140_000;
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes: 4 * FILLER_CHUNK,
        ..crate::qos::MemoryPolicy::default()
    };
    let (pool, _pool_guard) = rt::owned_private_slab_pool_for_test(&policy);
    let (metrics, _metrics_guard) = crate::telemetry::private_metrics_for_test();

    // Fill the heap tier to its ceiling. Every chunk is over the largest
    // primary class so every one of these routes to heap. Never released:
    // the pool is this test's own.
    let filler = vec![0u8; FILLER_CHUNK];
    let mut filled = 0usize;
    while pool
        .reserve_and_write(&filler, crate::core::rt::Claim::Reader)
        .is_some()
    {
        filled += 1;
    }
    assert!(filled > 0, "fixture: the heap tier took some filler first");

    let topic = "test_sample_rejected_slab_exhausted";
    let reader = Arc::new(
        ReaderBuilder::<BigBlob>::new(topic.to_string())
            .qos(QoS::reliable().keep_last(1))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let recorder = RejectionRecorder::<BigBlob>::new();
    let subscriber = super::subscriber::ReaderSubscriber::<BigBlob>::new(
        topic.to_string(),
        network_ring,
        status,
        None,
        None,
        Some(Arc::clone(&recorder) as Arc<dyn DataReaderListener<BigBlob>>),
        dispose,
        reorder,
    )
    .with_room(reader.network_room_for_test().cloned());

    // Bigger than the largest primary class (128 KiB) after CDR encoding,
    // so process_admitted's re-encode also skips primary/large and must
    // hit the (now full) heap tier: remaining budget is under the 140,000
    // byte filler chunk, well below this.
    let big_sample = BigBlob {
        id: 1,
        data: vec![0xABu8; 200_000],
    };
    let mut bytes = vec![0u8; 210_000];
    let len = big_sample
        .encode(&mut bytes, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    bytes.truncate(len);

    let writer_guid = [0x63u8; 16];
    subscriber.on_data_with_writer(topic, writer_guid, 1, &bytes, crate::dds::CdrVersion::Xcdr2);

    let calls = recorder.calls();
    assert_eq!(
        calls.len(),
        1,
        "the slab-exhausted admission must reject exactly this sample"
    );
    assert_eq!(calls[0].last_reason, SampleRejectedReason::ResourceLimit);
    assert_eq!(calls[0].total_count, 1);
    assert_eq!(calls[0].total_count_change, 1);

    assert_eq!(
        metrics.samples_rejected_slab_exhausted(),
        1,
        "the slab-exhausted telemetry counter must move by 1"
    );

    assert!(
        reader.take().expect("take should not error").is_none(),
        "a slab-exhausted sample must never reach the ring"
    );
}

/// Wire twin for [`Keyed`]. The `#[derive(DDS)]` macro never generates
/// `compute_key`/`has_key` overrides for any field annotation (checked:
/// `hdds-codegen`'s derive has no key-field handling at all), so `Keyed`
/// implements `DDS` by hand and delegates the CDR codec to this derived
/// twin, the same split `Gated`/`GatedWire` use earlier in this file.
#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
pub(super) struct KeyedWire {
    key: i64,
    value: i64,
}

/// A real keyed type for the `last_instance_handle` test: `has_key()` is
/// `true` and `compute_key()` derives all 16 bytes of the hash from the
/// `key` field (the key itself in the low 8 bytes, a mix of it in the
/// high 8), so a handle that kept only half of the hash would not equal
/// the `InstanceHandle` the reader's `SampleInfo` reports for the same
/// instance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Keyed {
    key: i64,
    value: i64,
}

impl DDS for Keyed {
    fn type_descriptor() -> &'static crate::core::types::TypeDescriptor {
        KeyedWire::type_descriptor()
    }

    fn encode(&self, buf: &mut [u8], version: crate::dds::CdrVersion) -> crate::dds::Result<usize> {
        KeyedWire {
            key: self.key,
            value: self.value,
        }
        .encode(buf, version)
    }

    fn decode(buf: &[u8], version: crate::dds::CdrVersion) -> crate::dds::Result<Self> {
        let wire = KeyedWire::decode(buf, version)?;
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

fn encoded_keyed(key: i64, value: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let len = Keyed { key, value }
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf.truncate(len);
    buf
}

/// Two DIFFERENT instances rejected in a row: `last_instance_handle` must
/// report the most recently rejected one, not the first or a stale value.
#[test]
fn last_instance_handle_reports_the_most_recently_rejected_instance() {
    use crate::dds::listener::DataReaderListener;
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();

    let admitted_capacity: usize = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() - 1;
    let depth = u32::try_from(admitted_capacity).expect("admitted_capacity fits in u32");

    let topic = "test_sample_rejected_last_instance_handle";
    let reader = Arc::new(
        ReaderBuilder::<Keyed>::new(topic.to_string())
            .qos(QoS::reliable().keep_last(depth))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let recorder = RejectionRecorder::<Keyed>::new();
    let subscriber = super::subscriber::ReaderSubscriber::<Keyed>::new(
        topic.to_string(),
        network_ring,
        status,
        None,
        None,
        Some(Arc::clone(&recorder) as Arc<dyn DataReaderListener<Keyed>>),
        dispose,
        reorder,
    )
    .with_room(reader.network_room_for_test().cloned());

    let writer_guid = [0x64u8; 16];
    // Fill the ring with a single filler instance (key=0), then reject
    // exactly two DIFFERENT instances (key=111, then key=222).
    for seq_1based in 1..=admitted_capacity {
        let seq = u64::try_from(seq_1based).expect("seq fits in u64 for this test size");
        let bytes = encoded_keyed(0, 0);
        subscriber.on_data_with_writer(
            topic,
            writer_guid,
            seq,
            &bytes,
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    let first_rejected_seq = u64::try_from(admitted_capacity + 1).expect("fits in u64");
    subscriber.on_data_with_writer(
        topic,
        writer_guid,
        first_rejected_seq,
        &encoded_keyed(111, 1),
        crate::dds::CdrVersion::Xcdr2,
    );
    let second_rejected_seq = u64::try_from(admitted_capacity + 2).expect("fits in u64");
    subscriber.on_data_with_writer(
        topic,
        writer_guid,
        second_rejected_seq,
        &encoded_keyed(222, 2),
        crate::dds::CdrVersion::Xcdr2,
    );

    let calls = recorder.calls();
    assert_eq!(calls.len(), 2, "exactly two samples must be rejected");
    let handle_of = |key: i64| super::InstanceHandle::new(Keyed { key, value: 0 }.compute_key());
    assert_eq!(
        calls[0].last_instance_handle,
        Some(handle_of(111)),
        "the first rejection must report key=111's instance, full 16-byte handle"
    );
    assert_eq!(
        calls[1].last_instance_handle,
        Some(handle_of(222)),
        "the second, most recent rejection must report key=222's instance, not the first"
    );
    // The same derivation the reader's own metadata uses: the handle a
    // rejection reports is the one `SampleInfo` carries for that instance
    // (here the admitted filler instance, key=0), so an application can
    // hand it straight to `take_instance` / `read_instance`.
    let (sample, info) = reader
        .take_with_info()
        .expect("take_with_info must not fail")
        .expect("the filler samples are still in the ring");
    assert_eq!(
        sample.map(|s| s.key),
        Some(0),
        "the admitted filler instance"
    );
    assert_eq!(
        info.instance_handle,
        handle_of(0),
        "SampleInfo::instance_handle and SampleRejectedStatus::last_instance_handle share \
         one derivation"
    );
}

/// DDS v1.4 Sec.2.2.4.2.2: a read or take clears DATA_AVAILABLE and nothing
/// else; a plain communication status such as SAMPLE_REJECTED is reset only
/// by its own listener call or its own getter (Sec.2.2.4.2.1). A reader with
/// no listener overflows its ring (SAMPLE_REJECTED raised), then the
/// application drains it with `take()` down to the empty take that runs the
/// idle clear: the bit must survive that drain so a WaitSet on
/// SAMPLE_REJECTED still wakes, and the getter is what clears it.
#[test]
fn draining_the_ring_with_take_leaves_an_unread_sample_rejected_bit_raised() {
    use crate::dds::StatusMask;
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();

    let admitted_capacity: usize = crate::config::READER_HISTORY_RING_SIZE.next_power_of_two() - 1;
    let total: usize = admitted_capacity + 1;

    let topic = "test_sample_rejected_survives_take_drain";
    let reader = Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(keep_all_up_to(admitted_capacity))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let sample_rejected = reader.sample_rejected_for_test();
    let subscriber = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        topic.to_string(),
        network_ring,
        Arc::clone(&status),
        None,
        None,
        None,
        dispose,
        reorder,
        super::subscriber::CoherentConfig::default(),
        None,
        None,
        sample_rejected,
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    )
    .with_room(reader.network_room_for_test().cloned());

    let writer_guid = [0x64u8; 16];
    for seq_1based in 1..=total {
        let seq = u64::try_from(seq_1based).expect("seq fits in u64 for this test size");
        let value = i32::try_from(seq_1based).expect("seq fits in i32 for this test size");
        let bytes = encoded_point(value, value);
        subscriber.on_data_with_writer(
            topic,
            writer_guid,
            seq,
            &bytes,
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert!(
        status
            .get_active_statuses()
            .contains(StatusMask::SAMPLE_REJECTED),
        "overflowing the ring must raise SAMPLE_REJECTED"
    );

    // Drain every admitted sample, then the empty take that runs the
    // reader's idle clear.
    let mut taken = 0usize;
    while reader.take().expect("take must not fail").is_some() {
        taken += 1;
    }
    assert_eq!(taken, admitted_capacity, "every admitted sample is taken");

    assert!(
        status
            .get_active_statuses()
            .contains(StatusMask::SAMPLE_REJECTED),
        "take() clears DATA_AVAILABLE only (DDS v1.4 Sec.2.2.4.2.2): an unread \
         SAMPLE_REJECTED must survive draining the ring"
    );
    let rejected = reader.get_sample_rejected_status();
    assert_eq!(rejected.total_count_change, 1);
    assert!(
        !status
            .get_active_statuses()
            .contains(StatusMask::SAMPLE_REJECTED),
        "the getter is the consumer that clears the bit"
    );
}

/// `get_sample_rejected_status()` must never clear a SAMPLE_REJECTED it did
/// not return. A getter racing a reporter (no listener): if the getter
/// releases the state lock BEFORE clearing the bit, a rejection landing in
/// between (increment + raise) has its bit erased while its delta is still
/// pending, and a WaitSet sleeps on an unread rejection. Checked at
/// quiescence: the bit is raised exactly when a delta is pending, and
/// consumed + pending == reported. The window is a few instructions wide,
/// so this is a stress test: a pass proves nothing on its own, a failure
/// is a real ordering defect.
#[test]
fn getter_never_clears_a_rejection_it_did_not_return() {
    use crate::dds::listener::SampleRejectedReason;
    use crate::dds::StatusMask;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    const REPORTS: u32 = 20_000;

    let topic = "test_sample_rejected_getter_vs_reporter";
    let reader = Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(QoS::reliable().keep_last(4))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let sample_rejected = reader.sample_rejected_for_test();
    let subscriber = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            topic.to_string(),
            network_ring,
            Arc::clone(&status),
            None,
            None,
            None,
            dispose,
            reorder,
            super::subscriber::CoherentConfig::default(),
            None,
            None,
            sample_rejected,
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            None,
            None,
            #[cfg(feature = "security")]
            None,
        )
        .with_room(reader.network_room_for_test().cloned()),
    );

    let reporter = {
        let subscriber = Arc::clone(&subscriber);
        std::thread::spawn(move || {
            for _ in 0..REPORTS {
                subscriber
                    .report_sample_rejected_for_test(SampleRejectedReason::ResourceLimit, None);
            }
        })
    };
    let mut consumed: i64 = 0;
    while !reporter.is_finished() {
        consumed += i64::from(reader.get_sample_rejected_status().total_count_change);
    }
    reporter.join().expect("reporter thread must not panic");

    // Quiescent: no reporter and no getter in flight.
    let bit_raised = status
        .get_active_statuses()
        .contains(StatusMask::SAMPLE_REJECTED);
    let pending = reader.get_sample_rejected_status();
    assert_eq!(
        consumed + i64::from(pending.total_count_change),
        i64::from(REPORTS),
        "no delta lost, none double-delivered"
    );
    assert_eq!(
        bit_raised,
        pending.total_count_change > 0,
        "SAMPLE_REJECTED must be raised exactly when an unread delta is pending: \
         a getter cleared a rejection it did not return"
    );
}

/// Listener that reacts to a rejection by causing ANOTHER rejection on the
/// same reader, synchronously, from inside `on_sample_rejected`, exactly
/// once. The production route it models: `take()` from inside the callback
/// (the natural reaction to "ring full") on a reader behind a
/// coherent-presentation barrier delivers the pending set through
/// `process_admitted` on the calling thread, and a still-full ring rejects
/// again. Driven through the test seam here.
struct ReentrantRejecter {
    subscriber:
        std::sync::Mutex<Option<std::sync::Weak<super::subscriber::ReaderSubscriber<Point>>>>,
    depth: std::sync::atomic::AtomicUsize,
    max_depth: std::sync::atomic::AtomicUsize,
    calls: std::sync::atomic::AtomicUsize,
}

impl crate::dds::listener::DataReaderListener<Point> for ReentrantRejecter {
    fn on_data_available(&self, _sample: &Point) {}

    fn on_sample_rejected(&self, _status: crate::dds::listener::SampleRejectedStatus) {
        use std::sync::atomic::Ordering;
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let depth = self.depth.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_depth.fetch_max(depth, Ordering::SeqCst);
        if call == 1 {
            let subscriber = self
                .subscriber
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            if let Some(subscriber) = subscriber {
                subscriber.report_sample_rejected_for_test(
                    crate::dds::listener::SampleRejectedReason::ResourceLimit,
                    None,
                );
            }
        }
        self.depth.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A dropped reader's ordered listener queues are closed: a status queued
/// for its listener after the drop is never told.
#[test]
fn a_dropped_reader_s_listener_queues_are_closed() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let _ = rt::init_slab_pool();
    let reader = ReaderBuilder::<Point>::new("ClosedQueues".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader");
    let queues = reader.listener_queues_for_test();
    assert_eq!(queues.len(), 3, "network rejected and lost, local rejected");
    drop(reader);
    for queue in queues {
        let told = Arc::new(AtomicBool::new(false));
        let t = Arc::clone(&told);
        assert!(queue
            .push(Box::new(move || t.store(true, Ordering::SeqCst)))
            .is_ok());
        queue.tell();
        assert!(
            !told.load(Ordering::SeqCst),
            "told after the reader was dropped"
        );
    }
}

/// A listener whose reaction rejects again on the same reader (see
/// `ReentrantRejecter`) is told of that rejection too, after its callback
/// returns, in order (`notices::Ordered`): never a deadlock, never a call
/// nested in its own. Watchdog-timed so a deadlock fails fast.
#[test]
fn a_listener_rejecting_again_from_inside_on_sample_rejected_does_not_deadlock() {
    use crate::dds::listener::{DataReaderListener, SampleRejectedReason};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let _ = rt::init_slab_pool();

    let topic = "test_sample_rejected_reentrant_listener";
    let reader = Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(QoS::reliable().keep_last(4))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let listener = Arc::new(ReentrantRejecter {
        subscriber: Mutex::new(None),
        depth: AtomicUsize::new(0),
        max_depth: AtomicUsize::new(0),
        calls: AtomicUsize::new(0),
    });
    let subscriber = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new(
            topic.to_string(),
            network_ring,
            status,
            None,
            None,
            Some(Arc::clone(&listener) as Arc<dyn DataReaderListener<Point>>),
            dispose,
            reorder,
        )
        .with_room(reader.network_room_for_test().cloned()),
    );
    *listener
        .subscriber
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = Some(Arc::downgrade(&subscriber));

    let (tx, rx) = std::sync::mpsc::channel();
    let subscriber_bg = Arc::clone(&subscriber);
    let _report_thread = std::thread::spawn(move || {
        subscriber_bg.report_sample_rejected_for_test(SampleRejectedReason::ResourceLimit, None);
        let _ = tx.send(());
    });
    if rx.recv_timeout(Duration::from_secs(2)).is_err() {
        panic!(
            "report_sample_rejected deadlocked: a listener re-entering the same reader's \
             rejection path from inside on_sample_rejected must get a nested delivery"
        );
    }
    assert_eq!(
        listener.calls.load(Ordering::SeqCst),
        2,
        "the outer rejection and the one it caused are both delivered"
    );
    assert_eq!(
        listener.max_depth.load(Ordering::SeqCst),
        1,
        "the second is delivered after the first callback returned"
    );
}

/// A `WaitsetSignal` hook (`core::rt::waitset::WaitsetSignal`, a public
/// trait registered through the public `Condition::add_waitset_signal`)
/// runs on the thread that raises the status. A hook that consumes the
/// status it was woken for, `get_sample_rejected_status()` from inside
/// `signal()`, must not deadlock against the rejection raising it: the
/// bit is raised under the reader's rejection state lock, the hooks run
/// only after that lock is released.
struct StatusReadingSignal {
    reader: std::sync::Arc<super::DataReader<Point>>,
    seen: std::sync::Mutex<Vec<crate::dds::listener::SampleRejectedStatus>>,
}

impl crate::core::rt::waitset::WaitsetSignal for StatusReadingSignal {
    fn signal(&self) {
        let status = self.reader.get_sample_rejected_status();
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(status);
    }

    fn id(&self) -> u64 {
        0x5A11
    }
}

/// See `StatusReadingSignal`. Watchdog-timed so a deadlock fails fast.
#[test]
fn a_signal_hook_reading_the_status_from_inside_signal_does_not_deadlock() {
    use crate::core::rt::waitset::WaitsetSignal;
    use crate::dds::listener::SampleRejectedReason;
    use crate::dds::{Condition as _, StatusMask};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let _ = rt::init_slab_pool();

    let topic = "test_sample_rejected_signal_hook_reads_status";
    let reader = Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(QoS::reliable().keep_last(4))
            .network_ring_for_test()
            .build()
            .expect("reliable reader with a test network ring should build"),
    );
    let network_ring = Arc::clone(
        reader
            .network_ring_for_test()
            .expect("network_ring_for_test() should provide a ring"),
    );
    let status = reader.get_status_condition();
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    let sample_rejected = reader.sample_rejected_for_test();
    let subscriber = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            topic.to_string(),
            network_ring,
            Arc::clone(&status),
            None,
            None,
            None,
            dispose,
            reorder,
            super::subscriber::CoherentConfig::default(),
            None,
            None,
            sample_rejected,
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            None,
            None,
            #[cfg(feature = "security")]
            None,
        )
        .with_room(reader.network_room_for_test().cloned()),
    );

    status.set_enabled_statuses(StatusMask::SAMPLE_REJECTED);
    let hook = Arc::new(StatusReadingSignal {
        reader: Arc::clone(&reader),
        seen: Mutex::new(Vec::new()),
    });
    status.add_waitset_signal(Arc::clone(&hook) as Arc<dyn WaitsetSignal>);

    let (tx, rx) = std::sync::mpsc::channel();
    let subscriber_bg = Arc::clone(&subscriber);
    let _report_thread = std::thread::spawn(move || {
        subscriber_bg.report_sample_rejected_for_test(SampleRejectedReason::ResourceLimit, None);
        let _ = tx.send(());
    });
    if rx.recv_timeout(Duration::from_secs(2)).is_err() {
        panic!(
            "report_sample_rejected deadlocked: a WaitSet signal hook reading \
             get_sample_rejected_status() from inside signal() must not deadlock against \
             the rejection that raised the bit"
        );
    }

    let seen = hook.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        seen.len(),
        1,
        "the enabled SAMPLE_REJECTED must signal the hook exactly once"
    );
    assert_eq!(
        seen[0].total_count_change, 1,
        "the hook consumed the rejection that woke it"
    );
    assert!(
        !status
            .get_active_statuses()
            .contains(StatusMask::SAMPLE_REJECTED),
        "consumed from inside the hook: nothing is left pending"
    );
}

/// `TopicRegistry::heartbeat_handlers` never expired its entries before
/// `HeartbeatHandlerToken` existed: every RELIABLE reader built against a
/// shared registry (e.g. a reconnect loop rebuilding the same reader) left
/// one more dead handler behind, all still reachable from
/// `deliver_heartbeat`'s broadcast loop. The smallest setup that registers
/// a handler is a RELIABLE reader with a registry and no transport/
/// participant (see `builder.rs`'s `_ => Arc::new(ReaderHeartbeatHandler::new(..))`
/// arm) -- no live socket or discovery needed to prove the token's lifecycle.
#[test]
fn dropping_a_reliable_reader_unregisters_its_heartbeat_handler() {
    let _ = rt::init_slab_pool();
    let registry = std::sync::Arc::new(crate::engine::TopicRegistry::new());
    let before = registry.heartbeat_handler_count();

    let reader = ReaderBuilder::<Point>::new("test_heartbeat_token_drop".to_string())
        .qos(QoS::reliable())
        .with_registry(std::sync::Arc::clone(&registry))
        .build()
        .expect("reliable reader without transport/participant should build");

    assert_eq!(
        registry.heartbeat_handler_count(),
        before + 1,
        "building a RELIABLE reader against a registry must register a heartbeat handler"
    );

    drop(reader);
    assert_eq!(
        registry.heartbeat_handler_count(),
        before,
        "dropping the reader must unregister its heartbeat handler"
    );
}

#[test]
fn take_deduplicates_replay_scenario() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    // Write 3 messages (goes through merger -> reader ring)
    let msgs = [
        Point { x: 1, y: 10 },
        Point { x: 2, y: 20 },
        Point { x: 3, y: 30 },
    ];
    for msg in &msgs {
        writer.write(msg).expect("write should succeed");
    }

    // Simulate TRANSIENT_LOCAL replay: push duplicate entries with same seqs into ring.
    // The writer starts at seq=1, so writes produce seq 1, 2, 3.
    let slab_pool = rt::get_slab_pool();
    let ring = reader.ring_for_test();
    for (i, msg) in msgs.iter().enumerate() {
        let seq = (i as u32) + 1; // match writer's seq numbering
        let mut buf = vec![0u8; 256];
        let len = msg
            .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
            .expect("encode should succeed");
        let (handle, _metric) = slab_pool
            .reserve_and_write(&buf[..len], crate::core::rt::Claim::Reader)
            .expect("slab reserve");
        // Test uses 256-byte buffer, but clamp defensively per IndexEntry protocol
        let entry = IndexEntry::new(seq, handle, len.min(u32::MAX as usize) as u32);
        ring.push(entry);
    }

    // take() pumps ring -> cache (dedup rejects duplicates), then takes from cache
    let mut received = Vec::new();
    while let Ok(Some(msg)) = reader.take() {
        received.push(msg);
    }

    assert_eq!(
        received.len(),
        3,
        "Should get exactly 3 messages, not 6 (dedup should reject replay duplicates)"
    );
    assert_eq!(received[0], Point { x: 1, y: 10 });
    assert_eq!(received[1], Point { x: 2, y: 20 });
    assert_eq!(received[2], Point { x: 3, y: 30 });
}

#[test]
fn late_writer_lifespan_registration_invalidates_probe_cache() {
    // Guards the epoch-gated writer-lifespan probe in pump_ring_to_cache:
    // a reader that already probed the registry (and cached "no finite
    // lifespan known") must re-probe after register_writer_lifespan bumps
    // the epoch, adopting a late-registered finite lifespan on the very
    // next pump (startup-race close, DDS v1.4 2.2.3.16).
    let _ = rt::init_slab_pool();

    let registry = std::sync::Arc::new(crate::engine::TopicRegistry::new());

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("lifespan_epoch".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");

    let reader = ReaderBuilder::<Point>::new("lifespan_epoch".to_string())
        .qos(QoS::best_effort())
        .with_registry(std::sync::Arc::clone(&registry))
        .build()
        .expect("reader build should succeed");

    reader.bind_to_writer(writer.merger());

    // First take: probes the registry (nothing registered yet), caches the
    // current epoch, and the sample flows through with lifespan infinite.
    writer
        .write(&Point { x: 1, y: 1 })
        .expect("write should succeed");
    let first = reader
        .take()
        .expect("take should not error")
        .expect("sample should be delivered while lifespan is infinite");
    assert_eq!(first.x, 1);

    // Late registration, as if SEDP announced the writer's Lifespan after
    // the reader already probed. The epoch bump must invalidate the cached
    // "no lifespan" answer.
    registry.register_writer_lifespan_of("lifespan_epoch", [0x77; 16], 1); // 1 ns

    writer
        .write(&Point { x: 2, y: 2 })
        .expect("write should succeed");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = reader.take().expect("take should not error");
    assert!(
        second.is_none(),
        "reader must re-probe after the epoch bump and expire the sample via the 1ns lifespan"
    );
}

/// A departed writer's lifespan is kept, whatever the reader took, until the
/// writer is announced again; and at most `MAX_DEPARTED_LIFESPANS` of them,
/// the oldest dropped first.
#[test]
fn a_departed_writers_lifespan_is_kept_until_the_writer_is_announced_again() {
    let departed = super::subscriber::DepartedLifespans::new();
    let (first, second) = ([0x51; 16], [0x52; 16]);
    departed.record(first, 7);
    departed.record(second, 9);
    assert_eq!(departed.lifespan_of(&first), Some(7));
    departed.forget(&first);
    assert_eq!(departed.lifespan_of(&first), None, "announced again");
    assert_eq!(departed.lifespan_of(&second), Some(9), "still departed");

    for n in 0..1024u32 {
        let mut writer = [0x60; 16];
        writer[12..].copy_from_slice(&n.to_be_bytes());
        departed.record(writer, 1);
    }
    assert_eq!(
        departed.lifespan_of(&second),
        None,
        "the oldest copy goes past the bound"
    );
    let mut newest = [0x60; 16];
    newest[12..].copy_from_slice(&1023u32.to_be_bytes());
    assert_eq!(departed.lifespan_of(&newest), Some(1));
}

/// A writer's lifespan record goes with the writer (its endpoint dispose, or
/// its participant's departure, both through `notify_writer_dispose`); the
/// 1.4 form of the registration, which knows no writer, still records the
/// topic's smallest.
#[test]
#[allow(deprecated)]
fn a_writers_lifespan_record_goes_with_the_writer() {
    let registry = crate::engine::TopicRegistry::new();
    let writer = [0x41; 16];
    registry.register_writer_lifespan_of("gone", writer, 5);
    assert_eq!(registry.writer_lifespan(&writer), Some(5));
    registry.notify_writer_dispose(writer, crate::engine::subscriber::DisposeKind::Unregistered);
    assert_eq!(registry.writer_lifespan(&writer), None);
    assert!(
        !registry.looks_up_writer_lifespans(),
        "the last finite lifespan gone, the take path skips the lookup"
    );

    registry.register_writer_lifespan("topic_only", 7);
    assert_eq!(
        registry.min_writer_lifespan_for_topic("topic_only"),
        Some(7)
    );
}

/// LIFESPAN is a DataWriter QoS (DDS v1.4 Sec.2.2.3.16): a sample expires
/// by the lifespan of the writer that wrote it. Two writers on one topic, one
/// announcing a 1 ns lifespan: the other one's samples are delivered, its
/// own expire. The lifespan is kept per writer: a per-TOPIC value (the
/// smallest of the topic) would expire every writer's samples by it.
#[test]
fn a_writers_lifespan_expires_its_own_samples_and_no_other_writers() {
    let _ = rt::init_slab_pool();
    let registry = std::sync::Arc::new(crate::engine::TopicRegistry::new());
    let reader = ReaderBuilder::<Point>::new("lifespan_per_writer".to_string())
        .qos(QoS::best_effort())
        .with_registry(std::sync::Arc::clone(&registry))
        .build()
        .expect("reader build should succeed");

    let short_lived: [u8; 16] = [0x31; 16];
    let long_lived: [u8; 16] = [0x32; 16];
    registry.register_writer_lifespan_of("lifespan_per_writer", short_lived, 1); // 1 ns

    let push = |writer: [u8; 16], seq: u32, x: i32| {
        let sample_bytes = encoded_point(x, x);
        let mut payload = Vec::with_capacity(16 + sample_bytes.len());
        payload.extend_from_slice(&writer);
        payload.extend_from_slice(&sample_bytes);
        let (handle, _metric) = rt::get_slab_pool()
            .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
            .expect("slab reserve");
        // Written a millisecond ago, by the writer's own clock.
        let written = crate::telemetry::metrics::current_time_ns().saturating_sub(1_000_000);
        let mut entry = IndexEntry::with_timestamp(seq, handle, payload.len() as u32, written);
        entry.mark_source_ts();
        entry.mark_guid_prefix();
        assert!(reader.ring_for_test().push(entry));
    };
    push(short_lived, 1, 1);
    push(long_lived, 1, 2);

    let delivered = reader.take().expect("take should not error");
    assert_eq!(
        delivered,
        Some(Point { x: 2, y: 2 }),
        "the long-lived writer's sample must survive the other writer's lifespan"
    );
    assert_eq!(
        reader.take().expect("take"),
        None,
        "and the short-lived one expired"
    );
}

// ---------------------------------------------------------------------------
// take_with_info(): per-sample metadata on the intra and network transit
// paths. take() itself keeps its exact signature and behavior (covered by
// every test above); these prove the sibling recovers the metadata that
// take() discards.
// ---------------------------------------------------------------------------

#[test]
fn take_with_info_reports_intra_source_timestamp() {
    let _ = rt::init_slab_pool();

    let writer = crate::dds::writer::WriterBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer build should succeed");
    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");
    reader.bind_to_writer(writer.merger());

    let before_ns = crate::telemetry::metrics::current_time_ns();
    writer
        .write(&Point { x: 5, y: 6 })
        .expect("write should succeed");

    let (msg, info) = reader
        .take_with_info()
        .expect("take_with_info should not error")
        .expect("should receive message");
    assert_eq!(msg, Some(Point { x: 5, y: 6 }));

    // The intra path stamps write_start_ns: a true source timestamp.
    let source = info
        .source_timestamp_ns
        .expect("intra samples carry a source timestamp");
    assert!(
        source >= before_ns,
        "source timestamp must be the write-side clock"
    );
    assert!(info.reception_timestamp_ns >= source);
    // Ring identity is not mapped back to a GUID in v1.
    assert_eq!(info.writer_guid, None);
    assert_eq!(info.sequence_number, 1, "first write is writer seq 1");
    assert!(info.instance_handle.is_nil(), "keyless topic");
    assert!(info.valid_data);
}

/// Decode-the-bytes proof for the network metadata transit: build a ring
/// entry EXACTLY the way `ReaderSubscriber::process_admitted` does for a
/// known writer (16-byte GUID prefix ahead of the encoded sample in the
/// slab payload, GUID_PREFIX + SOURCE_TS flags on the entry) and assert
/// `take_with_info()` recovers every field. No sockets: the entry is
/// pushed straight into the reader's ring.
#[test]
fn take_with_info_decodes_guid_prefixed_network_entry() {
    let _ = rt::init_slab_pool();

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    let writer_guid: [u8; 16] = [
        0x01, 0x0f, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x00, 0x00, 0x00,
        0x02,
    ];
    let source_ts_ns = 1_234_567_890u64;

    let sample_bytes = encoded_point(21, 42);
    let mut payload = Vec::with_capacity(16 + sample_bytes.len());
    payload.extend_from_slice(&writer_guid);
    payload.extend_from_slice(&sample_bytes);

    let slab_pool = rt::get_slab_pool();
    let (handle, _metric) = slab_pool
        .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
        .expect("slab reserve");
    let mut entry = IndexEntry::with_timestamp(1, handle, payload.len() as u32, source_ts_ns);
    entry.mark_source_ts();
    entry.mark_guid_prefix();
    assert!(reader.ring_for_test().push(entry));

    let (msg, info) = reader
        .take_with_info()
        .expect("take_with_info should not error")
        .expect("should receive message");
    assert_eq!(msg, Some(Point { x: 21, y: 42 }));
    assert_eq!(info.writer_guid, Some(writer_guid));
    assert_eq!(info.source_timestamp_ns, Some(source_ts_ns));
    assert!(info.reception_timestamp_ns > source_ts_ns);
    assert_eq!(info.sequence_number, 1);
    assert!(info.valid_data);
}

/// A network entry whose datagram carried no INFO_TS: `process_admitted`
/// stamps reception time and leaves SOURCE_TS unset, so the info must
/// report `source_timestamp_ns = None` and hand back that exact
/// reception stamp (no pop-time restamp).
#[test]
fn take_with_info_without_info_ts_reports_reception_only() {
    let _ = rt::init_slab_pool();

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    let sample_bytes = encoded_point(1, 2);
    let slab_pool = rt::get_slab_pool();
    let (handle, _metric) = slab_pool
        .reserve_and_write(&sample_bytes, crate::core::rt::Claim::Reader)
        .expect("slab reserve");
    let reception_ns = 55_555u64;
    let entry = IndexEntry::with_timestamp(3, handle, sample_bytes.len() as u32, reception_ns);
    assert!(reader.ring_for_test().push(entry));

    let (msg, info) = reader
        .take_with_info()
        .expect("take_with_info should not error")
        .expect("should receive message");
    assert_eq!(msg, Some(Point { x: 1, y: 2 }));
    assert_eq!(info.source_timestamp_ns, None);
    assert_eq!(info.reception_timestamp_ns, reception_ns);
    assert_eq!(info.writer_guid, None);
    assert_eq!(info.sequence_number, 3);
}

/// The legacy `try_take` path is the only other decode site of ring
/// entries: it must skip the GUID prefix and return the sample bytes
/// (it has no metadata surface, so the GUID is simply dropped).
#[test]
#[allow(deprecated)]
fn legacy_try_take_skips_guid_prefix() {
    let _ = rt::init_slab_pool();

    let reader = ReaderBuilder::<Point>::new("test".to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("reader build should succeed");

    let writer_guid = [0x42u8; 16];
    let sample_bytes = encoded_point(3, 4);
    let mut payload = Vec::with_capacity(16 + sample_bytes.len());
    payload.extend_from_slice(&writer_guid);
    payload.extend_from_slice(&sample_bytes);

    let slab_pool = rt::get_slab_pool();
    let (handle, _metric) = slab_pool
        .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
        .expect("slab reserve");
    let mut entry = IndexEntry::with_timestamp(1, handle, payload.len() as u32, 1);
    entry.mark_guid_prefix();
    assert!(reader.ring_for_test().push(entry));

    let msg = reader
        .try_take()
        .expect("try_take should not error")
        .expect("should receive message");
    assert_eq!(msg, Point { x: 3, y: 4 });
}

// ---------------------------------------------------------------------------
// DATA_AVAILABLE clear vs. a racing push (lost-wakeup window).
//
// The producer's sequence is ring push, then status store, then WaitSet
// signal. A reader that observed the ring empty and then clears the
// status can overwrite a store that landed in between; the next
// WaitSet::wait consumes the driver bit, sees the condition untriggered
// and blocks with a sample sitting in the ring. The deterministic tests
// below interpose the write in that exact window through the one-shot
// `idle_clear_hook` seam; the stress test lets two threads race for it.
//
// What each kind proves. The seam runs the producer sequence on the
// reader's own thread, so every store it makes is sequenced before the
// clear: these tests pin the check-then-act logic (a clear that swaps a
// raised wake word re-checks that word's source and re-raises) and
// would fail against a plain-store clear, but they exercise none of the
// cross-thread ordering the fix's Acquire/Release argument rests on.
// They are not a memory-model proof. The per-word argument (one plain
// Release store per producer, a swap per word on the reader side) lives
// in the `WakeWords` and `clear_data_available_if_idle` docs, not here.
// The stress tests are the cross-thread evidence: no seam, a stall
// detector, one writer thread first, then two writer threads for the
// two-word step, then a pumping thread for the cache.
// ---------------------------------------------------------------------------

/// Replay the producer sequence of `TopicMerger::push` for the primary
/// ring exactly: ring push, then the plain store of `WakeWord::Primary`
/// (`raise_data_available`), which signals the WaitSet. Used instead of
/// `DataWriter::write` inside the seam: the writer is not `Sync`, and
/// the seam only accepts a `Send` closure.
fn replay_producer_push(ring: &rt::IndexRing, status: &crate::dds::StatusCondition, sample: Point) {
    let payload = encoded_point(sample.x, sample.y);
    let (handle, _metric) = rt::get_slab_pool()
        .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
        .expect("slab reserve");
    let entry = IndexEntry::with_timestamp(1_000, handle, payload.len() as u32, 1);
    assert!(ring.push(entry), "ring push");
    status.raise_data_available(super::runtime::WakeWord::Primary.index());
}

/// Current value of one of the reader's wake words.
fn wake_word(reader: &super::DataReader<Point>, word: super::runtime::WakeWord) -> u32 {
    reader
        .get_status_condition()
        .wake_words()
        .load(word.index())
}

/// Build a bound writer/reader pair on `topic` with the given QoS.
fn bound_pair(
    topic: &str,
    qos: QoS,
) -> (
    crate::dds::writer::DataWriter<Point>,
    std::sync::Arc<super::DataReader<Point>>,
) {
    let _ = rt::init_slab_pool();
    let writer = crate::dds::writer::WriterBuilder::<Point>::new(topic.to_string())
        .qos(qos.clone())
        .build()
        .expect("writer build should succeed");
    let reader = std::sync::Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(qos)
            .build()
            .expect("reader build should succeed"),
    );
    reader.bind_to_writer(writer.merger());
    (writer, reader)
}

/// Run `drain` (some empty-observing reader operation) with a producer
/// push of `racing` interposed between the reader's emptiness
/// observation and its status clear, then assert the wake-up survived:
/// the condition is triggered, a WaitSet returns without waiting, and
/// the sample is there.
fn assert_racing_push_keeps_data_available(
    reader: &std::sync::Arc<super::DataReader<Point>>,
    racing: Point,
    drain: impl FnOnce(&super::DataReader<Point>),
) {
    use crate::dds::Condition;
    use std::sync::Arc;
    use std::time::Duration;

    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&**reader).expect("attach reader");

    let ring = Arc::clone(reader.ring_for_test());
    let status = reader.get_status_condition();
    reader.set_idle_clear_hook(move || replay_producer_push(&ring, &status, racing));

    drain(reader);

    assert!(
        reader.get_status_condition().get_trigger_value(),
        "DATA_AVAILABLE must survive a push that raced the clear"
    );
    // The clear swapped the producer's RAISED away, found the push in
    // the re-check and put the trigger back with its own bit.
    assert_eq!(
        wake_word(reader, super::runtime::WakeWord::Primary),
        crate::dds::condition::WAKE_RERAISED,
        "the primary word carries the reader's re-raise"
    );
    let triggered = waitset
        .wait(Some(Duration::from_millis(200)))
        .expect("WaitSet must not block on a pending sample");
    assert_eq!(triggered.len(), 1);
    let got = reader
        .take()
        .expect("take should not error")
        .expect("the racing sample must be pending");
    assert_eq!(got, racing);

    // The empty take after the drain reads the re-raise alone,
    // re-checks, finds nothing, and the word settles.
    assert_eq!(reader.take().expect("take"), None);
    assert_eq!(wake_word(reader, super::runtime::WakeWord::Primary), 0);
    assert!(!reader.get_status_condition().get_trigger_value());
}

/// take() on the single-ring fast path: the pop returned None, the
/// cache was empty, the clear follows. Mirrors the blocking-arm loop of
/// the cross-thread latency benchmark (wait, take Some, wait, take None).
#[test]
fn take_keeps_data_available_when_a_push_races_the_clear() {
    let (writer, reader) = bound_pair("wakeup-take", QoS::best_effort().keep_last(1));

    // Prime like the benchmark loop: one delivered sample leaves the
    // condition triggered, the following empty take is the one that clears.
    writer.write(&Point { x: 1, y: 1 }).expect("write");
    assert_eq!(reader.take().expect("take"), Some(Point { x: 1, y: 1 }));

    assert_racing_push_keeps_data_available(&reader, Point { x: 2, y: 2 }, |r| {
        assert_eq!(r.take().expect("take"), None);
    });
}

/// Same window on the K>1 merge path (two bound writers, so the pump
/// goes through `pump_merge` and the merge-branch clear).
#[test]
fn merged_take_keeps_data_available_when_a_push_races_the_clear() {
    let (writer, reader) = bound_pair("wakeup-merge", QoS::best_effort().keep_last(1));
    let second = crate::dds::writer::WriterBuilder::<Point>::new("wakeup-merge".to_string())
        .qos(QoS::best_effort().keep_last(1))
        .build()
        .expect("second writer build should succeed");
    reader.bind_to_writer(second.merger());

    writer.write(&Point { x: 1, y: 1 }).expect("write");
    assert_eq!(reader.take().expect("take"), Some(Point { x: 1, y: 1 }));

    assert_racing_push_keeps_data_available(&reader, Point { x: 2, y: 2 }, |r| {
        assert_eq!(r.take().expect("take"), None);
    });
}

/// Same window after take_all() drained everything.
#[test]
fn take_all_keeps_data_available_when_a_push_races_the_clear() {
    let (writer, reader) = bound_pair("wakeup-take-all", QoS::best_effort().keep_last(4));

    writer.write(&Point { x: 1, y: 1 }).expect("write");
    assert_racing_push_keeps_data_available(&reader, Point { x: 2, y: 2 }, |r| {
        assert_eq!(r.take_all().expect("take_all"), vec![Point { x: 1, y: 1 }]);
    });
}

/// Same window on the read() pump (`pump_ring_to_cache` clear site).
#[test]
fn read_keeps_data_available_when_a_push_races_the_clear() {
    let (_writer, reader) = bound_pair("wakeup-read", QoS::best_effort().keep_last(4));

    assert_racing_push_keeps_data_available(&reader, Point { x: 2, y: 2 }, |r| {
        assert_eq!(r.read().expect("read"), None);
    });
}

/// Same window on the legacy try_take() path, which takes like take(): its
/// clear follows the empty take after the last sample.
#[test]
#[allow(deprecated)]
fn try_take_keeps_data_available_when_a_push_races_the_clear() {
    let (writer, reader) = bound_pair("wakeup-try-take", QoS::best_effort().keep_last(4));

    writer.write(&Point { x: 1, y: 1 }).expect("write");
    assert_racing_push_keeps_data_available(&reader, Point { x: 2, y: 2 }, |r| {
        assert_eq!(r.try_take().expect("try_take"), Some(Point { x: 1, y: 1 }));
        assert_eq!(r.try_take().expect("try_take"), None);
    });
}

/// Two threads racing for the window: the reader blocks on a WaitSet
/// and drains until take() returns None; the writer sends the next
/// sample the moment the previous one is acknowledged, so its push
/// lands right around the reader's empty take on every iteration.
///
/// Pacing the writer instead (the benchmark's shape) hits the window
/// about once per ten thousand samples, and detecting the hit needs a
/// latency bound that a loaded host breaks on its own. Here a hit is
/// unambiguous: the reader never acknowledges, the writer's bounded
/// wait expires, and the run reports the sequence number it stalled on.
/// With the clear fixed, the reader re-raises DATA_AVAILABLE itself and
/// no acknowledgement is ever late by more than a scheduling quantum.
#[test]
fn waitset_reader_never_stalls_behind_a_racing_write() {
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const SAMPLES: i32 = 20_000;
    const STOP: i32 = -1;

    let (writer, reader) = bound_pair("wakeup-stress", QoS::best_effort().keep_last(4));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    let acked = Arc::new(AtomicI32::new(-1));
    let reader_thread = std::thread::spawn({
        let acked = Arc::clone(&acked);
        let reader = Arc::clone(&reader);
        move || -> (usize, bool) {
            let mut received = 0usize;
            loop {
                // Longer than the writer's patience: a stalled reader is
                // rescued by the STOP write and reports normally.
                if waitset.wait(Some(Duration::from_secs(20))).is_err() {
                    return (received, true);
                }
                while let Some(sample) = reader.take().expect("take") {
                    if sample.x == STOP {
                        return (received, false);
                    }
                    received += 1;
                    acked.store(sample.x, Ordering::Release);
                }
            }
        }
    });

    let mut stalled_at: Option<i32> = None;
    for seq in 0..SAMPLES {
        writer.write(&Point { x: seq, y: 0 }).expect("write");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut spins = 0u32;
        while acked.load(Ordering::Acquire) != seq {
            if Instant::now() >= deadline {
                stalled_at = Some(seq);
                break;
            }
            spins = spins.wrapping_add(1);
            if spins.is_multiple_of(64) {
                std::thread::yield_now();
            } else {
                std::hint::spin_loop();
            }
        }
        if stalled_at.is_some() {
            break;
        }
    }
    writer.write(&Point { x: STOP, y: 0 }).expect("stop write");

    let (received, timed_out) = reader_thread.join().expect("reader thread");
    assert_eq!(
        stalled_at, None,
        "reader stalled behind a write that raced its DATA_AVAILABLE clear"
    );
    assert!(!timed_out, "reader WaitSet timed out");
    assert_eq!(
        received, SAMPLES as usize,
        "best-effort KeepLast(4) lost samples"
    );
}

/// The re-raise is itself a write to the word, and the next producer
/// store and the next clear come after it. Seam replay of the sequence
/// behind the `fetch_or(RERAISED)` re-raise: a clear reads a producer's
/// store and re-raises; the producer stores again for a further sample
/// (overwriting the re-raise with RAISED); the clear after draining the
/// first must find the further one, and the clear after draining that
/// one, which reads nothing but the reader's own re-raise, must clear
/// for good. Every store here is sequenced on the reader's thread (see
/// the section comment), so what this pins is the check-then-act logic
/// across consecutive clears, not the release-sequence step.
#[test]
fn second_clear_after_a_re_raise_still_hands_the_next_sample_over() {
    use crate::dds::Condition;
    use std::sync::Arc;
    use std::time::Duration;

    let (writer, reader) = bound_pair("wakeup-re-raise", QoS::best_effort().keep_last(4));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");
    let ring = Arc::clone(reader.ring_for_test());
    let status = reader.get_status_condition();
    let hook = |sample: Point| {
        let ring = Arc::clone(&ring);
        let status = Arc::clone(&status);
        move || replay_producer_push(&ring, &status, sample)
    };

    // Prime: one delivered sample leaves the condition triggered, the
    // following empty take is the first clear.
    writer.write(&Point { x: 1, y: 1 }).expect("write");
    assert_eq!(reader.take().expect("take"), Some(Point { x: 1, y: 1 }));

    // First window: the clear reads the producer's store, finds the
    // raced sample and re-raises.
    reader.set_idle_clear_hook(hook(Point { x: 2, y: 2 }));
    assert_eq!(reader.take().expect("take"), None);
    assert!(status.get_trigger_value(), "first re-raise");

    // Draining the raced sample does not clear (the pop returned Some);
    // the empty take after it is the second clear, and the producer's
    // next store is interposed in its window. The re-raise before it
    // must not make this clear skip its re-check.
    assert_eq!(reader.take().expect("take"), Some(Point { x: 2, y: 2 }));
    reader.set_idle_clear_hook(hook(Point { x: 3, y: 3 }));
    assert_eq!(reader.take().expect("take"), None);
    assert!(status.get_trigger_value(), "second re-raise");
    let triggered = waitset
        .wait(Some(Duration::from_millis(200)))
        .expect("WaitSet must not block on a pending sample");
    assert_eq!(triggered.len(), 1);
    assert_eq!(
        reader.take().expect("take"),
        Some(Point { x: 3, y: 3 }),
        "the sample stored after the re-raise must not be stranded"
    );

    // Third clear: the last write to the status is this reader's own
    // re-raise and nothing is pending, so it clears for good and the
    // WaitSet blocks instead of spinning on a sticky re-raise.
    assert_eq!(reader.take().expect("take"), None);
    assert!(
        !status.get_trigger_value(),
        "nothing pending, nothing raised"
    );
    assert!(
        matches!(
            waitset.wait(Some(Duration::from_millis(50))),
            Err(crate::dds::Error::WouldBlock)
        ),
        "a re-raise with nothing behind it must not stick"
    );
    assert_eq!(reader.take().expect("take"), None);
}

// ---------------------------------------------------------------------------
// The same window, dispose producer. `ReaderSubscriber::on_dispose`
// queues an event (no ring push) through `DisposeQueue::push`, which
// raises `WakeWord::Dispose` itself, so the re-check for that word is
// the word's own previous value: every ring is empty when a dispose is
// what raced the clear. Same seam, same on-thread caveat as above.
// ---------------------------------------------------------------------------

fn dispose_event(seq: u64) -> super::subscriber::DisposeEvent {
    super::subscriber::DisposeEvent {
        key_hash: [0xAB; 16],
        kind: crate::engine::subscriber::DisposeKind::Disposed,
        seq,
        writer_guid: None,
        order_seq: seq,
        announced: false,
        read: false,
        from_local_writer: false,
        disposed_generation_count: 0,
        no_writers_generation_count: 0,
        source_timestamp_ns: None,
    }
}

/// A dispose of the instance the LOCAL samples belong to.
///
/// A keyless topic has exactly one instance and `DDS::compute_key`
/// returns the nil handle for it, so this event and every `Point`
/// written here concern the SAME instance. That matters: DDS orders
/// samples per instance, so a test using [`dispose_event`]'s unrelated
/// `0xAB` handle could never show an ordering violation - the two
/// streams would be independent by definition.
fn dispose_event_same_instance(seq: u64) -> super::subscriber::DisposeEvent {
    super::subscriber::DisposeEvent {
        key_hash: [0u8; 16],
        kind: crate::engine::subscriber::DisposeKind::Disposed,
        seq,
        writer_guid: None,
        order_seq: seq,
        announced: false,
        read: false,
        from_local_writer: false,
        disposed_generation_count: 0,
        no_writers_generation_count: 0,
        source_timestamp_ns: None,
    }
}

/// A dispose landing between the reader's emptiness observation and its
/// clear must keep DATA_AVAILABLE up: the WaitSet returns, take() has
/// nothing (no sample rides a dispose), and the event is waiting in
/// `get_dispose_events`.
#[test]
fn take_keeps_data_available_when_a_dispose_races_the_clear() {
    use crate::dds::Condition;
    use std::sync::Arc;
    use std::time::Duration;

    let (writer, reader) = bound_pair("wakeup-dispose", QoS::best_effort().keep_last(1));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    // Prime like the sample tests: one delivered sample leaves the
    // condition triggered, the following empty take is the one that clears.
    writer.write(&Point { x: 1, y: 1 }).expect("write");
    assert_eq!(reader.take().expect("take"), Some(Point { x: 1, y: 1 }));

    // Replay `on_dispose` exactly: the queue push raises the word.
    let queue = Arc::clone(reader.dispose_queue_for_test());
    reader.set_idle_clear_hook(move || queue.push(dispose_event(42)));

    // `take_with_info` is the accessor that can report an instance-state
    // change, so it is the one this test drives. The raced dispose must come
    // back OUT of it rather than being stranded behind a clear.
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the dispose that raced the clear must be delivered, not lost");
    assert!(data.is_none(), "an instance-state change carries no data");
    assert!(!info.valid_data, "and says so through valid_data");
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
    assert_eq!(info.instance_handle, super::InstanceHandle::new([0xAB; 16]));
    assert_eq!(info.sequence_number, 42);

    // Delivered means settled: the condition falls and the next wait blocks
    // instead of spinning, which is the whole point of delivering it.
    assert!(
        !reader.get_status_condition().get_trigger_value(),
        "a delivered instance-state change must settle the condition"
    );
    assert_eq!(
        wake_word(&reader, super::runtime::WakeWord::Dispose),
        0,
        "and settle the word it raised"
    );
    assert!(
        waitset.wait(Some(Duration::from_millis(200))).is_err(),
        "nothing is owed any more, so this must reach its timeout"
    );
}

/// An instance-state change is DELIVERED to the application through the normal
/// take path, and delivering it is what settles the condition it raised.
///
/// It must not sit on a side queue that only a Rust-only extension can drain:
/// `take()` could then never settle the condition and an ordinary wait/take
/// loop would spin at 100% CPU for as long as the event was there. Every C
/// binding would be in that position permanently, having no drain API at all.
#[test]
fn a_dispose_is_delivered_as_a_sample_and_then_settles() {
    use crate::dds::condition::WAKE_RAISED;
    use crate::dds::Condition;
    use std::time::Duration;

    let (_writer, reader) = bound_pair("wakeup-dispose-once", QoS::best_effort().keep_last(1));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    reader.dispose_queue_for_test().push(dispose_event(7));
    assert_eq!(
        wake_word(&reader, super::runtime::WakeWord::Dispose),
        WAKE_RAISED
    );
    let triggered = waitset
        .wait(Some(Duration::from_millis(200)))
        .expect("dispose wakes the reader");
    assert_eq!(triggered.len(), 1);

    // The application is TOLD what happened, through the standard accessor.
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the instance-state change must be delivered");
    assert!(data.is_none());
    assert!(!info.valid_data);
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
    assert_eq!(info.sequence_number, 7);

    // And now nothing is owed: no spin.
    assert!(!reader.get_status_condition().get_trigger_value());
    assert!(
        waitset.wait(Some(Duration::from_millis(200))).is_err(),
        "a consumed instance-state change must not keep waking the WaitSet"
    );
    assert_eq!(
        reader.take_with_info().expect("take_with_info"),
        None,
        "and it is consumed exactly once"
    );
}

/// An instance-state change must be ordered against the SAME instance's
/// data the way it arrived, and today it is not.
///
/// The sequence below is the ordinary instance lifecycle: a writer
/// publishes, disposes the instance, then publishes it again. Per-instance
/// order is the one thing DDS does promise about samples, and the second
/// write means the instance is ALIVE at the end.
///
/// `take_with_info` drains the cache before it ever looks at the
/// notification queue, so the application is handed the resurrection data
/// first and the dispose last, and concludes the instance is dead when it
/// is alive. Nothing recovers from that: the two facts arrive in the wrong
/// order with no marker saying so.
#[test]
fn an_instance_state_change_is_ordered_against_the_data_that_follows_it() {
    let (writer, reader) = bound_pair("dispose-ordering", QoS::best_effort().keep_last(4));

    // The instance is alive and carries a sample.
    writer.write(&Point { x: 1, y: 1 }).expect("write");
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the first sample");
    assert_eq!(data, Some(Point { x: 1, y: 1 }));
    assert!(info.valid_data);

    // The writer disposes it, and only THEN writes it again.
    reader
        .dispose_queue_for_test()
        .push(dispose_event_same_instance(10));
    writer.write(&Point { x: 2, y: 2 }).expect("write");

    // Arrival order was dispose, then data. That is what must come out.
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("something is owed");
    assert!(
        data.is_none() && !info.valid_data,
        "the dispose arrived BEFORE the second write and must be delivered \
         first; delivering the data first tells the application the instance \
         died after it was resurrected"
    );
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
    assert_eq!(info.instance_handle, super::InstanceHandle::nil());

    // ...and the resurrection data after it, so the instance reads ALIVE.
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the second sample");
    assert_eq!(data, Some(Point { x: 2, y: 2 }));
    assert!(info.valid_data);

    assert_eq!(reader.take_with_info().expect("take_with_info"), None);
}

/// A steady stream of data must not STARVE an instance-state change.
///
/// `take_with_info` consults the notification queue only when the pump and
/// the cache came back empty, so a reader that always has at least one
/// sample pending never reaches that branch. The notification is not
/// delayed by a bounded amount: it is withheld for as long as the topic
/// keeps producing, which on a periodic topic is for ever.
///
/// One sample per take, one write per take, is exactly a reader keeping
/// pace with a periodic writer - the ordinary case, not a corner.
#[test]
fn a_steady_stream_of_data_does_not_starve_an_instance_state_change() {
    let (writer, reader) = bound_pair("dispose-starvation", QoS::best_effort().keep_last(4));

    // The instance is disposed ONCE, up front. Everything after this point
    // is the application waiting to be told.
    reader
        .dispose_queue_for_test()
        .push(dispose_event_same_instance(1));

    for round in 0..100i32 {
        writer.write(&Point { x: round, y: round }).expect("write");
        let (data, info) = reader
            .take_with_info()
            .expect("take_with_info")
            .expect("a sample is always pending here");
        if data.is_none() {
            assert!(!info.valid_data);
            // Delivered. That is the behaviour this test wants.
            return;
        }
    }

    panic!(
        "100 takes went by with a notification queued and none was delivered; \
         a periodic writer withholds it for ever"
    );
}

/// `take()` and `take_with_info()` are documented as interchangeable
/// sample-for-sample. They are not: an empty `take()` DESTROYS every queued
/// instance-state change, so a reader that mixes the two - a helper that
/// polls with `take()`, an app that falls back to it - silently loses state
/// changes the next `take_with_info()` was going to report.
#[test]
fn an_empty_take_does_not_destroy_a_state_change_owed_to_take_with_info() {
    let (_writer, reader) = bound_pair("dispose-mixed-accessors", QoS::best_effort().keep_last(4));

    reader
        .dispose_queue_for_test()
        .push(dispose_event_same_instance(5));

    // A plain take() finds no DATA and returns None, as it must: it cannot
    // express an instance-state change in its return type.
    assert_eq!(reader.take().expect("take"), None);

    // But the change is still owed to an accessor that CAN report it.
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the state change survives an accessor that could not report it");
    assert!(data.is_none() && !info.valid_data);
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
}

/// The exact shape `examples/shape_main.rs` uses: drain data with `take()`
/// until it returns `None`, THEN read the lifecycle transitions with
/// `get_dispose_events()`.
///
/// Step 1 made the terminal `take()` drain the notification queue to kill a
/// 100% CPU spin. That drain destroys precisely what the next call was about
/// to read, so our OMG conformance binary stops printing its
/// NOT_ALIVE_DISPOSED / NOT_ALIVE_NO_WRITERS lines - which is what the OMG
/// dispose and unregister checks scan for.
#[test]
fn take_until_none_then_get_dispose_events_still_sees_the_transitions() {
    let (writer, reader) = bound_pair("dispose-shape-main", QoS::best_effort().keep_last(4));

    writer.write(&Point { x: 1, y: 1 }).expect("write");
    reader
        .dispose_queue_for_test()
        .push(dispose_event_same_instance(3));

    // shape_main's drain loop, verbatim in shape.
    while let Ok(Some(_)) = reader.take() {}

    #[allow(deprecated)]
    let events = reader.get_dispose_events();
    assert_eq!(
        events.len(),
        1,
        "the terminal take() must not eat the transition the conformance app \
         reads on the very next line"
    );
}

/// The invariant the announce mechanism exists to protect: a wait/take loop
/// that can never report an instance-state change must still come to rest.
///
/// This is the 100% CPU spin the whole change set was opened to kill, and it
/// is the reason the first cut destroyed the events. Announcing settles the
/// same debt without destroying anything, so this must still hold - and the
/// transition must still be there afterwards, which is the half the first cut
/// got wrong.
#[test]
fn a_take_only_loop_comes_to_rest_without_losing_the_transition() {
    use crate::dds::Condition;
    use std::time::Duration;

    let (_writer, reader) = bound_pair("dispose-no-spin", QoS::best_effort().keep_last(4));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    reader
        .dispose_queue_for_test()
        .push(dispose_event_same_instance(11));

    // The transition wakes the loop exactly once.
    let triggered = waitset
        .wait(Some(Duration::from_millis(200)))
        .expect("the transition must wake a waiting reader");
    assert_eq!(triggered.len(), 1);

    // The loop takes what it can express, which is nothing, and that
    // observation settles the wake-up debt.
    assert_eq!(reader.take().expect("take"), None);
    assert!(
        !reader.get_status_condition().get_trigger_value(),
        "an announced transition must not keep the condition raised, or the \
         loop spins at 100% CPU for as long as it is ignored"
    );
    assert!(
        waitset.wait(Some(Duration::from_millis(200))).is_err(),
        "and the next wait must block instead of returning immediately"
    );

    // ...while the transition itself is still owed to an accessor that can
    // carry it.
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("announcing must not consume the transition");
    assert!(data.is_none() && !info.valid_data);
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
    assert_eq!(info.sequence_number, 11);
}

/// A NEW transition on an already-announced instance re-arms the wake-up.
/// Otherwise a single ignored `take()` would mute that instance for the rest
/// of the reader's life.
#[test]
fn a_later_transition_re_arms_an_announced_instance() {
    use crate::dds::Condition;

    let (_writer, reader) = bound_pair("dispose-rearm", QoS::best_effort().keep_last(4));

    reader
        .dispose_queue_for_test()
        .push(dispose_event_same_instance(1));
    assert_eq!(reader.take().expect("take"), None);
    assert!(!reader.get_status_condition().get_trigger_value());

    // The same instance transitions again (disposed, then unregistered).
    reader
        .dispose_queue_for_test()
        .push(super::subscriber::DisposeEvent {
            key_hash: [0u8; 16],
            kind: crate::engine::subscriber::DisposeKind::Unregistered,
            seq: 2,
            writer_guid: None,
            order_seq: 2,
            announced: false,
            read: false,
            from_local_writer: false,
            disposed_generation_count: 0,
            no_writers_generation_count: 0,
            source_timestamp_ns: None,
        });
    assert!(
        reader.get_status_condition().get_trigger_value(),
        "new information owes a new wake-up"
    );

    let (_, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the merged transition");
    assert_eq!(
        info.instance_state,
        super::InstanceState::NotAliveDisposed,
        "disposed and unregistered merge to DISPOSED, the only DDS answer"
    );
}

/// Every accessor that returns a `T`-shaped value must come to rest, not
/// just `take()`.
///
/// `take_all()`, `take_instance*()` and `read()` all reach the idle clear
/// without being able to report an instance state, so each one is its own
/// copy of the 100% CPU loop if it does not announce. Covering `take()` alone
/// would leave the same bug in the others, which is why the announce lives at
/// the single point they share.
#[test]
fn every_data_shaped_accessor_comes_to_rest_on_a_pending_transition() {
    use crate::dds::Condition;

    // One reader per accessor: announcing is idempotent, so reusing a reader
    // would let the first accessor mask the others.
    type Drain = Box<dyn Fn(&super::DataReader<Point>)>;
    let cases: Vec<(&str, Drain)> = vec![
        (
            "take_all",
            Box::new(|r: &super::DataReader<Point>| {
                r.take_all().expect("take_all");
            }),
        ),
        (
            "take_instance",
            Box::new(|r: &super::DataReader<Point>| {
                r.take_instance(super::InstanceHandle::nil())
                    .expect("take_instance");
            }),
        ),
        (
            "read",
            Box::new(|r: &super::DataReader<Point>| {
                r.read().expect("read");
            }),
        ),
        (
            "try_take",
            Box::new(|r: &super::DataReader<Point>| {
                // Deprecated since 0.9.0, still public, still able to spin.
                #[allow(deprecated)]
                let _ = r.try_take();
            }),
        ),
    ];

    for (name, drain) in cases {
        let (_writer, reader) = bound_pair(
            &format!("dispose-rest-{name}"),
            QoS::best_effort().keep_last(4),
        );
        reader
            .dispose_queue_for_test()
            .push(dispose_event_same_instance(21));
        assert!(
            reader.get_status_condition().get_trigger_value(),
            "{name}: the transition must raise the condition first"
        );

        drain(&reader);

        assert!(
            !reader.get_status_condition().get_trigger_value(),
            "{name}: an accessor that cannot report the transition must still \
             settle its wake-up, or a wait/{name} loop spins for ever"
        );

        // And, as everywhere else, the transition itself survives.
        let (data, info) = reader
            .take_with_info()
            .expect("take_with_info")
            .unwrap_or_else(|| panic!("{name}: the transition must not be destroyed"));
        assert!(data.is_none() && !info.valid_data, "{name}");
    }
}

/// The placement rule itself, exercised directly.
///
/// The two end-to-end ordering tests above run over an intra-process pair,
/// whose samples carry no writer GUID, so they only ever reach the
/// "different writers" branch. The rule that matters on the wire - compare
/// sequence numbers within ONE writer - has to be tested where it lives.
#[test]
fn a_transition_is_placed_by_its_own_writers_sequence_numbers() {
    use super::subscriber::{DisposeEvent, DisposeQueue};
    use crate::dds::condition::StatusCondition;
    use crate::engine::subscriber::DisposeKind;
    use std::sync::Arc;

    const W: [u8; 16] = [0x11; 16];
    const OTHER: [u8; 16] = [0x22; 16];

    let queued = |writer: Option<[u8; 16]>, order_seq: u64| {
        let q = DisposeQueue::new(Arc::new(StatusCondition::new()));
        q.push(DisposeEvent {
            key_hash: [7u8; 16],
            kind: DisposeKind::Disposed,
            seq: 1,
            writer_guid: writer,
            order_seq,
            announced: false,
            read: false,
            from_local_writer: false,
            disposed_generation_count: 0,
            no_writers_generation_count: 0,
            source_timestamp_ns: None,
        });
        q
    };

    // Nothing in the cache: nothing to be ordered against.
    assert!(queued(Some(W), 5).pop_if_before(&[], &[]).is_some());

    // Same writer: the wire order decides, and only STRICTLY earlier wins.
    assert!(
        queued(Some(W), 5)
            .pop_if_before(&[(Some(W), 9)], &[])
            .is_some(),
        "a transition emitted before the queued sample must precede it"
    );
    assert!(
        queued(Some(W), 9)
            .pop_if_before(&[(Some(W), 5)], &[])
            .is_none(),
        "a transition emitted after the queued sample must follow it"
    );
    assert!(
        queued(Some(W), 7)
            .pop_if_before(&[(Some(W), 7)], &[])
            .is_none(),
        "equal sequence numbers are the vendor that rides the dispose flag on \
         the sample itself: the value goes out first, the transition after"
    );

    // A writer that disappeared: after everything it ever sent, never before.
    assert!(
        queued(Some(W), u64::MAX)
            .pop_if_before(&[(Some(W), 1)], &[])
            .is_none(),
        "a synthesized transition must never jump ahead of its writer's \
         remaining samples"
    );

    // Across writers DDS promises no order, so holding it back would only
    // starve it behind traffic it has nothing to do with.
    assert!(queued(Some(W), 9)
        .pop_if_before(&[(Some(OTHER), 1)], &[])
        .is_some());
    assert!(queued(None, 9)
        .pop_if_before(&[(Some(W), 1)], &[])
        .is_some());
    assert!(queued(Some(W), 9)
        .pop_if_before(&[(None, 1)], &[])
        .is_some());
}

/// `DataWriter::write_w_timestamp`'s override used not to reach a PURE
/// intra-process write (no remote peer) at all: `write_intra_process_fast`
/// stamped every local ring entry from the real write-time clock, read
/// before `stamp_source_ts()` was ever consulted, never from the staged
/// override. A co-located reader's `SampleInfo::source_timestamp_ns` for
/// such a write was always "now", whatever timestamp the application
/// asked for.
///
/// Mutant: reverting `commit_intra_process_entry`'s `IndexEntry` to build
/// `timestamp_ns: write_start_ns` (the pre-fix field) makes this fail:
/// `info.source_timestamp_ns` would be some real nanosecond-since-epoch
/// value near "now", not exactly `42`.
#[test]
fn write_w_timestamp_reaches_a_pure_intra_process_write() {
    // An exact multiple of 1e9 (2026-01-01T00:00:00Z): zero sub-second
    // fraction, so the lossy RTPS `Time_t` 32-bit-fraction round trip
    // (`rtps_timestamp_from_unix_nanos`/`unix_nanos_from_rtps_timestamp`,
    // shared with the wire/journal path) cannot be confused with the
    // defect this test pins. Same convention as
    // `write_w_timestamp_journals_the_given_timestamp_once`.
    let given_ns: u64 = 1_767_225_600 * 1_000_000_000;
    let (writer, reader) = bound_pair("write-w-timestamp-intra-process", QoS::best_effort());
    writer
        .write_w_timestamp(&Point { x: 7, y: 8 }, given_ns)
        .expect("write_w_timestamp");
    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the sample");
    assert_eq!(data, Some(Point { x: 7, y: 8 }));
    assert_eq!(
        info.source_timestamp_ns,
        Some(given_ns),
        "the override must reach the intra-process fast path's ring entry, \
         not the real write-time clock"
    );
}

/// The default reader's keyless ALIVE path is the one it always had: a
/// write, a take, a second write and a second take report the second
/// sample NOT_NEW (DDS v1.4 Sec.2.2.2.5.1.3: the view state changes only
/// with a new generation of the instance, and the instance never left
/// ALIVE).
///
/// Mutant: resetting `nil_seen` on every arrival in
/// `InstanceTable::arrive`'s ALIVE fast path makes this fail: the second
/// sample reports NEW.
#[test]
fn by_reception_keyless_second_sample_after_a_take_is_not_new() {
    let (writer, reader) = bound_pair("by-reception-keyless-not-new", QoS::best_effort());
    for (n, expected) in [(1, super::ViewState::New), (2, super::ViewState::NotNew)] {
        writer.write(&Point { x: n, y: n }).expect("write");
        let (_, info) = reader
            .take_with_info()
            .expect("take_with_info")
            .expect("the sample");
        assert_eq!(info.view_state, expected, "sample {n}");
    }
}

/// The same under BY_SOURCE_TIMESTAMP, whose admission takes the nil
/// instance's lock: only a NOT_ALIVE to ALIVE revival starts a generation
/// the application has not seen.
///
/// Mutant: dropping `!was_alive &&` from
/// `InstanceTable::sync_nil_after_revival` makes this fail.
#[test]
fn by_source_keyless_second_sample_after_a_take_is_not_new() {
    let (writer, reader) = bound_pair(
        "by-source-keyless-not-new",
        QoS::best_effort().destination_order_by_source(),
    );
    for (n, expected) in [(1, super::ViewState::New), (2, super::ViewState::NotNew)] {
        writer.write(&Point { x: n, y: n }).expect("write");
        let (_, info) = reader
            .take_with_info()
            .expect("take_with_info")
            .expect("the sample");
        assert_eq!(info.view_state, expected, "sample {n}");
    }
}

/// A BY_SOURCE_TIMESTAMP reader's intra-process listener is handed no
/// payload (`ReaderBuilder::build`'s delivery observer): the sample is
/// admitted only when the reader's pump decodes it, after the writer's
/// call. It is read normally.
/// The payload-less notification is tested separately with a listener
/// that drains its associated reader.
#[test]
fn by_source_timestamp_the_local_listener_carries_no_payload() {
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);
    impl crate::dds::listener::DataReaderListener<Point> for Counting {
        fn on_data_available(&self, _sample: &Point) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let (writer, reader) = bound_pair(
        "by-source-local-no-payload",
        QoS::best_effort()
            .keep_last(4)
            .destination_order_by_source(),
    );
    let listener = std::sync::Arc::new(Counting::default());
    reader.set_listener(
        Some(
            listener.clone() as std::sync::Arc<dyn crate::dds::listener::DataReaderListener<Point>>
        ),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );
    writer.write(&Point { x: 4, y: 4 }).expect("write");
    assert_eq!(listener.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(reader.take().expect("take"), Some(Point { x: 4, y: 4 }));
}

/// DDS v1.4 Sec.2.2.3.17, order 1: a DATA sample (ts=200, writer A,
/// intra-process) ACCEPTED and taken, THEN a dispose from a DIFFERENT
/// writer B (ts=300, newer) arrives. The dispose is accepted (newer than
/// the watermark DATA@200 set) and reported; nothing about the already-
/// delivered data changes.
///
/// The dispose is newer, so no mutant of the ordering changes this
/// outcome: the next test pins the refusal.
#[test]
fn by_source_timestamp_data_then_newer_different_writer_dispose_both_land() {
    let (writer, reader) = bound_pair(
        "by-source-ts-order-data-then-dispose",
        QoS::best_effort()
            .keep_last(4)
            .destination_order_by_source(),
    );

    // Writer A's data, source ts = 200 (through the real
    // `write_w_timestamp` API, which reaches the intra-process fast
    // path too): pumped AND taken, so the cache is empty and the
    // acceptance watermark is the only thing left holding the fact that
    // 200 was seen.
    writer
        .write_w_timestamp(&Point { x: 1, y: 2 }, 200)
        .expect("write_w_timestamp");
    assert_eq!(reader.take().expect("take"), Some(Point { x: 1, y: 2 }));
    assert!(reader.cache().is_empty());

    // A DIFFERENT writer B's dispose of the same instance, source ts =
    // 300 (newer): accepted, state moves to NOT_ALIVE_DISPOSED.
    reader
        .dispose_queue_for_test()
        .push(super::subscriber::DisposeEvent {
            key_hash: [0u8; 16],
            kind: crate::engine::subscriber::DisposeKind::Disposed,
            seq: 1,
            writer_guid: Some([0x22; 16]),
            order_seq: 1,
            announced: false,
            read: false,
            from_local_writer: false,
            disposed_generation_count: 0,
            no_writers_generation_count: 0,
            source_timestamp_ns: Some(300),
        });

    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the newer dispose must be reported");
    assert!(data.is_none() && !info.valid_data);
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
    assert_eq!(info.source_timestamp_ns, Some(300));

    assert_eq!(
        reader.take_with_info().expect("take_with_info"),
        None,
        "nothing left to report"
    );
}

/// Same instance, reception order reversed: a DIFFERENT writer B's
/// dispose (ts=300) is accepted FIRST (nothing competes yet), raising
/// the watermark to 300. Writer A's data (ts=200) then arrives and is
/// REJECTED by the SAME watermark at its admission
/// (`InstanceTable::admit_by_source`) -- it never reaches the cache, is
/// never delivered, and does not revive the instance. DDS v1.4 Sec.2.2.3.17's "same final value
/// regardless of reception order" promise: a reader that saw dispose
/// THEN data ends at the SAME NOT_ALIVE_DISPOSED state as one that saw
/// data then dispose (the test above), even though this one never saw
/// the data at all.
///
/// Mutant: making `InstanceEntry::admit_by_source` skip its ordering
/// check (admitting every sample unconditionally) makes this fail: the
/// stale DATA@200 would be delivered and would revive the instance.
#[test]
fn by_source_timestamp_dispose_then_older_different_writer_data_rejects_the_data() {
    let (writer, reader) = bound_pair(
        "by-source-ts-order-dispose-then-data",
        QoS::best_effort()
            .keep_last(4)
            .destination_order_by_source(),
    );

    reader
        .dispose_queue_for_test()
        .push(super::subscriber::DisposeEvent {
            key_hash: [0u8; 16],
            kind: crate::engine::subscriber::DisposeKind::Disposed,
            seq: 1,
            writer_guid: Some([0x22; 16]),
            order_seq: 1,
            announced: false,
            read: false,
            from_local_writer: false,
            disposed_generation_count: 0,
            no_writers_generation_count: 0,
            source_timestamp_ns: Some(300),
        });

    // Writer A's data, source ts = 200 (older than the watermark the
    // dispose just set), through the real `write_w_timestamp` API:
    // queued on the ring, never yet pumped.
    writer
        .write_w_timestamp(&Point { x: 3, y: 4 }, 200)
        .expect("write_w_timestamp");

    let (data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the dispose, already accepted, must be reported");
    assert!(data.is_none() && !info.valid_data);
    assert_eq!(info.instance_state, super::InstanceState::NotAliveDisposed);
    assert_eq!(info.source_timestamp_ns, Some(300));

    assert_eq!(
        reader.take_with_info().expect("take_with_info"),
        None,
        "the stale data must never surface: not now, not as a later \
         revival of the instance"
    );
    assert!(
        reader.cache().is_empty(),
        "the rejected data must never have entered the cache at all"
    );
}

/// DDS v1.4 Sec.2.2.3.17 finding: a local sample's `writer_guid` was
/// always `None` (no GUID prefix on the intra-process payload), so two
/// writers tied on source timestamp -- one local to a reader, one
/// remote -- resolved the tie differently on a reader local to EACH of
/// them: the pair would disagree on the survivor depending on which one
/// happened to be "local" from where it was observed. Under
/// BY_SOURCE_TIMESTAMP, the crown (K==1) single local writer's real
/// identity (`local_writer_identity`, the one EXCLUSIVE ownership
/// arbitration already used) is resolved instead of reporting `None`.
///
/// Mutant: deleting the `cached.writer_guid = local_writer_guid`
/// patch-up in `take_projected`'s crown loop makes this fail: the local
/// write's `info.writer_guid` would be `None` again.
#[test]
fn by_source_timestamp_reports_a_real_identity_for_a_local_writer() {
    let (writer, reader) = bound_pair(
        "by-source-ts-local-identity",
        QoS::best_effort()
            .keep_last(4)
            .destination_order_by_source(),
    );
    writer.write(&Point { x: 5, y: 6 }).expect("write");
    let (_data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the sample");
    assert!(
        info.writer_guid.is_some(),
        "a local writer must carry a real identity under BY_SOURCE_TIMESTAMP, \
         not None, so a tie against a remote writer resolves the same way on \
         every reader"
    );
}

/// Control: BY_RECEPTION_TIMESTAMP (the default) keeps reporting `None`
/// for a local sample's writer, byte-for-byte the pre-existing
/// behaviour -- the lookup the previous test exercises is gated behind
/// BY_SOURCE_TIMESTAMP and must cost (and change) nothing otherwise.
#[test]
fn by_reception_timestamp_still_reports_no_identity_for_a_local_writer() {
    let (writer, reader) = bound_pair(
        "by-reception-local-identity-control",
        QoS::best_effort().keep_last(4),
    );
    writer.write(&Point { x: 5, y: 6 }).expect("write");
    let (_data, info) = reader
        .take_with_info()
        .expect("take_with_info")
        .expect("the sample");
    assert_eq!(info.writer_guid, None);
}

/// DDS v1.4 Sec.2.2.2.5.1.4 is the same rule for a transition's
/// `no_writers_generation_count` as for a data sample's: the value AT
/// THE TIME it was received, stamped once by `DisposeQueue::push`, never
/// re-read from the instance table later. A transition queued BEFORE a
/// revival must keep reporting the OLD count even once a later sample
/// (through a `SampleCache` sharing the same table) has moved it on.
#[test]
fn a_transitions_no_writers_generation_count_is_stamped_at_its_own_receipt() {
    use super::cache::{CachedSample, InstanceHandle, InstanceTable, SampleCache};
    use super::subscriber::{DisposeEvent, DisposeQueue};
    use crate::dds::condition::StatusCondition;
    use crate::engine::subscriber::DisposeKind;
    use std::sync::Arc;

    let instances = Arc::new(InstanceTable::new());
    let queue = DisposeQueue::with_instances(
        Arc::new(StatusCondition::new()),
        Arc::clone(&instances),
        None,
    );
    let cache: SampleCache<i32> = SampleCache::with_instances(4, Arc::clone(&instances));
    let handle = InstanceHandle::new([7u8; 16]);

    let transition = |seq: u64| DisposeEvent {
        key_hash: [7u8; 16],
        kind: DisposeKind::Unregistered,
        seq,
        writer_guid: None,
        order_seq: seq,
        announced: false,
        read: false,
        from_local_writer: false,
        disposed_generation_count: 0,
        no_writers_generation_count: 0,
        source_timestamp_ns: None,
    };

    // First transition, generation still 0.
    queue.push(transition(1));
    let first = queue.pop_one().expect("first transition");
    assert_eq!(first.no_writers_generation_count, 0);

    // A sample, through a cache sharing the same instance table, revives
    // the instance to generation 1.
    cache.push(CachedSample::with_meta(99, 2, 0, handle, None, false));
    assert_eq!(instances.no_writers_generation_count(handle), 1);

    // A SECOND transition, queued only now, must carry the NEW
    // generation - this one really was received after the revival.
    queue.push(transition(3));
    let second = queue.pop_one().expect("second transition");
    assert_eq!(
        second.no_writers_generation_count, 1,
        "stamped at ITS OWN receipt (after the revival), not before it"
    );
}

/// Instance-state transitions are NETWORK-ONLY, and the measured
/// intra-process path depends on it.
///
/// `send_lifecycle_change` returns early when the writer has no transport, so
/// a same-process pair produces no transition at all. That is what lets the
/// ordering work claim zero cost on the crown 1w1r round trip BY
/// CONSTRUCTION: the branch is not cheap there, it is unreachable there. An
/// argument like that is worth exactly as much as the test that pins it, so
/// here is the test - if an intra-process writer ever starts queueing
/// transitions, this fails and the cost claim has to be re-made by
/// measurement.
///
/// It also records a real gap, deliberately: an application whose writer and
/// reader share a process cannot observe instance lifecycle AT ALL. That is
/// a known limitation, not fixed here.
#[test]
fn an_intra_process_writer_queues_no_instance_state_transition() {
    let (writer, reader) = bound_pair("dispose-intra-none", QoS::best_effort().keep_last(4));

    writer.write(&Point { x: 1, y: 1 }).expect("write");
    writer.dispose(&Point { x: 1, y: 1 }).expect("dispose");
    writer
        .unregister_instance(&Point { x: 1, y: 1 })
        .expect("unregister");

    assert!(
        reader.dispose_queue_for_test().is_empty(),
        "an intra-process writer must not reach the transition queue; if it \
         now does, the crown path is no longer structurally free of this work"
    );
}

#[test]
fn drained_dispose_owes_no_wake() {
    use crate::dds::Condition;
    use std::time::Duration;

    let (_writer, reader) = bound_pair("wakeup-dispose-drained", QoS::best_effort().keep_last(1));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    reader.dispose_queue_for_test().push(dispose_event(9));
    let triggered = waitset
        .wait(Some(Duration::from_millis(200)))
        .expect("dispose wakes the reader");
    assert_eq!(triggered.len(), 1);

    #[allow(deprecated)]
    let legacy = reader.get_dispose_events();
    assert_eq!(legacy.len(), 1);
    assert_eq!(
        wake_word(&reader, super::runtime::WakeWord::Dispose),
        0,
        "the drain settles the word"
    );
    assert!(!reader.get_status_condition().get_trigger_value());
    assert_eq!(reader.take().expect("take"), None);
    assert!(!reader.get_status_condition().get_trigger_value());
    assert!(
        matches!(
            waitset.wait(Some(Duration::from_millis(50))),
            Err(crate::dds::Error::WouldBlock)
        ),
        "a drained dispose owes no wake-up"
    );
    #[allow(deprecated)]
    let legacy = reader.get_dispose_events();
    assert!(legacy.is_empty());
}

/// Two producers in the same window: a bound writer's push (ring) and
/// a dispose (queue), each raising its own word; the clear swaps both
/// words and the re-check must find both, in either order. Both are
/// re-raised in that one clear, so one wake-up covers both: the sample
/// comes out of the take after it, and the event waits in
/// `get_dispose_events` with nothing further owed (the empty take after
/// the sample reads two re-raises and settles both words). On one
/// thread this pins the check-then-act over two words; the per-word
/// ordering step for two producer THREADS is argued at the call site
/// and exercised by the two-writer stress test below.
#[test]
fn take_keeps_both_producers_when_a_push_and_a_dispose_race_the_clear() {
    use crate::dds::Condition;
    use std::sync::Arc;
    use std::time::Duration;

    for dispose_first in [false, true] {
        let topic = if dispose_first {
            "wakeup-dispose-then-push"
        } else {
            "wakeup-push-then-dispose"
        };
        let (writer, reader) = bound_pair(topic, QoS::best_effort().keep_last(1));
        let waitset = crate::dds::WaitSet::new();
        waitset.attach(&*reader).expect("attach reader");

        writer.write(&Point { x: 1, y: 1 }).expect("write");
        assert_eq!(reader.take().expect("take"), Some(Point { x: 1, y: 1 }));

        let ring = Arc::clone(reader.ring_for_test());
        let queue = Arc::clone(reader.dispose_queue_for_test());
        let status = reader.get_status_condition();
        reader.set_idle_clear_hook(move || {
            let push = || replay_producer_push(&ring, &status, Point { x: 2, y: 2 });
            let dispose = || queue.push(dispose_event(42));
            if dispose_first {
                dispose();
                push();
            } else {
                push();
                dispose();
            }
        });

        // Drive the race with `take_with_info`, the accessor that can report
        // BOTH producers. The invariant under test is that NEITHER is lost to
        // the clear they raced.
        //
        // Their relative ORDER is deliberately not asserted here, and that is a
        // known limit of this step rather than an oversight. The data push and
        // the instance-state change still travel on two different channels -
        // the ring and the dispose queue - so a push that lands during a clear,
        // after that call's pump, is seen one call later than a notification
        // that lands at the same instant. Moving the notification onto the
        // reader's own ring is what makes the order exact by construction, and
        // that is the planned next step.
        let mut got_data = false;
        let mut got_notification = false;
        for _ in 0..8 {
            match reader.take_with_info().expect("take_with_info") {
                Some((Some(point), info)) => {
                    assert_eq!(point, Point { x: 2, y: 2 });
                    assert!(info.valid_data);
                    got_data = true;
                }
                Some((None, info)) => {
                    assert!(!info.valid_data);
                    assert_eq!(info.sequence_number, 42);
                    got_notification = true;
                }
                None if got_data && got_notification => break,
                None => {
                    // Nothing yet: the WaitSet must still say something is owed,
                    // which is the defect this test was written for.
                    assert!(
                        reader.get_status_condition().get_trigger_value(),
                        "DATA_AVAILABLE must survive two producers racing the clear \
                         (dispose_first={dispose_first})"
                    );
                    let triggered = waitset
                        .wait(Some(Duration::from_millis(200)))
                        .expect("WaitSet must not block while something is owed");
                    assert_eq!(triggered.len(), 1);
                }
            }
        }
        assert!(
            got_data,
            "the racing push must be delivered (dispose_first={dispose_first})"
        );
        assert!(
            got_notification,
            "the racing dispose must be delivered too (dispose_first={dispose_first})"
        );

        // Both consumed, nothing owed.
        assert_eq!(wake_word(&reader, super::runtime::WakeWord::Primary), 0);
        assert_eq!(wake_word(&reader, super::runtime::WakeWord::Dispose), 0);
        assert!(
            matches!(
                waitset.wait(Some(Duration::from_millis(50))),
                Err(crate::dds::Error::WouldBlock)
            ),
            "nothing further owed once both are taken (dispose_first={dispose_first})"
        );
        assert_eq!(reader.take_with_info().expect("take_with_info"), None);
        assert!(
            !reader.get_status_condition().get_trigger_value(),
            "nothing pending, nothing raised (dispose_first={dispose_first})"
        );
    }
}

/// Two producer threads racing the same clear: a second writer bound
/// to the reader adds a second ring and a second merger notify, which
/// raises `WakeWord::Extra` (a `fetch_or` on the shared word) while the
/// first keeps its plain store on `WakeWord::Primary`; the reader's
/// clear swaps each word and must see each writer's push through its
/// own word's edge. This is the cross-thread evidence for the per-word
/// argument in `clear_data_available_if_idle`; the seam tests replay
/// two producers on one thread and cannot exercise it.
///
/// Lockstep rounds: both writers publish right after the same barrier,
/// then each waits for its own acknowledgement before the next round.
/// With independent pacing the other writer's next sample would drain a
/// stranded one and mask the stall; in lockstep a lost wake-up on
/// either sample leaves nothing else to wake the reader, and the
/// writer's bounded wait reports the round it stalled on. A stalled
/// writer keeps crossing the barrier without writing so the other
/// thread is never left waiting on it.
#[test]
fn waitset_reader_never_stalls_behind_two_racing_writers() {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    const ROUNDS: i32 = 10_000;
    const STOP: i32 = -1;

    struct Lockstep {
        barrier: Barrier,
        stop: AtomicBool,
        /// Last sequence taken from each writer, indexed by `Point::y`.
        acked: [AtomicI32; 2],
    }

    fn run_writer(
        writer: &crate::dds::writer::DataWriter<Point>,
        lane: i32,
        lockstep: &Lockstep,
    ) -> Option<i32> {
        let mut stalled_at = None;
        for seq in 0..ROUNDS {
            lockstep.barrier.wait();
            if lockstep.stop.load(Ordering::Acquire) {
                continue;
            }
            writer.write(&Point { x: seq, y: lane }).expect("write");
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut spins = 0u32;
            while lockstep.acked[lane as usize].load(Ordering::Acquire) != seq {
                if Instant::now() >= deadline {
                    stalled_at = Some(seq);
                    lockstep.stop.store(true, Ordering::Release);
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins.is_multiple_of(64) {
                    std::thread::yield_now();
                } else {
                    std::hint::spin_loop();
                }
            }
        }
        stalled_at
    }

    let (writer_a, reader) = bound_pair("wakeup-two-writers", QoS::best_effort().keep_last(4));
    let writer_b =
        crate::dds::writer::WriterBuilder::<Point>::new("wakeup-two-writers".to_string())
            .qos(QoS::best_effort().keep_last(4))
            .build()
            .expect("second writer build should succeed");
    reader.bind_to_writer(writer_b.merger());
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    let lockstep = Arc::new(Lockstep {
        barrier: Barrier::new(2),
        stop: AtomicBool::new(false),
        acked: [AtomicI32::new(-1), AtomicI32::new(-1)],
    });

    let reader_thread = std::thread::spawn({
        let lockstep = Arc::clone(&lockstep);
        let reader = Arc::clone(&reader);
        move || -> (usize, bool) {
            let mut received = 0usize;
            loop {
                if waitset.wait(Some(Duration::from_secs(20))).is_err() {
                    return (received, true);
                }
                while let Some(sample) = reader.take().expect("take") {
                    if sample.x == STOP {
                        return (received, false);
                    }
                    received += 1;
                    lockstep.acked[sample.y as usize].store(sample.x, Ordering::Release);
                }
            }
        }
    });

    let writer_b_thread = std::thread::spawn({
        let lockstep = Arc::clone(&lockstep);
        move || run_writer(&writer_b, 1, &lockstep)
    });
    let stalled_a = run_writer(&writer_a, 0, &lockstep);
    let stalled_b = writer_b_thread.join().expect("writer thread");
    writer_a
        .write(&Point { x: STOP, y: 0 })
        .expect("stop write");

    let (received, timed_out) = reader_thread.join().expect("reader thread");
    assert_eq!(
        stalled_a, None,
        "reader stalled behind writer A's push that raced its DATA_AVAILABLE clear"
    );
    assert_eq!(
        stalled_b, None,
        "reader stalled behind writer B's push that raced its DATA_AVAILABLE clear"
    );
    assert!(!timed_out, "reader WaitSet timed out");
    assert_eq!(
        received,
        2 * ROUNDS as usize,
        "best-effort KeepLast(4) lost samples"
    );
}

// ---------------------------------------------------------------------------
// The same window, cache side. `DataReader` is `Sync`: on the K>1 path
// (two threads may drain at once there, serialized by the binding-table
// mutex; the K==1 ring has a single consumer by contract) a pump on
// another thread can move a ring entry into the cache and leave it
// there between the reader's cache pop and its clear, and the ring walk
// of the re-check then finds nothing. Seam replay of that interleaving
// first, then a concurrent pumping thread with a stall detector.
// ---------------------------------------------------------------------------

/// A sample moved from the ring into the cache between the reader's
/// cache pop and its clear must not rely on the re-check to keep
/// DATA_AVAILABLE up: another thread's `take_instance` with a handle
/// that matches nothing (`Point` is keyless: every sample carries the
/// nil handle) could pump the ring entry into the cache while the take was
/// between its pop and its clear. The consumer gate holds that pump
/// out of the whole take: the hook runs the producer sequence and
/// starts that very `take_instance` on another thread, which must not
/// complete before the take returns, and the sample it then deposits
/// must still wake the WaitSet through the push's own raise. Two
/// bindings, so both the take and the pump go through `pump_merge`.
#[test]
fn a_pump_into_the_cache_waits_for_the_take_that_is_clearing() {
    use crate::dds::Condition;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let (writer, reader) = bound_pair("wakeup-cache", QoS::best_effort().keep_last(4));
    // Never writes: bound only to put the reader on the K>1 path.
    let idle = crate::dds::writer::WriterBuilder::<Point>::new("wakeup-cache".to_string())
        .qos(QoS::best_effort().keep_last(4))
        .build()
        .expect("second writer build should succeed");
    reader.bind_to_writer(idle.merger());
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    writer.write(&Point { x: 1, y: 1 }).expect("write");
    assert_eq!(reader.take().expect("take"), Some(Point { x: 1, y: 1 }));

    let ring = Arc::clone(reader.ring_for_test());
    let status = reader.get_status_condition();
    let pumper = Arc::clone(&reader);
    let pumper_done = Arc::new(AtomicBool::new(false));
    let (pumper_tx, pumper_rx) = std::sync::mpsc::channel();
    let done = Arc::clone(&pumper_done);
    reader.set_idle_clear_hook(move || {
        replay_producer_push(&ring, &status, Point { x: 2, y: 2 });
        let finished = Arc::clone(&done);
        let handle = std::thread::spawn(move || {
            let taken = pumper
                .take_instance(super::InstanceHandle::new([0xEE; 16]))
                .expect("take_instance");
            finished.store(true, Ordering::Release);
            taken
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !done.load(Ordering::Acquire),
            "the take is between its pop and its clear: a pump on another thread must wait"
        );
        pumper_tx.send(handle).expect("hand the pumper back");
    });

    assert_eq!(reader.take().expect("take"), None);

    let handle = pumper_rx.recv().expect("the seam ran");
    assert_eq!(
        handle.join().expect("pumper thread"),
        None,
        "a handle no sample carries takes nothing and leaves the pumped sample in the cache"
    );
    assert!(
        reader.get_status_condition().get_trigger_value(),
        "DATA_AVAILABLE must be up for the sample the pump left in the cache"
    );
    let triggered = waitset
        .wait(Some(Duration::from_millis(200)))
        .expect("WaitSet must not block on a sample waiting in the cache");
    assert_eq!(triggered.len(), 1);
    assert_eq!(
        reader.take().expect("take"),
        Some(Point { x: 2, y: 2 }),
        "the sample the pump left in the cache must be handed over"
    );
    assert_eq!(reader.take().expect("take"), None);
    assert!(!reader.get_status_condition().get_trigger_value());
}

/// A concurrent `take_instance` on another thread moves entries from
/// the rings into the cache without taking them (its handle matches
/// nothing) while the reader thread runs the wait/take loop. Two
/// bindings so the reader is on the K>1 path, where the binding-table
/// mutex under the consumer gate makes concurrent drains legal (the
/// gate alone does on the K==1 path). Every sample still reaches the reader through the
/// cache; one stranded there with the status cleared stalls the
/// writer's bounded wait, because the pumping thread produces nothing
/// that would wake the reader.
///
/// The window itself (the pump's critical section landing between the
/// reader's cache pop and its ring walk) is a few dozen nanoseconds
/// wide behind a mutex hand-off, and this run does not reliably hit
/// it: the seam test above pins it. What this run guards is the
/// concurrent drain end to end, lock order included (binding table,
/// then cache, on both threads), with the stall detector armed.
#[test]
fn waitset_reader_never_stalls_behind_a_concurrent_take_instance() {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const SAMPLES: i32 = 10_000;
    const STOP: i32 = -1;

    let (writer, reader) = bound_pair("wakeup-pump-race", QoS::best_effort().keep_last(4));
    // Never writes: bound only to put the reader on the K>1 path.
    let idle = crate::dds::writer::WriterBuilder::<Point>::new("wakeup-pump-race".to_string())
        .qos(QoS::best_effort().keep_last(4))
        .build()
        .expect("second writer build should succeed");
    reader.bind_to_writer(idle.merger());
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");

    let acked = Arc::new(AtomicI32::new(-1));
    let reader_thread = std::thread::spawn({
        let acked = Arc::clone(&acked);
        let reader = Arc::clone(&reader);
        move || -> (usize, bool) {
            let mut received = 0usize;
            loop {
                if waitset.wait(Some(Duration::from_secs(20))).is_err() {
                    return (received, true);
                }
                while let Some(sample) = reader.take().expect("take") {
                    if sample.x == STOP {
                        return (received, false);
                    }
                    received += 1;
                    acked.store(sample.x, Ordering::Release);
                }
            }
        }
    });

    let stop = Arc::new(AtomicBool::new(false));
    let pumper_thread = std::thread::spawn({
        let stop = Arc::clone(&stop);
        let reader = Arc::clone(&reader);
        move || -> u64 {
            let mut pumps = 0u64;
            while !stop.load(Ordering::Acquire) {
                assert_eq!(
                    reader
                        .take_instance(super::InstanceHandle::new([0xEE; 16]))
                        .expect("take_instance"),
                    None,
                    "a handle no sample carries never takes"
                );
                pumps += 1;
                if pumps.is_multiple_of(16) {
                    std::thread::yield_now();
                }
            }
            pumps
        }
    });

    let mut stalled_at: Option<i32> = None;
    for seq in 0..SAMPLES {
        writer.write(&Point { x: seq, y: 0 }).expect("write");
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut spins = 0u32;
        while acked.load(Ordering::Acquire) != seq {
            if Instant::now() >= deadline {
                stalled_at = Some(seq);
                break;
            }
            spins = spins.wrapping_add(1);
            if spins.is_multiple_of(64) {
                std::thread::yield_now();
            } else {
                std::hint::spin_loop();
            }
        }
        if stalled_at.is_some() {
            break;
        }
    }
    writer.write(&Point { x: STOP, y: 0 }).expect("stop write");

    let (received, timed_out) = reader_thread.join().expect("reader thread");
    stop.store(true, Ordering::Release);
    let pumps = pumper_thread.join().expect("pumper thread");
    assert_eq!(
        stalled_at, None,
        "reader stalled behind a sample a concurrent pump moved into the cache"
    );
    assert!(!timed_out, "reader WaitSet timed out");
    assert_eq!(
        received, SAMPLES as usize,
        "best-effort KeepLast(4) lost samples"
    );
    assert!(pumps > 0, "the pumping thread never ran");
}

// ---------------------------------------------------------------------------
// The same window, network ring, entry in flight. The clear side walks
// the network ring without the binding-table mutex, so an entry another
// thread popped from it and has not yet deposited is invisible to both
// the ring walk and the cache check; the deposit side re-raises when it
// finds every ring word zero (`DataReader::cover_deposit` states the
// argument). A reader with a network ring and no bound writer is the
// topology where two draining threads are legal and only that ring
// carries samples. The RX producer is replayed by hand
// (`ReaderSubscriber::process_admitted` needs a datagram): ring push,
// then the shared raise of `WakeWord::Network`.
// ---------------------------------------------------------------------------

/// Replay the producer sequence of `ReaderSubscriber::process_admitted`
/// on the network ring: ring push, then the read-modify-write raise of
/// `WakeWord::Network`, which signals the WaitSet. `seq` is the cache
/// dedup key, so samples that can share the cache need distinct ones.
fn replay_network_push(
    ring: &rt::IndexRing,
    room: Option<&std::sync::Arc<super::admission::HistoryRoom>>,
    status: &crate::dds::StatusCondition,
    seq: u32,
    sample: Point,
) {
    let payload = encoded_point(sample.x, sample.y);
    let (handle, _metric) = rt::get_slab_pool()
        .reserve_and_write(&payload, crate::core::rt::Claim::Reader)
        .expect("slab reserve");
    let entry = IndexEntry::with_timestamp(seq, handle, payload.len() as u32, 1);
    // Every entry of a network ring holds a place of its room, as the
    // subscriber's pushes do.
    let place = room.map(|room| room.reserve(0).expect("a place in the network ring"));
    assert!(ring.push(entry), "network ring push");
    if let Some(place) = place {
        place.into_ring();
    }
    status.raise_data_available_shared(super::runtime::WakeWord::Network.index());
}

/// A reader with a network ring and no bound writer.
fn network_reader(topic: &str, qos: QoS) -> std::sync::Arc<super::DataReader<Point>> {
    let _ = rt::init_slab_pool();
    std::sync::Arc::new(
        ReaderBuilder::<Point>::new(topic.to_string())
            .qos(qos)
            .network_ring_for_test()
            .build()
            .expect("reader build should succeed"),
    )
}

/// Seam replay of the in-flight transfer. `take_instance` (thread B)
/// pops the network entry inside `pump_merge`; the seam then starts
/// thread A's `take()` while the entry is out of its ring and not yet
/// in the cache. Before the consumer gate that take ran through: it
/// found the network ring and the cache empty, swapped the network
/// word away, and only the deposit's re-raise kept the sample from
/// sitting in the cache while the WaitSet slept. The gate makes the
/// in-flight state invisible to A: its take waits for B's deposit and
/// then hands the sample over, and the RX raise is never swapped away.
#[test]
fn a_take_during_an_in_flight_network_pump_waits_for_the_deposit() {
    use crate::dds::Condition;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let reader = network_reader("wakeup-network-in-flight", QoS::best_effort().keep_last(4));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");
    let network = Arc::clone(reader.network_ring_for_test().expect("network ring"));
    let room = reader.network_room_for_test().cloned();
    let status = reader.get_status_condition();

    replay_network_push(&network, room.as_ref(), &status, 1, Point { x: 1, y: 1 });
    assert!(status.get_trigger_value(), "the RX raise triggers");

    let taker_done = Arc::new(AtomicBool::new(false));
    let (taker_tx, taker_rx) = std::sync::mpsc::channel();
    let taker = Arc::clone(&reader);
    let done = Arc::clone(&taker_done);
    reader.set_pump_deposit_hook(move || {
        // Thread A: the take that runs through this window.
        let finished = Arc::clone(&done);
        let handle = std::thread::spawn(move || {
            let taken = taker.take().expect("take");
            finished.store(true, Ordering::Release);
            taken
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !done.load(Ordering::Acquire),
            "the entry is in flight: a take on another thread must wait for the deposit"
        );
        taker_tx.send(handle).expect("hand the taker back");
    });

    assert_eq!(
        reader
            .take_instance(super::InstanceHandle::new([0xEE; 16]))
            .expect("take_instance"),
        None,
        "a handle no sample carries takes nothing and leaves the deposit in the cache"
    );

    let handle = taker_rx.recv().expect("the seam ran");
    assert_eq!(
        handle.join().expect("taker thread"),
        Some(Point { x: 1, y: 1 }),
        "the sample the pump deposited is handed to the waiting take"
    );

    // The empty take after it finds nothing and settles.
    assert_eq!(reader.take().expect("take"), None);
    assert_eq!(wake_word(&reader, super::runtime::WakeWord::Primary), 0);
    assert!(!status.get_trigger_value());
    assert!(
        matches!(
            waitset.wait(Some(Duration::from_millis(50))),
            Err(crate::dds::Error::WouldBlock)
        ),
        "nothing further owed"
    );
}

/// A concurrent `take_instance` moves entries from the network ring
/// into the cache without taking them while the reader thread runs the
/// wait/take loop; the RX producer is replayed from this thread with
/// the pacing of the other stress tests (the next sample goes out the
/// moment the previous one is acknowledged). Network ring and no bound
/// writer: two draining threads are legal here, and the clear side
/// walks the network ring without the binding-table mutex. The
/// in-flight window is a few dozen nanoseconds wide and this run does
/// not reliably hit it; the seam test above pins it. What this run
/// guards is the deposit-side rule end to end with the stall detector
/// armed, lock order included.
#[test]
fn waitset_reader_never_stalls_behind_a_concurrent_network_pump() {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const SAMPLES: i32 = 10_000;
    const STOP: i32 = -1;

    let reader = network_reader("wakeup-network-pump-race", QoS::best_effort().keep_last(4));
    let waitset = crate::dds::WaitSet::new();
    waitset.attach(&*reader).expect("attach reader");
    let network = Arc::clone(reader.network_ring_for_test().expect("network ring"));
    let room = reader.network_room_for_test().cloned();
    let status = reader.get_status_condition();

    let acked = Arc::new(AtomicI32::new(-1));
    let reader_thread = std::thread::spawn({
        let acked = Arc::clone(&acked);
        let reader = Arc::clone(&reader);
        move || -> (usize, bool) {
            let mut received = 0usize;
            loop {
                if waitset.wait(Some(Duration::from_secs(20))).is_err() {
                    return (received, true);
                }
                while let Some(sample) = reader.take().expect("take") {
                    if sample.x == STOP {
                        return (received, false);
                    }
                    received += 1;
                    acked.store(sample.x, Ordering::Release);
                }
            }
        }
    });

    let stop = Arc::new(AtomicBool::new(false));
    let pumper_thread = std::thread::spawn({
        let stop = Arc::clone(&stop);
        let reader = Arc::clone(&reader);
        move || -> u64 {
            let mut pumps = 0u64;
            while !stop.load(Ordering::Acquire) {
                assert_eq!(
                    reader
                        .take_instance(super::InstanceHandle::new([0xEE; 16]))
                        .expect("take_instance"),
                    None,
                    "a handle no sample carries never takes"
                );
                pumps += 1;
                if pumps.is_multiple_of(16) {
                    std::thread::yield_now();
                }
            }
            pumps
        }
    });

    let mut stalled_at: Option<i32> = None;
    for seq in 0..SAMPLES {
        // seq + 1: the dedup key must not be zero-based twice (the STOP
        // sample takes SAMPLES + 1).
        replay_network_push(
            &network,
            room.as_ref(),
            &status,
            seq as u32 + 1,
            Point { x: seq, y: 0 },
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut spins = 0u32;
        while acked.load(Ordering::Acquire) != seq {
            if Instant::now() >= deadline {
                stalled_at = Some(seq);
                break;
            }
            spins = spins.wrapping_add(1);
            if spins.is_multiple_of(64) {
                std::thread::yield_now();
            } else {
                std::hint::spin_loop();
            }
        }
        if stalled_at.is_some() {
            break;
        }
    }
    replay_network_push(
        &network,
        room.as_ref(),
        &status,
        SAMPLES as u32 + 1,
        Point { x: STOP, y: 0 },
    );

    let (received, timed_out) = reader_thread.join().expect("reader thread");
    stop.store(true, Ordering::Release);
    let pumps = pumper_thread.join().expect("pumper thread");
    assert_eq!(
        stalled_at, None,
        "reader stalled behind a network entry a concurrent pump moved into the cache"
    );
    assert!(!timed_out, "reader WaitSet timed out");
    assert_eq!(
        received, SAMPLES as usize,
        "best-effort KeepLast(4) lost samples"
    );
    assert!(pumps > 0, "the pumping thread never ran");
}

// ---------------------------------------------------------------------------
// The unicast receive door (`engine::unicast_router::route_raw_rtps_message`,
// fed by TCP and QUIC) and the reorder gate of a non-volatile reliable reader.
//
// (a) and (b) pin that the door tells a HEARTBEAT to the reader's gate and
// not only to its ACKNACK logic, and that it does not drop a GAP outright;
// otherwise a TRANSIENT_LOCAL reader fed through this door would deliver
// nothing at all. The controls (c1, c2) seed the same gate the way the UDP
// control loop does and prove the fixture delivers once seeded; disabling
// the gate in `builder.rs` makes (a) and (b) pass trivially, so the gate on
// this path is the real one.
//
// The reader is built by the real `ReaderBuilder` against a registry, so
// the gate under test is the one `builder.rs` constructs from the QoS
// (TRANSIENT_LOCAL + RELIABLE -> enabled, NOT seeded on first data), and
// the subscriber is the one the builder registers. Nothing is mocked.
// ---------------------------------------------------------------------------
mod unicast_door_reorder_gate {
    use super::{encoded_point, Point, ReaderBuilder};
    use crate::core::discovery::multicast::control_parser::scan_all_embedded_control_submessages;
    use crate::core::discovery::multicast::{classify_rtps, PacketKind};
    use crate::core::rt;
    use crate::dds::{DataReader, QoS};
    use crate::engine::{
        route_raw_rtps_message, RouterMetrics, TopicRegistry, UnicastRouteOutcome,
    };
    use crate::protocol::builder::{self, RtpsEndpointContext};
    use std::sync::Arc;

    const WRITER_PREFIX: [u8; 12] = [0x5A; 12];
    const WRITER_ENTITY: [u8; 4] = [0x00, 0x00, 0x01, 0x03];
    /// ENTITYID_UNKNOWN: the readers of this module are built without a
    /// participant, so they have no entity id a writer could name, and a
    /// HEARTBEAT or GAP addressed to a named reader is not theirs (RTPS 2.5
    /// 8.3.8.4, 8.3.8.6). The writer addresses every matched reader.
    const READER_ENTITY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

    fn writer_guid() -> [u8; 16] {
        let mut g = [0u8; 16];
        g[..12].copy_from_slice(&WRITER_PREFIX);
        g[12..].copy_from_slice(&WRITER_ENTITY);
        g
    }

    fn ctx() -> RtpsEndpointContext {
        RtpsEndpointContext {
            guid_prefix: WRITER_PREFIX,
            reader_entity_id: READER_ENTITY,
            writer_entity_id: WRITER_ENTITY,
            encapsulation_kind: crate::protocol::discovery::constants::PLAIN_CDR2_LE,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        }
    }

    /// A user DATA from writer W carrying `Point { x: seq, y: 0 }`, decoded
    /// back to prove the wire says what the test thinks it says.
    fn data(topic: &str, seq: u64) -> Vec<u8> {
        let x = i32::try_from(seq).expect("test seq fits i32");
        let pkt = builder::build_data_packet_with_context(
            &ctx(),
            topic,
            seq,
            &encoded_point(x, 0),
            crate::dds::CdrVersion::Xcdr2,
        );
        assert_eq!(classify_rtps(&pkt).0, PacketKind::Data, "fixture: DATA");
        assert_eq!(builder::extract_writer_guid(&pkt), Some(writer_guid()));
        assert_eq!(builder::extract_sequence_number(&pkt), Some(seq));
        pkt
    }

    /// HEARTBEAT(first, last) from writer W, decoded back.
    fn heartbeat(first: u64, last: u64) -> Vec<u8> {
        let pkt = builder::build_heartbeat_packet_with_context(&ctx(), first, last, 1);
        assert_eq!(classify_rtps(&pkt).0, PacketKind::Heartbeat, "fixture: HB");
        assert_eq!(&pkt[8..20], &WRITER_PREFIX, "fixture: HB header prefix");
        let (_gaps, hbs, _) = scan_all_embedded_control_submessages(&pkt);
        assert_eq!(hbs.len(), 1, "fixture: exactly one HEARTBEAT decodes");
        assert_eq!(hbs[0].info.writer_entity_id, WRITER_ENTITY);
        assert_eq!(hbs[0].info.first_seq, i64::try_from(first).expect("fits"));
        assert_eq!(hbs[0].info.last_seq, i64::try_from(last).expect("fits"));
        pkt
    }

    /// GAP(gapStart, gapList.base, empty bitmap) from writer W, decoded back.
    fn gap(gap_start: u64, gap_list_base: u64) -> Vec<u8> {
        let pkt = builder::build_gap_packet_from_parts(
            &READER_ENTITY,
            &WRITER_ENTITY,
            gap_start,
            gap_list_base,
            &[],
            WRITER_PREFIX,
        );
        assert!(!pkt.is_empty(), "fixture: the GAP encodes");
        assert_eq!(classify_rtps(&pkt).0, PacketKind::Gap, "fixture: GAP");
        assert_eq!(&pkt[8..20], &WRITER_PREFIX, "fixture: GAP header prefix");
        let (gaps, _hbs, _) = scan_all_embedded_control_submessages(&pkt);
        assert_eq!(gaps.len(), 1, "fixture: exactly one GAP decodes");
        assert_eq!(gaps[0].info.writer_entity_id, WRITER_ENTITY);
        assert_eq!(gaps[0].info.gap_start, gap_start);
        assert_eq!(gaps[0].info.gap_list_base, gap_list_base);
        // The decoder materialises the implicit leading range
        // [gapStart, gapList.base) into the list (control_parser.rs), and
        // the empty bitmap adds nothing: exactly 1 and 2 for GAP(1, 3).
        assert_eq!(
            gaps[0].info.gap_list_seqs,
            (gap_start..gap_list_base).collect::<Vec<u64>>()
        );
        pkt
    }

    /// A TRANSIENT_LOCAL RELIABLE reader built by the real builder, its
    /// subscriber registered in `registry`, and writer W bound to its topic
    /// the way SEDP binds a remote writer.
    fn non_volatile_reliable_reader(topic: &str) -> (Arc<TopicRegistry>, DataReader<Point>) {
        let _ = rt::init_slab_pool();
        let registry = Arc::new(TopicRegistry::new());
        let reader = ReaderBuilder::<Point>::new(topic.to_string())
            .qos(QoS::reliable().transient_local())
            .with_registry(Arc::clone(&registry))
            .build()
            .expect("reader build");
        bind_writer_as_sedp_does(&registry, topic);
        (registry, reader)
    }

    /// What the SEDP handler records for a remote writer before any DATA
    /// can be admitted: its topic (sedp -> register_writer_guid) and its
    /// OWNERSHIP kind (sedp_handler.rs:316). Without the latter the
    /// reader's OWNERSHIP gate DEFERS every sample as unresolved, which
    /// looks exactly like a held reorder gate, and turns the control red for
    /// that reason.
    fn bind_writer_as_sedp_does(registry: &TopicRegistry, topic: &str) {
        registry.register_writer_guid(writer_guid(), topic.to_string());
        registry.register_writer_ownership_kind(
            writer_guid(),
            crate::qos::ownership::OwnershipKind::Shared,
        );
    }

    fn taken_xs(reader: &DataReader<Point>) -> Vec<i32> {
        let mut out = Vec::new();
        while let Ok(Some(p)) = reader.take() {
            out.push(p.x);
        }
        out
    }

    fn door(pkt: &[u8], registry: &TopicRegistry) -> UnicastRouteOutcome {
        let metrics = RouterMetrics::new();
        route_raw_rtps_message(pkt, registry, &metrics, None)
    }

    /// (a) HEARTBEAT(1,3) then DATA 1,2,3, ALL through the unicast door.
    #[test]
    fn unicast_door_heartbeat_then_data_delivers_to_non_volatile_reader() {
        let topic = "UnicastGateA";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        let hb = door(&heartbeat(1, 3), &registry);
        let outs: Vec<_> = (1..=3u64)
            .map(|s| door(&data(topic, s), &registry))
            .collect();
        eprintln!("(a) HEARTBEAT outcome={hb:?} DATA outcomes={outs:?}");

        assert_eq!(
            taken_xs(&reader),
            vec![1, 2, 3],
            "(a) HEARTBEAT(1,3) + DATA 1..3 via route_raw_rtps_message: \
             the non-volatile reliable reader must deliver all three"
        );
    }

    /// (b) DATA 3 then GAP(1, base 3), both through the unicast door.
    #[test]
    fn unicast_door_gap_releases_held_sample_of_non_volatile_reader() {
        let topic = "UnicastGateB";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        let d = door(&data(topic, 3), &registry);
        let g = door(&gap(1, 3), &registry);
        eprintln!("(b) DATA outcome={d:?} GAP outcome={g:?}");

        assert_eq!(
            taken_xs(&reader),
            vec![3],
            "(b) DATA 3 + GAP[1,3) via route_raw_rtps_message: seq 3 must be \
             delivered once 1 and 2 are declared irrelevant"
        );
    }

    /// One datagram carrying a GAP and then a HEARTBEAT, the way a durable
    /// replay sends `[INFO_DST, GAP, HEARTBEAT]`: the header of the first,
    /// then the second's submessages. Decoded back, both halves, before use.
    fn gap_then_heartbeat(gap_start: u64, gap_list_base: u64, first: u64, last: u64) -> Vec<u8> {
        let mut pkt = gap(gap_start, gap_list_base);
        pkt.extend_from_slice(&heartbeat(first, last)[20..]);
        assert_eq!(pkt.len() % 4, 0, "fixture: submessages stay 4-aligned");
        assert_eq!(
            classify_rtps(&pkt).0,
            PacketKind::Gap,
            "fixture: the datagram is named by its first submessage, the GAP"
        );
        let (gaps, hbs, _) = scan_all_embedded_control_submessages(&pkt);
        assert_eq!(gaps.len(), 1, "fixture: one GAP decodes");
        assert_eq!(hbs.len(), 1, "fixture: one HEARTBEAT decodes behind it");
        assert_eq!(hbs[0].info.first_seq, i64::try_from(first).expect("fits"));
        pkt
    }

    /// Counts the HEARTBEATs in every datagram the registry hands its
    /// heartbeat handlers - the path that answers with an ACKNACK.
    struct CountingHeartbeatHandler(std::sync::atomic::AtomicUsize);

    impl crate::engine::demux::HeartbeatHandler for CountingHeartbeatHandler {
        fn on_heartbeat(
            &self,
            bytes: &[u8],
            _origin: Option<crate::core::discovery::multicast::Origin>,
        ) {
            let (_gaps, hbs, _) = scan_all_embedded_control_submessages(bytes);
            self.0
                .fetch_add(hbs.len(), std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// (e) A HEARTBEAT riding BEHIND a GAP. The classifier names the datagram
    /// by the GAP, so the HEARTBEAT arrives through the GAP arm, and it must
    /// not vanish with it (nothing seeded, nothing answered): the held sample
    /// is released, and the HEARTBEAT reaches the handlers that answer it
    /// with an ACKNACK.
    #[test]
    fn unicast_door_answers_a_heartbeat_riding_behind_a_gap() {
        let topic = "UnicastGateE";
        let (registry, reader) = non_volatile_reliable_reader(topic);
        let counter = Arc::new(CountingHeartbeatHandler(
            std::sync::atomic::AtomicUsize::new(0),
        ));
        let _id = registry.register_heartbeat_handler(counter.clone());

        let _ = door(&data(topic, 3), &registry);
        let outcome = door(&gap_then_heartbeat(1, 3, 3, 3), &registry);

        assert_eq!(outcome, UnicastRouteOutcome::Delivered);
        assert_eq!(
            taken_xs(&reader),
            vec![3],
            "(e) the GAP half releases seq 3"
        );
        assert_eq!(
            counter.0.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "(e) the HEARTBEAT behind the GAP must reach the handlers that \
             answer it, exactly once"
        );
    }

    /// (f) ORDER. The UDP door applies a Gap-named datagram's GAPs before its
    /// HEARTBEATs (listener.rs, Gap branch), and here the order decides what
    /// the application gets: GAP(1, base 3) first seeds the gate at 3 and
    /// releases the held seq 3; HEARTBEAT(firstSN 5) first would seed at 5
    /// and leave seq 3 behind the base. The same datagram must give the same
    /// answer whichever transport carried it.
    #[test]
    fn unicast_door_applies_a_gap_named_datagram_in_the_udp_order() {
        let topic = "UnicastGateF";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        let _ = door(&data(topic, 3), &registry);
        let _ = door(&gap_then_heartbeat(1, 3, 5, 5), &registry);

        assert_eq!(
            taken_xs(&reader),
            vec![3],
            "(f) GAP first, as on UDP: seq 3 is released before the \
             HEARTBEAT moves the base to 5"
        );
    }

    /// `first` followed by the submessages of each of `rest`, as one
    /// datagram. Only concatenates; each caller decodes what it built.
    fn one_datagram(first: Vec<u8>, rest: &[Vec<u8>]) -> Vec<u8> {
        let mut pkt = first;
        for more in rest {
            pkt.extend_from_slice(&more[20..]);
        }
        assert_eq!(pkt.len() % 4, 0, "fixture: submessages stay 4-aligned");
        pkt
    }

    /// (h) The commonest HEARTBEAT on the wire: piggybacked on the DATA it
    /// covers, `[INFO_TS, DATA 1, HEARTBEAT(1,1)]`. The classifier names the
    /// datagram by its DATA, so the HEARTBEAT arrives through the Data arm,
    /// which must look at more than the sample: otherwise the gate is never
    /// seeded and seq 1 stays held.
    #[test]
    fn unicast_door_seeds_from_a_heartbeat_piggybacked_on_data() {
        let topic = "UnicastGateH";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        let pkt = one_datagram(data(topic, 1), &[heartbeat(1, 1)]);
        assert_eq!(
            classify_rtps(&pkt).0,
            PacketKind::Data,
            "fixture: named by its DATA"
        );
        let (gaps, hbs, _) = scan_all_embedded_control_submessages(&pkt);
        assert_eq!(
            (gaps.len(), hbs.len()),
            (0, 1),
            "fixture: one HEARTBEAT rides along"
        );

        let _ = door(&pkt, &registry);

        assert_eq!(
            taken_xs(&reader),
            vec![1],
            "(h) the piggybacked HEARTBEAT seeds the gate and seq 1 is released"
        );
    }

    /// (i) Same, behind a DATA_FRAG this door cannot reassemble (no fragment
    /// buffer). The fragment is dropped and counted; the HEARTBEAT riding
    /// with it still describes the writer and is still applied, as on UDP.
    #[test]
    fn unicast_door_applies_controls_riding_with_a_dropped_fragment() {
        let topic = "UnicastGateI";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        let frags = builder::build_data_frag_packets(
            &ctx(),
            99,
            &[0u8; 9000],
            1024,
            crate::dds::CdrVersion::Xcdr2,
        );
        assert!(!frags.is_empty(), "fixture: 9000 octets fragment");
        let pkt = one_datagram(frags[0].clone(), &[heartbeat(1, 1)]);
        assert_eq!(
            classify_rtps(&pkt).0,
            PacketKind::DataFrag,
            "fixture: named by its fragment"
        );
        let (_gaps, hbs, _) = scan_all_embedded_control_submessages(&pkt);
        assert_eq!(hbs.len(), 1, "fixture: one HEARTBEAT rides along");

        let metrics = RouterMetrics::new();
        let outcome = route_raw_rtps_message(&pkt, &registry, &metrics, None);
        assert_eq!(
            outcome,
            UnicastRouteOutcome::Dropped,
            "no fragment buffer: dropped"
        );

        let _ = door(&data(topic, 1), &registry);
        assert_eq!(
            taken_xs(&reader),
            vec![1],
            "(i) the HEARTBEAT behind the dropped fragment seeded the gate"
        );
    }

    /// (j) ORDER for a datagram named by its DATA. The UDP listener's compound
    /// scan forwards GAPs before HEARTBEATs for every kind but HEARTBEAT, so
    /// `[DATA 9, GAP(1, base 3), HEARTBEAT(firstSN 5)]` must release a seq 3
    /// held earlier, not lose it behind a base of 5: the door must not apply
    /// HEARTBEATs first for everything that is not a GAP.
    #[test]
    fn unicast_door_applies_a_data_named_datagram_in_the_udp_order() {
        let topic = "UnicastGateJ";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        let _ = door(&data(topic, 3), &registry);
        let pkt = one_datagram(data(topic, 9), &[gap(1, 3), heartbeat(5, 9)]);
        assert_eq!(
            classify_rtps(&pkt).0,
            PacketKind::Data,
            "fixture: named by its DATA"
        );
        let (gaps, hbs, _) = scan_all_embedded_control_submessages(&pkt);
        assert_eq!(
            (gaps.len(), hbs.len()),
            (1, 1),
            "fixture: a GAP and a HEARTBEAT ride along"
        );
        let _ = door(&pkt, &registry);

        assert_eq!(
            taken_xs(&reader),
            vec![3],
            "(j) GAP first, as on UDP: seq 3 is released before the base \
             moves to 5; 9 waits for 5..8"
        );
    }

    /// A GAP with arbitrary 64-bit sequence fields, WITHOUT the decoding
    /// assertions of `gap()`: these are GAPs RTPS calls invalid. The wire is
    /// still read back, so the test knows which SIGNED numbers it sent.
    fn raw_gap(gap_start: u64, gap_list_base: u64) -> Vec<u8> {
        let pkt = builder::build_gap_packet_from_parts(
            &READER_ENTITY,
            &WRITER_ENTITY,
            gap_start,
            gap_list_base,
            &[],
            WRITER_PREFIX,
        );
        assert_eq!(pkt[20], 0x08, "fixture: the first submessage is the GAP");
        assert_eq!(classify_rtps(&pkt).0, PacketKind::Gap, "fixture: named GAP");
        pkt
    }

    /// gapStart and gapList.base as the wire carries them: SequenceNumber_t,
    /// a signed high word and an unsigned low word (RTPS v2.5 Sec.9.4.2.5).
    fn wire_gap_numbers(pkt: &[u8]) -> (i64, i64) {
        let le = pkt[21] & 0x01 != 0;
        let sn = |at: usize| {
            let word = |o: usize| {
                let b: [u8; 4] = pkt[o..o + 4].try_into().expect("4 octets");
                if le {
                    u32::from_le_bytes(b)
                } else {
                    u32::from_be_bytes(b)
                }
            };
            let high = word(at) as i32;
            let low = word(at + 4);
            (i64::from(high) << 32) | i64::from(low)
        };
        // header 20 + submessage header 4 + readerId 4 + writerId 4
        (sn(32), sn(40))
    }

    /// (k) A GAP whose gapStart is NEGATIVE - invalid, RTPS v2.5
    /// Sec.8.3.8.4.3 - must not blind its writer for good. On a gate not yet
    /// seeded, `on_gap` starts from gapStart; casting the negative number to a
    /// u64 would land the base at or above 2^63, every later DATA would read
    /// as already delivered, and no HEARTBEAT can move a base backwards. The
    /// take must return the writer's samples here.
    #[test]
    fn a_gap_with_a_negative_start_no_longer_blinds_its_writer() {
        let topic = "UnicastGateK";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        // The minimal malformed case: ONLY gapStart is negative, the base is
        // a valid 11. Making both negative would let the base check reject
        // the GAP first and leave the gapStart check untested; here only the
        // gapStart check stands between this GAP and the gate.
        let bad = raw_gap((1u64 << 63) + 1, 11);
        let (start, base) = wire_gap_numbers(&bad);
        assert!(
            start < 0 && base == 11,
            "fixture: gapStart negative, base valid ({start}, {base})"
        );

        let _ = door(&bad, &registry);
        let _ = door(&data(topic, 1), &registry);
        let _ = door(&heartbeat(1, 1), &registry);

        assert_eq!(
            taken_xs(&reader),
            vec![1],
            "(k) the invalid GAP is refused, so the next HEARTBEAT seeds the \
             gate and seq 1 is delivered"
        );
    }

    /// (l) The decoder refuses exactly the GAPs RTPS calls invalid: gapStart
    /// zero or negative (Sec.8.3.8.4.3), gapList.base zero or negative
    /// (Sec.8.3.5.5, minimum >= 1). One row per condition, so deleting any
    /// one of them turns this red; and a valid GAP as the control.
    #[test]
    fn the_decoder_refuses_the_gaps_rtps_calls_invalid() {
        let negative = (1u64 << 63) + 5;
        for (start, base, why) in [
            (0u64, 3u64, "gapStart zero"),
            (negative, 3, "gapStart negative"),
            (1, 0, "gapList.base zero"),
            (1, negative, "gapList.base negative"),
        ] {
            let pkt = raw_gap(start, base);
            let (gaps, _hbs, _) = scan_all_embedded_control_submessages(&pkt);
            assert!(gaps.is_empty(), "(l) {why}: must not decode, got {gaps:?}");
        }
        let (gaps, _hbs, _) = scan_all_embedded_control_submessages(&raw_gap(1, 3));
        assert_eq!(gaps.len(), 1, "(l) control: GAP(1, 3) decodes");
    }

    /// A BEST_EFFORT + TRANSIENT_LOCAL reader receives a best-effort
    /// writer's samples. Its gate must not be the reliable one, seeded only
    /// by a HEARTBEAT or a GAP - a best-effort writer sends neither, in
    /// HDDS as in RTPS, so the reader would receive nothing at all.
    /// RTPS 2.5 8.4.12.1 T2 accepts a change on its sequence number alone.
    #[test]
    fn a_best_effort_durable_reader_receives_a_heartbeatless_writer() {
        let _ = rt::init_slab_pool();
        let topic = "BestEffortDurableNoHeartbeat";
        let registry = Arc::new(TopicRegistry::new());
        let reader = ReaderBuilder::<Point>::new(topic.to_string())
            .qos(QoS::best_effort().transient_local())
            .with_registry(Arc::clone(&registry))
            .build()
            .expect("reader build");
        bind_writer_as_sedp_does(&registry, topic);

        for s in 1..=3u64 {
            let _ = door(&data(topic, s), &registry);
        }
        assert_eq!(taken_xs(&reader), vec![1, 2, 3]);
    }

    /// The same reader never waits for a hole (nobody repairs a best-effort
    /// reader) and discards what arrives late (T2: "no duplicate changes
    /// and no out-of-order changes").
    #[test]
    fn a_best_effort_reader_skips_a_hole_and_discards_the_late_change() {
        let _ = rt::init_slab_pool();
        let topic = "BestEffortHoleAndLate";
        let registry = Arc::new(TopicRegistry::new());
        let reader = ReaderBuilder::<Point>::new(topic.to_string())
            .qos(QoS::best_effort().transient_local())
            .with_registry(Arc::clone(&registry))
            .build()
            .expect("reader build");
        bind_writer_as_sedp_does(&registry, topic);

        for s in [1u64, 3, 2, 3, 4] {
            let _ = door(&data(topic, s), &registry);
        }
        assert_eq!(taken_xs(&reader), vec![1, 3, 4]);
    }

    /// (g) The firstSN rule, pinned at the one function that holds it.
    ///
    /// A HEARTBEAT whose firstSN is not strictly positive is malformed (RTPS
    /// v2.5 Sec.9.3.2) and must seed nothing. The rule lives in
    /// `control::seed_reorder_gate`, which BOTH doors call, so this pins it
    /// for UDP and TCP/QUIC at once.
    ///
    /// Why not through the door, like (a)..(f): because there it cannot be
    /// seen. A gate seeded at 0 holds every sample (no DATA carries seq 0),
    /// and the next valid HEARTBEAT fast-forwards it (`first_seq > next`), so
    /// refusing and seeding-at-0 deliver the same thing; they differ only past
    /// the 4096-sample cap. A door-level test of this rule would pass with the
    /// rule deleted.
    #[test]
    fn seed_rule_refuses_a_first_sn_that_is_not_positive() {
        use crate::core::discovery::multicast::control::seed_reorder_gate;
        use crate::core::discovery::multicast::control_types::HeartbeatInfo;

        let hb = |first_seq: i64| HeartbeatInfo {
            writer_entity_id: WRITER_ENTITY,
            first_seq,
            last_seq: 3,
            count: 1,
            final_flag: false,
            liveliness_flag: false,
        };

        let (refusing, _r1) = non_volatile_reliable_reader("SeedRuleRefuse");
        assert!(
            !seed_reorder_gate(&refusing, &WRITER_PREFIX, &hb(0), [0; 4], None),
            "(g) firstSN 0 must notify no gate"
        );
        assert!(
            !seed_reorder_gate(&refusing, &WRITER_PREFIX, &hb(-1), [0; 4], None),
            "(g) a negative firstSN must notify no gate"
        );

        // Control: the same writer, the same registry shape, a valid firstSN.
        // Without it, "false" could just mean the writer is not bound.
        let (accepting, _r2) = non_volatile_reliable_reader("SeedRuleAccept");
        assert!(
            seed_reorder_gate(&accepting, &WRITER_PREFIX, &hb(1), [0; 4], None),
            "(g) control: firstSN 1 from a bound writer notifies its gate"
        );
    }

    /// (c1) CONTROL: DATA 1..3 through the door, then the seeding call the
    /// UDP control channel makes (`control.rs` -> notify_writer_heartbeat).
    /// The first assertion proves the real gate is on the path (it HOLDS),
    /// the second that the fixture delivers once seeded.
    #[test]
    fn control_udp_heartbeat_seed_releases_door_data() {
        let topic = "UnicastGateC1";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        for s in 1..=3u64 {
            let _ = door(&data(topic, s), &registry);
        }
        assert_eq!(
            taken_xs(&reader),
            Vec::<i32>::new(),
            "(c1) unseeded non-volatile gate must HOLD every sample"
        );
        assert!(
            registry.notify_writer_heartbeat(writer_guid(), 1),
            "(c1) writer W must resolve to the reader's topic"
        );
        assert_eq!(
            taken_xs(&reader),
            vec![1, 2, 3],
            "(c1) the UDP-path seed must release the held samples in order"
        );
    }

    /// (d) SANITY: the door itself delivers when the reorder gate is
    /// disabled (VOLATILE BEST_EFFORT), same fixture otherwise.
    #[test]
    fn unicast_door_delivers_to_volatile_best_effort_reader() {
        let topic = "UnicastGateD";
        let _ = rt::init_slab_pool();
        let registry = Arc::new(TopicRegistry::new());
        let reader = ReaderBuilder::<Point>::new(topic.to_string())
            .qos(QoS::best_effort())
            .with_registry(Arc::clone(&registry))
            .build()
            .expect("reader build");
        bind_writer_as_sedp_does(&registry, topic);
        let o = door(&data(topic, 1), &registry);
        eprintln!("(d) DATA outcome={o:?}");
        assert_eq!(taken_xs(&reader), vec![1], "(d) gate disabled: delivered");
    }

    /// (c2) CONTROL: DATA 3 through the door, then the GAP call the UDP
    /// control channel makes (`control.rs` -> notify_writer_gap).
    #[test]
    fn control_udp_gap_releases_door_data() {
        let topic = "UnicastGateC2";
        let (registry, reader) = non_volatile_reliable_reader(topic);

        let _ = door(&data(topic, 3), &registry);
        assert_eq!(taken_xs(&reader), Vec::<i32>::new(), "(c2) held");
        // Exactly the arguments control.rs:769 hands over for GAP(1, 3).
        assert!(registry.notify_writer_gap(writer_guid(), 1, 3, vec![1, 2]));
        assert_eq!(
            taken_xs(&reader),
            vec![3],
            "(c2) the UDP-path GAP must release seq 3"
        );
    }
}

/// RTPS 2.5 8.4.12: a reliable reader keeps one WriterProxy for each
/// RELIABLE writer it is matched with (`matched_writer_add`), under the
/// GUID it announces, and drops it when that writer goes
/// (`matched_writer_remove`). A best-effort writer is never acknowledged,
/// and a best-effort reader keeps no proxy at all.
#[test]
fn a_reliable_reader_keeps_a_proxy_per_matched_reliable_writer_only() {
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::{SedpData, SpdpData};

    let _ = rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("proxy_per_writer")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "ProxyPerWriter";
    let reliable = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable())
        .build()
        .expect("reliable reader");
    let _best_effort = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::best_effort())
        .build()
        .expect("best-effort reader");

    // The GUID the reliable reader announced, read back from the local
    // discovery database the announcement feeds: its proxies must carry it.
    let fsm = participant.discovery().expect("discovery FSM");
    let prefix = participant.guid().prefix;
    let announced: Vec<[u8; 16]> = fsm
        .find_readers_for_topic(topic)
        .into_iter()
        .filter(|r| {
            r.endpoint_guid.prefix == prefix
                && matches!(r.qos.reliability, crate::dds::qos::Reliability::Reliable)
        })
        .map(|r| r.endpoint_guid.as_bytes())
        .collect();
    assert_eq!(announced.len(), 1, "one reliable reader announced");
    // Its subscriber reports that same id, so a HEARTBEAT or GAP addressed
    // to another reader passes it by.
    let [.., e0, e1, e2, e3] = announced[0];
    let subscribers = participant
        .registry
        .as_ref()
        .and_then(|registry| registry.get_topic(topic))
        .expect("the readers' topic is registered")
        .reader_entity_ids();
    assert!(
        subscribers.contains(&Some([e0, e1, e2, e3])),
        "{subscribers:02x?}"
    );

    // A remote participant past the FSM's startup probation, confirmed by
    // two SPDP announcements (same sequence as `live_discovery` in
    // sedp_handler.rs).
    let remote_prefix = [0x5A; 12];
    let spdp = || SpdpData {
        participant_guid: GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]),
        lease_duration_ms: 100_000,
        domain_id: domain.id(),
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
    };
    std::thread::sleep(std::time::Duration::from_millis(300));
    fsm.handle_spdp(spdp());
    std::thread::sleep(std::time::Duration::from_millis(150));
    fsm.handle_spdp(spdp());

    let announce = |entity_id: [u8; 4], qos: QoS| {
        let writer = GUID::new(remote_prefix, entity_id);
        fsm.handle_sedp(SedpData {
            topic_name: topic.to_string(),
            type_name: Point::type_descriptor().type_name.to_string(),
            participant_guid: GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]),
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
        });
        writer
    };
    let reliable_writer = announce([0x00, 0x00, 0x01, 0x02], QoS::reliable());
    let best_effort_writer = announce([0x00, 0x00, 0x02, 0x02], QoS::best_effort());

    let registry = &participant.user_data_registry;
    assert_eq!(
        registry.readers_of(&reliable_writer.as_bytes()),
        announced,
        "the reliable writer is tracked by the reliable reader alone, under its announced GUID"
    );
    assert!(
        registry
            .readers_of(&best_effort_writer.as_bytes())
            .is_empty(),
        "a best-effort writer is never acknowledged"
    );

    assert!(fsm.remove_remote_endpoint(reliable_writer));
    assert!(
        registry.readers_of(&reliable_writer.as_bytes()).is_empty(),
        "the proxy goes with the writer"
    );

    // Announced again, it matches again; the reader dropped, its proxy goes.
    let reliable_writer = announce([0x00, 0x00, 0x01, 0x02], QoS::reliable());
    assert_eq!(registry.readers_of(&reliable_writer.as_bytes()), announced);
    drop(reliable);
    assert!(
        registry.readers_of(&reliable_writer.as_bytes()).is_empty(),
        "the proxy goes with the reader"
    );
}

/// A remote participant that announces twice inside this participant's
/// probation window and then goes silent (a few SPDPs at startup, then a
/// long resend period). Its writer's SEDP arrives inside the window
/// too. The DDS match waits for the FSM's confirmation gate, which only a
/// later SPDP releases; the reader's WriterProxy must not (RTPS 2.5 8.4.12
/// `matched_writer_add` is a discovery event), whichever side was there
/// first: a reader registered before the SEDP (live path) and one registered
/// after it (catch-up path) both track the writer at once, and both drop it
/// when the writer goes.
#[test]
fn a_writer_discovered_inside_probation_is_tracked_before_its_match_surfaces() {
    use crate::core::discovery::GUID;
    use crate::protocol::discovery::{SedpData, SpdpData};

    let _ = rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("proxy_inside_probation")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "ProxyInsideProbation";
    let before = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable())
        .build()
        .expect("reader registered before the SEDP");

    let fsm = participant.discovery().expect("discovery FSM");
    let remote_prefix = [0x5B; 12];
    let remote_participant = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
    let spdp = || SpdpData {
        participant_guid: remote_participant,
        lease_duration_ms: 100_000,
        domain_id: domain.id(),
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
    };
    // Both announcements land inside the 250 ms probation window, and the
    // second inside the entry's own 100 ms window: the participant is known,
    // never confirmed, and nothing arrives after the boundary.
    fsm.handle_spdp(spdp());
    fsm.handle_spdp(spdp());
    let writer = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0x02]);
    fsm.handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: Point::type_descriptor().type_name.to_string(),
        participant_guid: remote_participant,
        endpoint_guid: writer,
        qos_hash: 1,
        qos: Some(QoS::reliable()),
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
    });
    assert!(
        !fsm.is_probation_done(),
        "the whole exchange happened inside the probation window"
    );

    let after = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable())
        .build()
        .expect("reader registered after the SEDP");

    let prefix = participant.guid().prefix;
    let mut announced: Vec<[u8; 16]> = fsm
        .find_readers_for_topic(topic)
        .into_iter()
        .filter(|r| r.endpoint_guid.prefix == prefix)
        .map(|r| r.endpoint_guid.as_bytes())
        .collect();
    announced.sort_unstable();
    assert_eq!(announced.len(), 2, "two reliable readers announced");

    let registry = &participant.user_data_registry;
    assert_eq!(
        registry.readers_of(&writer.as_bytes()),
        announced,
        "both readers track the writer although its match is still deferred"
    );

    assert!(fsm.remove_remote_endpoint(writer));
    assert!(
        registry.readers_of(&writer.as_bytes()).is_empty(),
        "the proxies go with the writer, matched or not"
    );
    drop(before);
    drop(after);
}

/// The same peer, on the wire: its writer's HEARTBEAT reaches a reliable
/// reader whose match the FSM still holds back, and the reader acknowledges
/// it under its own name. Each reader answers from its own proxy: a reader
/// with no proxy answers nothing, so the writer would never receive an
/// ACKNACK and whole batches would go undelivered.
#[test]
fn a_reader_acknowledges_a_writer_whose_participant_went_silent_inside_probation() {
    use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
    use crate::core::discovery::GUID;
    use crate::protocol::builder::{build_heartbeat_packet_with_context, RtpsEndpointContext};
    use crate::protocol::discovery::{SedpData, SpdpData};
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    let _ = rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("silent_peer_acknack")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "SilentPeerAcknack";
    let _reader = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable())
        .build()
        .expect("reliable reader");

    // The peer: one socket, announced as its metatraffic locator so the
    // ACKNACK comes back here.
    let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
    peer.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    let peer_addr = peer.local_addr().expect("peer addr");

    let fsm = participant.discovery().expect("discovery FSM");
    let remote_prefix = [0x5C; 12];
    let remote_participant = GUID::new(remote_prefix, [0x00, 0x00, 0x01, 0xC1]);
    let spdp = || SpdpData {
        participant_guid: remote_participant,
        lease_duration_ms: 100_000,
        domain_id: domain.id(),
        metatraffic_unicast_locators: vec![peer_addr],
        default_unicast_locators: vec![peer_addr],
        default_multicast_locators: vec![],
        metatraffic_multicast_locators: vec![],
        identity_token: None,
        permissions_token: None,
        participant_security_info: None,
        vendor_id: None,
        hdds_capabilities: None,
        builtin_endpoint_set: None,
    };
    fsm.handle_spdp(spdp());
    fsm.handle_spdp(spdp());
    let writer_entity_id = [0x00, 0x00, 0x01, 0x02];
    fsm.handle_sedp(SedpData {
        topic_name: topic.to_string(),
        type_name: Point::type_descriptor().type_name.to_string(),
        participant_guid: remote_participant,
        endpoint_guid: GUID::new(remote_prefix, writer_entity_id),
        qos_hash: 1,
        qos: Some(QoS::reliable()),
        type_object: None,
        dependents: Vec::new(),
        type_object_legacy_v1: false,
        unicast_locators: vec![peer_addr],
        user_data: None,
        shm_capability: None,
        has_explicit_reliability: true,
        has_explicit_ownership: false,
        has_ownership_strength: false,
        type_information: None,
        type_consistency: None,
        group_entity_id: None,
        endpoint_security_info: None,
    });
    assert!(
        !fsm.is_probation_done(),
        "the whole exchange happened inside the probation window"
    );

    // The peer sends nothing but HEARTBEATs (readerId ENTITYID_UNKNOWN:
    // every reader tracking the writer), to the metatraffic unicast port,
    // which is bound on every interface.
    let mapping = participant.port_mapping().expect("port mapping");
    let dest = std::net::SocketAddr::from(([127, 0, 0, 1], mapping.metatraffic_unicast));
    let ctx = RtpsEndpointContext {
        guid_prefix: remote_prefix,
        reader_entity_id: [0; 4],
        writer_entity_id,
        encapsulation_kind: 0,
        publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
    };
    let mut buf = [0u8; 1024];
    let mut answered = None;
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut count = 0u32;
    while Instant::now() < deadline && answered.is_none() {
        count += 1;
        let heartbeat = build_heartbeat_packet_with_context(&ctx, 1, 3, count);
        peer.send_to(&heartbeat, dest).expect("send heartbeat");
        // Up to ~200 ms for the answer (the control thread batches
        // non-final HEARTBEATs for 50 ms).
        for _ in 0..2 {
            if let Ok((len, _)) = peer.recv_from(&mut buf) {
                answered = parse_all_acknack_submessages(&buf[..len])
                    .into_iter()
                    .find(|a| a.writer_entity_id == writer_entity_id);
                if answered.is_some() {
                    break;
                }
            }
        }
    }
    let acknack = answered.expect("the reader answered the writer's HEARTBEAT within 4 s");
    assert_eq!(
        acknack.bitmap_base, 1,
        "it holds nothing of the writer and asks from the first sample"
    );
    let prefix = participant.guid().prefix;
    let announced: Vec<[u8; 4]> = fsm
        .find_readers_for_topic(topic)
        .into_iter()
        .filter(|r| r.endpoint_guid.prefix == prefix)
        .map(|r| {
            let bytes = r.endpoint_guid.as_bytes();
            [bytes[12], bytes[13], bytes[14], bytes[15]]
        })
        .collect();
    assert_eq!(
        announced,
        vec![acknack.reader_entity_id],
        "it answers under its own, announced readerId"
    );
}

/// A remote peer for the probation tests below: one UDP socket announced as
/// its metatraffic locator, its participant GUID and its writer on `topic`.
struct ProbationPeer {
    socket: std::net::UdpSocket,
    prefix: [u8; 12],
    domain_id: u32,
    topic: &'static str,
}

impl ProbationPeer {
    const WRITER_ENTITY_ID: [u8; 4] = [0x00, 0x00, 0x01, 0x02];

    fn new(prefix: [u8; 12], domain_id: u32, topic: &'static str) -> Self {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .expect("read timeout");
        Self {
            socket,
            prefix,
            domain_id,
            topic,
        }
    }

    fn participant(&self) -> crate::core::discovery::GUID {
        crate::core::discovery::GUID::new(self.prefix, [0x00, 0x00, 0x01, 0xC1])
    }

    fn writer(&self) -> crate::core::discovery::GUID {
        crate::core::discovery::GUID::new(self.prefix, Self::WRITER_ENTITY_ID)
    }

    fn spdp(&self) -> crate::protocol::discovery::SpdpData {
        let addr = self.socket.local_addr().expect("peer addr");
        crate::protocol::discovery::SpdpData {
            participant_guid: self.participant(),
            lease_duration_ms: 100_000,
            domain_id: self.domain_id,
            metatraffic_unicast_locators: vec![addr],
            default_unicast_locators: vec![addr],
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

    fn sedp(&self) -> crate::protocol::discovery::SedpData {
        crate::protocol::discovery::SedpData {
            topic_name: self.topic.to_string(),
            type_name: Point::type_descriptor().type_name.to_string(),
            participant_guid: self.participant(),
            endpoint_guid: self.writer(),
            qos_hash: 1,
            qos: Some(QoS::reliable()),
            type_object: None,
            dependents: Vec::new(),
            type_object_legacy_v1: false,
            unicast_locators: vec![self.socket.local_addr().expect("peer addr")],
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

    /// One HEARTBEAT (readerId ENTITYID_UNKNOWN) to the participant's
    /// metatraffic unicast port; returns the ACKNACK answering it for this
    /// writer, if one arrives within ~200 ms.
    fn heartbeat(
        &self,
        participant: &crate::Participant,
        count: u32,
    ) -> Option<crate::core::discovery::multicast::control_types::AckNackInfo> {
        use crate::core::discovery::multicast::control_parser::parse_all_acknack_submessages;
        use crate::protocol::builder::{build_heartbeat_packet_with_context, RtpsEndpointContext};
        let mapping = participant.port_mapping().expect("port mapping");
        let dest = std::net::SocketAddr::from(([127, 0, 0, 1], mapping.metatraffic_unicast));
        let ctx = RtpsEndpointContext {
            guid_prefix: self.prefix,
            reader_entity_id: [0; 4],
            writer_entity_id: Self::WRITER_ENTITY_ID,
            encapsulation_kind: 0,
            publisher_entity_id: [0x00, 0x00, 0x01, 0x08],
        };
        let packet = build_heartbeat_packet_with_context(&ctx, 1, 3, count);
        self.socket.send_to(&packet, dest).expect("send heartbeat");
        let mut buf = [0u8; 1024];
        for _ in 0..2 {
            if let Ok((len, _)) = self.socket.recv_from(&mut buf) {
                let found = parse_all_acknack_submessages(&buf[..len])
                    .into_iter()
                    .find(|a| a.writer_entity_id == Self::WRITER_ENTITY_ID);
                if found.is_some() {
                    return found;
                }
            }
        }
        None
    }
}

/// Sleep until the participant's discovery FSM is `uptime` old.
fn sleep_until_uptime(
    fsm: &crate::core::discovery::multicast::DiscoveryFsm,
    uptime: std::time::Duration,
) {
    let now = fsm.uptime();
    if now < uptime {
        std::thread::sleep(uptime - now);
    }
}

/// Records every endpoint discovery surfaces to the application.
#[derive(Default)]
struct SurfacedEndpoints(std::sync::Mutex<Vec<crate::core::discovery::GUID>>);

impl crate::core::discovery::multicast::DiscoveryListener for SurfacedEndpoints {
    fn on_endpoint_discovered(&self, endpoint: crate::core::discovery::multicast::EndpointInfo) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(endpoint.endpoint_guid);
    }
}

/// A quiet peer: announced once inside our probation, its writer's SEDP
/// ~150 ms later, then no SPDP for 30 s and no further SEDP, only HEARTBEATs. The
/// probation boundary fires on the participant's own clock (the control
/// thread), keeps the peer because it spoke after its first 100 ms, and its
/// next HEARTBEAT, at a distinct instant, confirms it and surfaces the match.
/// Before: nothing fired the boundary at all, and the match waited for the
/// next SPDP, 30 s away.
#[test]
fn a_quiet_peer_heard_after_its_announcement_matches_on_our_own_clock() {
    use std::time::{Duration, Instant};
    let _ = rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("quiet_peer_own_clock")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let fsm = participant.discovery().expect("discovery FSM");
    let surfaced = std::sync::Arc::new(SurfacedEndpoints::default());
    fsm.register_listener(surfaced.clone());
    let peer = ProbationPeer::new([0x5D; 12], domain.id(), "QuietPeerOwnClock");
    assert!(
        fsm.uptime() < Duration::from_millis(90),
        "fixture: the peer must announce early in the probation window"
    );

    fsm.handle_spdp(peer.spdp());
    std::thread::sleep(Duration::from_millis(150));
    fsm.handle_sedp(peer.sedp());
    assert!(
        fsm.uptime() < Duration::from_millis(250) && !fsm.is_probation_done(),
        "fixture: the SEDP lands inside the probation window"
    );

    // Nothing reaches the FSM now but the clock.
    sleep_until_uptime(&fsm, Duration::from_millis(320));
    assert!(
        fsm.is_probation_done(),
        "the boundary fired with no SPDP or SEDP after it"
    );
    assert!(
        fsm.has_participant(&peer.participant()),
        "a peer that spoke after its first 100 ms survives the boundary"
    );

    let deadline = Instant::now() + Duration::from_secs(1);
    let mut count = 0;
    while Instant::now() < deadline
        && !surfaced
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&peer.writer())
    {
        count += 1;
        let _ = peer.heartbeat(&participant, count);
    }
    assert!(
        surfaced
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&peer.writer()),
        "its HEARTBEAT confirmed it and surfaced the writer within 1 s"
    );
}

/// RTPS 2.5 8.4.12: the WriterProxy a reliable reader takes at discovery
/// must survive the probation boundary for a peer that is alive.
/// Same quiet-peer shape as above; the boundary passes (on the timer), then a
/// local endpoint is created (creating one must not fire the boundary, or the
/// purge would take the proxy with the peer), and only then does the peer
/// send its first HEARTBEAT. The reader answers it.
#[test]
fn a_writer_proxy_taken_inside_probation_survives_the_boundary() {
    use std::time::{Duration, Instant};
    let _ = rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("proxy_survives_boundary")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "ProxySurvivesBoundary";
    let _reader = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable())
        .build()
        .expect("reliable reader");
    let fsm = participant.discovery().expect("discovery FSM");
    let peer = ProbationPeer::new([0x5E; 12], domain.id(), topic);
    assert!(
        fsm.uptime() < Duration::from_millis(90),
        "fixture: the peer must announce early in the probation window"
    );

    fsm.handle_spdp(peer.spdp());
    std::thread::sleep(Duration::from_millis(150));
    fsm.handle_sedp(peer.sedp());
    assert!(
        !fsm.is_probation_done(),
        "fixture: the SEDP lands inside the probation window"
    );

    sleep_until_uptime(&fsm, Duration::from_millis(320));
    let _other = participant
        .topic::<Point>("ProxySurvivesBoundaryOther")
        .expect("topic")
        .writer()
        .build()
        .expect("a local endpoint created after the boundary");
    assert!(fsm.is_probation_done());

    let prefix = participant.guid().prefix;
    let reader_guid: Vec<[u8; 16]> = fsm
        .find_readers_for_topic(topic)
        .into_iter()
        .filter(|r| r.endpoint_guid.prefix == prefix)
        .map(|r| r.endpoint_guid.as_bytes())
        .collect();
    assert_eq!(
        participant
            .user_data_registry
            .readers_of(&peer.writer().as_bytes()),
        reader_guid,
        "the reader still tracks the writer past the boundary"
    );

    let deadline = Instant::now() + Duration::from_secs(4);
    let mut count = 0;
    let mut answered = None;
    while Instant::now() < deadline && answered.is_none() {
        count += 1;
        answered = peer.heartbeat(&participant, count);
    }
    let acknack = answered.expect("the reader answered the writer's HEARTBEAT");
    assert_eq!(acknack.bitmap_base, 1, "asks from the first sample");
    assert_eq!(acknack.reader_entity_id[..], reader_guid[0][12..]);
}

/// When the probation boundary DOES purge a participant (nothing heard from
/// it after its first 100 ms: the zombie shape), the WriterProxies discovery
/// gave its writers go with it (a dead writer is owed no ACKNACK), and come
/// back with the participant if it announces again: its retained SEDP is
/// replayed through discovery, which pairs the reader anew.
#[test]
fn a_purged_participant_takes_its_writer_proxies_and_brings_them_back() {
    use std::time::Duration;
    let _ = rt::init_slab_pool();
    let domain = crate::test_support::domains::unique_domain();
    let participant = crate::Participant::builder("proxy_purged_and_back")
        .domain_id(domain.id())
        .with_transport(crate::TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic = "ProxyPurgedAndBack";
    let _reader = participant
        .topic::<Point>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable())
        .build()
        .expect("reliable reader");
    let fsm = participant.discovery().expect("discovery FSM");
    let peer = ProbationPeer::new([0x5F; 12], domain.id(), topic);

    fsm.handle_spdp(peer.spdp());
    let heard = std::time::Instant::now();
    fsm.handle_sedp(peer.sedp());
    assert!(!fsm.is_probation_done(), "fixture: inside probation");
    let registry = &participant.user_data_registry;
    let tracked = registry.readers_of(&peer.writer().as_bytes());
    assert_eq!(
        tracked.len(),
        1,
        "the reader tracks the writer at discovery"
    );

    // Past the boundary, and past the peer's own verdict (judged once it
    // is as old as the probation span), both fired by the control thread.
    sleep_until_uptime(&fsm, Duration::from_millis(320));
    let verdict = heard + Duration::from_millis(330);
    if let Some(left) = verdict.checked_duration_since(std::time::Instant::now()) {
        std::thread::sleep(left);
    }
    assert!(fsm.is_probation_done(), "the boundary fired on the timer");
    assert!(
        !fsm.has_participant(&peer.participant()),
        "never heard from after its first 100 ms: purged"
    );
    assert!(
        registry.readers_of(&peer.writer().as_bytes()).is_empty(),
        "the proxy goes with the purged participant"
    );

    fsm.handle_spdp(peer.spdp());
    assert!(fsm.has_participant(&peer.participant()));
    assert_eq!(
        registry.readers_of(&peer.writer().as_bytes()),
        tracked,
        "its next SPDP rebuilds the writer, and the proxy with it"
    );
}

/// A reliable network reader's subscriber on `topic` crediting `credit`,
/// with coherent access on (a tagged sequence takes the coherent path), and
/// the ring it delivers to.
fn credited_subscriber(
    topic: &str,
    credit: crate::core::reader::ReaderAckCredit,
) -> (
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    use std::sync::{Arc, Mutex};
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        topic.to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
        // Coherent access on, so the tagged sequence takes the coherent
        // staging path and its own duplicate filter.
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
        None,
        Some(credit),
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    (ring, sub)
}

/// After a re-match (the writer left discovery and came back under the same
/// GUID), the reader's fresh WriterProxy knows nothing and requests what the
/// reader already holds. The retransmissions are duplicates to the reader's
/// filter and are not delivered again, but they were received: they must
/// move the acknowledgement forward, or a KEEP_ALL writer waits for an
/// acknowledgement that never comes.
#[test]
fn a_retransmission_after_a_rematch_is_acknowledged_though_not_redelivered() {
    use crate::core::reader::{HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xB7; 16];
    let credit = ReaderAckCredit::new(registry.clone(), [0xA0; 16]);
    credit.match_writer(writer);

    let (ring, sub) = credited_subscriber("Rematch", credit.clone());
    let data = encoded_point(1, 2);
    let heartbeat = |count| HeartbeatSeen {
        first_seq: 1,
        last_seq: 5,
        count,
        final_flag: false,
    };
    // Sequences 1..=3 carry samples, 4 carries none (a key-only DATA, a
    // registration marker), 5 is tagged with a coherent set: each path has
    // its own duplicate filter.
    let receive_all = || {
        for seq in 1..=3u64 {
            sub.on_data_with_writer("Rematch", writer, seq, &data, crate::dds::CdrVersion::Xcdr2);
        }
        sub.on_writer_non_data(writer, 4);
        sub.on_data_coherent(
            "Rematch",
            writer,
            5,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(5),
            None,
            None,
        );
    };

    receive_all();
    let delivered = ring.len();
    assert!(delivered >= 3, "the three untagged samples are delivered");
    let answer = credit
        .answer_heartbeat(&writer, &heartbeat(1))
        .expect("matched");
    assert_eq!(answer.bitmap_base, 6);

    credit.unmatch_writer(&writer);
    credit.match_writer(writer);
    let answer = credit
        .answer_heartbeat(&writer, &heartbeat(2))
        .expect("re-matched");
    assert_eq!(answer.bitmap_base, 1, "a fresh proxy requests everything");

    receive_all();
    assert_eq!(
        ring.len(),
        delivered,
        "the retransmissions are not delivered again"
    );
    let answer = credit
        .answer_heartbeat(&writer, &heartbeat(3))
        .expect("matched");
    assert_eq!(
        (answer.bitmap_base, answer.final_flag),
        (6, true),
        "they were received, and are acknowledged"
    );
}

/// A DataWriter re-created under the GUID of one that left (a participant
/// rebuilt in the same process with the same prefix and entity ids, or a
/// participant that authenticated again) is a new writer: its sequence
/// numbers start again at 1 (RTPS v2.5 Sec.8.3.5.4), and the reader that
/// retired the old one delivers them. Its reorder gate must not keep the old
/// writer's high-water mark: dropping every sample below it as already
/// delivered and crediting it to the acknowledgement would stop the writer
/// from ever sending it again, leaving the re-created writer deaf until it
/// passed where the old one stopped.
#[test]
fn a_writer_recreated_under_a_retired_guid_is_delivered_from_its_first_sample() {
    use crate::core::reader::{HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::subscriber::DisposeKind;
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let pool = rt::get_slab_pool();
    let writer = [0xB8; 16];
    let data = encoded_point(1, 2);
    // The gates of a RELIABLE reader: VOLATILE (seeded by its first
    // sample) and TRANSIENT_LOCAL (seeded by the writer's HEARTBEAT).
    for (durable, gate) in [
        (false, super::reorder::ReorderGate::new(true, true)),
        (true, super::reorder::ReorderGate::new(true, false)),
    ] {
        let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
        credit.match_writer(writer);
        let (ring, sub, _) = gated_subscriber("Recreated", credit.clone(), gate);
        let mut taken = 0usize;
        let mut take = |ring: &rt::IndexRing| {
            while let Some(entry) = ring.pop() {
                pool.release(entry.handle);
                taken += 1;
            }
            taken
        };

        if durable {
            sub.on_writer_heartbeat(writer, 1);
        }
        for seq in 1..=5u64 {
            sub.on_data_with_writer(
                "Recreated",
                writer,
                seq,
                &data,
                crate::dds::CdrVersion::Xcdr2,
            );
        }
        assert_eq!(take(&ring), 5, "durable={durable}: the first writer");

        // The writer leaves (its SEDP dispose, its participant's departure
        // or purge, or a re-authentication), and the match goes with it.
        sub.on_writer_dispose("Recreated", writer, DisposeKind::Unregistered);
        assert_eq!(
            sub.delivery_lock_count(),
            0,
            "durable={durable}: its delivery lock goes with it"
        );
        credit.unmatch_writer(&writer);

        // The same GUID is announced again, by a new writer, whose first
        // HEARTBEAT shows its sequence numbers started again.
        credit.match_writer(writer);
        sub.on_writer_heartbeat_range(writer, 1, 3);
        for seq in 1..=3u64 {
            sub.on_data_with_writer(
                "Recreated",
                writer,
                seq,
                &data,
                crate::dds::CdrVersion::Xcdr2,
            );
        }
        assert_eq!(
            take(&ring),
            8,
            "durable={durable}: the re-created writer's samples 1..=3 are delivered"
        );
        let answer = credit
            .answer_heartbeat(
                &writer,
                &HeartbeatSeen {
                    first_seq: 1,
                    last_seq: 3,
                    count: 7,
                    final_flag: false,
                },
            )
            .expect("matched");
        assert_eq!(
            (answer.bitmap_base, answer.missing.is_empty()),
            (4, true),
            "durable={durable}: what was delivered, and only that, is acknowledged"
        );
    }
}

/// A best-effort reader's gate keeps the highest sequence it took from each
/// writer and discards anything older (RTPS v2.5 Sec.8.4.12.1): a writer
/// re-created under a retired GUID starts again at 1 and must not be taken
/// for the old one's stale traffic.
#[test]
fn a_best_effort_reader_takes_a_writer_recreated_under_a_retired_guid() {
    use crate::engine::subscriber::DisposeKind;
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let pool = rt::get_slab_pool();
    let writer = [0xB9; 16];
    let data = encoded_point(1, 2);
    let credit = crate::core::reader::ReaderAckCredit::new(
        crate::core::reader::ReaderProxyRegistry::new(),
        [0xA0; 16],
    );
    let (ring, sub, _) = gated_subscriber(
        "RecreatedBe",
        credit,
        super::reorder::ReorderGate::new_best_effort(),
    );
    for seq in 1..=5u64 {
        sub.on_data_with_writer(
            "RecreatedBe",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    sub.on_writer_dispose("RecreatedBe", writer, DisposeKind::Unregistered);
    // Re-created, it is announced (SEDP) before it is heard.
    sub.on_writer_qos_resolved(writer);
    for seq in 1..=3u64 {
        sub.on_data_with_writer(
            "RecreatedBe",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    let mut taken = 0;
    while let Some(entry) = ring.pop() {
        pool.release(entry.handle);
        taken += 1;
    }
    assert_eq!(taken, 8, "the re-created writer's 1..=3 are taken");
}

/// A reliable reader without a bounded history (KEEP_LAST), with the
/// reorder gate a reliable reader has in production.
fn gated_subscriber(
    topic: &str,
    credit: crate::core::reader::ReaderAckCredit,
    gate: super::reorder::ReorderGate,
) -> (
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
    std::sync::Arc<std::sync::Mutex<crate::dds::listener::SampleRejectedStatus>>,
) {
    gated_subscriber_on(
        topic,
        credit,
        std::sync::Arc::new(std::sync::Mutex::new(gate)),
        None,
    )
}
fn gated_subscriber_on(
    topic: &str,
    credit: crate::core::reader::ReaderAckCredit,
    gate: std::sync::Arc<std::sync::Mutex<super::reorder::ReorderGate>>,
    listener: Option<std::sync::Arc<dyn crate::dds::listener::DataReaderListener<Point>>>,
) -> (
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
    std::sync::Arc<std::sync::Mutex<crate::dds::listener::SampleRejectedStatus>>,
) {
    use std::sync::{Arc, Mutex};
    let ring = Arc::new(rt::IndexRing::with_capacity(8192));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let rejected = Arc::new(Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        topic.to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        listener,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        gate,
        super::subscriber::CoherentConfig::default(),
        None,
        Some(credit),
        Arc::clone(&rejected),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    (ring, sub, rejected)
}

/// a reliable reader missed 2 and 5, and received all the gate can
/// hold above them. The repair of 2 is older than the duplicate window: it
/// must not be dropped as a duplicate AND acknowledged (lost for good) because
/// the gate gave the gap up to bound its memory. At its bound the gate
/// refuses, unacknowledged, and the stream resumes in order once the gap
/// fills. Both durabilities, with the reorder gate they have in production.
#[test]
fn a_repair_older_than_the_duplicate_window_is_delivered_in_order() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    for volatile in [false, true] {
        let registry = ReaderProxyRegistry::new();
        let writer = [0xB8; 16];
        let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
        credit.match_writer(writer);
        let (ring, sub, rejected) = gated_subscriber(
            "OldRepair",
            credit.clone(),
            super::reorder::ReorderGate::new(true, volatile),
        );
        if !volatile {
            sub.on_writer_heartbeat(writer, 1);
        }
        let pool = rt::get_slab_pool();
        let delivered = std::cell::RefCell::new(Vec::new());
        let receive = |seq: u64| {
            let value = i32::try_from(seq).expect("small");
            sub.on_data_with_writer(
                "OldRepair",
                writer,
                seq,
                &encoded_point(value, value),
                crate::dds::CdrVersion::Xcdr2,
            );
            while let Some(entry) = ring.pop() {
                pool.release(entry.handle);
                delivered.borrow_mut().push(u64::from(entry.seq));
            }
        };
        // 3, 4 and 6..=4099: the 4096 samples the gate holds at most.
        receive(1);
        for seq in [3, 4].into_iter().chain(6..=4099) {
            receive(seq);
        }
        receive(4100);
        receive(5);
        assert_eq!(*delivered.borrow(), vec![1], "volatile={volatile}: held");
        assert_eq!(
            rejected.lock().expect("status").total_count,
            0,
            "held back, not rejected: no SAMPLE_REJECTED"
        );
        let (base, missing) = acknowledged(&credit, &writer, 4100, 1);
        assert_eq!(base, 2);
        assert_eq!(
            missing.iter().filter(|&&seq| seq == 2 || seq == 5).count(),
            2,
            "volatile={volatile}: the gap is asked for"
        );
        // The repairs, then what was refused, as the writer sends them again.
        receive(2);
        receive(5);
        receive(4100);
        assert_eq!(
            *delivered.borrow(),
            (1..=4100).collect::<Vec<u64>>(),
            "volatile={volatile}: every sample once, in order"
        );
        assert_eq!(acknowledged(&credit, &writer, 4100, 2), (4101, vec![]));
    }
}

/// Receive `seq` from `writer` on `sub`, then drain what the ring got.
fn receive_and_drain(
    sub: &super::subscriber::ReaderSubscriber<Point>,
    ring: &rt::IndexRing,
    writer: [u8; 16],
    seq: u64,
    delivered: &mut Vec<u64>,
) {
    use crate::engine::Subscriber;
    let value = i32::try_from(seq).expect("small");
    sub.on_data_with_writer(
        "Gated",
        writer,
        seq,
        &encoded_point(value, value),
        crate::dds::CdrVersion::Xcdr2,
    );
    drain_seqs(ring, delivered);
}

fn drain_seqs(ring: &rt::IndexRing, delivered: &mut Vec<u64>) {
    let pool = rt::get_slab_pool();
    while let Some(entry) = ring.pop() {
        pool.release(entry.handle);
        delivered.push(u64::from(entry.seq));
    }
}

/// A VOLATILE reader whose gate a GAP seeded before any DATA (our writer
/// answers such a reader's request for older history with one) joins where
/// the GAP ends. A repair of that first sequence arriving after the next
/// one is owed, not a duplicate of something before the join.
#[test]
fn a_volatile_reader_seeded_by_a_gap_takes_the_repair_above_it() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let writer = [0xBA; 16];
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub, _rejected) = gated_subscriber(
        "Gated",
        credit.clone(),
        super::reorder::ReorderGate::new(true, true),
    );
    let mut delivered = Vec::new();
    sub.on_writer_gap(writer, 1, 101, Vec::new());
    receive_and_drain(&sub, &ring, writer, 102, &mut delivered);
    receive_and_drain(&sub, &ring, writer, 101, &mut delivered);
    assert_eq!(delivered, vec![101, 102]);
    assert_eq!(acknowledged(&credit, &writer, 102, 1), (103, vec![]));
}

/// A gated reliable reader with a credit, seeded by a HEARTBEAT at 1.
fn seeded_reader(
    writer: [u8; 16],
) -> (
    crate::core::reader::ReaderAckCredit,
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;
    let _ = rt::init_slab_pool();
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub, _rejected) = gated_subscriber(
        "Gated",
        credit.clone(),
        super::reorder::ReorderGate::new(true, false),
    );
    sub.on_writer_heartbeat(writer, 1);
    (credit, ring, sub)
}

/// A sequence carrying no sample (a dispose, an unregister) above a gap is
/// acknowledged, and the gate does not record it. Once the gap fills, the
/// gate would wait for it forever: nothing sends it again, and a writer
/// whose changes are all acknowledged goes quiet. The repair that fills
/// the gap moves the writer proxy past it, and the gate follows at once.
#[test]
fn a_sequence_without_a_sample_above_a_gap_does_not_stall_the_gate() {
    use crate::engine::Subscriber;

    let writer = [0xBB; 16];
    let (credit, ring, sub) = seeded_reader(writer);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 1, &mut delivered);
    sub.on_writer_non_data(writer, 3);
    for seq in 4..=4100 {
        receive_and_drain(&sub, &ring, writer, seq, &mut delivered);
    }
    assert_eq!(delivered, vec![1], "4.. wait for 2");
    receive_and_drain(&sub, &ring, writer, 2, &mut delivered);
    drain_seqs(&ring, &mut delivered);
    // The gate holds the change without a sample among its 4096, so the
    // last sample it holds is 4098.
    let mut expected = vec![1, 2];
    expected.extend(4..=4098);
    assert_eq!(delivered, expected, "released with the repair, in order");
    // What was refused, or not yet acknowledged, sent again.
    receive_and_drain(&sub, &ring, writer, 4099, &mut delivered);
    receive_and_drain(&sub, &ring, writer, 4100, &mut delivered);
    expected.extend([4099, 4100]);
    assert_eq!(delivered, expected);
    assert_eq!(acknowledged(&credit, &writer, 4100, 1).0, 4101);
}

/// A GAP that fills the gap below a sequence the gate never recorded (a
/// sample-less DATA) moves the proxy past both; the gate follows.
#[test]
fn a_gap_below_a_sequence_without_a_sample_releases_what_waits() {
    use crate::engine::Subscriber;

    let writer = [0xBD; 16];
    let (credit, ring, sub) = seeded_reader(writer);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 1, &mut delivered);
    sub.on_writer_non_data(writer, 3);
    for seq in 4..=10 {
        receive_and_drain(&sub, &ring, writer, seq, &mut delivered);
    }
    sub.on_writer_gap(writer, 2, 3, Vec::new());
    drain_seqs(&ring, &mut delivered);
    let mut expected = vec![1];
    expected.extend(4..=10);
    assert_eq!(delivered, expected);
    assert_eq!(acknowledged(&credit, &writer, 10, 1).0, 11);
}

/// The end-of-coherent-set marker of a coherent writer, received by a
/// reader that does not read coherent sets, is a change without a sample:
/// the gate passes it and the next sample is not held.
#[test]
fn a_coherent_set_marker_does_not_hold_a_plain_reader() {
    use crate::engine::Subscriber;

    let writer = [0xBE; 16];
    let (credit, ring, sub) = seeded_reader(writer);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 1, &mut delivered);
    receive_and_drain(&sub, &ring, writer, 2, &mut delivered);
    sub.on_ecs("Gated", writer, 3, 2, None, None);
    receive_and_drain(&sub, &ring, writer, 4, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 4]);
    assert_eq!(acknowledged(&credit, &writer, 4, 1), (5, vec![]));
    // The marker sent again is a duplicate.
    sub.on_ecs("Gated", writer, 3, 2, None, None);
    receive_and_drain(&sub, &ring, writer, 5, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 4, 5]);
}

/// A durable reader's delivery starts where the writer's history does (its
/// HEARTBEAT). A change without a sample (a dispose, an end-of-set marker)
/// reaching the gate first must not seed it above the history still to
/// come: that history would be dropped as delivered, and acknowledged.
#[test]
fn a_change_without_a_sample_before_the_heartbeat_does_not_seed_the_gate() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    for first in ["marker", "dispose"] {
        let writer = [0xBF; 16];
        let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
        credit.match_writer(writer);
        let (ring, sub, _rejected) = gated_subscriber(
            "Gated",
            credit.clone(),
            super::reorder::ReorderGate::new(true, false),
        );
        match first {
            "marker" => sub.on_ecs("Gated", writer, 50, 49, None, None),
            _ => sub.on_writer_non_data(writer, 50),
        }
        sub.on_writer_heartbeat(writer, 1);
        let mut delivered = Vec::new();
        for seq in 1..=49 {
            receive_and_drain(&sub, &ring, writer, seq, &mut delivered);
        }
        receive_and_drain(&sub, &ring, writer, 51, &mut delivered);
        let mut expected: Vec<u64> = (1..=49).collect();
        expected.push(51);
        assert_eq!(delivered, expected, "{first}");
        assert_eq!(
            acknowledged(&credit, &writer, 51, 1),
            (52, vec![]),
            "{first}"
        );
    }
}

/// A sample-less change above the gap leaves the gate's base on it once the
/// gap fills. A KEEP_ALL reader with one free place must not take the next
/// sample for one held above a gap: nothing is missing.
#[test]
fn a_filled_gap_below_a_change_without_a_sample_leaves_no_phantom_gap() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let writer = [0xC0; 16];
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub, rejected) = keep_all_subscriber(
        "Phantom",
        credit.clone(),
        3,
        super::reorder::ReorderGate::new(true, false),
    );
    sub.on_writer_heartbeat(writer, 1);
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "Phantom",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };
    receive(1);
    sub.on_writer_non_data(writer, 3);
    receive(2);
    // Two places taken, one free: 4 is next in line, not held.
    receive(4);
    assert_eq!(rejected.lock().expect("status").total_count, 0);
    assert_eq!(ring.len(), 3, "1, 2 and 4 in the history");
    assert_eq!(acknowledged(&credit, &writer, 4, 1), (5, vec![]));
}

/// A coherent reader acknowledges a coherent sample when it stages it,
/// before the sample reaches the reorder gate. Its gate must not
/// follow the writer proxy past a staged set: the set would be dropped
/// below the gate's base when it commits.
#[test]
fn a_coherent_readers_gate_does_not_skip_a_staged_set() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let writer = [0xBC; 16];
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    credit.match_writer(writer);
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        "Gated".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, false))),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
        None,
        Some(credit),
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    sub.on_writer_heartbeat(writer, 1);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 1, &mut delivered);
    // A set 2..=3, staged (and acknowledged), then a plain sample after its
    // end marker 4, which is still on its way.
    let data = encoded_point(7, 9);
    for seq in [2, 3] {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(2),
            None,
            None,
        );
    }
    receive_and_drain(&sub, &ring, writer, 5, &mut delivered);
    sub.on_ecs("Gated", writer, 4, 3, None, None);
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3, 5]);
}

/// A sequence older than the duplicate window stays owed only while the
/// WriterProxy awaits it: once a GAP declares it irrelevant, a DATA carrying
/// it is a duplicate.
#[test]
fn a_gap_settles_a_sequence_older_than_the_duplicate_window() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xB9; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub) = credited_subscriber("OldGap", credit.clone());
    let pool = rt::get_slab_pool();
    let mut delivered = Vec::new();
    let mut receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "OldGap",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
        while let Some(entry) = ring.pop() {
            pool.release(entry.handle);
            delivered.push(u64::from(entry.seq));
        }
    };
    receive(1);
    for seq in 3..=4099 {
        receive(seq);
    }
    sub.on_writer_gap(writer, 2, 3, Vec::new());
    receive(2);
    assert!(
        !delivered.contains(&2),
        "declared irrelevant, then a duplicate"
    );
}

/// A GAP that reaches a reliable reader (RTPS v2.5 Sec.8.3.8.4), through
/// whichever door, moves that reader's acknowledgement: its WriterProxy
/// stops requesting the sequences the writer declared irrelevant.
#[test]
fn a_gap_reaching_a_reader_moves_its_acknowledgement() {
    use crate::core::reader::{Addressees, HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xB7; 16];
    let credit = ReaderAckCredit::new(registry.clone(), [0xA0; 16]);
    credit.match_writer(writer);
    let (_ring, sub) = credited_subscriber("GapCredit", credit);

    sub.on_writer_gap(writer, 1, 4, vec![1, 2, 3]);

    let answers = registry.answer_heartbeat(
        &writer,
        Addressees::All,
        &HeartbeatSeen {
            first_seq: 1,
            last_seq: 5,
            count: 1,
            final_flag: false,
        },
    );
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].bitmap_base, 4);
    assert_eq!(answers[0].missing, vec![4, 5]);
}

/// A reliable reader acknowledges every change it receives (RTPS v2.5
/// Sec.8.4.12): the samples of an HDDS writer's coherent set and the
/// End-of-Coherent-Set marker that closes it (Sec.8.7.5), which carries a
/// sequence number of its own. Left unacknowledged, a writer that learns
/// acknowledgements repairs the marker for ever and never sees its set
/// acknowledged: a TRANSIENT_LOCAL coherent publisher that waits for its
/// readers then stalls on every set (HDDS<->HDDS).
#[test]
fn an_hdds_coherent_set_and_its_closing_marker_are_acknowledged() {
    use crate::core::reader::{HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xB8; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (_ring, sub) = credited_subscriber("EcsAck", credit.clone());
    let data = encoded_point(1, 2);

    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in 1..=3u64 {
        sub.on_data_coherent(
            "EcsAck",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            None,
            None,
        );
    }
    sub.on_ecs("EcsAck", writer, 4, 3, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);

    let answer = credit
        .answer_heartbeat(
            &writer,
            &HeartbeatSeen {
                first_seq: 1,
                last_seq: 4,
                count: 1,
                final_flag: false,
            },
        )
        .expect("matched");
    assert_eq!(
        (answer.bitmap_base, answer.missing, answer.final_flag),
        (5, vec![], true),
        "the three samples and the marker are all acknowledged"
    );
}

/// A reader that does not read coherent sets still receives the marker as a
/// change of its writer, and acknowledges it.
#[test]
fn a_reader_without_coherent_access_acknowledges_the_closing_marker() {
    use crate::core::reader::{HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xB9; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        "EcsPlain".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
        super::subscriber::CoherentConfig::default(),
        None,
        Some(credit.clone()),
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    let data = encoded_point(1, 2);
    for seq in 1..=2u64 {
        sub.on_data_with_writer(
            "EcsPlain",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    sub.on_ecs("EcsPlain", writer, 3, 2, None, None);
    let answer = credit
        .answer_heartbeat(
            &writer,
            &HeartbeatSeen {
                first_seq: 1,
                last_seq: 3,
                count: 1,
                final_flag: false,
            },
        )
        .expect("matched");
    assert_eq!((answer.bitmap_base, answer.missing), (4, vec![]));
}

/// After a re-match the fresh WriterProxy requests what the reader already
/// holds; an HDDS writer's coherent samples sent again are duplicates, not
/// delivered twice, but received: they are acknowledged like any other.
#[test]
fn an_hdds_coherent_retransmission_after_a_rematch_is_acknowledged() {
    use crate::core::reader::{HeartbeatSeen, ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xBA; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (_ring, sub) = credited_subscriber("EcsRematch", credit.clone());
    let data = encoded_point(1, 2);
    let receive = || {
        for seq in 1..=3u64 {
            sub.on_data_coherent(
                "EcsRematch",
                writer,
                seq,
                &data,
                crate::dds::CdrVersion::Xcdr2,
                Some(seq),
                None,
                None,
            );
        }
    };
    let heartbeat = HeartbeatSeen {
        first_seq: 1,
        last_seq: 3,
        count: 1,
        final_flag: false,
    };

    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    receive();
    credit.unmatch_writer(&writer);
    credit.match_writer(writer);
    receive();
    crate::engine::router::set_route_writer_is_hdds_for_test(false);

    let answer = credit
        .answer_heartbeat(&writer, &heartbeat)
        .expect("matched");
    assert_eq!((answer.bitmap_base, answer.missing), (4, vec![]));
}

/// A KEEP_ALL reliable network reader's subscriber on `topic`, crediting
/// `credit`, behind `gate`, delivering into a ring of `usable` entries whose
/// room it reserves (the builder's `room` for a KEEP_ALL reader). Returns
/// the ring, the subscriber and its SAMPLE_REJECTED status.
fn keep_all_subscriber(
    topic: &str,
    credit: crate::core::reader::ReaderAckCredit,
    usable: usize,
    gate: super::reorder::ReorderGate,
) -> (
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
    std::sync::Arc<std::sync::Mutex<crate::dds::listener::SampleRejectedStatus>>,
) {
    use std::sync::{Arc, Mutex};
    let ring = Arc::new(rt::IndexRing::with_capacity(usable + 1));
    assert_eq!(ring.usable_capacity(), usable, "a power of two minus one");
    let status = Arc::new(crate::dds::StatusCondition::new());
    let rejected = Arc::new(Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    let mut sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        topic.to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(gate)),
        super::subscriber::CoherentConfig::default(),
        None,
        Some(credit),
        Arc::clone(&rejected),
        Vec::new(),
        crate::qos::partition::Partition::default(),
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
    (ring, sub, rejected)
}

/// Take every entry out of `ring` (the application's take), giving each
/// sample's slab slot and its place in `sub`'s history back, and return how
/// many there were.
fn drain_ring(ring: &rt::IndexRing, sub: &super::subscriber::ReaderSubscriber<Point>) -> usize {
    let pool = rt::get_slab_pool();
    let mut taken = 0;
    while let Some(entry) = ring.pop() {
        pool.release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
        taken += 1;
    }
    taken
}

/// What a reliable reader answers `writer` after a HEARTBEAT announcing
/// 1..=`last_seq`: its acknowledgement base and the sequences it requests.
fn acknowledged(
    credit: &crate::core::reader::ReaderAckCredit,
    writer: &[u8; 16],
    last_seq: i64,
    count: u32,
) -> (u64, Vec<u64>) {
    let answer = credit
        .answer_heartbeat(
            writer,
            &crate::core::reader::HeartbeatSeen {
                first_seq: 1,
                last_seq,
                count,
                final_flag: false,
            },
        )
        .expect("matched");
    (answer.bitmap_base, answer.missing)
}

/// DDS v1.4 Sec.2.2.3.19 and its footnote 28: a RELIABLE KEEP_ALL reader
/// with no room left discards the sample "so that the sample can be re-sent
/// at a later time". It must not acknowledge it, and it must take the copy
/// the writer sends again once the application has taken.
#[test]
fn a_full_keep_all_reader_does_not_acknowledge_what_it_refuses() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC1; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    // A RELIABLE VOLATILE reader's gate.
    let (ring, sub, rejected) = keep_all_subscriber(
        "FullKeepAll",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, true),
    );
    let receive = |seqs: std::ops::RangeInclusive<u64>| {
        for seq in seqs {
            let value = i32::try_from(seq).expect("small");
            sub.on_data_with_writer(
                "FullKeepAll",
                writer,
                seq,
                &encoded_point(value, value),
                crate::dds::CdrVersion::Xcdr2,
            );
        }
    };

    receive(1..=10);
    assert_eq!(ring.len(), 7, "the ring holds seven");
    assert_eq!(
        acknowledged(&credit, &writer, 10, 1),
        (8, vec![8, 9, 10]),
        "the three refused are requested again, not acknowledged"
    );
    assert_eq!(
        rejected.lock().expect("status").total_count,
        3,
        "each refusal is a SAMPLE_REJECTED"
    );

    assert_eq!(drain_ring(&ring, &sub), 7);
    receive(8..=10);
    assert_eq!(
        ring.len(),
        3,
        "the resends are taken, not dropped as duplicates"
    );
    assert_eq!(acknowledged(&credit, &writer, 10, 2), (11, vec![]));
    drain_ring(&ring, &sub);
}

/// A pool of this thread's own (`rt::private_slab_pool_for_test`) with no
/// heap tier, every slot of it held, and the one sample a head may take
/// past the heap tier's ceiling (`rt::Claim::Head`) taken too: the returned
/// handles, to give back.
fn exhausted_private_slab_pool() -> (
    &'static std::sync::Arc<rt::SlabPool>,
    rt::PrivateSlabPoolGuard,
    Vec<rt::SlabHandle>,
) {
    let policy = crate::qos::MemoryPolicy {
        max_heap_bytes: 0,
        ..crate::qos::MemoryPolicy::default()
    };
    let (pool, guard) = rt::owned_private_slab_pool_for_test(&policy);
    let mut held = Vec::new();
    while let Some((handle, _)) = pool.reserve_and_write(&[0u8; 1], crate::core::rt::Claim::Reader)
    {
        held.push(handle);
    }
    assert!(!held.is_empty(), "fixture: the pool gave slots first");
    let (head, _) = pool
        .reserve_and_write(&[0u8; 1], crate::core::rt::Claim::Head)
        .expect("fixture: a head passes the ceiling once");
    held.push(head);
    (pool, guard, held)
}

/// DDS v1.4 Sec.2.2.3.19 footnote 28 again, for the storage a sample needs
/// rather than its place in the history: a RELIABLE reader whose slab pool
/// has no room for a sample refuses it before acknowledging it, reports it
/// as SAMPLE_REJECTED, and takes the copy the writer sends again once the
/// pool has room. A sample stored only after its acknowledgement would be lost.
/// Only the first sample comes before the pool has room: those above a
/// refused one are held by the gate, which joined the writer at it (see
/// `a_volatile_reader_joins_at_the_first_sample_it_refuses`).
#[test]
fn a_reliable_reader_does_not_acknowledge_what_its_storage_refuses() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let (pool, _guard, held) = exhausted_private_slab_pool();
    let (metrics, _metrics_guard) = crate::telemetry::private_metrics_for_test();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC3; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub, rejected) = keep_all_subscriber(
        "StorageRefused",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, true),
    );
    let receive = |seqs: std::ops::RangeInclusive<u64>| {
        for seq in seqs {
            let value = i32::try_from(seq).expect("small");
            sub.on_data_with_writer(
                "StorageRefused",
                writer,
                seq,
                &encoded_point(value, value),
                crate::dds::CdrVersion::Xcdr2,
            );
        }
    };

    receive(1..=1);
    assert_eq!(ring.len(), 0, "nothing stored");
    assert_eq!(
        acknowledged(&credit, &writer, 3, 1),
        (1, vec![1, 2, 3]),
        "what could not be stored is requested again, not acknowledged"
    );
    let status = rejected.lock().expect("status").clone();
    assert_eq!(status.total_count, 1, "the refusal is a SAMPLE_REJECTED");
    assert_eq!(
        status.last_reason,
        crate::dds::listener::SampleRejectedReason::ResourceLimit
    );
    assert_eq!(
        metrics.samples_rejected_slab_exhausted(),
        1,
        "counted as the slab pool's refusals, not the ring's"
    );
    assert_eq!(
        sub.room.as_ref().expect("room").taken(),
        0,
        "a refused sample holds no place"
    );

    for handle in held {
        pool.release(handle);
    }
    receive(1..=3);
    assert_eq!(
        ring.len(),
        3,
        "the resends are stored, not dropped as duplicates"
    );
    assert_eq!(acknowledged(&credit, &writer, 3, 2), (4, vec![]));
    drain_ring(&ring, &sub);
}

/// A VOLATILE reliable reader joins its writer at the first DATA it
/// receives (`ReorderGate` seeded by the first DATA), whether it stores
/// that DATA or refuses it for want of storage. A refused sample is
/// requested again, so it is owed to the reader: the samples above it
/// wait for it, and its resend is delivered first. Joined at the first
/// sample it STORED instead (4, the pool having room again in the middle
/// of the writer's resend), the reader delivered 4 and 5 ahead of 1..=3,
/// then took the resends of 1..=3 for history from before its join:
/// dropped, and acknowledged, lost for good.
///
/// This pool has no heap tier, so no room for the head of a gap: 4 and 5,
/// above it, cannot be held either (`SlabPool::hold`). Refused
/// unacknowledged, they come again after 1..=3.
#[test]
fn a_volatile_reader_joins_at_the_first_sample_it_refuses() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let (pool, _guard, held) = exhausted_private_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC4; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    // A RELIABLE VOLATILE reader's gate.
    let (ring, sub, _rejected) = keep_all_subscriber(
        "JoinAtRefusal",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, true),
    );
    let receive = |seqs: std::ops::RangeInclusive<u64>| {
        for seq in seqs {
            let value = i32::try_from(seq).expect("small");
            sub.on_data_with_writer(
                "JoinAtRefusal",
                writer,
                seq,
                &encoded_point(value, value),
                crate::dds::CdrVersion::Xcdr2,
            );
        }
    };

    receive(1..=3);
    assert_eq!(ring.len(), 0, "nothing stored");
    for handle in held {
        pool.release(handle);
    }
    // The pool has room again in the middle of the writer's resend.
    receive(4..=5);
    assert_eq!(
        ring.len(),
        0,
        "2..=5 wait for 1, owed to a reader that joined at 1"
    );
    assert_eq!(
        acknowledged(&credit, &writer, 5, 1),
        (1, vec![1, 2, 3, 4, 5]),
        "the refused sample is still requested, and those above it, which \
         had no room to be held"
    );

    receive(1..=5);
    let mut delivered = Vec::new();
    while let Some(entry) = ring.pop() {
        delivered.push(entry.seq);
        pool.release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
    }
    assert_eq!(
        delivered,
        vec![1, 2, 3, 4, 5],
        "the resends are delivered, in order"
    );
    assert_eq!(acknowledged(&credit, &writer, 5, 2), (6, vec![]));
}

/// The same join for a sample its history has no place for: a VOLATILE
/// KEEP_ALL reader full of another writer's samples refuses a new writer's
/// first two, and joins that writer at the first of them.
#[test]
fn a_volatile_reader_joins_at_the_first_sample_its_history_refuses() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let (first, second) = ([0xD1; 16], [0xD2; 16]);
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(first);
    credit.match_writer(second);
    let (ring, sub, _rejected) = keep_all_subscriber(
        "JoinAtFullHistory",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, true),
    );
    let receive = |writer: [u8; 16], seqs: std::ops::RangeInclusive<u64>| {
        for seq in seqs {
            let value = i32::try_from(seq).expect("small");
            sub.on_data_with_writer(
                "JoinAtFullHistory",
                writer,
                seq,
                &encoded_point(value, value),
                crate::dds::CdrVersion::Xcdr2,
            );
        }
    };

    receive(first, 1..=7);
    assert_eq!(ring.len(), 7, "the history is full");
    receive(second, 1..=2);
    assert_eq!(drain_ring(&ring, &sub), 7, "only the first writer's");
    receive(second, 3..=3);
    assert_eq!(ring.len(), 0, "3 waits for 1 and 2");
    assert_eq!(acknowledged(&credit, &second, 3, 1), (1, vec![1, 2]));

    receive(second, 1..=2);
    let mut delivered = Vec::new();
    while let Some(entry) = ring.pop() {
        delivered.push(entry.seq);
        rt::get_slab_pool().release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
    }
    assert_eq!(delivered, vec![1, 2, 3], "the resends, in order");
    assert_eq!(acknowledged(&credit, &second, 3, 2), (4, vec![]));
}

/// A sample the reorder gate holds takes no storage until it is released:
/// storage held through the gate is what the sample the gate waits for
/// needs. Held samples that took the last slab slots on arrival left the
/// awaited one refused at every resend, and the gate never released them.
#[test]
fn a_held_sample_leaves_the_storage_to_the_one_the_gate_awaits() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let (pool, _guard, mut held) = exhausted_private_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC5; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    // A RELIABLE TRANSIENT_LOCAL reader's gate, seeded at 1 by a HEARTBEAT.
    let (ring, sub, _rejected) = keep_all_subscriber(
        "HeldStorage",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, false),
    );
    sub.on_writer_heartbeat(writer, 1);
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "HeldStorage",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };
    // Two slots free, three samples held above the awaited one.
    for _ in 0..2 {
        pool.release(held.pop().expect("a held slot"));
    }
    for seq in 2..=4 {
        receive(seq);
    }
    assert_eq!(ring.len(), 0, "2..=4 wait in the gate for 1");

    receive(1);
    assert!(
        acknowledged(&credit, &writer, 4, 1).0 > 1,
        "the awaited sample found storage and was acknowledged"
    );
    let first = ring.pop().expect("the awaited sample reached the ring");
    assert_eq!(first.seq, 1);
    pool.release(first.handle);
    drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
    drain_ring(&ring, &sub);
    for handle in held {
        pool.release(handle);
    }
}

/// A sample whose preparation panics (here its field extractor) is
/// received: acknowledged, delivered as nothing, the panic carried on.
/// Left unacknowledged, it would panic again at every resend and its
/// writer's stream would stop at its sequence.
#[test]
fn a_sample_whose_preparation_panics_is_acknowledged() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC6; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, mut sub, _rejected) = keep_all_subscriber(
        "PreparePanics",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, true),
    );
    sub.content_filter = Some(
        crate::dds::filter::ContentFilter::new("x > 0")
            .expect("filter")
            .evaluator(),
    );
    sub.field_extractor = Some(std::sync::Arc::new(|_: &Point| {
        panic!("a field extractor that panics")
    }));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sub.on_data_with_writer(
            "PreparePanics",
            writer,
            1,
            &encoded_point(1, 1),
            crate::dds::CdrVersion::Xcdr2,
        );
    }));
    assert!(panicked.is_err(), "the panic goes on");
    assert_eq!(ring.len(), 0, "nothing delivered");
    assert_eq!(
        acknowledged(&credit, &writer, 1, 1),
        (2, vec![]),
        "received, so acknowledged"
    );
}

/// A full KEEP_ALL history does not refuse a sample its content filter
/// rejects: that sample takes no place, it is received and acknowledged.
/// Refusing it would get it resent and reported as SAMPLE_REJECTED for nothing.
#[test]
fn a_full_history_takes_a_filtered_sample_without_a_place() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC8; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, mut sub, rejected) = keep_all_subscriber(
        "FilteredWhenFull",
        credit.clone(),
        1,
        super::reorder::ReorderGate::new(true, true),
    );
    sub.content_filter = Some(
        crate::dds::filter::ContentFilter::new("x < 5")
            .expect("filter")
            .evaluator(),
    );
    for (seq, x) in [(1u64, 1i32), (2, 9)] {
        sub.on_data_with_writer(
            "FilteredWhenFull",
            writer,
            seq,
            &encoded_point(x, x),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert_eq!(ring.len(), 1, "the history is full with the first");
    assert_eq!(
        acknowledged(&credit, &writer, 2, 1),
        (3, vec![]),
        "the filtered sample is received"
    );
    assert_eq!(rejected.lock().expect("status").total_count, 0);
    drain_ring(&ring, &sub);
}

/// A sample the reorder gate would hold is acknowledged on arrival, so it
/// takes its place in the ring then. Before the writer's first HEARTBEAT
/// the gap below it is unknown: a KEEP_LAST reader holds it all the same,
/// with its place, as long as one place stays free for the first sample of
/// that gap, which arrives in order and with it the gap fills one sample
/// at a time as the application takes. It refuses (unacknowledged, not
/// reported) only the sample that would take that last place: held samples
/// filling the ring would wait for good for a gap with no place.
#[test]
fn a_keep_last_reader_holds_what_arrives_before_the_first_heartbeat_with_its_place() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC7; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    // A RELIABLE TRANSIENT_LOCAL reader's gate, not seeded yet.
    let (ring, mut sub, rejected) = keep_all_subscriber(
        "KeepLastBeforeHeartbeat",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, false),
    );
    sub.room = Some(super::admission::HistoryRoom::ring_only(&ring, 7));
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "KeepLastBeforeHeartbeat",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };
    for seq in 1..=7u64 {
        receive(seq);
    }
    assert_eq!(ring.len(), 0, "held until the gap is known");
    assert_eq!(
        sub.room.as_ref().expect("room").taken(),
        6,
        "each held sample with its place, the last place left free"
    );
    assert_eq!(
        acknowledged(&credit, &writer, 7, 1),
        (7, vec![7]),
        "held, so acknowledged; the seventh refused, asked again"
    );
    assert_eq!(rejected.lock().expect("status").total_count, 0);
    sub.on_writer_heartbeat(writer, 1);
    assert_eq!(ring.len(), 6, "released, each with its place");
    receive(7);
    assert_eq!(ring.len(), 7, "in order, it takes the last place");
    assert_eq!(drain_ring(&ring, &sub), 7);
}

/// A BEST_EFFORT reader acknowledges nothing: with no storage it drops the
/// sample and reports it, and takes the next one once the pool has room.
#[test]
fn a_best_effort_reader_out_of_storage_drops_and_reports() {
    use crate::engine::Subscriber;

    let (pool, _guard, held) = exhausted_private_slab_pool();
    let ring = std::sync::Arc::new(rt::IndexRing::with_capacity(8));
    let status = std::sync::Arc::new(crate::dds::StatusCondition::new());
    let rejected = std::sync::Arc::new(std::sync::Mutex::new(
        crate::dds::listener::SampleRejectedStatus::default(),
    ));
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        "StorageBestEffort".to_string(),
        std::sync::Arc::clone(&ring),
        std::sync::Arc::clone(&status),
        None,
        None,
        None,
        std::sync::Arc::new(super::subscriber::DisposeQueue::new(std::sync::Arc::clone(
            &status,
        ))),
        std::sync::Arc::new(std::sync::Mutex::new(
            super::reorder::ReorderGate::new_best_effort(),
        )),
        super::subscriber::CoherentConfig::default(),
        None,
        None,
        std::sync::Arc::clone(&rejected),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    )
    .with_room(Some(super::admission::HistoryRoom::new(
        &ring,
        crate::reliability::LENGTH_UNLIMITED,
    )));
    let writer = [0xC4; 16];
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "StorageBestEffort",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };

    receive(1);
    receive(2);
    assert_eq!(ring.len(), 0, "dropped");
    assert_eq!(rejected.lock().expect("status").total_count, 2);
    for handle in held {
        pool.release(handle);
    }
    receive(3);
    assert_eq!(ring.len(), 1, "the next sample is taken");
    drain_ring(&ring, &sub);
}

/// A sample the reorder gate will hold never takes a KEEP_ALL reader's last
/// free slot: the sample the gate waits for would find no room, and nothing
/// held could ever be released.
#[test]
fn a_held_sample_leaves_the_last_slot_to_the_one_the_gate_awaits() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC2; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    // A RELIABLE TRANSIENT_LOCAL reader's gate, seeded at 1 by a HEARTBEAT.
    let (ring, sub, _rejected) = keep_all_subscriber(
        "HeldKeepAll",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, false),
    );
    sub.on_writer_heartbeat(writer, 1);
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "HeldKeepAll",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };

    for seq in 2..=8 {
        receive(seq);
    }
    assert_eq!(ring.len(), 0, "2..=7 wait in the gate for 1");
    assert_eq!(
        sub.room.as_ref().expect("room").taken(),
        6,
        "six held, the seventh slot kept free"
    );
    receive(1);
    assert_eq!(ring.len(), 7, "1 took the last slot and released 2..=7");
    assert_eq!(
        sub.room.as_ref().expect("room").taken(),
        7,
        "in the ring, the seven keep their places until they are taken"
    );
    assert_eq!(acknowledged(&credit, &writer, 8, 1), (8, vec![8]));
    drain_ring(&ring, &sub);
}

/// A slot travels with its sample into the reorder gate: wherever the gate
/// discards the sample, the slot comes back.
#[test]
fn a_sample_the_gate_discards_gives_its_slot_back() {
    let ring = std::sync::Arc::new(rt::IndexRing::with_capacity(8));
    let room = super::admission::HistoryRoom::new(&ring, crate::reliability::LENGTH_UNLIMITED);
    let mut gate = super::reorder::ReorderGate::new(true, false);
    let writer = [0xC3; 16];
    let _ = gate.on_heartbeat(writer, 1);
    let held = gate.on_data(
        writer,
        3,
        super::reorder::PendingPayload {
            order: None,
            order_token: None,
            version: crate::dds::CdrVersion::Xcdr2,
            remote_seq: 3,
            source_ts_ns: None,
            slot: room.reserve(1),
            prepared: super::admission::Prepared::Discard,
            staged: None,
        },
    );
    assert!(held.is_empty());
    assert_eq!(room.taken(), 1);
    gate.forget_writer(&writer);
    assert_eq!(room.taken(), 0);
}

/// Every push into a KEEP_ALL reader's ring is reserved, the samples that
/// arrive without a slot included (here the path with no writer GUID): one
/// that took the room of samples waiting in the reorder gate would make
/// their release overflow the ring, after they were acknowledged.
#[test]
fn a_sample_without_a_slot_never_takes_the_room_of_held_ones() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC4; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub, _rejected) = keep_all_subscriber(
        "UnslottedKeepAll",
        credit,
        7,
        super::reorder::ReorderGate::new(true, false),
    );
    sub.on_writer_heartbeat(writer, 1);
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "UnslottedKeepAll",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };
    for seq in 2..=7 {
        receive(seq);
    }
    // Two samples with no writer GUID: the last free slot is the one the
    // gap below 2 needs, so neither takes it, although the ring itself has
    // room.
    sub.on_data("UnslottedKeepAll", 100, &encoded_point(100, 100));
    sub.on_data("UnslottedKeepAll", 101, &encoded_point(101, 101));
    assert_eq!(ring.len(), 0, "the last place is the gap's");

    let pool = rt::get_slab_pool();
    receive(1);
    let mut in_ring = Vec::new();
    while let Some(entry) = ring.pop() {
        pool.release(entry.handle);
        in_ring.push(entry.seq);
    }
    assert_eq!(
        in_ring,
        (1..=7).collect::<Vec<u32>>(),
        "1 released 2..=7, all of them"
    );
}

/// Before its first HEARTBEAT, a TRANSIENT_LOCAL KEEP_ALL reader cannot tell
/// how much room the gap below a sample needs. It holds the sample all the
/// same, with its place, acknowledged, as long as one place stays free for
/// the first sample of that gap; it refuses only the sample that would take
/// that last place, unacknowledged and without a SAMPLE_REJECTED (no
/// resource limit was reached). What it held is delivered once the gap is
/// filled, with no resend.
#[test]
fn an_unseeded_gate_holds_all_but_the_last_place() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC5; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub, rejected) = keep_all_subscriber(
        "UnseededKeepAll",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, false),
    );
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "UnseededKeepAll",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };
    for seq in 2..=8 {
        receive(seq);
    }
    assert_eq!(
        sub.room.as_ref().expect("room").taken(),
        6,
        "2..=7 held with their places, the last place left free"
    );
    assert_eq!(
        rejected.lock().expect("status").total_count,
        0,
        "not a resource limit"
    );
    assert_eq!(
        acknowledged(&credit, &writer, 8, 1),
        (1, vec![1, 8]),
        "2..=7 acknowledged; 1 never came, 8 refused"
    );

    sub.on_writer_heartbeat(writer, 1);
    receive(1);
    let pool = rt::get_slab_pool();
    let mut in_ring = Vec::new();
    while let Some(entry) = ring.pop() {
        pool.release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
        in_ring.push(entry.seq);
    }
    assert_eq!(in_ring, (1..=7).collect::<Vec<u32>>(), "no resend of 2..=7");
    receive(8);
    assert_eq!(ring.len(), 1, "8, in order now");
    assert_eq!(rejected.lock().expect("status").total_count, 0);
    drain_ring(&ring, &sub);
}

/// An HDDS writer's sample with no GSN under GROUP scope is passed straight
/// through to delivery (the coherent dispatch admitted it already). A full
/// KEEP_ALL reader refuses it there, and it must then be neither
/// acknowledged nor kept in the duplicate window: the writer sends it again,
/// and the copy is taken once the application made room.
#[test]
fn a_passed_through_coherent_sample_is_refused_unacknowledged() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC6; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let ring = Arc::new(rt::IndexRing::with_capacity(4));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let mut sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        "GroupPass".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, true))),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: true,
        },
        None,
        Some(credit.clone()),
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::default(),
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
    let receive = |seqs: std::ops::RangeInclusive<u64>| {
        for seq in seqs {
            let value = i32::try_from(seq).expect("small");
            sub.on_data_coherent(
                "GroupPass",
                writer,
                seq,
                &encoded_point(value, value),
                crate::dds::CdrVersion::Xcdr2,
                Some(seq),
                None,
                None,
            );
        }
    };

    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    receive(1..=5);
    assert_eq!(ring.len(), 3, "the ring holds three");
    assert_eq!(
        acknowledged(&credit, &writer, 5, 1),
        (4, vec![4, 5]),
        "the two refused are requested again"
    );
    assert_eq!(drain_ring(&ring, &sub), 3);
    receive(4..=5);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    assert_eq!(
        ring.len(),
        2,
        "the resends are taken, not dropped as duplicates"
    );
    assert_eq!(acknowledged(&credit, &writer, 5, 2), (6, vec![]));
    drain_ring(&ring, &sub);
}

/// A KEEP_ALL reader's network arrivals hold their places until the
/// application takes them: the pump hands a place from the ring to the
/// cached sample, and `take` gives it back.
#[test]
fn a_keep_all_reader_gives_a_place_back_when_the_application_takes() {
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let topic = "PlacesUntilTaken";
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let reader = ReaderBuilder::<Point>::new(topic.to_string())
        .qos(qos)
        .network_ring_for_test()
        .build()
        .expect("KEEP_ALL reader with a test network ring");
    let room = Arc::clone(reader.network_room_for_test().expect("KEEP_ALL has a room"));
    let status = reader.get_status_condition();
    let mut sub = super::subscriber::ReaderSubscriber::<Point>::new(
        topic.to_string(),
        Arc::clone(reader.network_ring_for_test().expect("network ring")),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(status)),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
    );
    sub.room = Some(Arc::clone(&room));
    let writer = [0x61u8; 16];
    for seq in 1..=4u64 {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            topic,
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert_eq!(room.taken(), 4, "four in the ring");

    let first = reader.take().expect("take").expect("a sample");
    assert_eq!(first.x, 1);
    assert_eq!(
        room.taken(),
        3,
        "the three pumped into the cache keep their places"
    );
    while reader.take().expect("take").is_some() {}
    assert_eq!(room.taken(), 0, "everything taken, every place back");
}

/// A KEEP_LAST reader's network ring is bounded by a room too (a full ring
/// first drops the samples newer ones replace, and refuses only when none
/// is); but its cache keeps the newest samples rather than refuse them, so a
/// place is given back as its sample leaves the ring, read or not.
#[test]
fn a_keep_last_reader_s_places_bound_its_network_ring_only() {
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let topic = "KeepLastPlaces";
    let reader = ReaderBuilder::<Point>::new(topic.to_string())
        .qos(QoS::reliable().keep_last(8))
        .network_ring_for_test()
        .build()
        .expect("KEEP_LAST reader with a test network ring");
    let room = Arc::clone(
        reader
            .network_room_for_test()
            .expect("a KEEP_LAST reader's network ring has a room"),
    );
    let status = reader.get_status_condition();
    let sub = super::subscriber::ReaderSubscriber::<Point>::new(
        topic.to_string(),
        Arc::clone(reader.network_ring_for_test().expect("network ring")),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(status)),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
    )
    .with_room(Some(Arc::clone(&room)));
    let writer = [0x63u8; 16];
    for seq in 1..=3u64 {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            topic,
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert_eq!(room.taken(), 3, "three in the ring");

    let read = reader.read_batch(8).expect("read_batch");
    assert_eq!(read.len(), 3, "all three read, and left in the cache");
    assert_eq!(
        room.taken(),
        0,
        "the cache holds no place: the ring has room for three more"
    );
}

/// The legacy `try_take` pops the network ring directly: the entry's place
/// comes back with it.
#[test]
fn the_legacy_take_gives_a_keep_all_place_back() {
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let topic = "LegacyPlaces";
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let reader = ReaderBuilder::<Point>::new(topic.to_string())
        .qos(qos)
        .network_ring_for_test()
        .build()
        .expect("KEEP_ALL reader with a test network ring");
    let room = Arc::clone(reader.network_room_for_test().expect("KEEP_ALL has a room"));
    let status = reader.get_status_condition();
    let mut sub = super::subscriber::ReaderSubscriber::<Point>::new(
        topic.to_string(),
        Arc::clone(reader.network_ring_for_test().expect("network ring")),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(status)),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
    );
    sub.room = Some(Arc::clone(&room));
    let writer = [0x62u8; 16];
    for seq in 1..=2u64 {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            topic,
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert_eq!(room.taken(), 2);
    #[allow(deprecated)]
    let first = reader.try_take().expect("try_take").expect("a sample");
    assert_eq!(first.x, 1);
    assert_eq!(room.taken(), 1, "the popped entry's place is back");
}

/// The legacy `try_take` keeps the newest `depth` samples like `take`, and
/// every entry that leaves a KEEP_LAST network ring gives its place back,
/// kept by the cache or not, or the ring would refuse samples it has room
/// for.
#[test]
fn the_legacy_take_gives_a_keep_last_place_back() {
    use crate::engine::Subscriber as _;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let topic = "LegacyTrimPlaces";
    let reader = ReaderBuilder::<Point>::new(topic.to_string())
        .qos(QoS::reliable().keep_last(2))
        .network_ring_for_test()
        .build()
        .expect("KEEP_LAST reader with a test network ring");
    let room = Arc::clone(reader.network_room_for_test().expect("a room"));
    let status = reader.get_status_condition();
    let sub = super::subscriber::ReaderSubscriber::<Point>::new(
        topic.to_string(),
        Arc::clone(reader.network_ring_for_test().expect("network ring")),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(status)),
        Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
    )
    .with_room(Some(Arc::clone(&room)));
    let writer = [0x64u8; 16];
    for seq in 1..=4u64 {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            topic,
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    }
    assert_eq!(room.taken(), 4);
    #[allow(deprecated)]
    let first = reader.try_take().expect("try_take").expect("a sample");
    assert_eq!(first.x, 3, "the newest two, the older one first");
    assert_eq!(room.taken(), 0, "the ring is empty: every place is back");
}

/// The cache's own per-instance bound never counts nor evicts a sample
/// holding a place in a KEEP_ALL reader's history, and still bounds the
/// others.
#[test]
fn the_cache_bound_skips_samples_holding_a_place() {
    let ring = rt::IndexRing::with_capacity(16);
    let room = super::admission::HistoryRoom::new(&ring, crate::reliability::LENGTH_UNLIMITED);
    let cache =
        super::cache::SampleCache::<u32>::new(2).with_room(Some(std::sync::Arc::clone(&room)));
    let held = |seq: u64| {
        cache.push_holding(
            super::cache::CachedSample::new(u32::try_from(seq).expect("small"), seq, seq),
            room.reserve(0),
            false,
        );
    };
    let free =
        |seq: u64| super::cache::CachedSample::new(u32::try_from(seq).expect("small"), seq, seq);
    held(1);
    held(2);
    cache.push(free(3));
    cache.push(free(4));
    cache.push(free(5));
    let mut kept = Vec::new();
    while let Some(value) = cache.take() {
        kept.push(value);
    }
    assert_eq!(
        kept,
        vec![1, 2, 4, 5],
        "the two held samples stay; of the others, the oldest goes"
    );
    assert_eq!(
        room.taken(),
        0,
        "taking the held ones gave their places back"
    );
}

/// Samples held in the reorder gate leave a place for every sequence the
/// gate still awaits below them: the whole gap fills in one repair round.
/// Keeping a single place let one awaited sample in per round, then refused
/// the next one for want of room while the held samples sat on it.
#[test]
fn held_samples_leave_room_for_the_whole_gap() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;

    let _ = rt::init_slab_pool();
    let registry = ReaderProxyRegistry::new();
    let writer = [0xC6; 16];
    let credit = ReaderAckCredit::new(registry, [0xA0; 16]);
    credit.match_writer(writer);
    let (ring, sub, _rejected) = keep_all_subscriber(
        "GapKeepAll",
        credit.clone(),
        7,
        super::reorder::ReorderGate::new(true, false),
    );
    sub.on_writer_heartbeat(writer, 1);
    let receive = |seq: u64| {
        let value = i32::try_from(seq).expect("small");
        sub.on_data_with_writer(
            "GapKeepAll",
            writer,
            seq,
            &encoded_point(value, value),
            crate::dds::CdrVersion::Xcdr2,
        );
    };

    // 1..=3 lost on the way; 4..=10 arrive and wait for them.
    for seq in 4..=10 {
        receive(seq);
    }
    assert_eq!(
        sub.room.as_ref().expect("room").taken(),
        4,
        "4..=7 held, three places kept for 1..=3, 8..=10 refused"
    );
    // The repair round brings the gap.
    for seq in 1..=3 {
        receive(seq);
    }
    let pool = rt::get_slab_pool();
    let mut in_ring = Vec::new();
    while let Some(entry) = ring.pop() {
        pool.release(entry.handle);
        drop(sub.room.as_ref().map(super::admission::HistoryRoom::adopt));
        in_ring.push(entry.seq);
    }
    assert_eq!(
        in_ring,
        (1..=7).collect::<Vec<u32>>(),
        "the gap filled at once"
    );
    assert_eq!(
        acknowledged(&credit, &writer, 10, 1),
        (8, vec![8, 9, 10]),
        "the refused ones are asked for again"
    );
}

/// Wait until `writer`'s gate waits for `next`: whoever released below it
/// has left the gate.
fn wait_for_gate(
    gate: &std::sync::Mutex<super::reorder::ReorderGate>,
    writer: &[u8; 16],
    next: u64,
    what: &str,
) {
    wait_until(
        || {
            gate.lock()
                .unwrap_or_else(|e| e.into_inner())
                .next_seq(writer)
                == Some(next)
        },
        what,
    );
}

/// Wait until `done` (at most ten seconds).
fn wait_until(done: impl Fn() -> bool, what: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        std::thread::yield_now();
    }
}

/// Until a sample released in another thread is either queued behind the
/// delivery under way, or delivered (`in_ring` samples in the ring).
fn wait_until_queued_or_delivered(
    gate: &std::sync::Mutex<super::reorder::ReorderGate>,
    ring: &rt::IndexRing,
    writer: &[u8; 16],
    in_ring: usize,
) {
    wait_until(
        || {
            gate.lock()
                .unwrap_or_else(|e| e.into_inner())
                .queued(writer)
                > 0
                || ring.len() >= in_ring
        },
        "the release was neither queued nor delivered",
    );
}

/// Stops in the announcement of each sample of `at` until told to go on
/// (at most ten seconds each, so a failing test cannot hang), and panics
/// once, on the first of them, if asked to.
struct Pause {
    at: Vec<i32>,
    paused: std::sync::Mutex<std::sync::mpsc::Sender<i32>>,
    resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    wait: bool,
    panic: std::sync::atomic::AtomicBool,
}

impl Pause {
    fn new(
        at: &[i32],
        wait: bool,
        panic: bool,
    ) -> (
        std::sync::Arc<Self>,
        std::sync::mpsc::Receiver<i32>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (paused_tx, paused_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let pause = std::sync::Arc::new(Self {
            at: at.to_vec(),
            paused: std::sync::Mutex::new(paused_tx),
            resume: std::sync::Mutex::new(resume_rx),
            wait,
            panic: std::sync::atomic::AtomicBool::new(panic),
        });
        (pause, paused_rx, resume_tx)
    }
}

impl Pause {
    /// The sample of value `x` is in the ring, its delivery under way.
    fn at_push(&self, x: i32) {
        if !self.at.contains(&x) {
            return;
        }
        if self.wait {
            let _ = self.paused.lock().expect("paused").send(x);
            let _ = self
                .resume
                .lock()
                .expect("resume")
                .recv_timeout(std::time::Duration::from_secs(10));
        }
        if self.at.first() == Some(&x)
            && self.panic.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            panic!("a delivery panics");
        }
    }
}

/// A reliable reader seeded at 1 whose gate the test can watch, its
/// deliveries paused by `pause` (`ReaderSubscriber::pushed_hook`).
fn watched_reader(
    writer: [u8; 16],
    pause: Option<std::sync::Arc<Pause>>,
) -> (
    crate::core::reader::ReaderAckCredit,
    std::sync::Arc<std::sync::Mutex<super::reorder::ReorderGate>>,
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    credit.match_writer(writer);
    let gate = Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, false)));
    let (ring, sub, _rejected) =
        gated_subscriber_on("Gated", credit.clone(), Arc::clone(&gate), None);
    if let Some(pause) = pause {
        *sub.pushed_hook.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(move |seq| {
            pause.at_push(i32::try_from(seq).expect("small"));
        }));
    }
    sub.on_writer_heartbeat(writer, 1);
    (credit, gate, ring, sub)
}

fn receive(sub: &super::subscriber::ReaderSubscriber<Point>, writer: [u8; 16], seq: u64) {
    use crate::engine::Subscriber;
    let value = i32::try_from(seq).expect("small");
    sub.on_data_with_writer(
        "Gated",
        writer,
        seq,
        &encoded_point(value, value),
        crate::dds::CdrVersion::Xcdr2,
    );
}

/// a reliable reader delivers a writer's samples in the order they
/// leave its reorder gate, whichever thread takes each one out. A thread
/// that took 1 out of the gate and has yet to deliver it while another
/// takes 3 out (the writer no longer has 2) must not see 3 delivered first.
/// Fails on the previous code: `[3, 1]`.
#[test]
fn samples_are_delivered_in_the_order_they_leave_the_gate() {
    use crate::engine::Subscriber;

    let writer = [0xBE; 16];
    let (credit, gate, ring, sub) = watched_reader(writer, None);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 3, &mut delivered);
    assert!(delivered.is_empty(), "3 waits for 1 and 2");

    std::thread::scope(|scope| {
        let held = credit.hold_next();
        let receiving = scope.spawn(|| receive(&sub, writer, 1));
        wait_until(|| !credit.holding(), "1 never left the gate");
        // Meanwhile the writer no longer has 2: 3 leaves the gate too.
        let heartbeat = scope.spawn(|| sub.on_writer_heartbeat(writer, 3));
        wait_for_gate(&gate, &writer, 4, "3 never left the gate");
        wait_until_queued_or_delivered(&gate, &ring, &writer, 1);
        drop(held);
        receiving.join().expect("receiving thread");
        heartbeat.join().expect("heartbeat thread");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 3]);
}

/// what one thread delivers is not overtaken by what another
/// releases meanwhile. The thread delivering 1 and 2, released together,
/// is still between them when another thread takes 3 out of the gate. This
/// pins that a delivery holds the writer's delivery lock from its take to
/// its last sample; the previous code held it too, and passes.
#[test]
fn a_release_is_not_overtaken_while_it_is_delivered() {
    let writer = [0xBF; 16];
    let (pause, paused, resume) = Pause::new(&[1], true, false);
    let (_credit, gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 2, &mut delivered);
    assert!(delivered.is_empty(), "2 waits for 1");

    std::thread::scope(|scope| {
        let first = scope.spawn(|| receive(&sub, writer, 1));
        paused
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("1 announced");
        let second = scope.spawn(|| receive(&sub, writer, 3));
        wait_for_gate(&gate, &writer, 4, "3 never left the gate");
        wait_until_queued_or_delivered(&gate, &ring, &writer, 2);
        resume.send(()).expect("resume");
        first.join().expect("first");
        second.join().expect("second");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// a thread that drains what others queued is not overtaken
/// either. 1 is being delivered; 2 and 3, released together meanwhile,
/// are queued; the thread that queued them delivers them once 1 is out,
/// and is between 2 and 3 when a third thread takes 4 out of the gate.
#[test]
fn a_drain_is_not_overtaken_while_it_delivers() {
    let writer = [0xC6; 16];
    let (pause, paused, resume) = Pause::new(&[1, 2], true, false);
    let (_credit, gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 3, &mut delivered);

    std::thread::scope(|scope| {
        let first = scope.spawn(|| receive(&sub, writer, 1));
        assert_eq!(
            paused.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(1)
        );
        let second = scope.spawn(|| receive(&sub, writer, 2));
        wait_for_gate(&gate, &writer, 4, "2 and 3 never left the gate");
        wait_until_queued_or_delivered(&gate, &ring, &writer, 2);
        resume.send(()).expect("resume 1");
        assert_eq!(
            paused.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(2)
        );
        let third = scope.spawn(|| receive(&sub, writer, 4));
        wait_for_gate(&gate, &writer, 5, "4 never left the gate");
        wait_until_queued_or_delivered(&gate, &ring, &writer, 3);
        resume.send(()).expect("resume 2");
        first.join().expect("first");
        second.join().expect("second");
        third.join().expect("third");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3, 4]);
}

/// a listener that panics on 1 loses nothing that follows it. The
/// thread delivering 1 and 2 panics on 1 while another has released 3 and
/// waits its turn: 2 and 3 are delivered all the same, in order (the router
/// catches the panic and the receive thread lives on). 2 must not be lost;
/// with a queue drained by one thread for all, 3 would be too.
#[test]
fn a_panicking_listener_loses_nothing_released_after_it() {
    let writer = [0xC4; 16];
    let (pause, paused, resume) = Pause::new(&[1], true, true);
    let (_credit, gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 2, &mut delivered);

    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            let panicked =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receive(&sub, writer, 1)));
            assert!(panicked.is_err(), "the listener panicked");
        });
        paused
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("1 announced");
        let second = scope.spawn(|| receive(&sub, writer, 3));
        wait_for_gate(&gate, &writer, 4, "3 never left the gate");
        wait_until_queued_or_delivered(&gate, &ring, &writer, 2);
        resume.send(()).expect("resume");
        first.join().expect("first");
        second.join().expect("second");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// a listener that panics on 1 does not hold back 2, released
/// with it and acknowledged: 2 is delivered by the same thread, at once,
/// not left for a later message that a writer with everything acknowledged
/// may never send (RTPS v2.5 Sec.8.4.9.2). The panic still reaches the
/// caller. 2 must not be lost.
#[test]
fn a_panicking_listener_does_not_hold_back_the_rest_of_its_release() {
    let writer = [0xC5; 16];
    let (pause, _paused, _resume) = Pause::new(&[1], false, true);
    let (_credit, _gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 2, &mut delivered);
    let panicked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receive(&sub, writer, 1)));
    assert!(panicked.is_err(), "the listener's panic reaches the caller");
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2]);
}

/// a release that leaves the gate on a HEARTBEAT (the writer no
/// longer has 1) is not overtaken, between the gate and its delivery, by a
/// sample another thread takes out after it.
#[test]
fn a_heartbeat_release_is_not_overtaken_after_the_gate() {
    use crate::engine::Subscriber;

    let writer = [0xC7; 16];
    let (credit, gate, ring, sub) = watched_reader(writer, None);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 2, &mut delivered);
    assert!(delivered.is_empty(), "2 waits for 1");

    std::thread::scope(|scope| {
        let held = credit.hold_next();
        let heartbeat = scope.spawn(|| sub.on_writer_heartbeat(writer, 2));
        wait_until(|| !credit.holding(), "2 never left the gate");
        let receiving = scope.spawn(|| receive(&sub, writer, 3));
        wait_for_gate(&gate, &writer, 4, "3 never left the gate");
        wait_until_queued_or_delivered(&gate, &ring, &writer, 1);
        drop(held);
        heartbeat.join().expect("heartbeat thread");
        receiving.join().expect("receiving thread");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![2, 3]);
}

/// what a thread queued goes out before what another releases
/// after it, even when the other finds the delivery lock free first. 2 is
/// queued behind 1's delivery, and its thread has yet to drain when 1's
/// delivery ends; 3 then takes the free lock: it delivers 2 before itself.
#[test]
fn a_release_queued_before_a_free_lock_goes_out_first() {
    let writer = [0xCA; 16];
    let (pause, paused, resume) = Pause::new(&[1], true, false);
    let (credit, gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();

    std::thread::scope(|scope| {
        let first = scope.spawn(|| receive(&sub, writer, 1));
        paused
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("1 announced");
        let held = credit.hold_next();
        let second = scope.spawn(|| receive(&sub, writer, 2));
        wait_until(|| !credit.holding(), "2 never left the gate");
        wait_until(
            || {
                gate.lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .queued(&writer)
                    > 0
            },
            "2 was not queued behind 1",
        );
        resume.send(()).expect("resume");
        first.join().expect("first");
        receive(&sub, writer, 3);
        drop(held);
        second.join().expect("second");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// a listener's panic does not stop the gate from following the
/// writer proxy. 3 is a change without a sample above the gap at 2, 4
/// waits behind it; the repair of 2 panics in the listener. The proxy
/// awaits nothing up to 4, so the gate must step over 3 and deliver 4 now:
/// the writer, with everything acknowledged, sends nothing more (RTPS v2.5
/// Sec.8.4.9.2).
#[test]
fn a_panicking_listener_does_not_stop_the_gate_following_the_proxy() {
    use crate::engine::Subscriber;

    let writer = [0xD1; 16];
    let (pause, _paused, _resume) = Pause::new(&[2], false, true);
    let (_credit, _gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 1, &mut delivered);
    sub.on_writer_non_data(writer, 3);
    receive_and_drain(&sub, &ring, writer, 4, &mut delivered);
    assert_eq!(delivered, vec![1], "4 waits for 2");
    let panicked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receive(&sub, writer, 2)));
    assert!(panicked.is_err(), "the listener's panic reaches the caller");
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 4]);
}

/// a listener's panic in a delivery released by a HEARTBEAT (the
/// writer no longer has 1) reaches the caller too, and the sample is
/// delivered.
#[test]
fn a_panic_in_a_heartbeat_release_reaches_the_caller() {
    use crate::engine::Subscriber;

    let writer = [0xD4; 16];
    let (pause, _paused, _resume) = Pause::new(&[2], false, true);
    let (_credit, _gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 2, &mut delivered);
    assert!(delivered.is_empty(), "2 waits for 1");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sub.on_writer_heartbeat(writer, 2);
    }));
    assert!(panicked.is_err(), "the listener's panic reaches the caller");
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![2]);
}

/// two releases queued by two threads behind one delivery go out
/// in the order they left the gate, neither replacing the other.
#[test]
fn two_releases_queued_behind_one_delivery_keep_their_order() {
    let writer = [0xD2; 16];
    let (pause, paused, resume) = Pause::new(&[1], true, false);
    let (_credit, gate, ring, sub) = watched_reader(writer, Some(pause));
    let mut delivered = Vec::new();
    let queued = || {
        gate.lock()
            .unwrap_or_else(|e| e.into_inner())
            .queued(&writer)
    };

    std::thread::scope(|scope| {
        let first = scope.spawn(|| receive(&sub, writer, 1));
        paused
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("1 announced");
        let second = scope.spawn(|| receive(&sub, writer, 2));
        wait_until(|| queued() == 1, "2 was not queued behind 1");
        let third = scope.spawn(|| receive(&sub, writer, 3));
        wait_until(|| queued() == 2, "3 was not queued behind 2");
        resume.send(()).expect("resume");
        first.join().expect("first");
        second.join().expect("second");
        third.join().expect("third");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// a sample whose listener panics is in the ring, and wakes the
/// reader all the same: an application on a WaitSet learns of it.
#[test]
fn a_panicking_listener_does_not_keep_the_sample_from_waking_the_reader() {
    use crate::dds::condition::Condition;

    let writer = [0xD3; 16];
    let (pause, _paused, _resume) = Pause::new(&[1], false, true);
    let (_credit, _gate, ring, sub) = watched_reader(writer, Some(pause));
    sub.status_condition
        .set_enabled_statuses(crate::dds::StatusMask::DATA_AVAILABLE);
    assert!(!sub.status_condition.get_trigger_value(), "nothing yet");
    let panicked =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receive(&sub, writer, 1)));
    assert!(panicked.is_err(), "the listener's panic reaches the caller");
    assert!(
        sub.status_condition.get_trigger_value(),
        "the reader is woken"
    );
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1]);
}

/// two writers of one reader are delivered independently. While
/// writer A's 1 is being delivered and its 2 and 3 wait their turn, writer
/// B's 11 is delivered at once, and B's delivery takes nothing of A's.
#[test]
fn one_writer_s_delivery_neither_waits_for_nor_takes_another_s() {
    use crate::engine::Subscriber;

    let a = [0xC8; 16];
    let b = [0xC9; 16];
    let (pause, paused, resume) = Pause::new(&[1], true, false);
    let (credit, gate, ring, sub) = watched_reader(a, Some(pause));
    credit.match_writer(b);
    sub.on_writer_heartbeat(b, 11);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, a, 3, &mut delivered);
    assert!(delivered.is_empty(), "3 waits for 1 and 2");

    std::thread::scope(|scope| {
        let first = scope.spawn(|| receive(&sub, a, 1));
        paused
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("1 announced");
        let second = scope.spawn(|| receive(&sub, a, 2));
        wait_for_gate(&gate, &a, 4, "2 and 3 never left the gate");
        wait_until(
            || gate.lock().unwrap_or_else(|e| e.into_inner()).queued(&a) > 0,
            "2 and 3 were not queued behind 1",
        );
        let other = scope.spawn(|| receive(&sub, b, 11));
        wait_until(|| ring.len() >= 2, "B waited for A");
        resume.send(()).expect("resume");
        first.join().expect("first");
        second.join().expect("second");
        other.join().expect("other");
    });
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 11, 2, 3]);
}

/// A reliable reader subscribed with `coherent_access` (GROUP scope when
/// `group`), its gate as a reliable reader's, seeded at 1.
fn coherent_reader(
    writer: [u8; 16],
    group: bool,
) -> (
    crate::core::reader::ReaderAckCredit,
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    use crate::engine::Subscriber;

    let (credit, ring, sub) =
        coherent_reader_on(writer, group, super::reorder::ReorderGate::new(true, false));
    sub.on_writer_heartbeat(writer, 1);
    (credit, ring, sub)
}

/// `coherent_reader` with the given gate (`ReorderGate::new(true, true)`:
/// RELIABLE VOLATILE, seeded by the first DATA), before any HEARTBEAT.
fn coherent_reader_on(
    writer: [u8; 16],
    group: bool,
    gate: super::reorder::ReorderGate,
) -> (
    crate::core::reader::ReaderAckCredit,
    std::sync::Arc<rt::IndexRing>,
    super::subscriber::ReaderSubscriber<Point>,
) {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    credit.match_writer(writer);
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let sub = super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
        "Gated".to_string(),
        Arc::clone(&ring),
        Arc::clone(&status),
        None,
        None,
        None,
        Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
        Arc::new(Mutex::new(gate)),
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: group,
        },
        None,
        Some(credit.clone()),
        Arc::new(Mutex::new(
            crate::dds::listener::SampleRejectedStatus::default(),
        )),
        Vec::new(),
        crate::qos::partition::Partition::default(),
        crate::qos::ownership::OwnershipKind::default(),
        None,
        None,
        None,
        #[cfg(feature = "security")]
        None,
    );
    (credit, ring, sub)
}

/// a standalone END marker (set 1..=3, marker 4) is a
/// change of its own. A reader that does not read coherent sets takes it as
/// a change without a sample: acknowledged, and its gate does not wait on it.
#[test]
fn a_plain_reader_passes_a_standalone_end_marker() {
    use crate::engine::Subscriber;

    let writer = [0xC1; 16];
    let (credit, ring, sub) = seeded_reader(writer);
    let mut delivered = Vec::new();
    for seq in 1..=3 {
        receive_and_drain(&sub, &ring, writer, seq, &mut delivered);
    }
    sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), 4);
    receive_and_drain(&sub, &ring, writer, 5, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3, 5]);
    assert_eq!(acknowledged(&credit, &writer, 5, 1), (6, Vec::new()));
}

/// a coherent reader acknowledges the standalone END marker that
/// closes its set, and a repair of it closes nothing again.
#[test]
fn a_coherent_reader_acknowledges_a_standalone_end_marker() {
    use crate::engine::Subscriber;

    let writer = [0xC2; 16];
    let (credit, ring, sub) = coherent_reader(writer, false);
    let data = encoded_point(7, 9);
    for seq in 1..=3 {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
    }
    sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), 4);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
    assert_eq!(acknowledged(&credit, &writer, 4, 1), (5, Vec::new()));
    // The writer repairs the marker (a NACK crossed the acknowledgement).
    sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), 4);
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
    assert!(
        sub.pending_coherent_end
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "the repaired marker waits for no sample"
    );
}

/// a repair of a marker the reader took is acknowledged again,
/// even by a writer proxy that forgot it (the writer was matched anew with
/// the same GUID): a duplicate was received all the same.
#[test]
fn a_repaired_marker_is_acknowledged_by_a_new_proxy() {
    use crate::engine::Subscriber;

    let writer = [0xCC; 16];
    let (credit, _ring, sub) = coherent_reader(writer, false);
    let data = encoded_point(7, 9);
    for seq in 1..=3 {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
    }
    sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), 4);
    credit.unmatch_writer(&writer);
    credit.match_writer(writer);
    sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), 4);
    let (_, missing) = acknowledged(&credit, &writer, 4, 1);
    assert!(!missing.contains(&4), "missing {missing:?}");
}

/// a GROUP marker that carries no sample count still steps the
/// writer's gate over its own sequence number, the one it came with: the
/// writer's next sample does not wait for it.
#[test]
fn a_group_marker_without_a_count_is_stepped_over() {
    use crate::engine::Subscriber;

    let writer = [0xCD; 16];
    let (_credit, ring, sub) = coherent_reader(writer, true);
    let data = encoded_point(7, 9);
    for seq in 1..=3 {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(10),
            Some([0, 0, 1, 8]),
        );
    }
    sub.on_coherent_end_marker("Gated", writer, Some(10), Some([0, 0, 1, 8]), 1, None, 4);
    let mut delivered = Vec::new();
    receive_and_drain(&sub, &ring, writer, 5, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3, 5]);
}

/// the END and the sample that completes its set, on two threads.
/// The END counts two of three samples staged; the third is staged before
/// the END records that it waits for it. The set is committed all the
/// same: counting and recording the wait are one step, and so are staging
/// the straggler and reading the wait. Once acknowledged the marker is not
/// sent again, so a missed completion would be for good.
#[test]
fn a_straggler_staged_while_the_end_counts_completes_the_set() {
    use crate::engine::Subscriber;

    let writer = [0xCE; 16];
    let (credit, ring, sub) = coherent_reader(writer, false);
    let data = encoded_point(7, 9);
    let stage = |seq: u64| {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
    };
    stage(1);
    stage(2);
    std::thread::scope(|scope| {
        let held = credit.hold_next();
        let end = scope.spawn(|| {
            sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), 4);
        });
        wait_until(|| !credit.holding(), "the END never counted");
        let straggler = scope.spawn(|| stage(3));
        wait_until(
            || {
                sub.coherent_buffer
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&writer)
                    .map_or(0, Vec::len)
                    == 3
                    || ring.len() == 3
            },
            "3 was never staged",
        );
        drop(held);
        end.join().expect("end");
        straggler.join().expect("straggler");
    });
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// a volatile reader that receives a set's END marker before the
/// set (UDP reorders) does not take the marker for its join point: the
/// samples that follow are delivered, not dropped as older than it.
#[test]
fn a_marker_first_does_not_seed_a_volatile_reader() {
    use crate::core::reader::{ReaderAckCredit, ReaderProxyRegistry};
    use crate::engine::Subscriber;
    use std::sync::{Arc, Mutex};

    let _ = rt::init_slab_pool();
    let writer = [0xCF; 16];
    let credit = ReaderAckCredit::new(ReaderProxyRegistry::new(), [0xA0; 16]);
    credit.match_writer(writer);
    let gate = Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, true)));
    let (ring, sub, _rejected) = gated_subscriber_on("Gated", credit.clone(), gate, None);
    sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), 4);
    let mut delivered = Vec::new();
    for seq in [1, 2, 3, 5] {
        receive_and_drain(&sub, &ring, writer, seq, &mut delivered);
    }
    assert_eq!(delivered, vec![1, 2, 3, 5]);
    assert_eq!(acknowledged(&credit, &writer, 5, 1), (6, Vec::new()));
}

/// a change without a sample that settles the writer proxy moves
/// the gate too. 3 and 5 wait behind 2; 4 is a marker the gate does not
/// record (above its base); the marker at 2 releases 3, and the proxy,
/// settled up to 5, must bring 5 out: the writer, with everything
/// acknowledged, sends nothing more (RTPS v2.5 Sec.8.4.9.2).
#[test]
fn a_change_without_a_sample_moves_the_gate_with_the_proxy() {
    use crate::engine::Subscriber;

    let writer = [0xD0; 16];
    let (_credit, ring, sub) = seeded_reader(writer);
    let mut delivered = Vec::new();
    for seq in [1, 3, 5] {
        receive_and_drain(&sub, &ring, writer, seq, &mut delivered);
    }
    sub.on_writer_non_data(writer, 4);
    sub.on_writer_non_data(writer, 2);
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 3, 5]);
}

/// a marker the duplicate record cannot take is refused like a
/// sample (the record's bound refuses, it never forgets): its set is not
/// closed, and the writer sends the marker again. Closing it unrecorded
/// would let that copy close the set a second time.
#[test]
fn a_marker_the_record_cannot_take_is_refused() {
    use crate::engine::Subscriber;

    let writer = [0xCB; 16];
    let (credit, ring, sub) = coherent_reader(writer, false);
    let data = encoded_point(7, 9);
    for seq in 1..=3 {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            None,
            None,
        );
    }
    let marker = sub.fill_missed_runs(writer, 4);
    sub.on_coherent_end_marker("Gated", writer, None, None, 1, Some(3), marker);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert!(delivered.is_empty(), "the set is not closed");
    assert!(
        sub.pending_coherent_end
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty(),
        "nothing waits on the refused marker"
    );
    assert!(
        credit.awaits(&writer, marker),
        "the refused marker is not acknowledged"
    );
}

/// under GROUP scope too, the marker's own sequence number is the
/// one it came with, and it is acknowledged.
#[test]
fn a_group_reader_acknowledges_a_standalone_end_marker() {
    use crate::engine::Subscriber;

    let writer = [0xC3; 16];
    let (credit, ring, sub) = coherent_reader(writer, true);
    let data = encoded_point(7, 9);
    for seq in 1..=3 {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(10),
            Some([0, 0, 1, 8]),
        );
    }
    sub.on_coherent_end_marker("Gated", writer, Some(10), Some([0, 0, 1, 8]), 1, Some(3), 4);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
    assert_eq!(acknowledged(&credit, &writer, 4, 1), (5, Vec::new()));
}

/// a GROUP set the gate passed while it was staged is delivered whole.
/// Scenario: the reader
/// acknowledges SN 79..82 on receipt, staged for the set 79..90; the writer
/// drops them from its history and its next HEARTBEAT says firstSN 83; the
/// gate followed, and when the END marker 91 released the set, 79..82 were
/// dropped as stale: 8 of the 12 samples reached the application.
#[test]
fn a_group_set_the_heartbeat_passed_while_staged_is_delivered_whole() {
    use crate::engine::Subscriber;

    let writer = [0xC4; 16];
    let (credit, ring, sub) = coherent_reader(writer, true);
    let data = encoded_point(7, 9);
    let stage = |seq| {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(10),
            Some([0, 0, 1, 8]),
        );
    };
    stage(1);
    stage(2);
    // Acknowledged on receipt, 1 and 2 left the writer's history.
    assert_eq!(acknowledged(&credit, &writer, 2, 1), (3, Vec::new()));
    sub.on_writer_heartbeat(writer, 3);
    stage(3);
    sub.on_coherent_end_marker("Gated", writer, Some(10), Some([0, 0, 1, 8]), 1, Some(3), 4);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// the same for an HDDS writer's set closed by its ECS (TOPIC scope):
/// the samples a HEARTBEAT passed while they were staged are committed with
/// the rest of the set.
#[test]
fn an_ecs_set_the_heartbeat_passed_while_staged_is_delivered_whole() {
    use crate::engine::Subscriber;

    let writer = [0xC5; 16];
    let (_credit, ring, sub) = coherent_reader(writer, false);
    let data = encoded_point(7, 9);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in 1..=2u64 {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            None,
            None,
        );
    }
    sub.on_writer_heartbeat(writer, 3);
    sub.on_data_coherent(
        "Gated",
        writer,
        3,
        &data,
        crate::dds::CdrVersion::Xcdr2,
        Some(3),
        None,
        None,
    );
    sub.on_ecs("Gated", writer, 4, 3, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// a VOLATILE reader takes nothing from before it joined, staged or
/// not. Its join floor is the first DATA it observed (here staged); a set
/// below it that a repair brings later is not delivered, after the newer one
/// or at all.
#[test]
fn a_volatile_reader_delivers_no_staged_set_from_before_it_joined() {
    use crate::engine::Subscriber;

    let writer = [0xC6; 16];
    let (_credit, ring, sub) =
        coherent_reader_on(writer, false, super::reorder::ReorderGate::new(true, true));
    let data = encoded_point(7, 9);
    let stage = |seq: u64| {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            None,
            None,
        );
    };
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in 5..=7 {
        stage(seq);
    }
    sub.on_ecs("Gated", writer, 8, 7, None, None);
    for seq in 1..=3 {
        stage(seq);
    }
    sub.on_ecs("Gated", writer, 4, 3, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![5, 6, 7]);
}

/// a VOLATILE reader's join floor counts a staged DATA: a set staged
/// before a later sample of the writer seeded the gate is delivered whole
/// when it closes, not dropped as from before the join.
#[test]
fn a_volatile_reader_delivers_a_set_staged_before_the_gate_was_seeded() {
    use crate::engine::Subscriber;

    let writer = [0xC7; 16];
    let (_credit, ring, sub) =
        coherent_reader_on(writer, false, super::reorder::ReorderGate::new(true, true));
    let data = encoded_point(7, 9);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in 1..=3u64 {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            None,
            None,
        );
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    receive(&sub, writer, 5);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    sub.on_ecs("Gated", writer, 4, 3, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    delivered.sort_unstable();
    assert_eq!(delivered, vec![1, 2, 3, 5]);
}

/// a TRANSIENT_LOCAL reader that stages a set before the writer's
/// first HEARTBEAT reaches it delivers the set whole when that HEARTBEAT
/// already says the writer dropped its first samples (acknowledged on
/// receipt): the writer's history is owed, there is no join to exclude.
#[test]
fn a_set_staged_before_the_first_heartbeat_is_delivered_whole() {
    use crate::engine::Subscriber;

    let writer = [0xC8; 16];
    let (_credit, ring, sub) =
        coherent_reader_on(writer, true, super::reorder::ReorderGate::new(true, false));
    let data = encoded_point(7, 9);
    let stage = |seq| {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(1),
            Some(10),
            Some([0, 0, 1, 8]),
        );
    };
    stage(1);
    stage(2);
    sub.on_writer_heartbeat(writer, 3);
    stage(3);
    sub.on_coherent_end_marker("Gated", writer, Some(10), Some([0, 0, 1, 8]), 1, Some(3), 4);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![1, 2, 3]);
}

/// a VOLATILE reader keeps an older set out even when that set closes
/// first, before anything seeded its gate.
#[test]
fn a_volatile_reader_keeps_out_an_older_set_that_closes_first() {
    use crate::engine::Subscriber;

    let writer = [0xC9; 16];
    let (_credit, ring, sub) =
        coherent_reader_on(writer, false, super::reorder::ReorderGate::new(true, true));
    let data = encoded_point(7, 9);
    let stage = |seq: u64, set: u64| {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(set),
            None,
            None,
        );
    };
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in 5..=7 {
        stage(seq, 5);
    }
    for seq in 1..=3 {
        stage(seq, 1);
    }
    sub.on_ecs("Gated", writer, 4, 3, None, None);
    sub.on_ecs("Gated", writer, 8, 7, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![5, 6, 7]);
}

/// a VOLATILE reader's join floor is the start of the first set it
/// observed, not whichever of its samples arrived first: a first set
/// reordered on the way (6 before 5) is delivered whole.
#[test]
fn a_volatile_reader_delivers_a_first_set_received_out_of_order() {
    use crate::engine::Subscriber;

    let writer = [0xCA; 16];
    let (_credit, ring, sub) =
        coherent_reader_on(writer, false, super::reorder::ReorderGate::new(true, true));
    let data = encoded_point(7, 9);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in [6u64, 5, 7] {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(5),
            None,
            None,
        );
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    receive(&sub, writer, 9);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    sub.on_ecs("Gated", writer, 8, 7, None, None);
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    delivered.sort_unstable();
    assert_eq!(delivered, vec![5, 6, 7, 9]);
}

/// an HDDS writer's sample without a group set reaching a GROUP-scope
/// reader is passed straight through, not staged: the gate takes it on
/// arrival. Told of it as staged too, a BEST_EFFORT gate counted it received
/// and then refused it as old.
#[test]
fn a_best_effort_group_reader_passes_an_unstaged_sample_through() {
    use crate::engine::Subscriber;

    let writer = [0xCB; 16];
    let (_credit, ring, sub) =
        coherent_reader_on(writer, true, super::reorder::ReorderGate::new_best_effort());
    let data = encoded_point(7, 9);
    crate::engine::router::set_route_writer_is_hdds_for_test(true);
    for seq in [5u64, 6] {
        sub.on_data_coherent(
            "Gated",
            writer,
            seq,
            &data,
            crate::dds::CdrVersion::Xcdr2,
            Some(seq),
            None,
            None,
        );
    }
    crate::engine::router::set_route_writer_is_hdds_for_test(false);
    let mut delivered = Vec::new();
    drain_seqs(&ring, &mut delivered);
    assert_eq!(delivered, vec![5, 6]);
}

/// a reader's ring has one producer, but a reader is delivered on
/// several threads: the router thread delivers writer A's DATA while the
/// control thread delivers what a HEARTBEAT of writer B releases from the
/// gate (and a TCP or QUIC transport has a routing thread of its own). Both
/// push into the ring at once; every sample must be there once (a lost
/// sample would already be acknowledged).
#[test]
fn a_heartbeat_release_and_a_sample_pushed_at_once_lose_nothing() {
    use crate::engine::Subscriber;

    let a = [0xE1; 16];
    let b = [0xE2; 16];
    let (credit, _gate, ring, sub) = watched_reader(a, None);
    credit.match_writer(b);
    sub.on_writer_heartbeat(b, 1);
    let per_round: u64 = 3000;
    let pool = rt::get_slab_pool();
    let mut bad_rounds = Vec::new();
    for round in 0..30u64 {
        let first = round * per_round + 1;
        let last = first + per_round - 1;
        // B's samples wait in the gate: B's first one never comes.
        for seq in first + 1..=last {
            receive(&sub, b, seq);
        }
        std::thread::scope(|scope| {
            let sub = &sub;
            scope.spawn(move || {
                for seq in first..=last {
                    receive(sub, a, seq);
                }
            });
            // The writer no longer has `first`: B's samples leave the gate.
            scope.spawn(move || sub.on_writer_heartbeat(b, first + 1));
        });
        let mut counts = std::collections::HashMap::new();
        while let Some(entry) = ring.pop() {
            pool.release(entry.handle);
            *counts.entry(u64::from(entry.seq)).or_insert(0u32) += 1;
        }
        // Both writers use the same sequence numbers: A's `first` once,
        // every other one twice.
        let wrong = (first..=last)
            .filter(|seq| {
                counts.get(seq).copied().unwrap_or(0) != if *seq == first { 1 } else { 2 }
            })
            .count();
        if wrong != 0 {
            bad_rounds.push((round, wrong));
        }
    }
    assert!(
        bad_rounds.is_empty(),
        "rounds with samples lost or doubled: {bad_rounds:?}"
    );
}

/// DDS 1.4 2.2.3.18 / 2.2.3.19: an inconsistent HISTORY / RESOURCE_LIMITS
/// pair makes the creation fail, for a DataReader exactly as for a
/// DataWriter. Until 2026-10 only the writer checked it: the reader was
/// created and silently enforced something else.
#[test]
fn reader_creation_refuses_what_writer_creation_refuses() {
    let inconsistent = [
        // depth (10) > max_samples_per_instance (5)
        crate::qos::ResourceLimits {
            max_samples: 100,
            max_instances: 1,
            max_samples_per_instance: 5,
            max_quota_bytes: 100_000,
        },
        // max_samples (50) < max_samples_per_instance (100)
        crate::qos::ResourceLimits {
            max_samples: 50,
            max_instances: 1,
            max_samples_per_instance: 100,
            max_quota_bytes: 100_000,
        },
    ];
    for limits in inconsistent {
        let mut qos = QoS::best_effort().keep_last(10);
        qos.resource_limits = limits;
        let writer = crate::dds::writer::WriterBuilder::<Point>::new("rqc".to_string())
            .qos(qos.clone())
            .build();
        assert!(writer.is_err(), "writer accepted {limits:?}");
        let reader = ReaderBuilder::<Point>::new("rqc".to_string())
            .qos(qos)
            .build();
        let Err(err) = reader else {
            panic!("reader accepted {limits:?}");
        };
        assert!(err.to_string().contains("DataReader"), "{err}");
    }

    // The consistent neighbour of each is accepted.
    let mut qos = QoS::best_effort().keep_last(5);
    qos.resource_limits = crate::qos::ResourceLimits {
        max_samples: 5,
        max_instances: 1,
        max_samples_per_instance: 5,
        max_quota_bytes: 100_000,
    };
    ReaderBuilder::<Point>::new("rqc".to_string())
        .qos(qos)
        .build()
        .expect("consistent QoS");
}

// ---- The presentation barrier seen by its readers ----
#[cfg(test)]
mod verify_door {
    use super::super::coherent_barrier::{publisher_key, CoherentSet};
    use super::super::reorder::PendingPayload;
    use super::ReaderBuilder;
    use super::{coherent_writer_guid, encoded_point, Point};
    use crate::core::rt;
    use crate::dds::qos::Presentation;
    use crate::dds::{InstanceStateMask, QoS, SampleStateMask, ViewStateMask, WaitSet};
    use std::sync::Arc;
    use std::time::Duration;

    fn payloads(from: i32, n: i32) -> Vec<PendingPayload> {
        (from..from + n)
            .map(|x| {
                PendingPayload::stored_for_test::<Point>(
                    u64::try_from(x).unwrap(),
                    &encoded_point(x, 0),
                )
            })
            .collect()
    }

    fn reader_on(
        sub: &crate::dds::Subscriber,
        topic: &str,
        listener: Option<Arc<dyn crate::dds::listener::DataReaderListener<Point>>>,
    ) -> Arc<super::super::DataReader<Point>> {
        let registry = Arc::new(crate::engine::TopicRegistry::new());
        let mut b = ReaderBuilder::<Point>::new(topic.to_string())
            .qos(
                QoS::best_effort()
                    .keep_all()
                    .presentation(Presentation::topic_coherent()),
            )
            .with_registry(registry)
            .subscriber(sub);
        if let Some(l) = listener {
            b = b.with_listener(l);
        }
        Arc::new(b.build().expect("reader"))
    }

    /// (3) A generation becomes pullable WITHOUT a deposit (the last
    /// unresolved peer member resolves): no wake word is raised, a WaitSet
    /// already blocked on the reader never wakes.
    #[test]
    fn v3_generation_unblocked_by_peer_resolution_wakes_the_waitset() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let a = reader_on(&sub, "VerifyWakeA", None);
        let _b = reader_on(&sub, "VerifyWakeB", None);
        let barrier = Arc::clone(sub.coherent_barrier());
        let wa = coherent_writer_guid(0xE1, 1);
        barrier.register_matched_writer(0, wa);
        // B still unresolved: A's generation is held (startup coherence).
        barrier.deposit(
            0,
            publisher_key([0xE1; 12], [0; 4]),
            CoherentSet::single(wa, payloads(1, 3)),
        );
        let cond = a
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("rc");
        let ws = WaitSet::new();
        ws.attach_condition(cond.clone()).expect("attach");
        let b2 = Arc::clone(&barrier);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            // B matches a writer of ANOTHER publisher: B resolved, A's
            // generation becomes releasable.
            b2.register_matched_writer(1, coherent_writer_guid(0xE2, 1));
        });
        let woke = ws.wait(Some(Duration::from_secs(2)));
        t.join().unwrap();
        let pullable = a.take_all().expect("take_all").len();
        assert_eq!(pullable, 3, "the generation is pullable");
        assert!(
            woke.is_ok(),
            "WaitSet blocked while a generation was pullable (lost wake)"
        );
    }

    /// (3b) Same with the departure drain: the peer's last writer unmatches.
    #[test]
    fn v3b_generation_unblocked_by_peer_departure_wakes_the_waitset() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let a = reader_on(&sub, "VerifyDepA", None);
        let _b = reader_on(&sub, "VerifyDepB", None);
        let barrier = Arc::clone(sub.coherent_barrier());
        let (wa, wb) = (coherent_writer_guid(0xE3, 1), coherent_writer_guid(0xE3, 2));
        barrier.register_matched_writer(0, wa);
        barrier.register_matched_writer(1, wb);
        barrier.deposit(
            0,
            publisher_key([0xE3; 12], [0; 4]),
            CoherentSet::single(wa, payloads(1, 3)),
        );
        let cond = a
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("rc");
        let ws = WaitSet::new();
        ws.attach_condition(cond.clone()).expect("attach");
        let b2 = Arc::clone(&barrier);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            b2.unregister_matched_writer(1, wb);
        });
        let woke = ws.wait(Some(Duration::from_secs(2)));
        t.join().unwrap();
        let pullable = a.take_all().expect("take_all").len();
        assert_eq!(pullable, 3, "the generation is pullable");
        assert!(
            woke.is_ok(),
            "WaitSet blocked while a generation was pullable (lost wake)"
        );
    }

    struct Counter(std::sync::atomic::AtomicUsize);
    impl crate::dds::listener::DataReaderListener<Point> for Counter {
        fn on_data_available(&self, _s: &Point) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// (3c) A listener-only application: on_data_available for a complete
    /// generation the barrier holds.
    #[test]
    fn v3c_listener_only_reader_hears_a_held_generation() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let counter = Arc::new(Counter(std::sync::atomic::AtomicUsize::new(0)));
        let _a = reader_on(&sub, "VerifyListener", Some(counter.clone()));
        let barrier = sub.coherent_barrier();
        let wa = coherent_writer_guid(0xE4, 1);
        barrier.register_matched_writer(0, wa);
        barrier.deposit(
            0,
            publisher_key([0xE4; 12], [0; 4]),
            CoherentSet::single(wa, payloads(1, 2)),
        );
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            counter.0.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "listener never called for a complete held generation"
        );
    }

    struct Reenter(std::sync::OnceLock<std::sync::Weak<super::super::DataReader<Point>>>);
    impl crate::dds::listener::DataReaderListener<Point> for Reenter {
        fn on_data_available(&self, _s: &Point) {
            if let Some(r) = self.0.get().and_then(std::sync::Weak::upgrade) {
                let _ = r.take();
            }
        }
    }

    struct FirstSight {
        reader: std::sync::OnceLock<std::sync::Weak<super::super::DataReader<Point>>>,
        seen: std::sync::Mutex<Option<usize>>,
    }
    impl crate::dds::listener::DataReaderListener<Point> for FirstSight {
        fn on_data_available(&self, _s: &Point) {
            let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
            if seen.is_none() {
                if let Some(r) = self.reader.get().and_then(std::sync::Weak::upgrade) {
                    *seen = Some(r.read_batch(16).map_or(0, |v| v.len()));
                }
            }
        }
    }

    /// (5c) A coherent set is announced once the whole set is in the ring:
    /// the first DATA_AVAILABLE for it finds every sample of it. Announced
    /// sample by sample, the first callback (and a WaitSet woken with it)
    /// found one of three.
    #[test]
    fn v5c_a_set_is_announced_once_whole() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let l = Arc::new(FirstSight {
            reader: std::sync::OnceLock::new(),
            seen: std::sync::Mutex::new(None),
        });
        let a = reader_on(&sub, "VerifyWhole", Some(l.clone()));
        l.reader.set(Arc::downgrade(&a)).ok();
        let barrier = sub.coherent_barrier();
        let wa = coherent_writer_guid(0xEC, 1);
        barrier.register_matched_writer(0, wa);
        barrier.deposit(
            0,
            publisher_key([0xEC; 12], [0; 4]),
            CoherentSet::single(wa, payloads(1, 3)),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while l.seen.lock().unwrap_or_else(|e| e.into_inner()).is_none()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            *l.seen.lock().unwrap_or_else(|e| e.into_inner()),
            Some(3),
            "the first announcement of the set finds all of it"
        );
    }

    /// (5) Lock order: the door delivers under the per-writer delivery
    /// lock; a DATA_AVAILABLE listener that takes (the textbook pattern)
    /// re-enters the door on the same thread and pulls the next generation
    /// of the same writer.
    #[test]
    fn v5_listener_that_takes_does_not_deadlock_the_door() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let l = Arc::new(Reenter(std::sync::OnceLock::new()));
        let a = reader_on(&sub, "VerifyReenter", Some(l.clone()));
        l.0.set(Arc::downgrade(&a)).ok();
        let barrier = sub.coherent_barrier();
        let wa = coherent_writer_guid(0xE5, 1);
        barrier.register_matched_writer(0, wa);
        let k = publisher_key([0xE5; 12], [0; 4]);
        barrier.deposit(0, k, CoherentSet::single(wa, payloads(1, 2)));
        barrier.deposit(0, k, CoherentSet::single(wa, payloads(3, 2)));
        let (tx, rx) = std::sync::mpsc::channel();
        let a2 = Arc::clone(&a);
        std::thread::spawn(move || {
            let r = a2.take().map(|s| s.is_some());
            let _ = tx.send(r.is_ok());
        });
        let done = rx.recv_timeout(Duration::from_secs(3));
        assert!(
            done.is_ok(),
            "take() never returned: the door deadlocked under its own listener"
        );
        // The take() returned: the thread's clone drops as it ends and
        // `a` with the scope, the last of them frees the reader.
    }

    /// A Subscriber of GROUP access scope (DDS v1.4 Sec.2.2.2.5.2.8).
    fn group_subscriber() -> crate::dds::Subscriber {
        crate::dds::Subscriber::new(
            QoS::default().presentation(Presentation::new(
                crate::dds::qos::PresentationAccessScope::Group,
                true,
                false,
            )),
            None,
            None,
            None,
        )
    }

    /// A coherent GROUP reader of `sub`.
    fn group_reader_on(
        sub: &crate::dds::Subscriber,
        topic: &str,
    ) -> Arc<super::super::DataReader<Point>> {
        let registry = Arc::new(crate::engine::TopicRegistry::new());
        Arc::new(
            ReaderBuilder::<Point>::new(topic.to_string())
                .qos(
                    QoS::best_effort()
                        .keep_all()
                        .presentation(Presentation::new(
                            crate::dds::qos::PresentationAccessScope::Group,
                            true,
                            false,
                        )),
                )
                .with_registry(registry)
                .subscriber(sub)
                .build()
                .expect("reader"),
        )
    }

    /// (2) Inside an access bracket the reader holds what the outermost
    /// `begin_access` published, whatever the accessors do: a read, then a
    /// take_all, see that one generation; one completed meanwhile waits for
    /// the next bracket.
    #[test]
    fn v2_a_bracket_sees_what_its_begin_published() {
        let _ = rt::init_slab_pool();
        let sub = group_subscriber();
        let a = group_reader_on(&sub, "VerifyReadTake");
        let barrier = sub.coherent_barrier();
        let wa = coherent_writer_guid(0xE6, 1);
        barrier.register_matched_writer(0, wa);
        let k = publisher_key([0xE6; 12], [0; 4]);
        barrier.deposit(0, k, CoherentSet::single(wa, payloads(1, 2)));
        sub.begin_access().expect("begin");
        barrier.deposit(0, k, CoherentSet::single(wa, payloads(3, 2)));
        assert!(a.read().expect("read").is_some());
        assert_eq!(
            a.take_all().expect("take_all").len(),
            2,
            "the first generation"
        );
        sub.end_access().expect("end");
        sub.begin_access().expect("begin");
        assert_eq!(
            a.take_all().expect("take_all").len(),
            2,
            "the second, next bracket"
        );
        sub.end_access().expect("end");
    }

    /// (2b) A ReadCondition evaluation (WaitSet trigger) changes nothing
    /// the reader holds or the barrier releases.
    #[test]
    fn v2b_trigger_evaluation_does_not_advance_the_barrier() {
        use crate::dds::Condition;
        let _ = rt::init_slab_pool();
        let sub = group_subscriber();
        let a = group_reader_on(&sub, "VerifyTrigger");
        let barrier = sub.coherent_barrier();
        let wa = coherent_writer_guid(0xE7, 1);
        barrier.register_matched_writer(0, wa);
        let k = publisher_key([0xE7; 12], [0; 4]);
        barrier.deposit(0, k, CoherentSet::single(wa, payloads(1, 2)));
        sub.begin_access().expect("begin");
        for g in 1..3 {
            barrier.deposit(0, k, CoherentSet::single(wa, payloads(1 + 2 * g, 2)));
        }
        let cond = a
            .create_readcondition(
                SampleStateMask::ANY,
                ViewStateMask::ANY,
                InstanceStateMask::ANY,
            )
            .expect("rc");
        for _ in 0..3 {
            assert!(cond.get_trigger_value());
        }
        assert_eq!(
            a.take_all().expect("take_all").len(),
            2,
            "evaluations pulled nothing"
        );
        sub.end_access().expect("end");
    }

    /// (6) A coherent reader of a GROUP-scope Subscriber read outside an
    /// access bracket: PRECONDITION_NOT_MET (DDS v1.4 Sec.2.2.2.5.2.8).
    #[test]
    fn v6_a_group_reader_is_read_inside_a_bracket() {
        let _ = rt::init_slab_pool();
        let sub = group_subscriber();
        let a = group_reader_on(&sub, "VerifyPrecondition");
        assert!(matches!(a.take(), Err(crate::dds::Error::InvalidState(_))));
        assert!(matches!(a.read(), Err(crate::dds::Error::InvalidState(_))));
        assert!(matches!(
            a.take_all(),
            Err(crate::dds::Error::InvalidState(_))
        ));
        sub.begin_access().expect("begin");
        assert!(a.take().expect("inside a bracket").is_none());
        sub.end_access().expect("end");
    }

    /// (6b) Two publishers' generations published by one `begin_access`:
    /// one take_all inside the bracket sees both.
    #[test]
    fn v6b_a_bracket_sees_every_publisher_s_generation() {
        let _ = rt::init_slab_pool();
        let sub = group_subscriber();
        let a = group_reader_on(&sub, "VerifyTwoPublishers");
        let barrier = sub.coherent_barrier();
        let (w1, w2) = (coherent_writer_guid(0xEA, 1), coherent_writer_guid(0xEB, 1));
        barrier.register_matched_writer(0, w1);
        barrier.register_matched_writer(0, w2);
        sub.begin_access().expect("begin");
        barrier.deposit(
            0,
            publisher_key([0xEA; 12], [0; 4]),
            CoherentSet::single(w1, payloads(1, 2)),
        );
        barrier.deposit(
            0,
            publisher_key([0xEB; 12], [0; 4]),
            CoherentSet::single(w2, payloads(3, 2)),
        );
        sub.end_access().expect("end");
        sub.begin_access().expect("begin");
        assert_eq!(
            a.take_all().expect("take_all").len(),
            4,
            "both publishers' generations"
        );
        sub.end_access().expect("end");
    }

    /// (S1) Every reader of a GROUP-scope Subscriber is read inside a
    /// bracket, its own presentation whatever it is: an ordered-only GROUP
    /// reader and a plain reader too (DDS v1.4 Sec.2.2.2.5.2.8: the
    /// PRESENTATION of "the Subscriber to which the DataReader belongs").
    #[test]
    fn s1_every_reader_of_a_group_subscriber_is_read_inside_a_bracket() {
        let _ = rt::init_slab_pool();
        let sub = group_subscriber();
        for (name, presentation) in [
            (
                "ordered-only",
                Presentation::new(crate::dds::qos::PresentationAccessScope::Group, false, true),
            ),
            ("plain", Presentation::default()),
        ] {
            let r = ReaderBuilder::<Point>::new(format!("VerifyScope-{name}"))
                .qos(QoS::best_effort().keep_all().presentation(presentation))
                .with_registry(Arc::new(crate::engine::TopicRegistry::new()))
                .subscriber(&sub)
                .build()
                .expect("reader");
            assert!(
                matches!(r.take(), Err(crate::dds::Error::InvalidState(_))),
                "{name}: outside a bracket"
            );
            sub.begin_access().expect("begin");
            assert!(r.take().expect("inside").is_none(), "{name}: inside");
            sub.end_access().expect("end");
        }
    }

    /// (S2) A bracket of a Subscriber whose access scope is not GROUP has
    /// no effect (DDS v1.4 Sec.2.2.2.5.2.8): a set completed while one is
    /// open is published at once, and the reader is read outside one.
    #[test]
    fn s2_a_bracket_of_a_topic_subscriber_has_no_effect() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(
            QoS::default().presentation(Presentation::topic_coherent()),
            None,
            None,
            None,
        );
        let a = reader_on(&sub, "VerifyTopicBracket", None);
        let barrier = sub.coherent_barrier();
        let w = coherent_writer_guid(0xED, 1);
        barrier.register_matched_writer(0, w);
        sub.begin_access().expect("begin");
        barrier.deposit(
            0,
            publisher_key([0xED; 12], [0; 4]),
            CoherentSet::single(w, payloads(1, 2)),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut got = 0;
        while got == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
            got = a.take_all().expect("take_all").len();
        }
        sub.end_access().expect("end");
        assert_eq!(got, 2, "published inside the bracket");
    }

    /// (4) Cost of the door on a barrier reader's empty take() vs a plain
    /// reader (informational, prints ns/op; asserts nothing). Ignored: its
    /// spin starves the timing fixtures of the tests run beside it; run it
    /// alone with `--ignored`.
    #[test]
    #[ignore = "informational cost probe, run alone"]
    fn v4_door_cost_informational() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let a = reader_on(&sub, "VerifyCostA", None);
        let barrier = sub.coherent_barrier();
        barrier.register_matched_writer(0, coherent_writer_guid(0xE8, 1));
        let plain = Arc::new(
            ReaderBuilder::<Point>::new("VerifyCostPlain".to_string())
                .qos(QoS::best_effort().keep_all())
                .with_registry(Arc::new(crate::engine::TopicRegistry::new()))
                .build()
                .expect("plain"),
        );
        let n = 200_000u32;
        for (name, r) in [("barrier", &a), ("plain", &plain)] {
            for _ in 0..10_000 {
                let _ = r.take();
            }
            let t0 = std::time::Instant::now();
            for _ in 0..n {
                let _ = std::hint::black_box(r.take());
            }
            eprintln!(
                "v4: empty take() {name}: {:.1} ns/op",
                t0.elapsed().as_nanos() as f64 / f64::from(n)
            );
        }
    }
    /// (5b) Control: one generation only -> the listener's take pulls nothing.
    #[test]
    fn v5b_control_single_generation_no_deadlock() {
        let _ = rt::init_slab_pool();
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let l = Arc::new(Reenter(std::sync::OnceLock::new()));
        let a = reader_on(&sub, "VerifyReenter1", Some(l.clone()));
        l.0.set(Arc::downgrade(&a)).ok();
        let barrier = sub.coherent_barrier();
        let wa = coherent_writer_guid(0xE9, 1);
        barrier.register_matched_writer(0, wa);
        barrier.deposit(
            0,
            publisher_key([0xE9; 12], [0; 4]),
            CoherentSet::single(wa, payloads(1, 2)),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let a2 = Arc::clone(&a);
        std::thread::spawn(move || {
            let _ = tx.send(a2.take().is_ok());
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).is_ok(),
            "control deadlocked"
        );
        // The take() returned: the thread's clone drops as it ends and
        // `a` with the scope, the last of them frees the reader.
    }
}

// ---------------------------------------------------------------------------
// DataRepresentation data-plane backstop: a reader drops an XCDR1-encoded
// sample by its type's REAL decode capability, independent of its
// `accepted_data_repr` list and of any match verdict (DDS-XTypes v1.3
// Sec.7.6.3.1.2). `ReaderBuilder::build` refuses to CREATE a reader that
// explicitly requests XCDR1 while its type cannot decode it
// (`cdr_negotiation::resolve_reader_data_representation`), so this gate
// cannot fire through the public API; it is tested directly, at the
// `ReaderSubscriber` level, as the backstop it is meant to be should that
// invariant ever be bypassed by some other construction path.
// ---------------------------------------------------------------------------

/// A standalone `ReaderSubscriber<RefusesXcdr1Tag>` (no participant, no
/// match registry), the same construction `ring_full_rejection_raises_sample_rejected_status`
/// uses for a direct `on_data_with_writer` drive. `accepted_data_repr` is
/// left at its "no restriction" default (`ReaderSubscriber::new` always
/// passes `Vec::new()`), on purpose: this isolates the type-capability
/// check from the explicit-list check, which is `cdr_negotiation`'s own
/// unit tests' job.
fn refusing_subscriber(
    topic: &str,
) -> std::sync::Arc<super::subscriber::ReaderSubscriber<RefusesXcdr1Tag>> {
    use std::sync::{Arc, Mutex};
    let status = Arc::new(crate::dds::StatusCondition::new());
    let dispose = Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status)));
    let reorder = Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false)));
    Arc::new(super::subscriber::ReaderSubscriber::<RefusesXcdr1Tag>::new(
        topic.to_string(),
        Arc::new(rt::IndexRing::with_capacity(16)),
        status,
        None,
        None,
        None,
        dispose,
        reorder,
    ))
}

/// The capability backstop drops an XCDR1 sample for a type that refuses
/// XCDR1, even though this reader's `accepted_data_repr` is empty ("no
/// restriction" by the explicit-list rule alone).
///
/// MUTANT: remove the `version == Xcdr1 && self.xcdr1.refuses_xcdr1()`
/// check from `data_repr_incompatible` (restoring the pre-fix behavior) and
/// this sample is admitted: `ring.is_empty()` fails.
#[test]
fn data_repr_backstop_drops_xcdr1_for_a_type_that_refuses_it() {
    use crate::engine::Subscriber as _;

    let _ = rt::init_slab_pool();
    let topic = "test_data_repr_backstop_xcdr1";
    let sub = refusing_subscriber(topic);
    let mut buf = [0u8; 4];
    let len = RefusesXcdr1Tag(7)
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr1)
        .expect("encode");
    sub.on_data_with_writer(
        topic,
        [0x70u8; 16],
        1,
        &buf[..len],
        crate::dds::CdrVersion::Xcdr1,
    );
    assert!(
        sub.ring.is_empty(),
        "an XCDR1 sample must not reach a reader whose type refuses XCDR1"
    );
}

/// Sanity: the same reader admits an XCDR2 sample. Without this, the test
/// above could pass for the wrong reason (e.g. a subscriber that admits
/// nothing at all).
#[test]
fn data_repr_backstop_admits_xcdr2_for_the_same_type() {
    use crate::engine::Subscriber as _;

    let _ = rt::init_slab_pool();
    let topic = "test_data_repr_backstop_xcdr2";
    let sub = refusing_subscriber(topic);
    let mut buf = [0u8; 4];
    let len = RefusesXcdr1Tag(7)
        .encode(&mut buf, crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    sub.on_data_with_writer(
        topic,
        [0x71u8; 16],
        1,
        &buf[..len],
        crate::dds::CdrVersion::Xcdr2,
    );
    assert_eq!(
        sub.ring.len(),
        1,
        "an XCDR2 sample must reach a reader whose type refuses only XCDR1"
    );
}

/// DDS v1.4 Sec.2.2.4.3.2: a local listener can take from its reader on
/// the notification alone, giving bounded RELIABLE KEEP_ALL its room back.
#[test]
fn by_source_notification_drains_bounded_local_history() {
    struct Draining {
        reader: std::sync::Weak<super::DataReader<Point>>,
        values: std::sync::Mutex<Vec<i32>>,
    }
    impl crate::dds::listener::DataReaderListener<Point> for Draining {
        fn on_data_available_notification(&self) {
            let reader = self.reader.upgrade().expect("reader alive");
            while let Some(sample) = reader.take().expect("listener take") {
                self.values.lock().unwrap().push(sample.x);
            }
        }
        fn on_data_available(&self, _sample: &Point) {
            panic!("an unaccepted payload reached the listener");
        }
    }
    let mut qos = QoS::reliable().keep_all().destination_order_by_source();
    qos.resource_limits.max_samples = 2;
    let (writer, reader) = bound_pair("by-source-notification-local", qos);
    let listener = std::sync::Arc::new(Draining {
        reader: std::sync::Arc::downgrade(&reader),
        values: std::sync::Mutex::new(Vec::new()),
    });
    reader.set_listener(
        Some(listener.clone()),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for x in 1..=8 {
            writer
                .write_w_timestamp(&Point { x, y: 0 }, u64::try_from(x).unwrap() * 100)
                .expect("write");
        }
        tx.send(()).unwrap();
    });
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("local callback drains outside merger locks");
    assert_eq!(
        *listener.values.lock().unwrap(),
        (1..=8).collect::<Vec<_>>()
    );
}

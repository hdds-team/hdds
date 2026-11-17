// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `emit_coherent_payloads` (TOPIC/INSTANCE scope) deposits a completed
//! per-writer set into the cross-reader presentation barrier
//! (`CoherentPresentationBarrier::deposit`). A set whose every member was
//! rejected for storage (`take_rejected_member` -> `step_gate_over_rejected`
//! -> `PendingPayload::nothing`) has a non-empty payloads Vec (len > 0) but
//! carries no sample at all: `CoherentSet::is_empty()` checks each writer's
//! Vec length, not whether its entries are real, so `deposit`'s own guard
//! never catches it either. Deposited anyway, it would take a round of its own in
//! the barrier -- with a second member on the same Publisher, that empty
//! round could pair with (or starve behind) the other member's real one.
//! `emit_coherent_group` filters this for GROUP scope; the TOPIC-scope door
//! must filter it the same way.

use super::coherent_barrier::CoherentPresentationBarrier;
use super::tests::{encoded_point, Point};
use crate::core::rt;
use crate::dds::QoS;
use crate::engine::Subscriber as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TOPIC: &str = "BarrierEmptyGeneration";

fn guid(prefix: u8, entity: u8) -> [u8; 16] {
    let mut g = [prefix; 16];
    g[12] = 0;
    g[13] = 0;
    g[14] = 0;
    g[15] = entity;
    g
}

/// A TOPIC-scope coherent reader, member `member` of `barrier`, its own
/// ring, driven by `sub`'s own presentation thread (`crate::dds::Subscriber`
/// owns the barrier and the thread that aligns and releases its rounds).
fn member_sub(
    ring: Arc<rt::IndexRing>,
    barrier: &Arc<CoherentPresentationBarrier>,
    member: super::coherent_barrier::MemberId,
) -> Arc<super::subscriber::ReaderSubscriber<Point>> {
    let status = Arc::new(crate::dds::StatusCondition::new());
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            TOPIC.to_string(),
            ring,
            status.clone(),
            None,
            None,
            None,
            Arc::new(super::subscriber::DisposeQueue::new(status)),
            Arc::new(Mutex::new(super::reorder::ReorderGate::new(false, false))),
            super::subscriber::CoherentConfig {
                coherent_access: true,
                is_group_scope: false,
            },
            None,
            None,
            Arc::new(Mutex::new(
                crate::dds::listener::SampleRejectedStatus::default(),
            )),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            Some(Arc::clone(barrier)),
            Some(member),
            #[cfg(feature = "security")]
            None,
        ),
    );
    sub.attach_barrier_delivery();
    sub
}

fn take_all(ring: &rt::IndexRing) -> Vec<u64> {
    let pool = rt::get_slab_pool_ref();
    let mut seqs = Vec::new();
    while let Some(entry) = ring.pop() {
        seqs.push(u64::from(entry.seq));
        pool.release(entry.handle);
    }
    seqs
}

const SETTLE: Duration = Duration::from_millis(300);

/// Two TOPIC-scope members of the same Publisher. Member 1's first
/// commit is entirely rejected for storage (every member of its set a
/// `nothing()` placeholder): it must not take a round of its own. Member
/// 0's real generation 1, and member 1's real generation (its first real
/// content), must each surface -- in particular member 1's real set must
/// not starve behind a phantom round the barrier thinks it already
/// produced.
#[test]
fn an_all_rejected_set_does_not_consume_a_barrier_generation() {
    let _ = rt::init_slab_pool();
    // Owns the barrier AND the presentation thread that aligns and
    // releases its rounds: a bare `CoherentPresentationBarrier` with no
    // owning `Subscriber` has nothing driving `deposit`'s rounds forward.
    let owner = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    let barrier = Arc::clone(owner.coherent_barrier());
    let member0 = barrier.reserve("A".into(), true);
    let member1 = barrier.reserve("B".into(), true);
    let wa = guid(0xA1, 1);
    let wb = guid(0xA1, 2);
    barrier.register_matched_writer(member0, wa);
    barrier.register_matched_writer(member1, wb);

    let ring0 = Arc::new(rt::IndexRing::with_capacity(64));
    let ring1 = Arc::new(rt::IndexRing::with_capacity(64));
    let sub0 = member_sub(Arc::clone(&ring0), &barrier, member0);
    let sub1 = member_sub(Arc::clone(&ring1), &barrier, member1);

    // Member 0's real generation 1.
    sub0.on_data_coherent(
        TOPIC,
        wa,
        1,
        &encoded_point(1, 1),
        crate::dds::CdrVersion::Xcdr2,
        Some(1),
        None,
        None,
    );
    sub0.on_ecs(TOPIC, wa, 2, 1, None, None);
    std::thread::sleep(SETTLE);

    // Member 1's first commit: every member of its set was rejected for
    // storage, so what reaches `emit_coherent_payloads` is a non-empty Vec
    // of nothing but `PendingPayload::nothing` placeholders (the shape
    // `take_rejected_member` produces; this seam reaches the same code
    // deterministically instead of racing a room-wait rejection).
    sub1.emit_all_rejected_set_for_test(wb, 1);
    std::thread::sleep(SETTLE);

    // Member 1's real generation (its first real content).
    sub1.on_data_coherent(
        TOPIC,
        wb,
        3,
        &encoded_point(2, 2),
        crate::dds::CdrVersion::Xcdr2,
        Some(3),
        None,
        None,
    );
    sub1.on_ecs(TOPIC, wb, 4, 3, None, None);
    std::thread::sleep(SETTLE);

    let r0 = take_all(&ring0);
    let r1 = take_all(&ring1);
    assert_eq!(
        r1,
        vec![3],
        "member 1's real set must surface: an all-rejected commit ahead of \
         it (ring0={r0:?}, ring1={r1:?}) must not have taken a barrier \
         generation that leaves this one waiting for a sibling round that \
         will never come"
    );
    assert_eq!(
        r0,
        vec![1],
        "member 0's real generation 1 must surface, undisturbed"
    );
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The deferred notices and the publishing thread, attacked.

use super::coherent_barrier::{publisher_key, CoherentSet};
use super::notices::{notify, Delivering};
use super::reorder::PendingPayload;
use super::tests::{encoded_point, Point};
use super::ReaderBuilder;
use crate::core::rt;
use crate::dds::listener::{DataReaderListener, SampleRejectedReason, SampleRejectedStatus};
use crate::dds::qos::{Presentation, PresentationAccessScope};
use crate::dds::{QoS, StatusMask};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn wguid(p: u8, entity: u8) -> [u8; 16] {
    let mut g = [p; 16];
    g[12] = 0;
    g[13] = 0;
    g[14] = 0;
    g[15] = entity;
    g
}

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

// ---------------------------------------------------------------------------
// N1. A delivery that unwinds keeps its held notices on the thread; the next
// notice told at once on that thread overtakes them; they are told only if
// that thread delivers again.
// ---------------------------------------------------------------------------

#[test]
fn n1_notices_of_a_delivery_that_panicked_are_told() {
    let told = Arc::new(Mutex::new(Vec::new()));
    let note = |n: u32| {
        let told = Arc::clone(&told);
        move || told.lock().unwrap().push(n)
    };
    let first = note(1);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _d = Delivering::enter();
        notify(first);
        panic!("verify: a delivery panics");
    }));
    // The application thread goes on, outside any delivery.
    notify(note(2));
    assert_eq!(
        *told.lock().unwrap(),
        vec![1, 2],
        "the notice held by the delivery that panicked was never told (or told after \
         a later one): it waits for a next delivery on this thread"
    );
}

// ---------------------------------------------------------------------------
// N2. SAMPLE_REJECTED snapshots reach the listener out of order: the dispatch
// lock orders the snapshots, the deferred call no longer follows it.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Records(Mutex<Vec<u32>>);
impl DataReaderListener<Point> for Records {
    fn on_sample_rejected(&self, status: SampleRejectedStatus) {
        self.0.lock().unwrap().push(status.total_count);
    }
}

#[test]
fn n2_sample_rejected_counts_reach_the_listener_in_order() {
    let _ = rt::init_slab_pool();
    let records = Arc::new(Records::default());
    let ring = Arc::new(rt::IndexRing::with_capacity(64));
    let status = Arc::new(crate::dds::StatusCondition::new());
    let sub = Arc::new(
        super::subscriber::ReaderSubscriber::<Point>::new_with_coherent(
            "VerifyRejectOrder".to_string(),
            Arc::clone(&ring),
            Arc::clone(&status),
            None,
            None,
            Some(records.clone() as Arc<dyn DataReaderListener<Point>>),
            Arc::new(super::subscriber::DisposeQueue::new(Arc::clone(&status))),
            Arc::new(Mutex::new(super::reorder::ReorderGate::new(true, false))),
            super::subscriber::CoherentConfig::default(),
            None,
            None,
            Arc::new(Mutex::new(SampleRejectedStatus::default())),
            Vec::new(),
            crate::qos::partition::Partition::default(),
            crate::qos::ownership::OwnershipKind::default(),
            None,
            None,
            None,
            #[cfg(feature = "security")]
            None,
        ),
    );
    let (reported_tx, reported_rx) = std::sync::mpsc::channel();
    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    // Router thread: a refusal inside a delivery (deliver_sample) that is
    // still under way.
    let router = {
        let sub = Arc::clone(&sub);
        std::thread::spawn(move || {
            let _d = Delivering::enter();
            sub.report_sample_rejected_for_test(SampleRejectedReason::ResourceLimit, None);
            reported_tx.send(()).unwrap();
            go_rx.recv().unwrap();
        })
    };
    reported_rx.recv().unwrap();
    // Control thread: a refusal in a delivery that ends first.
    {
        let _d = Delivering::enter();
        sub.report_sample_rejected_for_test(SampleRejectedReason::ResourceLimit, None);
    }
    go_tx.send(()).unwrap();
    router.join().unwrap();
    let seen = records.0.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![1, 2],
        "SAMPLE_REJECTED total_count went backwards at the listener"
    );
}

// ---------------------------------------------------------------------------
// N3. A publication that panics on the presentation thread (outside any
// listener): the readers already delivered are never woken, and the sets
// still to deliver in that publication are dropped, not "still released for
// the next one".
// ---------------------------------------------------------------------------

#[test]
fn n3_a_publication_that_panics_wakes_what_it_delivered_and_keeps_the_rest() {
    let _ = rt::init_slab_pool();
    let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    // Member 0: a real TOPIC-scope coherent reader, no listener.
    let a = ReaderBuilder::<Point>::new("VerifyPanicWake".to_string())
        .qos(
            QoS::best_effort()
                .keep_all()
                .presentation(Presentation::new(
                    PresentationAccessScope::Topic,
                    true,
                    false,
                )),
        )
        .with_registry(Arc::new(crate::engine::TopicRegistry::new()))
        .subscriber(&sub)
        .build()
        .expect("reader");
    let barrier = Arc::clone(sub.coherent_barrier());
    // Member 1: its delivery panics once (any defect in a delivery path).
    let b = barrier.reserve("B".into(), true);
    let panicked = Arc::new(AtomicBool::new(false));
    {
        let panicked = Arc::clone(&panicked);
        barrier.attach_deliver(
            b,
            Arc::new(move |_set: CoherentSet| {
                if !panicked.swap(true, Ordering::SeqCst) {
                    panic!("verify: a delivery panics");
                }
            }),
        );
    }
    // Member 2: counts its sets.
    let c = barrier.reserve("C".into(), true);
    let c_sets = Arc::new(AtomicUsize::new(0));
    {
        let c_sets = Arc::clone(&c_sets);
        barrier.attach_deliver(
            c,
            Arc::new(move |_set: CoherentSet| {
                c_sets.fetch_add(1, Ordering::SeqCst);
            }),
        );
    }
    let (wa, wb, wc) = (wguid(0xC3, 1), wguid(0xC3, 2), wguid(0xC3, 3));
    barrier.register_matched_writer(0, wa);
    barrier.register_matched_writer(b, wb);
    barrier.register_matched_writer(c, wc);
    let k = publisher_key([0xC3; 12], [0; 4]);
    let generation = |gsn: u64, from: i32| {
        barrier.deposit(
            0,
            k,
            CoherentSet::spec_part(vec![(wa, payloads(from, 1))], gsn, false),
        );
        barrier.deposit(
            b,
            k,
            CoherentSet::spec_part(vec![(wb, payloads(from, 1))], gsn, false),
        );
        barrier.deposit(
            c,
            k,
            CoherentSet::spec_part(vec![(wc, payloads(from, 1))], gsn, false),
        );
    };
    generation(1, 1);
    std::thread::sleep(Duration::from_millis(500));
    let woken = a
        .get_status_condition()
        .get_active_statuses()
        .and(StatusMask::DATA_AVAILABLE)
        .bits()
        != 0;
    let c_after_first = c_sets.load(Ordering::SeqCst);
    // A second generation: the presentation thread publishes again.
    generation(2, 2);
    std::thread::sleep(Duration::from_millis(500));
    let c_after_second = c_sets.load(Ordering::SeqCst);
    let a_taken = a.take_all().expect("TOPIC scope").len();
    eprintln!(
        "panicked={} A woken after gen 1={} A taken={} C sets after gen1={} after gen2={}",
        panicked.load(Ordering::SeqCst),
        woken,
        a_taken,
        c_after_first,
        c_after_second
    );
    assert!(
        panicked.load(Ordering::SeqCst),
        "fixture: B's delivery panicked"
    );
    let mut failures = Vec::new();
    if !woken {
        failures.push(
            "A's generation-1 sample is in its ring but DATA_AVAILABLE was never raised \
             (its wake is a held notice of the publication that panicked)",
        );
    }
    if c_after_second != 2 {
        failures.push(
            "C's generation-1 part was dropped by the publication that panicked, with no \
             SAMPLE_LOST (not 'still released for the next one')",
        );
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

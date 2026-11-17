// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The presentation barrier attacked: its publishing thread, its access
//! brackets, its Publisher keys.

use super::coherent_barrier::{publisher_key, CoherentSet};
use super::reorder::PendingPayload;
use super::tests::{encoded_point, Point};
use super::ReaderBuilder;
use crate::core::rt;
use crate::dds::qos::{Presentation, PresentationAccessScope};
use crate::dds::QoS;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
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

fn presentation(scope: PresentationAccessScope) -> Presentation {
    Presentation::new(scope, true, false)
}

fn build(
    sub: &crate::dds::Subscriber,
    topic: &str,
    scope: PresentationAccessScope,
    registry: Arc<crate::engine::TopicRegistry>,
    listener: Option<Arc<dyn crate::dds::listener::DataReaderListener<Point>>>,
) -> Arc<super::DataReader<Point>> {
    let mut b = ReaderBuilder::<Point>::new(topic.to_string())
        .qos(
            QoS::best_effort()
                .keep_all()
                .presentation(presentation(scope)),
        )
        .with_registry(registry)
        .subscriber(sub);
    if let Some(l) = listener {
        b = b.with_listener(l);
    }
    Arc::new(b.build().expect("reader"))
}

// ---------------------------------------------------------------------------
// A1. Lock order: router thread (writer delivery lock -> listener ->
// begin_access -> `publishing`) against the presentation thread
// (`publishing` -> deliver_coherent_set -> writer delivery lock).
// ---------------------------------------------------------------------------

struct OpensBracket {
    deposit: bool,
    sub: OnceLock<Weak<crate::dds::Subscriber>>,
    writer: [u8; 16],
    fired: AtomicBool,
    done: AtomicBool,
}

impl crate::dds::listener::DataReaderListener<Point> for OpensBracket {
    fn on_data_available(&self, _s: &Point) {
        if self.fired.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(sub) = self.sub.get().and_then(Weak::upgrade) else {
            return;
        };
        // A complete set of the same writer reaches the barrier meanwhile
        // (the router thread's next datagram would do it; here, the
        // barrier directly): the presentation thread starts delivering it.
        if self.deposit {
            sub.coherent_barrier().deposit(
                0,
                publisher_key([0xA1; 12], [0; 4]),
                CoherentSet::single(self.writer, payloads(100, 2)),
            );
        }
        std::thread::sleep(Duration::from_millis(300));
        // DDS v1.4 Sec.2.2.2.5 pattern 1: on notification, begin_access.
        let _ = sub.begin_access();
        let _ = sub.end_access();
        self.done.store(true, Ordering::SeqCst);
    }
}

/// A plain (non-set) sample of writer W delivered on the router thread runs
/// the reader's listener under W's delivery lock; the listener opens an
/// access bracket while the presentation thread delivers a set of the same
/// writer. Expected: the bracket opens and the listener returns.
#[test]
fn a1_router_listener_opening_a_bracket_does_not_deadlock_the_presentation_thread() {
    a1_run(true);
}

/// Control: the same listener with no set delivered by the presentation
/// thread meanwhile returns.
#[test]
fn a1_control_without_a_concurrent_set() {
    a1_run(false);
}

fn a1_run(deposit: bool) {
    let _ = rt::init_slab_pool();
    let sub = Arc::new(crate::dds::Subscriber::new(
        QoS::default(),
        None,
        None,
        None,
    ));
    let registry = Arc::new(crate::engine::TopicRegistry::new());
    let w = wguid(0xA1, 1);
    let listener = Arc::new(OpensBracket {
        deposit,
        sub: OnceLock::new(),
        writer: w,
        fired: AtomicBool::new(false),
        done: AtomicBool::new(false),
    });
    listener.sub.set(Arc::downgrade(&sub)).ok();
    let reader = build(
        &sub,
        "VerifyAbba",
        PresentationAccessScope::Topic,
        Arc::clone(&registry),
        Some(listener.clone()),
    );
    // The writer's OWNERSHIP as its SEDP would record it (the data-plane
    // ownership gate defers a writer it cannot resolve).
    registry.register_writer_ownership_kind(w, crate::qos::ownership::OwnershipKind::Shared);
    sub.coherent_barrier().register_matched_writer(0, w);
    let router = {
        let registry = Arc::clone(&registry);
        std::thread::spawn(move || {
            let topic = registry.get_topic("VerifyAbba").expect("topic registered");
            topic.deliver_with_writer(w, 1, &encoded_point(1, 1), crate::dds::CdrVersion::Xcdr2);
        })
    };
    let secs = std::env::var("VERIFY_A1_WAIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    while !listener.done.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let fired = listener.fired.load(Ordering::SeqCst);
    let done = listener.done.load(Ordering::SeqCst);
    if done {
        router.join().expect("router");
    }
    if done {
        // Both threads are out of their locks: the drop is safe and frees
        // the reader and its subscriber.
        drop(reader);
        drop(sub);
    } else {
        // The deadlock this test looks for holds locks the drop would wait
        // on: leave the objects to the process and let the assertion fail.
        std::mem::forget(reader);
        std::mem::forget(sub);
    }
    assert!(fired, "fixture: the plain sample reached the listener");
    assert!(
        done,
        "DEADLOCK: the router thread waits on `publishing` (begin_access) under the \
         writer's delivery lock, the presentation thread waits on that delivery lock \
         under `publishing`"
    );
}

// ---------------------------------------------------------------------------
// A2. A listener run by the presentation thread that opens a bracket reads
// the other readers of the generation before their part is delivered.
// ---------------------------------------------------------------------------

struct ReadsPeer {
    sub: OnceLock<Weak<crate::dds::Subscriber>>,
    peer: OnceLock<Weak<super::DataReader<Point>>>,
    seen: Mutex<Option<usize>>,
}

impl crate::dds::listener::DataReaderListener<Point> for ReadsPeer {
    fn on_data_available(&self, _s: &Point) {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.is_some() {
            return;
        }
        let (Some(sub), Some(peer)) = (
            self.sub.get().and_then(Weak::upgrade),
            self.peer.get().and_then(Weak::upgrade),
        ) else {
            return;
        };
        sub.begin_access().expect("begin");
        *seen = Some(peer.read_batch(16).map_or(usize::MAX, |v| v.len()));
        sub.end_access().expect("end");
    }
}

/// Two GROUP coherent readers of one Subscriber, one generation of one
/// Publisher (a part each). A's DATA_AVAILABLE listener opens an access
/// bracket and reads B: inside a bracket, B must hold its part of the
/// generation A was notified of (DDS v1.4 Sec.2.2.2.5 pattern 1,
/// Sec.2.2.3.6 coherent_access GROUP).
#[test]
fn a2_a_listener_bracket_sees_the_whole_generation() {
    let _ = rt::init_slab_pool();
    let sub = Arc::new(crate::dds::Subscriber::new(
        QoS::default(),
        None,
        None,
        None,
    ));
    let l = Arc::new(ReadsPeer {
        sub: OnceLock::new(),
        peer: OnceLock::new(),
        seen: Mutex::new(None),
    });
    l.sub.set(Arc::downgrade(&sub)).ok();
    let a = build(
        &sub,
        "VerifyTornA",
        PresentationAccessScope::Group,
        Arc::new(crate::engine::TopicRegistry::new()),
        Some(l.clone()),
    );
    let b = build(
        &sub,
        "VerifyTornB",
        PresentationAccessScope::Group,
        Arc::new(crate::engine::TopicRegistry::new()),
        None,
    );
    l.peer.set(Arc::downgrade(&b)).ok();
    let barrier = Arc::clone(sub.coherent_barrier());
    let (wa, wb) = (wguid(0xA2, 1), wguid(0xA2, 2));
    barrier.register_matched_writer(0, wa);
    barrier.register_matched_writer(1, wb);
    let k = publisher_key([0xA2; 12], [0; 4]);
    barrier.deposit(
        0,
        k,
        CoherentSet::spec_part(vec![(wa, payloads(1, 2))], 1, false),
    );
    barrier.deposit(
        1,
        k,
        CoherentSet::spec_part(vec![(wb, payloads(1, 2))], 1, false),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while l.seen.lock().unwrap().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let seen = *l.seen.lock().unwrap();
    assert_eq!(
        seen,
        Some(2),
        "TORN: A's listener, inside an access bracket, found B without its part of \
         the generation A was announced (B delivered after A's listener ran)"
    );
    drop((a, b));
}

// ---------------------------------------------------------------------------
// A3. Thread lifecycle: one thread per Subscriber; it leaves with it.
// Run alone (`--exact`): counts threads of the whole test process.
// ---------------------------------------------------------------------------

fn presentation_threads() -> usize {
    std::fs::read_dir("/proc/self/task")
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| {
                    std::fs::read_to_string(e.path().join("comm"))
                        .is_ok_and(|c| c.trim().starts_with("hdds-present"))
                })
                .count()
        })
        .unwrap_or(0)
}

#[test]
#[ignore = "counts process threads: run alone"]
fn a3_presentation_threads_leave_with_their_subscribers() {
    let _ = rt::init_slab_pool();
    let before = presentation_threads();
    let mut keep = Vec::new();
    for i in 0..16u8 {
        let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
        let r = build(
            &sub,
            &format!("VerifyThreads{i}"),
            PresentationAccessScope::Topic,
            Arc::new(crate::engine::TopicRegistry::new()),
            None,
        );
        sub.coherent_barrier()
            .register_matched_writer(0, wguid(0xB0 + i, 1));
        keep.push((sub, r));
    }
    std::thread::sleep(Duration::from_millis(100));
    let during = presentation_threads();
    eprintln!("presentation threads: before={before} with 16 subscribers={during}");
    drop(keep);
    std::thread::sleep(Duration::from_millis(700));
    let after = presentation_threads();
    eprintln!("presentation threads after drop: {after}");
    assert_eq!(during - before, 16, "one thread per Subscriber");
    assert_eq!(after, before, "threads leave with their barrier");
}

// ---------------------------------------------------------------------------
// A4. Publisher key learned between the keying of a set's writers and its
// queueing: the set is queued under a key no member is required for and
// released alone.
// ---------------------------------------------------------------------------

#[test]
fn a4_a_publisher_learned_mid_deposit_does_not_release_a_part_alone() {
    use super::coherent_barrier::CoherentPresentationBarrier;
    const PUBLISHER: [u8; 4] = [0, 0, 1, 8];
    // No publishing thread: publication only at begin_access (deterministic).
    let barrier = Arc::new(CoherentPresentationBarrier::new());
    let a = barrier.reserve("A".into(), true);
    let b = barrier.reserve("B".into(), true);
    let (w1, w2, w3) = (wguid(0xA4, 1), wguid(0xA4, 2), wguid(0xA4, 3));
    let learned = Arc::new(AtomicBool::new(false));
    let armed = Arc::new(AtomicBool::new(false));
    let weak = Arc::downgrade(&barrier);
    let resolver: super::coherent_barrier::PublisherResolver = {
        let learned = Arc::clone(&learned);
        let armed = Arc::clone(&armed);
        Arc::new(move |w: &[u8; 16]| {
            if *w == w2 && armed.swap(false, Ordering::SeqCst) {
                // Discovery learns the Publisher now, on another thread in
                // production (a SEDP match notification resolving the key).
                learned.store(true, Ordering::SeqCst);
                if let Some(barrier) = weak.upgrade() {
                    barrier.register_matched_writer(0, w1);
                    barrier.register_matched_writer(1, w3);
                }
            }
            learned.load(Ordering::SeqCst).then_some(PUBLISHER)
        })
    };
    barrier.attach_resolver(a, Arc::clone(&resolver));
    barrier.attach_resolver(b, resolver);
    let delivered = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    for (id, count) in [(a, &delivered[0]), (b, &delivered[1])] {
        let count = Arc::clone(count);
        barrier.attach_deliver(
            id,
            Arc::new(move |_set: CoherentSet| {
                count.fetch_add(1, Ordering::SeqCst);
            }),
        );
    }
    // Discovery does not know the Publisher yet: both writers under the
    // participant's key.
    barrier.register_matched_writer(a, w1);
    barrier.register_matched_writer(b, w3);
    armed.store(true, Ordering::SeqCst);
    let k = publisher_key([0xA4; 12], PUBLISHER);
    barrier.deposit(
        a,
        k,
        CoherentSet::single(w1, payloads(1, 1)).with_writer(w2, payloads(2, 1)),
    );
    assert!(
        learned.load(Ordering::SeqCst),
        "fixture: learned mid-deposit"
    );
    barrier.begin_access();
    let (da, db) = (
        delivered[0].load(Ordering::SeqCst),
        delivered[1].load(Ordering::SeqCst),
    );
    barrier.end_access();
    assert_eq!(
        (da, db),
        (0, 0),
        "TORN: A's part was released while B (required for the Publisher) holds none"
    );
}

trait WithWriter {
    fn with_writer(self, w: [u8; 16], p: Vec<PendingPayload>) -> Self;
}
impl WithWriter for CoherentSet {
    fn with_writer(mut self, w: [u8; 16], p: Vec<PendingPayload>) -> Self {
        self.writers.push((w, p));
        self
    }
}

// ---------------------------------------------------------------------------
// A5. A listener that panics on the presentation thread.
// ---------------------------------------------------------------------------

struct PanicsOnce(AtomicBool);
impl crate::dds::listener::DataReaderListener<Point> for PanicsOnce {
    fn on_data_available(&self, _s: &Point) {
        if !self.0.swap(true, Ordering::SeqCst) {
            panic!("verify: a user listener panics once");
        }
    }
}

/// A TOPIC-scope coherent reader (no bracket needed) whose listener panics
/// once. The router path survives a panicking listener (`announce`: "the
/// panic goes on after the wake"); the presentation thread must too, or
/// every later set of the Subscriber is never published.
#[test]
fn a5_a_panicking_listener_does_not_stop_the_presentation_thread() {
    let _ = rt::init_slab_pool();
    let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    let r = build(
        &sub,
        "VerifyPanic",
        PresentationAccessScope::Topic,
        Arc::new(crate::engine::TopicRegistry::new()),
        Some(Arc::new(PanicsOnce(AtomicBool::new(false)))),
    );
    let barrier = Arc::clone(sub.coherent_barrier());
    let w = wguid(0xA5, 1);
    barrier.register_matched_writer(0, w);
    let k = publisher_key([0xA5; 12], [0; 4]);
    barrier.deposit(0, k, CoherentSet::single(w, payloads(1, 2)));
    std::thread::sleep(Duration::from_millis(300));
    let first = r.take_all().expect("TOPIC scope: no bracket needed").len();
    barrier.deposit(0, k, CoherentSet::single(w, payloads(3, 2)));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut second = 0;
    while second == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        second = r.take_all().expect("take_all").len();
    }
    eprintln!("first set taken: {first}, second set taken: {second}");
    assert_eq!(
        second, 2,
        "the second set was never published: the panic killed the Subscriber's \
         presentation thread"
    );
}

/// The same panic on the application thread, inside `begin_access`'s
/// publication (the presentation thread already died of the first ones):
/// after it, the Subscriber must still publish at its next bracket.
#[test]
fn a5b_a_panic_inside_begin_access_leaves_the_subscriber_usable() {
    let _ = rt::init_slab_pool();
    let sub = crate::dds::Subscriber::new(QoS::default(), None, None, None);
    let r = build(
        &sub,
        "VerifyPanicBracket",
        PresentationAccessScope::Group,
        Arc::new(crate::engine::TopicRegistry::new()),
        Some(Arc::new(PanicsTwice(AtomicUsize::new(0)))),
    );
    let barrier = Arc::clone(sub.coherent_barrier());
    let w = wguid(0xA6, 1);
    barrier.register_matched_writer(0, w);
    let k = publisher_key([0xA6; 12], [0; 4]);
    // Set 1: the presentation thread delivers it, its listener panics twice.
    barrier.deposit(0, k, CoherentSet::single(w, payloads(1, 2)));
    std::thread::sleep(Duration::from_millis(300));
    // Set 2: published by the next bracket, on this thread: panic 3.
    barrier.deposit(0, k, CoherentSet::single(w, payloads(3, 2)));
    std::thread::sleep(Duration::from_millis(300));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = sub.begin_access();
    }))
    .is_err();
    eprintln!("panic 3 on the application thread: {panicked}");
    while sub.is_access_locked() {
        if sub.end_access().is_err() {
            break;
        }
    }
    sub.begin_access().expect("begin");
    let drained = r.take_all().expect("take_all").len();
    sub.end_access().expect("end");
    // Set 3: no listener panic any more.
    barrier.deposit(0, k, CoherentSet::single(w, payloads(5, 2)));
    std::thread::sleep(Duration::from_millis(300));
    sub.begin_access().expect("begin");
    let n = r.take_all().expect("take_all").len();
    sub.end_access().expect("end");
    eprintln!("drained after the panic: {drained}; set 3 taken: {n}");
    assert_eq!(n, 2, "set 3 was never published to the reader");
}

struct PanicsTwice(AtomicUsize);
impl crate::dds::listener::DataReaderListener<Point> for PanicsTwice {
    fn on_data_available(&self, _s: &Point) {
        if self.0.fetch_add(1, Ordering::SeqCst) < 3 {
            panic!("verify: a user listener panics");
        }
    }
}

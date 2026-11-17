// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `domain_registry.rs`'s `DomainState::endpoints` is a plain,
//! non-reentrant `RwLock`. `register_writer_with_match` /
//! `register_reader_with_match` (registration) and `unregister` (an
//! endpoint's drop) all decide PUBLICATION_MATCHED / SUBSCRIPTION_MATCHED
//! / OFFERED-or-REQUESTED_INCOMPATIBLE_QOS while that lock is held, and
//! reach the application's listener through `notices::notify`. A listener
//! that creates or deletes an endpoint on the SAME domain from inside such
//! a callback re-takes the same lock on the same thread: a plain `RwLock`
//! is not reentrant, so the thread deadlocks against itself.
//!
//! Every scenario below runs the risky operation on its own thread and
//! waits for it with a bounded `recv_timeout`: a reentrancy defect hangs
//! forever rather than merely failing, and a genuinely hung test would keep
//! the whole `cargo test` process (and the `flock`-shared cargo lock)
//! open indefinitely. A defect here FAILS the assertion instead.

use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus, SubscriptionMatchedStatus,
};
use hdds::{DataReader, DataWriter, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
}

/// Run `body` on its own thread and wait at most 10s for it to finish.
/// A reentrancy defect makes the scenarios below deadlock forever on that thread;
/// the leaked thread is harmless (it holds only its own leased domain's
/// lock, which no other test touches) and the process exits normally at
/// the end of the run regardless of it.
fn run_with_timeout(label: &str, body: impl FnOnce() + Send + 'static) {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::Builder::new()
        .name(label.to_string())
        .spawn(move || {
            body();
            let _ = tx.send(());
        })
        .expect("spawn");
    assert!(
        rx.recv_timeout(Duration::from_secs(10)).is_ok(),
        "{label}: deadlocked (the operation never completed within 10s) -- \
         a listener re-entered DomainState::endpoints while this thread \
         already held it"
    );
}

fn intra(name: &str, domain_id: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap()
}

/// Scenario 1: a reader's `on_subscription_matched`, fired
/// when its matched writer is DROPPED (current_count 1 -> 0, inside
/// `DomainState::unregister`), builds a brand new writer on the same
/// domain/topic from inside the callback.
#[test]
fn unmatch_listener_creates_a_writer() {
    let lease = hdds::test_support::domains::unique_domain();
    let p = intra("rr_um_creates_writer", lease.id());
    let topic_name = "rr_um_creates_writer".to_string();
    let topic = p.topic::<Probe>(&topic_name).unwrap();

    struct CreatesWriter {
        participant: Arc<Participant>,
        topic_name: String,
        created: AtomicUsize,
        // Kept alive so the newly-created writer is not instantly dropped
        // again (which would itself re-enter `unregister`).
        kept: Mutex<Option<DataWriter<Probe>>>,
    }
    impl DataWriterListener<Probe> for CreatesWriter {}
    impl DataReaderListener<Probe> for CreatesWriter {
        fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
            if status.current_count == 0 && status.current_count_change < 0 {
                let w = self
                    .participant
                    .topic::<Probe>(&self.topic_name)
                    .unwrap()
                    .writer()
                    .build()
                    .unwrap();
                self.created.fetch_add(1, Ordering::SeqCst);
                *self.kept.lock().unwrap() = Some(w);
            }
        }
    }

    let listener = Arc::new(CreatesWriter {
        participant: Arc::clone(&p),
        topic_name: topic_name.clone(),
        created: AtomicUsize::new(0),
        kept: Mutex::new(None),
    });
    let _reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&listener) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();

    let listener2 = Arc::clone(&listener);
    run_with_timeout("unmatch_listener_creates_a_writer", move || {
        drop(writer);
    });
    assert_eq!(
        listener2.created.load(Ordering::SeqCst),
        1,
        "the reader's on_subscription_matched(unmatch) listener never ran"
    );
}

/// Scenario 2: The mirror on the writer side: a writer's `on_publication_matched`,
/// fired when its matched reader is DROPPED, builds a new reader from
/// inside the callback.
#[test]
fn unmatch_listener_creates_a_reader() {
    let lease = hdds::test_support::domains::unique_domain();
    let p = intra("rr_um_creates_reader", lease.id());
    let topic_name = "rr_um_creates_reader".to_string();
    let topic = p.topic::<Probe>(&topic_name).unwrap();

    struct CreatesReader {
        participant: Arc<Participant>,
        topic_name: String,
        created: AtomicUsize,
        kept: Mutex<Option<DataReader<Probe>>>,
    }
    impl DataReaderListener<Probe> for CreatesReader {}
    impl DataWriterListener<Probe> for CreatesReader {
        fn on_publication_matched(&self, status: PublicationMatchedStatus) {
            if status.current_count == 0 && status.current_count_change < 0 {
                let r = self
                    .participant
                    .topic::<Probe>(&self.topic_name)
                    .unwrap()
                    .reader()
                    .build()
                    .unwrap();
                self.created.fetch_add(1, Ordering::SeqCst);
                *self.kept.lock().unwrap() = Some(r);
            }
        }
    }

    let listener = Arc::new(CreatesReader {
        participant: Arc::clone(&p),
        topic_name: topic_name.clone(),
        created: AtomicUsize::new(0),
        kept: Mutex::new(None),
    });
    let _writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&listener) as Arc<dyn DataWriterListener<Probe>>)
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();

    let listener2 = Arc::clone(&listener);
    run_with_timeout("unmatch_listener_creates_a_reader", move || {
        drop(reader);
    });
    assert_eq!(
        listener2.created.load(Ordering::SeqCst),
        1,
        "the writer's on_publication_matched(unmatch) listener never ran"
    );
}

/// Scenario 3: Same re-entrancy, but at REGISTRATION time: a reader already
/// exists; a NEW writer's own registration (`register_writer_with_match`,
/// which -- unlike `register_reader_with_match` -- had no deferral at
/// all) finds that reader, fires PUBLICATION_MATCHED on the writer's OWN
/// listener from inside the writer's own `build()` call, and that
/// listener creates yet another reader right there.
#[test]
fn match_listener_creates_an_entity_during_writer_registration() {
    let lease = hdds::test_support::domains::unique_domain();
    let p = intra("rr_reg_writer_creates", lease.id());
    let topic_name = "rr_reg_writer_creates".to_string();
    let topic = p.topic::<Probe>(&topic_name).unwrap();

    let _existing_reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();

    struct CreatesOnMatch {
        participant: Arc<Participant>,
        topic_name: String,
        // The entity this listener is attached to stays alive and
        // RE-matches every entity its own callback creates: without a
        // one-shot guard, each created reader matches the same live
        // writer, re-firing this same callback forever (unbounded
        // recursion through `tell_held`, not the deadlock this file is
        // about -- a plain test-fixture bug, guarded against here).
        once: std::sync::atomic::AtomicBool,
        created: AtomicUsize,
        kept: Mutex<Option<DataReader<Probe>>>,
    }
    impl DataReaderListener<Probe> for CreatesOnMatch {}
    impl DataWriterListener<Probe> for CreatesOnMatch {
        fn on_publication_matched(&self, status: PublicationMatchedStatus) {
            if status.current_count_change > 0 && !self.once.swap(true, Ordering::SeqCst) {
                let r = self
                    .participant
                    .topic::<Probe>(&self.topic_name)
                    .unwrap()
                    .reader()
                    .build()
                    .unwrap();
                self.created.fetch_add(1, Ordering::SeqCst);
                *self.kept.lock().unwrap() = Some(r);
            }
        }
    }

    let listener = Arc::new(CreatesOnMatch {
        participant: Arc::clone(&p),
        topic_name: topic_name.clone(),
        once: std::sync::atomic::AtomicBool::new(false),
        created: AtomicUsize::new(0),
        kept: Mutex::new(None),
    });
    let listener2 = Arc::clone(&listener);
    let kept_writer: Arc<Mutex<Option<DataWriter<Probe>>>> = Arc::new(Mutex::new(None));
    let kept_writer2 = Arc::clone(&kept_writer);
    run_with_timeout(
        "match_listener_creates_an_entity_during_writer_registration",
        move || {
            let w = topic
                .writer()
                .qos(QoS::reliable().keep_last(8))
                .with_listener(listener2 as Arc<dyn DataWriterListener<Probe>>)
                .build()
                .unwrap();
            *kept_writer2.lock().unwrap() = Some(w);
        },
    );
    assert_eq!(
        listener.created.load(Ordering::SeqCst),
        1,
        "the writer's on_publication_matched, fired during its own \
         registration, never ran"
    );
    drop(kept_writer);
}

/// Scenario 4: Mirror at registration time: a writer already exists; a new
/// reader's own registration finds it, fires SUBSCRIPTION_MATCHED on the
/// reader's own listener, which creates another writer.
#[test]
fn match_listener_creates_an_entity_during_reader_registration() {
    let lease = hdds::test_support::domains::unique_domain();
    let p = intra("rr_reg_reader_creates", lease.id());
    let topic_name = "rr_reg_reader_creates".to_string();
    let topic = p.topic::<Probe>(&topic_name).unwrap();

    let _existing_writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();

    struct CreatesOnMatch {
        participant: Arc<Participant>,
        topic_name: String,
        // See the mirror test above: a one-shot guard against unbounded
        // recursion through repeated re-matching, not part of the
        // deadlock being tested.
        once: std::sync::atomic::AtomicBool,
        created: AtomicUsize,
        kept: Mutex<Option<DataWriter<Probe>>>,
    }
    impl DataWriterListener<Probe> for CreatesOnMatch {}
    impl DataReaderListener<Probe> for CreatesOnMatch {
        fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
            if status.current_count_change > 0 && !self.once.swap(true, Ordering::SeqCst) {
                let w = self
                    .participant
                    .topic::<Probe>(&self.topic_name)
                    .unwrap()
                    .writer()
                    .build()
                    .unwrap();
                self.created.fetch_add(1, Ordering::SeqCst);
                *self.kept.lock().unwrap() = Some(w);
            }
        }
    }

    let listener = Arc::new(CreatesOnMatch {
        participant: Arc::clone(&p),
        topic_name: topic_name.clone(),
        once: std::sync::atomic::AtomicBool::new(false),
        created: AtomicUsize::new(0),
        kept: Mutex::new(None),
    });
    let listener2 = Arc::clone(&listener);
    let kept_reader: Arc<Mutex<Option<DataReader<Probe>>>> = Arc::new(Mutex::new(None));
    let kept_reader2 = Arc::clone(&kept_reader);
    run_with_timeout(
        "match_listener_creates_an_entity_during_reader_registration",
        move || {
            let r = topic
                .reader()
                .qos(QoS::reliable().keep_last(8))
                .with_listener(listener2 as Arc<dyn DataReaderListener<Probe>>)
                .build()
                .unwrap();
            *kept_reader2.lock().unwrap() = Some(r);
        },
    );
    assert_eq!(
        listener.created.load(Ordering::SeqCst),
        1,
        "the reader's on_subscription_matched, fired during its own \
         registration, never ran"
    );
    drop(kept_reader);
}

/// Scenario 5: A listener deletes ITSELF's peer: the reader pre-exists; a writer
/// is built, and that writer's OWN listener -- fired during the writer's
/// OWN registration, which finds the pre-existing reader and reports the
/// match -- immediately drops that very reader, its own newly-matched
/// peer. A DELETE re-entering the registry from inside the very
/// registration call that is reporting the match.
#[test]
fn match_listener_drops_its_own_peer() {
    let lease = hdds::test_support::domains::unique_domain();
    let p = intra("rr_drops_peer_reg", lease.id());
    let topic_name = "rr_drops_peer_reg".to_string();
    let topic = p.topic::<Probe>(&topic_name).unwrap();

    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    let peer: Arc<Mutex<Option<DataReader<Probe>>>> = Arc::new(Mutex::new(Some(reader)));

    struct DropsPeer {
        peer: Arc<Mutex<Option<DataReader<Probe>>>>,
        dropped: AtomicUsize,
    }
    impl DataReaderListener<Probe> for DropsPeer {}
    impl DataWriterListener<Probe> for DropsPeer {
        fn on_publication_matched(&self, status: PublicationMatchedStatus) {
            if status.current_count_change > 0 {
                if let Some(r) = self.peer.lock().unwrap().take() {
                    drop(r);
                    self.dropped.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    let listener = Arc::new(DropsPeer {
        peer: Arc::clone(&peer),
        dropped: AtomicUsize::new(0),
    });
    let listener2 = Arc::clone(&listener);
    run_with_timeout(
        "match_listener_drops_its_own_peer_at_registration",
        move || {
            let _writer = topic
                .writer()
                .qos(QoS::reliable().keep_last(8))
                .with_listener(listener2 as Arc<dyn DataWriterListener<Probe>>)
                .build()
                .unwrap();
        },
    );
    assert_eq!(
        listener.dropped.load(Ordering::SeqCst),
        1,
        "the writer never dropped its own newly-matched peer from inside \
         on_publication_matched"
    );
}

/// Scenario 6: Callbacks never fire for an endpoint once it is fully dropped: a
/// reader with a listener is built and dropped again before any writer
/// ever existed (so it never matched anything); a writer that WOULD have
/// matched it, had it still been registered, is built afterward. The
/// dead reader's listener must never be reached.
#[test]
fn no_callback_after_the_endpoint_is_dropped() {
    let lease = hdds::test_support::domains::unique_domain();
    let p = intra("rr_no_callback_after_drop", lease.id());
    let topic_name = "rr_no_callback_after_drop".to_string();
    let topic = p.topic::<Probe>(&topic_name).unwrap();

    #[derive(Default)]
    struct Seen(AtomicUsize);
    impl DataReaderListener<Probe> for Seen {
        fn on_subscription_matched(&self, _status: SubscriptionMatchedStatus) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let seen = Arc::new(Seen::default());
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .with_listener(Arc::clone(&seen) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .unwrap();
    drop(reader);

    let _writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));

    assert_eq!(
        seen.0.load(Ordering::SeqCst),
        0,
        "a dropped reader's listener fired after it was gone"
    );
}

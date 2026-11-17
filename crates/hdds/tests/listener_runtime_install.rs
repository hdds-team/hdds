// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Listeners installed on a live entity (`DataReader::set_listener`,
//! `DataWriter::set_listener`), and `on_data_available` for samples written
//! in the same process.
//!
//! A writer of this process delivers to a reader of this process through the
//! writer's merger, which never passes through the reader's network
//! subscriber: until the merger carried a delivery observer, a reader's
//! `on_data_available` was never called for those samples, even with a
//! listener given to the builder. These tests pin both paths of the merger
//! (sole reader, fan-out), the runtime install and removal, the status mask,
//! and that a sample reaching a reader both ways is announced once.

use hdds::dds::{
    DataReaderListener, DataWriterListener, PublicationMatchedStatus, StatusMask,
    SubscriptionMatchedStatus,
};
use hdds::{Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Reading {
    value: i64,
}

#[derive(Default)]
struct Heard {
    values: Mutex<Vec<i64>>,
    matched_current: AtomicU32,
    matched_calls: AtomicU32,
}

impl DataReaderListener<Reading> for Heard {
    fn on_data_available(&self, sample: &Reading) {
        self.values.lock().unwrap().push(sample.value);
    }

    fn on_subscription_matched(&self, status: SubscriptionMatchedStatus) {
        self.matched_current
            .store(status.current_count, Ordering::SeqCst);
        self.matched_calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl Heard {
    fn values(&self) -> Vec<i64> {
        self.values.lock().unwrap().clone()
    }
}

fn intra(name: &str) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap()
}

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}

#[test]
fn a_listener_installed_on_a_live_reader_hears_local_samples_until_removed() {
    let participant = intra("listener_runtime_sole");
    let topic = participant
        .topic::<Reading>("listener_runtime_sole")
        .unwrap();
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(64))
        .build()
        .unwrap();
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(64))
        .build()
        .unwrap();

    // Before any listener: delivered, not announced.
    writer.write(&Reading { value: 0 }).unwrap();

    let heard = Arc::new(Heard::default());
    reader.set_listener(
        Some(Arc::clone(&heard) as Arc<dyn DataReaderListener<Reading>>),
        StatusMask::ALL,
    );
    for value in 1..=5 {
        writer.write(&Reading { value }).unwrap();
    }
    // Intra-process delivery calls the listener inside write().
    assert_eq!(heard.values(), vec![1, 2, 3, 4, 5]);

    reader.set_listener(None, StatusMask::NONE);
    for value in 6..=8 {
        writer.write(&Reading { value }).unwrap();
    }
    assert_eq!(
        heard.values(),
        vec![1, 2, 3, 4, 5],
        "removed listener heard"
    );

    // Every sample still reached the ring.
    let mut taken = Vec::new();
    while let Some(sample) = reader.take().unwrap() {
        taken.push(sample.value);
    }
    assert_eq!(taken, (0..=8).collect::<Vec<_>>());
}

#[test]
fn a_builder_listener_hears_local_samples_on_the_fan_out_path() {
    let participant = intra("listener_runtime_fanout");
    let topic = participant
        .topic::<Reading>("listener_runtime_fanout")
        .unwrap();
    let heard = Arc::new(Heard::default());
    let with_listener = topic
        .reader()
        .qos(QoS::best_effort().keep_last(64))
        .with_listener(Arc::clone(&heard) as Arc<dyn DataReaderListener<Reading>>)
        .build()
        .unwrap();
    // A second reader: the merger takes its refcounted fan-out path.
    let plain = topic
        .reader()
        .qos(QoS::best_effort().keep_last(64))
        .build()
        .unwrap();
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(64))
        .build()
        .unwrap();
    for value in 1..=4 {
        writer.write(&Reading { value }).unwrap();
    }
    assert_eq!(heard.values(), vec![1, 2, 3, 4]);
    let mut n = 0;
    while plain.take().unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, 4);
    drop(with_listener);
}

#[test]
fn a_mask_without_data_available_keeps_on_data_available_silent() {
    let participant = intra("listener_runtime_mask");
    let topic = participant
        .topic::<Reading>("listener_runtime_mask")
        .unwrap();
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(64))
        .build()
        .unwrap();
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(64))
        .build()
        .unwrap();
    let heard = Arc::new(Heard::default());
    reader.set_listener(
        Some(Arc::clone(&heard) as Arc<dyn DataReaderListener<Reading>>),
        StatusMask::SUBSCRIPTION_MATCHED,
    );
    writer.write(&Reading { value: 1 }).unwrap();
    assert!(heard.values().is_empty());
    reader.set_listener(
        Some(Arc::clone(&heard) as Arc<dyn DataReaderListener<Reading>>),
        StatusMask::DATA_AVAILABLE,
    );
    writer.write(&Reading { value: 2 }).unwrap();
    assert_eq!(heard.values(), vec![2]);
}

#[test]
fn a_listener_that_takes_from_inside_the_callback_does_not_deadlock() {
    struct Taker {
        reader: Mutex<Option<Arc<hdds::DataReader<Reading>>>>,
        taken: Mutex<Vec<i64>>,
    }
    impl DataReaderListener<Reading> for Taker {
        fn on_data_available(&self, _sample: &Reading) {
            let guard = self.reader.lock().unwrap();
            if let Some(reader) = guard.as_ref() {
                while let Some(sample) = reader.take().unwrap() {
                    self.taken.lock().unwrap().push(sample.value);
                }
            }
        }
    }
    let participant = intra("listener_runtime_take_inside");
    let topic = participant
        .topic::<Reading>("listener_runtime_take_inside")
        .unwrap();
    let reader = Arc::new(
        topic
            .reader()
            .qos(QoS::best_effort().keep_last(64))
            .build()
            .unwrap(),
    );
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(64))
        .build()
        .unwrap();
    let taker = Arc::new(Taker {
        reader: Mutex::new(Some(Arc::clone(&reader))),
        taken: Mutex::new(Vec::new()),
    });
    reader.set_listener(
        Some(Arc::clone(&taker) as Arc<dyn DataReaderListener<Reading>>),
        StatusMask::ALL,
    );
    for value in 1..=3 {
        writer.write(&Reading { value }).unwrap();
    }
    assert_eq!(*taker.taken.lock().unwrap(), vec![1, 2, 3]);
    // Break the reader -> listener -> reader cycle.
    reader.set_listener(None, StatusMask::NONE);
    taker.reader.lock().unwrap().take();
}

/// A reader and a writer of two UDP participants of one process: the sample
/// is delivered by the writer's merger (same process) while the wire also
/// carries it; the listener must announce it once, and the match callbacks
/// registered at build time must reach a listener installed afterwards.
#[test]
fn a_listener_installed_after_build_hears_matches_and_each_sample_once() {
    #[derive(Default)]
    struct WriterHeard {
        current: AtomicI32,
        calls: AtomicU32,
    }
    impl DataWriterListener<Reading> for WriterHeard {
        fn on_publication_matched(&self, status: PublicationMatchedStatus) {
            self.current
                .store(status.current_count as i32, Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    let lease = hdds::test_support::domains::unique_domain();
    let domain = lease.id();
    let udp = move |name: &str| {
        Participant::builder(name)
            .domain_id(domain)
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .unwrap()
    };
    let sub = udp("listener_runtime_udp_sub");
    let publ = udp("listener_runtime_udp_pub");
    let topic = sub.topic::<Reading>("listener_runtime_udp").unwrap();
    let pub_topic = publ.topic::<Reading>("listener_runtime_udp").unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(64))
        .build()
        .unwrap();
    let heard = Arc::new(Heard::default());
    reader.set_listener(
        Some(Arc::clone(&heard) as Arc<dyn DataReaderListener<Reading>>),
        StatusMask::ALL,
    );
    let writer = pub_topic
        .writer()
        .qos(QoS::reliable().keep_last(64))
        .build()
        .unwrap();
    let writer_heard = Arc::new(WriterHeard::default());
    writer.set_listener(
        Some(Arc::clone(&writer_heard) as Arc<dyn DataWriterListener<Reading>>),
        StatusMask::ALL,
    );

    assert!(
        wait_for(Duration::from_secs(5), || heard
            .matched_current
            .load(Ordering::SeqCst)
            == 1),
        "on_subscription_matched never reported the local writer"
    );

    for value in 1..=5 {
        writer.write(&Reading { value }).unwrap();
    }
    assert!(wait_for(Duration::from_secs(5), || heard.values().len() >= 5));
    // Leave time for a second copy (the wire) to show up if there were one.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(heard.values(), vec![1, 2, 3, 4, 5]);

    // A reader created after the writer's listener was installed: the
    // writer's match callback, registered at its build, reaches it.
    let second = topic
        .reader()
        .qos(QoS::reliable().keep_last(64))
        .build()
        .unwrap();
    assert!(
        wait_for(Duration::from_secs(5), || writer_heard
            .current
            .load(Ordering::SeqCst)
            == 2),
        "on_publication_matched never reported the second reader (calls={})",
        writer_heard.calls.load(Ordering::SeqCst)
    );
    drop(second);
}

/// A TRANSIENT_LOCAL reader created after a writer of its process wrote is
/// replayed the writer's history through the writer's merger (DDS v1.4
/// Sec.2.2.3.4): its listener hears each replayed sample, once, as it hears
/// a live one. The replay pushed into the reader's ring and told nobody.
/// Told once the binding's locks are released: a listener that creates an
/// entity from inside the call does not deadlock.
fn a_replayed_history_is_announced(mode: TransportMode, name: &str) {
    struct Creates {
        heard: Mutex<Vec<i64>>,
        participant: Arc<Participant>,
        name: String,
    }
    impl DataReaderListener<Reading> for Creates {
        fn on_data_available(&self, sample: &Reading) {
            self.heard.lock().unwrap().push(sample.value);
            // Takes the domain's binding lock: the replay must not hold it.
            let topic = self
                .participant
                .topic::<Reading>(&format!("{}_side", self.name))
                .unwrap();
            drop(topic.writer().build().unwrap());
        }
    }
    // Only UDP opens real sockets; IntraProcess never touches a domain's
    // ports, so it keeps the harmless literal 0 instead of spending a lease.
    let lease = matches!(mode, TransportMode::UdpMulticast)
        .then(hdds::test_support::domains::unique_domain);
    let participant = Participant::builder(name)
        .domain_id(lease.as_ref().map_or(0, |l| l.id()))
        .with_transport(mode)
        .build()
        .unwrap();
    let topic = participant.topic::<Reading>(name).unwrap();
    let durable = || QoS::reliable().transient_local().keep_last(8);
    let writer = topic.writer().qos(durable()).build().unwrap();
    for value in 1..=3 {
        writer.write(&Reading { value }).unwrap();
    }
    let listener = Arc::new(Creates {
        heard: Mutex::new(Vec::new()),
        participant: Arc::clone(&participant),
        name: name.to_string(),
    });
    let reader = topic
        .reader()
        .qos(durable())
        .with_listener(Arc::clone(&listener) as Arc<dyn DataReaderListener<Reading>>)
        .build()
        .unwrap();
    assert_eq!(
        *listener.heard.lock().unwrap(),
        vec![1, 2, 3],
        "{name}: the replayed history was not announced"
    );
    writer.write(&Reading { value: 4 }).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(*listener.heard.lock().unwrap(), vec![1, 2, 3, 4], "{name}");
    let mut taken = Vec::new();
    while let Some(sample) = reader.take().unwrap() {
        taken.push(sample.value);
    }
    assert_eq!(taken, vec![1, 2, 3, 4], "{name}");
}

#[test]
fn a_replayed_history_is_announced_intra_process() {
    a_replayed_history_is_announced(TransportMode::IntraProcess, "listener_replay_intra");
}

#[test]
fn a_replayed_history_is_announced_over_udp() {
    a_replayed_history_is_announced(TransportMode::UdpMulticast, "listener_replay_udp");
}

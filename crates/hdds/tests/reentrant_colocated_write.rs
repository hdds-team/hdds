// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A co-located DATA_AVAILABLE listener that writes again through the SAME
//! writer (an echo, a relay), the writer in a Publisher: the write
//! completes, its change made before the listener runs.

use hdds::dds::DataReaderListener;
use hdds::{DataWriter, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(hdds::DDS, Debug, Clone)]
struct Echo {
    value: i64,
}

/// What a C application holds: the writer's handle, usable from its
/// callback (hdds_writer_write from on_data_available).
struct WriterHandle(*const DataWriter<Echo>);
unsafe impl Send for WriterHandle {}
unsafe impl Sync for WriterHandle {}

#[derive(Default)]
struct Relay {
    writer: OnceLock<WriterHandle>,
    seen: Mutex<Vec<i64>>,
    nested_ok: AtomicUsize,
    nested_err: AtomicUsize,
}

impl DataReaderListener<Echo> for Relay {
    fn on_data_available(&self, sample: &Echo) {
        self.seen.lock().unwrap().push(sample.value);
        if sample.value == 0 {
            if let Some(w) = self.writer.get() {
                // SAFETY: the writer outlives the test's single write; the
                // callback runs on the writing thread (as a C app's would).
                let w = unsafe { &*w.0 };
                match w.write(&Echo { value: 1 }) {
                    Ok(()) => self.nested_ok.fetch_add(1, Ordering::SeqCst),
                    Err(_) => self.nested_err.fetch_add(1, Ordering::SeqCst),
                };
            }
        }
    }
}

fn run() {
    let name = "vn_reent";
    let p: Arc<Participant> = Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = p.topic::<Echo>(name).unwrap();
    let relay = Arc::new(Relay::default());
    let _reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(64))
        .with_listener(Arc::clone(&relay) as Arc<dyn DataReaderListener<Echo>>)
        .build()
        .unwrap();
    let publisher = Arc::new(p.create_publisher(QoS::reliable().keep_last(64)).unwrap());
    // A DataWriter is !Sync: the listener reaches it on the writing thread
    // through a raw handle, as a C application's callback does.
    let writer = Box::new(
        topic
            .writer()
            .qos(QoS::reliable().keep_last(64))
            .publisher(&publisher)
            .build()
            .unwrap(),
    );
    let _ = relay.writer.set(WriterHandle(&raw const *writer));
    writer.write(&Echo { value: 0 }).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let seen = relay.seen.lock().unwrap().clone();
    assert_eq!(
        (relay.nested_ok.load(Ordering::SeqCst), relay.nested_err.load(Ordering::SeqCst), seen.clone()),
        (1, 0, vec![0, 1]),
        "a write from the co-located listener, through the same writer, must complete (seen {seen:?})"
    );
}

#[test]
fn reentrant_write_from_colocated_listener_same_writer_in_publisher() {
    run();
}

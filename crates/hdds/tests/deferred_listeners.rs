// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Listeners of co-located readers and of matches, on the threads that
//! deliver them: once per write, in order, from a thread-local destructor.
// (Adapted from the third verification of the deferred listeners.)

use hdds::dds::{DataReaderListener, SubscriptionMatchedStatus};
use hdds::{DataReader, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Reading {
    value: i64,
}

#[derive(Default)]
struct Taker {
    reader: OnceLock<Arc<Mutex<DataReader<Reading>>>>,
    calls: AtomicUsize,
    log: Mutex<Vec<(i64, Option<i64>, std::thread::ThreadId)>>,
}

impl DataReaderListener<Reading> for Taker {
    fn on_data_available(&self, sample: &Reading) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let took = self
            .reader
            .get()
            .and_then(|r| r.lock().unwrap().take().ok().flatten())
            .map(|s| s.value);
        self.log
            .lock()
            .unwrap()
            .push((sample.value, took, std::thread::current().id()));
    }
}

fn intra(name: &str) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap()
}

/// V1. Exactly once per write, on the writer thread, before write()
/// returns, the sample takeable from inside the listener.
fn once_per_write(fanout: bool) {
    let p = intra(if fanout { "vbf_da_fan" } else { "vbf_da_sole" });
    // One topic per run: the runs share a process and a domain.
    let topic = p
        .topic::<Reading>(if fanout { "vbf_da_fan" } else { "vbf_da_sole" })
        .unwrap();
    let taker = Arc::new(Taker::default());
    let reader = Arc::new(Mutex::new(
        topic
            .reader()
            .qos(QoS::reliable().keep_last(64))
            .with_listener(Arc::clone(&taker) as Arc<dyn DataReaderListener<Reading>>)
            .build()
            .unwrap(),
    ));
    let _ = taker.reader.set(Arc::clone(&reader));
    let _other = fanout.then(|| {
        topic
            .reader()
            .qos(QoS::reliable().keep_last(64))
            .build()
            .unwrap()
    });
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(64))
        .build()
        .unwrap();
    let me = std::thread::current().id();
    for v in 0..500i64 {
        writer.write(&Reading { value: v }).unwrap();
        assert_eq!(
            taker.calls.load(Ordering::SeqCst),
            usize::try_from(v + 1).unwrap(),
            "on_data_available not called exactly once before write() returned (write {v})"
        );
    }
    let log = taker.log.lock().unwrap();
    for (i, (v, took, tid)) in log.iter().enumerate() {
        assert_eq!(*v, i64::try_from(i).unwrap());
        assert_eq!(
            *took,
            Some(*v),
            "sample {v} not takeable inside its listener"
        );
        assert_eq!(*tid, me, "listener not on the writer thread");
    }
}

#[test]
fn v1_intra_da_once_per_write_sole() {
    once_per_write(false);
}

#[test]
fn v1_intra_da_once_per_write_fanout() {
    once_per_write(true);
}

/// V1b. A listener that writes to another topic (relay) from inside
/// on_data_available: the relayed reader is told too, once.
#[test]
fn v1b_relay_from_inside_the_listener() {
    struct Relay {
        out: OnceLock<Mutex<hdds::DataWriter<Reading>>>,
    }
    impl DataReaderListener<Reading> for Relay {
        fn on_data_available(&self, s: &Reading) {
            if let Some(w) = self.out.get() {
                w.lock()
                    .unwrap()
                    .write(&Reading {
                        value: s.value + 1000,
                    })
                    .unwrap();
            }
        }
    }
    #[derive(Default)]
    struct Count(AtomicUsize);
    impl DataReaderListener<Reading> for Count {
        fn on_data_available(&self, _s: &Reading) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let p = intra("vbf_relay");
    let a = p.topic::<Reading>("vbf_relay_a").unwrap();
    let b = p.topic::<Reading>("vbf_relay_b").unwrap();
    let relay = Arc::new(Relay {
        out: OnceLock::new(),
    });
    let count = Arc::new(Count::default());
    let _ra = a
        .reader()
        .with_listener(Arc::clone(&relay) as Arc<dyn DataReaderListener<Reading>>)
        .build()
        .unwrap();
    let _rb = b
        .reader()
        .with_listener(Arc::clone(&count) as Arc<dyn DataReaderListener<Reading>>)
        .build()
        .unwrap();
    let _ = relay.out.set(Mutex::new(b.writer().build().unwrap()));
    let wa = a.writer().build().unwrap();
    for v in 0..50 {
        wa.write(&Reading { value: v }).unwrap();
        assert_eq!(
            count.0.load(Ordering::SeqCst),
            usize::try_from(v + 1).unwrap()
        );
    }
}

/// V2b. Matched before data, UDP same process (lo): the reader listener
/// must see SUBSCRIPTION_MATCHED before the first DATA_AVAILABLE when the
/// writer only writes once it has matched.
#[derive(Default)]
struct Seq(Mutex<Vec<&'static str>>, Mutex<Vec<(u32, i32)>>);
impl DataReaderListener<Reading> for Seq {
    fn on_data_available(&self, _s: &Reading) {
        self.0.lock().unwrap().push("D");
    }
    fn on_subscription_matched(&self, s: SubscriptionMatchedStatus) {
        self.0.lock().unwrap().push("M");
        self.1
            .lock()
            .unwrap()
            .push((s.current_count, s.current_count_change));
    }
}

#[test]
fn v2b_matched_before_first_data_udp() {
    let udp = |n: &str| {
        Participant::builder(n)
            .domain_id(0)
            .with_transport(TransportMode::UdpMulticast)
            .build()
            .unwrap()
    };
    for round in 0..3 {
        let sub = udp(&format!("vbf_m_sub{round}"));
        let publ = udp(&format!("vbf_m_pub{round}"));
        let tname = format!("vbf_m_{round}");
        let seq = Arc::new(Seq::default());
        let _reader = sub
            .topic::<Reading>(&tname)
            .unwrap()
            .reader()
            .qos(QoS::reliable().keep_last(64))
            .with_listener(Arc::clone(&seq) as Arc<dyn DataReaderListener<Reading>>)
            .build()
            .unwrap();
        let writer = publ
            .topic::<Reading>(&tname)
            .unwrap()
            .writer()
            .qos(QoS::reliable().keep_last(64))
            .build()
            .unwrap();
        let t0 = Instant::now();
        while writer.matched_reader_count() == 0 && t0.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(writer.matched_reader_count() > 0, "no match");
        for v in 0..5 {
            writer.write(&Reading { value: v }).unwrap();
        }
        let t0 = Instant::now();
        while seq.0.lock().unwrap().iter().filter(|e| **e == "D").count() < 5
            && t0.elapsed() < Duration::from_secs(5)
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        let ev = seq.0.lock().unwrap().clone();
        eprintln!("round {round}: {ev:?} matched={:?}", seq.1.lock().unwrap());
        assert_eq!(ev.first(), Some(&"M"), "DATA before MATCHED: {ev:?}");
        assert_eq!(ev.iter().filter(|e| **e == "M").count(), 1, "{ev:?}");
    }
}

/// V7. write() from a thread-local destructor (a logger/flush-on-exit
/// pattern): HELD is a thread-local with a destructor.
#[test]
fn v7_write_from_a_thread_local_destructor() {
    struct OnExit(
        Option<hdds::DataWriter<Reading>>,
        Arc<Mutex<Option<String>>>,
    );
    impl Drop for OnExit {
        fn drop(&mut self) {
            if let Some(w) = self.0.take() {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    w.write(&Reading { value: 7 })
                }));
                *self.1.lock().unwrap() = Some(match r {
                    Ok(Ok(())) => "ok".into(),
                    Ok(Err(e)) => format!("err {e:?}"),
                    Err(_) => "PANICKED".into(),
                });
            }
        }
    }
    thread_local! {
        static SLOT: std::cell::RefCell<Option<OnExit>> = const { std::cell::RefCell::new(None) };
    }
    let p = intra("vbf_tls");
    let topic = p.topic::<Reading>("vbf_tls").unwrap();
    let reader = topic
        .reader()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    let outcome = Arc::new(Mutex::new(None));
    let o = Arc::clone(&outcome);
    let w = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    std::thread::spawn(move || {
        // SLOT registered BEFORE the notices TLS: destroyed after it.
        SLOT.with(|s| *s.borrow_mut() = Some(OnExit(None, Arc::clone(&o))));
        w.write(&Reading { value: 1 }).unwrap();
        SLOT.with(|s| *s.borrow_mut() = Some(OnExit(Some(w), o)));
    })
    .join()
    .ok();
    let got = outcome.lock().unwrap().clone();
    let mut n = 0;
    while reader.take().unwrap().is_some() {
        n += 1;
    }
    eprintln!("write from TLS dtor: {got:?}, reader got {n}");
    assert_eq!(got.as_deref(), Some("ok"));
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A RELIABLE KEEP_ALL writer and reader in ONE process share its slab pool
//! (`rt::get_slab_pool_ref`): the writer's unacknowledged history and the
//! reader's received samples take their storage from the same tiers.
//!
//! When the reader's receive pipeline stalls (a listener busy for 800 ms
//! while the application takes on another thread), the burst is partly
//! lost on the way and the writer's history fills the pool. The repair of
//! the missing sample at the head of the reader's gap then needs storage
//! the writer's history holds, and that history is freed only once the
//! repair is acknowledged: before the pool kept a share for readers, the
//! pair stalled for good (write 2935 of 4000 timed out after 30 s, one
//! sample delivered, 372 refusals). DDS 1.4 2.2.3.14 / 2.2.3.18: every
//! sample is delivered, in order; a writer blocked for memory waits at most
//! `max_blocking_time`, then fails with TIMEOUT, cleanly.

use hdds::dds::DataReaderListener;
use hdds::{DataWriter, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
    pad: Vec<u8>,
}

/// Holds the receive pipeline on the first sample it is told of.
struct HoldFirst(AtomicBool, Duration);
impl DataReaderListener<Probe> for HoldFirst {
    fn on_data_available(&self, _s: &Probe) {
        if !self.0.swap(true, Ordering::SeqCst) {
            std::thread::sleep(self.1);
        }
    }
}

/// The tests of this file each fill the process pool: run one at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn participant(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .shm_disable()
        .build()
        .expect("participant")
}

#[test]
fn a_stalled_reader_and_its_writer_in_one_process_never_deadlock() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    const SAMPLES: i64 = 4000;
    const PAD: usize = 6000;
    let domain = hdds::test_support::domains::unique_domain();
    let pa = participant("sp_pub", domain.id());
    let pb = participant("sp_sub", domain.id());
    let topic = "a_shared_pool_never_deadlocks";
    let reader = pb
        .topic::<Probe>(topic)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::new(HoldFirst(
            AtomicBool::new(false),
            Duration::from_millis(800),
        )) as Arc<dyn DataReaderListener<Probe>>)
        .build()
        .expect("reader");
    let writer: DataWriter<Probe> = pa
        .topic::<Probe>(topic)
        .expect("topic")
        .writer()
        .qos(
            QoS::reliable()
                .keep_all()
                .max_blocking_time(Duration::from_secs(30)),
        )
        .build()
        .expect("writer");
    let t = Instant::now();
    while writer.matched_reader_count() == 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(writer.matched_reader_count(), 1, "fixture: matched");
    std::thread::sleep(Duration::from_millis(200));

    let failed = Arc::new(AtomicUsize::new(0));
    let t0 = Instant::now();
    let mut got: Vec<i64> = Vec::new();
    std::thread::scope(|scope| {
        let f2 = Arc::clone(&failed);
        // A DataWriter is Send, not Sync: the writing thread owns it, and
        // hands it back so it outlives the reader's last take.
        let w = writer;
        let writing = scope.spawn(move || {
            for value in 0..SAMPLES {
                if let Err(e) = w.write(&Probe {
                    value,
                    pad: vec![0xA5; PAD],
                }) {
                    eprintln!("write {value} failed after {:?}: {e:?}", t0.elapsed());
                    f2.fetch_add(1, Ordering::SeqCst);
                    break;
                }
            }
            w
        });
        let mut last_len = 0usize;
        let mut last_progress = Instant::now();
        while t0.elapsed() < Duration::from_secs(90) {
            while let Some(s) = reader.take().expect("take") {
                got.push(s.value);
            }
            if got.len() as i64 >= SAMPLES || failed.load(Ordering::SeqCst) != 0 {
                break;
            }
            if got.len() != last_len {
                last_len = got.len();
                last_progress = Instant::now();
            } else if last_progress.elapsed() > Duration::from_secs(40) {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        drop(writing.join());
    });
    eprintln!(
        "got={} failed={} elapsed={:?} rejected={:?}",
        got.len(),
        failed.load(Ordering::SeqCst),
        t0.elapsed(),
        reader.get_sample_rejected_status(),
    );
    assert_eq!(
        failed.load(Ordering::SeqCst),
        0,
        "a write timed out: the pair stalled"
    );
    assert_eq!(got.len() as i64, SAMPLES, "every sample delivered");
    assert!(got.iter().copied().eq(0..SAMPLES), "in order");
}

/// A burst larger than the process pool, written by one application thread
/// that takes only afterwards: the write blocked for memory waits
/// `max_blocking_time`, then fails with TIMEOUT (never a hang); every sample
/// written reaches the reader, and the writer writes again once it took.
#[test]
fn a_burst_over_the_pool_times_out_cleanly_and_loses_nothing() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = hdds::test_support::domains::unique_domain();
    let pa = participant("sp_burst_pub", domain.id());
    let pb = participant("sp_burst_sub", domain.id());
    let topic = "a_burst_over_the_pool_times_out_cleanly";
    let reader = pb
        .topic::<Probe>(topic)
        .expect("t")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");
    let writer: DataWriter<Probe> = pa
        .topic::<Probe>(topic)
        .expect("t")
        .writer()
        .qos(
            QoS::reliable()
                .keep_all()
                .max_blocking_time(Duration::from_millis(1500)),
        )
        .build()
        .expect("writer");
    let t = Instant::now();
    while writer.matched_reader_count() == 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(200));
    let mut written = 0i64;
    let mut err = None;
    for value in 0..5000 {
        let w0 = Instant::now();
        match writer.write(&Probe {
            value,
            pad: vec![0x5A; 6000],
        }) {
            Ok(()) => written += 1,
            Err(e) => {
                err = Some((e, w0.elapsed()));
                break;
            }
        }
    }
    let (e, waited) = err.expect("5000 x 6 kB exceed the 16 MiB process pool");
    assert!(matches!(e, hdds::Error::WriteTimeout), "TIMEOUT, got {e:?}");
    assert!(
        waited >= Duration::from_millis(1400),
        "waited max_blocking_time: {waited:?}"
    );
    std::thread::sleep(Duration::from_millis(500));
    let mut got = Vec::new();
    let t1 = Instant::now();
    while (got.len() as i64) < written && t1.elapsed() < Duration::from_secs(20) {
        while let Some(s) = reader.take().expect("take") {
            got.push(s.value);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        got.len() as i64,
        written,
        "every sample written reaches the reader"
    );
    assert!(got.iter().copied().eq(0..written), "in order");
    writer
        .write(&Probe {
            value: -1,
            pad: vec![0; 6000],
        })
        .expect("write after take");
}

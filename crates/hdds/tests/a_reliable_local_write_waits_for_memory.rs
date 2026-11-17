// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A RELIABLE KEEP_ALL write whose sample a co-located reader is to receive
//! through the intra-process leg needs slab memory for that leg. Out of it
//! (the reader's untaken samples hold the pool), the write must block up to
//! `max_blocking_time` and then fail with TIMEOUT, as the history path does
//! (DDS 1.4 2.2.2.4.2.11, 2.2.3.18); it must not fail at once with
//! WouldBlock when the leg is the only one, nor, when a remote reader is
//! matched too, go on without the local reader at all: the local
//! RELIABLE reader must not lose the sample, unreported.

use hdds::{DataReader, DataWriter, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
    pad: Vec<u8>,
}

/// The tests of this file each fill the process pool: run one at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Everything `reader` holds, taken.
fn take_all(reader: &DataReader<Probe>) -> Vec<i64> {
    let mut got = Vec::new();
    while let Some(s) = reader.take().expect("take") {
        got.push(s.value);
    }
    got
}

/// Intra-process only: the write blocked for memory waits for the take
/// that frees it (another thread, a second after 1500 of the burst are in;
/// about 2200 fill the writers' part of the pool).
#[test]
fn an_intra_process_write_out_of_memory_waits_for_the_take() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = hdds::test_support::domains::unique_domain();
    let p = Participant::builder("lw_intra")
        .domain_id(domain.id())
        .with_transport(TransportMode::IntraProcess)
        .build()
        .expect("participant");
    let topic = "a_reliable_local_write_waits_intra";
    let reader = p
        .topic::<Probe>(topic)
        .expect("t")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");
    let writer: DataWriter<Probe> = p
        .topic::<Probe>(topic)
        .expect("t")
        .writer()
        .qos(
            QoS::reliable()
                .keep_all()
                .max_blocking_time(Duration::from_secs(10)),
        )
        .build()
        .expect("writer");
    std::thread::sleep(Duration::from_millis(200));
    let start_taking = Arc::new(AtomicBool::new(false));
    let mut outcome = None;
    let mut longest = Duration::ZERO;
    let mut taken = Vec::new();
    std::thread::scope(|s| {
        let st = Arc::clone(&start_taking);
        let r = &reader;
        let taker = s.spawn(move || {
            let t = Instant::now();
            while !st.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(60) {
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(1000));
            let mut got = Vec::new();
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(3) {
                got.extend(take_all(r));
                std::thread::sleep(Duration::from_millis(1));
            }
            got
        });
        for value in 0..5000i64 {
            // 1500 x 6 kB in: the taker starts a second later.
            if value == 1500 {
                start_taking.store(true, Ordering::SeqCst);
            }
            let w0 = Instant::now();
            let written = writer.write(&Probe {
                value,
                pad: vec![1; 6000],
            });
            longest = longest.max(w0.elapsed());
            if let Err(e) = written {
                outcome = Some((value, format!("{e:?}"), w0.elapsed()));
                break;
            }
        }
        start_taking.store(true, Ordering::SeqCst);
        taken = taker.join().expect("taker");
    });
    taken.extend(take_all(&reader));
    assert!(
        outcome.is_none(),
        "a reliable write blocked for memory must wait for the take: {outcome:?}"
    );
    assert!(
        longest >= Duration::from_millis(300),
        "fixture: a write waited for the take ({longest:?})"
    );
    assert!(taken.iter().copied().eq(0..5000), "every sample, in order");
}

/// A local reader and a remote one: out of memory for the local leg, the
/// write blocks, then times out; it never goes on without the local reader.
#[test]
fn a_write_out_of_memory_for_its_local_leg_times_out_and_skips_no_reader() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let domain = hdds::test_support::domains::unique_domain();
    let udp = |name: &str| {
        Participant::builder(name)
            .domain_id(domain.id())
            .with_transport(TransportMode::UdpMulticast)
            .shm_disable()
            .build()
            .expect("participant")
    };
    let pa = udp("lw_mixed_pub");
    let pb = udp("lw_mixed_sub");
    let topic = "a_reliable_local_write_waits_mixed";
    let qos = || QoS::reliable().keep_all();
    let local = pa
        .topic::<Probe>(topic)
        .expect("t")
        .reader()
        .qos(qos())
        .build()
        .expect("local reader");
    let remote = pb
        .topic::<Probe>(topic)
        .expect("t")
        .reader()
        .qos(qos())
        .build()
        .expect("remote reader");
    let writer: DataWriter<Probe> = pa
        .topic::<Probe>(topic)
        .expect("t")
        .writer()
        .qos(qos().max_blocking_time(Duration::from_millis(1500)))
        .build()
        .expect("writer");
    let t = Instant::now();
    while writer.matched_reader_count() < 2 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(writer.matched_reader_count(), 2, "fixture: both matched");
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
    let (e, waited) = err.expect("5000 x 6 kB twice over exceed the 16 MiB process pool");
    assert!(matches!(e, hdds::Error::WriteTimeout), "TIMEOUT, got {e:?}");
    assert!(
        waited >= Duration::from_millis(1400),
        "waited max_blocking_time: {waited:?}"
    );
    let mut local_got = Vec::new();
    let mut remote_got = Vec::new();
    let t1 = Instant::now();
    while ((local_got.len() as i64) < written || (remote_got.len() as i64) < written)
        && t1.elapsed() < Duration::from_secs(30)
    {
        local_got.extend(take_all(&local));
        remote_got.extend(take_all(&remote));
        std::thread::sleep(Duration::from_millis(2));
    }
    eprintln!(
        "written={written} local={} remote={}",
        local_got.len(),
        remote_got.len()
    );
    assert!(
        local_got.iter().copied().eq(0..written),
        "the local reader gets every sample written, in order ({} of {written})",
        local_got.len()
    );
    assert!(
        remote_got.iter().copied().eq(0..written),
        "the remote reader too ({} of {written})",
        remote_got.len()
    );
}

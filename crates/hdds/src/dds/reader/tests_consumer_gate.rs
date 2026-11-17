// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The two builds of the consumer gate (default compare-and-swap, feature
//! `fast-consumer-gate`) behave identically on the reader API: the same
//! script, run by each test lane against the gate it ships, must produce
//! the same transcript, written out here once for both.

use super::ReaderBuilder;
use crate::core::rt;
use crate::dds::writer::WriterBuilder;
use crate::dds::{
    DataReader, DataWriter, InstanceStateMask, QoS, SampleState, SampleStateMask, ViewStateMask,
    WaitSet,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, crate::DDS)]
struct Tick {
    id: i32,
}

fn pair(topic: &str, depth: u32) -> (DataWriter<Tick>, Arc<DataReader<Tick>>) {
    let _ = rt::init_slab_pool();
    let writer = WriterBuilder::<Tick>::new(topic.to_string())
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let reader = ReaderBuilder::<Tick>::new(topic.to_string())
        .qos(QoS::best_effort().keep_last(depth))
        .build()
        .expect("reader");
    reader.bind_to_writer(writer.merger());
    (writer, Arc::new(reader))
}

fn drain(reader: &DataReader<Tick>) -> Vec<i32> {
    let mut ids = Vec::new();
    while let Some(tick) = reader.take().expect("take") {
        ids.push(tick.id);
    }
    ids
}

/// One reader taken by one thread, then by a second thread (which, on the
/// owned gate, engages it), then through conditions, then by a WaitSet
/// thread and a taking thread at once. `first_on_other_thread` starts the
/// script with a consumer that is not the thread that built the reader.
fn script(topic: &str, first_on_other_thread: bool) -> Vec<String> {
    let (writer, reader) = pair(topic, 4096);
    let write = |ids: std::ops::Range<i32>| {
        for id in ids {
            writer.write(&Tick { id }).expect("write");
        }
    };
    let mut transcript = Vec::new();

    write(0..3);
    let first = if first_on_other_thread {
        let reader = Arc::clone(&reader);
        std::thread::spawn(move || drain(&reader))
            .join()
            .expect("first consumer")
    } else {
        drain(&reader)
    };
    transcript.push(format!("first consumer: {first:?}"));

    write(3..5);
    let other = {
        let reader = Arc::clone(&reader);
        std::thread::spawn(move || drain(&reader))
            .join()
            .expect("second consumer")
    };
    transcript.push(format!("another thread: {other:?}"));

    write(5..6);
    transcript.push(format!("back on this thread: {:?}", drain(&reader)));

    let condition = reader
        .create_readcondition(
            SampleStateMask::NOT_READ,
            ViewStateMask::ANY,
            InstanceStateMask::ALIVE,
        )
        .expect("condition");
    write(6..8);
    let read = reader.read_w_condition(&condition, 10).expect("read");
    transcript.push(format!(
        "read_w_condition: {:?}",
        read.iter()
            .map(|(tick, info)| (tick.map(|t| t.id), info.sample_state))
            .collect::<Vec<_>>()
    ));
    assert!(read
        .iter()
        .all(|(_, info)| info.sample_state == SampleState::NotRead));
    let any_state = reader
        .create_readcondition(
            SampleStateMask::ANY,
            ViewStateMask::ANY,
            InstanceStateMask::ALIVE,
        )
        .expect("condition");
    let taken = reader.take_w_condition(&any_state, 10).expect("take");
    transcript.push(format!(
        "take_w_condition: {:?}",
        taken
            .iter()
            .map(|(tick, info)| (tick.map(|t| t.id), info.sample_state))
            .collect::<Vec<_>>()
    ));

    // A WaitSet evaluating a condition while another thread takes: every
    // sample comes out of take() exactly once.
    const RACED: i32 = 2000;
    let stop = Arc::new(AtomicBool::new(false));
    let waiter = {
        let condition = Arc::clone(&condition);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let waitset = WaitSet::new();
            waitset.attach_condition(condition).expect("attach");
            while !stop.load(Ordering::Acquire) {
                let _ = waitset.wait(Some(Duration::from_millis(1)));
            }
        })
    };
    let taker = {
        let reader = Arc::clone(&reader);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut seen = Vec::new();
            loop {
                seen.extend(drain(&reader));
                if stop.load(Ordering::Acquire) {
                    seen.extend(drain(&reader));
                    return seen;
                }
                std::thread::yield_now();
            }
        })
    };
    for id in 100..100 + RACED {
        writer.write(&Tick { id }).expect("write");
        if id % 64 == 0 {
            std::thread::yield_now();
        }
    }
    std::thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Release);
    waiter.join().expect("waiter");
    let mut counts: BTreeMap<i32, usize> = BTreeMap::new();
    for id in taker.join().expect("taker") {
        *counts.entry(id).or_default() += 1;
    }
    let exactly_once = counts.len() == RACED as usize && counts.values().all(|n| *n == 1);
    transcript.push(format!(
        "raced take, every sample exactly once: {exactly_once}"
    ));
    transcript.push(format!("left over: {:?}", drain(&reader)));
    transcript
}

fn expected() -> Vec<String> {
    vec![
        "first consumer: [0, 1, 2]".to_string(),
        "another thread: [3, 4]".to_string(),
        "back on this thread: [5]".to_string(),
        "read_w_condition: [(Some(6), NotRead), (Some(7), NotRead)]".to_string(),
        "take_w_condition: [(Some(6), Read), (Some(7), Read)]".to_string(),
        "raced take, every sample exactly once: true".to_string(),
        "left over: []".to_string(),
    ]
}

#[test]
fn both_gates_give_the_same_transcript_when_the_building_thread_consumes_first() {
    assert_eq!(script("gate-transcript-local", false), expected());
}

#[test]
fn both_gates_give_the_same_transcript_when_another_thread_consumes_first() {
    assert_eq!(script("gate-transcript-remote", true), expected());
}

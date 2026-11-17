// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TIME_BASED_FILTER (DDS v1.4 Sec.2.2.3.12) for an application that waits
//! instead of polling: a sample that arrives inside the window of the
//! previous one is not lost, and a WaitSet is woken when the window ends
//! (the policy: "in steady state ... the system should guarantee delivery
//! [of] the last sample"). Real participant, real writer, real clock.

use hdds::dds::listener::DataReaderListener;
use hdds::dds::{Condition, StatusMask};
use hdds::{Participant, QoS, TransportMode, WaitSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, hdds::DDS)]
struct Value {
    value: i32,
}

const SEPARATION_MS: u64 = 400;

#[derive(Default)]
struct Probe {
    payloads: AtomicUsize,
    notifications: AtomicUsize,
}

impl DataReaderListener<Value> for Probe {
    fn on_data_available(&self, _sample: &Value) {
        self.payloads.fetch_add(1, Ordering::SeqCst);
    }
    fn on_data_available_notification(&self) {
        self.notifications.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_waiting_reader_is_woken_when_the_window_of_a_held_sample_ends() {
    let participant = Participant::builder("tbf-wake")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Value>("tbf-wake-topic").unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(
            QoS::reliable()
                .keep_last(8)
                .time_based_filter_millis(SEPARATION_MS),
        )
        .build()
        .unwrap();
    let probe = Arc::new(Probe::default());
    reader.set_listener(
        Some(probe.clone() as Arc<dyn DataReaderListener<Value>>),
        StatusMask::DATA_AVAILABLE,
    );
    let condition = reader.get_status_condition();
    condition.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    let waitset = WaitSet::new();
    waitset
        .attach_condition(Arc::clone(&condition) as Arc<dyn Condition>)
        .unwrap();

    let start = Instant::now();
    writer.write(&Value { value: 1 }).unwrap();
    let first = wait_for_take(&waitset, &reader, Duration::from_secs(2));
    assert_eq!(first, Some(1));

    // Inside the window: parked, not visible.
    writer.write(&Value { value: 2 }).unwrap();
    assert_eq!(reader.take().unwrap(), None);

    let second = wait_for_take(&waitset, &reader, Duration::from_secs(3));
    let elapsed = start.elapsed();
    assert_eq!(second, Some(2), "the held sample is delivered");
    // The listener was told, never handed a sample the filter may hold.
    assert_eq!(probe.payloads.load(Ordering::SeqCst), 0);
    assert!(probe.notifications.load(Ordering::SeqCst) >= 2);
    assert!(
        elapsed >= Duration::from_millis(SEPARATION_MS),
        "never before the window ends: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(SEPARATION_MS + 1500),
        "woken at the window's end, not by a later timeout: {elapsed:?}"
    );
}

/// A burst inside one window, then silence: the newest sample of the burst is
/// the one held, and a WaitSet is woken for its window's end with no further
/// arrival.
#[test]
fn a_waiting_reader_is_woken_for_the_last_sample_of_a_burst_that_goes_silent() {
    let participant = Participant::builder("tbf-wake-burst")
        .domain_id(211)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant.topic::<Value>("tbf-wake-burst-topic").unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(
            QoS::reliable()
                .keep_last(8)
                .time_based_filter_millis(SEPARATION_MS),
        )
        .build()
        .unwrap();
    let condition = reader.get_status_condition();
    condition.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    let waitset = WaitSet::new();
    waitset
        .attach_condition(Arc::clone(&condition) as Arc<dyn Condition>)
        .unwrap();

    let start = Instant::now();
    writer.write(&Value { value: 1 }).unwrap();
    assert_eq!(
        wait_for_take(&waitset, &reader, Duration::from_secs(2)),
        Some(1)
    );

    // Three writes inside the window of the shown sample, then nothing.
    for value in 2..=4 {
        writer.write(&Value { value }).unwrap();
    }
    assert_eq!(reader.take().unwrap(), None);

    let last = wait_for_take(&waitset, &reader, Duration::from_secs(3));
    let elapsed = start.elapsed();
    assert_eq!(last, Some(4), "the newest of the burst is the one held");
    assert!(
        elapsed >= Duration::from_millis(SEPARATION_MS),
        "never before the window ends: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(SEPARATION_MS + 1500),
        "woken at the window's end, not by a later timeout: {elapsed:?}"
    );
}

/// A newer sample can move the instant the parked one is due: a poor pick
/// (produced too soon after the one shown) is due a full separation after the
/// window ends, a good one when the window ends. A waiting reader is woken
/// for the instant of the sample that is parked, not the one it replaced.
#[test]
fn a_waiting_reader_is_woken_for_the_instant_a_replacement_is_due() {
    const SEPARATION: u64 = 1000;
    let participant = Participant::builder("tbf-wake-replaced")
        .domain_id(0)
        .with_transport(TransportMode::IntraProcess)
        .build()
        .unwrap();
    let topic = participant
        .topic::<Value>("tbf-wake-replaced-topic")
        .unwrap();
    let writer = topic
        .writer()
        .qos(QoS::reliable().keep_last(8))
        .build()
        .unwrap();
    let reader = topic
        .reader()
        .qos(
            QoS::reliable()
                .keep_last(8)
                .time_based_filter_millis(SEPARATION),
        )
        .build()
        .unwrap();
    let condition = reader.get_status_condition();
    condition.set_enabled_statuses(StatusMask::DATA_AVAILABLE);
    let waitset = WaitSet::new();
    waitset
        .attach_condition(Arc::clone(&condition) as Arc<dyn Condition>)
        .unwrap();

    // The writer's own clock, in ms from an arbitrary origin.
    let origin = 5_000_000_000_000u64;
    let produced = |ms: u64| origin + ms * 1_000_000;
    let start = Instant::now();
    writer
        .write_w_timestamp(&Value { value: 1 }, produced(0))
        .unwrap();
    assert_eq!(
        wait_for_take(&waitset, &reader, Duration::from_secs(2)),
        Some(1)
    );

    // Produced 300 ms after the one shown: a poor pick, due a full
    // separation after the window ends, at about 2000 ms.
    std::thread::sleep(Duration::from_millis(300).saturating_sub(start.elapsed()));
    writer
        .write_w_timestamp(&Value { value: 2 }, produced(300))
        .unwrap();
    assert_eq!(reader.take().unwrap(), None);
    // Produced 960 ms after it: a good pick, due when the window ends, at
    // about 1000 ms, and it replaces the first.
    std::thread::sleep(Duration::from_millis(960).saturating_sub(start.elapsed()));
    writer
        .write_w_timestamp(&Value { value: 3 }, produced(960))
        .unwrap();
    assert_eq!(reader.take().unwrap(), None);

    let second = wait_for_take(&waitset, &reader, Duration::from_secs(3));
    let elapsed = start.elapsed();
    assert_eq!(second, Some(3), "the newest is delivered");
    assert!(
        elapsed >= Duration::from_millis(SEPARATION),
        "never before the window ends: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(1250),
        "woken when the replacement is due, not when the replaced one was: {elapsed:?}"
    );
}

/// Wait on `waitset` and take until a sample comes or `limit` passes.
fn wait_for_take(
    waitset: &WaitSet,
    reader: &hdds::DataReader<Value>,
    limit: Duration,
) -> Option<i32> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(sample) = reader.take().unwrap() {
            return Some(sample.value);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || waitset.wait(Some(left)).is_err() {
            return reader.take().unwrap().map(|s| s.value);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TIME_BASED_FILTER at the application boundary (DDS v1.4 Sec.2.2.3.12),
//! through the reader's real receive path: network DATA, ring, pump, cache,
//! `take()`. Time is pinned (`gate::set_test_now`), so every instant is
//! explicit and nothing sleeps.
//!
//! The rules under test:
//! - an instance shows at most one sample per `minimum_separation`, measured
//!   between the instants two samples become visible;
//! - a sample that arrives just before the window ends is not lost: it
//!   becomes visible at the first access at or after the window's end;
//! - the newest sample of a window wins (the filter selects, HISTORY then
//!   applies to what it selected);
//! - a transition of the instance during the wait cancels the parked value;
//! - a sample is never refused once admitted and never starved: the last
//!   sample of a stream is shown whatever the pace of the arrivals.

use super::tests_history_limits::{key1, Keyed, NetworkReader, WRITER, WRITER_B};
use crate::dds::QoS;
use crate::engine::subscriber::DisposeKind;
use crate::engine::Subscriber as _;
use crate::qos::time_based_filter::gate::set_test_now;
use std::time::{Duration, Instant};

const SEP: Duration = Duration::from_secs(1);

/// Pins the filter's clock for the test; releases it on drop.
struct Clock {
    base: Instant,
    micros: std::cell::Cell<u64>,
}

impl Clock {
    fn new() -> Self {
        let base = Instant::now();
        set_test_now(Some(base));
        Self {
            base,
            micros: std::cell::Cell::new(0),
        }
    }

    /// Time stands at `micros` after the start.
    fn at_us(&self, micros: u64) {
        self.micros.set(micros);
        set_test_now(Some(self.base + Duration::from_micros(micros)));
    }

    /// The writer's change `seq`, stamped with the time as it stands (its
    /// source timestamp, as a real writer's INFO_TS carries it).
    fn deliver(&self, net: &NetworkReader<Keyed>, writer: [u8; 16], seq: u64, sample: &Keyed) {
        crate::engine::router::set_route_source_ts_ns(Some(
            1_000_000_000 + self.micros.get() * 1000,
        ));
        net.deliver(writer, seq, sample);
        crate::engine::router::set_route_source_ts_ns(None);
    }

    fn at_ms(&self, ms: u64) {
        self.at_us(ms * 1000);
    }

    /// The writer's change `seq`, stamped `ts_ns` whatever the time is.
    fn deliver_stamped(
        &self,
        net: &NetworkReader<Keyed>,
        writer: [u8; 16],
        seq: u64,
        sample: &Keyed,
        ts_ns: u64,
    ) {
        crate::engine::router::set_route_source_ts_ns(Some(ts_ns));
        net.deliver(writer, seq, sample);
        crate::engine::router::set_route_source_ts_ns(None);
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        set_test_now(None);
    }
}

fn filtered(topic: &str, qos: QoS) -> NetworkReader<Keyed> {
    NetworkReader::<Keyed>::new(
        topic,
        qos.time_based_filter(crate::dds::qos::TimeBasedFilter::new(SEP)),
    )
}

fn sample(value: i32) -> Keyed {
    Keyed { id: 1, value }
}

fn take_value(net: &NetworkReader<Keyed>) -> Option<i32> {
    net.reader.take().expect("take").map(|k| k.value)
}

/// The failure the OMG TIME_BASED_FILTER test provoked: a sample 0.3 ms
/// before the end of the previous one's window. It is not shown early, and
/// not lost: it is the first thing visible when the window ends.
///
/// Mutant: dropping a sample that finds the window closed (instead of
/// parking it) in `Gate::offer` leaves nothing at 1000 ms.
#[test]
fn a_sample_a_hair_before_the_window_ends_is_shown_when_it_ends() {
    let clock = Clock::new();
    let net = filtered("tbf-hair", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));

    clock.at_us(999_700);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None, "not visible before the window ends");

    clock.at_us(999_999);
    assert_eq!(
        take_value(&net),
        None,
        "one microsecond early is still early"
    );

    clock.at_ms(1000);
    assert_eq!(take_value(&net), Some(2));
    assert_eq!(take_value(&net), None);
}

/// Separation is between the instants samples become visible: a sample
/// shown late (the application only polled at 1050 ms) opens its window
/// there, and the next one is not visible 1000 ms after its arrival but
/// 1000 ms after it was shown.
///
/// Mutant: `Gate::due` not recording the instant it shows a parked sample
/// shows 3 at 1100 ms.
#[test]
fn the_window_runs_from_the_instant_a_sample_became_visible() {
    let clock = Clock::new();
    let net = filtered("tbf-visible", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    clock.at_ms(50);
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(1000);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None, "950 ms after it was shown");
    clock.at_ms(1049);
    assert_eq!(take_value(&net), None);
    clock.at_ms(1050);
    assert_eq!(take_value(&net), Some(2));
    // And 2 closed a window of its own, from the instant it was shown.
    clock.at_ms(1990);
    clock.deliver(&net, WRITER, 3, &sample(3));
    assert_eq!(take_value(&net), None);
    clock.at_ms(2049);
    assert_eq!(take_value(&net), None);
    clock.at_ms(2050);
    assert_eq!(take_value(&net), Some(3));
}

/// A parked sample is due, nobody accessed the reader, and a newer sample
/// arrives: the parked one is the one shown, the newer one waits a full
/// separation. Order and spacing hold whatever the timing of the accesses.
///
/// Mutant: showing the offered sample and leaving the parked one in place
/// (in `Gate::offer`, the open-window branch) shows 3 first and 2 after it.
#[test]
fn a_due_parked_sample_is_never_overtaken_by_a_newer_arrival() {
    let clock = Clock::new();
    let net = filtered("tbf-order", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(999);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None);

    // The window ended at 1000 ms and nobody looked; 3 arrives at 1001.
    // The writer produced it a separation after 2: a good pick.
    clock.at_ms(1001);
    clock.deliver_stamped(&net, WRITER, 3, &sample(3), 3_000_000_000);
    assert_eq!(take_value(&net), Some(2), "the older sample first");
    assert_eq!(take_value(&net), None, "3 waits a full separation");
    clock.at_ms(2000);
    assert_eq!(take_value(&net), None);
    clock.at_ms(2001);
    assert_eq!(take_value(&net), Some(3));
}

/// Several samples in one window: the newest is the one shown, the
/// others are never visible ("in steady state ... the system should
/// guarantee delivery [of] the last sample").
///
/// Mutant: keeping the oldest parked sample (`replace` -> keep) shows 2.
#[test]
fn the_newest_sample_of_a_window_is_the_one_shown() {
    let clock = Clock::new();
    let net = filtered("tbf-newest", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(300);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None);
    clock.at_ms(999);
    clock.deliver(&net, WRITER, 3, &sample(3));
    assert_eq!(take_value(&net), None);
    clock.at_ms(1000);
    assert_eq!(take_value(&net), Some(3));
    assert_eq!(take_value(&net), None);
}

/// KEEP_ALL keeps every sample the filter selected, until it is taken
/// (HISTORY applies after the filter); the samples the filter did not
/// select are not queued behind them.
#[test]
fn keep_all_keeps_what_the_filter_selected_and_nothing_else() {
    let clock = Clock::new();
    let net = filtered("tbf-keep-all", QoS::reliable().keep_all());
    let poll = |net: &NetworkReader<Keyed>| {
        let _ = net.reader.read_batch(usize::MAX).expect("read");
    };
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    poll(&net);
    clock.at_ms(500);
    clock.deliver(&net, WRITER, 2, &sample(2));
    poll(&net);
    clock.at_ms(980);
    clock.deliver(&net, WRITER, 3, &sample(3));
    poll(&net);
    assert_eq!(net.reader.cache().len(), 1, "2 and 3 wait for the window");
    clock.at_ms(1000);
    poll(&net);
    assert_eq!(net.reader.cache().len(), 2, "3 superseded 2");
    clock.at_ms(1950);
    clock.deliver(&net, WRITER, 4, &sample(4));
    poll(&net);
    clock.at_ms(1999);
    poll(&net);
    assert_eq!(net.reader.cache().len(), 2);
    clock.at_ms(2000);
    assert_eq!(
        net.take_all().iter().map(|k| k.value).collect::<Vec<_>>(),
        vec![1, 3, 4]
    );
}

/// A transition of the instance while a value waits cancels it: the
/// application must not see the value after the dispose that followed it,
/// whether the writer that disposed is the writer of the parked value or
/// another one (no revival of an instance disposed after the value arrived).
///
/// Mutant: dropping the `since` comparison in `SampleCache::enter` lets the
/// parked value in after the dispose in both cases.
#[test]
fn a_dispose_during_the_wait_cancels_the_parked_value() {
    for (disposer, dispose_seq) in [(WRITER, 3u64), (WRITER_B, 1u64)] {
        let clock = Clock::new();
        let net = filtered("tbf-dispose", QoS::reliable().keep_last(8));
        clock.at_ms(0);
        clock.deliver(&net, WRITER, 1, &sample(1));
        assert_eq!(take_value(&net), Some(1));
        clock.at_ms(600);
        clock.deliver(&net, WRITER, 2, &sample(2));
        assert_eq!(take_value(&net), None, "parked");
        clock.at_ms(700);
        net.subscriber.on_dispose_from_writer(
            &net.topic,
            disposer,
            dispose_seq,
            key1(),
            DisposeKind::Disposed,
        );

        clock.at_ms(1000);
        let mut seen = Vec::new();
        while let Some((data, info)) = net.reader.take_with_info().expect("take_with_info") {
            seen.push((data.map(|k| k.value), info.instance_state));
        }
        assert_eq!(
            seen.len(),
            1,
            "only the dispose, never the value after it: {seen:?}"
        );
        assert_eq!(seen[0].0, None, "{seen:?}");
        assert_eq!(
            net.reader
                .cache()
                .instances()
                .state_of(super::InstanceHandle::new(key1())),
            super::cache::InstanceState::NotAliveDisposed
        );
    }
}

/// A coherent set whose members are on instances with open windows is
/// delivered whole, and nothing is reported lost.
#[test]
fn a_coherent_set_on_open_windows_is_delivered_whole() {
    let clock = Clock::new();
    let qos = QoS::reliable()
        .keep_last(8)
        .time_based_filter(crate::dds::qos::TimeBasedFilter::new(SEP));
    let net = NetworkReader::<Keyed>::with_parts(
        "tbf-coherent",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig::default(),
    );
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &Keyed { id: 1, value: 10 });
    clock.deliver(&net, WRITER, 2, &Keyed { id: 2, value: 20 });
    let mut seen = net.take_all().iter().map(|k| k.value).collect::<Vec<_>>();
    seen.sort_unstable();
    assert_eq!(seen, vec![10, 20]);
    assert_eq!(net.lost(), 0);
}

/// Each instance has its own window.
#[test]
fn instances_filter_independently() {
    let clock = Clock::new();
    let net = filtered("tbf-instances", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &Keyed { id: 1, value: 1 });
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(10);
    clock.deliver(&net, WRITER, 2, &Keyed { id: 2, value: 2 });
    assert_eq!(take_value(&net), Some(2), "instance 2 has not shown yet");
    clock.at_ms(990);
    clock.deliver(&net, WRITER, 3, &Keyed { id: 1, value: 3 });
    assert_eq!(take_value(&net), None);
    clock.at_ms(1000);
    assert_eq!(take_value(&net), Some(3));
}

/// RESOURCE_LIMITS max_samples = 1 with KEEP_LAST(1): a newer sample of the
/// window replaces the parked one, it is not refused for want of the place
/// the parked one would have held, and nothing is reported rejected.
#[test]
fn a_full_resource_limit_does_not_pin_the_older_parked_sample() {
    let clock = Clock::new();
    let mut qos = QoS::best_effort().keep_last(1);
    qos.resource_limits.max_samples = 1;
    let net = filtered("tbf-limits", qos);
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(300);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None);
    clock.at_ms(980);
    clock.deliver(&net, WRITER, 3, &sample(3));
    assert_eq!(take_value(&net), None);
    assert_eq!(net.rejected().total_count, 0);
    clock.at_ms(1000);
    assert_eq!(take_value(&net), Some(3), "the newest, not the pinned one");
}

/// The places a KEEP_ALL history granted to samples still parked go back
/// when the reader goes away.
#[test]
fn dropping_a_reader_gives_back_the_places_of_its_parked_samples() {
    let clock = Clock::new();
    let mut qos = QoS::reliable().keep_all();
    qos.resource_limits.max_samples = 4;
    let net = filtered("tbf-drop", qos);
    let room = std::sync::Arc::clone(net.reader.network_room_for_test().expect("room"));
    let free_at_rest = room.free();
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(600);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None, "parked");
    assert_eq!(net.reader.cache().parked_count(), 1);
    let net_subscriber = std::sync::Arc::clone(&net.subscriber);
    drop(net);
    drop(net_subscriber);
    assert_eq!(room.free(), free_at_rest, "every place came back");
}

/// A transition recorded before a sample is pumped, sent after it by the
/// same writer: the sample cannot wait and then show after it.
#[test]
fn a_sample_pumped_after_its_writers_dispose_is_not_parked_behind_it() {
    let clock = Clock::new();
    let net = filtered("tbf-pumped-after", QoS::reliable().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(600);
    clock.deliver(&net, WRITER, 2, &sample(2));
    // No access yet: 2 is still in the receive queue when the dispose lands.
    net.subscriber
        .on_dispose_from_writer(&net.topic, WRITER, 3, key1(), DisposeKind::Disposed);
    clock.at_ms(700);
    let mut seen = Vec::new();
    while let Some((data, _)) = net.reader.take_with_info().expect("take_with_info") {
        seen.push(data.map(|k| k.value));
    }
    assert_eq!(seen, vec![None], "the dispose alone: {seen:?}");
    // And the value is not waiting behind it for its window to end.
    clock.at_ms(1000);
    assert_eq!(take_value(&net), None);
}

/// A sample the reader admitted is never refused for a queue it shares with
/// other instances: the newest value of an instance reaches the cache and
/// replaces the parked one, whatever else waits in the receive queue, and
/// the application sees it when the window ends.
///
/// Mutant: refusing an arrival when the whole queue holds 64 entries or
/// more (the reader-wide bound) loses 2 and reports SAMPLE_REJECTED.
#[test]
fn the_last_value_of_an_instance_is_not_refused_behind_a_deep_queue() {
    let clock = Clock::new();
    let net = filtered("tbf-deep-queue", QoS::reliable().keep_last(8));
    clock.at_ms(0);
    for seq in 1..=70u64 {
        clock.deliver(&net, WRITER, seq, &Keyed { id: 2, value: 100 });
    }
    clock.deliver(&net, WRITER, 71, &Keyed { id: 1, value: 1 });
    clock.at_ms(200);
    // Produced a second after the first one: a good pick.
    clock.deliver_stamped(&net, WRITER, 72, &Keyed { id: 1, value: 2 }, 2_000_000_000);
    assert_eq!(net.rejected().total_count, 0);

    clock.at_ms(1000);
    let first = net.take_all().iter().map(|k| k.value).collect::<Vec<_>>();
    assert!(first.contains(&1), "{first:?}");
    assert!(!first.contains(&2), "2 waits for its window: {first:?}");
    clock.at_ms(2000);
    assert_eq!(
        net.take_all()
            .iter()
            .filter(|k| k.id == 1)
            .map(|k| k.value)
            .collect::<Vec<_>>(),
        vec![2]
    );
}

/// A writer that keeps sending within the window, with a clock that does
/// not advance, never offers a good pick: the application still sees a
/// sample a full separation after the window ended, the newest then, and
/// the next window follows the same rule. The wait is counted from the
/// window, so the arrivals do not restart it.
///
/// Mutant: `Gate::waited_out` never true (or restarted by each arrival)
/// shows nothing until the stream stops.
#[test]
fn a_stream_that_keeps_arriving_is_not_starved() {
    let clock = Clock::new();
    let net = filtered("tbf-starve", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver_stamped(&net, WRITER, 1, &sample(0), 5_000_000_000);
    assert_eq!(take_value(&net), Some(0));
    let mut shown = Vec::new();
    for k in 1..=42u64 {
        clock.at_ms(100 * k);
        clock.deliver_stamped(&net, WRITER, 1 + k, &sample(k as i32), 5_000_000_000);
        if let Some(value) = take_value(&net) {
            shown.push((100 * k, value));
        }
    }
    assert_eq!(
        shown,
        vec![(2000, 19), (4000, 39)],
        "the newest parked, a separation after the window ended"
    );
}

/// A sample without a source timestamp carries only its reception time,
/// which says nothing of the writer's clock: it is not judged by it, and is
/// shown when the window ends.
///
/// Mutant: building the stamp from the timestamp whatever its origin parks
/// 2 until a full separation after the window ended (2000 ms).
#[test]
fn a_sample_without_a_source_timestamp_is_shown_when_the_window_ends() {
    let clock = Clock::new();
    let net = filtered("tbf-no-ts", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    net.deliver(WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(300);
    net.deliver(WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None);
    clock.at_ms(1000);
    assert_eq!(take_value(&net), Some(2));
}

/// A cache that cannot let a sample wait (ordered access) shows what finds
/// the window open and drops what finds it closed, as the strict rule does.
///
/// Mutant: `park` ignored in `SampleCache::stage` parks the second sample.
#[test]
fn a_cache_that_cannot_park_drops_what_must_wait() {
    use super::cache::{CachedSample, SampleCache};
    let clock = Clock::new();
    let cache = SampleCache::<i32>::new(8).with_time_based_filter(
        crate::dds::qos::TimeBasedFilter::new(SEP),
        false,
        None,
        None,
    );
    clock.at_ms(0);
    cache.push(CachedSample::new(1, 1, 0));
    clock.at_ms(500);
    cache.push(CachedSample::new(2, 2, 0));
    assert_eq!(cache.parked_count(), 0);
    clock.at_ms(1000);
    assert_eq!(cache.take(), Some(1));
    assert_eq!(cache.take(), None);
}

#[derive(Default)]
struct Probe {
    payloads: std::sync::atomic::AtomicUsize,
    notifications: std::sync::atomic::AtomicUsize,
}

impl crate::dds::listener::DataReaderListener<Keyed> for Probe {
    fn on_data_available(&self, _sample: &Keyed) {
        self.payloads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn on_data_available_notification(&self) {
        self.notifications
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A listener never receives a sample the filter may park or supersede: the
/// arrival is announced without a payload, and the sample is obtained by
/// `take`.
///
/// Mutant: ignoring the filter in `process_admitted`'s `notification_only`
/// hands the payload to `on_data_available`.
#[test]
fn a_filtered_reader_announces_arrivals_without_a_payload() {
    use std::sync::atomic::Ordering;
    let clock = Clock::new();
    let net = filtered("tbf-listener", QoS::best_effort().keep_last(8));
    let probe = std::sync::Arc::new(Probe::default());
    net.subscriber.listener.set(
        Some(probe.clone() as std::sync::Arc<dyn crate::dds::listener::DataReaderListener<Keyed>>),
        crate::dds::StatusMask::DATA_AVAILABLE,
    );
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    clock.at_ms(300);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(probe.payloads.load(Ordering::SeqCst), 0);
    assert_eq!(probe.notifications.load(Ordering::SeqCst), 2);
}

/// The instance came back to life while a value waited (dispose, then a
/// newer sample): the waiting value is from the generation before and is
/// not shown after the dispose that ended it.
///
/// Mutant: dropping the generation-counts comparison in `SampleCache::enter`
/// shows 2 at 1100 ms.
#[test]
fn a_value_from_before_a_dispose_and_a_revival_is_not_shown() {
    let clock = Clock::new();
    let net = filtered("tbf-revival", QoS::reliable().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(300);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None, "parked");
    clock.at_ms(400);
    net.subscriber
        .on_dispose_from_writer(&net.topic, WRITER, 3, key1(), DisposeKind::Disposed);
    let (data, _) = net.reader.take_with_info().expect("take").expect("dispose");
    assert!(data.is_none());
    clock.at_ms(500);
    clock.deliver(&net, WRITER, 4, &sample(4));
    clock.at_ms(1100);
    let mut seen = Vec::new();
    while let Some((data, _)) = net.reader.take_with_info().expect("take") {
        seen.push(data.map(|k| k.value));
    }
    assert!(
        !seen.contains(&Some(2)),
        "the stale value surfaced: {seen:?}"
    );
}

/// A writer faster than the separation: the newest sample at the window's
/// end is not always a good pick. One produced less than a separation (less
/// a 5 percent jitter allowance) after the one shown, by the writer's own
/// clock, waits for a newer one, so the application sees samples a
/// separation apart in the writer's time as well, not only in its own.
///
/// Mutant: `Gate::picked` always true shows 7 at 1000 ms.
#[test]
fn a_sample_produced_too_soon_after_the_shown_one_waits_for_a_newer() {
    let clock = Clock::new();
    let net = filtered("tbf-pick", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(0));
    assert_eq!(take_value(&net), Some(0));
    for k in 1..=7u64 {
        clock.at_ms(125 * k);
        clock.deliver(&net, WRITER, 1 + k, &sample(k as i32));
        assert_eq!(take_value(&net), None, "sample {k}");
    }
    clock.at_ms(1000);
    clock.deliver(&net, WRITER, 9, &sample(8));
    // 7 was produced at 875 ms, 8 at 1000 ms: 8 is the pick.
    clock.at_ms(1100);
    assert_eq!(take_value(&net), Some(8));
}

/// A sample that is not a good pick is still shown, a full separation after
/// the window ended with nothing newer: the last sample of a stream is not
/// lost ("in steady state ... the system should guarantee delivery [of] the
/// last sample").
///
/// Mutant: dropping the wait clause in `Gate::parked_due` never shows it.
#[test]
fn a_sample_that_is_not_a_good_pick_is_shown_once_it_has_waited() {
    let clock = Clock::new();
    let net = filtered("tbf-last", QoS::best_effort().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(300);
    clock.deliver(&net, WRITER, 2, &sample(2));
    assert_eq!(take_value(&net), None);
    clock.at_ms(1000);
    assert_eq!(
        take_value(&net),
        None,
        "the window is open, 2 is a poor pick"
    );
    clock.at_ms(1999);
    assert_eq!(take_value(&net), None);
    clock.at_ms(2000);
    assert_eq!(take_value(&net), Some(2));
}

/// What a cache told its waker: `(instance, instant)` of each wake.
type Wakes = std::sync::Arc<std::sync::Mutex<Vec<(super::InstanceHandle, Instant)>>>;

fn waking_cache(park: bool) -> (super::cache::SampleCache<i32>, Wakes) {
    let wakes: Wakes = Wakes::default();
    let seen = std::sync::Arc::clone(&wakes);
    let cache = super::cache::SampleCache::<i32>::new(8).with_time_based_filter(
        crate::dds::qos::TimeBasedFilter::new(SEP),
        park,
        Some(std::sync::Arc::new(move |handle, at| {
            seen.lock().expect("wakes").push((handle, at));
        })),
        None,
    );
    (cache, wakes)
}

/// A sample produced `ms` after the epoch of the writer's clock.
fn produced(value: i32, ms: u64) -> super::cache::CachedSample<i32> {
    super::cache::CachedSample::with_meta(
        value,
        value as u64,
        1_000_000_000 + ms * 1_000_000,
        super::InstanceHandle::nil(),
        Some(WRITER),
        true,
    )
}

/// The application waiting on the window of a parked sample is woken for the
/// instant the sample is due. A newer sample that replaces it can be due at
/// another instant (a good pick when the window ends, a poor one a full
/// separation after it): the wake follows.
///
/// Mutant: telling the waker only when a sample is parked into an empty
/// slot leaves 1000 ms unannounced.
#[test]
fn a_replacement_that_moves_the_due_instant_wakes_for_the_new_one() {
    let clock = Clock::new();
    let (cache, wakes) = waking_cache(true);
    let at = |ms: u64| clock.base + Duration::from_millis(ms);
    clock.at_ms(0);
    cache.push(produced(1, 0));
    assert_eq!(cache.take(), Some(1));

    // Produced 100 ms after the one shown: a poor pick, due at 2000.
    clock.at_ms(100);
    cache.push(produced(2, 100));
    // Produced 990 ms after it: a good pick, due when the window ends.
    clock.at_ms(990);
    cache.push(produced(3, 990));
    // Another good pick: still due at 1000, already told.
    clock.at_ms(995);
    cache.push(produced(4, 995));

    let told: Vec<Instant> = wakes.lock().expect("wakes").iter().map(|w| w.1).collect();
    assert_eq!(told, vec![at(2000), at(1000)]);
    clock.at_ms(1000);
    assert_eq!(cache.take(), Some(4));
}

/// A cache that cannot let a sample wait (ordered or coherent access) keeps
/// the strict rule: a sample that finds the window open is shown, whether or
/// not it is a good pick (produced too soon after the one shown by its
/// writer's clock). Dropping it would show fewer samples than one per
/// separation.
///
/// Mutant: `SampleCache::stage` using `Gate::shows_at_once` for a cache that
/// cannot park drops 2.
#[test]
fn a_cache_that_cannot_park_shows_a_poor_pick_that_finds_the_window_open() {
    let clock = Clock::new();
    let (cache, wakes) = waking_cache(false);
    clock.at_ms(0);
    cache.push(produced(1, 0));
    assert_eq!(cache.take(), Some(1));
    clock.at_ms(1000);
    cache.push(produced(2, 100));
    assert_eq!(cache.parked_count(), 0);
    assert!(wakes.lock().expect("wakes").is_empty());
    assert_eq!(cache.take(), Some(2));
}

/// A reader that cannot let a sample wait, fed by a writer whose clock does
/// not keep up (every sample a poor pick), shows one sample per separation
/// as the strict rule does, and not one in a stream.
///
/// Mutant: `SampleCache::stage` refusing a poor pick for a cache that cannot
/// park shows only 0.
#[test]
fn an_ordered_or_coherent_reader_shows_one_sample_per_separation_whatever_the_stamps() {
    for ordered in [true, false] {
        let clock = Clock::new();
        let qos = if ordered {
            QoS::best_effort().keep_last(8).presentation_topic_ordered()
        } else {
            QoS::best_effort()
                .keep_last(8)
                .presentation_topic_coherent()
        }
        .time_based_filter(crate::dds::qos::TimeBasedFilter::new(SEP));
        let net = NetworkReader::<Keyed>::with_parts(
            "tbf-no-park-stream",
            qos,
            super::reorder::ReorderGate::new_best_effort(),
            crate::qos::ownership::OwnershipKind::Shared,
            super::subscriber::CoherentConfig {
                coherent_access: !ordered,
                is_group_scope: false,
            },
        );
        let mut shown = Vec::new();
        for k in 0..6u64 {
            clock.at_ms(1000 * k);
            // The writer's clock advances 100 ms for each separation.
            let ts = 1_000_000_000 + 100_000_000 * k;
            let seq = 1 + 2 * k;
            crate::engine::router::set_route_source_ts_ns(Some(ts));
            if ordered {
                net.deliver(WRITER, seq, &sample(k as i32));
            } else {
                net.deliver_coherent(WRITER, seq, seq, &sample(k as i32));
                net.subscriber
                    .on_ecs(&net.topic, WRITER, seq + 1, seq, None, None);
            }
            crate::engine::router::set_route_source_ts_ns(None);
            shown.extend(net.take_all().iter().map(|s| s.value));
        }
        assert_eq!(shown, vec![0, 1, 2, 3, 4, 5], "ordered access: {ordered}");
    }
}

/// A member of a coherent set whose instance window is closed is not parked
/// and shown later, apart from its set: a reader presenting coherent sets
/// shows what finds its window open and drops what finds it closed.
///
/// Mutant: parking set members like any other sample shows 12 at 1000 ms.
#[test]
fn a_coherent_reader_never_shows_a_member_outside_its_set() {
    let clock = Clock::new();
    let qos = QoS::best_effort()
        .keep_last(8)
        .presentation_topic_coherent()
        .time_based_filter(crate::dds::qos::TimeBasedFilter::new(SEP));
    let net = NetworkReader::<Keyed>::with_parts(
        "tbf-coherent-closed",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let member = |seq: u64, start: u64, id: i32, value: i32| {
        crate::engine::router::set_route_source_ts_ns(Some(1_000_000_000 + seq));
        net.deliver_coherent(WRITER, seq, start, &Keyed { id, value });
        crate::engine::router::set_route_source_ts_ns(None);
    };
    let values = |net: &NetworkReader<Keyed>| {
        let mut v: Vec<i32> = net.take_all().iter().map(|k| k.value).collect();
        v.sort_unstable();
        v
    };
    clock.at_ms(0);
    member(1, 1, 1, 11);
    net.subscriber.on_ecs(&net.topic, WRITER, 2, 1, None, None);
    assert_eq!(values(&net), vec![11]);

    // A set of instance 1 (window closed) and instance 2 (open).
    clock.at_ms(300);
    member(3, 3, 1, 12);
    member(4, 3, 2, 21);
    net.subscriber.on_ecs(&net.topic, WRITER, 5, 4, None, None);
    assert_eq!(values(&net), vec![21], "the member whose window is open");
    clock.at_ms(1000);
    assert_eq!(values(&net), Vec::<i32>::new(), "12 is not shown later");
    clock.at_ms(3000);
    assert_eq!(values(&net), Vec::<i32>::new());
}

/// Two writes of one instance in one coherent set: the reader presents the
/// first and drops the second, which finds the window the first closed, as
/// the strict arrival rule always did; the second is not shown late, apart
/// from its set.
///
/// Mutant: parking set members (a coherent cache that can park) shows 12 at
/// 1000 ms.
#[test]
fn a_second_write_of_an_instance_in_a_coherent_set_is_dropped_not_shown_late() {
    let clock = Clock::new();
    let qos = QoS::best_effort()
        .keep_last(8)
        .presentation_topic_coherent()
        .time_based_filter(crate::dds::qos::TimeBasedFilter::new(SEP));
    let net = NetworkReader::<Keyed>::with_parts(
        "tbf-coherent-twice",
        qos,
        super::reorder::ReorderGate::new_best_effort(),
        crate::qos::ownership::OwnershipKind::Shared,
        super::subscriber::CoherentConfig {
            coherent_access: true,
            is_group_scope: false,
        },
    );
    let values =
        |net: &NetworkReader<Keyed>| net.take_all().iter().map(|k| k.value).collect::<Vec<i32>>();
    clock.at_ms(0);
    for (seq, value) in [(1, 11), (2, 12)] {
        crate::engine::router::set_route_source_ts_ns(Some(1_000_000_000 + seq));
        net.deliver_coherent(WRITER, seq, 1, &sample(value));
        crate::engine::router::set_route_source_ts_ns(None);
    }
    net.subscriber.on_ecs(&net.topic, WRITER, 3, 2, None, None);
    assert_eq!(values(&net), vec![11]);
    clock.at_ms(1000);
    assert_eq!(values(&net), Vec::<i32>::new());
    clock.at_ms(3000);
    assert_eq!(values(&net), Vec::<i32>::new());
}

/// A sample whose lifespan ran out while it waited for its window is not
/// shown (DDS v1.4 Sec.2.2.3.16), and does not close the window of the
/// sample that follows it.
///
/// Mutant: no lifespan test where a parked sample comes out shows 2.
#[test]
fn a_sample_that_expired_while_parked_is_not_shown() {
    let clock = Clock::new();
    let net = filtered(
        "tbf-lifespan",
        QoS::best_effort().keep_last(8).lifespan_millis(200),
    );
    let now_ns = crate::telemetry::metrics::current_time_ns;
    clock.at_ms(0);
    clock.deliver_stamped(&net, WRITER, 1, &sample(1), now_ns());
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(300);
    // The writer's clock is a second on: a good pick, due at 1000 ms.
    clock.deliver_stamped(&net, WRITER, 2, &sample(2), now_ns() + 1_000_000_000);
    assert_eq!(take_value(&net), None, "parked");
    clock.at_ms(1000);
    assert_eq!(take_value(&net), None, "its lifespan ended at 500 ms");
    // The writer's clock is a second on, a good pick.
    clock.deliver_stamped(&net, WRITER, 3, &sample(3), now_ns() + 1_000_000_000);
    assert_eq!(
        take_value(&net),
        Some(3),
        "the expired one closed no window"
    );
}

/// A separation too long to be added to an instant ("never") does not panic
/// the application thread that reads: the first sample is shown, the rest
/// wait for ever.
///
/// Mutant: an unchecked addition of the separation in `Gate::ready_at`
/// panics with an overflow.
#[test]
fn a_separation_of_ever_does_not_panic_the_reader() {
    let clock = Clock::new();
    let qos = QoS::best_effort().keep_last(8);
    let net = NetworkReader::<Keyed>::new(
        "tbf-forever",
        qos.time_based_filter(crate::dds::qos::TimeBasedFilter::new(Duration::MAX)),
    );
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(10);
    clock.deliver(&net, WRITER, 2, &sample(2));
    clock.deliver(&net, WRITER, 3, &sample(3));
    assert_eq!(take_value(&net), None);
    clock.at_ms(3_600_000);
    assert_eq!(take_value(&net), None);
}

/// A parked value made stale by a dispose is dropped without having shown:
/// it closes no window, so the sample that revives the instance once the
/// first window has ended is visible at once.
///
/// Mutant: showing the stale sample, then dropping it, where it comes out
/// (the window closes at that instant) delays 3 to 2000 ms.
#[test]
fn a_value_dropped_as_stale_does_not_close_the_window() {
    let clock = Clock::new();
    let net = filtered("tbf-stale-window", QoS::reliable().keep_last(8));
    clock.at_ms(0);
    clock.deliver(&net, WRITER, 1, &sample(1));
    assert_eq!(take_value(&net), Some(1));
    clock.at_ms(300);
    // Produced 960 ms after the one shown: a good pick, due at 1000 ms.
    clock.deliver_stamped(&net, WRITER, 2, &sample(2), 1_960_000_000);
    assert_eq!(take_value(&net), None, "parked");
    clock.at_ms(400);
    net.subscriber
        .on_dispose_from_writer(&net.topic, WRITER_B, 1, key1(), DisposeKind::Disposed);
    let (dispose, _) = net.reader.take_with_info().expect("take").expect("dispose");
    assert!(dispose.is_none());

    clock.at_ms(1000);
    clock.deliver(&net, WRITER, 3, &sample(3));
    let mut seen = Vec::new();
    while let Some(value) = take_value(&net) {
        seen.push(value);
    }
    assert_eq!(seen, vec![3], "the stale 2 never, and 3 not delayed");
}

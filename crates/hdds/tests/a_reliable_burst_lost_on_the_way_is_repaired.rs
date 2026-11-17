// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A RELIABLE KEEP_ALL writer and a RELIABLE KEEP_ALL reader in two
//! participants, over UDP (shared memory off): a burst that is mostly lost
//! on the way must still reach the reader whole, in order.
//!
//! DDSI-RTPS 2.5 Sec.8.4.7 / Sec.8.4.12: the writer keeps heartbeating and
//! answering ACKNACKs until every change is acknowledged; the reader keeps
//! requesting what it misses. DDS 1.4 Sec.2.2.3.14: in steady state "all
//! samples in the DataWriter history will eventually be delivered".
//!
//! The loss is not left to chance. The reader's listener holds the receive
//! pipeline on the first sample until the whole burst has been written, so
//! the bounded receive ring (`config::RX_RING_SIZE`, 256) overflows and
//! most of the burst is dropped before the reader sees it: every sample
//! past the ring must come back through HEARTBEAT -> ACKNACK -> retransmit.
//!
//! The second test does the same with samples large enough to be sent as
//! DATA_FRAG (over `DEFAULT_MAX_UNFRAGMENTED_SIZE`), so the ring drops
//! single fragments and leaves samples half-assembled.
//!
//! A KEEP_LAST reader is deliberately not used: DDS 1.4 Sec.2.2.3.18.2 lets
//! it replace samples the application has not taken yet, so its count can
//! settle below the burst without anything being stuck (it could be misread
//! as a stall with `QoS::reliable()`, whose reader depth is 100).

use hdds::dds::DataReaderListener;
use hdds::{DataWriter, DdsTrait, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(hdds::DDS, Debug, Clone)]
struct Probe {
    value: i64,
}

/// Over the 8 KiB unfragmented limit once serialized: sent as DATA_FRAG.
#[derive(hdds::DDS, Debug, Clone)]
struct Big {
    value: i64,
    body: Vec<u8>,
}

const BIG_BODY: usize = 20_000;

fn big(value: i64) -> Big {
    Big {
        value,
        body: vec![(value & 0xFF) as u8; BIG_BODY],
    }
}

/// Holds the receive pipeline on the first sample until the burst is out.
#[derive(Default)]
struct HoldFirst {
    held: AtomicBool,
    burst_written: AtomicBool,
}

impl HoldFirst {
    fn hold(&self) {
        if self.held.swap(true, Ordering::SeqCst) {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.burst_written.load(Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        // Let the last datagrams of the burst reach the full ring too.
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl DataReaderListener<Probe> for HoldFirst {
    fn on_data_available(&self, _sample: &Probe) {
        self.hold();
    }
}

impl DataReaderListener<Big> for HoldFirst {
    fn on_data_available(&self, _sample: &Big) {
        self.hold();
    }
}

fn participant(name: &str, domain: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .shm_disable()
        .build()
        .expect("participant")
}

/// Write `samples` values through a held pipeline and return what a
/// KEEP_ALL reader took, in take order.
fn burst_through_a_held_pipeline<T>(
    name: &str,
    samples: i64,
    make: impl Fn(i64) -> T,
    value_of: impl Fn(&T) -> i64,
) -> Vec<i64>
where
    T: DdsTrait + Clone + Send + Sync + 'static,
    HoldFirst: DataReaderListener<T>,
{
    let domain = hdds::test_support::domains::unique_domain();
    let publisher = participant(&format!("{name}_pub"), domain.id());
    let subscriber = participant(&format!("{name}_sub"), domain.id());

    let hold = Arc::new(HoldFirst::default());
    let reader = subscriber
        .topic::<T>(name)
        .expect("topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .with_listener(Arc::clone(&hold) as Arc<dyn DataReaderListener<T>>)
        .build()
        .expect("reader");
    let writer: DataWriter<T> = publisher
        .topic::<T>(name)
        .expect("topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");

    let deadline = Instant::now() + Duration::from_secs(10);
    while writer.matched_reader_count() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        writer.matched_reader_count(),
        1,
        "fixture: the writer must match the reader"
    );

    for value in 0..samples {
        writer.write(&make(value)).expect("write");
    }
    hold.burst_written.store(true, Ordering::SeqCst);

    let mut got: Vec<i64> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while (got.len() as i64) < samples && Instant::now() < deadline {
        while let Some(sample) = reader.take().expect("take") {
            got.push(value_of(&sample));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        hold.held.load(Ordering::SeqCst),
        "fixture: the receive pipeline must have been held, or nothing was lost"
    );
    got
}

#[test]
fn a_reliable_burst_lost_on_the_way_is_repaired() {
    const SAMPLES: i64 = 3000;
    let got = burst_through_a_held_pipeline(
        "a_reliable_burst_lost_on_the_way_is_repaired",
        SAMPLES,
        |value| Probe { value },
        |sample| sample.value,
    );
    assert_eq!(
        got.len() as i64,
        SAMPLES,
        "a reliable KEEP_ALL reader must get the whole burst back; it stopped at {} \
         (last {:?})",
        got.len(),
        got.last()
    );
    assert!(
        got.iter().copied().eq(0..SAMPLES),
        "every sample exactly once and in order"
    );
}

#[test]
fn a_fragmented_reliable_burst_lost_on_the_way_is_repaired() {
    const SAMPLES: i64 = 300;
    let got = burst_through_a_held_pipeline(
        "a_fragmented_reliable_burst_lost_on_the_way_is_repaired",
        SAMPLES,
        big,
        |sample: &Big| {
            assert_eq!(sample.body.len(), BIG_BODY, "a whole sample, reassembled");
            assert!(
                sample
                    .body
                    .iter()
                    .all(|b| *b == (sample.value & 0xFF) as u8),
                "sample {} reassembled from fragments of another",
                sample.value
            );
            sample.value
        },
    );
    assert_eq!(
        got.len() as i64,
        SAMPLES,
        "a reliable KEEP_ALL reader must get every fragmented sample back; it stopped \
         at {} (last {:?})",
        got.len(),
        got.last()
    );
    assert!(
        got.iter().copied().eq(0..SAMPLES),
        "every sample exactly once and in order"
    );
}

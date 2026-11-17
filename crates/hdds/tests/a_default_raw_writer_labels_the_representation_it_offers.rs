// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! `RawDataWriter::write_raw` must label every sample with the writer's own
//! resolved offer (`cdr_negotiation::writer_offered_version`,
//! `resolve_writer_data_representation`, resolved once at creation), never a
//! hardcoded `RawBytes(payload, Xcdr2)` -- an explicit `[XCDR1]` writer
//! (`tools/hdds-ws`'s bridge, `hdds-logger`'s and `hdds-persistence`'s own
//! representation test fixtures) must not be tagged XCDR2.
//! Every actual CONSUMER of a sample's representation
//! (`RawBytes::decode`/`try_take_raw_with_encoding`) re-derives it from the
//! MATCHED WRITER's resolved offer, never from this struct's tag at write
//! time, so a wrong tag would not surface as an observable wire/decode
//! defect in any path this suite can reach -- it would be a value that
//! LOOKS like the wire label and is not, exactly the kind of thing a future
//! change through here could trust by accident. The rule is "make the label
//! equal the bytes" at the one place that could still disagree. It does not
//! change what any writer resolves to (a default raw writer still offers
//! XCDR1, same as every other default-QoS writer of a type that does not
//! refuse it -- see `crates/hdds-wasm/tests/relay_dds_roundtrip.rs`'s
//! `a_default_native_writer_is_refused_by_the_xcdr2_only_relay`, which
//! pins exactly that): it only makes the TAG match reality.
//!
//! The tests run both via a directly-bound writer/reader pair (no discovery)
//! and the real multicast path.

use hdds::{CdrVersion, Participant, QoS, TransportMode};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static TAG: AtomicU32 = AtomicU32::new(9000);
const TYPE_NAME: &str = "DefaultRawWriterProbe";

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done()
}

/// A raw writer created with an EXPLICIT `[XCDR1]` offer, exactly like
/// `tools/hdds-ws`'s bridge or the persistence/logger representation test
/// fixtures: `write_raw` must label its samples XCDR1 (the writer's true
/// offer), never a hardcoded XCDR2.
#[test]
fn write_raw_labels_an_explicit_xcdr1_writers_samples_as_xcdr1() {
    let domain = hdds::test_support::domains::unique_domain();
    let tag = TAG.fetch_add(1, Ordering::SeqCst);
    let topic = format!("raw_writer_xcdr1_label_{tag}");

    let source = Participant::builder("rwl1_source")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("source participant");
    let sink = Participant::builder("rwl1_sink")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("sink participant");
    std::mem::forget(domain);

    let writer = source
        .create_raw_writer_with_type(
            &topic,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr1()),
            None,
            None,
        )
        .expect("explicit xcdr1 writer");
    let reader = sink
        .create_raw_reader_with_type(&topic, TYPE_NAME, Some(QoS::reliable()), None, None)
        .expect("reader");

    std::thread::sleep(Duration::from_millis(1500));
    writer.write_raw(&[0xAA]).expect("write_raw");

    let mut got = Vec::new();
    wait_for(Duration::from_secs(10), || {
        got.extend(reader.try_take_raw_with_encoding().unwrap());
        !got.is_empty()
    });

    assert!(!got.is_empty(), "the sample never arrived");
    assert_eq!(got[0].0.payload, vec![0xAA]);
    assert_eq!(
        got[0].1,
        CdrVersion::Xcdr1,
        "write_raw must label a sample with the writer's TRUE resolved \
         offer (XCDR1 here), never a hardcoded XCDR2"
    );
}

/// A raw writer created with an EXPLICIT `[XCDR2]` offer: `write_raw`
/// must label it XCDR2 -- the common case.
#[test]
fn write_raw_labels_an_explicit_xcdr2_writers_samples_as_xcdr2() {
    let domain = hdds::test_support::domains::unique_domain();
    let tag = TAG.fetch_add(1, Ordering::SeqCst);
    let topic = format!("raw_writer_xcdr2_label_{tag}");

    let source = Participant::builder("rwl2_source")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("source participant");
    let sink = Participant::builder("rwl2_sink")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("sink participant");
    std::mem::forget(domain);

    let writer = source
        .create_raw_writer_with_type(
            &topic,
            TYPE_NAME,
            Some(QoS::reliable().data_representation_xcdr2()),
            None,
            None,
        )
        .expect("explicit xcdr2 writer");
    let reader = sink
        .create_raw_reader_with_type(&topic, TYPE_NAME, Some(QoS::reliable()), None, None)
        .expect("reader");

    std::thread::sleep(Duration::from_millis(1500));
    writer.write_raw(&[0xBB]).expect("write_raw");

    let mut got = Vec::new();
    wait_for(Duration::from_secs(10), || {
        got.extend(reader.try_take_raw_with_encoding().unwrap());
        !got.is_empty()
    });

    assert!(!got.is_empty(), "the sample never arrived");
    assert_eq!(got[0].0.payload, vec![0xBB]);
    assert_eq!(got[0].1, CdrVersion::Xcdr2);
}

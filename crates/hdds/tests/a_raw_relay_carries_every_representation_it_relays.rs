// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Item 6: a raw relay (a raw reader feeding a raw writer) must forward
//! every sample under the DATA_REPRESENTATION it was actually encoded in,
//! never re-label it. DDS-XTypes v1.3 Sec.7.6.3.1.1: "Writers offer a
//! single representation. A writer will use its offered policy to
//! communicate with its matched readers."
//!
//! Before [`hdds::RawRelayWriter`], a relay built from one plain
//! `create_raw_writer_with_type` with no `DATA_REPRESENTATION` resolved
//! ONE representation at creation (RawBytes encodes XCDR1 natively, so an
//! unset QoS offers XCDR1) and then stamped every forwarded sample with
//! that single representation forever, whatever version the source
//! writer actually used -- `try_take_raw` even throws the per-sample
//! version away before the relay ever sees it. `RawRelayWriter` keeps one
//! real writer per representation it has carried and routes each payload
//! to the one that offers it, so the wire label always matches the bytes.
//!
//! Three cases, one topic graph each (source participant -> relay
//! participant -> sink participant, real UDP, no shortcuts):
//! * an XCDR2 source relayed to a Native default sink;
//! * an XCDR1 source relayed to a Native default sink;
//! * both an XCDR1 and an XCDR2 source writer on the SAME topic, relayed
//!   through the SAME `RawRelayWriter` -- the one combination no single
//!   fixed-QoS raw writer could ever carry correctly, because a plain
//!   writer resolves and freezes one representation at creation.
//!
//! The sink is a typed `Native` reader with DEFAULT QoS (no
//! `DATA_REPRESENTATION` set): its `decode()` records the version the wire
//! encapsulation header actually named, so the assertions check the wire
//! label, not only the decoded value.

use hdds::api::DDS;
use hdds::core::types::TypeDescriptor;
use hdds::test_support::domains::unique_domain;
use hdds::{CdrVersion, Participant, QoS, RawRelayWriter, TransportMode};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// `{ u32 tag; f64 value }`, encoded at the alignment each CDR version
/// actually uses for the trailing f64 (XCDR1 aligns 8-byte primitives at
/// 8, XCDR2 at 4 -- DDS-XTypes v1.3 Table 37).
static DESC: TypeDescriptor = TypeDescriptor {
    type_id: 0x7E22_0001,
    type_name: "RawRelayProbe",
    size_bytes: 16,
    alignment: 8,
    is_variable_size: false,
    fields: &[],
};

fn f_at(version: CdrVersion) -> usize {
    match version {
        CdrVersion::Xcdr1 => 8,
        CdrVersion::Xcdr2 => 4,
    }
}

fn put(buf: &mut [u8], tag: u32, value: f64, version: CdrVersion) -> hdds::api::Result<usize> {
    let at = f_at(version);
    if buf.len() < at + 8 {
        return Err(hdds::api::Error::BufferTooSmall);
    }
    buf[..4].copy_from_slice(&tag.to_le_bytes());
    for b in &mut buf[4..at] {
        *b = 0;
    }
    buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
    Ok(at + 8)
}

fn get(buf: &[u8], version: CdrVersion) -> hdds::api::Result<(u32, f64)> {
    let at = f_at(version);
    if buf.len() < at + 8 {
        return Err(hdds::api::Error::SerializationError);
    }
    let tag = u32::from_le_bytes(buf[..4].try_into().unwrap());
    let value = f64::from_le_bytes(buf[at..at + 8].try_into().unwrap());
    Ok((tag, value))
}

/// Every decode records the (tag, wire version) it was handed, so the
/// sink's own `decode()` -- not the test's bookkeeping -- is the witness
/// for what label reached the wire.
static DECODED: Mutex<Vec<(u32, f64, CdrVersion)>> = Mutex::new(Vec::new());

#[derive(Debug, Clone)]
struct Native {
    tag: u32,
    value: f64,
}

impl DDS for Native {
    fn type_descriptor() -> &'static TypeDescriptor {
        &DESC
    }
    fn encode(&self, buf: &mut [u8], version: CdrVersion) -> hdds::api::Result<usize> {
        put(buf, self.tag, self.value, version)
    }
    fn decode(buf: &[u8], version: CdrVersion) -> hdds::api::Result<Self> {
        let (tag, value) = get(buf, version)?;
        DECODED.lock().unwrap().push((tag, value, version));
        Ok(Self { tag, value })
    }
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

static TAG: AtomicU32 = AtomicU32::new(5000);

fn wait_for(timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    done()
}

fn decoded_for(tag: u32) -> Vec<(f64, CdrVersion)> {
    DECODED
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _)| *t == tag)
        .map(|(_, v, ver)| (*v, *ver))
        .collect()
}

fn participant(name: &str, domain_id: u32) -> Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain_id)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant should build")
}

/// Relay one source representation through a fresh `RawRelayWriter` (no
/// eager hint: this exercises the lazy, first-sample path) to a Native
/// default sink, and return what the sink decoded.
fn relay_one_representation(source_qos: QoS) -> Vec<(f64, CdrVersion)> {
    let domain = unique_domain();
    let tag = TAG.fetch_add(1, Ordering::SeqCst);
    let topic_a = format!("rr1_a_{tag}");
    let topic_b = format!("rr1_b_{tag}");

    let source = participant("rr1_source", domain.id());
    let relay = participant("rr1_relay", domain.id());
    let sink = participant("rr1_sink", domain.id());
    std::mem::forget(domain);

    let writer = source
        .topic::<Native>(&topic_a)
        .unwrap()
        .writer()
        .qos(source_qos)
        .build()
        .unwrap();

    let raw_reader = relay
        .create_raw_reader_with_type(&topic_a, DESC.type_name, Some(QoS::reliable()), None, None)
        .unwrap();
    let relay_writer = RawRelayWriter::new(
        Arc::clone(&relay),
        &topic_b,
        DESC.type_name,
        Some(QoS::reliable()),
        None,
        None,
    )
    .unwrap();

    let sink_reader = sink
        .topic::<Native>(&topic_b)
        .unwrap()
        .reader()
        .qos(QoS::reliable())
        .build()
        .unwrap();

    std::thread::sleep(Duration::from_millis(1500));

    let value = 10.0 + f64::from(tag);
    writer.write(&Native { tag, value }).unwrap();

    let mut got = Vec::new();
    let _ = wait_for(Duration::from_secs(5), || {
        for (sample, version) in raw_reader.try_take_raw_with_encoding().unwrap() {
            relay_writer.relay_write(&sample.payload, version).unwrap();
        }
        while let Ok(Some(sample)) = sink_reader.take() {
            got.push(sample.value);
        }
        !got.is_empty()
    });

    decoded_for(tag)
        .into_iter()
        .filter(|(v, _)| got.contains(v))
        .collect()
}

#[test]
fn an_xcdr2_source_relays_to_a_native_sink_labelled_xcdr2() {
    let decoded = relay_one_representation(QoS::reliable().data_representation_xcdr2());
    assert!(!decoded.is_empty(), "sink never took a sample");
    for (_, version) in &decoded {
        assert_eq!(*version, CdrVersion::Xcdr2, "wire label must stay XCDR2");
    }
}

#[test]
fn an_xcdr1_source_relays_to_a_native_sink_labelled_xcdr1() {
    let decoded = relay_one_representation(QoS::reliable().data_representation_xcdr1());
    assert!(!decoded.is_empty(), "sink never took a sample");
    for (_, version) in &decoded {
        assert_eq!(*version, CdrVersion::Xcdr1, "wire label must stay XCDR1");
    }
}

/// Two source writers on the SAME topic, one XCDR1 and one XCDR2, relayed
/// through ONE `RawRelayWriter`: the combination a single fixed-QoS raw
/// writer can never carry correctly, since it resolves and freezes one
/// representation at creation. The relay must carry both truthfully.
#[test]
fn mixed_xcdr1_and_xcdr2_sources_on_one_topic_both_relay_correctly() {
    let domain = unique_domain();
    let tag1 = TAG.fetch_add(1, Ordering::SeqCst);
    let tag2 = TAG.fetch_add(1, Ordering::SeqCst);
    let topic_a = format!("rr_mix_a_{tag1}");
    let topic_b = format!("rr_mix_b_{tag1}");

    let source = participant("rr_mix_source", domain.id());
    let relay = participant("rr_mix_relay", domain.id());
    let sink = participant("rr_mix_sink", domain.id());
    std::mem::forget(domain);

    // Two writers, same topic, same type, different offered representation.
    let w1 = source
        .topic::<Native>(&topic_a)
        .unwrap()
        .writer()
        .qos(QoS::reliable().data_representation_xcdr1())
        .build()
        .unwrap();
    let w2 = source
        .topic::<Native>(&topic_a)
        .unwrap()
        .writer()
        .qos(QoS::reliable().data_representation_xcdr2())
        .build()
        .unwrap();

    let raw_reader = relay
        .create_raw_reader_with_type(&topic_a, DESC.type_name, Some(QoS::reliable()), None, None)
        .unwrap();
    // Eager hint = Xcdr1: one representation known in advance (as a live
    // router would know the first-discovered writer's offer), the other
    // (Xcdr2) is created lazily on its first sample.
    let relay_writer = RawRelayWriter::new(
        Arc::clone(&relay),
        &topic_b,
        DESC.type_name,
        Some(QoS::reliable()),
        None,
        Some(CdrVersion::Xcdr1),
    )
    .unwrap();
    assert_eq!(relay_writer.representations(), vec![CdrVersion::Xcdr1]);

    let sink_reader = sink
        .topic::<Native>(&topic_b)
        .unwrap()
        .reader()
        .qos(QoS::reliable())
        .build()
        .unwrap();

    std::thread::sleep(Duration::from_millis(1500));

    let value1 = 100.0 + f64::from(tag1);
    let value2 = 100.0 + f64::from(tag2);
    w1.write(&Native {
        tag: tag1,
        value: value1,
    })
    .unwrap();
    w2.write(&Native {
        tag: tag2,
        value: value2,
    })
    .unwrap();

    let mut got = Vec::new();
    // Exit on both TAGS being seen, not a raw count: a RELIABLE pair may
    // legitimately redeliver (retransmit) the same sample, which would
    // satisfy a bare `len() >= 2` on one tag alone and starve the other.
    let _ = wait_for(Duration::from_secs(5), || {
        for (sample, version) in raw_reader.try_take_raw_with_encoding().unwrap() {
            relay_writer.relay_write(&sample.payload, version).unwrap();
        }
        while let Ok(Some(sample)) = sink_reader.take() {
            got.push(sample);
        }
        !decoded_for(tag1).is_empty() && !decoded_for(tag2).is_empty()
    });

    let decoded1 = decoded_for(tag1);
    let decoded2 = decoded_for(tag2);
    // Tolerate a possible RELIABLE retransmit duplicate: every decode of
    // this tag must carry the right value AND the right version.
    assert!(!decoded1.is_empty(), "tag1 (Xcdr1) never decoded: {got:?}");
    assert!(!decoded2.is_empty(), "tag2 (Xcdr2) never decoded: {got:?}");
    assert!(
        decoded1.iter().all(|d| *d == (value1, CdrVersion::Xcdr1)),
        "{decoded1:?}"
    );
    assert!(
        decoded2.iter().all(|d| *d == (value2, CdrVersion::Xcdr2)),
        "{decoded2:?}"
    );

    // Both representations ended up with their own writer.
    let mut reps = relay_writer.representations();
    reps.sort_by_key(|v| matches!(v, CdrVersion::Xcdr2));
    assert_eq!(reps, vec![CdrVersion::Xcdr1, CdrVersion::Xcdr2]);
}

/// `write_raw_with_encoding` refuses a payload tagged with a version the
/// writer does not offer, rather than send it mislabeled.
#[test]
fn write_raw_with_encoding_refuses_a_version_the_writer_does_not_offer() {
    let domain = unique_domain();
    let tag = TAG.fetch_add(1, Ordering::SeqCst);
    let relay = participant("rr_refuse", domain.id());
    std::mem::forget(domain);
    let topic = format!("rr_refuse_{tag}");
    let writer = relay
        .create_raw_writer_with_type(
            &topic,
            DESC.type_name,
            Some(QoS::reliable().data_representation_xcdr1()),
            None,
            None,
        )
        .unwrap();
    assert!(writer
        .write_raw_with_encoding(&[1, 2, 3], CdrVersion::Xcdr2)
        .is_err());
    assert!(writer
        .write_raw_with_encoding(&[1, 2, 3], CdrVersion::Xcdr1)
        .is_ok());
}

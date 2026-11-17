// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Item 6, through the REAL router path (`Router::run` -> `run_route`),
//! not just the `hdds::RawRelayWriter` primitive directly: a bridge
//! between two domains must relay a topic that carries more than one
//! DATA_REPRESENTATION without mislabeling either one.
//!
//! Two source writers on domain A, same topic, one offering XCDR1 and one
//! XCDR2 (DDS-XTypes v1.3 Sec.7.6.3.1.1: a writer offers and encodes
//! exactly one representation). A default Native reader on domain B,
//! behind the bridge, must see both values under their own correct wire
//! label.
//!
//! `run_route` must avoid two independent pitfalls for this to work:
//! * cloning the first DISCOVERED WRITER's resolved
//!   (single-element) `data_representation` onto the relay's own raw
//!   READER's QoS makes that reader accept only ONE representation and
//!   silently refuse to match the other writer at all;
//! * forwarding every payload through ONE plain `RawDataWriter` created
//!   once with no `DATA_REPRESENTATION` (resolves to XCDR1, since
//!   `RawBytes` encodes XCDR1 natively) relabels an XCDR2 sample as XCDR1
//!   on the wire.

use hdds::api::DDS;
use hdds::core::types::TypeDescriptor;
use hdds::test_support::domains::unique_domain;
use hdds::{CdrVersion, Participant, QoS, TransportMode};
use hdds_router::Router;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static DESC: TypeDescriptor = TypeDescriptor {
    type_id: 0x7E23_0001,
    type_name: "RouterRelayProbe",
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

#[derive(Debug, Clone)]
struct Native {
    tag: u32,
    value: f64,
}

static DECODED: Mutex<Vec<(u32, f64, CdrVersion)>> = Mutex::new(Vec::new());

impl DDS for Native {
    fn type_descriptor() -> &'static TypeDescriptor {
        &DESC
    }
    fn encode(&self, buf: &mut [u8], version: CdrVersion) -> hdds::api::Result<usize> {
        let at = f_at(version);
        if buf.len() < at + 8 {
            return Err(hdds::api::Error::BufferTooSmall);
        }
        buf[..4].copy_from_slice(&self.tag.to_le_bytes());
        for b in &mut buf[4..at] {
            *b = 0;
        }
        buf[at..at + 8].copy_from_slice(&self.value.to_le_bytes());
        Ok(at + 8)
    }
    fn decode(buf: &[u8], version: CdrVersion) -> hdds::api::Result<Self> {
        let at = f_at(version);
        if buf.len() < at + 8 {
            return Err(hdds::api::Error::SerializationError);
        }
        let tag = u32::from_le_bytes(buf[..4].try_into().unwrap());
        let value = f64::from_le_bytes(buf[at..at + 8].try_into().unwrap());
        DECODED.lock().unwrap().push((tag, value, version));
        Ok(Self { tag, value })
    }
    fn encodes_xcdr1_natively() -> bool {
        true
    }
}

static TAG: AtomicU32 = AtomicU32::new(9000);

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

fn decoded_for(tag: u32) -> Vec<(f64, CdrVersion)> {
    DECODED
        .lock()
        .unwrap()
        .iter()
        .filter(|(t, _, _)| *t == tag)
        .map(|(_, v, ver)| (*v, *ver))
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bridge_relays_mixed_xcdr1_and_xcdr2_sources_correctly() {
    let domain_a = unique_domain();
    let domain_b = unique_domain();
    let (id_a, id_b) = (domain_a.id(), domain_b.id());
    std::mem::forget(domain_a);
    std::mem::forget(domain_b);

    let tag1 = TAG.fetch_add(1, Ordering::SeqCst);
    let tag2 = TAG.fetch_add(1, Ordering::SeqCst);
    let topic = format!("router_relay_probe_{tag1}");

    let mut router = Router::bridge(id_a, id_b).expect("router config should build");
    let _handle = router.run().await.expect("router should start");

    let source = Participant::builder("router_relay_source")
        .domain_id(id_a)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("source participant should build");
    let sink = Participant::builder("router_relay_sink")
        .domain_id(id_b)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("sink participant should build");

    let w1 = source
        .topic::<Native>(&topic)
        .unwrap()
        .writer()
        .qos(QoS::reliable().data_representation_xcdr1())
        .build()
        .expect("xcdr1 writer should build");
    let w2 = source
        .topic::<Native>(&topic)
        .unwrap()
        .writer()
        .qos(QoS::reliable().data_representation_xcdr2())
        .build()
        .expect("xcdr2 writer should build");
    let sink_reader = sink
        .topic::<Native>(&topic)
        .unwrap()
        .reader()
        .qos(QoS::reliable())
        .build()
        .expect("sink reader should build");

    // Discovery across two participants PLUS the router's own two relay
    // participants: slower than a direct two-participant pairing.
    std::thread::sleep(Duration::from_millis(2500));

    let value1 = 1000.0 + f64::from(tag1);
    let value2 = 1000.0 + f64::from(tag2);
    w1.write(&Native {
        tag: tag1,
        value: value1,
    })
    .expect("xcdr1 write should succeed");
    w2.write(&Native {
        tag: tag2,
        value: value2,
    })
    .expect("xcdr2 write should succeed");

    let mut got = Vec::new();
    let settled = wait_for(Duration::from_secs(10), || {
        while let Ok(Some(sample)) = sink_reader.take() {
            got.push(sample);
        }
        !decoded_for(tag1).is_empty() && !decoded_for(tag2).is_empty()
    });

    let decoded1 = decoded_for(tag1);
    let decoded2 = decoded_for(tag2);
    assert!(
        settled,
        "timed out waiting for both representations; xcdr1={decoded1:?} xcdr2={decoded2:?} got={got:?}"
    );
    assert!(
        decoded1.iter().all(|d| *d == (value1, CdrVersion::Xcdr1)),
        "xcdr1 sample mislabeled or wrong value: {decoded1:?}"
    );
    assert!(
        decoded2.iter().all(|d| *d == (value2, CdrVersion::Xcdr2)),
        "xcdr2 sample mislabeled or wrong value: {decoded2:?}"
    );
}

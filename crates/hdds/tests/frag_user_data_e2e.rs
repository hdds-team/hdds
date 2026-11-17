// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! End-to-end fragmentation for user data over UDP.
//!
//! Covers the large-data scenario the OMG interoperability tests exercise:
//! a writer sends a sample with a 100 KB payload, the reader must receive it.
//! Exercises the full path: writer encode -> DATA_FRAG packets -> UDP loopback
//! -> MulticastListener classify -> router loop reassembly -> reader cache.

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, QoS, TransportMode};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, hdds::DDS)]
struct BigBlob {
    id: u32,
    data: Vec<u8>,
}

#[test]
fn test_100kb_sample_udp_roundtrip() {
    // 100KB payload -- forces DATA_FRAG on the wire (HDDS fragments above 8KB).
    const PAYLOAD_SIZE: usize = 100_000;

    // Declared first so it drops LAST, i.e. after both participants have
    // closed their sockets. Both sides must share ONE domain: the whole
    // point is that they discover each other and exchange fragments.
    let domain = unique_domain();

    let pub_part = Participant::builder("big_blob_pub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");
    let sub_part = Participant::builder("big_blob_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("subscriber participant");

    // Wait for SPDP + SEDP discovery.
    thread::sleep(Duration::from_millis(500));

    let writer = pub_part
        .topic::<BigBlob>("LargeDataTopic")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");

    let reader = sub_part
        .topic::<BigBlob>("LargeDataTopic")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    // Give both sides time to match.
    thread::sleep(Duration::from_millis(500));

    let sample = BigBlob {
        id: 42,
        data: vec![0xABu8; PAYLOAD_SIZE],
    };
    writer.write(&sample).expect("write 100KB sample");

    // Give the fragments time to travel and reassemble.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut received: Option<BigBlob> = None;
    while std::time::Instant::now() < deadline {
        match reader.take() {
            Ok(Some(msg)) => {
                received = Some(msg);
                break;
            }
            Ok(None) | Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }

    let msg = received.expect("subscriber should receive the 100KB sample");
    assert_eq!(msg.id, 42);
    assert_eq!(msg.data.len(), PAYLOAD_SIZE);
    assert!(
        msg.data.iter().all(|&b| b == 0xAB),
        "payload corrupted during reassembly"
    );
}

/// RTPS v2.5 Sec.8.3.7.9: INFO_TS applies to the DATA_FRAG submessages that
/// follow it in the same message, so a fragmented sample's source
/// timestamp comes from the fragments' INFO_TS like any other sample's.
/// `FragmentSet` carries it: otherwise delivery would read whatever an
/// unrelated earlier ordinary DATA had left in the per-thread INFO_TS
/// carried by `router::route_source_ts_ns`, since reassembly would never set
/// it for its own, much later, completion. A real
/// fragmented write (100 KB, forcing DATA_FRAG) over real UDP loopback,
/// decoded end to end: `SampleInfo::source_timestamp_ns` must equal
/// exactly what `write_w_timestamp` asked for.
#[test]
fn test_100kb_sample_source_timestamp_round_trips() {
    const PAYLOAD_SIZE: usize = 100_000;

    let domain = unique_domain();
    let pub_part = Participant::builder("big_blob_ts_pub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");
    let sub_part = Participant::builder("big_blob_ts_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("subscriber participant");

    thread::sleep(Duration::from_millis(500));

    let writer = pub_part
        .topic::<BigBlob>("LargeDataTimestampTopic")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");

    let reader = sub_part
        .topic::<BigBlob>("LargeDataTimestampTopic")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    thread::sleep(Duration::from_millis(500));

    // An exact multiple of 1e9 (2026-01-01T00:00:00Z): zero sub-second
    // fraction, so the lossy RTPS Time_t 32-bit-fraction round trip
    // cannot be confused with the defect this test pins (same convention
    // as the other `_w_timestamp` tests).
    let given_ns: u64 = 1_767_225_600 * 1_000_000_000;
    let sample = BigBlob {
        id: 99,
        data: vec![0xCDu8; PAYLOAD_SIZE],
    };
    writer
        .write_w_timestamp(&sample, given_ns)
        .expect("write_w_timestamp of a 100KB sample");

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut received: Option<(Option<BigBlob>, hdds::dds::SampleInfo)> = None;
    while std::time::Instant::now() < deadline {
        match reader.take_with_info() {
            Ok(Some(pair)) => {
                received = Some(pair);
                break;
            }
            Ok(None) | Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }

    let (data, info) = received.expect("subscriber should receive the 100KB sample");
    let msg = data.expect("a data sample, not a transition");
    assert_eq!(msg.id, 99);
    assert_eq!(msg.data.len(), PAYLOAD_SIZE);
    assert_eq!(
        info.source_timestamp_ns,
        Some(given_ns),
        "a fragmented sample's source timestamp must reach SampleInfo, not \
         be absent or leaked from an unrelated datagram"
    );
}

#[test]
fn test_large_data_regression_above_primary_pool_capacity() {
    // Large-data test, per design Sec. 6 #2.
    //
    // The slab pool's largest primary class holds 16 slots of
    // 128 KB. Beyond the 16th 100 KB sample the cache would silently drop
    // inserts and ACKNACK-driven retransmits would log "0 samples,
    // 1 gaps" forever. With the heap fallback the cache must
    // accept N > 16 samples and the subscriber must receive them all.
    const PAYLOAD_SIZE: usize = 100_000;
    const SAMPLE_COUNT: u32 = 20;

    // One shared domain for the pair, leased for the whole test (declared
    // first => dropped last, after both participants are torn down).
    let domain = unique_domain();

    let pub_part = Participant::builder("ld0_pub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("publisher participant");
    let sub_part = Participant::builder("ld0_sub")
        .domain_id(domain.id())
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("subscriber participant");

    thread::sleep(Duration::from_millis(500));

    let writer = pub_part
        .topic::<BigBlob>("LargeDataTopic_LD0")
        .expect("writer topic")
        .writer()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("writer");
    let reader = sub_part
        .topic::<BigBlob>("LargeDataTopic_LD0")
        .expect("reader topic")
        .reader()
        .qos(QoS::reliable().keep_all())
        .build()
        .expect("reader");

    thread::sleep(Duration::from_millis(500));

    for id in 0..SAMPLE_COUNT {
        let sample = BigBlob {
            id,
            data: vec![0xABu8; PAYLOAD_SIZE],
        };
        writer
            .write(&sample)
            .unwrap_or_else(|e| panic!("write sample {id}: {e:?}"));
    }

    // Reliable transport guarantees at-least-once delivery, so the reader
    // may surface retransmits as duplicate ids. The test asserts that the
    // set of distinct ids covers the full 0..SAMPLE_COUNT range.
    let mut received_ids: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline && received_ids.len() < SAMPLE_COUNT as usize {
        match reader.take() {
            Ok(Some(msg)) => {
                assert_eq!(msg.data.len(), PAYLOAD_SIZE, "sample {} truncated", msg.id);
                received_ids.insert(msg.id);
            }
            Ok(None) | Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }

    let received: Vec<u32> = received_ids.into_iter().collect();
    let expected: Vec<u32> = (0..SAMPLE_COUNT).collect();
    assert_eq!(
        received, expected,
        "expected {SAMPLE_COUNT} distinct samples, received {received:?}",
    );
}

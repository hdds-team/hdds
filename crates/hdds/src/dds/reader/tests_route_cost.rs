// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Micro-measure of the receive delivery path: one DATA datagram of a remote
//! writer, classified and routed (`route_data_packet`) to the real readers a
//! UDP participant built, each with its match registry entry. Not a
//! benchmark harness: an ignored test that prints the cost per datagram, for
//! a before/after comparison on one machine.
//!
//! Regime: one thread, no socket (the datagram is routed in place), a remote
//! writer of SHARED ownership whose topic mapping is recorded as its SEDP
//! records it, BEST_EFFORT KEEP_LAST(1) readers taken every 64 datagrams.
//!
//! `cargo test --release -p hdds --lib route_cost -- --ignored --nocapture`

use crate::core::discovery::multicast::{classify_rtps, PacketKind};
use crate::dds::{Participant, QoS, TransportMode, DDS};
use crate::engine::{route_data_packet, RouterMetrics};
use crate::qos::ownership::OwnershipKind;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Probe {
    value: i64,
}

const WRITER: [u8; 16] = [
    0x01, 0x0f, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x12, 0x02,
];

fn datagram(sn: u32, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]); // extraFlags
    body.extend_from_slice(&16u16.to_le_bytes()); // octetsToInlineQos
    body.extend_from_slice(&[0, 0, 0, 0]); // readerId: ENTITYID_UNKNOWN
    body.extend_from_slice(&WRITER[12..]);
    body.extend_from_slice(&0u32.to_le_bytes()); // writerSN high
    body.extend_from_slice(&sn.to_le_bytes()); // writerSN low
    body.extend_from_slice(payload);
    let mut packet = Vec::new();
    packet.extend_from_slice(b"RTPS");
    packet.extend_from_slice(&[2, 5, 0x01, 0x0f]);
    packet.extend_from_slice(&WRITER[..12]);
    packet.extend_from_slice(&[0x15, 0x05]); // DATA, E + D
    packet.extend_from_slice(&u16::try_from(body.len()).expect("fits").to_le_bytes());
    packet.extend_from_slice(&body);
    packet
}

fn serialized(value: i64) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    let len = Probe { value }
        .encode(&mut buf[4..], crate::dds::CdrVersion::Xcdr2)
        .expect("encode");
    buf[..4].copy_from_slice(&[0x00, 0x07, 0x00, 0x00]);
    buf.truncate(4 + len);
    buf
}

fn measure(readers: usize) -> f64 {
    let participant = Participant::builder(&format!("route_cost_{readers}"))
        .domain_id(0)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant");
    let topic_name = format!("route_cost_{readers}");
    let topic = participant.topic::<Probe>(&topic_name).expect("topic");
    let built: Vec<_> = (0..readers)
        .map(|_| {
            topic
                .reader()
                .qos(QoS::best_effort().keep_last(1))
                .build()
                .expect("reader")
        })
        .collect();
    let registry = participant
        .registry
        .clone()
        .expect("a UDP participant routes");
    registry.register_writer_guid(WRITER, topic_name.clone());
    registry.register_writer_ownership_kind(WRITER, OwnershipKind::Shared);
    let metrics = RouterMetrics::new();
    let payload = serialized(7);
    const WARMUP: u32 = 20_000;
    const N: u32 = 400_000;
    let packets: Vec<Vec<u8>> = (1..=WARMUP + N).map(|sn| datagram(sn, &payload)).collect();
    let (kind, offset, _, _) = classify_rtps(&packets[0]);
    assert_eq!(kind, PacketKind::Data);
    let route = |packet: &[u8]| {
        let _ = route_data_packet(packet, packet.len(), offset, &registry, &metrics);
    };
    for packet in &packets[..WARMUP as usize] {
        route(packet);
    }
    for r in &built {
        while r.take().expect("take").is_some() {}
    }
    let mut delivered = 0usize;
    let start = Instant::now();
    for (i, packet) in packets[WARMUP as usize..].iter().enumerate() {
        route(packet);
        if i % 64 == 63 {
            for r in &built {
                while r.take().expect("take").is_some() {
                    delivered += 1;
                }
            }
        }
    }
    let elapsed = start.elapsed();
    for r in &built {
        while r.take().expect("take").is_some() {
            delivered += 1;
        }
    }
    assert!(
        delivered > 0,
        "the readers received nothing: the regime is wrong"
    );
    elapsed.as_nanos() as f64 / f64::from(N)
}

#[test]
#[ignore = "micro-measure, run in release with --ignored --nocapture"]
fn route_cost() {
    for readers in [1usize, 2, 4] {
        let mut runs: Vec<f64> = (0..5).map(|_| measure(readers)).collect();
        runs.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        eprintln!(
            "ROUTE_COST readers={readers} ns/datagram min={:.1} median={:.1} max={:.1}",
            runs[0], runs[2], runs[4]
        );
    }
}

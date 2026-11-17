// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! What a participant puts on the wire to assert its AUTOMATIC writers,
//! read back as bytes by a peer that is only a socket: its SPDP is handed
//! to the participant's receive path, naming the socket as its
//! metatraffic unicast locator.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::core::discovery::GUID;
use crate::protocol::discovery::SpdpData;
use crate::protocol::rtps::participant_message::{
    decode_participant_message_data, KIND_AUTOMATIC, KIND_MANUAL, PARTICIPANT_MESSAGE_WRITER,
};
use crate::test_support::domains::unique_domain;
use crate::{Participant, QoS, TransportMode};

#[derive(Debug, Clone, PartialEq, crate::DDS)]
struct Beat {
    n: u32,
}

/// The SPDP of a peer at `socket`, announcing `endpoint_set` as its
/// builtin endpoints.
fn peer_announcement(
    prefix: [u8; 12],
    domain_id: u32,
    socket: &UdpSocket,
    endpoint_set: u32,
) -> Vec<u8> {
    let mut packet = crate::core::discovery::multicast::build_spdp_rtps_packet(
        &SpdpData {
            participant_guid: GUID::new(prefix, [0x00, 0x00, 0x01, 0xC1]),
            lease_duration_ms: 30_000,
            domain_id,
            metatraffic_unicast_locators: vec![socket.local_addr().expect("addr")],
            default_unicast_locators: vec![],
            default_multicast_locators: vec![],
            metatraffic_multicast_locators: vec![],
            identity_token: None,
            permissions_token: None,
            participant_security_info: None,
            vendor_id: None,
            hdds_capabilities: None,
            builtin_endpoint_set: None,
        },
        1,
        None,
    )
    .expect("an announcement");
    // PID_BUILTIN_ENDPOINT_SET (0x0058), 4 octets, little endian.
    let at = packet
        .windows(4)
        .position(|w| w == [0x58, 0x00, 0x04, 0x00])
        .expect("the announcement names its endpoints");
    packet[at + 4..at + 8].copy_from_slice(&endpoint_set.to_le_bytes());
    packet
}

/// `(sequence number, guid prefix, kind)` of each participant-message DATA
/// received on `socket` within `window`, `speak` called every 100 ms (a
/// peer that only announced itself once is purged as a stale one).
fn assertions(
    socket: &UdpSocket,
    window: Duration,
    speak: &dyn Fn(),
) -> Vec<(u64, [u8; 12], [u8; 4])> {
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .expect("timeout");
    let mut got = Vec::new();
    let mut buf = vec![0u8; 65536];
    let end = Instant::now() + window;
    let mut spoke = Instant::now();
    while Instant::now() < end {
        if spoke.elapsed() >= Duration::from_millis(100) {
            speak();
            spoke = Instant::now();
        }
        let Ok((n, _)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let datagram = &buf[..n];
        let mut at = 20;
        while at + 4 <= datagram.len() {
            let id = datagram[at];
            let len = usize::from(u16::from_le_bytes([datagram[at + 2], datagram[at + 3]]));
            let body = &datagram[at + 4..(at + 4 + len).min(datagram.len())];
            if id == 0x15 && body.len() >= 20 && body[8..12] == PARTICIPANT_MESSAGE_WRITER {
                let high = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);
                let low = u32::from_le_bytes([body[16], body[17], body[18], body[19]]);
                let sn = (u64::from(high) << 32) | u64::from(low);
                let message = decode_participant_message_data(&body[20..]).expect("decodes");
                got.push((sn, message.participant_guid_prefix, message.kind));
            }
            if len == 0 {
                break;
            }
            at += 4 + len;
        }
    }
    got
}

fn participant(name: &str, domain: u32) -> std::sync::Arc<Participant> {
    Participant::builder(name)
        .domain_id(domain)
        .with_transport(TransportMode::UdpMulticast)
        .build()
        .expect("participant")
}

#[test]
fn an_automatic_writer_is_asserted_every_third_of_its_lease() {
    let domain = unique_domain();
    let p = participant("asserts_automatic", domain.id());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    let ingress = p.relay_ingress.clone().expect("receive leg");
    let announcement = peer_announcement([0x0C; 12], domain.id(), &socket, 0x0000_0C3F);
    let speak = || ingress.dispatch(&announcement, "127.0.0.1:7410".parse().expect("addr"));
    speak();
    let _writer = p
        .topic::<Beat>("LivelinessWire")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness_automatic_millis(300))
        .build()
        .expect("writer");
    let got = assertions(&socket, Duration::from_millis(1050), &speak);
    // One at once, then one every 100 ms: about 11; scheduling slack only
    // ever delays one.
    assert!(
        (8..=12).contains(&got.len()),
        "{} assertions in 1.05 s: {got:?}",
        got.len()
    );
    for (i, (sn, prefix, kind)) in got.iter().enumerate() {
        assert_eq!(*prefix, p.guid().prefix, "its own participant");
        assert_eq!(*kind, KIND_AUTOMATIC);
        if i > 0 {
            assert_eq!(*sn, got[i - 1].0 + 1, "one sample after the other");
        }
    }
}

#[test]
fn no_assertion_reaches_a_peer_that_reads_none() {
    let domain = unique_domain();
    let p = participant("asserts_to_readers_only", domain.id());
    let reads = UdpSocket::bind("127.0.0.1:0").expect("socket");
    let reads_none = UdpSocket::bind("127.0.0.1:0").expect("socket");
    let ingress = p.relay_ingress.clone().expect("receive leg");
    let from = "127.0.0.1:7410".parse().expect("addr");
    let one = peer_announcement([0x0D; 12], domain.id(), &reads, 0x0000_0C3F);
    let other = peer_announcement([0x0E; 12], domain.id(), &reads_none, 0x0000_043F);
    let speak = || {
        ingress.dispatch(&one, from);
        ingress.dispatch(&other, from);
    };
    speak();
    let _writer = p
        .topic::<Beat>("LivelinessWireReaders")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness_automatic_millis(150))
        .build()
        .expect("writer");
    assert!(!assertions(&reads, Duration::from_millis(400), &speak).is_empty());
    assert!(assertions(&reads_none, Duration::from_millis(400), &speak).is_empty());
}

/// RTPS v2.5 Sec.8.4.13.5: `DataWriter::assert_liveliness()` on a
/// MANUAL_BY_PARTICIPANT writer with nothing to write still reaches the
/// wire, as a ParticipantMessage of kind MANUAL -- the same writer, same
/// SN space as AUTOMATIC's `KIND_AUTOMATIC` (Sec.9.6.3.1's key is
/// `guidPrefix || kind`; the sequence number is the writer's).
#[test]
fn assert_liveliness_sends_a_manual_participant_message() {
    let domain = unique_domain();
    let p = participant("asserts_manual_explicitly", domain.id());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    let ingress = p.relay_ingress.clone().expect("receive leg");
    let announcement = peer_announcement([0x11; 12], domain.id(), &socket, 0x0000_0C3F);
    let speak = || ingress.dispatch(&announcement, "127.0.0.1:7410".parse().expect("addr"));
    speak();
    let writer = p
        .topic::<Beat>("LivelinessWireManualAssert")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness_manual_participant_millis(300))
        .build()
        .expect("writer");
    writer.assert_liveliness().expect("assert_liveliness");
    let got = assertions(&socket, Duration::from_millis(900), &speak);
    assert!(!got.is_empty(), "the explicit assertion reaches the wire");
    for (_, prefix, kind) in &got {
        assert_eq!(*prefix, p.guid().prefix);
        assert_eq!(*kind, KIND_MANUAL, "not the AUTOMATIC instance");
    }
}

#[test]
fn a_participant_with_no_finite_automatic_writer_asserts_nothing() {
    let domain = unique_domain();
    let p = participant("asserts_nothing", domain.id());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    let ingress = p.relay_ingress.clone().expect("receive leg");
    let announcement = peer_announcement([0x0F; 12], domain.id(), &socket, 0x0000_0C3F);
    let speak = || ingress.dispatch(&announcement, "127.0.0.1:7410".parse().expect("addr"));
    speak();
    let _infinite = p
        .topic::<Beat>("LivelinessWireNone")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort())
        .build()
        .expect("writer");
    let _manual = p
        .topic::<Beat>("LivelinessWireManual")
        .expect("topic")
        .writer()
        .qos(QoS::best_effort().liveliness_manual_participant_millis(100))
        .build()
        .expect("writer");
    assert!(assertions(&socket, Duration::from_millis(600), &speak).is_empty());
}

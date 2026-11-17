// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Some of the domain ids below are the SUBJECT of their test and must stay
//! literal: `test_transport_creation_rtps_compliant`,
//! `test_transport_different_participant` and `test_transport_different_domain`
//! assert the RTPS `7400 + 250 * domain` mapping itself (domain 0 -> :7400,
//! domain 1 -> :7650), so a leased id would delete what they check. The tests
//! that merely need SOME transport lease one instead, because those bind real
//! unicast ports and a hand-picked id can collide with another test binary.

use super::*;
use crate::test_support::domains::unique_domain;
#[cfg(unix)]
use crate::transport::dscp::{get_socket_dscp, DscpClass, DscpConfig};
use crate::transport::socket_buffer::SocketBufferOptions;
use crate::transport::PortMapping;
#[cfg(unix)]
use crate::transport::TransportOptions;
use socket2::SockRef;
use std::num::NonZeroUsize;

#[test]
fn test_transport_creation_rtps_compliant() {
    let mapping = PortMapping::calculate(0, 0).expect("Port mapping calculation should succeed");
    let transport = UdpTransport::new(0, 0, mapping);
    assert!(transport.is_ok(), "Transport creation should succeed");

    let transport = transport.expect("Transport creation should succeed");
    assert_eq!(transport.domain_id, 0);
    assert_eq!(transport.participant_id, 0);
    assert_eq!(transport.multicast_addr.to_string(), "239.255.0.1:7400");
}

#[test]
fn test_transport_different_participant() {
    let mapping = PortMapping::calculate(0, 1).expect("Port mapping calculation should succeed");
    let transport = UdpTransport::new(0, 1, mapping);
    assert!(transport.is_ok(), "Should support multiple participants");

    let transport = transport.expect("Transport creation should succeed");
    assert_eq!(transport.participant_id, 1);
    assert_eq!(transport.multicast_addr.to_string(), "239.255.0.1:7400");
}

#[test]
fn test_transport_different_domain() {
    let mapping = PortMapping::calculate(1, 0).expect("Port mapping calculation should succeed");
    let transport = UdpTransport::new(1, 0, mapping);
    assert!(transport.is_ok(), "Should support different domains");

    let transport = transport.expect("Transport creation should succeed");
    assert_eq!(transport.domain_id, 1);
    assert_eq!(transport.multicast_addr.to_string(), "239.255.0.1:7650");
}

/// Two participants on ONE leased domain both bind the
/// metatraffic multicast socket. SPDP/SEDP share that port, computed from
/// the domain id alone (`PortMapping::calculate`), never from the
/// participant id, so this is the ordinary shape of running more than one
/// participant on a host, not an edge case.
///
/// What this test PROVES on Linux: SO_REUSEADDR alone has always been
/// enough here, and the `cfg(target_os)` block that forces
/// SO_REUSEPORT on BSD-family kernels (next to this socket's creation in
/// `UdpTransport::new_with_options_and_socket_buffers`) does not disturb
/// that -- it compiles to nothing on Linux, and this test's continued pass
/// is the evidence.
///
/// What this test CANNOT prove, and does not claim to: Darwin refused this
/// exact scenario with "Address already in use" (os error 48) because
/// SO_REUSEADDR alone is not enough there. Only a run on the macOS
/// guest (`ssh macos-vm`) exercises that branch; nothing
/// in this crate's Linux test suite can.
#[test]
fn two_participants_share_the_metatraffic_multicast_port() {
    let domain = unique_domain();
    let mapping0 = PortMapping::calculate(domain.id(), 0).expect("port mapping for participant 0");
    let mapping1 = PortMapping::calculate(domain.id(), 1).expect("port mapping for participant 1");
    assert_eq!(
        mapping0.metatraffic_multicast, mapping1.metatraffic_multicast,
        "the premise of this test: SPDP/SEDP multicast port is domain-only, so both \
         participants must bind the IDENTICAL port"
    );

    let first = UdpTransport::new(domain.id(), 0, mapping0);
    assert!(
        first.is_ok(),
        "first participant should bind the metatraffic multicast socket: {:?}",
        first.err()
    );
    let _first = first.expect("checked above");

    let second = UdpTransport::new(domain.id(), 1, mapping1);
    assert!(
        second.is_ok(),
        "second participant on the SAME domain must also bind the identical metatraffic \
         multicast port ({}) while the first is still alive -- Darwin \
         refuses this with SO_REUSEADDR alone (os error 48), Linux does not. {:?}",
        mapping0.metatraffic_multicast,
        second.err()
    );
}

/// The legacy `with_port` API maps a raw port onto the multicast address.
/// What is under test is that MAPPING, not any particular number -- so the
/// port is derived from a leased domain instead of hardcoded.
///
/// A hardcoded port such as `17400` (`PORT_BASE + DOMAIN_ID_GAIN * 40`) is the
/// SPDP multicast port of domain 40, a domain the allocator hands out. When
/// a concurrent test held that lease the test would fail WITHOUT the words
/// "Address already in use" anywhere -- `with_port` returns the error inside
/// a `Result` that the assertion below merely reports as
/// `assertion failed: transport.is_ok()`.
#[test]
#[allow(deprecated)]
fn test_transport_with_custom_port_legacy() {
    let domain = unique_domain();
    let port = u32::from(crate::config::PORT_BASE)
        + u32::from(crate::config::DOMAIN_ID_GAIN) * domain.id();
    let port = u16::try_from(port).expect("a pooled domain always has a port");

    let transport = UdpTransport::with_port(port);
    assert!(
        transport.is_ok(),
        "with_port({port}) failed on leased domain {}: {:?}",
        domain.id(),
        transport.err()
    );

    let transport = transport.expect("Legacy transport creation should succeed");
    assert_eq!(
        transport.multicast_addr.to_string(),
        format!("239.255.0.1:{port}")
    );
}

#[test]
fn test_transport_send() {
    // Nothing here is about a particular domain: it binds a transport and
    // sends one datagram. Leased, so the packet never lands on the fleet's
    // default domain-0 multicast port and the unicast port is ours alone.
    let domain = unique_domain();
    let mapping =
        PortMapping::calculate(domain.id(), 2).expect("Port mapping calculation should succeed");
    let transport =
        UdpTransport::new(domain.id(), 2, mapping).expect("Transport creation should succeed");
    let data = b"RTPS test packet";

    let result = transport.send(data);
    assert!(result.is_ok(), "Send should succeed");
}

#[test]
fn test_socket_sharing() {
    let domain = unique_domain();
    let mapping =
        PortMapping::calculate(domain.id(), 3).expect("Port mapping calculation should succeed");
    let transport =
        UdpTransport::new(domain.id(), 3, mapping).expect("Transport creation should succeed");
    let socket1 = transport.socket();
    let socket2 = transport.socket();

    assert!(Arc::ptr_eq(&socket1, &socket2));
}

#[cfg(unix)]
#[test]
fn explicit_dscp_reaches_metatraffic_and_user_data_sockets() {
    let domain = unique_domain();
    let mapping =
        PortMapping::calculate(domain.id(), 91).expect("valid isolated RTPS port mapping");
    let options = TransportOptions::default()
        .with_dscp(DscpConfig {
            discovery: DscpClass::Af21,
            user_data: DscpClass::Af41,
            metatraffic: DscpClass::Af31,
        })
        .resolve();
    let transport = UdpTransport::new_with_options(domain.id(), 91, mapping, &options)
        .expect("transport with explicit DSCP");

    assert_eq!(get_socket_dscp(&transport.socket), Some(DscpClass::Af31));
    assert_eq!(
        get_socket_dscp(&transport.metatraffic_unicast_socket),
        Some(DscpClass::Af31)
    );
    assert_eq!(
        get_socket_dscp(&transport.user_unicast_socket),
        Some(DscpClass::Af41)
    );
}

#[test]
fn explicit_socket_buffers_reach_every_udp_transport_socket() {
    const REQUESTED: usize = 64 * 1024;
    let mapping = PortMapping {
        metatraffic_multicast: 0,
        sedp_multicast: 0,
        metatraffic_unicast: 0,
        user_unicast: 0,
    };
    let transport_options = TransportOptions::default().resolve();
    let socket_buffers = SocketBufferOptions::default()
        .with_receive_buffer_size(NonZeroUsize::new(REQUESTED).unwrap())
        .with_send_buffer_size(NonZeroUsize::new(REQUESTED).unwrap())
        .resolve_with_env(None, None);

    let transport = UdpTransport::new_with_options_and_socket_buffers(
        0,
        0,
        mapping,
        &transport_options,
        &socket_buffers,
    )
    .expect("transport with explicit socket buffers");

    for socket in [
        &transport.socket,
        &transport.metatraffic_unicast_socket,
        &transport.user_unicast_socket,
    ] {
        assert!(
            SockRef::from(socket.as_ref()).send_buffer_size().unwrap() >= REQUESTED,
            "SO_SNDBUF must reach every UDP transport send socket"
        );
    }

    for socket in [&transport.socket, &transport.metatraffic_unicast_socket] {
        assert!(
            SockRef::from(socket.as_ref()).recv_buffer_size().unwrap() >= REQUESTED,
            "an explicit SO_RCVBUF must reach every receive-capable transport socket"
        );
    }
}

/// Regression: `parse_submessage_kind` must read at wire offset 20
/// (past the 20-byte RTPS header) and map IDs per RTPS v2.5 Table
/// 8.13. The previous implementation read at offset 16 (inside the
/// guid prefix) and swapped ACKNACK (0x06) with HEARTBEAT (0x07),
/// turning every diagnostic log line into garbage.
#[test]
fn parse_submessage_kind_reads_offset_20_and_maps_per_spec() {
    // Build a minimal RTPS frame: 20-byte header + 1-byte kind byte.
    let mut frame = vec![b'R', b'T', b'P', b'S']; // magic
    frame.extend_from_slice(&[2, 5]); // version 2.5
    frame.extend_from_slice(&[0x01, 0x1A]); // vendor (HDDS)
    frame.extend_from_slice(&[0u8; 12]); // guid prefix
    assert_eq!(frame.len(), 20, "RTPS header is 20 bytes");

    // The byte at offset 20 is the submessage kind.
    let cases: &[(u8, &str)] = &[
        (0x00, "HEADER_EXTENSION"),
        (0x06, "ACKNACK"),
        (0x07, "HEARTBEAT"),
        (0x08, "GAP"),
        (0x09, "INFO_TS"),
        (0x0C, "INFO_SRC"),
        (0x0D, "INFO_REPLY_IP4"),
        (0x0E, "INFO_DST"),
        (0x0F, "INFO_REPLY"),
        (0x12, "NACK_FRAG"),
        (0x13, "HEARTBEAT_FRAG"),
        (0x15, "DATA"),
        (0x16, "DATA_FRAG"),
        (0xFF, "OTHER"),
    ];
    for (id, expected) in cases {
        let mut packet = frame.clone();
        packet.push(*id);
        assert_eq!(
            UdpTransport::parse_submessage_kind(&packet),
            *expected,
            "kind 0x{id:02x} must map to {expected}"
        );
    }

    // A packet shorter than 21 bytes (no submessage byte) must
    // safely return "OTHER" rather than panic.
    assert_eq!(
        UdpTransport::parse_submessage_kind(&frame),
        "OTHER",
        "short packets must not panic"
    );
}

/// The periodic HEARTBEAT path's best-effort unicast send
/// (`UdpTransport::send_user_data_unicast_best_effort`, used from
/// `dds::writer::heartbeat_scheduler::send_heartbeat_to_readers`) must
/// deliver exactly like the ordinary blocking one on the common,
/// no-backpressure path: the only difference between the two is whether
/// the kernel may block THIS call when its send buffer has no room,
/// which the happy path here never exercises.
///
/// Mutant: swapping which counter either method increments (or routing
/// `send_user_data_unicast_best_effort` through the metatraffic socket
/// instead of the user-data one) makes this fail -- either the received
/// payload no longer matches, or the best-effort/blocking counters
/// attribute a send to the wrong path.
#[test]
fn best_effort_unicast_send_delivers_like_the_blocking_one() {
    let domain = unique_domain();
    let mapping =
        PortMapping::calculate(domain.id(), 50).expect("Port mapping calculation should succeed");
    let transport =
        UdpTransport::new(domain.id(), 50, mapping).expect("Transport creation should succeed");
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    receiver
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .expect("read timeout");
    let dest = receiver.local_addr().expect("receiver local addr");

    assert_eq!(transport.blocking_sends_for_test(), 0);
    assert_eq!(transport.best_effort_sends_for_test(), 0);

    let target = transport
        .resolve_best_effort_unicast(&dest)
        .expect("a plain unicast destination always resolves to Direct");
    let sent = transport
        .transmit_best_effort_resolved(&target, b"best-effort payload")
        .expect("best-effort send should succeed on the happy path");
    let mut buf = [0u8; 64];
    let (n, _) = receiver.recv_from(&mut buf).expect("receive the datagram");
    assert_eq!(&buf[..n], b"best-effort payload");
    assert_eq!(sent, n);
    assert_eq!(
        transport.best_effort_sends_for_test(),
        1,
        "the best-effort send must be the one counted"
    );
    assert_eq!(
        transport.blocking_sends_for_test(),
        0,
        "the best-effort send must not also count as a blocking one"
    );

    let sent2 = transport
        .send_user_data_unicast(b"blocking payload", &dest)
        .expect("the ordinary send must keep working unchanged");
    let (n2, _) = receiver
        .recv_from(&mut buf)
        .expect("receive the second datagram");
    assert_eq!(&buf[..n2], b"blocking payload");
    assert_eq!(sent2, n2);
    assert_eq!(
        transport.blocking_sends_for_test(),
        1,
        "the ordinary send must be the one counted this time"
    );
    assert_eq!(
        transport.best_effort_sends_for_test(),
        1,
        "the ordinary send must not also count as best-effort"
    );
}

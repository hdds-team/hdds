// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! E2E smoke test for unicast routing thread with TCP transport.
//!
//! Validates that:
//! 1. Participant with TCP creates and starts the TCP transport
//! 2. The "hdds-unicast-router" thread is spawned
//! 3. A raw TCP connection is accepted by the listener
//! 4. A length-prefixed RTPS-like packet is consumed without hanging or crashing
//! 5. The routing thread processes events (even if the packet is dropped/orphaned)

use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use hdds::test_support::domains::unique_domain;
use hdds::{Participant, TransportMode};

/// Helper: build a minimal RTPS DATA packet for testing.
///
/// Layout:
/// - RTPS header (20 bytes): magic "RTPS", version 2.3, vendorId 0x0199, guidPrefix
/// - DATA submessage header (4 bytes): submessageId=0x15, flags=0x01 (LE), octetsToNextHeader=20
/// - DATA submessage body (20 bytes): zeros (extraFlags, octetsToInlineQos, reader/writer entityIds, seqNum)
///
/// Total: 44 bytes -- enough for classify_rtps to recognize it as PacketKind::Data.
fn build_minimal_rtps_data_packet() -> Vec<u8> {
    let mut pkt = vec![0u8; 44];

    // RTPS header
    pkt[0..4].copy_from_slice(b"RTPS"); // magic
    pkt[4] = 0x02; // version major
    pkt[5] = 0x03; // version minor
    pkt[6] = 0x01; // vendorId high (HDDS)
    pkt[7] = 0x99; // vendorId low
                   // guidPrefix: bytes 8..20 (leave as zeros -- anonymous sender)

    // DATA submessage at offset 20
    pkt[20] = 0x15; // submessageId: DATA
    pkt[21] = 0x01; // flags: little-endian
                    // octetsToNextHeader (LE u16): 20 bytes of DATA body
    pkt[22] = 20;
    pkt[23] = 0;

    // DATA body at offset 24..44 (all zeros):
    // extraFlags(2) + octetsToInlineQos(2) + readerEntityId(4) + writerEntityId(4) + seqNum(8)
    // All zeros is fine -- we don't expect delivery, just that the router consumes it.

    pkt
}

/// Helper: encode a payload with the TCP length-prefix frame format.
///
/// Format: [4-byte big-endian length][payload]
fn frame_encode(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// The listener reports the address it is bound to. When that is the
/// unspecified address, Linux lets a client connect to it as if it were
/// loopback; Windows refuses (WSAEADDRNOTAVAIL). Connect to loopback then.
fn connectable(mut addr: std::net::SocketAddr) -> std::net::SocketAddr {
    if addr.ip().is_unspecified() {
        addr.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
    }
    addr
}

#[test]
fn unicast_routing_thread_is_spawned_with_tcp() {
    // 1. Build participant with UdpMulticast + TCP (port 0 = OS-assigned).
    //    UdpMulticast mode is required because the unicast routing thread needs
    //    the TopicRegistry and Router, which are only created in UdpMulticast mode.
    //
    //    This is the only participant in this file that really binds RTPS
    //    ports; without an explicit domain it defaulted to 0, the fleet-wide
    //    default that every other test binary also lands on. The lease is
    //    declared first so it outlives the participant's sockets.
    let domain = unique_domain();
    let participant = Participant::builder("unicast_e2e_test")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(domain.id())
        .with_tcp(0) // port 0 => OS assigns an ephemeral port
        .build()
        .expect("participant build should succeed with TCP");

    // 2. Verify TCP transport started and has a listen address
    let tcp_addr = participant
        .tcp_listen_addr()
        .expect("TCP transport should have a listen address");
    assert_ne!(tcp_addr.port(), 0, "TCP port should be assigned by OS");

    // 3. Give the unicast routing thread time to start
    thread::sleep(Duration::from_millis(100));

    // 4. Verify "hdds-unicast-router" thread exists
    //    We check by looking at thread names via /proc/self/task (Linux) or
    //    a more portable approach: just verify the thread was spawned by attempting
    //    a connection to the TCP port (if no thread, events would pile up).
    //
    //    Checking /proc is Linux-specific but works in CI:
    let router_thread_found = check_thread_exists("hdds-unicast-router");
    assert!(
        router_thread_found,
        "Expected 'hdds-unicast-router' thread to be spawned"
    );

    // 5. Connect a raw TCP client and send a length-prefixed RTPS packet
    let mut stream = TcpStream::connect(connectable(tcp_addr))
        .expect("TCP connection to participant should succeed");
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok();

    let rtps_packet = build_minimal_rtps_data_packet();
    let frame = frame_encode(&rtps_packet);

    stream
        .write_all(&frame)
        .expect("Should be able to write framed RTPS packet");
    stream.flush().expect("flush");

    // 6. Wait for the routing thread to pick up the TCP event
    thread::sleep(Duration::from_millis(500));

    // 7. Verify: the participant is still alive (no panic in routing thread)
    //    and the TCP transport is still operational
    assert!(
        participant.tcp_listen_addr().is_some(),
        "TCP transport should still be operational after receiving data"
    );

    // 8. Send a second packet to further confirm the loop continues
    let frame2 = frame_encode(&rtps_packet);
    // The write may fail if the connection was closed (TCP can reject after GUID
    // mismatch), but that's fine -- the important thing is the thread didn't crash.
    let _ = stream.write_all(&frame2);

    thread::sleep(Duration::from_millis(200));

    // Final check: participant still healthy
    assert!(
        participant.tcp_listen_addr().is_some(),
        "TCP transport should remain healthy"
    );
}

#[test]
fn tcp_listener_accepts_connection() {
    // Simpler test: just verify the TCP listener is functional
    let participant = Participant::builder("tcp_accept_test")
        .with_transport(TransportMode::IntraProcess)
        .with_tcp(0)
        .build()
        .expect("participant build");

    let addr = participant.tcp_listen_addr().expect("should have TCP addr");

    // Connect and immediately disconnect
    let stream = TcpStream::connect_timeout(&connectable(addr), Duration::from_secs(2));
    assert!(
        stream.is_ok(),
        "TCP listener should accept incoming connections"
    );

    // Drop the stream (disconnects)
    drop(stream);

    // Give time for cleanup
    thread::sleep(Duration::from_millis(100));

    // Participant should still be alive
    assert!(participant.tcp_listen_addr().is_some());
}

#[test]
fn tcp_garbage_data_does_not_crash_router() {
    // Send garbage (non-RTPS) data and verify the router thread survives
    let participant = Participant::builder("tcp_garbage_test")
        .with_transport(TransportMode::IntraProcess)
        .with_tcp(0)
        .build()
        .expect("participant build");

    let addr = participant.tcp_listen_addr().expect("should have TCP addr");

    thread::sleep(Duration::from_millis(100));

    let mut stream = TcpStream::connect(connectable(addr)).expect("connect");
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

    // Send garbage: a length-prefixed frame with random bytes (not valid RTPS)
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let frame = frame_encode(&garbage);
    let _ = stream.write_all(&frame);
    let _ = stream.flush();

    thread::sleep(Duration::from_millis(500));

    // Router should survive garbage data
    assert!(
        participant.tcp_listen_addr().is_some(),
        "TCP transport should survive garbage data without crashing"
    );
}

// ============================================================================
// Helpers
// ============================================================================

/// Check if a thread whose name starts with the given prefix exists.
///
/// Uses /proc/self/task on Linux to enumerate threads and read their comm names.
/// Note: Linux truncates thread names to 15 characters, so "hdds-unicast-router"
/// becomes "hdds-unicast-ro". We use starts_with to handle this.
///
/// On non-Linux platforms, returns true (skip the check).
fn check_thread_exists(name_prefix: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        // Linux comm names are max 15 chars, so truncate our prefix too
        let prefix = if name_prefix.len() > 15 {
            &name_prefix[..15]
        } else {
            name_prefix
        };
        let task_dir = "/proc/self/task";
        if let Ok(entries) = fs::read_dir(task_dir) {
            for entry in entries.flatten() {
                let comm_path = entry.path().join("comm");
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    let trimmed = comm.trim();
                    if trimmed == prefix || trimmed.starts_with(prefix) {
                        return true;
                    }
                }
            }
        }
        // Thread name not found
        false
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = name_prefix;
        true // Skip check on non-Linux
    }
}

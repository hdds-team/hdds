// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mutual-TLS proof on the production path: `IoThread` (server side, raw
//! `TcpEvent`s) against `TcpTransport` (dialing side).
//!
//! THE proof of the shipped feature: the I/O thread builds
//! `rustls::ServerConnection` from the `TlsConfig` Arc, so a refused client
//! certificate must surface as `ConnectionClosed` with a TLS reason and never
//! as `ConnectionAccepted`.
//!
//! TLS 1.3 semantic under test: the dialing HDDS side finishes its handshake
//! before the server verifies the client certificate, so a rejected dialer
//! observes `Connected` followed by `Disconnected`; no data is delivered.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::connection_manager::GuidPrefix;
use super::io_thread::{IoThread, IoThreadHandle, TcpEvent};
use super::metrics::TcpTransportMetrics;
use super::tls::TlsConfig;
use super::tls_test_pki::TestPki;
use super::transport::{TcpTransport, TcpTransportEvent};
use super::{TcpConfig, TcpRole};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const QUIET_WINDOW: Duration = Duration::from_millis(500);
/// Deadline for a single bulk message to cross the mTLS data path. Generous:
/// the failure it guards against is a permanent stall, not slowness.
const BULK_TIMEOUT: Duration = Duration::from_secs(10);

fn pki() -> &'static TestPki {
    TestPki::shared()
}

fn guid(id: u8) -> GuidPrefix {
    [id, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn server_mtls(crls: &[&[u8]]) -> TlsConfig {
    let pki = pki();
    let mut builder = TlsConfig::server()
        .with_cert_pem(pki.server_a_cert.clone())
        .with_key_pem(pki.server_a_key.clone())
        .require_client_cert()
        .with_root_cert_pem(pki.ca_a_cert.clone());
    for crl in crls {
        builder = builder.with_crl_pem(crl.to_vec());
    }
    builder.build().expect("mTLS server config")
}

fn client_cfg(identity: Option<(&[u8], &[u8])>) -> TlsConfig {
    let pki = pki();
    let mut builder = TlsConfig::client().with_root_cert_pem(pki.ca_a_cert.clone());
    if let Some((cert, key)) = identity {
        builder = builder
            .with_cert_pem(cert.to_vec())
            .with_key_pem(key.to_vec());
    }
    builder.build().expect("client config")
}

/// Spawn the server-side I/O thread with an mTLS config on 127.0.0.1:0.
fn spawn_server(tls: TlsConfig) -> (IoThreadHandle, SocketAddr, Arc<TcpTransportMetrics>) {
    let config = TcpConfig {
        enabled: true,
        listen_port: 0,
        listen_address: Some([127, 0, 0, 1].into()),
        role: TcpRole::ServerOnly,
        tls_enabled: true,
        tls_config: Some(tls),
        ..Default::default()
    };
    config.validate().expect("server config validates");
    let metrics = Arc::new(TcpTransportMetrics::new());
    let handle = IoThread::spawn(config, Arc::clone(&metrics)).expect("io thread");
    let addr = match handle.recv_timeout(STEP_TIMEOUT) {
        Some(TcpEvent::Started {
            local_addr: Some(addr),
        }) => addr,
        other => panic!("expected Started with a listener address, got {other:?}"),
    };
    (handle, addr, metrics)
}

fn dialer(tls: TlsConfig, server_addr: SocketAddr) -> TcpTransport {
    let config = TcpConfig {
        enabled: true,
        role: TcpRole::ClientOnly,
        initial_peers: vec![server_addr],
        tls_enabled: true,
        tls_config: Some(tls),
        ..Default::default()
    };
    TcpTransport::new(guid(0xC), config).expect("dialing transport")
}

/// Drain server events for `window`, returning them in order.
fn drain_server(handle: &IoThreadHandle, window: Duration) -> Vec<TcpEvent> {
    let deadline = Instant::now() + window;
    let mut events = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match handle.recv_timeout(remaining) {
            Some(ev) => events.push(ev),
            None => break,
        }
    }
    events
}

/// Collect dialer events until `done` says so or the timeout elapses.
fn collect_dialer(
    transport: &TcpTransport,
    timeout: Duration,
    done: impl Fn(&[TcpTransportEvent]) -> bool,
) -> Vec<TcpTransportEvent> {
    let deadline = Instant::now() + timeout;
    let mut events = Vec::new();
    while Instant::now() < deadline {
        events.extend(transport.poll_timeout(Duration::from_millis(50)));
        if done(&events) {
            break;
        }
    }
    events
}

fn has_connected(events: &[TcpTransportEvent], expected: &GuidPrefix) -> bool {
    events
        .iter()
        .any(|e| matches!(e, TcpTransportEvent::Connected { remote_guid, .. } if remote_guid == expected))
}

fn has_disconnected(events: &[TcpTransportEvent], expected: &GuidPrefix) -> bool {
    events
        .iter()
        .any(|e| matches!(e, TcpTransportEvent::Disconnected { remote_guid, .. } if remote_guid == expected))
}

/// Server-side refusal assertions shared by the negative cases.
fn assert_server_refused(handle: &IoThreadHandle, metrics: &TcpTransportMetrics, needle: &str) {
    let events = drain_server(handle, STEP_TIMEOUT);
    let accepted = events
        .iter()
        .any(|e| matches!(e, TcpEvent::ConnectionAccepted { .. }));
    assert!(
        !accepted,
        "server must never report ConnectionAccepted: {events:?}"
    );
    let closed_with_tls_reason = events.iter().any(|e| {
        matches!(
            e,
            TcpEvent::ConnectionClosed { reason: Some(reason), .. }
                if reason.contains("TLS") && reason.contains(needle)
        )
    });
    assert!(
        closed_with_tls_reason,
        "server must close with a TLS reason containing {needle:?}: {events:?}"
    );
    let snapshot = metrics.snapshot();
    assert_eq!(
        snapshot.active_connections, 0,
        "refused handshake must leave no active connection (and never underflow)"
    );
    assert_eq!(
        snapshot.connections_established, 0,
        "a client refused by the mTLS verifier is not an established connection"
    );
}

fn run_rejection(server_tls: TlsConfig, client_tls: TlsConfig, needle: &str) {
    let (mut server, addr, metrics) = spawn_server(server_tls);
    let client = dialer(client_tls, addr);
    let server_guid = guid(0x5);
    client.connect(server_guid, addr).expect("connect issued");

    // TLS 1.3: the dialer may see Connected first; it must then see Disconnected.
    let events = collect_dialer(&client, STEP_TIMEOUT, |evs| {
        has_disconnected(evs, &server_guid)
    });
    assert!(
        has_disconnected(&events, &server_guid),
        "dialer must be disconnected after the server refuses the certificate: {events:?}"
    );
    assert_eq!(client.connection_count(), 0);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, TcpTransportEvent::MessageReceived { .. })),
        "no data may cross a refused mTLS connection"
    );

    assert_server_refused(&server, &metrics, needle);
    let _ = client.shutdown();
    let _ = server.shutdown();
}

#[test]
fn tcp_transport_mtls_connects_with_client_certificate() {
    let pki = pki();
    let (mut server, addr, metrics) = spawn_server(server_mtls(&[]));
    let client = dialer(
        client_cfg(Some((&pki.client_a_cert, &pki.client_a_key))),
        addr,
    );
    let server_guid = guid(0x5);
    client.connect(server_guid, addr).expect("connect issued");

    let events = collect_dialer(&client, STEP_TIMEOUT, |evs| {
        has_connected(evs, &server_guid)
    });
    assert!(
        has_connected(&events, &server_guid),
        "dialer must report Connected with the right client certificate: {events:?}"
    );

    // Server side: the handshake completed (ConnectionAccepted) and stays up.
    let server_events = drain_server(&server, QUIET_WINDOW);
    assert!(
        server_events
            .iter()
            .any(|e| matches!(e, TcpEvent::ConnectionAccepted { .. })),
        "server must report ConnectionAccepted: {server_events:?}"
    );
    assert!(
        !server_events
            .iter()
            .any(|e| matches!(e, TcpEvent::ConnectionClosed { .. })),
        "accepted mTLS connection must stay open: {server_events:?}"
    );
    assert_eq!(client.connection_count(), 1);
    assert!(!has_disconnected(
        &client.poll_timeout(QUIET_WINDOW),
        &server_guid
    ));
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.active_connections, 1);
    assert_eq!(snapshot.connections_established, 1);
    assert_eq!(client.metrics().connections_established, 1);

    let _ = client.shutdown();
    let _ = server.shutdown();
}

#[test]
fn tcp_transport_mtls_rejects_anonymous_client() {
    run_rejection(server_mtls(&[]), client_cfg(None), "no certificates");
}

#[test]
fn tcp_transport_mtls_rejects_wrong_ca_client() {
    let pki = pki();
    run_rejection(
        server_mtls(&[]),
        client_cfg(Some((&pki.client_b_cert, &pki.client_b_key))),
        "UnknownIssuer",
    );
}

#[test]
fn tcp_transport_mtls_rejects_revoked_client() {
    let pki = pki();
    run_rejection(
        server_mtls(&[&pki.crl_a_revoking_client_a]),
        client_cfg(Some((&pki.client_a_cert, &pki.client_a_key))),
        "Revoked",
    );
}

// ---------------------------------------------------------------------------
// Bulk transfer over the mTLS data path.
//
// These two guard the edge-triggered readiness contract that `IoThread` has to
// honour on BOTH platforms. mio never re-arms a source by itself: on Linux the
// kernel supplies a fresh edge for every NEW arrival, and on Windows the only
// re-arm hook is an I/O operation returning `WouldBlock`. Doing one read (or
// one write pass) per readiness event therefore loses whatever did not fit in
// that single operation, with nothing left to wake the thread.
//
// Both cases are red on a host Linux run, which is why they live here and not
// only in the Windows gate: lane W3's four mTLS cases are the Windows
// corroboration, not the sole proof.
// ---------------------------------------------------------------------------

/// Connect an mTLS pair, send `size` bytes from the dialer, and return what the
/// server made of it.
fn bulk_transfer(size: usize) -> Result<(), String> {
    let pki = pki();
    let (mut server, addr, _metrics) = spawn_server(server_mtls(&[]));
    let client = dialer(
        client_cfg(Some((&pki.client_a_cert, &pki.client_a_key))),
        addr,
    );
    let server_guid = guid(0x5);
    client.connect(server_guid, addr).expect("connect issued");
    let events = collect_dialer(&client, STEP_TIMEOUT, |evs| {
        has_connected(evs, &server_guid)
    });
    if !has_connected(&events, &server_guid) {
        return Err(format!("dialer never connected: {events:?}"));
    }
    // Swallow ConnectionAccepted so the loop below only sees data events.
    let _ = drain_server(&server, Duration::from_millis(200));

    let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    client.send(&server_guid, &payload).expect("send issued");

    let deadline = Instant::now() + BULK_TIMEOUT;
    let mut delivered: Option<Vec<u8>> = None;
    let mut closed: Option<String> = None;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match server.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Some(TcpEvent::MessageReceived { payload, .. }) => {
                delivered = Some(payload);
                break;
            }
            Some(TcpEvent::ConnectionClosed { reason, .. }) => {
                closed = Some(format!("{reason:?}"));
                break;
            }
            Some(_) => {}
            None => {}
        }
        // Keep the dialer's event queue moving so its io thread is not blocked
        // on a full channel while we wait.
        let _ = client.poll_timeout(Duration::from_millis(10));
    }

    let _ = client.shutdown();
    let _ = server.shutdown();

    match (delivered, closed) {
        (Some(got), _) if got == payload => Ok(()),
        (Some(got), _) => Err(format!(
            "server delivered {} of {size} bytes (content mismatch or short frame)",
            got.len()
        )),
        (None, Some(reason)) => Err(format!(
            "server closed the connection mid-transfer instead of delivering \
             {size} bytes: {reason}"
        )),
        (None, None) => Err(format!(
            "server delivered nothing for {size} bytes within {BULK_TIMEOUT:?} \
             (readiness stall: the socket was never re-armed)"
        )),
    }
}

/// A TLS record larger than one `read_tls` call must still be delivered.
///
/// rustls reads ciphertext in 4 KiB chunks, so a 16 KiB message needs several
/// `read_tls` calls; a single call per readable event leaves the tail unread
/// with no further edge coming: nothing is delivered, deterministically, from
/// 4096 bytes up.
///
/// Sized under rustls' 64 KiB outgoing buffer on purpose: above that the WRITE
/// side has its own resume requirement, covered by the next test.
#[test]
fn tls_read_path_delivers_a_record_split_across_reads() {
    if let Err(e) = bulk_transfer(16 * 1024) {
        panic!("16 KiB mTLS message must arrive whole: {e}");
    }
}

/// Several messages that arrive in ONE readiness event must ALL be delivered.
///
/// Distinct failure mode from the two above, and the one they cannot see: a
/// drain that loops `read_tls` to `WouldBlock` correctly can still emit only
/// the FIRST complete frame it decodes and leave the rest sitting in the
/// plaintext buffer. On Linux the next arrival supplies a fresh edge and the
/// backlog trickles out; on Windows nothing re-arms the source and the
/// remainder is stuck until the peer happens to send again.
///
/// HONEST SCOPE: this test cannot FORCE the kernel to coalesce, so it does not
/// assert that one wake carried everything. It sends `MESSAGES` small frames
/// back to back without waiting for any of them, which makes coalescing the
/// common case, and it asserts that every frame arrives whole and in order. A
/// per-event emit limit is red here in the coalesced case and merely slow in
/// the uncoalesced one, so a failure is a real defect and a pass is evidence,
/// not a proof of the scheduling.
///
/// Test shape suggested by a peer session after an unrelated GPU kernel bug of
/// the same family (a heuristic that depended on the shape of the call rather
/// than on the data): the case that catches this family is never the nominal
/// one, it is the one that forces an unusual call shape.
#[test]
fn tls_read_path_delivers_every_message_of_a_coalesced_wake() {
    const MESSAGES: usize = 8;
    const BODY: usize = 512;

    let pki = pki();
    let (mut server, addr, _metrics) = spawn_server(server_mtls(&[]));
    let client = dialer(
        client_cfg(Some((&pki.client_a_cert, &pki.client_a_key))),
        addr,
    );
    let server_guid = guid(0x6);
    client.connect(server_guid, addr).expect("connect issued");
    let events = collect_dialer(&client, STEP_TIMEOUT, |evs| {
        has_connected(evs, &server_guid)
    });
    assert!(
        has_connected(&events, &server_guid),
        "dialer never connected: {events:?}"
    );
    let _ = drain_server(&server, Duration::from_millis(200));

    // Distinct bodies so an out-of-order or duplicated delivery is visible.
    let payloads: Vec<Vec<u8>> = (0..MESSAGES)
        .map(|m| (0..BODY).map(|i| ((m * 31 + i) % 251) as u8).collect())
        .collect();

    // Back to back, no read in between: the point is to let them pile up in
    // the server's socket buffer and be reported by as few events as possible.
    for payload in &payloads {
        client.send(&server_guid, payload).expect("send issued");
    }

    let deadline = Instant::now() + BULK_TIMEOUT;
    let mut got: Vec<Vec<u8>> = Vec::with_capacity(MESSAGES);
    let mut closed: Option<String> = None;
    while got.len() < MESSAGES {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match server.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Some(TcpEvent::MessageReceived { payload, .. }) => got.push(payload),
            Some(TcpEvent::ConnectionClosed { reason, .. }) => {
                closed = Some(format!("{reason:?}"));
                break;
            }
            Some(_) => {}
            None => {}
        }
        let _ = client.poll_timeout(Duration::from_millis(10));
    }

    let _ = client.shutdown();
    let _ = server.shutdown();

    if let Some(reason) = closed {
        panic!(
            "server closed mid-burst after {} of {MESSAGES} messages: {reason}",
            got.len()
        );
    }
    assert_eq!(
        got.len(),
        MESSAGES,
        "server delivered {} of {MESSAGES} back-to-back messages within {BULK_TIMEOUT:?} \
         (a per-event emit limit strands the rest of a coalesced wake)",
        got.len()
    );
    assert_eq!(
        got, payloads,
        "every message must arrive whole and in send order"
    );
}

/// A message larger than rustls' 64 KiB outgoing buffer must still complete.
///
/// `Writer::write` returns `Ok(0)` when rustls' `sendable_tls` is at its limit.
/// That is a buffer-full signal, not socket backpressure, so nothing re-arms
/// the source and the remainder of the send queue must be pumped by the sender
/// itself. RED with only the read-side drain in place (nothing delivered).
#[test]
fn tls_write_path_resumes_past_the_rustls_buffer_limit() {
    if let Err(e) = bulk_transfer(256 * 1024) {
        panic!("256 KiB mTLS message must arrive whole: {e}");
    }
}

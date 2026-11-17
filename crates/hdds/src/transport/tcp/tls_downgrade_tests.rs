// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Plaintext-downgrade refusal: a TLS-enabled I/O thread whose role slot has
//! no rustls configuration must refuse, never fall back to cleartext.
//!
//! `TcpConfig::validate` already refuses such configurations at
//! `TcpTransport::new`; these tests drive `IoThread::spawn` directly (no
//! validation) to prove the runtime guard on its own.

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::io_thread::{IoThread, IoThreadHandle, TcpEvent};
use super::metrics::TcpTransportMetrics;
use super::tls::TlsConfig;
use super::tls_test_pki::TestPki;
use super::{TcpConfig, TcpRole};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

fn server_only_tls() -> TlsConfig {
    let pki = TestPki::shared();
    TlsConfig::server()
        .with_cert_pem(pki.server_a_cert.clone())
        .with_key_pem(pki.server_a_key.clone())
        .build()
        .expect("server config")
}

fn client_only_tls() -> TlsConfig {
    let pki = TestPki::shared();
    TlsConfig::client()
        .with_root_cert_pem(pki.ca_a_cert.clone())
        .build()
        .expect("client config")
}

fn drain(handle: &IoThreadHandle, window: Duration) -> Vec<TcpEvent> {
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

/// Poll the failure counter to a deadline. The I/O thread records the failure
/// before it sends the event, so this normally returns on the first read; the
/// deadline only covers a scheduling hiccup instead of turning a security
/// gate into a flaky one.
fn wait_for_failed_count(metrics: &TcpTransportMetrics, expected: u64) -> u64 {
    let deadline = Instant::now() + STEP_TIMEOUT;
    loop {
        let seen = metrics.snapshot().connections_failed;
        if seen >= expected || Instant::now() >= deadline {
            return seen;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_for_error(handle: &IoThreadHandle, needle: &str) -> Vec<TcpEvent> {
    let deadline = Instant::now() + STEP_TIMEOUT;
    let mut events = Vec::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        match handle.recv_timeout(remaining) {
            Some(ev) => {
                let hit = matches!(&ev, TcpEvent::Error { error, .. } if error.contains(needle));
                events.push(ev);
                if hit {
                    return events;
                }
            }
            None => break,
        }
    }
    panic!("expected a TcpEvent::Error containing {needle:?}, got {events:?}");
}

#[test]
fn tls_enabled_transport_refuses_plaintext_dial_without_client_config() {
    // A plain listener stands in for the peer; it must never see a connection.
    let peer = TcpListener::bind("127.0.0.1:0").expect("bind");
    peer.set_nonblocking(true).expect("nonblocking");
    let peer_addr: SocketAddr = peer.local_addr().expect("addr");

    let config = TcpConfig {
        enabled: true,
        listen_port: 0,
        listen_address: Some([127, 0, 0, 1].into()),
        role: TcpRole::Auto,
        tls_enabled: true,
        tls_config: Some(server_only_tls()),
        ..Default::default()
    };
    assert!(
        config.validate().is_err(),
        "validate() must refuse this config"
    );
    let metrics = Arc::new(TcpTransportMetrics::new());
    let mut handle = IoThread::spawn(config, Arc::clone(&metrics)).expect("io thread");
    assert!(matches!(
        handle.recv_timeout(STEP_TIMEOUT),
        Some(TcpEvent::Started { .. })
    ));

    let conn_id = handle.connect(peer_addr).expect("connect command");
    let events = wait_for_error(&handle, "refusing plaintext dial");
    assert!(events.iter().any(|e| matches!(
        e,
        TcpEvent::Error { conn_id: Some(id), .. } if *id == conn_id
    )));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, TcpEvent::ConnectionEstablished { .. })),
        "no plaintext connection may be established: {events:?}"
    );
    assert_eq!(
        wait_for_failed_count(&metrics, 1),
        1,
        "the refused dial must be counted as a failed connection"
    );

    // The peer never received a TCP connection at all.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        peer.accept().is_err(),
        "the peer must not see a plaintext connection"
    );
    let _ = handle.shutdown();
}

#[test]
fn tls_enabled_transport_refuses_plaintext_accept_without_server_config() {
    let config = TcpConfig {
        enabled: true,
        listen_port: 0,
        listen_address: Some([127, 0, 0, 1].into()),
        role: TcpRole::ServerOnly,
        tls_enabled: true,
        tls_config: Some(client_only_tls()),
        ..Default::default()
    };
    assert!(
        config.validate().is_err(),
        "validate() must refuse this config"
    );
    let metrics = Arc::new(TcpTransportMetrics::new());
    let mut handle = IoThread::spawn(config, Arc::clone(&metrics)).expect("io thread");
    let addr = match handle.recv_timeout(STEP_TIMEOUT) {
        Some(TcpEvent::Started {
            local_addr: Some(addr),
        }) => addr,
        other => panic!("expected Started with a listener address, got {other:?}"),
    };

    let mut plain = TcpStream::connect(addr).expect("plain TCP connect");
    plain
        .set_read_timeout(Some(STEP_TIMEOUT))
        .expect("read timeout");

    let events = wait_for_error(&handle, "refusing plaintext accept");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, TcpEvent::ConnectionAccepted { .. })),
        "no plaintext connection may be accepted: {events:?}"
    );

    // The server dropped the stream: the plain client reads EOF or a reset,
    // never a byte.
    let mut buf = [0u8; 8];
    match plain.read(&mut buf) {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("plain client received {n} bytes on a refused connection"),
    }
    assert_eq!(metrics.snapshot().active_connections, 0);
    assert!(drain(&handle, Duration::from_millis(200))
        .iter()
        .all(|e| !matches!(e, TcpEvent::ConnectionAccepted { .. })));
    let _ = handle.shutdown();
}

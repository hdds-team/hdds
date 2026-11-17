// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Mutual-TLS handshake proofs at the `TlsAcceptor` / `TlsConnector` level.
//!
//! These prove the rustls `ServerConfig` produced by `TlsConfigBuilder`:
//! anonymous clients, clients from a foreign CA and revoked clients are
//! refused, the configured client is accepted. The production I/O-thread
//! proof lives in `tls_transport_tests.rs`.
//!
//! Every test runs on a 127.0.0.1:0 loopback pair with blocking sockets and a
//! bounded wait on the assertion side, so a regression fails on the step
//! timeout instead of hanging the suite. The handshake itself is bounded too:
//! see `accept_against_a_silent_peer_times_out`.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::tls::{TlsAcceptor, TlsConfig, TlsConnector, TlsStream, TlsVersion};
use super::tls_test_pki::TestPki;

const STEP_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
/// Handshake budget used by the bounded-handshake proofs. Short enough that a
/// regression (an unbounded loop) fails on the step timeout instead.
const HANDSHAKE_BUDGET: Duration = Duration::from_millis(300);

fn pki() -> &'static TestPki {
    TestPki::shared()
}

fn server_plain() -> TlsConfig {
    let pki = pki();
    TlsConfig::server()
        .with_cert_pem(pki.server_a_cert.clone())
        .with_key_pem(pki.server_a_key.clone())
        .build()
        .expect("plain server config")
}

fn server_mtls_with_crls(crls: &[&[u8]]) -> TlsConfig {
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

fn server_mtls() -> TlsConfig {
    server_mtls_with_crls(&[])
}

fn client_anonymous() -> TlsConfig {
    let pki = pki();
    TlsConfig::client()
        .with_root_cert_pem(pki.ca_a_cert.clone())
        .build()
        .expect("anonymous client config")
}

fn client_with(cert: &[u8], key: &[u8]) -> TlsConfig {
    let pki = pki();
    TlsConfig::client()
        .with_root_cert_pem(pki.ca_a_cert.clone())
        .with_cert_pem(cert.to_vec())
        .with_key_pem(key.to_vec())
        .build()
        .expect("client config with identity")
}

fn client_a() -> TlsConfig {
    let pki = pki();
    client_with(&pki.client_a_cert, &pki.client_a_key)
}

fn client_b() -> TlsConfig {
    let pki = pki();
    client_with(&pki.client_b_cert, &pki.client_b_key)
}

/// Outcome of one loopback handshake attempt.
struct Handshake {
    server: io::Result<TlsStream>,
    client: io::Result<TlsStream>,
}

/// Run a full handshake on a loopback pair, each side on its own thread.
fn handshake(server_cfg: TlsConfig, client_cfg: TlsConfig) -> Handshake {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");

    let (server_tx, server_rx) = mpsc::channel();
    thread::spawn(move || {
        let acceptor = TlsAcceptor::new(&server_cfg).expect("acceptor");
        let result = listener.accept().and_then(|(stream, _)| {
            stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
            stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
            acceptor.accept(stream)
        });
        let _ = server_tx.send(result);
    });

    let (client_tx, client_rx) = mpsc::channel();
    thread::spawn(move || {
        let connector = TlsConnector::new(&client_cfg).expect("connector");
        let result = TcpStream::connect(addr).and_then(|stream| {
            stream.set_read_timeout(Some(SOCKET_TIMEOUT))?;
            stream.set_write_timeout(Some(SOCKET_TIMEOUT))?;
            connector.connect("localhost", stream)
        });
        let _ = client_tx.send(result);
    });

    let server = server_rx
        .recv_timeout(STEP_TIMEOUT)
        .expect("server handshake must finish (ok or err) within the step timeout");
    let client = client_rx
        .recv_timeout(STEP_TIMEOUT)
        .expect("client handshake must finish (ok or err) within the step timeout");
    Handshake { server, client }
}

/// After a server-side refusal the client, which may have finished its own
/// TLS 1.3 handshake already, must see an error (alert or EOF) on its next
/// read and never receive application data.
fn assert_client_sees_refusal(client: io::Result<TlsStream>) {
    match client {
        Err(_) => {}
        Ok(mut stream) => {
            let mut buf = [0u8; 16];
            let result = stream.read(&mut buf);
            match result {
                Ok(0) => {}
                Ok(n) => panic!("rejected client must not receive data, got {n} bytes"),
                Err(e) => assert_ne!(
                    e.kind(),
                    io::ErrorKind::WouldBlock,
                    "socket timeout instead of a TLS refusal: {e}"
                ),
            }
        }
    }
}

fn server_error_string(result: io::Result<TlsStream>) -> String {
    match result {
        Ok(_) => panic!("server must refuse the handshake"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn mtls_client_without_certificate_is_rejected() {
    let hs = handshake(server_mtls(), client_anonymous());
    let err = server_error_string(hs.server);
    assert!(
        err.contains("no certificates"),
        "server must report NoCertificatesPresented, got: {err}"
    );
    assert_client_sees_refusal(hs.client);
}

#[test]
fn mtls_client_with_certificate_from_wrong_ca_is_rejected() {
    let hs = handshake(server_mtls(), client_b());
    let err = server_error_string(hs.server);
    assert!(
        err.contains("UnknownIssuer"),
        "server must report an unknown issuer, got: {err}"
    );
    assert_client_sees_refusal(hs.client);
}

#[test]
fn mtls_client_with_certificate_from_configured_ca_is_accepted() {
    let hs = handshake(server_mtls(), client_a());
    let mut server = hs.server.expect("server accepts client-a");
    let mut client = hs.client.expect("client-a completes the handshake");
    assert!(server.is_handshake_complete());
    assert!(client.is_handshake_complete());
    assert_eq!(server.alpn_protocol(), Some(&b"dds"[..]));
    assert_eq!(client.alpn_protocol(), Some(&b"dds"[..]));

    // Bytes round-trip in both directions over the mTLS session.
    client.write_all(b"ping").expect("client write");
    client.flush().expect("client flush");
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).expect("server read");
    assert_eq!(&buf, b"ping");

    server.write_all(b"pong").expect("server write");
    server.flush().expect("server flush");
    client.read_exact(&mut buf).expect("client read");
    assert_eq!(&buf, b"pong");
}

#[test]
fn server_without_require_client_cert_accepts_anonymous_client() {
    // Documented default: a plain TLS server never asks for a client certificate.
    let hs = handshake(server_plain(), client_anonymous());
    let server = hs.server.expect("plain server accepts an anonymous client");
    let client = hs.client.expect("anonymous client completes");
    assert!(server.is_handshake_complete());
    assert!(client.is_handshake_complete());
}

#[test]
fn mtls_rejection_closes_the_tcp_stream() {
    // The refused TlsStream is dropped by the server thread; the client's
    // socket must observe the close (alert or EOF) promptly, not sit until its
    // own read timeout expires.
    let hs = handshake(server_mtls(), client_anonymous());
    assert!(hs.server.is_err());
    let started = Instant::now();
    assert_client_sees_refusal(hs.client);
    assert!(
        started.elapsed() < SOCKET_TIMEOUT,
        "the client learned of the refusal only from its own socket timeout"
    );
}

/// A peer that opens the TCP connection and then says nothing must not pin the
/// accepting thread: the handshake is bounded and fails with `TimedOut`.
#[test]
fn accept_against_a_silent_peer_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let cfg = server_mtls();

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let acceptor = TlsAcceptor::new(&cfg).expect("acceptor");
        let result = listener.accept().and_then(|(stream, _)| {
            // No read timeout on purpose: the handshake bound must hold on a
            // plain blocking socket too.
            acceptor.accept_with_timeout(stream, HANDSHAKE_BUDGET)
        });
        let _ = tx.send(result.map(|_| ()));
    });

    // Connect and stay silent for the whole test.
    let _silent = TcpStream::connect(addr).expect("plain connect");
    let started = Instant::now();
    let result = rx
        .recv_timeout(STEP_TIMEOUT)
        .expect("the accepting thread must return, not hang");
    let err = result.expect_err("a silent peer cannot complete a handshake");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(
        started.elapsed() < STEP_TIMEOUT,
        "handshake bound did not fire in time"
    );
}

/// The same bound on the dialing side: a server that accepts the TCP
/// connection and never speaks TLS yields `TimedOut`.
#[test]
fn connect_against_a_silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    // Hold the accepted socket open, silent, for the life of the test.
    let keeper = thread::spawn(move || listener.accept().map(|(stream, _)| stream));

    // The dial runs on its own thread so an unbounded handshake fails the
    // test on the step timeout instead of hanging the suite.
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let connector = TlsConnector::new(&client_anonymous()).expect("connector");
        let result = TcpStream::connect(addr).and_then(|stream| {
            connector
                .connect_with_timeout("localhost", stream, HANDSHAKE_BUDGET)
                .map(|_| ())
        });
        let _ = tx.send(result);
    });

    let started = Instant::now();
    let result = rx
        .recv_timeout(STEP_TIMEOUT)
        .expect("the dialing thread must return, not hang");
    let err = result.expect_err("a silent server cannot complete a handshake");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    assert!(
        started.elapsed() < STEP_TIMEOUT,
        "handshake bound did not fire in time"
    );
    let _ = keeper.join();
}

#[test]
fn client_with_private_ca_trusts_only_that_ca() {
    // A client configured with CA-B must refuse server-a (issued by CA-A):
    // explicit roots replace system roots and are the only trust anchors.
    let pki = pki();
    let client_trusting_b = TlsConfig::client()
        .with_root_cert_pem(pki.ca_b_cert.clone())
        .build()
        .expect("client config");
    let hs = handshake(server_plain(), client_trusting_b);
    let err = match hs.client {
        Err(e) => e,
        Ok(_) => panic!("client trusting CA-B must refuse a CA-A server certificate"),
    };
    assert!(
        err.to_string().contains("UnknownIssuer"),
        "expected UnknownIssuer, got: {err}"
    );
    assert!(hs.server.is_err(), "server must see the client's alert");

    // Same client trusting CA-A completes (control).
    let hs = handshake(server_plain(), client_anonymous());
    assert!(hs.client.is_ok());
    assert!(hs.server.is_ok());
}

#[test]
fn mtls_revoked_client_certificate_is_rejected() {
    let pki = pki();
    let hs = handshake(
        server_mtls_with_crls(&[&pki.crl_a_revoking_client_a]),
        client_a(),
    );
    let err = server_error_string(hs.server);
    assert!(
        err.contains("Revoked"),
        "server must report a revoked certificate, got: {err}"
    );
    assert_client_sees_refusal(hs.client);
}

#[test]
fn mtls_unrevoked_client_certificate_passes_crl_check() {
    let pki = pki();
    let hs = handshake(server_mtls_with_crls(&[&pki.crl_a_empty]), client_a());
    assert!(hs.server.is_ok(), "client-a is not on the CRL");
    assert!(hs.client.is_ok());
}

#[test]
fn mtls_stale_crl_refuses_every_client() {
    // Fail closed: a CRL past its nextUpdate cannot vouch for anyone.
    let pki = pki();
    let hs = handshake(server_mtls_with_crls(&[&pki.crl_a_expired]), client_a());
    let err = server_error_string(hs.server);
    assert!(
        err.contains("revocation list expired"),
        "server must report an expired CRL, got: {err}"
    );
    assert_client_sees_refusal(hs.client);
}

#[test]
fn read_skips_plaintext_free_records_after_handshake() {
    // Under TLS 1.3 the server sends NewSessionTicket records right after the
    // handshake, before any application data. A single TlsStream::read on the
    // client must step over them and return the byte instead of a spurious
    // WouldBlock with the data still queued in the kernel buffer.
    let hs = handshake(server_plain(), client_anonymous());
    let mut server = hs.server.expect("server");
    let mut client = hs.client.expect("client");
    server.write_all(b"t").expect("server write");
    server.flush().expect("server flush");
    let mut byte = [0u8; 1];
    let n = client
        .read(&mut byte)
        .expect("first read after the handshake must deliver application data");
    assert_eq!((n, byte[0]), (1, b't'));
}

// ----------------------------------------------------------------------------
// Protocol version bounds and session resumption (applied, not just recorded)
// ----------------------------------------------------------------------------

fn server_plain_with(
    f: impl FnOnce(super::tls::TlsConfigBuilder) -> super::tls::TlsConfigBuilder,
) -> TlsConfig {
    let pki = pki();
    f(TlsConfig::server()
        .with_cert_pem(pki.server_a_cert.clone())
        .with_key_pem(pki.server_a_key.clone()))
    .build()
    .expect("server config")
}

fn client_anonymous_with(
    f: impl FnOnce(super::tls::TlsConfigBuilder) -> super::tls::TlsConfigBuilder,
) -> TlsConfig {
    let pki = pki();
    f(TlsConfig::client().with_root_cert_pem(pki.ca_a_cert.clone()))
        .build()
        .expect("client config")
}

#[test]
fn max_version_tls12_negotiates_tls12() {
    let server = server_plain_with(|b| b.with_max_version(TlsVersion::Tls12));
    let hs = handshake(server, client_anonymous());
    let server = hs.server.expect("TLS 1.2-capped server accepts");
    let client = hs.client.expect("default client negotiates TLS 1.2");
    assert_eq!(server.protocol_version(), Some(TlsVersion::Tls12));
    assert_eq!(client.protocol_version(), Some(TlsVersion::Tls12));

    // Same cap on the client side.
    let client = client_anonymous_with(|b| b.with_max_version(TlsVersion::Tls12));
    let hs = handshake(server_plain(), client);
    assert_eq!(
        hs.server
            .expect("server accepts a TLS 1.2 client")
            .protocol_version(),
        Some(TlsVersion::Tls12)
    );
    assert_eq!(
        hs.client.expect("client completes").protocol_version(),
        Some(TlsVersion::Tls12)
    );

    // Control: the defaults negotiate TLS 1.3.
    let hs = handshake(server_plain(), client_anonymous());
    assert_eq!(
        hs.server.expect("default server").protocol_version(),
        Some(TlsVersion::Tls13)
    );
    assert_eq!(
        hs.client.expect("default client").protocol_version(),
        Some(TlsVersion::Tls13)
    );
}

#[test]
fn min_version_tls13_refuses_tls12_only_client() {
    let server = server_plain_with(|b| b.with_min_version(TlsVersion::Tls13));
    let client = client_anonymous_with(|b| b.with_max_version(TlsVersion::Tls12));
    let hs = handshake(server, client);
    let err = server_error_string(hs.server);
    assert!(
        err.contains("Tls12NotOffered") || err.contains("incompatible"),
        "server must refuse a TLS 1.2-only client, got: {err}"
    );
    assert!(
        hs.client.is_err(),
        "a TLS 1.2-only client must not complete against a TLS 1.3-only server"
    );
}

/// Two consecutive handshakes with the same configurations (shared rustls
/// Arcs, so the client keeps whatever session material the first connection
/// produced). The first connection exchanges one byte so the client processes
/// the server's post-handshake session tickets. Returns the second
/// connection's (server, client) resumption verdicts.
fn second_handshake_resumed(
    server_cfg: &TlsConfig,
    client_cfg: &TlsConfig,
) -> (Option<bool>, Option<bool>) {
    let hs = handshake(server_cfg.clone(), client_cfg.clone());
    let mut server = hs.server.expect("first handshake, server");
    let mut client = hs.client.expect("first handshake, client");
    assert_eq!(server.is_resumed(), Some(false));
    assert_eq!(client.is_resumed(), Some(false));
    server.write_all(b"t").expect("server write");
    server.flush().expect("server flush");
    let mut byte = [0u8; 1];
    client
        .read_exact(&mut byte)
        .expect("client read (tickets + byte)");
    drop(server);
    drop(client);

    let hs = handshake(server_cfg.clone(), client_cfg.clone());
    let server = hs.server.expect("second handshake, server");
    let client = hs.client.expect("second handshake, client");
    (server.is_resumed(), client.is_resumed())
}

#[test]
fn resumption_enabled_resumes_second_session() {
    // Control for the two tests below: with the defaults the second
    // connection is a resumed handshake on both sides.
    let (server, client) = second_handshake_resumed(&server_plain(), &client_anonymous());
    assert_eq!(server, Some(true), "server must see a resumed handshake");
    assert_eq!(client, Some(true), "client must see a resumed handshake");
}

#[test]
fn resumption_disabled_never_resumes() {
    // Server side: no session storage, no tickets -> nothing to resume.
    let server = server_plain_with(|b| b.disable_session_resumption());
    let (s, c) = second_handshake_resumed(&server, &client_anonymous());
    assert_eq!(
        s,
        Some(false),
        "server with resumption disabled must run a full handshake"
    );
    assert_eq!(
        c,
        Some(false),
        "client must not observe a resumed handshake"
    );

    // Client side: never offers a previous session even to a ticketing server.
    let client = client_anonymous_with(|b| b.disable_session_resumption());
    let (s, c) = second_handshake_resumed(&server_plain(), &client);
    assert_eq!(
        s,
        Some(false),
        "server must run a full handshake for a non-resuming client"
    );
    assert_eq!(
        c,
        Some(false),
        "client with resumption disabled must run a full handshake"
    );
}

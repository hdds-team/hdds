// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! The write client against a fake InfluxDB v2 on loopback.
//!
//! Hermetic: a `std::net::TcpListener` on port 0 impersonates
//! `/api/v2/write`, records what it received and replies with whatever status
//! the test asks for. No InfluxDB, no network, no credentials.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use hdds_influx_sink::{InfluxError, InfluxHttpClient, WriteOutcome};

/// What the fake server saw.
#[derive(Debug, Clone, Default)]
struct Request {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

/// Serve `responses.len()` requests, replying with each status in turn, and
/// hand every request back over a channel. Returns the bound port.
fn spawn_fake_influx(responses: Vec<u16>) -> (u16, mpsc::Receiver<Request>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake influx");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for status in responses {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(_) => return,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            // Read the head, then exactly Content-Length bytes of body.
            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                raw.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&raw).to_string();
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let head = &text[..head_end];
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("Content-Length: ")
                                .and_then(|v| v.trim().parse().ok())
                        })
                        .unwrap_or(0);
                    if text.len() >= head_end + 4 + len {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let (head, body) = match text.split_once("\r\n\r\n") {
                Some((h, b)) => (h.to_string(), b.to_string()),
                None => (text.clone(), String::new()),
            };
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or("").to_string();
            let headers: Vec<String> = lines.map(|l| l.to_string()).collect();
            let _ = tx.send(Request {
                request_line,
                headers,
                body,
            });

            let payload = match status {
                204 => "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
                401 => "HTTP/1.1 401 Unauthorized\r\nContent-Length: 24\r\nConnection: close\r\n\r\n{\"code\":\"unauthorized\"}\n".to_string(),
                400 => "HTTP/1.1 400 Bad Request\r\nContent-Length: 21\r\nConnection: close\r\n\r\n{\"error\":\"bad line\"}\n".to_string(),
                _ => format!(
                    "HTTP/1.1 {} Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    status
                ),
            };
            let _ = stream.write_all(payload.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, rx)
}

fn client(port: u16) -> InfluxHttpClient {
    InfluxHttpClient::new(
        &format!("http://127.0.0.1:{}", port),
        "naskel",
        "telemetry",
        "s3cr3t-token",
    )
    .expect("client")
    .with_timeout(Duration::from_secs(5))
}

#[test]
fn write_sends_expected_request_line_headers_and_body() {
    let (port, rx) = spawn_fake_influx(vec![204]);
    let mut client = client(port);
    let lines = vec![
        "temperature,sensor_id=A value=21.5 1700000000000000000".to_string(),
        "temperature,sensor_id=B value=22.5 1700000000000000001".to_string(),
    ];
    assert_eq!(
        client.write_lines(&lines).expect("write"),
        WriteOutcome::Accepted
    );

    let req = rx.recv_timeout(Duration::from_secs(5)).expect("request");
    assert_eq!(
        req.request_line,
        "POST /api/v2/write?org=naskel&bucket=telemetry&precision=ns HTTP/1.1"
    );
    assert!(
        req.headers
            .iter()
            .any(|h| h == "Authorization: Token s3cr3t-token"),
        "missing token header: {:?}",
        req.headers
    );
    assert!(req
        .headers
        .iter()
        .any(|h| h.starts_with("Content-Length: ")));
    assert_eq!(req.body, lines.join("\n"));
}

#[test]
fn unauthorized_stops_the_sink() {
    let (port, rx) = spawn_fake_influx(vec![401]);
    let mut client = client(port);
    let lines = vec!["m value=1i 1".to_string()];
    match client.write_lines(&lines) {
        Err(InfluxError::Unauthorized(401)) => {}
        other => panic!("expected Unauthorized, got {:?}", other),
    }
    assert!(client.is_unauthorized());
    // The client stays refused and does not touch the socket again.
    rx.recv_timeout(Duration::from_secs(5)).expect("request");
    match client.write_lines(&lines) {
        Err(InfluxError::Unauthorized(_)) => {}
        other => panic!("expected a second Unauthorized, got {:?}", other),
    }
    assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
}

#[test]
fn https_is_refused_without_tls_and_accepted_with_it() {
    let result = InfluxHttpClient::new("https://influx.example:8086", "o", "b", "t");
    if cfg!(feature = "tls") {
        let client = result.expect("https must be usable when the tls feature is on");
        assert!(client.endpoint().tls);
    } else {
        match result {
            Ok(_) => panic!("https was accepted without the tls feature"),
            Err(e) => assert!(
                format!("{}", e).contains("tls"),
                "expected a tls hard error, got {}",
                e
            ),
        }
    }
}

#[test]
fn server_error_retries_then_keeps_the_batch() {
    // Three 500s with max_retries = 3: the client gives up and reports the
    // batch as kept, never as written.
    let (port, rx) = spawn_fake_influx(vec![500, 500, 500]);
    let mut client = client(port).with_max_retries(3);
    match client.write_lines(&["m value=1i 1".to_string()]) {
        Err(InfluxError::ServerUnavailable {
            status: 500,
            attempts: 3,
        }) => {}
        other => panic!("expected ServerUnavailable, got {:?}", other),
    }
    for _ in 0..3 {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("each attempt hits the server");
    }
    assert!(!client.is_unauthorized());
}

#[test]
fn a_recoverable_server_error_is_retried_and_then_accepted() {
    let (port, _rx) = spawn_fake_influx(vec![503, 204]);
    let mut client = client(port).with_max_retries(3);
    assert_eq!(
        client
            .write_lines(&["m value=1i 1".to_string()])
            .expect("write"),
        WriteOutcome::Accepted
    );
}

#[test]
fn a_rejected_batch_is_reported_with_the_server_body() {
    let (port, _rx) = spawn_fake_influx(vec![400]);
    let mut client = client(port);
    match client.write_lines(&["not line protocol".to_string()]) {
        Err(InfluxError::Rejected { status: 400, body }) => {
            assert!(body.contains("bad line"), "body was {:?}", body)
        }
        other => panic!("expected Rejected, got {:?}", other),
    }
}

#[test]
fn an_empty_batch_never_touches_the_network() {
    // Port 1 is not listening; an empty batch must not try to connect.
    let mut client = InfluxHttpClient::new("http://127.0.0.1:1", "o", "b", "t").expect("client");
    assert_eq!(
        client.write_lines(&[]).expect("empty"),
        WriteOutcome::Accepted
    );
}

/// The `tls` feature has to actually reach rustls.
///
/// It did not: `send` opened with an unconditional refusal for every https
/// endpoint, so the rustls code below it was unreachable and the crate linked
/// rustls and webpki-roots for nothing. The proof has to be observable
/// without a certificate authority, so it points the client at a plain TCP
/// server that answers with bytes no TLS peer would send: the write must fail
/// as a TLS exchange, never as "TLS transport is not compiled into this
/// build".
#[cfg(feature = "tls")]
#[test]
fn a_write_to_an_https_endpoint_goes_through_rustls() {
    use std::net::TcpListener;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake tls server");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            // Not a TLS record: rustls must reject the peer.
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n");
        }
    });

    let mut client = InfluxHttpClient::new(
        &format!("https://127.0.0.1:{}", port),
        "naskel",
        "telemetry",
        "s3cr3t-token",
    )
    .expect("an https client with the tls feature on")
    .with_timeout(Duration::from_secs(5))
    .with_max_retries(1);
    assert!(client.endpoint().tls);

    let err = client
        .write_lines(&["m value=1i 1".to_string()])
        .expect_err("a plaintext answer cannot satisfy a TLS client");
    let text = format!("{}", err);
    assert!(
        !text.contains("not compiled into this build"),
        "the tls feature is on and the client still refuses every https write: {}",
        text
    );
}

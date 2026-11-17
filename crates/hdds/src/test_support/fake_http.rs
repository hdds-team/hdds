// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Minimal in-process HTTP/1.1 server for hermetic backend tests.
//!
//! Cloud registry clients (Consul, AWS Cloud Map, Azure Table Storage) are
//! plain HTTP clients; this fake lets a test stand in for the registry on
//! `127.0.0.1:0` without a network, a container or a credential. It is
//! deliberately tiny: one connection at a time, `Connection: close` on
//! every response, requests parsed by method, target, headers and a
//! `Content-Length` body. That is all `reqwest` needs from a test peer.
//!
//! Every request is recorded (in order) so a test can assert what the
//! client sent; the handler can be swapped at any time so a test can flip
//! the registry from healthy to failing mid-run.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Largest request head (request line + headers) accepted.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// Largest request body accepted.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Per-connection socket timeout: a client that stalls cannot hang the
/// (single) accept loop for longer than this.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// One HTTP request as the fake saw it.
#[derive(Debug, Clone)]
pub struct FakeRequest {
    /// Request method (`GET`, `PUT`, ...), as sent.
    pub method: String,
    /// Request target, path plus optional query (`/v1/kv/x?dc=dc1`).
    pub target: String,
    /// Headers in wire order; names lower-cased, values trimmed.
    pub headers: Vec<(String, String)>,
    /// Body bytes (empty when there was no `Content-Length`).
    pub body: Vec<u8>,
}

impl FakeRequest {
    /// The target without its query string.
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    /// The query string without the `?`, if any.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, query)| query)
    }

    /// First header with this (case-insensitive) name.
    pub fn header(&self, name: &str) -> Option<&str> {
        let wanted = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == wanted)
            .map(|(_, value)| value.as_str())
    }

    /// The body as UTF-8 (lossy).
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// The response a handler returns.
#[derive(Debug, Clone)]
pub struct FakeResponse {
    /// HTTP status code.
    pub status: u16,
    /// Extra headers (`Content-Length` and `Connection` are added by the
    /// server).
    pub headers: Vec<(String, String)>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl FakeResponse {
    /// An empty response with this status.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A `text/plain` response.
    pub fn text(status: u16, body: &str) -> Self {
        Self::status(status)
            .with_header("Content-Type", "text/plain; charset=utf-8")
            .with_body(body.as_bytes())
    }

    /// An `application/json` response.
    pub fn json(status: u16, body: &str) -> Self {
        Self::status(status)
            .with_header("Content-Type", "application/json")
            .with_body(body.as_bytes())
    }

    /// Add a header.
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Replace the body.
    pub fn with_body(mut self, body: &[u8]) -> Self {
        self.body = body.to_vec();
        self
    }
}

/// A request handler: called on the server thread for every request.
pub type FakeHandler = Arc<dyn Fn(&FakeRequest) -> FakeResponse + Send + Sync>;

/// An HTTP/1.1 server bound to `127.0.0.1:0`, serving one connection at a
/// time on a background thread until dropped.
pub struct FakeHttpServer {
    addr: SocketAddr,
    handler: Arc<Mutex<FakeHandler>>,
    requests: Arc<Mutex<Vec<FakeRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeHttpServer {
    /// Bind a loopback port and start serving with `handler`.
    pub fn start<H>(handler: H) -> io::Result<Self>
    where
        H: Fn(&FakeRequest) -> FakeResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let handler: Arc<Mutex<FakeHandler>> = Arc::new(Mutex::new(Arc::new(handler)));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let thread_handler = Arc::clone(&handler);
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("hdds-fake-http".to_string())
            .spawn(move || {
                serve(&listener, &thread_handler, &thread_requests, &thread_stop);
            })?;

        Ok(Self {
            addr,
            handler,
            requests,
            stop,
            thread: Some(thread),
        })
    }

    /// The bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`, without a trailing slash.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Replace the handler; takes effect for the next request.
    pub fn set_handler<H>(&self, handler: H)
    where
        H: Fn(&FakeRequest) -> FakeResponse + Send + Sync + 'static,
    {
        *lock(&self.handler) = Arc::new(handler);
    }

    /// Every request served so far, in order.
    pub fn requests(&self) -> Vec<FakeRequest> {
        lock(&self.requests).clone()
    }

    /// Number of requests served so far.
    pub fn request_count(&self) -> usize {
        lock(&self.requests).len()
    }

    /// Forget the recorded requests.
    pub fn clear_requests(&self) {
        lock(&self.requests).clear();
    }
}

impl Drop for FakeHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock accept(): the loop re-checks the stop flag after every
        // connection, so one dummy connection ends it.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn serve(
    listener: &TcpListener,
    handler: &Mutex<FakeHandler>,
    requests: &Mutex<Vec<FakeRequest>>,
    stop: &AtomicBool,
) {
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(mut stream) = stream else {
            continue;
        };
        let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
        let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
        let _ = stream.set_nodelay(true);

        let response = match read_request(&mut stream) {
            Ok(Some(request)) => {
                let current = Arc::clone(&lock(handler));
                let response = current(&request);
                lock(requests).push(request);
                response
            }
            // Connection closed before a full request head: nothing to answer.
            Ok(None) => {
                let _ = stream.shutdown(Shutdown::Both);
                continue;
            }
            Err(error) => FakeResponse::text(400, &format!("bad request: {}", error)),
        };
        let _ = write_response(&mut stream, &response);
        let _ = stream.shutdown(Shutdown::Both);
    }
}

/// Read one request. `Ok(None)` when the peer closed before sending a
/// complete head (the drop() wake-up connection does exactly that).
fn read_request(stream: &mut TcpStream) -> io::Result<Option<FakeRequest>> {
    let mut buffer: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(end) = find_head_end(&buffer) {
            break end;
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too large",
            ));
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside the request head",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing target"))?
        .to_string();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported version {:?}", version),
        ));
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("malformed header line {:?}", line),
            ));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }

    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| {
            value
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad Content-Length"))
        })
        .transpose()?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }

    let mut body = buffer[head_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside the request body",
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(Some(FakeRequest {
        method,
        target,
        headers,
        body,
    }))
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn write_response(stream: &mut TcpStream, response: &FakeResponse) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason_phrase(response.status),
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A raw HTTP/1.1 client good enough to exercise the fake without
    /// pulling an HTTP crate into the always-on test surface.
    fn raw_request(addr: SocketAddr, request: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut stream = TcpStream::connect(addr).expect("connect to fake");
        stream.write_all(request).expect("write request");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("read response");
        let head_end = find_head_end(&response).expect("response head");
        let head = String::from_utf8_lossy(&response[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let status_line = lines.next().expect("status line");
        let status: u16 = status_line
            .split_whitespace()
            .nth(1)
            .expect("status code")
            .parse()
            .expect("numeric status");
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
            .collect();
        (status, headers, response[head_end + 4..].to_vec())
    }

    #[test]
    fn fake_parses_request_line_headers_and_content_length_body() {
        let server = FakeHttpServer::start(|request: &FakeRequest| {
            if request.method == "PUT" && request.path() == "/v1/kv/hdds/x" {
                FakeResponse::json(
                    200,
                    &format!(
                        r#"{{"echo":"{}","query":"{}"}}"#,
                        request.body_text(),
                        request.query().unwrap_or("")
                    ),
                )
            } else {
                FakeResponse::status(404)
            }
        })
        .expect("start fake");

        let body = br#"{"k":"v"}"#;
        let request = format!(
            "PUT /v1/kv/hdds/x?dc=dc1 HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            server.addr(),
            body.len()
        );
        let mut wire = request.into_bytes();
        wire.extend_from_slice(body);
        let (status, headers, response_body) = raw_request(server.addr(), &wire);
        assert_eq!(status, 200);
        assert_eq!(
            headers
                .iter()
                .find(|(name, _)| name == "content-type")
                .map(|(_, value)| value.as_str()),
            Some("application/json")
        );
        assert_eq!(
            String::from_utf8_lossy(&response_body),
            r#"{"echo":"{"k":"v"}","query":"dc=dc1"}"#
        );

        let (status, _, _) =
            raw_request(server.addr(), b"GET /elsewhere HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(status, 404);

        let requests = server.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method, "PUT");
        assert_eq!(requests[0].target, "/v1/kv/hdds/x?dc=dc1");
        assert_eq!(requests[0].header("content-type"), Some("application/json"));
        assert_eq!(requests[0].body, body);
        assert_eq!(requests[1].method, "GET");
        assert!(requests[1].body.is_empty());
    }

    #[test]
    fn handler_swap_takes_effect_and_drop_stops_the_thread() {
        let server = FakeHttpServer::start(|_: &FakeRequest| FakeResponse::text(200, "up"))
            .expect("start fake");
        let (status, _, body) = raw_request(server.addr(), b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!((status, body.as_slice()), (200, b"up".as_slice()));

        server.set_handler(|_: &FakeRequest| FakeResponse::text(503, "down"));
        let (status, _, body) = raw_request(server.addr(), b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!((status, body.as_slice()), (503, b"down".as_slice()));
        assert_eq!(server.request_count(), 2);

        // drop() joins the server thread; it must not hang on accept().
        let started = std::time::Instant::now();
        drop(server);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn malformed_head_gets_400_without_killing_the_server() {
        let server =
            FakeHttpServer::start(|_: &FakeRequest| FakeResponse::status(200)).expect("start fake");
        let (status, _, _) = raw_request(server.addr(), b"NOT-HTTP\r\n\r\n");
        assert_eq!(status, 400);
        let (status, _, _) = raw_request(server.addr(), b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(status, 200);
        assert_eq!(
            server.request_count(),
            1,
            "a rejected request is not recorded"
        );
    }
}

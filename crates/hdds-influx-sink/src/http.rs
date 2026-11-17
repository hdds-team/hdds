// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Minimal InfluxDB v2 write client on `std::net::TcpStream`.
//!
//! HTTP/1.1, one request per batch, `POST /api/v2/write?org=&bucket=&precision=ns`
//! with `Authorization: Token <token>`. No HTTP crate: the request is three
//! header lines and a body, and the only response fact that matters is the
//! status code.
//!
//! Failure policy, fail closed:
//! - an `https://` URL without the `tls` feature is a hard error at
//!   construction, never a silent downgrade to plaintext;
//! - 401 / 403 mark the client permanently unauthorized: the batch is kept,
//!   nothing else is attempted, and the caller is told to stop;
//! - 5xx is retried a bounded number of times and the batch is kept on
//!   failure, so a restarting InfluxDB does not eat samples;
//! - 4xx other than 401/403 (e.g. 400 on a malformed line) drops the batch,
//!   because retrying it would loop forever.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Errors the write client can produce.
#[derive(Debug)]
pub enum InfluxError {
    /// The configured URL cannot be used (bad scheme, missing host, or an
    /// https URL while the `tls` feature is off).
    Url(String),
    /// Socket or I/O failure.
    Io(std::io::Error),
    /// The server rejected the credentials (401 / 403). Terminal.
    Unauthorized(u16),
    /// The server rejected the payload (4xx other than 401/403).
    Rejected { status: u16, body: String },
    /// The server failed repeatedly (5xx) and the batch was kept.
    ServerUnavailable { status: u16, attempts: u32 },
    /// The response was not recognizable HTTP.
    MalformedResponse(String),
}

impl fmt::Display for InfluxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url(m) => write!(f, "influx url error: {}", m),
            Self::Io(e) => write!(f, "influx I/O error: {}", e),
            Self::Unauthorized(s) => write!(f, "influx refused the token (HTTP {})", s),
            Self::Rejected { status, body } => {
                write!(f, "influx rejected the batch (HTTP {}): {}", status, body)
            }
            Self::ServerUnavailable { status, attempts } => write!(
                f,
                "influx unavailable (HTTP {}) after {} attempts; batch kept",
                status, attempts
            ),
            Self::MalformedResponse(m) => write!(f, "malformed influx response: {}", m),
        }
    }
}

impl std::error::Error for InfluxError {}

impl From<std::io::Error> for InfluxError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// A parsed InfluxDB endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    /// Path prefix in front of `/api/v2/write` (empty for a bare host URL).
    pub prefix: String,
    pub tls: bool,
}

impl Endpoint {
    /// Parse `http://host:port[/prefix]`.
    ///
    /// `https://` is accepted only when the crate is built with the `tls`
    /// feature; otherwise it is a hard error, because falling back to
    /// plaintext would ship the auth token in the clear.
    pub fn parse(url: &str) -> Result<Self, InfluxError> {
        let (tls, rest) = if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            if !cfg!(feature = "tls") {
                return Err(InfluxError::Url(format!(
                    "{} is https but this build has no tls feature; \
                     rebuild hdds-influx-sink with --features tls or use http://",
                    url
                )));
            }
            (true, rest)
        } else {
            return Err(InfluxError::Url(format!(
                "{} has no http:// or https:// scheme",
                url
            )));
        };

        let (authority, prefix) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
            None => (rest, String::new()),
        };
        if authority.is_empty() {
            return Err(InfluxError::Url(format!("{} has no host", url)));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse::<u16>()
                    .map_err(|_| InfluxError::Url(format!("{} has a bad port", url)))?,
            ),
            None => (authority.to_string(), if tls { 443 } else { 80 }),
        };
        Ok(Self {
            host,
            port,
            prefix,
            tls,
        })
    }

    /// The request target for a write, including the query string.
    pub fn write_path(&self, org: &str, bucket: &str) -> String {
        format!(
            "{}/api/v2/write?org={}&bucket={}&precision=ns",
            self.prefix,
            percent_encode(org),
            percent_encode(bucket)
        )
    }
}

/// Percent-encode everything that is not an unreserved URL character.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{:02X}", other)),
        }
    }
    out
}

/// What happened to one write attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// InfluxDB accepted the batch (204).
    Accepted,
}

/// HTTP write client for InfluxDB v2.
#[derive(Debug)]
pub struct InfluxHttpClient {
    endpoint: Endpoint,
    org: String,
    bucket: String,
    token: String,
    timeout: Duration,
    max_retries: u32,
    /// Set once the server refuses the token; the client stops writing.
    unauthorized: bool,
}

impl InfluxHttpClient {
    /// Build a client from an InfluxDB v2 configuration.
    pub fn new(url: &str, org: &str, bucket: &str, token: &str) -> Result<Self, InfluxError> {
        Ok(Self {
            endpoint: Endpoint::parse(url)?,
            org: org.to_string(),
            bucket: bucket.to_string(),
            token: token.to_string(),
            timeout: Duration::from_secs(10),
            max_retries: 3,
            unauthorized: false,
        })
    }

    /// Build a client from the parsed YAML configuration.
    pub fn from_config(config: &crate::config::InfluxDbConfig) -> Result<Self, InfluxError> {
        Self::new(&config.url, &config.org, &config.bucket, &config.token)
    }

    /// Override the socket timeout (default 10 s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override how many times a 5xx is retried (default 3 attempts total).
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// True once the server has refused the token. The client stays refused.
    pub fn is_unauthorized(&self) -> bool {
        self.unauthorized
    }

    /// The endpoint this client talks to.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Write a batch of Line Protocol lines.
    ///
    /// The lines are joined with `\n`; an empty batch is a no-op.
    pub fn write_lines(&mut self, lines: &[String]) -> Result<WriteOutcome, InfluxError> {
        if lines.is_empty() {
            return Ok(WriteOutcome::Accepted);
        }
        if self.unauthorized {
            return Err(InfluxError::Unauthorized(401));
        }
        let body = lines.join("\n");
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let (status, response_body) = self.send(&body)?;
            match status {
                204 | 200 => return Ok(WriteOutcome::Accepted),
                401 | 403 => {
                    self.unauthorized = true;
                    return Err(InfluxError::Unauthorized(status));
                }
                s if (500..600).contains(&s) => {
                    if attempt >= self.max_retries {
                        return Err(InfluxError::ServerUnavailable {
                            status: s,
                            attempts: attempt,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(20 * attempt as u64));
                }
                s => {
                    return Err(InfluxError::Rejected {
                        status: s,
                        body: response_body,
                    })
                }
            }
        }
    }

    /// One HTTP request/response exchange. Returns (status, body).
    fn send(&self, body: &str) -> Result<(u16, String), InfluxError> {
        let addr = (self.endpoint.host.as_str(), self.endpoint.port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| InfluxError::Url(format!("{} does not resolve", self.endpoint.host)))?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        let request = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {host}:{port}\r\n\
             Authorization: Token {token}\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\
             Accept: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            path = self.endpoint.write_path(&self.org, &self.bucket),
            host = self.endpoint.host,
            port = self.endpoint.port,
            token = self.token,
            len = body.len(),
            body = body
        );
        let raw = if self.endpoint.tls {
            self.exchange_tls(stream, request.as_bytes())?
        } else {
            stream.write_all(request.as_bytes())?;
            stream.flush()?;
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw)?;
            raw
        };
        parse_response(&raw)
    }

    /// Same exchange over rustls. Only compiled with the `tls` feature; the
    /// non-TLS build never reaches here because [`Endpoint::parse`] refuses
    /// an https URL outright.
    #[cfg(feature = "tls")]
    fn exchange_tls(&self, stream: TcpStream, request: &[u8]) -> Result<Vec<u8>, InfluxError> {
        let server_name = rustls::pki_types::ServerName::try_from(self.endpoint.host.clone())
            .map_err(|e| {
                InfluxError::Url(format!(
                    "{} is not a TLS server name: {}",
                    self.endpoint.host, e
                ))
            })?;
        let mut conn = rustls::ClientConnection::new(tls_client_config(), server_name)
            .map_err(|e| InfluxError::MalformedResponse(format!("TLS handshake: {}", e)))?;
        let mut socket = stream;
        let mut tls = rustls::Stream::new(&mut conn, &mut socket);
        tls.write_all(request)?;
        tls.flush()?;
        let mut raw = Vec::new();
        match tls.read_to_end(&mut raw) {
            Ok(_) => {}
            // A server that closes without close_notify is common enough that
            // a complete response must not be thrown away over it.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => {}
            Err(e) => return Err(InfluxError::Io(e)),
        }
        Ok(raw)
    }

    #[cfg(not(feature = "tls"))]
    fn exchange_tls(&self, _stream: TcpStream, _request: &[u8]) -> Result<Vec<u8>, InfluxError> {
        Err(InfluxError::Url(
            "https requires the tls feature; this build has none".to_string(),
        ))
    }
}

/// Client config trusting the webpki root bundle. Built once.
#[cfg(feature = "tls")]
fn tls_client_config() -> std::sync::Arc<rustls::ClientConfig> {
    use std::sync::{Arc, OnceLock};
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    Arc::clone(CONFIG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("rustls default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(config)
    }))
}

/// Pull the status code and body out of an HTTP/1.1 response.
fn parse_response(raw: &[u8]) -> Result<(u16, String), InfluxError> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| InfluxError::MalformedResponse("empty response".to_string()))?;
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/") {
        return Err(InfluxError::MalformedResponse(format!(
            "status line {:?}",
            status_line
        )));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| InfluxError::MalformedResponse(format!("status line {:?}", status_line)))?;
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parsing() {
        let e = Endpoint::parse("http://localhost:8086").expect("parse");
        assert_eq!(e.host, "localhost");
        assert_eq!(e.port, 8086);
        assert_eq!(e.prefix, "");
        assert!(!e.tls);
        assert_eq!(
            e.write_path("my org", "my/bucket"),
            "/api/v2/write?org=my%20org&bucket=my%2Fbucket&precision=ns"
        );

        let e = Endpoint::parse("http://influx.example/influx/").expect("parse");
        assert_eq!(e.port, 80);
        assert_eq!(e.prefix, "/influx");

        assert!(Endpoint::parse("localhost:8086").is_err());
        assert!(Endpoint::parse("http://").is_err());
        assert!(Endpoint::parse("http://host:notaport").is_err());
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn https_without_the_tls_feature_is_an_error() {
        let err = Endpoint::parse("https://influx.example:8086").unwrap_err();
        assert!(format!("{}", err).contains("tls"), "{}", err);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn https_with_the_tls_feature_parses_and_defaults_to_443() {
        let e = Endpoint::parse("https://influx.example").expect("parse");
        assert!(e.tls);
        assert_eq!(e.port, 443);
    }

    #[test]
    fn response_parsing() {
        let (status, body) =
            parse_response(b"HTTP/1.1 204 No Content\r\nDate: x\r\n\r\n").expect("parse");
        assert_eq!(status, 204);
        assert_eq!(body, "");
        let (status, body) =
            parse_response(b"HTTP/1.1 400 Bad Request\r\n\r\n{\"error\":\"nope\"}").expect("parse");
        assert_eq!(status, 400);
        assert!(body.contains("nope"));
        assert!(parse_response(b"garbage").is_err());
    }
}

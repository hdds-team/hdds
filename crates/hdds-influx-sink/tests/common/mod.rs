// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! A fake InfluxDB v2 on loopback, shared by the DDS-wired sink tests.
//!
//! Hermetic: a `std::net::TcpListener` on port 0 answers `/api/v2/write` with
//! whatever status the test asks for and hands the request body back over a
//! channel. No InfluxDB, no network, no credentials.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Serve one response per entry of `statuses`, in order. Returns the bound
/// port and a channel carrying each request body.
pub fn spawn_fake_influx_statuses(statuses: Vec<u16>) -> (u16, mpsc::Receiver<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake influx");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for status in statuses {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(_) => return,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        raw.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&raw).to_string();
                        if let Some(head_end) = text.find("\r\n\r\n") {
                            let len: usize = text[..head_end]
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
                    Err(_) => break,
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let _ = tx.send(body);
            let response = if status == 204 {
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            } else {
                format!(
                    "HTTP/1.1 {} Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    status
                )
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (port, rx)
}

/// Every request answered with 204, `count` of them.
pub fn spawn_fake_influx(count: usize) -> (u16, mpsc::Receiver<String>) {
    spawn_fake_influx_statuses(vec![204; count])
}

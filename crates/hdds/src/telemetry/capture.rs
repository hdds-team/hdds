// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Live telemetry capture server for HDDS Viewer integration.
//!
//! Provides TCP server that streams telemetry frames to connected clients
//! and admin API integration for metrics extraction.

use super::export::encode_frame;
use super::metrics::{Frame, MetricsCollector, TAG_LATENCY_P50, TAG_LATENCY_P99};
use crate::admin::snapshot::MetricsSnapshot;
use crate::core::string_utils::format_string;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Telemetry exporter: binary fixed-width LE over TCP admin port.
///
/// Starts a TCP server on the specified port and pushes telemetry frames
/// to connected clients at 10 Hz (100ms interval).
pub struct Exporter {
    clients: Arc<Mutex<Vec<TcpStream>>>,
    shutdown: Arc<AtomicBool>,
}

impl Exporter {
    /// Start exporter on bind address + port.
    ///
    /// # Arguments
    /// - `bind_addr`: IP address to bind (e.g., "127.0.0.1")
    /// - `port`: TCP port (typically 4242)
    ///
    /// # Returns
    /// Exporter instance with background thread accepting clients.
    ///
    /// # Performance
    /// Non-blocking server, accepts multiple concurrent clients.
    pub fn start(bind_addr: &str, port: u16) -> io::Result<Self> {
        let addr = format_string(format_args!("{}:{}", bind_addr, port));
        let addr: SocketAddr = addr.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format_string(format_args!("Invalid address: {}", e)),
            )
        })?;

        // Create socket with reuse options to fix TIME_WAIT issue.
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

        // SO_REUSEADDR allows rapid rebind (fixes TIME_WAIT issue).
        socket.set_reuse_address(true)?;

        socket.bind(&addr.into())?;
        socket.listen(128)?; // backlog = 128 connections

        // Convert socket2::Socket to std::net::TcpListener.
        let listener: TcpListener = socket.into();
        listener.set_nonblocking(true)?;

        let clients = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let clients_clone = Arc::clone(&clients);
        let shutdown_clone = Arc::clone(&shutdown);

        // Spawn accept thread.
        thread::spawn(move || {
            accept_loop(listener, clients_clone, shutdown_clone);
        });

        Ok(Self { clients, shutdown })
    }

    /// Push telemetry frame to all connected clients.
    ///
    /// Encodes frame to binary LE format and sends to all clients.
    /// Disconnected clients are removed automatically.
    ///
    /// # Performance
    /// Target: < 10 us per push (encoding + TCP send).
    pub fn push(&self, frame: &Frame) {
        let bytes = match encode_frame(frame) {
            Ok(b) => b,
            Err(_) => return,
        };

        let mut clients = match self.clients.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[Exporter::push] clients lock poisoned, recovering");
                e.into_inner()
            }
        };

        // Send to all clients, remove disconnected ones.
        clients.retain_mut(|client| client.write_all(&bytes).is_ok());
    }

    /// Shutdown exporter and close all connections.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);

        // Close all client connections.
        let mut clients = match self.clients.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[Exporter::shutdown] clients lock poisoned, recovering");
                e.into_inner()
            }
        };
        clients.clear();
    }
}

fn accept_loop(
    listener: TcpListener,
    clients: Arc<Mutex<Vec<TcpStream>>>,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Try accept (non-blocking).
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Set stream to blocking for writes.
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true); // Disable Nagle for low-latency.

                let mut clients_guard = match clients.lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        log::debug!("[accept_loop] clients lock poisoned, recovering");
                        e.into_inner()
                    }
                };
                clients_guard.push(stream);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // No pending connections, sleep briefly.
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                // Other error, ignore and continue.
            }
        }
    }
}

// ===== Admin API Integration =====

/// Parse a telemetry frame into (sent, received, dropped, p50, p99) tuple.
pub fn parse_frame_fields(frame: &Frame) -> (u64, u64, u64, u64, u64) {
    let mut sent = 0;
    let mut recv = 0;
    let mut dropped = 0;
    let mut p50 = 0;
    let mut p99 = 0;

    for field in &frame.fields {
        match field.tag {
            10 => sent = field.value_u64,
            11 => recv = field.value_u64,
            12 => dropped = field.value_u64,
            TAG_LATENCY_P50 => p50 = field.value_u64,
            TAG_LATENCY_P99 => p99 = field.value_u64,
            unknown_tag => {
                // Log unknown telemetry tags so we can detect new metrics
                log::debug!(
                    "[telemetry] [!]  Unknown field tag: {} (value={})",
                    unknown_tag,
                    field.value_u64
                );
            }
        }
    }

    (sent, recv, dropped, p50, p99)
}

/// Extract metrics from a shared collector, recovering from poisoned locks.
pub fn extract_metrics_from_collector(
    epoch: u64,
    metrics: &Arc<Mutex<Option<Arc<MetricsCollector>>>>,
) -> MetricsSnapshot {
    let metrics_guard = match metrics.lock() {
        Ok(lock) => lock,
        Err(e) => {
            log::debug!("[admin] metrics lock poisoned, recovering");
            e.into_inner()
        }
    };

    if let Some(collector) = &*metrics_guard {
        let frame = collector.snapshot();
        let (sent, recv, dropped, p50, p99) = parse_frame_fields(&frame);

        MetricsSnapshot {
            epoch,
            messages_sent: sent,
            messages_received: recv,
            messages_dropped: dropped,
            latency_min_ns: 0,
            latency_p50_ns: p50,
            latency_p99_ns: p99,
            latency_max_ns: 0,
        }
    } else {
        MetricsSnapshot::empty(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exporter_start() {
        let exporter =
            Exporter::start("127.0.0.1", 0).expect("Exporter should bind to random port");
        exporter.shutdown();
    }

    #[test]
    fn test_exporter_push_no_clients() {
        let exporter =
            Exporter::start("127.0.0.1", 0).expect("Exporter should bind to random port");

        let frame = Frame::new(0);
        exporter.push(&frame);

        exporter.shutdown();
    }
}

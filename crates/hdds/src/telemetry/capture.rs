// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Live telemetry capture server for HDDS Viewer integration.
//!
//! Provides TCP server that streams telemetry frames to connected clients
//! and admin API integration for metrics extraction.

use super::export::encode_frame;
use super::metrics::{
    Frame, MetricsCollector, TAG_LATENCY_P50, TAG_LATENCY_P99, TAG_SAMPLES_REJECTED_RING_FULL,
    TAG_SAMPLES_REJECTED_SLAB_EXHAUSTED,
};
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
///
/// Dropping the last `Arc<Exporter>` stops the server: the accept thread
/// is joined and the listening socket closed before the drop returns.
/// Dropping one clone while another is still alive (e.g. a participant's)
/// does NOT stop the server -- ordinary reference counting, same as any
/// other `Arc<T>`. [`Exporter::shutdown`] is the explicit, forced stop:
/// it closes the server right now through ANY `Arc<Exporter>` clone, even
/// while others are still alive, because it mutates state shared by every
/// clone, not state private to the caller.
pub struct Exporter {
    clients: Arc<Mutex<Vec<TcpStream>>>,
    shutdown: Arc<AtomicBool>,
    accept: Mutex<Option<thread::JoinHandle<()>>>,
    local_addr: SocketAddr,
    /// Test-only: flipped from INSIDE the accept thread itself, right after
    /// it returns from [`accept_loop`] and so has already dropped its
    /// `TcpListener` (closing the fd). Lets a test prove THIS exporter's
    /// listening socket was actually closed by THIS process without
    /// racing the OS ephemeral-port allocator against every other test
    /// bind()-ing a random port at the same time (see
    /// [`listener_closed_for_test`](Self::listener_closed_for_test)).
    #[cfg(any(test, feature = "test-support"))]
    listener_closed: Arc<AtomicBool>,
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
        let local_addr = listener.local_addr()?;

        let clients = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));
        #[cfg(any(test, feature = "test-support"))]
        let listener_closed = Arc::new(AtomicBool::new(false));

        let clients_clone = Arc::clone(&clients);
        let shutdown_clone = Arc::clone(&shutdown);
        #[cfg(any(test, feature = "test-support"))]
        let listener_closed_clone = Arc::clone(&listener_closed);

        // Spawn accept thread.
        let accept = thread::Builder::new()
            .name("hdds-telemetry-tx".into())
            .spawn(crate::core::rt::shutdown::owned(move || {
                accept_loop(listener, clients_clone, shutdown_clone);
                // `listener` (moved into `accept_loop` above) has just been
                // dropped, closing the fd: this flag going true is the
                // authoritative, race-free signal that THIS exporter's
                // port is released by THIS process.
                #[cfg(any(test, feature = "test-support"))]
                listener_closed_clone.store(true, Ordering::Relaxed);
            }))?;

        Ok(Self {
            clients,
            shutdown,
            accept: Mutex::new(Some(accept)),
            local_addr,
            #[cfg(any(test, feature = "test-support"))]
            listener_closed,
        })
    }

    /// The address the server listens on (the port actually bound when
    /// started on port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
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

    /// Shutdown exporter and close all connections, synchronously: the
    /// accept thread is joined (bounded) and the listening socket closed
    /// before this returns.
    ///
    /// Safe to call through any `Arc<Exporter>` clone and more than once
    /// (idempotent): the shutdown flag, the client list and the accept
    /// thread's handle are all shared state, not per-clone state, so the
    /// first call to reach them wins and the rest are no-ops. This is what
    /// lets an explicit "stop" force the server down right now even while
    /// a participant still holds its own clone of the same `Arc<Exporter>`.
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
        drop(clients);

        // Join the accept thread so the port is actually released by the
        // time this call returns. `take()` makes a second caller (another
        // clone, or this same Exporter's own Drop) see `None` and skip it.
        let accept = match self.accept.lock() {
            Ok(mut lock) => lock.take(),
            Err(e) => e.into_inner().take(),
        };
        if let Some(accept) = accept {
            crate::core::rt::shutdown::join_bounded(accept, "telemetry exporter");
        }
    }

    /// Whether this exporter has already been shut down: its accept thread
    /// has ended and its port is released, either by an explicit
    /// [`shutdown`](Self::shutdown) or because its last `Arc<Exporter>`
    /// holder dropped.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Test-only: whether THIS exporter's accept thread has actually ended
    /// and dropped its `TcpListener`, i.e. its listening socket is closed
    /// in this process right now.
    ///
    /// Unlike re-binding the same address with a fresh `TcpListener`, this
    /// never races another test that happens to receive the same freed
    /// ephemeral port from the kernel between this exporter's shutdown and
    /// the check: the flag is set from inside the accept thread itself,
    /// not inferred from whether the port is still free process-wide.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn listener_closed_for_test(&self) -> bool {
        self.listener_closed.load(Ordering::Relaxed)
    }

    /// Test-only: a clone of the same shared flag [`listener_closed_for_test`]
    /// reads, usable after THIS `Exporter` value itself is dropped --
    /// `Drop` runs the same synchronous [`shutdown`](Self::shutdown) that
    /// an explicit call does, so the flag still answers truthfully once
    /// the `Exporter` is gone and `self` can no longer be called on.
    #[cfg(test)]
    pub(crate) fn listener_closed_flag_for_test(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.listener_closed)
    }
}

impl Drop for Exporter {
    fn drop(&mut self) {
        self.shutdown();
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

        // Not part of `parse_frame_fields`'s 5-tuple: that signature is
        // destructured by name at several existing call sites (see
        // `crate::admin::api::tests`), so the two SAMPLE_REJECTED
        // counters are projected here instead, straight off the same
        // frame.
        let mut samples_rejected_ring_full = 0;
        let mut samples_rejected_slab_exhausted = 0;
        for field in &frame.fields {
            match field.tag {
                TAG_SAMPLES_REJECTED_RING_FULL => samples_rejected_ring_full = field.value_u64,
                TAG_SAMPLES_REJECTED_SLAB_EXHAUSTED => {
                    samples_rejected_slab_exhausted = field.value_u64;
                }
                _ => {}
            }
        }

        MetricsSnapshot {
            epoch,
            messages_sent: sent,
            messages_received: recv,
            messages_dropped: dropped,
            latency_min_ns: 0,
            latency_p50_ns: p50,
            latency_p99_ns: p99,
            latency_max_ns: 0,
            samples_rejected_ring_full,
            samples_rejected_slab_exhausted,
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

    /// Dropping the exporter ends its accept thread and closes its port.
    #[test]
    fn a_dropped_exporter_releases_its_port() {
        let exporter =
            Exporter::start("127.0.0.1", 0).expect("Exporter should bind to random port");
        let addr = exporter.local_addr();
        assert!(
            TcpListener::bind(addr).is_err(),
            "the exporter does not hold its port"
        );
        let closed_flag = exporter.listener_closed_flag_for_test();
        drop(exporter);
        assert!(
            closed_flag.load(Ordering::Relaxed),
            "a dropped exporter should have closed its listening socket"
        );
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

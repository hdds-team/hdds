// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Admin API server binding and connection handling.
//!
//!
//! Accepts TCP connections, parses commands, and returns JSON snapshots.

use super::builder;
use super::format::{
    format_json_health, format_json_mesh, format_json_metrics, format_json_readers,
    format_json_topics, format_json_writers,
};
use super::protocol::{Command, Status};
use crate::admin::snapshot::{
    EndpointsSnapshot, MeshSnapshot, MetricsSnapshot, ParticipantDB, TopicsSnapshot,
};
use crate::telemetry::MetricsCollector;
use std::convert::TryFrom;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// Admin API server exposing mesh state via a lightweight TCP protocol.
pub struct AdminApi {
    _listener: Option<TcpListener>,
    shutdown: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    participant_db: Arc<RwLock<ParticipantDB>>,
    metrics: Arc<Mutex<Option<Arc<MetricsCollector>>>>,
    fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    accept_thread: Option<thread::JoinHandle<()>>,
    start_time: Instant,
}

impl AdminApi {
    /// Bind the admin API server to the provided address and port.
    pub fn bind(
        bind_addr: &str,
        port: u16,
        fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
    ) -> std::io::Result<Self> {
        let listener = create_tcp_listener(bind_addr, port)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let epoch = Arc::new(AtomicU64::new(0));
        let participant_db = Arc::new(RwLock::new(ParticipantDB::new()));
        let metrics = Arc::new(Mutex::new(None));
        let start_time = Instant::now();

        let accept_thread = spawn_accept_thread(
            listener.try_clone()?,
            shutdown.clone(),
            epoch.clone(),
            participant_db.clone(),
            start_time,
            metrics.clone(),
            fsm.clone(),
        );

        Ok(Self {
            _listener: Some(listener),
            shutdown,
            epoch,
            participant_db,
            metrics,
            fsm,
            accept_thread: Some(accept_thread),
            start_time,
        })
    }

    /// Inject a metrics collector reference shared with the runtime.
    pub fn set_metrics(&mut self, metrics_collector: Arc<MetricsCollector>) {
        let mut guard = match self.metrics.lock() {
            Ok(lock) => lock,
            Err(e) => {
                log::debug!("[AdminApi::set_metrics] metrics lock poisoned, recovering");
                e.into_inner()
            }
        };
        *guard = Some(metrics_collector);
    }

    /// Mark the local participant entry and bump the epoch.
    pub fn set_local_participant(&self, name: String) {
        builder::set_local_participant(&self.participant_db, &self.epoch, name);
    }

    /// Snapshot mesh state for synchronous queries.
    #[must_use]
    pub fn snapshot_mesh(&self) -> MeshSnapshot {
        builder::mesh_snapshot(&self.epoch, &self.participant_db, self.fsm.as_ref())
    }

    /// Snapshot topics (placeholder for Tier 0).
    #[must_use]
    pub fn snapshot_topics(&self) -> TopicsSnapshot {
        builder::topics_snapshot(&self.epoch, self.fsm.as_ref())
    }

    /// Snapshot writers (DataWriters) discovered by the discovery FSM.
    #[must_use]
    pub fn snapshot_writers(&self) -> EndpointsSnapshot {
        builder::writers_snapshot(&self.epoch, self.fsm.as_ref())
    }

    /// Snapshot readers (DataReaders) discovered by the discovery FSM.
    #[must_use]
    pub fn snapshot_readers(&self) -> EndpointsSnapshot {
        builder::readers_snapshot(&self.epoch, self.fsm.as_ref())
    }

    /// Snapshot metrics collected by the runtime.
    #[must_use]
    pub fn snapshot_metrics(&self) -> MetricsSnapshot {
        builder::metrics_snapshot(&self.epoch, &self.metrics)
    }

    /// Return the current uptime in seconds.
    #[must_use]
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Signal shutdown to the accept loop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }
}

impl Drop for AdminApi {
    fn drop(&mut self) {
        self.shutdown();
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
    }
}

fn create_tcp_listener(bind_addr: &str, port: u16) -> std::io::Result<TcpListener> {
    let addr = format!("{}:{}", bind_addr, port);
    let addr: SocketAddr = addr.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid address: {}", e),
        )
    })?;

    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;

    let listener: TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn spawn_accept_thread(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    db: Arc<RwLock<ParticipantDB>>,
    start_time: Instant,
    metrics: Arc<Mutex<Option<Arc<MetricsCollector>>>>,
    fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        accept_loop(listener, shutdown, epoch, db, start_time, metrics, fsm);
    })
}

fn accept_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    db: Arc<RwLock<ParticipantDB>>,
    start_time: Instant,
    metrics: Arc<Mutex<Option<Arc<MetricsCollector>>>>,
    fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);

                let shutdown_clone = shutdown.clone();
                let epoch_clone = epoch.clone();
                let db_clone = db.clone();
                let metrics_clone = metrics.clone();
                let fsm_clone = fsm.clone();

                thread::spawn(move || {
                    handle_client(
                        stream,
                        shutdown_clone,
                        epoch_clone,
                        db_clone,
                        start_time,
                        metrics_clone,
                        fsm_clone,
                    );
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {}
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    _shutdown: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    db: Arc<RwLock<ParticipantDB>>,
    start_time: Instant,
    metrics: Arc<Mutex<Option<Arc<MetricsCollector>>>>,
    fsm: Option<Arc<crate::core::discovery::multicast::DiscoveryFsm>>,
) {
    let mut buf = [0u8; 1024];

    loop {
        let mut header = [0u8; 5];
        if stream.read_exact(&mut header).is_err() {
            break;
        }

        let cmd_id = header[0];
        let _payload_len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]);
        let cmd = match Command::from_u8(cmd_id) {
            Some(c) => c,
            None => {
                send_error_response(&mut stream, Status::InvalidCommand);
                continue;
            }
        };

        let response = match cmd {
            Command::GetMesh => {
                let snapshot = builder::mesh_snapshot(&epoch, &db, fsm.as_ref());
                format_json_mesh(snapshot)
            }
            Command::GetTopics => {
                let snapshot = builder::topics_snapshot(&epoch, fsm.as_ref());
                format_json_topics(snapshot)
            }
            Command::GetMetrics => {
                let snapshot = builder::metrics_snapshot(&epoch, &metrics);
                format_json_metrics(snapshot)
            }
            Command::GetHealth => {
                let uptime = start_time.elapsed().as_secs();
                format_json_health(uptime)
            }
            Command::GetWriters => {
                let snapshot = builder::writers_snapshot(&epoch, fsm.as_ref());
                format_json_writers(snapshot)
            }
            Command::GetReaders => {
                let snapshot = builder::readers_snapshot(&epoch, fsm.as_ref());
                format_json_readers(snapshot)
            }
        };

        let response_bytes = response.as_bytes();
        let len = match u32::try_from(response_bytes.len()) {
            Ok(value) => value,
            Err(_) => {
                log::debug!(
                    "[admin] Response payload too large ({} bytes) for protocol frame",
                    response_bytes.len()
                );
                send_error_response(&mut stream, Status::InternalError);
                break;
            }
        };

        buf[0] = Status::Ok.to_byte();
        buf[1..5].copy_from_slice(&len.to_le_bytes());

        if stream.write_all(&buf[0..5]).is_err() {
            break;
        }
        if stream.write_all(response_bytes).is_err() {
            break;
        }
    }
}

fn send_error_response(stream: &mut TcpStream, status: Status) {
    let error_msg = r#"{"error":"invalid_command"}"#;
    let len = match u32::try_from(error_msg.len()) {
        Ok(value) => value,
        Err(_) => {
            log::debug!("[admin] Static error payload exceeded u32::MAX");
            return;
        }
    };
    let mut buf = [0u8; 5];
    buf[0] = status.to_byte();
    buf[1..5].copy_from_slice(&len.to_le_bytes());

    let _ = stream.write_all(&buf);
    let _ = stream.write_all(error_msg.as_bytes());
}

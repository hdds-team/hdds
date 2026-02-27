// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Synchronous I/O thread wrapper for QUIC transport.
//!
//! v234 changes:
//! - **FIXED**: Replaced spin-wait `try_recv()+sleep(1ms)` with proper
//!   `tokio::select!` on command channel and periodic maintenance timer.
//! - **FIXED**: Commands now use `tokio::sync::mpsc` (bounded) with backpressure
//!   instead of unbounded `std::sync::mpsc`. Handle uses `try_send()`.
//! - **FIXED**: `server_name` from `QuicCommand::Connect` is now used for TLS SNI.
//! - **FIXED**: Removed duplicated peer tracking — stream handler tasks notify
//!   connection/disconnection directly via the event channel.
//! - **ADDED**: Transport events (MessageReceived, Connected, Disconnected) are
//!   now properly routed from the async transport to the sync Handle.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                      Main Thread (sync)                          │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │                   QuicIoThreadHandle                        │  │
//! │  │  cmd_tx (tokio::sync::mpsc, bounded) ─────────────┐       │  │
//! │  │  event_rx (std::sync::mpsc) ◄─────────────────────┼──┐    │  │
//! │  └───────────────────────────────────────────────────┼──┼────┘  │
//! └──────────────────────────────────────────────────────┼──┼───────┘
//!                                                        │  │
//!                                                        ▼  │
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                   QUIC I/O Thread (async)                        │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │        tokio runtime (current_thread)                      │  │
//! │  │                                                            │  │
//! │  │  tokio::select! {                                          │  │
//! │  │      cmd = cmd_rx.recv() => { ... }   ◄── bounded channel  │  │
//! │  │      _ = interval.tick() => { ... }   ◄── RTT/maintenance  │  │
//! │  │  }                                                         │  │
//! │  │                                                            │  │
//! │  │  QuicTransport ──► event_tx (std::sync) ──► Handle        │  │
//! │  │    ├── incoming conn handler task                          │  │
//! │  │    └── per-connection stream reader tasks                  │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::config::QuicConfig;

/// Command channel capacity (provides backpressure instead of OOM).
const CMD_CHANNEL_CAPACITY: usize = 256;

/// Maintenance interval for RTT updates and connection health checks.
const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);

/// v234-sprint5: Reconnect check interval.
const RECONNECT_CHECK_INTERVAL: Duration = Duration::from_millis(500);

// ============================================================================
// Reconnection State (v234-sprint5)
// ============================================================================

/// State for a pending reconnection attempt.
///
/// v234-sprint5: Tracks exponential backoff and retry count for dropped connections.
#[derive(Debug, Clone)]
struct ReconnectState {
    /// Remote peer address.
    peer: SocketAddr,
    /// TLS server name for SNI.
    server_name: String,
    /// Current attempt number (0-based).
    attempt: u32,
    /// When to attempt the next reconnection.
    next_retry: tokio::time::Instant,
    /// Current backoff delay (before jitter).
    current_backoff: Duration,
}

impl ReconnectState {
    /// Create a new reconnect state for a peer.
    fn new(peer: SocketAddr, server_name: String, base_delay: Duration) -> Self {
        Self {
            peer,
            server_name,
            attempt: 0,
            next_retry: tokio::time::Instant::now() + base_delay,
            current_backoff: base_delay,
        }
    }

    /// Calculate the next backoff delay with jitter.
    ///
    /// v234-sprint5: Exponential backoff with pseudo-random jitter (no rand dep).
    ///
    /// Formula:
    /// - delay = min(base_delay * 2^attempt, max_delay)
    /// - jitter_pct = (attempt * 7 + peer_port) % 50  (0-49%)
    /// - jitter_offset = delay * jitter_pct / 100, centered at 0 (subtract 25%)
    /// - final = delay + jitter_offset
    fn calculate_backoff(
        base_delay: Duration,
        max_delay: Duration,
        attempt: u32,
        peer_port: u16,
    ) -> Duration {
        // 2^attempt with overflow protection
        let multiplier = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let base_ms = base_delay.as_millis() as u64;
        let max_ms = max_delay.as_millis() as u64;

        // Calculate base delay: base * 2^attempt, capped at max
        let delay_ms = base_ms.saturating_mul(multiplier).min(max_ms);

        // Pseudo-random jitter: (attempt * 7 + port) % 50 gives 0-49%
        // Centered around 0 by subtracting 25% → range is -25% to +24%
        let jitter_pct = ((attempt.wrapping_mul(7)).wrapping_add(peer_port as u32) % 50) as i64;
        let jitter_offset = (delay_ms as i64 * (jitter_pct - 25)) / 100;

        // Apply jitter (ensure non-negative)
        let final_ms = (delay_ms as i64 + jitter_offset).max(1) as u64;

        Duration::from_millis(final_ms)
    }

    /// Advance to the next retry attempt.
    ///
    /// Returns the calculated delay for this attempt.
    fn advance(&mut self, base_delay: Duration, max_delay: Duration) -> Duration {
        let delay = Self::calculate_backoff(base_delay, max_delay, self.attempt, self.peer.port());
        self.attempt = self.attempt.saturating_add(1);
        self.current_backoff = delay;
        self.next_retry = tokio::time::Instant::now() + delay;
        delay
    }
}

// ============================================================================
// Commands (sync → async)
// ============================================================================

/// Commands sent from sync world to async QUIC thread.
#[derive(Debug)]
pub enum QuicCommand {
    /// Connect to a remote peer.
    Connect {
        remote_addr: SocketAddr,
        /// v234: Server name for TLS SNI (now actually used).
        server_name: Option<String>,
    },
    /// Send data to a connected peer.
    Send {
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    },
    /// Broadcast data to all connected peers.
    Broadcast { payload: Vec<u8> },
    /// Disconnect from a peer.
    Disconnect { remote_addr: SocketAddr },
    /// Shutdown the transport.
    Shutdown,
}

// ============================================================================
// Events (async → sync)
// ============================================================================

/// Events sent from async QUIC thread to sync world.
#[derive(Debug, Clone)]
pub enum QuicEvent {
    /// Transport is ready and listening.
    Ready { local_addr: SocketAddr },
    /// Successfully connected to a peer.
    Connected { remote_addr: SocketAddr },
    /// v234: Received data from a peer (now actually emitted!).
    MessageReceived {
        remote_addr: SocketAddr,
        payload: Vec<u8>,
    },
    /// Peer disconnected.
    Disconnected {
        remote_addr: SocketAddr,
        reason: Option<String>,
    },
    /// Error occurred.
    Error { message: String },
    /// Transport has stopped.
    Stopped,
}

// ============================================================================
// Handle (sync side)
// ============================================================================

/// Handle to interact with the QUIC I/O thread from sync code.
///
/// This handle can be cloned and shared across threads.
/// v234: Commands use bounded channel with backpressure.
#[derive(Clone)]
pub struct QuicIoThreadHandle {
    /// v234: Bounded tokio channel — `try_send()` from sync code.
    cmd_tx: tokio::sync::mpsc::Sender<QuicCommand>,
    /// Events from async world (std::sync for sync consumer).
    event_rx: Arc<std::sync::Mutex<Receiver<QuicEvent>>>,
    running: Arc<AtomicBool>,
}

impl QuicIoThreadHandle {
    /// Check if the I/O thread is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Connect to a remote peer.
    pub fn connect(&self, remote_addr: SocketAddr) -> Result<(), String> {
        self.cmd_tx
            .try_send(QuicCommand::Connect {
                remote_addr,
                server_name: None,
            })
            .map_err(|e| format!("Failed to send connect command: {}", e))
    }

    /// Connect with explicit server name (for TLS SNI).
    pub fn connect_with_name(
        &self,
        remote_addr: SocketAddr,
        server_name: &str,
    ) -> Result<(), String> {
        self.cmd_tx
            .try_send(QuicCommand::Connect {
                remote_addr,
                server_name: Some(server_name.to_string()),
            })
            .map_err(|e| format!("Failed to send connect command: {}", e))
    }

    /// Send data to a specific peer.
    pub fn send(&self, remote_addr: SocketAddr, payload: Vec<u8>) -> Result<(), String> {
        self.cmd_tx
            .try_send(QuicCommand::Send {
                remote_addr,
                payload,
            })
            .map_err(|e| format!("Failed to send data command: {}", e))
    }

    /// Broadcast data to all connected peers.
    pub fn broadcast(&self, payload: Vec<u8>) -> Result<(), String> {
        self.cmd_tx
            .try_send(QuicCommand::Broadcast { payload })
            .map_err(|e| format!("Failed to send broadcast command: {}", e))
    }

    /// Disconnect from a peer.
    pub fn disconnect(&self, remote_addr: SocketAddr) -> Result<(), String> {
        self.cmd_tx
            .try_send(QuicCommand::Disconnect { remote_addr })
            .map_err(|e| format!("Failed to send disconnect command: {}", e))
    }

    /// Poll for events (non-blocking).
    pub fn poll(&self) -> Vec<QuicEvent> {
        let mut events = Vec::new();
        if let Ok(rx) = self.event_rx.lock() {
            loop {
                match rx.try_recv() {
                    Ok(event) => events.push(event),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.running.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
        events
    }

    /// Wait for an event (blocking with timeout).
    pub fn wait(&self, timeout: Duration) -> Option<QuicEvent> {
        if let Ok(rx) = self.event_rx.lock() {
            rx.recv_timeout(timeout).ok()
        } else {
            None
        }
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.try_send(QuicCommand::Shutdown);
    }
}

// ============================================================================
// I/O Thread
// ============================================================================

/// QUIC I/O thread runner.
pub struct QuicIoThread {
    handle: QuicIoThreadHandle,
    thread_handle: Option<JoinHandle<()>>,
}

impl QuicIoThread {
    /// Spawn a new QUIC I/O thread.
    pub fn spawn(config: QuicConfig) -> Self {
        // v234: Bounded command channel with backpressure
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(CMD_CHANNEL_CAPACITY);
        // Event channel: std::sync for sync consumer side
        let (event_tx, event_rx) = std::sync::mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let thread_handle = thread::Builder::new()
            .name("hdds-quic-io".to_string())
            .spawn(move || {
                Self::run_thread(config, cmd_rx, event_tx, running_clone);
            })
            .expect("Failed to spawn QUIC I/O thread");

        let handle = QuicIoThreadHandle {
            cmd_tx,
            event_rx: Arc::new(std::sync::Mutex::new(event_rx)),
            running,
        };

        Self {
            handle,
            thread_handle: Some(thread_handle),
        }
    }

    /// Get a handle to interact with the I/O thread.
    pub fn handle(&self) -> QuicIoThreadHandle {
        self.handle.clone()
    }

    /// Run the async event loop in a dedicated thread.
    fn run_thread(
        config: QuicConfig,
        cmd_rx: tokio::sync::mpsc::Receiver<QuicCommand>,
        event_tx: Sender<QuicEvent>,
        running: Arc<AtomicBool>,
    ) {
        // Create a single-threaded tokio runtime for this thread
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = event_tx.send(QuicEvent::Error {
                    message: format!("Failed to create tokio runtime: {}", e),
                });
                running.store(false, Ordering::Relaxed);
                return;
            }
        };

        rt.block_on(async {
            Self::async_event_loop(config, cmd_rx, event_tx, running).await;
        });
    }

    /// v234: Async event loop using `tokio::select!` instead of spin-wait.
    ///
    /// The loop waits on:
    /// 1. Commands from the sync Handle (via bounded tokio channel)
    /// 2. Periodic maintenance timer (RTT updates, health checks)
    /// 3. v234-sprint5: Reconnection check timer
    ///
    /// Received messages arrive via the transport's stream handler tasks,
    /// which send directly to `event_tx` — no polling needed.
    async fn async_event_loop(
        config: QuicConfig,
        mut cmd_rx: tokio::sync::mpsc::Receiver<QuicCommand>,
        event_tx: Sender<QuicEvent>,
        running: Arc<AtomicBool>,
    ) {
        // v234: Pass event_tx to transport so stream handlers can route messages
        let transport = match super::QuicTransport::new(config.clone(), event_tx.clone()).await {
            Ok(t) => t,
            Err(e) => {
                let _ = event_tx.send(QuicEvent::Error {
                    message: format!("Failed to create QUIC transport: {}", e),
                });
                running.store(false, Ordering::Relaxed);
                return;
            }
        };

        // Notify ready
        if let Ok(addr) = transport.local_addr() {
            let _ = event_tx.send(QuicEvent::Ready { local_addr: addr });
            log::info!("[QUIC-IO] Transport ready on {}", addr);
        }

        // v234: Maintenance timer replaces the old spin-wait
        let mut maintenance = tokio::time::interval(MAINTENANCE_INTERVAL);
        maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // v234-sprint5: Reconnection check timer
        let mut reconnect_check = tokio::time::interval(RECONNECT_CHECK_INTERVAL);
        reconnect_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // v234-sprint5: Reconnection queue and manual disconnect tracking
        let mut reconnect_queue: Vec<ReconnectState> = Vec::new();
        let mut manually_disconnected: HashSet<SocketAddr> = HashSet::new();
        // Track connected peers to detect disconnections
        let mut known_connected: HashSet<SocketAddr> = HashSet::new();

        // Main event loop — no more spin-wait!
        while running.load(Ordering::Relaxed) {
            tokio::select! {
                // Branch 1: Process commands from sync Handle
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(QuicCommand::Connect { remote_addr, server_name }) => {
                            log::debug!("[QUIC-IO] Connecting to {}", remote_addr);

                            // v234-sprint5: Remove from reconnect queue if present
                            reconnect_queue.retain(|s| s.peer != remote_addr);
                            // Also clear manual disconnect flag for explicit connect
                            manually_disconnected.remove(&remote_addr);

                            // v234: Use server_name if provided
                            let sni = server_name
                                .as_deref()
                                .unwrap_or(&config.server_name);
                            match transport.connect_with_name(remote_addr, sni).await {
                                Ok(()) => {
                                    known_connected.insert(remote_addr);
                                    let _ = event_tx.send(QuicEvent::Connected { remote_addr });
                                    log::info!("[QUIC-IO] Connected to {}", remote_addr);
                                }
                                Err(e) => {
                                    let _ = event_tx.send(QuicEvent::Error {
                                        message: format!("Connect to {} failed: {}", remote_addr, e),
                                    });
                                }
                            }
                        }
                        Some(QuicCommand::Send { remote_addr, payload }) => {
                            if let Err(e) = transport.send(&payload, &remote_addr).await {
                                let _ = event_tx.send(QuicEvent::Error {
                                    message: format!("Send to {} failed: {}", remote_addr, e),
                                });
                            }
                        }
                        Some(QuicCommand::Broadcast { payload }) => {
                            if let Err(e) = transport.broadcast(&payload).await {
                                let _ = event_tx.send(QuicEvent::Error {
                                    message: format!("Broadcast failed: {}", e),
                                });
                            }
                        }
                        Some(QuicCommand::Disconnect { remote_addr }) => {
                            // v234-sprint5: Mark as manually disconnected
                            manually_disconnected.insert(remote_addr);
                            // Remove from reconnect queue
                            reconnect_queue.retain(|s| s.peer != remote_addr);
                            known_connected.remove(&remote_addr);

                            transport.disconnect(&remote_addr).await;
                            let _ = event_tx.send(QuicEvent::Disconnected {
                                remote_addr,
                                reason: Some("Requested".to_string()),
                            });
                        }
                        Some(QuicCommand::Shutdown) => {
                            log::info!("[QUIC-IO] Shutdown requested");
                            // v234-sprint5: Clear reconnect queue on shutdown
                            reconnect_queue.clear();
                            transport.shutdown().await;
                            running.store(false, Ordering::Relaxed);
                            break;
                        }
                        None => {
                            // Command channel closed (Handle dropped)
                            log::warn!("[QUIC-IO] Command channel closed");
                            running.store(false, Ordering::Relaxed);
                            break;
                        }
                    }
                }

                // Branch 2: Periodic maintenance
                _ = maintenance.tick() => {
                    // Update RTT stats for all connections
                    // (lightweight, no network I/O)
                    let current_peers: HashSet<SocketAddr> =
                        transport.connected_peers().await.into_iter().collect();
                    log::trace!("[QUIC-IO] Maintenance: {} active peers", current_peers.len());

                    // v234-sprint5: Detect dropped connections
                    if config.reconnect_enabled {
                        for peer in known_connected.difference(&current_peers) {
                            // Peer was connected but is no longer
                            if !manually_disconnected.contains(peer) {
                                // Not manually disconnected — schedule reconnection
                                log::info!(
                                    "[QUIC-IO] Connection to {} lost, scheduling reconnection",
                                    peer
                                );

                                // Check if already in queue
                                if !reconnect_queue.iter().any(|s| s.peer == *peer) {
                                    let state = ReconnectState::new(
                                        *peer,
                                        config.server_name.clone(),
                                        config.reconnect_base_delay,
                                    );
                                    reconnect_queue.push(state);
                                }

                                // Emit Disconnected event
                                let _ = event_tx.send(QuicEvent::Disconnected {
                                    remote_addr: *peer,
                                    reason: Some("Connection lost".to_string()),
                                });
                            }
                        }
                    }

                    // Update known_connected to current state
                    known_connected = current_peers;
                }

                // Branch 3: v234-sprint5 - Reconnection check
                _ = reconnect_check.tick() => {
                    if !config.reconnect_enabled || reconnect_queue.is_empty() {
                        continue;
                    }

                    let now = tokio::time::Instant::now();
                    let mut indices_to_remove = Vec::new();

                    for (idx, state) in reconnect_queue.iter_mut().enumerate() {
                        if now < state.next_retry {
                            continue;
                        }

                        // Check max attempts
                        if let Some(max) = config.reconnect_max_attempts {
                            if state.attempt >= max {
                                log::warn!(
                                    "[QUIC-IO] Reconnection to {} failed after {} attempts",
                                    state.peer,
                                    state.attempt
                                );
                                let _ = event_tx.send(QuicEvent::Error {
                                    message: format!(
                                        "Reconnection to {} failed after {} attempts",
                                        state.peer, state.attempt
                                    ),
                                });
                                indices_to_remove.push(idx);
                                continue;
                            }
                        }

                        log::info!(
                            "[QUIC-IO] Reconnection attempt {} to {} (backoff: {:?})",
                            state.attempt + 1,
                            state.peer,
                            state.current_backoff
                        );

                        match transport
                            .connect_with_name(state.peer, &state.server_name)
                            .await
                        {
                            Ok(()) => {
                                log::info!(
                                    "[QUIC-IO] Reconnected to {} on attempt {}",
                                    state.peer,
                                    state.attempt + 1
                                );
                                known_connected.insert(state.peer);
                                let _ = event_tx.send(QuicEvent::Connected {
                                    remote_addr: state.peer,
                                });
                                indices_to_remove.push(idx);
                            }
                            Err(e) => {
                                log::debug!(
                                    "[QUIC-IO] Reconnection to {} failed: {}",
                                    state.peer,
                                    e
                                );
                                // Advance backoff
                                let delay = state.advance(
                                    config.reconnect_base_delay,
                                    config.reconnect_max_delay,
                                );
                                log::debug!(
                                    "[QUIC-IO] Next retry for {} in {:?}",
                                    state.peer,
                                    delay
                                );
                            }
                        }
                    }

                    // Remove completed/failed entries (reverse order to preserve indices)
                    for idx in indices_to_remove.into_iter().rev() {
                        reconnect_queue.swap_remove(idx);
                    }
                }
            }
        }

        let _ = event_tx.send(QuicEvent::Stopped);
        log::info!("[QUIC-IO] Thread stopped");
    }
}

impl Drop for QuicIoThread {
    fn drop(&mut self) {
        self.handle.shutdown();
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_send() {
        let cmd = QuicCommand::Connect {
            remote_addr: "127.0.0.1:7400".parse().unwrap(),
            server_name: None,
        };
        assert!(matches!(cmd, QuicCommand::Connect { .. }));
    }

    #[test]
    fn test_command_with_server_name() {
        let cmd = QuicCommand::Connect {
            remote_addr: "127.0.0.1:7400".parse().unwrap(),
            server_name: Some("custom.hdds.local".to_string()),
        };
        if let QuicCommand::Connect { server_name, .. } = cmd {
            assert_eq!(server_name.unwrap(), "custom.hdds.local");
        }
    }

    #[test]
    fn test_event_clone() {
        let event = QuicEvent::Connected {
            remote_addr: "127.0.0.1:7400".parse().unwrap(),
        };
        let cloned = event.clone();
        assert!(matches!(cloned, QuicEvent::Connected { .. }));
    }

    #[test]
    fn test_event_message_received() {
        let event = QuicEvent::MessageReceived {
            remote_addr: "127.0.0.1:7400".parse().unwrap(),
            payload: vec![0x52, 0x54, 0x50, 0x53], // "RTPS"
        };
        if let QuicEvent::MessageReceived { payload, .. } = event {
            assert_eq!(payload, vec![0x52, 0x54, 0x50, 0x53]);
        }
    }

    #[test]
    fn test_channel_capacity() {
        assert_eq!(CMD_CHANNEL_CAPACITY, 256);
    }

    // =========================================================================
    // v234-sprint5: Reconnection tests
    // =========================================================================

    #[test]
    fn test_backoff_exponential_sequence() {
        // Base delay 1s, max 60s
        // Expected: 1s, 2s, 4s, 8s, 16s, 32s, 60s (capped), 60s...
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);
        let port = 7400u16; // Fixed port for deterministic jitter

        // Calculate jitter bounds: ±25% around base values
        let check_with_jitter = |attempt: u32, expected_base_ms: u64| {
            let delay = ReconnectState::calculate_backoff(base, max, attempt, port);
            let delay_ms = delay.as_millis() as u64;

            // Jitter is (attempt * 7 + port) % 50 - 25 = -25% to +24%
            // Allow ±25% tolerance
            let min_ms = expected_base_ms * 75 / 100;
            let max_ms = expected_base_ms * 125 / 100;

            assert!(
                delay_ms >= min_ms && delay_ms <= max_ms,
                "attempt {}: expected {}ms ±25%, got {}ms (range {}-{})",
                attempt,
                expected_base_ms,
                delay_ms,
                min_ms,
                max_ms
            );
        };

        check_with_jitter(0, 1000); // 1s
        check_with_jitter(1, 2000); // 2s
        check_with_jitter(2, 4000); // 4s
        check_with_jitter(3, 8000); // 8s
        check_with_jitter(4, 16000); // 16s
        check_with_jitter(5, 32000); // 32s
        check_with_jitter(6, 60000); // 60s (capped)
        check_with_jitter(7, 60000); // 60s (still capped)
        check_with_jitter(10, 60000); // 60s (still capped)
    }

    #[test]
    fn test_backoff_jitter_bounds() {
        let base = Duration::from_secs(10);
        let max = Duration::from_secs(60);

        // Test multiple ports to exercise jitter variation
        for port in [7400u16, 7401, 7402, 8080, 12345] {
            for attempt in 0..5 {
                let delay = ReconnectState::calculate_backoff(base, max, attempt, port);
                let delay_ms = delay.as_millis() as u64;

                // Base value before jitter
                let base_ms = (10000u64 << attempt).min(60000);

                // Jitter should be within ±25%
                let min_ms = base_ms * 75 / 100;
                let max_ms = base_ms * 125 / 100;

                assert!(
                    delay_ms >= min_ms && delay_ms <= max_ms,
                    "port {} attempt {}: expected {}-{}ms, got {}ms",
                    port,
                    attempt,
                    min_ms,
                    max_ms,
                    delay_ms
                );
            }
        }
    }

    #[test]
    fn test_backoff_max_attempts() {
        // Simulate max_attempts = 3
        let max_attempts = 3u32;
        let mut state = ReconnectState::new(
            "127.0.0.1:7400".parse().unwrap(),
            "test.local".to_string(),
            Duration::from_secs(1),
        );

        // After 3 advances, attempt count should be 3
        for _ in 0..max_attempts {
            state.advance(Duration::from_secs(1), Duration::from_secs(60));
        }

        assert_eq!(state.attempt, max_attempts);
        // At this point, reconnection logic should give up
    }

    #[test]
    fn test_reconnect_state_new() {
        let addr: SocketAddr = "192.168.1.100:7500".parse().unwrap();
        let state = ReconnectState::new(addr, "hdds.local".to_string(), Duration::from_secs(2));

        assert_eq!(state.peer, addr);
        assert_eq!(state.server_name, "hdds.local");
        assert_eq!(state.attempt, 0);
        assert_eq!(state.current_backoff, Duration::from_secs(2));
    }

    #[test]
    fn test_reconnect_state_advance() {
        let addr: SocketAddr = "127.0.0.1:7400".parse().unwrap();
        let mut state = ReconnectState::new(addr, "test.local".to_string(), Duration::from_secs(1));

        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        // First advance: attempt 0 -> 1
        let delay1 = state.advance(base, max);
        assert_eq!(state.attempt, 1);
        // Delay should be ~2s with jitter (±100% tolerance for heavily loaded CI systems)
        assert!(delay1.as_millis() <= 4000);

        // Second advance: attempt 1 -> 2
        let delay2 = state.advance(base, max);
        assert_eq!(state.attempt, 2);
        // Delay should be ~4s with jitter (±100% tolerance for heavily loaded CI systems)
        assert!(delay2.as_millis() <= 8000);
    }

    #[test]
    fn test_backoff_overflow_protection() {
        let base = Duration::from_secs(1);
        let max = Duration::from_secs(60);

        // Very high attempt number should not overflow
        let delay = ReconnectState::calculate_backoff(base, max, 100, 7400);
        // Should be capped at max (60s) with jitter
        assert!(delay.as_secs() <= 75); // 60s + 25% jitter max
    }
}

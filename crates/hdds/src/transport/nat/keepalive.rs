// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! NAT binding keepalive via periodic STUN refresh.
//!
//! NAT bindings typically expire after 30-120 seconds of inactivity.
//! This module periodically re-sends STUN Binding Requests to refresh
//! the binding and detect address changes (e.g. NAT rebind).

use super::stun::StunClient;
use super::{NatConfig, NatError, ReflexiveAddress};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Holds the background thread handle and the stop channel sender.
///
/// Dropping the `StopHandle` sends the stop signal (by dropping the sender,
/// which causes `Disconnected` on the receiver side) and then joins the thread.
struct StopHandle {
    /// Dropping this signals the thread to exit via channel disconnect.
    /// Must be dropped BEFORE joining the thread.
    stop_tx: Option<mpsc::Sender<()>>,
    /// Background thread handle -- joined on drop.
    thread: Option<JoinHandle<()>>,
}

impl StopHandle {
    /// Signal the thread to stop and wait for it to finish.
    fn stop(&mut self) {
        // Drop the sender first -- this disconnects the channel and unblocks
        // the thread's recv_timeout() call with Disconnected.
        drop(self.stop_tx.take());
        // Now join the thread (it will exit promptly after seeing Disconnected).
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for StopHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// NAT binding keepalive manager.
///
/// Performs an initial STUN discovery, then spawns a background thread
/// that periodically re-discovers the reflexive address to keep the
/// NAT binding alive and detect address changes.
pub struct NatKeepalive {
    /// STUN server address
    stun_server: std::net::SocketAddr,
    /// Timeout per STUN request attempt
    stun_timeout: Duration,
    /// Maximum retransmission attempts per discovery
    max_retries: u32,
    /// Refresh interval (typically 25s for 30s NAT timeout)
    interval: Duration,
    /// Current discovered reflexive address (shared with refresh thread via Arc)
    current_address: Arc<RwLock<Option<ReflexiveAddress>>>,
    /// Whether the keepalive thread is running
    running: AtomicBool,
    /// Background thread + stop signal (None when not running)
    stop_handle: Mutex<Option<StopHandle>>,
}

impl NatKeepalive {
    /// Create a new keepalive manager from NAT configuration.
    pub fn new(config: &NatConfig, stun_server: std::net::SocketAddr) -> Self {
        Self {
            stun_server,
            stun_timeout: config.stun_timeout,
            max_retries: config.max_retries,
            interval: config.keepalive_interval,
            current_address: Arc::new(RwLock::new(None)),
            running: AtomicBool::new(false),
            stop_handle: Mutex::new(None),
        }
    }

    /// Perform initial STUN discovery and start the refresh thread.
    ///
    /// Returns the initially discovered reflexive address.
    pub fn start(&self) -> Result<ReflexiveAddress, NatError> {
        if self.running.load(Ordering::Acquire) {
            return self
                .current_address
                .read()
                .map_err(|e| NatError::InternalError(format!("lock poisoned: {}", e)))?
                .clone()
                .ok_or_else(|| NatError::InternalError("already running but no address".into()));
        }

        // Initial discovery (synchronous)
        let mut client = StunClient::new(self.stun_server, self.stun_timeout, self.max_retries);
        let initial = client.discover_reflexive_address()?;

        // Store the initial address
        {
            let mut addr = self.current_address.write().map_err(|e| {
                NatError::InternalError(format!("lock poisoned: {}", e))
            })?;
            *addr = Some(initial.clone());
        }

        self.running.store(true, Ordering::Release);

        // Create stop channel -- dropping the sender signals the thread to exit
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        // Clone parameters for the thread
        let server = self.stun_server;
        let timeout = self.stun_timeout;
        let retries = self.max_retries;
        let interval = self.interval;
        let current_addr = Some(initial.clone());

        // Share the current_address RwLock with the thread via Arc clone
        let shared_address = Arc::clone(&self.current_address);

        let handle = std::thread::Builder::new()
            .name("hdds-nat-keepalive".into())
            .spawn(move || {
                let mut client = StunClient::new(server, timeout, retries);
                let mut last_addr = current_addr;

                loop {
                    // Wait for the refresh interval or a stop signal
                    match stop_rx.recv_timeout(interval) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                            // Stop signal or channel closed -- exit
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            // Time to refresh the STUN binding
                        }
                    }

                    match client.discover_reflexive_address() {
                        Ok(new_addr) => {
                            if let Ok(mut current) = shared_address.write() {
                                let changed = current.as_ref().is_none_or(|old| {
                                    old.ip != new_addr.ip || old.port != new_addr.port
                                });

                                if changed {
                                    log::info!(
                                        "[NAT] reflexive address changed: {:?} -> {}:{}",
                                        last_addr
                                            .as_ref()
                                            .map(|a| format!("{}:{}", a.ip, a.port)),
                                        new_addr.ip,
                                        new_addr.port
                                    );
                                }

                                last_addr = Some(new_addr.clone());
                                *current = Some(new_addr);
                            }
                        }
                        Err(e) => {
                            log::warn!("[NAT] keepalive refresh failed: {}", e);
                        }
                    }
                }
            })
            .map_err(|e| NatError::InternalError(format!("failed to spawn thread: {}", e)))?;

        // Store the stop handle (sender + thread)
        {
            let mut guard = self.stop_handle.lock().map_err(|e| {
                NatError::InternalError(format!("lock poisoned: {}", e))
            })?;
            *guard = Some(StopHandle {
                stop_tx: Some(stop_tx),
                thread: Some(handle),
            });
        }

        Ok(initial)
    }

    /// Stop the keepalive refresh thread.
    ///
    /// Signals the thread to exit and waits for it to finish.
    /// Safe to call multiple times.
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);

        if let Ok(mut guard) = self.stop_handle.lock() {
            // Signal the thread to stop and join it.
            if let Some(ref mut handle) = *guard {
                handle.stop();
            }
            *guard = None;
        }
    }

    /// Get the current reflexive address, if known.
    #[must_use]
    pub fn current_address(&self) -> Option<ReflexiveAddress> {
        self.current_address
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Check if the reflexive address has changed since the given instant.
    #[must_use]
    pub fn address_changed_since(&self, since: Instant) -> bool {
        self.current_address
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|a| a.discovered_at > since))
            .unwrap_or(false)
    }

    /// Check if the keepalive thread is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }
}

impl Drop for NatKeepalive {
    fn drop(&mut self) {
        self.stop();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_config() -> NatConfig {
        NatConfig {
            stun_server: "127.0.0.1:3478".to_string(),
            enabled: true,
            keepalive_interval: Duration::from_secs(25),
            stun_timeout: Duration::from_secs(3),
            max_retries: 3,
        }
    }

    #[test]
    fn test_keepalive_creation() {
        let config = test_config();
        let server: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let keepalive = NatKeepalive::new(&config, server);

        assert!(!keepalive.is_running());
        assert!(keepalive.current_address().is_none());
    }

    #[test]
    fn test_address_changed_since_no_address() {
        let config = test_config();
        let server: SocketAddr = "127.0.0.1:3478".parse().unwrap();
        let keepalive = NatKeepalive::new(&config, server);

        assert!(!keepalive.address_changed_since(Instant::now()));
    }

    #[test]
    fn test_keepalive_start_stop() {
        use std::net::{Ipv4Addr, UdpSocket};

        // Set up a mock STUN server
        let server_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        server_socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let config = NatConfig {
            stun_server: server_addr.to_string(),
            enabled: true,
            keepalive_interval: Duration::from_secs(60), // long so thread won't re-query
            stun_timeout: Duration::from_secs(2),
            max_retries: 1,
        };

        // Spawn mock server that responds to one request
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 576];
            let (len, client_addr) = server_socket.recv_from(&mut buf).unwrap();
            assert!(len >= 20);

            let mut tid = [0u8; 12];
            tid.copy_from_slice(&buf[8..20]);

            let public_ip = Ipv4Addr::new(203, 0, 113, 42);
            let public_port: u16 = 54321;
            let magic_cookie: u32 = 0x2112_A442;
            let x_port = public_port ^ ((magic_cookie >> 16) as u16);
            let x_addr = u32::from(public_ip) ^ magic_cookie;

            let mut resp = Vec::new();
            resp.extend_from_slice(&0x0101u16.to_be_bytes());
            resp.extend_from_slice(&12u16.to_be_bytes());
            resp.extend_from_slice(&magic_cookie.to_be_bytes());
            resp.extend_from_slice(&tid);
            resp.extend_from_slice(&0x0020u16.to_be_bytes());
            resp.extend_from_slice(&8u16.to_be_bytes());
            resp.push(0x00);
            resp.push(0x01);
            resp.extend_from_slice(&x_port.to_be_bytes());
            resp.extend_from_slice(&x_addr.to_be_bytes());

            server_socket.send_to(&resp, client_addr).unwrap();
        });

        let keepalive = NatKeepalive::new(&config, server_addr);
        let result = keepalive.start();
        handle.join().unwrap();

        assert!(result.is_ok(), "start should succeed: {:?}", result.err());
        let addr = result.unwrap();
        assert_eq!(
            addr.ip,
            std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42))
        );
        assert_eq!(addr.port, 54321);

        assert!(keepalive.is_running());
        assert!(keepalive.current_address().is_some());

        keepalive.stop();
        assert!(!keepalive.is_running());
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Synchronous polling thread wrapper for cloud discovery.
//!
//! This module provides a sync interface to async cloud discovery backends
//! (Consul, AWS Cloud Map, Azure) by running a dedicated background thread
//! with its own tokio runtime.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                      Main Thread (sync)                          │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │               CloudDiscoveryPollerHandle                    │  │
//! │  │  cmd_tx ──────────────────────────────────────────┐        │  │
//! │  │  event_rx ◄───────────────────────────────────────┼──┐     │  │
//! │  └───────────────────────────────────────────────────┼──┼─────┘  │
//! └──────────────────────────────────────────────────────┼──┼────────┘
//!                                                        │  │
//!                                                        ▼  │
//! ┌──────────────────────────────────────────────────────────────────┐
//! │               Cloud Discovery Poller Thread (async)              │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │              tokio runtime (current_thread)                 │  │
//! │  │  ┌──────────────────────────────────────────────────────┐  │  │
//! │  │  │          CloudDiscovery (Consul/AWS/Azure)            │  │  │
//! │  │  │  - Periodic discover_participants()                   │  │  │
//! │  │  │  - Register/deregister on command                     │  │  │
//! │  │  └──────────────────────────────────────────────────────┘  │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::{ConsulDiscovery, ParticipantInfo};

// ============================================================================
// Configuration
// ============================================================================

/// Cloud discovery provider type.
#[derive(Debug, Clone)]
pub enum CloudProvider {
    /// HashiCorp Consul
    Consul { addr: String },
    /// AWS Cloud Map
    Aws {
        namespace: String,
        service: String,
        region: String,
    },
    /// Azure Service Discovery
    Azure { config_json: String },
}

/// Configuration for the cloud discovery poller.
#[derive(Debug, Clone)]
pub struct CloudPollerConfig {
    /// Cloud provider to use.
    pub provider: CloudProvider,
    /// Polling interval for discovery.
    pub poll_interval: Duration,
    /// Domain ID for filtering.
    pub domain_id: u32,
}

impl Default for CloudPollerConfig {
    fn default() -> Self {
        Self {
            provider: CloudProvider::Consul {
                addr: "http://localhost:8500".to_string(),
            },
            poll_interval: Duration::from_secs(5),
            domain_id: 0,
        }
    }
}

// ============================================================================
// Commands (sync → async)
// ============================================================================

/// Commands sent from sync world to async discovery thread.
#[derive(Debug)]
pub enum CloudCommand {
    /// Register this participant with the discovery service.
    Register { info: ParticipantInfo },
    /// Deregister this participant.
    Deregister { guid: [u8; 16] },
    /// Force an immediate discovery poll.
    PollNow,
    /// Shutdown the poller.
    Shutdown,
}

// ============================================================================
// Events (async → sync)
// ============================================================================

/// Events sent from async discovery thread to sync world.
#[derive(Debug, Clone)]
pub enum CloudEvent {
    /// Poller is ready and running.
    Ready,
    /// New participant discovered.
    ParticipantDiscovered { info: ParticipantInfo },
    /// Participant is no longer available.
    ParticipantLost { guid: [u8; 16] },
    /// Registration succeeded.
    Registered { guid: [u8; 16] },
    /// Deregistration succeeded.
    Deregistered { guid: [u8; 16] },
    /// Error occurred.
    Error { message: String },
    /// Poller has stopped.
    Stopped,
}

// ============================================================================
// Handle (sync side)
// ============================================================================

/// Handle to interact with the cloud discovery poller from sync code.
#[derive(Clone)]
pub struct CloudDiscoveryPollerHandle {
    cmd_tx: Sender<CloudCommand>,
    event_rx: Arc<std::sync::Mutex<Receiver<CloudEvent>>>,
    running: Arc<AtomicBool>,
}

impl CloudDiscoveryPollerHandle {
    /// Check if the poller is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Register this participant with the cloud discovery service.
    pub fn register(&self, info: ParticipantInfo) -> Result<(), String> {
        self.cmd_tx
            .send(CloudCommand::Register { info })
            .map_err(|e| format!("Failed to send register command: {}", e))
    }

    /// Deregister this participant.
    pub fn deregister(&self, guid: [u8; 16]) -> Result<(), String> {
        self.cmd_tx
            .send(CloudCommand::Deregister { guid })
            .map_err(|e| format!("Failed to send deregister command: {}", e))
    }

    /// Force an immediate discovery poll.
    pub fn poll_now(&self) -> Result<(), String> {
        self.cmd_tx
            .send(CloudCommand::PollNow)
            .map_err(|e| format!("Failed to send poll command: {}", e))
    }

    /// Poll for events (non-blocking).
    pub fn poll(&self) -> Vec<CloudEvent> {
        let mut events = Vec::new();
        if let Ok(rx) = self.event_rx.lock() {
            loop {
                match rx.try_recv() {
                    Ok(event) => events.push(event),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.running.store(false, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }
        events
    }

    /// Wait for an event (blocking with timeout).
    pub fn wait(&self, timeout: Duration) -> Option<CloudEvent> {
        if let Ok(rx) = self.event_rx.lock() {
            rx.recv_timeout(timeout).ok()
        } else {
            None
        }
    }

    /// Request shutdown.
    pub fn shutdown(&self) {
        let _ = self.cmd_tx.send(CloudCommand::Shutdown);
    }
}

// ============================================================================
// Poller Thread
// ============================================================================

/// Cloud discovery poller thread.
pub struct CloudDiscoveryPoller {
    handle: CloudDiscoveryPollerHandle,
    thread_handle: Option<JoinHandle<()>>,
}

impl CloudDiscoveryPoller {
    /// Spawn a new cloud discovery poller thread.
    pub fn spawn(config: CloudPollerConfig) -> Self {
        let (cmd_tx, cmd_rx) = channel();
        let (event_tx, event_rx) = channel();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
        let thread_handle = thread::Builder::new()
            .name("hdds-cloud-discovery".to_string())
            .spawn(move || {
                Self::run_thread(config, cmd_rx, event_tx, running_clone);
            })
            .expect("Failed to spawn cloud discovery poller thread");

        let handle = CloudDiscoveryPollerHandle {
            cmd_tx,
            event_rx: Arc::new(std::sync::Mutex::new(event_rx)),
            running,
        };

        Self {
            handle,
            thread_handle: Some(thread_handle),
        }
    }

    /// Get a handle to interact with the poller.
    pub fn handle(&self) -> CloudDiscoveryPollerHandle {
        self.handle.clone()
    }

    /// Run the async polling loop in a dedicated thread.
    fn run_thread(
        config: CloudPollerConfig,
        cmd_rx: Receiver<CloudCommand>,
        event_tx: Sender<CloudEvent>,
        running: Arc<AtomicBool>,
    ) {
        // Create a single-threaded tokio runtime for this thread
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = event_tx.send(CloudEvent::Error {
                    message: format!("Failed to create tokio runtime: {}", e),
                });
                running.store(false, Ordering::Relaxed);
                return;
            }
        };

        rt.block_on(async {
            Self::async_polling_loop(config, cmd_rx, event_tx, running).await;
        });
    }

    /// Async polling loop that periodically discovers participants.
    async fn async_polling_loop(
        config: CloudPollerConfig,
        cmd_rx: Receiver<CloudCommand>,
        event_tx: Sender<CloudEvent>,
        running: Arc<AtomicBool>,
    ) {
        // Create the Consul discovery backend (only Consul supported for now)
        let discovery = match &config.provider {
            CloudProvider::Consul { addr } => match ConsulDiscovery::new(addr) {
                Ok(d) => d,
                Err(e) => {
                    let _ = event_tx.send(CloudEvent::Error {
                        message: format!("Failed to create Consul discovery: {}", e),
                    });
                    running.store(false, Ordering::Relaxed);
                    return;
                }
            },
            CloudProvider::Aws { .. } => {
                // AWS Cloud Map - placeholder for now
                let _ = event_tx.send(CloudEvent::Error {
                    message: "AWS Cloud Map not yet implemented in sync wrapper".to_string(),
                });
                running.store(false, Ordering::Relaxed);
                return;
            }
            CloudProvider::Azure { .. } => {
                // Azure - placeholder for now
                let _ = event_tx.send(CloudEvent::Error {
                    message: "Azure discovery not yet implemented in sync wrapper".to_string(),
                });
                running.store(false, Ordering::Relaxed);
                return;
            }
        };

        let _ = event_tx.send(CloudEvent::Ready);
        log::info!("[CLOUD-DISCOVERY] Poller ready");

        // Track known participants to detect new/lost ones
        let mut known_participants: std::collections::HashMap<[u8; 16], ParticipantInfo> =
            std::collections::HashMap::new();

        let mut last_poll = std::time::Instant::now();

        // Main polling loop
        while running.load(Ordering::Relaxed) {
            // Check for commands
            let mut force_poll = false;
            match cmd_rx.try_recv() {
                Ok(cmd) => match cmd {
                    CloudCommand::Register { info } => {
                        use super::CloudDiscovery;
                        log::debug!("[CLOUD-DISCOVERY] Registering participant");
                        match discovery.register_participant(&info).await {
                            Ok(()) => {
                                let _ = event_tx.send(CloudEvent::Registered { guid: info.guid });
                                log::info!("[CLOUD-DISCOVERY] Registered participant");
                            }
                            Err(e) => {
                                let _ = event_tx.send(CloudEvent::Error {
                                    message: format!("Registration failed: {}", e),
                                });
                            }
                        }
                    }
                    CloudCommand::Deregister { guid } => {
                        use super::CloudDiscovery;
                        log::debug!("[CLOUD-DISCOVERY] Deregistering participant");
                        match discovery.deregister_participant(guid).await {
                            Ok(()) => {
                                let _ = event_tx.send(CloudEvent::Deregistered { guid });
                                log::info!("[CLOUD-DISCOVERY] Deregistered participant");
                            }
                            Err(e) => {
                                let _ = event_tx.send(CloudEvent::Error {
                                    message: format!("Deregistration failed: {}", e),
                                });
                            }
                        }
                    }
                    CloudCommand::PollNow => {
                        force_poll = true;
                    }
                    CloudCommand::Shutdown => {
                        log::info!("[CLOUD-DISCOVERY] Shutdown requested");
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                },
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    log::warn!("[CLOUD-DISCOVERY] Command channel disconnected");
                    running.store(false, Ordering::Relaxed);
                    break;
                }
            }

            // Periodic discovery poll
            if force_poll || last_poll.elapsed() >= config.poll_interval {
                use super::CloudDiscovery;
                last_poll = std::time::Instant::now();

                match discovery.discover_participants().await {
                    Ok(participants) => {
                        // Filter by domain_id
                        let filtered: Vec<ParticipantInfo> = participants
                            .into_iter()
                            .filter(|p| p.domain_id == config.domain_id)
                            .collect();

                        // Detect new participants
                        for info in &filtered {
                            if let std::collections::hash_map::Entry::Vacant(entry) =
                                known_participants.entry(info.guid)
                            {
                                entry.insert(info.clone());
                                let _ = event_tx
                                    .send(CloudEvent::ParticipantDiscovered { info: info.clone() });
                                log::debug!(
                                    "[CLOUD-DISCOVERY] Discovered participant: {}",
                                    info.name
                                );
                            }
                        }

                        // Detect lost participants
                        let current_guids: std::collections::HashSet<_> =
                            filtered.iter().map(|p| p.guid).collect();
                        let lost: Vec<_> = known_participants
                            .keys()
                            .filter(|g| !current_guids.contains(*g))
                            .cloned()
                            .collect();

                        for guid in lost {
                            known_participants.remove(&guid);
                            let _ = event_tx.send(CloudEvent::ParticipantLost { guid });
                            log::debug!("[CLOUD-DISCOVERY] Lost participant: {:02x?}", guid);
                        }
                    }
                    Err(e) => {
                        log::warn!("[CLOUD-DISCOVERY] Discovery poll failed: {}", e);
                    }
                }
            }

            // Brief sleep to avoid busy-waiting
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = event_tx.send(CloudEvent::Stopped);
        log::info!("[CLOUD-DISCOVERY] Poller stopped");
    }
}

impl Drop for CloudDiscoveryPoller {
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
    fn test_config_default() {
        let config = CloudPollerConfig::default();
        assert_eq!(config.poll_interval, Duration::from_secs(5));
        assert_eq!(config.domain_id, 0);
    }

    #[test]
    fn test_event_clone() {
        let event = CloudEvent::Ready;
        let cloned = event.clone();
        assert!(matches!(cloned, CloudEvent::Ready));
    }
}

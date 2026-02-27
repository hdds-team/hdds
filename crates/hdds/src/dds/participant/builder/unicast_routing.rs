// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Sprint 7: Unicast routing thread for TCP and QUIC transports.
//!
//! Polls TCP and QUIC transports for incoming RTPS messages and routes them
//! through `route_raw_rtps_message()` to the `TopicRegistry`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::core::discovery::fragment_buffer::FragmentBuffer;
use crate::engine::{route_raw_rtps_message, RouterMetrics, TopicRegistry};
use crate::transport::tcp::{TcpTransport, TcpTransportEvent};

#[cfg(feature = "quic")]
use crate::transport::quic::{QuicEvent, QuicIoThreadHandle};

const TCP_POLL_TIMEOUT: Duration = Duration::from_millis(50);
const NO_TRANSPORT_SLEEP: Duration = Duration::from_millis(50);
const FRAG_MAX_PENDING: usize = 64;
const FRAG_TIMEOUT_MS: u64 = 5000;

/// Unicast routing thread handle.
///
/// Automatically shuts down and joins the thread on Drop.
pub(in crate::dds::participant) struct UnicastRoutingThread {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Drop for UnicastRoutingThread {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Spawn the unicast routing thread.
///
/// The thread polls TCP and QUIC transports, routing received RTPS messages
/// through `route_raw_rtps_message()` to the `TopicRegistry`.
///
/// Auto-starts only when at least one of TCP or QUIC is configured.
pub(super) fn spawn(
    tcp: Option<Arc<TcpTransport>>,
    #[cfg(feature = "quic")] quic_handle: Option<QuicIoThreadHandle>,
    registry: Arc<TopicRegistry>,
    metrics: Arc<RouterMetrics>,
    shutdown: Arc<AtomicBool>,
) -> UnicastRoutingThread {
    let shutdown_clone = Arc::clone(&shutdown);

    #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
    let handle = thread::Builder::new()
        .name("hdds-unicast-router".into())
        .spawn(move || {
            log::info!(
                "[hdds] Unicast routing thread started (TCP={}, QUIC={})",
                tcp.is_some(),
                {
                    #[cfg(feature = "quic")]
                    {
                        quic_handle.is_some()
                    }
                    #[cfg(not(feature = "quic"))]
                    {
                        false
                    }
                },
            );

            let frag_buf = Mutex::new(FragmentBuffer::new(FRAG_MAX_PENDING, FRAG_TIMEOUT_MS));

            while !shutdown_clone.load(Ordering::Relaxed) {
                let mut had_transport = false;

                // --- TCP ---
                if let Some(ref tcp) = tcp {
                    had_transport = true;
                    for event in tcp.poll_timeout(TCP_POLL_TIMEOUT) {
                        match event {
                            TcpTransportEvent::MessageReceived { payload, from } => {
                                let outcome = route_raw_rtps_message(
                                    &payload,
                                    &registry,
                                    &metrics,
                                    Some(&frag_buf),
                                );
                                log::trace!("[unicast-router] TCP from {:?}: {:?}", from, outcome);
                            }
                            TcpTransportEvent::Connected {
                                remote_guid,
                                remote_addr,
                            } => {
                                log::debug!(
                                    "[unicast-router] TCP peer connected: {} (GUID {:?})",
                                    remote_addr,
                                    remote_guid
                                );
                            }
                            TcpTransportEvent::Disconnected {
                                remote_guid,
                                reason,
                            } => {
                                log::debug!(
                                    "[unicast-router] TCP peer disconnected: GUID {:?} ({})",
                                    remote_guid,
                                    reason.as_deref().unwrap_or("unknown")
                                );
                            }
                            _ => {}
                        }
                    }
                }

                // --- QUIC ---
                #[cfg(feature = "quic")]
                {
                    if let Some(ref handle) = quic_handle {
                        had_transport = true;
                        for event in handle.poll() {
                            match event {
                                QuicEvent::MessageReceived {
                                    payload,
                                    remote_addr,
                                } => {
                                    let outcome = route_raw_rtps_message(
                                        &payload,
                                        &registry,
                                        &metrics,
                                        Some(&frag_buf),
                                    );
                                    log::trace!(
                                        "[unicast-router] QUIC from {}: {:?}",
                                        remote_addr,
                                        outcome
                                    );
                                }
                                QuicEvent::Connected { remote_addr } => {
                                    log::debug!(
                                        "[unicast-router] QUIC peer connected: {}",
                                        remote_addr
                                    );
                                }
                                QuicEvent::Disconnected {
                                    remote_addr,
                                    reason,
                                } => {
                                    log::debug!(
                                        "[unicast-router] QUIC peer disconnected: {} ({})",
                                        remote_addr,
                                        reason.as_deref().unwrap_or("unknown")
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Avoid busy-loop if no transport is active
                if !had_transport {
                    thread::sleep(NO_TRANSPORT_SLEEP);
                }
            }

            log::info!("[hdds] Unicast routing thread stopped");
        })
        .expect("failed to spawn unicast routing thread");

    UnicastRoutingThread {
        shutdown,
        handle: Some(handle),
    }
}

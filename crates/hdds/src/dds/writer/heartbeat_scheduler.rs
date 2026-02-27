// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Periodic Heartbeat Scheduler for RTPS Reliable QoS
//!
//! This module implements a dedicated thread that sends HEARTBEAT messages
//! at regular intervals, independent of write() calls. This is required for
//! RTPS 2.5 conformance (Section 8.4.7.2) to enable recovery after bursts.
//!
//! ## Problem Solved
//!
//! Without periodic heartbeats, a writer that bursts data and then goes idle
//! will never trigger ACKNACK responses from readers, causing permanent loss.
//!
//! ## Protocol Flow
//!
//! ```text
//! Writer                              Reader
//!   ├──DATA(1-10000) burst────────────▶  (some lost)
//!   │                                   │
//!   │  (writer idle, thread continues)  │
//!   │                                   │
//!   ├──HEARTBEAT(first=1,last=10000)──▶  (every 100ms)
//!   │                                   │
//!   ◀──────────ACKNACK(missing=[...])──┤
//!   │                                   │
//!   ├──DATA retransmit────────────────▶
//! ```

use crate::protocol::builder::{self, RtpsEndpointContext};
use crate::reliability::HistoryCache;
use crate::transport::UdpTransport;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Default heartbeat period in milliseconds (RTPS recommendation: 100ms)
pub const DEFAULT_HEARTBEAT_PERIOD_MS: u64 = 100;

/// Shared state between the writer and the heartbeat scheduler thread.
#[derive(Debug)]
pub struct HeartbeatSchedulerState {
    /// Current highest sequence number written
    pub last_seq: AtomicU64,
    /// Stop flag to terminate the thread
    pub stop: AtomicBool,
    /// Heartbeat counter (monotonically increasing per RTPS spec)
    pub count: AtomicU32,
}

impl HeartbeatSchedulerState {
    /// Create new shared state.
    pub fn new() -> Self {
        Self {
            last_seq: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            count: AtomicU32::new(1),
        }
    }

    /// Update the last sequence number (called by writer on each write).
    pub fn update_seq(&self, seq: u64) {
        self.last_seq.store(seq, Ordering::Release);
    }

    /// Signal the thread to stop.
    pub fn signal_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// Check if stop was signaled.
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Get and increment the heartbeat counter.
    pub fn next_count(&self) -> u32 {
        self.count.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for HeartbeatSchedulerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to the heartbeat scheduler thread.
///
/// When dropped, signals the thread to stop and waits for it to join.
pub struct HeartbeatSchedulerHandle {
    state: Arc<HeartbeatSchedulerState>,
    thread: Option<JoinHandle<()>>,
}

impl HeartbeatSchedulerHandle {
    /// Get a reference to the shared state (for updating last_seq from writer).
    pub fn state(&self) -> &Arc<HeartbeatSchedulerState> {
        &self.state
    }
}

impl Drop for HeartbeatSchedulerHandle {
    fn drop(&mut self) {
        // Signal stop
        self.state.signal_stop();

        // Wait for thread to finish
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Spawn a periodic heartbeat scheduler thread.
///
/// Returns a handle that manages the thread lifecycle. The thread will
/// send HEARTBEAT messages every `period_ms` milliseconds until the
/// handle is dropped.
///
/// # Arguments
///
/// * `transport` - UDP transport for sending heartbeats
/// * `history_cache` - History cache to get first_seq
/// * `rtps_endpoint` - RTPS context for building packets
/// * `period_ms` - Heartbeat period in milliseconds
///
/// # Returns
///
/// A handle that owns the thread. Drop the handle to stop the thread.
pub fn spawn_heartbeat_scheduler(
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
    rtps_endpoint: RtpsEndpointContext,
    period_ms: u64,
) -> HeartbeatSchedulerHandle {
    let state = Arc::new(HeartbeatSchedulerState::new());
    let state_clone = Arc::clone(&state);
    let period = Duration::from_millis(period_ms);

    #[allow(clippy::expect_used)] // thread spawn failure is unrecoverable
    let thread = thread::Builder::new()
        .name("hdds-heartbeat".into())
        .spawn(move || {
            heartbeat_loop(transport, history_cache, rtps_endpoint, state_clone, period);
        })
        .expect("failed to spawn heartbeat thread");

    HeartbeatSchedulerHandle {
        state,
        thread: Some(thread),
    }
}

/// Main heartbeat loop - runs until stop is signaled.
fn heartbeat_loop(
    transport: Arc<UdpTransport>,
    history_cache: Arc<HistoryCache>,
    ctx: RtpsEndpointContext,
    state: Arc<HeartbeatSchedulerState>,
    period: Duration,
) {
    log::debug!(
        "[heartbeat] Starting periodic heartbeat thread (period={:?})",
        period
    );

    while !state.should_stop() {
        thread::sleep(period);

        if state.should_stop() {
            break;
        }

        // Get sequence range
        let last_seq = state.last_seq.load(Ordering::Acquire);
        if last_seq == 0 {
            // No data written yet, skip heartbeat
            continue;
        }

        let first_seq = history_cache.oldest_seq().unwrap_or(1);
        let count = state.next_count();

        // Build and send HEARTBEAT
        let packet = builder::build_heartbeat_packet_with_context(&ctx, first_seq, last_seq, count);

        if let Err(e) = transport.send(&packet) {
            log::debug!("[heartbeat] Failed to send HEARTBEAT: {}", e);
        } else {
            log::trace!(
                "[heartbeat] Sent HEARTBEAT first={} last={} count={}",
                first_seq,
                last_seq,
                count
            );
        }
    }

    log::debug!("[heartbeat] Heartbeat thread stopped");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_update_seq() {
        let state = HeartbeatSchedulerState::new();
        assert_eq!(state.last_seq.load(Ordering::Relaxed), 0);

        state.update_seq(42);
        assert_eq!(state.last_seq.load(Ordering::Relaxed), 42);

        state.update_seq(100);
        assert_eq!(state.last_seq.load(Ordering::Relaxed), 100);
    }

    #[test]
    fn test_state_stop_signal() {
        let state = HeartbeatSchedulerState::new();
        assert!(!state.should_stop());

        state.signal_stop();
        assert!(state.should_stop());
    }

    #[test]
    fn test_state_count_increment() {
        let state = HeartbeatSchedulerState::new();

        assert_eq!(state.next_count(), 1);
        assert_eq!(state.next_count(), 2);
        assert_eq!(state.next_count(), 3);
    }
}

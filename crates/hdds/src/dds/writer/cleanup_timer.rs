// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DurabilityService cleanup timer for writer history cache.
//!
//! Periodically removes acknowledged samples from the history cache after
//! the configured `service_cleanup_delay`. Only active when the cleanup delay > 0
//! and the writer uses TRANSIENT_LOCAL or PERSISTENT durability.
//!
//! DDS v1.4 Sec.2.2.3.5: The service_cleanup_delay controls the maximum duration
//! for which the data writer will maintain information regarding an instance once
//! it becomes NOT_ALIVE_DISPOSED.

use crate::reliability::HistoryCache;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Handle to a running cleanup timer thread.
///
/// When dropped, signals the background thread to stop.
pub struct CleanupTimerHandle {
    /// Signal to stop the background thread.
    stop: Arc<AtomicBool>,
    /// Thread join handle (Option so we can take it in drop).
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for CleanupTimerHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// Shared state for tracking acknowledged sequence numbers.
///
/// The writer (or reliable protocol) updates this when ACKNACKs are received.
pub struct CleanupState {
    /// The highest sequence number acknowledged by ALL matched readers.
    pub acked_seq: AtomicU64,
}

impl CleanupState {
    /// Create a new cleanup state.
    pub fn new() -> Self {
        Self {
            acked_seq: AtomicU64::new(0),
        }
    }

    /// Update the acknowledged sequence number.
    #[allow(dead_code)] // Called by reliable protocol handler and integration tests
    pub fn update_acked_seq(&self, seq: u64) {
        // Only update if higher (monotonic)
        let _ = self
            .acked_seq
            .fetch_update(Ordering::Release, Ordering::Acquire, |current| {
                if seq > current {
                    Some(seq)
                } else {
                    None
                }
            });
    }

    /// Get the current acknowledged sequence number.
    pub fn get_acked_seq(&self) -> u64 {
        self.acked_seq.load(Ordering::Acquire)
    }
}

impl Default for CleanupState {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn a background cleanup timer thread.
///
/// The thread wakes up every `interval` and removes samples from the history cache
/// that have been acknowledged by all matched readers (seq <= acked_seq).
///
/// # Arguments
///
/// * `history_cache` - The history cache to clean up
/// * `cleanup_state` - Shared state tracking acknowledged sequence numbers
/// * `interval` - How often to run the cleanup (typically cleanup_delay / 2)
///
/// # Returns
///
/// A handle that stops the timer thread when dropped.
pub fn spawn_cleanup_timer(
    history_cache: Arc<HistoryCache>,
    cleanup_state: Arc<CleanupState>,
    interval: Duration,
) -> CleanupTimerHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let thread = std::thread::Builder::new()
        .name("hdds-cleanup-timer".to_string())
        .spawn(move || {
            log::debug!(
                "[cleanup-timer] Started with interval {:?}",
                interval
            );

            while !stop_clone.load(Ordering::Acquire) {
                std::thread::sleep(interval);

                if stop_clone.load(Ordering::Acquire) {
                    break;
                }

                let acked = cleanup_state.get_acked_seq();
                if acked > 0 {
                    let removed = history_cache.remove_acknowledged(acked);
                    if removed > 0 {
                        log::debug!(
                            "[cleanup-timer] Removed {} acknowledged samples (acked_seq={})",
                            removed,
                            acked
                        );
                    }
                }
            }

            log::debug!("[cleanup-timer] Stopped");
        })
        .expect("failed to spawn cleanup timer thread");

    CleanupTimerHandle {
        stop,
        thread: Some(thread),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::rt::slabpool::SlabPool;
    use crate::qos::History;

    #[test]
    fn test_cleanup_state_monotonic() {
        let state = CleanupState::new();
        assert_eq!(state.get_acked_seq(), 0);

        state.update_acked_seq(10);
        assert_eq!(state.get_acked_seq(), 10);

        // Lower value should be ignored
        state.update_acked_seq(5);
        assert_eq!(state.get_acked_seq(), 10);

        state.update_acked_seq(20);
        assert_eq!(state.get_acked_seq(), 20);
    }

    #[test]
    fn test_cleanup_timer_removes_acknowledged() {
        let pool = Arc::new(SlabPool::new());
        let cache = Arc::new(HistoryCache::new_with_limits(
            pool,
            100,
            10_000_000,
            History::KeepLast(100),
        ));

        // Insert samples
        for i in 1..=10 {
            cache
                .insert(i, b"test data")
                .expect("insert should succeed");
        }
        assert_eq!(cache.len(), 10);

        let state = Arc::new(CleanupState::new());
        state.update_acked_seq(5);

        // Spawn cleanup timer with short interval
        let _handle = spawn_cleanup_timer(
            cache.clone(),
            state.clone(),
            Duration::from_millis(10),
        );

        // Wait for cleanup to run
        std::thread::sleep(Duration::from_millis(50));

        // Samples 1-5 should have been removed
        assert_eq!(cache.len(), 5);
        assert_eq!(cache.oldest_seq(), Some(6));
    }

    #[test]
    fn test_cleanup_timer_drops_cleanly() {
        let pool = Arc::new(SlabPool::new());
        let cache = Arc::new(HistoryCache::new_with_limits(
            pool,
            100,
            10_000_000,
            History::KeepLast(100),
        ));

        let state = Arc::new(CleanupState::new());
        let handle = spawn_cleanup_timer(
            cache,
            state,
            Duration::from_millis(10),
        );

        // Drop should signal stop and join
        drop(handle);
        // If we get here, the thread was successfully joined
    }
}

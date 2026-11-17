// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DurabilityService cleanup timer for writer history cache.
//!
//! Periodically removes acknowledged samples from the history cache after
//! the configured `service_cleanup_delay`. Only active when the cleanup delay > 0
//! and the writer uses TRANSIENT or PERSISTENT durability (TRANSIENT_LOCAL
//! writers are bounded by HISTORY and RESOURCE_LIMITS alone).
//!
//! DDS v1.4 Sec.2.2.3.5: The service_cleanup_delay controls the maximum duration
//! for which the data writer will maintain information regarding an instance once
//! it becomes NOT_ALIVE_DISPOSED.

use crate::reliability::HistoryCache;
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
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

/// A standalone acknowledged-sequence counter, for tests.
///
/// Production does NOT use this: the writer already tracks the per-reader
/// watermark in `ack_track` and `spawn_cleanup_timer` reads that one through
/// its closure. Keeping a second counter that something must remember to
/// update is the shape this codebase has been bitten by three times; this one
/// exists so a test can drive the timer without building a writer.
#[cfg(test)]
pub struct CleanupState {
    /// The highest sequence number acknowledged by ALL matched readers.
    pub acked_seq: AtomicU64,
}

#[cfg(test)]
impl CleanupState {
    /// Create a new cleanup state.
    pub fn new() -> Self {
        Self {
            acked_seq: AtomicU64::new(0),
        }
    }

    /// Update the acknowledged sequence number.
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

#[cfg(test)]
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
/// `acked_through` is asked for the highest sequence EVERY matched reader has
/// acknowledged. It is a closure rather than a counter this module owns,
/// deliberately: the writer already tracks that watermark in `ack_track`
/// (one entry per reader, updated at a single site in `nack.rs` when an
/// ACKNACK lands), and `DataWriter::acked_through` is its minimum. A second
/// counter to keep in step with the first is the shape that has produced
/// three separate defects in this codebase - two copies of one rule are
/// rarely symmetric. So there is one source of truth and this reads it.
pub fn spawn_cleanup_timer(
    history_cache: Arc<HistoryCache>,
    acked_through: Arc<dyn Fn() -> u64 + Send + Sync>,
    interval: Duration,
    delay_nanos: u64,
) -> crate::dds::Result<CleanupTimerHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let thread = std::thread::Builder::new()
        .name("hdds-cleanup-timer".to_string())
        .spawn(move || {
            log::debug!("[cleanup-timer] Started with interval {:?}", interval);

            while !stop_clone.load(Ordering::Acquire) {
                std::thread::sleep(interval);

                if stop_clone.load(Ordering::Acquire) {
                    break;
                }

                let acked = acked_through();
                if acked > 0 {
                    // DDS v1.4 Sec.2.2.3.5: remove an instance's
                    // information only once it has been explicitly
                    // disposed, no live writer still claims it, AND this
                    // delay has elapsed since -- never merely "every
                    // reader has acknowledged it" (`acked` bounds which
                    // changes are even eligible to be swept, not which
                    // ones ARE).
                    let removed = history_cache.remove_durability_expired(
                        acked,
                        delay_nanos,
                        crate::telemetry::metrics::current_time_ns(),
                    );
                    if removed > 0 {
                        log::debug!(
                            "[cleanup-timer] Removed {} disposed-and-expired samples (acked_seq={})",
                            removed,
                            acked
                        );
                    }
                }
            }

            log::debug!("[cleanup-timer] Stopped");
        })
        // Thread creation is a runtime resource failure (RLIMIT_NPROC, memory
        // pressure), not an invariant: report it to the writer's builder.
        .map_err(|e| {
            crate::dds::Error::Config(format!("failed to spawn cleanup timer thread: {e}"))
        })?;

    Ok(CleanupTimerHandle {
        stop,
        thread: Some(thread),
    })
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

    /// DDS v1.4 Sec.2.2.3.5: the timer removes an instance only once it is
    /// disposed, has no live writer, is acknowledged, AND the delay has
    /// elapsed -- a plain acked sample with no lifecycle change is left
    /// alone (an unconditional `remove_acknowledged` would sweep it; see
    /// `dds::writer::durability_service_tests` for the rule pinned
    /// directly against `remove_durability_expired`).
    #[test]
    fn test_cleanup_timer_leaves_a_plain_acked_sample_alone() {
        let pool = Arc::new(SlabPool::new());
        let cache = Arc::new(HistoryCache::new_with_limits(
            pool,
            100,
            10_000_000,
            History::KeepLast(100),
        ));

        cache.enable_durability_cleanup();
        for i in 1..=10 {
            cache
                .insert(i, b"test data")
                .expect("insert should succeed");
        }
        assert_eq!(cache.len(), 10);

        let state = Arc::new(CleanupState::new());
        state.update_acked_seq(5);

        let _handle = spawn_cleanup_timer(
            cache.clone(),
            Arc::new({
                let s = state.clone();
                move || s.get_acked_seq()
            }),
            Duration::from_millis(10),
            0,
        )
        .expect("spawn cleanup timer");

        std::thread::sleep(Duration::from_millis(50));

        assert_eq!(
            cache.len(),
            10,
            "none of these were ever disposed, so none are eligible"
        );
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
            Arc::new(move || state.get_acked_seq()),
            Duration::from_millis(10),
            0,
        )
        .expect("spawn cleanup timer");

        // Drop should signal stop and join
        drop(handle);
        // If we get here, the thread was successfully joined
    }
}

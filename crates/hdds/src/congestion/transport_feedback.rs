// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Transport feedback integration for congestion control.
//!
//! Detects EAGAIN/ENOBUFS errors and signals the congestion scorer.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Transport feedback signals for congestion control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSignal {
    /// Send succeeded normally.
    Success,
    /// EAGAIN/EWOULDBLOCK - socket buffer temporarily full.
    WouldBlock,
    /// ENOBUFS - kernel buffer exhausted.
    NoBuffers,
    /// Other transient error (may recover).
    TransientError,
    /// Fatal error (socket dead).
    FatalError,
}

impl TransportSignal {
    /// Check if this signal indicates congestion.
    pub fn is_congestion(&self) -> bool {
        matches!(self, Self::WouldBlock | Self::NoBuffers)
    }

    /// Check if the operation should be retried.
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::WouldBlock | Self::TransientError)
    }

    /// Check if the socket is still usable.
    pub fn is_recoverable(&self) -> bool {
        !matches!(self, Self::FatalError)
    }
}

/// Classify an IO error into a transport signal.
pub fn classify_error(err: &io::Error) -> TransportSignal {
    match err.kind() {
        // EAGAIN/EWOULDBLOCK - buffer full, try later
        io::ErrorKind::WouldBlock => TransportSignal::WouldBlock,

        // Connection issues that may recover
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::Interrupted => TransportSignal::TransientError,

        // Permission denied, address in use, etc. - fatal
        io::ErrorKind::PermissionDenied
        | io::ErrorKind::AddrInUse
        | io::ErrorKind::AddrNotAvailable => TransportSignal::FatalError,

        // Check raw OS error for ENOBUFS
        _ => {
            if let Some(raw) = err.raw_os_error() {
                // ENOBUFS = 105 on Linux, 55 on macOS/BSD
                #[cfg(target_os = "linux")]
                const ENOBUFS: i32 = 105;
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                const ENOBUFS: i32 = 55;
                #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
                const ENOBUFS: i32 = -1; // Not applicable

                if raw == ENOBUFS {
                    return TransportSignal::NoBuffers;
                }
            }

            // Default: transient, might recover
            TransportSignal::TransientError
        }
    }
}

/// Transport feedback observer for congestion control.
///
/// Tracks send results and provides signals to the congestion scorer.
#[derive(Debug)]
pub struct TransportFeedback {
    /// Total send attempts.
    sends_total: AtomicU64,
    /// Successful sends.
    sends_ok: AtomicU64,
    /// EAGAIN/EWOULDBLOCK count.
    eagain_count: AtomicU64,
    /// ENOBUFS count.
    nobufs_count: AtomicU64,
    /// Transient error count.
    transient_count: AtomicU64,
    /// Fatal error count.
    fatal_count: AtomicU64,
    /// Last error time.
    last_error: std::sync::RwLock<Option<Instant>>,
    /// Last congestion time.
    last_congestion: std::sync::RwLock<Option<Instant>>,
}

impl TransportFeedback {
    /// Create a new transport feedback observer.
    pub fn new() -> Self {
        Self {
            sends_total: AtomicU64::new(0),
            sends_ok: AtomicU64::new(0),
            eagain_count: AtomicU64::new(0),
            nobufs_count: AtomicU64::new(0),
            transient_count: AtomicU64::new(0),
            fatal_count: AtomicU64::new(0),
            last_error: std::sync::RwLock::new(None),
            last_congestion: std::sync::RwLock::new(None),
        }
    }

    /// Record a successful send.
    pub fn record_success(&self) {
        self.sends_total.fetch_add(1, Ordering::Relaxed);
        self.sends_ok.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a send error and return the signal.
    pub fn record_error(&self, err: &io::Error) -> TransportSignal {
        self.sends_total.fetch_add(1, Ordering::Relaxed);

        let signal = classify_error(err);

        match signal {
            TransportSignal::Success => {
                self.sends_ok.fetch_add(1, Ordering::Relaxed);
            }
            TransportSignal::WouldBlock => {
                self.eagain_count.fetch_add(1, Ordering::Relaxed);
                self.update_congestion_time();
            }
            TransportSignal::NoBuffers => {
                self.nobufs_count.fetch_add(1, Ordering::Relaxed);
                self.update_congestion_time();
            }
            TransportSignal::TransientError => {
                self.transient_count.fetch_add(1, Ordering::Relaxed);
            }
            TransportSignal::FatalError => {
                self.fatal_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.update_error_time();
        signal
    }

    /// Record a send result (Ok or Err).
    pub fn record_result<T>(&self, result: &io::Result<T>) -> TransportSignal {
        match result {
            Ok(_) => {
                self.record_success();
                TransportSignal::Success
            }
            Err(e) => self.record_error(e),
        }
    }

    fn update_error_time(&self) {
        if let Ok(mut guard) = self.last_error.write() {
            *guard = Some(Instant::now());
        }
    }

    fn update_congestion_time(&self) {
        if let Ok(mut guard) = self.last_congestion.write() {
            *guard = Some(Instant::now());
        }
    }

    /// Get total send attempts.
    pub fn sends_total(&self) -> u64 {
        self.sends_total.load(Ordering::Relaxed)
    }

    /// Get successful send count.
    pub fn sends_ok(&self) -> u64 {
        self.sends_ok.load(Ordering::Relaxed)
    }

    /// Get EAGAIN count.
    pub fn eagain_count(&self) -> u64 {
        self.eagain_count.load(Ordering::Relaxed)
    }

    /// Get ENOBUFS count.
    pub fn nobufs_count(&self) -> u64 {
        self.nobufs_count.load(Ordering::Relaxed)
    }

    /// Get total congestion events (EAGAIN + ENOBUFS).
    pub fn congestion_count(&self) -> u64 {
        self.eagain_count() + self.nobufs_count()
    }

    /// Get success rate (0.0 - 1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.sends_total();
        if total == 0 {
            return 1.0;
        }
        self.sends_ok() as f64 / total as f64
    }

    /// Get congestion rate (0.0 - 1.0).
    pub fn congestion_rate(&self) -> f64 {
        let total = self.sends_total();
        if total == 0 {
            return 0.0;
        }
        self.congestion_count() as f64 / total as f64
    }

    /// Check if congestion was detected recently.
    pub fn is_congested(&self, window: Duration) -> bool {
        if let Ok(guard) = self.last_congestion.read() {
            if let Some(t) = *guard {
                return t.elapsed() < window;
            }
        }
        false
    }

    /// Check if any error occurred recently.
    pub fn has_recent_error(&self, window: Duration) -> bool {
        if let Ok(guard) = self.last_error.read() {
            if let Some(t) = *guard {
                return t.elapsed() < window;
            }
        }
        false
    }

    /// Get time since last congestion event.
    pub fn time_since_congestion(&self) -> Option<Duration> {
        if let Ok(guard) = self.last_congestion.read() {
            guard.map(|t| t.elapsed())
        } else {
            None
        }
    }

    /// Reset all counters.
    pub fn reset(&self) {
        self.sends_total.store(0, Ordering::Relaxed);
        self.sends_ok.store(0, Ordering::Relaxed);
        self.eagain_count.store(0, Ordering::Relaxed);
        self.nobufs_count.store(0, Ordering::Relaxed);
        self.transient_count.store(0, Ordering::Relaxed);
        self.fatal_count.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_error.write() {
            *guard = None;
        }
        if let Ok(mut guard) = self.last_congestion.write() {
            *guard = None;
        }
    }

    /// Get a snapshot of current metrics.
    pub fn snapshot(&self) -> TransportFeedbackSnapshot {
        TransportFeedbackSnapshot {
            sends_total: self.sends_total(),
            sends_ok: self.sends_ok(),
            eagain_count: self.eagain_count(),
            nobufs_count: self.nobufs_count(),
            transient_count: self.transient_count.load(Ordering::Relaxed),
            fatal_count: self.fatal_count.load(Ordering::Relaxed),
        }
    }
}

impl Default for TransportFeedback {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of transport feedback metrics.
#[derive(Debug, Clone, Copy)]
pub struct TransportFeedbackSnapshot {
    /// Total send attempts.
    pub sends_total: u64,
    /// Successful sends.
    pub sends_ok: u64,
    /// EAGAIN/EWOULDBLOCK count.
    pub eagain_count: u64,
    /// ENOBUFS count.
    pub nobufs_count: u64,
    /// Transient error count.
    pub transient_count: u64,
    /// Fatal error count.
    pub fatal_count: u64,
}

impl TransportFeedbackSnapshot {
    /// Get total congestion events.
    pub fn congestion_count(&self) -> u64 {
        self.eagain_count + self.nobufs_count
    }

    /// Get success rate.
    pub fn success_rate(&self) -> f64 {
        if self.sends_total == 0 {
            return 1.0;
        }
        self.sends_ok as f64 / self.sends_total as f64
    }

    /// Get error rate.
    pub fn error_rate(&self) -> f64 {
        1.0 - self.success_rate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_would_block() {
        let err = io::Error::from(io::ErrorKind::WouldBlock);
        assert_eq!(classify_error(&err), TransportSignal::WouldBlock);
        assert!(classify_error(&err).is_congestion());
        assert!(classify_error(&err).should_retry());
    }

    #[test]
    fn test_classify_fatal() {
        let err = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(classify_error(&err), TransportSignal::FatalError);
        assert!(!classify_error(&err).is_recoverable());
    }

    #[test]
    fn test_classify_transient() {
        let err = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(classify_error(&err), TransportSignal::TransientError);
        assert!(classify_error(&err).is_recoverable());
    }

    #[test]
    fn test_feedback_new() {
        let fb = TransportFeedback::new();
        assert_eq!(fb.sends_total(), 0);
        assert_eq!(fb.sends_ok(), 0);
        assert_eq!(fb.eagain_count(), 0);
    }

    #[test]
    fn test_feedback_success() {
        let fb = TransportFeedback::new();

        fb.record_success();
        fb.record_success();
        fb.record_success();

        assert_eq!(fb.sends_total(), 3);
        assert_eq!(fb.sends_ok(), 3);
        assert!((fb.success_rate() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_feedback_eagain() {
        let fb = TransportFeedback::new();

        fb.record_success();
        let err = io::Error::from(io::ErrorKind::WouldBlock);
        let signal = fb.record_error(&err);

        assert_eq!(signal, TransportSignal::WouldBlock);
        assert_eq!(fb.sends_total(), 2);
        assert_eq!(fb.sends_ok(), 1);
        assert_eq!(fb.eagain_count(), 1);
        assert!((fb.success_rate() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_feedback_congestion_rate() {
        let fb = TransportFeedback::new();

        for _ in 0..8 {
            fb.record_success();
        }

        let err = io::Error::from(io::ErrorKind::WouldBlock);
        fb.record_error(&err);
        fb.record_error(&err);

        assert_eq!(fb.sends_total(), 10);
        assert_eq!(fb.congestion_count(), 2);
        assert!((fb.congestion_rate() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_feedback_is_congested() {
        let fb = TransportFeedback::new();

        assert!(!fb.is_congested(Duration::from_secs(1)));

        let err = io::Error::from(io::ErrorKind::WouldBlock);
        fb.record_error(&err);

        assert!(fb.is_congested(Duration::from_secs(1)));
    }

    #[test]
    fn test_feedback_record_result() {
        let fb = TransportFeedback::new();

        let ok_result: io::Result<usize> = Ok(100);
        assert_eq!(fb.record_result(&ok_result), TransportSignal::Success);

        let err_result: io::Result<usize> = Err(io::Error::from(io::ErrorKind::WouldBlock));
        assert_eq!(fb.record_result(&err_result), TransportSignal::WouldBlock);

        assert_eq!(fb.sends_total(), 2);
        assert_eq!(fb.sends_ok(), 1);
        assert_eq!(fb.eagain_count(), 1);
    }

    #[test]
    fn test_feedback_reset() {
        let fb = TransportFeedback::new();

        fb.record_success();
        fb.record_success();
        let err = io::Error::from(io::ErrorKind::WouldBlock);
        fb.record_error(&err);

        fb.reset();

        assert_eq!(fb.sends_total(), 0);
        assert_eq!(fb.sends_ok(), 0);
        assert_eq!(fb.eagain_count(), 0);
        assert!(!fb.is_congested(Duration::from_secs(1)));
    }

    #[test]
    fn test_snapshot() {
        let fb = TransportFeedback::new();

        for _ in 0..5 {
            fb.record_success();
        }
        let err = io::Error::from(io::ErrorKind::WouldBlock);
        fb.record_error(&err);

        let snap = fb.snapshot();
        assert_eq!(snap.sends_total, 6);
        assert_eq!(snap.sends_ok, 5);
        assert_eq!(snap.eagain_count, 1);
        assert_eq!(snap.congestion_count(), 1);
    }

    #[test]
    fn test_signal_properties() {
        assert!(TransportSignal::WouldBlock.is_congestion());
        assert!(TransportSignal::NoBuffers.is_congestion());
        assert!(!TransportSignal::Success.is_congestion());
        assert!(!TransportSignal::TransientError.is_congestion());

        assert!(TransportSignal::WouldBlock.should_retry());
        assert!(!TransportSignal::NoBuffers.should_retry());
        assert!(TransportSignal::TransientError.should_retry());

        assert!(TransportSignal::Success.is_recoverable());
        assert!(TransportSignal::WouldBlock.is_recoverable());
        assert!(!TransportSignal::FatalError.is_recoverable());
    }

    #[test]
    fn test_empty_success_rate() {
        let fb = TransportFeedback::new();
        assert!((fb.success_rate() - 1.0).abs() < 0.001);
        assert!(fb.congestion_rate().abs() < 0.001);
    }

    #[test]
    fn test_time_since_congestion() {
        let fb = TransportFeedback::new();

        assert!(fb.time_since_congestion().is_none());

        let err = io::Error::from(io::ErrorKind::WouldBlock);
        fb.record_error(&err);

        let elapsed = fb.time_since_congestion();
        assert!(elapsed.is_some());
        assert!(elapsed.unwrap() < Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_classify_enobufs_linux() {
        let err = io::Error::from_raw_os_error(105); // ENOBUFS on Linux
        assert_eq!(classify_error(&err), TransportSignal::NoBuffers);
        assert!(classify_error(&err).is_congestion());
    }
}

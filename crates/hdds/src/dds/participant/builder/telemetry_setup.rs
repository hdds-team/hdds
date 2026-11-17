// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Telemetry subsystem initialization.
//!
//! This module handles:
//! - MetricsCollector initialization
//! - Telemetry exporter setup (optional, can be disabled via env var)
//! - Telemetry push thread spawning

use crate::dds::participant::telemetry::telemetry_push_loop;
use crate::telemetry;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

/// Initialize metrics collector and telemetry exporter.
///
/// # Telemetry Exporter Control
/// - By default, shares the live exporter of the process, or starts one on
///   127.0.0.1:4242
/// - Falls back to random port if 4242 is busy (TIME_WAIT state)
/// - Can be disabled via `HDDS_EXPORTER_DISABLE=1|true|yes` env var
///
/// # Returns
/// The MetricsCollector for use throughout participant lifecycle, and the
/// exporter the participant keeps alive (it stops with the last holder).
pub(super) fn init_telemetry() -> (
    Arc<telemetry::MetricsCollector>,
    Option<Arc<telemetry::Exporter>>,
) {
    let metrics = telemetry::init_metrics();
    log::debug!("[hdds] metrics initialized");

    // Check if telemetry exporter should be disabled
    let exporter_raw = std::env::var("HDDS_EXPORTER_DISABLE").ok();
    if let Some(ref raw) = exporter_raw {
        log::debug!("[hdds] HDDS_EXPORTER_DISABLE={raw}");
    }

    let exporter_disabled = exporter_raw
        .as_deref()
        .map(|value| {
            let normalized = value.trim();
            normalized == "1"
                || normalized.eq_ignore_ascii_case("true")
                || normalized.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false);

    let exporter = if exporter_disabled {
        log::debug!("[hdds] telemetry exporter disabled via HDDS_EXPORTER_DISABLE");
        None
    } else {
        match telemetry::shared_exporter("127.0.0.1", 4242) {
            Ok(exporter) => Some(exporter),
            Err(err) => {
                log::debug!("[hdds] telemetry exporter disabled (init failed: {})", err);
                None
            }
        }
    };

    log::debug!("[hdds] telemetry setup complete");
    (metrics, exporter)
}

/// The telemetry push thread of a participant, and the exporter it keeps
/// alive. Dropping it stops the thread and joins it (also when the build
/// that started it fails half-way).
pub(crate) struct TelemetryThread {
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    _exporter: Option<Arc<telemetry::Exporter>>,
}

impl TelemetryThread {
    /// Stop the push thread and wait for it.
    pub(crate) fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            handle.thread().unpark();
            crate::core::rt::shutdown::join_bounded(handle, "telemetry push");
        }
    }
}

impl Drop for TelemetryThread {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn telemetry push thread.
///
/// Starts background thread that periodically pushes metrics to exporter.
///
/// # Arguments
/// - `metrics`: MetricsCollector to push from
/// - `exporter`: the exporter to keep alive while the thread runs
///
/// # Returns
/// TelemetryThread, which stops the thread when dropped
pub(super) fn spawn_telemetry_thread(
    metrics: Arc<telemetry::MetricsCollector>,
    exporter: Option<Arc<telemetry::Exporter>>,
) -> TelemetryThread {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let metrics_clone = metrics.clone();

    let handle = thread::Builder::new()
        .name("hdds-telemetry".into())
        .spawn(crate::core::rt::shutdown::owned(move || {
            telemetry_push_loop(metrics_clone, shutdown_clone)
        }))
        .map_err(|e| log::warn!("[hdds] telemetry push thread not started: {e}"))
        .ok();

    TelemetryThread {
        shutdown,
        handle,
        _exporter: exporter,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_telemetry() {
        // Just verify it doesn't crash
        let _telemetry = init_telemetry();
    }

    #[test]
    fn test_spawn_telemetry_thread() {
        let metrics = telemetry::init_metrics();
        let mut telemetry = spawn_telemetry_thread(metrics, None);

        // Immediately shut down: the push period is not waited out.
        let start = std::time::Instant::now();
        telemetry.stop();
        assert!(telemetry.handle.is_none());
        assert!(start.elapsed() < std::time::Duration::from_millis(90));
    }
}

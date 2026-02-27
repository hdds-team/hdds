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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

/// Initialize metrics collector and telemetry exporter.
///
/// # Telemetry Exporter Control
/// - By default, tries to bind to 127.0.0.1:4242
/// - Falls back to random port if 4242 is busy (TIME_WAIT state)
/// - Can be disabled via `HDDS_EXPORTER_DISABLE=1|true|yes` env var
///
/// # Returns
/// Arc<MetricsCollector> for use throughout participant lifecycle
pub(super) fn init_telemetry() -> Arc<telemetry::MetricsCollector> {
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

    if exporter_disabled {
        log::debug!("[hdds] telemetry exporter disabled via HDDS_EXPORTER_DISABLE");
    } else {
        // Try port 4242 first, fallback to random port if busy
        match telemetry::init_exporter("127.0.0.1", 4242).or_else(|_| {
            log::debug!("[!] Port 4242 busy (TIME_WAIT?), using random port");
            telemetry::init_exporter("127.0.0.1", 0)
        }) {
            Ok(exporter) => {
                let _ = exporter; // Keep exporter alive
            }
            Err(err) => {
                log::debug!("[hdds] telemetry exporter disabled (init failed: {})", err);
            }
        }
    }

    log::debug!("[hdds] telemetry setup complete");
    metrics
}

/// Telemetry thread components.
pub(super) struct TelemetryThread {
    pub shutdown: Arc<AtomicBool>,
    pub handle: thread::JoinHandle<()>,
}

/// Spawn telemetry push thread.
///
/// Starts background thread that periodically pushes metrics to exporter.
/// Thread can be stopped by setting `shutdown` flag to `true`.
///
/// # Arguments
/// - `metrics`: MetricsCollector to push from
///
/// # Returns
/// TelemetryThread with shutdown flag and thread handle
pub(super) fn spawn_telemetry_thread(metrics: Arc<telemetry::MetricsCollector>) -> TelemetryThread {
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let metrics_clone = metrics.clone();

    let handle = thread::spawn(move || telemetry_push_loop(metrics_clone, shutdown_clone));

    TelemetryThread { shutdown, handle }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_init_telemetry() {
        // Just verify it doesn't crash
        let _metrics = init_telemetry();
    }

    #[test]
    fn test_spawn_telemetry_thread() {
        let metrics = telemetry::init_metrics();
        let telemetry = spawn_telemetry_thread(metrics);

        // Immediately shut down
        telemetry.shutdown.store(true, Ordering::SeqCst);
        let _ = telemetry.handle.join();
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Telemetry and metrics collection for HDDS C FFI

use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;
use std::sync::Arc;

use super::HddsError;

/// Opaque handle to a MetricsCollector
#[repr(C)]
pub struct HddsMetrics {
    _private: [u8; 0],
}

/// Opaque handle to a telemetry Exporter
#[repr(C)]
pub struct HddsTelemetryExporter {
    _private: [u8; 0],
}

/// Telemetry metrics snapshot (C-compatible)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct HddsMetricsSnapshot {
    /// Timestamp in nanoseconds since epoch
    pub timestamp_ns: u64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
    /// Total messages dropped
    pub messages_dropped: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Latency p50 in nanoseconds
    pub latency_p50_ns: u64,
    /// Latency p99 in nanoseconds
    pub latency_p99_ns: u64,
    /// Latency p999 in nanoseconds
    pub latency_p999_ns: u64,
    /// Merge full count (backpressure events)
    pub merge_full_count: u64,
    /// Would-block count (send buffer full)
    pub would_block_count: u64,
}

// =============================================================================
// Global Metrics
// =============================================================================

/// Initialize the global metrics collector
///
/// Creates a thread-safe metrics collector for the entire HDDS instance.
/// Safe to call multiple times - subsequent calls return the same instance.
///
/// # Safety
/// The returned handle must be released with `hdds_telemetry_release`.
///
/// # Returns
/// Handle to the metrics collector, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_telemetry_init() -> *mut HddsMetrics {
    let metrics = hdds::telemetry::init_metrics();
    Arc::into_raw(metrics) as *mut HddsMetrics
}

/// Get the global metrics collector (if initialized)
///
/// # Safety
/// The returned handle must be released with `hdds_telemetry_release`.
///
/// # Returns
/// Handle to metrics collector, or NULL if not initialized
#[no_mangle]
pub unsafe extern "C" fn hdds_telemetry_get() -> *mut HddsMetrics {
    match hdds::telemetry::get_metrics_opt() {
        Some(metrics) => Arc::into_raw(metrics) as *mut HddsMetrics,
        None => ptr::null_mut(),
    }
}

/// Release a metrics handle
///
/// # Safety
/// - `metrics` must be a valid pointer from `hdds_telemetry_init` or `hdds_telemetry_get`
#[no_mangle]
pub unsafe extern "C" fn hdds_telemetry_release(metrics: *mut HddsMetrics) {
    if !metrics.is_null() {
        let _ = Arc::from_raw(metrics.cast::<hdds::telemetry::MetricsCollector>());
    }
}

/// Take a snapshot of current metrics
///
/// # Safety
/// - `metrics` must be a valid handle
/// - `out` must be a valid pointer to `HddsMetricsSnapshot`
///
/// # Returns
/// `HddsError::HddsOk` on success
#[no_mangle]
pub unsafe extern "C" fn hdds_telemetry_snapshot(
    metrics: *mut HddsMetrics,
    out: *mut HddsMetricsSnapshot,
) -> HddsError {
    if metrics.is_null() || out.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    // Clone the Arc to avoid consuming it
    let arc = Arc::from_raw(metrics.cast::<hdds::telemetry::MetricsCollector>());
    let clone = arc.clone();
    let _ = Arc::into_raw(arc); // Put it back

    let frame = clone.snapshot();

    // Extract fields from frame
    let mut snapshot = HddsMetricsSnapshot {
        timestamp_ns: frame.ts_ns,
        ..Default::default()
    };

    use hdds::telemetry::metrics::*;
    for field in &frame.fields {
        match field.tag {
            TAG_MESSAGES_SENT => snapshot.messages_sent = field.value_u64,
            TAG_MESSAGES_RECEIVED => snapshot.messages_received = field.value_u64,
            TAG_MESSAGES_DROPPED => snapshot.messages_dropped = field.value_u64,
            TAG_BYTES_SENT => snapshot.bytes_sent = field.value_u64,
            TAG_LATENCY_P50 => snapshot.latency_p50_ns = field.value_u64,
            TAG_LATENCY_P99 => snapshot.latency_p99_ns = field.value_u64,
            TAG_LATENCY_P999 => snapshot.latency_p999_ns = field.value_u64,
            TAG_MERGE_FULL_COUNT => snapshot.merge_full_count = field.value_u64,
            TAG_WOULD_BLOCK_COUNT => snapshot.would_block_count = field.value_u64,
            _ => {}
        }
    }

    *out = snapshot;
    HddsError::HddsOk
}

/// Record a latency sample
///
/// # Safety
/// - `metrics` must be a valid handle
///
/// # Arguments
/// * `start_ns` - Start timestamp in nanoseconds
/// * `end_ns` - End timestamp in nanoseconds
#[no_mangle]
pub unsafe extern "C" fn hdds_telemetry_record_latency(
    metrics: *mut HddsMetrics,
    start_ns: u64,
    end_ns: u64,
) {
    if metrics.is_null() {
        return;
    }

    let arc = Arc::from_raw(metrics.cast::<hdds::telemetry::MetricsCollector>());
    arc.add_latency_sample(start_ns, end_ns);
    let _ = Arc::into_raw(arc);
}

// =============================================================================
// Telemetry Exporter (TCP streaming server)
// =============================================================================

/// Start the telemetry export server
///
/// Creates a TCP server that streams metrics to connected clients (e.g., HDDS Viewer).
///
/// # Safety
/// - `bind_addr` must be a valid null-terminated C string.
/// - The returned handle must be released with `hdds_telemetry_stop_exporter`.
///
/// # Arguments
/// * `bind_addr` - IP address to bind (e.g., "127.0.0.1" or "0.0.0.0")
/// * `port` - Port number (default: 4242)
///
/// # Returns
/// Handle to exporter, or NULL on error
#[no_mangle]
pub unsafe extern "C" fn hdds_telemetry_start_exporter(
    bind_addr: *const c_char,
    port: u16,
) -> *mut HddsTelemetryExporter {
    if bind_addr.is_null() {
        return ptr::null_mut();
    }

    let Ok(addr_str) = CStr::from_ptr(bind_addr).to_str() else {
        return ptr::null_mut();
    };

    match hdds::telemetry::init_exporter(addr_str, port) {
        Ok(exporter) => Arc::into_raw(exporter) as *mut HddsTelemetryExporter,
        Err(e) => {
            log::error!("Failed to start telemetry exporter: {}", e);
            ptr::null_mut()
        }
    }
}

/// Stop and release the telemetry exporter
///
/// # Safety
/// - `exporter` must be a valid pointer from `hdds_telemetry_start_exporter`
#[no_mangle]
pub unsafe extern "C" fn hdds_telemetry_stop_exporter(exporter: *mut HddsTelemetryExporter) {
    if !exporter.is_null() {
        let _ = Arc::from_raw(exporter.cast::<hdds::telemetry::Exporter>());
    }
}

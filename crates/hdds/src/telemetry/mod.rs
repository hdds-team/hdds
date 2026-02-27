// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Telemetry collection, export, and live capture for HDDS monitoring.
//!
#![allow(missing_docs)]
//!
//! # Modules
//! - `metrics`: Thread-safe metrics collection with atomic counters and latency histograms
//! - `export`: Binary frame encoding/decoding (HDMX format)
//! - `capture`: Live telemetry streaming server for HDDS Viewer
//!
//! # Usage
//! ```rust,no_run
//! use hdds::telemetry::{init_metrics, init_exporter, get_metrics};
//!
//! // Initialize global metrics collector
//! let metrics = init_metrics();
//!
//! // Initialize telemetry exporter (optional)
//! let exporter = init_exporter("127.0.0.1", 4242).ok();
//!
//! // Record metrics
//! metrics.increment_sent(1);
//! let start_ns = 1_000_000u64;
//! let end_ns = 1_000_500u64;
//! metrics.add_latency_sample(start_ns, end_ns);
//!
//! // Snapshot current metrics
//! let frame = metrics.snapshot();
//! ```

/// Live telemetry streaming and capture server.
pub mod capture;
/// Binary telemetry frame encoding/decoding (HDMX format).
pub mod export;
/// Thread-safe metrics collection with atomic counters and latency histograms.
pub mod metrics;

pub use capture::{extract_metrics_from_collector, parse_frame_fields, Exporter};
pub use export::{decode_frame, encode_frame, MAGIC, VERSION};
pub use metrics::{Field, Frame, MetricsCollector};

use std::sync::{Arc, OnceLock};

static GLOBAL_METRICS: OnceLock<Arc<MetricsCollector>> = OnceLock::new();
static GLOBAL_EXPORTER: OnceLock<Arc<Exporter>> = OnceLock::new();

/// Initialize global metrics collector
pub fn init_metrics() -> Arc<MetricsCollector> {
    GLOBAL_METRICS
        .get_or_init(|| Arc::new(MetricsCollector::new()))
        .clone()
}

/// Get global metrics collector (creates if not initialized)
pub fn get_metrics() -> Arc<MetricsCollector> {
    GLOBAL_METRICS.get().cloned().unwrap_or_else(init_metrics)
}

/// Get global metrics collector (returns None if not initialized)
pub fn get_metrics_opt() -> Option<Arc<MetricsCollector>> {
    GLOBAL_METRICS.get().cloned()
}

/// Initialize global telemetry exporter
pub fn init_exporter(bind_addr: &str, port: u16) -> std::io::Result<Arc<Exporter>> {
    log::debug!("[hdds] telemetry::init_exporter({bind_addr}:{port}) starting");
    let exporter = Arc::new(Exporter::start(bind_addr, port)?);
    log::debug!("[hdds] telemetry::init_exporter({bind_addr}:{port}) ready");
    GLOBAL_EXPORTER.set(exporter.clone()).ok();
    Ok(exporter)
}

/// Get global exporter (returns None if not initialized)
pub fn get_exporter() -> Option<Arc<Exporter>> {
    GLOBAL_EXPORTER.get().cloned()
}

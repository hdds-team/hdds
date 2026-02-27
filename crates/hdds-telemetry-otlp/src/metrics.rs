// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS-specific metric instruments for HDDS.
//!
//! This module provides [`HddsMetrics`], a convenience wrapper around
//! OpenTelemetry counters and histograms that map to common DDS
//! operations (write, read, discovery).
//!
//! # Usage
//!
//! ```no_run
//! use hdds_telemetry_otlp::metrics::HddsMetrics;
//!
//! let m = HddsMetrics::new();
//! m.record_write(1_200);       // 1200 ns write latency
//! m.record_read();
//! m.record_discovery_event("participant_added");
//! ```

use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::{global, KeyValue};

/// Pre-built DDS metric instruments.
///
/// Create one instance per component and call the `record_*` methods
/// to emit measurements.  The underlying instruments are obtained from
/// the global `MeterProvider`, so [`crate::init_tracing`] (with
/// `export_metrics = true`) must be called first.
pub struct HddsMetrics {
    messages_sent: Counter<u64>,
    messages_received: Counter<u64>,
    discovery_events: Counter<u64>,
    write_latency_ns: Histogram<u64>,
}

impl HddsMetrics {
    /// Create a new set of HDDS metric instruments from the global meter.
    pub fn new() -> Self {
        let meter: Meter = global::meter("hdds");
        Self::from_meter(&meter)
    }

    /// Create instruments from an explicit [`Meter`].
    pub fn from_meter(meter: &Meter) -> Self {
        let messages_sent = meter
            .u64_counter("dds.messages.sent")
            .with_description("Total DDS messages sent")
            .build();

        let messages_received = meter
            .u64_counter("dds.messages.received")
            .with_description("Total DDS messages received")
            .build();

        let discovery_events = meter
            .u64_counter("dds.discovery.participants")
            .with_description("DDS discovery participant events")
            .build();

        let write_latency_ns = meter
            .u64_histogram("dds.latency.write_ns")
            .with_description("DDS write latency in nanoseconds")
            .build();

        Self {
            messages_sent,
            messages_received,
            discovery_events,
            write_latency_ns,
        }
    }

    /// Record a DDS write operation with the given latency in nanoseconds.
    ///
    /// Increments `dds.messages.sent` and records a sample in
    /// `dds.latency.write_ns`.
    pub fn record_write(&self, latency_ns: u64) {
        self.messages_sent.add(1, &[]);
        self.write_latency_ns.record(latency_ns, &[]);
    }

    /// Record a DDS read operation.
    ///
    /// Increments `dds.messages.received`.
    pub fn record_read(&self) {
        self.messages_received.add(1, &[]);
    }

    /// Record a DDS discovery event with the given event type.
    ///
    /// Increments `dds.discovery.participants` with an `event_type`
    /// attribute (e.g. `"participant_added"`, `"participant_removed"`).
    pub fn record_discovery_event(&self, event_type: &str) {
        self.discovery_events
            .add(1, &[KeyValue::new("event_type", event_type.to_string())]);
    }
}

impl Default for HddsMetrics {
    fn default() -> Self {
        Self::new()
    }
}

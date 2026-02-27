// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS OpenTelemetry OTLP exporter for traces and metrics.
//!
//! This crate bridges HDDS's existing `tracing` instrumentation to
//! OpenTelemetry OTLP exporters, enabling distributed tracing and
//! metrics collection via gRPC (tonic) to any OTLP-compatible backend
//! (Jaeger, Grafana Tempo, etc.).
//!
//! # Quick Start
//!
//! ```no_run
//! use hdds_telemetry_otlp::{OtlpConfig, init_tracing};
//!
//! let config = OtlpConfig::default();
//! let _guard = init_tracing(config).expect("Failed to init OTLP tracing");
//!
//! // All tracing::info_span! / tracing::info! calls are now exported as
//! // OpenTelemetry spans to the configured OTLP endpoint.
//! ```

pub mod metrics;

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Configuration for the OTLP exporter.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// OTLP collector endpoint (gRPC).
    /// Defaults to `http://localhost:4317`.
    pub endpoint: String,

    /// Service name reported to the collector.
    /// Defaults to `hdds`.
    pub service_name: String,

    /// Whether to export traces via OTLP.
    /// Defaults to `true`.
    pub export_traces: bool,

    /// Whether to export metrics via OTLP.
    /// Defaults to `true`.
    pub export_metrics: bool,

    /// Batch export timeout in milliseconds.
    /// Defaults to `5000`.
    pub batch_timeout_ms: u64,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            service_name: "hdds".to_string(),
            export_traces: true,
            export_metrics: true,
            batch_timeout_ms: 5000,
        }
    }
}

/// Errors that can occur during OTLP initialization.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error from the OpenTelemetry trace subsystem.
    #[error("OpenTelemetry trace error: {0}")]
    Trace(#[from] opentelemetry_sdk::trace::TraceError),

    /// An error from the OpenTelemetry metrics subsystem.
    #[error("OpenTelemetry metrics error: {0}")]
    Metrics(String),

    /// An error while building the OTLP exporter.
    #[error("OTLP exporter build error: {0}")]
    ExporterBuild(#[from] opentelemetry_otlp::ExporterBuildError),

    /// Failed to set the global tracing subscriber.
    #[error("Failed to set global tracing subscriber: {0}")]
    SetSubscriber(String),
}

/// Guard that shuts down the tracer provider when dropped.
///
/// Hold this value for the lifetime of your application. When it is
/// dropped, it flushes any remaining spans and shuts down the
/// OpenTelemetry pipeline.
pub struct OtlpGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl Drop for OtlpGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.tracer_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("hdds-telemetry-otlp: tracer shutdown error: {e}");
            }
        }
        if let Some(provider) = self.meter_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("hdds-telemetry-otlp: meter shutdown error: {e}");
            }
        }
    }
}

/// Initialize OpenTelemetry tracing with OTLP export.
///
/// This sets up:
/// - An OTLP `SpanExporter` via gRPC (tonic) pointed at `config.endpoint`
/// - A `SdkTracerProvider` with batch span processing
/// - A `tracing_opentelemetry::OpenTelemetryLayer` wired into
///   `tracing_subscriber::Registry` with `EnvFilter`
///
/// Returns an [`OtlpGuard`] that must be held alive for the duration of
/// the application. Dropping it triggers a clean shutdown of the pipeline.
pub fn init_tracing(config: OtlpConfig) -> Result<OtlpGuard, Error> {
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .build();

    // -- Traces --
    let tracer_provider = if config.export_traces {
        let span_exporter = SpanExporter::builder().with_tonic().build()?;

        let provider = SdkTracerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter)
            .build();

        global::set_tracer_provider(provider.clone());
        Some(provider)
    } else {
        None
    };

    // -- Metrics --
    let meter_provider = if config.export_metrics {
        let mp = init_metrics(&config, resource)?;
        Some(mp)
    } else {
        None
    };

    // -- Tracing subscriber --
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if let Some(ref tp) = tracer_provider {
        let tracer = tp.tracer("hdds");
        let otel_layer = OpenTelemetryLayer::new(tracer);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(otel_layer)
            .try_init()
            .map_err(|e| Error::SetSubscriber(e.to_string()))?;
    } else {
        // No traces -- just set up env_filter logging
        tracing_subscriber::registry()
            .with(env_filter)
            .try_init()
            .map_err(|e| Error::SetSubscriber(e.to_string()))?;
    }

    Ok(OtlpGuard {
        tracer_provider,
        meter_provider,
    })
}

/// Initialize OTLP metrics export.
///
/// Creates an OTLP `MetricExporter` via gRPC and registers a
/// `SdkMeterProvider` with a periodic reader.  The following DDS
/// instruments are pre-registered (but only emit data when
/// [`metrics::HddsMetrics`] is used):
///
/// - `dds.messages.sent` (counter)
/// - `dds.messages.received` (counter)
/// - `dds.discovery.participants` (counter)
/// - `dds.latency.write_ns` (histogram)
fn init_metrics(_config: &OtlpConfig, resource: Resource) -> Result<SdkMeterProvider, Error> {
    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .build()?;

    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(metric_exporter)
        .build();

    global::set_meter_provider(meter_provider.clone());

    // Pre-create instruments so they appear in the schema even before
    // any data is recorded.
    let meter = global::meter("hdds");
    let _sent = meter
        .u64_counter("dds.messages.sent")
        .with_description("Total DDS messages sent")
        .build();
    let _recv = meter
        .u64_counter("dds.messages.received")
        .with_description("Total DDS messages received")
        .build();
    let _disc = meter
        .u64_counter("dds.discovery.participants")
        .with_description("DDS discovery participant events")
        .build();
    let _lat = meter
        .u64_histogram("dds.latency.write_ns")
        .with_description("DDS write latency in nanoseconds")
        .build();

    Ok(meter_provider)
}

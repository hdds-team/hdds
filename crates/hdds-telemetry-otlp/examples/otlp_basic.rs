// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Basic example: export DDS-like tracing spans to an OTLP collector.
//!
//! Run a local OTLP collector on `localhost:4317` (e.g. Jaeger with OTLP
//! receiver) and then:
//!
//! ```sh
//! cargo run --example otlp_basic
//! ```
//!
//! You should see spans named `dds.write` and `dds.read` appear in the
//! collector UI.

use hdds_telemetry_otlp::metrics::HddsMetrics;
use hdds_telemetry_otlp::{init_tracing, OtlpConfig};

fn main() {
    // 1. Configure and initialize OTLP export
    let config = OtlpConfig {
        endpoint: "http://localhost:4317".to_string(),
        service_name: "hdds-example".to_string(),
        export_traces: true,
        export_metrics: true,
        batch_timeout_ms: 2000,
    };

    let _guard = init_tracing(config).expect("Failed to init OTLP tracing");

    // 2. Create metric instruments
    let metrics = HddsMetrics::new();

    // 3. Simulate some DDS activity with tracing spans
    simulate_dds_activity(&metrics);

    // 4. Give the batch exporter a moment to flush
    std::thread::sleep(std::time::Duration::from_secs(3));

    // 5. OtlpGuard is dropped here, triggering clean shutdown
    println!("Shutting down OTLP pipeline...");
}

fn simulate_dds_activity(metrics: &HddsMetrics) {
    for i in 0..5 {
        // Simulate a DDS write
        {
            let _span = tracing::info_span!("dds.write", topic = "SensorData", seq = i).entered();
            tracing::info!("Writing sample {} to topic SensorData", i);

            // Simulate some work
            std::thread::sleep(std::time::Duration::from_millis(10));

            // Record metrics
            let latency_ns = 10_000_000 + (i as u64 * 500_000); // ~10ms + jitter
            metrics.record_write(latency_ns);
        }

        // Simulate a DDS read
        {
            let _span = tracing::info_span!("dds.read", topic = "SensorData", seq = i).entered();
            tracing::info!("Reading sample {} from topic SensorData", i);

            std::thread::sleep(std::time::Duration::from_millis(5));
            metrics.record_read();
        }
    }

    // Simulate a discovery event
    {
        let _span = tracing::info_span!("dds.discovery").entered();
        tracing::info!("New participant discovered");
        metrics.record_discovery_event("participant_added");
    }
}

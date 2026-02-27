// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Prometheus-compatible metrics export for IP mobility.
//!
//! Provides functions to export mobility metrics in Prometheus text format.
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds::transport::mobility::{MobilityMetrics, prometheus};
//!
//! let metrics = MobilityMetrics::new();
//! // ... use metrics ...
//!
//! // Export as Prometheus text format
//! let output = prometheus::export_metrics(&metrics.snapshot(), "hdds");
//! println!("{}", output);
//! ```

use super::metrics::MobilityMetricsSnapshot;
use std::fmt::Write;

/// Prometheus metric type.
#[derive(Clone, Copy, Debug)]
pub enum MetricType {
    /// A counter that only increases.
    Counter,
    /// A gauge that can go up or down.
    Gauge,
}

impl MetricType {
    fn as_str(&self) -> &'static str {
        match self {
            MetricType::Counter => "counter",
            MetricType::Gauge => "gauge",
        }
    }
}

/// A single metric definition.
struct MetricDef {
    name: &'static str,
    help: &'static str,
    metric_type: MetricType,
}

const MOBILITY_METRICS: &[MetricDef] = &[
    MetricDef {
        name: "addresses_added_total",
        help: "Total number of IP addresses added",
        metric_type: MetricType::Counter,
    },
    MetricDef {
        name: "addresses_removed_total",
        help: "Total number of IP addresses removed",
        metric_type: MetricType::Counter,
    },
    MetricDef {
        name: "reannounce_bursts_total",
        help: "Total number of reannounce bursts triggered",
        metric_type: MetricType::Counter,
    },
    MetricDef {
        name: "reannounce_packets_total",
        help: "Total number of reannounce packets sent",
        metric_type: MetricType::Counter,
    },
    MetricDef {
        name: "polls_total",
        help: "Total number of IP detection polls performed",
        metric_type: MetricType::Counter,
    },
    MetricDef {
        name: "locators_expired_total",
        help: "Total number of locators that expired from hold-down",
        metric_type: MetricType::Counter,
    },
    MetricDef {
        name: "locators_active",
        help: "Current number of active locators",
        metric_type: MetricType::Gauge,
    },
    MetricDef {
        name: "locators_hold_down",
        help: "Current number of locators in hold-down state",
        metric_type: MetricType::Gauge,
    },
    MetricDef {
        name: "uptime_seconds",
        help: "Time since metrics were created in seconds",
        metric_type: MetricType::Gauge,
    },
];

/// Export mobility metrics in Prometheus text format.
///
/// # Arguments
///
/// * `snapshot` - The metrics snapshot to export
/// * `prefix` - Metric name prefix (e.g., "hdds" -> "hdds_mobility_...")
///
/// # Returns
///
/// A string in Prometheus text exposition format.
pub fn export_metrics(snapshot: &MobilityMetricsSnapshot, prefix: &str) -> String {
    let mut output = String::with_capacity(2048);

    for def in MOBILITY_METRICS {
        let full_name = format!("{}_mobility_{}", prefix, def.name);

        // TYPE line
        let _ = writeln!(output, "# TYPE {} {}", full_name, def.metric_type.as_str());

        // HELP line
        let _ = writeln!(output, "# HELP {} {}", full_name, def.help);

        // Value line
        let value = get_metric_value(snapshot, def.name);
        let _ = writeln!(output, "{} {}", full_name, value);

        // Blank line between metrics
        let _ = writeln!(output);
    }

    // Add derived metrics
    append_derived_metrics(&mut output, snapshot, prefix);

    output
}

/// Get the value for a metric by name.
// @audit-ok: Simple pattern matching (cyclo 11, cogni 1) - metric name to value lookup table
fn get_metric_value(snapshot: &MobilityMetricsSnapshot, name: &str) -> String {
    match name {
        "addresses_added_total" => snapshot.addresses_added.to_string(),
        "addresses_removed_total" => snapshot.addresses_removed.to_string(),
        "reannounce_bursts_total" => snapshot.reannounce_bursts.to_string(),
        "reannounce_packets_total" => snapshot.reannounce_packets.to_string(),
        "polls_total" => snapshot.polls_performed.to_string(),
        "locators_expired_total" => snapshot.locators_expired.to_string(),
        "locators_active" => snapshot.locators_active.to_string(),
        "locators_hold_down" => snapshot.locators_hold_down.to_string(),
        "uptime_seconds" => format!("{:.3}", snapshot.uptime.as_secs_f64()),
        _ => "0".to_string(),
    }
}

/// Append derived metrics.
fn append_derived_metrics(output: &mut String, snapshot: &MobilityMetricsSnapshot, prefix: &str) {
    // Total locators
    let _ = writeln!(output, "# TYPE {}_mobility_locators_total gauge", prefix);
    let _ = writeln!(
        output,
        "# HELP {}_mobility_locators_total Total number of tracked locators (active + hold-down)",
        prefix
    );
    let _ = writeln!(
        output,
        "{}_mobility_locators_total {}",
        prefix,
        snapshot.total_locators()
    );
    let _ = writeln!(output);

    // Total changes
    let _ = writeln!(output, "# TYPE {}_mobility_changes_total counter", prefix);
    let _ = writeln!(
        output,
        "# HELP {}_mobility_changes_total Total number of IP address changes (added + removed)",
        prefix
    );
    let _ = writeln!(
        output,
        "{}_mobility_changes_total {}",
        prefix,
        snapshot.total_changes()
    );
    let _ = writeln!(output);

    // Average packets per burst
    let _ = writeln!(
        output,
        "# TYPE {}_mobility_avg_packets_per_burst gauge",
        prefix
    );
    let _ = writeln!(
        output,
        "# HELP {}_mobility_avg_packets_per_burst Average number of packets per reannounce burst",
        prefix
    );
    let _ = writeln!(
        output,
        "{}_mobility_avg_packets_per_burst {:.3}",
        prefix,
        snapshot.avg_packets_per_burst()
    );
    let _ = writeln!(output);

    // Poll rate
    let _ = writeln!(output, "# TYPE {}_mobility_poll_rate gauge", prefix);
    let _ = writeln!(
        output,
        "# HELP {}_mobility_poll_rate IP detection polls per second",
        prefix
    );
    let _ = writeln!(
        output,
        "{}_mobility_poll_rate {:.3}",
        prefix,
        snapshot.poll_rate()
    );
    let _ = writeln!(output);

    // Change rate per minute
    let _ = writeln!(
        output,
        "# TYPE {}_mobility_change_rate_per_minute gauge",
        prefix
    );
    let _ = writeln!(
        output,
        "# HELP {}_mobility_change_rate_per_minute IP address changes per minute",
        prefix
    );
    let _ = writeln!(
        output,
        "{}_mobility_change_rate_per_minute {:.3}",
        prefix,
        snapshot.change_rate_per_minute()
    );
}

/// Export a single metric value in Prometheus format.
///
/// Useful for custom integrations.
pub fn format_metric(name: &str, help: &str, metric_type: MetricType, value: f64) -> String {
    format!(
        "# TYPE {} {}\n# HELP {} {}\n{} {}\n",
        name,
        metric_type.as_str(),
        name,
        help,
        name,
        value
    )
}

/// Export a labeled metric value.
pub fn format_labeled_metric(name: &str, labels: &[(&str, &str)], value: f64) -> String {
    if labels.is_empty() {
        format!("{} {}\n", name, value)
    } else {
        let label_str: String = labels
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, v))
            .collect::<Vec<_>>()
            .join(",");
        format!("{}{{{}}} {}\n", name, label_str, value)
    }
}

/// Builder for custom metrics export.
pub struct MetricsExporter {
    prefix: String,
    output: String,
}

impl MetricsExporter {
    /// Create a new exporter with the given prefix.
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            output: String::with_capacity(4096),
        }
    }

    /// Add a counter metric.
    pub fn counter(&mut self, name: &str, help: &str, value: u64) -> &mut Self {
        let full_name = format!("{}_{}", self.prefix, name);
        let _ = writeln!(self.output, "# TYPE {} counter", full_name);
        let _ = writeln!(self.output, "# HELP {} {}", full_name, help);
        let _ = writeln!(self.output, "{} {}", full_name, value);
        let _ = writeln!(self.output);
        self
    }

    /// Add a gauge metric.
    pub fn gauge(&mut self, name: &str, help: &str, value: f64) -> &mut Self {
        let full_name = format!("{}_{}", self.prefix, name);
        let _ = writeln!(self.output, "# TYPE {} gauge", full_name);
        let _ = writeln!(self.output, "# HELP {} {}", full_name, help);
        let _ = writeln!(self.output, "{} {}", full_name, value);
        let _ = writeln!(self.output);
        self
    }

    /// Add a labeled counter.
    pub fn counter_labeled(
        &mut self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        value: u64,
    ) -> &mut Self {
        let full_name = format!("{}_{}", self.prefix, name);

        // Only write TYPE/HELP if this is the first occurrence
        if !self.output.contains(&format!("# TYPE {}", full_name)) {
            let _ = writeln!(self.output, "# TYPE {} counter", full_name);
            let _ = writeln!(self.output, "# HELP {} {}", full_name, help);
        }

        let _ = write!(
            self.output,
            "{}",
            format_labeled_metric(&full_name, labels, value as f64)
        );
        self
    }

    /// Add a labeled gauge.
    pub fn gauge_labeled(
        &mut self,
        name: &str,
        help: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) -> &mut Self {
        let full_name = format!("{}_{}", self.prefix, name);

        // Only write TYPE/HELP if this is the first occurrence
        if !self.output.contains(&format!("# TYPE {}", full_name)) {
            let _ = writeln!(self.output, "# TYPE {} gauge", full_name);
            let _ = writeln!(self.output, "# HELP {} {}", full_name, help);
        }

        let _ = write!(
            self.output,
            "{}",
            format_labeled_metric(&full_name, labels, value)
        );
        self
    }

    /// Build the final output string.
    pub fn build(self) -> String {
        self.output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_snapshot() -> MobilityMetricsSnapshot {
        MobilityMetricsSnapshot {
            addresses_added: 10,
            addresses_removed: 5,
            reannounce_bursts: 3,
            reannounce_packets: 15,
            polls_performed: 120,
            locators_expired: 2,
            locators_active: 2,
            locators_hold_down: 1,
            uptime: Duration::from_secs(60),
        }
    }

    #[test]
    fn test_export_metrics_format() {
        let snapshot = make_snapshot();
        let output = export_metrics(&snapshot, "hdds");

        // Check structure
        assert!(output.contains("# TYPE hdds_mobility_addresses_added_total counter"));
        assert!(output.contains("# HELP hdds_mobility_addresses_added_total"));
        assert!(output.contains("hdds_mobility_addresses_added_total 10"));

        // Check gauges
        assert!(output.contains("# TYPE hdds_mobility_locators_active gauge"));
        assert!(output.contains("hdds_mobility_locators_active 2"));
    }

    #[test]
    fn test_export_metrics_derived() {
        let snapshot = make_snapshot();
        let output = export_metrics(&snapshot, "hdds");

        // Total changes = 10 + 5 = 15
        assert!(output.contains("hdds_mobility_changes_total 15"));

        // Total locators = 2 + 1 = 3
        assert!(output.contains("hdds_mobility_locators_total 3"));

        // Avg packets per burst = 15 / 3 = 5
        assert!(output.contains("hdds_mobility_avg_packets_per_burst 5.000"));
    }

    #[test]
    fn test_export_metrics_rates() {
        let snapshot = make_snapshot();
        let output = export_metrics(&snapshot, "hdds");

        // Poll rate = 120 / 60 = 2.0
        assert!(output.contains("hdds_mobility_poll_rate 2.000"));

        // Change rate = 15 changes / 1 minute = 15.0
        assert!(output.contains("hdds_mobility_change_rate_per_minute 15.000"));
    }

    #[test]
    fn test_format_metric() {
        let output = format_metric("my_counter", "A test counter", MetricType::Counter, 42.0);

        assert!(output.contains("# TYPE my_counter counter"));
        assert!(output.contains("# HELP my_counter A test counter"));
        assert!(output.contains("my_counter 42"));
    }

    #[test]
    fn test_format_labeled_metric() {
        let output = format_labeled_metric(
            "http_requests_total",
            &[("method", "GET"), ("status", "200")],
            123.0,
        );

        assert!(output.contains("http_requests_total{method=\"GET\",status=\"200\"} 123"));
    }

    #[test]
    fn test_format_labeled_metric_no_labels() {
        let output = format_labeled_metric("simple_metric", &[], 42.0);
        assert_eq!(output, "simple_metric 42\n");
    }

    #[test]
    fn test_metrics_exporter() {
        let mut exporter = MetricsExporter::new("hdds");
        exporter.counter("events_total", "Total events", 100).gauge(
            "current_value",
            "Current value",
            42.5,
        );
        let output = exporter.build();

        assert!(output.contains("# TYPE hdds_events_total counter"));
        assert!(output.contains("hdds_events_total 100"));
        assert!(output.contains("# TYPE hdds_current_value gauge"));
        assert!(output.contains("hdds_current_value 42.5"));
    }

    #[test]
    fn test_metrics_exporter_labeled() {
        let mut exporter = MetricsExporter::new("app");
        exporter
            .counter_labeled("http_requests", "HTTP requests", &[("method", "GET")], 100)
            .counter_labeled("http_requests", "HTTP requests", &[("method", "POST")], 50);
        let output = exporter.build();

        assert!(output.contains("http_requests{method=\"GET\"} 100"));
        assert!(output.contains("http_requests{method=\"POST\"} 50"));
    }

    #[test]
    fn test_metric_type_as_str() {
        assert_eq!(MetricType::Counter.as_str(), "counter");
        assert_eq!(MetricType::Gauge.as_str(), "gauge");
    }

    #[test]
    fn test_export_empty_snapshot() {
        let snapshot = MobilityMetricsSnapshot::default();
        let output = export_metrics(&snapshot, "test");

        // Should still produce valid output
        assert!(output.contains("# TYPE test_mobility_addresses_added_total counter"));
        assert!(output.contains("test_mobility_addresses_added_total 0"));
    }
}

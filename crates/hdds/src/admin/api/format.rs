// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! JSON formatting for Admin API responses (serde-free).
//!
//! Manually renders snapshots as JSON for minimal dependencies.

use super::super::snapshot::{EndpointsSnapshot, MeshSnapshot, MetricsSnapshot, TopicsSnapshot};
use super::time::timestamp_iso8601;

/// Render a mesh snapshot as JSON (serde-free for core crate minimalism).
pub(crate) fn format_json_mesh(snapshot: MeshSnapshot) -> String {
    let participants_json: Vec<String> = snapshot
        .participants
        .iter()
        .map(|p| {
            let mut fields = vec![
                format!(r#""guid":"{}""#, p.guid),
                format!(r#""name":"{}""#, p.name),
                format!(r#""is_local":{}"#, p.is_local),
            ];

            if let Some(ref state) = p.state {
                fields.push(format!(r#""state":"{}""#, state));
            }
            if let Some(ref endpoints) = p.endpoints {
                let endpoints_json: Vec<String> =
                    endpoints.iter().map(|e| format!(r#""{}""#, e)).collect();
                fields.push(format!(r#""endpoints":[{}]"#, endpoints_json.join(",")));
            }
            if let Some(lease_ms) = p.lease_ms {
                fields.push(format!(r#""lease_ms":{}"#, lease_ms));
            }
            if let Some(last_seen_ago_ms) = p.last_seen_ago_ms {
                fields.push(format!(r#""last_seen_ago_ms":{}"#, last_seen_ago_ms));
            }

            format!("{{{}}}", fields.join(","))
        })
        .collect();

    format!(
        r#"{{"schema_version":"1.0","timestamp":"{}","epoch":{},"participants":[{}]}}"#,
        timestamp_iso8601(),
        snapshot.epoch,
        participants_json.join(",")
    )
}

/// Render the topics snapshot as JSON (Tier 0 placeholder).
pub(crate) fn format_json_topics(snapshot: TopicsSnapshot) -> String {
    let topics_json: Vec<String> = snapshot
        .topics
        .iter()
        .map(|topic| {
            format!(
                r#"{{"name":"{}","type_name":"{}","writers":{},"readers":{}}}"#,
                topic.name, topic.type_name, topic.writers_count, topic.readers_count
            )
        })
        .collect();

    format!(
        r#"{{"schema_version":"1.0","timestamp":"{}","epoch":{},"topics":[{}]}}"#,
        timestamp_iso8601(),
        snapshot.epoch,
        topics_json.join(",")
    )
}

/// Render the metrics snapshot as JSON payload.
pub(crate) fn format_json_metrics(snapshot: MetricsSnapshot) -> String {
    format!(
        r#"{{"schema_version":"1.0","timestamp":"{}","epoch":{},"messages_sent":{},"messages_received":{},"messages_dropped":{},"latency_min_ns":{},"latency_p50_ns":{},"latency_p99_ns":{},"latency_max_ns":{}}}"#,
        timestamp_iso8601(),
        snapshot.epoch,
        snapshot.messages_sent,
        snapshot.messages_received,
        snapshot.messages_dropped,
        snapshot.latency_min_ns,
        snapshot.latency_p50_ns,
        snapshot.latency_p99_ns,
        snapshot.latency_max_ns
    )
}

/// Render health status message.
pub(crate) fn format_json_health(uptime_secs: u64) -> String {
    format!(
        r#"{{"schema_version":"1.0","timestamp":"{}","status":"ok","version":"0.1.0","uptime_secs":{}}}"#,
        timestamp_iso8601(),
        uptime_secs
    )
}

pub(crate) fn format_json_writers(snapshot: EndpointsSnapshot) -> String {
    format_endpoints(snapshot, "writers")
}

pub(crate) fn format_json_readers(snapshot: EndpointsSnapshot) -> String {
    format_endpoints(snapshot, "readers")
}

fn format_endpoints(snapshot: EndpointsSnapshot, label: &str) -> String {
    let endpoints_json: Vec<String> = snapshot
        .endpoints
        .iter()
        .map(|endpoint| {
            format!(
                r#"{{"guid":"{}","participant_guid":"{}","topic":"{}","type":"{}","reliability":"{}","durability":"{}","history":"{}"}}"#,
                endpoint.guid,
                endpoint.participant_guid,
                endpoint.topic_name,
                endpoint.type_name,
                endpoint.reliability,
                endpoint.durability,
                endpoint.history
            )
        })
        .collect();

    format!(
        r#"{{"schema_version":"1.0","timestamp":"{}","epoch":{},"{}":[{}]}}"#,
        timestamp_iso8601(),
        snapshot.epoch,
        label,
        endpoints_json.join(",")
    )
}

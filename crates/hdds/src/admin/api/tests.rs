// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use super::format::{
    format_json_health, format_json_mesh, format_json_metrics, format_json_topics,
};
use super::time::timestamp_iso8601;
use super::AdminApi;
use crate::admin::snapshot::{MeshSnapshot, MetricsSnapshot, TopicsSnapshot};
use crate::telemetry::parse_frame_fields;

#[test]
fn test_admin_api_bind() {
    let api = AdminApi::bind("127.0.0.1", 0, None).expect("AdminApi bind should succeed");
    api.shutdown();
}

#[test]
fn test_snapshot_mesh_empty() {
    let api = AdminApi::bind("127.0.0.1", 0, None).expect("AdminApi bind should succeed");
    let snapshot = api.snapshot_mesh();
    assert_eq!(snapshot.participants.len(), 0);
    api.shutdown();
}

#[test]
fn test_snapshot_mesh_with_local() {
    let api = AdminApi::bind("127.0.0.1", 0, None).expect("AdminApi bind should succeed");
    api.set_local_participant("test_node".to_string());
    let snapshot = api.snapshot_mesh();
    assert_eq!(snapshot.participants.len(), 1);
    assert_eq!(snapshot.participants[0].name, "test_node");
    api.shutdown();
}

#[test]
fn test_snapshot_topics_empty() {
    let api = AdminApi::bind("127.0.0.1", 0, None).expect("AdminApi bind should succeed");
    let snapshot = api.snapshot_topics();
    assert_eq!(snapshot.topics.len(), 0);
    api.shutdown();
}

#[test]
fn test_format_json_mesh() {
    use super::super::snapshot::ParticipantView;

    let snapshot = MeshSnapshot {
        epoch: 42,
        participants: vec![ParticipantView {
            guid: "00.00.00.01".to_string(),
            name: "test".to_string(),
            is_local: true,
            state: None,
            endpoints: None,
            lease_ms: None,
            last_seen_ago_ms: None,
        }],
    };

    let json = format_json_mesh(snapshot);
    assert!(json.contains(r#""schema_version":"1.0""#));
    assert!(json.contains(r#""timestamp":""#));
    assert!(json.contains(r#""epoch":42"#));
    assert!(json.contains(r#""name":"test""#));
}

#[test]
fn test_format_json_topics() {
    let snapshot = TopicsSnapshot {
        epoch: 10,
        topics: Vec::new(),
    };

    let json = format_json_topics(snapshot);
    assert!(json.contains(r#""schema_version":"1.0""#));
    assert!(json.contains(r#""timestamp":""#));
    assert!(json.contains(r#""topics":[]"#));
}

#[test]
fn test_format_json_metrics() {
    let snapshot = MetricsSnapshot {
        epoch: 5,
        messages_sent: 1000,
        messages_received: 950,
        messages_dropped: 10,
        latency_min_ns: 100,
        latency_p50_ns: 500,
        latency_p99_ns: 1000,
        latency_max_ns: 5000,
    };

    let json = format_json_metrics(snapshot);
    assert!(json.contains(r#""schema_version":"1.0""#));
    assert!(json.contains(r#""timestamp":""#));
    assert!(json.contains(r#""messages_sent":1000"#));
    assert!(json.contains(r#""latency_p99_ns":1000"#));
}

#[test]
fn test_format_json_health() {
    let json = format_json_health(3600);
    assert!(json.contains(r#""schema_version":"1.0""#));
    assert!(json.contains(r#""timestamp":""#));
    assert!(json.contains(r#""status":"ok""#));
    assert!(json.contains(r#""version":"0.1.0""#));
    assert!(json.contains(r#""uptime_secs":3600"#));
}

#[test]
fn test_timestamp_iso8601_format() {
    let ts = timestamp_iso8601();
    assert!(ts.contains('T'));
    assert!(ts.ends_with('Z'));
    assert!(ts.len() >= 20);
}

#[test]
fn test_uptime_secs() {
    let api = AdminApi::bind("127.0.0.1", 0, None).expect("AdminApi bind should succeed");
    let uptime = api.uptime_secs();
    assert_eq!(uptime, 0);
    api.shutdown();
}

#[test]
fn test_parse_frame_complete() {
    use crate::telemetry::metrics::{DType, Field, Frame};

    let frame = Frame {
        ts_ns: 0,
        fields: vec![
            Field {
                tag: 10,
                dtype: DType::U64,
                value_u64: 100,
            },
            Field {
                tag: 11,
                dtype: DType::U64,
                value_u64: 200,
            },
            Field {
                tag: 12,
                dtype: DType::U64,
                value_u64: 5,
            },
            Field {
                tag: 20,
                dtype: DType::U64,
                value_u64: 1000,
            },
            Field {
                tag: 21,
                dtype: DType::U64,
                value_u64: 5000,
            },
        ],
    };

    let (sent, recv, dropped, p50, p99) = parse_frame_fields(&frame);

    assert_eq!(sent, 100);
    assert_eq!(recv, 200);
    assert_eq!(dropped, 5);
    assert_eq!(p50, 1000);
    assert_eq!(p99, 5000);
}

#[test]
fn test_parse_frame_unknown_tags_ignored() {
    use crate::telemetry::metrics::{DType, Field, Frame};

    let frame = Frame {
        ts_ns: 0,
        fields: vec![
            Field {
                tag: 10,
                dtype: DType::U64,
                value_u64: 100,
            },
            Field {
                tag: 99,
                dtype: DType::U64,
                value_u64: 999,
            },
        ],
    };

    let (sent, recv, dropped, p50, p99) = parse_frame_fields(&frame);

    assert_eq!(sent, 100);
    assert_eq!(recv, 0);
    assert_eq!(dropped, 0);
    assert_eq!(p50, 0);
    assert_eq!(p99, 0);
}

#[test]
fn test_parse_frame_missing_tags() {
    use crate::telemetry::metrics::{DType, Field, Frame};

    let frame = Frame {
        ts_ns: 0,
        fields: vec![Field {
            tag: 10,
            dtype: DType::U64,
            value_u64: 50,
        }],
    };

    let (sent, recv, dropped, p50, p99) = parse_frame_fields(&frame);

    assert_eq!(sent, 50);
    assert_eq!(recv, 0);
    assert_eq!(dropped, 0);
    assert_eq!(p50, 0);
    assert_eq!(p99, 0);
}

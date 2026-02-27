// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Main DDS sink orchestrator.
//!
//! Connects configuration, field mapping, line protocol generation,
//! and batching into a single entry point.

use crate::buffer::BatchBuffer;
use crate::config::SinkConfig;
use crate::influx::{FieldValue, LineProtocolWriter};
use crate::mapping::FieldMapper;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// Default batch size if not configured.
const DEFAULT_BATCH_SIZE: usize = 1000;

/// Default flush interval if not configured (milliseconds).
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 1000;

/// Errors that can occur during sink operations.
#[derive(Debug)]
pub enum SinkError {
    /// The topic has no configured sink mapping.
    UnknownTopic(String),
    /// The sample produced no fields (InfluxDB requires at least one).
    NoFields(String),
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SinkError::UnknownTopic(t) => write!(f, "no sink configured for topic: {}", t),
            SinkError::NoFields(t) => {
                write!(f, "sample from topic '{}' produced no fields", t)
            }
        }
    }
}

impl std::error::Error for SinkError {}

/// Rate limiter state for downsampling.
struct RateLimiter {
    /// Minimum interval between samples in nanoseconds.
    min_interval_ns: u64,
    /// Timestamp of the last accepted sample.
    last_sample_ns: u64,
}

impl RateLimiter {
    fn new(samples_per_second: u32) -> Self {
        let min_interval_ns = if samples_per_second == 0 {
            0
        } else {
            1_000_000_000 / samples_per_second as u64
        };
        Self {
            min_interval_ns,
            last_sample_ns: 0,
        }
    }

    /// Check if this sample should be accepted based on rate limiting.
    fn should_accept(&mut self, timestamp_ns: u64) -> bool {
        if self.min_interval_ns == 0 {
            return true;
        }
        if timestamp_ns >= self.last_sample_ns + self.min_interval_ns {
            self.last_sample_ns = timestamp_ns;
            true
        } else {
            false
        }
    }
}

/// DDS-to-InfluxDB sink orchestrator.
///
/// Takes DDS samples (as JSON), maps them to InfluxDB Line Protocol,
/// buffers them, and produces batches ready for transmission.
pub struct DdsSink {
    config: SinkConfig,
    writer: LineProtocolWriter,
    buffers: HashMap<String, BatchBuffer>,
    mappers: HashMap<String, FieldMapper>,
    rate_limiters: HashMap<String, RateLimiter>,
    samples_recorded: u64,
    samples_dropped: u64,
}

impl DdsSink {
    /// Create a new sink from configuration.
    pub fn from_config(config: SinkConfig) -> Self {
        let mut buffers = HashMap::new();
        let mut mappers = HashMap::new();
        let mut rate_limiters = HashMap::new();

        for sink_cfg in &config.sinks {
            let batch_size = sink_cfg.batch_size.unwrap_or(DEFAULT_BATCH_SIZE);
            let flush_ms = sink_cfg.flush_interval_ms.unwrap_or(DEFAULT_FLUSH_INTERVAL_MS);

            buffers.insert(
                sink_cfg.topic.clone(),
                BatchBuffer::new(batch_size, Duration::from_millis(flush_ms)),
            );

            mappers.insert(
                sink_cfg.topic.clone(),
                FieldMapper::new(sink_cfg.tags.clone(), sink_cfg.fields.clone()),
            );

            if let Some(rate) = sink_cfg.sample_rate {
                rate_limiters.insert(sink_cfg.topic.clone(), RateLimiter::new(rate));
            }
        }

        Self {
            config,
            writer: LineProtocolWriter::new(),
            buffers,
            mappers,
            rate_limiters,
            samples_recorded: 0,
            samples_dropped: 0,
        }
    }

    /// Record a single DDS sample from a topic.
    ///
    /// The sample is mapped to Line Protocol, rate-limited if configured,
    /// and added to the appropriate batch buffer.
    ///
    /// Returns `Ok(())` on success. The sample may be silently dropped
    /// if the rate limiter rejects it.
    pub fn record_sample(
        &mut self,
        topic: &str,
        sample: &serde_json::Value,
        timestamp_ns: u64,
    ) -> Result<(), SinkError> {
        // Check rate limiter
        if let Some(limiter) = self.rate_limiters.get_mut(topic) {
            if !limiter.should_accept(timestamp_ns) {
                self.samples_dropped += 1;
                return Ok(());
            }
        }

        // Find the topic config to get the measurement name
        let topic_cfg = self
            .config
            .sinks
            .iter()
            .find(|s| s.topic == topic)
            .ok_or_else(|| SinkError::UnknownTopic(topic.to_string()))?;
        let measurement = topic_cfg.measurement.clone();

        // Map sample to tags + fields
        let mapper = self
            .mappers
            .get(topic)
            .ok_or_else(|| SinkError::UnknownTopic(topic.to_string()))?;
        let (tags, fields) = mapper.map_sample(sample);

        if fields.is_empty() {
            return Err(SinkError::NoFields(topic.to_string()));
        }

        // Build tag refs for the writer
        let tag_refs: Vec<(&str, &str)> = tags
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let field_owned: Vec<(String, FieldValue)> = fields;
        let field_refs: Vec<(&str, FieldValue)> = field_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();

        // Write the point
        self.writer
            .write_point(&measurement, &tag_refs, &field_refs, timestamp_ns);

        // Move the line to the topic buffer
        let lines = self.writer.flush();
        if let Some(buffer) = self.buffers.get_mut(topic) {
            for line in lines {
                buffer.add(line);
            }
        }

        self.samples_recorded += 1;
        Ok(())
    }

    /// Flush all topic buffers, returning all pending Line Protocol lines.
    pub fn flush_all(&mut self) -> Vec<String> {
        let mut all_lines = Vec::new();

        for buffer in self.buffers.values_mut() {
            all_lines.extend(buffer.flush());
        }

        // Also flush the writer in case there are orphaned lines
        all_lines.extend(self.writer.flush());

        all_lines
    }

    /// Get the total number of samples successfully recorded.
    pub fn samples_recorded(&self) -> u64 {
        self.samples_recorded
    }

    /// Get the total number of samples dropped (rate-limited).
    pub fn samples_dropped(&self) -> u64 {
        self.samples_dropped
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &SinkConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_config() -> SinkConfig {
        SinkConfig {
            influxdb: crate::config::InfluxDbConfig {
                url: "http://localhost:8086".to_string(),
                org: "test".to_string(),
                bucket: "test".to_string(),
                token: "test-token".to_string(),
            },
            sinks: vec![crate::config::TopicSinkConfig {
                topic: "Temperature".to_string(),
                measurement: "temperature".to_string(),
                tags: vec!["sensor_id".to_string()],
                fields: vec!["value".to_string()],
                sample_rate: None,
                batch_size: Some(100),
                flush_interval_ms: Some(1000),
            }],
        }
    }

    fn test_config_with_rate_limit() -> SinkConfig {
        SinkConfig {
            influxdb: crate::config::InfluxDbConfig {
                url: "http://localhost:8086".to_string(),
                org: "test".to_string(),
                bucket: "test".to_string(),
                token: "test-token".to_string(),
            },
            sinks: vec![crate::config::TopicSinkConfig {
                topic: "FastSensor".to_string(),
                measurement: "fast_sensor".to_string(),
                tags: vec!["id".to_string()],
                fields: vec!["value".to_string()],
                sample_rate: Some(10), // 10 samples/sec = 100ms interval
                batch_size: Some(100),
                flush_interval_ms: Some(1000),
            }],
        }
    }

    #[test]
    fn test_dds_sink_record_and_flush_roundtrip() {
        let config = test_config();
        let mut sink = DdsSink::from_config(config);

        let sample = json!({
            "sensor_id": "S1",
            "value": 22.5
        });

        sink.record_sample("Temperature", &sample, 1_000_000_000)
            .expect("record");

        assert_eq!(sink.samples_recorded(), 1);
        assert_eq!(sink.samples_dropped(), 0);

        let lines = sink.flush_all();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0],
            "temperature,sensor_id=S1 value=22.5 1000000000"
        );
    }

    #[test]
    fn test_dds_sink_downsample_respects_rate() {
        let config = test_config_with_rate_limit();
        let mut sink = DdsSink::from_config(config);

        let sample = json!({
            "id": "fast1",
            "value": 1.0
        });

        // 10 samples/sec = 100_000_000 ns interval
        // Send samples at 50ms intervals (too fast, should drop every other one)
        let base_ns: u64 = 1_000_000_000;
        let interval_ns: u64 = 50_000_000; // 50ms

        for i in 0..10 {
            let ts = base_ns + i * interval_ns;
            let _ = sink.record_sample("FastSensor", &sample, ts);
        }

        // With 100ms min interval and 50ms actual interval over 10 samples (0..450ms),
        // accepted timestamps: 0, 100ms, 200ms, 300ms, 400ms = 5 samples
        assert_eq!(sink.samples_recorded(), 5);
        assert_eq!(sink.samples_dropped(), 5);

        let lines = sink.flush_all();
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn test_dds_sink_unknown_topic() {
        let config = test_config();
        let mut sink = DdsSink::from_config(config);

        let sample = json!({"value": 1.0});

        let result = sink.record_sample("NonExistent", &sample, 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            SinkError::UnknownTopic(t) => assert_eq!(t, "NonExistent"),
            other => panic!("expected UnknownTopic, got: {}", other),
        }
    }

    #[test]
    fn test_dds_sink_no_fields_error() {
        let config = test_config();
        let mut sink = DdsSink::from_config(config);

        // Sample has the tag but not the field
        let sample = json!({
            "sensor_id": "S1",
            "wrong_field": 42
        });

        let result = sink.record_sample("Temperature", &sample, 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            SinkError::NoFields(t) => assert_eq!(t, "Temperature"),
            other => panic!("expected NoFields, got: {}", other),
        }
    }

    #[test]
    fn test_dds_sink_multiple_samples() {
        let config = test_config();
        let mut sink = DdsSink::from_config(config);

        for i in 0..5 {
            let sample = json!({
                "sensor_id": format!("S{}", i),
                "value": i as f64 * 10.0
            });
            sink.record_sample("Temperature", &sample, (i + 1) as u64 * 1_000_000_000)
                .expect("record");
        }

        assert_eq!(sink.samples_recorded(), 5);

        let lines = sink.flush_all();
        assert_eq!(lines.len(), 5);

        // Verify first and last lines
        assert!(lines[0].starts_with("temperature,sensor_id=S0 value=0"));
        assert!(lines[4].starts_with("temperature,sensor_id=S4 value=40"));
    }
}

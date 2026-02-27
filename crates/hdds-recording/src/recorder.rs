// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS message recorder.
//!
//! Subscribes to topics and records messages to file.

use crate::filter::{TopicFilter, TypeFilter};
use crate::format::{HddsFormat, HddsWriter, Message, OutputFormat, RecordingMetadata};
use crate::rotation::{RotationPolicy, RotationTrigger};
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

/// Recorder configuration.
#[derive(Debug, Clone)]
pub struct RecorderConfig {
    /// Domain ID to record.
    pub domain_id: u32,

    /// Output file path.
    pub output_path: PathBuf,

    /// Output format.
    pub format: OutputFormat,

    /// Topic filter (None = all topics).
    pub topic_filter: Option<TopicFilter>,

    /// Type filter (None = all types).
    pub type_filter: Option<TypeFilter>,

    /// File rotation policy.
    pub rotation: Option<RotationPolicy>,

    /// Optional description for metadata.
    pub description: Option<String>,
}

impl RecorderConfig {
    /// Create a new recorder config with defaults.
    pub fn new<P: AsRef<Path>>(output_path: P) -> Self {
        let path = output_path.as_ref().to_path_buf();
        let format = OutputFormat::from_extension(&path).unwrap_or(OutputFormat::Hdds);

        Self {
            domain_id: 0,
            output_path: path,
            format,
            topic_filter: None,
            type_filter: None,
            rotation: None,
            description: None,
        }
    }

    /// Set domain ID.
    pub fn domain_id(mut self, domain_id: u32) -> Self {
        self.domain_id = domain_id;
        self
    }

    /// Set topic filter.
    pub fn topic_filter(mut self, filter: TopicFilter) -> Self {
        self.topic_filter = Some(filter);
        self
    }

    /// Set type filter.
    pub fn type_filter(mut self, filter: TypeFilter) -> Self {
        self.type_filter = Some(filter);
        self
    }

    /// Set rotation policy.
    pub fn rotation(mut self, policy: RotationPolicy) -> Self {
        self.rotation = Some(policy);
        self
    }

    /// Set description.
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Recorder errors.
#[derive(Debug, Error)]
pub enum RecorderError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Format error: {0}")]
    Format(#[from] crate::format::FormatError),

    #[error("DDS error: {0}")]
    Dds(String),

    #[error("Not recording")]
    NotRecording,

    #[error("Already recording")]
    AlreadyRecording,
}

/// Recording statistics.
#[derive(Debug, Clone, Default)]
pub struct RecordingStats {
    /// Total messages recorded.
    pub message_count: u64,

    /// Total bytes written.
    pub bytes_written: u64,

    /// Messages per second (average).
    pub messages_per_second: f64,

    /// Recording duration in seconds.
    pub duration_secs: f64,

    /// Topics recorded.
    pub topic_count: usize,

    /// Current file index (for rotation).
    pub file_index: u32,
}

/// DDS message recorder.
pub struct Recorder {
    config: RecorderConfig,
    writer: Option<HddsWriter>,
    start_time: Option<Instant>,
    start_nanos: u64,
    stats: RecordingStats,
}

impl Recorder {
    /// Create a new recorder.
    pub fn new(config: RecorderConfig) -> Self {
        Self {
            config,
            writer: None,
            start_time: None,
            start_nanos: 0,
            stats: RecordingStats::default(),
        }
    }

    /// Start recording.
    pub fn start(&mut self) -> Result<(), RecorderError> {
        if self.writer.is_some() {
            return Err(RecorderError::AlreadyRecording);
        }

        let metadata = RecordingMetadata {
            domain_id: self.config.domain_id,
            description: self.config.description.clone(),
            ..Default::default()
        };

        let writer = HddsWriter::create(&self.config.output_path, metadata)?;
        self.writer = Some(writer);
        self.start_time = Some(Instant::now());
        self.start_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        self.stats = RecordingStats::default();

        tracing::info!("Started recording to {}", self.config.output_path.display());

        Ok(())
    }

    /// Stop recording and finalize file.
    pub fn stop(&mut self) -> Result<RecordingStats, RecorderError> {
        let writer = self.writer.take().ok_or(RecorderError::NotRecording)?;
        writer.finalize()?;

        // Update final stats
        if let Some(start) = self.start_time.take() {
            self.stats.duration_secs = start.elapsed().as_secs_f64();
            if self.stats.duration_secs > 0.0 {
                self.stats.messages_per_second =
                    self.stats.message_count as f64 / self.stats.duration_secs;
            }
        }

        tracing::info!(
            "Stopped recording: {} messages, {:.1}s",
            self.stats.message_count,
            self.stats.duration_secs
        );

        Ok(self.stats.clone())
    }

    /// Record a message.
    pub fn record(&mut self, msg: Message) -> Result<(), RecorderError> {
        // Apply filters
        if let Some(ref filter) = self.config.topic_filter {
            if !filter.matches(&msg.topic_name) {
                return Ok(());
            }
        }

        if let Some(ref filter) = self.config.type_filter {
            if !filter.matches(&msg.type_name) {
                return Ok(());
            }
        }

        // Check rotation
        if let Some(ref policy) = self.config.rotation {
            if self.should_rotate(policy) {
                self.rotate()?;
            }
        }

        // Write message
        let writer = self.writer.as_mut().ok_or(RecorderError::NotRecording)?;
        writer.write_message(&msg)?;

        // Update stats
        self.stats.message_count += 1;
        self.stats.bytes_written += msg.payload.len() as u64 + 50; // ~50 bytes overhead

        Ok(())
    }

    /// Record a raw DDS sample.
    pub fn record_sample(
        &mut self,
        topic_name: &str,
        type_name: &str,
        writer_guid: &str,
        sequence_number: u64,
        payload: &[u8],
        qos_hash: u32,
    ) -> Result<(), RecorderError> {
        let timestamp_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
            - self.start_nanos;

        let msg = Message {
            timestamp_nanos,
            topic_name: topic_name.to_string(),
            type_name: type_name.to_string(),
            writer_guid: writer_guid.to_string(),
            sequence_number,
            payload: payload.to_vec(),
            qos_hash,
        };

        self.record(msg)
    }

    /// Check if recording should rotate.
    fn should_rotate(&self, policy: &RotationPolicy) -> bool {
        match policy.trigger {
            RotationTrigger::Size(max_bytes) => self.stats.bytes_written >= max_bytes,
            RotationTrigger::Duration(max_secs) => self
                .start_time
                .map(|t| t.elapsed().as_secs() >= max_secs)
                .unwrap_or(false),
            RotationTrigger::Messages(max_msgs) => self.stats.message_count >= max_msgs,
        }
    }

    /// Rotate to a new file.
    fn rotate(&mut self) -> Result<(), RecorderError> {
        // Finalize current file
        if let Some(writer) = self.writer.take() {
            writer.finalize()?;
        }

        // Increment file index
        self.stats.file_index += 1;

        // Create new filename with index
        let new_path = self.rotated_path(self.stats.file_index);

        let metadata = RecordingMetadata {
            domain_id: self.config.domain_id,
            description: self.config.description.clone(),
            ..Default::default()
        };

        let writer = HddsWriter::create(&new_path, metadata)?;
        self.writer = Some(writer);

        // Reset per-file stats
        self.stats.bytes_written = 0;
        self.start_time = Some(Instant::now());

        tracing::info!("Rotated to {}", new_path.display());

        Ok(())
    }

    /// Generate rotated filename.
    fn rotated_path(&self, index: u32) -> PathBuf {
        let stem = self
            .config
            .output_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("recording");
        let ext = self
            .config
            .output_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("hdds");
        let parent = self.config.output_path.parent().unwrap_or(Path::new("."));

        parent.join(format!("{}_{:04}.{}", stem, index, ext))
    }

    /// Check if currently recording.
    pub fn is_recording(&self) -> bool {
        self.writer.is_some()
    }

    /// Get current statistics.
    pub fn stats(&self) -> &RecordingStats {
        &self.stats
    }

    /// Get configuration.
    pub fn config(&self) -> &RecorderConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_recorder_config_builder() {
        let config = RecorderConfig::new("/tmp/test.hdds")
            .domain_id(42)
            .description("Test recording");

        assert_eq!(config.domain_id, 42);
        assert_eq!(config.format, OutputFormat::Hdds);
        assert_eq!(config.description, Some("Test recording".into()));
    }

    #[test]
    fn test_recorder_start_stop() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.hdds");

        let config = RecorderConfig::new(&path);
        let mut recorder = Recorder::new(config);

        assert!(!recorder.is_recording());

        recorder.start().expect("start");
        assert!(recorder.is_recording());

        let stats = recorder.stop().expect("stop");
        assert!(!recorder.is_recording());
        assert_eq!(stats.message_count, 0);
    }

    #[test]
    fn test_recorder_record_messages() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.hdds");

        let config = RecorderConfig::new(&path);
        let mut recorder = Recorder::new(config);

        recorder.start().expect("start");

        for i in 0..10 {
            recorder
                .record_sample(
                    "TestTopic",
                    "TestType",
                    "0102030405060708090a0b0c00000302",
                    i,
                    &[1, 2, 3, 4],
                    0,
                )
                .expect("record");
        }

        let stats = recorder.stop().expect("stop");
        assert_eq!(stats.message_count, 10);
    }

    #[test]
    fn test_recorder_topic_filter() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.hdds");

        let config = RecorderConfig::new(&path)
            .topic_filter(TopicFilter::include(vec!["Temperature".into()]));
        let mut recorder = Recorder::new(config);

        recorder.start().expect("start");

        // This should be recorded
        recorder
            .record_sample("Temperature", "TempType", "guid", 1, &[1], 0)
            .expect("record");

        // This should be filtered out
        recorder
            .record_sample("Pressure", "PressType", "guid", 2, &[2], 0)
            .expect("record");

        let stats = recorder.stop().expect("stop");
        assert_eq!(stats.message_count, 1);
    }

    #[test]
    fn test_rotated_path() {
        let config = RecorderConfig::new("/tmp/capture.hdds");
        let recorder = Recorder::new(config);

        let rotated = recorder.rotated_path(5);
        assert_eq!(rotated.to_str().expect("path"), "/tmp/capture_0005.hdds");
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! DDS message replay/playback.
//!
//! Reads recorded messages and publishes them with timing control.

use crate::filter::TopicFilter;
use crate::format::{HddsReader, Message};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;

/// Playback speed control.
#[derive(Debug, Clone, Copy, Default)]
pub enum PlaybackSpeed {
    /// Real-time playback (1.0x).
    #[default]
    Realtime,
    /// Fixed speed multiplier (e.g., 2.0 = 2x faster).
    Speed(f64),
    /// As fast as possible (no timing).
    Unlimited,
}

impl PlaybackSpeed {
    /// Get the speed multiplier (Unlimited returns f64::INFINITY).
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::Realtime => 1.0,
            Self::Speed(s) => *s,
            Self::Unlimited => f64::INFINITY,
        }
    }

    /// Calculate delay for a given timestamp delta.
    pub fn delay_for(&self, delta_nanos: u64) -> Option<Duration> {
        match self {
            Self::Unlimited => None,
            Self::Realtime => Some(Duration::from_nanos(delta_nanos)),
            Self::Speed(s) => {
                if *s <= 0.0 {
                    None
                } else {
                    Some(Duration::from_nanos((delta_nanos as f64 / s) as u64))
                }
            }
        }
    }
}

/// Player configuration.
#[derive(Debug, Clone)]
pub struct PlayerConfig {
    /// Input file path.
    pub input_path: PathBuf,

    /// Playback speed.
    pub speed: PlaybackSpeed,

    /// Topic filter (None = all topics).
    pub topic_filter: Option<TopicFilter>,

    /// Loop playback.
    pub loop_playback: bool,

    /// Start offset (skip first N nanoseconds).
    pub start_offset_nanos: u64,

    /// End time (stop after N nanoseconds, 0 = play all).
    pub end_time_nanos: u64,
}

impl PlayerConfig {
    /// Create a new player config.
    pub fn new<P: AsRef<Path>>(input_path: P) -> Self {
        Self {
            input_path: input_path.as_ref().to_path_buf(),
            speed: PlaybackSpeed::Realtime,
            topic_filter: None,
            loop_playback: false,
            start_offset_nanos: 0,
            end_time_nanos: 0,
        }
    }

    /// Set playback speed.
    pub fn speed(mut self, speed: PlaybackSpeed) -> Self {
        self.speed = speed;
        self
    }

    /// Set speed as multiplier.
    pub fn speed_multiplier(mut self, multiplier: f64) -> Self {
        self.speed = if multiplier <= 0.0 {
            PlaybackSpeed::Unlimited
        } else if (multiplier - 1.0).abs() < 0.001 {
            PlaybackSpeed::Realtime
        } else {
            PlaybackSpeed::Speed(multiplier)
        };
        self
    }

    /// Set topic filter.
    pub fn topic_filter(mut self, filter: TopicFilter) -> Self {
        self.topic_filter = Some(filter);
        self
    }

    /// Enable loop playback.
    pub fn loop_playback(mut self, enable: bool) -> Self {
        self.loop_playback = enable;
        self
    }

    /// Set start offset.
    pub fn start_offset(mut self, offset: Duration) -> Self {
        self.start_offset_nanos = offset.as_nanos() as u64;
        self
    }

    /// Set end time.
    pub fn end_time(mut self, end: Duration) -> Self {
        self.end_time_nanos = end.as_nanos() as u64;
        self
    }
}

/// Player errors.
#[derive(Debug, Error)]
pub enum PlayerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Format error: {0}")]
    Format(#[from] crate::format::FormatError),

    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Playback cancelled")]
    Cancelled,
}

/// Playback statistics.
#[derive(Debug, Clone, Default)]
pub struct PlaybackStats {
    /// Total messages played.
    pub messages_played: u64,

    /// Total messages skipped (filtered).
    pub messages_skipped: u64,

    /// Playback duration in seconds.
    pub duration_secs: f64,

    /// Actual messages per second.
    pub messages_per_second: f64,

    /// Recording duration in seconds.
    pub recording_duration_secs: f64,

    /// Number of loops completed.
    pub loops_completed: u32,
}

/// DDS message player.
pub struct Player {
    config: PlayerConfig,
    reader: Option<HddsReader>,
    last_timestamp: u64,
    playback_start: Option<Instant>,
    stats: PlaybackStats,
    cancelled: bool,
}

impl Player {
    /// Create a new player.
    pub fn new(config: PlayerConfig) -> Self {
        Self {
            config,
            reader: None,
            last_timestamp: 0,
            playback_start: None,
            stats: PlaybackStats::default(),
            cancelled: false,
        }
    }

    /// Open the recording file.
    pub fn open(&mut self) -> Result<(), PlayerError> {
        if !self.config.input_path.exists() {
            return Err(PlayerError::FileNotFound(self.config.input_path.clone()));
        }

        let reader = HddsReader::open(&self.config.input_path)?;

        self.stats.recording_duration_secs = reader.duration_nanos() as f64 / 1_000_000_000.0;
        self.reader = Some(reader);
        self.last_timestamp = 0;
        self.playback_start = Some(Instant::now());

        tracing::info!(
            "Opened {} ({} messages, {:.1}s)",
            self.config.input_path.display(),
            self.reader.as_ref().map(|r| r.message_count()).unwrap_or(0),
            self.stats.recording_duration_secs
        );

        Ok(())
    }

    /// Get the next message to play.
    ///
    /// Returns `Ok(None)` when playback is complete.
    /// Handles timing based on playback speed.
    pub fn next_message(&mut self) -> Result<Option<Message>, PlayerError> {
        if self.cancelled {
            return Err(PlayerError::Cancelled);
        }

        loop {
            let reader = match &mut self.reader {
                Some(r) => r,
                None => return Ok(None),
            };

            match reader.read_message()? {
                Some(msg) => {
                    // Apply time filters
                    if msg.timestamp_nanos < self.config.start_offset_nanos {
                        self.stats.messages_skipped += 1;
                        continue;
                    }

                    if self.config.end_time_nanos > 0
                        && msg.timestamp_nanos > self.config.end_time_nanos
                    {
                        // End time reached
                        if self.config.loop_playback {
                            self.restart()?;
                            continue;
                        }
                        return Ok(None);
                    }

                    // Apply topic filter
                    if let Some(ref filter) = self.config.topic_filter {
                        if !filter.matches(&msg.topic_name) {
                            self.stats.messages_skipped += 1;
                            continue;
                        }
                    }

                    // Apply timing
                    if msg.timestamp_nanos > self.last_timestamp {
                        let delta = msg.timestamp_nanos - self.last_timestamp;
                        if let Some(delay) = self.config.speed.delay_for(delta) {
                            std::thread::sleep(delay);
                        }
                    }

                    self.last_timestamp = msg.timestamp_nanos;
                    self.stats.messages_played += 1;

                    return Ok(Some(msg));
                }
                None => {
                    // End of file
                    if self.config.loop_playback {
                        self.restart()?;
                        continue;
                    }

                    // Update final stats
                    if let Some(start) = self.playback_start {
                        self.stats.duration_secs = start.elapsed().as_secs_f64();
                        if self.stats.duration_secs > 0.0 {
                            self.stats.messages_per_second =
                                self.stats.messages_played as f64 / self.stats.duration_secs;
                        }
                    }

                    return Ok(None);
                }
            }
        }
    }

    /// Restart playback from beginning.
    fn restart(&mut self) -> Result<(), PlayerError> {
        self.reader = None;
        let reader = HddsReader::open(&self.config.input_path)?;
        self.reader = Some(reader);
        self.last_timestamp = 0;
        self.stats.loops_completed += 1;

        tracing::debug!("Restarting playback (loop {})", self.stats.loops_completed);

        Ok(())
    }

    /// Cancel playback.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Check if playback is complete.
    pub fn is_complete(&self) -> bool {
        self.reader.is_none() || self.cancelled
    }

    /// Get playback statistics.
    pub fn stats(&self) -> &PlaybackStats {
        &self.stats
    }

    /// Get recording metadata.
    pub fn metadata(&self) -> Option<&crate::format::RecordingMetadata> {
        self.reader.as_ref().map(|r| r.metadata())
    }

    /// Get total message count in recording.
    pub fn total_messages(&self) -> u64 {
        self.reader.as_ref().map(|r| r.message_count()).unwrap_or(0)
    }

    /// Get configuration.
    pub fn config(&self) -> &PlayerConfig {
        &self.config
    }

    /// Iterate over all messages.
    pub fn messages(mut self) -> impl Iterator<Item = Result<Message, PlayerError>> {
        std::iter::from_fn(move || match self.next_message() {
            Ok(Some(msg)) => Some(Ok(msg)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{HddsFormat, HddsWriter, RecordingMetadata};
    use tempfile::tempdir;

    fn create_test_recording(path: &Path, count: u64) {
        let metadata = RecordingMetadata::default();
        let mut writer = HddsWriter::create(path, metadata).expect("create");

        for i in 0..count {
            let msg = Message {
                timestamp_nanos: i * 1_000_000, // 1ms apart
                topic_name: "TestTopic".into(),
                type_name: "TestType".into(),
                writer_guid: "01020304050607080910111213141516".into(),
                sequence_number: i,
                payload: vec![i as u8],
                qos_hash: 0,
            };
            writer.write_message(&msg).expect("write");
        }

        writer.finalize().expect("finalize");
    }

    #[test]
    fn test_playback_speed_delay() {
        let realtime = PlaybackSpeed::Realtime;
        assert_eq!(
            realtime.delay_for(1_000_000),
            Some(Duration::from_nanos(1_000_000))
        );

        let double = PlaybackSpeed::Speed(2.0);
        assert_eq!(
            double.delay_for(1_000_000),
            Some(Duration::from_nanos(500_000))
        );

        let unlimited = PlaybackSpeed::Unlimited;
        assert_eq!(unlimited.delay_for(1_000_000), None);
    }

    #[test]
    fn test_player_config_builder() {
        let config = PlayerConfig::new("/tmp/test.hdds")
            .speed_multiplier(2.0)
            .loop_playback(true)
            .start_offset(Duration::from_secs(10));

        assert!(matches!(config.speed, PlaybackSpeed::Speed(s) if (s - 2.0).abs() < 0.001));
        assert!(config.loop_playback);
        assert_eq!(config.start_offset_nanos, 10_000_000_000);
    }

    #[test]
    fn test_player_open_and_read() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.hdds");

        create_test_recording(&path, 10);

        let config = PlayerConfig::new(&path).speed(PlaybackSpeed::Unlimited);
        let mut player = Player::new(config);

        player.open().expect("open");
        assert_eq!(player.total_messages(), 10);

        let mut count = 0;
        while let Some(_msg) = player.next_message().expect("next") {
            count += 1;
        }

        assert_eq!(count, 10);
        assert_eq!(player.stats().messages_played, 10);
    }

    #[test]
    fn test_player_with_filter() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.hdds");

        // Create recording with mixed topics
        {
            let metadata = RecordingMetadata::default();
            let mut writer = HddsWriter::create(&path, metadata).expect("create");

            for i in 0..10 {
                let topic = if i % 2 == 0 { "TopicA" } else { "TopicB" };
                let msg = Message {
                    timestamp_nanos: i * 1_000_000,
                    topic_name: topic.into(),
                    type_name: "Type".into(),
                    writer_guid: "guid".into(),
                    sequence_number: i,
                    payload: vec![],
                    qos_hash: 0,
                };
                writer.write_message(&msg).expect("write");
            }
            writer.finalize().expect("finalize");
        }

        let config = PlayerConfig::new(&path)
            .speed(PlaybackSpeed::Unlimited)
            .topic_filter(TopicFilter::include(vec!["TopicA".into()]));

        let mut player = Player::new(config);
        player.open().expect("open");

        let mut count = 0;
        while let Some(_msg) = player.next_message().expect("next") {
            count += 1;
        }

        assert_eq!(count, 5); // Only TopicA messages
        assert_eq!(player.stats().messages_skipped, 5);
    }

    #[test]
    fn test_player_cancel() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.hdds");

        create_test_recording(&path, 100);

        let config = PlayerConfig::new(&path).speed(PlaybackSpeed::Unlimited);
        let mut player = Player::new(config);

        player.open().expect("open");

        // Read a few messages
        for _ in 0..5 {
            player.next_message().expect("next");
        }

        // Cancel
        player.cancel();

        // Next should return error
        assert!(player.next_message().is_err());
        assert!(player.is_complete());
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! File rotation policies for recording.
//!
//! Supports rotation based on:
//! - File size
//! - Duration
//! - Message count

/// Rotation policy configuration.
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Trigger condition for rotation.
    pub trigger: RotationTrigger,

    /// Maximum number of files to keep (0 = unlimited).
    pub max_files: u32,

    /// Filename pattern for rotated files.
    pub pattern: RotationPattern,
}

/// Trigger condition for file rotation.
#[derive(Debug, Clone, Copy)]
pub enum RotationTrigger {
    /// Rotate when file reaches size in bytes.
    Size(u64),

    /// Rotate after duration in seconds.
    Duration(u64),

    /// Rotate after message count.
    Messages(u64),
}

/// Filename pattern for rotated files.
#[derive(Debug, Clone)]
pub enum RotationPattern {
    /// Sequential numbering: capture_0001.hdds, capture_0002.hdds, ...
    Sequential,

    /// Timestamp-based: capture_20240115_143022.hdds
    Timestamp,

    /// Custom pattern with placeholders: capture_{n}_{ts}.hdds
    Custom(String),
}

impl RotationPolicy {
    /// Create a size-based rotation policy.
    ///
    /// # Arguments
    /// * `max_size_mb` - Maximum file size in megabytes.
    pub fn by_size(max_size_mb: u64) -> Self {
        Self {
            trigger: RotationTrigger::Size(max_size_mb * 1024 * 1024),
            max_files: 0,
            pattern: RotationPattern::Sequential,
        }
    }

    /// Create a duration-based rotation policy.
    ///
    /// # Arguments
    /// * `duration_secs` - Maximum duration in seconds.
    pub fn by_duration(duration_secs: u64) -> Self {
        Self {
            trigger: RotationTrigger::Duration(duration_secs),
            max_files: 0,
            pattern: RotationPattern::Sequential,
        }
    }

    /// Create a message count-based rotation policy.
    ///
    /// # Arguments
    /// * `max_messages` - Maximum number of messages per file.
    pub fn by_messages(max_messages: u64) -> Self {
        Self {
            trigger: RotationTrigger::Messages(max_messages),
            max_files: 0,
            pattern: RotationPattern::Sequential,
        }
    }

    /// Set maximum number of files to keep (for cleanup).
    pub fn with_max_files(mut self, max: u32) -> Self {
        self.max_files = max;
        self
    }

    /// Use timestamp-based filenames.
    pub fn with_timestamp_pattern(mut self) -> Self {
        self.pattern = RotationPattern::Timestamp;
        self
    }

    /// Use custom filename pattern.
    pub fn with_custom_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern = RotationPattern::Custom(pattern.into());
        self
    }

    /// Generate a filename for the given rotation index.
    pub fn generate_filename(&self, base_name: &str, extension: &str, index: u32) -> String {
        match &self.pattern {
            RotationPattern::Sequential => {
                format!("{}_{:04}.{}", base_name, index, extension)
            }
            RotationPattern::Timestamp => {
                let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
                format!("{}_{}.{}", base_name, ts, extension)
            }
            RotationPattern::Custom(pattern) => {
                let ts = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
                pattern
                    .replace("{n}", &format!("{:04}", index))
                    .replace("{ts}", &ts)
                    .replace("{base}", base_name)
                    .replace("{ext}", extension)
            }
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::by_size(100) // 100 MB default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_by_size() {
        let policy = RotationPolicy::by_size(50);

        match policy.trigger {
            RotationTrigger::Size(size) => assert_eq!(size, 50 * 1024 * 1024),
            _ => panic!("Wrong trigger type"),
        }
    }

    #[test]
    fn test_rotation_by_duration() {
        let policy = RotationPolicy::by_duration(3600);

        match policy.trigger {
            RotationTrigger::Duration(secs) => assert_eq!(secs, 3600),
            _ => panic!("Wrong trigger type"),
        }
    }

    #[test]
    fn test_rotation_by_messages() {
        let policy = RotationPolicy::by_messages(100_000);

        match policy.trigger {
            RotationTrigger::Messages(count) => assert_eq!(count, 100_000),
            _ => panic!("Wrong trigger type"),
        }
    }

    #[test]
    fn test_sequential_filename() {
        let policy = RotationPolicy::by_size(100);
        let name = policy.generate_filename("capture", "hdds", 5);
        assert_eq!(name, "capture_0005.hdds");
    }

    #[test]
    fn test_custom_pattern_filename() {
        let policy = RotationPolicy::by_size(100).with_custom_pattern("{base}_part{n}.{ext}");

        let name = policy.generate_filename("recording", "hdds", 3);
        assert_eq!(name, "recording_part0003.hdds");
    }

    #[test]
    fn test_max_files() {
        let policy = RotationPolicy::by_size(100).with_max_files(10);
        assert_eq!(policy.max_files, 10);
    }
}

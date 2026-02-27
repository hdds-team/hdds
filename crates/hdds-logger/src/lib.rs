// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Distributed Logger
//!
//! Aggregate and centralize logs from distributed DDS participants.
//!
//! # Features
//!
//! - **Log Collection**: Subscribe to DDS log topics or aggregate telemetry
//! - **Multiple Formats**: JSON (ELK-ready), plain text, syslog (RFC 5424)
//! - **Flexible Output**: File (with rotation), stdout, syslog daemon
//! - **Filtering**: By log level, participant, topic pattern
//!
//! # Example
//!
//! ```rust,ignore
//! use hdds_logger::{LogCollector, LogConfig, OutputFormat};
//!
//! let config = LogConfig::builder()
//!     .format(OutputFormat::Json)
//!     .output_file("logs/hdds.log")
//!     .level(LogLevel::Debug)
//!     .build();
//!
//! let collector = LogCollector::new(config)?;
//! collector.run()?;
//! ```

mod collector;
mod filter;
mod formatter;
mod output;

pub use collector::{LogCollector, LogEntry, LogSource, StopHandle};
pub use filter::{LogFilter, LogLevel};
pub use formatter::{LogFormatter, OutputFormat};
pub use output::{FileRotation, LogOutput, OutputConfig};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Logger configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Output format.
    pub format: OutputFormat,
    /// Output configuration.
    pub output: OutputConfig,
    /// Log filter settings.
    pub filter: LogFilter,
    /// DDS domain ID to monitor.
    pub domain_id: u32,
    /// Log topic name pattern (supports wildcards).
    pub topic_pattern: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            output: OutputConfig::Stdout,
            filter: LogFilter::default(),
            domain_id: 0,
            topic_pattern: "rt/rosout".to_string(),
        }
    }
}

impl LogConfig {
    /// Create a new builder.
    pub fn builder() -> LogConfigBuilder {
        LogConfigBuilder::default()
    }
}

/// Builder for LogConfig.
#[derive(Debug, Default)]
pub struct LogConfigBuilder {
    format: Option<OutputFormat>,
    output: Option<OutputConfig>,
    filter: Option<LogFilter>,
    domain_id: Option<u32>,
    topic_pattern: Option<String>,
}

impl LogConfigBuilder {
    /// Set output format.
    pub fn format(mut self, format: OutputFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Set output to file with optional rotation.
    pub fn output_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.output = Some(OutputConfig::File {
            path: path.into(),
            rotation: None,
        });
        self
    }

    /// Set output to file with rotation.
    pub fn output_file_rotated(mut self, path: impl Into<PathBuf>, rotation: FileRotation) -> Self {
        self.output = Some(OutputConfig::File {
            path: path.into(),
            rotation: Some(rotation),
        });
        self
    }

    /// Set output to stdout.
    pub fn output_stdout(mut self) -> Self {
        self.output = Some(OutputConfig::Stdout);
        self
    }

    /// Set output to syslog.
    pub fn output_syslog(mut self, facility: SyslogFacility) -> Self {
        self.output = Some(OutputConfig::Syslog { facility });
        self
    }

    /// Set minimum log level.
    pub fn level(mut self, level: LogLevel) -> Self {
        let mut filter = self.filter.take().unwrap_or_default();
        filter.min_level = level;
        self.filter = Some(filter);
        self
    }

    /// Set participant filter (GUID prefix pattern).
    pub fn participant_filter(mut self, pattern: impl Into<String>) -> Self {
        let mut filter = self.filter.take().unwrap_or_default();
        filter.participant_pattern = Some(pattern.into());
        self.filter = Some(filter);
        self
    }

    /// Set topic filter pattern.
    pub fn topic_filter(mut self, pattern: impl Into<String>) -> Self {
        let mut filter = self.filter.take().unwrap_or_default();
        filter.topic_pattern = Some(pattern.into());
        self.filter = Some(filter);
        self
    }

    /// Set DDS domain ID.
    pub fn domain_id(mut self, id: u32) -> Self {
        self.domain_id = Some(id);
        self
    }

    /// Set log topic pattern to subscribe.
    pub fn topic_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.topic_pattern = Some(pattern.into());
        self
    }

    /// Build the configuration.
    pub fn build(self) -> LogConfig {
        LogConfig {
            format: self.format.unwrap_or(OutputFormat::Text),
            output: self.output.unwrap_or(OutputConfig::Stdout),
            filter: self.filter.unwrap_or_default(),
            domain_id: self.domain_id.unwrap_or(0),
            topic_pattern: self
                .topic_pattern
                .unwrap_or_else(|| "rt/rosout".to_string()),
        }
    }
}

/// Syslog facility (RFC 5424).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SyslogFacility {
    Kern,
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    #[default]
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl SyslogFacility {
    /// Get the numeric facility code.
    pub fn code(&self) -> u8 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Mail => 2,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Syslog => 5,
            Self::Lpr => 6,
            Self::News => 7,
            Self::Uucp => 8,
            Self::Cron => 9,
            Self::Local0 => 16,
            Self::Local1 => 17,
            Self::Local2 => 18,
            Self::Local3 => 19,
            Self::Local4 => 20,
            Self::Local5 => 21,
            Self::Local6 => 22,
            Self::Local7 => 23,
        }
    }
}

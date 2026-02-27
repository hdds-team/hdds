// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Log formatters: JSON, text, syslog (RFC 5424).

use crate::{LogEntry, LogLevel, SyslogFacility};
use serde::{Deserialize, Serialize};

/// Output format for log entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutputFormat {
    /// Plain text format (human-readable).
    #[default]
    Text,
    /// JSON format (ELK/structured logging ready).
    Json,
    /// Syslog RFC 5424 format.
    Syslog,
    /// JSON Lines format (one JSON object per line).
    JsonLines,
}

/// Log formatter trait.
pub trait LogFormatter {
    /// Format a log entry to string.
    fn format(&self, entry: &LogEntry) -> String;
}

/// Text formatter for human-readable output.
#[derive(Debug, Clone)]
pub struct TextFormatter {
    /// Include timestamp.
    pub show_timestamp: bool,
    /// Include participant ID.
    pub show_participant: bool,
    /// Include topic name.
    pub show_topic: bool,
    /// Use colors (ANSI escape codes).
    pub use_colors: bool,
}

impl Default for TextFormatter {
    fn default() -> Self {
        Self {
            show_timestamp: true,
            show_participant: true,
            show_topic: true,
            use_colors: true,
        }
    }
}

impl TextFormatter {
    /// Create formatter without colors.
    #[cfg(test)]
    fn no_colors() -> Self {
        Self {
            use_colors: false,
            ..Default::default()
        }
    }

    /// Get ANSI color code for log level.
    fn level_color(&self, level: LogLevel) -> &'static str {
        if !self.use_colors {
            return "";
        }
        match level {
            LogLevel::Unset => "\x1b[37m",   // White
            LogLevel::Debug => "\x1b[36m",   // Cyan
            LogLevel::Info => "\x1b[32m",    // Green
            LogLevel::Warn => "\x1b[33m",    // Yellow
            LogLevel::Error => "\x1b[31m",   // Red
            LogLevel::Fatal => "\x1b[35;1m", // Magenta bold
        }
    }

    /// Get ANSI reset code.
    fn reset(&self) -> &'static str {
        if self.use_colors {
            "\x1b[0m"
        } else {
            ""
        }
    }
}

impl LogFormatter for TextFormatter {
    fn format(&self, entry: &LogEntry) -> String {
        let mut parts = Vec::new();

        if self.show_timestamp {
            parts.push(entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string());
        }

        // Level with color
        let level_str = format!(
            "{}[{:5}]{}",
            self.level_color(entry.level),
            entry.level.as_str(),
            self.reset()
        );
        parts.push(level_str);

        if self.show_participant {
            parts.push(format!(
                "[{}]",
                &entry.participant_id[..8.min(entry.participant_id.len())]
            ));
        }

        if self.show_topic {
            if let Some(ref topic) = entry.topic {
                parts.push(format!("[{}]", topic));
            }
        }

        if let Some(ref node) = entry.node_name {
            parts.push(format!("[{}]", node));
        }

        parts.push(entry.message.clone());

        parts.join(" ")
    }
}

/// JSON formatter for structured logging.
#[derive(Debug, Clone, Default)]
pub struct JsonFormatter {
    /// Pretty print JSON.
    pub pretty: bool,
}

impl JsonFormatter {
    /// Create compact JSON formatter.
    pub fn compact() -> Self {
        Self { pretty: false }
    }
}

/// JSON log entry structure (ELK-compatible).
#[derive(Debug, Serialize)]
struct JsonLogEntry<'a> {
    #[serde(rename = "@timestamp")]
    timestamp: String,
    level: &'static str,
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    topic: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<&'a str>,
    participant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    function: Option<&'a str>,
    source: &'static str,
}

impl LogFormatter for JsonFormatter {
    fn format(&self, entry: &LogEntry) -> String {
        let json_entry = JsonLogEntry {
            timestamp: entry.timestamp.to_rfc3339(),
            level: entry.level.as_str(),
            message: &entry.message,
            topic: entry.topic.as_deref(),
            node: entry.node_name.as_deref(),
            participant_id: &entry.participant_id,
            file: entry.file.as_deref(),
            line: entry.line,
            function: entry.function.as_deref(),
            source: "hdds-logger",
        };

        if self.pretty {
            serde_json::to_string_pretty(&json_entry).unwrap_or_else(|_| entry.message.clone())
        } else {
            serde_json::to_string(&json_entry).unwrap_or_else(|_| entry.message.clone())
        }
    }
}

/// Syslog RFC 5424 formatter.
#[derive(Debug, Clone)]
pub struct SyslogFormatter {
    /// Syslog facility.
    pub facility: SyslogFacility,
    /// Application name.
    pub app_name: String,
    /// Hostname (or "-" for nil).
    pub hostname: String,
}

impl Default for SyslogFormatter {
    fn default() -> Self {
        Self {
            facility: SyslogFacility::Local0,
            app_name: "hdds-logger".to_string(),
            hostname: gethostname(),
        }
    }
}

impl SyslogFormatter {
    /// Create with custom facility.
    #[cfg(test)]
    fn with_facility(facility: SyslogFacility) -> Self {
        Self {
            facility,
            ..Default::default()
        }
    }

    /// Calculate PRI value (facility * 8 + severity).
    fn pri(&self, level: LogLevel) -> u8 {
        self.facility.code() * 8 + level.syslog_severity()
    }
}

impl LogFormatter for SyslogFormatter {
    fn format(&self, entry: &LogEntry) -> String {
        // RFC 5424 format:
        // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG

        let pri = self.pri(entry.level);
        let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ");
        let procid = std::process::id();
        let msgid = entry.topic.as_deref().unwrap_or("-");

        // Structured data (optional)
        let sd = if let Some(ref node) = entry.node_name {
            format!(
                "[hdds node=\"{}\" participant=\"{}\"]",
                node, entry.participant_id
            )
        } else {
            format!("[hdds participant=\"{}\"]", entry.participant_id)
        };

        format!(
            "<{}>1 {} {} {} {} {} {} {}",
            pri, timestamp, self.hostname, self.app_name, procid, msgid, sd, entry.message
        )
    }
}

/// Get hostname or fallback to "localhost".
fn gethostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string())
}

/// Create a formatter for the given output format.
pub fn create_formatter(format: OutputFormat) -> Box<dyn LogFormatter + Send + Sync> {
    match format {
        OutputFormat::Text => Box::new(TextFormatter::default()),
        OutputFormat::Json | OutputFormat::JsonLines => Box::new(JsonFormatter::compact()),
        OutputFormat::Syslog => Box::new(SyslogFormatter::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn sample_entry() -> LogEntry {
        LogEntry {
            timestamp: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
            level: LogLevel::Info,
            message: "Test message".to_string(),
            participant_id: "01020304-0506-0708-090a-0b0c0d0e0f10".to_string(),
            topic: Some("rt/rosout".to_string()),
            node_name: Some("/test_node".to_string()),
            file: Some("test.cpp".to_string()),
            line: Some(42),
            function: Some("test_func".to_string()),
        }
    }

    #[test]
    fn test_text_formatter() {
        let formatter = TextFormatter::no_colors();
        let entry = sample_entry();
        let output = formatter.format(&entry);

        assert!(output.contains("2024-01-15"));
        assert!(output.contains("[INFO ]"));
        assert!(output.contains("Test message"));
        assert!(output.contains("rt/rosout"));
    }

    #[test]
    fn test_json_formatter() {
        let formatter = JsonFormatter::compact();
        let entry = sample_entry();
        let output = formatter.format(&entry);

        assert!(output.contains("\"@timestamp\""));
        assert!(output.contains("\"level\":\"INFO\""));
        assert!(output.contains("\"message\":\"Test message\""));
        assert!(output.contains("\"topic\":\"rt/rosout\""));
    }

    #[test]
    fn test_syslog_formatter() {
        let formatter = SyslogFormatter::default();
        let entry = sample_entry();
        let output = formatter.format(&entry);

        // Should start with PRI
        assert!(output.starts_with('<'));
        // Should contain version "1"
        assert!(output.contains(">1 "));
        // Should contain structured data
        assert!(output.contains("[hdds"));
        // Should contain message
        assert!(output.contains("Test message"));
    }

    #[test]
    fn test_syslog_pri_calculation() {
        let formatter = SyslogFormatter::with_facility(SyslogFacility::Local0);

        // Local0 (16) * 8 + Info severity (6) = 134
        assert_eq!(formatter.pri(LogLevel::Info), 134);

        // Local0 (16) * 8 + Error severity (3) = 131
        assert_eq!(formatter.pri(LogLevel::Error), 131);
    }
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Log collector - subscribes to DDS log topics and aggregates logs.

use crate::{
    filter::LogFilter,
    formatter::{create_formatter, LogFormatter},
    output::{create_output, LogOutput},
    LogConfig, LogLevel,
};
use chrono::{DateTime, TimeZone, Utc};
use hdds::{Participant, TransportMode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Source of a log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LogSource {
    /// From DDS log topic (e.g., rt/rosout).
    #[default]
    DdsTopic,
    /// From internal telemetry.
    Telemetry,
    /// From local application.
    Local,
}

/// A collected log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp when log was generated.
    pub timestamp: DateTime<Utc>,
    /// Log severity level.
    pub level: LogLevel,
    /// Log message.
    pub message: String,
    /// Participant GUID (hex string).
    pub participant_id: String,
    /// Topic name (if from DDS topic).
    pub topic: Option<String>,
    /// Node name (for ROS 2 logs).
    pub node_name: Option<String>,
    /// Source file name.
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Source function name.
    pub function: Option<String>,
}

impl Default for LogEntry {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            level: LogLevel::Info,
            message: String::new(),
            participant_id: String::new(),
            topic: None,
            node_name: None,
            file: None,
            line: None,
            function: None,
        }
    }
}

impl LogEntry {
    /// Create a new log entry with message.
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            message: message.into(),
            ..Default::default()
        }
    }

    /// Set participant ID.
    pub fn with_participant(mut self, id: impl Into<String>) -> Self {
        self.participant_id = id.into();
        self
    }

    /// Set topic name.
    pub fn with_topic(mut self, topic: impl Into<String>) -> Self {
        self.topic = Some(topic.into());
        self
    }

    /// Set node name.
    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.node_name = Some(node.into());
        self
    }

    /// Set source location.
    pub fn with_location(
        mut self,
        file: impl Into<String>,
        line: u32,
        function: impl Into<String>,
    ) -> Self {
        self.file = Some(file.into());
        self.line = Some(line);
        self.function = Some(function.into());
        self
    }
}

/// Log collector that subscribes to DDS log topics.
pub struct LogCollector {
    config: LogConfig,
    formatter: Box<dyn LogFormatter + Send + Sync>,
    output: Box<dyn LogOutput>,
    filter: LogFilter,
    running: Arc<AtomicBool>,
    stats: CollectorStats,
}

/// Collector statistics.
#[derive(Debug, Default)]
pub struct CollectorStats {
    /// Total logs received.
    pub logs_received: u64,
    /// Logs written (after filtering).
    pub logs_written: u64,
    /// Logs filtered out.
    pub logs_filtered: u64,
    /// Write errors.
    pub write_errors: u64,
}

impl LogCollector {
    /// Create a new log collector.
    pub fn new(config: LogConfig) -> io::Result<Self> {
        let formatter = create_formatter(config.format);
        let output = create_output(&config.output)?;
        let filter = config.filter.clone();

        Ok(Self {
            config,
            formatter,
            output,
            filter,
            running: Arc::new(AtomicBool::new(false)),
            stats: CollectorStats::default(),
        })
    }

    /// Get collector statistics.
    pub fn stats(&self) -> &CollectorStats {
        &self.stats
    }

    /// Process a single log entry.
    pub fn process(&mut self, entry: LogEntry) -> io::Result<()> {
        self.stats.logs_received += 1;

        // Apply filter
        if !self.filter.matches(&entry) {
            self.stats.logs_filtered += 1;
            return Ok(());
        }

        // Format and write
        let line = self.formatter.format(&entry);
        match self.output.write(&line) {
            Ok(()) => {
                self.stats.logs_written += 1;
                Ok(())
            }
            Err(e) => {
                self.stats.write_errors += 1;
                Err(e)
            }
        }
    }

    /// Flush output.
    pub fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }

    /// Check if collector is running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Stop the collector.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get a handle to stop the collector from another thread.
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle {
            running: self.running.clone(),
        }
    }

    /// Run the collector (blocking).
    ///
    /// This would subscribe to DDS topics and process incoming logs.
    pub fn run(&mut self) -> io::Result<()> {
        self.running.store(true, Ordering::SeqCst);

        tracing::info!(
            domain_id = self.config.domain_id,
            topic_pattern = %self.config.topic_pattern,
            "Starting log collector"
        );

        self.run_with_processor(|collector, entry| collector.process(entry))?;

        tracing::info!(
            logs_received = self.stats.logs_received,
            logs_written = self.stats.logs_written,
            "Log collector stopped"
        );

        Ok(())
    }

    /// Run with a callback for each log entry (for testing/integration).
    pub fn run_with_callback<F>(&mut self, mut callback: F) -> io::Result<()>
    where
        F: FnMut(&LogEntry),
    {
        self.running.store(true, Ordering::SeqCst);

        self.run_with_processor(|collector, entry| {
            callback(&entry);
            collector.process(entry)
        })
    }

    fn run_with_processor<F>(&mut self, mut handler: F) -> io::Result<()>
    where
        F: FnMut(&mut LogCollector, LogEntry) -> io::Result<()>,
    {
        let topic_pattern = self.config.topic_pattern.clone();

        let participant = Participant::builder("hdds-logger")
            .with_transport(TransportMode::UdpMulticast)
            .domain_id(self.config.domain_id)
            .build()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut readers: HashMap<String, hdds::RawDataReader> = HashMap::new();
        let mut last_discovery = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);

        while self.running.load(Ordering::SeqCst) {
            if last_discovery.elapsed() >= Duration::from_secs(1) {
                match participant.discover_topics() {
                    Ok(topics) => {
                        for info in topics {
                            if !topic_matches(&topic_pattern, &info.name) {
                                continue;
                            }

                            if readers.contains_key(&info.name) {
                                continue;
                            }

                            let reader = match participant.create_raw_reader_with_type(
                                &info.name,
                                &info.type_name,
                                Some(info.qos.clone()),
                                info.type_object.clone(),
                            ) {
                                Ok(reader) => reader,
                                Err(err) => {
                                    tracing::warn!(
                                        "Failed to create raw reader for {}: {}",
                                        info.name,
                                        err
                                    );
                                    match participant.create_raw_reader(&info.name, None) {
                                        Ok(reader) => reader,
                                        Err(fallback_err) => {
                                            tracing::warn!(
                                                "Fallback raw reader failed for {}: {}",
                                                info.name,
                                                fallback_err
                                            );
                                            continue;
                                        }
                                    }
                                }
                            };

                            readers.insert(info.name.clone(), reader);
                        }
                    }
                    Err(err) => {
                        tracing::warn!("DDS discovery failed: {}", err);
                    }
                }
                last_discovery = Instant::now();
            }

            for (topic, reader) in readers.iter() {
                match reader.try_take_raw() {
                    Ok(samples) => {
                        for sample in samples {
                            if let Some(entry) =
                                parse_ros2_log(&sample.payload, "unknown", topic.as_str())
                            {
                                if let Err(err) = handler(self, entry) {
                                    tracing::warn!("Log output failed: {}", err);
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::debug!("DDS read failed for {}: {}", topic, err);
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(20));
        }

        self.flush()
    }
}

/// Handle to stop a running collector.
#[derive(Clone)]
pub struct StopHandle {
    running: Arc<AtomicBool>,
}

impl StopHandle {
    /// Stop the collector.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Parse ROS 2 rcl_interfaces/Log message.
///
/// ROS 2 Log message structure:
/// - stamp: builtin_interfaces/Time
/// - level: uint8 (DEBUG=10, INFO=20, WARN=30, ERROR=40, FATAL=50)
/// - name: string (logger name)
/// - msg: string (log message)
/// - file: string (source file)
/// - function: string (function name)
/// - line: uint32 (line number)
pub fn parse_ros2_log(data: &[u8], participant_id: &str, topic: &str) -> Option<LogEntry> {
    let (payload, little_endian) = strip_cdr_encapsulation(data);
    let mut cursor = CdrCursor::new(payload, little_endian);

    let sec = cursor.read_i32()?;
    let nanosec = cursor.read_u32()?;
    let level = cursor.read_u8()?;
    let name = cursor.read_string()?;
    let msg = cursor.read_string()?;
    let file = cursor.read_string()?;
    let function = cursor.read_string()?;
    let line = cursor.read_u32()?;

    let timestamp = Utc
        .timestamp_opt(sec as i64, nanosec)
        .single()
        .unwrap_or_else(Utc::now);

    let level = match level {
        10 => LogLevel::Debug,
        20 => LogLevel::Info,
        30 => LogLevel::Warn,
        40 => LogLevel::Error,
        50 => LogLevel::Fatal,
        _ => LogLevel::Unset,
    };

    Some(LogEntry {
        timestamp,
        level,
        message: msg,
        participant_id: participant_id.to_string(),
        topic: Some(topic.to_string()),
        node_name: if name.is_empty() { None } else { Some(name) },
        file: if file.is_empty() { None } else { Some(file) },
        line: Some(line),
        function: if function.is_empty() {
            None
        } else {
            Some(function)
        },
    })
}

fn topic_matches(pattern: &str, text: &str) -> bool {
    if pattern == text {
        return true;
    }
    if !pattern.contains('*') && !pattern.contains('?') {
        return false;
    }
    glob_match(pattern, text)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    glob_match_recursive(&pattern_chars, &text_chars, 0, 0)
}

fn glob_match_recursive(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() {
        return ti == text.len();
    }

    match pattern[pi] {
        '*' => {
            for i in ti..=text.len() {
                if glob_match_recursive(pattern, text, pi + 1, i) {
                    return true;
                }
            }
            false
        }
        '?' => {
            if ti < text.len() {
                glob_match_recursive(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
        c => {
            if ti < text.len() && text[ti] == c {
                glob_match_recursive(pattern, text, pi + 1, ti + 1)
            } else {
                false
            }
        }
    }
}

fn strip_cdr_encapsulation(buf: &[u8]) -> (&[u8], bool) {
    if buf.len() < 4 {
        return (buf, true);
    }

    let rep_id = u16::from_be_bytes([buf[0], buf[1]]);
    match rep_id {
        0x0000 | 0x0002 => (&buf[4..], false),
        0x0001 | 0x0003 => (&buf[4..], true),
        _ => (buf, true),
    }
}

struct CdrCursor<'a> {
    buf: &'a [u8],
    pos: usize,
    little_endian: bool,
}

impl<'a> CdrCursor<'a> {
    fn new(buf: &'a [u8], little_endian: bool) -> Self {
        Self {
            buf,
            pos: 0,
            little_endian,
        }
    }

    fn align(&mut self, alignment: usize) -> Option<()> {
        let mask = alignment.saturating_sub(1);
        let aligned = (self.pos + mask) & !mask;
        if aligned > self.buf.len() {
            return None;
        }
        self.pos = aligned;
        Some(())
    }

    fn read_u8(&mut self) -> Option<u8> {
        self.align(1)?;
        if self.pos + 1 > self.buf.len() {
            return None;
        }
        let val = self.buf[self.pos];
        self.pos += 1;
        Some(val)
    }

    fn read_u32(&mut self) -> Option<u32> {
        self.align(4)?;
        self.read_u32_raw()
    }

    fn read_i32(&mut self) -> Option<i32> {
        self.align(4)?;
        self.read_i32_raw()
    }

    fn read_string(&mut self) -> Option<String> {
        self.align(4)?;
        let len = self.read_u32_raw()? as usize;
        if len == 0 {
            return Some(String::new());
        }
        if self.pos + len > self.buf.len() {
            return None;
        }
        let raw = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        let trimmed = if raw.last() == Some(&0) {
            &raw[..len - 1]
        } else {
            raw
        };
        Some(String::from_utf8_lossy(trimmed).to_string())
    }

    fn read_u32_raw(&mut self) -> Option<u32> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let bytes = [
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ];
        self.pos += 4;
        Some(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn read_i32_raw(&mut self) -> Option<i32> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let bytes = [
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ];
        self.pos += 4;
        Some(if self.little_endian {
            i32::from_le_bytes(bytes)
        } else {
            i32::from_be_bytes(bytes)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OutputConfig, OutputFormat};

    #[test]
    fn test_log_entry_builder() {
        let entry = LogEntry::new(LogLevel::Error, "Something went wrong")
            .with_participant("01020304-0506-0708-090a-0b0c0d0e0f10")
            .with_topic("rt/rosout")
            .with_node("/my_node")
            .with_location("main.cpp", 42, "main");

        assert_eq!(entry.level, LogLevel::Error);
        assert_eq!(entry.message, "Something went wrong");
        assert_eq!(entry.topic, Some("rt/rosout".to_string()));
        assert_eq!(entry.node_name, Some("/my_node".to_string()));
        assert_eq!(entry.line, Some(42));
    }

    #[test]
    fn test_collector_process() {
        let config = LogConfig {
            format: OutputFormat::Text,
            output: OutputConfig::Stdout,
            filter: LogFilter::min_level(LogLevel::Warn),
            ..Default::default()
        };

        let mut collector = LogCollector::new(config).unwrap();

        // Info should be filtered
        let info_entry =
            LogEntry::new(LogLevel::Info, "Info message").with_participant("test-participant");
        collector.process(info_entry).unwrap();
        assert_eq!(collector.stats.logs_filtered, 1);
        assert_eq!(collector.stats.logs_written, 0);

        // Error should pass
        let error_entry =
            LogEntry::new(LogLevel::Error, "Error message").with_participant("test-participant");
        collector.process(error_entry).unwrap();
        assert_eq!(collector.stats.logs_written, 1);
    }

    #[test]
    fn test_stop_handle() {
        let config = LogConfig::default();
        let collector = LogCollector::new(config).unwrap();
        let handle = collector.stop_handle();

        assert!(!collector.is_running());
        handle.stop();
        assert!(!collector.is_running());
    }
}

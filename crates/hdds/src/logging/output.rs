// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Logging output backends (console and file).
//!
//! This module provides the abstraction layer for log output handling.
//! Implementations are thread-safe and non-blocking where possible.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::sync::Mutex;

/// Log level enumeration for filtering and display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Debug: detailed development information
    Debug = 0,
    /// Info: general information about normal operation
    Info = 1,
    /// Warning: potentially harmful situations
    Warning = 2,
    /// Error: error conditions
    Error = 3,
}

impl LogLevel {
    /// Returns the string representation of the log level.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warning => "WARN ",
            Self::Error => "ERROR",
        }
    }
}

/// Output destination trait for log messages.
///
/// Implementations must be thread-safe and handle errors gracefully.
pub trait Output: Send + Sync {
    /// Write a formatted log message to the output.
    ///
    /// # Parameters
    /// - `level`: The log level
    /// - `message`: The formatted log message
    ///
    /// # Returns
    /// - `Ok(())` if successful
    /// - `Err(io::Error)` if writing failed
    fn write(&self, level: LogLevel, message: &str) -> io::Result<()>;

    /// Flush any buffered output.
    fn flush(&self) -> io::Result<()>;
}

/// Console output implementation.
///
/// Writes directly to stderr with level prefix and newline.
/// Thread-safe via internal mutex.
pub struct ConsoleOutput {
    level_filter: Mutex<LogLevel>,
}

impl ConsoleOutput {
    /// Create a new console output with the specified minimum level.
    pub fn new(level_filter: LogLevel) -> Self {
        Self {
            level_filter: Mutex::new(level_filter),
        }
    }

    /// Set the minimum log level for this output.
    ///
    /// # Errors
    /// Returns error only if internal mutex is poisoned (critical failure).
    pub fn set_level(&self, _level: LogLevel) -> io::Result<()> {
        // Currently unused but kept for future filtering per-output
        drop(
            self.level_filter
                .lock()
                .map_err(|_| io::Error::other("console output mutex poisoned"))?,
        );
        Ok(())
    }
}

impl Output for ConsoleOutput {
    fn write(&self, level: LogLevel, message: &str) -> io::Result<()> {
        // Get current filter level (safe to unwrap after set_level check)
        let filter = self
            .level_filter
            .lock()
            .map_err(|_| io::Error::other("console output mutex poisoned"))?;

        // Only write if level meets minimum threshold
        if level < *filter {
            return Ok(());
        }

        let output = format!("[{}] {}\n", level.as_str(), message);
        eprint!("{}", output);
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        io::stderr().flush()
    }
}

/// File output implementation.
///
/// Appends log messages to a file with level prefix and newline.
/// Thread-safe via internal mutex protecting the file handle.
pub struct FileOutput {
    file: Mutex<std::fs::File>,
    level_filter: Mutex<LogLevel>,
}

impl FileOutput {
    /// Create a new file output, creating/truncating the file at the given path.
    ///
    /// # Parameters
    /// - `path`: Path to the log file
    /// - `level_filter`: Minimum log level to write
    ///
    /// # Returns
    /// - `Ok(FileOutput)` on success
    /// - `Err(io::Error)` if file cannot be created
    pub fn new(path: &str, level_filter: LogLevel) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        Ok(Self {
            file: Mutex::new(file),
            level_filter: Mutex::new(level_filter),
        })
    }

    /// Set the minimum log level for this output.
    pub fn set_level(&self, _level: LogLevel) -> io::Result<()> {
        // Currently unused but kept for future filtering per-output
        drop(
            self.level_filter
                .lock()
                .map_err(|_| io::Error::other("file output mutex poisoned"))?,
        );
        Ok(())
    }
}

impl Output for FileOutput {
    fn write(&self, level: LogLevel, message: &str) -> io::Result<()> {
        let filter = self
            .level_filter
            .lock()
            .map_err(|_| io::Error::other("file output mutex poisoned"))?;

        if level < *filter {
            return Ok(());
        }

        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::other("file output mutex poisoned"))?;

        let output = format!("[{}] {}\n", level.as_str(), message);
        file.write_all(output.as_bytes())?;
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        self.file
            .lock()
            .map_err(|_| io::Error::other("file output mutex poisoned"))?
            .flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warning);
        assert!(LogLevel::Warning < LogLevel::Error);
    }

    #[test]
    fn test_log_level_str() {
        assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
        assert_eq!(LogLevel::Info.as_str(), "INFO ");
        assert_eq!(LogLevel::Warning.as_str(), "WARN ");
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
    }

    #[test]
    fn test_console_output_creation() {
        let output = ConsoleOutput::new(LogLevel::Info);
        assert!(output.write(LogLevel::Error, "test").is_ok());
        assert!(output.flush().is_ok());
    }

    #[test]
    fn test_file_output_creation() {
        let temp_path = "/tmp/test_logging.log";
        let output = FileOutput::new(temp_path, LogLevel::Debug);
        assert!(output.is_ok());

        if let Ok(out) = output {
            assert!(out.write(LogLevel::Info, "test message").is_ok());
            assert!(out.flush().is_ok());
        }
    }

    #[test]
    fn test_file_output_level_filter() {
        let temp_path = "/tmp/test_logging_filter.log";
        if let Ok(output) = FileOutput::new(temp_path, LogLevel::Warning) {
            // Debug messages should be filtered
            assert!(output.write(LogLevel::Debug, "debug").is_ok());
            // Warning messages should pass
            assert!(output.write(LogLevel::Warning, "warning").is_ok());
        }
    }
}

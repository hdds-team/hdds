// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Global logger instance and initialization.
//!
//! Provides a thread-safe singleton logger with support for multiple outputs.
//! Uses lazy initialization to avoid startup overhead.

use super::output::{LogLevel, Output};
use std::io;
use std::sync::{Arc, Mutex, OnceLock};

static LOGGER: OnceLock<Arc<Mutex<GlobalLogger>>> = OnceLock::new();

/// Global logger state.
///
/// Manages the active output destination and log level filtering.
/// All operations are thread-safe via internal mutex.
pub struct GlobalLogger {
    output: Option<Arc<dyn Output>>,
    level_filter: LogLevel,
}

impl GlobalLogger {
    /// Create a new logger without any output (disabled state).
    fn new() -> Self {
        Self {
            output: None,
            level_filter: LogLevel::Info,
        }
    }

    /// Set the output destination.
    ///
    /// # Parameters
    /// - `output`: The output implementation (e.g., ConsoleOutput, FileOutput)
    fn set_output(&mut self, output: Arc<dyn Output>) {
        self.output = Some(output);
    }

    /// Set the global log level filter.
    ///
    /// Messages below this level will be ignored.
    fn set_level_filter(&mut self, level: LogLevel) {
        self.level_filter = level;
    }

    /// Write a log message if logging is enabled and level matches.
    ///
    /// # Parameters
    /// - `level`: The message's log level
    /// - `message`: The formatted message
    fn log(&self, level: LogLevel, message: &str) -> io::Result<()> {
        // Check level filter first (cheap operation)
        if level < self.level_filter {
            return Ok(());
        }

        // Write only if output is configured
        if let Some(ref output) = self.output {
            output.write(level, message)?;
        }

        Ok(())
    }

    /// Flush any buffered output.
    fn flush(&self) -> io::Result<()> {
        if let Some(ref output) = self.output {
            output.flush()?;
        }
        Ok(())
    }
}

/// Initialize the global logger with the given output.
///
/// This function can only be called once. Subsequent calls are ignored.
/// Call this early in your application startup, before any logging macros.
///
/// # Parameters
/// - `output`: The output destination
/// - `level`: Minimum log level
///
/// # Example
/// ```ignore
/// use hdds::logging::{init_logger, ConsoleOutput, LogLevel};
/// let output = ConsoleOutput::new(LogLevel::Debug);
/// init_logger(Arc::new(output), LogLevel::Debug);
/// ```
pub fn init_logger(output: Arc<dyn Output>, level: LogLevel) {
    let _ = LOGGER.get_or_init(|| {
        let mut logger = GlobalLogger::new();
        logger.set_output(output);
        logger.set_level_filter(level);
        Arc::new(Mutex::new(logger))
    });
}

/// Get the global logger instance.
///
/// Returns None if logger not yet initialized.
/// Panics only if the mutex is poisoned (critical system failure).
#[inline]
fn get_logger() -> Option<Arc<Mutex<GlobalLogger>>> {
    LOGGER.get().cloned()
}

/// Internal: Execute a log operation with the global logger.
///
/// If logger is not initialized, this is a no-op (returns Ok).
/// This function is called by the logging macros.
///
/// # Parameters
/// - `level`: The log level
/// - `message`: The formatted message
#[inline]
pub(crate) fn log_message(level: LogLevel, message: &str) -> io::Result<()> {
    match get_logger() {
        Some(logger) => {
            let guard = logger
                .lock()
                .map_err(|_| io::Error::other("global logger mutex poisoned"))?;
            guard.log(level, message)
        }
        None => Ok(()), // Not initialized yet, silent no-op
    }
}

/// Trace a function entry point.
///
/// Used by `trace_fn!()` macro for call stack instrumentation.
/// Logs with timestamp for call stack debugging.
///
/// # Parameters
/// - `fn_name`: The function name (usually `module::function_name`)
#[inline]
pub(crate) fn trace_entry(fn_name: &str) -> io::Result<()> {
    let msg = format!("[ENTER:FNC] {}", fn_name);
    log_message(LogLevel::Debug, &msg)
}

/// Flush the global logger's output.
///
/// Safe to call even if logger not initialized.
pub fn flush_logger() -> io::Result<()> {
    match get_logger() {
        Some(logger) => {
            let guard = logger
                .lock()
                .map_err(|_| io::Error::other("global logger mutex poisoned"))?;
            guard.flush()
        }
        None => Ok(()), // Not initialized, no-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::output::ConsoleOutput;

    #[test]
    fn test_logger_creation() {
        let output = Arc::new(ConsoleOutput::new(LogLevel::Debug));
        init_logger(output, LogLevel::Debug);
        // If we get here without panic, initialization worked
    }

    #[test]
    fn test_log_message_no_panic() {
        // Should not panic even if logger not initialized
        let result = log_message(LogLevel::Info, "test message");
        // Ok(()) for uninitialized, Ok(()) for successful write
        assert!(result.is_ok());
    }

    #[test]
    fn test_flush_logger_no_panic() {
        // Should not panic even if logger not initialized
        let result = flush_logger();
        assert!(result.is_ok());
    }

    #[test]
    fn test_level_filtering() {
        let output = Arc::new(ConsoleOutput::new(LogLevel::Warning));
        init_logger(output.clone(), LogLevel::Warning);

        // These should all return Ok without crashing
        let _ = log_message(LogLevel::Debug, "debug");
        let _ = log_message(LogLevel::Info, "info");
        let _ = log_message(LogLevel::Warning, "warning");
        let _ = log_message(LogLevel::Error, "error");
    }
}

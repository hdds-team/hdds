// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Compile-time configurable logging system.
//!
//! This module provides zero-cost abstractions for logging with four severity levels:
//! - `debug!()` - Development/debugging information
//! - `info!()` - General operational information
//! - `warn!()` - Warning conditions
//! - `error!()` - Error conditions
//!
//! ## Features
//!
//! - **Zero-cost when disabled**: Logging macros expand to no-op when feature disabled
//! - **Compile-time configurable**: Enable/disable via `logging` Cargo feature
//! - **Thread-safe**: All operations are safe across multiple threads
//! - **Flexible output**: Support for console and file outputs
//! - **Level filtering**: Configure minimum log level at runtime
//!
//! ## Example
//!
//! ```ignore
//! use hdds::logging::{init_logger, ConsoleOutput, LogLevel};
//! use std::sync::Arc;
//!
//! // Initialize early in main()
//! let console = Arc::new(ConsoleOutput::new(LogLevel::Debug));
//! init_logger(console, LogLevel::Debug);
//!
//! // Use anywhere in your code
//! debug!("Detailed info: {}", value);
//! info!("Normal operation");
//! warn!("Suspicious activity: {}", reason);
//! error!("Critical failure: {}", cause);
//! ```
//!
//! When feature `logging` is disabled, all macros compile to empty expressions
//! with zero runtime overhead.

#[cfg(feature = "logging")]
pub mod logger;
#[cfg(feature = "logging")]
mod output;

#[cfg(feature = "logging")]
pub use output::{ConsoleOutput, FileOutput, LogLevel, Output};

#[cfg(feature = "logging")]
pub use logger::{flush_logger, init_logger};

/// Debug-level log message.
///
/// Formatted the same as `println!()` macro.
/// Only emitted if compiled with `logging` feature and level >= Debug.
///
/// # Example
/// ```ignore
/// debug!("Processing item {}: {}", id, value);
/// ```
#[macro_export]
#[cfg(feature = "logging")]
macro_rules! debug {
    ($($arg:tt)*) => {
        let _ = $crate::logging::logger::log_message(
            $crate::logging::LogLevel::Debug,
            &format!($($arg)*),
        );
    };
}

/// Info-level log message.
///
/// Formatted the same as `println!()` macro.
/// Only emitted if compiled with `logging` feature and level >= Info.
///
/// # Example
/// ```ignore
/// info!("Service started on port {}", port);
/// ```
#[macro_export]
#[cfg(feature = "logging")]
macro_rules! info {
    ($($arg:tt)*) => {
        let _ = $crate::logging::logger::log_message(
            $crate::logging::LogLevel::Info,
            &format!($($arg)*),
        );
    };
}

/// Warning-level log message.
///
/// Formatted the same as `println!()` macro.
/// Only emitted if compiled with `logging` feature and level >= Warning.
///
/// # Example
/// ```ignore
/// warn!("Slow response detected: {}ms", elapsed_ms);
/// ```
#[macro_export]
#[cfg(feature = "logging")]
macro_rules! warn {
    ($($arg:tt)*) => {
        let _ = $crate::logging::logger::log_message(
            $crate::logging::LogLevel::Warning,
            &format!($($arg)*),
        );
    };
}

/// Error-level log message.
///
/// Formatted the same as `println!()` macro.
/// Only emitted if compiled with `logging` feature and level >= Error.
///
/// # Example
/// ```ignore
/// error!("Connection lost: {}", error_code);
/// ```
#[macro_export]
#[cfg(feature = "logging")]
macro_rules! error {
    ($($arg:tt)*) => {
        let _ = $crate::logging::logger::log_message(
            $crate::logging::LogLevel::Error,
            &format!($($arg)*),
        );
    };
}

/// Function entry trace marker.
///
/// Logs `[ENTER:FNC] function_name` for call stack instrumentation.
/// Only active when both `logging` AND `trace` features are enabled.
///
/// # Example
/// ```ignore
/// fn parse_spdp_data(bytes: &[u8]) -> Result<Data> {
///     trace_fn!("parse_spdp_data");
///     // ...
/// }
/// ```
#[macro_export]
#[cfg(all(feature = "logging", feature = "trace"))]
macro_rules! trace_fn {
    ($fn_name:expr) => {
        let _ = $crate::logging::logger::trace_entry($fn_name);
    };
}

/// No-op trace macro (when trace feature disabled).
#[macro_export]
#[cfg(not(all(feature = "logging", feature = "trace")))]
macro_rules! trace_fn {
    ($fn_name:expr) => {};
}

/// No-op debug macro (when logging feature disabled).
#[macro_export]
#[cfg(not(feature = "logging"))]
macro_rules! debug {
    ($($arg:tt)*) => {};
}

/// No-op info macro (when logging feature disabled).
#[macro_export]
#[cfg(not(feature = "logging"))]
macro_rules! info {
    ($($arg:tt)*) => {};
}

/// No-op warn macro (when logging feature disabled).
#[macro_export]
#[cfg(not(feature = "logging"))]
macro_rules! warn {
    ($($arg:tt)*) => {};
}

/// No-op error macro (when logging feature disabled).
#[macro_export]
#[cfg(not(feature = "logging"))]
macro_rules! error {
    ($($arg:tt)*) => {};
}

#[cfg(all(test, feature = "logging"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_macros_compile() {
        // This test just verifies the macros compile without error
        debug!("debug message");
        info!("info message");
        warn!("warn message");
        error!("error message");

        debug!("with args: {}", 42);
        info!("with format: {:?}", vec![1, 2, 3]);
    }

    #[test]
    fn test_init_and_log() {
        let console = Arc::new(ConsoleOutput::new(LogLevel::Debug));
        init_logger(console, LogLevel::Debug);

        // These should not panic
        debug!("test debug");
        info!("test info");
        warn!("test warning");
        error!("test error");

        // Flush should succeed
        assert!(flush_logger().is_ok());
    }

    #[test]
    fn test_multiple_init_calls_safe() {
        let console = Arc::new(ConsoleOutput::new(LogLevel::Info));
        init_logger(console.clone(), LogLevel::Info);

        // Second call is ignored (safe)
        init_logger(console, LogLevel::Debug);

        // Logging still works
        info!("still works");
    }
}

#[cfg(all(test, not(feature = "logging")))]
mod tests_disabled {
    #[test]
    fn test_macros_noop_disabled() {
        // These macros should expand to nothing when logging disabled
        debug!("not compiled");
        info!("not compiled");
        warn!("not compiled");
        error!("not compiled");

        // Test passes if we get here (no compilation errors)
    }
}

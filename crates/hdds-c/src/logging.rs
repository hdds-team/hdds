// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Logging initialization for HDDS C FFI

use std::ffi::CStr;
use std::os::raw::c_char;

use super::HddsError;

/// Log level for HDDS logging
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HddsLogLevel {
    HddsLogOff = 0,
    HddsLogError = 1,
    HddsLogWarn = 2,
    HddsLogInfo = 3,
    HddsLogDebug = 4,
    HddsLogTrace = 5,
}

impl From<HddsLogLevel> for log::LevelFilter {
    fn from(level: HddsLogLevel) -> Self {
        match level {
            HddsLogLevel::HddsLogOff => log::LevelFilter::Off,
            HddsLogLevel::HddsLogError => log::LevelFilter::Error,
            HddsLogLevel::HddsLogWarn => log::LevelFilter::Warn,
            HddsLogLevel::HddsLogInfo => log::LevelFilter::Info,
            HddsLogLevel::HddsLogDebug => log::LevelFilter::Debug,
            HddsLogLevel::HddsLogTrace => log::LevelFilter::Trace,
        }
    }
}

/// Initialize HDDS logging with console output
///
/// # Safety
/// Must be called from a single thread during initialization.
///
/// # Arguments
/// * `level` - Minimum log level to display
///
/// # Returns
/// `HddsError::HddsOk` on success, `HddsError::HddsOperationFailed` if already initialized
///
/// # Example (C)
/// ```c
/// hdds_logging_init(HDDS_LOG_INFO);
/// ```
#[no_mangle]
pub unsafe extern "C" fn hdds_logging_init(level: HddsLogLevel) -> HddsError {
    let filter: log::LevelFilter = level.into();

    match env_logger::Builder::new()
        .filter_level(filter)
        .format_timestamp_millis()
        .try_init()
    {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed, // Already initialized
    }
}

/// Initialize HDDS logging with environment variable override
///
/// Reads `RUST_LOG` environment variable if set, otherwise uses provided level.
///
/// # Safety
/// Must be called from a single thread during initialization.
///
/// # Arguments
/// * `default_level` - Default log level if `RUST_LOG` is not set
///
/// # Returns
/// `HddsError::HddsOk` on success
#[no_mangle]
pub unsafe extern "C" fn hdds_logging_init_env(default_level: HddsLogLevel) -> HddsError {
    let filter: log::LevelFilter = default_level.into();

    match env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(filter.to_string()),
    )
    .format_timestamp_millis()
    .try_init()
    {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

/// Initialize HDDS logging with custom filter string
///
/// # Safety
/// - `filter` must be a valid null-terminated C string or NULL.
///
/// # Arguments
/// * `filter` - Log filter string (e.g., "hdds=debug,info")
///
/// # Returns
/// `HddsError::HddsOk` on success
///
/// # Example (C)
/// ```c
/// hdds_logging_init_with_filter("hdds=debug");
/// ```
#[no_mangle]
pub unsafe extern "C" fn hdds_logging_init_with_filter(filter: *const c_char) -> HddsError {
    if filter.is_null() {
        return HddsError::HddsInvalidArgument;
    }

    let Ok(filter_str) = CStr::from_ptr(filter).to_str() else {
        return HddsError::HddsInvalidArgument;
    };

    match env_logger::Builder::new()
        .parse_filters(filter_str)
        .format_timestamp_millis()
        .try_init()
    {
        Ok(()) => HddsError::HddsOk,
        Err(_) => HddsError::HddsOperationFailed,
    }
}

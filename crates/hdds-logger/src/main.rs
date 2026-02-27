// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Distributed Logger CLI
//!
//! Aggregate and centralize logs from DDS participants.
//!
//! # Usage
//!
//! ```bash
//! # Log to stdout in text format
//! hdds-logger --domain 0
//!
//! # Log to file in JSON format with rotation
//! hdds-logger --output logs/hdds.log --format json --rotate 10M
//!
//! # Filter by level and topic
//! hdds-logger --level warn --topic "rt/rosout"
//!
//! # Output to syslog
//! hdds-logger --syslog --facility local0
//! ```

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use hdds_logger::{
    FileRotation, LogCollector, LogConfig, LogFilter, LogLevel, OutputConfig, OutputFormat,
    StopHandle, SyslogFacility,
};
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "hdds-logger")]
#[command(author = "naskel.com")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Distributed logging service for HDDS - aggregate logs from DDS participants")]
#[command(long_about = None)]
struct Cli {
    /// DDS domain ID to monitor
    #[arg(short, long, default_value = "0")]
    domain: u32,

    /// Log topic pattern to subscribe (supports wildcards)
    #[arg(short, long, default_value = "rt/rosout")]
    topic: String,

    /// Output file path (use - for stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: FormatArg,

    /// Minimum log level
    #[arg(short, long, value_enum, default_value = "info")]
    level: LevelArg,

    /// Enable file rotation with max size (e.g., 10M, 100K, 1G)
    #[arg(long)]
    rotate: Option<String>,

    /// Maximum number of rotated files to keep
    #[arg(long, default_value = "5")]
    rotate_keep: u32,

    /// Output to syslog instead of file/stdout
    #[arg(long)]
    syslog: bool,

    /// Syslog facility (when --syslog is used)
    #[arg(long, value_enum, default_value = "local0")]
    facility: FacilityArg,

    /// Filter by participant GUID pattern
    #[arg(long)]
    participant: Option<String>,

    /// Filter by node name pattern
    #[arg(long)]
    node: Option<String>,

    /// Use colors in text output
    #[arg(long, default_value = "true")]
    colors: bool,

    /// Verbose mode (show internal logs)
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Text,
    Json,
    JsonLines,
    Syslog,
}

impl From<FormatArg> for OutputFormat {
    fn from(arg: FormatArg) -> Self {
        match arg {
            FormatArg::Text => OutputFormat::Text,
            FormatArg::Json => OutputFormat::Json,
            FormatArg::JsonLines => OutputFormat::JsonLines,
            FormatArg::Syslog => OutputFormat::Syslog,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LevelArg {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl From<LevelArg> for LogLevel {
    fn from(arg: LevelArg) -> Self {
        match arg {
            LevelArg::Debug => LogLevel::Debug,
            LevelArg::Info => LogLevel::Info,
            LevelArg::Warn => LogLevel::Warn,
            LevelArg::Error => LogLevel::Error,
            LevelArg::Fatal => LogLevel::Fatal,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum FacilityArg {
    Kern,
    User,
    Daemon,
    Auth,
    Syslog,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl From<FacilityArg> for SyslogFacility {
    fn from(arg: FacilityArg) -> Self {
        match arg {
            FacilityArg::Kern => SyslogFacility::Kern,
            FacilityArg::User => SyslogFacility::User,
            FacilityArg::Daemon => SyslogFacility::Daemon,
            FacilityArg::Auth => SyslogFacility::Auth,
            FacilityArg::Syslog => SyslogFacility::Syslog,
            FacilityArg::Local0 => SyslogFacility::Local0,
            FacilityArg::Local1 => SyslogFacility::Local1,
            FacilityArg::Local2 => SyslogFacility::Local2,
            FacilityArg::Local3 => SyslogFacility::Local3,
            FacilityArg::Local4 => SyslogFacility::Local4,
            FacilityArg::Local5 => SyslogFacility::Local5,
            FacilityArg::Local6 => SyslogFacility::Local6,
            FacilityArg::Local7 => SyslogFacility::Local7,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup tracing for internal logs
    let filter = if cli.verbose {
        EnvFilter::new("hdds_logger=debug,hdds=debug")
    } else {
        EnvFilter::new("hdds_logger=info,hdds=warn")
    };

    fmt().with_env_filter(filter).with_target(false).init();

    // Build configuration
    let config = build_config(&cli)?;

    tracing::info!(
        domain = cli.domain,
        topic = %cli.topic,
        format = ?cli.format,
        level = ?cli.level,
        "Starting HDDS Logger"
    );

    // Create and run collector
    let mut collector = LogCollector::new(config).context("Failed to create log collector")?;

    // Setup Ctrl+C handler
    let stop_handle = collector.stop_handle();
    ctrlc_handler(stop_handle);

    // Run collector
    collector.run().context("Log collector error")?;

    let stats = collector.stats();
    tracing::info!(
        logs_received = stats.logs_received,
        logs_written = stats.logs_written,
        logs_filtered = stats.logs_filtered,
        "Logger shutdown complete"
    );

    Ok(())
}

fn build_config(cli: &Cli) -> Result<LogConfig> {
    // Build output config
    let output = if cli.syslog {
        OutputConfig::Syslog {
            facility: cli.facility.into(),
        }
    } else if let Some(ref path) = cli.output {
        let rotation = cli.rotate.as_ref().map(|size_str| {
            let max_size = parse_size(size_str).unwrap_or(10 * 1024 * 1024);
            FileRotation {
                max_size,
                max_files: cli.rotate_keep,
                compress: false,
            }
        });
        OutputConfig::File {
            path: path.clone(),
            rotation,
        }
    } else {
        OutputConfig::Stdout
    };

    // Build filter
    let mut filter = LogFilter::min_level(cli.level.into());
    filter.participant_pattern = cli.participant.clone();
    filter.node_pattern = cli.node.clone();

    Ok(LogConfig {
        format: cli.format.into(),
        output,
        filter,
        domain_id: cli.domain,
        topic_pattern: cli.topic.clone(),
    })
}

/// Parse size string like "10M", "100K", "1G".
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim().to_uppercase();

    if let Some(num) = s.strip_suffix('K') {
        num.parse::<u64>().ok().map(|n| n * 1024)
    } else if let Some(num) = s.strip_suffix('M') {
        num.parse::<u64>().ok().map(|n| n * 1024 * 1024)
    } else if let Some(num) = s.strip_suffix('G') {
        num.parse::<u64>().ok().map(|n| n * 1024 * 1024 * 1024)
    } else {
        s.parse::<u64>().ok()
    }
}

/// Setup Ctrl+C handler.
fn ctrlc_handler(stop_handle: StopHandle) {
    let _ = ctrlc::set_handler(move || {
        tracing::info!("Received Ctrl+C, shutting down...");
        stop_handle.stop();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("100"), Some(100));
        assert_eq!(parse_size("10K"), Some(10 * 1024));
        assert_eq!(parse_size("10M"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("10m"), Some(10 * 1024 * 1024)); // Case insensitive
        assert_eq!(parse_size("invalid"), None);
    }
}

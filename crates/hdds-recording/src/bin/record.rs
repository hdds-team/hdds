// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-record - Record DDS messages to file.
//!
//! Usage:
//!   hdds-record --domain 0 --output capture.hdds
//!   hdds-record --domain 0 --output capture.hdds --topics "rt/*"
//!   hdds-record --domain 0 --output capture.hdds --rotate-size 100

use clap::Parser;
use hdds::{Participant, TransportMode};
use hdds_recording::{
    filter::TopicFilter,
    recorder::{Recorder, RecorderConfig},
    rotation::RotationPolicy,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "hdds-record")]
#[command(about = "Record DDS messages to file")]
#[command(version)]
struct Args {
    /// DDS domain ID
    #[arg(short, long, default_value = "0")]
    domain: u32,

    /// Output file path (.hdds or .mcap)
    #[arg(short, long)]
    output: PathBuf,

    /// Topic filter (include pattern, supports wildcards)
    #[arg(short, long)]
    topics: Option<String>,

    /// Exclude topics (pattern)
    #[arg(long)]
    exclude_topics: Option<String>,

    /// Type filter (include pattern)
    #[arg(long)]
    types: Option<String>,

    /// Recording description
    #[arg(long)]
    description: Option<String>,

    /// Rotate files by size (MB)
    #[arg(long)]
    rotate_size: Option<u64>,

    /// Rotate files by duration (seconds)
    #[arg(long)]
    rotate_duration: Option<u64>,

    /// Maximum number of rotated files to keep
    #[arg(long, default_value = "0")]
    max_files: u32,

    /// Duration to record (seconds, 0 = indefinite)
    #[arg(long, default_value = "0")]
    duration: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Quiet mode (minimal output)
    #[arg(short, long)]
    quiet: bool,
}

struct RecordingReader {
    reader: hdds::RawDataReader,
    type_name: String,
    qos_hash: u32,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Setup logging
    let filter = args.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .init();

    // Build recorder config
    let mut config = RecorderConfig::new(&args.output).domain_id(args.domain);

    // Topic filter
    if let Some(pattern) = &args.topics {
        let patterns: Vec<String> = pattern.split(',').map(|s| s.trim().to_string()).collect();
        config = config.topic_filter(TopicFilter::include(patterns));
    } else if let Some(pattern) = &args.exclude_topics {
        let patterns: Vec<String> = pattern.split(',').map(|s| s.trim().to_string()).collect();
        config = config.topic_filter(TopicFilter::exclude(patterns));
    }

    // Description
    if let Some(desc) = &args.description {
        config = config.description(desc.clone());
    }

    // Rotation policy
    if let Some(size_mb) = args.rotate_size {
        let policy = RotationPolicy::by_size(size_mb).with_max_files(args.max_files);
        config = config.rotation(policy);
    } else if let Some(duration) = args.rotate_duration {
        let policy = RotationPolicy::by_duration(duration).with_max_files(args.max_files);
        config = config.rotation(policy);
    }

    // Create recorder
    let mut recorder = Recorder::new(config);

    if !args.quiet {
        info!("HDDS Recording Service v{}", env!("CARGO_PKG_VERSION"));
        info!("Domain: {}", args.domain);
        info!("Output: {}", args.output.display());
        if let Some(ref topics) = args.topics {
            info!("Topics: {}", topics);
        }
    }

    // Start recording
    recorder.start()?;

    if !args.quiet {
        info!("Recording started. Press Ctrl+C to stop.");
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let participant = Participant::builder("hdds-record")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(args.domain)
        .build()?;

    let topic_filter = recorder.config().topic_filter.clone();
    let type_filter = recorder.config().type_filter.clone();
    let mut readers: HashMap<String, RecordingReader> = HashMap::new();
    let mut last_discovery = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut last_report = Instant::now();

    // Recording loop
    let start = Instant::now();
    let duration_limit = if args.duration > 0 {
        Some(std::time::Duration::from_secs(args.duration))
    } else {
        None
    };

    while running.load(Ordering::SeqCst) {
        // Check duration limit
        if let Some(limit) = duration_limit {
            if start.elapsed() >= limit {
                info!("Duration limit reached");
                break;
            }
        }

        if last_discovery.elapsed() >= Duration::from_secs(1) {
            match participant.discover_topics() {
                Ok(topics) => {
                    for info in topics {
                        if info.publisher_count == 0 {
                            continue;
                        }

                        if let Some(ref filter) = topic_filter {
                            if !filter.matches(&info.name) {
                                continue;
                            }
                        }

                        if let Some(ref filter) = type_filter {
                            if !filter.matches(&info.type_name) {
                                continue;
                            }
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
                                warn!("Failed to create reader for {}: {}", info.name, err);
                                continue;
                            }
                        };

                        readers.insert(
                            info.name.clone(),
                            RecordingReader {
                                reader,
                                type_name: info.type_name.clone(),
                                qos_hash: info.qos_hash,
                            },
                        );
                    }
                }
                Err(err) => {
                    warn!("DDS discovery failed: {}", err);
                }
            }
            last_discovery = Instant::now();
        }

        for (topic, entry) in readers.iter() {
            match entry.reader.try_take_raw() {
                Ok(samples) => {
                    for sample in samples {
                        let seq = sample.sequence_number.unwrap_or(0);
                        let writer_guid = if sample.writer_guid.is_zero() {
                            "unknown".to_string()
                        } else {
                            sample.writer_guid.to_string()
                        };
                        recorder.record_sample(
                            topic,
                            &entry.type_name,
                            &writer_guid,
                            seq,
                            &sample.payload,
                            entry.qos_hash,
                        )?;
                    }
                }
                Err(err) => {
                    warn!("DDS read failed for {}: {}", topic, err);
                }
            }
        }

        // Print periodic stats
        if !args.quiet && last_report.elapsed() >= Duration::from_secs(10) {
            let stats = recorder.stats();
            if stats.message_count > 0 {
                info!(
                    "Recorded {} messages ({:.1} MB)",
                    stats.message_count,
                    stats.bytes_written as f64 / 1_048_576.0
                );
            }
            last_report = Instant::now();
        }

        std::thread::sleep(Duration::from_millis(20));
    }

    // Stop recording
    let stats = recorder.stop()?;

    if !args.quiet {
        info!("Recording stopped");
        info!("  Messages: {}", stats.message_count);
        info!("  Duration: {:.1}s", stats.duration_secs);
        info!("  Throughput: {:.1} msg/s", stats.messages_per_second);
        info!("  File: {}", args.output.display());
    }

    Ok(())
}

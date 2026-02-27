// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-replay - Replay recorded DDS messages.
//!
//! Usage:
//!   hdds-replay --input capture.hdds
//!   hdds-replay --input capture.hdds --speed 2.0
//!   hdds-replay --input capture.hdds --loop

use clap::Parser;
use hdds::dds::Durability as HddsDurability;
use hdds::{Participant, QoS, TransportMode};
use hdds_recording::{
    filter::TopicFilter,
    player::{PlaybackSpeed, Player, PlayerConfig},
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "hdds-replay")]
#[command(about = "Replay recorded DDS messages")]
#[command(version)]
struct Args {
    /// Input recording file (.hdds)
    #[arg(short, long)]
    input: PathBuf,

    /// Playback speed multiplier (1.0 = realtime, 0 = unlimited)
    #[arg(short, long, default_value = "1.0")]
    speed: f64,

    /// Loop playback indefinitely
    #[arg(short, long)]
    loop_playback: bool,

    /// Topic filter (include pattern, supports wildcards)
    #[arg(short, long)]
    topics: Option<String>,

    /// Start offset (seconds from beginning)
    #[arg(long, default_value = "0")]
    start: u64,

    /// End time (seconds from beginning, 0 = play all)
    #[arg(long, default_value = "0")]
    end: u64,

    /// DDS domain ID for publishing
    #[arg(short, long, default_value = "0")]
    domain: u32,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Quiet mode (minimal output)
    #[arg(short, long)]
    quiet: bool,

    /// Dry run (don't publish, just iterate)
    #[arg(long)]
    dry_run: bool,

    /// Show recording info and exit
    #[arg(long)]
    info_only: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Setup logging
    let filter = args.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .init();

    // Verify input file exists
    if !args.input.exists() {
        anyhow::bail!("Input file not found: {}", args.input.display());
    }

    // Build player config
    let speed = if args.speed <= 0.0 {
        PlaybackSpeed::Unlimited
    } else if (args.speed - 1.0).abs() < 0.001 {
        PlaybackSpeed::Realtime
    } else {
        PlaybackSpeed::Speed(args.speed)
    };

    let mut config = PlayerConfig::new(&args.input)
        .speed(speed)
        .loop_playback(args.loop_playback);

    // Time range
    if args.start > 0 {
        config = config.start_offset(Duration::from_secs(args.start));
    }
    if args.end > 0 {
        config = config.end_time(Duration::from_secs(args.end));
    }

    // Topic filter
    if let Some(pattern) = &args.topics {
        let patterns: Vec<String> = pattern.split(',').map(|s| s.trim().to_string()).collect();
        config = config.topic_filter(TopicFilter::include(patterns));
    }

    // Create player
    let mut player = Player::new(config);

    // Open file
    player.open()?;

    // Show info
    if !args.quiet || args.info_only {
        info!("HDDS Replay Service v{}", env!("CARGO_PKG_VERSION"));
        info!("Input: {}", args.input.display());

        if let Some(meta) = player.metadata() {
            info!("Recording info:");
            info!("  Start time: {}", meta.start_time);
            info!("  Domain: {}", meta.domain_id);
            info!("  HDDS version: {}", meta.hdds_version);
            if let Some(ref host) = meta.hostname {
                info!("  Hostname: {}", host);
            }
            if let Some(ref desc) = meta.description {
                info!("  Description: {}", desc);
            }
            info!("  Topics: {}", meta.topics.len());
            for topic in &meta.topics {
                info!(
                    "    - {} ({}) - {} messages",
                    topic.name, topic.type_name, topic.message_count
                );
            }
        }

        info!("Total messages: {}", player.total_messages());
        info!(
            "Recording duration: {:.1}s",
            player.stats().recording_duration_secs
        );
        info!("Playback speed: {}", format_speed(speed));

        if args.loop_playback {
            info!("Loop: enabled");
        }
    }

    // Info only mode
    if args.info_only {
        return Ok(());
    }

    if !args.quiet {
        info!("Starting playback. Press Ctrl+C to stop.");
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let participant = Participant::builder("hdds-replay")
        .with_transport(TransportMode::UdpMulticast)
        .domain_id(args.domain)
        .build()?;

    let qos_map = qos_map_from_metadata(player.metadata());
    let mut writers: HashMap<String, hdds::RawDataWriter> = HashMap::new();

    // Playback loop
    let start_time = std::time::Instant::now();
    let mut last_progress = 0u64;

    while running.load(Ordering::SeqCst) {
        match player.next_message() {
            Ok(Some(msg)) => {
                if args.dry_run {
                    // Dry run: just count messages
                } else {
                    if !writers.contains_key(&msg.topic_name) {
                        let qos = qos_map.get(&msg.topic_name).cloned();
                        match participant.create_raw_writer_with_type(
                            &msg.topic_name,
                            &msg.type_name,
                            qos,
                            None,
                        ) {
                            Ok(writer) => {
                                writers.insert(msg.topic_name.clone(), writer);
                            }
                            Err(err) => {
                                warn!("Failed to create writer for {}: {}", msg.topic_name, err);
                            }
                        }
                    }

                    if let Some(writer) = writers.get(&msg.topic_name) {
                        if let Err(err) = writer.write_raw(&msg.payload) {
                            warn!("Publish failed for {}: {}", msg.topic_name, err);
                        }
                    }
                }

                // Progress update (every second)
                let elapsed = start_time.elapsed().as_secs();
                if !args.quiet && elapsed > last_progress {
                    last_progress = elapsed;
                    let stats = player.stats();
                    info!(
                        "Played {} messages ({:.1}%)",
                        stats.messages_played,
                        (stats.messages_played as f64 / player.total_messages() as f64) * 100.0
                    );
                }
            }
            Ok(None) => {
                // Playback complete
                break;
            }
            Err(e) => {
                warn!("Playback error: {}", e);
                break;
            }
        }
    }

    // Final stats
    let stats = player.stats();

    if !args.quiet {
        info!("Playback complete");
        info!("  Messages played: {}", stats.messages_played);
        info!("  Messages skipped: {}", stats.messages_skipped);
        info!("  Duration: {:.1}s", stats.duration_secs);
        info!("  Throughput: {:.1} msg/s", stats.messages_per_second);
        if stats.loops_completed > 0 {
            info!("  Loops completed: {}", stats.loops_completed);
        }
    }

    Ok(())
}

fn format_speed(speed: PlaybackSpeed) -> String {
    match speed {
        PlaybackSpeed::Realtime => "1.0x (realtime)".to_string(),
        PlaybackSpeed::Speed(s) => format!("{:.1}x", s),
        PlaybackSpeed::Unlimited => "unlimited".to_string(),
    }
}

fn qos_map_from_metadata(
    metadata: Option<&hdds_recording::RecordingMetadata>,
) -> HashMap<String, QoS> {
    let mut map = HashMap::new();

    if let Some(metadata) = metadata {
        for topic in &metadata.topics {
            map.insert(
                topic.name.clone(),
                qos_from_strings(&topic.reliability, &topic.durability),
            );
        }
    }

    map
}

fn qos_from_strings(reliability: &str, durability: &str) -> QoS {
    let mut qos = if reliability.eq_ignore_ascii_case("reliable") {
        QoS::reliable()
    } else {
        QoS::best_effort()
    };

    qos.durability = if durability.eq_ignore_ascii_case("transient_local")
        || durability.eq_ignore_ascii_case("transient")
        || durability.eq_ignore_ascii_case("persistent")
    {
        HddsDurability::TransientLocal
    } else {
        HddsDurability::Volatile
    };

    qos
}

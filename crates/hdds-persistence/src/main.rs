// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Persistence Service CLI
//!
//! Provides TRANSIENT/PERSISTENT durability for DDS topics.
//!
//! # Usage
//!
//! ```bash
//! # Run with default settings (HDDS DDS integration)
//! hdds-persistence --db hdds_persist.db
//!
//! # Filter specific topics
//! hdds-persistence --topics "State/*" --retention-count 1000
//!
//! # Specify DDS domain
//! hdds-persistence --domain 0 --topics "*"
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use hdds::{Participant, TransportMode};
use hdds_persistence::{
    Config, DurabilitySubscriber, HddsDdsInterface, LateJoinerPublisher, MockDdsInterface,
    PersistenceService, SqliteStore,
};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(ValueEnum, Debug, Clone, Copy)]
enum ServiceMode {
    All,
    Subscriber,
    Publisher,
}

#[derive(Parser, Debug)]
#[command(name = "hdds-persistence")]
#[command(about = "HDDS Persistence Service - TRANSIENT/PERSISTENT durability", long_about = None)]
struct Args {
    /// Database path (SQLite file)
    #[arg(short, long, default_value = "hdds_persist.db")]
    db: String,

    /// Topic filter (supports wildcards: "State/*", "*")
    #[arg(short, long, default_value = "*")]
    topics: String,

    /// Retention count (max samples per topic)
    #[arg(short, long, default_value_t = 10000)]
    retention_count: usize,

    /// Retention time in seconds (0 = infinite)
    #[arg(long, default_value_t = 0)]
    retention_time: u64,

    /// Retention size in bytes (0 = infinite)
    #[arg(long, default_value_t = 0)]
    retention_size: u64,

    /// Domain ID
    #[arg(long, default_value_t = 0)]
    domain: u32,

    /// Participant name
    #[arg(short, long, default_value = "PersistenceService")]
    name: String,

    /// Use mock DDS interface (for testing without real DDS)
    #[arg(long)]
    mock: bool,

    /// Service mode: all, subscriber, or publisher
    #[arg(long, value_enum, default_value_t = ServiceMode::All)]
    mode: ServiceMode,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Replay stored samples for a topic
    Replay {
        /// Topic to replay
        topic: String,
    },
    /// Show statistics
    Stats,
    /// Clear all stored samples
    Clear {
        /// Confirm deletion
        #[arg(long)]
        confirm: bool,
    },
    /// List stored topics
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args = Args::parse();

    // Create SQLite store
    let store = SqliteStore::new(&args.db)?;

    // Handle subcommands
    if let Some(cmd) = args.command {
        return handle_command(cmd, store).await;
    }

    tracing::info!("HDDS Persistence Service starting...");
    tracing::info!("  Database: {}", args.db);
    tracing::info!("  Topics: {}", args.topics);
    tracing::info!("  Retention: {} samples", args.retention_count);
    if args.retention_size > 0 {
        tracing::info!("  Retention size: {} bytes", args.retention_size);
    }
    tracing::info!("  Domain: {}", args.domain);

    // Create configuration
    let config = Config::builder()
        .topic_filter(&args.topics)
        .retention_count(args.retention_count)
        .retention_time_secs(args.retention_time)
        .retention_size_bytes(args.retention_size)
        .domain_id(args.domain)
        .participant_name(&args.name)
        .build();

    if args.mock {
        // Run with mock DDS interface (for testing)
        tracing::info!("Running with mock DDS interface");
        let dds = MockDdsInterface::new();
        run_service(args.mode, config, store, dds).await?;
    } else {
        tracing::info!("Running with HDDS DDS integration");

        let participant = Participant::builder(&args.name)
            .with_transport(TransportMode::UdpMulticast)
            .domain_id(args.domain)
            .build()?;

        let dds = HddsDdsInterface::new(participant)?;
        run_service(args.mode, config, store, dds).await?;
    }

    Ok(())
}

async fn run_service<D>(mode: ServiceMode, config: Config, store: SqliteStore, dds: D) -> Result<()>
where
    D: hdds_persistence::DdsInterface + 'static,
{
    match mode {
        ServiceMode::All => {
            let service = PersistenceService::new(config, store, dds);
            service.run().await
        }
        ServiceMode::Subscriber => {
            let store = Arc::new(RwLock::new(store));
            let dds = Arc::new(dds);
            let subscriber = DurabilitySubscriber::new(config, store, dds);
            subscriber.run().await
        }
        ServiceMode::Publisher => {
            let store = Arc::new(RwLock::new(store));
            let dds = Arc::new(dds);
            let publisher = LateJoinerPublisher::new(config, store, dds);
            publisher.run().await
        }
    }
}

async fn handle_command(cmd: Commands, store: SqliteStore) -> Result<()> {
    use hdds_persistence::PersistenceStore;

    match cmd {
        Commands::Replay { topic } => {
            let samples = store.load(&topic)?;
            println!("Replaying {} samples for topic '{}':", samples.len(), topic);
            for sample in &samples {
                println!(
                    "  seq={}, ts={}, size={} bytes",
                    sample.sequence,
                    sample.timestamp_ns,
                    sample.payload.len()
                );
            }
        }
        Commands::Stats => {
            let count = store.count()?;
            println!("Total samples stored: {}", count);
        }
        Commands::Clear { confirm } => {
            if confirm {
                store.clear()?;
                println!("All samples cleared.");
            } else {
                println!("Use --confirm to actually delete samples.");
            }
        }
        Commands::List => {
            let samples = store.query_range("*", 0, u64::MAX)?;
            let topics: std::collections::HashSet<_> =
                samples.iter().map(|s| s.topic.clone()).collect();

            println!("Stored topics:");
            for topic in &topics {
                let count = store.load(topic)?.len();
                println!("  {} ({} samples)", topic, count);
            }
        }
    }

    Ok(())
}

// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Routing Service CLI
//!
//! Command-line tool for routing DDS messages between domains.
//!
//! # Usage
//!
//! ```bash
//! # Simple domain bridge
//! hdds-router --from-domain 0 --to-domain 1
//!
//! # Bidirectional bridge
//! hdds-router --from-domain 0 --to-domain 1 --bidirectional
//!
//! # With topic remapping
//! hdds-router --from-domain 0 --to-domain 1 --remap "Sensor/*:Vehicle/*"
//!
//! # Using configuration file
//! hdds-router --config router.toml
//!
//! # Filter specific topics
//! hdds-router --from-domain 0 --to-domain 1 --topics Temperature,Pressure
//! ```

use clap::{Parser, Subcommand};
use hdds_router::{RouteConfig, Router, RouterConfig, RouterError, TopicRemap};
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

/// HDDS DDS Routing Service
#[derive(Parser, Debug)]
#[command(name = "hdds-router")]
#[command(about = "HDDS DDS Routing Service - Domain bridging and topic transformation")]
#[command(version)]
struct Args {
    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Source domain ID
    #[arg(long, conflicts_with = "config")]
    from_domain: Option<u32>,

    /// Destination domain ID
    #[arg(long, conflicts_with = "config")]
    to_domain: Option<u32>,

    /// Enable bidirectional routing
    #[arg(short, long)]
    bidirectional: bool,

    /// Topics to route (comma-separated, or patterns with *)
    #[arg(short, long, value_delimiter = ',')]
    topics: Option<Vec<String>>,

    /// Topic remappings (format: "from:to", can repeat)
    #[arg(short, long, value_delimiter = ',')]
    remap: Option<Vec<String>>,

    /// Exclude topics (comma-separated)
    #[arg(long, value_delimiter = ',')]
    exclude: Option<Vec<String>>,

    /// Statistics reporting interval (seconds, 0 to disable)
    #[arg(long, default_value = "10")]
    stats_interval: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate example configuration file
    GenConfig {
        /// Output file path
        #[arg(short, long, default_value = "router.toml")]
        output: PathBuf,
    },

    /// Validate a configuration file
    Validate {
        /// Configuration file path
        #[arg(short, long)]
        config: PathBuf,
    },

    /// Show routing status (requires running router)
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Handle subcommands
    if let Some(cmd) = args.command {
        return match cmd {
            Commands::GenConfig { output } => cmd_gen_config(output),
            Commands::Validate { config } => cmd_validate(config),
            Commands::Status => cmd_status().await,
        };
    }

    // Build configuration
    let config = build_config(&args)?;

    // Create and run router
    let mut router = Router::new(config)?;

    println!("HDDS Routing Service v{}", env!("CARGO_PKG_VERSION"));
    println!("=====================================");
    println!();

    for route in router.routes() {
        println!(
            "Route: Domain {} -> Domain {}",
            route.from_domain, route.to_domain
        );
    }
    println!();
    println!("Press Ctrl+C to stop...");
    println!();

    let handle = router.run().await?;

    // Stats reporting task
    let stats_interval = args.stats_interval;
    let stats_handle = handle.clone();
    if stats_interval > 0 {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(stats_interval));
            loop {
                interval.tick().await;
                if !stats_handle.is_running() {
                    break;
                }
                if let Ok(stats) = stats_handle.get_stats().await {
                    print_stats(&stats);
                }
            }
        });
    }

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");
    handle.stop();

    // Print final stats
    if let Ok(stats) = handle.get_stats().await {
        println!("\nFinal Statistics:");
        print_stats(&stats);
    }

    Ok(())
}

fn build_config(args: &Args) -> Result<RouterConfig, RouterError> {
    // Load from file if specified
    if let Some(ref config_path) = args.config {
        return RouterConfig::from_file(config_path).map_err(RouterError::Config);
    }

    // Build from command line arguments
    let from_domain = args.from_domain.ok_or_else(|| {
        RouterError::Config(crate::config::ConfigError::Invalid(
            "Missing --from-domain (or use --config)".into(),
        ))
    })?;

    let to_domain = args.to_domain.ok_or_else(|| {
        RouterError::Config(crate::config::ConfigError::Invalid(
            "Missing --to-domain (or use --config)".into(),
        ))
    })?;

    // Build topic selection
    let topics = if let Some(ref topics) = args.topics {
        hdds_router::config::TopicSelection::Include(topics.clone())
    } else if let Some(ref exclude) = args.exclude {
        hdds_router::config::TopicSelection::Exclude(exclude.clone())
    } else {
        hdds_router::config::TopicSelection::All
    };

    // Parse remaps
    let remaps: Vec<TopicRemap> = args
        .remap
        .as_ref()
        .map(|remaps| {
            remaps
                .iter()
                .filter_map(|s| {
                    let parts: Vec<&str> = s.splitn(2, ':').collect();
                    if parts.len() == 2 {
                        Some(TopicRemap::new(parts[0], parts[1]))
                    } else {
                        tracing::warn!("Invalid remap format: {} (expected from:to)", s);
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let route_config = RouteConfig {
        from_domain,
        to_domain,
        bidirectional: args.bidirectional,
        topics,
        remaps,
        qos_transform: None,
    };

    let mut config = RouterConfig::default();
    config.add_route(route_config);
    config.stats_interval_secs = args.stats_interval;
    config.log_level = args.log_level.clone();

    Ok(config)
}

fn cmd_gen_config(output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = RouterConfig {
        name: "example-router".into(),
        routes: vec![
            RouteConfig {
                from_domain: 0,
                to_domain: 1,
                bidirectional: false,
                topics: hdds_router::config::TopicSelection::Include(vec![
                    "Temperature".into(),
                    "Pressure".into(),
                ]),
                remaps: vec![
                    TopicRemap::new("Temperature", "Vehicle/Engine/Temperature"),
                    TopicRemap::new("Sensor/*", "Vehicle/*"),
                ],
                qos_transform: Some(hdds_router::config::QosTransformConfig {
                    reliability: Some("reliable".into()),
                    durability: Some("transient_local".into()),
                    history_depth: Some(10),
                    deadline_us: None,
                    lifespan_us: None,
                }),
            },
            RouteConfig {
                from_domain: 2,
                to_domain: 3,
                bidirectional: true,
                topics: hdds_router::config::TopicSelection::Exclude(vec!["Internal/*".into()]),
                remaps: Vec::new(),
                qos_transform: None,
            },
        ],
        enable_stats: true,
        stats_interval_secs: 10,
        log_level: "info".into(),
    };

    let toml_str = toml::to_string_pretty(&config)?;

    // Add comments
    let content = format!(
        r#"# HDDS Router Configuration
# Generated by hdds-router gen-config

{}
"#,
        toml_str
    );

    std::fs::write(&output, content)?;
    println!("Generated configuration file: {}", output.display());
    Ok(())
}

fn cmd_validate(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    match RouterConfig::from_file(&config_path) {
        Ok(config) => {
            println!("Configuration valid!");
            println!();
            println!("Router: {}", config.name);
            println!("Routes: {}", config.routes.len());
            for (i, route) in config.routes.iter().enumerate() {
                println!(
                    "  [{}] Domain {} -> Domain {} {}",
                    i,
                    route.from_domain,
                    route.to_domain,
                    if route.bidirectional {
                        "(bidirectional)"
                    } else {
                        ""
                    }
                );
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Configuration invalid: {}", e);
            std::process::exit(1);
        }
    }
}

async fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("hdds-router status");
    eprintln!("-------------------");
    eprintln!("The `status` command requires a running router with admin interface.");
    eprintln!();
    eprintln!("This feature is planned for a future release.");
    eprintln!("It will connect to the router's admin socket to report:");
    eprintln!("  - Active routes and throughput");
    eprintln!("  - Connected domains and participants");
    eprintln!("  - Error counts and dropped messages");
    eprintln!();
    eprintln!("Workaround: use `hdds-admin` or `hddsctl` for live monitoring.");
    Ok(())
}

fn print_stats(stats: &[hdds_router::RouteStatsSnapshot]) {
    println!("--- Route Statistics ---");
    for stat in stats {
        println!(
            "  Domain {} -> {}: {} msgs ({:.1} msg/s), {} bytes, {} dropped, {} errors",
            stat.from_domain,
            stat.to_domain,
            stat.messages_routed,
            stat.messages_per_second(),
            format_bytes(stat.bytes_routed),
            stat.messages_dropped,
            stat.errors
        );
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// Re-export config module for main
mod config {
    pub use hdds_router::config::*;
}

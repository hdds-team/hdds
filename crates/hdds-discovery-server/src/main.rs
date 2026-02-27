// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Discovery Server
//!
//! Standalone discovery server for DDS environments where multicast is unavailable:
//! - Cloud/Kubernetes deployments
//! - Corporate networks with multicast disabled
//! - NAT traversal scenarios
//! - WAN deployments
//!
//! # Usage
//!
//! ```bash
//! # Start server on default port (7400)
//! hdds-discovery-server
//!
//! # Custom port and config
//! hdds-discovery-server --port 7410 --config server.json
//!
//! # Enable relay mode for NAT traversal
//! hdds-discovery-server --port 7400 --relay
//! ```

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod server;

pub use config::ServerConfig;
pub use server::DiscoveryServer;

/// HDDS Discovery Server - Centralized discovery for DDS in cloud environments
#[derive(Parser, Debug)]
#[command(name = "hdds-discovery-server")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// TCP port to listen on
    #[arg(short, long, default_value = "7400")]
    port: u16,

    /// Bind address (0.0.0.0 for all interfaces)
    #[arg(short, long, default_value = "0.0.0.0")]
    bind: String,

    /// Configuration file (JSON format)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable relay mode (forward DATA between participants)
    #[arg(long, default_value = "false")]
    relay: bool,

    /// Participant lease duration in seconds
    #[arg(long, default_value = "30")]
    lease_duration: u64,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Domain ID to serve (0 = all domains)
    #[arg(short, long, default_value = "0")]
    domain: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    let level = match args.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(true)
        .with_thread_ids(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Load or create config
    let config = if let Some(config_path) = args.config {
        info!("Loading config from {:?}", config_path);
        ServerConfig::from_file(&config_path)?
    } else {
        ServerConfig {
            bind_address: args.bind.parse()?,
            port: args.port,
            domain_id: args.domain,
            lease_duration_secs: args.lease_duration,
            relay_enabled: args.relay,
            ..Default::default()
        }
    };

    let addr: SocketAddr = format!("{}:{}", config.bind_address, config.port).parse()?;

    info!("+----------------------------------------------------+");
    info!(
        "|       HDDS Discovery Server v{}              |",
        env!("CARGO_PKG_VERSION")
    );
    info!("+----------------------------------------------------+");
    info!("|  Bind:   {:40} |", addr);
    info!(
        "|  Domain: {:40} |",
        if config.domain_id == 0 {
            "all".to_string()
        } else {
            config.domain_id.to_string()
        }
    );
    info!(
        "|  Relay:  {:40} |",
        if config.relay_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        "|  Lease:  {:40} |",
        format!("{}s", config.lease_duration_secs)
    );
    info!("+----------------------------------------------------+");

    // Create and run server
    let server = DiscoveryServer::new(config).await?;

    // Handle shutdown signals
    let server_handle = server.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received, stopping server...");
        server_handle.shutdown().await;
    });

    // Run server
    server.run().await?;

    info!("Discovery server stopped");
    Ok(())
}

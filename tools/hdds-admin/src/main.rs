// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! HDDS Administration CLI
//!
//! Command-line tool for monitoring and managing HDDS systems.
//!
//! # Usage
//!
//! ```bash
//! # Show health status
//! hdds-admin health
//!
//! # List participants
//! hdds-admin mesh
//!
//! # Show metrics
//! hdds-admin metrics
//!
//! # Watch mode (continuous updates)
//! hdds-admin watch --interval 1
//! ```

use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::Deserialize;
use std::time::Duration;
use tabled::{Table, Tabled};

/// HDDS Administration CLI
#[derive(Parser, Debug)]
#[command(name = "hdds-admin")]
#[command(about = "HDDS Administration CLI")]
#[command(version)]
struct Args {
    /// Gateway URL
    #[arg(short, long, default_value = "http://127.0.0.1:8080")]
    gateway: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show system health
    Health,

    /// List discovered participants
    Mesh,

    /// Show active topics
    Topics,

    /// Show runtime metrics
    Metrics,

    /// Show gateway info
    Info,

    /// Watch mode (continuous updates)
    Watch {
        /// Update interval in seconds
        #[arg(short, long, default_value = "1")]
        interval: u64,
    },

    /// Show all information (health + mesh + metrics)
    Status,
}

// Response types
#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    uptime_secs: Option<u64>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MeshResponse {
    epoch: u64,
    participants: Vec<Participant>,
}

#[derive(Debug, Deserialize)]
struct Participant {
    guid: String,
    name: String,
    is_local: bool,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TopicsResponse {
    topics: Vec<Topic>,
}

#[derive(Debug, Deserialize)]
struct Topic {
    name: String,
    #[serde(default)]
    type_name: String,
    #[serde(default)]
    writers_count: usize,
    #[serde(default)]
    readers_count: usize,
}

#[derive(Debug, Deserialize)]
struct MetricsResponse {
    epoch: u64,
    messages_sent: u64,
    messages_received: u64,
    messages_dropped: u64,
    latency_p50_ns: u64,
    latency_p99_ns: u64,
}

#[derive(Debug, Deserialize)]
struct InfoResponse {
    name: String,
    version: String,
    api_version: String,
    endpoints: Vec<String>,
}

fn main() {
    let args = Args::parse();

    let result = match args.command {
        Commands::Health => cmd_health(&args.gateway),
        Commands::Mesh => cmd_mesh(&args.gateway),
        Commands::Topics => cmd_topics(&args.gateway),
        Commands::Metrics => cmd_metrics(&args.gateway),
        Commands::Info => cmd_info(&args.gateway),
        Commands::Watch { interval } => cmd_watch(&args.gateway, interval),
        Commands::Status => cmd_status(&args.gateway),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "Error:".red().bold(), e);
        std::process::exit(1);
    }
}

fn cmd_health(gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/health", gateway);
    let resp: HealthResponse = reqwest::blocking::get(&url)?.json()?;

    let status_colored = if resp.status == "ok" {
        resp.status.green().bold()
    } else {
        resp.status.red().bold()
    };

    println!("{}", "HDDS Health Status".cyan().bold());
    println!("  Status:  {}", status_colored);

    if let Some(uptime) = resp.uptime_secs {
        println!("  Uptime:  {}", format_duration(uptime));
    }

    if let Some(version) = resp.version {
        println!("  Version: {}", version);
    }

    Ok(())
}

fn cmd_mesh(gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/mesh", gateway);
    let resp: MeshResponse = reqwest::blocking::get(&url)?.json()?;

    println!("{}", "Participant Mesh".cyan().bold());
    println!("  Epoch: {}", resp.epoch);
    println!("  Count: {}", resp.participants.len());
    println!();

    if resp.participants.is_empty() {
        println!("  {}", "No participants discovered".yellow());
    } else {
        // Build table
        let rows: Vec<ParticipantRow> = resp
            .participants
            .iter()
            .map(|p| ParticipantRow {
                guid: truncate_guid(&p.guid),
                name: if p.name.is_empty() {
                    "-".to_string()
                } else {
                    p.name.clone()
                },
                local: if p.is_local { "yes" } else { "no" }.to_string(),
                state: p.state.clone().unwrap_or_else(|| "-".to_string()),
            })
            .collect();

        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    Ok(())
}

#[derive(Tabled)]
struct ParticipantRow {
    #[tabled(rename = "GUID")]
    guid: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Local")]
    local: String,
    #[tabled(rename = "State")]
    state: String,
}

#[derive(Tabled)]
struct TopicRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Type")]
    type_name: String,
    #[tabled(rename = "Writers")]
    writers: usize,
    #[tabled(rename = "Readers")]
    readers: usize,
}

fn cmd_topics(gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/topics", gateway);
    let resp: TopicsResponse = reqwest::blocking::get(&url)?.json()?;

    println!("{}", "Active Topics".cyan().bold());
    println!("  Count: {}", resp.topics.len());
    println!();

    if resp.topics.is_empty() {
        println!("  {}", "No active topics".yellow());
    } else {
        // Build table manually
        let rows: Vec<TopicRow> = resp
            .topics
            .iter()
            .map(|t| TopicRow {
                name: t.name.clone(),
                type_name: t.type_name.clone(),
                writers: t.writers_count,
                readers: t.readers_count,
            })
            .collect();
        let table = Table::new(rows).to_string();
        println!("{}", table);
    }

    Ok(())
}

fn cmd_metrics(gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/metrics", gateway);
    let resp: MetricsResponse = reqwest::blocking::get(&url)?.json()?;

    println!("{}", "Runtime Metrics".cyan().bold());
    println!("  Epoch: {}", resp.epoch);
    println!();
    println!("  {}", "Messages".bold());
    println!("    Sent:     {}", format_count(resp.messages_sent));
    println!("    Received: {}", format_count(resp.messages_received));
    println!(
        "    Dropped:  {}",
        if resp.messages_dropped > 0 {
            format_count(resp.messages_dropped).red().to_string()
        } else {
            format_count(resp.messages_dropped)
        }
    );
    println!();
    println!("  {}", "Latency".bold());
    println!("    p50: {}", format_ns(resp.latency_p50_ns));
    println!("    p99: {}", format_ns(resp.latency_p99_ns));

    Ok(())
}

fn cmd_info(gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/info", gateway);
    let resp: InfoResponse = reqwest::blocking::get(&url)?.json()?;

    println!("{}", "Gateway Info".cyan().bold());
    println!("  Name:        {}", resp.name);
    println!("  Version:     {}", resp.version);
    println!("  API Version: {}", resp.api_version);
    println!();
    println!("  {}", "Endpoints:".bold());
    for endpoint in &resp.endpoints {
        println!("    {}", endpoint);
    }

    Ok(())
}

fn cmd_watch(gateway: &str, interval: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "{} (interval: {}s, Ctrl+C to stop)",
        "Watch Mode".cyan().bold(),
        interval
    );
    println!();

    loop {
        // Clear screen
        print!("\x1B[2J\x1B[1;1H");

        println!(
            "{} - {}",
            "HDDS Admin Watch".cyan().bold(),
            chrono::Local::now().format("%H:%M:%S")
        );
        println!("{}", "=".repeat(50));

        // Health
        if let Ok(health) = fetch_health(gateway) {
            let status = if health.status == "ok" {
                health.status.green()
            } else {
                health.status.red()
            };
            println!(
                "Health: {} | Uptime: {}",
                status,
                format_duration(health.uptime_secs.unwrap_or(0))
            );
        }

        // Mesh
        if let Ok(mesh) = fetch_mesh(gateway) {
            println!(
                "Mesh: {} participants (epoch {})",
                mesh.participants.len(),
                mesh.epoch
            );
        }

        // Metrics
        if let Ok(metrics) = fetch_metrics(gateway) {
            println!(
                "Messages: {} sent, {} recv, {} dropped",
                format_count(metrics.messages_sent),
                format_count(metrics.messages_received),
                format_count(metrics.messages_dropped)
            );
            println!(
                "Latency: p50={}, p99={}",
                format_ns(metrics.latency_p50_ns),
                format_ns(metrics.latency_p99_ns)
            );
        }

        std::thread::sleep(Duration::from_secs(interval));
    }
}

fn cmd_status(gateway: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "HDDS System Status".cyan().bold());
    println!("{}", "=".repeat(50));
    println!();

    // Health
    cmd_health(gateway)?;
    println!();

    // Mesh
    cmd_mesh(gateway)?;
    println!();

    // Metrics
    cmd_metrics(gateway)?;

    Ok(())
}

// Helper functions
fn fetch_health(gateway: &str) -> Result<HealthResponse, Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/health", gateway);
    Ok(reqwest::blocking::get(&url)?.json()?)
}

fn fetch_mesh(gateway: &str) -> Result<MeshResponse, Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/mesh", gateway);
    Ok(reqwest::blocking::get(&url)?.json()?)
}

fn fetch_metrics(gateway: &str) -> Result<MetricsResponse, Box<dyn std::error::Error>> {
    let url = format!("{}/api/v1/metrics", gateway);
    Ok(reqwest::blocking::get(&url)?.json()?)
}

fn format_count(count: u64) -> String {
    if count < 1_000 {
        count.to_string()
    } else if count < 1_000_000 {
        format!("{:.1}K", count as f64 / 1_000.0)
    } else if count < 1_000_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else {
        format!("{:.1}B", count as f64 / 1_000_000_000.0)
    }
}

fn format_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{} ns", ns)
    } else if ns < 1_000_000 {
        format!("{:.1} us", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.1} ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.1} s", ns as f64 / 1_000_000_000.0)
    }
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn truncate_guid(guid: &str) -> String {
    if guid.len() > 20 {
        format!("{}...", &guid[..17])
    } else {
        guid.to_string()
    }
}

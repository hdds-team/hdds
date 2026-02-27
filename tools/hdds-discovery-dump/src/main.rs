// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-discovery-dump - Dump live DDS discovery state
//!
//! Shows discovered participants, readers, and writers in real-time.

use clap::Parser;
use colored::*;
use hdds::core::discovery::multicast::fsm::EndpointInfo;
use hdds::core::discovery::multicast::ParticipantInfo;
use hdds::core::discovery::GUID;
use hdds::Participant;
use std::collections::HashMap;

type TopicEndpoints = (Vec<EndpointInfo>, Vec<EndpointInfo>);
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Dump live DDS discovery state
#[derive(Parser, Debug)]
#[command(name = "hdds-discovery-dump")]
#[command(version = "0.1.0")]
#[command(about = "Dump DDS discovery state (participants, readers, writers)")]
struct Args {
    /// DDS domain ID
    #[arg(short, long, default_value = "0")]
    domain: u32,

    /// Discovery duration in seconds (0 = one-shot dump)
    #[arg(long, default_value = "5")]
    timeout: u64,

    /// Output format: pretty, json
    #[arg(short, long, default_value = "pretty")]
    format: OutputFormat,

    /// Continuous monitoring mode (refresh every N seconds)
    #[arg(short = 'w', long)]
    watch: Option<u64>,

    /// Only show specific topic
    #[arg(short = 't', long)]
    topic: Option<String>,

    /// Quiet mode - compact output
    #[arg(long)]
    quiet: bool,
}

#[derive(Clone, Debug)]
enum OutputFormat {
    Pretty,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" | "p" => Ok(OutputFormat::Pretty),
            "json" | "j" => Ok(OutputFormat::Json),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(&args) {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    if !args.quiet {
        eprintln!(
            "{} Discovery dump (domain={})",
            ">>>".green().bold(),
            args.domain
        );
    }

    // Create participant with UDP discovery
    let participant = Participant::builder("hdds-discovery-dump")
        .domain_id(args.domain)
        .build()?;
    let participant = Arc::new(participant);

    // Wait for discovery
    if !args.quiet && args.timeout > 0 {
        eprintln!(
            "{}",
            format!("    Discovering for {} seconds...", args.timeout).dimmed()
        );
    }

    if let Some(watch_interval) = args.watch {
        // Continuous watch mode
        let interval = Duration::from_secs(watch_interval.max(1));
        while running.load(Ordering::SeqCst) {
            print!("\x1B[2J\x1B[1;1H"); // Clear screen
            dump_discovery_state(&participant, args)?;
            std::thread::sleep(interval);
        }
    } else {
        // One-shot mode with timeout
        if args.timeout > 0 {
            std::thread::sleep(Duration::from_secs(args.timeout));
        }
        dump_discovery_state(&participant, args)?;
    }

    Ok(())
}

fn dump_discovery_state(
    participant: &Arc<Participant>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let discovery = match participant.discovery() {
        Some(d) => d,
        None => {
            if !args.quiet {
                eprintln!(
                    "{}",
                    "Discovery not available (intra-process mode?)".yellow()
                );
            }
            return Ok(());
        }
    };

    // Get discovered participants
    let participants = discovery.get_participants();

    // Get all topics with their endpoints
    let all_topics = discovery.get_all_topics();

    match args.format {
        OutputFormat::Pretty => {
            print_pretty(&participants, &all_topics, args)?;
        }
        OutputFormat::Json => {
            print_json(&participants, &all_topics, args)?;
        }
    }

    Ok(())
}

fn print_pretty(
    participants: &[ParticipantInfo],
    all_topics: &HashMap<String, (Vec<EndpointInfo>, Vec<EndpointInfo>)>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("{}", "=== DDS Discovery State ===".bold());
    println!();

    // Participants
    println!(
        "{} {} participant(s) discovered",
        "Participants:".cyan().bold(),
        participants.len()
    );
    println!();

    for (i, p) in participants.iter().enumerate() {
        let guid_str = format_guid(&p.guid);
        let state_str = format!("{:?}", p.state);
        let endpoints_str: Vec<String> = p.endpoints.iter().map(|e| e.to_string()).collect();

        if args.quiet {
            println!(
                "  [{}] {} ({}) {}",
                i + 1,
                guid_str,
                state_str,
                endpoints_str.join(", ")
            );
        } else {
            println!("  {} {}", format!("[{}]", i + 1).yellow(), guid_str.green());
            println!("      State: {}", state_str.white());
            println!("      Endpoints: {}", endpoints_str.join(", "));
            println!(
                "      Lease: {}ms (expires in {}ms)",
                p.lease_duration_ms,
                p.lease_duration_ms
                    .saturating_sub(p.last_seen.elapsed().as_millis() as u64)
            );
            println!();
        }
    }

    // Filter topics if requested
    let filtered_topics: Vec<(&String, &TopicEndpoints)> = if let Some(ref filter) = args.topic {
        all_topics
            .iter()
            .filter(|(name, _)| name.contains(filter))
            .collect()
    } else {
        all_topics.iter().collect()
    };

    println!(
        "{} {} topic(s)",
        "Topics:".cyan().bold(),
        filtered_topics.len()
    );
    println!();

    for (topic_name, (writers, readers)) in &filtered_topics {
        if args.quiet {
            println!(
                "  {} ({}W/{}R)",
                topic_name.cyan(),
                writers.len(),
                readers.len()
            );
        } else {
            println!("  {} {}", "Topic:".white(), topic_name.cyan().bold());
            println!(
                "      Writers: {}  Readers: {}",
                writers.len().to_string().green(),
                readers.len().to_string().blue()
            );

            // Show writer details
            for w in writers.iter() {
                println!(
                    "        {} {} (type: {})",
                    "W".green(),
                    format_guid(&w.endpoint_guid),
                    w.type_name.dimmed()
                );
            }

            // Show reader details
            for r in readers.iter() {
                println!(
                    "        {} {} (type: {})",
                    "R".blue(),
                    format_guid(&r.endpoint_guid),
                    r.type_name.dimmed()
                );
            }
            println!();
        }
    }

    // Summary
    let total_writers: usize = all_topics.values().map(|(w, _)| w.len()).sum();
    let total_readers: usize = all_topics.values().map(|(_, r)| r.len()).sum();

    println!("{}", "--- Summary ---".dimmed());
    println!(
        "  Participants: {}  Topics: {}  Writers: {}  Readers: {}",
        participants.len().to_string().white(),
        all_topics.len().to_string().white(),
        total_writers.to_string().green(),
        total_readers.to_string().blue()
    );
    println!();

    Ok(())
}

fn print_json(
    participants: &[ParticipantInfo],
    all_topics: &HashMap<String, (Vec<EndpointInfo>, Vec<EndpointInfo>)>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    // Filter topics if requested
    let filtered_topics: Vec<(&String, &TopicEndpoints)> = if let Some(ref filter) = args.topic {
        all_topics
            .iter()
            .filter(|(name, _)| name.contains(filter))
            .collect()
    } else {
        all_topics.iter().collect()
    };

    print!("{{");
    print!("\"domain\":{},", args.domain);

    // Participants
    print!("\"participants\":[");
    for (i, p) in participants.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!(
            "{{\"guid\":\"{}\",\"state\":\"{:?}\",\"endpoints\":[{}],\"lease_ms\":{}}}",
            format_guid(&p.guid),
            p.state,
            p.endpoints
                .iter()
                .map(|e| format!("\"{}\"", e))
                .collect::<Vec<_>>()
                .join(","),
            p.lease_duration_ms
        );
    }
    print!("],");

    // Topics
    print!("\"topics\":[");
    for (i, (topic_name, (writers, readers))) in filtered_topics.iter().enumerate() {
        if i > 0 {
            print!(",");
        }

        print!("{{\"name\":\"{}\",", topic_name);
        print!("\"writers\":[");
        for (j, w) in writers.iter().enumerate() {
            if j > 0 {
                print!(",");
            }
            print!(
                "{{\"guid\":\"{}\",\"type\":\"{}\"}}",
                format_guid(&w.endpoint_guid),
                w.type_name
            );
        }
        print!("],\"readers\":[");
        for (j, r) in readers.iter().enumerate() {
            if j > 0 {
                print!(",");
            }
            print!(
                "{{\"guid\":\"{}\",\"type\":\"{}\"}}",
                format_guid(&r.endpoint_guid),
                r.type_name
            );
        }
        print!("]}}");
    }
    print!("]");

    println!("}}");

    Ok(())
}

fn format_guid(guid: &GUID) -> String {
    let bytes = guid.as_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}.{:02x}{:02x}{:02x}{:02x}.{:02x}{:02x}{:02x}{:02x}.{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

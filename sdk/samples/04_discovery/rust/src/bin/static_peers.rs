// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! # HDDS Sample: Static Peers Discovery
//!
//! Demonstrates **static peer configuration** - manual discovery for environments
//! where multicast is unavailable (cloud, containers, VPNs).
//!
//! ## Multicast vs Static Peers
//!
//! ```text
//! Multicast Discovery:              Static Peers:
//! ┌─────────────────────────┐      ┌─────────────────────────┐
//! │   Multicast Group       │      │   No multicast needed   │
//! │   239.255.0.1:7400      │      │                         │
//! │                         │      │   A ───────► B          │
//! │   A ◄────► B ◄────► C   │      │     ◄───────            │
//! │     Auto-discover all   │      │   Explicit connections  │
//! └─────────────────────────┘      └─────────────────────────┘
//! ```
//!
//! ## When to Use Static Peers
//!
//! | Environment       | Multicast? | Solution           |
//! |-------------------|------------|--------------------|
//! | Local network     | Usually    | SPDP multicast     |
//! | Docker containers | Rarely     | Static peers       |
//! | Kubernetes        | No         | Static peers + TCP |
//! | AWS/GCP/Azure     | No         | Static peers + TCP |
//! | VPN tunnels       | Varies     | Static peers safer |
//!
//! ## Configuration
//!
//! ```text
//! Terminal 1 (Server):              Terminal 2 (Client):
//! ┌───────────────────────┐        ┌───────────────────────┐
//! │ --listen 7400         │        │ --peer 127.0.0.1:7400 │
//! │                       │◄──────►│                       │
//! │ Waits for connections │        │ Connects to server    │
//! └───────────────────────┘        └───────────────────────┘
//! ```
//!
//! ## TCP Mode
//!
//! For cloud deployments, TCP is often more reliable:
//! ```bash
//! cargo run --bin static_peers -- --tcp --peer 192.168.1.100:7400
//! ```
//!
//! ## Running the Sample
//!
//! ```bash
//! # Terminal 1 - Listen on port 7400
//! cargo run --bin static_peers -- --listen 7400
//!
//! # Terminal 2 - Connect to Terminal 1
//! cargo run --bin static_peers -- --peer 127.0.0.1:7400
//!
//! # With TCP (for cloud/container environments)
//! cargo run --bin static_peers -- --tcp --listen 7400
//! cargo run --bin static_peers -- --tcp --peer 127.0.0.1:7400
//! ```

use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

fn print_usage(prog: &str) {
    println!("Usage: {} [OPTIONS]", prog);
    println!();
    println!("Options:");
    println!("  -l, --listen PORT   Listen on specified port");
    println!("  -p, --peer ADDR     Add static peer (host:port)");
    println!("  --tcp               Use TCP transport instead of UDP");
    println!("  -h, --help          Show this help");
    println!();
    println!("Examples:");
    println!("  Terminal 1: {} --listen 7400", prog);
    println!("  Terminal 2: {} --peer 127.0.0.1:7400", prog);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HDDS Static Peers Discovery Sample ===\n");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mut listen_port: Option<u16> = None;
    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut use_tcp = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" | "-l" => {
                i += 1;
                if i < args.len() {
                    listen_port = Some(args[i].parse()?);
                }
            }
            "--peer" | "-p" => {
                i += 1;
                if i < args.len() {
                    peers.push(args[i].parse()?);
                }
            }
            "--tcp" => {
                use_tcp = true;
            }
            "--help" | "-h" => {
                print_usage(&args[0]);
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Default configuration if nothing specified
    if listen_port.is_none() && peers.is_empty() {
        println!("No configuration specified. Using defaults:");
        println!("  Listen port: 7400");
        println!("  Static peer: 127.0.0.1:7401");
        println!();
        listen_port = Some(7400);
        peers.push("127.0.0.1:7401".parse()?);
    }

    println!("Configuration:");
    if let Some(port) = listen_port {
        println!("  Listen port: {}", port);
    }
    println!("  Transport: {}", if use_tcp { "TCP" } else { "UDP" });
    println!("  Static peers: {:?}", peers);
    println!();

    // Build participant with static peer configuration
    println!("Creating DomainParticipant with static peers...");

    let mut builder = hdds::Participant::builder("StaticPeers").domain_id(0);

    // Configure transport
    if use_tcp {
        // For TCP, use TcpConfig with initial peers
        let tcp_config = hdds::TcpConfig::tcp_only(peers.clone());
        builder = builder.tcp_config(tcp_config).tcp_only();
    } else {
        // For UDP, use add_static_peer with multicast enabled
        builder = builder.with_transport(hdds::TransportMode::UdpMulticast);
        for peer in &peers {
            builder = builder.add_static_peer(&peer.to_string());
        }
    }

    // Apply custom port if specified
    if let Some(port) = listen_port {
        builder = builder.with_discovery_ports(port, port + 10, port + 11);
    }

    let participant = builder.build()?;

    println!("[OK] Participant created: {}", participant.name());
    println!("     Transport: {}", if use_tcp { "TCP" } else { "UDP" });

    // Create writer and reader
    let writer = participant.create_raw_writer("StaticPeersDemo", None)?;
    let reader = participant.create_raw_reader("StaticPeersDemo", None)?;

    println!("[OK] Endpoints created");

    println!("\n--- Waiting for Static Peers ---");
    println!("Configured peers will be contacted directly.");
    if !use_tcp {
        println!("Multicast discovery is also active.\n");
    } else {
        println!("No multicast discovery is used.\n");
    }

    // Communication loop
    let instance_id = std::process::id();
    let mut msg_count = 0;

    loop {
        msg_count += 1;

        // Send message
        let message = format!("Static peer {} says hello #{}", instance_id, msg_count);
        match writer.write_raw(message.as_bytes()) {
            Ok(_) => println!("[SENT] {}", message),
            Err(e) => println!("[WARN] Send failed (peer may not be connected): {}", e),
        }

        // Small delay to allow data to arrive
        thread::sleep(Duration::from_millis(100));

        // Receive messages
        match reader.try_take_raw() {
            Ok(samples) => {
                for sample in samples {
                    if let Ok(data) = String::from_utf8(sample.payload) {
                        println!("[RECV] {}", data);
                    }
                }
            }
            Err(e) => {
                if !matches!(e, hdds::Error::WouldBlock) {
                    println!("[WARN] Read error: {}", e);
                }
            }
        }

        thread::sleep(Duration::from_secs(2));

        if msg_count >= 10 {
            break;
        }
    }

    // Show connection status
    println!("\n--- Connection Status ---");
    if let Some(discovery) = participant.discovery() {
        println!("Connected peers: {}", discovery.participant_count());
    }

    println!("\n=== Sample Complete ===");
    Ok(())
}

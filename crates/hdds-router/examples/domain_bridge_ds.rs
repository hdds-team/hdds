// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Realistic scenario: bridge a local multicast domain to a remote
//! domain using a Discovery Server, with topic remapping.
//!
//! Domain 0 = local LAN (UDP multicast, default)
//! Domain 1 = remote site via Discovery Server
//!
//! Topics: Sensor/* on domain 0 become Vehicle/* on domain 1.
//!
//! This example creates the Router and starts it briefly to prove
//! the full participant creation path works (including DS config).
//! It stops after a few seconds.
//!
//! Run: cargo run -p hdds-router --example domain_bridge_ds
//!
//! With a real Discovery Server:
//!   cargo run -p hdds-router --example domain_bridge_ds -- 10.0.0.100:7400

use hdds_router::{DomainConfig, RouteConfig, Router, RouterConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .init();

    let ds_addr = std::env::args().nth(1);

    println!("=== Domain Bridge with Discovery Server ===\n");

    // Build config
    let mut config = RouterConfig {
        name: "local-to-remote-bridge".into(),
        ..Default::default()
    };

    config.add_route(
        RouteConfig::new(0, 1)
            .bidirectional(true)
            .topics(hdds_router::config::TopicSelection::Pattern(
                "Sensor/*".into(),
            ))
            .remap("Sensor/*", "Vehicle/*"),
    );

    if let Some(ref addr) = ds_addr {
        println!("Domain 1 Discovery Server: {}\n", addr);
        config.set_domain_config(
            1,
            DomainConfig {
                discovery_server: Some(addr.clone()),
            },
        );
    } else {
        println!("No Discovery Server address provided.");
        println!("Domain 1 will use UDP multicast (same as domain 0).\n");
        println!("Usage: domain_bridge_ds [discovery_server:port]\n");
    }

    config.validate()?;

    // Print config summary
    println!("Configuration:");
    println!("  Router: {}", config.name);
    for route in &config.routes {
        println!(
            "  Route: domain {} -> domain {} (bidir: {})",
            route.from_domain, route.to_domain, route.bidirectional
        );
        for remap in &route.remaps {
            println!("    Remap: {} -> {}", remap.from, remap.to);
        }
    }
    for domain_id in [0u32, 1] {
        match config.discovery_server_for(domain_id) {
            Some(addr) => println!("  Domain {}: Discovery Server @ {}", domain_id, addr),
            None => println!("  Domain {}: UDP multicast", domain_id),
        }
    }
    println!();

    // Create router (validates config + builds Route objects)
    let mut router = Router::new(config)?;

    println!(
        "Router created with {} routes (including reverse for bidir)\n",
        router.routes().len()
    );

    // Start the router — this creates DDS Participants
    // For domain 1, it will use discovery_server_addr() if configured
    println!("Starting router (will run for 5 seconds)...\n");

    let handle = router.run().await?;

    // Let it run briefly
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Get stats
    if let Ok(stats) = handle.get_stats().await {
        println!("Route statistics:");
        for stat in &stats {
            println!(
                "  Domain {} -> {}: {} msgs, {} bytes, {} errors",
                stat.from_domain,
                stat.to_domain,
                stat.messages_routed,
                stat.bytes_routed,
                stat.errors
            );
        }
    }
    println!();

    // Stop
    handle.stop();
    println!("Router stopped. Done!");

    Ok(())
}

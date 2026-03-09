// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Demonstrates per-domain Discovery Server configuration.
//!
//! This example shows how to:
//! - Configure domains with Discovery Server via TOML
//! - Build the same config programmatically
//! - Validate config lookup helpers
//!
//! Run: cargo run -p hdds-router --example discovery_server_config

use hdds_router::{DomainConfig, RouteConfig, RouterConfig};

fn main() {
    println!("=== Discovery Server Config Demo ===\n");

    // --- 1. TOML parsing ---
    println!("1) Parsing TOML with per-domain Discovery Server config:\n");

    let toml_input = r#"
name = "ds-demo-router"

[[routes]]
from_domain = 0
to_domain = 1
bidirectional = true

[routes.topics]
type = "Include"
value = ["Sensor/*", "Status"]

[[routes.remaps]]
from = "Sensor/*"
to = "Vehicle/*"

# Domain 0: default UDP multicast (no domain config needed)
# Domain 1: uses a Discovery Server
[domains.1]
discovery_server = "10.0.0.100:7400"
"#;

    let config: RouterConfig = toml::from_str(toml_input).expect("TOML parse failed");
    config.validate().expect("Validation failed");

    println!("  Router name: {}", config.name);
    println!("  Routes: {}", config.routes.len());
    println!("  Domain configs: {}", config.domains.len());
    println!();

    // Check each domain
    for domain_id in [0u32, 1] {
        match config.discovery_server_for(domain_id) {
            Some(addr) => println!("  Domain {}: Discovery Server at {}", domain_id, addr),
            None => println!("  Domain {}: UDP multicast (default)", domain_id),
        }
    }
    println!();

    // Round-trip: serialize back to TOML
    let reserialized = toml::to_string_pretty(&config).expect("serialize failed");
    println!("  Round-trip TOML:\n");
    for line in reserialized.lines() {
        println!("    {}", line);
    }
    println!();

    // --- 2. Programmatic config ---
    println!("2) Building the same config programmatically:\n");

    let mut config2 = RouterConfig {
        name: "ds-demo-router-2".into(),
        ..Default::default()
    };

    config2.add_route(
        RouteConfig::new(0, 1)
            .bidirectional(true)
            .topics(hdds_router::config::TopicSelection::Include(vec![
                "Sensor/*".into(),
                "Status".into(),
            ]))
            .remap("Sensor/*", "Vehicle/*"),
    );

    config2.set_domain_config(
        1,
        DomainConfig {
            discovery_server: Some("10.0.0.100:7400".into()),
        },
    );

    config2.validate().expect("Validation failed");

    println!("  Domain 0 DS: {:?}", config2.discovery_server_for(0));
    println!("  Domain 1 DS: {:?}", config2.discovery_server_for(1));
    println!("  Domain 99 DS: {:?}", config2.discovery_server_for(99));
    println!();

    // --- 3. Multi-domain scenario ---
    println!("3) Multi-domain with multiple Discovery Servers:\n");

    let multi_toml = r#"
name = "multi-ds-router"

[[routes]]
from_domain = 0
to_domain = 1

[[routes]]
from_domain = 0
to_domain = 2

[[routes]]
from_domain = 1
to_domain = 2
bidirectional = true

[domains.1]
discovery_server = "ds-east.example.com:7400"

[domains.2]
discovery_server = "ds-west.example.com:7400"
"#;

    let multi_config: RouterConfig = toml::from_str(multi_toml).expect("parse");
    multi_config.validate().expect("validate");

    for domain_id in [0u32, 1, 2] {
        match multi_config.discovery_server_for(domain_id) {
            Some(addr) => println!("  Domain {} -> Discovery Server: {}", domain_id, addr),
            None => println!("  Domain {} -> UDP multicast", domain_id),
        }
    }
    println!();

    // --- 4. Edge cases ---
    println!("4) Edge cases:\n");

    // Domain config with no discovery_server (all defaults)
    let edge_toml = r#"
name = "edge-router"

[[routes]]
from_domain = 0
to_domain = 1

[domains.1]
"#;

    let edge_config: RouterConfig = toml::from_str(edge_toml).expect("parse");
    println!(
        "  Domain with empty config -> DS: {:?}",
        edge_config.discovery_server_for(1)
    );

    // No domains section at all
    let minimal_toml = r#"
name = "minimal"
[[routes]]
from_domain = 0
to_domain = 1
"#;
    let minimal_config: RouterConfig = toml::from_str(minimal_toml).expect("parse");
    println!(
        "  No domains section -> DS: {:?}",
        minimal_config.discovery_server_for(0)
    );

    println!("\nAll checks passed!");
}

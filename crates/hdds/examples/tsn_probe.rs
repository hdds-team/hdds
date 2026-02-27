// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! TSN Probe Example - Check TSN capabilities on network interfaces
//!
//! Usage:
//!   cargo run --example tsn_probe
//!   cargo run --example tsn_probe -- enp1s0
//!
//! This example probes TSN (Time-Sensitive Networking) capabilities:
//! - Hardware timestamping support
//! - SO_TXTIME / LaunchTime availability
//! - ETF/TAPRIO qdisc detection
//! - PTP hardware clock

#![allow(unused_imports)]
use hdds::transport::tsn::{TsnConfig, TsnEnforcement, TsnProbe, TxTimePolicy};
use std::env;

fn main() {
    let iface = env::args().nth(1).unwrap_or_else(|| {
        // Try to find a suitable interface
        find_ethernet_interface().unwrap_or_else(|| "eth0".to_string())
    });

    println!("+========================================================+");
    println!("|           HDDS TSN Capabilities Probe                  |");
    println!("+========================================================+\n");

    println!("Interface: {}\n", iface);

    match TsnProbe::probe(&iface) {
        Ok(caps) => {
            println!("+-----------------------------------------+");
            println!("| TSN Capabilities                        |");
            println!("+-----------------------------------------+");
            println!("| SO_TXTIME        : {:?}", caps.so_txtime);
            println!("| HW Timestamping  : {:?}", caps.hw_timestamping);
            println!("| ETF qdisc        : {}", caps.etf_configured);
            println!("| TAPRIO qdisc     : {}", caps.taprio_configured);
            println!("| MQPRIO qdisc     : {}", caps.mqprio_configured);
            println!("| PTP Clock        : {:?}", caps.phc_device);
            println!("| Kernel           : {:?}", caps.kernel_version);
            println!("+-----------------------------------------+\n");

            // Show notes
            if !caps.notes.is_empty() {
                println!("Notes:");
                for note in &caps.notes {
                    println!("  - {}", note);
                }
                println!();
            }

            // Status
            println!("Status:");
            println!("  TSN Ready          : {}", caps.is_tsn_ready());
            println!("  Scheduled TX Ready : {}", caps.is_scheduled_tx_ready());
            println!("  Priority Queues    : {}", caps.has_priority_queues());

            // Recommend configuration
            println!("\nRecommended TsnConfig:");
            let config = recommend_config(&caps);
            println!("  enabled: {}", config.enabled);
            println!("  enforcement: {:?}", config.enforcement);
            println!("  tx_time: {:?}", config.tx_time);
            if let Some(pcp) = config.pcp {
                println!("  pcp: {}", pcp);
            }
        }
        Err(e) => {
            println!("[X] Failed to probe TSN capabilities: {}", e);
            println!("\nMake sure you have permission to access network interfaces.");
            println!("Try running with sudo or CAP_NET_ADMIN capability.");
        }
    }
}

fn find_ethernet_interface() -> Option<String> {
    // Check common ethernet interface names
    for name in &["eth0", "enp0s31f6", "enp1s0", "eno1", "ens33"] {
        let path = format!("/sys/class/net/{}", name);
        if std::path::Path::new(&path).exists() {
            return Some(name.to_string());
        }
    }

    // Try to find any non-loopback, non-virtual interface
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo"
                || name.starts_with("docker")
                || name.starts_with("br-")
                || name.starts_with("veth")
                || name.starts_with("virbr")
            {
                continue;
            }
            // Check if it's a physical device
            let device_path = format!("/sys/class/net/{}/device", name);
            if std::path::Path::new(&device_path).exists() {
                return Some(name);
            }
        }
    }

    None
}

fn recommend_config(caps: &hdds::transport::tsn::TsnCapabilities) -> TsnConfig {
    let mut config = TsnConfig::default();

    // Enable TSN if any capability is available
    if caps.so_txtime.is_available() || caps.hw_timestamping.is_available() {
        config.enabled = true;
    }

    // Set enforcement based on capabilities
    if caps.is_scheduled_tx_ready() {
        config.enforcement = TsnEnforcement::Strict;
        config.tx_time = TxTimePolicy::Mandatory;
        println!("\n[OK] Full TSN support - LaunchTime scheduling available");
    } else if caps.has_priority_queues() {
        config.enforcement = TsnEnforcement::BestEffort;
        config.tx_time = TxTimePolicy::Opportunistic;
        println!("\n[!]  Priority tagging only - configure ETF qdisc for LaunchTime");
    } else if caps.is_tsn_ready() {
        config.enforcement = TsnEnforcement::BestEffort;
        config.tx_time = TxTimePolicy::Opportunistic;
        println!("\n[!]  Basic TSN support - configure mqprio + ETF for full features");
    } else {
        println!("\n[X] No TSN support detected");
    }

    // Set high priority for real-time traffic
    config.pcp = Some(6);

    config
}

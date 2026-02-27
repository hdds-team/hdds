// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

use hdds_gen::qos_generator::QosGenerator;
use std::env;
use std::path::PathBuf;

fn main() {
    // Initialize tracing for diagnostics
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "qos-validator" => {
            if let Err(e) = generate_qos_validator() {
                eprintln!("[ERROR] {}", e);
                std::process::exit(1);
            }
        }
        "--help" | "-h" | "help" => {
            print_help();
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_help();
            std::process::exit(1);
        }
    }
}

fn generate_qos_validator() -> anyhow::Result<()> {
    // Base directory defaults to ./hdds_test, override with HDDS_TEST_DIR env var
    let base_dir =
        PathBuf::from(std::env::var("HDDS_TEST_DIR").unwrap_or_else(|_| "hdds_test".into()));

    tracing::info!("Initializing QoS Validator Generator");
    let generator = QosGenerator::new(base_dir)?;

    tracing::info!("Starting generation");
    let report = generator.generate()?;

    report.summary();

    Ok(())
}

fn print_help() {
    println!("hdds-gen v0.1");
    println!();
    println!("USAGE:");
    println!("    hdds-gen <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    qos-validator  Generate 22-policy QoS validator (48 profiles + 96 scripts)");
    println!("    help           Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("    hdds-gen qos-validator");
    println!();
}

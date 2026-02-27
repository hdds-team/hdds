// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

mod conversion;
mod mcq;
mod rti_loader;

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "hdds-convert-qos")]
#[command(about = "Multi-vendor QoS converter (RTI/FastDDS/Cyclone -> MCQ canonical format)")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse and validate MCQ YAML file
    Validate {
        /// Input MCQ YAML file
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Show verbose validation details
        #[arg(short, long)]
        verbose: bool,
    },

    /// Convert vendor XML to MCQ
    Convert {
        /// Input vendor XML file (RTI/FastDDS/Cyclone)
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output MCQ YAML file
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Vendor format (auto-detect if not specified)
        #[arg(long, value_enum)]
        from: Option<VendorFormat>,

        /// Strict mode (reject CRITICAL violations)
        #[arg(long)]
        strict: bool,

        /// Preview mode (dry-run, no file write)
        #[arg(long)]
        preview: bool,
    },

    /// Show MCQ normalization
    Normalize {
        /// Input MCQ YAML file
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output normalized MCQ YAML file
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum VendorFormat {
    Rti,
    FastDds,
    Cyclone,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { input, verbose } => {
            cmd_validate(&input, verbose)?;
        }
        Commands::Convert {
            input,
            output,
            from,
            strict,
            preview,
        } => {
            cmd_convert(&input, output, from, strict, preview)?;
        }
        Commands::Normalize { input, output } => {
            cmd_normalize(&input, output)?;
        }
    }

    Ok(())
}

fn cmd_validate(input: &Path, verbose: bool) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(input)?;

    match mcq::Mcq::from_yaml(&yaml) {
        Ok(mcq) => {
            // Collect all warnings (MAJOR/MINOR) even if parsing succeeded
            let warnings = mcq.collect_validation_errors();

            if warnings.is_empty() {
                println!(
                    "[OK] MCQ validation passed: {} (no warnings)",
                    input.display()
                );
            } else {
                println!(
                    "[OK] MCQ validation passed: {} ({} warnings)",
                    input.display(),
                    warnings.len()
                );
                println!();

                for (idx, warning) in warnings.iter().enumerate() {
                    match warning {
                        mcq::ValidationError::Critical { field, message } => {
                            println!("  {}. [CRITICAL] [{}]: {}", idx + 1, field, message);
                        }
                        mcq::ValidationError::Major { field, message } => {
                            println!("  {}. [MAJOR] [{}]: {}", idx + 1, field, message);
                        }
                        mcq::ValidationError::Minor { field, message } => {
                            println!("  {}. [MINOR] [{}]: {}", idx + 1, field, message);
                        }
                    }
                }
                println!();
            }

            if verbose {
                println!("Metadata:");
                println!("  source: {}", mcq.metadata.source);
                println!("  profile: {}", mcq.metadata.profile_name);
                println!("  conformance: {}", mcq.metadata.conformance_profile);
                println!("\nEntities:");
                println!("  datawriter_qos: {} entries", mcq.datawriter_qos.len());
                println!("  datareader_qos: {} entries", mcq.datareader_qos.len());
            }
            Ok(())
        }
        Err(critical_errors) => {
            eprintln!("[ERROR] MCQ validation FAILED: {}", input.display());
            eprintln!(
                "\n{} CRITICAL errors (strict mode reject):\n",
                critical_errors.len()
            );

            for (idx, error) in critical_errors.iter().enumerate() {
                match error {
                    mcq::ValidationError::Critical { field, message } => {
                        eprintln!("  {}. [CRITICAL] [{}]: {}", idx + 1, field, message);
                    }
                    mcq::ValidationError::Major { field, message } => {
                        eprintln!("  {}. [MAJOR] [{}]: {}", idx + 1, field, message);
                    }
                    mcq::ValidationError::Minor { field, message } => {
                        eprintln!("  {}. [MINOR] [{}]: {}", idx + 1, field, message);
                    }
                }
            }

            anyhow::bail!(
                "Validation failed with {} CRITICAL errors",
                critical_errors.len()
            );
        }
    }
}

fn cmd_convert(
    input: &Path,
    output: Option<PathBuf>,
    from: Option<VendorFormat>,
    strict: bool,
    preview: bool,
) -> anyhow::Result<()> {
    // Read input XML
    let xml_content = std::fs::read_to_string(input)?;

    // Auto-detect vendor if not specified
    let vendor = if let Some(fmt) = from {
        format!("{fmt:?}").to_lowercase()
    } else {
        println!("[INFO] Auto-detecting vendor...");
        match rti_loader::RtiLoader::detect_vendor(&xml_content) {
            Ok(v) => {
                println!("[OK] Detected vendor: {v}");
                v
            }
            Err(e) => {
                anyhow::bail!("Failed to detect vendor: {e}. Use --from to specify manually.");
            }
        }
    };

    // Parse based on vendor (currently only RTI supported)
    let mcq_raw = if vendor.starts_with("rti") {
        rti_loader::RtiLoader::parse_xml(&xml_content)?
    } else {
        anyhow::bail!("Unsupported vendor: {vendor}. Only RTI is supported in this version.");
    };

    // Convert with validation and scoring
    let mode = if strict {
        conversion::ConversionMode::Strict
    } else {
        conversion::ConversionMode::Compat
    };

    let (mcq, report) = conversion::ConversionEngine::convert(mcq_raw, mode).map_err(|errors| {
        let msg = errors
            .iter()
            .map(|e| format!("  - {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::anyhow!("Conversion failed with CRITICAL errors:\n{msg}")
    })?;

    println!(
        "[SCORE] Fidelity score: {}/100 (tags: {})",
        report.fidelity_score,
        report.tags.join(", ")
    );

    if !report.validation_errors.is_empty() {
        println!(
            "\n[WARN] {} validation warnings:",
            report.validation_errors.len()
        );
        for err in &report.validation_errors {
            println!("  - {} [{}]: {}", err.severity, err.field, err.message);
        }
    }

    // Serialize to YAML
    let yaml_output = serde_yaml::to_string(&mcq)?;

    // Output
    if preview {
        println!("\n[PREVIEW] Preview mode (dry-run, no file write):\n");
        println!("{yaml_output}");
    } else if let Some(out_path) = output {
        std::fs::write(&out_path, &yaml_output)?;
        println!("\n[OK] MCQ written to: {}", out_path.display());

        // Write report as JSON
        let report_path = out_path.with_extension("report.json");
        let report_json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&report_path, report_json)?;
        println!("[OK] Fidelity report written to: {}", report_path.display());
    } else {
        println!("\n{yaml_output}");
    }

    Ok(())
}

fn cmd_normalize(input: &Path, output: Option<PathBuf>) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(input)?;
    let mut mcq = mcq::Mcq::from_yaml(&yaml)
        .map_err(|errors| anyhow::anyhow!("Validation failed with {} errors", errors.len()))?;

    mcq.normalize();

    let normalized_yaml = serde_yaml::to_string(&mcq)?;

    if let Some(out_path) = output {
        std::fs::write(&out_path, normalized_yaml)?;
        println!("[OK] Normalized MCQ written to: {}", out_path.display());
    } else {
        println!("{normalized_yaml}");
    }

    Ok(())
}

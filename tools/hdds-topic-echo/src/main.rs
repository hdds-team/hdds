// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-topic-echo - Echo DDS topic messages in real-time
//!
//! Like `rostopic echo` but for DDS/RTPS.

use chrono::Local;
use clap::Parser;
use colored::*;
use hdds::{Participant, QoS, RawSample};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Echo DDS topic messages in real-time
#[derive(Parser, Debug)]
#[command(name = "hdds-topic-echo")]
#[command(version = "0.1.0")]
#[command(about = "Echo DDS topic messages (like rostopic echo)")]
struct Args {
    /// Topic name to subscribe to
    topic: String,

    /// DDS domain ID
    #[arg(short, long, default_value = "0")]
    domain: u32,

    /// Output format: pretty, json, compact, raw
    #[arg(short, long, default_value = "pretty")]
    format: OutputFormat,

    /// Shortcut for --format json
    #[arg(long)]
    json: bool,

    /// Shortcut for --format raw
    #[arg(long)]
    raw: bool,

    /// Maximum number of samples to receive (0 = unlimited)
    #[arg(short = 'n', long, default_value = "0")]
    count: u64,

    /// Show verbose metadata (sequence, source GUID, timestamps)
    #[arg(short, long)]
    verbose: bool,

    /// QoS profile: best-effort, reliable
    #[arg(short, long, default_value = "reliable")]
    qos: QoSProfile,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Quiet mode - only output data, no headers
    #[arg(short = 'q', long)]
    quiet: bool,
}

#[derive(Clone, Debug, PartialEq)]
enum OutputFormat {
    Pretty,
    Json,
    Compact,
    Raw,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" | "p" => Ok(OutputFormat::Pretty),
            "json" | "j" => Ok(OutputFormat::Json),
            "compact" | "c" => Ok(OutputFormat::Compact),
            "raw" | "r" | "hex" => Ok(OutputFormat::Raw),
            _ => Err(format!("Unknown format: {}", s)),
        }
    }
}

#[derive(Clone, Debug)]
enum QoSProfile {
    BestEffort,
    Reliable,
}

impl std::str::FromStr for QoSProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "best-effort" | "besteffort" | "be" => Ok(QoSProfile::BestEffort),
            "reliable" | "rel" | "r" => Ok(QoSProfile::Reliable),
            _ => Err(format!("Unknown QoS: {}", s)),
        }
    }
}

fn main() {
    let args = Args::parse();

    // Handle color preference
    if args.no_color || !is_tty() {
        colored::control::set_override(false);
    }

    // Determine output format (shortcuts override --format)
    let format = if args.json {
        OutputFormat::Json
    } else if args.raw {
        OutputFormat::Raw
    } else {
        args.format.clone()
    };

    if let Err(e) = run_echo(&args, format) {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

fn run_echo(args: &Args, format: OutputFormat) -> Result<(), Box<dyn std::error::Error>> {
    // Setup Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // Print header
    if !args.quiet {
        print_header(args, &format);
    }

    // Create participant
    let participant = Participant::builder("hdds-topic-echo")
        .domain_id(args.domain)
        .build()?;
    let participant = Arc::new(participant);

    // Select QoS
    let qos = match args.qos {
        QoSProfile::BestEffort => QoS::best_effort(),
        QoSProfile::Reliable => QoS::reliable(),
    };

    // Create raw reader
    let reader = participant.create_raw_reader(&args.topic, Some(qos))?;

    let sample_count = AtomicU64::new(0);
    let max_samples = args.count;

    // Main loop
    while running.load(Ordering::SeqCst) {
        if max_samples > 0 && sample_count.load(Ordering::SeqCst) >= max_samples {
            break;
        }

        // Take all available samples
        match reader.try_take_raw() {
            Ok(samples) => {
                let is_empty = samples.is_empty();

                for sample in samples {
                    let count = sample_count.fetch_add(1, Ordering::SeqCst) + 1;

                    if max_samples > 0 && count > max_samples {
                        break;
                    }

                    print_sample(&sample, &format, args.verbose, count);
                    let _ = io::stdout().flush();
                }

                if is_empty {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Err(e) => {
                if !args.quiet {
                    eprintln!("{}: {}", "Warning".yellow(), e);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    if !args.quiet {
        let total = sample_count.load(Ordering::SeqCst);
        eprintln!("\n{} Received {} sample(s)", "---".dimmed(), total);
    }

    Ok(())
}

fn print_header(args: &Args, format: &OutputFormat) {
    eprintln!(
        "{} {} {} (domain={}, qos={:?}, format={:?})",
        ">>>".green().bold(),
        "Subscribing to".bold(),
        args.topic.cyan(),
        args.domain,
        args.qos,
        format
    );
    eprintln!("{}", "Press Ctrl+C to stop".dimmed());
    eprintln!();
}

fn print_sample(sample: &RawSample, format: &OutputFormat, verbose: bool, seq: u64) {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

    match format {
        OutputFormat::Pretty => print_pretty(sample, verbose, &timestamp.to_string(), seq),
        OutputFormat::Json => print_json(sample, verbose, seq),
        OutputFormat::Compact => print_compact(sample, seq),
        OutputFormat::Raw => print_raw(sample, verbose, &timestamp.to_string(), seq),
    }
}

fn print_pretty(sample: &RawSample, verbose: bool, timestamp: &str, seq: u64) {
    if verbose {
        println!(
            "{} [{}] seq={} len={}",
            format!("[{}]", timestamp).dimmed(),
            format!("#{}", seq).yellow(),
            sample.sequence_number.unwrap_or(0),
            sample.payload.len()
        );
    } else {
        println!(
            "{} {} ({} bytes)",
            format!("[{}]", timestamp).dimmed(),
            format!("#{}", seq).yellow(),
            sample.payload.len()
        );
    }

    print_payload_decoded(&sample.payload);
    println!();
}

fn print_json(sample: &RawSample, verbose: bool, seq: u64) {
    let payload_b64 = base64_encode(&sample.payload);

    if verbose {
        let ts = sample
            .source_timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        println!(
            r#"{{"seq":{},"len":{},"timestamp":{:.6},"payload":"{}"}}"#,
            seq,
            sample.payload.len(),
            ts,
            payload_b64
        );
    } else {
        println!(r#"{{"seq":{},"payload":"{}"}}"#, seq, payload_b64);
    }
}

fn print_compact(sample: &RawSample, seq: u64) {
    let preview: String = sample
        .payload
        .iter()
        .take(32)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("");

    let suffix = if sample.payload.len() > 32 { "..." } else { "" };
    println!(
        "#{}: {}{} ({} bytes)",
        seq,
        preview,
        suffix,
        sample.payload.len()
    );
}

fn print_raw(sample: &RawSample, verbose: bool, timestamp: &str, seq: u64) {
    if verbose {
        println!(
            "{} #{} ({} bytes)",
            format!("[{}]", timestamp).dimmed(),
            seq,
            sample.payload.len()
        );
    }

    print_hex_dump(&sample.payload);
    println!();
}

fn print_payload_decoded(payload: &[u8]) {
    if payload.is_empty() {
        println!("  {}", "(empty)".dimmed());
        return;
    }

    // Skip CDR encapsulation (4 bytes) if present
    let data = if payload.len() > 4 {
        &payload[4..]
    } else {
        payload
    };

    // Try string detection
    if let Some(s) = try_decode_string(data) {
        println!("  {}: {}", "string".cyan(), s.green());
        return;
    }

    // Try numeric types
    if data.len() == 4 {
        let ival = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let fval = f32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        println!("  {}: {} | f32: {:.4}", "i32".cyan(), ival, fval);
        return;
    }

    if data.len() == 8 {
        let ival = i64::from_le_bytes(data[0..8].try_into().unwrap());
        let fval = f64::from_le_bytes(data[0..8].try_into().unwrap());
        println!("  {}: {} | f64: {:.6}", "i64".cyan(), ival, fval);
        return;
    }

    // Default hex preview
    let preview: String = data
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    let suffix = if data.len() > 16 { " ..." } else { "" };
    println!("  {}: {}{}", "bytes".cyan(), preview, suffix);
}

fn try_decode_string(data: &[u8]) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len == 0 || len > 10000 || 4 + len > data.len() {
        return None;
    }

    let str_bytes = &data[4..4 + len.saturating_sub(1)];
    if let Ok(s) = std::str::from_utf8(str_bytes) {
        if s.chars()
            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        {
            return Some(format!("\"{}\"", s));
        }
    }
    None
}

fn print_hex_dump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("  {:04x}  ", i * 16);

        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{:02x} ", byte);
        }

        for j in chunk.len()..16 {
            if j == 8 {
                print!(" ");
            }
            print!("   ");
        }

        print!(" |");
        for byte in chunk {
            print!(
                "{}",
                if *byte >= 0x20 && *byte < 0x7f {
                    *byte as char
                } else {
                    '.'
                }
            );
        }
        println!("|");
    }
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in data.chunks(3) {
        let (b0, b1, b2) = (
            chunk[0] as usize,
            chunk.get(1).copied().unwrap_or(0) as usize,
            chunk.get(2).copied().unwrap_or(0) as usize,
        );

        result.push(CHARS[b0 >> 2] as char);
        result.push(CHARS[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        result.push(if chunk.len() > 1 {
            CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            CHARS[b2 & 0x3f] as char
        } else {
            '='
        });
    }
    result
}

fn is_tty() -> bool {
    #[cfg(unix)]
    unsafe {
        libc::isatty(libc::STDOUT_FILENO) != 0
    }
    #[cfg(not(unix))]
    true
}

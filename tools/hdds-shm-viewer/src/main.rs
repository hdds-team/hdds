// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-shm-viewer - Inspect HDDS shared memory segments
//!
//! Displays information about SHM segments used for zero-copy IPC.

use clap::Parser;
use colored::*;
use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Magic number for HDDS SHM segments
const HDDS_MAGIC: u32 = 0x4844_4453; // "HDDS"

/// Inspect HDDS shared memory segments
#[derive(Parser, Debug)]
#[command(name = "hdds-shm-viewer")]
#[command(version = "0.1.0")]
#[command(about = "Inspect HDDS shared memory segments")]
struct Args {
    /// Filter by domain ID
    #[arg(short, long)]
    domain: Option<u32>,

    /// Show detailed slot information
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Output format: pretty, json
    #[arg(short, long, default_value = "pretty")]
    format: OutputFormat,

    /// Show only summary statistics
    #[arg(short, long)]
    summary: bool,

    /// Specific segment name to inspect (without /dev/shm prefix)
    #[arg()]
    segment: Option<String>,
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

/// Information about a SHM segment
#[derive(Debug)]
struct SegmentInfo {
    name: String,
    file_size: u64,
    segment_type: SegmentType,
    control: Option<ControlInfo>,
    error: Option<String>,
}

#[derive(Debug)]
enum SegmentType {
    Writer,
    Notify,
    Unknown,
}

/// Control block information
#[derive(Debug)]
struct ControlInfo {
    magic: u32,
    version: u32,
    capacity: u32,
    slot_size: u32,
    head: u64,
    is_valid: bool,
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(&args) {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let shm_dir = Path::new("/dev/shm");

    if !shm_dir.exists() {
        return Err("Shared memory directory /dev/shm not found".into());
    }

    // Collect segments
    let segments = if let Some(ref name) = args.segment {
        // Inspect specific segment
        vec![inspect_segment(name)?]
    } else {
        // Scan for HDDS segments
        scan_hdds_segments(shm_dir, args.domain)?
    };

    // Output
    match args.format {
        OutputFormat::Pretty => print_pretty(&segments, args),
        OutputFormat::Json => print_json(&segments),
    }

    Ok(())
}

fn scan_hdds_segments(
    shm_dir: &Path,
    domain_filter: Option<u32>,
) -> Result<Vec<SegmentInfo>, Box<dyn std::error::Error>> {
    let mut segments = Vec::new();

    for entry in fs::read_dir(shm_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(n) => n,
            None => continue,
        };

        // Check if this is an HDDS segment
        if !name.starts_with("hdds_") {
            continue;
        }

        // Filter by domain if specified
        if let Some(domain) = domain_filter {
            let domain_prefix = format!("hdds_d{}_", domain);
            let notify_prefix = format!("hdds_notify_d{}_", domain);
            if !name.starts_with(&domain_prefix) && !name.starts_with(&notify_prefix) {
                continue;
            }
        }

        match inspect_segment(name) {
            Ok(info) => segments.push(info),
            Err(e) => {
                segments.push(SegmentInfo {
                    name: name.to_string(),
                    file_size: entry.metadata().map(|m| m.len()).unwrap_or(0),
                    segment_type: SegmentType::Unknown,
                    control: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    // Sort by name
    segments.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(segments)
}

fn inspect_segment(name: &str) -> Result<SegmentInfo, Box<dyn std::error::Error>> {
    let shm_name = if name.starts_with('/') {
        name.to_string()
    } else {
        format!("/{}", name)
    };

    let display_name = name.trim_start_matches('/').to_string();

    // Determine segment type
    let segment_type = if display_name.contains("_w") {
        SegmentType::Writer
    } else if display_name.contains("notify") {
        SegmentType::Notify
    } else {
        SegmentType::Unknown
    };

    // Get file size from /dev/shm
    let file_path = format!("/dev/shm/{}", display_name);
    let file_size = fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0);

    // Try to open and read control block
    let control = open_and_read_control(&shm_name).ok();

    Ok(SegmentInfo {
        name: display_name,
        file_size,
        segment_type,
        control,
        error: None,
    })
}

fn open_and_read_control(shm_name: &str) -> Result<ControlInfo, Box<dyn std::error::Error>> {
    let c_name = CString::new(shm_name)?;

    // Open the segment
    let fd = unsafe { libc::shm_open(c_name.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        return Err("Failed to open segment".into());
    }

    // Map just the control block (64 bytes)
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            64,
            libc::PROT_READ,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };

    unsafe { libc::close(fd) };

    if ptr == libc::MAP_FAILED {
        return Err("Failed to map segment".into());
    }

    // Read control block fields
    // Layout: head(8) + capacity(4) + slot_size(4) + magic(4) + version(4) + pad(40)
    let head_ptr = ptr as *const AtomicU64;
    let capacity_ptr = unsafe { (ptr as *const u8).add(8) as *const AtomicU32 };
    let slot_size_ptr = unsafe { (ptr as *const u8).add(12) as *const AtomicU32 };
    let magic_ptr = unsafe { (ptr as *const u8).add(16) as *const AtomicU32 };
    let version_ptr = unsafe { (ptr as *const u8).add(20) as *const AtomicU32 };

    let head = unsafe { (*head_ptr).load(Ordering::Relaxed) };
    let capacity = unsafe { (*capacity_ptr).load(Ordering::Relaxed) };
    let slot_size = unsafe { (*slot_size_ptr).load(Ordering::Relaxed) };
    let magic = unsafe { (*magic_ptr).load(Ordering::Relaxed) };
    let version = unsafe { (*version_ptr).load(Ordering::Relaxed) };

    // Unmap
    unsafe { libc::munmap(ptr, 64) };

    let is_valid = magic == HDDS_MAGIC;

    Ok(ControlInfo {
        magic,
        version,
        capacity,
        slot_size,
        head,
        is_valid,
    })
}

fn print_pretty(segments: &[SegmentInfo], args: &Args) {
    if segments.is_empty() {
        println!("{}", "No HDDS shared memory segments found".yellow());
        return;
    }

    if args.summary {
        print_summary(segments);
        return;
    }

    println!();
    println!("{}", "=== HDDS Shared Memory Segments ===".bold());
    println!();

    let mut total_size: u64 = 0;
    let mut total_messages: u64 = 0;
    let mut writer_count = 0;
    let mut notify_count = 0;

    for seg in segments {
        total_size += seg.file_size;

        let type_badge = match seg.segment_type {
            SegmentType::Writer => {
                writer_count += 1;
                "WRITER".green()
            }
            SegmentType::Notify => {
                notify_count += 1;
                "NOTIFY".blue()
            }
            SegmentType::Unknown => "UNKNOWN".yellow(),
        };

        println!(
            "  {} {} ({})",
            type_badge,
            seg.name.cyan(),
            format_size(seg.file_size)
        );

        if let Some(ref ctrl) = seg.control {
            let valid_badge = if ctrl.is_valid {
                "VALID".green()
            } else {
                "INVALID".red()
            };

            if args.verbose {
                println!(
                    "      Magic: 0x{:08X} [{}]  Version: {}",
                    ctrl.magic, valid_badge, ctrl.version
                );
                println!(
                    "      Capacity: {} slots  Slot size: {} bytes",
                    ctrl.capacity, ctrl.slot_size
                );
                println!(
                    "      Head: {} (messages written)",
                    ctrl.head.to_string().yellow()
                );

                // Calculate usage
                if ctrl.capacity > 0 {
                    let ring_used = (ctrl.head % ctrl.capacity as u64) as u32;
                    let usage_pct = (ring_used as f64 / ctrl.capacity as f64) * 100.0;
                    println!(
                        "      Ring fill: {}/{} ({:.1}%)",
                        ring_used, ctrl.capacity, usage_pct
                    );
                }
            } else {
                println!(
                    "      [{}] cap={} slots, head={}, slot={}B",
                    valid_badge, ctrl.capacity, ctrl.head, ctrl.slot_size
                );
            }

            total_messages += ctrl.head;
        }

        if let Some(ref err) = seg.error {
            println!("      {}: {}", "Error".red(), err);
        }

        println!();
    }

    // Summary
    println!("{}", "--- Summary ---".dimmed());
    println!(
        "  Segments: {} ({} writers, {} notify)",
        segments.len(),
        writer_count,
        notify_count
    );
    println!("  Total size: {}", format_size(total_size));
    println!("  Total messages: {}", total_messages);
    println!();
}

fn print_summary(segments: &[SegmentInfo]) {
    let mut total_size: u64 = 0;
    let mut total_messages: u64 = 0;
    let mut writer_count = 0;
    let mut notify_count = 0;
    let mut valid_count = 0;

    for seg in segments {
        total_size += seg.file_size;

        match seg.segment_type {
            SegmentType::Writer => writer_count += 1,
            SegmentType::Notify => notify_count += 1,
            SegmentType::Unknown => {}
        }

        if let Some(ref ctrl) = seg.control {
            if ctrl.is_valid {
                valid_count += 1;
            }
            total_messages += ctrl.head;
        }
    }

    println!(
        "segments={} writers={} notify={} valid={} size={} messages={}",
        segments.len(),
        writer_count,
        notify_count,
        valid_count,
        total_size,
        total_messages
    );
}

fn print_json(segments: &[SegmentInfo]) {
    print!("{{\"segments\":[");

    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            print!(",");
        }

        let seg_type = match seg.segment_type {
            SegmentType::Writer => "writer",
            SegmentType::Notify => "notify",
            SegmentType::Unknown => "unknown",
        };

        print!(
            "{{\"name\":\"{}\",\"type\":\"{}\",\"size\":{}",
            seg.name, seg_type, seg.file_size
        );

        if let Some(ref ctrl) = seg.control {
            print!(
                ",\"control\":{{\"magic\":{},\"version\":{},\"capacity\":{},\"slot_size\":{},\"head\":{},\"valid\":{}}}",
                ctrl.magic,
                ctrl.version,
                ctrl.capacity,
                ctrl.slot_size,
                ctrl.head,
                ctrl.is_valid
            );
        }

        if let Some(ref err) = seg.error {
            print!(",\"error\":\"{}\"", err.replace('"', "\\\""));
        }

        print!("}}");
    }

    println!("]}}");
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

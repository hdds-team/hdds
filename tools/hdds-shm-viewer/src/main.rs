// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! hdds-shm-viewer - Inspect HDDS shared memory segments
//!
//! Displays information about SHM segments used for zero-copy IPC.
//!
//! # Read-only, by construction
//!
//! Every segment is opened as a plain file under `/dev/shm` and a small,
//! fixed-size prefix of bytes is read with `std::fs::File`. Nothing here
//! calls `shm_open`, `mmap`, or takes any product lock: `/dev/shm` IS the
//! backing store POSIX shared memory objects use on Linux, so reading the
//! file IS reading the segment, without attaching to it the way a writer or
//! reader process does. This tool never writes or unlinks anything under
//! `/dev/shm`.
//!
//! # Segment families recognised
//!
//! * **Ring writer segments** -- `/hdds_d<domain>_w<writer-guid-hex>`. Header
//!   is `ShmControl` (`crates/hdds/src/transport/shm/slot.rs`, `pub`).
//! * **Notify segments, version 2** (current, since HDDS 1.5.0) --
//!   `/hdds_notify_v2_d<domain>_<topic>`. Header is `NotifyHeader`
//!   (`crates/hdds/src/transport/shm/notify.rs`, private to that crate; see
//!   the module doc there for the full layout and lifecycle). This tool
//!   reads the fixed header fields and, best-effort, counts live rows in
//!   the user table -- WITHOUT taking the header's robust mutex, so the
//!   count is a snapshot, not a synchronized read.
//! * **Notify segments, version 1** (legacy, pre-1.5.0) --
//!   `/hdds_notify_d<domain>_<topic>`, a bare bucket array with no header.
//!   Listed and labelled legacy; nothing to decode.
//! * **Owner sidecar files** -- `<segment-name>.owner`, written by
//!   `crates/hdds/src/transport/shm/owner.rs` next to a ring segment. Never
//!   listed as a segment of their own; the pid they name is attached to the
//!   segment they belong to.

#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use colored::*;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
/// Magic number for HDDS ring (writer) SHM segments.
/// Mirrors `ShmControl::MAGIC` (crates/hdds/src/transport/shm/slot.rs, `pub`).
const HDDS_MAGIC: u32 = 0x4844_4453; // "HDDS"

#[cfg(target_os = "linux")]
/// Name prefix of ring writer segments, up to and including the domain's
/// trailing underscore: `/hdds_d<domain>_w<writer-guid-hex>`.
/// Mirrors `format!("hdds_d{domain_id}_")` built in
/// `crates/hdds/src/transport/shm/segment.rs`.
const RING_FAMILY_PREFIX: &str = "hdds_d";

#[cfg(target_os = "linux")]
/// Name prefix of version-2 notify segments: `/hdds_notify_v2_d<domain>_<topic>`.
/// Mirrors `NOTIFY_PREFIX` in `crates/hdds/src/transport/shm/notify.rs`, which
/// is `pub(crate)` there and not reachable from this tool's own crate.
const NOTIFY_V2_FAMILY_PREFIX: &str = "hdds_notify_v2_d";

#[cfg(target_os = "linux")]
/// Name prefix of legacy version-1 notify segments (HDDS before the v2
/// header): `/hdds_notify_d<domain>_<topic>`. See notify.rs module doc,
/// section "Older peers on the same host".
const NOTIFY_V1_FAMILY_PREFIX: &str = "hdds_notify_d";

#[cfg(target_os = "linux")]
/// "NTFY" read little-endian. Mirrors `NOTIFY_MAGIC` in notify.rs (private
/// there).
const NOTIFY_V2_MAGIC: u32 = 0x5946_544E;

#[cfg(target_os = "linux")]
/// Mirrors `NOTIFY_LAYOUT_VERSION` in notify.rs (private there).
const NOTIFY_V2_LAYOUT_VERSION: u32 = 2;

#[cfg(target_os = "linux")]
/// Size in bytes of one `UserSlot` row in the v2 header's user table.
/// notify.rs asserts this at compile time: `size_of::<UserSlot>() == 64`.
const NOTIFY_USER_SLOT_SIZE: usize = 64;

#[cfg(target_os = "linux")]
/// Byte offset of the user table's first row from the start of the v2
/// header (`NotifyHeader` in notify.rs). The header lays out five `u32`
/// fields -- magic, version, lock_abi, max_users, closed (20 bytes) --
/// then padding to the 64-byte alignment its `LockStorage` field requires
/// (44 bytes: 20 + 44 = 64), then `LockStorage` itself (64 bytes: 64..128).
/// The user table starts right after, at byte 128.
const NOTIFY_V2_USER_TABLE_OFFSET: usize = 128;

#[cfg(target_os = "linux")]
/// A `UserSlot.state` value of 1 means the row is live.
/// Mirrors `SLOT_LIVE` in notify.rs (private there).
const NOTIFY_SLOT_LIVE: u32 = 1;

#[cfg(target_os = "linux")]
/// Upper bound on how many user-table rows this tool will ever scan, no
/// matter what a segment's own `max_users` field claims. The product's
/// `NOTIFY_MAX_USERS` is 1024; this leaves headroom for a future bump
/// without letting a corrupt or foreign header turn a diagnostic read into
/// an unbounded one.
const NOTIFY_V2_USER_TABLE_SANITY_CAP: u32 = 1 << 16;

#[cfg(target_os = "linux")]
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

    /// Specific segment name to inspect (without the /dev/shm prefix; a
    /// leading '/' is accepted and ignored)
    #[arg()]
    segment: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
enum OutputFormat {
    Pretty,
    Json,
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
/// Which segment family a name parsed as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Family {
    Writer,
    NotifyV2,
    NotifyLegacyV1,
}

#[cfg(target_os = "linux")]
/// The result of classifying one `/dev/shm` entry name.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ParsedEntry {
    /// Does not start with "hdds_" at all: not ours, ignored.
    NotHdds,
    /// An owner sidecar file (`<segment>.owner`). Never a segment of its
    /// own; carries the base segment name it belongs to.
    Owner(String),
    /// A recognised HDDS segment family, with its parsed domain and, for
    /// the families that have one, its (sanitized) topic name.
    Segment(Family, u32, Option<String>),
    /// Starts with "hdds_" but matched none of the known families.
    UnrecognizedHdds,
}

#[cfg(target_os = "linux")]
/// Information about a SHM segment
#[derive(Debug)]
struct SegmentInfo {
    name: String,
    file_size: u64,
    domain: Option<u32>,
    topic: Option<String>,
    kind: SegmentKind,
    /// pid recorded in this segment's `.owner` sidecar, if any (ring writer
    /// segments only -- notify segments track liveness in their own header,
    /// not via a sidecar).
    owner_pid: Option<u32>,
    error: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum SegmentKind {
    /// Ring writer segment. `None` when the control block could not be read.
    Writer(Option<RingControlInfo>),
    /// Version-2 notify segment. `None` when the header could not be read.
    NotifyV2(Option<NotifyV2Info>),
    /// Version-1 (legacy) notify segment: a bare bucket array, no header.
    NotifyLegacyV1,
    Unknown,
}

#[cfg(target_os = "linux")]
/// Ring segment control block, decoded from `ShmControl`'s layout
/// (crates/hdds/src/transport/shm/slot.rs): head (u64), capacity (u32),
/// slot_size (u32), magic (u32), version (u32), ... (fields after that are
/// not needed here).
#[derive(Debug)]
struct RingControlInfo {
    magic: u32,
    version: u32,
    capacity: u32,
    slot_size: u32,
    head: u64,
    is_valid: bool,
}

#[cfg(target_os = "linux")]
/// Version-2 notify header fields this tool can read without the header's
/// lock.
#[derive(Debug)]
struct NotifyV2Info {
    magic: u32,
    version: u32,
    is_valid: bool,
    /// Never reset once set: the segment's last live user has already left.
    closed: bool,
    max_users: u32,
    /// Best-effort count of rows whose `state == SLOT_LIVE`, read without
    /// the header's mutex. `None` when the user table itself could not be
    /// read (e.g. a truncated file).
    live_users: Option<u32>,
}

#[cfg(target_os = "linux")]
fn main() {
    let args = Args::parse();

    if let Err(e) = run(&args) {
        eprintln!("{}: {}", "Error".red().bold(), e);
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let shm_dir = Path::new("/dev/shm");

    if !shm_dir.exists() {
        return Err("Shared memory directory /dev/shm not found".into());
    }

    // Collect segments
    let segments = if let Some(ref name) = args.segment {
        // Inspect one specific segment
        let name = name.trim_start_matches('/');
        let owner_pid = read_owner_pid(&shm_dir.join(format!("{name}.owner")));
        vec![inspect_segment(name, owner_pid)]
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

#[cfg(target_os = "linux")]
/// Split "`<digits>_<rest>`" into the parsed domain id and `rest`.
fn split_domain_then_rest(s: &str) -> Option<(u32, &str)> {
    let underscore = s.find('_')?;
    let domain: u32 = s[..underscore].parse().ok()?;
    Some((domain, &s[underscore + 1..]))
}

#[cfg(target_os = "linux")]
/// Classify a `/dev/shm` basename that is known to start with "hdds_" and
/// is not an owner sidecar.
fn classify(name: &str) -> Option<(Family, u32, Option<String>)> {
    if let Some(rest) = name.strip_prefix(NOTIFY_V2_FAMILY_PREFIX) {
        let (domain, topic) = split_domain_then_rest(rest)?;
        if topic.is_empty() {
            return None;
        }
        return Some((Family::NotifyV2, domain, Some(topic.to_string())));
    }

    if let Some(rest) = name.strip_prefix(NOTIFY_V1_FAMILY_PREFIX) {
        let (domain, topic) = split_domain_then_rest(rest)?;
        if topic.is_empty() {
            return None;
        }
        return Some((Family::NotifyLegacyV1, domain, Some(topic.to_string())));
    }

    if let Some(rest) = name.strip_prefix(RING_FAMILY_PREFIX) {
        let (domain, writer_rest) = split_domain_then_rest(rest)?;
        if writer_rest.starts_with('w') && writer_rest.len() > 1 {
            return Some((Family::Writer, domain, None));
        }
        return None;
    }

    None
}

#[cfg(target_os = "linux")]
/// Classify one `/dev/shm` entry name end to end: foreign names, owner
/// sidecars, and the three known segment families.
fn parse_shm_entry(name: &str) -> ParsedEntry {
    if !name.starts_with("hdds_") {
        return ParsedEntry::NotHdds;
    }
    if let Some(base) = name.strip_suffix(".owner") {
        return ParsedEntry::Owner(base.to_string());
    }
    match classify(name) {
        Some((family, domain, topic)) => ParsedEntry::Segment(family, domain, topic),
        None => ParsedEntry::UnrecognizedHdds,
    }
}

#[cfg(target_os = "linux")]
fn scan_hdds_segments(
    shm_dir: &Path,
    domain_filter: Option<u32>,
) -> Result<Vec<SegmentInfo>, Box<dyn std::error::Error>> {
    let mut owner_pids: HashMap<String, u32> = HashMap::new();
    let mut candidates: Vec<(String, Family, u32, Option<String>)> = Vec::new();
    let mut unrecognized: Vec<String> = Vec::new();

    for entry in fs::read_dir(shm_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = match file_name.to_str() {
            Some(n) => n.to_string(),
            None => continue,
        };

        match parse_shm_entry(&name) {
            ParsedEntry::NotHdds => continue,
            ParsedEntry::Owner(base) => {
                if let Some(pid) = read_owner_pid(&shm_dir.join(&name)) {
                    owner_pids.insert(base, pid);
                }
            }
            ParsedEntry::Segment(family, domain, topic) => {
                candidates.push((name, family, domain, topic));
            }
            ParsedEntry::UnrecognizedHdds => {
                // Unknown domain, so a domain filter can never match it.
                if domain_filter.is_none() {
                    unrecognized.push(name);
                }
            }
        }
    }

    let mut segments = Vec::new();

    for (name, family, domain, topic) in candidates {
        if let Some(filter) = domain_filter {
            if domain != filter {
                continue;
            }
        }
        let owner_pid = owner_pids.get(&name).copied();
        let path = shm_dir.join(&name);
        segments.push(build_segment_info(
            &path, name, family, domain, topic, owner_pid,
        ));
    }

    for name in unrecognized {
        let owner_pid = owner_pids.get(&name).copied();
        let file_size = fs::metadata(shm_dir.join(&name))
            .map(|m| m.len())
            .unwrap_or(0);
        segments.push(SegmentInfo {
            name,
            file_size,
            domain: None,
            topic: None,
            kind: SegmentKind::Unknown,
            owner_pid,
            error: None,
        });
    }

    // Sort by name
    segments.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(segments)
}

#[cfg(target_os = "linux")]
fn build_segment_info(
    path: &Path,
    name: String,
    family: Family,
    domain: u32,
    topic: Option<String>,
    owner_pid: Option<u32>,
) -> SegmentInfo {
    let file_size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let kind = match family {
        Family::Writer => SegmentKind::Writer(read_ring_control(path).ok()),
        Family::NotifyV2 => SegmentKind::NotifyV2(read_notify_v2_header(path).ok()),
        Family::NotifyLegacyV1 => SegmentKind::NotifyLegacyV1,
    };

    SegmentInfo {
        name,
        file_size,
        domain: Some(domain),
        topic,
        kind,
        owner_pid,
        error: None,
    }
}

#[cfg(target_os = "linux")]
/// Inspect one named segment (the `segment` CLI argument). Unlike the
/// directory scan, this accepts any name: one that is not a recognised
/// HDDS family is reported as `Unknown` rather than rejected.
fn inspect_segment(name: &str, owner_pid: Option<u32>) -> SegmentInfo {
    let path = Path::new("/dev/shm").join(name);

    match parse_shm_entry(name) {
        ParsedEntry::Segment(family, domain, topic) => {
            build_segment_info(&path, name.to_string(), family, domain, topic, owner_pid)
        }
        _ => {
            let file_size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            SegmentInfo {
                name: name.to_string(),
                file_size,
                domain: None,
                topic: None,
                kind: SegmentKind::Unknown,
                owner_pid,
                error: None,
            }
        }
    }
}

#[cfg(target_os = "linux")]
/// Read the pid recorded in an owner sidecar file, if it parses.
///
/// Mirrors the format `owner::record_owner` writes:
/// `"<version>:<pid>:<boot_id>:<pid_ns>:<start_time>"`
/// (crates/hdds/src/transport/shm/owner.rs, `OWNER_RECORD_VERSION` = "v3",
/// private there). Only the pid is useful to a viewer; this tool never
/// judges liveness the way `owner_is_dead` does, it only labels.
fn read_owner_pid(path: &Path) -> Option<u32> {
    const OWNER_RECORD_VERSION: &str = "v3";

    let content = fs::read_to_string(path).ok()?;
    let mut parts = content.split(':');
    let version = parts.next()?;
    if version != OWNER_RECORD_VERSION {
        return None;
    }
    let pid_str = parts.next()?;
    pid_str.parse().ok()
}

#[cfg(target_os = "linux")]
/// Read a ring writer segment's control block (first 24 bytes: head,
/// capacity, slot_size, magic, version -- see `RingControlInfo`).
fn read_ring_control(path: &Path) -> Result<RingControlInfo, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut buf = [0u8; 24];
    file.read_exact(&mut buf)?;

    let head = u64::from_le_bytes(buf[0..8].try_into().expect("buf[0..8] is exactly 8 bytes"));
    let capacity = u32::from_le_bytes(
        buf[8..12]
            .try_into()
            .expect("buf[8..12] is exactly 4 bytes"),
    );
    let slot_size = u32::from_le_bytes(
        buf[12..16]
            .try_into()
            .expect("buf[12..16] is exactly 4 bytes"),
    );
    let magic = u32::from_le_bytes(
        buf[16..20]
            .try_into()
            .expect("buf[16..20] is exactly 4 bytes"),
    );
    let version = u32::from_le_bytes(
        buf[20..24]
            .try_into()
            .expect("buf[20..24] is exactly 4 bytes"),
    );

    Ok(RingControlInfo {
        magic,
        version,
        capacity,
        slot_size,
        head,
        is_valid: magic == HDDS_MAGIC,
    })
}

#[cfg(target_os = "linux")]
/// Read a version-2 notify segment's fixed header fields, and best-effort
/// count its live user-table rows.
fn read_notify_v2_header(path: &Path) -> Result<NotifyV2Info, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut header = [0u8; NOTIFY_V2_USER_TABLE_OFFSET];
    file.read_exact(&mut header)?;

    let magic = u32::from_le_bytes(
        header[0..4]
            .try_into()
            .expect("header[0..4] is exactly 4 bytes"),
    );
    let version = u32::from_le_bytes(
        header[4..8]
            .try_into()
            .expect("header[4..8] is exactly 4 bytes"),
    );
    // Offset 8..12 is lock_abi: not shown, not useful to a human reader.
    let max_users = u32::from_le_bytes(
        header[12..16]
            .try_into()
            .expect("header[12..16] is exactly 4 bytes"),
    );
    let closed = u32::from_le_bytes(
        header[16..20]
            .try_into()
            .expect("header[16..20] is exactly 4 bytes"),
    ) != 0;

    let is_valid = magic == NOTIFY_V2_MAGIC && version == NOTIFY_V2_LAYOUT_VERSION;

    // Best-effort live-row count: read the user table WITHOUT taking the
    // header's robust mutex (this tool never locks or writes a product
    // segment). Each row's `state` field is read in isolation, so a row
    // mid-update could be seen as momentarily free or live; the count is a
    // snapshot, not a synchronized read. Only attempted on a header that at
    // least claims to be ours.
    let live_users = if is_valid {
        count_live_notify_rows(&mut file, max_users)
    } else {
        None
    };

    Ok(NotifyV2Info {
        magic,
        version,
        is_valid,
        closed,
        max_users,
        live_users,
    })
}

#[cfg(target_os = "linux")]
/// Count `UserSlot` rows whose `state == SLOT_LIVE`, reading from `file`'s
/// current position (right after the fixed header, i.e. the start of the
/// user table). Bounded by `max_users` and by `NOTIFY_V2_USER_TABLE_SANITY_CAP`,
/// and by how many full rows the file actually has.
fn count_live_notify_rows(file: &mut fs::File, max_users: u32) -> Option<u32> {
    let rows_to_scan = max_users.min(NOTIFY_V2_USER_TABLE_SANITY_CAP);
    if rows_to_scan == 0 {
        return Some(0);
    }

    let table_bytes = rows_to_scan as usize * NOTIFY_USER_SLOT_SIZE;
    let mut table = vec![0u8; table_bytes];
    // A short read (truncated/foreign file) is not an error: scan whatever
    // full rows came back and say so honestly via the row count, rather
    // than failing the whole header read over it.
    let read = file.read(&mut table).ok()?;
    let full_rows = read / NOTIFY_USER_SLOT_SIZE;

    let mut live = 0u32;
    for i in 0..full_rows {
        let offset = i * NOTIFY_USER_SLOT_SIZE;
        let state = u32::from_le_bytes(
            table[offset..offset + 4]
                .try_into()
                .expect("row slice is exactly 4 bytes"),
        );
        if state == NOTIFY_SLOT_LIVE {
            live += 1;
        }
    }
    Some(live)
}

#[cfg(target_os = "linux")]
fn segment_locator(seg: &SegmentInfo) -> String {
    match (seg.domain, &seg.topic) {
        (Some(d), Some(t)) => format!(" domain={d} topic={t}"),
        (Some(d), None) => format!(" domain={d}"),
        (None, _) => String::new(),
    }
}

#[cfg(target_os = "linux")]
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
    let mut notify_v2_count = 0;
    let mut notify_legacy_count = 0;

    for seg in segments {
        total_size += seg.file_size;

        let type_badge = match &seg.kind {
            SegmentKind::Writer(_) => {
                writer_count += 1;
                "WRITER".green()
            }
            SegmentKind::NotifyV2(_) => {
                notify_v2_count += 1;
                "NOTIFY-V2".blue()
            }
            SegmentKind::NotifyLegacyV1 => {
                notify_legacy_count += 1;
                "NOTIFY-LEGACY".yellow()
            }
            SegmentKind::Unknown => "UNKNOWN".yellow(),
        };

        println!(
            "  {} {} ({}){}",
            type_badge,
            seg.name.cyan(),
            format_size(seg.file_size),
            segment_locator(seg).dimmed()
        );

        if let Some(pid) = seg.owner_pid {
            println!("      Owner pid: {}", pid);
        }

        match &seg.kind {
            SegmentKind::Writer(Some(ctrl)) => {
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

                    if ctrl.capacity > 0 {
                        let capacity = u64::from(ctrl.capacity);
                        let ring_used = ctrl.head % capacity;
                        let usage_pct = (ring_used as f64 / capacity as f64) * 100.0;
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
            SegmentKind::Writer(None) => {
                println!("      {}", "Could not read ring control block".red());
            }
            SegmentKind::NotifyV2(Some(hdr)) => {
                let valid_badge = if hdr.is_valid {
                    "VALID".green()
                } else {
                    "INVALID".red()
                };
                let state_badge = if hdr.closed {
                    "CLOSED".red()
                } else {
                    "OPEN".green()
                };

                if args.verbose {
                    println!(
                        "      Magic: 0x{:08X} [{}]  Version: {}",
                        hdr.magic, valid_badge, hdr.version
                    );
                    println!("      State: {}", state_badge);
                    match hdr.live_users {
                        Some(live) => {
                            println!("      Live users: {} / {} rows", live, hdr.max_users)
                        }
                        None => {
                            println!("      Live users: {} (user table unreadable)", "?".yellow())
                        }
                    }
                } else {
                    match hdr.live_users {
                        Some(live) => println!(
                            "      [{}] [{}] users={}/{}",
                            valid_badge, state_badge, live, hdr.max_users
                        ),
                        None => println!(
                            "      [{}] [{}] users=?/{}",
                            valid_badge, state_badge, hdr.max_users
                        ),
                    }
                }
            }
            SegmentKind::NotifyV2(None) => {
                println!("      {}", "Could not read v2 notify header".red());
            }
            SegmentKind::NotifyLegacyV1 => {
                println!(
                    "      {}",
                    "legacy v1 bucket array, no header (pre-1.5.0 layout)".dimmed()
                );
            }
            SegmentKind::Unknown => {}
        }

        if let Some(ref err) = seg.error {
            println!("      {}: {}", "Error".red(), err);
        }

        println!();
    }

    // Summary
    println!("{}", "--- Summary ---".dimmed());
    println!(
        "  Segments: {} ({} writers, {} notify-v2, {} notify-legacy)",
        segments.len(),
        writer_count,
        notify_v2_count,
        notify_legacy_count
    );
    println!("  Total size: {}", format_size(total_size));
    println!("  Total messages: {}", total_messages);
    println!();
}

#[cfg(target_os = "linux")]
fn print_summary(segments: &[SegmentInfo]) {
    let mut total_size: u64 = 0;
    let mut total_messages: u64 = 0;
    let mut writer_count = 0;
    let mut notify_v2_count = 0;
    let mut notify_legacy_count = 0;
    let mut valid_count = 0;

    for seg in segments {
        total_size += seg.file_size;

        match &seg.kind {
            SegmentKind::Writer(ctrl) => {
                writer_count += 1;
                if let Some(ctrl) = ctrl {
                    if ctrl.is_valid {
                        valid_count += 1;
                    }
                    total_messages += ctrl.head;
                }
            }
            SegmentKind::NotifyV2(hdr) => {
                notify_v2_count += 1;
                if let Some(hdr) = hdr {
                    if hdr.is_valid {
                        valid_count += 1;
                    }
                }
            }
            SegmentKind::NotifyLegacyV1 => {
                notify_legacy_count += 1;
            }
            SegmentKind::Unknown => {}
        }
    }

    println!(
        "segments={} writers={} notify_v2={} notify_legacy={} valid={} size={} messages={}",
        segments.len(),
        writer_count,
        notify_v2_count,
        notify_legacy_count,
        valid_count,
        total_size,
        total_messages
    );
}

#[cfg(target_os = "linux")]
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "linux")]
fn print_json(segments: &[SegmentInfo]) {
    print!("{{\"segments\":[");

    for (i, seg) in segments.iter().enumerate() {
        if i > 0 {
            print!(",");
        }

        let seg_type = match &seg.kind {
            SegmentKind::Writer(_) => "writer",
            SegmentKind::NotifyV2(_) => "notify_v2",
            SegmentKind::NotifyLegacyV1 => "notify_legacy_v1",
            SegmentKind::Unknown => "unknown",
        };

        print!(
            "{{\"name\":\"{}\",\"type\":\"{}\",\"size\":{}",
            json_escape(&seg.name),
            seg_type,
            seg.file_size
        );

        if let Some(domain) = seg.domain {
            print!(",\"domain\":{}", domain);
        }
        if let Some(ref topic) = seg.topic {
            print!(",\"topic\":\"{}\"", json_escape(topic));
        }
        if let Some(pid) = seg.owner_pid {
            print!(",\"owner_pid\":{}", pid);
        }

        match &seg.kind {
            SegmentKind::Writer(Some(ctrl)) => {
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
            SegmentKind::NotifyV2(Some(hdr)) => {
                let live_users = match hdr.live_users {
                    Some(n) => n.to_string(),
                    None => "null".to_string(),
                };
                print!(
                    ",\"notify\":{{\"magic\":{},\"version\":{},\"valid\":{},\"closed\":{},\"max_users\":{},\"live_users\":{}}}",
                    hdr.magic, hdr.version, hdr.is_valid, hdr.closed, hdr.max_users, live_users
                );
            }
            _ => {}
        }

        if let Some(ref err) = seg.error {
            print!(",\"error\":\"{}\"", json_escape(err));
        }

        print!("}}");
    }

    println!("]}}");
}

#[cfg(target_os = "linux")]
fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// HDDS shared memory segments only exist on Linux (`/dev/shm`, `shm_open`).
/// The tool stays in every build and says so instead of failing obscurely.
#[cfg(not(target_os = "linux"))]
fn main() {
    // clap is compiled out on this platform, so answer the two flags every
    // CLI is expected to answer by hand instead of exiting 2 over them.
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "-V" | "--version" => {
            println!("hdds-shm-viewer {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        "-h" | "--help" => {
            println!("hdds-shm-viewer {}", env!("CARGO_PKG_VERSION"));
            println!("Inspect HDDS shared memory segments.");
            println!();
            println!(
                "HDDS shared memory is Linux-only (/dev/shm, shm_open), so this build accepts"
            );
            println!("--help and --version only; every other invocation exits 2.");
            return;
        }
        _ => {}
    }
    eprintln!(
        "hdds-shm-viewer: HDDS shared memory is Linux-only; nothing to inspect on this platform"
    );
    eprintln!("hdds-shm-viewer: --help and --version are the only accepted arguments here");
    std::process::exit(2);
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn classify_writer_ring_name() {
        assert_eq!(
            classify("hdds_d7_w0102030405060708090a0b0c0d0e0f10"),
            Some((Family::Writer, 7, None))
        );
    }

    #[test]
    fn classify_notify_v2_name() {
        assert_eq!(
            classify("hdds_notify_v2_d42_my_topic"),
            Some((Family::NotifyV2, 42, Some("my_topic".to_string())))
        );
    }

    #[test]
    fn classify_notify_legacy_v1_name() {
        assert_eq!(
            classify("hdds_notify_d3_rosout"),
            Some((Family::NotifyLegacyV1, 3, Some("rosout".to_string())))
        );
    }

    #[test]
    fn classify_v1_and_v2_names_never_cross_match() {
        // A v2 name must never be read as a v1 (legacy) one, or vice versa:
        // the prefixes differ ("v2_d" vs "d" right after "hdds_notify_"),
        // which is also what lets v1 and v2 peers coexist on one host
        // without corrupting each other's object (see notify.rs module doc).
        let v2 = classify("hdds_notify_v2_d0_t").unwrap();
        assert_eq!(v2.0, Family::NotifyV2);
        let v1 = classify("hdds_notify_d0_t").unwrap();
        assert_eq!(v1.0, Family::NotifyLegacyV1);
    }

    #[test]
    fn classify_rejects_malformed_names() {
        assert_eq!(classify("hdds_d7_notawriter"), None); // no 'w' marker
        assert_eq!(classify("hdds_dx_w123"), None); // domain not numeric
        assert_eq!(classify("hdds_notify_v2_d9_"), None); // empty topic
        assert_eq!(classify("hdds_notify_d9_"), None); // empty topic
        assert_eq!(classify("hdds_unrelated"), None);
    }

    #[test]
    fn parse_shm_entry_ignores_foreign_names() {
        assert_eq!(
            parse_shm_entry("some_other_app_segment"),
            ParsedEntry::NotHdds
        );
        assert_eq!(parse_shm_entry("cyclonedds_cs"), ParsedEntry::NotHdds);
        assert_eq!(parse_shm_entry(""), ParsedEntry::NotHdds);
    }

    #[test]
    fn parse_shm_entry_flags_unrecognized_hdds_names() {
        assert_eq!(
            parse_shm_entry("hdds_future_feature_x"),
            ParsedEntry::UnrecognizedHdds
        );
    }

    #[test]
    fn parse_shm_entry_treats_owner_sidecar_as_not_a_segment() {
        let name = "hdds_d7_w0102030405060708090a0b0c0d0e0f10.owner";
        assert_eq!(
            parse_shm_entry(name),
            ParsedEntry::Owner("hdds_d7_w0102030405060708090a0b0c0d0e0f10".to_string())
        );
    }

    #[test]
    fn parse_shm_entry_v2_owner_lookalike_is_still_a_sidecar() {
        // Notify segments do not have owner sidecars in the product (they
        // track liveness in their own header), but if one existed under
        // that name, it must still be classified as a sidecar, never as a
        // segment named "...topic.owner".
        let name = "hdds_notify_v2_d0_topic.owner";
        assert_eq!(
            parse_shm_entry(name),
            ParsedEntry::Owner("hdds_notify_v2_d0_topic".to_string())
        );
    }

    #[test]
    fn decode_ring_control_from_bytes() {
        // Layout per ShmControl (crates/hdds/src/transport/shm/slot.rs):
        // head: u64, capacity: u32, slot_size: u32, magic: u32, version: u32.
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&42u64.to_le_bytes());
        buf[8..12].copy_from_slice(&256u32.to_le_bytes());
        buf[12..16].copy_from_slice(&1024u32.to_le_bytes());
        buf[16..20].copy_from_slice(&HDDS_MAGIC.to_le_bytes());
        buf[20..24].copy_from_slice(&2u32.to_le_bytes());

        let head = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let capacity = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let slot_size = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let magic = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let version = u32::from_le_bytes(buf[20..24].try_into().unwrap());

        assert_eq!(head, 42);
        assert_eq!(capacity, 256);
        assert_eq!(slot_size, 1024);
        assert_eq!(magic, HDDS_MAGIC);
        assert_eq!(version, 2);
    }

    /// Builds a byte buffer matching `NotifyHeader`'s layout (notify.rs) for
    /// `rows` user-table rows, with `live_rows` of them marked SLOT_LIVE,
    /// and runs it through `read_notify_v2_header` via a real (non-/dev/shm)
    /// temp file -- this test never touches /dev/shm.
    fn write_fake_notify_segment(
        rows: usize,
        live_rows: usize,
        magic: u32,
        version: u32,
        closed: bool,
    ) -> std::path::PathBuf {
        let mut bytes = vec![0u8; NOTIFY_V2_USER_TABLE_OFFSET + rows * NOTIFY_USER_SLOT_SIZE];
        bytes[0..4].copy_from_slice(&magic.to_le_bytes());
        bytes[4..8].copy_from_slice(&version.to_le_bytes());
        // 8..12 lock_abi: irrelevant to this tool, leave zeroed.
        bytes[12..16].copy_from_slice(&(rows as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&(if closed { 1u32 } else { 0u32 }).to_le_bytes());

        for i in 0..live_rows.min(rows) {
            let offset = NOTIFY_V2_USER_TABLE_OFFSET + i * NOTIFY_USER_SLOT_SIZE;
            bytes[offset..offset + 4].copy_from_slice(&NOTIFY_SLOT_LIVE.to_le_bytes());
        }

        let path = std::env::temp_dir().join(format!(
            "hdds-shm-viewer-test-notify-{}-{}.bin",
            std::process::id(),
            rows
        ));
        fs::write(&path, &bytes).expect("write fake notify segment");
        path
    }

    #[test]
    fn decode_notify_v2_header_counts_live_rows() {
        let path =
            write_fake_notify_segment(8, 3, NOTIFY_V2_MAGIC, NOTIFY_V2_LAYOUT_VERSION, false);
        let info = read_notify_v2_header(&path).expect("decode header");
        let _ = fs::remove_file(&path);

        assert!(info.is_valid);
        assert!(!info.closed);
        assert_eq!(info.max_users, 8);
        assert_eq!(info.live_users, Some(3));
    }

    #[test]
    fn decode_notify_v2_header_flags_wrong_magic_as_invalid() {
        let path = write_fake_notify_segment(4, 1, 0xDEAD_BEEF, NOTIFY_V2_LAYOUT_VERSION, false);
        let info = read_notify_v2_header(&path).expect("decode header");
        let _ = fs::remove_file(&path);

        assert!(!info.is_valid);
        // Never scans rows on a header that does not even claim to be ours.
        assert_eq!(info.live_users, None);
    }

    #[test]
    fn decode_notify_v2_header_reports_closed_state() {
        let path = write_fake_notify_segment(2, 0, NOTIFY_V2_MAGIC, NOTIFY_V2_LAYOUT_VERSION, true);
        let info = read_notify_v2_header(&path).expect("decode header");
        let _ = fs::remove_file(&path);

        assert!(info.closed);
        assert_eq!(info.live_users, Some(0));
    }

    #[test]
    fn decode_notify_v2_header_rejects_truncated_file() {
        let path = std::env::temp_dir().join(format!(
            "hdds-shm-viewer-test-notify-truncated-{}.bin",
            std::process::id()
        ));
        fs::write(&path, [0u8; 32]).expect("write truncated file"); // < 128 bytes
        let result = read_notify_v2_header(&path);
        let _ = fs::remove_file(&path);

        assert!(result.is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod live_segment_tests {
    //! Exercises the scanner against a REAL v2 notify segment created
    //! through the product's own API, not a hand-rolled byte buffer. Only
    //! enabled by the `hdds` dev-dependency (see Cargo.toml): the shipped
    //! binary never links against `hdds`.
    use super::*;
    use hdds::transport::shm::TopicNotify;

    #[test]
    fn scan_finds_a_live_v2_notify_segment_with_one_user() {
        // A domain far outside any valid DDS domain id, carrying this
        // process's pid so a stale segment from a crashed previous run, or
        // a concurrent test binary, can never collide with it.
        let pid = std::process::id();
        let domain = 3_000_000_000u32.wrapping_add(pid);
        let topic = format!("shmviewertest_{pid}");
        let name = TopicNotify::segment_name(domain, &topic);

        let handle = TopicNotify::new(&name, true).expect("create a real v2 notify segment");

        let found = scan_hdds_segments(Path::new("/dev/shm"), Some(domain)).expect("scan /dev/shm");

        let seg = found
            .iter()
            .find(|s| s.domain == Some(domain))
            .expect("the segment just created should be listed");

        assert_eq!(seg.topic.as_deref(), Some(topic.as_str()));
        match &seg.kind {
            SegmentKind::NotifyV2(Some(hdr)) => {
                assert!(hdr.is_valid);
                assert!(!hdr.closed);
                // This process is the segment's only attached user.
                assert_eq!(hdr.live_users, Some(1));
            }
            other => panic!("expected a readable, valid v2 notify header, got {other:?}"),
        }

        drop(handle);
    }
}

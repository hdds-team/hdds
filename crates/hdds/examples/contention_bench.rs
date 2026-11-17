// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

/// Multi-thread contention benchmark for the intra-process hot path.
///
/// Exercises the lock-free structures under real thread contention:
/// - TopicMerger inline OnceLock slots + RwLock overflow (readers > 16)
/// - SlabPool reserve (CAS claim) / release (fetch_and) under N writers
/// - add_reader racing push (--churn mode: readers join mid-traffic)
/// - StatusCondition / metrics atomics on every sample
///
/// One process, one topic, N writer threads x M reader threads. Every
/// reader is bound to every writer's merger. History depth is sized to
/// the full traffic volume so best-effort intra-process delivery must
/// be EXACT: any loss, duplicate, reorder or corruption is a defect
/// (bench bug or engine race), never an acceptable drop.
///
/// Usage:
///   contention_bench <writers> <readers> <msgs_per_writer> [--churn] [--pace N]
///
/// * `--churn`  start with 1 reader; the remaining readers are created,
///   bound and started WHILE writers are mid-traffic. Writers hold at
///   25% progress until all late readers joined, so late readers are
///   guaranteed a live tail of traffic. Late readers only assert
///   no-dup + per-writer monotonic + received > 0.
/// * `--pace N` spin-loop N iterations after each write (default 0).
///
/// Machine-parseable output:
///   RESULT writers=N readers=M expected=X
///   WRITER j: written=W retries=R errors=E
///   READER k: received=Y dups=D reorder=R corrupt=C errors=E p50=P p99=Q late=0|1
///   VERDICT: PASS|FAIL
use hdds::{Error, Participant, QoS, TransportMode, DDS};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

// Same shape as latency_benchmark's BenchMessage, plus the writer_id
// field so readers can track per-writer sequences across the merge.
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct BenchMessage {
    seq: u64,
    timestamp_ns: u64,
    writer_id: u64,
}

/// Hard ceiling for a full scenario run (per reader, from traffic start).
const DEADLINE: Duration = Duration::from_secs(30);
/// After writers finish, a reader exits once no sample arrived for this long.
const DRAIN_GRACE: Duration = Duration::from_millis(500);
/// Max time a writer holds at the churn checkpoint waiting for late readers.
const CHURN_HOLD_TIMEOUT: Duration = Duration::from_secs(10);

struct Config {
    writers: usize,
    readers: usize,
    msgs_per_writer: usize,
    churn: bool,
    pace: u32,
}

#[derive(Default)]
struct WriterStats {
    written: u64,
    retries: u64,
    errors: u64,
}

#[derive(Default)]
struct ReaderStats {
    received: u64,
    dups: u64,
    reorder: u64,
    corrupt: u64,
    errors: u64,
    timed_out: bool,
    latencies: Vec<u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = parse_args()?;
    let expected = cfg.writers * cfg.msgs_per_writer;

    println!("=== HDDS Contention Benchmark ===");
    println!(
        "[CFG] writers={} readers={} msgs_per_writer={} churn={} pace={}",
        cfg.writers, cfg.readers, cfg.msgs_per_writer, cfg.churn, cfg.pace
    );

    // Intra-process only: no sockets, no discovery traffic on the host
    // (keeps interop docker matrices clean). Domain 39 = hdds project id.
    let participant = Participant::builder("contention_bench")
        .with_transport(TransportMode::IntraProcess)
        .domain_id(39)
        .build()?;
    let topic = participant.topic::<BenchMessage>("ContentionTopic")?;

    // History depth covers the FULL traffic volume so nothing is ever
    // trimmed: exact delivery is asserted for every non-late reader.
    let depth = u32::try_from(expected).map_err(|_| "scenario too large for KeepLast depth")?;

    // Writers first so reader auto-bind (domain registry) sees them all.
    let mut writers = Vec::with_capacity(cfg.writers);
    let mut mergers = Vec::with_capacity(cfg.writers);
    for _ in 0..cfg.writers {
        let writer = topic
            .writer()
            .qos(QoS::best_effort().keep_last(1))
            .build()?;
        mergers.push(writer.merger());
        writers.push(writer);
    }

    let initial_readers = if cfg.churn { 1 } else { cfg.readers };
    let mut readers = Vec::with_capacity(initial_readers);
    for _ in 0..initial_readers {
        readers.push(make_reader(&topic, depth, &mergers)?);
    }

    let writers_done = Arc::new(AtomicBool::new(false));
    let churn_ready = Arc::new(AtomicBool::new(!cfg.churn));
    // Writers + main: main crossing the barrier defines traffic start.
    let start_barrier = Arc::new(Barrier::new(cfg.writers + 1));
    let deadline = Instant::now() + DEADLINE;

    // Reader threads (initial set, expected = full traffic).
    let mut reader_handles = Vec::with_capacity(cfg.readers);
    for (k, reader) in readers.into_iter().enumerate() {
        let done = Arc::clone(&writers_done);
        let handle = thread::Builder::new()
            .name(format!("cb-reader-{k}"))
            .spawn(move || {
                reader_loop(
                    &reader,
                    cfg.writers,
                    cfg.msgs_per_writer,
                    Some(expected as u64),
                    deadline,
                    &done,
                )
            })?;
        reader_handles.push((k, false, handle));
    }

    // Writer threads.
    let churn_hold_at = (cfg.msgs_per_writer / 4).max(1) as u64;
    let mut writer_handles = Vec::with_capacity(cfg.writers);
    for (j, writer) in writers.into_iter().enumerate() {
        let barrier = Arc::clone(&start_barrier);
        let ready = Arc::clone(&churn_ready);
        let msgs = cfg.msgs_per_writer as u64;
        let pace = cfg.pace;
        let churn = cfg.churn;
        let handle = thread::Builder::new()
            .name(format!("cb-writer-{j}"))
            .spawn(move || {
                barrier.wait();
                let mut stats = WriterStats::default();
                for seq in 0..msgs {
                    // Churn checkpoint: hold at 25% until every late
                    // reader is registered, so late readers always see
                    // a live tail of traffic (received > 0 assertable).
                    if churn && seq == churn_hold_at {
                        let hold_start = Instant::now();
                        while !ready.load(Ordering::Acquire)
                            && hold_start.elapsed() < CHURN_HOLD_TIMEOUT
                        {
                            thread::yield_now();
                        }
                    }
                    let msg = BenchMessage {
                        seq,
                        timestamp_ns: get_timestamp_ns(),
                        writer_id: j as u64,
                    };
                    let attempt_start = Instant::now();
                    loop {
                        match writer.write(&msg) {
                            Ok(()) => {
                                stats.written += 1;
                                break;
                            }
                            Err(Error::WouldBlock) => {
                                // Slab pool momentarily exhausted: back
                                // off and retry until the deadline.
                                stats.retries += 1;
                                if attempt_start.elapsed() > DEADLINE {
                                    stats.errors += 1;
                                    break;
                                }
                                thread::yield_now();
                            }
                            Err(_) => {
                                stats.errors += 1;
                                break;
                            }
                        }
                    }
                    for _ in 0..pace {
                        std::hint::spin_loop();
                    }
                }
                stats
            })?;
        writer_handles.push((j, handle));
    }

    // Release the writers.
    start_barrier.wait();
    let traffic_start = Instant::now();

    // Churn: create + bind + start the late readers while traffic flows.
    if cfg.churn {
        thread::sleep(Duration::from_millis(5));
        for k in 1..cfg.readers {
            let reader = make_reader(&topic, depth, &mergers)?;
            let done = Arc::clone(&writers_done);
            let handle = thread::Builder::new()
                .name(format!("cb-reader-{k}"))
                .spawn(move || {
                    reader_loop(
                        &reader,
                        cfg.writers,
                        cfg.msgs_per_writer,
                        None, // late joiner: no exact expected count
                        deadline,
                        &done,
                    )
                })?;
            reader_handles.push((k, true, handle));
        }
        churn_ready.store(true, Ordering::Release);
    }

    // Collect writers, then signal readers to drain and exit. A panic
    // inside the engine (reader/writer hot path) must not kill the
    // report: a panicked thread is recorded and forces a FAIL verdict.
    let mut writer_stats = Vec::with_capacity(cfg.writers);
    for (j, handle) in writer_handles {
        match handle.join() {
            Ok(stats) => writer_stats.push((j, stats, false)),
            Err(_) => writer_stats.push((j, WriterStats::default(), true)),
        }
    }
    writers_done.store(true, Ordering::Release);

    let mut reader_stats = Vec::with_capacity(cfg.readers);
    for (k, late, handle) in reader_handles {
        match handle.join() {
            Ok(stats) => reader_stats.push((k, late, stats, false)),
            Err(_) => reader_stats.push((k, late, ReaderStats::default(), true)),
        }
    }
    let elapsed = traffic_start.elapsed();

    // ---- Report -------------------------------------------------------
    println!("INFO elapsed_ms={}", elapsed.as_millis());
    println!(
        "RESULT writers={} readers={} expected={}",
        cfg.writers, cfg.readers, expected
    );

    let mut pass = true;
    for (j, stats, panicked) in &writer_stats {
        println!(
            "WRITER {}: written={} retries={} errors={} panicked={}",
            j,
            stats.written,
            stats.retries,
            stats.errors,
            u8::from(*panicked)
        );
        if stats.written != cfg.msgs_per_writer as u64 || stats.errors != 0 || *panicked {
            pass = false;
            println!("INFO writer {} incomplete", j);
        }
    }

    for (k, late, stats, panicked) in &mut reader_stats {
        let (p50, p99) = percentiles(&mut stats.latencies);
        println!(
            "READER {}: received={} dups={} reorder={} corrupt={} errors={} p50={} p99={} late={} panicked={}",
            k,
            stats.received,
            stats.dups,
            stats.reorder,
            stats.corrupt,
            stats.errors,
            p50,
            p99,
            u8::from(*late),
            u8::from(*panicked)
        );
        let clean = stats.dups == 0
            && stats.reorder == 0
            && stats.corrupt == 0
            && stats.errors == 0
            && !*panicked;
        let complete = if *late {
            stats.received > 0
        } else {
            stats.received == expected as u64
        };
        if !clean || !complete {
            pass = false;
            println!(
                "INFO reader {} FAIL (clean={} complete={} timed_out={} panicked={})",
                k, clean, complete, stats.timed_out, panicked
            );
        }
    }

    println!("VERDICT: {}", if pass { "PASS" } else { "FAIL" });
    if !pass {
        std::process::exit(1);
    }
    Ok(())
}

/// Build a reader with a full-depth history and bind it to every writer
/// merger. The builder may already have auto-bound via the domain
/// registry; the reader's binding table dedups by merger identity so
/// double-binding is a no-op.
fn make_reader(
    topic: &hdds::Topic<BenchMessage>,
    depth: u32,
    mergers: &[Arc<hdds::core::rt::TopicMerger>],
) -> hdds::Result<hdds::DataReader<BenchMessage>> {
    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(depth))
        .build()?;
    for merger in mergers {
        reader.bind_to_writer(Arc::clone(merger));
    }
    Ok(reader)
}

/// Reader spin loop: take() until the expected count is reached (initial
/// readers), the writers are done and the ring drained (late readers), or
/// the deadline expires.
fn reader_loop(
    reader: &hdds::DataReader<BenchMessage>,
    writers: usize,
    msgs_per_writer: usize,
    expected: Option<u64>,
    deadline: Instant,
    writers_done: &AtomicBool,
) -> ReaderStats {
    let mut stats = ReaderStats {
        latencies: Vec::with_capacity(writers * msgs_per_writer),
        ..ReaderStats::default()
    };
    // Per-writer duplicate bitmap (seqs are dense in 0..msgs_per_writer)
    // and last-seen seq for the monotonicity check.
    let words = msgs_per_writer.div_ceil(64);
    let mut seen: Vec<Vec<u64>> = vec![vec![0u64; words]; writers];
    let mut last_seq: Vec<i64> = vec![-1; writers];
    let mut idle_since: Option<Instant> = None;

    loop {
        match reader.take() {
            Ok(Some(msg)) => {
                idle_since = None;
                let recv_ns = get_timestamp_ns();
                stats.received += 1;
                let w = msg.writer_id as usize;
                let s = msg.seq as usize;
                if w >= writers || s >= msgs_per_writer {
                    // Payload outside the scenario space: decoded bytes
                    // did not come from a live sample (slab reuse race).
                    stats.corrupt += 1;
                } else {
                    stats
                        .latencies
                        .push(recv_ns.saturating_sub(msg.timestamp_ns));
                    let (word, bit) = (s / 64, s % 64);
                    if seen[w][word] & (1u64 << bit) != 0 {
                        stats.dups += 1;
                    } else {
                        seen[w][word] |= 1u64 << bit;
                    }
                    if (s as i64) < last_seq[w] {
                        stats.reorder += 1;
                    } else {
                        last_seq[w] = s as i64;
                    }
                }
                if let Some(exp) = expected {
                    if stats.received >= exp {
                        break;
                    }
                }
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    stats.timed_out = true;
                    break;
                }
                if writers_done.load(Ordering::Acquire) {
                    let since = *idle_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= DRAIN_GRACE {
                        break;
                    }
                }
                std::hint::spin_loop();
                thread::yield_now();
            }
            Err(_) => {
                // Decode failure: torn slab read or foreign bytes.
                stats.errors += 1;
            }
        }
    }
    stats
}

fn percentiles(latencies: &mut [u64]) -> (u64, u64) {
    if latencies.is_empty() {
        return (0, 0);
    }
    latencies.sort_unstable();
    let p50 = latencies[(latencies.len() / 2).min(latencies.len() - 1)];
    let p99 = latencies[(latencies.len() * 99 / 100).min(latencies.len() - 1)];
    (p50, p99)
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positional = Vec::new();
    let mut churn = false;
    let mut pace = 0u32;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--churn" => churn = true,
            "--pace" => {
                i += 1;
                pace = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--pace requires a numeric argument")?;
            }
            other => positional.push(other.to_string()),
        }
        i += 1;
    }
    if positional.len() != 3 {
        return Err(
            "usage: contention_bench <writers> <readers> <msgs_per_writer> [--churn] [--pace N]"
                .to_string(),
        );
    }
    let parse = |s: &str, name: &str| -> Result<usize, String> {
        let v: usize = s.parse().map_err(|_| format!("invalid {name}: {s}"))?;
        if v == 0 {
            return Err(format!("{name} must be > 0"));
        }
        Ok(v)
    };
    let cfg = Config {
        writers: parse(&positional[0], "writers")?,
        readers: parse(&positional[1], "readers")?,
        msgs_per_writer: parse(&positional[2], "msgs_per_writer")?,
        churn,
        pace,
    };
    if cfg.churn && cfg.readers < 2 {
        return Err("--churn requires at least 2 readers".to_string());
    }
    Ok(cfg)
}

// Get high-resolution timestamp in nanoseconds (same approach as
// latency_benchmark.rs).
#[inline]
fn get_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

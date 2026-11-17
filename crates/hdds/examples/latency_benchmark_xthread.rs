// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! Cross-thread intra-process publisher-to-subscriber latency.
//!
//! # Why this exists, and what it is NOT
//!
//! The sibling `latency_benchmark` writes and takes on ONE thread, in a tight
//! loop. That measures the engine's transfer cost with no thread handoff and no
//! wakeup, and it is the number behind the one-thread figure. It is
//! a real number for a real usage (a polling loop), but it is not what an
//! application with a separate subscriber thread experiences.
//!
//! This benchmark measures the cross-thread path, which is the
//! "publisher-to-subscriber end-to-end" figure.
//!
//! # Two arms, deliberately, because one number would hide the split
//!
//! * `spin` - the reader thread busy-polls `take()`. This is the handoff alone:
//!   cache line transfer between two cores, no scheduler.
//! * `waitset` - the reader thread blocks in `WaitSet::wait()`. This is the
//!   handoff PLUS the wakeup, which is what a normal application pays.
//!
//! The difference between the two arms is the cost of waking a sleeping
//! reader. Reporting only the second would make the engine look slow for a
//! reason that is the kernel's; reporting only the first would oversell.
//!
//! # Pacing, and why it is not optional
//!
//! Both arms are paced by the same inter-send interval. Without pacing the
//! `waitset` reader would never actually reach sleep, the wakeup would never be
//! paid, and the arm would silently degenerate into a slower copy of `spin`.
//! The interval must stay comfortably above the measured latency for the reader
//! to be asleep when the sample lands.
//!
//! # Pinning
//!
//! The two threads are pinned to two DIFFERENT cores, taken from the
//! environment. On an SMT machine, pin to two distinct PHYSICAL cores: a pair
//! of hyperthread siblings shares an L1 and would report a handoff cost that no
//! two-core deployment ever sees. The engine's own threads are excluded from
//! both cores before the participant is built; see
//! [`reserve_cores_for_benchmark`].
//!
//! # What the numbers depend on besides the code
//!
//! Measured on a benchmark host (performance governor, 15 rounds of 10000
//! samples per arm, 200 us send interval, binary built with
//! `CARGO_PROFILE_RELEASE_LTO=thin CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`),
//! the CPU idle configuration alone moves the result:
//!
//! |         | stock idle policy | idle states past C1 disabled |
//! |---------|-------------------|------------------------------|
//! | spin    | 389 ns p50 / 675 ns p99 | 320 ns p50 / 418 ns p99 |
//! | waitset | 3440 ns p50 / 22259 ns p99 | 2765 ns p50 / 15950 ns p99 |
//!
//! The cores idle between paced sends and their exit latency lands inside the
//! measurement. Quoting a figure from this benchmark without saying which
//! column it came from makes it unreproducible.
//!
//! The build recipe matters as much: the same source as a plain
//! `cargo build --release` measured 28 ns slower on the polling arm and about
//! 100 ns slower on the blocking arm. The workspace release profile does not
//! enable LTO; the bench profile does. A/B both sides with the same flags.
//!
//! # Environment
//!
//! | Variable                    | Default | Meaning                        |
//! |-----------------------------|---------|--------------------------------|
//! | `HDDS_XBENCH_WRITER_CPU`    | 2       | core for the publishing thread |
//! | `HDDS_XBENCH_READER_CPU`    | 3       | core for the subscribing thread|
//! | `HDDS_XBENCH_MESSAGES`      | 10000   | measured samples per arm       |
//! | `HDDS_XBENCH_WARMUP`        | 2000    | discarded samples per arm      |
//! | `HDDS_XBENCH_INTERVAL_US`   | 200     | inter-send interval            |
//! | `HDDS_XBENCH_ARM`           | both    | `spin`, `waitset`, or `both`   |
//! | `HDDS_XBENCH_BURST`         | 1       | samples per burst              |
//! | `HDDS_XBENCH_BURST_GAP_US`  | 2       | gap inside a burst             |
//! | `HDDS_XBENCH_HISTORY`       | = burst | KeepLast depth on both ends    |
//! | `HDDS_XBENCH_CHURN`         | 0       | drop one reader before measuring|
//! | `HDDS_XBENCH_ATTACH_WAITSET`| 1       | polling arm attaches a WaitSet |

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::uninlined_format_args)]

use hdds::{Participant, QoS, WaitSet, DDS};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// A sample carrying its own send timestamp, in nanoseconds since the
/// benchmark's monotonic base.
#[derive(Debug, Clone, Copy, PartialEq, DDS)]
struct XMsg {
    seq: u64,
    sent_ns: u64,
}

/// Sentinel sequence number telling the reader thread to stop.
const STOP: u64 = u64::MAX;

/// Pin the calling thread to one CPU.
///
/// A failure here is fatal rather than a warning: an unpinned run produces a
/// number that looks like the others and means something else.
fn pin_to_cpu(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);
        let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        assert!(rc == 0, "sched_setaffinity to cpu {} failed", cpu);
    }
}

/// Restrict the calling thread to every online CPU EXCEPT the listed ones.
///
/// Called before the participant is built, so that every thread the engine
/// spawns inherits this mask and can never be scheduled onto a benchmark core.
/// Without it the measurement threads are pinned but the engine's own discovery
/// and receive threads are not, so one of them lands on a benchmark core every
/// few thousand samples and preempts a busy-poll reader for longer than a whole
/// send interval. That shows up as a handful of best-effort losses per run and
/// as a slow upward drift of the median, neither of which is the data path.
fn reserve_cores_for_benchmark(excluded: &[usize]) {
    // The universe is the affinity mask this process STARTED with, captured
    // once before anything pins itself. Asking the system for its CPU count
    // here is a trap: under musl,
    // `_SC_NPROCESSORS_ONLN` is answered from the CALLING THREAD's affinity
    // mask, so on the second arm - after the first arm pinned this thread to
    // one core - it returns 1, the loop then produces an empty mask, and
    // `sched_setaffinity` fails with EINVAL. Under glibc it reads sysfs and
    // hides the bug. A process under a cgroup cpuset would meet the same
    // thing on either libc.
    let universe = original_affinity();
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if libc::CPU_ISSET(cpu, &universe) && !excluded.contains(&cpu) {
                libc::CPU_SET(cpu, &mut set);
            }
        }
        assert!(
            libc::CPU_COUNT(&set) > 0,
            "excluding the benchmark cores leaves no CPU for the engine threads: \
             this process was given {} CPUs and {:?} were reserved",
            libc::CPU_COUNT(&universe),
            excluded
        );
        let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        assert!(rc == 0, "sched_setaffinity for the engine threads failed");
    }
}

/// The affinity mask the process was started with, captured on first use and
/// never recomputed. Every later question about "which CPUs may we use" is
/// answered from this, not from the current thread's mask, which the benchmark
/// itself narrows.
fn original_affinity() -> libc::cpu_set_t {
    use std::sync::OnceLock;
    // cpu_set_t is a plain bit array; wrapping it keeps OnceLock happy about
    // Send/Sync without an unsafe impl on a foreign type.
    struct Mask(libc::cpu_set_t);
    // SAFETY: a bit array with no interior mutability, written once.
    unsafe impl Send for Mask {}
    unsafe impl Sync for Mask {}
    static ORIGINAL: OnceLock<Mask> = OnceLock::new();
    ORIGINAL
        .get_or_init(|| unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            let rc = libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set);
            assert!(rc == 0, "sched_getaffinity failed");
            Mask(set)
        })
        .0
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(default)
}

/// Nanoseconds elapsed since `base`, monotonic.
///
/// `SystemTime` would be wall-clock and can step; `Instant` cannot travel
/// inside a message, so the two threads share a base instead.
#[inline]
fn now_ns(base: Instant) -> u64 {
    base.elapsed().as_nanos() as u64
}

/// Cost of one `now_ns` call, so a reader can subtract it from the latencies.
///
/// Every measured latency contains exactly two of these calls, one on each
/// side, so the floor of this benchmark is twice what this reports.
fn measure_clock_overhead(base: Instant) -> u64 {
    const REPS: u64 = 200_000;
    let start = Instant::now();
    let mut sink = 0u64;
    for _ in 0..REPS {
        sink = sink.wrapping_add(now_ns(base));
    }
    let elapsed = start.elapsed().as_nanos() as u64;
    std::hint::black_box(sink);
    elapsed / REPS
}

struct Stats {
    count: usize,
    min: u64,
    mean: u64,
    p50: u64,
    p95: u64,
    p99: u64,
    max: u64,
    /// Samples above `TAIL_THRESHOLD_NS`, counted rather than left to the
    /// percentiles. A tail whose SHAPE is a tight cluster far from the median
    /// is an external periodic event, not engine dispersion, and only a count
    /// makes that distinguishable: it scales with wall-clock time, so it moves
    /// when the send interval moves.
    above_tail: usize,
}

/// Anything past this is not the engine: the median sits two orders of
/// magnitude below it in every arm.
const TAIL_THRESHOLD_NS: u64 = 5_000;

fn summarize(mut samples: Vec<u64>) -> Option<Stats> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_unstable();
    let count = samples.len();
    Some(Stats {
        count,
        min: samples[0],
        mean: samples.iter().sum::<u64>() / count as u64,
        p50: samples[count / 2],
        p95: samples[count * 95 / 100],
        p99: samples[count * 99 / 100],
        max: samples[count - 1],
        above_tail: samples.iter().filter(|ns| **ns > TAIL_THRESHOLD_NS).count(),
    })
}

/// One arm of the benchmark.
///
/// Returns the per-sample latencies in send order, and how many samples the
/// reader never saw. A non-zero miss count invalidates the percentiles, so it
/// is returned rather than logged and forgotten.
fn run_arm(
    arm: &str,
    messages: usize,
    warmup: usize,
    interval: Duration,
    writer_cpu: usize,
    reader_cpu: usize,
) -> Result<(Vec<u64>, usize), Box<dyn std::error::Error>> {
    let base = Instant::now();
    let total = warmup + messages;

    // Order matters: the engine's threads inherit whatever mask is in force
    // when they are created, so the two benchmark cores must be reserved
    // BEFORE the participant exists.
    reserve_cores_for_benchmark(&[writer_cpu, reader_cpu]);
    let participant = Participant::builder("xthread_latency").build()?;
    let topic = participant.topic::<XMsg>("XThreadBenchTopic")?;
    // History depth follows the burst length. KeepLast(1) is the crown QoS
    // and stays the default, but under a burst a reader that falls one
    // sample behind for any reason (a page fault on the latency vector, a
    // stray interrupt) finds two entries pending, and KeepLast(1) then
    // evicts the older one by design: the loss is the QoS working, not the
    // engine, and the surviving percentiles are optimistic. A depth equal to
    // the burst keeps every sample of a burst deliverable so the numbers
    // describe the engine.
    let burst_len = env_usize("HDDS_XBENCH_BURST", 1).max(1);
    // HDDS_XBENCH_HISTORY overrides the depth without changing the pacing.
    // Its use: telling a lost wake-up apart from a scheduler stall on the
    // blocking arm. With KeepLast(1) both show up as a lost sample; with a
    // deeper history a stall merely delays the sample while a lost wake-up
    // still strands it until the next write.
    let history =
        u32::try_from(env_usize("HDDS_XBENCH_HISTORY", burst_len).max(1)).unwrap_or(u32::MAX);
    let writer = topic
        .writer()
        .qos(QoS::best_effort().keep_last(history))
        .build()?;

    // Reader churn: create and drop a reader on this writer BEFORE the
    // measured one exists (HDDS_XBENCH_CHURN=1). This is the topology an
    // application that recreates subscribers leaves behind, rmw_hdds
    // included. The merger's single-reader fast path must survive it: a
    // dropped reader's tombstone must not keep counting, or every later push
    // takes the fan-out loop. A fresh pair cannot show that cost; this knob
    // lets the benchmark expose it.
    if env_usize("HDDS_XBENCH_CHURN", 0) != 0 {
        let churned = topic
            .reader()
            .qos(QoS::best_effort().keep_last(1))
            .build()?;
        churned.bind_to_writer(writer.merger());
        drop(churned);
    }

    let reader = topic
        .reader()
        .qos(QoS::best_effort().keep_last(history))
        .build()?;
    reader.bind_to_writer(writer.merger());

    // The reader owns a WaitSet in both arms so that the two arms differ in
    // exactly one thing: whether the thread blocks or polls. The polling arm
    // can opt out of attaching it (HDDS_XBENCH_ATTACH_WAITSET=0): a perf
    // census showed the writer spending a third of its cycles notifying a
    // WaitSet nobody was sleeping on, and this is the A/B that says how much
    // of that lands on the latency path rather than on the writer alone.
    let blocking = arm == "waitset";
    let attach = blocking || env_usize("HDDS_XBENCH_ATTACH_WAITSET", 1) != 0;
    let waitset = WaitSet::new();
    if attach {
        waitset.attach(&reader)?;
    }
    let (ready_tx, ready_rx) = mpsc::channel::<()>();

    let reader_thread = thread::spawn(move || -> (Vec<u64>, usize) {
        pin_to_cpu(reader_cpu);
        let mut latencies = Vec::with_capacity(total);
        let mut seen = 0usize;
        let _ = ready_tx.send(());

        loop {
            if blocking {
                // A timeout rather than an unbounded wait: a dropped sample
                // must end the run with a miss count, not hang the harness.
                if waitset.wait(Some(Duration::from_secs(5))).is_err() {
                    break;
                }
            }
            match reader.take() {
                Ok(Some(msg)) => {
                    let arrival = now_ns(base);
                    if msg.seq == STOP {
                        break;
                    }
                    seen += 1;
                    latencies.push(arrival.saturating_sub(msg.sent_ns));
                }
                Ok(None) => {
                    if !blocking {
                        std::hint::spin_loop();
                    }
                }
                Err(_) => break,
            }
        }
        (latencies, total - seen.min(total))
    });

    pin_to_cpu(writer_cpu);
    ready_rx.recv()?;

    // Burst pacing: `burst_len` samples `burst_gap` apart, then `interval`
    // before the next burst. With burst_len == 1 this is the plain paced
    // regime. A paced regime cannot judge a spin-before-park design: the
    // spin budget expires before the next sample arrives and the measured
    // gain is nil by construction. Only a burst shows whether a reader that
    // was just woken stays awake for the samples that follow.
    let burst_len = burst_len as u64;
    let burst_gap = Duration::from_micros(env_usize("HDDS_XBENCH_BURST_GAP_US", 2) as u64);
    let mut deadline = Instant::now();
    for seq in 0..total as u64 {
        deadline += if burst_len > 1 && seq % burst_len != 0 {
            burst_gap
        } else {
            interval
        };
        let now = Instant::now();
        if deadline > now {
            // Sub-interval gaps are spun, not slept: a sleep of a few
            // microseconds is a timer slack lottery and would put the writer
            // core to sleep in the middle of the burst it is supposed to
            // sustain.
            if deadline - now < Duration::from_micros(50) {
                while Instant::now() < deadline {
                    std::hint::spin_loop();
                }
            } else {
                thread::sleep(deadline - now);
            }
        }
        writer.write(&XMsg {
            seq,
            sent_ns: now_ns(base),
        })?;
    }

    // The history is KeepLast(1), so a sentinel sent too soon evicts sample N
    // and is then indistinguishable from a genuine best-effort drop. Wait far
    // longer than any observed latency before sending it, and send it more than
    // once in case the reader was mid-take on the first.
    thread::sleep(interval.max(Duration::from_millis(20)));
    for _ in 0..3 {
        writer.write(&XMsg {
            seq: STOP,
            sent_ns: now_ns(base),
        })?;
        thread::sleep(Duration::from_millis(1));
    }

    let (mut latencies, missed) = reader_thread
        .join()
        .map_err(|_| "reader thread panicked".to_string())?;

    // Discard the warm-up prefix only now, so the miss count above covers the
    // whole run rather than the measured tail alone.
    let drained = latencies.split_off(warmup.min(latencies.len()));
    Ok((drained, missed))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let writer_cpu = env_usize("HDDS_XBENCH_WRITER_CPU", 2);
    let reader_cpu = env_usize("HDDS_XBENCH_READER_CPU", 3);
    let messages = env_usize("HDDS_XBENCH_MESSAGES", 10_000);
    let warmup = env_usize("HDDS_XBENCH_WARMUP", 2_000);
    let interval_us = env_usize("HDDS_XBENCH_INTERVAL_US", 200);
    let arm = std::env::var("HDDS_XBENCH_ARM").unwrap_or_else(|_| "both".to_string());

    assert!(
        writer_cpu != reader_cpu,
        "writer and reader must sit on different cores"
    );

    let base = Instant::now();
    let clock_ns = measure_clock_overhead(base);

    println!("=== HDDS cross-thread intra-process latency ===");
    println!("Writer CPU:   {}", writer_cpu);
    println!("Reader CPU:   {}", reader_cpu);
    println!("Messages:     {}", messages);
    println!("Warmup:       {}", warmup);
    println!("Interval:     {} us", interval_us);
    println!(
        "Clock cost:   {} ns per timestamp (two per sample)",
        clock_ns
    );

    let arms: &[&str] = match arm.as_str() {
        "spin" => &["spin"],
        "waitset" => &["waitset"],
        _ => &["spin", "waitset"],
    };

    for name in arms {
        let (latencies, missed) = run_arm(
            name,
            messages,
            warmup,
            Duration::from_micros(interval_us as u64),
            writer_cpu,
            reader_cpu,
        )?;

        println!("\n--- arm: {} ---", name);
        println!("{}_missed: {}", name, missed);
        match summarize(latencies) {
            Some(stats) => {
                println!("{}_samples:  {}", name, stats.count);
                println!("{}_min_ns:   {}", name, stats.min);
                println!("{}_mean_ns:  {}", name, stats.mean);
                println!("{}_p50_ns:   {}", name, stats.p50);
                println!("{}_p95_ns:   {}", name, stats.p95);
                println!("{}_p99_ns:   {}", name, stats.p99);
                println!("{}_max_ns:   {}", name, stats.max);
                println!(
                    "{}_above_{}us: {}",
                    name,
                    TAIL_THRESHOLD_NS / 1000,
                    stats.above_tail
                );
            }
            None => println!("{}_samples:  0 (NO DATA)", name),
        }
    }

    Ok(())
}

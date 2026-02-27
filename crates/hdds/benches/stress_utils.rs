// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![cfg(feature = "bench-stress")]
#![allow(dead_code)] // Benchmark utilities, not all used yet
#![allow(unused_imports)] // Preparation imports
#![allow(clippy::missing_panics_doc)] // Benchmark utilities panic on failure
#![allow(clippy::cast_possible_truncation)] // Benchmark casts
#![allow(clippy::cast_precision_loss)] // Stats precision loss acceptable
#![allow(clippy::uninlined_format_args)] // Benchmark code readability
#![allow(clippy::doc_markdown)] // Benchmark docs
#![allow(clippy::unreadable_literal)] // Benchmark constants
#![allow(clippy::borrow_as_ptr)] // Benchmark pointer operations
#![allow(clippy::items_after_statements)] // Benchmark helpers
#![allow(clippy::wildcard_imports)] // Test utilities
#![allow(clippy::module_name_repetitions)] // Benchmark module names
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::semicolon_if_nothing_returned)] // Benchmark code formatting
#![allow(clippy::redundant_closure_for_method_calls)] // Test code clarity
#![allow(clippy::similar_names)] // Test variable naming
#![allow(clippy::shadow_unrelated)] // Test scoping
#![allow(clippy::needless_pass_by_value)] // Test functions
#![allow(clippy::cast_possible_wrap)] // Test conversions
#![allow(clippy::single_match_else)] // Test clarity
#![allow(clippy::needless_continue)] // Test logic
#![allow(clippy::cast_lossless)] // Test simplicity
#![allow(clippy::match_wild_err_arm)] // Test error handling
#![allow(clippy::explicit_iter_loop)] // Test iteration
#![allow(clippy::must_use_candidate)] // Test functions
#![allow(clippy::if_not_else)] // Test conditionals
#![allow(clippy::map_unwrap_or)] // Test options
#![allow(clippy::match_wildcard_for_single_variants)] // Test patterns
#![allow(clippy::ignored_unit_patterns)] // Test closures
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::missing_errors_doc)] // Benchmark utilities

/// Stress Benchmark Utilities
///
/// Provides helpers for:
/// - Thread CPU affinity (Linux)
/// - Latency statistics computation (p50, p95, p99, p99.9, p99.99, max)
/// - CSV export for benchmark results
use std::fs::File;
use std::io::Write;

/// Topology types for stress benchmarks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    OneToOne,
    OneToN { readers: usize },
    NToOne { writers: usize },
    NToM { writers: usize, readers: usize },
}

impl std::fmt::Display for Topology {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Topology::OneToOne => write!(f, "1to1"),
            Topology::OneToN { readers } => write!(f, "1to{}", readers),
            Topology::NToOne { writers } => write!(f, "{}to1", writers),
            Topology::NToM { writers, readers } => write!(f, "{}to{}", writers, readers),
        }
    }
}

/// Latency statistics
#[derive(Debug, Clone, Copy)]
pub struct LatencyStats {
    pub min_ns: u64,
    pub mean_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub p9999_ns: u64,
    pub max_ns: u64,
    pub count: usize,
}

impl LatencyStats {
    /// Compute latency statistics from sorted samples
    pub fn from_sorted(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::zero();
        }

        let count = samples.len();
        let sum: u64 = samples.iter().sum();
        let mean_ns = sum / count as u64;

        Self {
            min_ns: samples[0],
            mean_ns,
            p50_ns: percentile(samples, 50.0),
            p95_ns: percentile(samples, 95.0),
            p99_ns: percentile(samples, 99.0),
            p999_ns: percentile(samples, 99.9),
            p9999_ns: percentile(samples, 99.99),
            max_ns: samples[count - 1],
            count,
        }
    }

    /// Create zero stats (for empty samples)
    pub fn zero() -> Self {
        Self {
            min_ns: 0,
            mean_ns: 0,
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
            p999_ns: 0,
            p9999_ns: 0,
            max_ns: 0,
            count: 0,
        }
    }
}

/// Compute percentile from sorted samples
fn percentile(samples: &[u64], pct: f64) -> u64 {
    if samples.is_empty() {
        return 0;
    }
    let idx = ((samples.len() as f64) * (pct / 100.0)) as usize;
    let idx = idx.min(samples.len() - 1);
    samples[idx]
}

/// Benchmark result for one configuration
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub topology: Topology,
    pub payload_bytes: usize,
    pub keep_last: usize,
    pub num_messages: usize,
    pub latency: LatencyStats,
    pub throughput_msg_s: f64,
    pub drops: u64,
}

impl BenchResult {
    /// Export to CSV line
    pub fn to_csv_line(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{:.0},{}\n",
            self.topology,
            self.payload_bytes,
            self.keep_last,
            self.num_messages,
            self.latency.min_ns,
            self.latency.p50_ns,
            self.latency.p95_ns,
            self.latency.p99_ns,
            self.latency.p999_ns,
            self.latency.max_ns,
            self.throughput_msg_s,
            self.drops
        )
    }

    /// CSV header
    pub fn csv_header() -> &'static str {
        "topology,payload_bytes,keep_last,num_messages,min_ns,p50_ns,p95_ns,p99_ns,p999_ns,max_ns,throughput_msg_s,drops\n"
    }
}

/// Export benchmark results to CSV
pub fn export_csv(results: &[BenchResult], path: &str) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(BenchResult::csv_header().as_bytes())?;
    for result in results {
        file.write_all(result.to_csv_line().as_bytes())?;
    }
    Ok(())
}

/// Set thread affinity to a specific CPU core (Linux only)
#[cfg(target_os = "linux")]
pub fn set_thread_affinity(core_id: usize) -> Result<(), String> {
    use std::mem;

    unsafe {
        let mut cpu_set: libc::cpu_set_t = mem::zeroed();
        libc::CPU_SET(core_id, &mut cpu_set);

        let result = libc::sched_setaffinity(
            0, // current thread
            mem::size_of::<libc::cpu_set_t>(),
            &cpu_set,
        );

        if result == 0 {
            Ok(())
        } else {
            Err(format!("Failed to set affinity to core {}", core_id))
        }
    }
}

/// Set thread affinity (stub for non-Linux platforms)
#[cfg(not(target_os = "linux"))]
pub fn set_thread_affinity(core_id: usize) -> Result<(), String> {
    eprintln!(
        "Warning: Thread affinity not supported on this platform (core_id={})",
        core_id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{export_csv, percentile, BenchResult, LatencyStats, Topology};

    #[test]
    fn test_latency_stats_computation() {
        let samples = vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000];
        let stats = LatencyStats::from_sorted(&samples);

        assert_eq!(stats.min_ns, 100);
        assert_eq!(stats.max_ns, 1000);
        assert_eq!(stats.mean_ns, 550);
        assert_eq!(stats.p50_ns, 500);
        assert_eq!(stats.count, 10);
    }

    #[test]
    fn test_latency_stats_empty() {
        let samples: Vec<u64> = vec![];
        let stats = LatencyStats::from_sorted(&samples);

        assert_eq!(stats.count, 0);
        assert_eq!(stats.min_ns, 0);
        assert_eq!(stats.max_ns, 0);
    }

    #[test]
    fn test_csv_export_format() {
        let result = BenchResult {
            topology: Topology::OneToOne,
            payload_bytes: 64,
            keep_last: 10,
            num_messages: 1000,
            latency: LatencyStats {
                min_ns: 100,
                mean_ns: 550,
                p50_ns: 500,
                p95_ns: 900,
                p99_ns: 950,
                p999_ns: 990,
                p9999_ns: 999,
                max_ns: 1000,
                count: 1000,
            },
            throughput_msg_s: 500_000.0,
            drops: 0,
        };

        let csv_line = result.to_csv_line();
        assert!(csv_line.contains("1to1"));
        assert!(csv_line.contains("64"));
        assert!(csv_line.contains("10"));
        assert!(csv_line.contains("500000"));
    }

    #[test]
    fn test_topology_display() {
        assert_eq!(Topology::OneToOne.to_string(), "1to1");
        assert_eq!(Topology::OneToN { readers: 3 }.to_string(), "1to3");
        assert_eq!(Topology::NToOne { writers: 3 }.to_string(), "3to1");
        assert_eq!(
            Topology::NToM {
                writers: 3,
                readers: 3
            }
            .to_string(),
            "3to3"
        );
    }
}

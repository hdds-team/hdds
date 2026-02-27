// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com
//!
//! Benchmark: DataReader Cache API - read() vs take() performance
//!
//! Validates Phase 4 criterion: take() <= 5% regression vs direct ring pop
//!
//! This benchmarks the cache layer operations directly, isolated from network I/O.

#![allow(clippy::uninlined_format_args)]
#![allow(dead_code)]

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hdds::core::rt::{IndexEntry, IndexRing, SlabHandle};

// ============================================================================
// Simulate the cache operations for benchmarking
// ============================================================================

/// Simulated cache entry (mirrors CachedSample structure)
#[derive(Clone)]
struct CacheEntry {
    data: [u8; 64], // Simulated payload
    seq: u64,
}

/// Simple cache for benchmarking (mirrors SampleCache behavior)
struct BenchCache {
    buffer: parking_lot::Mutex<Vec<CacheEntry>>,
    read_cursor: std::sync::atomic::AtomicUsize,
}

impl BenchCache {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: parking_lot::Mutex::new(Vec::with_capacity(capacity)),
            read_cursor: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn push(&self, entry: CacheEntry) {
        self.buffer.lock().push(entry);
    }

    /// Simulates take() - removes from front
    fn take(&self) -> Option<CacheEntry> {
        let mut buffer = self.buffer.lock();
        if buffer.is_empty() {
            return None;
        }
        Some(buffer.remove(0))
    }

    /// Simulates read() - clones without removing
    fn read(&self) -> Option<CacheEntry> {
        let buffer = self.buffer.lock();
        let cursor = self.read_cursor.load(std::sync::atomic::Ordering::Relaxed);
        if cursor >= buffer.len() {
            return None;
        }
        self.read_cursor
            .store(cursor + 1, std::sync::atomic::Ordering::Relaxed);
        Some(buffer[cursor].clone())
    }

    fn clear(&self) {
        self.buffer.lock().clear();
        self.read_cursor
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

// ============================================================================
// Benchmarks
// ============================================================================

/// Benchmark: Direct ring pop (baseline - what try_take() essentially does)
fn bench_ring_pop(c: &mut Criterion) {
    let mut group = c.benchmark_group("reader_api");

    group.bench_function("ring_pop_baseline", |b| {
        let ring = IndexRing::with_capacity(1024);
        let mut seq = 0u32;

        b.iter(|| {
            // Push then pop (simulates write->read flow)
            let entry = IndexEntry::new(seq, SlabHandle(seq), 64);
            seq = seq.wrapping_add(1);
            ring.push(entry);
            let result = ring.pop();
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark: Cache take() operation (new API)
fn bench_cache_take(c: &mut Criterion) {
    let mut group = c.benchmark_group("reader_api");

    group.bench_function("cache_take", |b| {
        let cache = BenchCache::new(1024);
        let mut seq = 0u64;

        b.iter(|| {
            cache.push(CacheEntry {
                data: [0u8; 64],
                seq,
            });
            seq += 1;
            let result = cache.take();
            black_box(result)
        })
    });

    group.finish();
}

/// Benchmark: Cache read() operation (new API - non-destructive)
fn bench_cache_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("reader_api");

    group.bench_function("cache_read", |b| {
        let cache = BenchCache::new(1024);
        let mut seq = 0u64;

        b.iter(|| {
            cache.clear();
            cache.push(CacheEntry {
                data: [0u8; 64],
                seq,
            });
            seq += 1;
            let result = cache.read();
            black_box(result)
        })
    });

    group.finish();
}

/// Summary comparison benchmark - THE KEY COMPARISON
fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("take_comparison");

    // Ring pop only (try_take baseline - excludes slab operations)
    group.bench_function("try_take_ring_only", |b| {
        let ring = IndexRing::with_capacity(1024);
        let mut seq = 0u32;

        b.iter(|| {
            let entry = IndexEntry::new(seq, SlabHandle(seq), 64);
            seq = seq.wrapping_add(1);
            ring.push(entry);
            let result = ring.pop();
            black_box(result)
        })
    });

    // Cache take (new API)
    group.bench_function("take_cache_new_api", |b| {
        let cache = BenchCache::new(1024);
        let mut seq = 0u64;

        b.iter(|| {
            cache.push(CacheEntry {
                data: [0u8; 64],
                seq,
            });
            seq += 1;
            let result = cache.take();
            black_box(result)
        })
    });

    // Cache read (new API - the new feature)
    group.bench_function("read_cache_new_api", |b| {
        let cache = BenchCache::new(1024);

        b.iter(|| {
            cache.clear();
            cache.push(CacheEntry {
                data: [0u8; 64],
                seq: 1,
            });
            let result = cache.read();
            black_box(result)
        })
    });

    group.finish();
}

/// Throughput benchmark: Batch operations
fn bench_batch_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("reader_api_throughput");

    for batch_size in [10, 100].iter() {
        // Ring-based batch (baseline)
        group.bench_with_input(
            BenchmarkId::new("ring_batch", batch_size),
            batch_size,
            |b, &size| {
                let ring = IndexRing::with_capacity(2048);

                b.iter(|| {
                    // Fill ring
                    for i in 0..size {
                        ring.push(IndexEntry::new(i as u32, SlabHandle(i as u32), 64));
                    }
                    // Drain ring
                    let mut count = 0;
                    while ring.pop().is_some() {
                        count += 1;
                    }
                    black_box(count)
                })
            },
        );

        // Cache-based batch (new API)
        group.bench_with_input(
            BenchmarkId::new("cache_batch", batch_size),
            batch_size,
            |b, &size| {
                let cache = BenchCache::new(2048);

                b.iter(|| {
                    // Fill cache
                    for i in 0..size {
                        cache.push(CacheEntry {
                            data: [0u8; 64],
                            seq: i as u64,
                        });
                    }
                    // Drain cache
                    let mut count = 0;
                    while cache.take().is_some() {
                        count += 1;
                    }
                    black_box(count)
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    reader_api_benches,
    bench_ring_pop,
    bench_cache_take,
    bench_cache_read,
    bench_comparison,
);

criterion_group!(
    name = throughput_benches;
    config = Criterion::default().sample_size(50);
    targets = bench_batch_throughput
);

criterion_main!(reader_api_benches, throughput_benches);

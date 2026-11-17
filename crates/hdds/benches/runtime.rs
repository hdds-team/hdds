// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

#![allow(clippy::uninlined_format_args)] // Test/bench code readability over pedantic
#![allow(clippy::cast_precision_loss)] // Stats/metrics need this
#![allow(clippy::cast_sign_loss)] // Test data conversions
#![allow(clippy::cast_possible_truncation)] // Test parameters
#![allow(clippy::float_cmp)] // Test assertions with constants
#![allow(clippy::unreadable_literal)] // Large test constants
#![allow(clippy::doc_markdown)] // Test documentation
#![allow(clippy::missing_panics_doc)] // Tests/examples panic on failure
#![allow(clippy::missing_errors_doc)] // Test documentation
#![allow(clippy::items_after_statements)] // Test helpers
#![allow(clippy::module_name_repetitions)] // Test modules
#![allow(clippy::too_many_lines)] // Example/test code
#![allow(clippy::match_same_arms)] // Test pattern matching
#![allow(clippy::no_effect_underscore_binding)] // Test variables
#![allow(clippy::semicolon_if_nothing_returned)] // Benchmark code formatting
#![allow(clippy::wildcard_imports)] // Test utility imports
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

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hdds::core::rt::{IndexEntry, IndexRing, MergerReader, SlabHandle, SlabPool, TopicMerger};
use hdds::qos::{LargePoolConfig, MemoryPolicy};
use std::cell::Cell;
use std::sync::Arc;

// ============================================================================
// SlabPool Benchmarks
// ============================================================================

/// Benchmark: SlabPool::reserve (16B allocation)
/// Target: < 50 ns
fn bench_slabpool_reserve_16b(c: &mut Criterion) {
    c.bench_function("slabpool_reserve_16b", |b| {
        let pool = SlabPool::new();
        b.iter(|| {
            let (handle, _) = pool.reserve(black_box(16)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::reserve (256B allocation)
/// Target: < 50 ns
fn bench_slabpool_reserve_256b(c: &mut Criterion) {
    c.bench_function("slabpool_reserve_256b", |b| {
        let pool = SlabPool::new();
        b.iter(|| {
            let (handle, _) = pool.reserve(black_box(256)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::reserve (1KB allocation)
/// Target: < 50 ns
fn bench_slabpool_reserve_1kb(c: &mut Criterion) {
    c.bench_function("slabpool_reserve_1kb", |b| {
        let pool = SlabPool::new();
        b.iter(|| {
            let (handle, _) = pool.reserve(black_box(1024)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::release
/// Target: < 50 ns
fn bench_slabpool_release(c: &mut Criterion) {
    c.bench_function("slabpool_release", |b| {
        let pool = SlabPool::new();
        b.iter(|| {
            let (handle, _) = pool.reserve(256).unwrap();
            pool.release(black_box(handle));
        })
    });
}

/// Benchmark: SlabPool reserve + release cycle
/// Target: < 150 ns total
fn bench_slabpool_full_cycle(c: &mut Criterion) {
    c.bench_function("slabpool_full_cycle", |b| {
        let pool = SlabPool::new();
        b.iter(|| {
            let (handle, _) = pool.reserve(black_box(256)).unwrap();
            pool.release(handle);
        })
    });
}

// ============================================================================
// IndexRing Benchmarks
// ============================================================================

/// Benchmark: IndexRing::push (SPSC producer)
/// Target: < 50 ns (single atomic write)
fn bench_indexring_push(c: &mut Criterion) {
    let ring = IndexRing::with_capacity(1024);
    let seq = Cell::new(0u32);
    let occupancy = Cell::new(0usize);
    let capacity = 1024;

    c.bench_function("indexring_push", |b| {
        b.iter_batched(
            || {
                if occupancy.get() >= capacity - 1 && ring.pop().is_some() {
                    occupancy.set(occupancy.get() - 1);
                }
            },
            |_| {
                let entry = IndexEntry::new(
                    seq.get(),
                    SlabHandle::legacy_handle_to_primary(seq.get()),
                    0,
                );
                seq.set(seq.get().wrapping_add(1));
                let pushed = ring.push(black_box(entry));
                debug_assert!(pushed);
                occupancy.set(occupancy.get() + 1);
                black_box(pushed);
            },
            BatchSize::SmallInput,
        )
    });
}

/// Benchmark: IndexRing::pop (SPSC consumer)
/// Target: < 50 ns (single atomic read)
fn bench_indexring_pop(c: &mut Criterion) {
    let ring = IndexRing::with_capacity(1024);
    let seq = Cell::new(0u32);
    let occupancy = Cell::new(0usize);

    c.bench_function("indexring_pop", |b| {
        b.iter_batched(
            || {
                if occupancy.get() == 0 {
                    let entry = IndexEntry::new(
                        seq.get(),
                        SlabHandle::legacy_handle_to_primary(seq.get()),
                        0,
                    );
                    seq.set(seq.get().wrapping_add(1));
                    let pushed = ring.push(entry);
                    debug_assert!(pushed);
                    occupancy.set(occupancy.get() + 1);
                }
            },
            |_| {
                let popped = ring.pop();
                debug_assert!(popped.is_some());
                occupancy.set(occupancy.get() - 1);
                black_box(popped);
            },
            BatchSize::SmallInput,
        )
    });
}

/// Benchmark: Full SPSC cycle (push -> pop)
/// Target: < 100 ns total
fn bench_indexring_roundtrip(c: &mut Criterion) {
    let ring = IndexRing::with_capacity(1024);
    let mut seq: u32 = 0;

    c.bench_function("indexring_roundtrip", |b| {
        b.iter(|| {
            let entry = IndexEntry::new(seq, SlabHandle::legacy_handle_to_primary(seq), 0);
            seq = seq.wrapping_add(1);
            ring.push(black_box(entry));
            let popped = ring.pop();
            debug_assert!(popped.is_some());
            black_box(popped);
        })
    });
}

/// Benchmark: TopicMerger::push (fan-out to N readers)
/// Target: < 500 ns for N=5
fn bench_topicmerger_push_5subs(c: &mut Criterion) {
    let merger = TopicMerger::new();
    // Local pool for push()'s refcount side-table traffic. The fixture
    // handles reference unclaimed slots (id masked into the 64-slot
    // class-0 range), so the counters drift but nothing is ever freed.
    let pool = SlabPool::new();
    let mut subscribers = Vec::new();
    let occupancies: Vec<Cell<usize>> = (0..5).map(|_| Cell::new(0usize)).collect();
    let notify = Arc::new(|| {});
    for _ in 0..5 {
        let ring = Arc::new(IndexRing::with_capacity(256));
        merger.add_reader(MergerReader::new(ring.clone(), notify.clone()));
        subscribers.push(ring);
    }
    let seq = Cell::new(0u32);

    c.bench_function("topicmerger_push_5subs", |b| {
        b.iter_batched(
            || {
                for (ring, occ) in subscribers.iter().zip(occupancies.iter()) {
                    if occ.get() > 0 {
                        let _ = ring.pop();
                        occ.set(occ.get() - 1);
                    }
                }
            },
            |_| {
                let entry = IndexEntry::new(
                    seq.get(),
                    SlabHandle::legacy_handle_to_primary(seq.get() & 63),
                    0,
                );
                seq.set(seq.get().wrapping_add(1));
                let pushed = merger.push(black_box(entry), &pool);
                debug_assert!(pushed);
                for occ in occupancies.iter() {
                    occ.set(occ.get() + 1);
                }
                black_box(pushed);
            },
            BatchSize::SmallInput,
        )
    });
}

// ============================================================================
// Integrated Benchmarks (SlabPool + IndexRing)
// ============================================================================

/// Benchmark: Full message flow (reserve + push + pop + release)
/// Target: < 150 ns total
fn bench_full_message_flow(c: &mut Criterion) {
    c.bench_function("full_message_flow", |b| {
        let pool = SlabPool::new();
        let ring = IndexRing::with_capacity(1024);

        b.iter(|| {
            // Writer path: reserve buffer
            let (handle, _buf) = pool.reserve(black_box(256)).unwrap();

            // Enqueue to ring
            let entry = IndexEntry::new(1, handle, 256);
            ring.push(entry);

            // Reader path: dequeue from ring
            let popped = ring.pop().unwrap();

            // Release buffer
            pool.release(popped.handle);
        })
    });
}

/// Benchmark: SlabPool::reserve_and_write primary-hit (256B).
///
/// Primary-hit regression guard for the SlabHandle enum migration. The
/// allocation path goes through Tier 1 (primary 14-class pool) and the
/// returned handle is the `SlabHandle::Primary { pool_id, slot_id }`
/// variant. Compare against `slabpool_reserve_256b` (the streaming API
/// retained for write_intra_process_fast) to surface any enum-dispatch
/// regression versus the legacy struct(u32) layout.
fn bench_slabpool_reserve_and_write_primary_256b(c: &mut Criterion) {
    let pool = SlabPool::new();
    let payload = vec![0xABu8; 256];
    c.bench_function("slabpool_reserve_and_write_primary_256b", |b| {
        b.iter(|| {
            let handle = pool.bench_reserve_and_write(black_box(&payload)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::reserve_and_write primary-hit at 1 KB.
fn bench_slabpool_reserve_and_write_primary_1kb(c: &mut Criterion) {
    let pool = SlabPool::new();
    let payload = vec![0xABu8; 1024];
    c.bench_function("slabpool_reserve_and_write_primary_1kb", |b| {
        b.iter(|| {
            let handle = pool.bench_reserve_and_write(black_box(&payload)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::reserve_and_write primary-hit at 4 KB.
fn bench_slabpool_reserve_and_write_primary_4kb(c: &mut Criterion) {
    let pool = SlabPool::new();
    let payload = vec![0xABu8; 4096];
    c.bench_function("slabpool_reserve_and_write_primary_4kb", |b| {
        b.iter(|| {
            let handle = pool.bench_reserve_and_write(black_box(&payload)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::reserve_and_write primary-hit at 16 KB.
fn bench_slabpool_reserve_and_write_primary_16kb(c: &mut Criterion) {
    let pool = SlabPool::new();
    let payload = vec![0xABu8; 16_384];
    c.bench_function("slabpool_reserve_and_write_primary_16kb", |b| {
        b.iter(|| {
            let handle = pool.bench_reserve_and_write(black_box(&payload)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::reserve_and_write large-hit (256 KB).
///
/// 200 KB payload exceeds the 128 KB primary ceiling and lands in the
/// secondary `Large` tier configured with a 256 KB class.
fn bench_slabpool_reserve_and_write_large_200kb(c: &mut Criterion) {
    let policy = MemoryPolicy {
        large_pool: LargePoolConfig {
            classes: vec![(262_144, 8)],
        },
        max_heap_bytes: 16 * 1024 * 1024,
        ..MemoryPolicy::default()
    };
    let pool = SlabPool::with_policy(&policy);
    let payload = vec![0xCDu8; 200_000];
    c.bench_function("slabpool_reserve_and_write_large_200kb", |b| {
        b.iter(|| {
            let handle = pool.bench_reserve_and_write(black_box(&payload)).unwrap();
            pool.release(handle);
        })
    });
}

/// Benchmark: SlabPool::reserve_and_write heap-fallback (200 KB) without
/// secondary pool. The allocation always reaches Tier 3 because the
/// payload exceeds the 128 KB primary ceiling and the large pool is
/// disabled. `Box::new_uninit_slice` + `copy_nonoverlapping` are the
/// hot operations under measurement.
fn bench_slabpool_reserve_and_write_heap_200kb(c: &mut Criterion) {
    let policy = MemoryPolicy {
        large_pool: LargePoolConfig::default(),
        max_heap_bytes: 64 * 1024 * 1024,
        ..MemoryPolicy::default()
    };
    let pool = SlabPool::with_policy(&policy);
    let payload = vec![0xEFu8; 200_000];
    c.bench_function("slabpool_reserve_and_write_heap_200kb", |b| {
        b.iter(|| {
            let handle = pool.bench_reserve_and_write(black_box(&payload)).unwrap();
            pool.release(handle);
        })
    });
}

criterion_group!(
    slabpool_benches,
    bench_slabpool_reserve_16b,
    bench_slabpool_reserve_256b,
    bench_slabpool_reserve_1kb,
    bench_slabpool_release,
    bench_slabpool_full_cycle,
    bench_slabpool_reserve_and_write_primary_256b,
    bench_slabpool_reserve_and_write_primary_1kb,
    bench_slabpool_reserve_and_write_primary_4kb,
    bench_slabpool_reserve_and_write_primary_16kb,
    bench_slabpool_reserve_and_write_large_200kb,
    bench_slabpool_reserve_and_write_heap_200kb,
);

criterion_group!(
    indexring_benches,
    bench_indexring_push,
    bench_indexring_pop,
    bench_indexring_roundtrip,
    bench_topicmerger_push_5subs
);

criterion_group!(integrated_benches, bench_full_message_flow);

criterion_main!(slabpool_benches, indexring_benches, integrated_benches);

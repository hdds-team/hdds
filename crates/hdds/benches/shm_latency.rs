// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2025-2026 naskel.com

//! SHM Transport Round-Trip Latency Benchmark
//!
//! Moved out of `crates/hdds/src/transport/shm/integration.rs`'s
//! `#[test] fn test_end_to_end_latency`: that unit test
//! asserted `avg_ns < 5000.0`, an absolute wall-clock budget for a
//! same-process write()+try_read() round trip. A debug build under a
//! loaded CI runner, a sanitizer build, or a slower machine can miss that
//! budget while the transport itself is perfectly healthy -- the property
//! is genuinely a SPEED claim, not a behavioral one, so it belongs here
//! (a benchmark, run on demand, read by a human comparing numbers) rather
//! than in the default `cargo test` gate.
//!
//! Run with: `cargo bench -p hdds --bench shm_latency`

#![allow(clippy::cast_precision_loss)] // ns/iteration averages

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hdds::core::discovery::GUID;
use hdds::transport::shm::{ShmReaderTransport, ShmWriterTransport};

fn test_guid(id: u8) -> GUID {
    let mut bytes = [0u8; 16];
    bytes[0] = id;
    bytes[15] = 0x02; // Writer entity kind
    GUID::from_bytes(bytes)
}

/// Round trip: writer.write() followed by reader.try_read() on the same
/// message, both sides same-process. Mirrors the removed unit test's
/// setup exactly (same message size, same warmup count) so historical
/// numbers stay comparable.
fn bench_shm_end_to_end_round_trip(c: &mut Criterion) {
    let guid = test_guid(4);
    let mut writer = ShmWriterTransport::new(0, guid, "bench_shm_latency").expect("writer create");
    let mut reader = ShmReaderTransport::new(0, "bench_shm_latency").expect("reader create");
    reader.attach_writer(guid).expect("attach writer");

    let msg = [0u8; 64];
    let mut buf = [0u8; 256];

    // Warmup: let the ring settle before criterion's own warmup takes over.
    for _ in 0..1000 {
        writer.write(&msg).ok();
        reader.try_read(&mut buf);
    }

    c.bench_function("shm_end_to_end_round_trip_64b", |b| {
        b.iter(|| {
            writer.write(black_box(&msg)).expect("write");
            let len = reader.try_read(&mut buf).expect("read");
            black_box(len)
        });
    });
}

criterion_group!(shm_latency_benches, bench_shm_end_to_end_round_trip);
criterion_main!(shm_latency_benches);

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

//! Throughput and Latency Benchmarks for HDDS
//!
//! Measures core performance characteristics:
//! - CDR encoding/decoding throughput
//! - RTPS packet construction throughput
//! - Submessage encoding throughput

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hdds::protocol::builder::{build_data_packet, build_heartbeat_packet};
use hdds::protocol::rtps::{
    encode_acknack_with_count, encode_data, encode_gap, encode_heartbeat, encode_info_dst,
    encode_info_ts,
};
use hdds::{Cdr2Decode, Cdr2Encode};

// ============================================================================
// Helper: Temperature-like struct for CDR benchmarks
// ============================================================================

/// A simple struct for CDR encoding/decoding benchmarks.
/// Mimics the generated Temperature type without requiring the generated module.
#[derive(Debug, Clone, PartialEq)]
struct BenchTemperature {
    value: f32,
    timestamp: i32,
}

impl Cdr2Encode for BenchTemperature {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, hdds::CdrError> {
        if dst.len() < 8 {
            return Err(hdds::CdrError::BufferTooSmall);
        }
        dst[0..4].copy_from_slice(&self.value.to_le_bytes());
        dst[4..8].copy_from_slice(&self.timestamp.to_le_bytes());
        Ok(8)
    }

    fn max_cdr2_size(&self) -> usize {
        8
    }
}

impl Cdr2Decode for BenchTemperature {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
        if src.len() < 8 {
            return Err(hdds::CdrError::UnexpectedEof);
        }
        let value = f32::from_le_bytes([src[0], src[1], src[2], src[3]]);
        let timestamp = i32::from_le_bytes([src[4], src[5], src[6], src[7]]);
        Ok((BenchTemperature { value, timestamp }, 8))
    }
}

/// A larger struct with variable-size fields for more realistic CDR benchmarks.
#[derive(Debug, Clone, PartialEq)]
struct BenchSensorData {
    sensor_id: u32,
    temperature: f64,
    humidity: f64,
    label: String,
    readings: Vec<f32>,
}

impl Cdr2Encode for BenchSensorData {
    fn encode_cdr2_le(&self, dst: &mut [u8]) -> Result<usize, hdds::CdrError> {
        let mut offset = 0;
        let used = self.sensor_id.encode_cdr2_le(&mut dst[offset..])?;
        offset += used;
        let used = self.temperature.encode_cdr2_le(&mut dst[offset..])?;
        offset += used;
        let used = self.humidity.encode_cdr2_le(&mut dst[offset..])?;
        offset += used;
        let used = self.label.encode_cdr2_le(&mut dst[offset..])?;
        offset += used;
        let used = self.readings.encode_cdr2_le(&mut dst[offset..])?;
        offset += used;
        Ok(offset)
    }

    fn max_cdr2_size(&self) -> usize {
        4 + 8 + 8 + self.label.max_cdr2_size() + self.readings.max_cdr2_size()
    }
}

impl Cdr2Decode for BenchSensorData {
    fn decode_cdr2_le(src: &[u8]) -> Result<(Self, usize), hdds::CdrError> {
        let mut offset = 0;
        let (sensor_id, used) = u32::decode_cdr2_le(&src[offset..])?;
        offset += used;
        let (temperature, used) = f64::decode_cdr2_le(&src[offset..])?;
        offset += used;
        let (humidity, used) = f64::decode_cdr2_le(&src[offset..])?;
        offset += used;
        let (label, used) = String::decode_cdr2_le(&src[offset..])?;
        offset += used;
        let (readings, used) = Vec::<f32>::decode_cdr2_le(&src[offset..])?;
        offset += used;
        Ok((
            BenchSensorData {
                sensor_id,
                temperature,
                humidity,
                label,
                readings,
            },
            offset,
        ))
    }
}

// ============================================================================
// Benchmark 1: CDR Encoding Throughput
// ============================================================================

/// Benchmark encoding 1000 Temperature structs (fixed-size, 8 bytes each).
fn bench_cdr_encode_temperature_batch(c: &mut Criterion) {
    let samples: Vec<BenchTemperature> = (0..1000)
        .map(|i| BenchTemperature {
            value: 20.0 + (i as f32) * 0.01,
            timestamp: 1700000000 + i,
        })
        .collect();
    let mut buf = vec![0u8; 8192];

    let mut group = c.benchmark_group("cdr_encode");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("temperature_x1000", |b| {
        b.iter(|| {
            for sample in samples.iter() {
                let written = sample.encode_cdr2_le(black_box(&mut buf)).unwrap();
                black_box(written);
            }
        })
    });
    group.finish();
}

/// Benchmark encoding variable-size SensorData structs.
fn bench_cdr_encode_sensor_data(c: &mut Criterion) {
    let samples: Vec<BenchSensorData> = (0..100)
        .map(|i| BenchSensorData {
            sensor_id: i,
            temperature: 20.0 + (i as f64) * 0.5,
            humidity: 50.0 + (i as f64) * 0.1,
            label: format!("sensor_{}", i),
            readings: (0..10).map(|j| (i * 10 + j) as f32 * 0.1).collect(),
        })
        .collect();
    let mut buf = vec![0u8; 65536];

    let mut group = c.benchmark_group("cdr_encode");
    group.throughput(Throughput::Elements(100));

    group.bench_function("sensor_data_x100", |b| {
        b.iter(|| {
            for sample in samples.iter() {
                let written = sample.encode_cdr2_le(black_box(&mut buf)).unwrap();
                black_box(written);
            }
        })
    });
    group.finish();
}

// ============================================================================
// Benchmark 2: CDR Decoding Throughput
// ============================================================================

/// Benchmark decoding 1000 pre-encoded Temperature structs.
fn bench_cdr_decode_temperature_batch(c: &mut Criterion) {
    // Pre-encode 1000 Temperature structs
    let samples: Vec<BenchTemperature> = (0..1000)
        .map(|i| BenchTemperature {
            value: 20.0 + (i as f32) * 0.01,
            timestamp: 1700000000 + i,
        })
        .collect();

    let encoded: Vec<Vec<u8>> = samples
        .iter()
        .map(|s| {
            let mut buf = vec![0u8; 16];
            let written = s.encode_cdr2_le(&mut buf).unwrap();
            buf.truncate(written);
            buf
        })
        .collect();

    let mut group = c.benchmark_group("cdr_decode");
    group.throughput(Throughput::Elements(1000));

    group.bench_function("temperature_x1000", |b| {
        b.iter(|| {
            for enc in encoded.iter() {
                let (decoded, _) =
                    BenchTemperature::decode_cdr2_le(black_box(enc.as_slice())).unwrap();
                black_box(decoded);
            }
        })
    });
    group.finish();
}

/// Benchmark decoding variable-size SensorData structs.
fn bench_cdr_decode_sensor_data(c: &mut Criterion) {
    let samples: Vec<BenchSensorData> = (0..100)
        .map(|i| BenchSensorData {
            sensor_id: i,
            temperature: 20.0 + (i as f64) * 0.5,
            humidity: 50.0 + (i as f64) * 0.1,
            label: format!("sensor_{}", i),
            readings: (0..10).map(|j| (i * 10 + j) as f32 * 0.1).collect(),
        })
        .collect();

    let encoded: Vec<Vec<u8>> = samples
        .iter()
        .map(|s| {
            let mut buf = vec![0u8; 1024];
            let written = s.encode_cdr2_le(&mut buf).unwrap();
            buf.truncate(written);
            buf
        })
        .collect();

    let mut group = c.benchmark_group("cdr_decode");
    group.throughput(Throughput::Elements(100));

    group.bench_function("sensor_data_x100", |b| {
        b.iter(|| {
            for enc in encoded.iter() {
                let (decoded, _) =
                    BenchSensorData::decode_cdr2_le(black_box(enc.as_slice())).unwrap();
                black_box(decoded);
            }
        })
    });
    group.finish();
}

// ============================================================================
// Benchmark 3: RTPS Packet Construction
// ============================================================================

/// Benchmark building complete RTPS DATA packets (header + submessage).
fn bench_rtps_data_packet_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("rtps_packet");

    // Vary payload sizes: 64B, 256B, 1KB, 4KB
    for payload_size in [64, 256, 1024, 4096] {
        let payload = vec![0xABu8; payload_size];
        group.throughput(Throughput::Bytes(payload_size as u64));

        group.bench_with_input(
            BenchmarkId::new("data_packet", payload_size),
            &payload,
            |b, payload| {
                b.iter(|| {
                    let packet =
                        build_data_packet("bench/throughput", black_box(42), black_box(payload));
                    black_box(packet);
                })
            },
        );
    }
    group.finish();
}

/// Benchmark building RTPS HEARTBEAT packets.
fn bench_rtps_heartbeat_packet_construction(c: &mut Criterion) {
    c.bench_function("rtps_heartbeat_packet", |b| {
        b.iter(|| {
            let packet = build_heartbeat_packet(black_box(1), black_box(100), black_box(5));
            black_box(packet);
        })
    });
}

// ============================================================================
// Benchmark 4: Individual Submessage Encoding
// ============================================================================

/// Benchmark encoding individual DATA submessages (without RTPS header).
fn bench_submessage_data_encode(c: &mut Criterion) {
    let reader_id = [0x00, 0x00, 0x00, 0x04];
    let writer_id = [0x00, 0x00, 0x00, 0x03];
    let payload = vec![0u8; 256];

    c.bench_function("submsg_encode_data_256B", |b| {
        b.iter(|| {
            let buf = encode_data(
                black_box(&reader_id),
                black_box(&writer_id),
                black_box(42),
                black_box(&payload),
            )
            .unwrap();
            black_box(buf);
        })
    });
}

/// Benchmark encoding HEARTBEAT submessages.
fn bench_submessage_heartbeat_encode(c: &mut Criterion) {
    let reader_id = [0x00, 0x00, 0x00, 0x00];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];

    c.bench_function("submsg_encode_heartbeat", |b| {
        b.iter(|| {
            let buf = encode_heartbeat(
                black_box(&reader_id),
                black_box(&writer_id),
                black_box(1),
                black_box(100),
                black_box(5),
            )
            .unwrap();
            black_box(buf);
        })
    });
}

/// Benchmark encoding ACKNACK submessages with varying bitmap sizes.
fn bench_submessage_acknack_encode(c: &mut Criterion) {
    let reader_id = [0x00, 0x00, 0x04, 0xC7];
    let writer_id = [0x00, 0x00, 0x03, 0xC2];

    let mut group = c.benchmark_group("submsg_encode_acknack");

    // Empty bitmap (positive ACK)
    group.bench_function("empty_bitmap", |b| {
        b.iter(|| {
            let buf = encode_acknack_with_count(
                black_box(&reader_id),
                black_box(&writer_id),
                black_box(10),
                black_box(0),
                black_box(&[]),
                black_box(1),
            )
            .unwrap();
            black_box(buf);
        })
    });

    // 256-bit bitmap (8 words, maximum RTPS bitmap)
    let large_bitmap: Vec<u32> = vec![0xAAAA_AAAA; 8];
    group.bench_function("256bit_bitmap", |b| {
        b.iter(|| {
            let buf = encode_acknack_with_count(
                black_box(&reader_id),
                black_box(&writer_id),
                black_box(1),
                black_box(256),
                black_box(&large_bitmap),
                black_box(1),
            )
            .unwrap();
            black_box(buf);
        })
    });

    group.finish();
}

/// Benchmark encoding GAP submessages.
fn bench_submessage_gap_encode(c: &mut Criterion) {
    let reader_id = [0x00, 0x00, 0x00, 0x04];
    let writer_id = [0x00, 0x00, 0x00, 0x03];
    let bitmap: &[u32] = &[0x0000_001F];

    c.bench_function("submsg_encode_gap", |b| {
        b.iter(|| {
            let buf = encode_gap(
                black_box(&reader_id),
                black_box(&writer_id),
                black_box(1),
                black_box(10),
                black_box(32),
                black_box(bitmap),
            )
            .unwrap();
            black_box(buf);
        })
    });
}

/// Benchmark encoding INFO_TS submessages.
fn bench_submessage_info_ts_encode(c: &mut Criterion) {
    c.bench_function("submsg_encode_info_ts", |b| {
        b.iter(|| {
            let buf = encode_info_ts(black_box(1700000000), black_box(0x80000000));
            black_box(buf);
        })
    });
}

/// Benchmark encoding INFO_DST submessages.
fn bench_submessage_info_dst_encode(c: &mut Criterion) {
    let guid_prefix: [u8; 12] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
    ];

    c.bench_function("submsg_encode_info_dst", |b| {
        b.iter(|| {
            let buf = encode_info_dst(black_box(&guid_prefix));
            black_box(buf);
        })
    });
}

// ============================================================================
// Benchmark 5: CDR Encode + RTPS Wrap (Full Send Path)
// ============================================================================

/// Benchmark the full send path: CDR encode -> RTPS DATA packet.
fn bench_full_send_path(c: &mut Criterion) {
    let samples: Vec<BenchTemperature> = (0..100)
        .map(|i| BenchTemperature {
            value: 20.0 + (i as f32) * 0.01,
            timestamp: 1700000000 + i,
        })
        .collect();
    let mut cdr_buf = vec![0u8; 256];

    let mut group = c.benchmark_group("full_send_path");
    group.throughput(Throughput::Elements(100));

    group.bench_function("cdr_encode_plus_rtps_wrap_x100", |b| {
        b.iter(|| {
            for (i, sample) in samples.iter().enumerate() {
                // Step 1: CDR encode
                let written = sample.encode_cdr2_le(black_box(&mut cdr_buf)).unwrap();
                // Step 2: Wrap in RTPS DATA packet
                let packet =
                    build_data_packet("bench/full_path", (i + 1) as u64, &cdr_buf[..written]);
                black_box(packet);
            }
        })
    });
    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    cdr_benches,
    bench_cdr_encode_temperature_batch,
    bench_cdr_encode_sensor_data,
    bench_cdr_decode_temperature_batch,
    bench_cdr_decode_sensor_data,
);

criterion_group!(
    rtps_packet_benches,
    bench_rtps_data_packet_construction,
    bench_rtps_heartbeat_packet_construction,
);

criterion_group!(
    submessage_benches,
    bench_submessage_data_encode,
    bench_submessage_heartbeat_encode,
    bench_submessage_acknack_encode,
    bench_submessage_gap_encode,
    bench_submessage_info_ts_encode,
    bench_submessage_info_dst_encode,
);

criterion_group!(integration_benches, bench_full_send_path,);

criterion_main!(
    cdr_benches,
    rtps_packet_benches,
    submessage_benches,
    integration_benches,
);

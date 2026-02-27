#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Latency Sample - Measures round-trip latency

This sample demonstrates latency measurement using ping-pong pattern:
- Publisher sends timestamped message
- Subscriber echoes back
- Publisher calculates round-trip time

Key concepts:
- High-resolution timestamps
- Latency percentiles (p50, p99, p99.9)
- Histogram analysis
"""

import os
import sys
import time
import statistics
from dataclasses import dataclass, field
from typing import List, Optional

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds

MAX_SAMPLES = 10000
WARMUP_SAMPLES = 100
PAYLOAD_SIZE = 64

PING_TOPIC = "LatencyPing"
PONG_TOPIC = "LatencyPong"


@dataclass
class LatencyStats:
    """Latency statistics"""
    samples: List[float] = field(default_factory=list)
    min: float = 0
    max: float = 0
    mean: float = 0
    std_dev: float = 0
    p50: float = 0
    p90: float = 0
    p99: float = 0
    p999: float = 0


def get_time_ns() -> int:
    """Get current time in nanoseconds"""
    return time.perf_counter_ns()


def percentile(sorted_samples: List[float], p: float) -> float:
    """Calculate percentile from sorted samples"""
    if not sorted_samples:
        return 0.0
    idx = (p / 100.0) * (len(sorted_samples) - 1)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_samples) - 1)
    frac = idx - lo
    return sorted_samples[lo] * (1 - frac) + sorted_samples[hi] * frac


def calculate_stats(stats: LatencyStats) -> None:
    """Calculate latency statistics"""
    if not stats.samples:
        return

    # Sort for percentiles
    stats.samples.sort()

    # Min/Max
    stats.min = stats.samples[0]
    stats.max = stats.samples[-1]

    # Mean and standard deviation
    stats.mean = statistics.mean(stats.samples)
    stats.std_dev = statistics.stdev(stats.samples) if len(stats.samples) > 1 else 0

    # Percentiles
    stats.p50 = percentile(stats.samples, 50)
    stats.p90 = percentile(stats.samples, 90)
    stats.p99 = percentile(stats.samples, 99)
    stats.p999 = percentile(stats.samples, 99.9)


def print_histogram(samples: List[float]) -> None:
    """Print ASCII histogram of latency distribution"""
    if not samples:
        return

    num_buckets = 20
    min_val = samples[0]
    max_val = samples[-1]
    range_val = max_val - min_val
    if range_val == 0:
        range_val = 1

    buckets = [0] * num_buckets
    for s in samples:
        bucket = int((s - min_val) / range_val * (num_buckets - 1))
        bucket = min(bucket, num_buckets - 1)
        buckets[bucket] += 1

    max_count = max(buckets)

    print("\nLatency Distribution:")
    for i in range(num_buckets):
        bucket_min = min_val + (range_val * i / num_buckets)
        bucket_max = min_val + (range_val * (i + 1) / num_buckets)
        bar_len = (buckets[i] * 40 // max_count) if max_count > 0 else 0

        print(f"{bucket_min:7.1f}-{bucket_max:7.1f} us |{'#' * bar_len} {buckets[i]}")


def serialize_latency_msg(sequence: int, timestamp_ns: int, payload_size: int) -> bytes:
    """Serialize a latency message to bytes"""
    # Simple format: sequence (8 bytes) + timestamp (8 bytes) + payload
    import struct
    header = struct.pack('<QQ', sequence, timestamp_ns)
    payload = bytes(payload_size)
    return header + payload


def deserialize_latency_msg(data: bytes) -> tuple:
    """Deserialize a latency message from bytes"""
    import struct
    sequence, timestamp_ns = struct.unpack('<QQ', data[:16])
    return sequence, timestamp_ns


def run_ping(participant: hdds.Participant, num_samples: int) -> int:
    """Run the ping (publisher) side of the latency test"""
    print("Creating endpoints...")
    writer = participant.create_writer(PING_TOPIC, qos=hdds.QoS.reliable())
    reader = participant.create_reader(PONG_TOPIC, qos=hdds.QoS.reliable())
    print("[OK] Endpoints created")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    print("\n--- Running Latency Test (PING) ---")
    print("Waiting for pong peer...\n")

    # Wait for peer to be ready
    time.sleep(1.0)

    # Latency statistics
    stats = LatencyStats()

    # Warmup
    print(f"Running warmup ({WARMUP_SAMPLES} samples)...")
    for i in range(WARMUP_SAMPLES):
        msg = serialize_latency_msg(i, get_time_ns(), PAYLOAD_SIZE)
        writer.write(msg)
        # Wait for pong response
        if waitset.wait(timeout=1.0):
            reader.take()
        time.sleep(0.001)

    # Measurement
    print(f"Running measurement ({num_samples} samples)...\n")

    for i in range(num_samples):
        send_time = get_time_ns()
        msg = serialize_latency_msg(WARMUP_SAMPLES + i, send_time, PAYLOAD_SIZE)
        writer.write(msg)

        # Wait for pong response
        if waitset.wait(timeout=1.0):
            response = reader.take()
            if response:
                recv_time = get_time_ns()
                rtt_ns = recv_time - send_time
                stats.samples.append(rtt_ns / 1000.0)  # Convert to microseconds

        if (i + 1) % (num_samples // 10) == 0:
            print(f"  Progress: {i + 1}/{num_samples} samples")

        time.sleep(0.001)  # 1ms interval

    # Calculate statistics
    calculate_stats(stats)

    # Print results
    print("\n--- Latency Results ---\n")
    print("Round-trip latency (microseconds):")
    print(f"  Min:    {stats.min:8.2f} us")
    print(f"  Max:    {stats.max:8.2f} us")
    print(f"  Mean:   {stats.mean:8.2f} us")
    print(f"  StdDev: {stats.std_dev:8.2f} us")
    print()
    print("Percentiles:")
    print(f"  p50:    {stats.p50:8.2f} us (median)")
    print(f"  p90:    {stats.p90:8.2f} us")
    print(f"  p99:    {stats.p99:8.2f} us")
    print(f"  p99.9:  {stats.p999:8.2f} us")

    # Print histogram
    print_histogram(stats.samples)

    # One-way latency estimate
    print("\n--- One-Way Latency Estimate ---")
    print(f"  Estimated: {stats.p50 / 2:.2f} us (RTT/2)")

    return 0


def run_pong(participant: hdds.Participant) -> int:
    """Run the pong (subscriber/echo) side of the latency test"""
    print("Creating endpoints...")
    reader = participant.create_reader(PING_TOPIC, qos=hdds.QoS.reliable())
    writer = participant.create_writer(PONG_TOPIC, qos=hdds.QoS.reliable())
    print("[OK] Endpoints created")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    print("\n--- Running Latency Test (PONG) ---")
    print("Echoing messages (Ctrl+C to exit)...\n")

    count = 0
    try:
        while True:
            if waitset.wait(timeout=5.0):
                while True:
                    data = reader.take()
                    if data is None:
                        break
                    # Echo back immediately
                    writer.write(data)
                    count += 1
                    if count % 1000 == 0:
                        print(f"  Echoed {count} messages")
            else:
                print("  (timeout - waiting for ping)")
    except KeyboardInterrupt:
        print(f"\nInterrupted after echoing {count} messages")

    return 0


def main():
    print("=== HDDS Latency Benchmark ===\n")

    num_samples = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    num_samples = min(num_samples, MAX_SAMPLES)

    is_pong = len(sys.argv) > 2 and sys.argv[2] == "--pong"

    print("Configuration:")
    print(f"  Samples: {num_samples} (+ {WARMUP_SAMPLES} warmup)")
    print(f"  Payload: {PAYLOAD_SIZE} bytes")
    print(f"  Mode: {'PONG (echo)' if is_pong else 'PING (publisher)'}\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating participant...")
    participant = hdds.Participant("LatencyTest")
    print("[OK] Participant created")

    try:
        if is_pong:
            return run_pong(participant)
        else:
            return run_ping(participant, num_samples)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 1
    finally:
        print("\n=== Benchmark Complete ===")


if __name__ == "__main__":
    sys.exit(main())

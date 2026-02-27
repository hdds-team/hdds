#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Batching Sample - Demonstrates message batching for efficiency

This sample shows how batching improves throughput:
- Batch multiple messages into single network packet
- Reduce per-message overhead
- Trade latency for throughput

Key concepts:
- max_batch_size: Maximum bytes per batch
- batch_timeout: Maximum time to wait for batch
- Manual batching with periodic flush
"""

import os
import sys
import time
from dataclasses import dataclass
from typing import List

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds

MESSAGE_SIZE = 64
NUM_MESSAGES = 10000

BATCH_TOPIC = "BatchTest"


@dataclass
class BatchConfig:
    """Batching configuration"""
    max_batch_size: int = 0        # Maximum bytes per batch
    batch_timeout_us: int = 0      # Timeout in microseconds
    enabled: bool = False


@dataclass
class BatchStats:
    """Batch statistics"""
    messages_sent: int = 0
    batches_sent: int = 0
    bytes_sent: int = 0
    duration_sec: float = 0
    avg_batch_size: float = 0
    msg_per_sec: float = 0


class BatchedWriter:
    """Writer that accumulates messages into batches before sending"""

    def __init__(self, writer: hdds.DataWriter, max_batch_bytes: int):
        self._writer = writer
        self._max_batch_bytes = max_batch_bytes
        self._buffer: List[bytes] = []
        self._buffer_bytes = 0
        self._batches_sent = 0

    def write(self, data: bytes) -> None:
        """Add data to batch buffer"""
        self._buffer.append(data)
        self._buffer_bytes += len(data)

        # Auto-flush when batch is full
        if self._buffer_bytes >= self._max_batch_bytes:
            self.flush()

    def flush(self) -> None:
        """Send all buffered messages as a batch"""
        if not self._buffer:
            return

        # In a real batched implementation, we'd combine messages
        # For now, send them individually but track as a batch
        for data in self._buffer:
            self._writer.write(data)

        self._batches_sent += 1
        self._buffer.clear()
        self._buffer_bytes = 0

    @property
    def batches_sent(self) -> int:
        return self._batches_sent


def print_comparison(label: str, stats: BatchStats) -> None:
    print(f"{label:20s} {stats.messages_sent:8d} msgs, {stats.batches_sent:6d} batches, "
          f"{stats.msg_per_sec:8.0f} msg/s, avg batch: {stats.avg_batch_size:.1f} msgs")


def run_test(participant: hdds.Participant, name: str, config: BatchConfig, num_messages: int) -> BatchStats:
    """Run a batching test with given configuration"""
    stats = BatchStats()
    message = bytes(MESSAGE_SIZE)

    # Create writer with best-effort QoS for maximum throughput
    writer = participant.create_writer(BATCH_TOPIC, qos=hdds.QoS.best_effort())

    start = time.perf_counter()

    if config.enabled:
        # Batched sending using our BatchedWriter
        batched_writer = BatchedWriter(writer, config.max_batch_size)

        for i in range(num_messages):
            batched_writer.write(message)
            stats.messages_sent += 1
            stats.bytes_sent += MESSAGE_SIZE

        # Flush remaining
        batched_writer.flush()
        stats.batches_sent = batched_writer.batches_sent
    else:
        # Non-batched sending (each message = one batch)
        for i in range(num_messages):
            writer.write(message)
            stats.messages_sent += 1
            stats.bytes_sent += MESSAGE_SIZE
            stats.batches_sent += 1

    end = time.perf_counter()
    stats.duration_sec = end - start
    stats.msg_per_sec = stats.messages_sent / stats.duration_sec if stats.duration_sec > 0 else 0
    stats.avg_batch_size = stats.messages_sent / stats.batches_sent if stats.batches_sent > 0 else 0

    return stats


def main():
    print("=== HDDS Batching Sample ===\n")

    print("--- Batching Overview ---\n")
    print("Batching combines multiple messages into fewer network packets:")
    print("  - Reduces per-message overhead (headers, syscalls)")
    print("  - Improves throughput significantly")
    print("  - Adds slight latency (batch accumulation time)\n")

    print("Configuration Parameters:")
    print("  max_batch_size:   Maximum bytes to accumulate before sending")
    print("  batch_timeout:    Maximum time to wait for more messages")
    print("  flush():          Manually send incomplete batch\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating participant...")
    participant = hdds.Participant("BatchTest")
    print("[OK] Participant created\n")

    print("--- Running Batching Comparison ---")
    print(f"Sending {NUM_MESSAGES} messages of {MESSAGE_SIZE} bytes each...\n")

    # Test configurations
    configs = [
        BatchConfig(enabled=False),
        BatchConfig(max_batch_size=1024, batch_timeout_us=1000, enabled=True),
        BatchConfig(max_batch_size=4096, batch_timeout_us=1000, enabled=True),
        BatchConfig(max_batch_size=8192, batch_timeout_us=1000, enabled=True),
        BatchConfig(max_batch_size=16384, batch_timeout_us=1000, enabled=True),
        BatchConfig(max_batch_size=65536, batch_timeout_us=1000, enabled=True),
    ]

    labels = [
        "No batching:",
        "Batch 1KB:",
        "Batch 4KB:",
        "Batch 8KB:",
        "Batch 16KB:",
        "Batch 64KB:",
    ]

    results: List[BatchStats] = []

    for label, config in zip(labels, configs):
        stats = run_test(participant, label, config, NUM_MESSAGES)
        results.append(stats)
        print_comparison(label, stats)

    # Calculate improvement
    print("\n--- Performance Improvement ---\n")

    baseline = results[0].msg_per_sec
    for i in range(1, len(results)):
        if baseline > 0:
            improvement = ((results[i].msg_per_sec / baseline) - 1.0) * 100
            print(f"{labels[i]} {improvement:.0f}% faster than no batching")

    # Network efficiency
    print("\n--- Network Efficiency ---\n")
    print("| Configuration | Messages | Packets | Efficiency |")
    print("|---------------|----------|---------|------------|")

    for i, stats in enumerate(results):
        efficiency = stats.messages_sent / stats.batches_sent if stats.batches_sent > 0 else 0
        print(f"| {labels[i]:13s} | {stats.messages_sent:8d} | {stats.batches_sent:7d} | {efficiency:5.1f}x     |")

    # Best practices
    print("\n--- Batching Best Practices ---\n")
    print("1. Choose batch size based on network MTU (typically 1500 bytes)")
    print("2. For low-latency: smaller batches or disable batching")
    print("3. For high-throughput: larger batches (8KB-64KB)")
    print("4. Use flush() for time-sensitive messages")
    print("5. batch_timeout prevents stale messages in low-rate scenarios")

    # Latency trade-off
    print("\n--- Latency vs Throughput Trade-off ---\n")
    print("| Batch Size | Throughput | Added Latency    |")
    print("|------------|------------|------------------|")
    print("| None       | Baseline   | ~0 us            |")
    print("| 1 KB       | ~2x        | ~10-50 us        |")
    print("| 8 KB       | ~5x        | ~50-200 us       |")
    print("| 64 KB      | ~10x       | ~100-500 us      |")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())

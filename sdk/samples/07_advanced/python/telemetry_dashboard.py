#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Telemetry Dashboard - Monitor DDS performance metrics in real-time.

Initializes HDDS telemetry, creates pub/sub on a test topic, records
latency for each write/read cycle, takes periodic snapshots, and
starts a Prometheus-compatible TCP exporter.

Usage:
    python telemetry_dashboard.py

Expected output:
    --- Snapshot #1 ---
    Messages sent: 10 | received: 10
    Latency p50: 0.120 ms | p99: 0.450 ms
    ...
    Exporter running on 0.0.0.0:4242
"""

import os
import sys
import struct
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


BATCH_SIZE: int = 10
NUM_BATCHES: int = 5
EXPORTER_PORT: int = 4242


def now_ns() -> int:
    """Monotonic timestamp in nanoseconds."""
    return time.monotonic_ns()


def print_snapshot(snap: hdds.telemetry.MetricsSnapshot, idx: int) -> None:
    """Print a formatted metrics snapshot."""
    print(f"--- Snapshot #{idx} ---")
    print(f"  Messages sent:     {snap.messages_sent}   | received: {snap.messages_received}")
    print(f"  Messages dropped:  {snap.messages_dropped}")
    print(f"  Bytes sent:        {snap.bytes_sent}")
    print(f"  Latency p50: {snap.latency_p50_ms:.3f} ms | "
          f"p99: {snap.latency_p99_ms:.3f} ms | "
          f"p999: {snap.latency_p999_ms:.3f} ms")
    print(f"  Backpressure: merge_full={snap.merge_full_count}, "
          f"would_block={snap.would_block_count}")
    print()


def main() -> int:
    print("=" * 60)
    print("HDDS Telemetry Dashboard (Python)")
    print("=" * 60)
    print()

    hdds.logging.init(hdds.LogLevel.INFO)

    # Initialize telemetry
    metrics = hdds.telemetry.init()
    print("[OK] Telemetry initialized")

    # Create participant + endpoints
    participant = hdds.Participant("TelemetryDashboard")
    writer = participant.create_writer("TelemetryTopic", qos=hdds.QoS.reliable())
    reader = participant.create_reader("TelemetryTopic", qos=hdds.QoS.reliable())
    print("[OK] Pub/Sub created on 'TelemetryTopic'")

    # Start exporter
    exporter = hdds.telemetry.start_exporter("0.0.0.0", EXPORTER_PORT)
    print(f"[OK] Exporter running on 0.0.0.0:{EXPORTER_PORT}\n")

    # Write/read cycles with latency measurement
    for batch in range(NUM_BATCHES):
        for i in range(BATCH_SIZE):
            msg_id = batch * BATCH_SIZE + i
            payload = struct.pack('<i', msg_id)

            start = now_ns()
            writer.write(payload)
            _ = reader.take()  # best-effort read back
            end = now_ns()

            metrics.record_latency(start, end)

        # Snapshot after each batch
        snap = metrics.snapshot()
        print_snapshot(snap, batch + 1)

    # Final summary
    print("=== Dashboard Summary ===")
    final_snap = metrics.snapshot()
    print(f"Total messages sent: {final_snap.messages_sent}")
    print(f"Total bytes sent:    {final_snap.bytes_sent}")
    print(f"Final p99 latency:   {final_snap.latency_p99_ms:.3f} ms")

    exporter.stop()
    print("\n=== Telemetry Dashboard Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())

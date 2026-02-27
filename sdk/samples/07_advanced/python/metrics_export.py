#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Metrics Export - Focused telemetry exporter example.

Initializes telemetry, starts a TCP exporter on port 9090, records
1000 latency samples in a loop, takes a final snapshot, and stops.
Connect HDDS Viewer to http://localhost:9090 for live metrics.

Usage:
    python metrics_export.py

Expected output:
    [OK] Exporter listening on 127.0.0.1:9090
    Recording 1000 latency samples...
    --- Final Metrics ---
    Latency p50: 0.001 ms | p99: 0.003 ms | p999: 0.005 ms
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds


NUM_SAMPLES: int = 1000
EXPORTER_PORT: int = 9090


def simulate_work() -> None:
    """Simulate a small unit of work."""
    total = 0
    for i in range(100):
        total += i


def main() -> int:
    print("=" * 60)
    print("HDDS Metrics Export Sample (Python)")
    print("=" * 60)
    print()

    # Initialize telemetry
    metrics = hdds.telemetry.init()
    print("[OK] Telemetry initialized")

    # Start exporter
    exporter = hdds.telemetry.start_exporter("127.0.0.1", EXPORTER_PORT)
    print(f"[OK] Exporter listening on 127.0.0.1:{EXPORTER_PORT}\n")

    # Record latency samples
    print(f"Recording {NUM_SAMPLES} latency samples...")

    for i in range(NUM_SAMPLES):
        start = time.monotonic_ns()
        simulate_work()
        end = time.monotonic_ns()

        metrics.record_latency(start, end)

        if (i + 1) % 250 == 0:
            print(f"  ... {i + 1}/{NUM_SAMPLES}")

    # Final snapshot
    print("\n--- Final Metrics ---")
    snap = metrics.snapshot()
    print(f"  Latency p50:  {snap.latency_p50_ms:.4f} ms")
    print(f"  Latency p99:  {snap.latency_p99_ms:.4f} ms")
    print(f"  Latency p999: {snap.latency_p999_ms:.4f} ms")
    print(f"  Messages sent: {snap.messages_sent} | received: {snap.messages_received}")

    # Cleanup
    print("\nStopping exporter...")
    exporter.stop()

    print("\n=== Metrics Export Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())

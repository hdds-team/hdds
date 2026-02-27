#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Throughput Sample - Measures maximum message throughput

This sample demonstrates throughput measurement:
- Publisher sends messages as fast as possible
- Subscriber counts received messages
- Calculate messages/sec and MB/sec

Key concepts:
- Sustained throughput measurement
- Variable payload sizes
- Publisher and subscriber modes
"""

import argparse
import os
import signal
import sys
import time
from dataclasses import dataclass, field

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds

DEFAULT_PAYLOAD_SIZE = 256
DEFAULT_DURATION_SEC = 10
MAX_PAYLOAD_SIZE = 64 * 1024

THROUGHPUT_TOPIC = "ThroughputTest"


@dataclass
class ThroughputStats:
    """Throughput statistics"""
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    duration_sec: float = 0
    msg_per_sec: float = 0
    mb_per_sec: float = 0


running = True


def signal_handler(sig, frame):
    global running
    running = False


def calculate_stats(stats: ThroughputStats, is_publisher: bool) -> None:
    if stats.duration_sec <= 0:
        return

    if is_publisher:
        stats.msg_per_sec = stats.messages_sent / stats.duration_sec
        stats.mb_per_sec = (stats.bytes_sent / (1024 * 1024)) / stats.duration_sec
    else:
        stats.msg_per_sec = stats.messages_received / stats.duration_sec
        stats.mb_per_sec = (stats.bytes_received / (1024 * 1024)) / stats.duration_sec


def print_progress(stats: ThroughputStats, elapsed_sec: int, is_publisher: bool) -> None:
    if is_publisher:
        current_msg_sec = stats.messages_sent / elapsed_sec
        current_mb_sec = (stats.bytes_sent / (1024 * 1024)) / elapsed_sec
    else:
        current_msg_sec = stats.messages_received / elapsed_sec
        current_mb_sec = (stats.bytes_received / (1024 * 1024)) / elapsed_sec

    print(f"  [{elapsed_sec:2d} sec] {current_msg_sec:.0f} msg/s, {current_mb_sec:.2f} MB/s")


def serialize_throughput_msg(sequence: int, timestamp_ns: int, payload: bytes) -> bytes:
    """Serialize a throughput message to bytes"""
    import struct
    # Format: sequence (8 bytes) + timestamp (8 bytes) + payload_size (4 bytes) + payload
    header = struct.pack('<QQI', sequence, timestamp_ns, len(payload))
    return header + payload


def get_msg_size(payload_size: int) -> int:
    """Get total message size including header"""
    return 8 + 8 + 4 + payload_size  # sequence + timestamp + size + payload


def run_publisher(participant: hdds.Participant, payload_size: int, duration_sec: int) -> int:
    """Run as publisher"""
    global running

    print("Creating DataWriter...")
    writer = participant.create_writer(THROUGHPUT_TOPIC, qos=hdds.QoS.best_effort())
    print("[OK] DataWriter created")

    print("\n--- Running Throughput Test (PUBLISHER) ---")
    print("Press Ctrl+C to stop early.\n")

    # Initialize statistics
    stats = ThroughputStats()
    payload = bytes(payload_size)
    msg_size = get_msg_size(payload_size)

    # Run test
    start_time = time.perf_counter()
    last_progress_sec = 0

    print("Publishing messages...\n")

    while running:
        elapsed = time.perf_counter() - start_time
        if elapsed >= duration_sec:
            break

        # Send message
        msg = serialize_throughput_msg(stats.messages_sent, time.perf_counter_ns(), payload)
        writer.write(msg)

        stats.messages_sent += 1
        stats.bytes_sent += msg_size

        # Progress update every second
        current_sec = int(elapsed)
        if current_sec > last_progress_sec:
            print_progress(stats, current_sec, True)
            last_progress_sec = current_sec

    stats.duration_sec = time.perf_counter() - start_time

    # Calculate final statistics
    calculate_stats(stats, True)

    # Print results
    print("\n--- Throughput Results ---\n")
    print(f"Messages sent:     {stats.messages_sent}")
    print(f"Bytes sent:        {stats.bytes_sent} ({stats.bytes_sent / (1024 * 1024):.2f} MB)")
    print(f"Duration:          {stats.duration_sec:.2f} seconds\n")

    print("Throughput:")
    print(f"  Messages/sec:    {stats.msg_per_sec:.0f}")
    print(f"  MB/sec:          {stats.mb_per_sec:.2f}")
    print(f"  Gbps:            {stats.mb_per_sec * 8 / 1024:.2f}")

    return 0


def run_subscriber(participant: hdds.Participant, payload_size: int, duration_sec: int) -> int:
    """Run as subscriber"""
    global running

    print("Creating DataReader...")
    reader = participant.create_reader(THROUGHPUT_TOPIC, qos=hdds.QoS.best_effort())
    print("[OK] DataReader created")

    # Create waitset for efficient waiting
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    print("\n--- Running Throughput Test (SUBSCRIBER) ---")
    print("Press Ctrl+C to stop early.\n")

    # Initialize statistics
    stats = ThroughputStats()
    msg_size = get_msg_size(payload_size)

    # Run test
    start_time = time.perf_counter()
    last_progress_sec = 0

    print("Receiving messages...\n")

    while running:
        elapsed = time.perf_counter() - start_time
        if elapsed >= duration_sec:
            break

        # Wait for data with short timeout for responsiveness
        if waitset.wait(timeout=0.1):
            # Take all available samples
            while True:
                data = reader.take()
                if data is None:
                    break
                stats.messages_received += 1
                stats.bytes_received += len(data)

        # Progress update every second
        current_sec = int(elapsed)
        if current_sec > last_progress_sec and stats.messages_received > 0:
            print_progress(stats, current_sec, False)
            last_progress_sec = current_sec

    stats.duration_sec = time.perf_counter() - start_time

    # Calculate final statistics
    calculate_stats(stats, False)

    # Print results
    print("\n--- Throughput Results ---\n")
    print(f"Messages received: {stats.messages_received}")
    print(f"Bytes received:    {stats.bytes_received} ({stats.bytes_received / (1024 * 1024):.2f} MB)")
    print(f"Duration:          {stats.duration_sec:.2f} seconds\n")

    print("Throughput:")
    print(f"  Messages/sec:    {stats.msg_per_sec:.0f}")
    print(f"  MB/sec:          {stats.mb_per_sec:.2f}")
    print(f"  Gbps:            {stats.mb_per_sec * 8 / 1024:.2f}")

    return 0


def main():
    global running

    parser = argparse.ArgumentParser(description="HDDS Throughput Benchmark")
    parser.add_argument("-p", "--pub", action="store_true", help="Run as publisher (default)")
    parser.add_argument("-s", "--sub", action="store_true", help="Run as subscriber")
    parser.add_argument("-d", "--duration", type=int, default=DEFAULT_DURATION_SEC,
                        help=f"Test duration in seconds (default: {DEFAULT_DURATION_SEC})")
    parser.add_argument("-z", "--size", type=int, default=DEFAULT_PAYLOAD_SIZE,
                        help=f"Payload size in bytes (default: {DEFAULT_PAYLOAD_SIZE})")
    args = parser.parse_args()

    print("=== HDDS Throughput Benchmark ===\n")

    is_publisher = not args.sub
    duration_sec = args.duration
    payload_size = min(args.size, MAX_PAYLOAD_SIZE)
    msg_size = get_msg_size(payload_size)

    print("Configuration:")
    print(f"  Mode: {'PUBLISHER' if is_publisher else 'SUBSCRIBER'}")
    print(f"  Duration: {duration_sec} seconds")
    print(f"  Payload size: {payload_size} bytes")
    print(f"  Message size: {msg_size} bytes (with header)\n")

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating participant...")
    participant = hdds.Participant("ThroughputTest")
    print("[OK] Participant created")

    try:
        if is_publisher:
            return run_publisher(participant, payload_size, duration_sec)
        else:
            return run_subscriber(participant, payload_size, duration_sec)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 1
    finally:
        print("\n=== Benchmark Complete ===")


if __name__ == "__main__":
    sys.exit(main())

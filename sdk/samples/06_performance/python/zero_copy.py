#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Zero-Copy Sample - Demonstrates zero-copy data sharing concepts

This sample shows how to approach zero-copy for large payloads:
- Intra-process: Direct reference sharing
- Inter-process: Shared memory segments
- Memory-mapped buffers for large data

Key concepts:
- Avoiding unnecessary memory copies
- Using memoryview for zero-copy slicing
- Shared memory for inter-process communication

NOTE: CONCEPT DEMO - This sample demonstrates the APPLICATION PATTERN for Zero-Copy / Shared Memory Loans.
The native Zero-Copy / Shared Memory Loans API is not yet exported to the C/C++/Python SDK.
This sample uses standard participant/writer/reader API to show the concept.
"""

import os
import sys
import time
from dataclasses import dataclass
from typing import Optional
import mmap

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'python'))

import hdds

LARGE_PAYLOAD_SIZE = 1024 * 1024  # 1 MB
NUM_ITERATIONS = 100

ZERO_COPY_TOPIC = "ZeroCopyTest"


@dataclass
class ZeroCopyConfig:
    """Zero-copy configuration"""
    enable_shared_memory: bool = True
    enable_memoryview: bool = True
    buffer_size: int = 64 * 1024 * 1024  # 64 MB


@dataclass
class ZeroCopyResults:
    """Performance results"""
    copy_time_ms: float = 0
    zero_copy_time_ms: float = 0
    speedup: float = 0
    bytes_transferred: int = 0


def print_zero_copy_overview():
    print("--- Zero-Copy Overview ---\n")
    print("Traditional copy path:")
    print("  Application -> [COPY] -> DDS Buffer -> [COPY] -> Network")
    print("  Network -> [COPY] -> DDS Buffer -> [COPY] -> Application\n")

    print("Zero-copy path:")
    print("  Application -> [SHARED MEMORY] -> Application")
    print("  (No copies for intra-host communication)\n")

    print("Benefits:")
    print("  - Eliminates memory copies for large payloads")
    print("  - Reduces CPU usage")
    print("  - Lower latency for large messages")
    print("  - Better cache utilization\n")


def benchmark_copy_vs_zero_copy(payload_size: int, iterations: int) -> ZeroCopyResults:
    """Benchmark memory copy vs zero-copy (reference) operations"""
    results = ZeroCopyResults()
    results.bytes_transferred = payload_size * iterations

    # Allocate test buffers
    src_buffer = bytearray(payload_size)
    for i in range(min(payload_size, 1024)):
        src_buffer[i] = 0xAB

    # Benchmark with copy
    start = time.perf_counter()
    for i in range(iterations):
        dst_buffer = bytearray(src_buffer)  # Creates copy
        dst_buffer[0] = i % 256  # Prevent optimization
    copy_time = time.perf_counter() - start
    results.copy_time_ms = copy_time * 1000

    # Benchmark zero-copy using memoryview (no actual copy)
    start = time.perf_counter()
    for i in range(iterations):
        # memoryview provides zero-copy access to buffer
        view = memoryview(src_buffer)
        view[0] = i % 256  # Direct access, no copy
    zc_time = time.perf_counter() - start
    results.zero_copy_time_ms = zc_time * 1000

    results.speedup = results.copy_time_ms / max(results.zero_copy_time_ms, 0.001)

    return results


def demonstrate_memoryview():
    """Demonstrate Python's memoryview for zero-copy buffer access"""
    print("--- memoryview Demonstration ---\n")

    # Create a buffer
    buffer = bytearray(LARGE_PAYLOAD_SIZE)
    for i in range(min(LARGE_PAYLOAD_SIZE, 1024)):
        buffer[i] = 0xCD

    print(f"Original buffer: {len(buffer)} bytes at {id(buffer)}")

    # Create memoryview - no copy!
    view = memoryview(buffer)
    print(f"memoryview: {len(view)} bytes, references same memory")

    # Slice without copying
    slice_view = view[0:1024]
    print(f"Slice view: {len(slice_view)} bytes (zero-copy slice)")

    # Verify it's the same memory
    view[0] = 0xFF
    print(f"After modifying view[0]: buffer[0] = 0x{buffer[0]:02X} (same memory)")

    print("[OK] memoryview provides zero-copy buffer access\n")


def demonstrate_hdds_zero_copy(participant: hdds.Participant):
    """Demonstrate zero-copy patterns with HDDS"""
    print("--- HDDS Zero-Copy Patterns ---\n")

    # Create endpoints
    writer = participant.create_writer(ZERO_COPY_TOPIC, qos=hdds.QoS.best_effort())
    reader = participant.create_reader(ZERO_COPY_TOPIC, qos=hdds.QoS.best_effort())
    print("[OK] Zero-copy endpoints created")

    # Create waitset
    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)

    # Pattern 1: Pre-allocated buffer reuse
    print("\nPattern 1: Pre-allocated buffer reuse")
    print("  - Allocate buffer once, reuse for multiple writes")
    print("  - Avoids allocation overhead per message")

    buffer = bytearray(LARGE_PAYLOAD_SIZE)
    for i in range(min(LARGE_PAYLOAD_SIZE, 1024)):
        buffer[i] = 0xAB

    start = time.perf_counter()
    for i in range(10):
        # Modify in place
        buffer[0] = i
        # Write (HDDS handles the copy internally)
        writer.write(bytes(buffer))
    elapsed = (time.perf_counter() - start) * 1000
    print(f"  [OK] Sent 10 x {LARGE_PAYLOAD_SIZE // 1024} KB in {elapsed:.2f} ms")

    # Pattern 2: memoryview for efficient slicing
    print("\nPattern 2: memoryview for efficient slicing")
    print("  - Use memoryview to work with buffer portions")
    print("  - No intermediate copies for slicing operations")

    large_buffer = bytearray(4 * 1024 * 1024)  # 4 MB
    view = memoryview(large_buffer)

    # Write different portions without copying
    for i in range(4):
        chunk = view[i * 1024 * 1024:(i + 1) * 1024 * 1024]
        chunk[0] = i
        writer.write(bytes(chunk))
    print("  [OK] Sent 4 x 1 MB chunks using memoryview slices")

    print("\n[OK] Zero-copy patterns demonstrated\n")


def main():
    print("=== HDDS Zero-Copy Sample ===\n")
    print("NOTE: CONCEPT DEMO - Native Zero-Copy / Shared Memory Loans API not yet in SDK.")
    print("      Using standard pub/sub API to demonstrate the pattern.\n")

    print_zero_copy_overview()

    # Configuration
    config = ZeroCopyConfig(
        enable_shared_memory=True,
        enable_memoryview=True,
        buffer_size=64 * 1024 * 1024
    )

    print("Zero-Copy Configuration:")
    print(f"  Shared Memory: {'ENABLED' if config.enable_shared_memory else 'DISABLED'}")
    print(f"  memoryview: {'ENABLED' if config.enable_memoryview else 'DISABLED'}")
    print(f"  Buffer Size: {config.buffer_size // (1024 * 1024)} MB\n")

    # Initialize logging
    hdds.logging.init(hdds.LogLevel.INFO)

    # Create participant
    print("Creating participant...")
    participant = hdds.Participant("ZeroCopyTest")
    print("[OK] Participant created\n")

    # Demonstrate memoryview
    demonstrate_memoryview()

    # Demonstrate HDDS patterns
    demonstrate_hdds_zero_copy(participant)

    # Benchmark copy vs zero-copy
    print("--- Performance Comparison ---\n")

    payload_sizes = [1024, 64*1024, 256*1024, 1024*1024, 4*1024*1024]
    size_labels = ["1 KB", "64 KB", "256 KB", "1 MB", "4 MB"]

    print("| Payload | With Copy | Zero-Copy | Speedup |")
    print("|---------|-----------|-----------|--------|")

    for size, label in zip(payload_sizes, size_labels):
        r = benchmark_copy_vs_zero_copy(size, NUM_ITERATIONS)
        print(f"| {label:7s} | {r.copy_time_ms:7.2f} ms | {r.zero_copy_time_ms:7.2f} ms | {r.speedup:5.1f}x  |")

    # When to use zero-copy
    print("\n--- When to Use Zero-Copy ---\n")
    print("Recommended when:")
    print("  - Payload size > 64 KB")
    print("  - Same-host communication (intra-process or inter-process)")
    print("  - High message rates with large payloads")
    print("  - CPU is bottleneck (reduces memcpy overhead)\n")

    print("Not recommended when:")
    print("  - Small payloads (< 1 KB) - overhead dominates")
    print("  - Cross-network communication (copy required anyway)")
    print("  - Security isolation required between processes")

    # Memory considerations
    print("\n--- Memory Considerations ---\n")
    print("Shared memory must be configured:")
    print("  - /dev/shm size (Linux): check with 'df -h /dev/shm'")
    print("  - Segment size: must fit all loaned samples")
    print("  - Cleanup: segments persist until explicitly removed")

    # Python-specific notes
    print("\n--- Python-Specific Notes ---\n")
    print("Python approaches to zero-copy:")
    print("  1. memoryview - zero-copy views into bytes/bytearray")
    print("  2. mmap - memory-mapped files for shared memory")
    print("  3. multiprocessing.shared_memory (Python 3.8+)")
    print("  4. numpy arrays with shared memory backing")
    print()
    print("Example with mmap:")
    print("  import mmap")
    print("  # Anonymous shared memory")
    print("  shm = mmap.mmap(-1, size)")
    print("  # File-backed shared memory")
    print("  with open('/dev/shm/hdds_buffer', 'r+b') as f:")
    print("      shm = mmap.mmap(f.fileno(), size)")

    print("\n=== Sample Complete ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())

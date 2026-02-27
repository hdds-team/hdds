# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS telemetry and metrics collection module.

Provides counters, latency percentiles, and a TCP export server for
real-time metrics monitoring. The global metrics collector is thread-safe
and can be shared across all DDS entities in a process.

Typical workflow:
    1. Call ``init()`` to create the global metrics collector.
    2. Use ``snapshot()`` to capture point-in-time metrics.
    3. Optionally start an exporter for external monitoring tools.

Example::

    import hdds

    metrics = hdds.telemetry.init()

    # ... after some DDS activity ...
    snap = metrics.snapshot()
    print(f"Messages sent: {snap.messages_sent}")
    print(f"Latency P99: {snap.latency_p99_ms:.2f} ms")

    # Start TCP exporter for HDDS Viewer
    exporter = hdds.telemetry.start_exporter("0.0.0.0", 4242)

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

from __future__ import annotations
from ctypes import byref
from typing import Optional
from dataclasses import dataclass

from ._native import get_lib, check_error, MetricsSnapshot as _MetricsSnapshot

__all__ = ['init', 'get', 'Metrics', 'MetricsSnapshot', 'Exporter', 'start_exporter']


@dataclass
class MetricsSnapshot:
    """Point-in-time snapshot of all tracked telemetry metrics.

    All latency values are in nanoseconds. Use the convenience properties
    (``latency_p50_ms``, ``latency_p99_ms``, ``latency_p999_ms``) for
    millisecond values.

    Attributes:
        timestamp_ns: Snapshot timestamp in nanoseconds since epoch.
        messages_sent: Total messages sent across all writers.
        messages_received: Total messages received across all readers.
        messages_dropped: Total messages dropped (buffer overflow, etc.).
        bytes_sent: Total bytes sent across all writers.
        latency_p50_ns: 50th percentile (median) end-to-end latency in nanoseconds.
        latency_p99_ns: 99th percentile end-to-end latency in nanoseconds.
        latency_p999_ns: 99.9th percentile end-to-end latency in nanoseconds.
        merge_full_count: Number of backpressure events (merge buffer full).
        would_block_count: Number of would-block events (send buffer full).
    """
    timestamp_ns: int
    messages_sent: int
    messages_received: int
    messages_dropped: int
    bytes_sent: int
    latency_p50_ns: int
    latency_p99_ns: int
    latency_p999_ns: int
    merge_full_count: int
    would_block_count: int

    @property
    def latency_p50_ms(self) -> float:
        """P50 latency in milliseconds."""
        return self.latency_p50_ns / 1_000_000

    @property
    def latency_p99_ms(self) -> float:
        """P99 latency in milliseconds."""
        return self.latency_p99_ns / 1_000_000

    @property
    def latency_p999_ms(self) -> float:
        """P99.9 latency in milliseconds."""
        return self.latency_p999_ns / 1_000_000


class Metrics:
    """HDDS global metrics collector handle.

    Wraps the native metrics collector. Obtained via ``init()`` or ``get()``.
    Thread-safe: snapshot() and record_latency() can be called from any thread.
    """

    def __init__(self, handle):
        self._handle = handle

    def __del__(self):
        if self._handle:
            lib = get_lib()
            lib.hdds_telemetry_release(self._handle)
            self._handle = None

    def snapshot(self) -> MetricsSnapshot:
        """Take a point-in-time snapshot of all tracked metrics.

        Returns:
            MetricsSnapshot dataclass with current metric values.

        Raises:
            HddsException: If the snapshot operation fails.
        """
        lib = get_lib()
        raw = _MetricsSnapshot()
        err = lib.hdds_telemetry_snapshot(self._handle, byref(raw))
        check_error(err)

        return MetricsSnapshot(
            timestamp_ns=raw.timestamp_ns,
            messages_sent=raw.messages_sent,
            messages_received=raw.messages_received,
            messages_dropped=raw.messages_dropped,
            bytes_sent=raw.bytes_sent,
            latency_p50_ns=raw.latency_p50_ns,
            latency_p99_ns=raw.latency_p99_ns,
            latency_p999_ns=raw.latency_p999_ns,
            merge_full_count=raw.merge_full_count,
            would_block_count=raw.would_block_count,
        )

    def record_latency(self, start_ns: int, end_ns: int) -> None:
        """Record a latency sample for percentile tracking.

        Args:
            start_ns: Start timestamp in nanoseconds (epoch-based).
            end_ns: End timestamp in nanoseconds (epoch-based).
        """
        lib = get_lib()
        lib.hdds_telemetry_record_latency(self._handle, start_ns, end_ns)


class Exporter:
    """Telemetry TCP export server for HDDS Viewer and external tools.

    Streams metrics to connected TCP clients. Created via ``start_exporter()``.
    Stopped automatically when garbage collected, or explicitly via ``stop()``.
    """

    def __init__(self, handle):
        self._handle = handle

    def __del__(self):
        self.stop()

    def stop(self) -> None:
        """Stop the exporter and close all connections. Safe to call multiple times."""
        if self._handle:
            lib = get_lib()
            lib.hdds_telemetry_stop_exporter(self._handle)
            self._handle = None


def init() -> Metrics:
    """
    Initialize the global metrics collector.

    Returns:
        Metrics handle for taking snapshots
    """
    lib = get_lib()
    handle = lib.hdds_telemetry_init()
    if not handle:
        raise RuntimeError("Failed to initialize telemetry")
    return Metrics(handle)


def get() -> Optional[Metrics]:
    """
    Get the global metrics collector if initialized.

    Returns:
        Metrics handle, or None if not initialized
    """
    lib = get_lib()
    handle = lib.hdds_telemetry_get()
    if not handle:
        return None
    return Metrics(handle)


def start_exporter(bind_addr: str = "127.0.0.1", port: int = 4242) -> Exporter:
    """
    Start the telemetry export server.

    The exporter streams metrics to connected clients (e.g., HDDS Viewer).

    Args:
        bind_addr: IP address to bind (default: "127.0.0.1")
        port: Port number (default: 4242)

    Returns:
        Exporter handle (stops when garbage collected)
    """
    lib = get_lib()
    handle = lib.hdds_telemetry_start_exporter(bind_addr.encode('utf-8'), port)
    if not handle:
        raise RuntimeError(f"Failed to start telemetry exporter on {bind_addr}:{port}")
    return Exporter(handle)

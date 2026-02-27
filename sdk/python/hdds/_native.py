# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS Native FFI bindings via ctypes.

This module provides the low-level ctypes interface to the hdds-c shared library.
It handles library discovery, loading, function signature setup, error handling,
and C-compatible type definitions.

This is an internal module. Users should import from ``hdds`` directly.

Library Discovery Order:
    1. ``HDDS_LIB_PATH`` environment variable (explicit override).
    2. Development build paths (``target/release``, ``target/debug``).
    3. System library paths (``/usr/local/lib``, ``/usr/lib``).
    4. System dynamic linker (fallback).
"""

from __future__ import annotations
import ctypes
from ctypes import (
    c_void_p, c_char_p, c_uint8, c_uint16, c_uint32, c_uint64, c_int32, c_int64,
    c_size_t, c_bool, POINTER, Structure, byref
)
from pathlib import Path
from typing import Optional
import os
import sys


# =============================================================================
# Library Loading
# =============================================================================

def _find_library() -> str:
    """Find the hdds-c shared library."""
    # Search paths in order of preference:
    # 1. HDDS_LIB_PATH (explicit user override - MUST be first!)
    # 2. Development paths (for dev builds)
    # 3. System paths (fallback)
    search_paths = []

    # Environment variable takes highest priority
    if hdds_lib_path := os.environ.get("HDDS_LIB_PATH"):
        search_paths.append(Path(hdds_lib_path))

    # Development: relative to this file
    search_paths.extend([
        Path(__file__).parent.parent.parent.parent.parent / "target" / "release",
        Path(__file__).parent.parent.parent.parent.parent / "target" / "debug",
    ])

    # Installed: system paths (last resort)
    search_paths.extend([
        Path("/usr/local/lib"),
        Path("/usr/lib"),
    ])

    lib_name = {
        "linux": "libhdds_c.so",
        "darwin": "libhdds_c.dylib",
        "win32": "hdds_c.dll",
    }.get(sys.platform, "libhdds_c.so")

    for path in search_paths:
        lib_path = path / lib_name
        if lib_path.exists():
            return str(lib_path)

    # Try system loader
    return lib_name


def _load_library() -> ctypes.CDLL:
    """Load the hdds-c library."""
    lib_path = _find_library()
    try:
        return ctypes.CDLL(lib_path)
    except OSError as e:
        raise ImportError(
            f"Could not load hdds-c library from {lib_path}. "
            f"Make sure hdds-c is built: cargo build --release -p hdds-c\n"
            f"Error: {e}"
        )


# Load library
_lib: Optional[ctypes.CDLL] = None


def get_lib() -> ctypes.CDLL:
    """Get the loaded hdds-c library, loading it lazily on first call.

    The library is loaded once and cached for the lifetime of the process.
    Function signatures are set up immediately after loading.

    Returns:
        The loaded ctypes.CDLL handle.

    Raises:
        ImportError: If the hdds-c shared library cannot be found or loaded.
    """
    global _lib
    if _lib is None:
        _lib = _load_library()
        _setup_signatures(_lib)
    return _lib


# =============================================================================
# Error Handling
# =============================================================================

class HddsError:
    """Error codes from the hdds-c library.

    These constants correspond to the HddsError enum in hdds.h.
    Only a subset of the full error range is exposed here; additional
    error codes (10+) may be returned by the C library for domain-specific errors.

    Attributes:
        OK: Operation completed successfully.
        INVALID_ARGUMENT: Invalid argument provided (null pointer, invalid value).
        NOT_FOUND: Requested resource not found (also used for no-data-available).
        OPERATION_FAILED: Generic operation failure.
        OUT_OF_MEMORY: Memory allocation failed.
    """
    OK = 0
    INVALID_ARGUMENT = 1
    NOT_FOUND = 2
    OPERATION_FAILED = 3
    OUT_OF_MEMORY = 4


class HddsException(Exception):
    """Exception raised by HDDS FFI operations.

    Wraps an integer error code from the C library with a human-readable message.

    Args:
        code: Integer error code from HddsError.
        message: Optional override message. If empty, auto-generated from code.

    Attributes:
        code: The integer error code.
        message: Human-readable error description.
    """
    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message or self._code_to_message(code)
        super().__init__(self.message)

    @staticmethod
    def _code_to_message(code: int) -> str:
        return {
            HddsError.OK: "OK",
            HddsError.INVALID_ARGUMENT: "Invalid argument",
            HddsError.NOT_FOUND: "Not found",
            HddsError.OPERATION_FAILED: "Operation failed",
            HddsError.OUT_OF_MEMORY: "Out of memory",
        }.get(code, f"Unknown error ({code})")


def check_error(code: int) -> None:
    """Check an FFI return code and raise HddsException if it indicates failure.

    Args:
        code: Integer error code returned by a C FFI function.

    Raises:
        HddsException: If code is not HddsError.OK.
    """
    if code != HddsError.OK:
        raise HddsException(code)


# =============================================================================
# Liveliness Kind Enum
# =============================================================================

class LivelinessKind:
    """Liveliness QoS kind values.

    Controls how the DDS infrastructure determines whether an entity is alive.

    Attributes:
        AUTOMATIC: Infrastructure automatically asserts liveliness.
        MANUAL_BY_PARTICIPANT: Application asserts per participant.
        MANUAL_BY_TOPIC: Application asserts per writer/topic.
    """
    AUTOMATIC = 0
    MANUAL_BY_PARTICIPANT = 1
    MANUAL_BY_TOPIC = 2


# =============================================================================
# Function Signatures
# =============================================================================

def _setup_signatures(lib: ctypes.CDLL) -> None:
    """Set up function signatures for type safety."""

    # -------------------------------------------------------------------------
    # Participant
    # -------------------------------------------------------------------------
    lib.hdds_participant_create.argtypes = [c_char_p]
    lib.hdds_participant_create.restype = c_void_p

    lib.hdds_participant_destroy.argtypes = [c_void_p]
    lib.hdds_participant_destroy.restype = None

    lib.hdds_participant_graph_guard_condition.argtypes = [c_void_p]
    lib.hdds_participant_graph_guard_condition.restype = c_void_p

    # -------------------------------------------------------------------------
    # DataWriter
    # -------------------------------------------------------------------------
    lib.hdds_writer_create.argtypes = [c_void_p, c_char_p]
    lib.hdds_writer_create.restype = c_void_p

    lib.hdds_writer_create_with_qos.argtypes = [c_void_p, c_char_p, c_void_p]
    lib.hdds_writer_create_with_qos.restype = c_void_p

    lib.hdds_writer_write.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
    lib.hdds_writer_write.restype = c_int32

    lib.hdds_writer_destroy.argtypes = [c_void_p]
    lib.hdds_writer_destroy.restype = None

    # -------------------------------------------------------------------------
    # DataReader
    # -------------------------------------------------------------------------
    lib.hdds_reader_create.argtypes = [c_void_p, c_char_p]
    lib.hdds_reader_create.restype = c_void_p

    lib.hdds_reader_create_with_qos.argtypes = [c_void_p, c_char_p, c_void_p]
    lib.hdds_reader_create_with_qos.restype = c_void_p

    lib.hdds_reader_take.argtypes = [c_void_p, POINTER(c_uint8), c_size_t, POINTER(c_size_t)]
    lib.hdds_reader_take.restype = c_int32

    lib.hdds_reader_get_status_condition.argtypes = [c_void_p]
    lib.hdds_reader_get_status_condition.restype = c_void_p

    lib.hdds_reader_destroy.argtypes = [c_void_p]
    lib.hdds_reader_destroy.restype = None

    # -------------------------------------------------------------------------
    # QoS
    # -------------------------------------------------------------------------
    lib.hdds_qos_default.argtypes = []
    lib.hdds_qos_default.restype = c_void_p

    lib.hdds_qos_reliable.argtypes = []
    lib.hdds_qos_reliable.restype = c_void_p

    lib.hdds_qos_best_effort.argtypes = []
    lib.hdds_qos_best_effort.restype = c_void_p

    lib.hdds_qos_rti_defaults.argtypes = []
    lib.hdds_qos_rti_defaults.restype = c_void_p

    lib.hdds_qos_destroy.argtypes = [c_void_p]
    lib.hdds_qos_destroy.restype = None

    lib.hdds_qos_clone.argtypes = [c_void_p]
    lib.hdds_qos_clone.restype = c_void_p

    # QoS Setters
    lib.hdds_qos_set_history_depth.argtypes = [c_void_p, c_uint32]
    lib.hdds_qos_set_history_depth.restype = c_int32

    lib.hdds_qos_set_history_keep_all.argtypes = [c_void_p]
    lib.hdds_qos_set_history_keep_all.restype = c_int32

    lib.hdds_qos_set_persistent.argtypes = [c_void_p]
    lib.hdds_qos_set_persistent.restype = c_int32

    lib.hdds_qos_set_reliable.argtypes = [c_void_p]
    lib.hdds_qos_set_reliable.restype = c_int32

    lib.hdds_qos_set_best_effort.argtypes = [c_void_p]
    lib.hdds_qos_set_best_effort.restype = c_int32

    lib.hdds_qos_set_volatile.argtypes = [c_void_p]
    lib.hdds_qos_set_volatile.restype = c_int32

    lib.hdds_qos_set_transient_local.argtypes = [c_void_p]
    lib.hdds_qos_set_transient_local.restype = c_int32

    lib.hdds_qos_set_deadline_ns.argtypes = [c_void_p, c_uint64]
    lib.hdds_qos_set_deadline_ns.restype = c_int32

    lib.hdds_qos_set_lifespan_ns.argtypes = [c_void_p, c_uint64]
    lib.hdds_qos_set_lifespan_ns.restype = c_int32

    lib.hdds_qos_set_ownership_shared.argtypes = [c_void_p]
    lib.hdds_qos_set_ownership_shared.restype = c_int32

    lib.hdds_qos_set_ownership_exclusive.argtypes = [c_void_p, c_int32]
    lib.hdds_qos_set_ownership_exclusive.restype = c_int32

    lib.hdds_qos_add_partition.argtypes = [c_void_p, c_char_p]
    lib.hdds_qos_add_partition.restype = c_int32

    lib.hdds_qos_set_liveliness_automatic_ns.argtypes = [c_void_p, c_uint64]
    lib.hdds_qos_set_liveliness_automatic_ns.restype = c_int32

    lib.hdds_qos_set_liveliness_manual_participant_ns.argtypes = [c_void_p, c_uint64]
    lib.hdds_qos_set_liveliness_manual_participant_ns.restype = c_int32

    lib.hdds_qos_set_liveliness_manual_topic_ns.argtypes = [c_void_p, c_uint64]
    lib.hdds_qos_set_liveliness_manual_topic_ns.restype = c_int32

    lib.hdds_qos_set_time_based_filter_ns.argtypes = [c_void_p, c_uint64]
    lib.hdds_qos_set_time_based_filter_ns.restype = c_int32

    lib.hdds_qos_set_latency_budget_ns.argtypes = [c_void_p, c_uint64]
    lib.hdds_qos_set_latency_budget_ns.restype = c_int32

    lib.hdds_qos_set_transport_priority.argtypes = [c_void_p, c_int32]
    lib.hdds_qos_set_transport_priority.restype = c_int32

    lib.hdds_qos_set_resource_limits.argtypes = [c_void_p, c_size_t, c_size_t, c_size_t]
    lib.hdds_qos_set_resource_limits.restype = c_int32

    # QoS Getters
    lib.hdds_qos_is_reliable.argtypes = [c_void_p]
    lib.hdds_qos_is_reliable.restype = c_bool

    lib.hdds_qos_is_transient_local.argtypes = [c_void_p]
    lib.hdds_qos_is_transient_local.restype = c_bool

    lib.hdds_qos_get_history_depth.argtypes = [c_void_p]
    lib.hdds_qos_get_history_depth.restype = c_uint32

    lib.hdds_qos_get_deadline_ns.argtypes = [c_void_p]
    lib.hdds_qos_get_deadline_ns.restype = c_uint64

    lib.hdds_qos_get_lifespan_ns.argtypes = [c_void_p]
    lib.hdds_qos_get_lifespan_ns.restype = c_uint64

    lib.hdds_qos_is_ownership_exclusive.argtypes = [c_void_p]
    lib.hdds_qos_is_ownership_exclusive.restype = c_bool

    lib.hdds_qos_get_ownership_strength.argtypes = [c_void_p]
    lib.hdds_qos_get_ownership_strength.restype = c_int32

    lib.hdds_qos_get_liveliness_kind.argtypes = [c_void_p]
    lib.hdds_qos_get_liveliness_kind.restype = c_int32

    lib.hdds_qos_get_liveliness_lease_ns.argtypes = [c_void_p]
    lib.hdds_qos_get_liveliness_lease_ns.restype = c_uint64

    lib.hdds_qos_get_time_based_filter_ns.argtypes = [c_void_p]
    lib.hdds_qos_get_time_based_filter_ns.restype = c_uint64

    lib.hdds_qos_get_latency_budget_ns.argtypes = [c_void_p]
    lib.hdds_qos_get_latency_budget_ns.restype = c_uint64

    lib.hdds_qos_get_transport_priority.argtypes = [c_void_p]
    lib.hdds_qos_get_transport_priority.restype = c_int32

    lib.hdds_qos_get_max_samples.argtypes = [c_void_p]
    lib.hdds_qos_get_max_samples.restype = c_size_t

    lib.hdds_qos_get_max_instances.argtypes = [c_void_p]
    lib.hdds_qos_get_max_instances.restype = c_size_t

    lib.hdds_qos_get_max_samples_per_instance.argtypes = [c_void_p]
    lib.hdds_qos_get_max_samples_per_instance.restype = c_size_t

    # -------------------------------------------------------------------------
    # WaitSet
    # -------------------------------------------------------------------------
    lib.hdds_waitset_create.argtypes = []
    lib.hdds_waitset_create.restype = c_void_p

    lib.hdds_waitset_destroy.argtypes = [c_void_p]
    lib.hdds_waitset_destroy.restype = None

    lib.hdds_waitset_attach_status_condition.argtypes = [c_void_p, c_void_p]
    lib.hdds_waitset_attach_status_condition.restype = c_int32

    lib.hdds_waitset_attach_guard_condition.argtypes = [c_void_p, c_void_p]
    lib.hdds_waitset_attach_guard_condition.restype = c_int32

    lib.hdds_waitset_detach_condition.argtypes = [c_void_p, c_void_p]
    lib.hdds_waitset_detach_condition.restype = c_int32

    lib.hdds_waitset_wait.argtypes = [c_void_p, c_int64, POINTER(c_void_p), c_size_t, POINTER(c_size_t)]
    lib.hdds_waitset_wait.restype = c_int32

    # -------------------------------------------------------------------------
    # GuardCondition
    # -------------------------------------------------------------------------
    lib.hdds_guard_condition_create.argtypes = []
    lib.hdds_guard_condition_create.restype = c_void_p

    lib.hdds_guard_condition_release.argtypes = [c_void_p]
    lib.hdds_guard_condition_release.restype = None

    lib.hdds_guard_condition_set_trigger.argtypes = [c_void_p, c_bool]
    lib.hdds_guard_condition_set_trigger.restype = c_int32

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------
    lib.hdds_logging_init.argtypes = [c_int32]
    lib.hdds_logging_init.restype = c_int32

    lib.hdds_logging_init_env.argtypes = [c_int32]
    lib.hdds_logging_init_env.restype = c_int32

    lib.hdds_logging_init_with_filter.argtypes = [c_char_p]
    lib.hdds_logging_init_with_filter.restype = c_int32

    # -------------------------------------------------------------------------
    # Participant Info
    # -------------------------------------------------------------------------
    lib.hdds_participant_name.argtypes = [c_void_p]
    lib.hdds_participant_name.restype = c_char_p

    lib.hdds_participant_domain_id.argtypes = [c_void_p]
    lib.hdds_participant_domain_id.restype = c_uint32

    lib.hdds_participant_id.argtypes = [c_void_p]
    lib.hdds_participant_id.restype = c_uint8

    # -------------------------------------------------------------------------
    # Entity Info
    # -------------------------------------------------------------------------
    lib.hdds_writer_topic_name.argtypes = [c_void_p, c_char_p, c_size_t, POINTER(c_size_t)]
    lib.hdds_writer_topic_name.restype = c_int32

    lib.hdds_reader_topic_name.argtypes = [c_void_p, c_char_p, c_size_t, POINTER(c_size_t)]
    lib.hdds_reader_topic_name.restype = c_int32

    # -------------------------------------------------------------------------
    # Publisher / Subscriber
    # -------------------------------------------------------------------------
    lib.hdds_publisher_create.argtypes = [c_void_p]
    lib.hdds_publisher_create.restype = c_void_p

    lib.hdds_publisher_create_with_qos.argtypes = [c_void_p, c_void_p]
    lib.hdds_publisher_create_with_qos.restype = c_void_p

    lib.hdds_publisher_destroy.argtypes = [c_void_p]
    lib.hdds_publisher_destroy.restype = None

    lib.hdds_subscriber_create.argtypes = [c_void_p]
    lib.hdds_subscriber_create.restype = c_void_p

    lib.hdds_subscriber_create_with_qos.argtypes = [c_void_p, c_void_p]
    lib.hdds_subscriber_create_with_qos.restype = c_void_p

    lib.hdds_subscriber_destroy.argtypes = [c_void_p]
    lib.hdds_subscriber_destroy.restype = None

    # -------------------------------------------------------------------------
    # Publisher -> DataWriter
    # -------------------------------------------------------------------------
    lib.hdds_publisher_create_writer.argtypes = [c_void_p, c_char_p]
    lib.hdds_publisher_create_writer.restype = c_void_p

    lib.hdds_publisher_create_writer_with_qos.argtypes = [c_void_p, c_char_p, c_void_p]
    lib.hdds_publisher_create_writer_with_qos.restype = c_void_p

    # -------------------------------------------------------------------------
    # Subscriber -> DataReader
    # -------------------------------------------------------------------------
    lib.hdds_subscriber_create_reader.argtypes = [c_void_p, c_char_p]
    lib.hdds_subscriber_create_reader.restype = c_void_p

    lib.hdds_subscriber_create_reader_with_qos.argtypes = [c_void_p, c_char_p, c_void_p]
    lib.hdds_subscriber_create_reader_with_qos.restype = c_void_p

    # -------------------------------------------------------------------------
    # Participant (extended)
    # -------------------------------------------------------------------------
    lib.hdds_participant_create_with_transport.argtypes = [c_char_p, c_int32]
    lib.hdds_participant_create_with_transport.restype = c_void_p

    # -------------------------------------------------------------------------
    # Status Condition
    # -------------------------------------------------------------------------
    lib.hdds_status_condition_release.argtypes = [c_void_p]
    lib.hdds_status_condition_release.restype = None

    # -------------------------------------------------------------------------
    # Version
    # -------------------------------------------------------------------------
    lib.hdds_version.argtypes = []
    lib.hdds_version.restype = c_char_p

    # -------------------------------------------------------------------------
    # QoS XML Loading (optional, requires qos-loaders feature)
    # -------------------------------------------------------------------------
    if hasattr(lib, 'hdds_qos_from_xml'):
        lib.hdds_qos_from_xml.argtypes = [c_char_p]
        lib.hdds_qos_from_xml.restype = c_void_p

    if hasattr(lib, 'hdds_qos_load_fastdds_xml'):
        lib.hdds_qos_load_fastdds_xml.argtypes = [c_char_p]
        lib.hdds_qos_load_fastdds_xml.restype = c_void_p

    # -------------------------------------------------------------------------
    # TypeObject (optional, requires xtypes feature)
    # -------------------------------------------------------------------------
    if hasattr(lib, 'hdds_type_object_release'):
        lib.hdds_type_object_release.argtypes = [c_void_p]
        lib.hdds_type_object_release.restype = None

    if hasattr(lib, 'hdds_type_object_hash'):
        lib.hdds_type_object_hash.argtypes = [c_void_p, POINTER(c_uint8), POINTER(c_uint8), c_size_t]
        lib.hdds_type_object_hash.restype = c_int32

    # -------------------------------------------------------------------------
    # Telemetry
    # -------------------------------------------------------------------------
    lib.hdds_telemetry_init.argtypes = []
    lib.hdds_telemetry_init.restype = c_void_p

    lib.hdds_telemetry_get.argtypes = []
    lib.hdds_telemetry_get.restype = c_void_p

    lib.hdds_telemetry_release.argtypes = [c_void_p]
    lib.hdds_telemetry_release.restype = None

    lib.hdds_telemetry_snapshot.argtypes = [c_void_p, c_void_p]
    lib.hdds_telemetry_snapshot.restype = c_int32

    lib.hdds_telemetry_record_latency.argtypes = [c_void_p, c_uint64, c_uint64]
    lib.hdds_telemetry_record_latency.restype = None

    lib.hdds_telemetry_start_exporter.argtypes = [c_char_p, c_uint16]
    lib.hdds_telemetry_start_exporter.restype = c_void_p

    lib.hdds_telemetry_stop_exporter.argtypes = [c_void_p]
    lib.hdds_telemetry_stop_exporter.restype = None


# =============================================================================
# Log Level Enum
# =============================================================================

class TransportMode:
    """Transport mode for participant creation.

    Attributes:
        INTRA_PROCESS: No network, fastest for same-process communication.
        UDP_MULTICAST: UDP multicast for network discovery and communication.
    """
    INTRA_PROCESS = 0
    UDP_MULTICAST = 1


class LogLevel:
    """HDDS logging level constants.

    Attributes:
        OFF: Logging disabled.
        ERROR: Error-level messages only.
        WARN: Warning and above.
        INFO: Informational and above (default).
        DEBUG: Debug and above.
        TRACE: All messages including trace.
    """
    OFF = 0
    ERROR = 1
    WARN = 2
    INFO = 3
    DEBUG = 4
    TRACE = 5


# =============================================================================
# Metrics Snapshot Structure
# =============================================================================

class MetricsSnapshot(Structure):
    """C-compatible telemetry metrics snapshot structure.

    Maps directly to the HddsMetricsSnapshot struct in hdds.h.
    Used internally by the telemetry module. Users should use
    ``hdds.telemetry.MetricsSnapshot`` (the dataclass version) instead.
    """
    _fields_ = [
        ("timestamp_ns", c_uint64),
        ("messages_sent", c_uint64),
        ("messages_received", c_uint64),
        ("messages_dropped", c_uint64),
        ("bytes_sent", c_uint64),
        ("latency_p50_ns", c_uint64),
        ("latency_p99_ns", c_uint64),
        ("latency_p999_ns", c_uint64),
        ("merge_full_count", c_uint64),
        ("would_block_count", c_uint64),
    ]

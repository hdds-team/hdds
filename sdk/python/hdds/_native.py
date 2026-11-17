# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS Native FFI bindings via ctypes.

This module provides the low-level ctypes interface to the hdds-c shared library.
It handles library discovery, loading, function signature setup, error handling,
and C-compatible type definitions.

This is an internal module. Users should import from ``hdds`` directly.

Library Discovery Order:
    1. ``HDDS_LIB_PATH`` environment variable (strict override): a directory
       containing ``libhdds_c.so`` or the full path of the library. When set,
       it is the ONLY candidate; nothing else is probed. A relative value is
       resolved against the current directory; an empty value is an error,
       never a fallback.
    2. Library bundled inside the installed package,
       ``<package>/_lib/libhdds_c.so``. Only a wheel built with the native
       library inside it ships that directory; no wheel built from this
       repository does today, so the candidate is normally absent.
    3. Repository development build, ``<repo>/target/release`` then
       ``<repo>/target/debug``. Source checkouts only: the tier exists when
       this file sits at ``<repo>/sdk/python/hdds/_native.py`` next to the
       workspace ``Cargo.toml``; an installed wheel skips it.
    4. System library directories, ``/usr/local/lib`` then ``/usr/lib``.
    5. The bare library name handed to the system dynamic linker
       (``LD_LIBRARY_PATH`` / ``ldconfig``).

Loading fails closed: when no candidate loads, ``ImportError`` lists every
path that was tried, the dynamic-linker error of every candidate that
existed but did not load, and the build command for the native library
(``cargo build --release -p hdds-c``, default features).

A candidate that exists but fails to load stops the search only when it
came from ``HDDS_LIB_PATH``: an explicit override is never silently
replaced by another library. On the implicit tiers 2-5 the error is
recorded and the next candidate is tried, so a stale or ``--all-features``
build left in ``target/release`` cannot mask a working library further
down the order; every recorded error is reported if none of them loads.
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

# Build command for the native library. Default features only: an
# ``--all-features`` build links the ``rmw`` feature, whose ROS 2 symbols
# (rosidl_runtime_c_*) are undefined outside a sourced ROS 2 environment.
BUILD_COMMAND = "cargo build --release -p hdds-c"

_LIB_NAMES = {
    "linux": "libhdds_c.so",
    "darwin": "libhdds_c.dylib",
    "win32": "hdds_c.dll",
}


def _library_name() -> str:
    """Platform-specific file name of the hdds-c shared library."""
    return _LIB_NAMES.get(sys.platform, "libhdds_c.so")


def _repo_root() -> Optional[Path]:
    """Repository root when this file lives in a source checkout.

    ``<repo>/sdk/python/hdds/_native.py`` has the repository root four
    levels up. Returns ``None`` unless that directory looks like the
    checkout (``sdk/python/hdds/_native.py`` below it and a workspace
    ``Cargo.toml`` beside ``sdk``): an installed wheel under
    ``site-packages`` never gets a development-build candidate.
    """
    try:
        root = Path(__file__).resolve().parents[3]
    except IndexError:
        return None
    checkout = root / "sdk" / "python" / "hdds" / "_native.py"
    if checkout.is_file() and (root / "Cargo.toml").is_file():
        return root
    return None


def _bundled_dir() -> Path:
    """Directory a bundled-library wheel ships the native library in.

    Populated only by a wheel built with ``libhdds_c.so`` inside it (fat
    manylinux wheel): the pure-Python wheel built from
    this repository never ships one, so the candidate normally does not
    exist on disk and is skipped.
    """
    return Path(__file__).resolve().parent / "_lib"


def _candidates() -> list:
    """Ordered list of load candidates (see the module docstring).

    Entries are absolute file paths, except for a trailing bare library
    name which is handed to the system dynamic linker. When
    ``HDDS_LIB_PATH`` is set the list holds exactly one entry.
    """
    lib_name = _library_name()

    override = os.environ.get("HDDS_LIB_PATH")
    if override is not None:
        if override.strip() == "":
            raise _import_error(
                [], "HDDS_LIB_PATH is set but empty (unset it to use the "
                "default discovery order, or point it at the library)")
        override_path = Path(os.path.abspath(os.path.expanduser(override)))
        # A full library path (existing file, or a name carrying a shared
        # library suffix) is taken as is; anything else is a directory.
        is_file = override_path.is_file() or bool(
            {".so", ".dylib", ".dll"} & set(override_path.suffixes)
        )
        if is_file:
            return [str(override_path)]
        return [str(override_path / lib_name)]

    candidates = [str(_bundled_dir() / lib_name)]
    repo_root = _repo_root()
    if repo_root is not None:
        candidates.append(str(repo_root / "target" / "release" / lib_name))
        candidates.append(str(repo_root / "target" / "debug" / lib_name))
    candidates.append(str(Path("/usr/local/lib") / lib_name))
    candidates.append(str(Path("/usr") / "lib" / lib_name))
    candidates.append(lib_name)
    return candidates


def _import_error(tried: list, detail: str, errors: Optional[list] = None) -> ImportError:
    """Fail-closed ImportError: every candidate, and why each one that existed failed.

    ``errors`` is a list of ``(candidate, message)`` pairs recorded while
    walking the implicit tiers; nothing is dropped, so a library that
    existed but did not load is always reported even when a later
    candidate also failed.
    """
    failures = dict(errors or [])
    lines = ["Could not load the hdds-c native library (" + _library_name() + ")."]
    if detail:
        lines.append("Last error: " + detail)
    lines.append("Paths tried, in order:" if tried else "Paths tried: none")
    for candidate in tried:
        if os.path.isabs(candidate):
            lines.append("  - " + candidate)
        else:
            lines.append("  - " + candidate + " (system dynamic linker)")
        if candidate in failures:
            lines.append("      exists but did not load: " + failures[candidate])
    lines.append(
        "Build it from the repository with: " + BUILD_COMMAND
        + " (default features; never --all-features, the rmw feature needs ROS 2)"
    )
    lines.append(
        "then point HDDS_LIB_PATH at the directory holding the library "
        "(for example <repo>/target/release)."
    )
    return ImportError("\n".join(lines))


def _override_is_set() -> bool:
    """True when ``HDDS_LIB_PATH`` selects the library explicitly."""
    return os.environ.get("HDDS_LIB_PATH") is not None


def _load_library() -> "tuple[ctypes.CDLL, str]":
    """Load the hdds-c library, fail closed with an actionable ImportError.

    Returns the loaded handle and the path (or bare name) that loaded it.

    An explicit ``HDDS_LIB_PATH`` candidate that exists but fails to load
    raises immediately: the override is the only candidate and is never
    replaced by another library. On the implicit tiers the failure is
    recorded and the search continues, so a stale or ``--all-features``
    build sitting in ``target/release`` (undefined ROS 2 symbols) does not
    hide a working library on a later tier; if nothing loads, every
    recorded error is listed in the ImportError.
    """
    strict = _override_is_set()
    tried = []
    errors = []
    for candidate in _candidates():
        tried.append(candidate)
        if os.path.isabs(candidate) and not os.path.isfile(candidate):
            continue
        try:
            return ctypes.CDLL(candidate), candidate
        except OSError as e:
            if strict:
                raise _import_error(tried, str(e), [(candidate, str(e))]) from e
            errors.append((candidate, str(e)))
    detail = errors[-1][1] if errors else "no candidate exists on disk"
    raise _import_error(tried, detail, errors)


# Load library
_lib: Optional[ctypes.CDLL] = None
_lib_path: Optional[str] = None


def get_lib() -> ctypes.CDLL:
    """Get the loaded hdds-c library, loading it lazily on first call.

    The library is loaded once and cached for the lifetime of the process.
    Function signatures are set up immediately after loading.

    Returns:
        The loaded ctypes.CDLL handle.

    Raises:
        ImportError: If the hdds-c shared library cannot be found or loaded.
    """
    global _lib, _lib_path
    if _lib is None:
        lib, path = _load_library()
        _setup_signatures(lib)
        _lib = lib
        _lib_path = path
    return _lib


def library_path() -> str:
    """Path of the native library in use (loads it on first call).

    Returns the absolute path that was loaded, or the bare library name
    when the system dynamic linker resolved it (discovery tier 5).

    Raises:
        ImportError: If the hdds-c shared library cannot be found or loaded.
    """
    get_lib()
    path = _lib_path
    # Not an assert: ``python -O`` strips those, and this function is
    # annotated ``-> str``.
    if path is None:
        raise ImportError("hdds-c library loaded without recording its path")
    return path


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
        INVALID_STATE: Invalid entity state for the operation (DDS
            PRECONDITION_NOT_MET: a read outside an access bracket of a
            GROUP-scope Subscriber, an end_access with no begin_access).
        TIMEOUT: Operation did not complete before the requested timeout.
        UNSUPPORTED: The operation is not implemented by the loaded library.
    """
    OK = 0
    INVALID_ARGUMENT = 1
    NOT_FOUND = 2
    OPERATION_FAILED = 3
    OUT_OF_MEMORY = 4
    INVALID_STATE = 14
    TIMEOUT = 24
    UNSUPPORTED = 41


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
            HddsError.INVALID_STATE: "Invalid state (PRECONDITION_NOT_MET)",
            HddsError.TIMEOUT: "Timeout",
            HddsError.UNSUPPORTED: "Not supported by the native library",
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

    # Newer than the 1.4.0 C ABI manifest, like matched_reader_count below:
    # guarded so the binding still loads an older libhdds_c
    # (Participant.assert_liveliness() then raises).
    if hasattr(lib, 'hdds_participant_assert_liveliness'):
        lib.hdds_participant_assert_liveliness.argtypes = [c_void_p]
        lib.hdds_participant_assert_liveliness.restype = c_int32

    # -------------------------------------------------------------------------
    # DataWriter
    # -------------------------------------------------------------------------
    lib.hdds_writer_create.argtypes = [c_void_p, c_char_p]
    lib.hdds_writer_create.restype = c_void_p

    lib.hdds_writer_create_with_qos.argtypes = [c_void_p, c_char_p, c_void_p]
    lib.hdds_writer_create_with_qos.restype = c_void_p

    lib.hdds_writer_create_with_type.argtypes = [c_void_p, c_char_p, c_char_p, c_void_p]
    lib.hdds_writer_create_with_type.restype = c_void_p

    lib.hdds_writer_write.argtypes = [c_void_p, POINTER(c_uint8), c_size_t]
    lib.hdds_writer_write.restype = c_int32

    # Newer than the 1.4.0 C ABI manifest: guarded so the binding still loads
    # an older libhdds_c (DataWriter.matched_reader_count() then raises).
    if hasattr(lib, 'hdds_writer_matched_reader_count'):
        lib.hdds_writer_matched_reader_count.argtypes = [c_void_p, POINTER(c_uint32)]
        lib.hdds_writer_matched_reader_count.restype = c_int32

    if hasattr(lib, 'hdds_writer_wait_for_matched_readers'):
        lib.hdds_writer_wait_for_matched_readers.argtypes = [c_void_p, c_uint32, c_uint64]
        lib.hdds_writer_wait_for_matched_readers.restype = c_int32

    if hasattr(lib, 'hdds_writer_wait_for_acknowledgments'):
        lib.hdds_writer_wait_for_acknowledgments.argtypes = [c_void_p, c_uint64]
        lib.hdds_writer_wait_for_acknowledgments.restype = c_int32

    # Newer than the 1.4.0 C ABI manifest, like matched_reader_count above:
    # guarded so the binding still loads an older libhdds_c
    # (DataWriter.assert_liveliness() then raises).
    if hasattr(lib, 'hdds_writer_assert_liveliness'):
        lib.hdds_writer_assert_liveliness.argtypes = [c_void_p]
        lib.hdds_writer_assert_liveliness.restype = c_int32

    lib.hdds_writer_destroy.argtypes = [c_void_p]
    lib.hdds_writer_destroy.restype = None

    # Newer than the 1.4.0 C ABI manifest, like matched_reader_count above:
    # guarded so the binding still loads an older libhdds_c
    # (DataWriter.get_status_condition() then raises).
    if hasattr(lib, 'hdds_writer_get_status_condition'):
        lib.hdds_writer_get_status_condition.argtypes = [c_void_p]
        lib.hdds_writer_get_status_condition.restype = c_void_p

    # -------------------------------------------------------------------------
    # DataReader
    # -------------------------------------------------------------------------
    lib.hdds_reader_create.argtypes = [c_void_p, c_char_p]
    lib.hdds_reader_create.restype = c_void_p

    lib.hdds_reader_create_with_qos.argtypes = [c_void_p, c_char_p, c_void_p]
    lib.hdds_reader_create_with_qos.restype = c_void_p

    lib.hdds_reader_create_with_type.argtypes = [c_void_p, c_char_p, c_char_p, c_void_p]
    lib.hdds_reader_create_with_type.restype = c_void_p

    lib.hdds_reader_take.argtypes = [c_void_p, POINTER(c_uint8), c_size_t, POINTER(c_size_t)]
    lib.hdds_reader_take.restype = c_int32

    # DATA_REPRESENTATION and the per-sample representation (newer than the
    # 1.4.0 C ABI): guarded so the binding still loads an older libhdds_c,
    # whose readers then request XCDR2 only and take without the identifier.
    if hasattr(lib, 'hdds_reader_take_ex'):
        lib.hdds_reader_take_ex.argtypes = [
            c_void_p, POINTER(c_uint8), c_size_t, POINTER(c_size_t), POINTER(c_uint16)]
        lib.hdds_reader_take_ex.restype = c_int32
    if hasattr(lib, 'hdds_qos_set_data_representation'):
        lib.hdds_qos_set_data_representation.argtypes = [
            c_void_p, POINTER(ctypes.c_int16), c_size_t]
        lib.hdds_qos_set_data_representation.restype = c_int32
    if hasattr(lib, 'hdds_qos_get_data_representation'):
        lib.hdds_qos_get_data_representation.argtypes = [
            c_void_p, POINTER(ctypes.c_int16), c_size_t, POINTER(c_size_t)]
        lib.hdds_qos_get_data_representation.restype = c_int32
    if hasattr(lib, 'hdds_writer_create_with_extensibility'):
        lib.hdds_writer_create_with_extensibility.argtypes = [
            c_void_p, c_char_p, c_char_p, c_void_p, c_uint32]
        lib.hdds_writer_create_with_extensibility.restype = c_void_p

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

    # Newer than the 1.4.0 C ABI manifest: guarded so the binding still loads
    # an older libhdds_c (QoS.max_blocking_time_ms()/_secs() then raises).
    if hasattr(lib, 'hdds_qos_set_max_blocking_time_ns'):
        lib.hdds_qos_set_max_blocking_time_ns.argtypes = [c_void_p, c_uint64]
        lib.hdds_qos_set_max_blocking_time_ns.restype = c_int32

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

    if hasattr(lib, 'hdds_qos_get_max_blocking_time_ns'):
        lib.hdds_qos_get_max_blocking_time_ns.argtypes = [c_void_p]
        lib.hdds_qos_get_max_blocking_time_ns.restype = c_uint64

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
    lib.hdds_guard_condition_set_trigger.restype = None

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

    # Newer than the 1.4.0 C ABI manifest, like hdds_writer_wait_for_acknowledgments:
    # guarded so the binding still loads an older libhdds_c
    # (Publisher.wait_for_acknowledgments() then raises).
    if hasattr(lib, 'hdds_publisher_wait_for_acknowledgments'):
        lib.hdds_publisher_wait_for_acknowledgments.argtypes = [c_void_p, c_uint64]
        lib.hdds_publisher_wait_for_acknowledgments.restype = c_int32

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

    if hasattr(lib, 'hdds_publisher_create_writer_with_extensibility'):
        lib.hdds_publisher_create_writer_with_extensibility.argtypes = [
            c_void_p, c_char_p, c_void_p, c_uint32]
        lib.hdds_publisher_create_writer_with_extensibility.restype = c_void_p

    # A writer created for a type announces that type's name (absent from an
    # older library).
    if hasattr(lib, 'hdds_publisher_create_writer_with_type'):
        lib.hdds_publisher_create_writer_with_type.argtypes = [
            c_void_p, c_char_p, c_char_p, c_void_p, c_uint32]
        lib.hdds_publisher_create_writer_with_type.restype = c_void_p

    # -------------------------------------------------------------------------
    # Subscriber -> DataReader
    # -------------------------------------------------------------------------
    # Access brackets (DDS v1.4 Sec.2.2.2.5.2.8); absent from an older
    # library.
    if hasattr(lib, 'hdds_subscriber_begin_access'):
        lib.hdds_subscriber_begin_access.argtypes = [c_void_p]
        lib.hdds_subscriber_begin_access.restype = c_int32
    if hasattr(lib, 'hdds_subscriber_end_access'):
        lib.hdds_subscriber_end_access.argtypes = [c_void_p]
        lib.hdds_subscriber_end_access.restype = c_int32

    lib.hdds_subscriber_create_reader.argtypes = [c_void_p, c_char_p]
    lib.hdds_subscriber_create_reader.restype = c_void_p

    lib.hdds_subscriber_create_reader_with_qos.argtypes = [c_void_p, c_char_p, c_void_p]
    lib.hdds_subscriber_create_reader_with_qos.restype = c_void_p

    if hasattr(lib, 'hdds_subscriber_create_reader_with_type'):
        lib.hdds_subscriber_create_reader_with_type.argtypes = [
            c_void_p, c_char_p, c_char_p, c_void_p]
        lib.hdds_subscriber_create_reader_with_type.restype = c_void_p

    # -------------------------------------------------------------------------
    # Participant (extended)
    # -------------------------------------------------------------------------
    lib.hdds_participant_create_with_transport.argtypes = [c_char_p, c_int32]
    lib.hdds_participant_create_with_transport.restype = c_void_p

    # Config builder API for advanced participant creation
    lib.hdds_config_create.argtypes = [c_char_p]
    lib.hdds_config_create.restype = c_void_p

    lib.hdds_config_destroy.argtypes = [c_void_p]
    lib.hdds_config_destroy.restype = None

    lib.hdds_config_set_domain_id.argtypes = [c_void_p, c_uint32]
    lib.hdds_config_set_domain_id.restype = c_int32

    lib.hdds_config_set_transport_mode.argtypes = [c_void_p, c_int32]
    lib.hdds_config_set_transport_mode.restype = c_int32

    lib.hdds_config_build.argtypes = [c_void_p]
    lib.hdds_config_build.restype = c_void_p

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
    # Conditions / content filtering (optional: exported only when
    # crates/hdds-c/src/condition_ffi.rs is compiled into the library).
    # Used by hdds/conditions.py; declared here so a pointer-returning
    # function never falls back to the default c_int restype.
    # -------------------------------------------------------------------------
    if hasattr(lib, 'hdds_create_reader_filtered'):
        lib.hdds_create_reader_filtered.argtypes = [c_void_p, c_void_p, c_void_p]
        lib.hdds_create_reader_filtered.restype = c_void_p

    if hasattr(lib, 'hdds_content_filtered_topic_set_params'):
        lib.hdds_content_filtered_topic_set_params.argtypes = [
            c_void_p, POINTER(c_char_p), c_size_t
        ]
        lib.hdds_content_filtered_topic_set_params.restype = None

    if hasattr(lib, 'hdds_content_filtered_topic_delete'):
        lib.hdds_content_filtered_topic_delete.argtypes = [c_void_p]
        lib.hdds_content_filtered_topic_delete.restype = None

    if hasattr(lib, 'hdds_create_read_condition'):
        lib.hdds_create_read_condition.argtypes = [c_void_p, c_uint32, c_uint32, c_uint32]
        lib.hdds_create_read_condition.restype = c_void_p

    if hasattr(lib, 'hdds_read_condition_get_trigger'):
        lib.hdds_read_condition_get_trigger.argtypes = [c_void_p]
        lib.hdds_read_condition_get_trigger.restype = c_bool

    if hasattr(lib, 'hdds_read_condition_delete'):
        lib.hdds_read_condition_delete.argtypes = [c_void_p]
        lib.hdds_read_condition_delete.restype = None

    if hasattr(lib, 'hdds_create_query_condition'):
        lib.hdds_create_query_condition.argtypes = [
            c_void_p, c_uint32, c_uint32, c_uint32, c_char_p, POINTER(c_char_p), c_size_t
        ]
        lib.hdds_create_query_condition.restype = c_void_p

    if hasattr(lib, 'hdds_query_condition_delete'):
        lib.hdds_query_condition_delete.argtypes = [c_void_p]
        lib.hdds_query_condition_delete.restype = None

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

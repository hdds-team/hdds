# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS Python SDK - High-performance DDS bindings for Python.

Provides Pythonic access to the HDDS DDS implementation via ctypes FFI
bindings to the native Rust library. All DDS entities (Participant, DataWriter,
DataReader, etc.) are available as Python classes with RAII-like lifecycle
management through context managers.

Main entry points:
    - ``Participant``: DDS domain participant (start here).
    - ``QoS``: Quality of Service configuration with fluent builder API.
    - ``WaitSet``: Blocking synchronization on data availability.
    - ``ReaderListener`` / ``WriterListener``: Callback-based event notification.

Submodules:
    - ``hdds.logging``: Logging configuration (init, init_env, init_filter).
    - ``hdds.telemetry``: Metrics collection and export.
    - ``hdds.listener``: Listener base classes and status types.

Example:
    >>> import hdds
    >>> hdds.logging.init(hdds.LogLevel.INFO)
    >>> with hdds.Participant("my_app") as p:
    ...     writer = p.create_writer("topic", qos=hdds.QoS.reliable())
    ...     writer.write(b"Hello DDS!")
"""

from .participant import Participant, TransportMode
from .qos import QoS
from .entities import DataWriter, DataReader, Publisher, Subscriber
from .waitset import WaitSet, GuardCondition
from ._native import HddsException, HddsError, LogLevel

# Submodules
from . import logging
from . import telemetry
from . import listener
from .listener import ReaderListener, WriterListener

__version__ = "0.8.0"


def version() -> str:
    """
    Get the HDDS native library version string.

    Returns:
        Version string (e.g., "1.0.5")
    """
    from ._native import get_lib
    lib = get_lib()
    raw = lib.hdds_version()
    if raw:
        return raw.decode('utf-8')
    return "unknown"


__all__ = [
    # Core classes
    "Participant",
    "TransportMode",
    "QoS",
    "DataWriter",
    "DataReader",
    "Publisher",
    "Subscriber",
    "WaitSet",
    "GuardCondition",
    # Functions
    "version",
    # Errors
    "HddsException",
    "HddsError",
    # Enums
    "LogLevel",
    # Listener
    "ReaderListener",
    "WriterListener",
    # Submodules
    "logging",
    "telemetry",
    "listener",
]

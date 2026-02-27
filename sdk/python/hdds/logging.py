# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS logging configuration module.

Provides functions to initialize the HDDS logging subsystem. Logging should
be initialized once at application startup, before creating any DDS entities.
Calling init functions more than once will raise an error.

Three initialization modes are available:

1. **Level-based** -- ``init(LogLevel.DEBUG)``
2. **Environment override** -- ``init_env()`` reads ``RUST_LOG`` env var.
3. **Filter string** -- ``init_filter("hdds::discovery=trace")``

Example::

    import hdds
    hdds.logging.init(hdds.LogLevel.DEBUG)

    # Or with environment variable fallback:
    hdds.logging.init_env(hdds.LogLevel.INFO)

    # Or with custom per-module filter:
    hdds.logging.init_filter("hdds=debug,hdds::transport=trace")

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

from __future__ import annotations
from ._native import get_lib, check_error, LogLevel

__all__ = ['init', 'init_env', 'init_filter', 'LogLevel']


def init(level: int = LogLevel.INFO) -> None:
    """
    Initialize HDDS logging with specified level.

    Args:
        level: Log level (LogLevel.OFF, ERROR, WARN, INFO, DEBUG, TRACE)

    Raises:
        HddsException: If logging was already initialized
    """
    lib = get_lib()
    err = lib.hdds_logging_init(level)
    check_error(err)


def init_env(default_level: int = LogLevel.INFO) -> None:
    """
    Initialize HDDS logging with environment variable override.

    Reads RUST_LOG environment variable if set, otherwise uses default_level.

    Args:
        default_level: Default log level if RUST_LOG is not set
    """
    lib = get_lib()
    err = lib.hdds_logging_init_env(default_level)
    check_error(err)


def init_filter(filter_str: str) -> None:
    """
    Initialize HDDS logging with custom filter string.

    Args:
        filter_str: Log filter (e.g., "hdds=debug", "hdds::discovery=trace")
    """
    lib = get_lib()
    err = lib.hdds_logging_init_with_filter(filter_str.encode('utf-8'))
    check_error(err)

# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS WaitSet and GuardCondition for synchronization.

Provides blocking synchronization primitives for event-driven DDS communication.
A WaitSet blocks the calling thread until one or more attached conditions become
active (e.g., data available on a reader, or a guard condition is triggered).

Typical usage pattern::

    waitset = hdds.WaitSet()
    waitset.attach_reader(reader)
    while True:
        if waitset.wait(timeout=1.0):
            data = reader.take()
            if data:
                process(data)

Both WaitSet and GuardCondition support the context manager protocol for
automatic cleanup.

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

from __future__ import annotations
from typing import Optional, List, TYPE_CHECKING
import ctypes

if TYPE_CHECKING:
    from .entities import DataReader


class GuardCondition:
    """Manually triggered condition for waking a WaitSet.

    A guard condition provides a way for application threads to wake
    a WaitSet without requiring DDS data. Useful for implementing
    shutdown signals, timer events, or custom notification patterns.

    Example:
        >>> cond = GuardCondition()
        >>> waitset.attach_guard(cond)
        >>> # From another thread:
        >>> cond.trigger()

    Raises:
        RuntimeError: If the native guard condition cannot be created.
    """

    def __init__(self):
        from ._native import get_lib

        lib = get_lib()
        self._handle = lib.hdds_guard_condition_create()
        if not self._handle:
            raise RuntimeError("Failed to create guard condition")

    def trigger(self) -> None:
        """Trigger the condition, waking any WaitSet this condition is attached to.

        Thread-safe: can be called from any thread.

        Raises:
            RuntimeError: If the guard condition has been destroyed.
            HddsException: If the trigger operation fails.
        """
        from ._native import get_lib, check_error

        if not self._handle:
            raise RuntimeError("Guard condition has been destroyed")

        lib = get_lib()
        check_error(lib.hdds_guard_condition_set_trigger(self._handle, True))

    def close(self) -> None:
        """Release the native guard condition resources. Safe to call multiple times."""
        from ._native import get_lib

        if self._handle:
            lib = get_lib()
            lib.hdds_guard_condition_release(self._handle)
            self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "GuardCondition()"


class WaitSet:
    """Synchronization primitive for blocking on DDS conditions.

    A WaitSet blocks the calling thread until one or more attached conditions
    become active. Conditions include DataReader status conditions (data
    available) and manually triggered GuardConditions.

    Supports the context manager protocol for automatic cleanup.

    Example:
        >>> with WaitSet() as waitset:
        ...     waitset.attach_reader(reader)
        ...     if waitset.wait(timeout=5.0):
        ...         data = reader.take()

    Raises:
        RuntimeError: If the native waitset cannot be created.
    """

    def __init__(self):
        from ._native import get_lib

        lib = get_lib()
        self._handle = lib.hdds_waitset_create()
        if not self._handle:
            raise RuntimeError("Failed to create waitset")

        self._attached_readers: List[DataReader] = []
        self._attached_guards: List[GuardCondition] = []

    def attach_reader(self, reader: DataReader) -> None:
        """
        Attach a reader's status condition to the waitset.

        The waitset will wake when data is available on the reader.

        Args:
            reader: DataReader to monitor
        """
        from ._native import get_lib, check_error

        if reader in self._attached_readers:
            return  # Already attached

        cond = reader.get_status_condition()
        lib = get_lib()
        check_error(lib.hdds_waitset_attach_status_condition(self._handle, cond))
        self._attached_readers.append(reader)

    def detach_reader(self, reader: DataReader) -> None:
        """
        Detach a reader from the waitset.

        Args:
            reader: DataReader to stop monitoring
        """
        from ._native import get_lib, check_error

        if reader not in self._attached_readers:
            return

        cond = reader.get_status_condition()
        lib = get_lib()
        check_error(lib.hdds_waitset_detach_condition(self._handle, cond))
        self._attached_readers.remove(reader)

    def attach_guard(self, guard: GuardCondition) -> None:
        """
        Attach a guard condition to the waitset.

        Args:
            guard: GuardCondition to monitor
        """
        from ._native import get_lib, check_error

        if guard in self._attached_guards:
            return

        lib = get_lib()
        check_error(lib.hdds_waitset_attach_guard_condition(self._handle, guard._handle))
        self._attached_guards.append(guard)

    def detach_guard(self, guard: GuardCondition) -> None:
        """
        Detach a guard condition from the waitset.

        Args:
            guard: GuardCondition to stop monitoring
        """
        from ._native import get_lib, check_error

        if guard not in self._attached_guards:
            return

        lib = get_lib()
        check_error(lib.hdds_waitset_detach_condition(self._handle, guard._handle))
        self._attached_guards.remove(guard)

    def wait(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for conditions to trigger.

        Args:
            timeout: Maximum wait time in seconds.
                     None = block indefinitely
                     0 = non-blocking poll

        Returns:
            True if conditions triggered, False on timeout

        Example:
            >>> if waitset.wait(timeout=5.0):
            ...     print("Conditions triggered!")
        """
        import ctypes
        from ._native import get_lib, HddsError

        if not self._handle:
            raise RuntimeError("WaitSet has been destroyed")

        if timeout is None:
            timeout_ns = -1
        else:
            timeout_ns = int(timeout * 1_000_000_000)

        lib = get_lib()

        # Allocate output array for triggered conditions
        max_conditions = 64
        out_conditions = (ctypes.c_void_p * max_conditions)()
        out_len = ctypes.c_size_t(0)

        err = lib.hdds_waitset_wait(
            self._handle,
            timeout_ns,
            out_conditions,
            max_conditions,
            ctypes.byref(out_len),
        )

        if err == HddsError.OK:
            return True
        elif err == HddsError.NOT_FOUND:
            return False  # Timeout
        else:
            from ._native import HddsException
            raise HddsException(err)

    def close(self) -> None:
        """Release waitset resources. Safe to call multiple times."""
        from ._native import get_lib

        if self._handle:
            lib = get_lib()
            lib.hdds_waitset_destroy(self._handle)
            self._handle = None
            self._attached_readers.clear()
            self._attached_guards.clear()

    def __enter__(self) -> WaitSet:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"WaitSet(readers={len(self._attached_readers)}, guards={len(self._attached_guards)})"

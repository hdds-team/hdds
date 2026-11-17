# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Listener API - Callback-based event notification.

Override methods in ReaderListener or WriterListener to receive events, then
install the listener on a reader or writer.

Example:
    >>> import hdds
    >>>
    >>> class MyListener(hdds.ReaderListener):
    ...     def on_data_available(self, data: bytes):
    ...         print(f"Received {len(data)} bytes")
    ...     def on_subscription_matched(self, status):
    ...         print(f"Matched: {status.current_count} writers")
    ...
    >>> reader.set_listener(MyListener())
    >>> ...
    >>> reader.clear_listener()

Threading and safety contract:

- Callbacks run on HDDS threads (the router / discovery threads, or the
  thread calling ``write()`` for a reader of the same participant), with the
  GIL acquired by ctypes for the duration of the callback. Callbacks can come
  from several threads: synchronize what they share.
- Only the methods a listener overrides are installed: a status whose method
  is not overridden is not reported (and SAMPLE_REJECTED then stays on the
  reader's status condition).
- An exception raised by a callback is logged on the ``hdds.listener``
  logger (``logging.exception``) and swallowed: it never propagates into the
  HDDS thread that called back.
- ``clear_listener()``, a replacing ``set_listener()`` and the destruction of
  the entity return only once no callback of the previous listener is
  running on another thread (the GIL is released while they wait). A
  callback may clear or replace its own listener, take from its reader, or
  write.
- ``set_listener()`` / ``clear_listener()`` may race on one entity from
  several threads: the listener that reached the library last stays
  installed and registered.
- Do not destroy a reader or writer (close its participant) from inside one
  of its own callbacks: the library refuses to free it under the code that
  called back, leaks it and logs an error.
- Status objects and data bytes are copies, safe to keep after the callback.
- ``on_liveliness_changed`` reports the matched writers alive and not
  alive. ``on_liveliness_lost`` reports this writer (MANUAL_BY_PARTICIPANT,
  MANUAL_BY_TOPIC only) failing to assert within its lease.
  ``on_sample_lost`` is never called yet: the core does not raise that
  status.
- Installed listeners are removed at interpreter exit (``atexit``), so no
  callback reaches a finalizing interpreter.

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

# Annotations stay strings so the package keeps parsing and importing on the
# oldest interpreter pyproject.toml claims (requires-python >= 3.9).
from __future__ import annotations

import atexit
import ctypes
import itertools
import logging
import threading
from ctypes import (
    c_void_p,
    c_uint8,
    c_uint32,
    c_int32,
    c_uint64,
    c_size_t,
    c_char_p,
    POINTER,
    Structure,
    CFUNCTYPE,
)
from typing import Any, Callable, Dict, Optional, Tuple

from ._native import get_lib, check_error

_log = logging.getLogger("hdds.listener")


# =============================================================================
# C status structures (must match hdds-c repr(C) layout)
# =============================================================================

class SubscriptionMatchedStatus(Structure):
    """Status for subscription matched events."""
    _fields_ = [
        ("total_count", c_uint32),
        ("total_count_change", c_int32),
        ("current_count", c_uint32),
        ("current_count_change", c_int32),
    ]

    def __repr__(self):
        return (
            f"SubscriptionMatchedStatus(total={self.total_count}, "
            f"current={self.current_count}, "
            f"change={self.current_count_change})"
        )


class PublicationMatchedStatus(Structure):
    """Status for publication matched events."""
    _fields_ = [
        ("total_count", c_uint32),
        ("total_count_change", c_int32),
        ("current_count", c_uint32),
        ("current_count_change", c_int32),
    ]

    def __repr__(self):
        return (
            f"PublicationMatchedStatus(total={self.total_count}, "
            f"current={self.current_count}, "
            f"change={self.current_count_change})"
        )


class LivelinessChangedStatus(Structure):
    """Status for liveliness changed events."""
    _fields_ = [
        ("alive_count", c_uint32),
        ("alive_count_change", c_int32),
        ("not_alive_count", c_uint32),
        ("not_alive_count_change", c_int32),
    ]

    def __repr__(self):
        return (
            f"LivelinessChangedStatus(alive={self.alive_count}, "
            f"not_alive={self.not_alive_count})"
        )


class LivelinessLostStatus(Structure):
    """Status for liveliness lost events (MANUAL_BY_* only)."""
    _fields_ = [
        ("total_count", c_uint32),
        ("total_count_change", c_int32),
    ]

    def __repr__(self):
        return f"LivelinessLostStatus(total={self.total_count}, change={self.total_count_change})"


class SampleLostStatus(Structure):
    """Status for sample lost events."""
    _fields_ = [
        ("total_count", c_uint32),
        ("total_count_change", c_int32),
    ]

    def __repr__(self):
        return f"SampleLostStatus(total={self.total_count}, change={self.total_count_change})"


class SampleRejectedStatus(Structure):
    """Status for sample rejected events.

    last_reason values:
        0 = NotRejected
        1 = ResourceLimit
        2 = InstanceLimit
        3 = SamplesPerInstanceLimit
    """
    _fields_ = [
        ("total_count", c_uint32),
        ("total_count_change", c_int32),
        ("last_reason", c_uint32),
    ]

    def __repr__(self):
        return (
            f"SampleRejectedStatus(total={self.total_count}, "
            f"reason={self.last_reason})"
        )


class DeadlineMissedStatus(Structure):
    """Status for deadline missed events."""
    _fields_ = [
        ("total_count", c_uint32),
        ("total_count_change", c_int32),
    ]

    def __repr__(self):
        return f"DeadlineMissedStatus(total={self.total_count}, change={self.total_count_change})"


class IncompatibleQosStatus(Structure):
    """Status for incompatible QoS events."""
    _fields_ = [
        ("total_count", c_uint32),
        ("total_count_change", c_int32),
        ("last_policy_id", c_uint32),
    ]

    def __repr__(self):
        return (
            f"IncompatibleQosStatus(total={self.total_count}, "
            f"policy_id={self.last_policy_id})"
        )


# =============================================================================
# C callback function types
# =============================================================================

ON_DATA_AVAILABLE = CFUNCTYPE(None, POINTER(c_uint8), c_size_t, c_void_p)
ON_SUBSCRIPTION_MATCHED = CFUNCTYPE(None, POINTER(SubscriptionMatchedStatus), c_void_p)
ON_PUBLICATION_MATCHED = CFUNCTYPE(None, POINTER(PublicationMatchedStatus), c_void_p)
ON_LIVELINESS_CHANGED = CFUNCTYPE(None, POINTER(LivelinessChangedStatus), c_void_p)
ON_SAMPLE_LOST = CFUNCTYPE(None, POINTER(SampleLostStatus), c_void_p)
ON_SAMPLE_REJECTED = CFUNCTYPE(None, POINTER(SampleRejectedStatus), c_void_p)
ON_DEADLINE_MISSED = CFUNCTYPE(None, POINTER(DeadlineMissedStatus), c_void_p)
ON_INCOMPATIBLE_QOS = CFUNCTYPE(None, POINTER(IncompatibleQosStatus), c_void_p)
ON_SAMPLE_WRITTEN = CFUNCTYPE(None, POINTER(c_uint8), c_size_t, c_uint64, c_void_p)
ON_OFFERED_DEADLINE_MISSED = CFUNCTYPE(None, c_uint64, c_void_p)
ON_OFFERED_INCOMPATIBLE_QOS = CFUNCTYPE(None, c_uint32, c_char_p, c_void_p)
ON_LIVELINESS_LOST = CFUNCTYPE(None, POINTER(LivelinessLostStatus), c_void_p)


# =============================================================================
# C listener structs (must match hdds-c repr(C) field order)
# =============================================================================

class _CReaderListener(Structure):
    """C-layout struct matching HddsReaderListener."""
    _fields_ = [
        ("on_data_available", ON_DATA_AVAILABLE),
        ("on_subscription_matched", ON_SUBSCRIPTION_MATCHED),
        ("on_liveliness_changed", ON_LIVELINESS_CHANGED),
        ("on_sample_lost", ON_SAMPLE_LOST),
        ("on_sample_rejected", ON_SAMPLE_REJECTED),
        ("on_deadline_missed", ON_DEADLINE_MISSED),
        ("on_incompatible_qos", ON_INCOMPATIBLE_QOS),
        ("user_data", c_void_p),
    ]


class _CWriterListener(Structure):
    """C-layout struct matching HddsWriterListener."""
    _fields_ = [
        ("on_sample_written", ON_SAMPLE_WRITTEN),
        ("on_publication_matched", ON_PUBLICATION_MATCHED),
        ("on_offered_deadline_missed", ON_OFFERED_DEADLINE_MISSED),
        ("on_offered_incompatible_qos", ON_OFFERED_INCOMPATIBLE_QOS),
        ("on_liveliness_lost", ON_LIVELINESS_LOST),
        ("user_data", c_void_p),
    ]


# =============================================================================
# ReaderListener
# =============================================================================

class ReaderListener:
    """Base class for DataReader listeners. Override methods you care about.

    Example:
        >>> class MyListener(ReaderListener):
        ...     def on_data_available(self, data: bytes):
        ...         print(f"Got {len(data)} bytes")
        ...
        ...     def on_subscription_matched(self, status):
        ...         print(f"Matched with {status.current_count} writers")
    """

    def on_data_available(self, data: bytes) -> None:
        """Called when new data is available.

        Args:
            data: The serialized sample data as bytes.
        """
        pass

    def on_subscription_matched(self, status: SubscriptionMatchedStatus) -> None:
        """Called when the reader matches/unmatches with a writer.

        Args:
            status: Current subscription matched status.
        """
        pass

    def on_liveliness_changed(self, status: LivelinessChangedStatus) -> None:
        """Called when liveliness of a matched writer changes.

        Args:
            status: Current liveliness status.
        """
        pass

    def on_sample_lost(self, status: SampleLostStatus) -> None:
        """Called when samples are lost (gap in sequence numbers).

        Args:
            status: Sample lost status.
        """
        pass

    def on_sample_rejected(self, status: SampleRejectedStatus) -> None:
        """Called when samples are rejected due to resource limits.

        Args:
            status: Sample rejected status with reason.
        """
        pass

    def on_deadline_missed(self, status: DeadlineMissedStatus) -> None:
        """Called when the requested deadline is missed.

        Args:
            status: Deadline missed status.
        """
        pass

    def on_incompatible_qos(self, status: IncompatibleQosStatus) -> None:
        """Called when QoS is incompatible with a matched writer.

        Args:
            status: Incompatible QoS status.
        """
        pass

# =============================================================================
# WriterListener
# =============================================================================

class WriterListener:
    """Base class for DataWriter listeners. Override methods you care about.

    Example:
        >>> class MyWriterListener(WriterListener):
        ...     def on_publication_matched(self, status):
        ...         print(f"Matched with {status.current_count} readers")
        ...
        ...     def on_liveliness_lost(self, status):
        ...         print(f"Liveliness lost! (total={status.total_count})")
    """

    def on_sample_written(self, data: bytes, sequence_number: int) -> None:
        """Called after a sample is successfully written.

        Args:
            data: The serialized sample data as bytes.
            sequence_number: The assigned RTPS sequence number.
        """
        pass

    def on_publication_matched(self, status: PublicationMatchedStatus) -> None:
        """Called when the writer matches/unmatches with a reader.

        Args:
            status: Current publication matched status.
        """
        pass

    def on_offered_deadline_missed(self, instance_handle: int) -> None:
        """Called when an offered deadline is missed.

        Args:
            instance_handle: Handle of the instance that missed the deadline (0 if none).
        """
        pass

    def on_offered_incompatible_qos(self, policy_id: int, policy_name: str) -> None:
        """Called when QoS is incompatible with a matched reader.

        Args:
            policy_id: QosPolicyId_t of the incompatible QoS policy
                (DDS v1.4 Sec.2.3.3, e.g. DURABILITY 2, DEADLINE 4,
                LIVELINESS 8, RELIABILITY 11).
            policy_name: Name of the policy (e.g., "RELIABILITY").
        """
        pass

    def on_liveliness_lost(self, status: LivelinessLostStatus) -> None:
        """Called when liveliness is lost (MANUAL_BY_* only): this writer
        did not assert (write, dispose, unregister or assert_liveliness)
        within its offered LIVELINESS lease.

        Args:
            status: Liveliness lost status.
        """
        pass


# =============================================================================
# Dispatch: one set of C thunks for the whole process
# =============================================================================
#
# The C callbacks are module-level CFUNCTYPE objects, created once and never
# freed, so no C pointer HDDS holds can outlive its thunk (freeing a ctypes
# thunk while HDDS may still call it, or while it is still executing because
# a callback cleared its own listener, would crash the process). The C
# ``user_data`` is a small integer key into ``_INSTALLED``; the thunk looks
# the Python listener up at call time and does nothing for a key that is no
# longer installed.

_INSTALLED: Dict[int, Tuple[str, int, Any, bool]] = {}
"""key -> (kind, native handle, Python listener, installed by an entity);
kind is "reader" or "writer"."""

_INSTALLED_LOCK = threading.Lock()
_KEYS = itertools.count(1)


def _listener_for(user_data) -> Any:
    if not user_data:
        return None
    entry = _INSTALLED.get(int(user_data))
    return entry[2] if entry is not None else None


def _call(name: str, user_data, invoke: Callable[[Any], None]) -> None:
    """Run ``invoke(listener)``; log and swallow anything it raises."""
    listener = _listener_for(user_data)
    if listener is None:
        return
    try:
        invoke(listener)
    except BaseException:  # noqa: BLE001 - nothing may unwind into HDDS
        _log.exception("exception in listener callback %s (swallowed)", name)


def _bytes(data_ptr, length: int) -> bytes:
    return ctypes.string_at(data_ptr, length) if (data_ptr and length) else b""


def _copy(status_ptr, cls):
    # A copy: the C status lives only for the duration of the callback.
    return cls.from_buffer_copy(status_ptr.contents)


@ON_DATA_AVAILABLE
def _c_on_data_available(data_ptr, length, user_data):
    _call("on_data_available", user_data,
          lambda l: l.on_data_available(_bytes(data_ptr, length)))


@ON_SUBSCRIPTION_MATCHED
def _c_on_subscription_matched(status_ptr, user_data):
    _call("on_subscription_matched", user_data,
          lambda l: l.on_subscription_matched(_copy(status_ptr, SubscriptionMatchedStatus)))


@ON_LIVELINESS_CHANGED
def _c_on_liveliness_changed(status_ptr, user_data):
    _call("on_liveliness_changed", user_data,
          lambda l: l.on_liveliness_changed(_copy(status_ptr, LivelinessChangedStatus)))


@ON_SAMPLE_LOST
def _c_on_sample_lost(status_ptr, user_data):
    _call("on_sample_lost", user_data,
          lambda l: l.on_sample_lost(_copy(status_ptr, SampleLostStatus)))


@ON_SAMPLE_REJECTED
def _c_on_sample_rejected(status_ptr, user_data):
    _call("on_sample_rejected", user_data,
          lambda l: l.on_sample_rejected(_copy(status_ptr, SampleRejectedStatus)))


@ON_DEADLINE_MISSED
def _c_on_deadline_missed(status_ptr, user_data):
    _call("on_deadline_missed", user_data,
          lambda l: l.on_deadline_missed(_copy(status_ptr, DeadlineMissedStatus)))


@ON_INCOMPATIBLE_QOS
def _c_on_incompatible_qos(status_ptr, user_data):
    _call("on_incompatible_qos", user_data,
          lambda l: l.on_incompatible_qos(_copy(status_ptr, IncompatibleQosStatus)))


@ON_SAMPLE_WRITTEN
def _c_on_sample_written(data_ptr, length, seq, user_data):
    _call("on_sample_written", user_data,
          lambda l: l.on_sample_written(_bytes(data_ptr, length), int(seq)))


@ON_PUBLICATION_MATCHED
def _c_on_publication_matched(status_ptr, user_data):
    _call("on_publication_matched", user_data,
          lambda l: l.on_publication_matched(_copy(status_ptr, PublicationMatchedStatus)))


@ON_OFFERED_DEADLINE_MISSED
def _c_on_offered_deadline_missed(instance_handle, user_data):
    _call("on_offered_deadline_missed", user_data,
          lambda l: l.on_offered_deadline_missed(int(instance_handle)))


@ON_OFFERED_INCOMPATIBLE_QOS
def _c_on_offered_incompatible_qos(policy_id, policy_name, user_data):
    name = policy_name.decode("utf-8", errors="replace") if policy_name else ""
    _call("on_offered_incompatible_qos", user_data,
          lambda l: l.on_offered_incompatible_qos(int(policy_id), name))


@ON_LIVELINESS_LOST
def _c_on_liveliness_lost(status_ptr, user_data):
    _call("on_liveliness_lost", user_data,
          lambda l: l.on_liveliness_lost(_copy(status_ptr, LivelinessLostStatus)))


_READER_THUNKS = {
    "on_data_available": _c_on_data_available,
    "on_subscription_matched": _c_on_subscription_matched,
    "on_liveliness_changed": _c_on_liveliness_changed,
    "on_sample_lost": _c_on_sample_lost,
    "on_sample_rejected": _c_on_sample_rejected,
    "on_deadline_missed": _c_on_deadline_missed,
    "on_incompatible_qos": _c_on_incompatible_qos,
}

_WRITER_THUNKS = {
    "on_sample_written": _c_on_sample_written,
    "on_publication_matched": _c_on_publication_matched,
    "on_offered_deadline_missed": _c_on_offered_deadline_missed,
    "on_offered_incompatible_qos": _c_on_offered_incompatible_qos,
    "on_liveliness_lost": _c_on_liveliness_lost,
}


def _overrides(listener: Any, base: type, name: str) -> bool:
    """Whether ``listener`` provides its own ``name`` (not the base no-op)."""
    impl = getattr(type(listener), name, None)
    if impl is None:
        # Not a subclass: any callable attribute counts.
        return callable(getattr(listener, name, None))
    return impl is not getattr(base, name)


def _c_struct(listener: Any, key: int, base: type, thunks: dict, struct_cls):
    c_listener = struct_cls()
    for name, thunk in thunks.items():
        if _overrides(listener, base, name):
            setattr(c_listener, name, thunk)
    c_listener.user_data = key
    return c_listener


# =============================================================================
# FFI function setup (called lazily when listeners are used)
# =============================================================================

def _setup_listener_signatures(lib: ctypes.CDLL) -> None:
    """Set up function signatures for listener FFI functions."""
    if hasattr(lib, "hdds_reader_set_listener"):
        lib.hdds_reader_set_listener.argtypes = [c_void_p, POINTER(_CReaderListener)]
        lib.hdds_reader_set_listener.restype = c_int32

    if hasattr(lib, "hdds_reader_clear_listener"):
        lib.hdds_reader_clear_listener.argtypes = [c_void_p]
        lib.hdds_reader_clear_listener.restype = c_int32

    if hasattr(lib, "hdds_writer_set_listener"):
        lib.hdds_writer_set_listener.argtypes = [c_void_p, POINTER(_CWriterListener)]
        lib.hdds_writer_set_listener.restype = c_int32

    if hasattr(lib, "hdds_writer_clear_listener"):
        lib.hdds_writer_clear_listener.argtypes = [c_void_p]
        lib.hdds_writer_clear_listener.restype = c_int32

    if hasattr(lib, "hdds_reader_exchange_listener"):
        lib.hdds_reader_exchange_listener.argtypes = [
            c_void_p, POINTER(_CReaderListener), POINTER(c_void_p)]
        lib.hdds_reader_exchange_listener.restype = c_int32

    if hasattr(lib, "hdds_writer_exchange_listener"):
        lib.hdds_writer_exchange_listener.argtypes = [
            c_void_p, POINTER(_CWriterListener), POINTER(c_void_p)]
        lib.hdds_writer_exchange_listener.restype = c_int32


def _exchange(kind: str, handle, c_listener) -> Optional[int]:
    """Install ``c_listener`` (None: remove) natively; return the key of the
    listener it replaced, None if there was none.

    The native call reports which listener it replaced and drained, so the
    key forgotten is the right one whatever the order in which concurrent
    installs on one entity reached the library. ctypes releases the GIL for
    the call, so the replaced listener's callbacks running on other threads
    can finish while it waits for them.
    """
    lib = get_lib()
    _setup_listener_signatures(lib)
    if not hasattr(lib, f"hdds_{kind}_exchange_listener"):
        # A library older than the exchange functions (whose set_listener
        # returned HDDS_UNSUPPORTED): set/clear, and let its error surface.
        if c_listener is None:
            ret = getattr(lib, f"hdds_{kind}_clear_listener")(handle)
        else:
            ret = getattr(lib, f"hdds_{kind}_set_listener")(handle, ctypes.byref(c_listener))
        check_error(ret)
        return None
    previous = c_void_p()
    if kind == "reader":
        ret = lib.hdds_reader_exchange_listener(
            handle, ctypes.byref(c_listener) if c_listener is not None else None,
            ctypes.byref(previous))
    else:
        ret = lib.hdds_writer_exchange_listener(
            handle, ctypes.byref(c_listener) if c_listener is not None else None,
            ctypes.byref(previous))
    check_error(ret)
    return previous.value or None


def _install(kind: str, handle, listener: Any, from_entity: bool = False) -> int:
    """Install ``listener`` on a native reader/writer; return its key.

    Forgets the key of the listener it replaced.
    """
    key = next(_KEYS)
    native = int(handle.value if isinstance(handle, c_void_p) else handle)
    # Registered before the native call: a callback may fire before it
    # returns.
    with _INSTALLED_LOCK:
        _INSTALLED[key] = (kind, native, listener, from_entity)
    if kind == "reader":
        c_listener = _c_struct(listener, key, ReaderListener, _READER_THUNKS, _CReaderListener)
    else:
        c_listener = _c_struct(listener, key, WriterListener, _WRITER_THUNKS, _CWriterListener)
    try:
        previous = _exchange(kind, handle, c_listener)
    except BaseException:
        _forget(key)
        raise
    _forget(previous)
    return key


def _clear(kind: str, handle) -> None:
    """Remove the native listener and forget its key; returns once its
    callbacks running on other threads are over."""
    _forget(_exchange(kind, handle, None))


def _keys_of(native_handle) -> list:
    """The keys installed on a native handle, taken BEFORE destroying it:
    once destroyed, its address can be reused by a new entity whose keys must
    not be forgotten."""
    native = int(native_handle.value if isinstance(native_handle, c_void_p) else native_handle)
    with _INSTALLED_LOCK:
        return [k for k, v in _INSTALLED.items() if v[1] == native]


def _forget_keys(keys) -> None:
    """Forget keys whose native entity was destroyed (destruction waited for
    every callback of them)."""
    with _INSTALLED_LOCK:
        for key in keys:
            _INSTALLED.pop(key, None)


def _forget(key: Optional[int]) -> None:
    """Drop a key whose native listener was replaced, cleared or destroyed."""
    if key is None:
        return
    with _INSTALLED_LOCK:
        _INSTALLED.pop(key, None)


@atexit.register
def _clear_all_at_exit() -> None:
    """Remove every listener an entity installed before the interpreter
    finalizes. (An entity forgets its key when it is destroyed, so every
    handle seen here is live; listeners installed through the handle-level
    functions are the caller's to clear.)"""
    with _INSTALLED_LOCK:
        entries = [(k, v) for k, v in _INSTALLED.items() if v[3]]
    if not entries:
        return
    try:
        lib = get_lib()
        _setup_listener_signatures(lib)
    except Exception:  # noqa: BLE001 - best effort at exit
        return
    for key, (kind, native, _listener, _owned) in entries:
        try:
            if kind == "reader":
                lib.hdds_reader_clear_listener(c_void_p(native))
            else:
                lib.hdds_writer_clear_listener(c_void_p(native))
        except Exception:  # noqa: BLE001 - best effort at exit
            pass
        _forget(key)


# =============================================================================
# Handle-level API (kept for callers holding raw handles)
# =============================================================================

def set_reader_listener(reader_handle: c_void_p, listener: ReaderListener) -> int:
    """Install a Python ReaderListener on a native reader handle.

    Prefer ``DataReader.set_listener``, which also removes the listener when
    the reader is destroyed. Returns the installation key (pass it to
    ``clear_reader_listener`` to release the Python reference). Clear it
    before destroying the reader through this handle.

    Raises:
        HddsException: If the FFI call fails.
    """
    return _install("reader", reader_handle, listener)


def clear_reader_listener(reader_handle: c_void_p, key: Optional[int] = None) -> None:
    """Remove the listener from a native reader handle.

    Returns once no callback of it runs on another thread. ``key`` is
    accepted for compatibility; the key forgotten is the one the native call
    reports as replaced.

    Raises:
        HddsException: If the FFI call fails.
    """
    del key
    _clear("reader", reader_handle)


def set_writer_listener(writer_handle: c_void_p, listener: WriterListener) -> int:
    """Install a Python WriterListener on a native writer handle.

    Prefer ``DataWriter.set_listener``. Returns the installation key.

    Raises:
        HddsException: If the FFI call fails.
    """
    return _install("writer", writer_handle, listener)


def clear_writer_listener(writer_handle: c_void_p, key: Optional[int] = None) -> None:
    """Remove the listener from a native writer handle.

    Raises:
        HddsException: If the FFI call fails.
    """
    del key
    _clear("writer", writer_handle)

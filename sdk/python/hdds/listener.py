# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
HDDS Listener API - Callback-based event notification.

Provides Python wrappers for DDS listener callbacks.
Override methods in ReaderListener or WriterListener to receive events.

Example:
    >>> import hdds
    >>>
    >>> class MyListener(hdds.ReaderListener):
    ...     def on_data_available(self, data: bytes):
    ...         print(f"Received {len(data)} bytes")
    ...     def on_subscription_matched(self, status):
    ...         print(f"Matched: {status.current_count} writers")
    ...
    >>> listener = MyListener()
    >>> # reader.set_listener(listener)  # once core API supports it

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

import ctypes
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
from typing import Optional

from ._native import get_lib, check_error


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
ON_LIVELINESS_LOST = CFUNCTYPE(None, c_void_p)


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

    def _to_c_listener(self) -> _CReaderListener:
        """Convert this Python listener to a C struct with CFUNCTYPE callbacks.

        IMPORTANT: The returned struct holds references to CFUNCTYPE wrappers.
        These references are stored on self._c_callbacks to prevent garbage
        collection while the listener is active.

        Returns:
            A _CReaderListener struct ready to pass to the C FFI.
        """
        listener_ref = self

        # Create callback wrappers that route to Python methods.
        # We must keep references to prevent GC from collecting them.

        def _on_data_available(data_ptr, length, _user_data):
            if data_ptr and length > 0:
                buf = ctypes.string_at(data_ptr, length)
                listener_ref.on_data_available(buf)

        def _on_subscription_matched(status_ptr, _user_data):
            if status_ptr:
                listener_ref.on_subscription_matched(status_ptr.contents)

        def _on_liveliness_changed(status_ptr, _user_data):
            if status_ptr:
                listener_ref.on_liveliness_changed(status_ptr.contents)

        def _on_sample_lost(status_ptr, _user_data):
            if status_ptr:
                listener_ref.on_sample_lost(status_ptr.contents)

        def _on_sample_rejected(status_ptr, _user_data):
            if status_ptr:
                listener_ref.on_sample_rejected(status_ptr.contents)

        def _on_deadline_missed(status_ptr, _user_data):
            if status_ptr:
                listener_ref.on_deadline_missed(status_ptr.contents)

        def _on_incompatible_qos(status_ptr, _user_data):
            if status_ptr:
                listener_ref.on_incompatible_qos(status_ptr.contents)

        # Wrap in CFUNCTYPE (prevents GC via self._c_callbacks)
        cb_data = ON_DATA_AVAILABLE(_on_data_available)
        cb_sub_matched = ON_SUBSCRIPTION_MATCHED(_on_subscription_matched)
        cb_liveliness = ON_LIVELINESS_CHANGED(_on_liveliness_changed)
        cb_lost = ON_SAMPLE_LOST(_on_sample_lost)
        cb_rejected = ON_SAMPLE_REJECTED(_on_sample_rejected)
        cb_deadline = ON_DEADLINE_MISSED(_on_deadline_missed)
        cb_incompat = ON_INCOMPATIBLE_QOS(_on_incompatible_qos)

        # Store references to prevent garbage collection
        self._c_callbacks = [
            cb_data, cb_sub_matched, cb_liveliness,
            cb_lost, cb_rejected, cb_deadline, cb_incompat,
        ]

        c_listener = _CReaderListener()
        c_listener.on_data_available = cb_data
        c_listener.on_subscription_matched = cb_sub_matched
        c_listener.on_liveliness_changed = cb_liveliness
        c_listener.on_sample_lost = cb_lost
        c_listener.on_sample_rejected = cb_rejected
        c_listener.on_deadline_missed = cb_deadline
        c_listener.on_incompatible_qos = cb_incompat
        c_listener.user_data = None

        return c_listener


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
        ...     def on_liveliness_lost(self):
        ...         print("Liveliness lost!")
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
            policy_id: ID of the incompatible QoS policy.
            policy_name: Name of the policy (e.g., "RELIABILITY").
        """
        pass

    def on_liveliness_lost(self) -> None:
        """Called when liveliness is lost (MANUAL_BY_* only)."""
        pass

    def _to_c_listener(self) -> _CWriterListener:
        """Convert this Python listener to a C struct with CFUNCTYPE callbacks.

        IMPORTANT: The returned struct holds references to CFUNCTYPE wrappers.
        These references are stored on self._c_callbacks to prevent garbage
        collection while the listener is active.

        Returns:
            A _CWriterListener struct ready to pass to the C FFI.
        """
        listener_ref = self

        def _on_sample_written(data_ptr, length, seq_num, _user_data):
            if data_ptr and length > 0:
                buf = ctypes.string_at(data_ptr, length)
                listener_ref.on_sample_written(buf, seq_num)

        def _on_publication_matched(status_ptr, _user_data):
            if status_ptr:
                listener_ref.on_publication_matched(status_ptr.contents)

        def _on_offered_deadline_missed(instance_handle, _user_data):
            listener_ref.on_offered_deadline_missed(instance_handle)

        def _on_offered_incompatible_qos(policy_id, policy_name_ptr, _user_data):
            name = ""
            if policy_name_ptr:
                name = policy_name_ptr.decode("utf-8", errors="replace")
            listener_ref.on_offered_incompatible_qos(policy_id, name)

        def _on_liveliness_lost(_user_data):
            listener_ref.on_liveliness_lost()

        # Wrap in CFUNCTYPE
        cb_written = ON_SAMPLE_WRITTEN(_on_sample_written)
        cb_pub_matched = ON_PUBLICATION_MATCHED(_on_publication_matched)
        cb_offered_deadline = ON_OFFERED_DEADLINE_MISSED(_on_offered_deadline_missed)
        cb_offered_incompat = ON_OFFERED_INCOMPATIBLE_QOS(_on_offered_incompatible_qos)
        cb_liveliness_lost = ON_LIVELINESS_LOST(_on_liveliness_lost)

        # Store references to prevent garbage collection
        self._c_callbacks = [
            cb_written, cb_pub_matched, cb_offered_deadline,
            cb_offered_incompat, cb_liveliness_lost,
        ]

        c_listener = _CWriterListener()
        c_listener.on_sample_written = cb_written
        c_listener.on_publication_matched = cb_pub_matched
        c_listener.on_offered_deadline_missed = cb_offered_deadline
        c_listener.on_offered_incompatible_qos = cb_offered_incompat
        c_listener.on_liveliness_lost = cb_liveliness_lost
        c_listener.user_data = None

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


def set_reader_listener(reader_handle: c_void_p, listener: ReaderListener) -> None:
    """Install a Python ReaderListener on a reader via the C FFI.

    Args:
        reader_handle: Opaque reader handle (c_void_p).
        listener: A ReaderListener subclass instance.

    Raises:
        HddsException: If the FFI call fails.
    """
    lib = get_lib()
    _setup_listener_signatures(lib)
    c_listener = listener._to_c_listener()
    ret = lib.hdds_reader_set_listener(reader_handle, ctypes.byref(c_listener))
    # Store c_listener on the Python listener to keep it alive
    listener._active_c_listener = c_listener
    check_error(ret)


def clear_reader_listener(reader_handle: c_void_p) -> None:
    """Remove the listener from a reader.

    Args:
        reader_handle: Opaque reader handle (c_void_p).

    Raises:
        HddsException: If the FFI call fails.
    """
    lib = get_lib()
    _setup_listener_signatures(lib)
    ret = lib.hdds_reader_clear_listener(reader_handle)
    check_error(ret)


def set_writer_listener(writer_handle: c_void_p, listener: WriterListener) -> None:
    """Install a Python WriterListener on a writer via the C FFI.

    Args:
        writer_handle: Opaque writer handle (c_void_p).
        listener: A WriterListener subclass instance.

    Raises:
        HddsException: If the FFI call fails.
    """
    lib = get_lib()
    _setup_listener_signatures(lib)
    c_listener = listener._to_c_listener()
    ret = lib.hdds_writer_set_listener(writer_handle, ctypes.byref(c_listener))
    # Store c_listener on the Python listener to keep it alive
    listener._active_c_listener = c_listener
    check_error(ret)


def clear_writer_listener(writer_handle: c_void_p) -> None:
    """Remove the listener from a writer.

    Args:
        writer_handle: Opaque writer handle (c_void_p).

    Raises:
        HddsException: If the FFI call fails.
    """
    lib = get_lib()
    _setup_listener_signatures(lib)
    ret = lib.hdds_writer_clear_listener(writer_handle)
    check_error(ret)

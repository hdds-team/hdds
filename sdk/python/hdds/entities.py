# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS DDS entity classes: DataWriter, DataReader, Publisher, and Subscriber.

These classes are not instantiated directly. They are created by the
Participant (or Publisher/Subscriber) factory methods:
    - ``Participant.create_writer()`` / ``Publisher.create_writer()``
    - ``Participant.create_reader()`` / ``Subscriber.create_reader()``
    - ``Participant.create_publisher()``
    - ``Participant.create_subscriber()``

All entities hold opaque FFI handles to their native counterparts and are
destroyed automatically when the parent Participant is closed.

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

from __future__ import annotations
from typing import Optional, Any, Iterator, TYPE_CHECKING
import contextlib
import ctypes
import warnings

from .qos import QoS

if TYPE_CHECKING:
    from .listener import (
        SubscriptionMatchedStatus, PublicationMatchedStatus, DeadlineMissedStatus,
        IncompatibleQosStatus, LivelinessChangedStatus, LivelinessLostStatus,
        SampleLostStatus, SampleRejectedStatus,
    )


def _require(symbol: str, api: str) -> Any:
    """The loaded native library, or NotImplementedError if it lacks ``symbol``.

    For C functions newer than the oldest libhdds_c the binding can load.
    """
    from ._native import get_lib

    lib = get_lib()
    if not hasattr(lib, symbol):
        raise NotImplementedError(
            f"{api} needs {symbol} from libhdds_c 1.5.0 or later; "
            "the loaded library does not export it"
        )
    return lib


def _creation_error(kind: str, topic_name: str, qos: Optional[QoS]) -> RuntimeError:
    """Build the error raised when the native library refuses a writer/reader.

    The C constructors return NULL without a reason. The most common cause is
    a QoS that breaks a DDS consistency rule, which ``QoS.consistency_problems``
    can name, so the message says which rule; otherwise it points at the
    native log, where the library writes the reason at WARN level.
    """
    message = f"Failed to create {kind} for topic '{topic_name}'"
    problems = qos.consistency_problems() if qos is not None else []
    if problems:
        message += ": inconsistent QoS: " + "; ".join(problems)
    else:
        message += (
            " (enable hdds.logging.init(hdds.LogLevel.WARN) to see the reason"
            " reported by the native library)"
        )
    return RuntimeError(message)


class _SerializedKey(ctypes.Structure):
    _fields_ = [("hash", ctypes.c_uint8 * 16),
                ("protected_hash", ctypes.c_uint8 * 16),
                ("payload", ctypes.c_void_p), ("payload_len", ctypes.c_size_t),
                ("representation", ctypes.c_uint16)]


def _has_key_codec(msg_type):
    """Older generated types keep the legacy ABI until regenerated."""
    return (msg_type is not None and getattr(msg_type, "has_key", lambda: False)()
            and hasattr(msg_type, "HDDS_KEY_SUPPORTED")
            and all(callable(getattr(msg_type, method, None)) for method in
                    ("encode_key_cdr2_le", "compute_key")))


class DataWriter:
    """DDS DataWriter for publishing data to a topic.

    DataWriters are created via ``Participant.create_writer()`` or
    ``Publisher.create_writer()``. They serialize and send data samples
    to matched DataReaders on the same topic.

    Example:
        >>> writer = participant.create_writer("topic", qos=QoS.reliable())
        >>> writer.write(b"raw CDR bytes")
    """

    def __init__(self):
        """Private constructor. Use Participant.create_writer()."""
        raise RuntimeError("Use Participant.create_writer() to create DataWriter")

    @classmethod
    def _from_handle(
        cls,
        topic_name: str,
        handle: ctypes.c_void_p,
        qos: QoS,
        extensibility_known: bool = False,
        keyed_type: Optional[type] = None,
    ) -> DataWriter:
        """Internal: create from FFI handle.

        ``extensibility_known`` is True when ``create_writer`` resolved a
        real extensibility (an explicit ``extensibility=`` or a ``msg_type``
        carrying ``HDDS_EXTENSIBILITY``), so every sample is labelled right.
        False means the writer labels every sample FINAL regardless of what
        is actually written -- ``write_typed`` warns once if that body turns
        out not to be FINAL.
        """
        writer = cls.__new__(cls)
        writer._topic_name = topic_name
        writer._handle = handle
        writer._qos = qos
        writer._extensibility_known = extensibility_known
        writer._ext_warned = False
        writer._keyed_type = keyed_type
        writer._status_condition = None
        return writer

    @property
    def topic_name(self) -> str:
        """Get the topic name this writer publishes to.

        Returns:
            Topic name string.
        """
        return self._topic_name

    @property
    def qos(self) -> QoS:
        """Get the QoS configuration for this writer.

        Returns:
            QoS profile used by this writer.
        """
        return self._qos

    def write(self, data: bytes) -> None:
        """Write a data sample to the topic.

        The data must be raw bytes (typically CDR-serialized). For typed
        publishing, use ``write_typed()`` instead.

        Args:
            data: Raw bytes to publish.

        Raises:
            RuntimeError: If the writer has been destroyed or the write fails.
            TypeError: If data is not bytes.
            HddsException: If the native write operation fails.
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data).__name__}")
        self._write_raw(data)

    def write_typed(self, msg: Any) -> None:
        """Write a typed message, automatically CDR2-encoding it.

        The message must have an ``encode_cdr2_le()`` method (as generated
        by hdds_gen). This is the recommended API for typed publishing.

        Args:
            msg: A typed message object with ``encode_cdr2_le() -> bytes``.

        Raises:
            RuntimeError: If the writer has been destroyed.
            AttributeError: If msg has no ``encode_cdr2_le`` method.
            HddsException: If the native write operation fails.

        Example:
            >>> from generated.HelloWorld import HelloWorld
            >>> writer = participant.create_writer("HelloWorldTopic", HelloWorld)
            >>> writer.write_typed(HelloWorld(id=1, message="hi"))
        """
        if self._keyed_type is not None:
            self._instance_operation("write", msg)
        else:
            self._write_raw(self._encode_typed(msg))

    def _encode_typed(self, msg: Any) -> bytes:
        """Encode and warn when the writer cannot label this type correctly."""
        if not self._extensibility_known and not self._ext_warned:
            ext = getattr(type(msg), "HDDS_EXTENSIBILITY", None)
            if ext is not None and ext != "final":
                warnings.warn(
                    f"writer for topic {self._topic_name!r} was created without "
                    f"msg_type or extensibility, so every sample is labelled FINAL "
                    f"(CDR2_LE); {type(msg).__name__} is {ext.upper()} "
                    f"(DDS-XTypes 1.3 Table 60 wants D_CDR2_LE/PL_CDR2_LE). Pass "
                    f"create_writer({self._topic_name!r}, {type(msg).__name__}) "
                    "so the writer labels its samples correctly.",
                    stacklevel=2,
                )
                self._ext_warned = True
        return msg.encode_cdr2_le()

    def matched_reader_count(self) -> int:
        """Number of remote DataReaders currently matched with this writer.

        A remote reader is matched once discovery has found it and its QoS is
        compatible. Zero after a few seconds usually means discovery is not
        happening at all (see the network troubleshooting guide).

        Raises:
            RuntimeError: If the writer has been destroyed.
            NotImplementedError: If the loaded libhdds_c predates 1.5.0.
            HddsException: If the native call fails.
        """
        from ._native import check_error

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")
        lib = _require(
            "hdds_writer_matched_reader_count", "DataWriter.matched_reader_count()")
        count = ctypes.c_uint32(0)
        check_error(lib.hdds_writer_matched_reader_count(self._handle, ctypes.byref(count)))
        return count.value

    def wait_for_readers(self, min_count: int = 1, timeout: float = 10.0) -> bool:
        """Block until at least ``min_count`` remote readers are matched.

        Args:
            min_count: Number of matched readers to wait for.
            timeout: Maximum time to wait, in seconds (0 checks once).

        Returns:
            True if the count was reached, False on timeout.

        Raises:
            RuntimeError: If the writer has been destroyed.
            ValueError: If ``min_count`` or ``timeout`` is negative.
            NotImplementedError: If the loaded libhdds_c predates 1.5.0.
            HddsException: If the native call fails for another reason.

        Example:
            >>> if not writer.wait_for_readers(1, timeout=5.0):
            ...     print("no subscriber found: is multicast reachable?")
        """
        from ._native import check_error, HddsError

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")
        if min_count < 0 or timeout < 0:
            raise ValueError("min_count and timeout must be >= 0")
        lib = _require(
            "hdds_writer_wait_for_matched_readers", "DataWriter.wait_for_readers()")
        err = lib.hdds_writer_wait_for_matched_readers(
            self._handle, min_count, int(timeout * 1000))
        if err == HddsError.TIMEOUT:
            return False
        check_error(err)
        return True

    def wait_for_acknowledgments(self, timeout: float = 10.0) -> bool:
        """Block until every sample written has been acknowledged by every
        matched RELIABLE reader (DDS v1.4 Sec.2.2.2.4.2.15).

        A writer whose RELIABILITY QoS is BEST_EFFORT returns True at once,
        per the same spec section.

        Args:
            timeout: Maximum time to wait, in seconds.

        Returns:
            True once acknowledged, False on timeout.

        Raises:
            RuntimeError: If the writer has been destroyed.
            ValueError: If ``timeout`` is negative.
            NotImplementedError: If the loaded libhdds_c predates 1.5.0.
            HddsException: If the native call fails for another reason.

        Example:
            >>> writer.write(sample)
            >>> if not writer.wait_for_acknowledgments(timeout=2.0):
            ...     print("a reliable reader has not caught up yet")
        """
        from ._native import check_error, HddsError

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        lib = _require(
            "hdds_writer_wait_for_acknowledgments", "DataWriter.wait_for_acknowledgments()")
        err = lib.hdds_writer_wait_for_acknowledgments(self._handle, int(timeout * 1000))
        if err == HddsError.TIMEOUT:
            return False
        check_error(err)
        return True

    def assert_liveliness(self) -> None:
        """Manually assert this writer's liveliness (DDS v1.4 Sec.2.2.3.11).

        Renews its LIVELINESS lease without writing a sample. A no-op for
        AUTOMATIC liveliness or an infinite lease.

        Raises:
            RuntimeError: If the writer has been destroyed.
            NotImplementedError: If the loaded libhdds_c predates 1.5.0.
            HddsException: If the native call fails.
        """
        from ._native import check_error

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")
        lib = _require("hdds_writer_assert_liveliness", "DataWriter.assert_liveliness()")
        check_error(lib.hdds_writer_assert_liveliness(self._handle))

    def _write_raw(self, data: bytes) -> None:
        """Write raw bytes."""
        from ._native import get_lib, check_error

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")

        if self._keyed_type is not None:
            self._instance_operation("write", data)
            return
        lib = get_lib()
        data_ptr = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        err = lib.hdds_writer_write(self._handle, data_ptr, len(data))
        check_error(err)

    def get_publication_matched_status(self) -> PublicationMatchedStatus:
        """Read publication matched and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import PublicationMatchedStatus

        if not self._handle:
            raise RuntimeError("DataWriter has been destroyed")
        lib = _require("hdds_writer_get_publication_matched_status", "DataWriter.get_publication_matched_status()")
        function = lib.hdds_writer_get_publication_matched_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(PublicationMatchedStatus)]
        function.restype = ctypes.c_int32
        status = PublicationMatchedStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_offered_deadline_missed_status(self) -> DeadlineMissedStatus:
        """Read offered deadline missed and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import DeadlineMissedStatus

        if not self._handle:
            raise RuntimeError("DataWriter has been destroyed")
        lib = _require("hdds_writer_get_offered_deadline_missed_status", "DataWriter.get_offered_deadline_missed_status()")
        function = lib.hdds_writer_get_offered_deadline_missed_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(DeadlineMissedStatus)]
        function.restype = ctypes.c_int32
        status = DeadlineMissedStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_offered_incompatible_qos_status(self) -> IncompatibleQosStatus:
        """Read offered incompatible qos and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import IncompatibleQosStatus

        if not self._handle:
            raise RuntimeError("DataWriter has been destroyed")
        lib = _require("hdds_writer_get_offered_incompatible_qos_status", "DataWriter.get_offered_incompatible_qos_status()")
        function = lib.hdds_writer_get_offered_incompatible_qos_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(IncompatibleQosStatus)]
        function.restype = ctypes.c_int32
        status = IncompatibleQosStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_liveliness_lost_status(self) -> LivelinessLostStatus:
        """Read liveliness lost and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import LivelinessLostStatus

        if not self._handle:
            raise RuntimeError("DataWriter has been destroyed")
        lib = _require("hdds_writer_get_liveliness_lost_status", "DataWriter.get_liveliness_lost_status()")
        function = lib.hdds_writer_get_liveliness_lost_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(LivelinessLostStatus)]
        function.restype = ctypes.c_int32
        status = LivelinessLostStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def _instance_operation(self, operation, data, source_timestamp_ns=None):
        from ._native import check_error

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")
        key = None
        serialized = data if isinstance(data, bytes) else None
        if isinstance(data, bytes) and self._keyed_type is not None:
            decode = getattr(self._keyed_type, "decode_cdr2_le", None)
            if not callable(decode):
                raise NotImplementedError("pre-encoded keyed operations require a decoding codec")
            data, _ = decode(data)
        if not isinstance(data, bytes):
            msg = data
            keyed = self._keyed_type is not None
            if operation.startswith("write") or not keyed:
                data = serialized if serialized is not None else self._encode_typed(msg)
            else:
                data = b""
            if keyed:
                if not hasattr(msg, "encode_key_cdr2_le") or not getattr(msg, "HDDS_KEY_SUPPORTED", False):
                    raise NotImplementedError("keyed publishing requires a current hddsgen codec")
                key_bytes = msg.encode_key_cdr2_le()
                key_buffer = ctypes.create_string_buffer(key_bytes)
                normal = msg.compute_key()
                protected = msg.compute_key(protected_key=True)
                if len(normal) != 16 or len(protected) != 16:
                    raise ValueError("KeyHash must contain 16 bytes")
                key = _SerializedKey((ctypes.c_uint8 * 16).from_buffer_copy(normal),
                                     (ctypes.c_uint8 * 16).from_buffer_copy(protected),
                                     ctypes.cast(key_buffer, ctypes.c_void_p), len(key_bytes), 2)
        symbol = "hdds_writer_" + operation + ("_keyed" if key is not None else "")
        lib = _require(symbol, "DataWriter." + operation + "()")
        buffer = ctypes.create_string_buffer(data)
        args = [self._handle, buffer, len(data)]
        if key is not None:
            args.append(ctypes.byref(key))
        if operation.endswith("_w_timestamp"):
            if not isinstance(source_timestamp_ns, int):
                raise TypeError("source_timestamp_ns must be an integer")
            if not 0 <= source_timestamp_ns <= 0xffffffffffffffff:
                raise ValueError("source_timestamp_ns must fit uint64")
            args.append(source_timestamp_ns)
        function = getattr(lib, symbol)
        argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        if key is not None:
            argtypes.append(ctypes.POINTER(_SerializedKey))
        if operation.endswith("_w_timestamp"):
            argtypes.append(ctypes.c_uint64)
        if operation.startswith("register_instance"):
            argtypes.append(ctypes.POINTER(ctypes.c_uint8 * 16))
            handle = (ctypes.c_uint8 * 16)()
            args.append(ctypes.byref(handle))
        function.argtypes = argtypes
        function.restype = ctypes.c_int32
        check_error(function(*args))
        if operation.startswith("register_instance"):
            return bytes(handle)

    def write_w_timestamp(self, data: bytes, source_timestamp_ns: int) -> None:
        """Write bytes with a source timestamp in nanoseconds since Unix epoch."""
        return self._instance_operation("write_w_timestamp", data, source_timestamp_ns)

    def dispose(self, data: Any) -> None:
        """Dispose."""
        return self._instance_operation("dispose", data)

    def dispose_w_timestamp(self, data: Any, source_timestamp_ns: int) -> None:
        """Dispose with a source timestamp in nanoseconds since Unix epoch."""
        return self._instance_operation("dispose_w_timestamp", data, source_timestamp_ns)

    def unregister_instance(self, data: Any) -> None:
        """Unregister instance."""
        return self._instance_operation("unregister_instance", data)

    def unregister_instance_w_timestamp(self, data: Any, source_timestamp_ns: int) -> None:
        """Unregister with a source timestamp in nanoseconds since Unix epoch."""
        return self._instance_operation("unregister_instance_w_timestamp", data, source_timestamp_ns)

    def register_instance(self, data: Any) -> bytes:
        """Register a typed instance, or raw keyless bytes, without emitting data."""
        return self._instance_operation("register_instance", data)

    def register_instance_w_timestamp(self, data: Any, source_timestamp_ns: int) -> bytes:
        """Register without emitting data; accept epoch nanoseconds for API symmetry."""
        return self._instance_operation("register_instance_w_timestamp", data, source_timestamp_ns)

    def write_typed_w_timestamp(self, msg: Any, source_timestamp_ns: int) -> None:
        """CDR2-encode a message and write it with an explicit source timestamp."""
        self._instance_operation("write_w_timestamp", msg, source_timestamp_ns)

    def get_status_condition(self) -> ctypes.c_void_p:
        """Get the status condition handle for WaitSet integration.

        The status condition triggers on PUBLICATION_MATCHED,
        OFFERED_INCOMPATIBLE_QOS and OFFERED_DEADLINE_MISSED. It is cached
        after the first call. Use with ``WaitSet.attach_writer()`` for
        event-driven match notification.

        Returns:
            Opaque status condition handle (c_void_p).

        Raises:
            RuntimeError: If the writer has been destroyed.
        """
        from ._native import get_lib

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")

        if self._status_condition is None:
            lib = get_lib()
            self._status_condition = lib.hdds_writer_get_status_condition(self._handle)

        return self._status_condition

    def set_listener(self, listener) -> None:
        """Install a WriterListener on this writer, replacing any listener.

        Only the methods ``listener`` overrides are reported. Callbacks run on
        HDDS threads (``on_sample_written`` on the thread calling
        ``write()``); an exception they raise is logged on the
        ``hdds.listener`` logger, never propagated. Replacing returns once
        the previous listener's callbacks running on other threads are over.
        See ``hdds.listener`` for the full threading contract.

        Args:
            listener: A ``WriterListener`` subclass instance.

        Raises:
            RuntimeError: If the writer has been destroyed.
            HddsException: If the native call fails.

        Example:
            >>> class MyListener(hdds.WriterListener):
            ...     def on_publication_matched(self, status):
            ...         print(f"Matched {status.current_count} readers")
            >>> writer.set_listener(MyListener())
        """
        from .listener import _install

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")
        _install("writer", self._handle, listener, from_entity=True)
        self._listener = listener

    def clear_listener(self) -> None:
        """Remove the listener from this writer.

        Returns once no callback of it runs on another thread. A callback may
        clear its own listener.
        """
        from .listener import _clear

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")
        _clear("writer", self._handle)
        self._listener = None

    def _destroy(self) -> None:
        """Internal cleanup."""
        from ._native import get_lib
        from .listener import _forget_keys, _keys_of

        if self._handle:
            lib = get_lib()
            handle, self._handle = self._handle, None
            self._status_condition = None
            keys = _keys_of(handle)
            # Waits for running listener callbacks.
            lib.hdds_writer_destroy(handle)
            _forget_keys(keys)
            self._listener = None

    def __repr__(self) -> str:
        return f"DataWriter(topic={self._topic_name!r})"


CDR_LE = 0x0001
"""Encapsulation identifier of an XCDR1 sample (DDS-XTypes 1.3 Table 60)."""
CDR2_LE = 0x0007
"""Encapsulation identifier of an XCDR2 sample."""


def decodes_xcdr1(msg_type: Optional[type]) -> bool:
    """Whether the generated class ``msg_type`` decodes XCDR1 as well as XCDR2.

    hdds_gen 2.0 and later emit ``decode_by_encapsulation`` (and the module
    marker ``HDDS_DECODES_XCDR1``); earlier classes decode XCDR2 only.
    """
    return msg_type is not None and callable(getattr(msg_type, "decode_by_encapsulation", None))


_EXTENSIBILITY_CODES = {"final": 0, "appendable": 1, "mutable": 2}

# The type name an endpoint with a type but no declared name announces, as
# earlier releases did.
PLACEHOLDER_TYPE_NAME = "RawBytes"


def endpoint_type_name(type_name: Optional[str], msg_type: Optional[type]) -> Optional[str]:
    """The type name an endpoint announces in discovery, or None for an
    endpoint with no type of its own.

    ``type_name`` when given; else, for an endpoint created for ``msg_type``,
    the qualified IDL name the generated class says (``type_name()``,
    hdds_gen), else the placeholder ``"RawBytes"`` explicitly (a class of an
    older hdds_gen). An endpoint created for a type never adopts the name a
    peer announces (DDS-XTypes 1.3 7.6.3.4.2 Step 2 would pair it with a
    peer whose bytes it cannot decode). None only when there is neither a name
    nor a type: the endpoint then adopts the name its topic's other endpoints
    announce, else ``"RawBytes"``.

    An empty ``type_name`` is no name (the C ABI reads an empty name as a
    type-less endpoint, which adopts): for an endpoint with a ``msg_type`` it
    gives the class's name, never an adopted one.

    Raises:
        ValueError: a ``type_name`` containing a NUL character, which the C
            string would cut short.
    """
    if type_name is not None and "\0" in type_name:
        raise ValueError("type_name must not contain a NUL character")
    if type_name:
        return type_name
    if msg_type is None:
        return None
    declared = getattr(msg_type, "type_name", None)
    if callable(declared):
        try:
            name = declared()
        except Exception:  # a class whose type_name() needs state is not a name
            name = None
        if isinstance(name, str) and name and "\0" not in name:
            return name
    return PLACEHOLDER_TYPE_NAME


def writer_extensibility(
    extensibility: Optional[str], msg_type: Optional[type]
) -> Optional[int]:
    """The C ABI extensibility (``HDDS_EXTENSIBILITY_*``) of a writer, or
    None for a writer that labels every sample FINAL (``CDR2_LE``), as
    earlier releases did.

    ``extensibility`` when given; else the ``HDDS_EXTENSIBILITY`` a class
    hdds_gen 2.0 or later generated carries (``"final"``, ``"appendable"``,
    ``"mutable"``), so a writer of ``msg_type`` labels every sample with the
    encapsulation identifier its body needs (DDS-XTypes 1.3 7.6.3.1.2,
    Table 60: ``D_CDR2_LE`` for an APPENDABLE type, the hdds_gen default,
    ``PL_CDR2_LE`` for a MUTABLE one). A class without it (an older
    hdds_gen) keeps the earlier behaviour.

    Raises:
        ValueError: an extensibility that is none of the three.
    """
    if extensibility is None and msg_type is not None:
        extensibility = getattr(msg_type, "HDDS_EXTENSIBILITY", None)
    if extensibility is None:
        return None
    if extensibility not in _EXTENSIBILITY_CODES:
        raise ValueError("extensibility: 'final', 'appendable' or 'mutable'")
    return _EXTENSIBILITY_CODES[extensibility]


def reader_qos_for(msg_type: Optional[type], qos: Optional[QoS]) -> Optional[QoS]:
    """The QoS of a reader of ``msg_type``: ``qos`` requesting [XCDR, XCDR2]
    when the class decodes XCDR1 and ``qos`` sets no DATA_REPRESENTATION
    (DDS-XTypes 1.3 7.6.3.1.1: a reader that deserializes version 1 requests
    XCDR as well); ``qos`` unchanged otherwise. A class that decodes XCDR2
    only keeps the reader at XCDR2, so it is never handed XCDR1 bytes.

    Raises:
        RuntimeError: ``msg_type`` decodes XCDR1 but the loaded libhdds_c
            predates ``hdds_qos_set_data_representation`` (added together
            with ``hdds_reader_take_ex``, same release: a library missing
            one is missing both). That old library has no API to request
            XCDR2 only here, and no way for ``take_with_encapsulation`` to
            learn a taken sample's true representation either -- its
            fallback there can only ever assume ``CDR2_LE``. Requesting
            the default (empty DATA_REPRESENTATION) on such a library
            would announce ``[XCDR, XCDR2]`` (this library's own
            ``resolve_reader_data_representation``) and risk matching a
            writer that offers XCDR1 (the default for any writer of a
            type that does not refuse it), with no
            way to notice the mismatch: a silent mislabel rather than a
            loud refusal. Fail here instead of guessing -- unconditionally:
            a lib missing this ABI cannot report back whatever `qos`
            already carries, either, so there is no reading of `qos` this
            function can trust enough to skip the refusal.
    """
    if not decodes_xcdr1(msg_type):
        return qos
    from ._native import get_lib
    if not hasattr(get_lib(), "hdds_qos_set_data_representation"):
        raise RuntimeError(
            "%s decodes XCDR1 (hdds_gen 2.0+), but the loaded libhdds_c "
            "predates hdds_qos_set_data_representation/"
            "hdds_reader_take_ex and cannot request XCDR2 only, nor learn "
            "a taken sample's true representation: refusing rather than "
            "risking a silent mislabel. Upgrade libhdds_c, or use "
            "generated code from before hdds_gen 2.0 (XCDR2-only) with "
            "this library." % (msg_type.__name__ if msg_type else "<unknown>")
        )
    base = qos.clone() if qos is not None else QoS.default()
    if not base.get_data_representation():
        base.data_representation(QoS.XCDR_DATA_REPRESENTATION, QoS.XCDR2_DATA_REPRESENTATION)
    return base


class DataReader:
    """DDS DataReader for subscribing to data on a topic.

    DataReaders are created via ``Participant.create_reader()`` or
    ``Subscriber.create_reader()``. They receive data samples published
    by matched DataWriters on the same topic.

    Use ``take()`` for non-blocking data retrieval, or attach the reader
    to a ``WaitSet`` for event-driven reading.

    Example:
        >>> reader = participant.create_reader("topic")
        >>> data = reader.take()  # Non-blocking, returns None if no data
        >>> if data is not None:
        ...     process(data)
    """

    DEFAULT_BUFFER_SIZE = 65536
    """Default receive buffer size in bytes (64 KB)."""

    def __init__(self):
        """Private constructor. Use Participant.create_reader()."""
        raise RuntimeError("Use Participant.create_reader() to create DataReader")

    @classmethod
    def _from_handle(
        cls,
        topic_name: str,
        handle: ctypes.c_void_p,
        qos: QoS,
    ) -> DataReader:
        """Internal: create from FFI handle."""
        reader = cls.__new__(cls)
        reader._topic_name = topic_name
        reader._handle = handle
        reader._qos = qos
        reader._status_condition = None
        return reader

    @property
    def topic_name(self) -> str:
        """Get the topic name this reader subscribes to.

        Returns:
            Topic name string.
        """
        return self._topic_name

    @property
    def qos(self) -> QoS:
        """Get the QoS configuration for this reader.

        Returns:
            QoS profile used by this reader.
        """
        return self._qos

    def take(self, buffer_size: int = DEFAULT_BUFFER_SIZE) -> Optional[bytes]:
        """Take one sample from the reader (non-blocking).

        Removes and returns the next available data sample. If no data is
        available, returns None immediately without blocking.

        Args:
            buffer_size: Maximum size of data to read in bytes. If the actual
                sample exceeds this, only ``buffer_size`` bytes are returned.

        Returns:
            Raw bytes of the data sample, or None if no data is available.

        Raises:
            RuntimeError: If the reader has been destroyed.
            HddsException: If the native take operation fails.
        """
        return self._take_raw(buffer_size)

    def take_typed(self, msg_type: type, buffer_size: int = DEFAULT_BUFFER_SIZE) -> Optional[Any]:
        """Take one sample and decode it as a typed message.

        The message type must have a ``decode_cdr2_le(data) -> (msg, bytes_read)``
        class method (as generated by hdds_gen). A class that also has
        ``decode_by_encapsulation`` (hdds_gen 2.0) is handed the sample's
        encapsulation identifier and decodes XCDR1 as well; one that has not
        refuses an XCDR1 sample (ValueError) rather than misread it, which
        happens only when the reader's QoS requested XCDR.

        Args:
            msg_type: The message class with ``decode_cdr2_le`` class method.
            buffer_size: Maximum receive buffer size.

        Returns:
            A decoded message instance, or None if no data is available.

        Raises:
            RuntimeError: If the reader has been destroyed.
            AttributeError: If msg_type has no ``decode_cdr2_le`` method.

        Example:
            >>> from generated.HelloWorld import HelloWorld
            >>> reader = participant.create_reader("HelloWorldTopic")
            >>> msg = reader.take_typed(HelloWorld)
            >>> if msg is not None:
            ...     print(msg.message)
        """
        sample = self.take_with_encapsulation(buffer_size)
        if sample is None:
            return None
        data, encapsulation_id = sample
        if decodes_xcdr1(msg_type):
            msg, _ = msg_type.decode_by_encapsulation(encapsulation_id, data)
            return msg
        if encapsulation_id != CDR2_LE:
            raise ValueError(
                "an XCDR1 sample (encapsulation %#06x), and %s decodes XCDR2 only"
                % (encapsulation_id, msg_type.__name__))
        msg, _ = msg_type.decode_cdr2_le(data)
        return msg

    def take_with_encapsulation(
        self, buffer_size: int = DEFAULT_BUFFER_SIZE
    ) -> Optional[tuple[bytes, int]]:
        """Take one sample and the representation it is in (non-blocking).

        Returns ``(bytes, encapsulation_id)``: ``CDR_LE`` (0x0001) for XCDR1,
        ``CDR2_LE`` (0x0007) for XCDR2 (the encoding version; the
        extensibility framing is not reported), or None if no data is
        available. With a libhdds_c older than ``hdds_reader_take_ex``, the
        identifier is always ``CDR2_LE``: this reader's generated code does
        NOT decode XCDR1 (``reader_qos_for`` refuses at creation otherwise,
        rather than let this path ever report a taken sample's true
        representation wrong), and such a reader requests XCDR2 only.
        """
        from ._native import get_lib, HddsError

        if not self._handle:
            raise RuntimeError("Reader has been destroyed")
        lib = get_lib()
        if not hasattr(lib, "hdds_reader_take_ex"):
            data = self._take_raw(buffer_size)
            return None if data is None else (data, CDR2_LE)

        buffer = (ctypes.c_uint8 * buffer_size)()
        actual_size = ctypes.c_size_t(0)
        encapsulation_id = ctypes.c_uint16(0)
        # A sample longer than the buffer stays in the reader: take it again at
        # the length the reader reported (a few attempts).
        for _ in range(4):
            err = lib.hdds_reader_take_ex(
                self._handle, buffer, buffer_size,
                ctypes.byref(actual_size), ctypes.byref(encapsulation_id))
            if err != HddsError.OUT_OF_MEMORY:
                break
            buffer_size = actual_size.value
            buffer = (ctypes.c_uint8 * buffer_size)()
        if err == HddsError.NOT_FOUND:
            return None
        if err != HddsError.OK:
            from ._native import HddsException
            raise HddsException(err)
        return bytes(buffer[:actual_size.value]), encapsulation_id.value

    def _take_raw(self, buffer_size: int) -> Optional[bytes]:
        """Non-blocking take."""
        from ._native import get_lib, HddsError

        if not self._handle:
            raise RuntimeError("Reader has been destroyed")

        lib = get_lib()

        # Allocate buffer
        buffer = (ctypes.c_uint8 * buffer_size)()
        actual_size = ctypes.c_size_t(0)

        # A sample longer than the buffer stays in the reader: take it again at
        # the length the reader reported (a few attempts).
        for _ in range(4):
            err = lib.hdds_reader_take(
                self._handle,
                buffer,
                buffer_size,
                ctypes.byref(actual_size)
            )
            if err != HddsError.OUT_OF_MEMORY:
                break
            buffer_size = actual_size.value
            buffer = (ctypes.c_uint8 * buffer_size)()

        if err == HddsError.NOT_FOUND:
            return None  # No data available
        if err != HddsError.OK:
            from ._native import HddsException
            raise HddsException(err)

        return bytes(buffer[:actual_size.value])

    def get_subscription_matched_status(self) -> SubscriptionMatchedStatus:
        """Read subscription matched and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import SubscriptionMatchedStatus

        if not self._handle:
            raise RuntimeError("DataReader has been destroyed")
        lib = _require("hdds_reader_get_subscription_matched_status", "DataReader.get_subscription_matched_status()")
        function = lib.hdds_reader_get_subscription_matched_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(SubscriptionMatchedStatus)]
        function.restype = ctypes.c_int32
        status = SubscriptionMatchedStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_requested_deadline_missed_status(self) -> DeadlineMissedStatus:
        """Read requested deadline missed and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import DeadlineMissedStatus

        if not self._handle:
            raise RuntimeError("DataReader has been destroyed")
        lib = _require("hdds_reader_get_requested_deadline_missed_status", "DataReader.get_requested_deadline_missed_status()")
        function = lib.hdds_reader_get_requested_deadline_missed_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(DeadlineMissedStatus)]
        function.restype = ctypes.c_int32
        status = DeadlineMissedStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_requested_incompatible_qos_status(self) -> IncompatibleQosStatus:
        """Read requested incompatible qos and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import IncompatibleQosStatus

        if not self._handle:
            raise RuntimeError("DataReader has been destroyed")
        lib = _require("hdds_reader_get_requested_incompatible_qos_status", "DataReader.get_requested_incompatible_qos_status()")
        function = lib.hdds_reader_get_requested_incompatible_qos_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(IncompatibleQosStatus)]
        function.restype = ctypes.c_int32
        status = IncompatibleQosStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_liveliness_changed_status(self) -> LivelinessChangedStatus:
        """Read liveliness changed and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import LivelinessChangedStatus

        if not self._handle:
            raise RuntimeError("DataReader has been destroyed")
        lib = _require("hdds_reader_get_liveliness_changed_status", "DataReader.get_liveliness_changed_status()")
        function = lib.hdds_reader_get_liveliness_changed_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(LivelinessChangedStatus)]
        function.restype = ctypes.c_int32
        status = LivelinessChangedStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_sample_lost_status(self) -> SampleLostStatus:
        """Read sample lost and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import SampleLostStatus

        if not self._handle:
            raise RuntimeError("DataReader has been destroyed")
        lib = _require("hdds_reader_get_sample_lost_status", "DataReader.get_sample_lost_status()")
        function = lib.hdds_reader_get_sample_lost_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(SampleLostStatus)]
        function.restype = ctypes.c_int32
        status = SampleLostStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_sample_rejected_status(self) -> SampleRejectedStatus:
        """Read sample rejected and reset changes (DDS 1.4 2.2.4.2.1)."""
        from ._native import check_error
        from .listener import SampleRejectedStatus

        if not self._handle:
            raise RuntimeError("DataReader has been destroyed")
        lib = _require("hdds_reader_get_sample_rejected_status", "DataReader.get_sample_rejected_status()")
        function = lib.hdds_reader_get_sample_rejected_status
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(SampleRejectedStatus)]
        function.restype = ctypes.c_int32
        status = SampleRejectedStatus()
        check_error(function(self._handle, ctypes.byref(status)))
        return status

    def get_status_condition(self) -> ctypes.c_void_p:
        """Get the status condition handle for WaitSet integration.

        The status condition triggers when new data is available. It is cached
        after the first call. Use with ``WaitSet.attach_reader()`` for
        event-driven reading.

        Returns:
            Opaque status condition handle (c_void_p).

        Raises:
            RuntimeError: If the reader has been destroyed.
        """
        from ._native import get_lib

        if not self._handle:
            raise RuntimeError("Reader has been destroyed")

        if self._status_condition is None:
            lib = get_lib()
            self._status_condition = lib.hdds_reader_get_status_condition(self._handle)

        return self._status_condition

    def set_listener(self, listener) -> None:
        """Install a ReaderListener on this reader, replacing any listener.

        Only the methods ``listener`` overrides are reported. Callbacks run on
        HDDS threads (for a writer of the same participant, on the thread
        calling ``write()``); an exception they raise is logged on the
        ``hdds.listener`` logger, never propagated. A callback may ``take()``
        from this reader. Replacing returns once the previous listener's
        callbacks running on other threads are over. See ``hdds.listener``
        for the full threading contract.

        Args:
            listener: A ``ReaderListener`` subclass instance.

        Raises:
            RuntimeError: If the reader has been destroyed.
            HddsException: If the native call fails.

        Example:
            >>> class MyListener(hdds.ReaderListener):
            ...     def on_data_available(self, data):
            ...         print(f"Got {len(data)} bytes")
            >>> reader.set_listener(MyListener())
        """
        from .listener import _install

        if not self._handle:
            raise RuntimeError("Reader has been destroyed")
        _install("reader", self._handle, listener, from_entity=True)
        self._listener = listener

    def clear_listener(self) -> None:
        """Remove the listener from this reader.

        Returns once no callback of it runs on another thread. A callback may
        clear its own listener.
        """
        from .listener import _clear

        if not self._handle:
            raise RuntimeError("Reader has been destroyed")
        _clear("reader", self._handle)
        self._listener = None

    def _destroy(self) -> None:
        """Internal cleanup."""
        from ._native import get_lib
        from .listener import _forget_keys, _keys_of

        if self._handle:
            lib = get_lib()
            handle, self._handle = self._handle, None
            self._status_condition = None
            keys = _keys_of(handle)
            # Waits for running listener callbacks.
            lib.hdds_reader_destroy(handle)
            _forget_keys(keys)
            self._listener = None

    def __repr__(self) -> str:
        return f"DataReader(topic={self._topic_name!r})"


class Publisher:
    """
    DDS Publisher entity.

    Groups DataWriters and applies common QoS policies.

    Example:
        >>> pub = participant.create_publisher()
        >>> writer = pub.create_writer("topic")
    """

    def __init__(self):
        """Private constructor. Use Participant.create_publisher()."""
        raise RuntimeError("Use Participant.create_publisher() to create Publisher")

    @classmethod
    def _from_handle(
        cls,
        handle: ctypes.c_void_p,
        qos: Optional[QoS],
    ) -> Publisher:
        """Internal: create from FFI handle."""
        pub = cls.__new__(cls)
        pub._handle = handle
        pub._qos = qos
        pub._writers: list[DataWriter] = []
        return pub

    @property
    def qos(self) -> Optional[QoS]:
        """Get QoS configuration."""
        return self._qos

    def create_writer(
        self,
        topic_name: str,
        msg_type: Optional[type] = None,
        qos: Optional[QoS] = None,
        extensibility: Optional[str] = None,
        type_name: Optional[str] = None,
    ) -> DataWriter:
        """
        Create a DataWriter from this Publisher.

        Args:
            topic_name: Name of the topic
            msg_type: The generated class the bodies are encoded from, passed
                positionally as the natural way to create a typed writer
                (``pub.create_writer("topic", SensorData)``): its
                ``HDDS_EXTENSIBILITY`` (hdds_gen 2.0) labels every sample
                when ``extensibility`` is None; see Participant.create_writer.
                A writer created without it, then given a non-FINAL typed
                instance in ``write_typed()``, warns once instead of
                mislabelling every sample silently.
            qos: QoS configuration (default if None)
            extensibility: "final", "appendable" or "mutable", the
                extensibility of the IDL type the bodies are encoded from;
                see Participant.create_writer.
            type_name: DDS type name announced via SEDP. Without it, a
                writer of ``msg_type`` announces the class's own type name
                (``type_name()``), never a peer's; without ``msg_type``
                either it adopts the name its topic's readers announce,
                else ``"RawBytes"``.

        Returns:
            DataWriter for publishing

        Raises:
            RuntimeError: If writer creation fails
            ValueError: An unknown extensibility
        """
        from ._native import get_lib

        if not self._handle:
            raise RuntimeError("Publisher has been destroyed")

        if isinstance(msg_type, QoS):
            # Releases before 1.5 took the QoS as the second positional
            # argument; keep such calls working instead of silently
            # dropping their QoS.
            if qos is not None:
                raise TypeError("create_writer() got a QoS both positionally and as qos=")
            qos, msg_type = msg_type, None

        lib = get_lib()
        code = writer_extensibility(extensibility, msg_type)
        keyed = code is not None and _has_key_codec(msg_type)
        announced = endpoint_type_name(type_name, msg_type)
        if keyed:
            function = getattr(lib, "hdds_publisher_create_writer_keyed", None)
            if function is None:
                raise RuntimeError("this libhdds_c cannot label a writer's extensibility")
            function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32]
            function.restype = ctypes.c_void_p
            handle = function(
                self._handle,
                topic_name.encode('utf-8'),
                announced.encode("utf-8") if announced is not None else None,
                qos._c_handle if qos is not None else None,
                code,
            )
        elif announced is not None and (
            announced != PLACEHOLDER_TYPE_NAME
            or hasattr(lib, "hdds_publisher_create_writer_with_type")
        ):
            # An endpoint with a type announces its own name: the _with_type
            # entry (FINAL labels when the class says no extensibility). An
            # older libhdds_c has no such entry but announces "RawBytes" from
            # every other constructor, so that name falls through to them.
            create = _require("hdds_publisher_create_writer_with_type",
                              "Publisher.create_writer() with a type name")
            handle = create.hdds_publisher_create_writer_with_type(
                self._handle,
                topic_name.encode('utf-8'),
                announced.encode("utf-8"),
                qos._c_handle if qos is not None else None,
                code if code is not None else 0,
            )
        elif code is not None:
            if not hasattr(lib, "hdds_publisher_create_writer_with_extensibility"):
                raise RuntimeError("this libhdds_c cannot label a writer's extensibility")
            handle = lib.hdds_publisher_create_writer_with_extensibility(
                self._handle,
                topic_name.encode('utf-8'),
                qos._c_handle if qos is not None else None,
                code,
            )
        elif qos is not None:
            handle = lib.hdds_publisher_create_writer_with_qos(
                self._handle,
                topic_name.encode('utf-8'),
                qos._c_handle,
            )
        else:
            handle = lib.hdds_publisher_create_writer(
                self._handle,
                topic_name.encode('utf-8'),
            )
        if not handle:
            raise _creation_error("writer", topic_name, qos)

        writer = DataWriter._from_handle(
            topic_name, handle, qos or QoS.default(), extensibility_known=(code is not None),
            keyed_type=msg_type if keyed else None
        )
        self._writers.append(writer)
        return writer

    def wait_for_acknowledgments(self, timeout: float = 10.0) -> bool:
        """Block until the data of every writer of this Publisher has been
        acknowledged by every matched RELIABLE reader (DDS v1.4
        Sec.2.2.2.4.1.12).

        ``timeout`` bounds the whole call, not each writer. A BEST_EFFORT
        writer owes nothing, and a Publisher without a writer returns True
        at once.

        Args:
            timeout: Maximum time to wait, in seconds.

        Returns:
            True once acknowledged, False on timeout.

        Raises:
            RuntimeError: If the publisher has been destroyed.
            ValueError: If ``timeout`` is negative.
            NotImplementedError: If the loaded libhdds_c predates 1.5.0.
            HddsException: If the native call fails for another reason.

        Example:
            >>> pub.create_writer("topic", qos=QoS.reliable()).write(sample)
            >>> if not pub.wait_for_acknowledgments(timeout=2.0):
            ...     print("a reliable reader has not caught up yet")
        """
        from ._native import check_error, HddsError

        if not self._handle:
            raise RuntimeError("Publisher has been destroyed")
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        lib = _require(
            "hdds_publisher_wait_for_acknowledgments", "Publisher.wait_for_acknowledgments()")
        err = lib.hdds_publisher_wait_for_acknowledgments(self._handle, int(timeout * 1000))
        if err == HddsError.TIMEOUT:
            return False
        check_error(err)
        return True

    def _destroy(self) -> None:
        """Internal cleanup."""
        from ._native import get_lib

        for writer in self._writers:
            writer._destroy()
        self._writers.clear()

        if self._handle:
            lib = get_lib()
            lib.hdds_publisher_destroy(self._handle)
            self._handle = None

    def __repr__(self) -> str:
        return f"Publisher(writers={len(self._writers)})"


class Subscriber:
    """
    DDS Subscriber entity.

    Groups DataReaders and applies common QoS policies.

    Example:
        >>> sub = participant.create_subscriber()
        >>> reader = sub.create_reader("topic")
    """

    def __init__(self):
        """Private constructor. Use Participant.create_subscriber()."""
        raise RuntimeError("Use Participant.create_subscriber() to create Subscriber")

    @classmethod
    def _from_handle(
        cls,
        handle: ctypes.c_void_p,
        qos: Optional[QoS],
    ) -> Subscriber:
        """Internal: create from FFI handle."""
        sub = cls.__new__(cls)
        sub._handle = handle
        sub._qos = qos
        sub._readers: list[DataReader] = []
        return sub

    @property
    def qos(self) -> Optional[QoS]:
        """Get QoS configuration."""
        return self._qos

    def create_reader(
        self,
        topic_name: str,
        qos: Optional[QoS] = None,
        msg_type: Optional[type] = None,
        type_name: Optional[str] = None,
    ) -> DataReader:
        """
        Create a DataReader from this Subscriber.

        Args:
            topic_name: Name of the topic
            qos: QoS configuration (default if None)
            msg_type: The generated class the samples are decoded with
                (``take_typed``). One that decodes XCDR1 too
                (``decode_by_encapsulation``, hdds_gen 2.0) makes the reader
                request XCDR as well as XCDR2 when ``qos`` sets no
                DATA_REPRESENTATION; otherwise the reader requests XCDR2.
                The reader announces the class's own type name
                (``type_name()``), never a peer's.
            type_name: DDS type name announced via SEDP. Without it and
                without ``msg_type`` the reader adopts the name its topic's
                writers announce, else ``"RawBytes"``.

        Returns:
            DataReader for subscribing

        Raises:
            RuntimeError: If reader creation fails
        """
        from ._native import get_lib

        if not self._handle:
            raise RuntimeError("Subscriber has been destroyed")

        lib = get_lib()
        qos = reader_qos_for(msg_type, qos)
        announced = endpoint_type_name(type_name, msg_type)
        if announced is not None and (
            announced != PLACEHOLDER_TYPE_NAME
            or hasattr(lib, "hdds_subscriber_create_reader_with_type")
        ):
            # (An older libhdds_c announces "RawBytes" from the constructors
            # below, so that name needs no _with_type entry.)
            create = _require("hdds_subscriber_create_reader_with_type",
                              "Subscriber.create_reader() with a type name")
            handle = create.hdds_subscriber_create_reader_with_type(
                self._handle,
                topic_name.encode('utf-8'),
                announced.encode('utf-8'),
                qos._c_handle if qos is not None else None,
            )
        elif qos is not None:
            handle = lib.hdds_subscriber_create_reader_with_qos(
                self._handle,
                topic_name.encode('utf-8'),
                qos._c_handle,
            )
        else:
            handle = lib.hdds_subscriber_create_reader(
                self._handle,
                topic_name.encode('utf-8'),
            )
        if not handle:
            raise _creation_error("reader", topic_name, qos)

        reader = DataReader._from_handle(topic_name, handle, qos or QoS.default())
        self._readers.append(reader)
        return reader

    def begin_access(self) -> None:
        """Open an access bracket (DDS v1.4 Sec.2.2.2.5.2.8).

        When this Subscriber's PRESENTATION access scope is GROUP, its
        readers are read only inside a bracket: outside, ``take()`` raises
        HddsException with ``HddsError.INVALID_STATE``. Brackets nest: each
        ``begin_access()`` is closed by its own ``end_access()``. For any
        other access scope a bracket has no effect. Prefer ``access()``.

        Raises:
            RuntimeError: If the Subscriber has been destroyed, or the
                native library has no access brackets.
            HddsException: If the native call fails.
        """
        self._bracket("hdds_subscriber_begin_access")

    def end_access(self) -> None:
        """Close the bracket ``begin_access()`` opened.

        Raises:
            HddsException: ``HddsError.INVALID_STATE`` when no bracket is
                open (PRECONDITION_NOT_MET).
        """
        self._bracket("hdds_subscriber_end_access")

    @contextlib.contextmanager
    def access(self) -> Iterator[Subscriber]:
        """An access bracket for the ``with`` block.

        Example:
            >>> with subscriber.access():
            ...     a = reader_a.take()
            ...     b = reader_b.take()
        """
        self.begin_access()
        try:
            yield self
        finally:
            self.end_access()

    def _bracket(self, name: str) -> None:
        from ._native import check_error, get_lib

        if not self._handle:
            raise RuntimeError("Subscriber has been destroyed")
        lib = get_lib()
        call = getattr(lib, name, None)
        if call is None:
            raise RuntimeError(f"the native library has no {name}")
        check_error(call(self._handle))

    def _destroy(self) -> None:
        """Internal cleanup."""
        from ._native import get_lib

        for reader in self._readers:
            reader._destroy()
        self._readers.clear()

        if self._handle:
            lib = get_lib()
            lib.hdds_subscriber_destroy(self._handle)
            self._handle = None

    def __repr__(self) -> str:
        return f"Subscriber(readers={len(self._readers)})"

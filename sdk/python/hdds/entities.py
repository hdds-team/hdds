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
from typing import Optional, Any, TYPE_CHECKING
import ctypes

from .qos import QoS

if TYPE_CHECKING:
    pass


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
    ) -> DataWriter:
        """Internal: create from FFI handle."""
        writer = cls.__new__(cls)
        writer._topic_name = topic_name
        writer._handle = handle
        writer._qos = qos
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
        publishing, serialize your type before calling this method.

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

    def _write_raw(self, data: bytes) -> None:
        """Write raw bytes."""
        from ._native import get_lib, check_error

        if not self._handle:
            raise RuntimeError("Writer has been destroyed")

        lib = get_lib()
        data_ptr = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        err = lib.hdds_writer_write(self._handle, data_ptr, len(data))
        check_error(err)

    def _destroy(self) -> None:
        """Internal cleanup."""
        from ._native import get_lib

        if self._handle:
            lib = get_lib()
            lib.hdds_writer_destroy(self._handle)
            self._handle = None

    def __repr__(self) -> str:
        return f"DataWriter(topic={self._topic_name!r})"


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

    def _take_raw(self, buffer_size: int) -> Optional[bytes]:
        """Non-blocking take."""
        from ._native import get_lib, HddsError

        if not self._handle:
            raise RuntimeError("Reader has been destroyed")

        lib = get_lib()

        # Allocate buffer
        buffer = (ctypes.c_uint8 * buffer_size)()
        actual_size = ctypes.c_size_t(0)

        err = lib.hdds_reader_take(
            self._handle,
            buffer,
            buffer_size,
            ctypes.byref(actual_size)
        )

        if err == HddsError.NOT_FOUND:
            return None  # No data available
        if err != HddsError.OK:
            from ._native import HddsException
            raise HddsException(err)

        return bytes(buffer[:actual_size.value])

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

    def _destroy(self) -> None:
        """Internal cleanup."""
        from ._native import get_lib

        if self._handle:
            lib = get_lib()
            lib.hdds_reader_destroy(self._handle)
            self._handle = None
            self._status_condition = None

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
        qos: Optional[QoS] = None,
    ) -> DataWriter:
        """
        Create a DataWriter from this Publisher.

        Args:
            topic_name: Name of the topic
            qos: QoS configuration (default if None)

        Returns:
            DataWriter for publishing

        Raises:
            RuntimeError: If writer creation fails
        """
        from ._native import get_lib

        if not self._handle:
            raise RuntimeError("Publisher has been destroyed")

        lib = get_lib()
        if qos is not None:
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
            raise RuntimeError(f"Failed to create writer for topic '{topic_name}'")

        writer = DataWriter._from_handle(topic_name, handle, qos or QoS.default())
        self._writers.append(writer)
        return writer

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
    ) -> DataReader:
        """
        Create a DataReader from this Subscriber.

        Args:
            topic_name: Name of the topic
            qos: QoS configuration (default if None)

        Returns:
            DataReader for subscribing

        Raises:
            RuntimeError: If reader creation fails
        """
        from ._native import get_lib

        if not self._handle:
            raise RuntimeError("Subscriber has been destroyed")

        lib = get_lib()
        if qos is not None:
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
            raise RuntimeError(f"Failed to create reader for topic '{topic_name}'")

        reader = DataReader._from_handle(topic_name, handle, qos or QoS.default())
        self._readers.append(reader)
        return reader

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

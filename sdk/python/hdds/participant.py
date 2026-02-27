# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS Participant - Entry point for DDS communication.

The Participant is the central entity in DDS. It acts as a factory for
DataWriters, DataReaders, Publishers, and Subscribers. Each Participant
joins a DDS domain and participates in discovery with other Participants
in the same domain.

Participants support the context manager protocol for automatic cleanup::

    with hdds.Participant("my_app") as p:
        writer = p.create_writer("topic")
        writer.write(b"hello")
    # Participant and all child entities are destroyed here.

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

from __future__ import annotations
from enum import IntEnum
from typing import Optional, TYPE_CHECKING
import ctypes

from .qos import QoS
from .entities import DataWriter, DataReader, Publisher, Subscriber

if TYPE_CHECKING:
    pass


class TransportMode(IntEnum):
    """Transport mode for participant creation."""
    INTRA_PROCESS = 0
    UDP_MULTICAST = 1


class Participant:
    """
    DDS Domain Participant.

    The Participant is the entry point for all DDS operations.
    It manages discovery, writers, readers, and topics.

    Example:
        >>> with hdds.Participant("my_app") as p:
        ...     writer = p.create_writer("topic")
        ...     writer.write(b"Hello")

        >>> p = hdds.Participant("my_app")
        >>> # ... use participant
        >>> p.close()
    """

    def __init__(
        self,
        name: str,
        domain_id: int = 0,
        enable_discovery: bool = True,
        transport: TransportMode = TransportMode.UDP_MULTICAST,
    ):
        """
        Create a new DDS Participant.

        Args:
            name: Application/participant name
            domain_id: DDS domain ID (0-232)
            enable_discovery: Enable UDP multicast discovery
            transport: Transport mode (UDP_MULTICAST or INTRA_PROCESS)
        """
        from ._native import get_lib

        self._name = name
        self._domain_id = domain_id
        self._enable_discovery = enable_discovery
        self._writers: list[DataWriter] = []
        self._readers: list[DataReader] = []
        self._publishers: list[Publisher] = []
        self._subscribers: list[Subscriber] = []

        lib = get_lib()
        self._handle = lib.hdds_participant_create_with_transport(
            name.encode('utf-8'),
            int(transport),
        )
        if not self._handle:
            raise RuntimeError(f"Failed to create participant '{name}'")

    @property
    def name(self) -> str:
        """Get participant name via the native FFI handle.

        Returns:
            The participant name string. Falls back to the name passed
            at construction if the FFI call returns NULL.
        """
        from ._native import get_lib
        lib = get_lib()
        name_ptr = lib.hdds_participant_name(self._handle)
        if name_ptr:
            return name_ptr.decode('utf-8')
        return self._name

    @property
    def domain_id(self) -> int:
        """Get domain ID from native handle.

        Returns:
            DDS domain ID (default 0).
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_participant_domain_id(self._handle)

    @property
    def participant_id(self) -> int:
        """Get unique participant ID within domain (0-119).

        Returns:
            Participant ID assigned during creation. Each domain supports
            up to 120 concurrent participants.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_participant_id(self._handle)

    def create_writer(
        self,
        topic_name: str,
        qos: Optional[QoS] = None,
    ) -> DataWriter:
        """
        Create a DataWriter for the given topic.

        Args:
            topic_name: Name of the topic
            qos: QoS configuration (default if None)

        Returns:
            DataWriter for publishing

        Example:
            >>> writer = participant.create_writer("Temperature",
            ...     qos=QoS.reliable().transient_local())
        """
        from ._native import get_lib

        if qos is None:
            qos = QoS.default()

        lib = get_lib()
        qos_handle = qos._c_handle if qos else None
        if qos_handle:
            handle = lib.hdds_writer_create_with_qos(
                self._handle,
                topic_name.encode('utf-8'),
                qos_handle
            )
        else:
            handle = lib.hdds_writer_create(
                self._handle,
                topic_name.encode('utf-8')
            )
        if not handle:
            raise RuntimeError(f"Failed to create writer for topic '{topic_name}'")

        writer = DataWriter._from_handle(topic_name, handle, qos)
        self._writers.append(writer)
        return writer

    def create_reader(
        self,
        topic_name: str,
        qos: Optional[QoS] = None,
    ) -> DataReader:
        """
        Create a DataReader for the given topic.

        Args:
            topic_name: Name of the topic
            qos: QoS configuration (default if None)

        Returns:
            DataReader for subscribing

        Example:
            >>> reader = participant.create_reader("Temperature",
            ...     qos=QoS.reliable())
            >>> data = reader.take()
        """
        from ._native import get_lib

        if qos is None:
            qos = QoS.default()

        lib = get_lib()
        qos_handle = qos._c_handle if qos else None
        if qos_handle:
            handle = lib.hdds_reader_create_with_qos(
                self._handle,
                topic_name.encode('utf-8'),
                qos_handle
            )
        else:
            handle = lib.hdds_reader_create(
                self._handle,
                topic_name.encode('utf-8')
            )
        if not handle:
            raise RuntimeError(f"Failed to create reader for topic '{topic_name}'")

        reader = DataReader._from_handle(topic_name, handle, qos)
        self._readers.append(reader)
        return reader

    def create_publisher(
        self,
        qos: Optional[QoS] = None,
    ) -> Publisher:
        """
        Create a Publisher for grouping DataWriters.

        Args:
            qos: QoS configuration (default if None)

        Returns:
            Publisher instance

        Example:
            >>> pub = participant.create_publisher()
            >>> writer = pub.create_writer("topic")
        """
        from ._native import get_lib

        lib = get_lib()
        if qos is not None:
            handle = lib.hdds_publisher_create_with_qos(self._handle, qos._c_handle)
        else:
            handle = lib.hdds_publisher_create(self._handle)
        if not handle:
            raise RuntimeError("Failed to create publisher")

        publisher = Publisher._from_handle(handle, qos)
        self._publishers.append(publisher)
        return publisher

    def create_subscriber(
        self,
        qos: Optional[QoS] = None,
    ) -> Subscriber:
        """
        Create a Subscriber for grouping DataReaders.

        Args:
            qos: QoS configuration (default if None)

        Returns:
            Subscriber instance

        Example:
            >>> sub = participant.create_subscriber()
            >>> reader = sub.create_reader("topic")
        """
        from ._native import get_lib

        lib = get_lib()
        if qos is not None:
            handle = lib.hdds_subscriber_create_with_qos(self._handle, qos._c_handle)
        else:
            handle = lib.hdds_subscriber_create(self._handle)
        if not handle:
            raise RuntimeError("Failed to create subscriber")

        subscriber = Subscriber._from_handle(handle, qos)
        self._subscribers.append(subscriber)
        return subscriber

    def close(self) -> None:
        """Close the participant and release all associated resources.

        Destroys all child entities (publishers, subscribers, writers, readers)
        before destroying the participant itself. Called automatically when
        exiting a context manager (``with`` block) or during garbage collection.

        Safe to call multiple times. Subsequent calls are no-ops.
        """
        from ._native import get_lib

        # Destroy all publishers and subscribers (and their writers/readers)
        for pub in self._publishers:
            pub._destroy()
        for sub in self._subscribers:
            sub._destroy()
        self._publishers.clear()
        self._subscribers.clear()

        # Destroy directly-created writers and readers
        for writer in self._writers:
            writer._destroy()
        for reader in self._readers:
            reader._destroy()
        self._writers.clear()
        self._readers.clear()

        # Destroy participant
        if self._handle:
            lib = get_lib()
            lib.hdds_participant_destroy(self._handle)
            self._handle = None

    def __enter__(self) -> Participant:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - closes participant."""
        self.close()

    def __del__(self):
        """Destructor - ensure cleanup."""
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"Participant(name={self._name!r}, domain_id={self._domain_id})"

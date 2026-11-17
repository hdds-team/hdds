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
import os

from .qos import QoS
from .entities import DataWriter, DataReader, Publisher, Subscriber, _creation_error, endpoint_type_name, writer_extensibility, _has_key_codec

if TYPE_CHECKING:
    pass


def _bad_domain_env_suffix() -> str:
    """Suffix for the participant error when HDDS_DOMAIN_ID picked the domain
    and does not parse.

    The native layer returns NULL with no reason, so the wrapper names the
    variable itself. Mirrors the core rule: unset or empty is no domain,
    otherwise ASCII decimal digits naming 0..232. Empty when there is nothing
    to report (valid value, or unset: the failure has another cause).
    """
    raw = os.environ.get("HDDS_DOMAIN_ID")
    if not raw:
        return ""
    digits = raw.lstrip("0") or "0"
    if raw.isascii() and raw.isdigit() and len(digits) <= 3 and int(digits) <= 232:
        return ""
    return f": HDDS_DOMAIN_ID={raw} is not a valid domain id (0..232)"


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
        domain_id: Optional[int] = None,
        enable_discovery: bool = True,
        transport: TransportMode = TransportMode.UDP_MULTICAST,
    ):
        """
        Create a new DDS Participant.

        Args:
            name: Application/participant name
            domain_id: DDS domain ID (0-232). None (default) means HDDS_DOMAIN_ID
                if set and valid, else 0; an explicit value always wins.
            enable_discovery: Enable UDP multicast discovery
            transport: Transport mode (UDP_MULTICAST or INTRA_PROCESS)
        """
        from ._native import get_lib

        self._name = name
        self._enable_discovery = enable_discovery
        self._writers: list[DataWriter] = []
        self._readers: list[DataReader] = []
        self._publishers: list[Publisher] = []
        self._subscribers: list[Subscriber] = []

        lib = get_lib()

        # If discovery is disabled, force INTRA_PROCESS transport
        # (no FFI toggle for discovery - transport mode controls it)
        if not enable_discovery:
            transport = TransportMode.INTRA_PROCESS

        cfg = lib.hdds_config_create(name.encode('utf-8'))
        if not cfg:
            raise RuntimeError(f"Failed to create config for '{name}'")
        if domain_id is not None:
            lib.hdds_config_set_domain_id(cfg, domain_id)
        lib.hdds_config_set_transport_mode(cfg, int(transport))
        self._handle = lib.hdds_config_build(cfg)
        if not self._handle:
            # An explicit domain_id never reads HDDS_DOMAIN_ID.
            env_hint = "" if domain_id is not None else _bad_domain_env_suffix()
            raise RuntimeError(f"Failed to create participant '{name}'{env_hint}")
        self._domain_id = lib.hdds_participant_domain_id(self._handle)

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

    def assert_liveliness(self) -> None:
        """Manually assert this participant's liveliness (DDS v1.4 Sec.2.2.3.11).

        Renews the lease every MANUAL_BY_PARTICIPANT writer of this
        participant shares, with nothing to write. A no-op on a
        participant with no such writer yet.

        Raises:
            NotImplementedError: If the loaded libhdds_c predates 1.5.0.
            HddsException: If the native call fails.
        """
        from ._native import check_error
        from .entities import _require

        lib = _require("hdds_participant_assert_liveliness", "Participant.assert_liveliness()")
        check_error(lib.hdds_participant_assert_liveliness(self._handle))

    def create_writer(
        self,
        topic_name: str,
        msg_type: Optional[type] = None,
        qos: Optional[QoS] = None,
        type_name: Optional[str] = None,
        extensibility: Optional[str] = None,
    ) -> DataWriter:
        """
        Create a DataWriter for the given topic.

        Args:
            topic_name: Name of the topic
            msg_type: The generated class the bodies are encoded from,
                passed positionally as the natural way to create a typed
                writer (``participant.create_writer("Temperature", Temperature)``).
                A class hdds_gen 2.0 or later generated carries its
                extensibility (``HDDS_EXTENSIBILITY``), which the writer
                then uses when ``extensibility`` is None, so its samples
                are labelled right without saying it; an older class says
                nothing and keeps the earlier behaviour. A writer created
                without ``msg_type`` (or ``extensibility``) that is later
                handed a non-FINAL typed instance in ``write_typed()`` warns
                once instead of silently mislabelling every sample FINAL.
            qos: QoS configuration (default if None)
            type_name: DDS type name announced via SEDP. Default: the
                ``type_name()`` of ``msg_type`` when given (a class of an older
                hdds_gen says none and announces "RawBytes"); without
                ``msg_type`` the writer has no type of its own and adopts the
                name its topic's readers announce, else "RawBytes" (creation
                blocks up to HDDS_TYPE_ADOPT_WAIT_MS when that is set).
                       Must match the remote reader's type name for interop.
            extensibility: "final", "appendable" or "mutable", the
                extensibility of the IDL type the bodies are encoded from
                (hdds_gen makes a type without an annotation APPENDABLE).
                The encapsulation identifier of every sample names it
                (DDS-XTypes 1.3 Table 60: D_CDR2_LE for appendable,
                PL_CDR2_LE for mutable); None labels every body FINAL
                (CDR2_LE), as earlier releases did, unless ``msg_type``
                says it.

        Returns:
            DataWriter for publishing

        Example:
            >>> writer = participant.create_writer("Temperature", Temperature,
            ...     qos=QoS.reliable().transient_local())
        """
        from ._native import get_lib

        if isinstance(msg_type, QoS):
            # Releases before 1.5 took the QoS as the second positional
            # argument; keep such calls working instead of silently
            # dropping their QoS.
            if qos is not None:
                raise TypeError("create_writer() got a QoS both positionally and as qos=")
            qos, msg_type = msg_type, None

        if qos is None:
            qos = QoS.default()

        lib = get_lib()
        qos_handle = qos._c_handle if qos else None
        code = writer_extensibility(extensibility, msg_type)
        keyed = code is not None and _has_key_codec(msg_type)
        # An endpoint created for a type announces that type's name, never a
        # peer's; only an endpoint with no type adopts (type_name stays None).
        type_name = endpoint_type_name(type_name, msg_type)
        if code is not None:
            symbol = "hdds_writer_create_keyed" if keyed else "hdds_writer_create_with_extensibility"
            if not hasattr(lib, symbol):
                raise RuntimeError("this libhdds_c cannot label a writer's extensibility")
            function = getattr(lib, symbol)
            function.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32]
            function.restype = ctypes.c_void_p
            handle = function(
                self._handle,
                topic_name.encode('utf-8'),
                type_name.encode('utf-8') if type_name is not None else None,
                qos_handle,
                code,
            )
        elif type_name is not None:
            handle = lib.hdds_writer_create_with_type(
                self._handle,
                topic_name.encode('utf-8'),
                type_name.encode('utf-8'),
                qos_handle,
            )
        elif qos_handle:
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
            raise _creation_error("writer", topic_name, qos)

        writer = DataWriter._from_handle(
            topic_name, handle, qos, extensibility_known=(code is not None),
            keyed_type=msg_type if keyed else None
        )
        self._writers.append(writer)
        return writer

    def create_reader(
        self,
        topic_name: str,
        qos: Optional[QoS] = None,
        type_name: Optional[str] = None,
        msg_type: Optional[type] = None,
    ) -> DataReader:
        """
        Create a DataReader for the given topic.

        Args:
            topic_name: Name of the topic
            qos: QoS configuration (default if None)
            type_name: DDS type name announced via SEDP. Default: the
                ``type_name()`` of ``msg_type`` when given (a class of an older
                hdds_gen says none and announces "RawBytes"); without
                ``msg_type`` the reader has no type of its own and adopts the
                name its topic's writers announce, else "RawBytes" (creation
                blocks up to HDDS_TYPE_ADOPT_WAIT_MS when that is set).
                       Must match the remote writer's type name for interop.
            msg_type: The generated class the samples are decoded with
                (``take_typed``). One that decodes XCDR1 too
                (``decode_by_encapsulation``, hdds_gen 2.0) makes the reader
                request XCDR as well as XCDR2 (DDS-XTypes 1.3 7.6.3.1.1)
                when ``qos`` sets no DATA_REPRESENTATION, so a default
                writer, which offers XCDR, reaches it. Without it, or with an
                older class, the reader requests XCDR2 only.

        Returns:
            DataReader for subscribing

        Example:
            >>> reader = participant.create_reader("Temperature",
            ...     qos=QoS.reliable())
            >>> data = reader.take()
        """
        from ._native import get_lib

        from .entities import reader_qos_for

        if qos is None:
            qos = QoS.default()
        qos = reader_qos_for(msg_type, qos)
        type_name = endpoint_type_name(type_name, msg_type)

        lib = get_lib()
        qos_handle = qos._c_handle if qos else None
        if type_name is not None:
            handle = lib.hdds_reader_create_with_type(
                self._handle,
                topic_name.encode('utf-8'),
                type_name.encode('utf-8'),
                qos_handle,
            )
        elif qos_handle:
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
            raise _creation_error("reader", topic_name, qos)

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

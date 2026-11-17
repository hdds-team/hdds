# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS QoS (Quality of Service) configuration.

Provides a fluent builder API for configuring all 22 DDS QoS policies.
QoS profiles can be created from preset factory methods, loaded from
XML profile files (FastDDS format), or built up incrementally with
the chaining builder pattern.

Factory methods:
    - ``QoS.default()`` -- BestEffort, Volatile, KeepLast(100).
    - ``QoS.reliable()`` -- Reliable delivery with NACK-based retransmission.
    - ``QoS.best_effort()`` -- Fire-and-forget, lowest overhead.
    - ``QoS.rti_defaults()`` -- Interoperability preset: Reliable, Volatile, KeepLast(10).
    - ``QoS.from_file(path)`` -- Load from XML profile (auto-detect vendor).

Example::

    qos = (QoS.reliable()
           .transient_local()
           .history_depth(10)
           .deadline_ms(100)
           .partition("sensors"))
    writer = participant.create_writer("Temperature", qos=qos)

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

from __future__ import annotations
from enum import Enum, auto
from typing import Optional, List, TYPE_CHECKING
import ctypes

if TYPE_CHECKING:
    from ._native import ctypes

#: LENGTH_UNLIMITED as the C ABI encodes it for RESOURCE_LIMITS (``size_t``).
SIZE_MAX = ctypes.c_size_t(-1).value
#: "Infinite" as the C ABI encodes durations in nanoseconds (``uint64_t``).
UINT64_MAX = ctypes.c_uint64(-1).value


class Reliability(Enum):
    """Reliability QoS kind.

    Attributes:
        BEST_EFFORT: No delivery guarantee; lowest overhead.
        RELIABLE: Guaranteed delivery with NACK-driven retransmission.
    """
    BEST_EFFORT = auto()
    RELIABLE = auto()


class Durability(Enum):
    """Durability QoS kind.

    Controls whether data is cached for late-joining readers.

    Attributes:
        VOLATILE: No caching; data is lost once sent.
        TRANSIENT_LOCAL: Data cached in writer memory for late joiners.
    """
    VOLATILE = auto()
    TRANSIENT_LOCAL = auto()


class LivelinessKind(Enum):
    """Liveliness QoS kind.

    Controls how the DDS infrastructure determines whether an entity is alive.

    Attributes:
        AUTOMATIC: Infrastructure automatically asserts liveliness.
        MANUAL_BY_PARTICIPANT: Application must assert per participant.
        MANUAL_BY_TOPIC: Application must assert per writer/topic.
    """
    AUTOMATIC = 0
    MANUAL_BY_PARTICIPANT = 1
    MANUAL_BY_TOPIC = 2


class OwnershipKind(Enum):
    """Ownership QoS kind.

    Attributes:
        SHARED: Multiple writers can update the same instance.
        EXCLUSIVE: Only the writer with the highest strength can update.
    """
    SHARED = auto()
    EXCLUSIVE = auto()


class QoS:
    """
    DDS Quality of Service configuration.

    Use factory methods for common profiles:
        - QoS.default() - BestEffort, Volatile
        - QoS.reliable() - Reliable delivery
        - QoS.best_effort() - Fire-and-forget
        - QoS.rti_defaults() - Interoperability preset (Reliable, Volatile, KeepLast(10))

    Example:
        >>> qos = QoS.reliable().transient_local().history_depth(10)
        >>> qos = QoS.from_file("fastdds_profile.xml")
    """

    def __init__(self, _handle: Optional[ctypes.c_void_p] = None):
        """Create QoS. Use factory methods instead."""
        self._handle = _handle
        self._owned = _handle is None  # Track if we own the handle

        if self._handle is None:
            from ._native import get_lib
            lib = get_lib()
            self._handle = lib.hdds_qos_default()
            self._owned = True

    def __del__(self):
        """Clean up native handle."""
        if self._owned and self._handle:
            try:
                from ._native import get_lib
                lib = get_lib()
                lib.hdds_qos_destroy(self._handle)
            except Exception:
                pass  # Ignore errors during cleanup
            self._handle = None

    @classmethod
    def default(cls) -> QoS:
        """Create default QoS (BestEffort, Volatile, KeepLast(100))."""
        from ._native import get_lib
        lib = get_lib()
        handle = lib.hdds_qos_default()
        qos = cls.__new__(cls)
        qos._handle = handle
        qos._owned = True
        return qos

    @classmethod
    def reliable(cls) -> QoS:
        """Create Reliable QoS with NACK-driven retransmission."""
        from ._native import get_lib
        lib = get_lib()
        handle = lib.hdds_qos_reliable()
        qos = cls.__new__(cls)
        qos._handle = handle
        qos._owned = True
        return qos

    @classmethod
    def best_effort(cls) -> QoS:
        """Create BestEffort QoS (fire-and-forget)."""
        from ._native import get_lib
        lib = get_lib()
        handle = lib.hdds_qos_best_effort()
        qos = cls.__new__(cls)
        qos._handle = handle
        qos._owned = True
        return qos

    @classmethod
    def rti_defaults(cls) -> QoS:
        """Create the interoperability QoS preset (Reliable, Volatile, KeepLast(10))."""
        from ._native import get_lib
        lib = get_lib()
        handle = lib.hdds_qos_rti_defaults()
        qos = cls.__new__(cls)
        qos._handle = handle
        qos._owned = True
        return qos

    @classmethod
    def from_file(cls, path: str) -> QoS:
        """
        Load QoS from XML profile file.

        Supports FastDDS and other vendor XML formats.
        Vendor is auto-detected from XML structure.

        **Note:** This method requires the ``qos-loaders`` Cargo feature to be
        enabled when building HDDS. If not available, raises ``NotImplementedError``.

        ``qos-loaders`` is a default feature of the ``hdds-c`` crate, so
        the documented build command already enables it::

            cargo build --release -p hdds-c

        Args:
            path: Path to XML profile file (FastDDS, etc.)

        Returns:
            QoS configured from file

        Raises:
            NotImplementedError: If qos-loaders feature is not enabled
            FileNotFoundError: If file doesn't exist
            ValueError: If file cannot be parsed

        Example:
            >>> qos = QoS.from_file("fastdds_profile.xml")
            >>> writer = participant.create_writer("topic", qos)
        """
        # Check if qos-loaders feature is available
        from ._native import get_lib
        lib = get_lib()

        # Try auto-detect vendor format first (hdds_qos_from_xml)
        if hasattr(lib, 'hdds_qos_from_xml'):
            handle = lib.hdds_qos_from_xml(path.encode('utf-8'))
            if handle:
                qos = cls.__new__(cls)
                qos._handle = handle
                qos._owned = True
                return qos
            raise ValueError(f"Failed to load QoS from {path}")

        # Fall back to FastDDS-specific loader
        if hasattr(lib, 'hdds_qos_load_fastdds_xml'):
            handle = lib.hdds_qos_load_fastdds_xml(path.encode('utf-8'))
            if handle:
                qos = cls.__new__(cls)
                qos._handle = handle
                qos._owned = True
                return qos
            raise ValueError(f"Failed to load QoS from {path}")

        raise NotImplementedError("QoS.from_file() requires qos-loaders feature")

    @classmethod
    def from_fastdds_xml(cls, path: str) -> QoS:
        """
        Load QoS from a FastDDS XML profile file.

        Uses the FastDDS-specific parser directly. For auto-detection
        of vendor format, use ``QoS.from_file()`` instead.

        **Note:** Requires the ``qos-loaders`` Cargo feature.

        Args:
            path: Path to FastDDS XML profile file

        Returns:
            QoS configured from file

        Raises:
            NotImplementedError: If qos-loaders feature is not enabled
            ValueError: If file cannot be parsed
        """
        from ._native import get_lib
        lib = get_lib()

        if not hasattr(lib, 'hdds_qos_load_fastdds_xml'):
            raise NotImplementedError(
                "QoS.from_fastdds_xml() requires qos-loaders feature"
            )

        handle = lib.hdds_qos_load_fastdds_xml(path.encode('utf-8'))
        if not handle:
            raise ValueError(f"Failed to load FastDDS QoS from {path}")

        qos = cls.__new__(cls)
        qos._handle = handle
        qos._owned = True
        return qos

    def clone(self) -> QoS:
        """Create an independent deep copy of this QoS profile.

        Returns:
            A new QoS instance with the same settings.
        """
        from ._native import get_lib
        lib = get_lib()
        handle = lib.hdds_qos_clone(self._handle)
        if not handle:
            raise RuntimeError("Failed to clone QoS handle")
        qos = QoS.__new__(QoS)
        qos._handle = handle
        qos._owned = True
        return qos

    # -------------------------------------------------------------------------
    # Fluent builder methods
    # -------------------------------------------------------------------------

    XCDR_DATA_REPRESENTATION = 0
    """DDS-XTypes 1.3 7.6.3.1.1: XCDR encoding version 1."""
    XCDR2_DATA_REPRESENTATION = 2
    """XCDR encoding version 2."""

    def data_representation(self, *ids: int) -> QoS:
        """Set DATA_REPRESENTATION (DDS-XTypes 1.3 7.6.3.1.1).

        ``ids`` in order, XCDR (0) and XCDR2 (2) only. A writer offers the
        first one; a reader requests them all. No argument clears the list:
        a writer or reader then offers and requests XCDR2. A reader created
        with ``msg_type`` set to a class that decodes XCDR1 too
        (``decode_by_encapsulation``) requests both when the list is empty.

        Raises:
            HddsException: An identifier other than 0 or 2.
            RuntimeError: The native library has no DATA_REPRESENTATION
                setter.
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        if not hasattr(lib, 'hdds_qos_set_data_representation'):
            raise RuntimeError("this libhdds_c has no DATA_REPRESENTATION setter")
        array = (ctypes.c_int16 * max(len(ids), 1))(*ids)
        check_error(lib.hdds_qos_set_data_representation(self._handle, array, len(ids)))
        return self

    def get_data_representation(self) -> List[int]:
        """The DATA_REPRESENTATION list ([] when none is set)."""
        from ._native import get_lib, check_error
        lib = get_lib()
        if not hasattr(lib, 'hdds_qos_get_data_representation'):
            return []
        array = (ctypes.c_int16 * 8)()
        count = ctypes.c_size_t(0)
        check_error(lib.hdds_qos_get_data_representation(
            self._handle, array, 8, ctypes.byref(count)))
        return list(array[:min(count.value, 8)])

    def transient_local(self) -> QoS:
        """Set durability to TRANSIENT_LOCAL (late-joiner support)."""
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_transient_local(self._handle))
        return self

    def volatile(self) -> QoS:
        """Set durability to VOLATILE (no caching)."""
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_volatile(self._handle))
        return self

    def history_depth(self, depth: int) -> QoS:
        """Set history depth (KEEP_LAST policy).

        Args:
            depth: Number of samples to keep per instance.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_history_depth(self._handle, depth))
        return self

    def history_keep_all(self) -> QoS:
        """Set history to KEEP_ALL (unbounded)."""
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_history_keep_all(self._handle))
        return self

    def persistent(self) -> QoS:
        """Set durability to PERSISTENT (disk storage)."""
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_persistent(self._handle))
        return self

    def set_reliable(self) -> QoS:
        """Switch to RELIABLE delivery."""
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_reliable(self._handle))
        return self

    def set_best_effort(self) -> QoS:
        """Switch to BEST_EFFORT delivery."""
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_best_effort(self._handle))
        return self

    def deadline_ms(self, milliseconds: int) -> QoS:
        """Set deadline period in milliseconds.

        The deadline defines the maximum expected interval between successive
        data samples. Missing a deadline triggers a deadline missed event.

        Args:
            milliseconds: Deadline period in milliseconds.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_deadline_ns(self._handle, milliseconds * 1_000_000))
        return self

    def deadline_secs(self, seconds: int) -> QoS:
        """Set deadline period in seconds.

        Args:
            seconds: Deadline period in seconds.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_deadline_ns(self._handle, seconds * 1_000_000_000))
        return self

    def lifespan_ms(self, milliseconds: int) -> QoS:
        """Set lifespan duration in milliseconds.

        Samples older than the lifespan are automatically discarded.

        Args:
            milliseconds: Lifespan duration in milliseconds.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_lifespan_ns(self._handle, milliseconds * 1_000_000))
        return self

    def lifespan_secs(self, seconds: int) -> QoS:
        """Set lifespan duration in seconds.

        Args:
            seconds: Lifespan duration in seconds.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_lifespan_ns(self._handle, seconds * 1_000_000_000))
        return self

    def max_blocking_time_ms(self, milliseconds: int) -> QoS:
        """Set RELIABILITY max_blocking_time in milliseconds (DDS v1.4 Sec.2.2.3.14).

        How long a RELIABLE writer's ``write()`` may block for room before it
        raises due to a timeout. Default 100 ms, the DDS spec's default.
        Ignored by BEST_EFFORT writers.

        Args:
            milliseconds: Maximum blocking time in milliseconds.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_max_blocking_time_ns(
            self._handle, milliseconds * 1_000_000))
        return self

    def max_blocking_time_secs(self, seconds: int) -> QoS:
        """Set RELIABILITY max_blocking_time in seconds (DDS v1.4 Sec.2.2.3.14).

        Args:
            seconds: Maximum blocking time in seconds.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_max_blocking_time_ns(
            self._handle, seconds * 1_000_000_000))
        return self

    def liveliness_automatic(self, lease_secs: float) -> QoS:
        """Set liveliness to AUTOMATIC with given lease duration.

        The DDS infrastructure automatically asserts liveliness at the
        configured rate.

        Args:
            lease_secs: Lease duration in seconds (fractional allowed).

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_liveliness_automatic_ns(
            self._handle, int(lease_secs * 1_000_000_000)))
        return self

    def liveliness_manual_participant(self, lease_secs: float) -> QoS:
        """Set liveliness to MANUAL_BY_PARTICIPANT with given lease duration.

        The application must explicitly assert liveliness for the participant.

        Args:
            lease_secs: Lease duration in seconds (fractional allowed).

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_liveliness_manual_participant_ns(
            self._handle, int(lease_secs * 1_000_000_000)))
        return self

    def liveliness_manual_topic(self, lease_secs: float) -> QoS:
        """Set liveliness to MANUAL_BY_TOPIC with given lease duration.

        The application must explicitly assert liveliness per writer/topic.

        Args:
            lease_secs: Lease duration in seconds (fractional allowed).

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_liveliness_manual_topic_ns(
            self._handle, int(lease_secs * 1_000_000_000)))
        return self

    def ownership_shared(self) -> QoS:
        """Set ownership to SHARED (multiple writers allowed)."""
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_ownership_shared(self._handle))
        return self

    def ownership_exclusive(self, strength: int) -> QoS:
        """Set ownership to EXCLUSIVE with given strength.

        Only the writer with the highest ownership strength can update
        a given instance. Other writers are silently ignored.

        Args:
            strength: Ownership strength value (higher wins).

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_ownership_exclusive(self._handle, strength))
        return self

    def partition(self, name: str) -> QoS:
        """Add a partition name for logical isolation.

        Only endpoints sharing at least one partition name can communicate.
        Can be called multiple times to add multiple partitions.

        Args:
            name: Partition name string.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_add_partition(self._handle, name.encode('utf-8')))
        return self

    def time_based_filter_ms(self, milliseconds: int) -> QoS:
        """Set time-based filter minimum separation in milliseconds.

        Limits the rate at which samples are delivered to the reader.
        Samples arriving faster than the minimum separation are dropped.

        Args:
            milliseconds: Minimum time between delivered samples.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_time_based_filter_ns(
            self._handle, milliseconds * 1_000_000))
        return self

    def latency_budget_ms(self, milliseconds: int) -> QoS:
        """Set latency budget hint in milliseconds.

        Informs the middleware of the maximum acceptable delay from writing
        to delivery. This is a hint, not a guarantee.

        Args:
            milliseconds: Latency budget in milliseconds.

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_latency_budget_ns(
            self._handle, milliseconds * 1_000_000))
        return self

    def transport_priority(self, priority: int) -> QoS:
        """Set transport priority for network QoS mechanisms.

        Higher values indicate higher priority. The effective behavior
        depends on network infrastructure (DSCP marking, traffic shaping).

        Args:
            priority: Transport priority value (higher = more important).

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        check_error(lib.hdds_qos_set_transport_priority(self._handle, priority))
        return self

    def resource_limits(
        self,
        max_samples: int = -1,
        max_instances: int = -1,
        max_samples_per_instance: int = -1,
    ) -> QoS:
        """Set resource limits on the entity.

        Controls the maximum resources consumed by a DataReader or DataWriter.

        Args:
            max_samples: Maximum total samples across all instances (-1 = unlimited).
            max_instances: Maximum number of instances (-1 = unlimited).
            max_samples_per_instance: Maximum samples per instance (-1 = unlimited).

        Returns:
            self (for chaining).
        """
        from ._native import get_lib, check_error
        lib = get_lib()
        # -1 means LENGTH_UNLIMITED, which the C ABI encodes as SIZE_MAX. It
        # must be SIZE_MAX exactly: any other large value (2**63 - 1, say) is
        # a finite limit that takes part in the consistency checks, so
        # max_samples=500 alone would be refused as smaller than
        # max_samples_per_instance.
        ms = SIZE_MAX if max_samples < 0 else max_samples
        mi = SIZE_MAX if max_instances < 0 else max_instances
        mspi = SIZE_MAX if max_samples_per_instance < 0 else max_samples_per_instance
        check_error(lib.hdds_qos_set_resource_limits(self._handle, ms, mi, mspi))
        return self

    # -------------------------------------------------------------------------
    # Inspection methods
    # -------------------------------------------------------------------------

    def is_reliable(self) -> bool:
        """Check if reliability is RELIABLE.

        Returns:
            True if reliable, False if best-effort.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_is_reliable(self._handle)

    def is_transient_local(self) -> bool:
        """Check if durability is TRANSIENT_LOCAL.

        Returns:
            True if transient-local, False otherwise.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_is_transient_local(self._handle)

    def is_ownership_exclusive(self) -> bool:
        """Check if ownership is EXCLUSIVE.

        Returns:
            True if exclusive, False if shared.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_is_ownership_exclusive(self._handle)

    def get_history_depth(self) -> int:
        """Get history depth (KEEP_LAST count).

        Returns:
            Number of samples kept per instance.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_history_depth(self._handle)

    def get_deadline_ns(self) -> int:
        """Get deadline period in nanoseconds.

        Returns:
            Deadline in nanoseconds. UINT64_MAX means infinite (no deadline).
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_deadline_ns(self._handle)

    def get_lifespan_ns(self) -> int:
        """Get lifespan duration in nanoseconds.

        Returns:
            Lifespan in nanoseconds. UINT64_MAX means infinite (no expiry).
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_lifespan_ns(self._handle)

    def get_max_blocking_time_ns(self) -> int:
        """Get RELIABILITY max_blocking_time in nanoseconds (DDS v1.4 Sec.2.2.3.14).

        Returns:
            Max blocking time in nanoseconds. Default 100_000_000 (100 ms).
            UINT64_MAX means infinite.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_max_blocking_time_ns(self._handle)

    def get_ownership_strength(self) -> int:
        """Get ownership strength value.

        Returns:
            Ownership strength (meaningful only when ownership is EXCLUSIVE).
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_ownership_strength(self._handle)

    def get_liveliness_kind(self) -> LivelinessKind:
        """Get liveliness kind.

        Returns:
            LivelinessKind enum value (AUTOMATIC, MANUAL_BY_PARTICIPANT, or MANUAL_BY_TOPIC).
        """
        from ._native import get_lib
        lib = get_lib()
        value = lib.hdds_qos_get_liveliness_kind(self._handle)
        return LivelinessKind(value)

    def get_liveliness_lease_ns(self) -> int:
        """Get liveliness lease duration in nanoseconds.

        Returns:
            Lease duration in nanoseconds. UINT64_MAX means infinite.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_liveliness_lease_ns(self._handle)

    def get_transport_priority(self) -> int:
        """Get transport priority value.

        Returns:
            Transport priority (higher values indicate higher priority).
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_transport_priority(self._handle)

    def get_time_based_filter_ns(self) -> int:
        """Get time-based filter minimum separation in nanoseconds.

        Returns:
            Minimum separation in nanoseconds. 0 means no filtering.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_time_based_filter_ns(self._handle)

    def get_latency_budget_ns(self) -> int:
        """Get latency budget in nanoseconds.

        Returns:
            Latency budget in nanoseconds. 0 means no latency budget set.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_latency_budget_ns(self._handle)

    def get_max_samples(self) -> int:
        """Get max samples resource limit.

        Returns:
            Maximum number of samples, or ``SIZE_MAX`` for unlimited.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_max_samples(self._handle)

    def get_max_instances(self) -> int:
        """Get max instances resource limit.

        Returns:
            Maximum number of instances, or ``SIZE_MAX`` for unlimited.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_max_instances(self._handle)

    def get_max_samples_per_instance(self) -> int:
        """Get max samples per instance resource limit.

        Returns:
            Maximum samples per instance, or ``SIZE_MAX`` for unlimited.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_max_samples_per_instance(self._handle)

    @property
    def _c_handle(self) -> ctypes.c_void_p:
        """Internal: get C handle for FFI calls."""
        return self._handle

    def consistency_problems(self) -> List[str]:
        """List the HISTORY / RESOURCE_LIMITS consistency rules this QoS breaks.

        These are the rules DDS 1.4 attaches to the two policies (2.2.3.18 and
        2.2.3.19); breaking one makes the creation of a writer or reader fail:
        every limit must be > 0 or unlimited,
        ``max_samples >= max_samples_per_instance`` and, for KEEP_LAST,
        ``depth <= max_samples_per_instance``. An unlimited value takes part in
        no comparison.

        The native library is the authority (it is the one that refuses the
        entity); this method only explains a refusal. An empty list means none
        of these rules is broken.

        Example:
            >>> QoS.default().resource_limits(max_samples_per_instance=50).consistency_problems()
            ['history depth (100) must be <= resource_limits max_samples_per_instance (50)']
        """
        problems: List[str] = []
        limits = (
            ("max_samples", self.get_max_samples()),
            ("max_instances", self.get_max_instances()),
            ("max_samples_per_instance", self.get_max_samples_per_instance()),
        )
        for name, value in limits:
            if value == 0:
                problems.append(f"resource_limits {name} must be > 0 or unlimited (-1)")
        total, per_instance = limits[0][1], limits[2][1]
        if total != SIZE_MAX and per_instance != SIZE_MAX and total < per_instance:
            problems.append(
                f"resource_limits max_samples ({total}) must be >= "
                f"max_samples_per_instance ({per_instance})"
            )
        depth = self.get_history_depth()  # 0 for KEEP_ALL
        if depth and per_instance != SIZE_MAX and depth > per_instance:
            problems.append(
                f"history depth ({depth}) must be <= "
                f"resource_limits max_samples_per_instance ({per_instance})"
            )
        return problems

    def _non_default_policies(self) -> List[str]:
        """Describe every inspectable policy that differs from QoS.default()."""
        default = QoS.default()
        parts: List[str] = []

        def duration(ns: int) -> str:
            if ns == UINT64_MAX:
                return "infinite"
            if ns % 1_000_000 == 0:
                return f"{ns // 1_000_000}ms"
            return f"{ns}ns"

        def limit(value: int) -> str:
            return "unlimited" if value == SIZE_MAX else str(value)

        if self.get_deadline_ns() != default.get_deadline_ns():
            parts.append(f"deadline={duration(self.get_deadline_ns())}")
        if self.get_lifespan_ns() != default.get_lifespan_ns():
            parts.append(f"lifespan={duration(self.get_lifespan_ns())}")
        if self.get_max_blocking_time_ns() != default.get_max_blocking_time_ns():
            parts.append(f"max_blocking_time={duration(self.get_max_blocking_time_ns())}")
        if self.get_latency_budget_ns() != default.get_latency_budget_ns():
            parts.append(f"latency_budget={duration(self.get_latency_budget_ns())}")
        if self.get_time_based_filter_ns() != default.get_time_based_filter_ns():
            parts.append(f"time_based_filter={duration(self.get_time_based_filter_ns())}")
        if (self.get_liveliness_kind() != default.get_liveliness_kind()
                or self.get_liveliness_lease_ns() != default.get_liveliness_lease_ns()):
            parts.append(
                f"liveliness={self.get_liveliness_kind().name.lower()}"
                f"/{duration(self.get_liveliness_lease_ns())}"
            )
        if self.is_ownership_exclusive():
            parts.append(f"ownership=exclusive(strength={self.get_ownership_strength()})")
        if self.get_transport_priority() != default.get_transport_priority():
            parts.append(f"transport_priority={self.get_transport_priority()}")
        limits = (self.get_max_samples(), self.get_max_instances(),
                  self.get_max_samples_per_instance())
        default_limits = (default.get_max_samples(), default.get_max_instances(),
                          default.get_max_samples_per_instance())
        if limits != default_limits:
            parts.append(
                "resource_limits(max_samples={}, max_instances={}, "
                "max_samples_per_instance={})".format(*(limit(v) for v in limits))
            )
        return parts

    def __repr__(self) -> str:
        """Reliability, durability, history, then every inspectable policy
        that differs from ``QoS.default()``.

        Partition and the PERSISTENT durability kind have no getter in the C
        API and cannot be shown (PERSISTENT reads as ``volatile`` here, since
        ``is_transient_local()`` is the only durability query).
        """
        reliable = "reliable" if self.is_reliable() else "best_effort"
        durability = "transient_local" if self.is_transient_local() else "volatile"
        depth = self.get_history_depth()
        history = "keep_all" if depth == 0 else f"depth={depth}"
        parts = [reliable, durability, history] + self._non_default_policies()
        return f"QoS({', '.join(parts)})"

    __str__ = __repr__

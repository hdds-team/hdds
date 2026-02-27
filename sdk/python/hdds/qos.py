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
    - ``QoS.rti_defaults()`` -- RTI Connext DDS 6.x compatible defaults.
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
        - QoS.rti_defaults() - RTI Connext compatible

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
        """Create RTI Connext-compatible QoS defaults."""
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

        Supports FastDDS, RTI Connext, and other vendor formats.
        Vendor is auto-detected from XML structure.

        **Note:** This method requires the ``qos-loaders`` Cargo feature to be
        enabled when building HDDS. If not available, raises ``NotImplementedError``.

        To enable qos-loaders, build HDDS with::

            cargo build --features qos-loaders

        Or when using pip/maturin::

            HDDS_FEATURES=qos-loaders pip install hdds

        Args:
            path: Path to XML profile file (FastDDS, RTI Connext, etc.)

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
        qos = QoS.__new__(QoS)
        qos._handle = handle
        qos._owned = True
        return qos

    # -------------------------------------------------------------------------
    # Fluent builder methods
    # -------------------------------------------------------------------------

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
        # Convert -1 to SIZE_MAX
        import sys
        size_max = sys.maxsize
        ms = size_max if max_samples < 0 else max_samples
        mi = size_max if max_instances < 0 else max_instances
        mspi = size_max if max_samples_per_instance < 0 else max_samples_per_instance
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
            Maximum number of samples, or sys.maxsize for unlimited.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_max_samples(self._handle)

    def get_max_instances(self) -> int:
        """Get max instances resource limit.

        Returns:
            Maximum number of instances, or sys.maxsize for unlimited.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_max_instances(self._handle)

    def get_max_samples_per_instance(self) -> int:
        """Get max samples per instance resource limit.

        Returns:
            Maximum samples per instance, or sys.maxsize for unlimited.
        """
        from ._native import get_lib
        lib = get_lib()
        return lib.hdds_qos_get_max_samples_per_instance(self._handle)

    @property
    def _c_handle(self) -> ctypes.c_void_p:
        """Internal: get C handle for FFI calls."""
        return self._handle

    def __repr__(self) -> str:
        reliable = "reliable" if self.is_reliable() else "best_effort"
        durability = "transient_local" if self.is_transient_local() else "volatile"
        depth = self.get_history_depth()
        return f"QoS({reliable}, {durability}, depth={depth})"

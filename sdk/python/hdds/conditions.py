# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""HDDS ReadCondition, QueryCondition, and ContentFilteredTopic.

Provides Python bindings for DDS content filtering and condition-based
data access via the hdds-c FFI layer.

ContentFilteredTopic:
    Filtered view of a topic using SQL-like expressions. Only samples
    matching the filter are delivered to readers.

ReadCondition:
    Condition based on DataReader sample/view/instance state masks.

QueryCondition:
    ReadCondition extended with a SQL-like content query.

Example:
    >>> with hdds.Participant("my_app") as p:
    ...     # ContentFilteredTopic
    ...     cft = p.create_content_filtered_topic(
    ...         "high_temp", "sensors/temperature",
    ...         "value > %0", ["25.0"])
    ...     reader = cft.create_reader(p)
    ...
    ...     # ReadCondition
    ...     cond = ReadCondition(reader,
    ...         sample_state=SampleState.NOT_READ,
    ...         view_state=ViewState.ANY,
    ...         instance_state=InstanceState.ALIVE)

SPDX-License-Identifier: Apache-2.0 OR MIT
Copyright (c) 2025-2026 naskel.com
"""

from __future__ import annotations
from typing import Optional, List, TYPE_CHECKING
import ctypes

if TYPE_CHECKING:
    from .participant import Participant
    from .entities import DataReader
    from .qos import QoS


# =============================================================================
# State mask constants
# =============================================================================

class SampleState:
    """Sample state mask constants for ReadCondition.

    Attributes:
        READ: Sample has been read.
        NOT_READ: Sample has not been read.
        ANY: Any sample state.
    """
    READ = 0x01
    NOT_READ = 0x02
    ANY = 0x03


class ViewState:
    """View state mask constants for ReadCondition.

    Attributes:
        NEW: Instance is new (first sample).
        NOT_NEW: Instance is not new (subsequent samples).
        ANY: Any view state.
    """
    NEW = 0x01
    NOT_NEW = 0x02
    ANY = 0x03


class InstanceState:
    """Instance state mask constants for ReadCondition.

    Attributes:
        ALIVE: Instance is alive (writer exists).
        NOT_ALIVE_DISPOSED: Instance writer has disposed.
        NOT_ALIVE_NO_WRITERS: Instance writer has lost liveliness.
        ANY: Any instance state.
    """
    ALIVE = 0x01
    NOT_ALIVE_DISPOSED = 0x02
    NOT_ALIVE_NO_WRITERS = 0x04
    ANY = 0x07


# =============================================================================
# ContentFilteredTopic
# =============================================================================

class ContentFilteredTopic:
    """Filtered view of a DDS topic using SQL-like expressions.

    Only samples matching the filter expression are delivered to readers
    created from this filtered topic.

    Created via ``Participant.create_content_filtered_topic()``.

    Example:
        >>> cft = participant.create_content_filtered_topic(
        ...     "high_temp", "sensors/temperature",
        ...     "value > %0", ["25.0"])
        >>> reader = cft.create_reader(participant)
    """

    def __init__(
        self,
        name: str,
        related_topic: str,
        filter_expression: str,
        handle: ctypes.c_void_p,
    ):
        self._name = name
        self._related_topic = related_topic
        self._filter_expression = filter_expression
        self._handle = handle

    @property
    def name(self) -> str:
        """Get the filtered topic name."""
        return self._name

    @property
    def related_topic_name(self) -> str:
        """Get the related (underlying) topic name."""
        return self._related_topic

    @property
    def filter_expression(self) -> str:
        """Get the SQL-like filter expression."""
        return self._filter_expression

    def create_reader(
        self,
        participant: Participant,
        qos: Optional[QoS] = None,
    ) -> DataReader:
        """Create a DataReader from this ContentFilteredTopic.

        The reader only receives samples matching the filter expression.

        Args:
            participant: Participant that owns the reader.
            qos: QoS configuration (default if None).

        Returns:
            DataReader filtered by this topic's expression.

        Raises:
            RuntimeError: If reader creation fails.
        """
        from ._native import get_lib
        from .entities import DataReader

        lib = get_lib()
        qos_handle = qos._c_handle if qos else None
        handle = lib.hdds_create_reader_filtered(
            participant._handle,
            self._handle,
            qos_handle,
        )
        if not handle:
            raise RuntimeError(
                f"Failed to create filtered reader for topic '{self._related_topic}'"
            )

        return DataReader._from_handle(self._related_topic, handle, qos)

    def set_expression_parameters(self, params: List[str]) -> None:
        """Set new expression parameters at runtime.

        Allows changing filter thresholds without recreating the topic.

        Args:
            params: New parameter values for %0, %1, etc.
        """
        from ._native import get_lib

        lib = get_lib()
        if params:
            c_params = (ctypes.c_char_p * len(params))(
                *[p.encode('utf-8') for p in params]
            )
            lib.hdds_content_filtered_topic_set_params(
                self._handle, c_params, len(params)
            )
        else:
            lib.hdds_content_filtered_topic_set_params(
                self._handle, None, 0
            )

    def close(self) -> None:
        """Delete the ContentFilteredTopic and free resources."""
        from ._native import get_lib

        if self._handle:
            lib = get_lib()
            lib.hdds_content_filtered_topic_delete(self._handle)
            self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return (
            f"ContentFilteredTopic(name={self._name!r}, "
            f"related={self._related_topic!r}, "
            f"filter={self._filter_expression!r})"
        )


# =============================================================================
# ReadCondition
# =============================================================================

class ReadCondition:
    """Condition based on DataReader sample/view/instance state masks.

    A ReadCondition triggers when samples matching the specified state masks
    exist in the associated DataReader.

    Example:
        >>> cond = ReadCondition(reader,
        ...     sample_state=SampleState.NOT_READ,
        ...     view_state=ViewState.ANY,
        ...     instance_state=InstanceState.ALIVE)
        >>> waitset.attach_read_condition(cond)
    """

    def __init__(
        self,
        reader: DataReader,
        sample_state: int = SampleState.ANY,
        view_state: int = ViewState.ANY,
        instance_state: int = InstanceState.ANY,
    ):
        """Create a ReadCondition.

        Args:
            reader: Associated DataReader.
            sample_state: Bitmask of sample states to match.
            view_state: Bitmask of view states to match.
            instance_state: Bitmask of instance states to match.

        Raises:
            RuntimeError: If condition creation fails.
        """
        from ._native import get_lib

        lib = get_lib()
        self._handle = lib.hdds_create_read_condition(
            reader._handle,
            sample_state,
            view_state,
            instance_state,
        )
        if not self._handle:
            raise RuntimeError("Failed to create ReadCondition")

    @property
    def trigger_value(self) -> bool:
        """Get the current trigger value.

        Returns:
            True if condition is triggered, False otherwise.
        """
        from ._native import get_lib

        if not self._handle:
            return False
        lib = get_lib()
        return bool(lib.hdds_read_condition_get_trigger(self._handle))

    def close(self) -> None:
        """Delete the ReadCondition and free resources."""
        from ._native import get_lib

        if self._handle:
            lib = get_lib()
            lib.hdds_read_condition_delete(self._handle)
            self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "ReadCondition()"


# =============================================================================
# QueryCondition
# =============================================================================

class QueryCondition:
    """ReadCondition extended with SQL-like content query.

    A QueryCondition adds content-based filtering on top of the state-based
    filtering of ReadCondition.

    Example:
        >>> cond = QueryCondition(reader,
        ...     query="temperature > %0",
        ...     params=["25.0"],
        ...     sample_state=SampleState.NOT_READ)
        >>> waitset.attach_query_condition(cond)
    """

    def __init__(
        self,
        reader: DataReader,
        query: str,
        params: Optional[List[str]] = None,
        sample_state: int = SampleState.ANY,
        view_state: int = ViewState.ANY,
        instance_state: int = InstanceState.ANY,
    ):
        """Create a QueryCondition.

        Args:
            reader: Associated DataReader.
            query: SQL-like query expression (e.g., "temperature > %0").
            params: Parameter values for %0, %1, etc.
            sample_state: Bitmask of sample states to match.
            view_state: Bitmask of view states to match.
            instance_state: Bitmask of instance states to match.

        Raises:
            RuntimeError: If condition creation fails.
        """
        from ._native import get_lib

        self._query = query
        params = params or []

        lib = get_lib()
        if params:
            c_params = (ctypes.c_char_p * len(params))(
                *[p.encode('utf-8') for p in params]
            )
            self._handle = lib.hdds_create_query_condition(
                reader._handle,
                sample_state,
                view_state,
                instance_state,
                query.encode('utf-8'),
                c_params,
                len(params),
            )
        else:
            self._handle = lib.hdds_create_query_condition(
                reader._handle,
                sample_state,
                view_state,
                instance_state,
                query.encode('utf-8'),
                None,
                0,
            )
        if not self._handle:
            raise RuntimeError(f"Failed to create QueryCondition with query '{query}'")

    @property
    def query_expression(self) -> str:
        """Get the query expression string."""
        return self._query

    def close(self) -> None:
        """Delete the QueryCondition and free resources."""
        from ._native import get_lib

        if self._handle:
            lib = get_lib()
            lib.hdds_query_condition_delete(self._handle)
            self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"QueryCondition(query={self._query!r})"

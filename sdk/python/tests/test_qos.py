# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Tests for HDDS QoS module.
"""

import pytest
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestQoSCreation:
    """Test QoS creation methods."""

    def test_default_qos(self):
        """Test default QoS creation."""
        from hdds.qos import QoS

        qos = QoS.default()
        assert qos is not None
        assert not qos.is_reliable()
        assert not qos.is_transient_local()
        assert qos.get_history_depth() == 100

    def test_reliable_qos(self):
        """Test reliable QoS creation."""
        from hdds.qos import QoS

        qos = QoS.reliable()
        assert qos.is_reliable()
        assert not qos.is_transient_local()

    def test_best_effort_qos(self):
        """Test best effort QoS creation."""
        from hdds.qos import QoS

        qos = QoS.best_effort()
        assert not qos.is_reliable()

    def test_rti_defaults_qos(self):
        """Test RTI defaults QoS creation."""
        from hdds.qos import QoS

        qos = QoS.rti_defaults()
        assert qos.is_reliable()
        assert qos.get_history_depth() == 10


class TestQoSFluent:
    """Test fluent builder API."""

    def test_transient_local(self):
        """Test setting transient local."""
        from hdds.qos import QoS

        qos = QoS.default().transient_local()
        assert qos.is_transient_local()

    def test_history_depth(self):
        """Test setting history depth."""
        from hdds.qos import QoS

        qos = QoS.default().history_depth(50)
        assert qos.get_history_depth() == 50

    def test_chained_methods(self):
        """Test chaining multiple methods."""
        from hdds.qos import QoS

        qos = (QoS.reliable()
               .transient_local()
               .history_depth(25)
               .deadline_ms(100)
               .partition("test"))

        assert qos.is_reliable()
        assert qos.is_transient_local()
        assert qos.get_history_depth() == 25

    def test_ownership_exclusive(self):
        """Test setting exclusive ownership."""
        from hdds.qos import QoS

        qos = QoS.default().ownership_exclusive(50)
        assert qos.is_ownership_exclusive()
        assert qos.get_ownership_strength() == 50

    def test_ownership_shared(self):
        """Test setting shared ownership."""
        from hdds.qos import QoS

        qos = QoS.default().ownership_exclusive(10).ownership_shared()
        assert not qos.is_ownership_exclusive()

    def test_liveliness_automatic(self):
        """Test setting automatic liveliness."""
        from hdds.qos import QoS, LivelinessKind

        qos = QoS.default().liveliness_automatic(5.0)
        assert qos.get_liveliness_kind() == LivelinessKind.AUTOMATIC
        # 5 seconds = 5_000_000_000 ns
        assert qos.get_liveliness_lease_ns() == 5_000_000_000

    def test_liveliness_manual_participant(self):
        """Test setting manual-by-participant liveliness."""
        from hdds.qos import QoS, LivelinessKind

        qos = QoS.default().liveliness_manual_participant(2.5)
        assert qos.get_liveliness_kind() == LivelinessKind.MANUAL_BY_PARTICIPANT

    def test_transport_priority(self):
        """Test setting transport priority."""
        from hdds.qos import QoS

        qos = QoS.default().transport_priority(42)
        assert qos.get_transport_priority() == 42


class TestQoSClone:
    """Test QoS cloning."""

    def test_clone(self):
        """Test cloning QoS."""
        from hdds.qos import QoS

        original = QoS.reliable().transient_local().history_depth(77)
        cloned = original.clone()

        # Verify cloned values match
        assert cloned.is_reliable()
        assert cloned.is_transient_local()
        assert cloned.get_history_depth() == 77

        # Verify independent - modifying clone doesn't affect original
        cloned.history_depth(10)
        assert original.get_history_depth() == 77
        assert cloned.get_history_depth() == 10


class TestQoSRepr:
    """Test QoS string representation."""

    def test_repr_default(self):
        """Test repr for default QoS."""
        from hdds.qos import QoS

        qos = QoS.default()
        repr_str = repr(qos)
        assert "best_effort" in repr_str
        assert "volatile" in repr_str

    def test_repr_reliable_transient(self):
        """Test repr for reliable transient-local QoS."""
        from hdds.qos import QoS

        qos = QoS.reliable().transient_local()
        repr_str = repr(qos)
        assert "reliable" in repr_str
        assert "transient_local" in repr_str


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

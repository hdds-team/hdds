# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Tests for HDDS QoS module.
"""

import pytest
import sys
import time
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Every test here talks to the native library (per-test gate in conftest.py).
pytestmark = pytest.mark.native


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
        """Test rti_defaults() QoS preset creation."""
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

    def test_max_blocking_time_default_is_100ms(self):
        """DDS v1.4 Sec.2.2.3.14: the default max_blocking_time is 100 ms."""
        from hdds.qos import QoS

        for qos in (QoS.default(), QoS.reliable(), QoS.best_effort(), QoS.rti_defaults()):
            assert qos.get_max_blocking_time_ns() == 100_000_000

    def test_max_blocking_time_ms(self):
        """Test setting max_blocking_time in milliseconds."""
        from hdds.qos import QoS

        qos = QoS.reliable().max_blocking_time_ms(300)
        assert qos.get_max_blocking_time_ns() == 300_000_000

    def test_max_blocking_time_secs(self):
        """Test setting max_blocking_time in seconds."""
        from hdds.qos import QoS

        qos = QoS.reliable().max_blocking_time_secs(2)
        assert qos.get_max_blocking_time_ns() == 2_000_000_000


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

    def test_default_shows_no_extra_policy(self):
        """Only the three base fields when nothing differs from default."""
        from hdds.qos import QoS

        assert repr(QoS.default()) == "QoS(best_effort, volatile, depth=100)"

    def test_repr_shows_every_non_default_policy(self):
        """A policy that was set is visible in both repr() and str()."""
        from hdds.qos import QoS

        qos = (QoS.reliable().history_depth(20).deadline_ms(100).lifespan_secs(5)
               .max_blocking_time_ms(300)
               .ownership_exclusive(strength=50).time_based_filter_ms(50)
               .latency_budget_ms(100).transport_priority(5)
               .resource_limits(max_samples=500))
        for text in (repr(qos), str(qos)):
            assert "depth=20" in text
            assert "deadline=100ms" in text
            assert "lifespan=5000ms" in text
            assert "max_blocking_time=300ms" in text
            assert "latency_budget=100ms" in text
            assert "time_based_filter=50ms" in text
            assert "ownership=exclusive(strength=50)" in text
            assert "transport_priority=5" in text
            assert "max_samples=500" in text
            assert "max_instances=unlimited" in text

    def test_repr_keep_all(self):
        from hdds.qos import QoS

        assert "keep_all" in repr(QoS.reliable().history_keep_all())


class TestResourceLimits:
    """RESOURCE_LIMITS: -1 is LENGTH_UNLIMITED, and refusals say why."""

    def test_minus_one_is_size_max(self):
        """-1 must reach the C ABI as SIZE_MAX, the only unlimited value."""
        from hdds.qos import QoS, SIZE_MAX

        qos = QoS.default().resource_limits(max_samples=500)
        assert qos.get_max_samples() == 500
        assert qos.get_max_instances() == SIZE_MAX
        assert qos.get_max_samples_per_instance() == SIZE_MAX
        assert qos.consistency_problems() == []

    def test_max_samples_alone_creates_a_writer(self, intra_participant):
        """Regression: max_samples with the other limits unlimited is legal."""
        from hdds.qos import QoS

        qos = QoS.reliable().history_depth(20).resource_limits(max_samples=500)
        writer = intra_participant.create_writer("rl_max_samples_only", qos=qos)
        assert writer is not None

    def test_depth_above_per_instance_names_the_rule(self, intra_participant):
        """The refusal names the broken rule and its values."""
        from hdds.qos import QoS

        qos = QoS.default().resource_limits(500, 10, 50)  # default depth is 100
        assert qos.consistency_problems() == [
            "history depth (100) must be <= resource_limits "
            "max_samples_per_instance (50)"
        ]
        with pytest.raises(RuntimeError, match=r"history depth \(100\) must be <="):
            intra_participant.create_writer("rl_depth", qos=qos)

    def test_max_samples_below_per_instance_names_the_rule(self, intra_participant):
        from hdds.qos import QoS

        qos = QoS.reliable().history_depth(5).resource_limits(10, -1, 20)
        with pytest.raises(RuntimeError, match=r"max_samples \(10\) must be >="):
            intra_participant.create_writer("rl_total", qos=qos)

    def test_reader_is_refused_like_a_writer(self, intra_participant):
        """DDS 1.4 2.2.3.18/2.2.3.19 hold for a DataReader too."""
        from hdds.qos import QoS

        qos = QoS.default().resource_limits(500, 10, 50)  # default depth is 100
        with pytest.raises(RuntimeError, match=r"reader.*history depth \(100\) must be <="):
            intra_participant.create_reader("rl_reader_depth", qos=qos)
        qos = QoS.reliable().history_depth(5).resource_limits(10, -1, 20)
        with pytest.raises(RuntimeError, match=r"reader.*max_samples \(10\) must be >="):
            intra_participant.create_reader("rl_reader_total", qos=qos)
        ok = QoS.reliable().history_depth(20).resource_limits(500, 10, 50)
        assert intra_participant.create_reader("rl_reader_ok", qos=ok) is not None

    def test_consistent_limits_are_accepted(self, intra_participant):
        from hdds.qos import QoS

        qos = QoS.reliable().history_depth(20).resource_limits(500, 10, 50)
        assert qos.consistency_problems() == []
        assert intra_participant.create_writer("rl_ok", qos=qos) is not None


class TestMaxBlockingTime:
    """A RELIABLE writer's write() blocks for at most its QoS
    max_blocking_time (DDS v1.4 Sec.2.2.3.14), proven end-to-end: a matched
    RELIABLE KEEP_ALL reader with resource_limits full of exactly one sample,
    and that never calls take(), makes the second write() block.
    """

    def test_writer_write_blocks_for_its_qos_max_blocking_time(self, intra_participant):
        from hdds.qos import QoS
        from hdds._native import HddsException

        reader_qos = QoS.reliable().history_keep_all().resource_limits(1, 1, 1)
        reader = intra_participant.create_reader(
            "max_blocking_time_py_topic", qos=reader_qos
        )

        configured_ms = 300
        writer_qos = (QoS.reliable().history_keep_all().resource_limits(1, 1, 1)
                      .max_blocking_time_ms(configured_ms))
        writer = intra_participant.create_writer(
            "max_blocking_time_py_topic", qos=writer_qos
        )

        # Fills the reader's one slot of room; the reader never takes it.
        writer.write(b"first")

        start = time.monotonic()
        with pytest.raises(HddsException):
            writer.write(b"second")
        waited = time.monotonic() - start

        # A tight band around the configured 300ms proves the QoS value was
        # actually used, not the DDS default of 100ms (a mutated or ignored
        # setter would come back around 100ms instead).
        assert waited >= 0.25, f"returned too early: waited {waited:.3f}s"
        assert waited < 0.6, f"returned too late: waited {waited:.3f}s"

        del reader


class TestMatchedReaders:
    """DataWriter.matched_reader_count() / wait_for_readers()."""

    def test_no_remote_reader_means_zero_and_timeout(self, intra_participant):
        writer = intra_participant.create_writer("matched_none")
        assert writer.matched_reader_count() == 0
        assert writer.wait_for_readers(1, timeout=0.05) is False
        assert writer.wait_for_readers(0, timeout=0) is True

    def test_negative_arguments_are_refused(self, intra_participant):
        writer = intra_participant.create_writer("matched_neg")
        with pytest.raises(ValueError):
            writer.wait_for_readers(-1)
        with pytest.raises(ValueError):
            writer.wait_for_readers(1, timeout=-1)


class TestWaitForAcknowledgments:
    """DataWriter.wait_for_acknowledgments()."""

    def test_default_best_effort_qos_returns_at_once(self, intra_participant):
        # DDS v1.4 Sec.2.2.2.4.2.15: a BEST_EFFORT writer (the default QoS)
        # returns True at once, with no matched reader to wait for either.
        writer = intra_participant.create_writer("wait_for_ack_best_effort")
        assert writer.wait_for_acknowledgments(timeout=5.0) is True

    def test_negative_timeout_is_refused(self, intra_participant):
        writer = intra_participant.create_writer("wait_for_ack_neg")
        with pytest.raises(ValueError):
            writer.wait_for_acknowledgments(timeout=-1)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

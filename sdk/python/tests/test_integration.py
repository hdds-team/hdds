# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Integration tests for HDDS Python SDK.

These tests exercise real FFI calls via an IntraProcess participant
(no network required). They verify pub/sub roundtrips, type_name
support, WaitSet behavior, QoS application, and lifecycle management.
"""

import time

import pytest

from hdds.participant import Participant, TransportMode
from hdds.qos import QoS
from hdds.waitset import WaitSet, GuardCondition


# =========================================================================
# TestPubSub -- basic publish/subscribe roundtrips
# =========================================================================

class TestPubSub:
    """Basic publish/subscribe data path tests."""

    def test_write_and_take_roundtrip(self, intra_participant):
        writer = intra_participant.create_writer("test_roundtrip")
        reader = intra_participant.create_reader("test_roundtrip")
        time.sleep(0.05)

        payload = b"hello from python"
        writer.write(payload)
        time.sleep(0.05)

        data = reader.take()
        assert data is not None
        assert data == payload

    def test_take_returns_none_when_empty(self, intra_participant):
        reader = intra_participant.create_reader("test_empty")
        time.sleep(0.05)

        data = reader.take()
        assert data is None

    def test_multiple_samples_in_order(self, intra_participant):
        writer = intra_participant.create_writer("test_order")
        reader = intra_participant.create_reader("test_order")
        time.sleep(0.05)

        messages = [f"msg-{i}".encode() for i in range(5)]
        for msg in messages:
            writer.write(msg)
        time.sleep(0.05)

        received = []
        for _ in range(10):
            data = reader.take()
            if data is None:
                break
            received.append(data)

        assert received == messages

    def test_large_payload(self, intra_participant):
        writer = intra_participant.create_writer("test_large")
        reader = intra_participant.create_reader("test_large")
        time.sleep(0.05)

        payload = b"X" * 65536
        writer.write(payload)
        time.sleep(0.05)

        data = reader.take()
        assert data is not None
        assert len(data) == 65536
        assert data == payload


# =========================================================================
# TestTypeName -- type_name parameter support
# =========================================================================

class TestTypeName:
    """Tests for the type_name parameter on create_writer/create_reader."""

    def test_writer_with_type_name(self, intra_participant):
        writer = intra_participant.create_writer(
            "test_type_w", type_name="MyType"
        )
        assert writer is not None

    def test_reader_with_type_name(self, intra_participant):
        reader = intra_participant.create_reader(
            "test_type_r", type_name="MyType"
        )
        assert reader is not None

    def test_roundtrip_with_type_name(self, intra_participant):
        writer = intra_participant.create_writer(
            "test_type_rt", type_name="SensorData"
        )
        reader = intra_participant.create_reader(
            "test_type_rt", type_name="SensorData"
        )
        time.sleep(0.05)

        payload = b"typed-payload"
        writer.write(payload)
        time.sleep(0.05)

        data = reader.take()
        assert data is not None
        assert data == payload

    def test_type_name_with_qos(self, intra_participant):
        qos = QoS.reliable()
        writer = intra_participant.create_writer(
            "test_type_qos", qos=qos, type_name="QosType"
        )
        reader = intra_participant.create_reader(
            "test_type_qos", qos=qos, type_name="QosType"
        )
        time.sleep(0.05)

        writer.write(b"qos-typed")
        time.sleep(0.05)

        data = reader.take()
        assert data is not None
        assert data == b"qos-typed"

    def test_backward_compat_no_type_name(self, intra_participant):
        writer = intra_participant.create_writer("test_no_type")
        reader = intra_participant.create_reader("test_no_type")
        time.sleep(0.05)

        writer.write(b"compat")
        time.sleep(0.05)

        data = reader.take()
        assert data is not None
        assert data == b"compat"


# =========================================================================
# TestWaitSet -- WaitSet and GuardCondition
# =========================================================================

class TestWaitSet:
    """WaitSet synchronization tests."""

    def test_timeout_returns_false(self):
        guard = GuardCondition()
        ws = WaitSet()
        ws.attach_guard(guard)

        result = ws.wait(timeout=0.05)
        assert result is False
        ws.close()
        guard.close()

    def test_data_available_returns_true(self, intra_participant):
        writer = intra_participant.create_writer("test_ws_data")
        reader = intra_participant.create_reader("test_ws_data")
        ws = WaitSet()
        ws.attach_reader(reader)
        time.sleep(0.05)

        writer.write(b"wake up")
        result = ws.wait(timeout=2.0)
        assert result is True
        ws.close()

    def test_guard_condition_trigger(self):
        guard = GuardCondition()
        ws = WaitSet()
        ws.attach_guard(guard)

        # Trigger synchronously before wait to avoid threading issues
        guard.trigger()

        result = ws.wait(timeout=1.0)
        assert result is True

        ws.close()
        guard.close()

    def test_context_manager(self):
        guard = GuardCondition()

        with WaitSet() as ws:
            ws.attach_guard(guard)
            result = ws.wait(timeout=0.01)
            assert result is False
        # WaitSet should be closed after with block
        guard.close()


# =========================================================================
# TestQoSIntegration -- QoS applied to endpoints
# =========================================================================

class TestQoSIntegration:
    """QoS policies applied to real endpoints."""

    def test_reliable_roundtrip(self, intra_participant):
        qos = QoS.reliable()
        writer = intra_participant.create_writer("test_qos_rel", qos=qos)
        reader = intra_participant.create_reader("test_qos_rel", qos=qos)
        time.sleep(0.05)

        writer.write(b"reliable-data")
        time.sleep(0.05)

        data = reader.take()
        assert data is not None
        assert data == b"reliable-data"


# =========================================================================
# TestParticipantLifecycle -- creation, naming, cleanup
# =========================================================================

class TestParticipantLifecycle:
    """Participant lifecycle management."""

    def test_participant_name(self):
        p = Participant("lifecycle_test", transport=TransportMode.INTRA_PROCESS)
        assert p.name == "lifecycle_test"
        p.close()

    def test_context_manager(self):
        with Participant("ctx_test", transport=TransportMode.INTRA_PROCESS) as p:
            assert p.name == "ctx_test"
        # Should be closed cleanly

    def test_double_close(self):
        p = Participant("double_close", transport=TransportMode.INTRA_PROCESS)
        p.close()
        p.close()  # Should not raise


# =========================================================================
# TestPubSubEntities -- Publisher/Subscriber entity path
# =========================================================================

class TestPubSubEntities:
    """Publisher/Subscriber grouping entities."""

    def test_publisher_subscriber_roundtrip(self, intra_participant):
        pub = intra_participant.create_publisher()
        sub = intra_participant.create_subscriber()

        writer = pub.create_writer("test_pubsub_ent")
        reader = sub.create_reader("test_pubsub_ent")
        time.sleep(0.05)

        writer.write(b"via-entities")
        time.sleep(0.05)

        data = reader.take()
        assert data is not None
        assert data == b"via-entities"

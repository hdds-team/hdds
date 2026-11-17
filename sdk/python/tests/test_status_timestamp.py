# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""DDS 1.4 2.2.4.2.1 status reset and 2.2.2.4.2 timestamp operations.

Uses the real shared library on loopback. ctypes below reads SampleInfo
through the existing C condition API, independently of the writer wrapper.
"""
import ctypes as c
import time

import pytest
from hdds import Participant, TransportMode, QoS
from hdds._native import HddsError

pytestmark = pytest.mark.native


class SampleInfo(c.Structure):
    _fields_ = [("sample_state", c.c_uint32), ("view_state", c.c_uint32),
                ("instance_state", c.c_uint32), ("valid_data", c.c_bool),
                ("instance_handle", c.c_uint8 * 16),
                ("source_timestamp_ns", c.c_uint64),
                ("reception_timestamp_ns", c.c_uint64),
                ("sequence_number", c.c_uint64)]


def until(f):
    end = time.monotonic() + 10
    while True:
        result = f()
        if result:
            return result
        assert time.monotonic() < end, "condition timed out"


def matched(getter, count):
    status = getter()
    return status if status.current_count == count else None


@pytest.mark.parametrize("typed", [False, True])
def test_match_unmatch_reset_and_timestamps(native_lib, typed):
    with Participant("py_status_writer", domain_id=215, transport=TransportMode.UDP_MULTICAST) as wp, \
         Participant("py_status_reader", domain_id=215, transport=TransportMode.UDP_MULTICAST) as rp:
        w = wp.create_writer("py_status_timestamp", qos=QoS.reliable())
        r = rp.create_reader("py_status_timestamp", qos=QoS.reliable())
        pub = until(lambda: matched(w.get_publication_matched_status, 1))
        sub = until(lambda: matched(r.get_subscription_matched_status, 1))
        for status in (pub, sub):
            assert (status.total_count, status.total_count_change, status.current_count_change) == (1, 1, 1)
        for status in (w.get_publication_matched_status(), r.get_subscription_matched_status()):
            assert (status.total_count, status.total_count_change, status.current_count_change) == (1, 0, 0)
        for _ in range(2):
            status = r.get_requested_deadline_missed_status()
            assert status.total_count == 0
            assert status.total_count_change == 0
        for _ in range(2):
            status = w.get_offered_deadline_missed_status()
            assert status.total_count == 0
            assert status.total_count_change == 0
        for _ in range(2):
            status = r.get_requested_incompatible_qos_status()
            assert status.total_count == 0
            assert status.total_count_change == 0
            assert status.last_policy_id == 0
        for _ in range(2):
            status = w.get_offered_incompatible_qos_status()
            assert status.total_count == 0
            assert status.total_count_change == 0
            assert status.last_policy_id == 0
        for delta in (1, 0):
            status = r.get_liveliness_changed_status()
            assert status.alive_count == 1
            assert status.alive_count_change == delta
            assert status.not_alive_count == 0
            assert status.not_alive_count_change == 0
        for _ in range(2):
            status = w.get_liveliness_lost_status()
            assert status.total_count == 0
            assert status.total_count_change == 0
        for _ in range(2):
            status = r.get_sample_lost_status()
            assert status.total_count == 0
            assert status.total_count_change == 0
        for _ in range(2):
            status = r.get_sample_rejected_status()
            assert status.total_count == 0
            assert status.total_count_change == 0
            assert status.last_reason == 0
        assert w.register_instance(b"abcd") == bytes(16)
        assert w.register_instance_w_timestamp(b"abcd", 500000000) == bytes(16)
        lib = native_lib
        lib.hdds_reader_take_w_condition.argtypes = [c.c_void_p, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t), c.POINTER(SampleInfo)]
        lib.hdds_reader_take_w_condition.restype = c.c_int32
        cond = lib.hdds_create_read_condition(r._handle, 3, 3, 7)
        assert cond
        output, size, info = c.create_string_buffer(32), c.c_size_t(), SampleInfo()

        def take():
            err = lib.hdds_reader_take_w_condition(r._handle, cond, output, 32, c.byref(size), c.byref(info))
            assert err in (HddsError.OK, HddsError.NOT_FOUND)
            return err == HddsError.OK

        stamp = 1700000000500000000  # Exactly representable RTPS fraction.
        try:
            assert not take()  # Registration emits no sample.
            if typed:
                class Message:
                    def encode_cdr2_le(self):
                        return b"abcd"
                w.write_typed_w_timestamp(Message(), stamp)
            else:
                w.write_w_timestamp(b"abcd", stamp)
            until(take)
            assert info.valid_data and info.source_timestamp_ns == stamp
            assert output.raw[:size.value] == b"abcd"
            assert w.wait_for_acknowledgments(10)
            w.write(b"next")
            until(take)
            assert info.valid_data and info.source_timestamp_ns > stamp
            w.dispose_w_timestamp(b"abcd", stamp)
            until(take)
            assert not info.valid_data and info.instance_state == 2
            w.unregister_instance_w_timestamp(b"abcd", stamp)
            w.dispose(b"abcd")
            w.unregister_instance(b"abcd")
        finally:
            lib.hdds_read_condition_delete(cond)
        r._destroy()
        pub = until(lambda: matched(w.get_publication_matched_status, 0))
        assert pub.total_count == 1 and pub.current_count_change == -1
        assert w.get_publication_matched_status().current_count_change == 0
        r = rp.create_reader("py_status_timestamp", qos=QoS.reliable())
        until(lambda: matched(r.get_subscription_matched_status, 1))
        w._destroy()
        sub = until(lambda: matched(r.get_subscription_matched_status, 0))
        assert sub.total_count == 1 and sub.current_count_change == -1
        assert r.get_subscription_matched_status().current_count_change == 0


@pytest.mark.parametrize("stamp", [-1, 2**64, 1.5, None])
def test_timestamp_argument_validation(intra_participant, stamp):
    w = intra_participant.create_writer("py_timestamp_validation")
    with pytest.raises((TypeError, ValueError)):
        w.write_w_timestamp(b"abcd", stamp)


def test_destroyed_entities_reject_operations(intra_participant):
    w = intra_participant.create_writer("py_status_closed")
    r = intra_participant.create_reader("py_status_closed")
    w._destroy()
    r._destroy()
    with pytest.raises(RuntimeError):
        w.get_publication_matched_status()
    with pytest.raises(RuntimeError):
        r.get_subscription_matched_status()
    with pytest.raises(RuntimeError):
        w.write_w_timestamp(b"abcd", 1)


def test_incompatible_status_preserves_policy_and_resets_changes(native_lib):
    # DDS 1.4 RELIABILITY requested/offered rule: BEST_EFFORT cannot
    # satisfy a RELIABLE reader; both endpoints report policy id 11.
    with Participant("py_incompat_writer", domain_id=215, transport=TransportMode.UDP_MULTICAST) as wp, \
         Participant("py_incompat_reader", domain_id=215, transport=TransportMode.UDP_MULTICAST) as rp:
        w = wp.create_writer("py_status_incompatible", qos=QoS.best_effort())
        r = rp.create_reader("py_status_incompatible", qos=QoS.reliable())

        def incompatible(getter):
            status = getter()
            return status if status.total_count else None

        for getter in (w.get_offered_incompatible_qos_status, r.get_requested_incompatible_qos_status):
            first = until(lambda: incompatible(getter))
            assert first.total_count_change > 0 and first.last_policy_id == 11
            second = getter()
            assert second.total_count == first.total_count
            assert second.total_count_change == 0 and second.last_policy_id == 11


def test_publisher_wait_for_acknowledgments(native_lib):
    # DDS 1.4 2.2.2.4.1.12: the Publisher waits for the data of its writers.
    with Participant("py_pubwait_writer", domain_id=216, transport=TransportMode.UDP_MULTICAST) as wp, \
         Participant("py_pubwait_reader", domain_id=216, transport=TransportMode.UDP_MULTICAST) as rp:
        pub = wp.create_publisher()
        assert pub.wait_for_acknowledgments(0) is True
        w = pub.create_writer("py_publisher_wait", qos=QoS.reliable())
        rp.create_reader("py_publisher_wait", qos=QoS.reliable())
        until(lambda: matched(w.get_publication_matched_status, 1))
        w.write(b"abcd")
        assert pub.wait_for_acknowledgments(10) is True
        with pytest.raises(ValueError):
            pub.wait_for_acknowledgments(-1)
        pub._destroy()
        with pytest.raises(RuntimeError):
            pub.wait_for_acknowledgments(1)

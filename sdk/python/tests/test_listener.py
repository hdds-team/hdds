# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Listener callbacks through the native library.

Covers: on_data_available with the written bytes (on the writing thread for
a reader of the same participant, on an HDDS thread over the network),
matched statuses between two UDP participants, on_sample_written, an
exception in a callback logged and not propagated, only overridden methods
installed, clear / destroy while a callback runs on another thread (they
wait), and a callback that clears its own listener.

The network test needs multicast on the interface HDDS picks: set
HDDS_INTERFACE=lo on a host whose default route is a VPN or a container
bridge.
"""

import logging
import threading
import time

import pytest

import hdds
from hdds.participant import Participant, TransportMode
from hdds.qos import QoS

pytestmark = pytest.mark.native


def _wait_until(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


@pytest.fixture
def intra():
    p = Participant("py_listener_intra", transport=TransportMode.INTRA_PROCESS)
    yield p
    p.close()


def _qos():
    return QoS.reliable().history_depth(64)


class Recorder(hdds.ReaderListener):
    def __init__(self):
        self.data = []
        self.threads = set()
        self.matched = []
        self.lock = threading.Lock()

    def on_data_available(self, data):
        with self.lock:
            self.data.append(data)
            self.threads.add(threading.get_ident())

    def on_subscription_matched(self, status):
        with self.lock:
            self.matched.append(
                (status.total_count, status.total_count_change,
                 status.current_count, status.current_count_change))


def test_data_available_on_the_writing_thread(intra):
    reader = intra.create_reader("py_listener_data", qos=_qos())
    writer = intra.create_writer("py_listener_data", qos=_qos())
    rec = Recorder()
    reader.set_listener(rec)

    writer.write(b"one")
    writer.write(b"two")
    # Same participant: delivered inside write().
    assert rec.data == [b"one", b"two"]
    assert rec.threads == {threading.get_ident()}

    reader.clear_listener()
    writer.write(b"three")
    assert rec.data == [b"one", b"two"]
    taken = []
    while (sample := reader.take()) is not None:
        taken.append(sample)
    assert taken == [b"one", b"two", b"three"]


def test_take_inside_the_callback(intra):
    reader = intra.create_reader("py_listener_take_inside", qos=_qos())
    writer = intra.create_writer("py_listener_take_inside", qos=_qos())
    taken = []

    class Taker(hdds.ReaderListener):
        def on_data_available(self, data):
            while (sample := reader.take()) is not None:
                taken.append(sample)

    reader.set_listener(Taker())
    for i in range(3):
        writer.write(bytes([i]))
    assert taken == [b"\x00", b"\x01", b"\x02"]
    reader.clear_listener()


def test_exception_in_callback_is_logged_not_propagated(intra, caplog):
    reader = intra.create_reader("py_listener_raise", qos=_qos())
    writer = intra.create_writer("py_listener_raise", qos=_qos())
    calls = []

    class Raiser(hdds.ReaderListener):
        def on_data_available(self, data):
            calls.append(data)
            raise ValueError("listener failure (expected by this test)")

    reader.set_listener(Raiser())
    with caplog.at_level(logging.ERROR, logger="hdds.listener"):
        writer.write(b"a")  # must not raise
        writer.write(b"b")
    assert calls == [b"a", b"b"]
    errors = [r for r in caplog.records if r.name == "hdds.listener"]
    assert len(errors) == 2
    assert "on_data_available" in errors[0].getMessage()
    assert errors[0].exc_info[0] is ValueError
    reader.clear_listener()


def test_only_overridden_methods_are_installed(intra):
    from hdds import listener as listener_mod

    class OnlyMatched(hdds.ReaderListener):
        def on_subscription_matched(self, status):
            pass

    c_struct = listener_mod._c_struct(
        OnlyMatched(), 7, hdds.ReaderListener,
        listener_mod._READER_THUNKS, listener_mod._CReaderListener)
    assert bool(c_struct.on_subscription_matched)
    assert not bool(c_struct.on_data_available)
    assert not bool(c_struct.on_sample_rejected)
    assert c_struct.user_data == 7


def test_clear_from_inside_own_callback(intra):
    reader = intra.create_reader("py_listener_self_clear", qos=_qos())
    writer = intra.create_writer("py_listener_self_clear", qos=_qos())
    calls = []
    after = []

    class SelfClear(hdds.ReaderListener):
        def on_data_available(self, data):
            calls.append(data)
            reader.clear_listener()
            after.append("still running")

    reader.set_listener(SelfClear())
    writer.write(b"a")
    writer.write(b"b")
    assert calls == [b"a"]
    assert after == ["still running"]


@pytest.mark.parametrize("remove", ["clear", "destroy"])
def test_removal_waits_for_a_callback_running_on_another_thread(remove):
    p = Participant("py_listener_removal_" + remove, transport=TransportMode.INTRA_PROCESS)
    try:
        reader = p.create_reader("py_listener_removal", qos=_qos())
        writer = p.create_writer("py_listener_removal", qos=_qos())
        entered = threading.Event()
        finished = threading.Event()

        class Slow(hdds.ReaderListener):
            def on_data_available(self, data):
                entered.set()
                time.sleep(0.3)
                finished.set()

        reader.set_listener(Slow())
        t = threading.Thread(target=writer.write, args=(b"slow",))
        t.start()
        assert entered.wait(5.0)
        if remove == "clear":
            reader.clear_listener()
        else:
            reader._destroy()
        assert finished.is_set(), "removal returned while the callback was running"
        t.join(5.0)
        assert not t.is_alive()
    finally:
        p.close()


def test_matched_and_network_data():
    sub = Participant("py_listener_net_sub")
    pub = Participant("py_listener_net_pub")
    try:
        reader = sub.create_reader("py_listener_net", qos=_qos())
        rec = Recorder()
        reader.set_listener(rec)

        writer = pub.create_writer("py_listener_net", qos=_qos())
        written = []
        pub_matched = []

        class WriterRec(hdds.WriterListener):
            def on_sample_written(self, data, sequence_number):
                written.append((data, sequence_number))

            def on_publication_matched(self, status):
                pub_matched.append((status.current_count, status.current_count_change))

        writer.set_listener(WriterRec())

        assert _wait_until(lambda: len(rec.matched) >= 1)
        assert rec.matched[0] == (1, 1, 1, 1)

        for i in range(5):
            writer.write(f"net-{i}".encode())
        assert [d for d, _ in written] == [f"net-{i}".encode() for i in range(5)]
        seqs = [s for _, s in written]
        assert seqs == sorted(seqs) and len(set(seqs)) == 5

        assert _wait_until(lambda: len(rec.data) >= 5)
        time.sleep(0.2)
        assert rec.data == [f"net-{i}".encode() for i in range(5)]
        assert threading.get_ident() not in rec.threads

        before = len(pub_matched)
        sub.create_reader("py_listener_net", qos=_qos())
        assert _wait_until(lambda: len(pub_matched) > before)
        assert pub_matched[-1] == (2, 1)
    finally:
        pub.close()
        sub.close()


def test_concurrent_set_listener_keeps_the_installed_one(intra):
    """Two threads replace the listener of one reader while a writer writes:
    whichever install reached the library last stays installed, alive, and
    is the only one registered."""
    from hdds import listener as listener_mod

    reader = intra.create_reader("py_listener_concurrent", qos=_qos())
    writer = intra.create_writer("py_listener_concurrent", qos=_qos())
    calls = []
    stop = threading.Event()

    class Counting(hdds.ReaderListener):
        def on_data_available(self, data):
            calls.append(1)

    def install_loop():
        for _ in range(150):
            reader.set_listener(Counting())

    def write_loop():
        while not stop.is_set():
            writer.write(b"c")
            while reader.take() is not None:
                pass

    w = threading.Thread(target=write_loop)
    w.start()
    a = threading.Thread(target=install_loop)
    b = threading.Thread(target=install_loop)
    a.start()
    b.start()
    a.join()
    b.join()
    before = len(calls)
    assert _wait_until(lambda: len(calls) > before, 5.0), "the installed listener is dead"
    stop.set()
    w.join()
    keys = listener_mod._keys_of(reader._handle)
    assert len(keys) == 1, f"expected one registered listener, found {len(keys)}"
    reader.clear_listener()
    assert listener_mod._keys_of(reader._handle) == []


def test_destroy_inside_own_callback_does_not_crash(intra):
    writer = intra.create_writer("py_listener_destroy_inside", qos=_qos())
    calls = []

    class DestroyMe(hdds.WriterListener):
        def on_sample_written(self, data, sequence_number):
            calls.append(data)
            # The library refuses to free the writer under the write() that
            # called back (it leaks it and logs an error) and removes the
            # listener.
            writer._destroy()

    writer.set_listener(DestroyMe())
    writer.write(b"x")
    assert calls == [b"x"]

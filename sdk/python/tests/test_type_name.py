# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""An endpoint created for a type announces that type's own name.

DDS-XTypes 1.3 Sec.7.6.3.4.2 Step 2: with no TypeObject the type names of a
writer and a reader must be equal. A class hdds_gen generated says its
qualified IDL name (``type_name()``); ``create_writer`` / ``create_reader``
given ``msg_type`` announce it and never adopt the name a peer announces
(only an endpoint with neither a type nor a name does). The announced name is
the intra-process match key, so delivery tells which name an endpoint
announced.
"""

import time

import pytest

from hdds.entities import PLACEHOLDER_TYPE_NAME, endpoint_type_name


class Named:
    @classmethod
    def type_name(cls):
        return "mod::Named"


class Other:
    @classmethod
    def type_name(cls):
        return "mod::Other"


class Older:
    """A class of an older hdds_gen: no type_name()."""


def test_the_name_is_the_explicit_one_then_the_class_then_the_placeholder():
    assert endpoint_type_name("Explicit", Named) == "Explicit"
    assert endpoint_type_name(None, Named) == "mod::Named"
    assert endpoint_type_name(None, Older) == PLACEHOLDER_TYPE_NAME
    # No type and no name: the endpoint adopts.
    assert endpoint_type_name(None, None) is None


def test_an_empty_override_is_no_name_and_a_nul_is_refused():
    # An empty name at the C ABI is an endpoint with no type, which adopts:
    # for an endpoint with a class it is the class's name instead.
    assert endpoint_type_name("", Named) == "mod::Named"
    assert endpoint_type_name("", Older) == PLACEHOLDER_TYPE_NAME
    assert endpoint_type_name("", None) is None
    with pytest.raises(ValueError):
        endpoint_type_name("A\0B", Named)
    with pytest.raises(ValueError):
        endpoint_type_name("A\0B", None)

    class NulName:
        @classmethod
        def type_name(cls):
            return "A\0B"

    assert endpoint_type_name(None, NulName) == PLACEHOLDER_TYPE_NAME


def test_a_type_name_that_is_not_a_name_is_the_placeholder():
    class Broken:
        @classmethod
        def type_name(cls):
            raise RuntimeError("needs state")

    class Empty:
        @classmethod
        def type_name(cls):
            return ""

    assert endpoint_type_name(None, Broken) == PLACEHOLDER_TYPE_NAME
    assert endpoint_type_name(None, Empty) == PLACEHOLDER_TYPE_NAME


@pytest.fixture
def participant(intra_participant):
    return intra_participant


def _delivered(reader, expect):
    deadline = time.time() + (2.0 if expect else 0.15)
    while True:
        data = reader.take()
        if data is not None or time.time() >= deadline:
            return data
        time.sleep(0.01)


@pytest.mark.native
def test_same_type_writer_and_reader_match(participant):
    writer = participant.create_writer("py_tn_same", Named)
    reader = participant.create_reader("py_tn_same", msg_type=Named)
    writer.write(b"payload")
    assert _delivered(reader, True) == b"payload"


@pytest.mark.native
def test_a_typed_reader_never_adopts_a_peers_name(participant):
    writer = participant.create_writer("py_tn_foreign", Named)
    other = participant.create_reader("py_tn_foreign", msg_type=Other)
    older = participant.create_reader("py_tn_foreign", msg_type=Older)
    writer.write(b"payload")
    assert _delivered(other, False) is None
    assert _delivered(older, False) is None


@pytest.mark.native
def test_a_typed_writer_never_adopts_a_peers_name(participant):
    reader = participant.create_reader("py_tn_foreign_w", msg_type=Named)
    other = participant.create_writer("py_tn_foreign_w", Other)
    older = participant.create_writer("py_tn_foreign_w", Older)
    other.write(b"payload")
    older.write(b"payload")
    assert _delivered(reader, False) is None


@pytest.mark.native
def test_an_endpoint_with_no_type_adopts_the_name(participant):
    writer = participant.create_writer("py_tn_raw", Named)
    reader = participant.create_reader("py_tn_raw")
    writer.write(b"payload")
    assert _delivered(reader, True) == b"payload"


@pytest.mark.native
def test_publisher_and_subscriber_endpoints_announce_their_own_name(participant):
    publisher = participant.create_publisher()
    subscriber = participant.create_subscriber()
    # Every non-keyed branch of Publisher.create_writer passes the name.
    writer = publisher.create_writer("py_tn_pubsub", Named)
    qos_writer = publisher.create_writer("py_tn_pubsub_q", Named, qos=participant_qos())
    explicit = publisher.create_writer("py_tn_pubsub_e", type_name="mod::Named")
    same = subscriber.create_reader("py_tn_pubsub", msg_type=Named)
    other = subscriber.create_reader("py_tn_pubsub", msg_type=Other)
    qos_same = subscriber.create_reader("py_tn_pubsub_q", msg_type=Named, qos=participant_qos())
    explicit_same = subscriber.create_reader("py_tn_pubsub_e", type_name="mod::Named")
    writer.write(b"one")
    qos_writer.write(b"two")
    explicit.write(b"three")
    assert _delivered(same, True) == b"one"
    assert _delivered(other, False) is None
    assert _delivered(qos_same, True) == b"two"
    assert _delivered(explicit_same, True) == b"three"


def participant_qos():
    from hdds.qos import QoS

    return QoS.best_effort() if hasattr(QoS, "best_effort") else QoS.default()


@pytest.mark.native
def test_an_empty_override_never_adopts_on_any_entry(participant):
    publisher = participant.create_publisher()
    subscriber = participant.create_subscriber()
    writer = participant.create_writer("py_tn_empty", Named)
    pub_writer = publisher.create_writer("py_tn_empty_ps", Named)
    # An empty type_name with a class is the class's name, so these match.
    same = participant.create_reader("py_tn_empty", msg_type=Named, type_name="")
    sub_same = subscriber.create_reader("py_tn_empty_ps", msg_type=Named, type_name="")
    # ... and with another class they do not: nothing was adopted.
    other = participant.create_reader("py_tn_empty", msg_type=Other, type_name="")
    sub_other = subscriber.create_reader("py_tn_empty_ps", msg_type=Other, type_name="")
    writer.write(b"one")
    pub_writer.write(b"two")
    assert _delivered(same, True) == b"one"
    assert _delivered(sub_same, True) == b"two"
    assert _delivered(other, False) is None
    assert _delivered(sub_other, False) is None
    # An empty-named writer of a class does not feed a Named reader.
    reader = participant.create_reader("py_tn_empty_w", msg_type=Named)
    participant.create_writer("py_tn_empty_w", Other, type_name="").write(b"x")
    publisher.create_writer("py_tn_empty_w", Other, type_name="").write(b"y")
    assert _delivered(reader, False) is None


@pytest.mark.native
def test_a_nul_in_the_name_is_refused_on_every_entry(participant):
    publisher = participant.create_publisher()
    subscriber = participant.create_subscriber()
    with pytest.raises(ValueError):
        participant.create_writer("py_tn_nul", Named, type_name="A\0B")
    with pytest.raises(ValueError):
        participant.create_reader("py_tn_nul", msg_type=Named, type_name="A\0B")
    with pytest.raises(ValueError):
        publisher.create_writer("py_tn_nul", Named, type_name="A\0B")
    with pytest.raises(ValueError):
        subscriber.create_reader("py_tn_nul", msg_type=Named, type_name="A\0B")


def test_an_older_library_gets_the_placeholder_from_the_legacy_entries(monkeypatch):
    """No _with_type entry in libhdds_c: "RawBytes" is announced by every
    other constructor of such a library, so it needs none."""
    from types import SimpleNamespace

    from hdds.entities import Publisher, Subscriber

    calls = []

    def legacy(name):
        def call(*args):
            calls.append(name)
            return 2
        return call

    lib = SimpleNamespace(
        hdds_publisher_create_writer=legacy("writer"),
        hdds_publisher_create_writer_with_qos=legacy("writer_qos"),
        hdds_subscriber_create_reader=legacy("reader"),
        hdds_subscriber_create_reader_with_qos=legacy("reader_qos"),
        hdds_qos_default=lambda: 3,
        hdds_qos_destroy=lambda _handle: None,
    )
    monkeypatch.setattr("hdds._native.get_lib", lambda: lib)
    publisher = Publisher._from_handle(1, None)
    subscriber = Subscriber._from_handle(1, None)
    publisher.create_writer("older", Older)
    subscriber.create_reader("older", msg_type=Older)
    assert calls == ["writer", "reader"]
    # A real name cannot be announced by such a library: refused, not dropped.
    with pytest.raises(NotImplementedError):
        publisher.create_writer("older", Named)
    with pytest.raises(NotImplementedError):
        subscriber.create_reader("older", msg_type=Named)
    publisher._handle = subscriber._handle = None

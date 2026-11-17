# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""A writer labels its samples with the extensibility of its type.

DDS-XTypes 1.3 7.6.3.1.2, Table 60: the encapsulation identifier of a
sample names its type's extensibility (``D_CDR2_LE`` APPENDABLE,
``PL_CDR2_LE`` MUTABLE, ``CDR2_LE`` FINAL). A class hdds_gen 2.0 generated
says it (``HDDS_EXTENSIBILITY``); ``create_writer(..., msg_type=T)`` of a
Participant or a Publisher hands it to the C ABI writer, which labels every
sample with it (the bytes on the wire are checked by
``scripts/test-sdk-typed.sh``). An older class says nothing and keeps the
earlier writer (every sample ``CDR2_LE``); ``extensibility=`` overrides.
"""

import warnings

import pytest

from hdds.entities import DataWriter, writer_extensibility

FINAL, APPENDABLE, MUTABLE = 0, 1, 2


class Appendable:
    """A class of hdds_gen 2.0, APPENDABLE (the hdds_gen default)."""

    HDDS_EXTENSIBILITY = "appendable"


class Mutable:
    HDDS_EXTENSIBILITY = "mutable"


class Final:
    HDDS_EXTENSIBILITY = "final"


class Older:
    """A class of hdds_gen 1.x: no extensibility."""


class Bogus:
    HDDS_EXTENSIBILITY = "extensible"


def test_the_class_says_the_extensibility():
    assert writer_extensibility(None, Appendable) == APPENDABLE
    assert writer_extensibility(None, Mutable) == MUTABLE
    assert writer_extensibility(None, Final) == FINAL
    assert writer_extensibility(None, Older) is None
    assert writer_extensibility(None, None) is None


def test_an_explicit_extensibility_overrides_the_class():
    assert writer_extensibility("final", Mutable) == FINAL
    assert writer_extensibility("mutable", Older) == MUTABLE


def test_an_unknown_extensibility_is_refused():
    with pytest.raises(ValueError):
        writer_extensibility(None, Bogus)
    with pytest.raises(ValueError):
        writer_extensibility("extensible", None)


class _Recorder:
    """Records the extensibility each C ABI writer constructor receives."""

    def __init__(self, lib, monkeypatch):
        self.calls = []
        for name, at in (
            ("hdds_writer_create_with_extensibility", 4),
            ("hdds_publisher_create_writer_with_extensibility", 3),
            ("hdds_publisher_create_writer_with_type", 4),
        ):
            real = getattr(lib, name)

            def wrapper(*args, _real=real, _name=name, _at=at):
                self.calls.append((_name, args[_at]))
                return _real(*args)

            monkeypatch.setattr(lib, name, wrapper)


@pytest.mark.native
def test_a_participant_writer_hands_the_class_extensibility_to_the_c_abi(
    native_lib, monkeypatch
):
    from hdds.participant import Participant, TransportMode

    rec = _Recorder(native_lib, monkeypatch)
    with Participant("py_ext_participant", transport=TransportMode.INTRA_PROCESS) as p:
        p.create_writer("py_ext_a", msg_type=Appendable)
        p.create_writer("py_ext_m", msg_type=Mutable)
        p.create_writer("py_ext_f", msg_type=Final)
        p.create_writer("py_ext_o", msg_type=Older)
        p.create_writer("py_ext_x", msg_type=Mutable, extensibility="appendable")
        with pytest.raises(ValueError):
            p.create_writer("py_ext_b", msg_type=Bogus)
    assert [c[1] for c in rec.calls] == [APPENDABLE, MUTABLE, FINAL, APPENDABLE]


@pytest.mark.native
def test_a_publisher_writer_hands_the_class_extensibility_to_the_c_abi(
    native_lib, monkeypatch
):
    from hdds.participant import Participant, TransportMode
    from hdds.qos import QoS

    rec = _Recorder(native_lib, monkeypatch)
    with Participant("py_ext_publisher", transport=TransportMode.INTRA_PROCESS) as p:
        publisher = p.create_publisher()
        publisher.create_writer("py_pub_ext_a", msg_type=Appendable)
        publisher.create_writer("py_pub_ext_m", qos=QoS.reliable(), msg_type=Mutable)
        publisher.create_writer("py_pub_ext_o", msg_type=Older)
        publisher.create_writer("py_pub_ext_f", extensibility="final")
    # A writer of a class announces the class's type name (the _with_type
    # entry); one with no class has no type to announce and adopts.
    assert rec.calls == [
        ("hdds_publisher_create_writer_with_type", APPENDABLE),
        ("hdds_publisher_create_writer_with_type", MUTABLE),
        ("hdds_publisher_create_writer_with_type", FINAL),
        ("hdds_publisher_create_writer_with_extensibility", FINAL),
    ]


class _FakeAppendable:
    """A generated class instance: HDDS_EXTENSIBILITY, encode_cdr2_le()."""

    HDDS_EXTENSIBILITY = "appendable"

    def encode_cdr2_le(self) -> bytes:
        return b"\x00\x00\x00\x00"


class _FakeFinal:
    HDDS_EXTENSIBILITY = "final"

    def encode_cdr2_le(self) -> bytes:
        return b"\x00\x00\x00\x00"


class _FakeOlder:
    """A class of hdds_gen 1.x: no extensibility, like test_writer_extensibility's Older."""

    def encode_cdr2_le(self) -> bytes:
        return b"\x00\x00\x00\x00"


def _fake_writer(extensibility_known: bool, monkeypatch: pytest.MonkeyPatch) -> DataWriter:
    """A DataWriter with no native handle at all: write_typed's warning
    logic needs no C ABI, so this unit-tests it without a built libhdds_c.
    """
    writer = DataWriter._from_handle(
        "py_ext_warn", object(), None, extensibility_known=extensibility_known
    )
    monkeypatch.setattr(writer, "_write_raw", lambda data: None)
    return writer


def test_write_typed_warns_once_when_the_writer_was_created_without_the_extensibility(
    monkeypatch: pytest.MonkeyPatch,
):
    """A writer created without msg_type or extensibility labels every
    sample FINAL regardless of the real body: write_typed warns the first
    time it is handed a non-FINAL typed instance, and never again for that
    writer (the mislabelling does not change from one write to the next).
    """
    writer = _fake_writer(extensibility_known=False, monkeypatch=monkeypatch)
    with pytest.warns(UserWarning, match="py_ext_warn.*FINAL"):
        writer.write_typed(_FakeAppendable())
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        writer.write_typed(_FakeAppendable())  # no second warning


def test_write_typed_never_warns_for_a_final_class(monkeypatch: pytest.MonkeyPatch):
    """FINAL is exactly what an extensibility-unaware writer already
    labels every sample: nothing to warn about.
    """
    writer = _fake_writer(extensibility_known=False, monkeypatch=monkeypatch)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        writer.write_typed(_FakeFinal())


def test_write_typed_never_warns_for_a_class_with_no_extensibility(monkeypatch: pytest.MonkeyPatch):
    """A class from an hdds_gen older than 1.3 says nothing: nothing to
    compare the writer's (always FINAL) labelling against.
    """
    writer = _fake_writer(extensibility_known=False, monkeypatch=monkeypatch)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        writer.write_typed(_FakeOlder())


def test_write_typed_never_warns_when_the_writer_already_knows_the_extensibility(
    monkeypatch: pytest.MonkeyPatch,
):
    """create_writer(topic, Cls) (or extensibility=) already labelled every
    sample right at creation: nothing left to warn about at write time.
    """
    writer = _fake_writer(extensibility_known=True, monkeypatch=monkeypatch)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        writer.write_typed(_FakeAppendable())



@pytest.mark.native
def test_a_qos_passed_positionally_is_still_the_writer_qos(native_lib, monkeypatch):
    """Before 1.5 the QoS was the second positional argument of
    create_writer(); such a call must keep its QoS, not lose it as a type."""
    import hdds.participant as participant_mod
    from hdds.participant import Participant, TransportMode
    from hdds.qos import QoS

    seen = []

    def spy(extensibility, msg_type):
        seen.append(msg_type)
        return writer_extensibility(extensibility, msg_type)

    monkeypatch.setattr(participant_mod, "writer_extensibility", spy)
    with Participant("py_pos_qos", transport=TransportMode.INTRA_PROCESS) as p:
        q = QoS.reliable()
        w = p.create_writer("py_pos_qos_t", q)
        assert w is not None
        assert w.qos is q
        with pytest.raises(TypeError):
            p.create_writer("py_pos_qos_u", q, qos=q)
    assert seen == [None]

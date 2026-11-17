# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""DATA_REPRESENTATION through the Python SDK (DDS-XTypes 1.3 7.6.3.1.1).

A reader requests what its decoding class reads: XCDR and XCDR2 for a class
with ``decode_by_encapsulation`` (hdds_gen 2.0), XCDR2 only otherwise; it
learns each sample's representation (``take_with_encapsulation``), and
``take_typed`` never hands XCDR1 bytes to a class that decodes XCDR2 only.
"""

import pytest

from hdds.entities import reader_qos_for, decodes_xcdr1
from hdds.qos import QoS

pytestmark = pytest.mark.native

CDR_LE = 0x0001
CDR2_LE = 0x0007


class Xcdr2Only:
    """A class of hdds_gen 1.x: decode_cdr2_le only."""

    @classmethod
    def decode_cdr2_le(cls, data):
        return ("cdr2", bytes(data)), len(data)


class BothVersions(Xcdr2Only):
    """A class of hdds_gen 2.0: also decode_by_encapsulation."""

    @classmethod
    def decode_by_encapsulation(cls, encapsulation_id, data):
        return (encapsulation_id, bytes(data)), len(data)


def test_the_setter_takes_xcdr_and_xcdr2_only(native_lib):
    qos = QoS.default()
    assert qos.get_data_representation() == []
    qos.data_representation(QoS.XCDR_DATA_REPRESENTATION, QoS.XCDR2_DATA_REPRESENTATION)
    assert qos.get_data_representation() == [0, 2]
    from hdds._native import HddsException
    with pytest.raises(HddsException):
        qos.data_representation(1)
    assert qos.get_data_representation() == [0, 2], "a refused list leaves the QoS as it was"
    qos.data_representation()
    assert qos.get_data_representation() == []


def test_a_reader_requests_xcdr_only_for_a_class_that_decodes_it(native_lib):
    assert decodes_xcdr1(BothVersions) and not decodes_xcdr1(Xcdr2Only)
    assert not decodes_xcdr1(None)
    base = QoS.reliable()
    assert reader_qos_for(BothVersions, base).get_data_representation() == [0, 2]
    assert base.get_data_representation() == [], "the caller's QoS is not modified"
    assert reader_qos_for(Xcdr2Only, base) is base
    assert reader_qos_for(None, base) is base
    explicit = QoS.reliable().data_representation(QoS.XCDR2_DATA_REPRESENTATION)
    assert reader_qos_for(BothVersions, explicit).get_data_representation() == [2]
    assert reader_qos_for(BothVersions, None).get_data_representation() == [0, 2]


def test_take_typed_dispatches_by_representation_and_refuses_xcdr1_to_an_old_class(
    intra_participant,
):
    xcdr1_writer = intra_participant.create_writer(
        "py_datarep", qos=QoS.reliable().data_representation(QoS.XCDR_DATA_REPRESENTATION))
    xcdr2_writer = intra_participant.create_writer("py_datarep", qos=QoS.reliable())
    reader = intra_participant.create_reader(
        "py_datarep", qos=QoS.reliable(), msg_type=BothVersions)
    assert reader.qos.get_data_representation() == [0, 2]

    xcdr1_writer.write(b"\x01\x02\x03\x04")
    xcdr2_writer.write(b"\x05\x06\x07\x08")
    assert reader.take_typed(BothVersions) == (CDR_LE, b"\x01\x02\x03\x04")
    assert reader.take_typed(BothVersions) == (CDR2_LE, b"\x05\x06\x07\x08")
    assert reader.take_typed(BothVersions) is None

    xcdr1_writer.write(b"\x09\x0a\x0b\x0c")
    with pytest.raises(ValueError, match="XCDR1"):
        reader.take_typed(Xcdr2Only)
    xcdr2_writer.write(b"\x0d\x0e\x0f\x10")
    assert reader.take_typed(Xcdr2Only) == ("cdr2", b"\x0d\x0e\x0f\x10")

    xcdr1_writer.write(b"\x11\x12\x13\x14")
    assert reader.take_with_encapsulation() == (b"\x11\x12\x13\x14", CDR_LE)


def test_a_reader_of_an_old_class_requests_xcdr2_and_misses_an_xcdr1_writer(intra_participant):
    reader = intra_participant.create_reader(
        "py_datarep_old", qos=QoS.reliable(), msg_type=Xcdr2Only)
    assert reader.qos.get_data_representation() == []
    writer = intra_participant.create_writer(
        "py_datarep_old", qos=QoS.reliable().data_representation(QoS.XCDR_DATA_REPRESENTATION))
    writer.write(b"\x01\x00\x00\x00")
    assert reader.take() is None, "an XCDR2 reader is never handed an XCDR1 sample"


class _LibWithoutTakeEx:
    """Stands in for a libhdds_c predating hdds_reader_take_ex /
    hdds_qos_set_data_representation (added together, same release):
    neither attribute exists on it at all, exactly like `hasattr` sees an
    older loaded library.
    """


def test_reader_qos_for_refuses_rather_than_mislabel_on_an_old_library(native_lib, monkeypatch):
    """Item 3 (datarep-default upgrade path): on a libhdds_c that predates
    hdds_qos_set_data_representation/hdds_reader_take_ex, a reader of a
    class that decodes XCDR1 (BothVersions) cannot be made to request
    XCDR2 only, and take_with_encapsulation cannot learn a taken sample's
    true representation either -- its fallback always assumes CDR2_LE.
    Before this fix, reader_qos_for silently left such a reader's QoS at
    the empty default, which this library's own
    resolve_reader_data_representation announces as [XCDR, XCDR2]: a
    reader that could match an XCDR1 writer and then have
    take_with_encapsulation mislabel its samples CDR2_LE. It must refuse
    instead.
    """
    # Built against the REAL native library, before the ABI is hidden
    # below: a class that decodes XCDR2 only never reaches the ABI check
    # at all, whatever QoS it is paired with.
    plain_reliable = QoS.reliable()

    import hdds._native as native_module

    monkeypatch.setattr(native_module, "get_lib", lambda: _LibWithoutTakeEx())

    with pytest.raises(RuntimeError, match="XCDR1"):
        reader_qos_for(BothVersions, None)
    with pytest.raises(RuntimeError, match="XCDR1"):
        reader_qos_for(BothVersions, plain_reliable)

    assert reader_qos_for(Xcdr2Only, None) is None
    assert reader_qos_for(Xcdr2Only, plain_reliable) is plain_reliable

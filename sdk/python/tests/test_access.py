# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Subscriber access brackets (DDS v1.4 Sec.2.2.2.5.2.8).

A reader of a GROUP-scope Subscriber is read only inside an access
bracket: outside, ``take()`` raises INVALID_STATE (PRECONDITION_NOT_MET);
inside (``with subscriber.access()``, or begin/end, nested) it reads.
"""

import pytest

from hdds._native import HddsError, HddsException
from hdds.qos import QoS

pytestmark = pytest.mark.native

GROUP_PROFILE = """<?xml version="1.0" encoding="UTF-8"?>
<dds><profiles>
  <data_reader profile_name="g" is_default_profile="true">
    <qos><presentation><access_scope>GROUP</access_scope>
      <coherent_access>false</coherent_access><ordered_access>false</ordered_access>
    </presentation></qos>
  </data_reader>
</profiles></dds>
"""


@pytest.fixture
def group_subscriber(intra_participant, tmp_path):
    profile = tmp_path / "group.xml"
    profile.write_text(GROUP_PROFILE)
    return intra_participant.create_subscriber(QoS.from_fastdds_xml(str(profile)))


def test_a_group_reader_is_read_inside_a_bracket(group_subscriber):
    reader = group_subscriber.create_reader("py_access_topic")
    with pytest.raises(HddsException) as outside:
        reader.take()
    assert outside.value.code == HddsError.INVALID_STATE
    with group_subscriber.access():
        assert reader.take() is None
        with group_subscriber.access():
            assert reader.take() is None
        assert reader.take() is None
    with pytest.raises(HddsException):
        reader.take()
    group_subscriber.begin_access()
    assert reader.take() is None
    group_subscriber.end_access()


def test_end_access_without_begin_is_invalid_state(intra_participant):
    subscriber = intra_participant.create_subscriber()
    with pytest.raises(HddsException) as no_bracket:
        subscriber.end_access()
    assert no_bracket.value.code == HddsError.INVALID_STATE


def test_access_closes_on_exception(group_subscriber):
    reader = group_subscriber.create_reader("py_access_exc_topic")
    with pytest.raises(ValueError):
        with group_subscriber.access():
            assert reader.take() is None
            raise ValueError("an application error inside the bracket")
    with pytest.raises(HddsException) as outside:
        reader.take()
    assert outside.value.code == HddsError.INVALID_STATE
    with pytest.raises(HddsException) as no_bracket:
        group_subscriber.end_access()
    assert no_bracket.value.code == HddsError.INVALID_STATE

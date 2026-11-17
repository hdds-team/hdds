# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Pytest configuration for HDDS Python SDK tests.

Tests marked ``native`` need the hdds-c shared library. The gate is a
per-test fixture, never a session-level skip: when ``HDDS_LIB_PATH`` is set
and the library does not load the test FAILS (fail closed); when it is
unset and no library is discoverable the test is skipped with the loader's
message. Hermetic tests (discovery, wheel contents) carry no marker and run
without any native library.
"""

import os
import sys
from pathlib import Path

import pytest

# Add SDK to path
SDK_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(SDK_ROOT))


@pytest.fixture(scope="session")
def native_lib():
    """The loaded hdds-c library, or a per-test skip/fail when unavailable."""
    from hdds._native import get_lib
    try:
        return get_lib()
    except ImportError as e:
        if os.environ.get("HDDS_LIB_PATH"):
            pytest.fail(
                "HDDS_LIB_PATH is set but the native library did not load "
                "(fail closed):\n" + str(e),
                pytrace=False,
            )
        pytest.skip("Native library not available: " + str(e))


@pytest.fixture(autouse=True)
def _native_gate(request):
    """Resolve ``native_lib`` for every test carrying the ``native`` marker."""
    if request.node.get_closest_marker("native") is not None:
        request.getfixturevalue("native_lib")


@pytest.fixture
def qos_default(native_lib):
    """Fixture for default QoS."""
    from hdds.qos import QoS
    return QoS.default()


@pytest.fixture
def qos_reliable(native_lib):
    """Fixture for reliable QoS."""
    from hdds.qos import QoS
    return QoS.reliable()


@pytest.fixture
def intra_participant(native_lib):
    """Fixture for an IntraProcess participant (no network)."""
    from hdds.participant import Participant, TransportMode
    p = Participant("test", transport=TransportMode.INTRA_PROCESS)
    yield p
    p.close()

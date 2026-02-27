# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""
Pytest configuration for HDDS Python SDK tests.
"""

import pytest
import sys
from pathlib import Path

# Add SDK to path
SDK_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(SDK_ROOT))


def pytest_configure(config):
    """Configure pytest."""
    # Check if native library is available
    try:
        from hdds._native import get_lib
        get_lib()
    except ImportError as e:
        pytest.skip(f"Native library not available: {e}", allow_module_level=True)


@pytest.fixture
def qos_default():
    """Fixture for default QoS."""
    from hdds.qos import QoS
    return QoS.default()


@pytest.fixture
def qos_reliable():
    """Fixture for reliable QoS."""
    from hdds.qos import QoS
    return QoS.reliable()

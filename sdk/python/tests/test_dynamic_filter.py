# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Exercise the documented ctypes consumer against the selected library."""

import runpy
from pathlib import Path

import pytest


@pytest.mark.native
def test_dynamic_filter_example(capsys):
    example = Path(__file__).resolve().parent.parent / "examples" / "dynamic_filter.py"
    runpy.run_path(str(example), run_name="__main__")
    assert "Dynamic CDR roundtrip and field-map evaluation: PASS" in capsys.readouterr().out

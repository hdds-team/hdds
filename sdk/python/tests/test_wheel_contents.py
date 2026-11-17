# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Hermetic packaging test: the SDK builds as a pure-Python wheel.

When ``HDDS_PY_WHEEL`` names an existing wheel (scripts/test-sdk.sh sets
it to the artefact Layer 1b installs, so the gate builds the wheel once)
that file is inspected. Otherwise the wheel is built offline (``pip wheel
--no-build-isolation --no-deps --no-index``) from a COPY of sdk/python
under ``tmp_path`` so the source tree never receives ``build/`` or
``*.egg-info`` (setuptools writes both in place). Needs no native library.
"""

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = SDK_ROOT.parent.parent

# Recorded at import time, BEFORE any test runs: artefacts a developer's own
# in-place ``pip wheel .`` left behind are not this module's doing.
_ARTEFACT_NAMES = ("build", "dist", "hdds.egg-info")
_PRE_EXISTING = {name for name in _ARTEFACT_NAMES if (SDK_ROOT / name).exists()}


def _build_wheel(dest: Path) -> Path:
    src = dest / "src"
    src.mkdir()
    shutil.copytree(SDK_ROOT / "hdds", src / "hdds",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("pyproject.toml", "README.md", "LICENSE-APACHE", "LICENSE-MIT"):
        shutil.copy(SDK_ROOT / name, src / name)
    out = dest / "dist"
    cmd = [sys.executable, "-m", "pip", "wheel", "--no-build-isolation",
           "--no-deps", "--no-index", "-w", str(out), str(src)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.fail("wheel build failed (setuptools>=77 must be installed on the host):\n"
                    + proc.stdout + proc.stderr, pytrace=False)
    wheels = sorted(out.glob("hdds-*.whl"))
    assert len(wheels) == 1, wheels
    return wheels[0]


@pytest.fixture(scope="module")
def wheel(tmp_path_factory) -> Path:
    handed = os.environ.get("HDDS_PY_WHEEL")
    if handed:
        path = Path(handed)
        assert path.is_file(), f"HDDS_PY_WHEEL={handed} is not a file"
        return path
    return _build_wheel(tmp_path_factory.mktemp("wheel"))


def _package_version() -> str:
    sys.path.insert(0, str(SDK_ROOT))
    try:
        import hdds
        return hdds.__version__
    finally:
        sys.path.pop(0)


def test_wheel_is_pure_python(wheel: Path):
    assert wheel.name.endswith("-py3-none-any.whl"), wheel.name
    assert wheel.name == f"hdds-{_package_version()}-py3-none-any.whl"


def test_wheel_ships_the_ctypes_binding_and_no_tests(wheel: Path):
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
    assert "hdds/_native.py" in names
    assert "hdds/__init__.py" in names
    assert "hdds/py.typed" in names  # PEP 561 marker
    assert not any(n.startswith("tests/") or "/tests/" in n for n in names), names
    assert not any(n.endswith((".so", ".pyd", ".dylib")) for n in names), names


def test_wheel_metadata_matches_package(wheel: Path):
    with zipfile.ZipFile(wheel) as zf:
        meta_name = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")][0]
        metadata = zf.read(meta_name).decode("utf-8")
    fields = {}
    for line in metadata.split("\n\n", 1)[0].splitlines():
        key, _, value = line.partition(": ")
        fields.setdefault(key, []).append(value)
    assert fields["Version"] == [_package_version()]
    licence = fields.get("License-Expression", []) + fields.get("License", [])
    assert any("Apache-2.0 OR MIT" in v for v in licence), licence
    assert "Requires-Dist" not in fields or all(
        "extra ==" in v for v in fields["Requires-Dist"]), fields.get("Requires-Dist")


def test_wheel_ships_both_licence_texts(wheel: Path):
    """PEP 639 licence files are redistributed with the wheel (dist-info/licenses/)."""
    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        licences = [n for n in names if "/licenses/" in n]
        assert licences, names
        texts = {Path(n).name: zf.read(n).decode("utf-8") for n in licences}
    assert set(texts) == {"LICENSE-APACHE", "LICENSE-MIT"}, sorted(texts)
    assert "Apache License" in texts["LICENSE-APACHE"]
    assert "MIT License" in texts["LICENSE-MIT"]


def test_wheel_build_creates_no_new_artefact_in_the_source_tree(wheel: Path):
    """This module's own build never writes into sdk/python.

    setuptools writes ``build/`` and ``*.egg-info`` NEXT TO THE SOURCES, so
    the wheel is built from a copy under ``tmp_path``. The documented
    in-place recipe (``pip wheel .`` inside sdk/python) does create them,
    which is why the assertion is scoped to what this test session created
    rather than to their absence: pre-existing artefacts from a developer's
    own in-place build are none of this test's business, and they are
    gitignored (see the next test) so they never dirty the worktree.
    """
    created = {name for name in _ARTEFACT_NAMES if (SDK_ROOT / name).exists()} - _PRE_EXISTING
    assert not created, f"{sorted(created)} appeared in the source tree during this run"


def test_in_place_build_artefacts_are_gitignored():
    """A user following the documented recipe must not dirty the worktree.

    Fails (never skips) outside a git checkout: the rule is enforced by
    ``git check-ignore``, and a tree where it cannot run is not evidence.
    """
    inside = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
    )
    assert inside.returncode == 0, (
        "%s is not a git checkout; the gitignore rule cannot be checked" % REPO_ROOT
    )
    for name in _ARTEFACT_NAMES:
        probe = f"sdk/python/{name}/x" if name != "hdds.egg-info" else "sdk/python/hdds.egg-info/PKG-INFO"
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "check-ignore", "-q", probe],
            capture_output=True,
        )
        assert proc.returncode == 0, f"{probe} is not gitignored (rc={proc.returncode})"

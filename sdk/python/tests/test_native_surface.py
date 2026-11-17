# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Binding-vs-library parity, derived from the C ABI manifest plus ``nm``.

No hand-written symbol list: the binding side is what hdds/_native.py and
hdds/listener.py declare (``lib.<name>.argtypes``) and what
hdds/conditions.py calls (``lib.<name>(``); the library side is the
``function standalone`` rows of scripts/c-abi/hdds-c-<ver>-x86_64-linux.manifest
(header surface) and the dynamic symbol table of the loaded library
(``nm -D``, the same tool the manifest generator uses).

The conditions.py symbols come from crates/hdds-c/src/condition_ffi.rs,
which is compiled and re-exported by crates/hdds-c/src/lib.rs. They are
newer than the newest released C ABI manifest, so they are checked against
the in-tree public header (sdk/c/include/hdds.h) and the loaded library's
dynamic symbol table instead.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = SDK_ROOT.parent.parent
HDDS_PKG = SDK_ROOT / "hdds"
MANIFEST_GLOB = "hdds-c-*-x86_64-linux.manifest"
MANIFEST_VERSION = re.compile(r"hdds-c-(\d+)\.(\d+)\.(\d+)-x86_64-linux\.manifest$")


def _declared_symbols(*files: str) -> set:
    """Symbols the binding gives argtypes to (hasattr-guarded ones included)."""
    found = set()
    for name in files:
        text = (HDDS_PKG / name).read_text()
        found.update(re.findall(r"lib\.(hdds_\w+)\.argtypes", text))
    return found


def _guarded_symbols(name: str) -> set:
    """Symbols declared under ``if hasattr(lib, '<sym>')`` (feature-optional)."""
    text = (HDDS_PKG / name).read_text()
    return set(re.findall(r"if hasattr\(lib, ['\"](hdds_\w+)['\"]\)", text))


def _called_symbols(name: str) -> set:
    text = (HDDS_PKG / name).read_text()
    return set(re.findall(r"lib\.(hdds_\w+)\(", text))


def _manifest_version(path: Path) -> tuple:
    match = MANIFEST_VERSION.search(path.name)
    assert match, f"unexpected manifest name {path.name}"
    return tuple(int(g) for g in match.groups())


def _newest_manifest() -> Path:
    """Highest-versioned manifest by numeric version (1.10.0 > 1.4.0)."""
    manifests = list((REPO_ROOT / "scripts" / "c-abi").glob(MANIFEST_GLOB))
    assert manifests, "no C ABI manifest under scripts/c-abi"
    return max(manifests, key=_manifest_version)


def _manifest_functions() -> set:
    manifest = _newest_manifest()
    functions = set()
    for line in manifest.read_text().splitlines():
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0] == "function" and cols[1] == "standalone":
            functions.add(cols[2])
    assert functions, manifest
    return functions


def test_manifest_is_picked_by_numeric_version(tmp_path, monkeypatch):
    """A 1.10.0 manifest must win over 1.4.0 (lexicographic sort gets it wrong)."""
    fake = tmp_path / "scripts" / "c-abi"
    fake.mkdir(parents=True)
    for ver in ("1.4.0", "1.10.0", "1.9.3"):
        (fake / f"hdds-c-{ver}-x86_64-linux.manifest").write_text("")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    assert _newest_manifest().name == "hdds-c-1.10.0-x86_64-linux.manifest"


def _resolve_loaded_library(library: str) -> str:
    """Absolute path of the loaded library, even when the linker resolved a bare name.

    ``library_path()`` returns the bare library name for discovery tier 5
    (``ldconfig`` / ``LD_LIBRARY_PATH``). The library IS loaded in this
    process at that point, so its real path is in the process memory map;
    reading it there keeps the parity proof running instead of skipping it.
    """
    if Path(library).is_file():
        return library
    maps = Path("/proc/self/maps")
    if maps.exists():
        stem = Path(library).name
        for line in maps.read_text().splitlines():
            path = line.split(" ", 5)[-1].strip()
            if path.endswith(stem) and Path(path).is_file():
                return path
    pytest.fail(
        "cannot locate the loaded library on disk (library_path() = "
        + library + "); the binding-vs-library parity proof needs a file path",
        pytrace=False,
    )


def _exported_symbols(library: str) -> set:
    """Dynamic symbol table of the loaded library, via the manifest generator's tool.

    ``nm`` is a REQUIRED tool for this proof, never an optional one: a
    missing binutils must close the gate, not silently disable the only
    check that the binding and the library agree. scripts/test-sdk.sh
    Layer 1 checks for it before running pytest.
    """
    nm = shutil.which("nm")
    if nm is None:
        pytest.fail(
            "nm (binutils) is required for the binding-vs-library parity proof; "
            "install it rather than skipping the check",
            pytrace=False,
        )
    path = _resolve_loaded_library(library)
    out = subprocess.run([nm, "-D", "--defined-only", "--format=posix", path],
                         capture_output=True, text=True, check=True).stdout
    return {line.split()[0] for line in out.splitlines() if line.startswith("hdds_")}


@pytest.fixture(scope="module")
def library_path(native_lib):
    from hdds import _native
    return _native.library_path()


@pytest.mark.native
def test_declared_symbols_resolve(native_lib, library_path):
    """Every unguarded symbol _native.py / listener.py declares exists in the library.

    Symbols declared under ``if hasattr(lib, ...)`` are feature-optional
    (qos-loaders, xtypes, the conditions surface): for those the binding
    only has to agree with the library, i.e. ``hasattr`` is true exactly
    when ``nm -D`` exports the symbol.
    """
    declared = _declared_symbols("_native.py", "listener.py")
    assert len(declared) >= 100, declared
    guarded = _guarded_symbols("_native.py")
    assert guarded <= declared, sorted(guarded - declared)
    exported = _exported_symbols(library_path)

    required = declared - guarded
    missing_in_lib = required - exported
    assert not missing_in_lib, f"declared but not exported by {library_path}: {sorted(missing_in_lib)}"

    disagree = {s for s in guarded if hasattr(native_lib, s) != (s in exported)}
    assert not disagree, f"hasattr and nm -D disagree for optional symbols: {sorted(disagree)}"


def test_conditions_symbols_are_all_guarded():
    """conditions.py's symbols are newer than the released manifest, so every one must be hasattr-guarded."""
    called = _called_symbols("conditions.py")
    guarded = _guarded_symbols("_native.py")
    assert called <= guarded, sorted(called - guarded)


def _header_functions() -> set:
    """Function names the in-tree public header declares (sdk/c/include/hdds.h)."""
    text = (REPO_ROOT / "sdk" / "c" / "include" / "hdds.h").read_text()
    return set(re.findall(r"\b(hdds_\w+)\s*\(", text))


def test_declared_symbols_are_in_the_manifest_header_surface():
    """A symbol the binding declares must be part of the public C ABI (hdds.h).

    The manifest is the newest RELEASED surface. A symbol added since is
    accepted only when the binding guards it with ``hasattr`` (so the binding
    still loads the released library) AND the in-tree header declares it.
    """
    declared = _declared_symbols("_native.py", "listener.py")
    conditions = _called_symbols("conditions.py")
    manifest = _manifest_functions()
    newer = (declared - conditions) - manifest
    unguarded = sorted(newer - _guarded_symbols("_native.py") - _guarded_symbols("listener.py"))
    assert not unguarded, (
        "declared by the Python binding, absent from the newest C ABI manifest and "
        f"not hasattr-guarded: {unguarded}"
    )
    unknown = sorted(newer - _header_functions())
    assert not unknown, f"declared by the Python binding but absent from hdds.h: {unknown}"


def test_conditions_binding_has_signatures_for_every_call():
    """conditions.py calls nothing that _native.py leaves without argtypes/restype."""
    called = _called_symbols("conditions.py")
    declared = _declared_symbols("_native.py")
    assert called, "conditions.py binds no symbols?"
    assert called <= declared, sorted(called - declared)


@pytest.mark.native
def test_conditions_symbols_are_exported_and_declared(native_lib, library_path):
    """Every symbol conditions.py calls is exported by the library and declared in hdds.h."""
    called = _called_symbols("conditions.py")
    exported = _exported_symbols(library_path)
    assert called <= exported, sorted(called - exported)
    assert called <= _header_functions(), sorted(called - _header_functions())

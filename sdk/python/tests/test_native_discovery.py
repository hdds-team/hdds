# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2025-2026 naskel.com

"""Hermetic tests of the native library discovery order (hdds/_native.py).

No real libhdds_c.so is needed: a fake library file lives in ``tmp_path``
and ``ctypes.CDLL`` is monkeypatched. The order under test is the one in
the module docstring (and, verbatim, in README.md):

    1. HDDS_LIB_PATH (strict override, the only candidate when set)
    2. <package>/_lib (library bundled in the installed wheel)
    3. <repo>/target/release, <repo>/target/debug
    4. /usr/local/lib, /usr/lib
    5. bare library name -> system dynamic linker
"""

import gc
import sys
from pathlib import Path

import pytest

SDK_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SDK_ROOT))

from hdds import _native  # noqa: E402

LIB_NAME = _native._library_name()
REPO_ROOT = SDK_ROOT.parent.parent


class _FakeFunc:
    def __init__(self):
        self.argtypes = None
        self.restype = None


class _FakeCDLL:
    """Accepts any attribute so ``_setup_signatures`` can run against it."""

    def __init__(self, path):
        self._name = path
        self._funcs = {}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._funcs.setdefault(name, _FakeFunc())


@pytest.fixture(autouse=True)
def _fresh_loader(monkeypatch):
    """Each test starts with no cached library and no HDDS_LIB_PATH."""
    # Native entities (owned QoS, readers, participants) left in reference
    # cycles by earlier tests are only freed by a GC pass, and their __del__
    # calls get_lib(). Run that pass now, while the real cache is still in
    # place; otherwise it lands inside a test whose cache was just reset and
    # reloads the library through this file's fake CDLL.
    gc.collect()
    monkeypatch.delenv("HDDS_LIB_PATH", raising=False)
    monkeypatch.setattr(_native, "_lib", None)
    monkeypatch.setattr(_native, "_lib_path", None)
    yield
    monkeypatch.setattr(_native, "_lib", None)
    monkeypatch.setattr(_native, "_lib_path", None)


def _patch_cdll(monkeypatch, loadable=None, fail_on=()):
    """CDLL that succeeds for ``loadable`` paths and raises OSError otherwise."""
    calls = []

    def fake_cdll(path):
        calls.append(path)
        if path in fail_on:
            raise OSError(f"fake dlopen failure for {path}")
        if loadable is None or path in loadable:
            return _FakeCDLL(path)
        raise OSError(f"cannot open shared object file: {path}")

    monkeypatch.setattr(_native.ctypes, "CDLL", fake_cdll)
    return calls


def test_default_candidate_order_is_bundled_then_dev_then_system_then_bare():
    expected = [
        str(SDK_ROOT / "hdds" / "_lib" / LIB_NAME),
        str(REPO_ROOT / "target" / "release" / LIB_NAME),
        str(REPO_ROOT / "target" / "debug" / LIB_NAME),
        str(Path("/usr/local/lib") / LIB_NAME),
        str(Path("/usr/lib") / LIB_NAME),
        LIB_NAME,
    ]
    assert _native._candidates() == expected


def test_dev_path_is_the_repository_root():
    # <repo>/sdk/python/hdds/_native.py -> four parents up is <repo>
    assert _native._repo_root() == REPO_ROOT
    assert (REPO_ROOT / "Cargo.toml").is_file(), "dev path must point at the checkout root"


def test_installed_layout_has_no_dev_tier(monkeypatch, tmp_path):
    """An installed wheel (site-packages/hdds/_native.py) skips tier 3 entirely."""
    fake = tmp_path / "venv" / "lib" / "python3.13" / "site-packages" / "hdds" / "_native.py"
    fake.parent.mkdir(parents=True)
    fake.write_text("")
    monkeypatch.setattr(_native, "__file__", str(fake))
    assert _native._repo_root() is None
    candidates = _native._candidates()
    assert not any("target" in c for c in candidates), candidates
    assert candidates == [
        str(fake.parent / "_lib" / LIB_NAME),
        str(Path("/usr/local/lib") / LIB_NAME),
        str(Path("/usr/lib") / LIB_NAME),
        LIB_NAME,
    ]


def test_bundled_wheel_tier_is_probed_second(monkeypatch, tmp_path):
    """A wheel that ships the library in <package>/_lib loads it before any other tier.

    The wheel built from this repository is pure Python and ships no
    ``_lib`` directory, so the candidate is normally absent; this test
    populates it the way a bundled-library wheel would.
    """
    pkg = tmp_path / "venv" / "lib" / "python3.13" / "site-packages" / "hdds"
    (pkg / "_lib").mkdir(parents=True)
    bundled = pkg / "_lib" / LIB_NAME
    bundled.write_bytes(b"")
    system = tmp_path / "usr" / "lib" / LIB_NAME
    system.parent.mkdir(parents=True)
    system.write_bytes(b"")
    monkeypatch.setattr(_native, "__file__", str(pkg / "_native.py"))
    assert _native._candidates()[0] == str(bundled)
    calls = _patch_cdll(monkeypatch)
    _native.get_lib()
    assert calls == [str(bundled)]
    assert _native.library_path() == str(bundled)


def test_bundled_tier_is_absent_from_the_wheel_this_repository_builds():
    """The pure-Python wheel ships no native library: the tier exists, the directory does not."""
    assert not (SDK_ROOT / "hdds" / "_lib").exists()


def test_checkout_layout_without_cargo_toml_has_no_dev_tier(monkeypatch, tmp_path):
    """Four parents up is not enough: the root must carry the workspace Cargo.toml."""
    fake = tmp_path / "copy" / "sdk" / "python" / "hdds" / "_native.py"
    fake.parent.mkdir(parents=True)
    fake.write_text("")
    monkeypatch.setattr(_native, "__file__", str(fake))
    assert _native._repo_root() is None
    (tmp_path / "copy" / "Cargo.toml").write_text("[workspace]\n")
    assert _native._repo_root() == tmp_path / "copy"


def test_env_dir_is_the_only_candidate(monkeypatch, tmp_path):
    monkeypatch.setenv("HDDS_LIB_PATH", str(tmp_path))
    assert _native._candidates() == [str(tmp_path / LIB_NAME)]


def test_env_file_is_the_only_candidate(monkeypatch, tmp_path):
    lib = tmp_path / "custom-name.so"
    lib.write_bytes(b"")
    monkeypatch.setenv("HDDS_LIB_PATH", str(lib))
    assert _native._candidates() == [str(lib)]


def test_env_dir_wins_and_is_loaded(monkeypatch, tmp_path):
    lib = tmp_path / LIB_NAME
    lib.write_bytes(b"")
    monkeypatch.setenv("HDDS_LIB_PATH", str(tmp_path))
    calls = _patch_cdll(monkeypatch)
    _native.get_lib()
    assert calls == [str(lib)]
    assert _native.library_path() == str(lib)


def test_env_file_wins_and_is_loaded(monkeypatch, tmp_path):
    lib = tmp_path / "libhdds_c_custom.so"
    lib.write_bytes(b"")
    monkeypatch.setenv("HDDS_LIB_PATH", str(lib))
    calls = _patch_cdll(monkeypatch)
    _native.get_lib()
    assert calls == [str(lib)]


def test_env_empty_is_an_error_not_a_fallback(monkeypatch):
    """`export HDDS_LIB_PATH=` must not silently switch to tiers 2-5."""
    monkeypatch.setenv("HDDS_LIB_PATH", "")
    calls = _patch_cdll(monkeypatch)
    with pytest.raises(ImportError) as info:
        _native.get_lib()
    assert calls == []
    message = str(info.value)
    assert "HDDS_LIB_PATH is set but empty" in message
    assert str(REPO_ROOT / "target") not in message
    assert "/usr/lib" not in message


def test_env_relative_path_is_resolved_against_cwd(monkeypatch, tmp_path):
    lib_dir = tmp_path / "rel" / "lib"
    lib_dir.mkdir(parents=True)
    (lib_dir / LIB_NAME).write_bytes(b"")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HDDS_LIB_PATH", "rel/lib")
    expected = str((tmp_path / "rel" / "lib" / LIB_NAME).resolve())
    assert _native._candidates() == [expected]
    calls = _patch_cdll(monkeypatch)
    _native.get_lib()
    assert calls == [expected]
    assert _native.library_path() == expected


def test_env_relative_missing_path_is_reported_absolute(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HDDS_LIB_PATH", "does/not/exist")
    calls = _patch_cdll(monkeypatch)
    with pytest.raises(ImportError) as info:
        _native.get_lib()
    assert calls == []
    message = str(info.value)
    assert str((tmp_path / "does" / "not" / "exist" / LIB_NAME).resolve()) in message
    assert "(system dynamic linker)" not in message


def test_env_tilde_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HDDS_LIB_PATH", "~/libs")
    assert _native._candidates() == [str(tmp_path / "libs" / LIB_NAME)]


def test_env_set_but_missing_fails_closed_without_fallback(monkeypatch, tmp_path):
    """Strict override: a wrong HDDS_LIB_PATH never falls through to tiers 2-5."""
    monkeypatch.setenv("HDDS_LIB_PATH", str(tmp_path / "nowhere"))
    calls = _patch_cdll(monkeypatch)
    with pytest.raises(ImportError) as info:
        _native.get_lib()
    assert calls == [], "no dlopen attempted (not even the bare name)"
    message = str(info.value)
    assert str(tmp_path / "nowhere" / LIB_NAME) in message
    assert str(REPO_ROOT / "target") not in message, "tier 3 must not be probed"
    assert "/usr/lib" not in message, "tier 4 must not be probed"
    assert _native.BUILD_COMMAND in message
    assert "HDDS_LIB_PATH" in message


def test_existing_but_unloadable_override_raises(monkeypatch, tmp_path):
    """An rmw build (undefined ROS 2 symbols) under HDDS_LIB_PATH surfaces its dlopen error."""
    lib = tmp_path / LIB_NAME
    lib.write_bytes(b"")
    monkeypatch.setenv("HDDS_LIB_PATH", str(tmp_path))
    calls = _patch_cdll(monkeypatch, fail_on={str(lib)})
    with pytest.raises(ImportError) as info:
        _native.get_lib()
    assert calls == [str(lib)]
    assert "fake dlopen failure" in str(info.value)


def test_existing_but_unloadable_override_never_falls_through(monkeypatch, tmp_path):
    """HDDS_LIB_PATH is the ONLY candidate: a broken override is never replaced.

    Even with a loadable library on a later tier, an explicit override that
    exists but fails to load raises. The strictness belongs to the override,
    not to the implicit tiers (see the next test).
    """
    override_dir = tmp_path / "override"
    override_dir.mkdir()
    broken = override_dir / LIB_NAME
    broken.write_bytes(b"")
    monkeypatch.setenv("HDDS_LIB_PATH", str(override_dir))
    calls = _patch_cdll(monkeypatch, loadable=None, fail_on={str(broken)})
    with pytest.raises(ImportError) as info:
        _native.get_lib()
    assert calls == [str(broken)], "nothing but the override may reach dlopen"
    message = str(info.value)
    assert "fake dlopen failure" in message
    assert "/usr/lib" not in message, "tier 4 must not be probed"
    assert _native._lib is None


def test_unloadable_implicit_candidate_does_not_mask_a_later_tier(monkeypatch, tmp_path):
    """An --all-features rmw build in target/release must not break the import.

    Tier 3 exists on disk and fails to load (undefined rosidl_runtime_c_*
    symbols outside a sourced ROS 2 environment). With no explicit override
    the loader records that error and keeps walking, so a good library on
    tier 4 still wins.
    """
    dev = tmp_path / "target" / "release" / LIB_NAME
    dev.parent.mkdir(parents=True)
    dev.write_bytes(b"")
    system = tmp_path / "usr" / "lib" / LIB_NAME
    system.parent.mkdir(parents=True)
    system.write_bytes(b"")
    monkeypatch.setattr(_native, "_candidates",
                        lambda: [str(dev), str(system), LIB_NAME])
    calls = _patch_cdll(monkeypatch, loadable={str(system), LIB_NAME}, fail_on={str(dev)})
    assert _native.library_path() == str(system)
    assert calls == [str(dev), str(system)]


def test_every_implicit_dlopen_failure_is_reported_when_nothing_loads(monkeypatch, tmp_path):
    """Nothing is masked silently: each failing candidate names its own error."""
    dev = tmp_path / "target" / "release" / LIB_NAME
    dev.parent.mkdir(parents=True)
    dev.write_bytes(b"")
    system = tmp_path / "usr" / "lib" / LIB_NAME
    system.parent.mkdir(parents=True)
    system.write_bytes(b"")
    monkeypatch.setattr(_native, "_candidates",
                        lambda: [str(dev), str(system), LIB_NAME])
    calls = _patch_cdll(monkeypatch, loadable=set(), fail_on={str(dev)})
    with pytest.raises(ImportError) as info:
        _native.get_lib()
    assert calls == [str(dev), str(system), LIB_NAME]
    message = str(info.value)
    assert "fake dlopen failure for " + str(dev) in message
    assert "cannot open shared object file: " + str(system) in message
    assert "cannot open shared object file: " + LIB_NAME in message
    assert message.count("exists but did not load:") == 3, message
    assert _native.BUILD_COMMAND in message
    assert _native._lib is None


def test_bare_name_is_tried_last_when_nothing_exists(monkeypatch):
    monkeypatch.setattr(_native, "_candidates",
                        lambda: [str(Path("/nonexistent-a") / LIB_NAME),
                                 str(Path("/nonexistent-b") / LIB_NAME),
                                 LIB_NAME])
    calls = _patch_cdll(monkeypatch, loadable=set())
    with pytest.raises(ImportError) as info:
        _native.get_lib()
    assert calls == [LIB_NAME], "only the bare name reaches dlopen"
    message = str(info.value)
    for tried in ("/nonexistent-a", "/nonexistent-b", LIB_NAME + " (system dynamic linker)"):
        assert tried in message
    assert _native.BUILD_COMMAND in message


def test_bare_name_success_reports_bare_name_as_library_path(monkeypatch):
    monkeypatch.setattr(_native, "_candidates", lambda: [LIB_NAME])
    _patch_cdll(monkeypatch, loadable={LIB_NAME})
    _native.get_lib()
    assert _native.library_path() == LIB_NAME


def test_first_existing_dev_candidate_wins_over_system(monkeypatch, tmp_path):
    dev = tmp_path / "target" / "release"
    dev.mkdir(parents=True)
    (dev / LIB_NAME).write_bytes(b"")
    system = tmp_path / "usr" / "lib"
    system.mkdir(parents=True)
    (system / LIB_NAME).write_bytes(b"")
    monkeypatch.setattr(_native, "_candidates",
                        lambda: [str(dev / LIB_NAME), str(system / LIB_NAME), LIB_NAME])
    calls = _patch_cdll(monkeypatch)
    _native.get_lib()
    assert calls == [str(dev / LIB_NAME)]


def test_library_is_loaded_once(monkeypatch, tmp_path):
    (tmp_path / LIB_NAME).write_bytes(b"")
    monkeypatch.setenv("HDDS_LIB_PATH", str(tmp_path))
    calls = _patch_cdll(monkeypatch)
    first = _native.get_lib()
    second = _native.get_lib()
    assert first is second
    assert len(calls) == 1


def test_docstring_order_matches_readme():
    """The README quotes the docstring block verbatim (scripts/check-python-docs.sh diffs it too)."""
    def block(text: str) -> list:
        # From the marker line to the end of the enclosing block: the
        # docstring terminator in _native.py, the fenced-code terminator in
        # README.md (same bounds as scripts/check-python-docs.sh), so the
        # whole discovery section is compared and not just the numbered list.
        lines = text.splitlines()
        start = lines.index("Library Discovery Order:")
        end = next(i for i in range(start, len(lines))
                   if lines[i] in ('"""', "```"))
        return lines[start:end]

    native_src = (SDK_ROOT / "hdds" / "_native.py").read_text()
    readme_src = (SDK_ROOT / "README.md").read_text()
    assert block(native_src) == block(readme_src)


def test_public_api_exports_library_path():
    import hdds
    assert "library_path" in hdds.__all__
    assert hdds.library_path is _native.library_path
